import asyncio
import uuid
from collections.abc import AsyncIterator
from typing import cast

from app.core.config import settings
from app.core.security import (
    ClientIdentity,
    get_current_client,
    require_api_access_token,
    verify_scan_access,
)
from app.db.session import get_db
from app.repositories.scan import ScanRepository
from app.schemas.scan import (
    ScanAssistantRequest,
    ScanAssistantResponse,
    ScanCreateResponse,
    ScanFindingsResponse,
    ScanResponse,
    ScanResultsResponse,
)
from app.services.local_ai import generate_local_explanation, get_local_ai_status
from app.services.rag_assistant import answer_scan_question
from app.services.report import ReportService
from app.services.scan_service import ScanService
from app.services.upload_admission import upload_admission as upload_admission
from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Query,
    Request,
    status,
)
from fastapi.responses import HTMLResponse, JSONResponse, Response
from python_multipart.exceptions import MultipartParseError
from sqlalchemy.orm import Session
from starlette.concurrency import run_in_threadpool
from starlette.datastructures import FormData, UploadFile

router = APIRouter(
    prefix="/scans",
    tags=["scans"],
    dependencies=[Depends(require_api_access_token)],
)

_UPLOAD_CHUNK_BYTES = 64 * 1024


async def _iter_upload_chunks(upload: UploadFile) -> AsyncIterator[bytes]:
    while chunk := await upload.read(_UPLOAD_CHUNK_BYTES):
        yield chunk


async def _read_upload_with_limit(upload: UploadFile, max_bytes: int, label: str) -> bytes:
    """Read a multipart part incrementally and abort before materializing an oversized body."""
    content = bytearray()
    async for chunk in _iter_upload_chunks(upload):
        if len(content) + len(chunk) > max_bytes:
            raise HTTPException(
                status_code=status.HTTP_413_CONTENT_TOO_LARGE,
                detail=f"{label} exceeds the configured upload limit of {max_bytes} bytes.",
            )
        content.extend(chunk)
    return bytes(content)


async def _run_scan_orchestration(
    service: ScanService,
    *,
    project_name: str,
    spec_filename: str,
    spec_bytes: bytes,
    source_filename: str,
    source_bytes: bytes,
    client_id: str,
) -> uuid.UUID:
    """Keep a scan thread and its admission reservation alive through request cancellation."""
    operation = asyncio.create_task(
        run_in_threadpool(
            service.create_and_submit_scan,
            project_name=project_name,
            spec_filename=spec_filename,
            spec_bytes=spec_bytes,
            source_filename=source_filename,
            source_bytes=source_bytes,
            client_id=client_id,
        )
    )
    cancellation_requested = False
    while not operation.done():
        try:
            await asyncio.shield(operation)
        except asyncio.CancelledError:
            cancellation_requested = True

    if cancellation_requested:
        # Consume any background exception before propagating the client's cancellation.
        if not operation.cancelled():
            operation.exception()
        raise asyncio.CancelledError
    return operation.result()


def _get_upload_parts(form: FormData) -> tuple[UploadFile, UploadFile | None, str]:
    parts: dict[str, list[object]] = {
        "openapi_file": [],
        "source_archive": [],
        "project_name": [],
    }
    for name, value in form.multi_items():
        if name not in parts:
            raise HTTPException(status_code=422, detail="Unexpected multipart field.")
        parts[name].append(value)

    openapi_values = parts["openapi_file"]
    archive_values = parts["source_archive"]
    project_values = parts["project_name"]
    if (
        len(openapi_values) != 1
        or len(archive_values) > 1
        or len(project_values) > 1
        or not isinstance(openapi_values[0], UploadFile)
        or (archive_values and not isinstance(archive_values[0], UploadFile))
        or (project_values and not isinstance(project_values[0], str))
    ):
        raise HTTPException(status_code=422, detail="Invalid multipart upload fields.")

    project_name = cast(
        str,
        project_values[0] if project_values else "API Security Analysis Project",
    )
    return (
        openapi_values[0],
        cast(UploadFile, archive_values[0]) if archive_values else None,
        project_name,
    )


@router.post("", status_code=status.HTTP_202_ACCEPTED, response_model=ScanCreateResponse)
async def create_scan(
    request: Request,
    client: ClientIdentity = Depends(get_current_client),
    db: Session = Depends(get_db),
) -> ScanCreateResponse:
    """Upload an OpenAPI specification file and source code ZIP archive to submit a scan."""
    # Authentication dependencies run before this manual multipart parse because this
    # endpoint deliberately has no File/Form body parameters.
    media_type = request.headers.get("content-type", "").partition(";")[0].strip().lower()
    if media_type != "multipart/form-data":
        raise HTTPException(
            status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            detail="A multipart/form-data request is required.",
        )

    content_length_header = request.headers.get("content-length")
    if content_length_header:
        try:
            content_length = int(content_length_header)
            if content_length > settings.max_upload_bytes:
                raise HTTPException(
                    status_code=status.HTTP_413_CONTENT_TOO_LARGE,
                    detail=(
                        f"Request payload ({content_length} bytes) exceeds maximum "
                        f"upload limit of {settings.max_upload_bytes} bytes."
                    ),
                )
        except ValueError:
            pass

    reservation = upload_admission.try_reserve(client.client_id)
    if reservation is None:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Scan upload capacity is currently full.",
            headers={"Retry-After": "1"},
        )
    try:
        try:
            async with request.form(max_files=2, max_fields=1, max_part_size=1024 * 1024) as form:
                openapi_file, source_archive, project_name = _get_upload_parts(form)
                spec_bytes = await _read_upload_with_limit(
                    openapi_file,
                    min(settings.max_upload_bytes, settings.max_spec_bytes),
                    "OpenAPI specification",
                )
                source_bytes = (
                    await _read_upload_with_limit(
                        source_archive,
                        min(settings.max_upload_bytes, settings.max_archive_bytes),
                        "Source archive",
                    )
                    if source_archive
                    else b""
                )
                spec_filename = openapi_file.filename or "openapi.yaml"
                source_filename = (
                    (source_archive.filename or "source.zip") if source_archive else "Not provided"
                )
        except MultipartParseError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="There was an error parsing the multipart body.",
            ) from exc

        service = ScanService(db)
        try:
            # A cancelled request must not release admission while its synchronous
            # worker thread can still persist scan state or use the workspace.
            scan_id = await _run_scan_orchestration(
                service,
                project_name=project_name,
                spec_filename=spec_filename,
                spec_bytes=spec_bytes,
                source_filename=source_filename,
                source_bytes=source_bytes,
                client_id=client.client_id,
            )
        except ValueError as exc:
            msg = str(exc)
            if "CAPACITY_EXCEEDED" in msg or "CONCURRENCY_LIMIT" in msg:
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail=msg,
                ) from exc
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=msg,
            ) from exc

        repo = ScanRepository(db)
        scan = repo.get_scan(scan_id)
        if not scan:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to retrieve created scan record",
            )

        return ScanCreateResponse(
            scan_id=scan.id,
            status=scan.status.lower(),
            project_name=scan.project_name,
            created_at=scan.created_at,
        )
    finally:
        reservation.release()


@router.get("", response_model=list[ScanResponse])
def list_scans(
    limit: int = Query(50, ge=1, le=100),
    client: ClientIdentity = Depends(get_current_client),
    db: Session = Depends(get_db),
) -> list[ScanResponse]:
    """List recent scans for the authenticated client."""
    repo = ScanRepository(db)
    scans = repo.list_scans(client_id=client.client_id, is_admin=client.is_admin, limit=limit)
    return [
        ScanResponse(
            scan_id=s.id,
            status=s.status.lower(),
            project_name=s.project_name,
            spec_filename=s.spec_filename,
            source_filename=s.source_filename,
            spec_hash=s.spec_hash,
            source_hash=s.source_hash,
            engine_version=s.engine_version,
            rule_set_version=s.rule_set_version,
            config_version=s.config_version,
            error_message=s.error_message,
            created_at=s.created_at,
            started_at=s.started_at,
            completed_at=s.completed_at,
        )
        for s in scans
    ]


@router.get("/{scan_id}", response_model=ScanResponse)
def get_scan_status(
    scan_id: uuid.UUID,
    client: ClientIdentity = Depends(get_current_client),
    db: Session = Depends(get_db),
) -> ScanResponse:
    """Retrieve scan status and reproducibility metadata."""
    repo = ScanRepository(db)
    scan = repo.get_scan(scan_id)
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan with ID '{scan_id}' not found",
        )

    verify_scan_access(scan, client)

    return ScanResponse(
        scan_id=scan.id,
        status=scan.status.lower(),
        project_name=scan.project_name,
        spec_filename=scan.spec_filename,
        source_filename=scan.source_filename,
        spec_hash=scan.spec_hash,
        source_hash=scan.source_hash,
        engine_version=scan.engine_version,
        rule_set_version=scan.rule_set_version,
        config_version=scan.config_version,
        error_message=scan.error_message,
        created_at=scan.created_at,
        started_at=scan.started_at,
        completed_at=scan.completed_at,
    )


@router.get("/{scan_id}/results", response_model=ScanResultsResponse)
def get_scan_results(
    scan_id: uuid.UUID,
    client: ClientIdentity = Depends(get_current_client),
    db: Session = Depends(get_db),
) -> ScanResultsResponse:
    """Retrieve high-level MultiLayerAnalysisResult metrics summary and matched endpoints."""
    repo = ScanRepository(db)
    scan_data = repo.get_scan_with_result(scan_id)
    if not scan_data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan with ID '{scan_id}' not found",
        )

    scan, result = scan_data
    verify_scan_access(scan, client)

    if not result:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Results for scan ID '{scan_id}' are not available (Status: {scan.status})",
        )

    return ScanResultsResponse(
        scan_id=scan.id,
        metrics_summary=result.metrics_summary,
        matched_endpoints=result.matched_endpoints,
    )


@router.get("/{scan_id}/findings", response_model=ScanFindingsResponse)
def get_scan_findings(
    scan_id: uuid.UUID,
    client: ClientIdentity = Depends(get_current_client),
    db: Session = Depends(get_db),
) -> ScanFindingsResponse:
    """Retrieve itemized findings categorized by SPEC_ONLY, SOURCE_ONLY, and CORRELATED layers."""
    repo = ScanRepository(db)
    scan_data = repo.get_scan_with_result(scan_id)
    if not scan_data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan with ID '{scan_id}' not found",
        )

    scan, result = scan_data
    verify_scan_access(scan, client)

    if not result:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Findings for scan ID '{scan_id}' are not available (Status: {scan.status})",
        )

    return ScanFindingsResponse(
        scan_id=scan.id,
        spec_only_findings=result.spec_only_findings,
        source_only_findings=result.source_only_findings,
        correlated_findings=result.correlated_findings,
    )


@router.post("/{scan_id}/assistant", response_model=ScanAssistantResponse)
def ask_scan_assistant(
    scan_id: uuid.UUID,
    request_data: ScanAssistantRequest,
    client: ClientIdentity = Depends(get_current_client),
    db: Session = Depends(get_db),
) -> ScanAssistantResponse:
    """Answer a scan question from stored evidence and bundled security guidance."""
    repo = ScanRepository(db)
    scan_data = repo.get_scan_with_result(scan_id)
    if not scan_data:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found.")

    scan, result = scan_data
    verify_scan_access(scan, client)
    if not result:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="The scan has no completed analysis results yet.",
        )

    ai_status = get_local_ai_status()
    response = answer_scan_question(
        request_data.question,
        spec_findings=result.spec_only_findings,
        source_findings=result.source_only_findings,
        correlated_findings=result.correlated_findings,
        matched_endpoints=result.matched_endpoints,
        limit=request_data.limit,
        local_ai_status=ai_status,
    )
    explanation = generate_local_explanation(
        request_data.question,
        response["sources"],
        status_data=ai_status,
    )
    retrieved_source_ids = {str(source["id"]) for source in response["sources"]}
    cited_source_ids = (
        [
            source_id
            for source_id in explanation.cited_source_ids
            if source_id in retrieved_source_ids
        ]
        if explanation
        else []
    )
    response.update(
        {
            "ai_status": ai_status["status"],
            "model_name": ai_status["model_name"],
            "ai_used": explanation is not None,
            "ai_explanation": explanation.explanation if explanation else None,
            "recommendations": explanation.recommendations if explanation else [],
            "cited_source_ids": cited_source_ids,
            "notice": (
                "Local model generated this explanation from retrieved, redacted evidence."
                if explanation
                else response["notice"]
            ),
        }
    )
    return ScanAssistantResponse(scan_id=scan.id, **response)


@router.get("/{scan_id}/report", response_model=None)
def get_scan_report(
    scan_id: uuid.UUID,
    format: str = Query("json", pattern="^(json|html)$"),
    client: ClientIdentity = Depends(get_current_client),
    db: Session = Depends(get_db),
) -> Response:
    """Retrieve formatted analysis report in canonical JSON or standalone HTML format."""
    repo = ScanRepository(db)
    scan_data = repo.get_scan_with_result(scan_id)
    if not scan_data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan with ID '{scan_id}' not found",
        )

    scan, result = scan_data
    verify_scan_access(scan, client)

    if format == "html":
        html_content = ReportService.generate_html_report(scan, result)
        return HTMLResponse(content=html_content)

    json_report = ReportService.generate_json_report(scan, result)
    return JSONResponse(content=json_report)
