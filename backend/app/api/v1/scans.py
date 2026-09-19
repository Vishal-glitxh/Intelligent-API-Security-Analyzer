import uuid

from app.db.session import get_db
from app.repositories.scan import ScanRepository
from app.schemas.scan import (
    ScanCreateResponse,
    ScanFindingsResponse,
    ScanResponse,
    ScanResultsResponse,
)
from app.services.report import ReportService
from app.services.scan_service import ScanService
from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, UploadFile, status
from fastapi.responses import HTMLResponse, JSONResponse, Response
from sqlalchemy.orm import Session

router = APIRouter(prefix="/scans", tags=["scans"])


@router.post("", status_code=status.HTTP_202_ACCEPTED, response_model=ScanCreateResponse)
async def create_scan(
    openapi_file: UploadFile = File(...),
    source_archive: UploadFile = File(...),
    project_name: str = Form("API Security Analysis Project"),
    db: Session = Depends(get_db),
) -> ScanCreateResponse:
    """Upload an OpenAPI specification file and source code ZIP archive to submit a scan."""
    spec_bytes = await openapi_file.read()
    source_bytes = await source_archive.read()

    spec_filename = openapi_file.filename or "openapi.yaml"
    source_filename = source_archive.filename or "source.zip"

    service = ScanService(db)

    try:
        scan_id = service.create_and_submit_scan(
            project_name=project_name,
            spec_filename=spec_filename,
            spec_bytes=spec_bytes,
            source_filename=source_filename,
            source_bytes=source_bytes,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
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


@router.get("/{scan_id}", response_model=ScanResponse)
def get_scan_status(
    scan_id: uuid.UUID,
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


@router.get("/{scan_id}/report", response_model=None)
def get_scan_report(
    scan_id: uuid.UUID,
    format: str = Query("json", pattern="^(json|html)$"),
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

    if format == "html":
        html_content = ReportService.generate_html_report(scan, result)
        return HTMLResponse(content=html_content)

    json_report = ReportService.generate_json_report(scan, result)
    return JSONResponse(content=json_report)
