import asyncio
import io
import uuid
import zipfile
from collections.abc import Generator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import cast
from unittest.mock import patch

import pytest
import yaml
from app.core.config import settings
from app.core.security import (
    ClientIdentity,
    ScanRateLimiter,
    _parse_client_tokens_setting,
    clear_test_client_tokens,
    register_test_client_token,
    verify_scan_access,
)
from app.db.models import ScanRateBucket
from app.db.session import SessionLocal, get_db
from app.main import app
from app.repositories.scan import ScanRepository
from app.services.archive import extract_source_archive, validate_spec_upload
from fastapi.testclient import TestClient
from starlette.types import ASGIApp, Message, Receive, Scope, Send

SAMPLE_SPEC_YAML = """openapi: 3.0.3
info:
  title: Test Security API
  version: 1.0.0
paths:
  /ping:
    get:
      summary: Ping
      responses:
        '200':
          description: OK
"""


def _sample_archive() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("app/main.py", "from fastapi import FastAPI\napp = FastAPI()\n")
    return buf.getvalue()


def _valid_files() -> dict[str, tuple[str, bytes, str]]:
    return {
        "openapi_file": ("openapi.yaml", SAMPLE_SPEC_YAML.encode("utf-8"), "application/x-yaml"),
        "source_archive": ("source.zip", _sample_archive(), "application/zip"),
    }


@pytest.fixture(autouse=True)
def cleanup_tokens() -> Generator[None]:
    clear_test_client_tokens()
    yield
    clear_test_client_tokens()


def _clear_application_rate_limit_buckets() -> None:
    # The test guard points SessionLocal exclusively at the disposable PostgreSQL DB.
    with SessionLocal() as db:
        db.query(ScanRateBucket).delete()
        db.commit()


@pytest.fixture(autouse=True)
def isolate_application_rate_limit_buckets() -> Generator[None]:
    _clear_application_rate_limit_buckets()
    yield
    _clear_application_rate_limit_buckets()


# ==============================================================================
# 1. AUTHENTICATION & AUTHORIZATION TESTS
# ==============================================================================


def test_unauthenticated_scan_submission_rejected() -> None:
    unauthenticated_client = TestClient(app)
    response = unauthenticated_client.post("/api/v1/scans", files=_valid_files())
    assert response.status_code == 401
    assert "X-API-Key or Bearer token is required" in response.json()["detail"]


def test_unauthenticated_scan_status_and_report_access_rejected() -> None:
    unauthenticated_client = TestClient(app)
    fake_id = uuid.uuid4()

    res_status = unauthenticated_client.get(f"/api/v1/scans/{fake_id}")
    assert res_status.status_code == 401

    res_report = unauthenticated_client.get(f"/api/v1/scans/{fake_id}/report")
    assert res_report.status_code == 401

    res_results = unauthenticated_client.get(f"/api/v1/scans/{fake_id}/results")
    assert res_results.status_code == 401

    res_findings = unauthenticated_client.get(f"/api/v1/scans/{fake_id}/findings")
    assert res_findings.status_code == 401


def test_authorized_owner_access_and_unauthorized_tenant_isolation() -> None:
    register_test_client_token("tenant-alpha-token", "tenant-alpha")
    register_test_client_token("tenant-beta-token", "tenant-beta")

    client_alpha = TestClient(app, headers={"X-API-Key": "tenant-alpha-token"})
    client_beta = TestClient(app, headers={"Authorization": "Bearer tenant-beta-token"})

    # 1. Tenant Alpha creates a scan
    response = client_alpha.post(
        "/api/v1/scans",
        files=_valid_files(),
        data={"project_name": "Tenant Alpha Project"},
    )
    assert response.status_code == 202
    scan_id = response.json()["scan_id"]

    # 2. Tenant Alpha can access their own scan status
    res_alpha = client_alpha.get(f"/api/v1/scans/{scan_id}")
    assert res_alpha.status_code == 200
    assert res_alpha.json()["scan_id"] == scan_id

    # 3. Tenant Beta receives 403 Forbidden attempting to access Tenant Alpha's scan
    res_beta_status = client_beta.get(f"/api/v1/scans/{scan_id}")
    assert res_beta_status.status_code == 403
    assert "You do not have permission to access this scan" in res_beta_status.json()["detail"]

    res_beta_report = client_beta.get(f"/api/v1/scans/{scan_id}/report")
    assert res_beta_report.status_code == 403

    res_beta_results = client_beta.get(f"/api/v1/scans/{scan_id}/results")
    assert res_beta_results.status_code == 403

    res_beta_findings = client_beta.get(f"/api/v1/scans/{scan_id}/findings")
    assert res_beta_findings.status_code == 403


def test_legacy_unowned_scan_is_not_exposed_to_non_admin_clients() -> None:
    scan = SimpleNamespace(client_id=None)
    with pytest.raises(Exception) as error:
        verify_scan_access(scan, ClientIdentity(client_id="tenant-alpha"))
    assert getattr(error.value, "status_code", None) == 403
    verify_scan_access(scan, ClientIdentity(client_id="admin", is_admin=True))


def test_malformed_client_token_json_is_ignored_with_sanitized_warning(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    sensitive_marker = "do-not-log-this-token-value"
    monkeypatch.setattr(settings, "api_client_tokens", f'{{"tenant":"{sensitive_marker}"')

    assert _parse_client_tokens_setting() == {}
    assert "JSONDecodeError" in caplog.text
    assert "malformed API_CLIENT_TOKENS JSON configuration" in caplog.text
    assert sensitive_marker not in caplog.text


def _invoke_rate_limiter(
    limiter: ScanRateLimiter,
    header: tuple[bytes, bytes],
    *,
    client_host: str = "127.0.0.1",
) -> tuple[int, bool]:
    passed_downstream = False

    async def receive() -> Message:
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message: Message) -> None:
        return None

    async def downstream(scope: Scope, body_receive: Receive, body_send: Send) -> None:
        nonlocal passed_downstream
        passed_downstream = True
        await body_send({"type": "http.response.start", "status": 202, "headers": []})
        await body_send({"type": "http.response.body", "body": b""})

    limiter.app = cast(ASGIApp, downstream)
    status_codes: list[int] = []

    async def recording_send(message: Message) -> None:
        if message["type"] == "http.response.start":
            status_codes.append(int(message["status"]))

    asyncio.run(
        limiter(
            cast(
                Scope,
                {
                    "type": "http",
                    "method": "POST",
                    "path": "/api/v1/scans",
                    "headers": [header],
                    "client": (client_host, 1234),
                },
            ),
            receive,
            recording_send,
        )
    )
    return status_codes[0], passed_downstream


def test_scan_rate_limit_is_shared_across_instances_and_resets_expired_bucket(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.core.security import ClientIdentity
    from app.db.session import SessionLocal

    monkeypatch.setattr(settings, "scan_rate_limit_requests", 1)
    monkeypatch.setattr(settings, "scan_rate_limit_window_seconds", 30)
    first = ScanRateLimiter(cast(ASGIApp, lambda scope, receive, send: None))
    second = ScanRateLimiter(cast(ASGIApp, lambda scope, receive, send: None))
    key = first._bucket_key(ClientIdentity("shared-client"))
    try:
        assert first._consume(key) is True
        assert second._consume(key) is False
        with SessionLocal() as db:
            bucket = db.get(ScanRateBucket, key)
            assert bucket is not None
            bucket.window_started_at = datetime.now(UTC) - timedelta(minutes=1)
            db.commit()
        assert second._consume(key) is True
    finally:
        with SessionLocal() as db:
            db.delete(db.get(ScanRateBucket, key))
            db.commit()


def test_unique_invalid_tokens_share_one_bounded_database_bucket(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.db.session import SessionLocal
    from sqlalchemy import select

    monkeypatch.setattr(settings, "scan_rate_limit_requests", 2)
    limiter = ScanRateLimiter(cast(ASGIApp, lambda scope, receive, send: None))
    first = limiter._bucket_key(None)
    try:
        assert _invoke_rate_limiter(limiter, (b"x-api-key", b"invalid-one")) == (202, True)
        assert _invoke_rate_limiter(limiter, (b"x-api-key", b"invalid-two")) == (202, True)
        assert _invoke_rate_limiter(limiter, (b"x-api-key", b"invalid-three")) == (429, False)
        with SessionLocal() as db:
            keys = list(
                db.scalars(
                    select(ScanRateBucket.bucket_key).where(ScanRateBucket.bucket_key == first)
                )
            )
            assert keys == [first]
    finally:
        with SessionLocal() as db:
            db.delete(db.get(ScanRateBucket, first))
            db.commit()


# ==============================================================================
# 2. BOUNDED UPLOADS & STREAMING EXTRACTION TESTS
# ==============================================================================


def test_scan_submission_rejects_content_length_oversized() -> None:
    client = TestClient(app, headers={"X-API-Key": settings.api_access_token or ""})
    response = client.post(
        "/api/v1/scans",
        headers={"Content-Length": str(settings.max_upload_bytes + 1024)},
        files=_valid_files(),
    )
    assert response.status_code == 413
    assert "exceeds maximum upload limit" in response.json()["detail"]


def test_scan_submission_rejects_an_oversized_stream_before_analysis() -> None:
    client = TestClient(app, headers={"X-API-Key": settings.api_access_token or ""})
    oversized_spec = b"x" * (min(settings.max_upload_bytes, settings.max_spec_bytes) + 1)

    response = client.post(
        "/api/v1/scans",
        files={
            "openapi_file": ("openapi.yaml", oversized_spec, "application/x-yaml"),
            "source_archive": ("source.zip", _sample_archive(), "application/zip"),
        },
    )
    assert response.status_code == 413
    assert "configured upload limit" in response.json()["detail"]


def test_archive_extraction_limits_enforced(tmp_path: Path) -> None:
    oversized_archive = b"0" * (settings.max_archive_bytes + 1)
    with pytest.raises(ValueError, match="UNTRUSTED_ARCHIVE_REJECTED: Source archive size"):
        extract_source_archive(oversized_archive, tmp_path)


def test_archive_file_count_limits_enforced(tmp_path: Path) -> None:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for i in range(settings.max_files_per_scan + 1):
            zf.writestr(f"file_{i}.py", "x = 1\n")
    zip_bytes = buf.getvalue()

    with pytest.raises(ValueError, match="UNTRUSTED_ARCHIVE_REJECTED: Archive file count"):
        extract_source_archive(zip_bytes, tmp_path)


def test_archive_uncompressed_size_limits_enforced(tmp_path: Path) -> None:
    buf = io.BytesIO()
    chunk = b"0" * (1024 * 1024)  # 1 MB
    num_files = (settings.max_uncompressed_bytes // (1024 * 1024)) + 1
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for i in range(num_files):
            zf.writestr(f"f_{i}.txt", chunk)
    zip_bytes = buf.getvalue()

    with pytest.raises(ValueError, match="UNTRUSTED_ARCHIVE_REJECTED: Cumulative uncompressed"):
        extract_source_archive(zip_bytes, tmp_path)


def test_decompression_bomb_stream_chunking_defense(tmp_path: Path) -> None:
    buf = io.BytesIO()
    # 5MB of zeros compressed is under 10KB, but exceeds max_individual_file_bytes (1MB)
    huge_data = b"0" * (settings.max_individual_file_bytes + 1024)
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("bomb.py", huge_data)
    zip_bytes = buf.getvalue()

    with pytest.raises(ValueError, match="UNTRUSTED_ARCHIVE_REJECTED: Individual file"):
        extract_source_archive(zip_bytes, tmp_path)


def test_zip_slip_remains_blocked(tmp_path: Path) -> None:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("../../etc/passwd", "evil")
    zip_bytes = buf.getvalue()

    with pytest.raises(ValueError, match="UNTRUSTED_ARCHIVE_REJECTED: Zip Slip attempt detected"):
        extract_source_archive(zip_bytes, tmp_path)


def test_symlink_attacks_blocked(tmp_path: Path) -> None:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        info = zipfile.ZipInfo("symlink_entry")
        info.external_attr = 0o120755 << 16  # S_IFLNK
        zf.writestr(info, "/etc/shadow")
    zip_bytes = buf.getvalue()

    with pytest.raises(ValueError, match="UNTRUSTED_ARCHIVE_REJECTED: Symlink detected"):
        extract_source_archive(zip_bytes, tmp_path)


# ==============================================================================
# 3. RESOURCE EXHAUSTION & CAPACITY CONTROLS
# ==============================================================================


def test_queue_capacity_limit_enforced() -> None:
    client = TestClient(app, headers={"X-API-Key": settings.api_access_token or ""})

    with patch.object(ScanRepository, "count_active_scans", return_value=settings.max_active_scans):
        response = client.post("/api/v1/scans", files=_valid_files())
        assert response.status_code == 429
        assert "Maximum queue capacity reached" in response.json()["detail"]


def test_per_client_concurrency_limit_enforced() -> None:
    register_test_client_token("busy-client-token", "busy-client")
    client = TestClient(app, headers={"X-API-Key": "busy-client-token"})

    with patch.object(
        ScanRepository,
        "count_client_active_scans",
        return_value=settings.max_concurrent_scans_per_client,
    ):
        response = client.post("/api/v1/scans", files=_valid_files())
        assert response.status_code == 429
        assert "CLIENT_CONCURRENCY_LIMIT_EXCEEDED" in response.json()["detail"]


def test_scan_startup_recovery_cleans_interrupted_scans() -> None:
    db_gen = get_db()
    db = next(db_gen)
    try:
        repo = ScanRepository(db)
        scan = repo.create_scan(
            project_name="Interrupted Test Project",
            spec_filename="openapi.yaml",
            source_filename="source.zip",
        )
        repo.update_status(scan.id, "RUNNING")

        recovered_ids = repo.recover_interrupted_scans()
        assert scan.id in recovered_ids

        recovered_scan = repo.get_scan(scan.id)
        assert recovered_scan is not None
        assert recovered_scan.status == "FAILED"
        assert "SYSTEM_INTERRUPTED" in (recovered_scan.error_message or "")
    finally:
        try:
            next(db_gen)
        except StopIteration:
            pass


# ==============================================================================
# 4. CONFIGURATION AS AUTHORITATIVE SOURCE
# ==============================================================================


def test_archive_limits_derive_from_authoritative_settings() -> None:
    with patch.object(settings, "max_spec_bytes", 50):
        with pytest.raises(ValueError, match="OpenAPI spec size .* exceeds maximum limit of 50 B"):
            validate_spec_upload("openapi.yaml", b"x" * 60)

        validate_spec_upload("openapi.yaml", b"x" * 40)


def test_archive_file_count_derives_from_authoritative_settings(tmp_path: Path) -> None:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for i in range(5):
            zf.writestr(f"file_{i}.txt", "data")
    zip_bytes = buf.getvalue()

    with patch.object(settings, "max_files_per_scan", 3):
        with pytest.raises(
            ValueError, match="Archive file count .* exceeds maximum limit of 3 files"
        ):
            extract_source_archive(zip_bytes, tmp_path)


# ==============================================================================
# 5. DEPLOYMENT & DATABASE EXPOSURE VERIFICATION
# ==============================================================================


def test_docker_compose_postgres_localhost_binding() -> None:
    compose_path = Path("docker-compose.yml")
    assert compose_path.exists()
    content = compose_path.read_text(encoding="utf-8")
    compose_data = yaml.safe_load(content)

    postgres_service = compose_data.get("services", {}).get("postgres", {})
    ports = postgres_service.get("ports", [])
    assert "127.0.0.1:5432:5432" in ports
    assert "5432:5432" not in ports

    api_service = compose_data.get("services", {}).get("api", {})
    api_ports = api_service.get("ports", [])
    assert "127.0.0.1:8000:8000" in api_ports
    assert "8000:8000" not in api_ports


def test_invalid_authentication_token_rejected() -> None:
    client = TestClient(app, headers={"X-API-Key": "completely-invalid-bogus-token"})
    response = client.post("/api/v1/scans", files=_valid_files())
    assert response.status_code == 401
    assert "Invalid authentication credentials" in response.json()["detail"]


def test_scan_client_id_persistence() -> None:
    db_gen = get_db()
    db = next(db_gen)
    try:
        repo = ScanRepository(db)
        scan = repo.create_scan(
            project_name="Client ID Persistence Test",
            spec_filename="openapi.yaml",
            source_filename="source.zip",
            client_id="verified-client-42",
        )
        fetched = repo.get_scan(scan.id)
        assert fetched is not None
        assert fetched.client_id == "verified-client-42"
    finally:
        try:
            next(db_gen)
        except StopIteration:
            pass


def test_list_scans_authentication_and_tenant_isolation() -> None:
    unauthenticated_client = TestClient(app)
    assert unauthenticated_client.get("/api/v1/scans").status_code == 401

    register_test_client_token("tenant-list-a-token", "tenant-list-a")
    register_test_client_token("tenant-list-b-token", "tenant-list-b")

    client_a = TestClient(app, headers={"X-API-Key": "tenant-list-a-token"})
    client_b = TestClient(app, headers={"Authorization": "Bearer tenant-list-b-token"})

    # Client A creates scan
    res_a = client_a.post(
        "/api/v1/scans",
        files=_valid_files(),
        data={"project_name": "Project Alpha Isolation"},
    )
    assert res_a.status_code == 202
    scan_a_id = res_a.json()["scan_id"]

    # Client B creates scan
    res_b = client_b.post(
        "/api/v1/scans",
        files=_valid_files(),
        data={"project_name": "Project Beta Isolation"},
    )
    assert res_b.status_code == 202
    scan_b_id = res_b.json()["scan_id"]

    # Verify listing isolation
    list_a = client_a.get("/api/v1/scans")
    assert list_a.status_code == 200
    ids_a = [s["scan_id"] for s in list_a.json()]
    assert scan_a_id in ids_a
    assert scan_b_id not in ids_a

    list_b = client_b.get("/api/v1/scans")
    assert list_b.status_code == 200
    ids_b = [s["scan_id"] for s in list_b.json()]
    assert scan_b_id in ids_b
    assert scan_a_id not in ids_b


def test_research_benchmarks_authentication_and_payload() -> None:
    unauthenticated_client = TestClient(app)
    assert unauthenticated_client.get("/api/v1/research/benchmarks").status_code == 401

    register_test_client_token("research-analyst-token", "research-analyst")
    client = TestClient(app, headers={"X-API-Key": "research-analyst-token"})
    response = client.get("/api/v1/research/benchmarks")
    assert response.status_code == 200
    data = response.json()
    assert "baseline" in data
    assert "external" in data
    assert "phase7" in data
