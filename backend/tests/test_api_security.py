import io
import uuid
import zipfile
from collections.abc import Generator
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml
from app.core.config import settings
from app.core.security import (
    clear_test_client_tokens,
    register_test_client_token,
)
from app.db.session import get_db
from app.main import app
from app.repositories.scan import ScanRepository
from app.services.archive import extract_source_archive, validate_spec_upload
from fastapi.testclient import TestClient

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

        recovered_count = repo.recover_interrupted_scans()
        assert recovered_count >= 1

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
