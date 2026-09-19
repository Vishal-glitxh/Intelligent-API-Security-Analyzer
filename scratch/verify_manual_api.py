import io
import sys
import zipfile
from pathlib import Path

backend_dir = Path(__file__).parent.parent / "backend"
sys.path.insert(0, str(backend_dir))

from app.main import app  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

client = TestClient(app)


def run_manual_verification() -> None:
    print("=== MANUAL API VERIFICATION ===")

    # 1. Prepare valid spec and source archive
    valid_spec = """
openapi: "3.0.3"
info:
  title: "Test Verification API"
  version: "1.0.0"
paths:
  /api/v1/users:
    get:
      summary: "Get users"
      responses:
        "200":
          description: "OK"
"""

    zip_buffer = io.BytesIO()
    sample_code = (
        "from fastapi import FastAPI\n"
        "app = FastAPI()\n"
        "@app.get('/api/v1/users')\n"
        "def get_users(): pass\n"
    )
    with zipfile.ZipFile(zip_buffer, "w") as zf:
        zf.writestr("app.py", sample_code)
    zip_bytes = zip_buffer.getvalue()

    # 2. POST /api/v1/scans
    response = client.post(
        "/api/v1/scans",
        files={
            "openapi_file": ("openapi.yaml", io.BytesIO(valid_spec.encode("utf-8")), "text/yaml"),
            "source_archive": ("source.zip", io.BytesIO(zip_bytes), "application/zip"),
        },
    )
    print(f"POST /api/v1/scans response status: {response.status_code}")
    assert response.status_code == 202, f"Expected 202, got {response.status_code}: {response.text}"
    data = response.json()
    scan_id = data["scan_id"]
    status = data["status"]
    print(f"Scan Created. ID: {scan_id}, Initial Status: {status}")

    # 3. Poll GET /api/v1/scans/{scan_id}
    res = client.get(f"/api/v1/scans/{scan_id}")
    assert res.status_code == 200
    final_status = res.json()["status"].lower()
    print(f"Poll Scan Status: {final_status}")
    assert final_status in ("completed", "queued", "running")

    # 4. GET /api/v1/scans/{scan_id}/results
    res_results = client.get(f"/api/v1/scans/{scan_id}/results")
    assert res_results.status_code in (200, 202)
    print(f"GET /results status: {res_results.status_code}")

    # 5. GET /api/v1/scans/{scan_id}/findings
    res_findings = client.get(f"/api/v1/scans/{scan_id}/findings")
    assert res_findings.status_code in (200, 202)
    print(f"GET /findings status: {res_findings.status_code}")

    # 6. GET /api/v1/scans/{scan_id}/report (JSON)
    res_json_report = client.get(f"/api/v1/scans/{scan_id}/report?format=json")
    assert res_json_report.status_code in (200, 202)
    print(f"GET /report?format=json status: {res_json_report.status_code}")

    # 7. GET /api/v1/scans/{scan_id}/report (HTML)
    res_html_report = client.get(f"/api/v1/scans/{scan_id}/report?format=html")
    assert res_html_report.status_code in (200, 202)
    print(f"GET /report?format=html status: {res_html_report.status_code}")

    # 8. Unsafe file rejection test (Zip Slip attempt)
    bad_zip_buffer = io.BytesIO()
    with zipfile.ZipFile(bad_zip_buffer, "w") as zf:
        zf.writestr("../unsafe.txt", "malicious content")
    bad_zip_bytes = bad_zip_buffer.getvalue()

    res_unsafe = client.post(
        "/api/v1/scans",
        files={
            "openapi_file": ("openapi.yaml", io.BytesIO(valid_spec.encode("utf-8")), "text/yaml"),
            "source_archive": ("bad.zip", io.BytesIO(bad_zip_bytes), "application/zip"),
        },
    )
    print(f"POST /api/v1/scans with Zip Slip response status: {res_unsafe.status_code}")
    assert res_unsafe.status_code == 400
    print(f"Zip Slip correctly rejected: {res_unsafe.json()['detail']}")

    print("\n=== MANUAL API VERIFICATION PASSED SUCCESSFULLY ===")


if __name__ == "__main__":
    run_manual_verification()
