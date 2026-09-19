import io
import zipfile

from app.main import app
from fastapi.testclient import TestClient

client = TestClient(app)

SAMPLE_SPEC_YAML = """openapi: 3.0.3
info:
  title: Test Service API
  version: 1.0.0
paths:
  /items:
    get:
      summary: List items
      responses:
        '200':
          description: OK
"""


SAMPLE_FASTAPI_SOURCE = """
from fastapi import FastAPI

app = FastAPI()

@app.get("/items")
def list_items():
    return [{"id": 1, "name": "item"}]
"""


def create_sample_zip(filename: str = "app/main.py", content: str = SAMPLE_FASTAPI_SOURCE) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr(filename, content)
    return buf.getvalue()


def test_scan_creation_and_completion_flow() -> None:
    spec_bytes = SAMPLE_SPEC_YAML.encode("utf-8")
    zip_bytes = create_sample_zip()

    response = client.post(
        "/api/v1/scans",
        files={
            "openapi_file": ("openapi.yaml", spec_bytes, "application/x-yaml"),
            "source_archive": ("source.zip", zip_bytes, "application/zip"),
        },
        data={"project_name": "API Test Suite Project"},
    )

    assert response.status_code == 202

    data = response.json()
    assert "scan_id" in data
    assert data["status"] in ("queued", "completed")
    assert data["project_name"] == "API Test Suite Project"

    scan_id = data["scan_id"]

    # Retrieve status endpoint
    status_resp = client.get(f"/api/v1/scans/{scan_id}")
    assert status_resp.status_code == 200
    status_data = status_resp.json()
    assert status_data["scan_id"] == scan_id

    assert status_data["status"] == "completed"
    assert status_data["spec_hash"] is not None
    assert status_data["source_hash"] is not None

    # Retrieve /results endpoint
    results_resp = client.get(f"/api/v1/scans/{scan_id}/results")
    assert results_resp.status_code == 200
    results_data = results_resp.json()
    assert results_data["scan_id"] == scan_id
    assert "metrics_summary" in results_data
    assert "matched_endpoints" in results_data

    # Retrieve /findings endpoint
    findings_resp = client.get(f"/api/v1/scans/{scan_id}/findings")
    assert findings_resp.status_code == 200
    findings_data = findings_resp.json()
    assert findings_data["scan_id"] == scan_id
    assert "spec_only_findings" in findings_data
    assert "source_only_findings" in findings_data
    assert "correlated_findings" in findings_data

    # Retrieve /report endpoint (JSON)
    json_report_resp = client.get(f"/api/v1/scans/{scan_id}/report?format=json")
    assert json_report_resp.status_code == 200
    json_report = json_report_resp.json()
    assert "scan" in json_report
    assert "metrics_summary" in json_report

    # Retrieve /report endpoint (HTML)
    html_report_resp = client.get(f"/api/v1/scans/{scan_id}/report?format=html")
    assert html_report_resp.status_code == 200
    assert "text/html" in html_report_resp.headers["content-type"]
    assert "Intelligent API Security Analyzer" in html_report_resp.text


def test_scan_lifecycle_state_transitions() -> None:
    """Verify state transitions QUEUED -> RUNNING -> COMPLETED deterministically."""
    import uuid
    from collections.abc import Callable
    from concurrent.futures import Future
    from typing import Any

    from app.db.session import SessionLocal
    from app.jobs.runner import JobResult, JobRunner, JobStatus
    from app.repositories.scan import ScanRepository
    from app.services.scan_service import ScanService

    states_observed: list[str] = []

    class SpyJobRunner(JobRunner):
        def submit(
            self,
            job_id: str,
            func: Callable[[Any], Any],
            input_data: Any,
        ) -> Future[JobResult[Any]]:
            raise NotImplementedError

        def run(
            self,
            job_id: str,
            func: Callable[[Any], Any],
            input_data: Any,
            timeout: float | None = None,
        ) -> JobResult[Any]:
            db_session = SessionLocal()
            try:
                repo = ScanRepository(db_session)
                scan = repo.get_scan(uuid.UUID(job_id))
                if scan:
                    states_observed.append(scan.status)
            finally:
                db_session.close()

            # Delegate to actual worker
            res = func(input_data)
            return JobResult[Any](job_id=job_id, status=JobStatus.COMPLETED, result=res)

    db = SessionLocal()
    try:
        service = ScanService(db, job_runner=SpyJobRunner())
        spec_bytes = SAMPLE_SPEC_YAML.encode("utf-8")
        zip_bytes = create_sample_zip()

        # Check status right after creation vs during execution vs completion
        scan_id = service.create_and_submit_scan(
            project_name="Lifecycle Verification Project",
            spec_filename="openapi.yaml",
            spec_bytes=spec_bytes,
            source_filename="source.zip",
            source_bytes=zip_bytes,
        )

        repo = ScanRepository(db)
        final_scan = repo.get_scan(scan_id)
        assert final_scan is not None
        final_status = final_scan.status

        # Verification of state sequence
        assert len(states_observed) == 1
        running_state = states_observed[0]

        assert running_state == "RUNNING"
        assert final_status == "COMPLETED"
    finally:
        db.close()


def test_findings_preservation_spec_source_correlated() -> None:
    """Verify independent preservation of SPEC_ONLY, SOURCE_ONLY, and CORRELATED findings."""
    from app.analysis.correlation.models import (
        CorrelatedFinding,
        MultiLayerAnalysisResult,
    )
    from app.analysis.findings import Evidence, Finding, Severity
    from app.db.session import SessionLocal
    from app.repositories.scan import ScanRepository
    from app.schemas.worker import AnalysisWorkerOutput

    ev = Evidence(kind="TEST_KIND", message="Test evidence message")
    spec_finding = Finding(
        rule_id="SPEC-001",
        rule_version="1.0.0",
        title="Unauthenticated Endpoint",
        severity=Severity.HIGH,
        confidence=0.9,
        rationale="OpenAPI spec missing auth requirement",
        remediation="Add security requirement",
        evidence=(ev,),
    )
    source_finding = Finding(
        rule_id="SRC-001",
        rule_version="1.0.0",
        title="Hardcoded Secret in Code",
        severity=Severity.MEDIUM,
        confidence=0.8,
        rationale="Source AST found API key string",
        remediation="Move secret to env var",
        evidence=(ev,),
    )
    correlated_finding = CorrelatedFinding(
        rule_id="CORR-001",
        rule_version="1.0.0",
        title="Divergent Auth Control",
        severity=Severity.CRITICAL,
        confidence=0.95,
        rationale="Spec enforces bearer auth but source code missing auth decorator",
        remediation="Align spec and implementation",
        evidence=(ev,),
    )

    multi_layer_res = MultiLayerAnalysisResult(
        spec_only_findings=(spec_finding,),
        source_only_findings=(source_finding,),
        correlated_findings=(correlated_finding,),
        matched_endpoints=(),
        unmatched_spec_endpoints=(),
        unmatched_source_endpoints=(),
        metrics_summary={"total": 3},
    )

    db = SessionLocal()
    try:
        repo = ScanRepository(db)
        scan = repo.create_scan(
            project_name="Preservation Test Project",
            spec_filename="openapi.yaml",
            source_filename="source.zip",
        )
        worker_output = AnalysisWorkerOutput(
            scan_id=str(scan.id),
            result=multi_layer_res,
            error_message=None,
        )
        repo.save_worker_output(worker_output)

        # 1. Verify via GET /findings
        findings_resp = client.get(f"/api/v1/scans/{scan.id}/findings")
        assert findings_resp.status_code == 200
        fdata = findings_resp.json()

        assert len(fdata["spec_only_findings"]) == 1
        assert fdata["spec_only_findings"][0]["rule_id"] == "SPEC-001"

        assert len(fdata["source_only_findings"]) == 1
        assert fdata["source_only_findings"][0]["rule_id"] == "SRC-001"

        assert len(fdata["correlated_findings"]) == 1
        assert fdata["correlated_findings"][0]["rule_id"] == "CORR-001"

        # 2. Verify via GET /results
        results_resp = client.get(f"/api/v1/scans/{scan.id}/results")
        assert results_resp.status_code == 200
        rdata = results_resp.json()
        assert rdata["scan_id"] == str(scan.id)
        assert "metrics_summary" in rdata


        # 3. Verify via GET /report (JSON)
        json_report_resp = client.get(f"/api/v1/scans/{scan.id}/report?format=json")
        assert json_report_resp.status_code == 200
        jreport = json_report_resp.json()
        assert len(jreport["spec_only_findings"]) == 1
        assert len(jreport["source_only_findings"]) == 1
        assert len(jreport["correlated_findings"]) == 1


        # 4. Verify via GET /report (HTML)
        html_report_resp = client.get(f"/api/v1/scans/{scan.id}/report?format=html")
        assert html_report_resp.status_code == 200
        html_text = html_report_resp.text
        assert "Spec-Only" in html_text
        assert "Source-Only" in html_text
        assert "Correlated Evidence Findings" in html_text
        assert "CORR-001" in html_text


    finally:
        db.close()


def test_get_nonexistent_scan_404() -> None:
    fake_id = "00000000-0000-0000-0000-000000000000"
    assert client.get(f"/api/v1/scans/{fake_id}").status_code == 404
    assert client.get(f"/api/v1/scans/{fake_id}/results").status_code == 404
    assert client.get(f"/api/v1/scans/{fake_id}/findings").status_code == 404
    assert client.get(f"/api/v1/scans/{fake_id}/report").status_code == 404
