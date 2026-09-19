import uuid
from pathlib import Path

from app.db.session import SessionLocal
from app.repositories.scan import ScanRepository
from app.schemas.worker import AnalysisWorkerInput, AnalysisWorkerOutput
from app.services.analysis_worker import execute_analysis_worker


def test_worker_execution_invalid_spec(tmp_path: Path) -> None:
    invalid_input = AnalysisWorkerInput(
        scan_id=str(uuid.uuid4()),
        spec_content="invalid: yaml: [",
        source_dir=str(tmp_path),
    )

    output = execute_analysis_worker(invalid_input)
    assert output.result is None
    assert output.error_message is not None
    assert "OPENAPI_PARSING_ERROR" in output.error_message


def test_startup_scan_recovery() -> None:
    db = SessionLocal()
    try:
        repo = ScanRepository(db)
        scan = repo.create_scan(
            project_name="Interrupted Test Project",
            spec_filename="openapi.yaml",
            source_filename="source.zip",
        )
        scan_id = scan.id
        repo.update_status(scan_id, "RUNNING")

        recovered_count = repo.recover_interrupted_scans()
        assert recovered_count >= 1

        recovered_scan = repo.get_scan(scan_id)
        assert recovered_scan is not None
        assert recovered_scan.status == "FAILED"
        assert "SYSTEM_INTERRUPTED" in (recovered_scan.error_message or "")
    finally:
        db.close()


def test_save_worker_output_failure_handling() -> None:
    db = SessionLocal()
    try:
        repo = ScanRepository(db)
        scan = repo.create_scan(
            project_name="Worker Error Test",
            spec_filename="openapi.yaml",
            source_filename="source.zip",
        )

        error_output = AnalysisWorkerOutput(
            scan_id=str(scan.id),
            result=None,
            error_message="PROCESS_EXECUTION_ERROR: Worker process terminated unexpectedly",
        )

        res = repo.save_worker_output(error_output)
        assert res is None

        updated_scan = repo.get_scan(scan.id)
        assert updated_scan is not None
        assert updated_scan.status == "FAILED"
        assert "PROCESS_EXECUTION_ERROR" in (updated_scan.error_message or "")
    finally:
        db.close()


def test_worker_process_crash_handling() -> None:
    """Verify handling when worker process crashes / fails unexpectedly in job runner."""
    from collections.abc import Callable
    from concurrent.futures import Future
    from typing import Any

    from app.jobs.runner import JobResult, JobRunner, JobStatus
    from app.services.scan_service import SCRATCH_SCANS_DIR, ScanService

    class CrashingJobRunner(JobRunner):
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
            return JobResult[Any](
                job_id=job_id,
                status=JobStatus.FAILED,
                error="BrokenProcessPool: Worker process terminated unexpectedly",
            )

    db = SessionLocal()
    try:
        service = ScanService(db, job_runner=CrashingJobRunner())
        scan_id = service.create_and_submit_scan(
            project_name="Crash Test Project",
            spec_filename="openapi.yaml",
            spec_bytes=b"openapi: 3.0.0\ninfo:\n  title: T\n  version: 1.0\npaths: {}",
            source_filename="source.zip",
            source_bytes=b"PK\x05\x06" + b"\x00" * 18,  # Empty zip bytes
        )
        repo = ScanRepository(db)
        scan = repo.get_scan(scan_id)
        assert scan is not None
        assert scan.status == "FAILED"
        assert "PROCESS_EXECUTION_ERROR" in (scan.error_message or "")

        # Verify workspace cleaned up
        workspace_dir = SCRATCH_SCANS_DIR / str(scan_id)
        assert not workspace_dir.exists()
    finally:
        db.close()


def test_scan_execution_timeout_handling() -> None:
    """Verify handling when worker execution times out."""
    from collections.abc import Callable
    from concurrent.futures import Future
    from typing import Any

    from app.jobs.runner import JobResult, JobRunner, JobStatus
    from app.services.scan_service import SCRATCH_SCANS_DIR, ScanService

    class TimingOutJobRunner(JobRunner):
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
            return JobResult[Any](
                job_id=job_id,
                status=JobStatus.FAILED,
                error="TimeoutError: Job execution timed out after 300s",
            )

    db = SessionLocal()
    try:
        service = ScanService(db, job_runner=TimingOutJobRunner())
        scan_id = service.create_and_submit_scan(
            project_name="Timeout Test Project",
            spec_filename="openapi.yaml",
            spec_bytes=b"openapi: 3.0.0\ninfo:\n  title: T\n  version: 1.0\npaths: {}",
            source_filename="source.zip",
            source_bytes=b"PK\x05\x06" + b"\x00" * 18,
        )
        repo = ScanRepository(db)
        scan = repo.get_scan(scan_id)
        assert scan is not None
        assert scan.status == "FAILED"
        assert "TIMEOUT_EXCEEDED" in (scan.error_message or "")

        workspace_dir = SCRATCH_SCANS_DIR / str(scan_id)
        assert not workspace_dir.exists()
    finally:
        db.close()


def test_persistence_failure_handling() -> None:
    """Verify handling when DB persistence fails during scan result save."""
    from unittest.mock import patch

    from app.services.scan_service import SCRATCH_SCANS_DIR, ScanService
    from sqlalchemy.exc import SQLAlchemyError

    db = SessionLocal()
    try:
        service = ScanService(db)
        with patch.object(
            ScanRepository, "save_worker_output", side_effect=SQLAlchemyError("DB write failure")
        ):
            scan_id = service.create_and_submit_scan(
                project_name="Persistence Failure Test",
                spec_filename="openapi.yaml",
                spec_bytes=b"openapi: 3.0.3\ninfo:\n  title: Test\n  version: '1.0.0'\npaths: {}\n",
                source_filename="source.zip",
                source_bytes=b"PK\x05\x06" + b"\x00" * 18,
            )

            repo = ScanRepository(db)
            scan = repo.get_scan(scan_id)
            assert scan is not None
            assert scan.status == "FAILED"
            assert "PERSISTENCE_ERROR" in (scan.error_message or "")

            # Verify workspace cleaned up
            workspace_dir = SCRATCH_SCANS_DIR / str(scan_id)
            assert not workspace_dir.exists()
    finally:
        db.close()


def test_temporary_workspace_cleanup() -> None:
    """Verify temporary workspace scratch/scans/{scan_id} is deleted after processing."""
    from app.services.scan_service import SCRATCH_SCANS_DIR, ScanService

    db = SessionLocal()
    try:
        service = ScanService(db)
        scan_id = service.create_and_submit_scan(
            project_name="Cleanup Test Project",
            spec_filename="openapi.yaml",
            spec_bytes=b"openapi: 3.0.0\ninfo:\n  title: T\n  version: 1.0\npaths: {}",
            source_filename="source.zip",
            source_bytes=b"PK\x05\x06" + b"\x00" * 18,
        )

        workspace_dir = SCRATCH_SCANS_DIR / str(scan_id)
        assert not workspace_dir.exists()
    finally:
        db.close()
