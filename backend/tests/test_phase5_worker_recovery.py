import os
import time
import uuid
from pathlib import Path

import pytest
from app.db.session import SessionLocal
from app.repositories.scan import ScanRepository
from app.schemas.worker import AnalysisWorkerInput, AnalysisWorkerOutput
from app.services.analysis_worker import execute_analysis_worker


def _blocking_scan_worker(input_data: AnalysisWorkerInput) -> AnalysisWorkerOutput:
    """Child-process fixture that records its PID and remains active until killed."""
    source_dir = Path(input_data.source_dir)
    marker = source_dir.parent.parent / f"{input_data.scan_id}.pid"
    marker.write_text(
        f"{os.getpid()}:{source_dir.is_dir()}",
        encoding="utf-8",
    )
    while True:
        time.sleep(0.05)


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

        recovered_ids = repo.recover_interrupted_scans()
        assert scan_id in recovered_ids

        recovered_scan = repo.get_scan(scan_id)
        assert recovered_scan is not None
        assert recovered_scan.status == "FAILED"
        assert "SYSTEM_INTERRUPTED" in (recovered_scan.error_message or "")
    finally:
        db.close()


def test_startup_recovery_removes_only_recovered_workspaces(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from app.services import scan_service

    monkeypatch.setattr(scan_service, "SCRATCH_SCANS_DIR", tmp_path)
    db = SessionLocal()
    try:
        repo = ScanRepository(db)
        interrupted = repo.create_scan(
            project_name="Interrupted Workspace",
            spec_filename="openapi.yaml",
            source_filename="source.zip",
        )
        repo.update_status(interrupted.id, "RUNNING")
        completed = repo.create_scan(
            project_name="Completed Workspace",
            spec_filename="openapi.yaml",
            source_filename="source.zip",
        )
        repo.update_status(completed.id, "COMPLETED")
        interrupted_path = tmp_path / str(interrupted.id)
        completed_path = tmp_path / str(completed.id)
        interrupted_path.mkdir()
        completed_path.mkdir()

        recovered_ids = repo.recover_interrupted_scans()
        for recovered_id in recovered_ids:
            scan_service.cleanup_scan_workspace(recovered_id)

        assert interrupted.id in recovered_ids
        assert not interrupted_path.exists()
        assert completed_path.exists()
    finally:
        db.close()


def test_workspace_cleanup_does_not_follow_symlink_to_another_scan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from app.services import scan_service

    monkeypatch.setattr(scan_service, "SCRATCH_SCANS_DIR", tmp_path)
    other_scan_id = uuid.uuid4()
    symlink_scan_id = uuid.uuid4()
    other_workspace = tmp_path / str(other_scan_id)
    symlink_workspace = tmp_path / str(symlink_scan_id)
    other_workspace.mkdir()
    (other_workspace / "keep.txt").write_text("active scan data", encoding="utf-8")
    symlink_workspace.symlink_to(other_workspace, target_is_directory=True)

    scan_service.cleanup_scan_workspace(symlink_scan_id)

    assert not symlink_workspace.exists()
    assert (other_workspace / "keep.txt").read_text(encoding="utf-8") == "active scan data"


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


def test_real_worker_timeout_terminates_child_before_workspace_cleanup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from app.jobs.runner import LocalProcessJobRunner
    from app.services import scan_service

    monkeypatch.setattr(scan_service, "SCRATCH_SCANS_DIR", tmp_path)
    # Allow Python's spawn startup and module import to complete before the analysis
    # timeout begins to exercise the intentionally non-terminating worker function.
    monkeypatch.setattr("app.services.scan_service.settings.scan_timeout_seconds", 2.0)
    monkeypatch.setattr(scan_service, "execute_analysis_worker", _blocking_scan_worker)
    db = SessionLocal()
    try:
        service = scan_service.ScanService(db, job_runner=LocalProcessJobRunner(max_workers=1))
        scan_id = service.create_and_submit_scan(
            project_name="Real Child Timeout Test",
            spec_filename="openapi.yaml",
            spec_bytes=b"openapi: 3.0.3\ninfo: {title: Test, version: '1.0'}\npaths: {}\n",
            source_filename="source.zip",
            source_bytes=b"PK\x05\x06" + b"\x00" * 18,
        )

        marker = tmp_path / f"{scan_id}.pid"
        scan = ScanRepository(db).get_scan(scan_id)
        assert scan is not None
        assert marker.is_file(), scan.error_message
        pid_text, workspace_was_present = marker.read_text(encoding="utf-8").split(":")
        assert workspace_was_present == "True"
        with pytest.raises(ProcessLookupError):
            os.kill(int(pid_text), 0)

        assert scan.status == "FAILED"
        assert "TIMEOUT_EXCEEDED" in (scan.error_message or "")
        assert not (tmp_path / str(scan_id)).exists()
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
