import hashlib
import logging
import shutil
import uuid
from pathlib import Path

from app.core.config import settings
from app.jobs.runner import JobRunner, JobStatus, LocalProcessJobRunner
from app.repositories.scan import ScanRepository
from app.schemas.worker import AnalysisWorkerInput, AnalysisWorkerOutput
from app.services.analysis_worker import execute_analysis_worker, sanitize_error_message
from app.services.archive import (
    extract_source_archive,
    validate_source_archive_filename,
    validate_spec_upload,
)
from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)

SCRATCH_SCANS_DIR = Path("scratch/scans")

_shared_job_runner: JobRunner | None = None


def get_default_job_runner() -> JobRunner:
    """Retrieve or initialize the bounded process job runner singleton."""
    global _shared_job_runner
    if _shared_job_runner is None:
        _shared_job_runner = LocalProcessJobRunner(
            max_workers=settings.max_worker_processes,
            max_memory_bytes=settings.worker_max_memory_bytes,
        )
    return _shared_job_runner


def shutdown_default_job_runner(wait: bool = True) -> None:
    """Shutdown the shared process runner on application shutdown."""
    global _shared_job_runner
    if _shared_job_runner is not None and isinstance(_shared_job_runner, LocalProcessJobRunner):
        _shared_job_runner.shutdown(wait=wait)
        _shared_job_runner = None


class ScanService:
    def __init__(self, db: Session, job_runner: JobRunner | None = None) -> None:
        self.db = db
        self.repo = ScanRepository(db)
        self._owns_job_runner = job_runner is not None
        self.job_runner = job_runner or get_default_job_runner()

    def create_and_submit_scan(
        self,
        project_name: str,
        spec_filename: str,
        spec_bytes: bytes,
        source_filename: str,
        source_bytes: bytes,
        client_id: str | None = None,
    ) -> uuid.UUID:
        """Validate upload inputs, enforce queue limits, extract archive, and launch execution."""
        # 1. Capacity & Rate/Quota Controls
        active_total = self.repo.count_active_scans()
        if active_total >= settings.max_active_scans:
            raise ValueError(
                f"SCAN_QUEUE_CAPACITY_EXCEEDED: Maximum queue capacity reached "
                f"({active_total}/{settings.max_active_scans} active scans)."
            )

        if client_id:
            client_active = self.repo.count_client_active_scans(client_id)
            if client_active >= settings.max_concurrent_scans_per_client:
                raise ValueError(
                    f"CLIENT_CONCURRENCY_LIMIT_EXCEEDED: Client '{client_id}' already has "
                    f"{client_active} active scan(s) running or queued."
                )

        # 2. Input Validation against authoritative configuration
        validate_spec_upload(spec_filename, spec_bytes, settings.max_spec_bytes)
        validate_source_archive_filename(source_filename)

        spec_content = spec_bytes.decode("utf-8", errors="replace")
        spec_hash = hashlib.sha256(spec_bytes).hexdigest()
        source_hash = hashlib.sha256(source_bytes).hexdigest()

        # 3. Create Scan ORM Record
        scan = self.repo.create_scan(
            project_name=project_name,
            spec_filename=spec_filename,
            source_filename=source_filename,
            spec_hash=spec_hash,
            source_hash=source_hash,
            client_id=client_id,
        )
        scan_id = scan.id
        workspace_dir = (SCRATCH_SCANS_DIR / str(scan_id)).resolve()
        workspace_dir.mkdir(parents=True, exist_ok=True)
        source_dir = workspace_dir / "source"

        try:
            # 4. Extract Archive safely
            extract_source_archive(
                source_bytes,
                source_dir,
                max_archive_size_bytes=settings.max_archive_bytes,
                max_uncompressed_total_bytes=settings.max_uncompressed_bytes,
                max_file_count=settings.max_files_per_scan,
                max_individual_file_bytes=settings.max_individual_file_bytes,
            )
        except Exception as e:
            # Cleanup workspace on extraction failure
            shutil.rmtree(workspace_dir, ignore_errors=True)
            sanitized_err = sanitize_error_message(e, "UNTRUSTED_ARCHIVE_REJECTED")
            self.repo.update_status(scan_id, "FAILED", error_message=sanitized_err)
            raise ValueError(sanitized_err) from e

        # 5. Prepare Worker Input DTO
        worker_input = AnalysisWorkerInput(
            scan_id=str(scan_id),
            spec_content=spec_content,
            source_dir=str(source_dir),
        )

        # 6. Process Job Execution
        self._execute_scan_job(scan_id, worker_input, workspace_dir)

        return scan_id

    def _execute_scan_job(
        self,
        scan_id: uuid.UUID,
        worker_input: AnalysisWorkerInput,
        workspace_dir: Path,
    ) -> None:
        """Run analysis worker and persist output, ensuring workspace cleanup."""
        self.repo.update_status(scan_id, "RUNNING")

        timeout_sec = settings.scan_timeout_seconds
        try:
            job_result = self.job_runner.run(
                job_id=str(scan_id),
                func=execute_analysis_worker,
                input_data=worker_input,
                timeout=timeout_sec,
            )

            if job_result.status == JobStatus.COMPLETED and isinstance(
                job_result.result, AnalysisWorkerOutput
            ):
                worker_output: AnalysisWorkerOutput = job_result.result
                if worker_output.error_message:
                    self.repo.update_status(
                        scan_id, "FAILED", error_message=worker_output.error_message
                    )
                else:
                    try:
                        self.repo.save_worker_output(worker_output)
                    except Exception as exc:
                        logger.error("Failed to save scan results: %s", exc, exc_info=True)
                        err_msg = sanitize_error_message(exc, "PERSISTENCE_ERROR")
                        self.repo.update_status(scan_id, "FAILED", error_message=err_msg)

            elif job_result.status == JobStatus.FAILED:
                raw_err = job_result.error or "Worker execution failed"
                if "TimeoutError" in raw_err or "timed out" in raw_err.lower():
                    sanitized_err = (
                        f"TIMEOUT_EXCEEDED: Scan execution exceeded {int(timeout_sec)} seconds"
                    )
                else:
                    first_line = raw_err.splitlines()[0] if raw_err else ""
                    sanitized_err = (
                        "PROCESS_EXECUTION_ERROR: Worker process terminated "
                        f"unexpectedly ({first_line})"
                    )

                sanitized_err = sanitize_error_message(
                    Exception(sanitized_err), "PROCESS_EXECUTION_ERROR"
                )
                self.repo.update_status(scan_id, "FAILED", error_message=sanitized_err)

            else:
                self.repo.update_status(
                    scan_id,
                    "FAILED",
                    error_message="PROCESS_EXECUTION_ERROR: Unexpected job state",
                )

        except Exception as exc:
            logger.error("Unhandled scan execution exception: %s", exc, exc_info=True)
            sanitized_err = sanitize_error_message(exc, "PROCESS_EXECUTION_ERROR")
            self.repo.update_status(scan_id, "FAILED", error_message=sanitized_err)

        finally:
            # Guaranteed cleanup of sandboxed temporary workspace
            try:
                if workspace_dir.exists():
                    shutil.rmtree(workspace_dir)
            except Exception as cleanup_err:
                logger.warning(
                    "Failed to clean temporary workspace for scan %s: %s",
                    scan_id,
                    cleanup_err,
                )
            if self._owns_job_runner and isinstance(self.job_runner, LocalProcessJobRunner):
                self.job_runner.shutdown(wait=True)
