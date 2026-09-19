import hashlib
import logging
import shutil
import uuid
from pathlib import Path

from app.jobs.runner import JobRunner, JobStatus, LocalProcessJobRunner
from app.repositories.scan import ScanRepository
from app.schemas.worker import AnalysisWorkerInput, AnalysisWorkerOutput
from app.services.analysis_worker import execute_analysis_worker, sanitize_error_message
from app.services.archive import extract_source_archive, validate_spec_upload
from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)

SCAN_TIMEOUT_SECONDS = 300.0  # 5 minutes boundary
SCRATCH_SCANS_DIR = Path("scratch/scans")


class ScanService:
    def __init__(self, db: Session, job_runner: JobRunner | None = None) -> None:
        self.db = db
        self.repo = ScanRepository(db)
        self.job_runner = job_runner or LocalProcessJobRunner(max_workers=2)

    def create_and_submit_scan(
        self,
        project_name: str,
        spec_filename: str,
        spec_bytes: bytes,
        source_filename: str,
        source_bytes: bytes,
    ) -> uuid.UUID:
        """Validate upload inputs, create scan record, extract archive, and launch execution."""
        # 1. Input Validation
        validate_spec_upload(spec_filename, spec_bytes)

        spec_content = spec_bytes.decode("utf-8", errors="replace")
        spec_hash = hashlib.sha256(spec_bytes).hexdigest()
        source_hash = hashlib.sha256(source_bytes).hexdigest()

        # 2. Create Scan ORM Record
        scan = self.repo.create_scan(
            project_name=project_name,
            spec_filename=spec_filename,
            source_filename=source_filename,
            spec_hash=spec_hash,
            source_hash=source_hash,
        )
        scan_id = scan.id
        workspace_dir = (SCRATCH_SCANS_DIR / str(scan_id)).resolve()
        workspace_dir.mkdir(parents=True, exist_ok=True)
        source_dir = workspace_dir / "source"

        try:
            # 3. Extract Archive
            extract_source_archive(source_bytes, source_dir)
        except Exception as e:
            # Cleanup workspace on extraction failure
            shutil.rmtree(workspace_dir, ignore_errors=True)
            sanitized_err = sanitize_error_message(e, "UNTRUSTED_ARCHIVE_REJECTED")
            self.repo.update_status(scan_id, "FAILED", error_message=sanitized_err)
            raise ValueError(sanitized_err) from e

        # 4. Prepare Worker Input DTO
        worker_input = AnalysisWorkerInput(
            scan_id=str(scan_id),
            spec_content=spec_content,
            source_dir=str(source_dir),
        )

        # 5. Process Job Execution
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

        try:
            job_result = self.job_runner.run(
                job_id=str(scan_id),
                func=execute_analysis_worker,
                input_data=worker_input,
                timeout=SCAN_TIMEOUT_SECONDS,
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
                        f"TIMEOUT_EXCEEDED: Scan execution exceeded "
                        f"{int(SCAN_TIMEOUT_SECONDS)} seconds"
                    )
                else:
                    first_line = raw_err.splitlines()[0] if raw_err else ""
                    sanitized_err = (
                        f"PROCESS_EXECUTION_ERROR: Worker process terminated "
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
