"""PostgreSQL-leased scan workers shared across API replicas."""

from __future__ import annotations

import logging
import threading
from pathlib import Path

from app.core.config import settings
from app.db.session import SessionLocal
from app.jobs.runner import JobStatus
from app.repositories.scan import ClaimedScan, ScanRepository
from app.schemas.worker import AnalysisWorkerInput, AnalysisWorkerOutput
from app.services.analysis_worker import execute_analysis_worker, sanitize_error_message
from app.services.archive import extract_source_archive
from app.services.artifact_storage import get_artifact_storage
from app.services.scan_service import SCRATCH_SCANS_DIR, get_default_job_runner

logger = logging.getLogger(__name__)


def _workspace_for(claim: ClaimedScan) -> Path:
    root = SCRATCH_SCANS_DIR.resolve()
    scan_directory = SCRATCH_SCANS_DIR / str(claim.scan_id)
    if scan_directory.is_symlink():
        raise ValueError("Scan workspace path is not a regular directory.")
    scan_directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    if scan_directory.resolve().parent != root:
        raise ValueError("Scan workspace path escaped the scratch directory.")
    path = scan_directory / str(claim.lease_token)
    if path.is_symlink():
        raise ValueError("Scan lease workspace path is not a regular directory.")
    path.mkdir(parents=True, exist_ok=True)
    if path.resolve().parent != scan_directory.resolve():
        raise ValueError("Scan lease workspace path escaped its scan directory.")
    return path


def process_one_claim(worker_id: str) -> bool:
    """Claim and execute at most one job; return whether a job was claimed."""
    lease_seconds = settings.scan_timeout_seconds + settings.scan_lease_grace_seconds
    with SessionLocal() as db:
        repo = ScanRepository(db)
        claim = repo.claim_next_scan(
            worker_id=worker_id,
            lease_seconds=lease_seconds,
            max_attempts=settings.scan_job_max_attempts,
        )
    if claim is None:
        return False

    storage = get_artifact_storage()
    terminal = False
    heartbeat_stop = threading.Event()
    heartbeat_interval = max(1.0, min(30.0, settings.scan_lease_grace_seconds / 3))

    def renew_lease() -> None:
        while not heartbeat_stop.wait(heartbeat_interval):
            try:
                with SessionLocal() as heartbeat_db:
                    if not ScanRepository(heartbeat_db).renew_claimed_scan(
                        claim.scan_id, claim.lease_token, lease_seconds
                    ):
                        logger.warning("Worker lease was fenced for scan %s.", claim.scan_id)
                        return
            except Exception as exc:
                logger.error("Could not renew worker lease (%s).", type(exc).__name__)

    heartbeat = threading.Thread(
        target=renew_lease,
        name=f"scan-lease-{claim.scan_id}",
        daemon=True,
    )
    heartbeat.start()
    try:
        workspace = _workspace_for(claim)
        source_dir = workspace / "source"
        if not claim.spec_artifact_key:
            raise ValueError("Queued scan is missing its OpenAPI artifact reference.")
        spec_bytes = storage.get(claim.spec_artifact_key, max_bytes=settings.max_spec_bytes)
        source_bytes = (
            storage.get(claim.source_artifact_key, max_bytes=settings.max_archive_bytes)
            if claim.source_artifact_key
            else b""
        )
        if source_bytes:
            extract_source_archive(
                source_bytes,
                source_dir,
                max_archive_size_bytes=settings.max_archive_bytes,
                max_uncompressed_total_bytes=settings.max_uncompressed_bytes,
                max_file_count=settings.max_files_per_scan,
                max_individual_file_bytes=settings.max_individual_file_bytes,
            )
        else:
            source_dir.mkdir(parents=True, exist_ok=True)

        worker_input = AnalysisWorkerInput(
            scan_id=str(claim.scan_id),
            spec_content=spec_bytes.decode("utf-8", errors="replace"),
            source_dir=str(source_dir),
        )
        result = get_default_job_runner().run(
            job_id=f"{claim.scan_id}:{claim.lease_token}",
            func=execute_analysis_worker,
            input_data=worker_input,
            timeout=settings.scan_timeout_seconds,
        )
        with SessionLocal() as db:
            repo = ScanRepository(db)
            if result.status == JobStatus.COMPLETED and isinstance(
                result.result, AnalysisWorkerOutput
            ):
                if result.result.error_message:
                    terminal = repo.fail_claimed_scan(
                        claim.scan_id,
                        claim.lease_token,
                        result.result.error_message,
                    )
                else:
                    saved = repo.save_worker_output(result.result, lease_token=claim.lease_token)
                    terminal = saved is not None
            else:
                raw_error = result.error or "Scan worker execution failed."
                if "TimeoutError" in raw_error or "timed out" in raw_error.lower():
                    error = sanitize_error_message(
                        Exception(
                            f"Scan execution exceeded {int(settings.scan_timeout_seconds)} seconds."
                        ),
                        "TIMEOUT_EXCEEDED",
                    )
                else:
                    error = sanitize_error_message(
                        Exception("Worker process terminated unexpectedly."),
                        "PROCESS_EXECUTION_ERROR",
                    )
                # A failed child is a terminal analysis outcome. Infrastructure failures
                # while fetching inputs are retried below; they are not scanner findings.
                terminal = repo.fail_claimed_scan(claim.scan_id, claim.lease_token, error)
                logger.warning(
                    "Scan worker process failed for %s (%s).",
                    claim.scan_id,
                    type(raw_error).__name__,
                )
    except Exception as exc:
        safe_error = sanitize_error_message(exc, "SCAN_INPUT_UNAVAILABLE")
        with SessionLocal() as db:
            ScanRepository(db).retry_claimed_scan(
                claim.scan_id,
                claim.lease_token,
                safe_error,
                settings.scan_job_max_attempts,
            )
        logger.warning("Scan job %s will be retried if attempts remain.", claim.scan_id)
    finally:
        heartbeat_stop.set()
        heartbeat.join(timeout=heartbeat_interval + 1)
        # Each lease has an isolated workspace so a stale worker cannot delete a
        # reclaimed worker's files after its lease expires.
        lease_workspace = SCRATCH_SCANS_DIR / str(claim.scan_id) / str(claim.lease_token)
        try:
            lease_workspace.resolve().relative_to(SCRATCH_SCANS_DIR.resolve())
            if lease_workspace.exists() and not lease_workspace.is_symlink():
                import shutil

                shutil.rmtree(lease_workspace)
            scan_directory = lease_workspace.parent
            if scan_directory.exists() and not scan_directory.is_symlink():
                try:
                    scan_directory.rmdir()
                except OSError:
                    # Another active/reclaimed lease may still own this scan directory.
                    pass
        except OSError, ValueError:
            logger.warning("Could not clean lease workspace for scan %s.", claim.scan_id)
        if terminal:
            for key in (claim.spec_artifact_key, claim.source_artifact_key):
                if key:
                    try:
                        storage.delete(key)
                    except Exception:
                        logger.warning("Could not clean terminal scan artifact %s.", claim.scan_id)
    return True
