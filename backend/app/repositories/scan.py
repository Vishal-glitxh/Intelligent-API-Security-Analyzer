import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from app.analysis.correlation import MultiLayerAnalysisResult
from app.db.models import AuditEvent, CoordinationLock, Scan, ScanRateBucket, ScanResult
from app.schemas.worker import AnalysisWorkerOutput
from sqlalchemy import case, delete, func, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session


@dataclass(frozen=True)
class ClaimedScan:
    scan_id: uuid.UUID
    lease_token: uuid.UUID
    spec_artifact_key: str
    source_artifact_key: str | None
    spec_filename: str
    source_filename: str
    spec_hash: str | None
    client_id: str | None


class ScanCapacityError(ValueError):
    pass


def _serialize_evidence(evidence_tuple: tuple[Any, ...]) -> list[dict[str, Any]]:
    serialized: list[dict[str, Any]] = []
    for evidence in evidence_tuple:
        location = getattr(evidence, "location", None)
        file_path = getattr(evidence, "file", None) or getattr(location, "file", None)
        line = getattr(evidence, "line", None) or getattr(location, "line", None)
        column = getattr(evidence, "column", None) or getattr(location, "column", None)
        end_line = getattr(location, "end_line", None)
        end_column = getattr(location, "end_column", None)
        serialized.append(
            {
                "kind": getattr(evidence, "kind", getattr(evidence, "category", "")),
                "message": getattr(evidence, "message", ""),
                "file": file_path,
                "line": line,
                "column": column,
                "end_line": end_line,
                "end_column": end_column,
                "source_hash": getattr(evidence, "source_hash", None),
                "provenance": getattr(evidence, "provenance", None),
                "location": {
                    "file": file_path,
                    "line": line,
                    "column": column,
                    "end_line": end_line,
                    "end_column": end_column,
                }
                if file_path or line or column
                else None,
            }
        )
    return serialized


def _serialize_finding(finding: Any) -> dict[str, Any]:
    sev = getattr(finding, "severity", "")
    sev_str = sev.value if hasattr(sev, "value") else str(sev)

    return {
        "rule_id": getattr(finding, "rule_id", ""),
        "rule_version": getattr(finding, "rule_version", "1.0.0"),
        "title": getattr(finding, "title", ""),
        "severity": sev_str,
        "confidence": getattr(finding, "confidence", 1.0),
        "rationale": getattr(finding, "rationale", ""),
        "remediation": getattr(finding, "remediation", ""),
        "evidence": _serialize_evidence(getattr(finding, "evidence", ())),
    }


def _serialize_matched_endpoint(endpoint: Any) -> dict[str, Any] | None:
    if endpoint is None:
        return None
    tier = getattr(endpoint, "match_tier", "")
    tier_str = tier.value if hasattr(tier, "value") else str(tier)

    return {
        "spec_path": getattr(endpoint, "spec_path", ""),
        "spec_method": getattr(endpoint, "spec_method", ""),
        "source_path": getattr(endpoint, "source_path", ""),
        "source_method": getattr(endpoint, "source_method", ""),
        "match_tier": tier_str,
        "rationale": getattr(endpoint, "rationale", ""),
    }


def _serialize_correlated_finding(corr: Any) -> dict[str, Any]:
    state = getattr(corr, "correlation_state", "")
    state_str = state.value if hasattr(state, "value") else str(state)
    severity = getattr(corr, "severity", "")
    severity_str = severity.value if hasattr(severity, "value") else str(severity)

    return {
        "rule_id": getattr(corr, "rule_id", ""),
        "rule_version": getattr(corr, "rule_version", "1.0.0"),
        "title": getattr(corr, "title", ""),
        "severity": severity_str,
        "confidence": getattr(corr, "confidence", 1.0),
        "evidence": _serialize_evidence(tuple(getattr(corr, "evidence", ()))),
        "correlation_state": state_str,
        "matched_endpoint": _serialize_matched_endpoint(getattr(corr, "matched_endpoint", None)),
        "spec_findings": [_serialize_finding(f) for f in getattr(corr, "spec_findings", ())],
        "source_findings": [_serialize_finding(f) for f in getattr(corr, "source_findings", ())],
        "rationale": getattr(corr, "rationale", ""),
        "remediation": getattr(corr, "remediation", ""),
    }


class ScanRepository:
    def __init__(self, db: Session) -> None:
        self.db = db

    def create_scan(
        self,
        project_name: str,
        spec_filename: str,
        source_filename: str,
        spec_hash: str | None = None,
        source_hash: str | None = None,
        client_id: str | None = None,
        scan_id: uuid.UUID | None = None,
        spec_artifact_key: str | None = None,
        source_artifact_key: str | None = None,
        spec_content_type: str = "application/octet-stream",
        source_content_type: str | None = None,
    ) -> Scan:
        scan = Scan(
            id=scan_id or uuid.uuid4(),
            project_name=project_name,
            status="QUEUED",
            spec_filename=spec_filename,
            source_filename=source_filename,
            spec_hash=spec_hash,
            source_hash=source_hash,
            client_id=client_id,
            spec_artifact_key=spec_artifact_key,
            source_artifact_key=source_artifact_key,
            spec_content_type=spec_content_type,
            source_content_type=source_content_type,
        )
        self.db.add(scan)
        self.db.commit()
        self.db.refresh(scan)
        return scan

    def enqueue_scan(
        self,
        *,
        scan_id: uuid.UUID,
        project_name: str,
        spec_filename: str,
        source_filename: str,
        spec_hash: str,
        source_hash: str | None,
        client_id: str,
        spec_artifact_key: str,
        source_artifact_key: str | None,
        spec_content_type: str,
        source_content_type: str | None,
        max_active: int,
        max_per_client: int,
    ) -> Scan:
        """Atomically enforce shared capacity and persist a durable queued scan."""
        lock = self.db.scalar(
            select(CoordinationLock)
            .where(CoordinationLock.lock_name == "scan-admission")
            .with_for_update()
        )
        if lock is None:
            raise RuntimeError("Shared scan admission migration is not installed.")
        active_total = self.count_active_scans()
        if active_total >= max_active:
            raise ScanCapacityError(
                "SCAN_QUEUE_CAPACITY_EXCEEDED: Maximum queue capacity reached "
                f"({active_total}/{max_active} active scans)."
            )
        active_client = self.count_client_active_scans(client_id)
        if active_client >= max_per_client:
            raise ScanCapacityError("CLIENT_CONCURRENCY_LIMIT_EXCEEDED: Client scan limit reached.")
        scan = Scan(
            id=scan_id,
            project_name=project_name,
            status="QUEUED",
            spec_filename=spec_filename,
            source_filename=source_filename,
            spec_hash=spec_hash,
            source_hash=source_hash,
            client_id=client_id,
            spec_artifact_key=spec_artifact_key,
            source_artifact_key=source_artifact_key,
            spec_content_type=spec_content_type,
            source_content_type=source_content_type,
        )
        self.db.add(scan)
        self.db.commit()
        self.db.refresh(scan)
        return scan

    def claim_next_scan(
        self, *, worker_id: str, lease_seconds: float, max_attempts: int
    ) -> ClaimedScan | None:
        """Claim one queued or expired job using PostgreSQL row-lock skipping."""
        self.db.execute(
            update(Scan)
            .where(
                Scan.status == "RUNNING",
                Scan.lease_expires_at <= func.now(),
                Scan.attempt_count >= max_attempts,
            )
            .values(
                status="FAILED",
                error_message="WORKER_RETRY_LIMIT: Scan worker lease expired too many times.",
                completed_at=func.now(),
                lease_owner=None,
                lease_token=None,
                lease_expires_at=None,
            )
        )
        self.db.flush()
        scan = self.db.scalar(
            select(Scan)
            .where(
                (Scan.status == "QUEUED")
                | (
                    (Scan.status == "RUNNING")
                    & (Scan.lease_expires_at <= func.now())
                    & (Scan.attempt_count < max_attempts)
                )
            )
            .order_by(Scan.created_at)
            .limit(1)
            .with_for_update(skip_locked=True)
        )
        if scan is None:
            self.db.commit()
            return None
        token = uuid.uuid4()
        scan.status = "RUNNING"
        scan.lease_owner = worker_id
        scan.lease_token = token
        scan.lease_expires_at = func.now() + func.make_interval(0, 0, 0, 0, 0, 0, lease_seconds)
        scan.attempt_count += 1
        scan.started_at = scan.started_at or func.now()
        self.db.commit()
        return ClaimedScan(
            scan_id=scan.id,
            lease_token=token,
            spec_artifact_key=scan.spec_artifact_key or "",
            source_artifact_key=scan.source_artifact_key,
            spec_filename=scan.spec_filename,
            source_filename=scan.source_filename,
            spec_hash=scan.spec_hash,
            client_id=scan.client_id,
        )

    def retry_claimed_scan(
        self, scan_id: uuid.UUID, lease_token: uuid.UUID, error_message: str, max_attempts: int
    ) -> bool:
        scan = self.db.scalar(select(Scan).where(Scan.id == scan_id).with_for_update())
        if scan is None or scan.status != "RUNNING" or scan.lease_token != lease_token:
            self.db.rollback()
            return False
        if scan.attempt_count < max_attempts:
            scan.status = "QUEUED"
            scan.error_message = error_message
            scan.lease_owner = None
            scan.lease_token = None
            scan.lease_expires_at = None
            scan.started_at = None
        else:
            scan.status = "FAILED"
            scan.error_message = error_message
            scan.completed_at = func.now()
            scan.lease_owner = None
            scan.lease_token = None
            scan.lease_expires_at = None
        self.db.commit()
        return True

    def renew_claimed_scan(
        self, scan_id: uuid.UUID, lease_token: uuid.UUID, lease_seconds: float
    ) -> bool:
        result = self.db.execute(
            update(Scan)
            .where(
                Scan.id == scan_id,
                Scan.status == "RUNNING",
                Scan.lease_token == lease_token,
            )
            .values(
                lease_expires_at=func.now() + func.make_interval(0, 0, 0, 0, 0, 0, lease_seconds)
            )
            .returning(Scan.id)
        )
        self.db.commit()
        return result.scalar_one_or_none() is not None

    def fail_claimed_scan(
        self, scan_id: uuid.UUID, lease_token: uuid.UUID, error_message: str
    ) -> bool:
        scan = self.db.scalar(select(Scan).where(Scan.id == scan_id).with_for_update())
        if scan is None or scan.status != "RUNNING" or scan.lease_token != lease_token:
            self.db.rollback()
            return False
        scan.status = "FAILED"
        scan.error_message = error_message
        scan.completed_at = func.now()
        scan.lease_owner = None
        scan.lease_token = None
        scan.lease_expires_at = None
        self.db.commit()
        return True

    def count_active_scans(self) -> int:
        """Count total scans currently in QUEUED or RUNNING states."""
        stmt = select(func.count()).select_from(Scan).where(Scan.status.in_(["QUEUED", "RUNNING"]))
        return int(self.db.scalar(stmt) or 0)

    def count_client_active_scans(self, client_id: str) -> int:
        """Count active scans currently queued or running for a specific client."""
        stmt = (
            select(func.count())
            .select_from(Scan)
            .where(Scan.client_id == client_id, Scan.status.in_(["QUEUED", "RUNNING"]))
        )
        return int(self.db.scalar(stmt) or 0)

    def consume_rate_limit(self, bucket_key: str, window_seconds: int, maximum: int) -> bool:
        """Atomically consume a shared PostgreSQL fixed-window rate-limit slot."""
        interval = func.make_interval(0, 0, 0, 0, 0, 0, window_seconds)
        expired = ScanRateBucket.window_started_at <= func.now() - interval
        self.db.execute(delete(ScanRateBucket).where(expired))
        statement = (
            pg_insert(ScanRateBucket)
            .values(
                bucket_key=bucket_key,
                window_started_at=func.now(),
                request_count=1,
            )
            .on_conflict_do_update(
                index_elements=[ScanRateBucket.bucket_key],
                set_={
                    "window_started_at": case(
                        (expired, func.now()), else_=ScanRateBucket.window_started_at
                    ),
                    "request_count": case(
                        (expired, 1),
                        (
                            ScanRateBucket.request_count < maximum + 1,
                            ScanRateBucket.request_count + 1,
                        ),
                        else_=maximum + 1,
                    ),
                },
            )
            .returning(ScanRateBucket.request_count)
        )
        count = self.db.scalar(statement)
        self.db.commit()
        return int(count or 0) <= maximum

    def list_scans(
        self,
        client_id: str | None = None,
        is_admin: bool = False,
        limit: int = 50,
    ) -> list[Scan]:
        """Retrieve recent scans ordered by creation date."""
        stmt = select(Scan).order_by(Scan.created_at.desc()).limit(limit)
        if not is_admin and client_id:
            stmt = stmt.where(Scan.client_id == client_id)
        return list(self.db.scalars(stmt).all())

    def get_scan(self, scan_id: uuid.UUID) -> Scan | None:
        stmt = select(Scan).where(Scan.id == scan_id)
        return self.db.scalar(stmt)

    def get_scan_with_result(self, scan_id: uuid.UUID) -> tuple[Scan, ScanResult | None] | None:
        scan = self.get_scan(scan_id)
        if not scan:
            return None
        stmt = select(ScanResult).where(ScanResult.scan_id == scan_id)
        result = self.db.scalar(stmt)
        return scan, result

    def update_status(
        self,
        scan_id: uuid.UUID,
        status: str,
        error_message: str | None = None,
        started_at: datetime | None = None,
        completed_at: datetime | None = None,
    ) -> None:
        values: dict[str, Any] = {"status": status}
        if error_message is not None:
            values["error_message"] = error_message
        if started_at is not None:
            values["started_at"] = started_at
        if completed_at is not None:
            values["completed_at"] = completed_at

        stmt = update(Scan).where(Scan.id == scan_id).values(**values)
        self.db.execute(stmt)
        self.db.commit()

    def save_worker_output(
        self, worker_output: AnalysisWorkerOutput, lease_token: uuid.UUID | None = None
    ) -> ScanResult | None:
        """Persist AnalysisWorkerOutput to database updating Scan status & ScanResult."""
        scan_uuid = uuid.UUID(worker_output.scan_id)
        scan = self.db.scalar(select(Scan).where(Scan.id == scan_uuid).with_for_update())
        if not scan:
            return None
        if lease_token is not None and (
            scan.status != "RUNNING" or scan.lease_token != lease_token
        ):
            self.db.rollback()
            return None

        now = datetime.now(UTC)

        if worker_output.error_message or worker_output.result is None:
            err_msg = (
                worker_output.error_message or "PROCESS_EXECUTION_ERROR: Worker produced no result"
            )
            scan.status = "FAILED"
            scan.error_message = err_msg
            scan.completed_at = now
            scan.lease_owner = None
            scan.lease_token = None
            scan.lease_expires_at = None
            self.db.commit()
            return None

        res: MultiLayerAnalysisResult = worker_output.result

        spec_only_dicts = [_serialize_finding(f) for f in res.spec_only_findings]
        source_only_dicts = [_serialize_finding(f) for f in res.source_only_findings]
        correlated_dicts = [_serialize_correlated_finding(c) for c in res.correlated_findings]
        matched_dicts = [
            d
            for d in (_serialize_matched_endpoint(m) for m in res.matched_endpoints)
            if d is not None
        ]

        scan_result = ScanResult(
            scan_id=scan_uuid,
            metrics_summary=res.metrics_summary,
            spec_only_findings=spec_only_dicts,
            source_only_findings=source_only_dicts,
            correlated_findings=correlated_dicts,
            matched_endpoints=matched_dicts,
        )

        scan.status = "COMPLETED"
        scan.completed_at = now
        scan.lease_owner = None
        scan.lease_token = None
        scan.lease_expires_at = None
        self.db.add(scan_result)

        # Audit Event logging
        audit_event = AuditEvent(
            action="SCAN_COMPLETED",
            target_type="SCAN",
            target_id=str(scan.id),
            details=(
                f"Scan for project '{scan.project_name}' completed successfully "
                f"in {worker_output.execution_time_seconds:.2f}s"
            ),
        )
        self.db.add(audit_event)

        self.db.commit()
        self.db.refresh(scan_result)
        return scan_result

    def recover_interrupted_scans(self) -> list[uuid.UUID]:
        """Mark active records failed and return their ids for workspace reconciliation."""
        stmt = (
            update(Scan)
            .where(Scan.status.in_(["QUEUED", "RUNNING"]))
            .values(
                status="FAILED",
                error_message="SYSTEM_INTERRUPTED: Scan halted by application restart",
                completed_at=datetime.now(UTC),
            )
            .returning(Scan.id)
        )
        interrupted_ids = list(self.db.scalars(stmt))
        self.db.commit()
        return interrupted_ids
