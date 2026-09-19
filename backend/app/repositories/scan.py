import uuid
from datetime import UTC, datetime
from typing import Any

from app.analysis.correlation import MultiLayerAnalysisResult
from app.db.models import AuditEvent, Scan, ScanResult
from app.schemas.worker import AnalysisWorkerOutput
from sqlalchemy import select, update
from sqlalchemy.orm import Session


def _serialize_evidence(evidence_tuple: tuple[Any, ...]) -> list[dict[str, Any]]:
    return [
        {
            "kind": getattr(e, "kind", ""),
            "message": getattr(e, "message", ""),
            "location": getattr(e, "location", None),
        }
        for e in evidence_tuple
    ]


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

    return {
        "rule_id": getattr(corr, "rule_id", ""),
        "rule_version": getattr(corr, "rule_version", "1.0.0"),
        "title": getattr(corr, "title", ""),
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
    ) -> Scan:
        scan = Scan(
            project_name=project_name,
            status="QUEUED",
            spec_filename=spec_filename,
            source_filename=source_filename,
            spec_hash=spec_hash,
            source_hash=source_hash,
        )
        self.db.add(scan)
        self.db.commit()
        self.db.refresh(scan)
        return scan

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

    def save_worker_output(self, worker_output: AnalysisWorkerOutput) -> ScanResult | None:
        """Persist AnalysisWorkerOutput to database updating Scan status & ScanResult."""
        scan_uuid = uuid.UUID(worker_output.scan_id)
        scan = self.get_scan(scan_uuid)
        if not scan:
            return None

        now = datetime.now(UTC)

        if worker_output.error_message or worker_output.result is None:
            err_msg = (
                worker_output.error_message or "PROCESS_EXECUTION_ERROR: Worker produced no result"
            )
            scan.status = "FAILED"
            scan.error_message = err_msg
            scan.completed_at = now
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

    def recover_interrupted_scans(self) -> int:
        """Recover scans stuck in QUEUED or RUNNING states at application startup."""
        stmt = (
            update(Scan)
            .where(Scan.status.in_(["QUEUED", "RUNNING"]))
            .values(
                status="FAILED",
                error_message="SYSTEM_INTERRUPTED: Scan halted by application restart",
                completed_at=datetime.now(UTC),
            )
        )
        result = self.db.execute(stmt)
        self.db.commit()
        return int(getattr(result, "rowcount", 0))
