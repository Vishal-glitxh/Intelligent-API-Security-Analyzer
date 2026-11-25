import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import JSON, DateTime, ForeignKey, Index, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


class AuditEvent(Base):
    """Foundational audit event entity for security and operational events."""

    __tablename__ = "audit_events"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    action: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    actor: Mapped[str | None] = mapped_column(String(255), nullable=True)
    target_type: Mapped[str | None] = mapped_column(String(100), nullable=True)
    target_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    details: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        nullable=False,
    )


class Scan(Base):
    """Scan metadata entity tracking scan lifecycle, status, and versioning."""

    __tablename__ = "scans"
    __table_args__ = (Index("ix_scans_expired_lease", "status", "lease_expires_at"),)

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    project_name: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    spec_filename: Mapped[str] = mapped_column(String(255), nullable=False)
    source_filename: Mapped[str] = mapped_column(String(255), nullable=False)
    spec_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    source_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    engine_version: Mapped[str] = mapped_column(String(50), nullable=False, default="0.1.0")
    rule_set_version: Mapped[str] = mapped_column(String(50), nullable=False, default="0.1.0")
    config_version: Mapped[str] = mapped_column(String(50), nullable=False, default="1.0.0")
    client_id: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    spec_artifact_key: Mapped[str | None] = mapped_column(String(512), nullable=True)
    source_artifact_key: Mapped[str | None] = mapped_column(String(512), nullable=True)
    spec_content_type: Mapped[str] = mapped_column(
        String(128), nullable=False, default="application/octet-stream"
    )
    source_content_type: Mapped[str | None] = mapped_column(String(128), nullable=True)
    lease_owner: Mapped[str | None] = mapped_column(String(255), nullable=True)
    lease_token: Mapped[uuid.UUID | None] = mapped_column(nullable=True)
    lease_expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    attempt_count: Mapped[int] = mapped_column(default=0, server_default="0", nullable=False)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        nullable=False,
    )

    result: Mapped[ScanResult | None] = relationship(
        "ScanResult",
        back_populates="scan",
        uselist=False,
        cascade="all, delete-orphan",
    )


class CoordinationLock(Base):
    """Singleton rows used to serialize global admission decisions across replicas."""

    __tablename__ = "coordination_locks"

    lock_name: Mapped[str] = mapped_column(String(64), primary_key=True)


class UploadReservation(Base):
    """Shared expiring reservations for multipart upload admission."""

    __tablename__ = "upload_reservations"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    client_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC), nullable=False
    )


class ScanRateBucket(Base):
    """Shared fixed-window scan-rate bucket keyed by trusted client identity."""

    __tablename__ = "scan_rate_buckets"

    bucket_key: Mapped[str] = mapped_column(String(80), primary_key=True)
    window_started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    request_count: Mapped[int] = mapped_column(nullable=False)


class ScanResult(Base):
    """Scan analysis result entity persisting Phase 4 MultiLayerAnalysisResult as JSONB."""

    __tablename__ = "scan_results"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    scan_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True
    )
    metrics_summary: Mapped[dict[str, Any]] = mapped_column(
        JSON().with_variant(JSONB, "postgresql"), nullable=False
    )
    spec_only_findings: Mapped[list[dict[str, Any]]] = mapped_column(
        JSON().with_variant(JSONB, "postgresql"), nullable=False
    )
    source_only_findings: Mapped[list[dict[str, Any]]] = mapped_column(
        JSON().with_variant(JSONB, "postgresql"), nullable=False
    )
    correlated_findings: Mapped[list[dict[str, Any]]] = mapped_column(
        JSON().with_variant(JSONB, "postgresql"), nullable=False
    )
    matched_endpoints: Mapped[list[dict[str, Any]]] = mapped_column(
        JSON().with_variant(JSONB, "postgresql"), nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        nullable=False,
    )

    scan: Mapped[Scan] = relationship("Scan", back_populates="result")
