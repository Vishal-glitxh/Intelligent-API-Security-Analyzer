"""add durable scan leases, shared admission, and rate coordination

Revision ID: 2af81c6e9b40
Revises: 7b8e1a9c3f2d
Create Date: 2026-11-23
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "2af81c6e9b40"
down_revision: str | Sequence[str] | None = "7b8e1a9c3f2d"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("scans", sa.Column("spec_artifact_key", sa.String(512), nullable=True))
    op.add_column("scans", sa.Column("source_artifact_key", sa.String(512), nullable=True))
    op.add_column(
        "scans",
        sa.Column(
            "spec_content_type",
            sa.String(128),
            server_default="application/octet-stream",
            nullable=False,
        ),
    )
    op.add_column("scans", sa.Column("source_content_type", sa.String(128), nullable=True))
    op.add_column("scans", sa.Column("lease_owner", sa.String(255), nullable=True))
    op.add_column("scans", sa.Column("lease_token", postgresql.UUID(as_uuid=True), nullable=True))
    op.add_column("scans", sa.Column("lease_expires_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column(
        "scans", sa.Column("attempt_count", sa.Integer(), server_default="0", nullable=False)
    )
    op.create_index("ix_scans_expired_lease", "scans", ["status", "lease_expires_at"])

    op.create_table(
        "coordination_locks",
        sa.Column("lock_name", sa.String(64), primary_key=True),
    )
    op.bulk_insert(
        sa.table("coordination_locks", sa.column("lock_name", sa.String(64))),
        [{"lock_name": "scan-admission"}],
    )
    op.create_table(
        "upload_reservations",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("client_id", sa.String(255), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
    )
    op.create_index("ix_upload_reservations_client_id", "upload_reservations", ["client_id"])
    op.create_index("ix_upload_reservations_expires_at", "upload_reservations", ["expires_at"])
    op.create_table(
        "scan_rate_buckets",
        sa.Column("bucket_key", sa.String(80), primary_key=True),
        sa.Column("window_started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("request_count", sa.Integer(), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("scan_rate_buckets")
    op.drop_index("ix_upload_reservations_expires_at", table_name="upload_reservations")
    op.drop_index("ix_upload_reservations_client_id", table_name="upload_reservations")
    op.drop_table("upload_reservations")
    op.drop_table("coordination_locks")
    op.drop_index("ix_scans_expired_lease", table_name="scans")
    op.drop_column("scans", "attempt_count")
    op.drop_column("scans", "lease_expires_at")
    op.drop_column("scans", "lease_token")
    op.drop_column("scans", "lease_owner")
    op.drop_column("scans", "source_content_type")
    op.drop_column("scans", "spec_content_type")
    op.drop_column("scans", "source_artifact_key")
    op.drop_column("scans", "spec_artifact_key")
