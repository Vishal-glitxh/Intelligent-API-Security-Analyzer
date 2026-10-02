"""add client_id to scans

Revision ID: 7b8e1a9c3f2d
Revises: 3e61a4f881e2
Create Date: 2026-10-02 01:20:00.000000

"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa

revision: str = "7b8e1a9c3f2d"
down_revision: str | Sequence[str] | None = "3e61a4f881e2"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("scans", sa.Column("client_id", sa.String(length=255), nullable=True))
    op.create_index(op.f("ix_scans_client_id"), "scans", ["client_id"], unique=False)


def downgrade() -> None:
    op.drop_index(op.f("ix_scans_client_id"), table_name="scans")
    op.drop_column("scans", "client_id")
