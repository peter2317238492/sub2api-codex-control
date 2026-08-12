"""Index durable approval decisions awaiting Connector dispatch.

Revision ID: 20260730_0006
Revises: 20260723_0005
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "20260730_0006"
down_revision: str | None = "20260723_0005"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_index(
        "ix_approvals_undispatched",
        "approvals",
        ["status", "decision_dispatched_at", "id"],
    )


def downgrade() -> None:
    op.drop_index("ix_approvals_undispatched", table_name="approvals")
