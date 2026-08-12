"""Bind approval idempotency to the original device request.

Revision ID: 20260731_0008
Revises: 20260730_0007
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260731_0008"
down_revision: str | None = "20260730_0007"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

LEGACY_REQUEST_HASH = "0" * 64


def upgrade() -> None:
    # Historical rows cannot reconstruct details that a default-deny path
    # intentionally discarded. The sentinel can never authenticate a replay,
    # so those rows fail closed while all new requests store their real hash.
    op.add_column(
        "approvals",
        sa.Column(
            "request_hash",
            sa.String(length=64),
            nullable=False,
            server_default=sa.text(f"'{LEGACY_REQUEST_HASH}'"),
        ),
    )
    op.create_check_constraint(
        "ck_approvals_request_hash_length",
        "approvals",
        "length(request_hash) = 64",
    )
    op.alter_column("approvals", "request_hash", server_default=None)


def downgrade() -> None:
    op.drop_constraint(
        "ck_approvals_request_hash_length",
        "approvals",
        type_="check",
    )
    op.drop_column("approvals", "request_hash")
