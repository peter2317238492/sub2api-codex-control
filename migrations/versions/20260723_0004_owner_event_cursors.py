"""Add commit-ordered browser event cursors per owner.

Revision ID: 20260723_0004
Revises: 20260713_0003
Create Date: 2026-07-23
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260723_0004"
down_revision: str | None = "20260713_0003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "event_owner_cursors",
        sa.Column("owner_user_id", sa.String(length=128), nullable=False),
        sa.Column("last_cursor", sa.BigInteger(), nullable=False),
        sa.Column(
            "minimum_resume_cursor",
            sa.BigInteger(),
            server_default=sa.text("0"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "last_cursor >= 0",
            name=op.f("ck_event_owner_cursors_nonnegative_last_cursor"),
        ),
        sa.CheckConstraint(
            "last_cursor <= 9223372036854775807",
            name=op.f("ck_event_owner_cursors_bounded_last_cursor"),
        ),
        sa.CheckConstraint(
            "minimum_resume_cursor >= 0",
            name=op.f("ck_event_owner_cursors_nonnegative_minimum_resume_cursor"),
        ),
        sa.CheckConstraint(
            "minimum_resume_cursor <= last_cursor",
            name=op.f("ck_event_owner_cursors_valid_resume_window"),
        ),
        sa.PrimaryKeyConstraint(
            "owner_user_id",
            name=op.f("pk_event_owner_cursors"),
        ),
    )
    op.add_column(
        "event_log",
        sa.Column("owner_cursor", sa.BigInteger(), nullable=True),
    )

    # Preserve every existing browser cursor exactly. Compacting to row numbers
    # would strand clients whose last durable cursor came from the global ID.
    op.execute("UPDATE event_log SET owner_cursor = id")
    op.alter_column("event_log", "owner_cursor", nullable=False)
    op.create_check_constraint(
        op.f("ck_event_log_positive_owner_cursor"),
        "event_log",
        "owner_cursor > 0",
    )
    op.create_check_constraint(
        op.f("ck_event_log_bounded_owner_cursor"),
        "event_log",
        "owner_cursor <= 9223372036854775807",
    )
    op.create_unique_constraint(
        "uq_event_log_owner_cursor",
        "event_log",
        ["owner_user_id", "owner_cursor"],
    )
    op.execute(
        """
        INSERT INTO event_owner_cursors (owner_user_id, last_cursor)
        SELECT owner_user_id, max(owner_cursor)
        FROM event_log
        GROUP BY owner_user_id
        """
    )


def downgrade() -> None:
    op.drop_constraint("uq_event_log_owner_cursor", "event_log", type_="unique")
    op.drop_constraint(
        op.f("ck_event_log_bounded_owner_cursor"),
        "event_log",
        type_="check",
    )
    op.drop_constraint(
        op.f("ck_event_log_positive_owner_cursor"),
        "event_log",
        type_="check",
    )
    op.drop_column("event_log", "owner_cursor")
    op.drop_table("event_owner_cursors")
