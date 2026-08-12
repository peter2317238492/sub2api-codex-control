"""Add durable device outbox and scoped command idempotency.

Revision ID: 20260713_0003
Revises: 20260713_0002
Create Date: 2026-07-13
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260713_0003"
down_revision: str | None = "20260713_0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

UPGRADE_CURSOR_GUARD = """
DO $codex_control$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM devices
        WHERE last_server_sequence <> last_server_acked_sequence
    ) THEN
        RAISE EXCEPTION
            'cannot create durable outbox while server frames are unacknowledged';
    END IF;
END
$codex_control$
"""

DOWNGRADE_CURSOR_GUARD = """
DO $codex_control$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM devices
        WHERE last_server_sequence <> last_server_acked_sequence
    ) OR EXISTS (
        SELECT 1
        FROM device_outbox
        WHERE acked_at IS NULL
    ) THEN
        RAISE EXCEPTION
            'cannot drop durable outbox while server frames are unacknowledged';
    END IF;
END
$codex_control$
"""


def upgrade() -> None:
    op.execute(sa.text(UPGRADE_CURSOR_GUARD))
    # Repair databases that applied the original 0002 revision with VARCHAR(16).
    op.alter_column(
        "thread_bindings",
        "status",
        existing_type=sa.String(length=16),
        type_=sa.String(length=32),
        existing_nullable=False,
    )

    op.add_column(
        "commands",
        sa.Column(
            "idempotency_scope",
            sa.String(length=512),
            server_default="legacy",
            nullable=False,
        ),
    )
    op.drop_constraint("uq_commands_owner_idempotency", "commands", type_="unique")
    op.create_unique_constraint(
        "uq_commands_scoped_idempotency",
        "commands",
        ["owner_user_id", "device_id", "idempotency_scope", "idempotency_key"],
    )

    op.create_table(
        "device_outbox",
        sa.Column("device_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("sequence", sa.BigInteger(), nullable=False),
        sa.Column("encoded_envelope", sa.Text(), nullable=False),
        sa.Column(
            "ack_sequence",
            sa.BigInteger(),
            server_default=sa.text("0"),
            nullable=False,
        ),
        sa.Column("frame_type", sa.String(length=32), nullable=False),
        sa.Column("byte_size", sa.Integer(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.Column("retained_until", sa.DateTime(timezone=True), nullable=False),
        sa.Column("acked_at", sa.DateTime(timezone=True)),
        sa.CheckConstraint(
            "sequence > 0",
            name=op.f("ck_device_outbox_positive_sequence"),
        ),
        sa.CheckConstraint(
            "ack_sequence >= 0",
            name=op.f("ck_device_outbox_nonnegative_ack_sequence"),
        ),
        sa.CheckConstraint(
            "byte_size > 0",
            name=op.f("ck_device_outbox_positive_byte_size"),
        ),
        sa.CheckConstraint(
            "retained_until > created_at",
            name=op.f("ck_device_outbox_valid_retention"),
        ),
        sa.CheckConstraint(
            "acked_at IS NULL OR acked_at >= created_at",
            name=op.f("ck_device_outbox_valid_ack_time"),
        ),
        sa.CheckConstraint(
            "frame_type NOT IN ('hello', 'hello_ack')",
            name=op.f("ck_device_outbox_non_handshake_frame"),
        ),
        sa.ForeignKeyConstraint(
            ["device_id"],
            ["devices.id"],
            name=op.f("fk_device_outbox_device_id_devices"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint(
            "device_id",
            "sequence",
            name=op.f("pk_device_outbox"),
        ),
    )
    op.create_index(
        "ix_device_outbox_retained_until",
        "device_outbox",
        ["retained_until"],
    )
    op.create_index("ix_device_outbox_acked_at", "device_outbox", ["acked_at"])


def downgrade() -> None:
    op.execute(sa.text(DOWNGRADE_CURSOR_GUARD))
    op.drop_index("ix_device_outbox_acked_at", table_name="device_outbox")
    op.drop_index("ix_device_outbox_retained_until", table_name="device_outbox")
    op.drop_table("device_outbox")

    op.drop_constraint("uq_commands_scoped_idempotency", "commands", type_="unique")
    op.execute(
        """
        WITH ranked AS (
            SELECT
                id,
                row_number() OVER (
                    PARTITION BY owner_user_id, idempotency_key
                    ORDER BY created_at, id
                ) AS duplicate_number
            FROM commands
        )
        UPDATE commands AS command
        SET idempotency_key =
            left(command.idempotency_key, 85)
            || ':downgrade:'
            || replace(command.id::text, '-', '')
        FROM ranked
        WHERE command.id = ranked.id
          AND ranked.duplicate_number > 1
        """
    )
    op.create_unique_constraint(
        "uq_commands_owner_idempotency",
        "commands",
        ["owner_user_id", "idempotency_key"],
    )
    op.drop_column("commands", "idempotency_scope")

    # 0002 now defines VARCHAR(32), so its downgrade target keeps the widened type.
