"""Add realtime device, command, thread, and approval state.

Revision ID: 20260713_0002
Revises: 20260713_0001
Create Date: 2026-07-13
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "20260713_0002"
down_revision: str | None = "20260713_0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


JSONB = postgresql.JSONB(astext_type=sa.Text())


def upgrade() -> None:
    op.add_column(
        "device_pairings",
        sa.Column(
            "workspace_roots",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'[]'::jsonb"),
            nullable=False,
        ),
    )
    op.add_column(
        "devices",
        sa.Column(
            "workspace_roots",
            JSONB,
            server_default=sa.text("'[]'::jsonb"),
            nullable=False,
        ),
    )
    op.add_column(
        "devices",
        sa.Column(
            "model_catalog",
            JSONB,
            server_default=sa.text("'[]'::jsonb"),
            nullable=False,
        ),
    )
    op.add_column(
        "devices", sa.Column("model_catalog_updated_at", sa.DateTime(timezone=True))
    )
    op.add_column("devices", sa.Column("active_epoch", sa.String(length=128)))
    op.add_column(
        "devices", sa.Column("active_connection_nonce", sa.String(length=128))
    )
    op.add_column(
        "devices",
        sa.Column(
            "last_device_sequence",
            sa.BigInteger(),
            server_default=sa.text("0"),
            nullable=False,
        ),
    )
    op.add_column(
        "devices",
        sa.Column(
            "last_server_sequence",
            sa.BigInteger(),
            server_default=sa.text("0"),
            nullable=False,
        ),
    )
    op.add_column(
        "devices",
        sa.Column(
            "last_server_acked_sequence",
            sa.BigInteger(),
            server_default=sa.text("0"),
            nullable=False,
        ),
    )
    op.add_column(
        "devices",
        sa.Column(
            "last_event_sequence",
            sa.BigInteger(),
            server_default=sa.text("0"),
            nullable=False,
        ),
    )
    op.create_index("ix_devices_active_epoch", "devices", ["active_epoch"])
    op.create_index(
        "ix_devices_active_connection_nonce", "devices", ["active_connection_nonce"]
    )
    op.create_check_constraint(
        op.f("ck_devices_nonnegative_device_sequence"),
        "devices",
        "last_device_sequence >= 0",
    )
    op.create_check_constraint(
        op.f("ck_devices_nonnegative_server_sequence"),
        "devices",
        "last_server_sequence >= 0",
    )
    op.create_check_constraint(
        op.f("ck_devices_nonnegative_server_acked_sequence"),
        "devices",
        "last_server_acked_sequence >= 0",
    )
    op.create_check_constraint(
        op.f("ck_devices_nonnegative_event_sequence"),
        "devices",
        "last_event_sequence >= 0",
    )
    op.create_check_constraint(
        op.f("ck_devices_valid_server_ack"),
        "devices",
        "last_server_acked_sequence <= last_server_sequence",
    )

    op.add_column(
        "device_connections",
        sa.Column(
            "last_device_sequence",
            sa.BigInteger(),
            server_default=sa.text("0"),
            nullable=False,
        ),
    )
    op.add_column(
        "device_connections",
        sa.Column(
            "last_server_sequence",
            sa.BigInteger(),
            server_default=sa.text("0"),
            nullable=False,
        ),
    )
    op.add_column(
        "device_connections",
        sa.Column(
            "last_server_acked_sequence",
            sa.BigInteger(),
            server_default=sa.text("0"),
            nullable=False,
        ),
    )
    op.add_column(
        "device_connections", sa.Column("closed_reason", sa.String(length=255))
    )
    op.create_check_constraint(
        op.f("ck_device_connections_nonnegative_device_sequence"),
        "device_connections",
        "last_device_sequence >= 0",
    )
    op.create_check_constraint(
        op.f("ck_device_connections_nonnegative_server_sequence"),
        "device_connections",
        "last_server_sequence >= 0",
    )
    op.create_check_constraint(
        op.f("ck_device_connections_nonnegative_server_acked_sequence"),
        "device_connections",
        "last_server_acked_sequence >= 0",
    )

    op.alter_column("thread_bindings", "remote_thread_id", nullable=True)
    op.alter_column(
        "thread_bindings",
        "status",
        existing_type=sa.String(length=16),
        type_=sa.String(length=32),
        existing_nullable=False,
    )
    op.add_column(
        "thread_bindings",
        sa.Column(
            "title", sa.String(length=255), server_default="New thread", nullable=False
        ),
    )
    op.add_column(
        "thread_bindings",
        sa.Column("model", sa.String(length=128), server_default="", nullable=False),
    )
    op.add_column("thread_bindings", sa.Column("active_turn_id", sa.String(length=255)))
    op.add_column(
        "thread_bindings",
        sa.Column(
            "snapshot",
            JSONB,
            server_default=sa.text("'{\"messages\": []}'::jsonb"),
            nullable=False,
        ),
    )
    op.add_column("thread_bindings", sa.Column("last_error", sa.Text()))
    op.create_index(
        "ix_thread_bindings_active_turn_id", "thread_bindings", ["active_turn_id"]
    )
    op.drop_constraint(
        op.f("ck_thread_bindings_status"), "thread_bindings", type_="check"
    )
    op.execute("UPDATE thread_bindings SET status = 'idle' WHERE status = 'active'")
    op.alter_column("thread_bindings", "status", server_default="idle")
    op.create_check_constraint(
        op.f("ck_thread_bindings_status"),
        "thread_bindings",
        "status IN ('idle', 'running', 'waiting_for_approval', 'failed', 'closed', 'stale')",
    )

    op.add_column("commands", sa.Column("request_hash", sa.String(length=64)))
    op.execute(
        "UPDATE commands SET request_hash = repeat('0', 64) WHERE request_hash IS NULL"
    )
    op.alter_column("commands", "request_hash", nullable=False)
    op.drop_constraint(op.f("ck_commands_status"), "commands", type_="check")
    op.create_check_constraint(
        op.f("ck_commands_status"),
        "commands",
        "status IN ('queued', 'dispatched', 'acknowledged', 'succeeded', 'failed', "
        "'denied', 'cancelled', 'expired')",
    )

    op.add_column("approvals", sa.Column("external_command_id", sa.String(length=255)))
    op.add_column("approvals", sa.Column("summary", sa.String(length=512)))
    op.execute(
        "UPDATE approvals SET summary = 'Approval request' WHERE summary IS NULL"
    )
    op.alter_column("approvals", "summary", nullable=False)
    op.add_column(
        "approvals", sa.Column("decision_dispatched_at", sa.DateTime(timezone=True))
    )
    op.create_index(
        "ix_approvals_external_command_id", "approvals", ["external_command_id"]
    )


def downgrade() -> None:
    op.drop_index("ix_approvals_external_command_id", table_name="approvals")
    op.drop_column("approvals", "decision_dispatched_at")
    op.drop_column("approvals", "summary")
    op.drop_column("approvals", "external_command_id")

    op.drop_constraint(op.f("ck_commands_status"), "commands", type_="check")
    op.create_check_constraint(
        op.f("ck_commands_status"),
        "commands",
        "status IN ('queued', 'dispatched', 'acknowledged', 'succeeded', "
        "'failed', 'cancelled', 'expired')",
    )
    op.drop_column("commands", "request_hash")

    op.drop_constraint(
        op.f("ck_thread_bindings_status"), "thread_bindings", type_="check"
    )
    op.execute(
        "UPDATE thread_bindings SET status = 'stale' WHERE status NOT IN ('closed', 'stale')"
    )
    op.alter_column(
        "thread_bindings",
        "status",
        existing_type=sa.String(length=32),
        type_=sa.String(length=16),
        existing_nullable=False,
    )
    op.alter_column("thread_bindings", "status", server_default="active")
    op.create_check_constraint(
        op.f("ck_thread_bindings_status"),
        "thread_bindings",
        "status IN ('active', 'closed', 'stale')",
    )
    op.drop_index("ix_thread_bindings_active_turn_id", table_name="thread_bindings")
    op.drop_column("thread_bindings", "last_error")
    op.drop_column("thread_bindings", "snapshot")
    op.drop_column("thread_bindings", "active_turn_id")
    op.drop_column("thread_bindings", "model")
    op.drop_column("thread_bindings", "title")
    op.execute(
        "UPDATE thread_bindings SET remote_thread_id = 'downgrade:' || id::text "
        "WHERE remote_thread_id IS NULL"
    )
    op.alter_column("thread_bindings", "remote_thread_id", nullable=False)

    op.drop_constraint(
        op.f("ck_device_connections_nonnegative_server_acked_sequence"),
        "device_connections",
        type_="check",
    )
    op.drop_constraint(
        op.f("ck_device_connections_nonnegative_server_sequence"),
        "device_connections",
        type_="check",
    )
    op.drop_constraint(
        op.f("ck_device_connections_nonnegative_device_sequence"),
        "device_connections",
        type_="check",
    )
    op.drop_column("device_connections", "closed_reason")
    op.drop_column("device_connections", "last_server_acked_sequence")
    op.drop_column("device_connections", "last_server_sequence")
    op.drop_column("device_connections", "last_device_sequence")

    op.drop_constraint(op.f("ck_devices_valid_server_ack"), "devices", type_="check")
    op.drop_constraint(
        op.f("ck_devices_nonnegative_event_sequence"), "devices", type_="check"
    )
    op.drop_constraint(
        op.f("ck_devices_nonnegative_server_acked_sequence"),
        "devices",
        type_="check",
    )
    op.drop_constraint(
        op.f("ck_devices_nonnegative_server_sequence"), "devices", type_="check"
    )
    op.drop_constraint(
        op.f("ck_devices_nonnegative_device_sequence"), "devices", type_="check"
    )
    op.drop_index("ix_devices_active_connection_nonce", table_name="devices")
    op.drop_index("ix_devices_active_epoch", table_name="devices")
    op.drop_column("devices", "last_event_sequence")
    op.drop_column("devices", "last_server_acked_sequence")
    op.drop_column("devices", "last_server_sequence")
    op.drop_column("devices", "last_device_sequence")
    op.drop_column("devices", "active_connection_nonce")
    op.drop_column("devices", "active_epoch")
    op.drop_column("devices", "model_catalog_updated_at")
    op.drop_column("devices", "model_catalog")
    op.drop_column("devices", "workspace_roots")
    op.drop_column("device_pairings", "workspace_roots")
