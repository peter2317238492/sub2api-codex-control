"""Create the initial Control API data model.

Revision ID: 20260713_0001
Revises:
Create Date: 2026-07-13
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "20260713_0001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


UUID = postgresql.UUID(as_uuid=True)
JSONB = postgresql.JSONB(astext_type=sa.Text())
NOW = sa.text("CURRENT_TIMESTAMP")


def upgrade() -> None:
    op.create_table(
        "control_sessions",
        sa.Column("id", UUID, nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("csrf_token_hash", sa.String(length=64), nullable=False),
        sa.Column("sub2api_user_id", sa.String(length=128), nullable=False),
        sa.Column("username", sa.String(length=255), nullable=True),
        sa.Column("email", sa.String(length=320), nullable=True),
        sa.Column("display_name", sa.String(length=255), nullable=True),
        sa.Column("token_version", sa.String(length=64), nullable=True),
        sa.Column(
            "issued_at", sa.DateTime(timezone=True), server_default=NOW, nullable=False
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "last_seen_at",
            sa.DateTime(timezone=True),
            server_default=NOW,
            nullable=False,
        ),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("request_ip", sa.String(length=64), nullable=True),
        sa.Column("user_agent", sa.String(length=512), nullable=True),
        sa.CheckConstraint(
            "expires_at > issued_at", name=op.f("ck_control_sessions_valid_lifetime")
        ),
        sa.PrimaryKeyConstraint("id", name="pk_control_sessions"),
        sa.UniqueConstraint("token_hash", name="uq_control_sessions_token_hash"),
    )
    op.create_index(
        "ix_control_sessions_active_user",
        "control_sessions",
        ["sub2api_user_id", "expires_at", "revoked_at"],
    )
    op.create_index(
        "ix_control_sessions_expires_at", "control_sessions", ["expires_at"]
    )
    op.create_index(
        "ix_control_sessions_revoked_at", "control_sessions", ["revoked_at"]
    )
    op.create_index(
        "ix_control_sessions_sub2api_user_id", "control_sessions", ["sub2api_user_id"]
    )

    op.create_table(
        "devices",
        sa.Column("id", UUID, nullable=False),
        sa.Column("owner_user_id", sa.String(length=128), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("public_key", sa.Text(), nullable=False),
        sa.Column("refresh_credential_hash", sa.String(length=64), nullable=True),
        sa.Column(
            "credential_version",
            sa.Integer(),
            server_default=sa.text("0"),
            nullable=False,
        ),
        sa.Column(
            "status", sa.String(length=16), server_default="active", nullable=False
        ),
        sa.Column(
            "device_metadata",
            JSONB,
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=NOW, nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=NOW, nullable=False
        ),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "credential_version >= 0",
            name=op.f("ck_devices_nonnegative_credential_version"),
        ),
        sa.CheckConstraint(
            "status IN ('active', 'revoked')", name=op.f("ck_devices_status")
        ),
        sa.PrimaryKeyConstraint("id", name="pk_devices"),
        sa.UniqueConstraint("public_key", name="uq_devices_public_key"),
        sa.UniqueConstraint(
            "refresh_credential_hash", name="uq_devices_refresh_credential_hash"
        ),
    )
    op.create_index("ix_devices_last_seen_at", "devices", ["last_seen_at"])
    op.create_index("ix_devices_owner_user_id", "devices", ["owner_user_id"])
    op.create_index("ix_devices_status", "devices", ["status"])

    op.create_table(
        "device_pairings",
        sa.Column("id", UUID, nullable=False),
        sa.Column("code_hash", sa.String(length=64), nullable=False),
        sa.Column("poll_token_hash", sa.String(length=64), nullable=False),
        sa.Column("public_key", sa.Text(), nullable=False),
        sa.Column("device_name", sa.String(length=255), nullable=False),
        sa.Column(
            "device_metadata",
            JSONB,
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column(
            "status", sa.String(length=16), server_default="pending", nullable=False
        ),
        sa.Column("claimed_by_user_id", sa.String(length=128), nullable=True),
        sa.Column("claimed_by_session_id", UUID, nullable=True),
        sa.Column("device_id", UUID, nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=NOW, nullable=False
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("claimed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("credential_delivered_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("source_ip", sa.String(length=64), nullable=True),
        sa.CheckConstraint(
            "expires_at > created_at",
            name=op.f("ck_device_pairings_valid_lifetime"),
        ),
        sa.CheckConstraint(
            "status IN ('pending', 'claimed', 'completed', 'expired', 'cancelled')",
            name=op.f("ck_device_pairings_status"),
        ),
        sa.ForeignKeyConstraint(
            ["claimed_by_session_id"],
            ["control_sessions.id"],
            name="fk_device_pairings_claimed_by_session_id_control_sessions",
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["device_id"],
            ["devices.id"],
            name="fk_device_pairings_device_id_devices",
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_device_pairings"),
        sa.UniqueConstraint("code_hash", name="uq_device_pairings_code_hash"),
        sa.UniqueConstraint("device_id", name="uq_device_pairings_device_id"),
        sa.UniqueConstraint(
            "poll_token_hash", name="uq_device_pairings_poll_token_hash"
        ),
    )
    op.create_index(
        "ix_device_pairings_claimed_by_user_id",
        "device_pairings",
        ["claimed_by_user_id"],
    )
    op.create_index("ix_device_pairings_expires_at", "device_pairings", ["expires_at"])
    op.create_index(
        "ix_device_pairings_expiry_status",
        "device_pairings",
        ["expires_at", "status"],
    )
    op.create_index("ix_device_pairings_status", "device_pairings", ["status"])

    op.create_table(
        "device_connections",
        sa.Column("id", UUID, nullable=False),
        sa.Column("device_id", UUID, nullable=False),
        sa.Column("connection_nonce", sa.String(length=128), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("appserver_epoch", sa.String(length=128), nullable=True),
        sa.Column(
            "connected_at",
            sa.DateTime(timezone=True),
            server_default=NOW,
            nullable=False,
        ),
        sa.Column(
            "last_heartbeat_at",
            sa.DateTime(timezone=True),
            server_default=NOW,
            nullable=False,
        ),
        sa.Column("disconnected_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("remote_address", sa.String(length=128), nullable=True),
        sa.Column("connector_version", sa.String(length=64), nullable=True),
        sa.Column("codex_version", sa.String(length=64), nullable=True),
        sa.Column(
            "connection_metadata",
            JSONB,
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "status IN ('connected', 'disconnected')",
            name=op.f("ck_device_connections_status"),
        ),
        sa.ForeignKeyConstraint(
            ["device_id"],
            ["devices.id"],
            name="fk_device_connections_device_id_devices",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_device_connections"),
        sa.UniqueConstraint(
            "connection_nonce", name="uq_device_connections_connection_nonce"
        ),
    )
    op.create_index(
        "ix_device_connections_appserver_epoch",
        "device_connections",
        ["appserver_epoch"],
    )
    op.create_index(
        "ix_device_connections_device_id", "device_connections", ["device_id"]
    )
    op.create_index(
        "ix_device_connections_last_heartbeat_at",
        "device_connections",
        ["last_heartbeat_at"],
    )
    op.create_index("ix_device_connections_status", "device_connections", ["status"])

    op.create_table(
        "thread_bindings",
        sa.Column("id", UUID, nullable=False),
        sa.Column("owner_user_id", sa.String(length=128), nullable=False),
        sa.Column("device_id", UUID, nullable=False),
        sa.Column("remote_thread_id", sa.String(length=255), nullable=False),
        sa.Column(
            "status", sa.String(length=16), server_default="active", nullable=False
        ),
        sa.Column("cwd", sa.Text(), nullable=True),
        sa.Column("appserver_epoch", sa.String(length=128), nullable=False),
        sa.Column(
            "last_event_sequence",
            sa.BigInteger(),
            server_default=sa.text("0"),
            nullable=False,
        ),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=NOW, nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=NOW, nullable=False
        ),
        sa.CheckConstraint(
            "last_event_sequence >= 0",
            name=op.f("ck_thread_bindings_nonnegative_event_sequence"),
        ),
        sa.CheckConstraint(
            "status IN ('active', 'closed', 'stale')",
            name=op.f("ck_thread_bindings_status"),
        ),
        sa.ForeignKeyConstraint(
            ["device_id"],
            ["devices.id"],
            name="fk_thread_bindings_device_id_devices",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_thread_bindings"),
        sa.UniqueConstraint(
            "device_id", "remote_thread_id", name="uq_thread_bindings_device_thread"
        ),
    )
    op.create_index(
        "ix_thread_bindings_owner_user_id", "thread_bindings", ["owner_user_id"]
    )
    op.create_index("ix_thread_bindings_status", "thread_bindings", ["status"])

    op.create_table(
        "commands",
        sa.Column("id", UUID, nullable=False),
        sa.Column("owner_user_id", sa.String(length=128), nullable=False),
        sa.Column("device_id", UUID, nullable=False),
        sa.Column("thread_binding_id", UUID, nullable=True),
        sa.Column("idempotency_key", sa.String(length=128), nullable=False),
        sa.Column("method", sa.String(length=128), nullable=False),
        sa.Column("payload", JSONB, nullable=False),
        sa.Column(
            "status", sa.String(length=24), server_default="queued", nullable=False
        ),
        sa.Column("appserver_epoch", sa.String(length=128), nullable=True),
        sa.Column("result", JSONB, nullable=True),
        sa.Column("error_code", sa.String(length=128), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=NOW, nullable=False
        ),
        sa.Column("dispatched_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("acknowledged_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "status IN ('queued', 'dispatched', 'acknowledged', 'succeeded', "
            "'failed', 'cancelled', 'expired')",
            name=op.f("ck_commands_status"),
        ),
        sa.ForeignKeyConstraint(
            ["device_id"],
            ["devices.id"],
            name="fk_commands_device_id_devices",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["thread_binding_id"],
            ["thread_bindings.id"],
            name="fk_commands_thread_binding_id_thread_bindings",
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_commands"),
        sa.UniqueConstraint(
            "owner_user_id", "idempotency_key", name="uq_commands_owner_idempotency"
        ),
    )
    op.create_index("ix_commands_appserver_epoch", "commands", ["appserver_epoch"])
    op.create_index("ix_commands_device_id", "commands", ["device_id"])
    op.create_index("ix_commands_expires_at", "commands", ["expires_at"])
    op.create_index("ix_commands_method", "commands", ["method"])
    op.create_index("ix_commands_owner_user_id", "commands", ["owner_user_id"])
    op.create_index("ix_commands_status", "commands", ["status"])
    op.create_index("ix_commands_thread_binding_id", "commands", ["thread_binding_id"])

    op.create_table(
        "approvals",
        sa.Column("id", UUID, nullable=False),
        sa.Column("owner_user_id", sa.String(length=128), nullable=False),
        sa.Column("device_id", UUID, nullable=False),
        sa.Column("command_id", UUID, nullable=True),
        sa.Column("decided_by_session_id", UUID, nullable=True),
        sa.Column("approval_kind", sa.String(length=128), nullable=False),
        sa.Column("request", JSONB, nullable=False),
        sa.Column(
            "status", sa.String(length=16), server_default="pending", nullable=False
        ),
        sa.Column("appserver_epoch", sa.String(length=128), nullable=False),
        sa.Column(
            "requested_at",
            sa.DateTime(timezone=True),
            server_default=NOW,
            nullable=False,
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("decided_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("decision_reason", sa.Text(), nullable=True),
        sa.CheckConstraint(
            "expires_at > requested_at", name=op.f("ck_approvals_valid_lifetime")
        ),
        sa.CheckConstraint(
            "status IN ('pending', 'approved', 'denied', 'expired', 'cancelled')",
            name=op.f("ck_approvals_status"),
        ),
        sa.ForeignKeyConstraint(
            ["command_id"],
            ["commands.id"],
            name="fk_approvals_command_id_commands",
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["decided_by_session_id"],
            ["control_sessions.id"],
            name="fk_approvals_decided_by_session_id_control_sessions",
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["device_id"],
            ["devices.id"],
            name="fk_approvals_device_id_devices",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_approvals"),
    )
    op.create_index("ix_approvals_appserver_epoch", "approvals", ["appserver_epoch"])
    op.create_index("ix_approvals_command_id", "approvals", ["command_id"])
    op.create_index("ix_approvals_device_id", "approvals", ["device_id"])
    op.create_index("ix_approvals_expires_at", "approvals", ["expires_at"])
    op.create_index("ix_approvals_owner_user_id", "approvals", ["owner_user_id"])
    op.create_index("ix_approvals_status", "approvals", ["status"])

    op.create_table(
        "event_log",
        sa.Column("id", sa.BigInteger(), sa.Identity(), nullable=False),
        sa.Column("owner_user_id", sa.String(length=128), nullable=False),
        sa.Column("device_id", UUID, nullable=False),
        sa.Column("thread_binding_id", UUID, nullable=True),
        sa.Column("sequence", sa.BigInteger(), nullable=False),
        sa.Column("event_type", sa.String(length=128), nullable=False),
        sa.Column("payload", JSONB, nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "ingested_at",
            sa.DateTime(timezone=True),
            server_default=NOW,
            nullable=False,
        ),
        sa.CheckConstraint(
            "sequence >= 0", name=op.f("ck_event_log_nonnegative_sequence")
        ),
        sa.ForeignKeyConstraint(
            ["device_id"],
            ["devices.id"],
            name="fk_event_log_device_id_devices",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["thread_binding_id"],
            ["thread_bindings.id"],
            name="fk_event_log_thread_binding_id_thread_bindings",
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_event_log"),
        sa.UniqueConstraint(
            "device_id", "sequence", name="uq_event_log_device_sequence"
        ),
    )
    op.create_index("ix_event_log_event_type", "event_log", ["event_type"])
    op.create_index("ix_event_log_ingested_at", "event_log", ["ingested_at"])
    op.create_index(
        "ix_event_log_owner_ingested", "event_log", ["owner_user_id", "ingested_at"]
    )
    op.create_index("ix_event_log_owner_user_id", "event_log", ["owner_user_id"])
    op.create_index(
        "ix_event_log_thread_binding_id", "event_log", ["thread_binding_id"]
    )

    op.create_table(
        "audit_events",
        sa.Column("id", sa.BigInteger(), sa.Identity(), nullable=False),
        sa.Column("actor_user_id", sa.String(length=128), nullable=True),
        sa.Column("actor_session_id", UUID, nullable=True),
        sa.Column("actor_device_id", UUID, nullable=True),
        sa.Column("action", sa.String(length=128), nullable=False),
        sa.Column("outcome", sa.String(length=16), nullable=False),
        sa.Column("resource_type", sa.String(length=128), nullable=True),
        sa.Column("resource_id", sa.String(length=255), nullable=True),
        sa.Column("request_id", sa.String(length=128), nullable=True),
        sa.Column("source_ip", sa.String(length=64), nullable=True),
        sa.Column("user_agent", sa.String(length=512), nullable=True),
        sa.Column(
            "metadata", JSONB, server_default=sa.text("'{}'::jsonb"), nullable=False
        ),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=NOW, nullable=False
        ),
        sa.CheckConstraint(
            "outcome IN ('succeeded', 'denied', 'failed')",
            name=op.f("ck_audit_events_outcome"),
        ),
        sa.ForeignKeyConstraint(
            ["actor_device_id"],
            ["devices.id"],
            name="fk_audit_events_actor_device_id_devices",
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["actor_session_id"],
            ["control_sessions.id"],
            name="fk_audit_events_actor_session_id_control_sessions",
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_audit_events"),
    )
    op.create_index("ix_audit_events_action", "audit_events", ["action"])
    op.create_index(
        "ix_audit_events_actor_device_id", "audit_events", ["actor_device_id"]
    )
    op.create_index(
        "ix_audit_events_actor_session_id", "audit_events", ["actor_session_id"]
    )
    op.create_index("ix_audit_events_actor_user_id", "audit_events", ["actor_user_id"])
    op.create_index("ix_audit_events_created_at", "audit_events", ["created_at"])
    op.create_index("ix_audit_events_outcome", "audit_events", ["outcome"])
    op.create_index("ix_audit_events_request_id", "audit_events", ["request_id"])
    op.create_index(
        "ix_audit_events_resource", "audit_events", ["resource_type", "resource_id"]
    )


def downgrade() -> None:
    op.drop_table("audit_events")
    op.drop_table("event_log")
    op.drop_table("approvals")
    op.drop_table("commands")
    op.drop_table("thread_bindings")
    op.drop_table("device_connections")
    op.drop_table("device_pairings")
    op.drop_table("devices")
    op.drop_table("control_sessions")
