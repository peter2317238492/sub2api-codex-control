"""Add retention indexes and preserve immutable audit actor identifiers.

Revision ID: 20260723_0005
Revises: 20260723_0004
Create Date: 2026-07-23
"""

from collections.abc import Sequence

from alembic import op

revision: str = "20260723_0005"
down_revision: str | None = "20260723_0004"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

DOWNGRADE_AUDIT_REFERENCE_GUARD = """
DO $codex_control$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM audit_events AS audit
        LEFT JOIN control_sessions AS session
          ON session.id = audit.actor_session_id
        WHERE audit.actor_session_id IS NOT NULL
          AND session.id IS NULL
    ) OR EXISTS (
        SELECT 1
        FROM audit_events AS audit
        LEFT JOIN devices AS device
          ON device.id = audit.actor_device_id
        WHERE audit.actor_device_id IS NOT NULL
          AND device.id IS NULL
    ) THEN
        RAISE EXCEPTION
            'cannot restore audit actor foreign keys while historical references are orphaned';
    END IF;
END
$codex_control$
"""


def upgrade() -> None:
    # Audit actor UUIDs are immutable historical values. Retained session/device
    # tombstones can expire sooner than their audit evidence, so SET NULL would
    # silently rewrite an append-only audit row.
    op.drop_constraint(
        "fk_audit_events_actor_session_id_control_sessions",
        "audit_events",
        type_="foreignkey",
    )
    op.drop_constraint(
        "fk_audit_events_actor_device_id_devices",
        "audit_events",
        type_="foreignkey",
    )
    op.create_index(
        "ix_device_connections_retention",
        "device_connections",
        ["status", "disconnected_at", "id"],
    )
    op.create_index(
        "ix_commands_retention",
        "commands",
        ["status", "completed_at", "id"],
    )
    op.create_index(
        "ix_approvals_retention",
        "approvals",
        ["status", "decided_at", "id"],
    )
    op.create_index(
        "ix_thread_bindings_retention",
        "thread_bindings",
        ["status", "updated_at", "id"],
    )
    op.create_index(
        "ix_devices_retention",
        "devices",
        ["status", "revoked_at", "id"],
    )


def downgrade() -> None:
    op.execute(DOWNGRADE_AUDIT_REFERENCE_GUARD)
    op.create_foreign_key(
        "fk_audit_events_actor_session_id_control_sessions",
        "audit_events",
        "control_sessions",
        ["actor_session_id"],
        ["id"],
        ondelete="SET NULL",
    )
    op.create_foreign_key(
        "fk_audit_events_actor_device_id_devices",
        "audit_events",
        "devices",
        ["actor_device_id"],
        ["id"],
        ondelete="SET NULL",
    )
    op.drop_index("ix_devices_retention", table_name="devices")
    op.drop_index("ix_thread_bindings_retention", table_name="thread_bindings")
    op.drop_index("ix_approvals_retention", table_name="approvals")
    op.drop_index("ix_commands_retention", table_name="commands")
    op.drop_index("ix_device_connections_retention", table_name="device_connections")
