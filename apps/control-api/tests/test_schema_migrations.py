from __future__ import annotations

import importlib.util
import io
from pathlib import Path
from types import ModuleType

from alembic.migration import MigrationContext
from alembic.operations import Operations
from sqlalchemy import CheckConstraint, UniqueConstraint
from sqlalchemy.dialects import postgresql, sqlite
from sqlalchemy.schema import CreateTable

from control_api.db import DATABASE_SCHEMA_REVISION
from control_api.models import Approval, Command, DeviceOutbox, ThreadBinding

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]


def test_readiness_revision_matches_single_migration_head() -> None:
    migrations = [
        load_migration(path.name)
        for path in sorted((REPOSITORY_ROOT / "migrations" / "versions").glob("*.py"))
    ]
    revisions = {migration.revision for migration in migrations}
    down_revisions = {migration.down_revision for migration in migrations}

    assert revisions - down_revisions == {DATABASE_SCHEMA_REVISION}


def load_migration(filename: str) -> ModuleType:
    path = REPOSITORY_ROOT / "migrations" / "versions" / filename
    spec = importlib.util.spec_from_file_location(f"test_{path.stem}", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def render_postgresql_migration(filename: str, operation: str) -> str:
    output = io.StringIO()
    context = MigrationContext.configure(
        dialect_name="postgresql",
        opts={"as_sql": True, "output_buffer": output},
    )
    migration = load_migration(filename)
    migration.op = Operations(context)
    getattr(migration, operation)()
    return " ".join(output.getvalue().split())


def test_thread_binding_status_has_room_for_all_protocol_states() -> None:
    status = ThreadBinding.__table__.c.status
    assert status.type.length == 32

    migration_sql = render_postgresql_migration("20260713_0002_realtime_control.py", "upgrade")
    assert "ALTER TABLE thread_bindings ALTER COLUMN status TYPE VARCHAR(32)" in migration_sql


def test_command_idempotency_is_scoped_by_device_and_resource() -> None:
    scope = Command.__table__.c.idempotency_scope
    assert scope.type.length == 512
    assert not scope.nullable
    assert scope.default is not None and scope.default.arg == "legacy"

    unique_constraints = {
        constraint.name: tuple(column.name for column in constraint.columns)
        for constraint in Command.__table__.constraints
        if isinstance(constraint, UniqueConstraint)
    }
    assert unique_constraints["uq_commands_scoped_idempotency"] == (
        "owner_user_id",
        "device_id",
        "idempotency_scope",
        "idempotency_key",
    )
    assert "uq_commands_owner_idempotency" not in unique_constraints


def test_device_outbox_is_portable_and_has_cleanup_guards() -> None:
    table = DeviceOutbox.__table__
    assert tuple(column.name for column in table.primary_key.columns) == (
        "device_id",
        "sequence",
    )
    assert table.c.frame_type.type.length == 32
    assert {index.name for index in table.indexes} == {
        "ix_device_outbox_acked_at",
        "ix_device_outbox_retained_until",
    }
    assert {
        constraint.name
        for constraint in table.constraints
        if isinstance(constraint, CheckConstraint)
    } == {
        "ck_device_outbox_non_handshake_frame",
        "ck_device_outbox_nonnegative_ack_sequence",
        "ck_device_outbox_positive_byte_size",
        "ck_device_outbox_positive_sequence",
        "ck_device_outbox_valid_ack_time",
        "ck_device_outbox_valid_retention",
    }

    for dialect in (postgresql.dialect(), sqlite.dialect()):
        ddl = str(CreateTable(table).compile(dialect=dialect))
        assert "encoded_envelope" in ddl
        assert "PRIMARY KEY (device_id, sequence)" in ddl


def test_durable_outbox_migration_upgrade_and_downgrade_sql() -> None:
    upgrade_sql = render_postgresql_migration("20260713_0003_durable_outbox.py", "upgrade")
    assert "cannot create durable outbox while server frames are unacknowledged" in upgrade_sql
    assert upgrade_sql.index("cannot create durable outbox") < upgrade_sql.index(
        "CREATE TABLE device_outbox"
    )
    assert "ALTER TABLE thread_bindings ALTER COLUMN status TYPE VARCHAR(32)" in upgrade_sql
    assert "CREATE TABLE device_outbox" in upgrade_sql
    assert "PRIMARY KEY (device_id, sequence)" in upgrade_sql
    assert "UNIQUE (owner_user_id, device_id, idempotency_scope, idempotency_key)" in upgrade_sql

    downgrade_sql = render_postgresql_migration("20260713_0003_durable_outbox.py", "downgrade")
    assert "cannot drop durable outbox while server frames are unacknowledged" in downgrade_sql
    assert "device_outbox WHERE acked_at IS NULL" in downgrade_sql
    assert downgrade_sql.index("cannot drop durable outbox") < downgrade_sql.index(
        "DROP TABLE device_outbox"
    )
    assert "DROP TABLE device_outbox" in downgrade_sql
    assert "row_number() OVER" in downgrade_sql
    assert "ranked.duplicate_number > 1" in downgrade_sql
    assert "UNIQUE (owner_user_id, idempotency_key)" in downgrade_sql
    assert "DROP COLUMN idempotency_scope" in downgrade_sql


def test_approval_reconciliation_index_matches_migration() -> None:
    indexes = {
        index.name: tuple(column.name for column in index.columns)
        for index in Approval.__table__.indexes
    }
    assert indexes["ix_approvals_undispatched"] == (
        "status",
        "decision_dispatched_at",
        "id",
    )

    upgrade_sql = render_postgresql_migration(
        "20260730_0006_approval_reconciliation.py",
        "upgrade",
    )
    assert (
        "CREATE INDEX ix_approvals_undispatched ON approvals (status, decision_dispatched_at, id)"
        in upgrade_sql
    )
    downgrade_sql = render_postgresql_migration(
        "20260730_0006_approval_reconciliation.py",
        "downgrade",
    )
    assert "DROP INDEX ix_approvals_undispatched" in downgrade_sql


def test_retry_safe_pairing_migration_requires_drained_v1_pairings() -> None:
    filename = "20260730_0007_retry_safe_pairing.py"
    upgrade_sql = render_postgresql_migration(filename, "upgrade")

    assert "v1 pending or claimed pairings exist" in upgrade_sql
    assert "LOCK TABLE device_pairings IN SHARE ROW EXCLUSIVE MODE" in upgrade_sql
    assert "WHERE status IN ('pending', 'claimed')" in upgrade_sql
    assert upgrade_sql.index("v1 pending or claimed pairings exist") < upgrade_sql.index(
        "ADD COLUMN protocol_version"
    )
    assert "ADD COLUMN refresh_credential_hash VARCHAR(64)" in upgrade_sql
    assert "ADD COLUMN proof_created_at TIMESTAMP WITH TIME ZONE" in upgrade_sql
    assert "ADD COLUMN audience VARCHAR(4096)" in upgrade_sql
    assert "ADD COLUMN credential_scheme INTEGER DEFAULT 1 NOT NULL" in upgrade_sql
    assert "DROP CONSTRAINT uq_devices_public_key" in upgrade_sql
    assert (
        "CREATE UNIQUE INDEX uq_devices_live_public_key ON devices (public_key) "
        "WHERE status = 'active'"
    ) in upgrade_sql
    assert "status IN ('pairing', 'active')" not in upgrade_sql
    assert "DROP CONSTRAINT ck_devices_status" not in upgrade_sql

    downgrade_sql = render_postgresql_migration(filename, "downgrade")
    assert "LOCK TABLE device_pairings, devices IN SHARE ROW EXCLUSIVE MODE" in downgrade_sql
    assert "cannot remove retry-safe pairing while v2 pairing credentials exist" in downgrade_sql
    assert "cannot restore global device public-key uniqueness" in downgrade_sql
    assert downgrade_sql.index("cannot remove retry-safe pairing") < downgrade_sql.index(
        "DROP INDEX uq_devices_live_public_key"
    )
    assert "ADD CONSTRAINT uq_devices_public_key UNIQUE (public_key)" in downgrade_sql
    assert "DROP COLUMN credential_scheme" in downgrade_sql
    assert "DROP COLUMN protocol_version" in downgrade_sql
    assert "DROP CONSTRAINT ck_devices_status" not in downgrade_sql


def test_approval_request_identity_matches_migration() -> None:
    request_hash = Approval.__table__.c.request_hash
    assert request_hash.type.length == 64
    assert not request_hash.nullable
    assert request_hash.default is not None
    assert request_hash.default.arg == "0" * 64
    assert "ck_approvals_request_hash_length" in {
        constraint.name
        for constraint in Approval.__table__.constraints
        if isinstance(constraint, CheckConstraint)
    }

    filename = "20260731_0008_approval_request_identity.py"
    upgrade_sql = render_postgresql_migration(filename, "upgrade")
    assert "ADD COLUMN request_hash VARCHAR(64) DEFAULT" in upgrade_sql
    assert "NOT NULL" in upgrade_sql
    assert "ADD CONSTRAINT ck_approvals_request_hash_length" in upgrade_sql
    assert "CHECK (length(request_hash) = 64)" in upgrade_sql
    assert "ALTER COLUMN request_hash DROP DEFAULT" in upgrade_sql
    assert upgrade_sql.index("ADD COLUMN request_hash") < upgrade_sql.index(
        "ADD CONSTRAINT ck_approvals_request_hash_length"
    )
    assert upgrade_sql.index("ADD CONSTRAINT ck_approvals_request_hash_length") < upgrade_sql.index(
        "ALTER COLUMN request_hash DROP DEFAULT"
    )

    downgrade_sql = render_postgresql_migration(filename, "downgrade")
    assert "DROP CONSTRAINT ck_approvals_request_hash_length" in downgrade_sql
    assert "DROP COLUMN request_hash" in downgrade_sql
    assert downgrade_sql.index(
        "DROP CONSTRAINT ck_approvals_request_hash_length"
    ) < downgrade_sql.index("DROP COLUMN request_hash")
