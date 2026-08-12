from __future__ import annotations

import importlib.util
import io
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import ModuleType

from alembic.migration import MigrationContext
from alembic.operations import Operations
from conftest import Harness
from sqlalchemy import func, select

from control_api.models import (
    Approval,
    ApprovalStatus,
    AuditEvent,
    AuditOutcome,
    Command,
    CommandStatus,
    ConnectionStatus,
    ControlSession,
    Device,
    DeviceConnection,
    DeviceOutbox,
    DevicePairing,
    DeviceStatus,
    PairingStatus,
    ThreadBinding,
    ThreadBindingStatus,
)
from control_api.retention import RetentionService

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]


def _load_migration(filename: str) -> ModuleType:
    path = REPOSITORY_ROOT / "migrations" / "versions" / filename
    spec = importlib.util.spec_from_file_location(f"test_{path.stem}", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _render_postgresql_migration(filename: str, operation: str) -> str:
    output = io.StringIO()
    context = MigrationContext.configure(
        dialect_name="postgresql",
        opts={"as_sql": True, "output_buffer": output},
    )
    migration = _load_migration(filename)
    migration.op = Operations(context)
    getattr(migration, operation)()
    return " ".join(output.getvalue().split())


def _one_day_windows(harness: Harness, *, batch_size: int = 100) -> None:
    harness.settings.session_record_retention_days = 1
    harness.settings.device_pairing_retention_days = 1
    harness.settings.device_connection_retention_days = 1
    harness.settings.command_record_retention_days = 1
    harness.settings.approval_record_retention_days = 1
    harness.settings.thread_binding_retention_days = 1
    harness.settings.revoked_device_retention_days = 1
    harness.settings.audit_event_retention_days = 1
    harness.settings.retention_sweep_batch_size = batch_size


async def test_retention_is_batch_bounded_and_preserves_recent_revocation(
    harness: Harness,
) -> None:
    _one_day_windows(harness, batch_size=2)
    now = datetime.now(UTC)
    expired_at = now - timedelta(days=3)
    sessions = [
        ControlSession(
            token_hash=f"{index:064x}",
            csrf_token_hash=f"{index + 10:064x}",
            sub2api_user_id="42",
            issued_at=expired_at - timedelta(minutes=10),
            expires_at=expired_at,
            last_seen_at=expired_at,
        )
        for index in range(1, 4)
    ]
    recently_revoked = ControlSession(
        token_hash="a" * 64,
        csrf_token_hash="b" * 64,
        sub2api_user_id="42",
        issued_at=expired_at - timedelta(minutes=10),
        expires_at=expired_at,
        last_seen_at=expired_at,
        revoked_at=now,
    )
    async with harness.database.session_factory() as db:
        db.add_all([*sessions, recently_revoked])
        await db.commit()

    service = RetentionService(harness.settings)
    async with harness.database.session_factory() as db:
        first = await service.sweep(db, now=now)
    assert first.control_sessions == 2
    async with harness.database.session_factory() as db:
        second = await service.sweep(db, now=now)
    assert second.control_sessions == 1

    async with harness.database.session_factory() as db:
        remaining_ids = set((await db.scalars(select(ControlSession.id))).all())
    assert remaining_ids == {recently_revoked.id}

    async with harness.database.session_factory() as db:
        after_revocation_window = await service.sweep(db, now=now + timedelta(days=2))
    assert after_revocation_window.control_sessions == 1


async def test_retention_preserves_live_unacknowledged_and_inconsistent_state(
    harness: Harness,
) -> None:
    _one_day_windows(harness)
    now = datetime.now(UTC)
    old = now - timedelta(days=3)
    future = now + timedelta(minutes=5)
    device = Device(
        owner_user_id="42",
        name="Retention device",
        public_key=f"retention-{uuid.uuid4()}",
        status=DeviceStatus.ACTIVE,
        workspace_roots=["/workspace"],
        last_server_sequence=1,
        last_server_acked_sequence=0,
    )
    async with harness.database.session_factory() as db:
        db.add(device)
        await db.flush()
        closed_thread = ThreadBinding(
            owner_user_id="42",
            device_id=device.id,
            remote_thread_id="closed-thread",
            status=ThreadBindingStatus.CLOSED,
            cwd="/workspace",
            title="Closed",
            model="gpt-5.5",
            appserver_epoch="epoch-retention",
            updated_at=old,
        )
        active_turn_thread = ThreadBinding(
            owner_user_id="42",
            device_id=device.id,
            remote_thread_id="inconsistent-closed-thread",
            status=ThreadBindingStatus.CLOSED,
            active_turn_id="turn-still-active",
            cwd="/workspace",
            title="Still active",
            model="gpt-5.5",
            appserver_epoch="epoch-retention",
            updated_at=old,
        )
        db.add_all([closed_thread, active_turn_thread])
        await db.flush()
        completed = Command(
            owner_user_id="42",
            device_id=device.id,
            thread_binding_id=closed_thread.id,
            idempotency_key="completed-retention",
            idempotency_scope="retention",
            request_hash="c" * 64,
            method="turn/interrupt",
            payload={},
            status=CommandStatus.SUCCEEDED,
            completed_at=old,
            expires_at=old,
        )
        pending = Command(
            owner_user_id="42",
            device_id=device.id,
            idempotency_key="pending-retention",
            idempotency_scope="retention",
            request_hash="d" * 64,
            method="model/list",
            payload={},
            status=CommandStatus.QUEUED,
            created_at=old,
            expires_at=future,
        )
        missing_terminal_time = Command(
            owner_user_id="42",
            device_id=device.id,
            idempotency_key="missing-terminal-time",
            idempotency_scope="retention",
            request_hash="e" * 64,
            method="model/list",
            payload={},
            status=CommandStatus.FAILED,
            created_at=old,
            expires_at=old,
        )
        db.add_all([completed, pending, missing_terminal_time])
        await db.flush()
        delivered_approval = Approval(
            owner_user_id="42",
            device_id=device.id,
            command_id=completed.id,
            external_command_id="retention-approval",
            approval_kind="permission",
            summary="Delivered decision",
            request={},
            status=ApprovalStatus.DENIED,
            appserver_epoch="epoch-retention",
            requested_at=old - timedelta(minutes=1),
            expires_at=old + timedelta(minutes=1),
            decided_at=old,
            decision_dispatched_at=old,
            decision_reason="user_denied",
        )
        undelivered_approval = Approval(
            owner_user_id="42",
            device_id=device.id,
            external_command_id="undelivered-retention-approval",
            approval_kind="permission",
            summary="Undelivered decision",
            request={},
            status=ApprovalStatus.DENIED,
            appserver_epoch="epoch-retention",
            requested_at=old - timedelta(minutes=1),
            expires_at=old + timedelta(minutes=1),
            decided_at=old,
            decision_reason="timeout_default_deny",
        )
        disconnected = DeviceConnection(
            device_id=device.id,
            connection_nonce=f"closed-{uuid.uuid4()}",
            status=ConnectionStatus.DISCONNECTED,
            connected_at=old - timedelta(minutes=1),
            last_heartbeat_at=old,
            disconnected_at=old,
        )
        stale_but_connected = DeviceConnection(
            device_id=device.id,
            connection_nonce=f"live-{uuid.uuid4()}",
            status=ConnectionStatus.CONNECTED,
            connected_at=old - timedelta(minutes=1),
            last_heartbeat_at=old,
        )
        outbox = DeviceOutbox(
            device_id=device.id,
            sequence=1,
            encoded_envelope="unacknowledged-security-state",
            ack_sequence=0,
            frame_type="approval_decision",
            byte_size=31,
            created_at=old,
            retained_until=now + timedelta(days=1),
        )
        old_audit = AuditEvent(
            actor_user_id="42",
            action="retention.old",
            outcome=AuditOutcome.SUCCEEDED,
            created_at=old,
        )
        recent_audit = AuditEvent(
            actor_user_id="42",
            action="retention.recent",
            outcome=AuditOutcome.SUCCEEDED,
            created_at=now,
        )
        db.add_all(
            [
                delivered_approval,
                undelivered_approval,
                disconnected,
                stale_but_connected,
                outbox,
                old_audit,
                recent_audit,
            ]
        )
        await db.commit()

    service = RetentionService(harness.settings)
    async with harness.database.session_factory() as db:
        blocked = await service.sweep(db, now=now)
    assert blocked.approvals == 0
    assert blocked.commands == 0
    assert blocked.device_connections == 1
    assert blocked.thread_bindings == 0
    assert blocked.audit_events == 1

    async with harness.database.session_factory() as db:
        stored_outbox = await db.get(DeviceOutbox, (device.id, 1))
        assert stored_outbox is not None
        stored_outbox.acked_at = now
        device_row = await db.get(Device, device.id)
        assert device_row is not None
        device_row.last_server_acked_sequence = 1
        await db.commit()
    async with harness.database.session_factory() as db:
        unblocked = await service.sweep(db, now=now)
    assert unblocked.approvals == 1
    assert unblocked.commands == 1
    assert unblocked.thread_bindings == 0

    async with harness.database.session_factory() as db:
        stored_approval = await db.get(Approval, undelivered_approval.id)
        assert stored_approval is not None
        stored_approval.decision_reason = "disconnect_default_deny"
        await db.commit()
    async with harness.database.session_factory() as db:
        reconciled = await service.sweep(db, now=now)
    assert reconciled.approvals == 1
    assert reconciled.thread_bindings == 1

    async with harness.database.session_factory() as db:
        assert await db.get(Approval, undelivered_approval.id) is None
        assert await db.get(Command, pending.id) is not None
        assert await db.get(Command, missing_terminal_time.id) is not None
        assert await db.get(ThreadBinding, active_turn_thread.id) is not None
        assert await db.get(DeviceConnection, stale_but_connected.id) is not None
        assert await db.get(AuditEvent, recent_audit.id) is not None


async def test_revoked_device_requires_all_security_dependencies_to_be_gone(
    harness: Harness,
) -> None:
    _one_day_windows(harness)
    now = datetime.now(UTC)
    old = now - timedelta(days=3)
    removable = Device(
        owner_user_id="42",
        name="Removable revoked device",
        public_key=f"removable-{uuid.uuid4()}",
        status=DeviceStatus.REVOKED,
        revoked_at=old,
        workspace_roots=[],
    )
    blocked = Device(
        owner_user_id="42",
        name="Blocked revoked device",
        public_key=f"blocked-{uuid.uuid4()}",
        status=DeviceStatus.REVOKED,
        revoked_at=old,
        workspace_roots=[],
        last_server_sequence=1,
        last_server_acked_sequence=0,
    )
    active = Device(
        owner_user_id="42",
        name="Active device",
        public_key=f"active-{uuid.uuid4()}",
        status=DeviceStatus.ACTIVE,
        revoked_at=old,
        workspace_roots=[],
    )
    async with harness.database.session_factory() as db:
        db.add_all([removable, blocked, active])
        await db.flush()
        db.add(
            DeviceOutbox(
                device_id=blocked.id,
                sequence=1,
                encoded_envelope="blocked-unacknowledged",
                ack_sequence=0,
                frame_type="command",
                byte_size=22,
                created_at=old,
                retained_until=now + timedelta(days=1),
            )
        )
        await db.commit()

    service = RetentionService(harness.settings)
    async with harness.database.session_factory() as db:
        result = await service.sweep(db, now=now)
    assert result.devices == 1
    async with harness.database.session_factory() as db:
        assert await db.get(Device, removable.id) is None
        assert await db.get(Device, blocked.id) is not None
        assert await db.get(Device, active.id) is not None


async def test_only_terminal_pairings_are_retained_while_live_states_are_preserved(
    harness: Harness,
) -> None:
    _one_day_windows(harness, batch_size=10)
    now = datetime.now(UTC)
    old = now - timedelta(days=3)
    expired = DevicePairing(
        code_hash="1" * 64,
        poll_token_hash="2" * 64,
        public_key="expired-pairing-key",
        device_name="Expired pairing",
        status=PairingStatus.EXPIRED,
        created_at=old - timedelta(minutes=10),
        expires_at=old,
    )
    completed = DevicePairing(
        code_hash="3" * 64,
        poll_token_hash="4" * 64,
        public_key="completed-pairing-key",
        device_name="Completed pairing",
        status=PairingStatus.COMPLETED,
        created_at=old - timedelta(minutes=10),
        expires_at=old,
        credential_delivered_at=old,
        completed_at=old,
    )
    pending = DevicePairing(
        code_hash="5" * 64,
        poll_token_hash="6" * 64,
        public_key="pending-pairing-key",
        device_name="Pending pairing",
        status=PairingStatus.PENDING,
        created_at=old - timedelta(minutes=10),
        expires_at=old,
    )
    claimed = DevicePairing(
        code_hash="7" * 64,
        poll_token_hash="8" * 64,
        public_key="claimed-pairing-key",
        device_name="Claimed pairing",
        status=PairingStatus.CLAIMED,
        claimed_by_user_id="42",
        created_at=old - timedelta(minutes=10),
        expires_at=old,
        claimed_at=old,
    )
    async with harness.database.session_factory() as db:
        db.add_all([expired, completed, pending, claimed])
        await db.commit()

    async with harness.database.session_factory() as db:
        result = await RetentionService(harness.settings).sweep(db, now=now)
    assert result.device_pairings == 2
    async with harness.database.session_factory() as db:
        assert await db.get(DevicePairing, expired.id) is None
        assert await db.get(DevicePairing, completed.id) is None
        assert await db.get(DevicePairing, pending.id) is not None
        assert await db.get(DevicePairing, claimed.id) is not None


def test_retention_migration_adds_and_reverses_all_query_indexes() -> None:
    upgrade = _render_postgresql_migration("20260723_0005_retention_indexes.py", "upgrade")
    downgrade = _render_postgresql_migration("20260723_0005_retention_indexes.py", "downgrade")
    for index in (
        "ix_device_connections_retention",
        "ix_commands_retention",
        "ix_approvals_retention",
        "ix_thread_bindings_retention",
        "ix_devices_retention",
    ):
        assert f"CREATE INDEX {index}" in upgrade
        assert f"DROP INDEX {index}" in downgrade
    assert "DROP CONSTRAINT fk_audit_events_actor_session_id_control_sessions" in upgrade
    assert "DROP CONSTRAINT fk_audit_events_actor_device_id_devices" in upgrade
    assert "historical references are orphaned" in downgrade
    assert "ADD CONSTRAINT fk_audit_events_actor_session_id_control_sessions" in downgrade
    assert "ADD CONSTRAINT fk_audit_events_actor_device_id_devices" in downgrade


async def test_audit_deletion_is_age_only_and_does_not_append_recursive_audit(
    harness: Harness,
) -> None:
    _one_day_windows(harness, batch_size=10)
    now = datetime.now(UTC)
    async with harness.database.session_factory() as db:
        db.add_all(
            [
                AuditEvent(
                    actor_user_id="42",
                    action="old.audit",
                    outcome=AuditOutcome.SUCCEEDED,
                    created_at=now - timedelta(days=2),
                ),
                AuditEvent(
                    actor_user_id="42",
                    action="new.audit",
                    outcome=AuditOutcome.SUCCEEDED,
                    created_at=now,
                ),
            ]
        )
        await db.commit()
    async with harness.database.session_factory() as db:
        result = await RetentionService(harness.settings).sweep(db, now=now)
    assert result.audit_events == 1
    async with harness.database.session_factory() as db:
        actions = set((await db.scalars(select(AuditEvent.action))).all())
        count = await db.scalar(select(func.count(AuditEvent.id)))
    assert actions == {"new.audit"}
    assert count == 1
