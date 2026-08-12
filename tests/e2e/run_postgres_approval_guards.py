#!/usr/bin/env python3
from __future__ import annotations

import asyncio
import os
import sys
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import quote

from control_api.approvals import ApprovalService
from control_api.db import Database
from control_api.events import EventService
from control_api.models import Approval, ApprovalStatus, AuditEvent, Device, EventLog
from sqlalchemy import func, select


class UnusedStore:
    """The reconciliation paths append durable events but do not access Redis."""


def database_url() -> str:
    password_file = Path(
        os.environ.get(
            "CONTROL_DATABASE_PASSWORD_FILE",
            "/run/secrets/control_db_password",
        )
    )
    password = password_file.read_text(encoding="utf-8").rstrip("\r\n")
    if not password:
        raise RuntimeError("Control database password is empty")
    user = os.environ.get("CONTROL_DB_USER", "codex_control")
    host = os.environ.get("CONTROL_DB_HOST", "postgres")
    port = os.environ.get("CONTROL_DB_PORT", "5432")
    name = os.environ.get("CONTROL_DB_NAME", "codex_control")
    query = os.environ.get("CONTROL_DB_QUERY", "")
    return (
        "postgresql+asyncpg://"
        f"{quote(user, safe='')}:{quote(password, safe='')}@{host}:{port}/"
        f"{quote(name, safe='')}{query}"
    )


def make_approval(
    *,
    device: Device,
    run_id: str,
    suffix: str,
    status: ApprovalStatus,
    epoch: str,
    now: datetime,
    dispatched: bool = False,
) -> Approval:
    return Approval(
        owner_user_id=device.owner_user_id,
        device_id=device.id,
        external_command_id=f"acceptance-{run_id}-{suffix}",
        approval_kind="permission",
        summary=f"PostgreSQL acceptance guard {suffix}",
        request={"acceptance_case": suffix},
        status=status,
        appserver_epoch=epoch,
        requested_at=now,
        expires_at=now + timedelta(minutes=10),
        decided_at=None if status == ApprovalStatus.PENDING else now,
        decision_dispatched_at=now if dispatched else None,
        decision_reason=(
            None
            if status == ApprovalStatus.PENDING
            else "user_approved"
            if status == ApprovalStatus.APPROVED
            else "user_denied"
        ),
    )


async def assert_rows(
    database: Database,
    expected: dict[uuid.UUID, tuple[ApprovalStatus, str | None, bool]],
) -> None:
    async with database.session_factory() as db:
        rows = {
            row.id: row
            for row in (
                await db.scalars(select(Approval).where(Approval.id.in_(expected)))
            ).all()
        }
    if set(rows) != set(expected):
        raise AssertionError("PostgreSQL approval guard rows were lost")
    for approval_id, (status, reason, dispatched) in expected.items():
        row = rows[approval_id]
        if row.status != status or row.decision_reason != reason:
            raise AssertionError(
                f"approval {approval_id} was {row.status}/{row.decision_reason}, "
                f"expected {status}/{reason}"
            )
        if (row.decision_dispatched_at is not None) != dispatched:
            raise AssertionError(f"approval {approval_id} dispatch marker changed")


async def assert_durable_evidence(
    database: Database,
    approval_ids: set[uuid.UUID],
    expected_reason: str,
) -> None:
    string_ids = {str(approval_id) for approval_id in approval_ids}
    async with database.session_factory() as db:
        audits = list(
            (
                await db.scalars(
                    select(AuditEvent).where(
                        AuditEvent.action == "approval.default_deny",
                        AuditEvent.resource_id.in_(string_ids),
                    )
                )
            ).all()
        )
        events = list(
            (
                await db.scalars(
                    select(EventLog).where(EventLog.event_type == "approval.resolved")
                )
            ).all()
        )
    if {audit.resource_id for audit in audits} != string_ids:
        raise AssertionError("default-deny audit evidence is incomplete")
    matched_events = {
        str(event.payload.get("approval_id"))
        for event in events
        if event.payload.get("reason") == expected_reason
        and str(event.payload.get("approval_id")) in string_ids
    }
    if matched_events != string_ids:
        raise AssertionError("default-deny browser-event evidence is incomplete")


async def main(device_id: uuid.UUID) -> None:
    settings = SimpleNamespace(
        database_url=database_url(),
        database_pool_size=5,
        database_max_overflow=5,
        database_pool_timeout_seconds=3.0,
        database_connect_timeout_seconds=5.0,
        database_command_timeout_seconds=10.0,
    )
    database = Database(settings)
    store = UnusedStore()
    events = EventService(SimpleNamespace(), store)  # type: ignore[arg-type]
    approvals = ApprovalService(store, events)  # type: ignore[arg-type]
    run_id = uuid.uuid4().hex[:12]
    now = datetime.now(UTC)

    try:
        async with database.session_factory() as db:
            device = await db.get(Device, device_id)
            if device is None or not device.active_epoch:
                raise AssertionError("acceptance device has no active app-server epoch")
            current_epoch = device.active_epoch
            stale_epoch = f"acceptance-stale-{run_id}"
            stale_pending = make_approval(
                device=device,
                run_id=run_id,
                suffix="stale-pending",
                status=ApprovalStatus.PENDING,
                epoch=stale_epoch,
                now=now,
            )
            stale_approved = make_approval(
                device=device,
                run_id=run_id,
                suffix="stale-approved",
                status=ApprovalStatus.APPROVED,
                epoch=stale_epoch,
                now=now,
            )
            stale_denied = make_approval(
                device=device,
                run_id=run_id,
                suffix="stale-denied",
                status=ApprovalStatus.DENIED,
                epoch=stale_epoch,
                now=now,
            )
            stale_dispatched = make_approval(
                device=device,
                run_id=run_id,
                suffix="stale-dispatched",
                status=ApprovalStatus.APPROVED,
                epoch=stale_epoch,
                now=now,
                dispatched=True,
            )
            current_pending = make_approval(
                device=device,
                run_id=run_id,
                suffix="current-pending",
                status=ApprovalStatus.PENDING,
                epoch=current_epoch,
                now=now,
            )
            db.add_all(
                [
                    stale_pending,
                    stale_approved,
                    stale_denied,
                    stale_dispatched,
                    current_pending,
                ]
            )
            await db.commit()

        async def reconcile_stale() -> int:
            async with database.session_factory() as db:
                locked_device = await db.scalar(
                    select(Device).where(Device.id == device_id).with_for_update()
                )
                if locked_device is None:
                    raise AssertionError("acceptance device disappeared")
                events = await approvals.deny_stale_epoch(
                    db, locked_device, current_epoch
                )
                await db.commit()
                return len(events)

        stale_counts = sorted(
            await asyncio.gather(reconcile_stale(), reconcile_stale())
        )
        if stale_counts != [0, 3] or await reconcile_stale() != 0:
            raise AssertionError(
                f"stale-epoch rows were not claimed exactly once: {stale_counts}"
            )

        stale_claimed = {stale_pending.id, stale_approved.id, stale_denied.id}
        await assert_rows(
            database,
            {
                stale_pending.id: (
                    ApprovalStatus.DENIED,
                    "stale_epoch_default_deny",
                    False,
                ),
                stale_approved.id: (
                    ApprovalStatus.DENIED,
                    "stale_epoch_default_deny",
                    False,
                ),
                stale_denied.id: (
                    ApprovalStatus.DENIED,
                    "stale_epoch_default_deny",
                    False,
                ),
                stale_dispatched.id: (ApprovalStatus.APPROVED, "user_approved", True),
                current_pending.id: (ApprovalStatus.PENDING, None, False),
            },
        )
        await assert_durable_evidence(
            database,
            stale_claimed,
            "stale_epoch_default_deny",
        )

        async with database.session_factory() as db:
            current = await db.get(Approval, current_pending.id)
            if current is None:
                raise AssertionError("current-epoch control row disappeared")
            current.status = ApprovalStatus.APPROVED
            current.decided_at = now
            current.decision_reason = "user_approved"
            current.decision_dispatched_at = now

            stored_device = await db.get(Device, device_id)
            if stored_device is None:
                raise AssertionError("acceptance device disappeared")
            disconnected_pending = make_approval(
                device=stored_device,
                run_id=run_id,
                suffix="disconnect-pending",
                status=ApprovalStatus.PENDING,
                epoch=current_epoch,
                now=now,
            )
            disconnected_approved = make_approval(
                device=stored_device,
                run_id=run_id,
                suffix="disconnect-approved",
                status=ApprovalStatus.APPROVED,
                epoch=current_epoch,
                now=now,
            )
            disconnected_denied = make_approval(
                device=stored_device,
                run_id=run_id,
                suffix="disconnect-denied",
                status=ApprovalStatus.DENIED,
                epoch=current_epoch,
                now=now,
            )
            disconnected_dispatched = make_approval(
                device=stored_device,
                run_id=run_id,
                suffix="disconnect-dispatched",
                status=ApprovalStatus.APPROVED,
                epoch=current_epoch,
                now=now,
                dispatched=True,
            )
            db.add_all(
                [
                    disconnected_pending,
                    disconnected_approved,
                    disconnected_denied,
                    disconnected_dispatched,
                ]
            )
            await db.commit()

        async def reconcile_disconnect() -> int:
            async with database.session_factory() as db:
                locked_device = await db.scalar(
                    select(Device).where(Device.id == device_id).with_for_update()
                )
                if locked_device is None:
                    raise AssertionError("acceptance device disappeared")
                events = await approvals.deny_disconnected(db, locked_device)
                await db.commit()
                return len(events)

        disconnect_count = await reconcile_disconnect()
        if disconnect_count != 3 or await reconcile_disconnect() != 0:
            raise AssertionError(
                f"disconnect rows were not claimed exactly once: {disconnect_count}"
            )

        disconnect_claimed = {
            disconnected_pending.id,
            disconnected_approved.id,
            disconnected_denied.id,
        }
        await assert_rows(
            database,
            {
                disconnected_pending.id: (
                    ApprovalStatus.DENIED,
                    "disconnect_default_deny",
                    False,
                ),
                disconnected_approved.id: (
                    ApprovalStatus.DENIED,
                    "disconnect_default_deny",
                    False,
                ),
                disconnected_denied.id: (
                    ApprovalStatus.DENIED,
                    "disconnect_default_deny",
                    False,
                ),
                disconnected_dispatched.id: (
                    ApprovalStatus.APPROVED,
                    "user_approved",
                    True,
                ),
            },
        )
        await assert_durable_evidence(
            database,
            disconnect_claimed,
            "disconnect_default_deny",
        )

        async with database.session_factory() as db:
            default_deny_audits = await db.scalar(
                select(func.count(AuditEvent.id)).where(
                    AuditEvent.action == "approval.default_deny",
                    AuditEvent.resource_id.in_(
                        {
                            str(approval_id)
                            for approval_id in stale_claimed | disconnect_claimed
                        }
                    ),
                )
            )
        if default_deny_audits != 6:
            raise AssertionError(
                "PostgreSQL default-deny audit count was not exactly six"
            )
    finally:
        await database.close()

    print(
        "PostgreSQL approval guards passed: stale epoch and disconnect decisions "
        "were default-denied exactly once with durable audit/event evidence."
    )


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: run_postgres_approval_guards.py DEVICE_ID")
    asyncio.run(main(uuid.UUID(sys.argv[1])))
