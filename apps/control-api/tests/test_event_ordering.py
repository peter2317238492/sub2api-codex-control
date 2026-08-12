from __future__ import annotations

import asyncio
import importlib.util
import io
import json
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest
from alembic.migration import MigrationContext
from alembic.operations import Operations
from conftest import Harness, exchange
from sqlalchemy import CheckConstraint, UniqueConstraint, select

from control_api.events import (
    MAX_EVENT_CURSOR,
    BrowserCursorResetRequired,
    BrowserEventTooLarge,
    EventCursorExhausted,
    EventService,
)
from control_api.models import (
    Approval,
    ApprovalStatus,
    Device,
    DeviceStatus,
    EventLog,
    EventOwnerCursor,
    ThreadBinding,
    ThreadBindingStatus,
)
from control_api.realtime import BrowserSocketClose

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]


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


def test_event_cursor_schema_is_owner_scoped_and_monotonic() -> None:
    cursor_table = EventOwnerCursor.__table__
    assert tuple(column.name for column in cursor_table.primary_key.columns) == ("owner_user_id",)
    assert not cursor_table.c.last_cursor.nullable
    assert {
        constraint.name
        for constraint in cursor_table.constraints
        if isinstance(constraint, CheckConstraint)
    } == {
        "ck_event_owner_cursors_nonnegative_last_cursor",
        "ck_event_owner_cursors_bounded_last_cursor",
        "ck_event_owner_cursors_nonnegative_minimum_resume_cursor",
        "ck_event_owner_cursors_valid_resume_window",
    }

    event_table = EventLog.__table__
    assert not event_table.c.owner_cursor.nullable
    unique_constraints = {
        constraint.name: tuple(column.name for column in constraint.columns)
        for constraint in event_table.constraints
        if isinstance(constraint, UniqueConstraint)
    }
    assert unique_constraints["uq_event_log_owner_cursor"] == (
        "owner_user_id",
        "owner_cursor",
    )


def test_owner_cursor_migration_preserves_existing_browser_cursors() -> None:
    filename = "20260723_0004_owner_event_cursors.py"
    upgrade_sql = render_postgresql_migration(filename, "upgrade")
    assert "CREATE TABLE event_owner_cursors" in upgrade_sql
    assert "UPDATE event_log SET owner_cursor = id" in upgrade_sql
    assert "ALTER TABLE event_log ALTER COLUMN owner_cursor SET NOT NULL" in upgrade_sql
    assert "UNIQUE (owner_user_id, owner_cursor)" in upgrade_sql
    assert "SELECT owner_user_id, max(owner_cursor)" in upgrade_sql
    assert upgrade_sql.index("UPDATE event_log SET owner_cursor = id") < upgrade_sql.index(
        "ALTER TABLE event_log ALTER COLUMN owner_cursor SET NOT NULL"
    )

    downgrade_sql = render_postgresql_migration(filename, "downgrade")
    assert downgrade_sql.index("DROP COLUMN owner_cursor") < downgrade_sql.index(
        "DROP TABLE event_owner_cursors"
    )


async def _seed_devices(harness: Harness) -> tuple[Device, Device, Device]:
    devices = (
        Device(
            owner_user_id="42",
            name="Owner 42 device A",
            public_key=f"event-cursor-{uuid.uuid4()}",
            status=DeviceStatus.ACTIVE,
            device_metadata={},
            workspace_roots=[],
        ),
        Device(
            owner_user_id="42",
            name="Owner 42 device B",
            public_key=f"event-cursor-{uuid.uuid4()}",
            status=DeviceStatus.ACTIVE,
            device_metadata={},
            workspace_roots=[],
        ),
        Device(
            owner_user_id="99",
            name="Owner 99 device",
            public_key=f"event-cursor-{uuid.uuid4()}",
            status=DeviceStatus.ACTIVE,
            device_metadata={},
            workspace_roots=[],
        ),
    )
    async with harness.database.session_factory() as db:
        db.add_all(devices)
        await db.commit()
    return devices


async def test_owner_cursor_is_ordered_across_devices_and_independent_across_owners(
    harness: Harness,
) -> None:
    device_a, device_b, device_other = await _seed_devices(harness)

    async with harness.database.session_factory() as db:
        first = await harness.app.state.events.emit(
            db,
            owner_user_id="42",
            device_id=device_a.id,
            event_type="device.updated",
            data={"event": "first"},
        )
    async with harness.database.session_factory() as db:
        other_owner = await harness.app.state.events.emit(
            db,
            owner_user_id="99",
            device_id=device_other.id,
            event_type="device.updated",
            data={"event": "other"},
        )
    async with harness.database.session_factory() as db:
        second = await harness.app.state.events.emit(
            db,
            owner_user_id="42",
            device_id=device_b.id,
            event_type="device.updated",
            data={"event": "second"},
        )

    assert (first.cursor, second.cursor, other_owner.cursor) == ("1", "2", "1")
    async with harness.database.session_factory() as db:
        owner_events = await harness.app.state.events.catch_up(db, "42", 0)
        cursor_rows = list(
            (
                await db.scalars(select(EventOwnerCursor).order_by(EventOwnerCursor.owner_user_id))
            ).all()
        )
    assert [event.data["event"] for event in owner_events] == ["first", "second"]
    assert [(row.owner_user_id, row.last_cursor) for row in cursor_rows] == [
        ("42", 2),
        ("99", 1),
    ]


async def test_browser_event_catch_up_page_exposes_row_pagination(
    harness: Harness,
) -> None:
    device, _, _ = await _seed_devices(harness)
    occurred_at = datetime(2026, 7, 30, 12, 0, tzinfo=UTC)
    for index in range(3):
        async with harness.database.session_factory() as db:
            await harness.app.state.events.append(
                db,
                owner_user_id="42",
                device_id=device.id,
                event_type="device.updated",
                data={"index": index},
                occurred_at=occurred_at,
            )
            await db.commit()

    service = EventService(
        SimpleNamespace(
            browser_event_catchup_limit=2,
            browser_event_catchup_max_bytes=1024 * 1024,
        ),
        harness.store,
    )
    async with harness.database.session_factory() as db:
        first_page = await service.catch_up_page(db, "42", 0)
    assert [event.cursor for event in first_page.events] == ["1", "2"]
    assert first_page.has_more is True
    assert first_page.serialized_bytes == sum(
        len(event.model_dump_json().encode("utf-8")) for event in first_page.events
    )

    async with harness.database.session_factory() as db:
        second_page = await service.catch_up_page(db, "42", 2)
    assert [event.cursor for event in second_page.events] == ["3"]
    assert second_page.has_more is False

    async with harness.database.session_factory() as db:
        compatible = await service.catch_up(db, "42", 0)
    assert isinstance(compatible, list)
    assert [event.cursor for event in compatible] == ["1", "2"]


async def test_browser_event_catch_up_page_enforces_exact_utf8_byte_budget(
    harness: Harness,
) -> None:
    device, _, _ = await _seed_devices(harness)
    occurred_at = datetime(2026, 7, 30, 12, 0, tzinfo=UTC)
    for text in ("first 事件", "second 事件", "third 事件"):
        async with harness.database.session_factory() as db:
            await harness.app.state.events.append(
                db,
                owner_user_id="42",
                device_id=device.id,
                event_type="device.updated",
                data={"text": text},
                occurred_at=occurred_at,
            )
            await db.commit()

    async with harness.database.session_factory() as db:
        all_events = await harness.app.state.events.catch_up(db, "42", 0)
    encoded_sizes = [len(event.model_dump_json().encode("utf-8")) for event in all_events]
    assert encoded_sizes[0] > len(all_events[0].model_dump_json())

    service = EventService(
        SimpleNamespace(
            browser_event_catchup_limit=3,
            browser_event_catchup_max_bytes=encoded_sizes[0] + encoded_sizes[1] - 1,
        ),
        harness.store,
    )
    async with harness.database.session_factory() as db:
        page = await service.catch_up_page(db, "42", 0)
    assert [event.cursor for event in page.events] == ["1"]
    assert page.has_more is True
    assert page.serialized_bytes == encoded_sizes[0]

    exact_service = EventService(
        SimpleNamespace(
            browser_event_catchup_limit=3,
            browser_event_catchup_max_bytes=encoded_sizes[0] + encoded_sizes[1],
        ),
        harness.store,
    )
    async with harness.database.session_factory() as db:
        exact_page = await exact_service.catch_up_page(db, "42", 0)
    assert [event.cursor for event in exact_page.events] == ["1", "2"]
    assert exact_page.has_more is True
    assert exact_page.serialized_bytes == encoded_sizes[0] + encoded_sizes[1]


async def test_browser_event_larger_than_page_budget_requires_bootstrap(
    harness: Harness,
) -> None:
    device, _, _ = await _seed_devices(harness)
    async with harness.database.session_factory() as db:
        await harness.app.state.events.append(
            db,
            owner_user_id="42",
            device_id=device.id,
            event_type="device.updated",
            data={"text": "oversized 事件"},
            occurred_at=datetime(2026, 7, 30, 12, 0, tzinfo=UTC),
        )
        await db.commit()
    async with harness.database.session_factory() as db:
        durable_event = (await harness.app.state.events.catch_up(db, "42", 0))[0]
    encoded_size = len(durable_event.model_dump_json().encode("utf-8"))
    service = EventService(
        SimpleNamespace(
            browser_event_catchup_limit=10,
            browser_event_catchup_max_bytes=encoded_size - 1,
        ),
        harness.store,
    )

    async with harness.database.session_factory() as db:
        with pytest.raises(BrowserEventTooLarge, match="cursor 1") as raised:
            await service.catch_up_page(db, "42", 0)
    assert isinstance(raised.value, BrowserCursorResetRequired)
    assert raised.value.cursor == 1
    assert raised.value.serialized_bytes == encoded_size
    assert raised.value.byte_limit == encoded_size - 1


async def test_atomic_bootstrap_returns_owner_snapshot_and_event_baseline(
    harness: Harness,
) -> None:
    assert (await harness.client.get("/v1/bootstrap")).status_code == 401
    assert (await exchange(harness)).status_code == 201
    device, second_device, other_device = await _seed_devices(harness)
    device.model_catalog = [
        {"id": "gpt-5.5", "display_name": "GPT-5.5", "description": "Pinned"},
        {"id": "invalid"},
    ]
    now = datetime.now(UTC)
    thread = ThreadBinding(
        owner_user_id="42",
        device_id=device.id,
        remote_thread_id="remote-bootstrap",
        status=ThreadBindingStatus.RUNNING,
        cwd="/workspace",
        title="Atomic snapshot",
        model="gpt-5.5",
        appserver_epoch="bootstrap-epoch",
        snapshot={
            "messages": [
                {
                    "id": "assistant-1",
                    "role": "assistant",
                    "text": "durable text",
                    "created_at": now.isoformat(),
                    "pending": True,
                }
            ]
        },
    )
    foreign_thread = ThreadBinding(
        owner_user_id="99",
        device_id=other_device.id,
        remote_thread_id="foreign-bootstrap",
        status=ThreadBindingStatus.IDLE,
        cwd="/foreign",
        title="Foreign",
        model="gpt-5.5",
        appserver_epoch="foreign-epoch",
        snapshot={"messages": []},
    )
    pending = Approval(
        owner_user_id="42",
        device_id=device.id,
        external_command_id="pending-bootstrap",
        approval_kind="permission",
        summary="Pending bootstrap approval",
        request={"scope": "workspace"},
        status=ApprovalStatus.PENDING,
        appserver_epoch="bootstrap-epoch",
        requested_at=now,
        expires_at=now + timedelta(minutes=5),
    )
    expired = Approval(
        owner_user_id="42",
        device_id=device.id,
        external_command_id="expired-bootstrap",
        approval_kind="permission",
        summary="Expired",
        request={},
        status=ApprovalStatus.PENDING,
        appserver_epoch="bootstrap-epoch",
        requested_at=now - timedelta(minutes=10),
        expires_at=now - timedelta(minutes=5),
    )
    async with harness.database.session_factory() as db:
        await db.merge(device)
        db.add_all([thread, foreign_thread, pending, expired])
        await db.commit()
    async with harness.database.session_factory() as db:
        event = await harness.app.state.events.emit(
            db,
            owner_user_id="42",
            device_id=device.id,
            event_type="device.updated",
            data={"baseline": True},
        )

    response = await harness.client.get("/v1/bootstrap")
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    body = response.json()
    assert body["event_cursor"] == event.cursor == "1"
    assert {item["id"] for item in body["devices"]} == {
        str(device.id),
        str(second_device.id),
    }
    assert all(item["id"] != str(other_device.id) for item in body["devices"])
    assert [item["id"] for item in body["threads"]] == [str(thread.id)]
    assert "messages" not in body["threads"][0]
    assert [item["approval_id"] for item in body["approvals"]] == [str(pending.id)]
    assert set(body["models_by_device"]) == {item["id"] for item in body["devices"]}
    assert body["models_by_device"][str(device.id)] == [
        {"id": "gpt-5.5", "display_name": "GPT-5.5", "description": "Pinned"}
    ]

    detail_response = await harness.client.get(f"/v1/threads/{thread.id}")
    assert detail_response.status_code == 200
    assert detail_response.headers["cache-control"] == "no-store"
    detail = detail_response.json()
    assert detail["event_cursor"] == event.cursor
    assert detail["thread"]["messages"][0]["text"] == "durable text"


async def test_bootstrap_releases_event_barrier_before_redis_status_lookup(
    harness: Harness,
) -> None:
    assert (await exchange(harness)).status_code == 201
    device, _, _ = await _seed_devices(harness)
    entered_redis = asyncio.Event()
    release_redis = asyncio.Event()
    original_get = harness.store.get

    async def blocking_connection_get(key: str) -> str | None:
        if key.startswith("connection:"):
            entered_redis.set()
            await release_redis.wait()
        return await original_get(key)

    harness.store.get = blocking_connection_get  # type: ignore[method-assign]
    bootstrap_task = asyncio.create_task(harness.client.get("/v1/bootstrap"))
    try:
        await asyncio.wait_for(entered_redis.wait(), timeout=1)
        async with harness.database.session_factory() as db:
            late = await asyncio.wait_for(
                harness.app.state.events.emit(
                    db,
                    owner_user_id="42",
                    device_id=device.id,
                    event_type="device.updated",
                    data={"phase": "after-barrier"},
                ),
                timeout=1,
            )
        release_redis.set()
        response = await asyncio.wait_for(bootstrap_task, timeout=1)
    finally:
        release_redis.set()
        harness.store.get = original_get  # type: ignore[method-assign]
        if not bootstrap_task.done():
            bootstrap_task.cancel()
            await asyncio.gather(bootstrap_task, return_exceptions=True)

    assert response.status_code == 200
    assert response.json()["event_cursor"] == "0"
    assert late.cursor == "1"
    async with harness.database.session_factory() as db:
        replay = await harness.app.state.events.catch_up(db, "42", 0)
    assert [event.data["phase"] for event in replay] == ["after-barrier"]


async def test_thread_detail_watermark_does_not_read_connection_store(
    harness: Harness,
) -> None:
    assert (await exchange(harness)).status_code == 201
    device, _, _ = await _seed_devices(harness)
    binding = ThreadBinding(
        owner_user_id="42",
        device_id=device.id,
        remote_thread_id="detail-no-redis",
        status=ThreadBindingStatus.IDLE,
        cwd="/workspace",
        title="No Redis detail",
        model="gpt",
        appserver_epoch="epoch-detail-no-redis",
        snapshot={"messages": []},
    )
    async with harness.database.session_factory() as db:
        db.add(binding)
        await db.commit()
    original_get = harness.store.get

    async def reject_connection_get(key: str) -> str | None:
        if key.startswith("connection:"):
            raise AssertionError("thread detail must not query Redis connection state")
        return await original_get(key)

    harness.store.get = reject_connection_get  # type: ignore[method-assign]
    try:
        response = await harness.client.get(f"/v1/threads/{binding.id}")
    finally:
        harness.store.get = original_get  # type: ignore[method-assign]
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    assert response.json() == {
        "event_cursor": "0",
        "thread": {
            "id": str(binding.id),
            "device_id": str(device.id),
            "title": "No Redis detail",
            "cwd": "/workspace",
            "model": "gpt",
            "updated_at": response.json()["thread"]["updated_at"],
            "status": "idle",
            "messages": [],
        },
    }


class _RecordingBrowserSocket:
    def __init__(self, expected: int) -> None:
        self.sent: list[str] = []
        self.complete = asyncio.Event()
        self._expected = expected

    async def send_text(self, value: str) -> None:
        self.sent.append(value)
        if len(self.sent) >= self._expected:
            self.complete.set()


async def test_browser_pubsub_wakeups_coalesce_without_buffering_event_payloads(
    harness: Harness,
) -> None:
    queue: asyncio.Queue[None] = asyncio.Queue(maxsize=1)
    ready = asyncio.Event()
    pump = asyncio.create_task(harness.app.state.realtime._pump_browser_events("42", queue, ready))
    try:
        await asyncio.wait_for(ready.wait(), timeout=1)
        for cursor in range(1, 4):
            await harness.store.publish(
                "browser:42",
                json.dumps({"cursor": str(cursor), "payload": "x" * 1024}),
            )
        for _ in range(10):
            await asyncio.sleep(0)

        assert queue.qsize() == 1
        assert queue.get_nowait() is None
        assert not pump.done()
    finally:
        pump.cancel()
        await asyncio.gather(pump, return_exceptions=True)


async def test_reverse_publish_notification_drains_durable_events_in_cursor_order(
    harness: Harness,
) -> None:
    device, _, _ = await _seed_devices(harness)
    committed = []
    for index in range(2):
        async with harness.database.session_factory() as db:
            event = await harness.app.state.events.append(
                db,
                owner_user_id="42",
                device_id=device.id,
                event_type="device.updated",
                data={"index": index},
            )
            await db.commit()
            committed.append(event)

    harness.settings.browser_event_catchup_limit = 1
    socket = _RecordingBrowserSocket(expected=2)
    queue: asyncio.Queue[None] = asyncio.Queue()
    latest_cursor = [0]
    forward = asyncio.create_task(
        harness.app.state.realtime._forward_browser_queue(
            socket,
            "42",
            queue,
            latest_cursor,
        )
    )
    try:
        # The higher cursor arrives first, as can happen across API workers.
        await queue.put(None)
        await asyncio.wait_for(socket.complete.wait(), timeout=1)
        assert [json.loads(raw)["cursor"] for raw in socket.sent] == ["1", "2"]
        assert [json.loads(raw)["data"]["index"] for raw in socket.sent] == [0, 1]
        assert latest_cursor == [2]

        # The delayed lower notification is now only a redundant wake-up.
        await queue.put(None)
        await asyncio.sleep(0)
        assert len(socket.sent) == 2
    finally:
        forward.cancel()
        await asyncio.gather(forward, return_exceptions=True)


async def test_browser_forwarding_continues_when_byte_budget_not_row_limit_pages(
    harness: Harness,
) -> None:
    device, _, _ = await _seed_devices(harness)
    committed = []
    for index in range(2):
        async with harness.database.session_factory() as db:
            event = await harness.app.state.events.append(
                db,
                owner_user_id="42",
                device_id=device.id,
                event_type="device.updated",
                data={"index": index, "text": "x" * 256},
            )
            await db.commit()
            committed.append(event)

    encoded_sizes = [len(event.model_dump_json().encode("utf-8")) for event in committed]
    harness.settings.browser_event_catchup_limit = 500
    harness.settings.browser_event_catchup_max_bytes = max(encoded_sizes)
    assert sum(encoded_sizes) > harness.settings.browser_event_catchup_max_bytes
    socket = _RecordingBrowserSocket(expected=2)
    queue: asyncio.Queue[None] = asyncio.Queue()
    latest_cursor = [0]
    forward = asyncio.create_task(
        harness.app.state.realtime._forward_browser_queue(
            socket,
            "42",
            queue,
            latest_cursor,
        )
    )
    try:
        await queue.put(None)
        await asyncio.wait_for(socket.complete.wait(), timeout=1)

        assert [json.loads(raw)["cursor"] for raw in socket.sent] == ["1", "2"]
        assert latest_cursor == [2]
    finally:
        forward.cancel()
        await asyncio.gather(forward, return_exceptions=True)


async def test_browser_forwarding_stops_before_delivery_when_authority_task_ends(
    harness: Harness,
) -> None:
    device, _, _ = await _seed_devices(harness)
    async with harness.database.session_factory() as db:
        await harness.app.state.events.append(
            db,
            owner_user_id="42",
            device_id=device.id,
            event_type="device.updated",
            data={"must_not": "be delivered"},
        )
        await db.commit()

    async def revoked() -> None:
        raise BrowserSocketClose(4401, "control session expired")

    authority = asyncio.create_task(revoked())
    await asyncio.gather(authority, return_exceptions=True)
    socket = _RecordingBrowserSocket(expected=1)
    queue: asyncio.Queue[None] = asyncio.Queue()
    await queue.put(None)

    with pytest.raises(BrowserSocketClose) as closed:
        await harness.app.state.realtime._forward_browser_queue(
            socket,
            "42",
            queue,
            [0],
            (authority,),
        )

    assert closed.value.code == 4401
    assert socket.sent == []


async def test_prune_advances_resume_floor_and_rejects_stale_or_future_cursor(
    harness: Harness,
) -> None:
    device, _, _ = await _seed_devices(harness)
    for index in range(3):
        async with harness.database.session_factory() as db:
            await harness.app.state.events.emit(
                db,
                owner_user_id="42",
                device_id=device.id,
                event_type="device.updated",
                data={"index": index},
            )

    harness.settings.browser_event_max_per_owner = 2
    async with harness.database.session_factory() as db:
        assert await harness.app.state.events.prune(db) == 1
    async with harness.database.session_factory() as db:
        state = await db.get(EventOwnerCursor, "42")
        assert state is not None
        assert (state.minimum_resume_cursor, state.last_cursor) == (1, 3)

    async with harness.database.session_factory() as db:
        with pytest.raises(BrowserCursorResetRequired, match="older than retained"):
            await harness.app.state.events.catch_up(db, "42", 0)
    async with harness.database.session_factory() as db:
        resumed = await harness.app.state.events.catch_up(db, "42", 1)
        assert [event.cursor for event in resumed] == ["2", "3"]
    async with harness.database.session_factory() as db:
        with pytest.raises(BrowserCursorResetRequired, match="ahead"):
            await harness.app.state.events.catch_up(db, "42", 4)


async def test_event_cursor_exhaustion_rolls_back_device_sequence(
    harness: Harness,
) -> None:
    device, _, _ = await _seed_devices(harness)
    async with harness.database.session_factory() as db:
        db.add(
            EventOwnerCursor(
                owner_user_id="42",
                last_cursor=MAX_EVENT_CURSOR,
                minimum_resume_cursor=0,
            )
        )
        await db.commit()

    async with harness.database.session_factory() as db:
        with pytest.raises(EventCursorExhausted, match="signed bigint"):
            await harness.app.state.events.emit(
                db,
                owner_user_id="42",
                device_id=device.id,
                event_type="device.updated",
                data={"exhausted": True},
            )
        await db.rollback()

    async with harness.database.session_factory() as db:
        stored = await db.get(Device, device.id)
        events = list(
            (await db.scalars(select(EventLog).where(EventLog.owner_user_id == "42"))).all()
        )
    assert stored is not None and stored.last_event_sequence == 0
    assert events == []
