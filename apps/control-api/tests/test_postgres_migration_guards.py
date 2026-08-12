from __future__ import annotations

import asyncio
import importlib.util
import os
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any

import asyncpg
import pytest
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from control_api.capacity import (
    OwnerCapacityExceeded,
    approval_capacity_denial_reason_locked,
    ensure_approval_record_capacity_locked,
    ensure_device_creation_capacity,
    ensure_thread_creation_capacity,
)
from control_api.config import Settings
from control_api.db import Base
from control_api.events import EventService
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
from control_api.realtime import ActiveDeviceSocket, RealtimeService, StaleConnection
from control_api.storage import InMemoryKeyValueStore

POSTGRES_DSN = os.environ.get("CONTROL_TEST_POSTGRES_DSN")
REPOSITORY_ROOT = Path(__file__).resolve().parents[3]

pytestmark = pytest.mark.skipif(
    not POSTGRES_DSN,
    reason="CONTROL_TEST_POSTGRES_DSN is required for real PostgreSQL migration guards",
)


def load_migration() -> ModuleType:
    path = REPOSITORY_ROOT / "migrations" / "versions" / "20260713_0003_durable_outbox.py"
    spec = importlib.util.spec_from_file_location("test_pg_guard_migration", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_retry_safe_pairing_migration() -> ModuleType:
    path = REPOSITORY_ROOT / "migrations" / "versions" / "20260730_0007_retry_safe_pairing.py"
    spec = importlib.util.spec_from_file_location(
        "test_pg_retry_safe_pairing_migration",
        path,
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


async def test_real_postgres_upgrade_and_downgrade_cursor_guards() -> None:
    assert POSTGRES_DSN is not None
    dsn = POSTGRES_DSN.replace("postgresql+asyncpg://", "postgresql://", 1)
    connection = await asyncpg.connect(dsn)
    schema = f"codex_guard_{uuid.uuid4().hex}"
    migration = load_migration()
    try:
        await connection.execute(f'CREATE SCHEMA "{schema}"')
        await connection.execute(f'SET search_path TO "{schema}"')
        await connection.execute(
            """
            CREATE TABLE devices (
                id uuid PRIMARY KEY,
                last_server_sequence bigint NOT NULL,
                last_server_acked_sequence bigint NOT NULL
            )
            """
        )
        device_id = uuid.uuid4()
        await connection.execute(
            "INSERT INTO devices VALUES ($1, 4, 4)",
            device_id,
        )
        await connection.execute(migration.UPGRADE_CURSOR_GUARD)

        await connection.execute(
            "UPDATE devices SET last_server_sequence = 5 WHERE id = $1",
            device_id,
        )
        with pytest.raises(asyncpg.PostgresError, match="unacknowledged"):
            await connection.execute(migration.UPGRADE_CURSOR_GUARD)

        await connection.execute(
            "UPDATE devices SET last_server_acked_sequence = 5 WHERE id = $1",
            device_id,
        )
        await connection.execute(
            """
            CREATE TABLE device_outbox (
                device_id uuid NOT NULL,
                sequence bigint NOT NULL,
                acked_at timestamptz
            )
            """
        )
        await connection.execute(
            "INSERT INTO device_outbox VALUES ($1, 5, NULL)",
            device_id,
        )
        with pytest.raises(asyncpg.PostgresError, match="unacknowledged"):
            await connection.execute(migration.DOWNGRADE_CURSOR_GUARD)

        await connection.execute("UPDATE device_outbox SET acked_at = CURRENT_TIMESTAMP")
        await connection.execute(migration.DOWNGRADE_CURSOR_GUARD)
    finally:
        await connection.execute("SET search_path TO public")
        await connection.execute(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE')
        await connection.close()


async def test_real_postgres_retry_safe_pairing_upgrade_rejects_live_v1_rows() -> None:
    assert POSTGRES_DSN is not None
    dsn = POSTGRES_DSN.replace("postgresql+asyncpg://", "postgresql://", 1)
    connection = await asyncpg.connect(dsn)
    schema = f"codex_pairing_upgrade_guard_{uuid.uuid4().hex}"
    migration = load_retry_safe_pairing_migration()
    try:
        await connection.execute(f'CREATE SCHEMA "{schema}"')
        await connection.execute(f'SET search_path TO "{schema}"')
        await connection.execute(
            """
            CREATE TABLE device_pairings (
                id uuid PRIMARY KEY,
                status text NOT NULL
            )
            """
        )
        pairing_id = uuid.uuid4()
        await connection.execute(
            "INSERT INTO device_pairings VALUES ($1, 'pending')",
            pairing_id,
        )

        with pytest.raises(asyncpg.PostgresError, match="v1 pending or claimed"):
            await connection.execute(migration.UPGRADE_LIVE_PAIRING_GUARD)

        await connection.execute(
            "UPDATE device_pairings SET status = 'expired' WHERE id = $1",
            pairing_id,
        )
        await connection.execute(migration.UPGRADE_LIVE_PAIRING_GUARD)

        await connection.execute(
            "UPDATE device_pairings SET status = 'claimed' WHERE id = $1",
            pairing_id,
        )
        with pytest.raises(asyncpg.PostgresError, match="v1 pending or claimed"):
            await connection.execute(migration.UPGRADE_LIVE_PAIRING_GUARD)

        await connection.execute(
            "UPDATE device_pairings SET status = 'completed' WHERE id = $1",
            pairing_id,
        )
        await connection.execute(migration.UPGRADE_LIVE_PAIRING_GUARD)
    finally:
        await connection.execute("SET search_path TO public")
        await connection.execute(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE')
        await connection.close()


async def test_real_postgres_retry_safe_pairing_downgrade_guards_identity() -> None:
    assert POSTGRES_DSN is not None
    dsn = POSTGRES_DSN.replace("postgresql+asyncpg://", "postgresql://", 1)
    connection = await asyncpg.connect(dsn)
    schema = f"codex_pairing_downgrade_guard_{uuid.uuid4().hex}"
    migration = load_retry_safe_pairing_migration()
    try:
        await connection.execute(f'CREATE SCHEMA "{schema}"')
        await connection.execute(f'SET search_path TO "{schema}"')
        await connection.execute(
            """
            CREATE TABLE device_pairings (
                id uuid PRIMARY KEY,
                protocol_version integer NOT NULL
            )
            """
        )
        await connection.execute(
            """
            CREATE TABLE devices (
                id uuid PRIMARY KEY,
                public_key text NOT NULL,
                credential_scheme integer NOT NULL
            )
            """
        )

        pairing_id = uuid.uuid4()
        first_device_id = uuid.uuid4()
        second_device_id = uuid.uuid4()
        await connection.execute(
            "INSERT INTO device_pairings VALUES ($1, 2)",
            pairing_id,
        )
        await connection.execute(
            "INSERT INTO devices VALUES ($1, 'shared-public-key', 1)",
            first_device_id,
        )
        with pytest.raises(asyncpg.PostgresError, match="v2 pairing credentials"):
            await connection.execute(migration.DOWNGRADE_IDENTITY_GUARD)

        await connection.execute(
            "UPDATE device_pairings SET protocol_version = 1 WHERE id = $1",
            pairing_id,
        )
        await connection.execute(
            "UPDATE devices SET credential_scheme = 2 WHERE id = $1",
            first_device_id,
        )
        with pytest.raises(asyncpg.PostgresError, match="v2 pairing credentials"):
            await connection.execute(migration.DOWNGRADE_IDENTITY_GUARD)

        await connection.execute(
            "UPDATE devices SET credential_scheme = 1 WHERE id = $1",
            first_device_id,
        )
        await connection.execute(
            "INSERT INTO devices VALUES ($1, 'shared-public-key', 1)",
            second_device_id,
        )
        with pytest.raises(asyncpg.PostgresError, match="global device public-key uniqueness"):
            await connection.execute(migration.DOWNGRADE_IDENTITY_GUARD)

        await connection.execute(
            "DELETE FROM devices WHERE id = $1",
            second_device_id,
        )
        await connection.execute(migration.DOWNGRADE_IDENTITY_GUARD)
    finally:
        await connection.execute("SET search_path TO public")
        await connection.execute(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE')
        await connection.close()


async def test_real_postgres_owner_cursor_blocks_reverse_commit() -> None:
    assert POSTGRES_DSN is not None
    raw_dsn = POSTGRES_DSN.replace("postgresql+asyncpg://", "postgresql://", 1)
    async_dsn = raw_dsn.replace("postgresql://", "postgresql+asyncpg://", 1)
    schema = f"codex_event_order_{uuid.uuid4().hex}"
    administrator = await asyncpg.connect(raw_dsn)
    observer = await asyncpg.connect(raw_dsn)
    engine = None
    task_b: asyncio.Task[object] | None = None
    try:
        await administrator.execute(f'CREATE SCHEMA "{schema}"')
        engine = create_async_engine(
            async_dsn,
            connect_args={"server_settings": {"search_path": schema}},
        )
        async with engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)

        settings = Settings(
            environment="test",
            database_url=async_dsn,
            redis_url="memory://",
            session_hmac_secret="event-order-test-secret-with-at-least-32-bytes",
            cookie_secure=False,
            allowed_origins_csv="https://control.example.test",
        )
        store = InMemoryKeyValueStore("event-order:")
        events = EventService(settings, store)
        sessions = async_sessionmaker(engine, expire_on_commit=False, autoflush=False)

        device_a = Device(
            owner_user_id="owner",
            name="A",
            public_key=f"postgres-event-a-{uuid.uuid4()}",
            status=DeviceStatus.ACTIVE,
            device_metadata={},
            workspace_roots=[],
        )
        device_b = Device(
            owner_user_id="owner",
            name="B",
            public_key=f"postgres-event-b-{uuid.uuid4()}",
            status=DeviceStatus.ACTIVE,
            device_metadata={},
            workspace_roots=[],
        )
        async with sessions() as seed:
            seed.add_all([device_a, device_b])
            await seed.commit()

        async with sessions() as transaction_a, sessions() as transaction_b:
            first = await events.append(
                transaction_a,
                owner_user_id="owner",
                device_id=device_a.id,
                event_type="device.updated",
                data={"transaction": "a"},
            )
            backend_b = int(await transaction_b.scalar(text("SELECT pg_backend_pid()")))

            async def append_and_commit_b() -> object:
                second = await events.append(
                    transaction_b,
                    owner_user_id="owner",
                    device_id=device_b.id,
                    event_type="device.updated",
                    data={"transaction": "b"},
                )
                await transaction_b.commit()
                return second

            task_b = asyncio.create_task(append_and_commit_b())
            wait_state = None
            for _ in range(200):
                wait_state = await observer.fetchrow(
                    """
                    SELECT wait_event_type, wait_event
                    FROM pg_stat_activity
                    WHERE pid = $1
                    """,
                    backend_b,
                )
                if wait_state is not None and wait_state["wait_event_type"] == "Lock":
                    break
                await asyncio.sleep(0.01)
            assert wait_state is not None
            assert wait_state["wait_event_type"] == "Lock"
            assert not task_b.done()

            # B has attempted to reach commit, but cannot receive cursor 2 until
            # A's cursor 1 transaction commits and releases the owner row lock.
            await transaction_a.commit()
            second = await asyncio.wait_for(task_b, timeout=2)
            assert first.cursor == "1"
            assert second.cursor == "2"

        async with sessions() as verify:
            rows = list(
                (
                    await verify.scalars(
                        select(EventLog)
                        .where(EventLog.owner_user_id == "owner")
                        .order_by(EventLog.owner_cursor)
                    )
                ).all()
            )
            head = await verify.get(EventOwnerCursor, "owner")
        assert [row.payload["transaction"] for row in rows] == ["a", "b"]
        assert head is not None and head.last_cursor == 2
        await store.close()
    finally:
        if task_b is not None and not task_b.done():
            task_b.cancel()
            await asyncio.gather(task_b, return_exceptions=True)
        if engine is not None:
            await engine.dispose()
        await observer.close()
        await administrator.execute(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE')
        await administrator.close()


class _RecordingSessionContext:
    def __init__(self, context: Any, backend_pids: asyncio.Queue[int]) -> None:
        self._context = context
        self._backend_pids = backend_pids

    async def __aenter__(self) -> Any:
        session = await self._context.__aenter__()
        backend_pid = int(await session.scalar(text("SELECT pg_backend_pid()")))
        await self._backend_pids.put(backend_pid)
        return session

    async def __aexit__(self, *args: object) -> object:
        return await self._context.__aexit__(*args)


class _RecordingSessionFactory:
    def __init__(self, factory: async_sessionmaker[Any]) -> None:
        self._factory = factory
        self.backend_pids: asyncio.Queue[int] = asyncio.Queue()

    def __call__(self) -> _RecordingSessionContext:
        return _RecordingSessionContext(self._factory(), self.backend_pids)


class _BlockingDeviceSocket:
    def __init__(self, *, blocked: bool) -> None:
        self.sent: list[str] = []
        self.started = asyncio.Event()
        self.release = asyncio.Event()
        if not blocked:
            self.release.set()

    async def send_text(self, value: str) -> None:
        self.started.set()
        await self.release.wait()
        self.sent.append(value)


async def test_real_postgres_device_send_barrier_serializes_revocation() -> None:
    assert POSTGRES_DSN is not None
    raw_dsn = POSTGRES_DSN.replace("postgresql+asyncpg://", "postgresql://", 1)
    async_dsn = raw_dsn.replace("postgresql://", "postgresql+asyncpg://", 1)
    schema = f"codex_device_send_barrier_{uuid.uuid4().hex}"
    administrator = await asyncpg.connect(raw_dsn)
    observer = await asyncpg.connect(raw_dsn)
    engine = None
    send_task: asyncio.Task[None] | None = None
    revoke_task: asyncio.Task[None] | None = None
    try:
        await administrator.execute(f'CREATE SCHEMA "{schema}"')
        engine = create_async_engine(
            async_dsn,
            connect_args={"server_settings": {"search_path": schema}},
        )
        async with engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)

        settings = Settings(
            environment="test",
            database_url=async_dsn,
            redis_url="memory://",
            session_hmac_secret="device-send-barrier-secret-with-at-least-32-bytes",
            cookie_secure=False,
            allowed_origins_csv="https://control.example.test",
            device_hello_timeout_seconds=5,
        )
        sessions = async_sessionmaker(engine, expire_on_commit=False, autoflush=False)
        recording_sessions = _RecordingSessionFactory(sessions)
        realtime = object.__new__(RealtimeService)
        realtime._database = SimpleNamespace(session_factory=recording_sessions)
        realtime._settings = settings

        async def seed_device() -> Device:
            device = Device(
                owner_user_id="owner",
                name="PostgreSQL send barrier",
                public_key=f"postgres-send-barrier-{uuid.uuid4()}",
                status=DeviceStatus.ACTIVE,
                device_metadata={},
                workspace_roots=["/workspace"],
                active_epoch="epoch-postgres-send-barrier",
                active_connection_nonce=str(uuid.uuid4()),
            )
            async with sessions() as seed:
                seed.add(device)
                await seed.commit()
            return device

        def active_connection(device: Device, socket: _BlockingDeviceSocket) -> ActiveDeviceSocket:
            return ActiveDeviceSocket(
                websocket=socket,  # type: ignore[arg-type]
                device_id=device.id,
                owner_user_id=device.owner_user_id,
                connection_nonce=device.active_connection_nonce or "",
                epoch=device.active_epoch or "",
            )

        # If a send owns the device row first, revoke cannot commit until that
        # bounded send finishes. Therefore a successful send is always pre-revoke.
        first = await seed_device()
        first_socket = _BlockingDeviceSocket(blocked=True)
        first_connection = active_connection(first, first_socket)
        send_task = asyncio.create_task(
            realtime._send_if_active(first_connection, ["pre-revoke-frame"])
        )
        await asyncio.wait_for(first_socket.started.wait(), timeout=2)
        await asyncio.wait_for(recording_sessions.backend_pids.get(), timeout=2)

        revoke_pid: asyncio.Future[int] = asyncio.get_running_loop().create_future()

        async def revoke_first() -> None:
            async with sessions() as revoker:
                revoke_pid.set_result(int(await revoker.scalar(text("SELECT pg_backend_pid()"))))
                locked = await revoker.scalar(
                    select(Device).where(Device.id == first.id).with_for_update()
                )
                assert locked is not None
                locked.status = DeviceStatus.REVOKED
                locked.active_epoch = None
                locked.active_connection_nonce = None
                locked.revoked_at = datetime.now(UTC)
                await revoker.commit()

        revoke_task = asyncio.create_task(revoke_first())
        await _wait_for_postgres_lock(observer, await revoke_pid)
        assert not revoke_task.done()
        first_socket.release.set()
        await asyncio.wait_for(send_task, timeout=2)
        await asyncio.wait_for(revoke_task, timeout=2)
        send_task = None
        revoke_task = None
        assert first_socket.sent == ["pre-revoke-frame"]

        # If revoke owns and commits the row first, a blocked sender rechecks
        # the committed authority and cannot emit even one stale frame.
        second = await seed_device()
        second_socket = _BlockingDeviceSocket(blocked=False)
        second_connection = active_connection(second, second_socket)
        async with sessions() as revoker:
            locked = await revoker.scalar(
                select(Device).where(Device.id == second.id).with_for_update()
            )
            assert locked is not None
            locked.status = DeviceStatus.REVOKED
            locked.active_epoch = None
            locked.active_connection_nonce = None
            locked.revoked_at = datetime.now(UTC)
            send_task = asyncio.create_task(
                realtime._send_if_active(second_connection, ["must-not-send"])
            )
            sender_pid = await asyncio.wait_for(recording_sessions.backend_pids.get(), timeout=2)
            await _wait_for_postgres_lock(observer, sender_pid)
            assert not send_task.done()
            await revoker.commit()
        with pytest.raises(StaleConnection, match="no longer active"):
            await asyncio.wait_for(send_task, timeout=2)
        send_task = None
        assert second_socket.sent == []
    finally:
        for task in (send_task, revoke_task):
            if task is not None and not task.done():
                task.cancel()
        await asyncio.gather(
            *(task for task in (send_task, revoke_task) if task is not None),
            return_exceptions=True,
        )
        if engine is not None:
            await engine.dispose()
        await observer.close()
        await administrator.execute(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE')
        await administrator.close()


async def test_real_postgres_snapshot_barrier_catches_late_event_once() -> None:
    assert POSTGRES_DSN is not None
    raw_dsn = POSTGRES_DSN.replace("postgresql+asyncpg://", "postgresql://", 1)
    async_dsn = raw_dsn.replace("postgresql://", "postgresql+asyncpg://", 1)
    schema = f"codex_snapshot_order_{uuid.uuid4().hex}"
    administrator = await asyncpg.connect(raw_dsn)
    observer = await asyncpg.connect(raw_dsn)
    engine = None
    late_task: asyncio.Task[object] | None = None
    try:
        await administrator.execute(f'CREATE SCHEMA "{schema}"')
        engine = create_async_engine(
            async_dsn,
            connect_args={"server_settings": {"search_path": schema}},
        )
        async with engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)

        settings = Settings(
            environment="test",
            database_url=async_dsn,
            redis_url="memory://",
            session_hmac_secret="snapshot-order-test-secret-with-at-least-32-bytes",
            cookie_secure=False,
            allowed_origins_csv="https://control.example.test",
        )
        store = InMemoryKeyValueStore("snapshot-order:")
        events = EventService(settings, store)
        sessions = async_sessionmaker(engine, expire_on_commit=False, autoflush=False)
        device = Device(
            owner_user_id="owner",
            name="Snapshot device",
            public_key=f"postgres-snapshot-{uuid.uuid4()}",
            status=DeviceStatus.ACTIVE,
            device_metadata={},
            workspace_roots=[],
        )
        async with sessions() as seed:
            seed.add(device)
            await seed.commit()
            initial = await events.append(
                seed,
                owner_user_id="owner",
                device_id=device.id,
                event_type="device.updated",
                data={"phase": "snapshot"},
            )
            await seed.commit()
        assert initial.cursor == "1"

        async with sessions() as snapshot, sessions() as writer:
            baseline = await events.lock_snapshot_cursor(snapshot, "owner")
            snapshot_rows = list(
                (
                    await snapshot.scalars(
                        select(EventLog)
                        .where(EventLog.owner_user_id == "owner")
                        .order_by(EventLog.owner_cursor)
                    )
                ).all()
            )
            writer_pid = int(await writer.scalar(text("SELECT pg_backend_pid()")))

            async def append_late_event() -> object:
                late = await events.append(
                    writer,
                    owner_user_id="owner",
                    device_id=device.id,
                    event_type="device.updated",
                    data={"phase": "late"},
                )
                await writer.commit()
                return late

            late_task = asyncio.create_task(append_late_event())
            wait_state = None
            for _ in range(200):
                wait_state = await observer.fetchrow(
                    """
                    SELECT wait_event_type, wait_event
                    FROM pg_stat_activity
                    WHERE pid = $1
                    """,
                    writer_pid,
                )
                if wait_state is not None and wait_state["wait_event_type"] == "Lock":
                    break
                await asyncio.sleep(0.01)
            assert wait_state is not None
            assert wait_state["wait_event_type"] == "Lock"
            assert not late_task.done()
            assert baseline == 1
            assert [row.payload["phase"] for row in snapshot_rows] == ["snapshot"]

            await snapshot.commit()
            late = await asyncio.wait_for(late_task, timeout=2)
            assert late.cursor == "2"

        async with sessions() as reconnect:
            catch_up = await events.catch_up(reconnect, "owner", baseline)
        assert [event.cursor for event in catch_up] == ["2"]
        assert [event.data["phase"] for event in catch_up] == ["late"]
        await store.close()
    finally:
        if late_task is not None and not late_task.done():
            late_task.cancel()
            await asyncio.gather(late_task, return_exceptions=True)
        if engine is not None:
            await engine.dispose()
        await observer.close()
        await administrator.execute(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE')
        await administrator.close()


async def test_real_postgres_owner_capacity_serializes_last_slot_across_devices() -> None:
    assert POSTGRES_DSN is not None
    raw_dsn = POSTGRES_DSN.replace("postgresql+asyncpg://", "postgresql://", 1)
    async_dsn = raw_dsn.replace("postgresql://", "postgresql+asyncpg://", 1)
    schema = f"codex_owner_capacity_{uuid.uuid4().hex}"
    administrator = await asyncpg.connect(raw_dsn)
    observer = await asyncpg.connect(raw_dsn)
    engine = None
    running_task: asyncio.Task[str] | None = None
    try:
        await administrator.execute(f'CREATE SCHEMA "{schema}"')
        engine = create_async_engine(
            async_dsn,
            connect_args={"server_settings": {"search_path": schema}},
        )
        async with engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)

        settings = Settings(
            environment="test",
            database_url=async_dsn,
            redis_url="memory://",
            session_hmac_secret="capacity-test-secret-with-at-least-32-bytes",
            cookie_secure=False,
            allowed_origins_csv="https://control.example.test",
            bootstrap_max_devices=1,
            bootstrap_max_threads=1,
            bootstrap_max_pending_approvals=1,
        )
        store = InMemoryKeyValueStore("capacity-order:")
        events = EventService(settings, store)
        sessions = async_sessionmaker(engine, expire_on_commit=False, autoflush=False)

        device_a = Device(
            owner_user_id="owner",
            name="A",
            public_key=f"capacity-a-{uuid.uuid4()}",
            status=DeviceStatus.ACTIVE,
            device_metadata={},
            workspace_roots=["/workspace"],
        )
        device_b = Device(
            owner_user_id="owner",
            name="B",
            public_key=f"capacity-b-{uuid.uuid4()}",
            status=DeviceStatus.ACTIVE,
            device_metadata={},
            workspace_roots=["/workspace"],
        )

        async with sessions() as first, sessions() as second:
            await ensure_device_creation_capacity(first, events, settings, "owner")
            first.add(device_a)
            await first.flush()
            second_pid = int(await second.scalar(text("SELECT pg_backend_pid()")))

            async def create_second_device() -> str:
                try:
                    await ensure_device_creation_capacity(second, events, settings, "owner")
                    second.add(device_b)
                    await second.commit()
                    return "created"
                except OwnerCapacityExceeded as exc:
                    await second.rollback()
                    return exc.code

            running_task = asyncio.create_task(create_second_device())
            await _wait_for_postgres_lock(observer, second_pid)
            assert not running_task.done()
            await first.commit()
            assert await asyncio.wait_for(running_task, timeout=2) == "active_device_limit_exceeded"
            running_task = None

        async with sessions() as seed:
            # The active-device quota is independently proven above. A second
            # device lets the remaining races exercise Device -> Owner ordering
            # across different device rows.
            seed.add(device_b)
            await seed.commit()

        settings.owner_max_approval_records = 1
        record_now = datetime.now(UTC)
        async with sessions() as first, sessions() as second:
            await first.scalar(select(Device).where(Device.id == device_a.id).with_for_update())
            await events.lock_owner_cursor(first, "owner")
            await ensure_approval_record_capacity_locked(
                first,
                settings,
                "owner",
                device_a.id,
            )
            first.add(
                Approval(
                    owner_user_id="owner",
                    device_id=device_a.id,
                    external_command_id="approval-record-a",
                    approval_kind="permission",
                    summary="Record A",
                    request={},
                    status=ApprovalStatus.DENIED,
                    appserver_epoch="epoch-0123456789",
                    requested_at=record_now,
                    expires_at=record_now + timedelta(minutes=1),
                    decided_at=record_now,
                    decision_reason="device_offline_default_deny",
                )
            )
            await first.flush()
            second_pid = int(await second.scalar(text("SELECT pg_backend_pid()")))

            async def claim_last_approval_record() -> str:
                await second.scalar(
                    select(Device).where(Device.id == device_b.id).with_for_update()
                )
                await events.lock_owner_cursor(second, "owner")
                try:
                    await ensure_approval_record_capacity_locked(
                        second,
                        settings,
                        "owner",
                        device_b.id,
                    )
                    await second.commit()
                    return "created"
                except OwnerCapacityExceeded as exc:
                    await second.rollback()
                    return exc.code

            running_task = asyncio.create_task(claim_last_approval_record())
            await _wait_for_postgres_lock(observer, second_pid)
            assert not running_task.done()
            await first.commit()
            assert (
                await asyncio.wait_for(running_task, timeout=2)
                == "owner_approval_record_limit_exceeded"
            )
            running_task = None

        async with sessions() as first, sessions() as second:
            await first.scalar(select(Device).where(Device.id == device_a.id).with_for_update())
            await ensure_thread_creation_capacity(first, events, settings, "owner")
            first.add(
                ThreadBinding(
                    owner_user_id="owner",
                    device_id=device_a.id,
                    remote_thread_id="capacity-thread-a",
                    status=ThreadBindingStatus.IDLE,
                    cwd="/workspace",
                    title="A",
                    model="gpt",
                    appserver_epoch="epoch-0123456789",
                    snapshot={"messages": []},
                )
            )
            await first.flush()
            second_pid = int(await second.scalar(text("SELECT pg_backend_pid()")))

            async def create_second_thread() -> str:
                await second.scalar(
                    select(Device).where(Device.id == device_b.id).with_for_update()
                )
                try:
                    await ensure_thread_creation_capacity(second, events, settings, "owner")
                    second.add(
                        ThreadBinding(
                            owner_user_id="owner",
                            device_id=device_b.id,
                            remote_thread_id="capacity-thread-b",
                            status=ThreadBindingStatus.IDLE,
                            cwd="/workspace",
                            title="B",
                            model="gpt",
                            appserver_epoch="epoch-0123456789",
                            snapshot={"messages": []},
                        )
                    )
                    await second.commit()
                    return "created"
                except OwnerCapacityExceeded as exc:
                    await second.rollback()
                    return exc.code

            running_task = asyncio.create_task(create_second_thread())
            await _wait_for_postgres_lock(observer, second_pid)
            assert not running_task.done()
            await first.commit()
            assert await asyncio.wait_for(running_task, timeout=2) == "thread_limit_exceeded"
            running_task = None

        now = datetime.now(UTC)
        async with sessions() as first, sessions() as second:
            await first.scalar(select(Device).where(Device.id == device_a.id).with_for_update())
            await events.lock_owner_cursor(first, "owner")
            assert (
                await approval_capacity_denial_reason_locked(
                    first, settings, "owner", device_a.id, now
                )
                is None
            )
            first.add(
                Approval(
                    owner_user_id="owner",
                    device_id=device_a.id,
                    external_command_id="approval-a",
                    approval_kind="permission",
                    summary="A",
                    request={},
                    status=ApprovalStatus.PENDING,
                    appserver_epoch="epoch-0123456789",
                    requested_at=now,
                    expires_at=now + timedelta(minutes=1),
                )
            )
            await first.flush()
            second_pid = int(await second.scalar(text("SELECT pg_backend_pid()")))

            async def create_second_approval() -> str:
                await second.scalar(
                    select(Device).where(Device.id == device_b.id).with_for_update()
                )
                await events.lock_owner_cursor(second, "owner")
                reason = await approval_capacity_denial_reason_locked(
                    second, settings, "owner", device_b.id, now
                )
                second.add(
                    Approval(
                        owner_user_id="owner",
                        device_id=device_b.id,
                        external_command_id="approval-b",
                        approval_kind="permission",
                        summary="B",
                        request={},
                        status=(
                            ApprovalStatus.PENDING if reason is None else ApprovalStatus.DENIED
                        ),
                        appserver_epoch="epoch-0123456789",
                        requested_at=now,
                        expires_at=now + timedelta(minutes=1),
                        decided_at=now if reason is not None else None,
                        decision_reason=reason,
                    )
                )
                await second.commit()
                return reason or "pending"

            running_task = asyncio.create_task(create_second_approval())
            await _wait_for_postgres_lock(observer, second_pid)
            assert not running_task.done()
            await first.commit()
            assert (
                await asyncio.wait_for(running_task, timeout=2)
                == "owner_approval_limit_default_deny"
            )
            running_task = None

        async with sessions() as verify:
            devices = list(
                (await verify.scalars(select(Device).where(Device.owner_user_id == "owner"))).all()
            )
            threads = list(
                (
                    await verify.scalars(
                        select(ThreadBinding).where(ThreadBinding.owner_user_id == "owner")
                    )
                ).all()
            )
            approvals = list(
                (
                    await verify.scalars(
                        select(Approval)
                        .where(Approval.owner_user_id == "owner")
                        .order_by(Approval.external_command_id)
                    )
                ).all()
            )
        assert len(devices) == 2
        assert len(threads) == 1
        assert [approval.status for approval in approvals] == [
            ApprovalStatus.PENDING,
            ApprovalStatus.DENIED,
            ApprovalStatus.DENIED,
        ]
        await store.close()
    finally:
        if running_task is not None and not running_task.done():
            running_task.cancel()
            await asyncio.gather(running_task, return_exceptions=True)
        if engine is not None:
            await engine.dispose()
        await observer.close()
        await administrator.execute(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE')
        await administrator.close()


async def test_real_postgres_catchup_share_lock_blocks_retention_floor_advance() -> None:
    assert POSTGRES_DSN is not None
    raw_dsn = POSTGRES_DSN.replace("postgresql+asyncpg://", "postgresql://", 1)
    async_dsn = raw_dsn.replace("postgresql://", "postgresql+asyncpg://", 1)
    schema = f"codex_retention_cursor_{uuid.uuid4().hex}"
    administrator = await asyncpg.connect(raw_dsn)
    observer = await asyncpg.connect(raw_dsn)
    engine = None
    prune_task: asyncio.Task[int] | None = None
    try:
        await administrator.execute(f'CREATE SCHEMA "{schema}"')
        engine = create_async_engine(
            async_dsn,
            connect_args={"server_settings": {"search_path": schema}},
        )
        async with engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)
        settings = Settings(
            environment="test",
            database_url=async_dsn,
            redis_url="memory://",
            session_hmac_secret="retention-test-secret-with-at-least-32-bytes",
            cookie_secure=False,
            allowed_origins_csv="https://control.example.test",
        )
        settings.browser_event_max_per_owner = 2
        store = InMemoryKeyValueStore("retention-order:")
        events = EventService(settings, store)
        sessions = async_sessionmaker(engine, expire_on_commit=False, autoflush=False)
        device = Device(
            owner_user_id="owner",
            name="Retention",
            public_key=f"retention-{uuid.uuid4()}",
            status=DeviceStatus.ACTIVE,
            device_metadata={},
            workspace_roots=[],
        )
        async with sessions() as seed:
            seed.add(device)
            await seed.commit()
            for index in range(3):
                await events.append(
                    seed,
                    owner_user_id="owner",
                    device_id=device.id,
                    event_type="device.updated",
                    data={"index": index},
                )
                await seed.commit()

        async with sessions() as reader, sessions() as pruner:
            catch_up = await events.catch_up(reader, "owner", 0)
            assert [event.cursor for event in catch_up] == ["1", "2", "3"]
            pruner_pid = int(await pruner.scalar(text("SELECT pg_backend_pid()")))
            prune_task = asyncio.create_task(events.prune(pruner))
            await _wait_for_postgres_lock(observer, pruner_pid)
            assert not prune_task.done()

            # The client received a self-consistent retained window before the
            # writer can delete cursor 1 and advance minimum_resume_cursor.
            await reader.commit()
            assert await asyncio.wait_for(prune_task, timeout=2) == 1
            prune_task = None

        async with sessions() as verify:
            state = await verify.get(EventOwnerCursor, "owner")
            rows = list(
                (
                    await verify.scalars(
                        select(EventLog)
                        .where(EventLog.owner_user_id == "owner")
                        .order_by(EventLog.owner_cursor)
                    )
                ).all()
            )
        assert state is not None
        assert (state.minimum_resume_cursor, state.last_cursor) == (1, 3)
        assert [row.owner_cursor for row in rows] == [2, 3]
        await store.close()
    finally:
        if prune_task is not None and not prune_task.done():
            prune_task.cancel()
            await asyncio.gather(prune_task, return_exceptions=True)
        if engine is not None:
            await engine.dispose()
        await observer.close()
        await administrator.execute(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE')
        await administrator.close()


async def test_real_postgres_retention_preserves_unacked_and_fk_audit_history() -> None:
    from control_api.models import (
        AuditEvent,
        AuditOutcome,
        Command,
        CommandStatus,
        ControlSession,
        DeviceOutbox,
    )
    from control_api.retention import RetentionService

    assert POSTGRES_DSN is not None
    raw_dsn = POSTGRES_DSN.replace("postgresql+asyncpg://", "postgresql://", 1)
    async_dsn = raw_dsn.replace("postgresql://", "postgresql+asyncpg://", 1)
    schema = f"codex_state_retention_{uuid.uuid4().hex}"
    administrator = await asyncpg.connect(raw_dsn)
    engine = None
    try:
        await administrator.execute(f'CREATE SCHEMA "{schema}"')
        engine = create_async_engine(
            async_dsn,
            connect_args={"server_settings": {"search_path": schema}},
        )
        async with engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)
        settings = Settings(
            environment="test",
            database_url=async_dsn,
            redis_url="memory://",
            session_hmac_secret="state-retention-test-secret-with-at-least-32-bytes",
            cookie_secure=False,
            allowed_origins_csv="https://control.example.test",
            session_record_retention_days=1,
            command_record_retention_days=1,
            revoked_device_retention_days=30,
            audit_event_retention_days=365,
            retention_sweep_batch_size=100,
        )
        sessions = async_sessionmaker(engine, expire_on_commit=False, autoflush=False)
        now = datetime.now(UTC)
        old = now - timedelta(days=3)
        control_session = ControlSession(
            token_hash="a" * 64,
            csrf_token_hash="b" * 64,
            sub2api_user_id="owner",
            issued_at=old - timedelta(minutes=10),
            expires_at=old,
            last_seen_at=old,
        )
        device = Device(
            owner_user_id="owner",
            name="Retention",
            public_key=f"state-retention-{uuid.uuid4()}",
            status=DeviceStatus.ACTIVE,
            device_metadata={},
            workspace_roots=[],
            last_server_sequence=1,
            last_server_acked_sequence=0,
        )
        async with sessions() as seed:
            seed.add_all([control_session, device])
            await seed.flush()
            audit = AuditEvent(
                actor_user_id="owner",
                actor_session_id=control_session.id,
                actor_device_id=device.id,
                action="retention.fk-history",
                outcome=AuditOutcome.SUCCEEDED,
                created_at=now,
            )
            command = Command(
                owner_user_id="owner",
                device_id=device.id,
                idempotency_key="real-postgres-retention",
                idempotency_scope="retention",
                request_hash="c" * 64,
                method="model/list",
                payload={},
                status=CommandStatus.SUCCEEDED,
                created_at=old,
                completed_at=old,
                expires_at=old,
            )
            outbox = DeviceOutbox(
                device_id=device.id,
                sequence=1,
                encoded_envelope="unacknowledged-command",
                ack_sequence=0,
                frame_type="command",
                byte_size=22,
                created_at=old,
                retained_until=now + timedelta(days=1),
            )
            seed.add_all([audit, command, outbox])
            await seed.commit()

        service = RetentionService(settings)
        async with sessions() as db:
            blocked = await service.sweep(db, now=now)
        assert blocked.control_sessions == 1
        assert blocked.commands == 0
        async with sessions() as verify:
            stored_audit = await verify.get(AuditEvent, audit.id)
            assert stored_audit is not None
            assert stored_audit.actor_session_id == control_session.id
            assert stored_audit.actor_device_id == device.id
            assert await verify.get(Command, command.id) is not None

        async with sessions() as db:
            stored_outbox = await db.get(DeviceOutbox, (device.id, 1))
            stored_device = await db.get(Device, device.id)
            assert stored_outbox is not None and stored_device is not None
            stored_outbox.acked_at = now
            stored_device.last_server_acked_sequence = 1
            await db.commit()
        async with sessions() as db:
            unblocked = await service.sweep(db, now=now)
        assert unblocked.commands == 1
        async with sessions() as verify:
            assert await verify.get(Command, command.id) is None
            assert await verify.get(AuditEvent, audit.id) is not None

        async with sessions() as db:
            stored_outbox = await db.get(DeviceOutbox, (device.id, 1))
            stored_device = await db.get(Device, device.id)
            assert stored_outbox is not None and stored_device is not None
            await db.delete(stored_outbox)
            stored_device.status = DeviceStatus.REVOKED
            stored_device.revoked_at = now - timedelta(days=40)
            await db.commit()
        async with sessions() as db:
            device_cleanup = await service.sweep(db, now=now)
        assert device_cleanup.devices == 1
        async with sessions() as verify:
            immutable_audit = await verify.get(AuditEvent, audit.id)
            assert await verify.get(Device, device.id) is None
            assert immutable_audit is not None
            assert immutable_audit.actor_session_id == control_session.id
            assert immutable_audit.actor_device_id == device.id

        migration_path = (
            REPOSITORY_ROOT / "migrations" / "versions" / "20260723_0005_retention_indexes.py"
        )
        migration_spec = importlib.util.spec_from_file_location(
            "test_pg_retention_migration",
            migration_path,
        )
        assert migration_spec is not None and migration_spec.loader is not None
        retention_migration = importlib.util.module_from_spec(migration_spec)
        migration_spec.loader.exec_module(retention_migration)
        await administrator.execute(f'SET search_path TO "{schema}"')
        with pytest.raises(asyncpg.PostgresError, match="historical references are orphaned"):
            await administrator.execute(retention_migration.DOWNGRADE_AUDIT_REFERENCE_GUARD)

        index_rows = await administrator.fetch(
            "SELECT indexname FROM pg_indexes WHERE schemaname = $1",
            schema,
        )
        index_names = {str(row["indexname"]) for row in index_rows}
        assert {
            "ix_device_connections_retention",
            "ix_commands_retention",
            "ix_approvals_retention",
            "ix_thread_bindings_retention",
            "ix_devices_retention",
        } <= index_names
    finally:
        if engine is not None:
            await engine.dispose()
        await administrator.execute("SET search_path TO public")
        await administrator.execute(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE')
        await administrator.close()


async def _wait_for_postgres_lock(observer: asyncpg.Connection, backend_pid: int) -> None:
    wait_state = None
    for _ in range(200):
        wait_state = await observer.fetchrow(
            """
            SELECT wait_event_type, wait_event
            FROM pg_stat_activity
            WHERE pid = $1
            """,
            backend_pid,
        )
        if wait_state is not None and wait_state["wait_event_type"] == "Lock":
            break
        await asyncio.sleep(0.01)
    assert wait_state is not None
    assert wait_state["wait_event_type"] == "Lock"
