from __future__ import annotations

import asyncio
import base64
import gc
import json
import time
import uuid
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any

import pytest
from conftest import ORIGIN, Harness, exchange
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

import control_api.realtime as realtime_module
from control_api.app import _run_sweep_cycle
from control_api.approvals import (
    NON_DISPATCHABLE_APPROVAL_REASONS,
    ApprovalDeviceOffline,
)
from control_api.commands import (
    CommandCapacityExceeded,
    CommandIdempotencyConflict,
    wire_idempotency_key,
)
from control_api.models import (
    Approval,
    ApprovalStatus,
    AuditEvent,
    Command,
    CommandStatus,
    ConnectionStatus,
    ControlSession,
    Device,
    DeviceConnection,
    DeviceOutbox,
    DeviceStatus,
    EventLog,
    ThreadBinding,
    ThreadBindingStatus,
)
from control_api.protocol import (
    ALLOWED_RPC_METHODS,
    ControlEnvelope,
    HelloPayload,
    ensure_ascii_json_byte_length,
)
from control_api.realtime import ActiveDeviceSocket, BrowserSessionGate, RealtimeProtocolError
from control_api.services import RequestMetadata
from control_api.storage import InMemoryKeyValueStore
from control_api.thread_snapshot import serialized_json_byte_length

EPOCH_ONE = "epoch-one-0123456789abcdef012345"
EPOCH_TWO = "epoch-two-0123456789abcdef012345"
EPOCH_THREE = "epoch-three-0123456789abcdef0123"


def csrf_headers(harness: Harness) -> dict[str, str]:
    token = harness.client.cookies.get(harness.settings.csrf_cookie_name)
    assert token is not None
    return {"Origin": ORIGIN, harness.settings.csrf_header_name: token}


class RecordingWebSocket:
    def __init__(self) -> None:
        self.sent: list[str] = []
        self.closed: list[tuple[int, str]] = []
        self.headers: dict[str, str] = {}
        self.client = None

    async def send_text(self, value: str) -> None:
        self.sent.append(value)

    async def close(self, code: int, reason: str) -> None:
        self.closed.append((code, reason))


class FailingSendWebSocket(RecordingWebSocket):
    async def send_text(self, value: str) -> None:
        raise RuntimeError("simulated socket send failure")


class BlockingSendWebSocket(RecordingWebSocket):
    def __init__(self) -> None:
        super().__init__()
        self.started = asyncio.Event()
        self.release = asyncio.Event()

    async def send_text(self, value: str) -> None:
        self.sent.append(value)
        self.started.set()
        await self.release.wait()


def frame(
    device_id: uuid.UUID,
    sequence: int,
    envelope_type: str,
    payload: dict[str, Any],
    *,
    epoch: str = EPOCH_THREE,
    ack: int = 0,
) -> ControlEnvelope:
    return ControlEnvelope.model_validate(
        {
            "version": 1,
            "id": str(uuid.uuid4()),
            "device_id": str(device_id),
            "epoch": epoch,
            "seq": sequence,
            "ack": ack,
            "type": envelope_type,
            "sent_at": datetime.now(UTC),
            "payload": payload,
        }
    )


async def seed_active_device(
    harness: Harness,
    *,
    epoch: str = EPOCH_THREE,
) -> tuple[Device, ActiveDeviceSocket]:
    device = Device(
        owner_user_id="42",
        name="Hardening test device",
        public_key=f"test-public-key-{uuid.uuid4()}",
        status="active",
        workspace_roots=["/workspace"],
        active_epoch=epoch,
    )
    nonce = str(uuid.uuid4())
    device.active_connection_nonce = nonce
    async with harness.database.session_factory() as db:
        db.add(device)
        await db.commit()
    registry = json.dumps(
        {"connection_nonce": nonce, "epoch": epoch, "instance_id": "test"},
        separators=(",", ":"),
    )
    await harness.store.set(
        f"connection:{device.id}",
        registry,
        harness.settings.device_registry_ttl_seconds,
    )
    connection = ActiveDeviceSocket(
        websocket=RecordingWebSocket(),  # type: ignore[arg-type]
        device_id=device.id,
        owner_user_id=device.owner_user_id,
        connection_nonce=nonce,
        epoch=epoch,
        registry_value=registry,
    )
    return device, connection


async def seed_connectable_device(harness: Harness) -> tuple[Device, HelloPayload]:
    public_key = (
        base64.urlsafe_b64encode(uuid.uuid4().bytes + uuid.uuid4().bytes).rstrip(b"=").decode()
    )
    device = Device(
        owner_user_id="42",
        name="Activation test device",
        public_key=public_key,
        status=DeviceStatus.ACTIVE,
        workspace_roots=["/workspace"],
    )
    async with harness.database.session_factory() as db:
        db.add(device)
        await db.commit()
    return device, HelloPayload(
        connector_version=harness.settings.connector_expected_version,
        codex_version=harness.settings.codex_expected_version,
        schema_digest=harness.settings.appserver_schema_digest,
        public_key=device.public_key,
        capabilities=sorted(ALLOWED_RPC_METHODS),
        workspace_roots=["/workspace"],
        resumed_from_seq=0,
    )


def hello_frame(device: Device, hello: HelloPayload, epoch: str) -> ControlEnvelope:
    return ControlEnvelope.model_validate(
        {
            "version": 1,
            "id": str(uuid.uuid4()),
            "device_id": str(device.id),
            "epoch": epoch,
            "seq": 0,
            "ack": 0,
            "type": "hello",
            "sent_at": datetime.now(UTC),
            "payload": hello.model_dump(mode="json"),
        }
    )


async def test_inbound_cursor_rolls_back_with_failed_durable_projection(
    harness: Harness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    device, connection = await seed_active_device(harness)
    binding = ThreadBinding(
        owner_user_id="42",
        device_id=device.id,
        remote_thread_id="rollback-thread",
        status=ThreadBindingStatus.RUNNING,
        cwd="/workspace",
        title="Rollback",
        model="gpt-5.5",
        appserver_epoch=EPOCH_THREE,
        snapshot={"messages": []},
    )
    async with harness.database.session_factory() as db:
        db.add(binding)
        await db.commit()

    async def fail_append(*_args: object, **_kwargs: object) -> object:
        raise RuntimeError("simulated durable projection failure")

    monkeypatch.setattr(harness.app.state.events, "append", fail_append)
    incoming = frame(
        device.id,
        1,
        "event",
        {
            "method": "item/agentMessage/delta",
            "params": {
                "threadId": binding.remote_thread_id,
                "itemId": "assistant-1",
                "delta": "must roll back",
            },
        },
    )
    with pytest.raises(RuntimeError, match="durable projection failure"):
        await harness.app.state.realtime._process_device_frame(connection, incoming)

    async with harness.database.session_factory() as db:
        stored_device = await db.get(Device, device.id)
        stored_binding = await db.get(ThreadBinding, binding.id)
        event_count = await db.scalar(select(func.count(EventLog.id)))
    assert stored_device.last_device_sequence == 0
    assert stored_binding.snapshot == {"messages": []}
    assert event_count == 0


async def test_database_outbox_survives_cache_loss_and_enforces_bounds(
    harness: Harness,
) -> None:
    device, connection = await seed_active_device(harness)
    socket = connection.websocket
    sequence = await harness.app.state.realtime._send_envelope(
        connection,
        "heartbeat_ack",
        {"received_seq": 0},
    )
    assert sequence == 1
    assert await harness.store.get(f"device-outbox:{device.id}:1") is None

    async with harness.database.session_factory() as db:
        durable = await db.get(DeviceOutbox, (device.id, 1))
    assert durable is not None
    assert durable.encoded_envelope == socket.sent[0]

    await harness.store.close()
    replay_socket = RecordingWebSocket()
    replay_connection = ActiveDeviceSocket(
        websocket=replay_socket,  # type: ignore[arg-type]
        device_id=device.id,
        owner_user_id="42",
        connection_nonce=connection.connection_nonce,
        epoch=EPOCH_THREE,
        registry_value=connection.registry_value,
    )
    await harness.app.state.realtime._replay_outbox(replay_connection)
    assert replay_socket.sent == [durable.encoded_envelope]

    harness.settings.device_max_outbox_frames = 1
    with pytest.raises(RealtimeProtocolError, match="frame limit"):
        await harness.app.state.realtime._send_envelope(
            connection,
            "heartbeat_ack",
            {"received_seq": 0},
        )
    async with harness.database.session_factory() as db:
        stored_device = await db.get(Device, device.id)
        outbox_count = await db.scalar(select(func.count(DeviceOutbox.sequence)))
    assert stored_device.last_server_sequence == 1
    assert outbox_count == 1

    harness.settings.device_max_outbox_frames = 2
    harness.settings.device_max_outbox_bytes = durable.byte_size + 10
    with pytest.raises(RealtimeProtocolError, match="byte limit"):
        await harness.app.state.realtime._send_envelope(
            connection,
            "heartbeat_ack",
            {"received_seq": 0},
        )
    harness.settings.device_max_outbox_bytes = 8388608
    harness.settings.device_outbox_retention_seconds = 3600
    async with harness.database.session_factory() as db:
        durable = await db.get(DeviceOutbox, (device.id, 1))
        durable.created_at = datetime.now(UTC) - timedelta(hours=2)
        durable.retained_until = datetime.now(UTC) + timedelta(hours=1)
        await db.commit()
    with pytest.raises(RealtimeProtocolError, match="retention limit"):
        await harness.app.state.realtime._send_envelope(
            connection,
            "heartbeat_ack",
            {"received_seq": 0},
        )


async def test_concurrent_command_and_approval_dispatch_allocate_one_frame_each(
    harness: Harness,
) -> None:
    device, connection = await seed_active_device(harness)
    now = datetime.now(UTC)
    command = Command(
        owner_user_id="42",
        device_id=device.id,
        idempotency_key="dispatch-once",
        idempotency_scope="dispatch-once",
        request_hash="0" * 64,
        method="model/list",
        payload={"limit": 100},
        status=CommandStatus.QUEUED,
        appserver_epoch=EPOCH_THREE,
        expires_at=now + timedelta(seconds=30),
    )
    approval = Approval(
        owner_user_id="42",
        device_id=device.id,
        external_command_id="approval-dispatch-once",
        approval_kind="permission",
        summary="Dispatch once",
        request={},
        status=ApprovalStatus.DENIED,
        appserver_epoch=EPOCH_THREE,
        requested_at=now,
        expires_at=now + timedelta(seconds=30),
        decided_at=now,
        decision_reason="user_denied",
    )
    async with harness.database.session_factory() as db:
        db.add_all([command, approval])
        await db.commit()

    await asyncio.gather(
        harness.app.state.realtime._dispatch_command(connection, command.id),
        harness.app.state.realtime._dispatch_command(connection, command.id),
    )
    await asyncio.gather(
        harness.app.state.realtime._dispatch_approval(connection, approval.id),
        harness.app.state.realtime._dispatch_approval(connection, approval.id),
    )

    async with harness.database.session_factory() as db:
        stored_command = await db.get(Command, command.id)
        stored_approval = await db.get(Approval, approval.id)
        rows = list(
            (
                await db.scalars(
                    select(DeviceOutbox)
                    .where(DeviceOutbox.device_id == device.id)
                    .order_by(DeviceOutbox.sequence)
                )
            ).all()
        )
    assert stored_command.status == CommandStatus.DISPATCHED
    assert stored_approval.decision_dispatched_at is not None
    assert [row.frame_type for row in rows] == ["command", "approval_decision"]
    assert len(connection.websocket.sent) == 2


async def test_device_dispatch_subscription_is_ready_before_pending_scan(
    harness: Harness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    device, connection = await seed_active_device(harness)
    activation = asyncio.Event()
    duplicate_processed = asyncio.Event()
    dispatch_calls = 0
    original_dispatch_command = harness.app.state.realtime._dispatch_command

    async def record_dispatch(
        dispatched_connection: ActiveDeviceSocket,
        command_id: uuid.UUID,
    ) -> None:
        nonlocal dispatch_calls
        dispatch_calls += 1
        try:
            await original_dispatch_command(dispatched_connection, command_id)
        finally:
            if dispatch_calls == 2:
                duplicate_processed.set()

    monkeypatch.setattr(harness.app.state.realtime, "_dispatch_command", record_dispatch)
    durable = json.dumps(
        {
            "version": 1,
            "id": str(uuid.uuid4()),
            "device_id": str(device.id),
            "epoch": EPOCH_THREE,
            "seq": 1,
            "ack": 0,
            "type": "heartbeat_ack",
            "sent_at": datetime.now(UTC).isoformat(),
            "payload": {"received_seq": 0},
        },
        separators=(",", ":"),
    )
    now = datetime.now(UTC)
    async with harness.database.session_factory() as db:
        stored_device = await db.get(Device, device.id)
        stored_device.last_server_sequence = 1
        db.add(
            DeviceOutbox(
                device_id=device.id,
                sequence=1,
                encoded_envelope=durable,
                ack_sequence=0,
                frame_type="heartbeat_ack",
                byte_size=len(durable.encode("utf-8")),
                created_at=now,
                retained_until=now + timedelta(hours=1),
            )
        )
        await db.commit()

    dispatch_loop = await harness.app.state.realtime._start_device_dispatch(
        connection,
        activation,
    )

    command = Command(
        owner_user_id="42",
        device_id=device.id,
        idempotency_key="subscriber-ready-window",
        idempotency_scope="subscriber-ready-window",
        request_hash="f" * 64,
        method="model/list",
        payload={"limit": 100},
        status=CommandStatus.QUEUED,
        appserver_epoch=EPOCH_THREE,
        expires_at=datetime.now(UTC) + timedelta(seconds=30),
    )
    async with harness.database.session_factory() as db:
        db.add(command)
        await db.commit()
    subscribers = await harness.store.publish(
        f"device-dispatch:{device.id}",
        json.dumps({"kind": "command", "command_id": str(command.id)}),
    )
    assert subscribers == 1
    await asyncio.sleep(0)
    async with harness.database.session_factory() as db:
        queued = await db.get(Command, command.id)
        assert queued.status == CommandStatus.QUEUED
        assert (
            await db.scalar(
                select(DeviceOutbox).where(
                    DeviceOutbox.device_id == device.id,
                    DeviceOutbox.frame_type == "command",
                )
            )
            is None
        )

    await harness.app.state.realtime._replay_outbox(connection)
    await harness.app.state.realtime._dispatch_pending(connection)
    activation.set()
    try:
        await asyncio.wait_for(duplicate_processed.wait(), timeout=1)
        async with harness.database.session_factory() as db:
            stored = await db.get(Command, command.id)
            outbox = list(
                (
                    await db.scalars(
                        select(DeviceOutbox)
                        .where(DeviceOutbox.device_id == device.id)
                        .order_by(DeviceOutbox.sequence)
                    )
                ).all()
            )
        assert stored.status == CommandStatus.DISPATCHED
        assert [row.sequence for row in outbox] == [1, 2]
        assert dispatch_calls == 2
        frames = [json.loads(encoded) for encoded in connection.websocket.sent]
        assert [(frame["seq"], frame["type"]) for frame in frames] == [
            (1, "heartbeat_ack"),
            (2, "command"),
        ]
    finally:
        dispatch_loop.cancel()
        await asyncio.gather(dispatch_loop, return_exceptions=True)


async def test_device_handler_rechecks_authority_after_missed_revoke(
    harness: Harness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert (await exchange(harness)).status_code == 201
    device, hello = await seed_connectable_device(harness)
    command_id = uuid.uuid4()
    durable_command = json.dumps(
        {
            "version": 1,
            "id": str(uuid.uuid4()),
            "device_id": str(device.id),
            "epoch": EPOCH_THREE,
            "seq": 1,
            "ack": 0,
            "type": "command",
            "sent_at": datetime.now(UTC).isoformat(),
            "payload": {"command_id": str(command_id), "method": "model/list", "params": {}},
        },
        separators=(",", ":"),
    )
    now = datetime.now(UTC)
    async with harness.database.session_factory() as db:
        stored_device = await db.get(Device, device.id)
        stored_device.last_server_sequence = 1
        db.add(
            Command(
                id=command_id,
                owner_user_id="42",
                device_id=device.id,
                idempotency_key="revoke-before-replay",
                idempotency_scope="revoke-before-replay",
                request_hash="a" * 64,
                method="model/list",
                payload={},
                status=CommandStatus.DISPATCHED,
                appserver_epoch=EPOCH_THREE,
                expires_at=now + timedelta(seconds=30),
            )
        )
        db.add(
            DeviceOutbox(
                device_id=device.id,
                sequence=1,
                encoded_envelope=durable_command,
                ack_sequence=0,
                frame_type="command",
                byte_size=len(durable_command.encode("utf-8")),
                created_at=now,
                retained_until=now + timedelta(hours=1),
            )
        )
        await db.commit()
    websocket = RecordingWebSocket()
    websocket.headers = {"authorization": "Bearer test-device-access-token"}
    websocket.accept = lambda: asyncio.sleep(0)  # type: ignore[attr-defined]
    websocket.receive_text = lambda: asyncio.sleep(  # type: ignore[attr-defined]
        0,
        result=hello_frame(device, hello, EPOCH_THREE).model_dump_json(),
    )
    activation_finished = asyncio.Event()
    release_activation = asyncio.Event()
    published: list[tuple[str, dict[str, object], int]] = []
    original_publish = harness.store.publish
    original_send_hello_ack = harness.app.state.realtime._send_hello_ack

    async def authenticate_access_token(_db: AsyncSession, _token: str) -> Device:
        return device

    async def pause_after_hello_ack(
        connection: ActiveDeviceSocket,
        hello_payload: HelloPayload,
    ) -> None:
        await original_send_hello_ack(connection, hello_payload)
        activation_finished.set()
        await release_activation.wait()

    async def record_publish(channel: str, value: str) -> int:
        subscribers = await original_publish(channel, value)
        if channel == f"device-dispatch:{device.id}":
            published.append((channel, json.loads(value), subscribers))
        return subscribers

    monkeypatch.setattr(harness.store, "publish", record_publish)
    monkeypatch.setattr(
        harness.app.state.device_tokens,
        "authenticate_access_token",
        authenticate_access_token,
    )
    monkeypatch.setattr(harness.app.state.realtime, "_send_hello_ack", pause_after_hello_ack)

    handler = asyncio.create_task(
        harness.app.state.realtime.handle_device(websocket)  # type: ignore[arg-type]
    )
    try:
        await asyncio.wait_for(activation_finished.wait(), timeout=1)
        async with harness.database.session_factory() as db:
            active = await db.get(Device, device.id)
        assert active.active_connection_nonce is not None

        revoked = await harness.client.delete(
            f"/v1/devices/{device.id}",
            headers=csrf_headers(harness),
        )
        assert revoked.status_code == 204
        assert published[-1] == (
            f"device-dispatch:{device.id}",
            {
                "kind": "kick",
                "replaced_connection_nonces": [active.active_connection_nonce],
            },
            0,
        )

        release_activation.set()
        await asyncio.wait_for(handler, timeout=1)
        assert len(websocket.sent) == 1
        assert json.loads(websocket.sent[0])["type"] == "hello_ack"
        assert durable_command not in websocket.sent
        assert websocket.closed == [(4001, "connection registry ownership was lost")]
    finally:
        release_activation.set()
        if not handler.done():
            handler.cancel()
        await asyncio.gather(handler, return_exceptions=True)


async def test_device_handler_consumes_done_dispatch_failure_during_setup(
    harness: Harness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    device, hello = await seed_connectable_device(harness)
    websocket = RecordingWebSocket()
    websocket.headers = {"authorization": "Bearer test-device-access-token"}
    websocket.accept = lambda: asyncio.sleep(0)  # type: ignore[attr-defined]
    websocket.receive_text = lambda: asyncio.sleep(  # type: ignore[attr-defined]
        0,
        result=hello_frame(device, hello, EPOCH_THREE).model_dump_json(),
    )
    created_tasks: list[asyncio.Task[None]] = []
    unhandled: list[dict[str, object]] = []

    async def authenticate_access_token(_db: AsyncSession, _token: str) -> Device:
        return device

    async def fail_dispatch() -> None:
        raise RuntimeError("simulated dispatch failure")

    async def start_failed_dispatch(
        _connection: ActiveDeviceSocket,
        _activation: asyncio.Event,
    ) -> asyncio.Task[None]:
        task = asyncio.create_task(fail_dispatch())
        created_tasks.append(task)
        await asyncio.sleep(0)
        assert task.done()
        return task

    async def fail_replay(_connection: ActiveDeviceSocket) -> None:
        raise RealtimeProtocolError("simulated replay setup failure")

    monkeypatch.setattr(
        harness.app.state.device_tokens,
        "authenticate_access_token",
        authenticate_access_token,
    )
    monkeypatch.setattr(
        harness.app.state.realtime,
        "_start_device_dispatch",
        start_failed_dispatch,
    )
    monkeypatch.setattr(harness.app.state.realtime, "_replay_outbox", fail_replay)
    loop = asyncio.get_running_loop()
    previous_handler = loop.get_exception_handler()
    loop.set_exception_handler(lambda _loop, context: unhandled.append(context))
    try:
        await harness.app.state.realtime.handle_device(websocket)  # type: ignore[arg-type]
        assert websocket.closed == [(4400, "simulated replay setup failure")]
        assert len(created_tasks) == 1 and created_tasks[0].done()
        created_tasks.clear()
        gc.collect()
        await asyncio.sleep(0)
        assert unhandled == []
    finally:
        loop.set_exception_handler(previous_handler)


async def test_dispatch_send_failure_leaves_replayable_claimed_frame(
    harness: Harness,
) -> None:
    device, connection = await seed_active_device(harness)
    connection.websocket = FailingSendWebSocket()  # type: ignore[assignment]
    command = Command(
        owner_user_id="42",
        device_id=device.id,
        idempotency_key="dispatch-recovery",
        idempotency_scope="dispatch-recovery",
        request_hash="1" * 64,
        method="model/list",
        payload={"limit": 100},
        status=CommandStatus.QUEUED,
        appserver_epoch=EPOCH_THREE,
        expires_at=datetime.now(UTC) + timedelta(seconds=30),
    )
    async with harness.database.session_factory() as db:
        db.add(command)
        await db.commit()

    with pytest.raises(RuntimeError, match="socket send failure"):
        await harness.app.state.realtime._dispatch_command(connection, command.id)
    async with harness.database.session_factory() as db:
        stored_command = await db.get(Command, command.id)
        row = await db.scalar(select(DeviceOutbox).where(DeviceOutbox.device_id == device.id))
    assert stored_command.status == CommandStatus.DISPATCHED
    assert row is not None and row.frame_type == "command"

    replay_socket = RecordingWebSocket()
    replay_connection = ActiveDeviceSocket(
        websocket=replay_socket,  # type: ignore[arg-type]
        device_id=device.id,
        owner_user_id="42",
        connection_nonce=connection.connection_nonce,
        epoch=EPOCH_THREE,
        registry_value=connection.registry_value,
    )
    await harness.app.state.realtime._replay_outbox(replay_connection)
    assert replay_socket.sent == [row.encoded_envelope]
    async with harness.database.session_factory() as db:
        stored_device = await db.get(Device, device.id)
        outbox_count = await db.scalar(select(func.count(DeviceOutbox.sequence)))
    assert stored_device.last_server_sequence == 1
    assert outbox_count == 1


async def test_missing_duplicate_ack_fails_with_receive_cursor_instead_of_waiting(
    harness: Harness,
) -> None:
    device, connection = await seed_active_device(harness)
    async with harness.database.session_factory() as db:
        stored = await db.get(Device, device.id)
        stored.last_device_sequence = 1
        await db.commit()
    duplicate = frame(device.id, 1, "heartbeat", {"status": "ok"})
    with pytest.raises(RealtimeProtocolError, match="receive cursor 1"):
        await harness.app.state.realtime._process_device_frame(connection, duplicate)


async def test_three_epoch_backlog_advances_cursor_without_projecting_stale_resources(
    harness: Harness,
) -> None:
    device, connection = await seed_active_device(harness)
    current_binding = ThreadBinding(
        owner_user_id="42",
        device_id=device.id,
        remote_thread_id="current-thread",
        status=ThreadBindingStatus.RUNNING,
        cwd="/workspace",
        title="Current title",
        model="gpt-5.5",
        active_turn_id="current-turn",
        appserver_epoch=EPOCH_THREE,
        snapshot={"messages": []},
    )
    old_binding = ThreadBinding(
        owner_user_id="42",
        device_id=device.id,
        remote_thread_id="old-thread",
        status=ThreadBindingStatus.RUNNING,
        cwd="/workspace",
        title="Old title",
        model="gpt-5.5",
        active_turn_id="old-turn",
        appserver_epoch=EPOCH_ONE,
        snapshot={"messages": []},
    )
    old_command = Command(
        owner_user_id="42",
        device_id=device.id,
        thread_binding_id=current_binding.id,
        idempotency_key="old-command",
        idempotency_scope="old-epoch-scope",
        request_hash="0" * 64,
        method="turn/start",
        payload={"threadId": "current-thread", "input": []},
        status=CommandStatus.DISPATCHED,
        appserver_epoch=EPOCH_ONE,
        expires_at=datetime.now(UTC) + timedelta(seconds=30),
    )
    async with harness.database.session_factory() as db:
        db.add_all([current_binding, old_binding])
        await db.flush()
        old_command.thread_binding_id = current_binding.id
        db.add(old_command)
        await db.commit()

    frames = [
        frame(
            device.id,
            1,
            "command_ack",
            {
                "command_id": str(old_command.id),
                "state": "completed",
                "result": {"turn": {"id": "stale-turn"}},
            },
            epoch=EPOCH_ONE,
        ),
        frame(
            device.id,
            2,
            "event",
            {
                "method": "item/agentMessage/delta",
                "params": {
                    "threadId": "old-thread",
                    "itemId": "old-message",
                    "delta": "old backlog",
                },
            },
            epoch=EPOCH_ONE,
        ),
        frame(
            device.id,
            3,
            "event",
            {
                "method": "thread/status/changed",
                "params": {"threadId": "current-thread", "status": "failed"},
            },
            epoch=EPOCH_ONE,
        ),
        frame(
            device.id,
            4,
            "error",
            {"code": "upstream_error", "message": "epoch two", "retryable": False},
            epoch=EPOCH_TWO,
        ),
        frame(
            device.id,
            5,
            "approval_request",
            {
                "approval_id": str(uuid.uuid4()),
                "command_id": "stale-approval",
                "kind": "command",
                "summary": "Must be dropped",
                "details": {},
                "expires_at": datetime.now(UTC) + timedelta(seconds=30),
            },
            epoch=EPOCH_ONE,
        ),
        frame(
            device.id,
            6,
            "heartbeat",
            {"status": "ok"},
            epoch=EPOCH_TWO,
        ),
    ]
    for incoming in frames:
        await harness.app.state.realtime._process_device_frame(connection, incoming)

    async with harness.database.session_factory() as db:
        stored_device = await db.get(Device, device.id)
        stored_current = await db.get(ThreadBinding, current_binding.id)
        stored_old = await db.get(ThreadBinding, old_binding.id)
        stored_command = await db.get(Command, old_command.id)
        approval_count = await db.scalar(select(func.count(Approval.id)))
        protocol_audit = await db.scalar(
            select(AuditEvent).where(AuditEvent.action == "device.protocol_error")
        )
    assert stored_device.last_device_sequence == 6
    assert stored_command.status == CommandStatus.DISPATCHED
    assert stored_current.status == ThreadBindingStatus.RUNNING
    assert stored_current.active_turn_id == "current-turn"
    assert stored_current.snapshot == {"messages": []}
    assert stored_old.status == ThreadBindingStatus.RUNNING
    assert stored_old.active_turn_id == "old-turn"
    assert stored_old.snapshot == {"messages": []}
    assert approval_count == 0
    assert protocol_audit is None


@pytest.mark.parametrize(
    "method",
    [
        "turn/diff/updated",
        "item/reasoning/textDelta",
        "item/commandExecution/outputDelta",
        "item/fileChange/outputDelta",
        "serverRequest/resolved",
    ],
)
async def test_raw_or_sensitive_device_events_are_rejected(
    harness: Harness,
    method: str,
) -> None:
    device, connection = await seed_active_device(harness)
    incoming = frame(
        device.id,
        1,
        "event",
        {"method": method, "params": {"threadId": "unknown"}},
    )
    with pytest.raises(RealtimeProtocolError, match="not allowlisted"):
        await harness.app.state.realtime._process_device_frame(connection, incoming)
    async with harness.database.session_factory() as db:
        stored = await db.get(Device, device.id)
    assert stored.last_device_sequence == 0


async def test_expired_capacity_and_disconnect_approvals_fail_closed(
    harness: Harness,
) -> None:
    device, connection = await seed_active_device(harness)
    expired_id = uuid.uuid4()
    await harness.app.state.realtime._apply_approval_request(
        connection,
        frame(
            device.id,
            1,
            "approval_request",
            {
                "approval_id": str(expired_id),
                "command_id": "expired-on-arrival",
                "kind": "command",
                "summary": "Expired",
                "details": {"command": "pwd"},
                "expires_at": datetime.now(UTC) - timedelta(seconds=1),
            },
        ),
    )
    async with harness.database.session_factory() as db:
        expired = await db.get(Approval, expired_id)
    assert expired.status == ApprovalStatus.DENIED
    assert expired.decision_reason == "expired_on_arrival_default_deny"
    assert expired.expires_at > expired.requested_at

    harness.settings.device_max_pending_approvals = 1
    now = datetime.now(UTC)
    pending = Approval(
        owner_user_id="42",
        device_id=device.id,
        external_command_id="pending-one",
        approval_kind="permission",
        summary="Pending",
        request={},
        status=ApprovalStatus.PENDING,
        appserver_epoch=EPOCH_THREE,
        requested_at=now,
        expires_at=now + timedelta(seconds=60),
    )
    async with harness.database.session_factory() as db:
        db.add(pending)
        await db.commit()
    limited_id = uuid.uuid4()
    await harness.app.state.realtime._apply_approval_request(
        connection,
        frame(
            device.id,
            2,
            "approval_request",
            {
                "approval_id": str(limited_id),
                "command_id": "limited",
                "kind": "permission",
                "summary": "Over limit",
                "details": {},
                "expires_at": now + timedelta(seconds=30),
            },
        ),
    )
    async with harness.database.session_factory() as db:
        limited = await db.get(Approval, limited_id)
    assert limited.status == ApprovalStatus.DENIED
    assert limited.decision_reason == "approval_limit_default_deny"

    await harness.app.state.realtime._end_connection(connection, "websocket_closed")
    async with harness.database.session_factory() as db:
        stored_pending = await db.get(Approval, pending.id)
        stored_device = await db.get(Device, device.id)
    assert stored_pending.status == ApprovalStatus.DENIED
    assert stored_pending.decision_reason == "disconnect_default_deny"
    assert stored_device.active_connection_nonce is None
    assert await harness.store.get(f"connection:{device.id}") is None


async def test_approval_id_replay_must_match_the_original_request(
    harness: Harness,
) -> None:
    device, connection = await seed_active_device(harness)
    approval_id = uuid.uuid4()
    expires_at = datetime.now(UTC) + timedelta(seconds=30)
    payload = {
        "approval_id": str(approval_id),
        "command_id": "external-command-one",
        "kind": "permission",
        "summary": "Allow workspace write",
        "details": {"permissions": ["workspace-write"]},
        "expires_at": expires_at,
    }
    original = frame(device.id, 1, "approval_request", payload)

    await harness.app.state.realtime._apply_approval_request(connection, original)
    await harness.app.state.realtime._apply_approval_request(connection, original)

    changed = dict(payload)
    changed["summary"] = "Allow unrestricted write"
    with pytest.raises(RealtimeProtocolError, match="different request"):
        await harness.app.state.realtime._apply_approval_request(
            connection,
            frame(device.id, 2, "approval_request", changed),
        )

    async with harness.database.session_factory() as db:
        stored = await db.get(Approval, approval_id)
        count = await db.scalar(
            select(func.count()).select_from(Approval).where(Approval.id == approval_id)
        )
    assert count == 1
    assert stored is not None
    assert len(stored.request_hash) == 64
    assert stored.request_hash != "0" * 64
    assert stored.summary == payload["summary"]
    assert stored.request == payload["details"]


async def test_owner_and_projection_approval_limits_default_deny(
    harness: Harness,
) -> None:
    first_device, first_connection = await seed_active_device(harness)
    second_device, second_connection = await seed_active_device(harness)
    harness.settings.bootstrap_max_pending_approvals = 1
    now = datetime.now(UTC)
    first_id = uuid.uuid4()
    await harness.app.state.realtime._apply_approval_request(
        first_connection,
        frame(
            first_device.id,
            1,
            "approval_request",
            {
                "approval_id": str(first_id),
                "command_id": "owner-capacity-a",
                "kind": "permission",
                "summary": "First",
                "details": {},
                "expires_at": now + timedelta(seconds=30),
            },
        ),
    )
    second_id = uuid.uuid4()
    await harness.app.state.realtime._apply_approval_request(
        second_connection,
        frame(
            second_device.id,
            1,
            "approval_request",
            {
                "approval_id": str(second_id),
                "command_id": "owner-capacity-b",
                "kind": "permission",
                "summary": "Second",
                "details": {},
                "expires_at": now + timedelta(seconds=30),
            },
        ),
    )
    async with harness.database.session_factory() as db:
        first = await db.get(Approval, first_id)
        second = await db.get(Approval, second_id)
    assert first is not None and first.status == ApprovalStatus.PENDING
    assert second is not None and second.status == ApprovalStatus.DENIED
    assert second.decision_reason == "owner_approval_limit_default_deny"

    harness.settings.bootstrap_max_pending_approvals = 32
    oversized_id = uuid.uuid4()
    await harness.app.state.realtime._apply_approval_request(
        second_connection,
        frame(
            second_device.id,
            2,
            "approval_request",
            {
                "approval_id": str(oversized_id),
                "command_id": "oversized-approval",
                "kind": "permission",
                "summary": "Oversized",
                "details": {"blob": "x" * 70_000},
                "expires_at": now + timedelta(seconds=30),
            },
        ),
    )
    async with harness.database.session_factory() as db:
        oversized = await db.get(Approval, oversized_id)
    assert oversized is not None and oversized.status == ApprovalStatus.DENIED
    assert oversized.decision_reason == "approval_size_default_deny"


async def test_stale_epoch_reconciliation_claims_each_undispatched_decision_once(
    harness: Harness,
) -> None:
    device, _ = await seed_active_device(harness, epoch=EPOCH_TWO)
    now = datetime.now(UTC)

    def approval(
        suffix: str,
        status: ApprovalStatus,
        epoch: str,
        *,
        dispatched: bool = False,
    ) -> Approval:
        return Approval(
            owner_user_id="42",
            device_id=device.id,
            external_command_id=f"stale-claim-{suffix}",
            approval_kind="permission",
            summary=f"Stale claim {suffix}",
            request={},
            status=status,
            appserver_epoch=epoch,
            requested_at=now,
            expires_at=now + timedelta(seconds=60),
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

    pending = approval("pending", ApprovalStatus.PENDING, EPOCH_ONE)
    approved = approval("approved", ApprovalStatus.APPROVED, EPOCH_ONE)
    denied = approval("denied", ApprovalStatus.DENIED, EPOCH_ONE)
    dispatched_approved = approval(
        "dispatched-approved", ApprovalStatus.APPROVED, EPOCH_ONE, dispatched=True
    )
    dispatched_denied = approval(
        "dispatched-denied", ApprovalStatus.DENIED, EPOCH_ONE, dispatched=True
    )
    current = approval("current", ApprovalStatus.PENDING, EPOCH_TWO)
    async with harness.database.session_factory() as db:
        db.add_all([pending, approved, denied, dispatched_approved, dispatched_denied, current])
        await db.commit()

    async def reconcile() -> int:
        async with harness.database.session_factory() as db:
            stored_device = await db.scalar(
                select(Device).where(Device.id == device.id).with_for_update()
            )
            assert stored_device is not None
            events = await harness.app.state.approvals.deny_stale_epoch(
                db, stored_device, EPOCH_TWO
            )
            await db.commit()
            return len(events)

    assert sorted(await asyncio.gather(reconcile(), reconcile())) == [0, 3]
    assert await reconcile() == 0

    async with harness.database.session_factory() as db:
        rows = {
            row.id: row
            for row in (
                await db.scalars(select(Approval).where(Approval.device_id == device.id))
            ).all()
        }
        audit_ids = set(
            (
                await db.scalars(
                    select(AuditEvent.resource_id).where(
                        AuditEvent.action == "approval.default_deny"
                    )
                )
            ).all()
        )
        resolution_count = await db.scalar(
            select(func.count(EventLog.id)).where(EventLog.event_type == "approval.resolved")
        )

    for claimed in (pending, approved, denied):
        assert rows[claimed.id].status == ApprovalStatus.DENIED
        assert rows[claimed.id].decision_reason == "stale_epoch_default_deny"
        assert rows[claimed.id].decision_dispatched_at is None
        assert str(claimed.id) in audit_ids
    assert rows[dispatched_approved.id].status == ApprovalStatus.APPROVED
    assert rows[dispatched_approved.id].decision_reason == "user_approved"
    assert rows[dispatched_approved.id].decision_dispatched_at.replace(tzinfo=UTC) == now
    assert rows[dispatched_denied.id].status == ApprovalStatus.DENIED
    assert rows[dispatched_denied.id].decision_reason == "user_denied"
    assert rows[dispatched_denied.id].decision_dispatched_at.replace(tzinfo=UTC) == now
    assert rows[current.id].status == ApprovalStatus.PENDING
    assert resolution_count == 3


async def test_disconnect_reconciles_undispatched_decisions_and_suppresses_replay(
    harness: Harness,
) -> None:
    device, connection = await seed_active_device(harness)
    now = datetime.now(UTC)

    def approval(suffix: str, status: ApprovalStatus, *, dispatched: bool = False) -> Approval:
        return Approval(
            owner_user_id="42",
            device_id=device.id,
            external_command_id=f"disconnect-{suffix}",
            approval_kind="permission",
            summary=f"Disconnect {suffix}",
            request={},
            status=status,
            appserver_epoch=EPOCH_THREE,
            requested_at=now,
            expires_at=now + timedelta(seconds=60),
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

    pending = approval("pending", ApprovalStatus.PENDING)
    approved = approval("approved", ApprovalStatus.APPROVED)
    denied = approval("denied", ApprovalStatus.DENIED)
    dispatched = approval("dispatched", ApprovalStatus.APPROVED, dispatched=True)
    async with harness.database.session_factory() as db:
        db.add_all([pending, approved, denied, dispatched])
        await db.commit()

    await harness.app.state.realtime._end_connection(connection, "websocket_closed")
    await harness.app.state.realtime._end_connection(connection, "duplicate_cleanup")

    async with harness.database.session_factory() as db:
        rows = {
            row.id: row
            for row in (
                await db.scalars(select(Approval).where(Approval.device_id == device.id))
            ).all()
        }
        approval_audits = await db.scalar(
            select(func.count(AuditEvent.id)).where(
                AuditEvent.action == "approval.default_deny",
                AuditEvent.resource_id.in_([str(pending.id), str(approved.id), str(denied.id)]),
            )
        )
    for claimed in (pending, approved, denied):
        assert rows[claimed.id].status == ApprovalStatus.DENIED
        assert rows[claimed.id].decision_reason == "disconnect_default_deny"
        assert rows[claimed.id].decision_dispatched_at is None
    assert rows[dispatched.id].status == ApprovalStatus.APPROVED
    assert rows[dispatched.id].decision_reason == "user_approved"
    assert rows[dispatched.id].decision_dispatched_at.replace(tzinfo=UTC) == now
    assert approval_audits == 3

    replacement_nonce = str(uuid.uuid4())
    replacement_registry = json.dumps(
        {
            "connection_nonce": replacement_nonce,
            "epoch": EPOCH_THREE,
            "instance_id": "replacement",
        },
        separators=(",", ":"),
    )
    async with harness.database.session_factory() as db:
        stored_device = await db.get(Device, device.id)
        stored_device.active_connection_nonce = replacement_nonce
        await db.commit()
    replacement = ActiveDeviceSocket(
        websocket=RecordingWebSocket(),  # type: ignore[arg-type]
        device_id=device.id,
        owner_user_id="42",
        connection_nonce=replacement_nonce,
        epoch=EPOCH_THREE,
        registry_value=replacement_registry,
    )
    await harness.app.state.realtime._dispatch_pending(replacement)
    async with harness.database.session_factory() as db:
        assert await db.scalar(select(func.count(DeviceOutbox.sequence))) == 0
    assert replacement.websocket.sent == []


async def test_disconnect_waits_for_durable_approval_dispatch_and_does_not_clobber_it(
    harness: Harness,
) -> None:
    device, connection = await seed_active_device(harness)
    socket = BlockingSendWebSocket()
    connection.websocket = socket  # type: ignore[assignment]
    now = datetime.now(UTC)
    approval = Approval(
        owner_user_id="42",
        device_id=device.id,
        external_command_id="dispatch-versus-disconnect",
        approval_kind="permission",
        summary="Dispatch versus disconnect",
        request={},
        status=ApprovalStatus.APPROVED,
        appserver_epoch=EPOCH_THREE,
        requested_at=now,
        expires_at=now + timedelta(seconds=60),
        decided_at=now,
        decision_reason="user_approved",
    )
    async with harness.database.session_factory() as db:
        db.add(approval)
        await db.commit()

    dispatch = asyncio.create_task(
        harness.app.state.realtime._dispatch_approval(connection, approval.id)
    )
    await socket.started.wait()
    disconnect = asyncio.create_task(
        harness.app.state.realtime._end_connection(connection, "websocket_closed")
    )
    await asyncio.sleep(0)
    assert not disconnect.done()
    socket.release.set()
    await asyncio.gather(dispatch, disconnect)

    async with harness.database.session_factory() as db:
        stored = await db.get(Approval, approval.id)
        outbox = await db.scalar(
            select(DeviceOutbox).where(
                DeviceOutbox.device_id == device.id,
                DeviceOutbox.frame_type == "approval_decision",
            )
        )
        default_denies = await db.scalar(
            select(func.count(AuditEvent.id)).where(
                AuditEvent.action == "approval.default_deny",
                AuditEvent.resource_id == str(approval.id),
            )
        )
    assert stored.status == ApprovalStatus.APPROVED
    assert stored.decision_reason == "user_approved"
    assert stored.decision_dispatched_at is not None
    assert outbox is not None
    assert default_denies == 0


async def test_approval_decision_rejects_precommit_or_new_epoch_registry(
    harness: Harness,
) -> None:
    device, connection = await seed_active_device(harness)
    now = datetime.now(UTC)
    approval = Approval(
        owner_user_id="42",
        device_id=device.id,
        external_command_id="registry-race",
        approval_kind="permission",
        summary="Registry race",
        request={},
        status=ApprovalStatus.PENDING,
        appserver_epoch=EPOCH_THREE,
        requested_at=now,
        expires_at=now + timedelta(seconds=60),
    )
    async with harness.database.session_factory() as db:
        db.add(approval)
        await db.commit()
    await harness.store.set(
        f"connection:{device.id}",
        json.dumps(
            {
                "connection_nonce": str(uuid.uuid4()),
                "epoch": EPOCH_TWO,
                "instance_id": "precommit-race",
            },
            separators=(",", ":"),
        ),
        harness.settings.device_registry_ttl_seconds,
    )
    metadata = RequestMetadata(source_ip=None, user_agent=None, request_id="approval-race")
    async with harness.database.session_factory() as db:
        with pytest.raises(ApprovalDeviceOffline):
            await harness.app.state.approvals.decide(
                db,
                owner_user_id="42",
                approval_id=approval.id,
                decision="approve",
                session_id=uuid.uuid4(),
                metadata=metadata,
            )
    async with harness.database.session_factory() as db:
        stored = await db.get(Approval, approval.id)
    assert stored.status == ApprovalStatus.DENIED
    assert stored.decision_reason == "device_offline_default_deny"
    await harness.store.set(
        f"connection:{device.id}",
        connection.registry_value,
        harness.settings.device_registry_ttl_seconds,
    )


async def test_connection_registry_compare_refresh_and_delete_are_owner_safe(
    harness: Harness,
) -> None:
    await harness.store.set("connection:test", "owner-one", 30)
    assert await harness.store.compare_refresh("connection:test", "owner-two", 60) is False
    assert await harness.store.get("connection:test") == "owner-one"
    assert await harness.store.compare_delete("connection:test", "owner-two") is False
    assert await harness.store.compare_refresh("connection:test", "owner-one", 60) is True
    assert await harness.store.compare_delete("connection:test", "owner-one") is True
    assert await harness.store.get("connection:test") is None


async def test_activation_ownership_failure_cleans_committed_connection(
    harness: Harness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    device, hello = await seed_connectable_device(harness)
    now = datetime.now(UTC)
    pending = Approval(
        owner_user_id="42",
        device_id=device.id,
        external_command_id="activation-pending",
        approval_kind="permission",
        summary="Pending during activation",
        request={},
        status=ApprovalStatus.PENDING,
        appserver_epoch=EPOCH_ONE,
        requested_at=now,
        expires_at=now + timedelta(seconds=60),
    )
    async with harness.database.session_factory() as db:
        db.add(pending)
        await db.commit()

    async def lose_ownership(*_args: object, **_kwargs: object) -> bool:
        return False

    monkeypatch.setattr(harness.store, "compare_refresh", lose_ownership)
    with pytest.raises(RealtimeProtocolError, match="ownership was lost"):
        await harness.app.state.realtime._begin_connection(
            RecordingWebSocket(),  # type: ignore[arg-type]
            device.id,
            hello_frame(device, hello, EPOCH_ONE),
            hello,
        )

    async with harness.database.session_factory() as db:
        stored_device = await db.get(Device, device.id)
        stored_approval = await db.get(Approval, pending.id)
        connection = await db.scalar(
            select(DeviceConnection).where(DeviceConnection.device_id == device.id)
        )
    assert stored_device.active_connection_nonce is None
    assert stored_approval.status == ApprovalStatus.DENIED
    assert stored_approval.decision_reason == "disconnect_default_deny"
    assert connection.status == ConnectionStatus.DISCONNECTED
    assert connection.closed_reason == "activation_failed"
    assert await harness.store.get(f"connection:{device.id}") is None


async def test_activation_publish_failure_runs_ownership_safe_cleanup(
    harness: Harness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    device, hello = await seed_connectable_device(harness)
    original_publish = harness.store.publish

    async def fail_kick(channel: str, value: str) -> int:
        if channel == f"device-dispatch:{device.id}":
            raise RuntimeError("simulated kick publish failure")
        return await original_publish(channel, value)

    monkeypatch.setattr(harness.store, "publish", fail_kick)
    with pytest.raises(RuntimeError, match="kick publish failure"):
        await harness.app.state.realtime._begin_connection(
            RecordingWebSocket(),  # type: ignore[arg-type]
            device.id,
            hello_frame(device, hello, EPOCH_ONE),
            hello,
        )

    async with harness.database.session_factory() as db:
        stored_device = await db.get(Device, device.id)
        connection = await db.scalar(
            select(DeviceConnection).where(DeviceConnection.device_id == device.id)
        )
    assert stored_device.active_connection_nonce is None
    assert connection.status == ConnectionStatus.DISCONNECTED
    assert connection.closed_reason == "activation_failed"
    assert await harness.store.get(f"connection:{device.id}") is None


async def test_failed_old_activation_cleanup_does_not_clobber_newer_owner(
    harness: Harness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    device, hello = await seed_connectable_device(harness)
    now = datetime.now(UTC)
    pending = Approval(
        owner_user_id="42",
        device_id=device.id,
        external_command_id="newer-wins-pending",
        approval_kind="permission",
        summary="Must remain for newer owner",
        request={},
        status=ApprovalStatus.PENDING,
        appserver_epoch=EPOCH_TWO,
        requested_at=now,
        expires_at=now + timedelta(seconds=60),
    )
    async with harness.database.session_factory() as db:
        db.add(pending)
        await db.commit()

    newer_nonce = str(uuid.uuid4())
    newer_registry = json.dumps(
        {
            "connection_nonce": newer_nonce,
            "epoch": EPOCH_TWO,
            "instance_id": "newer-instance",
        },
        separators=(",", ":"),
    )

    async def newer_wins_then_fail(
        db: AsyncSession,
        stored_device: Device,
        _current_epoch: str,
    ) -> int:
        stored_device.active_connection_nonce = newer_nonce
        stored_device.active_epoch = EPOCH_TWO
        db.add(
            DeviceConnection(
                device_id=stored_device.id,
                connection_nonce=newer_nonce,
                status=ConnectionStatus.CONNECTED,
                appserver_epoch=EPOCH_TWO,
                connected_at=datetime.now(UTC),
                last_heartbeat_at=datetime.now(UTC),
            )
        )
        await db.commit()
        await harness.store.set(
            f"connection:{stored_device.id}",
            newer_registry,
            harness.settings.device_registry_ttl_seconds,
        )
        raise RuntimeError("post-register activation failure")

    monkeypatch.setattr(
        harness.app.state.approvals,
        "deny_stale_epoch",
        newer_wins_then_fail,
    )
    with pytest.raises(RuntimeError, match="post-register activation failure"):
        await harness.app.state.realtime._begin_connection(
            RecordingWebSocket(),  # type: ignore[arg-type]
            device.id,
            hello_frame(device, hello, EPOCH_ONE),
            hello,
        )

    async with harness.database.session_factory() as db:
        stored_device = await db.get(Device, device.id)
        stored_approval = await db.get(Approval, pending.id)
        connections = list(
            (
                await db.scalars(
                    select(DeviceConnection)
                    .where(DeviceConnection.device_id == device.id)
                    .order_by(DeviceConnection.connected_at)
                )
            ).all()
        )
    assert stored_device.active_connection_nonce == newer_nonce
    assert stored_device.active_epoch == EPOCH_TWO
    assert stored_approval.status == ApprovalStatus.PENDING
    assert {connection.connection_nonce: connection.status for connection in connections}[
        newer_nonce
    ] == ConnectionStatus.CONNECTED
    assert all(
        connection.status == ConnectionStatus.DISCONNECTED
        for connection in connections
        if connection.connection_nonce != newer_nonce
    )
    assert await harness.store.get(f"connection:{device.id}") == newer_registry


async def test_replaced_connection_cannot_reclaim_or_delete_registry(harness: Harness) -> None:
    public_key = "p" * 48
    device = Device(
        owner_user_id="42",
        name="Replacement test",
        public_key=public_key,
        status=DeviceStatus.ACTIVE,
        workspace_roots=["/workspace"],
    )
    async with harness.database.session_factory() as db:
        db.add(device)
        await db.commit()
    hello = HelloPayload(
        connector_version=harness.settings.connector_expected_version,
        codex_version=harness.settings.codex_expected_version,
        schema_digest=harness.settings.appserver_schema_digest,
        public_key=public_key,
        capabilities=sorted(ALLOWED_RPC_METHODS),
        workspace_roots=["/workspace"],
        resumed_from_seq=0,
    )

    def hello_envelope(epoch: str) -> ControlEnvelope:
        return ControlEnvelope.model_validate(
            {
                "version": 1,
                "id": str(uuid.uuid4()),
                "device_id": str(device.id),
                "epoch": epoch,
                "seq": 0,
                "ack": 0,
                "type": "hello",
                "sent_at": datetime.now(UTC),
                "payload": hello.model_dump(mode="json"),
            }
        )

    first_socket = RecordingWebSocket()
    first = await harness.app.state.realtime._begin_connection(
        first_socket,  # type: ignore[arg-type]
        device.id,
        hello_envelope(EPOCH_ONE),
        hello,
    )
    second_socket = RecordingWebSocket()
    second = await harness.app.state.realtime._begin_connection(
        second_socket,  # type: ignore[arg-type]
        device.id,
        hello_envelope(EPOCH_TWO),
        hello,
    )
    assert first_socket.closed == [(4001, "replaced by a newer connection")]
    assert await harness.store.get(f"connection:{device.id}") == second.registry_value
    async with harness.database.session_factory() as db:
        stored = await db.get(Device, device.id)
    assert stored.active_connection_nonce == second.connection_nonce

    await harness.app.state.realtime._end_connection(first, "late_old_cleanup")
    assert await harness.store.get(f"connection:{device.id}") == second.registry_value
    async with harness.database.session_factory() as db:
        stored = await db.get(Device, device.id)
    assert stored.active_connection_nonce == second.connection_nonce

    await harness.app.state.realtime._end_connection(second, "current_cleanup")
    assert await harness.store.get(f"connection:{device.id}") is None


async def test_device_connection_history_is_pruned_at_hard_cap(harness: Harness) -> None:
    harness.settings.device_max_connection_records = 1
    device, hello = await seed_connectable_device(harness)

    first = await harness.app.state.realtime._begin_connection(
        RecordingWebSocket(),  # type: ignore[arg-type]
        device.id,
        hello_frame(device, hello, EPOCH_ONE),
        hello,
    )
    second = await harness.app.state.realtime._begin_connection(
        RecordingWebSocket(),  # type: ignore[arg-type]
        device.id,
        hello_frame(device, hello, EPOCH_TWO),
        hello,
    )

    async with harness.database.session_factory() as db:
        rows = list(
            (
                await db.scalars(
                    select(DeviceConnection).where(DeviceConnection.device_id == device.id)
                )
            ).all()
        )
    assert len(rows) == 1
    assert rows[0].connection_nonce == second.connection_nonce
    assert rows[0].status == ConnectionStatus.CONNECTED

    await harness.app.state.realtime._end_connection(first, "already_pruned")
    await harness.app.state.realtime._end_connection(second, "test_cleanup")


async def test_scoped_idempotency_isolated_capacity_bounded_and_race_safe(
    harness: Harness,
) -> None:
    device, _ = await seed_active_device(harness)
    thread_one = ThreadBinding(
        owner_user_id="42",
        device_id=device.id,
        remote_thread_id="thread-one",
        status=ThreadBindingStatus.IDLE,
        cwd="/workspace",
        title="One",
        model="gpt-5.5",
        appserver_epoch=EPOCH_THREE,
    )
    thread_two = ThreadBinding(
        owner_user_id="42",
        device_id=device.id,
        remote_thread_id="thread-two",
        status=ThreadBindingStatus.IDLE,
        cwd="/workspace",
        title="Two",
        model="gpt-5.5",
        appserver_epoch=EPOCH_THREE,
    )
    async with harness.database.session_factory() as db:
        db.add_all([thread_one, thread_two])
        await db.commit()
    metadata = RequestMetadata(source_ip=None, user_agent=None, request_id="hardening-test")

    async def create_for(
        binding: ThreadBinding,
        *,
        key: str,
        text: str,
        scope: str | None = None,
    ) -> Command:
        async with harness.database.session_factory() as db:
            stored_device = await db.get(Device, device.id)
            return await harness.app.state.commands.create(
                db,
                owner_user_id="42",
                device=stored_device,
                method="turn/start",
                params={
                    "threadId": binding.remote_thread_id,
                    "input": [{"type": "text", "text": text}],
                },
                idempotency_key=key,
                metadata=metadata,
                thread_binding_id=binding.id,
                idempotency_scope=scope,
            )

    first = await create_for(thread_one, key="shared", text="hello")
    reused = await create_for(thread_one, key="shared", text="hello")
    isolated = await create_for(thread_two, key="shared", text="hello")
    assert reused.id == first.id
    assert isolated.id != first.id
    with pytest.raises(CommandIdempotencyConflict):
        await create_for(thread_one, key="shared", text="different")

    harness.settings.device_max_outstanding_commands = 2
    assert (await create_for(thread_one, key="shared", text="hello")).id == first.id
    with pytest.raises(CommandCapacityExceeded):
        await create_for(thread_one, key="over-capacity", text="new")

    async with harness.database.session_factory() as db:
        seeded_commands = list((await db.scalars(select(Command))).all())
        for seeded_command in seeded_commands:
            seeded_command.status = CommandStatus.SUCCEEDED
        await db.commit()

    harness.settings.device_max_outstanding_commands = 10
    race_scope = f"device:{device.id}|method:turn/start|resource:race"
    raced = await asyncio.gather(
        create_for(thread_one, key="race", text="same", scope=race_scope),
        create_for(thread_one, key="race", text="same", scope=race_scope),
    )
    assert raced[0].id == raced[1].id
    async with harness.database.session_factory() as db:
        race_count = await db.scalar(
            select(func.count(Command.id)).where(
                Command.device_id == device.id,
                Command.idempotency_scope == race_scope,
                Command.idempotency_key == "race",
            )
        )
    assert race_count == 1
    async with harness.database.session_factory() as db:
        existing_commands = list((await db.scalars(select(Command))).all())
        for existing_command in existing_commands:
            existing_command.status = CommandStatus.SUCCEEDED
        await db.commit()
    harness.settings.device_max_outstanding_commands = 1
    capacity_results = await asyncio.gather(
        create_for(
            thread_one,
            key="capacity-a",
            text="a",
            scope=f"device:{device.id}|method:turn/start|resource:capacity-a",
        ),
        create_for(
            thread_two,
            key="capacity-b",
            text="b",
            scope=f"device:{device.id}|method:turn/start|resource:capacity-b",
        ),
        return_exceptions=True,
    )
    assert sum(isinstance(result, Command) for result in capacity_results) == 1
    assert sum(isinstance(result, CommandCapacityExceeded) for result in capacity_results) == 1


async def test_dispatched_idempotency_identity_includes_api_scope(harness: Harness) -> None:
    device, connection = await seed_active_device(harness)
    commands = [
        Command(
            owner_user_id="42",
            device_id=device.id,
            idempotency_key="shared-user-key",
            idempotency_scope=f"device:{device.id}|method:model/list|resource:{resource}",
            request_hash=character * 64,
            method="model/list",
            payload={},
            status=CommandStatus.QUEUED,
            appserver_epoch=EPOCH_THREE,
            expires_at=datetime.now(UTC) + timedelta(seconds=30),
        )
        for resource, character in (("one", "1"), ("two", "2"))
    ]
    async with harness.database.session_factory() as db:
        db.add_all(commands)
        await db.commit()

    for command in commands:
        await harness.app.state.realtime._dispatch_command(connection, command.id)

    envelopes = [json.loads(encoded) for encoded in connection.websocket.sent]
    wire_keys = [envelope["payload"]["idempotency_key"] for envelope in envelopes]
    assert wire_keys == [
        wire_idempotency_key(command.idempotency_scope, command.idempotency_key)
        for command in commands
    ]
    assert len(set(wire_keys)) == 2
    assert all(len(key) == 64 and key != "shared-user-key" for key in wire_keys)


async def test_terminal_command_history_cannot_exceed_device_record_cap(
    harness: Harness,
) -> None:
    device, _ = await seed_active_device(harness)
    harness.settings.device_max_command_records = 1
    metadata = RequestMetadata(source_ip=None, user_agent=None, request_id="command-cap")
    async with harness.database.session_factory() as db:
        stored_device = await db.get(Device, device.id)
        first = await harness.app.state.commands.create(
            db,
            owner_user_id="42",
            device=stored_device,
            method="model/list",
            params={},
            idempotency_key="first-record",
            metadata=metadata,
        )
    async with harness.database.session_factory() as db:
        stored = await db.get(Command, first.id)
        stored.status = CommandStatus.SUCCEEDED
        stored.completed_at = datetime.now(UTC)
        await db.commit()
    async with harness.database.session_factory() as db:
        stored_device = await db.get(Device, device.id)
        with pytest.raises(CommandCapacityExceeded, match="record limit"):
            await harness.app.state.commands.create(
                db,
                owner_user_id="42",
                device=stored_device,
                method="model/list",
                params={},
                idempotency_key="second-record",
                metadata=metadata,
            )


async def test_committed_command_is_returned_when_post_commit_wakes_fail(
    harness: Harness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    device, _ = await seed_active_device(harness)
    metadata = RequestMetadata(source_ip=None, user_agent=None, request_id="post-commit-wake")

    async def failed_publish(_channel: str, _message: str) -> int:
        raise RuntimeError("injected publish failure")

    monkeypatch.setattr(harness.store, "publish", failed_publish)

    async def create() -> Command:
        async with harness.database.session_factory() as db:
            stored_device = await db.get(Device, device.id)
            return await harness.app.state.commands.create(
                db,
                owner_user_id="42",
                device=stored_device,
                method="model/list",
                params={"limit": 100},
                idempotency_key="post-commit-wake",
                metadata=metadata,
            )

    created = await create()
    replayed = await create()
    assert replayed.id == created.id
    async with harness.database.session_factory() as db:
        commands = list((await db.scalars(select(Command))).all())
        events = int(await db.scalar(select(func.count(EventLog.id))) or 0)
    assert len(commands) == 1
    assert commands[0].status == CommandStatus.QUEUED
    assert events == 1


async def test_owner_command_cap_is_atomic_across_devices(harness: Harness) -> None:
    first_device, _ = await seed_active_device(harness)
    second_device, _ = await seed_active_device(harness)
    harness.settings.owner_max_command_records = 1
    metadata = RequestMetadata(source_ip=None, user_agent=None, request_id="owner-command-cap")

    async def create(device_id: uuid.UUID, key: str) -> Command:
        async with harness.database.session_factory() as db:
            device = await db.get(Device, device_id)
            return await harness.app.state.commands.create(
                db,
                owner_user_id="42",
                device=device,
                method="model/list",
                params={"limit": 100},
                idempotency_key=key,
                metadata=metadata,
            )

    results = await asyncio.gather(
        create(first_device.id, "owner-cap-first"),
        create(second_device.id, "owner-cap-second"),
        return_exceptions=True,
    )
    assert sum(isinstance(result, Command) for result in results) == 1
    assert sum(isinstance(result, CommandCapacityExceeded) for result in results) == 1
    async with harness.database.session_factory() as db:
        assert int(await db.scalar(select(func.count(Command.id))) or 0) == 1


async def test_every_command_route_requires_an_idempotency_header(harness: Harness) -> None:
    schema = harness.app.openapi()
    paths = (
        "/v1/devices/{device_id}/models/sync",
        "/v1/devices/{device_id}/threads/sync",
        "/v1/devices/{device_id}/threads",
        "/v1/threads/{thread_id}/sync",
        "/v1/threads/{thread_id}/resume",
        "/v1/threads/{thread_id}/turns",
        "/v1/threads/{thread_id}/turns/current/steer",
        "/v1/threads/{thread_id}/turns/current/interrupt",
    )
    for path in paths:
        parameters = schema["paths"][path]["post"]["parameters"]
        header = next(
            item
            for item in parameters
            if item.get("in") == "header" and item.get("name") == "Idempotency-Key"
        )
        assert header["required"] is True

    assert (await exchange(harness)).status_code == 201
    device, _ = await seed_active_device(harness)
    response = await harness.client.post(
        f"/v1/devices/{device.id}/models/sync",
        headers=csrf_headers(harness),
    )
    assert response.status_code == 422
    async with harness.database.session_factory() as db:
        assert int(await db.scalar(select(func.count(Command.id))) or 0) == 0


async def test_protocol_payload_rate_and_event_retention_limits(harness: Harness) -> None:
    device, _ = await seed_active_device(harness)
    realtime = harness.app.state.realtime
    raw = frame(
        device.id,
        1,
        "event",
        {"method": "turn/plan/updated", "params": {"threadId": "x"}},
    ).model_dump_json()

    harness.settings.device_max_envelope_bytes = 64
    with pytest.raises(RealtimeProtocolError, match="envelope exceeds"):
        realtime._parse_device_envelope(raw)
    harness.settings.device_max_envelope_bytes = 262144

    harness.settings.device_max_event_bytes = 32
    with pytest.raises(RealtimeProtocolError, match="event exceeds"):
        realtime._parse_device_envelope(raw)
    harness.settings.device_max_event_bytes = 262144

    result_raw = frame(
        device.id,
        1,
        "command_ack",
        {
            "command_id": str(uuid.uuid4()),
            "state": "completed",
            "result": {"text": "x" * 200},
        },
    ).model_dump_json()
    harness.settings.device_max_result_bytes = 64
    with pytest.raises(RealtimeProtocolError, match="result exceeds"):
        realtime._parse_device_envelope(result_raw)
    harness.settings.device_max_result_bytes = 524288

    approval_raw = frame(
        device.id,
        1,
        "approval_request",
        {
            "approval_id": str(uuid.uuid4()),
            "command_id": "large",
            "kind": "command",
            "summary": "Large",
            "details": {"text": "x" * 200},
            "expires_at": datetime.now(UTC) + timedelta(seconds=30),
        },
    ).model_dump_json()
    harness.settings.device_max_approval_bytes = 64
    with pytest.raises(RealtimeProtocolError, match="approval request exceeds"):
        realtime._parse_device_envelope(approval_raw)
    harness.settings.device_max_approval_bytes = 65536

    harness.settings.device_max_json_depth = 4
    deep_raw = frame(
        device.id,
        1,
        "event",
        {
            "method": "turn/plan/updated",
            "params": {"a": {"b": {"c": {"d": "too deep"}}}},
        },
    ).model_dump_json()
    with pytest.raises(RealtimeProtocolError, match="nesting limit"):
        realtime._parse_device_envelope(deep_raw)
    harness.settings.device_max_json_depth = 16

    harness.settings.device_max_json_nodes = 10
    with pytest.raises(RealtimeProtocolError, match="node limit"):
        realtime._parse_device_envelope(raw)
    harness.settings.device_max_json_nodes = 10000

    harness.settings.device_max_string_chars = 128
    long_string_raw = frame(
        device.id,
        1,
        "event",
        {
            "method": "turn/plan/updated",
            "params": {"text": "x" * 129},
        },
    ).model_dump_json()
    with pytest.raises(RealtimeProtocolError, match="string exceeds"):
        realtime._parse_device_envelope(long_string_raw)
    harness.settings.device_max_string_chars = 200000

    harness.settings.device_frame_rate_limit = 1
    await realtime._enforce_device_frame_rate(device.id)
    with pytest.raises(RealtimeProtocolError, match="rate limit"):
        await realtime._enforce_device_frame_rate(device.id)

    harness.settings.browser_event_max_per_owner = 2
    for index in range(3):
        async with harness.database.session_factory() as db:
            await harness.app.state.events.emit(
                db,
                owner_user_id="42",
                device_id=device.id,
                event_type="device.updated",
                data={"index": index},
            )
    async with harness.database.session_factory() as db:
        assert await harness.app.state.events.prune(db) == 1
    async with harness.database.session_factory() as db:
        remaining = list(
            (
                await db.scalars(
                    select(EventLog).where(EventLog.owner_user_id == "42").order_by(EventLog.id)
                )
            ).all()
        )
    assert [event.payload["index"] for event in remaining] == [1, 2]

    harness.settings.browser_event_max_per_owner = 100000
    harness.settings.browser_event_retention_days = 1
    async with harness.database.session_factory() as db:
        remaining[0].ingested_at = datetime.now(UTC) - timedelta(days=2)
        await db.merge(remaining[0])
        await db.commit()
    async with harness.database.session_factory() as db:
        assert await harness.app.state.events.prune(db) == 1
    async with harness.database.session_factory() as db:
        final_events = list((await db.scalars(select(EventLog))).all())
    assert [event.payload["index"] for event in final_events] == [2]


async def test_sweep_lease_renews_and_reentry_cannot_run_concurrently(
    harness: Harness,
) -> None:
    store = InMemoryKeyValueStore("renewal-test:")
    started = asyncio.Event()
    refresh_count = 0
    retention_count = 0
    original_refresh = store.compare_refresh

    async def counted_refresh(key: str, value: str, ttl_seconds: int) -> bool:
        nonlocal refresh_count
        refresh_count += 1
        return await original_refresh(key, value, ttl_seconds)

    store.compare_refresh = counted_refresh  # type: ignore[method-assign]

    class SlowCommands:
        async def expire_due(self, _db: AsyncSession) -> int:
            started.set()
            await asyncio.sleep(1.2)
            return 0

    class NoopExpiry:
        async def expire_due(self, _db: AsyncSession) -> int:
            return 0

        async def reconcile_undispatched(self, _db: AsyncSession, *, limit: int) -> int:
            del limit
            return 0

    class NoopEvents:
        async def prune(self, _db: AsyncSession) -> int:
            return 0

    class NoopRealtime:
        async def prune_outbox(self, _db: AsyncSession) -> int:
            return 0

    class NoopRetention:
        async def sweep(self, _db: AsyncSession) -> SimpleNamespace:
            nonlocal retention_count
            retention_count += 1
            return SimpleNamespace(total=0)

    fake_app = SimpleNamespace(
        state=SimpleNamespace(
            store=store,
            database=harness.database,
            pairing_service=NoopExpiry(),
            commands=SlowCommands(),
            approvals=NoopExpiry(),
            events=NoopEvents(),
            realtime=NoopRealtime(),
            retention=NoopRetention(),
            settings=SimpleNamespace(retention_sweep_batch_size=500),
        )
    )
    # The retention sweep is gated on time.monotonic(), which is uptime on
    # Linux, so an absolute 0.0 only looks "over a minute ago" on a host that
    # has been up for a minute. Anchor the deadline to the current clock.
    retention_due = time.monotonic() - 61.0
    first = asyncio.create_task(
        _run_sweep_cycle(fake_app, retention_due, lease_ttl_seconds=1)  # type: ignore[arg-type]
    )
    await started.wait()
    acquired, _ = await _run_sweep_cycle(  # type: ignore[arg-type]
        fake_app,
        retention_due,
        lease_ttl_seconds=1,
    )
    assert acquired is False
    assert (await first)[0] is True
    assert refresh_count >= 2
    assert retention_count == 1
    assert await store.get("state-sweep-lease") is None
    await store.close()


async def test_expiry_claims_are_single_winner_and_reentry_safe(harness: Harness) -> None:
    device, _ = await seed_active_device(harness)
    base = datetime.now(UTC)
    command = Command(
        owner_user_id="42",
        device_id=device.id,
        idempotency_key="expire-race",
        idempotency_scope="expire-race",
        request_hash="e" * 64,
        method="model/list",
        payload={"limit": 100},
        status=CommandStatus.ACKNOWLEDGED,
        appserver_epoch=EPOCH_THREE,
        expires_at=base + timedelta(seconds=60),
    )
    approval = Approval(
        owner_user_id="42",
        device_id=device.id,
        external_command_id="expire-approval-race",
        approval_kind="permission",
        summary="Expiry race",
        request={},
        status=ApprovalStatus.PENDING,
        appserver_epoch=EPOCH_THREE,
        requested_at=base,
        expires_at=base + timedelta(seconds=60),
    )
    async with harness.database.session_factory() as db:
        db.add_all([command, approval])
        await db.commit()
    sweep_time = base + timedelta(seconds=120)

    async def expire_commands() -> int:
        async with harness.database.session_factory() as db:
            return await harness.app.state.commands.expire_due(db, now=sweep_time)

    async def expire_approvals() -> int:
        async with harness.database.session_factory() as db:
            return await harness.app.state.approvals.expire_due(db, now=sweep_time)

    assert sorted(await asyncio.gather(expire_commands(), expire_commands())) == [0, 1]
    assert sorted(await asyncio.gather(expire_approvals(), expire_approvals())) == [0, 1]
    assert await expire_commands() == 0
    assert await expire_approvals() == 0
    async with harness.database.session_factory() as db:
        command_audits = await db.scalar(
            select(func.count(AuditEvent.id)).where(AuditEvent.action == "command.expire")
        )
        approval_audits = await db.scalar(
            select(func.count(AuditEvent.id)).where(
                AuditEvent.action == "approval.default_deny",
                AuditEvent.resource_id == str(approval.id),
            )
        )
    assert command_audits == 1
    assert approval_audits == 1


async def test_outbox_prune_keeps_active_unacked_and_cleans_revoked_or_acked(
    harness: Harness,
) -> None:
    active, _ = await seed_active_device(harness)
    revoked = Device(
        owner_user_id="42",
        name="Revoked outbox device",
        public_key=f"revoked-{uuid.uuid4()}",
        status=DeviceStatus.REVOKED,
        workspace_roots=["/workspace"],
        last_server_sequence=1,
        last_server_acked_sequence=0,
    )
    now = datetime.now(UTC)
    created = now - timedelta(days=2)
    retained_until = now - timedelta(days=1)
    async with harness.database.session_factory() as db:
        db.add(revoked)
        await db.flush()
        db.add_all(
            [
                DeviceOutbox(
                    device_id=active.id,
                    sequence=1,
                    encoded_envelope="active-unacked",
                    ack_sequence=0,
                    frame_type="command",
                    byte_size=14,
                    created_at=created,
                    retained_until=retained_until,
                ),
                DeviceOutbox(
                    device_id=active.id,
                    sequence=2,
                    encoded_envelope="active-acked",
                    ack_sequence=0,
                    frame_type="heartbeat_ack",
                    byte_size=12,
                    created_at=created,
                    retained_until=retained_until,
                    acked_at=created + timedelta(hours=1),
                ),
                DeviceOutbox(
                    device_id=revoked.id,
                    sequence=1,
                    encoded_envelope="revoked-unacked",
                    ack_sequence=0,
                    frame_type="command",
                    byte_size=15,
                    created_at=created,
                    retained_until=retained_until,
                ),
            ]
        )
        await db.commit()
    async with harness.database.session_factory() as db:
        assert await harness.app.state.realtime.prune_outbox(db, now=now) == 2
    async with harness.database.session_factory() as db:
        rows = list((await db.scalars(select(DeviceOutbox))).all())
        stored_revoked = await db.get(Device, revoked.id)
    assert [(row.device_id, row.sequence) for row in rows] == [(active.id, 1)]
    assert stored_revoked.last_server_acked_sequence == stored_revoked.last_server_sequence == 1


async def test_start_turn_refreshes_binding_after_device_lock_before_snapshot_merge(
    harness: Harness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert (await exchange(harness)).status_code == 201
    device, _ = await seed_active_device(harness)
    binding = ThreadBinding(
        owner_user_id="42",
        device_id=device.id,
        remote_thread_id="snapshot-race-thread",
        status=ThreadBindingStatus.IDLE,
        cwd="/workspace",
        title="Snapshot race",
        model="gpt-5.5",
        appserver_epoch=EPOCH_THREE,
        snapshot={"messages": []},
    )
    async with harness.database.session_factory() as db:
        db.add(binding)
        await db.commit()
    original_require = harness.app.state.commands.require_owned_online_device
    injected = False

    async def inject_delta_before_lock(
        db: AsyncSession,
        *,
        owner_user_id: str,
        device_id: uuid.UUID,
        for_update: bool = False,
    ) -> Device:
        nonlocal injected
        if for_update and not injected:
            injected = True
            async with harness.database.session_factory() as event_db:
                stored = await event_db.get(ThreadBinding, binding.id)
                stored.snapshot = {
                    "messages": [
                        {
                            "id": "assistant-race",
                            "role": "assistant",
                            "text": "committed delta",
                            "created_at": datetime.now(UTC).isoformat(),
                        }
                    ]
                }
                await event_db.commit()
        return await original_require(
            db,
            owner_user_id=owner_user_id,
            device_id=device_id,
            for_update=for_update,
        )

    monkeypatch.setattr(
        harness.app.state.commands,
        "require_owned_online_device",
        inject_delta_before_lock,
    )
    response = await harness.client.post(
        f"/v1/threads/{binding.id}/turns",
        headers={
            "Origin": ORIGIN,
            harness.settings.csrf_header_name: harness.client.cookies.get(
                harness.settings.csrf_cookie_name
            ),
            "Idempotency-Key": "user-race-message",
        },
        json={"text": "user message"},
    )
    assert response.status_code == 202
    async with harness.database.session_factory() as db:
        stored = await db.get(ThreadBinding, binding.id)
    assert [message["text"] for message in stored.snapshot["messages"]] == [
        "committed delta",
        "user message",
    ]


async def test_oversized_turn_is_422_before_database_outbox_or_dispatch_side_effects(
    harness: Harness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert (await exchange(harness)).status_code == 201
    device, _ = await seed_active_device(harness)
    binding = ThreadBinding(
        owner_user_id="42",
        device_id=device.id,
        remote_thread_id="budget-boundary-thread",
        status=ThreadBindingStatus.IDLE,
        cwd="/workspace",
        title="Budget boundary",
        model="gpt-5.5",
        appserver_epoch=EPOCH_THREE,
        snapshot={"messages": []},
    )
    async with harness.database.session_factory() as db:
        db.add(binding)
        await db.commit()
        counts_before = {
            "commands": await db.scalar(select(func.count(Command.id))),
            "outbox": await db.scalar(select(func.count(DeviceOutbox.sequence))),
            "audits": await db.scalar(select(func.count(AuditEvent.id))),
            "events": await db.scalar(select(func.count(EventLog.id))),
        }

    published: list[tuple[str, str]] = []
    original_publish = harness.store.publish

    async def record_publish(channel: str, value: str) -> int:
        published.append((channel, value))
        return await original_publish(channel, value)

    monkeypatch.setattr(harness.store, "publish", record_publish)
    response = await harness.client.post(
        f"/v1/threads/{binding.id}/turns",
        headers={
            "Origin": ORIGIN,
            harness.settings.csrf_header_name: harness.client.cookies.get(
                harness.settings.csrf_cookie_name
            ),
            "Idempotency-Key": "oversized-turn",
        },
        # This is the shared emoji-over-limit vector: 200001 compact ensure_ascii bytes.
        json={"text": "😀" * 16_666 + "a" * 9},
    )
    assert response.status_code == 422
    assert response.json() == {"detail": "command_payload_too_large"}

    async with harness.database.session_factory() as db:
        stored_binding = await db.get(ThreadBinding, binding.id)
        counts_after = {
            "commands": await db.scalar(select(func.count(Command.id))),
            "outbox": await db.scalar(select(func.count(DeviceOutbox.sequence))),
            "audits": await db.scalar(select(func.count(AuditEvent.id))),
            "events": await db.scalar(select(func.count(EventLog.id))),
        }
    assert counts_after == counts_before
    assert stored_binding.status == ThreadBindingStatus.IDLE
    assert stored_binding.snapshot == {"messages": []}
    assert published == []


async def test_turn_history_compacts_oldest_unicode_messages_within_snapshot_budget(
    harness: Harness,
) -> None:
    assert (await exchange(harness)).status_code == 201
    harness.settings.device_max_result_bytes = 4_096
    device, _ = await seed_active_device(harness)
    binding = ThreadBinding(
        owner_user_id="42",
        device_id=device.id,
        remote_thread_id="bounded-history-thread",
        status=ThreadBindingStatus.IDLE,
        cwd="/workspace",
        title="Bounded history",
        model="gpt-5.5",
        appserver_epoch=EPOCH_THREE,
        snapshot={"messages": []},
    )
    async with harness.database.session_factory() as db:
        db.add(binding)
        await db.commit()

    turns = [
        ("unicode-oldest", "界" * 200),
        ("unicode-middle", "😀" * 150),
        ("unicode-newest", "新" * 200),
    ]
    for key, text in turns:
        response = await harness.client.post(
            f"/v1/threads/{binding.id}/turns",
            headers={
                "Origin": ORIGIN,
                harness.settings.csrf_header_name: harness.client.cookies.get(
                    harness.settings.csrf_cookie_name
                ),
                "Idempotency-Key": key,
            },
            json={"text": text},
        )
        assert response.status_code == 202
        async with harness.database.session_factory() as db:
            stored = await db.get(ThreadBinding, binding.id)
            command = await db.get(Command, uuid.UUID(response.json()["id"]))
            command.status = CommandStatus.SUCCEEDED
            command.completed_at = datetime.now(UTC)
            await db.commit()
        assert stored.snapshot["messages"][-1]["id"] == key
        assert ensure_ascii_json_byte_length(stored.snapshot) <= 4_096
        assert serialized_json_byte_length(stored.snapshot) <= 4_096

    assert [message["id"] for message in stored.snapshot["messages"]] == [
        "unicode-middle",
        "unicode-newest",
    ]


async def test_unfit_turn_snapshot_returns_422_without_persistence_or_dispatch(
    harness: Harness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert (await exchange(harness)).status_code == 201
    harness.settings.device_max_result_bytes = 4_096
    device, _ = await seed_active_device(harness)
    binding = ThreadBinding(
        owner_user_id="42",
        device_id=device.id,
        remote_thread_id="unfit-snapshot-thread",
        status=ThreadBindingStatus.IDLE,
        cwd="/workspace",
        title="Unfit snapshot",
        model="gpt-5.5",
        appserver_epoch=EPOCH_THREE,
        snapshot={"messages": []},
    )
    async with harness.database.session_factory() as db:
        db.add(binding)
        await db.commit()
        counts_before = {
            "commands": await db.scalar(select(func.count(Command.id))),
            "outbox": await db.scalar(select(func.count(DeviceOutbox.sequence))),
            "audits": await db.scalar(select(func.count(AuditEvent.id))),
            "events": await db.scalar(select(func.count(EventLog.id))),
        }

    published: list[tuple[str, str]] = []
    original_publish = harness.store.publish

    async def record_publish(channel: str, value: str) -> int:
        published.append((channel, value))
        return await original_publish(channel, value)

    monkeypatch.setattr(harness.store, "publish", record_publish)
    response = await harness.client.post(
        f"/v1/threads/{binding.id}/turns",
        headers={
            "Origin": ORIGIN,
            harness.settings.csrf_header_name: harness.client.cookies.get(
                harness.settings.csrf_cookie_name
            ),
            "Idempotency-Key": "unfit-current-message",
        },
        json={"text": "😀" * 400},
    )
    assert response.status_code == 422
    assert response.json() == {"detail": "thread_snapshot_too_large"}

    async with harness.database.session_factory() as db:
        stored = await db.get(ThreadBinding, binding.id)
        counts_after = {
            "commands": await db.scalar(select(func.count(Command.id))),
            "outbox": await db.scalar(select(func.count(DeviceOutbox.sequence))),
            "audits": await db.scalar(select(func.count(AuditEvent.id))),
            "events": await db.scalar(select(func.count(EventLog.id))),
        }
    assert counts_after == counts_before
    assert stored.snapshot == {"messages": []}
    assert stored.status == ThreadBindingStatus.IDLE
    assert published == []


async def test_concurrent_distinct_turns_allow_only_one_nonterminal_start(
    harness: Harness,
) -> None:
    assert (await exchange(harness)).status_code == 201
    device, _ = await seed_active_device(harness)
    binding = ThreadBinding(
        owner_user_id="42",
        device_id=device.id,
        remote_thread_id="concurrent-budget-thread",
        status=ThreadBindingStatus.IDLE,
        cwd="/workspace",
        title="Concurrent budget",
        model="gpt-5.5",
        appserver_epoch=EPOCH_THREE,
        snapshot={"messages": []},
    )
    async with harness.database.session_factory() as db:
        db.add(binding)
        await db.commit()

    async def submit(key: str, text: str):
        return await harness.client.post(
            f"/v1/threads/{binding.id}/turns",
            headers={
                "Origin": ORIGIN,
                harness.settings.csrf_header_name: harness.client.cookies.get(
                    harness.settings.csrf_cookie_name
                ),
                "Idempotency-Key": key,
            },
            json={"text": text},
        )

    responses = await asyncio.gather(
        submit("concurrent-cjk", "界" * 50),
        submit("concurrent-emoji", "😀" * 50),
    )
    assert sorted(response.status_code for response in responses) == [202, 409]
    accepted_index = next(
        index for index, response in enumerate(responses) if response.status_code == 202
    )
    rejected = next(response for response in responses if response.status_code == 409)
    assert rejected.json() == {"detail": "turn_start_in_progress"}
    accepted_key = ("concurrent-cjk", "concurrent-emoji")[accepted_index]

    async with harness.database.session_factory() as db:
        stored = await db.get(ThreadBinding, binding.id)
        command_count = await db.scalar(
            select(func.count(Command.id)).where(Command.thread_binding_id == binding.id)
        )
    message_ids = [message["id"] for message in stored.snapshot["messages"]]
    assert message_ids == [accepted_key]
    assert command_count == 1


async def test_concurrent_identical_turn_start_replays_one_command(
    harness: Harness,
) -> None:
    assert (await exchange(harness)).status_code == 201
    device, _ = await seed_active_device(harness)
    binding = ThreadBinding(
        owner_user_id="42",
        device_id=device.id,
        remote_thread_id="concurrent-idempotent-thread",
        status=ThreadBindingStatus.IDLE,
        cwd="/workspace",
        title="Concurrent idempotency",
        model="gpt-5.5",
        appserver_epoch=EPOCH_THREE,
        snapshot={"messages": []},
    )
    async with harness.database.session_factory() as db:
        db.add(binding)
        await db.commit()

    async def submit():
        return await harness.client.post(
            f"/v1/threads/{binding.id}/turns",
            headers={
                "Origin": ORIGIN,
                harness.settings.csrf_header_name: harness.client.cookies.get(
                    harness.settings.csrf_cookie_name
                ),
                "Idempotency-Key": "concurrent-identical",
            },
            json={"text": "same message"},
        )

    responses = await asyncio.gather(submit(), submit())
    assert [response.status_code for response in responses] == [202, 202]
    assert responses[0].json()["id"] == responses[1].json()["id"]

    async with harness.database.session_factory() as db:
        stored = await db.get(ThreadBinding, binding.id)
        commands = list(
            (await db.scalars(select(Command).where(Command.thread_binding_id == binding.id))).all()
        )
    assert len(commands) == 1
    assert [message["id"] for message in stored.snapshot["messages"]] == ["concurrent-identical"]


@pytest.mark.parametrize("operation", ["steer", "interrupt"])
async def test_active_turn_mutation_rechecks_binding_after_device_lock(
    harness: Harness,
    monkeypatch: pytest.MonkeyPatch,
    operation: str,
) -> None:
    assert (await exchange(harness)).status_code == 201
    device, _ = await seed_active_device(harness)
    binding = ThreadBinding(
        owner_user_id="42",
        device_id=device.id,
        remote_thread_id=f"stale-{operation}-thread",
        status=ThreadBindingStatus.RUNNING,
        cwd="/workspace",
        title=f"Stale {operation}",
        model="gpt-5.5",
        appserver_epoch=EPOCH_THREE,
        active_turn_id="turn-before-terminal-event",
        snapshot={"messages": []},
    )
    async with harness.database.session_factory() as db:
        db.add(binding)
        await db.commit()

    original_require = harness.app.state.commands.require_owned_online_device
    injected = False

    async def terminate_turn_before_device_lock(
        db: AsyncSession,
        *,
        owner_user_id: str,
        device_id: uuid.UUID,
        for_update: bool = False,
    ) -> Device:
        nonlocal injected
        if for_update and not injected:
            injected = True
            async with harness.database.session_factory() as event_db:
                stored = await event_db.get(ThreadBinding, binding.id)
                stored.active_turn_id = None
                stored.status = ThreadBindingStatus.IDLE
                await event_db.commit()
        return await original_require(
            db,
            owner_user_id=owner_user_id,
            device_id=device_id,
            for_update=for_update,
        )

    monkeypatch.setattr(
        harness.app.state.commands,
        "require_owned_online_device",
        terminate_turn_before_device_lock,
    )
    url = f"/v1/threads/{binding.id}/turns/current/{operation}"
    headers = {**csrf_headers(harness), "Idempotency-Key": f"stale-{operation}"}
    if operation == "steer":
        response = await harness.client.post(url, headers=headers, json={"text": "later"})
    else:
        response = await harness.client.post(url, headers=headers)

    assert injected is True
    assert response.status_code == 409
    assert response.json() == {"detail": "turn_not_active"}
    async with harness.database.session_factory() as db:
        command_count = await db.scalar(
            select(func.count(Command.id)).where(Command.thread_binding_id == binding.id)
        )
    assert command_count == 0


async def test_thread_start_takes_process_mutex_before_any_device_lock(
    harness: Harness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert (await exchange(harness)).status_code == 201
    device, _ = await seed_active_device(harness)
    entered_device_query = asyncio.Event()
    original_require = harness.app.state.commands.require_owned_online_device

    async def observed_require(*args: object, **kwargs: object) -> Device:
        entered_device_query.set()
        return await original_require(*args, **kwargs)

    monkeypatch.setattr(
        harness.app.state.commands,
        "require_owned_online_device",
        observed_require,
    )
    async with harness.app.state.commands.serialize_device_mutation(device.id):
        pending_request = asyncio.create_task(
            harness.client.post(
                f"/v1/devices/{device.id}/threads",
                headers={
                    **csrf_headers(harness),
                    "Idempotency-Key": "process-mutex-before-device-lock",
                },
                json={"cwd": "/workspace"},
            )
        )
        with pytest.raises(TimeoutError):
            await asyncio.wait_for(entered_device_query.wait(), timeout=0.05)
        assert not pending_request.done()

    response = await asyncio.wait_for(pending_request, timeout=2)
    assert response.status_code == 202
    assert entered_device_query.is_set()


async def test_terminal_sweeps_commit_state_audit_and_events_atomically(
    harness: Harness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    device, _ = await seed_active_device(harness)
    base = datetime.now(UTC)
    command_binding = ThreadBinding(
        id=uuid.uuid4(),
        owner_user_id="42",
        device_id=device.id,
        remote_thread_id="command-expiry-thread",
        status=ThreadBindingStatus.RUNNING,
        cwd="/workspace",
        title="Command expiry",
        model="gpt-5.5",
        appserver_epoch=EPOCH_THREE,
        active_turn_id="turn-command",
        snapshot={"messages": []},
    )
    approval_binding = ThreadBinding(
        id=uuid.uuid4(),
        owner_user_id="42",
        device_id=device.id,
        remote_thread_id="approval-expiry-thread",
        status=ThreadBindingStatus.WAITING_FOR_APPROVAL,
        cwd="/workspace",
        title="Approval expiry",
        model="gpt-5.5",
        appserver_epoch=EPOCH_THREE,
        active_turn_id="turn-approval",
        snapshot={"messages": []},
    )
    expiring_command = Command(
        id=uuid.uuid4(),
        owner_user_id="42",
        device_id=device.id,
        thread_binding_id=command_binding.id,
        idempotency_key="atomic-command-expiry",
        idempotency_scope="atomic-command-expiry",
        request_hash="a" * 64,
        method="turn/start",
        payload={"threadId": command_binding.remote_thread_id, "input": []},
        status=CommandStatus.ACKNOWLEDGED,
        appserver_epoch=EPOCH_THREE,
        created_at=base,
        expires_at=base + timedelta(seconds=1),
    )
    approval_command = Command(
        id=uuid.uuid4(),
        owner_user_id="42",
        device_id=device.id,
        thread_binding_id=approval_binding.id,
        idempotency_key="atomic-approval-expiry",
        idempotency_scope="atomic-approval-expiry",
        request_hash="b" * 64,
        method="turn/start",
        payload={"threadId": approval_binding.remote_thread_id, "input": []},
        status=CommandStatus.SUCCEEDED,
        appserver_epoch=EPOCH_THREE,
        created_at=base,
        expires_at=base + timedelta(seconds=60),
        completed_at=base,
    )
    expiring_approval = Approval(
        id=uuid.uuid4(),
        owner_user_id="42",
        device_id=device.id,
        command_id=approval_command.id,
        external_command_id="atomic-approval-expiry",
        approval_kind="permission",
        summary="Atomic expiry",
        request={"path": "/workspace/file"},
        status=ApprovalStatus.PENDING,
        appserver_epoch=EPOCH_THREE,
        requested_at=base,
        expires_at=base + timedelta(seconds=1),
    )
    async with harness.database.session_factory() as db:
        db.add_all(
            [
                command_binding,
                approval_binding,
                expiring_command,
                approval_command,
                expiring_approval,
            ]
        )
        await db.commit()

    async def fail_append(*_args: object, **_kwargs: object) -> object:
        raise RuntimeError("simulated event append failure")

    sweep_time = base + timedelta(seconds=2)
    with monkeypatch.context() as scoped:
        scoped.setattr(harness.app.state.events, "append", fail_append)
        async with harness.database.session_factory() as db:
            with pytest.raises(RuntimeError, match="event append failure"):
                await harness.app.state.commands.expire_due(db, now=sweep_time)
        async with harness.database.session_factory() as db:
            with pytest.raises(RuntimeError, match="event append failure"):
                await harness.app.state.approvals.expire_due(db, now=sweep_time)

    async with harness.database.session_factory() as db:
        stored_command = await db.get(Command, expiring_command.id)
        stored_approval = await db.get(Approval, expiring_approval.id)
        stored_command_binding = await db.get(ThreadBinding, command_binding.id)
        stored_approval_binding = await db.get(ThreadBinding, approval_binding.id)
        audit_count = await db.scalar(select(func.count(AuditEvent.id)))
        event_count = await db.scalar(select(func.count(EventLog.id)))
    assert stored_command.status == CommandStatus.ACKNOWLEDGED
    assert stored_approval.status == ApprovalStatus.PENDING
    assert stored_command_binding.status == ThreadBindingStatus.RUNNING
    assert stored_approval_binding.status == ThreadBindingStatus.WAITING_FOR_APPROVAL
    assert audit_count == 0
    assert event_count == 0

    async def fail_publish(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError("simulated post-commit publish failure")

    with monkeypatch.context() as scoped:
        scoped.setattr(harness.app.state.events, "publish", fail_publish)
        async with harness.database.session_factory() as db:
            assert await harness.app.state.commands.expire_due(db, now=sweep_time) == 1
        async with harness.database.session_factory() as db:
            assert await harness.app.state.approvals.expire_due(db, now=sweep_time) == 1

    async with harness.database.session_factory() as db:
        stored_command = await db.get(Command, expiring_command.id)
        stored_approval = await db.get(Approval, expiring_approval.id)
        stored_command_binding = await db.get(ThreadBinding, command_binding.id)
        stored_approval_binding = await db.get(ThreadBinding, approval_binding.id)
        actions = list((await db.scalars(select(AuditEvent.action).order_by(AuditEvent.id))).all())
        event_types = list(
            (await db.scalars(select(EventLog.event_type).order_by(EventLog.id))).all()
        )
    assert stored_command.status == CommandStatus.EXPIRED
    assert stored_approval.status == ApprovalStatus.DENIED
    assert stored_approval.decision_reason == "timeout_default_deny"
    assert stored_command_binding.status == ThreadBindingStatus.FAILED
    assert stored_command_binding.active_turn_id is None
    assert stored_approval_binding.status == ThreadBindingStatus.FAILED
    assert stored_approval_binding.active_turn_id is None
    assert actions == ["command.expire", "approval.default_deny"]
    assert event_types == [
        "command.updated",
        "thread.updated",
        "approval.resolved",
        "thread.updated",
    ]


async def test_dispatch_terminal_rejections_are_atomic_and_repair_bindings(
    harness: Harness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    device, connection = await seed_active_device(harness)
    now = datetime.now(UTC)
    expired_binding = ThreadBinding(
        id=uuid.uuid4(),
        owner_user_id="42",
        device_id=device.id,
        remote_thread_id="expired-dispatch-thread",
        status=ThreadBindingStatus.RUNNING,
        cwd="/workspace",
        title="Expired dispatch",
        model="gpt-5.5",
        appserver_epoch=EPOCH_THREE,
        active_turn_id="expired-turn",
        snapshot={"messages": []},
    )
    stale_binding = ThreadBinding(
        id=uuid.uuid4(),
        owner_user_id="42",
        device_id=device.id,
        remote_thread_id="stale-dispatch-thread",
        status=ThreadBindingStatus.RUNNING,
        cwd="/workspace",
        title="Stale dispatch",
        model="gpt-5.5",
        appserver_epoch=EPOCH_TWO,
        active_turn_id="stale-turn",
        snapshot={"messages": []},
    )
    expired = Command(
        owner_user_id="42",
        device_id=device.id,
        thread_binding_id=expired_binding.id,
        idempotency_key="expired-dispatch",
        idempotency_scope="expired-dispatch",
        request_hash="c" * 64,
        method="turn/start",
        payload={"threadId": expired_binding.remote_thread_id, "input": []},
        status=CommandStatus.QUEUED,
        appserver_epoch=EPOCH_THREE,
        expires_at=now - timedelta(seconds=1),
    )
    stale = Command(
        owner_user_id="42",
        device_id=device.id,
        thread_binding_id=stale_binding.id,
        idempotency_key="stale-dispatch",
        idempotency_scope="stale-dispatch",
        request_hash="d" * 64,
        method="turn/start",
        payload={"threadId": stale_binding.remote_thread_id, "input": []},
        status=CommandStatus.QUEUED,
        appserver_epoch=EPOCH_TWO,
        expires_at=now + timedelta(seconds=30),
    )
    async with harness.database.session_factory() as db:
        db.add_all([expired_binding, stale_binding, expired, stale])
        await db.commit()

    async def fail_append(*_args: object, **_kwargs: object) -> object:
        raise RuntimeError("dispatch event append failed")

    with monkeypatch.context() as scoped:
        scoped.setattr(harness.app.state.events, "append", fail_append)
        with pytest.raises(RuntimeError, match="dispatch event append failed"):
            await harness.app.state.realtime._dispatch_command(connection, expired.id)

    async with harness.database.session_factory() as db:
        stored = await db.get(Command, expired.id)
        binding = await db.get(ThreadBinding, expired_binding.id)
        assert stored.status == CommandStatus.QUEUED
        assert binding.status == ThreadBindingStatus.RUNNING
        assert await db.scalar(select(func.count(AuditEvent.id))) == 0
        assert await db.scalar(select(func.count(EventLog.id))) == 0

    async def fail_publish(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError("terminal browser publish failed")

    with monkeypatch.context() as scoped:
        scoped.setattr(harness.app.state.events, "publish", fail_publish)
        await harness.app.state.realtime._dispatch_command(connection, expired.id)
        await harness.app.state.realtime._dispatch_command(connection, stale.id)
    async with harness.database.session_factory() as db:
        stored_expired = await db.get(Command, expired.id)
        stored_stale = await db.get(Command, stale.id)
        repaired_expired = await db.get(ThreadBinding, expired_binding.id)
        repaired_stale = await db.get(ThreadBinding, stale_binding.id)
        actions = set((await db.scalars(select(AuditEvent.action))).all())
        event_types = list(
            (await db.scalars(select(EventLog.event_type).order_by(EventLog.id))).all()
        )
    assert stored_expired.status == CommandStatus.EXPIRED
    assert stored_expired.error_code == "expired"
    assert stored_stale.status == CommandStatus.DENIED
    assert stored_stale.error_code == "invalid_epoch"
    assert repaired_expired.status == ThreadBindingStatus.FAILED
    assert repaired_expired.active_turn_id is None
    assert repaired_stale.status == ThreadBindingStatus.FAILED
    assert repaired_stale.active_turn_id is None
    assert actions == {"command.expire", "command.dispatch_reject"}
    assert event_types == [
        "command.updated",
        "thread.updated",
        "command.updated",
        "thread.updated",
    ]
    assert connection.websocket.sent == []


async def test_resume_ack_migrates_stale_binding_and_accepts_current_epoch_events(
    harness: Harness,
) -> None:
    device, connection = await seed_active_device(harness)
    binding = ThreadBinding(
        id=uuid.uuid4(),
        owner_user_id="42",
        device_id=device.id,
        remote_thread_id="resume-across-epoch",
        status=ThreadBindingStatus.STALE,
        cwd="/workspace",
        title="Resume across epoch",
        model="gpt-5.5",
        appserver_epoch=EPOCH_TWO,
        snapshot={"messages": []},
    )
    command = Command(
        id=uuid.uuid4(),
        owner_user_id="42",
        device_id=device.id,
        thread_binding_id=binding.id,
        idempotency_key="resume-across-epoch",
        idempotency_scope="resume-across-epoch",
        request_hash="e" * 64,
        method="thread/resume",
        payload={"threadId": binding.remote_thread_id},
        status=CommandStatus.DISPATCHED,
        appserver_epoch=EPOCH_THREE,
        expires_at=datetime.now(UTC) + timedelta(seconds=30),
    )
    async with harness.database.session_factory() as db:
        db.add_all([binding, command])
        await db.commit()

    await harness.app.state.realtime._apply_command_ack(
        connection,
        frame(
            device.id,
            1,
            "command_ack",
            {
                "command_id": str(command.id),
                "state": "completed",
                "result": {"thread": {"id": binding.remote_thread_id}},
            },
        ),
    )
    await harness.app.state.realtime._apply_device_event(
        connection,
        frame(
            device.id,
            2,
            "event",
            {
                "method": "item/agentMessage/delta",
                "params": {
                    "threadId": binding.remote_thread_id,
                    "itemId": "resumed-message",
                    "delta": "current epoch works",
                },
            },
        ),
    )

    async with harness.database.session_factory() as db:
        stored = await db.get(ThreadBinding, binding.id)
        stored_command = await db.get(Command, command.id)
        event_types = list(
            (await db.scalars(select(EventLog.event_type).order_by(EventLog.id))).all()
        )
    assert stored_command.status == CommandStatus.SUCCEEDED
    assert stored.status == ThreadBindingStatus.IDLE
    assert stored.appserver_epoch == EPOCH_THREE
    assert len(stored.snapshot["messages"]) == 1
    assert stored.snapshot["messages"][0] == {
        "id": "resumed-message",
        "role": "assistant",
        "text": "current epoch works",
        "created_at": stored.snapshot["messages"][0]["created_at"],
    }
    assert event_types == ["command.updated", "thread.updated", "turn.delta"]


async def test_resume_route_survives_prelookup_rollback(harness: Harness) -> None:
    assert (await exchange(harness)).status_code == 201
    device, _ = await seed_active_device(harness)
    binding = ThreadBinding(
        owner_user_id="42",
        device_id=device.id,
        remote_thread_id="resume-route-rollback",
        status=ThreadBindingStatus.STALE,
        cwd="/workspace",
        title="Resume route rollback",
        model="gpt-5.5",
        appserver_epoch=EPOCH_TWO,
        snapshot={"messages": []},
    )
    async with harness.database.session_factory() as db:
        db.add(binding)
        await db.commit()

    response = await harness.client.post(
        f"/v1/threads/{binding.id}/resume",
        headers={**csrf_headers(harness), "Idempotency-Key": "resume-route-rollback"},
    )
    assert response.status_code == 202
    async with harness.database.session_factory() as db:
        command = await db.scalar(select(Command).where(Command.thread_binding_id == binding.id))
    assert command is not None
    assert command.method == "thread/resume"
    assert command.payload == {"threadId": binding.remote_thread_id}
    assert command.appserver_epoch == EPOCH_THREE


async def test_approval_decision_is_owner_idempotent_across_session_rotation(
    harness: Harness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert (await exchange(harness, "first-session-token")).status_code == 201
    device, _ = await seed_active_device(harness)
    now = datetime.now(UTC)
    approval = Approval(
        owner_user_id="42",
        device_id=device.id,
        external_command_id="session-rotation-approval",
        approval_kind="permission",
        summary="Session rotation",
        request={"path": "/workspace/file"},
        status=ApprovalStatus.PENDING,
        appserver_epoch=EPOCH_THREE,
        requested_at=now,
        expires_at=now + timedelta(seconds=60),
    )
    async with harness.database.session_factory() as db:
        first_session = await db.scalar(
            select(ControlSession).where(ControlSession.revoked_at.is_(None))
        )
        assert first_session is not None
        first_session_id = first_session.id
        db.add(approval)
        await db.commit()

    async def fail_publish(*_args: object, **_kwargs: object) -> int:
        raise RuntimeError("simulated Redis publish failure")

    with monkeypatch.context() as scoped:
        scoped.setattr(harness.store, "publish", fail_publish)
        first = await harness.client.post(
            f"/v1/approvals/{approval.id}/decision",
            headers=csrf_headers(harness),
            json={"decision": "approve"},
        )
    assert first.status_code == 204

    assert (await exchange(harness, "rotated-session-token")).status_code == 201
    async with harness.database.session_factory() as db:
        second_session = await db.scalar(
            select(ControlSession)
            .where(ControlSession.revoked_at.is_(None))
            .order_by(ControlSession.issued_at.desc(), ControlSession.id.desc())
        )
        assert second_session is not None
        assert second_session.id != first_session_id

    with monkeypatch.context() as scoped:
        scoped.setattr(harness.store, "publish", fail_publish)
        replay = await harness.client.post(
            f"/v1/approvals/{approval.id}/decision",
            headers=csrf_headers(harness),
            json={"decision": "approve"},
        )
    assert replay.status_code == 204

    conflict = await harness.client.post(
        f"/v1/approvals/{approval.id}/decision",
        headers=csrf_headers(harness),
        json={"decision": "deny"},
    )
    assert conflict.status_code == 409
    assert conflict.json() == {"detail": "approval_already_decided"}

    async with harness.database.session_factory() as db:
        stored = await db.get(Approval, approval.id)
        audit_count = await db.scalar(
            select(func.count(AuditEvent.id)).where(
                AuditEvent.action == "approval.decide",
                AuditEvent.resource_id == str(approval.id),
            )
        )
        event_count = await db.scalar(
            select(func.count(EventLog.id)).where(
                EventLog.event_type == "approval.resolved",
                EventLog.payload["approval_id"].as_string() == str(approval.id),
            )
        )
    assert stored.status == ApprovalStatus.APPROVED
    assert stored.decision_reason == "user_approved"
    assert stored.decided_by_session_id == first_session_id
    assert stored.decision_dispatched_at is None
    assert audit_count == 1
    assert event_count == 1

    wake_attempts = 0

    async def fail_first_wake(channel: str, _value: str) -> int:
        nonlocal wake_attempts
        assert channel == f"device-dispatch:{device.id}"
        wake_attempts += 1
        if wake_attempts == 1:
            raise RuntimeError("first reconcile wake failed")
        return 0

    with monkeypatch.context() as scoped:
        scoped.setattr(harness.store, "publish", fail_first_wake)
        async with harness.database.session_factory() as db:
            assert await harness.app.state.approvals.reconcile_undispatched(db) == 0
        async with harness.database.session_factory() as db:
            assert await harness.app.state.approvals.reconcile_undispatched(db) == 1
    assert wake_attempts == 2


async def test_approval_expiry_classifies_dispatchability_and_retention(
    harness: Harness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    online, online_connection = await seed_active_device(harness, epoch=EPOCH_THREE)
    stale, _ = await seed_active_device(harness, epoch=EPOCH_TWO)
    offline, _ = await seed_active_device(harness, epoch=EPOCH_THREE)
    revoked, _ = await seed_active_device(harness, epoch=EPOCH_THREE)
    base = datetime.now(UTC)
    approvals = {
        "online": Approval(
            owner_user_id="42",
            device_id=online.id,
            external_command_id="online-timeout",
            approval_kind="permission",
            summary="Online timeout",
            request={"large": "payload"},
            status=ApprovalStatus.PENDING,
            appserver_epoch=EPOCH_THREE,
            requested_at=base,
            expires_at=base + timedelta(seconds=1),
        ),
        "stale": Approval(
            owner_user_id="42",
            device_id=stale.id,
            external_command_id="stale-timeout",
            approval_kind="permission",
            summary="Stale timeout",
            request={"large": "payload"},
            status=ApprovalStatus.PENDING,
            appserver_epoch=EPOCH_ONE,
            requested_at=base,
            expires_at=base + timedelta(seconds=1),
        ),
        "offline": Approval(
            owner_user_id="42",
            device_id=offline.id,
            external_command_id="offline-timeout",
            approval_kind="permission",
            summary="Offline timeout",
            request={"large": "payload"},
            status=ApprovalStatus.PENDING,
            appserver_epoch=EPOCH_THREE,
            requested_at=base,
            expires_at=base + timedelta(seconds=1),
        ),
        "revoked": Approval(
            owner_user_id="42",
            device_id=revoked.id,
            external_command_id="revoked-timeout",
            approval_kind="permission",
            summary="Revoked timeout",
            request={"large": "payload"},
            status=ApprovalStatus.PENDING,
            appserver_epoch=EPOCH_THREE,
            requested_at=base,
            expires_at=base + timedelta(seconds=1),
        ),
    }
    async with harness.database.session_factory() as db:
        stored_revoked = await db.get(Device, revoked.id)
        stored_revoked.status = DeviceStatus.REVOKED
        stored_revoked.revoked_at = base
        stored_revoked.active_epoch = None
        stored_revoked.active_connection_nonce = None
        db.add_all(approvals.values())
        await db.commit()
    await harness.store.delete(f"connection:{offline.id}")

    published: list[str] = []

    async def record_publish(channel: str, _value: str) -> int:
        published.append(channel)
        return 0

    with monkeypatch.context() as scoped:
        scoped.setattr(harness.store, "publish", record_publish)
        async with harness.database.session_factory() as db:
            assert (
                await harness.app.state.approvals.expire_due(
                    db,
                    now=base + timedelta(seconds=2),
                )
                == 4
            )
    assert [channel for channel in published if channel.startswith("device-dispatch:")] == [
        f"device-dispatch:{online.id}"
    ]

    expected_reasons = {
        "online": "timeout_default_deny",
        "stale": "stale_epoch_default_deny",
        "offline": "device_offline_default_deny",
        "revoked": "device_revoked_default_deny",
    }
    async with harness.database.session_factory() as db:
        stored_rows = {
            name: await db.get(Approval, approval.id) for name, approval in approvals.items()
        }
    for name, row in stored_rows.items():
        assert row.status == ApprovalStatus.DENIED
        assert row.decision_reason == expected_reasons[name]
        assert row.external_command_id is None
        assert row.summary == "Approval denied"
        assert row.request == {}
    assert "timeout_default_deny" not in NON_DISPATCHABLE_APPROVAL_REASONS
    assert "device_revoked_default_deny" in NON_DISPATCHABLE_APPROVAL_REASONS

    published.clear()
    with monkeypatch.context() as scoped:
        scoped.setattr(harness.store, "publish", record_publish)
        async with harness.database.session_factory() as db:
            assert await harness.app.state.approvals.reconcile_undispatched(db) == 1
    assert published == [f"device-dispatch:{online.id}"]

    await harness.app.state.realtime._dispatch_approval(
        online_connection,
        approvals["online"].id,
    )
    async with harness.database.session_factory() as db:
        online_row = await db.get(Approval, approvals["online"].id)
    assert online_row.decision_dispatched_at is not None
    assert len(online_connection.websocket.sent) == 1

    old = base - timedelta(days=2)
    harness.settings.approval_record_retention_days = 1
    async with harness.database.session_factory() as db:
        for name in ("stale", "offline", "revoked"):
            row = await db.get(Approval, approvals[name].id)
            row.decided_at = old
        await db.commit()
    async with harness.database.session_factory() as db:
        result = await harness.app.state.retention.sweep(db, now=base)
    assert result.approvals == 3
    async with harness.database.session_factory() as db:
        assert await db.get(Approval, approvals["online"].id) is not None
        for name in ("stale", "offline", "revoked"):
            assert await db.get(Approval, approvals[name].id) is None


async def test_approval_record_caps_stop_terminal_audit_and_event_growth(
    harness: Harness,
) -> None:
    device, connection = await seed_active_device(harness)
    harness.settings.device_max_approval_records = 2
    harness.settings.owner_max_approval_records = 10
    now = datetime.now(UTC)

    async def submit(approval_id: uuid.UUID, sequence: int) -> None:
        await harness.app.state.realtime._apply_approval_request(
            connection,
            frame(
                device.id,
                sequence,
                "approval_request",
                {
                    "approval_id": str(approval_id),
                    "command_id": f"terminal-growth-{sequence}",
                    "kind": "permission",
                    "summary": "Attacker-controlled summary",
                    "details": {"blob": "x" * 1024},
                    "expires_at": now - timedelta(seconds=1),
                },
            ),
        )

    accepted_ids = [uuid.uuid4(), uuid.uuid4()]
    await submit(accepted_ids[0], 1)
    await submit(accepted_ids[1], 2)
    async with harness.database.session_factory() as db:
        counts_at_cap = {
            "approvals": await db.scalar(select(func.count(Approval.id))),
            "audits": await db.scalar(select(func.count(AuditEvent.id))),
            "events": await db.scalar(select(func.count(EventLog.id))),
        }
        rows = list((await db.scalars(select(Approval).order_by(Approval.id))).all())
    assert counts_at_cap == {"approvals": 2, "audits": 2, "events": 2}
    assert all(row.external_command_id is None for row in rows)
    assert all(row.summary == "Approval denied" for row in rows)
    assert all(row.request == {} for row in rows)

    for sequence in range(3, 8):
        with pytest.raises(
            RealtimeProtocolError,
            match="device_approval_record_limit_exceeded",
        ):
            await submit(uuid.uuid4(), sequence)
    async with harness.database.session_factory() as db:
        counts_after_attack = {
            "approvals": await db.scalar(select(func.count(Approval.id))),
            "audits": await db.scalar(select(func.count(AuditEvent.id))),
            "events": await db.scalar(select(func.count(EventLog.id))),
        }
    assert counts_after_attack == counts_at_cap

    second_device, second_connection = await seed_active_device(harness)
    harness.settings.device_max_approval_records = 10
    harness.settings.owner_max_approval_records = 2
    with pytest.raises(
        RealtimeProtocolError,
        match="owner_approval_record_limit_exceeded",
    ):
        await harness.app.state.realtime._apply_approval_request(
            second_connection,
            frame(
                second_device.id,
                1,
                "approval_request",
                {
                    "approval_id": str(uuid.uuid4()),
                    "command_id": "owner-terminal-growth",
                    "kind": "permission",
                    "summary": "Owner cap",
                    "details": {},
                    "expires_at": now + timedelta(seconds=30),
                },
            ),
        )
    async with harness.database.session_factory() as db:
        assert await db.scalar(select(func.count(Approval.id))) == 2
        assert await db.scalar(select(func.count(AuditEvent.id))) == 2
        assert await db.scalar(select(func.count(EventLog.id))) == 2


async def test_revoke_atomically_denies_undispatched_approvals_and_is_retry_safe(
    harness: Harness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert (await exchange(harness)).status_code == 201
    device, _ = await seed_active_device(harness)
    now = datetime.now(UTC)
    binding = ThreadBinding(
        owner_user_id="42",
        device_id=device.id,
        remote_thread_id="revoked-thread",
        status=ThreadBindingStatus.IDLE,
        cwd="/workspace",
        title="Revoked thread",
        model="gpt-5.5",
        appserver_epoch=EPOCH_THREE,
        snapshot={"messages": []},
    )

    def approval(
        suffix: str,
        status: ApprovalStatus,
        *,
        dispatched: bool = False,
    ) -> Approval:
        return Approval(
            owner_user_id="42",
            device_id=device.id,
            external_command_id=f"revoke-{suffix}",
            approval_kind="permission",
            summary=f"Revoke {suffix}",
            request={"secret": "remove me"},
            status=status,
            appserver_epoch=EPOCH_THREE,
            requested_at=now,
            expires_at=now + timedelta(seconds=60),
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

    pending = approval("pending", ApprovalStatus.PENDING)
    approved = approval("approved", ApprovalStatus.APPROVED)
    denied = approval("denied", ApprovalStatus.DENIED)
    dispatched = approval("dispatched", ApprovalStatus.APPROVED, dispatched=True)
    async with harness.database.session_factory() as db:
        db.add_all([binding, pending, approved, denied, dispatched])
        await db.commit()

    original_append = harness.app.state.events.append

    async def fail_device_event(*args: object, **kwargs: object) -> object:
        if kwargs.get("event_type") == "device.updated":
            raise RuntimeError("simulated final event failure")
        return await original_append(*args, **kwargs)

    with monkeypatch.context() as scoped:
        scoped.setattr(harness.app.state.events, "append", fail_device_event)
        with pytest.raises(RuntimeError, match="final event failure"):
            await harness.client.delete(
                f"/v1/devices/{device.id}",
                headers=csrf_headers(harness),
            )
    async with harness.database.session_factory() as db:
        unchanged_device = await db.get(Device, device.id)
        unchanged_binding = await db.get(ThreadBinding, binding.id)
        unchanged_rows = {
            row.id: row.status
            for row in (
                await db.scalars(select(Approval).where(Approval.device_id == device.id))
            ).all()
        }
        assert await db.scalar(select(func.count(EventLog.id))) == 0
        assert (
            await db.scalar(
                select(func.count(AuditEvent.id)).where(
                    AuditEvent.action.in_(("approval.default_deny", "device.revoke"))
                )
            )
            == 0
        )
    assert unchanged_device.status == DeviceStatus.ACTIVE
    assert unchanged_device.active_epoch == EPOCH_THREE
    assert unchanged_binding.status == ThreadBindingStatus.IDLE
    assert unchanged_rows == {
        pending.id: ApprovalStatus.PENDING,
        approved.id: ApprovalStatus.APPROVED,
        denied.id: ApprovalStatus.DENIED,
        dispatched.id: ApprovalStatus.APPROVED,
    }

    async def fail_post_commit(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError("simulated post-commit cleanup failure")

    async def fail_publish(*_args: object, **_kwargs: object) -> int:
        raise RuntimeError("simulated post-commit publish failure")

    with monkeypatch.context() as scoped:
        scoped.setattr(harness.app.state.device_tokens, "revoke_access_token", fail_post_commit)
        scoped.setattr(harness.store, "delete", fail_post_commit)
        scoped.setattr(harness.store, "publish", fail_publish)
        first = await harness.client.delete(
            f"/v1/devices/{device.id}",
            headers=csrf_headers(harness),
        )
        second = await harness.client.delete(
            f"/v1/devices/{device.id}",
            headers=csrf_headers(harness),
        )
    assert first.status_code == 204
    assert second.status_code == 204

    async with harness.database.session_factory() as db:
        stored_device = await db.get(Device, device.id)
        stored_binding = await db.get(ThreadBinding, binding.id)
        rows = {
            row.id: row
            for row in (
                await db.scalars(select(Approval).where(Approval.device_id == device.id))
            ).all()
        }
        default_deny_count = await db.scalar(
            select(func.count(AuditEvent.id)).where(AuditEvent.action == "approval.default_deny")
        )
        revoke_count = await db.scalar(
            select(func.count(AuditEvent.id)).where(AuditEvent.action == "device.revoke")
        )
        event_types = list(
            (await db.scalars(select(EventLog.event_type).order_by(EventLog.id))).all()
        )
    assert stored_device.status == DeviceStatus.REVOKED
    assert stored_device.refresh_credential_hash is None
    assert stored_device.active_epoch is None
    assert stored_device.active_connection_nonce is None
    assert stored_binding.status == ThreadBindingStatus.CLOSED
    for claimed in (pending, approved, denied):
        assert rows[claimed.id].status == ApprovalStatus.DENIED
        assert rows[claimed.id].decision_reason == "device_revoked_default_deny"
        assert rows[claimed.id].external_command_id is None
        assert rows[claimed.id].summary == "Approval denied"
        assert rows[claimed.id].request == {}
    assert rows[dispatched.id].status == ApprovalStatus.APPROVED
    assert rows[dispatched.id].decision_reason == "user_approved"
    assert rows[dispatched.id].decision_dispatched_at is not None
    assert default_deny_count == 3
    assert revoke_count == 1
    assert event_types == [
        "approval.resolved",
        "approval.resolved",
        "approval.resolved",
        "thread.updated",
        "device.updated",
    ]


async def test_safe_archive_releases_visible_capacity_but_retained_history_is_bounded(
    harness: Harness,
) -> None:
    assert (await exchange(harness)).status_code == 201
    device, _ = await seed_active_device(harness)
    harness.settings.bootstrap_max_threads = 1
    harness.settings.owner_max_thread_records = 2
    binding = ThreadBinding(
        owner_user_id="42",
        device_id=device.id,
        remote_thread_id="archive-first",
        status=ThreadBindingStatus.RUNNING,
        cwd="/workspace",
        title="Archive first",
        model="gpt-5.5",
        appserver_epoch=EPOCH_THREE,
        active_turn_id="active-turn",
        snapshot={"messages": []},
    )
    async with harness.database.session_factory() as db:
        db.add(binding)
        await db.commit()

    blocked = await harness.client.delete(
        f"/v1/threads/{binding.id}",
        headers=csrf_headers(harness),
    )
    assert blocked.status_code == 409
    assert blocked.json() == {"detail": "thread_not_archivable"}

    async with harness.database.session_factory() as db:
        stored = await db.get(ThreadBinding, binding.id)
        stored.status = ThreadBindingStatus.IDLE
        stored.active_turn_id = None
        await db.commit()
    archived = await harness.client.delete(
        f"/v1/threads/{binding.id}",
        headers=csrf_headers(harness),
    )
    assert archived.status_code == 204

    created = await harness.client.post(
        f"/v1/devices/{device.id}/threads",
        headers={**csrf_headers(harness), "Idempotency-Key": "archive-replacement"},
        json={"cwd": "/workspace"},
    )
    assert created.status_code == 202
    replacement_id = uuid.UUID(created.json()["id"])
    async with harness.database.session_factory() as db:
        replacement = await db.get(ThreadBinding, replacement_id)
        command = await db.scalar(
            select(Command).where(Command.thread_binding_id == replacement_id)
        )
        replacement.status = ThreadBindingStatus.FAILED
        replacement.active_turn_id = None
        command.status = CommandStatus.SUCCEEDED
        command.completed_at = datetime.now(UTC)
        await db.commit()
    second_archive = await harness.client.delete(
        f"/v1/threads/{replacement_id}",
        headers=csrf_headers(harness),
    )
    assert second_archive.status_code == 204

    at_retained_cap = await harness.client.post(
        f"/v1/devices/{device.id}/threads",
        headers={**csrf_headers(harness), "Idempotency-Key": "retained-cap"},
        json={"cwd": "/workspace"},
    )
    assert at_retained_cap.status_code == 409
    assert at_retained_cap.json() == {"detail": "thread_capacity_exceeded"}
    async with harness.database.session_factory() as db:
        statuses = list(
            (
                await db.scalars(select(ThreadBinding.status).order_by(ThreadBinding.created_at))
            ).all()
        )
        archive_audits = await db.scalar(
            select(func.count(AuditEvent.id)).where(AuditEvent.action == "thread.archive")
        )
    assert statuses == [ThreadBindingStatus.STALE, ThreadBindingStatus.STALE]
    assert archive_audits == 2


async def test_browser_event_forwarder_polls_durable_log_without_redis_wakeup(
    harness: Harness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    device, _ = await seed_active_device(harness)
    async with harness.database.session_factory() as db:
        event = await harness.app.state.events.append(
            db,
            owner_user_id="42",
            device_id=device.id,
            event_type="device.updated",
            data={"id": str(device.id), "status": "offline"},
        )
        await db.commit()

    class SignallingWebSocket(RecordingWebSocket):
        def __init__(self) -> None:
            super().__init__()
            self.delivered = asyncio.Event()

        async def send_text(self, value: str) -> None:
            await super().send_text(value)
            self.delivered.set()

    socket = SignallingWebSocket()
    latest_cursor = [0]
    session_gate = BrowserSessionGate()
    session_gate.authorized.set()
    monkeypatch.setattr(realtime_module, "BROWSER_EVENT_DB_POLL_SECONDS", 0.01)
    forwarder = asyncio.create_task(
        harness.app.state.realtime._forward_browser_queue(
            socket,  # type: ignore[arg-type]
            "42",
            asyncio.Queue(),
            latest_cursor,
            session_gate,
        )
    )
    await asyncio.wait_for(socket.delivered.wait(), timeout=1)
    forwarder.cancel()
    await asyncio.gather(forwarder, return_exceptions=True)
    assert len(socket.sent) == 1
    assert json.loads(socket.sent[0])["cursor"] == event.cursor
    assert latest_cursor == [int(event.cursor)]
