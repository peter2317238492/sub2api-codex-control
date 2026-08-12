from __future__ import annotations

import asyncio
import json
import uuid
from datetime import UTC, datetime, timedelta

from conftest import Harness
from sqlalchemy import func, select

from control_api.models import (
    AuditEvent,
    Command,
    CommandStatus,
    Device,
    DeviceOutbox,
    DeviceStatus,
    EventLog,
    ThreadBinding,
    ThreadBindingStatus,
)
from control_api.protocol import CommandAckPayload, ControlEnvelope
from control_api.realtime import ActiveDeviceSocket

OLD_EPOCH = "old-epoch-0123456789abcdef012345"
NEW_EPOCH = "new-epoch-0123456789abcdef012345"


class RecordingWebSocket:
    def __init__(self) -> None:
        self.closed: list[tuple[int, str]] = []

    async def close(self, code: int, reason: str) -> None:
        self.closed.append((code, reason))


def device_frame(
    device_id: uuid.UUID,
    sequence: int,
    frame_type: str,
    payload: dict[str, object],
    *,
    epoch: str = OLD_EPOCH,
) -> ControlEnvelope:
    return ControlEnvelope.model_validate(
        {
            "version": 1,
            "id": str(uuid.uuid4()),
            "device_id": str(device_id),
            "epoch": epoch,
            "seq": sequence,
            "ack": 0,
            "type": frame_type,
            "sent_at": datetime.now(UTC),
            "payload": payload,
        }
    )


async def test_epoch_activation_terminalizes_old_work_without_punching_outbox_holes(
    harness: Harness,
) -> None:
    now = datetime.now(UTC)
    device_id = uuid.uuid4()
    device = Device(
        id=device_id,
        owner_user_id="42",
        name="Epoch replacement device",
        public_key="epoch-replacement-test-key",
        status=DeviceStatus.ACTIVE,
        workspace_roots=["/workspace"],
        active_epoch=NEW_EPOCH,
        active_connection_nonce=str(uuid.uuid4()),
        last_server_sequence=1,
        last_server_acked_sequence=0,
    )
    bindings = [
        ThreadBinding(
            owner_user_id="42",
            id=uuid.uuid4(),
            device_id=device_id,
            remote_thread_id=f"remote-{index}",
            status=ThreadBindingStatus.RUNNING,
            cwd="/workspace",
            title=f"Epoch command {index}",
            model="gpt-5.5",
            appserver_epoch=OLD_EPOCH,
            active_turn_id=f"turn-{index}",
            snapshot={"messages": []},
            created_at=now,
            updated_at=now,
        )
        for index in range(3)
    ]
    states = (
        CommandStatus.QUEUED,
        CommandStatus.DISPATCHED,
        CommandStatus.ACKNOWLEDGED,
    )
    commands = [
        Command(
            owner_user_id="42",
            id=uuid.uuid4(),
            device_id=device_id,
            thread_binding_id=binding.id,
            idempotency_key=f"epoch-{index}",
            idempotency_scope=f"epoch-{index}",
            request_hash=str(index) * 64,
            method="turn/start",
            payload={"threadId": binding.remote_thread_id, "input": []},
            status=state,
            appserver_epoch=OLD_EPOCH,
            created_at=now,
            expires_at=now + timedelta(seconds=30),
        )
        for index, (binding, state) in enumerate(zip(bindings, states, strict=True), start=1)
    ]
    encoded = json.dumps(
        {
            "version": 1,
            "id": str(uuid.uuid4()),
            "device_id": str(device_id),
            "epoch": OLD_EPOCH,
            "seq": 1,
            "ack": 0,
            "type": "command",
            "sent_at": now.isoformat().replace("+00:00", "Z"),
            "payload": {"command_id": str(commands[1].id)},
        },
        separators=(",", ":"),
    )
    outbox = DeviceOutbox(
        device_id=device_id,
        sequence=1,
        encoded_envelope=encoded,
        ack_sequence=0,
        frame_type="command",
        byte_size=len(encoded.encode()),
        created_at=now,
        retained_until=now + timedelta(days=1),
    )
    async with harness.database.session_factory() as db:
        db.add_all([device, *bindings, *commands, outbox])
        await db.commit()

    async with harness.database.session_factory() as db:
        locked_device = await db.scalar(
            select(Device).where(Device.id == device.id).with_for_update()
        )
        assert locked_device is not None
        emitted = await harness.app.state.realtime._reconcile_stale_epoch_commands(
            db,
            locked_device,
            NEW_EPOCH,
            now + timedelta(seconds=1),
        )
        await db.commit()

    assert len(emitted) == 6
    async with harness.database.session_factory() as db:
        stored_commands = {
            command.id: command
            for command in (
                await db.scalars(select(Command).where(Command.device_id == device.id))
            ).all()
        }
        stored_bindings = list(
            (
                await db.scalars(
                    select(ThreadBinding)
                    .where(ThreadBinding.device_id == device.id)
                    .order_by(ThreadBinding.created_at)
                )
            ).all()
        )
        stored_device = await db.get(Device, device.id)
        stored_outbox = await db.get(DeviceOutbox, (device.id, 1))
        audit_count = await db.scalar(
            select(func.count(AuditEvent.id)).where(AuditEvent.resource_type == "command")
        )
        event_count = await db.scalar(
            select(func.count(EventLog.id)).where(EventLog.device_id == device.id)
        )

    queued_command = stored_commands[commands[0].id]
    assert queued_command.status == CommandStatus.DENIED
    assert queued_command.error_code == "invalid_epoch"
    for command_id in (commands[1].id, commands[2].id):
        command = stored_commands[command_id]
        assert command.status == CommandStatus.FAILED
        assert command.error_code == "epoch_replaced_indeterminate"
        assert command.result is None
    assert all(binding.status == ThreadBindingStatus.FAILED for binding in stored_bindings)
    assert all(binding.active_turn_id is None for binding in stored_bindings)
    assert audit_count == 3
    assert event_count == 6
    assert stored_outbox is not None
    assert stored_outbox.encoded_envelope == encoded
    assert stored_outbox.acked_at is None
    assert stored_device is not None
    assert stored_device.last_server_sequence == 1
    assert stored_device.last_server_acked_sequence == 0


async def test_epoch_activation_marks_unlinked_visible_binding_resume_required_once(
    harness: Harness,
) -> None:
    now = datetime.now(UTC)
    device_id = uuid.uuid4()
    device = Device(
        id=device_id,
        owner_user_id="42",
        name="Unlinked epoch device",
        public_key=f"unlinked-{uuid.uuid4()}",
        status=DeviceStatus.ACTIVE,
        workspace_roots=["/workspace"],
        active_epoch=NEW_EPOCH,
    )
    binding = ThreadBinding(
        id=uuid.uuid4(),
        owner_user_id="42",
        device_id=device_id,
        remote_thread_id="unlinked-old-thread",
        status=ThreadBindingStatus.IDLE,
        cwd="/workspace",
        title="Needs resume",
        model="gpt-5.5",
        appserver_epoch=OLD_EPOCH,
        active_turn_id="stale-turn",
        snapshot={"messages": []},
        created_at=now,
        updated_at=now,
    )
    async with harness.database.session_factory() as db:
        db.add_all([device, binding])
        await db.commit()

    async with harness.database.session_factory() as db:
        stored_device = await db.get(Device, device.id)
        first = await harness.app.state.realtime._reconcile_stale_epoch_commands(
            db, stored_device, NEW_EPOCH, now + timedelta(seconds=1)
        )
        await db.commit()
    async with harness.database.session_factory() as db:
        stored_device = await db.get(Device, device.id)
        second = await harness.app.state.realtime._reconcile_stale_epoch_commands(
            db, stored_device, NEW_EPOCH, now + timedelta(seconds=2)
        )
        await db.commit()

    assert len(first) == 1
    assert second == []
    async with harness.database.session_factory() as db:
        stored = await db.get(ThreadBinding, binding.id)
        audit_count = await db.scalar(
            select(func.count(AuditEvent.id)).where(
                AuditEvent.action == "thread.epoch_reconcile",
                AuditEvent.resource_id == str(binding.id),
            )
        )
        event_count = await db.scalar(
            select(func.count(EventLog.id)).where(EventLog.thread_binding_id == binding.id)
        )
    assert stored.status == ThreadBindingStatus.FAILED
    assert stored.active_turn_id is None
    assert "resume" in stored.last_error
    assert audit_count == 1
    assert event_count == 1


async def test_old_epoch_event_is_ignored_and_terminal_ack_only_refines_command(
    harness: Harness,
) -> None:
    now = datetime.now(UTC)
    nonce = str(uuid.uuid4())
    device_id = uuid.uuid4()
    binding_id = uuid.uuid4()
    command_id = uuid.uuid4()
    device = Device(
        id=device_id,
        owner_user_id="42",
        name="Stale replay device",
        public_key=f"stale-replay-{uuid.uuid4()}",
        status=DeviceStatus.ACTIVE,
        workspace_roots=["/workspace"],
        active_epoch=NEW_EPOCH,
        active_connection_nonce=nonce,
        last_server_sequence=1,
    )
    binding = ThreadBinding(
        id=binding_id,
        owner_user_id="42",
        device_id=device_id,
        remote_thread_id="stale-thread",
        status=ThreadBindingStatus.FAILED,
        cwd="/workspace",
        title="Stale replay",
        model="gpt-5.5",
        appserver_epoch=OLD_EPOCH,
        active_turn_id=None,
        last_error="app-server epoch was replaced; resume the thread to continue",
        snapshot={"messages": []},
        created_at=now,
        updated_at=now,
    )
    command = Command(
        id=command_id,
        owner_user_id="42",
        device_id=device_id,
        thread_binding_id=binding_id,
        idempotency_key="stale-terminal-refine",
        idempotency_scope="stale-terminal-refine",
        request_hash="a" * 64,
        method="turn/start",
        payload={"threadId": binding.remote_thread_id, "input": []},
        status=CommandStatus.FAILED,
        appserver_epoch=OLD_EPOCH,
        error_code="epoch_replaced_indeterminate",
        error_message="execution state is indeterminate",
        completed_at=now,
        created_at=now,
        expires_at=now + timedelta(seconds=30),
    )
    encoded = json.dumps({"durable": "server-outbox"}, separators=(",", ":"))
    outbox = DeviceOutbox(
        device_id=device_id,
        sequence=1,
        encoded_envelope=encoded,
        ack_sequence=0,
        frame_type="command",
        byte_size=len(encoded.encode()),
        created_at=now,
        retained_until=now + timedelta(days=1),
    )
    async with harness.database.session_factory() as db:
        db.add_all([device, binding, command, outbox])
        await db.commit()

    registry = json.dumps(
        {"connection_nonce": nonce, "epoch": NEW_EPOCH, "instance_id": "test"},
        separators=(",", ":"),
    )
    await harness.store.set(
        f"connection:{device.id}", registry, harness.settings.device_registry_ttl_seconds
    )
    connection = ActiveDeviceSocket(
        websocket=RecordingWebSocket(),  # type: ignore[arg-type]
        device_id=device.id,
        owner_user_id="42",
        connection_nonce=nonce,
        epoch=NEW_EPOCH,
        registry_value=registry,
    )
    stale_event = device_frame(
        device.id,
        1,
        "event",
        {
            "method": "turn/started",
            "params": {"threadId": binding.remote_thread_id, "turnId": "must-not-project"},
        },
    )
    terminal_ack = device_frame(
        device.id,
        2,
        "command_ack",
        {
            "command_id": str(command.id),
            "state": "completed",
            "result": {"turn": {"id": "completed-old-turn"}},
        },
    )

    await harness.app.state.realtime._process_device_frame(connection, stale_event)
    await harness.app.state.realtime._process_device_frame(connection, terminal_ack)

    async with harness.database.session_factory() as db:
        stored_device = await db.get(Device, device.id)
        stored_binding = await db.get(ThreadBinding, binding.id)
        stored_command = await db.get(Command, command.id)
        stored_outbox = await db.get(DeviceOutbox, (device.id, 1))
        events = list(
            (
                await db.scalars(
                    select(EventLog).where(EventLog.device_id == device.id).order_by(EventLog.id)
                )
            ).all()
        )
        audit = await db.scalar(
            select(AuditEvent).where(AuditEvent.action == "command.epoch_terminal_refine")
        )
    assert stored_device.last_device_sequence == 2
    assert stored_binding.status == ThreadBindingStatus.FAILED
    assert stored_binding.active_turn_id is None
    assert stored_binding.snapshot == {"messages": []}
    assert stored_command.status == CommandStatus.SUCCEEDED
    assert stored_command.result == {"turn": {"id": "completed-old-turn"}}
    assert stored_command.error_code is None
    assert stored_outbox.encoded_envelope == encoded
    assert stored_outbox.acked_at is None
    assert [event.event_type for event in events] == ["command.updated"]
    assert audit.details["previous_error_code"] == "epoch_replaced_indeterminate"


async def test_delayed_old_kick_cannot_close_authoritative_connection(harness: Harness) -> None:
    socket = RecordingWebSocket()
    connection = ActiveDeviceSocket(
        websocket=socket,  # type: ignore[arg-type]
        device_id=uuid.uuid4(),
        owner_user_id="42",
        connection_nonce="authoritative-nonce",
        epoch=NEW_EPOCH,
    )
    ready = asyncio.Event()
    task = asyncio.create_task(harness.app.state.realtime._device_dispatch_loop(connection, ready))
    await asyncio.wait_for(ready.wait(), timeout=1)

    await harness.store.publish(
        f"device-dispatch:{connection.device_id}",
        json.dumps({"kind": "kick", "replaced_connection_nonces": ["older-connection"]}),
    )
    await asyncio.sleep(0)
    assert socket.closed == []
    assert not task.done()

    await harness.store.publish(
        f"device-dispatch:{connection.device_id}",
        json.dumps({"kind": "kick", "replaced_connection_nonces": [connection.connection_nonce]}),
    )
    await asyncio.wait_for(task, timeout=1)
    assert socket.closed == [(4001, "connection replaced")]


def test_thread_read_preserves_authoritative_running_state_and_turn(harness: Harness) -> None:
    binding_id = uuid.uuid4()
    command_id = uuid.uuid4()
    binding = ThreadBinding(
        id=binding_id,
        owner_user_id="42",
        device_id=uuid.uuid4(),
        remote_thread_id="running-thread",
        status=ThreadBindingStatus.IDLE,
        cwd="/workspace",
        title="Running",
        model="gpt-5.5",
        appserver_epoch=NEW_EPOCH,
        snapshot={"messages": []},
    )
    command = Command(
        id=command_id,
        owner_user_id="42",
        device_id=binding.device_id,
        thread_binding_id=binding.id,
        idempotency_key="read-running",
        idempotency_scope="read-running",
        request_hash="b" * 64,
        method="thread/read",
        payload={"threadId": binding.remote_thread_id},
        status=CommandStatus.SUCCEEDED,
        appserver_epoch=NEW_EPOCH,
    )
    ack = CommandAckPayload(
        command_id=command_id,
        state="completed",
        result={
            "thread": {
                "id": binding.remote_thread_id,
                "status": {"type": "active"},
                "turns": [
                    {"id": "completed-turn", "status": "completed", "items": []},
                    {"id": "running-turn", "status": "inProgress", "items": []},
                ],
            }
        },
    )

    harness.app.state.realtime._apply_command_to_binding(binding, command, ack, NEW_EPOCH)

    assert binding.status == ThreadBindingStatus.RUNNING
    assert binding.active_turn_id == "running-turn"
