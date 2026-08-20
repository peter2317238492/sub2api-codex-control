from __future__ import annotations

import asyncio
import base64
import json
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from conftest import ORIGIN, Harness, exchange
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import select

from control_api.commands import canonical_request_hash
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
    DeviceStatus,
    ThreadBinding,
    ThreadBindingStatus,
)
from control_api.protocol import CommandAckPayload, ControlEnvelope
from control_api.realtime import ActiveDeviceSocket, RealtimeService
from control_api.security import TokenDigester
from control_api.sub2api import Sub2APIUser

EPOCH = "epoch-0123456789abcdef0123456789"


class RecordingWebSocket:
    def __init__(self) -> None:
        self.closed: list[tuple[int, str]] = []

    async def close(self, code: int, reason: str) -> None:
        self.closed.append((code, reason))


def new_identity() -> tuple[Ed25519PrivateKey, str]:
    private_key = Ed25519PrivateKey.generate()
    raw = private_key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    return private_key, base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


async def seed_device(
    harness: Harness,
    *,
    owner: str = "42",
    online: bool = False,
) -> tuple[Device, Ed25519PrivateKey, str]:
    private_key, public_key = new_identity()
    refresh_credential = f"dcr_{uuid.uuid4().hex}{uuid.uuid4().hex}"
    connection_nonce = str(uuid.uuid4()) if online else None
    digester = TokenDigester(harness.settings.session_hmac_secret.get_secret_value())
    device = Device(
        owner_user_id=owner,
        name=f"Device {owner}",
        public_key=public_key,
        refresh_credential_hash=digester.digest("device-refresh", refresh_credential),
        credential_version=1,
        status=DeviceStatus.ACTIVE,
        device_metadata={"connector_version": "0.1.4", "codex_version": "0.147.0"},
        workspace_roots=["/workspace"],
        active_epoch=EPOCH if online else None,
        active_connection_nonce=connection_nonce,
    )
    async with harness.database.session_factory() as db:
        db.add(device)
        await db.commit()
    if online:
        await harness.store.set(
            f"connection:{device.id}",
            json.dumps(
                {
                    "connection_nonce": connection_nonce,
                    "epoch": EPOCH,
                    "instance_id": "test",
                }
            ),
            90,
        )
    return device, private_key, refresh_credential


async def seed_thread(harness: Harness, device: Device, owner: str = "42") -> ThreadBinding:
    binding = ThreadBinding(
        owner_user_id=owner,
        device_id=device.id,
        remote_thread_id=f"remote-{uuid.uuid4()}",
        status=ThreadBindingStatus.IDLE,
        cwd="/workspace",
        title="Managed thread",
        model="gpt-5.5",
        appserver_epoch=device.active_epoch or EPOCH,
        snapshot={"messages": []},
    )
    async with harness.database.session_factory() as db:
        db.add(binding)
        await db.commit()
    return binding


def csrf_headers(harness: Harness) -> dict[str, str]:
    return {
        "Origin": ORIGIN,
        harness.settings.csrf_header_name: harness.client.cookies.get(
            harness.settings.csrf_cookie_name
        ),
    }


def signed_token_request(
    device: Device,
    private_key: Ed25519PrivateKey,
) -> dict[str, str]:
    timestamp = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    nonce = (
        base64.urlsafe_b64encode(uuid.uuid4().bytes + uuid.uuid4().bytes[:8]).rstrip(b"=").decode()
    )
    proof = f"{device.id}\n{timestamp}\n{nonce}".encode()
    signature = base64.urlsafe_b64encode(private_key.sign(proof)).rstrip(b"=").decode()
    return {
        "device_id": str(device.id),
        "public_key": device.public_key,
        "timestamp": timestamp,
        "nonce": nonce,
        "signature": signature,
    }


async def test_device_connect_token_rotates_and_rejects_nonce_replay(
    harness: Harness,
) -> None:
    device, private_key, refresh_credential = await seed_device(harness)
    payload = signed_token_request(device, private_key)
    first = await harness.client.post(
        "/v1/device/connect-token",
        headers={"Authorization": f"Device {refresh_credential}"},
        json=payload,
    )
    assert first.status_code == 200
    first_token = first.json()["access_token"]

    replay = await harness.client.post(
        "/v1/device/connect-token",
        headers={"Authorization": f"Device {refresh_credential}"},
        json=payload,
    )
    assert replay.status_code == 409
    assert replay.json() == {"detail": "device_proof_replayed"}

    second = await harness.client.post(
        "/v1/device/connect-token",
        headers={"Authorization": f"Device {refresh_credential}"},
        json=signed_token_request(device, private_key),
    )
    assert second.status_code == 200
    second_token = second.json()["access_token"]
    assert second_token != first_token

    async with harness.database.session_factory() as db:
        assert (
            await harness.app.state.device_tokens.authenticate_access_token(db, first_token) is None
        )
    async with harness.database.session_factory() as db:
        authenticated = await harness.app.state.device_tokens.authenticate_access_token(
            db, second_token
        )
    assert authenticated is not None
    assert authenticated.id == device.id

    async with harness.database.session_factory() as db:
        stored = await db.get(Device, device.id)
    persisted = "|".join(str(value) for value in stored.__dict__.values())
    assert first_token not in persisted
    assert second_token not in persisted
    assert refresh_credential not in persisted


async def test_revoke_device_immediately_kicks_cross_instance_and_rejects_old_tokens(
    harness: Harness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert (await exchange(harness)).status_code == 201
    device, private_key, refresh_credential = await seed_device(harness, online=True)
    active_nonce = device.active_connection_nonce
    assert active_nonce is not None
    async with harness.database.session_factory() as db:
        db.add(
            DeviceConnection(
                device_id=device.id,
                connection_nonce=active_nonce,
                status=ConnectionStatus.CONNECTED,
                appserver_epoch=EPOCH,
                connected_at=datetime.now(UTC),
                last_heartbeat_at=datetime.now(UTC),
            )
        )
        await db.commit()

    issued = await harness.client.post(
        "/v1/device/connect-token",
        headers={"Authorization": f"Device {refresh_credential}"},
        json=signed_token_request(device, private_key),
    )
    assert issued.status_code == 200
    access_token = issued.json()["access_token"]

    published: list[tuple[str, dict[str, object], int]] = []
    original_publish = harness.store.publish

    async def record_publish(channel: str, value: str) -> int:
        subscribers = await original_publish(channel, value)
        if channel == f"device-dispatch:{device.id}":
            published.append((channel, json.loads(value), subscribers))
        return subscribers

    monkeypatch.setattr(harness.store, "publish", record_publish)

    state = harness.app.state
    other_instance = RealtimeService(
        harness.settings,
        harness.database,
        harness.store,
        state.device_tokens,
        state.session_service,
        state.events,
        state.commands,
        state.approvals,
        "other-instance",
    )
    socket = RecordingWebSocket()
    connection = ActiveDeviceSocket(
        websocket=socket,  # type: ignore[arg-type]
        device_id=device.id,
        owner_user_id="42",
        connection_nonce=active_nonce,
        epoch=EPOCH,
    )
    ready = asyncio.Event()
    dispatch = asyncio.create_task(other_instance._device_dispatch_loop(connection, ready))
    await asyncio.wait_for(ready.wait(), timeout=1)

    revoked = await harness.client.delete(
        f"/v1/devices/{device.id}",
        headers=csrf_headers(harness),
    )
    assert revoked.status_code == 204
    await asyncio.wait_for(dispatch, timeout=1)
    assert socket.closed == [(4001, "connection replaced")]
    assert published == [
        (
            f"device-dispatch:{device.id}",
            {"kind": "kick", "replaced_connection_nonces": [active_nonce]},
            1,
        )
    ]

    rejected_refresh = await harness.client.post(
        "/v1/device/connect-token",
        headers={"Authorization": f"Device {refresh_credential}"},
        json=signed_token_request(device, private_key),
    )
    assert rejected_refresh.status_code == 401
    assert rejected_refresh.json() == {"detail": "invalid_device_credential"}
    async with harness.database.session_factory() as db:
        assert await state.device_tokens.authenticate_access_token(db, access_token) is None
        stored_device = await db.get(Device, device.id)
        stored_connection = await db.scalar(
            select(DeviceConnection).where(DeviceConnection.device_id == device.id)
        )
    assert stored_device.status == DeviceStatus.REVOKED
    assert stored_device.active_epoch is None
    assert stored_device.active_connection_nonce is None
    assert stored_connection.status == ConnectionStatus.DISCONNECTED
    assert stored_connection.closed_reason == "device_revoked"


async def test_revoke_device_without_active_connection_is_idempotent_and_sends_no_kick(
    harness: Harness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert (await exchange(harness)).status_code == 201
    device, _, _ = await seed_device(harness, online=False)
    published_channels: list[str] = []
    original_publish = harness.store.publish

    async def record_publish(channel: str, value: str) -> int:
        published_channels.append(channel)
        return await original_publish(channel, value)

    monkeypatch.setattr(harness.store, "publish", record_publish)
    first = await harness.client.delete(f"/v1/devices/{device.id}", headers=csrf_headers(harness))
    second = await harness.client.delete(f"/v1/devices/{device.id}", headers=csrf_headers(harness))
    assert first.status_code == second.status_code == 204
    assert f"device-dispatch:{device.id}" not in published_channels

    async with harness.database.session_factory() as db:
        stored = await db.get(Device, device.id)
        revoke_audits = list(
            (
                await db.scalars(
                    select(AuditEvent).where(
                        AuditEvent.action == "device.revoke",
                        AuditEvent.resource_id == str(device.id),
                    )
                )
            ).all()
        )
    assert stored.status == DeviceStatus.REVOKED
    assert stored.credential_version == 2
    assert len(revoke_audits) == 1


async def test_device_connect_token_ip_limit_precedes_authentication_and_audit(
    harness: Harness,
) -> None:
    harness.settings.device_token_issue_limit = 1
    device, private_key, refresh_credential = await seed_device(harness)
    headers = {"Authorization": f"Device {refresh_credential}"}

    first = await harness.client.post(
        "/v1/device/connect-token",
        headers=headers,
        json=signed_token_request(device, private_key),
    )
    assert first.status_code == 200

    async with harness.database.session_factory() as db:
        audit_count_before = len(
            list(
                (
                    await db.scalars(
                        select(AuditEvent).where(AuditEvent.action == "device.connect_token.issue")
                    )
                ).all()
            )
        )

    async def unexpected_issue(*args: object, **kwargs: object) -> object:
        raise AssertionError("rate-limited request reached device authentication")

    harness.app.state.device_tokens.issue = unexpected_issue
    blocked = await harness.client.post(
        "/v1/device/connect-token",
        headers=headers,
        json=signed_token_request(device, private_key),
    )

    assert blocked.status_code == 429
    assert blocked.json() == {"detail": "device_connect_token_rate_limited"}
    assert blocked.headers["retry-after"] == str(harness.settings.rate_limit_window_seconds)
    async with harness.database.session_factory() as db:
        audit_count_after = len(
            list(
                (
                    await db.scalars(
                        select(AuditEvent).where(AuditEvent.action == "device.connect_token.issue")
                    )
                ).all()
            )
        )
    assert audit_count_before == audit_count_after == 1


async def test_cross_user_device_thread_and_revoke_access_are_hidden(
    harness: Harness,
) -> None:
    device, _, _ = await seed_device(harness, owner="owner-a")
    thread = await seed_thread(harness, device, owner="owner-a")
    now = datetime.now(UTC)
    approval = Approval(
        owner_user_id="owner-a",
        device_id=device.id,
        external_command_id="owner-a-approval",
        approval_kind="permission",
        summary="Owner A only",
        request={"private": "owner-a"},
        status=ApprovalStatus.PENDING,
        appserver_epoch=EPOCH,
        requested_at=now,
        expires_at=now + timedelta(seconds=120),
    )
    async with harness.database.session_factory() as db:
        db.add(approval)
        await db.commit()
    harness.sub2api.result = Sub2APIUser(user_id="owner-b", username="bob")
    assert (await exchange(harness, "another-valid-access-token")).status_code == 201

    devices = await harness.client.get("/v1/devices")
    assert devices.status_code == 200
    assert devices.json() == {"items": []}
    bootstrap = await harness.client.get("/v1/bootstrap")
    assert bootstrap.status_code == 200
    assert bootstrap.json()["devices"] == []
    assert bootstrap.json()["threads"] == []
    assert bootstrap.json()["approvals"] == []
    assert bootstrap.json()["models_by_device"] == {}
    assert (await harness.client.get("/v1/approvals")).json() == {"items": []}

    headers = csrf_headers(harness)
    hidden_reads = [
        await harness.client.get(f"/v1/devices/{device.id}/models"),
        await harness.client.get(f"/v1/devices/{device.id}/threads"),
        await harness.client.get(f"/v1/threads/{thread.id}"),
    ]
    hidden_mutations = [
        await harness.client.post(
            f"/v1/devices/{device.id}/models/sync",
            headers={**headers, "Idempotency-Key": "cross-owner-models"},
        ),
        await harness.client.post(
            f"/v1/devices/{device.id}/threads/sync",
            headers={**headers, "Idempotency-Key": "cross-owner-threads"},
        ),
        await harness.client.post(
            f"/v1/devices/{device.id}/threads",
            headers={**headers, "Idempotency-Key": "cross-owner-start"},
            json={"cwd": "/workspace"},
        ),
        await harness.client.post(
            f"/v1/threads/{thread.id}/sync",
            headers={**headers, "Idempotency-Key": "cross-owner-read"},
        ),
        await harness.client.post(
            f"/v1/threads/{thread.id}/resume",
            headers={**headers, "Idempotency-Key": "cross-owner-resume"},
        ),
        await harness.client.post(
            f"/v1/threads/{thread.id}/turns",
            headers={**headers, "Idempotency-Key": "cross-owner-turn"},
            json={"text": "private"},
        ),
        await harness.client.post(
            f"/v1/threads/{thread.id}/turns/current/steer",
            headers={**headers, "Idempotency-Key": "cross-owner-steer"},
            json={"text": "private"},
        ),
        await harness.client.post(
            f"/v1/threads/{thread.id}/turns/current/interrupt",
            headers={**headers, "Idempotency-Key": "cross-owner-interrupt"},
        ),
        await harness.client.post(
            f"/v1/approvals/{approval.id}/decision",
            headers=headers,
            json={"decision": "approve"},
        ),
        await harness.client.delete(f"/v1/devices/{device.id}", headers=headers),
    ]
    assert all(response.status_code == 404 for response in [*hidden_reads, *hidden_mutations])
    async with harness.database.session_factory() as db:
        assert list((await db.scalars(select(Command))).all()) == []
        stored = await db.get(Approval, approval.id)
    assert stored is not None and stored.status == ApprovalStatus.PENDING


async def test_sensitive_mutations_require_a_recent_control_session(
    harness: Harness,
) -> None:
    assert (await exchange(harness)).status_code == 201
    device, _, _ = await seed_device(harness, online=True)
    now = datetime.now(UTC)
    approval = Approval(
        owner_user_id="42",
        device_id=device.id,
        external_command_id="recent-auth-approval",
        approval_kind="permission",
        summary="Recent authentication required",
        request={},
        status=ApprovalStatus.PENDING,
        appserver_epoch=EPOCH,
        requested_at=now,
        expires_at=now + timedelta(seconds=120),
    )
    async with harness.database.session_factory() as db:
        session = await db.scalar(select(ControlSession))
        assert session is not None
        session.issued_at = now - timedelta(
            seconds=harness.settings.recent_auth_max_age_seconds + 1
        )
        db.add(approval)
        await db.commit()

    assert (await harness.client.get("/v1/devices")).status_code == 200
    requests = [
        await harness.client.post(
            "/v1/pairings/claim",
            headers=csrf_headers(harness),
            json={"code": "ABCD-EFGH-JKLM-NPQR"},
        ),
        await harness.client.delete(f"/v1/devices/{device.id}", headers=csrf_headers(harness)),
        await harness.client.post(
            f"/v1/approvals/{approval.id}/decision",
            headers=csrf_headers(harness),
            json={"decision": "approve"},
        ),
    ]
    for response in requests:
        assert response.status_code == 401
        assert response.json() == {"detail": "reauth_required"}
        assert response.headers["www-authenticate"] == "Sub2API"

    async with harness.database.session_factory() as db:
        stored_device = await db.get(Device, device.id)
        stored_approval = await db.get(Approval, approval.id)
    assert stored_device.status == DeviceStatus.ACTIVE
    assert stored_approval.status == ApprovalStatus.PENDING

    assert (await exchange(harness, "fresh-sub2api-access-token")).status_code == 201
    fresh_claim = await harness.client.post(
        "/v1/pairings/claim",
        headers=csrf_headers(harness),
        json={"code": "ABCD-EFGH-JKLM-NPQR"},
    )
    assert fresh_claim.status_code == 404
    assert fresh_claim.json() == {"detail": "pairing_not_found"}


async def test_command_idempotency_and_dangerous_field_rejection(harness: Harness) -> None:
    assert (await exchange(harness)).status_code == 201
    device, _, _ = await seed_device(harness, online=True)
    thread = await seed_thread(harness, device)
    headers = {**csrf_headers(harness), "Idempotency-Key": "same-turn-key"}

    first = await harness.client.post(
        f"/v1/threads/{thread.id}/turns",
        headers=headers,
        json={"text": "hello"},
    )
    second = await harness.client.post(
        f"/v1/threads/{thread.id}/turns",
        headers=headers,
        json={"text": "hello"},
    )
    assert first.status_code == 202
    assert second.status_code == 202
    assert first.json()["id"] == second.json()["id"]

    conflict = await harness.client.post(
        f"/v1/threads/{thread.id}/turns",
        headers=headers,
        json={"text": "different"},
    )
    assert conflict.status_code == 409
    assert conflict.json() == {"detail": "idempotency_conflict"}
    dangerous = await harness.client.post(
        f"/v1/threads/{thread.id}/turns",
        headers={**csrf_headers(harness), "Idempotency-Key": "dangerous"},
        json={"text": "hello", "method": "fs/read"},
    )
    assert dangerous.status_code == 422

    async with harness.database.session_factory() as db:
        commands = list((await db.scalars(select(Command))).all())
    assert len(commands) == 1
    assert commands[0].method == "turn/start"
    assert set(commands[0].payload) == {"threadId", "input"}


async def test_offline_device_rejects_commands_without_persisting_them(
    harness: Harness,
) -> None:
    assert (await exchange(harness)).status_code == 201
    device, _, _ = await seed_device(harness, online=False)
    thread = await seed_thread(harness, device)
    response = await harness.client.post(
        f"/v1/threads/{thread.id}/turns",
        headers={**csrf_headers(harness), "Idempotency-Key": "offline-turn"},
        json={"text": "hello"},
    )
    assert response.status_code == 409
    assert response.json() == {"detail": "device_offline"}
    async with harness.database.session_factory() as db:
        commands = list((await db.scalars(select(Command))).all())
    assert commands == []


async def test_model_catalog_is_user_scoped_and_available_offline(harness: Harness) -> None:
    assert (await exchange(harness)).status_code == 201
    device, _, _ = await seed_device(harness, online=False)
    async with harness.database.session_factory() as db:
        stored = await db.get(Device, device.id)
        stored.model_catalog = [
            {
                "id": "gpt-5.5",
                "display_name": "GPT-5.5",
                "description": "Verified while online",
            }
        ]
        stored.model_catalog_updated_at = datetime.now(UTC)
        await db.commit()

    response = await harness.client.get(f"/v1/devices/{device.id}/models")
    assert response.status_code == 200
    assert response.json() == {
        "items": [
            {
                "id": "gpt-5.5",
                "display_name": "GPT-5.5",
                "description": "Verified while online",
            }
        ]
    }
    async with harness.database.session_factory() as db:
        commands = list((await db.scalars(select(Command))).all())
    assert commands == []


async def test_command_deadline_transitions_to_expired(harness: Harness) -> None:
    device, _, _ = await seed_device(harness, online=True)
    now = datetime.now(UTC)
    command = Command(
        owner_user_id="42",
        device_id=device.id,
        idempotency_key="expired-command",
        request_hash="0" * 64,
        method="model/list",
        payload={"limit": 100},
        status=CommandStatus.ACKNOWLEDGED,
        appserver_epoch=EPOCH,
        created_at=now - timedelta(seconds=31),
        expires_at=now - timedelta(seconds=1),
    )
    async with harness.database.session_factory() as db:
        db.add(command)
        await db.commit()
    async with harness.database.session_factory() as db:
        assert await harness.app.state.commands.expire_due(db, now=now) == 1
    async with harness.database.session_factory() as db:
        stored = await db.get(Command, command.id)
    assert stored.status == CommandStatus.EXPIRED
    assert stored.error_code == "expired"


async def test_device_turn_events_are_normalized_for_browser_consumers(
    harness: Harness,
) -> None:
    device, _, _ = await seed_device(harness, online=True)
    thread = await seed_thread(harness, device)
    async with harness.database.session_factory() as db:
        stored = await db.get(ThreadBinding, thread.id)
        stored.status = ThreadBindingStatus.RUNNING
        stored.active_turn_id = "turn-1"
        await db.commit()

    connection = ActiveDeviceSocket(
        websocket=None,  # type: ignore[arg-type]
        device_id=device.id,
        owner_user_id="42",
        connection_nonce="test-connection",
        epoch=EPOCH,
    )
    delta = ControlEnvelope.model_validate(
        {
            "version": 1,
            "id": str(uuid.uuid4()),
            "device_id": str(device.id),
            "epoch": EPOCH,
            "seq": 1,
            "ack": 0,
            "type": "event",
            "sent_at": datetime.now(UTC),
            "payload": {
                "method": "item/agentMessage/delta",
                "params": {
                    "threadId": thread.remote_thread_id,
                    "itemId": "assistant-1",
                    "delta": "Hello",
                },
            },
        }
    )
    await harness.app.state.realtime._apply_device_event(connection, delta)

    completed = ControlEnvelope.model_validate(
        {
            "version": 1,
            "id": str(uuid.uuid4()),
            "device_id": str(device.id),
            "epoch": EPOCH,
            "seq": 2,
            "ack": 0,
            "type": "event",
            "sent_at": datetime.now(UTC),
            "payload": {
                "method": "turn/completed",
                "params": {
                    "threadId": thread.remote_thread_id,
                    "turnId": "turn-1",
                },
            },
        }
    )
    await harness.app.state.realtime._apply_device_event(connection, completed)

    async with harness.database.session_factory() as db:
        events = await harness.app.state.events.catch_up(db, "42", 0)
        stored = await db.get(ThreadBinding, thread.id)
    assert [(event.type, event.data["thread_id"]) for event in events] == [
        ("turn.delta", str(thread.id)),
        ("turn.completed", str(thread.id)),
    ]
    assert events[0].data == {
        "thread_id": str(thread.id),
        "device_id": str(device.id),
        "message_id": "assistant-1",
        "delta": "Hello",
    }
    assert events[1].data["turn_id"] == "turn-1"
    assert stored.status == ThreadBindingStatus.IDLE
    assert stored.active_turn_id is None
    assert stored.snapshot["messages"][0]["text"] == "Hello"


async def test_thread_list_ack_projects_only_managed_workspace_threads(
    harness: Harness,
) -> None:
    device, _, _ = await seed_device(harness, online=True)
    command = Command(
        owner_user_id="42",
        device_id=device.id,
        idempotency_key="thread-list-projection",
        request_hash=canonical_request_hash("thread/list", {"limit": 100}),
        method="thread/list",
        payload={"limit": 100},
        status=CommandStatus.DISPATCHED,
        appserver_epoch=EPOCH,
        created_at=datetime.now(UTC),
        expires_at=datetime.now(UTC) + timedelta(seconds=30),
    )
    async with harness.database.session_factory() as db:
        db.add(command)
        await db.commit()

    connection = ActiveDeviceSocket(
        websocket=None,  # type: ignore[arg-type]
        device_id=device.id,
        owner_user_id="42",
        connection_nonce="test-connection",
        epoch=EPOCH,
    )
    acknowledgement = ControlEnvelope.model_validate(
        {
            "version": 1,
            "id": str(uuid.uuid4()),
            "device_id": str(device.id),
            "epoch": EPOCH,
            "seq": 1,
            "ack": 0,
            "type": "command_ack",
            "sent_at": datetime.now(UTC),
            "payload": {
                "command_id": str(command.id),
                "state": "completed",
                "result": {
                    "data": [
                        {
                            "id": "managed-thread",
                            "cwd": "/workspace/project",
                            "name": None,
                            "preview": "Managed preview",
                            "status": {"type": "active", "activeFlags": []},
                            "createdAt": 1_700_000_000,
                            "updatedAt": 1_700_000_100,
                        },
                        {
                            "id": "outside-thread",
                            "cwd": "/private/project",
                            "preview": "Must not project",
                            "status": {"type": "idle"},
                            "createdAt": 1_700_000_000,
                            "updatedAt": 1_700_000_100,
                        },
                    ]
                },
            },
        }
    )
    await harness.app.state.realtime._apply_command_ack(connection, acknowledgement)

    async with harness.database.session_factory() as db:
        bindings = list((await db.scalars(select(ThreadBinding))).all())
        stored_command = await db.get(Command, command.id)
        events = await harness.app.state.events.catch_up(db, "42", 0)
    assert stored_command.status == CommandStatus.SUCCEEDED
    assert len(bindings) == 1
    assert bindings[0].remote_thread_id == "managed-thread"
    assert bindings[0].title == "Managed preview"
    assert bindings[0].status == ThreadBindingStatus.RUNNING
    assert [event.type for event in events] == ["command.updated", "thread.updated"]
    assert set(events[1].data) == {
        "id",
        "thread_id",
        "device_id",
        "title",
        "cwd",
        "model",
        "updated_at",
        "status",
    }
    updated_at = bindings[0].updated_at
    if updated_at.tzinfo is None:
        updated_at = updated_at.replace(tzinfo=UTC)
    assert events[1].data == {
        "id": str(bindings[0].id),
        "thread_id": str(bindings[0].id),
        "device_id": str(device.id),
        "title": "Managed preview",
        "cwd": "/workspace/project",
        "model": "",
        "updated_at": updated_at.isoformat().replace("+00:00", "Z"),
        "status": "running",
    }


async def test_nested_projected_results_bind_thread_and_turn_ids(harness: Harness) -> None:
    device, _, _ = await seed_device(harness, online=True)
    binding = ThreadBinding(
        owner_user_id="42",
        device_id=device.id,
        remote_thread_id=None,
        status=ThreadBindingStatus.RUNNING,
        cwd="/workspace",
        title="New managed thread",
        model="gpt-5.5",
        appserver_epoch=EPOCH,
        snapshot={"messages": []},
    )
    start_command = Command(
        owner_user_id="42",
        device_id=device.id,
        idempotency_key="nested-thread-result",
        request_hash="0" * 64,
        method="thread/start",
        payload={"cwd": "/workspace"},
        status=CommandStatus.SUCCEEDED,
        appserver_epoch=EPOCH,
    )
    start_ack = CommandAckPayload(
        command_id=uuid.uuid4(),
        state="completed",
        result={"thread": {"id": "remote-projected-thread", "cwd": "/workspace"}},
    )

    harness.app.state.realtime._apply_command_to_binding(
        binding,
        start_command,
        start_ack,
        EPOCH,
    )
    assert binding.remote_thread_id == "remote-projected-thread"
    assert binding.status == ThreadBindingStatus.IDLE

    turn_command = Command(
        owner_user_id="42",
        device_id=device.id,
        idempotency_key="nested-turn-result",
        request_hash="1" * 64,
        method="turn/start",
        payload={"threadId": binding.remote_thread_id, "input": []},
        status=CommandStatus.SUCCEEDED,
        appserver_epoch=EPOCH,
    )
    turn_ack = CommandAckPayload(
        command_id=uuid.uuid4(),
        state="completed",
        result={"turn": {"id": "projected-turn", "status": "inProgress"}},
    )

    harness.app.state.realtime._apply_command_to_binding(
        binding,
        turn_command,
        turn_ack,
        EPOCH,
    )
    assert binding.active_turn_id == "projected-turn"
    assert binding.status == ThreadBindingStatus.RUNNING


async def test_stale_epoch_and_timeout_approvals_default_deny(harness: Harness) -> None:
    assert (await exchange(harness)).status_code == 201
    device, _, _ = await seed_device(harness, online=True)
    now = datetime.now(UTC)
    stale = Approval(
        owner_user_id="42",
        device_id=device.id,
        external_command_id="appserver:stale",
        approval_kind="command",
        summary="Run command",
        request={"command": "pwd"},
        status=ApprovalStatus.PENDING,
        appserver_epoch="older-epoch-0123456789abcdef",
        requested_at=now,
        expires_at=now + timedelta(seconds=120),
    )
    timed_out = Approval(
        owner_user_id="42",
        device_id=device.id,
        external_command_id="appserver:timeout",
        approval_kind="permission",
        summary="Permission",
        request={"reason": "test"},
        status=ApprovalStatus.PENDING,
        appserver_epoch=EPOCH,
        requested_at=now - timedelta(seconds=121),
        expires_at=now - timedelta(seconds=1),
    )
    async with harness.database.session_factory() as db:
        db.add_all([stale, timed_out])
        await db.commit()

    decision = await harness.client.post(
        f"/v1/approvals/{stale.id}/decision",
        headers=csrf_headers(harness),
        json={"decision": "approve"},
    )
    assert decision.status_code == 409
    assert decision.json() == {"detail": "approval_stale_epoch"}
    async with harness.database.session_factory() as db:
        assert await harness.app.state.approvals.expire_due(db, now=now) == 1
    async with harness.database.session_factory() as db:
        stale_row = await db.get(Approval, stale.id)
        timeout_row = await db.get(Approval, timed_out.id)
    assert stale_row.status == ApprovalStatus.DENIED
    assert stale_row.decision_reason == "stale_epoch_default_deny"
    assert timeout_row.status == ApprovalStatus.DENIED
    assert timeout_row.decision_reason == "timeout_default_deny"


async def test_browser_event_catchup_is_user_scoped(harness: Harness) -> None:
    device_a, _, _ = await seed_device(harness, owner="owner-a")
    device_b, _, _ = await seed_device(harness, owner="owner-b")
    async with harness.database.session_factory() as db:
        await harness.app.state.events.emit(
            db,
            owner_user_id="owner-a",
            device_id=device_a.id,
            event_type="device.updated",
            data={"id": str(device_a.id), "owner": "a"},
        )
    async with harness.database.session_factory() as db:
        await harness.app.state.events.emit(
            db,
            owner_user_id="owner-b",
            device_id=device_b.id,
            event_type="device.updated",
            data={"id": str(device_b.id), "owner": "b"},
        )
    async with harness.database.session_factory() as db:
        events_a = await harness.app.state.events.catch_up(db, "owner-a", 0)
    async with harness.database.session_factory() as db:
        events_b = await harness.app.state.events.catch_up(db, "owner-b", 0)
    assert [event.data["owner"] for event in events_a] == ["a"]
    assert [event.data["owner"] for event in events_b] == ["b"]


async def test_cache_gets_never_enqueue_and_all_sync_posts_are_idempotent(
    harness: Harness,
) -> None:
    assert (await exchange(harness)).status_code == 201
    device, _, _ = await seed_device(harness, online=True)
    thread = await seed_thread(harness, device)

    assert (await harness.client.get(f"/v1/devices/{device.id}/models")).status_code == 200
    assert (await harness.client.get(f"/v1/devices/{device.id}/threads")).status_code == 200
    detail = await harness.client.get(f"/v1/threads/{thread.id}")
    assert detail.status_code == 200
    assert set(detail.json()) == {"event_cursor", "thread"}
    async with harness.database.session_factory() as db:
        assert list((await db.scalars(select(Command))).all()) == []

    assert (await harness.client.post(f"/v1/devices/{device.id}/models/sync")).status_code == 403
    headers = csrf_headers(harness)
    contracts = [
        (f"/v1/devices/{device.id}/models/sync", "sync-models"),
        (f"/v1/devices/{device.id}/threads/sync", "sync-threads"),
        (f"/v1/threads/{thread.id}/sync", "sync-thread-detail"),
    ]
    command_ids: list[str] = []
    for path, key in contracts:
        operation_headers = {**headers, "Idempotency-Key": key}
        first = await harness.client.post(path, headers=operation_headers)
        repeated = await harness.client.post(path, headers=operation_headers)
        assert first.status_code == repeated.status_code == 202
        assert first.json()["id"] == repeated.json()["id"]
        command_ids.append(first.json()["id"])
    assert len(set(command_ids)) == 3

    async with harness.database.session_factory() as db:
        stored = await db.get(ThreadBinding, thread.id)
        assert stored is not None
        stored.remote_thread_id = "changed-remote-thread-id"
        await db.commit()
    conflicting = await harness.client.post(
        f"/v1/threads/{thread.id}/sync",
        headers={**headers, "Idempotency-Key": "sync-thread-detail"},
    )
    assert conflicting.status_code == 409
    assert conflicting.json()["detail"] == "idempotency_conflict"

    async with harness.database.session_factory() as db:
        commands = list((await db.scalars(select(Command).order_by(Command.created_at))).all())
    assert len(commands) == 3
    assert [command.method for command in commands] == [
        "model/list",
        "thread/list",
        "thread/read",
    ]
