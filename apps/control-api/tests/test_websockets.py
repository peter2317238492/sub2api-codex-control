from __future__ import annotations

import asyncio
import base64
import time
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from conftest import ORIGIN, FakeSub2API
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import FastAPI
from sqlalchemy import select
from starlette.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

import control_api.realtime as realtime_module
from control_api.app import create_app
from control_api.commands import canonical_request_hash
from control_api.config import Settings
from control_api.db import Base, Database
from control_api.events import MAX_EVENT_CURSOR
from control_api.models import (
    Command,
    CommandStatus,
    ControlSession,
    Device,
    DeviceOutbox,
    DeviceStatus,
)
from control_api.realtime import (
    BrowserConnectionLimitExceeded,
    BrowserSessionGate,
    BrowserSocketClose,
    RealtimeService,
)
from control_api.security import SessionCredentialProtector, TokenDigester
from control_api.services import RequestMetadata, SessionService
from control_api.storage import InMemoryKeyValueStore
from control_api.sub2api import (
    RevokedSub2APIToken,
    Sub2APIRequestIdentity,
    Sub2APIUnavailable,
    Sub2APIUser,
)

EPOCH = "epoch-0123456789abcdef0123456789"
NEXT_EPOCH = "epoch-fedcba9876543210fedcba9876"
SCHEMA_DIGEST = "511c1b3ca038a80740a5a41ca10a7f925c0f744e582fb9aaa03cc46c6e98b80b"
CAPABILITIES = [
    "model/list",
    "thread/start",
    "thread/list",
    "thread/read",
    "thread/resume",
    "turn/start",
    "turn/steer",
    "turn/interrupt",
]


@dataclass
class WebSocketHarness:
    client: TestClient
    app: FastAPI
    database: Database
    settings: Settings
    store: InMemoryKeyValueStore
    sub2api: FakeSub2API


class RecordingBrowserWebSocket:
    def __init__(self) -> None:
        self.closed = asyncio.Event()
        self.close_code: int | None = None
        self.close_reason: str | None = None
        self.sent_text: list[str] = []

    async def send_text(self, value: str) -> None:
        self.sent_text.append(value)

    async def close(self, code: int, reason: str) -> None:
        self.close_code = code
        self.close_reason = reason
        self.closed.set()


def new_realtime_instance(
    websocket_harness: WebSocketHarness,
    instance_id: str,
) -> RealtimeService:
    state = websocket_harness.app.state
    return RealtimeService(
        websocket_harness.settings,
        websocket_harness.database,
        websocket_harness.store,
        state.device_tokens,
        state.session_service,
        state.events,
        state.commands,
        state.approvals,
        instance_id,
    )


async def monitor_browser_session_and_apply_close(
    realtime: RealtimeService,
    socket: RecordingBrowserWebSocket,
    session_id: uuid.UUID,
    raw_token: str,
    ready: asyncio.Event,
    session_gate: BrowserSessionGate | None = None,
) -> None:
    gate = session_gate or BrowserSessionGate()
    try:
        await realtime._monitor_browser_session(session_id, raw_token, ready, gate)
    except BrowserSocketClose as exc:
        await socket.close(exc.code, exc.reason)


@pytest.fixture
def websocket_harness(tmp_path: Path):
    settings = Settings(
        environment="test",
        database_url=f"sqlite+aiosqlite:///{tmp_path / 'websocket.db'}",
        redis_url="memory://",
        redis_prefix="websocket-test:",
        session_hmac_secret="a-test-secret-that-is-long-and-never-production",
        cookie_secure=False,
        allowed_origins_csv=ORIGIN,
        device_heartbeat_timeout_seconds=15,
    )
    database = Database(settings)
    store = InMemoryKeyValueStore(settings.redis_prefix)
    sub2api = FakeSub2API()
    app = create_app(
        settings,
        database=database,
        store=store,
        sub2api_client=sub2api,
    )

    async def setup() -> None:
        async with database.engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)

    async def cleanup() -> None:
        async with database.engine.begin() as connection:
            await connection.run_sync(Base.metadata.drop_all)
        await store.close()
        await database.close()

    with TestClient(app, base_url=ORIGIN) as client:
        client.portal.call(setup)
        yield WebSocketHarness(client, app, database, settings, store, sub2api)
        client.portal.call(cleanup)


def new_identity() -> tuple[Ed25519PrivateKey, str]:
    private_key = Ed25519PrivateKey.generate()
    raw = private_key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    return private_key, base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def signed_request(
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


def envelope(
    device_id: uuid.UUID,
    sequence: int,
    ack: int,
    envelope_type: str,
    payload: dict[str, object],
    *,
    epoch: str = EPOCH,
) -> dict[str, object]:
    return {
        "version": 1,
        "id": str(uuid.uuid4()),
        "device_id": str(device_id),
        "epoch": epoch,
        "seq": sequence,
        "ack": ack,
        "type": envelope_type,
        "sent_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "payload": payload,
    }


def test_device_websocket_replay_ack_and_gap_close(
    websocket_harness: WebSocketHarness,
) -> None:
    private_key, public_key = new_identity()
    refresh_credential = f"dcr_{uuid.uuid4().hex}{uuid.uuid4().hex}"
    digest = TokenDigester(websocket_harness.settings.session_hmac_secret.get_secret_value())
    device = Device(
        owner_user_id="42",
        name="Connector",
        public_key=public_key,
        refresh_credential_hash=digest.digest("device-refresh", refresh_credential),
        credential_version=1,
        status=DeviceStatus.ACTIVE,
        device_metadata={},
        workspace_roots=["/workspace"],
    )
    command = Command(
        owner_user_id="42",
        device_id=device.id,
        idempotency_key="model-list-websocket",
        request_hash=canonical_request_hash("model/list", {"limit": 100}),
        method="model/list",
        payload={"limit": 100},
        status=CommandStatus.QUEUED,
        appserver_epoch=EPOCH,
        expires_at=datetime.now(UTC) + timedelta(seconds=30),
    )

    async def seed() -> None:
        async with websocket_harness.database.session_factory() as db:
            db.add(device)
            await db.flush()
            command.device_id = device.id
            db.add(command)
            await db.commit()

    websocket_harness.client.portal.call(seed)
    token = websocket_harness.client.post(
        "/v1/device/connect-token",
        headers={"Authorization": f"Device {refresh_credential}"},
        json=signed_request(device, private_key),
    )
    assert token.status_code == 200
    access_token = token.json()["access_token"]

    with websocket_harness.client.websocket_connect(
        "/codex-ws/device",
        headers={"Authorization": f"Bearer {access_token}"},
    ) as premature:
        premature.send_json(envelope(device.id, 1, 0, "heartbeat", {"status": "ok"}))
        with pytest.raises(WebSocketDisconnect) as closed:
            premature.receive_json()
        assert closed.value.code == 4400

    with websocket_harness.client.websocket_connect(
        "/codex-ws/device",
        headers={"Authorization": f"Bearer {access_token}"},
    ) as socket:
        socket.send_json(
            envelope(
                device.id,
                0,
                0,
                "hello",
                {
                    "connector_version": "0.1.2",
                    "codex_version": "0.147.0",
                    "schema_digest": SCHEMA_DIGEST,
                    "public_key": public_key,
                    "capabilities": CAPABILITIES,
                    "workspace_roots": ["/workspace"],
                    "resumed_from_seq": 0,
                },
            )
        )
        hello_ack = socket.receive_json()
        assert hello_ack["type"] == "hello_ack"
        assert hello_ack["seq"] == 0
        assert hello_ack["ack"] == 0
        assert {
            key: hello_ack["payload"][key]
            for key in (
                "protocol_version",
                "device_id",
                "epoch",
                "schema_digest",
                "received_seq",
            )
        } == {
            "protocol_version": 1,
            "device_id": str(device.id),
            "epoch": EPOCH,
            "schema_digest": SCHEMA_DIGEST,
            "received_seq": 0,
        }

        command_frame = socket.receive_json()
        assert command_frame["type"] == "command"
        assert command_frame["seq"] == 1
        assert command_frame["payload"]["method"] == "model/list"

        socket.send_json(
            envelope(
                device.id,
                1,
                1,
                "command_ack",
                {
                    "command_id": str(command.id),
                    "state": "completed",
                    "result": {
                        "models": [
                            {
                                "id": "gpt-5.5",
                                "displayName": "GPT-5.5",
                                "description": "Pinned model",
                            }
                        ]
                    },
                },
            )
        )
        command_ack = socket.receive_json()
        assert command_ack["type"] == "heartbeat_ack"
        assert command_ack["seq"] == 2

        async def verify_command() -> tuple[CommandStatus, list[dict[str, object]]]:
            async with websocket_harness.database.session_factory() as db:
                stored_command = await db.get(Command, command.id)
                stored_device = await db.get(Device, device.id)
                return stored_command.status, stored_device.model_catalog

        command_status, model_catalog = websocket_harness.client.portal.call(verify_command)
        assert command_status == CommandStatus.SUCCEEDED
        assert model_catalog == [
            {
                "id": "gpt-5.5",
                "display_name": "GPT-5.5",
                "description": "Pinned model",
            }
        ]

        heartbeat = envelope(device.id, 2, 2, "heartbeat", {"status": "ok"})
        socket.send_json(heartbeat)
        heartbeat_ack = socket.receive_json()
        assert heartbeat_ack["type"] == "heartbeat_ack"
        assert heartbeat_ack["seq"] == 3
        assert heartbeat_ack["ack"] == 2

        duplicate = dict(heartbeat)
        duplicate["id"] = str(uuid.uuid4())
        duplicate["ack"] = 3
        socket.send_json(duplicate)
        duplicate_ack = socket.receive_json()
        assert duplicate_ack["seq"] == 3
        assert duplicate_ack["ack"] == 2

        async def verify_duplicate_ack_reuse() -> tuple[int, list[tuple[int, bool]]]:
            async with websocket_harness.database.session_factory() as db:
                stored_device = await db.get(Device, device.id)
                rows = list(
                    (
                        await db.scalars(
                            select(DeviceOutbox)
                            .where(DeviceOutbox.device_id == device.id)
                            .order_by(DeviceOutbox.sequence)
                        )
                    ).all()
                )
                return stored_device.last_server_sequence, [
                    (row.sequence, row.acked_at is not None) for row in rows
                ]

        server_sequence, retained_rows = websocket_harness.client.portal.call(
            verify_duplicate_ack_reuse
        )
        assert server_sequence == 3
        assert retained_rows == [(3, True)]

        socket.send_json(envelope(device.id, 4, 3, "heartbeat", {"status": "ok"}))
        with pytest.raises(WebSocketDisconnect) as closed:
            socket.receive_json()
        assert closed.value.code == 4400

    with websocket_harness.client.websocket_connect(
        "/codex-ws/device",
        headers={"Authorization": f"Bearer {access_token}"},
    ) as reconnected:
        reconnected.send_json(
            envelope(
                device.id,
                0,
                3,
                "hello",
                {
                    "connector_version": "0.1.2",
                    "codex_version": "0.147.0",
                    "schema_digest": SCHEMA_DIGEST,
                    "public_key": public_key,
                    "capabilities": CAPABILITIES,
                    "workspace_roots": ["/workspace"],
                    "resumed_from_seq": 2,
                },
                epoch=NEXT_EPOCH,
            )
        )
        hello_after_replay = reconnected.receive_json()
        assert hello_after_replay["type"] == "hello_ack"
        assert hello_after_replay["seq"] == 0
        assert hello_after_replay["ack"] == 2
        assert hello_after_replay["epoch"] == NEXT_EPOCH
        reconnected.send_json(envelope(device.id, 3, 3, "heartbeat", {"status": "ok"}))
        replay_ack = reconnected.receive_json()
        assert replay_ack["type"] == "heartbeat_ack"
        assert replay_ack["seq"] == 4
        assert replay_ack["ack"] == 3
        assert replay_ack["epoch"] == NEXT_EPOCH
        reconnected.send_json(
            envelope(
                device.id,
                4,
                4,
                "heartbeat",
                {"status": "ok"},
                epoch=NEXT_EPOCH,
            )
        )
        current_ack = reconnected.receive_json()
        assert current_ack["seq"] == 5
        assert current_ack["ack"] == 4
        reconnected.close(1000)

    metrics = websocket_harness.app.state.operational_metrics.render()
    assert (
        'codex_control_websocket_events_total{event="accepted",kind="device",reason="accepted"} 2.0'
    ) in metrics
    assert (
        'codex_control_websocket_events_total{event="rejected",kind="device",reason="protocol_error"}'
        " 1.0"
    ) in metrics
    assert (
        'codex_control_command_transitions_total{from_status="dispatched",to_status="succeeded"}'
        " 1.0"
    ) in metrics


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("workspace_roots", ["/different-scope"]),
        ("schema_digest", "b" * 64),
        ("capabilities", CAPABILITIES[:-1]),
        ("connector_version", "0.2.0"),
        ("codex_version", "0.145.0"),
    ],
)
def test_device_websocket_rejects_hello_contract_drift(
    websocket_harness: WebSocketHarness,
    field: str,
    value: object,
) -> None:
    private_key, public_key = new_identity()
    refresh_credential = f"dcr_{uuid.uuid4().hex}{uuid.uuid4().hex}"
    digest = TokenDigester(websocket_harness.settings.session_hmac_secret.get_secret_value())
    device = Device(
        owner_user_id="42",
        name="Connector",
        public_key=public_key,
        refresh_credential_hash=digest.digest("device-refresh", refresh_credential),
        credential_version=1,
        status=DeviceStatus.ACTIVE,
        device_metadata={},
        workspace_roots=["/workspace"],
    )

    async def seed() -> None:
        async with websocket_harness.database.session_factory() as db:
            db.add(device)
            await db.commit()

    websocket_harness.client.portal.call(seed)
    token = websocket_harness.client.post(
        "/v1/device/connect-token",
        headers={"Authorization": f"Device {refresh_credential}"},
        json=signed_request(device, private_key),
    )
    assert token.status_code == 200

    with websocket_harness.client.websocket_connect(
        "/codex-ws/device",
        headers={"Authorization": f"Bearer {token.json()['access_token']}"},
    ) as socket:
        hello_payload: dict[str, object] = {
            "connector_version": "0.1.2",
            "codex_version": "0.147.0",
            "schema_digest": SCHEMA_DIGEST,
            "public_key": public_key,
            "capabilities": CAPABILITIES,
            "workspace_roots": ["/workspace"],
            "resumed_from_seq": 0,
        }
        hello_payload[field] = value
        socket.send_json(
            envelope(
                device.id,
                0,
                0,
                "hello",
                hello_payload,
            )
        )
        with pytest.raises(WebSocketDisconnect) as closed:
            socket.receive_json()
        assert closed.value.code == 4400


def test_browser_websocket_catchup_is_scoped_to_session_user(
    websocket_harness: WebSocketHarness,
) -> None:
    websocket_harness.sub2api.result = Sub2APIUser(user_id="owner-a", username="alice")
    exchange_a = websocket_harness.client.post(
        "/v1/session/exchange",
        headers={"Origin": ORIGIN},
        json={"access_token": "owner-a-access-token"},
    )
    assert exchange_a.status_code == 201

    async def seed_events() -> None:
        async with websocket_harness.database.session_factory() as db:
            device_a = Device(
                owner_user_id="owner-a",
                name="A",
                public_key=base64.urlsafe_b64encode(b"a" * 32).rstrip(b"=").decode(),
                status=DeviceStatus.ACTIVE,
                device_metadata={},
                workspace_roots=[],
            )
            device_b = Device(
                owner_user_id="owner-b",
                name="B",
                public_key=base64.urlsafe_b64encode(b"b" * 32).rstrip(b"=").decode(),
                status=DeviceStatus.ACTIVE,
                device_metadata={},
                workspace_roots=[],
            )
            db.add_all([device_a, device_b])
            await db.commit()
        async with websocket_harness.database.session_factory() as db:
            await websocket_harness.app.state.events.emit(
                db,
                owner_user_id="owner-a",
                device_id=device_a.id,
                event_type="device.updated",
                data={"owner": "a"},
            )
        async with websocket_harness.database.session_factory() as db:
            await websocket_harness.app.state.events.emit(
                db,
                owner_user_id="owner-b",
                device_id=device_b.id,
                event_type="device.updated",
                data={"owner": "b"},
            )

    websocket_harness.client.portal.call(seed_events)
    cookie_a = websocket_harness.client.cookies.get(websocket_harness.settings.cookie_name)
    with websocket_harness.client.websocket_connect(
        "/codex-ws/browser?cursor=0",
        headers={
            "Origin": ORIGIN,
            "Cookie": f"{websocket_harness.settings.cookie_name}={cookie_a}",
        },
    ) as browser_a:
        assert browser_a.receive_json()["data"]["owner"] == "a"
        browser_a.send_text("close")
        with pytest.raises(WebSocketDisconnect):
            browser_a.receive_json()

    websocket_harness.sub2api.result = Sub2APIUser(user_id="owner-b", username="bob")
    exchange_b = websocket_harness.client.post(
        "/v1/session/exchange",
        headers={"Origin": ORIGIN},
        json={"access_token": "owner-b-access-token"},
    )
    assert exchange_b.status_code == 201
    cookie_b = websocket_harness.client.cookies.get(websocket_harness.settings.cookie_name)
    with websocket_harness.client.websocket_connect(
        "/codex-ws/browser?cursor=0",
        headers={
            "Origin": ORIGIN,
            "Cookie": f"{websocket_harness.settings.cookie_name}={cookie_b}",
        },
    ) as browser_b:
        assert browser_b.receive_json()["data"]["owner"] == "b"
        browser_b.send_text("close")
        with pytest.raises(WebSocketDisconnect):
            browser_b.receive_json()


def test_browser_connection_leases_enforce_cross_instance_session_cap(
    websocket_harness: WebSocketHarness,
) -> None:
    websocket_harness.settings.browser_max_connections_per_session = 2
    websocket_harness.settings.browser_max_connections_per_user = 4
    first_instance = websocket_harness.app.state.realtime
    second_instance = new_realtime_instance(websocket_harness, "second-instance")

    async def scenario() -> None:
        session_id = uuid.uuid4()
        first = await first_instance._acquire_browser_connection_lease(session_id, "owner")
        second = await second_instance._acquire_browser_connection_lease(session_id, "owner")
        with pytest.raises(BrowserConnectionLimitExceeded):
            await second_instance._acquire_browser_connection_lease(session_id, "owner")

        await first_instance._release_browser_connection_lease(first)
        replacement = await second_instance._acquire_browser_connection_lease(
            session_id,
            "owner",
        )
        # A delayed cleanup from the former owner must not delete the replacement.
        await first_instance._release_browser_connection_lease(first)
        with pytest.raises(BrowserConnectionLimitExceeded):
            await first_instance._acquire_browser_connection_lease(session_id, "owner")

        await second_instance._release_browser_connection_lease(second)
        await second_instance._release_browser_connection_lease(replacement)

    websocket_harness.client.portal.call(scenario)


def test_browser_connection_leases_enforce_user_cap_and_rollback_session_slot(
    websocket_harness: WebSocketHarness,
) -> None:
    websocket_harness.settings.browser_max_connections_per_session = 2
    websocket_harness.settings.browser_max_connections_per_user = 3
    first_instance = websocket_harness.app.state.realtime
    second_instance = new_realtime_instance(websocket_harness, "second-instance")

    async def scenario() -> None:
        first_session = uuid.uuid4()
        second_session = uuid.uuid4()
        first = await first_instance._acquire_browser_connection_lease(
            first_session,
            "shared-owner",
        )
        second = await second_instance._acquire_browser_connection_lease(
            first_session,
            "shared-owner",
        )
        third = await first_instance._acquire_browser_connection_lease(
            second_session,
            "shared-owner",
        )
        with pytest.raises(BrowserConnectionLimitExceeded):
            await second_instance._acquire_browser_connection_lease(
                second_session,
                "shared-owner",
            )

        # The failed user-scope admission must have released its session slot.
        await first_instance._release_browser_connection_lease(first)
        replacement = await second_instance._acquire_browser_connection_lease(
            second_session,
            "shared-owner",
        )
        independent = await first_instance._acquire_browser_connection_lease(
            uuid.uuid4(),
            "other-owner",
        )

        for lease in (second, third, replacement, independent):
            await second_instance._release_browser_connection_lease(lease)

    websocket_harness.client.portal.call(scenario)


def test_browser_connection_lease_expiry_recovers_capacity_and_cleanup_is_owner_safe(
    websocket_harness: WebSocketHarness,
) -> None:
    websocket_harness.settings.browser_max_connections_per_session = 1
    websocket_harness.settings.browser_max_connections_per_user = 1
    websocket_harness.settings.browser_connection_lease_ttl_seconds = 1
    realtime = websocket_harness.app.state.realtime

    async def scenario() -> None:
        session_id = uuid.uuid4()
        owner = "owner-identifier-must-not-appear-in-redis"
        stale = await realtime._acquire_browser_connection_lease(session_id, owner)
        assert owner not in stale.user_slot.key
        assert owner not in stale.user_slot.value

        await asyncio.sleep(1.05)
        replacement = await realtime._acquire_browser_connection_lease(session_id, owner)
        await realtime._release_browser_connection_lease(stale)
        with pytest.raises(BrowserConnectionLimitExceeded):
            await realtime._acquire_browser_connection_lease(session_id, owner)

        await realtime._release_browser_connection_lease(replacement)
        final = await realtime._acquire_browser_connection_lease(session_id, owner)
        await realtime._release_browser_connection_lease(final)

    websocket_harness.client.portal.call(scenario)


def test_browser_websocket_cap_rejects_then_releases_on_clean_close(
    websocket_harness: WebSocketHarness,
) -> None:
    websocket_harness.settings.browser_max_connections_per_session = 1
    websocket_harness.settings.browser_max_connections_per_user = 1
    exchange = websocket_harness.client.post(
        "/v1/session/exchange",
        headers={"Origin": ORIGIN},
        json={"access_token": "browser-cap-access-token"},
    )
    assert exchange.status_code == 201
    cookie = websocket_harness.client.cookies.get(websocket_harness.settings.cookie_name)
    headers = {
        "Origin": ORIGIN,
        "Cookie": f"{websocket_harness.settings.cookie_name}={cookie}",
    }

    with websocket_harness.client.websocket_connect(
        "/codex-ws/browser?cursor=0",
        headers=headers,
    ) as first:
        with pytest.raises(WebSocketDisconnect) as rejected:
            with websocket_harness.client.websocket_connect(
                "/codex-ws/browser?cursor=0",
                headers=headers,
            ):
                pass
        assert rejected.value.code == 4429
        first.send_text("close")
        with pytest.raises(WebSocketDisconnect) as closed:
            first.receive_json()
        assert closed.value.code == 1000

    async def wait_for_release() -> None:
        async with websocket_harness.database.session_factory() as db:
            session = await db.scalar(select(ControlSession))
        assert session is not None
        deadline = asyncio.get_running_loop().time() + 1
        while True:
            try:
                probe = (
                    await websocket_harness.app.state.realtime._acquire_browser_connection_lease(
                        session.id,
                        session.sub2api_user_id,
                    )
                )
            except BrowserConnectionLimitExceeded:
                if asyncio.get_running_loop().time() >= deadline:
                    raise AssertionError("browser connection lease was not released") from None
                await asyncio.sleep(0.01)
                continue
            await websocket_harness.app.state.realtime._release_browser_connection_lease(probe)
            return

    websocket_harness.client.portal.call(wait_for_release)
    with websocket_harness.client.websocket_connect(
        "/codex-ws/browser?cursor=0",
        headers=headers,
    ) as replacement:
        replacement.send_text("close")
        with pytest.raises(WebSocketDisconnect) as closed:
            replacement.receive_json()
        assert closed.value.code == 1000


def test_browser_websocket_lease_dependency_failure_closes_1013(
    websocket_harness: WebSocketHarness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    exchange = websocket_harness.client.post(
        "/v1/session/exchange",
        headers={"Origin": ORIGIN},
        json={"access_token": "browser-lease-failure-access-token"},
    )
    assert exchange.status_code == 201
    cookie = websocket_harness.client.cookies.get(websocket_harness.settings.cookie_name)

    async def unavailable(*_args: object, **_kwargs: object) -> bool:
        raise RuntimeError("simulated lease store failure")

    monkeypatch.setattr(websocket_harness.store, "set_if_absent", unavailable)
    with pytest.raises(WebSocketDisconnect) as closed:
        with websocket_harness.client.websocket_connect(
            "/codex-ws/browser?cursor=0",
            headers={
                "Origin": ORIGIN,
                "Cookie": f"{websocket_harness.settings.cookie_name}={cookie}",
            },
        ):
            pass
    assert closed.value.code == 1013


@pytest.mark.parametrize(
    ("error", "expected_code", "expect_revoked"),
    [
        (RevokedSub2APIToken("revoked"), 4401, True),
        (Sub2APIUnavailable("temporarily unavailable"), 1013, False),
    ],
)
def test_browser_websocket_periodically_rechecks_upstream_identity(
    websocket_harness: WebSocketHarness,
    error: Exception,
    expected_code: int,
    expect_revoked: bool,
) -> None:
    websocket_harness.settings.session_upstream_recheck_seconds = 1
    access_token = "browser-upstream-recheck-token"
    exchange = websocket_harness.client.post(
        "/v1/session/exchange",
        headers={"Origin": ORIGIN},
        json={"access_token": access_token},
    )
    assert exchange.status_code == 201
    cookie = websocket_harness.client.cookies.get(websocket_harness.settings.cookie_name)

    with websocket_harness.client.websocket_connect(
        "/codex-ws/browser?cursor=0",
        headers={
            "Origin": ORIGIN,
            "Cookie": f"{websocket_harness.settings.cookie_name}={cookie}",
        },
    ) as socket:
        # The monitor must bypass the fresh exchange marker on admission, then
        # repeat that authoritative check at the configured cadence. Admission
        # finishes after the socket is accepted, so wait for that second
        # authoritative check instead of racing it.
        deadline = time.monotonic() + 5.0
        while len(websocket_harness.sub2api.seen_tokens) < 2:
            assert time.monotonic() < deadline, (
                "admission did not repeat the authoritative upstream check"
            )
            time.sleep(0.01)
        assert websocket_harness.sub2api.seen_tokens[:2] == [access_token, access_token]
        websocket_harness.sub2api.result = error
        with pytest.raises(WebSocketDisconnect) as closed:
            socket.receive_json()
        assert closed.value.code == expected_code

    assert len(websocket_harness.sub2api.seen_tokens) >= 2
    assert set(websocket_harness.sub2api.seen_tokens) == {access_token}

    async def session_was_revoked() -> bool:
        async with websocket_harness.database.session_factory() as db:
            record = await db.scalar(select(ControlSession))
        assert record is not None
        return record.revoked_at is not None

    assert websocket_harness.client.portal.call(session_was_revoked) is expect_revoked


def test_browser_event_delivery_pauses_during_periodic_upstream_recheck(
    websocket_harness: WebSocketHarness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(realtime_module, "BROWSER_SESSION_RECHECK_SECONDS", 0.01)
    access_token = "browser-paused-delivery-token"
    exchange = websocket_harness.client.post(
        "/v1/session/exchange",
        headers={"Origin": ORIGIN},
        json={"access_token": access_token},
    )
    assert exchange.status_code == 201
    raw_token = websocket_harness.client.cookies.get(websocket_harness.settings.cookie_name)
    assert raw_token is not None

    async def scenario() -> list[str]:
        realtime = websocket_harness.app.state.realtime
        async with websocket_harness.database.session_factory() as db:
            session = await db.scalar(select(ControlSession))
        assert session is not None

        ready = asyncio.Event()
        session_gate = BrowserSessionGate()
        monitor = asyncio.create_task(
            realtime._monitor_browser_session(
                session.id,
                raw_token,
                ready,
                session_gate,
            )
        )
        release_recheck = asyncio.Event()
        try:
            await asyncio.wait_for(ready.wait(), timeout=1)
            assert session_gate.authorized.is_set()
            original_verify = websocket_harness.sub2api.verify_access_token
            recheck_started = asyncio.Event()

            async def delayed_verify(
                token: str,
                request_identity: Sub2APIRequestIdentity,
            ) -> Sub2APIUser:
                recheck_started.set()
                await release_recheck.wait()
                return await original_verify(token, request_identity)

            monkeypatch.setattr(
                websocket_harness.sub2api,
                "verify_access_token",
                delayed_verify,
            )
            await asyncio.wait_for(recheck_started.wait(), timeout=1)
            assert not session_gate.authorized.is_set()

            socket = RecordingBrowserWebSocket()
            delivery = asyncio.create_task(
                realtime._send_browser_event_when_authorized(
                    socket,  # type: ignore[arg-type]
                    "sensitive-event",
                    session_gate,
                    (monitor,),
                )
            )
            await asyncio.sleep(0)
            assert socket.sent_text == []

            release_recheck.set()
            await asyncio.wait_for(delivery, timeout=1)
            return socket.sent_text
        finally:
            release_recheck.set()
            if not monitor.done():
                monitor.cancel()
            await asyncio.gather(monitor, return_exceptions=True)

    assert websocket_harness.client.portal.call(scenario) == ["sensitive-event"]


def test_browser_upstream_recheck_has_total_wall_clock_timeout(
    websocket_harness: WebSocketHarness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(realtime_module, "BROWSER_SESSION_RECHECK_SECONDS", 0.01)
    exchange = websocket_harness.client.post(
        "/v1/session/exchange",
        headers={"Origin": ORIGIN},
        json={"access_token": "browser-bounded-recheck-token"},
    )
    assert exchange.status_code == 201
    raw_token = websocket_harness.client.cookies.get(websocket_harness.settings.cookie_name)
    assert raw_token is not None

    async def scenario() -> tuple[int, str, bool]:
        realtime = websocket_harness.app.state.realtime
        async with websocket_harness.database.session_factory() as db:
            session = await db.scalar(select(ControlSession))
        assert session is not None

        ready = asyncio.Event()
        session_gate = BrowserSessionGate()
        monitor = asyncio.create_task(
            realtime._monitor_browser_session(
                session.id,
                raw_token,
                ready,
                session_gate,
            )
        )
        try:
            await asyncio.wait_for(ready.wait(), timeout=1)
            websocket_harness.settings.sub2api_timeout_seconds = 0.02
            recheck_started = asyncio.Event()
            never_finishes = asyncio.Event()

            async def stalled_verify(
                _token: str,
                _request_identity: Sub2APIRequestIdentity,
            ) -> Sub2APIUser:
                recheck_started.set()
                await never_finishes.wait()
                raise AssertionError("unreachable")

            monkeypatch.setattr(
                websocket_harness.sub2api,
                "verify_access_token",
                stalled_verify,
            )
            await asyncio.wait_for(recheck_started.wait(), timeout=1)
            with pytest.raises(BrowserSocketClose) as closed:
                await asyncio.wait_for(monitor, timeout=1)
            return closed.value.code, closed.value.reason, session_gate.authorized.is_set()
        finally:
            if not monitor.done():
                monitor.cancel()
            await asyncio.gather(monitor, return_exceptions=True)

    assert websocket_harness.client.portal.call(scenario) == (
        1013,
        "control session verification unavailable",
        False,
    )


def test_blocked_browser_event_send_fails_closed(
    websocket_harness: WebSocketHarness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(realtime_module, "BROWSER_EVENT_SEND_TIMEOUT_SECONDS", 0.01)

    class BlockingBrowserWebSocket(RecordingBrowserWebSocket):
        def __init__(self) -> None:
            super().__init__()
            self.send_started = asyncio.Event()

        async def send_text(self, value: str) -> None:
            self.send_started.set()
            await asyncio.Event().wait()

    async def scenario() -> tuple[int, str, bool, int]:
        session_gate = BrowserSessionGate()
        session_gate.authorized.set()
        socket = BlockingBrowserWebSocket()
        with pytest.raises(BrowserSocketClose) as closed:
            await websocket_harness.app.state.realtime._send_browser_event_when_authorized(
                socket,  # type: ignore[arg-type]
                "sensitive-event",
                session_gate,
                (),
            )
        assert socket.send_started.is_set()
        return (
            closed.value.code,
            closed.value.reason,
            session_gate.sends_drained.is_set(),
            session_gate.in_flight_sends,
        )

    assert websocket_harness.client.portal.call(scenario) == (
        1013,
        "browser event delivery unavailable",
        True,
        0,
    )


def test_browser_connection_lease_renewal_failure_closes_1013(
    websocket_harness: WebSocketHarness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    websocket_harness.settings.browser_connection_lease_ttl_seconds = 0.03
    realtime = websocket_harness.app.state.realtime

    async def lost_lease(*_args: object, **_kwargs: object) -> bool:
        return False

    monkeypatch.setattr(websocket_harness.store, "compare_refresh", lost_lease)

    async def scenario() -> int:
        lease = await realtime._acquire_browser_connection_lease(uuid.uuid4(), "owner")
        try:
            with pytest.raises(BrowserSocketClose) as closed:
                await asyncio.wait_for(
                    realtime._renew_browser_connection_lease(lease),
                    timeout=1,
                )
            return closed.value.code
        finally:
            await realtime._release_browser_connection_lease(lease)

    assert websocket_harness.client.portal.call(scenario) == 1013


def test_cross_instance_logout_closes_browser_websocket_immediately(
    websocket_harness: WebSocketHarness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    exchange = websocket_harness.client.post(
        "/v1/session/exchange",
        headers={"Origin": ORIGIN},
        json={"access_token": "cross-instance-logout-access-token"},
    )
    assert exchange.status_code == 201

    published: list[tuple[str, str, int]] = []
    original_publish = websocket_harness.store.publish

    async def record_publish(channel: str, value: str) -> int:
        subscribers = await original_publish(channel, value)
        published.append((channel, value, subscribers))
        return subscribers

    monkeypatch.setattr(websocket_harness.store, "publish", record_publish)

    async def scenario() -> tuple[uuid.UUID, str, RecordingBrowserWebSocket]:
        async with websocket_harness.database.session_factory() as db:
            session = await db.scalar(select(ControlSession))
        assert session is not None

        socket = RecordingBrowserWebSocket()
        ready = asyncio.Event()
        monitor = asyncio.create_task(
            monitor_browser_session_and_apply_close(
                websocket_harness.app.state.realtime,
                socket,
                session.id,
                websocket_harness.client.cookies.get(websocket_harness.settings.cookie_name),
                ready,
            )
        )
        await asyncio.wait_for(ready.wait(), timeout=1)
        assert not monitor.done()

        # This is a distinct service object, as it would be in another API process,
        # sharing only the durable database and Redis-compatible store.
        other_instance = SessionService(
            websocket_harness.settings,
            websocket_harness.store,
            TokenDigester(websocket_harness.settings.session_hmac_secret.get_secret_value()),
            websocket_harness.sub2api,
            SessionCredentialProtector(
                websocket_harness.settings.session_hmac_secret.get_secret_value(),
                random_handle_bytes=websocket_harness.settings.session_token_bytes,
            ),
        )
        async with websocket_harness.database.session_factory() as db:
            durable_session = await db.get(ControlSession, session.id)
            assert durable_session is not None
            await other_instance.revoke(
                db,
                durable_session,
                RequestMetadata(None, None, "cross-instance-logout"),
            )

        await asyncio.wait_for(socket.closed.wait(), timeout=1)
        await asyncio.wait_for(monitor, timeout=1)
        return session.id, session.token_hash, socket

    session_id, token_hash, socket = websocket_harness.client.portal.call(scenario)
    assert socket.close_code == 4401
    assert published == [
        (f"control-session-revoked:{session_id}", str(session_id), 1),
    ]
    assert token_hash not in published[0][0]
    assert token_hash not in published[0][1]


def test_browser_session_rechecks_database_after_subscribe_race(
    websocket_harness: WebSocketHarness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    exchange = websocket_harness.client.post(
        "/v1/session/exchange",
        headers={"Origin": ORIGIN},
        json={"access_token": "subscribe-race-access-token"},
    )
    assert exchange.status_code == 201

    published: list[tuple[str, str, int]] = []
    original_publish = websocket_harness.store.publish

    async def record_publish(channel: str, value: str) -> int:
        subscribers = await original_publish(channel, value)
        published.append((channel, value, subscribers))
        return subscribers

    monkeypatch.setattr(websocket_harness.store, "publish", record_publish)

    async def scenario() -> tuple[uuid.UUID, RecordingBrowserWebSocket]:
        async with websocket_harness.database.session_factory() as db:
            authenticated_session = await db.scalar(select(ControlSession))
        assert authenticated_session is not None

        # The logout lands after the socket's initial authentication but before its
        # revocation subscription. Pub/Sub has no subscriber, so the post-subscribe
        # database recheck is what must close the socket.
        other_instance = SessionService(
            websocket_harness.settings,
            websocket_harness.store,
            TokenDigester(websocket_harness.settings.session_hmac_secret.get_secret_value()),
            websocket_harness.sub2api,
            SessionCredentialProtector(
                websocket_harness.settings.session_hmac_secret.get_secret_value(),
                random_handle_bytes=websocket_harness.settings.session_token_bytes,
            ),
        )
        async with websocket_harness.database.session_factory() as db:
            durable_session = await db.get(ControlSession, authenticated_session.id)
            assert durable_session is not None
            await other_instance.revoke(
                db,
                durable_session,
                RequestMetadata(None, None, "subscribe-race"),
            )

        socket = RecordingBrowserWebSocket()
        ready = asyncio.Event()
        monitor = asyncio.create_task(
            monitor_browser_session_and_apply_close(
                websocket_harness.app.state.realtime,
                socket,
                authenticated_session.id,
                websocket_harness.client.cookies.get(websocket_harness.settings.cookie_name),
                ready,
            )
        )
        await asyncio.wait_for(ready.wait(), timeout=1)
        await asyncio.wait_for(socket.closed.wait(), timeout=1)
        await asyncio.wait_for(monitor, timeout=1)
        return authenticated_session.id, socket

    session_id, socket = websocket_harness.client.portal.call(scenario)
    assert socket.close_code == 4401
    assert published == [
        (f"control-session-revoked:{session_id}", str(session_id), 0),
    ]


def test_browser_session_subscription_failure_is_fail_closed(
    websocket_harness: WebSocketHarness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    exchange = websocket_harness.client.post(
        "/v1/session/exchange",
        headers={"Origin": ORIGIN},
        json={"access_token": "subscription-failure-access-token"},
    )
    assert exchange.status_code == 201

    async def broken_subscription(
        _channel: str,
        _ready: asyncio.Event | None = None,
    ):  # type: ignore[no-untyped-def]
        raise RuntimeError("simulated subscription failure")
        yield ""  # pragma: no cover

    monkeypatch.setattr(websocket_harness.store, "subscribe", broken_subscription)

    async def scenario() -> RecordingBrowserWebSocket:
        async with websocket_harness.database.session_factory() as db:
            session = await db.scalar(select(ControlSession))
        assert session is not None

        socket = RecordingBrowserWebSocket()
        ready = asyncio.Event()
        monitor = asyncio.create_task(
            monitor_browser_session_and_apply_close(
                websocket_harness.app.state.realtime,
                socket,
                session.id,
                websocket_harness.client.cookies.get(websocket_harness.settings.cookie_name),
                ready,
            )
        )
        await asyncio.wait_for(ready.wait(), timeout=1)
        await asyncio.wait_for(socket.closed.wait(), timeout=1)
        await asyncio.wait_for(monitor, timeout=1)
        return socket

    socket = websocket_harness.client.portal.call(scenario)
    assert socket.close_code == 1013


def test_browser_websocket_subscription_failure_closes_1013_after_upgrade(
    websocket_harness: WebSocketHarness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    exchange = websocket_harness.client.post(
        "/v1/session/exchange",
        headers={"Origin": ORIGIN},
        json={"access_token": "websocket-subscription-failure-access-token"},
    )
    assert exchange.status_code == 201
    cookie = websocket_harness.client.cookies.get(websocket_harness.settings.cookie_name)

    async def broken_subscription(
        _channel: str,
        _ready: asyncio.Event | None = None,
    ):  # type: ignore[no-untyped-def]
        raise RuntimeError("simulated subscription failure")
        yield ""  # pragma: no cover

    monkeypatch.setattr(websocket_harness.store, "subscribe", broken_subscription)
    with websocket_harness.client.websocket_connect(
        "/codex-ws/browser?cursor=0",
        headers={
            "Origin": ORIGIN,
            "Cookie": f"{websocket_harness.settings.cookie_name}={cookie}",
        },
    ) as socket:
        with pytest.raises(WebSocketDisconnect) as closed:
            socket.receive_json()
        assert closed.value.code == 1013


def test_browser_session_database_failure_is_retryable_infrastructure_close(
    websocket_harness: WebSocketHarness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    exchange = websocket_harness.client.post(
        "/v1/session/exchange",
        headers={"Origin": ORIGIN},
        json={"access_token": "session-database-failure-access-token"},
    )
    assert exchange.status_code == 201

    async def unavailable(_session_id: uuid.UUID, _raw_token: str) -> datetime | None:
        raise RuntimeError("simulated session database failure")

    monkeypatch.setattr(
        websocket_harness.app.state.realtime,
        "_active_browser_session_expiry",
        unavailable,
    )

    async def scenario() -> RecordingBrowserWebSocket:
        async with websocket_harness.database.session_factory() as db:
            session = await db.scalar(select(ControlSession))
        assert session is not None

        socket = RecordingBrowserWebSocket()
        ready = asyncio.Event()
        monitor = asyncio.create_task(
            monitor_browser_session_and_apply_close(
                websocket_harness.app.state.realtime,
                socket,
                session.id,
                websocket_harness.client.cookies.get(websocket_harness.settings.cookie_name),
                ready,
            )
        )
        await asyncio.wait_for(ready.wait(), timeout=1)
        await asyncio.wait_for(socket.closed.wait(), timeout=1)
        await asyncio.wait_for(monitor, timeout=1)
        return socket

    socket = websocket_harness.client.portal.call(scenario)
    assert socket.close_code == 1013


@pytest.mark.parametrize("cursor", ["-1", str(MAX_EVENT_CURSOR + 1), "not-an-integer"])
def test_browser_websocket_rejects_cursor_outside_signed_bigint(
    websocket_harness: WebSocketHarness,
    cursor: str,
) -> None:
    exchange = websocket_harness.client.post(
        "/v1/session/exchange",
        headers={"Origin": ORIGIN},
        json={"access_token": "cursor-bound-access-token"},
    )
    assert exchange.status_code == 201
    cookie = websocket_harness.client.cookies.get(websocket_harness.settings.cookie_name)
    with pytest.raises(WebSocketDisconnect) as closed:
        with websocket_harness.client.websocket_connect(
            f"/codex-ws/browser?cursor={cursor}",
            headers={
                "Origin": ORIGIN,
                "Cookie": f"{websocket_harness.settings.cookie_name}={cookie}",
            },
        ):
            pass
    assert closed.value.code == 4400


def test_browser_websocket_requires_bootstrap_for_future_cursor(
    websocket_harness: WebSocketHarness,
) -> None:
    exchange = websocket_harness.client.post(
        "/v1/session/exchange",
        headers={"Origin": ORIGIN},
        json={"access_token": "future-cursor-access-token"},
    )
    assert exchange.status_code == 201
    cookie = websocket_harness.client.cookies.get(websocket_harness.settings.cookie_name)
    with websocket_harness.client.websocket_connect(
        "/codex-ws/browser?cursor=1",
        headers={
            "Origin": ORIGIN,
            "Cookie": f"{websocket_harness.settings.cookie_name}={cookie}",
        },
    ) as socket:
        with pytest.raises(WebSocketDisconnect) as closed:
            socket.receive_json()
        assert closed.value.code == 4409


def test_browser_websocket_requires_bootstrap_for_pruned_cursor(
    websocket_harness: WebSocketHarness,
) -> None:
    exchange = websocket_harness.client.post(
        "/v1/session/exchange",
        headers={"Origin": ORIGIN},
        json={"access_token": "stale-cursor-access-token"},
    )
    assert exchange.status_code == 201

    async def seed_and_prune() -> None:
        device = Device(
            owner_user_id="42",
            name="Pruned",
            public_key=f"pruned-{uuid.uuid4()}",
            status=DeviceStatus.ACTIVE,
            device_metadata={},
            workspace_roots=[],
        )
        async with websocket_harness.database.session_factory() as db:
            db.add(device)
            await db.commit()
            for index in range(3):
                await websocket_harness.app.state.events.append(
                    db,
                    owner_user_id="42",
                    device_id=device.id,
                    event_type="device.updated",
                    data={"index": index},
                )
                await db.commit()
        websocket_harness.settings.browser_event_max_per_owner = 2
        async with websocket_harness.database.session_factory() as db:
            assert await websocket_harness.app.state.events.prune(db) == 1

    websocket_harness.client.portal.call(seed_and_prune)
    cookie = websocket_harness.client.cookies.get(websocket_harness.settings.cookie_name)
    with websocket_harness.client.websocket_connect(
        "/codex-ws/browser?cursor=0",
        headers={
            "Origin": ORIGIN,
            "Cookie": f"{websocket_harness.settings.cookie_name}={cookie}",
        },
    ) as socket:
        with pytest.raises(WebSocketDisconnect) as closed:
            socket.receive_json()
        assert closed.value.code == 4409
