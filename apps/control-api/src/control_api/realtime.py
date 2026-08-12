from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import time
import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import WebSocket, WebSocketDisconnect
from pydantic import ValidationError
from sqlalchemy import delete, func, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from .approvals import NON_DISPATCHABLE_APPROVAL_REASONS, ApprovalService
from .capacity import (
    OwnerCapacityExceeded,
    approval_capacity_denial_reason_locked,
    bounded_model_catalog,
    ensure_approval_projection_fits,
    ensure_approval_record_capacity_locked,
    ensure_thread_projection_fits,
    total_thread_count,
    visible_thread_count,
)
from .commands import (
    CommandService,
    command_view,
    repair_binding_for_terminal_command,
    thread_event_data,
    wire_idempotency_key,
)
from .config import Settings
from .db import Database
from .device_auth import DeviceTokenService
from .events import MAX_EVENT_CURSOR, BrowserCursorResetRequired, EventService
from .models import (
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
    DeviceStatus,
    ThreadBinding,
    ThreadBindingStatus,
)
from .operational_metrics import COMMAND_TERMINAL_STATUSES, OperationalMetrics, elapsed_seconds
from .protocol import (
    ALLOWED_RPC_METHODS,
    SERVER_OUTBOUND_TYPES,
    ApprovalRequestPayload,
    CommandAckPayload,
    ControlEnvelope,
    DeviceEventPayload,
    HeartbeatPayload,
    HelloPayload,
    ProtocolErrorPayload,
    require_device_outbound,
)
from .schemas import BrowserEvent
from .security import (
    canonicalize_ed25519_public_key,
    canonicalize_workspace_roots,
    origin_is_allowed,
)
from .services import SessionService, control_session_revocation_channel
from .storage import KeyValueStore
from .thread_snapshot import ThreadSnapshotTooLarge, compact_thread_snapshot

ALLOWED_DEVICE_EVENTS = frozenset(
    {
        "thread/status/changed",
        "thread/name/updated",
        "turn/started",
        "turn/completed",
        "turn/plan/updated",
        "item/agentMessage/delta",
        "error",
    }
)
BROWSER_SESSION_RECHECK_SECONDS = 15.0
BROWSER_SESSION_SUBSCRIBE_TIMEOUT_SECONDS = 5.0
BROWSER_EVENT_DB_POLL_SECONDS = 5.0
_LOGGER = logging.getLogger(__name__)


class RealtimeProtocolError(Exception):
    pass


class SequenceGap(RealtimeProtocolError):
    pass


class StaleConnection(RealtimeProtocolError):
    pass


class BrowserConnectionLimitExceeded(Exception):
    pass


class BrowserSocketClose(Exception):
    def __init__(self, code: int, reason: str) -> None:
        super().__init__(reason)
        self.code = code
        self.reason = reason


@dataclass(frozen=True, slots=True)
class BrowserLeaseSlot:
    key: str
    value: str


@dataclass(frozen=True, slots=True)
class BrowserConnectionLease:
    session_slot: BrowserLeaseSlot
    user_slot: BrowserLeaseSlot

    @property
    def slots(self) -> tuple[BrowserLeaseSlot, BrowserLeaseSlot]:
        return (self.session_slot, self.user_slot)


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _iso(value: datetime) -> str:
    return _utc(value).isoformat().replace("+00:00", "Z")


def _approval_request_hash(payload: ApprovalRequestPayload) -> str:
    encoded = json.dumps(
        {
            "command_id": payload.command_id,
            "kind": payload.kind,
            "summary": payload.summary,
            "details": payload.details,
            "expires_at": _iso(payload.expires_at),
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _extract_string(value: Any, *keys: str) -> str | None:
    if not isinstance(value, dict):
        return None
    for key in keys:
        candidate = value.get(key)
        if isinstance(candidate, str) and candidate:
            return candidate
    for nested_key in ("thread", "turn", "item", "message"):
        nested = value.get(nested_key)
        candidate = _extract_string(nested, *keys)
        if candidate:
            return candidate
    return None


def _thread_status(value: str | None) -> ThreadBindingStatus | None:
    if value is None:
        return None
    normalized = value.lower().replace("-", "_")
    mapping = {
        "idle": ThreadBindingStatus.IDLE,
        "running": ThreadBindingStatus.RUNNING,
        "in_progress": ThreadBindingStatus.RUNNING,
        "waiting_for_approval": ThreadBindingStatus.WAITING_FOR_APPROVAL,
        "failed": ThreadBindingStatus.FAILED,
        "error": ThreadBindingStatus.FAILED,
        "closed": ThreadBindingStatus.CLOSED,
    }
    return mapping.get(normalized)


def _wire_thread_status(value: Any) -> ThreadBindingStatus:
    if isinstance(value, dict):
        value = value.get("type")
    normalized = str(value or "").lower().replace("-", "_")
    if normalized in {"active", "running", "in_progress", "inprogress"}:
        return ThreadBindingStatus.RUNNING
    if normalized in {"systemerror", "system_error", "failed", "error"}:
        return ThreadBindingStatus.FAILED
    return ThreadBindingStatus.IDLE


def _wire_timestamp(value: Any, fallback: datetime) -> datetime:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return fallback
    try:
        return datetime.fromtimestamp(value, UTC)
    except (OverflowError, OSError, ValueError):
        return fallback


def _cwd_in_roots(cwd: str, roots: list[str]) -> bool:
    try:
        canonical = canonicalize_workspace_roots([cwd])[0]
    except ValueError:
        return False
    return any(canonical == root or canonical.startswith(f"{root}/") for root in roots)


def _encoded_json_size(value: Any) -> int:
    return len(json.dumps(value, separators=(",", ":"), ensure_ascii=True).encode("utf-8"))


def _validate_json_shape(
    value: Any,
    *,
    max_depth: int,
    max_nodes: int,
    max_string_chars: int,
) -> None:
    stack: list[tuple[Any, int]] = [(value, 1)]
    nodes = 0
    while stack:
        current, depth = stack.pop()
        nodes += 1
        if nodes > max_nodes:
            raise RealtimeProtocolError("JSON payload exceeds the node limit")
        if depth > max_depth:
            raise RealtimeProtocolError("JSON payload exceeds the nesting limit")
        if isinstance(current, str):
            if len(current) > max_string_chars:
                raise RealtimeProtocolError("JSON string exceeds the character limit")
            continue
        if isinstance(current, dict):
            for key, nested in current.items():
                if not isinstance(key, str) or len(key) > max_string_chars:
                    raise RealtimeProtocolError("JSON object key exceeds the character limit")
                stack.append((nested, depth + 1))
            continue
        if isinstance(current, list):
            stack.extend((nested, depth + 1) for nested in current)


@dataclass
class ActiveDeviceSocket:
    websocket: WebSocket
    device_id: uuid.UUID
    owner_user_id: str
    connection_nonce: str
    epoch: str
    registry_value: str = ""
    received_sequence: int = 0
    send_lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    last_activity: float = field(default_factory=time.monotonic)


@dataclass
class FrameEffects:
    browser_events: list[BrowserEvent] = field(default_factory=list)
    approval_dispatches: list[uuid.UUID] = field(default_factory=list)
    command_transitions: list[tuple[str, str, float | None]] = field(default_factory=list)
    approval_outcomes: list[tuple[str, str]] = field(default_factory=list)


class ConnectionHub:
    def __init__(self) -> None:
        self._connections: dict[uuid.UUID, ActiveDeviceSocket] = {}
        self._lock = asyncio.Lock()

    async def register(
        self,
        connection: ActiveDeviceSocket,
        ownership_check: Callable[[], Awaitable[bool]],
    ) -> None:
        async with self._lock:
            if not await ownership_check():
                raise StaleConnection("connection registry ownership was lost before activation")
            previous = self._connections.get(connection.device_id)
            self._connections[connection.device_id] = connection
        if previous is not None and previous.connection_nonce != connection.connection_nonce:
            await previous.websocket.close(code=4001, reason="replaced by a newer connection")

    async def unregister(self, connection: ActiveDeviceSocket) -> None:
        async with self._lock:
            current = self._connections.get(connection.device_id)
            if current is connection:
                self._connections.pop(connection.device_id, None)


class RealtimeService:
    def __init__(
        self,
        settings: Settings,
        database: Database,
        store: KeyValueStore,
        token_service: DeviceTokenService,
        session_service: SessionService,
        events: EventService,
        commands: CommandService,
        approvals: ApprovalService,
        instance_id: str,
        metrics: OperationalMetrics | None = None,
    ) -> None:
        self._settings = settings
        self._database = database
        self._store = store
        self._tokens = token_service
        self._sessions = session_service
        self._events = events
        self._commands = commands
        self._approvals = approvals
        self._instance_id = instance_id
        self._metrics = metrics or OperationalMetrics()
        self._hub = ConnectionHub()

    async def handle_device(self, websocket: WebSocket) -> None:
        authorization = websocket.headers.get("authorization", "")
        if not authorization.startswith("Bearer "):
            self._metrics.websocket_rejected("device", "missing_auth")
            await websocket.close(code=4401, reason="device access token required")
            return
        access_token = authorization.removeprefix("Bearer ").strip()
        async with self._database.session_factory() as db:
            device = await self._tokens.authenticate_access_token(db, access_token)
        if device is None:
            self._metrics.websocket_rejected("device", "invalid_auth")
            await websocket.close(code=4401, reason="invalid device access token")
            return

        await websocket.accept()
        connection: ActiveDeviceSocket | None = None
        dispatch_task: asyncio.Task[None] | None = None
        opened = False
        close_reason = "unknown"
        try:
            async with asyncio.timeout(self._settings.device_hello_timeout_seconds):
                first_raw = await websocket.receive_text()
                await self._enforce_device_frame_rate(device.id)
                first = self._parse_device_envelope(first_raw)
            if first.device_id != device.id:
                raise RealtimeProtocolError("frame targets a different device")
            if first.type != "hello":
                raise RealtimeProtocolError("hello must be the first device frame")
            hello = HelloPayload.model_validate(first.payload)
            canonical_key = canonicalize_ed25519_public_key(hello.public_key)
            if canonical_key != device.public_key:
                raise RealtimeProtocolError("hello public key does not match the paired device")
            if frozenset(hello.workspace_roots) != frozenset(device.workspace_roots):
                raise RealtimeProtocolError(
                    "hello workspace roots do not match the paired device scope"
                )
            self._validate_hello_contract(device, first, hello)
            connection = await self._begin_connection(websocket, device.id, first, hello)
            self._metrics.websocket_opened("device")
            opened = True
            await self._send_hello_ack(
                connection,
                hello,
            )
            dispatch_activation = asyncio.Event()
            dispatch_task = await self._start_device_dispatch(connection, dispatch_activation)
            await self._replay_outbox(connection)
            await self._dispatch_pending(connection)
            dispatch_activation.set()

            tasks = {
                asyncio.create_task(self._device_receive_loop(connection)),
                dispatch_task,
                asyncio.create_task(self._heartbeat_watchdog(connection)),
            }
            done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            for task in pending:
                task.cancel()
            await asyncio.gather(*pending, return_exceptions=True)
            for task in done:
                if task.cancelled():
                    continue
                error = task.exception()
                if error is not None:
                    raise error
        except StaleConnection as exc:
            close_reason = "connection_replaced"
            if connection is not None:
                await self._end_connection(connection, "connection_replaced")
                connection = None
            await websocket.close(code=4001, reason=str(exc)[:120])
        except (TimeoutError, ValidationError, ValueError, RealtimeProtocolError) as exc:
            close_reason = "protocol_error"
            if connection is not None:
                await self._end_connection(connection, "protocol_error")
                connection = None
            await websocket.close(code=4400, reason=str(exc)[:120])
        except WebSocketDisconnect as exc:
            close_reason = _websocket_close_reason(exc.code)
        finally:
            if dispatch_task is not None:
                if not dispatch_task.done():
                    dispatch_task.cancel()
                await asyncio.gather(dispatch_task, return_exceptions=True)
            if connection is not None:
                cleanup = asyncio.create_task(self._end_connection(connection, "websocket_closed"))
                try:
                    await asyncio.shield(cleanup)
                except asyncio.CancelledError:
                    await cleanup
            if opened:
                self._metrics.websocket_closed("device", close_reason)
            elif close_reason == "protocol_error":
                self._metrics.websocket_rejected("device", close_reason)

    async def handle_browser(self, websocket: WebSocket) -> None:
        origin = websocket.headers.get("origin")
        if origin is None or not origin_is_allowed(origin, self._settings):
            self._metrics.websocket_rejected("browser", "origin_denied")
            await websocket.close(code=4403, reason="origin not allowed")
            return
        raw_token = websocket.cookies.get(self._settings.cookie_name)
        try:
            async with self._database.session_factory() as db:
                session = await self._sessions.resolve(db, raw_token, touch=False)
        except Exception as exc:
            _LOGGER.warning(
                "browser session resolution failed",
                extra={"error_type": type(exc).__name__},
            )
            self._metrics.websocket_rejected("browser", "dependency_unavailable")
            await self._close_browser_infrastructure_unavailable(
                websocket,
                "control session verification unavailable",
            )
            return
        if session is None:
            self._metrics.websocket_rejected("browser", "invalid_auth")
            await websocket.close(code=4401, reason="control session required")
            return
        cursor_raw = websocket.query_params.get("cursor", "0")
        try:
            cursor = int(cursor_raw)
        except ValueError:
            self._metrics.websocket_rejected("browser", "invalid_cursor")
            await websocket.close(code=4400, reason="cursor must be an integer")
            return
        if cursor < 0 or cursor > MAX_EVENT_CURSOR:
            self._metrics.websocket_rejected("browser", "invalid_cursor")
            await websocket.close(code=4400, reason="cursor must be a signed bigint")
            return

        try:
            lease = await self._acquire_browser_connection_lease(
                session.id,
                session.sub2api_user_id,
            )
        except BrowserConnectionLimitExceeded:
            self._metrics.websocket_rejected("browser", "capacity_exceeded")
            await websocket.close(code=4429, reason="browser connection limit exceeded")
            return
        except Exception as exc:
            _LOGGER.warning(
                "browser connection lease acquisition failed",
                extra={"error_type": type(exc).__name__},
            )
            self._metrics.websocket_rejected("browser", "dependency_unavailable")
            await self._close_browser_infrastructure_unavailable(
                websocket,
                "browser connection capacity unavailable",
            )
            return

        tasks: set[asyncio.Task[None]] = set()
        requested_close: BrowserSocketClose | None = None
        opened = False
        close_reason = "unknown"
        try:
            await websocket.accept()
            self._metrics.websocket_opened("browser")
            opened = True
            live_queue: asyncio.Queue[None] = asyncio.Queue(maxsize=1)
            subscription_ready = asyncio.Event()
            subscription_task = asyncio.create_task(
                self._pump_browser_events(session.sub2api_user_id, live_queue, subscription_ready)
            )
            session_monitor_ready = asyncio.Event()
            session_monitor_task = asyncio.create_task(
                self._monitor_browser_session(session.id, session_monitor_ready)
            )
            lease_renewal_task = asyncio.create_task(self._renew_browser_connection_lease(lease))
            tasks.update({subscription_task, session_monitor_task, lease_renewal_task})

            await self._wait_for_browser_subscription(subscription_ready, subscription_task)
            await session_monitor_ready.wait()
            if session_monitor_task.done():
                error = session_monitor_task.exception()
                if error is not None:
                    raise error
                raise RuntimeError("browser session monitor ended unexpectedly")
            latest_cursor = [cursor]
            while True:
                self._raise_if_browser_dependency_ended(
                    subscription_task,
                    session_monitor_task,
                    lease_renewal_task,
                )
                async with self._database.session_factory() as db:
                    try:
                        page = await self._events.catch_up_page(
                            db, session.sub2api_user_id, latest_cursor[0]
                        )
                    except BrowserCursorResetRequired as exc:
                        raise BrowserSocketClose(
                            4409,
                            "event cursor requires bootstrap",
                        ) from exc
                for event in page.events:
                    self._raise_if_browser_dependency_ended(
                        subscription_task,
                        session_monitor_task,
                        lease_renewal_task,
                    )
                    await websocket.send_text(event.model_dump_json())
                    latest_cursor[0] = int(event.cursor)
                if not page.has_more:
                    break

            tasks.update(
                {
                    asyncio.create_task(
                        self._forward_browser_queue(
                            websocket,
                            session.sub2api_user_id,
                            live_queue,
                            latest_cursor,
                            (
                                subscription_task,
                                session_monitor_task,
                                lease_renewal_task,
                            ),
                        )
                    ),
                    asyncio.create_task(self._browser_receive_loop(websocket)),
                }
            )
            done, pending = await asyncio.wait(
                tasks,
                return_when=asyncio.FIRST_COMPLETED,
            )
            for task in done:
                if task.cancelled():
                    continue
                error = task.exception()
                if error is not None:
                    raise error
        except WebSocketDisconnect as exc:
            close_reason = _websocket_close_reason(exc.code)
        except BrowserSocketClose as exc:
            requested_close = exc
            close_reason = _websocket_close_reason(exc.code)
        except Exception as exc:
            _LOGGER.warning(
                "browser realtime dependency failed",
                extra={"error_type": type(exc).__name__},
            )
            requested_close = BrowserSocketClose(
                1013,
                "browser realtime temporarily unavailable",
            )
            close_reason = "dependency_unavailable"
        finally:
            cleanup = asyncio.create_task(self._cleanup_browser_connection(tasks, lease))
            try:
                await asyncio.shield(cleanup)
            except asyncio.CancelledError:
                await cleanup
            if opened:
                self._metrics.websocket_closed("browser", close_reason)
        if requested_close is not None:
            await self._close_browser(
                websocket,
                requested_close.code,
                requested_close.reason,
            )

    def _parse_device_envelope(self, raw: str) -> ControlEnvelope:
        if len(raw.encode("utf-8")) > self._settings.device_max_envelope_bytes:
            raise RealtimeProtocolError("device envelope exceeds the byte limit")
        envelope = ControlEnvelope.model_validate_json(raw)
        require_device_outbound(envelope)
        _validate_json_shape(
            envelope.model_dump(mode="json"),
            max_depth=self._settings.device_max_json_depth,
            max_nodes=self._settings.device_max_json_nodes,
            max_string_chars=self._settings.device_max_string_chars,
        )
        payload_size = _encoded_json_size(envelope.payload)
        if envelope.type == "command_ack":
            result = envelope.payload.get("result")
            if (
                result is not None
                and _encoded_json_size(result) > self._settings.device_max_result_bytes
            ):
                raise RealtimeProtocolError("command result exceeds the byte limit")
        elif envelope.type == "event" and payload_size > self._settings.device_max_event_bytes:
            raise RealtimeProtocolError("device event exceeds the byte limit")
        elif (
            envelope.type == "approval_request"
            and payload_size > self._settings.device_max_approval_bytes
        ):
            raise RealtimeProtocolError("approval request exceeds the byte limit")
        return envelope

    async def _enforce_device_frame_rate(self, device_id: uuid.UUID) -> None:
        count = await self._store.increment(
            f"device-frame-rate:{device_id}",
            self._settings.rate_limit_window_seconds,
        )
        if count > self._settings.device_frame_rate_limit:
            raise RealtimeProtocolError("device frame rate limit exceeded")

    def _validate_hello_contract(
        self,
        device: Device,
        envelope: ControlEnvelope,
        hello: HelloPayload,
    ) -> None:
        metadata = device.device_metadata or {}
        if envelope.ack is None:
            raise RealtimeProtocolError("hello must acknowledge the server receive cursor")
        if hello.connector_version != self._settings.connector_expected_version:
            raise RealtimeProtocolError("connector version does not match the frozen contract")
        if hello.codex_version != self._settings.codex_expected_version:
            raise RealtimeProtocolError("Codex version does not match the frozen contract")
        if hello.schema_digest != self._settings.appserver_schema_digest:
            raise RealtimeProtocolError(
                "app-server schema digest does not match the frozen contract"
            )
        if frozenset(hello.capabilities) != ALLOWED_RPC_METHODS:
            raise RealtimeProtocolError("device capabilities do not match the control allowlist")
        if metadata.get("connector_version") not in {None, "", hello.connector_version}:
            raise RealtimeProtocolError("connector version changed after pairing")
        if metadata.get("codex_version") not in {None, "", hello.codex_version}:
            raise RealtimeProtocolError("Codex version changed after pairing")

    async def _begin_connection(
        self,
        websocket: WebSocket,
        device_id: uuid.UUID,
        envelope: ControlEnvelope,
        hello: HelloPayload,
    ) -> ActiveDeviceSocket:
        now = datetime.now(UTC)
        connection_nonce = str(uuid.uuid4())
        registry = json.dumps(
            {
                "connection_nonce": connection_nonce,
                "epoch": envelope.epoch,
                "instance_id": self._instance_id,
            },
            separators=(",", ":"),
        )
        received_sequence = 0
        replaced_connection_nonces: list[str] = []
        async with self._database.session_factory() as db:
            device = await db.scalar(select(Device).where(Device.id == device_id).with_for_update())
            if device is None or device.status != DeviceStatus.ACTIVE:
                raise RealtimeProtocolError("device is not active")
            if envelope.ack is None or envelope.ack > device.last_server_sequence:
                raise RealtimeProtocolError("hello acknowledgement exceeds the server sequence")
            if hello.resumed_from_seq > device.last_device_sequence:
                raise RealtimeProtocolError("hello resume cursor exceeds the server receive cursor")
            previous_ack = device.last_server_acked_sequence
            if envelope.ack > previous_ack:
                device.last_server_acked_sequence = envelope.ack
                await self._ack_outbox_locked(db, device.id, envelope.ack, now)
            received_sequence = device.last_device_sequence
            previous_connections = list(
                (
                    await db.scalars(
                        select(DeviceConnection).where(
                            DeviceConnection.device_id == device.id,
                            DeviceConnection.status == ConnectionStatus.CONNECTED,
                        )
                    )
                ).all()
            )
            replaced_connection_nonces = [
                previous.connection_nonce for previous in previous_connections
            ]
            for previous in previous_connections:
                previous.status = ConnectionStatus.DISCONNECTED
                previous.disconnected_at = now
                previous.closed_reason = "replaced"
            await db.flush()
            connection_count = int(
                await db.scalar(
                    select(func.count(DeviceConnection.id)).where(
                        DeviceConnection.device_id == device.id
                    )
                )
                or 0
            )
            if connection_count >= self._settings.device_max_connection_records:
                prune_count = connection_count - self._settings.device_max_connection_records + 1
                stale_connection_ids = (
                    select(DeviceConnection.id)
                    .where(
                        DeviceConnection.device_id == device.id,
                        DeviceConnection.status == ConnectionStatus.DISCONNECTED,
                    )
                    .order_by(DeviceConnection.disconnected_at, DeviceConnection.id)
                    .limit(prune_count)
                )
                await db.execute(
                    delete(DeviceConnection)
                    .where(DeviceConnection.id.in_(stale_connection_ids))
                    .execution_options(synchronize_session=False)
                )
                await db.flush()
                connection_count = int(
                    await db.scalar(
                        select(func.count(DeviceConnection.id)).where(
                            DeviceConnection.device_id == device.id
                        )
                    )
                    or 0
                )
                if connection_count >= self._settings.device_max_connection_records:
                    raise RealtimeProtocolError("device connection record limit reached")
            device.active_epoch = envelope.epoch
            device.active_connection_nonce = connection_nonce
            device.last_seen_at = now
            metadata = dict(device.device_metadata)
            metadata.update(
                {
                    "connector_version": hello.connector_version,
                    "codex_version": hello.codex_version,
                    "schema_digest": hello.schema_digest,
                    "capabilities": hello.capabilities,
                }
            )
            device.device_metadata = metadata
            connection_row = DeviceConnection(
                device_id=device.id,
                connection_nonce=connection_nonce,
                status=ConnectionStatus.CONNECTED,
                appserver_epoch=envelope.epoch,
                connected_at=now,
                last_heartbeat_at=now,
                remote_address=(websocket.client.host if websocket.client else None),
                connector_version=hello.connector_version,
                codex_version=hello.codex_version,
                connection_metadata={
                    "schema_digest": hello.schema_digest,
                    "capabilities": hello.capabilities,
                    "instance_id": self._instance_id,
                },
                last_device_sequence=device.last_device_sequence,
                last_server_sequence=device.last_server_sequence,
                last_server_acked_sequence=device.last_server_acked_sequence,
            )
            db.add(connection_row)
            db.add(
                AuditEvent(
                    actor_user_id=device.owner_user_id,
                    actor_device_id=device.id,
                    action="device.connect",
                    outcome=AuditOutcome.SUCCEEDED,
                    resource_type="device_connection",
                    resource_id=connection_nonce,
                    source_ip=connection_row.remote_address,
                    user_agent=websocket.headers.get("user-agent", "")[:512] or None,
                    details={"epoch": envelope.epoch},
                )
            )
            await self._store.set(
                f"connection:{device_id}",
                registry,
                self._settings.device_registry_ttl_seconds,
            )
            try:
                await db.commit()
            except Exception:
                await self._store.compare_delete(f"connection:{device_id}", registry)
                raise
            owner_user_id = device.owner_user_id

        if replaced_connection_nonces:
            self._metrics.websocket_replaced("device")

        connection = ActiveDeviceSocket(
            websocket=websocket,
            device_id=device_id,
            owner_user_id=owner_user_id,
            connection_nonce=connection_nonce,
            epoch=envelope.epoch,
            registry_value=registry,
            received_sequence=received_sequence,
        )
        reconciliation_attempted = False
        reconciliation_completed = False
        reconciliation_started = time.monotonic()
        try:
            await self._hub.register(
                connection,
                lambda: self._store.compare_refresh(
                    f"connection:{device_id}",
                    registry,
                    self._settings.device_registry_ttl_seconds,
                ),
            )
            await self._store.publish(
                f"device-dispatch:{device_id}",
                json.dumps(
                    {
                        "kind": "kick",
                        "replaced_connection_nonces": replaced_connection_nonces,
                    },
                    separators=(",", ":"),
                ),
            )
            activation_events: list[BrowserEvent] = []
            reconciliation_observations: list[tuple[str, int]] = []
            reconciliation_transitions: list[tuple[str, str, float]] = []
            reconciliation_attempted = True
            reconciliation_started = time.monotonic()
            async with self._database.session_factory() as db:
                device = await db.scalar(
                    select(Device).where(Device.id == device_id).with_for_update()
                )
                if (
                    device is None
                    or device.active_connection_nonce != connection_nonce
                    or device.active_epoch != envelope.epoch
                ):
                    raise StaleConnection("connection was replaced during activation")
                activation_events.extend(
                    await self._reconcile_stale_epoch_commands(
                        db,
                        device,
                        envelope.epoch,
                        now,
                        observations=reconciliation_observations,
                        command_transitions=reconciliation_transitions,
                    )
                )
                approval_events = await self._approvals.deny_stale_epoch(db, device, envelope.epoch)
                activation_events.extend(approval_events)
                reconciliation_observations.append(("approval_stale_epoch", len(approval_events)))
                activation_events.append(
                    await self._events.append(
                        db,
                        owner_user_id=device.owner_user_id,
                        device_id=device.id,
                        event_type="device.updated",
                        data=self._device_event_data(device, "online"),
                    )
                )
                await db.commit()
            reconciliation_duration = elapsed_seconds(reconciliation_started)
            for phase, items in reconciliation_observations:
                self._metrics.reconciliation(
                    phase,
                    "succeeded",
                    items,
                    reconciliation_duration,
                )
            for from_status, to_status, duration in reconciliation_transitions:
                self._metrics.command_transition(
                    from_status,
                    to_status,
                    duration_seconds=duration,
                )
            reconciliation_completed = True
            for event in activation_events:
                await self._events.publish(owner_user_id, event)
        except BaseException:
            if reconciliation_attempted and not reconciliation_completed:
                duration = elapsed_seconds(reconciliation_started)
                for phase in (
                    "command_stale_epoch",
                    "thread_stale_epoch",
                    "approval_stale_epoch",
                ):
                    self._metrics.reconciliation(phase, "failed", 0, duration)
            cleanup = asyncio.create_task(self._end_connection(connection, "activation_failed"))
            try:
                await asyncio.shield(cleanup)
            except asyncio.CancelledError:
                try:
                    await cleanup
                except Exception:
                    pass
            except Exception:
                pass
            raise
        return connection

    async def _process_device_frame(
        self,
        connection: ActiveDeviceSocket,
        envelope: ControlEnvelope,
    ) -> tuple[bool, bool, str | None]:
        if envelope.device_id != connection.device_id:
            raise RealtimeProtocolError("frame targets a different device")
        stale_replay = envelope.epoch != connection.epoch
        now = datetime.now(UTC)
        effects = FrameEffects()
        async with self._database.session_factory() as db:
            device = await db.scalar(
                select(Device).where(Device.id == connection.device_id).with_for_update()
            )
            if (
                device is None
                or device.active_connection_nonce != connection.connection_nonce
                or device.active_epoch != connection.epoch
            ):
                raise StaleConnection("connection is no longer active")
            if envelope.ack is not None and envelope.ack > device.last_server_sequence:
                raise RealtimeProtocolError("acknowledgement exceeds the last server sequence")
            duplicate = envelope.seq <= device.last_device_sequence
            duplicate_response: str | None = None
            if duplicate:
                replay = await db.scalar(
                    select(DeviceOutbox)
                    .where(
                        DeviceOutbox.device_id == device.id,
                        DeviceOutbox.ack_sequence >= envelope.seq,
                    )
                    .order_by(DeviceOutbox.sequence)
                    .limit(1)
                )
                duplicate_response = replay.encoded_envelope if replay is not None else None
                if duplicate_response is None:
                    raise RealtimeProtocolError(
                        "duplicate frame is already applied through receive cursor "
                        f"{device.last_device_sequence}; reconnect for cursor synchronization"
                    )
            if envelope.ack is not None and envelope.ack > device.last_server_acked_sequence:
                device.last_server_acked_sequence = envelope.ack
                await self._ack_outbox_locked(db, device.id, envelope.ack, now)
            if not duplicate and envelope.seq != device.last_device_sequence + 1:
                raise SequenceGap(
                    f"device sequence gap: got {envelope.seq} after {device.last_device_sequence}"
                )
            if not duplicate:
                await self._apply_device_frame_tx(
                    db,
                    connection,
                    envelope,
                    effects,
                    stale_replay=stale_replay,
                )
                device.last_device_sequence = envelope.seq
            device.last_seen_at = now
            connection_row = await db.scalar(
                select(DeviceConnection).where(
                    DeviceConnection.connection_nonce == connection.connection_nonce
                )
            )
            if connection_row is not None:
                connection_row.last_heartbeat_at = now
                connection_row.last_device_sequence = device.last_device_sequence
                connection_row.last_server_acked_sequence = device.last_server_acked_sequence
            await db.commit()
        connection.received_sequence = max(connection.received_sequence, envelope.seq)
        connection.last_activity = time.monotonic()
        await self._refresh_registry(connection)
        for from_status, to_status, duration in effects.command_transitions:
            self._metrics.command_transition(
                from_status,
                to_status,
                duration_seconds=duration,
            )
        for event in effects.browser_events:
            await self._events.publish(connection.owner_user_id, event)
        for outcome, reason in effects.approval_outcomes:
            self._metrics.approval_outcome(outcome, reason)
        for approval_id in effects.approval_dispatches:
            await self._store.publish(
                f"device-dispatch:{connection.device_id}",
                json.dumps({"kind": "approval", "approval_id": str(approval_id)}),
            )
        return duplicate, stale_replay, duplicate_response

    async def _device_receive_loop(self, connection: ActiveDeviceSocket) -> None:
        while True:
            raw = await connection.websocket.receive_text()
            await self._enforce_device_frame_rate(connection.device_id)
            envelope = self._parse_device_envelope(raw)
            if envelope.type == "hello":
                raise RealtimeProtocolError("hello is only valid as the first frame")
            duplicate, stale_replay, duplicate_response = await self._process_device_frame(
                connection, envelope
            )
            if duplicate:
                if duplicate_response is not None:
                    async with connection.send_lock:
                        await self._send_if_active(connection, [duplicate_response])
            else:
                await self._send_envelope(
                    connection,
                    "heartbeat_ack",
                    {"received_seq": envelope.seq},
                )
            if not stale_replay and envelope.type == "heartbeat":
                await self._dispatch_pending(connection)

    async def _apply_device_frame_tx(
        self,
        db: AsyncSession,
        connection: ActiveDeviceSocket,
        envelope: ControlEnvelope,
        effects: FrameEffects,
        *,
        stale_replay: bool = False,
    ) -> None:
        if stale_replay:
            await self._apply_stale_device_frame_tx(db, connection, envelope, effects)
            return
        if envelope.type == "heartbeat":
            HeartbeatPayload.model_validate(envelope.payload)
            return
        if envelope.type == "heartbeat_ack":
            return
        if envelope.type == "command_ack":
            await self._apply_command_ack_tx(db, connection, envelope, effects)
            return
        if envelope.type == "event":
            await self._apply_device_event_tx(db, connection, envelope, effects)
            return
        if envelope.type == "approval_request":
            await self._apply_approval_request_tx(db, connection, envelope, effects)
            return
        if envelope.type == "error":
            error = ProtocolErrorPayload.model_validate(envelope.payload)
            db.add(
                AuditEvent(
                    actor_user_id=connection.owner_user_id,
                    actor_device_id=connection.device_id,
                    action="device.protocol_error",
                    outcome=AuditOutcome.FAILED,
                    resource_type="device_connection",
                    resource_id=connection.connection_nonce,
                    details={"epoch": envelope.epoch, **error.model_dump()},
                )
            )
            return
        if envelope.type == "hello":
            raise RealtimeProtocolError("hello is only valid as the first frame")
        raise RealtimeProtocolError(f"unsupported device frame {envelope.type}")

    async def _apply_stale_device_frame_tx(
        self,
        db: AsyncSession,
        connection: ActiveDeviceSocket,
        envelope: ControlEnvelope,
        effects: FrameEffects,
    ) -> None:
        """Validate old-epoch spool frames without projecting stale app-server state."""

        if envelope.type == "command_ack":
            await self._apply_command_ack_tx(db, connection, envelope, effects)
            return
        if envelope.type == "heartbeat":
            HeartbeatPayload.model_validate(envelope.payload)
            return
        if envelope.type == "heartbeat_ack":
            return
        if envelope.type == "event":
            event = DeviceEventPayload.model_validate(envelope.payload)
            if event.method not in ALLOWED_DEVICE_EVENTS:
                raise RealtimeProtocolError("device event method is not allowlisted")
            return
        if envelope.type == "approval_request":
            ApprovalRequestPayload.model_validate(envelope.payload)
            return
        if envelope.type == "error":
            ProtocolErrorPayload.model_validate(envelope.payload)
            return
        if envelope.type == "hello":
            raise RealtimeProtocolError("hello is only valid as the first frame")
        raise RealtimeProtocolError(f"unsupported device frame {envelope.type}")

    async def _send_hello_ack(
        self,
        connection: ActiveDeviceSocket,
        hello: HelloPayload,
    ) -> None:
        envelope = {
            "version": 1,
            "id": str(uuid.uuid4()),
            "device_id": str(connection.device_id),
            "epoch": connection.epoch,
            "seq": 0,
            "ack": connection.received_sequence,
            "type": "hello_ack",
            "sent_at": _iso(datetime.now(UTC)),
            "payload": {
                "protocol_version": 1,
                "device_id": str(connection.device_id),
                "epoch": connection.epoch,
                "schema_digest": hello.schema_digest,
                "received_seq": connection.received_sequence,
                "connection_id": connection.connection_nonce,
                "heartbeat_timeout_seconds": self._settings.device_heartbeat_timeout_seconds,
            },
        }
        encoded = json.dumps(envelope, separators=(",", ":"), ensure_ascii=True)
        async with connection.send_lock:
            await self._send_if_active(connection, [encoded])

    async def _send_envelope(
        self,
        connection: ActiveDeviceSocket,
        envelope_type: str,
        payload: dict[str, Any],
    ) -> int:
        if envelope_type not in SERVER_OUTBOUND_TYPES:
            raise ValueError("server envelope type is not allowed")
        if envelope_type == "hello_ack":
            raise ValueError("hello_ack must use the unsequenced handshake path")
        async with connection.send_lock:
            async with self._database.session_factory() as db:
                device = await self._lock_active_device(db, connection)
                sequence, encoded = await self._persist_envelope_locked(
                    db,
                    connection,
                    device,
                    envelope_type,
                    payload,
                )
                await db.commit()
            await self._send_if_active(connection, [encoded])
            return sequence

    async def _lock_active_device(
        self,
        db: AsyncSession,
        connection: ActiveDeviceSocket,
    ) -> Device:
        device = await db.scalar(
            select(Device).where(Device.id == connection.device_id).with_for_update()
        )
        if (
            device is None
            or device.status != DeviceStatus.ACTIVE
            or device.active_connection_nonce != connection.connection_nonce
            or device.active_epoch != connection.epoch
        ):
            raise StaleConnection("connection is no longer active")
        return device

    async def _send_if_active(
        self,
        connection: ActiveDeviceSocket,
        encoded_frames: list[str],
    ) -> None:
        async with self._database.session_factory() as db:
            await self._lock_active_device(db, connection)
            async with asyncio.timeout(self._settings.device_hello_timeout_seconds):
                for encoded in encoded_frames:
                    await connection.websocket.send_text(encoded)

    async def _persist_envelope_locked(
        self,
        db: AsyncSession,
        connection: ActiveDeviceSocket,
        device: Device,
        envelope_type: str,
        payload: dict[str, Any],
    ) -> tuple[int, str]:
        sequence = device.last_server_sequence + 1
        envelope = {
            "version": 1,
            "id": str(uuid.uuid4()),
            "device_id": str(device.id),
            "epoch": connection.epoch,
            "seq": sequence,
            "ack": device.last_device_sequence,
            "type": envelope_type,
            "sent_at": _iso(datetime.now(UTC)),
            "payload": payload,
        }
        encoded = json.dumps(envelope, separators=(",", ":"), ensure_ascii=True)
        encoded_size = len(encoded.encode("utf-8"))
        if encoded_size > self._settings.device_max_envelope_bytes:
            raise RealtimeProtocolError("server envelope exceeds the byte limit")
        await db.execute(
            delete(DeviceOutbox).where(
                DeviceOutbox.device_id == device.id,
                DeviceOutbox.acked_at.is_not(None),
            )
        )
        count, total_bytes, oldest = (
            await db.execute(
                select(
                    func.count(DeviceOutbox.sequence),
                    func.coalesce(func.sum(DeviceOutbox.byte_size), 0),
                    func.min(DeviceOutbox.created_at),
                ).where(
                    DeviceOutbox.device_id == device.id,
                    DeviceOutbox.acked_at.is_(None),
                )
            )
        ).one()
        if int(count) >= self._settings.device_max_outbox_frames:
            raise RealtimeProtocolError("device outbox frame limit reached")
        if int(total_bytes) + encoded_size > self._settings.device_max_outbox_bytes:
            raise RealtimeProtocolError("device outbox byte limit reached")
        now = datetime.now(UTC)
        if oldest is not None and _utc(oldest) <= now - timedelta(
            seconds=self._settings.device_outbox_retention_seconds
        ):
            raise RealtimeProtocolError("device outbox retention limit reached")
        db.add(
            DeviceOutbox(
                device_id=device.id,
                sequence=sequence,
                encoded_envelope=encoded,
                ack_sequence=device.last_device_sequence,
                frame_type=envelope_type,
                byte_size=encoded_size,
                created_at=now,
                retained_until=now
                + timedelta(seconds=self._settings.device_outbox_retention_seconds),
            )
        )
        device.last_server_sequence = sequence
        connection_row = await db.scalar(
            select(DeviceConnection).where(
                DeviceConnection.connection_nonce == connection.connection_nonce
            )
        )
        if connection_row is not None:
            connection_row.last_server_sequence = sequence
        return sequence, encoded

    async def _replay_outbox(self, connection: ActiveDeviceSocket) -> None:
        async with connection.send_lock:
            async with self._database.session_factory() as db:
                device = await self._lock_active_device(db, connection)
                first = device.last_server_acked_sequence + 1
                last = device.last_server_sequence
                rows = list(
                    (
                        await db.scalars(
                            select(DeviceOutbox)
                            .where(
                                DeviceOutbox.device_id == connection.device_id,
                                DeviceOutbox.sequence >= first,
                                DeviceOutbox.sequence <= last,
                            )
                            .order_by(DeviceOutbox.sequence)
                        )
                    ).all()
                )
                if last - first + 1 > self._settings.device_max_outbox_frames:
                    raise RealtimeProtocolError("device outbox replay exceeds the safety limit")
                expected = list(range(first, last + 1))
                if [row.sequence for row in rows] != expected:
                    raise RealtimeProtocolError("device outbox has a durable sequence hole")
                async with asyncio.timeout(self._settings.device_hello_timeout_seconds):
                    for row in rows:
                        await connection.websocket.send_text(row.encoded_envelope)

    async def _ack_outbox_locked(
        self,
        db: AsyncSession,
        device_id: uuid.UUID,
        acknowledged_sequence: int,
        now: datetime,
    ) -> None:
        await db.execute(
            update(DeviceOutbox)
            .where(
                DeviceOutbox.device_id == device_id,
                DeviceOutbox.sequence <= acknowledged_sequence,
                DeviceOutbox.acked_at.is_(None),
            )
            .values(acked_at=now)
        )
        latest_acked = await db.scalar(
            select(func.max(DeviceOutbox.sequence)).where(
                DeviceOutbox.device_id == device_id,
                DeviceOutbox.acked_at.is_not(None),
            )
        )
        if latest_acked is not None:
            await db.execute(
                delete(DeviceOutbox).where(
                    DeviceOutbox.device_id == device_id,
                    DeviceOutbox.acked_at.is_not(None),
                    DeviceOutbox.sequence < latest_acked,
                )
            )

    async def prune_outbox(
        self,
        db: AsyncSession,
        now: datetime | None = None,
    ) -> int:
        now = now or datetime.now(UTC)
        revoked = await db.execute(
            delete(DeviceOutbox).where(
                DeviceOutbox.device_id.in_(
                    select(Device.id).where(Device.status == DeviceStatus.REVOKED)
                )
            )
        )
        cursor_reconciled = await db.execute(
            update(Device)
            .where(
                Device.status == DeviceStatus.REVOKED,
                Device.last_server_acked_sequence < Device.last_server_sequence,
            )
            .values(last_server_acked_sequence=Device.last_server_sequence)
        )
        acknowledged = await db.execute(
            delete(DeviceOutbox).where(
                DeviceOutbox.acked_at.is_not(None),
                DeviceOutbox.retained_until <= now,
            )
        )
        removed = int(revoked.rowcount or 0) + int(acknowledged.rowcount or 0)
        if removed or int(cursor_reconciled.rowcount or 0):
            await db.commit()
        return removed

    async def _refresh_registry(self, connection: ActiveDeviceSocket) -> None:
        refreshed = await self._store.compare_refresh(
            f"connection:{connection.device_id}",
            connection.registry_value,
            self._settings.device_registry_ttl_seconds,
        )
        if not refreshed:
            raise StaleConnection("connection registry ownership was lost")

    async def _start_device_dispatch(
        self,
        connection: ActiveDeviceSocket,
        activation: asyncio.Event | None = None,
    ) -> asyncio.Task[None]:
        ready = asyncio.Event()
        dispatch_task = asyncio.create_task(
            self._device_dispatch_loop(connection, ready, activation)
        )
        ready_task = asyncio.create_task(ready.wait())
        try:
            done, _ = await asyncio.wait(
                {dispatch_task, ready_task},
                timeout=self._settings.device_hello_timeout_seconds,
                return_when=asyncio.FIRST_COMPLETED,
            )
        except BaseException:
            ready_task.cancel()
            dispatch_task.cancel()
            await asyncio.gather(ready_task, dispatch_task, return_exceptions=True)
            raise
        if ready_task not in done or dispatch_task in done:
            ready_task.cancel()
            if dispatch_task not in done:
                dispatch_task.cancel()
            await asyncio.gather(ready_task, dispatch_task, return_exceptions=True)
            if dispatch_task in done:
                if dispatch_task.cancelled():
                    raise RealtimeProtocolError(
                        "device dispatch subscription stopped before becoming ready"
                    )
                if error := dispatch_task.exception():
                    raise error
            raise RealtimeProtocolError("device dispatch subscription did not become ready")
        try:
            await self._refresh_registry(connection)
            async with self._database.session_factory() as db:
                await self._lock_active_device(db, connection)
        except BaseException:
            dispatch_task.cancel()
            await asyncio.gather(dispatch_task, return_exceptions=True)
            raise
        return dispatch_task

    async def _device_dispatch_loop(
        self,
        connection: ActiveDeviceSocket,
        ready: asyncio.Event | None = None,
        activation: asyncio.Event | None = None,
    ) -> None:
        async for raw in self._store.subscribe(f"device-dispatch:{connection.device_id}", ready):
            if activation is not None:
                await activation.wait()
            try:
                message = json.loads(raw)
            except json.JSONDecodeError:
                continue
            kind = message.get("kind")
            if kind == "kick":
                replaced = message.get("replaced_connection_nonces")
                if (
                    isinstance(replaced, list)
                    and all(isinstance(value, str) for value in replaced)
                    and connection.connection_nonce in replaced
                ):
                    await connection.websocket.close(code=4001, reason="connection replaced")
                    return
                continue
            if kind == "command":
                try:
                    command_id = uuid.UUID(str(message.get("command_id")))
                except ValueError:
                    continue
                await self._dispatch_command(connection, command_id)
            if kind == "approval":
                try:
                    approval_id = uuid.UUID(str(message.get("approval_id")))
                except ValueError:
                    continue
                await self._dispatch_approval(connection, approval_id)

    async def _heartbeat_watchdog(self, connection: ActiveDeviceSocket) -> None:
        interval = max(1.0, self._settings.device_heartbeat_timeout_seconds / 3)
        while True:
            await asyncio.sleep(interval)
            if (
                time.monotonic() - connection.last_activity
                > self._settings.device_heartbeat_timeout_seconds
            ):
                await connection.websocket.close(code=4000, reason="heartbeat timeout")
                return

    async def _dispatch_pending(self, connection: ActiveDeviceSocket) -> None:
        async with self._database.session_factory() as db:
            command_ids = list(
                (
                    await db.scalars(
                        select(Command.id).where(
                            Command.device_id == connection.device_id,
                            Command.status == CommandStatus.QUEUED,
                        )
                    )
                ).all()
            )
            approval_ids = list(
                (
                    await db.scalars(
                        select(Approval.id).where(
                            Approval.device_id == connection.device_id,
                            Approval.status.in_([ApprovalStatus.APPROVED, ApprovalStatus.DENIED]),
                            Approval.decision_dispatched_at.is_(None),
                            or_(
                                Approval.decision_reason.is_(None),
                                Approval.decision_reason.not_in(NON_DISPATCHABLE_APPROVAL_REASONS),
                            ),
                        )
                    )
                ).all()
            )
        for command_id in command_ids:
            await self._dispatch_command(connection, command_id)
        for approval_id in approval_ids:
            await self._dispatch_approval(connection, approval_id)

    async def _dispatch_command(
        self,
        connection: ActiveDeviceSocket,
        command_id: uuid.UUID,
    ) -> None:
        terminal_events: list[BrowserEvent] = []
        encoded: str | None = None
        transition: tuple[str, str, float | None] | None = None
        async with connection.send_lock:
            async with self._database.session_factory() as db:
                device = await self._lock_active_device(db, connection)
                await self._events.lock_owner_cursor(db, connection.owner_user_id)
                command = await db.scalar(
                    select(Command).where(Command.id == command_id).with_for_update()
                )
                if (
                    command is None
                    or command.device_id != connection.device_id
                    or command.status != CommandStatus.QUEUED
                ):
                    return
                now = datetime.now(UTC)
                if command.expires_at is None or _utc(command.expires_at) <= now:
                    previous_status = command.status
                    command.status = CommandStatus.EXPIRED
                    command.completed_at = now
                    command.error_code = "expired"
                    command.error_message = "command deadline passed before dispatch"
                    terminal_events = await self._record_terminal_dispatch_rejection(
                        db,
                        command,
                        now,
                        audit_action="command.expire",
                        audit_outcome=AuditOutcome.FAILED,
                        reason="expired_before_dispatch",
                    )
                    await db.commit()
                    transition = (
                        previous_status.value,
                        command.status.value,
                        (now - _utc(command.created_at)).total_seconds(),
                    )
                elif command.appserver_epoch != connection.epoch:
                    previous_status = command.status
                    command.status = CommandStatus.DENIED
                    command.completed_at = now
                    command.error_code = "invalid_epoch"
                    command.error_message = "command belongs to a stale app-server epoch"
                    terminal_events = await self._record_terminal_dispatch_rejection(
                        db,
                        command,
                        now,
                        audit_action="command.dispatch_reject",
                        audit_outcome=AuditOutcome.DENIED,
                        reason="stale_epoch",
                    )
                    await db.commit()
                    transition = (
                        previous_status.value,
                        command.status.value,
                        (now - _utc(command.created_at)).total_seconds(),
                    )
                else:
                    payload = {
                        "command_id": str(command.id),
                        "idempotency_key": wire_idempotency_key(
                            command.idempotency_scope, command.idempotency_key
                        ),
                        "method": command.method,
                        "params": command.payload,
                        "deadline_at": _iso(_utc(command.expires_at)),
                    }
                    _, encoded = await self._persist_envelope_locked(
                        db,
                        connection,
                        device,
                        "command",
                        payload,
                    )
                    command.status = CommandStatus.DISPATCHED
                    command.dispatched_at = now
                    await db.commit()
                    transition = (
                        CommandStatus.QUEUED.value,
                        CommandStatus.DISPATCHED.value,
                        None,
                    )
            if transition is not None:
                self._metrics.command_transition(
                    transition[0], transition[1], duration_seconds=transition[2]
                )
            for event in terminal_events:
                try:
                    await self._events.publish(connection.owner_user_id, event)
                except Exception:
                    _LOGGER.exception(
                        "failed to publish durable terminal command event",
                        extra={"command_id": str(command_id)},
                    )
            if encoded is not None:
                await self._send_if_active(connection, [encoded])

    async def _record_terminal_dispatch_rejection(
        self,
        db: AsyncSession,
        command: Command,
        now: datetime,
        *,
        audit_action: str,
        audit_outcome: AuditOutcome,
        reason: str,
    ) -> list[BrowserEvent]:
        db.add(
            AuditEvent(
                actor_user_id=command.owner_user_id,
                actor_device_id=command.device_id,
                action=audit_action,
                outcome=audit_outcome,
                resource_type="command",
                resource_id=str(command.id),
                details={
                    "device_id": str(command.device_id),
                    "method": command.method,
                    "reason": reason,
                },
            )
        )
        events = [
            await self._events.append(
                db,
                owner_user_id=command.owner_user_id,
                device_id=command.device_id,
                thread_binding_id=command.thread_binding_id,
                event_type="command.updated",
                data={
                    "device_id": str(command.device_id),
                    "command": command_view(command).model_dump(mode="json"),
                },
            )
        ]
        binding = (
            await db.scalar(
                select(ThreadBinding)
                .where(
                    ThreadBinding.id == command.thread_binding_id,
                    ThreadBinding.device_id == command.device_id,
                    ThreadBinding.owner_user_id == command.owner_user_id,
                )
                .with_for_update()
            )
            if command.thread_binding_id is not None
            else None
        )
        if binding is not None and repair_binding_for_terminal_command(binding, command, now):
            events.append(
                await self._events.append(
                    db,
                    owner_user_id=command.owner_user_id,
                    device_id=command.device_id,
                    thread_binding_id=binding.id,
                    event_type="thread.updated",
                    data=thread_event_data(binding),
                )
            )
        return events

    async def _reconcile_stale_epoch_commands(
        self,
        db: AsyncSession,
        device: Device,
        current_epoch: str,
        now: datetime,
        *,
        observations: list[tuple[str, int]] | None = None,
        command_transitions: list[tuple[str, str, float]] | None = None,
    ) -> list[BrowserEvent]:
        """Terminalize work that cannot be resumed by a replacement app-server."""

        await self._events.lock_owner_cursor(db, device.owner_user_id)
        commands = list(
            (
                await db.scalars(
                    select(Command)
                    .where(
                        Command.device_id == device.id,
                        Command.owner_user_id == device.owner_user_id,
                        Command.appserver_epoch != current_epoch,
                        Command.status.in_(
                            (
                                CommandStatus.QUEUED,
                                CommandStatus.DISPATCHED,
                                CommandStatus.ACKNOWLEDGED,
                            )
                        ),
                    )
                    .order_by(Command.created_at, Command.id)
                    .with_for_update()
                )
            ).all()
        )
        events: list[BrowserEvent] = []
        for command in commands:
            previous_status = command.status
            queued = command.status == CommandStatus.QUEUED
            if queued:
                command.status = CommandStatus.DENIED
                command.error_code = "invalid_epoch"
                command.error_message = "command belonged to an app-server epoch that was replaced"
                audit_action = "command.dispatch_reject"
                audit_outcome = AuditOutcome.DENIED
                reason = "stale_epoch_before_dispatch"
            else:
                # Once a frame may have reached the old child process, retrying it
                # could duplicate a mutation. Report uncertainty and require an
                # explicit read/resume instead of guessing that execution failed.
                command.status = CommandStatus.FAILED
                command.error_code = "epoch_replaced_indeterminate"
                command.error_message = (
                    "app-server epoch ended before a terminal acknowledgement; "
                    "execution state is indeterminate"
                )
                audit_action = "command.epoch_reconcile"
                audit_outcome = AuditOutcome.FAILED
                reason = "epoch_replaced_indeterminate"
            command.completed_at = now
            command.result = None
            events.extend(
                await self._record_terminal_dispatch_rejection(
                    db,
                    command,
                    now,
                    audit_action=audit_action,
                    audit_outcome=audit_outcome,
                    reason=reason,
                )
            )
            if command_transitions is not None:
                command_transitions.append(
                    (
                        previous_status.value,
                        command.status.value,
                        (now - _utc(command.created_at)).total_seconds(),
                    )
                )
        await db.flush()
        stale_bindings = list(
            (
                await db.scalars(
                    select(ThreadBinding)
                    .where(
                        ThreadBinding.device_id == device.id,
                        ThreadBinding.owner_user_id == device.owner_user_id,
                        ThreadBinding.appserver_epoch != current_epoch,
                        ThreadBinding.status.in_(
                            (
                                ThreadBindingStatus.IDLE,
                                ThreadBindingStatus.RUNNING,
                                ThreadBindingStatus.WAITING_FOR_APPROVAL,
                            )
                        ),
                    )
                    .order_by(ThreadBinding.created_at, ThreadBinding.id)
                    .with_for_update()
                )
            ).all()
        )
        for binding in stale_bindings:
            previous_epoch = binding.appserver_epoch
            binding.status = ThreadBindingStatus.FAILED
            binding.active_turn_id = None
            binding.last_error = "app-server epoch was replaced; resume the thread to continue"
            binding.updated_at = now
            db.add(
                AuditEvent(
                    actor_user_id=device.owner_user_id,
                    actor_device_id=device.id,
                    action="thread.epoch_reconcile",
                    outcome=AuditOutcome.FAILED,
                    resource_type="thread_binding",
                    resource_id=str(binding.id),
                    details={
                        "old_epoch": previous_epoch,
                        "current_epoch": current_epoch,
                        "reason": "resume_required_after_epoch_replacement",
                    },
                )
            )
            events.append(
                await self._events.append(
                    db,
                    owner_user_id=device.owner_user_id,
                    device_id=device.id,
                    thread_binding_id=binding.id,
                    event_type="thread.updated",
                    data=self._thread_event_data(binding),
                )
            )
        if observations is not None:
            observations.extend(
                (
                    ("command_stale_epoch", len(commands)),
                    ("thread_stale_epoch", len(stale_bindings)),
                )
            )
        return events

    async def _dispatch_approval(
        self,
        connection: ActiveDeviceSocket,
        approval_id: uuid.UUID,
    ) -> None:
        async with connection.send_lock:
            async with self._database.session_factory() as db:
                device = await self._lock_active_device(db, connection)
                approval = await db.scalar(
                    select(Approval).where(Approval.id == approval_id).with_for_update()
                )
                if (
                    approval is None
                    or approval.device_id != connection.device_id
                    or approval.status not in {ApprovalStatus.APPROVED, ApprovalStatus.DENIED}
                    or approval.decision_dispatched_at is not None
                    or approval.appserver_epoch != connection.epoch
                    or approval.decision_reason in NON_DISPATCHABLE_APPROVAL_REASONS
                ):
                    return
                decision = "approve" if approval.status == ApprovalStatus.APPROVED else "deny"
                payload = {
                    "approval_id": str(approval.id),
                    "decision": decision,
                    "decided_at": _iso(_utc(approval.decided_at or datetime.now(UTC))),
                }
                _, encoded = await self._persist_envelope_locked(
                    db,
                    connection,
                    device,
                    "approval_decision",
                    payload,
                )
                approval.decision_dispatched_at = datetime.now(UTC)
                await db.commit()
            await self._send_if_active(connection, [encoded])

    async def _apply_command_ack(
        self,
        connection: ActiveDeviceSocket,
        envelope: ControlEnvelope,
    ) -> None:
        effects = FrameEffects()
        async with self._database.session_factory() as db:
            await self._apply_command_ack_tx(db, connection, envelope, effects)
            await db.commit()
        for from_status, to_status, duration in effects.command_transitions:
            self._metrics.command_transition(
                from_status,
                to_status,
                duration_seconds=duration,
            )
        for event in effects.browser_events:
            await self._events.publish(connection.owner_user_id, event)

    async def _apply_command_ack_tx(
        self,
        db: AsyncSession,
        connection: ActiveDeviceSocket,
        envelope: ControlEnvelope,
        effects: FrameEffects,
    ) -> None:
        payload = CommandAckPayload.model_validate(envelope.payload)
        now = datetime.now(UTC)
        device = await db.scalar(
            select(Device)
            .where(
                Device.id == connection.device_id,
                Device.owner_user_id == connection.owner_user_id,
            )
            .with_for_update()
        )
        if device is None:
            return
        await self._events.lock_owner_cursor(db, connection.owner_user_id)
        command = await db.scalar(
            select(Command)
            .where(
                Command.id == payload.command_id,
                Command.device_id == connection.device_id,
                Command.owner_user_id == connection.owner_user_id,
            )
            .with_for_update()
        )
        if command is None:
            return
        if command.appserver_epoch != envelope.epoch:
            raise RealtimeProtocolError("command acknowledgement belongs to a stale epoch")
        current_epoch = envelope.epoch == connection.epoch
        terminal_wire_states = {"completed", "failed", "expired", "denied"}
        if not current_epoch:
            if not (
                command.status == CommandStatus.FAILED
                and command.error_code == "epoch_replaced_indeterminate"
                and payload.state in terminal_wire_states
            ):
                return
            states = {
                "completed": CommandStatus.SUCCEEDED,
                "failed": CommandStatus.FAILED,
                "expired": CommandStatus.EXPIRED,
                "denied": CommandStatus.DENIED,
            }
            previous_error_code = command.error_code
            previous_status = command.status
            command.status = states[payload.state]
            command.completed_at = now
            command.result = payload.result
            command.error_code = payload.error.code if payload.error is not None else None
            command.error_message = payload.error.message if payload.error is not None else None
            db.add(
                AuditEvent(
                    actor_user_id=connection.owner_user_id,
                    actor_device_id=connection.device_id,
                    action="command.epoch_terminal_refine",
                    outcome=(
                        AuditOutcome.SUCCEEDED
                        if command.status == CommandStatus.SUCCEEDED
                        else AuditOutcome.FAILED
                    ),
                    resource_type="command",
                    resource_id=str(command.id),
                    details={
                        "epoch": envelope.epoch,
                        "state": payload.state,
                        "previous_error_code": previous_error_code,
                    },
                )
            )
            await db.flush()
            effects.browser_events.append(
                await self._events.append(
                    db=db,
                    owner_user_id=connection.owner_user_id,
                    device_id=connection.device_id,
                    thread_binding_id=command.thread_binding_id,
                    event_type="command.updated",
                    data={
                        "device_id": str(connection.device_id),
                        "command": command_view(command).model_dump(mode="json"),
                    },
                )
            )
            effects.command_transitions.append(
                (
                    previous_status.value,
                    command.status.value,
                    (now - _utc(command.created_at)).total_seconds(),
                )
            )
            return
        if command.status in {
            CommandStatus.SUCCEEDED,
            CommandStatus.FAILED,
            CommandStatus.DENIED,
            CommandStatus.CANCELLED,
            CommandStatus.EXPIRED,
        }:
            return
        states = {
            "accepted": CommandStatus.ACKNOWLEDGED,
            "running": CommandStatus.ACKNOWLEDGED,
            "completed": CommandStatus.SUCCEEDED,
            "failed": CommandStatus.FAILED,
            "expired": CommandStatus.EXPIRED,
            "denied": CommandStatus.DENIED,
        }
        previous_status = command.status
        command.status = states[payload.state]
        if payload.state in {"accepted", "running"}:
            command.acknowledged_at = now
        else:
            command.completed_at = now
        command.result = payload.result
        if payload.error is not None:
            command.error_code = payload.error.code
            command.error_message = payload.error.message
        projected_bindings: list[ThreadBinding] = []
        if (
            current_epoch
            and command.method == "model/list"
            and command.status == CommandStatus.SUCCEEDED
        ):
            device.model_catalog = bounded_model_catalog(payload.result, self._settings)
            device.model_catalog_updated_at = now
        if (
            current_epoch
            and command.method == "thread/list"
            and command.status == CommandStatus.SUCCEEDED
        ):
            projected_bindings = await self._project_thread_list(
                db,
                device,
                connection.owner_user_id,
                envelope.epoch,
                payload.result,
                now,
            )
        binding = (
            await db.scalar(
                select(ThreadBinding)
                .where(
                    ThreadBinding.id == command.thread_binding_id,
                    ThreadBinding.device_id == command.device_id,
                    ThreadBinding.owner_user_id == command.owner_user_id,
                )
                .with_for_update()
            )
            if command.thread_binding_id
            else None
        )
        resume_migrates_epoch = (
            binding is not None
            and command.method == "thread/resume"
            and command.status == CommandStatus.SUCCEEDED
            and command.payload.get("threadId") == binding.remote_thread_id
        )
        if binding is not None and (
            binding.appserver_epoch == envelope.epoch or resume_migrates_epoch
        ):
            self._apply_command_to_binding(binding, command, payload, envelope.epoch)
            try:
                ensure_thread_projection_fits(binding)
            except OwnerCapacityExceeded as exc:
                raise RealtimeProtocolError(exc.code) from exc
        else:
            binding = None
        await db.flush()
        effects.browser_events.append(
            await self._events.append(
                db=db,
                owner_user_id=connection.owner_user_id,
                device_id=connection.device_id,
                thread_binding_id=command.thread_binding_id,
                event_type="command.updated",
                data={
                    "device_id": str(connection.device_id),
                    "command": command_view(command).model_dump(mode="json"),
                },
            )
        )
        if binding is not None:
            effects.browser_events.append(
                await self._events.append(
                    db,
                    owner_user_id=connection.owner_user_id,
                    device_id=connection.device_id,
                    thread_binding_id=command.thread_binding_id,
                    event_type="thread.updated",
                    data=self._thread_event_data(binding),
                )
            )
        for projected in projected_bindings:
            effects.browser_events.append(
                await self._events.append(
                    db,
                    owner_user_id=connection.owner_user_id,
                    device_id=connection.device_id,
                    thread_binding_id=projected.id,
                    event_type="thread.updated",
                    data=self._thread_event_data(projected),
                )
            )
        effects.command_transitions.append(
            (
                previous_status.value,
                command.status.value,
                (
                    (now - _utc(command.created_at)).total_seconds()
                    if command.status.value in COMMAND_TERMINAL_STATUSES
                    else None
                ),
            )
        )

    async def _project_thread_list(
        self,
        db: AsyncSession,
        device: Device,
        owner_user_id: str,
        epoch: str,
        result: Any,
        now: datetime,
    ) -> list[ThreadBinding]:
        candidates: Any = None
        if isinstance(result, dict):
            for key in ("data", "threads", "items"):
                if isinstance(result.get(key), list):
                    candidates = result[key]
                    break
        if not isinstance(candidates, list):
            return []

        projected: list[ThreadBinding] = []
        visible_count = await visible_thread_count(db, owner_user_id)
        total_count = await total_thread_count(db, owner_user_id)
        for raw in candidates[:500]:
            if not isinstance(raw, dict):
                continue
            remote_id = _extract_string(raw, "id", "threadId", "thread_id")
            cwd = _extract_string(raw, "cwd")
            if (
                not remote_id
                or len(remote_id) > 255
                or not cwd
                or not _cwd_in_roots(cwd, device.workspace_roots)
            ):
                continue
            binding = await db.scalar(
                select(ThreadBinding).where(
                    ThreadBinding.device_id == device.id,
                    ThreadBinding.owner_user_id == owner_user_id,
                    ThreadBinding.remote_thread_id == remote_id,
                )
            )
            title = _extract_string(raw, "name", "title", "preview") or "Managed thread"
            title = title.strip()[:255] or "Managed thread"
            created_at = _wire_timestamp(raw.get("createdAt"), now)
            updated_at = _wire_timestamp(raw.get("updatedAt"), now)
            status = _wire_thread_status(raw.get("status"))
            if binding is None:
                if (
                    visible_count >= self._settings.bootstrap_max_threads
                    or total_count >= self._settings.owner_max_thread_records
                ):
                    continue
                binding = ThreadBinding(
                    id=uuid.uuid4(),
                    owner_user_id=owner_user_id,
                    device_id=device.id,
                    remote_thread_id=remote_id,
                    status=status,
                    cwd=cwd,
                    title=title,
                    model="",
                    appserver_epoch=epoch,
                    snapshot={"messages": []},
                    created_at=created_at,
                    updated_at=updated_at,
                )
                try:
                    ensure_thread_projection_fits(binding)
                except OwnerCapacityExceeded:
                    continue
                db.add(binding)
                await db.flush()
                visible_count += 1
                total_count += 1
            else:
                if (
                    binding.status in {ThreadBindingStatus.CLOSED, ThreadBindingStatus.STALE}
                    and status not in {ThreadBindingStatus.CLOSED, ThreadBindingStatus.STALE}
                    and visible_count >= self._settings.bootstrap_max_threads
                ):
                    continue
                if binding.status in {
                    ThreadBindingStatus.CLOSED,
                    ThreadBindingStatus.STALE,
                } and status not in {ThreadBindingStatus.CLOSED, ThreadBindingStatus.STALE}:
                    visible_count += 1
                binding.cwd = cwd
                binding.title = title
                binding.status = status
                binding.appserver_epoch = epoch
                binding.updated_at = updated_at
                try:
                    ensure_thread_projection_fits(binding)
                except OwnerCapacityExceeded as exc:
                    raise RealtimeProtocolError(exc.code) from exc
            projected.append(binding)
        return projected

    def _apply_command_to_binding(
        self,
        binding: ThreadBinding,
        command: Command,
        payload: CommandAckPayload,
        epoch: str,
    ) -> None:
        if command.status in {
            CommandStatus.FAILED,
            CommandStatus.DENIED,
            CommandStatus.EXPIRED,
        }:
            binding.status = ThreadBindingStatus.FAILED
            binding.last_error = command.error_message or command.error_code
            return
        if command.status != CommandStatus.SUCCEEDED:
            return
        result = payload.result
        if command.method == "thread/start":
            remote_thread_id = _extract_string(result, "threadId", "thread_id", "id")
            if remote_thread_id:
                binding.remote_thread_id = remote_thread_id
            binding.status = ThreadBindingStatus.IDLE
            binding.appserver_epoch = epoch
        elif command.method == "thread/read" and isinstance(result, dict):
            try:
                binding.snapshot = self._snapshot_from_result(result, binding.snapshot)
            except ThreadSnapshotTooLarge as exc:
                raise RealtimeProtocolError(
                    "projected thread snapshot exceeds the byte limit"
                ) from exc
            projected_thread = result.get("thread")
            if not isinstance(projected_thread, dict):
                projected_thread = result
            if "status" in projected_thread:
                binding.status = _wire_thread_status(projected_thread.get("status"))
                active_turn_id = None
                if binding.status == ThreadBindingStatus.RUNNING:
                    turns = projected_thread.get("turns")
                    if isinstance(turns, list):
                        for candidate in reversed(turns):
                            if not isinstance(candidate, dict):
                                continue
                            if _wire_thread_status(candidate.get("status")) != (
                                ThreadBindingStatus.RUNNING
                            ):
                                continue
                            active_turn_id = _extract_string(candidate, "id", "turnId", "turn_id")
                            if active_turn_id:
                                break
                binding.active_turn_id = active_turn_id
        elif command.method == "thread/resume":
            binding.status = ThreadBindingStatus.IDLE
            binding.appserver_epoch = epoch
        elif command.method == "turn/start":
            binding.status = ThreadBindingStatus.RUNNING
            binding.active_turn_id = _extract_string(result, "turnId", "turn_id", "id")
        elif command.method == "turn/interrupt":
            binding.status = ThreadBindingStatus.IDLE
            binding.active_turn_id = None

    async def _apply_device_event(
        self,
        connection: ActiveDeviceSocket,
        envelope: ControlEnvelope,
    ) -> None:
        effects = FrameEffects()
        async with self._database.session_factory() as db:
            await self._apply_device_event_tx(db, connection, envelope, effects)
            await db.commit()
        for event in effects.browser_events:
            await self._events.publish(connection.owner_user_id, event)

    async def _apply_device_event_tx(
        self,
        db: AsyncSession,
        connection: ActiveDeviceSocket,
        envelope: ControlEnvelope,
        effects: FrameEffects,
    ) -> None:
        event = DeviceEventPayload.model_validate(envelope.payload)
        if event.method not in ALLOWED_DEVICE_EVENTS:
            raise RealtimeProtocolError("device event method is not allowlisted")
        device = await db.scalar(
            select(Device)
            .where(
                Device.id == connection.device_id,
                Device.owner_user_id == connection.owner_user_id,
            )
            .with_for_update()
        )
        if device is None:
            return
        await self._events.lock_owner_cursor(db, connection.owner_user_id)
        remote_thread_id = _extract_string(event.params, "threadId", "thread_id")
        browser_type = "thread.updated"
        browser_data: dict[str, Any] | None = None
        binding_id: uuid.UUID | None = None
        binding = None
        if remote_thread_id:
            binding = await db.scalar(
                select(ThreadBinding)
                .where(
                    ThreadBinding.device_id == connection.device_id,
                    ThreadBinding.owner_user_id == connection.owner_user_id,
                    ThreadBinding.remote_thread_id == remote_thread_id,
                    ThreadBinding.appserver_epoch == envelope.epoch,
                )
                .with_for_update()
            )
        if binding is not None:
            binding_id = binding.id
            completed_turn_id = None
            if event.method == "thread/name/updated":
                title = _extract_string(event.params, "name", "title")
                if title:
                    binding.title = title.strip()[:255] or binding.title
            if event.method == "thread/status/changed":
                status_value = _extract_string(event.params, "status")
                binding.status = _thread_status(status_value) or binding.status
            if event.method == "turn/started":
                binding.status = ThreadBindingStatus.RUNNING
                binding.active_turn_id = _extract_string(event.params, "turnId", "turn_id", "id")
            if event.method == "turn/completed":
                completed_turn_id = (
                    _extract_string(event.params, "turnId", "turn_id", "id")
                    or binding.active_turn_id
                )
                binding.status = ThreadBindingStatus.IDLE
                binding.active_turn_id = None
                browser_type = "turn.completed"
            if event.method == "item/agentMessage/delta":
                normalized_delta = self._append_delta(binding, event.params)
                if normalized_delta is not None:
                    message_id, delta = normalized_delta
                    browser_type = "turn.delta"
                    browser_data = {
                        "thread_id": str(binding.id),
                        "device_id": str(binding.device_id),
                        "message_id": message_id,
                        "delta": delta,
                    }
            if event.method == "error":
                binding.status = ThreadBindingStatus.FAILED
                binding.last_error = _extract_string(event.params, "message", "error")
            binding.updated_at = datetime.now(UTC)
            try:
                ensure_thread_projection_fits(binding)
            except OwnerCapacityExceeded as exc:
                raise RealtimeProtocolError(exc.code) from exc
            await db.flush()
            if browser_data is None:
                browser_data = self._thread_event_data(binding)
                browser_data["method"] = event.method
                if completed_turn_id:
                    browser_data["turn_id"] = completed_turn_id
        if browser_data is None or binding_id is None:
            return
        effects.browser_events.append(
            await self._events.append(
                db,
                owner_user_id=connection.owner_user_id,
                device_id=connection.device_id,
                thread_binding_id=binding_id,
                event_type=browser_type,
                data=browser_data,
                occurred_at=envelope.sent_at,
            )
        )

    async def _apply_approval_request(
        self,
        connection: ActiveDeviceSocket,
        envelope: ControlEnvelope,
    ) -> None:
        effects = FrameEffects()
        async with self._database.session_factory() as db:
            await self._apply_approval_request_tx(db, connection, envelope, effects)
            await db.commit()
        for outcome, reason in effects.approval_outcomes:
            self._metrics.approval_outcome(outcome, reason)
        for event in effects.browser_events:
            await self._events.publish(connection.owner_user_id, event)
        for approval_id in effects.approval_dispatches:
            await self._store.publish(
                f"device-dispatch:{connection.device_id}",
                json.dumps({"kind": "approval", "approval_id": str(approval_id)}),
            )

    async def _apply_approval_request_tx(
        self,
        db: AsyncSession,
        connection: ActiveDeviceSocket,
        envelope: ControlEnvelope,
        effects: FrameEffects,
    ) -> None:
        payload = ApprovalRequestPayload.model_validate(envelope.payload)
        now = datetime.now(UTC)
        device = await db.scalar(
            select(Device)
            .where(
                Device.id == connection.device_id,
                Device.owner_user_id == connection.owner_user_id,
            )
            .with_for_update()
        )
        if device is None:
            raise RealtimeProtocolError("approval device is unavailable")
        await self._events.lock_owner_cursor(db, connection.owner_user_id)
        requested_expiry = min(
            _utc(payload.expires_at),
            now + timedelta(seconds=self._settings.approval_ttl_seconds),
        )
        request_hash = _approval_request_hash(payload)
        command_id: uuid.UUID | None = None
        try:
            candidate = uuid.UUID(payload.command_id)
        except ValueError:
            candidate = None
        existing = await db.get(Approval, payload.approval_id)
        if existing is not None:
            if (
                existing.device_id != connection.device_id
                or existing.appserver_epoch != envelope.epoch
            ):
                raise RealtimeProtocolError("approval id was replayed across devices or epochs")
            if not hmac.compare_digest(existing.request_hash, request_hash):
                raise RealtimeProtocolError("approval id was replayed with a different request")
            return
        try:
            await ensure_approval_record_capacity_locked(
                db,
                self._settings,
                connection.owner_user_id,
                connection.device_id,
            )
        except OwnerCapacityExceeded as exc:
            raise RealtimeProtocolError(exc.code) from exc
        command = None
        if candidate is not None:
            command = await db.scalar(
                select(Command).where(
                    Command.id == candidate,
                    Command.device_id == connection.device_id,
                    Command.appserver_epoch == envelope.epoch,
                )
            )
            if command is not None:
                command_id = command.id
        denial_reason: str | None = None
        if requested_expiry <= now:
            denial_reason = "expired_on_arrival_default_deny"
        else:
            denial_reason = await approval_capacity_denial_reason_locked(
                db,
                self._settings,
                connection.owner_user_id,
                connection.device_id,
                now,
            )
        stored_expiry = (
            requested_expiry if requested_expiry > now else now + timedelta(microseconds=1)
        )
        approval = Approval(
            id=payload.approval_id,
            owner_user_id=connection.owner_user_id,
            device_id=connection.device_id,
            command_id=command_id,
            external_command_id=payload.command_id if denial_reason is None else None,
            approval_kind=payload.kind,
            summary=payload.summary if denial_reason is None else "Approval denied",
            request=payload.details if denial_reason is None else {},
            request_hash=request_hash,
            status=ApprovalStatus.PENDING if denial_reason is None else ApprovalStatus.DENIED,
            appserver_epoch=envelope.epoch,
            requested_at=now,
            expires_at=stored_expiry,
            decided_at=now if denial_reason is not None else None,
            decision_reason=denial_reason,
        )
        if denial_reason is None:
            try:
                ensure_approval_projection_fits(approval, device)
            except OwnerCapacityExceeded:
                denial_reason = "approval_size_default_deny"
                approval.status = ApprovalStatus.DENIED
                approval.decided_at = now
                approval.decision_reason = denial_reason
                approval.external_command_id = None
                approval.summary = "Approval denied"
                approval.request = {}
        db.add(approval)
        updated_binding: ThreadBinding | None = None
        if denial_reason is None and command is not None and command.thread_binding_id is not None:
            binding = await db.get(ThreadBinding, command.thread_binding_id)
            if binding is not None and binding.appserver_epoch == envelope.epoch:
                binding.status = ThreadBindingStatus.WAITING_FOR_APPROVAL
                updated_binding = binding
        db.add(
            AuditEvent(
                actor_user_id=connection.owner_user_id,
                actor_device_id=connection.device_id,
                action="approval.request",
                outcome=(AuditOutcome.SUCCEEDED if denial_reason is None else AuditOutcome.DENIED),
                resource_type="approval",
                resource_id=str(approval.id),
                details={
                    "kind": payload.kind,
                    "epoch": envelope.epoch,
                    "default_deny_reason": denial_reason,
                },
            )
        )
        await db.flush()
        if denial_reason is None:
            event_type = "approval.created"
            data = self._approvals.item(approval, device).model_dump(mode="json")
        else:
            event_type = "approval.resolved"
            data = {
                "approval_id": str(approval.id),
                "decision": "deny",
                "reason": denial_reason,
            }
        effects.browser_events.append(
            await self._events.append(
                db,
                owner_user_id=connection.owner_user_id,
                device_id=connection.device_id,
                event_type=event_type,
                data=data,
            )
        )
        if updated_binding is not None:
            effects.browser_events.append(
                await self._events.append(
                    db,
                    owner_user_id=connection.owner_user_id,
                    device_id=connection.device_id,
                    thread_binding_id=updated_binding.id,
                    event_type="thread.updated",
                    data=self._thread_event_data(updated_binding),
                )
            )
        if denial_reason is not None:
            effects.approval_dispatches.append(approval.id)
            effects.approval_outcomes.append(("denied", denial_reason))
        else:
            effects.approval_outcomes.append(("requested", "device_request"))

    async def _end_connection(
        self,
        connection: ActiveDeviceSocket,
        reason: str,
    ) -> None:
        async with connection.send_lock:
            await self._hub.unregister(connection)
            await self._store.compare_delete(
                f"connection:{connection.device_id}",
                connection.registry_value,
            )
            events: list[BrowserEvent] = []
            async with self._database.session_factory() as db:
                device = await db.scalar(
                    select(Device).where(Device.id == connection.device_id).with_for_update()
                )
                connection_row = await db.scalar(
                    select(DeviceConnection)
                    .where(DeviceConnection.connection_nonce == connection.connection_nonce)
                    .with_for_update()
                )
                if (
                    connection_row is not None
                    and connection_row.status == ConnectionStatus.CONNECTED
                ):
                    connection_row.status = ConnectionStatus.DISCONNECTED
                    connection_row.disconnected_at = datetime.now(UTC)
                    connection_row.closed_reason = reason
                is_current = (
                    device is not None
                    and device.active_connection_nonce == connection.connection_nonce
                )
                if device is not None and is_current:
                    device.active_connection_nonce = None
                    events.extend(await self._approvals.deny_disconnected(db, device))
                    events.append(
                        await self._events.append(
                            db,
                            owner_user_id=device.owner_user_id,
                            device_id=device.id,
                            event_type="device.updated",
                            data=self._device_event_data(device, "offline"),
                        )
                    )
                await db.commit()
        for event in events:
            await self._events.publish(connection.owner_user_id, event)

    async def _pump_browser_events(
        self,
        owner_user_id: str,
        queue: asyncio.Queue[None],
        ready: asyncio.Event,
    ) -> None:
        async for _event in self._store.subscribe(f"browser:{owner_user_id}", ready):
            try:
                queue.put_nowait(None)
            except asyncio.QueueFull:
                # Redis is only a wake-up path; one pending signal is sufficient.
                pass

    async def _wait_for_browser_subscription(
        self,
        ready: asyncio.Event,
        subscription_task: asyncio.Task[None],
    ) -> None:
        ready_wait = asyncio.create_task(ready.wait())
        try:
            done, _ = await asyncio.wait(
                {ready_wait, subscription_task},
                timeout=BROWSER_SESSION_SUBSCRIBE_TIMEOUT_SECONDS,
                return_when=asyncio.FIRST_COMPLETED,
            )
            if not done:
                raise TimeoutError("browser event subscription timed out")
            if subscription_task in done:
                error = subscription_task.exception()
                if error is not None:
                    raise error
                if not ready.is_set():
                    raise RuntimeError("browser event subscription ended before it was ready")
            if not ready.is_set():
                raise RuntimeError("browser event subscription was not ready")
        finally:
            if not ready_wait.done():
                ready_wait.cancel()
            await asyncio.gather(ready_wait, return_exceptions=True)

    @staticmethod
    def _raise_if_browser_dependency_ended(*tasks: asyncio.Task[None]) -> None:
        for task in tasks:
            if not task.done():
                continue
            if task.cancelled():
                raise RuntimeError("browser realtime dependency was cancelled")
            error = task.exception()
            if error is not None:
                raise error
            raise RuntimeError("browser realtime dependency ended unexpectedly")

    async def _acquire_browser_connection_lease(
        self,
        session_id: uuid.UUID,
        owner_user_id: str,
    ) -> BrowserConnectionLease:
        lease_value = f"{self._instance_id}:{uuid.uuid4()}"
        session_slot = await self._acquire_browser_lease_slot(
            f"browser-lease:session:{session_id}",
            self._settings.browser_max_connections_per_session,
            lease_value,
        )
        try:
            owner_digest = hmac.new(
                self._settings.session_hmac_secret.get_secret_value().encode("utf-8"),
                f"browser-lease-owner:{owner_user_id}".encode(),
                hashlib.sha256,
            ).hexdigest()
            user_slot = await self._acquire_browser_lease_slot(
                f"browser-lease:user:{owner_digest}",
                self._settings.browser_max_connections_per_user,
                lease_value,
            )
        except BaseException:
            cleanup = asyncio.create_task(self._release_browser_lease_slots((session_slot,)))
            try:
                await asyncio.shield(cleanup)
            except asyncio.CancelledError:
                await cleanup
            raise
        return BrowserConnectionLease(session_slot=session_slot, user_slot=user_slot)

    async def _acquire_browser_lease_slot(
        self,
        key_prefix: str,
        limit: int,
        lease_value: str,
    ) -> BrowserLeaseSlot:
        for slot in range(limit):
            key = f"{key_prefix}:{slot}"
            async with asyncio.timeout(self._settings.redis_command_timeout_seconds):
                acquired = await self._store.set_if_absent(
                    key,
                    lease_value,
                    self._settings.browser_connection_lease_ttl_seconds,
                )
            if acquired:
                return BrowserLeaseSlot(key=key, value=lease_value)
        raise BrowserConnectionLimitExceeded("browser connection lease slots are full")

    async def _renew_browser_connection_lease(
        self,
        lease: BrowserConnectionLease,
    ) -> None:
        interval = self._settings.browser_connection_lease_ttl_seconds / 3
        while True:
            await asyncio.sleep(interval)
            try:
                for slot in lease.slots:
                    async with asyncio.timeout(self._settings.redis_command_timeout_seconds):
                        refreshed = await self._store.compare_refresh(
                            slot.key,
                            slot.value,
                            self._settings.browser_connection_lease_ttl_seconds,
                        )
                    if not refreshed:
                        raise RuntimeError("browser connection lease ownership was lost")
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                _LOGGER.warning(
                    "browser connection lease renewal failed",
                    extra={"error_type": type(exc).__name__},
                )
                raise BrowserSocketClose(
                    1013,
                    "browser connection lease unavailable",
                ) from exc

    async def _release_browser_connection_lease(
        self,
        lease: BrowserConnectionLease,
    ) -> None:
        await self._release_browser_lease_slots(tuple(reversed(lease.slots)))

    async def _cleanup_browser_connection(
        self,
        tasks: set[asyncio.Task[None]],
        lease: BrowserConnectionLease,
    ) -> None:
        for task in tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        await self._release_browser_connection_lease(lease)

    async def _release_browser_lease_slots(
        self,
        slots: tuple[BrowserLeaseSlot, ...],
    ) -> None:
        for slot in slots:
            try:
                async with asyncio.timeout(self._settings.redis_command_timeout_seconds):
                    await self._store.compare_delete(slot.key, slot.value)
            except Exception as exc:
                # TTL is the crash-safe fallback; cleanup failure must not mask the
                # WebSocket's original close reason.
                _LOGGER.warning(
                    "browser connection lease cleanup failed",
                    extra={"error_type": type(exc).__name__},
                )

    async def _forward_browser_queue(
        self,
        websocket: WebSocket,
        owner_user_id: str,
        queue: asyncio.Queue[None],
        latest_cursor: list[int],
        dependency_tasks: tuple[asyncio.Task[None], ...] = (),
    ) -> None:
        while True:
            self._raise_if_browser_dependency_ended(*dependency_tasks)
            try:
                await asyncio.wait_for(
                    queue.get(),
                    timeout=BROWSER_EVENT_DB_POLL_SECONDS,
                )
            except TimeoutError:
                pass

            # Pub/Sub is only a wake-up signal. A later transaction can publish
            # first after both commits, so trusting notification order would let
            # the browser advance past an earlier durable event permanently. The
            # timeout also recovers a committed event whose Redis publish failed.
            while True:
                self._raise_if_browser_dependency_ended(*dependency_tasks)
                async with self._database.session_factory() as db:
                    try:
                        page = await self._events.catch_up_page(
                            db,
                            owner_user_id,
                            latest_cursor[0],
                        )
                    except BrowserCursorResetRequired as exc:
                        raise BrowserSocketClose(
                            4409,
                            "event cursor requires bootstrap",
                        ) from exc
                for event in page.events:
                    self._raise_if_browser_dependency_ended(*dependency_tasks)
                    await websocket.send_text(event.model_dump_json())
                    latest_cursor[0] = int(event.cursor)
                if not page.has_more:
                    break

    @staticmethod
    async def _browser_receive_loop(websocket: WebSocket) -> None:
        message = await websocket.receive_text()
        if message == "close":
            raise BrowserSocketClose(1000, "client requested close")
        raise BrowserSocketClose(1008, "browser event channel is server-only")

    async def _monitor_browser_session(
        self,
        session_id: uuid.UUID,
        ready: asyncio.Event,
    ) -> None:
        subscription_ready = asyncio.Event()
        subscription = self._store.subscribe(
            control_session_revocation_channel(session_id),
            subscription_ready,
        )
        next_signal: asyncio.Task[str] | None = None
        subscription_ready_wait: asyncio.Task[bool] | None = None
        try:
            # Starting iteration performs the actual Redis SUBSCRIBE. Rechecking the
            # durable row only after it is ready closes the authenticate/subscribe race.
            next_signal = asyncio.create_task(anext(subscription))
            subscription_ready_wait = asyncio.create_task(subscription_ready.wait())
            done, _ = await asyncio.wait(
                {next_signal, subscription_ready_wait},
                timeout=BROWSER_SESSION_SUBSCRIBE_TIMEOUT_SECONDS,
                return_when=asyncio.FIRST_COMPLETED,
            )
            if not done:
                raise TimeoutError("control session revocation subscription timed out")
            if next_signal in done:
                error = next_signal.exception()
                if error is not None:
                    raise error
            if not subscription_ready.is_set():
                raise RuntimeError("control session revocation subscription was not ready")
            if not subscription_ready_wait.done():
                subscription_ready_wait.cancel()
            await asyncio.gather(subscription_ready_wait, return_exceptions=True)
            subscription_ready_wait = None
            expires_at = await self._active_browser_session_expiry(session_id)
            if expires_at is None:
                raise BrowserSocketClose(4401, "control session expired")
            ready.set()

            expected_signal = str(session_id)
            while True:
                remaining = (expires_at - datetime.now(UTC)).total_seconds()
                if remaining <= 0:
                    raise BrowserSocketClose(4401, "control session expired")
                done, _ = await asyncio.wait(
                    {next_signal},
                    timeout=min(BROWSER_SESSION_RECHECK_SECONDS, remaining),
                )
                if next_signal in done:
                    signal = next_signal.result()
                    next_signal = asyncio.create_task(anext(subscription))
                    if signal != expected_signal:
                        raise RuntimeError("invalid control session revocation signal")

                # Pub/Sub is only a prompt. PostgreSQL remains the authority, and
                # the periodic check covers a publish lost after a durable revoke.
                expires_at = await self._active_browser_session_expiry(session_id)
                if expires_at is None:
                    raise BrowserSocketClose(4401, "control session expired")
        except asyncio.CancelledError:
            raise
        except BrowserSocketClose:
            raise
        except Exception as exc:
            _LOGGER.warning(
                "browser session monitor dependency failed",
                extra={"error_type": type(exc).__name__},
            )
            raise BrowserSocketClose(
                1013,
                "control session verification unavailable",
            ) from exc
        finally:
            ready.set()
            if subscription_ready_wait is not None:
                if not subscription_ready_wait.done():
                    subscription_ready_wait.cancel()
                await asyncio.gather(subscription_ready_wait, return_exceptions=True)
            if next_signal is not None:
                if not next_signal.done():
                    next_signal.cancel()
                await asyncio.gather(next_signal, return_exceptions=True)

    async def _active_browser_session_expiry(
        self,
        session_id: uuid.UUID,
    ) -> datetime | None:
        async with self._database.session_factory() as db:
            session = await db.get(ControlSession, session_id)
        if (
            session is None
            or session.revoked_at is not None
            or _utc(session.expires_at) <= datetime.now(UTC)
        ):
            return None
        return _utc(session.expires_at)

    @staticmethod
    async def _close_browser_infrastructure_unavailable(
        websocket: WebSocket,
        reason: str,
    ) -> None:
        await RealtimeService._close_browser(websocket, 1013, reason)

    @staticmethod
    async def _close_browser(websocket: WebSocket, code: int, reason: str) -> None:
        try:
            await websocket.close(code=code, reason=reason)
        except Exception:
            # The peer may already have disconnected; ending the handler is fail-closed.
            pass

    def _snapshot_from_result(
        self,
        result: dict[str, Any],
        current: dict[str, Any],
    ) -> dict[str, Any]:
        thread = result.get("thread") if isinstance(result.get("thread"), dict) else result
        turns = thread.get("turns") if isinstance(thread, dict) else None
        if not isinstance(turns, list):
            return compact_thread_snapshot(
                current,
                max_bytes=self._settings.device_max_result_bytes,
            )
        messages: list[dict[str, Any]] = []
        for turn in turns:
            if not isinstance(turn, dict):
                continue
            items = turn.get("items")
            if not isinstance(items, list):
                continue
            for item in items:
                if not isinstance(item, dict):
                    continue
                text = _extract_string(item, "text", "content")
                if not text:
                    continue
                role = item.get("role")
                if role not in {"user", "assistant", "system"}:
                    role = "assistant"
                messages.append(
                    {
                        "id": str(item.get("id") or uuid.uuid4()),
                        "role": role,
                        "text": text,
                        "created_at": _iso(datetime.now(UTC)),
                    }
                )
        return compact_thread_snapshot(
            {"messages": messages},
            max_bytes=self._settings.device_max_result_bytes,
        )

    def _append_delta(
        self,
        binding: ThreadBinding,
        params: dict[str, Any],
    ) -> tuple[str, str] | None:
        delta = _extract_string(params, "delta", "text")
        if not delta:
            return None
        item_id = _extract_string(params, "itemId", "item_id", "id") or "assistant-current"
        snapshot = dict(binding.snapshot or {})
        messages = [dict(item) for item in snapshot.get("messages", []) if isinstance(item, dict)]
        message = next((item for item in reversed(messages) if item.get("id") == item_id), None)
        if message is None:
            message = {
                "id": item_id,
                "role": "assistant",
                "text": "",
                "created_at": _iso(datetime.now(UTC)),
            }
            messages.append(message)
        combined = str(message.get("text", "")) + delta
        if len(combined) > self._settings.device_max_string_chars:
            raise RealtimeProtocolError("projected message exceeds the character limit")
        message["text"] = combined
        snapshot["messages"] = messages
        try:
            snapshot = compact_thread_snapshot(
                snapshot,
                max_bytes=self._settings.device_max_result_bytes,
                required_message_id=item_id,
            )
        except ThreadSnapshotTooLarge as exc:
            raise RealtimeProtocolError("projected thread snapshot exceeds the byte limit") from exc
        binding.snapshot = snapshot
        return item_id, delta

    @staticmethod
    def _device_event_data(device: Device, status: str) -> dict[str, Any]:
        metadata = device.device_metadata or {}
        return {
            "id": str(device.id),
            "name": device.name,
            "status": status,
            "connector_version": str(metadata.get("connector_version", "")),
            "codex_version": str(metadata.get("codex_version", "")),
            "last_seen_at": _iso(device.last_seen_at) if device.last_seen_at else None,
            "workspace_roots": device.workspace_roots,
        }

    @staticmethod
    def _thread_event_data(binding: ThreadBinding) -> dict[str, Any]:
        visible_status = (
            binding.status.value
            if binding.status
            in {
                ThreadBindingStatus.IDLE,
                ThreadBindingStatus.RUNNING,
                ThreadBindingStatus.WAITING_FOR_APPROVAL,
                ThreadBindingStatus.FAILED,
            }
            else "failed"
        )
        return {
            "id": str(binding.id),
            "thread_id": str(binding.id),
            "device_id": str(binding.device_id),
            "title": binding.title,
            "cwd": binding.cwd or "",
            "model": binding.model,
            "updated_at": _iso(binding.updated_at),
            "status": visible_status,
        }


def _websocket_close_reason(code: int | None) -> str:
    return {
        1000: "peer_disconnect",
        1001: "server_shutdown",
        1008: "protocol_error",
        1013: "dependency_unavailable",
        4000: "heartbeat_timeout",
        4001: "connection_replaced",
        4400: "protocol_error",
        4401: "invalid_auth",
        4403: "origin_denied",
        4409: "invalid_cursor",
        4429: "capacity_exceeded",
    }.get(code, "unknown")
