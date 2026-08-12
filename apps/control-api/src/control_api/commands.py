from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from .command_budget import validate_command_budget
from .config import Settings
from .events import EventService
from .models import (
    AuditEvent,
    AuditOutcome,
    Command,
    CommandStatus,
    Device,
    DeviceStatus,
    ThreadBinding,
    ThreadBindingStatus,
)
from .operational_metrics import OperationalMetrics
from .protocol import ALLOWED_RPC_METHODS
from .schemas import BrowserEvent, CommandView
from .services import RequestMetadata
from .storage import KeyValueStore
from .views import thread_summary

_LOGGER = logging.getLogger(__name__)


class CommandError(Exception):
    pass


class DeviceOffline(CommandError):
    pass


class CommandIdempotencyConflict(CommandError):
    pass


class CommandObjectNotFound(CommandError):
    pass


class CommandCapacityExceeded(CommandError):
    pass


class TurnStartInProgress(CommandError):
    pass


def canonical_request_hash(
    method: str,
    params: dict[str, object],
    scope: str | None = None,
) -> str:
    document: dict[str, object] = {"method": method, "params": params}
    if scope is not None:
        document["scope"] = scope
    encoded = json.dumps(
        document,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode()
    return hashlib.sha256(encoded).hexdigest()


def command_scope(
    device_id: uuid.UUID,
    method: str,
    thread_binding_id: uuid.UUID | None,
    params: dict[str, object],
) -> str:
    resource = str(thread_binding_id) if thread_binding_id is not None else params.get("threadId")
    normalized_resource = str(resource)[:255] if resource else "device"
    return f"device:{device_id}|method:{method}|resource:{normalized_resource}"


def wire_idempotency_key(scope: str, key: str) -> str:
    """Derive the Connector journal identity from the API's full idempotency scope."""

    digest = hashlib.sha256()
    digest.update(b"sub2api-codex-control/wire-idempotency/v1\0")
    digest.update(scope.encode("utf-8"))
    digest.update(b"\0")
    digest.update(key.encode("utf-8"))
    return digest.hexdigest()


def command_view(command: Command) -> CommandView:
    return CommandView(
        id=command.id,
        state=command.status.value,
        method=command.method,
        deadline_at=command.expires_at,
        result=command.result,
        error_code=command.error_code,
        error_message=command.error_message,
    )


def thread_event_data(binding: ThreadBinding) -> dict[str, object]:
    data = thread_summary(binding).model_dump(mode="json")
    data["thread_id"] = str(binding.id)
    return data


def repair_binding_for_terminal_command(
    binding: ThreadBinding,
    command: Command,
    now: datetime,
) -> bool:
    """Project a terminal command onto its binding without reviving archived state."""

    if binding.status in {ThreadBindingStatus.CLOSED, ThreadBindingStatus.STALE}:
        return False
    binding.status = ThreadBindingStatus.FAILED
    binding.active_turn_id = None
    binding.last_error = command.error_message or command.error_code
    binding.updated_at = now
    return True


class CommandService:
    def __init__(
        self,
        settings: Settings,
        store: KeyValueStore,
        events: EventService,
        metrics: OperationalMetrics,
    ) -> None:
        self._settings = settings
        self._store = store
        self._events = events
        self._metrics = metrics
        self._device_create_locks: dict[uuid.UUID, asyncio.Lock] = {}
        self._device_lock_owners: dict[uuid.UUID, asyncio.Task[object]] = {}
        self._owner_create_locks: dict[str, asyncio.Lock] = {}
        self._thread_mutation_locks: dict[uuid.UUID, asyncio.Lock] = {}

    def thread_mutation_lock(self, thread_binding_id: uuid.UUID) -> asyncio.Lock:
        return self._thread_mutation_locks.setdefault(thread_binding_id, asyncio.Lock())

    @asynccontextmanager
    async def serialize_device_mutation(self, device_id: uuid.UUID) -> AsyncIterator[None]:
        task = asyncio.current_task()
        if task is None:
            raise RuntimeError("device mutation requires an asyncio task")
        if self._device_lock_owners.get(device_id) is task:
            yield
            return
        lock = self._device_create_locks.setdefault(device_id, asyncio.Lock())
        async with lock:
            self._device_lock_owners[device_id] = task
            try:
                yield
            finally:
                self._device_lock_owners.pop(device_id, None)

    @asynccontextmanager
    async def serialize_owner_command_creation(self, owner_user_id: str) -> AsyncIterator[None]:
        lock = self._owner_create_locks.setdefault(owner_user_id, asyncio.Lock())
        async with lock:
            yield

    async def is_online(
        self,
        device_id: uuid.UUID,
        connection_nonce: str | None = None,
    ) -> bool:
        if not connection_nonce:
            return False
        raw = await self._store.get(f"connection:{device_id}")
        if raw is None:
            return False
        try:
            parsed_registry = json.loads(raw)
        except json.JSONDecodeError:
            return False
        if not isinstance(parsed_registry, dict):
            return False
        registry = parsed_registry
        return registry.get("connection_nonce") == connection_nonce

    async def require_owned_online_device(
        self,
        db: AsyncSession,
        *,
        owner_user_id: str,
        device_id: uuid.UUID,
        for_update: bool = False,
    ) -> Device:
        query = select(Device).where(
            Device.id == device_id,
            Device.owner_user_id == owner_user_id,
        )
        if for_update:
            query = query.with_for_update()
        device = await db.scalar(query)
        if device is None or device.status == DeviceStatus.REVOKED:
            raise CommandObjectNotFound("device was not found")
        if not device.active_epoch or not await self.is_online(
            device.id, device.active_connection_nonce
        ):
            raise DeviceOffline("device is offline")
        return device

    async def create(
        self,
        db: AsyncSession,
        *,
        owner_user_id: str,
        device: Device,
        method: str,
        params: dict[str, object],
        idempotency_key: str,
        metadata: RequestMetadata,
        thread_binding_id: uuid.UUID | None = None,
        deadline_seconds: int | None = None,
        idempotency_scope: str | None = None,
    ) -> Command:
        if method not in ALLOWED_RPC_METHODS:
            self._metrics.rpc_policy("prohibited", "denied")
            raise ValueError("command method is not allowlisted")
        validate_command_budget(
            device_id=device.id,
            epoch=device.active_epoch or "",
            workspace_roots=list(device.workspace_roots or []),
            method=method,
            params=params,
            idempotency_key=idempotency_key,
            max_envelope_bytes=self._settings.device_max_envelope_bytes,
        )
        scope = idempotency_scope or command_scope(
            device.id,
            method,
            thread_binding_id,
            params,
        )
        if not scope or len(scope) > 512:
            raise ValueError("idempotency scope is invalid")
        request_hash = canonical_request_hash(method, params, scope)

        async with self.serialize_device_mutation(device.id):
            async with self.serialize_owner_command_creation(owner_user_id):
                return await self._create_serialized(
                    db,
                    owner_user_id=owner_user_id,
                    device=device,
                    method=method,
                    params=params,
                    idempotency_key=idempotency_key,
                    metadata=metadata,
                    thread_binding_id=thread_binding_id,
                    deadline_seconds=deadline_seconds,
                    scope=scope,
                    request_hash=request_hash,
                )

    async def _create_serialized(
        self,
        db: AsyncSession,
        *,
        owner_user_id: str,
        device: Device,
        method: str,
        params: dict[str, object],
        idempotency_key: str,
        metadata: RequestMetadata,
        thread_binding_id: uuid.UUID | None,
        deadline_seconds: int | None,
        scope: str,
        request_hash: str,
    ) -> Command:
        async def find_existing() -> Command | None:
            return await db.scalar(
                select(Command).where(
                    Command.owner_user_id == owner_user_id,
                    Command.device_id == device.id,
                    Command.idempotency_scope == scope,
                    Command.idempotency_key == idempotency_key,
                )
            )

        existing = await find_existing()
        if existing is not None:
            return await self._reuse_existing(existing, request_hash, device.id)

        locked_device = await db.scalar(
            select(Device)
            .where(
                Device.id == device.id,
                Device.owner_user_id == owner_user_id,
                Device.status == DeviceStatus.ACTIVE,
            )
            .with_for_update()
        )
        if locked_device is None:
            raise CommandObjectNotFound("device was not found")
        device = locked_device
        existing = await find_existing()
        if existing is not None:
            return await self._reuse_existing(existing, request_hash, device.id)

        outstanding = int(
            await db.scalar(
                select(func.count(Command.id)).where(
                    Command.device_id == device.id,
                    Command.status.in_(
                        [
                            CommandStatus.QUEUED,
                            CommandStatus.DISPATCHED,
                            CommandStatus.ACKNOWLEDGED,
                        ]
                    ),
                )
            )
            or 0
        )
        if outstanding >= self._settings.device_max_outstanding_commands:
            raise CommandCapacityExceeded("device has too many outstanding commands")

        device_records = int(
            await db.scalar(select(func.count(Command.id)).where(Command.device_id == device.id))
            or 0
        )
        if device_records >= self._settings.device_max_command_records:
            raise CommandCapacityExceeded("device command record limit reached")
        # The owner cursor row is the cross-replica serialization point for the
        # owner-wide retained-command quota. The in-process owner lock above
        # supplies the same guarantee for SQLite and avoids needless DB waits.
        await self._events.lock_owner_cursor(db, owner_user_id)
        owner_records = int(
            await db.scalar(
                select(func.count(Command.id)).where(Command.owner_user_id == owner_user_id)
            )
            or 0
        )
        if owner_records >= self._settings.owner_max_command_records:
            raise CommandCapacityExceeded("owner command record limit reached")

        if method == "turn/start" and thread_binding_id is not None:
            active_turn_start = await db.scalar(
                select(Command.id)
                .where(
                    Command.owner_user_id == owner_user_id,
                    Command.device_id == device.id,
                    Command.thread_binding_id == thread_binding_id,
                    Command.method == "turn/start",
                    Command.status.in_(
                        (
                            CommandStatus.QUEUED,
                            CommandStatus.DISPATCHED,
                            CommandStatus.ACKNOWLEDGED,
                        )
                    ),
                )
                .limit(1)
            )
            if active_turn_start is not None:
                raise TurnStartInProgress("thread already has a nonterminal turn/start command")

        now = datetime.now(UTC)
        ttl = min(
            deadline_seconds or self._settings.command_ttl_seconds,
            self._settings.command_ttl_seconds,
        )
        command = Command(
            owner_user_id=owner_user_id,
            device_id=device.id,
            thread_binding_id=thread_binding_id,
            idempotency_key=idempotency_key,
            idempotency_scope=scope,
            request_hash=request_hash,
            method=method,
            payload=params,
            status=CommandStatus.QUEUED,
            appserver_epoch=device.active_epoch,
            created_at=now,
            expires_at=now + timedelta(seconds=ttl),
        )
        try:
            async with db.begin_nested():
                db.add(command)
                await db.flush()
        except IntegrityError:
            existing = await find_existing()
            if existing is None:
                raise
            return await self._reuse_existing(existing, request_hash, device.id)
        db.add(
            AuditEvent(
                actor_user_id=owner_user_id,
                action="command.create",
                outcome=AuditOutcome.SUCCEEDED,
                resource_type="command",
                resource_id=str(command.id),
                request_id=metadata.request_id,
                source_ip=metadata.source_ip,
                user_agent=metadata.user_agent,
                details={
                    "device_id": str(device.id),
                    "method": method,
                    "idempotency_scope": scope,
                },
            )
        )
        browser_events = [
            await self._events.append(
                db,
                owner_user_id=owner_user_id,
                device_id=device.id,
                thread_binding_id=thread_binding_id,
                event_type="command.updated",
                data={
                    "device_id": str(device.id),
                    "command": command_view(command).model_dump(mode="json"),
                },
            )
        ]
        if thread_binding_id is not None:
            binding = await db.get(ThreadBinding, thread_binding_id)
            if (
                binding is not None
                and binding.owner_user_id == owner_user_id
                and binding.status not in {ThreadBindingStatus.CLOSED, ThreadBindingStatus.STALE}
            ):
                thread_data = thread_summary(binding).model_dump(mode="json")
                thread_data["thread_id"] = str(binding.id)
                browser_events.append(
                    await self._events.append(
                        db,
                        owner_user_id=owner_user_id,
                        device_id=device.id,
                        thread_binding_id=binding.id,
                        event_type="thread.updated",
                        data=thread_data,
                    )
                )
        await db.commit()
        self._metrics.command_transition("none", CommandStatus.QUEUED.value)
        self._metrics.rpc_policy("allowlisted", "accepted")
        await self._notify_dispatch_best_effort(device.id, command.id)
        for event in browser_events:
            await self._publish_event_best_effort(owner_user_id, event, command.id)
        return command

    async def _reuse_existing(
        self,
        existing: Command,
        request_hash: str,
        device_id: uuid.UUID,
    ) -> Command:
        if existing.request_hash != request_hash:
            self._metrics.command_idempotency("conflict")
            raise CommandIdempotencyConflict(
                "idempotency key was already used for another operation"
            )
        self._metrics.command_idempotency("replayed")
        self._metrics.rpc_policy("allowlisted", "accepted")
        if existing.status == CommandStatus.QUEUED:
            await self._notify_dispatch_best_effort(device_id, existing.id)
        return existing

    async def _notify_dispatch_best_effort(
        self,
        device_id: uuid.UUID,
        command_id: uuid.UUID,
    ) -> None:
        try:
            await self.notify_dispatch(device_id, command_id)
        except Exception:
            # PostgreSQL and the durable event log are authoritative. Device
            # heartbeat scanning recovers a lost Redis wake without duplicating
            # the command or turning a committed request into an HTTP 500.
            _LOGGER.exception(
                "failed to publish durable command dispatch wake",
                extra={"command_id": str(command_id)},
            )

    async def _publish_event_best_effort(
        self,
        owner_user_id: str,
        event: BrowserEvent,
        command_id: uuid.UUID,
    ) -> None:
        try:
            await self._events.publish(owner_user_id, event)
        except Exception:
            # Browser cursor catch-up replays this already committed event.
            _LOGGER.exception(
                "failed to publish durable command browser event",
                extra={"command_id": str(command_id)},
            )

    async def notify_dispatch(self, device_id: uuid.UUID, command_id: uuid.UUID) -> None:
        await self._store.publish(
            f"device-dispatch:{device_id}",
            json.dumps({"kind": "command", "command_id": str(command_id)}),
        )

    async def expire_due(self, db: AsyncSession, now: datetime | None = None) -> int:
        now = now or datetime.now(UTC)
        expirable = (
            CommandStatus.QUEUED,
            CommandStatus.DISPATCHED,
            CommandStatus.ACKNOWLEDGED,
        )
        candidates = list(
            (
                await db.execute(
                    select(Command.id, Command.device_id, Command.owner_user_id)
                    .where(
                        Command.status.in_(expirable),
                        Command.expires_at <= now,
                    )
                    .order_by(Command.device_id, Command.id)
                    .limit(self._settings.retention_sweep_batch_size)
                )
            ).all()
        )
        # Do not retain the snapshot transaction while acquiring durable locks.
        await db.rollback()
        expired = 0
        for command_id, device_id, owner_user_id in candidates:
            device = await db.scalar(
                select(Device)
                .where(
                    Device.id == device_id,
                    Device.owner_user_id == owner_user_id,
                )
                .with_for_update()
            )
            if device is None:
                await db.rollback()
                continue
            await self._events.lock_owner_cursor(db, owner_user_id)
            command = await db.scalar(
                select(Command)
                .where(
                    Command.id == command_id,
                    Command.device_id == device_id,
                    Command.owner_user_id == owner_user_id,
                    Command.status.in_(expirable),
                    Command.expires_at <= now,
                )
                .with_for_update(skip_locked=True)
            )
            if command is None:
                await db.rollback()
                continue
            previous_status = command.status
            command.status = CommandStatus.EXPIRED
            command.completed_at = now
            command.error_code = "expired"
            command.error_message = "command deadline passed before completion"
            db.add(
                AuditEvent(
                    actor_user_id=command.owner_user_id,
                    action="command.expire",
                    outcome=AuditOutcome.FAILED,
                    resource_type="command",
                    resource_id=str(command.id),
                    details={"device_id": str(command.device_id), "method": command.method},
                )
            )
            browser_events: list[BrowserEvent] = [
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
                browser_events.append(
                    await self._events.append(
                        db,
                        owner_user_id=command.owner_user_id,
                        device_id=command.device_id,
                        thread_binding_id=binding.id,
                        event_type="thread.updated",
                        data=thread_event_data(binding),
                    )
                )
            await db.commit()
            self._metrics.command_transition(
                previous_status.value,
                CommandStatus.EXPIRED.value,
                duration_seconds=(now - _as_utc(command.created_at)).total_seconds(),
            )
            expired += 1
            for event in browser_events:
                try:
                    await self._events.publish(command.owner_user_id, event)
                except Exception:
                    # EventLog is authoritative; a browser catches up by cursor.
                    _LOGGER.exception(
                        "failed to publish durable command expiry event",
                        extra={"command_id": str(command.id)},
                    )
        return expired


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)
