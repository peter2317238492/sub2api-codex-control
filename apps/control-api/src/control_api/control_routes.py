from __future__ import annotations

import asyncio
import json
import logging
import uuid
from datetime import UTC, datetime
from typing import Literal

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, Response, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .approvals import (
    ApprovalDecisionConflict,
    ApprovalDeviceOffline,
    ApprovalExpired,
    ApprovalNotFound,
    ApprovalStaleEpoch,
)
from .capacity import (
    OwnerCapacityExceeded,
    active_pending_approval_count,
    device_bootstrap_summary,
    ensure_approval_projection_fits,
    ensure_device_projection_fits,
    ensure_model_catalog_fits,
    ensure_thread_creation_capacity_locked,
    ensure_thread_projection_fits,
    ensure_thread_visibility_capacity_locked,
    thread_is_safely_archivable,
)
from .commands import (
    CommandCapacityExceeded,
    CommandIdempotencyConflict,
    CommandObjectNotFound,
    DeviceOffline,
    TurnStartInProgress,
    canonical_request_hash,
    command_scope,
    command_view,
)
from .db import get_db_session
from .dependencies import (
    require_mutating_session,
    require_recent_mutating_session,
    require_session,
)
from .device_auth import (
    DeviceCredentialRejected,
    DeviceProofRejected,
    DeviceProofReplay,
)
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
    DeviceStatus,
    ThreadBinding,
    ThreadBindingStatus,
)
from .protocol import ensure_ascii_json_byte_length
from .schemas import (
    ApprovalDecisionRequest,
    ApprovalListResponse,
    CommandView,
    ControlBootstrapResponse,
    DeviceConnectTokenRequest,
    DeviceConnectTokenResponse,
    DeviceListResponse,
    ManagedThreadListResponse,
    ManagedThreadSummary,
    ModelListResponse,
    ModelSummary,
    ThreadDetailSnapshot,
    ThreadStartRequest,
    TurnTextRequest,
)
from .security import client_ip, request_id
from .services import RateLimitExceeded, RequestMetadata
from .thread_snapshot import compact_thread_snapshot
from .views import device_summary, thread_detail, thread_summary

router = APIRouter()
_LOGGER = logging.getLogger(__name__)


def _metadata(request: Request) -> RequestMetadata:
    settings = request.app.state.settings
    return RequestMetadata(
        source_ip=client_ip(request, settings),
        user_agent=request.headers.get("user-agent", "")[:512] or None,
        request_id=request_id(request),
    )


def _idempotency(value: str) -> str:
    normalized = value.strip()
    if not normalized or len(normalized) > 128:
        raise HTTPException(status_code=400, detail="invalid_idempotency_key")
    return normalized


async def _owned_thread(
    db: AsyncSession,
    owner_user_id: str,
    thread_id: uuid.UUID,
) -> ThreadBinding:
    binding = await db.scalar(
        select(ThreadBinding).where(
            ThreadBinding.id == thread_id,
            ThreadBinding.owner_user_id == owner_user_id,
        )
    )
    if binding is None:
        raise HTTPException(status_code=404, detail="thread_not_found")
    return binding


def _command_error(exc: Exception) -> HTTPException:
    if isinstance(exc, CommandObjectNotFound):
        return HTTPException(status_code=404, detail="device_not_found")
    if isinstance(exc, DeviceOffline):
        return HTTPException(status_code=409, detail="device_offline")
    if isinstance(exc, CommandIdempotencyConflict):
        return HTTPException(status_code=409, detail="idempotency_conflict")
    if isinstance(exc, CommandCapacityExceeded):
        return HTTPException(status_code=429, detail="too_many_outstanding_commands")
    if isinstance(exc, TurnStartInProgress):
        return HTTPException(status_code=409, detail="turn_start_in_progress")
    return HTTPException(status_code=500, detail="command_creation_failed")


def _model_catalog(device: Device) -> list[ModelSummary]:
    items: list[ModelSummary] = []
    for raw in device.model_catalog or []:
        try:
            items.append(ModelSummary.model_validate(raw))
        except ValueError:
            continue
    return items


@router.post(
    "/device/connect-token",
    response_model=DeviceConnectTokenResponse,
    tags=["device"],
)
async def issue_device_connect_token(
    payload: DeviceConnectTokenRequest,
    request: Request,
    authorization: str | None = Header(default=None),
    db: AsyncSession = Depends(get_db_session),
) -> DeviceConnectTokenResponse:
    settings = request.app.state.settings
    try:
        await request.app.state.rate_limiter.check(
            "device-connect-token-ip",
            client_ip(request, settings),
            settings.device_token_issue_limit,
        )
    except RateLimitExceeded as exc:
        raise HTTPException(
            status_code=429,
            detail="device_connect_token_rate_limited",
            headers={"Retry-After": str(exc.retry_after)},
        ) from None

    try:
        issued = await request.app.state.device_tokens.issue(
            db,
            authorization,
            payload,
            _metadata(request),
        )
    except DeviceCredentialRejected:
        raise HTTPException(
            status_code=401,
            detail="invalid_device_credential",
            headers={"WWW-Authenticate": "Device"},
        ) from None
    except DeviceProofReplay:
        raise HTTPException(status_code=409, detail="device_proof_replayed") from None
    except DeviceProofRejected:
        raise HTTPException(status_code=401, detail="invalid_device_proof") from None
    return DeviceConnectTokenResponse(
        access_token=issued.value,
        expires_at=issued.expires_at,
    )


@router.get("/devices", response_model=DeviceListResponse, tags=["device"])
async def list_devices(
    request: Request,
    session: ControlSession = Depends(require_session),
    db: AsyncSession = Depends(get_db_session),
) -> DeviceListResponse:
    devices = list(
        (
            await db.scalars(
                select(Device)
                .where(
                    Device.owner_user_id == session.sub2api_user_id,
                    Device.status != DeviceStatus.REVOKED,
                )
                .order_by(Device.created_at.desc())
                .limit(request.app.state.settings.bootstrap_max_devices)
            )
        ).all()
    )
    return DeviceListResponse(
        items=[await device_summary(device, request.app.state.store) for device in devices]
    )


@router.get("/bootstrap", response_model=ControlBootstrapResponse, tags=["control"])
async def bootstrap_control(
    request: Request,
    response: Response,
    session: ControlSession = Depends(require_session),
    db: AsyncSession = Depends(get_db_session),
) -> ControlBootstrapResponse:
    response.headers["Cache-Control"] = "no-store"
    owner_user_id = session.sub2api_user_id
    event_cursor = await request.app.state.events.lock_snapshot_cursor(db, owner_user_id)
    settings = request.app.state.settings
    devices = list(
        (
            await db.scalars(
                select(Device)
                .where(
                    Device.owner_user_id == owner_user_id,
                    Device.status != DeviceStatus.REVOKED,
                )
                .order_by(Device.created_at.desc())
                .limit(settings.bootstrap_max_devices + 1)
            )
        ).all()
    )
    if len(devices) > settings.bootstrap_max_devices:
        raise HTTPException(status_code=413, detail="bootstrap_device_limit_exceeded")
    bindings = list(
        (
            await db.scalars(
                select(ThreadBinding)
                .join(Device, Device.id == ThreadBinding.device_id)
                .where(
                    ThreadBinding.owner_user_id == owner_user_id,
                    ThreadBinding.status.not_in(
                        (ThreadBindingStatus.CLOSED, ThreadBindingStatus.STALE)
                    ),
                    Device.status != DeviceStatus.REVOKED,
                )
                .order_by(ThreadBinding.updated_at.desc())
                .limit(settings.bootstrap_max_threads + 1)
            )
        ).all()
    )
    if len(bindings) > settings.bootstrap_max_threads:
        raise HTTPException(status_code=413, detail="bootstrap_thread_limit_exceeded")
    pending_approval_count = await active_pending_approval_count(db, owner_user_id)
    if pending_approval_count > settings.bootstrap_max_pending_approvals:
        raise HTTPException(status_code=413, detail="bootstrap_approval_limit_exceeded")
    thread_views = [thread_summary(binding) for binding in bindings]
    approval_views = await request.app.state.approvals.list_pending(db, owner_user_id)
    models_by_device = {str(device.id): _model_catalog(device) for device in devices}
    try:
        for device in devices:
            ensure_device_projection_fits(device)
            ensure_model_catalog_fits(device, settings)
        for binding in bindings:
            ensure_thread_projection_fits(binding)
        device_by_id = {device.id: device for device in devices}
        pending_rows = list(
            (
                await db.scalars(
                    select(Approval)
                    .join(Device, Device.id == Approval.device_id)
                    .where(
                        Approval.owner_user_id == owner_user_id,
                        Approval.status == ApprovalStatus.PENDING,
                        Approval.expires_at > datetime.now(UTC),
                        Device.status != DeviceStatus.REVOKED,
                    )
                )
            ).all()
        )
        for approval in pending_rows:
            device = device_by_id.get(approval.device_id)
            if device is None:
                raise OwnerCapacityExceeded("approval_device_not_bootstrap_visible")
            ensure_approval_projection_fits(approval, device)
    except OwnerCapacityExceeded as exc:
        raise HTTPException(
            status_code=413,
            detail={
                "code": exc.code,
                "recovery": "reduce retained control state or raise validated bootstrap limits",
            },
        ) from None
    await db.commit()

    # Redis connection state is eventually consistent and is not part of the DB
    # snapshot. Resolve it only after releasing the owner-wide event barrier.
    device_views = await asyncio.gather(
        *(device_summary(device, request.app.state.store) for device in devices)
    )
    snapshot = ControlBootstrapResponse(
        event_cursor=str(event_cursor),
        devices=list(device_views),
        threads=thread_views,
        approvals=approval_views,
        models_by_device=models_by_device,
    )
    if len(snapshot.model_dump_json().encode("utf-8")) > settings.bootstrap_max_response_bytes:
        raise HTTPException(status_code=413, detail="bootstrap_response_limit_exceeded")
    return snapshot


@router.delete("/devices/{device_id}", status_code=204, tags=["device"])
async def revoke_device(
    device_id: uuid.UUID,
    request: Request,
    session: ControlSession = Depends(require_recent_mutating_session),
    db: AsyncSession = Depends(get_db_session),
) -> None:
    browser_events = []
    replaced_connection_nonces: list[str] = []
    device = await db.scalar(
        select(Device)
        .where(
            Device.id == device_id,
            Device.owner_user_id == session.sub2api_user_id,
        )
        .with_for_update()
    )
    if device is None:
        raise HTTPException(status_code=404, detail="device_not_found")
    if device.status != DeviceStatus.REVOKED:
        now = datetime.now(UTC)
        await request.app.state.events.lock_owner_cursor(db, session.sub2api_user_id)
        active_connection_nonce = device.active_connection_nonce
        connections = list(
            (
                await db.scalars(
                    select(DeviceConnection).where(
                        DeviceConnection.device_id == device.id,
                        DeviceConnection.status == ConnectionStatus.CONNECTED,
                    )
                )
            ).all()
        )
        replaced_connection_nonces = sorted(
            {
                nonce
                for nonce in (
                    active_connection_nonce,
                    *(connection.connection_nonce for connection in connections),
                )
                if nonce is not None
            }
        )
        device.status = DeviceStatus.REVOKED
        device.revoked_at = now
        device.refresh_credential_hash = None
        device.credential_version += 1
        device.active_epoch = None
        device.active_connection_nonce = None
        for connection in connections:
            connection.status = ConnectionStatus.DISCONNECTED
            connection.disconnected_at = now
            connection.closed_reason = "device_revoked"
        browser_events.extend(await request.app.state.approvals.deny_revoked(db, device))
        bindings = list(
            (
                await db.scalars(
                    select(ThreadBinding)
                    .where(
                        ThreadBinding.device_id == device.id,
                        ThreadBinding.status != ThreadBindingStatus.CLOSED,
                    )
                    .with_for_update()
                )
            ).all()
        )
        for binding in bindings:
            binding.status = ThreadBindingStatus.CLOSED
            binding.active_turn_id = None
            binding.last_error = "device revoked"
            binding.updated_at = now
            thread_data = thread_summary(binding).model_dump(mode="json")
            thread_data["thread_id"] = str(binding.id)
            browser_events.append(
                await request.app.state.events.append(
                    db,
                    owner_user_id=session.sub2api_user_id,
                    device_id=device.id,
                    thread_binding_id=binding.id,
                    event_type="thread.updated",
                    data=thread_data,
                )
            )
        db.add(
            AuditEvent(
                actor_user_id=session.sub2api_user_id,
                actor_session_id=session.id,
                action="device.revoke",
                outcome=AuditOutcome.SUCCEEDED,
                resource_type="device",
                resource_id=str(device.id),
                request_id=request_id(request),
                source_ip=client_ip(request, request.app.state.settings),
                user_agent=request.headers.get("user-agent", "")[:512] or None,
                details={},
            )
        )
        revoked_view = device_bootstrap_summary(device).model_copy(update={"status": "revoked"})
        browser_events.append(
            await request.app.state.events.append(
                db,
                owner_user_id=session.sub2api_user_id,
                device_id=device.id,
                event_type="device.updated",
                data=revoked_view.model_dump(mode="json"),
            )
        )
        await db.commit()
    post_commit_actions = [
        request.app.state.device_tokens.revoke_access_token(device.id),
        request.app.state.store.delete(f"connection:{device.id}"),
    ]
    if replaced_connection_nonces:
        post_commit_actions.append(
            request.app.state.store.publish(
                f"device-dispatch:{device.id}",
                json.dumps(
                    {
                        "kind": "kick",
                        "replaced_connection_nonces": replaced_connection_nonces,
                    },
                    separators=(",", ":"),
                ),
            )
        )
    post_commit_actions.extend(
        request.app.state.events.publish(session.sub2api_user_id, event) for event in browser_events
    )
    for action in post_commit_actions:
        try:
            await action
        except Exception:
            _LOGGER.exception(
                "post-commit device revocation notification failed",
                extra={"device_id": str(device.id)},
            )


@router.get(
    "/devices/{device_id}/models",
    response_model=ModelListResponse,
    tags=["threads"],
)
async def list_models(
    device_id: uuid.UUID,
    request: Request,
    session: ControlSession = Depends(require_session),
    db: AsyncSession = Depends(get_db_session),
) -> ModelListResponse:
    device = await db.scalar(
        select(Device).where(
            Device.id == device_id,
            Device.owner_user_id == session.sub2api_user_id,
            Device.status == DeviceStatus.ACTIVE,
        )
    )
    if device is None:
        raise HTTPException(status_code=404, detail="device_not_found")
    return ModelListResponse(items=_model_catalog(device))


@router.post(
    "/devices/{device_id}/models/sync",
    response_model=CommandView,
    status_code=status.HTTP_202_ACCEPTED,
    tags=["threads"],
)
async def sync_models(
    device_id: uuid.UUID,
    request: Request,
    idempotency_key: str = Header(alias="Idempotency-Key"),
    session: ControlSession = Depends(require_mutating_session),
    db: AsyncSession = Depends(get_db_session),
) -> CommandView:
    try:
        device = await request.app.state.commands.require_owned_online_device(
            db,
            owner_user_id=session.sub2api_user_id,
            device_id=device_id,
        )
        command = await request.app.state.commands.create(
            db,
            owner_user_id=session.sub2api_user_id,
            device=device,
            method="model/list",
            params={"limit": 100},
            idempotency_key=_idempotency(idempotency_key),
            metadata=_metadata(request),
        )
    except (
        CommandObjectNotFound,
        DeviceOffline,
        CommandIdempotencyConflict,
        CommandCapacityExceeded,
    ) as exc:
        raise _command_error(exc) from None
    return command_view(command)


@router.get(
    "/devices/{device_id}/threads",
    response_model=ManagedThreadListResponse,
    tags=["threads"],
)
async def list_threads(
    device_id: uuid.UUID,
    request: Request,
    session: ControlSession = Depends(require_session),
    db: AsyncSession = Depends(get_db_session),
) -> ManagedThreadListResponse:
    device = await db.scalar(
        select(Device).where(
            Device.id == device_id,
            Device.owner_user_id == session.sub2api_user_id,
            Device.status != DeviceStatus.REVOKED,
        )
    )
    if device is None:
        raise HTTPException(status_code=404, detail="device_not_found")
    bindings = list(
        (
            await db.scalars(
                select(ThreadBinding)
                .where(
                    ThreadBinding.device_id == device.id,
                    ThreadBinding.owner_user_id == session.sub2api_user_id,
                    ThreadBinding.status.not_in(
                        (ThreadBindingStatus.CLOSED, ThreadBindingStatus.STALE)
                    ),
                )
                .order_by(ThreadBinding.updated_at.desc())
                .limit(request.app.state.settings.bootstrap_max_threads)
            )
        ).all()
    )
    return ManagedThreadListResponse(items=[thread_summary(binding) for binding in bindings])


@router.post(
    "/devices/{device_id}/threads/sync",
    response_model=CommandView,
    status_code=status.HTTP_202_ACCEPTED,
    tags=["threads"],
)
async def sync_threads(
    device_id: uuid.UUID,
    request: Request,
    idempotency_key: str = Header(alias="Idempotency-Key"),
    session: ControlSession = Depends(require_mutating_session),
    db: AsyncSession = Depends(get_db_session),
) -> CommandView:
    try:
        device = await request.app.state.commands.require_owned_online_device(
            db, owner_user_id=session.sub2api_user_id, device_id=device_id
        )
        command = await request.app.state.commands.create(
            db,
            owner_user_id=session.sub2api_user_id,
            device=device,
            method="thread/list",
            params={"limit": 100},
            idempotency_key=_idempotency(idempotency_key),
            metadata=_metadata(request),
        )
    except (
        CommandObjectNotFound,
        DeviceOffline,
        CommandIdempotencyConflict,
        CommandCapacityExceeded,
    ) as exc:
        raise _command_error(exc) from None
    return command_view(command)


@router.post(
    "/devices/{device_id}/threads",
    response_model=ManagedThreadSummary,
    status_code=status.HTTP_202_ACCEPTED,
    tags=["threads"],
)
async def start_thread(
    device_id: uuid.UUID,
    payload: ThreadStartRequest,
    request: Request,
    idempotency_key: str = Header(alias="Idempotency-Key"),
    session: ControlSession = Depends(require_mutating_session),
    db: AsyncSession = Depends(get_db_session),
) -> ManagedThreadSummary:
    key = _idempotency(idempotency_key)
    params: dict[str, object] = {"cwd": payload.cwd}
    if payload.model:
        params["model"] = payload.model
    scope = command_scope(device_id, "thread/start", None, {"threadId": "threads"})
    request_hash = canonical_request_hash("thread/start", params, scope)

    async def existing_binding() -> ThreadBinding | None:
        existing_command = await db.scalar(
            select(Command).where(
                Command.owner_user_id == session.sub2api_user_id,
                Command.device_id == device_id,
                Command.idempotency_scope == scope,
                Command.idempotency_key == key,
            )
        )
        if existing_command is None:
            return None
        if existing_command.request_hash != request_hash:
            raise HTTPException(status_code=409, detail="idempotency_conflict")
        if existing_command.thread_binding_id is None:
            raise HTTPException(status_code=409, detail="thread_start_state_invalid")
        found = await db.get(ThreadBinding, existing_command.thread_binding_id)
        if found is None:
            raise HTTPException(status_code=409, detail="thread_start_state_invalid")
        return found

    async with request.app.state.commands.serialize_device_mutation(device_id):
        try:
            device = await request.app.state.commands.require_owned_online_device(
                db,
                owner_user_id=session.sub2api_user_id,
                device_id=device_id,
                for_update=True,
            )
        except (CommandObjectNotFound, DeviceOffline) as exc:
            raise _command_error(exc) from None
        replay = await existing_binding()
        if replay is not None:
            await db.commit()
            return thread_summary(replay)
        await request.app.state.events.lock_owner_cursor(db, session.sub2api_user_id)
        replay = await existing_binding()
        if replay is not None:
            await db.commit()
            return thread_summary(replay)
        try:
            await ensure_thread_creation_capacity_locked(
                db,
                request.app.state.settings,
                session.sub2api_user_id,
            )
        except OwnerCapacityExceeded:
            await db.rollback()
            raise HTTPException(status_code=409, detail="thread_capacity_exceeded") from None
        now = datetime.now(UTC)
        binding = ThreadBinding(
            owner_user_id=session.sub2api_user_id,
            device_id=device.id,
            remote_thread_id=None,
            status=ThreadBindingStatus.RUNNING,
            cwd=payload.cwd,
            title="New thread",
            model=payload.model or "",
            appserver_epoch=device.active_epoch or "",
            snapshot={"messages": []},
            created_at=now,
            updated_at=now,
        )
        db.add(binding)
        await db.flush()
        try:
            ensure_thread_projection_fits(binding)
        except OwnerCapacityExceeded as exc:
            await db.rollback()
            raise HTTPException(status_code=413, detail=exc.code) from None
        try:
            command = await request.app.state.commands.create(
                db,
                owner_user_id=session.sub2api_user_id,
                device=device,
                method="thread/start",
                params=params,
                idempotency_key=key,
                metadata=_metadata(request),
                thread_binding_id=binding.id,
                idempotency_scope=scope,
            )
        except (CommandIdempotencyConflict, CommandCapacityExceeded) as exc:
            await db.rollback()
            raise _command_error(exc) from None
        if command.thread_binding_id != binding.id:
            await db.delete(binding)
            await db.commit()
            existing_binding = (
                await db.get(ThreadBinding, command.thread_binding_id)
                if command.thread_binding_id is not None
                else None
            )
            if existing_binding is None:
                raise HTTPException(status_code=409, detail="thread_start_state_invalid")
            return thread_summary(existing_binding)
        return thread_summary(binding)


@router.get(
    "/threads/{thread_id}",
    response_model=ThreadDetailSnapshot,
    tags=["threads"],
)
async def read_thread(
    thread_id: uuid.UUID,
    request: Request,
    response: Response,
    session: ControlSession = Depends(require_session),
    db: AsyncSession = Depends(get_db_session),
) -> ThreadDetailSnapshot:
    response.headers["Cache-Control"] = "no-store"
    event_cursor = await request.app.state.events.lock_snapshot_cursor(db, session.sub2api_user_id)
    binding = await _owned_thread(db, session.sub2api_user_id, thread_id)
    if (
        ensure_ascii_json_byte_length(binding.snapshot or {})
        > request.app.state.settings.device_max_result_bytes
    ):
        raise HTTPException(
            status_code=413,
            detail={
                "code": "thread_snapshot_too_large",
                "recovery": "synchronize the thread to replace its cached snapshot",
            },
        )
    detail = thread_detail(binding)
    await db.commit()
    return ThreadDetailSnapshot(event_cursor=str(event_cursor), thread=detail)


@router.delete("/threads/{thread_id}", status_code=204, tags=["threads"])
async def archive_thread(
    thread_id: uuid.UUID,
    request: Request,
    session: ControlSession = Depends(require_mutating_session),
    db: AsyncSession = Depends(get_db_session),
) -> None:
    owner_user_id = session.sub2api_user_id
    actor_session_id = session.id
    device_id = await db.scalar(
        select(ThreadBinding.device_id).where(
            ThreadBinding.id == thread_id,
            ThreadBinding.owner_user_id == owner_user_id,
        )
    )
    if device_id is None:
        raise HTTPException(status_code=404, detail="thread_not_found")
    await db.rollback()
    async with request.app.state.commands.serialize_device_mutation(device_id):
        device = await db.scalar(
            select(Device)
            .where(
                Device.id == device_id,
                Device.owner_user_id == owner_user_id,
                Device.status == DeviceStatus.ACTIVE,
            )
            .with_for_update()
        )
        if device is None:
            raise HTTPException(status_code=404, detail="thread_not_found")
        await request.app.state.events.lock_owner_cursor(db, owner_user_id)
        binding = await db.scalar(
            select(ThreadBinding)
            .where(
                ThreadBinding.id == thread_id,
                ThreadBinding.owner_user_id == owner_user_id,
                ThreadBinding.device_id == device.id,
            )
            .with_for_update()
        )
        if binding is None:
            raise HTTPException(status_code=404, detail="thread_not_found")
        if binding.status in {ThreadBindingStatus.CLOSED, ThreadBindingStatus.STALE}:
            await db.commit()
            return
        if not await thread_is_safely_archivable(db, binding):
            await db.rollback()
            raise HTTPException(status_code=409, detail="thread_not_archivable")
        binding.status = ThreadBindingStatus.STALE
        binding.updated_at = datetime.now(UTC)
        db.add(
            AuditEvent(
                actor_user_id=owner_user_id,
                actor_session_id=actor_session_id,
                action="thread.archive",
                outcome=AuditOutcome.SUCCEEDED,
                resource_type="thread_binding",
                resource_id=str(binding.id),
                request_id=request_id(request),
                source_ip=client_ip(request, request.app.state.settings),
                user_agent=request.headers.get("user-agent", "")[:512] or None,
                details={"device_id": str(device.id)},
            )
        )
        data = thread_summary(binding).model_dump(mode="json")
        data.update({"thread_id": str(binding.id), "archived": True})
        event = await request.app.state.events.append(
            db,
            owner_user_id=owner_user_id,
            device_id=device.id,
            thread_binding_id=binding.id,
            event_type="thread.updated",
            data=data,
        )
        await db.commit()
    try:
        await request.app.state.events.publish(owner_user_id, event)
    except Exception:
        _LOGGER.exception(
            "failed to publish durable thread archive event",
            extra={"thread_id": str(thread_id)},
        )


@router.post(
    "/threads/{thread_id}/sync",
    response_model=CommandView,
    status_code=status.HTTP_202_ACCEPTED,
    tags=["threads"],
)
async def sync_thread(
    thread_id: uuid.UUID,
    request: Request,
    idempotency_key: str = Header(alias="Idempotency-Key"),
    session: ControlSession = Depends(require_mutating_session),
    db: AsyncSession = Depends(get_db_session),
) -> CommandView:
    binding = await _owned_thread(db, session.sub2api_user_id, thread_id)
    if not binding.remote_thread_id:
        raise HTTPException(status_code=409, detail="thread_not_started")
    try:
        device = await request.app.state.commands.require_owned_online_device(
            db,
            owner_user_id=session.sub2api_user_id,
            device_id=binding.device_id,
        )
        command = await request.app.state.commands.create(
            db,
            owner_user_id=session.sub2api_user_id,
            device=device,
            method="thread/read",
            params={"threadId": binding.remote_thread_id, "includeTurns": True},
            idempotency_key=_idempotency(idempotency_key),
            metadata=_metadata(request),
            thread_binding_id=binding.id,
        )
    except (
        CommandObjectNotFound,
        DeviceOffline,
        CommandIdempotencyConflict,
        CommandCapacityExceeded,
    ) as exc:
        raise _command_error(exc) from None
    return command_view(command)


@router.post(
    "/threads/{thread_id}/resume",
    response_model=CommandView,
    status_code=status.HTTP_202_ACCEPTED,
    tags=["threads"],
)
async def resume_thread(
    thread_id: uuid.UUID,
    request: Request,
    idempotency_key: str = Header(alias="Idempotency-Key"),
    session: ControlSession = Depends(require_mutating_session),
    db: AsyncSession = Depends(get_db_session),
) -> CommandView:
    key = _idempotency(idempotency_key)
    owner_user_id = session.sub2api_user_id
    device_id = await db.scalar(
        select(ThreadBinding.device_id).where(
            ThreadBinding.id == thread_id,
            ThreadBinding.owner_user_id == owner_user_id,
        )
    )
    if device_id is None:
        raise HTTPException(status_code=404, detail="thread_not_found")
    await db.rollback()
    async with request.app.state.commands.serialize_device_mutation(device_id):
        try:
            device = await request.app.state.commands.require_owned_online_device(
                db,
                owner_user_id=owner_user_id,
                device_id=device_id,
                for_update=True,
            )
            await request.app.state.events.lock_owner_cursor(db, owner_user_id)
            binding = await db.scalar(
                select(ThreadBinding)
                .where(
                    ThreadBinding.id == thread_id,
                    ThreadBinding.owner_user_id == owner_user_id,
                    ThreadBinding.device_id == device.id,
                )
                .with_for_update()
            )
            if binding is None:
                raise HTTPException(status_code=404, detail="thread_not_found")
            if not binding.remote_thread_id:
                raise HTTPException(status_code=409, detail="thread_not_started")
            params = {"threadId": binding.remote_thread_id}
            scope = command_scope(device.id, "thread/resume", binding.id, params)
            reservation = await db.scalar(
                select(Command.id)
                .where(
                    Command.thread_binding_id == binding.id,
                    Command.method == "thread/resume",
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
            if (
                binding.status in {ThreadBindingStatus.CLOSED, ThreadBindingStatus.STALE}
                and reservation is None
            ):
                await ensure_thread_visibility_capacity_locked(
                    db,
                    request.app.state.settings,
                    owner_user_id,
                )
            command = await request.app.state.commands.create(
                db,
                owner_user_id=owner_user_id,
                device=device,
                method="thread/resume",
                params=params,
                idempotency_key=key,
                metadata=_metadata(request),
                thread_binding_id=binding.id,
                idempotency_scope=scope,
            )
        except OwnerCapacityExceeded:
            await db.rollback()
            raise HTTPException(status_code=409, detail="thread_capacity_exceeded") from None
        except (
            CommandObjectNotFound,
            DeviceOffline,
            CommandIdempotencyConflict,
            CommandCapacityExceeded,
        ) as exc:
            await db.rollback()
            raise _command_error(exc) from None
    return command_view(command)


@router.post(
    "/threads/{thread_id}/turns",
    response_model=CommandView,
    status_code=status.HTTP_202_ACCEPTED,
    tags=["turns"],
)
async def start_turn(
    thread_id: uuid.UUID,
    payload: TurnTextRequest,
    request: Request,
    idempotency_key: str = Header(alias="Idempotency-Key"),
    session: ControlSession = Depends(require_mutating_session),
    db: AsyncSession = Depends(get_db_session),
) -> CommandView:
    key = _idempotency(idempotency_key)
    device_id = await db.scalar(
        select(ThreadBinding.device_id).where(
            ThreadBinding.id == thread_id,
            ThreadBinding.owner_user_id == session.sub2api_user_id,
        )
    )
    if device_id is None:
        raise HTTPException(status_code=404, detail="thread_not_found")
    async with request.app.state.commands.thread_mutation_lock(thread_id):
        async with request.app.state.commands.serialize_device_mutation(device_id):
            try:
                device = await request.app.state.commands.require_owned_online_device(
                    db,
                    owner_user_id=session.sub2api_user_id,
                    device_id=device_id,
                    for_update=True,
                )
                binding = await db.scalar(
                    select(ThreadBinding)
                    .where(
                        ThreadBinding.id == thread_id,
                        ThreadBinding.owner_user_id == session.sub2api_user_id,
                        ThreadBinding.device_id == device.id,
                    )
                    .execution_options(populate_existing=True)
                    .with_for_update()
                )
                if binding is None:
                    raise HTTPException(status_code=404, detail="thread_not_found")
                if not binding.remote_thread_id:
                    raise HTTPException(status_code=409, detail="thread_not_started")
                snapshot = dict(binding.snapshot or {})
                messages = list(snapshot.get("messages", []))
                if not any(isinstance(item, dict) and item.get("id") == key for item in messages):
                    messages.append(
                        {
                            "id": key,
                            "role": "user",
                            "text": payload.text,
                            "created_at": datetime.now(UTC).isoformat(),
                            "pending": False,
                        }
                    )
                    snapshot["messages"] = messages
                binding.snapshot = compact_thread_snapshot(
                    snapshot,
                    max_bytes=request.app.state.settings.device_max_result_bytes,
                    required_message_id=key,
                )
                binding.status = ThreadBindingStatus.RUNNING
                command = await request.app.state.commands.create(
                    db,
                    owner_user_id=session.sub2api_user_id,
                    device=device,
                    method="turn/start",
                    params={
                        "threadId": binding.remote_thread_id,
                        "input": [{"type": "text", "text": payload.text}],
                    },
                    idempotency_key=key,
                    metadata=_metadata(request),
                    thread_binding_id=binding.id,
                )
            except (
                CommandObjectNotFound,
                DeviceOffline,
                CommandIdempotencyConflict,
                CommandCapacityExceeded,
                TurnStartInProgress,
            ) as exc:
                await db.rollback()
                raise _command_error(exc) from None
    return command_view(command)


@router.post(
    "/threads/{thread_id}/turns/current/steer",
    response_model=CommandView,
    status_code=status.HTTP_202_ACCEPTED,
    tags=["turns"],
)
async def steer_turn(
    thread_id: uuid.UUID,
    payload: TurnTextRequest,
    request: Request,
    idempotency_key: str = Header(alias="Idempotency-Key"),
    session: ControlSession = Depends(require_mutating_session),
    db: AsyncSession = Depends(get_db_session),
) -> CommandView:
    key = _idempotency(idempotency_key)
    owner_user_id = session.sub2api_user_id
    device_id = await db.scalar(
        select(ThreadBinding.device_id).where(
            ThreadBinding.id == thread_id,
            ThreadBinding.owner_user_id == owner_user_id,
        )
    )
    if device_id is None:
        raise HTTPException(status_code=404, detail="thread_not_found")
    async with request.app.state.commands.thread_mutation_lock(thread_id):
        async with request.app.state.commands.serialize_device_mutation(device_id):
            try:
                device = await request.app.state.commands.require_owned_online_device(
                    db,
                    owner_user_id=owner_user_id,
                    device_id=device_id,
                    for_update=True,
                )
                binding = await db.scalar(
                    select(ThreadBinding)
                    .where(
                        ThreadBinding.id == thread_id,
                        ThreadBinding.owner_user_id == owner_user_id,
                        ThreadBinding.device_id == device.id,
                    )
                    .execution_options(populate_existing=True)
                    .with_for_update()
                )
                if binding is None:
                    raise HTTPException(status_code=404, detail="thread_not_found")
                if not binding.remote_thread_id or not binding.active_turn_id:
                    raise HTTPException(status_code=409, detail="turn_not_active")
                command = await request.app.state.commands.create(
                    db,
                    owner_user_id=owner_user_id,
                    device=device,
                    method="turn/steer",
                    params={
                        "threadId": binding.remote_thread_id,
                        "expectedTurnId": binding.active_turn_id,
                        "input": [{"type": "text", "text": payload.text}],
                    },
                    idempotency_key=key,
                    metadata=_metadata(request),
                    thread_binding_id=binding.id,
                )
            except (
                CommandObjectNotFound,
                DeviceOffline,
                CommandIdempotencyConflict,
                CommandCapacityExceeded,
            ) as exc:
                await db.rollback()
                raise _command_error(exc) from None
    return command_view(command)


@router.post(
    "/threads/{thread_id}/turns/current/interrupt",
    response_model=CommandView,
    status_code=status.HTTP_202_ACCEPTED,
    tags=["turns"],
)
async def interrupt_turn(
    thread_id: uuid.UUID,
    request: Request,
    idempotency_key: str = Header(alias="Idempotency-Key"),
    session: ControlSession = Depends(require_mutating_session),
    db: AsyncSession = Depends(get_db_session),
) -> CommandView:
    key = _idempotency(idempotency_key)
    owner_user_id = session.sub2api_user_id
    device_id = await db.scalar(
        select(ThreadBinding.device_id).where(
            ThreadBinding.id == thread_id,
            ThreadBinding.owner_user_id == owner_user_id,
        )
    )
    if device_id is None:
        raise HTTPException(status_code=404, detail="thread_not_found")
    async with request.app.state.commands.thread_mutation_lock(thread_id):
        async with request.app.state.commands.serialize_device_mutation(device_id):
            try:
                device = await request.app.state.commands.require_owned_online_device(
                    db,
                    owner_user_id=owner_user_id,
                    device_id=device_id,
                    for_update=True,
                )
                binding = await db.scalar(
                    select(ThreadBinding)
                    .where(
                        ThreadBinding.id == thread_id,
                        ThreadBinding.owner_user_id == owner_user_id,
                        ThreadBinding.device_id == device.id,
                    )
                    .execution_options(populate_existing=True)
                    .with_for_update()
                )
                if binding is None:
                    raise HTTPException(status_code=404, detail="thread_not_found")
                if not binding.remote_thread_id or not binding.active_turn_id:
                    raise HTTPException(status_code=409, detail="turn_not_active")
                command = await request.app.state.commands.create(
                    db,
                    owner_user_id=owner_user_id,
                    device=device,
                    method="turn/interrupt",
                    params={
                        "threadId": binding.remote_thread_id,
                        "turnId": binding.active_turn_id,
                    },
                    idempotency_key=key,
                    metadata=_metadata(request),
                    thread_binding_id=binding.id,
                )
            except (
                CommandObjectNotFound,
                DeviceOffline,
                CommandIdempotencyConflict,
                CommandCapacityExceeded,
            ) as exc:
                await db.rollback()
                raise _command_error(exc) from None
    return command_view(command)


@router.get("/approvals", response_model=ApprovalListResponse, tags=["approvals"])
async def list_approvals(
    request: Request,
    state: Literal["pending"] = Query(default="pending"),
    session: ControlSession = Depends(require_session),
    db: AsyncSession = Depends(get_db_session),
) -> ApprovalListResponse:
    del state
    return ApprovalListResponse(
        items=await request.app.state.approvals.list_pending(db, session.sub2api_user_id)
    )


@router.post(
    "/approvals/{approval_id}/decision",
    status_code=204,
    tags=["approvals"],
)
async def decide_approval(
    approval_id: uuid.UUID,
    payload: ApprovalDecisionRequest,
    request: Request,
    session: ControlSession = Depends(require_recent_mutating_session),
    db: AsyncSession = Depends(get_db_session),
) -> None:
    try:
        await request.app.state.approvals.decide(
            db,
            owner_user_id=session.sub2api_user_id,
            approval_id=approval_id,
            decision=payload.decision,
            session_id=session.id,
            metadata=_metadata(request),
        )
    except ApprovalNotFound:
        raise HTTPException(status_code=404, detail="approval_not_found") from None
    except ApprovalExpired:
        raise HTTPException(status_code=410, detail="approval_expired") from None
    except ApprovalStaleEpoch:
        raise HTTPException(status_code=409, detail="approval_stale_epoch") from None
    except ApprovalDeviceOffline:
        raise HTTPException(status_code=409, detail="device_offline") from None
    except ApprovalDecisionConflict:
        raise HTTPException(status_code=409, detail="approval_already_decided") from None
