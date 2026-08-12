from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import exists, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from .config import (
    BOOTSTRAP_APPROVAL_ITEM_MAX_BYTES,
    BOOTSTRAP_DEVICE_SUMMARY_MAX_BYTES,
    BOOTSTRAP_MODEL_CATALOG_MAX_BYTES,
    BOOTSTRAP_THREAD_SUMMARY_MAX_BYTES,
    Settings,
)
from .models import (
    Approval,
    ApprovalStatus,
    Command,
    CommandStatus,
    Device,
    DeviceOutbox,
    DeviceStatus,
    ThreadBinding,
    ThreadBindingStatus,
)
from .protocol import ensure_ascii_json_byte_length
from .schemas import ApprovalItem, DeviceSummary, ModelSummary
from .views import thread_summary

if TYPE_CHECKING:
    from .events import EventService


class OwnerCapacityExceeded(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def device_bootstrap_summary(device: Device) -> DeviceSummary:
    metadata = device.device_metadata or {}
    return DeviceSummary(
        id=device.id,
        name=device.name,
        status="offline",
        connector_version=str(metadata.get("connector_version", "")),
        codex_version=str(metadata.get("codex_version", "")),
        last_seen_at=device.last_seen_at,
        workspace_roots=device.workspace_roots or [],
    )


def ensure_device_projection_fits(device: Device) -> None:
    projection = device_bootstrap_summary(device).model_copy(
        update={"status": "offline", "last_seen_at": datetime.max.replace(tzinfo=UTC)}
    )
    if (
        ensure_ascii_json_byte_length(projection.model_dump(mode="json"))
        > BOOTSTRAP_DEVICE_SUMMARY_MAX_BYTES
    ):
        raise OwnerCapacityExceeded("device_summary_too_large")


def ensure_thread_projection_fits(binding: ThreadBinding) -> None:
    projection = thread_summary(binding).model_copy(update={"status": "waiting_for_approval"})
    if (
        ensure_ascii_json_byte_length(projection.model_dump(mode="json"))
        > BOOTSTRAP_THREAD_SUMMARY_MAX_BYTES
    ):
        raise OwnerCapacityExceeded("thread_summary_too_large")


def bounded_model_catalog(result: Any, settings: Settings) -> list[dict[str, Any]]:
    candidates = result
    if isinstance(result, dict):
        for key in ("data", "models", "items"):
            if isinstance(result.get(key), list):
                candidates = result[key]
                break
    if not isinstance(candidates, list):
        return []

    catalog: list[dict[str, Any]] = []
    for raw in candidates:
        if len(catalog) >= settings.bootstrap_max_models_per_device:
            break
        if not isinstance(raw, dict):
            continue
        model_id = _first_string(raw, "id", "model", "slug")
        if not model_id:
            continue
        display_name = _first_string(raw, "display_name", "displayName", "name") or model_id
        description = _first_string(raw, "description")
        try:
            model = ModelSummary(
                id=model_id[:128],
                display_name=display_name[:255],
                description=description[:512] if description else None,
            )
        except ValueError:
            continue
        candidate = [*catalog, model.model_dump(mode="json")]
        if ensure_ascii_json_byte_length(candidate) > BOOTSTRAP_MODEL_CATALOG_MAX_BYTES:
            break
        catalog = candidate
    return catalog


def ensure_model_catalog_fits(device: Device, settings: Settings) -> None:
    catalog = [
        model.model_dump(mode="json")
        for raw in (device.model_catalog or [])[: settings.bootstrap_max_models_per_device + 1]
        if (model := _validated_model(raw)) is not None
    ]
    if len(catalog) > settings.bootstrap_max_models_per_device:
        raise OwnerCapacityExceeded("model_catalog_item_limit_exceeded")
    if ensure_ascii_json_byte_length(catalog) > BOOTSTRAP_MODEL_CATALOG_MAX_BYTES:
        raise OwnerCapacityExceeded("model_catalog_too_large")


def ensure_approval_projection_fits(approval: Approval, device: Device) -> None:
    item = ApprovalItem(
        approval_id=approval.id,
        command_id=approval.external_command_id
        or (str(approval.command_id) if approval.command_id else ""),
        kind=approval.approval_kind,
        summary=approval.summary,
        details=approval.request,
        expires_at=approval.expires_at,
        device_id=device.id,
        device_name=device.name,
        created_at=approval.requested_at,
    )
    if (
        ensure_ascii_json_byte_length(item.model_dump(mode="json"))
        > BOOTSTRAP_APPROVAL_ITEM_MAX_BYTES
    ):
        raise OwnerCapacityExceeded("approval_item_too_large")


async def active_device_count(db: AsyncSession, owner_user_id: str) -> int:
    return int(
        await db.scalar(
            select(func.count(Device.id)).where(
                Device.owner_user_id == owner_user_id,
                Device.status != DeviceStatus.REVOKED,
            )
        )
        or 0
    )


async def total_device_count(db: AsyncSession, owner_user_id: str) -> int:
    return int(
        await db.scalar(select(func.count(Device.id)).where(Device.owner_user_id == owner_user_id))
        or 0
    )


async def ensure_device_creation_capacity(
    db: AsyncSession,
    events: EventService,
    settings: Settings,
    owner_user_id: str,
) -> None:
    await events.lock_owner_cursor(db, owner_user_id)
    if await active_device_count(db, owner_user_id) >= settings.bootstrap_max_devices:
        raise OwnerCapacityExceeded("active_device_limit_exceeded")
    if await total_device_count(db, owner_user_id) >= settings.owner_max_device_records:
        raise OwnerCapacityExceeded("device_record_limit_exceeded")


async def visible_thread_count(db: AsyncSession, owner_user_id: str) -> int:
    hidden_statuses = (ThreadBindingStatus.CLOSED, ThreadBindingStatus.STALE)
    resume_reservation = exists(
        select(Command.id).where(
            Command.thread_binding_id == ThreadBinding.id,
            Command.method == "thread/resume",
            Command.status.in_(
                (
                    CommandStatus.QUEUED,
                    CommandStatus.DISPATCHED,
                    CommandStatus.ACKNOWLEDGED,
                )
            ),
        )
    )
    return int(
        await db.scalar(
            select(func.count(ThreadBinding.id))
            .join(Device, Device.id == ThreadBinding.device_id)
            .where(
                ThreadBinding.owner_user_id == owner_user_id,
                Device.status != DeviceStatus.REVOKED,
                (ThreadBinding.status.not_in(hidden_statuses) | resume_reservation),
            )
        )
        or 0
    )


async def total_thread_count(db: AsyncSession, owner_user_id: str) -> int:
    return int(
        await db.scalar(
            select(func.count(ThreadBinding.id)).where(ThreadBinding.owner_user_id == owner_user_id)
        )
        or 0
    )


async def ensure_thread_creation_capacity(
    db: AsyncSession,
    events: EventService,
    settings: Settings,
    owner_user_id: str,
) -> None:
    await events.lock_owner_cursor(db, owner_user_id)
    await ensure_thread_creation_capacity_locked(db, settings, owner_user_id)


async def ensure_thread_creation_capacity_locked(
    db: AsyncSession,
    settings: Settings,
    owner_user_id: str,
) -> None:
    await ensure_thread_visibility_capacity_locked(db, settings, owner_user_id)
    if await total_thread_count(db, owner_user_id) >= settings.owner_max_thread_records:
        raise OwnerCapacityExceeded("thread_record_limit_exceeded")


async def ensure_thread_visibility_capacity_locked(
    db: AsyncSession,
    settings: Settings,
    owner_user_id: str,
) -> None:
    if await visible_thread_count(db, owner_user_id) >= settings.bootstrap_max_threads:
        raise OwnerCapacityExceeded("thread_limit_exceeded")


async def active_pending_approval_count(db: AsyncSession, owner_user_id: str) -> int:
    return int(
        await db.scalar(
            select(func.count(Approval.id))
            .join(Device, Device.id == Approval.device_id)
            .where(
                Approval.owner_user_id == owner_user_id,
                Approval.status == ApprovalStatus.PENDING,
                Approval.expires_at > datetime.now(UTC),
                Device.status != DeviceStatus.REVOKED,
            )
        )
        or 0
    )


async def approval_capacity_denial_reason_locked(
    db: AsyncSession,
    settings: Settings,
    owner_user_id: str,
    device_id: uuid.UUID,
    now: datetime,
) -> str | None:
    device_pending = int(
        await db.scalar(
            select(func.count(Approval.id)).where(
                Approval.device_id == device_id,
                Approval.status == ApprovalStatus.PENDING,
                Approval.expires_at > now,
            )
        )
        or 0
    )
    if device_pending >= settings.device_max_pending_approvals:
        return "approval_limit_default_deny"
    if (
        await active_pending_approval_count(db, owner_user_id)
        >= settings.bootstrap_max_pending_approvals
    ):
        return "owner_approval_limit_default_deny"
    return None


async def ensure_approval_record_capacity_locked(
    db: AsyncSession,
    settings: Settings,
    owner_user_id: str,
    device_id: uuid.UUID,
) -> None:
    device_records = int(
        await db.scalar(select(func.count(Approval.id)).where(Approval.device_id == device_id)) or 0
    )
    if device_records >= settings.device_max_approval_records:
        raise OwnerCapacityExceeded("device_approval_record_limit_exceeded")
    owner_records = int(
        await db.scalar(
            select(func.count(Approval.id)).where(Approval.owner_user_id == owner_user_id)
        )
        or 0
    )
    if owner_records >= settings.owner_max_approval_records:
        raise OwnerCapacityExceeded("owner_approval_record_limit_exceeded")


async def thread_is_safely_archivable(
    db: AsyncSession,
    binding: ThreadBinding,
) -> bool:
    if binding.status not in {ThreadBindingStatus.IDLE, ThreadBindingStatus.FAILED}:
        return False
    if binding.active_turn_id is not None:
        return False
    outstanding_command = await db.scalar(
        select(Command.id)
        .where(
            Command.thread_binding_id == binding.id,
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
    if outstanding_command is not None:
        return False
    pending_approval = await db.scalar(
        select(Approval.id)
        .join(Command, Command.id == Approval.command_id)
        .where(
            Command.thread_binding_id == binding.id,
            Approval.status == ApprovalStatus.PENDING,
        )
        .limit(1)
    )
    if pending_approval is not None:
        return False
    unacknowledged_frame = await db.scalar(
        select(DeviceOutbox.sequence)
        .where(
            DeviceOutbox.device_id == binding.device_id,
            DeviceOutbox.acked_at.is_(None),
        )
        .limit(1)
    )
    return unacknowledged_frame is None


def _validated_model(raw: object) -> ModelSummary | None:
    try:
        return ModelSummary.model_validate(raw)
    except ValueError:
        return None


def _first_string(value: dict[str, Any], *keys: str) -> str | None:
    for key in keys:
        candidate = value.get(key)
        if isinstance(candidate, str) and candidate:
            return candidate
    return None
