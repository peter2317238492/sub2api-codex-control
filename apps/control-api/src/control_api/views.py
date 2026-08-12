from __future__ import annotations

import json

from pydantic import ValidationError

from .models import Device, DeviceStatus, ThreadBinding, ThreadBindingStatus
from .schemas import DeviceSummary, ManagedThreadSummary, ThreadDetail, ThreadMessage
from .storage import KeyValueStore


async def device_summary(device: Device, store: KeyValueStore) -> DeviceSummary:
    registry_raw = await store.get(f"connection:{device.id}")
    try:
        parsed_registry = json.loads(registry_raw) if registry_raw is not None else {}
    except json.JSONDecodeError:
        parsed_registry = {}
    registry_nonce = (
        parsed_registry.get("connection_nonce") if isinstance(parsed_registry, dict) else None
    )
    if device.status == DeviceStatus.REVOKED:
        status = "revoked"
    elif device.active_connection_nonce and registry_nonce == device.active_connection_nonce:
        status = "online"
    else:
        status = "offline"
    metadata = device.device_metadata or {}
    return DeviceSummary(
        id=device.id,
        name=device.name,
        status=status,
        connector_version=str(metadata.get("connector_version", "")),
        codex_version=str(metadata.get("codex_version", "")),
        last_seen_at=device.last_seen_at,
        workspace_roots=device.workspace_roots or [],
    )


def thread_summary(binding: ThreadBinding) -> ManagedThreadSummary:
    visible_status = (
        binding.status
        if binding.status
        in {
            ThreadBindingStatus.IDLE,
            ThreadBindingStatus.RUNNING,
            ThreadBindingStatus.WAITING_FOR_APPROVAL,
            ThreadBindingStatus.FAILED,
        }
        else ThreadBindingStatus.FAILED
    )
    return ManagedThreadSummary(
        id=binding.id,
        device_id=binding.device_id,
        title=binding.title,
        cwd=binding.cwd or "",
        model=binding.model,
        updated_at=binding.updated_at,
        status=visible_status.value,
    )


def thread_detail(binding: ThreadBinding) -> ThreadDetail:
    messages: list[ThreadMessage] = []
    snapshot = binding.snapshot or {}
    for raw in snapshot.get("messages", []):
        try:
            messages.append(ThreadMessage.model_validate(raw))
        except ValidationError:
            continue
    return ThreadDetail(**thread_summary(binding).model_dump(), messages=messages)
