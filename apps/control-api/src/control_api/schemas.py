from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from .security import canonicalize_workspace_roots


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ExchangeRequest(StrictModel):
    access_token: str | None = Field(default=None, min_length=16, max_length=8192)


class UserView(StrictModel):
    id: str
    username: str | None = None
    email: str | None = None
    display_name: str | None = None


class SessionView(StrictModel):
    id: uuid.UUID
    user: UserView
    issued_at: datetime
    expires_at: datetime
    reauth_at: datetime
    csrf_header_name: str


class PairingStartRequest(StrictModel):
    protocol_version: Literal[2] = 2
    pairing_id: uuid.UUID
    created_at: datetime
    audience: str = Field(min_length=1, max_length=4096)
    public_key: str = Field(min_length=40, max_length=256)
    display_name: str = Field(min_length=1, max_length=255)
    connector_version: str = Field(min_length=1, max_length=64)
    codex_version: str = Field(min_length=1, max_length=64)
    workspace_roots: list[str] = Field(min_length=1, max_length=32)
    code_commitment: str = Field(pattern=r"^[0-9a-f]{64}$")
    poll_token_commitment: str = Field(pattern=r"^[0-9a-f]{64}$")
    refresh_credential_commitment: str = Field(pattern=r"^[0-9a-f]{64}$")
    signature: str = Field(min_length=80, max_length=128)

    @field_validator("display_name", "connector_version", "codex_version")
    @classmethod
    def normalize_text(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("value cannot be blank")
        return value

    @field_validator("workspace_roots")
    @classmethod
    def validate_workspace_roots(cls, value: list[str]) -> list[str]:
        return canonicalize_workspace_roots(value)


class PairingStartResponse(StrictModel):
    pairing_id: uuid.UUID
    expires_at: datetime
    poll_url: str


class PairingClaimRequest(StrictModel):
    code: str = Field(
        pattern=(
            r"^[23456789ABCDEFGHJKLMNPQRSTUVWXYZ]{4}"
            r"(?:-[23456789ABCDEFGHJKLMNPQRSTUVWXYZ]{4}){3}$"
        )
    )


class PairingClaimResponse(StrictModel):
    pairing_id: uuid.UUID
    device_id: uuid.UUID
    device_name: str
    status: Literal["claimed"] = "claimed"


class DeviceConnectTokenRequest(StrictModel):
    device_id: uuid.UUID
    public_key: str = Field(min_length=40, max_length=256)
    timestamp: str = Field(min_length=20, max_length=64)
    nonce: str = Field(min_length=32, max_length=128)
    signature: str = Field(min_length=80, max_length=128)


class DeviceConnectTokenResponse(StrictModel):
    access_token: str
    expires_at: datetime


class DeviceSummary(StrictModel):
    id: uuid.UUID
    name: str = Field(min_length=1, max_length=255)
    status: Literal["online", "offline", "revoked", "upgrading"]
    connector_version: str = Field(max_length=64)
    codex_version: str = Field(max_length=64)
    last_seen_at: datetime | None
    workspace_roots: list[str] = Field(max_length=32)


class DeviceListResponse(StrictModel):
    items: list[DeviceSummary]


class ThreadMessage(StrictModel):
    id: str
    role: Literal["user", "assistant", "system"]
    text: str
    created_at: datetime
    pending: bool = False
    error: bool = False


class ManagedThreadSummary(StrictModel):
    id: uuid.UUID
    device_id: uuid.UUID
    title: str = Field(min_length=1, max_length=255)
    cwd: str = Field(max_length=4096)
    model: str = Field(max_length=128)
    updated_at: datetime
    status: Literal["idle", "running", "waiting_for_approval", "failed"]


class ManagedThreadListResponse(StrictModel):
    items: list[ManagedThreadSummary]


class ThreadDetail(ManagedThreadSummary):
    messages: list[ThreadMessage]


class ThreadDetailSnapshot(StrictModel):
    event_cursor: str
    thread: ThreadDetail


class ThreadStartRequest(StrictModel):
    cwd: str = Field(min_length=1, max_length=4096)
    model: str | None = Field(default=None, min_length=1, max_length=128)


class TurnTextRequest(StrictModel):
    text: str = Field(min_length=1, max_length=200_000)

    @field_validator("text")
    @classmethod
    def reject_blank_text(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("text cannot be blank")
        return value


class ApprovalDecisionRequest(StrictModel):
    decision: Literal["approve", "deny"]


class ApprovalItem(StrictModel):
    approval_id: uuid.UUID
    command_id: str
    kind: Literal["command", "file_change", "permission"]
    summary: str = Field(min_length=1, max_length=512)
    details: dict[str, Any]
    expires_at: datetime
    device_id: uuid.UUID
    device_name: str
    created_at: datetime


class ApprovalListResponse(StrictModel):
    items: list[ApprovalItem]


class CommandView(StrictModel):
    id: uuid.UUID
    state: Literal[
        "queued",
        "dispatched",
        "acknowledged",
        "succeeded",
        "failed",
        "denied",
        "cancelled",
        "expired",
    ]
    method: Literal[
        "model/list",
        "thread/start",
        "thread/list",
        "thread/read",
        "thread/resume",
        "turn/start",
        "turn/steer",
        "turn/interrupt",
    ]
    deadline_at: datetime | None
    result: dict[str, Any] | list[Any] | str | int | float | bool | None = None
    error_code: str | None = None
    error_message: str | None = None


class ModelSummary(StrictModel):
    id: str = Field(min_length=1, max_length=128)
    display_name: str = Field(min_length=1, max_length=255)
    description: str | None = Field(default=None, max_length=512)


class ModelListResponse(StrictModel):
    items: list[ModelSummary]


class ControlBootstrapResponse(StrictModel):
    event_cursor: str
    devices: list[DeviceSummary]
    threads: list[ManagedThreadSummary]
    approvals: list[ApprovalItem]
    models_by_device: dict[str, list[ModelSummary]]


class BrowserEvent(StrictModel):
    cursor: str
    type: Literal[
        "device.updated",
        "thread.updated",
        "turn.delta",
        "turn.completed",
        "approval.created",
        "approval.resolved",
        "command.updated",
    ]
    occurred_at: datetime
    data: dict[str, Any]


class PairingPendingResponse(StrictModel):
    status: Literal["pending"] = "pending"
    pairing_id: uuid.UUID
    expires_at: datetime


class PairingCompletedResponse(StrictModel):
    status: Literal["claimed"] = "claimed"
    device_id: uuid.UUID


class HealthResponse(StrictModel):
    status: Literal["ok"] = "ok"


class ReadinessResponse(StrictModel):
    status: Literal["ready", "not_ready"]
    checks: dict[str, Literal["ok", "failed"]]
