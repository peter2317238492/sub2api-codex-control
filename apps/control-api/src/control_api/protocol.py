from __future__ import annotations

import json
import re
import uuid
from datetime import datetime
from typing import Annotated, Any, Literal

from pydantic import BaseModel, BeforeValidator, ConfigDict, Field, field_validator, model_validator

from .security import canonicalize_workspace_roots

PROTOCOL_VERSION = 1
MAX_FRAME_BYTES = 262_144
MAX_ENSURE_ASCII_PARAMS_BYTES = 229_376
MAX_ENSURE_ASCII_PROJECTED_BYTES = 229_376
MAX_ENSURE_ASCII_TEXT_BYTES = 200_000
MAX_TEXT_CODE_POINTS = 200_000
MAX_SEQUENCE = 9_223_372_036_854_775_807
_CANONICAL_UUID = re.compile(
    r"^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$"
)
_RFC3339_DATETIME = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$"
)
AllowedRpcMethod = Literal[
    "model/list",
    "thread/start",
    "thread/list",
    "thread/read",
    "thread/resume",
    "turn/start",
    "turn/steer",
    "turn/interrupt",
]
ProtocolErrorCode = Literal[
    "invalid_envelope",
    "unsupported_version",
    "unauthorized",
    "policy_denied",
    "invalid_epoch",
    "expired",
    "conflict",
    "upstream_error",
    "invalid_upstream",
    "indeterminate",
    "internal_error",
]
ALLOWED_RPC_METHODS = frozenset(
    {
        "model/list",
        "thread/start",
        "thread/list",
        "thread/read",
        "thread/resume",
        "turn/start",
        "turn/steer",
        "turn/interrupt",
    }
)

DEVICE_OUTBOUND_TYPES = frozenset(
    {"hello", "heartbeat", "heartbeat_ack", "command_ack", "event", "approval_request", "error"}
)
SERVER_OUTBOUND_TYPES = frozenset(
    {"hello_ack", "heartbeat", "heartbeat_ack", "command", "approval_decision", "token_refresh"}
)


class WireModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


def _require_canonical_uuid(value: Any) -> Any:
    if isinstance(value, uuid.UUID):
        return value
    if not isinstance(value, str) or _CANONICAL_UUID.fullmatch(value) is None:
        raise ValueError("UUID fields must use canonical hyphenated notation")
    return value


def _require_rfc3339_datetime(value: Any) -> Any:
    if isinstance(value, datetime):
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("datetime values must include a UTC offset")
        return value
    if not isinstance(value, str) or _RFC3339_DATETIME.fullmatch(value) is None:
        raise ValueError("datetime fields must use RFC 3339 notation")
    return value


WireUUID = Annotated[uuid.UUID, BeforeValidator(_require_canonical_uuid)]
WireDateTime = Annotated[datetime, BeforeValidator(_require_rfc3339_datetime)]


def _wire_json_default(value: Any) -> str:
    if isinstance(value, uuid.UUID):
        return str(value)
    if isinstance(value, datetime):
        return value.isoformat().replace("+00:00", "Z")
    raise TypeError(f"{type(value).__name__} is not JSON serializable")


def ensure_ascii_json_byte_length(value: Any) -> int:
    try:
        encoded = json.dumps(
            value,
            ensure_ascii=True,
            separators=(",", ":"),
            allow_nan=False,
            default=_wire_json_default,
        )
    except (TypeError, ValueError) as exc:
        raise ValueError("wire value is not JSON serializable") from exc
    return len(encoded.encode("ascii"))


def ensure_ascii_string_content_byte_length(value: str) -> int:
    return ensure_ascii_json_byte_length(value) - 2


class ControlEnvelope(WireModel):
    version: Literal[1]
    id: WireUUID
    device_id: WireUUID
    epoch: str = Field(min_length=16, max_length=128)
    seq: int = Field(strict=True, ge=0, le=MAX_SEQUENCE)
    ack: int | None = Field(default=None, strict=True, ge=0, le=MAX_SEQUENCE)
    type: Literal[
        "hello",
        "hello_ack",
        "heartbeat",
        "heartbeat_ack",
        "command",
        "command_ack",
        "event",
        "approval_request",
        "approval_decision",
        "token_refresh",
        "error",
    ]
    sent_at: WireDateTime
    payload: dict[str, Any]

    @model_validator(mode="before")
    @classmethod
    def validate_frame_budget(cls, value: Any) -> Any:
        if isinstance(value, dict) and ensure_ascii_json_byte_length(value) > MAX_FRAME_BYTES:
            raise ValueError(f"control envelope exceeds the {MAX_FRAME_BYTES}-byte wire budget")
        return value

    @field_validator("version", mode="before")
    @classmethod
    def validate_version_type(cls, value: Any) -> Any:
        if type(value) is not int:
            raise ValueError("control protocol version must be an integer")
        return value

    @model_validator(mode="after")
    def validate_handshake_sequence(self) -> ControlEnvelope:
        is_handshake = self.type in {"hello", "hello_ack"}
        if is_handshake and self.seq != 0:
            raise ValueError("hello and hello_ack must use sequence zero")
        if not is_handshake and self.seq == 0:
            raise ValueError("only hello and hello_ack may use sequence zero")
        WIRE_PAYLOAD_MODELS[self.type].model_validate(self.payload)
        return self


class HelloPayload(WireModel):
    connector_version: str = Field(min_length=1, max_length=64)
    codex_version: str = Field(min_length=1, max_length=64)
    schema_digest: str = Field(min_length=16, max_length=256)
    public_key: str = Field(min_length=40, max_length=256)
    capabilities: list[str] = Field(min_length=1, max_length=32)
    workspace_roots: list[str] = Field(min_length=1, max_length=32)
    resumed_from_seq: int = Field(default=0, strict=True, ge=0, le=MAX_SEQUENCE)

    @field_validator("capabilities")
    @classmethod
    def validate_capabilities(cls, value: list[str]) -> list[str]:
        if len(value) != len(set(value)):
            raise ValueError("capabilities cannot contain duplicates")
        unknown = set(value) - ALLOWED_RPC_METHODS
        if unknown:
            raise ValueError(f"unsupported capabilities: {sorted(unknown)}")
        return value

    @field_validator("workspace_roots")
    @classmethod
    def validate_workspace_roots(cls, value: list[str]) -> list[str]:
        return canonicalize_workspace_roots(value)


class HeartbeatPayload(WireModel):
    status: Literal["ok"]


class HeartbeatAckPayload(WireModel):
    received_seq: int = Field(strict=True, ge=0, le=MAX_SEQUENCE)


class HelloAckPayload(WireModel):
    connection_id: WireUUID
    protocol_version: Literal[1]
    device_id: WireUUID
    epoch: str = Field(min_length=16, max_length=128)
    schema_digest: str = Field(min_length=16, max_length=256)
    received_seq: int = Field(strict=True, ge=0, le=MAX_SEQUENCE)
    heartbeat_timeout_seconds: int = Field(strict=True, ge=5, le=300)

    @field_validator("protocol_version", mode="before")
    @classmethod
    def validate_protocol_version_type(cls, value: Any) -> Any:
        if type(value) is not int:
            raise ValueError("protocol_version must be an integer")
        return value


class CommandPayload(WireModel):
    command_id: WireUUID
    idempotency_key: str = Field(min_length=1, max_length=128)
    method: AllowedRpcMethod
    params: dict[str, Any]
    deadline_at: WireDateTime

    @model_validator(mode="after")
    def validate_param_budget(self) -> CommandPayload:
        if ensure_ascii_json_byte_length(self.params) > MAX_ENSURE_ASCII_PARAMS_BYTES:
            raise ValueError(
                f"command params exceed the {MAX_ENSURE_ASCII_PARAMS_BYTES}-byte "
                "ensure_ascii budget"
            )
        if self.method not in {"turn/start", "turn/steer"}:
            return self
        inputs = self.params.get("input")
        if not isinstance(inputs, list) or len(inputs) != 1 or not isinstance(inputs[0], dict):
            raise ValueError("remote turns require exactly one text input")
        item = inputs[0]
        if set(item) - {"type", "text", "text_elements"} or item.get("type") != "text":
            raise ValueError("remote turns allow text input only")
        if "text_elements" in item and item["text_elements"] != []:
            raise ValueError("remote turn text_elements must be empty")
        text = item.get("text")
        if not isinstance(text, str) or not text.strip() or len(text) > MAX_TEXT_CODE_POINTS:
            raise ValueError(f"turn text must contain 1 to {MAX_TEXT_CODE_POINTS} characters")
        if ensure_ascii_string_content_byte_length(text) > MAX_ENSURE_ASCII_TEXT_BYTES:
            raise ValueError(
                f"turn text exceeds the {MAX_ENSURE_ASCII_TEXT_BYTES}-byte ensure_ascii budget"
            )
        return self


class ProtocolErrorPayload(WireModel):
    code: ProtocolErrorCode
    message: str = Field(min_length=1, max_length=4096)
    retryable: bool = Field(strict=True)

    @field_validator("message")
    @classmethod
    def validate_message_content(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("protocol error message cannot be blank")
        return value


class CommandAckError(ProtocolErrorPayload):
    pass


class CommandAckPayload(WireModel):
    command_id: WireUUID
    state: Literal["accepted", "running", "completed", "failed", "expired", "denied"]
    result: Any = None
    error: CommandAckError | None = None

    @model_validator(mode="after")
    def validate_state_shape(self) -> CommandAckPayload:
        has_result = "result" in self.model_fields_set
        has_error = "error" in self.model_fields_set
        if self.state in {"accepted", "running"} and (has_result or has_error):
            raise ValueError("non-terminal command acknowledgements cannot carry result or error")
        if self.state == "completed" and (not has_result or has_error):
            raise ValueError("completed command acknowledgements require result and forbid error")
        if self.state in {"failed", "expired", "denied"} and (
            not has_error or self.error is None or has_result
        ):
            raise ValueError("failed command acknowledgements require error and forbid result")
        if (
            has_result
            and ensure_ascii_json_byte_length(self.result) > MAX_ENSURE_ASCII_PROJECTED_BYTES
        ):
            raise ValueError(
                f"command result exceeds the {MAX_ENSURE_ASCII_PROJECTED_BYTES}-byte "
                "ensure_ascii budget"
            )
        return self


class DeviceEventPayload(WireModel):
    method: str = Field(min_length=1, max_length=128)
    params: dict[str, Any]

    @model_validator(mode="after")
    def validate_projected_budget(self) -> DeviceEventPayload:
        if ensure_ascii_json_byte_length(self.params) > MAX_ENSURE_ASCII_PROJECTED_BYTES:
            raise ValueError(
                f"event params exceed the {MAX_ENSURE_ASCII_PROJECTED_BYTES}-byte "
                "ensure_ascii budget"
            )
        return self


class ApprovalRequestPayload(WireModel):
    approval_id: WireUUID
    command_id: str = Field(min_length=1, max_length=255)
    kind: Literal["command", "file_change", "permission"]
    summary: str = Field(min_length=1, max_length=512)
    details: dict[str, Any]
    expires_at: WireDateTime


class ApprovalDecisionPayload(WireModel):
    approval_id: WireUUID
    decision: Literal["approve", "deny"]
    decided_at: WireDateTime


class TokenRefreshPayload(WireModel):
    pass


WIRE_PAYLOAD_MODELS: dict[str, type[WireModel]] = {
    "hello": HelloPayload,
    "hello_ack": HelloAckPayload,
    "heartbeat": HeartbeatPayload,
    "heartbeat_ack": HeartbeatAckPayload,
    "command": CommandPayload,
    "command_ack": CommandAckPayload,
    "event": DeviceEventPayload,
    "approval_request": ApprovalRequestPayload,
    "approval_decision": ApprovalDecisionPayload,
    "token_refresh": TokenRefreshPayload,
    "error": ProtocolErrorPayload,
}


def validate_envelope_payload(envelope: ControlEnvelope) -> WireModel:
    """Decode a wire payload with the model selected by the envelope discriminator."""
    return WIRE_PAYLOAD_MODELS[envelope.type].model_validate(envelope.payload)


def require_device_outbound(envelope: ControlEnvelope) -> None:
    if envelope.type not in DEVICE_OUTBOUND_TYPES:
        raise ValueError(f"device cannot send envelope type {envelope.type}")
