from __future__ import annotations

import json
from typing import Any

from .protocol import (
    MAX_ENSURE_ASCII_PARAMS_BYTES,
    MAX_ENSURE_ASCII_PROJECTED_BYTES,
    MAX_ENSURE_ASCII_TEXT_BYTES,
    MAX_FRAME_BYTES,
    MAX_TEXT_CODE_POINTS,
    ensure_ascii_json_byte_length,
    ensure_ascii_string_content_byte_length,
)

MAX_DEVICE_ENVELOPE_BYTES = MAX_FRAME_BYTES
MAX_COMMAND_PARAMS_BYTES = MAX_ENSURE_ASCII_PARAMS_BYTES
MAX_PROJECTED_COMMAND_PARAMS_BYTES = MAX_ENSURE_ASCII_PROJECTED_BYTES
MAX_TURN_TEXT_ENCODED_BYTES = MAX_ENSURE_ASCII_TEXT_BYTES
MAX_TURN_TEXT_CODE_POINTS = MAX_TEXT_CODE_POINTS

_MAX_SEQUENCE = 9_223_372_036_854_775_807
_UUID_PLACEHOLDER = "ffffffff-ffff-ffff-ffff-ffffffffffff"
_TIMESTAMP_PLACEHOLDER = "9999-12-31T23:59:59.999999Z"


class CommandPayloadTooLarge(ValueError):
    pass


def compact_ensure_ascii_size(value: Any) -> int:
    return ensure_ascii_json_byte_length(value)


def ensure_ascii_string_content_size(value: str) -> int:
    return ensure_ascii_string_content_byte_length(value)


def connector_compact_json_size(value: Any) -> int:
    """Return the bytes emitted by Go encoding/json for valid Python JSON values."""
    encoded = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    encoded = (
        encoded.replace("<", r"\u003c")
        .replace(">", r"\u003e")
        .replace("&", r"\u0026")
        .replace("\u2028", r"\u2028")
        .replace("\u2029", r"\u2029")
    )
    try:
        return len(encoded.encode("utf-8"))
    except UnicodeEncodeError:
        # Unpaired surrogates are not valid UTF-8; the canonical limit remains fail closed.
        return compact_ensure_ascii_size(value)


def validate_turn_text_budget(text: str) -> None:
    if len(text) > MAX_TURN_TEXT_CODE_POINTS:
        raise CommandPayloadTooLarge("turn text exceeds the Unicode code point limit")
    if ensure_ascii_string_content_size(text) > MAX_TURN_TEXT_ENCODED_BYTES:
        raise CommandPayloadTooLarge("turn text exceeds the compact ensure_ascii byte limit")


def projected_command_params(
    method: str,
    params: dict[str, object],
    workspace_roots: list[str],
) -> dict[str, object]:
    """Mirror the Connector's size-relevant canonical additions without policy expansion."""
    projected = dict(params)
    if method in {"thread/start", "thread/resume"}:
        projected["sandbox"] = "workspace-write"
        projected["approvalPolicy"] = "on-request"
        projected["approvalsReviewer"] = "user"
    elif method == "thread/list":
        cwd = params.get("cwd")
        if cwd is None:
            projected["cwd"] = list(workspace_roots)
        elif isinstance(cwd, str):
            projected["cwd"] = [cwd]
    elif method == "thread/read" and "includeTurns" not in projected:
        projected["includeTurns"] = False
    elif method in {"turn/start", "turn/steer"}:
        input_items = params.get("input")
        if isinstance(input_items, list) and len(input_items) == 1:
            item = input_items[0]
            if isinstance(item, dict) and item.get("type") == "text":
                canonical_item = dict(item)
                canonical_item["text_elements"] = []
                projected["input"] = [canonical_item]
        if method == "turn/start":
            projected["sandboxPolicy"] = {
                "type": "workspaceWrite",
                "writableRoots": [],
                "networkAccess": False,
                "excludeSlashTmp": True,
                "excludeTmpdirEnvVar": True,
            }
            projected["approvalPolicy"] = "on-request"
            projected["approvalsReviewer"] = "user"
    return projected


def validate_command_budget(
    *,
    device_id: object,
    epoch: str,
    workspace_roots: list[str],
    method: str,
    params: dict[str, object],
    idempotency_key: str,
    max_envelope_bytes: int,
) -> None:
    if method in {"turn/start", "turn/steer"}:
        input_items = params.get("input")
        if isinstance(input_items, list) and len(input_items) == 1:
            item = input_items[0]
            if isinstance(item, dict) and isinstance(item.get("text"), str):
                validate_turn_text_budget(item["text"])

    if compact_ensure_ascii_size(params) > MAX_COMMAND_PARAMS_BYTES:
        raise CommandPayloadTooLarge("command params exceed the compact ensure_ascii byte limit")

    projected = projected_command_params(method, params, workspace_roots)
    if (
        compact_ensure_ascii_size(projected) > MAX_PROJECTED_COMMAND_PARAMS_BYTES
        or connector_compact_json_size(projected) > MAX_PROJECTED_COMMAND_PARAMS_BYTES
    ):
        raise CommandPayloadTooLarge(
            "projected command params exceed the compact ensure_ascii byte limit"
        )

    envelope = {
        "version": 1,
        "id": _UUID_PLACEHOLDER,
        "device_id": str(device_id),
        "epoch": epoch,
        "seq": _MAX_SEQUENCE,
        "ack": _MAX_SEQUENCE,
        "type": "command",
        "sent_at": _TIMESTAMP_PLACEHOLDER,
        "payload": {
            "command_id": _UUID_PLACEHOLDER,
            "idempotency_key": idempotency_key,
            "method": method,
            "params": params,
            "deadline_at": _TIMESTAMP_PLACEHOLDER,
        },
    }
    effective_envelope_limit = min(max_envelope_bytes, MAX_DEVICE_ENVELOPE_BYTES)
    if compact_ensure_ascii_size(envelope) > effective_envelope_limit:
        raise CommandPayloadTooLarge("command envelope exceeds the compact ensure_ascii byte limit")
