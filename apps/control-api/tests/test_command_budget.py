from __future__ import annotations

import json
from pathlib import Path

import pytest

from control_api.command_budget import (
    MAX_COMMAND_PARAMS_BYTES,
    MAX_DEVICE_ENVELOPE_BYTES,
    MAX_PROJECTED_COMMAND_PARAMS_BYTES,
    MAX_TURN_TEXT_ENCODED_BYTES,
    CommandPayloadTooLarge,
    compact_ensure_ascii_size,
    connector_compact_json_size,
    ensure_ascii_string_content_size,
    projected_command_params,
    validate_command_budget,
    validate_turn_text_budget,
)

_REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
_BUDGET_VECTORS = json.loads(
    (
        _REPOSITORY_ROOT / "packages" / "control-protocol" / "fixtures" / "json-budget-vectors.json"
    ).read_text()
)
_RPC_POLICY = json.loads(
    (
        _REPOSITORY_ROOT / "packages" / "control-protocol" / "fixtures" / "rpc-policy.json"
    ).read_text()
)


def _vector_value(vector: dict[str, object]) -> str:
    return str(vector["unit"]) * int(vector["repeat"]) + str(vector.get("suffix", ""))


def test_python_budget_constants_match_the_shared_rpc_policy() -> None:
    assert MAX_DEVICE_ENVELOPE_BYTES == _RPC_POLICY["max_frame_bytes"]
    assert MAX_COMMAND_PARAMS_BYTES == _RPC_POLICY["max_ensure_ascii_params_bytes"]
    assert MAX_PROJECTED_COMMAND_PARAMS_BYTES == _RPC_POLICY["max_ensure_ascii_projected_bytes"]
    assert MAX_TURN_TEXT_ENCODED_BYTES == _RPC_POLICY["max_ensure_ascii_text_bytes"]
    assert MAX_DEVICE_ENVELOPE_BYTES - MAX_PROJECTED_COMMAND_PARAMS_BYTES == 32 * 1024


@pytest.mark.parametrize("vector", _BUDGET_VECTORS["string_content"], ids=lambda row: row["name"])
def test_turn_text_uses_shared_compact_ensure_ascii_boundaries(
    vector: dict[str, object],
) -> None:
    text = _vector_value(vector)
    assert ensure_ascii_string_content_size(text) == vector["expected_bytes"]
    if vector["allowed"]:
        validate_turn_text_budget(text)
    else:
        with pytest.raises(CommandPayloadTooLarge):
            validate_turn_text_budget(text)


@pytest.mark.parametrize("vector", _BUDGET_VECTORS["escape_samples"], ids=lambda row: row["name"])
def test_turn_text_uses_shared_escape_sizes(vector: dict[str, object]) -> None:
    assert ensure_ascii_string_content_size(str(vector["value"])) == vector["expected_bytes"]


@pytest.mark.parametrize("vector", _BUDGET_VECTORS["json_documents"], ids=lambda row: row["name"])
def test_params_use_shared_compact_ensure_ascii_boundaries(
    vector: dict[str, object],
) -> None:
    document = {str(vector["key"]): _vector_value(vector)}
    encoded_size = compact_ensure_ascii_size(document)
    assert encoded_size == vector["expected_bytes"]
    assert (encoded_size <= MAX_COMMAND_PARAMS_BYTES) is vector["allowed"]
    if vector["allowed"]:
        validate_command_budget(
            device_id="ffffffff-ffff-ffff-ffff-ffffffffffff",
            epoch="e" * 128,
            workspace_roots=["/workspace"],
            method="model/list",
            params=document,
            idempotency_key="request-1",
            max_envelope_bytes=MAX_DEVICE_ENVELOPE_BYTES,
        )
    else:
        with pytest.raises(CommandPayloadTooLarge, match="params"):
            validate_command_budget(
                device_id="ffffffff-ffff-ffff-ffff-ffffffffffff",
                epoch="e" * 128,
                workspace_roots=["/workspace"],
                method="model/list",
                params=document,
                idempotency_key="request-1",
                max_envelope_bytes=MAX_DEVICE_ENVELOPE_BYTES,
            )


def test_turn_text_enforces_code_points_before_encoded_bytes() -> None:
    with pytest.raises(CommandPayloadTooLarge, match="Unicode code point"):
        validate_turn_text_budget("a" * 200_001)
    with pytest.raises(CommandPayloadTooLarge, match="ensure_ascii"):
        validate_turn_text_budget("😀" * 16_666 + "a" * 9)


def test_projected_budget_includes_connector_html_escaping() -> None:
    text = "<" * 200_000
    validate_turn_text_budget(text)
    projected = projected_command_params(
        "turn/start",
        {"threadId": "thread-1", "input": [{"type": "text", "text": text}]},
        ["/workspace"],
    )
    assert compact_ensure_ascii_size(projected) <= MAX_PROJECTED_COMMAND_PARAMS_BYTES
    assert connector_compact_json_size(projected) > MAX_PROJECTED_COMMAND_PARAMS_BYTES
    with pytest.raises(CommandPayloadTooLarge, match="projected"):
        validate_command_budget(
            device_id="ffffffff-ffff-ffff-ffff-ffffffffffff",
            epoch="e" * 128,
            workspace_roots=["/workspace"],
            method="turn/start",
            params={"threadId": "thread-1", "input": [{"type": "text", "text": text}]},
            idempotency_key="request-1",
            max_envelope_bytes=MAX_DEVICE_ENVELOPE_BYTES,
        )


def test_command_budget_accounts_for_connector_projection_and_envelope_wrapper() -> None:
    params = {
        "threadId": "😀" * 512,
        "clientUserMessageId": "😀" * 512,
        "expectedTurnId": "😀" * 512,
        "input": [{"type": "text", "text": "a" * 200_000}],
    }
    projected = projected_command_params("turn/steer", params, ["/workspace"])
    assert projected["input"] == [{"type": "text", "text": "a" * 200_000, "text_elements": []}]
    assert compact_ensure_ascii_size(projected) <= MAX_PROJECTED_COMMAND_PARAMS_BYTES
    validate_command_budget(
        device_id="ffffffff-ffff-ffff-ffff-ffffffffffff",
        epoch="😀" * 128,
        workspace_roots=["/workspace"],
        method="turn/steer",
        params=params,
        idempotency_key="😀" * 128,
        max_envelope_bytes=MAX_DEVICE_ENVELOPE_BYTES,
    )

    start_projection = projected_command_params(
        "turn/start",
        {"threadId": "thread-1", "input": [{"type": "text", "text": "hello"}]},
        ["/workspace"],
    )
    assert start_projection["sandboxPolicy"] == {
        "type": "workspaceWrite",
        "writableRoots": [],
        "networkAccess": False,
        "excludeSlashTmp": True,
        "excludeTmpdirEnvVar": True,
    }
    assert start_projection["approvalPolicy"] == "on-request"
    assert start_projection["approvalsReviewer"] == "user"

    resume_projection = projected_command_params(
        "thread/resume", {"threadId": "thread-1"}, ["/workspace"]
    )
    assert resume_projection == {
        "threadId": "thread-1",
        "sandbox": "workspace-write",
        "approvalPolicy": "on-request",
        "approvalsReviewer": "user",
    }


def test_command_budget_rejects_when_a_smaller_configured_envelope_cannot_fit() -> None:
    with pytest.raises(CommandPayloadTooLarge, match="envelope"):
        validate_command_budget(
            device_id="ffffffff-ffff-ffff-ffff-ffffffffffff",
            epoch="e" * 128,
            workspace_roots=["/workspace"],
            method="turn/start",
            params={
                "threadId": "thread-1",
                "input": [{"type": "text", "text": "a" * 4_000}],
            },
            idempotency_key="request-1",
            max_envelope_bytes=4_096,
        )
