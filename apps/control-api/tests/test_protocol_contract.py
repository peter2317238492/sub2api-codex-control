from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from control_api.protocol import (
    MAX_ENSURE_ASCII_PARAMS_BYTES,
    MAX_ENSURE_ASCII_PROJECTED_BYTES,
    MAX_ENSURE_ASCII_TEXT_BYTES,
    MAX_FRAME_BYTES,
    MAX_SEQUENCE,
    CommandAckPayload,
    CommandPayload,
    ControlEnvelope,
    DeviceEventPayload,
    HelloAckPayload,
    ProtocolErrorPayload,
    ensure_ascii_json_byte_length,
    ensure_ascii_string_content_byte_length,
    validate_envelope_payload,
)

FIXTURE_PATH = (
    Path(__file__).resolve().parents[3]
    / "packages"
    / "control-protocol"
    / "fixtures"
    / "wire-envelopes.json"
)
BUDGET_FIXTURE_PATH = FIXTURE_PATH.with_name("json-budget-vectors.json")


def load_wire_fixture() -> dict[str, Any]:
    return json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))


def load_budget_fixture() -> dict[str, Any]:
    return json.loads(BUDGET_FIXTURE_PATH.read_text(encoding="utf-8"))


def expand_vector(vector: dict[str, Any]) -> str:
    return str(vector["unit"]) * int(vector["repeat"]) + str(vector.get("suffix", ""))


def test_shared_valid_wire_fixtures_decode_with_discriminated_payload_models() -> None:
    fixture = load_wire_fixture()
    assert fixture["protocol_version"] == 1
    decoded: dict[str, object] = {}
    for case in fixture["valid"]:
        envelope = ControlEnvelope.model_validate(case["envelope"])
        decoded[case["name"]] = validate_envelope_payload(envelope)

    hello_ack = decoded["hello_ack"]
    assert isinstance(hello_ack, HelloAckPayload)
    assert str(hello_ack.connection_id) == "22222222-2222-4222-8222-222222222222"
    assert hello_ack.heartbeat_timeout_seconds == 60

    protocol_error = decoded["error"]
    assert isinstance(protocol_error, ProtocolErrorPayload)
    assert protocol_error.code == "invalid_upstream"


@pytest.mark.parametrize("case", load_wire_fixture()["invalid"], ids=lambda case: case["name"])
def test_shared_invalid_wire_fixtures_fail_closed(case: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        envelope = ControlEnvelope.model_validate(case["envelope"])
        validate_envelope_payload(envelope)


def test_shared_ascii_cjk_and_emoji_text_boundaries_match_pydantic() -> None:
    fixture = load_budget_fixture()
    assert fixture["version"] == 1
    assert fixture["encoding"] == "compact-ensure-ascii"
    for vector in fixture["string_content"]:
        text = expand_vector(vector)
        assert ensure_ascii_string_content_byte_length(text) == vector["expected_bytes"]
        assert vector["expected_bytes"] == (
            MAX_ENSURE_ASCII_TEXT_BYTES if vector["allowed"] else MAX_ENSURE_ASCII_TEXT_BYTES + 1
        )
        payload = {
            "command_id": "33333333-3333-4333-8333-333333333333",
            "idempotency_key": f"boundary-{vector['name']}",
            "method": "turn/start",
            "params": {
                "threadId": "managed-thread-1",
                "input": [{"type": "text", "text": text}],
            },
            "deadline_at": "2026-07-13T00:01:04Z",
        }
        if vector["allowed"]:
            assert CommandPayload.model_validate(payload).params["input"][0]["text"] == text
        else:
            with pytest.raises(ValidationError):
                CommandPayload.model_validate(payload)


def test_shared_escape_samples_match_python_ensure_ascii_encoding() -> None:
    fixture = load_budget_fixture()
    for sample in fixture["escape_samples"]:
        assert ensure_ascii_string_content_byte_length(sample["value"]) == sample["expected_bytes"]


@pytest.mark.parametrize(
    ("field", "value"),
    [("seq", "1"), ("seq", 1.0), ("seq", True), ("sent_at", 1)],
)
def test_envelope_does_not_coerce_wire_scalar_types(field: str, value: object) -> None:
    fixture = load_wire_fixture()
    source = next(case["envelope"] for case in fixture["valid"] if case["name"] == "heartbeat")
    envelope = json.loads(json.dumps(source))
    envelope[field] = value
    with pytest.raises(ValidationError):
        ControlEnvelope.model_validate(envelope)


@pytest.mark.parametrize("retryable", ["false", 0])
def test_protocol_error_does_not_coerce_retryable(retryable: object) -> None:
    fixture = load_wire_fixture()
    source = next(case["envelope"] for case in fixture["valid"] if case["name"] == "error")
    envelope = json.loads(json.dumps(source))
    envelope["payload"]["retryable"] = retryable
    with pytest.raises(ValidationError):
        ControlEnvelope.model_validate(envelope)


def test_signed_bigint_sequence_boundaries_apply_to_every_wire_cursor() -> None:
    fixture = load_wire_fixture()
    assert int(fixture["limits"]["max_sequence"]) == MAX_SEQUENCE
    cases = [
        ("heartbeat", None, "seq"),
        ("heartbeat", None, "ack"),
        ("hello", "payload", "resumed_from_seq"),
        ("hello_ack", "payload", "received_seq"),
        ("heartbeat_ack", "payload", "received_seq"),
    ]
    for fixture_name, container, field in cases:
        source = next(case["envelope"] for case in fixture["valid"] if case["name"] == fixture_name)
        envelope = json.loads(json.dumps(source))
        target = envelope if container is None else envelope[container]
        target[field] = MAX_SEQUENCE
        ControlEnvelope.model_validate(envelope)

        target[field] = MAX_SEQUENCE + 1
        with pytest.raises(ValidationError):
            ControlEnvelope.model_validate(envelope)


def test_epoch_and_multibyte_workspace_root_boundaries_match_shared_limits() -> None:
    fixture = load_wire_fixture()
    heartbeat = next(case["envelope"] for case in fixture["valid"] if case["name"] == "heartbeat")
    epoch_limit = fixture["limits"]["max_epoch_code_points"]
    at_epoch_limit = json.loads(json.dumps(heartbeat))
    at_epoch_limit["epoch"] = "e" * epoch_limit
    ControlEnvelope.model_validate(at_epoch_limit)
    at_epoch_limit["epoch"] += "e"
    with pytest.raises(ValidationError):
        ControlEnvelope.model_validate(at_epoch_limit)

    hello = next(case["envelope"] for case in fixture["valid"] if case["name"] == "hello")
    root_at_limit = "/" + "😀" * 1_023 + "aaa"
    root_over_limit = root_at_limit + "a"
    assert len(root_at_limit.encode()) == fixture["limits"]["max_workspace_root_utf8_bytes"]
    assert len(root_over_limit.encode()) == fixture["limits"]["max_workspace_root_utf8_bytes"] + 1

    at_root_limit = json.loads(json.dumps(hello))
    at_root_limit["payload"]["workspace_roots"] = [root_at_limit]
    ControlEnvelope.model_validate(at_root_limit)
    at_root_limit["payload"]["workspace_roots"] = [root_over_limit]
    with pytest.raises(ValidationError):
        ControlEnvelope.model_validate(at_root_limit)
    at_root_limit["payload"]["workspace_roots"] = ["/workspace/../escape"]
    with pytest.raises(ValidationError):
        ControlEnvelope.model_validate(at_root_limit)


def test_non_finite_json_values_and_noncanonical_dates_fail_closed() -> None:
    fixture = load_wire_fixture()
    event = next(case["envelope"] for case in fixture["valid"] if case["name"] == "event")
    non_finite = json.loads(json.dumps(event))
    non_finite["payload"]["params"] = {"value": float("nan")}
    with pytest.raises(ValidationError):
        ControlEnvelope.model_validate(non_finite)

    date_only = json.loads(json.dumps(event))
    date_only["sent_at"] = "2026-07-13"
    with pytest.raises(ValidationError):
        ControlEnvelope.model_validate(date_only)


def test_shared_params_and_projected_json_boundaries_match_pydantic() -> None:
    fixture = load_budget_fixture()
    for vector in fixture["json_documents"]:
        document = {str(vector["key"]): expand_vector(vector)}
        assert ensure_ascii_json_byte_length(document) == vector["expected_bytes"]
        expected = (
            MAX_ENSURE_ASCII_PARAMS_BYTES
            if vector["allowed"]
            else MAX_ENSURE_ASCII_PARAMS_BYTES + 1
        )
        assert vector["expected_bytes"] == expected
        command = {
            "command_id": "33333333-3333-4333-8333-333333333333",
            "idempotency_key": f"params-{vector['name']}",
            "method": "model/list",
            "params": document,
            "deadline_at": "2026-07-13T00:01:04Z",
        }
        acknowledgement = {
            "command_id": "33333333-3333-4333-8333-333333333333",
            "state": "completed",
            "result": document,
        }
        event = {"method": "turn/completed", "params": document}
        assert MAX_ENSURE_ASCII_PROJECTED_BYTES == MAX_ENSURE_ASCII_PARAMS_BYTES
        if vector["allowed"]:
            CommandPayload.model_validate(command)
            CommandAckPayload.model_validate(acknowledgement)
            DeviceEventPayload.model_validate(event)
        else:
            with pytest.raises(ValidationError):
                CommandPayload.model_validate(command)
            with pytest.raises(ValidationError):
                CommandAckPayload.model_validate(acknowledgement)
            with pytest.raises(ValidationError):
                DeviceEventPayload.model_validate(event)


def test_pydantic_enforces_exact_wire_frame_boundary() -> None:
    fixture = load_wire_fixture()
    approval = next(
        case["envelope"] for case in fixture["valid"] if case["name"] == "approval_request"
    )
    base = json.loads(json.dumps(approval))
    base["payload"]["details"] = {"padding": ""}
    base_bytes = ensure_ascii_json_byte_length(base)
    base["payload"]["details"]["padding"] = "a" * (MAX_FRAME_BYTES - base_bytes)
    assert ensure_ascii_json_byte_length(base) == MAX_FRAME_BYTES
    ControlEnvelope.model_validate(base)

    base["payload"]["details"]["padding"] += "a"
    assert ensure_ascii_json_byte_length(base) == MAX_FRAME_BYTES + 1
    with pytest.raises(ValidationError):
        ControlEnvelope.model_validate(base)
