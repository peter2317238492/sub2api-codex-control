from __future__ import annotations

import json
import logging
import os
import subprocess
import sys

from control_api.logging_config import MAX_MESSAGE_LENGTH, SafeJsonFormatter


def _record(**overrides: object) -> logging.LogRecord:
    values: dict[str, object] = {
        "name": "control_api.services",
        "level": logging.WARNING,
        "pathname": __file__,
        "lineno": 1,
        "msg": "cache operation failed",
        "args": (),
        "exc_info": None,
    }
    values.update(overrides)
    return logging.LogRecord(**values)  # type: ignore[arg-type]


def _format(record: logging.LogRecord) -> tuple[str, dict[str, object]]:
    encoded = SafeJsonFormatter().format(record)
    return encoded, json.loads(encoded)


def test_formatter_emits_bounded_schema_and_allowlisted_scalars() -> None:
    record = _record(msg="x" * (MAX_MESSAGE_LENGTH + 20))
    record.event = "session.exchange_failed"
    record.request_id = "request-123"
    record.route = "/v1/devices/{device_id}"
    record.outcome = "denied"
    record.duration_ms = 12.5
    record.retryable = True
    record.retention_removed_total = 7

    _, payload = _format(record)

    assert payload["timestamp"].endswith("Z")
    assert payload["severity"] == "WARNING"
    assert payload["component"] == "control-api"
    assert payload["release"] == "0.1.1@unknown"
    assert payload["logger"] == "control_api.services"
    assert payload["event"] == "session.exchange_failed"
    assert len(payload["message"]) == MAX_MESSAGE_LENGTH
    assert payload["request_id"] == "request-123"
    assert payload["route"] == "/v1/devices/{device_id}"
    assert payload["outcome"] == "denied"
    assert payload["duration_ms"] == 12.5
    assert payload["retryable"] is True
    assert payload["retention_removed_total"] == 7


def test_formatter_drops_sensitive_extras_and_never_interpolates_arguments() -> None:
    secret = "provider-access-token-that-must-not-appear"
    record = _record(msg="provider call failed for %s", args=(secret,))
    record.access_token = secret
    record.request_body = {"prompt": secret}
    record.cookie = secret
    record.device_id = "raw-device-uuid"
    record.device_id_hash = "sha256:0123456789abcdef"

    encoded, payload = _format(record)

    assert secret not in encoded
    assert "access_token" not in payload
    assert "request_body" not in payload
    assert "cookie" not in payload
    assert "device_id" not in payload
    assert payload["device_id_hash"] == "sha256:0123456789abcdef"
    assert payload["message"] == "provider call failed for %s"


def test_formatter_redacts_credentials_and_query_strings_in_message() -> None:
    record = _record(
        msg=(
            "exchange failed authorization=Bearer abc123 "
            "poll_token=pairing-secret /v1/pairings?id=private"
        )
    )

    encoded, payload = _format(record)

    assert "abc123" not in encoded
    assert "pairing-secret" not in encoded
    assert "private" not in encoded
    assert payload["message"] == (
        "exchange failed authorization=[REDACTED] poll_token=[REDACTED] /v1/pairings?[REDACTED]"
    )


def test_formatter_summarizes_exception_without_payload_or_traceback() -> None:
    secret = "database-password-that-must-not-appear"
    try:
        raise RuntimeError(secret)
    except RuntimeError:
        record = _record(msg="database operation failed", exc_info=sys.exc_info())

    encoded, payload = _format(record)

    assert payload["exception"] is True
    assert payload["exception_type"] == "RuntimeError"
    assert secret not in encoded
    assert "Traceback" not in encoded


def test_uvicorn_access_projection_omits_client_and_request_target() -> None:
    secret = "poll-token-in-query"
    record = _record(
        name="uvicorn.access",
        level=logging.INFO,
        msg='%s - "%s %s HTTP/%s" %d',
        args=("203.0.113.7:49152", "GET", f"/v1/pairings?poll_token={secret}", "1.1", 204),
    )

    encoded, payload = _format(record)

    assert payload["event"] == "http.request"
    assert payload["message"] == "HTTP request completed"
    assert payload["method"] == "GET"
    assert payload["status_code"] == 204
    assert secret not in encoded
    assert "203.0.113.7" not in encoded
    assert "/v1/pairings" not in encoded


def test_dependency_message_does_not_expose_uncontrolled_payload() -> None:
    secret = "redis-url-with-password-that-must-not-appear"
    record = _record(name="third_party.client", msg=f"connection failed: {secret}")

    encoded, payload = _format(record)

    assert payload["event"] == "dependency.log"
    assert payload["message"] == "Dependency log event"
    assert secret not in encoded


def test_main_import_reconfigures_uvicorn_and_application_logs_as_json() -> None:
    script = """
import logging
import control_api.main

logging.getLogger("control_api.probe").warning(
    "probe failed for %s",
    "access-token-that-must-not-appear",
    extra={"event": "probe.failed", "reason": "dependency_unavailable"},
)
logging.getLogger("uvicorn.error").warning(
    "server probe failed for %s",
    "provider-key-that-must-not-appear",
)
logging.getLogger("uvicorn.access").info(
    '%s - "%s %s HTTP/%s" %d',
    "127.0.0.1:1234",
    "GET",
    "/v1/session?access_token=must-not-appear",
    "1.1",
    200,
)
"""
    environment = os.environ.copy()
    completed = subprocess.run(
        [sys.executable, "-c", script],
        check=True,
        capture_output=True,
        text=True,
        env=environment,
    )
    records = [json.loads(line) for line in completed.stdout.splitlines()]

    assert [record["event"] for record in records] == [
        "probe.failed",
        "server.log",
        "http.request",
    ]
    assert records[0]["reason"] == "dependency_unavailable"
    assert records[2]["status_code"] == 200
    assert "must-not-appear" not in completed.stdout
