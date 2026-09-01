from __future__ import annotations

import json
import logging
import logging.config
import math
import os
import re
from datetime import UTC, datetime
from typing import Any

COMPONENT = "control-api"
MAX_EVENT_LENGTH = 64
MAX_LOGGER_LENGTH = 128
MAX_MESSAGE_LENGTH = 256

_EVENT_PATTERN = re.compile(r"^[a-z][a-z0-9_.-]*$")
_SAFE_VALUE_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@/+\-]*$")
_SAFE_ROUTE_PATTERN = re.compile(r"^(?:_unmatched|/[A-Za-z0-9_./{}:\-]{0,255})$")
_CONTROL_CHARACTERS = re.compile(r"[\x00-\x1f\x7f]+")
_BEARER_VALUE = re.compile(r"(?i)\bbearer\s+[^\s,;]+")
_SECRET_ASSIGNMENT = re.compile(
    r"(?i)\b(authorization|cookie|set-cookie|csrf|access_token|refresh_token|"
    r"poll_token|device_token|provider_key|private_key|pairing_code|secret|credential|"
    r"signed_nonce)\b\s*[:=]\s*(?:bearer\s+)?(?:\"[^\"]*\"|'[^']*'|[^\s,;]+)"
)
_URL_QUERY = re.compile(r"(?P<path>(?:https?://[^\s?]+|/[^\s?]*))\?[^\s\"']+")

_SAFE_TEXT_FIELDS: dict[str, int] = {
    "release": 128,
    "request_id": 128,
    "command_id": 64,
    "approval_id": 64,
    "device_id_hash": 128,
    "app_server_epoch_hash": 128,
    "outcome": 64,
    "reason": 64,
    "error_type": 128,
    "method": 16,
}
_SAFE_INTEGER_FIELDS = frozenset(
    {
        "status_code",
        "close_code",
        "retention_removed_total",
        "row_count",
        "retry_count",
    }
)
_SAFE_NUMBER_FIELDS = frozenset({"duration_ms", "age_seconds", "spool_utilization_ratio"})
_SAFE_BOOLEAN_FIELDS = frozenset({"retryable", "success"})


def _bounded_text(value: str, limit: int) -> str:
    normalized = _CONTROL_CHARACTERS.sub(" ", value).strip()
    if len(normalized) <= limit:
        return normalized
    return normalized[: limit - 3] + "..."


def _safe_message(record: logging.LogRecord) -> str:
    if not record.name.startswith(("control_api", "uvicorn")):
        return "Dependency log event"
    # Log arguments can contain provider errors or request data. Keep only the
    # developer-authored template and project known credential shapes away.
    if not isinstance(record.msg, str):
        return "Log event"
    message = _CONTROL_CHARACTERS.sub(" ", record.msg)
    message = _URL_QUERY.sub(r"\g<path>?[REDACTED]", message)
    message = _SECRET_ASSIGNMENT.sub(lambda match: f"{match.group(1)}=[REDACTED]", message)
    message = _BEARER_VALUE.sub("Bearer [REDACTED]", message)
    return _bounded_text(message, MAX_MESSAGE_LENGTH) or "Log event"


def _safe_event(record: logging.LogRecord) -> str:
    value = getattr(record, "event", None)
    if (
        isinstance(value, str)
        and len(value) <= MAX_EVENT_LENGTH
        and _EVENT_PATTERN.fullmatch(value)
    ):
        return value
    if record.name == "uvicorn.access":
        return "http.request"
    if record.name.startswith("uvicorn"):
        return "server.log"
    if record.name.startswith("control_api"):
        return "application.log"
    return "dependency.log"


def _safe_identifier(value: Any, limit: int) -> str | None:
    if not isinstance(value, str) or len(value) > limit or not _SAFE_VALUE_PATTERN.fullmatch(value):
        return None
    return value


def _exception_type(record: logging.LogRecord) -> str | None:
    if not record.exc_info or not record.exc_info[0]:
        return None
    name = getattr(record.exc_info[0], "__name__", "Exception")
    return _safe_identifier(name, 128) or "Exception"


def _project_access_record(record: logging.LogRecord, payload: dict[str, Any]) -> None:
    payload["message"] = "HTTP request completed"
    if not isinstance(record.args, tuple) or len(record.args) < 5:
        return
    method = _safe_identifier(record.args[1], _SAFE_TEXT_FIELDS["method"])
    status_code = record.args[4]
    if method is not None:
        payload["method"] = method
    if isinstance(status_code, int) and not isinstance(status_code, bool):
        payload["status_code"] = status_code


class SafeJsonFormatter(logging.Formatter):
    """Serialize a deliberately small, credential-safe production log record."""

    def __init__(self, release: str | None = None) -> None:
        super().__init__()
        configured = release or (
            f"{os.environ.get('CONTROL_BUILD_VERSION', '0.1.8')}@"
            f"{os.environ.get('CONTROL_BUILD_VCS_REF', 'unknown')}"
        )
        self._release = _safe_identifier(configured, _SAFE_TEXT_FIELDS["release"]) or "unknown"

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(record.created, UTC)
            .isoformat(timespec="milliseconds")
            .replace("+00:00", "Z"),
            "severity": _bounded_text(record.levelname.upper(), 16),
            "component": COMPONENT,
            "release": self._release,
            "logger": _bounded_text(record.name, MAX_LOGGER_LENGTH),
            "event": _safe_event(record),
            "message": _safe_message(record),
        }

        if record.name == "uvicorn.access":
            _project_access_record(record, payload)

        for field, limit in _SAFE_TEXT_FIELDS.items():
            value = _safe_identifier(getattr(record, field, None), limit)
            if value is not None:
                payload[field] = value
        route = getattr(record, "route", None)
        if isinstance(route, str) and _SAFE_ROUTE_PATTERN.fullmatch(route):
            payload["route"] = route
        for field in _SAFE_INTEGER_FIELDS:
            value = getattr(record, field, None)
            if isinstance(value, int) and not isinstance(value, bool) and abs(value) <= 10**15:
                payload[field] = value
        for field in _SAFE_NUMBER_FIELDS:
            value = getattr(record, field, None)
            if (
                isinstance(value, (int, float))
                and not isinstance(value, bool)
                and math.isfinite(value)
                and abs(value) <= 10**15
            ):
                payload[field] = value
        for field in _SAFE_BOOLEAN_FIELDS:
            value = getattr(record, field, None)
            if isinstance(value, bool):
                payload[field] = value

        exception_type = _exception_type(record)
        if exception_type is not None:
            payload["exception"] = True
            payload["exception_type"] = exception_type

        return json.dumps(payload, ensure_ascii=True, separators=(",", ":"))


def _log_level(level: str | int | None) -> str | int:
    if level is not None:
        return level
    uvicorn_level = logging.getLogger("uvicorn.error").level
    return uvicorn_level if uvicorn_level != logging.NOTSET else logging.INFO


def build_json_logging_config(level: str | int | None = None) -> dict[str, Any]:
    configured_level = _log_level(level)
    return {
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": {"safe_json": {"()": SafeJsonFormatter}},
        "handlers": {
            "safe_json": {
                "class": "logging.StreamHandler",
                "formatter": "safe_json",
                "stream": "ext://sys.stdout",
            }
        },
        "root": {"handlers": ["safe_json"], "level": logging.WARNING},
        "loggers": {
            "control_api": {
                "handlers": ["safe_json"],
                "level": configured_level,
                "propagate": False,
            },
            "uvicorn": {
                "handlers": ["safe_json"],
                "level": configured_level,
                "propagate": False,
            },
            "uvicorn.error": {
                "handlers": [],
                "level": configured_level,
                "propagate": True,
            },
            "uvicorn.access": {
                "handlers": ["safe_json"],
                "level": configured_level,
                "propagate": False,
            },
        },
    }


def configure_json_logging(level: str | int | None = None) -> None:
    logging.config.dictConfig(build_json_logging_config(level))
