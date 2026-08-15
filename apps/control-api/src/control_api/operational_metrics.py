from __future__ import annotations

import math
import threading
import time
from collections import defaultdict
from collections.abc import Iterable
from datetime import UTC, datetime

SESSION_EXCHANGE_OUTCOMES = frozenset(
    {
        "succeeded",
        "rate_limited",
        "conflicting_token",
        "missing_token",
        "invalid_token",
        "disabled_user",
        "upstream_unavailable",
        "upstream_protocol_error",
        "capacity_exceeded",
        "credential_too_large",
    }
)
PAIRING_OPERATIONS = frozenset({"start", "claim", "poll"})
PAIRING_OUTCOMES = frozenset(
    {
        "succeeded",
        "pending",
        "rate_limited",
        "unauthorized",
        "not_found",
        "expired",
        "conflict",
        "capacity_exceeded",
        "invalid_input",
    }
)
WEBSOCKET_KINDS = frozenset({"browser", "device"})
WEBSOCKET_EVENTS = frozenset({"accepted", "closed", "rejected", "replaced"})
WEBSOCKET_REASONS = frozenset(
    {
        "accepted",
        "peer_disconnect",
        "missing_auth",
        "invalid_auth",
        "origin_denied",
        "invalid_cursor",
        "capacity_exceeded",
        "dependency_unavailable",
        "protocol_error",
        "heartbeat_timeout",
        "connection_replaced",
        "stale_connection",
        "server_shutdown",
        "unknown",
    }
)
COMMAND_STATUSES = frozenset(
    {
        "none",
        "queued",
        "dispatched",
        "acknowledged",
        "succeeded",
        "failed",
        "denied",
        "cancelled",
        "expired",
    }
)
COMMAND_TERMINAL_STATUSES = frozenset({"succeeded", "failed", "denied", "cancelled", "expired"})
COMMAND_IDEMPOTENCY_OUTCOMES = frozenset({"replayed", "conflict"})
APPROVAL_OUTCOMES = frozenset({"requested", "approved", "denied"})
APPROVAL_REASONS = frozenset(
    {
        "device_request",
        "user_approved",
        "user_denied",
        "device_offline_default_deny",
        "disconnect_default_deny",
        "device_revoked_default_deny",
        "stale_epoch_default_deny",
        "timeout_default_deny",
        "expired_on_arrival_default_deny",
        "approval_limit_default_deny",
        "owner_approval_limit_default_deny",
        "approval_size_default_deny",
        "not_found_or_not_owned",
        "decision_conflict",
    }
)
RPC_POLICY_CLASSES = frozenset({"allowlisted", "prohibited"})
RPC_POLICY_OUTCOMES = frozenset({"accepted", "denied"})
RECONCILIATION_PHASES = frozenset(
    {"command_stale_epoch", "thread_stale_epoch", "approval_stale_epoch"}
)
MAINTENANCE_PHASES = frozenset(
    {
        "pairing_expiry",
        "command_expiry",
        "approval_expiry",
        "approval_reconcile",
        "event_prune",
        "outbox_prune",
        "retention_sweep",
        "retention_control_sessions",
        "retention_device_pairings",
        "retention_approvals",
        "retention_commands",
        "retention_device_connections",
        "retention_thread_bindings",
        "retention_devices",
        "retention_audit_events",
    }
)
RUN_OUTCOMES = frozenset({"succeeded", "failed"})
DEPENDENCIES = frozenset({"database", "database_migrations", "redis"})
DEPENDENCY_OUTCOMES = frozenset({"ok", "failed"})
HTTP_METHODS = frozenset({"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"})
HTTP_STATUS_CLASSES = frozenset({"1xx", "2xx", "3xx", "4xx", "5xx"})

_HTTP_BUCKETS = (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0)
_COMMAND_BUCKETS = (0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0, 120.0)
_MAINTENANCE_BUCKETS = (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0)
_DEPENDENCY_BUCKETS = (0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0)


def _label(value: object) -> str:
    return str(value).replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')


def _sample(name: str, value: int | float, labels: tuple[tuple[str, str], ...]) -> str:
    label_text = ""
    if labels:
        rendered = ",".join(f'{key}="{_label(item)}"' for key, item in labels)
        label_text = f"{{{rendered}}}"
    return f"{name}{label_text} {value}"


def _family(lines: list[str], name: str, help_text: str, metric_type: str) -> None:
    lines.extend((f"# HELP {name} {help_text}", f"# TYPE {name} {metric_type}"))


def _bounded(value: str, allowed: frozenset[str], field: str) -> str:
    if value not in allowed:
        raise ValueError(f"unsupported {field}: {value}")
    return value


class OperationalMetrics:
    """Process-local metrics with fixed labels and no user-controlled identifiers."""

    def __init__(self, http_routes: Iterable[str] = ()) -> None:
        self._http_routes = frozenset(http_routes) | {"_unmatched"}
        self._lock = threading.Lock()
        self._counters: dict[tuple[str, tuple[tuple[str, str], ...]], float] = defaultdict(float)
        self._gauges: dict[tuple[str, tuple[tuple[str, str], ...]], float] = defaultdict(float)
        self._histograms: dict[
            tuple[str, tuple[tuple[str, str], ...]], tuple[list[int], float, int]
        ] = {}

        for kind in sorted(WEBSOCKET_KINDS):
            self._set_gauge("codex_control_websocket_connections_active", 0, kind=kind)
        for dependency in sorted(DEPENDENCIES):
            self._set_gauge("codex_control_dependency_ready", 0, dependency=dependency)
        for phase in sorted(MAINTENANCE_PHASES):
            self._set_gauge("codex_control_maintenance_batch_saturated", 0, phase=phase)
            self._set_gauge(
                "codex_control_maintenance_last_success_timestamp_seconds", 0, phase=phase
            )

    def session_exchange(self, outcome: str) -> None:
        self._increment(
            "codex_control_session_exchange_total",
            outcome=_bounded(outcome, SESSION_EXCHANGE_OUTCOMES, "session outcome"),
        )

    def pairing(self, operation: str, outcome: str) -> None:
        self._increment(
            "codex_control_pairing_operations_total",
            operation=_bounded(operation, PAIRING_OPERATIONS, "pairing operation"),
            outcome=_bounded(outcome, PAIRING_OUTCOMES, "pairing outcome"),
        )

    def websocket_rejected(self, kind: str, reason: str) -> None:
        self._websocket_event(kind, "rejected", reason)

    def websocket_opened(self, kind: str) -> None:
        kind = _bounded(kind, WEBSOCKET_KINDS, "websocket kind")
        self._websocket_event(kind, "accepted", "accepted")
        self._add_gauge("codex_control_websocket_connections_active", 1, kind=kind)

    def websocket_closed(self, kind: str, reason: str) -> None:
        kind = _bounded(kind, WEBSOCKET_KINDS, "websocket kind")
        self._websocket_event(kind, "closed", reason)
        self._add_gauge("codex_control_websocket_connections_active", -1, floor=0, kind=kind)

    def websocket_replaced(self, kind: str) -> None:
        self._websocket_event(kind, "replaced", "connection_replaced")

    def _websocket_event(self, kind: str, event: str, reason: str) -> None:
        self._increment(
            "codex_control_websocket_events_total",
            kind=_bounded(kind, WEBSOCKET_KINDS, "websocket kind"),
            event=_bounded(event, WEBSOCKET_EVENTS, "websocket event"),
            reason=_bounded(reason, WEBSOCKET_REASONS, "websocket reason"),
        )

    def command_transition(
        self,
        from_status: str,
        to_status: str,
        *,
        duration_seconds: float | None = None,
    ) -> None:
        from_status = _bounded(from_status, COMMAND_STATUSES, "command source status")
        to_status = _bounded(to_status, COMMAND_STATUSES, "command target status")
        self._increment(
            "codex_control_command_transitions_total",
            from_status=from_status,
            to_status=to_status,
        )
        if duration_seconds is not None and to_status in COMMAND_TERMINAL_STATUSES:
            self._observe_histogram(
                "codex_control_command_duration_seconds",
                max(0.0, duration_seconds),
                _COMMAND_BUCKETS,
                outcome=to_status,
            )

    def command_idempotency(self, outcome: str) -> None:
        self._increment(
            "codex_control_command_idempotency_total",
            outcome=_bounded(outcome, COMMAND_IDEMPOTENCY_OUTCOMES, "idempotency outcome"),
        )

    def approval_outcome(self, outcome: str, reason: str) -> None:
        self._increment(
            "codex_control_approval_outcomes_total",
            outcome=_bounded(outcome, APPROVAL_OUTCOMES, "approval outcome"),
            reason=_bounded(reason, APPROVAL_REASONS, "approval reason"),
        )

    def rpc_policy(self, method_class: str, outcome: str) -> None:
        self._increment(
            "codex_control_rpc_policy_total",
            method_class=_bounded(method_class, RPC_POLICY_CLASSES, "RPC method class"),
            outcome=_bounded(outcome, RPC_POLICY_OUTCOMES, "RPC policy outcome"),
        )

    def reconciliation(self, phase: str, outcome: str, items: int, duration: float) -> None:
        phase = _bounded(phase, RECONCILIATION_PHASES, "reconciliation phase")
        outcome = _bounded(outcome, RUN_OUTCOMES, "reconciliation outcome")
        self._increment("codex_control_reconciliation_runs_total", phase=phase, outcome=outcome)
        if items:
            self._increment(
                "codex_control_reconciliation_items_total",
                amount=items,
                phase=phase,
                outcome=outcome,
            )
        self._observe_histogram(
            "codex_control_reconciliation_duration_seconds",
            max(0.0, duration),
            _MAINTENANCE_BUCKETS,
            phase=phase,
        )

    def maintenance(
        self, phase: str, outcome: str, items: int, duration: float, limit: int
    ) -> None:
        phase = _bounded(phase, MAINTENANCE_PHASES, "maintenance phase")
        outcome = _bounded(outcome, RUN_OUTCOMES, "maintenance outcome")
        self._increment("codex_control_maintenance_runs_total", phase=phase, outcome=outcome)
        if items:
            self._increment("codex_control_maintenance_items_total", amount=items, phase=phase)
        self._observe_histogram(
            "codex_control_maintenance_duration_seconds",
            max(0.0, duration),
            _MAINTENANCE_BUCKETS,
            phase=phase,
        )
        self._set_gauge(
            "codex_control_maintenance_batch_saturated",
            int(outcome == "succeeded" and limit > 0 and items >= limit),
            phase=phase,
        )
        if outcome == "succeeded":
            self._set_gauge(
                "codex_control_maintenance_last_success_timestamp_seconds",
                datetime.now(UTC).timestamp(),
                phase=phase,
            )

    def dependency_check(self, dependency: str, outcome: str, duration: float) -> None:
        dependency = _bounded(dependency, DEPENDENCIES, "dependency")
        outcome = _bounded(outcome, DEPENDENCY_OUTCOMES, "dependency outcome")
        self._increment(
            "codex_control_dependency_checks_total",
            dependency=dependency,
            outcome=outcome,
        )
        self._set_gauge(
            "codex_control_dependency_ready", int(outcome == "ok"), dependency=dependency
        )
        self._observe_histogram(
            "codex_control_dependency_check_duration_seconds",
            max(0.0, duration),
            _DEPENDENCY_BUCKETS,
            dependency=dependency,
        )

    def http_request(
        self,
        method: str,
        route: str,
        status_code: int,
        duration: float,
    ) -> None:
        method = method if method in HTTP_METHODS else "OTHER"
        route = route if route in self._http_routes else "_unmatched"
        status_class = f"{max(1, min(5, status_code // 100))}xx"
        status_class = _bounded(status_class, HTTP_STATUS_CLASSES, "HTTP status class")
        self._increment(
            "codex_control_http_requests_total",
            method=method,
            route=route,
            status_class=status_class,
        )
        self._observe_histogram(
            "codex_control_http_request_duration_seconds",
            max(0.0, duration),
            _HTTP_BUCKETS,
            method=method,
            route=route,
        )

    def database_pool(self, values: dict[str, int | float]) -> None:
        for state in ("size", "checked_in", "checked_out", "overflow", "capacity"):
            self._set_gauge(
                "codex_control_database_pool_connections", values.get(state, 0), state=state
            )

    def _increment(self, name: str, amount: int | float = 1, **labels: str) -> None:
        if amount < 0 or not math.isfinite(float(amount)):
            raise ValueError("counter increments must be finite and non-negative")
        key = (name, tuple(sorted(labels.items())))
        with self._lock:
            self._counters[key] += float(amount)

    def _set_gauge(self, name: str, value: int | float, **labels: str) -> None:
        if not math.isfinite(float(value)):
            raise ValueError("gauge values must be finite")
        key = (name, tuple(sorted(labels.items())))
        with self._lock:
            self._gauges[key] = float(value)

    def _add_gauge(
        self,
        name: str,
        amount: int | float,
        *,
        floor: float | None = None,
        **labels: str,
    ) -> None:
        key = (name, tuple(sorted(labels.items())))
        with self._lock:
            value = self._gauges[key] + float(amount)
            self._gauges[key] = float(max(floor, value)) if floor is not None else value

    def _observe_histogram(
        self,
        name: str,
        value: float,
        buckets: tuple[float, ...],
        **labels: str,
    ) -> None:
        if value < 0 or not math.isfinite(value):
            raise ValueError("histogram observations must be finite and non-negative")
        key = (name, tuple(sorted(labels.items())))
        with self._lock:
            counts, total, count = self._histograms.get(key, ([0 for _ in buckets], 0.0, 0))
            for index, upper_bound in enumerate(buckets):
                if value <= upper_bound:
                    counts[index] += 1
            self._histograms[key] = (counts, total + value, count + 1)

    def render(self) -> str:
        with self._lock:
            counters = dict(self._counters)
            gauges = dict(self._gauges)
            histograms = {
                key: (list(counts), total, count)
                for key, (counts, total, count) in self._histograms.items()
            }

        lines: list[str] = []
        counter_families = {
            "codex_control_session_exchange_total": "Control session exchanges by bounded outcome.",
            "codex_control_pairing_operations_total": (
                "Pairing operations by bounded operation and outcome."
            ),
            "codex_control_websocket_events_total": (
                "WebSocket lifecycle events by endpoint kind and bounded reason."
            ),
            "codex_control_command_transitions_total": "Durable command state transitions.",
            "codex_control_command_idempotency_total": "Command idempotency replays and conflicts.",
            "codex_control_approval_outcomes_total": (
                "Approval requests and terminal outcomes by bounded reason."
            ),
            "codex_control_rpc_policy_total": "RPC allowlist decisions by bounded method class.",
            "codex_control_reconciliation_runs_total": "Reconciliation runs by phase and outcome.",
            "codex_control_reconciliation_items_total": "Items affected by reconciliation runs.",
            "codex_control_maintenance_runs_total": "Maintenance phase runs by outcome.",
            "codex_control_maintenance_items_total": "Rows affected by maintenance phases.",
            "codex_control_dependency_checks_total": "Readiness dependency checks by outcome.",
            "codex_control_http_requests_total": (
                "HTTP requests by method, route template, and status class."
            ),
        }
        for name, help_text in counter_families.items():
            _family(lines, name, help_text, "counter")
            for (metric, labels), value in sorted(counters.items()):
                if metric == name:
                    lines.append(_sample(name, value, labels))

        gauge_families = {
            "codex_control_websocket_connections_active": (
                "Accepted WebSocket connections currently active."
            ),
            "codex_control_maintenance_batch_saturated": (
                "Whether the latest successful maintenance phase reached its batch limit."
            ),
            "codex_control_maintenance_last_success_timestamp_seconds": (
                "Unix timestamp of the latest successful maintenance phase."
            ),
            "codex_control_dependency_ready": "Latest readiness state for a bounded dependency.",
            "codex_control_database_pool_connections": (
                "Database pool state for this Control API process."
            ),
        }
        for name, help_text in gauge_families.items():
            _family(lines, name, help_text, "gauge")
            for (metric, labels), value in sorted(gauges.items()):
                if metric == name:
                    lines.append(_sample(name, value, labels))

        histogram_families = {
            "codex_control_http_request_duration_seconds": (
                "HTTP request duration by method and route template.",
                _HTTP_BUCKETS,
            ),
            "codex_control_command_duration_seconds": (
                "Command duration from durable creation to terminal state.",
                _COMMAND_BUCKETS,
            ),
            "codex_control_reconciliation_duration_seconds": (
                "Reconciliation phase duration.",
                _MAINTENANCE_BUCKETS,
            ),
            "codex_control_maintenance_duration_seconds": (
                "Maintenance phase duration.",
                _MAINTENANCE_BUCKETS,
            ),
            "codex_control_dependency_check_duration_seconds": (
                "Readiness dependency check duration.",
                _DEPENDENCY_BUCKETS,
            ),
        }
        for name, (help_text, buckets) in histogram_families.items():
            _family(lines, name, help_text, "histogram")
            for (metric, labels), (counts, total, count) in sorted(histograms.items()):
                if metric != name:
                    continue
                for upper_bound, bucket_count in zip(buckets, counts, strict=True):
                    le = str(upper_bound)
                    lines.append(_sample(f"{name}_bucket", bucket_count, labels + (("le", le),)))
                lines.append(_sample(f"{name}_bucket", count, labels + (("le", "+Inf"),)))
                lines.append(_sample(f"{name}_sum", total, labels))
                lines.append(_sample(f"{name}_count", count, labels))
        return "\n".join(lines) + "\n"


def elapsed_seconds(started: float) -> float:
    return max(0.0, time.monotonic() - started)
