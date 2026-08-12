from __future__ import annotations

import asyncio
import time
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from .models import (
    Approval,
    ApprovalStatus,
    AuditEvent,
    AuditOutcome,
    Command,
    CommandStatus,
    ConnectionStatus,
    ControlSession,
    Device,
    DeviceConnection,
    DeviceOutbox,
    DevicePairing,
    DeviceStatus,
    EventLog,
    PairingStatus,
)
from .operational_metrics import OperationalMetrics

_AUDIT_ACTIONS = frozenset(
    {
        "approval.decide",
        "approval.default_deny",
        "approval.request",
        "command.create",
        "command.dispatch_reject",
        "command.epoch_terminal_refine",
        "command.expire",
        "device.connect",
        "device.connect_token.issue",
        "device.protocol_error",
        "device.revoke",
        "pairing.claim",
        "pairing.complete",
        "pairing.expire",
        "pairing.poll",
        "pairing.recover",
        "pairing.start",
        "session.exchange",
        "session.logout",
        "thread.archive",
        "thread.epoch_reconcile",
    }
)


class MetricsService:
    def __init__(
        self,
        cache_seconds: float,
        query_timeout_seconds: float,
        build_version: str,
        build_vcs_ref: str,
        operational: OperationalMetrics,
        database: Any,
    ) -> None:
        self._cache_seconds = cache_seconds
        self._query_timeout_seconds = query_timeout_seconds
        self._build_version = build_version
        self._build_vcs_ref = build_vcs_ref
        self._operational = operational
        self._database = database
        self._cached_body: str | None = None
        self._cached_until = 0.0
        self._lock = asyncio.Lock()

    async def render(self, db: AsyncSession) -> str:
        self._operational.database_pool(self._database.pool_snapshot())
        now = time.monotonic()
        if self._cached_body is not None and now < self._cached_until:
            return self._cached_body + self._operational.render()
        async with self._lock:
            now = time.monotonic()
            if self._cached_body is not None and now < self._cached_until:
                return self._cached_body + self._operational.render()
            try:
                async with asyncio.timeout(self._query_timeout_seconds):
                    body = await render_metrics(
                        db,
                        build_version=self._build_version,
                        build_vcs_ref=self._build_vcs_ref,
                    )
            except TimeoutError:
                if self._cached_body is not None:
                    return self._cached_body + self._operational.render()
                raise
            self._cached_body = body
            self._cached_until = time.monotonic() + self._cache_seconds
            return body + self._operational.render()


def _label(value: object) -> str:
    raw = getattr(value, "value", value)
    return str(raw).replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')


def _sample(name: str, value: int | float, **labels: object) -> str:
    label_text = ""
    if labels:
        rendered = ",".join(f'{key}="{_label(item)}"' for key, item in sorted(labels.items()))
        label_text = f"{{{rendered}}}"
    return f"{name}{label_text} {value}"


def _family(lines: list[str], name: str, help_text: str, metric_type: str) -> None:
    lines.extend((f"# HELP {name} {help_text}", f"# TYPE {name} {metric_type}"))


async def _grouped_counts(
    db: AsyncSession,
    model: Any,
    status_column: Any,
    id_column: Any,
) -> list[tuple[object, int]]:
    rows = (
        await db.execute(
            select(status_column, func.count(id_column)).select_from(model).group_by(status_column)
        )
    ).all()
    return [(status, int(count)) for status, count in rows]


def _complete_counts(
    counts: list[tuple[object, int]], statuses: type[Any]
) -> list[tuple[object, int]]:
    by_status = {getattr(status, "value", status): count for status, count in counts}
    return [(status, by_status.get(status.value, 0)) for status in statuses]


async def render_metrics(
    db: AsyncSession,
    now: datetime | None = None,
    *,
    build_version: str = "0.1.0",
    build_vcs_ref: str = "unknown",
) -> str:
    """Render low-cardinality, persistent control-plane state as Prometheus text."""

    now = now or datetime.now(UTC)
    active_sessions = int(
        await db.scalar(
            select(func.count(ControlSession.id)).where(
                ControlSession.revoked_at.is_(None),
                ControlSession.expires_at > now,
            )
        )
        or 0
    )
    pairing_counts = _complete_counts(
        await _grouped_counts(db, DevicePairing, DevicePairing.status, DevicePairing.id),
        PairingStatus,
    )
    device_counts = _complete_counts(
        await _grouped_counts(db, Device, Device.status, Device.id), DeviceStatus
    )
    connection_counts = _complete_counts(
        await _grouped_counts(db, DeviceConnection, DeviceConnection.status, DeviceConnection.id),
        ConnectionStatus,
    )
    command_counts = _complete_counts(
        await _grouped_counts(db, Command, Command.status, Command.id), CommandStatus
    )
    approval_counts = _complete_counts(
        await _grouped_counts(db, Approval, Approval.status, Approval.id), ApprovalStatus
    )

    outbox_count, outbox_bytes, oldest_outbox = (
        await db.execute(
            select(
                func.count(DeviceOutbox.sequence),
                func.coalesce(func.sum(DeviceOutbox.byte_size), 0),
                func.min(DeviceOutbox.created_at),
            ).where(DeviceOutbox.acked_at.is_(None))
        )
    ).one()
    oldest_heartbeat = await db.scalar(
        select(func.min(DeviceConnection.last_heartbeat_at)).where(
            DeviceConnection.status == ConnectionStatus.CONNECTED
        )
    )
    event_rows = int(await db.scalar(select(func.count(EventLog.id))) or 0)
    audit_rows = (
        await db.execute(
            select(AuditEvent.action, AuditEvent.outcome, func.count(AuditEvent.id)).group_by(
                AuditEvent.action,
                AuditEvent.outcome,
            )
        )
    ).all()
    normalized_audit_rows: dict[tuple[str, str], int] = {}
    audit_outcomes = {item.value for item in AuditOutcome}
    for action, outcome, count in audit_rows:
        raw_action = str(getattr(action, "value", action))
        raw_outcome = str(getattr(outcome, "value", outcome))
        labels = (
            raw_action if raw_action in _AUDIT_ACTIONS else "_other",
            raw_outcome if raw_outcome in audit_outcomes else "_other",
        )
        normalized_audit_rows[labels] = normalized_audit_rows.get(labels, 0) + int(count)

    outbox_age = 0.0
    if oldest_outbox is not None:
        if oldest_outbox.tzinfo is None:
            oldest_outbox = oldest_outbox.replace(tzinfo=UTC)
        outbox_age = max(0.0, (now - oldest_outbox.astimezone(UTC)).total_seconds())
    heartbeat_age = 0.0
    if oldest_heartbeat is not None:
        if oldest_heartbeat.tzinfo is None:
            oldest_heartbeat = oldest_heartbeat.replace(tzinfo=UTC)
        heartbeat_age = max(0.0, (now - oldest_heartbeat.astimezone(UTC)).total_seconds())

    lines: list[str] = []
    _family(lines, "codex_control_build_info", "Control API build information.", "gauge")
    lines.append(
        _sample(
            "codex_control_build_info",
            1,
            version=build_version,
            vcs_ref=build_vcs_ref,
        )
    )
    _family(
        lines,
        "codex_control_sessions_active",
        "Unexpired, non-revoked Control sessions.",
        "gauge",
    )
    lines.append(_sample("codex_control_sessions_active", active_sessions))

    for name, help_text, counts in (
        ("codex_control_device_pairings", "Device pairings by persistent status.", pairing_counts),
        ("codex_control_devices", "Devices by persistent status.", device_counts),
        (
            "codex_control_device_connections",
            "Device connection records by persistent status.",
            connection_counts,
        ),
        ("codex_control_commands", "Commands by persistent status.", command_counts),
        ("codex_control_approvals", "Approvals by persistent status.", approval_counts),
    ):
        _family(lines, name, help_text, "gauge")
        for status, count in counts:
            lines.append(_sample(name, count, status=status))

    _family(
        lines,
        "codex_control_device_outbox_frames",
        "Unacknowledged durable device outbox frames.",
        "gauge",
    )
    lines.append(_sample("codex_control_device_outbox_frames", int(outbox_count)))
    _family(
        lines,
        "codex_control_device_outbox_bytes",
        "Bytes held by unacknowledged durable device outbox frames.",
        "gauge",
    )
    lines.append(_sample("codex_control_device_outbox_bytes", int(outbox_bytes)))
    _family(
        lines,
        "codex_control_device_outbox_oldest_age_seconds",
        "Age of the oldest unacknowledged durable device outbox frame.",
        "gauge",
    )
    lines.append(_sample("codex_control_device_outbox_oldest_age_seconds", outbox_age))
    _family(
        lines,
        "codex_control_device_heartbeat_age_seconds_max",
        "Age of the oldest heartbeat among connected device records.",
        "gauge",
    )
    lines.append(_sample("codex_control_device_heartbeat_age_seconds_max", heartbeat_age))
    _family(
        lines,
        "codex_control_event_log_rows",
        "Durable browser event rows retained for reconnect catch-up.",
        "gauge",
    )
    lines.append(_sample("codex_control_event_log_rows", event_rows))
    _family(
        lines,
        "codex_control_audit_events_retained",
        "Audit events currently retained, grouped by bounded action and outcome.",
        "gauge",
    )
    for (action, outcome), count in sorted(normalized_audit_rows.items()):
        lines.append(
            _sample(
                "codex_control_audit_events_retained",
                int(count),
                action=action,
                outcome=outcome,
            )
        )
    _family(
        lines,
        "codex_control_metrics_generated_timestamp_seconds",
        "Unix timestamp when this database-backed snapshot was generated.",
        "gauge",
    )
    lines.append(_sample("codex_control_metrics_generated_timestamp_seconds", now.timestamp()))
    return "\n".join(lines) + "\n"
