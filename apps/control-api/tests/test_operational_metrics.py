from __future__ import annotations

import pytest

from control_api.operational_metrics import OperationalMetrics


def test_operational_metrics_render_only_bounded_labels() -> None:
    metrics = OperationalMetrics({"/v1/devices/{device_id}"})

    metrics.session_exchange("invalid_token")
    metrics.pairing("claim", "capacity_exceeded")
    metrics.websocket_opened("browser")
    metrics.websocket_replaced("device")
    metrics.websocket_closed("browser", "peer_disconnect")
    metrics.command_transition("queued", "dispatched")
    metrics.command_transition("dispatched", "succeeded", duration_seconds=0.75)
    metrics.command_idempotency("replayed")
    metrics.approval_outcome("denied", "stale_epoch_default_deny")
    metrics.rpc_policy("prohibited", "denied")
    metrics.reconciliation("command_stale_epoch", "succeeded", 2, 0.1)
    metrics.maintenance("command_expiry", "succeeded", 500, 0.2, 500)
    metrics.dependency_check("redis", "ok", 0.01)
    metrics.http_request("GET", "/v1/devices/{device_id}", 200, 0.02)
    metrics.http_request("GET", "/v1/devices/sensitive-device-id", 404, 0.01)
    metrics.database_pool(
        {"size": 10, "checked_in": 8, "checked_out": 2, "overflow": 0, "capacity": 30}
    )

    body = metrics.render()

    assert 'codex_control_session_exchange_total{outcome="invalid_token"} 1.0' in body
    assert (
        'codex_control_pairing_operations_total{operation="claim",outcome="capacity_exceeded"} 1.0'
    ) in body
    assert 'codex_control_websocket_connections_active{kind="browser"} 0.0' in body
    assert (
        'codex_control_command_transitions_total{from_status="dispatched",to_status="succeeded"}'
        " 1.0"
    ) in body
    assert 'codex_control_command_duration_seconds_count{outcome="succeeded"} 1' in body
    assert (
        'codex_control_approval_outcomes_total{outcome="denied",reason="stale_epoch_default_deny"}'
        " 1.0"
    ) in body
    assert 'codex_control_rpc_policy_total{method_class="prohibited",outcome="denied"} 1.0' in body
    assert 'codex_control_maintenance_batch_saturated{phase="command_expiry"} 1.0' in body
    assert 'codex_control_dependency_ready{dependency="redis"} 1.0' in body
    assert 'route="/v1/devices/{device_id}"' in body
    assert 'route="_unmatched"' in body
    assert "sensitive-device-id" not in body


def test_websocket_active_gauge_cannot_become_negative() -> None:
    metrics = OperationalMetrics()

    metrics.websocket_closed("device", "peer_disconnect")

    assert 'codex_control_websocket_connections_active{kind="device"} 0.0' in metrics.render()


@pytest.mark.parametrize(
    ("method", "arguments"),
    [
        ("session_exchange", ("attacker-controlled",)),
        ("pairing", ("claim", "attacker-controlled")),
        ("websocket_rejected", ("browser", "attacker-controlled")),
        ("command_transition", ("queued", "attacker-controlled")),
        ("approval_outcome", ("denied", "attacker-controlled")),
        ("rpc_policy", ("attacker-controlled", "denied")),
        ("dependency_check", ("attacker-controlled", "ok", 0.1)),
    ],
)
def test_operational_metrics_reject_unbounded_labels(
    method: str, arguments: tuple[object, ...]
) -> None:
    metrics = OperationalMetrics()

    with pytest.raises(ValueError, match="unsupported"):
        getattr(metrics, method)(*arguments)
