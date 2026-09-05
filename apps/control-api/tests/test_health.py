from __future__ import annotations

from conftest import Harness, exchange


async def test_liveness_and_readiness(harness: Harness) -> None:
    live = await harness.client.get("/v1/health/live")
    ready = await harness.client.get("/v1/health/ready")

    assert live.status_code == 200
    assert live.json() == {"status": "ok"}
    assert ready.status_code == 200
    assert ready.json() == {
        "status": "ready",
        "checks": {
            "database": "ok",
            "database_migrations": "ok",
            "redis": "ok",
            "sub2api_contract": "ok",
            "connector_release": "ok",
        },
    }


async def test_internal_metrics_are_persistent_and_low_cardinality(harness: Harness) -> None:
    assert (await exchange(harness)).status_code == 201

    unauthenticated = await harness.client.get("/internal/metrics")
    response = await harness.client.get(
        "/internal/metrics",
        headers={
            "Authorization": (f"Bearer {harness.settings.metrics_bearer_token.get_secret_value()}")
        },
    )

    assert unauthenticated.status_code == 401
    assert unauthenticated.headers["www-authenticate"] == "Bearer"
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["content-type"].startswith("text/plain; version=0.0.4")
    assert 'codex_control_build_info{vcs_ref="unknown",version="0.1.11"} 1' in response.text
    assert "codex_control_sessions_active 1" in response.text
    assert (
        'codex_control_audit_events_retained{action="session.exchange",outcome="succeeded"} 1'
        in response.text
    )
    assert 'codex_control_session_exchange_total{outcome="succeeded"} 1.0' in response.text
    assert 'codex_control_database_pool_connections{state="capacity"}' in response.text
    assert "alice@example.test" not in response.text
    assert "sub2api-access-token-value" not in response.text


async def test_internal_metrics_timeout_fails_closed(harness: Harness) -> None:
    class TimeoutMetrics:
        async def render(self, _db: object) -> str:
            raise TimeoutError

    original = harness.app.state.metrics
    harness.app.state.metrics = TimeoutMetrics()
    try:
        response = await harness.client.get(
            "/internal/metrics",
            headers={
                "Authorization": (
                    f"Bearer {harness.settings.metrics_bearer_token.get_secret_value()}"
                )
            },
        )
    finally:
        harness.app.state.metrics = original

    assert response.status_code == 503
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["retry-after"] == "15"
