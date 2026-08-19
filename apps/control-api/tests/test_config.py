from __future__ import annotations

import pytest
from pydantic import ValidationError

from control_api.config import Settings


@pytest.mark.parametrize(
    ("field", "insecure_value"),
    [
        ("session_hmac_secret", "development-only-change-this-session-secret"),
        ("session_hmac_secret", "replace-with-at-least-32-random-bytes"),
        ("session_hmac_secret", "  REPLACE-WITH-AT-LEAST-32-RANDOM-BYTES  "),
        ("session_hmac_secret", "a-test-secret-that-is-long-and-never-production"),
        ("session_hmac_secret", "device-send-barrier-secret-with-at-least-32-bytes"),
        ("session_hmac_secret", "production-secret-that-is-longer-than-32-bytes"),
        ("metrics_bearer_token", "development-only-change-this-metrics-token"),
        ("metrics_bearer_token", "replace-with-at-least-32-random-bytes"),
        ("metrics_bearer_token", "production-metrics-token-that-is-longer-than-32-bytes"),
    ],
)
def test_production_rejects_known_insecure_secret_values(
    field: str,
    insecure_value: str,
) -> None:
    values = {
        "environment": "production",
        "database_url": "postgresql+asyncpg://control:secret@postgres/control",
        "redis_url": "redis://redis:6379/0",
        "session_hmac_secret": "3f" * 32,
        "metrics_bearer_token": "4e" * 32,
        "cookie_secure": True,
        "allowed_origins_csv": "https://control.example.test",
        "sub2api_contract_marker": "0.1.178/e0c48a1",
    }
    values[field] = insecure_value

    with pytest.raises(ValidationError, match="known development, test, or example"):
        Settings(**values)


def test_production_requires_the_exact_frozen_sub2api_marker(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "control_api.connector_release.admitted_connector_release",
        lambda _settings: object(),
    )
    common = {
        "environment": "production",
        "database_url": "postgresql+asyncpg://control:secret@postgres/control",
        "redis_url": "redis://redis:6379/0",
        "session_hmac_secret": "3f" * 32,
        "metrics_bearer_token": "4e" * 32,
        "cookie_secure": True,
        "allowed_origins_csv": "https://control.example.test",
        "connector_release_metadata_json": "admitted-by-test-double",
    }
    with pytest.raises(ValidationError):
        Settings(**common, sub2api_contract_marker="0.1.178/wrong")

    settings = Settings(**common, sub2api_contract_marker="0.1.178/e0c48a1")
    assert settings.sub2api_contract_ready is True


@pytest.mark.parametrize(
    "sub2api_base_url",
    [
        "https://sub2api:8080",
        "http://attacker.example:8080",
        "http://user@sub2api:8080",
        "http://sub2api:8081",
        "http://sub2api:8080/api",
        "http://sub2api:8080?target=other",
        "http://sub2api:8080#fragment",
    ],
)
def test_production_requires_the_frozen_internal_sub2api_origin(
    sub2api_base_url: str,
) -> None:
    with pytest.raises(ValidationError, match="frozen internal Sub2API origin"):
        Settings(
            environment="production",
            database_url="postgresql+asyncpg://control:secret@postgres/control",
            redis_url="redis://redis:6379/0",
            session_hmac_secret="3f" * 32,
            metrics_bearer_token="4e" * 32,
            cookie_secure=True,
            allowed_origins_csv="https://control.example.test",
            sub2api_contract_marker="0.1.178/e0c48a1",
            sub2api_base_url=sub2api_base_url,
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("sub2api_expected_version", "0.1.154"),
        ("sub2api_expected_commit", "deadbeef"),
        ("connector_expected_version", "0.2.0"),
        ("codex_expected_version", "0.145.0"),
        ("appserver_schema_digest", "0" * 64),
    ],
)
def test_frozen_runtime_contract_cannot_be_redefined(field: str, value: str) -> None:
    with pytest.raises(ValidationError):
        Settings(**{field: value})


def test_device_envelope_budget_defaults_to_protocol_maximum_and_cannot_expand() -> None:
    assert Settings().device_max_envelope_bytes == 262_144
    with pytest.raises(ValidationError):
        Settings(device_max_envelope_bytes=262_145)


def test_realtime_resource_and_redis_timeout_defaults_are_bounded() -> None:
    settings = Settings()
    assert settings.database_pool_timeout_seconds == 3.0
    assert settings.database_connect_timeout_seconds == 5.0
    assert settings.database_command_timeout_seconds == 10.0
    assert settings.redis_connect_timeout_seconds == 3.0
    assert settings.redis_command_timeout_seconds == 3.0
    assert settings.session_upstream_recheck_seconds == 15
    assert settings.browser_event_catchup_max_bytes == 1024 * 1024
    assert settings.browser_max_connections_per_session == 4
    assert settings.browser_max_connections_per_user == 8
    assert settings.browser_connection_lease_ttl_seconds == 60


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("redis_connect_timeout_seconds", 31),
        ("redis_command_timeout_seconds", 31),
        ("session_upstream_recheck_seconds", 16),
        ("database_pool_timeout_seconds", 31),
        ("database_connect_timeout_seconds", 31),
        ("database_command_timeout_seconds", 61),
        ("browser_event_catchup_max_bytes", 16 * 1024 * 1024 + 1),
        ("browser_max_connections_per_session", 33),
        ("browser_max_connections_per_user", 129),
        ("browser_connection_lease_ttl_seconds", 301),
    ],
)
def test_realtime_resource_and_redis_timeout_caps_cannot_expand(field: str, value: int) -> None:
    with pytest.raises(ValidationError):
        Settings(**{field: value})


def test_browser_user_connection_cap_covers_session_cap() -> None:
    with pytest.raises(ValidationError, match="MAX_CONNECTIONS_PER_USER"):
        Settings(
            browser_max_connections_per_session=4,
            browser_max_connections_per_user=3,
        )


def test_production_rejects_lax_control_cookies() -> None:
    with pytest.raises(ValidationError, match="SameSite=Strict"):
        Settings(
            environment="production",
            database_url="postgresql+asyncpg://control:secret@postgres/control",
            redis_url="redis://redis:6379/0",
            session_hmac_secret="3f" * 32,
            metrics_bearer_token="4e" * 32,
            cookie_secure=True,
            cookie_samesite="lax",
            allowed_origins_csv="https://control.example.test",
            sub2api_contract_marker="0.1.178/e0c48a1",
        )


@pytest.mark.parametrize(
    "overrides",
    [
        {"owner_max_active_sessions": 101, "owner_max_session_records": 100},
        {"device_max_command_records": 1001, "owner_max_command_records": 1000},
        {"bootstrap_max_threads": 101, "owner_max_thread_records": 100},
        {"device_max_pending_approvals": 33, "device_max_approval_records": 32},
        {"bootstrap_max_pending_approvals": 101, "owner_max_approval_records": 100},
    ],
)
def test_retained_record_caps_cover_active_projection_caps(
    overrides: dict[str, int],
) -> None:
    with pytest.raises(ValidationError):
        Settings(**overrides)
