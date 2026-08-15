from __future__ import annotations

from datetime import UTC, datetime

import pytest
from conftest import ORIGIN, Harness, exchange
from sqlalchemy import func, select

from control_api.models import AuditEvent, ControlSession
from control_api.security import CONTROL_SESSION_DIGEST_PURPOSE, TokenDigester
from control_api.sub2api import (
    DisabledSub2APIUser,
    InvalidSub2APIToken,
    RevokedSub2APIToken,
    Sub2APIProtocolError,
    Sub2APIUnavailable,
    Sub2APIUser,
)


async def test_exchange_sets_secure_session_shape_and_persists_no_bearer(
    harness: Harness,
) -> None:
    raw_access_token = "sub2api-access-token-value"
    response = await exchange(harness, raw_access_token)

    assert response.status_code == 201
    assert response.json()["user"] == {
        "id": "42",
        "username": "alice",
        "email": "alice@example.test",
        "display_name": "Alice",
    }
    set_cookie_headers = response.headers.get_list("set-cookie")
    control_cookie = next(
        value for value in set_cookie_headers if harness.settings.cookie_name in value
    )
    csrf_cookie = next(
        value for value in set_cookie_headers if harness.settings.csrf_cookie_name in value
    )
    assert "HttpOnly" in control_cookie
    assert "SameSite=strict" in control_cookie
    assert raw_access_token not in control_cookie
    assert "HttpOnly" not in csrf_cookie
    assert response.headers["cache-control"] == "no-store"
    assert harness.sub2api.seen_tokens == [raw_access_token]

    async with harness.database.session_factory() as db:
        records = list((await db.scalars(select(ControlSession))).all())
    assert len(records) == 1
    record = records[0]
    persisted_values = "|".join(str(value) for value in record.__dict__.values())
    assert raw_access_token not in persisted_values
    assert record.token_hash != raw_access_token
    assert record.csrf_token_hash not in "\n".join(set_cookie_headers)
    column_names = {column.name for column in ControlSession.__table__.columns}
    assert "access_token" not in column_names
    assert "refresh_token" not in column_names
    marker = await harness.store.get(f"session-upstream-ok:{record.id}")
    assert marker is not None
    assert raw_access_token not in marker

    body = response.json()
    issued_at = datetime.fromisoformat(body["issued_at"])
    reauth_at = datetime.fromisoformat(body["reauth_at"])
    expires_at = datetime.fromisoformat(body["expires_at"])
    assert (reauth_at - issued_at).total_seconds() == harness.settings.recent_auth_max_age_seconds
    assert issued_at < reauth_at < expires_at


async def test_session_cache_cannot_substitute_another_users_record(harness: Harness) -> None:
    assert (await exchange(harness, "first-user-access-token")).status_code == 201
    first_raw_token = harness.client.cookies.get(harness.settings.cookie_name)
    async with harness.database.session_factory() as db:
        first = await db.scalar(
            select(ControlSession).where(ControlSession.sub2api_user_id == "42")
        )
    assert first is not None

    harness.sub2api.result = Sub2APIUser(user_id="84", username="mallory")
    assert (await exchange(harness, "second-user-access-token")).status_code == 201
    async with harness.database.session_factory() as db:
        second = await db.scalar(
            select(ControlSession).where(ControlSession.sub2api_user_id == "84")
        )
    assert second is not None

    cache_key = f"session:{first.token_hash}"
    await harness.store.set(cache_key, str(second.id), harness.settings.session_ttl_seconds)
    async with harness.database.session_factory() as db:
        resolved = await harness.app.state.session_service.resolve(db, first_raw_token, touch=False)
    assert resolved is not None
    assert resolved.id == first.id
    assert resolved.sub2api_user_id == "42"
    assert await harness.store.get(cache_key) == str(first.id)

    nonexistent_token = "nonexistent-control-session-token"
    digester = TokenDigester(harness.settings.session_hmac_secret.get_secret_value())
    nonexistent_hash = digester.digest(CONTROL_SESSION_DIGEST_PURPOSE, nonexistent_token)
    poisoned_key = f"session:{nonexistent_hash}"
    await harness.store.set(poisoned_key, str(second.id), harness.settings.session_ttl_seconds)
    async with harness.database.session_factory() as db:
        assert (
            await harness.app.state.session_service.resolve(db, nonexistent_token, touch=False)
            is None
        )
    assert await harness.store.get(poisoned_key) is None


async def test_current_session_digest_is_invisible_to_legacy_resolver(harness: Harness) -> None:
    assert (await exchange(harness, "generation-separated-access-token")).status_code == 201
    raw_cookie = harness.client.cookies.get(harness.settings.cookie_name)
    assert raw_cookie is not None
    async with harness.database.session_factory() as db:
        record = await db.scalar(select(ControlSession))
    assert record is not None

    digester = TokenDigester(harness.settings.session_hmac_secret.get_secret_value())
    assert record.token_hash == digester.digest(CONTROL_SESSION_DIGEST_PURPOSE, raw_cookie)
    assert record.token_hash != digester.digest("control-session", raw_cookie)


async def test_tampered_sealed_session_cookie_fails_before_upstream_recheck(
    harness: Harness,
) -> None:
    assert (await exchange(harness, "tamper-resistant-access-token")).status_code == 201
    raw_cookie = harness.client.cookies.get(harness.settings.cookie_name)
    assert raw_cookie is not None
    version, handle, payload = raw_cookie.split(".", 2)
    replacement = "A" if payload[10] != "A" else "B"
    tampered = f"{version}.{handle}.{payload[:10]}{replacement}{payload[11:]}"

    response = await harness.client.get(
        "/v1/session",
        headers={"Cookie": f"{harness.settings.cookie_name}={tampered}"},
    )

    assert response.status_code == 401
    assert harness.sub2api.seen_tokens == ["tamper-resistant-access-token"]


async def test_refresh_token_field_is_rejected_and_not_reflected(harness: Harness) -> None:
    refresh_token = "sub2api-refresh-token-must-never-enter-control-api"
    response = await harness.client.post(
        "/v1/session/exchange",
        headers={"Origin": ORIGIN},
        json={
            "access_token": "sub2api-access-token-value",
            "refresh_token": refresh_token,
        },
    )

    assert response.status_code == 422
    assert refresh_token not in response.text
    assert harness.sub2api.seen_tokens == []
    async with harness.database.session_factory() as db:
        records = list((await db.scalars(select(ControlSession))).all())
    assert records == []


async def test_exchange_accepts_pwa_bearer_header_without_request_body(
    harness: Harness,
) -> None:
    response = await harness.client.post(
        "/v1/session/exchange",
        headers={
            "Origin": ORIGIN,
            "Authorization": "Bearer pwa-sub2api-access-token",
        },
    )
    assert response.status_code == 201
    assert harness.sub2api.seen_tokens == ["pwa-sub2api-access-token"]


async def test_exchange_rejects_access_token_that_cannot_fit_a_secure_cookie(
    harness: Harness,
) -> None:
    access_token = "oversized-secret-" + "x" * 4000

    response = await exchange(harness, access_token)

    assert response.status_code == 422
    assert response.json() == {"detail": "sub2api_access_token_too_large"}
    assert access_token not in response.text
    assert harness.settings.cookie_name not in response.headers.get("set-cookie", "")
    async with harness.database.session_factory() as db:
        sessions = list((await db.scalars(select(ControlSession))).all())
        audits = list((await db.scalars(select(AuditEvent))).all())
    assert sessions == []
    assert len(audits) == 1
    assert audits[0].details == {"reason": "access_token_too_large"}


async def test_cached_read_rechecks_and_revokes_disabled_user_after_marker_miss(
    harness: Harness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    access_token = "disabled-after-exchange-access-token"
    assert (await exchange(harness, access_token)).status_code == 201
    harness.sub2api.result = DisabledSub2APIUser("disabled")

    assert (await harness.client.get("/v1/session")).status_code == 200
    assert harness.sub2api.seen_tokens == [access_token]

    original_get = harness.store.get

    async def miss_upstream_marker(key: str) -> str | None:
        if key.startswith("session-upstream-ok:"):
            return None
        return await original_get(key)

    monkeypatch.setattr(harness.store, "get", miss_upstream_marker)
    rejected = await harness.client.get("/v1/session")

    assert rejected.status_code == 401
    assert rejected.json() == {"detail": "control_session_required"}
    assert harness.sub2api.seen_tokens == [access_token, access_token]
    async with harness.database.session_factory() as db:
        record = await db.scalar(select(ControlSession))
        audit = await db.scalar(
            select(AuditEvent).where(AuditEvent.action == "session.upstream_revoke")
        )
    assert record is not None and record.revoked_at is not None
    assert audit is not None and audit.details == {"reason": "USER_INACTIVE"}


async def test_replayed_redis_marker_cannot_extend_upstream_recheck_window(
    harness: Harness,
) -> None:
    access_token = "marker-replay-access-token"
    assert (await exchange(harness, access_token)).status_code == 201
    async with harness.database.session_factory() as db:
        record = await db.scalar(select(ControlSession))
    assert record is not None
    stale_verified_at = (
        int(datetime.now(UTC).timestamp())
        - harness.settings.session_upstream_recheck_seconds
        - 1
    )
    signature = harness.app.state.session_service._upstream_marker_signature(
        record,
        stale_verified_at,
    )
    await harness.store.set(
        f"session-upstream-ok:{record.id}",
        f"v1.{stale_verified_at}.{signature}",
        ttl_seconds=harness.settings.session_ttl_seconds,
    )
    harness.sub2api.result = RevokedSub2APIToken("revoked")

    response = await harness.client.get("/v1/session")

    assert response.status_code == 401
    assert harness.sub2api.seen_tokens == [access_token, access_token]


async def test_mutation_forces_token_revocation_check_while_read_cache_is_fresh(
    harness: Harness,
) -> None:
    access_token = "revoked-after-exchange-access-token"
    assert (await exchange(harness, access_token)).status_code == 201
    harness.sub2api.result = RevokedSub2APIToken("revoked")
    csrf_token = harness.client.cookies.get(harness.settings.csrf_cookie_name)

    rejected = await harness.client.post(
        "/v1/pairings/claim",
        headers={"Origin": ORIGIN, harness.settings.csrf_header_name: csrf_token},
        json={"code": "2345-6789-ABCD-EFGH"},
    )

    assert rejected.status_code == 401
    assert rejected.json() == {"detail": "control_session_required"}
    assert harness.sub2api.seen_tokens == [access_token, access_token]
    async with harness.database.session_factory() as db:
        record = await db.scalar(select(ControlSession))
        audit = await db.scalar(
            select(AuditEvent).where(AuditEvent.action == "session.upstream_revoke")
        )
    assert record is not None and record.revoked_at is not None
    assert audit is not None and audit.details == {"reason": "TOKEN_REVOKED"}


@pytest.mark.parametrize(
    ("error", "expected_status", "expected_detail"),
    [
        (Sub2APIUnavailable("unavailable"), 503, "sub2api_auth_unavailable"),
        (Sub2APIProtocolError("invalid response"), 502, "sub2api_auth_contract_error"),
    ],
)
async def test_upstream_recheck_failure_is_retryable_and_does_not_revoke_session(
    harness: Harness,
    monkeypatch: pytest.MonkeyPatch,
    error: Exception,
    expected_status: int,
    expected_detail: str,
) -> None:
    access_token = "retryable-upstream-failure-token"
    assert (await exchange(harness, access_token)).status_code == 201
    harness.sub2api.result = error
    original_get = harness.store.get

    async def miss_upstream_marker(key: str) -> str | None:
        if key.startswith("session-upstream-ok:"):
            return None
        return await original_get(key)

    monkeypatch.setattr(harness.store, "get", miss_upstream_marker)
    response = await harness.client.get("/v1/session")

    assert response.status_code == expected_status
    assert response.json() == {"detail": expected_detail}
    async with harness.database.session_factory() as db:
        record = await db.scalar(select(ControlSession))
        upstream_audits = list(
            (
                await db.scalars(
                    select(AuditEvent).where(AuditEvent.action == "session.upstream_revoke")
                )
            ).all()
        )
    assert record is not None and record.revoked_at is None
    assert upstream_audits == []


@pytest.mark.parametrize(
    ("user", "reason"),
    [
        (Sub2APIUser(user_id="84", token_version="7"), "USER_MISMATCH"),
        (Sub2APIUser(user_id="42", token_version="8"), "TOKEN_VERSION_MISMATCH"),
    ],
)
async def test_recheck_revokes_identity_or_token_version_mismatch(
    harness: Harness,
    user: Sub2APIUser,
    reason: str,
) -> None:
    assert (await exchange(harness, "identity-drift-token")).status_code == 201
    harness.sub2api.result = user
    csrf_token = harness.client.cookies.get(harness.settings.csrf_cookie_name)

    response = await harness.client.post(
        "/v1/pairings/claim",
        headers={"Origin": ORIGIN, harness.settings.csrf_header_name: csrf_token},
        json={"code": "2345-6789-ABCD-EFGH"},
    )

    assert response.status_code == 401
    async with harness.database.session_factory() as db:
        audit = await db.scalar(
            select(AuditEvent).where(AuditEvent.action == "session.upstream_revoke")
        )
    assert audit is not None and audit.details == {"reason": reason}


async def test_exchange_forwards_browser_session_binding_identity(harness: Harness) -> None:
    harness.settings.trust_forwarded_for = True
    response = await harness.client.post(
        "/v1/session/exchange",
        headers={
            "Origin": ORIGIN,
            "User-Agent": "Bound Browser/7.0",
            "X-Forwarded-For": "203.0.113.55",
        },
        json={"access_token": "bound-access-token"},
    )

    assert response.status_code == 201
    assert len(harness.sub2api.seen_request_identities) == 1
    identity = harness.sub2api.seen_request_identities[0]
    assert identity.client_ip == "203.0.113.55"
    assert identity.user_agent == "Bound Browser/7.0"


async def test_exchange_ip_limit_precedes_verification_and_never_reflects_token(
    harness: Harness,
) -> None:
    harness.settings.session_exchange_limit = 1
    first_token = "first-sub2api-access-token"
    blocked_token = "blocked-sub2api-token-must-not-be-reflected"

    assert (await exchange(harness, first_token)).status_code == 201
    blocked = await exchange(harness, blocked_token)

    assert blocked.status_code == 429
    assert blocked.json() == {"detail": "session_exchange_rate_limited"}
    assert blocked.headers["retry-after"] == str(harness.settings.rate_limit_window_seconds)
    assert harness.sub2api.seen_tokens == [first_token]
    assert blocked_token not in blocked.text


async def test_exchange_enforces_active_session_cap(harness: Harness) -> None:
    harness.settings.owner_max_active_sessions = 1

    assert (await exchange(harness, "first-active-session")).status_code == 201
    blocked = await exchange(harness, "second-active-session")

    assert blocked.status_code == 429
    assert blocked.json() == {"detail": "control_session_capacity_exceeded"}
    async with harness.database.session_factory() as db:
        count = await db.scalar(select(func.count(ControlSession.id)))
    assert count == 1


async def test_exchange_prunes_terminal_sessions_at_retained_cap(harness: Harness) -> None:
    assert (await exchange(harness, "first-retained-session")).status_code == 201
    assert (await exchange(harness, "second-retained-session")).status_code == 201
    now = datetime.now(UTC)
    async with harness.database.session_factory() as db:
        records = list(
            (
                await db.scalars(
                    select(ControlSession).order_by(ControlSession.issued_at, ControlSession.id)
                )
            ).all()
        )
        for record in records:
            record.revoked_at = now
        await db.commit()
    harness.settings.owner_max_session_records = 2

    assert (await exchange(harness, "replacement-session")).status_code == 201

    async with harness.database.session_factory() as db:
        records = list((await db.scalars(select(ControlSession))).all())
    assert len(records) == 2
    assert sum(record.revoked_at is None for record in records) == 1


@pytest.mark.parametrize(
    ("error", "expected_status", "expected_detail"),
    [
        (InvalidSub2APIToken("invalid"), 401, "invalid_sub2api_access_token"),
        (DisabledSub2APIUser("disabled"), 403, "sub2api_user_disabled"),
    ],
)
async def test_invalid_or_disabled_sub2api_users_get_no_session(
    harness: Harness,
    error: Exception,
    expected_status: int,
    expected_detail: str,
) -> None:
    harness.sub2api.result = error
    response = await exchange(harness)

    assert response.status_code == expected_status
    assert response.json() == {"detail": expected_detail}
    assert harness.settings.cookie_name not in response.headers.get("set-cookie", "")
    async with harness.database.session_factory() as db:
        sessions = list((await db.scalars(select(ControlSession))).all())
        audits = list((await db.scalars(select(AuditEvent))).all())
    assert sessions == []
    assert len(audits) == 1
    assert audits[0].action == "session.exchange"


async def test_exchange_requires_an_explicit_allowed_origin(harness: Harness) -> None:
    missing = await harness.client.post(
        "/v1/session/exchange",
        json={"access_token": "sub2api-access-token-value"},
    )
    disallowed = await harness.client.post(
        "/v1/session/exchange",
        headers={"Origin": "https://attacker.example"},
        json={"access_token": "sub2api-access-token-value"},
    )

    assert missing.status_code == 403
    assert missing.json() == {"detail": "origin_required"}
    assert disallowed.status_code == 403
    assert disallowed.json() == {"detail": "origin_not_allowed"}
    assert harness.sub2api.seen_tokens == []


async def test_exchange_rejects_cross_site_fetch_metadata_with_an_allowed_origin(
    harness: Harness,
) -> None:
    response = await harness.client.post(
        "/v1/session/exchange",
        headers={"Origin": ORIGIN, "Sec-Fetch-Site": "cross-site"},
        json={"access_token": "sub2api-access-token-value"},
    )

    assert response.status_code == 403
    assert response.json() == {"detail": "fetch_metadata_not_allowed"}
    assert harness.sub2api.seen_tokens == []


async def test_logout_requires_csrf_and_revokes_the_session(harness: Harness) -> None:
    assert (await exchange(harness)).status_code == 201
    current = await harness.client.get("/v1/session")
    assert current.status_code == 200

    missing_csrf = await harness.client.post(
        "/v1/session/logout",
        headers={"Origin": ORIGIN},
    )
    assert missing_csrf.status_code == 403

    csrf_token = harness.client.cookies.get(harness.settings.csrf_cookie_name)
    logout = await harness.client.post(
        "/v1/session/logout",
        headers={
            "Origin": ORIGIN,
            harness.settings.csrf_header_name: csrf_token,
        },
    )
    assert logout.status_code == 204
    assert (await harness.client.get("/v1/session")).status_code == 401

    async with harness.database.session_factory() as db:
        record = await db.scalar(select(ControlSession))
    assert record is not None
    assert record.revoked_at is not None


async def test_logout_clears_cookies_when_redis_invalidation_fails(
    harness: Harness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert (await exchange(harness)).status_code == 201
    harness.sub2api.result = RevokedSub2APIToken("revoked before logout")

    async def unavailable(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError("simulated Redis outage")

    monkeypatch.setattr(harness.store, "get", unavailable)
    monkeypatch.setattr(harness.store, "set", unavailable)
    monkeypatch.setattr(harness.store, "publish", unavailable)
    monkeypatch.setattr(harness.store, "delete", unavailable)
    csrf_token = harness.client.cookies.get(harness.settings.csrf_cookie_name)

    logout = await harness.client.post(
        "/v1/session/logout",
        headers={
            "Origin": ORIGIN,
            harness.settings.csrf_header_name: csrf_token,
        },
    )

    assert logout.status_code == 204
    assert harness.client.cookies.get(harness.settings.cookie_name) is None
    assert harness.client.cookies.get(harness.settings.csrf_cookie_name) is None
    async with harness.database.session_factory() as db:
        record = await db.scalar(select(ControlSession))
    assert record is not None
    assert record.revoked_at is not None
    assert harness.sub2api.seen_tokens == ["sub2api-access-token-value"]
