from __future__ import annotations

import asyncio

import httpx
import pytest

from control_api.config import Settings
from control_api.sub2api import (
    DisabledSub2APIUser,
    HTTPSub2APIClient,
    InvalidSub2APIToken,
    RevokedSub2APIToken,
    Sub2APIProtocolError,
    Sub2APIRequestIdentity,
    Sub2APIUnavailable,
    parse_auth_me,
)


async def test_auth_me_uses_bearer_access_token() -> None:
    seen_authorization: list[str] = []
    seen_binding_headers: list[tuple[str, str]] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        seen_authorization.append(request.headers["Authorization"])
        seen_binding_headers.append(
            (request.headers["X-Forwarded-For"], request.headers["User-Agent"])
        )
        assert request.url.path == "/api/v1/auth/me"
        return httpx.Response(
            200,
            json={
                "code": 0,
                "message": "success",
                "data": {
                    "id": 42,
                    "username": "alice",
                    "status": "active",
                },
            },
        )

    settings = Settings(environment="test", sub2api_base_url="http://sub2api:8080")
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(handler),
        base_url=settings.sub2api_base_url,
    ) as http_client:
        client = HTTPSub2APIClient(settings, client=http_client)
        user = await client.verify_access_token(
            "only-this-access-token",
            Sub2APIRequestIdentity(
                client_ip="203.0.113.42",
                user_agent="Control Browser/1.0",
            ),
        )

    assert seen_authorization == ["Bearer only-this-access-token"]
    assert seen_binding_headers == [("203.0.113.42", "Control Browser/1.0")]
    assert user.user_id == "42"
    assert user.token_version is None


async def test_auth_me_enforces_shared_wall_clock_timeout_for_injected_client() -> None:
    request_started = asyncio.Event()
    request_cancelled = asyncio.Event()
    release_request = asyncio.Event()

    async def handler(_request: httpx.Request) -> httpx.Response:
        request_started.set()
        try:
            await release_request.wait()
        except asyncio.CancelledError:
            request_cancelled.set()
            raise
        return httpx.Response(500)

    settings = Settings(
        environment="test",
        sub2api_base_url="http://sub2api:8080",
        sub2api_timeout_seconds=0.01,
    )
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(handler),
        base_url=settings.sub2api_base_url,
        timeout=None,
    ) as http_client:
        client = HTTPSub2APIClient(settings, client=http_client)
        with pytest.raises(Sub2APIUnavailable, match="timed out"):
            await client.verify_access_token(
                "still-locally-valid-access-token",
                Sub2APIRequestIdentity(client_ip="203.0.113.42", user_agent="browser"),
            )

    assert request_started.is_set()
    assert request_cancelled.is_set()


async def test_auth_me_rejects_unauthorized_response() -> None:
    async def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"message": "unauthorized"})

    settings = Settings(environment="test", sub2api_base_url="http://sub2api:8080")
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(handler),
        base_url=settings.sub2api_base_url,
    ) as http_client:
        client = HTTPSub2APIClient(settings, client=http_client)
        with pytest.raises(InvalidSub2APIToken):
            await client.verify_access_token(
                "invalid-access-token",
                Sub2APIRequestIdentity(client_ip="203.0.113.42", user_agent="browser"),
            )


async def test_auth_me_classifies_user_inactive_401_as_disabled() -> None:
    async def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            401,
            json={"code": "USER_INACTIVE", "message": "User account is inactive"},
        )

    settings = Settings(environment="test", sub2api_base_url="http://sub2api:8080")
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(handler),
        base_url=settings.sub2api_base_url,
    ) as http_client:
        client = HTTPSub2APIClient(settings, client=http_client)
        with pytest.raises(DisabledSub2APIUser):
            await client.verify_access_token(
                "inactive-user-access-token",
                Sub2APIRequestIdentity(client_ip="203.0.113.42", user_agent="browser"),
            )


async def test_auth_me_classifies_token_revoked_401() -> None:
    async def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            401,
            json={"code": "TOKEN_REVOKED", "message": "Token was revoked"},
        )

    settings = Settings(environment="test", sub2api_base_url="http://sub2api:8080")
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(handler),
        base_url=settings.sub2api_base_url,
    ) as http_client:
        client = HTTPSub2APIClient(settings, client=http_client)
        with pytest.raises(RevokedSub2APIToken):
            await client.verify_access_token(
                "revoked-access-token",
                Sub2APIRequestIdentity(client_ip="203.0.113.42", user_agent="browser"),
            )


@pytest.mark.parametrize(
    "payload",
    [
        {"success": False, "code": "INTERNAL_ERROR"},
        {"code": "TOKEN_REVOKED", "message": "unexpected 2xx envelope"},
    ],
)
async def test_auth_me_treats_2xx_error_envelopes_as_protocol_failures(
    payload: dict[str, object],
) -> None:
    async def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=payload)

    settings = Settings(environment="test", sub2api_base_url="http://sub2api:8080")
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(handler),
        base_url=settings.sub2api_base_url,
    ) as http_client:
        client = HTTPSub2APIClient(settings, client=http_client)
        with pytest.raises(Sub2APIProtocolError):
            await client.verify_access_token(
                "still-locally-valid-access-token",
                Sub2APIRequestIdentity(client_ip="203.0.113.42", user_agent="browser"),
            )


@pytest.mark.parametrize("status_code", [201, 202, 204, 206])
async def test_auth_me_requires_the_frozen_http_200_status(status_code: int) -> None:
    async def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            status_code,
            json={
                "code": 0,
                "message": "success",
                "data": {"id": 42, "status": "active"},
            },
        )

    settings = Settings(environment="test", sub2api_base_url="http://sub2api:8080")
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(handler),
        base_url=settings.sub2api_base_url,
    ) as http_client:
        client = HTTPSub2APIClient(settings, client=http_client)
        with pytest.raises(Sub2APIProtocolError):
            await client.verify_access_token(
                "still-locally-valid-access-token",
                Sub2APIRequestIdentity(client_ip="203.0.113.42", user_agent="browser"),
            )


@pytest.mark.parametrize(
    "payload",
    [
        {"code": 0, "data": {"id": 42, "status": "active"}},
        {
            "code": 0,
            "message": "success",
            "data": {"id": 42, "status": "active"},
            "success": True,
        },
        {"code": 200, "message": "success", "data": {"id": 42, "status": "active"}},
        {"code": "0", "message": "success", "data": {"id": 42, "status": "active"}},
        {"code": False, "message": "success", "data": {"id": 42, "status": "active"}},
        {"code": 0, "message": "ok", "data": {"id": 42, "status": "active"}},
        {
            "code": 0,
            "message": "success",
            "data": {"user": {"id": 42, "status": "active"}},
        },
        {"code": 0, "message": "success", "data": {"id": "42", "status": "active"}},
        {"code": 0, "message": "success", "data": {"id": True, "status": "active"}},
        {"code": 0, "message": "success", "data": {"id": 0, "status": "active"}},
        {"code": 0, "message": "success", "data": {"id": 2**63, "status": "active"}},
        {"code": 0, "message": "success", "data": {"id": 42}},
        {"code": 0, "message": "success", "data": {"id": 42, "status": 1}},
        {"code": 0, "message": "success", "data": {"id": 42, "status": "unknown"}},
        {"code": 0, "message": "success", "data": {"id": 42, "status": "Active"}},
        {"code": 0, "message": "success", "data": {"id": 42, "status": "active "}},
        {
            "code": 0,
            "message": "success",
            "data": {"id": 42, "status": "active", "username": False},
        },
        {
            "code": 0,
            "message": "success",
            "data": {"id": 42, "status": "active", "email": []},
        },
        {"code": 0, "message": "success", "id": 42},
    ],
)
def test_auth_me_accepts_only_the_frozen_success_envelope(
    payload: dict[str, object],
) -> None:
    with pytest.raises(Sub2APIProtocolError):
        parse_auth_me(payload)


@pytest.mark.parametrize(
    "payload",
    [
        {"id": 42, "status": "disabled"},
        {"id": 42, "status": "inactive"},
        {"id": 42, "status": "suspended"},
    ],
)
def test_auth_me_rejects_disabled_users(payload: dict[str, object]) -> None:
    with pytest.raises(DisabledSub2APIUser):
        parse_auth_me({"code": 0, "message": "success", "data": payload})
