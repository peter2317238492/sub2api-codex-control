from __future__ import annotations

import httpx
import pytest

from control_api.config import Settings
from control_api.sub2api import (
    DisabledSub2APIUser,
    HTTPSub2APIClient,
    InvalidSub2APIToken,
    Sub2APIRequestIdentity,
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
                "data": {
                    "user": {
                        "id": 42,
                        "username": "alice",
                        "status": "active",
                        "tokenVersion": 7,
                    }
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
    assert user.token_version == "7"


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


@pytest.mark.parametrize(
    "payload",
    [
        {"id": 42, "status": "disabled"},
        {"id": 42, "is_active": False},
        {"id": 42, "disabled": True},
    ],
)
def test_auth_me_rejects_disabled_users(payload: dict[str, object]) -> None:
    with pytest.raises(DisabledSub2APIUser):
        parse_auth_me({"data": payload})
