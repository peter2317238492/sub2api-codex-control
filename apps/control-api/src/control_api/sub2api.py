from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any, Protocol

import httpx

from .config import Settings


class Sub2APIError(Exception):
    pass


class InvalidSub2APIToken(Sub2APIError):
    pass


class RevokedSub2APIToken(InvalidSub2APIToken):
    pass


class DisabledSub2APIUser(Sub2APIError):
    pass


class Sub2APIUnavailable(Sub2APIError):
    pass


class Sub2APIProtocolError(Sub2APIError):
    pass


@dataclass(frozen=True)
class Sub2APIUser:
    user_id: str
    username: str | None = None
    email: str | None = None
    display_name: str | None = None
    token_version: str | None = None


@dataclass(frozen=True)
class Sub2APIRequestIdentity:
    client_ip: str
    user_agent: str


class Sub2APIIdentityVerifier(Protocol):
    async def verify_access_token(
        self,
        access_token: str,
        request_identity: Sub2APIRequestIdentity,
    ) -> Sub2APIUser: ...

    async def close(self) -> None: ...


class HTTPSub2APIClient:
    def __init__(self, settings: Settings, client: httpx.AsyncClient | None = None) -> None:
        self._settings = settings
        self._owns_client = client is None
        self._client = client or httpx.AsyncClient(
            base_url=settings.sub2api_base_url,
            timeout=settings.sub2api_timeout_seconds,
            verify=settings.sub2api_verify_tls,
            follow_redirects=False,
        )

    async def verify_access_token(
        self,
        access_token: str,
        request_identity: Sub2APIRequestIdentity,
    ) -> Sub2APIUser:
        try:
            async with asyncio.timeout(self._settings.sub2api_timeout_seconds):
                response = await self._client.get(
                    self._settings.sub2api_auth_me_path,
                    headers={
                        "Authorization": f"Bearer {access_token}",
                        "Accept": "application/json",
                        "User-Agent": request_identity.user_agent,
                        "X-Forwarded-For": request_identity.client_ip,
                    },
                )
        except TimeoutError as exc:
            raise Sub2APIUnavailable("Sub2API authentication endpoint timed out") from exc
        except httpx.RequestError as exc:
            raise Sub2APIUnavailable("Sub2API authentication endpoint is unavailable") from exc

        error_code = _response_error_code(response)
        if response.status_code == 401 and error_code == "USER_INACTIVE":
            raise DisabledSub2APIUser("Sub2API user is disabled")
        if response.status_code == 401 and error_code == "TOKEN_REVOKED":
            raise RevokedSub2APIToken("Sub2API access token was revoked")
        if response.status_code in {401, 403}:
            raise InvalidSub2APIToken("Sub2API rejected the access token")
        if response.status_code < 200 or response.status_code >= 300:
            raise Sub2APIUnavailable(
                f"Sub2API authentication endpoint returned HTTP {response.status_code}"
            )
        if response.status_code != 200:
            raise Sub2APIProtocolError(
                f"Sub2API authentication endpoint returned unexpected HTTP {response.status_code}"
            )
        try:
            body = response.json()
        except ValueError as exc:
            raise Sub2APIProtocolError("Sub2API returned non-JSON identity data") from exc
        return parse_auth_me(body)

    async def close(self) -> None:
        if self._owns_client:
            await self._client.aclose()


def parse_auth_me(body: Any) -> Sub2APIUser:
    if not isinstance(body, dict):
        raise Sub2APIProtocolError("Sub2API identity payload must be an object")
    if set(body) != {"code", "message", "data"}:
        raise Sub2APIProtocolError("Sub2API identity response has an unexpected envelope")
    if type(body["code"]) is not int or body["code"] != 0:
        raise Sub2APIProtocolError("Sub2API identity response reported failure")
    if body["message"] != "success":
        raise Sub2APIProtocolError("Sub2API identity response has an unexpected message")

    candidate: Any = body["data"]
    if not isinstance(candidate, dict):
        raise Sub2APIProtocolError("Sub2API identity data must be an object")

    user_id = candidate.get("id")
    if type(user_id) is not int or not 1 <= user_id <= 2**63 - 1:
        raise Sub2APIProtocolError("Sub2API identity response has an invalid user id")
    if not _user_is_enabled(candidate):
        raise DisabledSub2APIUser("Sub2API user is disabled")

    return Sub2APIUser(
        user_id=str(user_id),
        username=_optional_string(candidate.get("username"), "username"),
        email=_optional_string(candidate.get("email"), "email"),
        display_name=None,
        token_version=None,
    )


def _response_error_code(response: httpx.Response) -> str | None:
    try:
        body = response.json()
    except ValueError:
        return None
    if not isinstance(body, dict):
        return None
    code = body.get("code")
    return code if isinstance(code, str) else None


def _optional_string(value: Any, field_name: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise Sub2APIProtocolError(f"Sub2API returned an invalid {field_name}")
    normalized = value.strip()
    return normalized or None


def _user_is_enabled(user: dict[str, Any]) -> bool:
    raw_status = user.get("status")
    if not isinstance(raw_status, str):
        raise Sub2APIProtocolError("Sub2API returned a missing or invalid user status")
    if raw_status == "active":
        return True
    if raw_status in {
        "disabled",
        "inactive",
        "banned",
        "blocked",
        "suspended",
        "deleted",
        "locked",
    }:
        return False
    raise Sub2APIProtocolError("Sub2API returned an unknown user status")
