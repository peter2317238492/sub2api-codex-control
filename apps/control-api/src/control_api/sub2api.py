from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

import httpx

from .config import Settings


class Sub2APIError(Exception):
    pass


class InvalidSub2APIToken(Sub2APIError):
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
            response = await self._client.get(
                self._settings.sub2api_auth_me_path,
                headers={
                    "Authorization": f"Bearer {access_token}",
                    "Accept": "application/json",
                    "User-Agent": request_identity.user_agent,
                    "X-Forwarded-For": request_identity.client_ip,
                },
            )
        except httpx.RequestError as exc:
            raise Sub2APIUnavailable("Sub2API authentication endpoint is unavailable") from exc

        if response.status_code == 401 and _response_error_code(response) == "USER_INACTIVE":
            raise DisabledSub2APIUser("Sub2API user is disabled")
        if response.status_code in {401, 403}:
            raise InvalidSub2APIToken("Sub2API rejected the access token")
        if response.status_code < 200 or response.status_code >= 300:
            raise Sub2APIUnavailable(
                f"Sub2API authentication endpoint returned HTTP {response.status_code}"
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
    if body.get("success") is False:
        raise InvalidSub2APIToken("Sub2API identity response reported failure")
    response_code = body.get("code")
    if response_code not in {None, 0, 200, "0", "200"}:
        raise InvalidSub2APIToken("Sub2API identity response reported failure")

    candidate: Any = body.get("data", body)
    if isinstance(candidate, dict) and isinstance(candidate.get("user"), dict):
        candidate = candidate["user"]
    if not isinstance(candidate, dict):
        raise Sub2APIProtocolError("Sub2API identity data must be an object")

    user_id = _first(candidate, "id", "user_id", "userId")
    if user_id is None or isinstance(user_id, bool) or not str(user_id).strip():
        raise Sub2APIProtocolError("Sub2API identity response has no user id")
    if not _user_is_enabled(candidate):
        raise DisabledSub2APIUser("Sub2API user is disabled")

    return Sub2APIUser(
        user_id=str(user_id),
        username=_optional_string(_first(candidate, "username", "name")),
        email=_optional_string(candidate.get("email")),
        display_name=_optional_string(_first(candidate, "display_name", "displayName", "nickname")),
        token_version=_optional_string(
            _first(candidate, "token_version", "tokenVersion", "TokenVersion")
        ),
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


def _first(mapping: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        if key in mapping:
            return mapping[key]
    return None


def _optional_string(value: Any) -> str | None:
    if value is None:
        return None
    normalized = str(value).strip()
    return normalized or None


def _user_is_enabled(user: dict[str, Any]) -> bool:
    if _coerce_boolean(user.get("disabled")) is True:
        return False
    for key in ("is_active", "isActive", "active", "enabled"):
        if key in user and _coerce_boolean(user[key]) is False:
            return False

    raw_status = user.get("status")
    if raw_status is None:
        return True
    if isinstance(raw_status, bool):
        return raw_status
    if isinstance(raw_status, int):
        return raw_status == 1
    normalized = str(raw_status).strip().lower()
    if normalized in {"active", "enabled", "normal", "1"}:
        return True
    if normalized in {
        "disabled",
        "inactive",
        "banned",
        "blocked",
        "suspended",
        "deleted",
        "locked",
        "0",
    }:
        return False
    raise Sub2APIProtocolError("Sub2API returned an unknown user status")


def _coerce_boolean(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, int) and value in {0, 1}:
        return bool(value)
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"true", "1", "yes"}:
            return True
        if normalized in {"false", "0", "no"}:
            return False
    return None
