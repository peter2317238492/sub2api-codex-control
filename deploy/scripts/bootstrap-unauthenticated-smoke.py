#!/usr/bin/env python3
"""Read-only public smoke checks for the one-time unsigned bootstrap path."""

from __future__ import annotations

import argparse
import base64
import hashlib
import http.client
import json
import os
import secrets
import ssl
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import NamedTuple
from urllib.parse import SplitResult, urlsplit

MAX_RESPONSE_BYTES = 1024 * 1024
USER_AGENT = "sub2api-codex-control-unsigned-bootstrap-smoke/1"
ZERO_UUID = "00000000-0000-0000-0000-000000000000"

BROWSER_CSP_DIRECTIVES = (
    "default-src 'none'",
    "connect-src 'self'",
    "frame-ancestors 'none'",
    "script-src 'self'",
    "style-src 'self'",
    "worker-src 'self'",
)
API_CSP = (
    "default-src 'none'; base-uri 'none'; form-action 'none'; "
    "frame-ancestors 'none'; object-src 'none'"
)
PERMISSIONS_POLICY = (
    "accelerometer=(), autoplay=(), camera=(), display-capture=(), "
    "geolocation=(), gyroscope=(), magnetometer=(), microphone=(), "
    "payment=(), publickey-credentials-get=(), usb=()"
)
HSTS = "max-age=63072000; includesubdomains"


class SmokeFailure(RuntimeError):
    """A public deployment invariant was not satisfied."""


class ParsedOrigin(NamedTuple):
    scheme: str
    host: str
    port: int
    authority: str
    value: str


class HTTPResponse(NamedTuple):
    status: int
    headers: dict[str, list[str]]
    body: bytes


def parse_origin(value: str, *, allow_http: bool = False) -> ParsedOrigin:
    raw = value.strip()
    parsed: SplitResult = urlsplit(raw)
    allowed_schemes = {"https"} | ({"http"} if allow_http else set())
    if parsed.scheme not in allowed_schemes:
        expected = "https" if not allow_http else "http or https"
        raise SmokeFailure(f"base URL must use {expected}")
    if parsed.username is not None or parsed.password is not None:
        raise SmokeFailure("base URL must not contain credentials")
    if parsed.hostname is None:
        raise SmokeFailure("base URL must contain a host")
    if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        raise SmokeFailure(
            "base URL must be an origin without a path, query, or fragment"
        )
    try:
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
    except ValueError as exc:
        raise SmokeFailure("base URL contains an invalid port") from exc
    return ParsedOrigin(
        parsed.scheme,
        parsed.hostname,
        port,
        parsed.netloc,
        f"{parsed.scheme}://{parsed.netloc}",
    )


class SmokeClient:
    def __init__(
        self,
        origin: ParsedOrigin,
        *,
        timeout: float,
        ca_file: Path | None,
    ) -> None:
        self.origin = origin
        self.timeout = timeout
        self.ssl_context = (
            ssl.create_default_context(
                cafile=str(ca_file) if ca_file is not None else None
            )
            if origin.scheme == "https"
            else None
        )

    def _connection(self) -> http.client.HTTPConnection:
        if self.origin.scheme == "https":
            return http.client.HTTPSConnection(
                self.origin.host,
                self.origin.port,
                timeout=self.timeout,
                context=self.ssl_context,
            )
        return http.client.HTTPConnection(
            self.origin.host,
            self.origin.port,
            timeout=self.timeout,
        )

    def get(self, path: str, headers: dict[str, str] | None = None) -> HTTPResponse:
        request_headers = {
            "Accept": "application/json",
            "Host": self.origin.authority,
            "User-Agent": USER_AGENT,
        }
        request_headers.update(headers or {})
        connection = self._connection()
        try:
            connection.request("GET", path, headers=request_headers)
            response = connection.getresponse()
            response_headers: dict[str, list[str]] = {}
            for name, value in response.getheaders():
                response_headers.setdefault(name.lower(), []).append(value.strip())
            body = (
                b"" if response.status == 101 else response.read(MAX_RESPONSE_BYTES + 1)
            )
            if len(body) > MAX_RESPONSE_BYTES:
                raise SmokeFailure(
                    f"GET {path} returned more than {MAX_RESPONSE_BYTES} bytes"
                )
            return HTTPResponse(response.status, response_headers, body)
        except SmokeFailure:
            raise
        except (OSError, http.client.HTTPException) as exc:
            raise SmokeFailure(f"GET {path} failed: {exc}") from exc
        finally:
            connection.close()

    def websocket_upgrade(self, path: str, *, browser: bool) -> HTTPResponse:
        key = base64.b64encode(secrets.token_bytes(16)).decode("ascii")
        headers = {
            "Accept": "*/*",
            "Connection": "Upgrade",
            "Upgrade": "websocket",
            "Sec-WebSocket-Version": "13",
            "Sec-WebSocket-Key": key,
        }
        if browser:
            headers["Origin"] = self.origin.value
        response = self.get(path, headers)
        if response.status == 101:
            expected_accept = base64.b64encode(
                hashlib.sha1(
                    f"{key}258EAFA5-E914-47DA-95CA-C5AB0DC85B11".encode("ascii")
                ).digest()
            ).decode("ascii")
            actual_accept = _single_header(response, "Sec-WebSocket-Accept")
            detail = "valid" if actual_accept == expected_accept else "invalid"
            raise SmokeFailure(
                f"unauthenticated WebSocket GET {path} upgraded with a {detail} acceptance"
            )
        if response.status not in {401, 403}:
            raise SmokeFailure(
                f"unauthenticated WebSocket GET {path} returned {response.status}; "
                "expected 401 or 403 before upgrade"
            )
        return response


def _single_header(response: HTTPResponse, name: str) -> str | None:
    values = response.headers.get(name.lower(), [])
    return values[0] if len(values) == 1 else None


def require_single_header(
    response: HTTPResponse,
    name: str,
    expected: str | None = None,
) -> str:
    values = response.headers.get(name.lower(), [])
    if len(values) != 1:
        raise SmokeFailure(
            f"expected exactly one {name} header, received {len(values)}"
        )
    value = values[0]
    if expected is not None and value.lower() != expected.lower():
        raise SmokeFailure(f"unexpected {name} header value")
    return value


def verify_browser_headers(response: HTTPResponse) -> None:
    content_type = require_single_header(response, "Content-Type")
    if "text/html" not in content_type.lower():
        raise SmokeFailure("/codex/ did not return HTML")
    csp = require_single_header(response, "Content-Security-Policy")
    for directive in BROWSER_CSP_DIRECTIVES:
        if directive not in csp:
            raise SmokeFailure(f"browser CSP is missing {directive}")
    if "'unsafe-inline'" in csp or "'unsafe-eval'" in csp:
        raise SmokeFailure("browser CSP permits unsafe inline or evaluated content")
    require_single_header(response, "Cross-Origin-Opener-Policy", "same-origin")
    require_single_header(response, "Cross-Origin-Resource-Policy", "same-origin")
    require_single_header(response, "Permissions-Policy", PERMISSIONS_POLICY)
    require_single_header(response, "Referrer-Policy", "no-referrer")
    require_single_header(response, "Strict-Transport-Security", HSTS)
    require_single_header(response, "X-Content-Type-Options", "nosniff")
    require_single_header(response, "X-Frame-Options", "DENY")
    if response.headers.get("access-control-allow-origin"):
        raise SmokeFailure("/codex/ unexpectedly grants cross-origin access")


def verify_api_headers(response: HTTPResponse) -> None:
    require_single_header(response, "Cache-Control", "no-store")
    require_single_header(response, "Content-Security-Policy", API_CSP)
    require_single_header(response, "Cross-Origin-Opener-Policy", "same-origin")
    require_single_header(response, "Cross-Origin-Resource-Policy", "same-origin")
    require_single_header(response, "Permissions-Policy", PERMISSIONS_POLICY)
    require_single_header(response, "Pragma", "no-cache")
    require_single_header(response, "Referrer-Policy", "no-referrer")
    require_single_header(response, "Strict-Transport-Security", HSTS)
    require_single_header(response, "X-Content-Type-Options", "nosniff")
    require_single_header(response, "X-Frame-Options", "DENY")
    if response.headers.get("access-control-allow-origin"):
        raise SmokeFailure("Control API unexpectedly grants cross-origin access")


def require_status(response: HTTPResponse, path: str, expected: set[int]) -> None:
    if response.status not in expected:
        wanted = "/".join(str(status) for status in sorted(expected))
        raise SmokeFailure(f"GET {path} returned {response.status}; expected {wanted}")


def verify_readiness(response: HTTPResponse) -> None:
    try:
        payload = json.loads(response.body)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SmokeFailure("readiness response is not JSON") from exc
    if not isinstance(payload, dict) or payload.get("status") != "ready":
        raise SmokeFailure("readiness response does not report ready")
    checks = payload.get("checks")
    required = {
        "connector_release",
        "database",
        "database_migrations",
        "redis",
        "sub2api_contract",
    }
    if not isinstance(checks, dict) or not required.issubset(checks):
        raise SmokeFailure("readiness response is missing required dependency checks")
    if any(value != "ok" for value in checks.values()):
        raise SmokeFailure("readiness response contains a failed dependency check")


def run_smoke(
    base_url: str,
    *,
    timeout: float = 10.0,
    ca_file: Path | None = None,
    allow_http: bool = False,
) -> dict[str, object]:
    if timeout <= 0:
        raise SmokeFailure("timeout must be positive")
    if ca_file is not None and (not ca_file.is_file() or ca_file.is_symlink()):
        raise SmokeFailure("CA file must be a regular, non-symlink file")

    origin = parse_origin(base_url, allow_http=allow_http)
    client = SmokeClient(origin, timeout=timeout, ca_file=ca_file)
    checks: list[dict[str, object]] = []

    shell_path = "/codex/"
    shell = client.get(shell_path, {"Accept": "text/html"})
    require_status(shell, shell_path, {200})
    verify_browser_headers(shell)
    checks.append(
        {"name": "pwa_shell", "method": "GET", "path": shell_path, "status": 200}
    )

    ready_path = "/codex-api/v1/health/ready"
    ready = client.get(ready_path)
    require_status(ready, ready_path, {200})
    verify_readiness(ready)
    verify_api_headers(ready)
    checks.append(
        {"name": "api_readiness", "method": "GET", "path": ready_path, "status": 200}
    )

    unauthenticated_paths = (
        ("session_rejection", "/codex-api/v1/session"),
        ("device_list_rejection", "/codex-api/v1/devices"),
        (
            "device_pairing_poll_rejection",
            f"/codex-api/v1/device-pairings/{ZERO_UUID}/poll",
        ),
    )
    for name, path in unauthenticated_paths:
        response = client.get(path)
        require_status(response, path, {401, 403})
        checks.append(
            {"name": name, "method": "GET", "path": path, "status": response.status}
        )

    websocket_paths = (
        ("browser_websocket_rejection", "/codex-ws/browser", True),
        ("device_websocket_rejection", "/codex-ws/device", False),
    )
    for name, path, browser in websocket_paths:
        response = client.websocket_upgrade(path, browser=browser)
        checks.append(
            {"name": name, "method": "GET", "path": path, "status": response.status}
        )

    return {
        "schema_version": 1,
        "kind": "unsigned-bootstrap-unauthenticated-smoke",
        "result": "passed",
        "base_url": origin.value,
        "checked_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "checks": checks,
    }


def write_result(result: dict[str, object], output: str) -> None:
    encoded = (json.dumps(result, indent=2, sort_keys=True) + "\n").encode("utf-8")
    if output == "-":
        sys.stdout.buffer.write(encoded)
        return

    destination = Path(output)
    if not destination.parent.is_dir():
        raise SmokeFailure("output parent directory does not exist")
    fd, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.", suffix=".tmp", dir=destination.parent
    )
    temporary = Path(temporary_name)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        temporary.replace(destination)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Verify the public, unauthenticated surface after an unsigned first deployment"
        )
    )
    parser.add_argument(
        "--base-url",
        required=True,
        help="public HTTPS origin without a path, for example https://sub2api.example.com",
    )
    parser.add_argument(
        "--output",
        default="-",
        help="JSON evidence path (created mode 0600), or - for stdout",
    )
    parser.add_argument(
        "--timeout", type=float, default=10.0, help="per-request timeout"
    )
    parser.add_argument(
        "--ca-file", type=Path, help="optional private CA certificate bundle"
    )
    parser.add_argument(
        "--allow-http",
        action="store_true",
        help="allow an HTTP origin for local tests only; production must omit this flag",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        result = run_smoke(
            args.base_url,
            timeout=args.timeout,
            ca_file=args.ca_file,
            allow_http=args.allow_http,
        )
        write_result(result, args.output)
    except SmokeFailure as exc:
        print(f"unsigned bootstrap smoke failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
