from __future__ import annotations

import argparse
import http.client
import json
import time
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

LOGOUT_PATH = "/api/v1/auth/logout"
AUTHORIZATION = "Bearer fixture-access-token"
REFRESH_TOKEN = "fixture-refresh-token"
RESPONSE_MARKER = "authenticated-logout-header-fixture"
COOKIE_COUNT = 23


def expected_cookie_headers() -> list[str]:
    return [
        f"fixture_{index:02d}={'x' * 150}{index:02d}; Path=/; HttpOnly; Secure; "
        "SameSite=Strict; Max-Age=0"
        for index in range(COOKIE_COUNT)
    ]


@dataclass(frozen=True)
class Response:
    status: int
    headers: list[tuple[str, str]]
    body: bytes

    def header_values(self, name: str) -> list[str]:
        lowered = name.lower()
        return [value for header, value in self.headers if header.lower() == lowered]


class Handler(BaseHTTPRequestHandler):
    server_version = "AuthenticatedLogoutHeaderFixture/1"

    def do_GET(self) -> None:
        if self.path == "/health":
            self._reply(200, b"ok\n", include_large_header=False)
            return
        self._reply(404, b"not found\n", include_large_header=False)

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        if self.path != LOGOUT_PATH:
            self._reply(404, b"not found\n", include_large_header=False)
            return
        body = self.rfile.read(length)
        try:
            payload = json.loads(body)
        except (UnicodeDecodeError, json.JSONDecodeError):
            payload = None
        if (
            self.headers.get("Authorization") != AUTHORIZATION
            or self.headers.get_content_type() != "application/json"
            or payload != {"refresh_token": REFRESH_TOKEN}
        ):
            self._reply(401, b"authenticated JSON request required\n", include_large_header=False)
            return
        response = json.dumps(
            {"code": 0, "data": {"revoked": True}, "marker": RESPONSE_MARKER},
            separators=(",", ":"),
        ).encode("ascii")
        self._reply(200, response, include_large_header=True)

    def log_message(self, format: str, *args: object) -> None:
        return

    def _reply(self, status: int, body: bytes, *, include_large_header: bool) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        if include_large_header:
            for cookie in expected_cookie_headers():
                self.send_header("Set-Cookie", cookie)
            self.send_header(
                "Content-Security-Policy",
                f"default-src 'none'; report-uri /{RESPONSE_MARKER}",
            )
            self.send_header("X-Fixture-Marker", RESPONSE_MARKER)
        self.end_headers()
        self.wfile.write(body)


def request(
    port: int,
    path: str,
    method: str = "GET",
    *,
    body: bytes | None = None,
    headers: dict[str, str] | None = None,
) -> Response:
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
    try:
        connection.request(method, path, body=body, headers=headers or {})
        response = connection.getresponse()
        return Response(response.status, response.getheaders(), response.read())
    finally:
        connection.close()


def wait_until_ready() -> None:
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        try:
            upstream = request(8080, "/health")
            edge = request(18080, "/health")
            if upstream.status == 200 and edge.status == 200:
                return
        except OSError:
            pass
        time.sleep(0.1)
    raise SystemExit("Nginx fixture did not become ready")


def probe() -> None:
    wait_until_ready()
    request_body = json.dumps(
        {"refresh_token": REFRESH_TOKEN}, separators=(",", ":")
    ).encode("ascii")
    request_headers = {
        "Authorization": AUTHORIZATION,
        "Content-Type": "application/json",
    }
    baseline = request(
        18081,
        LOGOUT_PATH,
        "POST",
        body=request_body,
        headers=request_headers,
    )
    if baseline.status != 502:
        raise SystemExit(f"default buffer did not reproduce 502: {baseline.status}")

    fixed = request(
        18080,
        LOGOUT_PATH,
        "POST",
        body=request_body,
        headers=request_headers,
    )
    if fixed.status != 200:
        raise SystemExit(f"buffer snippet did not preserve upstream 200: {fixed.status}")
    cookies = fixed.header_values("Set-Cookie")
    if cookies != expected_cookie_headers():
        raise SystemExit(f"Set-Cookie list changed: received {len(cookies)} of {COOKIE_COUNT}")
    csp = fixed.header_values("Content-Security-Policy")
    if csp != [f"default-src 'none'; report-uri /{RESPONSE_MARKER}"]:
        raise SystemExit("CSP marker is missing or changed")
    if fixed.header_values("X-Fixture-Marker") != [RESPONSE_MARKER]:
        raise SystemExit("response marker header is missing or changed")
    if RESPONSE_MARKER.encode("ascii") not in fixed.body:
        raise SystemExit("response marker body is missing or changed")
    header_bytes = sum(
        len(name.encode("latin-1")) + len(value.encode("latin-1")) + 4
        for name, value in fixed.headers
    ) + 2
    if not 4_096 < header_bytes < 16_384:
        raise SystemExit(f"fixture response headers are outside (4k, 16k): {header_bytes}")
    print(
        "authenticated logout header reproduction passed: "
        f"default=502 fixed=200 cookies={len(cookies)} headers={header_bytes}"
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("serve", "probe"))
    args = parser.parse_args()
    if args.mode == "probe":
        probe()
        return
    ThreadingHTTPServer(("127.0.0.1", 8080), Handler).serve_forever()


if __name__ == "__main__":
    main()
