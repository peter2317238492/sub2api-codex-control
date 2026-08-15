from __future__ import annotations

import importlib.util
import json
import stat
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Self

REPO_ROOT = Path(__file__).resolve().parents[3]
SCRIPT_PATH = REPO_ROOT / "deploy/scripts/bootstrap-unauthenticated-smoke.py"
SPEC = importlib.util.spec_from_file_location("smoke_unsigned_bootstrap", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
SMOKE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SMOKE)


class FixtureHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, _format: str, *args: object) -> None:
        del args

    def _security_headers(self, *, browser: bool) -> None:
        headers = (
            {
                "Content-Security-Policy": (
                    "default-src 'none'; base-uri 'none'; connect-src 'self'; "
                    "font-src 'self'; form-action 'self'; frame-ancestors 'none'; "
                    "img-src 'self' data:; manifest-src 'self'; object-src 'none'; "
                    "script-src 'self'; style-src 'self'; worker-src 'self'"
                ),
                "Cross-Origin-Opener-Policy": "same-origin",
                "Cross-Origin-Resource-Policy": "same-origin",
                "Permissions-Policy": SMOKE.PERMISSIONS_POLICY,
                "Referrer-Policy": "no-referrer",
                "Strict-Transport-Security": "max-age=63072000; includeSubDomains",
                "X-Content-Type-Options": "nosniff",
                "X-Frame-Options": "DENY",
            }
            if browser
            else {
                "Cache-Control": "no-store",
                "Content-Security-Policy": SMOKE.API_CSP,
                "Cross-Origin-Opener-Policy": "same-origin",
                "Cross-Origin-Resource-Policy": "same-origin",
                "Permissions-Policy": SMOKE.PERMISSIONS_POLICY,
                "Pragma": "no-cache",
                "Referrer-Policy": "no-referrer",
                "Strict-Transport-Security": "max-age=63072000; includeSubDomains",
                "X-Content-Type-Options": "nosniff",
                "X-Frame-Options": "DENY",
            }
        )
        omitted = getattr(self.server, "omitted_header", None)
        for name, value in headers.items():
            if name != omitted:
                self.send_header(name, value)

    def _reply(self, status: int, body: bytes, *, browser: bool = False) -> None:
        self.send_response(status)
        self._security_headers(browser=browser)
        self.send_header(
            "Content-Type",
            "text/html; charset=utf-8" if browser else "application/json",
        )
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        records = self.server.records  # type: ignore[attr-defined]
        records.append(
            {
                "path": self.path,
                "authorization": self.headers.get("Authorization"),
                "cookie": self.headers.get("Cookie"),
                "origin": self.headers.get("Origin"),
                "upgrade": self.headers.get("Upgrade"),
            }
        )
        if self.path == "/codex/":
            self._reply(200, b"<!doctype html><title>Control</title>", browser=True)
            return
        if self.path == "/codex-api/v1/health/ready":
            body = json.dumps(
                {
                    "status": "ready",
                    "checks": {
                        "connector_release": "ok",
                        "database": "ok",
                        "database_migrations": "ok",
                        "redis": "ok",
                        "sub2api_contract": "ok",
                    },
                }
            ).encode()
            self._reply(200, body)
            return
        if self.path.startswith("/codex-api/v1/"):
            self._reply(401, b'{"detail":"authentication_required"}')
            return
        if self.path in {"/codex-ws/browser", "/codex-ws/device"}:
            status = self.server.websocket_status  # type: ignore[attr-defined]
            self.send_response_only(status)
            if status == 101:
                self.send_header("Connection", "Upgrade")
                self.send_header("Upgrade", "websocket")
                self.send_header("Sec-WebSocket-Accept", "invalid-fixture-value")
            else:
                self.send_header("Content-Length", "0")
            self.end_headers()
            return
        self._reply(404, b'{"detail":"not_found"}')


class FixtureServer:
    def __init__(
        self, *, omitted_header: str | None = None, websocket_status: int = 403
    ) -> None:
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), FixtureHandler)
        self.server.omitted_header = omitted_header  # type: ignore[attr-defined]
        self.server.websocket_status = websocket_status  # type: ignore[attr-defined]
        self.server.records = []  # type: ignore[attr-defined]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self) -> Self:
        self.thread.start()
        return self

    def __exit__(self, *args: object) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    @property
    def base_url(self) -> str:
        host, port = self.server.server_address
        return f"http://{host}:{port}"


class UnsignedBootstrapSmokeTests(unittest.TestCase):
    def test_passes_without_sending_credentials_and_records_all_checks(self) -> None:
        with FixtureServer() as fixture:
            result = SMOKE.run_smoke(fixture.base_url, allow_http=True)

        self.assertEqual(result["result"], "passed")
        checks = result["checks"]
        self.assertEqual(len(checks), 7)
        self.assertEqual({check["status"] for check in checks}, {200, 401, 403})
        for record in fixture.server.records:  # type: ignore[attr-defined]
            self.assertIsNone(record["authorization"])
            self.assertIsNone(record["cookie"])
        browser = next(
            record
            for record in fixture.server.records  # type: ignore[attr-defined]
            if record["path"] == "/codex-ws/browser"
        )
        self.assertEqual(browser["origin"], fixture.base_url)
        self.assertEqual(browser["upgrade"], "websocket")

    def test_rejects_missing_production_browser_security_header(self) -> None:
        with (
            FixtureServer(omitted_header="X-Frame-Options") as fixture,
            self.assertRaisesRegex(SMOKE.SmokeFailure, "X-Frame-Options"),
        ):
            SMOKE.run_smoke(fixture.base_url, allow_http=True)

    def test_rejects_unauthenticated_websocket_upgrade(self) -> None:
        with (
            FixtureServer(websocket_status=101) as fixture,
            self.assertRaisesRegex(SMOKE.SmokeFailure, "upgraded"),
        ):
            SMOKE.run_smoke(fixture.base_url, allow_http=True)

    def test_https_is_required_without_explicit_local_test_override(self) -> None:
        with self.assertRaisesRegex(SMOKE.SmokeFailure, "must use https"):
            SMOKE.run_smoke("http://127.0.0.1:18092")

    def test_cli_writes_private_json_evidence(self) -> None:
        with FixtureServer() as fixture, tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "smoke.json"
            exit_code = SMOKE.main(
                [
                    "--base-url",
                    fixture.base_url,
                    "--allow-http",
                    "--output",
                    str(output),
                ]
            )
            self.assertEqual(exit_code, 0)
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
            self.assertEqual(json.loads(output.read_text())["result"], "passed")


if __name__ == "__main__":
    unittest.main()
