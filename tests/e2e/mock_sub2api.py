#!/usr/bin/env python3
from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Handler(BaseHTTPRequestHandler):
    server_version = "Sub2APIMock/1"

    def do_GET(self) -> None:
        if self.path == "/health":
            self._json(200, {"status": "ok"})
            return
        if self.path != "/api/v1/auth/me":
            self._json(404, {"message": "not_found"})
            return
        if self.headers.get("Authorization") != "Bearer e2e-access-token-value":
            self._json(401, {"message": "unauthorized"})
            return
        self._json(
            200,
            {
                "code": 0,
                "data": {
                    "user": {
                        "id": "e2e-user-42",
                        "username": "e2e-user",
                        "status": "active",
                        "tokenVersion": 1,
                    }
                },
            },
        )

    def log_message(self, format: str, *args: object) -> None:
        # Deliberately omit request headers so bearer credentials cannot reach logs.
        print(f"sub2api-mock: {self.command} {self.path} {format % args}", flush=True)

    def _json(self, status: int, body: dict[str, object]) -> None:
        payload = json.dumps(body, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(payload)


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
