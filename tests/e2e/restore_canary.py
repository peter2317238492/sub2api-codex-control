from __future__ import annotations

import os

from control_api.main import app
from fastapi.testclient import TestClient


def require_status(response: object, expected: int, label: str) -> None:
    status_code = getattr(response, "status_code", None)
    if status_code != expected:
        raise RuntimeError(f"restore canary {label} returned HTTP {status_code}")


def main() -> None:
    origin = os.environ["CONTROL_ALLOWED_ORIGINS_CSV"].split(",", 1)[0]
    csrf_cookie_name = os.environ.get("CONTROL_CSRF_COOKIE_NAME", "codex_csrf")
    csrf_header_name = os.environ.get("CONTROL_CSRF_HEADER_NAME", "x-csrf-token")

    with TestClient(app, base_url=origin) as client:
        require_status(client.get("/v1/health/ready"), 200, "readiness")
        require_status(
            client.post(
                "/v1/session/exchange",
                headers={"Origin": origin},
                json={"access_token": "e2e-access-token-value"},
            ),
            201,
            "session exchange",
        )
        require_status(client.get("/v1/session"), 200, "session read")
        require_status(client.get("/v1/bootstrap"), 200, "bootstrap")
        csrf_token = client.cookies.get(csrf_cookie_name)
        if not csrf_token:
            raise RuntimeError("restore canary did not receive a CSRF cookie")
        require_status(
            client.post(
                "/v1/session/logout",
                headers={"Origin": origin, csrf_header_name: csrf_token},
            ),
            204,
            "session logout",
        )

    print("Restore application canary passed.")


if __name__ == "__main__":
    main()
