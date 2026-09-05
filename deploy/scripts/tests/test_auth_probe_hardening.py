from __future__ import annotations

import importlib.util
import json
import os
import tempfile
import types
import unittest
from pathlib import Path
from typing import Self
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[3]
PROBE_PATH = REPO_ROOT / "deploy/scripts/probe-sub2api-auth-contract.py"
SPEC = importlib.util.spec_from_file_location("probe_sub2api_auth_contract", PROBE_PATH)
assert SPEC is not None and SPEC.loader is not None
PROBE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROBE)


class Response:
    def __init__(self, url: str, status: int, value: object | None = None) -> None:
        self.url = url
        self.status = status
        self.payload = b"" if value is None else json.dumps(value).encode()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def geturl(self) -> str:
        return self.url

    def read(self, _limit: int) -> bytes:
        return self.payload


class Opener:
    def __init__(
        self,
        *,
        refreshed_user: str = "fixture-user",
        disabled_code: str = "USER_INACTIVE",
        revoked_code: str = "TOKEN_REVOKED",
        binding_code: str = "SESSION_BINDING_MISMATCH",
        flat_refresh: bool = False,
    ) -> None:
        self.refreshed_user = refreshed_user
        self.disabled_code = disabled_code
        self.revoked_code = revoked_code
        self.binding_code = binding_code
        self.flat_refresh = flat_refresh
        self.old_refresh_used = False
        self.logged_out = False

    def open(self, request: object, timeout: float) -> Response:
        del timeout
        method = request.get_method()
        url = request.full_url
        path = url.removeprefix(PROBE.EXPECTED_AUTH_ORIGIN)
        authorization = request.get_header("Authorization")
        headers = {key.lower(): value for key, value in request.header_items()}
        body = json.loads(request.data) if request.data else {}
        if method == "GET" and path == "/api/v1/auth/me":
            if authorization == "Bearer active-access":
                return Response(url, 200, {"data": {"id": "fixture-user"}})
            if authorization == "Bearer rotated-access":
                if "x-forwarded-for" in headers or headers.get(
                    "user-agent", ""
                ).startswith("sub2api-auth-contract-probe/"):
                    return Response(url, 401, {"code": self.binding_code})
                return Response(url, 200, {"data": {"id": self.refreshed_user}})
            if authorization == "Bearer disabled-access":
                return Response(url, 401, {"code": self.disabled_code})
            return Response(url, 401, {"code": self.revoked_code})
        if method == "POST" and path == "/api/v1/auth/refresh":
            refresh = body.get("refresh_token")
            if refresh == "active-refresh" and not self.old_refresh_used:
                self.old_refresh_used = True
                data = {
                    "access_token": "rotated-access",
                    "refresh_token": "rotated-refresh",
                    "expires_in": 600,
                    "token_type": "Bearer",
                }
                return Response(
                    url,
                    200,
                    data
                    if self.flat_refresh
                    else {"code": 0, "message": "success", "data": data},
                )
            return Response(url, 401, {"error": "rejected"})
        if (
            method == "POST"
            and path == "/api/v1/auth/logout"
            and authorization == "Bearer rotated-access"
            and body.get("refresh_token") == "rotated-refresh"
        ):
            self.logged_out = True
            return Response(url, 204)
        return Response(url, 400, {"error": "unexpected fixture request"})


class AuthProbeHardeningTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="auth-probe-tests.")
        self.root = Path(self.temporary.name)
        self.contract = self.root / "contract.json"
        self.contract.write_bytes(
            (REPO_ROOT / "docs/contracts/sub2api-auth.v0.2.1.json").read_bytes()
        )
        self.contract.chmod(0o644)
        contract_sha = PROBE.hashlib.sha256(self.contract.read_bytes()).hexdigest()
        self.runtime = self.root / "runtime.json"
        self.runtime.write_text(
            json.dumps(
                {
                    "container_id": "1" * 64,
                    "image_id": f"sha256:{'2' * 64}",
                    "image_digest": f"registry/sub2api@sha256:{'3' * 64}",
                    "binary_sha256": "4" * 64,
                    "runtime_version": "0.2.1",
                    "runtime_commit": "578785ee7fb35030b094b69624efe25670a36f5f",
                    "contract_sha256": contract_sha,
                }
            ),
            encoding="utf-8",
        )
        self.runtime.chmod(0o600)
        self.tokens: dict[str, Path] = {}
        for value in (
            "active-access",
            "active-refresh",
            "disabled-access",
            "revoked-access",
        ):
            path = self.root / value
            path.write_text(f"{value}\n", encoding="utf-8")
            path.chmod(0o600)
            self.tokens[value] = path

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def arguments(self) -> types.SimpleNamespace:
        return types.SimpleNamespace(
            base_url=PROBE.EXPECTED_AUTH_ORIGIN,
            active_access_token_file=self.tokens["active-access"],
            active_refresh_token_file=self.tokens["active-refresh"],
            disabled_access_token_file=self.tokens["disabled-access"],
            revoked_access_token_file=self.tokens["revoked-access"],
            runtime_attestation=self.runtime,
            contract_file=self.contract,
            probe_nonce="a" * 64,
            expected_user_id="fixture-user",
            timeout=5.0,
        )

    def test_probe_binds_contract_loopback_nonce_and_exact_identity(self) -> None:
        opener = Opener()
        with mock.patch.object(
            PROBE.urllib.request, "build_opener", return_value=opener
        ) as build_opener:
            evidence = PROBE.run(self.arguments())
        self.assertTrue(opener.logged_out)
        self.assertEqual(evidence["format_version"], 4)
        self.assertEqual(evidence["probe"]["base_url"], PROBE.EXPECTED_AUTH_ORIGIN)
        self.assertEqual(evidence["probe"]["nonce"], "a" * 64)
        self.assertEqual(evidence["probe"]["network_namespace_container_id"], "1" * 64)
        self.assertEqual(
            evidence["fixtures"]["auth_me_success"]["user_id"], "fixture-user"
        )
        self.assertTrue(evidence["fixtures"]["refresh_rotation"]["same_identity"])
        self.assertEqual(
            evidence["fixtures"]["auth_me_session_binding_mismatch"],
            {
                "status": 401,
                "code": "SESSION_BINDING_MISMATCH",
                "ip_and_user_agent_changed": True,
            },
        )
        serialized = json.dumps(evidence)
        self.assertNotIn("active-access", serialized)
        self.assertNotIn("active-refresh", serialized)
        proxy_handler = build_opener.call_args.args[0]
        self.assertEqual(proxy_handler.proxies, {})

    def test_probe_rejects_unbound_origin_and_refreshed_identity(self) -> None:
        arguments = self.arguments()
        arguments.base_url = "https://unrelated.example"
        with self.assertRaisesRegex(ValueError, "exactly"):
            PROBE.run(arguments)

        with (
            mock.patch.object(
                PROBE.urllib.request,
                "build_opener",
                return_value=Opener(refreshed_user="other-user"),
            ),
            self.assertRaisesRegex(ValueError, "preserve the exact active identity"),
        ):
            PROBE.run(self.arguments())

    def test_probe_rejects_random_invalid_tokens_as_semantic_fixtures(self) -> None:
        with (
            mock.patch.object(
                PROBE.urllib.request,
                "build_opener",
                return_value=Opener(disabled_code="INVALID_TOKEN"),
            ),
            self.assertRaisesRegex(ValueError, "USER_INACTIVE"),
        ):
            PROBE.run(self.arguments())

        with (
            mock.patch.object(
                PROBE.urllib.request,
                "build_opener",
                return_value=Opener(revoked_code="INVALID_TOKEN"),
            ),
            self.assertRaisesRegex(ValueError, "TOKEN_REVOKED"),
        ):
            PROBE.run(self.arguments())

        with (
            mock.patch.object(
                PROBE.urllib.request,
                "build_opener",
                return_value=Opener(binding_code="INVALID_TOKEN"),
            ),
            self.assertRaisesRegex(ValueError, "IP/User-Agent mismatch"),
        ):
            PROBE.run(self.arguments())

    def test_probe_rejects_legacy_flat_refresh_response(self) -> None:
        with (
            mock.patch.object(
                PROBE.urllib.request,
                "build_opener",
                return_value=Opener(flat_refresh=True),
            ),
            self.assertRaisesRegex(ValueError, "response envelope"),
        ):
            PROBE.run(self.arguments())

    def test_probe_rejects_token_symlink_hardlink_and_broad_mode(self) -> None:
        original = self.tokens["disabled-access"]
        alias = self.root / "disabled-alias"
        alias.symlink_to(original)
        arguments = self.arguments()
        arguments.disabled_access_token_file = alias
        with self.assertRaisesRegex(ValueError, "regular non-symlink"):
            PROBE.run(arguments)

        hardlink = self.root / "disabled-hardlink"
        os.link(original, hardlink)
        arguments.disabled_access_token_file = original
        with self.assertRaisesRegex(ValueError, "exactly one hard link"):
            PROBE.run(arguments)
        hardlink.unlink()

        original.chmod(0o640)
        with self.assertRaisesRegex(ValueError, "0600"):
            PROBE.run(arguments)

    def test_probe_rejects_contract_or_runtime_identity_drift(self) -> None:
        contract = json.loads(self.contract.read_text(encoding="utf-8"))
        contract["endpoints"]["identity"]["path"] = "/api/v1/unrelated"
        self.contract.write_text(json.dumps(contract), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "contract hash differs"):
            PROBE.run(self.arguments())

        self.contract.write_bytes(
            (REPO_ROOT / "docs/contracts/sub2api-auth.v0.2.1.json").read_bytes()
        )
        runtime = json.loads(self.runtime.read_text(encoding="utf-8"))
        runtime["container_id"] = f"sha256:{'1' * 64}"
        self.runtime.write_text(json.dumps(runtime), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "container ID is invalid"):
            PROBE.run(self.arguments())

    def test_probe_rejects_session_binding_error_contract_drift(self) -> None:
        original = json.loads(self.contract.read_text(encoding="utf-8"))
        cases = (
            ("status", 403, "error semantics"),
            ("code", "INVALID_TOKEN", "SESSION_BINDING_MISMATCH"),
        )
        for field, value, expected_error in cases:
            with self.subTest(field=field):
                contract = json.loads(json.dumps(original))
                contract["endpoints"]["identity"]["session_binding_mismatch_error"][
                    field
                ] = value
                self.contract.write_text(json.dumps(contract), encoding="utf-8")
                runtime = PROBE.load_runtime(self.runtime)
                runtime["contract_sha256"] = PROBE.hashlib.sha256(
                    self.contract.read_bytes()
                ).hexdigest()
                with self.assertRaisesRegex(ValueError, expected_error):
                    PROBE.load_contract(self.contract, runtime)

    def test_probe_rejects_session_binding_request_header_drift(self) -> None:
        original = json.loads(self.contract.read_text(encoding="utf-8"))
        cases = (
            {
                "client_ip_header": "Forwarded",
                "user_agent_header": "User-Agent",
            },
            {"client_ip_header": "X-Forwarded-For"},
            {
                "client_ip_header": "X-Forwarded-For",
                "user_agent_header": "User-Agent",
                "fallback_header": "X-Real-IP",
            },
        )
        for request_contract in cases:
            with self.subTest(request_contract=request_contract):
                contract = json.loads(json.dumps(original))
                contract["endpoints"]["identity"]["session_binding_request"] = (
                    request_contract
                )
                self.contract.write_text(json.dumps(contract), encoding="utf-8")
                runtime = PROBE.load_runtime(self.runtime)
                runtime["contract_sha256"] = PROBE.hashlib.sha256(
                    self.contract.read_bytes()
                ).hexdigest()
                with self.assertRaisesRegex(ValueError, "request headers"):
                    PROBE.load_contract(self.contract, runtime)


if __name__ == "__main__":
    unittest.main()
