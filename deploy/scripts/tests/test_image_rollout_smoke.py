from __future__ import annotations

import argparse
import builtins
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
import uuid
from datetime import datetime, timezone
from pathlib import Path
from types import ModuleType, SimpleNamespace
from unittest import mock

SCRIPT = Path(__file__).resolve().parents[1] / "image-rollout-smoke.py"
SPEC = importlib.util.spec_from_file_location("image_rollout_smoke", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
SMOKE: ModuleType = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = SMOKE
SPEC.loader.exec_module(SMOKE)

NOW = datetime(2026, 8, 13, 12, 0, 0, tzinfo=timezone.utc)


def canonical(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("ascii")


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def response(status: int, body: object = b"", content_type: str | None = None) -> object:
    raw = body if isinstance(body, bytes) else json.dumps(body).encode("utf-8")
    headers = {} if content_type is None else {"content-type": (content_type,)}
    return SMOKE.Response(status, headers, raw)


class FakeClient:
    def __init__(self, overrides: dict[str, object] | None = None) -> None:
        self.requests: list[tuple[str, dict[str, str]]] = []
        self.responses = {
            "/codex/": response(
                200, b"<!doctype html><title>Codex Control</title>", "text/html"
            ),
            "/codex/manifest.webmanifest": response(
                200,
                {
                    "name": "Sub2API Codex Control",
                    "scope": "/codex/",
                    "start_url": "/codex/",
                },
            ),
            "/codex-api/v1/health/live": response(200, {"status": "ok"}),
            "/codex-api/v1/health/ready": response(
                200, {"checks": SMOKE.EXPECTED_READY_CHECKS, "status": "ready"}
            ),
            "/codex-api/v1/session": response(401),
            "/codex-ws/browser": response(401),
            "/codex-ws/device": response(403),
            "/codex-ws": response(404),
            "/codex-ws/adjacent": response(404),
        }
        self.responses.update(overrides or {})

    def get(self, path: str, headers: dict[str, str] | None = None) -> object:
        self.requests.append((path, dict(headers or {})))
        value = self.responses[path]
        if isinstance(value, Exception):
            raise value
        return value


class SmokeProducerTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent)
        self.root = Path(self.temp.name)
        self.paths: dict[str, Path] = {}
        self._write_fixtures()

    def tearDown(self) -> None:
        self.temp.cleanup()

    def write(self, name: str, value: object) -> Path:
        path = self.root / name
        path.write_bytes(canonical(value))
        path.chmod(0o600)
        self.paths[name] = path
        return path

    def _write_fixtures(self) -> None:
        image_api = "sha256:" + "a" * 64
        image_pwa = "sha256:" + "b" * 64
        plan = {
            "allowed_changes": {},
            "artifact_manifest_sha256": "1" * 64,
            "command": "plan",
            "format_version": 1,
            "new": {
                "images": {
                    "control-api": image_api,
                    "postgres-tools": "sha256:" + "c" * 64,
                    "pwa": image_pwa,
                },
                "release": SMOKE.TARGET_RELEASE,
                "vcs_ref": SMOKE.TARGET_VCS_REF,
            },
            "new_compose": {},
            "new_compose_sha256": "2" * 64,
            "old": {},
            "old_compose_sha256": "3" * 64,
            "service_components": {},
            "status": "admitted",
        }
        plan_raw = canonical(plan)
        self.write("plan.json", plan)
        baseline = {
            "command": "baseline",
            "format_version": 1,
            "rollout_plan_sha256": digest(plan_raw),
            "status": "admitted",
        }
        running = {
            "command": "running",
            "containers": {
                "codex-pwa": {"image_id": image_pwa},
                "control-api": {"image_id": image_api},
                "control-api-replica": {"image_id": image_api},
            },
            "format_version": 1,
            "plan_sha256": digest(plan_raw),
            "status": "admitted",
        }
        invariants = {
            "command": "invariants",
            "format_version": 1,
            "status": "admitted",
            "unchanged": True,
        }
        baseline_raw = canonical(baseline)
        running_raw = canonical(running)
        invariants_raw = canonical(invariants)
        self.write("baseline.json", baseline)
        self.write("running.json", running)
        self.write("invariants.json", invariants)
        target_without_binding = {
            "baseline_sha256": digest(baseline_raw),
            "invariants_sha256": digest(invariants_raw),
            "plan_sha256": digest(plan_raw),
            "running_sha256": digest(running_raw),
        }
        challenge = {
            "issued_at": "2026-08-13T12:00:00Z",
            "nonce": "4" * 64,
            "rollout_id": str(uuid.UUID("12345678-1234-4234-9234-123456789abc")),
            "schema_version": 1,
            "target": {
                **target_without_binding,
                "binding_sha256": digest(canonical(target_without_binding)),
            },
        }
        self.write("challenge.json", challenge)
        self.write("origin.json", {"origin": "https://control.example", "schema_version": 1})

    def args(self) -> argparse.Namespace:
        return argparse.Namespace(
            origin_file=str(self.paths["origin.json"]),
            challenge=str(self.paths["challenge.json"]),
            plan=str(self.paths["plan.json"]),
            baseline=str(self.paths["baseline.json"]),
            running=str(self.paths["running.json"]),
            invariants=str(self.paths["invariants.json"]),
        )

    def execute(self, client: FakeClient | None = None) -> tuple[dict[str, object], bool]:
        chosen = client or FakeClient()
        return SMOKE.execute(
            self.args(), client_factory=lambda _origin: chosen, clock=lambda: NOW
        )

    def rewrite(self, name: str, mutate: object) -> None:
        path = self.paths[name]
        value = json.loads(path.read_text(encoding="ascii"))
        mutate(value)
        path.write_bytes(canonical(value))
        path.chmod(0o600)

    def test_success_has_frozen_privacy_safe_shape_and_hashes(self) -> None:
        client = FakeClient()
        result, success = self.execute(client)
        self.assertTrue(success)
        self.assertEqual(result["schema_version"], "image-rollout-smoke-result-v1")
        self.assertEqual(result["status"], "passed")
        self.assertEqual(result["check_count"], 9)
        self.assertEqual(result["checks_passed"], 9)
        self.assertEqual(
            result["check_catalog_sha256"],
            "3056c52085fbed3d43437a111ee73be56c051a62df7fd3aceef9fca1c54225a1",
        )
        without_result = dict(result)
        observed = without_result.pop("result_sha256")
        expected = digest(canonical(without_result)[:-1])
        self.assertEqual(observed, expected)
        encoded = canonical(result).decode("ascii")
        for forbidden in (
            "control.example",
            str(self.root),
            "origin",
            "body",
            "password",
            "token",
            "username",
        ):
            self.assertNotIn(forbidden, encoded.lower())
        self.assertEqual([path for path, _headers in client.requests], [
            item["path"] for item in SMOKE.CHECK_CATALOG
        ])

    def test_catalog_constant_matches_exact_ordered_catalog(self) -> None:
        observed = digest(
            json.dumps(
                SMOKE.CHECK_CATALOG,
                ensure_ascii=True,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("ascii")
        )
        self.assertEqual(observed, SMOKE.CHECK_CATALOG_SHA256)
        self.assertGreaterEqual(SMOKE.CHECK_COUNT, 7)

    def test_plan_target_release_and_vcs_are_frozen(self) -> None:
        self.rewrite("plan.json", lambda value: value["new"].__setitem__("release", "other"))
        with self.assertRaises(SMOKE.SmokeError):
            self.execute()

    def test_challenge_tamper_is_rejected(self) -> None:
        self.rewrite(
            "challenge.json",
            lambda value: value["target"].__setitem__("running_sha256", "f" * 64),
        )
        with self.assertRaises(SMOKE.SmokeError):
            self.execute()

    def test_evidence_tamper_is_rejected_by_challenge(self) -> None:
        self.rewrite("invariants.json", lambda value: value.__setitem__("extra", True))
        with self.assertRaises(SMOKE.SmokeError):
            self.execute()

    def test_stale_challenge_is_rejected(self) -> None:
        with self.assertRaises(SMOKE.SmokeError):
            SMOKE.execute(
                self.args(),
                client_factory=lambda _origin: FakeClient(),
                clock=lambda: datetime(2026, 8, 13, 12, 6, tzinfo=timezone.utc),
            )

    def test_http_status_redirect_and_body_failures_are_generic(self) -> None:
        cases = (
            {"/codex/": response(500)},
            {"/codex/": response(302, content_type="text/html")},
            {"/codex-api/v1/health/live": response(200, {"status": "wrong"})},
            {"/codex-api/v1/health/ready": response(200, b"not-json")},
            {"/codex-api/v1/session": response(200)},
        )
        for override in cases:
            with self.subTest(override=override):
                result, success = self.execute(FakeClient(override))
                self.assertFalse(success)
                self.assertEqual(result["status"], "failed")
                self.assertLess(result["checks_passed"], SMOKE.CHECK_COUNT)
                self.assertNotIn("body", canonical(result).decode("ascii"))

    def test_failure_reports_the_exact_completed_check_count(self) -> None:
        result, success = self.execute(
            FakeClient({"/codex-ws/adjacent": response(200)})
        )
        self.assertFalse(success)
        self.assertEqual(result["checks_passed"], 8)

    def test_insecure_or_noncanonical_origin_is_rejected(self) -> None:
        for origin in (
            "http://control.example",
            "https://user:secret@control.example",
            "https://control.example/path",
            "https://CONTROL.example",
            "https://control.example:443",
        ):
            with self.subTest(origin=origin):
                self.write("origin.json", {"origin": origin, "schema_version": 1})
                with self.assertRaises(SMOKE.SmokeError):
                    self.execute()

    def test_websocket_upgrade_and_adjacent_guard_fail_closed(self) -> None:
        for path, status in (
            ("/codex-ws/browser", 101),
            ("/codex-ws/device", 200),
            ("/codex-ws", 308),
            ("/codex-ws/adjacent", 200),
        ):
            with self.subTest(path=path):
                result, success = self.execute(FakeClient({path: response(status)}))
                self.assertFalse(success)
                self.assertEqual(result["status"], "failed")

    def test_symlink_file_and_symlink_ancestor_are_rejected(self) -> None:
        real = self.paths["origin.json"]
        link = self.root / "origin-link.json"
        link.symlink_to(real)
        with self.assertRaises(SMOKE.SmokeError):
            SMOKE.secure_read(str(link), SMOKE.MAX_ORIGIN_BYTES)
        directory_link = self.root / "directory-link"
        directory_link.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(SMOKE.SmokeError):
            SMOKE.secure_read(str(directory_link / "origin.json"), SMOKE.MAX_ORIGIN_BYTES)

    def test_group_or_other_writable_ancestor_is_rejected(self) -> None:
        self.root.chmod(0o770)
        try:
            with self.assertRaises(SMOKE.SmokeError):
                SMOKE.secure_read(
                    str(self.paths["origin.json"]), SMOKE.MAX_ORIGIN_BYTES
                )
        finally:
            self.root.chmod(0o700)

    def test_mode_owner_and_hard_link_policy_is_fail_closed(self) -> None:
        path = self.paths["origin.json"]
        path.chmod(0o640)
        with self.assertRaises(SMOKE.SmokeError):
            SMOKE.secure_read(str(path), SMOKE.MAX_ORIGIN_BYTES)

    def test_regular_file_and_current_owner_are_required(self) -> None:
        path = self.paths["origin.json"]
        real_fstat = SMOKE.os.fstat

        def wrong_owner(fd: int) -> object:
            observed = real_fstat(fd)
            if not stat_is_regular(observed.st_mode):
                return observed
            return SimpleNamespace(
                st_dev=observed.st_dev,
                st_ino=observed.st_ino,
                st_mode=observed.st_mode,
                st_uid=observed.st_uid + 1,
                st_nlink=observed.st_nlink,
                st_size=observed.st_size,
                st_mtime_ns=observed.st_mtime_ns,
                st_ctime_ns=observed.st_ctime_ns,
            )

        with mock.patch.object(SMOKE.os, "fstat", side_effect=wrong_owner):
            with self.assertRaises(SMOKE.SmokeError):
                SMOKE.secure_read(str(path), SMOKE.MAX_ORIGIN_BYTES)
        directory = self.root / "evidence-directory"
        directory.mkdir(mode=0o600)
        with self.assertRaises(SMOKE.SmokeError):
            SMOKE.secure_read(str(directory), SMOKE.MAX_ORIGIN_BYTES)
        path.chmod(0o600)
        hard_link = self.root / "origin-hard.json"
        os.link(path, hard_link)
        with self.assertRaises(SMOKE.SmokeError):
            SMOKE.secure_read(str(path), SMOKE.MAX_ORIGIN_BYTES)

    def test_noncanonical_relative_and_duplicate_json_inputs_are_rejected(self) -> None:
        with self.assertRaises(SMOKE.SmokeError):
            SMOKE.secure_read("origin.json", SMOKE.MAX_ORIGIN_BYTES)
        with self.assertRaises(SMOKE.SmokeError):
            SMOKE.secure_read(
                "/" + str(self.paths["origin.json"]), SMOKE.MAX_ORIGIN_BYTES
            )
        path = self.paths["origin.json"]
        path.write_bytes(b'{"origin":"https://control.example","origin":"https://other","schema_version":1}\n')
        path.chmod(0o600)
        with self.assertRaises(SMOKE.SmokeError):
            SMOKE.decode_canonical_json(path.read_bytes())
        with self.assertRaises(SMOKE.SmokeError):
            SMOKE.decode_canonical_json(b'{"value":123456789012345678901}\n')
        with self.assertRaises(SMOKE.SmokeError):
            SMOKE.decode_canonical_json(b'{"value":1.5}\n')

    def test_read_time_metadata_change_is_rejected(self) -> None:
        real_fstat = SMOKE.os.fstat
        regular_calls = 0

        def changing_fstat(fd: int) -> object:
            nonlocal regular_calls
            observed = real_fstat(fd)
            if stat_is_regular(observed.st_mode):
                regular_calls += 1
                if regular_calls == 2:
                    values = {
                        name: getattr(observed, name)
                        for name in (
                            "st_dev", "st_ino", "st_mode", "st_uid", "st_nlink",
                            "st_size", "st_mtime_ns", "st_ctime_ns"
                        )
                    }
                    values["st_ctime_ns"] += 1
                    return SimpleNamespace(**values)
            return observed

        with mock.patch.object(SMOKE.os, "fstat", side_effect=changing_fstat):
            with self.assertRaises(SMOKE.SmokeError):
                SMOKE.secure_read(str(self.paths["origin.json"]), SMOKE.MAX_ORIGIN_BYTES)

    def test_parent_substitution_during_read_is_rejected(self) -> None:
        real_fstat = SMOKE.os.fstat
        target_parent = os.stat(self.root, follow_symlinks=False)
        parent_observations = 0

        def substituting_fstat(fd: int) -> object:
            nonlocal parent_observations
            observed = real_fstat(fd)
            if (
                observed.st_dev == target_parent.st_dev
                and observed.st_ino == target_parent.st_ino
            ):
                parent_observations += 1
                if parent_observations == 2:
                    values = {
                        name: getattr(observed, name)
                        for name in (
                            "st_dev", "st_ino", "st_mode", "st_uid", "st_nlink",
                            "st_size", "st_mtime_ns", "st_ctime_ns"
                        )
                    }
                    values["st_ino"] += 1
                    return SimpleNamespace(**values)
            return observed

        with mock.patch.object(SMOKE.os, "fstat", side_effect=substituting_fstat):
            with self.assertRaises(SMOKE.SmokeError):
                SMOKE.secure_read(
                    str(self.paths["origin.json"]), SMOKE.MAX_ORIGIN_BYTES
                )

    def test_direct_transport_ignores_proxy_environment(self) -> None:
        connection = mock.Mock()
        raw_response = mock.Mock()
        raw_response.status = 200
        raw_response.getheaders.return_value = []
        raw_response.read.return_value = b"{}"
        connection.getresponse.return_value = raw_response
        with mock.patch.dict(
            os.environ,
            {"HTTPS_PROXY": "http://proxy.invalid", "https_proxy": "http://other.invalid"},
        ), mock.patch.object(
            SMOKE.http.client, "HTTPSConnection", return_value=connection
        ) as constructor:
            client = SMOKE.DirectHTTPSClient(
                SMOKE.Origin("control.example", 443, "control.example", "https://control.example")
            )
            client.get("/fixed")
        constructor.assert_called_once()
        self.assertEqual(constructor.call_args.args[:2], ("control.example", 443))
        context = constructor.call_args.kwargs["context"]
        self.assertIsNone(context.keylog_filename)
        self.assertGreaterEqual(context.minimum_version, SMOKE.ssl.TLSVersion.TLSv1_2)
        request_headers = connection.request.call_args.kwargs["headers"]
        self.assertNotIn("Proxy-Authorization", request_headers)
        self.assertNotIn("Authorization", request_headers)
        self.assertNotIn("Cookie", request_headers)

    def test_tls_trust_ignores_ca_environment_overrides(self) -> None:
        with mock.patch.dict(
            os.environ,
            {
                "SSL_CERT_DIR": str(self.root / "attacker-certs"),
                "SSL_CERT_FILE": str(self.root / "attacker.pem"),
            },
        ):
            client = SMOKE.DirectHTTPSClient(
                SMOKE.Origin(
                    "control.example", 443, "control.example", "https://control.example"
                )
            )
        stats = client.context.cert_store_stats()
        self.assertGreater(stats["x509_ca"], 0)

    def test_direct_transport_rejects_oversized_response_without_details(self) -> None:
        connection = mock.Mock()
        raw_response = mock.Mock()
        raw_response.status = 200
        raw_response.getheaders.return_value = []
        raw_response.read.return_value = b"x" * (SMOKE.MAX_RESPONSE_BYTES + 1)
        connection.getresponse.return_value = raw_response
        with mock.patch.object(
            SMOKE.http.client, "HTTPSConnection", return_value=connection
        ):
            client = SMOKE.DirectHTTPSClient(
                SMOKE.Origin(
                    "control.example", 443, "control.example", "https://control.example"
                )
            )
            with self.assertRaisesRegex(SMOKE.SmokeError, "^image-rollout-smoke: failed$"):
                client.get("/fixed")

    def test_request_deadline_bounds_dns_connect_and_response(self) -> None:
        observed: list[tuple[str, float]] = []

        def record_timer(kind: int, seconds: float) -> tuple[float, float]:
            self.assertEqual(kind, SMOKE.signal.ITIMER_REAL)
            observed.append(("timer", seconds))
            return (0.0, 0.0)

        with mock.patch.object(SMOKE.signal, "getitimer", return_value=(0.0, 0.0)), mock.patch.object(
            SMOKE.signal, "signal", return_value=SMOKE.signal.SIG_DFL
        ) as handler, mock.patch.object(
            SMOKE.signal, "setitimer", side_effect=record_timer
        ):
            with SMOKE.RequestDeadline():
                observed.append(("request", 0.0))
        self.assertEqual(
            observed,
            [
                ("timer", SMOKE.REQUEST_TIMEOUT_SECONDS),
                ("request", 0.0),
                ("timer", 0.0),
            ],
        )
        self.assertEqual(handler.call_count, 2)

    def test_existing_process_alarm_fails_closed(self) -> None:
        with mock.patch.object(SMOKE.signal, "getitimer", return_value=(1.0, 0.0)):
            with self.assertRaises(SMOKE.SmokeError):
                with SMOKE.RequestDeadline():
                    self.fail("deadline should not enter with an existing alarm")

    def test_unrelated_secret_environment_does_not_change_result(self) -> None:
        with mock.patch.dict(
            os.environ,
            {
                "PASSWORD": "do-not-use",
                "TOKEN": "do-not-use",
                "USERNAME": "do-not-use",
                "SSLKEYLOGFILE": str(self.root / "must-not-be-created"),
            },
        ):
            result, success = self.execute()
        self.assertTrue(success)
        self.assertFalse((self.root / "must-not-be-created").exists())
        encoded = canonical(result).decode("ascii")
        self.assertNotIn("do-not-use", encoded)

    def test_cli_rejects_unexpected_argv_and_never_accepts_secret_flags(self) -> None:
        command = [
            sys.executable,
            "-I",
            str(SCRIPT),
            "--origin-file",
            str(self.paths["origin.json"]),
            "--challenge",
            str(self.paths["challenge.json"]),
            "--plan",
            str(self.paths["plan.json"]),
            "--baseline",
            str(self.paths["baseline.json"]),
            "--running",
            str(self.paths["running.json"]),
            "--invariants",
            str(self.paths["invariants.json"]),
            "--token",
            "super-private-value",
        ]
        completed = subprocess.run(command, text=True, capture_output=True, check=False)
        self.assertNotEqual(completed.returncode, 0)
        self.assertEqual(completed.stdout, "")
        self.assertEqual(completed.stderr, SMOKE.GENERIC_ERROR + "\n")
        self.assertNotIn("super-private-value", completed.stderr)
        source = SCRIPT.read_text(encoding="ascii").lower()
        self.assertNotIn('add_argument("--token', source)
        self.assertNotIn('add_argument("--password', source)
        self.assertNotIn('add_argument("--username', source)
        self.assertNotIn('add_argument("--output', source)
        duplicate = command[:-2] + ["--invariants", str(self.paths["invariants.json"])]
        completed = subprocess.run(duplicate, text=True, capture_output=True, check=False)
        self.assertNotEqual(completed.returncode, 0)
        self.assertEqual(completed.stdout, "")
        self.assertEqual(completed.stderr, SMOKE.GENERIC_ERROR + "\n")

    def test_unexpected_internal_exception_is_also_generic(self) -> None:
        with mock.patch.object(SMOKE, "parse_args", side_effect=RuntimeError("private")):
            stderr = mock.Mock()
            with mock.patch.object(SMOKE.sys, "stderr", stderr):
                self.assertEqual(SMOKE.main([]), 1)
        stderr.write.assert_any_call(SMOKE.GENERIC_ERROR)
        for call in stderr.write.call_args_list:
            self.assertNotIn("private", str(call))

    def test_cli_success_stdout_is_one_canonical_object_and_stderr_empty(self) -> None:
        with mock.patch.object(SMOKE, "execute", return_value=({"a": 1}, True)):
            stdout = mock.Mock()
            stdout.buffer = mock.Mock()
            with mock.patch.object(SMOKE.sys, "stdout", stdout), mock.patch.object(
                SMOKE, "parse_args", return_value=self.args()
            ):
                self.assertEqual(SMOKE.main([]), 0)
            stdout.buffer.write.assert_called_once_with(b'{"a":1}\n')

    def test_execute_has_no_high_level_file_write_path(self) -> None:
        real_open = builtins.open

        def reject_write(file: object, mode: str = "r", *args: object, **kwargs: object) -> object:
            if any(marker in mode for marker in ("w", "a", "x", "+")):
                self.fail("smoke execution attempted a file write")
            return real_open(file, mode, *args, **kwargs)

        with mock.patch.object(builtins, "open", side_effect=reject_write):
            _result, success = self.execute()
        self.assertTrue(success)


def stat_is_regular(mode: int) -> bool:
    import stat

    return stat.S_ISREG(mode)


if __name__ == "__main__":
    unittest.main()
