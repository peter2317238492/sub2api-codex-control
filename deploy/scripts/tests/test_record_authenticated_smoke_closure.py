from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import stat
import subprocess
import sys
import tempfile
import threading
import unittest
from contextlib import redirect_stdout
from email.message import Message
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import jsonschema

REPO_ROOT = Path(__file__).resolve().parents[3]
SCRIPT = REPO_ROOT / "deploy/scripts/record-authenticated-smoke-closure.py"
SCHEMA = REPO_ROOT / "deploy/schemas/authenticated-smoke-closure.schema.json"
SMOKE_SCRIPT = REPO_ROOT / "tests/e2e/smoke.py"


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


CLOSURE = load_module("record_authenticated_smoke_closure", SCRIPT)
SMOKE = load_module("authenticated_smoke_producer", SMOKE_SCRIPT)


def sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def write_private(path: Path, content: bytes) -> None:
    path.write_bytes(content)
    path.chmod(0o600)


def response(status: int, body: object = b"", headers: dict[str, str] | None = None):
    message = Message()
    for name, value in (headers or {}).items():
        message[name] = value
    encoded = (
        body
        if isinstance(body, bytes)
        else json.dumps(body, separators=(",", ":")).encode()
    )
    return SMOKE.Result(status, message, encoded)


class FakeStream:
    def close(self) -> None:
        return None


class RealCatalogSmoke(SMOKE.Smoke):
    """Run the real producer catalog with deterministic HTTP/WebSocket transport."""

    def __init__(self) -> None:
        super().__init__(
            "https://control.example.com",
            False,
            True,
            None,
            closure_catalog_required=True,
        )
        self.authenticated = False
        self.cookies = [
            SimpleNamespace(name="__Host-codex_control", value="session"),
            SimpleNamespace(name="codex_csrf", value="csrf"),
        ]

    @staticmethod
    def security_headers(*, html: bool = False) -> dict[str, str]:
        headers = {
            "Cache-Control": "no-store",
            "Content-Security-Policy": (
                "default-src 'none'; connect-src 'self'; frame-ancestors 'none'; "
                "script-src 'self'; style-src 'self'; worker-src 'self'"
            ),
            "Cross-Origin-Opener-Policy": "same-origin",
            "Cross-Origin-Resource-Policy": "same-origin",
            "Permissions-Policy": "geolocation=()",
            "Pragma": "no-cache",
            "Referrer-Policy": "no-referrer",
            "Strict-Transport-Security": "max-age=31536000",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
        }
        if html:
            headers["Content-Type"] = "text/html"
            headers.pop("Cache-Control")
            headers.pop("Pragma")
        return headers

    def request(
        self,
        path: str,
        *,
        method: str = "GET",
        body: object | None = None,
        headers: dict[str, str] | None = None,
    ):
        headers = headers or {}
        if path == "/codex/":
            return response(200, b"<!doctype html>", self.security_headers(html=True))
        if path == "/codex/manifest.webmanifest":
            return response(
                200,
                {
                    "scope": "/codex/",
                    "start_url": "/codex/",
                    "icons": [
                        {"sizes": "192x192", "type": "image/png"},
                        {"sizes": "512x512", "type": "image/png"},
                    ],
                },
            )
        if path == "/codex/sw.js":
            return response(
                200,
                b"worker",
                {"Service-Worker-Allowed": "/codex/", "Cache-Control": "no-cache"},
            )
        if path == "/codex-api/v1/health/live":
            return response(200, {"status": "ok"})
        if path == "/codex-api/v1/health/ready":
            return response(
                200,
                {"checks": {"database": "ok", "redis": "ok", "contract": "ok"}},
                self.security_headers(),
            )
        if path == "/codex-api/v1/session/exchange":
            if headers.get("Origin") == "https://evil.example":
                return response(403)
            token = body if False else None
            del token
            if method == "OPTIONS":
                return response(403)
            if body == {"access_token": "invalid-access-token-value"}:
                return response(401, b"rejected")
            self.authenticated = True
            return response(
                201,
                b"accepted",
                {
                    "Set-Cookie": "__Host-codex_control=session; HttpOnly; SameSite=Strict; Secure"
                },
            )
        if path == "/codex-api/v1/session/logout":
            if "x-csrf-token" not in {name.lower() for name in headers}:
                return response(403)
            self.authenticated = False
            return response(204)
        if path == "/codex-api/v1/session":
            if self.authenticated:
                return response(
                    200,
                    {
                        "user": {"id": "fixture-user"},
                        "csrf_header_name": "x-csrf-token",
                    },
                )
            return response(401)
        if path in {"/codex-ws/browser", "/codex-ws/device"}:
            return response(400)
        if path in {"/codex-ws/raw-rpc", "/codex-api/internal/metrics"}:
            return response(404)
        if path.startswith("/codex-api/v1/"):
            return response(404 if self.authenticated else 401)
        raise AssertionError("fake transport received an unexpected route")

    def open_websocket(self, path: str, *, origin: str, cookie: str):
        del path, origin, cookie
        return 101, {"upgrade": "websocket"}, FakeStream()


def real_producer_output(challenge: Path) -> bytes:
    parsed = SMOKE.read_closure_challenge(challenge)
    smoke = RealCatalogSmoke()
    with redirect_stdout(io.StringIO()) as output:
        smoke.run("short-lived-token", expected_user_id="fixture-user")
        smoke.validate_closure_catalog()
    return (
        output.getvalue()
        + f"1..84 # closure-challenge-sha256={parsed.challenge_sha256} "
        + f"target-binding-sha256={parsed.target_binding_sha256}\n"
    ).encode()


class ClosureFixture:
    def __init__(self, root: Path, *, deployment_id: str | None = None) -> None:
        self.deployment_id = deployment_id or "12345678-1234-4123-8123-123456789abc"
        self.deployment = root / f"bootstrap-20260812T000000Z-{self.deployment_id}"
        self.deployment.mkdir(mode=0o700)
        self.original_smoke = self.deployment / "production-smoke.txt"
        self.plan = self.deployment / "plan.json"
        self.images = self.deployment / "images.json"
        self.running = self.deployment / "running-containers.json"
        write_private(
            self.original_smoke, b'{"result":"passed","mode":"unauthenticated"}\n'
        )
        api_image = "sha256:" + "1" * 64
        pwa_image = "sha256:" + "2" * 64
        backup_image = "sha256:" + "3" * 64
        self.public_origin = "https://control.example.com"
        plan_value = {
            "format_version": 1,
            "status": "admitted",
            "public_origin": self.public_origin,
            "release": "0.1.0",
            "source_revision": "a" * 64,
            "api_image": api_image,
            "pwa_image": pwa_image,
            "backup_image": backup_image,
        }
        images_value = {
            "format_version": 1,
            "status": "admitted",
            "release": "0.1.0",
            "source_revision": "a" * 64,
            "api": {"image_id": api_image, "source": "sub2api-codex-control"},
            "pwa": {"image_id": pwa_image, "source": "sub2api-codex-control"},
            "backup": {
                "image_id": backup_image,
                "source": "sub2api-codex-control",
            },
        }
        running_value = {
            "format_version": 1,
            "status": "admitted",
            "verified_at": "2026-08-12T00:00:00Z",
            "containers": {
                "control-api": {"container_id": "4" * 64, "image_id": api_image},
                "control-api-replica": {
                    "container_id": "5" * 64,
                    "image_id": api_image,
                },
                "codex-pwa": {"container_id": "6" * 64, "image_id": pwa_image},
            },
            "pwa_network": {"container_id": "6" * 64},
        }
        write_private(self.plan, CLOSURE.canonical_json(plan_value) + b"\n")
        write_private(self.images, CLOSURE.canonical_json(images_value) + b"\n")
        write_private(self.running, CLOSURE.canonical_json(running_value) + b"\n")
        self.descriptors = {
            "compose_plan": self.descriptor(self.plan),
            "local_images": self.descriptor(self.images),
            "running_containers": self.descriptor(self.running),
            "production_smoke": self.descriptor(self.original_smoke),
        }
        admission = {
            "admission_binding_sha256": "a" * 64,
            "admission_mode": "fresh-backup-v1",
            "fresh": True,
            "manifest_sha256": "b" * 64,
            "snapshot_directory": "/secure/backups/production-preflight-fixture",
            "stale_exception": None,
        }
        self.record_value = {
            "format_version": 1,
            "status": "bootstrapped-unsigned",
            "trust_mode": "unsigned-first-deployment-v1",
            "recorded_at": "2026-08-12T00:00:00Z",
            "signed_release_verified": False,
            "authenticated_smoke_pending": True,
            "bootstrap_exceptions": {
                "sub2api_public_connect": False,
                "unauthenticated_smoke": True,
                "stale_production_backup": False,
            },
            "production_backup_admissions": {
                "initial": admission,
                "before_migration": dict(admission),
                "after_bootstrap": dict(admission),
            },
            "verified_evidence": self.descriptors,
            "normal_signed_deployment_required_for_next_release": True,
        }
        self.bootstrap = self.deployment / "bootstrap-deployment.json"
        self.write_record()
        self.external = root / "external"
        self.external.mkdir(mode=0o700)
        self.smoke = self.external / "producer-output.log"
        self.challenge = CLOSURE.prepare_challenge(self.bootstrap)
        write_private(self.smoke, real_producer_output(self.challenge))

    @staticmethod
    def descriptor(path: Path) -> dict[str, object]:
        content = path.read_bytes()
        return {"path": str(path), "sha256": sha256(content), "size": len(content)}

    def smoke_content(self, challenge: Path | None = None) -> bytes:
        return real_producer_output(challenge or self.challenge)

    def write_record(self, *, raw: bytes | None = None) -> None:
        content = (
            CLOSURE.canonical_json(self.record_value) + b"\n" if raw is None else raw
        )
        write_private(self.bootstrap, content)


class AuthenticatedSmokeClosureTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(dir=REPO_ROOT)
        self.root = Path(self.temporary.name)
        self.root.chmod(0o700)
        self.fixture = ClosureFixture(self.root)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_imports_evidence_byte_for_byte_and_records_only_relative_basename(
        self,
    ) -> None:
        before = self.fixture.bootstrap.read_bytes()
        before_stat = self.fixture.bootstrap.stat()
        target = CLOSURE.record_closure(self.fixture.bootstrap, self.fixture.smoke)

        self.assertEqual(self.fixture.bootstrap.read_bytes(), before)
        after_stat = self.fixture.bootstrap.stat()
        self.assertEqual(
            (after_stat.st_dev, after_stat.st_ino),
            (before_stat.st_dev, before_stat.st_ino),
        )
        self.assertEqual(after_stat.st_mtime_ns, before_stat.st_mtime_ns)
        imported_smoke = self.fixture.deployment / CLOSURE.SMOKE_EVIDENCE_FILENAME
        self.assertEqual(imported_smoke.read_bytes(), self.fixture.smoke.read_bytes())
        for path in (
            target,
            imported_smoke,
            self.fixture.challenge,
        ):
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(path.stat().st_nlink, 1)

        closure = json.loads(target.read_text(encoding="ascii"))
        smoke_evidence = closure["authenticated_smoke"]["evidence"]
        self.assertEqual(smoke_evidence["basename"], CLOSURE.SMOKE_EVIDENCE_FILENAME)
        self.assertEqual(
            smoke_evidence["sha256"], sha256(self.fixture.smoke.read_bytes())
        )
        self.assertEqual(smoke_evidence["size"], len(self.fixture.smoke.read_bytes()))
        self.assertIsNone(closure["revocation_observation"])
        encoded = target.read_bytes()
        self.assertNotIn(str(self.fixture.smoke).encode(), encoded)
        self.assertNotIn(str(self.fixture.deployment).encode(), encoded)
        self.assertNotIn(
            json.loads(self.fixture.challenge.read_text())["nonce"].encode(), encoded
        )

    def test_binds_bootstrap_record_deployment_and_nonce_hash(self) -> None:
        target = CLOSURE.record_closure(self.fixture.bootstrap, self.fixture.smoke)
        closure = json.loads(target.read_text())
        challenge = json.loads(self.fixture.challenge.read_text())
        binding = closure["closure_challenge"]
        self.assertEqual(binding["deployment_id"], self.fixture.deployment_id)
        self.assertEqual(binding["deployment_basename"], self.fixture.deployment.name)
        self.assertEqual(
            binding["bootstrap_record_sha256"],
            sha256(self.fixture.bootstrap.read_bytes()),
        )
        self.assertEqual(binding["nonce_sha256"], sha256(challenge["nonce"].encode()))
        self.assertNotEqual(binding["nonce_sha256"], challenge["nonce"])

    def test_real_smoke_producer_emits_bound_tap_plan(self) -> None:
        output = real_producer_output(self.fixture.challenge)
        parsed = SMOKE.read_closure_challenge(self.fixture.challenge)
        self.assertEqual(len(output.decode().splitlines()), 85)
        self.assertTrue(
            output.endswith(
                (
                    f"1..84 # closure-challenge-sha256={parsed.challenge_sha256} "
                    f"target-binding-sha256={parsed.target_binding_sha256}\n"
                ).encode()
            )
        )
        result = CLOSURE.parse_smoke_log(
            output, parsed.challenge_sha256, parsed.target_binding_sha256
        )
        self.assertEqual(result["checks_passed"], 84)

    def test_real_smoke_producer_rejects_challenge_ancestor_symlink(self) -> None:
        alias = self.root / "deployment-alias"
        alias.symlink_to(self.fixture.deployment, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "symlink ancestor"):
            SMOKE.read_closure_challenge_sha256(alias / self.fixture.challenge.name)

    def test_real_smoke_producer_catalog_drift_is_rejected(self) -> None:
        output = real_producer_output(self.fixture.challenge)
        changed = output.replace(
            b"ok 42 - API emits exactly one X-Content-Type-Options header",
            b"ok 42 - producer description drift",
        )
        parsed = SMOKE.read_closure_challenge(self.fixture.challenge)
        with self.assertRaisesRegex(CLOSURE.ClosureError, "catalog differs"):
            CLOSURE.parse_smoke_log(
                changed, parsed.challenge_sha256, parsed.target_binding_sha256
            )

    def test_real_producer_format_is_accepted_without_custom_status_line(self) -> None:
        result = CLOSURE.parse_smoke_log(
            self.fixture.smoke.read_bytes(),
            sha256(self.fixture.challenge.read_bytes()),
            json.loads(self.fixture.challenge.read_text())["target"]["binding_sha256"],
        )
        self.assertEqual(result["checks_passed"], 84)
        self.assertTrue(result["tap_plan_observed"])
        self.assertNotIn(b"authenticated_smoke_status", self.fixture.smoke.read_bytes())

    def test_rejects_unbound_failed_duplicate_missing_extra_and_wrong_catalog(
        self,
    ) -> None:
        good = self.fixture.smoke_content().decode()
        cases = {
            "unbound": good.rsplit("\n", 2)[0] + "\n1..84\n",
            "failed": good.replace("ok 42 -", "not ok 42 -", 1),
            "duplicate": good.replace("ok 42 -", "ok 41 -", 1),
            "missing": good.replace(
                f"ok 42 - {CLOSURE.EXPECTED_CHECK_DESCRIPTIONS[41]}\n", "", 1
            ),
            "extra": good.replace("1..84", "HTTP status=502\n1..84", 1),
            "catalog": good.replace(
                "ok 1 - PWA shell is reachable at /codex/",
                "ok 1 - arbitrary successful-looking check",
            ),
        }
        for name, content in cases.items():
            with self.subTest(name=name):
                write_private(self.fixture.smoke, content.encode())
                with self.assertRaises(CLOSURE.ClosureError):
                    CLOSURE.record_closure(self.fixture.bootstrap, self.fixture.smoke)
                self.assertFalse(
                    (self.fixture.deployment / CLOSURE.CLOSURE_FILENAME).exists()
                )
                self.assertFalse(
                    (self.fixture.deployment / CLOSURE.SMOKE_EVIDENCE_FILENAME).exists()
                )

    def test_cross_deployment_replay_is_rejected(self) -> None:
        second_root = self.root / "second"
        second_root.mkdir(mode=0o700)
        second = ClosureFixture(
            second_root, deployment_id="87654321-4321-4321-8321-cba987654321"
        )
        replay = second.external / "replayed.log"
        write_private(replay, self.fixture.smoke.read_bytes())
        with self.assertRaisesRegex(
            CLOSURE.ClosureError, "different closure challenge"
        ):
            CLOSURE.record_closure(second.bootstrap, replay)

    def test_challenge_replay_after_bootstrap_mutation_is_rejected(self) -> None:
        challenge = self.fixture.challenge.read_bytes()
        self.fixture.record_value["recorded_at"] = "2026-08-12T00:00:01Z"
        self.fixture.write_record()
        self.assertEqual(self.fixture.challenge.read_bytes(), challenge)
        with self.assertRaisesRegex(CLOSURE.ClosureError, "different bootstrap record"):
            CLOSURE.record_closure(self.fixture.bootstrap, self.fixture.smoke)

    def test_challenge_deployment_id_and_nonce_tamper_are_rejected(self) -> None:
        original = json.loads(self.fixture.challenge.read_text())
        original_smoke = self.fixture.smoke.read_bytes()
        cases = {
            "deployment ID": {
                **original,
                "deployment_id": "87654321-4321-4321-8321-cba987654321",
            },
            "nonce": {**original, "nonce": "not-a-valid-nonce"},
        }
        for message, value in cases.items():
            with self.subTest(message=message):
                write_private(
                    self.fixture.challenge,
                    CLOSURE.canonical_json(value) + b"\n",
                )
                write_private(self.fixture.smoke, original_smoke)
                with self.assertRaisesRegex(CLOSURE.ClosureError, message):
                    CLOSURE.record_closure(self.fixture.bootstrap, self.fixture.smoke)
                write_private(
                    self.fixture.challenge,
                    CLOSURE.canonical_json(original) + b"\n",
                )

    def test_rejects_dotdot_noncanonical_and_ancestor_symlink_paths(self) -> None:
        noncanonical = Path(
            str(
                self.fixture.bootstrap.parent
                / ".."
                / self.fixture.deployment.name
                / self.fixture.bootstrap.name
            )
        )
        with self.assertRaisesRegex(CLOSURE.ClosureError, "canonical"):
            CLOSURE.prepare_challenge(noncanonical)
        with self.assertRaisesRegex(CLOSURE.ClosureError, "canonical"):
            CLOSURE.prepare_challenge(
                Path("//") / self.fixture.bootstrap.relative_to("/")
            )

        symlink_root = self.root / "alias"
        symlink_root.symlink_to(
            self.fixture.deployment.parent, target_is_directory=True
        )
        aliased_bootstrap = (
            symlink_root / self.fixture.deployment.name / self.fixture.bootstrap.name
        )
        with self.assertRaisesRegex(CLOSURE.ClosureError, "symlink ancestor"):
            CLOSURE.record_closure(aliased_bootstrap, self.fixture.smoke)

    def test_rejects_external_evidence_with_symlink_ancestor(self) -> None:
        alias = self.root / "external-alias"
        alias.symlink_to(self.fixture.external, target_is_directory=True)
        with self.assertRaisesRegex(CLOSURE.ClosureError, "symlink ancestor"):
            CLOSURE.record_closure(
                self.fixture.bootstrap, alias / self.fixture.smoke.name
            )

    def test_challenge_closure_and_imports_are_noreplace(self) -> None:
        with self.assertRaisesRegex(CLOSURE.ClosureError, "already exists"):
            CLOSURE.prepare_challenge(self.fixture.bootstrap)
        target = CLOSURE.record_closure(self.fixture.bootstrap, self.fixture.smoke)
        first = target.read_bytes()
        with self.assertRaises(CLOSURE.ClosureError):
            CLOSURE.record_closure(self.fixture.bootstrap, self.fixture.smoke)
        self.assertEqual(target.read_bytes(), first)

    def test_existing_challenge_symlink_conflict_is_never_replaced(self) -> None:
        self.fixture.challenge.unlink()
        sentinel = self.root / "challenge-sentinel"
        write_private(sentinel, b"challenge sentinel\n")
        self.fixture.challenge.symlink_to(sentinel)
        with self.assertRaisesRegex(CLOSURE.ClosureError, "already exists"):
            CLOSURE.prepare_challenge(self.fixture.bootstrap)
        self.assertTrue(self.fixture.challenge.is_symlink())
        self.assertEqual(sentinel.read_bytes(), b"challenge sentinel\n")

    def test_existing_symlink_conflict_is_never_followed_or_replaced(self) -> None:
        sentinel = self.root / "sentinel"
        write_private(sentinel, b"sentinel\n")
        target = self.fixture.deployment / CLOSURE.SMOKE_EVIDENCE_FILENAME
        target.symlink_to(sentinel)
        with self.assertRaisesRegex(CLOSURE.ClosureError, "without following links"):
            CLOSURE.record_closure(self.fixture.bootstrap, self.fixture.smoke)
        self.assertTrue(target.is_symlink())
        self.assertEqual(sentinel.read_bytes(), b"sentinel\n")

    def test_existing_closure_symlink_conflict_is_never_replaced(self) -> None:
        sentinel = self.root / "closure-sentinel"
        write_private(sentinel, b"closure sentinel\n")
        target = self.fixture.deployment / CLOSURE.CLOSURE_FILENAME
        target.symlink_to(sentinel)
        with self.assertRaisesRegex(CLOSURE.ClosureError, "already exists"):
            CLOSURE.record_closure(self.fixture.bootstrap, self.fixture.smoke)
        self.assertTrue(target.is_symlink())
        self.assertEqual(sentinel.read_bytes(), b"closure sentinel\n")
        self.assertFalse(
            (self.fixture.deployment / CLOSURE.SMOKE_EVIDENCE_FILENAME).exists()
        )

    def test_missing_atomic_noreplace_primitive_fails_without_publication(self) -> None:
        with (
            mock.patch.object(
                CLOSURE,
                "atomic_rename_noreplace",
                side_effect=CLOSURE.ClosureError("unsupported primitive"),
            ),
            self.assertRaisesRegex(CLOSURE.ClosureError, "unsupported primitive"),
        ):
            CLOSURE.record_closure(self.fixture.bootstrap, self.fixture.smoke)
        self.assertFalse(
            (self.fixture.deployment / CLOSURE.SMOKE_EVIDENCE_FILENAME).exists()
        )
        self.assertFalse((self.fixture.deployment / CLOSURE.CLOSURE_FILENAME).exists())
        self.assertEqual(
            list(self.fixture.deployment.glob(".authenticated-smoke.log.tmp-*")), []
        )

    def test_failure_after_import_preserves_exact_siblings_for_resume(self) -> None:
        with (
            mock.patch.object(
                CLOSURE, "build_closure", side_effect=CLOSURE.ClosureError("injected")
            ),
            self.assertRaisesRegex(CLOSURE.ClosureError, "injected"),
        ):
            CLOSURE.record_closure(self.fixture.bootstrap, self.fixture.smoke)
        self.assertTrue(
            (self.fixture.deployment / CLOSURE.SMOKE_EVIDENCE_FILENAME).exists()
        )
        self.assertTrue(self.fixture.challenge.exists())
        target = CLOSURE.record_closure(self.fixture.bootstrap, self.fixture.smoke)
        self.assertTrue(target.exists())

    def test_sigkill_after_smoke_publish_and_before_closure_resumes(self) -> None:
        child = r"""
import importlib.util
import os
import signal
import sys

spec = importlib.util.spec_from_file_location("closure_crash_child", sys.argv[1])
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)
point = sys.argv[4]
real_import = module.import_evidence_noreplace
real_rename = module.atomic_rename_noreplace

def crash_after_rename(directory_descriptor, source, destination):
    real_rename(directory_descriptor, source, destination)
    if point == "rename-smoke" and destination == module.SMOKE_EVIDENCE_FILENAME:
        os.kill(os.getpid(), signal.SIGKILL)

def crash_import(*args, **kwargs):
    value = real_import(*args, **kwargs)
    if point == "smoke":
        os.kill(os.getpid(), signal.SIGKILL)
    return value

real_build = module.build_closure
def crash_build(*args, **kwargs):
    value = real_build(*args, **kwargs)
    if point == "before-closure":
        os.kill(os.getpid(), signal.SIGKILL)
    return value

module.atomic_rename_noreplace = crash_after_rename
module.import_evidence_noreplace = crash_import
module.build_closure = crash_build
module.record_closure(sys.argv[2], sys.argv[3])
"""
        for point in ("rename-smoke", "smoke", "before-closure"):
            with self.subTest(point=point):
                case_root = self.root / point
                case_root.mkdir(mode=0o700)
                fixture = ClosureFixture(case_root)
                result = subprocess.run(
                    [
                        sys.executable,
                        "-c",
                        child,
                        str(SCRIPT),
                        str(fixture.bootstrap),
                        str(fixture.smoke),
                        point,
                    ],
                    check=False,
                    capture_output=True,
                )
                self.assertEqual(result.returncode, -9)
                smoke_target = fixture.deployment / CLOSURE.SMOKE_EVIDENCE_FILENAME
                self.assertEqual(smoke_target.read_bytes(), fixture.smoke.read_bytes())
                self.assertEqual(smoke_target.stat().st_nlink, 1)
                self.assertFalse(
                    (fixture.deployment / CLOSURE.CLOSURE_FILENAME).exists()
                )
                smoke_inode = smoke_target.stat().st_ino
                target = CLOSURE.record_closure(fixture.bootstrap, fixture.smoke)
                self.assertTrue(target.exists())
                self.assertEqual(smoke_target.stat().st_ino, smoke_inode)

    def test_existing_fixed_sibling_conflict_fails_without_overwrite(self) -> None:
        target = self.fixture.deployment / CLOSURE.SMOKE_EVIDENCE_FILENAME
        write_private(target, b"conflicting durable sibling\n")
        before = target.read_bytes()
        with self.assertRaisesRegex(CLOSURE.ClosureError, "conflicts"):
            CLOSURE.record_closure(self.fixture.bootstrap, self.fixture.smoke)
        self.assertEqual(target.read_bytes(), before)
        self.assertFalse((self.fixture.deployment / CLOSURE.CLOSURE_FILENAME).exists())

    def test_revocation_input_and_fixed_sibling_are_always_rejected(self) -> None:
        observation = self.fixture.external / "revocation-output.log"
        write_private(observation, b"operator-authored diagnostic only\n")
        with self.assertRaisesRegex(CLOSURE.ClosureError, "unsupported"):
            CLOSURE.record_closure(
                self.fixture.bootstrap, self.fixture.smoke, observation
            )
        self.assertFalse(
            (self.fixture.deployment / CLOSURE.SMOKE_EVIDENCE_FILENAME).exists()
        )

        sibling = self.fixture.deployment / CLOSURE.REVOCATION_EVIDENCE_FILENAME
        write_private(sibling, b"pre-existing diagnostic\n")
        before = sibling.read_bytes()
        with self.assertRaisesRegex(CLOSURE.ClosureError, "already exists"):
            CLOSURE.record_closure(self.fixture.bootstrap, self.fixture.smoke)
        self.assertEqual(sibling.read_bytes(), before)
        self.assertFalse(
            (self.fixture.deployment / CLOSURE.SMOKE_EVIDENCE_FILENAME).exists()
        )

    def test_failure_cleanup_does_not_unlink_replacement_inode(self) -> None:
        original_build = CLOSURE.build_closure
        replacement = b"concurrent replacement must survive\n"

        def replace_then_fail(*args, **kwargs):
            smoke_target = self.fixture.deployment / CLOSURE.SMOKE_EVIDENCE_FILENAME
            smoke_target.unlink()
            write_private(smoke_target, replacement)
            original_build(*args, **kwargs)
            raise CLOSURE.ClosureError("injected after replacement")

        with (
            mock.patch.object(CLOSURE, "build_closure", side_effect=replace_then_fail),
            self.assertRaisesRegex(CLOSURE.ClosureError, "after replacement"),
        ):
            CLOSURE.record_closure(self.fixture.bootstrap, self.fixture.smoke)
        self.assertEqual(
            (self.fixture.deployment / CLOSURE.SMOKE_EVIDENCE_FILENAME).read_bytes(),
            replacement,
        )

    def test_evidence_import_rejects_oversized_source_without_partial_sibling(
        self,
    ) -> None:
        write_private(
            self.fixture.smoke,
            b"x" * (CLOSURE.MAX_SMOKE_LOG_BYTES + 1),
        )
        with self.assertRaisesRegex(CLOSURE.ClosureError, "invalid size"):
            CLOSURE.record_closure(self.fixture.bootstrap, self.fixture.smoke)
        self.assertFalse(
            (self.fixture.deployment / CLOSURE.SMOKE_EVIDENCE_FILENAME).exists()
        )

    def test_external_source_policy_rejects_symlink_mode_and_hardlink(self) -> None:
        for case in ("symlink", "mode", "hardlink"):
            with self.subTest(case=case):
                source = self.fixture.external / f"{case}.log"
                if case == "symlink":
                    source.symlink_to(self.fixture.smoke)
                else:
                    write_private(source, self.fixture.smoke.read_bytes())
                    if case == "mode":
                        source.chmod(0o640)
                    else:
                        CLOSURE.os.link(
                            source, self.fixture.external / "second-link.log"
                        )
                with self.assertRaises(CLOSURE.ClosureError):
                    CLOSURE.record_closure(self.fixture.bootstrap, source)
                self.assertFalse(
                    (self.fixture.deployment / CLOSURE.SMOKE_EVIDENCE_FILENAME).exists()
                )

    def test_import_and_closure_publication_fsync_file_and_directory(self) -> None:
        real_fsync = CLOSURE.os.fsync
        synced_types: list[int] = []

        def observe(descriptor: int) -> None:
            synced_types.append(stat.S_IFMT(CLOSURE.os.fstat(descriptor).st_mode))
            real_fsync(descriptor)

        with mock.patch.object(CLOSURE.os, "fsync", side_effect=observe):
            CLOSURE.record_closure(self.fixture.bootstrap, self.fixture.smoke)
        self.assertGreaterEqual(synced_types.count(stat.S_IFREG), 2)
        self.assertGreaterEqual(synced_types.count(stat.S_IFDIR), 2)

    def test_concurrent_publish_allows_exactly_one_closure(self) -> None:
        results: list[Path] = []
        errors: list[BaseException] = []

        def invoke() -> None:
            try:
                results.append(
                    CLOSURE.record_closure(self.fixture.bootstrap, self.fixture.smoke)
                )
            except CLOSURE.ClosureError as error:
                errors.append(error)

        threads = [threading.Thread(target=invoke) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=5)
        self.assertEqual(len(results), 1)
        self.assertEqual(len(errors), 1)
        self.assertIsInstance(errors[0], CLOSURE.ClosureError)

    def test_schema_and_semantic_verifier_validate_real_closure(self) -> None:
        target = CLOSURE.record_closure(self.fixture.bootstrap, self.fixture.smoke)
        schema = json.loads(SCHEMA.read_text())
        self.assertFalse(schema["additionalProperties"])
        self.assertEqual(schema["properties"]["format_version"]["const"], 2)
        jsonschema.Draft202012Validator.check_schema(schema)
        value = json.loads(target.read_text())
        jsonschema.Draft202012Validator(schema).validate(value)
        directory_descriptor, _ = CLOSURE.open_private_directory(
            self.fixture.deployment
        )
        try:
            CLOSURE.validate_closure_document(
                value, directory_descriptor, self.fixture.deployment
            )
        finally:
            CLOSURE.os.close(directory_descriptor)

    def test_semantic_verifier_rejects_cross_field_tampering(self) -> None:
        target = CLOSURE.record_closure(self.fixture.bootstrap, self.fixture.smoke)
        original = json.loads(target.read_text())
        cases = {}
        bootstrap = json.loads(json.dumps(original))
        bootstrap["closure_challenge"]["bootstrap_record_sha256"] = "9" * 64
        cases["bootstrap SHA"] = bootstrap
        smoke = json.loads(json.dumps(original))
        smoke["authenticated_smoke"]["challenge_sha256"] = "9" * 64
        cases["challenge SHA"] = smoke
        count = json.loads(json.dumps(original))
        count["original_verified_evidence"]["count"] += 1
        cases["evidence count"] = count
        basename = json.loads(json.dumps(original))
        basename["authenticated_smoke"]["evidence"]["basename"] = "other.log"
        cases["fixed evidence basename"] = basename
        catalog = json.loads(json.dumps(original))
        catalog["authenticated_smoke"]["check_catalog_sha256"] = "9" * 64
        cases["catalog digest"] = catalog
        target_digest = json.loads(json.dumps(original))
        target_digest["closure_challenge"]["target"]["binding_sha256"] = "9" * 64
        cases["target binding digest"] = target_digest
        for message, value in cases.items():
            with (
                self.subTest(message=message),
                self.assertRaisesRegex(CLOSURE.ClosureError, message),
            ):
                CLOSURE.validate_closure_structure(value)

    def test_directory_verifier_rejects_self_consistent_target_rewrite(self) -> None:
        target = CLOSURE.record_closure(self.fixture.bootstrap, self.fixture.smoke)
        value = json.loads(target.read_text())
        rewritten = value["closure_challenge"]["target"]
        rewritten["artifact_identity_sha256"] = "9" * 64
        without_digest = {
            key: rewritten[key] for key in sorted(rewritten) if key != "binding_sha256"
        }
        rewritten["binding_sha256"] = sha256(CLOSURE.canonical_json(without_digest))
        value["authenticated_smoke"]["target_binding_sha256"] = rewritten[
            "binding_sha256"
        ]
        CLOSURE.validate_closure_structure(value)
        directory_descriptor, _ = CLOSURE.open_private_directory(
            self.fixture.deployment
        )
        try:
            with self.assertRaisesRegex(CLOSURE.ClosureError, "fixed evidence"):
                CLOSURE.validate_closure_document(
                    value, directory_descriptor, self.fixture.deployment
                )
        finally:
            CLOSURE.os.close(directory_descriptor)

    def test_cli_has_no_token_input_and_prints_only_relative_result(self) -> None:
        arguments = CLOSURE.parse_args(
            [
                "--bootstrap-record",
                str(self.fixture.bootstrap),
                "--smoke-log",
                str(self.fixture.smoke),
            ]
        )
        self.assertEqual(
            set(vars(arguments)),
            {
                "bootstrap_record",
                "prepare_challenge",
                "smoke_log",
            },
        )
        self.assertIsInstance(arguments.bootstrap_record, str)
        self.assertIsInstance(arguments.smoke_log, str)
        with (
            redirect_stdout(io.StringIO()),
            mock.patch("sys.stderr", io.StringIO()),
            self.assertRaises(SystemExit),
        ):
            CLOSURE.parse_args(
                [
                    "--bootstrap-record",
                    str(self.fixture.bootstrap),
                    "--smoke-log",
                    str(self.fixture.smoke),
                    "--revocation-observation",
                    str(self.fixture.external / "diagnostic.log"),
                ]
            )
        with redirect_stdout(io.StringIO()) as output:
            self.assertEqual(
                CLOSURE.main(
                    [
                        "--bootstrap-record",
                        str(self.fixture.bootstrap),
                        "--smoke-log",
                        str(self.fixture.smoke),
                    ]
                ),
                0,
            )
        self.assertEqual(output.getvalue(), CLOSURE.CLOSURE_FILENAME + "\n")

    def test_cli_rejects_noncanonical_path_before_any_write(self) -> None:
        noncanonical = str(
            self.fixture.deployment
            / ".."
            / self.fixture.deployment.name
            / self.fixture.bootstrap.name
        )
        with mock.patch("sys.stderr", io.StringIO()) as stderr:
            self.assertEqual(
                CLOSURE.main(
                    [
                        "--bootstrap-record",
                        noncanonical,
                        "--smoke-log",
                        str(self.fixture.smoke),
                    ]
                ),
                1,
            )
        self.assertIn("canonical and absolute", stderr.getvalue())
        self.assertFalse((self.fixture.deployment / CLOSURE.CLOSURE_FILENAME).exists())

    def test_no_private_source_path_is_printed_on_error(self) -> None:
        secret_source = self.fixture.external / "private-name.log"
        write_private(secret_source, b"not tap\n")
        with (
            redirect_stdout(io.StringIO()) as stdout,
            mock.patch("sys.stderr", io.StringIO()) as stderr,
        ):
            self.assertEqual(
                CLOSURE.main(
                    [
                        "--bootstrap-record",
                        str(self.fixture.bootstrap),
                        "--smoke-log",
                        str(secret_source),
                    ]
                ),
                1,
            )
        self.assertNotIn(str(secret_source), stdout.getvalue() + stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
