from __future__ import annotations

import http.client
import importlib.util
import json
import os
import secrets
import stat
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


collector = load_module("monitoring_collector", ROOT / "collector" / "collector.py")
receiver = load_module("monitoring_receiver", ROOT / "evidence-receiver" / "receiver.py")
derive_bearer = load_module("derive_metrics_bearer", ROOT / "derive-metrics-bearer.py")
proxy = load_module("alertmanager_proxy", ROOT / "alertmanager-proxy.py")
admission = load_module("observability_admission", ROOT / "observability-admission.py")
external_relay = load_module("external_delivery_relay", ROOT / "external-delivery-relay.py")

NONCE = "0123456789abcdef0123456789abcdef"


class CollectorTests(unittest.TestCase):
    def test_empty_directory_does_not_fake_required_green_signals(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            rendered = collector.render_metrics(Path(directory), "1.2.3", "a" * 40, now=time.time())
        for family in (
            "codex_control_connector_up",
            'codex_control_synthetic_probe_success{probe="session_exchange"}',
            "codex_control_external_backup_last_success_timestamp_seconds",
            "codex_control_external_restore_rehearsal_last_success_timestamp_seconds",
        ):
            self.assertNotIn(family, rendered)
        connector_rendered = collector.render_connector_metrics(Path(directory), now=time.time())
        self.assertIn(
            'codex_control_monitoring_evidence_file_valid{source="connector.prom"} 0',
            connector_rendered,
        )

    def test_accepts_only_fresh_owner_only_allowlisted_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "synthetics.prom"
            source.write_text(
                'codex_control_synthetic_probe_success{probe="live"} 1\n',
                encoding="ascii",
            )
            source.chmod(0o600)
            rendered = collector.render_metrics(Path(directory), "1.2.3", "b" * 40)
            self.assertIn('codex_control_synthetic_probe_success{probe="live"} 1', rendered)
            source.chmod(0o644)
            rendered = collector.render_metrics(Path(directory), "1.2.3", "b" * 40)
            self.assertNotIn('codex_control_synthetic_probe_success{probe="live"} 1', rendered)

    def test_rejects_stale_or_unbounded_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "synthetics.prom"
            source.write_text(
                'codex_control_synthetic_probe_success{probe="invented"} 1\n',
                encoding="ascii",
            )
            source.chmod(0o600)
            rendered = collector.render_metrics(Path(directory), "1.2.3", "c" * 40)
            self.assertNotIn('probe="invented"', rendered)
            source.write_text(
                'codex_control_synthetic_probe_success{probe="ready"} 1\n',
                encoding="ascii",
            )
            source.chmod(0o600)
            old = time.time() - 1000
            os.utime(source, (old, old))
            rendered = collector.render_metrics(Path(directory), "1.2.3", "c" * 40)
            self.assertNotIn('probe="ready"', rendered)

    def test_rejects_non_boolean_negative_and_future_timestamp_values(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "synthetics.prom"
            source.write_text(
                'codex_control_synthetic_probe_success{probe="live"} 2\n',
                encoding="ascii",
            )
            source.chmod(0o600)
            rendered = collector.render_metrics(root, "1.2.3", "d" * 40)
            self.assertNotIn('probe="live"', rendered)
            source = root / "backup.prom"
            source.write_text(
                "codex_control_external_backup_last_success_timestamp_seconds 9999999999\n",
                encoding="ascii",
            )
            source.chmod(0o600)
            rendered = collector.render_metrics(root, "1.2.3", "d" * 40, now=1_700_000_000)
            self.assertNotIn("9999999999", rendered)
            source = root / "infrastructure.prom"
            source.write_text(
                "codex_control_external_redis_evicted_keys_total -1\n",
                encoding="ascii",
            )
            source.chmod(0o600)
            rendered = collector.render_metrics(root, "1.2.3", "d" * 40)
            self.assertNotIn("evicted_keys_total -1", rendered)

    def test_expected_identity_rejects_placeholders(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ValueError):
                collector.render_metrics(Path(directory), "unknown", "a" * 40)
            with self.assertRaises(ValueError):
                collector.render_metrics(Path(directory), "replace-with-release", "a" * 40)
            with self.assertRaises(ValueError):
                collector.render_metrics(Path(directory), "1.2.3", "replace-me")


class ReceiverTests(unittest.TestCase):
    def _payload(self, status: str) -> dict:
        return {
            "status": status,
            "alerts": [
                {
                    "status": status,
                    "labels": {
                        "alertname": "CodexControlLocalDeliveryTest",
                        "controlled_nonce": NONCE,
                        "ignored": "not-recorded",
                    },
                    "annotations": {"credential": "not-recorded"},
                    "startsAt": "2026-08-13T00:00:00Z",
                    "endsAt": "2026-08-13T00:01:00Z" if status == "resolved" else "",
                    "fingerprint": "abc123",
                }
            ],
        }

    def test_append_and_verify_firing_resolved_pair(self) -> None:
        test_tmp = os.environ.get("CONTROL_MONITORING_TEST_TMPDIR")
        with tempfile.TemporaryDirectory(dir=test_tmp or ROOT / "tests") as directory:
            evidence = Path(directory) / "delivery.jsonl"
            firing = receiver.normalize_payload(self._payload("firing"))[0]
            resolved = receiver.normalize_payload(self._payload("resolved"))[0]
            firing["received_at"] = "2026-08-13T00:00:30Z"
            resolved["received_at"] = "2026-08-13T00:01:30Z"
            receiver.append_records(evidence, [firing])
            receiver.append_records(evidence, [resolved])
            self.assertEqual(stat.S_IMODE(evidence.stat().st_mode), 0o600)
            lines = evidence.read_text(encoding="ascii").splitlines()
            self.assertEqual(len(lines), 2)
            self.assertNotIn("credential", "\n".join(lines))
            result = json.loads(
                receiver.verify_delivery(evidence, "CodexControlLocalDeliveryTest", NONCE)
            )
            self.assertFalse(result["external_operator_delivery_verified"])
            self.assertEqual(result["fingerprint"], "abc123")
            with self.assertRaises(ValueError):
                receiver.verify_delivery(
                    evidence,
                    "CodexControlLocalDeliveryTest",
                    "f" * 32,
                )

    def test_verify_rejects_unsafe_evidence_and_reversed_time(self) -> None:
        test_tmp = os.environ.get("CONTROL_MONITORING_TEST_TMPDIR")
        with tempfile.TemporaryDirectory(dir=test_tmp or ROOT / "tests") as directory:
            evidence = Path(directory) / "delivery.jsonl"
            firing = receiver.normalize_payload(self._payload("firing"))[0]
            resolved = dict(receiver.normalize_payload(self._payload("resolved"))[0])
            resolved["received_at"] = firing["received_at"]
            receiver.append_records(evidence, [firing, resolved])
            with self.assertRaises(ValueError):
                receiver.verify_delivery(evidence, "CodexControlLocalDeliveryTest", NONCE)

    def test_receiver_post_requires_independent_bearer(self) -> None:
        test_tmp = os.environ.get("CONTROL_MONITORING_TEST_TMPDIR")
        with tempfile.TemporaryDirectory(dir=test_tmp or ROOT / "tests") as directory:
            evidence = Path(directory) / "delivery.jsonl"
            receiver.ReceiverHandler.evidence_file = evidence
            receiver.ReceiverHandler.bearer = "b" * 64
            server = receiver.ThreadingHTTPServer(("127.0.0.1", 0), receiver.ReceiverHandler)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                body = json.dumps(self._payload("firing"))
                connection = http.client.HTTPConnection("127.0.0.1", server.server_port)
                connection.request(
                    "POST",
                    "/v1/alerts",
                    body=body,
                    headers={"Content-Type": "application/json"},
                )
                self.assertEqual(connection.getresponse().status, 401)
                self.assertFalse(evidence.exists())
                connection.close()
                connection = http.client.HTTPConnection("127.0.0.1", server.server_port)
                connection.request(
                    "POST",
                    "/v1/alerts",
                    body=body,
                    headers={
                        "Authorization": f"Bearer {'b' * 64}",
                        "Content-Type": "application/json",
                    },
                )
                self.assertEqual(connection.getresponse().status, 200)
                self.assertTrue(evidence.exists())
                connection.close()
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)
            evidence.chmod(0o644)
            with self.assertRaises(ValueError):
                receiver.verify_delivery(evidence, "CodexControlLocalDeliveryTest", NONCE)


class BearerProvisioningTests(unittest.TestCase):
    def test_derives_directly_to_new_owner_only_file(self) -> None:
        test_tmp = os.environ.get("CONTROL_MONITORING_TEST_TMPDIR")
        with tempfile.TemporaryDirectory(dir=test_tmp or ROOT / "tests") as directory:
            root = Path(directory)
            secret = root / "session-secret"
            output = root / "metrics-bearer"
            secret.write_bytes(b"s" * 32 + b"\n")
            secret.chmod(0o600)
            derive_bearer.derive(secret, output, os.geteuid(), os.getegid())
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
            self.assertEqual(len(output.read_text(encoding="ascii").strip()), 64)
            with self.assertRaises(FileExistsError):
                derive_bearer.derive(secret, output, os.geteuid(), os.getegid())

    def test_domains_are_distinct_and_failure_leaves_no_output(self) -> None:
        test_tmp = os.environ.get("CONTROL_MONITORING_TEST_TMPDIR")
        with tempfile.TemporaryDirectory(dir=test_tmp or ROOT / "tests") as directory:
            root = Path(directory)
            secret = root / "root-secret"
            secret.write_bytes(secrets.token_bytes(32))
            secret.chmod(0o600)
            outputs = []
            for name, domain in derive_bearer.DOMAINS.items():
                output = root / name
                derive_bearer.derive(secret, output, os.geteuid(), os.getegid(), domain)
                outputs.append(output.read_bytes())
            self.assertEqual(len(set(outputs)), len(derive_bearer.DOMAINS))
            bad = root / "bad"
            secret.chmod(0o644)
            with self.assertRaises(ValueError):
                derive_bearer.derive(secret, bad, os.geteuid(), os.getegid())
            self.assertFalse(bad.exists())
            secret.chmod(0o600)
            real_parent = root / "real-parent"
            real_parent.mkdir(mode=0o700)
            linked_parent = root / "linked-parent"
            linked_parent.symlink_to(real_parent, target_is_directory=True)
            linked_output = linked_parent / "bearer"
            with self.assertRaises(ValueError):
                derive_bearer.derive(
                    secret,
                    linked_output,
                    os.geteuid(),
                    os.getegid(),
                )
            self.assertFalse((real_parent / "bearer").exists())

    @unittest.skipUnless(os.geteuid() == 0, "root-only target owner test")
    def test_root_can_provision_into_explicit_target_owned_directory(self) -> None:
        test_tmp = os.environ.get("CONTROL_MONITORING_TEST_TMPDIR")
        with tempfile.TemporaryDirectory(dir=test_tmp or ROOT / "tests") as directory:
            root = Path(directory)
            secret = root / "root-secret"
            target = root / "target"
            secret.write_bytes(secrets.token_bytes(32))
            secret.chmod(0o600)
            target.mkdir(mode=0o700)
            try:
                os.chown(target, 65532, 65532)
            except PermissionError:
                self.skipTest("CAP_CHOWN is intentionally absent")
            output = target / "bearer"
            derive_bearer.derive(secret, output, 65532, 65532)
            self.assertEqual(output.stat().st_uid, 65532)
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)


class StaticStackTests(unittest.TestCase):
    def test_compose_security_and_pins(self) -> None:
        compose = (ROOT / "compose.yaml").read_text(encoding="utf-8")
        self.assertIn("prom/prometheus:v3.13.2@sha256:1147c928", compose)
        self.assertIn("prom/alertmanager:v0.33.1@sha256:a89f8d452", compose)
        helper = (ROOT / "helper.Dockerfile").read_text(encoding="utf-8")
        self.assertIn("org.opencontainers.image.source-closure-sha256", helper)
        self.assertEqual(compose.count("network_mode: host"), 3)
        self.assertNotIn("ports:", compose)
        self.assertNotIn("expose:", compose)
        self.assertNotIn("docker.sock", compose)
        self.assertNotIn("privileged:", compose)
        self.assertIn("network_mode: service:alertmanager", compose)
        self.assertIn("--web.listen-address=127.0.0.1:9093", compose)
        self.assertIn("internal: true", compose)
        for expected in ("read_only: true", "no-new-privileges:true", "cap_drop:", "pids_limit:"):
            self.assertIn(expected, compose)

    def test_exact_loopback_control_targets_and_dedicated_bearer(self) -> None:
        config = (ROOT / "prometheus" / "prometheus.yml").read_text(encoding="utf-8")
        self.assertEqual(config.count("127.0.0.1:18090"), 1)
        self.assertEqual(config.count("127.0.0.1:18093"), 1)
        self.assertIn("credentials_file: /run/secrets/control_metrics_bearer", config)
        self.assertEqual(config.count("127.0.0.1:19091"), 2)
        self.assertEqual(config.count("127.0.0.1:19093"), 2)
        self.assertNotIn("session_hmac", config.lower())
        compose = (ROOT / "compose.yaml").read_text(encoding="utf-8")
        self.assertNotIn("session_hmac", compose.lower())

    def test_proxy_allowlist_has_no_silence_or_admin_route(self) -> None:
        self.assertEqual(
            proxy.ALLOWED,
            {("POST", "/api/v2/alerts"), ("GET", "/metrics"), ("GET", "/-/ready")},
        )

    def test_proxy_rejects_unauthenticated_and_silence_requests(self) -> None:
        proxy.ProxyHandler.bearer = "c" * 64
        server = proxy.ThreadingHTTPServer(("127.0.0.1", 0), proxy.ProxyHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            connection = http.client.HTTPConnection("127.0.0.1", server.server_port)
            connection.request("GET", "/metrics")
            self.assertEqual(connection.getresponse().status, 401)
            connection.close()
            connection = http.client.HTTPConnection("127.0.0.1", server.server_port)
            connection.request(
                "POST",
                "/api/v2/silences",
                body="{}",
                headers={"Authorization": f"Bearer {'c' * 64}"},
            )
            self.assertEqual(connection.getresponse().status, 404)
            connection.close()
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_proxy_socket_identity_requires_owner_only_real_socket(self) -> None:
        test_tmp = os.environ.get("CONTROL_MONITORING_TEST_TMPDIR")
        with tempfile.TemporaryDirectory(dir=test_tmp or ROOT / "tests") as directory:
            socket_path = Path(directory) / "alertmanager.sock"
            unix_socket = proxy.socket.socket(proxy.socket.AF_UNIX, proxy.socket.SOCK_STREAM)
            try:
                unix_socket.bind(str(socket_path))
                socket_path.chmod(0o600)
                identity = proxy.validate_socket(socket_path)
                self.assertEqual(identity, (socket_path.stat().st_dev, socket_path.stat().st_ino))
                socket_path.chmod(0o660)
                with self.assertRaises(ValueError):
                    proxy.validate_socket(socket_path)
            finally:
                unix_socket.close()

    def test_strict_verifier_and_complete_helper_closure_are_declared(self) -> None:
        verifier = (ROOT / "verify-stack.sh").read_text(encoding="utf-8")
        for required in (
            "--strict",
            'require_command "$RUFF_BIN"',
            'require_command "$PROMTOOL_BIN"',
            "docker compose version",
            '"common.py"',
            '"alertmanager-proxy.py"',
            '"collector/collector.py"',
            '"evidence-receiver/receiver.py"',
        ):
            self.assertIn(required, verifier)
        self.assertTrue(os.access(ROOT / "verify-stack.sh", os.X_OK))


if __name__ == "__main__":
    unittest.main()
