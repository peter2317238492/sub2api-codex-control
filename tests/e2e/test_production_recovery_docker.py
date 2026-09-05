"""Exercise recovery against real Docker datastores and synthetic backup admission.

Preload the PostgreSQL and Redis images; this test never pulls images or uses
production data. Override RECOVERY_TEST_POSTGRES_IMAGE/RECOVERY_TEST_REDIS_IMAGE
to test another admitted image, then run this file with unittest.
"""

from __future__ import annotations

import importlib.util
import json
import os
import secrets
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location(
    "recovery_fixture", ROOT / "deploy/scripts/tests/test_production_recovery.py"
)
assert spec is not None and spec.loader is not None
fixtures = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixtures)


class ProductionRecoveryDockerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.docker = shutil.which("docker")
        if cls.docker is None:
            raise RuntimeError("Docker and preloaded datastore images are required")
        cls.images = {}
        for role, default in (("postgres", "postgres:18-alpine"), ("redis", "redis:7-alpine")):
            reference = os.environ.get(f"RECOVERY_TEST_{role.upper()}_IMAGE", default)
            cls.images[role] = cls.command("image", "inspect", reference, "--format", "{{.Id}}").stdout.decode().strip()

    @classmethod
    def command(cls, *args: str) -> subprocess.CompletedProcess[bytes]:
        return subprocess.run([cls.docker, *args], check=True, capture_output=True, timeout=120)

    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.fixture = fixtures.RecoveryFixture(Path(temporary.name))
        self.fixture.docker = Path(self.docker)
        self.before_containers = self.command("container", "ls", "-a", "--format", "{{.Names}}").stdout.splitlines()
        self.before_volumes = self.command("volume", "ls", "--format", "{{.Name}}").stdout.splitlines()
        token = secrets.token_hex(8)
        postgres = f"recovery-test-pg-{token}"
        redis = f"recovery-test-redis-{token}"
        for name in (postgres, redis):
            self.addCleanup(self.command, "rm", "-f", "--volumes", name)
        self.command(
            "run", "--pull", "never", "-d", "--name", postgres,
            "--network", "none", "--read-only",
            "--tmpfs", "/var/lib/postgresql:rw,nosuid,nodev,size=512m",
            "--tmpfs", "/run/postgresql:rw,nosuid,nodev,size=16m",
            "--env", "POSTGRES_HOST_AUTH_METHOD=trust",
            "--env", "POSTGRES_USER=recovery_admin",
            self.images["postgres"],
        )
        fixtures.recovery.wait_for_command(
            [self.docker, "exec", postgres, "pg_isready", "-h", "127.0.0.1", "-U", "recovery_admin", "-d", "postgres"],
            label="test PostgreSQL readiness", timeout_seconds=60,
        )
        self.command(
            "exec", postgres, "psql", "-U", "recovery_admin", "-d", "postgres", "-c",
            "CREATE TABLE recovery_fixture (id serial PRIMARY KEY, value text); "
            "INSERT INTO recovery_fixture(value) SELECT 'record-' || n FROM generate_series(1,100) n;",
        )
        dump = self.command("exec", postgres, "pg_dump", "-U", "recovery_admin", "-Fc", "postgres").stdout
        for name in ("sub2api-postgres.dump", "postgres-codex_control.dump"):
            (self.fixture.snapshot / name).write_bytes(dump)
        self.command(
            "run", "--pull", "never", "-d", "--name", redis,
            "--network", "none", "--read-only", "--tmpfs", "/data:rw,nosuid,nodev,size=32m",
            self.images["redis"], "redis-server", "--save", "", "--appendonly", "no",
        )
        fixtures.recovery.wait_for_command(
            [self.docker, "exec", redis, "redis-cli", "PING"],
            label="test Redis readiness", timeout_seconds=60,
        )
        self.command("exec", redis, "redis-cli", "SET", "recovery-fixture", "value")
        self.command("exec", redis, "redis-cli", "SAVE")
        (self.fixture.snapshot / "redis-logical.rdb").write_bytes(
            self.command("exec", redis, "cat", "/data/dump.rdb").stdout
        )
        self.rebind_artifacts()

    def rebind_artifacts(self) -> None:
        admission = json.loads(self.fixture.admission.read_bytes())
        for role, image in self.images.items():
            admission["containers"][role]["image_id"] = image
        for name, record in admission["artifacts"].items():
            path = self.fixture.snapshot / name
            record.update(sha256=fixtures.sha256(path), size=path.stat().st_size)
        fixtures.write_json(self.fixture.admission, admission)

    def assert_recovery_cleanup(self) -> None:
        for kind, before, formatter in (
            ("container", self.before_containers, "{{.Names}}"),
            ("volume", self.before_volumes, "{{.Name}}"),
        ):
            after = self.command(kind, "ls", "--all" if kind == "container" else "--quiet", "--format", formatter).stdout.splitlines()
            leaked = [name for name in set(after) - set(before) if name.startswith(b"codex-control-restore-")]
            self.assertEqual(leaked, [], f"recovery left {kind} resources")

    def test_real_dump_and_rdb_restore_and_cleanup(self) -> None:
        receipt = json.loads(self.fixture.restore(timeout_seconds=120).read_bytes())
        self.assertEqual(receipt["redis"]["key_count"], 1)
        for database in receipt["postgresql"]["databases"]:
            self.assertEqual(database["table_count"], 1)
            self.assertEqual(database["sequence_count"], 1)
        self.assert_recovery_cleanup()

    def test_invalid_dump_fails_and_removes_restore_storage(self) -> None:
        (self.fixture.snapshot / "sub2api-postgres.dump").write_bytes(b"invalid custom dump")
        self.rebind_artifacts()
        with self.assertRaisesRegex(AssertionError, "restore isolated PostgreSQL database"):
            self.fixture.restore(timeout_seconds=120)
        self.assertFalse((self.fixture.root / "restore.json").exists())
        self.assert_recovery_cleanup()


if __name__ == "__main__":
    unittest.main()
