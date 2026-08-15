from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess
import sys
import tarfile
import tempfile
import textwrap
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
SCRIPT = REPO_ROOT / "deploy/scripts/backup-production-state.py"
DEPLOY = REPO_ROOT / "deploy/scripts/deploy-production.sh"
PG_RESTORE_CONTAINER = REPO_ROOT / "deploy/scripts/pg-restore-via-container.sh"
BOOTSTRAP_ADMISSION = REPO_ROOT / "deploy/scripts/bootstrap-admission.py"


FAKE_DOCKER = r"""#!/usr/bin/env python3
import os
import pathlib
import json
import sys

arguments = sys.argv[1:]
log = pathlib.Path(os.environ["FAKE_DOCKER_LOG"])
with log.open("a", encoding="utf-8") as destination:
    destination.write(repr(arguments) + "\n")

if arguments[:1] == ["inspect"]:
    identities = {
        "sub2api": ("1" * 64, "sha256:" + "1" * 64),
        "sub2api-postgres": ("2" * 64, "sha256:" + "2" * 64),
        "sub2api-redis": ("3" * 64, "sha256:" + "3" * 64),
    }
    if "--format" in arguments:
        name = arguments[-1]
        container_id, image_id = identities[name]
        formatted_count = log.read_text(encoding="utf-8").count("'--format'")
        pid = 9999 if os.environ.get("DRIFT_IDENTITIES") == "1" and formatted_count >= 4 else 4321
        print(f"{container_id}|{image_id}|/{name}|true|{pid}")
    else:
        print(json.dumps([{
            "Id": identities[name][0],
            "Image": identities[name][1],
            "Name": f"/{name}",
            "State": {"Running": True},
            "Config": {"Env": ["SECRET=private"]},
            "NetworkSettings": {
                "Networks": {
                    "sub2api-network": {
                        "NetworkID": "4" * 64,
                        "EndpointID": identities[name][0],
                    }
                }
            },
        } for name in arguments[1:]]))
    raise SystemExit(0)

if arguments[:2] == ["network", "inspect"]:
    requested = arguments[2:]
    members = {
        value[0]: {"Name": name, "EndpointID": value[0]}
        for name, value in {
            "sub2api": ("1" * 64, "sha256:" + "1" * 64),
            "sub2api-postgres": ("2" * 64, "sha256:" + "2" * 64),
            "sub2api-redis": ("3" * 64, "sha256:" + "3" * 64),
        }.items()
    }
    values = []
    for name in requested:
        values.append({
            "Name": name,
            "Id": ("4" if name == "sub2api-network" else "5") * 64,
            "Driver": "bridge",
            "Scope": "local",
            "Internal": False,
            "Attachable": False,
            "Ingress": False,
            "EnableIPv6": False,
            "IPAM": {"Driver": "default"},
            "Options": {},
            "Containers": members if name == "sub2api-network" else {},
        })
    print(json.dumps(values))
    raise SystemExit(0)

if arguments[:2] == ["image", "inspect"]:
    print(json.dumps([{"Id": value, "RepoDigests": [f"fixture@sha256:{'a' * 64}"]} for value in arguments[2:]]))
    raise SystemExit(0)

if arguments[:2] == ["exec", "-i"]:
    if arguments[3:] == ["pg_restore", "--list"]:
        supplied = sys.stdin.buffer.read()
        if not supplied.startswith(b"PGDUMP-CUSTOM-FIXTURE"):
            raise SystemExit(19)
        print("1; 0 0 TABLE public users sub2api")
        raise SystemExit(0)
    script = arguments[5]
    supplied = sys.stdin.buffer.read()
    if os.environ.get("LEAK_SECRET") == "1":
        sys.stderr.buffer.write(supplied)
    if "redis-check-rdb" in script:
        if os.environ.get("FAIL_REDIS_VALIDATION") == "1":
            raise SystemExit(8)
        if not supplied.startswith(b"REDIS"):
            raise SystemExit(9)
        print("RDB is valid")
    elif "pg_dump --username" in script:
        sys.stdout.buffer.write(b"PGDUMP-CUSTOM-FIXTURE\x00\x01")
    elif "pg_dumpall" in script:
        print("CREATE ROLE sub2api;")
    elif "SELECT current_database" in script:
        print("sub2api|16.4|sub2api|{sub2api=CTc/sub2api}")
    elif "SELECT EXISTS" in script:
        print("t")
    elif "INFO persistence" in script:
        print("# Persistence\nrdb_last_save_time:1\ndir\n/data\naclfile\n/data/users.acl\nuser default on #hash ~* +@all")
    elif "--rdb" in script:
        if os.environ.get("BAD_REDIS_RDB") == "1":
            sys.stdout.buffer.write(b"not-an-rdb")
        else:
            sys.stdout.buffer.write(b"REDIS0011fixture-rdb-payload")
    elif '"$3"' in script:
        print("PONG")
    else:
        raise SystemExit(77)
    raise SystemExit(0)

if arguments[:1] == ["cp"]:
    sys.stdout.buffer.write(pathlib.Path(os.environ["FAKE_REDIS_TAR"]).read_bytes())
    raise SystemExit(0)

if arguments[:1] == ["diff"]:
    print("C /app/sub2api")
    raise SystemExit(0)

if arguments[:1] == ["exec"]:
    if "exec tar -C" in arguments[4]:
        sys.stdout.buffer.write(pathlib.Path(os.environ["FAKE_RUNTIME_TAR"]).read_bytes())
    else:
        print("Sub2API 0.1.175")
        print("a" * 64 + "  /app/sub2api")
        print("a" * 64 + "  /proc/1/exe")
    raise SystemExit(0)

raise SystemExit(78)
"""


FAKE_PG_RESTORE = r"""#!/bin/sh
set -eu
if [ "${FAIL_PG_RESTORE:-0}" = 1 ]; then
  exit 12
fi
test "$1" = --list
grep -a -q PGDUMP-CUSTOM-FIXTURE "$2"
printf '%s\n' '1; 0 0 TABLE public users sub2api'
"""


FAKE_NGINX = r"""#!/bin/sh
set -eu
test "$1" = -T
printf '%s\n' \
  'events {}' \
  'http {' \
  "  ssl_certificate $FIXTURE_CERTIFICATE;" \
  "  ssl_certificate_key $FIXTURE_PRIVATE_KEY;" \
  '}'
"""


FAKE_OPENSSL = r"""#!/bin/sh
set -eu
test "$1" = x509
printf '%s\n' \
  'subject=CN=control.example.test' \
  'issuer=CN=fixture-ca' \
  'serial=01' \
  'notBefore=Jan  1 00:00:00 2026 GMT' \
  'notAfter=Jan  1 00:00:00 2027 GMT' \
  'sha256 Fingerprint=AA:BB'
"""


class ProductionStateBackupTests(unittest.TestCase):
    def test_redis_cli_uses_portable_short_host_and_port_options(self) -> None:
        source = SCRIPT.read_text(encoding="utf-8")

        self.assertNotIn("--host 127.0.0.1", source)
        self.assertNotIn('--port "$2"', source)
        self.assertGreaterEqual(source.count('-h 127.0.0.1 -p "$2"'), 3)

    def test_live_sub2api_logs_are_excluded_from_host_archive(self) -> None:
        source = SCRIPT.read_text(encoding="utf-8")

        self.assertIn('f"{relative_archive_name(arguments.sub2api_data)}/logs"', source)

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.docker = self.write_executable("docker", FAKE_DOCKER)
        self.pg_restore = self.write_executable("pg_restore", FAKE_PG_RESTORE)
        self.nginx = self.write_executable("nginx", FAKE_NGINX)
        self.openssl = self.write_executable("openssl", FAKE_OPENSSL)

        self.backup_root = self.root / "backups"
        self.backup_root.mkdir(mode=0o700)
        self.result_parent = self.root / "records"
        self.result_parent.mkdir(mode=0o700)
        self.result_file = self.result_parent / "production-backup.json"

        self.production = self.root / "production"
        self.production.mkdir()
        self.data = self.production / "data"
        self.data.mkdir()
        (self.data / "state.db").write_text("state", encoding="ascii")
        self.config = self.production / "config.yaml"
        self.config.write_text("secret: fixture\n", encoding="ascii")
        self.compose = self.production / "docker-compose.local.yml"
        self.compose.write_text("services: {}\n", encoding="ascii")
        self.environment_file = self.production / ".env"
        self.environment_file.write_text("PASSWORD=not-printed\n", encoding="ascii")
        self.nginx_config = self.production / "nginx"
        self.nginx_config.mkdir()
        (self.nginx_config / "nginx.conf").write_text("events {}\n", encoding="ascii")
        self.release_records = self.production / "release-records"
        self.release_records.mkdir()
        release_record = self.release_records / "deployment-fixture"
        release_record.mkdir()
        (release_record / "deployment.json").write_text(
            '{"status":"deployed"}\n', encoding="ascii"
        )
        self.release_verification = self.production / "release-verification.json"
        self.release_verification.write_text(
            '{"status":"verified"}\n', encoding="ascii"
        )
        self.source_verification = self.production / "source-verification.json"
        self.source_verification.write_text(
            '{"status":"verified"}\n', encoding="ascii"
        )

        self.certificate = self.production / "fullchain.pem"
        self.certificate.write_text("PUBLIC CERTIFICATE FIXTURE\n", encoding="ascii")
        self.private_key = self.production / "privkey.pem"
        self.private_key.write_text(
            "PRIVATE KEY MUST NOT BE COPIED\n", encoding="ascii"
        )
        self.private_key.chmod(0o600)

        self.postgres_password = self.root / "postgres-password"
        self.postgres_password.write_text("postgres-super-secret\n", encoding="ascii")
        self.postgres_password.chmod(0o600)
        self.redis_password = self.root / "redis-password"
        self.redis_password.write_text("redis-super-secret\n", encoding="ascii")
        self.redis_password.chmod(0o600)

        redis_directory = self.root / "redis-data"
        redis_directory.mkdir()
        (redis_directory / "users.acl").write_text(
            "user default on #hash\n", encoding="ascii"
        )
        self.redis_tar = self.root / "redis.tar"
        with tarfile.open(self.redis_tar, "w") as archive:
            archive.add(redis_directory, arcname="data")
        runtime_directory = self.root / "app"
        runtime_directory.mkdir()
        (runtime_directory / "sub2api").write_text("runtime-binary", encoding="ascii")
        self.runtime_tar = self.root / "runtime.tar"
        with tarfile.open(self.runtime_tar, "w") as archive:
            archive.add(runtime_directory / "sub2api", arcname="app/sub2api")
        self.proc_root = self.root / "proc"
        proc_pid = self.proc_root / "4321"
        proc_pid.mkdir(parents=True)
        (proc_pid / "exe").symlink_to(runtime_directory / "sub2api")

        self.docker_log = self.root / "docker.log"
        self.environment = os.environ.copy()
        self.environment.update(
            {
                "PATH": f"{self.bin}:{self.environment['PATH']}",
                "FAKE_DOCKER_LOG": str(self.docker_log),
                "FAKE_REDIS_TAR": str(self.redis_tar),
                "FAKE_RUNTIME_TAR": str(self.runtime_tar),
                "FIXTURE_CERTIFICATE": str(self.certificate),
                "FIXTURE_PRIVATE_KEY": str(self.private_key),
                "LEAK_SECRET": "1",
            }
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write_executable(self, name: str, value: str) -> Path:
        path = self.bin / name
        path.write_text(textwrap.dedent(value), encoding="utf-8")
        path.chmod(0o700)
        return path

    def command(self) -> list[str]:
        return [
            sys.executable,
            str(SCRIPT),
            "--backup-root",
            str(self.backup_root),
            "--result-file",
            str(self.result_file),
            "--sub2api-container",
            "sub2api",
            "--postgres-container",
            "sub2api-postgres",
            "--postgres-user",
            "sub2api",
            "--postgres-database",
            "sub2api",
            "--additional-postgres-database",
            "codex_control",
            "--postgres-password-file",
            str(self.postgres_password),
            "--redis-container",
            "sub2api-redis",
            "--redis-user",
            "default",
            "--redis-password-file",
            str(self.redis_password),
            "--sub2api-data",
            str(self.data),
            "--sub2api-config",
            str(self.config),
            "--sub2api-compose",
            str(self.compose),
            "--sub2api-environment",
            str(self.environment_file),
            "--nginx-config",
            str(self.nginx_config),
            "--release-records",
            str(self.release_records),
            "--release-evidence",
            str(self.release_verification),
            "--release-evidence",
            str(self.source_verification),
            "--docker-network",
            "sub2api-network",
            "--docker-network",
            "pwa-network",
            "--expected-owner-uid",
            str(os.geteuid()),
            "--proc-root",
            str(self.proc_root),
            "--docker",
            str(self.docker),
            "--pg-restore",
            str(self.pg_restore),
            "--nginx",
            str(self.nginx),
            "--openssl",
            str(self.openssl),
        ]

    def run_backup(self) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            self.command(),
            check=False,
            capture_output=True,
            text=True,
            env=self.environment,
        )

    def test_creates_one_private_fully_validated_snapshot_without_secret_output(
        self,
    ) -> None:
        result = self.run_backup()
        self.assertEqual(result.returncode, 0, result.stderr)
        for secret in ("postgres-super-secret", "redis-super-secret"):
            self.assertNotIn(secret, result.stdout)
            self.assertNotIn(secret, result.stderr)
            self.assertNotIn(secret, self.docker_log.read_text(encoding="utf-8"))

        snapshots = list(self.backup_root.glob("production-preflight-*"))
        self.assertEqual(len(snapshots), 1)
        snapshot = snapshots[0]
        self.assertEqual(stat.S_IMODE(snapshot.stat().st_mode), 0o700)
        expected = {
            "sub2api-postgres.dump",
            "sub2api-postgres.contents.txt",
            "postgres-globals.sql",
            "postgres-database-metadata.txt",
            "postgres-codex_control.dump",
            "postgres-codex_control.contents.txt",
            "postgres-additional-databases.json",
            "docker-container-inspect.json",
            "docker-image-inspect.json",
            "docker-network-inspect.json",
            "docker-networks.json",
            "redis-logical.rdb",
            "redis-rdb-validation.txt",
            "redis-config-acl.txt",
            "redis-persistence.tar",
            "redis-persistence.contents.txt",
            "sub2api-host-files.tar.gz",
            "sub2api-host-files.contents.txt",
            "sub2api-runtime.txt",
            "sub2api-running-executable.json",
            "sub2api-runtime-files.tar",
            "sub2api-runtime-files.contents.txt",
            "sub2api-container-diff.txt",
            "nginx-effective-config.txt",
            "nginx-config.tar.gz",
            "nginx-config.contents.txt",
            "nginx-certificates.txt",
            "nginx-tls-files.json",
            "nginx-tls-private.tar.gz",
            "nginx-tls-private.contents.txt",
            "release-evidence-inventory.json",
            "release-evidence-release-verification.json",
            "release-evidence-source-verification.json",
            "release-records-inventory.json",
            "release-records.tar.gz",
            "release-records.contents.txt",
            "backup-record.json",
            "manifest.sha256",
            "READY.json",
        }
        self.assertEqual({path.name for path in snapshot.iterdir()}, expected)
        for path in snapshot.iterdir():
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600, path.name)

        for line in (
            (snapshot / "manifest.sha256").read_text(encoding="ascii").splitlines()
        ):
            expected_hash, name = line.split("  ", 1)
            actual_hash = hashlib.sha256((snapshot / name).read_bytes()).hexdigest()
            self.assertEqual(actual_hash, expected_hash, name)

        ready = json.loads((snapshot / "READY.json").read_text(encoding="utf-8"))
        self.assertEqual(ready["status"], "ready")
        self.assertEqual(
            ready["manifest_sha256"],
            hashlib.sha256((snapshot / "manifest.sha256").read_bytes()).hexdigest(),
        )
        record = json.loads(
            (snapshot / "backup-record.json").read_text(encoding="utf-8")
        )
        self.assertEqual(record["status"], "ready")
        self.assertEqual(record["redis"]["logical_rdb_validator"], "redis-check-rdb")
        self.assertEqual(record["containers"]["sub2api"]["container_id"], "1" * 64)

        tls = json.loads(
            (snapshot / "nginx-tls-files.json").read_text(encoding="utf-8")
        )
        self.assertIn("sha256", tls["certificates"][0])
        self.assertNotIn("sha256", tls["private_keys"][0])
        self.assertNotIn(
            "PRIVATE KEY MUST NOT BE COPIED",
            (snapshot / "nginx-certificates.txt").read_text(encoding="utf-8"),
        )
        with tarfile.open(snapshot / "nginx-tls-private.tar.gz", "r:gz") as archive:
            key_member = next(
                member
                for member in archive.getmembers()
                if member.name == str(self.private_key).removeprefix("/")
            )
            key_file = archive.extractfile(key_member)
            assert key_file is not None
            self.assertEqual(key_file.read(), b"PRIVATE KEY MUST NOT BE COPIED\n")
        result_record = json.loads(self.result_file.read_text(encoding="utf-8"))
        self.assertEqual(result_record["snapshot_directory"], str(snapshot))
        self.assertEqual(stat.S_IMODE(self.result_file.stat().st_mode), 0o600)
        admission = subprocess.run(
            [
                sys.executable,
                str(BOOTSTRAP_ADMISSION),
                "backup-receipt",
                "--result-file",
                str(self.result_file),
                "--max-age-seconds",
                "300",
                "--expected-owner-uid",
                str(os.geteuid()),
                "--current-identities",
                str(snapshot / "docker-container-inspect.json"),
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(admission.returncode, 0, admission.stderr)
        self.assertEqual(json.loads(admission.stdout)["status"], "admitted")

    def test_pg_restore_failure_leaves_no_ready_or_partial_snapshot(self) -> None:
        self.environment["FAIL_PG_RESTORE"] = "1"
        result = self.run_backup()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("PostgreSQL pg_restore validation", result.stderr)
        self.assertFalse(self.result_file.exists())
        self.assertEqual(list(self.backup_root.iterdir()), [])
        self.assertNotIn("postgres-super-secret", result.stderr)

    def test_uses_container_pg_restore_when_host_tool_is_unavailable(self) -> None:
        command = self.command()
        option = command.index("--pg-restore")
        del command[option : option + 2]
        result = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            env=self.environment,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        docker_commands = self.docker_log.read_text(encoding="utf-8")
        self.assertIn("'pg_restore', '--list'", docker_commands)

    def test_invalid_redis_snapshot_fails_closed(self) -> None:
        self.environment["BAD_REDIS_RDB"] = "1"
        self.environment["FAIL_REDIS_VALIDATION"] = "1"
        self.write_executable("redis-check-rdb", "#!/bin/sh\nexit 17\n")
        result = self.run_backup()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Redis RDB validation", result.stderr)
        self.assertFalse(self.result_file.exists())
        self.assertEqual(list(self.backup_root.iterdir()), [])

    def test_container_restart_during_snapshot_fails_closed(self) -> None:
        self.environment["DRIFT_IDENTITIES"] = "1"
        result = self.run_backup()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("container changed during the backup", result.stderr)
        self.assertFalse(self.result_file.exists())
        self.assertEqual(list(self.backup_root.iterdir()), [])

    def test_rejects_non_private_backup_root_before_docker_access(self) -> None:
        self.backup_root.chmod(0o755)
        result = self.run_backup()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("mode must be exactly 0700", result.stderr)
        self.assertFalse(self.docker_log.exists())

    def test_rejects_missing_required_source_before_docker_access(self) -> None:
        self.environment_file.unlink()
        result = self.run_backup()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Sub2API environment file is not accessible", result.stderr)
        self.assertFalse(self.docker_log.exists())

    def test_deployment_requires_full_snapshot_before_auth_probe_or_mutation(
        self,
    ) -> None:
        script = DEPLOY.read_text(encoding="utf-8")
        backup = script.index("stage=create-production-state-backup")
        pull = script.index("stage=acquire-release-images")
        auth_probe = script.index("stage=verify-sub2api")
        freeze = script.index("stage=freeze-control-writers")
        stopped_before = script.index("stage=capture-writers-stopped-before-backup")
        control_backup = script.index("stage=create-final-premigration-backup")
        stopped_after = script.index("stage=capture-writers-stopped-after-backup")
        freeze_receipt = script.index("stage=admit-writer-freeze-window")
        reverse_plan = script.index("stage=admit-bounded-reverse-plan")
        terminal_admission = script.index("stage=record-final-pre-migration-admission")
        migrate = script.index("stage=migrate")
        migration_exposure_gate = script.index(
            "stage=reject-uncontrolled-migration-writer-exposure"
        )
        restore = script.index("stage=prove-isolated-restore")
        isolation = script.index("stage=prove-live-datastore-isolation")
        start = script.index('stage="start-$service"')
        self.assertLess(backup, pull)
        self.assertLess(backup, restore)
        self.assertLess(restore, isolation)
        self.assertLess(isolation, pull)
        self.assertLess(backup, auth_probe)
        self.assertLess(auth_probe, freeze)
        self.assertLess(freeze, stopped_before)
        self.assertLess(stopped_before, control_backup)
        self.assertLess(control_backup, stopped_after)
        self.assertLess(stopped_after, freeze_receipt)
        self.assertLess(freeze_receipt, reverse_plan)
        self.assertLess(reverse_plan, terminal_admission)
        self.assertLess(terminal_admission, migrate)
        self.assertLess(control_backup, migrate)
        self.assertLess(migrate, start)
        self.assertLess(migrate, migration_exposure_gate)
        self.assertLess(migration_exposure_gate, start)
        self.assertIn("run_production_state_backup", script[backup:pull])
        self.assertIn('python3 "$production_state_backup"', script)
        self.assertIn("--additional-postgres-database", script)
        self.assertIn("CONTROL_PRODUCTION_BACKUP_ROOT", script)
        self.assertNotIn("command -v pg_restore", script)
        self.assertIn('--pg-restore "$pg_restore_validator"', script)

    def test_container_pg_restore_adapter_streams_inherited_dump(self) -> None:
        adapter_bin = self.root / "adapter-bin"
        adapter_bin.mkdir()
        docker_log = self.root / "adapter-docker.log"
        fake_docker = adapter_bin / "docker"
        fake_docker.write_text(
            "#!/bin/sh\n"
            "set -eu\n"
            'printf \'%s\\n\' "$*" > "$ADAPTER_DOCKER_LOG"\n'
            "grep -a -q PGDUMP-CUSTOM-FIXTURE\n"
            "printf '%s\\n' '1; 0 0 TABLE public users sub2api'\n",
            encoding="ascii",
        )
        fake_docker.chmod(0o700)
        dump = self.root / "adapter.dump"
        dump.write_bytes(b"PGDUMP-CUSTOM-FIXTURE\x00\x01")
        environment = os.environ.copy()
        environment.update(
            {
                "PATH": f"{adapter_bin}:{environment['PATH']}",
                "ADAPTER_DOCKER_LOG": str(docker_log),
                "PG_RESTORE_IMAGE": f"registry.example/postgres@sha256:{'a' * 64}",
            }
        )
        result = subprocess.run(
            [str(PG_RESTORE_CONTAINER), "--list", str(dump)],
            check=False,
            capture_output=True,
            text=True,
            env=environment,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("TABLE public users", result.stdout)
        command = docker_log.read_text(encoding="utf-8")
        self.assertIn("--network none", command)
        self.assertIn("--entrypoint pg_restore", command)

        environment["PG_RESTORE_IMAGE"] = "registry.example/postgres:latest"
        docker_log.unlink()
        rejected = subprocess.run(
            [str(PG_RESTORE_CONTAINER), "--list", str(dump)],
            check=False,
            capture_output=True,
            text=True,
            env=environment,
        )
        self.assertNotEqual(rejected.returncode, 0)
        self.assertFalse(docker_log.exists())


if __name__ == "__main__":
    unittest.main()
