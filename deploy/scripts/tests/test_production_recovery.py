from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[3]
RECOVERY = REPO_ROOT / "deploy/scripts/production-recovery.py"
SCHEMA = REPO_ROOT / "deploy/schemas/production-recovery-receipt.schema.json"
IMAGE_PG = f"sha256:{'1' * 64}"
IMAGE_REDIS = f"sha256:{'2' * 64}"
IMAGE_API = f"sha256:{'3' * 64}"
IMAGE_PWA = f"sha256:{'4' * 64}"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_json(path: Path, value: object, mode: int = 0o600) -> None:
    path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")
    path.chmod(mode)


class RecoveryFixture:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.root.chmod(0o700)
        self.snapshot = root / "snapshot"
        self.snapshot.mkdir(mode=0o700)
        artifact_payloads = {
            "sub2api-postgres.dump": b"sub2api-dump",
            "postgres-codex_control.dump": b"control-dump",
            "postgres-additional-databases.json": b'{"codex_control":"backed_up"}\n',
            "redis-logical.rdb": b"redis-rdb",
            "release-records.tar.gz": b"release-records",
            "release-records-inventory.json": b'{"entries":[]}\n',
            "release-evidence-inventory.json": b"[]\n",
            "docker-network-inspect.json": b"[]\n",
            "docker-networks.json": b"[]\n",
        }
        for name, payload in artifact_payloads.items():
            path = self.snapshot / name
            path.write_bytes(payload)
            path.chmod(0o600)
        manifest = self.snapshot / "manifest.sha256"
        manifest.write_text("fixture manifest\n", encoding="ascii")
        manifest.chmod(0o600)
        self.receipt = root / "backup-result.json"
        write_json(
            self.receipt,
            {
                "schema_version": 1,
                "status": "ready",
                "snapshot_directory": str(self.snapshot),
                "manifest_sha256": sha256(manifest),
            },
        )
        self.admission = root / "backup-admission.json"
        write_json(
            self.admission,
            {
                "format_version": 1,
                "status": "admitted",
                "fresh": True,
                "admission_mode": "fresh-production-backup",
                "owner_uid": os.geteuid(),
                "receipt_path": str(self.receipt),
                "receipt_sha256": sha256(self.receipt),
                "snapshot_directory": str(self.snapshot),
                "manifest_sha256": sha256(manifest),
                "artifacts": {
                    name: {
                        "sha256": sha256(self.snapshot / name),
                        "size": (self.snapshot / name).stat().st_size,
                    }
                    for name in artifact_payloads
                },
                "containers": {
                    "postgres": {
                        "name": "sub2api-postgres",
                        "container_id": "a" * 64,
                        "image_id": IMAGE_PG,
                    },
                    "redis": {
                        "name": "sub2api-redis",
                        "container_id": "b" * 64,
                        "image_id": IMAGE_REDIS,
                    },
                    "sub2api": {
                        "name": "sub2api",
                        "container_id": "c" * 64,
                        "image_id": f"sha256:{'5' * 64}",
                    },
                },
            },
        )
        self.plan = root / "plan.json"
        write_json(
            self.plan,
            {
                "format_version": 1,
                "datastores": {
                    "postgres": {
                        "role": "codex_control",
                        "database": "codex_control",
                        "sub2api_database": "sub2api",
                        "host": "postgres",
                        "port": "5432",
                    },
                    "redis": {
                        "auth_mode": "password",
                        "user": "codex_control",
                        "prefix": "codex-control:",
                        "host": "redis",
                        "port": "6379",
                    },
                },
            },
        )
        self.control_pg_secret = root / "control-pg-secret"
        self.control_pg_secret.write_text("control-pg-password\n", encoding="ascii")
        self.control_pg_secret.chmod(0o600)
        self.control_redis_secret = root / "control-redis-secret"
        self.control_redis_secret.write_text(
            "control-redis-password\n", encoding="ascii"
        )
        self.control_redis_secret.chmod(0o600)
        self.log = root / "docker.log"
        self.docker = root / "docker"
        self.docker.write_text(
            """#!/bin/sh
set -eu
printf '%s\n' "$*" >> "$FAKE_DOCKER_LOG"
all=$*
case "$all" in
  'inspect --type container '*) exit 1 ;;
  *'ACL LIST'*)
    printf '%s\n' 'user default on #bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb ~* &* +@all' \
      'user codex_control on #aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa ~codex-control:* &codex-control:* -@all +ping +get +set +del +incr +expire +eval +publish +subscribe +unsubscribe +client|setinfo'
    ;;
  *'--dbname sub2api'*'--command SELECT 1')
    printf '%s\n' 'permission denied' >&2
    exit 2
    ;;
  *'current_user'*) printf '%s\n' 'codex_control|codex_control' ;;
  *'pg_auth_members'*) printf '%s\n' '0' ;;
  *'SELECT ((SELECT count(*) FROM pg_class'*) printf '%s\n' '0' ;;
  *'SELECT (rolcanlogin'*) printf '%s\n' 'true' ;;
  *'has_database_privilege'*) printf '%s\n' 'true' ;;
  *'pg_get_userbyid(nspowner)'*) printf '%s\n' 'true' ;;
  *'pg_get_userbyid(datdba)'*) printf '%s\n' 'true' ;;
  *'redis-cli --no-auth-warning --raw PING'*) printf '%s\n' 'NOAUTH Authentication required' ;;
  *'redis-cli'*' PING'*) printf '%s\n' 'PONG' ;;
  *'redis-cli'*' DBSIZE'*) printf '%s\n' '7' ;;
  *'redis-cli'*' CONFIG GET dir'*) printf '%s\n' 'NOPERM command not allowed' ;;
  *'redis-cli'*' CONFIG GET aclfile'*) printf '%s\n' 'aclfile' '/data/users.acl' ;;
  *'redis-cli'*' SET codex-control:isolation-probe-'*) printf '%s\n' 'OK' ;;
  *'redis-cli'*' GET codex-control:isolation-probe-'*) printf '%s\n' 'recovery-isolation' ;;
  *'redis-cli'*' DEL codex-control:isolation-probe-'*) printf '%s\n' '1' ;;
  *'redis-cli'*' GET !recovery-isolation-denied:'*) printf '%s\n' 'NOPERM key not allowed' ;;
  *'redis-cli'*' SET !recovery-isolation-denied:'*) printf '%s\n' 'NOPERM key not allowed' ;;
  *'redis-cli'*' PUBLISH codex-control:isolation-probe-'*) printf '%s\n' '0' ;;
  *'redis-cli'*' PUBLISH !recovery-isolation-denied:'*) printf '%s\n' 'NOPERM channel not allowed' ;;
  *'SELECT count(*)::text ||'*) printf '%s\n' '1|2|3' ;;
  run\\ -d*) printf '%064d\n' 0 ;;
  *) : ;;
esac
""",
            encoding="ascii",
        )
        self.docker.chmod(0o700)

    def run(self, *arguments: str, success: bool = True) -> subprocess.CompletedProcess[str]:
        environment = os.environ.copy()
        environment["FAKE_DOCKER_LOG"] = str(self.log)
        result = subprocess.run(
            [sys.executable, str(RECOVERY), *arguments],
            check=False,
            capture_output=True,
            text=True,
            env=environment,
        )
        if success and result.returncode != 0:
            raise AssertionError(result.stderr)
        if not success and result.returncode == 0:
            raise AssertionError(result.stdout)
        return result

    def restore(self) -> Path:
        output = self.root / "restore.json"
        self.run(
            "isolated-restore",
            "--backup-admission",
            str(self.admission),
            "--output",
            str(output),
            "--docker",
            str(self.docker),
            "--timeout-seconds",
            "2",
            "--expected-owner-uid",
            str(os.geteuid()),
        )
        return output

    def isolation(self) -> Path:
        output = self.root / "isolation.json"
        self.run(
            "live-isolation",
            "--backup-admission",
            str(self.admission),
            "--plan",
            str(self.plan),
            "--output",
            str(output),
            "--docker",
            str(self.docker),
            "--postgres-container",
            "sub2api-postgres",
            "--postgres-admin-user",
            "sub2api",
            "--postgres-admin-database",
            "sub2api",
            "--control-postgres-password-file",
            str(self.control_pg_secret),
            "--redis-container",
            "sub2api-redis",
            "--redis-admin-user",
            "default",
            "--control-redis-password-file",
            str(self.control_redis_secret),
            "--expected-owner-uid",
            str(os.geteuid()),
        )
        return output


class ProductionRecoveryTests(unittest.TestCase):
    def test_real_isolated_restore_is_networkless_and_cleanup_is_proven(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = RecoveryFixture(Path(temporary))
            output = fixture.restore()
            receipt = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(receipt["type"], "production-isolated-restore-v1")
            self.assertTrue(receipt["isolation"]["temporary_containers_removed"])
            self.assertEqual(receipt["redis"]["key_count"], 7)
            self.assertEqual(len(receipt["postgresql"]["databases"]), 2)
            commands = fixture.log.read_text(encoding="utf-8")
            self.assertEqual(commands.count("--network none"), 2)
            self.assertEqual(commands.count("run --pull never"), 2)
            self.assertIn("pg_restore --exit-on-error --no-owner --no-acl", commands)
            self.assertNotIn("pg_restore --list", commands)
            self.assertIn("redis-server --bind 127.0.0.1", commands)
            self.assertEqual(commands.count("rm -f codex-control-restore-"), 2)
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            fixture.run(
                "isolated-restore",
                "--backup-admission",
                str(fixture.admission),
                "--output",
                str(output),
                "--docker",
                str(fixture.docker),
                "--expected-owner-uid",
                str(os.geteuid()),
                success=False,
            )

    def test_restore_rejects_nonfresh_or_tampered_full_backup(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = RecoveryFixture(Path(temporary))
            value = json.loads(fixture.admission.read_text(encoding="utf-8"))
            value["fresh"] = False
            write_json(fixture.admission, value)
            fixture.run(
                "isolated-restore",
                "--backup-admission",
                str(fixture.admission),
                "--output",
                str(fixture.root / "rejected.json"),
                "--docker",
                str(fixture.docker),
                "--expected-owner-uid",
                str(os.geteuid()),
                success=False,
            )

    def test_live_isolation_proves_database_and_redis_boundaries(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = RecoveryFixture(Path(temporary))
            output = fixture.isolation()
            receipt = json.loads(output.read_text(encoding="utf-8"))
            self.assertTrue(receipt["postgresql"]["control_to_sub2api_connect_denied"])
            self.assertTrue(receipt["redis"]["inside_prefix_read_write_passed"])
            self.assertTrue(receipt["redis"]["outside_prefix_read_denied"])
            self.assertTrue(receipt["redis"]["outside_prefix_write_denied"])
            self.assertTrue(receipt["redis"]["outside_channel_publish_denied"])
            self.assertTrue(receipt["redis"]["anonymous_access_denied"])
            self.assertTrue(receipt["redis"]["enabled_nopass_users_absent"])
            commands = fixture.log.read_text(encoding="utf-8")
            self.assertIn("--dbname sub2api", commands)
            self.assertIn("ACL LIST", commands)
            self.assertIn("GET !recovery-isolation-denied:", commands)
            self.assertIn("SET !recovery-isolation-denied:", commands)
            self.assertIn("PUBLISH !recovery-isolation-denied:", commands)
            self.assertIn("CONFIG GET dir", commands)
            self.assertIn("redis-cli --no-auth-warning --raw PING", commands)
            self.assertNotIn("control-pg-password", commands)
            self.assertNotIn("control-redis-password", commands)

    def test_live_isolation_rejects_an_enabled_nopass_user(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = RecoveryFixture(Path(temporary))
            script = fixture.docker.read_text(encoding="ascii").replace(
                "user default on #" + "b" * 64,
                "user default on nopass",
            )
            fixture.docker.write_text(script, encoding="ascii")
            fixture.docker.chmod(0o700)
            fixture.run(
                "live-isolation",
                "--backup-admission",
                str(fixture.admission),
                "--plan",
                str(fixture.plan),
                "--output",
                str(fixture.root / "rejected-isolation.json"),
                "--docker",
                str(fixture.docker),
                "--postgres-container",
                "sub2api-postgres",
                "--postgres-admin-user",
                "sub2api",
                "--postgres-admin-database",
                "sub2api",
                "--control-postgres-password-file",
                str(fixture.control_pg_secret),
                "--redis-container",
                "sub2api-redis",
                "--redis-admin-user",
                "default",
                "--control-redis-password-file",
                str(fixture.control_redis_secret),
                "--expected-owner-uid",
                str(os.geteuid()),
                success=False,
            )

    def test_writer_freeze_rejects_a_restart_during_the_final_backup(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = RecoveryFixture(Path(temporary))
            current = fixture.root / "current.json"
            base = {
                "Id": "d" * 64,
                "Image": f"sha256:{'6' * 64}",
                "Config": {"Labels": {"com.docker.compose.service": "control-api"}},
                "State": {
                    "Running": True,
                    "StartedAt": "2026-08-15T00:00:00Z",
                },
                "RestartCount": 0,
            }
            write_json(current, [base])
            stopped_before = fixture.root / "stopped-before.json"
            before = json.loads(json.dumps(base))
            before["State"]["Running"] = False
            write_json(stopped_before, [before])
            stopped_after = fixture.root / "stopped-after.json"
            after = json.loads(json.dumps(before))
            after["State"]["StartedAt"] = "2026-08-15T00:01:00Z"
            after["RestartCount"] = 1
            write_json(stopped_after, [after])
            unfreeze = fixture.root / "unfreeze.json"
            fixture.run(
                "writer-unfreeze-plan",
                "--current-control-containers",
                str(current),
                "--output",
                str(unfreeze),
                "--expected-owner-uid",
                str(os.geteuid()),
            )
            fixture.run(
                "writer-freeze-receipt",
                "--current-control-containers",
                str(current),
                "--stopped-before-backup",
                str(stopped_before),
                "--stopped-after-backup",
                str(stopped_after),
                "--unfreeze-plan",
                str(unfreeze),
                "--output",
                str(fixture.root / "rejected-freeze.json"),
                "--expected-owner-uid",
                str(os.geteuid()),
                success=False,
            )

    def test_reverse_plan_binds_every_receipt_and_exact_old_new_images(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = RecoveryFixture(Path(temporary))
            restore = fixture.restore()
            isolation = fixture.isolation()
            releases = fixture.root / "releases.json"
            write_json(
                releases,
                {"api": {"image_id": IMAGE_API}, "pwa": {"image_id": IMAGE_PWA}},
            )
            revisions = fixture.root / "revisions.json"
            write_json(
                revisions,
                {
                    "source_database_revision": "20260731_0007",
                    "target_migration_head": "20260731_0008",
                },
            )
            premigration_dump = fixture.root / "codex-control.dump"
            premigration_dump.write_bytes(b"premigration")
            premigration_dump.chmod(0o600)
            premigration = fixture.root / "premigration.json"
            write_json(
                premigration,
                {
                    "dump_path": str(premigration_dump),
                    "dump_sha256": sha256(premigration_dump),
                },
            )
            current = fixture.root / "current.json"
            write_json(
                current,
                [
                    {
                        "Id": "d" * 64,
                        "Image": f"sha256:{'6' * 64}",
                        "Config": {"Labels": {"com.docker.compose.service": "control-api"}},
                        "State": {
                            "Running": True,
                            "StartedAt": "2026-08-15T00:00:00Z",
                        },
                        "RestartCount": 0,
                    },
                    {
                        "Id": "e" * 64,
                        "Image": f"sha256:{'7' * 64}",
                        "Config": {
                            "Labels": {
                                "com.docker.compose.service": "control-api-replica"
                            }
                        },
                        "State": {
                            "Running": False,
                            "StartedAt": "2026-08-14T23:59:00Z",
                        },
                        "RestartCount": 2,
                    },
                ],
            )
            stopped_before = fixture.root / "writers-stopped-before.json"
            stopped_after = fixture.root / "writers-stopped-after.json"
            stopped_value = [
                {
                    "Id": "d" * 64,
                    "Image": f"sha256:{'6' * 64}",
                    "Config": {
                        "Labels": {"com.docker.compose.service": "control-api"}
                    },
                    "State": {
                        "Running": False,
                        "StartedAt": "2026-08-15T00:00:00Z",
                    },
                    "RestartCount": 0,
                },
                {
                    "Id": "e" * 64,
                    "Image": f"sha256:{'7' * 64}",
                    "Config": {
                        "Labels": {
                            "com.docker.compose.service": "control-api-replica"
                        }
                    },
                    "State": {
                        "Running": False,
                        "StartedAt": "2026-08-14T23:59:00Z",
                    },
                    "RestartCount": 2,
                },
            ]
            write_json(stopped_before, stopped_value)
            write_json(stopped_after, stopped_value)
            unfreeze = fixture.root / "writer-unfreeze-plan.json"
            fixture.run(
                "writer-unfreeze-plan",
                "--current-control-containers",
                str(current),
                "--output",
                str(unfreeze),
                "--expected-owner-uid",
                str(os.geteuid()),
            )
            unfreeze_value = json.loads(unfreeze.read_text(encoding="utf-8"))
            replica_unfreeze = next(
                step
                for step in unfreeze_value["steps"]
                if step["service"] == "control-api-replica"
            )
            self.assertEqual(
                replica_unfreeze["action"], "keep-exact-prior-container-stopped"
            )
            freeze = fixture.root / "writer-freeze-receipt.json"
            fixture.run(
                "writer-freeze-receipt",
                "--current-control-containers",
                str(current),
                "--stopped-before-backup",
                str(stopped_before),
                "--stopped-after-backup",
                str(stopped_after),
                "--unfreeze-plan",
                str(unfreeze),
                "--output",
                str(freeze),
                "--expected-owner-uid",
                str(os.geteuid()),
            )
            compose = fixture.root / "compose.json"
            write_json(
                compose,
                {
                    "services": {
                        "control-api": {"image": "new-api"},
                        "control-api-replica": {"image": "new-api"},
                        "codex-pwa": {"image": "new-pwa"},
                    }
                },
            )
            reverse = fixture.root / "reverse.json"
            rollback_compose = fixture.root / "rollback-compose.json"
            fixture.run(
                "reverse-plan",
                "--backup-admission",
                str(fixture.admission),
                "--plan",
                str(fixture.plan),
                "--releases",
                str(releases),
                "--revisions",
                str(revisions),
                "--premigration-backup",
                str(premigration),
                "--restore-receipt",
                str(restore),
                "--isolation-receipt",
                str(isolation),
                "--unfreeze-plan",
                str(unfreeze),
                "--writer-freeze-receipt",
                str(freeze),
                "--current-control-containers",
                str(current),
                "--compose-config",
                str(compose),
                "--rollback-compose-output",
                str(rollback_compose),
                "--output",
                str(reverse),
                "--expected-owner-uid",
                str(os.geteuid()),
            )
            value = json.loads(reverse.read_text(encoding="utf-8"))
            self.assertTrue(value["limits"]["automatic_reverse_on_failure"])
            self.assertEqual(value["limits"]["max_attempts_per_step"], 1)
            self.assertTrue(value["limits"]["migration_required"])
            self.assertFalse(
                value["limits"]["writer_exposure_after_database_mutation_allowed"]
            )
            self.assertTrue(value["limits"]["application_reverse_preserves_database"])
            self.assertEqual(
                value["limits"]["database_restore_policy"],
                "only-before-writer-exposure-after-observed-mutation",
            )
            self.assertEqual(
                value["limits"]["post_reverse_verification_timeout_seconds"], 120
            )
            self.assertEqual(
                sum(step["timeout_seconds"] for step in value["reverse_steps"])
                + 120,
                value["limits"]["total_timeout_seconds"],
            )
            self.assertEqual(len(value["forward_steps"]), 4)
            self.assertLessEqual(
                len(value["reverse_steps"]), value["limits"]["max_reverse_steps"]
            )
            self.assertEqual(
                value["reverse_steps"][0]["services"],
                ["control-api", "control-api-replica", "control-migrate"],
            )
            self.assertEqual(
                value["reverse_steps"][1]["condition"],
                "database-mutated-and-writers-never-reexposed",
            )
            api_step = next(
                step for step in value["reverse_steps"] if step.get("service") == "control-api"
            )
            self.assertEqual(api_step["previous"]["image_id"], f"sha256:{'6' * 64}")
            self.assertEqual(
                value["bindings"]["writer_unfreeze_plan_sha256"], sha256(unfreeze)
            )
            self.assertEqual(
                value["bindings"]["writer_freeze_receipt_sha256"], sha256(freeze)
            )
            rollback = json.loads(rollback_compose.read_text(encoding="utf-8"))
            self.assertEqual(
                rollback["services"]["control-api"]["image"], f"sha256:{'6' * 64}"
            )
            self.assertEqual(
                value["bindings"]["rollback_compose_sha256"], sha256(rollback_compose)
            )
            unfreeze_proof = fixture.root / "writer-unfreeze-proof.json"
            fixture.run(
                "writer-unfreeze-proof",
                "--current-control-containers",
                str(current),
                "--observed-control-containers",
                str(current),
                "--unfreeze-plan",
                str(unfreeze),
                "--output",
                str(unfreeze_proof),
                "--expected-owner-uid",
                str(os.geteuid()),
            )
            proof_value = json.loads(unfreeze_proof.read_text(encoding="utf-8"))
            self.assertTrue(proof_value["exact_container_ids_restored"])
            self.assertFalse(proof_value["database_restore_performed"])
            self.assertEqual(
                sum(step["timeout_seconds"] for step in unfreeze_value["steps"])
                + unfreeze_value["limits"][
                    "post_unfreeze_verification_timeout_seconds"
                ],
                unfreeze_value["limits"]["total_timeout_seconds"],
            )

    def test_recovery_schema_is_valid(self) -> None:
        try:
            import jsonschema
        except ImportError:
            self.skipTest("jsonschema is unavailable")
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        jsonschema.Draft202012Validator.check_schema(schema)


if __name__ == "__main__":
    unittest.main()
