from __future__ import annotations

import copy
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[3]
ADMISSION = REPO_ROOT / "deploy/scripts/bootstrap-admission.py"

API_IMAGE = f"sha256:{'a' * 64}"
PWA_IMAGE = f"sha256:{'b' * 64}"
BACKUP_IMAGE = f"sha256:{'c' * 64}"
SOURCE_REVISION = "d" * 40
RELEASE = "0.1.0-bootstrap.20260805T000000Z"
MIGRATION_HEAD = "20260731_0008"
TEST_BACKUP_UID = 65_534 if os.geteuid() == 0 else os.geteuid()
TEST_BACKUP_GID = 65_534 if os.getegid() == 0 else os.getegid()


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_json(path: Path, value: object, *, mode: int = 0o600) -> None:
    path.write_text(json.dumps(value, sort_keys=True), encoding="utf-8")
    path.chmod(mode)


def run_admission(
    *arguments: str, success: bool = True
) -> tuple[subprocess.CompletedProcess[str], dict[str, Any] | None]:
    result = subprocess.run(
        [sys.executable, str(ADMISSION), *arguments],
        check=False,
        capture_output=True,
        text=True,
    )
    if success:
        if result.returncode != 0:
            raise AssertionError(f"admission failed: {result.stderr}")
        lines = result.stdout.splitlines()
        if len(lines) != 1:
            raise AssertionError(
                f"success output is not one JSON line: {result.stdout!r}"
            )
        try:
            payload = json.loads(lines[0])
        except json.JSONDecodeError as exc:
            raise AssertionError(
                f"success output is not JSON: {result.stdout!r}"
            ) from exc
        if not isinstance(payload, dict):
            raise AssertionError("success output must be a JSON object")
        return result, payload
    if result.returncode == 0:
        raise AssertionError(f"admission unexpectedly succeeded: {result.stdout}")
    if result.stdout != "":
        raise AssertionError(f"failure emitted stdout: {result.stdout!r}")
    return result, None


def container_identities() -> dict[str, dict[str, str]]:
    return {
        name: {
            "container_id": character * 64,
            "image_id": f"sha256:{character * 64}",
            "name": name,
        }
        for name, character in (("sub2api", "1"), ("postgres", "2"), ("redis", "3"))
    }


def create_backup_receipt(
    root: Path, *, created_at: datetime | None = None
) -> tuple[Path, Path, Path, dict[str, dict[str, str]]]:
    created_at = created_at or datetime.now(UTC)
    backup_root = root / "production-backups"
    backup_root.mkdir(mode=0o700)
    snapshot = backup_root / "production-preflight-20260805T000000Z-fixture"
    snapshot.mkdir(mode=0o700)

    artifacts = {
        "sub2api-postgres.dump": b"PGDUMP-CUSTOM-FIXTURE\x00\x01",
        "redis-logical.rdb": b"REDIS0011fixture-rdb-payload",
        "nginx-effective-config.txt": b"events {}\nhttp {}\n",
    }
    for name, content in artifacts.items():
        path = snapshot / name
        path.write_bytes(content)
        path.chmod(0o600)

    identities = container_identities()
    record = {
        "schema_version": 1,
        "status": "ready",
        "created_at": created_at.isoformat().replace("+00:00", "Z"),
        "snapshot_directory": snapshot.name,
        "containers": identities,
        "sources": {},
        "redis": {
            "logical_rdb_validator": "redis-check-rdb",
            "persistence_path": "/data",
        },
        "artifacts": [
            {"path": name, "sha256": sha256(snapshot / name), "size": len(content)}
            for name, content in sorted(artifacts.items())
        ],
    }
    record_path = snapshot / "backup-record.json"
    write_json(record_path, record)

    manifest_members = sorted([*artifacts, record_path.name])
    manifest = snapshot / "manifest.sha256"
    manifest.write_text(
        "".join(f"{sha256(snapshot / name)}  {name}\n" for name in manifest_members),
        encoding="ascii",
    )
    manifest.chmod(0o600)
    manifest_sha = sha256(manifest)

    ready = snapshot / "READY.json"
    write_json(
        ready,
        {
            "schema_version": 1,
            "status": "ready",
            "manifest": manifest.name,
            "manifest_sha256": manifest_sha,
        },
    )
    result_file = root / "production-backup-result.json"
    write_json(
        result_file,
        {
            "schema_version": 1,
            "status": "ready",
            "snapshot_directory": str(snapshot),
            "manifest_sha256": manifest_sha,
        },
    )
    identities_path = root / "current-identities.json"
    write_json(
        identities_path,
        [
            {
                "Id": value["container_id"],
                "Image": value["image_id"],
                "Name": f"/{value['name']}",
                "State": {"Running": True},
            }
            for value in identities.values()
        ],
    )
    return result_file, snapshot, identities_path, identities


def refresh_backup_manifest(result_file: Path, snapshot: Path) -> None:
    record = json.loads((snapshot / "backup-record.json").read_text(encoding="utf-8"))
    artifact_names = [entry["path"] for entry in record["artifacts"]]
    manifest_names = sorted([*artifact_names, "backup-record.json"])
    manifest = snapshot / "manifest.sha256"
    manifest.write_text(
        "".join(f"{sha256(snapshot / name)}  {name}\n" for name in manifest_names),
        encoding="ascii",
    )
    manifest.chmod(0o600)
    manifest_sha = sha256(manifest)
    ready = json.loads((snapshot / "READY.json").read_text(encoding="utf-8"))
    ready["manifest_sha256"] = manifest_sha
    write_json(snapshot / "READY.json", ready)
    result = json.loads(result_file.read_text(encoding="utf-8"))
    result["manifest_sha256"] = manifest_sha
    write_json(result_file, result)


def hardened_service(image: str, component: str) -> dict[str, Any]:
    return {
        "image": image,
        "pull_policy": "never",
        "read_only": True,
        "tmpfs": ["/tmp:rw,noexec,nosuid,nodev,size=32m,mode=1777"],
        "cap_drop": ["ALL"],
        "security_opt": ["no-new-privileges:true"],
        "pids_limit": 128,
        "mem_limit": "512m",
        "cpus": 1.0,
        "init": True,
        "labels": {
            "org.opencontainers.image.version": RELEASE,
            "org.opencontainers.image.revision": SOURCE_REVISION,
            "org.opencontainers.image.source": "sub2api-codex-control",
            "com.sub2api-codex.component": component,
        },
    }


def compose_config(backup_dir: Path) -> dict[str, Any]:
    environment = {
        "CONTROL_ENVIRONMENT": "production",
        "CONTROL_API_PREFIX": "/v1",
        "CONTROL_EXTERNAL_API_BASE_PATH": "/codex-api",
        "CONTROL_BUILD_VERSION": RELEASE,
        "CONTROL_BUILD_VCS_REF": SOURCE_REVISION,
        "CONTROL_COOKIE_SECURE": "true",
        "CONTROL_COOKIE_SAMESITE": "strict",
        "CONTROL_COOKIE_NAME": "__Host-codex_control",
        "CONTROL_CSRF_COOKIE_NAME": "codex_csrf",
        "CONTROL_CSRF_HEADER_NAME": "x-csrf-token",
        "CONTROL_SUB2API_BASE_URL": "http://sub2api:8080",
        "CONTROL_SUB2API_AUTH_ME_PATH": "/api/v1/auth/me",
        "CONTROL_SUB2API_EXPECTED_VERSION": "0.1.175",
        "CONTROL_SUB2API_EXPECTED_COMMIT": "93c32fa",
        "CONTROL_SUB2API_CONTRACT_MARKER": "0.1.175/93c32fa",
        "CONTROL_TRUST_FORWARDED_FOR": "true",
        "CONTROL_ALLOWED_ORIGINS_CSV": "https://control.example.com",
        "CONTROL_DATABASE_PASSWORD_FILE": "/run/secrets/control_db_password",
        "CONTROL_REDIS_PASSWORD_FILE": "/run/secrets/control_redis_password",
        "CONTROL_SESSION_HMAC_SECRET_FILE": "/run/secrets/control_session_hmac_secret",
        "CONTROL_DB_HOST": "postgres",
        "CONTROL_DB_PORT": "5432",
        "CONTROL_DB_USER": "codex_control",
        "CONTROL_DB_NAME": "codex_control",
        "CONTROL_DB_QUERY": "",
        "CONTROL_REDIS_HOST": "redis",
        "CONTROL_REDIS_PORT": "6379",
        "CONTROL_REDIS_AUTH_MODE": "none",
        "CONTROL_REDIS_SCHEME": "redis",
        "CONTROL_REDIS_USER": "default",
        "CONTROL_REDIS_DATABASE": "0",
        "CONTROL_REDIS_QUERY": "",
        "CONTROL_REDIS_PREFIX": "codex-control:",
        "CONTROL_API_WORKERS": "1",
    }
    application_secrets = [
        {
            "source": "control_db_password",
            "target": "/run/secrets/control_db_password",
        },
        {
            "source": "control_redis_password",
            "target": "/run/secrets/control_redis_password",
        },
        {
            "source": "control_session_hmac_secret",
            "target": "/run/secrets/control_session_hmac_secret",
        },
    ]
    api = hardened_service(API_IMAGE, "control-api")
    api.update(
        {
            "command": ["api"],
            "environment": copy.deepcopy(environment),
            "secrets": copy.deepcopy(application_secrets),
            "networks": {"sub2api-network": {}},
            "ports": [
                {
                    "name": "control-api-loopback",
                    "mode": "ingress",
                    "host_ip": "127.0.0.1",
                    "target": 8090,
                    "published": "18090",
                    "protocol": "tcp",
                }
            ],
        }
    )
    replica = copy.deepcopy(api)
    replica["labels"]["com.sub2api-codex.component"] = "control-api-replica"
    replica["ports"][0].update(name="control-api-replica-loopback", published="18093")
    replica["profiles"] = ["multi-instance"]

    migrate = hardened_service(API_IMAGE, "control-migrate")
    migrate.update(
        {
            "command": ["migrate"],
            "environment": copy.deepcopy(environment),
            "secrets": copy.deepcopy(application_secrets),
            "networks": {"sub2api-network": {}},
        }
    )

    pwa = hardened_service(PWA_IMAGE, "pwa")
    pwa.update(
        {
            "networks": {"pwa-network": {}},
            "ports": [
                {
                    "name": "pwa-loopback",
                    "mode": "ingress",
                    "host_ip": "127.0.0.1",
                    "target": 8080,
                    "published": "18091",
                    "protocol": "tcp",
                }
            ],
        }
    )

    backup = hardened_service(BACKUP_IMAGE, "control-backup")
    backup.update(
        {
            "profiles": ["ops"],
            "environment": {
                "BACKUP_DIR": "/backups",
                "CONTROL_DATABASE_PASSWORD_FILE": "/run/secrets/control_db_password",
                "CONTROL_DB_HOST": "postgres",
                "CONTROL_DB_PORT": "5432",
                "CONTROL_DB_USER": "codex_control",
                "CONTROL_DB_NAME": "codex_control",
            },
            "secrets": [copy.deepcopy(application_secrets[0])],
            "networks": {"sub2api-network": {}},
            "volumes": [
                {"type": "bind", "source": str(backup_dir), "target": "/backups"}
            ],
            "user": f"{TEST_BACKUP_UID}:{TEST_BACKUP_GID}",
        }
    )
    return {
        "name": "sub2api-codex-control",
        "services": {
            "control-migrate": migrate,
            "control-api": api,
            "control-api-replica": replica,
            "codex-pwa": pwa,
            "control-backup": backup,
        },
        "secrets": {
            "control_db_password": {
                "name": "control_db_password",
                "file": "/secure/control_db_password",
            },
            "control_redis_password": {
                "name": "control_redis_password",
                "file": "/secure/control_redis_password",
            },
            "control_session_hmac_secret": {
                "name": "control_session_hmac_secret",
                "file": "/secure/control_session_hmac_secret",
            },
        },
        "networks": {
            "sub2api-network": {
                "name": "sub2api-network",
                "external": True,
            },
            "pwa-network": {
                "name": "sub2api-codex-control_pwa-network",
                "driver": "bridge",
                "driver_opts": {
                    "com.docker.network.bridge.enable_ip_masquerade": "false",
                    "com.docker.network.bridge.enable_icc": "false",
                },
            },
        },
    }


def write_migration_fixture(repo: Path) -> None:
    versions = repo / "migrations/versions"
    versions.mkdir(parents=True)
    (repo / "migrations/alembic.ini").write_text("[alembic]\n", encoding="ascii")
    (versions / f"{MIGRATION_HEAD}_fixture.py").write_text(
        textwrap.dedent(
            f'''\
            """Bootstrap target fixture."""

            revision: str = "{MIGRATION_HEAD}"
            down_revision: str | None = None
            '''
        ),
        encoding="ascii",
    )


def image_inspect(
    reference: str, component: str, *, source: str = "sub2api-codex-control"
) -> list[dict[str, Any]]:
    return [
        {
            "Id": reference,
            "RepoDigests": [],
            "Architecture": "amd64",
            "Os": "linux",
            "Created": "2026-08-05T00:00:00Z",
            "Config": {
                "User": "10001:10001" if reference == API_IMAGE else "postgres",
                "Labels": {
                    "org.opencontainers.image.version": RELEASE,
                    "org.opencontainers.image.revision": SOURCE_REVISION,
                    "org.opencontainers.image.source": source,
                    "com.sub2api-codex.component": component,
                },
            },
        }
    ]


def running_container_inspect(
    image_id: str,
    container_character: str,
    *,
    target_port: int,
    published_port: str,
    network: str,
) -> list[dict[str, Any]]:
    network_id = "8" * 64 if network.endswith("pwa-network") else "9" * 64
    endpoint_id = container_character * 64
    return [
        {
            "Id": container_character * 64,
            "Name": f"/{'codex-pwa' if network.endswith('pwa-network') else 'api'}",
            "Image": image_id,
            "HostConfig": {
                "ReadonlyRootfs": True,
                "Privileged": False,
                "CapAdd": None,
                "CapDrop": ["ALL"],
                "SecurityOpt": ["no-new-privileges:true"],
                "PortBindings": {
                    f"{target_port}/tcp": [
                        {"HostIp": "127.0.0.1", "HostPort": published_port}
                    ]
                },
            },
            "State": {"Running": True, "Health": {"Status": "healthy"}},
            "NetworkSettings": {
                "Ports": {
                    f"{target_port}/tcp": [
                        {"HostIp": "127.0.0.1", "HostPort": published_port}
                    ]
                },
                "Networks": {
                    network: {"NetworkID": network_id, "EndpointID": endpoint_id}
                },
            },
        }
    ]


def pwa_network_inspect(network: str, container_id: str) -> list[dict[str, Any]]:
    return [
        {
            "Name": network,
            "Id": "8" * 64,
            "Scope": "local",
            "Driver": "bridge",
            "Internal": False,
            "Attachable": False,
            "Ingress": False,
            "ConfigOnly": False,
            "EnableIPv6": False,
            "Options": {
                "com.docker.network.bridge.enable_ip_masquerade": "false",
                "com.docker.network.bridge.enable_icc": "false",
            },
            "Labels": {
                "com.docker.compose.project": "sub2api-codex-control",
                "com.docker.compose.network": "pwa-network",
            },
            "Containers": {container_id: {"Name": "codex-pwa", "EndpointID": "6" * 64}},
        }
    ]


FAKE_DOCKER = r"""#!/usr/bin/env python3
import os
import pathlib
import sys

arguments = sys.argv[1:]
pathlib.Path(os.environ["FAKE_DOCKER_LOG"]).write_text(
    repr(arguments) + "\n", encoding="utf-8"
)
required = ("run", "--rm", "--entrypoint", "pg_restore", "--list")
if not all(value in arguments for value in required):
    raise SystemExit(64)
if os.environ["EXPECTED_POSTGRES_TOOLS_IMAGE"] not in arguments:
    raise SystemExit(65)
sys.stdout.buffer.write(pathlib.Path(os.environ["FAKE_BACKUP_MANIFEST"]).read_bytes())
"""


class BackupReceiptTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        (
            self.result_file,
            self.snapshot,
            self.identities_file,
            self.identities,
        ) = create_backup_receipt(self.root)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def invoke(self, *, success: bool = True) -> dict[str, Any] | None:
        _, value = run_admission(
            "backup-receipt",
            "--result-file",
            str(self.result_file),
            "--max-age-seconds",
            "900",
            "--current-identities",
            str(self.identities_file),
            success=success,
        )
        return value

    def test_accepts_fresh_complete_snapshot_with_stable_container_identities(
        self,
    ) -> None:
        value = self.invoke()
        assert value is not None
        self.assertEqual(value["status"], "admitted")
        self.assertEqual(value["snapshot_directory"], str(self.snapshot))
        self.assertEqual(
            value["manifest_sha256"], sha256(self.snapshot / "manifest.sha256")
        )

    def test_rejects_tampered_artifact_and_tampered_manifest(self) -> None:
        artifact = self.snapshot / "redis-logical.rdb"
        artifact.write_bytes(artifact.read_bytes() + b"tampered")
        artifact.chmod(0o600)
        self.invoke(success=False)

        self.temporary.cleanup()
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        (
            self.result_file,
            self.snapshot,
            self.identities_file,
            self.identities,
        ) = create_backup_receipt(self.root)
        manifest = self.snapshot / "manifest.sha256"
        manifest.write_text(
            manifest.read_text(encoding="ascii") + "\n", encoding="ascii"
        )
        manifest.chmod(0o600)
        self.invoke(success=False)

    def test_rejects_stale_snapshot_even_when_all_hashes_are_consistent(self) -> None:
        record_path = self.snapshot / "backup-record.json"
        record = json.loads(record_path.read_text(encoding="utf-8"))
        record["created_at"] = (
            (datetime.now(UTC) - timedelta(hours=2)).isoformat().replace("+00:00", "Z")
        )
        write_json(record_path, record)
        refresh_backup_manifest(self.result_file, self.snapshot)
        old = time.time() - 7200
        for path in [self.result_file, *self.snapshot.iterdir(), self.snapshot]:
            os.utime(path, (old, old), follow_symlinks=False)
        self.invoke(success=False)

    def test_rejects_identity_drift_after_the_snapshot(self) -> None:
        current = [
            {
                "Id": value["container_id"],
                "Image": value["image_id"],
                "Name": f"/{value['name']}",
                "State": {"Running": True},
            }
            for value in self.identities.values()
        ]
        current[0]["Id"] = "9" * 64
        write_json(self.identities_file, current)
        self.invoke(success=False)

    def test_fresh_max_age_cannot_be_used_as_stale_override(self) -> None:
        run_admission(
            "backup-receipt",
            "--result-file",
            str(self.result_file),
            "--max-age-seconds",
            "691200",
            "--current-identities",
            str(self.identities_file),
            success=False,
        )

    def test_current_container_identities_are_mandatory(self) -> None:
        run_admission(
            "backup-receipt",
            "--result-file",
            str(self.result_file),
            "--max-age-seconds",
            "1800",
            success=False,
        )

class ControlBackupTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.directory = self.root / "control-backups"
        self.directory.mkdir(mode=0o700)
        self.dump = self.directory / "codex-control-20260805T000000Z-fixture.dump"
        self.manifest = (
            self.directory / "codex-control-20260805T000000Z-fixture.contents.txt"
        )
        self.checksum = self.directory / "codex-control-20260805T000000Z-fixture.sha256"
        self.dump.write_bytes(b"PGDUMP-CUSTOM-CONTROL-FIXTURE\x00\x01")
        self.manifest.write_text(
            "1; 0 0 TABLE public devices codex_control\n", encoding="utf-8"
        )
        self.checksum.write_text(
            f"{sha256(self.dump)}  {self.dump.name}\n", encoding="ascii"
        )
        for path in (self.dump, self.manifest, self.checksum):
            path.chmod(0o600)
        self.docker = self.root / "docker"
        self.docker.write_text(textwrap.dedent(FAKE_DOCKER), encoding="utf-8")
        self.docker.chmod(0o700)
        self.docker_log = self.root / "docker.log"
        self.environment = os.environ.copy()
        self.environment.update(
            {
                "EXPECTED_POSTGRES_TOOLS_IMAGE": BACKUP_IMAGE,
                "FAKE_BACKUP_MANIFEST": str(self.manifest),
                "FAKE_DOCKER_LOG": str(self.docker_log),
            }
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def invoke(
        self,
        *,
        not_before: float | None = None,
        max_age_seconds: int = 300,
        success: bool = True,
    ) -> dict[str, Any] | None:
        not_before = not_before if not_before is not None else time.time() - 5
        result = subprocess.run(
            [
                sys.executable,
                str(ADMISSION),
                "control-backup",
                "--directory",
                str(self.directory),
                "--not-before",
                str(not_before),
                "--max-age-seconds",
                str(max_age_seconds),
                "--expected-owner-uid",
                str(os.geteuid()),
                "--postgres-tools-image",
                BACKUP_IMAGE,
                "--docker",
                str(self.docker),
            ],
            check=False,
            capture_output=True,
            text=True,
            env=self.environment,
        )
        if success:
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(len(result.stdout.splitlines()), 1, result.stdout)
            value = json.loads(result.stdout)
            self.assertIsInstance(value, dict)
            return value
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertEqual(result.stdout, "")
        return None

    def test_accepts_one_fresh_private_checksum_and_restore_validated_backup(
        self,
    ) -> None:
        value = self.invoke()
        assert value is not None
        self.assertEqual(Path(value["dump_path"]).resolve(), self.dump.resolve())
        self.assertEqual(value["dump_sha256"], sha256(self.dump))
        command = self.docker_log.read_text(encoding="utf-8")
        self.assertIn("pg_restore", command)
        self.assertIn(BACKUP_IMAGE, command)

    def test_rejects_tampered_dump(self) -> None:
        self.dump.write_bytes(self.dump.read_bytes() + b"tampered")
        self.dump.chmod(0o600)
        self.invoke(success=False)

    def test_rejects_stale_backup(self) -> None:
        old = time.time() - 3600
        for path in (self.dump, self.manifest, self.checksum):
            os.utime(path, (old, old))
        self.invoke(not_before=old - 5, max_age_seconds=60, success=False)


class ComposePlanTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.repo = self.root / "source"
        self.repo.mkdir()
        write_migration_fixture(self.repo)
        self.backup = self.root / "production-backups"
        self.backup.mkdir(mode=0o700)
        if os.geteuid() == 0:
            os.chown(self.backup, TEST_BACKUP_UID, TEST_BACKUP_GID)
        self.config_path = self.root / "compose.json"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def invoke(
        self, config: dict[str, Any], *, success: bool = True
    ) -> dict[str, Any] | None:
        write_json(self.config_path, config)
        _, value = run_admission(
            "compose-plan",
            "--compose-config",
            str(self.config_path),
            "--repo-root",
            str(self.repo),
            "--expected-backup-user",
            f"{TEST_BACKUP_UID}:{TEST_BACKUP_GID}",
            success=success,
        )
        return value

    def test_accepts_immutable_hardened_production_compose(self) -> None:
        value = self.invoke(compose_config(self.backup))
        assert value is not None
        self.assertEqual(value["api_image"], API_IMAGE)
        self.assertEqual(value["pwa_image"], PWA_IMAGE)
        self.assertEqual(value["backup_image"], BACKUP_IMAGE)
        self.assertEqual(value["release"], RELEASE)
        self.assertEqual(value["source_revision"], SOURCE_REVISION)
        self.assertEqual(value["target_migration_head"], MIGRATION_HEAD)
        self.assertEqual(value["backup_user"], f"{TEST_BACKUP_UID}:{TEST_BACKUP_GID}")
        self.assertEqual(value["redis_prefix"], "codex-control:")
        self.assertEqual(value["pwa_network_driver"], "bridge")
        self.assertEqual(
            value["pwa_network_driver_opts"],
            {
                "com.docker.network.bridge.enable_ip_masquerade": "false",
                "com.docker.network.bridge.enable_icc": "false",
            },
        )
        self.assertEqual(
            value["secret_files"]["control_db_password"],
            "/secure/control_db_password",
        )

    def test_rejects_local_tags_and_build_definitions(self) -> None:
        for label, mutate in (
            (
                "local tag",
                lambda value: value["services"]["control-api"].update(
                    image="sub2api-codex-control-api:local"
                ),
            ),
            (
                "build definition",
                lambda value: value["services"]["codex-pwa"].update(
                    build={"context": str(self.repo)}
                ),
            ),
        ):
            with self.subTest(label=label):
                config = compose_config(self.backup)
                mutate(config)
                self.invoke(config, success=False)

    def test_rejects_each_insecure_pwa_network_shape(self) -> None:
        mutations = {
            "internal network": lambda network: network.update(internal=True),
            "missing ICC option": lambda network: network["driver_opts"].pop(
                "com.docker.network.bridge.enable_icc"
            ),
            "masquerading enabled": lambda network: network["driver_opts"].update(
                **{"com.docker.network.bridge.enable_ip_masquerade": "true"}
            ),
            "ICC enabled": lambda network: network["driver_opts"].update(
                **{"com.docker.network.bridge.enable_icc": "true"}
            ),
            "extra driver option": lambda network: network["driver_opts"].update(
                **{"com.docker.network.bridge.name": "codex-pwa"}
            ),
        }
        for label, mutate in mutations.items():
            with self.subTest(label=label):
                config = compose_config(self.backup)
                mutate(config["networks"]["pwa-network"])
                self.invoke(config, success=False)

    def test_rejects_non_hardened_or_exposed_services(self) -> None:
        mutations: dict[str, Callable[[dict[str, Any]], None]] = {
            "writable root": lambda value: value["services"]["control-api"].update(
                read_only=False
            ),
            "retained capability": lambda value: value["services"]["codex-pwa"].update(
                cap_drop=[]
            ),
            "privilege escalation": lambda value: value["services"][
                "control-backup"
            ].update(security_opt=[]),
            "public API": lambda value: value["services"]["control-api"]["ports"][
                0
            ].update(host_ip="0.0.0.0"),
            "wrong primary port": lambda value: value["services"]["control-api"][
                "ports"
            ][0].update(published="19090"),
            "wrong replica port": lambda value: value["services"][
                "control-api-replica"
            ]["ports"][0].update(published="19093"),
            "wrong PWA port": lambda value: value["services"]["codex-pwa"]["ports"][
                0
            ].update(published="19091"),
            "wrong external network": lambda value: value["networks"][
                "sub2api-network"
            ].update(name="other-network"),
        }
        for label, mutate in mutations.items():
            with self.subTest(label=label):
                config = compose_config(self.backup)
                mutate(config)
                self.invoke(config, success=False)

    def test_rejects_backup_directory_inside_source_checkout(self) -> None:
        checkout_backup = self.repo / "backups"
        checkout_backup.mkdir(mode=0o700)
        self.invoke(compose_config(checkout_backup), success=False)

    def test_rejects_unexpected_backup_identity(self) -> None:
        config = compose_config(self.backup)
        config["services"]["control-backup"]["user"] = "71:71"
        self.invoke(config, success=False)


class RuntimeSecretTests(unittest.TestCase):
    def create_secrets(self, root: Path) -> tuple[Path, Path, Path, int, int, int]:
        parent = root / "runtime-secrets"
        parent.mkdir(mode=0o700)
        api_uid = TEST_BACKUP_UID
        api_gid = TEST_BACKUP_GID
        backup_uid = TEST_BACKUP_UID
        values = (
            (parent / "control_db_password", 0o440, backup_uid, api_gid),
            (parent / "control_redis_password", 0o400, api_uid, api_gid),
            (parent / "control_session_hmac_secret", 0o400, api_uid, api_gid),
        )
        for path, mode, uid, gid in values:
            path.write_text("fixture-secret-value\n", encoding="ascii")
            path.chmod(mode)
            if os.geteuid() == 0:
                path.chown(uid, gid)
        return (*[value[0] for value in values], api_uid, api_gid, backup_uid)

    def invoke(
        self,
        database: Path,
        redis: Path,
        session: Path,
        api_uid: int,
        api_gid: int,
        backup_uid: int,
        *,
        success: bool = True,
    ) -> tuple[subprocess.CompletedProcess[str], dict[str, Any] | None]:
        return run_admission(
            "runtime-secrets",
            "--database-secret",
            str(database),
            "--redis-secret",
            str(redis),
            "--session-secret",
            str(session),
            "--api-uid",
            str(api_uid),
            "--api-gid",
            str(api_gid),
            "--backup-uid",
            str(backup_uid),
            "--parent-uid",
            str(os.geteuid()),
            "--parent-gid",
            str(os.getegid()),
            success=success,
        )

    def test_admits_least_privilege_shared_database_secret(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            values = self.create_secrets(Path(temporary))
            _, payload = self.invoke(*values)
            assert payload is not None
            self.assertEqual(payload["status"], "admitted")
            self.assertEqual(payload["secrets"]["database"]["mode"], "0440")
            self.assertEqual(
                payload["secrets"]["database"]["readers"],
                ["control-api", "control-backup"],
            )
            self.assertEqual(payload["secrets"]["redis"]["mode"], "0400")

    def test_rejects_owner_writable_runtime_secret(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            values = self.create_secrets(Path(temporary))
            values[0].chmod(0o640)
            result, _ = self.invoke(*values, success=False)
            self.assertIn("mode must be exactly 0440", result.stderr)

    def test_rejects_hardlinked_runtime_secret(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            values = self.create_secrets(Path(temporary))
            os.link(values[0], values[0].with_name("database-hardlink"))
            result, _ = self.invoke(*values, success=False)
            self.assertIn("exactly one hard link", result.stderr)


class BootstrapImageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.repo = self.root / "source"
        self.repo.mkdir()
        write_migration_fixture(self.repo)
        self.backup = self.root / "production-backups"
        self.backup.mkdir(mode=0o700)
        if os.geteuid() == 0:
            os.chown(self.backup, TEST_BACKUP_UID, TEST_BACKUP_GID)
        self.compose_path = self.root / "compose.json"
        write_json(self.compose_path, compose_config(self.backup))
        _, plan = run_admission(
            "compose-plan",
            "--compose-config",
            str(self.compose_path),
            "--repo-root",
            str(self.repo),
            "--expected-backup-user",
            f"{TEST_BACKUP_UID}:{TEST_BACKUP_GID}",
        )
        assert plan is not None
        self.plan_path = self.root / "plan.json"
        write_json(self.plan_path, plan)
        self.api_path = self.root / "api-inspect.json"
        self.pwa_path = self.root / "pwa-inspect.json"
        self.backup_path = self.root / "backup-inspect.json"
        self.write_valid_inspects()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write_valid_inspects(self) -> None:
        write_json(self.api_path, image_inspect(API_IMAGE, "control-api"))
        write_json(self.pwa_path, image_inspect(PWA_IMAGE, "pwa"))
        write_json(self.backup_path, image_inspect(BACKUP_IMAGE, "control-backup"))

    def invoke(self, *, success: bool = True) -> dict[str, Any] | None:
        _, value = run_admission(
            "images",
            "--plan",
            str(self.plan_path),
            "--api-inspect",
            str(self.api_path),
            "--pwa-inspect",
            str(self.pwa_path),
            "--backup-inspect",
            str(self.backup_path),
            success=success,
        )
        return value

    def test_accepts_exact_linux_amd64_image_ids_and_oci_labels(self) -> None:
        value = self.invoke()
        assert value is not None
        self.assertEqual(value["api"]["image_id"], API_IMAGE)
        self.assertEqual(value["pwa"]["image_id"], PWA_IMAGE)
        self.assertEqual(value["backup"]["image_id"], BACKUP_IMAGE)

    def test_rejects_image_id_mismatch(self) -> None:
        invalid = image_inspect(f"sha256:{'9' * 64}", "control-api")
        write_json(self.api_path, invalid)
        self.invoke(success=False)

    def test_rejects_api_image_runtime_user_drift(self) -> None:
        invalid = image_inspect(API_IMAGE, "control-api")
        invalid[0]["Config"]["User"] = "0:0"
        write_json(self.api_path, invalid)
        self.invoke(success=False)

    def test_rejects_wrong_architecture_or_os(self) -> None:
        for label, key, value in (
            ("architecture", "Architecture", "arm64"),
            ("operating system", "Os", "windows"),
        ):
            with self.subTest(label=label):
                self.write_valid_inspects()
                invalid = image_inspect(PWA_IMAGE, "pwa")
                invalid[0][key] = value
                write_json(self.pwa_path, invalid)
                self.invoke(success=False)

    def test_rejects_mismatched_or_placeholder_oci_labels(self) -> None:
        for label, key, value in (
            ("release", "org.opencontainers.image.version", "wrong"),
            ("revision", "org.opencontainers.image.revision", "0" * 40),
            ("source", "org.opencontainers.image.source", "unknown"),
        ):
            with self.subTest(label=label):
                self.write_valid_inspects()
                invalid = image_inspect(BACKUP_IMAGE, "control-backup")
                invalid[0]["Config"]["Labels"][key] = value
                write_json(self.backup_path, invalid)
                self.invoke(success=False)

    def running_arguments(self) -> tuple[list[str], dict[str, Path]]:
        image_evidence = self.invoke()
        assert image_evidence is not None
        images_path = self.root / "images.json"
        write_json(images_path, image_evidence)
        paths = {
            "control-api": self.root / "running-api.json",
            "control-api-replica": self.root / "running-api-replica.json",
            "codex-pwa": self.root / "running-pwa.json",
            "pwa-network": self.root / "running-pwa-network.json",
        }
        write_json(
            paths["control-api"],
            running_container_inspect(
                API_IMAGE,
                "4",
                target_port=8090,
                published_port="18090",
                network="sub2api-network",
            ),
        )
        write_json(
            paths["control-api-replica"],
            running_container_inspect(
                API_IMAGE,
                "5",
                target_port=8090,
                published_port="18093",
                network="sub2api-network",
            ),
        )
        write_json(
            paths["codex-pwa"],
            running_container_inspect(
                PWA_IMAGE,
                "6",
                target_port=8080,
                published_port="18091",
                network="sub2api-codex-control_pwa-network",
            ),
        )
        write_json(
            paths["pwa-network"],
            pwa_network_inspect("sub2api-codex-control_pwa-network", "6" * 64),
        )
        return (
            [
                "running",
                "--plan",
                str(self.plan_path),
                "--images",
                str(images_path),
                "--api-inspect",
                str(paths["control-api"]),
                "--api-replica-inspect",
                str(paths["control-api-replica"]),
                "--pwa-inspect",
                str(paths["codex-pwa"]),
                "--pwa-network-inspect",
                str(paths["pwa-network"]),
            ],
            paths,
        )

    def test_accepts_running_healthy_containers_bound_to_admitted_images(self) -> None:
        arguments, _ = self.running_arguments()
        _, value = run_admission(*arguments)
        assert value is not None
        self.assertEqual(value["status"], "admitted")
        self.assertEqual(
            set(value["containers"]),
            {"control-api", "control-api-replica", "codex-pwa"},
        )
        self.assertEqual(value["pwa_network"]["container_id"], "6" * 64)

    def test_rejects_running_container_image_drift(self) -> None:
        arguments, paths = self.running_arguments()
        replica = json.loads(paths["control-api-replica"].read_text(encoding="utf-8"))
        replica[0]["Image"] = f"sha256:{'9' * 64}"
        write_json(paths["control-api-replica"], replica)
        run_admission(*arguments, success=False)

    def test_rejects_runtime_pwa_port_or_network_boundary_drift(self) -> None:
        labels = (
            "missing runtime mapping",
            "internal runtime network",
            "runtime masquerading enabled",
            "unexpected network member",
        )
        for label in labels:
            with self.subTest(label=label):
                arguments, paths = self.running_arguments()
                path = (
                    paths["codex-pwa"]
                    if label == "missing runtime mapping"
                    else paths["pwa-network"]
                )
                value = json.loads(path.read_text(encoding="utf-8"))
                if label == "missing runtime mapping":
                    value[0]["NetworkSettings"]["Ports"] = {"8080/tcp": None}
                elif label == "internal runtime network":
                    value[0]["Internal"] = True
                elif label == "runtime masquerading enabled":
                    value[0]["Options"][
                        "com.docker.network.bridge.enable_ip_masquerade"
                    ] = "true"
                else:
                    value[0]["Containers"]["7" * 64] = {"Name": "unexpected"}
                write_json(path, value)
                run_admission(*arguments, success=False)


class APIImageContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.observed = self.root / "observed.json"
        self.images = self.root / "images.json"
        self.versions_lock = self.root / "versions.lock.json"
        self.expected = {
            "appserver_schema_digest": "5" * 64,
            "codex_expected_version": "0.147.0",
            "sub2api_expected_commit": "93c32fa",
            "sub2api_expected_version": "0.1.175",
        }
        write_json(
            self.versions_lock,
            {
                "codex": {
                    "cli_version": self.expected["codex_expected_version"],
                    "schema_sha256": self.expected["appserver_schema_digest"],
                },
                "sub2api": {
                    "runtime_version": self.expected["sub2api_expected_version"],
                    "runtime_commit": "93c32fa" + "b" * 33,
                },
            },
        )
        write_json(
            self.images,
            {
                "format_version": 1,
                "status": "admitted",
                "api": {"image_id": API_IMAGE},
            },
        )
        write_json(self.observed, self.expected)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def invoke(
        self, *, success: bool = True
    ) -> tuple[subprocess.CompletedProcess[str], dict[str, Any] | None]:
        return run_admission(
            "api-image-contract",
            "--observed",
            str(self.observed),
            "--images",
            str(self.images),
            "--versions-lock",
            str(self.versions_lock),
            "--expected-image",
            API_IMAGE,
            success=success,
        )

    def test_admits_exact_embedded_tuple_derived_from_versions_lock(self) -> None:
        _, payload = self.invoke()
        assert payload is not None
        self.assertEqual(payload["status"], "admitted")
        self.assertEqual(payload["api_image"], API_IMAGE)
        self.assertEqual(payload["expected"], self.expected)
        self.assertEqual(payload["observed"], self.expected)
        self.assertEqual(payload["images_sha256"], sha256(self.images))
        self.assertEqual(payload["versions_lock_sha256"], sha256(self.versions_lock))

    def test_rejects_previous_0146_0171_api_image_tuple(self) -> None:
        write_json(
            self.observed,
            {
                "appserver_schema_digest": (
                    "ac97e738de5f8ad47db3fdce8492f9a37e42da729eb4bbbfabec38f8b88a145c"
                ),
                "codex_expected_version": "0.146.0",
                "sub2api_expected_commit": "f0e7a9c",
                "sub2api_expected_version": "0.1.171",
            },
        )
        result, _ = self.invoke(success=False)
        self.assertIn("API image embedded contract differs", result.stderr)
        self.assertIn("codex_expected_version", result.stderr)
        self.assertIn("sub2api_expected_version", result.stderr)

    def test_rejects_probe_image_that_is_not_admitted(self) -> None:
        write_json(
            self.images,
            {
                "format_version": 1,
                "status": "admitted",
                "api": {"image_id": PWA_IMAGE},
            },
        )
        result, _ = self.invoke(success=False)
        self.assertIn("did not use the admitted API image ID", result.stderr)

    def test_rejects_unexpected_observation_fields_or_invalid_lock_tuple(self) -> None:
        invalid_observed = dict(self.expected)
        invalid_observed["unchecked"] = "value"
        write_json(self.observed, invalid_observed)
        result, _ = self.invoke(success=False)
        self.assertIn("unexpected fields", result.stderr)

        write_json(self.observed, self.expected)
        lock = json.loads(self.versions_lock.read_text(encoding="utf-8"))
        lock["sub2api"]["runtime_commit"] = "93c32fa"
        write_json(self.versions_lock, lock)
        result, _ = self.invoke(success=False)
        self.assertIn("invalid Codex or Sub2API contract tuple", result.stderr)


def pristine_database_evidence() -> dict[str, Any]:
    return {
        "schema_version": 1,
        "database": "codex_control",
        "role": "codex_control",
        "before": {"database_exists": False, "role_exists": False},
        "after": {
            "database_exists": True,
            "role_exists": True,
            "alembic_version_exists": False,
            "tables": [],
            "views": [],
            "sequences": [],
        },
        "target_migration_head": MIGRATION_HEAD,
    }


class PristineDatabaseTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.evidence_path = self.root / "pristine-db.json"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def invoke(
        self, evidence: dict[str, Any], *, success: bool = True
    ) -> dict[str, Any] | None:
        write_json(self.evidence_path, evidence)
        _, value = run_admission(
            "pristine-db",
            "--evidence",
            str(self.evidence_path),
            success=success,
        )
        return value

    def test_accepts_new_empty_control_database_at_the_locked_target_head(self) -> None:
        value = self.invoke(pristine_database_evidence())
        assert value is not None
        self.assertEqual(value["database"], "codex_control")
        self.assertEqual(value["role"], "codex_control")
        self.assertEqual(value["target_migration_head"], MIGRATION_HEAD)

    def test_rejects_non_pristine_database_or_preexisting_role(self) -> None:
        mutations: dict[str, Callable[[dict[str, Any]], None]] = {
            "database existed before provisioning": lambda value: value[
                "before"
            ].update(database_exists=True),
            "role existed before provisioning": lambda value: value["before"].update(
                role_exists=True
            ),
            "alembic table exists": lambda value: value["after"].update(
                alembic_version_exists=True
            ),
            "application table exists": lambda value: value["after"]["tables"].append(
                "users"
            ),
            "view exists": lambda value: value["after"]["views"].append("active_users"),
            "sequence exists": lambda value: value["after"]["sequences"].append(
                "users_id_seq"
            ),
        }
        for label, mutate in mutations.items():
            with self.subTest(label=label):
                evidence = pristine_database_evidence()
                mutate(evidence)
                self.invoke(evidence, success=False)

    def test_rejects_wrong_target_migration_head(self) -> None:
        evidence = pristine_database_evidence()
        evidence["target_migration_head"] = "20260731_0007"
        self.invoke(evidence, success=False)


def postgres_boundary_evidence(*, public_connect: bool = True) -> dict[str, Any]:
    acl_sha256 = "e" * 64
    return {
        "schema_version": 1,
        "database": "codex_control",
        "role": "codex_control",
        "sub2api_database": "sub2api",
        "allow_sub2api_public_connect": public_connect,
        "before": {
            "database_exists": False,
            "role_exists": False,
            "sub2api_public_connect": public_connect,
            "sub2api_database_acl_sha256": acl_sha256,
        },
        "after": {
            "database_exists": True,
            "role_exists": True,
            "database_owner": "codex_control",
            "sub2api_public_connect": public_connect,
            "sub2api_database_acl_sha256": acl_sha256,
            "role_memberships": 0,
            "direct_database_acl_privileges": 0,
            "direct_schema_acl_privileges": 0,
            "direct_relation_acl_privileges": 0,
            "owned_schemas": 0,
            "owned_relations": 0,
            "effective_relation_privileges": 0,
            "effective_sequence_privileges": 0,
            "effective_schema_create_privileges": 0,
        },
    }


class PostgresBoundaryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.evidence_path = Path(self.temporary.name) / "postgres-boundary.json"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def invoke(
        self, evidence: dict[str, Any], *, success: bool = True
    ) -> dict[str, Any] | None:
        write_json(self.evidence_path, evidence)
        _, value = run_admission(
            "postgres-boundary",
            "--evidence",
            str(self.evidence_path),
            success=success,
        )
        return value

    def test_accepts_explicit_public_connect_exception_with_zero_privileges(
        self,
    ) -> None:
        value = self.invoke(postgres_boundary_evidence())
        assert value is not None
        self.assertTrue(value["sub2api_public_connect"])
        self.assertTrue(value["public_connect_exception_recorded"])
        self.assertEqual(value["role_memberships"], 0)

    def test_accepts_revoked_public_connect_without_exception(self) -> None:
        value = self.invoke(postgres_boundary_evidence(public_connect=False))
        assert value is not None
        self.assertFalse(value["public_connect_exception_recorded"])

    def test_rejects_public_connect_without_exact_exception(self) -> None:
        evidence = postgres_boundary_evidence()
        evidence["allow_sub2api_public_connect"] = False
        self.invoke(evidence, success=False)

    def test_rejects_acl_drift_membership_or_sub2api_privilege(self) -> None:
        mutations: dict[str, Callable[[dict[str, Any]], None]] = {
            "database ACL drift": lambda value: value["after"].update(
                sub2api_database_acl_sha256="f" * 64
            ),
            "membership": lambda value: value["after"].update(role_memberships=1),
            "schema grant": lambda value: value["after"].update(
                direct_schema_acl_privileges=1
            ),
            "table grant": lambda value: value["after"].update(
                effective_relation_privileges=1
            ),
        }
        for label, mutate in mutations.items():
            with self.subTest(label=label):
                evidence = postgres_boundary_evidence()
                mutate(evidence)
                self.invoke(evidence, success=False)


if __name__ == "__main__":
    unittest.main()
