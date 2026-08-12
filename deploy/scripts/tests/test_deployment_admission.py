from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import os
import stat
import subprocess
import sys
import tempfile
import time
import types
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Self
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[3]
ADMISSION = REPO_ROOT / "deploy/scripts/deployment-admission.py"
RUNTIME = REPO_ROOT / "deploy/scripts/verify-sub2api-runtime.py"
DEPLOY = REPO_ROOT / "deploy/scripts/deploy-production.sh"
BACKUP_SCRIPT = REPO_ROOT / "deploy/scripts/backup-control-db.sh"
PROBE = REPO_ROOT / "deploy/scripts/probe-sub2api-auth-contract.py"
ADMISSION_SPEC = importlib.util.spec_from_file_location(
    "deployment_admission", ADMISSION
)
assert ADMISSION_SPEC is not None and ADMISSION_SPEC.loader is not None
ADMISSION_MODULE = importlib.util.module_from_spec(ADMISSION_SPEC)
ADMISSION_SPEC.loader.exec_module(ADMISSION_MODULE)
PROBE_SPEC = importlib.util.spec_from_file_location(
    "probe_sub2api_auth_contract", PROBE
)
assert PROBE_SPEC is not None and PROBE_SPEC.loader is not None
PROBE_MODULE = importlib.util.module_from_spec(PROBE_SPEC)
PROBE_SPEC.loader.exec_module(PROBE_MODULE)

API_REF = f"registry.example/control-api@sha256:{'a' * 64}"
PWA_REF = f"registry.example/control-pwa@sha256:{'b' * 64}"
BACKUP_REF = f"registry.example/postgres-tools@sha256:{'c' * 64}"
SOURCE_REVISION = "d" * 40
RELEASE = "1.2.3"
SOURCE_REPOSITORY = "https://github.com/example/sub2api-codex-control"
TEST_BACKUP_UID = 65_534 if os.geteuid() == 0 else os.geteuid()
TEST_BACKUP_GID = 65_534 if os.getegid() == 0 else os.getegid()


def run_python(
    script: Path, *arguments: str, expect_success: bool = True
) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        [sys.executable, str(script), *arguments],
        check=False,
        capture_output=True,
        text=True,
    )
    if expect_success and result.returncode != 0:
        raise AssertionError(f"command failed: {result.stderr}")
    if not expect_success and result.returncode == 0:
        raise AssertionError(f"command unexpectedly succeeded: {result.stdout}")
    return result


def write_json(path: Path, value: object, mode: int = 0o600) -> None:
    path.write_text(json.dumps(value), encoding="utf-8")
    path.chmod(mode)


def hardened_service(image: str, component: str) -> dict[str, object]:
    return {
        "image": image,
        "build": None,
        "pull_policy": "never",
        "read_only": True,
        "cap_drop": ["ALL"],
        "security_opt": ["no-new-privileges:true"],
        "labels": {
            "org.opencontainers.image.version": RELEASE,
            "com.sub2api-codex.component": component,
        },
    }


def compose_config(backup_dir: Path) -> dict[str, object]:
    environment = {
        "CONTROL_ENVIRONMENT": "production",
        "CONTROL_BUILD_VERSION": RELEASE,
        "CONTROL_BUILD_VCS_REF": SOURCE_REVISION,
        "CONTROL_SUB2API_BASE_URL": "http://sub2api:8080",
        "CONTROL_SUB2API_CONTRACT_MARKER": "9.8.7/eeeeeee",
        "CONTROL_TRUST_FORWARDED_FOR": "true",
        "CONTROL_REDIS_AUTH_MODE": "password",
        "CONTROL_ALLOWED_ORIGINS_CSV": "https://control.example.test",
        "CONTROL_DATABASE_PASSWORD_FILE": "/run/secrets/control_db_password",
        "CONTROL_DB_HOST": "postgres",
        "CONTROL_DB_PORT": "5432",
        "CONTROL_DB_USER": "codex_control",
        "CONTROL_DB_NAME": "codex_control",
        "CONTROL_DB_QUERY": "",
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
    api = hardened_service(API_REF, "control-api")
    api["environment"] = environment
    api["entrypoint"] = None
    api["command"] = ["api"]
    api["secrets"] = copy.deepcopy(application_secrets)
    api["networks"] = {"sub2api-network": {}}
    api["ports"] = [
        {
            "name": "control-api-loopback",
            "mode": "ingress",
            "host_ip": "127.0.0.1",
            "target": 8090,
            "published": "18090",
            "protocol": "tcp",
        }
    ]
    replica = copy.deepcopy(api)
    replica["labels"]["com.sub2api-codex.component"] = "control-api-replica"
    replica["ports"][0].update(name="control-api-replica-loopback", published="18093")
    migrate = hardened_service(API_REF, "control-migrate")
    migrate["environment"] = copy.deepcopy(environment)
    migrate["entrypoint"] = None
    migrate["command"] = ["migrate"]
    migrate["secrets"] = copy.deepcopy(application_secrets)
    migrate["networks"] = {"sub2api-network": {}}
    pwa = hardened_service(PWA_REF, "pwa")
    pwa["entrypoint"] = None
    pwa["command"] = None
    pwa["networks"] = {"pwa-network": {}}
    pwa["ports"] = [
        {
            "name": "pwa-loopback",
            "mode": "ingress",
            "host_ip": "127.0.0.1",
            "target": 8080,
            "published": "18091",
            "protocol": "tcp",
        }
    ]
    backup = hardened_service(BACKUP_REF, "control-backup")
    backup["entrypoint"] = None
    backup["command"] = None
    backup["user"] = f"{TEST_BACKUP_UID}:{TEST_BACKUP_GID}"
    backup["environment"] = {
        key: environment[key]
        for key in (
            "CONTROL_DATABASE_PASSWORD_FILE",
            "CONTROL_DB_HOST",
            "CONTROL_DB_PORT",
            "CONTROL_DB_USER",
            "CONTROL_DB_NAME",
        )
    }
    backup["environment"]["BACKUP_DIR"] = "/backups"
    backup["secrets"] = [
        {
            "source": "control_db_password",
            "target": "/run/secrets/control_db_password",
        }
    ]
    backup["networks"] = {"sub2api-network": {}}
    backup["volumes"] = [
        {"type": "bind", "source": str(backup_dir), "target": "/backups"}
    ]
    return {
        "name": "admission-test",
        "networks": {
            "sub2api-network": {"name": "sub2api-network", "external": True},
            "pwa-network": {
                "name": "admission-test_pwa",
                "driver": "bridge",
                "driver_opts": {
                    "com.docker.network.bridge.enable_ip_masquerade": "false",
                    "com.docker.network.bridge.enable_icc": "false",
                },
            },
        },
        "services": {
            "control-api": api,
            "control-api-replica": replica,
            "control-migrate": migrate,
            "codex-pwa": pwa,
            "control-backup": backup,
        },
    }


class ComposePlanTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.repo = self.root / "repo"
        self.repo.mkdir()
        self.contract_relative = "docs/contracts/sub2api-auth.v9.8.7.json"
        self.contract = self.repo / self.contract_relative
        self.contract.parent.mkdir(parents=True)
        write_json(self.contract, {"format_version": 1}, mode=0o644)
        self.contract_sha = hashlib.sha256(self.contract.read_bytes()).hexdigest()
        self.versions_lock_path = self.root / "versions.lock.json"
        write_json(
            self.versions_lock_path,
            {
                "format_version": 1,
                "sub2api": {
                    "auth_contract_file": self.contract_relative,
                    "auth_contract_sha256": self.contract_sha,
                },
            },
        )
        self.versions_lock_sha = hashlib.sha256(
            self.versions_lock_path.read_bytes()
        ).hexdigest()
        self.backup = self.root / "backups"
        self.backup.mkdir(mode=0o700)
        if os.geteuid() == 0:
            os.chown(self.backup, TEST_BACKUP_UID, TEST_BACKUP_GID)
        self.config_path = self.root / "compose.json"
        self.release_path = self.root / "release.json"
        write_json(
            self.release_path,
            {
                "CONTROL_API_IMAGE": API_REF,
                "CONTROL_PWA_IMAGE": PWA_REF,
                "CONTROL_POSTGRES_TOOLS_IMAGE": BACKUP_REF,
                "CONTROL_RELEASE": RELEASE,
                "CONTROL_SOURCE_REPOSITORY": SOURCE_REPOSITORY,
                "CONTROL_MIGRATION_HEAD": "20260731_0008",
                "CONTROL_VCS_REF": SOURCE_REVISION,
                "CONTROL_VERSIONS_LOCK_SHA256": self.versions_lock_sha,
                "CONTROL_SUB2API_AUTH_CONTRACT_PATH": self.contract_relative,
                "CONTROL_SUB2API_AUTH_CONTRACT_SHA256": self.contract_sha,
                "CONTROL_RELEASE_INPUT_SHA256S": {
                    "versions.lock.json": self.versions_lock_sha,
                    self.contract_relative: self.contract_sha,
                },
            },
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def invoke(
        self, config: dict[str, object], *, success: bool = True
    ) -> subprocess.CompletedProcess[str]:
        write_json(self.config_path, config)
        return run_python(
            ADMISSION,
            "compose-plan",
            "--compose-config",
            str(self.config_path),
            "--release-verification",
            str(self.release_path),
            "--versions-lock",
            str(self.versions_lock_path),
            "--source-repository",
            SOURCE_REPOSITORY,
            "--repo-root",
            str(self.repo),
            expect_success=success,
        )

    def test_accepts_digest_only_production_plan(self) -> None:
        result = self.invoke(compose_config(self.backup))
        plan = json.loads(result.stdout)
        self.assertEqual(plan["api_image"], API_REF)
        self.assertEqual(plan["pwa_image"], PWA_REF)
        self.assertEqual(plan["backup_image"], BACKUP_REF)
        self.assertEqual(plan["source_revision"], SOURCE_REVISION)
        self.assertEqual(plan["versions_lock_sha256"], self.versions_lock_sha)
        self.assertEqual(plan["auth_contract_file"], str(self.contract.resolve()))
        self.assertEqual(plan["auth_contract_sha256"], self.contract_sha)
        self.assertEqual(
            set(plan["instances"]),
            {"control-api", "control-api-replica", "codex-pwa"},
        )
        self.assertEqual(plan["backup_owner_uid"], TEST_BACKUP_UID)
        self.assertEqual(plan["pwa_network_driver"], "bridge")
        self.assertEqual(
            plan["pwa_network_driver_opts"],
            {
                "com.docker.network.bridge.enable_ip_masquerade": "false",
                "com.docker.network.bridge.enable_icc": "false",
            },
        )

    def test_rejects_each_insecure_pwa_network_shape(self) -> None:
        mutations = {
            "internal network": lambda network: network.update(internal=True),
            "missing masquerade option": lambda network: network["driver_opts"].pop(
                "com.docker.network.bridge.enable_ip_masquerade"
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

    def test_rejects_unsigned_versions_lock_or_auth_contract_drift(self) -> None:
        original_lock = self.versions_lock_path.read_bytes()
        original_contract = self.contract.read_bytes()
        try:
            self.versions_lock_path.write_bytes(original_lock + b"\n")
            self.invoke(compose_config(self.backup), success=False)
            self.versions_lock_path.write_bytes(original_lock)
            self.contract.write_bytes(original_contract + b"\n")
            self.invoke(compose_config(self.backup), success=False)
        finally:
            self.versions_lock_path.write_bytes(original_lock)
            self.contract.write_bytes(original_contract)

    def test_rejects_each_mutable_or_inconsistent_plan_before_deploy(self) -> None:
        mutations = {
            "tagged API": lambda value: value["services"]["control-api"].update(
                image="registry.example/control-api:latest"
            ),
            "migrate mismatch": lambda value: value["services"][
                "control-migrate"
            ].update(image=f"registry.example/other@sha256:{'9' * 64}"),
            "retained build": lambda value: value["services"]["codex-pwa"].update(
                build={"context": "."}
            ),
            "unverified marker": lambda value: value["services"]["control-api"][
                "environment"
            ].update(CONTROL_SUB2API_CONTRACT_MARKER="UNVERIFIED"),
            "unauthenticated Redis": lambda value: value["services"]["control-api"][
                "environment"
            ].update(CONTROL_REDIS_AUTH_MODE="none"),
            "mutable backup image": lambda value: value["services"][
                "control-backup"
            ].update(image="postgres-tools:local"),
            "backup retained build": lambda value: value["services"][
                "control-backup"
            ].update(build={"context": "."}),
            "writable backup root": lambda value: value["services"][
                "control-backup"
            ].update(read_only=False),
            "backup label drift": lambda value: value["services"]["control-backup"][
                "labels"
            ].update(**{"org.opencontainers.image.version": "wrong"}),
            "checkout backup": lambda value: value["services"]["control-backup"].update(
                volumes=[
                    {
                        "type": "bind",
                        "source": str(self.repo / "backups"),
                        "target": "/backups",
                    }
                ]
            ),
            "missing API replica": lambda value: value["services"].pop(
                "control-api-replica"
            ),
            "replica image drift": lambda value: value["services"][
                "control-api-replica"
            ].update(image=f"registry.example/other@sha256:{'8' * 64}"),
            "public API bind": lambda value: value["services"]["control-api"]["ports"][
                0
            ].update(host_ip="0.0.0.0"),
            "replica extra network": lambda value: value["services"][
                "control-api-replica"
            ]["networks"].update(**{"pwa-network": {}}),
            "backup database drift": lambda value: value["services"]["control-backup"][
                "environment"
            ].update(CONTROL_DB_NAME="other"),
            "backup environment injection": lambda value: value["services"][
                "control-backup"
            ]["environment"].update(PGOPTIONS="-c search_path=public"),
            "backup secret drift": lambda value: value["services"]["control-backup"][
                "secrets"
            ][0].update(source="other_password"),
            "backup command override": lambda value: value["services"][
                "control-backup"
            ].update(command=["sh"]),
            "migrate host port": lambda value: value["services"][
                "control-migrate"
            ].update(ports=[{"target": 8090, "published": "19000"}]),
        }
        for label, mutate in mutations.items():
            with self.subTest(label=label):
                config = compose_config(self.backup)
                mutate(config)
                self.invoke(config, success=False)


class ReleaseImageTests(unittest.TestCase):
    def test_requires_exact_repo_digests_and_matching_oci_source_revision(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            plan = {
                "api_image": API_REF,
                "pwa_image": PWA_REF,
                "backup_image": BACKUP_REF,
                "release": RELEASE,
                "source_revision": SOURCE_REVISION,
                "source_repository": SOURCE_REPOSITORY,
                "signed_migration_head": "20260731_0008",
            }
            write_json(root / "plan.json", plan)

            def image(
                reference: str, image_id_character: str
            ) -> list[dict[str, object]]:
                return [
                    {
                        "Id": f"sha256:{image_id_character * 64}",
                        "RepoDigests": [reference],
                        "Config": {
                            "Labels": {
                                "org.opencontainers.image.version": RELEASE,
                                "org.opencontainers.image.revision": SOURCE_REVISION,
                                "org.opencontainers.image.source": SOURCE_REPOSITORY,
                            }
                        },
                        "Created": "2026-07-31T00:00:00Z",
                        "Architecture": "amd64",
                        "Os": "linux",
                    }
                ]

            write_json(root / "api.json", image(API_REF, "1"))
            write_json(root / "pwa.json", image(PWA_REF, "2"))
            write_json(root / "backup.json", image(BACKUP_REF, "3"))
            arguments = (
                "release-images",
                "--plan",
                str(root / "plan.json"),
                "--api-inspect",
                str(root / "api.json"),
                "--pwa-inspect",
                str(root / "pwa.json"),
                "--backup-inspect",
                str(root / "backup.json"),
            )
            result = run_python(ADMISSION, *arguments)
            self.assertEqual(json.loads(result.stdout)["api"]["reference"], API_REF)
            self.assertEqual(
                json.loads(result.stdout)["backup_tools"]["oci_labels"][
                    "org.opencontainers.image.source"
                ],
                SOURCE_REPOSITORY,
            )

            bad = image(API_REF, "1")
            bad[0]["RepoDigests"] = [f"registry.example/control-api@sha256:{'9' * 64}"]
            write_json(root / "api.json", bad)
            run_python(ADMISSION, *arguments, expect_success=False)

            write_json(root / "api.json", image(API_REF, "1"))
            for label_key in (
                "org.opencontainers.image.version",
                "org.opencontainers.image.revision",
                "org.opencontainers.image.source",
            ):
                with self.subTest(backup_label=label_key):
                    bad = image(BACKUP_REF, "3")
                    bad[0]["Config"]["Labels"][label_key] = "untrusted"
                    write_json(root / "backup.json", bad)
                    run_python(ADMISSION, *arguments, expect_success=False)

            write_json(root / "backup.json", image(BACKUP_REF, "3"))
            bad = image(BACKUP_REF, "3")
            bad[0]["RepoDigests"] = [
                f"registry.example/postgres-tools@sha256:{'9' * 64}"
            ]
            write_json(root / "backup.json", bad)
            run_python(ADMISSION, *arguments, expect_success=False)

            write_json(root / "backup.json", image(BACKUP_REF, "3"))
            bad = image(BACKUP_REF, "3")
            bad[0]["Architecture"] = "arm64"
            write_json(root / "backup.json", bad)
            run_python(ADMISSION, *arguments, expect_success=False)

            write_json(root / "backup.json", image(BACKUP_REF, "3"))
            bad = image(PWA_REF, "2")
            bad[0]["Architecture"] = "arm64"
            write_json(root / "pwa.json", bad)
            run_python(ADMISSION, *arguments, expect_success=False)


class SmokeInputReaderTests(unittest.TestCase):
    def test_rejects_file_not_owned_by_current_euid(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            token = Path(temporary) / "token"
            token.write_text("opaque-token\n", encoding="ascii")
            token.chmod(0o600)
            arguments = types.SimpleNamespace(
                token_file=token, expected_user_id="smoke-user"
            )
            with (
                mock.patch.object(
                    ADMISSION_MODULE.os,
                    "geteuid",
                    return_value=os.geteuid() + 1,
                ),
                self.assertRaisesRegex(ValueError, "not owned by UID"),
            ):
                ADMISSION_MODULE.smoke_input(arguments)


class RuntimeEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.contract = self.root / "auth.json"
        self.contract.write_text('{"format_version":1}\n', encoding="utf-8")
        self.contract.chmod(0o444)
        self.contract_sha = hashlib.sha256(self.contract.read_bytes()).hexdigest()
        self.image_ref = f"registry.example/sub2api@sha256:{'4' * 64}"
        self.container_id = "5" * 64
        self.image_id = f"sha256:{'6' * 64}"
        self.commit = "7" * 40
        self.version = "9.8.7"
        self.built_at = "2026-07-30T12:34:56Z"
        self.binary_sha = "8" * 64
        self.labels = {
            "org.opencontainers.image.version": self.version,
            "org.opencontainers.image.revision": self.commit,
            "org.opencontainers.image.created": self.built_at,
            "org.opencontainers.image.source": "https://github.com/Wei-Shaw/sub2api",
        }
        self.lock = {
            "format_version": 1,
            "sub2api": {
                "container_image": self.image_ref,
                "container_image_id": self.image_id,
                "runtime_binary_sha256": self.binary_sha,
                "runtime_version": self.version,
                "runtime_commit": self.commit,
                "runtime_built_at": self.built_at,
                "image_created": self.built_at,
                "image_label_created": self.built_at,
                "release_url": "https://github.com/Wei-Shaw/sub2api/releases/tag/v9.8.7",
                "image_label_version": self.version,
                "image_label_commit": self.commit,
                "auth_contract_file": self.contract.name,
                "auth_contract_sha256": self.contract_sha,
            },
        }
        process = {"Entrypoint": ["/app/sub2api"], "Cmd": ["serve"]}
        self.container = {
            "Id": self.container_id,
            "Name": "/sub2api",
            "Image": self.image_id,
            "Path": "/app/sub2api",
            "Args": ["serve"],
            "Config": {
                "Image": self.image_ref,
                "Labels": self.labels,
                **process,
            },
            "HostConfig": {
                "ReadonlyRootfs": True,
                "Privileged": False,
                "CapAdd": None,
                "CapDrop": ["ALL"],
                "SecurityOpt": ["no-new-privileges:true"],
                "PidMode": "",
                "IpcMode": "private",
                "UTSMode": "",
                "UsernsMode": "",
                "CgroupnsMode": "private",
                "NetworkMode": "sub2api-network",
                "Devices": [],
                "DeviceRequests": [],
                "DeviceCgroupRules": None,
                "Binds": None,
                "PublishAllPorts": False,
                "PortBindings": {
                    "8080/tcp": [{"HostIp": "127.0.0.1", "HostPort": "8080"}]
                },
            },
            "State": {
                "Running": True,
                "Pid": 4242,
                "Paused": False,
                "Restarting": False,
                "OOMKilled": False,
                "Dead": False,
                "Health": {"Status": "healthy"},
            },
            "RestartCount": 0,
            "Mounts": [
                {
                    "Destination": "/app/data",
                    "Type": "volume",
                    "Name": "sub2api-data",
                    "RW": True,
                }
            ],
            "NetworkSettings": {
                "Ports": {"8080/tcp": [{"HostIp": "127.0.0.1", "HostPort": "8080"}]},
                "Networks": {"sub2api-network": {"Aliases": ["sub2api"]}},
            },
        }
        self.image = {
            "Id": self.image_id,
            "RepoDigests": [self.image_ref],
            "Created": self.built_at,
            "Config": {"Labels": self.labels, **process},
        }
        self.probe_nonce = "f" * 64
        self.probe_user_id = "fixture-user"
        self.probe_base_url = "http://127.0.0.1:8080"
        self.evidence = {
            "format_version": 4,
            "captured_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            "probe": {
                "base_url": self.probe_base_url,
                "nonce": self.probe_nonce,
                "expected_user_id": self.probe_user_id,
                "network_namespace_container_id": self.container_id,
                "proxy_environment_disabled": True,
            },
            "runtime": {
                "container_id": self.container_id,
                "image_id": self.image_id,
                "image_digest": self.image_ref,
                "binary_sha256": self.binary_sha,
                "version": self.version,
                "commit": self.commit,
                "contract_sha256": self.contract_sha,
            },
            "contract_sha256": self.contract_sha,
            "fixtures": {
                "auth_me_success": {
                    "status": 200,
                    "identity_present": True,
                    "user_id": self.probe_user_id,
                },
                "auth_me_disabled": {"status": 401, "code": "USER_INACTIVE"},
                "auth_me_revoked": {"status": 401, "code": "TOKEN_REVOKED"},
                "auth_me_session_binding_mismatch": {
                    "status": 401,
                    "code": "SESSION_BINDING_MISMATCH",
                    "ip_and_user_agent_changed": True,
                },
                "refresh_rotation": {
                    "status": 200,
                    "access_token_present": True,
                    "refresh_token_present": True,
                    "expires_in_positive": True,
                    "token_type": "Bearer",
                    "refresh_rotated": True,
                    "refreshed_identity_status": 200,
                    "same_identity": True,
                    "old_refresh_rejected_status": 401,
                },
                "logout": {"status": 204, "refresh_after_logout_status": 401},
            },
        }

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def invoke(
        self,
        *,
        lock: dict[str, object] | None = None,
        container: dict[str, object] | None = None,
        after: dict[str, object] | None = None,
        image: dict[str, object] | None = None,
        evidence: dict[str, object] | None = None,
        success: bool = True,
    ) -> subprocess.CompletedProcess[str]:
        write_json(self.root / "lock.json", lock or self.lock)
        selected_container = container or self.container
        write_json(self.root / "container.json", [selected_container])
        write_json(self.root / "after.json", [after or selected_container])
        write_json(self.root / "name-after.json", [after or selected_container])
        write_json(self.root / "image.json", [image or self.image])
        write_json(self.root / "evidence.json", evidence or self.evidence)
        (self.root / "version.txt").write_text(
            f"Sub2API {self.version} commit {self.commit} built {self.built_at}\n",
            encoding="utf-8",
        )
        (self.root / "diff.txt").write_text("", encoding="utf-8")
        return run_python(
            RUNTIME,
            "--lock",
            str(self.root / "lock.json"),
            "--container-inspect",
            str(self.root / "container.json"),
            "--container-inspect-after",
            str(self.root / "after.json"),
            "--container-name-inspect-after",
            str(self.root / "name-after.json"),
            "--image-inspect",
            str(self.root / "image.json"),
            "--binary-sha256",
            self.binary_sha,
            "--pid1-host-pid",
            "4242",
            "--pid1-path",
            "/app/sub2api",
            "--pid1-sha256",
            self.binary_sha,
            "--version-output",
            str(self.root / "version.txt"),
            "--diff",
            str(self.root / "diff.txt"),
            "--expected-network",
            "sub2api-network",
            "--expected-alias",
            "sub2api",
            "--auth-evidence",
            str(self.root / "evidence.json"),
            "--auth-probe-nonce",
            self.probe_nonce,
            "--auth-probe-user-id",
            self.probe_user_id,
            "--auth-probe-base-url",
            self.probe_base_url,
            "--require-auth-evidence",
            expect_success=success,
        )

    def test_accepts_exact_immutable_runtime_and_auth_evidence(self) -> None:
        result = self.invoke()
        attestation = json.loads(result.stdout)
        self.assertEqual(attestation["container_id"], self.container_id)
        self.assertEqual(
            attestation["auth_evidence"]["fixtures"]["logout"]["status"], 204
        )

    def test_rejects_runtime_identity_mount_and_fixture_drift(self) -> None:
        cases: dict[str, dict[str, object]] = {}

        bad_lock = copy.deepcopy(self.lock)
        bad_lock["sub2api"]["image_label_version"] = "older"
        cases["incoherent lock labels"] = {"lock": bad_lock}

        bad_container = copy.deepcopy(self.container)
        bad_container["Mounts"].append(
            {"Destination": "/tmp", "Type": "tmpfs", "RW": True}
        )
        cases["extra writable mount"] = {"container": bad_container}

        stopped = copy.deepcopy(self.container)
        stopped["State"]["Running"] = False
        cases["stopped container"] = {"container": stopped}

        wrong_repo = copy.deepcopy(self.image)
        wrong_repo["RepoDigests"] = [f"registry.example/sub2api@sha256:{'9' * 64}"]
        cases["digest substring mismatch"] = {"image": wrong_repo}

        swapped = copy.deepcopy(self.container)
        swapped["Id"] = f"sha256:{'9' * 64}"
        cases["container replacement"] = {"after": swapped}

        stale = copy.deepcopy(self.evidence)
        stale["captured_at"] = (datetime.now(UTC) - timedelta(hours=1)).isoformat()
        cases["stale auth evidence"] = {"evidence": stale}

        for label, values in cases.items():
            with self.subTest(label=label):
                self.invoke(success=False, **values)


class BackupEvidenceTests(unittest.TestCase):
    def test_verifies_fresh_private_dump_checksum_and_recreated_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            backup = root / "backups"
            backup.mkdir(mode=0o700)
            dump = backup / "codex-control-20260731T000000Z-test.dump"
            manifest = backup / "codex-control-20260731T000000Z-test.contents.txt"
            checksum = backup / "codex-control-20260731T000000Z-test.sha256"
            dump.write_bytes(b"custom-format-fixture")
            manifest.write_bytes(b"fixture toc\n")
            checksum.write_text(
                f"{hashlib.sha256(dump.read_bytes()).hexdigest()}  {dump.name}\n",
                encoding="ascii",
            )
            for path in (dump, manifest, checksum):
                path.chmod(0o600)
            pg_restore = root / "pg_restore"
            pg_restore.write_text(
                "#!/bin/sh\nprintf 'fixture toc\\n'\n", encoding="ascii"
            )
            pg_restore.chmod(0o700)
            arguments = (
                "backup",
                "--directory",
                str(backup),
                "--not-before",
                str(time.time() - 2),
                "--pg-restore",
                str(pg_restore),
                "--expected-owner-uid",
                str(os.geteuid()),
            )
            result = run_python(ADMISSION, *arguments)
            self.assertEqual(json.loads(result.stdout)["dump_path"], str(dump))

            checksum.write_text(f"{'0' * 64}  {dump.name}\n", encoding="ascii")
            run_python(ADMISSION, *arguments, expect_success=False)

    def test_rejects_symlinked_metadata_and_owner_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            backup = root / "backups"
            backup.mkdir(mode=0o700)
            dump = backup / "codex-control-20260731T000000Z-test.dump"
            manifest = backup / "codex-control-20260731T000000Z-test.contents.txt"
            checksum = backup / "codex-control-20260731T000000Z-test.sha256"
            dump.write_bytes(b"fixture")
            manifest.write_bytes(b"fixture toc\n")
            checksum.write_text(
                f"{hashlib.sha256(b'fixture').hexdigest()}  {dump.name}\n",
                encoding="ascii",
            )
            for path in (dump, manifest, checksum):
                path.chmod(0o600)
            real_manifest = backup / "real-manifest"
            manifest.rename(real_manifest)
            manifest.symlink_to(real_manifest)
            pg_restore = root / "pg_restore"
            pg_restore.write_text(
                "#!/bin/sh\nprintf 'fixture toc\\n'\n", encoding="ascii"
            )
            pg_restore.chmod(0o700)
            arguments = (
                "backup",
                "--directory",
                str(backup),
                "--not-before",
                str(time.time() - 2),
                "--pg-restore",
                str(pg_restore),
                "--expected-owner-uid",
                str(os.geteuid()),
            )
            run_python(ADMISSION, *arguments, expect_success=False)

            manifest.unlink()
            real_manifest.rename(manifest)
            run_python(
                ADMISSION,
                *arguments[:-1],
                str(os.geteuid() + 1),
                expect_success=False,
            )


class RevisionBindingTests(unittest.TestCase):
    def test_packaged_head_must_match_signed_release_head(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "current.txt").write_text("20260730_0007\n", encoding="ascii")
            (root / "head.txt").write_text("20260731_0008 (head)\n", encoding="ascii")
            write_json(root / "plan.json", {"signed_migration_head": "20260731_0008"})
            arguments = (
                "revisions",
                "--current",
                str(root / "current.txt"),
                "--head",
                str(root / "head.txt"),
                "--plan",
                str(root / "plan.json"),
            )
            result = run_python(ADMISSION, *arguments)
            self.assertEqual(
                json.loads(result.stdout)["target_migration_head"], "20260731_0008"
            )
            write_json(root / "plan.json", {"signed_migration_head": "20260730_0007"})
            run_python(ADMISSION, *arguments, expect_success=False)

    def test_post_migration_revision_must_equal_head_before_start(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "current.txt").write_text("20260730_0007\n", encoding="ascii")
            (root / "head.txt").write_text("20260731_0008 (head)\n", encoding="ascii")
            arguments = (
                "revisions",
                "--current",
                str(root / "current.txt"),
                "--head",
                str(root / "head.txt"),
                "--require-current-head",
            )
            run_python(ADMISSION, *arguments, expect_success=False)
            (root / "current.txt").write_text("20260731_0008\n", encoding="ascii")
            run_python(ADMISSION, *arguments)


class AuthProbeTests(unittest.TestCase):
    def test_live_probe_rotates_then_revokes_without_recording_tokens(self) -> None:
        state = {"old_refresh_used": False, "logged_out": False}

        class Response:
            def __init__(self, status: int, value: object | None = None) -> None:
                self.status = status
                self.payload = b"" if value is None else json.dumps(value).encode()
                self.url = ""

            def __enter__(self) -> Self:
                return self

            def __exit__(self, *args: object) -> None:
                return None

            def read(self, _limit: int) -> bytes:
                return self.payload

            def geturl(self) -> str:
                return self.url

        class Opener:
            def open(self, request: object, timeout: float) -> Response:
                del timeout
                method = request.get_method()
                path = request.full_url.removeprefix("http://127.0.0.1:8080")
                authorization = request.get_header("Authorization")
                headers = {key.lower(): value for key, value in request.header_items()}
                body = json.loads(request.data) if request.data else {}
                if method == "GET" and path == "/api/v1/auth/me":
                    if authorization == "Bearer active-access":
                        response = Response(200, {"data": {"id": "fixture-user"}})
                        response.url = request.full_url
                        return response
                    if authorization == "Bearer rotated-access":
                        if "x-forwarded-for" in headers or headers.get(
                            "user-agent", ""
                        ).startswith("sub2api-auth-contract-probe/"):
                            response = Response(
                                401,
                                {
                                    "code": "SESSION_BINDING_MISMATCH",
                                    "message": "binding mismatch",
                                },
                            )
                        else:
                            response = Response(200, {"data": {"id": "fixture-user"}})
                        response.url = request.full_url
                        return response
                    if authorization == "Bearer disabled-access":
                        response = Response(
                            401,
                            {"code": "USER_INACTIVE", "message": "inactive"},
                        )
                        response.url = request.full_url
                        return response
                    response = Response(
                        401,
                        {"code": "TOKEN_REVOKED", "message": "revoked"},
                    )
                    response.url = request.full_url
                    return response
                if method == "POST" and path == "/api/v1/auth/refresh":
                    refresh = body.get("refresh_token")
                    if refresh == "active-refresh" and not state["old_refresh_used"]:
                        state["old_refresh_used"] = True
                        response = Response(
                            200,
                            {
                                "code": 0,
                                "message": "success",
                                "data": {
                                    "access_token": "rotated-access",
                                    "refresh_token": "rotated-refresh",
                                    "expires_in": 600,
                                    "token_type": "Bearer",
                                },
                            },
                        )
                        response.url = request.full_url
                        return response
                    response = Response(401, {"error": "rejected"})
                    response.url = request.full_url
                    return response
                if (
                    method == "POST"
                    and path == "/api/v1/auth/logout"
                    and authorization == "Bearer rotated-access"
                    and body.get("refresh_token") == "rotated-refresh"
                ):
                    state["logged_out"] = True
                    response = Response(204)
                    response.url = request.full_url
                    return response
                response = Response(400, {"error": "bad fixture"})
                response.url = request.full_url
                return response

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            token_values = {
                "active-access": "active-access",
                "active-refresh": "active-refresh",
                "disabled-access": "disabled-access",
                "revoked-access": "revoked-access",
            }
            token_paths: dict[str, Path] = {}
            for name, value in token_values.items():
                path = root / name
                path.write_text(f"{value}\n", encoding="ascii")
                path.chmod(0o600)
                token_paths[name] = path
            runtime = {
                "container_id": "1" * 64,
                "image_id": f"sha256:{'2' * 64}",
                "image_digest": f"registry/sub2api@sha256:{'3' * 64}",
                "binary_sha256": "4" * 64,
                "runtime_version": "1.0.0",
                "runtime_commit": "5" * 40,
            }
            contract = {
                "format_version": 1,
                "runtime": {"version": "1.0.0", "commit": "5" * 40},
                "source": {},
                "local_storage": {},
                "endpoints": {
                    "identity": {
                        "method": "GET",
                        "path": "/api/v1/auth/me",
                        "authorization": "bearer_access_token",
                        "disabled_user_error": {
                            "status": 401,
                            "code": "USER_INACTIVE",
                        },
                        "revoked_token_error": {
                            "status": 401,
                            "code": "TOKEN_REVOKED",
                        },
                        "session_binding_mismatch_error": {
                            "status": 401,
                            "code": "SESSION_BINDING_MISMATCH",
                        },
                        "session_binding_request": {
                            "client_ip_header": "X-Forwarded-For",
                            "user_agent_header": "User-Agent",
                        },
                    },
                    "refresh": {
                        "method": "POST",
                        "path": "/api/v1/auth/refresh",
                        "request_required": ["refresh_token"],
                        "response_envelope": {
                            "required": ["code", "message", "data"],
                            "code": 0,
                            "message": "success",
                            "data_required": [
                                "access_token",
                                "refresh_token",
                                "expires_in",
                                "token_type",
                            ],
                        },
                        "token_type": "Bearer",
                        "rotates_refresh_token": True,
                    },
                    "logout": {
                        "method": "POST",
                        "path": "/api/v1/auth/logout",
                        "authorization": "optional_bearer_access_token",
                        "request_required": ["refresh_token"],
                    },
                },
                "control_boundary": {
                    "accepted_sub2api_fields": ["access_token"],
                    "forbidden_sub2api_fields": ["refresh_token"],
                },
            }
            contract_path = root / "contract.json"
            write_json(contract_path, contract)
            runtime["contract_sha256"] = hashlib.sha256(
                contract_path.read_bytes()
            ).hexdigest()
            write_json(root / "runtime.json", runtime)
            arguments = types.SimpleNamespace(
                base_url="http://127.0.0.1:8080",
                active_access_token_file=token_paths["active-access"],
                active_refresh_token_file=token_paths["active-refresh"],
                disabled_access_token_file=token_paths["disabled-access"],
                revoked_access_token_file=token_paths["revoked-access"],
                runtime_attestation=root / "runtime.json",
                contract_file=contract_path,
                probe_nonce="6" * 64,
                expected_user_id="fixture-user",
                timeout=5.0,
            )
            with mock.patch.object(
                PROBE_MODULE.urllib.request, "build_opener", return_value=Opener()
            ):
                evidence = PROBE_MODULE.run(arguments)
            serialized = json.dumps(evidence)
            self.assertTrue(state["logged_out"])
            self.assertNotIn("active-access", serialized)
            self.assertNotIn("active-refresh", serialized)
            self.assertTrue(evidence["fixtures"]["refresh_rotation"]["refresh_rotated"])


class OperatorInputTests(unittest.TestCase):
    def test_private_env_copy_is_nofollow_owned_bounded_and_durable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            source = root / "production.env"
            source.write_text("CONTROL_RELEASE=1.2.3\n", encoding="ascii")
            source.chmod(0o600)
            destination = root / "pinned.env"
            arguments = types.SimpleNamespace(
                source=source,
                destination=destination,
                label="production Compose environment file",
                max_bytes=1024,
            )
            evidence = ADMISSION_MODULE.copy_private_file(arguments)
            self.assertEqual(destination.read_bytes(), source.read_bytes())
            self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o600)
            self.assertEqual(
                evidence["source_sha256"],
                hashlib.sha256(source.read_bytes()).hexdigest(),
            )

            destination.unlink()
            alias = root / "alias.env"
            alias.symlink_to(source)
            arguments.source = alias
            with self.assertRaisesRegex(ValueError, "not a regular file"):
                ADMISSION_MODULE.copy_private_file(arguments)

            arguments.source = source
            source.chmod(0o644)
            with self.assertRaisesRegex(ValueError, "not exactly 0600"):
                ADMISSION_MODULE.copy_private_file(arguments)
            source.chmod(0o600)
            source.write_bytes(b"x" * 1025)
            with self.assertRaisesRegex(ValueError, "larger than 1024 bytes"):
                ADMISSION_MODULE.copy_private_file(arguments)

    def test_admitted_release_input_copy_requires_hash_and_single_inode(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            source = root / "contract.json"
            source.write_text('{"format_version":1}\n', encoding="ascii")
            source.chmod(0o644)
            expected_sha256 = hashlib.sha256(source.read_bytes()).hexdigest()
            destination = root / "pinned-contract.json"
            arguments = types.SimpleNamespace(
                source=source,
                destination=destination,
                label="Sub2API auth contract",
                max_bytes=1024,
                expected_sha256=expected_sha256,
            )
            evidence = ADMISSION_MODULE.copy_admitted_file(arguments)
            self.assertEqual(evidence["source_sha256"], expected_sha256)
            self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o600)

            destination.unlink()
            arguments.expected_sha256 = "0" * 64
            with self.assertRaisesRegex(ValueError, "admitted SHA-256"):
                ADMISSION_MODULE.copy_admitted_file(arguments)
            arguments.expected_sha256 = expected_sha256
            hardlink = root / "contract-hardlink.json"
            os.link(source, hardlink)
            with self.assertRaisesRegex(ValueError, "exactly one hard link"):
                ADMISSION_MODULE.copy_admitted_file(arguments)

    def test_operator_directory_must_be_preprovisioned_private_and_owned(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            arguments = types.SimpleNamespace(
                directory=root, label="deployment record directory"
            )
            evidence = ADMISSION_MODULE.operator_directory(arguments)
            self.assertEqual(evidence["mode"], "0700")
            root.chmod(0o755)
            with self.assertRaisesRegex(ValueError, "exactly 0700"):
                ADMISSION_MODULE.operator_directory(arguments)


class RunningContainerTests(unittest.TestCase):
    def test_records_both_api_instances_and_rejects_runtime_boundary_drift(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            api_image_id = f"sha256:{'1' * 64}"
            pwa_image_id = f"sha256:{'2' * 64}"
            releases = {
                "api": {"image_id": api_image_id},
                "pwa": {"image_id": pwa_image_id},
            }
            instances = {
                "control-api": {
                    "image_id_key": "api",
                    "network": "sub2api-network",
                    "target_port": 8090,
                    "published_port": "18090",
                },
                "control-api-replica": {
                    "image_id_key": "api",
                    "network": "sub2api-network",
                    "target_port": 8090,
                    "published_port": "18093",
                },
                "codex-pwa": {
                    "image_id_key": "pwa",
                    "network": "control_pwa-network",
                    "target_port": 8080,
                    "published_port": "18091",
                },
            }
            write_json(root / "releases.json", releases)
            write_json(
                root / "plan.json",
                {
                    "instances": instances,
                    "pwa_network": "control_pwa-network",
                    "compose_project": "control",
                },
            )

            def container(
                identifier: str, image_id: str, network: str, target: int, port: str
            ) -> list[dict[str, object]]:
                network_id = "8" * 64 if network == "control_pwa-network" else "9" * 64
                return [
                    {
                        "Id": identifier * 64,
                        "Name": f"/{'codex-pwa' if network == 'control_pwa-network' else 'api'}",
                        "Image": image_id,
                        "HostConfig": {
                            "ReadonlyRootfs": True,
                            "Privileged": False,
                            "CapAdd": None,
                            "PortBindings": {
                                f"{target}/tcp": [
                                    {"HostIp": "127.0.0.1", "HostPort": port}
                                ]
                            },
                        },
                        "State": {
                            "Running": True,
                            "Health": {"Status": "healthy"},
                        },
                        "NetworkSettings": {
                            "Ports": {
                                **(
                                    {"80/tcp": None}
                                    if network == "control_pwa-network"
                                    else {}
                                ),
                                f"{target}/tcp": [
                                    {"HostIp": "127.0.0.1", "HostPort": port}
                                ],
                            },
                            "Networks": {
                                network: {
                                    "NetworkID": network_id,
                                    "EndpointID": identifier * 64,
                                }
                            },
                        },
                    }
                ]

            paths = {
                "api": root / "api.json",
                "replica": root / "replica.json",
                "pwa": root / "pwa.json",
                "pwa_network": root / "pwa-network.json",
            }
            write_json(
                paths["api"],
                container("a", api_image_id, "sub2api-network", 8090, "18090"),
            )
            write_json(
                paths["replica"],
                container("b", api_image_id, "sub2api-network", 8090, "18093"),
            )
            write_json(
                paths["pwa"],
                container("c", pwa_image_id, "control_pwa-network", 8080, "18091"),
            )
            write_json(
                paths["pwa_network"],
                [
                    {
                        "Name": "control_pwa-network",
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
                            "com.docker.compose.project": "control",
                            "com.docker.compose.network": "pwa-network",
                        },
                        "Containers": {
                            "c" * 64: {
                                "Name": "codex-pwa",
                                "EndpointID": "c" * 64,
                            }
                        },
                    }
                ],
            )
            arguments = (
                "running-containers",
                "--releases",
                str(root / "releases.json"),
                "--plan",
                str(root / "plan.json"),
                "--api-inspect",
                str(paths["api"]),
                "--api-replica-inspect",
                str(paths["replica"]),
                "--pwa-inspect",
                str(paths["pwa"]),
                "--pwa-network-inspect",
                str(paths["pwa_network"]),
            )
            result = run_python(ADMISSION, *arguments)
            self.assertEqual(
                set(json.loads(result.stdout)["containers"]), set(instances)
            )
            self.assertEqual(
                json.loads(result.stdout)["pwa_network"]["container_id"], "c" * 64
            )

            good_pwa = container(
                "c", pwa_image_id, "control_pwa-network", 8080, "18091"
            )
            missing_effective_port = json.loads(json.dumps(good_pwa))
            missing_effective_port[0]["NetworkSettings"]["Ports"]["8080/tcp"] = None
            write_json(paths["pwa"], missing_effective_port)
            run_python(ADMISSION, *arguments, expect_success=False)

            extra_effective_port = json.loads(json.dumps(good_pwa))
            extra_effective_port[0]["NetworkSettings"]["Ports"]["80/tcp"] = [
                {"HostIp": "127.0.0.1", "HostPort": "18080"}
            ]
            write_json(paths["pwa"], extra_effective_port)
            run_python(ADMISSION, *arguments, expect_success=False)
            write_json(paths["pwa"], good_pwa)

            bad_replica = container(
                "b", api_image_id, "unexpected-network", 8090, "18093"
            )
            write_json(paths["replica"], bad_replica)
            run_python(ADMISSION, *arguments, expect_success=False)

            write_json(
                paths["replica"],
                container("b", api_image_id, "sub2api-network", 8090, "18093"),
            )
            bad_network = json.loads(paths["pwa_network"].read_text(encoding="utf-8"))
            bad_network[0]["Options"]["com.docker.network.bridge.enable_icc"] = "true"
            write_json(paths["pwa_network"], bad_network)
            run_python(ADMISSION, *arguments, expect_success=False)

            good_network = json.loads(paths["pwa_network"].read_text(encoding="utf-8"))
            good_network[0]["Options"]["com.docker.network.bridge.enable_icc"] = "false"
            extra_member = json.loads(json.dumps(good_network))
            extra_member[0]["Containers"]["d" * 64] = {
                "Name": "unexpected-member",
                "EndpointID": "d" * 64,
            }
            write_json(paths["pwa_network"], extra_member)
            run_python(ADMISSION, *arguments, expect_success=False)


class BackupScriptTests(unittest.TestCase):
    def test_requires_preprovisioned_directory_and_syncs_artifacts_and_directory(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            backup = root / "backups"
            backup.mkdir(mode=0o700)
            password = root / "password"
            password.write_text("database-password\n", encoding="ascii")
            password.chmod(0o600)
            fake_bin = root / "bin"
            fake_bin.mkdir()
            pg_dump = fake_bin / "pg_dump"
            pg_dump.write_text(
                "#!/bin/sh\n"
                'while [ "$#" -gt 0 ]; do\n'
                '  if [ "$1" = --file ]; then shift; printf fixture > "$1"; fi\n'
                "  shift\n"
                "done\n",
                encoding="ascii",
            )
            pg_restore = fake_bin / "pg_restore"
            pg_restore.write_text(
                "#!/bin/sh\nprintf 'fixture toc\\n'\n", encoding="ascii"
            )
            sync = fake_bin / "sync"
            sync.write_text(
                '#!/bin/sh\nprintf \'%s\\n\' "$*" >> "$SYNC_LOG"\n',
                encoding="ascii",
            )
            for executable in (pg_dump, pg_restore, sync):
                executable.chmod(0o700)
            sync_log = root / "sync.log"
            environment = os.environ.copy()
            environment.update(
                {
                    "PATH": f"{fake_bin}:{environment['PATH']}",
                    "BACKUP_DIR": str(backup),
                    "CONTROL_DATABASE_PASSWORD_FILE": str(password),
                    "SYNC_LOG": str(sync_log),
                }
            )
            result = subprocess.run(
                [str(BACKUP_SCRIPT)],
                check=False,
                capture_output=True,
                text=True,
                env=environment,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(len(list(backup.glob("*.dump"))), 1)
            sync_lines = sync_log.read_text(encoding="utf-8").splitlines()
            self.assertEqual(len(sync_lines), 7)
            self.assertEqual(sync_lines[-1], f"-f {backup}")

            backup.chmod(0o755)
            rejected = subprocess.run(
                [str(BACKUP_SCRIPT)],
                check=False,
                capture_output=True,
                text=True,
                env=environment,
            )
            self.assertNotEqual(rejected.returncode, 0)
            self.assertIn("mode must be exactly 0700", rejected.stderr)


class WrapperFailClosedTests(unittest.TestCase):
    def test_wrapper_pins_compose_and_checks_revision_before_starting_both_apis(
        self,
    ) -> None:
        script = DEPLOY.read_text(encoding="utf-8")
        self.assertEqual(script.count("compose_source config --format json"), 1)
        self.assertNotIn("\ncompose config ", script)
        self.assertGreaterEqual(script.count('-f "$compose_snapshot"'), 2)
        self.assertEqual(script.count('--versions-lock "$versions_lock"'), 2)
        signed_verify = script.index("stage=verify-signed-release")
        source_extract = script.index("stage=extract-signed-source", signed_verify)
        compose_resolution = script.index("stage=resolve-compose", source_extract)
        first_pull = script.index("stage=pull-release-images", compose_resolution)
        self.assertLess(signed_verify, source_extract)
        self.assertLess(source_extract, compose_resolution)
        self.assertLess(compose_resolution, first_pull)
        self.assertIn('repo_root="$source_stage"', script[source_extract:compose_resolution])
        self.assertIn('--extract-to "$source_stage"', script[source_extract:compose_resolution])
        self.assertIn("--require-root-owner", script[source_extract:compose_resolution])
        self.assertIn("CONTROL_SOURCE_ARCHIVE_SHA256", script[source_extract:compose_resolution])
        self.assertIn("CONTROL_SOURCE_ATTESTATION_SHA256", script[source_extract:compose_resolution])
        self.assertIn("CONTROL_SOURCE_MANIFEST_SHA256", script[source_extract:compose_resolution])
        self.assertIn('versions_lock_source="$repo_root/versions.lock.json"', script)
        self.assertNotIn("auth_evidence=${SUB2API_AUTH_EVIDENCE_FILE", script)
        self.assertIn("external SUB2API_AUTH_EVIDENCE_FILE is prohibited", script)
        self.assertIn('--network "container:$sub2api_id"', script)
        self.assertIn("/usr/local/bin/probe-sub2api-auth-contract.py", script)
        self.assertNotIn('python3 "$auth_probe"', script)
        migration = script.index(
            "compose run --rm --no-deps --pull never control-migrate"
        )
        revision_gate = script.index("--require-current-head", migration)
        startup = script.index("stage=start-sidecars", revision_gate)
        self.assertLess(migration, revision_gate)
        self.assertLess(revision_gate, startup)
        self.assertIn("control-api control-api-replica codex-pwa", script[startup:])
        self.assertIn("--api-replica-inspect", script[startup:])

    def test_invalid_smoke_secret_never_reaches_compose_or_mutation(
        self,
    ) -> None:
        for case in ("missing", "broad", "symlink", "oversized", "missing-user"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                fake_bin = root / "bin"
                fake_bin.mkdir()
                log = root / "docker.log"
                docker = fake_bin / "docker"
                docker.write_text(
                    "#!/bin/sh\n"
                    'printf \'%s\\n\' "$*" >> "$FAKE_DOCKER_LOG"\n'
                    'case "$*" in\n'
                    "  'compose version') exit 0 ;;\n"
                    "esac\n"
                    "exit 99\n",
                    encoding="ascii",
                )
                docker.chmod(0o700)
                pg_restore = fake_bin / "pg_restore"
                pg_restore.write_text("#!/bin/sh\nexit 99\n", encoding="ascii")
                pg_restore.chmod(0o700)
                env_file = root / ".env"
                env_file.write_text("CONTROL_API_IMAGE=unused\n", encoding="ascii")
                env_file.chmod(0o600)
                records = root / "records"
                records.mkdir(mode=0o700)
                token = root / "smoke-access-token"
                token.write_text("short-lived-token\n", encoding="ascii")
                token.chmod(0o600)
                selected_token: Path | None = token
                if case == "missing":
                    selected_token = None
                elif case == "broad":
                    token.chmod(0o644)
                elif case == "symlink":
                    alias = root / "smoke-token-alias"
                    alias.symlink_to(token)
                    selected_token = alias
                elif case == "oversized":
                    token.write_text("x" * 65_537, encoding="ascii")
                environment = os.environ.copy()
                environment.pop("SUB2API_ACCESS_TOKEN", None)
                environment.update(
                    {
                        "PATH": f"{fake_bin}:{environment['PATH']}",
                        "FAKE_DOCKER_LOG": str(log),
                        "CONTROL_COMPOSE_ENV_FILE": str(env_file),
                        "CONTROL_DEPLOYMENT_RECORD_DIR": str(records),
                        "CONTROL_SMOKE_EXPECTED_USER_ID": (
                            "" if case == "missing-user" else "smoke-user"
                        ),
                    }
                )
                if selected_token is not None:
                    environment["CONTROL_SMOKE_ACCESS_TOKEN_FILE"] = str(selected_token)
                else:
                    environment.pop("CONTROL_SMOKE_ACCESS_TOKEN_FILE", None)
                result = subprocess.run(
                    [str(DEPLOY)],
                    check=False,
                    capture_output=True,
                    text=True,
                    env=environment,
                )
                self.assertNotEqual(result.returncode, 0)
                commands = log.read_text(encoding="utf-8")
                self.assertNotIn(" config ", commands)
                self.assertNotIn(" pull ", commands)
                self.assertNotIn("control-backup", commands)
                self.assertNotIn(" run ", commands)
                self.assertNotIn(" up ", commands)
                status_files = list(records.glob("deployment-*/status"))
                self.assertEqual(len(status_files), 1)
                self.assertEqual(
                    status_files[0].read_text().strip(), "failed:validate-smoke-input"
                )


if __name__ == "__main__":
    unittest.main()
