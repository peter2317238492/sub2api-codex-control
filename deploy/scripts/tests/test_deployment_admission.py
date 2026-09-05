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


def connector_metadata_value() -> dict[str, object]:
    matrix = (
        ("linux", "amd64", "deb"),
        ("linux", "amd64", "rpm"),
        ("linux", "arm64", "deb"),
        ("linux", "arm64", "rpm"),
    )
    return {
        "format_version": 1,
        "release_mode": "release",
        "releasable": True,
        "source_repository": SOURCE_REPOSITORY,
        "source_commit": "e" * 40,
        "version": "1.2.3",
        "tag": "connector-v1.2.3",
        "codex_version": "0.147.0",
        "schema_digest": "f" * 64,
        "manifest": {},
        "config_path_hint": "~/.config/sub2api-codex-connector/connector.json",
        "pair_command": "sub2api-codex-connector-ctl pair",
        "start_command": "sub2api-codex-connector-ctl start",
        "assets": [
            {
                "os": os_name,
                "arch": arch,
                "package_format": package_format,
                "sha256": f"{index + 1:x}" * 64,
                "size": index + 1,
            }
            for index, (os_name, arch, package_format) in enumerate(matrix)
        ],
    }


CONNECTOR_METADATA_JSON = json.dumps(
    connector_metadata_value(), sort_keys=True, separators=(",", ":")
)
CONNECTOR_METADATA_JSON_SHA256 = hashlib.sha256(
    CONNECTOR_METADATA_JSON.encode("ascii")
).hexdigest()


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
        "CONTROL_CONNECTOR_RELEASE_METADATA_JSON": CONNECTOR_METADATA_JSON,
        "CONTROL_SUB2API_BASE_URL": "http://sub2api:8080",
        "CONTROL_SUB2API_CONTRACT_MARKER": "9.8.7/eeeeeee",
        "CONTROL_TRUST_FORWARDED_FOR": "true",
        "CONTROL_REDIS_AUTH_MODE": "password",
        "CONTROL_REDIS_HOST": "redis",
        "CONTROL_REDIS_PORT": "6379",
        "CONTROL_REDIS_USER": "codex_control",
        "CONTROL_REDIS_PREFIX": "codex-control:",
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
                "CONTROL_CONNECTOR_RELEASE_METADATA_JSON_SHA256": (
                    CONNECTOR_METADATA_JSON_SHA256
                ),
                "CONTROL_SERVER_PACKAGE_MODE": "online",
                "CONTROL_SERVER_PACKAGE_DOCKER_HOST": "unix:///var/run/docker.sock",
                "CONTROL_SERVER_PACKAGE_MANIFEST_SHA256": "1" * 64,
                "CONTROL_SERVER_PACKAGE_VERIFICATION_RECEIPT_SHA256": "2" * 64,
                "_server_package": {
                    "mode": "online",
                    "docker_host": "unix:///var/run/docker.sock",
                    "manifest_sha256": "1" * 64,
                    "verification_receipt_sha256": "2" * 64,
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


class ServerPackageAdmissionTests(unittest.TestCase):
    def canonical(self, path: Path, value: object, mode: int) -> bytes:
        raw = (
            json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii")
            + b"\n"
        )
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
        path.chmod(mode)
        return raw

    def fixture(self, root: Path, *, mode: str = "offline") -> tuple[Path, Path, str]:
        package = root / "package"
        package.mkdir(mode=0o700)
        metadata = connector_metadata_value()
        metadata_raw = self.canonical(
            package / "connector-release-metadata.json", metadata, 0o444
        )
        connector_identity = {
            "source_repository": metadata["source_repository"],
            "source_commit": metadata["source_commit"],
            "version": metadata["version"],
            "tag": metadata["tag"],
            "release_id": 123,
            "workflow_run_id": 456,
            "workflow_run_attempt": 1,
        }
        aggregate = {
            "release": {
                key: connector_identity[key]
                for key in ("source_repository", "source_commit", "version", "tag")
            },
            "verification_run": {"run_id": 456, "run_attempt": 1},
            "public_release": {"release_id": 123},
        }
        connector_payloads = {
            "connector-release-metadata.json": metadata_raw,
            "connector-release-metadata.json.sigstore.json": b"connector bundle\n",
            "connector-public-verification-aggregate.json": self.canonical(
                package / "connector-public-verification-aggregate.json",
                aggregate,
                0o444,
            ),
            "connector-public-verification-aggregate.json.sigstore.json": b"aggregate bundle\n",
        }
        for name, raw in connector_payloads.items():
            path = package / name
            if not path.exists():
                path.write_bytes(raw)
                path.chmod(0o444)

        versions = {
            "format_version": 1,
            "codex": {"cli_version": "0.147.0", "schema_sha256": "f" * 64},
        }
        versions_raw = self.canonical(package / "source/versions.lock.json", versions, 0o444)
        contract_path = "docs/contracts/sub2api-auth.v9.8.7.json"
        contract_raw = self.canonical(
            package / f"source/{contract_path}", {"format_version": 1}, 0o444
        )
        source_files = {
            "source.tar.gz": b"source archive\n",
            "source-files.manifest": b"source manifest\n",
            "source-provenance.json": b"source attestation\n",
        }
        for name, raw in source_files.items():
            path = package / f"release/{name}"
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
            path.chmod(0o444)
        source_bundle = {
            role: {
                "filename": name,
                "sha256": hashlib.sha256(source_files[name]).hexdigest(),
                "size": len(source_files[name]),
            }
            for role, name in (
                ("archive", "source.tar.gz"),
                ("manifest", "source-files.manifest"),
                ("attestation", "source-provenance.json"),
            )
        }
        images = {
            "control-api": {"reference": API_REF, "digest": API_REF.rsplit("@", 1)[1]},
            "pwa": {"reference": PWA_REF, "digest": PWA_REF.rsplit("@", 1)[1]},
            "postgres-tools": {
                "reference": BACKUP_REF,
                "digest": BACKUP_REF.rsplit("@", 1)[1],
            },
        }
        control_lock = {
            "$schema": "fixture",
            "format_version": 1,
            "release": RELEASE,
            "release_tag": f"control-v{RELEASE}",
            "release_inputs": {
                "migration_head": "20260731_0008",
                "files": {
                    "versions.lock.json": hashlib.sha256(versions_raw).hexdigest(),
                    contract_path: hashlib.sha256(contract_raw).hexdigest(),
                },
            },
            "source": {
                "repository": SOURCE_REPOSITORY,
                "commit": SOURCE_REVISION,
                "ref": f"refs/tags/control-v{RELEASE}",
            },
            "source_bundle": source_bundle,
            "builder": {},
            "images": images,
        }
        lock_raw = self.canonical(
            package / "release/control-images.lock.json", control_lock, 0o444
        )
        bundle_raw = b"control lock bundle\n"
        bundle_path = package / "release/control-images.lock.sigstore.json"
        bundle_path.write_bytes(bundle_raw)
        bundle_path.chmod(0o444)

        evidence_names = [
            "control-images.lock.json",
            "control-images.lock.sigstore.json",
            *source_files,
        ]
        evidence = {
            name: {
                "filename": f"release/{name}",
                "sha256": hashlib.sha256((package / f"release/{name}").read_bytes()).hexdigest(),
                "size": (package / f"release/{name}").stat().st_size,
            }
            for name in evidence_names
        }
        image_file_paths: list[str] = []
        oci_export_record = None
        if mode == "offline":
            oci_export_raw = self.canonical(
                package / "oci-export-receipt.json",
                {"format_version": 1, "status": "verified"},
                0o444,
            )
            oci_export_record = {
                "filename": "oci-export-receipt.json",
                "sha256": hashlib.sha256(oci_export_raw).hexdigest(),
                "size": len(oci_export_raw),
            }
            image_file_paths.append("oci-export-receipt.json")
            for component, image in images.items():
                for suffix, raw in (
                    ("oci.tar", f"{component} archive\n".encode("ascii")),
                    (
                        "identity.json",
                        json.dumps(
                            {
                                "component": component,
                                "locked_digest": image["digest"],
                                "locked_reference": image["reference"],
                            },
                            sort_keys=True,
                            separators=(",", ":"),
                        ).encode("ascii")
                        + b"\n",
                    ),
                ):
                    relative = f"images/{component}.{suffix}"
                    path = package / relative
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(raw)
                    path.chmod(0o444)
                    image_file_paths.append(relative)
        file_paths = [
            *connector_payloads,
            "source/versions.lock.json",
            f"source/{contract_path}",
            *(f"release/{name}" for name in evidence_names),
            *image_file_paths,
        ]
        file_records = [
            {
                "mode": "0444",
                "path": path,
                "sha256": hashlib.sha256((package / path).read_bytes()).hexdigest(),
                "size": (package / path).stat().st_size,
            }
            for path in sorted(file_paths)
        ]
        connector_records = {
            role: {
                "filename": name,
                "sha256": hashlib.sha256((package / name).read_bytes()).hexdigest(),
                "size": (package / name).stat().st_size,
            }
            for role, name in (
                ("metadata", "connector-release-metadata.json"),
                ("metadata_bundle", "connector-release-metadata.json.sigstore.json"),
                ("aggregate", "connector-public-verification-aggregate.json"),
                (
                    "aggregate_bundle",
                    "connector-public-verification-aggregate.json.sigstore.json",
                ),
            )
        }
        package_images = {
            component: (
                {
                    "acquisition": "offline-oci",
                    "archive": {
                        "filename": f"images/{component}.oci.tar",
                        "sha256": hashlib.sha256(
                            (package / f"images/{component}.oci.tar").read_bytes()
                        ).hexdigest(),
                        "size": (package / f"images/{component}.oci.tar").stat().st_size,
                    },
                    "identity": {
                        "filename": f"images/{component}.identity.json",
                        "sha256": hashlib.sha256(
                            (package / f"images/{component}.identity.json").read_bytes()
                        ).hexdigest(),
                        "size": (
                            package / f"images/{component}.identity.json"
                        ).stat().st_size,
                    },
                    "locked_digest": image["digest"],
                    "locked_reference": image["reference"],
                }
                if mode == "offline"
                else {
                    "acquisition": "registry",
                    "digest": image["digest"],
                    "reference": image["reference"],
                    "repository": image["reference"].split("@", 1)[0],
                }
            )
            for component, image in images.items()
        }
        manifest = {
            "$schema": "https://sub2api-codex.invalid/schemas/server-package-inventory-v1.json",
            "format_version": 1,
            "product": "sub2api-codex-control-server",
            "release": RELEASE,
            "release_tag": f"control-v{RELEASE}",
            "mode": mode,
            "platform": "linux/amd64",
            "source": control_lock["source"],
            "builder": {},
            "source_date_epoch": 1,
            "common_payload_sha256": "7" * 64,
            "control_release": {
                "evidence": evidence,
                "lock_sha256": hashlib.sha256(lock_raw).hexdigest(),
                "bundle_sha256": hashlib.sha256(bundle_raw).hexdigest(),
            },
            "connector_release": {**connector_identity, **connector_records},
            "oci_export": oci_export_record,
            "source_bundle": source_bundle,
            "source_verification": {},
            "image_trust": {},
            "images": package_images,
            "lifecycle": {},
            "required_source_paths": [],
            "files": file_records,
        }
        manifest_path = package / "PACKAGE.json"
        manifest_raw = self.canonical(manifest_path, manifest, 0o444)
        package.chmod(0o555)
        receipt = {
            "$schema": "https://sub2api-codex.invalid/schemas/server-package-verification-v1.json",
            "format_version": 1,
            "status": "verified",
            "verified_at": 1,
            "release": RELEASE,
            "release_tag": f"control-v{RELEASE}",
            "mode": mode,
            "platform": "linux/amd64",
            "source": control_lock["source"],
            "package": {
                "filename": "server.tar.gz",
                "sha256": "8" * 64,
                "size": 1,
                "internal_manifest_sha256": hashlib.sha256(manifest_raw).hexdigest(),
                "extracted_root": str(package),
            },
            "release_manifest": {"filename": "server-packages.manifest.json", "sha256": "9" * 64, "size": 1},
            "trust": {},
        }
        receipt_path = root / "verification.json"
        self.canonical(receipt_path, receipt, 0o400)
        metadata_environment = metadata_raw.removesuffix(b"\n").decode("ascii")
        return manifest_path, receipt_path, metadata_environment

    def invoke(
        self,
        manifest: Path,
        receipt: Path,
        metadata_environment: str,
        *,
        mode: str = "offline",
        success: bool = True,
    ) -> subprocess.CompletedProcess[str]:
        environment = {
            **os.environ,
            "CONTROL_CONNECTOR_RELEASE_METADATA_JSON": metadata_environment,
            "DOCKER_HOST": "unix:///var/run/docker.sock",
        }
        result = subprocess.run(
            [
                sys.executable,
                str(ADMISSION),
                "server-package-release",
                "--manifest",
                str(manifest),
                "--verification-receipt",
                str(receipt),
                "--expected-manifest-sha256",
                hashlib.sha256(manifest.read_bytes()).hexdigest(),
                "--mode",
                mode,
                "--expected-source-repository",
                SOURCE_REPOSITORY,
                "--expected-source-commit",
                SOURCE_REVISION,
                "--expected-release-tag",
                f"control-v{RELEASE}",
                "--expected-owner-uid",
                str(os.geteuid()),
            ],
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

    def test_offline_package_receipt_generates_local_release_admission(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            manifest, receipt, metadata = self.fixture(Path(temporary))
            value = json.loads(self.invoke(manifest, receipt, metadata).stdout)
            self.assertEqual(value["CONTROL_SERVER_PACKAGE_MODE"], "offline")
            self.assertEqual(
                value["CONTROL_SERVER_PACKAGE_DOCKER_HOST"],
                "unix:///var/run/docker.sock",
            )
            self.assertEqual(value["CONTROL_API_IMAGE"], API_REF)
            self.assertEqual(
                value["CONTROL_CONNECTOR_RELEASE_METADATA_JSON_SHA256"],
                hashlib.sha256(metadata.encode("ascii")).hexdigest(),
            )
            self.assertEqual(
                value["_server_package"]["connector_release"]["release_id"], 123
            )
            self.assertEqual(
                value["_server_package"]["oci_export"]["filename"],
                "oci-export-receipt.json",
            )

    def test_package_admission_rejects_metadata_or_receipt_rebinding(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            manifest, receipt, metadata = self.fixture(Path(temporary))
            self.invoke(manifest, receipt, metadata + " ", success=False)
            receipt.chmod(0o600)
            value = json.loads(receipt.read_text(encoding="utf-8"))
            value["package"]["extracted_root"] = str(Path(temporary) / "other")
            self.canonical(receipt, value, 0o400)
            self.invoke(manifest, receipt, metadata, success=False)

    def test_package_admission_rejects_oci_export_or_outer_manifest_rebinding(
        self,
    ) -> None:
        for mutation, expected_error in (
            (
                lambda value: value["oci_export"].update(sha256="0" * 64),
                "OCI export binding differs",
            ),
            (
                lambda value: value.update(
                    consumer_verifier={
                        "filename": "server-package-verify.py",
                        "sha256": "0" * 64,
                        "size": 1,
                    }
                ),
                "unexpected schema",
            ),
        ):
            with self.subTest(
                expected_error=expected_error
            ), tempfile.TemporaryDirectory() as temporary:
                manifest, receipt, metadata = self.fixture(Path(temporary))
                package = manifest.parent
                package.chmod(0o700)
                manifest.chmod(0o600)
                manifest_value = json.loads(manifest.read_text(encoding="utf-8"))
                mutation(manifest_value)
                manifest_raw = self.canonical(manifest, manifest_value, 0o444)
                receipt.chmod(0o600)
                receipt_value = json.loads(receipt.read_text(encoding="utf-8"))
                receipt_value["package"]["internal_manifest_sha256"] = hashlib.sha256(
                    manifest_raw
                ).hexdigest()
                self.canonical(receipt, receipt_value, 0o400)
                package.chmod(0o555)
                result = self.invoke(manifest, receipt, metadata, success=False)
                self.assertIn(expected_error, result.stderr)


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
                "production_admission_profile": "immutable-image-v1",
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
        (self.root / "writable-sha256.txt").write_text("", encoding="utf-8")
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
            "--writable-file-sha256",
            str(self.root / "writable-sha256.txt"),
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

    def test_service_secret_copy_admits_service_owned_private_sources(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            source = root / "control_db_password"
            source.write_text("s3cret\n", encoding="ascii")
            destination = root / "control-db-password"
            arguments = types.SimpleNamespace(
                source=source,
                destination=destination,
                label="Control PostgreSQL password secret",
                max_bytes=1024,
            )
            for mode in (0o440, 0o400, 0o600, 0o640):
                source.chmod(mode)
                evidence = ADMISSION_MODULE.copy_service_secret(arguments)
                self.assertEqual(destination.read_bytes(), source.read_bytes())
                self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o600)
                self.assertEqual(
                    evidence["source_sha256"],
                    hashlib.sha256(source.read_bytes()).hexdigest(),
                )
                destination.unlink()
            for mode in (0o444, 0o460, 0o604):
                source.chmod(mode)
                with self.assertRaisesRegex(ValueError, "untrusted group or user"):
                    ADMISSION_MODULE.copy_service_secret(arguments)
            source.chmod(0o440)
            alias = root / "control_db_password.link"
            os.link(source, alias)
            with self.assertRaisesRegex(ValueError, "exactly one hard link"):
                ADMISSION_MODULE.copy_service_secret(arguments)

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
                service: str,
                identifier: str,
                image_id: str,
                network: str,
                target: int,
                port: str,
            ) -> list[dict[str, object]]:
                network_id = "8" * 64 if network == "control_pwa-network" else "9" * 64
                return [
                    {
                        "Id": identifier * 64,
                        "Name": f"/{service}",
                        "Image": image_id,
                        "Config": {
                            "Labels": {
                                "com.docker.compose.project": "control",
                                "com.docker.compose.service": service,
                                "com.docker.compose.oneoff": "False",
                                "com.docker.compose.container-number": "1",
                                "com.docker.compose.project.config_files": str(
                                    root / "compose-config.json"
                                ),
                            }
                        },
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
                container(
                    "control-api",
                    "a",
                    api_image_id,
                    "sub2api-network",
                    8090,
                    "18090",
                ),
            )
            write_json(
                paths["replica"],
                container(
                    "control-api-replica",
                    "b",
                    api_image_id,
                    "sub2api-network",
                    8090,
                    "18093",
                ),
            )
            write_json(
                paths["pwa"],
                container(
                    "codex-pwa",
                    "c",
                    pwa_image_id,
                    "control_pwa-network",
                    8080,
                    "18091",
                ),
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
                "codex-pwa",
                "c",
                pwa_image_id,
                "control_pwa-network",
                8080,
                "18091",
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
                "control-api-replica",
                "b",
                api_image_id,
                "unexpected-network",
                8090,
                "18093",
            )
            write_json(paths["replica"], bad_replica)
            run_python(ADMISSION, *arguments, expect_success=False)

            write_json(
                paths["replica"],
                container(
                    "control-api-replica",
                    "b",
                    api_image_id,
                    "sub2api-network",
                    8090,
                    "18093",
                ),
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


class RecoveryChainTests(unittest.TestCase):
    def test_terminal_recovery_chain_binds_backup_restore_isolation_and_reverse_plan(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            now = datetime.now(UTC).isoformat().replace("+00:00", "Z")
            paths = {
                name: root / f"{name}.json"
                for name in (
                    "plan",
                    "releases",
                    "revisions",
                    "premigration",
                    "full",
                    "restore",
                    "isolation",
                    "unfreeze",
                    "freeze",
                    "stopped_before",
                    "stopped_after",
                    "reverse",
                    "rollback_compose",
                    "current_control_containers",
                )
            }
            write_json(paths["plan"], {"release": "1.2.3"})
            api_image_id = f"sha256:{'3' * 64}"
            pwa_image_id = f"sha256:{'4' * 64}"
            write_json(
                paths["releases"],
                {
                    "api": {"image_id": api_image_id},
                    "pwa": {"image_id": pwa_image_id},
                },
            )
            write_json(
                paths["revisions"],
                {
                    "source_database_revision": "old",
                    "target_migration_head": "new",
                },
            )
            dump_sha = "5" * 64
            write_json(
                paths["premigration"],
                {"dump_path": "/private/dump", "dump_sha256": dump_sha},
            )
            write_json(paths["current_control_containers"], [])
            write_json(paths["stopped_before"], [])
            write_json(paths["stopped_after"], [])
            write_json(
                paths["rollback_compose"],
                {
                    "services": {
                        "control-api": {"image": api_image_id},
                        "control-api-replica": {"image": api_image_id},
                        "codex-pwa": {"image": pwa_image_id},
                    }
                },
            )
            required_artifacts = {
                name: {"sha256": "a" * 64, "size": 1}
                for name in (
                    "sub2api-postgres.dump",
                    "postgres-additional-databases.json",
                    "redis-logical.rdb",
                    "release-records.tar.gz",
                    "release-records-inventory.json",
                    "release-evidence-inventory.json",
                    "docker-network-inspect.json",
                    "docker-networks.json",
                )
            }
            full = {
                "status": "admitted",
                "fresh": True,
                "admission_mode": "fresh-production-backup",
                "owner_uid": os.geteuid(),
                "backup_created_at": now,
                "receipt_sha256": "b" * 64,
                "manifest_sha256": "c" * 64,
                "artifacts": required_artifacts,
            }
            write_json(paths["full"], full)
            full_sha = hashlib.sha256(paths["full"].read_bytes()).hexdigest()
            restore = {
                "format_version": 1,
                "type": "production-isolated-restore-v1",
                "status": "succeeded",
                "completed_at": now,
                "backup_admission_sha256": full_sha,
                "backup_receipt_sha256": full["receipt_sha256"],
                "snapshot_manifest_sha256": full["manifest_sha256"],
                "isolation": {
                    "docker_network_mode": "none",
                    "published_ports": 0,
                    "temporary_containers_removed": True,
                },
                "postgresql": {"restore_completed": True},
                "redis": {"restore_completed": True},
            }
            isolation = {
                "format_version": 1,
                "type": "production-datastore-isolation-v1",
                "status": "passed",
                "completed_at": now,
                "deployment_plan_sha256": hashlib.sha256(
                    paths["plan"].read_bytes()
                ).hexdigest(),
                "backup_admission_sha256": full_sha,
                "backup_receipt_sha256": full["receipt_sha256"],
                "snapshot_manifest_sha256": full["manifest_sha256"],
                "postgresql": {
                    "role_flags_exact": True,
                    "membership_count": 0,
                    "database_owner_exact": True,
                    "schema_and_object_owners_exact": True,
                    "public_connect_revoked": True,
                    "control_to_sub2api_connect_denied": True,
                    "control_positive_connection": True,
                },
                "redis": {
                    "authenticated": True,
                    "acl_exact": True,
                    "aclfile_configured": True,
                    "anonymous_access_denied": True,
                    "enabled_nopass_users_absent": True,
                    "inside_prefix_read_write_passed": True,
                    "outside_prefix_read_denied": True,
                    "outside_prefix_write_denied": True,
                    "inside_channel_publish_passed": True,
                    "outside_channel_publish_denied": True,
                    "administrative_command_denied": True,
                },
            }
            write_json(paths["restore"], restore)
            write_json(paths["isolation"], isolation)
            current_sha = hashlib.sha256(
                paths["current_control_containers"].read_bytes()
            ).hexdigest()
            unfreeze = {
                "format_version": 1,
                "type": "production-writer-unfreeze-plan-v1",
                "status": "admitted",
                "created_at": now,
                "limits": {
                    "max_steps": 2,
                    "max_attempts_per_step": 1,
                    "total_timeout_seconds": 240,
                    "post_unfreeze_verification_timeout_seconds": 120,
                    "database_restore_allowed": False,
                    "exact_container_ids_required": True,
                },
                "bindings": {
                    "current_control_containers_sha256": current_sha,
                },
                "steps": [
                    {
                        "ordinal": ordinal,
                        "action": "require-absent",
                        "service": service,
                        "previous": None,
                        "max_attempts": 1,
                        "timeout_seconds": 60,
                    }
                    for ordinal, service in enumerate(
                        ("control-api-replica", "control-api"), start=1
                    )
                ],
            }
            write_json(paths["unfreeze"], unfreeze)
            freeze = {
                "format_version": 1,
                "type": "production-writer-freeze-v1",
                "status": "passed",
                "completed_at": now,
                "bindings": {
                    "current_control_containers_sha256": current_sha,
                    "unfreeze_plan_sha256": hashlib.sha256(
                        paths["unfreeze"].read_bytes()
                    ).hexdigest(),
                    "stopped_before_backup_sha256": hashlib.sha256(
                        paths["stopped_before"].read_bytes()
                    ).hexdigest(),
                    "stopped_after_backup_sha256": hashlib.sha256(
                        paths["stopped_after"].read_bytes()
                    ).hexdigest(),
                },
                "no_write_window": {
                    "all_writers_stopped": True,
                    "container_restart_observed": False,
                    "exact_container_ids_preserved": True,
                },
                "writers": {
                    "control-api-replica": {"previous": None, "stopped": None},
                    "control-api": {"previous": None, "stopped": None},
                },
            }
            write_json(paths["freeze"], freeze)
            reverse = {
                "format_version": 1,
                "type": "production-bounded-reverse-plan-v1",
                "status": "admitted",
                "created_at": now,
                "limits": {
                    "automatic_reverse_on_failure": True,
                    "database_restore_requires_write_freeze": True,
                    "database_restore_policy": (
                        "only-before-writer-exposure-after-observed-mutation"
                    ),
                    "writer_exposure_after_database_mutation_allowed": False,
                    "application_reverse_preserves_database": True,
                    "migration_required": True,
                    "max_attempts_per_step": 1,
                    "max_reverse_steps": 5,
                    "total_timeout_seconds": 900,
                    "post_reverse_verification_timeout_seconds": 120,
                },
                "bindings": {
                    "deployment_plan_sha256": hashlib.sha256(
                        paths["plan"].read_bytes()
                    ).hexdigest(),
                    "release_images_sha256": hashlib.sha256(
                        paths["releases"].read_bytes()
                    ).hexdigest(),
                    "revisions_sha256": hashlib.sha256(
                        paths["revisions"].read_bytes()
                    ).hexdigest(),
                    "premigration_backup_sha256": hashlib.sha256(
                        paths["premigration"].read_bytes()
                    ).hexdigest(),
                    "full_backup_admission_sha256": full_sha,
                    "isolated_restore_receipt_sha256": hashlib.sha256(
                        paths["restore"].read_bytes()
                    ).hexdigest(),
                    "datastore_isolation_receipt_sha256": hashlib.sha256(
                        paths["isolation"].read_bytes()
                    ).hexdigest(),
                    "writer_unfreeze_plan_sha256": hashlib.sha256(
                        paths["unfreeze"].read_bytes()
                    ).hexdigest(),
                    "writer_freeze_receipt_sha256": hashlib.sha256(
                        paths["freeze"].read_bytes()
                    ).hexdigest(),
                    "current_control_containers_sha256": hashlib.sha256(
                        paths["current_control_containers"].read_bytes()
                    ).hexdigest(),
                    "rollback_compose_sha256": hashlib.sha256(
                        paths["rollback_compose"].read_bytes()
                    ).hexdigest(),
                },
                "forward_steps": [
                    {
                        "ordinal": 1,
                        "action": "apply-admitted-migration",
                        "from_revision": "old",
                        "to_revision": "new",
                        "timeout_seconds": 180,
                    },
                    {
                        "ordinal": 2,
                        "action": "recreate-one-service",
                        "service": "control-api-replica",
                        "new_image_id": api_image_id,
                        "timeout_seconds": 120,
                    },
                    {
                        "ordinal": 3,
                        "action": "recreate-one-service",
                        "service": "control-api",
                        "new_image_id": api_image_id,
                        "timeout_seconds": 120,
                    },
                    {
                        "ordinal": 4,
                        "action": "recreate-one-service",
                        "service": "codex-pwa",
                        "new_image_id": pwa_image_id,
                        "timeout_seconds": 120,
                    },
                ],
                "reverse_steps": [
                    {
                        "ordinal": 1,
                        "action": "stop-database-mutators",
                        "services": [
                            "control-api",
                            "control-api-replica",
                            "control-migrate",
                        ],
                        "max_attempts": 1,
                        "timeout_seconds": 105,
                    },
                    {
                        "ordinal": 2,
                        "action": "restore-control-database-from-premigration-dump",
                        "max_attempts": 1,
                        "timeout_seconds": 360,
                        "write_freeze_required": True,
                        "condition": "database-mutated-and-writers-never-reexposed",
                        "dump_path": "/private/dump",
                        "dump_sha256": dump_sha,
                    },
                    *[
                        {
                            "ordinal": ordinal,
                            "action": "remove-new-service",
                            "service": service,
                            "previous": None,
                            "max_attempts": 1,
                            "timeout_seconds": 105,
                        }
                        for ordinal, service in enumerate(
                            ("codex-pwa", "control-api", "control-api-replica"),
                            start=3,
                        )
                    ],
                ],
            }
            write_json(paths["reverse"], reverse)
            arguments = types.SimpleNamespace(
                plan=paths["plan"],
                releases=paths["releases"],
                revisions=paths["revisions"],
                backup=paths["premigration"],
                full_backup=paths["full"],
                restore_receipt=paths["restore"],
                isolation_receipt=paths["isolation"],
                writer_unfreeze_plan=paths["unfreeze"],
                writer_freeze_receipt=paths["freeze"],
                writers_stopped_before_backup=paths["stopped_before"],
                writers_stopped_after_backup=paths["stopped_after"],
                reverse_plan=paths["reverse"],
                rollback_compose=paths["rollback_compose"],
                current_control_containers=paths["current_control_containers"],
                recovery_max_age_seconds=1800,
            )
            value = ADMISSION_MODULE.recovery_chain(arguments, {"release": "1.2.3"})
            self.assertEqual(
                value["full_backup"]["sha256"], full_sha
            )
            self.assertEqual(
                value["bounded_reverse_plan"]["sha256"],
                hashlib.sha256(paths["reverse"].read_bytes()).hexdigest(),
            )

            isolation["redis"]["acl_exact"] = False
            write_json(paths["isolation"], isolation)
            with self.assertRaisesRegex(ValueError, "live datastore isolation"):
                ADMISSION_MODULE.recovery_chain(arguments, {"release": "1.2.3"})

            isolation["redis"]["acl_exact"] = True
            write_json(paths["isolation"], isolation)
            reverse["forward_steps"][1]["new_image_id"] = pwa_image_id
            write_json(paths["reverse"], reverse)
            with self.assertRaisesRegex(ValueError, "exact old and new identities"):
                ADMISSION_MODULE.recovery_chain(arguments, {"release": "1.2.3"})


class BoundedUninstallAdmissionTests(unittest.TestCase):
    @staticmethod
    def write_canonical(path: Path, value: object, mode: int = 0o600) -> bytes:
        payload = (
            json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n"
        ).encode("ascii")
        if path.exists():
            path.chmod(0o600)
        path.write_bytes(payload)
        path.chmod(mode)
        return payload

    @staticmethod
    def live_container(
        service: str,
        container_id: str,
        image_id: str,
        network: str,
        network_id: str,
        endpoint_id: str,
        published_port: str,
        labels: dict[str, str],
    ) -> dict[str, object]:
        target_port = 8080 if service == "codex-pwa" else 8090
        return {
            "Id": container_id,
            "Name": f"/{service}",
            "Image": image_id,
            "Config": {"Labels": labels},
            "HostConfig": {
                "PortBindings": {
                    f"{target_port}/tcp": [
                        {"HostIp": "127.0.0.1", "HostPort": published_port}
                    ]
                }
            },
            "State": {"Health": {"Status": "healthy"}, "Running": True},
            "NetworkSettings": {
                "Networks": {
                    network: {
                        "NetworkID": network_id,
                        "EndpointID": endpoint_id,
                    }
                }
            },
        }

    def fixture(
        self, root: Path
    ) -> tuple[types.SimpleNamespace, Path, dict[str, object]]:
        root.chmod(0o700)
        package_root = root / "active-package"
        package_root.mkdir(mode=0o700)
        manifest_path = package_root / "PACKAGE.json"
        manifest = {"release": RELEASE, "release_tag": f"v{RELEASE}"}
        manifest_raw = self.write_canonical(manifest_path, manifest, mode=0o444)
        receipt_path = package_root / "verification-receipt.json"
        receipt_raw = self.write_canonical(
            receipt_path,
            {
                "status": "verified",
                "manifest_sha256": hashlib.sha256(manifest_raw).hexdigest(),
            },
            mode=0o400,
        )
        package_root.chmod(0o555)

        deployment = root / "deployment-20260815T010203Z-99"
        deployment.mkdir(mode=0o700)
        compose_config = deployment / "compose-config.json"
        self.write_canonical(compose_config, {})
        status = deployment / "status"
        status.write_bytes(b"deployed\n")
        status.chmod(0o600)

        manifest_sha256 = hashlib.sha256(manifest_raw).hexdigest()
        receipt_sha256 = hashlib.sha256(receipt_raw).hexdigest()
        release = {
            "CONTROL_RELEASE": RELEASE,
            "CONTROL_SERVER_PACKAGE_DOCKER_HOST": "unix:///var/run/docker.sock",
            "CONTROL_SERVER_PACKAGE_MANIFEST_SHA256": manifest_sha256,
            "CONTROL_SERVER_PACKAGE_MODE": "offline",
            "CONTROL_SERVER_PACKAGE_VERIFICATION_RECEIPT_SHA256": receipt_sha256,
            "_server_package": {
                "docker_host": "unix:///var/run/docker.sock",
                "manifest_path": str(manifest_path),
                "manifest_sha256": manifest_sha256,
                "mode": "offline",
                "verification_receipt_path": str(receipt_path),
                "verification_receipt_sha256": receipt_sha256,
            },
        }
        release_raw = self.write_canonical(
            deployment / "release-verification.json", release
        )

        api_id = "a" * 64
        replica_id = "b" * 64
        pwa_id = "c" * 64
        api_image = f"sha256:{'1' * 64}"
        pwa_image = f"sha256:{'2' * 64}"
        sub2api_network_id = "9" * 64
        pwa_network_id = "8" * 64
        pwa_endpoint_id = "7" * 64
        published_ports = {
            "control-api": "18090",
            "control-api-replica": "18093",
            "codex-pwa": "18091",
        }
        container_labels = {
            service: {
                "com.docker.compose.project": "control",
                "com.docker.compose.service": service,
                "com.docker.compose.oneoff": "False",
                "com.docker.compose.container-number": "1",
                "com.docker.compose.project.config_files": str(compose_config),
                "com.example.package-runtime": f"{service}-identity",
            }
            for service in published_ports
        }
        terminal_containers = {
            "control-api": {
                "container_id": api_id,
                "container_name": "/control-api",
                "image_id": api_image,
                "health": "healthy",
                "network": "sub2api-network",
                "published_port": published_ports["control-api"],
                "compose_project": "control",
                "compose_service": "control-api",
                "compose_oneoff": False,
                "labels": container_labels["control-api"],
            },
            "control-api-replica": {
                "container_id": replica_id,
                "container_name": "/control-api-replica",
                "image_id": api_image,
                "health": "healthy",
                "network": "sub2api-network",
                "published_port": published_ports["control-api-replica"],
                "compose_project": "control",
                "compose_service": "control-api-replica",
                "compose_oneoff": False,
                "labels": container_labels["control-api-replica"],
            },
            "codex-pwa": {
                "container_id": pwa_id,
                "container_name": "/codex-pwa",
                "image_id": pwa_image,
                "health": "healthy",
                "network": "control_pwa-network",
                "published_port": published_ports["codex-pwa"],
                "compose_project": "control",
                "compose_service": "codex-pwa",
                "compose_oneoff": False,
                "labels": container_labels["codex-pwa"],
            },
        }
        network_options = {
            "com.docker.network.bridge.enable_ip_masquerade": "false",
            "com.docker.network.bridge.enable_icc": "false",
        }
        network_labels = {
            "com.docker.compose.network": "pwa-network",
            "com.docker.compose.project": "control",
            "com.example.package-network": "pwa-identity",
        }
        terminal_network = {
            "network_id": pwa_network_id,
            "name": "control_pwa-network",
            "compose_project": "control",
            "driver": "bridge",
            "internal": False,
            "enable_ipv6": False,
            "options": network_options,
            "container_id": pwa_id,
            "compose_network": "pwa-network",
            "labels": network_labels,
            "member_container_ids": [pwa_id],
        }
        deployment_record = {
            "format_version": 1,
            "release": RELEASE,
            "running": {
                "containers": terminal_containers,
                "pwa_network": terminal_network,
            },
            "signed_release": {
                "sha256": hashlib.sha256(release_raw).hexdigest(),
                "values": release,
            },
            "status": "deployed",
        }
        self.write_canonical(
            deployment / "deployment.json", deployment_record, mode=0o400
        )

        project_containers = [
            self.live_container(
                "control-api",
                api_id,
                api_image,
                "sub2api-network",
                sub2api_network_id,
                "4" * 64,
                published_ports["control-api"],
                container_labels["control-api"],
            ),
            self.live_container(
                "control-api-replica",
                replica_id,
                api_image,
                "sub2api-network",
                sub2api_network_id,
                "5" * 64,
                published_ports["control-api-replica"],
                container_labels["control-api-replica"],
            ),
            self.live_container(
                "codex-pwa",
                pwa_id,
                pwa_image,
                "control_pwa-network",
                pwa_network_id,
                pwa_endpoint_id,
                published_ports["codex-pwa"],
                container_labels["codex-pwa"],
            ),
        ]
        project_inspect = deployment / "uninstall-project-containers-inspect.json"
        self.write_canonical(project_inspect, project_containers)
        pwa_network_inspect = deployment / "uninstall-pwa-network-inspect.json"
        self.write_canonical(
            pwa_network_inspect,
            [
                {
                    "Attachable": False,
                    "ConfigOnly": False,
                    "Containers": {
                        pwa_id: {
                            "EndpointID": pwa_endpoint_id,
                            "Name": "codex-pwa",
                        }
                    },
                    "Driver": "bridge",
                    "EnableIPv6": False,
                    "Id": pwa_network_id,
                    "Ingress": False,
                    "Internal": False,
                    "Labels": network_labels,
                    "Name": "control_pwa-network",
                    "Options": network_options,
                    "Scope": "local",
                }
            ],
        )
        arguments = types.SimpleNamespace(
            deployment_directory=deployment,
            expected_manifest_sha256=manifest_sha256,
            expected_owner_uid=os.geteuid(),
            manifest=manifest_path,
            mode="offline",
            project_containers_inspect=project_inspect,
            pwa_network_inspect=pwa_network_inspect,
            record_root=root,
            trigger_stage=(
                "lifecycle-uninstall:20260815T010204Z-123456789-88-uninstall-"
                + "d" * 32
            ),
            verification_receipt=receipt_path,
        )
        artifacts: dict[str, object] = {
            "manifest": manifest,
            "manifest_path": manifest_path,
            "network_labels": network_labels,
            "project_containers": project_containers,
            "project_inspect": project_inspect,
            "pwa_network_id": pwa_network_id,
            "terminal_containers": terminal_containers,
        }
        return arguments, deployment, artifacts

    def test_admits_active_package_terminal_runtime_and_records_execution(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            arguments, deployment, artifacts = self.fixture(Path(temporary))
            plan = ADMISSION_MODULE.bounded_uninstall_plan(arguments)
            self.assertEqual(plan["status"], "admitted")
            self.assertEqual(
                plan["active_package"]["manifest_sha256"],
                arguments.expected_manifest_sha256,
            )
            self.assertEqual(
                set(plan["targets"]["containers"]),
                {"control-api", "control-api-replica", "codex-pwa"},
            )
            for service, terminal in artifacts["terminal_containers"].items():
                target = plan["targets"]["containers"][service]
                live = next(
                    item
                    for item in artifacts["project_containers"]
                    if item["Config"]["Labels"]["com.docker.compose.service"]
                    == service
                )
                self.assertEqual(target["container_id"], terminal["container_id"])
                self.assertEqual(target["container_name"], live["Name"])
                self.assertEqual(target["image_id"], terminal["image_id"])
                self.assertEqual(target["compose_project"], "control")
                self.assertEqual(target["compose_service"], service)
                self.assertFalse(target["compose_oneoff"])
                self.assertEqual(target["labels"], live["Config"]["Labels"])
            self.assertEqual(
                plan["targets"]["pwa_network"]["network_id"],
                artifacts["pwa_network_id"],
            )
            self.assertEqual(
                plan["targets"]["pwa_network"]["compose_network"], "pwa-network"
            )
            self.assertEqual(
                plan["targets"]["pwa_network"]["labels"],
                artifacts["network_labels"],
            )
            self.assertEqual(
                plan["targets"]["pwa_network"]["member_container_ids"],
                [artifacts["terminal_containers"]["codex-pwa"]["container_id"]],
            )
            self.assertTrue(plan["preserved"]["sub2api_runtime"])
            self.assertTrue(plan["preserved"]["postgresql"])
            self.assertTrue(plan["preserved"]["redis"])
            self.assertTrue(plan["preserved"]["nginx_configuration"])
            self.assertTrue(plan["preserved"]["logrotate_policy"])

            plan_path = deployment / "uninstall-plan.json"
            self.write_canonical(plan_path, plan, mode=0o400)
            empty_network_inspect = (
                deployment / "uninstall-pwa-network-empty-inspect.json"
            )
            empty_network_raw = self.write_canonical(
                empty_network_inspect,
                [
                    {
                        "Containers": {},
                        "Id": artifacts["pwa_network_id"],
                        "Labels": artifacts["network_labels"],
                        "Name": "control_pwa-network",
                    }
                ],
            )
            execution = ADMISSION_MODULE.bounded_uninstall_execution(
                types.SimpleNamespace(
                    empty_network_inspect=empty_network_inspect,
                    expected_owner_uid=os.geteuid(),
                    plan=plan_path,
                    project_containers_absent=True,
                    pwa_network_absent=True,
                    trigger_stage=arguments.trigger_stage,
                )
            )
            self.assertEqual(execution["status"], "succeeded")
            removed_by_service = {
                item["service"]: item
                for item in execution["removed"]["containers"]
            }
            for service, target in plan["targets"]["containers"].items():
                self.assertEqual(
                    removed_by_service[service], {"service": service, **target}
                )
            removed_network = execution["removed"]["pwa_network"]
            self.assertEqual(
                removed_network["network_id"],
                artifacts["pwa_network_id"],
            )
            self.assertEqual(
                removed_network["labels"],
                artifacts["network_labels"],
            )
            self.assertEqual(
                removed_network["member_container_ids_at_admission"],
                [artifacts["terminal_containers"]["codex-pwa"]["container_id"]],
            )
            self.assertEqual(
                removed_network["members_after_container_removal"],
                [],
            )
            self.assertEqual(
                execution["network_empty_evidence"],
                {
                    "path": str(empty_network_inspect),
                    "sha256": hashlib.sha256(empty_network_raw).hexdigest(),
                },
            )
            self.assertTrue(execution["postconditions"]["project_containers_absent"])
            self.assertTrue(execution["postconditions"]["one_off_containers_absent"])
            self.assertTrue(
                execution["postconditions"]["pwa_network_zero_members_before_removal"]
            )
            self.assertTrue(execution["postconditions"]["pwa_network_absent"])

    def test_execution_rejects_rebound_or_nonempty_network_evidence(self) -> None:
        mutations = {
            "network ID drift": lambda value: value.update(Id="f" * 64),
            "network name drift": lambda value: value.update(Name="replacement"),
            "network label drift": lambda value: value["Labels"].update(
                **{"com.example.package-network": "replacement"}
            ),
            "network still has member": lambda value: value["Containers"].update(
                **{"c" * 64: {"Name": "codex-pwa"}}
            ),
        }
        for label, mutate in mutations.items():
            with self.subTest(label=label), tempfile.TemporaryDirectory() as temporary:
                arguments, deployment, artifacts = self.fixture(Path(temporary))
                plan_path = deployment / "uninstall-plan.json"
                self.write_canonical(
                    plan_path,
                    ADMISSION_MODULE.bounded_uninstall_plan(arguments),
                    mode=0o400,
                )
                evidence = {
                    "Containers": {},
                    "Id": artifacts["pwa_network_id"],
                    "Labels": copy.deepcopy(artifacts["network_labels"]),
                    "Name": "control_pwa-network",
                }
                mutate(evidence)
                empty_network_inspect = (
                    deployment / "uninstall-pwa-network-empty-inspect.json"
                )
                self.write_canonical(empty_network_inspect, [evidence])
                execution_arguments = types.SimpleNamespace(
                    empty_network_inspect=empty_network_inspect,
                    expected_owner_uid=os.geteuid(),
                    plan=plan_path,
                    project_containers_absent=True,
                    pwa_network_absent=True,
                    trigger_stage=arguments.trigger_stage,
                )
                with self.assertRaisesRegex(
                    ValueError, "exact PWA network was empty"
                ):
                    ADMISSION_MODULE.bounded_uninstall_execution(
                        execution_arguments
                    )

    def test_rejects_extra_oneoff_project_container(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            arguments, _, artifacts = self.fixture(Path(temporary))
            project_containers = copy.deepcopy(artifacts["project_containers"])
            extra = copy.deepcopy(project_containers[0])
            extra["Id"] = "f" * 64
            extra["Config"]["Labels"]["com.docker.compose.service"] = "control-migrate"
            extra["Config"]["Labels"]["com.docker.compose.oneoff"] = "True"
            project_containers.append(extra)
            self.write_canonical(artifacts["project_inspect"], project_containers)
            with self.assertRaisesRegex(
                ValueError, "exactly three active project containers"
            ):
                ADMISSION_MODULE.bounded_uninstall_plan(arguments)

    def test_rejects_terminal_container_id_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            arguments, _, artifacts = self.fixture(Path(temporary))
            project_containers = copy.deepcopy(artifacts["project_containers"])
            project_containers[0]["Id"] = "f" * 64
            self.write_canonical(artifacts["project_inspect"], project_containers)
            with self.assertRaisesRegex(ValueError, "runtime drifted for control-api"):
                ADMISSION_MODULE.bounded_uninstall_plan(arguments)

    def test_rejects_active_package_hash_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            arguments, _, artifacts = self.fixture(Path(temporary))
            manifest_path = artifacts["manifest_path"]
            drifted_manifest = dict(artifacts["manifest"])
            drifted_manifest["release_tag"] = "v9.9.9-drifted"
            drifted_raw = self.write_canonical(
                manifest_path, drifted_manifest, mode=0o444
            )
            arguments.expected_manifest_sha256 = hashlib.sha256(drifted_raw).hexdigest()
            with self.assertRaisesRegex(ValueError, "active lifecycle package"):
                ADMISSION_MODULE.bounded_uninstall_plan(arguments)


class PostSuccessReverseAdmissionTests(unittest.TestCase):
    @staticmethod
    def write_canonical(path: Path, value: object, mode: int = 0o600) -> bytes:
        payload = (
            json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n"
        ).encode("ascii")
        if path.exists():
            path.chmod(0o600)
        path.write_bytes(payload)
        path.chmod(mode)
        return payload

    def fixture(
        self, root: Path
    ) -> tuple[types.SimpleNamespace, Path, dict[str, object]]:
        root.chmod(0o700)
        deployment = root / "deployment-20260815T010203Z-99"
        deployment.mkdir(mode=0o700)
        trigger = (
            "lifecycle-post-success:20260815T010204Z-123456789-88-upgrade-"
            + "a" * 32
        )
        compose_raw = self.write_canonical(deployment / "compose-config.json", {})
        versions_raw = self.write_canonical(deployment / "versions.lock.json", {})
        contract_raw = self.write_canonical(
            deployment / "sub2api-auth-contract.json", {}
        )
        probe = {
            "base_url": "http://127.0.0.1:8080",
            "nonce": "b" * 64,
            "expected_user_id": "fixture-user",
            "network_namespace_container_id": "c" * 64,
            "proxy_environment_disabled": True,
        }
        auth = {"format_version": 4, "probe": probe}
        self.write_canonical(deployment / "generated-auth-evidence.json", auth)
        auth_digest = hashlib.sha256(
            json.dumps(auth, sort_keys=True, separators=(",", ":")).encode("ascii")
        ).hexdigest()
        plan = {
            "resolved_compose_sha256": hashlib.sha256(compose_raw).hexdigest(),
            "versions_lock_sha256": hashlib.sha256(versions_raw).hexdigest(),
            "auth_contract_sha256": hashlib.sha256(contract_raw).hexdigest(),
            "compose_project": "sub2api-control",
            "sub2api_network": "sub2api-network",
        }
        plan_raw = self.write_canonical(deployment / "plan.json", plan)
        reverse_plan = {
            "format_version": 1,
            "type": "production-bounded-reverse-plan-v1",
            "status": "admitted",
            "limits": {
                "migration_required": False,
                "application_reverse_preserves_database": True,
                "writer_exposure_after_database_mutation_allowed": False,
                "database_restore_policy": (
                    "only-before-writer-exposure-after-observed-mutation"
                ),
                "automatic_reverse_on_failure": True,
                "database_restore_requires_write_freeze": True,
                "max_attempts_per_step": 1,
                "max_reverse_steps": 8,
                "post_reverse_verification_timeout_seconds": 120,
                "total_timeout_seconds": 900,
            },
            "bindings": {
                "deployment_plan_sha256": hashlib.sha256(plan_raw).hexdigest()
            },
            "reverse_steps": [
                {
                    "ordinal": 1,
                    "action": "stop-database-mutators",
                    "services": [
                        "control-api",
                        "control-api-replica",
                        "control-migrate",
                    ],
                    "max_attempts": 1,
                    "timeout_seconds": 105,
                },
                {
                    "ordinal": 2,
                    "action": "restore-control-database-from-premigration-dump",
                    "condition": "database-mutated-and-writers-never-reexposed",
                    "write_freeze_required": True,
                    "max_attempts": 1,
                    "timeout_seconds": 360,
                },
                {
                    "ordinal": 3,
                    "action": "recreate-prior-service",
                    "service": "codex-pwa",
                    "max_attempts": 1,
                    "timeout_seconds": 105,
                },
                {
                    "ordinal": 4,
                    "action": "recreate-prior-service",
                    "service": "control-api",
                    "max_attempts": 1,
                    "timeout_seconds": 105,
                },
                {
                    "ordinal": 5,
                    "action": "recreate-prior-service",
                    "service": "control-api-replica",
                    "max_attempts": 1,
                    "timeout_seconds": 105,
                },
            ],
        }
        reverse_raw = self.write_canonical(
            deployment / "reverse-plan.json", reverse_plan
        )
        rollback = {"services": {}}
        rollback_raw = self.write_canonical(
            deployment / "rollback-compose.json", rollback
        )
        record = {
            "format_version": 1,
            "status": "deployed",
            "source_database_revision": "head",
            "target_migration_head": "head",
            "deployed_database_revision": "head",
            "resolved_compose_sha256": hashlib.sha256(compose_raw).hexdigest(),
            "sub2api": {"auth_evidence": {"sha256": auth_digest, "probe": probe}},
            "recovery": {
                "bounded_reverse_plan": {
                    "path": str(deployment / "reverse-plan.json"),
                    "sha256": hashlib.sha256(reverse_raw).hexdigest(),
                    "size": len(reverse_raw),
                    "value": reverse_plan,
                },
                "rollback_compose": {
                    "path": str(deployment / "rollback-compose.json"),
                    "sha256": hashlib.sha256(rollback_raw).hexdigest(),
                    "size": len(rollback_raw),
                    "value": rollback,
                },
            },
        }
        self.write_canonical(deployment / "deployment.json", record, mode=0o400)
        arguments = types.SimpleNamespace(
            record_root=root,
            deployment_directory=deployment,
            trigger_stage=trigger,
            expected_owner_uid=os.geteuid(),
        )
        return arguments, deployment, record

    def test_admits_bound_same_schema_success_record(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            arguments, deployment, _ = self.fixture(Path(temporary))
            value = ADMISSION_MODULE.post_success_reverse_admission(arguments)
            self.assertEqual(value["status"], "admitted")
            self.assertTrue(value["application_only"])
            self.assertFalse(value["database_restore_allowed"])
            self.assertEqual(
                value["reverse_plan"]["path"], str(deployment / "reverse-plan.json")
            )

    def test_rejects_migration_bearing_success_record(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            arguments, deployment, record = self.fixture(Path(temporary))
            record["source_database_revision"] = "old"
            self.write_canonical(
                deployment / "deployment.json", record, mode=0o400
            )
            with self.assertRaisesRegex(ValueError, "application-only bounded reverse"):
                ADMISSION_MODULE.post_success_reverse_admission(arguments)


class WrapperFailClosedTests(unittest.TestCase):
    def test_offline_package_contract_has_no_pull_or_proxy_escape(self) -> None:
        script = DEPLOY.read_text(encoding="utf-8")
        self.assertIn("CONTROL_SERVER_PACKAGE_OFFLINE_CONTRACT=1", script.splitlines())
        self.assertIn(
            "CONTROL_SERVER_PACKAGE_POST_SUCCESS_REVERSE_CONTRACT=1",
            script.splitlines(),
        )
        mode_gate = script.index('case "$server_package_mode" in')
        docker_host_gate = script.index('case "${DOCKER_HOST:-}" in', mode_gate)
        proxy_gate = script.index('if [ "$server_package_mode" = offline ]; then', mode_gate)
        online_gate = script.index('if [ "$server_package_mode" = online ]; then', proxy_gate)
        first_pull = script.index('docker pull "$api_image"')
        self.assertLess(docker_host_gate, proxy_gate)
        self.assertIn("unix:///var/run/docker.sock", script[docker_host_gate:proxy_gate])
        self.assertIn('"${DOCKER_CONTEXT:-}"', script[docker_host_gate:proxy_gate])
        self.assertIn('"${DOCKER_TLS_VERIFY:-}"', script[docker_host_gate:proxy_gate])
        self.assertIn('"${DOCKER_CERT_PATH:-}"', script[docker_host_gate:proxy_gate])
        self.assertLess(proxy_gate, online_gate)
        self.assertLess(online_gate, first_pull)
        self.assertEqual(script[:online_gate].count("docker pull"), 0)
        self.assertIn('"${HTTPS_PROXY:-}"', script[proxy_gate:online_gate])
        self.assertIn("--pull never", script[first_pull:])

    def test_post_success_reverse_is_a_separate_lock_retaining_path(self) -> None:
        script = DEPLOY.read_text(encoding="utf-8")
        argument = "--lifecycle-bounded-reverse-after-success"
        self.assertIn(argument, script)
        dispatch = script.index('if [ "$lifecycle_post_success_reverse" = "1" ]; then')
        admission = script.index(
            'no_replace_json "$deployment_dir/post-success-reverse-admission.json"',
            dispatch,
        )
        reverse = script.index(
            'run_bounded_reverse "$lifecycle_reverse_trigger"', admission
        )
        normal = script.index("stage=validate-smoke-input", reverse)
        self.assertLess(dispatch, admission)
        self.assertLess(admission, reverse)
        self.assertLess(reverse, normal)
        self.assertIn("database_mutated=0", script[admission:reverse])
        self.assertIn("application_mutated=1", script[admission:reverse])
        self.assertIn("writer_exposure_started=1", script[admission:reverse])
        self.assertIn("post_success_reverse_admitted=1", script[admission:reverse])
        self.assertIn("release_deployment_lock=0", script[:admission])
        self.assertIn("release_deployment_lock=1", script[reverse:normal])
        self.assertIn("production deployment lock retained", script[reverse:normal])
        self.assertIn(
            'no_replace_json "$deployment_dir/reverse-execution.json"', script
        )

    def test_bounded_uninstall_is_exact_and_preserves_host_configuration(self) -> None:
        script = DEPLOY.read_text(encoding="utf-8")
        self.assertIn(
            "CONTROL_SERVER_PACKAGE_BOUNDED_UNINSTALL_CONTRACT=1",
            script.splitlines(),
        )
        self.assertIn("--lifecycle-bounded-uninstall", script)
        dispatch = script.index('if [ "$lifecycle_bounded_uninstall" = "1" ]; then')
        plan = script.index(
            'no_replace_json "$deployment_dir/uninstall-plan.json"', dispatch
        )
        first_mutation = script.index(
            'docker container stop --time 25 "$target_container_id"', plan
        )
        empty_network_proof = script.index(
            "stage=bounded-uninstall-prove-pwa-network-empty", first_mutation
        )
        network_removal = script.index(
            'docker network rm "$pwa_network_id"', empty_network_proof
        )
        execution = script.index(
            'no_replace_json "$deployment_dir/uninstall-execution.json"',
            network_removal,
        )
        success_lock_release = script.index(
            "release_deployment_lock=1", execution
        )
        post_success_reverse = script.index(
            'if [ "$lifecycle_post_success_reverse" = "1" ]; then', execution
        )
        normal_deployment = script.index("stage=validate-smoke-input", execution)
        self.assertLess(dispatch, plan)
        self.assertLess(plan, first_mutation)
        self.assertLess(first_mutation, empty_network_proof)
        self.assertLess(empty_network_proof, network_removal)
        self.assertLess(network_removal, execution)
        self.assertLess(execution, success_lock_release)
        self.assertLess(success_lock_release, post_success_reverse)
        self.assertLess(post_success_reverse, normal_deployment)

        uninstall_body = script[dispatch:post_success_reverse]
        self.assertIn(
            'targets containers "$service" container_id', uninstall_body
        )
        self.assertIn(
            'docker container stop --time 25 "$target_container_id"',
            uninstall_body,
        )
        self.assertIn('docker container rm "$target_container_id"', uninstall_body)
        self.assertIn('docker network rm "$pwa_network_id"', uninstall_body)
        self.assertIn(
            '"$deployment_dir/uninstall-pwa-network-empty-inspect.json"',
            uninstall_body,
        )
        self.assertIn("--empty-network-inspect", uninstall_body)
        self.assertNotIn("docker compose", uninstall_body)
        self.assertNotIn("nginx", uninstall_body.lower())
        self.assertNotIn("logrotate", uninstall_body.lower())
        self.assertNotIn("reload", uninstall_body.lower())

        no_replace_start = script.index("no_replace_json()")
        no_replace_end = script.index("run_compose_bounded()", no_replace_start)
        no_replace_body = script[no_replace_start:no_replace_end]
        self.assertIn("os.O_WRONLY | os.O_CREAT | os.O_EXCL", no_replace_body)
        self.assertIn("os.open(destination, flags, 0o400)", no_replace_body)
        self.assertEqual(
            uninstall_body.count(
                'no_replace_json "$deployment_dir/uninstall-plan.json"'
            ),
            1,
        )
        self.assertEqual(
            uninstall_body.count(
                'no_replace_json "$deployment_dir/uninstall-execution.json"'
            ),
            1,
        )

        cleanup_start = script.index("cleanup()")
        cleanup_end = script.index("compose_source()", cleanup_start)
        cleanup_body = script[cleanup_start:cleanup_end]
        self.assertIn(
            'elif [ "$bounded_uninstall_admitted" = "1" ]', cleanup_body
        )
        self.assertIn("release_deployment_lock=0", cleanup_body)
        self.assertIn(
            'write_status "failed:$failure_stage:lock-retained"', cleanup_body
        )

    def test_wrapper_pins_compose_and_checks_revision_before_starting_both_apis(
        self,
    ) -> None:
        script = DEPLOY.read_text(encoding="utf-8")
        self.assertEqual(script.count("compose_source config --format json"), 1)
        self.assertNotIn("\ncompose config ", script)
        self.assertGreaterEqual(script.count('-f "$compose_snapshot"'), 2)
        self.assertEqual(script.count('--versions-lock "$versions_lock"'), 2)
        self.assertNotIn("auth_evidence=${SUB2API_AUTH_EVIDENCE_FILE", script)
        self.assertIn("external SUB2API_AUTH_EVIDENCE_FILE is prohibited", script)
        self.assertIn('--network "container:$sub2api_id"', script)
        self.assertIn("/usr/local/bin/probe-sub2api-auth-contract.py", script)
        self.assertNotIn('python3 "$auth_probe"', script)
        migration = script.index(
            'run_compose_bounded 180 "$compose_snapshot" run --rm --no-deps --pull never control-migrate'
        )
        revision_gate = script.index("--require-current-head", migration)
        startup = script.index(
            "for service in control-api-replica control-api codex-pwa", revision_gate
        )
        migration_exposure_gate = script.index(
            "stage=reject-uncontrolled-migration-writer-exposure", revision_gate
        )
        application_mutation = script.index("application_mutated=1", revision_gate)
        self.assertLess(migration, revision_gate)
        self.assertLess(revision_gate, migration_exposure_gate)
        self.assertLess(migration_exposure_gate, application_mutation)
        self.assertLess(application_mutation, startup)
        self.assertIn(
            "a controlled traffic maintenance gate is required before any new API may be exposed",
            script[migration_exposure_gate:startup],
        )
        self.assertIn("--api-replica-inspect", script[startup:])
        restore_gate = script.index("stage=prove-isolated-restore")
        isolation_gate = script.index("stage=prove-live-datastore-isolation")
        freeze = script.index("stage=freeze-control-writers")
        final_backup = script.index("stage=create-final-premigration-backup")
        freeze_receipt = script.index("stage=admit-writer-freeze-window")
        final_admission = script.index("stage=record-final-pre-migration-admission")
        self.assertLess(restore_gate, isolation_gate)
        self.assertLess(isolation_gate, freeze)
        self.assertLess(freeze, final_backup)
        self.assertLess(final_backup, freeze_receipt)
        self.assertLess(freeze_receipt, final_admission)
        self.assertLess(final_admission, migration)
        self.assertIn('no_replace_json "$deployment_dir/deployment.json"', script)
        self.assertIn("run_bounded_reverse", script)
        self.assertIn("run_bounded_unfreeze", script)
        self.assertIn('if [ "$database_mutated" = "1" ]; then', script)
        self.assertIn(
            'if [ "$database_mutated" = "1" ] || [ "$application_mutated" = "1" ]; then',
            script,
        )
        self.assertIn(
            '[ "$writer_exposure_started" = "0" ]',
            script,
        )
        self.assertIn("a Control writer was exposed after the frozen backup", script)
        self.assertIn("no_writer_exposure_since_backup_proven", script)
        self.assertIn("post_success_admission", script)
        self.assertIn('docker container start "$prior_id"', script)
        self.assertIn(
            'if [ "$database_mutated" != "1" ] || [ "$database_restored" = "1" ]; then',
            script,
        )
        self.assertNotIn('mutation_started=1', script)
        unfreeze_start = script.index("run_bounded_unfreeze()")
        unfreeze_end = script.index("reverse_service_state()", unfreeze_start)
        unfreeze_body = script[unfreeze_start:unfreeze_end]
        self.assertIn('docker container start "$prior_id"', unfreeze_body)
        self.assertNotIn("restore_control_database", unfreeze_body)
        self.assertIn(
            'no_replace_json "$deployment_dir/writer-unfreeze-execution.json"',
            script,
        )
        self.assertIn(
            'no_replace_json "$deployment_dir/reverse-execution.json"', script
        )
        self.assertIn("os.O_WRONLY | os.O_CREAT | os.O_EXCL", script)
        self.assertIn("os.open(destination, flags, 0o400)", script)
        freeze_flag = script.index("freeze_started=1")
        writer_stop = script.index("stage=freeze-control-writers", freeze_flag)
        mutation_flag = script.index("database_mutated=1", final_admission)
        self.assertLess(freeze_flag, writer_stop)
        self.assertLess(final_admission, mutation_flag)
        self.assertLess(mutation_flag, migration)
        recovery_failure = script.index(
            'write_status "failed:$failure_stage:$recovery_kind-failed:lock-retained"'
        )
        lock_release = script.index('if [ "$release_deployment_lock" = "1" ]')
        self.assertIn("release_deployment_lock=0", script[:recovery_failure])
        self.assertLess(recovery_failure, lock_release)

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
                        "CONTROL_SERVER_PACKAGE_MODE": "online",
                        "DOCKER_HOST": "unix:///var/run/docker.sock",
                        "CONTROL_SERVER_PACKAGE_MANIFEST_PATH": str(root / "PACKAGE.json"),
                        "CONTROL_SERVER_PACKAGE_MANIFEST_SHA256": "1" * 64,
                        "CONTROL_SERVER_PACKAGE_VERIFICATION_RECEIPT": str(
                            root / "verification-receipt.json"
                        ),
                        "CONTROL_CONNECTOR_RELEASE_METADATA_JSON": (
                            CONNECTOR_METADATA_JSON
                        ),
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
