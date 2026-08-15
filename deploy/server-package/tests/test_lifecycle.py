from __future__ import annotations

import contextlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


MODULE_PATH = Path(__file__).resolve().parents[1] / "lifecycle.py"
SPEC = importlib.util.spec_from_file_location("server_package_lifecycle", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
lifecycle = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(lifecycle)


SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64
COMMIT = "d" * 40
REPOSITORY = "https://github.com/example/sub2api-codex-control"


class IsolatedEntrypointTests(unittest.TestCase):
    def test_cli_rejects_nonisolated_startup_before_shadow_import(self) -> None:
        with tempfile.TemporaryDirectory(prefix="lifecycle-shadow.") as temporary:
            root = Path(temporary)
            script = root / "lifecycle.py"
            marker = root / "argparse-imported"
            shutil.copy2(MODULE_PATH, script)
            (root / "argparse.py").write_text(
                f"from pathlib import Path\nPath({str(marker)!r}).write_text('owned')\n",
                encoding="ascii",
            )

            rejected = subprocess.run(
                [sys.executable, str(script), "--help"],
                cwd=root,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(rejected.returncode, 2)
            self.assertIn("isolated mode is required", rejected.stderr)
            self.assertIn("/usr/bin/python3 -I", rejected.stderr)
            self.assertFalse(marker.exists())

            admitted = subprocess.run(
                [sys.executable, "-I", str(script), "--help"],
                cwd=root,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(admitted.returncode, 0, admitted.stderr)
            self.assertFalse(marker.exists())


class LifecycleFixture(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.uid = os.geteuid()

    def tearDown(self) -> None:
        for path in sorted(
            self.root.rglob("*"), key=lambda item: len(item.parts), reverse=True
        ):
            if path.is_dir() and not path.is_symlink():
                path.chmod(0o700)
            elif path.exists() and not path.is_symlink():
                path.chmod(0o600)
        self.root.chmod(0o700)
        self.temporary.cleanup()

    def connector_metadata(self) -> dict[str, object]:
        assets = []
        for os_name, arch, package_format in (
            ("darwin", "amd64", "pkg"),
            ("darwin", "arm64", "pkg"),
            ("linux", "amd64", "deb"),
            ("linux", "amd64", "rpm"),
            ("linux", "arm64", "deb"),
            ("linux", "arm64", "rpm"),
        ):
            assets.append(
                {
                    "os": os_name,
                    "arch": arch,
                    "package_format": package_format,
                    "sha256": SHA_A,
                }
            )
        return {
            "format_version": 1,
            "release_mode": "release",
            "releasable": True,
            "source_repository": REPOSITORY,
            "source_commit": COMMIT,
            "version": "1.2.3",
            "tag": "connector-v1.2.3",
            "codex_version": "0.147.0",
            "schema_digest": SHA_B,
            "manifest": {},
            "config_path_hint": "~/.config/sub2api-codex-connector/connector.json",
            "pair_command": "sub2api-codex-connector-ctl pair",
            "start_command": "sub2api-codex-connector-ctl start",
            "assets": assets,
        }

    def verified_package(self) -> tuple[Path, Path]:
        package_root = self.root / "extracted-package"
        package_root.mkdir(mode=0o700)
        metadata_path = package_root / lifecycle.CONNECTOR_METADATA_FILENAME
        metadata_raw = lifecycle.canonical_json(self.connector_metadata())
        metadata_path.write_bytes(metadata_raw)
        metadata_path.chmod(0o444)
        connector_evidence: dict[str, dict[str, object]] = {}
        evidence_names = {
            "metadata": lifecycle.CONNECTOR_METADATA_FILENAME,
            "metadata_bundle": lifecycle.CONNECTOR_METADATA_BUNDLE_FILENAME,
            "aggregate": lifecycle.CONNECTOR_AGGREGATE_FILENAME,
            "aggregate_bundle": lifecycle.CONNECTOR_AGGREGATE_BUNDLE_FILENAME,
        }
        for role, filename in evidence_names.items():
            evidence_path = package_root / filename
            if role == "metadata":
                raw = metadata_raw
            else:
                raw = lifecycle.canonical_json({"fixture": role})
                evidence_path.write_bytes(raw)
                evidence_path.chmod(0o444)
            connector_evidence[role] = {
                "filename": filename,
                "sha256": lifecycle.sha256_file(evidence_path),
                "size": len(raw),
            }
        image_records = {}
        for component, digest_character in zip(
            lifecycle.COMPONENTS, ("1", "2", "3"), strict=True
        ):
            digest = f"sha256:{digest_character * 64}"
            repository = f"ghcr.io/example/control-{component}"
            image_records[component] = {
                "acquisition": "registry",
                "digest": digest,
                "reference": f"{repository}@{digest}",
                "repository": repository,
            }
        manifest = {
            "$schema": lifecycle.PACKAGE_SCHEMA_ID,
            "format_version": 1,
            "product": "sub2api-codex-control-server",
            "release": "1.2.3",
            "release_tag": "control-v1.2.3",
            "mode": "online",
            "platform": lifecycle.PLATFORM,
            "source": {
                "repository": REPOSITORY,
                "commit": COMMIT,
                "ref": "refs/tags/control-v1.2.3",
            },
            "builder": {
                "workflow_identity": (
                    f"{REPOSITORY}/.github/workflows/control-images.yml"
                    "@refs/tags/control-v1.2.3"
                ),
                "workflow_sha": COMMIT,
                "workflow_trigger": "push",
                "invocation_id": f"{REPOSITORY}/actions/runs/1/attempts/1",
                "cosign_version": "v2.6.1",
                "syft_version": "1.27.1",
            },
            "source_date_epoch": 1,
            "common_payload_sha256": SHA_C,
            "control_release": {},
            "source_bundle": {},
            "source_verification": {},
            "connector_release": {
                "source_repository": REPOSITORY,
                "source_commit": COMMIT,
                "version": "1.2.3",
                "tag": "connector-v1.2.3",
                "release_id": 1,
                "workflow_run_id": 2,
                "workflow_run_attempt": 1,
                **connector_evidence,
            },
            "image_trust": {},
            "images": image_records,
            "lifecycle": {
                "install": "bin/sub2api-control-install",
                "upgrade": "bin/sub2api-control-upgrade",
                "verify": "bin/sub2api-control-verify",
                "rollback": "bin/sub2api-control-rollback",
                "uninstall": "bin/sub2api-control-uninstall",
            },
            "required_source_paths": ["deploy/scripts/deploy-production.sh"],
            "files": sorted(
                [
                {
                    "mode": "0444",
                    "path": evidence["filename"],
                    "sha256": evidence["sha256"],
                    "size": evidence["size"],
                }
                for evidence in connector_evidence.values()
                ],
                key=lambda item: item["path"],
            ),
        }
        manifest_raw = lifecycle.canonical_json(manifest)
        manifest_path = package_root / lifecycle.PACKAGE_MANIFEST_FILENAME
        manifest_path.write_bytes(manifest_raw)
        manifest_path.chmod(0o444)
        package_root.chmod(0o555)
        receipt = {
            "$schema": lifecycle.VERIFICATION_RECEIPT_SCHEMA_ID,
            "format_version": 1,
            "status": "verified",
            "verified_at": 1,
            "release": manifest["release"],
            "release_tag": manifest["release_tag"],
            "mode": manifest["mode"],
            "platform": manifest["platform"],
            "source": manifest["source"],
            "package": {
                "filename": "sub2api-codex-control-server-1.2.3-linux-amd64-online.tar.gz",
                "sha256": SHA_A,
                "size": 123,
                "internal_manifest_sha256": lifecycle.sha256_file(manifest_path),
                "extracted_root": str(package_root),
            },
            "release_manifest": {
                "filename": "server-packages.manifest.json",
                "sha256": SHA_B,
                "size": 456,
            },
            "trust": {
                "cosign_version": "v2.6.1",
                "certificate_oidc_issuer": lifecycle.OIDC_ISSUER,
                "certificate_identity": manifest["builder"]["workflow_identity"],
                "certificate_github_workflow_sha": COMMIT,
                "certificate_github_workflow_trigger": "push",
                "certificate_github_workflow_repository": (
                    "example/sub2api-codex-control"
                ),
                "certificate_github_workflow_ref": "refs/tags/control-v1.2.3",
                "connector_certificate_oidc_issuer": lifecycle.OIDC_ISSUER,
                "connector_certificate_identity": (
                    f"{REPOSITORY}/.github/workflows/connector-release.yml"
                    "@refs/tags/connector-v1.2.3"
                ),
                "connector_certificate_github_workflow_sha": COMMIT,
                "connector_certificate_github_workflow_trigger": "push",
                "expected_connector_repository": REPOSITORY,
                "expected_connector_source_commit": COMMIT,
                "expected_connector_tag": "connector-v1.2.3",
                "expected_connector_release_id": 1,
                "expected_connector_workflow_run_id": 2,
                "expected_connector_workflow_run_attempt": 1,
                "expected_source_repository": REPOSITORY,
                "expected_source_commit": COMMIT,
                "expected_release_tag": "control-v1.2.3",
                "expected_api_repository": image_records["control-api"]["repository"],
                "expected_pwa_repository": image_records["pwa"]["repository"],
                "expected_postgres_tools_repository": image_records[
                    "postgres-tools"
                ]["repository"],
            },
        }
        receipt_path = self.root / "verification.json"
        receipt_path.write_bytes(lifecycle.canonical_json(receipt))
        receipt_path.chmod(0o400)
        return package_root, receipt_path

    def operator_environment(self) -> tuple[Path, dict[str, str]]:
        private = self.root / "private"
        private.mkdir(mode=0o700)
        values: dict[str, str] = {
            "CONTROL_DEPLOYMENT_RECORD_DIR": str(self.root / "deployment-records"),
            "CONTROL_PRODUCTION_BACKUP_ROOT": str(self.root / "backups"),
            "CONTROL_SMOKE_EXPECTED_USER_ID": "fixture-user",
            "SUB2API_FIXTURE_EXPECTED_USER_ID": "fixture-user",
            "SUB2API_HOST_DATA_PATH": str(self.root / "sub2api-data"),
        }
        for name in sorted(lifecycle.REQUIRED_OPERATOR_NAMES):
            if name in values:
                continue
            if name in lifecycle.ABSOLUTE_FILE_NAMES:
                referenced = private / name.lower()
                referenced.write_text("CONTROL_PUBLIC_ORIGIN=https://control.example\n")
                referenced.chmod(0o600)
                values[name] = str(referenced)
            else:
                self.fail(f"test fixture does not define required operator key {name}")
        operator_path = self.root / "operator.env"
        operator_path.write_text(
            "".join(f"{name}={value}\n" for name, value in sorted(values.items())),
            encoding="utf-8",
        )
        operator_path.chmod(0o600)
        return operator_path, values


class VerifiedPackageTests(LifecycleFixture):
    def test_receipt_binds_exact_package_tree(self) -> None:
        package_root, receipt_path = self.verified_package()
        manifest, receipt, connector_raw = lifecycle.validate_verified_package(
            package_root, receipt_path, expected_uid=self.uid
        )
        self.assertEqual(manifest["release"], "1.2.3")
        self.assertEqual(receipt["package"]["extracted_root"], str(package_root))
        self.assertEqual(
            lifecycle.strict_json(connector_raw, "metadata")["tag"],
            "connector-v1.2.3",
        )

    def test_rejects_changed_file_mode(self) -> None:
        package_root, receipt_path = self.verified_package()
        (package_root / lifecycle.CONNECTOR_METADATA_FILENAME).chmod(0o644)
        with self.assertRaisesRegex(lifecycle.LifecycleError, "metadata is invalid|mode"):
            lifecycle.validate_verified_package(
                package_root, receipt_path, expected_uid=self.uid
            )

    def test_rejects_receipt_for_different_extraction_root(self) -> None:
        package_root, receipt_path = self.verified_package()
        receipt_path.chmod(0o600)
        value = lifecycle.strict_json(receipt_path.read_bytes(), "receipt")
        value["package"]["extracted_root"] = str(self.root / "another-package")
        receipt_path.write_bytes(lifecycle.canonical_json(value))
        receipt_path.chmod(0o400)
        with self.assertRaisesRegex(lifecycle.LifecycleError, "different extracted"):
            lifecycle.validate_verified_package(
                package_root, receipt_path, expected_uid=self.uid
            )

    def test_rejects_noncanonical_receipt(self) -> None:
        package_root, receipt_path = self.verified_package()
        receipt_path.chmod(0o600)
        receipt_path.write_bytes(receipt_path.read_bytes().replace(b'"action"', b'"action"'))
        raw = receipt_path.read_bytes()
        receipt_path.write_bytes(b" \n" + raw)
        receipt_path.chmod(0o400)
        with self.assertRaisesRegex(lifecycle.LifecycleError, "canonical|valid JSON"):
            lifecycle.validate_verified_package(
                package_root, receipt_path, expected_uid=self.uid
            )

    def test_rejects_unknown_package_manifest_field(self) -> None:
        package_root, _ = self.verified_package()
        value = lifecycle.strict_json(
            (package_root / lifecycle.PACKAGE_MANIFEST_FILENAME).read_bytes(),
            "manifest",
        )
        value["future_unreviewed_field"] = True
        with self.assertRaisesRegex(lifecycle.LifecycleError, "keys mismatch"):
            lifecycle._validate_package_manifest(value)

    def test_rejects_receipt_with_unbound_control_certificate_policy(self) -> None:
        package_root, receipt_path = self.verified_package()
        receipt_path.chmod(0o600)
        value = lifecycle.strict_json(receipt_path.read_bytes(), "receipt")
        value["trust"]["certificate_github_workflow_ref"] = "refs/heads/main"
        receipt_path.write_bytes(lifecycle.canonical_json(value))
        receipt_path.chmod(0o400)
        with self.assertRaisesRegex(
            lifecycle.LifecycleError, "Control certificate policy"
        ):
            lifecycle.validate_verified_package(
                package_root, receipt_path, expected_uid=self.uid
            )


class OperatorEnvironmentTests(LifecycleFixture):
    def test_accepts_literal_private_file_references(self) -> None:
        operator_path, expected = self.operator_environment()
        observed, digest = lifecycle.parse_operator_env(
            operator_path, expected_uid=self.uid
        )
        self.assertEqual(observed, expected)
        self.assertRegex(digest, r"^[0-9a-f]{64}$")

    def test_rejects_connector_metadata_override(self) -> None:
        operator_path, _ = self.operator_environment()
        operator_path.write_text(
            operator_path.read_text()
            + 'CONTROL_CONNECTOR_RELEASE_METADATA_JSON={"releasable":false}\n'
        )
        operator_path.chmod(0o600)
        with self.assertRaisesRegex(lifecycle.LifecycleError, "override"):
            lifecycle.parse_operator_env(operator_path, expected_uid=self.uid)

    def test_rejects_raw_secret(self) -> None:
        operator_path, _ = self.operator_environment()
        operator_path.write_text(
            operator_path.read_text() + "SUB2API_ACCESS_TOKEN=secret-value\n"
        )
        operator_path.chmod(0o600)
        with self.assertRaisesRegex(lifecycle.LifecycleError, "raw secret"):
            lifecycle.parse_operator_env(operator_path, expected_uid=self.uid)

    def test_rejects_connector_override_in_compose_environment(self) -> None:
        operator_path, values = self.operator_environment()
        compose_env = Path(values["CONTROL_COMPOSE_ENV_FILE"])
        compose_env.write_text("export\tCONTROL_CONNECTOR_RELEASE_METADATA_JSON={}\n")
        compose_env.chmod(0o600)
        with self.assertRaisesRegex(lifecycle.LifecycleError, "must not override"):
            lifecycle.parse_operator_env(operator_path, expected_uid=self.uid)

    def test_rejects_unlisted_raw_secret_in_compose_environment(self) -> None:
        operator_path, values = self.operator_environment()
        compose_env = Path(values["CONTROL_COMPOSE_ENV_FILE"])
        compose_env.write_text("VENDOR_API_TOKEN=not-allowed\n")
        compose_env.chmod(0o600)
        with self.assertRaisesRegex(lifecycle.LifecycleError, "raw secret"):
            lifecycle.parse_operator_env(operator_path, expected_uid=self.uid)

    def test_requires_exact_0600_operator_mode(self) -> None:
        operator_path, _ = self.operator_environment()
        operator_path.chmod(0o640)
        with self.assertRaisesRegex(lifecycle.LifecycleError, "mode"):
            lifecycle.parse_operator_env(operator_path, expected_uid=self.uid)


class PreflightTests(unittest.TestCase):
    def test_requires_root(self) -> None:
        with mock.patch.object(lifecycle.os, "geteuid", return_value=1000):
            with self.assertRaisesRegex(lifecycle.LifecycleError, "root"):
                lifecycle.preflight_platform()

    def test_requires_linux_amd64(self) -> None:
        with (
            mock.patch.object(lifecycle.os, "geteuid", return_value=0),
            mock.patch.object(lifecycle.platform, "system", return_value="Darwin"),
            mock.patch.object(lifecycle.platform, "machine", return_value="arm64"),
        ):
            with self.assertRaisesRegex(lifecycle.LifecycleError, "Linux amd64"):
                lifecycle.preflight_platform()


class DockerImageValidationTests(unittest.TestCase):
    def test_inspect_requires_exact_repo_digest_and_linux_amd64(self) -> None:
        reference = f"ghcr.io/example/control-api@sha256:{'1' * 64}"
        result = lifecycle.subprocess.CompletedProcess(
            ["docker"],
            0,
            json.dumps(
                [
                    {
                        "RepoDigests": [reference],
                        "Os": "linux",
                        "Architecture": "arm64",
                    }
                ]
            ).encode("utf-8"),
            b"",
        )
        with mock.patch.object(lifecycle, "_run_bounded", return_value=result):
            with self.assertRaisesRegex(lifecycle.LifecycleError, "Linux amd64"):
                lifecycle._inspect_image("/usr/bin/docker", reference, env={})

    def test_host_cosign_version_must_match_exactly(self) -> None:
        result = lifecycle.subprocess.CompletedProcess(
            ["cosign"], 0, b"GitVersion: v3.0.5\n", b""
        )
        with mock.patch.object(lifecycle, "_run_bounded", return_value=result):
            with self.assertRaisesRegex(lifecycle.LifecycleError, "version mismatch"):
                lifecycle._verify_cosign_version(
                    "/usr/bin/cosign", "v3.0.6", env={}
                )


class StrictJsonTests(unittest.TestCase):
    def test_nonfinite_numbers_are_rejected(self) -> None:
        with self.assertRaisesRegex(lifecycle.LifecycleError, "non-finite"):
            lifecycle.strict_json(b'{"value":NaN}\n', "fixture", canonical=False)


class StateRecordTests(LifecycleFixture):
    def test_exclusive_json_is_canonical_and_never_overwrites(self) -> None:
        destination = self.root / "record.json"
        lifecycle.write_exclusive_json(destination, {"b": 2, "a": 1})
        self.assertEqual(destination.read_bytes(), b'{"a":1,"b":2}\n')
        self.assertEqual(destination.stat().st_mode & 0o777, 0o400)
        with self.assertRaises(FileExistsError):
            lifecycle.write_exclusive_json(destination, {"a": 3})
        self.assertEqual(destination.read_bytes(), b'{"a":1,"b":2}\n')


class LifecycleTransactionTests(LifecycleFixture):
    def operation_record(self, install_path: Path) -> dict[str, object]:
        return {
            "release": "1.2.3",
            "release_tag": "control-v1.2.3",
            "mode": "online",
            "archive_sha256": SHA_A,
            "internal_manifest_sha256": SHA_B,
            "source_verification_receipt_sha256": SHA_C,
            "verification_receipt_sha256": "1" * 64,
            "verification_receipt_path": str(self.root / "installed-receipt.json"),
            "connector_metadata_sha256": "2" * 64,
            "cosign_version": "v2.6.1",
            "verification_trust": {"fixture": True},
            "verification_trust_sha256": "3" * 64,
            "install_path": str(install_path),
        }

    def deployment_binding(self, operation_id: str) -> dict[str, object]:
        deployment = self.root / "deployment-records/deployment-20260815T000000Z-1"
        return {
            "operation_id": operation_id,
            "action": "install",
            "deployment_directory": str(deployment),
            "deployment_record_path": str(deployment / "deployment.json"),
            "deployment_record_sha256": "4" * 64,
            "terminal_status_path": str(deployment / "status"),
            "terminal_status": "deployed",
            "terminal_status_sha256": lifecycle.hashlib.sha256(
                b"deployed\n"
            ).hexdigest(),
        }

    def test_started_receipt_precedes_install_tree_mutation(self) -> None:
        paths = lifecycle.LifecyclePaths(self.root / "install", self.root / "state")
        installed_root = paths.install_root / "candidate"
        record = self.operation_record(installed_root)
        lease = lifecycle.LifecycleLockLease()
        events: list[str] = []

        def write_operation(
            unused_paths: object,
            unused_operation_id: object,
            suffix: str,
            unused_value: object,
        ) -> None:
            events.append(f"write:{suffix}")

        def ensure_installed(*args: object, **kwargs: object) -> None:
            events.append("ensure-installed")
            raise lifecycle.LifecycleError("copy failed")

        with (
            mock.patch.object(
                lifecycle, "validate_verified_package", return_value=({}, {}, b"{}\n")
            ),
            mock.patch.object(
                lifecycle, "parse_operator_env", return_value=({}, SHA_A)
            ),
            mock.patch.object(lifecycle, "sha256_file", return_value=SHA_B),
            mock.patch.object(lifecycle, "_prepare_roots"),
            mock.patch.object(
                lifecycle,
                "_operation_id",
                return_value=(
                    "20260815T000000Z-1-1-install-"
                    "0123456789abcdef0123456789abcdef"
                ),
            ),
            mock.patch.object(
                lifecycle,
                "lifecycle_lock",
                return_value=contextlib.nullcontext(lease),
            ),
            mock.patch.object(lifecycle, "_read_activation", return_value=None),
            mock.patch.object(
                lifecycle,
                "_candidate_operation_record",
                return_value=("candidate", installed_root, record),
            ),
            mock.patch.object(
                lifecycle, "_write_operation", side_effect=write_operation
            ),
            mock.patch.object(
                lifecycle, "_ensure_installed", side_effect=ensure_installed
            ),
            mock.patch.object(
                lifecycle,
                "_settle_failed_mutation",
                return_value=(
                    None,
                    {"type": "LifecycleError", "message": "copy failed"},
                    False,
                ),
            ),
        ):
            with self.assertRaisesRegex(lifecycle.LifecycleError, "copy failed"):
                lifecycle._install_or_upgrade(
                    "install",
                    package_root=self.root / "candidate-source",
                    verification_receipt=self.root / "verification.json",
                    operator_env_file=self.root / "operator.env",
                    paths=paths,
                    timeout_seconds=60,
                )
        self.assertEqual(
            events, ["write:started", "ensure-installed", "write:failed"]
        )

    def test_failed_bounded_uninstall_preserves_activation_and_package_tree(
        self,
    ) -> None:
        paths = lifecycle.LifecyclePaths(self.root / "install", self.root / "state")
        paths.install_root.mkdir(parents=True)
        paths.state_root.mkdir(parents=True)
        active_root = paths.install_root / "active"
        active_root.mkdir()
        paths.activation.write_text("preserved\n", encoding="ascii")
        operation_id = (
            "20260815T000000Z-1-1-install-"
            "0123456789abcdef0123456789abcdef"
        )
        activation = {
            "generation": 1,
            "active_release_id": "active",
            "previous_release_id": None,
            "production_deployment": self.deployment_binding(operation_id),
        }
        record = self.operation_record(active_root)
        lease = lifecycle.LifecycleLockLease()
        remove = mock.Mock()
        with (
            mock.patch.object(
                lifecycle,
                "parse_operator_env",
                return_value=(
                    {"CONTROL_DEPLOYMENT_RECORD_DIR": str(self.root / "records")},
                    SHA_A,
                ),
            ),
            mock.patch.object(lifecycle, "_prepare_roots"),
            mock.patch.object(
                lifecycle,
                "_operation_id",
                return_value=(
                    "20260815T000000Z-2-1-uninstall-"
                    "fedcba9876543210fedcba9876543210"
                ),
            ),
            mock.patch.object(
                lifecycle,
                "lifecycle_lock",
                return_value=contextlib.nullcontext(lease),
            ),
            mock.patch.object(lifecycle, "_read_activation", return_value=activation),
            mock.patch.object(
                lifecycle,
                "_require_current_invoking_package",
                return_value=(record, active_root, {}, b"{}\n"),
            ),
            mock.patch.object(lifecycle, "_write_operation"),
            mock.patch.object(lifecycle, "_reject_unresolved_deployment_recovery"),
            mock.patch.object(
                lifecycle,
                "_authenticate_active_deployment",
                return_value=self.root / "records/deployment-fixture",
            ),
            mock.patch.object(lifecycle, "_read_release_record", return_value=record),
            mock.patch.object(
                lifecycle,
                "_manifest_from_installed_record",
                return_value=(active_root, {}, b"{}\n"),
            ),
            mock.patch.object(
                lifecycle,
                "_invoke_bounded_uninstall",
                side_effect=lifecycle.LifecycleError("interface absent"),
            ),
            mock.patch.object(lifecycle, "_remove_validated_package", remove),
        ):
            with self.assertRaisesRegex(lifecycle.LifecycleError, "lock retained"):
                lifecycle._uninstall(
                    operator_env_file=self.root / "operator.env",
                    invoking_package_root=active_root,
                    paths=paths,
                )
        self.assertTrue(lease.retained)
        self.assertTrue(paths.activation.exists())
        self.assertTrue(active_root.exists())
        remove.assert_not_called()

    def test_uninstall_receipt_binds_local_docker_host(self) -> None:
        receipt = lifecycle._operation_receipt(
            operation_id="operation",
            action="uninstall",
            phase="started",
            status="in-progress",
            started_at=1,
            completed_at=None,
            release_id=None,
            record=None,
            activation_before=None,
            activation_after=None,
            operator_env_path=Path("/secure/operator.env"),
            operator_env_sha256=SHA_A,
            acquired_images=[],
            error=None,
        )
        self.assertEqual(receipt["docker_host"], lifecycle.LOCAL_DOCKER_HOST)

    def test_post_success_failure_reverses_before_activation_restore(self) -> None:
        events: list[str] = []
        lease = lifecycle.LifecycleLockLease()
        activation = {"active_release_id": "prior"}

        def reverse(*args: object, **kwargs: object) -> None:
            events.append("reverse")

        def restore(*args: object, **kwargs: object) -> dict[str, str]:
            events.append("restore")
            return activation

        with (
            mock.patch.object(
                lifecycle, "_invoke_post_success_reverse", side_effect=reverse
            ),
            mock.patch.object(
                lifecycle, "_restore_prior_activation", side_effect=restore
            ),
        ):
            observed, error, safety_failure = lifecycle._settle_failed_mutation(
                exc=OSError("commit failed"),
                lease=lease,
                paths=lifecycle.LifecyclePaths(self.root / "install", self.root / "state"),
                package_root=Path("/opt/current"),
                manifest={},
                connector_raw=b"{}\n",
                operator={},
                record={},
                operation_id="operation",
                activation_before=activation,
                activation_after=None,
                deployment_state={"completed": True},
            )
        self.assertEqual(events, ["reverse", "restore"])
        self.assertEqual(observed, activation)
        self.assertEqual(error["type"], "OSError")
        self.assertFalse(safety_failure)
        self.assertFalse(lease.retained)

    def test_unavailable_post_success_reverse_retains_lock_without_pointer_rewrite(
        self,
    ) -> None:
        lease = lifecycle.LifecycleLockLease()
        with (
            mock.patch.object(
                lifecycle,
                "_invoke_post_success_reverse",
                side_effect=lifecycle.LifecycleError("interface absent"),
            ),
            mock.patch.object(lifecycle, "_restore_prior_activation") as restore,
        ):
            observed, error, safety_failure = lifecycle._settle_failed_mutation(
                exc=OSError("commit failed"),
                lease=lease,
                paths=lifecycle.LifecyclePaths(self.root / "install", self.root / "state"),
                package_root=Path("/opt/current"),
                manifest={},
                connector_raw=b"{}\n",
                operator={},
                record={},
                operation_id="operation",
                activation_before={"active_release_id": "prior"},
                activation_after=None,
                deployment_state={"completed": True},
            )
        self.assertIsNone(observed)
        self.assertEqual(error["type"], "PostDeploymentReverseError")
        self.assertTrue(safety_failure)
        self.assertTrue(lease.retained)
        restore.assert_not_called()

    def test_old_invoking_package_is_rejected(self) -> None:
        paths = lifecycle.LifecyclePaths(self.root / "install", self.root / "state")
        activation = {"active_release_id": "current"}
        with (
            mock.patch.object(lifecycle, "_read_release_record", return_value={}),
            mock.patch.object(
                lifecycle,
                "_manifest_from_installed_record",
                return_value=(Path("/opt/current"), {}, b"{}\n"),
            ),
        ):
            with self.assertRaisesRegex(
                lifecycle.LifecycleError, "current authenticated"
            ):
                lifecycle._require_current_invoking_package(
                    paths, activation, Path("/opt/old")
                )

    def test_uninstall_rejects_retained_production_lock(self) -> None:
        record_root = self.root / "deployment-records"
        record_root.mkdir()
        (record_root / ".deployment.lock").mkdir()
        with mock.patch.object(
            lifecycle, "_deployment_directory_snapshot", return_value={}
        ):
            with self.assertRaisesRegex(lifecycle.LifecycleError, "retained"):
                lifecycle._reject_unresolved_deployment_recovery(record_root)

    def test_uninstall_rejects_failed_bounded_reverse_evidence(self) -> None:
        record_root = self.root / "deployment-records"
        deployment = record_root / "deployment-fixture"
        deployment.mkdir(parents=True)
        reverse = deployment / "reverse-execution.json"
        reverse.touch()
        reverse_raw = lifecycle.canonical_json(
            {
                "format_version": 1,
                "type": "production-bounded-reverse-execution-v1",
                "status": "failed",
            }
        )
        with (
            mock.patch.object(
                lifecycle,
                "_deployment_directory_snapshot",
                return_value={deployment.name: (1, 2)},
            ),
            mock.patch.object(lifecycle, "secure_read", return_value=reverse_raw),
        ):
            with self.assertRaisesRegex(lifecycle.LifecycleError, "failed"):
                lifecycle._reject_unresolved_deployment_recovery(record_root)

    def test_uninstall_cli_requires_operator_environment(self) -> None:
        parsed = lifecycle.build_parser().parse_args(
            ["uninstall", "--operator-env-file", "/secure/operator.env"]
        )
        self.assertEqual(parsed.operator_env_file, "/secure/operator.env")


if __name__ == "__main__":
    unittest.main()
