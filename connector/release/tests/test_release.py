from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
RELEASE_TOOL = REPO_ROOT / "connector/release/release.py"
CONFIG = REPO_ROOT / "connector/release/release-config.json"

RELEASE_SPEC = importlib.util.spec_from_file_location(
    "connector_release_tool", RELEASE_TOOL
)
if RELEASE_SPEC is None or RELEASE_SPEC.loader is None:
    raise RuntimeError("cannot load Connector release tool")
release = importlib.util.module_from_spec(RELEASE_SPEC)
RELEASE_SPEC.loader.exec_module(release)


def find_go() -> str:
    configured = os.environ.get("GO")
    if configured:
        return configured
    discovered = shutil.which("go")
    if discovered:
        return discovered
    bundled = Path("/tmp/sub2api-go-1.26.5/bin/go")
    if bundled.is_file():
        return str(bundled)
    raise unittest.SkipTest("Go is not available")


class ReleaseContractTests(unittest.TestCase):
    VERSION = "0.1.0"
    SOURCE_COMMIT = "0123456789abcdef0123456789abcdef01234567"

    def asset(self, name: str, asset_id: int) -> dict[str, object]:
        tag = f"connector-v{self.VERSION}"
        return {
            "id": asset_id,
            "name": name,
            "size": 1,
            "digest": f"sha256:{'0' * 64}",
            "state": "uploaded",
            "browser_download_url": (
                f"{release.RELEASE_REPOSITORY}/releases/download/{tag}/{name}"
            ),
        }

    def platform_receipt(self) -> dict[str, object]:
        inventory = [
            {"filename": name, "sha256": "0" * 64, "size": 1}
            for name in sorted(release.expected_core_asset_names(self.VERSION))
        ]
        packages = []
        for target in ("linux-amd64", "linux-arm64"):
            for package_format in ("deb", "rpm"):
                packages.append(
                    {
                        "target_id": target,
                        "package_format": package_format,
                        "filename": (
                            f"sub2api-codex-connector_{self.VERSION}_"
                            f"{target.replace('-', '_')}.{package_format}"
                        ),
                        "sha256": "0" * 64,
                        "size": 1,
                    }
                )
        return {
            "$schema": "https://sub2api-codex.invalid/schemas/connector-platform-verification-receipt-v1.json",
            "format_version": 1,
            "kind": "sub2api-codex-connector-platform-verification",
            "platform": "linux",
            "release": {
                "source_repository": release.RELEASE_REPOSITORY,
                "source_commit": self.SOURCE_COMMIT,
                "version": self.VERSION,
                "tag": f"connector-v{self.VERSION}",
                "codex_version": "0.144.1",
                "schema_digest": "0" * 64,
                "control_protocol_version": 1,
            },
            "evidence": {
                "manifest": {
                    "filename": release.MANIFEST,
                    "sha256": "0" * 64,
                    "size": 1,
                    "signature_bundle": f"{release.MANIFEST}.sigstore.json",
                },
                "release_metadata": {
                    "filename": release.CONNECTOR_RELEASE_METADATA,
                    "sha256": "0" * 64,
                    "size": 1,
                    "signature_bundle": (
                        f"{release.CONNECTOR_RELEASE_METADATA}.sigstore.json"
                    ),
                },
                "checksums": {
                    "filename": release.CHECKSUMS,
                    "sha256": "0" * 64,
                    "size": 1,
                    "signature_bundle": f"{release.CHECKSUMS}.sigstore.json",
                },
            },
            "trust": {
                "sigstore": {
                    "certificate_oidc_issuer": release.OIDC_ISSUER,
                    "certificate_identity": (
                        f"{release.RELEASE_REPOSITORY}/.github/workflows/"
                        f"connector-release.yml@refs/tags/connector-v{self.VERSION}"
                    ),
                    "certificate_github_workflow_sha": self.SOURCE_COMMIT,
                    "certificate_github_workflow_trigger": "push",
                },
                "apple": None,
                "rpm": {"signing_fingerprint": "A" * 40},
            },
            "verification_run": {
                "repository": release.RELEASE_REPOSITORY.removeprefix(
                    "https://github.com/"
                ),
                "run_id": 123,
                "run_attempt": 1,
            },
            "verified_targets": ["linux-amd64", "linux-arm64"],
            "verified_packages": packages,
            "core_inventory": inventory,
        }

    def vulnerability_binding_fixture(
        self,
    ) -> tuple[
        dict[str, object],
        dict[str, object],
        list[dict[str, object]],
        list[dict[str, object]],
        list[dict[str, object]],
    ]:
        root = {
            "id": "connector",
            "kind": "connector-manifest-v1",
            "path": "connector/manifest.json",
            "sha256": "1" * 64,
            "size": 11,
            "signature_bundle_path": "connector/manifest.json.sigstore.json",
            "signature_bundle_sha256": "2" * 64,
            "signature_bundle_size": 12,
        }
        target_specs = sorted(release.released_package_pairs())
        packages: list[dict[str, object]] = []
        targets: list[dict[str, object]] = []
        scanner_hashes = {
            "binary": "3" * 64,
            "install": "4" * 64,
            "config": "5" * 64,
            "ignorefile": "6" * 64,
            "vulnerability_metadata": "7" * 64,
            "vulnerability_database": "8" * 64,
            "vulnerability_manifest": "9" * 64,
            "java_metadata": "a" * 64,
            "java_database": "b" * 64,
            "java_manifest": "c" * 64,
        }
        inventory: list[dict[str, object]] = [
            {
                "path": root["path"],
                "role": "release-root",
                "sha256": root["sha256"],
                "size": root["size"],
                "target": "connector",
            },
            {
                "path": root["signature_bundle_path"],
                "role": "release-root-signature",
                "sha256": root["signature_bundle_sha256"],
                "size": root["signature_bundle_size"],
                "target": "connector",
            },
            {"path": "trivy-install-receipt.json", "role": "scanner-install", "sha256": scanner_hashes["install"], "size": 41, "target": "scanner"},
            {"path": "trivy", "role": "scanner-binary", "sha256": scanner_hashes["binary"], "size": 42, "target": "scanner"},
            {"path": "trivy-empty.yaml", "role": "scanner-config", "sha256": scanner_hashes["config"], "size": 0, "target": "scanner"},
            {"path": "trivy-empty.ignore", "role": "scanner-ignorefile", "sha256": scanner_hashes["ignorefile"], "size": 0, "target": "scanner"},
        ]
        database_records: dict[str, dict[str, object]] = {}
        for database_name, target, prefix, repository, tag, schema_version in (
            ("vulnerability", "vulnerability-database", "trivy-db-oci", "ghcr.io/aquasecurity/trivy-db", "2", 2),
            ("java", "java-database", "trivy-java-db-oci", "ghcr.io/aquasecurity/trivy-java-db", "1", 1),
        ):
            metadata_sha = scanner_hashes[f"{database_name}_metadata"]
            database_sha = scanner_hashes[f"{database_name}_database"]
            manifest_sha = scanner_hashes[f"{database_name}_manifest"]
            metadata_path = "trivy-db-metadata.json" if database_name == "vulnerability" else "trivy-java-db-metadata.json"
            database_path = "trivy.db" if database_name == "vulnerability" else "trivy-java.db"
            oci_files = [
                {"path": f"{prefix}/oci-layout", "role": "layout", "sha256": "d" * 64, "size": 51},
                {"path": f"{prefix}/index.json", "role": "index", "sha256": "e" * 64, "size": 52},
                {"path": f"{prefix}/blobs/sha256/{manifest_sha}", "role": "manifest", "sha256": manifest_sha, "size": 53},
                {"path": f"{prefix}/blobs/sha256/{'d' * 64}", "role": "config", "sha256": "d" * 64, "size": 54},
                {"path": f"{prefix}/blobs/sha256/{'e' * 64}", "role": "layer", "sha256": "e" * 64, "size": 55},
            ]
            inventory.extend(
                [
                    {"path": metadata_path, "role": "database-metadata", "sha256": metadata_sha, "size": 43, "target": target},
                    {"path": database_path, "role": "database-file", "sha256": database_sha, "size": 44, "target": target},
                    *[
                        {"path": item["path"], "role": f"database-oci-{item['role']}", "sha256": item["sha256"], "size": item["size"], "target": target}
                        for item in oci_files
                    ],
                ]
            )
            database_records[database_name] = {
                "database": {"path": database_path, "sha256": database_sha, "size": 44},
                "metadata": {"path": metadata_path, "sha256": metadata_sha, "size": 43},
                "oci": {"digest": f"sha256:{manifest_sha}", "files": oci_files, "layout_path": prefix},
                "repository": repository,
                "schema_version": schema_version,
                "tag": tag,
            }
        core_inventory: list[dict[str, object]] = [
            {"filename": "manifest.json", "sha256": root["sha256"], "size": root["size"]},
            {
                "filename": "manifest.json.sigstore.json",
                "sha256": root["signature_bundle_sha256"],
                "size": root["signature_bundle_size"],
            },
        ]
        reports: dict[str, str] = {}
        for index, (target_id, package_format) in enumerate(target_specs, start=3):
            name = f"connector-{target_id}-{package_format}"
            os_name, arch = target_id.split("-", maxsplit=1)
            filename = (
                f"sub2api-codex-connector_{self.VERSION}_{os_name}_{arch}."
                f"{package_format}"
            )
            artifact_sha = f"{index:064x}"
            sbom_sha = f"{index + 10:064x}"
            report_sha = f"{index + 20:064x}"
            execution_sha = f"{index + 30:064x}"
            artifact_size = 100 + index
            sbom_size = 200 + index
            artifact_path = f"connector/{filename}"
            sbom_path = f"connector/{filename}.spdx.json"
            scan_subject = f"{name}.{sbom_sha}.spdx.json"
            packages.append(
                {
                    "target_id": target_id,
                    "package_format": package_format,
                    "filename": filename,
                    "sha256": artifact_sha,
                    "size": artifact_size,
                }
            )
            targets.append(
                {
                    "name": name,
                    "kind": "file",
                    "identity": f"sha256:{artifact_sha}",
                    "root_id": "connector",
                    "artifact": {
                        "filename": filename,
                        "sha256": artifact_sha,
                        "size": artifact_size,
                        "delivery": {
                            "kind": "single",
                            "parts": [
                                {
                                    "path": artifact_path,
                                    "sha256": artifact_sha,
                                    "size": artifact_size,
                                    "index": 1,
                                    "count": 1,
                                }
                            ],
                        },
                    },
                    "sbom": {
                        "path": sbom_path,
                        "sha256": sbom_sha,
                        "size": sbom_size,
                        "format": "SPDX-2.3-json",
                        "scan_subject_name": scan_subject,
                    },
                    "report_path": f"vulnerability-{name}.json",
                    "report_sha256": report_sha,
                    "scan_execution_path": f"scan-execution-{name}.json",
                    "scan_execution_sha256": execution_sha,
                }
            )
            inventory.extend(
                [
                    {
                        "path": artifact_path,
                        "role": "artifact",
                        "sha256": artifact_sha,
                        "size": artifact_size,
                        "target": name,
                    },
                    {
                        "path": sbom_path,
                        "role": "sbom",
                        "sha256": sbom_sha,
                        "size": sbom_size,
                        "target": name,
                    },
                    {
                        "path": f"vulnerability-{name}.json",
                        "role": "report",
                        "sha256": report_sha,
                        "size": 300 + index,
                        "target": name,
                    },
                    {
                        "path": f"scan-execution-{name}.json",
                        "role": "scan-execution",
                        "sha256": execution_sha,
                        "size": 400 + index,
                        "target": name,
                    },
                ]
            )
            core_inventory.extend(
                [
                    {
                        "filename": filename,
                        "sha256": artifact_sha,
                        "size": artifact_size,
                    },
                    {
                        "filename": f"{filename}.spdx.json",
                        "sha256": sbom_sha,
                        "size": sbom_size,
                    },
                ]
            )
            reports[name] = report_sha
        receipt = {
            "source_commit": self.SOURCE_COMMIT,
            "core_roots": [root],
            "scanner": {
                "name": "trivy",
                "version": "0.74.0",
                "binary_sha256": scanner_hashes["binary"],
                "scanner_install_receipt_sha256": scanner_hashes["install"],
                "config_sha256": scanner_hashes["config"],
                "ignorefile_sha256": scanner_hashes["ignorefile"],
                "vulnerability_database_oci_digest": f"sha256:{scanner_hashes['vulnerability_manifest']}",
                "vulnerability_database_metadata_sha256": scanner_hashes["vulnerability_metadata"],
                "vulnerability_database_sha256": scanner_hashes["vulnerability_database"],
                "vulnerability_database_updated_at": "2026-08-15T00:00:00Z",
                "java_database_oci_digest": f"sha256:{scanner_hashes['java_manifest']}",
                "java_database_metadata_sha256": scanner_hashes["java_metadata"],
                "java_database_sha256": scanner_hashes["java_database"],
                "java_database_updated_at": "2026-08-15T00:00:00Z",
            },
            "report_sha256": reports,
        }
        manifest = {
            "format_version": 1,
            "profile": "connector-release",
            "source_commit": self.SOURCE_COMMIT,
            "source_repository": release.RELEASE_REPOSITORY,
            "core_roots": [root],
            "generated_at": "2026-08-15T00:00:00Z",
            "scanner": {
                "name": "trivy",
                "version": "0.74.0",
                "binary_sha256": scanner_hashes["binary"],
                "binary_size": 42,
                "install_receipt_path": "trivy-install-receipt.json",
                "install_receipt_sha256": scanner_hashes["install"],
                "configuration": {
                    "config": {"path": "trivy-empty.yaml", "sha256": scanner_hashes["config"], "size": 0},
                    "ignorefile": {"path": "trivy-empty.ignore", "sha256": scanner_hashes["ignorefile"], "size": 0},
                },
                "databases": database_records,
            },
            "targets": sorted(targets, key=lambda target: str(target["name"])),
        }
        return manifest, receipt, inventory, core_inventory, packages

    def test_read_json_rejects_duplicate_keys_and_nonfinite_numbers(self) -> None:
        with tempfile.TemporaryDirectory(prefix="connector-json-contract.") as directory:
            duplicate = Path(directory) / "duplicate.json"
            duplicate.write_text('{"key":1,"key":2}\n', encoding="ascii")
            with self.assertRaisesRegex(release.ReleaseError, "duplicate JSON key"):
                release.read_json(duplicate)
            nonfinite = Path(directory) / "nonfinite.json"
            nonfinite.write_text('{"value":NaN}\n', encoding="ascii")
            with self.assertRaisesRegex(release.ReleaseError, "non-finite JSON number"):
                release.read_json(nonfinite)

    def test_release_output_rejects_final_component_symlink(self) -> None:
        with tempfile.TemporaryDirectory(prefix="connector-output-contract.") as directory:
            root = Path(directory)
            real = root / "real"
            real.mkdir()
            link = root / "release"
            link.symlink_to(real, target_is_directory=True)
            with self.assertRaisesRegex(release.ReleaseError, "non-symlink directory"):
                release.release_output_directory(link)

    def test_platform_receipt_requires_the_exact_core_inventory(self) -> None:
        receipt = self.platform_receipt()
        self.assertEqual(
            release.validate_platform_receipt(receipt, "linux"), receipt
        )
        receipt["core_inventory"] = receipt["core_inventory"][:-1]
        with self.assertRaisesRegex(release.ReleaseError, "fixed .*-file matrix"):
            release.validate_platform_receipt(receipt, "linux")

    def test_public_descriptor_requires_the_exact_asset_union(self) -> None:
        core_names = sorted(release.expected_core_asset_names(self.VERSION))
        vulnerability_names = sorted(
            {
                *release.VULNERABILITY_PUBLIC_FIXED_ASSETS,
                *{
                    f"vulnerability-evidence-{index:016x}-fixture-{index}.json"
                    for index in range(release.public_evidence_file_count())
                },
            }
        )
        names = sorted([*core_names, *vulnerability_names])
        by_name = {
            name: self.asset(name, index)
            for index, name in enumerate(names, start=1)
        }
        descriptor = {
            "$schema": "https://sub2api-codex.invalid/schemas/connector-public-release-descriptor-v1.json",
            "format_version": 1,
            "kind": "github-public-immutable-release",
            "source_repository": release.RELEASE_REPOSITORY,
            "source_commit": self.SOURCE_COMMIT,
            "version": self.VERSION,
            "tag": f"connector-v{self.VERSION}",
            "release_id": 456,
            "workflow_run_id": 123,
            "workflow_run_attempt": 1,
            "published_at": "2026-08-15T00:00:00Z",
            "draft": False,
            "prerelease": False,
            "immutable": True,
            "core_assets": [by_name[name] for name in core_names],
            "vulnerability_assets": [by_name[name] for name in vulnerability_names],
            "assets": [by_name[name] for name in names],
        }
        self.assertEqual(release.validate_public_release_descriptor(descriptor), descriptor)
        descriptor["core_assets"] = descriptor["core_assets"][:-1]
        with self.assertRaisesRegex(release.ReleaseError, "core asset matrix"):
            release.validate_public_release_descriptor(descriptor)

    def test_vulnerability_manifest_binds_published_sboms_not_scan_aliases(self) -> None:
        manifest, receipt, inventory, core_inventory, packages = (
            self.vulnerability_binding_fixture()
        )
        release.validate_vulnerability_manifest_bindings(
            manifest, receipt, inventory, core_inventory, packages
        )
        first = manifest["targets"][0]
        first["sbom"]["path"] = first["sbom"]["scan_subject_name"]
        with self.assertRaisesRegex(release.ReleaseError, "not core-bound"):
            release.validate_vulnerability_manifest_bindings(
                manifest, receipt, inventory, core_inventory, packages
            )

    def test_vulnerability_paths_allow_subdirectories_but_reject_traversal(self) -> None:
        self.assertEqual(
            release.vulnerability_relative_path(
                "connector/manifest.json", "fixture path"
            ),
            "connector/manifest.json",
        )
        for value in ("../manifest.json", "connector//manifest.json", "/manifest.json"):
            with self.subTest(value=value), self.assertRaises(release.ReleaseError):
                release.vulnerability_relative_path(value, "fixture path")

    def test_native_package_sbom_models_mixed_license_components(self) -> None:
        config = json.loads(CONFIG.read_text())
        state = {
            "config": config,
            "go_version": config["go_version"],
            "source_date_epoch": 1700000000,
        }
        record = {
            "target": {
                "id": "linux-amd64",
                "goos": "linux",
                "goarch": "amd64",
            }
        }
        package = {"format": "deb"}
        modules = [
            {"kind": "mod", "path": "example.invalid/connector", "version": "(devel)"},
            {"kind": "dep", "path": "example.invalid/dependency", "version": "v1.2.3"},
        ]
        with tempfile.TemporaryDirectory(prefix="connector-package-sbom.") as directory:
            package_path = Path(directory) / "connector.deb"
            package_path.write_bytes(b"native package fixture\n")
            sbom = release.make_package_sbom(
                state, record, package, package_path, modules
            )

        archive = sbom["packages"][0]
        self.assertEqual(archive["licenseInfoFromFiles"], ["NOASSERTION"])
        self.assertEqual(archive["licenseDeclared"], "NOASSERTION")
        self.assertEqual(archive["licenseConcluded"], "NOASSERTION")
        connector = next(
            item
            for item in sbom["packages"]
            if item["SPDXID"] == "SPDXRef-Package-Connector"
        )
        self.assertEqual(connector["licenseDeclared"], "Apache-2.0")
        stdlib = next(
            item
            for item in sbom["packages"]
            if item["SPDXID"] == release.GO_STDLIB_SPDX_ID
        )
        self.assertEqual(stdlib["versionInfo"], "1.26.5")
        self.assertEqual(stdlib["licenseDeclared"], "BSD-3-Clause")
        relationships = sbom["relationships"]
        self.assertIn(
            {
                "spdxElementId": "SPDXRef-Package-ConnectorInstaller",
                "relationshipType": "CONTAINS",
                "relatedSpdxElement": release.GO_STDLIB_SPDX_ID,
            },
            relationships,
        )
        self.assertIn(
            {
                "spdxElementId": "SPDXRef-Package-Connector",
                "relationshipType": "DEPENDS_ON",
                "relatedSpdxElement": release.GO_STDLIB_SPDX_ID,
            },
            relationships,
        )


class ReleasePipelineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.go = find_go()
        cls.temporary = Path(tempfile.mkdtemp(prefix="connector-release-tests."))
        cls.first = cls.temporary / "first"
        cls.second = cls.temporary / "second"
        for output in (cls.first, cls.second):
            cls.run_tool(
                "prepare",
                "--mode",
                "local-unsigned",
                "--output",
                str(output),
                "--go",
                cls.go,
                "--source-date-epoch",
                "1700000000",
                "--target",
                "linux-amd64",
                "--skip-tests",
            )
            cls.run_tool("finalize", "--output", str(output), "--go", cls.go)

    @classmethod
    def tearDownClass(cls) -> None:
        shutil.rmtree(cls.temporary)

    @classmethod
    def run_tool(
        cls, *arguments: str, check: bool = True
    ) -> subprocess.CompletedProcess[str]:
        env = os.environ.copy()
        if Path("/tmp/sub2api-gomodcache").is_dir():
            env.setdefault("GOMODCACHE", "/tmp/sub2api-gomodcache")
        return subprocess.run(
            [sys.executable, str(RELEASE_TOOL), *arguments],
            cwd=REPO_ROOT,
            env=env,
            text=True,
            capture_output=True,
            check=check,
        )

    def fixture(self) -> Path:
        destination = self.temporary / self.id().rsplit(".", 1)[-1]
        shutil.copytree(self.first, destination)
        return destination

    def assert_rejected(self, output: Path, expected: str, *extra: str) -> None:
        result = self.run_tool("verify", "--output", str(output), *extra, check=False)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn(expected, result.stderr)

    def test_local_unsigned_evidence_verifies_only_with_explicit_flag(self) -> None:
        result = self.run_tool(
            "verify",
            "--output",
            str(self.first),
            "--allow-local-unsigned",
            "--target",
            "linux-amd64",
        )
        self.assertIn("verified local-unsigned", result.stdout)
        self.assert_rejected(self.first, "non-releasable")

    def test_two_clean_builds_are_byte_identical(self) -> None:
        first_files = {
            path.name: path.read_bytes()
            for path in self.first.iterdir()
            if path.is_file()
        }
        second_files = {
            path.name: path.read_bytes()
            for path in self.second.iterdir()
            if path.is_file()
        }
        self.assertEqual(first_files, second_files)

    def test_host_go_architecture_override_is_ignored(self) -> None:
        output = self.temporary / "host-goamd64-v3"
        previous = os.environ.get("GOAMD64")
        os.environ["GOAMD64"] = "v3"
        try:
            self.run_tool(
                "prepare",
                "--mode",
                "local-unsigned",
                "--output",
                str(output),
                "--go",
                self.go,
                "--source-date-epoch",
                "1700000000",
                "--target",
                "linux-amd64",
                "--skip-tests",
            )
        finally:
            if previous is None:
                os.environ.pop("GOAMD64", None)
            else:
                os.environ["GOAMD64"] = previous
        state = json.loads((output / ".release-work.json").read_text())
        fixture_manifest = json.loads((self.first / "manifest.json").read_text())
        self.assertEqual(
            state["targets"][0]["unsigned_sha256"],
            fixture_manifest["targets"][0]["artifact"]["reproducible_candidate_sha256"],
        )

    def test_artifact_tampering_fails(self) -> None:
        output = self.fixture()
        manifest = json.loads((output / "manifest.json").read_text())
        artifact = output / manifest["targets"][0]["artifact"]["filename"]
        with artifact.open("ab") as handle:
            handle.write(b"tamper")
        self.assert_rejected(output, "SHA256SUMS mismatch", "--allow-local-unsigned")

    def test_sbom_tampering_fails(self) -> None:
        output = self.fixture()
        manifest = json.loads((output / "manifest.json").read_text())
        sbom = output / manifest["targets"][0]["sbom"]["filename"]
        with sbom.open("ab") as handle:
            handle.write(b"\n")
        self.assert_rejected(output, "SHA256SUMS mismatch", "--allow-local-unsigned")

    def test_missing_sbom_fails(self) -> None:
        output = self.fixture()
        manifest = json.loads((output / "manifest.json").read_text())
        (output / manifest["targets"][0]["sbom"]["filename"]).unlink()
        self.assert_rejected(
            output, "missing or unlisted files", "--allow-local-unsigned"
        )

    def test_missing_signature_bundle_fails_before_manifest_is_trusted(self) -> None:
        output = self.fixture()
        (output / "RELEASE-NOT-FOR-DISTRIBUTION").unlink()
        fake_cosign = self.temporary / "fake-cosign"
        fake_cosign.write_text(
            "#!/bin/sh\nif [ \"$1\" = version ]; then echo 'GitVersion: v3.0.6'; exit 0; fi\nexit 0\n",
            encoding="ascii",
        )
        fake_cosign.chmod(0o755)
        self.assert_rejected(
            output,
            "missing signature bundle",
            "--cosign",
            str(fake_cosign),
            "--certificate-oidc-issuer",
            "https://token.actions.githubusercontent.com",
            "--certificate-identity",
            "https://github.com/example/control/.github/workflows/connector-release.yml@refs/tags/connector-v0.1.0",
            "--certificate-github-workflow-sha",
            "0123456789abcdef0123456789abcdef01234567",
            "--certificate-github-workflow-trigger",
            "push",
            "--apple-team-id",
            "ABCDE12345",
            "--apple-signing-identity",
            "Developer ID Application: Example (ABCDE12345)",
            "--apple-installer-identity",
            "Developer ID Installer: Example (ABCDE12345)",
            "--rpm-signing-fingerprint",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        )

    def test_unlisted_file_fails(self) -> None:
        output = self.fixture()
        (output / "unexpected.txt").write_text("not admitted\n", encoding="ascii")
        self.assert_rejected(output, "unlisted files", "--allow-local-unsigned")

    def test_unlisted_directory_fails(self) -> None:
        output = self.fixture()
        (output / "unexpected-directory").mkdir()
        self.assert_rejected(
            output, "not a regular non-symlink file", "--allow-local-unsigned"
        )

    def test_dangling_symlink_fails(self) -> None:
        output = self.fixture()
        (output / "unexpected-link").symlink_to("missing-target")
        self.assert_rejected(
            output, "not a regular non-symlink file", "--allow-local-unsigned"
        )

    def test_non_executable_artifact_mode_is_restored_after_verification(self) -> None:
        # Artifact transfers between release jobs strip file modes, so the
        # verifier restores the executable bit once the content has matched
        # the trusted digest; tampered content is still rejected by hash.
        output = self.fixture()
        manifest = json.loads((output / "manifest.json").read_text())
        artifact = output / manifest["targets"][0]["artifact"]["filename"]
        artifact.chmod(0o644)
        result = self.run_tool(
            "verify",
            "--output",
            str(output),
            "--allow-local-unsigned",
            "--target",
            "linux-amd64",
        )
        self.assertIn("verified local-unsigned", result.stdout)
        self.assertTrue(artifact.stat().st_mode & 0o100)

    def test_finalization_rejects_candidate_mutated_after_reproducibility_check(
        self,
    ) -> None:
        output = self.temporary / "mutated-before-finalize"
        self.run_tool(
            "prepare",
            "--mode",
            "local-unsigned",
            "--output",
            str(output),
            "--go",
            self.go,
            "--source-date-epoch",
            "1700000000",
            "--target",
            "linux-amd64",
            "--skip-tests",
        )
        state = json.loads((output / ".release-work.json").read_text())
        with (output / state["targets"][0]["filename"]).open("ab") as handle:
            handle.write(b"tamper")
        result = self.run_tool(
            "finalize", "--output", str(output), "--go", self.go, check=False
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("changed after reproducibility check", result.stderr)

    def test_local_unsigned_output_cannot_be_signed(self) -> None:
        output = self.fixture()
        result = self.run_tool(
            "sign",
            "--output",
            str(output),
            "--apple-team-id",
            "ABCDE12345",
            "--apple-signing-identity",
            "Developer ID Application: Example (ABCDE12345)",
            check=False,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("only finalized release-mode output can be signed", result.stderr)

    def test_manifest_sbom_and_provenance_subjects_match(self) -> None:
        manifest = json.loads((self.first / "manifest.json").read_text())
        target = manifest["targets"][0]
        artifact = target["artifact"]
        sbom = json.loads((self.first / target["sbom"]["filename"]).read_text())
        provenance = json.loads(
            (self.first / target["provenance"]["filename"]).read_text()
        )
        self.assertEqual(sbom["spdxVersion"], "SPDX-2.3")
        binary = next(
            item for item in sbom["files"] if item["fileName"] == artifact["filename"]
        )
        sha1 = hashlib.sha1(
            (self.first / artifact["filename"]).read_bytes()
        ).hexdigest()
        self.assertEqual(
            binary["checksums"],
            [
                {"algorithm": "SHA1", "checksumValue": sha1},
                {"algorithm": "SHA256", "checksumValue": artifact["sha256"]},
            ],
        )
        connector_package = next(
            item
            for item in sbom["packages"]
            if item["SPDXID"] == "SPDXRef-Package-Connector"
        )
        self.assertTrue(connector_package["filesAnalyzed"])
        self.assertEqual(
            connector_package["packageVerificationCode"][
                "packageVerificationCodeValue"
            ],
            hashlib.sha1(sha1.encode("ascii")).hexdigest(),
        )
        stdlib = next(
            item
            for item in sbom["packages"]
            if item["SPDXID"] == release.GO_STDLIB_SPDX_ID
        )
        stdlib_version = manifest["build"]["go_version"].removeprefix("go")
        self.assertEqual(
            stdlib,
            {
                "SPDXID": release.GO_STDLIB_SPDX_ID,
                "name": "Go standard library",
                "versionInfo": stdlib_version,
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": False,
                "licenseConcluded": "BSD-3-Clause",
                "licenseDeclared": "BSD-3-Clause",
                "copyrightText": "Copyright The Go Authors",
                "externalRefs": [
                    {
                        "referenceCategory": "PACKAGE-MANAGER",
                        "referenceType": "purl",
                        "referenceLocator": f"pkg:golang/stdlib@{stdlib_version}",
                    }
                ],
            },
        )
        self.assertIn(
            {
                "spdxElementId": "SPDXRef-Package-Connector",
                "relationshipType": "DEPENDS_ON",
                "relatedSpdxElement": release.GO_STDLIB_SPDX_ID,
            },
            sbom["relationships"],
        )
        self.assertEqual(
            provenance["subject"],
            [{"name": artifact["filename"], "digest": {"sha256": artifact["sha256"]}}],
        )
        self.assertEqual(provenance["predicateType"], "https://slsa.dev/provenance/v1")
        internal = provenance["predicate"]["buildDefinition"]["internalParameters"]
        self.assertEqual(
            set(internal),
            {
                "cgoEnabled",
                "goAmd64",
                "goArm64",
                "goEnv",
                "goExperiment",
                "goFips140",
                "goToolchain",
                "trimpath",
                "buildVcs",
                "goBuildId",
            },
        )
        external = provenance["predicate"]["buildDefinition"]["externalParameters"]
        self.assertEqual(
            external,
            {
                "sourceRepository": manifest["source"]["repository"],
                "sourceCommit": manifest["source"]["commit"],
                "connectorVersion": manifest["connector_version"],
                "controlProtocolVersion": manifest["control_protocol_version"],
                "codexVersion": manifest["codex_version"],
                "appserverSchemaSha256": manifest["appserver_schema_sha256"],
                "serverApiRelease": manifest["server_api_release"],
                "target": {
                    "id": target["id"],
                    "goos": target["os"],
                    "goarch": target["arch"],
                    "native_signature": target["native_signature"]["policy"],
                },
            },
        )
        self.assertNotIn("packages", external["target"])
        dependencies = provenance["predicate"]["buildDefinition"][
            "resolvedDependencies"
        ]
        for dependency in dependencies:
            if dependency["uri"].startswith("pkg:golang/") and "digest" in dependency:
                self.assertEqual(set(dependency["digest"]), {"dirHash1"})
        byproduct = provenance["predicate"]["runDetails"]["byproducts"]
        self.assertEqual(
            byproduct[0]["digest"],
            {"sha256": artifact["reproducible_candidate_sha256"]},
        )
        self.assertEqual(
            hashlib.sha256(
                (self.first / artifact["filename"]).read_bytes()
            ).hexdigest(),
            artifact["sha256"],
        )

    def test_release_config_pins_complete_target_matrix(self) -> None:
        config = json.loads(CONFIG.read_text())
        self.assertEqual(config["go_version"], "go1.26.5")
        self.assertEqual(
            config["go_build_environment"],
            {
                "CGO_ENABLED": "0",
                "GOAMD64": "v1",
                "GOARM64": "v8.0",
                "GOENV": "off",
                "GOEXPERIMENT": "",
                "GOFIPS140": "off",
                "GOTOOLCHAIN": "local",
            },
        )
        self.assertEqual(config["cosign_version"], "v3.0.6")
        self.assertEqual(
            [target["id"] for target in config["targets"]],
            ["linux-amd64", "linux-arm64"],
        )


if __name__ == "__main__":
    unittest.main()
