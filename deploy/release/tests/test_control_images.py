from __future__ import annotations

import argparse
import base64
import contextlib
import hashlib
import importlib.util
import io
import json
import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[3]
TOOL_PATH = REPO_ROOT / "deploy/release/control_images.py"
SPEC = importlib.util.spec_from_file_location("control_images", TOOL_PATH)
assert SPEC is not None and SPEC.loader is not None
control_images = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(control_images)

CONNECTOR_TOOL_PATH = REPO_ROOT / "connector/release/release.py"
CONNECTOR_SPEC = importlib.util.spec_from_file_location(
    "connector_release_tool", CONNECTOR_TOOL_PATH
)
assert CONNECTOR_SPEC is not None and CONNECTOR_SPEC.loader is not None
connector_release = importlib.util.module_from_spec(CONNECTOR_SPEC)
CONNECTOR_SPEC.loader.exec_module(connector_release)


SOURCE_REPOSITORY = "https://github.com/example/sub2api-codex-control"
SOURCE_COMMIT = "1" * 40
RELEASE = "0.1.0"
RELEASE_TAG = f"control-v{RELEASE}"
SOURCE_REF = f"refs/tags/{RELEASE_TAG}"
WORKFLOW_IDENTITY = (
    f"{SOURCE_REPOSITORY}/.github/workflows/control-images-release.yml@{SOURCE_REF}"
)
API_REPOSITORY = "ghcr.io/example/sub2api-codex-control-api"
PWA_REPOSITORY = "ghcr.io/example/sub2api-codex-control-pwa"
POSTGRES_TOOLS_REPOSITORY = "ghcr.io/example/sub2api-codex-postgres-tools"
API_DIGEST = f"sha256:{'a' * 64}"
PWA_DIGEST = f"sha256:{'b' * 64}"
POSTGRES_TOOLS_DIGEST = f"sha256:{'c' * 64}"
IMAGE_FIXTURES = {
    "control-api": (API_REPOSITORY, API_DIGEST),
    "pwa": (PWA_REPOSITORY, PWA_DIGEST),
    "postgres-tools": (POSTGRES_TOOLS_REPOSITORY, POSTGRES_TOOLS_DIGEST),
}


class ControlImageReleaseTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(
            prefix="control-image-release-tests."
        )
        self.release_dir = Path(self.temporary.name)
        self.common = {
            "release": RELEASE,
            "release_tag": RELEASE_TAG,
            "source_repository": SOURCE_REPOSITORY,
            "source_commit": SOURCE_COMMIT,
            "workflow_identity": WORKFLOW_IDENTITY,
            "workflow_sha": SOURCE_COMMIT,
            "workflow_trigger": "push",
            "invocation_id": f"{SOURCE_REPOSITORY}/actions/runs/123/attempts/1",
        }
        self._write_sbom("control-api")
        self._write_sbom("pwa")
        self._write_sbom("postgres-tools")
        self._write_provenance("control-api", API_REPOSITORY, API_DIGEST)
        self._write_provenance("pwa", PWA_REPOSITORY, PWA_DIGEST)
        self._write_provenance(
            "postgres-tools", POSTGRES_TOOLS_REPOSITORY, POSTGRES_TOOLS_DIGEST
        )
        self._write_source_bundle()
        control_images.command_create_lock(
            argparse.Namespace(
                **self.common,
                output_dir=str(self.release_dir),
                source_archive=str(
                    self.release_dir
                    / control_images.source_bundle_tool.ARCHIVE_FILENAME
                ),
                source_manifest=str(
                    self.release_dir
                    / control_images.source_bundle_tool.MANIFEST_FILENAME
                ),
                source_attestation=str(
                    self.release_dir
                    / control_images.source_bundle_tool.ATTESTATION_FILENAME
                ),
                control_api_repository=API_REPOSITORY,
                control_api_digest=API_DIGEST,
                control_api_sbom=str(self.release_dir / "control-api.spdx.json"),
                control_api_provenance=str(
                    self.release_dir / "control-api.provenance.json"
                ),
                pwa_repository=PWA_REPOSITORY,
                pwa_digest=PWA_DIGEST,
                pwa_sbom=str(self.release_dir / "pwa.spdx.json"),
                pwa_provenance=str(self.release_dir / "pwa.provenance.json"),
                postgres_tools_repository=POSTGRES_TOOLS_REPOSITORY,
                postgres_tools_digest=POSTGRES_TOOLS_DIGEST,
                postgres_tools_sbom=str(self.release_dir / "postgres-tools.spdx.json"),
                postgres_tools_provenance=str(
                    self.release_dir / "postgres-tools.provenance.json"
                ),
            )
        )
        (self.release_dir / control_images.BUNDLE_FILENAME).write_text(
            "{}\n", encoding="ascii"
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _write_sbom(self, component: str) -> None:
        value = {
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": component,
            "documentNamespace": f"https://example.invalid/{component}/sbom",
            "packages": [{"SPDXID": f"SPDXRef-{component}", "name": component}],
        }
        (self.release_dir / f"{component}.spdx.json").write_text(
            json.dumps(value, sort_keys=True), encoding="ascii"
        )

    def _write_provenance(self, component: str, repository: str, digest: str) -> None:
        control_images.command_create_provenance(
            argparse.Namespace(
                **self.common,
                component=component,
                repository=repository,
                digest=digest,
                output=str(self.release_dir / f"{component}.provenance.json"),
            )
        )

    def _write_source_bundle(self) -> None:
        tool = control_images.source_bundle_tool
        components = {
            "format_version": 1,
            "components": [
                {
                    "id": "fixture",
                    "license_files": [
                        {"path": "third_party/licenses/Fixture-LICENSE.txt"}
                    ],
                }
            ],
        }
        contents = {
            "README.md": b"public source fixture\n",
            "LICENSE": b"fixture license\n",
            "NOTICE": b"fixture notice\n",
            "THIRD_PARTY_NOTICES.md": b"fixture third-party notices\n",
            "scripts/check-licenses.py": b"#!/usr/bin/env python3\n",
            "scripts/check-public-tree.py": b"#!/usr/bin/env python3\n",
            "third_party/components.json": tool.canonical_json(components),
            "third_party/licenses/Fixture-LICENSE.txt": b"fixture dependency license\n",
        }
        # The release source closure grows with the release surface; seed every
        # path it requires so this fixture stays bound to that closure instead
        # of drifting behind it.
        for relative in sorted(tool.REQUIRED_SOURCE_PATHS):
            contents.setdefault(
                relative, b"{}\n" if relative.endswith(".json") else b"fixture\n"
            )
        records = [
            {
                "mode": "0555" if path.startswith("scripts/") else "0444",
                "path": path,
                "sha256": hashlib.sha256(content).hexdigest(),
                "size": len(content),
            }
            for path, content in sorted(contents.items())
        ]
        manifest = tool.manifest_bytes(records)
        manifest_path = self.release_dir / tool.MANIFEST_FILENAME
        manifest_path.write_bytes(manifest)
        archive_path = self.release_dir / tool.ARCHIVE_FILENAME
        epoch = 1_700_000_000
        with archive_path.open("wb") as raw:
            tool.write_archive_stream(raw, records, contents, epoch)
        attestation = {
            "$schema": tool.SCHEMA_ID,
            "format_version": tool.FORMAT_VERSION,
            "release": RELEASE,
            "source": {
                "commit": SOURCE_COMMIT,
                "repository": SOURCE_REPOSITORY,
            },
            "source_date_epoch": epoch,
            "file_count": len(records),
            "total_bytes": sum(record["size"] for record in records),
            "manifest": {
                "filename": tool.MANIFEST_FILENAME,
                "sha256": tool.sha256_file(manifest_path),
                "size": manifest_path.stat().st_size,
            },
            "archive": {
                "filename": tool.ARCHIVE_FILENAME,
                "sha256": tool.sha256_file(archive_path),
                "size": archive_path.stat().st_size,
            },
        }
        (self.release_dir / tool.ATTESTATION_FILENAME).write_bytes(
            tool.canonical_json(attestation)
        )

    def _verify_args(self, **overrides: str) -> argparse.Namespace:
        values = {
            "release_dir": str(self.release_dir),
            "cosign": "cosign",
            "certificate_oidc_issuer": "https://token.actions.githubusercontent.com",
            "certificate_identity": WORKFLOW_IDENTITY,
            "certificate_github_workflow_sha": SOURCE_COMMIT,
            "certificate_github_workflow_trigger": "push",
            "certificate_github_workflow_repository": "example/sub2api-codex-control",
            "certificate_github_workflow_ref": SOURCE_REF,
            "expected_source_repository": SOURCE_REPOSITORY,
            "expected_source_commit": SOURCE_COMMIT,
            "expected_release_tag": RELEASE_TAG,
            "expected_api_repository": API_REPOSITORY,
            "expected_pwa_repository": PWA_REPOSITORY,
            "expected_postgres_tools_repository": POSTGRES_TOOLS_REPOSITORY,
        }
        values.update(overrides)
        return argparse.Namespace(**values)

    def _fake_cosign(
        self, arguments: list[str], *, cwd: Path = REPO_ROOT
    ) -> subprocess.CompletedProcess[str]:
        del cwd
        command = list(arguments)
        if command[1] == "version":
            output = "GitVersion: v3.0.6\n"
        elif command[1] == "verify-blob":
            output = "Verified OK\n"
        elif command[1] == "verify":
            matching = [
                (component, digest)
                for component, (repository, digest) in IMAGE_FIXTURES.items()
                if command[-1] == f"{repository}@{digest}"
            ]
            self.assertEqual(len(matching), 1, command[-1])
            _, digest = matching[0]
            output = json.dumps(
                [{"critical": {"image": {"docker-manifest-digest": digest}}}]
            )
        elif command[1] == "verify-attestation":
            matching = [
                component
                for component, (repository, digest) in IMAGE_FIXTURES.items()
                if command[-1] == f"{repository}@{digest}"
            ]
            self.assertEqual(len(matching), 1, command[-1])
            component = matching[0]
            evidence_name = (
                "sbom"
                if command[command.index("--type") + 1] == "spdxjson"
                else "provenance"
            )
            lock = json.loads(
                (self.release_dir / control_images.LOCK_FILENAME).read_text()
            )
            image = lock["images"][component]
            predicate = json.loads(
                (self.release_dir / image[evidence_name]["filename"]).read_text()
            )
            statement = {
                "_type": "https://in-toto.io/Statement/v1",
                "subject": [
                    {
                        "name": image["repository"],
                        "digest": {"sha256": image["digest"].removeprefix("sha256:")},
                    }
                ],
                "predicateType": image[evidence_name]["predicate_type"],
                "predicate": predicate,
            }
            statement = self.mutate_statement(component, evidence_name, statement)
            payload = base64.b64encode(
                json.dumps(statement, sort_keys=True).encode("ascii")
            ).decode("ascii")
            output = json.dumps([{"payload": payload}])
        else:
            self.fail(f"unexpected Cosign command: {command}")
        return subprocess.CompletedProcess(command, 0, output, "")

    def mutate_statement(
        self, component: str, evidence_name: str, statement: dict[str, object]
    ) -> dict[str, object]:
        del component, evidence_name
        return statement

    def test_valid_release_verifies_and_emits_only_digest_pinned_compose_values(
        self,
    ) -> None:
        calls: list[list[str]] = []

        def fake(
            arguments: list[str], *, cwd: Path = REPO_ROOT
        ) -> subprocess.CompletedProcess[str]:
            calls.append(list(arguments))
            return self._fake_cosign(arguments, cwd=cwd)

        output = io.StringIO()
        with (
            mock.patch.object(control_images, "run_checked", side_effect=fake),
            contextlib.redirect_stdout(output),
        ):
            control_images.command_verify(self._verify_args())
        values = json.loads(output.getvalue())
        self.assertEqual(values["CONTROL_API_IMAGE"], f"{API_REPOSITORY}@{API_DIGEST}")
        self.assertEqual(values["CONTROL_PWA_IMAGE"], f"{PWA_REPOSITORY}@{PWA_DIGEST}")
        self.assertEqual(
            values["CONTROL_POSTGRES_TOOLS_IMAGE"],
            f"{POSTGRES_TOOLS_REPOSITORY}@{POSTGRES_TOOLS_DIGEST}",
        )
        self.assertEqual(values["CONTROL_RELEASE"], RELEASE)
        self.assertEqual(values["CONTROL_SOURCE_REPOSITORY"], SOURCE_REPOSITORY)
        self.assertEqual(
            values["CONTROL_MIGRATION_HEAD"], control_images.migration_head()
        )
        self.assertEqual(values["CONTROL_VCS_REF"], SOURCE_COMMIT)
        lock = json.loads(
            (self.release_dir / control_images.LOCK_FILENAME).read_text(
                encoding="utf-8"
            )
        )
        source_bundle = lock["source_bundle"]
        self.assertEqual(
            values["CONTROL_SOURCE_ARCHIVE_SHA256"],
            source_bundle["archive"]["sha256"],
        )
        self.assertEqual(
            values["CONTROL_SOURCE_ATTESTATION_SHA256"],
            source_bundle["attestation"]["sha256"],
        )
        self.assertEqual(
            values["CONTROL_SOURCE_MANIFEST_SHA256"],
            source_bundle["manifest"]["sha256"],
        )
        release_inputs = lock["release_inputs"]["files"]
        self.assertEqual(
            values["CONTROL_VERSIONS_LOCK_SHA256"],
            release_inputs["versions.lock.json"],
        )
        contract_path = "docs/contracts/sub2api-auth.v0.1.176.json"
        self.assertEqual(values["CONTROL_SUB2API_AUTH_CONTRACT_PATH"], contract_path)
        self.assertEqual(
            values["CONTROL_SUB2API_AUTH_CONTRACT_SHA256"],
            release_inputs[contract_path],
        )
        self.assertEqual(values["CONTROL_RELEASE_INPUT_SHA256S"], release_inputs)
        self.assertEqual(
            values["CONTROL_RELEASE_LOCK_SHA256"],
            control_images.sha256_file(self.release_dir / control_images.LOCK_FILENAME),
        )
        self.assertEqual(
            values["CONTROL_RELEASE_BUNDLE_SHA256"],
            control_images.sha256_file(
                self.release_dir / control_images.BUNDLE_FILENAME
            ),
        )
        self.assertEqual(
            set(values["CONTROL_RELEASE_EVIDENCE_SHA256S"]),
            {entry.name for entry in self.release_dir.iterdir()},
        )
        self.assertEqual(
            set(values),
            {
                "CONTROL_API_IMAGE",
                "CONTROL_MIGRATION_HEAD",
                "CONTROL_POSTGRES_TOOLS_IMAGE",
                "CONTROL_PWA_IMAGE",
                "CONTROL_RELEASE",
                "CONTROL_RELEASE_BUNDLE_SHA256",
                "CONTROL_RELEASE_EVIDENCE_SHA256S",
                "CONTROL_RELEASE_INPUT_SHA256S",
                "CONTROL_RELEASE_LOCK_SHA256",
                "CONTROL_SOURCE_ARCHIVE_SHA256",
                "CONTROL_SOURCE_ATTESTATION_SHA256",
                "CONTROL_SOURCE_MANIFEST_SHA256",
                "CONTROL_SOURCE_REPOSITORY",
                "CONTROL_SUB2API_AUTH_CONTRACT_PATH",
                "CONTROL_SUB2API_AUTH_CONTRACT_SHA256",
                "CONTROL_VCS_REF",
                "CONTROL_VERSIONS_LOCK_SHA256",
            },
        )
        expected_files = {
            control_images.LOCK_FILENAME,
            control_images.BUNDLE_FILENAME,
        }
        for component in control_images.COMPONENTS:
            expected_files.add(f"{component}.spdx.json")
            expected_files.add(f"{component}.provenance.json")
        expected_files.update(
            {
                control_images.source_bundle_tool.ARCHIVE_FILENAME,
                control_images.source_bundle_tool.MANIFEST_FILENAME,
                control_images.source_bundle_tool.ATTESTATION_FILENAME,
            }
        )
        self.assertEqual(
            {entry.name for entry in self.release_dir.iterdir()}, expected_files
        )

        verified_calls = [
            call for call in calls if len(call) > 1 and call[1].startswith("verify")
        ]
        self.assertEqual(len(verified_calls), 10)
        for call in verified_calls:
            self.assertIn("--certificate-identity", call)
            self.assertIn(WORKFLOW_IDENTITY, call)
            self.assertIn("--certificate-github-workflow-sha", call)
            self.assertIn(SOURCE_COMMIT, call)
            self.assertIn("--certificate-github-workflow-ref", call)
            self.assertIn(SOURCE_REF, call)
            self.assertFalse(any("regexp" in argument for argument in call))
        for component in control_images.COMPONENTS:
            component_calls = [
                call for call in verified_calls if f"component={component}" in call
            ]
            self.assertEqual(len(component_calls), 3, component)

    def test_wrong_external_identity_is_rejected_after_blob_verification(self) -> None:
        with (
            mock.patch.object(
                control_images, "run_checked", side_effect=self._fake_cosign
            ),
            self.assertRaisesRegex(control_images.ReleaseError, "workflow identity"),
        ):
            control_images.command_verify(
                self._verify_args(
                    certificate_identity=WORKFLOW_IDENTITY.replace(
                        "control-images", "other"
                    )
                )
            )

    def test_wrong_external_postgres_tools_repository_is_rejected(self) -> None:
        with (
            mock.patch.object(
                control_images, "run_checked", side_effect=self._fake_cosign
            ),
            self.assertRaisesRegex(
                control_images.ReleaseError, "postgres-tools repository"
            ),
        ):
            control_images.command_verify(
                self._verify_args(
                    expected_postgres_tools_repository=(
                        "ghcr.io/example/unapproved-postgres-tools"
                    )
                )
            )

    def test_missing_cosign_fails_closed_as_a_release_error(self) -> None:
        with self.assertRaisesRegex(control_images.ReleaseError, "cannot execute"):
            control_images.command_verify(
                self._verify_args(cosign="/definitely/missing/cosign")
            )

    def test_verification_rejects_group_writable_release_directory(self) -> None:
        self.release_dir.chmod(0o770)
        try:
            with self.assertRaisesRegex(
                control_images.ReleaseError, "writable by group or other"
            ):
                control_images.command_verify(self._verify_args())
        finally:
            self.release_dir.chmod(0o700)

    def test_verification_rejects_hard_linked_release_evidence(self) -> None:
        evidence = self.release_dir / "pwa.spdx.json"
        outside = self.release_dir.parent / "hard-linked-pwa.spdx.json"
        os.link(evidence, outside)
        self.addCleanup(outside.unlink)
        with self.assertRaisesRegex(
            control_images.ReleaseError, "exactly one hard link"
        ):
            control_images.command_verify(self._verify_args())

    def test_signing_validation_recomputes_checked_out_release_inputs(self) -> None:
        current = control_images.release_input_hashes(control_images.load_config())
        changed = dict(current)
        changed["versions.lock.json"] = "0" * 64
        with (
            mock.patch.object(
                control_images, "release_input_hashes", return_value=changed
            ),
            self.assertRaisesRegex(
                control_images.ReleaseError, "exact checked-out source"
            ),
        ):
            control_images.command_validate_release(
                argparse.Namespace(
                    release_dir=str(self.release_dir),
                    expect_bundle=True,
                )
            )

    def test_attestation_with_wrong_subject_is_rejected(self) -> None:
        def mutate(
            component: str, evidence_name: str, statement: dict[str, object]
        ) -> dict[str, object]:
            if component == "postgres-tools" and evidence_name == "provenance":
                subjects = statement["subject"]
                assert isinstance(subjects, list) and isinstance(subjects[0], dict)
                subjects[0]["digest"] = {"sha256": "0" * 64}
            return statement

        self.mutate_statement = mutate
        with (
            mock.patch.object(
                control_images, "run_checked", side_effect=self._fake_cosign
            ),
            self.assertRaisesRegex(
                control_images.ReleaseError, "attestation does not match"
            ),
        ):
            control_images.command_verify(self._verify_args())

    def test_tampered_sbom_for_each_component_is_rejected(self) -> None:
        for component in control_images.COMPONENTS:
            with self.subTest(component=component):
                path = self.release_dir / f"{component}.spdx.json"
                original = path.read_bytes()
                path.write_bytes(original + b"\n")
                with self.assertRaisesRegex(control_images.ReleaseError, "SHA-256"):
                    control_images.validate_release_directory(
                        self.release_dir, expect_bundle=True
                    )
                path.write_bytes(original)

    def test_tampered_source_asset_for_each_type_is_rejected(self) -> None:
        for filename in (
            control_images.source_bundle_tool.ARCHIVE_FILENAME,
            control_images.source_bundle_tool.MANIFEST_FILENAME,
            control_images.source_bundle_tool.ATTESTATION_FILENAME,
        ):
            with self.subTest(filename=filename):
                path = self.release_dir / filename
                original = path.read_bytes()
                path.write_bytes(original + b"x")
                with self.assertRaisesRegex(
                    control_images.ReleaseError, "source bundle"
                ):
                    control_images.validate_release_directory(
                        self.release_dir, expect_bundle=True
                    )
                path.write_bytes(original)

    def test_missing_bundle_is_rejected(self) -> None:
        (self.release_dir / control_images.BUNDLE_FILENAME).unlink()
        with self.assertRaisesRegex(
            control_images.ReleaseError, "missing release lock Sigstore bundle"
        ):
            control_images.validate_release_directory(
                self.release_dir, expect_bundle=True
            )

    def test_missing_postgres_tools_evidence_is_rejected(self) -> None:
        (self.release_dir / "postgres-tools.provenance.json").unlink()
        with self.assertRaisesRegex(
            control_images.ReleaseError, "missing postgres-tools provenance"
        ):
            control_images.validate_release_directory(
                self.release_dir, expect_bundle=True
            )

    def test_extra_file_is_rejected(self) -> None:
        (self.release_dir / "untrusted.txt").write_text("extra\n", encoding="ascii")
        with self.assertRaisesRegex(control_images.ReleaseError, "inventory mismatch"):
            control_images.validate_release_directory(
                self.release_dir, expect_bundle=True
            )

    def test_symlinked_evidence_is_rejected(self) -> None:
        evidence = self.release_dir / "pwa.spdx.json"
        contents = evidence.read_bytes()
        evidence.unlink()
        target = self.release_dir / ".outside-sbom"
        target.write_bytes(contents)
        evidence.symlink_to(target)
        with self.assertRaisesRegex(control_images.ReleaseError, "non-symlink"):
            control_images.validate_release_directory(
                self.release_dir, expect_bundle=True
            )

    def test_mutable_tag_and_malformed_digest_are_rejected(self) -> None:
        with self.assertRaisesRegex(control_images.ReleaseError, "without a tag"):
            control_images.validate_repository(
                f"{API_REPOSITORY}:latest", "API repository"
            )
        with self.assertRaisesRegex(control_images.ReleaseError, "immutable sha256"):
            control_images.validate_digest("sha256:abc", "API digest")

    def test_mixed_image_set_digest_is_rejected_by_atomic_provenance(self) -> None:
        lock_path = self.release_dir / control_images.LOCK_FILENAME
        lock = json.loads(lock_path.read_text())
        lock["images"]["postgres-tools"]["digest"] = f"sha256:{'d' * 64}"
        lock["images"]["postgres-tools"]["reference"] = (
            f"{POSTGRES_TOOLS_REPOSITORY}@sha256:{'d' * 64}"
        )
        lock_path.write_bytes(control_images.canonical_json(lock))
        with self.assertRaisesRegex(
            control_images.ReleaseError, "provenance predicate"
        ):
            control_images.validate_release_directory(
                self.release_dir, expect_bundle=True
            )

    def test_lock_binds_migration_contract_dependency_and_dockerfile_inputs(
        self,
    ) -> None:
        lock = json.loads((self.release_dir / control_images.LOCK_FILENAME).read_text())
        self.assertEqual(
            lock["release_inputs"]["migration_head"], control_images.migration_head()
        )
        expected = set(control_images.load_config()["release_input_files"])
        expected.update(
            control_images.load_config()["components"][component]["dockerfile"]
            for component in control_images.COMPONENTS
        )
        self.assertEqual(set(lock["release_inputs"]["files"]), expected)
        self.assertEqual(lock["source"]["commit"], SOURCE_COMMIT)
        self.assertEqual(lock["images"]["control-api"]["digest"], API_DIGEST)
        self.assertEqual(lock["images"]["pwa"]["digest"], PWA_DIGEST)
        self.assertEqual(
            lock["images"]["postgres-tools"]["digest"], POSTGRES_TOOLS_DIGEST
        )
        self.assertIn(
            "deploy/scripts/backup-control-db.sh", lock["release_inputs"]["files"]
        )
        self.assertIn(
            "apps/control-api/src/control_api/config.py",
            lock["release_inputs"]["files"],
        )

    def test_evidence_outside_release_directory_is_rejected(self) -> None:
        outside = self.release_dir.parent / "outside.spdx.json"
        outside.write_text(
            (self.release_dir / "control-api.spdx.json").read_text(), encoding="ascii"
        )
        self.addCleanup(outside.unlink)
        arguments = argparse.Namespace(
            **self.common,
            output_dir=str(self.release_dir),
            source_archive=str(
                self.release_dir / control_images.source_bundle_tool.ARCHIVE_FILENAME
            ),
            source_manifest=str(
                self.release_dir / control_images.source_bundle_tool.MANIFEST_FILENAME
            ),
            source_attestation=str(
                self.release_dir
                / control_images.source_bundle_tool.ATTESTATION_FILENAME
            ),
            control_api_repository=API_REPOSITORY,
            control_api_digest=API_DIGEST,
            control_api_sbom=str(outside),
            control_api_provenance=str(
                self.release_dir / "control-api.provenance.json"
            ),
            pwa_repository=PWA_REPOSITORY,
            pwa_digest=PWA_DIGEST,
            pwa_sbom=str(self.release_dir / "pwa.spdx.json"),
            pwa_provenance=str(self.release_dir / "pwa.provenance.json"),
            postgres_tools_repository=POSTGRES_TOOLS_REPOSITORY,
            postgres_tools_digest=POSTGRES_TOOLS_DIGEST,
            postgres_tools_sbom=str(self.release_dir / "postgres-tools.spdx.json"),
            postgres_tools_provenance=str(
                self.release_dir / "postgres-tools.provenance.json"
            ),
        )
        with self.assertRaisesRegex(control_images.ReleaseError, "direct children"):
            control_images.command_create_lock(arguments)


class WorkflowAndComposePolicyTests(unittest.TestCase):
    def test_documented_lock_schema_requires_exactly_all_release_components(
        self,
    ) -> None:
        schema = json.loads(
            (REPO_ROOT / "deploy/release/control-images-lock.schema.json").read_text()
        )
        images = schema["properties"]["images"]
        self.assertEqual(set(images["required"]), set(control_images.COMPONENTS))
        self.assertEqual(set(images["properties"]), set(control_images.COMPONENTS))

    def test_workflow_actions_are_commit_pinned_and_release_is_guarded(
        self,
    ) -> None:
        workflow = (
            REPO_ROOT / ".github/workflows/control-images-release.yml"
        ).read_text()
        self.assertNotIn('tags:\n      - "control-v*"', workflow)
        self.assertIn("workflow_dispatch:", workflow)
        self.assertIn("source-only-guard:", workflow)
        self.assertIn("needs: source-only-guard", workflow)
        self.assertIn("exit 1", workflow)
        self.assertIn("permissions: {}", workflow)
        for action in re.findall(r"uses:\s+([^\s#]+)", workflow):
            reference = action.rsplit("@", 1)[-1]
            self.assertRegex(reference, r"^[0-9a-f]{40}$", action)
        self.assertIn("cosign sign --yes", workflow)
        self.assertIn("--type spdxjson", workflow)
        self.assertIn("--type slsaprovenance1", workflow)
        self.assertIn("git/ref/tags/${GITHUB_REF_NAME}", workflow)
        self.assertIn("deploy/dockerfiles/postgres-tools.Dockerfile", workflow)
        self.assertIn("postgres-tools.spdx.json", workflow)
        self.assertIn("--component postgres-tools", workflow)
        self.assertIn("--expected-postgres-tools-repository", workflow)
        self.assertIn("for component in control-api pwa postgres-tools", workflow)

    def test_binary_release_workflows_are_unreachable_in_source_only_mode(self) -> None:
        for filename, forbidden_tag in (
            ("control-images-release.yml", "control-v*"),
            ("connector-release.yml", "connector-v*"),
        ):
            with self.subTest(filename=filename):
                workflow = (REPO_ROOT / ".github/workflows" / filename).read_text()
                self.assertNotIn(forbidden_tag, workflow.split("jobs:", 1)[0])
                self.assertIn("workflow_dispatch:", workflow.split("jobs:", 1)[0])
                self.assertRegex(
                    workflow,
                    r"source-only-guard:[\s\S]*?exit 1",
                )
                publish_jobs = re.findall(
                    r"^  ([A-Za-z0-9_-]+):\n(?:(?:    .*|\s*)\n)*?"
                    r"    needs: ([A-Za-z0-9_-]+)",
                    workflow,
                    flags=re.MULTILINE,
                )
                self.assertIn(
                    ("validate", "source-only-guard")
                    if filename.startswith("control")
                    else ("build", "source-only-guard"),
                    publish_jobs,
                )

    def test_ci_runs_on_main_and_pull_requests(self) -> None:
        workflow = (REPO_ROOT / ".github/workflows/ci.yml").read_text()
        trigger = workflow.split("permissions:", 1)[0]
        self.assertIn("push:", trigger)
        self.assertIn("branches:\n      - main", trigger)
        self.assertIn("pull_request:", trigger)
        self.assertIn("scripts/check-public-tree.py", workflow)
        self.assertIn("scripts/check-licenses.py", workflow)
        self.assertIn("deploy/release/tests", workflow)

    def test_source_bundle_is_verified_before_any_registry_login_or_push(self) -> None:
        workflow = (
            REPO_ROOT / ".github/workflows/control-images-release.yml"
        ).read_text()
        build = workflow.index("  build:")
        source = workflow.index(
            "Build and verify the deterministic source bundle before registry access",
            build,
        )
        login = workflow.index("Log in to the release registry", source)
        push = workflow.index("push: true", login)
        lock = workflow.index("control_images.py create-lock", push)
        self.assertLess(source, login)
        self.assertLess(login, push)
        self.assertLess(push, lock)
        self.assertIn("source_bundle.py build", workflow[source:login])
        self.assertIn("source_bundle.py verify", workflow[source:login])
        self.assertIn(
            'archive_sha256=$(digest "$RELEASE_DIR/source.tar")', workflow[source:login]
        )
        self.assertNotIn("source.tar.gz", workflow)
        self.assertIn('--source-archive "$RELEASE_DIR/source.tar"', workflow[lock:])
        self.assertIn(
            '--source-manifest "$RELEASE_DIR/source-files.manifest"', workflow[lock:]
        )
        self.assertIn(
            '--source-attestation "$RELEASE_DIR/source-attestation.json"',
            workflow[lock:],
        )

    def test_connector_release_checks_public_source_before_build_or_upload(
        self,
    ) -> None:
        workflow = (REPO_ROOT / ".github/workflows/connector-release.yml").read_text()
        build = workflow.index("  build:")
        public_check = workflow.index("scripts/check-public-tree.py", build)
        license_check = workflow.index("scripts/check-licenses.py", public_check)
        compile_step = workflow.index("release.py prepare", license_check)
        upload = workflow.index("actions/upload-artifact@", compile_step)
        self.assertLess(public_check, license_check)
        self.assertLess(license_check, compile_step)
        self.assertLess(compile_step, upload)

    def test_connector_release_stages_complete_native_package_authorities(
        self,
    ) -> None:
        workflow = (REPO_ROOT / ".github/workflows/connector-release.yml").read_text()
        linux_sign = workflow.index("  linux-native-sign:")
        sigstore = workflow.index("  attest:", linux_sign)
        linux_verify = workflow.index("  verify-linux-signed:", sigstore)
        publish = workflow.index("  publish:", linux_verify)
        public_linux = workflow.index("  verify-public-release-linux:", publish)
        self.assertLess(linux_sign, sigstore)
        self.assertLess(sigstore, linux_verify)
        self.assertLess(linux_verify, publish)
        self.assertLess(publish, public_linux)
        self.assertIn("environment: connector-release-linux", workflow)
        self.assertIn("connector/release/linux-sign-rpm.sh", workflow)
        self.assertIn("RPM_SIGNING_PRIVATE_KEY_BASE64", workflow)
        self.assertIn("RPM_EXPECTED_SIGNING_FINGERPRINT", workflow)
        self.assertIn("--rpm-signing-fingerprint", workflow)
        for target_id in connector_release.released_target_ids():
            self.assertGreaterEqual(workflow.count(f"--target {target_id}"), 2)
        self.assertGreaterEqual(workflow.count('refs/tags/${RELEASE_TAG}^{}'), 2)
        # This release publishes no Apple-signed artifact, so no Apple identity,
        # certificate, or notarization input may reach the workflow.
        for forbidden in (
            "MACOS_",
            "APPLE_",
            "--apple-",
            "macos-sign-notarize.sh",
            "connector-release-apple",
            "notarytool",
        ):
            self.assertNotIn(forbidden, workflow)

    def test_control_release_exports_offline_image_signature_closure(self) -> None:
        workflow = (
            REPO_ROOT / ".github/workflows/control-images-release.yml"
        ).read_text()
        signing = workflow.index(
            "Sign all digests and attach signed SBOM and SLSA v1 evidence"
        )
        save = workflow.index('cosign save "$image_ref"', signing)
        offline = workflow.index(
            "Verify all exported image trust bundles without registry access", save
        )
        upload = workflow.index(
            "Transfer the offline-verifiable image trust bundles", offline
        )
        self.assertLess(signing, save)
        self.assertLess(save, offline)
        self.assertLess(offline, upload)
        self.assertIn('cosign initialize', workflow[signing:offline])
        self.assertIn('trusted_root.json', workflow[signing:upload])
        self.assertIn('--offline', workflow[offline:upload])
        self.assertIn('--local-image "$IMAGE_TRUST_DIR/$component"', workflow[offline:upload])
        self.assertIn('name: control-image-trust-${{ github.run_attempt }}', workflow)

    def test_control_final_image_tags_wait_for_complete_public_replay(self) -> None:
        workflow = (
            REPO_ROOT / ".github/workflows/control-images-release.yml"
        ).read_text()
        attest = workflow.index("  attest:")
        package_build = workflow.index("  package-build:", attest)
        public = workflow.index("  verify-public-release:", package_build)
        promote = workflow.index("  promote-images:", public)
        self.assertLess(attest, package_build)
        self.assertLess(package_build, public)
        self.assertLess(public, promote)

        attest_section = workflow[attest:package_build]
        public_section = workflow[public:promote]
        promote_section = workflow[promote:]
        final_ref = '"${repository}:${GITHUB_REF_NAME}"'
        self.assertNotIn(final_ref, workflow[:promote])
        self.assertNotIn("docker buildx imagetools create", attest_section)
        self.assertNotIn("docker buildx imagetools", public_section)
        self.assertIn(
            "Re-run the image-root verifier against immutable digests",
            public_section,
        )
        self.assertIn('test "$authenticated_ref" = "$expected_ref"', public_section)
        self.assertIn(
            "needs:\n      - build\n      - verify-public-release",
            promote_section,
        )
        self.assertIn("environment: control-images-release-promote", promote_section)
        self.assertIn("contents: read\n      packages: write", promote_section)
        self.assertNotIn("id-token: write", promote_section)
        self.assertIn("ref: ${{ github.ref }}", promote_section)
        self.assertIn("fetch-tags: true", promote_section)
        self.assertIn("persist-credentials: false", promote_section)
        self.assertIn("docker/login-action@", promote_section)
        self.assertIn('git cat-file -e "${GITHUB_REF_NAME}^{tag}"', promote_section)
        self.assertGreaterEqual(
            promote_section.count('test "$peeled" = "$GITHUB_SHA"'), 2
        )
        self.assertIn(
            'docker buildx imagetools inspect "${repository}@${digest}"',
            promote_section,
        )
        self.assertIn("docker buildx imagetools create", promote_section)
        self.assertIn('--tag "${repository}:${GITHUB_REF_NAME}"', promote_section)
        self.assertIn('test "$promoted_digest" = "$digest"', promote_section)
        self.assertGreaterEqual(promote_section.count("assert_remote_tag"), 4)

    def test_control_server_packages_use_fixed_connector_and_separate_authorities(
        self,
    ) -> None:
        workflow = (
            REPO_ROOT / ".github/workflows/control-images-release.yml"
        ).read_text()
        attest = workflow.index("  attest:")
        package_build = workflow.index("  package-build:", attest)
        package_sign = workflow.index("  package-sign:", package_build)
        publish = workflow.index("  publish:", package_sign)
        self.assertLess(attest, package_build)
        self.assertLess(package_build, package_sign)
        self.assertLess(package_sign, publish)

        build_section = workflow[package_build:package_sign]
        sign_section = workflow[package_sign:publish]
        self.assertIn("environment: control-server-release-compatibility", build_section)
        self.assertIn("actions: read", build_section)
        self.assertIn("packages: read", build_section)
        self.assertNotIn("id-token: write", build_section)
        for variable in (
            "CONNECTOR_RELEASE_SOURCE_COMMIT",
            "CONNECTOR_RELEASE_TAG",
            "CONNECTOR_RELEASE_ID",
            "CONNECTOR_RELEASE_WORKFLOW_RUN_ID",
            "CONNECTOR_RELEASE_WORKFLOW_RUN_ATTEMPT",
        ):
            self.assertIn("${{ vars." + variable + " }}", build_section)
        self.assertIn("github-token: ${{ github.token }}", build_section)
        self.assertIn("run-id: ${{ vars.CONNECTOR_RELEASE_WORKFLOW_RUN_ID }}", build_section)
        aggregate_verify = build_section.index("release.py verify-aggregate")
        aggregate_parse = build_section.index(".public_release.descriptor.filename")
        self.assertLess(aggregate_verify, aggregate_parse)
        self.assertIn("create-public-release-descriptor", build_section)
        # Bound to the Connector release tool so the two releases cannot
        # disagree about the published asset union.
        self.assertIn(
            f".assets | length == {connector_release.public_release_asset_count()}",
            build_section,
        )
        self.assertIn("connector-release-metadata.json.sigstore.json", build_section)
        self.assertIn("oci_toolchain.py install", build_section)
        self.assertIn("oci_toolchain.py export-images", build_section)
        self.assertIn('temporary=$(mktemp "$RUNNER_TEMP/.oci-export-receipt.', build_section)
        self.assertIn('> "$temporary"', build_section)
        self.assertIn("os.fsync(descriptor)", build_section)
        self.assertIn("os.link(source, destination", build_section)
        self.assertIn('--oci-export-receipt "$RUNNER_TEMP/oci-export-receipt.json"', build_section)
        self.assertIn("server_package.py build", build_section)

        self.assertIn("environment: control-server-release-sigstore", sign_section)
        self.assertIn("id-token: write", sign_section)
        self.assertNotIn("packages: write", sign_section)
        self.assertIn("server_package.py sign", sign_section)
        self.assertIn("for mode in online offline", sign_section)
        self.assertIn('--extract-to "$extract_to"', sign_section)
        self.assertIn('--verification-receipt "$receipt"', sign_section)
        self.assertIn('bundle="${receipt}.sigstore.json"', sign_section)
        self.assertIn("control-server-package-receipts-signed-", sign_section)
        self.assertGreaterEqual(sign_section.count('refs/tags/${tag}^{}'), 1)

        scan = workflow.index("  vulnerability-scan:", package_sign)
        vulnerability_attest = workflow.index("  vulnerability-attest:", scan)
        scan_section = workflow[scan:vulnerability_attest]
        vulnerability_attest_section = workflow[vulnerability_attest:publish]
        for section in (scan_section, vulnerability_attest_section):
            self.assertIn("control-images.lock.json", section)
            self.assertIn("server-packages.manifest.json", section)
            self.assertIn("check-vulnerabilities.py", section)
        self.assertIn("core_roots: [", scan_section)
        self.assertIn('id: "control"', scan_section)
        self.assertIn('id: "server"', scan_section)
        self.assertNotIn("artifact_path", scan_section)
        self.assertNotIn("sbom_path", scan_section)
        control_root_verify = vulnerability_attest_section.index(
            'cosign verify-blob "$CONTROL_VULNERABILITY_DIR/control/control-images.lock.json"'
        )
        server_root_verify = vulnerability_attest_section.index(
            'cosign verify-blob "$CONTROL_VULNERABILITY_DIR/server/server-packages.manifest.json"'
        )
        receipt_replay = vulnerability_attest_section.index(
            "check-vulnerabilities.py verify-receipt"
        )
        self.assertLess(control_root_verify, receipt_replay)
        self.assertLess(server_root_verify, receipt_replay)

        publish_section = workflow[publish:]
        self.assertIn("- package-sign", publish_section)
        self.assertIn("- vulnerability-attest", publish_section)
        self.assertIn("server-package-verify.py.sigstore.json", publish_section)
        manifest_verify = publish_section.index(
            'cosign verify-blob "$manifest"'
        )
        verifier_parse = publish_section.index(".consumer_verifier")
        verifier_run = publish_section.index('python3 -I "$verifier" verify-release')
        self.assertLess(manifest_verify, verifier_parse)
        self.assertLess(verifier_parse, verifier_run)
        self.assertIn("published package verification receipt differs from public replay", publish_section)
        self.assertIn("--profile control-release", publish_section)

    def test_connector_release_closes_vulnerability_and_public_platform_receipts(
        self,
    ) -> None:
        workflow = (REPO_ROOT / ".github/workflows/connector-release.yml").read_text()
        attest = workflow.index("  attest:")
        scan = workflow.index("  vulnerability-scan:", attest)
        vulnerability_sign = workflow.index("  vulnerability-attest:", scan)
        publish = workflow.index("  publish:", vulnerability_sign)
        public_linux = workflow.index("  verify-public-release-linux:", publish)
        aggregate = workflow.index("  aggregate-public-verification:", public_linux)
        self.assertLess(attest, scan)
        self.assertLess(scan, vulnerability_sign)
        self.assertLess(vulnerability_sign, publish)
        self.assertLess(publish, public_linux)
        self.assertLess(public_linux, aggregate)

        vulnerability_section = workflow[scan:publish]
        self.assertIn("scripts/install-trivy.sh", vulnerability_section)
        # The scanner flags moved out of the workflow into the pinned scan
        # policy, which check-vulnerabilities.py enforces on every report.
        self.assertIn("run-vulnerability-scan.py", vulnerability_section)
        self.assertIn("--policy security/vulnerability-policy.json", vulnerability_section)
        policy = json.loads((REPO_ROOT / "security/vulnerability-policy.json").read_text())
        self.assertIn("--list-all-pkgs", json.dumps(policy))
        self.assertIn("build-vulnerability-manifest.py", vulnerability_section)
        self.assertIn("check-vulnerabilities.py", vulnerability_section)
        self.assertIn("vulnerability-receipt.sigstore.json", vulnerability_section)
        self.assertIn("core_roots: [{", vulnerability_section)
        self.assertIn('kind: "connector-manifest-v1"', vulnerability_section)
        self.assertNotIn("artifact_path", vulnerability_section)
        self.assertNotIn("sbom_path", vulnerability_section)
        root_verify = vulnerability_section.index(
            'cosign verify-blob "$VULNERABILITY_DIR/connector/manifest.json"'
        )
        receipt_verify = vulnerability_section.index(
            "check-vulnerabilities.py verify-receipt"
        )
        self.assertLess(root_verify, receipt_verify)
        publish_section = workflow[publish:public_linux]
        self.assertIn(
            f'test "$evidence_count" = {connector_release.public_evidence_file_count()}',
            publish_section,
        )
        self.assertIn(".evidence_inventory[].path", publish_section)

        public_section = workflow[public_linux:aggregate]
        self.assertIn("gh release verify-asset", public_section)
        self.assertIn("create-public-release-descriptor", public_section)
        self.assertIn("connector-public-verification-linux.json", public_section)
        self.assertNotIn("connector-public-verification-darwin.json", public_section)
        self.assertGreaterEqual(
            public_section.count("verify-receipt"),
            len(connector_release.released_platforms()),
        )
        aggregate_section = workflow[aggregate:]
        self.assertIn("aggregate-verification-receipts", aggregate_section)
        self.assertIn("verify-aggregate", aggregate_section)
        self.assertIn("environment: connector-release-sigstore", aggregate_section)
        self.assertIn("id-token: write", aggregate_section)
        self.assertIn("retention-days: 90", aggregate_section)

    def test_workflow_verifies_runtime_constraints_before_installing_dev_extras(
        self,
    ) -> None:
        workflow = (
            REPO_ROOT / ".github/workflows/control-images-release.yml"
        ).read_text()
        runtime_install = workflow.index("--editable apps/control-api")
        runtime_verify = workflow.index(
            ".release-venv/bin/python deploy/scripts/verify-python-constraints.py"
        )
        dev_install = workflow.index("--editable 'apps/control-api[dev]'")

        self.assertLess(runtime_install, runtime_verify)
        self.assertLess(runtime_verify, dev_install)
        self.assertNotIn("[dev]", workflow[runtime_install:runtime_verify])

    def test_pwa_nginx_config_copy_is_explicitly_non_root_readable(self) -> None:
        dockerfile = (REPO_ROOT / "deploy/dockerfiles/pwa.Dockerfile").read_text()
        config_copy = re.search(
            r"^COPY --chmod=(0?[0-7]{3,4}) "
            r"deploy/nginx/pwa-nginx\.conf /etc/nginx/nginx\.conf$",
            dockerfile,
            flags=re.MULTILINE,
        )

        self.assertIsNotNone(config_copy, "nginx.conf COPY must declare --chmod")
        assert config_copy is not None
        self.assertNotEqual(
            int(config_copy.group(1), 8) & 0o004,
            0,
            "nginx.conf must be readable by the non-root nginx user",
        )

    def test_package_manager_and_python_builder_are_exactly_pinned(self) -> None:
        package = json.loads((REPO_ROOT / "package.json").read_text())
        expected = (
            "pnpm@11.7.0+sha512."
            "19cc852c120c7125760f2443ee6be0ca5b40f9f50598de1a09a1f177503e010e"
            "57c23c77646e01e761de59bf874fb22a3398c33ab9691fc13eb946b6f0f4d620"
        )
        self.assertEqual(package["packageManager"], expected)
        workflow = (
            REPO_ROOT / ".github/workflows/control-images-release.yml"
        ).read_text()
        dockerfile = (REPO_ROOT / "deploy/dockerfiles/pwa.Dockerfile").read_text()
        self.assertIn(expected, workflow)
        self.assertIn(expected, dockerfile)
        pyproject = (REPO_ROOT / "apps/control-api/pyproject.toml").read_text()
        self.assertIn('requires = ["hatchling==1.27.0"]', pyproject)
        postgres_tools = (
            REPO_ROOT / "deploy/dockerfiles/postgres-tools.Dockerfile"
        ).read_text()
        self.assertIn(
            "POSTGRES_IMAGE=postgres:18-alpine@sha256:"
            "9a8afca54e7861fd90fab5fdf4c42477a6b1cb7d293595148e674e0a3181de15",
            postgres_tools,
        )
        self.assertIn(
            'org.opencontainers.image.version="${CONTROL_RELEASE}"', postgres_tools
        )
        self.assertIn('org.opencontainers.image.revision="${VCS_REF}"', postgres_tools)

    def test_production_overlay_has_no_local_or_build_fallback(self) -> None:
        overlay = (
            REPO_ROOT / "deploy/docker-compose/compose.production.yaml"
        ).read_text()
        self.assertNotIn(":-", overlay)
        self.assertNotIn(":local", overlay)
        self.assertEqual(overlay.count("build: !reset null"), 5)
        self.assertEqual(overlay.count("pull_policy: never"), 5)
        self.assertEqual(overlay.count("${CONTROL_API_IMAGE:?"), 3)
        self.assertEqual(overlay.count("${CONTROL_PWA_IMAGE:?"), 1)
        self.assertEqual(overlay.count("${CONTROL_POSTGRES_TOOLS_IMAGE:?"), 1)

    @unittest.skipUnless(shutil.which("docker"), "Docker Compose CLI is unavailable")
    def test_rendered_production_compose_removes_every_runtime_build(self) -> None:
        environment = os.environ.copy()
        environment.update(
            {
                "CONTROL_API_IMAGE": f"{API_REPOSITORY}@{API_DIGEST}",
                "CONTROL_PWA_IMAGE": f"{PWA_REPOSITORY}@{PWA_DIGEST}",
                "CONTROL_POSTGRES_TOOLS_IMAGE": (
                    f"{POSTGRES_TOOLS_REPOSITORY}@{POSTGRES_TOOLS_DIGEST}"
                ),
                "CONTROL_RELEASE": RELEASE,
                "CONTROL_VCS_REF": SOURCE_COMMIT,
                "CONTROL_PUBLIC_ORIGIN": "https://control.example.com",
                "CONTROL_CONNECTOR_RELEASE_METADATA_JSON": '{"releasable":false}',
            }
        )
        result = subprocess.run(
            [
                "docker",
                "compose",
                "--profile",
                "*",
                "-f",
                str(REPO_ROOT / "deploy/docker-compose/compose.yaml"),
                "-f",
                str(REPO_ROOT / "deploy/docker-compose/compose.production.yaml"),
                "config",
                "--format",
                "json",
            ],
            cwd=REPO_ROOT,
            env=environment,
            text=True,
            capture_output=True,
            check=False,
        )
        if result.returncode != 0:
            self.fail(f"production Compose overlay does not render: {result.stderr}")
        rendered = json.loads(result.stdout)
        for service in (
            "control-migrate",
            "control-api",
            "control-api-replica",
            "codex-pwa",
            "control-backup",
        ):
            self.assertNotIn("build", rendered["services"][service])
            self.assertRegex(
                rendered["services"][service]["image"], r"@sha256:[0-9a-f]{64}$"
            )
            self.assertEqual(rendered["services"][service].get("pull_policy"), "never")
        api_image = rendered["services"]["control-api"]["image"]
        self.assertEqual(rendered["services"]["control-migrate"]["image"], api_image)
        self.assertEqual(
            rendered["services"]["control-api-replica"]["image"], api_image
        )


if __name__ == "__main__":
    unittest.main()
