from __future__ import annotations

import argparse
import base64
import contextlib
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
        control_images.command_create_lock(
            argparse.Namespace(
                **self.common,
                output_dir=str(self.release_dir),
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

    def test_workflow_actions_are_commit_pinned_and_release_only_on_tag_push(
        self,
    ) -> None:
        workflow = (
            REPO_ROOT / ".github/workflows/control-images-release.yml"
        ).read_text()
        self.assertIn('tags:\n      - "control-v*"', workflow)
        self.assertNotIn("workflow_dispatch", workflow)
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
