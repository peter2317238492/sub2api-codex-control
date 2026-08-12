from __future__ import annotations

import hashlib
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
            output, "missing checksummed file", "--allow-local-unsigned"
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

    def test_downloaded_non_executable_artifact_still_verifies(self) -> None:
        output = self.fixture()
        manifest = json.loads((output / "manifest.json").read_text())
        artifact = output / manifest["targets"][0]["artifact"]["filename"]
        artifact.chmod(0o644)
        result = self.run_tool(
            "verify", "--output", str(output), "--allow-local-unsigned"
        )
        self.assertIn("verified local-unsigned", result.stdout)

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
            ["linux-amd64", "linux-arm64", "darwin-amd64", "darwin-arm64"],
        )


if __name__ == "__main__":
    unittest.main()
