import hashlib
import importlib.util
import json
import shutil
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "check_licenses", ROOT / "scripts/check-licenses.py"
)
assert SPEC is not None and SPEC.loader is not None
CHECK_LICENSES = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECK_LICENSES)


class LicenseComplianceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.root = Path(self.tempdir.name)
        for relative in (
            "LICENSE",
            "NOTICE",
            "THIRD_PARTY_NOTICES.md",
            "package.json",
            "pnpm-lock.yaml",
            "versions.lock.json",
            "apps/control-api/pyproject.toml",
            "apps/pwa/package.json",
            "deploy/constraints/control-api.txt",
            "connector/go.mod",
            "connector/go.sum",
            ".github/workflows/ci.yml",
            ".github/workflows/connector-release.yml",
            ".github/workflows/control-images-release.yml",
            "packages/appserver-schema/README.md",
            "packages/appserver-schema/codex-version.txt",
            "packages/appserver-schema/package.json",
            "packages/control-protocol/package.json",
        ):
            destination = self.root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / relative, destination)
        shutil.copytree(ROOT / "third_party", self.root / "third_party")
        for source in (ROOT / "connector").rglob("*.go"):
            destination = self.root / source.relative_to(ROOT)
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, destination)

    def test_current_license_policy_passes(self) -> None:
        self.assertEqual(CHECK_LICENSES.validate(self.root), [])

    def test_modified_license_text_fails_closed(self) -> None:
        path = self.root / "third_party/licenses/Vue-LICENSE.txt"
        path.write_text(path.read_text(encoding="utf-8") + "modified\n", encoding="utf-8")
        errors = CHECK_LICENSES.validate(self.root)
        self.assertTrue(any("SHA-256 mismatch" in error and "Vue-LICENSE" in error for error in errors))

    def test_self_consistent_manifest_and_license_tampering_fails_closed(self) -> None:
        license_path = self.root / "third_party/licenses/Vue-LICENSE.txt"
        tampered = license_path.read_bytes() + b"modified\n"
        license_path.write_bytes(tampered)
        digest = hashlib.sha256(tampered).hexdigest()
        manifest_path = self.root / "third_party/components.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        vue = next(component for component in manifest["components"] if component["id"] == "vue")
        vue["license_files"][0]["file_sha256"] = digest
        vue["license_files"][0]["source_sha256"] = digest
        manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        errors = CHECK_LICENSES.validate(self.root)
        self.assertTrue(any("components.json SHA-256 mismatch" in error for error in errors))

    def test_legacy_go_module_import_fails_closed(self) -> None:
        path = next((self.root / "connector").rglob("*.go"))
        path.write_text(
            path.read_text(encoding="utf-8")
            + '\nimportedFrom = "github.com/sub2api-codex/control/connector/internal/example"\n',
            encoding="utf-8",
        )
        errors = CHECK_LICENSES.validate(self.root)
        self.assertTrue(any("legacy private Go module import" in error for error in errors))

    def test_node_package_author_drift_fails_closed(self) -> None:
        path = self.root / "apps/pwa/package.json"
        package = json.loads(path.read_text(encoding="utf-8"))
        package["author"] = "Personal Name"
        path.write_text(json.dumps(package, indent=2) + "\n", encoding="utf-8")
        errors = CHECK_LICENSES.validate(self.root)
        self.assertTrue(any("neutral contributors author" in error for error in errors))

    def test_binary_tag_trigger_fails_closed(self) -> None:
        path = self.root / ".github/workflows/connector-release.yml"
        text = path.read_text(encoding="utf-8")
        path.write_text(
            text.replace(
                "on:\n  workflow_dispatch:\n",
                "on:\n  push:\n    tags:\n      - 'connector-v*'\n  workflow_dispatch:\n",
                1,
            ),
            encoding="utf-8",
        )
        errors = CHECK_LICENSES.validate(self.root)
        self.assertTrue(any("must expose only workflow_dispatch" in error for error in errors))

    def test_release_guard_bypass_fails_closed(self) -> None:
        path = self.root / ".github/workflows/control-images-release.yml"
        text = path.read_text(encoding="utf-8")
        path.write_text(text.replace("          exit 1", "          exit 0", 1), encoding="utf-8")
        errors = CHECK_LICENSES.validate(self.root)
        self.assertTrue(any("source-only-guard must terminate with exit 1" in error for error in errors))

    def test_conditional_release_guard_exit_fails_closed(self) -> None:
        path = self.root / ".github/workflows/connector-release.yml"
        text = path.read_text(encoding="utf-8")
        path.write_text(
            text.replace(
                "          exit 1",
                "          if false; then\n            exit 1\n          fi",
                1,
            ),
            encoding="utf-8",
        )
        errors = CHECK_LICENSES.validate(self.root)
        self.assertTrue(
            any("connector-release.yml SHA-256 mismatch" in error for error in errors)
        )

    def test_unguarded_release_job_fails_closed(self) -> None:
        path = self.root / ".github/workflows/control-images-release.yml"
        with path.open("a", encoding="utf-8") as workflow:
            workflow.write(
                "\n  rogue-publish:\n"
                "    runs-on: ubuntu-24.04\n"
                "    permissions:\n"
                "      contents: write\n"
                "    steps:\n"
                "      - run: gh release create rogue\n"
            )
        errors = CHECK_LICENSES.validate(self.root)
        self.assertTrue(
            any("control-images-release.yml SHA-256 mismatch" in error for error in errors)
        )

    def test_additional_workflow_fails_closed(self) -> None:
        path = self.root / ".github/workflows/rogue-release.yml"
        path.write_text(
            "name: Rogue release\non: workflow_dispatch\njobs: {}\n",
            encoding="utf-8",
        )
        errors = CHECK_LICENSES.validate(self.root)
        self.assertTrue(any("workflow file set mismatch" in error for error in errors))

    def test_ci_workflow_tampering_fails_closed(self) -> None:
        path = self.root / ".github/workflows/ci.yml"
        path.write_text(
            path.read_text(encoding="utf-8") + "\n# unauthorized release path\n",
            encoding="utf-8",
        )
        errors = CHECK_LICENSES.validate(self.root)
        self.assertTrue(any("ci.yml SHA-256 mismatch" in error for error in errors))

    def test_third_party_notice_table_tampering_fails_closed(self) -> None:
        path = self.root / "THIRD_PARTY_NOTICES.md"
        text = path.read_text(encoding="utf-8")
        path.write_text(
            text.replace(
                "| Alembic | 1.18.5 | Python runtime dependency | MIT |",
                "| Alembic | 9.9.9 | Python runtime dependency | Proprietary |",
                1,
            ),
            encoding="utf-8",
        )
        errors = CHECK_LICENSES.validate(self.root)
        self.assertTrue(any("THIRD_PARTY_NOTICES.md SHA-256 mismatch" in error for error in errors))
        self.assertTrue(any("component table does not match" in error for error in errors))


if __name__ == "__main__":
    unittest.main()
