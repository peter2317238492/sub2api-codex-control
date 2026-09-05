from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import os
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
TOOL_PATH = REPO_ROOT / "deploy/release/source_bundle.py"
SPEC = importlib.util.spec_from_file_location("source_bundle", TOOL_PATH)
assert SPEC is not None and SPEC.loader is not None
source_bundle = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(source_bundle)

REPOSITORY = "https://github.com/example/sub2api-codex-control"
RELEASE = "0.1.0"
EPOCH = 1_700_000_000
PORTABLE_USTAR_FIXTURE_SHA256 = (
    "b9a2c7e5e538e9f51bfac15d63cc32e0a0ee0d68e9161118918c944819985e2f"
)


class SourceBundleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="source-bundle-tests.")
        self.root = Path(self.temporary.name).resolve()
        self.repo = self.root / "repo"
        self.repo.mkdir(mode=0o700)
        self._git("init", "-q")
        self._git("config", "user.email", "release@example.invalid")
        self._git("config", "user.name", "Release Test")
        fixture_paths = {
            "README.md": "public source\n",
            "LICENSE": "test license\n",
            "NOTICE": "test notice\n",
            "THIRD_PARTY_NOTICES.md": "test third-party notices\n",
            "scripts/check.py": "#!/usr/bin/env python3\nprint('ok')\n",
            "scripts/check-licenses.py": "#!/usr/bin/env python3\n",
            "scripts/check-public-tree.py": "#!/usr/bin/env python3\n",
            "third_party/licenses/Example-LICENSE.txt": "example license\n",
        }
        for relative, content in fixture_paths.items():
            path = self.repo / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="ascii")
        for relative in sorted(source_bundle.REQUIRED_SOURCE_PATHS):
            path = self.repo / relative
            if path.exists():
                continue
            path.parent.mkdir(parents=True, exist_ok=True)
            content = "{}\n" if relative.endswith(".json") else "fixture\n"
            path.write_text(content, encoding="ascii")
        for relative in (
            "scripts/check.py",
            "scripts/check-licenses.py",
            "scripts/check-public-tree.py",
        ):
            (self.repo / relative).chmod(0o755)
        components = {
            "format_version": 1,
            "components": [
                {
                    "id": "example",
                    "license_files": [
                        {"path": "third_party/licenses/Example-LICENSE.txt"}
                    ],
                }
            ],
        }
        (self.repo / "third_party/components.json").write_text(
            json.dumps(components, sort_keys=True) + "\n", encoding="ascii"
        )
        self._git("add", ".")
        self._git("commit", "-qm", "fixture")
        self.commit = self._git("rev-parse", "HEAD").stdout.strip()
        self.expected_file_count = len(
            self._git("ls-files").stdout.splitlines()
        )
        self.first = self.root / "first"
        self.second = self.root / "second"
        self.first.mkdir(mode=0o700)
        self.second.mkdir(mode=0o700)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _git(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["git", "-C", str(self.repo), *arguments],
            check=True,
            capture_output=True,
            text=True,
        )

    def _build(self, output: Path | None = None) -> dict[str, object]:
        return source_bundle.build_bundle(
            self.repo,
            output or self.first,
            release=RELEASE,
            repository=REPOSITORY,
            commit=self.commit,
            source_date_epoch=EPOCH,
        )

    def _digests(self, directory: Path) -> dict[str, str]:
        return {
            "attestation_sha256": source_bundle.sha256_file(
                directory / source_bundle.ATTESTATION_FILENAME
            ),
            "manifest_sha256": source_bundle.sha256_file(
                directory / source_bundle.MANIFEST_FILENAME
            ),
            "archive_sha256": source_bundle.sha256_file(
                directory / source_bundle.ARCHIVE_FILENAME
            ),
        }

    def _verify(self, directory: Path | None = None) -> dict[str, object]:
        target = directory or self.first
        return source_bundle.verify_bundle(
            target,
            release=RELEASE,
            repository=REPOSITORY,
            commit=self.commit,
            **self._digests(target),
        )

    def _rewrite_without(self, removed_path: str) -> None:
        self._build()
        manifest_path = self.first / source_bundle.MANIFEST_FILENAME
        archive_path = self.first / source_bundle.ARCHIVE_FILENAME
        attestation_path = self.first / source_bundle.ATTESTATION_FILENAME
        records = [
            record
            for record in source_bundle.parse_manifest(manifest_path.read_bytes())
            if record["path"] != removed_path
        ]
        content_by_path = {
            record["path"]: (self.repo / record["path"]).read_bytes()
            for record in records
        }
        manifest_path.write_bytes(source_bundle.manifest_bytes(records))
        archive_path.unlink()
        source_bundle.write_archive(archive_path, records, content_by_path, EPOCH)
        attestation = json.loads(attestation_path.read_text(encoding="ascii"))
        attestation["file_count"] = len(records)
        attestation["total_bytes"] = sum(record["size"] for record in records)
        attestation["manifest"]["sha256"] = source_bundle.sha256_file(manifest_path)
        attestation["manifest"]["size"] = manifest_path.stat().st_size
        attestation["archive"]["sha256"] = source_bundle.sha256_file(archive_path)
        attestation["archive"]["size"] = archive_path.stat().st_size
        attestation_path.write_bytes(source_bundle.canonical_json(attestation))

    def test_build_is_deterministic_and_verifies(self) -> None:
        first = self._build(self.first)
        second = self._build(self.second)
        for filename in (
            source_bundle.ARCHIVE_FILENAME,
            source_bundle.MANIFEST_FILENAME,
            source_bundle.ATTESTATION_FILENAME,
        ):
            self.assertEqual(
                (self.first / filename).read_bytes(),
                (self.second / filename).read_bytes(),
                filename,
            )
        manifest_paths = {
            json.loads(line)["path"]
            for line in (self.first / source_bundle.MANIFEST_FILENAME)
            .read_text(encoding="ascii")
            .splitlines()
        }
        self.assertTrue(source_bundle.REQUIRED_SOURCE_PATHS <= manifest_paths)
        self.assertIn("third_party/licenses/Example-LICENSE.txt", manifest_paths)
        verified = self._verify()
        self.assertEqual(verified["file_count"], self.expected_file_count)
        self.assertEqual(first, second)

    def test_formal_server_runtime_closure_is_explicit(self) -> None:
        expected = {
            "LICENSE",
            "NOTICE",
            "THIRD_PARTY_NOTICES.md",
            "connector/internal/config/config.go",
            "connector/internal/protocol/protocol.go",
            "connector/packaging/verify-package-contents.sh",
            "connector/release/connector-aggregate-verification-receipt.schema.json",
            "connector/release/release-config.json",
            "deploy/schemas/production-recovery-receipt.schema.json",
            "deploy/scripts/deploy-production.sh",
            "deploy/scripts/probe-sub2api-auth-contract.py",
            "deploy/scripts/production-recovery.py",
            "deploy/scripts/verify-sub2api-runtime.py",
            "deploy/scripts/verify-sub2api-runtime.sh",
            "docs/contracts/sub2api-auth.v0.2.1.json",
            "packages/appserver-schema/generated/json-schema/codex_app_server_protocol.v2.schemas.json",
            "packages/control-protocol/fixtures/json-budget-vectors.json",
            "packages/control-protocol/fixtures/rpc-policy.json",
            "packages/control-protocol/fixtures/wire-envelopes.json",
            "packages/control-protocol/schema/control-envelope.schema.json",
            "scripts/build-vulnerability-manifest.py",
            "scripts/run-vulnerability-scan.py",
            "scripts/verify-formal-vulnerability-release.sh",
            "scripts/vulnerability_release_roots.py",
            "scripts/vulnerability_scan_evidence.py",
            "security/vulnerability-policy.json",
            "tests/e2e/smoke.py",
            "third_party/licenses/Trivy-LICENSE.txt",
            "versions.lock.json",
        }

        self.assertTrue(expected <= source_bundle.REQUIRED_SERVER_SOURCE_PATHS)

    def test_ustar_bytes_match_the_cross_runtime_fixture(self) -> None:
        content = b"portable source fixture\n"
        record = {
            "mode": "0444",
            "path": "README.md",
            "sha256": hashlib.sha256(content).hexdigest(),
            "size": len(content),
        }
        archive = io.BytesIO()
        source_bundle.write_archive_stream(
            archive,
            [record],
            {"README.md": content},
            EPOCH,
        )
        self.assertEqual(len(archive.getvalue()), 2048)
        self.assertEqual(
            hashlib.sha256(archive.getvalue()).hexdigest(),
            PORTABLE_USTAR_FIXTURE_SHA256,
        )

    def test_verify_and_extract_to_new_private_tree(self) -> None:
        self._build()
        extracted = self.root / "stage"
        result = source_bundle.extract_verified_bundle(
            self.first,
            extracted,
            release=RELEASE,
            repository=REPOSITORY,
            commit=self.commit,
            **self._digests(self.first),
        )
        self.assertTrue(result["extracted"])
        self.assertEqual((extracted / "README.md").read_text(), "public source\n")
        self.assertEqual((extracted / "README.md").stat().st_mode & 0o777, 0o444)
        self.assertEqual((extracted / "scripts/check.py").stat().st_mode & 0o777, 0o555)
        self.assertEqual(extracted.stat().st_mode & 0o777, 0o555)
        with self.assertRaisesRegex(
            source_bundle.SourceBundleError, "must not already"
        ):
            source_bundle.extract_verified_bundle(
                self.first,
                extracted,
                release=RELEASE,
                repository=REPOSITORY,
                commit=self.commit,
                **self._digests(self.first),
            )

    def test_dirty_tracked_checkout_is_rejected(self) -> None:
        (self.repo / "README.md").write_text("changed\n", encoding="ascii")
        with self.assertRaisesRegex(source_bundle.SourceBundleError, "dirty"):
            self._build()

    def test_assume_unchanged_cannot_hide_content_drift(self) -> None:
        self._git("update-index", "--assume-unchanged", "README.md")
        (self.repo / "README.md").write_text("hidden drift\n", encoding="ascii")
        self.assertEqual(
            self._git("status", "--porcelain=v1", "--untracked-files=no").stdout,
            "",
        )
        with self.assertRaisesRegex(
            source_bundle.SourceBundleError, "committed Git object"
        ):
            self._build()

    def test_replace_ref_and_assume_unchanged_cannot_replace_commit_blob(self) -> None:
        original_blob = self._git("rev-parse", "HEAD:README.md").stdout.strip()
        replacement = subprocess.run(
            ["git", "-C", str(self.repo), "hash-object", "-w", "--stdin"],
            check=True,
            input="replacement bytes\n",
            capture_output=True,
            text=True,
        ).stdout.strip()
        self._git("replace", original_blob, replacement)
        self._git("update-index", "--assume-unchanged", "README.md")
        (self.repo / "README.md").write_text("replacement bytes\n", encoding="ascii")
        self.assertEqual(
            self._git("status", "--porcelain=v1", "--untracked-files=no").stdout,
            "",
        )
        with self.assertRaisesRegex(
            source_bundle.SourceBundleError, "committed Git object"
        ):
            self._build()

    def test_required_license_closure_is_enforced_from_commit_tree(self) -> None:
        self._git("rm", "-q", "NOTICE")
        self._git("commit", "-qm", "remove required notice")
        self.commit = self._git("rev-parse", "HEAD").stdout.strip()
        with self.assertRaisesRegex(
            source_bundle.SourceBundleError, "required release"
        ):
            self._build()

    def test_declared_third_party_license_must_be_in_commit_tree(self) -> None:
        self._git("rm", "-q", "third_party/licenses/Example-LICENSE.txt")
        self._git("commit", "-qm", "remove declared license")
        self.commit = self._git("rev-parse", "HEAD").stdout.strip()
        with self.assertRaisesRegex(
            source_bundle.SourceBundleError, "declared third-party"
        ):
            self._build()

    def test_verifier_rejects_self_consistent_bundle_without_required_file(
        self,
    ) -> None:
        self._rewrite_without("NOTICE")
        with self.assertRaisesRegex(
            source_bundle.SourceBundleError, "required release"
        ):
            self._verify()

    def test_verifier_rejects_self_consistent_bundle_without_declared_license(
        self,
    ) -> None:
        self._rewrite_without("third_party/licenses/Example-LICENSE.txt")
        with self.assertRaisesRegex(
            source_bundle.SourceBundleError, "declared third-party"
        ):
            self._verify()

    def test_git_symlink_and_forbidden_tracked_path_are_rejected(self) -> None:
        os.symlink("README.md", self.repo / "link")
        self._git("add", "link")
        self._git("commit", "-qm", "link")
        self.commit = self._git("rev-parse", "HEAD").stdout.strip()
        with self.assertRaisesRegex(
            source_bundle.SourceBundleError, "unsupported mode"
        ):
            self._build()

        self._git("rm", "-q", "link")
        cache = self.repo / "node_modules/pkg.js"
        cache.parent.mkdir()
        cache.write_text("generated\n", encoding="ascii")
        self._git("add", "node_modules/pkg.js")
        self._git("commit", "-qm", "forbidden")
        self.commit = self._git("rev-parse", "HEAD").stdout.strip()
        with self.assertRaisesRegex(
            source_bundle.SourceBundleError, "forbidden|unexpected top-level"
        ):
            self._build()

    def test_hard_linked_or_special_worktree_file_is_rejected(self) -> None:
        outside = self.root / "outside"
        os.link(self.repo / "README.md", outside)
        with self.assertRaisesRegex(source_bundle.SourceBundleError, "hard link"):
            self._build()
        outside.unlink()

        original = (self.repo / "README.md").read_bytes()
        (self.repo / "README.md").unlink()
        os.mkfifo(self.repo / "README.md", 0o600)
        try:
            with self.assertRaisesRegex(
                source_bundle.SourceBundleError, "dirty|regular file"
            ):
                self._build()
        finally:
            (self.repo / "README.md").unlink()
            (self.repo / "README.md").write_bytes(original)

    def test_tampered_assets_are_rejected(self) -> None:
        self._build()
        expected = self._digests(self.first)
        for filename in (
            source_bundle.ARCHIVE_FILENAME,
            source_bundle.MANIFEST_FILENAME,
            source_bundle.ATTESTATION_FILENAME,
        ):
            with self.subTest(filename=filename):
                target = self.first / filename
                original = target.read_bytes()
                target.write_bytes(original + b"x")
                with self.assertRaisesRegex(source_bundle.SourceBundleError, "digest"):
                    source_bundle.verify_bundle(
                        self.first,
                        release=RELEASE,
                        repository=REPOSITORY,
                        commit=self.commit,
                        **expected,
                    )
                target.write_bytes(original)

    def test_manifest_rejects_traversal_duplicate_and_invalid_mode(self) -> None:
        digest = "0" * 64
        base = {"mode": "0444", "path": "README.md", "sha256": digest, "size": 0}
        traversal = dict(base, path="../escape")
        with self.assertRaisesRegex(source_bundle.SourceBundleError, "canonical"):
            source_bundle.parse_manifest(source_bundle.canonical_json(traversal))
        duplicate = source_bundle.canonical_json(base) * 2
        with self.assertRaisesRegex(source_bundle.SourceBundleError, "repeats"):
            source_bundle.parse_manifest(duplicate)
        invalid = dict(base, mode="0777")
        with self.assertRaisesRegex(source_bundle.SourceBundleError, "mode"):
            source_bundle.parse_manifest(source_bundle.canonical_json(invalid))

    def test_archive_rejects_links_duplicate_members_and_metadata_drift(self) -> None:
        self._build()
        records = source_bundle.parse_manifest(
            (self.first / source_bundle.MANIFEST_FILENAME).read_bytes()
        )
        content_by_path = {
            record["path"]: (self.repo / record["path"]).read_bytes()
            for record in records
        }

        def archive_bytes(kind: str) -> bytes:
            raw_path = self.root / f"{kind}.tar.gz"
            with tarfile.open(raw_path, mode="w", format=tarfile.USTAR_FORMAT) as tar:
                for index, record in enumerate(records):
                    info = tarfile.TarInfo(record["path"])
                    info.size = record["size"]
                    info.mode = int(record["mode"], 8)
                    info.uid = 0
                    info.gid = 0
                    info.uname = ""
                    info.gname = ""
                    info.mtime = EPOCH
                    if kind in {"link", "contiguous", "sparse"} and index == 0:
                        info.type = {
                            "link": tarfile.SYMTYPE,
                            "contiguous": tarfile.CONTTYPE,
                            "sparse": tarfile.GNUTYPE_SPARSE,
                        }[kind]
                        if kind == "link":
                            info.linkname = "README.md"
                            info.size = 0
                            tar.addfile(info)
                        else:
                            tar.addfile(
                                info,
                                io.BytesIO(content_by_path[record["path"]]),
                            )
                    else:
                        if kind == "mode" and index == 0:
                            info.mode = 0o777
                        tar.addfile(info, io.BytesIO(content_by_path[record["path"]]))
                        if kind == "duplicate" and index == 0:
                            tar.addfile(
                                info, io.BytesIO(content_by_path[record["path"]])
                            )
            return raw_path.read_bytes()

        for kind, message in (
            ("link", "regular file"),
            ("contiguous", "regular file"),
            ("sparse", "regular file"),
            ("duplicate", "order|repeats"),
            ("mode", "metadata"),
        ):
            with (
                self.subTest(kind=kind),
                self.assertRaisesRegex(source_bundle.SourceBundleError, message),
            ):
                source_bundle.validate_archive(archive_bytes(kind), records, EPOCH)

    def test_archive_rejects_noncanonical_headers_and_trailing_bytes(self) -> None:
        self._build()
        records = source_bundle.parse_manifest(
            (self.first / source_bundle.MANIFEST_FILENAME).read_bytes()
        )
        raw = (self.first / source_bundle.ARCHIVE_FILENAME).read_bytes()
        variants: dict[str, bytes] = {"trailer": raw + b"HIDDEN-TRAILER"}
        changed_padding = bytearray(raw)
        first_size = records[0]["size"]
        first_padding_offset = 512 + first_size
        changed_padding[first_padding_offset] = 1
        variants["nonzero-padding"] = bytes(changed_padding)
        changed_header = bytearray(raw)
        changed_header[265] = ord("X")
        header = changed_header[:512]
        header[148:156] = b"        "
        checksum = sum(header)
        changed_header[148:156] = f"{checksum:06o}".encode("ascii") + b"\0 "
        variants["header-drift"] = bytes(changed_header)

        for kind, candidate in variants.items():
            with (
                self.subTest(kind=kind),
                self.assertRaisesRegex(
                    source_bundle.SourceBundleError,
                    "canonical deterministic|metadata differs",
                ),
            ):
                source_bundle.validate_archive(candidate, records, EPOCH)

    def test_extract_rejects_symbolic_link_parent(self) -> None:
        self._build()
        real_parent = self.root / "real-parent"
        real_parent.mkdir(mode=0o700)
        alias = self.root / "alias-parent"
        alias.symlink_to(real_parent, target_is_directory=True)
        with self.assertRaisesRegex(
            source_bundle.SourceBundleError, "only real directories"
        ):
            source_bundle.extract_verified_bundle(
                self.first,
                alias / "stage",
                release=RELEASE,
                repository=REPOSITORY,
                commit=self.commit,
                **self._digests(self.first),
            )

    def test_placeholder_source_paths_are_narrowly_allowed(self) -> None:
        self.assertEqual(
            source_bundle.validate_path("deploy/docker-compose/secrets/README.md"),
            "deploy/docker-compose/secrets/README.md",
        )
        with self.assertRaisesRegex(source_bundle.SourceBundleError, "forbidden"):
            source_bundle.validate_path("deploy/docker-compose/secrets/value")
        with self.assertRaisesRegex(source_bundle.SourceBundleError, "forbidden"):
            source_bundle.validate_path("tests/e2e/reports/result.json")


if __name__ == "__main__":
    unittest.main()
