from __future__ import annotations

import importlib.util
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "check_public_tree", ROOT / "scripts/check-public-tree.py"
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class PublicTreeTests(unittest.TestCase):
    def test_repository_public_tree_is_clean(self) -> None:
        self.assertEqual(MODULE.scan(ROOT), [])

    def test_scanner_rejects_private_text_artifacts_and_links(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "safe.txt").write_text("control.example.com\n", encoding="utf-8")
            private = root / "notes.txt"
            private.write_text(
                "home=" + "/Users" + "/private-user/project\n", encoding="utf-8"
            )
            generated = root / "session.jsonl"
            generated.write_text("{}\n", encoding="utf-8")
            (root / "alias").symlink_to(private)

            failures = MODULE.scan(root)
            self.assertTrue(any("non-example home path" in item for item in failures))
            self.assertTrue(any("file suffix" in item for item in failures))
            self.assertTrue(any("symbolic links" in item for item in failures))

    def test_scanner_rejects_hardlinks_and_private_named_files(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = root / "source.txt"
            original.write_text("safe\n", encoding="utf-8")
            os.link(original, root / "second.txt")
            (root / ".env").write_text("SECRET=value\n", encoding="utf-8")

            failures = MODULE.scan(root)
            self.assertEqual(sum("hard-linked" in item for item in failures), 2)
            self.assertTrue(
                any(
                    "forbidden private or generated file name" in item
                    for item in failures
                )
            )

    def test_external_literal_file_is_private_and_values_are_not_reported(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            deny = root / "deny"
            deny.write_text("synthetic-private-value\n", encoding="utf-8")
            deny.chmod(0o600)
            source = root / "source"
            source.mkdir()
            (source / "notes.txt").write_text(
                "contains synthetic-private-value\n", encoding="utf-8"
            )

            literals = MODULE.load_external_literals(deny)
            self.assertEqual(
                MODULE.scan(source, literals),
                ["notes.txt: contains an externally denied literal"],
            )

            deny.chmod(0o644)
            with self.assertRaisesRegex(ValueError, "mode 0600"):
                MODULE.load_external_literals(deny)

    def test_scanner_rejects_oversized_text_without_skipping_content(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "oversized.txt").write_bytes(b"x" * (MODULE.TEXT_BYTES_LIMIT + 1))
            failures = MODULE.scan(root)
            self.assertEqual(
                failures,
                ["oversized.txt: file exceeds the public text size limit"],
            )

    def test_scanner_rejects_unlisted_non_utf8_file(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "binary.bin").write_bytes(b"\xffprivate bytes\n")
            failures = MODULE.scan(root)
            self.assertEqual(
                failures,
                ["binary.bin: non-UTF-8 file is not an admitted binary asset"],
            )

    def test_scanner_rejects_casefolded_credentials_and_generated_paths(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for relative in (
                "Private/value.txt",
                ".ENV",
                ".env.production",
                "credentials.json",
                "auth-export.json",
                "secret.token",
                "Secrets/value.txt",
            ):
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("synthetic\n", encoding="utf-8")
            failures = MODULE.scan(root)
            for relative in (
                "Private",
                ".ENV",
                ".env.production",
                "credentials.json",
                "auth-export.json",
                "secret.token",
                "Secrets",
            ):
                self.assertTrue(any(relative in item for item in failures), relative)

    def test_external_literal_in_path_is_redacted_for_early_failures(self) -> None:
        literal = "synthetic-private-value"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "safe.txt"
            target.write_text("safe\n", encoding="utf-8")
            (root / f"{literal}-link").symlink_to(target)
            hardlink = root / f"{literal}-hardlink"
            os.link(target, hardlink)
            failures = MODULE.scan(root, (literal,))
            self.assertTrue(any("symbolic links" in item for item in failures))
            self.assertTrue(any("hard-linked" in item for item in failures))
            self.assertTrue(all(literal not in item for item in failures))

    def test_directory_traversal_error_fails_closed_without_absolute_path(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)

            def walk_with_error(*_args: object, **kwargs: object):
                kwargs["onerror"](
                    PermissionError(13, "Permission denied", "/private/path")
                )
                return iter(())

            with mock.patch.object(MODULE.os, "walk", side_effect=walk_with_error):
                failures = MODULE.scan(root)
            self.assertEqual(
                failures,
                ["directory traversal failed: Permission denied"],
            )

    def test_git_index_and_head_blobs_are_scanned_independently_of_worktree(
        self,
    ) -> None:
        literal = "synthetic-private-value"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            subprocess.run(["git", "-C", str(root), "init", "-q"], check=True)
            subprocess.run(
                [
                    "git",
                    "-C",
                    str(root),
                    "config",
                    "user.email",
                    "test@example.invalid",
                ],
                check=True,
            )
            subprocess.run(
                ["git", "-C", str(root), "config", "user.name", "Public Tree Test"],
                check=True,
            )
            source = root / "tracked.txt"
            source.write_text("safe\n", encoding="utf-8")
            subprocess.run(["git", "-C", str(root), "add", "tracked.txt"], check=True)
            subprocess.run(
                ["git", "-C", str(root), "commit", "-qm", "safe"], check=True
            )
            source.write_text(f"{literal}\n", encoding="utf-8")
            subprocess.run(["git", "-C", str(root), "add", "tracked.txt"], check=True)
            source.write_text("safe again\n", encoding="utf-8")
            failures = MODULE.scan(root, (literal,))
            self.assertTrue(
                any(
                    "Git index tracked.txt" in item and "externally denied" in item
                    for item in failures
                )
            )
            self.assertTrue(all(literal not in item for item in failures))

            subprocess.run(
                ["git", "-C", str(root), "checkout", "--", "tracked.txt"], check=True
            )
            source.write_text(f"{literal}\n", encoding="utf-8")
            subprocess.run(["git", "-C", str(root), "add", "tracked.txt"], check=True)
            subprocess.run(
                ["git", "-C", str(root), "commit", "-qm", "private"], check=True
            )
            source.write_text("safe worktree\n", encoding="utf-8")
            subprocess.run(["git", "-C", str(root), "add", "tracked.txt"], check=True)
            failures = MODULE.scan(root, (literal,))
            self.assertTrue(
                any(
                    "Git HEAD tracked.txt" in item and "externally denied" in item
                    for item in failures
                )
            )
            self.assertTrue(all(literal not in item for item in failures))


if __name__ == "__main__":
    unittest.main()
