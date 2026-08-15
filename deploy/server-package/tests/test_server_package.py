"""Focused, offline tests for the server package format and verifier."""

from __future__ import annotations

import gzip
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock


MODULE_PATH = Path(__file__).resolve().parents[1] / "server_package.py"
SPEC = importlib.util.spec_from_file_location("server_package_under_test", MODULE_PATH)
if SPEC is None or SPEC.loader is None:  # pragma: no cover - import failure is fatal
    raise RuntimeError(f"cannot load {MODULE_PATH}")
SERVER_PACKAGE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = SERVER_PACKAGE
SPEC.loader.exec_module(SERVER_PACKAGE)


class IsolatedEntrypointTests(unittest.TestCase):
    def test_cli_rejects_nonisolated_startup_before_shadow_import(self) -> None:
        with tempfile.TemporaryDirectory(prefix="server-package-shadow.") as temporary:
            root = Path(temporary)
            script = root / "server-package-verify.py"
            marker = root / "platform-imported"
            shutil.copy2(MODULE_PATH, script)
            (root / "platform.py").write_text(
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


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while block := source.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def write_ustar_gzip(
    path: Path,
    members: list[dict[str, object]],
    *,
    epoch: int = 1_700_000_000,
) -> None:
    """Write a small canonical gzip-compressed USTAR fixture."""

    with path.open("xb") as raw:
        with gzip.GzipFile(
            filename="", mode="wb", compresslevel=9, fileobj=raw, mtime=epoch
        ) as compressed:
            with tarfile.open(
                fileobj=compressed, mode="w|", format=tarfile.USTAR_FORMAT
            ) as archive:
                for member in members:
                    content = member.get("content", b"")
                    assert isinstance(content, bytes)
                    info = tarfile.TarInfo(str(member["name"]))
                    info.type = member.get("type", tarfile.REGTYPE)
                    info.linkname = str(member.get("linkname", ""))
                    info.mode = int(member.get("mode", 0o444))
                    info.uid = int(member.get("uid", 0))
                    info.gid = int(member.get("gid", 0))
                    info.uname = str(member.get("uname", ""))
                    info.gname = str(member.get("gname", ""))
                    info.mtime = int(member.get("mtime", epoch))
                    info.size = len(content) if info.type == tarfile.REGTYPE else 0
                    archive.addfile(info, io.BytesIO(content) if content else None)
    path.chmod(0o600)


class CanonicalJsonTests(unittest.TestCase):
    def test_canonical_json_is_ascii_sorted_compact_and_newline_terminated(self) -> None:
        value = {"z": "snowman: \u2603", "a": [True, None, 1]}

        raw = SERVER_PACKAGE.canonical_json(value)

        self.assertEqual(
            raw,
            b'{"a":[true,null,1],"z":"snowman: \\u2603"}\n',
        )
        self.assertEqual(
            SERVER_PACKAGE.strict_json(raw, "fixture", canonical=True), value
        )

    def test_duplicate_key_is_rejected_before_canonicalization(self) -> None:
        with self.assertRaisesRegex(
            SERVER_PACKAGE.ServerPackageError, "repeats key 'a'"
        ):
            SERVER_PACKAGE.strict_json(b'{"a":1,"a":2}\n', "fixture")

    def test_noncanonical_spacing_is_rejected(self) -> None:
        with self.assertRaisesRegex(
            SERVER_PACKAGE.ServerPackageError, "not canonical JSON"
        ):
            SERVER_PACKAGE.strict_json(b'{"a": 1}\n', "fixture", canonical=True)

    def test_nonfinite_number_is_rejected_as_server_package_error(self) -> None:
        with self.assertRaises(SERVER_PACKAGE.ServerPackageError):
            SERVER_PACKAGE.strict_json(b'{"a":NaN}\n', "fixture", canonical=True)


class DeterministicArchiveTests(unittest.TestCase):
    EPOCH = 1_700_000_123

    def _make_stage(self, parent: Path) -> Path:
        stage = parent / "stage"
        (stage / "bin").mkdir(parents=True)
        (stage / "share").mkdir()
        executable = stage / "bin" / "run"
        executable.write_bytes(b"#!/bin/sh\nexit 0\n")
        executable.chmod(0o555)
        data = stage / "share" / "data.txt"
        data.write_bytes(b"deterministic payload\n")
        data.chmod(0o444)
        return stage

    def test_same_stage_and_epoch_produce_identical_archive_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage = self._make_stage(root)
            first = root / "first.tar.gz"
            second = root / "second.tar.gz"

            SERVER_PACKAGE.write_package_archive(
                stage,
                first,
                root_name="server-root",
                source_date_epoch=self.EPOCH,
            )
            SERVER_PACKAGE.write_package_archive(
                stage,
                second,
                root_name="server-root",
                source_date_epoch=self.EPOCH,
            )

            self.assertEqual(first.read_bytes(), second.read_bytes())
            self.assertEqual(first.read_bytes()[:10], b"\x1f\x8b\x08\x00" + self.EPOCH.to_bytes(4, "little") + b"\x02\xff")
            self.assertEqual(stat.S_IMODE(first.stat().st_mode), 0o444)
            self.assertEqual(
                SERVER_PACKAGE.validate_single_gzip(first)[0], self.EPOCH
            )

    def test_archive_is_sorted_ustar_with_normalized_metadata_and_modes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage = self._make_stage(root)
            archive_path = root / "archive.tar.gz"
            SERVER_PACKAGE.write_package_archive(
                stage,
                archive_path,
                root_name="server-root",
                source_date_epoch=self.EPOCH,
            )

            with tarfile.open(archive_path, "r:gz") as archive:
                members = archive.getmembers()

            self.assertEqual(
                [member.name for member in members],
                ["server-root/bin/run", "server-root/share/data.txt"],
            )
            self.assertEqual([member.mode for member in members], [0o555, 0o444])
            for member in members:
                self.assertEqual(member.type, tarfile.REGTYPE)
                self.assertEqual((member.uid, member.gid), (0, 0))
                self.assertEqual((member.uname, member.gname), ("", ""))
                self.assertEqual(member.mtime, self.EPOCH)
                self.assertEqual(member.pax_headers, {})


class PackageDeliveryTests(unittest.TestCase):
    def test_single_delivery_keeps_logical_archive(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            archive = output / "package.tar.gz"
            archive.write_bytes(b"1234567")
            archive.chmod(0o600)

            with mock.patch.object(SERVER_PACKAGE, "GITHUB_ASSET_LIMIT_BYTES", 8):
                delivery = SERVER_PACKAGE.package_delivery(output, archive)

            self.assertTrue(archive.is_file())
            self.assertEqual(delivery["kind"], "single")
            self.assertEqual(
                delivery["parts"],
                [
                    {
                        "filename": archive.name,
                        "sha256": hashlib.sha256(b"1234567").hexdigest(),
                        "size": 7,
                        "index": 1,
                        "count": 1,
                        "signature_bundle": (
                            archive.name + SERVER_PACKAGE.SIGNATURE_SUFFIX
                        ),
                    }
                ],
            )

    def test_split_delivery_has_deterministic_names_order_hashes_and_reassembly(self) -> None:
        payload = b"abcdefghijklm"
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            archive = output / "package.tar.gz"
            archive.write_bytes(payload)
            archive.chmod(0o600)

            with (
                mock.patch.object(SERVER_PACKAGE, "GITHUB_ASSET_LIMIT_BYTES", 8),
                mock.patch.object(SERVER_PACKAGE, "PACKAGE_PART_BYTES", 5),
            ):
                delivery = SERVER_PACKAGE.package_delivery(output, archive)

            self.assertFalse(archive.exists())
            self.assertEqual(delivery["kind"], "split")
            self.assertEqual(
                [part["filename"] for part in delivery["parts"]],
                [
                    "package.tar.gz.part-001-of-003",
                    "package.tar.gz.part-002-of-003",
                    "package.tar.gz.part-003-of-003",
                ],
            )
            self.assertEqual([part["size"] for part in delivery["parts"]], [5, 5, 3])
            reassembled = b""
            for index, part in enumerate(delivery["parts"], start=1):
                path = output / part["filename"]
                content = path.read_bytes()
                reassembled += content
                self.assertEqual(part["index"], index)
                self.assertEqual(part["count"], 3)
                self.assertEqual(part["sha256"], hashlib.sha256(content).hexdigest())
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o444)
            self.assertEqual(reassembled, payload)


class OciExportReceiptTests(unittest.TestCase):
    def _fixture(
        self, parent: Path
    ) -> tuple[Path, dict[str, Path], dict[str, object], dict[str, object]]:
        policy = json.loads(
            (MODULE_PATH.parent / "toolchain.json").read_text(encoding="utf-8")
        )
        producer = {
            "name": policy["tool"],
            "version": policy["version"],
            "platform": "linux/amd64",
            "size": next(
                item["size"]
                for item in policy["archive"]["members"]
                if item["name"] == policy["archive"]["binary_member"]
            ),
            "sha256": policy["archive"]["binary_sha256"],
        }
        archives: dict[str, Path] = {}
        lock: dict[str, object] = {"images": {}}
        records: list[dict[str, object]] = []
        for index, component in enumerate(SERVER_PACKAGE.COMPONENTS, start=1):
            archive = parent / f"{component}.oci.tar"
            archive.write_bytes(f"archive-{component}".encode("ascii"))
            digest = hashlib.sha256(f"manifest-{index}".encode("ascii")).hexdigest()
            repository = f"ghcr.io/example/{component}"
            reference = f"{repository}@sha256:{digest}"
            archives[component] = archive
            lock["images"][component] = {
                "digest": f"sha256:{digest}",
                "reference": reference,
                "repository": repository,
            }
            records.append(
                {
                    "archive": archive.name,
                    "component": component,
                    "reference": reference,
                    "remote_manifest": {
                        "media_type": "application/vnd.oci.image.manifest.v1+json",
                        "sha256": digest,
                        "size": 64,
                    },
                    "repeat_verified": True,
                    "sha256": sha256(archive),
                    "size": archive.stat().st_size,
                }
            )
        receipt_value = {
            "format_version": 1,
            "images": records,
            "producer": producer,
        }
        receipt = parent / SERVER_PACKAGE.OCI_EXPORT_RECEIPT_FILENAME
        receipt.write_bytes(SERVER_PACKAGE.canonical_json(receipt_value))
        return receipt, archives, lock, receipt_value

    def test_receipt_binds_pinned_producer_lock_and_all_archive_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            receipt, archives, lock, value = self._fixture(Path(temporary))

            observed = SERVER_PACKAGE.validate_oci_export_receipt(
                receipt, image_archives=archives, lock=lock
            )

            self.assertEqual(observed, value)
            identities = {
                component: {"manifest_size": 64}
                for component in SERVER_PACKAGE.COMPONENTS
            }
            SERVER_PACKAGE.validate_oci_remote_manifest_sizes(value, identities)
            identities["pwa"]["manifest_size"] = 63
            with self.assertRaises(SERVER_PACKAGE.ServerPackageError):
                SERVER_PACKAGE.validate_oci_remote_manifest_sizes(value, identities)

    def test_receipt_rejects_archive_tampering_after_export(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            receipt, archives, lock, _ = self._fixture(Path(temporary))
            archives["pwa"].write_bytes(b"tampered")

            with self.assertRaisesRegex(
                SERVER_PACKAGE.ServerPackageError,
                "differs from its producer receipt",
            ):
                SERVER_PACKAGE.validate_oci_export_receipt(
                    receipt, image_archives=archives, lock=lock
                )

    def test_receipt_rejects_unverified_repeat_or_registry_index(self) -> None:
        for mutation in ("repeat", "index"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                parent = Path(temporary)
                receipt, archives, lock, value = self._fixture(parent)
                if mutation == "repeat":
                    value["images"][0]["repeat_verified"] = False
                else:
                    value["images"][0]["remote_manifest"]["media_type"] = (
                        "application/vnd.oci.image.index.v1+json"
                    )
                receipt.unlink()
                receipt.write_bytes(SERVER_PACKAGE.canonical_json(value))

                with self.assertRaises(SERVER_PACKAGE.ServerPackageError):
                    SERVER_PACKAGE.validate_oci_export_receipt(
                        receipt, image_archives=archives, lock=lock
                    )


class SpdxValidationTests(unittest.TestCase):
    def _fixture(
        self, parent: Path
    ) -> tuple[dict[str, object], dict[str, object], dict[str, object]]:
        archive = parent / (
            "sub2api-codex-control-server-1.2.3-linux-amd64-online.tar.gz"
        )
        archive.write_bytes(b"server package fixture")
        archive.chmod(0o600)
        lock: dict[str, object] = {"images": {}}
        images = lock["images"]
        assert isinstance(images, dict)
        for component in SERVER_PACKAGE.COMPONENTS:
            filename = f"{component}.spdx.json"
            image_sbom = {
                "packages": [
                    {
                        "name": f"{component}-runtime-dependency",
                        "versionInfo": "1.0.0",
                        "downloadLocation": "NOASSERTION",
                        "filesAnalyzed": False,
                        "licenseConcluded": "NOASSERTION",
                        "licenseDeclared": "NOASSERTION",
                        "copyrightText": "NOASSERTION",
                    }
                ]
            }
            image_sbom_path = parent / filename
            image_sbom_path.write_bytes(SERVER_PACKAGE.canonical_json(image_sbom))
            image_sbom_path.chmod(0o600)
            images[component] = {
                "sbom": SERVER_PACKAGE.file_record(image_sbom_path)
            }
        value = SERVER_PACKAGE.make_package_sbom(
            archive,
            mode="online",
            release="1.2.3",
            source_date_epoch=1_700_000_000,
            lock=lock,
            release_dir=parent,
        )
        return SERVER_PACKAGE.file_record(archive), value, lock

    def _write(self, parent: Path, value: object) -> Path:
        path = parent / "package.spdx.json"
        path.write_bytes(SERVER_PACKAGE.canonical_json(value))
        path.chmod(0o600)
        return path

    def test_root_package_with_dependency_and_exact_relationships_is_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            record, value, lock = self._fixture(parent)
            path = self._write(parent, value)

            self.assertEqual(len(value["packages"]), 4)

            SERVER_PACKAGE.validate_package_sbom(
                path,
                record,
                mode="online",
                release="1.2.3",
            )
            SERVER_PACKAGE.validate_authenticated_package_sbom_dependencies(
                path,
                mode="online",
                control_release_dir=parent,
                lock=lock,
            )

    def test_unrelated_dependency_without_depends_on_relationship_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            record, value, _ = self._fixture(parent)
            relationships = value["relationships"]
            assert isinstance(relationships, list)
            relationships.pop()
            path = self._write(parent, value)

            with self.assertRaises(SERVER_PACKAGE.ServerPackageError):
                SERVER_PACKAGE.validate_package_sbom(
                    path,
                    record,
                    mode="online",
                    release="1.2.3",
                )

    def test_duplicate_root_package_identity_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            record, value, _ = self._fixture(parent)
            packages = value["packages"]
            assert isinstance(packages, list)
            packages.append(dict(packages[0]))
            path = self._write(parent, value)

            with self.assertRaises(SERVER_PACKAGE.ServerPackageError):
                SERVER_PACKAGE.validate_package_sbom(
                    path,
                    record,
                    mode="online",
                    release="1.2.3",
                )


class ArchiveSafetyTests(unittest.TestCase):
    EPOCH = 1_700_000_000
    ROOT = "sub2api-codex-control-server-1.2.3-linux-amd64-online"

    def _record(self, archive: Path) -> dict[str, object]:
        return {
            "filename": f"{self.ROOT}.tar.gz",
            "sha256": sha256(archive),
            "size": archive.stat().st_size,
            "internal_manifest_sha256": "0" * 64,
        }

    def _verify_rejected(self, members: list[dict[str, object]], pattern: str) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            archive = Path(temporary) / f"{self.ROOT}.tar.gz"
            write_ustar_gzip(archive, members, epoch=self.EPOCH)
            with self.assertRaisesRegex(SERVER_PACKAGE.ServerPackageError, pattern):
                SERVER_PACKAGE.verify_package_archive(
                    archive,
                    self._record(archive),
                    mode="online",
                    release_manifest={},
                )

    def test_traversal_member_is_rejected(self) -> None:
        self._verify_rejected(
            [{"name": f"{self.ROOT}/../escape", "content": b"x"}],
            "not canonical and relative",
        )

    def test_symlink_member_is_rejected(self) -> None:
        self._verify_rejected(
            [
                {
                    "name": f"{self.ROOT}/link",
                    "type": tarfile.SYMTYPE,
                    "linkname": "/etc/passwd",
                }
            ],
            "not a regular file",
        )

    def test_hardlink_member_is_rejected(self) -> None:
        self._verify_rejected(
            [
                {
                    "name": f"{self.ROOT}/link",
                    "type": tarfile.LNKTYPE,
                    "linkname": f"{self.ROOT}/target",
                }
            ],
            "not a regular file",
        )

    def test_non_normalized_member_metadata_is_rejected(self) -> None:
        variants = (
            {"mode": 0o644},
            {"uid": 501},
            {"gid": 20},
            {"uname": "root"},
            {"gname": "wheel"},
        )
        for variant in variants:
            with self.subTest(variant=variant):
                self._verify_rejected(
                    [
                        {
                            "name": f"{self.ROOT}/file",
                            "content": b"x",
                            **variant,
                        }
                    ],
                    "metadata is invalid",
                )

    def test_safe_extraction_supports_nested_sibling_directories(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary).resolve()
            archive = parent / f"{self.ROOT}.tar.gz"
            write_ustar_gzip(
                archive,
                [
                    {
                        "name": f"{self.ROOT}/tree/left/value.txt",
                        "content": b"left",
                    },
                    {
                        "name": f"{self.ROOT}/tree/right/value.txt",
                        "content": b"right",
                    },
                ],
                epoch=self.EPOCH,
            )

            extracted = SERVER_PACKAGE.safely_extract_package(
                archive, parent, expected_sha256=sha256(archive)
            )

            self.assertEqual(
                (extracted / "tree/left/value.txt").read_bytes(), b"left"
            )
            self.assertEqual(
                (extracted / "tree/right/value.txt").read_bytes(), b"right"
            )

    def test_safe_extraction_rejects_traversal_and_removes_partial_root(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary).resolve()
            archive = parent / f"{self.ROOT}.tar.gz"
            write_ustar_gzip(
                archive,
                [{"name": f"{self.ROOT}/../escape", "content": b"x"}],
                epoch=self.EPOCH,
            )

            with self.assertRaises(SERVER_PACKAGE.ServerPackageError):
                SERVER_PACKAGE.safely_extract_package(
                    archive, parent, expected_sha256=sha256(archive)
                )

            self.assertFalse((parent / self.ROOT).exists())
            self.assertFalse((parent / "escape").exists())


class CliSmokeTests(unittest.TestCase):
    def test_cli_parser_help_smoke_when_parser_is_available(self) -> None:
        parser_factory = getattr(SERVER_PACKAGE, "build_parser", None)
        if parser_factory is None:
            self.skipTest("server package CLI parser is not implemented yet")
        parser = parser_factory()
        with self.assertRaises(SystemExit) as raised:
            parser.parse_args(["--help"])
        self.assertEqual(raised.exception.code, 0)

    def test_build_requires_the_oci_export_receipt_option(self) -> None:
        parser = SERVER_PACKAGE.build_parser()
        build = next(
            action
            for action in parser._actions
            if action.__class__.__name__ == "_SubParsersAction"
        ).choices["build"]
        option = build._option_string_actions["--oci-export-receipt"]
        self.assertTrue(option.required)

    def test_standalone_verifier_switches_to_extracted_signed_tools(self) -> None:
        original = (
            SERVER_PACKAGE.CONTROL_IMAGES_PATH,
            SERVER_PACKAGE.SOURCE_BUNDLE_PATH,
            SERVER_PACKAGE.OCI_MAPPER_PATH,
            SERVER_PACKAGE.CONNECTOR_RELEASE_TOOL_PATH,
        )
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary).resolve()
            expected = (
                source / "deploy/release/control_images.py",
                source / "deploy/release/source_bundle.py",
                source / "deploy/scripts/map-oci-image-archive.py",
                source / "connector/release/release.py",
            )
            for path in expected:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("# signed fixture\n", encoding="ascii")

            with SERVER_PACKAGE.package_tool_root(source):
                self.assertEqual(
                    (
                        SERVER_PACKAGE.CONTROL_IMAGES_PATH,
                        SERVER_PACKAGE.SOURCE_BUNDLE_PATH,
                        SERVER_PACKAGE.OCI_MAPPER_PATH,
                        SERVER_PACKAGE.CONNECTOR_RELEASE_TOOL_PATH,
                    ),
                    expected,
                )

        self.assertEqual(
            (
                SERVER_PACKAGE.CONTROL_IMAGES_PATH,
                SERVER_PACKAGE.SOURCE_BUNDLE_PATH,
                SERVER_PACKAGE.OCI_MAPPER_PATH,
                SERVER_PACKAGE.CONNECTOR_RELEASE_TOOL_PATH,
            ),
            original,
        )


if __name__ == "__main__":
    unittest.main()
