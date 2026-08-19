from __future__ import annotations

import base64
import copy
import hashlib
import importlib.util
import io
import json
import os
import stat
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("oci_toolchain", ROOT / "oci_toolchain.py")
assert SPEC is not None and SPEC.loader is not None
TOOL = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = TOOL
SPEC.loader.exec_module(TOOL)


class OciToolchainTests(unittest.TestCase):
    def setUp(self) -> None:
        # The toolchain refuses to read or write under a group/other-writable
        # parent, and a shared temporary root such as /tmp is mode 1777, so
        # build these fixtures under the invoking user's home; otherwise that
        # check fires before the behaviour each test is asserting.
        self.temporary = tempfile.TemporaryDirectory(
            dir=Path.home(), prefix=".oci-toolchain-tests."
        )
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        os.chmod(self.root, 0o755)

    @staticmethod
    def sha(raw: bytes) -> str:
        return hashlib.sha256(raw).hexdigest()

    def test_committed_policy_pins_reviewed_crane_release(self) -> None:
        policy = TOOL.load_policy()
        self.assertEqual(policy["version"], "0.21.7")
        self.assertEqual(policy["platform"]["os"], "linux")
        self.assertEqual(policy["platform"]["architecture"], "amd64")
        self.assertEqual(policy["assets"]["archive"]["size"], 16473140)
        self.assertEqual(
            policy["assets"]["archive"]["sha256"],
            "1a57bc98207fa1c0d04bf760699099e26f8383499bfd55b99c1b919a928a7230",
        )
        self.assertEqual(
            policy["assets"]["checksums"]["sha256"],
            "cd15501232e498a51ef7d2d65dd2fb360f9f1086e234acef1af02343cea291f9",
        )
        self.assertEqual(
            policy["assets"]["provenance"]["sha256"],
            "349b91c17e49b1887cadc8eeafa4291a22df5afeb9fc00c271c4a6d138381a9a",
        )

    def test_json_parser_rejects_duplicates_and_nonstandard_numbers(self) -> None:
        with self.assertRaisesRegex(TOOL.ToolchainError, "duplicate key"):
            TOOL.parse_json(b'{"value":1,"value":2}', "fixture")
        with self.assertRaisesRegex(TOOL.ToolchainError, "non-standard"):
            TOOL.parse_json(b'{"value":NaN}', "fixture")

    def minimal_policy(self, binary: bytes) -> dict[str, object]:
        policy = copy.deepcopy(TOOL.load_policy())
        policy["archive"]["members"] = [
            {"name": "crane", "mode": "0755", "size": len(binary)}
        ]
        policy["archive"]["binary_sha256"] = self.sha(binary)
        return policy

    def archive(self, members: list[tuple[str, bytes, int, str]]) -> bytes:
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode="w:gz", format=tarfile.USTAR_FORMAT) as tar:
            for name, content, mode, kind in members:
                info = tarfile.TarInfo(name)
                info.mode = mode
                info.mtime = 0
                if kind == "file":
                    info.size = len(content)
                    tar.addfile(info, io.BytesIO(content))
                elif kind == "symlink":
                    info.type = tarfile.SYMTYPE
                    info.linkname = "crane"
                    tar.addfile(info)
                else:
                    raise AssertionError(kind)
        return output.getvalue()

    def configure_archive(self, policy: dict[str, object], raw: bytes) -> None:
        policy["assets"]["archive"]["size"] = len(raw)
        policy["assets"]["archive"]["sha256"] = self.sha(raw)

    def write_archive(self, raw: bytes) -> Path:
        path = self.root / "archive.tar.gz"
        path.write_bytes(raw)
        return path

    def test_extracts_only_exact_regular_crane_member_without_overwrite(self) -> None:
        binary = b"pinned crane"
        policy = self.minimal_policy(binary)
        raw = self.archive([("crane", binary, 0o755, "file")])
        self.configure_archive(policy, raw)
        destination = self.root / "bin" / "crane"
        destination.parent.mkdir()

        TOOL.extract_crane(self.write_archive(raw), destination, policy)

        self.assertEqual(destination.read_bytes(), binary)
        self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o555)
        with self.assertRaisesRegex(TOOL.ToolchainError, "already exists"):
            TOOL.extract_crane(self.root / "archive.tar.gz", destination, policy)

    def test_crane_binary_requires_exact_read_only_mode(self) -> None:
        crane, policy = self.fake_crane()
        crane.chmod(0o755)
        with self.assertRaisesRegex(TOOL.ToolchainError, "exactly 0555"):
            TOOL.verify_crane_binary(crane, policy)

    def test_archive_rejects_symlinks_and_traversal(self) -> None:
        binary = b"pinned crane"
        for name, kind, message in (
            ("crane", "symlink", "not a regular file"),
            ("../crane", "file", "unsafe member"),
        ):
            with self.subTest(name=name, kind=kind):
                case = self.root / f"case-{kind}"
                case.mkdir()
                policy = self.minimal_policy(binary)
                policy["archive"]["members"][0]["name"] = name
                policy["archive"]["binary_member"] = name
                raw = self.archive([(name, binary, 0o755, kind)])
                self.configure_archive(policy, raw)
                archive = case / "archive.tar.gz"
                archive.write_bytes(raw)
                with self.assertRaisesRegex(TOOL.ToolchainError, message):
                    TOOL.extract_crane(archive, case / "crane", policy)

    def test_archive_rejects_unexpected_and_duplicate_members(self) -> None:
        binary = b"pinned crane"
        policy = self.minimal_policy(binary)
        for members, message in (
            (
                [("crane", binary, 0o755, "file"), ("extra", b"x", 0o644, "file")],
                "inventory differs",
            ),
            (
                [("crane", binary, 0o755, "file"), ("crane", binary, 0o755, "file")],
                "repeats member",
            ),
        ):
            with self.subTest(message=message):
                raw = self.archive(members)
                self.configure_archive(policy, raw)
                archive = self.root / f"{self.sha(raw)}.tar.gz"
                archive.write_bytes(raw)
                with self.assertRaisesRegex(TOOL.ToolchainError, message):
                    TOOL.extract_crane(archive, self.root / f"out-{self.sha(raw)}", policy)

    def make_evidence(self) -> tuple[Path, dict[str, object]]:
        binary = b"pinned crane"
        policy = self.minimal_policy(binary)
        raw_archive = self.archive([("crane", binary, 0o755, "file")])
        archive_asset = policy["assets"]["archive"]
        archive_asset["size"] = len(raw_archive)
        archive_asset["sha256"] = self.sha(raw_archive)
        checksums = (
            f"{self.sha(raw_archive)}  {archive_asset['filename']}\n".encode("utf-8")
        )
        statement = {
            "_type": policy["provenance"]["statement_type"],
            "subject": [
                {
                    "name": archive_asset["filename"],
                    "digest": {"sha256": self.sha(raw_archive)},
                }
            ],
            "predicateType": policy["provenance"]["predicate_type"],
            "predicate": {},
        }
        provenance = json.dumps(
            {
                "mediaType": policy["provenance"]["media_type"],
                "verificationMaterial": {},
                "dsseEnvelope": {
                    "payload": base64.b64encode(
                        json.dumps(statement, separators=(",", ":")).encode("utf-8")
                    ).decode("ascii"),
                    "payloadType": policy["provenance"]["payload_type"],
                    "signatures": [{"sig": "evidence"}],
                },
            },
            separators=(",", ":"),
        ).encode("utf-8")
        for role, raw in (
            ("archive", raw_archive),
            ("checksums", checksums),
            ("provenance", provenance),
        ):
            asset = policy["assets"][role]
            asset["size"] = len(raw)
            asset["sha256"] = self.sha(raw)
            (self.root / asset["filename"]).write_bytes(raw)
        return self.root, policy

    def test_verifies_all_three_evidence_files_and_subject_bindings(self) -> None:
        directory, policy = self.make_evidence()
        paths = TOOL.verify_evidence(directory, policy)
        self.assertEqual(set(paths), {"archive", "checksums", "provenance"})

        checksums = paths["checksums"]
        checksums.write_text("0" * 64 + "  wrong.tar.gz\n", encoding="utf-8")
        policy["assets"]["checksums"]["size"] = checksums.stat().st_size
        policy["assets"]["checksums"]["sha256"] = hashlib.sha256(
            checksums.read_bytes()
        ).hexdigest()
        with self.assertRaisesRegex(TOOL.ToolchainError, "does not bind"):
            TOOL.verify_evidence(directory, policy)

    def fake_crane(self) -> tuple[Path, dict[str, object]]:
        binary = b"fake pinned crane"
        policy = self.minimal_policy(binary)
        crane = self.root / "crane"
        crane.write_bytes(binary)
        crane.chmod(0o555)
        return crane, policy

    def write_layout(self, path: Path, payload: bytes) -> None:
        digest = hashlib.sha256(payload).hexdigest()
        blob_directory = path / "blobs/sha256"
        blob_directory.mkdir(parents=True)
        (path / "oci-layout").write_text(
            '{"imageLayoutVersion":"1.0.0"}\n', encoding="utf-8"
        )
        (path / "index.json").write_text(
            json.dumps(
                {
                    "schemaVersion": 2,
                    "mediaType": "application/vnd.oci.image.index.v1+json",
                    "manifests": [
                        {
                            "mediaType": "application/vnd.oci.image.manifest.v1+json",
                            "digest": f"sha256:{digest}",
                            "size": len(payload),
                        }
                    ],
                },
                separators=(",", ":"),
            )
            + "\n",
            encoding="utf-8",
        )
        (blob_directory / digest).write_bytes(payload)

    def test_layout_rejects_links_and_extra_root_entries(self) -> None:
        layout = self.root / "linked-layout"
        self.write_layout(layout, b"manifest")
        blob = next((layout / "blobs/sha256").iterdir())
        blob.unlink()
        blob.symlink_to(layout / "index.json")
        with self.assertRaisesRegex(TOOL.ToolchainError, "symbolic link"):
            TOOL.scan_oci_layout(layout)

        other = self.root / "extra-layout"
        self.write_layout(other, b"manifest")
        (other / "unexpected").write_text("no\n", encoding="utf-8")
        with self.assertRaisesRegex(TOOL.ToolchainError, "root inventory"):
            TOOL.scan_oci_layout(other)

    def manifest_fixtures(self) -> tuple[dict[str, str], dict[str, bytes]]:
        references: dict[str, str] = {}
        manifests: dict[str, bytes] = {}
        for component in TOOL.COMPONENTS:
            raw = json.dumps(
                {
                    "schemaVersion": 2,
                    "mediaType": "application/vnd.oci.image.manifest.v1+json",
                    "config": {
                        "mediaType": "application/vnd.oci.image.config.v1+json",
                        "digest": f"sha256:{'0' * 64}",
                        "size": 2,
                    },
                    "layers": [],
                },
                separators=(",", ":"),
            ).encode("utf-8")
            reference = f"ghcr.io/owner/{component}@sha256:{self.sha(raw)}"
            references[component] = reference
            manifests[reference] = raw
        return references, manifests

    @mock.patch.object(TOOL.platform, "system", return_value="Linux")
    @mock.patch.object(TOOL.platform, "machine", return_value="x86_64")
    def test_export_uses_exact_command_and_repeats_each_archive(
        self, _machine: mock.Mock, _system: mock.Mock
    ) -> None:
        crane, policy = self.fake_crane()
        references, manifests = self.manifest_fixtures()
        commands: list[list[str]] = []

        def runner(command: list[str], **kwargs: object) -> SimpleNamespace:
            commands.append(command)
            if command[1] == "manifest":
                kwargs["stdout"].write(manifests[command[-1]])
            else:
                self.write_layout(Path(command[-1]), manifests[command[-2]])
            return SimpleNamespace(returncode=0)

        output = self.root / "images"
        receipt = TOOL.export_images(
            crane,
            output,
            references,
            policy,
            timeout_seconds=60,
            runner=runner,
        )

        self.assertEqual(len(commands), 9)
        pull_commands = [command for command in commands if command[1] == "pull"]
        for component_index, component in enumerate(TOOL.COMPONENTS):
            first, repeated = pull_commands[
                component_index * 2 : component_index * 2 + 2
            ]
            prefix = [
                os.fspath(crane),
                "pull",
                "--platform",
                "linux/amd64",
                "--format=oci",
                "--annotate-ref",
                references[component],
            ]
            self.assertEqual(first[:-1], prefix)
            self.assertEqual(repeated[:-1], prefix)
        self.assertEqual(
            {path.name for path in output.iterdir()}, set(TOOL.ARCHIVE_NAMES.values())
        )
        self.assertTrue(all(item["repeat_verified"] for item in receipt["images"]))
        self.assertTrue(
            all(
                item["remote_manifest"]["sha256"]
                == item["reference"].rsplit("@sha256:", 1)[1]
                for item in receipt["images"]
            )
        )
        for archive_path in output.iterdir():
            with tarfile.open(archive_path, "r:") as archive:
                self.assertEqual(
                    {member.name.rstrip("/") for member in archive.getmembers()},
                    {
                        "blobs",
                        "blobs/sha256",
                        "index.json",
                        "oci-layout",
                        next(
                            member.name
                            for member in archive.getmembers()
                            if member.name.startswith("blobs/sha256/")
                        ),
                    },
                )
                for member in archive.getmembers():
                    self.assertEqual(member.uid, 0)
                    self.assertEqual(member.gid, 0)
                    self.assertEqual(member.mtime, 0)

    @mock.patch.object(TOOL.platform, "system", return_value="Linux")
    @mock.patch.object(TOOL.platform, "machine", return_value="x86_64")
    def test_export_fails_if_repeated_bytes_differ(
        self, _machine: mock.Mock, _system: mock.Mock
    ) -> None:
        crane, policy = self.fake_crane()
        references, manifests = self.manifest_fixtures()
        invocation = 0

        def runner(command: list[str], **kwargs: object) -> SimpleNamespace:
            nonlocal invocation
            if command[1] == "manifest":
                kwargs["stdout"].write(manifests[command[-1]])
                return SimpleNamespace(returncode=0)
            invocation += 1
            self.write_layout(
                Path(command[-1]), f"attempt {invocation}".encode("ascii")
            )
            return SimpleNamespace(returncode=0)

        with self.assertRaisesRegex(TOOL.ToolchainError, "not byte-for-byte"):
            TOOL.export_images(
                crane,
                self.root / "images",
                references,
                policy,
                timeout_seconds=60,
                runner=runner,
            )
        self.assertFalse((self.root / "images").exists())
        self.assertFalse(
            any(path.name.startswith(".images.") for path in self.root.iterdir())
        )

    def test_remote_top_level_index_is_rejected_even_when_digest_matches(self) -> None:
        crane, _policy = self.fake_crane()
        raw = json.dumps(
            {
                "schemaVersion": 2,
                "mediaType": "application/vnd.oci.image.index.v1+json",
                "manifests": [],
            },
            separators=(",", ":"),
        ).encode("utf-8")
        reference = f"ghcr.io/owner/api@sha256:{self.sha(raw)}"

        def runner(_command: list[str], **kwargs: object) -> SimpleNamespace:
            kwargs["stdout"].write(raw)
            return SimpleNamespace(returncode=0)

        with self.assertRaisesRegex(TOOL.ToolchainError, "top-level index"):
            TOOL.inspect_remote_manifest(
                crane,
                reference,
                self.root / "manifest.json",
                60,
                runner,
                _policy,
            )

    def test_digest_references_and_exact_component_set_are_required(self) -> None:
        digest = "a" * 64
        values = [
            f"control-api=ghcr.io/owner/api@sha256:{digest}",
            f"pwa=ghcr.io/owner/pwa@sha256:{digest}",
            f"postgres-tools=ghcr.io/owner/tools@sha256:{digest}",
        ]
        self.assertEqual(set(TOOL.parse_image_specs(values)), set(TOOL.COMPONENTS))
        values[0] = "control-api=ghcr.io/owner/api:latest"
        with self.assertRaisesRegex(TOOL.ToolchainError, "not an exact digest"):
            TOOL.parse_image_specs(values)

    def test_output_directory_must_not_exist(self) -> None:
        output = self.root / "images"
        output.mkdir()
        with self.assertRaisesRegex(TOOL.ToolchainError, "already exists"):
            TOOL.prepare_output_destination(output)


if __name__ == "__main__":
    unittest.main()
