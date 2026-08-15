from __future__ import annotations

import argparse
import hashlib
import importlib.util
import io
import json
import os
import stat
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path, PurePosixPath
from unittest import mock

SCRIPT = Path(__file__).parents[1] / "build-image-rollout-tools.py"
SPEC = importlib.util.spec_from_file_location("build_image_rollout_tools", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
TOOLS = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = TOOLS
SPEC.loader.exec_module(TOOLS)

EPOCH = 1_786_540_876


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def make_writable(root: Path) -> None:
    if not root.exists() or root.is_symlink():
        return
    for path in sorted(root.rglob("*"), key=lambda item: len(item.parts), reverse=True):
        if path.is_symlink():
            continue
        try:
            path.chmod(0o700 if path.is_dir() else 0o600)
        except OSError:
            pass
    try:
        root.chmod(0o700)
    except OSError:
        pass


class IsolatedToolsFixture:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.inputs = root / "isolated-inputs"
        self.output_one = root / "output-one" / TOOLS.ARCHIVE_BASENAME
        self.output_two = root / "output-two" / TOOLS.ARCHIVE_BASENAME
        self.inputs.mkdir()
        self.output_one.parent.mkdir()
        self.output_two.parent.mkdir()
        self.output_one.parent.chmod(0o700)
        self.output_two.parent.chmod(0o700)
        self.paths: dict[str, Path] = {}
        self.contents: dict[str, bytes] = {}
        for index, relative in enumerate(TOOLS.TOOL_MEMBERS, start=1):
            basename = PurePosixPath(relative).name
            raw = (
                f"isolated fixture {index}: {basename}\n"
                f"not bytes from the repository input\n"
            ).encode("ascii")
            path = self.inputs / basename
            path.write_bytes(raw)
            path.chmod(0o600)
            self.paths[relative] = path
            self.contents[relative] = raw

    def build_args(self, output: Path | None = None) -> argparse.Namespace:
        by_argument = {
            argument: self.paths[relative]
            for relative, (argument, _) in TOOLS.TOOL_MEMBERS.items()
        }
        return argparse.Namespace(
            **by_argument,
            source_date_epoch=EPOCH,
            output=output or self.output_one,
        )

    def build(self, output: Path | None = None) -> tuple[dict[str, object], bytes]:
        selected = output or self.output_one
        result = TOOLS.build_bundle(self.build_args(selected))
        return result, selected.read_bytes()

    def payloads(self) -> tuple[dict[str, bytes], bytes]:
        _, manifest_raw = TOOLS.build_manifest(self.contents)
        return dict(self.contents), manifest_raw


class ToolsBundleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.fixture = IsolatedToolsFixture(self.root)

    def tearDown(self) -> None:
        make_writable(self.root)
        self.temporary.cleanup()

    def alternative_archive(
        self,
        *,
        names: list[str] | None = None,
        payloads: dict[str, bytes] | None = None,
        archive_format: int = tarfile.USTAR_FORMAT,
        mutate: object | None = None,
    ) -> bytes:
        tool_payloads, manifest_raw = self.fixture.payloads()
        all_payloads = {**tool_payloads, TOOLS.MANIFEST_BASENAME: manifest_raw}
        if payloads is not None:
            all_payloads.update(payloads)
        selected = names or list(TOOLS.ARCHIVE_MEMBER_ORDER)
        output = io.BytesIO()
        with tarfile.open(
            fileobj=output, mode="w:", format=archive_format
        ) as archive:
            for name in selected:
                is_directory = name in TOOLS.DIRECTORY_MEMBERS
                if name not in TOOLS.DIRECTORY_MEMBERS and name not in TOOLS.ARCHIVE_MEMBER_MODES:
                    info = tarfile.TarInfo(name)
                    info.mode = 0o444
                    info.uid = info.gid = 0
                    info.uname = info.gname = "root"
                    info.mtime = EPOCH
                    raw = b"unexpected\n"
                    info.size = len(raw)
                else:
                    mode = int(
                        (
                            TOOLS.DIRECTORY_MEMBERS
                            if is_directory
                            else TOOLS.ARCHIVE_MEMBER_MODES
                        )[name],
                        8,
                    )
                    raw = b"" if is_directory else all_payloads[name]
                    info = TOOLS._tar_info(
                        name,
                        mode,
                        EPOCH,
                        is_directory=is_directory,
                        size=len(raw),
                    )
                if mutate is not None:
                    mutate(name, info)
                archive.addfile(info, None if info.isdir() else io.BytesIO(raw))
        return output.getvalue()

    def verify_raw(self, raw: bytes, **kwargs: object) -> object:
        return TOOLS.verify_archive_bytes(
            raw,
            expected_archive_sha256=digest(raw),
            epoch=EPOCH,
            **kwargs,
        )

    def test_build_is_deterministic_and_uses_only_isolated_fixture_bytes(self) -> None:
        first_result, first = self.fixture.build(self.fixture.output_one)
        for index, path in enumerate(self.fixture.paths.values(), start=1):
            os.utime(path, (EPOCH + index * 100, EPOCH + index * 100))
            path.chmod(0o644 if index % 2 else 0o400)
        second_result, second = self.fixture.build(self.fixture.output_two)
        self.assertEqual(first, second)
        self.assertEqual(first_result["archive"], second_result["archive"])
        self.assertEqual(first_result["tooling_identity"], second_result["tooling_identity"])
        self.assertEqual(first_result["archive"]["sha256"], digest(first))
        self.assertNotIn(SCRIPT.read_bytes(), self.fixture.contents.values())
        for relative, raw in self.fixture.contents.items():
            self.assertIn(PurePosixPath(relative).name.encode("ascii"), first)
            self.assertIn(raw, first)

    def test_manifest_exact_shape_identity_and_canonical_encoding(self) -> None:
        manifest, raw = TOOLS.build_manifest(self.fixture.contents)
        self.assertEqual(
            set(manifest),
            {"files", "identity_sha256", "schema_version", "type"},
        )
        self.assertEqual(set(manifest["files"]), set(TOOLS.TOOL_MEMBERS))
        self.assertEqual(manifest["schema_version"], 1)
        self.assertEqual(manifest["type"], "image-rollout-tools-manifest-v1")
        projected = manifest["files"]
        self.assertEqual(
            manifest["identity_sha256"],
            digest(TOOLS.canonical_json(projected, newline=False)),
        )
        self.assertEqual(raw, TOOLS.canonical_json(manifest))
        self.assertEqual(TOOLS.parse_manifest(raw), manifest)
        for relative, raw_file in self.fixture.contents.items():
            self.assertEqual(
                projected[relative],
                {
                    "mode": TOOLS.TOOL_MEMBERS[relative][1],
                    "sha256": digest(raw_file),
                    "size": len(raw_file),
                },
            )

    def test_archive_is_exact_canonical_uncompressed_ustar(self) -> None:
        result, raw = self.fixture.build()
        self.assertEqual(raw[257:263], b"ustar\x00")
        self.assertNotEqual(raw[:2], b"\x1f\x8b")
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as archive:
            members = archive.getmembers()
            self.assertEqual(
                [member.name for member in members], list(TOOLS.ARCHIVE_MEMBER_ORDER)
            )
            for member in members:
                is_directory = member.name in TOOLS.DIRECTORY_MEMBERS
                expected_mode = int(
                    (
                        TOOLS.DIRECTORY_MEMBERS
                        if is_directory
                        else TOOLS.ARCHIVE_MEMBER_MODES
                    )[member.name],
                    8,
                )
                self.assertEqual(member.type, tarfile.DIRTYPE if is_directory else tarfile.REGTYPE)
                self.assertEqual(stat.S_IMODE(member.mode), expected_mode)
                self.assertEqual((member.uid, member.gid), (0, 0))
                self.assertEqual((member.uname, member.gname), ("root", "root"))
                self.assertEqual(member.mtime, EPOCH)
                self.assertEqual(member.pax_headers, {})
        verified = self.verify_raw(raw)
        self.assertEqual(verified.manifest["identity_sha256"], result["tooling_identity"])
        self.assertEqual(verified.files, self.fixture.contents)

    def test_build_rejects_wrong_basename_symlink_ancestor_hardlink_and_existing_output(self) -> None:
        baseline = self.fixture.build_args()
        cases: list[tuple[str, argparse.Namespace, str]] = []

        wrong = self.root / "wrong.py"
        wrong.write_bytes(b"wrong basename\n")
        wrong_args = self.fixture.build_args(self.fixture.output_one)
        wrong_args.admission_helper = wrong
        cases.append(("wrong basename", wrong_args, "unexpected basename"))

        symlink = self.root / "image-rollout-smoke.py"
        symlink.symlink_to(self.fixture.paths["deploy/scripts/image-rollout-smoke.py"])
        symlink_args = self.fixture.build_args(self.fixture.output_one)
        symlink_args.smoke_helper = symlink
        cases.append(("symlink", symlink_args, "symlink"))

        linked_directory = self.root / "linked-inputs"
        linked_directory.symlink_to(self.fixture.inputs, target_is_directory=True)
        ancestor_args = self.fixture.build_args(self.fixture.output_one)
        ancestor_args.wrapper = linked_directory / "rollout-bootstrap-images.sh"
        cases.append(("ancestor symlink", ancestor_args, "symlink ancestor"))

        for name, args, message in cases:
            with self.subTest(name=name), self.assertRaisesRegex(
                TOOLS.ToolsBundleError, message
            ):
                TOOLS.build_bundle(args)
            self.assertFalse(self.fixture.output_one.exists())

        hardlink = self.root / "image-rollout-admission.py"
        os.link(self.fixture.paths["deploy/scripts/image-rollout-admission.py"], hardlink)
        hardlink_args = self.fixture.build_args(self.fixture.output_one)
        hardlink_args.admission_helper = hardlink
        with self.assertRaisesRegex(TOOLS.ToolsBundleError, "singly-linked"):
            TOOLS.build_bundle(hardlink_args)
        self.assertFalse(self.fixture.output_one.exists())
        hardlink.unlink()

        sentinel = b"do not replace\n"
        self.fixture.output_one.write_bytes(sentinel)
        with self.assertRaisesRegex(TOOLS.ToolsBundleError, "already exists"):
            TOOLS.build_bundle(baseline)
        self.assertEqual(self.fixture.output_one.read_bytes(), sentinel)

        self.fixture.output_one.unlink()
        victim = self.root / "victim"
        victim.write_bytes(sentinel)
        self.fixture.output_one.symlink_to(victim)
        with self.assertRaisesRegex(TOOLS.ToolsBundleError, "already exists"):
            TOOLS.build_bundle(baseline)
        self.assertTrue(self.fixture.output_one.is_symlink())
        self.assertEqual(victim.read_bytes(), sentinel)

    def test_build_requires_private_output_parent_and_cleans_failed_publication(self) -> None:
        public = self.root / "public-output"
        public.mkdir(mode=0o755)
        target = public / TOOLS.ARCHIVE_BASENAME
        with self.assertRaisesRegex(TOOLS.ToolsBundleError, "mode 0700"):
            TOOLS.build_bundle(self.fixture.build_args(target))
        self.assertFalse(target.exists())

        failed = self.root / "failed-output"
        failed.mkdir(mode=0o700)
        failed_target = failed / TOOLS.ARCHIVE_BASENAME
        original = TOOLS.verify_archive_file
        calls = 0

        def fail_second_verify(*args: object, **kwargs: object) -> object:
            nonlocal calls
            calls += 1
            if calls == 1:
                raise TOOLS.ToolsBundleError("injected publication verification failure")
            return original(*args, **kwargs)

        with mock.patch.object(
            TOOLS,
            "verify_archive_file",
            side_effect=fail_second_verify,
        ), self.assertRaisesRegex(TOOLS.ToolsBundleError, "injected"):
            TOOLS.build_bundle(self.fixture.build_args(failed_target))
        self.assertFalse(failed_target.exists())

    def test_verify_requires_out_of_band_archive_identity_and_epoch(self) -> None:
        result, raw = self.fixture.build()
        with self.assertRaisesRegex(TOOLS.ToolsBundleError, "out-of-band digest"):
            TOOLS.verify_archive_bytes(
                raw,
                expected_archive_sha256="0" * 64,
                epoch=EPOCH,
            )
        with self.assertRaisesRegex(TOOLS.ToolsBundleError, "tools identity"):
            self.verify_raw(raw, expected_identity_sha256="0" * 64)
        with self.assertRaisesRegex(TOOLS.ToolsBundleError, "metadata"):
            TOOLS.verify_archive_bytes(
                raw,
                expected_archive_sha256=result["archive"]["sha256"],
                epoch=EPOCH + 1,
            )
        with self.assertRaisesRegex(TOOLS.ToolsBundleError, "lowercase SHA-256"):
            TOOLS.verify_archive_bytes(raw, expected_archive_sha256="ABC", epoch=EPOCH)

    def test_verify_rejects_member_set_order_duplicates_and_traversal(self) -> None:
        original = list(TOOLS.ARCHIVE_MEMBER_ORDER)
        cases = {
            "missing": original[:-1],
            "extra": [*original, "unexpected"],
            "duplicate": [*original, original[-1]],
            "reverse": list(reversed(original)),
            "absolute": [*original[:-1], "/absolute"],
            "traversal": [*original[:-1], "../escape"],
        }
        for name, members in cases.items():
            raw = self.alternative_archive(names=members)
            with self.subTest(name=name), self.assertRaisesRegex(
                TOOLS.ToolsBundleError, "member set or order"
            ):
                self.verify_raw(raw)

    def test_verify_rejects_each_noncanonical_member_metadata_field(self) -> None:
        target = "deploy/scripts/image-rollout-smoke.py"

        def mutation(attribute: str, value: object):
            def mutate(name: str, info: tarfile.TarInfo) -> None:
                if name == target:
                    setattr(info, attribute, value)

            return mutate

        cases = {
            "mode": mutation("mode", 0o755),
            "uid": mutation("uid", 1),
            "gid": mutation("gid", 1),
            "uname": mutation("uname", "operator"),
            "gname": mutation("gname", "operator"),
            "mtime": mutation("mtime", EPOCH + 1),
            "linkname": mutation("linkname", "unexpected"),
        }
        for name, mutate in cases.items():
            raw = self.alternative_archive(mutate=mutate)
            with self.subTest(name=name), self.assertRaisesRegex(
                TOOLS.ToolsBundleError, "metadata"
            ):
                self.verify_raw(raw)

    def test_verify_rejects_special_member_types(self) -> None:
        target = "deploy/scripts/image-rollout-smoke.py"
        for name, member_type in {
            "symlink": tarfile.SYMTYPE,
            "hardlink": tarfile.LNKTYPE,
            "fifo": tarfile.FIFOTYPE,
            "character": tarfile.CHRTYPE,
            "block": tarfile.BLKTYPE,
        }.items():
            def mutate(
                member_name: str,
                info: tarfile.TarInfo,
                selected_type: bytes = member_type,
            ) -> None:
                if member_name == target:
                    info.type = selected_type
                    info.size = 0
                    info.linkname = (
                        "target"
                        if selected_type in {tarfile.SYMTYPE, tarfile.LNKTYPE}
                        else ""
                    )

            raw = self.alternative_archive(mutate=mutate)
            with self.subTest(name=name), self.assertRaisesRegex(
                TOOLS.ToolsBundleError, "metadata"
            ):
                self.verify_raw(raw)

    def test_verify_rejects_non_ustar_compression_pax_and_noncanonical_padding(self) -> None:
        valid = self.alternative_archive()
        variants: dict[str, bytes] = {
            "gnu": self.alternative_archive(archive_format=tarfile.GNU_FORMAT),
            "trailing blocks": valid + b"\0" * 512,
        }

        payloads, manifest_raw = self.fixture.payloads()
        compressed = io.BytesIO()
        with tarfile.open(fileobj=compressed, mode="w:gz", format=tarfile.USTAR_FORMAT) as archive:
            all_payloads = {**payloads, TOOLS.MANIFEST_BASENAME: manifest_raw}
            for member_name in TOOLS.ARCHIVE_MEMBER_ORDER:
                is_directory = member_name in TOOLS.DIRECTORY_MEMBERS
                raw = b"" if is_directory else all_payloads[member_name]
                mode = int(
                    (
                        TOOLS.DIRECTORY_MEMBERS
                        if is_directory
                        else TOOLS.ARCHIVE_MEMBER_MODES
                    )[member_name],
                    8,
                )
                info = TOOLS._tar_info(
                    member_name,
                    mode,
                    EPOCH,
                    is_directory=is_directory,
                    size=len(raw),
                )
                archive.addfile(info, None if is_directory else io.BytesIO(raw))
        variants["gzip"] = compressed.getvalue()

        def add_pax(name: str, info: tarfile.TarInfo) -> None:
            if name == "deploy/scripts/image-rollout-smoke.py":
                info.pax_headers = {"comment": "not canonical"}

        variants["pax"] = self.alternative_archive(
            archive_format=tarfile.PAX_FORMAT, mutate=add_pax
        )
        for name, raw in variants.items():
            with self.subTest(name=name), self.assertRaises(TOOLS.ToolsBundleError):
                self.verify_raw(raw)

    def test_verify_rejects_manifest_byte_and_descriptor_tampering(self) -> None:
        manifest, manifest_raw = TOOLS.build_manifest(self.fixture.contents)
        target = "deploy/scripts/image-rollout-smoke.py"
        variants: dict[str, bytes] = {}

        changed = json.loads(manifest_raw)
        changed["files"][target]["sha256"] = "0" * 64
        changed["identity_sha256"] = digest(
            TOOLS.canonical_json(changed["files"], newline=False)
        )
        variants["descriptor hash"] = TOOLS.canonical_json(changed)

        pretty = json.dumps(manifest, indent=2, sort_keys=True).encode("ascii") + b"\n"
        variants["noncanonical JSON"] = pretty

        extra = dict(manifest)
        extra["private_path"] = "/secret/operator/path"
        variants["extra key"] = TOOLS.canonical_json(extra)

        duplicate = manifest_raw.replace(
            b'"schema_version":1',
            b'"schema_version":1,"schema_version":1',
            1,
        )
        variants["duplicate key"] = duplicate

        bad_mode = json.loads(manifest_raw)
        bad_mode["files"][target]["mode"] = "0777"
        bad_mode["identity_sha256"] = digest(
            TOOLS.canonical_json(bad_mode["files"], newline=False)
        )
        variants["bad mode"] = TOOLS.canonical_json(bad_mode)

        for name, changed_manifest in variants.items():
            raw = self.alternative_archive(
                payloads={TOOLS.MANIFEST_BASENAME: changed_manifest}
            )
            with self.subTest(name=name), self.assertRaises(TOOLS.ToolsBundleError):
                self.verify_raw(raw)

    def test_verify_rejects_changed_tool_bytes_even_with_valid_tar_hash(self) -> None:
        target = "deploy/scripts/image-rollout-smoke.py"
        raw = self.alternative_archive(payloads={target: b"tampered tool bytes\n"})
        with self.assertRaisesRegex(TOOLS.ToolsBundleError, "differ from the manifest"):
            self.verify_raw(raw)

    def test_verify_archive_input_rejects_symlink_hardlink_and_oversize(self) -> None:
        result, raw = self.fixture.build()
        original = self.fixture.output_one
        original.chmod(0o600)
        alias = self.root / "alias.tar"
        alias.symlink_to(original)
        linked = self.root / "linked.tar"
        os.link(original, linked)
        for name, path in {"symlink": alias, "hardlink": linked}.items():
            with self.subTest(name=name), self.assertRaises(TOOLS.ToolsBundleError):
                TOOLS.verify_archive_file(
                    path,
                    expected_archive_sha256=result["archive"]["sha256"],
                    epoch=EPOCH,
                )
        original.unlink()
        linked.unlink()
        huge = self.root / TOOLS.ARCHIVE_BASENAME
        with huge.open("wb") as handle:
            handle.truncate(TOOLS.MAX_ARCHIVE_BYTES + 1)
        with self.assertRaisesRegex(TOOLS.ToolsBundleError, "bounded"):
            TOOLS.verify_archive_file(
                huge,
                expected_archive_sha256=digest(raw),
                epoch=EPOCH,
            )

    def test_verify_has_no_extraction_side_effects(self) -> None:
        result, _ = self.fixture.build()
        before = sorted(path.relative_to(self.root) for path in self.root.rglob("*"))
        TOOLS.verify_bundle(
            argparse.Namespace(
                archive=self.fixture.output_one,
                expected_archive_sha256=result["archive"]["sha256"],
                expected_identity_sha256=result["tooling_identity"],
                source_date_epoch=EPOCH,
            )
        )
        after = sorted(path.relative_to(self.root) for path in self.root.rglob("*"))
        self.assertEqual(before, after)

    def test_privacy_safe_success_and_failure_output(self) -> None:
        secret = "PRIVATE-OPERATOR-SENTINEL"
        secret_root = self.root / secret
        secret_root.mkdir()
        secret_root.chmod(0o700)
        fixture = IsolatedToolsFixture(secret_root)
        result, _ = fixture.build()
        rendered = TOOLS.canonical_json(result).decode("ascii")
        self.assertNotIn(secret, rendered)
        self.assertNotIn(str(self.root), rendered)
        self.assertEqual(result["archive"]["basename"], TOOLS.ARCHIVE_BASENAME)
        self.assertEqual(result["manifest"]["basename"], TOOLS.MANIFEST_BASENAME)
        self.assertEqual(
            result["external_verifier"]["basename"], TOOLS.VERIFIER_BASENAME
        )
        self.assertEqual(
            result["self_sha256"], result["external_verifier"]["sha256"]
        )

        missing = secret_root / "missing" / TOOLS.ARCHIVE_BASENAME
        process = subprocess.run(
            [
                sys.executable,
                "-B",
                str(SCRIPT),
                "verify",
                "--archive",
                str(missing),
                "--expected-archive-sha256",
                "0" * 64,
                "--source-date-epoch",
                str(EPOCH),
            ],
            capture_output=True,
            check=False,
            env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
        )
        self.assertNotEqual(process.returncode, 0)
        self.assertEqual(process.stdout, b"")
        self.assertNotIn(secret.encode("ascii"), process.stderr)
        self.assertNotIn(str(self.root).encode(), process.stderr)

        for name, arguments in {
            "unknown": ["--unexpected-secret-option", secret],
            "epoch": [
                "verify",
                "--archive",
                str(missing),
                "--expected-archive-sha256",
                "0" * 64,
                "--source-date-epoch",
                secret,
            ],
        }.items():
            invalid = subprocess.run(
                [sys.executable, "-B", str(SCRIPT), *arguments],
                capture_output=True,
                check=False,
                env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
            )
            with self.subTest(name=name):
                self.assertEqual(invalid.returncode, 2)
                self.assertEqual(invalid.stdout, b"")
                self.assertNotIn(secret.encode("ascii"), invalid.stderr)
                self.assertNotIn(str(self.root).encode(), invalid.stderr)

    def test_internal_install_is_closed_root_safe_and_exact_for_current_owner(self) -> None:
        _, raw = self.fixture.build()
        verified = self.verify_raw(raw)
        destination = self.root / "installed-tools"
        owner = os.geteuid()
        TOOLS.install_verified_bundle(verified, destination, owner_uid=owner)
        TOOLS.verify_installed_bundle(verified, destination, owner_uid=owner)
        self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o555)
        expected_files = {**verified.files, TOOLS.MANIFEST_BASENAME: verified.manifest_raw}
        for name, expected in expected_files.items():
            path = destination / name
            self.assertEqual(path.read_bytes(), expected)
            self.assertEqual(
                stat.S_IMODE(path.stat().st_mode),
                int(TOOLS.ARCHIVE_MEMBER_MODES[name], 8),
            )
        for name in TOOLS.DIRECTORY_MEMBERS:
            self.assertEqual(stat.S_IMODE((destination / name).stat().st_mode), 0o555)

    def test_install_never_replaces_existing_file_directory_or_symlink(self) -> None:
        _, raw = self.fixture.build()
        verified = self.verify_raw(raw)
        sentinel = self.root / "sentinel"
        sentinel.write_bytes(b"preserve me\n")
        for kind in ("file", "directory", "symlink"):
            destination = self.root / f"existing-{kind}"
            if kind == "file":
                destination.write_bytes(b"existing\n")
            elif kind == "directory":
                destination.mkdir()
                (destination / "marker").write_bytes(b"existing\n")
            else:
                destination.symlink_to(sentinel)
            with self.subTest(kind=kind), self.assertRaisesRegex(
                TOOLS.ToolsBundleError, "already exists"
            ):
                TOOLS.install_verified_bundle(
                    verified, destination, owner_uid=os.geteuid()
                )
            if kind == "file":
                self.assertEqual(destination.read_bytes(), b"existing\n")
            elif kind == "directory":
                self.assertEqual((destination / "marker").read_bytes(), b"existing\n")
            else:
                self.assertTrue(destination.is_symlink())
                self.assertEqual(sentinel.read_bytes(), b"preserve me\n")

    def test_install_cleans_its_partial_private_destination_on_failure(self) -> None:
        _, raw = self.fixture.build()
        verified = self.verify_raw(raw)
        destination = self.root / "partial-install"
        original = TOOLS._write_all
        calls = 0

        def fail_after_one(descriptor: int, content: bytes, label: str) -> None:
            nonlocal calls
            calls += 1
            if calls == 2:
                raise TOOLS.ToolsBundleError("injected write failure")
            original(descriptor, content, label)

        with mock.patch.object(
            TOOLS, "_write_all", side_effect=fail_after_one
        ), self.assertRaisesRegex(TOOLS.ToolsBundleError, "injected"):
            TOOLS.install_verified_bundle(
                verified, destination, owner_uid=os.geteuid()
            )
        self.assertFalse(destination.exists())

    def test_installed_closure_detects_extra_tampered_mode_and_symlink(self) -> None:
        _, raw = self.fixture.build()
        verified = self.verify_raw(raw)
        owner = os.geteuid()
        cases = ("extra", "content", "mode", "symlink")
        for index, case in enumerate(cases):
            destination = self.root / f"installed-{index}"
            TOOLS.install_verified_bundle(verified, destination, owner_uid=owner)
            scripts = destination / "deploy/scripts"
            scripts.chmod(0o755)
            target = scripts / "image-rollout-smoke.py"
            if case == "extra":
                (scripts / "unexpected").write_bytes(b"extra\n")
            elif case == "content":
                target.chmod(0o644)
                target.write_bytes(b"tampered\n")
                target.chmod(0o555)
            elif case == "mode":
                target.chmod(0o755)
            else:
                target.unlink()
                target.symlink_to("image-rollout-admission.py")
            scripts.chmod(0o555)
            with self.subTest(case=case), self.assertRaises(TOOLS.ToolsBundleError):
                TOOLS.verify_installed_bundle(
                    verified, destination, owner_uid=owner
                )

    def test_external_verifier_requires_fixed_hash_mode_owner_chain_and_no_links(self) -> None:
        trust = self.root / "trusted-verifier"
        trust.mkdir(mode=0o700)
        verifier = trust / TOOLS.VERIFIER_BASENAME
        verifier.write_bytes(SCRIPT.read_bytes())
        verifier.chmod(0o555)
        expected = digest(verifier.read_bytes())
        descriptor = TOOLS.verify_trusted_verifier(
            verifier,
            trust,
            expected,
            owner_uid=os.geteuid(),
        )
        self.assertEqual(descriptor["sha256"], expected)
        self.assertNotIn(str(trust), TOOLS.canonical_json(descriptor).decode("ascii"))

        with self.assertRaisesRegex(TOOLS.ToolsBundleError, "out-of-band digest"):
            TOOLS.verify_trusted_verifier(
                verifier, trust, "0" * 64, owner_uid=os.geteuid()
            )
        verifier.chmod(0o755)
        with self.assertRaisesRegex(TOOLS.ToolsBundleError, "fixed read-only mode"):
            TOOLS.verify_trusted_verifier(
                verifier, trust, expected, owner_uid=os.geteuid()
            )
        verifier.chmod(0o555)

        alias = self.root / "alias-verifier"
        alias.mkdir()
        linked = alias / TOOLS.VERIFIER_BASENAME
        linked.symlink_to(verifier)
        with self.assertRaises(TOOLS.ToolsBundleError):
            TOOLS.verify_trusted_verifier(
                linked, alias, expected, owner_uid=os.geteuid()
            )

        hardlink = self.root / TOOLS.VERIFIER_BASENAME
        os.link(verifier, hardlink)
        with self.assertRaisesRegex(TOOLS.ToolsBundleError, "singly-linked"):
            TOOLS.verify_trusted_verifier(
                hardlink, self.root, expected, owner_uid=os.geteuid()
            )

    def test_extract_fails_before_archive_access_when_not_root(self) -> None:
        arguments = argparse.Namespace(
            archive=self.root / TOOLS.ARCHIVE_BASENAME,
            expected_archive_sha256="0" * 64,
            expected_identity_sha256=None,
            source_date_epoch=EPOCH,
            destination=self.root / "destination",
            expected_verifier_sha256="0" * 64,
            verifier_trust_anchor=Path("/"),
            archive_trust_anchor=Path("/"),
            destination_trust_anchor=Path("/"),
            admission_output=self.root / TOOLS.ADMISSION_BASENAME,
        )
        with mock.patch.object(
            TOOLS.os, "geteuid", return_value=12345
        ), self.assertRaisesRegex(TOOLS.ToolsBundleError, "run as root"):
            TOOLS.extract_bundle(arguments)
        self.assertFalse(arguments.destination.exists())

    def test_admission_result_has_exact_privacy_safe_contract(self) -> None:
        result, raw = self.fixture.build()
        self.assertEqual(
            set(result),
            {
                "archive",
                "command",
                "external_verifier",
                "manifest",
                "members",
                "schema_version",
                "self_sha256",
                "status",
                "tooling_identity",
                "type",
            },
        )
        self.assertEqual(result["type"], "image-rollout-tools-admission-v1")
        self.assertEqual(result["schema_version"], 1)
        self.assertEqual(set(result["members"]), set(TOOLS.TOOL_MEMBERS))
        self.assertEqual(
            result["self_sha256"], result["external_verifier"]["sha256"]
        )
        self.assertEqual(
            result["archive"],
            {
                "basename": TOOLS.ARCHIVE_BASENAME,
                "sha256": digest(raw),
                "size": len(raw),
            },
        )
        for relative, descriptor in result["members"].items():
            self.assertEqual(descriptor["basename"], PurePosixPath(relative).name)
            self.assertEqual(descriptor["mode"], TOOLS.TOOL_MEMBERS[relative][1])
            self.assertEqual(
                descriptor["sha256"], digest(self.fixture.contents[relative])
            )
            self.assertEqual(descriptor["size"], len(self.fixture.contents[relative]))
        rendered = TOOLS.canonical_json(result).decode("ascii")
        self.assertNotIn(str(self.root), rendered)
        self.assertNotIn("destination", rendered)
        self.assertNotIn('"path"', rendered)

    def test_install_with_admission_is_canonical_no_replace_and_transactional(self) -> None:
        _, raw = self.fixture.build()
        verified = self.verify_raw(raw)
        result = TOOLS.result_for(verified, "extract", "extracted")
        owner = os.geteuid()
        destination = self.root / "installed-with-admission"
        admission = destination / TOOLS.ADMISSION_BASENAME
        expected_raw = TOOLS.canonical_json(result)
        TOOLS.install_with_admission(
            verified,
            destination,
            admission,
            result,
            owner_uid=owner,
        )
        self.assertEqual(admission.read_bytes(), expected_raw)
        self.assertEqual(stat.S_IMODE(admission.stat().st_mode), 0o444)
        TOOLS.verify_installed_bundle(
            verified,
            destination,
            owner_uid=owner,
            admission_raw=expected_raw,
        )

        existing = self.root / "existing-admission-root"
        existing.mkdir()
        existing_admission = existing / TOOLS.ADMISSION_BASENAME
        existing_admission.write_bytes(b"preserve\n")
        with self.assertRaisesRegex(TOOLS.ToolsBundleError, "already exists"):
            TOOLS.install_with_admission(
                verified,
                existing,
                existing_admission,
                result,
                owner_uid=owner,
            )
        self.assertEqual(existing_admission.read_bytes(), b"preserve\n")

        partial = self.root / "partial-admission-root"
        partial_admission = partial / TOOLS.ADMISSION_BASENAME
        original_write = TOOLS._write_all

        def fail_admission_write(
            descriptor: int, content: bytes, label: str
        ) -> None:
            if label == "rollout tools admission output":
                raise TOOLS.ToolsBundleError("injected admission failure")
            original_write(descriptor, content, label)

        with mock.patch.object(
            TOOLS,
            "_write_all",
            side_effect=fail_admission_write,
        ), self.assertRaisesRegex(TOOLS.ToolsBundleError, "injected"):
            TOOLS.install_with_admission(
                verified,
                partial,
                partial_admission,
                result,
                owner_uid=owner,
            )
        self.assertFalse(partial.exists())

        victim = self.root / "admission-victim"
        victim.write_bytes(b"preserve victim\n")
        linked_root = self.root / "linked-admission-root"
        linked_root.mkdir()
        linked_admission = linked_root / TOOLS.ADMISSION_BASENAME
        linked_admission.symlink_to(victim)
        with self.assertRaisesRegex(TOOLS.ToolsBundleError, "already exists"):
            TOOLS.install_with_admission(
                verified,
                linked_root,
                linked_admission,
                result,
                owner_uid=owner,
            )
        self.assertTrue(linked_admission.is_symlink())
        self.assertEqual(victim.read_bytes(), b"preserve victim\n")

        wrong_result = TOOLS.result_for(verified, "verify", "verified")
        rejected = self.root / "rejected-admission-root"
        with self.assertRaisesRegex(TOOLS.ToolsBundleError, "exact extraction"):
            TOOLS.install_with_admission(
                verified,
                rejected,
                rejected / TOOLS.ADMISSION_BASENAME,
                wrong_result,
                owner_uid=owner,
            )
        self.assertFalse(rejected.exists())

    def test_cli_build_and_verify_emit_canonical_privacy_safe_json(self) -> None:
        archive = self.root / "cli-output" / TOOLS.ARCHIVE_BASENAME
        archive.parent.mkdir()
        archive.parent.chmod(0o700)
        command = [
            sys.executable,
            "-B",
            str(SCRIPT),
            "build",
            "--admission-helper",
            str(self.fixture.paths["deploy/scripts/image-rollout-admission.py"]),
            "--smoke-helper",
            str(self.fixture.paths["deploy/scripts/image-rollout-smoke.py"]),
            "--wrapper",
            str(self.fixture.paths["deploy/scripts/rollout-bootstrap-images.sh"]),
            "--record-schema",
            str(self.fixture.paths["deploy/schemas/image-rollout-record.schema.json"]),
            "--source-date-epoch",
            str(EPOCH),
            "--output",
            str(archive),
        ]
        environment = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}
        built = subprocess.run(
            command,
            capture_output=True,
            check=False,
            env=environment,
        )
        self.assertEqual(built.returncode, 0, built.stderr.decode())
        self.assertEqual(built.stderr, b"")
        build_result = json.loads(built.stdout)
        self.assertEqual(built.stdout, TOOLS.canonical_json(build_result))
        self.assertNotIn(str(self.root).encode(), built.stdout)

        verified = subprocess.run(
            [
                sys.executable,
                "-B",
                str(SCRIPT),
                "verify",
                "--archive",
                str(archive),
                "--expected-archive-sha256",
                build_result["archive"]["sha256"],
                "--expected-identity-sha256",
                build_result["tooling_identity"],
                "--source-date-epoch",
                str(EPOCH),
            ],
            capture_output=True,
            check=False,
            env=environment,
        )
        self.assertEqual(verified.returncode, 0, verified.stderr.decode())
        self.assertEqual(verified.stderr, b"")
        verify_result = json.loads(verified.stdout)
        self.assertEqual(verified.stdout, TOOLS.canonical_json(verify_result))
        self.assertEqual(verify_result["status"], "verified")
        self.assertEqual(
            verify_result["tooling_identity"], build_result["tooling_identity"]
        )
        self.assertNotIn(str(self.root).encode(), verified.stdout)


if __name__ == "__main__":
    unittest.main()
