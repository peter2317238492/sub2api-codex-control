from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import stat
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[3]
TOOL = REPO_ROOT / "deploy/scripts/build-unsigned-bootstrap-bundle.py"
SPEC = importlib.util.spec_from_file_location("build_unsigned_bootstrap_bundle", TOOL)
assert SPEC is not None and SPEC.loader is not None
BUNDLE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = BUNDLE
SPEC.loader.exec_module(BUNDLE)

VERIFIER_TOOL = REPO_ROOT / "deploy/scripts/verify-unsigned-bootstrap-bundle.py"
VERIFIER_SPEC = importlib.util.spec_from_file_location(
    "verify_unsigned_bootstrap_bundle_contract", VERIFIER_TOOL
)
assert VERIFIER_SPEC is not None and VERIFIER_SPEC.loader is not None
VERIFIER = importlib.util.module_from_spec(VERIFIER_SPEC)
sys.modules[VERIFIER_SPEC.name] = VERIFIER
VERIFIER_SPEC.loader.exec_module(VERIFIER)

BOOTSTRAP = "deploy/scripts/bootstrap-production-unsigned.sh"
DEPLOY = "deploy/scripts/deploy-production.sh"
EXECUTABLES = frozenset({BOOTSTRAP, DEPLOY})
CONTRACT = BUNDLE.SUB2API_AUTH_CONTRACT_PATH
NGINX_LOG_PROVISIONER = "deploy/scripts/provision-nginx-access-log.sh"
NGINX_LOG_PROVISIONER_HELPER = "deploy/scripts/provision-nginx-access-log.py"
NGINX_LOGROTATE = "deploy/nginx/codex-control-access.logrotate"
NGINX_REQUIRED_SOURCES = frozenset(
    {
        "deploy/nginx/api-security-headers.conf",
        "deploy/nginx/browser-security-headers.conf",
        NGINX_LOGROTATE,
        "deploy/nginx/hide-upstream-security-headers.conf",
        "deploy/nginx/http-context.conf",
        "deploy/nginx/server-locations.conf",
        "deploy/nginx/sub2api-logout-location.conf",
    }
)
NGINX_PROVISIONING_REQUIRED_SOURCES = NGINX_REQUIRED_SOURCES | frozenset(
    {NGINX_LOG_PROVISIONER_HELPER}
)
EPOCH = 1_700_000_000


def source_record(
    path: str, content: bytes, *, source_mode: int = 0o644
) -> BUNDLE.SourceRecord:
    return BUNDLE.SourceRecord(
        path=path,
        size=len(content),
        mode=source_mode,
        uid=501,
        gid=20,
        sha256=hashlib.sha256(content).hexdigest(),
    )


def command_result(
    stdout: bytes = b"", stderr: bytes = b"", returncode: int = 0
) -> BUNDLE.CommandResult:
    return BUNDLE.CommandResult(stdout=stdout, stderr=stderr, returncode=returncode)


class SourceIdentityTests(unittest.TestCase):
    def test_auth_contract_required_source_policy_matches_offline_verifier(
        self,
    ) -> None:
        self.assertEqual(
            BUNDLE.SUB2API_AUTH_CONTRACT_PATH,
            VERIFIER.SUB2API_AUTH_CONTRACT_PATH,
        )
        self.assertEqual(BUNDLE.REQUIRED_SOURCE_FILES, VERIFIER.REQUIRED_SOURCE_FILES)
        self.assertEqual(
            BUNDLE.EXECUTABLE_SOURCE_FILES,
            VERIFIER.EXECUTABLE_SOURCE_FILES,
        )
        self.assertEqual(BUNDLE.NGINX_REQUIRED_SOURCE_FILES, NGINX_REQUIRED_SOURCES)
        self.assertEqual(
            BUNDLE.NGINX_REQUIRED_SOURCE_FILES,
            VERIFIER.NGINX_REQUIRED_SOURCE_FILES,
        )
        self.assertEqual(
            BUNDLE.NGINX_PROVISIONER_HELPER_PATH,
            NGINX_LOG_PROVISIONER_HELPER,
        )
        self.assertEqual(
            BUNDLE.NGINX_PROVISIONING_REQUIRED_SOURCE_FILES,
            NGINX_PROVISIONING_REQUIRED_SOURCES,
        )
        self.assertEqual(
            BUNDLE.NGINX_PROVISIONING_REQUIRED_SOURCE_FILES,
            VERIFIER.NGINX_PROVISIONING_REQUIRED_SOURCE_FILES,
        )
        self.assertEqual(
            {
                path
                for path in BUNDLE.REQUIRED_SOURCE_FILES
                if path.startswith("deploy/nginx/")
            },
            NGINX_REQUIRED_SOURCES,
        )
        self.assertIn(CONTRACT, BUNDLE.REQUIRED_SOURCE_FILES)
        self.assertNotIn(CONTRACT, BUNDLE.EXECUTABLE_SOURCE_FILES)
        self.assertIn(NGINX_LOG_PROVISIONER, BUNDLE.EXECUTABLE_SOURCE_FILES)
        self.assertIn(NGINX_LOG_PROVISIONER_HELPER, BUNDLE.REQUIRED_SOURCE_FILES)
        self.assertNotIn(NGINX_LOG_PROVISIONER_HELPER, BUNDLE.EXECUTABLE_SOURCE_FILES)
        self.assertIn(NGINX_LOGROTATE, BUNDLE.REQUIRED_SOURCE_FILES)
        self.assertNotIn(NGINX_LOGROTATE, BUNDLE.EXECUTABLE_SOURCE_FILES)
        self.assertEqual(BUNDLE.exclusion_policy(), VERIFIER.exclusion_policy())

    def test_manifest_and_list_are_sorted_and_normalize_modes(self) -> None:
        records = [
            source_record("z-last.txt", b"z", source_mode=0o755),
            source_record(BOOTSTRAP, b"#!/bin/sh\n", source_mode=0o600),
            source_record(DEPLOY, b"#!/bin/sh\nexit 0\n", source_mode=0o644),
            source_record("a-first.txt", b"alpha", source_mode=0o700),
        ]

        with mock.patch.object(BUNDLE, "EXECUTABLE_SOURCE_FILES", EXECUTABLES):
            manifest = BUNDLE.source_hash_manifest_bytes(records)
            file_list = BUNDLE.source_list_bytes(records)

        expected_order = ["a-first.txt", BOOTSTRAP, DEPLOY, "z-last.txt"]
        self.assertEqual(
            [line.split("  ", 1)[1] for line in manifest.decode().splitlines()],
            expected_order,
        )
        self.assertEqual(
            [line.split("  ", 1)[1] for line in file_list.decode().splitlines()],
            expected_order,
        )
        manifest_modes = {
            line.split("  ", 1)[1]: line.split(" ", 1)[0]
            for line in manifest.decode().splitlines()
        }
        list_modes = {
            line.split("  ", 1)[1]: line.split(" ", 1)[0]
            for line in file_list.decode().splitlines()
        }
        for path in EXECUTABLES:
            self.assertEqual(manifest_modes[path], "0555")
            self.assertEqual(list_modes[path], "0555")
        self.assertEqual(manifest_modes["a-first.txt"], "0444")
        self.assertEqual(manifest_modes["z-last.txt"], "0444")

    def test_manifest_hash_is_a_standard_64_hex_vcs_ref(self) -> None:
        records = [
            source_record(BOOTSTRAP, b"#!/bin/sh\n"),
            source_record(DEPLOY, b"#!/bin/sh\nexit 0\n"),
            source_record("README.md", b"release\n"),
        ]
        with mock.patch.object(BUNDLE, "EXECUTABLE_SOURCE_FILES", EXECUTABLES):
            raw = BUNDLE.source_hash_manifest_bytes(records)
            revision = BUNDLE.sha256_bytes(raw)
        self.assertRegex(revision, r"^[0-9a-f]{64}$")
        self.assertEqual(revision, hashlib.sha256(raw).hexdigest())

    def test_parse_manifest_enforces_static_modes_and_canonical_sorting(self) -> None:
        records = sorted(
            [
                source_record(BOOTSTRAP, b"#!/bin/sh\n"),
                source_record(DEPLOY, b"#!/bin/sh\nexit 0\n"),
                source_record("README.md", b"release\n", source_mode=0o755),
            ],
            key=lambda item: item.path.encode("utf-8"),
        )
        with (
            mock.patch.object(BUNDLE, "EXECUTABLE_SOURCE_FILES", EXECUTABLES),
            mock.patch.object(BUNDLE, "REQUIRED_SOURCE_FILES", {"README.md"}),
        ):
            raw = BUNDLE.source_hash_manifest_bytes(records)
            parsed = BUNDLE.parse_source_hash_manifest(raw)
            self.assertEqual(
                [record.identity() for record in parsed],
                [record.identity() for record in records],
            )

            wrong_regular_mode = raw.replace(b"0444 ", b"0555 ", 1)
            with self.assertRaisesRegex(BUNDLE.BundleError, "static allowlist"):
                BUNDLE.parse_source_hash_manifest(wrong_regular_mode)

            rendered = raw.decode("utf-8").splitlines(keepends=True)
            with self.assertRaisesRegex(BUNDLE.BundleError, "not sorted"):
                BUNDLE.parse_source_hash_manifest(
                    (rendered[1] + rendered[0] + "".join(rendered[2:])).encode()
                )

    def test_auth_contract_manifest_is_required_and_cannot_be_executable(self) -> None:
        contract = source_record(CONTRACT, b'{"format_version":1}\n', source_mode=0o755)
        records = sorted(
            [
                contract,
                *(source_record(path, b"#!/bin/sh\n") for path in EXECUTABLES),
            ],
            key=lambda item: item.path.encode("utf-8"),
        )
        required = frozenset({CONTRACT})
        with (
            mock.patch.object(BUNDLE, "EXECUTABLE_SOURCE_FILES", EXECUTABLES),
            mock.patch.object(BUNDLE, "REQUIRED_SOURCE_FILES", required),
        ):
            raw = BUNDLE.source_hash_manifest_bytes(records)
            contract_line = next(
                line for line in raw.splitlines() if line.endswith(CONTRACT.encode())
            )
            self.assertTrue(contract_line.startswith(b"0444 "))
            BUNDLE.parse_source_hash_manifest(raw)

            missing = BUNDLE.source_hash_manifest_bytes(
                [record for record in records if record.path != CONTRACT]
            )
            with self.assertRaisesRegex(BUNDLE.BundleError, "missing required inputs"):
                BUNDLE.parse_source_hash_manifest(missing)

            executable = raw.replace(
                b"0444 " + str(contract.size).encode() + b" ",
                b"0555 " + str(contract.size).encode() + b" ",
                1,
            )
            with self.assertRaisesRegex(BUNDLE.BundleError, "static allowlist"):
                BUNDLE.parse_source_hash_manifest(executable)

    def test_each_nginx_provisioning_input_rejects_executable_manifest_mode(
        self,
    ) -> None:
        records = [
            source_record(path, f"fixture for {path}\n".encode())
            for path in sorted(
                BUNDLE.REQUIRED_SOURCE_FILES | BUNDLE.EXECUTABLE_SOURCE_FILES
            )
        ]
        raw = BUNDLE.source_hash_manifest_bytes(records)

        for relative in sorted(NGINX_PROVISIONING_REQUIRED_SOURCES):
            with self.subTest(relative=relative):
                lines = raw.decode("utf-8").splitlines(keepends=True)
                for index, line in enumerate(lines):
                    if line.endswith(f"  {relative}\n"):
                        self.assertTrue(line.startswith("0444 "))
                        lines[index] = "0555 " + line[5:]
                        break
                else:  # pragma: no cover - test fixture invariant
                    self.fail(f"required Nginx source is absent: {relative}")
                with self.assertRaisesRegex(
                    BUNDLE.BundleError,
                    rf"static allowlist: {relative.replace('.', r'\.')}",
                ):
                    BUNDLE.parse_source_hash_manifest("".join(lines).encode("utf-8"))

    def test_source_checksum_file_uses_sha256sum_format(self) -> None:
        records = [
            source_record("z.txt", b"z"),
            source_record("a.txt", b"alpha"),
        ]
        raw = BUNDLE.source_checksum_bytes(records)
        lines = raw.decode("ascii").splitlines()
        self.assertEqual(len(lines), 2)
        self.assertTrue(raw.endswith(b"\n"))
        self.assertEqual([line[66:] for line in lines], ["a.txt", "z.txt"])
        for line in lines:
            self.assertRegex(line, r"^[0-9a-f]{64}  [^\r\n]+$")


class SensitiveSourceTests(unittest.TestCase):
    def test_rejects_sensitive_local_file_names_and_private_key_containers(
        self,
    ) -> None:
        cases = {
            ".npmrc": b"//registry/:_authToken=secret\n",
            ".pypirc": b"[pypi]\npassword = secret\n",
            ".netrc": b"machine example login user password secret\n",
            "id_rsa": b"opaque private material\n",
            "id_rsa.bak": b"opaque private material\n",
            "deploy.key": b"opaque private material\n",
            "deploy.pem": (
                b"-----BEGIN " + b"PRIVATE KEY-----\n"
                b"cHJpdmF0ZQ==\n"
                b"-----END " + b"PRIVATE KEY-----\n"
            ),
            "client.p12": b"opaque private material\n",
            "client.pfx": b"opaque private material\n",
            "credentials.json": b'{"password":"secret"}\n',
            "credentials.json.orig": b'{"password":"secret"}\n',
            "prod-token.toml": b'token = "secret"\n',
            "service-secret.yaml": b"secret: value\n",
        }
        for path, content in cases.items():
            with self.subTest(path=path):
                self.assertIsNotNone(BUNDLE.sensitive_source_reason(path, content))

    def test_allows_public_material_templates_and_ordinary_token_source(self) -> None:
        public_certificate = (
            b"-----BEGIN CERTIFICATE-----\n"
            b"cHVibGljIGNlcnRpZmljYXRl\n"
            b"-----END CERTIFICATE-----\n"
        )
        cases = {
            "public-cert.pem": public_certificate,
            "credentials.example.json": b'{"token":"replace-me"}\n',
            "secret-config.template.yaml": b"secret: replace-me\n",
            "schemas/token.schema.json": b'{"title":"Token"}\n',
            "apps/pwa/src/api/token.ts": b"export type Token = string\n",
        }
        for path, content in cases.items():
            with self.subTest(path=path):
                self.assertIsNone(BUNDLE.sensitive_source_reason(path, content))

    def test_source_scan_fails_closed_for_sensitive_and_generated_report_files(
        self,
    ) -> None:
        cases = {
            ".npmrc": b"//registry/:_authToken=secret\n",
            "deploy.pem.tmp": (
                b"-----BEGIN " + b"PRIVATE KEY-----\n"
                b"cHJpdmF0ZQ==\n"
                b"-----END " + b"PRIVATE KEY-----\n"
            ),
            "notes.txt.bak": (
                b"-----BEGIN " + b"PRIVATE KEY-----\n"
                b"cHJpdmF0ZQ==\n"
                b"-----END " + b"PRIVATE KEY-----\n"
            ),
            "tests/e2e/reports/history.json": b"{}\n",
        }
        for relative, content in cases.items():
            with (
                self.subTest(relative=relative),
                tempfile.TemporaryDirectory(
                    prefix="sensitive-source-scan."
                ) as temporary,
            ):
                root = Path(temporary)
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(content)
                with self.assertRaisesRegex(
                    BUNDLE.BundleError,
                    "sensitive local file|private runtime content",
                ):
                    BUNDLE.scan_source(root)


class RequiredSourceTests(unittest.TestCase):
    def write_release_inputs(self, root: Path, *, omit: str | None = None) -> None:
        for relative in sorted(
            BUNDLE.REQUIRED_SOURCE_FILES | BUNDLE.EXECUTABLE_SOURCE_FILES
        ):
            if relative == omit:
                continue
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            content = (
                (REPO_ROOT / relative).read_bytes()
                if relative == CONTRACT
                else f"fixture for {relative}\n".encode()
            )
            path.write_bytes(content)

    def test_scan_requires_auth_contract_and_normalizes_it_to_0444(self) -> None:
        with tempfile.TemporaryDirectory(prefix="required-source-scan.") as temporary:
            root = Path(temporary)
            self.write_release_inputs(root)
            contract_path = root / CONTRACT
            contract_path.chmod(0o755)

            records = BUNDLE.scan_source(root)
            contract = next(record for record in records if record.path == CONTRACT)
            self.assertEqual(contract.mode, 0o755)
            self.assertEqual(contract.normalized_mode, 0o444)
            self.assertIn(
                f"0444 {contract.size}  {CONTRACT}\n",
                BUNDLE.source_list_bytes(records).decode(),
            )

    def test_scan_fails_when_auth_contract_is_missing(self) -> None:
        with tempfile.TemporaryDirectory(prefix="missing-auth-contract.") as temporary:
            root = Path(temporary)
            self.write_release_inputs(root, omit=CONTRACT)
            with self.assertRaisesRegex(
                BUNDLE.BundleError,
                rf"missing required release inputs.*{CONTRACT.replace('.', r'\.')}",
            ):
                BUNDLE.scan_source(root)

    def test_scan_fails_when_each_nginx_provisioning_input_is_missing(self) -> None:
        for relative in sorted(NGINX_PROVISIONING_REQUIRED_SOURCES):
            with (
                self.subTest(relative=relative),
                tempfile.TemporaryDirectory(
                    prefix="missing-nginx-release-input."
                ) as temporary,
            ):
                root = Path(temporary)
                self.write_release_inputs(root, omit=relative)
                with self.assertRaisesRegex(
                    BUNDLE.BundleError,
                    rf"missing required release inputs.*{relative.replace('.', r'\.')}",
                ):
                    BUNDLE.scan_source(root)


class SourceArchiveTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="source-archive-tests.")
        self.root = Path(self.temporary.name)
        self.context = self.root / "context"
        self.context.mkdir(mode=0o700)
        self.contents = {
            BOOTSTRAP: b"#!/bin/sh\nset -eu\n",
            DEPLOY: b"#!/bin/sh\nexit 0\n",
            CONTRACT: (REPO_ROOT / CONTRACT).read_bytes(),
            "README.md": b"ordinary source\n",
        }
        self.records = sorted(
            [source_record(path, content) for path, content in self.contents.items()],
            key=lambda item: item.path.encode("utf-8"),
        )
        for record in self.records:
            path = self.context / record.path
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(self.contents[record.path])

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_archive_extracts_with_static_executable_and_read_only_modes(self) -> None:
        archive_path = self.root / "source.tar.gz"
        extracted = self.root / "extracted"
        extracted.mkdir()
        with mock.patch.object(BUNDLE, "EXECUTABLE_SOURCE_FILES", EXECUTABLES):
            BUNDLE.create_source_archive(
                self.context, self.records, archive_path, EPOCH
            )
            log = BUNDLE.verify_source_archive(archive_path, self.records, EPOCH)
            with tarfile.open(archive_path, "r:gz") as archive:
                archive.extractall(extracted, filter="fully_trusted")
                members = {member.name: member for member in archive.getmembers()}

        for path in EXECUTABLES:
            self.assertEqual(members[path].mode, 0o555)
            self.assertEqual(stat.S_IMODE((extracted / path).stat().st_mode), 0o555)
        self.assertEqual(members["README.md"].mode, 0o444)
        self.assertEqual(stat.S_IMODE((extracted / "README.md").stat().st_mode), 0o444)
        self.assertEqual(members[CONTRACT].mode, 0o444)
        self.assertEqual(stat.S_IMODE((extracted / CONTRACT).stat().st_mode), 0o444)
        self.assertTrue(
            all(member.uid == member.gid == 0 for member in members.values())
        )
        self.assertEqual(log.count(b": OK\n"), len(self.records))

    def test_source_archive_is_deterministic_for_one_epoch(self) -> None:
        first = self.root / "source-first.tar.gz"
        second = self.root / "source-second.tar.gz"
        with mock.patch.object(BUNDLE, "EXECUTABLE_SOURCE_FILES", EXECUTABLES):
            BUNDLE.create_source_archive(self.context, self.records, first, EPOCH)
            BUNDLE.create_source_archive(self.context, self.records, second, EPOCH)
        self.assertEqual(first.read_bytes(), second.read_bytes())


class BundleChecksumTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="bundle-checksum-tests.")
        self.bundle = Path(self.temporary.name) / "bundle"
        self.bundle.mkdir(mode=0o700)
        BUNDLE.write_private(self.bundle / "alpha.txt", b"alpha\n")
        BUNDLE.write_private(self.bundle / "beta.json", b"{}\n")
        BUNDLE.write_bundle_checksums(self.bundle)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_checksum_closure_covers_every_file_except_itself(self) -> None:
        values = BUNDLE.parse_checksum_file((self.bundle / "SHA256SUMS").read_bytes())
        self.assertEqual(list(values), ["alpha.txt", "beta.json"])
        self.assertNotIn("SHA256SUMS", values)
        BUNDLE.verify_bundle_checksums(self.bundle)
        self.assertTrue(
            all(
                stat.S_IMODE(path.stat().st_mode) == 0o600
                for path in self.bundle.iterdir()
            )
        )

    def test_checksum_closure_rejects_extra_and_tampered_files(self) -> None:
        BUNDLE.write_private(self.bundle / "unlisted.txt", b"not admitted\n")
        with self.assertRaisesRegex(BUNDLE.BundleError, "exact bundle file inventory"):
            BUNDLE.verify_bundle_checksums(self.bundle)
        (self.bundle / "unlisted.txt").unlink()

        (self.bundle / "alpha.txt").chmod(0o600)
        (self.bundle / "alpha.txt").write_bytes(b"tampered\n")
        with self.assertRaisesRegex(BUNDLE.BundleError, "checksum mismatch: alpha.txt"):
            BUNDLE.verify_bundle_checksums(self.bundle)


class TransportTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="transport-tests.")
        self.root = Path(self.temporary.name)
        self.bundle = self.root / "bundle"
        self.bundle.mkdir(mode=0o700)
        BUNDLE.write_private(self.bundle / "alpha.txt", b"alpha\n")
        BUNDLE.write_private(self.bundle / "beta.bin", b"0123456789")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_transport_is_deterministic_and_has_exact_private_inventory(self) -> None:
        first = self.root / "first.tar"
        second = self.root / "second.tar"
        BUNDLE.create_transport_tar(self.bundle, first, EPOCH)
        BUNDLE.create_transport_tar(self.bundle, second, EPOCH)
        self.assertEqual(first.read_bytes(), second.read_bytes())
        BUNDLE.verify_transport_tar(first, self.bundle, EPOCH)

        with tarfile.open(first, "r:") as archive:
            members = archive.getmembers()
        self.assertEqual(
            [member.name for member in members], [".", "alpha.txt", "beta.bin"]
        )
        self.assertEqual(members[0].mode, 0o700)
        self.assertTrue(all(member.mode == 0o600 for member in members[1:]))
        self.assertTrue(all(member.mtime == EPOCH for member in members))

    def test_split_transport_reassembles_and_records_every_part(self) -> None:
        transport = self.root / "bundle.tar"
        transport.write_bytes(b"0123456789")
        transport.chmod(0o600)
        parts_dir = self.root / "parts"
        parts_dir.mkdir(mode=0o700)

        parts = BUNDLE.split_transport(transport, 4, parts_dir)

        self.assertEqual(
            [part.name for part in parts],
            [
                "bundle.tar.part-0000",
                "bundle.tar.part-0001",
                "bundle.tar.part-0002",
            ],
        )
        self.assertEqual(
            b"".join(part.read_bytes() for part in parts), transport.read_bytes()
        )
        self.assertTrue(
            all(stat.S_IMODE(part.stat().st_mode) == 0o600 for part in parts)
        )
        manifest = json.loads((parts_dir / "bundle.tar.parts.json").read_text())
        self.assertEqual([item["size"] for item in manifest["parts"]], [4, 4, 2])
        self.assertEqual(manifest["transport"]["sha256"], BUNDLE.sha256_file(transport))
        checksums = BUNDLE.parse_checksum_file(
            (parts_dir / "bundle.tar.parts.sha256").read_bytes()
        )
        self.assertEqual(set(checksums), {part.name for part in parts})
        for part in parts:
            self.assertEqual(checksums[part.name], BUNDLE.sha256_file(part))


class ImageEvidenceTests(unittest.TestCase):
    def test_logged_build_failure_surfaces_private_log_tail(self) -> None:
        def fail_build(*_args: object, **kwargs: object) -> object:
            log = kwargs["stdout"]
            assert hasattr(log, "write")
            log.write(b"deterministic build failure\n")
            return BUNDLE.subprocess.CompletedProcess(
                args=["docker", "buildx", "build"],
                returncode=17,
            )

        with tempfile.TemporaryDirectory(prefix="logged-build-failure.") as temporary:
            root = Path(temporary)
            log = root / "build.log"
            with (
                mock.patch.object(BUNDLE.subprocess, "run", side_effect=fail_build),
                self.assertRaisesRegex(
                    BUNDLE.BundleError,
                    "(?s)exit 17.*private build log tail.*deterministic build failure",
                ),
            ):
                BUNDLE.run_logged_build(
                    [
                        "docker",
                        "buildx",
                        "build",
                        "--output",
                        "type=docker,dest=artifact.tar",
                        ".",
                    ],
                    cwd=root,
                    log_path=log,
                    epoch=1_786_500_000,
                )
            self.assertEqual(log.read_bytes(), b"deterministic build failure\n")

    def test_build_tag_is_deterministic_full_identity_and_release_scoped(self) -> None:
        revision = "a" * 64
        tag = BUNDLE.image_tag_for_build(
            "pwa", "0.1.0-bootstrap.20260812.5", revision, "20260812T170000Z"
        )
        self.assertEqual(
            tag,
            "sub2api-codex-control-pwa:bootstrap-"
            f"0.1.0-bootstrap.20260812.5-{revision}-20260812T170000Z",
        )
        self.assertIn(revision, tag)

    def test_image_tag_preflight_and_cleanup_are_ownership_safe(self) -> None:
        tag = "example/image:bootstrap-test"
        image_id = "sha256:" + "c" * 64
        states: list[list[str]] = [[], [image_id], []]
        calls: list[list[str]] = []

        def fake(arguments: list[str]) -> BUNDLE.CommandResult:
            calls.append(arguments)
            if arguments[1:4] == ["image", "ls", "--quiet"]:
                return command_result(("\n".join(states.pop(0)) + "\n").encode("ascii"))
            if arguments[1:3] == ["image", "rm"]:
                return command_result()
            raise AssertionError(f"unexpected command: {arguments!r}")

        BUNDLE.require_image_tag_absent("docker-test", tag, command=fake)
        BUNDLE.cleanup_owned_image_tags(
            "docker-test",
            [BUNDLE.OwnedImageTag(tag=tag, expected_image_id=image_id)],
            command=fake,
        )
        self.assertFalse(states)
        self.assertEqual(calls[-2][1:3], ["image", "rm"])
        self.assertNotIn("--force", calls[-2])

    def test_image_cleanup_refuses_retargeted_tag(self) -> None:
        tag = "example/image:bootstrap-test"
        owned_id = "sha256:" + "c" * 64
        replacement_id = "sha256:" + "d" * 64

        def fake(arguments: list[str]) -> BUNDLE.CommandResult:
            self.assertNotEqual(arguments[1:3], ["image", "rm"])
            return command_result(f"{replacement_id}\n".encode("ascii"))

        with self.assertRaisesRegex(BUNDLE.BundleError, "identity-changed"):
            BUNDLE.cleanup_owned_image_tags(
                "docker-test",
                [BUNDLE.OwnedImageTag(tag=tag, expected_image_id=owned_id)],
                command=fake,
            )

    def test_image_tag_preflight_rejects_existing_tag(self) -> None:
        tag = "example/image:bootstrap-test"
        existing = "sha256:" + "e" * 64

        def fake(_arguments: list[str]) -> BUNDLE.CommandResult:
            return command_result(f"{existing}\n".encode("ascii"))

        with self.assertRaisesRegex(BUNDLE.BundleError, "pre-existing"):
            BUNDLE.require_image_tag_absent("docker-test", tag, command=fake)

    def test_all_build_commands_pin_linux_amd64_and_export_archives(self) -> None:
        context = Path("/private/context")
        self.assertEqual(BUNDLE.COMPONENTS, ("control-api", "pwa", "postgres-tools"))
        for component in BUNDLE.COMPONENTS:
            archive = Path(f"/private/{component}.tar")
            command = BUNDLE.build_command(
                docker="docker-test",
                component=component,
                context=context,
                archive=archive,
                tag=f"example/{component}:1.2.3-test",
                release="1.2.3",
                revision="a" * 64,
                epoch=EPOCH,
            )
            self.assertEqual(command[:3], ["docker-test", "buildx", "build"])
            self.assertEqual(command[command.index("--platform") + 1], "linux/amd64")
            self.assertIn("--provenance=false", command)
            self.assertIn("--sbom=false", command)
            self.assertEqual(
                command[command.index("--output") + 1],
                f"type=docker,dest={archive}",
            )
            self.assertNotIn("--push", command)
            self.assertNotIn("--load", command)
            has_csrf_arg = "VITE_CONTROL_CSRF_COOKIE_NAME=codex_csrf" in command
            self.assertEqual(has_csrf_arg, component == "pwa")

    def test_pinned_mapper_uses_archive_hash_digests_and_daemon_inspect(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pinned-mapper-tests.") as raw_root:
            root = Path(raw_root)
            archive = root / "image.tar"
            archive.write_bytes(b"portable image archive")
            inspect = root / "inspect.json"
            inspect.write_text("[]\n", encoding="ascii")
            labels = {"org.opencontainers.image.revision": "a" * 64}
            first = {
                "archive": {"sha256": BUNDLE.sha256_file(archive)},
                "image": {
                    "config_digest": "sha256:" + "b" * 64,
                    "manifest_digest": "sha256:" + "c" * 64,
                    "platform": "linux/amd64",
                },
                "daemon": None,
            }
            second = copy.deepcopy(first)
            second["daemon"] = {"id": "sha256:" + "b" * 64}
            calls: list[list[str]] = []

            def fake_command(arguments: list[str]) -> BUNDLE.CommandResult:
                calls.append(arguments)
                return command_result(BUNDLE.canonical_json(second))

            result = BUNDLE.verify_pinned_mapper(
                python="python-test",
                mapper=Path("/private/map.py"),
                archive=archive,
                tag="example/image:1.2.3-test",
                labels=labels,
                inspect_path=inspect,
                first=first,
                command=fake_command,
            )

        self.assertEqual(result, second)
        self.assertEqual(len(calls), 1)
        command = calls[0]
        self.assertEqual(
            command[command.index("--expected-platform") + 1], "linux/amd64"
        )
        self.assertEqual(
            command[command.index("--expected-archive-sha256") + 1],
            first["archive"]["sha256"],
        )
        self.assertEqual(
            command[command.index("--expected-manifest-digest") + 1],
            first["image"]["manifest_digest"],
        )
        self.assertEqual(
            command[command.index("--expected-config-digest") + 1],
            first["image"]["config_digest"],
        )
        self.assertEqual(command[command.index("--inspect-json") + 1], str(inspect))

    def test_image_inspect_accepts_expected_identity_and_rejects_drift(self) -> None:
        tag = "example/pwa:1.2.3-test"
        labels = BUNDLE.expected_labels("pwa", "1.2.3", "a" * 64, "example")
        inspection = {
            "Architecture": "amd64",
            "Config": {"Labels": labels, "User": "nginx"},
            "Id": "sha256:" + "b" * 64,
            "Os": "linux",
            "RepoTags": [tag],
        }
        self.assertEqual(
            BUNDLE.validate_image_inspect(inspection, "pwa", tag, labels),
            inspection["Id"],
        )

        cases = {
            "platform": {"Architecture": "arm64"},
            "tag": {"RepoTags": ["example/pwa:other"]},
            "user": {"Config": {"Labels": labels, "User": "root"}},
            "label": {
                "Config": {
                    "Labels": {**labels, "org.opencontainers.image.revision": "wrong"},
                    "User": "nginx",
                }
            },
        }
        for label, change in cases.items():
            with self.subTest(label=label):
                candidate = copy.deepcopy(inspection)
                candidate.update(change)
                with self.assertRaises(BUNDLE.BundleError):
                    BUNDLE.validate_image_inspect(candidate, "pwa", tag, labels)


class PwaRuntimeTests(unittest.TestCase):
    network_id = "a" * 64
    container_id = "d" * 64

    def fake_runtime(
        self,
        *,
        mode: bytes = b"444\n",
        network_options: dict[str, str] | None = None,
        cleanup_survivor: str | None = None,
        extra_effective_mapping: bool = False,
        extra_network_member: bool = False,
    ) -> tuple[object, list[tuple[list[str], dict[str, object]]]]:
        calls: list[tuple[list[str], dict[str, object]]] = []
        removed_containers: set[str] = set()
        network_removed = False

        def fake(arguments: list[str], **kwargs: object) -> BUNDLE.CommandResult:
            nonlocal network_removed
            calls.append((arguments, kwargs))
            if arguments[1:3] == ["network", "create"]:
                return command_result((self.network_id + "\n").encode("ascii"))
            if arguments[1] == "run":
                return command_result((self.container_id + "\n").encode("ascii"))
            if arguments[1:3] == ["container", "inspect"]:
                identifier = arguments[3]
                if identifier in removed_containers and identifier != cleanup_survivor:
                    return command_result(returncode=1)
                network = next(
                    call[-1] for call, _ in calls if call[1:3] == ["network", "create"]
                )
                inspection = [
                    {
                        "Args": ["-g", "daemon off;"],
                        "HostConfig": {
                            "NetworkMode": network,
                            "PortBindings": {
                                "8080/tcp": [{"HostIp": "127.0.0.1", "HostPort": ""}]
                            },
                        },
                        "NetworkSettings": {
                            "Networks": {network: {"NetworkID": self.network_id}},
                            "Ports": {
                                "80/tcp": (
                                    [
                                        {
                                            "HostIp": "127.0.0.1",
                                            "HostPort": "49153",
                                        }
                                    ]
                                    if extra_effective_mapping
                                    else None
                                ),
                                "8080/tcp": [
                                    {
                                        "HostIp": "127.0.0.1",
                                        "HostPort": "49152",
                                    }
                                ],
                            },
                        },
                        "Path": "nginx",
                        "State": {
                            "Health": {"Status": "healthy"},
                            "Running": True,
                        },
                    }
                ]
                return command_result(BUNDLE.canonical_json(inspection))
            if arguments[1:3] == ["network", "inspect"]:
                if network_removed and cleanup_survivor != "network":
                    return command_result(returncode=1)
                network = arguments[3]
                containers = {
                    self.container_id: {
                        "IPv4Address": "172.31.0.2/16",
                        "Name": next(
                            call[call.index("--name") + 1]
                            for call, _ in calls
                            if call[1] == "run"
                        ),
                    },
                }
                if extra_network_member:
                    containers["e" * 64] = {
                        "IPv4Address": "172.31.0.3/16",
                        "Name": "unexpected-peer",
                    }
                inspection = [
                    {
                        "Attachable": False,
                        "Containers": containers,
                        "Driver": "bridge",
                        "EnableIPv6": False,
                        "Id": self.network_id,
                        "Internal": False,
                        "Name": network,
                        "Options": (
                            dict(BUNDLE.PWA_NETWORK_OPTIONS)
                            if network_options is None
                            else network_options
                        ),
                    }
                ]
                return command_result(BUNDLE.canonical_json(inspection))
            if arguments[-2:] == ["id", "-u"]:
                return command_result(b"101\n")
            if "stat" in arguments:
                return command_result(mode)
            if "wget" in arguments:
                return command_result(b"ok\n")
            if arguments[1:4] == ["container", "rm", "--force"]:
                removed_containers.add(arguments[4])
                return command_result()
            if arguments[1:3] == ["network", "rm"]:
                network_removed = True
                return command_result()
            if "test" in arguments:
                return command_result()
            raise AssertionError(f"unexpected command: {arguments!r}")

        return fake, calls

    def test_pwa_runtime_is_non_root_read_only_isolated_and_healthy(self) -> None:
        fake, calls = self.fake_runtime()
        result = BUNDLE.verify_pwa_runtime(
            "docker-test",
            "example/pwa:test",
            command=fake,
            monotonic=lambda: 0,
            sleep=lambda _seconds: self.fail("healthy containers must not sleep"),
            host_health_probe=lambda port: (
                (200, b"ok\n") if port == 49152 else self.fail("unexpected host port")
            ),
        )

        self.assertEqual(result["status"], "verified")
        self.assertEqual(result["format_version"], 3)
        self.assertEqual(result["runtime_uid"], 101)
        self.assertEqual(result["nginx_config"]["mode"], "444")
        self.assertEqual(result["runtime"]["healthz_body"], "ok")
        self.assertEqual(result["host_health"]["status_code"], 200)
        self.assertTrue(result["network"]["sole_member"])
        self.assertEqual(result["network"]["container_id"], self.container_id)
        self.assertEqual(result["network"]["options"], BUNDLE.PWA_NETWORK_OPTIONS)
        self.assertEqual(result["port_mapping"]["host_ip"], "127.0.0.1")
        self.assertEqual(result["port_mapping"]["host_port"], 49152)
        network_create = calls[0][0]
        self.assertEqual(network_create[1:3], ["network", "create"])
        self.assertIn("com.docker.network.bridge.enable_icc=false", network_create)
        self.assertIn(
            "com.docker.network.bridge.enable_ip_masquerade=false", network_create
        )
        published_run = next(
            arguments
            for arguments, _ in calls
            if arguments[1] == "run" and "--publish" in arguments
        )
        self.assertEqual(
            published_run[published_run.index("--publish") + 1],
            "127.0.0.1::8080/tcp",
        )
        self.assertIn("--read-only", published_run)
        self.assertIn("--cap-drop", published_run)
        self.assertIn("no-new-privileges", published_run)
        self.assertEqual(
            result["cleanup"],
            {
                "containers_removed": True,
                "network_removed": True,
            },
        )
        self.assertEqual(calls[-1][0][1:3], ["network", "inspect"])

    def test_pwa_runtime_rejects_wrong_config_mode_and_still_cleans_up(self) -> None:
        fake, calls = self.fake_runtime(mode=b"640\n")
        with self.assertRaisesRegex(BUNDLE.BundleError, "runtime gate failed"):
            BUNDLE.verify_pwa_runtime(
                "docker-test",
                "example/pwa:test",
                command=fake,
                monotonic=lambda: 0,
                sleep=lambda _seconds: None,
                host_health_probe=lambda _port: (200, b"ok\n"),
            )
        self.assertEqual(calls[-1][0][1:3], ["network", "inspect"])

    def test_pwa_runtime_rejects_unexpected_network_member_and_still_cleans_up(
        self,
    ) -> None:
        fake, calls = self.fake_runtime(extra_network_member=True)
        with self.assertRaisesRegex(BUNDLE.BundleError, "exactly the PWA"):
            BUNDLE.verify_pwa_runtime(
                "docker-test",
                "example/pwa:test",
                command=fake,
                monotonic=lambda: 0,
                sleep=lambda _seconds: None,
                host_health_probe=lambda _port: (200, b"ok\n"),
            )
        self.assertEqual(calls[-1][0][1:3], ["network", "inspect"])

    def test_pwa_runtime_rejects_wrong_network_options(self) -> None:
        fake, _calls = self.fake_runtime(
            network_options={"com.docker.network.bridge.enable_icc": "false"}
        )
        with self.assertRaisesRegex(BUNDLE.BundleError, "topology or isolation"):
            BUNDLE.verify_pwa_runtime(
                "docker-test",
                "example/pwa:test",
                command=fake,
                monotonic=lambda: 0,
                sleep=lambda _seconds: None,
                host_health_probe=lambda _port: (200, b"ok\n"),
            )

    def test_pwa_runtime_rejects_additional_effective_port_mapping(self) -> None:
        fake, _calls = self.fake_runtime(extra_effective_mapping=True)
        with self.assertRaisesRegex(BUNDLE.BundleError, "additional effective"):
            BUNDLE.verify_pwa_runtime(
                "docker-test",
                "example/pwa:test",
                command=fake,
                monotonic=lambda: 0,
                sleep=lambda _seconds: None,
                host_health_probe=lambda _port: (200, b"ok\n"),
            )

    def test_pwa_runtime_rejects_cleanup_survivor(self) -> None:
        fake, _calls = self.fake_runtime(cleanup_survivor="network")
        with self.assertRaisesRegex(BUNDLE.BundleError, "cleanup failed.*network"):
            BUNDLE.verify_pwa_runtime(
                "docker-test",
                "example/pwa:test",
                command=fake,
                monotonic=lambda: 0,
                sleep=lambda _seconds: None,
                host_health_probe=lambda _port: (200, b"ok\n"),
            )


class PostgresRoundtripTests(unittest.TestCase):
    network_id = "a" * 64
    server_id = "b" * 64
    dump = b"PGDMP\x01portable-custom-format"
    dump_list = (
        b"1; 0 0 TABLE bundle_fixture items postgres\n"
        b"2; 0 0 TABLE DATA bundle_fixture items postgres\n"
        b"3; 0 0 SEQUENCE SET bundle_fixture item_seq postgres\n"
    )
    rows = (
        b"41|616c706861|<NULL>|0001ff\n"
        b"42|546f6b796f2de69db1e4baac|6c696e650a76616c7565|deadbeef\n"
    )
    schema = b"id:int8:NO\nlabel:text:NO\nnote:text:YES\npayload:bytea:NO\n"

    def fake_command(
        self,
        *,
        server_version: bytes = b"18.4\n",
        readiness: list[BUNDLE.CommandResult] | None = None,
        cleanup_survivor: str | None = None,
    ) -> tuple[object, list[tuple[list[str], dict[str, object]]]]:
        calls: list[tuple[list[str], dict[str, object]]] = []

        def fake(arguments: list[str], **kwargs: object) -> BUNDLE.CommandResult:
            calls.append((arguments, kwargs))
            if arguments[1:3] == ["network", "create"]:
                return command_result((self.network_id + "\n").encode("ascii"))
            if arguments[1] == "run" and "--detach" in arguments:
                return command_result((self.server_id + "\n").encode("ascii"))
            if arguments[1] == "run":
                entrypoint = arguments[arguments.index("--entrypoint") + 1]
                if entrypoint == "/bin/sh":
                    return command_result(
                        b"pg_dump (PostgreSQL) 18.4\npg_restore (PostgreSQL) 18.4\n"
                    )
                if entrypoint == "pg_dump":
                    return command_result(self.dump)
                if entrypoint == "pg_restore" and "--list" in arguments:
                    self.assertEqual(kwargs.get("input_bytes"), self.dump)
                    return command_result(self.dump_list)
                if entrypoint == "pg_restore":
                    self.assertEqual(kwargs.get("input_bytes"), self.dump)
                    return command_result()
            if arguments[1] == "exec" and "psql" in arguments:
                sql = arguments[arguments.index("--command") + 1]
                if sql == "SELECT 1":
                    self.assertIs(kwargs.get("check"), False)
                    if readiness:
                        return readiness.pop(0)
                    return command_result(b"1\n")
            if arguments[1] == "exec" and "psql" in arguments:
                sql = arguments[arguments.index("--command") + 1]
                if sql == "SHOW server_version":
                    return command_result(server_version)
                if "CREATE SCHEMA bundle_fixture" in sql:
                    return command_result()
                if "convert_to(label" in sql:
                    return command_result(self.rows)
                if "information_schema.columns" in sql:
                    return command_result(self.schema)
                if "SELECT last_value::text" in sql:
                    return command_result(b"42\n")
                if sql == "CREATE DATABASE restored_db":
                    return command_result()
            if arguments[1:4] == ["container", "rm", "--force"]:
                self.assertIs(kwargs.get("check"), False)
                return command_result()
            if arguments[1:3] == ["container", "inspect"]:
                self.assertIs(kwargs.get("check"), False)
                survived = cleanup_survivor == "container"
                return command_result(returncode=0 if survived else 1)
            if arguments[1:3] == ["network", "rm"]:
                self.assertIs(kwargs.get("check"), False)
                return command_result()
            if arguments[1:3] == ["network", "inspect"]:
                self.assertIs(kwargs.get("check"), False)
                survived = cleanup_survivor == "network"
                return command_result(returncode=0 if survived else 1)
            raise AssertionError(f"unexpected command: {arguments!r}")

        return fake, calls

    def test_roundtrip_verifies_dump_restore_and_cleans_every_resource(self) -> None:
        fake, calls = self.fake_command()
        tag = "example/postgres-tools:test"
        tools_image_id = "sha256:" + "c" * 64
        result = BUNDLE.verify_postgres_roundtrip(
            "docker-test",
            tag,
            tools_image_id,
            command=fake,
            monotonic=lambda: 0,
            sleep=lambda _seconds: self.fail("ready server must not sleep"),
        )

        self.assertEqual(result["status"], "verified")
        self.assertEqual(result["server"]["version"], "18.4")
        self.assertEqual(result["dump"]["sha256"], BUNDLE.sha256_bytes(self.dump))
        self.assertGreater(result["dump"]["list_entry_count"], 0)
        expected_fixture_side = {
            "canonical_rows_sha256": BUNDLE.sha256_bytes(self.rows),
            "row_count": 2,
            "schema_sha256": BUNDLE.sha256_bytes(self.schema),
            "sequence_last_value": 42,
        }
        self.assertEqual(result["fixture"]["source"], expected_fixture_side)
        self.assertEqual(result["fixture"]["restored"], expected_fixture_side)
        self.assertEqual(result["fixture"]["source"], result["fixture"]["restored"])
        self.assertEqual(
            result["tools"]["client_versions"],
            ["pg_dump (PostgreSQL) 18.4", "pg_restore (PostgreSQL) 18.4"],
        )
        self.assertEqual(
            result["cleanup"],
            {
                "containers_removed": True,
                "network_removed": True,
                "persistent_volume_created": False,
            },
        )
        VERIFIER.verify_postgres_roundtrip(result, tools_image_id, tag)
        tampered = copy.deepcopy(result)
        tampered["fixture"]["restored"]["row_count"] += 1
        with self.assertRaisesRegex(
            VERIFIER.VerificationError, "fixture identities differ"
        ):
            VERIFIER.verify_postgres_roundtrip(tampered, tools_image_id, tag)

        commands = [arguments for arguments, _kwargs in calls]
        run_commands = [command for command in commands if command[1] == "run"]
        self.assertEqual(len(run_commands), 5)
        for command in run_commands:
            self.assertIn(tools_image_id, command)
            self.assertNotIn(tag, command)
        network_create = next(
            command for command in commands if command[1:3] == ["network", "create"]
        )
        self.assertIn("--internal", network_create)
        server_run = next(
            command
            for command in commands
            if command[1] == "run" and "--detach" in command
        )
        self.assertIn("--pull", server_run)
        self.assertEqual(server_run[server_run.index("--pull") + 1], "never")
        self.assertNotIn("--volume", server_run)
        client_runs = [
            command
            for command in commands
            if command[1] == "run" and "--detach" not in command
        ]
        self.assertEqual(len(client_runs), 4)
        for command in client_runs:
            self.assertIn("--rm", command)
            self.assertIn("--read-only", command)
            self.assertIn("--cap-drop", command)
            self.assertIn("no-new-privileges", command)
            self.assertEqual(command[command.index("--platform") + 1], "linux/amd64")
            self.assertEqual(command[command.index("--pull") + 1], "never")
        interactive_runs = [
            command for command in client_runs if "--interactive" in command
        ]
        self.assertEqual(len(interactive_runs), 2)
        self.assertTrue(
            all(
                command[command.index("--entrypoint") + 1] == "pg_restore"
                for command in interactive_runs
            )
        )
        self.assertTrue(
            all(
                "--interactive" not in command
                for command in client_runs
                if command[command.index("--entrypoint") + 1] in {"/bin/sh", "pg_dump"}
            )
        )
        self.assertEqual(
            len(
                [
                    command
                    for command in commands
                    if command[1:4] == ["container", "rm", "--force"]
                ]
            ),
            5,
        )
        self.assertTrue(any(command[1:3] == ["network", "rm"] for command in commands))

    def test_readiness_requires_source_database_query_before_roundtrip(self) -> None:
        readiness = [
            command_result(
                b"",
                b'FATAL: database "source_db" does not exist\n',
                returncode=2,
            ),
            command_result(b"1\n"),
        ]
        fake, calls = self.fake_command(readiness=readiness)
        result = BUNDLE.verify_postgres_roundtrip(
            "docker-test",
            "example/postgres-tools:test",
            "sha256:" + "c" * 64,
            command=fake,
            monotonic=lambda: 0,
            sleep=lambda _seconds: None,
        )

        self.assertEqual(result["status"], "verified")
        probes = [
            (arguments, kwargs)
            for arguments, kwargs in calls
            if arguments[1] == "exec"
            and "--command" in arguments
            and arguments[arguments.index("--command") + 1] == "SELECT 1"
        ]
        self.assertEqual(len(probes), 2)
        self.assertTrue(all(kwargs.get("check") is False for _, kwargs in probes))
        self.assertTrue(
            all(
                arguments[arguments.index("--host") + 1] == "127.0.0.1"
                for arguments, _ in probes
            )
        )

    def test_main_failure_still_removes_server_and_network(self) -> None:
        fake, calls = self.fake_command(server_version=b"18.5\n")
        with self.assertRaisesRegex(BUNDLE.BundleError, "not exactly 18.4"):
            BUNDLE.verify_postgres_roundtrip(
                "docker-test",
                "example/postgres-tools:test",
                "sha256:" + "c" * 64,
                command=fake,
                monotonic=lambda: 0,
                sleep=lambda _seconds: None,
            )

        commands = [arguments for arguments, _kwargs in calls]
        self.assertTrue(
            any(command[1:4] == ["container", "rm", "--force"] for command in commands)
        )
        self.assertTrue(any(command[1:3] == ["network", "rm"] for command in commands))
        self.assertTrue(
            any(command[1:3] == ["network", "inspect"] for command in commands)
        )

    def test_cleanup_failure_fails_the_roundtrip(self) -> None:
        fake, calls = self.fake_command(cleanup_survivor="network")
        with self.assertRaisesRegex(BUNDLE.BundleError, "cleanup failed.*network"):
            BUNDLE.verify_postgres_roundtrip(
                "docker-test",
                "example/postgres-tools:test",
                "sha256:" + "c" * 64,
                command=fake,
                monotonic=lambda: 0,
                sleep=lambda _seconds: None,
            )
        self.assertEqual(
            [
                arguments[1:3]
                for arguments, _kwargs in calls
                if arguments[1:3] == ["network", "inspect"]
            ],
            [["network", "inspect"]],
        )


class PublicationSafetyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="bundle-publish-tests.")
        self.output = Path(self.temporary.name) / "output"
        self.transport = self.output / "transport"
        self.output.mkdir(mode=0o700)
        self.transport.mkdir(mode=0o700)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_bundle_id_reservation_is_exclusive_and_cleanup_is_owned(self) -> None:
        first = BUNDLE.reserve_bundle_id(self.output, "20260812T000000Z")
        with self.assertRaisesRegex(BUNDLE.BundleError, "already reserved"):
            BUNDLE.reserve_bundle_id(self.output, "20260812T000000Z")

        path = first.ownership.path
        path.unlink()
        BUNDLE.write_private(path, b"another invocation\n")
        BUNDLE.cleanup_owned_paths([first.ownership])
        self.assertEqual(path.read_bytes(), b"another invocation\n")

    def test_publish_never_overwrites_and_failure_cleanup_removes_only_owned(
        self,
    ) -> None:
        staging = self.output / "staging"
        staging.mkdir(mode=0o700)
        source = staging / "bundle.tar"
        BUNDLE.write_private(source, b"new artifact\n")
        destination = self.transport / "bundle.tar"
        BUNDLE.write_private(destination, b"existing artifact\n")
        with self.assertRaisesRegex(BUNDLE.BundleError, "refusing to overwrite"):
            BUNDLE.publish_file_noreplace(source, destination)
        self.assertEqual(destination.read_bytes(), b"existing artifact\n")
        self.assertEqual(source.read_bytes(), b"new artifact\n")

        destination.unlink()
        ownership = BUNDLE.publish_file_noreplace(source, destination)
        self.assertFalse(source.exists())
        self.assertEqual(destination.read_bytes(), b"new artifact\n")
        BUNDLE.cleanup_owned_paths([ownership])
        self.assertFalse(destination.exists())

    def test_mid_publish_collision_rolls_back_only_invocation_owned_files(self) -> None:
        staging = self.output / "staging"
        staging.mkdir(mode=0o700)
        first_source = staging / "first.tar"
        second_source = staging / "second.tar"
        BUNDLE.write_private(first_source, b"first\n")
        BUNDLE.write_private(second_source, b"second\n")
        first_destination = self.transport / first_source.name
        collision = self.transport / second_source.name
        BUNDLE.write_private(collision, b"another invocation\n")

        owned = [BUNDLE.publish_file_noreplace(first_source, first_destination)]
        with self.assertRaisesRegex(BUNDLE.BundleError, "refusing to overwrite"):
            BUNDLE.publish_file_noreplace(second_source, collision)
        BUNDLE.cleanup_owned_paths(owned)

        self.assertFalse(first_destination.exists())
        self.assertEqual(collision.read_bytes(), b"another invocation\n")
        self.assertEqual(second_source.read_bytes(), b"second\n")

    def test_ready_marker_is_last_and_fsyncs_after_published_files(self) -> None:
        bundle = self.output / "20260812T000000Z"
        bundle.mkdir(mode=0o700)
        BUNDLE.write_private(bundle / "artifact-manifest.json", b"{}\n")
        transport = self.transport / "production-bootstrap-20260812T000000Z.tar"
        BUNDLE.write_private(transport, b"transport\n")
        events: list[Path] = []
        real_fsync = BUNDLE.fsync_directory

        def record_fsync(path: Path) -> None:
            events.append(path)
            real_fsync(path)

        with mock.patch.object(BUNDLE, "fsync_directory", side_effect=record_fsync):
            ready = BUNDLE.publish_ready_marker(
                output=self.output,
                bundle_id="20260812T000000Z",
                final_bundle=bundle,
                final_transport=transport,
                release="0.1.0-bootstrap.5",
                revision="a" * 64,
                transport_sha=BUNDLE.sha256_file(transport),
            )
        self.assertTrue(BUNDLE.path_is_owned(ready))
        self.assertEqual(events[-1], self.output)
        value = json.loads(ready.path.read_text(encoding="ascii"))
        self.assertEqual(value["status"], "ready")
        self.assertEqual(value["transport"]["sha256"], BUNDLE.sha256_file(transport))

    def test_image_cleanup_failure_does_not_skip_local_failure_cleanup(self) -> None:
        staging = self.output / "staging"
        staging.mkdir(mode=0o700)
        BUNDLE.write_private(staging / "temporary", b"temporary\n")
        reservation = BUNDLE.reserve_bundle_id(self.output, "20260812T000000Z")
        partial = self.transport / "partial.tar"
        BUNDLE.write_private(partial, b"partial\n")
        partial_ownership = BUNDLE.owned_path(partial, is_directory=False)
        owned = [reservation.ownership, partial_ownership]

        with (
            mock.patch.object(
                BUNDLE,
                "cleanup_owned_image_tags",
                side_effect=BUNDLE.BundleError("identity-changed:example/image:test"),
            ),
            self.assertRaisesRegex(
                BUNDLE.BundleError, "primary failure; build cleanup failed"
            ),
        ):
            BUNDLE.finalize_build_cleanup(
                docker="docker-test",
                image_tags_cleaned=False,
                owned_image_tags=[
                    BUNDLE.OwnedImageTag(
                        tag="example/image:test", expected_image_id="sha256:" + "a" * 64
                    )
                ],
                staging=staging,
                published=False,
                owned_paths=owned,
                output=self.output,
                transport_output=self.transport,
                active_error=BUNDLE.BundleError("primary failure"),
            )

        self.assertFalse(staging.exists())
        self.assertFalse(reservation.ownership.path.exists())
        self.assertFalse(partial.exists())


if __name__ == "__main__":
    unittest.main()
