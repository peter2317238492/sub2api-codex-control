from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[3]
ROLLOUT = REPO_ROOT / "deploy/scripts/rollout-bootstrap-images.sh"
ADMISSION = REPO_ROOT / "deploy/scripts/image-rollout-admission.py"
SMOKE = REPO_ROOT / "deploy/scripts/image-rollout-smoke.py"
SCHEMA = REPO_ROOT / "deploy/schemas/image-rollout-record.schema.json"
ROOT_TEST_IMAGE = (
    "python:3.12-slim-bookworm@sha256:"
    "8a7e7cc04fd3e2bd787f7f24e22d5d119aa590d429b50c95dfe12b3abe52f48b"
)
ROOT_TEST_COMMAND = (
    "docker",
    "run",
    "--rm",
    "--network",
    "none",
    "--tmpfs",
    "/tmp:rw,nosuid,nodev,noexec,mode=1777,size=256m",
    "--tmpfs",
    "/private/tmp:rw,nosuid,nodev,mode=1777,size=256m",
    "--tmpfs",
    "/run:rw,nosuid,nodev,mode=0755,size=256m",
    "--mount",
    "type=bind,src={repo},dst=/workspace,readonly",
    "--workdir",
    "/workspace",
    ROOT_TEST_IMAGE,
    "/bin/sh",
    "-ceu",
    (
        "ln -s /usr/local/bin/python3 /usr/bin/python3; "
        "mkdir -p /opt/snapshot/deploy/scripts/tests /opt/snapshot/deploy/schemas; "
        "cp /workspace/deploy/scripts/rollout-bootstrap-images.sh "
        "/workspace/deploy/scripts/image-rollout-admission.py "
        "/workspace/deploy/scripts/image-rollout-smoke.py /opt/snapshot/deploy/scripts/; "
        "cp /workspace/deploy/scripts/tests/test_rollout_bootstrap_images.py "
        "/opt/snapshot/deploy/scripts/tests/; "
        "cp /workspace/deploy/schemas/image-rollout-record.schema.json "
        "/opt/snapshot/deploy/schemas/; "
        "cd /opt/snapshot; "
        "export CONTROL_WRAPPER_TEST_CONTAINER=1; "
        "exec /usr/local/bin/python3 -B -m unittest "
        "deploy.scripts.tests.test_rollout_bootstrap_images.WrapperBehaviorTests"
    ),
)
PROJECT = "sub2api-codex-control"
FORWARD_ORDER = ("control-api-replica", "control-api", "codex-pwa")
REVERSE_ORDER = tuple(reversed(FORWARD_ORDER))
TARGET_RELEASE = "0.1.0-bootstrap.20260813.1"
TARGET_VCS_REF = "d518538f6d36d0c2ff94b7b895798431ee981d6e585aac4732a6a2a2cf0ab8a9"
NEW_IMAGES = {
    "control-api": "sha256:" + "b" * 64,
    "pwa": "sha256:" + "c" * 64,
    "postgres-tools": "sha256:" + "d" * 64,
}
OLD_IMAGES = {
    "control-api": "sha256:" + "8" * 64,
    "pwa": "sha256:" + "9" * 64,
    "postgres-tools": "sha256:" + "a" * 64,
}
TOOL_MEMBERS = {
    "deploy/scripts/image-rollout-admission.py": ("0555", ADMISSION),
    "deploy/scripts/image-rollout-smoke.py": ("0555", SMOKE),
    "deploy/scripts/rollout-bootstrap-images.sh": ("0555", ROLLOUT),
    "deploy/schemas/image-rollout-record.schema.json": ("0444", SCHEMA),
}
PRIVATE_SENTINELS = (
    b"fixture-secret-must-never-reach-records",
    b"fixture-private-value-must-never-reach-records",
    b"fixture-private-origin.invalid",
)


def canonical(value: Any) -> bytes:
    return (
        json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("ascii")


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def write_json(path: Path, value: Any, mode: int = 0o600) -> None:
    path.write_bytes(canonical(value))
    path.chmod(mode)


def write_executable(path: Path, source: str) -> None:
    path.write_text(source, encoding="utf-8")
    path.chmod(0o555)


def descriptor(path: Path) -> dict[str, Any]:
    raw = path.read_bytes()
    return {"basename": path.name, "sha256": sha256(raw), "size": len(raw)}


def temporary_parent() -> str:
    return "/opt" if os.geteuid() == 0 else str(Path(tempfile.gettempdir()).resolve())


def shell_commands(script: str) -> list[str]:
    """Join shell continuations while leaving heredoc bodies harmless."""
    commands: list[str] = []
    current = ""
    for raw_line in script.splitlines():
        line = raw_line.strip()
        current = f"{current} {line}".strip()
        if current.endswith("\\"):
            current = current[:-1].rstrip()
            continue
        commands.append(current)
        current = ""
    if current:
        commands.append(current)
    return commands


def helper_calls(script: str, command: str) -> list[str]:
    needle = f'python "$admission_helper" {command}'
    return [line for line in shell_commands(script) if needle in line and "--help" not in line]


def command_flags(script: str, command: str) -> set[str]:
    return {
        flag
        for call in helper_calls(script, command)
        for flag in re.findall(r"--[a-z][a-z0-9-]+", call)
    }


def helper_required_flags(command: str) -> set[str]:
    result = subprocess.run(
        [sys.executable, "-B", "-I", str(ADMISSION), command, "--help"],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise AssertionError(result.stderr)
    usage = result.stdout.split("\n\n", 1)[0]
    usage = re.sub(r"\[[^]]*\]", "", usage, flags=re.DOTALL)
    flags = set(re.findall(r"--[a-z][a-z0-9-]+", usage))
    flags.discard("--help")
    return flags


class StaticRolloutContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.script = ROLLOUT.read_text(encoding="utf-8")

    def test_shell_syntax(self) -> None:
        subprocess.run(["sh", "-n", str(ROLLOUT)], check=True)

    def test_tools_are_separate_from_frozen_target_source(self) -> None:
        self.assertIn("CONTROL_ROLLOUT_TOOLS_ROOT", self.script)
        self.assertIn("CONTROL_ROLLOUT_TOOLS_ADMISSION", self.script)
        self.assertRegex(
            self.script,
            r'tools_manifest="?\$?\{?tools_root[^\n]*rollout-tools\.manifest\.json',
        )
        self.assertRegex(
            self.script,
            r'image-rollout-smoke\.py',
        )
        self.assertNotRegex(
            self.script,
            r'\$source_root/deploy/scripts/(?:image-rollout-admission|image-rollout-smoke|rollout-bootstrap-images)',
        )

    def test_direct_api_readiness_requires_connector_release_admission(self) -> None:
        self.assertRegex(
            self.script,
            r'set\(checks\) != \{[^}]*"connector_release"[^}]*\}',
        )

    def test_tools_builder_is_evidence_only_and_never_executed(self) -> None:
        self.assertIn("CONTROL_EXPECTED_TOOLS_ARCHIVE_SHA256", self.script)
        self.assertIn("CONTROL_EXPECTED_TOOLS_VERIFIER_SHA256", self.script)
        self.assertNotRegex(
            self.script,
            r'(?:python|exec|"\$[^" ]+")\s+[^\n]*build-image-rollout-tools\.py',
        )

    def test_no_arbitrary_smoke_command_surface(self) -> None:
        self.assertNotIn("CONTROL_SMOKE_COMMAND_FILE", self.script)
        self.assertNotRegex(self.script, r"smoke[_-]?command|argv.*smoke|/bin/true")
        self.assertIn("CONTROL_PUBLIC_ORIGIN_FILE", self.script)
        self.assertEqual(
            len(
                [
                    command
                    for command in shell_commands(self.script)
                    if 'python "$smoke_producer"' in command
                ]
            ),
            1,
        )

    def test_fixed_smoke_is_bound_to_all_admissions(self) -> None:
        calls = [
            command
            for command in shell_commands(self.script)
            if 'python "$smoke_producer"' in command
        ]
        self.assertEqual(len(calls), 1)
        body = calls[0]
        self.assertEqual(
            set(re.findall(r"--[a-z][a-z0-9-]+", body)),
            {
                "--origin-file",
                "--challenge",
                "--plan",
                "--baseline",
                "--running",
                "--invariants",
            },
        )

    def test_helper_cli_required_flags_are_all_supplied(self) -> None:
        for command in (
            "plan",
            "baseline",
            "running",
            "stage",
            "invariants",
            "record",
            "validate-record",
        ):
            with self.subTest(command=command):
                required = helper_required_flags(command)
                supplied = command_flags(self.script, command)
                self.assertEqual(required - supplied, set())

    def test_every_stage_calls_helper_and_persists_readiness(self) -> None:
        self.assertRegex(
            self.script,
            r'python "\$admission_helper" stage \\\n',
        )
        for flag in (
            "--plan",
            "--baseline",
            "--before",
            "--after",
            "--target",
            "--readiness",
            "--protected-before",
            "--protected-after",
        ):
            self.assertIn(flag, command_flags(self.script, "stage"))

    def test_success_and_failure_use_canonical_record_helper(self) -> None:
        self.assertRegex(
            self.script,
            r'python "\$admission_helper" record \\\n',
        )
        self.assertRegex(
            self.script,
            r'python "\$admission_helper" validate-record \\\n',
        )
        self.assertIn("image-rollout-record.json", self.script)
        self.assertIn("record-validation.json", self.script)
        self.assertNotRegex(
            self.script,
            r'write_text\([^\n]*image-rollout-record|json\.dump[^\n]*image-rollout-record',
        )

    def test_record_schema_gate_cannot_be_disabled_or_skipped(self) -> None:
        record_flags = command_flags(self.script, "record")
        validate_flags = command_flags(self.script, "validate-record")
        self.assertIn("--schema", record_flags)
        self.assertIn("--schema", validate_flags)
        self.assertIn("--record", validate_flags)
        self.assertNotRegex(
            self.script,
            r'(?:SKIP|DISABLE|ALLOW)[A-Z0-9_]*(?:SCHEMA|VALIDAT)',
        )
        self.assertNotRegex(self.script, r'validate-record[^\n]*(?:\|\|\s*:|\|\|\s*true)')

    def test_persistent_evidence_is_never_published_by_shell_redirection(self) -> None:
        self.assertNotRegex(
            self.script,
            r'(?m)(?:^|[;&|]\s*|\s)(?:>|>>)[ \t]*"\$rollout_dir/',
        )

    def test_raw_docker_and_verifier_output_never_enters_record_tree(self) -> None:
        for command in shell_commands(self.script):
            if re.search(r'"\$docker_bin" (?:container|image) inspect', command):
                self.assertRegex(
                    command,
                    r'\| python (?:"\$admission_helper" project-|-[c] )',
                )
                pipe = command.index("| python")
                self.assertNotIn('> "$rollout_dir/', command[:pipe])
            if 'python "$trusted_verifier"' in command:
                self.assertRegex(command, r'> "\$(?:archive_raw|source_raw)"$')
                self.assertNotIn('> "$rollout_dir/', command)
        for forbidden_name in (
            "raw-inspect",
            "docker-load.txt",
            "image-checksums.txt",
        ):
            self.assertNotIn(forbidden_name, self.script)
        self.assertNotRegex(self.script, r'"\$rollout_dir/[^"]*(?:stdout|stderr)')
        self.assertRegex(self.script, r"project-container")
        self.assertRegex(self.script, r"project-image")
        self.assertRegex(self.script, r"project-verifier")

    def test_only_offline_single_service_recreates_exist(self) -> None:
        up_calls = [
            command
            for command in shell_commands(self.script)
            if command.startswith('if ! compose_with "$') and " up -d " in command
        ]
        self.assertEqual(len(up_calls), 2)
        for body in up_calls:
            with self.subTest(command=body):
                for flag in (
                    "--no-deps",
                    "--force-recreate",
                    "--no-build",
                    "--pull never",
                ):
                    self.assertIn(flag, body)
                self.assertRegex(body, r'--wait-timeout "\$wait_timeout" "\$service"; then$')

    def test_forbidden_mutations_are_absent(self) -> None:
        forbidden = {
            "backup": r"backup-production-state|backup-production",
            "database dump": r"\bpg_dump(?:all)?\b",
            "migration": r"\balembic\s+(?:upgrade|downgrade)\b",
            "Compose down": r"compose_with[^\n]*\bdown\b|\bcompose\s+down\b",
            "Compose pull": r"compose_with[^\n]*\bpull\b(?! never)",
            "Docker pull": r'"\$docker_bin"\s+pull\b',
            "image build": r"compose_with[^\n]*\bbuild\b|\b(?:docker|buildx)\s+build\b",
            "migration service": r"(?:switch|restore)_service\s+control-migrate\b",
            "backup service": r"(?:switch|restore)_service\s+control-backup\b",
        }
        for label, pattern in forbidden.items():
            with self.subTest(label=label):
                self.assertIsNone(re.search(pattern, self.script))

    def test_runtime_executables_are_fixed_system_paths(self) -> None:
        for variable in (
            "CONTROL_DOCKER_BIN",
            "CONTROL_UFW_BIN",
            "CONTROL_SS_BIN",
            "CONTROL_SHA256SUM_BIN",
        ):
            self.assertNotIn(variable, self.script)
        for assignment in (
            "docker_bin=/usr/bin/docker",
            "ufw_bin=/usr/sbin/ufw",
            "ss_bin=/usr/bin/ss",
        ):
            self.assertIn(assignment, self.script)
        self.assertRegex(self.script, r"/usr/bin/python3 -B -I")
        self.assertNotIn("CONTROL_TEST_", self.script)
        self.assertNotRegex(
            self.script,
            r"load_capsule_value\s+(?:docker_bin|ufw_bin|ss_bin)",
        )

    def test_forward_order_is_fixed(self) -> None:
        calls = re.findall(
            r"^\s*switch_service\s+(control-api-replica|control-api|codex-pwa)\s+[123]\s+",
            self.script,
            re.MULTILINE,
        )
        self.assertEqual(calls, list(FORWARD_ORDER))

    def test_recovery_cli_and_capsule_are_explicit(self) -> None:
        self.assertIn("recover", self.script)
        self.assertIn("--confirm", self.script)
        self.assertIn("RECOVER-BOOTSTRAP-IMAGE-ROLLOUT", self.script)
        self.assertIn(".image-rollout.lock", self.script)
        self.assertRegex(self.script, r"journal")
        for direction in ("forward", "rollback"):
            for phase in ("intent", "result"):
                self.assertIn(f"journal_event {direction} {phase}", self.script)

    def test_each_archive_load_has_durable_intent_and_result(self) -> None:
        self.assertIn("journal_event load intent", self.script)
        self.assertIn("journal_event load result", self.script)

    def test_atomic_lock_capsule_protocol_is_single_path_and_complete(self) -> None:
        self.assertRegex(
            self.script,
            r"(?m)^lock_file=(?:\$record_root/\.image-rollout\.lock)?$",
        )
        self.assertIn('lock_file=$record_root/.image-rollout.lock', self.script)
        self.assertNotRegex(self.script, r"/\.image-rollout\.lock/capsule\.json")
        self.assertNotRegex(self.script, r'mkdir "\$lock_(?:dir|file)"')
        self.assertRegex(self.script, r"(?m)^read_recovery_capsule\(\) \{")
        self.assertRegex(self.script, r"(?m)^load_capsule_value\(\) \{")
        self.assertRegex(self.script, r"(?m)^initialize_event_sequence\(\) \{")
        self.assertRegex(
            self.script,
            re.compile(r'recover_main\(\).*?"\$lock_file"', re.DOTALL),
        )

    def test_root_container_gate_is_digest_pinned_and_dockerless(self) -> None:
        rendered = " ".join(ROOT_TEST_COMMAND)
        self.assertIn(ROOT_TEST_IMAGE, rendered)
        self.assertIn("--network none", rendered)
        self.assertIn("type=bind,src={repo},dst=/workspace,readonly", rendered)
        self.assertNotIn("/var/run/docker.sock", rendered)
        self.assertIn("WrapperBehaviorTests", rendered)
        self.assertIn("ln -s /usr/local/bin/python3 /usr/bin/python3", rendered)
        self.assertIn("/opt/snapshot", rendered)

    def test_frozen_d518_target_constants_remain_explicit(self) -> None:
        self.assertIn(f"TARGET_RELEASE={TARGET_RELEASE}", self.script)
        self.assertIn(f"TARGET_VCS_REF={TARGET_VCS_REF}", self.script)
        self.assertIn("TARGET_BUNDLE_ID=20260812T224530Z", self.script)
        for name in (
            "TARGET_MANIFEST_SHA256",
            "TARGET_READY_SHA256",
            "TARGET_TRANSPORT_LIST_SHA256",
            "TARGET_TRANSPORT_SHA256",
            "TARGET_API_ARCHIVE_SHA256",
            "TARGET_PWA_ARCHIVE_SHA256",
            "TARGET_TOOLS_ARCHIVE_SHA256",
        ):
            self.assertRegex(self.script, rf"(?m)^{name}=[0-9a-f]{{64}}$")


class IsolatedRolloutFixture:
    """A no-network, no-Docker fixture for the transaction wrapper.

    The helper and smoke members are deliberately mocked but installed through
    the same closed tools manifest/admission boundary as production. The mock
    helper records exact calls and emits privacy-safe canonical projections.
    """

    def __init__(self, root: Path, failure: str = "") -> None:
        self.root = root
        self.failure = failure
        self.record_root = root / "records"
        self.bundle = root / "20260812T224530Z"
        self.source = root / "target-source-d518"
        self.old_source = root / "old-source"
        self.base = root / "bootstrap-20260812T134654Z-c536c183-26e4-4e8e-9e66-db57e7053501"
        self.tools = root / "rollout-tools"
        self.bin = root / "bin"
        self.nginx = root / "nginx"
        for directory in (
            self.record_root,
            self.bundle,
            self.source,
            self.old_source,
            self.base,
            self.tools,
            self.bin,
            self.nginx,
        ):
            directory.mkdir(parents=True, exist_ok=True)
        self.record_root.chmod(0o700)
        self.calls_file = root / "calls.jsonl"
        self.state_file = root / "docker-state.json"
        self.ready = root / "production-bootstrap-20260812T224530Z.READY.json"
        self.migration = root / "migration-state.json"
        self.operator = root / "operator-exception.json"
        self.origin = root / "origin.json"
        self.tools_admission = self.tools / "rollout-tools.admission.json"
        self.old_compose = self.base / "compose-config.json"
        self._write_inputs()
        self._write_tools()
        self._write_commands()

    def _write_inputs(self) -> None:
        # Tiny fixture inputs are consumed only by the mocked admission helper.
        # Their names and ownership/mode contracts remain production-shaped.
        old_services: dict[str, dict[str, Any]] = {}
        for service in (
            "control-migrate",
            "control-api",
            "control-api-replica",
            "codex-pwa",
            "control-backup",
        ):
            component = (
                "pwa"
                if service == "codex-pwa"
                else "postgres-tools"
                if service == "control-backup"
                else "control-api"
            )
            old_services[service] = {
                "environment": {
                    "CONTROL_BUILD_VERSION": "0.1.0-bootstrap.old",
                    "CONTROL_BUILD_VCS_REF": "1" * 64,
                },
                "image": OLD_IMAGES[component],
                "labels": {
                    "org.opencontainers.image.revision": "1" * 64,
                    "org.opencontainers.image.version": "0.1.0-bootstrap.old",
                },
            }
        write_json(self.old_compose, {"name": PROJECT, "services": old_services}, 0o400)
        write_json(
            self.migration,
            {"current_revision": "20260731_0008", "head_revision": "20260731_0008"},
        )
        write_json(
            self.operator,
            {
                "schema_version": 1,
                "type": "no-duplicate-backup-operator-instruction-v1",
                "reason": "operator-prohibited-duplicate-backup",
            },
        )
        write_json(
            self.origin,
            {"origin": "https://fixture-private-origin.invalid", "schema_version": 1},
        )
        for name in (
            "bootstrap-deployment.json",
            "authenticated-smoke-closure.json",
            "plan.json",
            "images.json",
            "running-containers.json",
        ):
            write_json(self.base / name, {"fixture": name, "schema_version": 1})
        manifest = {
            "images": {
                component: {
                    "archive": archive,
                    "daemon_image_id": NEW_IMAGES[component],
                    "tag": f"fixture/{component}:{TARGET_RELEASE}",
                }
                for component, archive in (
                    ("control-api", "control-api-linux-amd64.tar"),
                    ("pwa", "pwa-linux-amd64.tar"),
                    ("postgres-tools", "postgres-tools-linux-amd64.tar"),
                )
            },
            "release": TARGET_RELEASE,
            "schema_version": 1,
            "vcs_ref": TARGET_VCS_REF,
        }
        write_json(self.bundle / "artifact-manifest.json", manifest)
        for name in (
            "control-api-linux-amd64.tar",
            "pwa-linux-amd64.tar",
            "postgres-tools-linux-amd64.tar",
        ):
            (self.bundle / name).write_bytes((name + "\n").encode("ascii"))
        (self.bundle / "bootstrap-images.sha256").write_text("fixture\n", encoding="ascii")
        (self.bundle / "transport-SHA256SUMS").write_text("fixture\n", encoding="ascii")
        write_json(
            self.ready,
            {
                "artifact_manifest_sha256": sha256(
                    (self.bundle / "artifact-manifest.json").read_bytes()
                ),
                "bundle_id": "20260812T224530Z",
                "release": TARGET_RELEASE,
                "transport": {
                    "file": "transport/production-bootstrap-20260812T224530Z.tar",
                    "sha256": "e" * 64,
                },
                "vcs_ref": TARGET_VCS_REF,
            },
            0o400,
        )
        for source in (self.source, self.old_source):
            (source / "deploy/docker-compose").mkdir(parents=True)
            (source / "target-marker.txt").write_text("d518 pristine\n", encoding="ascii")
            for path in sorted(source.rglob("*"), reverse=True):
                path.chmod(0o555 if path.is_dir() else 0o444)
            source.chmod(0o555)
        write_json(
            self.state_file,
            {
                "active": {service: "old" for service in FORWARD_ORDER},
                "consumed": [],
                "counts": {service: 0 for service in FORWARD_ORDER},
                "loaded": [],
            },
        )

    def _write_tools(self) -> None:
        paths: dict[str, Path] = {}
        for relative in TOOL_MEMBERS:
            path = self.tools / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            paths[relative] = path
        write_executable(paths["deploy/scripts/image-rollout-admission.py"], self._helper_source())
        write_executable(paths["deploy/scripts/image-rollout-smoke.py"], self._smoke_source())
        shutil.copy2(ROLLOUT, paths["deploy/scripts/rollout-bootstrap-images.sh"])
        self._patch_wrapper_copy(paths["deploy/scripts/rollout-bootstrap-images.sh"])
        paths["deploy/scripts/rollout-bootstrap-images.sh"].chmod(0o555)
        shutil.copy2(SCHEMA, paths["deploy/schemas/image-rollout-record.schema.json"])
        paths["deploy/schemas/image-rollout-record.schema.json"].chmod(0o444)
        files: dict[str, dict[str, Any]] = {}
        identity_input: dict[str, dict[str, Any]] = {}
        for relative, path in paths.items():
            mode = "0444" if relative.endswith(".json") else "0555"
            raw = path.read_bytes()
            files[relative] = {"mode": mode, "sha256": sha256(raw), "size": len(raw)}
            identity_input[relative] = dict(files[relative])
        manifest = {
            "files": files,
            "identity_sha256": sha256(canonical(identity_input)[:-1]),
            "schema_version": 1,
            "type": "image-rollout-tools-manifest-v1",
        }
        self.tools_manifest = self.tools / "rollout-tools.manifest.json"
        write_json(self.tools_manifest, manifest, 0o444)
        members = {
            relative: {
                "basename": path.name,
                **files[relative],
            }
            for relative, path in paths.items()
        }
        self.tools_archive_sha = "8" * 64
        self.tools_verifier_sha = "9" * 64
        admission = {
            "archive": {
                "basename": "image-rollout-tools.tar",
                "sha256": self.tools_archive_sha,
                "size": 1024,
            },
            "command": "extract",
            "manifest": descriptor(self.tools_manifest),
            "members": members,
            "schema_version": 1,
            "self_sha256": self.tools_verifier_sha,
            "status": "extracted",
            "tooling_identity": manifest["identity_sha256"],
            "type": "image-rollout-tools-admission-v1",
            "external_verifier": {
                "basename": "build-image-rollout-tools.py",
                "sha256": self.tools_verifier_sha,
                "size": 2048,
            },
        }
        write_json(self.tools_admission, admission, 0o444)
        for path in sorted(self.tools.rglob("*"), reverse=True):
            if path.is_dir():
                path.chmod(0o555)
        self.tools.chmod(0o555)

    def _patch_wrapper_copy(self, path: Path) -> None:
        """Bind the transaction harness to tiny admitted artifacts and offline readiness."""
        source = path.read_text(encoding="utf-8")
        replacements = {
            "TARGET_MANIFEST_SHA256": sha256(
                (self.bundle / "artifact-manifest.json").read_bytes()
            ),
            "TARGET_READY_SHA256": sha256(self.ready.read_bytes()),
            "TARGET_TRANSPORT_LIST_SHA256": sha256(
                (self.bundle / "transport-SHA256SUMS").read_bytes()
            ),
            "TARGET_TRANSPORT_SHA256": "e" * 64,
            "TARGET_API_ARCHIVE_SHA256": sha256(
                (self.bundle / "control-api-linux-amd64.tar").read_bytes()
            ),
            "TARGET_PWA_ARCHIVE_SHA256": sha256(
                (self.bundle / "pwa-linux-amd64.tar").read_bytes()
            ),
            "TARGET_TOOLS_ARCHIVE_SHA256": sha256(
                (self.bundle / "postgres-tools-linux-amd64.tar").read_bytes()
            ),
        }
        for name, value in replacements.items():
            source, count = re.subn(
                rf"(?m)^{name}=[0-9a-f]{{64}}$", f"{name}={value}", source
            )
            if count != 1:
                raise AssertionError(f"could not bind {name} in wrapper fixture")
        offline_readiness = r'''capture_readiness() {
  projection=$1
  compose=$2
  service=$3
  output=$4
  python - "$projection" "$compose" "$service" "$output" <<'PY'
import json, os, pathlib, sys
failures=set(filter(None,os.environ.get("CONTROL_TEST_FAILURE","").split(",")))
service=sys.argv[3]
if "readiness:"+service in failures: raise SystemExit(54)
projection=json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="ascii"))
compose=json.loads(pathlib.Path(sys.argv[2]).read_text(encoding="ascii"))
item=projection["containers"][service]
if item["image_id"] != compose["services"][service]["image"]: raise SystemExit(55)
value={"container_id":item["container_id"],"health":"healthy","image_id":item["image_id"],"networks":item["networks"],"ports":item["ports"],"restart_count":0,"schema_version":1,"service":service,"status":"ready"}
path=pathlib.Path(sys.argv[4]);path.write_text(json.dumps(value,sort_keys=True,separators=(",",":"))+"\n",encoding="ascii");path.chmod(0o600)
PY
  [ -f "$output" ] || return
  fsync_directory "$(/usr/bin/dirname "$output")" || return
}
'''
        source, count = re.subn(
            r"capture_readiness\(\) \{.*?\n\}\n\n(?=create_new_compose\(\))",
            lambda _match: offline_readiness + "\n",
            source,
            flags=re.DOTALL,
        )
        if count != 1:
            raise AssertionError("could not replace readiness in wrapper fixture")
        fsync_fault = r'''fsync_directory() {
  directory=$1
  case ",${CONTROL_TEST_FAILURE:-}," in
    *,capsule-directory-fsync,*)
      if [ -n "${record_root:-}" ] && [ "$directory" = "$record_root" ] \
        && [ -n "${lock_file:-}" ] && [ -f "$lock_file" ]; then
        return 74
      fi
      ;;
    *,journal-directory-fsync,*)
      if [ -n "${journal_dir:-}" ] && [ "$directory" = "$journal_dir" ]; then
        return 74
      fi
      ;;
    *,rollback-summary-directory-fsync,*)
      if [ -n "${rollout_dir:-}" ] && [ "$directory" = "$rollout_dir" ] \
        && [ -f "$rollout_dir/rollback-summary.json" ]; then
        return 74
      fi
      ;;
    *,challenge-directory-fsync,*)
      if [ -n "${rollout_dir:-}" ] && [ "$directory" = "$rollout_dir" ] \
        && [ -f "$rollout_dir/smoke-challenge.json" ]; then
        return 74
      fi
      ;;
    *,context-directory-fsync,*)
      if [ -n "${rollout_dir:-}" ] && [ "$directory" = "$rollout_dir" ] \
        && [ -f "$rollout_dir/context.json" ]; then
        return 74
      fi
      ;;
    *,terminal-directory-fsync,*)
      if [ -n "${rollout_dir:-}" ] && [ "$directory" = "$rollout_dir" ] \
        && [ -f "$rollout_dir/terminal-sha256.json" ]; then
        return 74
      fi
      ;;
  esac
  python - "$directory" <<'PY'
import os, sys
fd=os.open(sys.argv[1],os.O_RDONLY|getattr(os,"O_DIRECTORY",0)|getattr(os,"O_CLOEXEC",0))
try:os.fsync(fd)
finally:os.close(fd)
PY
}
'''
        source, count = re.subn(
            r"fsync_directory\(\) \{.*?\nPY\n\}\n",
            fsync_fault + "\n",
            source,
            flags=re.DOTALL,
        )
        if count != 1:
            raise AssertionError("could not bind deterministic fsync fault in wrapper fixture")
        partial_capsule = r'''    if "block:write:capsule" in set(filter(None, os.environ.get("CONTROL_TEST_FAILURE", "").split(","))):
        prefix = raw[:max(1, len(raw) // 2)]
        os.write(fd, prefix)
        os.fsync(fd)
        marker = pathlib.Path(os.environ["CONTROL_TEST_BLOCK_MARKER"])
        marker.write_text("write:capsule-partial\n", encoding="ascii")
        import time
        while marker.exists():
            time.sleep(0.05)
        raise SystemExit("released partial capsule fault")
'''
        source, count = re.subn(
            r'(temporary = target\.with_name\(f"\{target\.name\}\.tmp-\{os\.environ\[\'ROLLOUT_ID\'\]\}"\).*?fd = os\.open\(temporary, flags, 0o600\)\ntry:\n)',
            lambda match: match.group(1) + partial_capsule,
            source,
            count=1,
            flags=re.DOTALL,
        )
        if count != 1:
            raise AssertionError("could not instrument partial capsule publication")
        checkpoint = r'''test_checkpoint() {
  label=$1
  case ",${CONTROL_TEST_FAILURE:-}," in
    *,block:checkpoint:"$label",*) ;;
    *) return 0 ;;
  esac
  python - "$CONTROL_TEST_BLOCK_MARKER" "$label" <<'PY'
import pathlib,sys
pathlib.Path(sys.argv[1]).write_text("checkpoint:"+sys.argv[2]+"\n",encoding="ascii")
PY
  while [ -e "$CONTROL_TEST_BLOCK_MARKER" ]; do /bin/sleep 0.05; done
}

'''
        source = source.replace("write_capsule() {\n", checkpoint + "write_capsule() {\n", 1)
        source, count = re.subn(
            r'(fsync_directory "\$journal_dir" \|\| return\n  event_sequence=\$next_sequence\n)(\})',
            r'\1  test_checkpoint "journal-$direction-$phase-$service"\n\2',
            source,
            count=1,
        )
        if count != 1:
            raise AssertionError("could not instrument journal publication")
        exact_injections = {
            '  write_capsule\n  lock_owned=1\n': (
                '  test_checkpoint pre-capsule\n  write_capsule\n'
                '  lock_owned=1\n  test_checkpoint capsule-published\n'
            ),
            '  create_rollback_summary "$rollback_ok" "$invariants_restored"\n': (
                '  test_checkpoint pre-rollback-summary\n'
                '  create_rollback_summary "$rollback_ok" "$invariants_restored"\n'
                '  test_checkpoint rollback-summary\n'
            ),
            'create_challenge() {\n': (
                'create_challenge() {\n  test_checkpoint pre-challenge\n'
            ),
            '  fsync_directory "$rollout_dir"\n}\n\nrun_smoke() {': (
                '  fsync_directory "$rollout_dir"\n'
                '  test_checkpoint challenge\n}\n\nrun_smoke() {'
            ),
            'create_context() {\n  context_status=$1\n': (
                'create_context() {\n  context_status=$1\n'
                '  test_checkpoint "pre-context-$context_status"\n'
            ),
            '  fsync_directory "$rollout_dir"\n}\n\noptional_record_args() {': (
                '  fsync_directory "$rollout_dir"\n'
                '  test_checkpoint "context-$context_status"\n}\n\noptional_record_args() {'
            ),
            '    --output "$rollout_dir/image-rollout-record.json" >/dev/null\n': (
                '    --output "$rollout_dir/image-rollout-record.json" >/dev/null\n'
                '  test_checkpoint terminal-record\n'
            ),
            '  publish_canonical_json "$validation_transient" "$rollout_dir/record-validation.json" 0600\n': (
                '  publish_canonical_json "$validation_transient" "$rollout_dir/record-validation.json" 0600\n'
                '  test_checkpoint terminal-validation\n'
            ),
            "PY\n  fsync_directory \"$rollout_dir\"\n}\n\nremove_lock() {": (
                "PY\n  test_checkpoint terminal-receipt\n"
                "  fsync_directory \"$rollout_dir\"\n"
                "  test_checkpoint terminal-commit\n}\n\nremove_lock() {"
            ),
            'remove_lock() {\n': 'remove_lock() {\n  test_checkpoint pre-unlock\n',
        }
        for old, new in exact_injections.items():
            if source.count(old) != 1:
                raise AssertionError(f"could not instrument fixture checkpoint: {old!r}")
            source = source.replace(old, new, 1)
        path.write_text(source, encoding="utf-8")
        syntax = subprocess.run(
            ["sh", "-n", str(path)], check=False, capture_output=True, text=True
        )
        if syntax.returncode != 0:
            raise AssertionError(f"instrumented wrapper is invalid: {syntax.stderr}")

    def _helper_source(self) -> str:
        return r'''#!/usr/bin/python3
import hashlib
import json
import os
import pathlib
import sys

def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")

def digest(path):
    return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()

def argument(name, default=None):
    return sys.argv[sys.argv.index(name) + 1] if name in sys.argv else default

def consume(label):
    if label not in failures:
        return False
    state_path = pathlib.Path(os.environ["CONTROL_TEST_DOCKER_STATE"])
    state = json.loads(state_path.read_text(encoding="ascii"))
    if label in state["consumed"]:
        return False
    state["consumed"].append(label)
    state_path.write_bytes(canonical(state))
    return True

command = sys.argv[1] if len(sys.argv) > 1 else ""
with open(os.environ["CONTROL_TEST_CALL_LOG"], "a", encoding="utf-8") as stream:
    stream.write("helper " + " ".join(sys.argv[1:]) + "\n")
if "--help" in sys.argv:
    print("fixture helper usage")
    raise SystemExit(0)
failures = set(filter(None, os.environ.get("CONTROL_TEST_FAILURE", "").split(",")))
if consume("helper:" + command):
    raise SystemExit(31)
if command == "project-container":
    raw = json.load(sys.stdin)
    value = raw[0]
    service = argument("--service")
    print(json.dumps({"projection": value["Projection"], "schema_version": 1, "service": service}, sort_keys=True, separators=(",", ":")))
elif command == "project-image":
    value = json.load(sys.stdin)[0]
    print(json.dumps(value["Projection"], sort_keys=True, separators=(",", ":")))
elif command == "project-verifier":
    value = json.load(sys.stdin)
    print(json.dumps({"admission": argument("--kind") != "archive", "bundle_file_count": 36, "bundle_id": "20260812T224530Z", "kind": argument("--kind"), "release": "0.1.0-bootstrap.20260813.1", "schema_version": 1, "source_file_count": 1412, "source_root_verified": argument("--kind") != "archive", "status": value["status"], "vcs_ref": "d518538f6d36d0c2ff94b7b895798431ee981d6e585aac4732a6a2a2cf0ab8a9"}, sort_keys=True, separators=(",", ":")))
elif command in {"plan", "baseline", "running", "stage", "invariants"}:
    result = {"command": command, "format_version": 1, "status": "admitted"}
    if command == "invariants":
        result["unchanged"] = True
    if command == "stage":
        result["target"] = argument("--target")
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
elif command == "record":
    context = json.load(open(argument("--context"), encoding="ascii"))
    smoke_path = argument("--smoke")
    smoke = json.load(open(smoke_path, encoding="ascii")) if smoke_path else {"status": "not-run"}
    record = {"schema_version": 1, "status": context["status"], "smoke": smoke, "steps": context["steps"], "rollback": context["rollback"]}
    output = pathlib.Path(argument("--output"))
    fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        os.write(fd, canonical(record))
        os.fsync(fd)
    finally:
        os.close(fd)
    print(json.dumps(record, sort_keys=True, separators=(",", ":")))
elif command == "validate-record":
    if consume("helper:validate-record-after-read"):
        raise SystemExit(32)
    record_sha = digest(argument("--record"))
    if consume("helper:validate-record-bad-digest"):
        record_sha = "0" * 64
    print(json.dumps({"command": "validate-record", "format_version": 1, "record_sha256": record_sha, "schema_sha256": digest(argument("--schema")), "status": "valid"}, sort_keys=True, separators=(",", ":")))
else:
    raise SystemExit(33)
'''

    def _smoke_source(self) -> str:
        return r'''#!/usr/bin/python3
import hashlib
import json
import os
import pathlib
import sys
from datetime import datetime, timezone

with open(os.environ["CONTROL_TEST_CALL_LOG"], "a", encoding="utf-8") as stream:
    stream.write("smoke " + " ".join(sys.argv[1:]) + "\n")
challenge = pathlib.Path(sys.argv[sys.argv.index("--challenge") + 1]).read_bytes()
value = json.loads(challenge)
now = datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")
failures = set(filter(None, os.environ.get("CONTROL_TEST_FAILURE", "").split(",")))
result = {"challenge_sha256": hashlib.sha256(challenge).hexdigest(), "check_catalog_sha256": "3" * 64, "check_count": 9, "checks_passed": 0 if "smoke" in failures else 9, "completed_at": now, "schema_version": "image-rollout-smoke-result-v1", "started_at": now, "status": "failed" if "smoke" in failures else "passed", "target_binding_sha256": value["target"]["binding_sha256"]}
result["result_sha256"] = hashlib.sha256(json.dumps(result, sort_keys=True, separators=(",", ":")).encode("ascii")).hexdigest()
print(json.dumps(result, sort_keys=True, separators=(",", ":")))
if result["status"] == "failed":
    print("image-rollout-smoke: failed", file=sys.stderr)
raise SystemExit(0 if result["status"] == "passed" else 41)
'''

    def _write_commands(self) -> None:
        self.docker = self.bin / "docker"
        self.ufw = self.bin / "ufw"
        self.ss = self.bin / "ss"
        self.sha = self.bin / "sha256sum"
        self.verifier = self.bin / "trusted-verifier.py"
        write_executable(self.docker, self._docker_source())
        write_executable(
            self.ufw,
            "#!/usr/bin/python3\n"
            "import pathlib,sys\n"
            f"with pathlib.Path({str(self.calls_file)!r}).open('a', encoding='utf-8') as stream:\n"
            "    stream.write('ufw ' + ' '.join(sys.argv[1:]) + '\\n')\n"
            "print('Status: active')\n"
            "print('Default: deny (incoming), allow (outgoing)')\n"
            "print('fixture-private-value-must-never-reach-records')\n",
        )
        write_executable(
            self.ss,
            "#!/usr/bin/python3\n"
            "import pathlib,sys\n"
            f"with pathlib.Path({str(self.calls_file)!r}).open('a', encoding='utf-8') as stream:\n"
            "    stream.write('ss ' + ' '.join(sys.argv[1:]) + '\\n')\n"
            "print('tcp LISTEN 0 128 127.0.0.1:18090 0.0.0.0:* users:fixture-private-value-must-never-reach-records')\n",
        )
        write_executable(
            self.sha,
            "#!/bin/sh\nprintf '%s\\n' \"sha256sum $*\" >> \"$CONTROL_TEST_CALL_LOG\"\nexit 0\n",
        )
        write_executable(
            self.verifier,
            r'''#!/usr/bin/python3
import json
import os
import sys
with open(os.environ["CONTROL_TEST_CALL_LOG"], "a", encoding="utf-8") as stream:
    stream.write("verifier " + " ".join(sys.argv[1:]) + "\n")
print(json.dumps({"status": "archive-verified-non-admission" if sys.argv[1] == "verify-archive" else "verified", "secret": "fixture-secret-must-never-reach-records"}))
''',
        )

    def _docker_source(self) -> str:
        return f'''#!/usr/bin/python3
import json
import os
import pathlib
import signal
import sys
import time

SERVICES = {FORWARD_ORDER!r}
log = pathlib.Path(os.environ["CONTROL_TEST_CALL_LOG"])
state_path = pathlib.Path(os.environ["CONTROL_TEST_DOCKER_STATE"])
with log.open("a", encoding="utf-8") as stream:
    stream.write("docker " + " ".join(sys.argv[1:]) + "\\n")
state = json.loads(state_path.read_text(encoding="ascii"))

def save():
    state_path.write_text(json.dumps(state, sort_keys=True, separators=(",", ":")) + "\\n", encoding="ascii")

def consume(label):
    if "always:" + label in failures:
        return True
    if label not in failures or label in state["consumed"]:
        return False
    state["consumed"].append(label)
    save()
    return True

def block(label):
    if label not in failures:
        return
    marker = pathlib.Path(os.environ["CONTROL_TEST_BLOCK_MARKER"])
    marker.write_text(label + "\\n", encoding="ascii")
    while marker.exists():
        time.sleep(1)

def projection(service):
    active = state["active"][service]
    index = SERVICES.index(service) + 3
    if service == "codex-pwa":
        image = "sha256:" + (("c" if active == "new" else "9") * 64)
    else:
        image = "sha256:" + (("b" if active == "new" else "8") * 64)
    port = {{"control-api-replica": "18093", "control-api": "18090", "codex-pwa": "18091"}}[service]
    target = "8080/tcp" if service == "codex-pwa" else "8090/tcp"
    return {{"container_id": format(index + state["counts"][service], "064x"), "health": "healthy", "image_id": image, "networks": ["{PROJECT}_pwa-network" if service == "codex-pwa" else "sub2api-network"], "ports": [target + "=127.0.0.1:" + port], "project": "{PROJECT}", "release": "new" if active == "new" else "old", "restart_count": 0, "running": True, "service": service, "status": "running", "vcs_ref": ("2" if active == "new" else "1") * 64}}

args = sys.argv[1:]
failures = set(filter(None, os.environ.get("CONTROL_TEST_FAILURE", "").split(",")))
if args == ["compose", "version"]:
    print("Docker Compose version v2.fixture")
elif args[:1] == ["load"]:
    archive = pathlib.Path(args[args.index("--input") + 1]).name
    component = "postgres-tools" if archive.startswith("postgres-tools") else "pwa" if archive.startswith("pwa") else "control-api"
    block("block:load:" + component)
    if consume("load:" + component):
        raise SystemExit(43)
    state["loaded"].append(component)
    save()
    with log.open("a", encoding="utf-8") as stream:
        stream.write("load-mutation " + component + "\\n")
    if consume("kill:load:" + component):
        os.kill(os.getppid(), signal.SIGKILL)
    print("loaded")
elif args[:2] == ["image", "inspect"]:
    reference = args[2]
    component = "postgres-tools" if "postgres-tools" in reference else "pwa" if "pwa" in reference else "control-api"
    image_id = {{"control-api": "sha256:" + "b" * 64, "pwa": "sha256:" + "c" * 64, "postgres-tools": "sha256:" + "d" * 64}}[component]
    print(json.dumps([{{"Config": {{"Env": ["SECRET=fixture-secret-must-never-reach-records"]}}, "Projection": {{"image_id": image_id, "release": "{TARGET_RELEASE}", "schema_version": 1, "vcs_ref": "{TARGET_VCS_REF}"}}}}]))
elif args[:2] == ["container", "inspect"]:
    names = args[2:]
    if names == ["sub2api", "sub2api-postgres", "sub2api-redis"]:
        values = []
        for index, name in enumerate(("sub2api", "postgres", "redis"), 7):
            values.append({{"Config": {{"Env": ["SECRET=fixture-secret-must-never-reach-records"]}}, "Id": str(index) * 64, "Image": "sha256:" + str(index) * 64, "Name": "/" + name, "NetworkSettings": {{"Networks": {{"sub2api-network": {{}}}}, "Ports": {{}}}}, "State": {{"Health": {{"Status": "healthy"}}, "Running": True}}}})
        print(json.dumps(values))
    else:
        service = next((name for name in SERVICES if name in names[0]), SERVICES[0])
        print(json.dumps([{{"Config": {{"Env": ["SECRET=fixture-secret-must-never-reach-records"]}}, "Projection": projection(service)}}]))
elif args[:1] == ["compose"] and "ps" in args:
    service = args[-1]
    print("fixture-" + service)
elif args[:1] == ["compose"] and "up" in args:
    service = args[-1]
    snapshot = args[args.index("-f") + 1]
    direction = "rollback" if snapshot.endswith("compose-config.json") else "forward"
    block("block:" + direction + ":" + service)
    with log.open("a", encoding="utf-8") as stream:
        stream.write("transition " + direction + " " + service + "\\n")
    if consume("kill:" + direction + ":" + service):
        state["active"][service] = "old" if direction == "rollback" else "new"
        state["counts"][service] += 1
        save()
        with log.open("a", encoding="utf-8") as stream:
            stream.write("mutation " + direction + " " + service + "\\n")
        os.kill(os.getppid(), signal.SIGKILL)
    if consume(direction + ":" + service):
        raise SystemExit(42)
    state["active"][service] = "old" if direction == "rollback" else "new"
    state["counts"][service] += 1
    save()
    with log.open("a", encoding="utf-8") as stream:
        stream.write("mutation " + direction + " " + service + "\\n")
else:
    raise SystemExit(95)
'''

    def environment(self) -> dict[str, str]:
        return {
            "CONTROL_BASE_BOOTSTRAP_DIR": str(self.base),
            "CONTROL_BUNDLE_DIR": str(self.bundle),
            "CONTROL_BUNDLE_READY_RECORD": str(self.ready),
            "CONTROL_COMPOSE_PROJECT_NAME": PROJECT,
            "CONTROL_DEPLOYMENT_RECORD_DIR": str(self.record_root),
            "CONTROL_EXPECTED_TOOLS_ARCHIVE_SHA256": self.tools_archive_sha,
            "CONTROL_EXPECTED_TOOLS_VERIFIER_SHA256": self.tools_verifier_sha,
            "CONTROL_IMAGE_ROLLOUT_CONFIRM": "IMAGE_ONLY_FOLLOWUP",
            "CONTROL_IMAGE_ROLLOUT_WAIT_TIMEOUT_SECONDS": "2",
            "CONTROL_MIGRATION_STATE_FILE": str(self.migration),
            "CONTROL_NGINX_ROOT": str(self.nginx),
            "CONTROL_OLD_COMPOSE_SNAPSHOT": str(self.old_compose),
            "CONTROL_OLD_SOURCE_ROOT": str(self.old_source),
            "CONTROL_OPERATOR_NO_DUPLICATE_BACKUP_EXCEPTION_FILE": str(self.operator),
            "CONTROL_PUBLIC_ORIGIN_FILE": str(self.origin),
            "CONTROL_ROLLOUT_TOOLS_ADMISSION": str(self.tools_admission),
            "CONTROL_ROLLOUT_TOOLS_ROOT": str(self.tools),
            "CONTROL_TEST_CALL_LOG": str(self.calls_file),
            "CONTROL_TEST_BLOCK_MARKER": str(self.root / "blocked"),
            "CONTROL_TEST_DOCKER_STATE": str(self.state_file),
            "CONTROL_TEST_FAILURE": self.failure,
            "CONTROL_TRUSTED_BUNDLE_VERIFIER": str(self.verifier),
            "CONTROL_TRUSTED_BUNDLE_VERIFIER_SHA256": sha256(self.verifier.read_bytes()),
            "CONTROL_TRUSTED_SOURCE_ROOT": str(self.source),
            "HOME": str(self.root),
            "LC_ALL": "C",
            "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
            "PYTHONDONTWRITEBYTECODE": "1",
        }

    def run(self, *arguments: str) -> subprocess.CompletedProcess[bytes]:
        self.install_fixed_commands()
        return subprocess.run(
            ["sh", str(self.tools / "deploy/scripts/rollout-bootstrap-images.sh"), *arguments],
            env=self.environment(),
            check=False,
            capture_output=True,
        )

    def start(self, *arguments: str) -> subprocess.Popen[bytes]:
        self.install_fixed_commands()
        return subprocess.Popen(
            ["sh", str(self.tools / "deploy/scripts/rollout-bootstrap-images.sh"), *arguments],
            env=self.environment(),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )

    def wait_until_blocked(self, process: subprocess.Popen[bytes], label: str) -> None:
        marker = self.root / "blocked"
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            if marker.exists() and marker.read_text(encoding="ascii").strip() == label:
                return
            if process.poll() is not None:
                stdout, stderr = process.communicate()
                raise AssertionError(
                    f"wrapper exited before {label}: {process.returncode}; "
                    f"stdout={stdout!r}; stderr={stderr!r}"
                )
            time.sleep(0.02)
        raise AssertionError(f"wrapper did not reach blocking mutation {label}")

    def kill_blocked(self, process: subprocess.Popen[bytes]) -> None:
        os.killpg(process.pid, signal.SIGKILL)
        process.communicate(timeout=5)
        (self.root / "blocked").unlink(missing_ok=True)

    def release_blocked(self, process: subprocess.Popen[bytes]) -> subprocess.CompletedProcess[bytes]:
        (self.root / "blocked").unlink(missing_ok=True)
        stdout, stderr = process.communicate(timeout=20)
        return subprocess.CompletedProcess(process.args, process.returncode, stdout, stderr)

    def journal_values(self) -> list[dict[str, Any]]:
        rollouts = self.rollout_dirs()
        if len(rollouts) != 1:
            return []
        return [
            json.loads(path.read_bytes())
            for path in sorted((rollouts[0] / "journal").glob("*.json"))
        ]

    def install_fixed_commands(self) -> None:
        if os.environ.get("CONTROL_WRAPPER_TEST_CONTAINER") != "1":
            return
        for source, target in (
            (self.docker, Path("/usr/bin/docker")),
            (self.ufw, Path("/usr/sbin/ufw")),
            (self.ss, Path("/usr/bin/ss")),
        ):
            shutil.copyfile(source, target)
            target.chmod(0o555)

    def calls(self) -> list[str]:
        if not self.calls_file.exists():
            return []
        return self.calls_file.read_text(encoding="utf-8").splitlines()

    def state(self) -> dict[str, Any]:
        return json.loads(self.state_file.read_text(encoding="ascii"))

    def rollout_dirs(self) -> list[Path]:
        return sorted(self.record_root.glob("image-rollout-*"))

    @property
    def lock_path(self) -> Path:
        return self.record_root / ".image-rollout.lock"

    def record_bytes(self) -> bytes:
        return b"".join(
            path.read_bytes()
            for path in sorted(self.record_root.rglob("*"))
            if path.is_file()
        )


class RealRecordGateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(dir=temporary_parent())
        self.fixture = IsolatedRolloutFixture(Path(self.temporary.name))

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_real_helper_and_schema_validate_minimal_terminal_failure(self) -> None:
        self._assert_real_helper_gate()

    def _assert_real_helper_gate(self) -> None:
        real_root = self.fixture.root / "real-record-gate"
        scripts = real_root / "deploy/scripts"
        schemas = real_root / "deploy/schemas"
        scripts.mkdir(parents=True)
        schemas.mkdir(parents=True)
        real_root.chmod(0o700)
        helper = scripts / "image-rollout-admission.py"
        schema = schemas / "image-rollout-record.schema.json"
        shutil.copy2(ADMISSION, helper)
        shutil.copy2(SCHEMA, schema)
        helper.chmod(0o555)
        schema.chmod(0o444)
        context = {
            "completed_at": "2026-08-13T00:00:01Z",
            "created_at": "2026-08-13T00:00:00Z",
            "failure_stage": "preflight",
            "operations": {
                "archives_loaded": False,
                "backup_invoked": False,
                "build_invoked": False,
                "down_invoked": False,
                "load_invoked": False,
                "migrate_invoked": False,
                "postgres_tools_executed": False,
                "pull_invoked": False,
                "python_dont_write_bytecode": True,
            },
            "paths": {
                name: None
                for name in (
                    "archive_evidence",
                    "artifact_manifest",
                    "bootstrap_record",
                    "bundle_dir",
                    "bundle_evidence",
                    "closure_record",
                    "current_before_inspect",
                    "new_compose",
                    "old_compose",
                    "operator_exception",
                    "ready_record",
                    "smoke_challenge",
                    "source_evidence",
                    "source_root",
                    "tools_admission",
                    "tools_manifest",
                )
            },
            "rollback": {
                "completed_at": "2026-08-13T00:00:01Z",
                "evidence": None,
                "invariants_restored": True,
                "started_at": "2026-08-13T00:00:00Z",
                "status": "not-required",
                "steps": [],
                "trigger_stage": "preflight",
            },
            "rollout_id": "07e976a6-7519-41cb-ac8a-f37d860cc7de",
            "schema_version": 1,
            "status": "failed",
            "steps": [
                {
                    "after_inspect": None,
                    "completed_at": None,
                    "order": order,
                    "readiness_evidence": None,
                    "recreated": False,
                    "service": service,
                    "started_at": None,
                    "status": "not-run",
                }
                for order, service in enumerate(FORWARD_ORDER, 1)
            ],
            "type": "bootstrap-image-rollout-context-v1",
        }
        context_path = real_root / "context.json"
        record = real_root / "image-rollout-record.json"
        write_json(context_path, context)
        gate_environment = {
            **os.environ,
            "IMAGE_ROLLOUT_TEST_ALLOW_UNPRIVILEGED_TOOLS": "1",
            "PYTHONDONTWRITEBYTECODE": "1",
        }
        produced = subprocess.run(
            [
                sys.executable,
                "-B",
                "-I",
                str(helper),
                "record",
                "--context",
                str(context_path),
                "--schema",
                str(schema),
                "--output",
                str(record),
            ],
            env=gate_environment,
            check=False,
            capture_output=True,
        )
        self.assertEqual(
            produced.returncode,
            0,
            produced.stderr.decode(errors="replace"),
        )
        validated = subprocess.run(
            [
                sys.executable,
                "-B",
                "-I",
                str(helper),
                "validate-record",
                "--record",
                str(record),
                "--schema",
                str(schema),
            ],
            env=gate_environment,
            check=False,
            capture_output=True,
        )
        self.assertEqual(
            validated.returncode,
            0,
            validated.stderr.decode(errors="replace"),
        )
        self.assertEqual(json.loads(validated.stdout)["status"], "valid")
        tampered = json.loads(record.read_bytes())
        tampered["extra"] = True
        write_json(real_root / "tampered.json", tampered)
        rejected = subprocess.run(
            [
                sys.executable,
                "-B",
                "-I",
                str(helper),
                "validate-record",
                "--record",
                str(real_root / "tampered.json"),
                "--schema",
                str(schema),
            ],
            env=gate_environment,
            check=False,
            capture_output=True,
        )
        self.assertNotEqual(rejected.returncode, 0)


class WrapperBehaviorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if os.geteuid() != 0:
            raise unittest.SkipTest(
                "wrapper behavior suite requires root; run the pinned root-container gate"
            )

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(dir=temporary_parent())
        self.fixture = IsolatedRolloutFixture(Path(self.temporary.name))

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def assert_no_mutation(self) -> None:
        calls = self.fixture.calls()
        self.assertFalse(any(call.startswith("docker load ") for call in calls))
        self.assertFalse(any(call.startswith("transition ") for call in calls))

    def assert_record_hygiene(self) -> None:
        raw = self.fixture.record_bytes()
        for sentinel in PRIVATE_SENTINELS:
            with self.subTest(sentinel=sentinel):
                self.assertNotIn(sentinel, raw)
        names = [path.name for path in self.fixture.record_root.rglob("*")]
        self.assertFalse(any("raw" in name or "stdout" in name or "stderr" in name for name in names))

    def recover(self, fixture: IsolatedRolloutFixture) -> subprocess.CompletedProcess[bytes]:
        return fixture.run("recover", "--confirm", "RECOVER-BOOTSTRAP-IMAGE-ROLLOUT")

    def assert_recovery_is_journal_only(self, calls: list[str]) -> None:
        self.assertFalse(any(call.startswith("docker load ") for call in calls))
        self.assertFalse(any(call.startswith("docker image inspect ") for call in calls))
        self.assertFalse(any(call.startswith("transition forward ") for call in calls))
        self.assertFalse(any(call.startswith("smoke ") for call in calls))
        self.assertFalse(any(call.startswith("helper running ") for call in calls))
        self.assertFalse(any(call.startswith("helper stage ") for call in calls))

    def assert_no_recovery_mutation(self, calls: list[str]) -> None:
        self.assert_recovery_is_journal_only(calls)
        self.assertFalse(any(call.startswith("transition rollback ") for call in calls))

    def assert_rollback_attempts(
        self, events: list[dict[str, Any]], expected_attempts: list[int]
    ) -> None:
        intents = [value for value in events if value.get("phase") == "intent"]
        results = [value for value in events if value.get("phase") == "result"]
        self.assertEqual([value.get("attempt") for value in intents], expected_attempts)
        self.assertEqual([value.get("attempt") for value in results], expected_attempts)
        self.assertEqual(
            [(value.get("service"), value.get("started_at")) for value in intents],
            [(value.get("service"), value.get("started_at")) for value in results],
        )
        self.assertTrue(all(value.get("attempt") is not None for value in events))

    @staticmethod
    def kill_at_checkpoint(fixture: IsolatedRolloutFixture, label: str) -> None:
        fixture.failure = f"block:checkpoint:{label}"
        process = fixture.start()
        fixture.wait_until_blocked(process, f"checkpoint:{label}")
        fixture.kill_blocked(process)

    @staticmethod
    def rewrite_json(path: Path, mutate: Any) -> None:
        value = json.loads(path.read_bytes())
        mutate(value)
        write_json(path, value)

    def test_bad_confirmation_fails_before_all_side_effects(self) -> None:
        environment = self.fixture.environment()
        environment["CONTROL_IMAGE_ROLLOUT_CONFIRM"] = "wrong"
        result = subprocess.run(
            ["sh", str(self.fixture.tools / "deploy/scripts/rollout-bootstrap-images.sh")],
            env=environment,
            check=False,
            capture_output=True,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assert_no_mutation()

    def test_preload_contract_failures_do_not_load_or_recreate(self) -> None:
        mutations = (
            (self.fixture.tools_admission, "mode", lambda path: path.chmod(0o644)),
            (self.fixture.origin, "symlink", self._replace_with_symlink),
            (self.fixture.operator, "hardlink", self._replace_with_hardlink),
            (self.fixture.tools_manifest, "missing", self._remove_readonly_member),
        )
        for path, label, mutate in mutations:
            with self.subTest(label=label):
                temporary = tempfile.TemporaryDirectory(dir=temporary_parent())
                fixture = IsolatedRolloutFixture(Path(temporary.name))
                target = {
                    self.fixture.tools_admission: fixture.tools_admission,
                    self.fixture.origin: fixture.origin,
                    self.fixture.operator: fixture.operator,
                    self.fixture.tools_manifest: fixture.tools_manifest,
                }[path]
                mutate(target)
                result = fixture.run()
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(any(call.startswith("docker load ") for call in fixture.calls()))
                self.assertFalse(any(call.startswith("transition ") for call in fixture.calls()))
                temporary.cleanup()

    @staticmethod
    def _replace_with_symlink(path: Path) -> None:
        replacement = path.with_suffix(".real")
        path.rename(replacement)
        path.symlink_to(replacement)

    @staticmethod
    def _replace_with_hardlink(path: Path) -> None:
        os.link(path, path.with_suffix(".linked"))

    @staticmethod
    def _remove_readonly_member(path: Path) -> None:
        path.parent.chmod(0o755)
        path.unlink()
        path.parent.chmod(0o555)

    def test_success_has_exact_load_forward_helper_and_terminal_sequence(self) -> None:
        result = self.fixture.run()
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))
        calls = self.fixture.calls()
        self.assertEqual(sum(call.startswith("docker load --input ") for call in calls), 3)
        self.assertEqual(
            [call.removeprefix("load-mutation ") for call in calls if call.startswith("load-mutation ")],
            ["control-api", "pwa", "postgres-tools"],
        )
        self.assertEqual(
            [call for call in calls if call.startswith("transition forward ")],
            [f"transition forward {service}" for service in FORWARD_ORDER],
        )
        stages = [call for call in calls if call.startswith("helper stage ")]
        self.assertEqual(len(stages), 3)
        self.assertEqual(
            [next(service for service in FORWARD_ORDER if f"--target {service}" in call) for call in stages],
            list(FORWARD_ORDER),
        )
        self.assertEqual(sum(call.startswith("smoke ") for call in calls), 1)
        self.assertEqual(
            sum(call.startswith("helper record ") and "--help" not in call for call in calls),
            1,
        )
        self.assertEqual(
            sum(
                call.startswith("helper validate-record ") and "--help" not in call
                for call in calls
            ),
            1,
        )
        rollout = self.fixture.rollout_dirs()
        self.assertEqual(len(rollout), 1)
        for name in (
            "context.json",
            "smoke.json",
            "smoke-challenge.json",
            "image-rollout-record.json",
            "record-validation.json",
            "terminal-sha256.json",
        ):
            self.assertTrue((rollout[0] / name).is_file(), name)
        journal = sorted((rollout[0] / "journal").glob("*.json"))
        self.assertEqual(len(journal), 12)
        self.assertEqual(
            [
                (
                    json.loads(path.read_bytes())["direction"],
                    json.loads(path.read_bytes())["phase"],
                )
                for path in journal
            ],
            [
                (direction, phase)
                for direction, members in (
                    ("load", ("control-api", "pwa", "postgres-tools")),
                    ("forward", FORWARD_ORDER),
                )
                for _member in members
                for phase in ("intent", "result")
            ],
        )
        self.assertFalse((self.fixture.record_root / ".image-rollout.lock").exists())
        self.assertTrue(any(call.startswith("ufw ") for call in calls))
        self.assertTrue(any(call.startswith("ss ") for call in calls))
        self.assert_record_hygiene()

    def test_legacy_binary_override_environment_is_ignored(self) -> None:
        environment = self.fixture.environment()
        for variable in (
            "CONTROL_DOCKER_BIN",
            "CONTROL_UFW_BIN",
            "CONTROL_SS_BIN",
            "CONTROL_SHA256SUM_BIN",
        ):
            environment[variable] = "/bin/false"
        self.fixture.install_fixed_commands()
        result = subprocess.run(
            ["sh", str(self.fixture.tools / "deploy/scripts/rollout-bootstrap-images.sh")],
            env=environment,
            check=False,
            capture_output=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))
        self.assertEqual(sum(call.startswith("docker load ") for call in self.fixture.calls()), 3)

    def test_runtime_never_invokes_forbidden_verbs_or_services(self) -> None:
        result = self.fixture.run()
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))
        for call in self.fixture.calls():
            if not call.startswith("docker compose "):
                continue
            self.assertNotRegex(call, r"(?:^| )(?:down|build|pull)(?: |$)")
            self.assertNotIn("control-migrate", call)
            self.assertNotIn("control-backup", call)

    def test_normal_run_refuses_stale_lock_without_mutation(self) -> None:
        lock = self.fixture.lock_path
        write_json(lock, {"fixture": True})
        result = self.fixture.run()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"recover", result.stderr.lower())
        self.assert_no_mutation()

    def test_recovery_requires_exact_confirmation(self) -> None:
        lock = self.fixture.lock_path
        write_json(lock, {"fixture": True})
        for arguments in (("recover",), ("recover", "--confirm", "wrong")):
            with self.subTest(arguments=arguments):
                before = list(self.fixture.calls())
                result = self.fixture.run(*arguments)
                self.assertNotEqual(result.returncode, 0)
                delta = self.fixture.calls()[len(before) :]
                self.assertFalse(any(call.startswith("transition ") for call in delta))

    def test_missing_or_truncated_atomic_capsule_is_fail_closed(self) -> None:
        cases = {
            "missing": None,
            "empty": b"",
            "truncated": b'{"schema_version":1',
        }
        for label, content in cases.items():
            with self.subTest(label=label):
                temporary = tempfile.TemporaryDirectory(dir=temporary_parent())
                fixture = IsolatedRolloutFixture(Path(temporary.name))
                if content is not None:
                    fixture.lock_path.write_bytes(content)
                    fixture.lock_path.chmod(0o600)
                before = len(fixture.calls())
                result = self.recover(fixture)
                self.assertNotEqual(result.returncode, 0)
                delta = fixture.calls()[before:]
                self.assert_no_recovery_mutation(delta)
                if content is not None:
                    self.assertTrue(fixture.lock_path.exists())
                temporary.cleanup()

    def test_sigkill_during_atomic_capsule_write_leaves_no_published_partial_lock(self) -> None:
        self.fixture.failure = "block:write:capsule"
        process = self.fixture.start()
        self.fixture.wait_until_blocked(process, "write:capsule-partial")
        self.assertFalse(self.fixture.lock_path.exists())
        temporary_locks = list(self.fixture.record_root.glob(".image-rollout.lock.tmp-*"))
        self.assertEqual(len(temporary_locks), 1)
        self.assertGreater(temporary_locks[0].stat().st_size, 0)
        self.fixture.kill_blocked(process)
        self.fixture.failure = "helper:baseline"
        retry = self.fixture.run()
        self.assertNotEqual(retry.returncode, 0)
        self.assertGreaterEqual(
            sum(call.startswith("helper baseline ") for call in self.fixture.calls()), 1
        )
        self.assertEqual(list(self.fixture.record_root.glob(".image-rollout.lock.tmp-*")), [])

    def test_published_capsule_is_complete_regular_root_owned_single_link(self) -> None:
        self.fixture.failure = "block:checkpoint:capsule-published"
        process = self.fixture.start()
        self.fixture.wait_until_blocked(process, "checkpoint:capsule-published")
        lock = self.fixture.lock_path
        metadata = lock.lstat()
        self.assertTrue(stat.S_ISREG(metadata.st_mode))
        self.assertEqual(stat.S_IMODE(metadata.st_mode), 0o600)
        self.assertEqual(metadata.st_uid, 0)
        self.assertEqual(metadata.st_nlink, 1)
        capsule = json.loads(lock.read_bytes())
        self.assertEqual(capsule["paths"]["record_root"], str(self.fixture.record_root))
        self.assertEqual(capsule["paths"]["journal_dir"], str(self.fixture.rollout_dirs()[0] / "journal"))
        self.assertRegex(
            capsule["rollout_id"],
            r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
        )
        self.fixture.kill_blocked(process)

    def test_each_forward_and_post_forward_failure_rolls_back_reverse_prefix(self) -> None:
        expected = {
            "forward:control-api-replica": ("control-api-replica",),
            "forward:control-api": ("control-api", "control-api-replica"),
            "forward:codex-pwa": REVERSE_ORDER,
            "helper:running": REVERSE_ORDER,
            "helper:invariants": REVERSE_ORDER,
            "smoke": REVERSE_ORDER,
            "helper:record": REVERSE_ORDER,
        }
        for failure, reverse in expected.items():
            with self.subTest(failure=failure):
                temporary = tempfile.TemporaryDirectory(dir=temporary_parent())
                fixture = IsolatedRolloutFixture(Path(temporary.name), failure=failure)
                result = fixture.run()
                self.assertNotEqual(result.returncode, 0)
                rollback = [
                    call.removeprefix("transition rollback ")
                    for call in fixture.calls()
                    if call.startswith("transition rollback ")
                ]
                self.assertEqual(rollback, list(reverse))
                self.assertFalse(
                    any(
                        call.startswith("transition forward ")
                        for call in fixture.calls()[
                            next(
                                (
                                    index
                                    for index, call in enumerate(fixture.calls())
                                    if call.startswith("transition rollback ")
                                ),
                                len(fixture.calls()),
                            ) :
                        ]
                    )
                )
                self.assertFalse(
                    any(sentinel in fixture.record_bytes() for sentinel in PRIVATE_SENTINELS)
                )
                temporary.cleanup()

    def test_pre_invariant_failure_publishes_not_required_terminal_record(self) -> None:
        self.fixture.failure = "helper:baseline"
        result = self.fixture.run()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(any(call.startswith("transition ") for call in self.fixture.calls()))
        rollout = self.fixture.rollout_dirs()[0]
        record = json.loads((rollout / "image-rollout-record.json").read_bytes())
        self.assertEqual(record["status"], "failed")
        self.assertEqual(record["rollback"]["status"], "not-required")
        self.assertTrue((rollout / "terminal-sha256.json").is_file())
        self.assertFalse((self.fixture.record_root / ".image-rollout.lock").exists())

    def test_rollback_failure_retains_wal_then_recovery_retries_and_commits(self) -> None:
        temporary = tempfile.TemporaryDirectory(dir=temporary_parent())
        fixture = IsolatedRolloutFixture(Path(temporary.name), failure="smoke,rollback:codex-pwa")
        result = fixture.run()
        self.assertNotEqual(result.returncode, 0)
        rollback = [
            call.removeprefix("transition rollback ")
            for call in fixture.calls()
            if call.startswith("transition rollback ")
        ]
        self.assertEqual(rollback, list(REVERSE_ORDER))
        rollout = fixture.rollout_dirs()[0]
        self.assertFalse((rollout / "image-rollout-record.json").exists())
        self.assertFalse((rollout / "record-validation.json").exists())
        self.assertFalse((rollout / "terminal-sha256.json").exists())
        self.assertFalse((rollout / "rollback-summary.json").exists())
        self.assertTrue((fixture.record_root / ".image-rollout.lock").exists())
        first_round = [
            value
            for value in fixture.journal_values()
            if value.get("direction") == "rollback"
        ]
        self.assertEqual(
            [value["service"] for value in first_round if value["phase"] == "intent"],
            list(REVERSE_ORDER),
        )
        self.assertEqual(
            [value["status"] for value in first_round if value["phase"] == "result"],
            ["failed", "succeeded", "succeeded"],
        )
        self.assert_rollback_attempts(first_round, expected_attempts=[1, 2, 3])

        fixture.failure = ""
        before = len(fixture.calls())
        recovered = self.recover(fixture)
        self.assertEqual(recovered.returncode, 0, recovered.stderr.decode(errors="replace"))
        delta = fixture.calls()[before:]
        self.assert_recovery_is_journal_only(delta)
        self.assertEqual(
            [call for call in delta if call.startswith("transition rollback ")],
            ["transition rollback codex-pwa"],
        )
        record = json.loads((rollout / "image-rollout-record.json").read_bytes())
        self.assertEqual(record["status"], "failed")
        self.assertEqual(record["rollback"]["status"], "succeeded")
        self.assertTrue((rollout / "record-validation.json").is_file())
        self.assertTrue((rollout / "terminal-sha256.json").is_file())
        summary = json.loads((rollout / "rollback-summary.json").read_bytes())
        self.assertEqual(summary["status"], "succeeded")
        self.assertEqual(
            [(value["service"], value["status"]) for value in summary["steps"]],
            [
                ("codex-pwa", "failed"),
                ("control-api", "succeeded"),
                ("control-api-replica", "succeeded"),
                ("codex-pwa", "succeeded"),
            ],
        )
        self.assertFalse(fixture.lock_path.exists())
        all_rollback = [
            value
            for value in fixture.journal_values()
            if value.get("direction") == "rollback"
        ]
        self.assert_rollback_attempts(all_rollback, expected_attempts=[1, 2, 3, 4])
        temporary.cleanup()

    def test_consecutive_rollback_failures_retain_lock_without_terminal_record(self) -> None:
        self.fixture.failure = "smoke,always:rollback:codex-pwa"
        first = self.fixture.run()
        self.assertNotEqual(first.returncode, 0)
        rollout = self.fixture.rollout_dirs()[0]
        self.assertIn("transition rollback codex-pwa", self.fixture.calls())
        for _attempt in range(2):
            before = len(self.fixture.calls())
            failed_recovery = self.recover(self.fixture)
            self.assertNotEqual(failed_recovery.returncode, 0)
            delta = self.fixture.calls()[before:]
            self.assert_recovery_is_journal_only(delta)
            self.assertIn("transition rollback codex-pwa", delta)
            self.assertTrue(self.fixture.lock_path.exists())
            self.assertFalse((rollout / "image-rollout-record.json").exists())
            self.assertFalse((rollout / "record-validation.json").exists())
            self.assertFalse((rollout / "terminal-sha256.json").exists())
            self.assertFalse((rollout / "rollback-summary.json").exists())
        rollback_events = [
            value
            for value in self.fixture.journal_values()
            if value.get("direction") == "rollback"
        ]
        attempts = [value["attempt"] for value in rollback_events if value["phase"] == "intent"]
        self.assertEqual(attempts, list(range(1, len(attempts) + 1)))

    def test_record_commit_interruptions_never_rollback_and_recovery_completes(self) -> None:
        cases = (
            ("helper:validate-record", None),
            ("block:checkpoint:terminal-record", "checkpoint:terminal-record"),
            ("block:checkpoint:terminal-validation", "checkpoint:terminal-validation"),
            ("block:checkpoint:terminal-receipt", "checkpoint:terminal-receipt"),
            ("terminal-directory-fsync", None),
        )
        for failure, marker in cases:
            with self.subTest(failure=failure):
                temporary = tempfile.TemporaryDirectory(dir=temporary_parent())
                fixture = IsolatedRolloutFixture(Path(temporary.name), failure=failure)
                if marker is None:
                    interrupted = fixture.run()
                    self.assertNotEqual(interrupted.returncode, 0)
                else:
                    process = fixture.start()
                    fixture.wait_until_blocked(process, marker)
                    fixture.kill_blocked(process)
                rollout = fixture.rollout_dirs()[0]
                self.assertTrue((rollout / "image-rollout-record.json").is_file())
                self.assertFalse(
                    any(call.startswith("transition rollback ") for call in fixture.calls())
                )
                self.assertTrue(fixture.lock_path.exists())
                before = len(fixture.calls())
                fixture.failure = ""
                recovered = self.recover(fixture)
                self.assertEqual(
                    recovered.returncode,
                    0,
                    recovered.stderr.decode(errors="replace"),
                )
                delta = fixture.calls()[before:]
                self.assert_recovery_is_journal_only(delta)
                self.assertFalse(any(call.startswith("transition rollback ") for call in delta))
                self.assertTrue((rollout / "record-validation.json").is_file())
                self.assertGreater((rollout / "record-validation.json").stat().st_size, 0)
                self.assertTrue((rollout / "terminal-sha256.json").is_file())
                self.assertFalse(fixture.lock_path.exists())
                temporary.cleanup()

    def test_true_sigkill_after_forward_intent_before_mutation_recovers_conservatively(self) -> None:
        for service in FORWARD_ORDER:
            with self.subTest(service=service):
                temporary = tempfile.TemporaryDirectory(dir=temporary_parent())
                fixture = IsolatedRolloutFixture(
                    Path(temporary.name), failure=f"block:forward:{service}"
                )
                process = fixture.start()
                fixture.wait_until_blocked(process, f"block:forward:{service}")
                self.assertTrue(
                    any(
                        value.get("direction") == "forward"
                        and value.get("phase") == "intent"
                        and value.get("service") == service
                        for value in fixture.journal_values()
                    )
                )
                self.assertFalse(
                    any(call == f"mutation forward {service}" for call in fixture.calls())
                )
                fixture.kill_blocked(process)
                fixture.failure = ""
                before = len(fixture.calls())
                recovered = self.recover(fixture)
                self.assertEqual(
                    recovered.returncode,
                    0,
                    recovered.stderr.decode(errors="replace"),
                )
                delta = fixture.calls()[before:]
                self.assert_recovery_is_journal_only(delta)
                self.assertIn(f"transition rollback {service}", delta)
                self.assertEqual(
                    fixture.state()["active"], {name: "old" for name in FORWARD_ORDER}
                )
                temporary.cleanup()

    def test_load_intent_result_and_sigkill_boundaries_recover_without_reloading(self) -> None:
        components = ("control-api", "pwa", "postgres-tools")
        for component in components:
            for boundary in ("intent", "mutation"):
                with self.subTest(component=component, boundary=boundary):
                    temporary = tempfile.TemporaryDirectory(dir=temporary_parent())
                    failure = (
                        f"block:load:{component}"
                        if boundary == "intent"
                        else f"kill:load:{component}"
                    )
                    fixture = IsolatedRolloutFixture(Path(temporary.name), failure=failure)
                    if boundary == "intent":
                        process = fixture.start()
                        fixture.wait_until_blocked(process, f"block:load:{component}")
                        self.assertNotIn(component, fixture.state()["loaded"])
                        fixture.kill_blocked(process)
                    else:
                        killed = fixture.run()
                        self.assertNotEqual(killed.returncode, 0)
                        self.assertIn(component, fixture.state()["loaded"])
                        self.assertIn(f"load-mutation {component}", fixture.calls())
                    load_events = [
                        value
                        for value in fixture.journal_values()
                        if value.get("direction") == "load" and value.get("service") == component
                    ]
                    self.assertEqual([value["phase"] for value in load_events], ["intent"])
                    fixture.failure = ""
                    before = len(fixture.calls())
                    recovered = self.recover(fixture)
                    self.assertEqual(
                        recovered.returncode,
                        0,
                        recovered.stderr.decode(errors="replace"),
                    )
                    self.assert_recovery_is_journal_only(fixture.calls()[before:])
                    self.assertFalse(
                        (fixture.record_root / ".image-rollout.lock").exists()
                    )
                    temporary.cleanup()

    def test_recovery_sigkill_at_rollback_intent_is_repeatable_and_conservative(self) -> None:
        fixture = self.fixture
        fixture.failure = "smoke,block:rollback:codex-pwa"
        normal = fixture.start()
        fixture.wait_until_blocked(normal, "block:rollback:codex-pwa")
        self.assertEqual(fixture.state()["active"]["codex-pwa"], "new")
        fixture.kill_blocked(normal)
        first_recovery_start = len(fixture.calls())
        fixture.failure = "block:rollback:codex-pwa"
        first_recovery = fixture.start(
            "recover", "--confirm", "RECOVER-BOOTSTRAP-IMAGE-ROLLOUT"
        )
        fixture.wait_until_blocked(first_recovery, "block:rollback:codex-pwa")
        self.assert_recovery_is_journal_only(fixture.calls()[first_recovery_start:])
        fixture.kill_blocked(first_recovery)
        fixture.failure = ""
        second_recovery_start = len(fixture.calls())
        recovered = self.recover(fixture)
        self.assertEqual(recovered.returncode, 0, recovered.stderr.decode(errors="replace"))
        self.assert_recovery_is_journal_only(fixture.calls()[second_recovery_start:])
        self.assertEqual(
            fixture.state()["active"], {name: "old" for name in FORWARD_ORDER}
        )
        self.assertFalse((fixture.record_root / ".image-rollout.lock").exists())

    def test_sigkill_after_each_forward_mutation_requires_journal_recovery(self) -> None:
        expected = {
            "control-api-replica": ("control-api-replica",),
            "control-api": ("control-api", "control-api-replica"),
            "codex-pwa": REVERSE_ORDER,
        }
        for service, reverse in expected.items():
            with self.subTest(service=service):
                temporary = tempfile.TemporaryDirectory(dir=temporary_parent())
                fixture = IsolatedRolloutFixture(
                    Path(temporary.name), failure=f"kill:forward:{service}"
                )
                killed = fixture.run()
                self.assertNotEqual(killed.returncode, 0)
                self.assertEqual(fixture.state()["active"][service], "new")
                lock = fixture.record_root / ".image-rollout.lock"
                self.assertTrue(lock.is_file())
                journal = fixture.rollout_dirs()[0] / "journal"
                self.assertTrue(
                    any(
                        "forward-intent" in path.name and service in path.name
                        for path in journal.glob("*.json")
                    )
                )
                before = len(fixture.calls())
                normal = fixture.run()
                self.assertNotEqual(normal.returncode, 0)
                self.assertFalse(
                    any(
                        call.startswith(("docker load ", "transition ", "smoke "))
                        for call in fixture.calls()[before:]
                    )
                )
                recovered = fixture.run(
                    "recover", "--confirm", "RECOVER-BOOTSTRAP-IMAGE-ROLLOUT"
                )
                self.assertEqual(
                    recovered.returncode,
                    0,
                    recovered.stderr.decode(errors="replace"),
                )
                rollback = [
                    call.removeprefix("transition rollback ")
                    for call in fixture.calls()
                    if call.startswith("transition rollback ")
                ]
                self.assertEqual(rollback, list(reverse))
                self.assertFalse(lock.exists())
                self.assertEqual(
                    fixture.state()["active"],
                    {name: "old" for name in FORWARD_ORDER},
                )
                temporary.cleanup()

    def test_recovery_never_loads_forwards_or_smokes(self) -> None:
        self.fixture.failure = "kill:forward:control-api"
        killed = self.fixture.run()
        self.assertNotEqual(killed.returncode, 0)
        before = len(self.fixture.calls())
        recovered = self.fixture.run(
            "recover", "--confirm", "RECOVER-BOOTSTRAP-IMAGE-ROLLOUT"
        )
        self.assertEqual(recovered.returncode, 0, recovered.stderr.decode(errors="replace"))
        recovery_calls = self.fixture.calls()[before:]
        self.assertFalse(any(call.startswith("docker load ") for call in recovery_calls))
        self.assertFalse(any(call.startswith("transition forward ") for call in recovery_calls))
        self.assertFalse(any(call.startswith("smoke ") for call in recovery_calls))

    def test_bad_journal_or_capsule_metadata_causes_zero_recovery_mutation(self) -> None:
        mutators = {
            "capsule-mode": lambda _fixture, lock, _journal: lock.chmod(0o644),
            "capsule-hardlink": self._hardlink_capsule,
            "capsule-symlink": self._symlink_capsule,
            "capsule-truncated": self._truncate_capsule,
            "journal-hardlink": self._hardlink_journal,
            "journal-mode": self._mode_journal,
            "journal-symlink": self._symlink_journal,
            "journal-extra": self._extra_journal,
            "journal-gap": self._gap_journal,
            "journal-duplicate-sequence": self._duplicate_journal_sequence,
            "journal-wrong-rollout-id": self._wrong_journal_rollout,
            "journal-partial-temp": self._partial_journal_temp,
            "old-compose-content-drift": self._drift_old_compose_content,
            "old-compose-inode-drift": self._drift_old_compose_inode,
        }
        for label, mutate in mutators.items():
            with self.subTest(label=label):
                temporary = tempfile.TemporaryDirectory(dir=temporary_parent())
                fixture = IsolatedRolloutFixture(
                    Path(temporary.name), failure="kill:forward:control-api-replica"
                )
                killed = fixture.run()
                self.assertNotEqual(killed.returncode, 0)
                self.assertIn(
                    "mutation forward control-api-replica", fixture.calls(), label
                )
                lock = fixture.lock_path
                journal = fixture.rollout_dirs()[0] / "journal"
                mutate(fixture, lock, journal)
                before = len(fixture.calls())
                result = self.recover(fixture)
                self.assertNotEqual(result.returncode, 0)
                delta = fixture.calls()[before:]
                self.assert_no_recovery_mutation(delta)
                self.assertTrue(lock.exists())
                temporary.cleanup()

    @staticmethod
    def _symlink_capsule(_fixture: IsolatedRolloutFixture, lock: Path, _journal: Path) -> None:
        real = lock.with_name("capsule.real.json")
        lock.rename(real)
        lock.symlink_to(real.name)

    @staticmethod
    def _hardlink_capsule(_fixture: IsolatedRolloutFixture, lock: Path, _journal: Path) -> None:
        os.link(lock, lock.with_name("capsule.linked.json"))

    @staticmethod
    def _truncate_capsule(_fixture: IsolatedRolloutFixture, lock: Path, _journal: Path) -> None:
        lock.write_bytes(lock.read_bytes()[:32])
        lock.chmod(0o600)

    @staticmethod
    def _hardlink_journal(
        _fixture: IsolatedRolloutFixture, _lock: Path, journal: Path
    ) -> None:
        target = next(journal.glob("*.json"))
        os.link(target, journal / "hardlink.json")

    @staticmethod
    def _mode_journal(
        _fixture: IsolatedRolloutFixture, _lock: Path, journal: Path
    ) -> None:
        next(journal.glob("*.json")).chmod(0o644)

    @staticmethod
    def _symlink_journal(
        _fixture: IsolatedRolloutFixture, _lock: Path, journal: Path
    ) -> None:
        target = next(journal.glob("*.json"))
        real = target.with_suffix(".real")
        target.rename(real)
        target.symlink_to(real.name)

    @staticmethod
    def _extra_journal(
        _fixture: IsolatedRolloutFixture, _lock: Path, journal: Path
    ) -> None:
        write_json(journal / "999-unknown-event.json", {"schema_version": 1})

    @staticmethod
    def _gap_journal(
        _fixture: IsolatedRolloutFixture, _lock: Path, journal: Path
    ) -> None:
        target = sorted(journal.glob("*.json"))[0]
        match = re.match(r"^(\d{6})(-.+)$", target.name)
        if match is None:
            raise AssertionError(f"unexpected journal name: {target.name}")
        target.rename(target.with_name(f"{int(match.group(1)) + 1:06d}{match.group(2)}"))

    @staticmethod
    def _duplicate_journal_sequence(
        _fixture: IsolatedRolloutFixture, _lock: Path, journal: Path
    ) -> None:
        target = sorted(journal.glob("*.json"))[0]
        if "-load-" in target.name:
            duplicate_name = target.name.replace("-load-", "-forward-", 1)
        elif "-forward-" in target.name:
            duplicate_name = target.name.replace("-forward-", "-rollback-", 1)
        else:
            duplicate_name = target.name.replace("-rollback-", "-forward-", 1)
        duplicate = target.with_name(duplicate_name)
        if duplicate == target:
            raise AssertionError(f"could not forge duplicate sequence: {target.name}")
        duplicate.write_bytes(target.read_bytes())
        duplicate.chmod(0o600)

    @staticmethod
    def _wrong_journal_rollout(
        _fixture: IsolatedRolloutFixture, _lock: Path, journal: Path
    ) -> None:
        target = next(journal.glob("*.json"))
        value = json.loads(target.read_bytes())
        value["rollout_id"] = "00000000-0000-4000-8000-000000000000"
        write_json(target, value)

    @staticmethod
    def _partial_journal_temp(
        _fixture: IsolatedRolloutFixture, _lock: Path, journal: Path
    ) -> None:
        events = sorted(journal.glob("*.json"))
        sequence = len(events) + 1
        path = journal / f".{sequence:06d}-rollback-intent-control-api-replica.json.tmp"
        path.write_bytes(b'{"partial":')
        path.chmod(0o644)

    @staticmethod
    def _drift_old_compose_content(
        fixture: IsolatedRolloutFixture, _lock: Path, _journal: Path
    ) -> None:
        fixture.old_compose.chmod(0o600)
        fixture.old_compose.write_bytes(fixture.old_compose.read_bytes() + b" ")
        fixture.old_compose.chmod(0o400)

    @staticmethod
    def _drift_old_compose_inode(
        fixture: IsolatedRolloutFixture, _lock: Path, _journal: Path
    ) -> None:
        original = fixture.old_compose
        original.parent.chmod(0o755)
        replacement = original.with_suffix(".replacement.json")
        replacement.write_bytes(original.read_bytes())
        replacement.chmod(0o400)
        original.unlink()
        replacement.rename(original)
        original.parent.chmod(0o555)


if __name__ == "__main__":
    unittest.main()
