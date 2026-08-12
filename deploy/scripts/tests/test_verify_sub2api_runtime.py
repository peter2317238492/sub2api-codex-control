from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from datetime import UTC, datetime
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[3]
RUNTIME = REPO_ROOT / "deploy/scripts/verify-sub2api-runtime.py"
RUNTIME_SHELL = REPO_ROOT / "deploy/scripts/verify-sub2api-runtime.sh"
RUNTIME_SPEC = importlib.util.spec_from_file_location("verify_sub2api_runtime", RUNTIME)
assert RUNTIME_SPEC is not None and RUNTIME_SPEC.loader is not None
RUNTIME_MODULE = importlib.util.module_from_spec(RUNTIME_SPEC)
RUNTIME_SPEC.loader.exec_module(RUNTIME_MODULE)


def write_json(path: Path, value: object, mode: int = 0o600) -> None:
    path.write_text(json.dumps(value), encoding="utf-8")
    path.chmod(mode)


class RuntimeVerifierHardeningTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.contract = self.root / "auth-contract.json"
        self.contract.write_text('{"format_version":1}\n', encoding="utf-8")
        self.contract.chmod(0o444)
        self.contract_sha = hashlib.sha256(self.contract.read_bytes()).hexdigest()
        self.image_ref = f"registry.example/sub2api@sha256:{'4' * 64}"
        self.container_id = "5" * 64
        self.image_id = f"sha256:{'6' * 64}"
        self.commit = "7" * 40
        self.version = "9.8.7"
        self.built_at = "2026-07-30T12:34:56Z"
        self.binary_sha = "8" * 64
        self.network = "sub2api-network"
        self.probe_nonce = "a" * 64
        self.probe_user_id = "fixture-user"
        self.probe_base_url = "http://127.0.0.1:8080"
        self.labels = {
            "org.opencontainers.image.version": self.version,
            "org.opencontainers.image.revision": self.commit,
            "org.opencontainers.image.source": "https://github.com/Wei-Shaw/sub2api",
        }
        self.lock = {
            "format_version": 1,
            "sub2api": {
                "container_image": self.image_ref,
                "container_image_id": self.image_id,
                "runtime_binary_sha256": self.binary_sha,
                "runtime_version": self.version,
                "runtime_commit": self.commit,
                "runtime_built_at": self.built_at,
                "image_created": self.built_at,
                "release_url": "https://github.com/Wei-Shaw/sub2api/releases/tag/v9.8.7",
                "image_label_version": self.version,
                "image_label_commit": self.commit,
                "auth_contract_file": self.contract.name,
                "auth_contract_sha256": self.contract_sha,
            },
        }
        image_process = {"Entrypoint": ["/app/sub2api"], "Cmd": ["serve"]}
        self.container = {
            "Id": self.container_id,
            "Name": "/sub2api",
            "Image": self.image_id,
            "Path": "/app/sub2api",
            "Args": ["serve"],
            "Config": {
                "Image": self.image_ref,
                "Labels": self.labels,
                **image_process,
            },
            "HostConfig": {
                "ReadonlyRootfs": True,
                "Privileged": False,
                "CapAdd": None,
                "CapDrop": ["ALL"],
                "SecurityOpt": ["no-new-privileges:true"],
                "PidMode": "",
                "IpcMode": "private",
                "UTSMode": "",
                "UsernsMode": "",
                "CgroupnsMode": "private",
                "NetworkMode": self.network,
                "Devices": [],
                "DeviceRequests": [],
                "DeviceCgroupRules": None,
                "Binds": None,
                "VolumesFrom": None,
                "Tmpfs": None,
                "PublishAllPorts": False,
                "PortBindings": copy.deepcopy(RUNTIME_MODULE.EXPECTED_PORT_BINDINGS),
            },
            "State": {
                "Running": True,
                "Paused": False,
                "Restarting": False,
                "OOMKilled": False,
                "Dead": False,
                "Health": {"Status": "healthy"},
                "Pid": 4242,
            },
            "RestartCount": 0,
            "Mounts": [
                {
                    "Destination": "/app/data",
                    "Type": "volume",
                    "Name": "sub2api-data",
                    "RW": True,
                }
            ],
            "NetworkSettings": {
                "Ports": copy.deepcopy(RUNTIME_MODULE.EXPECTED_PORT_BINDINGS),
                "Networks": {
                    self.network: {
                        "Aliases": ["sub2api", "sub2api-1"],
                        "NetworkID": "network-id",
                        "EndpointID": "endpoint-id",
                        "IPAddress": "172.20.0.2",
                    }
                },
            },
        }
        self.image = {
            "Id": self.image_id,
            "RepoDigests": [self.image_ref],
            "Created": self.built_at,
            "Config": {"Labels": self.labels, **image_process},
        }
        self.evidence = {
            "format_version": 4,
            "captured_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            "probe": {
                "base_url": self.probe_base_url,
                "nonce": self.probe_nonce,
                "expected_user_id": self.probe_user_id,
                "network_namespace_container_id": self.container_id,
                "proxy_environment_disabled": True,
            },
            "runtime": {
                "container_id": self.container_id,
                "image_id": self.image_id,
                "image_digest": self.image_ref,
                "binary_sha256": self.binary_sha,
                "version": self.version,
                "commit": self.commit,
                "contract_sha256": self.contract_sha,
            },
            "contract_sha256": self.contract_sha,
            "fixtures": {
                "auth_me_success": {
                    "status": 200,
                    "identity_present": True,
                    "user_id": self.probe_user_id,
                },
                "auth_me_disabled": {"status": 401, "code": "USER_INACTIVE"},
                "auth_me_revoked": {"status": 401, "code": "TOKEN_REVOKED"},
                "auth_me_session_binding_mismatch": {
                    "status": 401,
                    "code": "SESSION_BINDING_MISMATCH",
                    "ip_and_user_agent_changed": True,
                },
                "refresh_rotation": {
                    "status": 200,
                    "access_token_present": True,
                    "refresh_token_present": True,
                    "expires_in_positive": True,
                    "token_type": "Bearer",
                    "refresh_rotated": True,
                    "refreshed_identity_status": 200,
                    "same_identity": True,
                    "old_refresh_rejected_status": 401,
                },
                "logout": {"status": 204, "refresh_after_logout_status": 401},
            },
        }

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def invoke(
        self,
        *,
        container: dict[str, object] | None = None,
        after: dict[str, object] | None = None,
        name_after: dict[str, object] | None = None,
        image: dict[str, object] | None = None,
        lock: dict[str, object] | None = None,
        diff_lines: list[str] | None = None,
        pid1_host_pid: int = 4242,
        pid1_path: str = "/app/sub2api",
        pid1_sha256: str | None = None,
        expected_network: str | None = None,
        expected_alias: str = "sub2api",
        evidence_path: Path | None = None,
        contract_path: Path | None = None,
        success: bool = True,
    ) -> subprocess.CompletedProcess[str]:
        selected = container if container is not None else self.container
        selected_after = after if after is not None else selected
        selected_name_after = name_after if name_after is not None else selected_after
        write_json(self.root / "versions.lock.json", lock or self.lock)
        write_json(self.root / "container.json", [selected])
        write_json(self.root / "after.json", [selected_after])
        write_json(self.root / "name-after.json", [selected_name_after])
        write_json(self.root / "image.json", [image or self.image])
        if evidence_path is None:
            evidence_path = self.root / "evidence.json"
            write_json(evidence_path, self.evidence)
        if contract_path is None:
            contract_path = self.contract
        (self.root / "version.txt").write_text(
            f"Sub2API {self.version} commit {self.commit} built {self.built_at}\n",
            encoding="utf-8",
        )
        (self.root / "diff.txt").write_text(
            "" if not diff_lines else "\n".join(diff_lines) + "\n", encoding="utf-8"
        )
        result = subprocess.run(
            [
                sys.executable,
                str(RUNTIME),
                "--lock",
                str(self.root / "versions.lock.json"),
                "--contract-file",
                str(contract_path),
                "--container-inspect",
                str(self.root / "container.json"),
                "--container-inspect-after",
                str(self.root / "after.json"),
                "--container-name-inspect-after",
                str(self.root / "name-after.json"),
                "--image-inspect",
                str(self.root / "image.json"),
                "--binary-sha256",
                self.binary_sha,
                "--pid1-host-pid",
                str(pid1_host_pid),
                "--pid1-path",
                pid1_path,
                "--pid1-sha256",
                pid1_sha256 or self.binary_sha,
                "--version-output",
                str(self.root / "version.txt"),
                "--diff",
                str(self.root / "diff.txt"),
                "--expected-network",
                expected_network or self.network,
                "--expected-alias",
                expected_alias,
                "--auth-evidence",
                str(evidence_path),
                "--require-auth-evidence",
                "--auth-probe-nonce",
                self.probe_nonce,
                "--auth-probe-user-id",
                self.probe_user_id,
                "--auth-probe-base-url",
                self.probe_base_url,
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        if success and result.returncode != 0:
            self.fail(f"runtime verifier failed: {result.stderr}")
        if not success and result.returncode == 0:
            self.fail(f"runtime verifier unexpectedly passed: {result.stdout}")
        return result

    def test_accepts_real_docker_id_and_attests_pid1_and_restart_count(self) -> None:
        result = self.invoke()
        attestation = json.loads(result.stdout)
        self.assertEqual(attestation["container_id"], self.container_id)
        self.assertEqual(attestation["image_id"], self.image_id)
        self.assertEqual(attestation["pid1_path"], "/app/sub2api")
        self.assertEqual(attestation["pid1_args"], ["serve"])
        self.assertEqual(attestation["restart_count"], 0)
        self.assertEqual(attestation["admission_profile"], "immutable-image-v1")
        self.assertNotIn("mutable_rootfs", attestation)

    def test_legacy_lock_fields_fail_closed_for_every_value(self) -> None:
        cases = {
            "production_admission_profile": [
                None,
                RUNTIME_MODULE.IMMUTABLE_PROFILE,
                "legacy-self-updated-production-v1",
                "skip-checks",
            ],
            "production_compatibility": [None, {}, {"allowed_diff": []}],
        }
        for field, values in cases.items():
            for value in values:
                with self.subTest(field=field, value=value):
                    lock = copy.deepcopy(self.lock)
                    lock["sub2api"][field] = value
                    result = self.invoke(lock=lock, success=False)
                    self.assertIn("prohibited legacy Sub2API fields", result.stderr)

    def test_rejects_symlinked_contract_snapshot(self) -> None:
        alias = self.root / "contract-alias.json"
        alias.symlink_to(self.contract)
        self.invoke(contract_path=alias, success=False)

    def test_contract_snapshot_rejects_hardlink(self) -> None:
        hardlink = self.root / "contract-hardlink.json"
        os.link(self.contract, hardlink)
        result = self.invoke(contract_path=self.contract, success=False)
        self.assertIn(
            "Sub2API auth contract snapshot must have exactly one filesystem link",
            result.stderr,
        )

    def test_contract_snapshot_rejects_wrong_euid_and_oversize(self) -> None:
        with (
            mock.patch.object(
                RUNTIME_MODULE.os, "geteuid", return_value=os.geteuid() + 1
            ),
            self.assertRaisesRegex(ValueError, "owned by the deployment user"),
        ):
            RUNTIME_MODULE.read_immutable_contract_bytes(
                self.contract,
                "Sub2API auth contract snapshot",
                max_bytes=RUNTIME_MODULE.MAX_AUTH_CONTRACT_BYTES,
            )

        self.contract.chmod(0o644)
        self.contract.write_bytes(b"{" + b" " * RUNTIME_MODULE.MAX_AUTH_CONTRACT_BYTES)
        self.contract.chmod(0o444)
        result = self.invoke(contract_path=self.contract, success=False)
        self.assertIn(
            "Sub2API auth contract snapshot size is outside the accepted range",
            result.stderr,
        )

    def test_contract_snapshot_requires_exact_immutable_bundle_mode(self) -> None:
        self.contract.chmod(0o444)
        self.invoke()

        rejected_modes = {
            "owner-writable": 0o644,
            "private-writable": 0o600,
            "executable": 0o555,
            "missing-shared-read-bits": 0o400,
        }
        for label, mode in rejected_modes.items():
            with self.subTest(label=label, mode=f"{mode:04o}"):
                self.contract.chmod(mode)
                result = self.invoke(success=False)
                self.assertIn(
                    "Sub2API auth contract snapshot must have exact mode 0444",
                    result.stderr,
                )

        self.contract.chmod(0o000)
        result = self.invoke(success=False)
        self.assertRegex(
            result.stderr,
            r"Sub2API auth contract snapshot.*(?:exact mode 0444|without following symlinks)",
        )

    def test_accepts_immutable_cmd_form_pid1(self) -> None:
        container = copy.deepcopy(self.container)
        image = copy.deepcopy(self.image)
        container["Config"]["Entrypoint"] = None
        container["Config"]["Cmd"] = ["/app/sub2api", "serve"]
        image["Config"]["Entrypoint"] = None
        image["Config"]["Cmd"] = ["/app/sub2api", "serve"]
        self.invoke(container=container, image=image)

    def test_shell_uses_container_subcommands_and_bare_container_id(self) -> None:
        write_json(self.root / "versions.lock.json", self.lock)
        write_json(self.root / "container-runtime.json", [self.container])
        write_json(self.root / "image-runtime.json", [self.image])
        write_json(self.root / "evidence-runtime.json", self.evidence)
        fake_bin = self.root / "bin"
        fake_bin.mkdir()
        docker = fake_bin / "docker"
        docker.write_text(
            """#!/usr/bin/env python3
import os
import pathlib
import sys

root = pathlib.Path(os.environ["FAKE_DOCKER_ROOT"])
args = sys.argv[1:]
with (root / "docker-commands.log").open("a", encoding="utf-8") as log:
    log.write(" ".join(args) + "\\n")
if args[:2] == ["container", "inspect"]:
    sys.stdout.write((root / "container-runtime.json").read_text())
elif args[:2] == ["image", "inspect"]:
    sys.stdout.write((root / "image-runtime.json").read_text())
elif args[:2] == ["container", "diff"]:
    pass
elif args[:3] == ["container", "exec", "5" * 64]:
    command = args[3:]
    if command == ["sha256sum", "/app/sub2api"]:
        print("8" * 64, " /app/sub2api")
    elif command == ["/app/sub2api", "--version"]:
        print("Sub2API 9.8.7 commit " + "7" * 40 + " built 2026-07-30T12:34:56Z")
    else:
        raise SystemExit("unexpected container exec: " + repr(command))
else:
    raise SystemExit("unexpected docker command: " + repr(args))
""",
            encoding="utf-8",
        )
        docker.chmod(0o700)
        fake_readlink = fake_bin / "readlink"
        fake_readlink.write_text(
            "#!/bin/sh\n[ \"$1\" = /proc/4242/exe ] || exit 2\nprintf '%s\\n' /app/sub2api\n",
            encoding="utf-8",
        )
        fake_readlink.chmod(0o700)
        fake_sha256sum = fake_bin / "sha256sum"
        fake_sha256sum.write_text(
            "#!/bin/sh\n[ \"$1\" = /proc/4242/exe ] || exit 2\nprintf '%s  %s\\n' '"
            + self.binary_sha
            + '\' "$1"\n',
            encoding="utf-8",
        )
        fake_sha256sum.chmod(0o700)
        environment = os.environ.copy()
        environment.update(
            {
                "PATH": f"{fake_bin}:{environment['PATH']}",
                "FAKE_DOCKER_ROOT": str(self.root),
                "VERSIONS_LOCK_FILE": str(self.root / "versions.lock.json"),
                "SUB2API_AUTH_CONTRACT_FILE": str(self.contract),
                "SUB2API_EXPECTED_NETWORK": self.network,
                "SUB2API_AUTH_EVIDENCE_FILE": str(self.root / "evidence-runtime.json"),
                "SUB2API_REQUIRE_AUTH_EVIDENCE": "1",
                "SUB2API_AUTH_EVIDENCE_NONCE": self.probe_nonce,
                "SUB2API_AUTH_EVIDENCE_EXPECTED_USER_ID": self.probe_user_id,
                "SUB2API_AUTH_EVIDENCE_BASE_URL": self.probe_base_url,
            }
        )
        result = subprocess.run(
            ["sh", str(RUNTIME_SHELL)],
            check=False,
            capture_output=True,
            text=True,
            env=environment,
        )
        if result.returncode != 0:
            self.fail(f"shell verifier failed: {result.stderr}")
        commands = (self.root / "docker-commands.log").read_text(encoding="utf-8")
        self.assertIn("container inspect sub2api", commands)
        self.assertIn(f"container inspect {self.container_id}", commands)
        self.assertNotIn("--user 0", commands)
        self.assertNotIn("sub2api.backup", commands)
        self.assertNotIn(".ash_history", commands)
        self.assertNotIn("\ninspect ", f"\n{commands}")

    def test_public_lock_has_only_portable_immutable_metadata(self) -> None:
        lock = json.loads((REPO_ROOT / "versions.lock.json").read_text(encoding="utf-8"))
        self.assertNotIn("captured_at", lock)
        self.assertTrue(
            RUNTIME_MODULE.PROHIBITED_LEGACY_LOCK_FIELDS.isdisjoint(lock["sub2api"])
        )

    def test_mutable_rootfs_and_writable_layer_drift_fail_closed(self) -> None:
        mutable = copy.deepcopy(self.container)
        mutable["HostConfig"]["ReadonlyRootfs"] = False
        self.invoke(container=mutable, success=False)

        for diff in ("A /tmp/new", "C /app/sub2api", "D /app/removed"):
            with self.subTest(diff=diff):
                self.invoke(diff_lines=[diff], success=False)

    def test_mutable_tag_config_image_fails_closed(self) -> None:
        tagged = copy.deepcopy(self.container)
        tagged["Config"]["Image"] = "registry.example/sub2api:latest"
        self.invoke(container=tagged, success=False)

    def test_rejects_prefixed_container_id_and_bare_image_id(self) -> None:
        prefixed = copy.deepcopy(self.container)
        prefixed["Id"] = f"sha256:{self.container_id}"
        self.invoke(container=prefixed, success=False)

        bare_image = copy.deepcopy(self.container)
        bare_image["Image"] = "6" * 64
        self.invoke(container=bare_image, success=False)

    def test_rejects_pid1_or_immutable_image_process_override(self) -> None:
        cases: list[dict[str, object]] = []
        wrong_path = copy.deepcopy(self.container)
        wrong_path["Path"] = "/bin/sh"
        cases.append(wrong_path)
        wrong_args = copy.deepcopy(self.container)
        wrong_args["Args"] = ["version"]
        cases.append(wrong_args)
        overridden_cmd = copy.deepcopy(self.container)
        overridden_cmd["Config"]["Cmd"] = ["different"]
        cases.append(overridden_cmd)
        for candidate in cases:
            with self.subTest(path=candidate["Path"], args=candidate["Args"]):
                self.invoke(container=candidate, success=False)

    def test_rejects_privilege_namespace_device_and_port_expansion(self) -> None:
        mutations = {
            "privileged": ("Privileged", True),
            "cap-add": ("CapAdd", ["NET_ADMIN"]),
            "unconfined-seccomp": (
                "SecurityOpt",
                ["no-new-privileges:true", "seccomp=unconfined"],
            ),
            "host-pid": ("PidMode", "host"),
            "host-ipc": ("IpcMode", "host"),
            "host-network": ("NetworkMode", "host"),
            "device": ("Devices", [{"PathOnHost": "/dev/kvm"}]),
            "device-request": ("DeviceRequests", [{"Capabilities": [["gpu"]]}]),
            "bind": ("Binds", ["/var/run/docker.sock:/var/run/docker.sock:ro"]),
            "volumes-from": ("VolumesFrom", ["untrusted:ro"]),
            "tmpfs": ("Tmpfs", {"/tmp": "rw"}),
            "publish-all": ("PublishAllPorts", True),
            "port-binding": (
                "PortBindings",
                {"8080/tcp": [{"HostIp": "0.0.0.0", "HostPort": "8080"}]},
            ),
        }
        for label, (field, value) in mutations.items():
            with self.subTest(label=label):
                candidate = copy.deepcopy(self.container)
                candidate["HostConfig"][field] = value
                self.invoke(container=candidate, success=False)

    def test_rejects_any_mount_other_than_named_app_data_volume(self) -> None:
        cases = []
        bind_data = copy.deepcopy(self.container)
        bind_data["Mounts"][0]["Type"] = "bind"
        cases.append(bind_data)
        unnamed = copy.deepcopy(self.container)
        del unnamed["Mounts"][0]["Name"]
        cases.append(unnamed)
        extra_read_only = copy.deepcopy(self.container)
        extra_read_only["Mounts"].append(
            {"Destination": "/etc/ssl", "Type": "bind", "RW": False}
        )
        cases.append(extra_read_only)
        for candidate in cases:
            with self.subTest(mounts=candidate["Mounts"]):
                self.invoke(container=candidate, success=False)

    def test_rejects_additional_network_or_published_network_port(self) -> None:
        additional = copy.deepcopy(self.container)
        additional["NetworkSettings"]["Networks"]["untrusted"] = {
            "Aliases": ["sub2api"]
        }
        self.invoke(container=additional, success=False)

        public = copy.deepcopy(self.container)
        public["NetworkSettings"]["Ports"]["8080/tcp"] = [
            {"HostIp": "0.0.0.0", "HostPort": "8080"}
        ]
        self.invoke(container=public, success=False)

    def test_rejects_final_restart_state_or_metadata_drift(self) -> None:
        restarted = copy.deepcopy(self.container)
        restarted["RestartCount"] = 1
        self.invoke(after=restarted, success=False)

        stopped = copy.deepcopy(self.container)
        stopped["State"]["Running"] = False
        self.invoke(name_after=stopped, success=False)

        remounted = copy.deepcopy(self.container)
        remounted["Mounts"][0]["Name"] = "replacement-data"
        self.invoke(after=remounted, success=False)

    def test_auth_evidence_reader_rejects_symlink_and_hardlink(self) -> None:
        real = self.root / "private-evidence.json"
        write_json(real, self.evidence)
        symlink = self.root / "evidence-symlink.json"
        symlink.symlink_to(real)
        self.invoke(evidence_path=symlink, success=False)

        hardlink = self.root / "evidence-hardlink.json"
        os.link(real, hardlink)
        self.invoke(evidence_path=real, success=False)
        hardlink.unlink()

    def test_auth_evidence_reader_requires_exact_private_mode(self) -> None:
        evidence = self.root / "private-mode-evidence.json"
        write_json(evidence, self.evidence, mode=0o600)
        self.invoke(evidence_path=evidence)

        for mode in (0o400, 0o444, 0o640, 0o700):
            with self.subTest(mode=f"{mode:04o}"):
                evidence.chmod(mode)
                result = self.invoke(evidence_path=evidence, success=False)
                self.assertIn(
                    "auth evidence must have exact mode 0600",
                    result.stderr,
                )

    def test_auth_evidence_reader_rejects_wrong_euid_and_oversize(self) -> None:
        evidence = self.root / "private-evidence.json"
        write_json(evidence, self.evidence)
        with (
            mock.patch.object(
                RUNTIME_MODULE.os, "geteuid", return_value=os.geteuid() + 1
            ),
            self.assertRaisesRegex(ValueError, "owned by the deployment user"),
        ):
            RUNTIME_MODULE.load_private_json(
                evidence,
                "auth evidence",
                max_bytes=RUNTIME_MODULE.MAX_AUTH_EVIDENCE_BYTES,
            )

        evidence.write_bytes(b"{" + b" " * RUNTIME_MODULE.MAX_AUTH_EVIDENCE_BYTES)
        evidence.chmod(0o600)
        self.invoke(evidence_path=evidence, success=False)

    def test_auth_evidence_rejects_wrong_probe_nonce_user_or_namespace(self) -> None:
        mutations = {
            "nonce": ("probe", "nonce", "b" * 64),
            "user": ("probe", "expected_user_id", "other-user"),
            "namespace": (
                "probe",
                "network_namespace_container_id",
                "9" * 64,
            ),
            "refreshed-identity": (
                "fixtures",
                "refresh_rotation",
                {
                    **self.evidence["fixtures"]["refresh_rotation"],
                    "same_identity": False,
                },
            ),
        }
        for label, (section, field, value) in mutations.items():
            with self.subTest(label=label):
                evidence = copy.deepcopy(self.evidence)
                evidence[section][field] = value
                path = self.root / f"evidence-{label}.json"
                write_json(path, evidence)
                self.invoke(evidence_path=path, success=False)


if __name__ == "__main__":
    unittest.main()
