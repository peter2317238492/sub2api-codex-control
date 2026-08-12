#!/usr/bin/env python3
"""Validate immutable Sub2API runtime evidence without invoking Docker."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import posixpath
import re
import stat
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, NoReturn
from urllib.parse import urlsplit

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
EXPECTED_PORT_BINDINGS = {"8080/tcp": [{"HostIp": "127.0.0.1", "HostPort": "8080"}]}
CONTAINER_ID_RE = re.compile(r"^[0-9a-f]{64}$")
IMAGE_ID_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
DIGEST_REF_RE = re.compile(r"^[^\s@]+@sha256:[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
IMMUTABLE_PROFILE = "immutable-image-v1"
PROHIBITED_LEGACY_LOCK_FIELDS = {
    "production_admission_profile",
    "production_compatibility",
}
MAX_AUTH_EVIDENCE_BYTES = 1024 * 1024
MAX_AUTH_CONTRACT_BYTES = 4 * 1024 * 1024


def fail(message: str) -> NoReturn:
    raise ValueError(message)


def load_json(path: Path, label: str) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        fail(f"cannot read {label} {path}: {exc}")


def read_owned_stable_bytes(
    path: Path, label: str, *, max_bytes: int, exact_mode: int
) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:
        fail("this platform cannot perform no-follow evidence reads")
    flags |= nofollow
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        fail(f"cannot open {label} {path} without following symlinks: {exc}")
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            fail(f"{label} is not a regular file")
        if before.st_uid != os.geteuid():
            fail(f"{label} is not owned by the deployment user")
        if before.st_nlink != 1:
            fail(f"{label} must have exactly one filesystem link")
        observed_mode = stat.S_IMODE(before.st_mode)
        if observed_mode != exact_mode:
            fail(f"{label} must have exact mode {exact_mode:04o}")
        if before.st_size <= 0 or before.st_size > max_bytes:
            fail(f"{label} size is outside the accepted range")

        chunks: list[bytes] = []
        remaining = max_bytes + 1
        while remaining:
            chunk = os.read(descriptor, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        if len(payload) > max_bytes:
            fail(f"{label} exceeds the maximum accepted size")

        after = os.fstat(descriptor)
        stable_fields = (
            "st_dev",
            "st_ino",
            "st_mode",
            "st_uid",
            "st_gid",
            "st_nlink",
            "st_size",
            "st_mtime_ns",
            "st_ctime_ns",
        )
        if any(
            getattr(before, field) != getattr(after, field) for field in stable_fields
        ):
            fail(f"{label} changed while it was being read")
        if len(payload) != before.st_size:
            fail(f"{label} size changed while it was being read")
    finally:
        os.close(descriptor)

    return payload


def read_private_bytes(path: Path, label: str, *, max_bytes: int) -> bytes:
    return read_owned_stable_bytes(path, label, max_bytes=max_bytes, exact_mode=0o600)


def read_immutable_contract_bytes(path: Path, label: str, *, max_bytes: int) -> bytes:
    return read_owned_stable_bytes(path, label, max_bytes=max_bytes, exact_mode=0o444)


def load_private_json(path: Path, label: str, *, max_bytes: int) -> Any:
    """Read one deployment-user-owned file without following its final symlink."""

    try:
        return json.loads(
            read_private_bytes(path, label, max_bytes=max_bytes).decode("utf-8")
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        fail(f"cannot decode {label} {path}: {exc}")


def single_inspect(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, list) or len(value) != 1 or not isinstance(value[0], dict):
        fail(f"{label} must contain exactly one Docker inspect object")
    return value[0]


def required_string(mapping: dict[str, Any], key: str, label: str) -> str:
    value = mapping.get(key)
    if not isinstance(value, str) or not value:
        fail(f"{label}.{key} must be a non-empty string")
    return value


def parse_diff(path: Path) -> list[str]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        fail(f"cannot read Docker diff evidence {path}: {exc}")
    for line in lines:
        if (
            len(line) < 4
            or line[:2] not in {"A ", "C ", "D "}
            or not line[2:].startswith("/")
            or posixpath.normpath(line[2:]) != line[2:]
        ):
            fail(f"Docker diff contains a malformed entry: {line!r}")
    if len(lines) != len(set(lines)):
        fail("Docker diff contains duplicate entries")
    return sorted(lines)


def expected_source_url(release_url: str) -> str:
    parsed = urlsplit(release_url)
    if parsed.scheme != "https" or parsed.netloc != "github.com":
        fail("sub2api.release_url must be an HTTPS GitHub release URL")
    parts = [part for part in parsed.path.split("/") if part]
    if len(parts) < 4 or parts[2] != "releases" or parts[3] != "tag":
        fail("sub2api.release_url does not identify a GitHub release tag")
    return f"https://github.com/{parts[0]}/{parts[1]}"


def validate_labels(
    labels: Any,
    *,
    version: str,
    commit: str,
    source: str,
    label: str,
) -> None:
    if not isinstance(labels, dict):
        fail(f"{label} has no OCI labels")
    expected = {
        "org.opencontainers.image.version": version,
        "org.opencontainers.image.revision": commit,
        "org.opencontainers.image.source": source,
    }
    for key, expected_value in expected.items():
        if labels.get(key) != expected_value:
            fail(
                f"{label} OCI label {key} mismatch: expected {expected_value!r}, "
                f"observed {labels.get(key)!r}"
            )


def validate_mounts(mounts: Any) -> list[dict[str, Any]]:
    if not isinstance(mounts, list):
        fail("container mounts are missing")
    if len(mounts) != 1:
        fail("exactly one /app/data Docker volume mount is required")
    sanitized: list[dict[str, Any]] = []
    for index, mount in enumerate(mounts):
        if not isinstance(mount, dict):
            fail(f"container mount {index} is not an object")
        destination = mount.get("Destination")
        mount_type = mount.get("Type")
        read_write = mount.get("RW")
        if not isinstance(destination, str) or not destination.startswith("/"):
            fail(f"container mount {index} has an invalid destination")
        normalized = posixpath.normpath(destination)
        if normalized != destination or normalized == "/":
            fail(f"container mount destination is not admissible: {destination}")
        if not isinstance(read_write, bool):
            fail(f"container mount {destination} has no RW flag")
        if mount_type != "volume":
            fail(f"container mount {destination} must be a Docker volume")
        if normalized != "/app/data" or not read_write:
            fail("the only admissible mount is a writable Docker volume at /app/data")
        volume_name = mount.get("Name")
        if not isinstance(volume_name, str) or not volume_name:
            fail("the /app/data Docker volume has no immutable volume identity")
        sanitized.append(
            {
                "destination": normalized,
                "type": mount_type,
                "read_write": read_write,
                "volume_name": volume_name,
            }
        )
    return sanitized


def empty_sequence(value: Any) -> bool:
    return value is None or value == []


def validate_host_config(
    host_config: Any,
    *,
    expected_network: str,
    expected_port_bindings: dict[str, list[dict[str, str]]],
) -> None:
    if not isinstance(host_config, dict):
        fail("Docker inspect output has no HostConfig object")
    if host_config.get("ReadonlyRootfs") is not True:
        fail("container root filesystem is not read-only")
    if host_config.get("Privileged") is not False:
        fail("privileged Sub2API containers are prohibited")
    if not empty_sequence(host_config.get("CapAdd")):
        fail("Sub2API container may not add Linux capabilities")
    cap_drop = host_config.get("CapDrop")
    security_opt = host_config.get("SecurityOpt")
    if cap_drop != ["ALL"]:
        fail("Sub2API container must drop all Linux capabilities")
    if security_opt not in (["no-new-privileges"], ["no-new-privileges:true"]):
        fail("Sub2API container must enable only no-new-privileges security options")

    exact_namespace_modes: dict[str, set[str]] = {
        "PidMode": {""},
        "IpcMode": {"", "private"},
        "UTSMode": {""},
        "UsernsMode": {"", "private"},
        "CgroupnsMode": {"", "private"},
    }
    for field, allowed in exact_namespace_modes.items():
        value = host_config.get(field)
        if value not in allowed:
            fail(f"Sub2API container has an inadmissible {field}: {value!r}")
    if host_config.get("NetworkMode") != expected_network:
        fail("Sub2API container network mode does not match the admitted network")

    for field in (
        "Devices",
        "DeviceRequests",
        "DeviceCgroupRules",
        "VolumesFrom",
    ):
        if not empty_sequence(host_config.get(field)):
            fail(f"Sub2API container has prohibited host resource access via {field}")
    if not empty_sequence(host_config.get("Binds")):
        fail("Sub2API container has prohibited host resource access via Binds")
    if host_config.get("Tmpfs") not in (None, {}):
        fail("Sub2API container has a prohibited tmpfs mount")
    if host_config.get("PublishAllPorts") is not False:
        fail("Sub2API container may not publish all exposed ports")
    if host_config.get("PortBindings") != expected_port_bindings:
        fail(
            "Sub2API container must publish only 127.0.0.1:8080 to container port 8080"
        )


def validate_process(container: dict[str, Any], image: dict[str, Any]) -> list[str]:
    config = container.get("Config")
    image_config = image.get("Config")
    if not isinstance(config, dict) or not isinstance(image_config, dict):
        fail("Docker inspect output has no Config object")

    raw_image_entrypoint = image_config.get("Entrypoint")
    raw_image_cmd = image_config.get("Cmd")
    if raw_image_entrypoint is not None and (
        not isinstance(raw_image_entrypoint, list)
        or any(not isinstance(value, str) for value in raw_image_entrypoint)
    ):
        fail("immutable image Entrypoint is not an exec-form string array")
    if raw_image_cmd is not None and (
        not isinstance(raw_image_cmd, list)
        or any(not isinstance(value, str) for value in raw_image_cmd)
    ):
        fail("immutable image Cmd is not an exec-form string array")
    if config.get("Entrypoint") != raw_image_entrypoint:
        fail("running container overrides the immutable image entrypoint")
    if config.get("Cmd") != raw_image_cmd:
        fail("running container overrides the immutable image command")

    image_entrypoint = raw_image_entrypoint or []
    image_cmd = raw_image_cmd or []
    process_vector = [*image_entrypoint, *image_cmd]
    if not process_vector or process_vector[0] != "/app/sub2api":
        fail("immutable image process vector is not rooted at /app/sub2api")
    expected_args = process_vector[1:]
    if (
        container.get("Path") != "/app/sub2api"
        or container.get("Args") != expected_args
    ):
        fail("container PID 1 Path/Args do not execute the immutable /app/sub2api")
    return expected_args


def validate_state(container: dict[str, Any], label: str) -> int:
    state = container.get("State")
    if not isinstance(state, dict):
        fail(f"{label} has no State object")
    for field in ("Paused", "Restarting", "OOMKilled", "Dead"):
        if state.get(field) is not False:
            fail(f"{label} has an inadmissible State.{field}")
    if state.get("Running") is not True:
        fail(f"{label} is not running")
    health = state.get("Health")
    if not isinstance(health, dict) or health.get("Status") != "healthy":
        fail(f"{label} health is not healthy")
    restart_count = container.get("RestartCount")
    if isinstance(restart_count, bool) or not isinstance(restart_count, int):
        fail(f"{label} RestartCount is missing or invalid")
    if restart_count < 0:
        fail(f"{label} RestartCount is negative")
    return restart_count


def validate_networks(
    container: dict[str, Any],
    *,
    expected_network: str,
    expected_alias: str,
    expected_port_bindings: dict[str, list[dict[str, str]]],
) -> dict[str, Any]:
    network_settings = container.get("NetworkSettings")
    if not isinstance(network_settings, dict):
        fail("Docker inspect output has no NetworkSettings object")
    networks = network_settings.get("Networks")
    if not isinstance(networks, dict) or set(networks) != {expected_network}:
        fail("Sub2API container must attach only to the admitted network")
    network = networks[expected_network]
    if not isinstance(network, dict):
        fail("Sub2API admitted network metadata is invalid")
    aliases = network.get("Aliases")
    if not isinstance(aliases, list) or expected_alias not in aliases:
        fail(f"Sub2API container lacks alias {expected_alias!r} on {expected_network}")
    ports = network_settings.get("Ports")
    if ports != expected_port_bindings:
        fail("Sub2API network metadata does not expose only 127.0.0.1:8080")
    return {
        "network": expected_network,
        "aliases": sorted(set(aliases)),
        "endpoint": network,
        "ports": ports,
    }


def parse_timestamp(value: Any, label: str) -> datetime:
    if not isinstance(value, str) or not value:
        fail(f"{label} must be an RFC3339 timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        fail(f"{label} must be an RFC3339 timestamp")
    if parsed.tzinfo is None:
        fail(f"{label} must include a timezone")
    return parsed.astimezone(UTC)


def validate_auth_evidence(
    evidence: Any,
    *,
    contract_sha256: str,
    container_id: str,
    image_id: str,
    image_digest: str,
    binary_sha256: str,
    version: str,
    commit: str,
    max_age_seconds: int,
    expected_probe_nonce: str,
    expected_user_id: str,
    expected_base_url: str,
) -> dict[str, Any]:
    if not isinstance(evidence, dict) or set(evidence) != {
        "format_version",
        "captured_at",
        "probe",
        "runtime",
        "contract_sha256",
        "fixtures",
    }:
        fail("auth evidence has unexpected or missing top-level fields")
    if evidence["format_version"] != 4:
        fail("auth evidence format_version must be 4")
    captured_at = parse_timestamp(evidence["captured_at"], "auth evidence captured_at")
    now = datetime.now(UTC)
    if captured_at > now + timedelta(seconds=60):
        fail("auth evidence captured_at is in the future")
    if now - captured_at > timedelta(seconds=max_age_seconds):
        fail("auth evidence is stale")
    if evidence["contract_sha256"] != contract_sha256:
        fail("auth evidence contract digest mismatch")

    expected_probe = {
        "base_url": expected_base_url,
        "nonce": expected_probe_nonce,
        "expected_user_id": expected_user_id,
        "network_namespace_container_id": container_id,
        "proxy_environment_disabled": True,
    }
    if evidence["probe"] != expected_probe:
        fail(
            "auth evidence is not bound to this probe nonce, user, and network namespace"
        )

    runtime = evidence["runtime"]
    expected_runtime = {
        "container_id": container_id,
        "image_id": image_id,
        "image_digest": image_digest,
        "binary_sha256": binary_sha256,
        "version": version,
        "commit": commit,
        "contract_sha256": contract_sha256,
    }
    if not isinstance(runtime, dict) or runtime != expected_runtime:
        fail("auth evidence is not bound to the observed Sub2API runtime")

    fixtures = evidence["fixtures"]
    if not isinstance(fixtures, dict) or set(fixtures) != {
        "auth_me_success",
        "auth_me_disabled",
        "auth_me_revoked",
        "auth_me_session_binding_mismatch",
        "refresh_rotation",
        "logout",
    }:
        fail("auth evidence has unexpected or missing fixtures")

    exact_fixtures: dict[str, tuple[set[str], dict[str, Any]]] = {
        "auth_me_success": (
            {"status", "identity_present", "user_id"},
            {"status": 200, "identity_present": True, "user_id": expected_user_id},
        ),
        "auth_me_disabled": (
            {"status", "code"},
            {"status": 401, "code": "USER_INACTIVE"},
        ),
        "auth_me_revoked": (
            {"status", "code"},
            {"status": 401, "code": "TOKEN_REVOKED"},
        ),
        "auth_me_session_binding_mismatch": (
            {"status", "code", "ip_and_user_agent_changed"},
            {
                "status": 401,
                "code": "SESSION_BINDING_MISMATCH",
                "ip_and_user_agent_changed": True,
            },
        ),
        "refresh_rotation": (
            {
                "status",
                "access_token_present",
                "refresh_token_present",
                "expires_in_positive",
                "token_type",
                "refresh_rotated",
                "refreshed_identity_status",
                "same_identity",
                "old_refresh_rejected_status",
            },
            {
                "status": 200,
                "access_token_present": True,
                "refresh_token_present": True,
                "expires_in_positive": True,
                "token_type": "Bearer",
                "refresh_rotated": True,
                "refreshed_identity_status": 200,
                "same_identity": True,
            },
        ),
        "logout": (
            {"status", "refresh_after_logout_status"},
            {},
        ),
    }
    for fixture_name, (expected_keys, expected_values) in exact_fixtures.items():
        fixture = fixtures[fixture_name]
        if not isinstance(fixture, dict) or set(fixture) != expected_keys:
            fail(f"auth evidence fixture {fixture_name} has unexpected fields")
        for key, expected_value in expected_values.items():
            if fixture.get(key) != expected_value:
                fail(f"auth evidence fixture {fixture_name}.{key} failed")

    if fixtures["refresh_rotation"]["old_refresh_rejected_status"] not in (401, 403):
        fail("auth evidence fixture refresh_rotation accepted the old refresh token")
    if fixtures["logout"]["status"] not in (200, 204):
        fail("auth evidence fixture logout failed")
    if fixtures["logout"]["refresh_after_logout_status"] not in (401, 403):
        fail("auth evidence fixture logout did not revoke the refresh token")

    return {
        "captured_at": evidence["captured_at"],
        "contract_sha256": contract_sha256,
        "probe": expected_probe,
        "sha256": hashlib.sha256(
            json.dumps(evidence, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest(),
        "fixtures": fixtures,
    }


def validate(args: argparse.Namespace) -> dict[str, Any]:
    lock_path = args.lock.resolve()
    lock = load_json(lock_path, "version lock")
    if not isinstance(lock, dict) or lock.get("format_version") != 1:
        fail("unsupported versions.lock.json format")
    sub2api = lock.get("sub2api")
    if not isinstance(sub2api, dict):
        fail("versions.lock.json has no sub2api object")
    legacy_fields = sorted(PROHIBITED_LEGACY_LOCK_FIELDS.intersection(sub2api))
    if legacy_fields:
        fail(
            "versions.lock.json contains prohibited legacy Sub2API fields: "
            + ", ".join(legacy_fields)
        )

    runtime_source_image = required_string(sub2api, "container_image", "sub2api")
    runtime_source_image_id = required_string(sub2api, "container_image_id", "sub2api")
    binary_sha256 = required_string(sub2api, "runtime_binary_sha256", "sub2api")
    version = required_string(sub2api, "runtime_version", "sub2api")
    commit = required_string(sub2api, "runtime_commit", "sub2api")
    built_at = required_string(sub2api, "runtime_built_at", "sub2api")
    runtime_source_image_created = required_string(sub2api, "image_created", "sub2api")
    release_url = required_string(sub2api, "release_url", "sub2api")
    lock_label_version = required_string(sub2api, "image_label_version", "sub2api")
    lock_label_commit = required_string(sub2api, "image_label_commit", "sub2api")
    if not DIGEST_REF_RE.fullmatch(runtime_source_image):
        fail("sub2api.container_image is not an immutable sha256 digest reference")
    if not IMAGE_ID_RE.fullmatch(runtime_source_image_id):
        fail("sub2api.container_image_id is not a full sha256 image ID")
    if not SHA256_RE.fullmatch(binary_sha256):
        fail("sub2api.runtime_binary_sha256 is invalid")
    if not COMMIT_RE.fullmatch(commit):
        fail("sub2api.runtime_commit must be a full 40-character Git commit")
    parse_timestamp(built_at, "sub2api.runtime_built_at")
    parse_timestamp(runtime_source_image_created, "sub2api.image_created")
    if lock_label_version != version or lock_label_commit != commit:
        fail(
            "version lock records OCI labels that do not match the runtime; "
            "an immutable rebuilt Sub2API image and updated lock are required"
        )
    source = expected_source_url(release_url)

    expected_image = runtime_source_image
    expected_image_id = runtime_source_image_id
    image_created = runtime_source_image_created
    expected_config_image = expected_image
    expected_port_bindings = EXPECTED_PORT_BINDINGS

    contract_relative = required_string(sub2api, "auth_contract_file", "sub2api")
    contract_sha256 = required_string(sub2api, "auth_contract_sha256", "sub2api")
    if not SHA256_RE.fullmatch(contract_sha256):
        fail("sub2api.auth_contract_sha256 is invalid")
    relative_contract_path = Path(contract_relative)
    if relative_contract_path.is_absolute() or any(
        part in {"", ".", ".."} for part in relative_contract_path.parts
    ):
        fail("sub2api.auth_contract_file is not one normalized relative path")
    if args.contract_file is not None:
        contract_payload = read_immutable_contract_bytes(
            args.contract_file,
            "Sub2API auth contract snapshot",
            max_bytes=MAX_AUTH_CONTRACT_BYTES,
        )
    else:
        contract_path = (lock_path.parent / relative_contract_path).resolve()
        try:
            contract_path.relative_to(lock_path.parent)
        except ValueError:
            fail("sub2api.auth_contract_file escapes the repository root")
        contract_payload = read_immutable_contract_bytes(
            contract_path,
            "Sub2API auth contract snapshot",
            max_bytes=MAX_AUTH_CONTRACT_BYTES,
        )
    observed_contract_sha256 = hashlib.sha256(contract_payload).hexdigest()
    if observed_contract_sha256 != contract_sha256:
        fail("Sub2API auth contract digest mismatch")

    container = single_inspect(
        load_json(args.container_inspect, "container inspect"), "container inspect"
    )
    container_after = single_inspect(
        load_json(args.container_inspect_after, "post-check container inspect"),
        "post-check container inspect",
    )
    container_name_after = single_inspect(
        load_json(
            args.container_name_inspect_after, "post-check named container inspect"
        ),
        "post-check named container inspect",
    )
    image = single_inspect(
        load_json(args.image_inspect, "image inspect"), "image inspect"
    )
    container_id = required_string(container, "Id", "container")
    image_id = required_string(container, "Image", "container")
    if not CONTAINER_ID_RE.fullmatch(container_id):
        fail("container ID is not Docker's full bare 64-hex identifier")
    if not IMAGE_ID_RE.fullmatch(image_id):
        fail("container image ID is not a full sha256 identifier")
    if image_id != expected_image_id:
        fail("running container image ID does not match the version lock")
    if image.get("Id") != image_id:
        fail("container image ID changed between inspect operations")
    if (
        container_after.get("Id") != container_id
        or container_name_after.get("Id") != container_id
    ):
        fail("Sub2API container identity changed during verification")
    immutable_fields = (
        "Name",
        "Path",
        "Args",
        "Image",
        "Config",
        "HostConfig",
        "Mounts",
    )
    for candidate_label, candidate in (
        ("post-check ID inspect", container_after),
        ("post-check name inspect", container_name_after),
    ):
        for field in immutable_fields:
            if candidate.get(field) != container.get(field):
                fail(
                    "Sub2API container metadata changed during verification: "
                    f"{candidate_label}.{field}"
                )
    state = container.get("State")
    state_after = container_after.get("State")
    state_name_after = container_name_after.get("State")
    if not all(
        isinstance(value, dict) for value in (state, state_after, state_name_after)
    ):
        fail("Docker inspect output has no stable State object")
    state_pid = state.get("Pid")
    if (
        isinstance(state_pid, bool)
        or not isinstance(state_pid, int)
        or state_pid <= 0
        or state_after.get("Pid") != state_pid
        or state_name_after.get("Pid") != state_pid
        or args.pid1_host_pid != state_pid
    ):
        fail("Sub2API host PID changed or does not match the PID 1 evidence")
    if args.pid1_path != "/app/sub2api":
        fail("Sub2API host /proc PID 1 executable is not /app/sub2api")
    if args.pid1_sha256 != binary_sha256:
        fail("Sub2API host /proc PID 1 hash does not match the locked runtime")
    config = container.get("Config")
    image_config = image.get("Config")
    if not isinstance(config, dict) or not isinstance(image_config, dict):
        fail("Docker inspect output has no Config object")
    if config.get("Image") != expected_config_image:
        fail("running container Config.Image does not match the version lock")
    repo_digests = image.get("RepoDigests")
    if not isinstance(repo_digests, list) or expected_image not in repo_digests:
        fail("locked Sub2API digest is absent from the inspected image RepoDigests")

    if image.get("Created") != image_created:
        fail(
            "inspected Sub2API image Created timestamp does not match the version lock"
        )
    validate_host_config(
        container.get("HostConfig"),
        expected_network=args.expected_network,
        expected_port_bindings=expected_port_bindings,
    )
    process_args = validate_process(container, image)
    initial_restart_count = validate_state(container, "Sub2API container")
    after_restart_count = validate_state(
        container_after, "post-check Sub2API container"
    )
    name_after_restart_count = validate_state(
        container_name_after, "post-check named Sub2API container"
    )
    if {
        initial_restart_count,
        after_restart_count,
        name_after_restart_count,
    } != {initial_restart_count}:
        fail("Sub2API container restarted during verification")

    validate_labels(
        config.get("Labels"),
        version=version,
        commit=commit,
        source=source,
        label="container",
    )
    validate_labels(
        image_config.get("Labels"),
        version=version,
        commit=commit,
        source=source,
        label="image",
    )
    mounts = validate_mounts(container.get("Mounts"))
    initial_network = validate_networks(
        container,
        expected_network=args.expected_network,
        expected_alias=args.expected_alias,
        expected_port_bindings=expected_port_bindings,
    )
    for candidate_label, candidate in (
        ("post-check ID inspect", container_after),
        ("post-check name inspect", container_name_after),
    ):
        candidate_network = validate_networks(
            candidate,
            expected_network=args.expected_network,
            expected_alias=args.expected_alias,
            expected_port_bindings=expected_port_bindings,
        )
        if candidate_network != initial_network:
            fail(f"Sub2API network identity changed during {candidate_label}")

    observed_binary_sha256 = args.binary_sha256.strip()
    if observed_binary_sha256 != binary_sha256:
        fail("/app/sub2api SHA-256 does not match the version lock")
    version_output = args.version_output.read_text(
        encoding="utf-8", errors="replace"
    ).strip()
    if (
        re.search(
            rf"(?<![0-9A-Za-z.]){re.escape(version)}(?![0-9A-Za-z.])", version_output
        )
        is None
        or re.search(rf"(?<![0-9a-f]){commit}(?![0-9a-f])", version_output) is None
        or built_at not in version_output
    ):
        fail("Sub2API --version output does not contain the exact locked runtime tuple")
    diff_lines = parse_diff(args.diff)
    if diff_lines:
        fail("immutable Sub2API container has writable-layer drift")

    auth: dict[str, Any] | None = None
    if args.auth_evidence:
        auth = validate_auth_evidence(
            load_private_json(
                args.auth_evidence,
                "auth evidence",
                max_bytes=MAX_AUTH_EVIDENCE_BYTES,
            ),
            contract_sha256=contract_sha256,
            container_id=container_id,
            image_id=image_id,
            image_digest=expected_image,
            binary_sha256=binary_sha256,
            version=version,
            commit=commit,
            max_age_seconds=args.auth_max_age_seconds,
            expected_probe_nonce=args.auth_probe_nonce,
            expected_user_id=args.auth_probe_user_id,
            expected_base_url=args.auth_probe_base_url,
        )
    elif args.require_auth_evidence:
        fail("fresh Sub2API authentication fixture evidence is required")

    return {
        "format_version": 2,
        "verified_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "admission_profile": IMMUTABLE_PROFILE,
        "container_id": container_id,
        "image_id": image_id,
        "image_digest": expected_image,
        "container_config_image": expected_config_image,
        "runtime_source_image": runtime_source_image,
        "runtime_source_image_id": runtime_source_image_id,
        "runtime_source_image_created": runtime_source_image_created,
        "binary_sha256": binary_sha256,
        "runtime_version": version,
        "runtime_commit": commit,
        "runtime_built_at": built_at,
        "pid1_host_pid": state_pid,
        "pid1_path": args.pid1_path,
        "pid1_sha256": args.pid1_sha256,
        "pid1_args": process_args,
        "restart_count": initial_restart_count,
        "oci_created": image_created,
        "oci_source": source,
        "mounts": mounts,
        "writable_layer_diff": diff_lines,
        "network": args.expected_network,
        "network_alias": args.expected_alias,
        "contract_sha256": contract_sha256,
        "auth_evidence": auth,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--lock", type=Path, required=True)
    parser.add_argument("--contract-file", type=Path)
    parser.add_argument("--container-inspect", type=Path, required=True)
    parser.add_argument("--container-inspect-after", type=Path, required=True)
    parser.add_argument("--container-name-inspect-after", type=Path, required=True)
    parser.add_argument("--image-inspect", type=Path, required=True)
    parser.add_argument("--binary-sha256", required=True)
    parser.add_argument("--pid1-host-pid", type=int, required=True)
    parser.add_argument("--pid1-path", required=True)
    parser.add_argument("--pid1-sha256", required=True)
    parser.add_argument("--version-output", type=Path, required=True)
    parser.add_argument("--diff", type=Path, required=True)
    parser.add_argument("--expected-network", required=True)
    parser.add_argument("--expected-alias", required=True)
    parser.add_argument("--auth-evidence", type=Path)
    parser.add_argument("--require-auth-evidence", action="store_true")
    parser.add_argument("--auth-max-age-seconds", type=int, default=900)
    parser.add_argument("--auth-probe-nonce")
    parser.add_argument("--auth-probe-user-id")
    parser.add_argument("--auth-probe-base-url")
    args = parser.parse_args()
    if args.auth_max_age_seconds <= 0:
        parser.error("--auth-max-age-seconds must be positive")
    if args.pid1_host_pid <= 0:
        parser.error("--pid1-host-pid must be positive")
    if not SHA256_RE.fullmatch(args.pid1_sha256):
        parser.error("--pid1-sha256 must be 64 lowercase hexadecimal characters")
    if args.auth_evidence or args.require_auth_evidence:
        if not isinstance(args.auth_probe_nonce, str) or not SHA256_RE.fullmatch(
            args.auth_probe_nonce
        ):
            parser.error(
                "--auth-probe-nonce must be 64 lowercase hexadecimal characters"
            )
        if (
            not isinstance(args.auth_probe_user_id, str)
            or not args.auth_probe_user_id
            or len(args.auth_probe_user_id) > 256
            or args.auth_probe_user_id.strip() != args.auth_probe_user_id
            or any(character.isspace() for character in args.auth_probe_user_id)
        ):
            parser.error(
                "--auth-probe-user-id must be one bounded non-whitespace value"
            )
        if args.auth_probe_base_url != "http://127.0.0.1:8080":
            parser.error("--auth-probe-base-url must be exactly http://127.0.0.1:8080")
    return args


def main() -> int:
    try:
        result = validate(parse_args())
    except (KeyError, TypeError, ValueError) as exc:
        print(f"verify-sub2api-runtime: {exc}", file=sys.stderr)
        return 1
    json.dump(result, sys.stdout, sort_keys=True, separators=(",", ":"))
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
