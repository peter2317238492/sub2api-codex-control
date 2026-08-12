#!/usr/bin/env python3
"""Fail-closed admission checks for signed production deployments.

This script deliberately has no project or third-party imports.  It consumes
only already-captured evidence and emits one compact JSON object after every
check for the selected subcommand has succeeded.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import math
import os
import re
import shutil
import stat
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, NoReturn
from urllib.parse import urlsplit

SCHEMA_VERSION = 1
IMAGE_ID_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
CONTAINER_ID_RE = re.compile(r"^[0-9a-f]{64}$")
IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,62}$")
PROJECT_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,62}$")
RELEASE_RE = re.compile(r"^[0-9A-Za-z][0-9A-Za-z._+-]{0,127}$")
SOURCE_REVISION_RE = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
REVISION_RE = re.compile(r"^[0-9A-Za-z][0-9A-Za-z_]{0,127}$")
MARKER_RE = re.compile(r"^[0-9A-Za-z][0-9A-Za-z._+:/-]{0,255}$")
MANIFEST_LINE_RE = re.compile(rb"([0-9a-f]{64})  ([0-9A-Za-z][0-9A-Za-z._-]*)\n")
BACKUP_DUMP_RE = re.compile(r"^codex-control-[0-9A-Za-zT_-]+\.dump$")
MAX_JSON_BYTES = 32 * 1024 * 1024
MAX_MANIFEST_BYTES = 16 * 1024 * 1024
MAX_CHECKSUM_BYTES = 1024
MAX_SECRET_BYTES = 65_536
MAX_FRESH_BACKUP_AGE_SECONDS = 1800
PLACEHOLDERS = {
    "dev",
    "development",
    "local",
    "none",
    "null",
    "replace-me",
    "unverified",
    "unknown",
}
SERVICE_NAMES = {
    "control-api",
    "control-api-replica",
    "control-migrate",
    "codex-pwa",
    "control-backup",
}
SECRET_TARGETS = {
    "/run/secrets/control_db_password": "control_db_password",
    "/run/secrets/control_redis_password": "control_redis_password",
    "/run/secrets/control_session_hmac_secret": "control_session_hmac_secret",
}


class AdmissionError(RuntimeError):
    """An intentionally concise admission failure."""


def fail(message: str) -> NoReturn:
    raise AdmissionError(message)


def compact_json(value: object) -> None:
    json.dump(value, sys.stdout, sort_keys=True, separators=(",", ":"))
    sys.stdout.write("\n")


def require_absolute(path: Path, label: str) -> None:
    if not path.is_absolute():
        fail(f"{label} must be absolute")


def allowed_owner(metadata: os.stat_result, expected_uid: int | None) -> bool:
    if expected_uid is not None:
        return metadata.st_uid == expected_uid
    return metadata.st_uid in {0, os.geteuid()}


def open_regular(
    path: Path,
    label: str,
    *,
    max_bytes: int,
    exact_mode: int | None = None,
    expected_uid: int | None = None,
    require_absolute_path: bool = False,
) -> tuple[int, os.stat_result]:
    if require_absolute_path:
        require_absolute(path, label)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
        metadata = os.fstat(descriptor)
    except OSError:
        fail(f"{label} is not an accessible real file")
    if not stat.S_ISREG(metadata.st_mode):
        os.close(descriptor)
        fail(f"{label} must be a regular file")
    if not allowed_owner(metadata, expected_uid):
        os.close(descriptor)
        fail(f"{label} has an unexpected owner")
    if exact_mode is not None and stat.S_IMODE(metadata.st_mode) != exact_mode:
        os.close(descriptor)
        fail(f"{label} mode must be exactly {exact_mode:04o}")
    if metadata.st_size < 0 or metadata.st_size > max_bytes:
        os.close(descriptor)
        fail(f"{label} exceeds its size limit")
    return descriptor, metadata


def read_descriptor(descriptor: int, label: str, max_bytes: int) -> bytes:
    try:
        os.lseek(descriptor, 0, os.SEEK_SET)
        chunks: list[bytes] = []
        total = 0
        while True:
            block = os.read(descriptor, min(131_072, max_bytes + 1 - total))
            if not block:
                break
            chunks.append(block)
            total += len(block)
            if total > max_bytes:
                fail(f"{label} exceeds its size limit")
        return b"".join(chunks)
    except OSError:
        fail(f"{label} could not be read")


def assert_stable(
    descriptor: int, original: os.stat_result, label: str
) -> os.stat_result:
    try:
        current = os.fstat(descriptor)
    except OSError:
        fail(f"{label} could not be re-inspected")
    identity = lambda value: (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_uid,
        value.st_gid,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )
    if identity(current) != identity(original):
        fail(f"{label} changed while it was validated")
    return current


def read_regular_bytes(
    path: Path,
    label: str,
    *,
    max_bytes: int,
    exact_mode: int | None = None,
    expected_uid: int | None = None,
    require_absolute_path: bool = False,
) -> tuple[bytes, os.stat_result]:
    descriptor, metadata = open_regular(
        path,
        label,
        max_bytes=max_bytes,
        exact_mode=exact_mode,
        expected_uid=expected_uid,
        require_absolute_path=require_absolute_path,
    )
    try:
        value = read_descriptor(descriptor, label, max_bytes)
        assert_stable(descriptor, metadata, label)
        return value, metadata
    finally:
        os.close(descriptor)


def load_json(
    path: Path,
    label: str,
    *,
    exact_mode: int | None = None,
    require_absolute_path: bool = False,
) -> Any:
    raw, _ = read_regular_bytes(
        path,
        label,
        max_bytes=MAX_JSON_BYTES,
        exact_mode=exact_mode,
        require_absolute_path=require_absolute_path,
    )
    try:
        return strict_json_bytes(raw, label)
    except UnicodeDecodeError:
        fail(f"{label} is not valid UTF-8 JSON")


def strict_json_bytes(raw: bytes, label: str) -> Any:
    def reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                fail(f"{label} contains a duplicate JSON key")
            result[key] = value
        return result

    def reject_constant(value: str) -> NoReturn:
        fail(f"{label} contains a non-finite JSON number: {value}")

    try:
        return json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=reject_duplicate_pairs,
            parse_constant=reject_constant,
        )
    except json.JSONDecodeError:
        fail(f"{label} is not valid UTF-8 JSON")


def open_directory(
    path: Path,
    label: str,
    *,
    exact_mode: int,
    expected_uid: int | None = None,
    expected_gid: int | None = None,
) -> tuple[int, os.stat_result]:
    require_absolute(path, label)
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_DIRECTORY", 0)
    )
    try:
        descriptor = os.open(path, flags)
        metadata = os.fstat(descriptor)
    except OSError:
        fail(f"{label} is not an accessible real directory")
    if not stat.S_ISDIR(metadata.st_mode):
        os.close(descriptor)
        fail(f"{label} must be a directory")
    if not allowed_owner(metadata, expected_uid):
        os.close(descriptor)
        fail(f"{label} has an unexpected owner")
    if expected_gid is not None and metadata.st_gid != expected_gid:
        os.close(descriptor)
        fail(f"{label} has an unexpected group")
    if stat.S_IMODE(metadata.st_mode) != exact_mode:
        os.close(descriptor)
        fail(f"{label} mode must be exactly {exact_mode:04o}")
    return descriptor, metadata


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_descriptor(descriptor: int, label: str) -> str:
    try:
        os.lseek(descriptor, 0, os.SEEK_SET)
        digest = hashlib.sha256()
        for block in iter(lambda: os.read(descriptor, 1024 * 1024), b""):
            digest.update(block)
        return digest.hexdigest()
    except OSError:
        fail(f"{label} could not be hashed")


def require_keys(value: dict[str, Any], expected: set[str], label: str) -> None:
    if set(value) != expected:
        fail(f"{label} has an unexpected schema")


def ready_object(value: Any, label: str, expected_keys: set[str]) -> dict[str, Any]:
    if not isinstance(value, dict):
        fail(f"{label} is not an object")
    require_keys(value, expected_keys, label)
    if value.get("schema_version") != SCHEMA_VERSION or value.get("status") != "ready":
        fail(f"{label} is not a ready schema version 1 record")
    return value


def parse_created_at(value: Any) -> datetime:
    if not isinstance(value, str) or not value:
        fail("backup-record.created_at is missing")
    try:
        parsed = datetime.fromisoformat(
            value.removesuffix("Z") + ("+00:00" if value.endswith("Z") else "")
        )
    except ValueError:
        fail("backup-record.created_at is invalid")
    if parsed.tzinfo is None or parsed.utcoffset() != UTC.utcoffset(parsed):
        fail("backup-record.created_at must include a UTC offset")
    return parsed.astimezone(UTC)


def parse_manifest(raw: bytes) -> dict[str, str]:
    if not raw or not raw.endswith(b"\n"):
        fail("backup manifest is empty or not newline terminated")
    position = 0
    entries: dict[str, str] = {}
    while position < len(raw):
        match = MANIFEST_LINE_RE.match(raw, position)
        if match is None:
            fail("backup manifest has a non-canonical entry")
        name = match.group(2).decode("ascii")
        if name in entries or name in {"manifest.sha256", "READY.json"}:
            fail("backup manifest has a duplicate or recursive entry")
        entries[name] = match.group(1).decode("ascii")
        position = match.end()
    if list(entries) != sorted(entries):
        fail("backup manifest entries are not sorted")
    if "backup-record.json" not in entries:
        fail("backup manifest does not cover backup-record.json")
    return entries


def validate_backup_identity(value: Any, role: str) -> dict[str, str]:
    if not isinstance(value, dict):
        fail(f"backup {role} identity is invalid")
    require_keys(value, {"container_id", "image_id", "name"}, f"backup {role} identity")
    container_id = value.get("container_id")
    image_id = value.get("image_id")
    name = value.get("name")
    if not isinstance(container_id, str) or not CONTAINER_ID_RE.fullmatch(container_id):
        fail(f"backup {role} container ID is invalid")
    if not isinstance(image_id, str) or not IMAGE_ID_RE.fullmatch(image_id):
        fail(f"backup {role} image ID is invalid")
    if (
        not isinstance(name, str)
        or not name
        or name.startswith("/")
        or len(name) > 128
        or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", name) is None
    ):
        fail(f"backup {role} container name is invalid")
    return {"container_id": container_id, "image_id": image_id, "name": name}


def validate_current_identities(
    path: Path, backup_identities: dict[str, dict[str, str]]
) -> None:
    value = load_json(path, "current container identities")
    if not isinstance(value, list) or len(value) != 3:
        fail("current identities must contain exactly three Docker inspect records")
    by_name: dict[str, dict[str, Any]] = {}
    for item in value:
        if not isinstance(item, dict):
            fail("one current container identity is invalid")
        name = item.get("Name")
        if not isinstance(name, str):
            fail("one current container name is invalid")
        name = name.removeprefix("/")
        if not name or name in by_name:
            fail("current container names are empty or duplicated")
        by_name[name] = item
    for role, expected in backup_identities.items():
        item = by_name.get(expected["name"])
        state = item.get("State") if isinstance(item, dict) else None
        if (
            item is None
            or item.get("Id") != expected["container_id"]
            or item.get("Image") != expected["image_id"]
            or not isinstance(state, dict)
            or state.get("Running") is not True
        ):
            fail(f"current {role} container identity differs from the backup")


def backup_receipt(args: argparse.Namespace) -> dict[str, Any]:
    if (
        type(args.max_age_seconds) is not int
        or not 0 < args.max_age_seconds <= MAX_FRESH_BACKUP_AGE_SECONDS
    ):
        fail("fresh backup age must be between 1 and 1800 seconds")
    result_raw, _ = read_regular_bytes(
        args.result_file,
        "production backup result",
        max_bytes=MAX_JSON_BYTES,
        exact_mode=0o600,
        require_absolute_path=True,
    )
    result = ready_object(
        strict_json_bytes(result_raw, "production backup result"),
        "production backup result",
        {"schema_version", "status", "snapshot_directory", "manifest_sha256"},
    )
    args.receipt_sha256 = sha256_bytes(result_raw)
    snapshot_text = result.get("snapshot_directory")
    result_manifest_sha256 = result.get("manifest_sha256")
    if not isinstance(snapshot_text, str) or not snapshot_text:
        fail("production backup result has no snapshot directory")
    if not isinstance(result_manifest_sha256, str) or not SHA256_RE.fullmatch(
        result_manifest_sha256
    ):
        fail("production backup result has no valid manifest hash")
    snapshot = Path(snapshot_text)
    directory_descriptor, directory_metadata = open_directory(
        snapshot, "production backup snapshot", exact_mode=0o700
    )
    descriptors: list[int] = []
    try:
        names = os.listdir(directory_descriptor)
        if len(names) != len(set(names)):
            fail("production backup snapshot contains duplicate names")
        files: dict[str, tuple[int, os.stat_result]] = {}
        for name in names:
            if not name or name in {".", ".."} or "/" in name or "\x00" in name:
                fail("production backup snapshot contains an invalid name")
            flags = (
                os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
            )
            try:
                descriptor = os.open(name, flags, dir_fd=directory_descriptor)
                metadata = os.fstat(descriptor)
            except OSError:
                fail("production backup snapshot contains an inaccessible entry")
            descriptors.append(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or not allowed_owner(metadata, None)
                or stat.S_IMODE(metadata.st_mode) != 0o600
            ):
                fail("production backup snapshot entries must be private regular files")
            files[name] = (descriptor, metadata)
        if not {"READY.json", "manifest.sha256", "backup-record.json"}.issubset(files):
            fail("production backup snapshot is incomplete")

        ready_raw = read_descriptor(
            files["READY.json"][0], "READY.json", MAX_JSON_BYTES
        )
        try:
            ready_value = json.loads(ready_raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            fail("READY.json is invalid")
        ready = ready_object(
            ready_value,
            "READY.json",
            {"schema_version", "status", "manifest", "manifest_sha256"},
        )
        if ready.get("manifest") != "manifest.sha256":
            fail("READY.json selects an unexpected manifest")

        manifest_raw = read_descriptor(
            files["manifest.sha256"][0], "backup manifest", MAX_MANIFEST_BYTES
        )
        manifest_sha256 = sha256_bytes(manifest_raw)
        if (
            manifest_sha256 != result_manifest_sha256
            or ready.get("manifest_sha256") != manifest_sha256
        ):
            fail("backup manifest hash differs from its ready receipts")
        entries = parse_manifest(manifest_raw)
        if set(entries) != set(files) - {"manifest.sha256", "READY.json"}:
            fail("backup manifest does not exactly cover the snapshot")
        for name, expected in entries.items():
            if sha256_descriptor(files[name][0], f"backup artifact {name}") != expected:
                fail("one backup artifact differs from the manifest")

        record_raw = read_descriptor(
            files["backup-record.json"][0], "backup-record.json", MAX_JSON_BYTES
        )
        try:
            record_value = json.loads(record_raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            fail("backup-record.json is invalid")
        record = ready_object(
            record_value,
            "backup-record.json",
            {
                "schema_version",
                "status",
                "created_at",
                "snapshot_directory",
                "containers",
                "sources",
                "redis",
                "artifacts",
            },
        )
        if record.get("snapshot_directory") != snapshot.name:
            fail("backup-record.json names a different snapshot")
        created_at = parse_created_at(record.get("created_at"))
        now = datetime.now(UTC)
        age = (now - created_at).total_seconds()
        if age < -60:
            fail("production backup creation time is in the future")
        fresh = age <= args.max_age_seconds
        if not fresh:
            fail("production backup is stale")

        artifact_values = record.get("artifacts")
        if not isinstance(artifact_values, list):
            fail("backup artifact inventory is invalid")
        artifact_inventory: dict[str, dict[str, Any]] = {}
        for item in artifact_values:
            if not isinstance(item, dict):
                fail("backup artifact inventory is invalid")
            require_keys(
                item, {"path", "sha256", "size"}, "backup artifact inventory entry"
            )
            name = item.get("path")
            digest = item.get("sha256")
            size = item.get("size")
            if (
                not isinstance(name, str)
                or name in artifact_inventory
                or name not in entries
                or name == "backup-record.json"
                or not isinstance(digest, str)
                or not SHA256_RE.fullmatch(digest)
                or not isinstance(size, int)
                or isinstance(size, bool)
                or size < 0
            ):
                fail("backup artifact inventory entry is invalid")
            artifact_inventory[name] = item
        expected_artifacts = set(entries) - {"backup-record.json"}
        if set(artifact_inventory) != expected_artifacts:
            fail("backup-record.json does not exactly inventory its artifacts")
        for name, item in artifact_inventory.items():
            descriptor, metadata = files[name]
            if item["sha256"] != entries[name] or item["size"] != metadata.st_size:
                fail("backup artifact inventory differs from the snapshot")
            assert_stable(descriptor, metadata, f"backup artifact {name}")

        container_values = record.get("containers")
        if not isinstance(container_values, dict) or set(container_values) != {
            "sub2api",
            "postgres",
            "redis",
        }:
            fail("backup container inventory is invalid")
        identities = {
            role: validate_backup_identity(container_values[role], role)
            for role in ("sub2api", "postgres", "redis")
        }
        if len({value["container_id"] for value in identities.values()}) != 3:
            fail("backup container IDs are not distinct")
        validate_current_identities(args.current_identities, identities)

        for descriptor, metadata in files.values():
            assert_stable(descriptor, metadata, "production backup snapshot entry")
        assert_stable(
            directory_descriptor, directory_metadata, "production backup snapshot"
        )
        return {
            "admission_mode": "fresh-production-backup",
            "format_version": SCHEMA_VERSION,
            "fresh": fresh,
            "status": "admitted",
            "snapshot_directory": str(snapshot),
            "manifest_sha256": manifest_sha256,
            "backup_created_at": created_at.isoformat().replace("+00:00", "Z"),
            "receipt_path": str(args.result_file),
            "receipt_sha256": args.receipt_sha256,
            "max_age_seconds": args.max_age_seconds,
            "containers": {
                role: {
                    "name": value["name"],
                    "container_id": value["container_id"],
                    "image_id": value["image_id"],
                }
                for role, value in identities.items()
            },
            "admission_binding_sha256": sha256_bytes(
                json.dumps(
                    {
                        "backup_created_at": created_at.isoformat().replace(
                            "+00:00", "Z"
                        ),
                        "containers": identities,
                        "manifest_sha256": manifest_sha256,
                        "receipt_path": str(args.result_file),
                        "receipt_sha256": args.receipt_sha256,
                        "snapshot_directory": str(snapshot),
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")
            ),
        }
    finally:
        for descriptor in descriptors:
            os.close(descriptor)
        os.close(directory_descriptor)


def service(config: dict[str, Any], name: str) -> dict[str, Any]:
    services = config.get("services")
    if not isinstance(services, dict) or not isinstance(services.get(name), dict):
        fail(f"resolved Compose config has no {name} service")
    return services[name]


def require_hardened(value: dict[str, Any], name: str) -> None:
    if value.get("build") is not None:
        fail(f"{name} retains a build definition")
    if value.get("pull_policy") != "never":
        fail(f"{name} must use pull_policy never")
    if value.get("read_only") is not True:
        fail(f"{name} must use a read-only root filesystem")
    if value.get("cap_drop") != ["ALL"]:
        fail(f"{name} must drop exactly all Linux capabilities")
    if value.get("security_opt") != ["no-new-privileges:true"]:
        fail(f"{name} must enable exactly no-new-privileges")
    if value.get("privileged") not in (None, False):
        fail(f"{name} must not be privileged")
    for key in ("cap_add", "devices", "device_cgroup_rules"):
        if value.get(key) not in (None, []):
            fail(f"{name} has prohibited {key}")
    for key in ("network_mode", "pid", "ipc"):
        if value.get(key) not in (None, ""):
            fail(f"{name} has prohibited {key}")


def require_networks(value: dict[str, Any], name: str, expected: set[str]) -> None:
    networks = value.get("networks")
    if not isinstance(networks, dict) or set(networks) != expected:
        fail(f"{name} has unexpected network attachments")


def require_no_ports(value: dict[str, Any], name: str) -> None:
    if value.get("ports") not in (None, []):
        fail(f"{name} must not publish host ports")


def require_loopback_port(
    value: dict[str, Any],
    name: str,
    *,
    port_name: str,
    target: int,
    published: str,
) -> None:
    ports = value.get("ports")
    if not isinstance(ports, list) or len(ports) != 1 or not isinstance(ports[0], dict):
        fail(f"{name} must publish exactly one port")
    port = ports[0]
    observed_published = port.get("published")
    if isinstance(observed_published, int) and not isinstance(observed_published, bool):
        observed_published = str(observed_published)
    if (
        port.get("name") != port_name
        or port.get("host_ip") != "127.0.0.1"
        or port.get("target") != target
        or observed_published != published
        or port.get("protocol") != "tcp"
        or port.get("mode") != "ingress"
    ):
        fail(f"{name} does not use its exact loopback port")


def secret_bindings(value: dict[str, Any], name: str) -> dict[str, str]:
    secrets = value.get("secrets")
    if not isinstance(secrets, list):
        fail(f"{name} has no resolved secret bindings")
    result: dict[str, str] = {}
    for item in secrets:
        if not isinstance(item, dict):
            fail(f"{name} has an invalid secret binding")
        source = item.get("source")
        target = item.get("target")
        if (
            not isinstance(source, str)
            or not source
            or not isinstance(target, str)
            or not target
            or target in result
        ):
            fail(f"{name} has an invalid secret binding")
        result[target] = source
    return result


def concrete(value: Any, label: str, pattern: re.Pattern[str]) -> str:
    if not isinstance(value, str) or not pattern.fullmatch(value):
        fail(f"{label} is not concrete")
    if (
        value.casefold() in PLACEHOLDERS
        or "replace" in value.casefold()
        or set(value) == {"0"}
    ):
        fail(f"{label} is a placeholder")
    return value


def derive_migration_head(repo_root: Path) -> str:
    versions = repo_root / "migrations" / "versions"
    if not versions.is_dir() or versions.is_symlink():
        fail("repository has no real migrations/versions directory")
    revisions: dict[str, str | None] = {}
    for path in sorted(versions.glob("*.py")):
        if path.is_symlink() or not path.is_file():
            fail("migration path is not a real regular file")
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except (OSError, UnicodeDecodeError, SyntaxError):
            fail("one migration cannot be parsed")
        revision: str | None = None
        down_revision: str | None = None
        seen_revision = False
        seen_down_revision = False
        for node in tree.body:
            target: str | None = None
            value_node: ast.expr | None = None
            if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
                target, value_node = node.target.id, node.value
            elif (
                isinstance(node, ast.Assign)
                and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name)
            ):
                target, value_node = node.targets[0].id, node.value
            if target not in {"revision", "down_revision"} or value_node is None:
                continue
            try:
                literal = ast.literal_eval(value_node)
            except (ValueError, TypeError):
                fail("migration revision metadata must be literal")
            if target == "revision":
                if seen_revision or not isinstance(literal, str):
                    fail("migration has invalid revision metadata")
                revision = literal
                seen_revision = True
            else:
                if seen_down_revision or (
                    literal is not None and not isinstance(literal, str)
                ):
                    fail("migration has an unsupported down_revision")
                down_revision = literal
                seen_down_revision = True
        if (
            not seen_revision
            or not seen_down_revision
            or revision is None
            or not REVISION_RE.fullmatch(revision)
            or revision in revisions
            or (down_revision is not None and not REVISION_RE.fullmatch(down_revision))
        ):
            fail("migration revision graph is invalid")
        revisions[revision] = down_revision
    if not revisions:
        fail("repository contains no migrations")
    unknown_parents = {
        parent for parent in revisions.values() if parent is not None
    } - set(revisions)
    if unknown_parents:
        fail("migration graph references an unknown parent")
    heads = set(revisions) - {
        parent for parent in revisions.values() if parent is not None
    }
    if len(heads) != 1:
        fail("migration graph does not have exactly one head")
    return next(iter(heads))


def compose_plan(args: argparse.Namespace) -> dict[str, Any]:
    require_absolute(args.repo_root, "repository root")
    try:
        repo_root = args.repo_root.resolve(strict=True)
    except OSError:
        fail("repository root is not accessible")
    if not repo_root.is_dir():
        fail("repository root is not a directory")
    raw, _ = read_regular_bytes(
        args.compose_config, "resolved Compose config", max_bytes=MAX_JSON_BYTES
    )
    try:
        config = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        fail("resolved Compose config is not valid UTF-8 JSON")
    if not isinstance(config, dict):
        fail("resolved Compose config is not an object")
    services = config.get("services")
    if not isinstance(services, dict) or set(services) != SERVICE_NAMES:
        fail("resolved Compose config must contain exactly the admitted services")
    api = service(config, "control-api")
    replica = service(config, "control-api-replica")
    migrate = service(config, "control-migrate")
    pwa = service(config, "codex-pwa")
    backup = service(config, "control-backup")
    selected = {
        "control-api": api,
        "control-api-replica": replica,
        "control-migrate": migrate,
        "codex-pwa": pwa,
        "control-backup": backup,
    }
    for name, value in selected.items():
        require_hardened(value, name)

    api_image = api.get("image")
    pwa_image = pwa.get("image")
    backup_image = backup.get("image")
    for image, label in (
        (api_image, "Control API image"),
        (pwa_image, "PWA image"),
        (backup_image, "PostgreSQL tools image"),
    ):
        if not isinstance(image, str) or not IMAGE_ID_RE.fullmatch(image):
            fail(f"{label} is not an exact local sha256 image ID")
    if replica.get("image") != api_image or migrate.get("image") != api_image:
        fail("Control API, replica, and migration images differ")
    if len({api_image, pwa_image, backup_image}) != 3:
        fail("bootstrap image IDs must be distinct")

    environments = [
        api.get("environment"),
        replica.get("environment"),
        migrate.get("environment"),
    ]
    if not all(isinstance(value, dict) for value in environments):
        fail("Control API production environment is missing")
    api_environment = environments[0]
    assert isinstance(api_environment, dict)
    if environments[1] != api_environment or environments[2] != api_environment:
        fail("Control API service environments differ")
    expected_environment = {
        "CONTROL_ENVIRONMENT": "production",
        "CONTROL_API_PREFIX": "/v1",
        "CONTROL_EXTERNAL_API_BASE_PATH": "/codex-api",
        "CONTROL_DATABASE_PASSWORD_FILE": "/run/secrets/control_db_password",
        "CONTROL_COOKIE_SECURE": "true",
        "CONTROL_COOKIE_SAMESITE": "strict",
        "CONTROL_COOKIE_NAME": "__Host-codex_control",
        "CONTROL_CSRF_COOKIE_NAME": "codex_csrf",
        "CONTROL_CSRF_HEADER_NAME": "x-csrf-token",
        "CONTROL_SUB2API_BASE_URL": "http://sub2api:8080",
        "CONTROL_SUB2API_AUTH_ME_PATH": "/api/v1/auth/me",
        "CONTROL_SUB2API_EXPECTED_VERSION": "0.1.175",
        "CONTROL_SUB2API_EXPECTED_COMMIT": "93c32fa",
        "CONTROL_TRUST_FORWARDED_FOR": "true",
        "CONTROL_DB_HOST": "postgres",
        "CONTROL_DB_PORT": "5432",
        "CONTROL_DB_USER": "codex_control",
        "CONTROL_DB_NAME": "codex_control",
        "CONTROL_REDIS_PASSWORD_FILE": "/run/secrets/control_redis_password",
        "CONTROL_REDIS_HOST": "redis",
        "CONTROL_REDIS_PORT": "6379",
        "CONTROL_REDIS_AUTH_MODE": "none",
        "CONTROL_REDIS_SCHEME": "redis",
        "CONTROL_REDIS_USER": "default",
        "CONTROL_REDIS_DATABASE": "0",
        "CONTROL_REDIS_PREFIX": "codex-control:",
        "CONTROL_SESSION_HMAC_SECRET_FILE": "/run/secrets/control_session_hmac_secret",
        "CONTROL_API_WORKERS": "1",
    }
    for key, expected in expected_environment.items():
        if api_environment.get(key) != expected:
            fail(f"production environment {key} is not the admitted value")
    if api_environment.get("CONTROL_DB_QUERY") not in (None, ""):
        fail("production database query must be empty during bootstrap")
    if api_environment.get("CONTROL_REDIS_QUERY") not in (None, ""):
        fail("production Redis query must be empty during bootstrap")
    release = concrete(
        api_environment.get("CONTROL_BUILD_VERSION"), "control release", RELEASE_RE
    )
    source_revision = concrete(
        api_environment.get("CONTROL_BUILD_VCS_REF"),
        "control source revision",
        SOURCE_REVISION_RE,
    )
    marker = api_environment.get("CONTROL_SUB2API_CONTRACT_MARKER")
    if marker != "0.1.175/93c32fa":
        fail("Sub2API contract marker is not the admitted production tuple")
    origin = api_environment.get("CONTROL_ALLOWED_ORIGINS_CSV")
    if not isinstance(origin, str) or "," in origin:
        fail("production must have one public origin")
    parsed_origin = urlsplit(origin)
    if (
        parsed_origin.scheme != "https"
        or not parsed_origin.netloc
        or parsed_origin.path not in ("", "/")
        or parsed_origin.query
        or parsed_origin.fragment
        or parsed_origin.username is not None
        or parsed_origin.password is not None
    ):
        fail("production public origin is not one HTTPS origin")
    for name, value in selected.items():
        labels = value.get("labels")
        if (
            not isinstance(labels, dict)
            or labels.get("org.opencontainers.image.version") != release
            or labels.get("org.opencontainers.image.revision") != source_revision
        ):
            fail(f"{name} release labels differ from the production environment")

    expected_commands: dict[str, list[str] | None] = {
        "control-api": ["api"],
        "control-api-replica": ["api"],
        "control-migrate": ["migrate"],
        "codex-pwa": None,
        "control-backup": None,
    }
    for name, expected in expected_commands.items():
        value = selected[name]
        if value.get("command") != expected or value.get("entrypoint") is not None:
            fail(f"{name} has an unexpected command or entrypoint")

    for name, value in (
        ("control-api", api),
        ("control-api-replica", replica),
        ("control-migrate", migrate),
    ):
        if secret_bindings(value, name) != SECRET_TARGETS:
            fail(f"{name} does not receive exactly the application secrets")
    if secret_bindings(backup, "control-backup") != {
        "/run/secrets/control_db_password": "control_db_password"
    }:
        fail("control-backup does not receive exactly the database secret")
    if pwa.get("secrets") not in (None, []):
        fail("codex-pwa must not receive application secrets")
    secret_definitions = config.get("secrets")
    if not isinstance(secret_definitions, dict) or set(secret_definitions) != set(
        SECRET_TARGETS.values()
    ):
        fail("resolved Compose config has unexpected secret definitions")
    secret_files: dict[str, str] = {}
    for name, definition in secret_definitions.items():
        if not isinstance(definition, dict):
            fail("one resolved Compose secret definition is invalid")
        secret_file = definition.get("file")
        if not isinstance(secret_file, str) or not Path(secret_file).is_absolute():
            fail("resolved Compose secret files must be absolute")
        secret_files[name] = secret_file

    networks = config.get("networks")
    if not isinstance(networks, dict) or set(networks) != {
        "sub2api-network",
        "pwa-network",
    }:
        fail("resolved Compose config has unexpected networks")
    sub2api_network = networks["sub2api-network"]
    pwa_network = networks["pwa-network"]
    expected_pwa_driver_opts = {
        "com.docker.network.bridge.enable_ip_masquerade": "false",
        "com.docker.network.bridge.enable_icc": "false",
    }
    if (
        not isinstance(sub2api_network, dict)
        or sub2api_network.get("name") != "sub2api-network"
        or sub2api_network.get("external") is not True
        or sub2api_network.get("internal") not in (None, False)
    ):
        fail("Sub2API network is not the exact existing external network")
    if (
        not isinstance(pwa_network, dict)
        or pwa_network.get("driver") != "bridge"
        or pwa_network.get("internal") not in (None, False)
        or pwa_network.get("enable_ipv6") not in (None, False)
        or pwa_network.get("external") not in (None, False)
        or pwa_network.get("driver_opts") != expected_pwa_driver_opts
        or not isinstance(pwa_network.get("name"), str)
        or not pwa_network["name"]
    ):
        fail(
            "PWA network is not one named non-internal bridge with exact "
            "masquerading-disabled and ICC-disabled options"
        )
    require_networks(api, "control-api", {"sub2api-network"})
    require_networks(replica, "control-api-replica", {"sub2api-network"})
    require_networks(migrate, "control-migrate", {"sub2api-network"})
    require_networks(backup, "control-backup", {"sub2api-network"})
    require_networks(pwa, "codex-pwa", {"pwa-network"})
    require_no_ports(migrate, "control-migrate")
    require_no_ports(backup, "control-backup")
    require_loopback_port(
        api,
        "control-api",
        port_name="control-api-loopback",
        target=8090,
        published="18090",
    )
    require_loopback_port(
        replica,
        "control-api-replica",
        port_name="control-api-replica-loopback",
        target=8090,
        published="18093",
    )
    require_loopback_port(
        pwa,
        "codex-pwa",
        port_name="pwa-loopback",
        target=8080,
        published="18091",
    )

    backup_environment = backup.get("environment")
    if not isinstance(backup_environment, dict):
        fail("control-backup environment is missing")
    database_keys = {
        "CONTROL_DATABASE_PASSWORD_FILE",
        "CONTROL_DB_HOST",
        "CONTROL_DB_PORT",
        "CONTROL_DB_USER",
        "CONTROL_DB_NAME",
    }
    if set(backup_environment) != {"BACKUP_DIR", *database_keys}:
        fail("control-backup environment is not minimal")
    if backup_environment.get("BACKUP_DIR") != "/backups":
        fail("control-backup destination must be /backups")
    for key in database_keys:
        if backup_environment.get(key) != api_environment.get(key):
            fail(f"control-backup disagrees with Control API on {key}")
    volumes = backup.get("volumes")
    if (
        not isinstance(volumes, list)
        or len(volumes) != 1
        or not isinstance(volumes[0], dict)
        or volumes[0].get("type") != "bind"
        or volumes[0].get("target") != "/backups"
        or volumes[0].get("read_only") not in (None, False)
    ):
        fail("control-backup must have one writable /backups bind mount")
    backup_source = volumes[0].get("source")
    if not isinstance(backup_source, str):
        fail("control-backup source directory is missing")
    backup_directory = Path(backup_source)
    user = backup.get("user")
    if not isinstance(user, str) or re.fullmatch(r"[0-9]+:[0-9]+", user) is None:
        fail("control-backup must have an explicit numeric UID:GID")
    if user != args.expected_backup_user:
        fail("control-backup UID:GID is not the admitted bootstrap identity")
    uid_text, gid_text = user.split(":", 1)
    backup_uid, backup_gid = int(uid_text), int(gid_text)
    if backup_uid == 0 or backup_gid == 0:
        fail("control-backup must not run as root")
    directory_descriptor, _ = open_directory(
        backup_directory,
        "control backup directory",
        exact_mode=0o700,
        expected_uid=backup_uid,
        expected_gid=backup_gid,
    )
    os.close(directory_descriptor)
    resolved_backup = backup_directory.resolve(strict=True)
    try:
        resolved_backup.relative_to(repo_root)
    except ValueError:
        pass
    else:
        fail("control backup directory must be outside the source repository")

    project = config.get("name")
    if not isinstance(project, str) or not PROJECT_RE.fullmatch(project):
        fail("resolved Compose project name is invalid")
    target_head = derive_migration_head(repo_root)
    return {
        "format_version": SCHEMA_VERSION,
        "status": "admitted",
        "compose_sha256": sha256_bytes(raw),
        "compose_project": project,
        "api_image": api_image,
        "pwa_image": pwa_image,
        "backup_image": backup_image,
        "release": release,
        "source_revision": source_revision,
        "sub2api_contract_marker": marker,
        "backup_user": user,
        "backup_directory": str(resolved_backup),
        "secret_files": secret_files,
        "sub2api_network": sub2api_network["name"],
        "pwa_network": pwa_network["name"],
        "pwa_network_driver": "bridge",
        "pwa_network_driver_opts": expected_pwa_driver_opts,
        "public_origin": origin.rstrip("/"),
        "redis_prefix": api_environment["CONTROL_REDIS_PREFIX"],
        "target_migration_head": target_head,
        "instances": {
            "control-api": {
                "image_id_key": "api",
                "network": sub2api_network["name"],
                "target_port": 8090,
                "published_port": "18090",
            },
            "control-api-replica": {
                "image_id_key": "api",
                "network": sub2api_network["name"],
                "target_port": 8090,
                "published_port": "18093",
            },
            "codex-pwa": {
                "image_id_key": "pwa",
                "network": pwa_network["name"],
                "target_port": 8080,
                "published_port": "18091",
            },
        },
    }


def inspect_image(path: Path, label: str) -> dict[str, Any]:
    value = load_json(path, f"{label} image inspection")
    if not isinstance(value, list) or len(value) != 1 or not isinstance(value[0], dict):
        fail(f"{label} image inspection must contain exactly one object")
    return value[0]


def images(args: argparse.Namespace) -> dict[str, Any]:
    plan = load_json(args.plan, "bootstrap Compose plan")
    if (
        not isinstance(plan, dict)
        or plan.get("format_version") != 1
        or plan.get("status") != "admitted"
    ):
        fail("bootstrap Compose plan is not admitted")
    release = concrete(plan.get("release"), "control release", RELEASE_RE)
    source_revision = concrete(
        plan.get("source_revision"), "control source revision", SOURCE_REVISION_RE
    )
    inputs = {
        "api": (plan.get("api_image"), args.api_inspect),
        "pwa": (plan.get("pwa_image"), args.pwa_inspect),
        "backup": (plan.get("backup_image"), args.backup_inspect),
    }
    observed: dict[str, dict[str, str]] = {}
    ids: list[str] = []
    for name, (expected_id, path) in inputs.items():
        if not isinstance(expected_id, str) or not IMAGE_ID_RE.fullmatch(expected_id):
            fail(f"plan {name} image is not a local sha256 ID")
        inspection = inspect_image(path, name)
        config = inspection.get("Config")
        labels = config.get("Labels") if isinstance(config, dict) else None
        if inspection.get("Id") != expected_id:
            fail(f"{name} image ID differs from the Compose plan")
        if inspection.get("Os") != "linux" or inspection.get("Architecture") != "amd64":
            fail(f"{name} image is not linux/amd64")
        if not isinstance(labels, dict):
            fail(f"{name} image has no OCI labels")
        if name == "api" and config.get("User") != "10001:10001":
            fail("api image does not run as the admitted 10001:10001 user")
        source = labels.get("org.opencontainers.image.source")
        if (
            labels.get("org.opencontainers.image.version") != release
            or labels.get("org.opencontainers.image.revision") != source_revision
            or not isinstance(source, str)
            or not source.strip()
            or source.strip().casefold() in PLACEHOLDERS
            or "replace" in source.casefold()
        ):
            fail(f"{name} image OCI identity differs from the Compose plan")
        observed[name] = {"image_id": expected_id, "source": source.strip()}
        ids.append(expected_id)
    if len(set(ids)) != 3:
        fail("inspected bootstrap image IDs are not distinct")
    return {
        "format_version": SCHEMA_VERSION,
        "status": "admitted",
        "release": release,
        "source_revision": source_revision,
        **observed,
    }


def api_image_contract(args: argparse.Namespace) -> dict[str, Any]:
    if not IMAGE_ID_RE.fullmatch(args.expected_image):
        fail("admitted API image is not one exact local sha256 image ID")
    images_raw, _ = read_regular_bytes(
        args.images,
        "admitted image evidence",
        max_bytes=MAX_JSON_BYTES,
        exact_mode=0o600,
        require_absolute_path=True,
    )
    try:
        image_evidence = strict_json_bytes(images_raw, "admitted image evidence")
    except UnicodeDecodeError:
        fail("admitted image evidence is not valid UTF-8 JSON")
    if (
        not isinstance(image_evidence, dict)
        or image_evidence.get("format_version") != SCHEMA_VERSION
        or image_evidence.get("status") != "admitted"
    ):
        fail("image evidence is not admitted")
    admitted_api = image_evidence.get("api")
    if (
        not isinstance(admitted_api, dict)
        or admitted_api.get("image_id") != args.expected_image
    ):
        fail("API image contract probe did not use the admitted API image ID")
    observed = load_json(
        args.observed,
        "API image embedded contract observation",
        exact_mode=0o600,
        require_absolute_path=True,
    )
    versions_lock_raw, _ = read_regular_bytes(
        args.versions_lock,
        "versions lock",
        max_bytes=MAX_JSON_BYTES,
    )
    try:
        versions_lock = strict_json_bytes(versions_lock_raw, "versions lock")
    except UnicodeDecodeError:
        fail("versions lock is not valid UTF-8 JSON")
    if not isinstance(observed, dict) or not isinstance(versions_lock, dict):
        fail("API image contract evidence or versions lock is not an object")

    codex = versions_lock.get("codex")
    sub2api = versions_lock.get("sub2api")
    if not isinstance(codex, dict) or not isinstance(sub2api, dict):
        fail("versions lock is missing the Codex or Sub2API contract")
    codex_version = codex.get("cli_version")
    schema_digest = codex.get("schema_sha256")
    sub2api_version = sub2api.get("runtime_version")
    sub2api_commit = sub2api.get("runtime_commit")
    if (
        not isinstance(codex_version, str)
        or not RELEASE_RE.fullmatch(codex_version)
        or not isinstance(schema_digest, str)
        or not SHA256_RE.fullmatch(schema_digest)
        or not isinstance(sub2api_version, str)
        or not RELEASE_RE.fullmatch(sub2api_version)
        or not isinstance(sub2api_commit, str)
        or re.fullmatch(r"[0-9a-f]{40}", sub2api_commit) is None
    ):
        fail("versions lock contains an invalid Codex or Sub2API contract tuple")

    expected = {
        "appserver_schema_digest": schema_digest,
        "codex_expected_version": codex_version,
        "sub2api_expected_commit": sub2api_commit[:7],
        "sub2api_expected_version": sub2api_version,
    }
    if set(observed) != set(expected) or any(
        not isinstance(value, str) or not value for value in observed.values()
    ):
        fail("API image embedded contract observation has unexpected fields")
    mismatches = sorted(
        name
        for name, expected_value in expected.items()
        if observed[name] != expected_value
    )
    if mismatches:
        fail(
            "API image embedded contract differs from versions.lock.json: "
            + ", ".join(mismatches)
        )
    return {
        "format_version": SCHEMA_VERSION,
        "status": "admitted",
        "api_image": args.expected_image,
        "images_sha256": sha256_bytes(images_raw),
        "versions_lock_sha256": sha256_bytes(versions_lock_raw),
        "expected": expected,
        "observed": observed,
    }


def runtime_secrets(args: argparse.Namespace) -> dict[str, Any]:
    numeric_values = {
        "API UID": args.api_uid,
        "API GID": args.api_gid,
        "backup UID": args.backup_uid,
        "secret parent UID": args.parent_uid,
        "secret parent GID": args.parent_gid,
    }
    for label, value in numeric_values.items():
        if value < 0 or value > 2**31 - 1:
            fail(f"{label} is outside the admitted numeric range")
    if args.api_uid == 0 or args.api_gid == 0 or args.backup_uid == 0:
        fail("runtime secret readers must be non-root")

    paths = {
        "database": args.database_secret,
        "redis": args.redis_secret,
        "session_hmac": args.session_secret,
    }
    parent_paths = {path.parent for path in paths.values()}
    if len(parent_paths) != 1:
        fail("runtime secrets must share one private parent directory")
    parent = next(iter(parent_paths))
    parent_descriptor, _ = open_directory(
        parent,
        "runtime secret parent directory",
        exact_mode=0o700,
        expected_uid=args.parent_uid,
        expected_gid=args.parent_gid,
    )
    os.close(parent_descriptor)

    expectations = {
        "database": (args.backup_uid, args.api_gid, 0o440),
        "redis": (args.api_uid, args.api_gid, 0o400),
        "session_hmac": (args.api_uid, args.api_gid, 0o400),
    }
    evidence: dict[str, dict[str, object]] = {}
    identities: set[tuple[int, int]] = set()
    for name, path in paths.items():
        path_text = str(path)
        if any(character in path_text for character in (",", "\n", "\r", "\x00")):
            fail(f"{name} runtime secret path is not Docker-mount safe")
        expected_uid, expected_gid, expected_mode = expectations[name]
        descriptor, metadata = open_regular(
            path,
            f"{name} runtime secret",
            max_bytes=MAX_SECRET_BYTES,
            exact_mode=expected_mode,
            expected_uid=expected_uid,
            require_absolute_path=True,
        )
        try:
            if metadata.st_gid != expected_gid:
                fail(f"{name} runtime secret has an unexpected group")
            if metadata.st_size == 0:
                fail(f"{name} runtime secret is empty")
            if metadata.st_nlink != 1:
                fail(f"{name} runtime secret must have exactly one hard link")
            identity = (metadata.st_dev, metadata.st_ino)
            if identity in identities:
                fail("runtime secret files must be distinct inodes")
            identities.add(identity)
            assert_stable(descriptor, metadata, f"{name} runtime secret")
        finally:
            os.close(descriptor)
        evidence[name] = {
            "path": path_text,
            "uid": metadata.st_uid,
            "gid": metadata.st_gid,
            "mode": f"{stat.S_IMODE(metadata.st_mode):04o}",
            "size": metadata.st_size,
            "readers": (
                ["control-api", "control-backup"]
                if name == "database"
                else ["control-api"]
            ),
        }
    return {
        "format_version": SCHEMA_VERSION,
        "status": "admitted",
        "parent": str(parent),
        "parent_mode": "0700",
        "secrets": evidence,
    }


def inspect_container(path: Path, label: str) -> dict[str, Any]:
    value = load_json(path, f"{label} container inspection")
    if not isinstance(value, list) or len(value) != 1 or not isinstance(value[0], dict):
        fail(f"{label} container inspection must contain exactly one object")
    return value[0]


def require_pwa_network_inspect(
    path: Path,
    *,
    expected_name: str,
    expected_project: str,
    pwa_container: dict[str, Any],
) -> dict[str, Any]:
    value = load_json(path, "PWA Docker network inspection", exact_mode=0o600)
    if not isinstance(value, list) or len(value) != 1 or not isinstance(value[0], dict):
        fail("PWA Docker network inspection must contain exactly one object")
    network = value[0]
    expected_options = {
        "com.docker.network.bridge.enable_ip_masquerade": "false",
        "com.docker.network.bridge.enable_icc": "false",
    }
    network_id = network.get("Id")
    labels = network.get("Labels")
    if (
        not isinstance(network_id, str)
        or not CONTAINER_ID_RE.fullmatch(network_id)
        or network.get("Name") != expected_name
        or network.get("Driver") != "bridge"
        or network.get("Scope") != "local"
        or network.get("Internal") is not False
        or network.get("Attachable") is not False
        or network.get("Ingress") is not False
        or network.get("ConfigOnly") is not False
        or network.get("EnableIPv6") is not False
        or network.get("Options") != expected_options
        or not isinstance(labels, dict)
        or labels.get("com.docker.compose.project") != expected_project
        or labels.get("com.docker.compose.network") != "pwa-network"
    ):
        fail("running PWA network does not retain the admitted bridge boundary")
    expected_container_id = pwa_container.get("Id")
    container_name = pwa_container.get("Name")
    network_settings = pwa_container.get("NetworkSettings")
    attachments = (
        network_settings.get("Networks") if isinstance(network_settings, dict) else None
    )
    attachment = (
        attachments.get(expected_name) if isinstance(attachments, dict) else None
    )
    if (
        not isinstance(expected_container_id, str)
        or not CONTAINER_ID_RE.fullmatch(expected_container_id)
        or not isinstance(container_name, str)
        or not container_name.startswith("/")
        or not isinstance(attachment, dict)
        or attachment.get("NetworkID") != network_id
        or not isinstance(attachment.get("EndpointID"), str)
        or not CONTAINER_ID_RE.fullmatch(attachment["EndpointID"])
    ):
        fail("running PWA container is not bound to the inspected network identity")
    containers = network.get("Containers")
    if not isinstance(containers, dict) or set(containers) != {expected_container_id}:
        fail("running PWA network must contain exactly the admitted PWA container")
    member = containers[expected_container_id]
    if (
        not isinstance(member, dict)
        or member.get("Name") != container_name.removeprefix("/")
        or member.get("EndpointID") != attachment["EndpointID"]
    ):
        fail("running PWA network has inconsistent container attachment evidence")
    return {
        "network_id": network_id,
        "name": expected_name,
        "compose_project": expected_project,
        "driver": "bridge",
        "internal": False,
        "enable_ipv6": bool(network.get("EnableIPv6", False)),
        "options": expected_options,
        "container_id": expected_container_id,
    }


def running(args: argparse.Namespace) -> dict[str, Any]:
    plan = load_json(args.plan, "bootstrap Compose plan")
    image_evidence = load_json(args.images, "bootstrap image evidence")
    if (
        not isinstance(plan, dict)
        or plan.get("format_version") != SCHEMA_VERSION
        or plan.get("status") != "admitted"
        or not isinstance(image_evidence, dict)
        or image_evidence.get("format_version") != SCHEMA_VERSION
        or image_evidence.get("status") != "admitted"
        or image_evidence.get("release") != plan.get("release")
        or image_evidence.get("source_revision") != plan.get("source_revision")
    ):
        fail("running container evidence inputs are not one admitted bootstrap plan")
    instances = plan.get("instances")
    if not isinstance(instances, dict) or set(instances) != {
        "control-api",
        "control-api-replica",
        "codex-pwa",
    }:
        fail("bootstrap plan has an invalid running instance set")
    paths = {
        "control-api": args.api_inspect,
        "control-api-replica": args.api_replica_inspect,
        "codex-pwa": args.pwa_inspect,
    }
    result: dict[str, dict[str, str]] = {}
    observed_containers: dict[str, dict[str, Any]] = {}
    observed_container_ids: set[str] = set()
    for name, path in paths.items():
        expected = instances.get(name)
        if not isinstance(expected, dict):
            fail(f"bootstrap plan has no admitted {name} instance")
        image_key = expected.get("image_id_key")
        if image_key not in {"api", "pwa"}:
            fail(f"bootstrap plan has an invalid image binding for {name}")
        image_value = image_evidence.get(image_key)
        expected_image_id = (
            image_value.get("image_id") if isinstance(image_value, dict) else None
        )
        if not isinstance(expected_image_id, str) or not IMAGE_ID_RE.fullmatch(
            expected_image_id
        ):
            fail(f"bootstrap image evidence has no admitted {image_key} image")
        container = inspect_container(path, name)
        if container.get("Image") != expected_image_id:
            fail(f"running {name} does not use the admitted image ID")
        container_id = container.get("Id")
        if (
            not isinstance(container_id, str)
            or not CONTAINER_ID_RE.fullmatch(container_id)
            or container_id in observed_container_ids
        ):
            fail(f"running {name} has an invalid or duplicate container ID")
        observed_container_ids.add(container_id)
        observed_containers[name] = container
        host_config = container.get("HostConfig")
        if not isinstance(host_config, dict):
            fail(f"running {name} has no Docker host configuration")
        if host_config.get("ReadonlyRootfs") is not True:
            fail(f"running {name} root filesystem is not read-only")
        if (
            host_config.get("Privileged") not in (None, False)
            or host_config.get("CapAdd") not in (None, [])
            or host_config.get("CapDrop") != ["ALL"]
            or host_config.get("SecurityOpt")
            not in (["no-new-privileges"], ["no-new-privileges:true"])
        ):
            fail(f"running {name} does not retain the admitted privilege boundary")
        target_port = expected.get("target_port")
        published_port = expected.get("published_port")
        if (
            not isinstance(target_port, int)
            or isinstance(target_port, bool)
            or not isinstance(published_port, str)
            or not published_port.isdigit()
        ):
            fail(f"bootstrap plan has invalid port evidence for {name}")
        expected_ports = {
            f"{target_port}/tcp": [{"HostIp": "127.0.0.1", "HostPort": published_port}]
        }
        if host_config.get("PortBindings") != expected_ports:
            fail(f"running {name} does not use the admitted loopback port")
        state = container.get("State")
        health = state.get("Health") if isinstance(state, dict) else None
        if (
            not isinstance(state, dict)
            or state.get("Running") is not True
            or not isinstance(health, dict)
            or health.get("Status") != "healthy"
        ):
            fail(f"running {name} is not healthy")
        network_settings = container.get("NetworkSettings")
        attached = (
            network_settings.get("Networks")
            if isinstance(network_settings, dict)
            else None
        )
        network = expected.get("network")
        if (
            not isinstance(attached, dict)
            or not isinstance(network, str)
            or set(attached) != {network}
        ):
            fail(f"running {name} is not on exactly the admitted network")
        runtime_ports = network_settings.get("Ports")
        expected_runtime_port = [{"HostIp": "127.0.0.1", "HostPort": published_port}]
        if (
            not isinstance(runtime_ports, dict)
            or runtime_ports.get(f"{target_port}/tcp") != expected_runtime_port
            or any(
                value not in (None, [])
                for key, value in runtime_ports.items()
                if key != f"{target_port}/tcp"
            )
        ):
            fail(f"running {name} does not expose exactly the admitted runtime port")
        result[name] = {
            "container_id": container_id,
            "image_id": expected_image_id,
            "health": "healthy",
            "network": network,
            "published_port": published_port,
        }
    pwa_network = plan.get("pwa_network")
    if not isinstance(pwa_network, str) or not pwa_network:
        fail("bootstrap plan has no admitted PWA network")
    network_evidence = require_pwa_network_inspect(
        args.pwa_network_inspect,
        expected_name=pwa_network,
        expected_project=plan.get("compose_project"),
        pwa_container=observed_containers["codex-pwa"],
    )
    return {
        "format_version": SCHEMA_VERSION,
        "status": "admitted",
        "verified_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "containers": result,
        "pwa_network": network_evidence,
    }


def parse_text_evidence(raw: bytes) -> dict[str, Any]:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        fail("pristine database evidence is not UTF-8")
    values: dict[str, str] = {}
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        if line.count("=") != 1:
            fail("text database evidence is not canonical key=value data")
        key, value = line.split("=", 1)
        if not key or key.strip() != key or value.strip() != value or key in values:
            fail("text database evidence has invalid or duplicate keys")
        values[key] = value
    expected = {
        "schema_version",
        "database",
        "role",
        "before_database_exists",
        "before_role_exists",
        "after_database_exists",
        "after_role_exists",
        "after_alembic_version_exists",
        "after_tables",
        "after_views",
        "after_sequences",
        "target_migration_head",
    }
    if set(values) != expected or values.get("schema_version") != "1":
        fail("text database evidence has an unexpected schema")
    boolean = {"true": True, "false": False}
    boolean_keys = (
        "before_database_exists",
        "before_role_exists",
        "after_database_exists",
        "after_role_exists",
        "after_alembic_version_exists",
    )
    if any(values[key] not in boolean for key in boolean_keys):
        fail("text database evidence has an invalid boolean")
    for key in ("after_tables", "after_views", "after_sequences"):
        if values[key] != "":
            fail("text database evidence reports existing application objects")
    return {
        "schema_version": 1,
        "database": values["database"],
        "role": values["role"],
        "before": {
            "database_exists": boolean[values["before_database_exists"]],
            "role_exists": boolean[values["before_role_exists"]],
        },
        "after": {
            "database_exists": boolean[values["after_database_exists"]],
            "role_exists": boolean[values["after_role_exists"]],
            "alembic_version_exists": boolean[values["after_alembic_version_exists"]],
            "tables": [],
            "views": [],
            "sequences": [],
        },
        "target_migration_head": values["target_migration_head"],
    }


def pristine_db(args: argparse.Namespace) -> dict[str, Any]:
    raw, _ = read_regular_bytes(
        args.evidence, "pristine database evidence", max_bytes=MAX_JSON_BYTES
    )
    try:
        evidence = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        evidence = parse_text_evidence(raw)
    if not isinstance(evidence, dict):
        fail("pristine database evidence is not an object")
    require_keys(
        evidence,
        {
            "schema_version",
            "database",
            "role",
            "before",
            "after",
            "target_migration_head",
        },
        "pristine database evidence",
    )
    if evidence.get("schema_version") != SCHEMA_VERSION:
        fail("pristine database evidence has an unsupported schema")
    database = evidence.get("database")
    role = evidence.get("role")
    if (
        not isinstance(database, str)
        or not IDENTIFIER_RE.fullmatch(database)
        or not isinstance(role, str)
        or not IDENTIFIER_RE.fullmatch(role)
        or database != "codex_control"
        or role != "codex_control"
    ):
        fail("pristine database evidence names unexpected resources")
    before = evidence.get("before")
    after = evidence.get("after")
    if not isinstance(before, dict) or not isinstance(after, dict):
        fail("pristine database evidence is missing before/after states")
    require_keys(
        before, {"database_exists", "role_exists"}, "pre-provision database evidence"
    )
    require_keys(
        after,
        {
            "database_exists",
            "role_exists",
            "alembic_version_exists",
            "tables",
            "views",
            "sequences",
        },
        "post-provision database evidence",
    )
    if before != {"database_exists": False, "role_exists": False}:
        fail("Control database or role existed before provisioning")
    if after.get("database_exists") is not True or after.get("role_exists") is not True:
        fail("Control database or role was not provisioned")
    if after.get("alembic_version_exists") is not False:
        fail("Control database already has alembic_version")
    for key in ("tables", "views", "sequences"):
        value = after.get(key)
        if not isinstance(value, list) or value:
            fail("Control database is not pristine after provisioning")
    repo_root = Path(__file__).resolve().parents[2]
    target_head = derive_migration_head(repo_root)
    if evidence.get("target_migration_head") != target_head:
        fail("database evidence targets a different migration head")
    return {
        "format_version": SCHEMA_VERSION,
        "status": "admitted",
        "database": database,
        "role": role,
        "target_migration_head": target_head,
        "pristine": True,
    }


def postgres_boundary(args: argparse.Namespace) -> dict[str, Any]:
    evidence = load_json(args.evidence, "PostgreSQL bootstrap boundary evidence")
    if not isinstance(evidence, dict):
        fail("PostgreSQL bootstrap boundary evidence is not an object")
    require_keys(
        evidence,
        {
            "schema_version",
            "database",
            "role",
            "sub2api_database",
            "allow_sub2api_public_connect",
            "before",
            "after",
        },
        "PostgreSQL bootstrap boundary evidence",
    )
    if (
        evidence.get("schema_version") != SCHEMA_VERSION
        or evidence.get("database") != "codex_control"
        or evidence.get("role") != "codex_control"
        or evidence.get("sub2api_database") != "sub2api"
    ):
        fail("PostgreSQL bootstrap boundary evidence names unexpected resources")
    allow_public = evidence.get("allow_sub2api_public_connect")
    before = evidence.get("before")
    after = evidence.get("after")
    if (
        not isinstance(allow_public, bool)
        or not isinstance(before, dict)
        or not isinstance(after, dict)
    ):
        fail("PostgreSQL bootstrap boundary evidence has invalid state")
    require_keys(
        before,
        {
            "database_exists",
            "role_exists",
            "sub2api_public_connect",
            "sub2api_database_acl_sha256",
        },
        "pre-provision PostgreSQL boundary",
    )
    require_keys(
        after,
        {
            "database_exists",
            "role_exists",
            "database_owner",
            "sub2api_public_connect",
            "sub2api_database_acl_sha256",
            "role_memberships",
            "direct_database_acl_privileges",
            "direct_schema_acl_privileges",
            "direct_relation_acl_privileges",
            "owned_schemas",
            "owned_relations",
            "effective_relation_privileges",
            "effective_sequence_privileges",
            "effective_schema_create_privileges",
        },
        "post-provision PostgreSQL boundary",
    )
    if (
        before.get("database_exists") is not False
        or before.get("role_exists") is not False
    ):
        fail("Control database or role existed before PostgreSQL bootstrap")
    public_connect = before.get("sub2api_public_connect")
    if not isinstance(public_connect, bool) or allow_public != public_connect:
        fail("Sub2API PUBLIC CONNECT requires its exact explicit bootstrap exception")
    if (
        after.get("database_exists") is not True
        or after.get("role_exists") is not True
        or after.get("database_owner") != "codex_control"
        or after.get("sub2api_public_connect") is not public_connect
    ):
        fail("post-provision PostgreSQL identity differs from the admitted boundary")
    before_acl = before.get("sub2api_database_acl_sha256")
    after_acl = after.get("sub2api_database_acl_sha256")
    if (
        not isinstance(before_acl, str)
        or not SHA256_RE.fullmatch(before_acl)
        or after_acl != before_acl
    ):
        fail("Sub2API database ACL changed during PostgreSQL bootstrap")
    zero_fields = (
        "role_memberships",
        "direct_database_acl_privileges",
        "direct_schema_acl_privileges",
        "direct_relation_acl_privileges",
        "owned_schemas",
        "owned_relations",
        "effective_relation_privileges",
        "effective_sequence_privileges",
        "effective_schema_create_privileges",
    )
    if any(
        type(after.get(name)) is not int or after[name] != 0 for name in zero_fields
    ):
        fail("Control role gained membership, ownership, or Sub2API privileges")
    return {
        "format_version": SCHEMA_VERSION,
        "status": "admitted",
        "database": "codex_control",
        "role": "codex_control",
        "sub2api_database": "sub2api",
        "sub2api_public_connect": public_connect,
        "public_connect_exception_recorded": allow_public,
        "sub2api_database_acl_sha256": before_acl,
        "role_memberships": 0,
        "direct_schema_acl_privileges": 0,
        "direct_relation_acl_privileges": 0,
        "effective_relation_privileges": 0,
        "effective_sequence_privileges": 0,
    }


def control_backup(args: argparse.Namespace) -> dict[str, Any]:
    if args.max_age_seconds <= 0 or args.expected_owner_uid <= 0:
        fail("control backup age and owner inputs are invalid")
    if not math.isfinite(args.not_before) or args.not_before < 0:
        fail("control backup admission window is invalid")
    if not IMAGE_ID_RE.fullmatch(args.postgres_tools_image):
        fail("PostgreSQL tools image must be one exact local sha256 image ID")
    if any(character in str(args.directory) for character in (",", "\n", "\r")):
        fail("control backup directory cannot be represented as a Docker bind mount")
    docker = (
        shutil.which(args.docker) if os.path.sep not in args.docker else args.docker
    )
    if docker is None or not Path(docker).is_file() or not os.access(docker, os.X_OK):
        fail("Docker is required for control backup validation")
    directory_descriptor, directory_metadata = open_directory(
        args.directory,
        "control backup directory",
        exact_mode=0o700,
        expected_uid=args.expected_owner_uid,
    )
    descriptors: list[int] = []
    try:
        now = datetime.now(UTC).timestamp()
        candidates: list[tuple[str, int, os.stat_result]] = []
        for name in os.listdir(directory_descriptor):
            if BACKUP_DUMP_RE.fullmatch(name) is None:
                continue
            path = args.directory / name
            descriptor, metadata = open_regular(
                path,
                f"control backup dump {name}",
                max_bytes=2**63 - 1,
                exact_mode=0o600,
                expected_uid=args.expected_owner_uid,
            )
            descriptors.append(descriptor)
            if metadata.st_nlink != 1:
                fail("control backup dump must have exactly one hard link")
            if metadata.st_mtime >= args.not_before:
                candidates.append((name, descriptor, metadata))
        if len(candidates) != 1:
            fail("control backup admission requires exactly one new dump")
        dump_name, dump_descriptor, dump_metadata = candidates[0]
        if dump_metadata.st_size <= 0:
            fail("control backup dump is empty")
        if dump_metadata.st_mtime > now + 60:
            fail("control backup dump modification time is in the future")
        if now - dump_metadata.st_mtime > args.max_age_seconds:
            fail("control backup dump is stale")
        stem = dump_name.removesuffix(".dump")
        manifest_name = f"{stem}.contents.txt"
        checksum_name = f"{stem}.sha256"
        manifest_path = args.directory / manifest_name
        checksum_path = args.directory / checksum_name
        manifest_descriptor, manifest_metadata = open_regular(
            manifest_path,
            "control backup manifest",
            max_bytes=MAX_MANIFEST_BYTES,
            exact_mode=0o600,
            expected_uid=args.expected_owner_uid,
        )
        checksum_descriptor, checksum_metadata = open_regular(
            checksum_path,
            "control backup checksum",
            max_bytes=MAX_CHECKSUM_BYTES,
            exact_mode=0o600,
            expected_uid=args.expected_owner_uid,
        )
        descriptors.extend((manifest_descriptor, checksum_descriptor))
        if manifest_metadata.st_nlink != 1 or checksum_metadata.st_nlink != 1:
            fail("control backup metadata must have exactly one hard link")
        for label, metadata in (
            ("manifest", manifest_metadata),
            ("checksum", checksum_metadata),
        ):
            if metadata.st_mtime < args.not_before or metadata.st_mtime > now + 60:
                fail(f"control backup {label} is outside the admission window")
            if now - metadata.st_mtime > args.max_age_seconds:
                fail(f"control backup {label} is stale")
        checksum_raw = read_descriptor(
            checksum_descriptor, "control backup checksum", MAX_CHECKSUM_BYTES
        )
        try:
            checksum_text = checksum_raw.decode("ascii")
        except UnicodeDecodeError:
            fail("control backup checksum is not ASCII")
        match = re.fullmatch(r"([0-9a-f]{64})  ([^/\s]+)\n", checksum_text)
        if match is None or match.group(2) != dump_name:
            fail("control backup checksum is not canonical")
        dump_sha256 = sha256_descriptor(dump_descriptor, "control backup dump")
        if dump_sha256 != match.group(1):
            fail("control backup dump checksum mismatch")
        stored_manifest = read_descriptor(
            manifest_descriptor, "control backup manifest", MAX_MANIFEST_BYTES
        )
        if not stored_manifest:
            fail("control backup manifest is empty")

        mount = f"type=bind,src={args.directory},dst=/backups,readonly"
        command = [
            str(docker),
            "run",
            "--rm",
            "--pull",
            "never",
            "--network",
            "none",
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--user",
            f"{args.expected_owner_uid}:{args.expected_owner_uid}",
            "--pids-limit",
            "64",
            "--memory",
            "128m",
            "--mount",
            mount,
            "--entrypoint",
            "pg_restore",
            args.postgres_tools_image,
            "--list",
            f"/backups/{dump_name}",
        ]
        try:
            result = subprocess.run(
                command,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                check=False,
            )
        except OSError:
            fail("Docker could not validate the control backup")
        if result.returncode != 0:
            fail("containerized pg_restore rejected the control backup")
        if len(result.stdout) > MAX_MANIFEST_BYTES:
            fail("containerized pg_restore output exceeds the admission limit")
        if result.stdout != stored_manifest:
            fail("control backup manifest differs from containerized pg_restore")
        for descriptor, metadata, label in (
            (dump_descriptor, dump_metadata, "control backup dump"),
            (manifest_descriptor, manifest_metadata, "control backup manifest"),
            (checksum_descriptor, checksum_metadata, "control backup checksum"),
        ):
            assert_stable(descriptor, metadata, label)
        assert_stable(
            directory_descriptor, directory_metadata, "control backup directory"
        )
        return {
            "format_version": SCHEMA_VERSION,
            "status": "admitted",
            "verified_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            "dump_path": str(args.directory / dump_name),
            "dump_sha256": dump_sha256,
            "dump_size": dump_metadata.st_size,
            "dump_mtime": datetime.fromtimestamp(dump_metadata.st_mtime, UTC)
            .isoformat()
            .replace("+00:00", "Z"),
            "manifest_path": str(manifest_path),
            "manifest_sha256": sha256_bytes(stored_manifest),
            "checksum_path": str(checksum_path),
            "owner_uid": args.expected_owner_uid,
            "postgres_tools_image": args.postgres_tools_image,
        }
    finally:
        for descriptor in descriptors:
            os.close(descriptor)
        os.close(directory_descriptor)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Validate signed production deployment evidence."
    )
    commands = parser.add_subparsers(dest="command", required=True)

    backup_parser = commands.add_parser("backup-receipt")
    backup_parser.add_argument("--result-file", type=Path, required=True)
    backup_parser.add_argument("--max-age-seconds", type=int, required=True)
    backup_parser.add_argument("--current-identities", type=Path, required=True)
    backup_parser.set_defaults(handler=backup_receipt)

    compose_parser = commands.add_parser("compose-plan")
    compose_parser.add_argument("--compose-config", type=Path, required=True)
    compose_parser.add_argument("--repo-root", type=Path, required=True)
    compose_parser.add_argument("--expected-backup-user", default="70:70")
    compose_parser.set_defaults(handler=compose_plan)

    images_parser = commands.add_parser("images")
    images_parser.add_argument("--plan", type=Path, required=True)
    images_parser.add_argument("--api-inspect", type=Path, required=True)
    images_parser.add_argument("--pwa-inspect", type=Path, required=True)
    images_parser.add_argument("--backup-inspect", type=Path, required=True)
    images_parser.set_defaults(handler=images)

    image_contract_parser = commands.add_parser("api-image-contract")
    image_contract_parser.add_argument("--observed", type=Path, required=True)
    image_contract_parser.add_argument("--images", type=Path, required=True)
    image_contract_parser.add_argument("--versions-lock", type=Path, required=True)
    image_contract_parser.add_argument("--expected-image", required=True)
    image_contract_parser.set_defaults(handler=api_image_contract)

    secrets_parser = commands.add_parser("runtime-secrets")
    secrets_parser.add_argument("--database-secret", type=Path, required=True)
    secrets_parser.add_argument("--redis-secret", type=Path, required=True)
    secrets_parser.add_argument("--session-secret", type=Path, required=True)
    secrets_parser.add_argument("--api-uid", type=int, required=True)
    secrets_parser.add_argument("--api-gid", type=int, required=True)
    secrets_parser.add_argument("--backup-uid", type=int, required=True)
    secrets_parser.add_argument("--parent-uid", type=int, required=True)
    secrets_parser.add_argument("--parent-gid", type=int, required=True)
    secrets_parser.set_defaults(handler=runtime_secrets)

    running_parser = commands.add_parser("running")
    running_parser.add_argument("--plan", type=Path, required=True)
    running_parser.add_argument("--images", type=Path, required=True)
    running_parser.add_argument("--api-inspect", type=Path, required=True)
    running_parser.add_argument("--api-replica-inspect", type=Path, required=True)
    running_parser.add_argument("--pwa-inspect", type=Path, required=True)
    running_parser.add_argument("--pwa-network-inspect", type=Path, required=True)
    running_parser.set_defaults(handler=running)

    pristine_parser = commands.add_parser("pristine-db")
    pristine_parser.add_argument("--evidence", type=Path, required=True)
    pristine_parser.set_defaults(handler=pristine_db)

    postgres_parser = commands.add_parser("postgres-boundary")
    postgres_parser.add_argument("--evidence", type=Path, required=True)
    postgres_parser.set_defaults(handler=postgres_boundary)

    control_backup_parser = commands.add_parser("control-backup")
    control_backup_parser.add_argument("--directory", type=Path, required=True)
    control_backup_parser.add_argument("--not-before", type=float, required=True)
    control_backup_parser.add_argument("--max-age-seconds", type=int, required=True)
    control_backup_parser.add_argument("--expected-owner-uid", type=int, required=True)
    control_backup_parser.add_argument("--postgres-tools-image", required=True)
    control_backup_parser.add_argument("--docker", default="docker")
    control_backup_parser.set_defaults(handler=control_backup)
    return parser.parse_args()


def main() -> int:
    os.umask(0o077)
    args = parse_args()
    value = args.handler(args)
    compact_json(value)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except AdmissionError as error:
        print(f"bootstrap-admission: {error}", file=sys.stderr)
        raise SystemExit(1) from None
