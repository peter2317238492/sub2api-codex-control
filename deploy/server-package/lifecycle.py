#!/usr/bin/env python3
"""Fail-closed lifecycle operations for verified Control server packages.

The public CLI deliberately uses fixed production roots.  Tests may call
``run_lifecycle`` with an explicit ``LifecyclePaths`` instance, but callers
cannot redirect production state through environment variables or CLI flags.
"""

from __future__ import annotations

import sys

if __name__ == "__main__" and (
    sys.version_info < (3, 11)
    or not sys.flags.isolated
    or not getattr(sys.flags, "safe_path", False)
):
    print(
        "lifecycle: Python 3.11+ isolated mode is required; run with "
        "/usr/bin/python3 -I",
        file=sys.stderr,
    )
    raise SystemExit(2)

# The verifier and lifecycle import trusted tools from verified package
# trees whose inventories are exact; never let the interpreter write
# bytecode caches into them, regardless of the operator's environment.
sys.dont_write_bytecode = True

import argparse
import contextlib
import hashlib
import json
import os
import platform
import re
import shutil
import signal
import stat
import subprocess
import time
import uuid
from collections.abc import Iterable, Iterator, Mapping, Sequence
from pathlib import Path, PurePosixPath
from typing import Any, BinaryIO, NoReturn


FORMAT_VERSION = 1
PACKAGE_SCHEMA_ID = (
    "https://sub2api-codex.invalid/schemas/server-package-inventory-v1.json"
)
VERIFICATION_RECEIPT_SCHEMA_ID = (
    "https://sub2api-codex.invalid/schemas/server-package-verification-v1.json"
)
LIFECYCLE_RECEIPT_SCHEMA_ID = (
    "https://sub2api-codex.invalid/schemas/server-package-lifecycle-v1.json"
)
RELEASE_RECORD_SCHEMA_ID = (
    "https://sub2api-codex.invalid/schemas/server-package-installation-v1.json"
)
ACTIVATION_SCHEMA_ID = (
    "https://sub2api-codex.invalid/schemas/server-package-activation-v1.json"
)
PACKAGE_MANIFEST_FILENAME = "PACKAGE.json"
OCI_EXPORT_RECEIPT_FILENAME = "oci-export-receipt.json"
CONNECTOR_METADATA_FILENAME = "connector-release-metadata.json"
CONNECTOR_METADATA_BUNDLE_FILENAME = (
    f"{CONNECTOR_METADATA_FILENAME}.sigstore.json"
)
CONNECTOR_AGGREGATE_FILENAME = "connector-public-verification-aggregate.json"
CONNECTOR_AGGREGATE_BUNDLE_FILENAME = (
    f"{CONNECTOR_AGGREGATE_FILENAME}.sigstore.json"
)
PLATFORM = "linux/amd64"
MODES = {"online", "offline"}
COMPONENTS = ("control-api", "pwa", "postgres-tools")
MAX_JSON_BYTES = 32 * 1024 * 1024
MAX_OPERATOR_ENV_BYTES = 1024 * 1024
MAX_PACKAGE_FILES = 30_000
MAX_FILE_BYTES = 16 * 1024 * 1024 * 1024
MAX_DEPLOYMENT_TIMEOUT_SECONDS = 24 * 60 * 60
DEFAULT_DEPLOYMENT_TIMEOUT_SECONDS = 2 * 60 * 60
MAX_POST_SUCCESS_REVERSE_TIMEOUT_SECONDS = 20 * 60
MAX_BOUNDED_UNINSTALL_TIMEOUT_SECONDS = 6 * 60
OIDC_ISSUER = "https://token.actions.githubusercontent.com"
OFFLINE_CONTRACT_LINE = "CONTROL_SERVER_PACKAGE_OFFLINE_CONTRACT=1"
POST_SUCCESS_REVERSE_CONTRACT_LINE = (
    "CONTROL_SERVER_PACKAGE_POST_SUCCESS_REVERSE_CONTRACT=1"
)
POST_SUCCESS_REVERSE_ARGUMENT = "--lifecycle-bounded-reverse-after-success"
POST_SUCCESS_REVERSE_TRIGGER_PREFIX = "lifecycle-post-success:"
BOUNDED_UNINSTALL_CONTRACT_LINE = (
    "CONTROL_SERVER_PACKAGE_BOUNDED_UNINSTALL_CONTRACT=1"
)
BOUNDED_UNINSTALL_ARGUMENT = "--lifecycle-bounded-uninstall"
BOUNDED_UNINSTALL_TRIGGER_PREFIX = "lifecycle-uninstall:"
LOCAL_DOCKER_HOST = "unix:///var/run/docker.sock"
UNINSTALL_SERVICES = ("control-api", "control-api-replica", "codex-pwa")
UNINSTALL_PRESERVED_RESOURCES = {
    "sub2api_runtime": True,
    "postgresql": True,
    "redis": True,
    "application_data": True,
    "secrets": True,
    "backups": True,
    "deployment_records": True,
    "container_images": True,
    "connector_user_state": True,
    "nginx_configuration": True,
    "logrotate_policy": True,
}
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
VERSION_RE = re.compile(
    r"^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
    r"(?:-[0-9A-Za-z.-]+)?$"
)
ENV_NAME_RE = re.compile(r"^[A-Z][A-Z0-9_]*$")
SAFE_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,255}$")
PORTABLE_PATH_RE = re.compile(r"^[A-Za-z0-9._+@/-]+$")
IMAGE_REFERENCE_RE = re.compile(
    r"^(?P<repository>ghcr\.io/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)"
    r"@(?P<digest>sha256:[0-9a-f]{64})$"
)


class LifecyclePaths:
    __slots__ = ("install_root", "state_root")

    def __init__(
        self,
        install_root: Path = Path("/opt/sub2api-codex-control/releases"),
        state_root: Path = Path("/var/lib/sub2api-codex-control"),
    ) -> None:
        self.install_root = install_root
        self.state_root = state_root

    @property
    def operation_root(self) -> Path:
        return self.state_root / "operations"

    @property
    def release_record_root(self) -> Path:
        return self.state_root / "releases"

    @property
    def verification_receipt_root(self) -> Path:
        return self.state_root / "verification-receipts"

    @property
    def activation(self) -> Path:
        return self.state_root / "activation.json"

    @property
    def lock(self) -> Path:
        return self.state_root / ".lifecycle.lock"


DEFAULT_PATHS = LifecyclePaths()


class LifecycleError(RuntimeError):
    pass


class CommandError(LifecycleError):
    def __init__(self, label: str, returncode: int) -> None:
        super().__init__(f"{label} failed with exit status {returncode}")
        self.label = label
        self.returncode = returncode


class LifecycleLockLease:
    __slots__ = ("retained",)

    def __init__(self) -> None:
        self.retained = False

    def retain_for_review(self) -> None:
        self.retained = True


def fail(message: str) -> NoReturn:
    raise LifecycleError(message)


def canonical_json(value: Any) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
        + b"\n"
    )


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            fail(f"JSON object repeats key {key!r}")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> NoReturn:
    fail(f"JSON contains prohibited non-finite number {value}")


def strict_json(raw: bytes, label: str, *, canonical: bool = True) -> Any:
    if not 0 < len(raw) <= MAX_JSON_BYTES:
        fail(f"{label} size is outside the accepted range")
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise LifecycleError(f"{label} is not valid JSON") from exc
    if canonical and canonical_json(value) != raw:
        fail(f"{label} is not canonical JSON")
    return value


def exact_object(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        fail(f"{label} must be an object")
    actual = set(value)
    if actual != keys:
        fail(
            f"{label} keys mismatch; missing={sorted(keys - actual)}, "
            f"extra={sorted(actual - keys)}"
        )
    return value


def require_string(value: Any, label: str, *, maximum: int = 4096) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > maximum
        or any(character in value for character in "\x00\r\n")
    ):
        fail(f"{label} must be one bounded non-empty string")
    return value


def require_sha256(value: Any, label: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        fail(f"{label} must be one lowercase SHA-256")
    return value


def require_positive_integer(value: Any, label: str, maximum: int) -> int:
    if type(value) is not int or not 0 < value <= maximum:
        fail(f"{label} must be a positive integer no greater than {maximum}")
    return value


def validate_portable_path(value: Any, label: str) -> str:
    text = require_string(value, label)
    if (
        not text.isascii()
        or PORTABLE_PATH_RE.fullmatch(text) is None
        or "\\" in text
    ):
        fail(f"{label} is not portable ASCII")
    path = PurePosixPath(text)
    if (
        path.is_absolute()
        or path.as_posix() != text
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        fail(f"{label} is not one canonical relative path")
    return text


def sha256_stream(source: BinaryIO) -> str:
    digest = hashlib.sha256()
    while block := source.read(1024 * 1024):
        digest.update(block)
    return digest.hexdigest()


def sha256_file(path: Path) -> str:
    descriptor = os.open(
        path,
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        with os.fdopen(descriptor, "rb", closefd=False) as source:
            return sha256_stream(source)
    finally:
        os.close(descriptor)


def secure_hash_file(
    path: Path,
    label: str,
    *,
    expected_uid: int,
    accepted_modes: set[int],
    maximum: int = MAX_FILE_BYTES,
) -> tuple[str, int]:
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise LifecycleError(f"cannot securely open {label}: {path}") from exc
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != expected_uid
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) not in accepted_modes
            or not 0 <= before.st_size <= maximum
        ):
            fail(f"{label} ownership, type, mode, link count, or size is invalid")
        digest = hashlib.sha256()
        total = 0
        while block := os.read(descriptor, 1024 * 1024):
            total += len(block)
            if total > before.st_size or total > maximum:
                fail(f"{label} grew while hashed")
            digest.update(block)
        after = os.fstat(descriptor)
        if total != before.st_size or _stable_fields(before) != _stable_fields(after):
            fail(f"{label} changed while hashed")
        return digest.hexdigest(), total
    finally:
        os.close(descriptor)


def _stable_fields(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def secure_read(
    path: Path,
    label: str,
    *,
    expected_uid: int,
    accepted_modes: set[int],
    maximum: int = MAX_JSON_BYTES,
) -> bytes:
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise LifecycleError(f"cannot securely open {label}: {path}") from exc
    try:
        before = os.fstat(descriptor)
        mode = stat.S_IMODE(before.st_mode)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != expected_uid
            or before.st_nlink != 1
            or mode not in accepted_modes
            or not 0 <= before.st_size <= maximum
        ):
            fail(f"{label} ownership, type, mode, link count, or size is invalid")
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            block = os.read(descriptor, min(1024 * 1024, remaining))
            if not block:
                fail(f"{label} was truncated while read")
            chunks.append(block)
            remaining -= len(block)
        if os.read(descriptor, 1):
            fail(f"{label} grew while read")
        after = os.fstat(descriptor)
        if _stable_fields(before) != _stable_fields(after):
            fail(f"{label} changed while read")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def validate_directory(
    path: Path,
    label: str,
    *,
    expected_uid: int,
    exact_mode: int | None = None,
    writable: bool = False,
) -> os.stat_result:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise LifecycleError(f"cannot inspect {label}: {path}") from exc
    mode = stat.S_IMODE(metadata.st_mode)
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != expected_uid
    ):
        fail(f"{label} must be a real directory owned by uid {expected_uid}")
    if exact_mode is not None and mode != exact_mode:
        fail(f"{label} must have mode {exact_mode:04o}")
    if not writable and mode & 0o022:
        fail(f"{label} must not be group- or world-writable")
    return metadata


def _absolute_normalized(path: Path, label: str) -> Path:
    if not path.is_absolute() or Path(os.path.normpath(str(path))) != path:
        fail(f"{label} must be an absolute normalized path")
    return path


def _validate_existing_ancestors(path: Path, *, expected_uid: int) -> None:
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current /= part
        if not current.exists() and not current.is_symlink():
            break
        metadata = current.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            fail(f"path ancestor is not a real directory: {current}")
        if metadata.st_uid != expected_uid or stat.S_IMODE(metadata.st_mode) & 0o022:
            fail(f"path ancestor is not trusted: {current}")


def ensure_private_directory(path: Path, *, expected_uid: int) -> None:
    _absolute_normalized(path, "private directory")
    _validate_existing_ancestors(path, expected_uid=expected_uid)
    missing: list[Path] = []
    current = path
    while not current.exists():
        if current.is_symlink():
            fail(f"private directory path contains a symlink: {current}")
        missing.append(current)
        current = current.parent
    validate_directory(
        current, "private directory ancestor", expected_uid=expected_uid
    )
    for directory in reversed(missing):
        directory.mkdir(mode=0o700)
        os.chmod(directory, 0o700)
    validate_directory(
        path,
        "private directory",
        expected_uid=expected_uid,
        exact_mode=0o700,
    )


def preflight_platform() -> None:
    if os.geteuid() != 0:
        fail("server package lifecycle operations must run as root")
    machine = platform.machine().lower()
    if platform.system() != "Linux" or machine not in {"x86_64", "amd64"}:
        fail("server package lifecycle operations require Linux amd64")


def _validate_package_manifest(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        fail("package manifest must be an object")
    expected_keys = {
        "$schema",
        "format_version",
        "product",
        "release",
        "release_tag",
        "mode",
        "platform",
        "source",
        "builder",
        "source_date_epoch",
        "common_payload_sha256",
        "control_release",
        "source_bundle",
        "source_verification",
        "connector_release",
        "oci_export",
        "image_trust",
        "images",
        "lifecycle",
        "required_source_paths",
        "files",
    }
    if set(value) != expected_keys:
        fail(
            "package manifest keys mismatch; "
            f"missing={sorted(expected_keys - set(value))}, "
            f"extra={sorted(set(value) - expected_keys)}"
        )
    if (
        value["$schema"] != PACKAGE_SCHEMA_ID
        or type(value["format_version"]) is not int
        or value["format_version"] != FORMAT_VERSION
        or value["product"] != "sub2api-codex-control-server"
        or value["platform"] != PLATFORM
        or value["mode"] not in MODES
    ):
        fail("package manifest identity is unsupported")
    require_positive_integer(
        value["source_date_epoch"], "package source epoch", (1 << 32) - 1
    )
    require_sha256(value["common_payload_sha256"], "common payload SHA-256")
    release = require_string(value["release"], "package release")
    if VERSION_RE.fullmatch(release) is None:
        fail("package release is not a supported semantic version")
    if value["release_tag"] != f"control-v{release}":
        fail("package release tag is invalid")
    source = exact_object(
        value["source"],
        {"repository", "commit", "ref"},
        "package source",
    )
    repository = require_string(source["repository"], "source repository")
    if re.fullmatch(r"https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository) is None:
        fail("package source repository is not canonical GitHub HTTPS")
    if COMMIT_RE.fullmatch(require_string(source["commit"], "source commit")) is None:
        fail("package source commit is invalid")
    if source["ref"] != f"refs/tags/{value['release_tag']}":
        fail("package source ref is invalid")
    builder = exact_object(
        value["builder"],
        {
            "workflow_identity",
            "workflow_sha",
            "workflow_trigger",
            "invocation_id",
            "cosign_version",
            "syft_version",
        },
        "package builder",
    )
    workflow_identity = require_string(
        builder["workflow_identity"], "workflow identity"
    )
    invocation_id = require_string(builder["invocation_id"], "builder invocation")
    if (
        builder["workflow_sha"] != source["commit"]
        or builder["workflow_trigger"] != "push"
        or re.fullmatch(
            rf"{re.escape(repository)}/\.github/workflows/"
            rf"[A-Za-z0-9._-]+\.ya?ml@refs/tags/{re.escape(value['release_tag'])}",
            workflow_identity,
        )
        is None
        or re.fullmatch(
            rf"{re.escape(repository)}/actions/runs/"
            r"[1-9][0-9]*/attempts/[1-9][0-9]*",
            invocation_id,
        )
        is None
    ):
        fail("package builder identity is invalid")
    for key, label in (
        ("cosign_version", "builder Cosign version"),
        ("syft_version", "builder Syft version"),
    ):
        if re.fullmatch(
            r"v[0-9]+\.[0-9]+\.[0-9]+", require_string(builder[key], label)
        ) is None:
            fail(f"package {label} is invalid")
    connector_release = _validate_connector_release_record(
        value["connector_release"]
    )
    expected_lifecycle = {
        "install": "bin/sub2api-control-install",
        "upgrade": "bin/sub2api-control-upgrade",
        "verify": "bin/sub2api-control-verify",
        "rollback": "bin/sub2api-control-rollback",
        "uninstall": "bin/sub2api-control-uninstall",
    }
    if value["lifecycle"] != expected_lifecycle:
        fail("package lifecycle entry points are not the fixed inventory")
    required_source_paths = value["required_source_paths"]
    if (
        not isinstance(required_source_paths, list)
        or not required_source_paths
        or required_source_paths != sorted(set(required_source_paths))
    ):
        fail("package required source paths are invalid")
    for path in required_source_paths:
        validate_portable_path(path, "required source path")
    images = exact_object(value["images"], set(COMPONENTS), "package images")
    for component in COMPONENTS:
        image = images[component]
        if not isinstance(image, dict):
            fail(f"package image {component} must be an object")
        if value["mode"] == "online":
            image = exact_object(
                image,
                {"acquisition", "digest", "reference", "repository"},
                f"online image {component}",
            )
            if image["acquisition"] != "registry":
                fail(f"online image acquisition is invalid: {component}")
            _validate_image_reference(
                image["reference"], image["repository"], image["digest"], component
            )
        else:
            image = exact_object(
                image,
                {
                    "acquisition",
                    "archive",
                    "identity",
                    "locked_digest",
                    "locked_reference",
                },
                f"offline image {component}",
            )
            if image["acquisition"] != "offline-oci":
                fail(f"offline image acquisition is invalid: {component}")
            archive = _validate_file_record(image["archive"], f"{component} archive")
            identity = _validate_file_record(image["identity"], f"{component} identity")
            if archive["filename"] != f"images/{component}.oci.tar":
                fail(f"offline archive filename is invalid: {component}")
            if identity["filename"] != f"images/{component}.identity.json":
                fail(f"offline identity filename is invalid: {component}")
            reference = require_string(
                image["locked_reference"], f"{component} locked reference"
            )
            digest = require_string(image["locked_digest"], f"{component} locked digest")
            match = IMAGE_REFERENCE_RE.fullmatch(reference)
            if match is None or match.group("digest") != digest:
                fail(f"offline image reference is invalid: {component}")
    files = value["files"]
    if not isinstance(files, list) or not files or len(files) > MAX_PACKAGE_FILES:
        fail("package file inventory is invalid")
    seen: set[str] = set()
    for record in files:
        item = exact_object(
            record, {"mode", "path", "sha256", "size"}, "package file record"
        )
        path = validate_portable_path(item["path"], "package file path")
        if path in seen:
            fail(f"package file inventory repeats {path}")
        seen.add(path)
        if item["mode"] not in {"0444", "0555"}:
            fail(f"package file mode is invalid: {path}")
        require_sha256(item["sha256"], f"package file {path} SHA-256")
        if type(item["size"]) is not int or not 0 <= item["size"] <= MAX_FILE_BYTES:
            fail(f"package file size is invalid: {path}")
    if [record["path"] for record in files] != sorted(seen):
        fail("package file inventory is not sorted")
    file_map = {record["path"]: record for record in files}
    if value["mode"] == "online":
        if value["oci_export"] is not None or OCI_EXPORT_RECEIPT_FILENAME in file_map:
            fail("online package must not contain an OCI export receipt")
    else:
        oci_export = _validate_file_record(
            value["oci_export"], "package OCI export receipt"
        )
        receipt_file = file_map.get(OCI_EXPORT_RECEIPT_FILENAME)
        if (
            oci_export["filename"] != OCI_EXPORT_RECEIPT_FILENAME
            or receipt_file is None
            or receipt_file["mode"] != "0444"
            or receipt_file["sha256"] != oci_export["sha256"]
            or receipt_file["size"] != oci_export["size"]
        ):
            fail("offline package OCI export receipt differs from its binding")
    for role in ("metadata", "metadata_bundle", "aggregate", "aggregate_bundle"):
        evidence = connector_release[role]
        package_file = file_map.get(evidence["filename"])
        if (
            package_file is None
            or package_file["mode"] != "0444"
            or package_file["sha256"] != evidence["sha256"]
            or package_file["size"] != evidence["size"]
        ):
            fail(f"package Connector evidence differs from its binding: {role}")
    return value


def _validate_file_record(value: Any, label: str) -> dict[str, Any]:
    record = exact_object(value, {"filename", "sha256", "size"}, label)
    validate_portable_path(record["filename"], f"{label} filename")
    require_sha256(record["sha256"], f"{label} SHA-256")
    if type(record["size"]) is not int or not 0 < record["size"] <= MAX_FILE_BYTES:
        fail(f"{label} size is invalid")
    return record


def _validate_connector_release_record(value: Any) -> dict[str, Any]:
    record = exact_object(
        value,
        {
            "source_repository",
            "source_commit",
            "version",
            "tag",
            "release_id",
            "workflow_run_id",
            "workflow_run_attempt",
            "metadata",
            "metadata_bundle",
            "aggregate",
            "aggregate_bundle",
        },
        "package Connector release binding",
    )
    repository = require_string(
        record["source_repository"], "Connector source repository"
    )
    if re.fullmatch(
        r"https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository
    ) is None:
        fail("Connector source repository is not canonical GitHub HTTPS")
    if COMMIT_RE.fullmatch(
        require_string(record["source_commit"], "Connector source commit")
    ) is None:
        fail("Connector source commit is invalid")
    version = require_string(record["version"], "Connector release version")
    if VERSION_RE.fullmatch(version) is None or record["tag"] != f"connector-v{version}":
        fail("Connector release version and tag are inconsistent")
    for name in ("release_id", "workflow_run_id", "workflow_run_attempt"):
        if type(record[name]) is not int or record[name] <= 0:
            fail(f"Connector release {name} must be a positive integer")
    expected_names = {
        "metadata": CONNECTOR_METADATA_FILENAME,
        "metadata_bundle": CONNECTOR_METADATA_BUNDLE_FILENAME,
        "aggregate": CONNECTOR_AGGREGATE_FILENAME,
        "aggregate_bundle": CONNECTOR_AGGREGATE_BUNDLE_FILENAME,
    }
    for role, filename in expected_names.items():
        evidence = _validate_file_record(record[role], f"Connector {role}")
        if evidence["filename"] != filename:
            fail(f"Connector {role} filename is invalid")
    return record


def _validate_image_reference(
    reference_value: Any,
    repository_value: Any,
    digest_value: Any,
    component: str,
) -> str:
    reference = require_string(reference_value, f"{component} image reference")
    repository = require_string(repository_value, f"{component} image repository")
    digest = require_string(digest_value, f"{component} image digest")
    match = IMAGE_REFERENCE_RE.fullmatch(reference)
    if (
        match is None
        or match.group("repository") != repository
        or match.group("digest") != digest
        or DIGEST_RE.fullmatch(digest) is None
    ):
        fail(f"{component} image is not one exact GHCR digest reference")
    return reference


def _validate_receipt(value: Any) -> dict[str, Any]:
    receipt = exact_object(
        value,
        {
            "$schema",
            "format_version",
            "status",
            "verified_at",
            "release",
            "release_tag",
            "mode",
            "platform",
            "source",
            "package",
            "release_manifest",
            "trust",
        },
        "package verification receipt",
    )
    if (
        receipt["$schema"] != VERIFICATION_RECEIPT_SCHEMA_ID
        or receipt["format_version"] != FORMAT_VERSION
        or receipt["status"] != "verified"
        or receipt["platform"] != PLATFORM
        or receipt["mode"] not in MODES
        or type(receipt["verified_at"]) is not int
        or receipt["verified_at"] <= 0
    ):
        fail("package verification receipt identity is invalid")
    package = exact_object(
        receipt["package"],
        {
            "filename",
            "sha256",
            "size",
            "internal_manifest_sha256",
            "extracted_root",
        },
        "verification receipt package",
    )
    validate_portable_path(package["filename"], "verified package filename")
    require_sha256(package["sha256"], "verified package SHA-256")
    require_sha256(
        package["internal_manifest_sha256"], "verified package manifest SHA-256"
    )
    if type(package["size"]) is not int or not 0 < package["size"] <= MAX_FILE_BYTES:
        fail("verified package size is invalid")
    require_string(package["extracted_root"], "verified extracted root")
    release_manifest = exact_object(
        receipt["release_manifest"],
        {"filename", "sha256", "size"},
        "verified release manifest",
    )
    if release_manifest["filename"] != "server-packages.manifest.json":
        fail("verified release manifest filename is invalid")
    require_sha256(release_manifest["sha256"], "release manifest SHA-256")
    if type(release_manifest["size"]) is not int or release_manifest["size"] <= 0:
        fail("verified release manifest size is invalid")
    trust = exact_object(
        receipt["trust"],
        {
            "cosign_version",
            "certificate_oidc_issuer",
            "certificate_identity",
            "certificate_github_workflow_sha",
            "certificate_github_workflow_trigger",
            "certificate_github_workflow_repository",
            "certificate_github_workflow_ref",
            "connector_certificate_oidc_issuer",
            "connector_certificate_identity",
            "connector_certificate_github_workflow_sha",
            "connector_certificate_github_workflow_trigger",
            "expected_connector_repository",
            "expected_connector_source_commit",
            "expected_connector_tag",
            "expected_connector_release_id",
            "expected_connector_workflow_run_id",
            "expected_connector_workflow_run_attempt",
            "expected_source_repository",
            "expected_source_commit",
            "expected_release_tag",
            "expected_api_repository",
            "expected_pwa_repository",
            "expected_postgres_tools_repository",
        },
        "package verification trust",
    )
    integer_pins = {
        "expected_connector_release_id",
        "expected_connector_workflow_run_id",
        "expected_connector_workflow_run_attempt",
    }
    for key, item in trust.items():
        if key in integer_pins:
            require_positive_integer(item, f"verification trust {key}", (1 << 63) - 1)
        else:
            require_string(item, f"verification trust {key}")
    if (
        trust["certificate_oidc_issuer"] != OIDC_ISSUER
        or trust["connector_certificate_oidc_issuer"] != OIDC_ISSUER
    ):
        fail("package receipt does not use the fixed GitHub OIDC issuer")
    if re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", trust["cosign_version"]) is None:
        fail("package verification receipt Cosign version is invalid")
    return receipt


def _walk_package_tree(root: Path, *, expected_uid: int) -> tuple[set[str], set[str]]:
    files: set[str] = set()
    directories: set[str] = set()
    stack = [root]
    while stack:
        directory = stack.pop()
        relative_directory = directory.relative_to(root).as_posix()
        validate_directory(
            directory,
            "package directory",
            expected_uid=expected_uid,
            exact_mode=0o555,
        )
        if relative_directory != ".":
            directories.add(relative_directory)
        with os.scandir(directory) as entries:
            for entry in entries:
                relative = Path(entry.path).relative_to(root).as_posix()
                validate_portable_path(relative, "package tree path")
                metadata = entry.stat(follow_symlinks=False)
                if stat.S_ISDIR(metadata.st_mode):
                    stack.append(Path(entry.path))
                elif stat.S_ISREG(metadata.st_mode):
                    if (
                        metadata.st_uid != expected_uid
                        or metadata.st_nlink != 1
                        or stat.S_IMODE(metadata.st_mode) not in {0o444, 0o555}
                    ):
                        fail(f"package file metadata is invalid: {relative}")
                    files.add(relative)
                else:
                    fail(f"package contains a link or unsupported entry: {relative}")
                if len(files) > MAX_PACKAGE_FILES:
                    fail("package tree exceeds the accepted file count")
                if len(directories) + len(stack) > MAX_PACKAGE_FILES * 2:
                    fail("package tree exceeds the accepted directory count")
    return files, directories


def _validate_connector_metadata(raw: bytes) -> dict[str, Any]:
    metadata = strict_json(raw, "Connector release metadata", canonical=True)
    if not isinstance(metadata, dict):
        fail("Connector release metadata must be an object")
    required = {
        "format_version",
        "release_mode",
        "releasable",
        "source_repository",
        "source_commit",
        "version",
        "tag",
        "codex_version",
        "schema_digest",
        "manifest",
        "config_path_hint",
        "pair_command",
        "start_command",
        "assets",
    }
    if set(metadata) != required:
        fail("Connector release metadata keys are invalid")
    if (
        type(metadata["format_version"]) is not int
        or metadata["format_version"] != 1
        or metadata["release_mode"] != "release"
        or metadata["releasable"] is not True
    ):
        fail("Connector release metadata is not a public release")
    if COMMIT_RE.fullmatch(require_string(metadata["source_commit"], "Connector source commit")) is None:
        fail("Connector release metadata source commit is invalid")
    version = require_string(metadata["version"], "Connector version")
    if VERSION_RE.fullmatch(version) is None or metadata["tag"] != f"connector-v{version}":
        fail("Connector release metadata version and tag are inconsistent")
    if VERSION_RE.fullmatch(require_string(metadata["codex_version"], "Codex version")) is None:
        fail("Connector release metadata Codex version is invalid")
    require_sha256(metadata["schema_digest"], "Connector schema digest")
    assets = metadata["assets"]
    if not isinstance(assets, list) or len(assets) != 4:
        fail("Connector release metadata must contain exactly four native packages")
    tuples: list[tuple[str, str, str]] = []
    for asset in assets:
        if not isinstance(asset, dict):
            fail("Connector release metadata asset must be an object")
        os_name = require_string(asset.get("os"), "Connector asset OS")
        arch = require_string(asset.get("arch"), "Connector asset architecture")
        package_format = require_string(
            asset.get("package_format"), "Connector asset package format"
        )
        require_sha256(asset.get("sha256"), "Connector asset SHA-256")
        tuples.append((os_name, arch, package_format))
    expected = [
        ("linux", "amd64", "deb"),
        ("linux", "amd64", "rpm"),
        ("linux", "arm64", "deb"),
        ("linux", "arm64", "rpm"),
    ]
    if sorted(tuples) != expected:
        fail("Connector release metadata native package matrix is incomplete")
    return metadata


def validate_verified_package(
    package_root: Path,
    verification_receipt: Path,
    *,
    expected_uid: int = 0,
) -> tuple[dict[str, Any], dict[str, Any], bytes]:
    package_root = _absolute_normalized(package_root, "package root")
    verification_receipt = _absolute_normalized(
        verification_receipt, "verification receipt"
    )
    validate_directory(
        package_root,
        "verified extracted package",
        expected_uid=expected_uid,
        exact_mode=0o555,
    )
    receipt_raw = secure_read(
        verification_receipt,
        "package verification receipt",
        expected_uid=expected_uid,
        accepted_modes={0o400},
    )
    receipt = _validate_receipt(strict_json(receipt_raw, "verification receipt"))
    if Path(receipt["package"]["extracted_root"]) != package_root:
        fail("verification receipt is bound to a different extracted package root")
    manifest_raw = secure_read(
        package_root / PACKAGE_MANIFEST_FILENAME,
        "package manifest",
        expected_uid=expected_uid,
        accepted_modes={0o444},
    )
    manifest_sha256 = hashlib.sha256(manifest_raw).hexdigest()
    if manifest_sha256 != receipt["package"]["internal_manifest_sha256"]:
        fail("package manifest differs from the verification receipt")
    manifest = _validate_package_manifest(
        strict_json(manifest_raw, "package manifest", canonical=True)
    )
    for key in ("release", "release_tag", "mode", "platform", "source"):
        if receipt[key] != manifest[key]:
            fail(f"verification receipt {key} differs from the package manifest")
    trust = receipt["trust"]
    if trust["cosign_version"] != manifest["builder"]["cosign_version"]:
        fail("verification receipt Cosign version differs from the package builder")
    if (
        trust["expected_source_repository"] != manifest["source"]["repository"]
        or trust["expected_source_commit"] != manifest["source"]["commit"]
        or trust["expected_release_tag"] != manifest["release_tag"]
    ):
        fail("verification receipt Control source policy differs from the package")
    source_repository_slug = manifest["source"]["repository"].removeprefix(
        "https://github.com/"
    )
    if (
        trust["certificate_identity"] != manifest["builder"]["workflow_identity"]
        or trust["certificate_github_workflow_sha"]
        != manifest["builder"]["workflow_sha"]
        or trust["certificate_github_workflow_trigger"]
        != manifest["builder"]["workflow_trigger"]
        or trust["certificate_github_workflow_repository"]
        != source_repository_slug
        or trust["certificate_github_workflow_ref"] != manifest["source"]["ref"]
    ):
        fail("verification receipt Control certificate policy differs from the package")
    expected_image_repositories: dict[str, str] = {}
    for component in COMPONENTS:
        image = manifest["images"][component]
        reference = image.get("reference", image.get("locked_reference"))
        match = IMAGE_REFERENCE_RE.fullmatch(
            require_string(reference, f"{component} image reference")
        )
        if match is None:
            fail(f"package image reference is invalid: {component}")
        expected_image_repositories[component] = match.group("repository")
    if (
        trust["expected_api_repository"]
        != expected_image_repositories["control-api"]
        or trust["expected_pwa_repository"] != expected_image_repositories["pwa"]
        or trust["expected_postgres_tools_repository"]
        != expected_image_repositories["postgres-tools"]
    ):
        fail("verification receipt image repository policy differs from the package")
    connector_release = manifest["connector_release"]
    connector_pins = {
        "expected_connector_repository": "source_repository",
        "expected_connector_source_commit": "source_commit",
        "expected_connector_tag": "tag",
        "expected_connector_release_id": "release_id",
        "expected_connector_workflow_run_id": "workflow_run_id",
        "expected_connector_workflow_run_attempt": "workflow_run_attempt",
    }
    if any(
        trust[trust_key] != connector_release[release_key]
        for trust_key, release_key in connector_pins.items()
    ):
        fail("verification receipt Connector policy differs from the package")
    if (
        trust["connector_certificate_identity"]
        != (
            f"{connector_release['source_repository']}"
            "/.github/workflows/connector-release.yml"
            f"@refs/tags/{connector_release['tag']}"
        )
        or trust["connector_certificate_github_workflow_sha"]
        != connector_release["source_commit"]
        or trust["connector_certificate_github_workflow_trigger"] != "push"
    ):
        fail("verification receipt Connector certificate policy is invalid")
    actual_files, _ = _walk_package_tree(package_root, expected_uid=expected_uid)
    expected_records = {record["path"]: record for record in manifest["files"]}
    expected_files = set(expected_records) | {PACKAGE_MANIFEST_FILENAME}
    if actual_files != expected_files:
        fail(
            "verified package tree differs from its exact inventory; "
            f"missing={sorted(expected_files - actual_files)}, "
            f"extra={sorted(actual_files - expected_files)}"
        )
    for relative, record in expected_records.items():
        path = package_root / relative
        observed_sha256, observed_size = secure_hash_file(
            path,
            f"package file {relative}",
            expected_uid=expected_uid,
            accepted_modes={int(record["mode"], 8)},
            maximum=record["size"],
        )
        if observed_size != record["size"] or observed_sha256 != record["sha256"]:
            fail(f"package file differs from its exact inventory: {relative}")
    connector_raw = secure_read(
        package_root / CONNECTOR_METADATA_FILENAME,
        "packaged Connector release metadata",
        expected_uid=expected_uid,
        accepted_modes={0o444},
        maximum=MAX_JSON_BYTES,
    )
    connector_metadata = _validate_connector_metadata(connector_raw)
    connector_release = manifest["connector_release"]
    for metadata_key, release_key in (
        ("source_repository", "source_repository"),
        ("source_commit", "source_commit"),
        ("version", "version"),
        ("tag", "tag"),
    ):
        if connector_metadata[metadata_key] != connector_release[release_key]:
            fail(
                "Connector release metadata differs from the package binding: "
                f"{metadata_key}"
            )
    return manifest, receipt, connector_raw


ABSOLUTE_FILE_NAMES = {
    "CONTROL_COMPOSE_ENV_FILE",
    "CONTROL_SMOKE_ACCESS_TOKEN_FILE",
    "SUB2API_FIXTURE_ACTIVE_ACCESS_TOKEN_FILE",
    "SUB2API_FIXTURE_ACTIVE_REFRESH_TOKEN_FILE",
    "SUB2API_FIXTURE_DISABLED_ACCESS_TOKEN_FILE",
    "SUB2API_FIXTURE_REVOKED_ACCESS_TOKEN_FILE",
    "SUB2API_POSTGRES_PASSWORD_FILE",
    "SUB2API_REDIS_PASSWORD_FILE",
    "SUB2API_HOST_CONFIG_PATH",
    "SUB2API_HOST_COMPOSE_FILE",
    "SUB2API_HOST_ENV_FILE",
}
ABSOLUTE_DIRECTORY_NAMES = {
    "CONTROL_DEPLOYMENT_RECORD_DIR",
    "CONTROL_PRODUCTION_BACKUP_ROOT",
    "SUB2API_HOST_DATA_PATH",
    "CONTROL_NGINX_CONFIG_PATH",
    "SUB2API_EXPECTED_DATA_BIND_SOURCE",
}
# Explicit bind policy for a Sub2API container whose /app/data is a host
# bind mount; the runtime verifier refuses a bind without all four values
# (verify-sub2api-runtime.sh), so the operator must supply none or all.
BIND_POLICY_ID_NAMES = {
    "SUB2API_EXPECTED_DATA_BIND_UID",
    "SUB2API_EXPECTED_DATA_BIND_GID",
}
BIND_POLICY_MODE_NAME = "SUB2API_EXPECTED_DATA_BIND_MODE"
BIND_POLICY_NAMES = {
    "SUB2API_EXPECTED_DATA_BIND_SOURCE",
    BIND_POLICY_MODE_NAME,
    *BIND_POLICY_ID_NAMES,
}
ACCEPTED_BIND_MODES = {"0700", "0750", "0755"}
MAX_BIND_POLICY_ID = 65535
IDENTIFIER_NAMES = {
    "CONTROL_SMOKE_EXPECTED_USER_ID",
    "SUB2API_FIXTURE_EXPECTED_USER_ID",
    "CONTROL_COMPOSE_PROJECT_NAME",
    "SUB2API_CONTAINER",
    "SUB2API_POSTGRES_CONTAINER",
    "SUB2API_POSTGRES_USER",
    "SUB2API_DB_NAME",
    "SUB2API_REDIS_CONTAINER",
    "SUB2API_REDIS_USER",
}
POSITIVE_INTEGER_NAMES = {
    "SUB2API_AUTH_EVIDENCE_MAX_AGE_SECONDS",
    "CONTROL_PREMIGRATION_BACKUP_MAX_AGE_SECONDS",
    "CONTROL_DEPLOYMENT_WAIT_TIMEOUT_SECONDS",
    "CONTROL_PRODUCTION_BACKUP_MAX_AGE_SECONDS",
    "CONTROL_RECOVERY_RECEIPT_MAX_AGE_SECONDS",
    "CONTROL_RECOVERY_RESTORE_TIMEOUT_SECONDS",
}
CONTAINER_PATH_NAMES = {"SUB2API_REDIS_DATA_PATH"}
ALLOWED_OPERATOR_NAMES = (
    ABSOLUTE_FILE_NAMES
    | ABSOLUTE_DIRECTORY_NAMES
    | IDENTIFIER_NAMES
    | POSITIVE_INTEGER_NAMES
    | CONTAINER_PATH_NAMES
    | BIND_POLICY_ID_NAMES
    | {BIND_POLICY_MODE_NAME}
)
REQUIRED_OPERATOR_NAMES = {
    "CONTROL_COMPOSE_ENV_FILE",
    "CONTROL_DEPLOYMENT_RECORD_DIR",
    "CONTROL_PRODUCTION_BACKUP_ROOT",
    "CONTROL_SMOKE_ACCESS_TOKEN_FILE",
    "CONTROL_SMOKE_EXPECTED_USER_ID",
    "SUB2API_FIXTURE_ACTIVE_ACCESS_TOKEN_FILE",
    "SUB2API_FIXTURE_ACTIVE_REFRESH_TOKEN_FILE",
    "SUB2API_FIXTURE_DISABLED_ACCESS_TOKEN_FILE",
    "SUB2API_FIXTURE_REVOKED_ACCESS_TOKEN_FILE",
    "SUB2API_FIXTURE_EXPECTED_USER_ID",
    "SUB2API_HOST_DATA_PATH",
    "SUB2API_HOST_CONFIG_PATH",
    "SUB2API_HOST_COMPOSE_FILE",
    "SUB2API_HOST_ENV_FILE",
}
RAW_SECRET_NAMES = {
    "SUB2API_ACCESS_TOKEN",
    "SUB2API_AUTH_EVIDENCE_FILE",
    "CONTROL_DB_PASSWORD",
    "CONTROL_REDIS_PASSWORD",
    "CONTROL_DATABASE_PASSWORD",
    "CONTROL_SESSION_HMAC_SECRET",
    "SUB2API_POSTGRES_PASSWORD",
    "SUB2API_REDIS_PASSWORD",
}
RESERVED_ENV_NAMES = {
    "CONTROL_CONNECTOR_RELEASE_METADATA_JSON",
    "CONTROL_RELEASE_EVIDENCE_DIR",
    "CONTROL_RELEASE_CERTIFICATE_OIDC_ISSUER",
    "CONTROL_RELEASE_CERTIFICATE_IDENTITY",
    "CONTROL_RELEASE_CERTIFICATE_WORKFLOW_SHA",
    "CONTROL_RELEASE_CERTIFICATE_WORKFLOW_TRIGGER",
    "CONTROL_RELEASE_CERTIFICATE_WORKFLOW_REPOSITORY",
    "CONTROL_RELEASE_CERTIFICATE_WORKFLOW_REF",
    "CONTROL_RELEASE_EXPECTED_SOURCE_REPOSITORY",
    "CONTROL_RELEASE_EXPECTED_SOURCE_COMMIT",
    "CONTROL_RELEASE_EXPECTED_TAG",
    "CONTROL_RELEASE_EXPECTED_API_REPOSITORY",
    "CONTROL_RELEASE_EXPECTED_PWA_REPOSITORY",
    "CONTROL_RELEASE_EXPECTED_POSTGRES_TOOLS_REPOSITORY",
    "CONTROL_RELEASE_COSIGN_BIN",
    "CONTROL_SERVER_PACKAGE_MODE",
    "CONTROL_SERVER_PACKAGE_MANIFEST_PATH",
    "CONTROL_SERVER_PACKAGE_MANIFEST_SHA256",
    "CONTROL_SERVER_PACKAGE_VERIFICATION_RECEIPT",
    "VERSIONS_LOCK_FILE",
    "CONTROL_TIMEOUT_BIN",
}


def _validate_private_referenced_file(
    path: Path,
    label: str,
    *,
    expected_uid: int,
    additional_uids: Iterable[int] = (),
) -> None:
    accepted_uids = {expected_uid, *additional_uids}
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise LifecycleError(f"cannot inspect {label}: {path}") from exc
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid not in accepted_uids
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) & 0o077
    ):
        fail(f"{label} must be one private regular file owned by an admitted user")


def _audit_compose_env(path: Path, *, expected_uid: int) -> None:
    raw = secure_read(
        path,
        "production Compose environment",
        expected_uid=expected_uid,
        accepted_modes={0o400, 0o600},
        maximum=MAX_OPERATOR_ENV_BYTES,
    )
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise LifecycleError("production Compose environment is not UTF-8") from exc
    for line_number, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        assignment = re.match(
            r"^[ \t]*(?:export[ \t]+)?([A-Za-z_][A-Za-z0-9_]*)[ \t]*=",
            line,
        )
        if assignment is None:
            continue
        name = assignment.group(1)
        if name in RESERVED_ENV_NAMES:
            fail(
                "production Compose environment must not override lifecycle-owned "
                f"input {name}"
            )
        if name in RAW_SECRET_NAMES or re.search(
            r"(?:PASSWORD|TOKEN|SECRET|PRIVATE_KEY|CREDENTIAL)$", name
        ):
            fail(
                f"production Compose environment line {line_number} contains "
                f"prohibited raw secret {name}"
            )


def parse_operator_env(path: Path, *, expected_uid: int = 0) -> tuple[dict[str, str], str]:
    path = _absolute_normalized(path, "operator environment file")
    raw = secure_read(
        path,
        "operator environment file",
        expected_uid=expected_uid,
        accepted_modes={0o600},
        maximum=MAX_OPERATOR_ENV_BYTES,
    )
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise LifecycleError("operator environment file is not UTF-8") from exc
    values: dict[str, str] = {}
    for line_number, line in enumerate(text.splitlines(), 1):
        if not line or line.startswith("#"):
            continue
        if line != line.strip() or "=" not in line:
            fail(f"operator environment line {line_number} is not literal NAME=value")
        name, value = line.split("=", 1)
        if ENV_NAME_RE.fullmatch(name) is None or not value:
            fail(f"operator environment line {line_number} is invalid")
        if name in values:
            fail(f"operator environment repeats {name}")
        if name == "CONTROL_CONNECTOR_RELEASE_METADATA_JSON":
            fail("operator cannot override packaged Connector release metadata")
        if name in RAW_SECRET_NAMES or re.search(
            r"(?:PASSWORD|TOKEN|SECRET|PRIVATE_KEY|CREDENTIAL)$", name
        ):
            fail(f"operator environment contains prohibited raw secret {name}")
        if name in RESERVED_ENV_NAMES:
            fail(f"operator environment attempts to override reserved input {name}")
        if name not in ALLOWED_OPERATOR_NAMES:
            fail(f"operator environment name is not allowlisted: {name}")
        if any(ord(character) < 0x20 or ord(character) == 0x7F for character in value):
            fail(f"operator environment value contains a control character: {name}")
        if name in ABSOLUTE_FILE_NAMES | ABSOLUTE_DIRECTORY_NAMES | CONTAINER_PATH_NAMES:
            candidate = Path(value)
            _absolute_normalized(candidate, name)
            # The Sub2API config lives inside the Sub2API data tree, which
            # the Sub2API service user owns; it is validated after the bind
            # policy is known so that owner can be admitted explicitly.
            if name in ABSOLUTE_FILE_NAMES and name != "SUB2API_HOST_CONFIG_PATH":
                _validate_private_referenced_file(
                    candidate, name, expected_uid=expected_uid
                )
        elif name in POSITIVE_INTEGER_NAMES:
            if not value.isdigit() or not 0 < int(value) <= MAX_DEPLOYMENT_TIMEOUT_SECONDS:
                fail(f"operator environment value is invalid: {name}")
        elif name in BIND_POLICY_ID_NAMES:
            if not value.isdigit() or not 0 < int(value) <= MAX_BIND_POLICY_ID:
                fail(f"operator environment value is invalid: {name}")
        elif name == BIND_POLICY_MODE_NAME:
            if value not in ACCEPTED_BIND_MODES:
                fail(f"operator environment value is invalid: {name}")
        elif SAFE_IDENTIFIER_RE.fullmatch(value) is None:
            fail(f"operator environment identifier is invalid: {name}")
        values[name] = value
    missing = REQUIRED_OPERATOR_NAMES - set(values)
    if missing:
        fail(f"operator environment lacks required values: {sorted(missing)}")
    bind_policy_present = BIND_POLICY_NAMES & set(values)
    if bind_policy_present and bind_policy_present != BIND_POLICY_NAMES:
        fail(
            "operator environment must supply the complete Sub2API bind policy: "
            f"{sorted(BIND_POLICY_NAMES)}"
        )
    admitted_config_uids: list[int] = []
    if bind_policy_present:
        admitted_config_uids.append(int(values["SUB2API_EXPECTED_DATA_BIND_UID"]))
    _validate_private_referenced_file(
        Path(values["SUB2API_HOST_CONFIG_PATH"]),
        "SUB2API_HOST_CONFIG_PATH",
        expected_uid=expected_uid,
        additional_uids=admitted_config_uids,
    )
    _audit_compose_env(Path(values["CONTROL_COMPOSE_ENV_FILE"]), expected_uid=expected_uid)
    return values, hashlib.sha256(raw).hexdigest()


def _fixed_environment() -> dict[str, str]:
    return {
        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "HOME": "/root",
        "USER": "root",
        "LOGNAME": "root",
        "SHELL": "/bin/sh",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "TZ": "UTC",
        "TMPDIR": "/var/tmp",
        "PYTHONDONTWRITEBYTECODE": "1",
        "HTTP_PROXY": "",
        "HTTPS_PROXY": "",
        "ALL_PROXY": "",
        "NO_PROXY": "*",
        "http_proxy": "",
        "https_proxy": "",
        "all_proxy": "",
        "no_proxy": "*",
        "DOCKER_HOST": LOCAL_DOCKER_HOST,
    }


def _resolve_trusted_executable(name: str, *, expected_uid: int) -> str:
    located = shutil.which(name, path=_fixed_environment()["PATH"])
    if located is None:
        fail(f"required executable is unavailable: {name}")
    try:
        resolved = Path(located).resolve(strict=True)
        metadata = resolved.stat()
    except OSError as exc:
        raise LifecycleError(f"cannot inspect required executable {name}") from exc
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != expected_uid
        or stat.S_IMODE(metadata.st_mode) & 0o022
        or not metadata.st_mode & stat.S_IXUSR
    ):
        fail(f"required executable is not trusted: {resolved}")
    _validate_existing_ancestors(resolved.parent, expected_uid=expected_uid)
    return str(resolved)


def _verify_cosign_version(
    cosign: str,
    expected_version: str,
    *,
    env: Mapping[str, str],
) -> str:
    if re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", expected_version) is None:
        fail("package builder Cosign version is invalid")
    result = _run_bounded(
        [cosign, "version"],
        env=env,
        cwd=None,
        timeout_seconds=30,
        label="verify host Cosign version",
        capture_output=True,
    )
    combined = (result.stdout or b"") + b"\n" + (result.stderr or b"")
    if len(combined) > 1024 * 1024:
        fail("Cosign version output exceeds the accepted size")
    versions = set(re.findall(rb"v[0-9]+\.[0-9]+\.[0-9]+", combined))
    observed = {version.decode("ascii") for version in versions}
    if observed != {expected_version}:
        fail(
            f"Cosign version mismatch: expected {expected_version}, "
            f"observed {sorted(observed)}"
        )
    return expected_version


def _run_bounded(
    argv: Sequence[str],
    *,
    env: Mapping[str, str],
    cwd: Path | None,
    timeout_seconds: int,
    label: str,
    capture_output: bool = False,
) -> subprocess.CompletedProcess[bytes]:
    stdout: int | None = subprocess.PIPE if capture_output else None
    stderr: int | None = subprocess.PIPE if capture_output else None
    process = subprocess.Popen(
        list(argv),
        cwd=cwd,
        env=dict(env),
        stdin=subprocess.DEVNULL,
        stdout=stdout,
        stderr=stderr,
        start_new_session=True,
    )
    try:
        output, error = process.communicate(timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGTERM)
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
        raise LifecycleError(f"{label} exceeded its bounded timeout")
    if process.returncode != 0:
        raise CommandError(label, process.returncode)
    return subprocess.CompletedProcess(argv, process.returncode, output, error)


def _inspect_image(
    docker: str,
    reference: str,
    *,
    env: Mapping[str, str],
    timeout_seconds: int = 120,
) -> None:
    result = _run_bounded(
        [docker, "image", "inspect", reference],
        env=env,
        cwd=None,
        timeout_seconds=timeout_seconds,
        label=f"inspect locked image {reference}",
        capture_output=True,
    )
    if result.stdout is None or len(result.stdout) > MAX_JSON_BYTES:
        fail(f"Docker image inspection is invalid: {reference}")
    try:
        inspected = json.loads(result.stdout.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise LifecycleError(f"Docker returned invalid image inspection for {reference}") from exc
    if not isinstance(inspected, list) or len(inspected) != 1:
        fail(f"Docker image inspection is ambiguous: {reference}")
    repo_digests = inspected[0].get("RepoDigests")
    if not isinstance(repo_digests, list) or reference not in repo_digests:
        fail(f"local Docker image is not bound to locked digest {reference}")
    if inspected[0].get("Os") != "linux" or inspected[0].get("Architecture") != "amd64":
        fail(f"local Docker image platform is not Linux amd64: {reference}")


def acquire_images(
    package_root: Path,
    manifest: dict[str, Any],
    *,
    env: Mapping[str, str],
    docker: str,
    timeout_seconds: int,
) -> list[str]:
    references: list[str] = []
    for component in COMPONENTS:
        record = manifest["images"][component]
        if manifest["mode"] == "online":
            reference = _validate_image_reference(
                record["reference"], record["repository"], record["digest"], component
            )
            _run_bounded(
                [docker, "pull", "--platform", "linux/amd64", reference],
                env=env,
                cwd=None,
                timeout_seconds=timeout_seconds,
                label=f"pull locked image {component}",
            )
        else:
            reference = require_string(
                record["locked_reference"], f"{component} locked reference"
            )
            archive_record = record["archive"]
            archive = package_root / archive_record["filename"]
            before_sha256 = sha256_file(archive)
            if before_sha256 != archive_record["sha256"]:
                fail(f"offline image archive changed before Docker load: {component}")
            _run_bounded(
                [docker, "load", "--input", str(archive)],
                env=env,
                cwd=None,
                timeout_seconds=timeout_seconds,
                label=f"load locked offline image {component}",
            )
            if sha256_file(archive) != before_sha256:
                fail(f"offline image archive changed during Docker load: {component}")
        _inspect_image(docker, reference, env=env)
        references.append(reference)
    if len(set(references)) != len(COMPONENTS):
        fail("package image references are not unique")
    return references


def _write_all(descriptor: int, content: bytes) -> None:
    view = memoryview(content)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            fail("short write while recording lifecycle state")
        view = view[written:]


def write_exclusive_json(path: Path, value: Any, *, mode: int = 0o400) -> None:
    content = canonical_json(value)
    temporary = path.parent / f".{path.name}.tmp-{uuid.uuid4().hex}"
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(temporary, flags, mode)
        try:
            _write_all(descriptor, content)
            os.fchmod(descriptor, mode)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.link(temporary, path, follow_symlinks=False)
        parent_descriptor = os.open(
            path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        )
        try:
            os.fsync(parent_descriptor)
        finally:
            os.close(parent_descriptor)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def replace_json(path: Path, value: Any) -> None:
    temporary = path.parent / f".{path.name}.tmp-{uuid.uuid4().hex}"
    write_exclusive_json(temporary, value)
    try:
        os.replace(temporary, path)
        descriptor = os.open(
            path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        )
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


@contextlib.contextmanager
def lifecycle_lock(
    paths: LifecyclePaths, operation_id: str
) -> Iterator[LifecycleLockLease]:
    lease = LifecycleLockLease()
    holder = {
        "format_version": FORMAT_VERSION,
        "operation_id": operation_id,
        "pid": os.getpid(),
        "started_at": int(time.time()),
    }
    content = canonical_json(holder)
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(paths.lock, flags, 0o400)
    except FileExistsError as exc:
        raise LifecycleError(
            f"another lifecycle operation is active, or stale lock requires review: {paths.lock}"
        ) from exc
    try:
        _write_all(descriptor, content)
        os.fchmod(descriptor, 0o400)
        os.fsync(descriptor)
        locked_metadata = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    try:
        yield lease
    finally:
        try:
            current = paths.lock.lstat()
        except FileNotFoundError:
            fail("lifecycle lock disappeared during the operation")
        if (
            current.st_dev != locked_metadata.st_dev
            or current.st_ino != locked_metadata.st_ino
            or not stat.S_ISREG(current.st_mode)
            or current.st_uid != 0
        ):
            fail("lifecycle lock changed during the operation")
        if not lease.retained:
            paths.lock.unlink()
            parent_descriptor = os.open(
                paths.lock.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
            )
            try:
                os.fsync(parent_descriptor)
            finally:
                os.close(parent_descriptor)


def _operation_id(action: str) -> str:
    return (
        f"{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}-"
        f"{time.time_ns()}-{os.getpid()}-{action}-{uuid.uuid4().hex}"
    )


def _activation_summary(value: dict[str, Any] | None) -> dict[str, Any] | None:
    if value is None:
        return None
    return {
        "generation": value["generation"],
        "active_release_id": value["active_release_id"],
        "previous_release_id": value["previous_release_id"],
        "production_deployment": value["production_deployment"],
    }


def _validate_production_deployment_binding(value: Any) -> dict[str, Any]:
    binding = exact_object(
        value,
        {
            "operation_id",
            "action",
            "deployment_directory",
            "deployment_record_path",
            "deployment_record_sha256",
            "terminal_status_path",
            "terminal_status",
            "terminal_status_sha256",
        },
        "active production deployment binding",
    )
    operation_id = require_string(
        binding["operation_id"], "active production deployment operation id"
    )
    action = require_string(
        binding["action"], "active production deployment lifecycle action"
    )
    if action not in {"install", "upgrade", "rollback"}:
        fail("active production deployment lifecycle action is invalid")
    if re.fullmatch(
        rf"[0-9]{{8}}T[0-9]{{6}}Z-[0-9]+-[0-9]+-{action}-[0-9a-f]{{32}}",
        operation_id,
    ) is None:
        fail("active production deployment operation and action differ")
    deployment_directory = _absolute_normalized(
        Path(
            require_string(
                binding["deployment_directory"],
                "active production deployment directory",
            )
        ),
        "active production deployment directory",
    )
    if re.fullmatch(
        r"deployment-[0-9]{8}T[0-9]{6}Z-[0-9]+", deployment_directory.name
    ) is None:
        fail("active production deployment directory identity is invalid")
    deployment_record_path = _absolute_normalized(
        Path(
            require_string(
                binding["deployment_record_path"],
                "active production deployment record path",
            )
        ),
        "active production deployment record path",
    )
    terminal_status_path = _absolute_normalized(
        Path(
            require_string(
                binding["terminal_status_path"],
                "active production deployment terminal status path",
            )
        ),
        "active production deployment terminal status path",
    )
    if deployment_record_path != deployment_directory / "deployment.json":
        fail("active production deployment record path is not fixed")
    if terminal_status_path != deployment_directory / "status":
        fail("active production deployment terminal status path is not fixed")
    require_sha256(
        binding["deployment_record_sha256"],
        "active production deployment record hash",
    )
    require_sha256(
        binding["terminal_status_sha256"],
        "active production deployment terminal status hash",
    )
    if (
        binding["terminal_status"] != "deployed"
        or binding["terminal_status_sha256"]
        != hashlib.sha256(b"deployed\n").hexdigest()
    ):
        fail("active production deployment terminal status is invalid")
    return binding


def _read_activation(paths: LifecyclePaths) -> dict[str, Any] | None:
    if not paths.activation.exists() and not paths.activation.is_symlink():
        return None
    raw = secure_read(
        paths.activation,
        "activation pointer",
        expected_uid=0,
        accepted_modes={0o400},
    )
    value = exact_object(
        strict_json(raw, "activation pointer"),
        {
            "$schema",
            "format_version",
            "generation",
            "activated_at",
            "operation_id",
            "active_release_id",
            "previous_release_id",
            "production_deployment",
        },
        "activation pointer",
    )
    if (
        value["$schema"] != ACTIVATION_SCHEMA_ID
        or value["format_version"] != FORMAT_VERSION
        or type(value["generation"]) is not int
        or value["generation"] <= 0
        or type(value["activated_at"]) is not int
        or value["activated_at"] <= 0
    ):
        fail("activation pointer identity is invalid")
    _validate_release_id(value["active_release_id"])
    if value["previous_release_id"] is not None:
        _validate_release_id(value["previous_release_id"])
        if value["previous_release_id"] == value["active_release_id"]:
            fail("activation pointer repeats the active release as previous")
    require_string(value["operation_id"], "activation operation id")
    deployment = _validate_production_deployment_binding(
        value["production_deployment"]
    )
    if deployment["operation_id"] != value["operation_id"]:
        fail("activation and production deployment operation ids differ")
    return value


def _validate_release_id(value: Any) -> str:
    release_id = require_string(value, "release id", maximum=160)
    if re.fullmatch(r"[0-9A-Za-z][0-9A-Za-z.-]+", release_id) is None:
        fail("release id is invalid")
    return release_id


def _release_id(manifest: dict[str, Any], receipt: dict[str, Any]) -> str:
    return (
        f"{manifest['release']}-{manifest['mode']}-"
        f"{receipt['package']['sha256']}"
    )


def _release_record_path(paths: LifecyclePaths, release_id: str) -> Path:
    return paths.release_record_root / f"{_validate_release_id(release_id)}.json"


def _release_record_value(
    manifest: dict[str, Any],
    receipt: dict[str, Any],
    *,
    release_id: str,
    install_path: Path,
    source_verification_receipt_sha256: str,
    source_verification_receipt_path: Path,
    verification_receipt_sha256: str,
    verification_receipt_path: Path,
    connector_metadata_sha256: str,
    installed_at: int,
) -> dict[str, Any]:
    return {
        "$schema": RELEASE_RECORD_SCHEMA_ID,
        "format_version": FORMAT_VERSION,
        "release_id": release_id,
        "release": manifest["release"],
        "release_tag": manifest["release_tag"],
        "mode": manifest["mode"],
        "platform": PLATFORM,
        "archive_sha256": receipt["package"]["sha256"],
        "archive_size": receipt["package"]["size"],
        "internal_manifest_sha256": receipt["package"]["internal_manifest_sha256"],
        "source_verification_receipt_sha256": source_verification_receipt_sha256,
        "source_verification_receipt_path": str(source_verification_receipt_path),
        "verification_receipt_sha256": verification_receipt_sha256,
        "verification_receipt_path": str(verification_receipt_path),
        "release_manifest_sha256": receipt["release_manifest"]["sha256"],
        "connector_metadata_sha256": connector_metadata_sha256,
        "cosign_version": manifest["builder"]["cosign_version"],
        "install_path": str(install_path),
        "source": manifest["source"],
        "builder": manifest["builder"],
        "images": manifest["images"],
        "verification_trust": receipt["trust"],
        "verification_trust_sha256": hashlib.sha256(
            canonical_json(receipt["trust"])
        ).hexdigest(),
        "installed_at": installed_at,
    }


def _validate_release_record(value: Any, paths: LifecyclePaths) -> dict[str, Any]:
    record = exact_object(
        value,
        {
            "$schema",
            "format_version",
            "release_id",
            "release",
            "release_tag",
            "mode",
            "platform",
            "archive_sha256",
            "archive_size",
            "internal_manifest_sha256",
            "source_verification_receipt_sha256",
            "source_verification_receipt_path",
            "verification_receipt_sha256",
            "verification_receipt_path",
            "release_manifest_sha256",
            "connector_metadata_sha256",
            "cosign_version",
            "install_path",
            "source",
            "builder",
            "images",
            "verification_trust",
            "verification_trust_sha256",
            "installed_at",
        },
        "installed release record",
    )
    if (
        record["$schema"] != RELEASE_RECORD_SCHEMA_ID
        or record["format_version"] != FORMAT_VERSION
        or record["platform"] != PLATFORM
        or record["mode"] not in MODES
        or type(record["installed_at"]) is not int
        or record["installed_at"] <= 0
    ):
        fail("installed release record identity is invalid")
    release_id = _validate_release_id(record["release_id"])
    expected_path = paths.install_root / release_id
    if Path(require_string(record["install_path"], "installed release path")) != expected_path:
        fail("installed release record path is not fixed")
    expected_receipt_path = paths.verification_receipt_root / f"{release_id}.json"
    expected_source_receipt_path = (
        paths.verification_receipt_root / f"{release_id}.source.json"
    )
    if Path(
        require_string(
            record["verification_receipt_path"],
            "installed verification receipt path",
        )
    ) != expected_receipt_path:
        fail("installed verification receipt record path is not fixed")
    if Path(
        require_string(
            record["source_verification_receipt_path"],
            "source verification receipt path",
        )
    ) != expected_source_receipt_path:
        fail("source verification receipt record path is not fixed")
    for key in (
        "archive_sha256",
        "internal_manifest_sha256",
        "source_verification_receipt_sha256",
        "verification_receipt_sha256",
        "release_manifest_sha256",
        "connector_metadata_sha256",
        "verification_trust_sha256",
    ):
        require_sha256(record[key], f"installed release {key}")
    if type(record["archive_size"]) is not int or record["archive_size"] <= 0:
        fail("installed release archive size is invalid")
    if re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", record["cosign_version"]) is None:
        fail("installed release Cosign version is invalid")
    if hashlib.sha256(canonical_json(record["verification_trust"])).hexdigest() != record[
        "verification_trust_sha256"
    ]:
        fail("installed release verification trust hash is invalid")
    return record


def _read_release_record(paths: LifecyclePaths, release_id: str) -> dict[str, Any]:
    path = _release_record_path(paths, release_id)
    raw = secure_read(
        path,
        "installed release record",
        expected_uid=0,
        accepted_modes={0o400},
    )
    record = _validate_release_record(strict_json(raw, "installed release record"), paths)
    if record["release_id"] != release_id:
        fail("installed release record filename and identity differ")
    return record


def _installed_verification_receipt(
    receipt: dict[str, Any], installed_root: Path
) -> tuple[dict[str, Any], bytes, str]:
    installed_receipt = strict_json(
        canonical_json(receipt),
        "source package verification receipt",
        canonical=True,
    )
    installed_receipt["package"]["extracted_root"] = str(installed_root)
    installed_content = canonical_json(installed_receipt)
    return (
        installed_receipt,
        installed_content,
        hashlib.sha256(installed_content).hexdigest(),
    )


def _candidate_operation_record(
    paths: LifecyclePaths,
    manifest: dict[str, Any],
    receipt: dict[str, Any],
    connector_raw: bytes,
    receipt_sha256: str,
) -> tuple[str, Path, dict[str, Any]]:
    source_content = canonical_json(receipt)
    if hashlib.sha256(source_content).hexdigest() != receipt_sha256:
        fail("verification receipt changed before lifecycle intent was recorded")
    release_id = _release_id(manifest, receipt)
    destination = paths.install_root / release_id
    _, _, installed_receipt_sha256 = _installed_verification_receipt(
        receipt, destination
    )
    trust = strict_json(
        canonical_json(receipt["trust"]),
        "candidate package verification trust",
        canonical=True,
    )
    return (
        release_id,
        destination,
        {
            "release": manifest["release"],
            "mode": manifest["mode"],
            "archive_sha256": receipt["package"]["sha256"],
            "internal_manifest_sha256": receipt["package"][
                "internal_manifest_sha256"
            ],
            "source_verification_receipt_sha256": receipt_sha256,
            "verification_receipt_sha256": installed_receipt_sha256,
            "connector_metadata_sha256": hashlib.sha256(connector_raw).hexdigest(),
            "cosign_version": manifest["builder"]["cosign_version"],
            "verification_trust": trust,
            "verification_trust_sha256": hashlib.sha256(
                canonical_json(trust)
            ).hexdigest(),
            "install_path": str(destination),
        },
    )


def _persist_verification_receipt(
    paths: LifecyclePaths,
    release_id: str,
    receipt: dict[str, Any],
    source_expected_sha256: str,
    installed_root: Path,
) -> tuple[Path, str, Path]:
    source_path = paths.verification_receipt_root / f"{release_id}.source.json"
    path = paths.verification_receipt_root / f"{release_id}.json"
    source_content = canonical_json(receipt)
    if hashlib.sha256(source_content).hexdigest() != source_expected_sha256:
        fail("verification receipt changed before installation")
    if source_path.exists() or source_path.is_symlink():
        observed = secure_read(
            source_path,
            "persisted source package verification receipt",
            expected_uid=0,
            accepted_modes={0o400},
        )
        if observed != source_content:
            fail("persisted source verification receipt differs from this package")
    else:
        write_exclusive_json(source_path, receipt)
    installed_receipt, installed_content, installed_sha256 = (
        _installed_verification_receipt(receipt, installed_root)
    )
    if path.exists() or path.is_symlink():
        observed = secure_read(
            path,
            "persisted installed package verification receipt",
            expected_uid=0,
            accepted_modes={0o400},
        )
        if observed != installed_content:
            fail("persisted installed verification receipt differs from this package")
    else:
        write_exclusive_json(path, installed_receipt)
    return path, installed_sha256, source_path


def _secure_copy(
    source: Path,
    destination: Path,
    *,
    expected_uid: int,
    mode: int,
    expected_sha256: str,
    expected_size: int,
) -> None:
    source_descriptor = os.open(
        source,
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        destination_descriptor = os.open(
            destination,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            mode,
        )
        try:
            before = os.fstat(source_descriptor)
            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_uid != expected_uid
                or before.st_nlink != 1
                or stat.S_IMODE(before.st_mode) != mode
                or before.st_size != expected_size
                or not 0 <= expected_size <= MAX_FILE_BYTES
            ):
                fail(f"package copy source metadata is invalid: {source}")
            digest = hashlib.sha256()
            total = 0
            while block := os.read(source_descriptor, 1024 * 1024):
                total += len(block)
                if total > expected_size:
                    fail(f"package copy source grew: {source}")
                digest.update(block)
                _write_all(destination_descriptor, block)
            after = os.fstat(source_descriptor)
            if (
                total != expected_size
                or digest.hexdigest() != expected_sha256
                or _stable_fields(before) != _stable_fields(after)
            ):
                fail(
                    f"package copy source changed or differs from inventory: {source}"
                )
            os.fchmod(destination_descriptor, mode)
            os.fsync(destination_descriptor)
        finally:
            os.close(destination_descriptor)
    finally:
        os.close(source_descriptor)


def _remove_validated_package(root: Path, manifest: dict[str, Any]) -> None:
    expected = {record["path"] for record in manifest["files"]} | {
        PACKAGE_MANIFEST_FILENAME
    }
    actual, directories = _walk_package_tree(root, expected_uid=0)
    if actual != expected:
        fail("refusing to remove an installed package with unexpected content")
    os.chmod(root, 0o700)
    for relative in sorted(
        directories, key=lambda item: len(PurePosixPath(item).parts)
    ):
        os.chmod(root / relative, 0o700)
    for relative in sorted(expected, key=lambda item: len(PurePosixPath(item).parts), reverse=True):
        (root / relative).unlink()
    for relative in sorted(
        directories, key=lambda item: len(PurePosixPath(item).parts), reverse=True
    ):
        directory = root / relative
        os.chmod(directory, 0o700)
        directory.rmdir()
    root.rmdir()


def _cleanup_staging(root: Path) -> None:
    if not root.exists() and not root.is_symlink():
        return
    metadata = root.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != 0:
        fail("cannot clean an untrusted package staging directory")
    for directory, subdirectories, files in os.walk(root, topdown=False, followlinks=False):
        current = Path(directory)
        for name in files:
            child = current / name
            child_metadata = child.lstat()
            if stat.S_ISLNK(child_metadata.st_mode) or not stat.S_ISREG(child_metadata.st_mode):
                fail("package staging directory contains an unsupported entry")
            child.unlink()
        for name in subdirectories:
            child = current / name
            os.chmod(child, 0o700)
            child.rmdir()
    os.chmod(root, 0o700)
    root.rmdir()


def _copy_immutable_package(
    source_root: Path,
    destination: Path,
    manifest: dict[str, Any],
) -> None:
    staging = destination.parent / f".staging-{destination.name}-{uuid.uuid4().hex}"
    staging.mkdir(mode=0o700)
    created_directories: set[Path] = {staging}
    try:
        manifest_content = canonical_json(manifest)
        records = list(manifest["files"]) + [
            {
                "path": PACKAGE_MANIFEST_FILENAME,
                "mode": "0444",
                "sha256": hashlib.sha256(manifest_content).hexdigest(),
                "size": len(manifest_content),
            }
        ]
        for record in records:
            relative = Path(*PurePosixPath(record["path"]).parts)
            target = staging / relative
            missing: list[Path] = []
            current = target.parent
            while current != staging and not current.exists():
                missing.append(current)
                current = current.parent
            for directory in reversed(missing):
                directory.mkdir(mode=0o700)
                created_directories.add(directory)
            _secure_copy(
                source_root / relative,
                target,
                expected_uid=0,
                mode=int(record["mode"], 8),
                expected_sha256=record["sha256"],
                expected_size=record["size"],
            )
        for directory in sorted(
            created_directories, key=lambda item: len(item.parts), reverse=True
        ):
            os.chmod(directory, 0o555)
        if destination.exists() or destination.is_symlink():
            fail(f"immutable installed release already exists: {destination}")
        os.rename(staging, destination)
        descriptor = os.open(
            destination.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        )
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except BaseException:
        _cleanup_staging(staging)
        raise


def _manifest_from_installed_record(
    record: dict[str, Any], paths: LifecyclePaths
) -> tuple[Path, dict[str, Any], bytes]:
    root = Path(record["install_path"])
    validate_directory(
        root,
        "installed package",
        expected_uid=0,
        exact_mode=0o555,
    )
    raw = secure_read(
        root / PACKAGE_MANIFEST_FILENAME,
        "installed package manifest",
        expected_uid=0,
        accepted_modes={0o444},
    )
    if hashlib.sha256(raw).hexdigest() != record["internal_manifest_sha256"]:
        fail("installed package manifest differs from its release record")
    receipt_path = Path(record["verification_receipt_path"])
    receipt_raw = secure_read(
        receipt_path,
        "persisted package verification receipt",
        expected_uid=0,
        accepted_modes={0o400},
    )
    if hashlib.sha256(receipt_raw).hexdigest() != record["verification_receipt_sha256"]:
        fail("persisted package verification receipt differs from its release record")
    persisted_receipt = _validate_receipt(
        strict_json(receipt_raw, "persisted package verification receipt")
    )
    if (
        persisted_receipt["package"]["sha256"] != record["archive_sha256"]
        or persisted_receipt["package"]["internal_manifest_sha256"]
        != record["internal_manifest_sha256"]
        or persisted_receipt["package"]["extracted_root"] != str(root)
        or persisted_receipt["trust"] != record["verification_trust"]
    ):
        fail("persisted verification receipt does not bind the installed package")
    source_receipt_path = Path(record["source_verification_receipt_path"])
    source_receipt_raw = secure_read(
        source_receipt_path,
        "persisted source package verification receipt",
        expected_uid=0,
        accepted_modes={0o400},
    )
    if (
        hashlib.sha256(source_receipt_raw).hexdigest()
        != record["source_verification_receipt_sha256"]
    ):
        fail("persisted source verification receipt differs from its release record")
    source_receipt = _validate_receipt(
        strict_json(source_receipt_raw, "persisted source verification receipt")
    )
    rebound_source = strict_json(
        canonical_json(source_receipt),
        "persisted source verification receipt",
    )
    rebound_source["package"]["extracted_root"] = str(root)
    if rebound_source != persisted_receipt:
        fail("installed verification receipt is not an exact root rebinding")
    manifest = _validate_package_manifest(strict_json(raw, "installed package manifest"))
    if (
        manifest["release"] != record["release"]
        or manifest["release_tag"] != record["release_tag"]
        or manifest["mode"] != record["mode"]
        or manifest["source"] != record["source"]
        or manifest["builder"] != record["builder"]
        or manifest["images"] != record["images"]
        or manifest["builder"]["cosign_version"] != record["cosign_version"]
    ):
        fail("installed package identity differs from its release record")
    actual, _ = _walk_package_tree(root, expected_uid=0)
    expected = {item["path"] for item in manifest["files"]} | {
        PACKAGE_MANIFEST_FILENAME
    }
    if actual != expected:
        fail("installed package tree differs from its exact inventory")
    for item in manifest["files"]:
        path = root / item["path"]
        observed_sha256, observed_size = secure_hash_file(
            path,
            f"installed package file {item['path']}",
            expected_uid=0,
            accepted_modes={int(item["mode"], 8)},
            maximum=item["size"],
        )
        if observed_size != item["size"] or observed_sha256 != item["sha256"]:
            fail(f"installed package file changed: {item['path']}")
    connector_raw = secure_read(
        root / CONNECTOR_METADATA_FILENAME,
        "installed Connector release metadata",
        expected_uid=0,
        accepted_modes={0o444},
    )
    if hashlib.sha256(connector_raw).hexdigest() != record["connector_metadata_sha256"]:
        fail("installed Connector release metadata differs from its release record")
    _validate_connector_metadata(connector_raw)
    return root, manifest, connector_raw


def _ensure_installed(
    paths: LifecyclePaths,
    source_root: Path,
    manifest: dict[str, Any],
    receipt: dict[str, Any],
    connector_raw: bytes,
    receipt_sha256: str,
) -> tuple[str, Path, dict[str, Any]]:
    release_id = _release_id(manifest, receipt)
    destination = paths.install_root / release_id
    record_path = _release_record_path(paths, release_id)
    destination_exists = destination.exists() or destination.is_symlink()
    record_exists = record_path.exists() or record_path.is_symlink()
    if destination_exists:
        if not record_exists:
            fail("installed package lacks its append-only release record")
        record = _read_release_record(paths, release_id)
        _manifest_from_installed_record(record, paths)
        if (
            record["archive_sha256"] != receipt["package"]["sha256"]
            or record["source_verification_receipt_sha256"] != receipt_sha256
            or record["connector_metadata_sha256"]
            != hashlib.sha256(connector_raw).hexdigest()
        ):
            fail("existing immutable installed release differs from this package")
        return release_id, destination, record
    if record_exists:
        record = _read_release_record(paths, release_id)
        preserved_receipts = (
            Path(record["source_verification_receipt_path"]),
            Path(record["verification_receipt_path"]),
        )
        if any(
            not path.exists() or path.is_symlink() for path in preserved_receipts
        ):
            fail("preserved release record lacks its verification receipts")
        (
            persisted_receipt_path,
            persisted_receipt_sha256,
            source_receipt_path,
        ) = _persist_verification_receipt(
            paths,
            release_id,
            receipt,
            receipt_sha256,
            destination,
        )
        expected_record = _release_record_value(
            manifest,
            receipt,
            release_id=release_id,
            install_path=destination,
            source_verification_receipt_sha256=receipt_sha256,
            source_verification_receipt_path=source_receipt_path,
            verification_receipt_sha256=persisted_receipt_sha256,
            verification_receipt_path=persisted_receipt_path,
            connector_metadata_sha256=hashlib.sha256(connector_raw).hexdigest(),
            installed_at=record["installed_at"],
        )
        if record != expected_record:
            fail("preserved release record differs from this verified package")
        try:
            _copy_immutable_package(source_root, destination, manifest)
            _manifest_from_installed_record(record, paths)
        except BaseException:
            if destination.exists() or destination.is_symlink():
                _remove_validated_package(destination, manifest)
            raise
        return release_id, destination, record
    try:
        _copy_immutable_package(source_root, destination, manifest)
        (
            persisted_receipt_path,
            persisted_receipt_sha256,
            source_receipt_path,
        ) = _persist_verification_receipt(
            paths,
            release_id,
            receipt,
            receipt_sha256,
            destination,
        )
        installed_at = int(time.time())
        record = _release_record_value(
            manifest,
            receipt,
            release_id=release_id,
            install_path=destination,
            source_verification_receipt_sha256=receipt_sha256,
            source_verification_receipt_path=source_receipt_path,
            verification_receipt_sha256=persisted_receipt_sha256,
            verification_receipt_path=persisted_receipt_path,
            connector_metadata_sha256=hashlib.sha256(connector_raw).hexdigest(),
            installed_at=installed_at,
        )
        write_exclusive_json(record_path, record)
    except BaseException:
        if destination.exists() or destination.is_symlink():
            _remove_validated_package(destination, manifest)
        raise
    return release_id, destination, record


def _deployment_environment(
    operator: Mapping[str, str],
    package_root: Path,
    manifest: dict[str, Any],
    connector_raw: bytes,
    record: dict[str, Any],
    *,
    expected_uid: int,
) -> tuple[dict[str, str], str | None]:
    env = _fixed_environment()
    env.update(operator)
    builder = manifest["builder"]
    trust = record["verification_trust"]
    for component in COMPONENTS:
        image = manifest["images"][component]
        reference = image.get("reference", image.get("locked_reference"))
        match = IMAGE_REFERENCE_RE.fullmatch(require_string(reference, "image reference"))
        if match is None:
            fail(f"package image reference is invalid: {component}")
    connector_json = connector_raw.decode("ascii").removesuffix("\n")
    injected = {
        "CONTROL_RELEASE_EVIDENCE_DIR": str(package_root / "release"),
        "CONTROL_RELEASE_CERTIFICATE_OIDC_ISSUER": trust[
            "certificate_oidc_issuer"
        ],
        "CONTROL_RELEASE_CERTIFICATE_IDENTITY": trust["certificate_identity"],
        "CONTROL_RELEASE_CERTIFICATE_WORKFLOW_SHA": trust[
            "certificate_github_workflow_sha"
        ],
        "CONTROL_RELEASE_CERTIFICATE_WORKFLOW_TRIGGER": trust[
            "certificate_github_workflow_trigger"
        ],
        "CONTROL_RELEASE_CERTIFICATE_WORKFLOW_REPOSITORY": trust[
            "certificate_github_workflow_repository"
        ],
        "CONTROL_RELEASE_CERTIFICATE_WORKFLOW_REF": trust[
            "certificate_github_workflow_ref"
        ],
        "CONTROL_RELEASE_EXPECTED_SOURCE_REPOSITORY": trust[
            "expected_source_repository"
        ],
        "CONTROL_RELEASE_EXPECTED_SOURCE_COMMIT": trust["expected_source_commit"],
        "CONTROL_RELEASE_EXPECTED_TAG": trust["expected_release_tag"],
        "CONTROL_RELEASE_EXPECTED_API_REPOSITORY": trust[
            "expected_api_repository"
        ],
        "CONTROL_RELEASE_EXPECTED_PWA_REPOSITORY": trust[
            "expected_pwa_repository"
        ],
        "CONTROL_RELEASE_EXPECTED_POSTGRES_TOOLS_REPOSITORY": trust[
            "expected_postgres_tools_repository"
        ],
        "CONTROL_SERVER_PACKAGE_MODE": manifest["mode"],
        "CONTROL_SERVER_PACKAGE_MANIFEST_PATH": str(
            package_root / PACKAGE_MANIFEST_FILENAME
        ),
        "CONTROL_SERVER_PACKAGE_MANIFEST_SHA256": record[
            "internal_manifest_sha256"
        ],
        "CONTROL_SERVER_PACKAGE_VERIFICATION_RECEIPT": record[
            "verification_receipt_path"
        ],
        "CONTROL_CONNECTOR_RELEASE_METADATA_JSON": connector_json,
        "VERSIONS_LOCK_FILE": str(package_root / "source/versions.lock.json"),
        "CONTROL_TIMEOUT_BIN": _resolve_trusted_executable(
            "timeout", expected_uid=expected_uid
        ),
    }
    if set(operator) & set(injected):
        fail("operator environment collides with lifecycle-owned deployment inputs")
    observed_cosign_version: str | None = None
    if manifest["mode"] == "online":
        cosign = _resolve_trusted_executable("cosign", expected_uid=expected_uid)
        observed_cosign_version = _verify_cosign_version(
            cosign,
            manifest["builder"]["cosign_version"],
            env=env,
        )
        injected["CONTROL_RELEASE_COSIGN_BIN"] = cosign
    env.update(injected)
    return env, observed_cosign_version


def _assert_deployment_contract(package_root: Path, manifest: dict[str, Any]) -> Path:
    script = package_root / "source/deploy/scripts/deploy-production.sh"
    raw = secure_read(
        script,
        "signed production deployment script",
        expected_uid=0,
        accepted_modes={0o555},
        maximum=4 * 1024 * 1024,
    )
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise LifecycleError("signed production deployment script is not UTF-8") from exc
    contract_lines = {line.strip() for line in text.splitlines()}
    if (
        POST_SUCCESS_REVERSE_CONTRACT_LINE not in contract_lines
        or POST_SUCCESS_REVERSE_ARGUMENT not in text
    ):
        fail(
            "signed production deployment script has no post-success bounded "
            "reverse interface"
        )
    if (
        BOUNDED_UNINSTALL_CONTRACT_LINE not in contract_lines
        or BOUNDED_UNINSTALL_ARGUMENT not in text
    ):
        fail(
            "signed production deployment script has no bounded uninstall interface"
        )
    if re.search(r"\balembic\b[^\n]*\bdowngrade\b", text):
        fail("signed production deployment script contains an implicit database downgrade")
    if manifest["mode"] == "offline":
        if OFFLINE_CONTRACT_LINE not in {line.strip() for line in text.splitlines()}:
            fail(
                "offline package deployment is unsupported by this signed deployment "
                "script; its no-pull contract is absent"
            )
        if "CONTROL_SERVER_PACKAGE_MODE" not in text:
            fail("offline deployment script does not consume the fixed package mode")
        for required_input in (
            "CONTROL_SERVER_PACKAGE_MANIFEST_PATH",
            "CONTROL_SERVER_PACKAGE_MANIFEST_SHA256",
            "CONTROL_SERVER_PACKAGE_VERIFICATION_RECEIPT",
        ):
            if required_input not in text:
                fail(
                    "offline deployment script does not consume fixed local "
                    f"verification input {required_input}"
                )
    if "CONTROL_CONNECTOR_RELEASE_METADATA_JSON" not in text:
        fail(
            "signed deployment script does not project packaged Connector release metadata"
        )
    return script


def _deployment_directory_snapshot(record_root: Path) -> dict[str, tuple[int, int]]:
    record_root = _absolute_normalized(record_root, "deployment record root")
    validate_directory(
        record_root,
        "deployment record root",
        expected_uid=0,
        exact_mode=0o700,
    )
    observed: dict[str, tuple[int, int]] = {}
    for entry in record_root.iterdir():
        if not entry.name.startswith("deployment-"):
            continue
        metadata = validate_directory(
            entry,
            "production deployment record",
            expected_uid=0,
            exact_mode=0o700,
        )
        observed[entry.name] = (metadata.st_dev, metadata.st_ino)
    return observed


def _locate_completed_deployment(
    record_root: Path,
    before: Mapping[str, tuple[int, int]],
    deployment_state: dict[str, Any],
) -> Path:
    after = _deployment_directory_snapshot(record_root)
    changed = {
        name
        for name in set(before) & set(after)
        if before[name] != after[name]
    }
    added = sorted(set(after) - set(before))
    if changed or len(added) != 1:
        fail(
            "signed production deployment did not create one unambiguous "
            "private deployment record"
        )
    deployment_directory = record_root / added[0]
    deployment_state["deployment_directory"] = deployment_directory
    deployment_record_path = deployment_directory / "deployment.json"
    deployment_record_raw = secure_read(
        deployment_record_path,
        "successful production deployment record",
        expected_uid=0,
        accepted_modes={0o400},
    )
    deployment_record = strict_json(
        deployment_record_raw, "successful production deployment record"
    )
    if (
        not isinstance(deployment_record, dict)
        or deployment_record.get("format_version") != FORMAT_VERSION
        or deployment_record.get("status") != "deployed"
    ):
        fail("successful production deployment record is not one deployed terminal")
    status_path = deployment_directory / "status"
    status = secure_read(
        status_path,
        "successful production deployment status",
        expected_uid=0,
        accepted_modes={0o600},
        maximum=1024,
    )
    if status != b"deployed\n":
        fail("signed production deployment has no exact deployed terminal status")
    deployment_lock = record_root / ".deployment.lock"
    if deployment_lock.exists() or deployment_lock.is_symlink():
        fail("successful production deployment retained its deployment lock")
    deployment_state.update(
        {
            "deployment_record_path": deployment_record_path,
            "deployment_record_sha256": hashlib.sha256(
                deployment_record_raw
            ).hexdigest(),
            "terminal_status_path": status_path,
            "terminal_status": "deployed",
            "terminal_status_sha256": hashlib.sha256(status).hexdigest(),
        }
    )
    return deployment_directory


def _completed_deployment_binding(
    deployment_state: Mapping[str, Any], operation_id: str, action: str
) -> dict[str, Any]:
    if deployment_state.get("completed") is not True:
        fail("production deployment did not reach a completed terminal")
    deployment_directory = deployment_state.get("deployment_directory")
    deployment_record_path = deployment_state.get("deployment_record_path")
    terminal_status_path = deployment_state.get("terminal_status_path")
    if not all(
        isinstance(value, Path)
        for value in (
            deployment_directory,
            deployment_record_path,
            terminal_status_path,
        )
    ):
        fail("production deployment terminal paths were not authenticated")
    return _validate_production_deployment_binding(
        {
            "operation_id": operation_id,
            "action": action,
            "deployment_directory": str(deployment_directory),
            "deployment_record_path": str(deployment_record_path),
            "deployment_record_sha256": deployment_state.get(
                "deployment_record_sha256"
            ),
            "terminal_status_path": str(terminal_status_path),
            "terminal_status": deployment_state.get("terminal_status"),
            "terminal_status_sha256": deployment_state.get(
                "terminal_status_sha256"
            ),
        }
    )


def _invoke_deployment(
    package_root: Path,
    manifest: dict[str, Any],
    connector_raw: bytes,
    operator: Mapping[str, str],
    record: dict[str, Any],
    *,
    timeout_seconds: int,
    deployment_state: dict[str, Any],
) -> str | None:
    script = _assert_deployment_contract(package_root, manifest)
    environment, observed_cosign_version = _deployment_environment(
        operator,
        package_root,
        manifest,
        connector_raw,
        record,
        expected_uid=0,
    )
    record_root = Path(operator["CONTROL_DEPLOYMENT_RECORD_DIR"])
    before = _deployment_directory_snapshot(record_root)
    deployment_state.clear()
    deployment_state.update(
        {
            "completed": False,
            "deployment_directory": None,
            "record_root": record_root,
        }
    )
    shell = _resolve_trusted_executable("sh", expected_uid=0)
    _run_bounded(
        [shell, str(script)],
        env=environment,
        cwd=package_root / "source",
        timeout_seconds=timeout_seconds,
        label="signed production deployment",
    )
    deployment_state["completed"] = True
    deployment_state["deployment_directory"] = _locate_completed_deployment(
        record_root, before, deployment_state
    )
    return observed_cosign_version


def _validate_post_success_reverse(
    deployment_directory: Path,
    record_root: Path,
    operation_id: str,
) -> None:
    if deployment_directory.parent != record_root:
        fail("post-success reverse record is outside the admitted deployment root")
    validate_directory(
        deployment_directory,
        "post-success reverse deployment record",
        expected_uid=0,
        exact_mode=0o700,
    )
    reverse_path = deployment_directory / "reverse-execution.json"
    reverse = strict_json(
        secure_read(
            reverse_path,
            "post-success bounded reverse execution",
            expected_uid=0,
            accepted_modes={0o400},
        ),
        "post-success bounded reverse execution",
    )
    if not isinstance(reverse, dict):
        fail("post-success bounded reverse execution must be an object")
    expected_trigger = f"{POST_SUCCESS_REVERSE_TRIGGER_PREFIX}{operation_id}"
    if (
        reverse.get("format_version") != FORMAT_VERSION
        or reverse.get("type") != "production-bounded-reverse-execution-v1"
        or reverse.get("status") != "succeeded"
        or reverse.get("trigger_stage") != expected_trigger
        or reverse.get("bounded") is not True
        or reverse.get("max_attempts_per_step") != 1
    ):
        fail("post-success bounded reverse execution evidence is incomplete")
    reverse_plan = deployment_directory / "reverse-plan.json"
    plan_sha256, _ = secure_hash_file(
        reverse_plan,
        "post-success bounded reverse plan",
        expected_uid=0,
        accepted_modes={0o600},
        maximum=MAX_JSON_BYTES,
    )
    if (
        reverse.get("reverse_plan_path") != str(reverse_plan)
        or reverse.get("reverse_plan_sha256") != plan_sha256
    ):
        fail("post-success bounded reverse does not bind its admitted plan")
    deployment_lock = record_root / ".deployment.lock"
    if deployment_lock.exists() or deployment_lock.is_symlink():
        fail("post-success bounded reverse retained the production deployment lock")


def _invoke_post_success_reverse(
    package_root: Path,
    manifest: dict[str, Any],
    connector_raw: bytes,
    operator: Mapping[str, str],
    record: dict[str, Any],
    deployment_state: Mapping[str, Any],
    operation_id: str,
) -> None:
    deployment_directory = deployment_state.get("deployment_directory")
    record_root = deployment_state.get("record_root")
    if not isinstance(deployment_directory, Path) or not isinstance(record_root, Path):
        fail(
            "signed production deployment completed without one authenticated "
            "record for bounded reverse"
        )
    script = _assert_deployment_contract(package_root, manifest)
    raw = secure_read(
        script,
        "signed production deployment script",
        expected_uid=0,
        accepted_modes={0o555},
        maximum=4 * 1024 * 1024,
    )
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise LifecycleError("signed production deployment script is not UTF-8") from exc
    lines = {line.strip() for line in text.splitlines()}
    if (
        POST_SUCCESS_REVERSE_CONTRACT_LINE not in lines
        or POST_SUCCESS_REVERSE_ARGUMENT not in text
    ):
        fail(
            "signed production deployment script has no post-success bounded "
            "reverse interface"
        )
    environment, _ = _deployment_environment(
        operator,
        package_root,
        manifest,
        connector_raw,
        record,
        expected_uid=0,
    )
    shell = _resolve_trusted_executable("sh", expected_uid=0)
    _run_bounded(
        [
            shell,
            str(script),
            POST_SUCCESS_REVERSE_ARGUMENT,
            str(deployment_directory),
            f"{POST_SUCCESS_REVERSE_TRIGGER_PREFIX}{operation_id}",
        ],
        env=environment,
        cwd=package_root / "source",
        timeout_seconds=MAX_POST_SUCCESS_REVERSE_TIMEOUT_SECONDS,
        label="signed post-success bounded reverse",
    )
    _validate_post_success_reverse(
        deployment_directory,
        record_root,
        operation_id,
    )


def _prepare_roots(paths: LifecyclePaths) -> None:
    for path in (
        paths.state_root,
        paths.operation_root,
        paths.release_record_root,
        paths.verification_receipt_root,
        paths.install_root,
    ):
        ensure_private_directory(path, expected_uid=0)


def _operation_package_binding(
    release_id: str, record: Mapping[str, Any]
) -> dict[str, Any]:
    return {
        "release_id": release_id,
        "release": record["release"],
        "mode": record["mode"],
        "archive_sha256": record["archive_sha256"],
        "internal_manifest_sha256": record["internal_manifest_sha256"],
        "source_verification_receipt_sha256": record[
            "source_verification_receipt_sha256"
        ],
        "verification_receipt_sha256": record["verification_receipt_sha256"],
        "connector_metadata_sha256": record["connector_metadata_sha256"],
        "cosign_version": record["cosign_version"],
        "verification_trust": record["verification_trust"],
        "verification_trust_sha256": record["verification_trust_sha256"],
        "install_path": record["install_path"],
    }


def _operation_receipt(
    *,
    operation_id: str,
    action: str,
    phase: str,
    status: str,
    started_at: int,
    completed_at: int | None,
    release_id: str | None,
    record: dict[str, Any] | None,
    activation_before: dict[str, Any] | None,
    activation_after: dict[str, Any] | None,
    operator_env_path: Path | None,
    operator_env_sha256: str | None,
    acquired_images: list[str],
    error: dict[str, str] | None,
    host_cosign_version: str | None = None,
    production_deployment: dict[str, Any] | None = None,
    bounded_uninstall: dict[str, Any] | None = None,
) -> dict[str, Any]:
    package = None
    if release_id is not None and record is not None:
        package = _operation_package_binding(release_id, record)
    return {
        "$schema": LIFECYCLE_RECEIPT_SCHEMA_ID,
        "format_version": FORMAT_VERSION,
        "operation_id": operation_id,
        "action": action,
        "phase": phase,
        "status": status,
        "started_at": started_at,
        "completed_at": completed_at,
        "actor_uid": 0,
        "package": package,
        "activation_before": _activation_summary(activation_before),
        "activation_after": _activation_summary(activation_after),
        "operator_environment": (
            None
            if operator_env_path is None
            else {
                "path": str(operator_env_path),
                "sha256": operator_env_sha256,
            }
        ),
        "acquired_images": acquired_images,
        "docker_host": (
            LOCAL_DOCKER_HOST
            if action in {"install", "upgrade", "rollback", "uninstall"}
            else None
        ),
        "database_downgrade_performed": False,
        "host_cosign_version": host_cosign_version,
        "production_deployment": production_deployment,
        "bounded_uninstall": bounded_uninstall,
        "error": error,
    }


def _write_operation(
    paths: LifecyclePaths,
    operation_id: str,
    suffix: str,
    value: dict[str, Any],
) -> None:
    write_exclusive_json(paths.operation_root / f"{operation_id}.{suffix}.json", value)


def _activation_value(
    *,
    operation_id: str,
    active_release_id: str,
    previous_release_id: str | None,
    generation: int,
    production_deployment: dict[str, Any],
) -> dict[str, Any]:
    return {
        "$schema": ACTIVATION_SCHEMA_ID,
        "format_version": FORMAT_VERSION,
        "generation": generation,
        "activated_at": int(time.time()),
        "operation_id": operation_id,
        "active_release_id": active_release_id,
        "previous_release_id": previous_release_id,
        "production_deployment": _validate_production_deployment_binding(
            production_deployment
        ),
    }


def _restore_prior_activation(
    paths: LifecyclePaths,
    activation_before: dict[str, Any] | None,
    attempted_activation: dict[str, Any] | None,
) -> dict[str, Any] | None:
    current = _read_activation(paths)
    if current == activation_before:
        return current
    if attempted_activation is None or current != attempted_activation:
        fail("activation pointer changed unexpectedly during a failed operation")
    if activation_before is None:
        paths.activation.unlink()
        descriptor = os.open(
            paths.activation.parent,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
        )
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    else:
        replace_json(paths.activation, activation_before)
    restored = _read_activation(paths)
    if restored != activation_before:
        fail("failed operation did not preserve the prior activation pointer")
    return restored


def _validate_timeout(timeout_seconds: int) -> int:
    return require_positive_integer(
        timeout_seconds, "deployment timeout", MAX_DEPLOYMENT_TIMEOUT_SECONDS
    )


def _terminal_error(exc: BaseException) -> dict[str, str]:
    if isinstance(exc, CommandError):
        return {
            "type": type(exc).__name__,
            "message": f"{exc.label} failed with exit status {exc.returncode}",
        }
    if isinstance(exc, LifecycleError):
        return {"type": type(exc).__name__, "message": str(exc)[:1024]}
    return {"type": type(exc).__name__, "message": "lifecycle operation aborted"}


def _runtime_invoking_package_root() -> Path:
    module_path = Path(__file__).absolute()
    if module_path.parent.name != "lib":
        fail("rollback and uninstall must run from an installed server package")
    return _absolute_normalized(module_path.parent.parent, "invoking package root")


def _require_current_invoking_package(
    paths: LifecyclePaths,
    activation: dict[str, Any] | None,
    invoking_package_root: Path,
) -> tuple[dict[str, Any], Path, dict[str, Any], bytes]:
    if activation is None:
        fail("operation requires one current active installed release")
    invoking_package_root = _absolute_normalized(
        invoking_package_root, "invoking package root"
    )
    active_record = _read_release_record(paths, activation["active_release_id"])
    active_root, manifest, connector_raw = _manifest_from_installed_record(
        active_record, paths
    )
    if active_root != invoking_package_root:
        fail(
            "rollback and uninstall must execute from the current authenticated "
            "activation-installed package"
        )
    return active_record, active_root, manifest, connector_raw


def _reject_unresolved_deployment_recovery(record_root: Path) -> None:
    deployment_directories = _deployment_directory_snapshot(record_root)
    deployment_lock = record_root / ".deployment.lock"
    if deployment_lock.exists() or deployment_lock.is_symlink():
        fail(
            "uninstall refuses a retained production deployment lock; "
            "complete and attest recovery first"
        )
    for name in sorted(deployment_directories):
        deployment_directory = record_root / name
        status_path = deployment_directory / "status"
        if status_path.exists() or status_path.is_symlink():
            raw_status = secure_read(
                status_path,
                "production deployment terminal status",
                expected_uid=0,
                accepted_modes={0o600},
                maximum=1024,
            )
            try:
                status = raw_status.decode("ascii").removesuffix("\n")
            except UnicodeDecodeError as exc:
                raise LifecycleError(
                    "production deployment terminal status is not ASCII"
                ) from exc
            if not status or "\n" in status or "\r" in status:
                fail("production deployment terminal status is malformed")
            if status.endswith(":lock-retained"):
                fail(
                    "uninstall refuses production deployment evidence with a "
                    "retained recovery lock"
                )
        reverse_path = deployment_directory / "reverse-execution.json"
        if reverse_path.exists() or reverse_path.is_symlink():
            reverse = strict_json(
                secure_read(
                    reverse_path,
                    "production bounded reverse execution",
                    expected_uid=0,
                    accepted_modes={0o400},
                ),
                "production bounded reverse execution",
            )
            if not isinstance(reverse, dict):
                fail("production bounded reverse execution must be an object")
            reverse_status = reverse.get("status")
            if (
                reverse.get("format_version") != FORMAT_VERSION
                or reverse.get("type")
                != "production-bounded-reverse-execution-v1"
                or not isinstance(reverse_status, str)
                or reverse_status not in {"succeeded", "failed"}
            ):
                fail("production bounded reverse execution evidence is unsupported")
            if reverse_status == "failed":
                fail(
                    "uninstall refuses a failed production bounded reverse; "
                    "complete and attest recovery first"
                )


def _authenticate_active_deployment(
    paths: LifecyclePaths,
    activation: dict[str, Any],
    operator: Mapping[str, str],
    active_record: Mapping[str, Any],
) -> Path:
    binding = _validate_production_deployment_binding(
        activation["production_deployment"]
    )
    operation_path = (
        paths.operation_root / f"{activation['operation_id']}.succeeded.json"
    )
    operation = exact_object(
        strict_json(
            secure_read(
                operation_path,
                "active deployment lifecycle succeeded receipt",
                expected_uid=0,
                accepted_modes={0o400},
            ),
            "active deployment lifecycle succeeded receipt",
        ),
        {
            "$schema",
            "format_version",
            "operation_id",
            "action",
            "phase",
            "status",
            "started_at",
            "completed_at",
            "actor_uid",
            "package",
            "activation_before",
            "activation_after",
            "operator_environment",
            "acquired_images",
            "docker_host",
            "database_downgrade_performed",
            "host_cosign_version",
            "production_deployment",
            "bounded_uninstall",
            "error",
        },
        "active deployment lifecycle succeeded receipt",
    )
    if (
        operation["$schema"] != LIFECYCLE_RECEIPT_SCHEMA_ID
        or operation["format_version"] != FORMAT_VERSION
        or operation["operation_id"] != activation["operation_id"]
        or operation["action"] != binding["action"]
        or operation["phase"] != "terminal"
        or operation["status"] != "succeeded"
        or operation["actor_uid"] != 0
        or operation["package"]
        != _operation_package_binding(activation["active_release_id"], active_record)
        or operation["activation_after"] != _activation_summary(activation)
        or operation["docker_host"] != LOCAL_DOCKER_HOST
        or operation["database_downgrade_performed"] is not False
        or operation["production_deployment"] != binding
        or operation["bounded_uninstall"] is not None
        or operation["error"] is not None
    ):
        fail(
            "active lifecycle succeeded receipt does not bind the production deployment"
        )

    record_root = _absolute_normalized(
        Path(
            require_string(
                operator["CONTROL_DEPLOYMENT_RECORD_DIR"],
                "deployment record root",
            )
        ),
        "deployment record root",
    )
    validate_directory(
        record_root,
        "deployment record root",
        expected_uid=0,
        exact_mode=0o700,
    )
    deployment_directory = Path(binding["deployment_directory"])
    if deployment_directory.parent != record_root:
        fail("active deployment binding is outside the fixed production record root")
    validate_directory(
        deployment_directory,
        "active production deployment record",
        expected_uid=0,
        exact_mode=0o700,
    )
    deployment_raw = secure_read(
        Path(binding["deployment_record_path"]),
        "active production deployment terminal",
        expected_uid=0,
        accepted_modes={0o400},
    )
    deployment = strict_json(
        deployment_raw, "active production deployment terminal"
    )
    if (
        hashlib.sha256(deployment_raw).hexdigest()
        != binding["deployment_record_sha256"]
        or not isinstance(deployment, dict)
        or deployment.get("format_version") != FORMAT_VERSION
        or deployment.get("status") != "deployed"
    ):
        fail("active production deployment terminal changed after activation")
    status = secure_read(
        Path(binding["terminal_status_path"]),
        "active production deployment status",
        expected_uid=0,
        accepted_modes={0o600},
        maximum=1024,
    )
    if (
        status != b"deployed\n"
        or hashlib.sha256(status).hexdigest() != binding["terminal_status_sha256"]
    ):
        fail("active production deployment status changed after activation")
    for prohibited in (
        "reverse-execution.json",
        "uninstall-plan.json",
        "uninstall-execution.json",
    ):
        evidence = deployment_directory / prohibited
        if evidence.exists() or evidence.is_symlink():
            fail(
                "active production deployment already has incompatible terminal "
                f"evidence: {prohibited}"
            )
    return deployment_directory


def _validate_bounded_uninstall(
    deployment_directory: Path,
    record_root: Path,
    operation_id: str,
    active_root: Path,
    active_record: Mapping[str, Any],
    active_binding: Mapping[str, Any],
) -> dict[str, Any]:
    if deployment_directory.parent != record_root:
        fail("bounded uninstall evidence is outside the production record root")
    validate_directory(
        deployment_directory,
        "bounded uninstall deployment record",
        expected_uid=0,
        exact_mode=0o700,
    )
    trigger = f"{BOUNDED_UNINSTALL_TRIGGER_PREFIX}{operation_id}"
    plan_path = deployment_directory / "uninstall-plan.json"
    plan_raw = secure_read(
        plan_path,
        "bounded uninstall plan",
        expected_uid=0,
        accepted_modes={0o400},
    )
    plan = exact_object(
        strict_json(plan_raw, "bounded uninstall plan"),
        {
            "format_version",
            "type",
            "status",
            "admitted_at",
            "trigger_stage",
            "deployment_record",
            "active_package",
            "compose_project",
            "targets",
            "limits",
            "one_off_containers_absent",
            "preserved",
        },
        "bounded uninstall plan",
    )
    deployment_record = exact_object(
        plan["deployment_record"],
        {"path", "sha256"},
        "bounded uninstall deployment record binding",
    )
    active_package = exact_object(
        plan["active_package"],
        {
            "manifest_path",
            "manifest_sha256",
            "verification_receipt_path",
            "verification_receipt_sha256",
            "mode",
            "release",
            "release_tag",
        },
        "bounded uninstall active package binding",
    )
    expected_active_package = {
        "manifest_path": str(active_root / PACKAGE_MANIFEST_FILENAME),
        "manifest_sha256": active_record["internal_manifest_sha256"],
        "verification_receipt_path": active_record["verification_receipt_path"],
        "verification_receipt_sha256": active_record[
            "verification_receipt_sha256"
        ],
        "mode": active_record["mode"],
        "release": active_record["release"],
        "release_tag": active_record["release_tag"],
    }
    compose_project = require_string(
        plan["compose_project"], "bounded uninstall Compose project"
    )
    if re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,62}", compose_project) is None:
        fail("bounded uninstall Compose project is invalid")
    if (
        plan["format_version"] != FORMAT_VERSION
        or plan["type"] != "production-bounded-uninstall-plan-v1"
        or plan["status"] != "admitted"
        or plan["trigger_stage"] != trigger
        or deployment_record
        != {
            "path": active_binding["deployment_record_path"],
            "sha256": active_binding["deployment_record_sha256"],
        }
        or active_package != expected_active_package
        or plan["one_off_containers_absent"] is not True
        or plan["preserved"] != UNINSTALL_PRESERVED_RESOURCES
    ):
        fail("bounded uninstall plan does not bind the active deployment")
    require_string(plan["admitted_at"], "bounded uninstall admission time")

    targets = exact_object(
        plan["targets"],
        {"containers", "pwa_network"},
        "bounded uninstall targets",
    )
    containers = exact_object(
        targets["containers"],
        set(UNINSTALL_SERVICES),
        "bounded uninstall container targets",
    )
    observed_container_ids: set[str] = set()
    for service in UNINSTALL_SERVICES:
        target = exact_object(
            containers[service],
            {
                "container_id",
                "container_name",
                "image_id",
                "compose_project",
                "compose_service",
                "compose_oneoff",
                "network",
                "labels",
            },
            f"bounded uninstall {service} target",
        )
        container_id = require_string(
            target["container_id"], f"bounded uninstall {service} container id"
        )
        if (
            SHA256_RE.fullmatch(container_id) is None
            or container_id in observed_container_ids
            or DIGEST_RE.fullmatch(
                require_string(
                    target["image_id"],
                    f"bounded uninstall {service} image id",
                )
            )
            is None
            or target["compose_project"] != compose_project
            or target["compose_service"] != service
            or target["compose_oneoff"] is not False
        ):
            fail(f"bounded uninstall {service} target identity is invalid")
        container_name = require_string(
            target["container_name"],
            f"bounded uninstall {service} container name",
            maximum=256,
        )
        labels = target["labels"]
        if (
            not container_name.startswith("/")
            or not isinstance(labels, dict)
            or not all(
                isinstance(key, str) and isinstance(value, str)
                for key, value in labels.items()
            )
            or labels.get("com.docker.compose.project") != compose_project
            or labels.get("com.docker.compose.service") != service
            or labels.get("com.docker.compose.oneoff") != "False"
            or labels.get("com.docker.compose.container-number") != "1"
            or labels.get("com.docker.compose.project.config_files")
            != str(deployment_directory / "compose-config.json")
        ):
            fail(f"bounded uninstall {service} ownership labels are invalid")
        require_string(
            target["network"], f"bounded uninstall {service} network"
        )
        observed_container_ids.add(container_id)

    pwa_network = exact_object(
        targets["pwa_network"],
        {
            "network_id",
            "name",
            "compose_project",
            "driver",
            "internal",
            "enable_ipv6",
            "options",
            "container_id",
            "compose_network",
            "labels",
            "member_container_ids",
        },
        "bounded uninstall PWA network target",
    )
    expected_network_options = {
        "com.docker.network.bridge.enable_icc": "false",
        "com.docker.network.bridge.enable_ip_masquerade": "false",
    }
    if (
        SHA256_RE.fullmatch(
            require_string(
                pwa_network["network_id"], "bounded uninstall PWA network id"
            )
        )
        is None
        or pwa_network["compose_project"] != compose_project
        or pwa_network["driver"] != "bridge"
        or pwa_network["internal"] is not False
        or pwa_network["enable_ipv6"] is not False
        or pwa_network["options"] != expected_network_options
        or pwa_network["container_id"]
        != containers["codex-pwa"]["container_id"]
        or pwa_network["compose_network"] != "pwa-network"
        or pwa_network["name"] != containers["codex-pwa"]["network"]
        or pwa_network["member_container_ids"]
        != [containers["codex-pwa"]["container_id"]]
    ):
        fail("bounded uninstall PWA network target identity is invalid")
    require_string(pwa_network["name"], "bounded uninstall PWA network name")
    network_labels = pwa_network["labels"]
    if (
        not isinstance(network_labels, dict)
        or not all(
            isinstance(key, str) and isinstance(value, str)
            for key, value in network_labels.items()
        )
        or network_labels.get("com.docker.compose.project") != compose_project
        or network_labels.get("com.docker.compose.network") != "pwa-network"
    ):
        fail("bounded uninstall PWA network ownership labels are invalid")
    limits = exact_object(
        plan["limits"],
        {
            "max_attempts_per_step",
            "total_timeout_seconds",
            "container_stop_timeout_seconds",
            "container_remove_timeout_seconds",
            "network_remove_timeout_seconds",
            "exact_ids_required",
            "drift_fail_closed",
        },
        "bounded uninstall limits",
    )
    if limits != {
        "max_attempts_per_step": 1,
        "total_timeout_seconds": 240,
        "container_stop_timeout_seconds": 30,
        "container_remove_timeout_seconds": 15,
        "network_remove_timeout_seconds": 30,
        "exact_ids_required": True,
        "drift_fail_closed": True,
    }:
        fail("bounded uninstall limits are not the fixed safety contract")

    execution_path = deployment_directory / "uninstall-execution.json"
    execution_raw = secure_read(
        execution_path,
        "bounded uninstall execution",
        expected_uid=0,
        accepted_modes={0o400},
    )
    execution = exact_object(
        strict_json(execution_raw, "bounded uninstall execution"),
        {
            "format_version",
            "type",
            "status",
            "trigger_stage",
            "uninstall_plan_path",
            "uninstall_plan_sha256",
            "deployment_record",
            "active_package",
            "removed",
            "network_empty_evidence",
            "postconditions",
            "preserved",
            "bounded",
            "max_attempts_per_step",
            "completed_at",
        },
        "bounded uninstall execution",
    )
    removed = exact_object(
        execution["removed"],
        {"containers", "pwa_network"},
        "bounded uninstall removed resources",
    )
    expected_removed_containers = [
        {"service": service, **containers[service]}
        for service in UNINSTALL_SERVICES
    ]
    expected_removed_network = {
        "network_id": pwa_network["network_id"],
        "name": pwa_network["name"],
        "labels": network_labels,
        "member_container_ids_at_admission": [
            containers["codex-pwa"]["container_id"]
        ],
        "members_after_container_removal": [],
    }
    network_empty_evidence = exact_object(
        execution["network_empty_evidence"],
        {"path", "sha256"},
        "bounded uninstall empty network evidence binding",
    )
    network_empty_path = deployment_directory / (
        "uninstall-pwa-network-empty-inspect.json"
    )
    network_empty_raw = secure_read(
        network_empty_path,
        "bounded uninstall empty PWA network evidence",
        expected_uid=0,
        accepted_modes={0o600},
    )
    network_empty = strict_json(
        network_empty_raw,
        "bounded uninstall empty PWA network evidence",
        canonical=False,
    )
    if (
        network_empty_evidence
        != {
            "path": str(network_empty_path),
            "sha256": hashlib.sha256(network_empty_raw).hexdigest(),
        }
        or not isinstance(network_empty, list)
        or len(network_empty) != 1
        or not isinstance(network_empty[0], dict)
        or network_empty[0].get("Id") != pwa_network["network_id"]
        or network_empty[0].get("Name") != pwa_network["name"]
        or network_empty[0].get("Labels") != network_labels
        or network_empty[0].get("Containers") != {}
    ):
        fail("bounded uninstall did not prove the exact PWA network was empty")
    postconditions = exact_object(
        execution["postconditions"],
        {
            "project_containers_absent",
            "one_off_containers_absent",
            "pwa_network_zero_members_before_removal",
            "pwa_network_absent",
        },
        "bounded uninstall postconditions",
    )
    plan_sha256 = hashlib.sha256(plan_raw).hexdigest()
    if (
        execution["format_version"] != FORMAT_VERSION
        or execution["type"] != "production-bounded-uninstall-execution-v1"
        or execution["status"] != "succeeded"
        or execution["trigger_stage"] != trigger
        or execution["uninstall_plan_path"] != str(plan_path)
        or execution["uninstall_plan_sha256"] != plan_sha256
        or execution["deployment_record"] != deployment_record
        or execution["active_package"] != active_package
        or removed["containers"] != expected_removed_containers
        or removed["pwa_network"] != expected_removed_network
        or postconditions
        != {
            "project_containers_absent": True,
            "one_off_containers_absent": True,
            "pwa_network_zero_members_before_removal": True,
            "pwa_network_absent": True,
        }
        or execution["preserved"] != UNINSTALL_PRESERVED_RESOURCES
        or execution["bounded"] is not True
        or execution["max_attempts_per_step"] != 1
    ):
        fail("bounded uninstall execution evidence is incomplete")
    require_string(
        execution["completed_at"], "bounded uninstall completion time"
    )

    terminal_status = secure_read(
        deployment_directory / "status",
        "bounded uninstall terminal status",
        expected_uid=0,
        accepted_modes={0o600},
        maximum=1024,
    )
    if terminal_status != f"uninstalled:{trigger}\n".encode("ascii"):
        fail("bounded uninstall has no exact successful terminal status")
    deployment_lock = record_root / ".deployment.lock"
    if deployment_lock.exists() or deployment_lock.is_symlink():
        fail("bounded uninstall retained the production deployment lock")
    return {
        "trigger_stage": trigger,
        "uninstall_plan": {"path": str(plan_path), "sha256": plan_sha256},
        "uninstall_execution": {
            "path": str(execution_path),
            "sha256": hashlib.sha256(execution_raw).hexdigest(),
        },
        "deployment_record": dict(deployment_record),
        "removed": removed,
        "postconditions": postconditions,
        "preserved": dict(UNINSTALL_PRESERVED_RESOURCES),
    }


def _invoke_bounded_uninstall(
    package_root: Path,
    manifest: dict[str, Any],
    connector_raw: bytes,
    operator: Mapping[str, str],
    record: dict[str, Any],
    deployment_directory: Path,
    active_binding: Mapping[str, Any],
    operation_id: str,
) -> dict[str, Any]:
    script = _assert_deployment_contract(package_root, manifest)
    raw = secure_read(
        script,
        "signed production deployment script",
        expected_uid=0,
        accepted_modes={0o555},
        maximum=4 * 1024 * 1024,
    )
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise LifecycleError("signed production deployment script is not UTF-8") from exc
    if (
        BOUNDED_UNINSTALL_CONTRACT_LINE
        not in {line.strip() for line in text.splitlines()}
        or BOUNDED_UNINSTALL_ARGUMENT not in text
    ):
        fail("signed production deployment script has no bounded uninstall interface")
    environment, _ = _deployment_environment(
        operator,
        package_root,
        manifest,
        connector_raw,
        record,
        expected_uid=0,
    )
    shell = _resolve_trusted_executable("sh", expected_uid=0)
    _run_bounded(
        [
            shell,
            str(script),
            BOUNDED_UNINSTALL_ARGUMENT,
            str(deployment_directory),
            f"{BOUNDED_UNINSTALL_TRIGGER_PREFIX}{operation_id}",
        ],
        env=environment,
        cwd=package_root / "source",
        timeout_seconds=MAX_BOUNDED_UNINSTALL_TIMEOUT_SECONDS,
        label="signed production bounded uninstall",
    )
    return _validate_bounded_uninstall(
        deployment_directory,
        Path(operator["CONTROL_DEPLOYMENT_RECORD_DIR"]),
        operation_id,
        package_root,
        record,
        active_binding,
    )


def _production_deployment_lock_retained(
    deployment_state: Mapping[str, Any],
) -> bool:
    record_root = deployment_state.get("record_root")
    if not isinstance(record_root, Path):
        return False
    deployment_lock = record_root / ".deployment.lock"
    return deployment_lock.exists() or deployment_lock.is_symlink()


def _settle_failed_mutation(
    *,
    exc: BaseException,
    lease: LifecycleLockLease,
    paths: LifecyclePaths,
    package_root: Path,
    manifest: dict[str, Any],
    connector_raw: bytes,
    operator: Mapping[str, str],
    record: dict[str, Any],
    operation_id: str,
    activation_before: dict[str, Any] | None,
    activation_after: dict[str, Any] | None,
    deployment_state: Mapping[str, Any],
) -> tuple[dict[str, Any] | None, dict[str, str], bool]:
    terminal_error = _terminal_error(exc)
    safety_error: dict[str, str] | None = None
    succeeded_receipt_ambiguous = False
    if deployment_state.get("completed") is True:
        try:
            _invoke_post_success_reverse(
                package_root,
                manifest,
                connector_raw,
                operator,
                record,
                deployment_state,
                operation_id,
            )
        except BaseException as reverse_exc:
            reverse_error = _terminal_error(reverse_exc)
            safety_error = {
                "type": "PostDeploymentReverseError",
                "message": (
                    f"{terminal_error['message']}; signed post-success bounded "
                    f"reverse failed: {reverse_error['message']}; lifecycle lock retained"
                )[:1024],
            }
        succeeded_path = paths.operation_root / f"{operation_id}.succeeded.json"
        succeeded_receipt_ambiguous = (
            succeeded_path.exists() or succeeded_path.is_symlink()
        )
    elif _production_deployment_lock_retained(deployment_state):
        safety_error = {
            "type": "ProductionRecoveryLockRetained",
            "message": (
                f"{terminal_error['message']}; signed deployment recovery retained "
                "its production lock; lifecycle lock retained"
            )[:1024],
        }
    if safety_error is not None:
        lease.retain_for_review()
        return None, safety_error, True
    try:
        observed_activation = _restore_prior_activation(
            paths, activation_before, activation_after
        )
    except BaseException as restore_exc:
        restore_error = _terminal_error(restore_exc)
        lease.retain_for_review()
        safety_error = {
            "type": "ActivationRestoreError",
            "message": (
                f"{terminal_error['message']}; prior activation restoration failed: "
                f"{restore_error['message']}; lifecycle lock retained"
            )[:1024],
        }
        return None, safety_error, True
    if succeeded_receipt_ambiguous:
        lease.retain_for_review()
        safety_error = {
            "type": "SucceededReceiptAmbiguity",
            "message": (
                f"{terminal_error['message']}; a succeeded receipt may have been "
                "created before its commit failed; bounded reverse completed and "
                "the prior activation was restored, but the lifecycle lock is retained"
            )[:1024],
        }
        return observed_activation, safety_error, True
    return observed_activation, terminal_error, False


def _write_failed_operation_or_retain(
    paths: LifecyclePaths,
    lease: LifecycleLockLease,
    operation_id: str,
    failed: dict[str, Any],
    exc: BaseException,
) -> None:
    try:
        _write_operation(paths, operation_id, "failed", failed)
    except BaseException as write_exc:
        lease.retain_for_review()
        write_error = _terminal_error(write_exc)
        raise LifecycleError(
            "lifecycle terminal failure receipt could not be written; "
            f"lifecycle lock retained: {write_error['message']}"
        ) from exc


def _install_or_upgrade(
    action: str,
    *,
    package_root: Path,
    verification_receipt: Path,
    operator_env_file: Path,
    paths: LifecyclePaths,
    timeout_seconds: int,
) -> dict[str, Any]:
    manifest, receipt, connector_raw = validate_verified_package(
        package_root, verification_receipt
    )
    operator, operator_sha256 = parse_operator_env(operator_env_file)
    receipt_sha256 = sha256_file(verification_receipt)
    _prepare_roots(paths)
    operation_id = _operation_id(action)
    started_at = int(time.time())
    with lifecycle_lock(paths, operation_id) as lease:
        activation_before = _read_activation(paths)
        if action == "install" and activation_before is not None:
            fail("install requires no active release; use upgrade")
        if action == "upgrade" and activation_before is None:
            fail("upgrade requires an active release; use install")
        release_id, installed_root, candidate_record = _candidate_operation_record(
            paths,
            manifest,
            receipt,
            connector_raw,
            receipt_sha256,
        )
        if (
            activation_before is not None
            and activation_before["active_release_id"] == release_id
        ):
            fail("requested package is already active")
        started = _operation_receipt(
            operation_id=operation_id,
            action=action,
            phase="started",
            status="in-progress",
            started_at=started_at,
            completed_at=None,
            release_id=release_id,
            record=candidate_record,
            activation_before=activation_before,
            activation_after=None,
            operator_env_path=operator_env_file,
            operator_env_sha256=operator_sha256,
            acquired_images=[],
            error=None,
        )
        _write_operation(paths, operation_id, "started", started)
        acquired: list[str] = []
        host_cosign_version: str | None = None
        activation_after: dict[str, Any] | None = None
        deployment_state: dict[str, Any] = {}
        production_deployment: dict[str, Any] | None = None
        record = candidate_record
        try:
            (
                observed_release_id,
                observed_installed_root,
                observed_record,
            ) = _ensure_installed(
                paths,
                package_root,
                manifest,
                receipt,
                connector_raw,
                receipt_sha256,
            )
            if (
                observed_release_id != release_id
                or observed_installed_root != installed_root
                or _operation_package_binding(observed_release_id, observed_record)
                != _operation_package_binding(release_id, candidate_record)
            ):
                fail("installed package differs from the recorded lifecycle intent")
            record = observed_record
            _assert_deployment_contract(installed_root, manifest)
            docker = _resolve_trusted_executable("docker", expected_uid=0)
            acquired = acquire_images(
                installed_root,
                manifest,
                env=_fixed_environment(),
                docker=docker,
                timeout_seconds=timeout_seconds,
            )
            host_cosign_version = _invoke_deployment(
                installed_root,
                manifest,
                connector_raw,
                operator,
                record,
                timeout_seconds=timeout_seconds,
                deployment_state=deployment_state,
            )
            production_deployment = _completed_deployment_binding(
                deployment_state, operation_id, action
            )
            previous = (
                activation_before["active_release_id"]
                if activation_before is not None
                else None
            )
            activation_after = _activation_value(
                operation_id=operation_id,
                active_release_id=release_id,
                previous_release_id=previous,
                generation=(activation_before["generation"] + 1)
                if activation_before is not None
                else 1,
                production_deployment=production_deployment,
            )
            replace_json(paths.activation, activation_after)
            terminal = _operation_receipt(
                operation_id=operation_id,
                action=action,
                phase="terminal",
                status="succeeded",
                started_at=started_at,
                completed_at=int(time.time()),
                release_id=release_id,
                record=record,
                activation_before=activation_before,
                activation_after=activation_after,
                operator_env_path=operator_env_file,
                operator_env_sha256=operator_sha256,
                acquired_images=acquired,
                error=None,
                host_cosign_version=host_cosign_version,
                production_deployment=production_deployment,
            )
            _write_operation(paths, operation_id, "succeeded", terminal)
            return terminal
        except BaseException as exc:
            observed_activation, terminal_error, safety_failure = (
                _settle_failed_mutation(
                    exc=exc,
                    lease=lease,
                    paths=paths,
                    package_root=installed_root,
                    manifest=manifest,
                    connector_raw=connector_raw,
                    operator=operator,
                    record=record,
                    operation_id=operation_id,
                    activation_before=activation_before,
                    activation_after=activation_after,
                    deployment_state=deployment_state,
                )
            )
            failed = _operation_receipt(
                operation_id=operation_id,
                action=action,
                phase="terminal",
                status="failed",
                started_at=started_at,
                completed_at=int(time.time()),
                release_id=release_id,
                record=record,
                activation_before=activation_before,
                activation_after=observed_activation,
                operator_env_path=operator_env_file,
                operator_env_sha256=operator_sha256,
                acquired_images=acquired,
                error=terminal_error,
                host_cosign_version=host_cosign_version,
            )
            _write_failed_operation_or_retain(
                paths, lease, operation_id, failed, exc
            )
            if safety_failure:
                raise LifecycleError(terminal_error["message"]) from exc
            raise


def _rollback(
    *,
    operator_env_file: Path,
    invoking_package_root: Path,
    paths: LifecyclePaths,
    timeout_seconds: int,
) -> dict[str, Any]:
    operator, operator_sha256 = parse_operator_env(operator_env_file)
    _prepare_roots(paths)
    operation_id = _operation_id("rollback")
    started_at = int(time.time())
    with lifecycle_lock(paths, operation_id) as lease:
        activation_before = _read_activation(paths)
        _require_current_invoking_package(
            paths, activation_before, invoking_package_root
        )
        if activation_before is None or activation_before["previous_release_id"] is None:
            fail("rollback requires one recorded previous active release")
        release_id = activation_before["previous_release_id"]
        record = _read_release_record(paths, release_id)
        package_root, manifest, connector_raw = _manifest_from_installed_record(
            record, paths
        )
        started = _operation_receipt(
            operation_id=operation_id,
            action="rollback",
            phase="started",
            status="in-progress",
            started_at=started_at,
            completed_at=None,
            release_id=release_id,
            record=record,
            activation_before=activation_before,
            activation_after=None,
            operator_env_path=operator_env_file,
            operator_env_sha256=operator_sha256,
            acquired_images=[],
            error=None,
        )
        _write_operation(paths, operation_id, "started", started)
        acquired: list[str] = []
        host_cosign_version: str | None = None
        activation_after: dict[str, Any] | None = None
        deployment_state: dict[str, Any] = {}
        production_deployment: dict[str, Any] | None = None
        try:
            _assert_deployment_contract(package_root, manifest)
            docker = _resolve_trusted_executable("docker", expected_uid=0)
            acquired = acquire_images(
                package_root,
                manifest,
                env=_fixed_environment(),
                docker=docker,
                timeout_seconds=timeout_seconds,
            )
            host_cosign_version = _invoke_deployment(
                package_root,
                manifest,
                connector_raw,
                operator,
                record,
                timeout_seconds=timeout_seconds,
                deployment_state=deployment_state,
            )
            production_deployment = _completed_deployment_binding(
                deployment_state, operation_id, "rollback"
            )
            activation_after = _activation_value(
                operation_id=operation_id,
                active_release_id=release_id,
                previous_release_id=activation_before["active_release_id"],
                generation=activation_before["generation"] + 1,
                production_deployment=production_deployment,
            )
            replace_json(paths.activation, activation_after)
            terminal = _operation_receipt(
                operation_id=operation_id,
                action="rollback",
                phase="terminal",
                status="succeeded",
                started_at=started_at,
                completed_at=int(time.time()),
                release_id=release_id,
                record=record,
                activation_before=activation_before,
                activation_after=activation_after,
                operator_env_path=operator_env_file,
                operator_env_sha256=operator_sha256,
                acquired_images=acquired,
                error=None,
                host_cosign_version=host_cosign_version,
                production_deployment=production_deployment,
            )
            _write_operation(paths, operation_id, "succeeded", terminal)
            return terminal
        except BaseException as exc:
            observed_activation, terminal_error, safety_failure = (
                _settle_failed_mutation(
                    exc=exc,
                    lease=lease,
                    paths=paths,
                    package_root=package_root,
                    manifest=manifest,
                    connector_raw=connector_raw,
                    operator=operator,
                    record=record,
                    operation_id=operation_id,
                    activation_before=activation_before,
                    activation_after=activation_after,
                    deployment_state=deployment_state,
                )
            )
            failed = _operation_receipt(
                operation_id=operation_id,
                action="rollback",
                phase="terminal",
                status="failed",
                started_at=started_at,
                completed_at=int(time.time()),
                release_id=release_id,
                record=record,
                activation_before=activation_before,
                activation_after=observed_activation,
                operator_env_path=operator_env_file,
                operator_env_sha256=operator_sha256,
                acquired_images=acquired,
                error=terminal_error,
                host_cosign_version=host_cosign_version,
            )
            _write_failed_operation_or_retain(
                paths, lease, operation_id, failed, exc
            )
            if safety_failure:
                raise LifecycleError(terminal_error["message"]) from exc
            raise


def _verify_read_only(
    *, package_root: Path, verification_receipt: Path
) -> dict[str, Any]:
    manifest, receipt, connector_raw = validate_verified_package(
        package_root, verification_receipt
    )
    return {
        "$schema": LIFECYCLE_RECEIPT_SCHEMA_ID,
        "format_version": FORMAT_VERSION,
        "action": "verify",
        "status": "verified",
        "read_only": True,
        "release": manifest["release"],
        "release_tag": manifest["release_tag"],
        "mode": manifest["mode"],
        "platform": PLATFORM,
        "archive_sha256": receipt["package"]["sha256"],
        "internal_manifest_sha256": receipt["package"]["internal_manifest_sha256"],
        "connector_metadata_sha256": hashlib.sha256(connector_raw).hexdigest(),
        "package_root": str(package_root),
    }


def _uninstall(
    *,
    operator_env_file: Path,
    invoking_package_root: Path,
    paths: LifecyclePaths,
) -> dict[str, Any]:
    operator, operator_sha256 = parse_operator_env(operator_env_file)
    _prepare_roots(paths)
    operation_id = _operation_id("uninstall")
    started_at = int(time.time())
    with lifecycle_lock(paths, operation_id) as lease:
        try:
            activation_before = _read_activation(paths)
        except BaseException as exc:
            lease.retain_for_review()
            error = _terminal_error(exc)
            raise LifecycleError(
                "uninstall cannot authenticate the active deployment binding; "
                f"lifecycle lock retained: {error['message']}"
            ) from exc
        (
            active_record,
            active_root,
            active_manifest,
            active_connector_raw,
        ) = _require_current_invoking_package(
            paths, activation_before, invoking_package_root
        )
        if activation_before is None:
            fail("uninstall requires one current active installed release")
        active_release_id = activation_before["active_release_id"]
        active_binding = activation_before["production_deployment"]
        started = _operation_receipt(
            operation_id=operation_id,
            action="uninstall",
            phase="started",
            status="in-progress",
            started_at=started_at,
            completed_at=None,
            release_id=active_release_id,
            record=active_record,
            activation_before=activation_before,
            activation_after=None,
            operator_env_path=operator_env_file,
            operator_env_sha256=operator_sha256,
            acquired_images=[],
            error=None,
            production_deployment=active_binding,
        )
        _write_operation(paths, operation_id, "started", started)
        bounded_uninstall: dict[str, Any] | None = None
        try:
            record_root = Path(operator["CONTROL_DEPLOYMENT_RECORD_DIR"])
            _reject_unresolved_deployment_recovery(record_root)
            deployment_directory = _authenticate_active_deployment(
                paths,
                activation_before,
                operator,
                active_record,
            )
            release_plans: list[tuple[Path, dict[str, Any]]] = []
            for entry in sorted(
                paths.install_root.iterdir(), key=lambda item: item.name
            ):
                if entry.name.startswith(".staging-"):
                    fail(f"stale package staging directory requires review: {entry}")
                release_id = _validate_release_id(entry.name)
                record = _read_release_record(paths, release_id)
                root, manifest, _ = _manifest_from_installed_record(record, paths)
                if root != entry:
                    fail("installed release directory and record differ")
                release_plans.append((root, manifest))
            bounded_uninstall = _invoke_bounded_uninstall(
                active_root,
                active_manifest,
                active_connector_raw,
                operator,
                active_record,
                deployment_directory,
                active_binding,
                operation_id,
            )
            if paths.activation.exists() or paths.activation.is_symlink():
                paths.activation.unlink()
                descriptor = os.open(
                    paths.activation.parent,
                    os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
                )
                try:
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
            for root, manifest in release_plans:
                _remove_validated_package(root, manifest)
            terminal = _operation_receipt(
                operation_id=operation_id,
                action="uninstall",
                phase="terminal",
                status="succeeded",
                started_at=started_at,
                completed_at=int(time.time()),
                release_id=active_release_id,
                record=active_record,
                activation_before=activation_before,
                activation_after=None,
                operator_env_path=operator_env_file,
                operator_env_sha256=operator_sha256,
                acquired_images=[],
                error=None,
                production_deployment=active_binding,
                bounded_uninstall=bounded_uninstall,
            )
            _write_operation(paths, operation_id, "succeeded", terminal)
            return terminal
        except BaseException as exc:
            lease.retain_for_review()
            try:
                activation_after = _read_activation(paths)
            except BaseException:
                activation_after = None
            terminal_error = _terminal_error(exc)
            failed = _operation_receipt(
                operation_id=operation_id,
                action="uninstall",
                phase="terminal",
                status="failed",
                started_at=started_at,
                completed_at=int(time.time()),
                release_id=active_release_id,
                record=active_record,
                activation_before=activation_before,
                activation_after=activation_after,
                operator_env_path=operator_env_file,
                operator_env_sha256=operator_sha256,
                acquired_images=[],
                error=terminal_error,
                production_deployment=active_binding,
                bounded_uninstall=bounded_uninstall,
            )
            _write_failed_operation_or_retain(
                paths, lease, operation_id, failed, exc
            )
            raise LifecycleError(
                f"{terminal_error['message']}; lifecycle lock retained"
            ) from exc


def run_lifecycle(
    action: str,
    *,
    package_root: Path | None = None,
    verification_receipt: Path | None = None,
    operator_env_file: Path | None = None,
    invoking_package_root: Path | None = None,
    paths: LifecyclePaths = DEFAULT_PATHS,
    timeout_seconds: int = DEFAULT_DEPLOYMENT_TIMEOUT_SECONDS,
    enforce_preflight: bool = True,
) -> dict[str, Any]:
    if action not in {"install", "upgrade", "verify", "rollback", "uninstall"}:
        fail(f"unsupported lifecycle action: {action}")
    if enforce_preflight:
        preflight_platform()
    timeout_seconds = _validate_timeout(timeout_seconds)
    if action in {"install", "upgrade"}:
        if package_root is None or verification_receipt is None or operator_env_file is None:
            fail(f"{action} requires package root, verification receipt, and operator env")
        if invoking_package_root is not None:
            fail(f"{action} does not accept an invoking package root")
        return _install_or_upgrade(
            action,
            package_root=package_root,
            verification_receipt=verification_receipt,
            operator_env_file=operator_env_file,
            paths=paths,
            timeout_seconds=timeout_seconds,
        )
    if action == "verify":
        if package_root is None or verification_receipt is None:
            fail("verify requires package root and verification receipt")
        if operator_env_file is not None or invoking_package_root is not None:
            fail(
                "verify is read-only and does not accept operator environment "
                "or invoking package input"
            )
        return _verify_read_only(
            package_root=package_root, verification_receipt=verification_receipt
        )
    if action == "rollback":
        if package_root is not None or verification_receipt is not None:
            fail("rollback selects only the recorded previous release")
        if operator_env_file is None:
            fail("rollback requires operator environment input")
        if invoking_package_root is None:
            fail("rollback requires its current installed invoking package identity")
        return _rollback(
            operator_env_file=operator_env_file,
            invoking_package_root=invoking_package_root,
            paths=paths,
            timeout_seconds=timeout_seconds,
        )
    if package_root is not None or verification_receipt is not None:
        fail("uninstall does not accept package or verification receipt inputs")
    if operator_env_file is None:
        fail("uninstall requires operator environment input")
    if invoking_package_root is None:
        fail("uninstall requires its current installed invoking package identity")
    return _uninstall(
        operator_env_file=operator_env_file,
        invoking_package_root=invoking_package_root,
        paths=paths,
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Operate an independently verified Control server package"
    )
    subparsers = parser.add_subparsers(dest="action", required=True)
    for action in ("install", "upgrade"):
        command = subparsers.add_parser(action)
        command.add_argument("--package-root", required=True)
        command.add_argument("--verification-receipt", required=True)
        command.add_argument("--operator-env-file", required=True)
        command.add_argument(
            "--deployment-timeout-seconds",
            type=int,
            default=DEFAULT_DEPLOYMENT_TIMEOUT_SECONDS,
        )
    verify = subparsers.add_parser("verify")
    verify.add_argument("--package-root", required=True)
    verify.add_argument("--verification-receipt", required=True)
    rollback = subparsers.add_parser("rollback")
    rollback.add_argument("--operator-env-file", required=True)
    rollback.add_argument(
        "--deployment-timeout-seconds",
        type=int,
        default=DEFAULT_DEPLOYMENT_TIMEOUT_SECONDS,
    )
    uninstall = subparsers.add_parser("uninstall")
    uninstall.add_argument("--operator-env-file", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        result = run_lifecycle(
            args.action,
            package_root=Path(os.path.abspath(args.package_root))
            if hasattr(args, "package_root")
            else None,
            verification_receipt=Path(os.path.abspath(args.verification_receipt))
            if hasattr(args, "verification_receipt")
            else None,
            operator_env_file=Path(os.path.abspath(args.operator_env_file))
            if hasattr(args, "operator_env_file")
            else None,
            invoking_package_root=(
                _runtime_invoking_package_root()
                if args.action in {"rollback", "uninstall"}
                else None
            ),
            timeout_seconds=getattr(
                args,
                "deployment_timeout_seconds",
                DEFAULT_DEPLOYMENT_TIMEOUT_SECONDS,
            ),
        )
    except (LifecycleError, OSError) as exc:
        print(f"lifecycle: {exc}", file=sys.stderr)
        return 2
    sys.stdout.buffer.write(canonical_json(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
