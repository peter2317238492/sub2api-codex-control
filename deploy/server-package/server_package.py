#!/usr/bin/env python3
"""Build, authenticate, extract, and operate Control server packages."""

from __future__ import annotations

import sys

if __name__ == "__main__" and (
    sys.version_info < (3, 11)
    or not sys.flags.isolated
    or not getattr(sys.flags, "safe_path", False)
):
    print(
        "server_package: Python 3.11+ isolated mode is required; "
        "run with /usr/bin/python3 -I",
        file=sys.stderr,
    )
    raise SystemExit(2)

# The verifier and lifecycle import trusted tools from verified package
# trees whose inventories are exact; never let the interpreter write
# bytecode caches into them, regardless of the operator's environment.
sys.dont_write_bytecode = True

import argparse
import base64
import binascii
import contextlib
import datetime as dt
import gzip
import hashlib
import importlib.util
import io
import json
import os
import platform
import re
import stat
import subprocess
import tarfile
import tempfile
import time
import uuid
import zlib
from collections.abc import Iterable, Iterator, Sequence
from pathlib import Path, PurePosixPath
from typing import Any, BinaryIO, NoReturn

SCHEMA_ID = "https://sub2api-codex.invalid/schemas/server-packages-v1.json"
PACKAGE_SCHEMA_ID = (
    "https://sub2api-codex.invalid/schemas/server-package-inventory-v1.json"
)
RECEIPT_SCHEMA_ID = (
    "https://sub2api-codex.invalid/schemas/server-package-verification-v1.json"
)
LIFECYCLE_SCHEMA_ID = (
    "https://sub2api-codex.invalid/schemas/server-package-lifecycle-v1.json"
)
FORMAT_VERSION = 1
MANIFEST_KIND = "server-packages-manifest-v1"
PLATFORM = "linux/amd64"
MODES = ("online", "offline")
TARGET_IDS = {
    "online": "server-online-linux-amd64",
    "offline": "server-offline-linux-amd64",
}
COMPONENTS = ("control-api", "pwa", "postgres-tools")
MANIFEST_FILENAME = "server-packages.manifest.json"
CHECKSUMS_FILENAME = "server-packages.sha256"
PACKAGE_MANIFEST_FILENAME = "PACKAGE.json"
PACKAGE_PREFIX = "sub2api-codex-control-server"
SIGNATURE_SUFFIX = ".sigstore.json"
SPDX_SUFFIX = ".spdx.json"
PROVENANCE_SUFFIX = ".provenance.json"
CONNECTOR_PROVENANCE_SUFFIX = ".intoto.json"
ATTESTATION_SUFFIX = ".intoto.sigstore.json"
SLSA_PREDICATE_TYPE = "https://slsa.dev/provenance/v1"
SPDX_FORMAT = "SPDX-2.3-json"
BUILD_TYPE = "https://sub2api-codex.invalid/build-types/server-package/v1"
MAX_JSON_BYTES = 32 * 1024 * 1024
MAX_PACKAGE_BYTES = 16 * 1024 * 1024 * 1024
MAX_PACKAGE_FILES = 30_000
MAX_PACKAGE_EXPANDED_BYTES = 32 * 1024 * 1024 * 1024
MAX_MEMBER_BYTES = 9 * 1024 * 1024 * 1024
GITHUB_ASSET_LIMIT_BYTES = 2 * 1024 * 1024 * 1024
PACKAGE_PART_BYTES = 1900 * 1024 * 1024
MAX_PACKAGE_PARTS = (MAX_PACKAGE_BYTES + PACKAGE_PART_BYTES - 1) // PACKAGE_PART_BYTES
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
VERSION_RE = re.compile(
    r"^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
    r"(?:-[0-9A-Za-z.-]+)?$"
)
PORTABLE_PATH_RE = re.compile(r"^[A-Za-z0-9._+@/-]+$")
ENV_NAME_RE = re.compile(r"^[A-Z][A-Z0-9_]*$")
FORBIDDEN_RAW_SECRET_NAMES = {
    "SUB2API_ACCESS_TOKEN",
    "SUB2API_AUTH_EVIDENCE_FILE",
    "CONTROL_DB_PASSWORD",
    "CONTROL_REDIS_PASSWORD",
    "SUB2API_POSTGRES_PASSWORD",
    "SUB2API_REDIS_PASSWORD",
}
# Assembled at runtime so this file's own packaged copy (and the source
# archive embedding it) never contains a contiguous marker for the
# private-key scan to flag.
SECRET_MARKERS = tuple(
    b"-----" + b"BEGIN " + kind + b" KEY" + b"-----"
    for kind in (b"PRIVATE", b"RSA PRIVATE", b"OPENSSH PRIVATE")
)
REQUIRED_LIFECYCLE = {
    "install": "bin/sub2api-control-install",
    "upgrade": "bin/sub2api-control-upgrade",
    "verify": "bin/sub2api-control-verify",
    "rollback": "bin/sub2api-control-rollback",
    "uninstall": "bin/sub2api-control-uninstall",
}
CONNECTOR_METADATA_FILENAME = "connector-release-metadata.json"
CONNECTOR_METADATA_BUNDLE_FILENAME = (
    f"{CONNECTOR_METADATA_FILENAME}{SIGNATURE_SUFFIX}"
)
CONNECTOR_AGGREGATE_FILENAME = "connector-public-verification-aggregate.json"
CONNECTOR_AGGREGATE_BUNDLE_FILENAME = (
    f"{CONNECTOR_AGGREGATE_FILENAME}{SIGNATURE_SUFFIX}"
)
OCI_EXPORT_RECEIPT_FILENAME = "oci-export-receipt.json"
CONSUMER_VERIFIER_FILENAME = "server-package-verify.py"
OCI_MANIFEST_MEDIA_TYPES = {
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
}
CONTROL_EVIDENCE_FILENAMES = {
    "control-images.lock.json",
    "control-images.lock.sigstore.json",
    "source.tar",
    "source-files.manifest",
    "source-attestation.json",
    *(f"{component}.{suffix}.json" for component in COMPONENTS for suffix in ("spdx", "provenance")),
}

MODULE_PATH = Path(__file__).resolve()
MODULE_DIR = MODULE_PATH.parent
if MODULE_DIR.name == "lib" and (MODULE_DIR.parent / PACKAGE_MANIFEST_FILENAME).is_file():
    PACKAGE_RUNTIME_ROOT: Path | None = MODULE_DIR.parent
    REPO_ROOT = PACKAGE_RUNTIME_ROOT / "source"
else:
    PACKAGE_RUNTIME_ROOT = None
    REPO_ROOT = MODULE_PATH.parents[2]
CONTROL_RELEASE_DIR = REPO_ROOT / "deploy/release"
CONTROL_IMAGES_PATH = CONTROL_RELEASE_DIR / "control_images.py"
SOURCE_BUNDLE_PATH = CONTROL_RELEASE_DIR / "source_bundle.py"
OCI_MAPPER_PATH = REPO_ROOT / "deploy/scripts/map-oci-image-archive.py"
CONNECTOR_RELEASE_TOOL_PATH = REPO_ROOT / "connector/release/release.py"


class ServerPackageError(RuntimeError):
    pass


def fail(message: str) -> NoReturn:
    raise ServerPackageError(message)


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


def connector_canonical_json(value: Any) -> bytes:
    """The byte form written by connector/release/release.py's canonical writer."""
    return (
        json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            indent=2,
            separators=(",", ": "),
        ).encode("ascii")
        + b"\n"
    )


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            fail(f"JSON object repeats key {key!r}")
        value[key] = item
    return value


def strict_json(raw: bytes, label: str, *, canonical: bool = False) -> Any:
    if len(raw) <= 0 or len(raw) > MAX_JSON_BYTES:
        fail(f"{label} size is outside the accepted range")
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=reject_duplicate_keys,
            parse_constant=lambda token: fail(
                f"{label} contains non-finite JSON number {token}"
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ServerPackageError(f"{label} is not valid JSON") from exc
    if canonical and canonical_json(value) != raw:
        fail(f"{label} is not canonical JSON")
    return value


def require_exact_keys(value: Any, expected: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        fail(f"{label} must be an object")
    if set(value) != expected:
        fail(
            f"{label} keys mismatch; missing={sorted(expected - set(value))}, "
            f"extra={sorted(set(value) - expected)}"
        )
    return value


def require_string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value or "\n" in value or "\r" in value:
        fail(f"{label} must be one non-empty string")
    return value


def require_sha256(value: Any, label: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        fail(f"{label} must be one lowercase SHA-256")
    return value


def require_size(value: Any, label: str, maximum: int = MAX_PACKAGE_BYTES) -> int:
    if type(value) is not int or not 0 < value <= maximum:
        fail(f"{label} size is outside the accepted range")
    return value


def validate_release(value: Any) -> str:
    release = require_string(value, "release")
    if VERSION_RE.fullmatch(release) is None:
        fail("release is not a supported semantic version")
    return release


def validate_tool_version(value: Any, label: str) -> str:
    version = require_string(value, label)
    if re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", version) is None:
        fail(f"{label} is invalid")
    return version


def validate_repository(value: Any) -> str:
    repository = require_string(value, "source repository")
    if re.fullmatch(
        r"https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository
    ) is None:
        fail("source repository is not one canonical HTTPS GitHub repository")
    return repository


def validate_commit(value: Any) -> str:
    commit = require_string(value, "source commit")
    if COMMIT_RE.fullmatch(commit) is None:
        fail("source commit must be 40 lowercase hexadecimal characters")
    return commit


def validate_portable_path(value: Any, label: str = "package path") -> str:
    path_value = require_string(value, label)
    if (
        not path_value.isascii()
        or PORTABLE_PATH_RE.fullmatch(path_value) is None
        or "\\" in path_value
    ):
        fail(f"{label} is not portable ASCII")
    path = PurePosixPath(path_value)
    if (
        path.is_absolute()
        or path.as_posix() != path_value
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        fail(f"{label} is not canonical and relative")
    return path_value


def sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def sha256_stream(source: BinaryIO) -> str:
    digest = hashlib.sha256()
    while block := source.read(1024 * 1024):
        digest.update(block)
    return digest.hexdigest()


def sha256_file(path: Path) -> str:
    with path.open("rb") as source:
        return sha256_stream(source)


def sha1_file(path: Path) -> str:
    digest = hashlib.sha1(usedforsecurity=False)
    with path.open("rb") as source:
        while block := source.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def iso8601(epoch: int) -> str:
    return dt.datetime.fromtimestamp(epoch, tz=dt.timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )


def stable_fields(metadata: os.stat_result) -> tuple[int, ...]:
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


def require_owned_directory(path: Path, label: str, *, root: bool = False) -> None:
    expected_uid = 0 if root else os.geteuid()
    absolute = path.absolute()
    current = absolute.parent
    while True:
        try:
            ancestor = current.lstat()
        except OSError as exc:
            raise ServerPackageError(
                f"cannot inspect {label} ancestor: {current}"
            ) from exc
        if (
            not stat.S_ISDIR(ancestor.st_mode)
            or ancestor.st_uid not in {0, expected_uid}
            or stat.S_IMODE(ancestor.st_mode) & 0o022
        ):
            fail(f"{label} has an unsafe path ancestor: {current}")
        if current == current.parent:
            break
        current = current.parent
    try:
        metadata = absolute.lstat()
    except OSError as exc:
        raise ServerPackageError(f"cannot inspect {label}: {path}") from exc
    if not stat.S_ISDIR(metadata.st_mode):
        fail(f"{label} must be one real directory")
    if metadata.st_uid != expected_uid:
        fail(f"{label} must be owned by uid {expected_uid}")
    if stat.S_IMODE(metadata.st_mode) & 0o022:
        fail(f"{label} must not be group or world writable")


def open_regular(
    path: Path,
    label: str,
    *,
    maximum: int = MAX_PACKAGE_BYTES,
    expected_uid: int | None = None,
) -> tuple[BinaryIO, os.stat_result]:
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:
        fail("this platform cannot open files without following symlinks")
    try:
        descriptor = os.open(
            path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | nofollow
        )
    except OSError as exc:
        raise ServerPackageError(f"cannot securely open {label}: {path}") from exc
    try:
        metadata = os.fstat(descriptor)
        uid = os.geteuid() if expected_uid is None else expected_uid
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            fail(f"{label} must be one regular singly-linked file")
        if metadata.st_uid != uid:
            fail(f"{label} must be owned by uid {uid}")
        if stat.S_IMODE(metadata.st_mode) & 0o022:
            fail(f"{label} must not be group or world writable")
        if metadata.st_size <= 0 or metadata.st_size > maximum:
            fail(f"{label} size is outside the accepted range")
        return os.fdopen(descriptor, "rb"), metadata
    except BaseException:
        os.close(descriptor)
        raise


def read_regular(
    path: Path,
    label: str,
    *,
    maximum: int = MAX_JSON_BYTES,
    expected_uid: int | None = None,
) -> bytes:
    source, before = open_regular(
        path, label, maximum=maximum, expected_uid=expected_uid
    )
    try:
        raw = source.read(maximum + 1)
        after = os.fstat(source.fileno())
        if len(raw) != before.st_size or len(raw) > maximum:
            fail(f"{label} changed size while read")
        if stable_fields(before) != stable_fields(after):
            fail(f"{label} changed while read")
        return raw
    finally:
        source.close()


def atomic_write(path: Path, content: bytes, mode: int = 0o644) -> None:
    if path.exists() or path.is_symlink():
        fail(f"refusing to overwrite existing output {path.name}")
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as destination:
            destination.write(content)
            destination.flush()
            os.fsync(destination.fileno())
        os.chmod(temporary, mode)
        os.link(temporary, path, follow_symlinks=False)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def import_tool(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        fail(f"cannot load trusted tool {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@contextlib.contextmanager
def package_tool_root(source_root: Path) -> Iterator[None]:
    global CONTROL_RELEASE_DIR
    global CONTROL_IMAGES_PATH
    global SOURCE_BUNDLE_PATH
    global OCI_MAPPER_PATH
    global CONNECTOR_RELEASE_TOOL_PATH
    old = (
        CONTROL_RELEASE_DIR,
        CONTROL_IMAGES_PATH,
        SOURCE_BUNDLE_PATH,
        OCI_MAPPER_PATH,
        CONNECTOR_RELEASE_TOOL_PATH,
    )
    CONTROL_RELEASE_DIR = source_root / "deploy/release"
    CONTROL_IMAGES_PATH = CONTROL_RELEASE_DIR / "control_images.py"
    SOURCE_BUNDLE_PATH = CONTROL_RELEASE_DIR / "source_bundle.py"
    OCI_MAPPER_PATH = source_root / "deploy/scripts/map-oci-image-archive.py"
    CONNECTOR_RELEASE_TOOL_PATH = source_root / "connector/release/release.py"
    try:
        for path in (
            CONTROL_IMAGES_PATH,
            SOURCE_BUNDLE_PATH,
            OCI_MAPPER_PATH,
            CONNECTOR_RELEASE_TOOL_PATH,
        ):
            if not path.is_file() or path.is_symlink():
                fail(f"verified package lacks trusted source tool {path}")
        yield
    finally:
        (
            CONTROL_RELEASE_DIR,
            CONTROL_IMAGES_PATH,
            SOURCE_BUNDLE_PATH,
            OCI_MAPPER_PATH,
            CONNECTOR_RELEASE_TOOL_PATH,
        ) = old


def run_checked(
    command: Sequence[str],
    *,
    env: dict[str, str] | None = None,
    timeout: int = 600,
    capture: bool = True,
) -> subprocess.CompletedProcess[str]:
    try:
        result = subprocess.run(
            list(command),
            check=False,
            stdin=subprocess.DEVNULL,
            capture_output=capture,
            text=True,
            env=env,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ServerPackageError(f"cannot execute {command[0]}: {exc}") from exc
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "").strip()
        fail(
            f"command failed with exit {result.returncode}: {command[0]}"
            + (f": {detail}" if detail else "")
        )
    return result


def verify_cosign_version(cosign: str, expected: str) -> None:
    expected_value = require_string(expected, "expected Cosign version")
    if re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", expected_value) is None:
        fail("expected Cosign version is invalid")
    result = run_checked([cosign, "version"])
    bare = expected_value.removeprefix("v")
    output = f"{result.stdout}\n{result.stderr}"
    if re.search(
        rf"(?:^|[^0-9A-Za-z])v?{re.escape(bare)}(?:$|[^0-9A-Za-z])",
        output,
    ) is None:
        fail(f"Cosign version differs from required {expected_value}")


def parse_assignments(values: Iterable[str], label: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for value in values:
        key, separator, item = value.partition("=")
        if not separator or not key or not item:
            fail(f"{label} must use NAME=VALUE syntax")
        if key in result:
            fail(f"{label} repeats {key}")
        result[key] = item
    return result


def file_record(path: Path, *, filename: str | None = None) -> dict[str, Any]:
    metadata = path.stat()
    return {
        "filename": filename or path.name,
        "sha256": sha256_file(path),
        "size": metadata.st_size,
    }


def validate_oci_export_receipt(
    path: Path,
    *,
    image_archives: dict[str, Path],
    lock: dict[str, Any],
) -> dict[str, Any]:
    value = require_exact_keys(
        strict_json(
            read_regular(path, "OCI export receipt", maximum=MAX_JSON_BYTES),
            "OCI export receipt",
            canonical=True,
        ),
        {"format_version", "images", "producer"},
        "OCI export receipt",
    )
    if (
        type(value["format_version"]) is not int
        or value["format_version"] != FORMAT_VERSION
    ):
        fail("OCI export receipt format version is unsupported")
    policy_path = OCI_MAPPER_PATH.parent.parent / "server-package/toolchain.json"
    policy = require_exact_keys(
        strict_json(
            read_regular(policy_path, "OCI toolchain policy", maximum=MAX_JSON_BYTES),
            "OCI toolchain policy",
        ),
        {
            "format_version",
            "tool",
            "version",
            "release",
            "platform",
            "assets",
            "archive",
            "provenance",
        },
        "OCI toolchain policy",
    )
    platform_policy = require_exact_keys(
        policy["platform"],
        {"os", "architecture", "archive_platform"},
        "OCI toolchain platform policy",
    )
    archive_policy = require_exact_keys(
        policy["archive"],
        {"members", "binary_member", "binary_sha256"},
        "OCI toolchain archive policy",
    )
    members = archive_policy["members"]
    if not isinstance(members, list):
        fail("OCI toolchain member policy is invalid")
    crane_members = [
        item
        for item in members
        if isinstance(item, dict) and item.get("name") == archive_policy["binary_member"]
    ]
    if len(crane_members) != 1:
        fail("OCI toolchain policy does not identify one Crane binary")
    crane_member = require_exact_keys(
        crane_members[0], {"name", "mode", "size"}, "Crane member policy"
    )
    producer = require_exact_keys(
        value["producer"], {"name", "version", "platform", "size", "sha256"},
        "OCI export producer",
    )
    expected_producer = {
        "name": policy["tool"],
        "version": policy["version"],
        "platform": f"{platform_policy['os']}/{platform_policy['architecture']}",
        "size": crane_member["size"],
        "sha256": archive_policy["binary_sha256"],
    }
    if producer != expected_producer:
        fail("OCI export producer differs from the signed toolchain policy")
    images = value["images"]
    if not isinstance(images, list) or len(images) != len(COMPONENTS):
        fail("OCI export receipt must contain exactly three image records")
    if set(image_archives) != set(COMPONENTS):
        fail("OCI export receipt validation requires exactly three archives")
    for record_value, component in zip(images, COMPONENTS, strict=True):
        record = require_exact_keys(
            record_value,
            {
                "archive",
                "component",
                "reference",
                "remote_manifest",
                "repeat_verified",
                "sha256",
                "size",
            },
            f"OCI export receipt image {component}",
        )
        image = lock["images"][component]
        archive_name = f"{component}.oci.tar"
        if (
            record["component"] != component
            or record["archive"] != archive_name
            or image_archives[component].name != archive_name
            or record["reference"] != image["reference"]
            or record["repeat_verified"] is not True
        ):
            fail(f"OCI export receipt identity is invalid: {component}")
        remote = require_exact_keys(
            record["remote_manifest"],
            {"media_type", "sha256", "size"},
            f"OCI export remote manifest {component}",
        )
        if (
            remote["media_type"] not in OCI_MANIFEST_MEDIA_TYPES
            or remote["sha256"] != image["digest"].removeprefix("sha256:")
        ):
            fail(f"OCI export remote manifest differs from the lock: {component}")
        require_size(remote["size"], f"OCI export remote manifest {component}")
        require_sha256(record["sha256"], f"OCI export archive {component}")
        require_size(record["size"], f"OCI export archive {component}", MAX_MEMBER_BYTES)
        archive_handle, archive_metadata = open_regular(
            image_archives[component],
            f"OCI export archive {component}",
            maximum=MAX_MEMBER_BYTES,
        )
        try:
            observed_sha256 = sha256_stream(archive_handle)
            after = os.fstat(archive_handle.fileno())
        finally:
            archive_handle.close()
        if (
            stable_fields(archive_metadata) != stable_fields(after)
            or archive_metadata.st_size != record["size"]
            or observed_sha256 != record["sha256"]
        ):
            fail(f"OCI export archive differs from its producer receipt: {component}")
    return value


def validate_oci_remote_manifest_sizes(
    receipt: dict[str, Any], identities: dict[str, dict[str, Any]]
) -> None:
    if set(identities) != set(COMPONENTS):
        fail("OCI identity closure must contain exactly three components")
    for record, component in zip(receipt["images"], COMPONENTS, strict=True):
        if record["remote_manifest"]["size"] != identities[component]["manifest_size"]:
            fail(
                f"OCI export remote manifest size differs from the archive: {component}"
            )


def package_delivery(output: Path, archive: Path) -> dict[str, Any]:
    size = archive.stat().st_size
    if size < GITHUB_ASSET_LIMIT_BYTES:
        return {
            "kind": "single",
            "parts": [
                {
                    **file_record(archive),
                    "index": 1,
                    "count": 1,
                    "signature_bundle": f"{archive.name}{SIGNATURE_SUFFIX}",
                }
            ],
        }
    count = (size + PACKAGE_PART_BYTES - 1) // PACKAGE_PART_BYTES
    if count > MAX_PACKAGE_PARTS:
        fail("server package needs more release parts than the accepted limit")
    width = max(3, len(str(count)))
    parts: list[dict[str, Any]] = []
    created: list[Path] = []
    try:
        with archive.open("rb") as source:
            for index in range(1, count + 1):
                name = f"{archive.name}.part-{index:0{width}d}-of-{count:0{width}d}"
                path = output / name
                descriptor = os.open(
                    path,
                    os.O_WRONLY
                    | os.O_CREAT
                    | os.O_EXCL
                    | getattr(os, "O_CLOEXEC", 0),
                    0o600,
                )
                created.append(path)
                written = 0
                with os.fdopen(descriptor, "wb") as destination:
                    remaining = min(
                        PACKAGE_PART_BYTES,
                        size - (index - 1) * PACKAGE_PART_BYTES,
                    )
                    while remaining:
                        block = source.read(min(1024 * 1024, remaining))
                        if not block:
                            fail("server package archive ended while splitting")
                        destination.write(block)
                        written += len(block)
                        remaining -= len(block)
                    destination.flush()
                    os.fsync(destination.fileno())
                os.chmod(path, 0o444)
                if (
                    path.stat().st_size != written
                    or written <= 0
                    or written >= GITHUB_ASSET_LIMIT_BYTES
                ):
                    fail("server package part size is invalid")
                parts.append(
                    {
                        **file_record(path),
                        "index": index,
                        "count": count,
                        "signature_bundle": f"{name}{SIGNATURE_SUFFIX}",
                    }
                )
            if source.read(1):
                fail("server package archive grew while splitting")
        if sum(part["size"] for part in parts) != size:
            fail("server package parts do not cover the logical archive size")
        archive.unlink()
        return {"kind": "split", "parts": parts}
    except BaseException:
        for path in created:
            try:
                path.unlink()
            except FileNotFoundError:
                pass
        raise


def validate_file_record(value: Any, label: str) -> dict[str, Any]:
    record = require_exact_keys(value, {"filename", "sha256", "size"}, label)
    validate_portable_path(record["filename"], f"{label} filename")
    require_sha256(record["sha256"], f"{label} SHA-256")
    require_size(record["size"], label)
    return record


def secure_copy(source: Path, destination: Path, mode: int) -> None:
    handle, before = open_regular(
        source, f"package input {source.name}", maximum=MAX_MEMBER_BYTES
    )
    destination.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(destination, flags, mode)
    except OSError as exc:
        handle.close()
        raise ServerPackageError(f"cannot create package member {destination}") from exc
    try:
        copied = 0
        with os.fdopen(descriptor, "wb") as target:
            while block := handle.read(1024 * 1024):
                copied += len(block)
                if copied > before.st_size:
                    fail(f"package input grew while copied: {source}")
                target.write(block)
            target.flush()
            os.fsync(target.fileno())
        after = os.fstat(handle.fileno())
        if copied != before.st_size or stable_fields(before) != stable_fields(after):
            fail(f"package input changed while copied: {source}")
        os.chmod(destination, mode)
    finally:
        handle.close()


def scan_public_content(path: Path, raw: bytes) -> None:
    lowered = path.as_posix().lower()
    if any(
        marker in lowered
        for marker in ("sub2apiauth", ".pem", ".p12", "id_rsa", "id_ed25519")
    ):
        fail(f"package contains a forbidden credential-like path: {path}")
    if any(marker in raw for marker in SECRET_MARKERS):
        fail(f"package contains private-key material: {path}")


def trust_arguments(args: argparse.Namespace) -> list[str]:
    values = (
        ("certificate OIDC issuer", args.certificate_oidc_issuer),
        ("certificate identity", args.certificate_identity),
        ("certificate workflow SHA", args.certificate_github_workflow_sha),
        ("certificate workflow trigger", args.certificate_github_workflow_trigger),
        ("certificate workflow repository", args.certificate_github_workflow_repository),
        ("certificate workflow ref", args.certificate_github_workflow_ref),
    )
    for label, value in values:
        require_string(value, label)
    validate_commit(args.certificate_github_workflow_sha)
    if args.certificate_github_workflow_trigger != "push":
        fail("certificate workflow trigger must be push")
    return [
        "--certificate-oidc-issuer",
        args.certificate_oidc_issuer,
        "--certificate-identity",
        args.certificate_identity,
        "--certificate-github-workflow-sha",
        args.certificate_github_workflow_sha,
        "--certificate-github-workflow-trigger",
        args.certificate_github_workflow_trigger,
        "--certificate-github-workflow-repository",
        args.certificate_github_workflow_repository,
        "--certificate-github-workflow-ref",
        args.certificate_github_workflow_ref,
    ]


def connector_trust_arguments(args: argparse.Namespace) -> list[str]:
    repository = validate_repository(args.expected_connector_repository)
    commit = validate_commit(args.expected_connector_source_commit)
    tag = require_string(args.expected_connector_tag, "expected Connector tag")
    if not tag.startswith("connector-v") or VERSION_RE.fullmatch(
        tag.removeprefix("connector-v")
    ) is None:
        fail("expected Connector tag is invalid")
    values = (
        ("Connector certificate OIDC issuer", args.connector_certificate_oidc_issuer),
        ("Connector certificate identity", args.connector_certificate_identity),
        (
            "Connector certificate workflow SHA",
            args.connector_certificate_github_workflow_sha,
        ),
        (
            "Connector certificate workflow trigger",
            args.connector_certificate_github_workflow_trigger,
        ),
    )
    for label, value in values:
        require_string(value, label)
    expected_identity = (
        f"{repository}/.github/workflows/connector-release.yml@refs/tags/{tag}"
    )
    if (
        args.connector_certificate_identity != expected_identity
        or args.connector_certificate_github_workflow_sha != commit
        or args.connector_certificate_github_workflow_trigger != "push"
    ):
        fail("Connector Sigstore policy differs from its exact release identity")
    for label, value in (
        ("Connector release ID", args.expected_connector_release_id),
        ("Connector workflow run ID", args.expected_connector_workflow_run_id),
        (
            "Connector workflow run attempt",
            args.expected_connector_workflow_run_attempt,
        ),
    ):
        if type(value) is not int or value <= 0:
            fail(f"{label} must be one positive integer")
    return [
        "--certificate-oidc-issuer",
        args.connector_certificate_oidc_issuer,
        "--certificate-identity",
        args.connector_certificate_identity,
        "--certificate-github-workflow-sha",
        args.connector_certificate_github_workflow_sha,
        "--certificate-github-workflow-trigger",
        args.connector_certificate_github_workflow_trigger,
    ]


def require_basename(value: Any, label: str) -> str:
    filename = validate_portable_path(value, label)
    if PurePosixPath(filename).parent != PurePosixPath("."):
        fail(f"{label} must be one basename")
    return filename


def connector_inventory_map(value: Any, label: str) -> dict[str, dict[str, Any]]:
    if not isinstance(value, list) or not value:
        fail(f"{label} must be one non-empty inventory")
    result: dict[str, dict[str, Any]] = {}
    order: list[str] = []
    for record_value in value:
        record = require_exact_keys(
            record_value, {"filename", "sha256", "size"}, f"{label} record"
        )
        name = require_basename(record["filename"], f"{label} filename")
        if name in result:
            fail(f"{label} repeats {name}")
        require_sha256(record["sha256"], f"{label} {name}")
        require_size(record["size"], f"{label} {name}")
        result[name] = record
        order.append(name)
    if order != sorted(order):
        fail(f"{label} is not sorted")
    return result


def require_connector_inventory_file(
    inventory: dict[str, dict[str, Any]],
    filename: Any,
    label: str,
    *,
    sha256: Any | None = None,
    size: Any | None = None,
) -> None:
    name = require_basename(filename, label)
    record = inventory.get(name)
    if record is None:
        fail(f"Connector aggregate inventory lacks {label}: {name}")
    if sha256 is not None and record["sha256"] != sha256:
        fail(f"Connector aggregate inventory SHA-256 differs for {label}")
    if size is not None and record["size"] != size:
        fail(f"Connector aggregate inventory size differs for {label}")


def validate_connector_metadata(
    metadata: Any,
    aggregate: dict[str, Any],
    args: argparse.Namespace,
) -> dict[str, Any]:
    value = require_exact_keys(
        metadata,
        {
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
        },
        "Connector release metadata",
    )
    release = aggregate["release"]
    if (
        type(value["format_version"]) is not int
        or value["format_version"] != 1
        or value["release_mode"] != "release"
        or value["releasable"] is not True
        or value["source_repository"] != args.expected_connector_repository
        or value["source_commit"] != args.expected_connector_source_commit
        or value["version"] != release["version"]
        or value["tag"] != args.expected_connector_tag
        or value["codex_version"] != release["codex_version"]
        or value["schema_digest"] != release["schema_digest"]
        or value["config_path_hint"]
        != "~/.config/sub2api-codex-connector/connector.json"
        or value["pair_command"] != "sub2api-codex-connector-ctl pair"
        or value["start_command"] != "sub2api-codex-connector-ctl start"
    ):
        fail("Connector release metadata differs from the verified aggregate release")
    manifest = require_exact_keys(
        value["manifest"],
        {"filename", "sha256", "size", "signature_bundle"},
        "Connector metadata manifest",
    )
    require_basename(manifest["filename"], "Connector manifest filename")
    require_sha256(manifest["sha256"], "Connector manifest SHA-256")
    require_size(manifest["size"], "Connector manifest")
    if (
        manifest["filename"] != "manifest.json"
        or value["manifest"]["signature_bundle"]
        != "manifest.json.sigstore.json"
        or value["manifest"] != aggregate["evidence"]["manifest"]
    ):
        fail("Connector metadata manifest differs from aggregate evidence")
    core = connector_inventory_map(
        aggregate["core_inventory"], "Connector aggregate core inventory"
    )
    assets = value["assets"]
    packages = aggregate["verified_packages"]
    expected_pairs = (
        ("linux", "amd64", "deb", "linux-amd64"),
        ("linux", "amd64", "rpm", "linux-amd64"),
        ("linux", "arm64", "deb", "linux-arm64"),
        ("linux", "arm64", "rpm", "linux-arm64"),
    )
    if (
        not isinstance(assets, list)
        or len(assets) != len(expected_pairs)
        or len(packages) != len(expected_pairs)
    ):
        fail("Connector metadata does not contain the complete package matrix")
    for asset_value, package, expected_pair in zip(
        assets, packages, expected_pairs, strict=True
    ):
        asset = require_exact_keys(
            asset_value,
            {
                "os",
                "arch",
                "package_format",
                "filename",
                "download_url",
                "sha256",
                "size",
                "signature_bundle",
                "sbom",
                "provenance",
            },
            "Connector metadata package",
        )
        os_name, arch, package_format, target_id = expected_pair
        if (
            (asset["os"], asset["arch"], asset["package_format"])
            != (os_name, arch, package_format)
            or package.get("target_id") != target_id
            or package.get("package_format") != package_format
            or package.get("filename") != asset["filename"]
            or package.get("sha256") != asset["sha256"]
            or package.get("size") != asset["size"]
        ):
            fail("Connector metadata package differs from aggregate package matrix")
        filename = require_basename(asset["filename"], "Connector package filename")
        require_sha256(asset["sha256"], f"Connector package {filename}")
        require_size(asset["size"], f"Connector package {filename}")
        if asset["signature_bundle"] != f"{filename}{SIGNATURE_SUFFIX}":
            fail("Connector package signature filename is not package-derived")
        expected_url = (
            f"{value['source_repository']}/releases/download/{value['tag']}/{filename}"
        )
        if asset["download_url"] != expected_url:
            fail("Connector package download URL is not immutable release content")
        require_connector_inventory_file(
            core,
            filename,
            "Connector package",
            sha256=asset["sha256"],
            size=asset["size"],
        )
        require_connector_inventory_file(
            core, asset["signature_bundle"], "Connector package signature"
        )
        sbom = require_exact_keys(
            asset["sbom"],
            {"format", "filename", "sha256", "size", "signature_bundle"},
            "Connector package SBOM",
        )
        expected_sbom = f"{filename}{SPDX_SUFFIX}"
        if (
            sbom["format"] != SPDX_FORMAT
            or sbom["filename"] != expected_sbom
            or sbom["signature_bundle"]
            != f"{expected_sbom}{SIGNATURE_SUFFIX}"
        ):
            fail("Connector package SBOM metadata is invalid")
        require_sha256(sbom["sha256"], "Connector package SBOM")
        require_size(sbom["size"], "Connector package SBOM")
        require_connector_inventory_file(
            core,
            sbom["filename"],
            "Connector package SBOM",
            sha256=sbom["sha256"],
            size=sbom["size"],
        )
        require_connector_inventory_file(
            core, sbom["signature_bundle"], "Connector SBOM signature"
        )
        provenance = require_exact_keys(
            asset["provenance"],
            {
                "predicate_type",
                "filename",
                "sha256",
                "size",
                "signature_bundle",
                "attestation_bundle",
            },
            "Connector package provenance",
        )
        expected_provenance = f"{filename}{CONNECTOR_PROVENANCE_SUFFIX}"
        if (
            provenance["predicate_type"] != SLSA_PREDICATE_TYPE
            or provenance["filename"] != expected_provenance
            or provenance["signature_bundle"]
            != f"{expected_provenance}{SIGNATURE_SUFFIX}"
            or provenance["attestation_bundle"]
            != f"{filename}{ATTESTATION_SUFFIX}"
        ):
            fail("Connector package provenance metadata is invalid")
        require_sha256(provenance["sha256"], "Connector package provenance")
        require_size(provenance["size"], "Connector package provenance")
        require_connector_inventory_file(
            core,
            provenance["filename"],
            "Connector package provenance",
            sha256=provenance["sha256"],
            size=provenance["size"],
        )
        require_connector_inventory_file(
            core,
            provenance["signature_bundle"],
            "Connector provenance signature",
        )
        require_connector_inventory_file(
            core,
            provenance["attestation_bundle"],
            "Connector provenance attestation",
        )
    return value


def connector_input_path(value: Any, expected_name: str, label: str) -> Path:
    path = Path(require_string(value, label)).absolute()
    if path.name != expected_name:
        fail(f"{label} must be named {expected_name}")
    require_owned_directory(path.parent, f"{label} parent")
    handle, _ = open_regular(path, label, maximum=MAX_JSON_BYTES)
    handle.close()
    return path


def verify_connector_release_inputs(args: argparse.Namespace) -> dict[str, Any]:
    connector_trust_arguments(args)
    metadata_path = connector_input_path(
        args.connector_release_metadata,
        CONNECTOR_METADATA_FILENAME,
        "Connector release metadata",
    )
    metadata_bundle_path = connector_input_path(
        args.connector_release_metadata_bundle,
        CONNECTOR_METADATA_BUNDLE_FILENAME,
        "Connector release metadata bundle",
    )
    aggregate_path = connector_input_path(
        args.connector_verification_aggregate,
        CONNECTOR_AGGREGATE_FILENAME,
        "Connector verification aggregate",
    )
    aggregate_bundle_path = connector_input_path(
        args.connector_verification_aggregate_bundle,
        CONNECTOR_AGGREGATE_BUNDLE_FILENAME,
        "Connector verification aggregate bundle",
    )
    run_checked(
        [
            args.cosign,
            "verify-blob",
            "--bundle",
            str(metadata_bundle_path),
            *connector_trust_arguments(args),
            str(metadata_path),
        ]
    )
    command = [
        sys.executable,
        "-I",
        str(CONNECTOR_RELEASE_TOOL_PATH),
        "verify-aggregate",
        "--aggregate",
        str(aggregate_path),
        "--bundle",
        str(aggregate_bundle_path),
        "--cosign",
        args.cosign,
        *connector_trust_arguments(args),
        "--expected-release-id",
        str(args.expected_connector_release_id),
        "--expected-tag",
        args.expected_connector_tag,
        "--expected-source-commit",
        args.expected_connector_source_commit,
        "--expected-workflow-run-id",
        str(args.expected_connector_workflow_run_id),
        "--expected-workflow-run-attempt",
        str(args.expected_connector_workflow_run_attempt),
    ]
    run_checked(command, timeout=900)
    connector_release = import_tool(
        CONNECTOR_RELEASE_TOOL_PATH, "server_package_connector_release"
    )
    aggregate_raw = read_regular(
        aggregate_path, "Connector verification aggregate", maximum=MAX_JSON_BYTES
    )
    aggregate = strict_json(aggregate_raw, "Connector verification aggregate")
    if connector_canonical_json(aggregate) != aggregate_raw:
        fail("Connector verification aggregate is not canonical connector JSON")
    try:
        connector_release.validate_aggregate_receipt(aggregate)
    except connector_release.ReleaseError as exc:
        raise ServerPackageError(f"Connector aggregate is invalid: {exc}") from exc
    release = aggregate["release"]
    verification_run = aggregate["verification_run"]
    public_release = aggregate["public_release"]
    if (
        release["source_repository"] != args.expected_connector_repository
        or release["source_commit"] != args.expected_connector_source_commit
        or release["tag"] != args.expected_connector_tag
        or public_release["release_id"] != args.expected_connector_release_id
        or verification_run["run_id"] != args.expected_connector_workflow_run_id
        or verification_run["run_attempt"]
        != args.expected_connector_workflow_run_attempt
    ):
        fail("Connector aggregate differs from the external immutable release policy")
    metadata_raw = read_regular(
        metadata_path, "Connector release metadata", maximum=MAX_JSON_BYTES
    )
    metadata_value = strict_json(metadata_raw, "Connector release metadata")
    if connector_canonical_json(metadata_value) != metadata_raw:
        fail("Connector release metadata is not canonical connector JSON")
    metadata = validate_connector_metadata(metadata_value, aggregate, args)
    metadata_evidence = aggregate["evidence"]["release_metadata"]
    if (
        metadata_evidence["filename"] != metadata_path.name
        or metadata_evidence["sha256"] != sha256_bytes(metadata_raw)
        or metadata_evidence["size"] != len(metadata_raw)
        or metadata_evidence["signature_bundle"] != metadata_bundle_path.name
    ):
        fail("Connector aggregate does not bind the supplied release metadata")
    core = connector_inventory_map(
        aggregate["core_inventory"], "Connector aggregate core inventory"
    )
    for path, label in (
        (metadata_path, "Connector release metadata"),
        (metadata_bundle_path, "Connector release metadata bundle"),
    ):
        require_connector_inventory_file(
            core,
            path.name,
            label,
            sha256=sha256_file(path),
            size=path.stat().st_size,
        )
    paths = {
        "metadata": metadata_path,
        "metadata_bundle": metadata_bundle_path,
        "aggregate": aggregate_path,
        "aggregate_bundle": aggregate_bundle_path,
    }
    return {
        "aggregate_value": aggregate,
        "metadata_value": metadata,
        "paths": paths,
        "identity": {
            "source_repository": release["source_repository"],
            "source_commit": release["source_commit"],
            "version": release["version"],
            "tag": release["tag"],
            "release_id": public_release["release_id"],
            "workflow_run_id": verification_run["run_id"],
            "workflow_run_attempt": verification_run["run_attempt"],
        },
    }


def copy_connector_release_evidence(
    connector: dict[str, Any], destination: Path
) -> dict[str, Any]:
    destination.mkdir(parents=True, exist_ok=True, mode=0o700)
    expected_names = {
        "metadata": CONNECTOR_METADATA_FILENAME,
        "metadata_bundle": CONNECTOR_METADATA_BUNDLE_FILENAME,
        "aggregate": CONNECTOR_AGGREGATE_FILENAME,
        "aggregate_bundle": CONNECTOR_AGGREGATE_BUNDLE_FILENAME,
    }
    for role, expected_name in expected_names.items():
        source = connector["paths"][role]
        target = destination / expected_name
        secure_copy(source, target, 0o444)
    copied = dict(connector)
    copied["paths"] = {
        role: destination / expected_name
        for role, expected_name in expected_names.items()
    }
    return connector_release_record(copied)


def connector_release_record(connector: dict[str, Any]) -> dict[str, Any]:
    record: dict[str, Any] = dict(connector["identity"])
    for role in ("metadata", "metadata_bundle", "aggregate", "aggregate_bundle"):
        record[role] = file_record(connector["paths"][role])
    return record


def use_connector_inputs_from_directory(
    args: argparse.Namespace, directory: Path
) -> None:
    args.connector_release_metadata = str(directory / CONNECTOR_METADATA_FILENAME)
    args.connector_release_metadata_bundle = str(
        directory / CONNECTOR_METADATA_BUNDLE_FILENAME
    )
    args.connector_verification_aggregate = str(
        directory / CONNECTOR_AGGREGATE_FILENAME
    )
    args.connector_verification_aggregate_bundle = str(
        directory / CONNECTOR_AGGREGATE_BUNDLE_FILENAME
    )


def load_control_tools() -> tuple[Any, Any]:
    return (
        import_tool(CONTROL_IMAGES_PATH, "server_package_control_images"),
        import_tool(SOURCE_BUNDLE_PATH, "server_package_source_bundle"),
    )


def control_verify_namespace(args: argparse.Namespace, release_dir: Path) -> argparse.Namespace:
    return argparse.Namespace(
        release_dir=str(release_dir),
        cosign=args.cosign,
        certificate_oidc_issuer=args.certificate_oidc_issuer,
        certificate_identity=args.certificate_identity,
        certificate_github_workflow_sha=args.certificate_github_workflow_sha,
        certificate_github_workflow_trigger=args.certificate_github_workflow_trigger,
        certificate_github_workflow_repository=(
            args.certificate_github_workflow_repository
        ),
        certificate_github_workflow_ref=args.certificate_github_workflow_ref,
        expected_source_repository=args.expected_source_repository,
        expected_source_commit=args.expected_source_commit,
        expected_release_tag=args.expected_release_tag,
        expected_api_repository=args.expected_api_repository,
        expected_pwa_repository=args.expected_pwa_repository,
        expected_postgres_tools_repository=args.expected_postgres_tools_repository,
    )


def verify_control_release(
    args: argparse.Namespace, release_dir: Path
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Authenticate the existing image/source release before package construction."""
    control_images, _ = load_control_tools()
    output = io.StringIO()
    namespace = control_verify_namespace(args, release_dir)
    try:
        with contextlib.redirect_stdout(output):
            control_images.command_verify(namespace)
    except (OSError, control_images.ReleaseError) as exc:
        raise ServerPackageError(f"Control release verification failed: {exc}") from exc
    verification = strict_json(
        output.getvalue().encode("utf-8"), "Control release verification output"
    )
    if not isinstance(verification, dict):
        fail("Control release verifier returned a non-object")
    lock_raw = read_regular(
        release_dir / control_images.LOCK_FILENAME,
        "Control image lock",
        maximum=MAX_JSON_BYTES,
    )
    lock = strict_json(lock_raw, "Control image lock")
    control_images.validate_lock(lock)
    if verification.get("CONTROL_RELEASE_LOCK_SHA256") != sha256_bytes(lock_raw):
        fail("Control verification output does not bind the image lock bytes")
    return lock, verification


def validate_image_trust_directory(directory: Path) -> dict[str, Any]:
    require_owned_directory(directory, "offline image trust directory")
    expected = {"trusted_root.json", *COMPONENTS}
    actual = {entry.name for entry in directory.iterdir()}
    if actual != expected:
        fail(
            "offline image trust inventory mismatch; "
            f"missing={sorted(expected - actual)}, extra={sorted(actual - expected)}"
        )
    trusted_root = directory / "trusted_root.json"
    strict_json(
        read_regular(trusted_root, "Sigstore trusted root", maximum=MAX_JSON_BYTES),
        "Sigstore trusted root",
    )
    result: dict[str, Any] = {"trusted_root": trusted_root, "components": {}}
    for component in COMPONENTS:
        component_dir = directory / component
        require_owned_directory(component_dir, f"{component} Cosign saved image")
        files = list(iter_owner_controlled_tree(component_dir))
        if not files:
            fail(f"{component} Cosign saved image is empty")
        if len(files) > MAX_PACKAGE_FILES:
            fail(f"{component} Cosign saved image has too many files")
        result["components"][component] = component_dir
    return result


SIGN_STATEMENT_PREDICATE_TYPE = "https://sigstore.dev/cosign/sign/v1"
MAX_SIGN_BUNDLE_BYTES = 1024 * 1024


def verify_saved_sign_statement(
    layout: Path,
    digest: str,
    expected_annotations: dict[str, str],
    label: str,
) -> None:
    """Bind a Cosign-saved layout to the locked digest and sign statement.

    The layout index must contain exactly the locked image, and one stored
    Sigstore bundle must carry the Cosign v3 sign statement whose subject
    pins that digest and every release annotation.
    """
    index = strict_json(
        read_regular(layout / "index.json", f"{label} layout index", maximum=MAX_JSON_BYTES),
        f"{label} layout index",
    )
    manifests = index.get("manifests") if isinstance(index, dict) else None
    if (
        not isinstance(manifests, list)
        or len(manifests) != 1
        or not isinstance(manifests[0], dict)
        or manifests[0].get("digest") != digest
    ):
        fail(f"{label} saved layout does not pin the locked digest")
    plain_digest = digest.removeprefix("sha256:")
    blob_dir = layout / "blobs" / "sha256"
    if not blob_dir.is_dir():
        fail(f"{label} saved layout has no blob directory")
    for blob in sorted(blob_dir.iterdir()):
        try:
            if not blob.is_file() or blob.stat().st_size > MAX_SIGN_BUNDLE_BYTES:
                continue
            bundle = json.loads(blob.read_bytes())
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            continue
        if not isinstance(bundle, dict):
            continue
        envelope = bundle.get("dsseEnvelope")
        if not isinstance(envelope, dict) or not isinstance(
            envelope.get("payload"), str
        ):
            continue
        try:
            statement = json.loads(base64.b64decode(envelope["payload"], validate=True))
        except (ValueError, binascii.Error):
            continue
        if (
            not isinstance(statement, dict)
            or statement.get("predicateType") != SIGN_STATEMENT_PREDICATE_TYPE
        ):
            continue
        subjects = statement.get("subject")
        if not isinstance(subjects, list):
            continue
        for subject in subjects:
            if not isinstance(subject, dict):
                continue
            subject_digest = subject.get("digest")
            annotations = subject.get("annotations")
            if (
                isinstance(subject_digest, dict)
                and subject_digest.get("sha256") == plain_digest
                and isinstance(annotations, dict)
                and all(
                    annotations.get(key) == value
                    for key, value in expected_annotations.items()
                )
            ):
                return
    fail(f"{label} saved layout lacks the verified sign statement binding")


def verify_offline_image_trust(
    args: argparse.Namespace,
    lock: dict[str, Any],
    saved: dict[str, Any],
    *,
    release_dir: Path | None = None,
) -> None:
    """Verify Cosign-saved images and attestations without registry access."""
    control_images, _ = load_control_tools()
    trust = trust_arguments(args)
    config = control_images.load_config()
    if config["cosign_version"] != args.expected_cosign_version:
        fail("Control release Cosign version differs from external policy")
    control_images.verify_cosign_version(args.cosign, config["cosign_version"])
    trusted_root = str(saved["trusted_root"])
    evidence_root = release_dir or Path(args.release_dir)
    for component in COMPONENTS:
        image = lock["images"][component]
        local_image = str(saved["components"][component])
        annotations = [
            "-a",
            f"component={component}",
            "-a",
            f"release_tag={lock['release_tag']}",
            "-a",
            f"source_commit={lock['source']['commit']}",
        ]
        run_checked(
            [
                args.cosign,
                "verify",
                "--offline=true",
                "--local-image",
                "--trusted-root",
                trusted_root,
                *trust,
                *annotations,
                local_image,
            ]
        )
        # Cosign v3 renders local-image signature claims without the digest
        # or annotations, so bind the digest through the layout itself.
        verify_saved_sign_statement(
            Path(local_image),
            image["digest"],
            {
                "component": component,
                "release_tag": lock["release_tag"],
                "source_commit": lock["source"]["commit"],
            },
            f"{component} offline signature",
        )
        for evidence_name, cosign_type in (
            ("sbom", "spdxjson"),
            ("provenance", "slsaprovenance1"),
        ):
            result = run_checked(
                [
                    args.cosign,
                    "verify-attestation",
                    "--offline=true",
                    "--local-image",
                    "--trusted-root",
                    trusted_root,
                    "--type",
                    cosign_type,
                    *trust,
                    local_image,
                ]
            )
            statements = control_images.decode_attestation_statements(
                result.stdout, f"{component} offline {evidence_name} attestation"
            )
            predicate = strict_json(
                read_regular(
                    evidence_root / image[evidence_name]["filename"],
                    f"{component} {evidence_name}",
                    maximum=MAX_JSON_BYTES,
                ),
                f"{component} {evidence_name}",
            )
            if not any(
                control_images.statement_matches(
                    statement,
                    repository=image["repository"],
                    digest=image["digest"],
                    predicate_type=image[evidence_name]["predicate_type"],
                    predicate=predicate,
                )
                for statement in statements
            ):
                fail(
                    f"{component} offline {evidence_name} attestation does not "
                    "match the locked predicate"
                )


def copy_release_evidence(source: Path, destination: Path, lock: dict[str, Any]) -> None:
    control_images, _ = load_control_tools()
    control_images.validate_release_directory(source, expect_bundle=True)
    destination.mkdir(parents=True, mode=0o700)
    for entry in sorted(source.iterdir(), key=lambda item: item.name):
        secure_copy(entry, destination / entry.name, 0o444)
    expected = {
        control_images.LOCK_FILENAME,
        control_images.BUNDLE_FILENAME,
        *(lock["source_bundle"][kind]["filename"] for kind in lock["source_bundle"]),
        *(
            lock["images"][component][kind]["filename"]
            for component in COMPONENTS
            for kind in ("sbom", "provenance")
        ),
    }
    if {entry.name for entry in destination.iterdir()} != expected:
        fail("copied Control release evidence inventory is not exact")


def copy_image_trust(saved: dict[str, Any], destination: Path) -> dict[str, Any]:
    destination.mkdir(parents=True, mode=0o700)
    secure_copy(saved["trusted_root"], destination / "trusted_root.json", 0o444)
    records: dict[str, Any] = {
        "trusted_root": file_record(
            destination / "trusted_root.json",
            filename="image-trust/trusted_root.json",
        ),
        "components": {},
    }
    for component in COMPONENTS:
        source_root = saved["components"][component]
        target_root = destination / component
        target_root.mkdir(parents=True, mode=0o700)
        component_records: list[dict[str, Any]] = []
        for relative, source in iter_owner_controlled_tree(source_root):
            target = target_root / relative
            secure_copy(source, target, 0o444)
            component_records.append(
                {
                    "mode": f"{stat.S_IMODE(target.stat().st_mode):04o}",
                    "path": f"image-trust/{component}/{relative}",
                    "sha256": sha256_file(target),
                    "size": target.stat().st_size,
                }
            )
        records["components"][component] = component_records
    return records


def oci_archive_inventory(
    archive: tarfile.TarFile, mapper: Any
) -> dict[str, tarfile.TarInfo]:
    inventory: dict[str, tarfile.TarInfo] = {}
    expanded = 0
    for count, member in enumerate(archive, start=1):
        if count > mapper.MAX_MEMBERS:
            fail("offline OCI archive has too many members")
        name = mapper.normalize_member_name(member)
        if name in inventory:
            fail(f"offline OCI archive repeats {name}")
        if member.isdir():
            if name not in {"blobs", "blobs/sha256"}:
                fail(f"offline OCI archive contains unexpected directory {name}")
        elif member.isreg():
            if name not in {"index.json", "oci-layout"} and re.fullmatch(
                r"blobs/sha256/[0-9a-f]{64}", name
            ) is None:
                fail(f"offline OCI archive contains unexpected file {name}")
            expanded += member.size
            if member.size < 0 or expanded > mapper.MAX_EXPANDED_BYTES:
                fail("offline OCI archive expanded size is outside the accepted range")
        else:
            fail(f"offline OCI archive member is not a regular file: {name}")
        inventory[name] = member
    for required in ("index.json", "oci-layout"):
        if required not in inventory or not inventory[required].isreg():
            fail(f"offline OCI archive is missing {required}")
    return inventory


def strict_oci_identity(
    archive_path: Path,
    *,
    component: str,
    lock: dict[str, Any],
) -> dict[str, Any]:
    mapper = import_tool(OCI_MAPPER_PATH, "server_package_oci_mapper")
    handle, metadata = mapper.open_archive(archive_path)
    try:
        archive_sha256 = mapper.sha256_stream(handle)
        handle.seek(0)
        try:
            archive = tarfile.open(fileobj=handle, mode="r:*")
        except (OSError, tarfile.TarError) as exc:
            raise ServerPackageError(f"cannot parse offline OCI archive: {exc}") from exc
        with archive:
            inventory = oci_archive_inventory(archive, mapper)
            blobs = mapper.verify_all_blobs(archive, inventory)
            layout = mapper.require_object(
                mapper.decode_json(
                    mapper.read_member(
                        archive, inventory["oci-layout"], "oci-layout", MAX_JSON_BYTES
                    ),
                    "oci-layout",
                ),
                "oci-layout",
            )
            if layout != {"imageLayoutVersion": "1.0.0"}:
                fail("offline OCI layout version is unsupported")
            index_raw = mapper.read_member(
                archive, inventory["index.json"], "index.json", MAX_JSON_BYTES
            )
            index = mapper.require_object(mapper.decode_json(index_raw, "index.json"), "index.json")
            mapper.require_exact_or_optional_keys(
                index,
                {"schemaVersion", "mediaType", "manifests"},
                {"annotations"},
                "offline OCI index",
            )
            if index.get("schemaVersion") != 2 or index.get("mediaType") != mapper.OCI_INDEX_MEDIA_TYPE:
                fail("offline OCI index is not OCI image index v1")
            manifests = index.get("manifests")
            if not isinstance(manifests, list) or len(manifests) != 1:
                fail("offline OCI index must select exactly one linux/amd64 manifest")
            selected = mapper.descriptor(
                manifests[0],
                "offline OCI manifest descriptor",
                mapper.MANIFEST_MEDIA_TYPES,
                allow_platform=True,
            )
            if selected.get("urls") is not None:
                fail("offline OCI manifest descriptor contains external URLs")
            manifest_digest = selected["digest"]
            manifest_member = mapper.require_blob(
                blobs,
                manifest_digest,
                selected["size"],
                "offline image manifest",
            )
            manifest = mapper.require_object(
                mapper.decode_json(
                    mapper.read_member(
                        archive, manifest_member, "image manifest", MAX_JSON_BYTES
                    ),
                    "image manifest",
                ),
                "image manifest",
            )
            mapper.require_exact_or_optional_keys(
                manifest,
                {"schemaVersion", "mediaType", "config", "layers"},
                {"annotations"},
                "offline image manifest",
            )
            if manifest.get("schemaVersion") != 2 or manifest.get("mediaType") != selected["mediaType"]:
                fail("offline image manifest identity differs from its descriptor")
            config_descriptor = mapper.descriptor(
                manifest.get("config"),
                "offline config descriptor",
                mapper.CONFIG_MEDIA_TYPES,
            )
            if config_descriptor.get("urls") is not None:
                fail("offline OCI config descriptor contains external URLs")
            config_digest = config_descriptor["digest"]
            config_member = mapper.require_blob(
                blobs,
                config_digest,
                config_descriptor["size"],
                "offline image config",
            )
            config = mapper.require_object(
                mapper.decode_json(
                    mapper.read_member(
                        archive, config_member, "image config", MAX_JSON_BYTES
                    ),
                    "image config",
                ),
                "image config",
            )
            expected_platform = mapper.split_platform(PLATFORM)
            observed_platform = mapper.platform_from_config(config)
            if observed_platform != expected_platform:
                fail(f"{component} offline image is not linux/amd64")
            mapper.validate_descriptor_platform(
                selected.get("platform"), expected_platform, "offline manifest platform"
            )
            expected_labels = {
                "org.opencontainers.image.source": lock["source"]["repository"],
                "org.opencontainers.image.revision": lock["source"]["commit"],
                "org.opencontainers.image.version": lock["release"],
            }
            labels = mapper.validate_labels(config, expected_labels)
            referenced = {manifest_digest, config_digest}
            layer_digests: list[str] = []
            layers = manifest.get("layers")
            if not isinstance(layers, list) or not layers:
                fail("offline OCI image manifest has no layers")
            for index_value, value in enumerate(layers):
                descriptor_value = mapper.descriptor(
                    value,
                    f"offline layer descriptor {index_value}",
                    mapper.LAYER_MEDIA_TYPES,
                )
                media_type = descriptor_value["mediaType"]
                if (
                    "nondistributable" in media_type
                    or "foreign" in media_type
                    or media_type
                    not in {
                        "application/vnd.oci.image.layer.v1.tar",
                        "application/vnd.oci.image.layer.v1.tar+gzip",
                        "application/vnd.oci.image.layer.v1.tar+zstd",
                    }
                ):
                    fail(f"offline OCI layer {index_value} is not distributable")
                if descriptor_value.get("urls") is not None:
                    fail(f"offline OCI layer {index_value} contains external URLs")
                mapper.require_blob(
                    blobs,
                    descriptor_value["digest"],
                    descriptor_value["size"],
                    f"offline image layer {index_value}",
                )
                referenced.add(descriptor_value["digest"])
                layer_digests.append(descriptor_value["digest"])
            if set(blobs) != referenced:
                fail(
                    "offline OCI blob closure is not exact; "
                    f"missing={sorted(referenced - set(blobs))}, "
                    f"extra={sorted(set(blobs) - referenced)}"
                )
            index_sha256 = f"sha256:{hashlib.sha256(index_raw).hexdigest()}"
            locked = lock["images"][component]
            # Crane's platform export synthesizes a local index. It cannot prove a
            # registry index digest, so formal packages currently require the lock
            # to name the selected linux/amd64 image manifest itself.
            if locked["digest"] != manifest_digest:
                fail(
                    f"{component} signed lock must pin the exported platform manifest"
                )
            annotations = mapper.require_string_mapping(
                selected.get("annotations"), "offline manifest annotations"
            )
            if (
                annotations.get("org.opencontainers.image.ref.name")
                != locked["reference"]
            ):
                fail(
                    f"{component} offline OCI ref-name annotation differs from "
                    "the locked digest reference"
                )
            containerd_reference = annotations.get("io.containerd.image.name")
            if (
                containerd_reference is not None
                and containerd_reference != locked["reference"]
            ):
                fail(
                    f"{component} offline containerd image annotation differs "
                    "from the locked reference"
                )
        handle.seek(0)
        if mapper.sha256_stream(handle) != archive_sha256:
            fail("offline OCI archive changed while verified")
        if mapper.stable_fields(os.fstat(handle.fileno())) != mapper.stable_fields(metadata):
            fail("offline OCI archive metadata changed while verified")
    finally:
        handle.close()
    return {
        "archive": {"sha256": archive_sha256, "size": metadata.st_size},
        "config_digest": config_digest,
        "index_sha256": index_sha256,
        "labels": labels,
        "layer_digests": layer_digests,
        "locked_digest": locked["digest"],
        "locked_reference": locked["reference"],
        "manifest_digest": manifest_digest,
        "manifest_size": selected["size"],
        "platform": PLATFORM,
    }


def build_oci_identity(
    *,
    component: str,
    archive: Path,
    lock: dict[str, Any],
) -> dict[str, Any]:
    try:
        return strict_oci_identity(archive, component=component, lock=lock)
    except (OSError, tarfile.TarError) as exc:
        raise ServerPackageError(
            f"{component} offline OCI archive verification failed: {exc}"
        ) from exc


def source_asset_hashes(lock: dict[str, Any]) -> dict[str, str]:
    return {
        lock["source_bundle"][kind]["filename"]: lock["source_bundle"][kind][
            "sha256"
        ]
        for kind in ("archive", "manifest", "attestation")
    }


def extract_signed_source(
    release_dir: Path,
    destination: Path,
    lock: dict[str, Any],
) -> dict[str, Any]:
    _, source_bundle = load_control_tools()
    assets = lock["source_bundle"]
    try:
        result = source_bundle.extract_verified_bundle(
            release_dir.resolve(),
            destination.resolve(),
            release=lock["release"],
            repository=lock["source"]["repository"],
            commit=lock["source"]["commit"],
            attestation_sha256=assets["attestation"]["sha256"],
            manifest_sha256=assets["manifest"]["sha256"],
            archive_sha256=assets["archive"]["sha256"],
            require_root_owner=False,
        )
    except (OSError, source_bundle.SourceBundleError) as exc:
        raise ServerPackageError(f"signed source extraction failed: {exc}") from exc
    return result


def iter_regular_tree(root: Path) -> Iterator[tuple[str, Path, int]]:
    seen_inodes: set[tuple[int, int]] = set()
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        relative = path.relative_to(root).as_posix()
        validate_portable_path(relative)
        metadata = path.lstat()
        if stat.S_ISDIR(metadata.st_mode):
            continue
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            fail(f"package staging tree contains a link or special file: {relative}")
        inode = (metadata.st_dev, metadata.st_ino)
        if inode in seen_inodes:
            fail(f"package staging tree contains a hard-link alias: {relative}")
        seen_inodes.add(inode)
        mode = stat.S_IMODE(metadata.st_mode)
        if mode not in {0o444, 0o555}:
            fail(f"package staging file has invalid mode {mode:04o}: {relative}")
        yield relative, path, mode


def iter_owner_controlled_tree(root: Path) -> Iterator[tuple[str, Path]]:
    seen_inodes: set[tuple[int, int]] = set()
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        relative = path.relative_to(root).as_posix()
        validate_portable_path(relative)
        metadata = path.lstat()
        if stat.S_ISDIR(metadata.st_mode):
            if metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) & 0o022:
                fail(f"input directory is not owner-controlled: {relative}")
            continue
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) & 0o022
        ):
            fail(f"input tree contains an unsafe file: {relative}")
        inode = (metadata.st_dev, metadata.st_ino)
        if inode in seen_inodes:
            fail(f"input tree contains a hard-link alias: {relative}")
        seen_inodes.add(inode)
        yield relative, path


def tree_inventory(root: Path, *, exclude: set[str] | None = None) -> list[dict[str, Any]]:
    excluded = exclude or set()
    result: list[dict[str, Any]] = []
    total = 0
    for relative, path, mode in iter_regular_tree(root):
        if relative in excluded:
            continue
        metadata = path.stat()
        total += metadata.st_size
        if metadata.st_size > MAX_MEMBER_BYTES or total > MAX_PACKAGE_EXPANDED_BYTES:
            fail("package staging content exceeds its accepted size")
        if len(result) >= MAX_PACKAGE_FILES:
            fail("package staging file count exceeds its accepted range")
        if metadata.st_size <= MAX_JSON_BYTES and not relative.startswith("images/"):
            scan_public_content(Path(relative), path.read_bytes())
        result.append(
            {
                "mode": f"{mode:04o}",
                "path": relative,
                "sha256": sha256_file(path),
                "size": metadata.st_size,
            }
        )
    return result


def require_server_source_closure(source_root: Path) -> list[str]:
    required = {
        "LICENSE",
        "NOTICE",
        "THIRD_PARTY_NOTICES.md",
        "deploy/scripts/deploy-production.sh",
        "deploy/scripts/deployment-admission.py",
        "deploy/scripts/bootstrap-admission.py",
        "deploy/scripts/backup-production-state.py",
        "deploy/scripts/production-recovery.py",
        "deploy/scripts/probe-sub2api-auth-contract.py",
        "deploy/scripts/pg-restore-via-container.sh",
        "deploy/scripts/map-oci-image-archive.py",
        "deploy/release/control_images.py",
        "deploy/release/source_bundle.py",
        "deploy/release/verify-control-images.sh",
        "deploy/release/control-images-config.json",
        "deploy/release/control-images-lock.schema.json",
        "deploy/release/source-bundle.schema.json",
        "deploy/docker-compose/compose.yaml",
        "deploy/docker-compose/compose.production.yaml",
        "deploy/docker-compose/.env.example",
        "deploy/server-package/server_package.py",
        "deploy/server-package/lifecycle.py",
        "deploy/server-package/oci_toolchain.py",
        "deploy/server-package/toolchain.json",
        "deploy/server-package/server-packages.schema.json",
        "deploy/server-package/OCI-TOOLCHAIN.md",
        "docs/contracts/sub2api-auth.v0.2.1.json",
        "connector/internal/config/config.go",
        "connector/internal/protocol/protocol.go",
        "connector/release/release.py",
        "connector/release/release-config.json",
        "connector/packaging/verify-package-contents.sh",
        "connector/release/connector-aggregate-verification-receipt.schema.json",
        "connector/release/connector-platform-verification-receipt.schema.json",
        "connector/release/connector-public-release-descriptor.schema.json",
        "connector/release/manifest.schema.json",
        "connector/release/connector-release-metadata.schema.json",
        "apps/control-api/src/control_api/connector_release.py",
        "packages/appserver-schema/generated/json-schema/codex_app_server_protocol.v2.schemas.json",
        "packages/control-protocol/fixtures/json-budget-vectors.json",
        "packages/control-protocol/fixtures/rpc-policy.json",
        "packages/control-protocol/fixtures/wire-envelopes.json",
        "packages/control-protocol/schema/control-envelope.schema.json",
        "deploy/schemas/production-recovery-receipt.schema.json",
        "deploy/scripts/verify-sub2api-runtime.py",
        "deploy/scripts/verify-sub2api-runtime.sh",
        "scripts/build-vulnerability-manifest.py",
        "scripts/check-licenses.py",
        "scripts/check-public-tree.py",
        "scripts/check-vulnerabilities.py",
        "scripts/install-trivy.sh",
        "scripts/run-vulnerability-scan.py",
        "scripts/vulnerability_release_roots.py",
        "scripts/vulnerability_scan_evidence.py",
        "scripts/verify-formal-vulnerability-release.sh",
        "security/README.md",
        "security/vulnerability-dispositions.json",
        "security/vulnerability-policy.json",
        "tests/e2e/smoke.py",
        "third_party/components.json",
        "third_party/licenses/Trivy-LICENSE.txt",
        "versions.lock.json",
        "deploy/server-package/INSTALL.md",
        "deploy/server-package/config/operator.env.example",
        *(
            f"deploy/server-package/{path}"
            for path in REQUIRED_LIFECYCLE.values()
        ),
    }
    missing = sorted(path for path in required if not (source_root / path).is_file())
    nginx_files = sorted(
        path.relative_to(source_root).as_posix()
        for path in (source_root / "deploy/nginx").glob("*")
        if path.is_file()
    )
    migration_files = sorted(
        path.relative_to(source_root).as_posix()
        for path in (source_root / "migrations").rglob("*")
        if path.is_file()
    )
    if not nginx_files:
        missing.append("deploy/nginx/*")
    if not migration_files:
        missing.append("migrations/*")
    if missing:
        fail(f"signed source lacks required server installation closure: {missing}")
    return sorted(required | set(nginx_files) | set(migration_files))


def copy_signed_source_tools(source_root: Path, stage: Path) -> None:
    mappings = {
        "deploy/server-package/server_package.py": "lib/server_package.py",
        "deploy/server-package/lifecycle.py": "lib/lifecycle.py",
        "deploy/server-package/INSTALL.md": "INSTALL.md",
        "deploy/server-package/config/operator.env.example": (
            "config/operator.env.example"
        ),
        **{
            source: source
            for source in REQUIRED_LIFECYCLE.values()
        },
    }
    # Lifecycle paths are repo-relative under deploy/server-package in source.
    for source_relative, destination_relative in list(mappings.items()):
        if source_relative.startswith("bin/"):
            del mappings[source_relative]
            mappings[f"deploy/server-package/{source_relative}"] = source_relative
    for source_relative, destination_relative in sorted(mappings.items()):
        source = source_root / source_relative
        mode = 0o555 if destination_relative.startswith("bin/") else 0o444
        secure_copy(source, stage / destination_relative, mode)


def common_payload_sha256(records: list[dict[str, Any]]) -> str:
    common = [
        record
        for record in records
        if not record["path"].startswith("images/")
        and record["path"] != OCI_EXPORT_RECEIPT_FILENAME
        and record["path"] != PACKAGE_MANIFEST_FILENAME
    ]
    return sha256_bytes(canonical_json(common))


def write_package_archive(
    stage: Path,
    destination: Path,
    *,
    root_name: str,
    source_date_epoch: int,
) -> None:
    if destination.exists() or destination.is_symlink():
        fail(f"refusing to overwrite package archive {destination.name}")
    fd, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.", dir=destination.parent
    )
    os.close(fd)
    temporary = Path(temporary_name)
    try:
        with temporary.open("wb") as raw_target:
            with gzip.GzipFile(
                filename="",
                mode="wb",
                compresslevel=9,
                fileobj=raw_target,
                mtime=source_date_epoch,
            ) as compressed:
                with tarfile.open(
                    fileobj=compressed, mode="w|", format=tarfile.USTAR_FORMAT
                ) as archive:
                    for relative, path, mode in iter_regular_tree(stage):
                        info = tarfile.TarInfo(f"{root_name}/{relative}")
                        info.type = tarfile.REGTYPE
                        info.mode = mode
                        info.uid = 0
                        info.gid = 0
                        info.uname = ""
                        info.gname = ""
                        info.mtime = source_date_epoch
                        info.size = path.stat().st_size
                        with path.open("rb") as source:
                            archive.addfile(info, source)
            raw_target.flush()
            os.fsync(raw_target.fileno())
        if temporary.stat().st_size > MAX_PACKAGE_BYTES:
            fail("server package archive exceeds its accepted size")
        os.chmod(temporary, 0o444)
        os.link(temporary, destination, follow_symlinks=False)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def copy_source_tree(source: Path, destination: Path) -> None:
    destination.mkdir(parents=True, mode=0o700)
    for relative, path, mode in iter_regular_tree(source):
        secure_copy(path, destination / relative, mode)


def stage_server_package(
    stage: Path,
    *,
    mode: str,
    release_dir: Path,
    lock: dict[str, Any],
    control_verification: dict[str, Any],
    image_trust: dict[str, Any],
    image_archives: dict[str, Path],
    oci_export_receipt_path: Path | None,
    oci_export_receipt_record: dict[str, Any] | None,
    connector_release: dict[str, Any],
    source_date_epoch: int,
) -> tuple[dict[str, Any], str, dict[str, dict[str, Any]]]:
    if mode not in MODES:
        fail(f"unsupported server package mode {mode}")
    stage.mkdir(mode=0o700)
    signed_source = stage / "source"
    source_verification = extract_signed_source(release_dir, signed_source, lock)
    if source_verification.get("source_date_epoch") != source_date_epoch:
        fail("package source epoch differs from the signed source attestation")
    required_source_paths = require_server_source_closure(signed_source)
    copy_signed_source_tools(stage / "source", stage)
    copy_release_evidence(release_dir, stage / "release", lock)
    image_trust_records = copy_image_trust(image_trust, stage / "image-trust")
    connector_records = copy_connector_release_evidence(connector_release, stage)

    image_records: dict[str, Any] = {}
    provenance_identities: dict[str, dict[str, Any]] = {}
    if mode == "online":
        if image_archives or oci_export_receipt_path is not None:
            fail("online package must not receive offline OCI archives")
        for component in COMPONENTS:
            image = lock["images"][component]
            image_records[component] = {
                "acquisition": "registry",
                "digest": image["digest"],
                "reference": image["reference"],
                "repository": image["repository"],
            }
    else:
        if (
            set(image_archives) != set(COMPONENTS)
            or oci_export_receipt_path is None
            or oci_export_receipt_record is None
        ):
            fail("offline package requires exactly three component OCI archives")
        receipt_target = stage / OCI_EXPORT_RECEIPT_FILENAME
        secure_copy(oci_export_receipt_path, receipt_target, 0o444)
        if file_record(receipt_target) != oci_export_receipt_record:
            fail("OCI export receipt changed while staged")
        images_dir = stage / "images"
        images_dir.mkdir(mode=0o700)
        for component in COMPONENTS:
            source = image_archives[component]
            identity = build_oci_identity(
                component=component,
                archive=source,
                lock=lock,
            )
            archive_name = f"{component}.oci.tar"
            target = images_dir / archive_name
            secure_copy(source, target, 0o444)
            if (
                sha256_file(target) != identity["archive"]["sha256"]
                or target.stat().st_size != identity["archive"]["size"]
            ):
                fail(f"{component} OCI archive changed while staged")
            identity_name = f"{component}.identity.json"
            identity_path = images_dir / identity_name
            atomic_write(identity_path, canonical_json(identity), mode=0o444)
            provenance_identities[component] = identity
            image_records[component] = {
                "acquisition": "offline-oci",
                "archive": file_record(target, filename=f"images/{archive_name}"),
                "identity": file_record(
                    identity_path, filename=f"images/{identity_name}"
                ),
                "locked_digest": identity["locked_digest"],
                "locked_reference": identity["locked_reference"],
            }

    records = tree_inventory(stage)
    common_digest = common_payload_sha256(records)
    control_evidence = {
        name: {
            "filename": f"release/{name}",
            "sha256": digest,
            "size": (stage / "release" / name).stat().st_size,
        }
        for name, digest in sorted(
            control_verification["CONTROL_RELEASE_EVIDENCE_SHA256S"].items()
        )
    }
    package_manifest = {
        "$schema": PACKAGE_SCHEMA_ID,
        "format_version": FORMAT_VERSION,
        "product": "sub2api-codex-control-server",
        "release": lock["release"],
        "release_tag": lock["release_tag"],
        "mode": mode,
        "platform": PLATFORM,
        "source": lock["source"],
        "builder": lock["builder"],
        "source_date_epoch": source_date_epoch,
        "common_payload_sha256": common_digest,
        "control_release": {
            "evidence": control_evidence,
            "lock_sha256": control_verification["CONTROL_RELEASE_LOCK_SHA256"],
            "bundle_sha256": control_verification[
                "CONTROL_RELEASE_BUNDLE_SHA256"
            ],
        },
        "source_bundle": lock["source_bundle"],
        "source_verification": source_verification,
        "connector_release": connector_records,
        "oci_export": (
            oci_export_receipt_record if mode == "offline" else None
        ),
        "image_trust": image_trust_records,
        "images": image_records,
        "lifecycle": REQUIRED_LIFECYCLE,
        "required_source_paths": required_source_paths,
        "files": records,
    }
    manifest_bytes = canonical_json(package_manifest)
    atomic_write(stage / PACKAGE_MANIFEST_FILENAME, manifest_bytes, mode=0o444)
    return package_manifest, sha256_bytes(manifest_bytes), provenance_identities


def spdx_verification_code(file_sha1: str) -> str:
    return hashlib.sha1(file_sha1.encode("ascii"), usedforsecurity=False).hexdigest()


# OS-level packages stay in the per-image SPDX evidence and are scanned
# through the container targets; aggregating deb and apk inventories into
# one SPDX document breaks Trivy's SBOM decoder ("multiple types of OS
# packages in SBOM are not supported").
OS_PACKAGE_PURL_PREFIXES = ("pkg:deb/", "pkg:apk/", "pkg:rpm/")


def image_package_purl(dependency: dict[str, Any]) -> str:
    references = dependency.get("externalRefs")
    if not isinstance(references, list):
        return ""
    for reference in references:
        if isinstance(reference, dict) and reference.get("referenceType") == "purl":
            locator = reference.get("referenceLocator")
            if isinstance(locator, str):
                return locator
    return ""


def is_os_image_package(dependency: dict[str, Any]) -> bool:
    return image_package_purl(dependency).startswith(OS_PACKAGE_PURL_PREFIXES)


def image_sbom_dependencies(
    release_dir: Path, lock: dict[str, Any]
) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    seen_identities: set[tuple[Any, Any, str]] = set()
    for component in COMPONENTS:
        sbom_record = lock["images"][component]["sbom"]
        sbom_raw = read_regular(
            release_dir / sbom_record["filename"],
            f"{component} image SBOM",
            maximum=MAX_JSON_BYTES,
        )
        # The authenticated Control lock records filename, predicate type,
        # and sha256 for each image SBOM; the digest fully binds the bytes.
        if sha256_bytes(sbom_raw) != sbom_record["sha256"]:
            fail(f"{component} image SBOM differs from the authenticated Control lock")
        sbom = strict_json(sbom_raw, f"{component} image SBOM")
        dependencies = sbom.get("packages") if isinstance(sbom, dict) else None
        if not isinstance(dependencies, list) or not dependencies:
            fail(f"{component} image SBOM contains no packages")
        for index, dependency_value in enumerate(dependencies):
            if not isinstance(dependency_value, dict):
                fail(f"{component} image SBOM package is invalid")
            if is_os_image_package(dependency_value):
                continue
            # The same language package can ship in several images; the
            # aggregated document lists each package identity once.
            identity = (
                dependency_value.get("name"),
                dependency_value.get("versionInfo"),
                image_package_purl(dependency_value),
            )
            if identity in seen_identities:
                continue
            seen_identities.add(identity)
            dependency = dict(dependency_value)
            dependency_id = (
                f"SPDXRef-Dependency-{component.replace('-', '')}-{index}-"
                f"{sha256_bytes(canonical_json(dependency))[:12]}"
            )
            dependency["SPDXID"] = dependency_id
            dependency.setdefault("downloadLocation", "NOASSERTION")
            dependency.setdefault("filesAnalyzed", False)
            dependency.setdefault("licenseConcluded", "NOASSERTION")
            dependency.setdefault("licenseDeclared", "NOASSERTION")
            dependency.setdefault("copyrightText", "NOASSERTION")
            result.append(dependency)
    return result


def make_package_sbom(
    archive: Path,
    *,
    mode: str,
    release: str,
    source_date_epoch: int,
    lock: dict[str, Any],
    release_dir: Path,
) -> dict[str, Any]:
    archive_sha256 = sha256_file(archive)
    archive_sha1 = sha1_file(archive)
    package_id = "SPDXRef-Package-ServerPackage"
    file_id = "SPDXRef-File-ServerPackage"
    packages: list[dict[str, Any]] = [
        {
            "name": f"sub2api-codex-control-server-{mode}",
            "SPDXID": package_id,
            "versionInfo": release,
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": True,
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": "Apache-2.0",
            "copyrightText": "NOASSERTION",
            "primaryPackagePurpose": "INSTALL",
            "packageVerificationCode": {
                "packageVerificationCodeValue": spdx_verification_code(archive_sha1)
            },
            "checksums": [
                {"algorithm": "SHA1", "checksumValue": archive_sha1},
                {"algorithm": "SHA256", "checksumValue": archive_sha256},
            ],
            "externalRefs": [
                {
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": (
                        "pkg:generic/sub2api-codex-control-server@"
                        f"{release}?arch=amd64&mode={mode}&os=linux"
                    ),
                }
            ],
        }
    ]
    relationships: list[dict[str, str]] = [
        {
            "spdxElementId": "SPDXRef-DOCUMENT",
            "relationshipType": "DESCRIBES",
            "relatedSpdxElement": package_id,
        },
        {
            "spdxElementId": package_id,
            "relationshipType": "CONTAINS",
            "relatedSpdxElement": file_id,
        },
    ]
    for dependency in image_sbom_dependencies(release_dir, lock):
        packages.append(dependency)
        relationships.append(
            {
                "spdxElementId": package_id,
                "relationshipType": "DEPENDS_ON",
                "relatedSpdxElement": dependency["SPDXID"],
            }
        )
    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"{archive.name}-sbom",
        "documentNamespace": (
            "https://sub2api-codex.invalid/spdx/server-package/"
            f"{archive_sha256}"
        ),
        "creationInfo": {
            "created": iso8601(source_date_epoch),
            "creators": ["Tool: sub2api-server-package-v1"],
            "licenseListVersion": "3.27",
        },
        "packages": packages,
        "files": [
            {
                "fileName": f"./{archive.name}",
                "SPDXID": file_id,
                "checksums": [
                    {"algorithm": "SHA1", "checksumValue": archive_sha1},
                    {"algorithm": "SHA256", "checksumValue": archive_sha256},
                ],
                "licenseConcluded": "NOASSERTION",
                "licenseInfoInFiles": ["NOASSERTION"],
                "copyrightText": "NOASSERTION",
            }
        ],
        "relationships": relationships,
    }


def make_package_provenance(
    archive: Path,
    *,
    mode: str,
    lock: dict[str, Any],
    package_manifest_sha256: str,
    source_date_epoch: int,
    image_records: dict[str, Any],
    control_lock_sha256: str,
    connector_release: dict[str, Any],
    oci_export_receipt: dict[str, Any] | None,
    oci_identities: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    dependencies = [
        {
            "uri": f"git+{lock['source']['repository']}@{lock['source']['commit']}",
            "digest": {"gitCommit": lock["source"]["commit"]},
        },
        {
            "uri": "file:control-images.lock.json",
            "digest": {"sha256": control_lock_sha256},
        },
    ]
    for kind in ("archive", "manifest", "attestation"):
        asset = lock["source_bundle"][kind]
        dependencies.append(
            {
                "uri": f"file:{asset['filename']}",
                "digest": {"sha256": asset["sha256"]},
            }
        )
    for role in ("metadata", "metadata_bundle", "aggregate", "aggregate_bundle"):
        asset = connector_release[role]
        dependencies.append(
            {
                "uri": f"file:{asset['filename']}",
                "digest": {"sha256": asset["sha256"]},
            }
        )
    for component in COMPONENTS:
        image = lock["images"][component]
        dependencies.append(
            {
                "uri": f"pkg:oci/{image['repository']}@{image['digest']}",
                "digest": {"sha256": image["digest"].removeprefix("sha256:")},
            }
        )
        offline = image_records.get(component)
        if isinstance(offline, dict) and offline.get("acquisition") == "offline-oci":
            identity = oci_identities.get(component)
            if not isinstance(identity, dict):
                fail(f"offline provenance lacks OCI identity: {component}")
            manifest_digest = require_string(
                identity["manifest_digest"], f"{component} manifest digest"
            )
            config_digest = require_string(
                identity["config_digest"], f"{component} config digest"
            )
            if (
                re.fullmatch(r"sha256:[0-9a-f]{64}", manifest_digest) is None
                or re.fullmatch(r"sha256:[0-9a-f]{64}", config_digest) is None
            ):
                fail(f"offline provenance OCI digests are invalid: {component}")
            dependencies.append(
                {
                    "uri": f"file:{offline['archive']['filename']}",
                    "digest": {"sha256": offline["archive"]["sha256"]},
                }
            )
            dependencies.extend(
                [
                    {
                        "uri": f"file:{offline['identity']['filename']}",
                        "digest": {"sha256": offline["identity"]["sha256"]},
                    },
                    {
                        "uri": f"oci:{image['reference']}#manifest",
                        "digest": {"sha256": manifest_digest.removeprefix("sha256:")},
                    },
                    {
                        "uri": f"oci:{image['reference']}#config",
                        "digest": {"sha256": config_digest.removeprefix("sha256:")},
                    },
                ]
            )
    if mode == "offline":
        if oci_export_receipt is None:
            fail("offline provenance requires the OCI export receipt")
        dependencies.append(
            {
                "uri": f"file:{oci_export_receipt['filename']}",
                "digest": {"sha256": oci_export_receipt["sha256"]},
            }
        )
    return {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [
            {"name": archive.name, "digest": {"sha256": sha256_file(archive)}}
        ],
        "predicateType": SLSA_PREDICATE_TYPE,
        "predicate": {
            "buildDefinition": {
                "buildType": BUILD_TYPE,
                "externalParameters": {
                    "mode": mode,
                    "platform": PLATFORM,
                    "release": lock["release"],
                    "release_tag": lock["release_tag"],
                    "source": lock["source"],
                    "connector_release": {
                        key: connector_release[key]
                        for key in (
                            "source_repository",
                            "source_commit",
                            "version",
                            "tag",
                            "release_id",
                            "workflow_run_id",
                            "workflow_run_attempt",
                        )
                    },
                },
                "internalParameters": {
                    "package_manifest_sha256": package_manifest_sha256,
                    "source_date_epoch": source_date_epoch,
                },
                "resolvedDependencies": dependencies,
            },
            "runDetails": {
                "builder": {"id": lock["builder"]["workflow_identity"]},
                "metadata": {
                    "invocationId": lock["builder"]["invocation_id"],
                    "startedOn": iso8601(source_date_epoch),
                    "finishedOn": iso8601(source_date_epoch),
                },
                "byproducts": [
                    {
                        "name": PACKAGE_MANIFEST_FILENAME,
                        "digest": {"sha256": package_manifest_sha256},
                    }
                ],
            },
        },
    }


def _build_server_packages_in_directory(args: argparse.Namespace) -> dict[str, Any]:
    release_dir = Path(args.release_dir).resolve()
    output = Path(args.output_dir).resolve()
    require_owned_directory(release_dir, "Control release evidence directory")
    require_owned_directory(output, "server package output directory")
    if any(output.iterdir()):
        fail("server package output directory must be empty")
    if not 0 < args.source_date_epoch <= (1 << 32) - 1:
        fail("source date epoch is outside the portable USTAR range")
    validate_repository(args.expected_source_repository)
    validate_commit(args.expected_source_commit)
    if args.expected_release_tag != f"control-v{validate_release(args.release)}":
        fail("release and expected release tag do not match")
    if args.expected_source_commit != args.certificate_github_workflow_sha:
        fail("source commit and certificate workflow SHA must match")
    trust_arguments(args)
    image_archives = {
        key: Path(value).resolve()
        for key, value in parse_assignments(args.image_archive, "image archive").items()
    }
    if set(image_archives) != set(COMPONENTS):
        fail("build requires exactly one OCI archive for every image component")
    image_trust = validate_image_trust_directory(Path(args.image_trust_dir).resolve())
    args.release_dir = str(release_dir)
    lock, control_verification = verify_control_release(args, release_dir)
    if lock["release"] != args.release:
        fail("signed Control release differs from the requested package release")
    verify_offline_image_trust(args, lock, image_trust)
    oci_export_source = Path(args.oci_export_receipt).resolve()
    oci_export_receipt = validate_oci_export_receipt(
        oci_export_source,
        image_archives=image_archives,
        lock=lock,
    )
    oci_export_target = output / OCI_EXPORT_RECEIPT_FILENAME
    secure_copy(oci_export_source, oci_export_target, 0o444)
    external_oci_export_record = file_record(oci_export_target)
    connector_release = verify_connector_release_inputs(args)
    external_connector_records = copy_connector_release_evidence(
        connector_release, output
    )

    package_records: dict[str, Any] = {}
    common_payload: str | None = None
    for mode in MODES:
        package_name = f"{PACKAGE_PREFIX}-{lock['release']}-linux-amd64-{mode}.tar.gz"
        root_name = package_name.removesuffix(".tar.gz")
        with tempfile.TemporaryDirectory(
            prefix=f"server-package-{mode}.", dir=output.parent
        ) as temporary:
            stage = Path(temporary) / root_name
            package_manifest, internal_sha, oci_identities = stage_server_package(
                stage,
                mode=mode,
                release_dir=release_dir,
                lock=lock,
                control_verification=control_verification,
                image_trust=image_trust,
                image_archives=image_archives if mode == "offline" else {},
                oci_export_receipt_path=(
                    oci_export_target if mode == "offline" else None
                ),
                oci_export_receipt_record=(
                    external_oci_export_record if mode == "offline" else None
                ),
                connector_release=connector_release,
                source_date_epoch=args.source_date_epoch,
            )
            if mode == "offline":
                validate_oci_remote_manifest_sizes(
                    oci_export_receipt, oci_identities
                )
            if mode == "online":
                secure_copy(
                    stage / "source/deploy/server-package/server_package.py",
                    output / CONSUMER_VERIFIER_FILENAME,
                    0o555,
                )
            if common_payload is None:
                common_payload = package_manifest["common_payload_sha256"]
            elif package_manifest["common_payload_sha256"] != common_payload:
                fail("online and offline package common payloads differ")
            archive = output / package_name
            write_package_archive(
                stage,
                archive,
                root_name=root_name,
                source_date_epoch=args.source_date_epoch,
            )
        sbom_bytes = canonical_json(
            make_package_sbom(
                archive,
                mode=mode,
                release=lock["release"],
                source_date_epoch=args.source_date_epoch,
                lock=lock,
                release_dir=release_dir,
            )
        )
        sbom_name = (
            f"{TARGET_IDS[mode]}.{sha256_bytes(sbom_bytes)}{SPDX_SUFFIX}"
        )
        sbom_path = output / sbom_name
        provenance_path = output / f"{package_name}{PROVENANCE_SUFFIX}"
        atomic_write(sbom_path, sbom_bytes)
        atomic_write(
            provenance_path,
            canonical_json(
                make_package_provenance(
                    archive,
                    mode=mode,
                    lock=lock,
                    package_manifest_sha256=internal_sha,
                    source_date_epoch=args.source_date_epoch,
                    image_records=package_manifest["images"],
                    control_lock_sha256=control_verification[
                        "CONTROL_RELEASE_LOCK_SHA256"
                    ],
                    connector_release=package_manifest["connector_release"],
                    oci_export_receipt=(
                        external_oci_export_record if mode == "offline" else None
                    ),
                    oci_identities=oci_identities,
                )
            ),
        )
        archive_record = file_record(archive)
        delivery = package_delivery(output, archive)
        package_records[mode] = {
            **archive_record,
            "target_id": TARGET_IDS[mode],
            "mode": mode,
            "platform": PLATFORM,
            "internal_manifest_sha256": internal_sha,
            "signature_bundle": f"{package_name}{SIGNATURE_SUFFIX}",
            "delivery": delivery,
            "sbom": {
                **file_record(sbom_path),
                "format": SPDX_FORMAT,
                "signature_bundle": f"{sbom_path.name}{SIGNATURE_SUFFIX}",
            },
            "provenance": {
                **file_record(provenance_path),
                "predicate_type": SLSA_PREDICATE_TYPE,
                "signature_bundle": f"{provenance_path.name}{SIGNATURE_SUFFIX}",
                "attestation_bundle": f"{package_name}{ATTESTATION_SUFFIX}",
            },
        }

    control_images, _ = load_control_tools()
    config = control_images.load_config()
    manifest = {
        "$schema": SCHEMA_ID,
        "format_version": FORMAT_VERSION,
        "kind": MANIFEST_KIND,
        "release": lock["release"],
        "release_tag": lock["release_tag"],
        "platform": PLATFORM,
        "source": lock["source"],
        "builder": lock["builder"],
        "control_release": {
            "lock": file_record(release_dir / control_images.LOCK_FILENAME),
            "bundle": file_record(release_dir / control_images.BUNDLE_FILENAME),
            "evidence_sha256s": control_verification[
                "CONTROL_RELEASE_EVIDENCE_SHA256S"
            ],
        },
        "connector_release": external_connector_records,
        "oci_export": external_oci_export_record,
        "consumer_verifier": file_record(output / CONSUMER_VERIFIER_FILENAME),
        "packages": package_records,
        "checksums": {
            "filename": CHECKSUMS_FILENAME,
            "signature_bundle": f"{CHECKSUMS_FILENAME}{SIGNATURE_SUFFIX}",
        },
        "signing": {
            "cosign_version": config["cosign_version"],
            "manifest_bundle": f"{MANIFEST_FILENAME}{SIGNATURE_SUFFIX}",
        },
    }
    manifest_path = output / MANIFEST_FILENAME
    atomic_write(manifest_path, canonical_json(manifest))
    content_names = [
        MANIFEST_FILENAME,
        OCI_EXPORT_RECEIPT_FILENAME,
        CONSUMER_VERIFIER_FILENAME,
        *(external_connector_records[role]["filename"] for role in (
            "metadata",
            "metadata_bundle",
            "aggregate",
            "aggregate_bundle",
        )),
    ]
    for mode in MODES:
        package = package_records[mode]
        content_names.extend(part["filename"] for part in package["delivery"]["parts"])
        content_names.extend([package["sbom"]["filename"], package["provenance"]["filename"]])
    checksum_lines = [
        f"{sha256_file(output / name)}  {name}" for name in sorted(content_names)
    ]
    atomic_write(
        output / CHECKSUMS_FILENAME,
        ("\n".join(checksum_lines) + "\n").encode("ascii"),
    )
    return manifest


def build_server_packages(args: argparse.Namespace) -> dict[str, Any]:
    output = Path(args.output_dir).resolve()
    require_owned_directory(output, "server package output directory")
    if any(output.iterdir()):
        fail("server package output directory must be empty")
    with tempfile.TemporaryDirectory(
        prefix="server-package-release.", dir=output.parent
    ) as temporary:
        staging = Path(temporary)
        staged_args = argparse.Namespace(**vars(args))
        staged_args.output_dir = str(staging)
        manifest = _build_server_packages_in_directory(staged_args)
        validate_unsigned_release_directory(staging, manifest)
        created: list[Path] = []
        try:
            for source in sorted(staging.iterdir(), key=lambda item: item.name):
                target = output / source.name
                os.link(source, target, follow_symlinks=False)
                created.append(target)
            directory_descriptor = os.open(
                output,
                os.O_RDONLY
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_DIRECTORY", 0),
            )
            try:
                os.fsync(directory_descriptor)
            finally:
                os.close(directory_descriptor)
        except BaseException:
            for target in reversed(created):
                try:
                    target.unlink()
                except FileNotFoundError:
                    pass
            raise
    return manifest


def signed_content_names(manifest: dict[str, Any]) -> list[str]:
    names = [
        MANIFEST_FILENAME,
        CHECKSUMS_FILENAME,
        manifest["oci_export"]["filename"],
        manifest["consumer_verifier"]["filename"],
    ]
    for mode in MODES:
        package = manifest["packages"][mode]
        names.extend(part["filename"] for part in package["delivery"]["parts"])
        names.extend([package["sbom"]["filename"], package["provenance"]["filename"]])
    return names


def release_content_names(manifest: dict[str, Any]) -> list[str]:
    names = signed_content_names(manifest)
    connector = manifest["connector_release"]
    names.extend(
        connector[role]["filename"]
        for role in ("metadata", "metadata_bundle", "aggregate", "aggregate_bundle")
    )
    if len(names) != len(set(names)):
        fail("server release content filenames collide")
    return names


def expected_release_files(manifest: dict[str, Any], *, signed: bool) -> set[str]:
    content = set(release_content_names(manifest))
    if not signed:
        return content
    bundles = {
        f"{name}{SIGNATURE_SUFFIX}" for name in signed_content_names(manifest)
    }
    bundles.update(
        manifest["packages"][mode]["signature_bundle"] for mode in MODES
    )
    bundles.update(
        manifest["packages"][mode]["provenance"]["attestation_bundle"]
        for mode in MODES
    )
    return content | bundles


def parse_checksums(raw: bytes) -> dict[str, str]:
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError as exc:
        raise ServerPackageError("server package checksums are not ASCII") from exc
    if not text.endswith("\n") or "\r" in text or "\0" in text:
        fail("server package checksums are not canonical text")
    result: dict[str, str] = {}
    for line in text.splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9][A-Za-z0-9._-]*)", line)
        if match is None:
            fail("server package checksums contain a malformed line")
        digest, name = match.groups()
        if name in result:
            fail(f"server package checksums repeat {name}")
        result[name] = digest
    if list(result) != sorted(result):
        fail("server package checksums are not sorted")
    return result


def validate_connector_release_record(value: Any, label: str) -> dict[str, Any]:
    record = require_exact_keys(
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
        label,
    )
    validate_repository(record["source_repository"])
    validate_commit(record["source_commit"])
    version = validate_release(record["version"])
    if record["tag"] != f"connector-v{version}":
        fail(f"{label} tag differs from its version")
    for name in ("release_id", "workflow_run_id", "workflow_run_attempt"):
        if type(record[name]) is not int or record[name] <= 0:
            fail(f"{label} {name} must be a positive integer")
    expected_files = {
        "metadata": CONNECTOR_METADATA_FILENAME,
        "metadata_bundle": CONNECTOR_METADATA_BUNDLE_FILENAME,
        "aggregate": CONNECTOR_AGGREGATE_FILENAME,
        "aggregate_bundle": CONNECTOR_AGGREGATE_BUNDLE_FILENAME,
    }
    for role, expected_name in expected_files.items():
        item = validate_file_record(record[role], f"{label} {role}")
        if item["filename"] != expected_name:
            fail(f"{label} {role} filename is invalid")
    return record


def validate_package_entry(value: Any, mode: str, release: str) -> dict[str, Any]:
    entry = require_exact_keys(
        value,
        {
            "filename",
            "sha256",
            "size",
            "target_id",
            "mode",
            "platform",
            "internal_manifest_sha256",
            "signature_bundle",
            "delivery",
            "sbom",
            "provenance",
        },
        f"{mode} package",
    )
    expected = f"{PACKAGE_PREFIX}-{release}-linux-amd64-{mode}.tar.gz"
    if entry["filename"] != expected:
        fail(f"{mode} package filename is invalid")
    if entry["target_id"] != TARGET_IDS[mode]:
        fail(f"{mode} package target identity is invalid")
    require_sha256(entry["sha256"], f"{mode} package SHA-256")
    require_size(entry["size"], f"{mode} package")
    require_sha256(
        entry["internal_manifest_sha256"], f"{mode} internal manifest SHA-256"
    )
    if entry["mode"] != mode or entry["platform"] != PLATFORM:
        fail(f"{mode} package identity is invalid")
    if entry["signature_bundle"] != f"{expected}{SIGNATURE_SUFFIX}":
        fail(f"{mode} package signature bundle filename is invalid")
    delivery = require_exact_keys(
        entry["delivery"], {"kind", "parts"}, f"{mode} package delivery"
    )
    parts = delivery["parts"]
    if (
        delivery["kind"] not in {"single", "split"}
        or not isinstance(parts, list)
        or not parts
        or len(parts) > MAX_PACKAGE_PARTS
    ):
        fail(f"{mode} package delivery is invalid")
    if delivery["kind"] == "single" and len(parts) != 1:
        fail(f"{mode} single package delivery must have exactly one part")
    if delivery["kind"] == "split" and len(parts) < 2:
        fail(f"{mode} split package delivery must have multiple parts")
    if (
        delivery["kind"] == "single"
        and entry["size"] >= GITHUB_ASSET_LIMIT_BYTES
    ):
        fail(f"{mode} package at the release asset limit must be split")
    if (
        delivery["kind"] == "split"
        and entry["size"] < GITHUB_ASSET_LIMIT_BYTES
    ):
        fail(f"{mode} package below the release asset limit must be single")
    if delivery["kind"] == "split":
        expected_count = (
            entry["size"] + PACKAGE_PART_BYTES - 1
        ) // PACKAGE_PART_BYTES
        if len(parts) != expected_count:
            fail(f"{mode} split package part count differs from its logical size")
    part_total = 0
    for index, part_value in enumerate(parts, start=1):
        part = require_exact_keys(
            part_value,
            {"filename", "sha256", "size", "index", "count", "signature_bundle"},
            f"{mode} package part {index}",
        )
        validate_portable_path(part["filename"], f"{mode} part filename")
        require_sha256(part["sha256"], f"{mode} part SHA-256")
        require_size(part["size"], f"{mode} part", GITHUB_ASSET_LIMIT_BYTES - 1)
        if (
            type(part["index"]) is not int
            or type(part["count"]) is not int
            or part["index"] != index
            or part["count"] != len(parts)
        ):
            fail(f"{mode} package part order is invalid")
        if part["signature_bundle"] != f"{part['filename']}{SIGNATURE_SUFFIX}":
            fail(f"{mode} package part signature filename is invalid")
        if delivery["kind"] == "split" and (
            (index < len(parts) and part["size"] != PACKAGE_PART_BYTES)
            or (index == len(parts) and part["size"] > PACKAGE_PART_BYTES)
        ):
            fail(f"{mode} split package part size is not canonical")
        part_total += part["size"]
    if part_total != entry["size"]:
        fail(f"{mode} package parts do not cover the logical archive")
    if delivery["kind"] == "single":
        part = parts[0]
        if (
            part["filename"] != entry["filename"]
            or part["sha256"] != entry["sha256"]
            or part["signature_bundle"] != entry["signature_bundle"]
        ):
            fail(f"{mode} single package delivery differs from its archive")
    else:
        width = max(3, len(str(len(parts))))
        for index, part in enumerate(parts, start=1):
            expected_part = (
                f"{entry['filename']}.part-{index:0{width}d}-of-{len(parts):0{width}d}"
            )
            if part["filename"] != expected_part:
                fail(f"{mode} split package part filename is invalid")
    sbom = require_exact_keys(
        entry["sbom"],
        {"filename", "sha256", "size", "format", "signature_bundle"},
        f"{mode} SBOM",
    )
    expected_sbom = f"{TARGET_IDS[mode]}.{sbom['sha256']}{SPDX_SUFFIX}"
    if (
        sbom["filename"] != expected_sbom
        or sbom["format"] != SPDX_FORMAT
        or sbom["signature_bundle"] != f"{expected_sbom}{SIGNATURE_SUFFIX}"
    ):
        fail(f"{mode} SBOM metadata is invalid")
    require_sha256(sbom["sha256"], f"{mode} SBOM SHA-256")
    require_size(sbom["size"], f"{mode} SBOM")
    provenance = require_exact_keys(
        entry["provenance"],
        {
            "filename",
            "sha256",
            "size",
            "predicate_type",
            "signature_bundle",
            "attestation_bundle",
        },
        f"{mode} provenance",
    )
    expected_provenance = f"{expected}{PROVENANCE_SUFFIX}"
    if (
        provenance["filename"] != expected_provenance
        or provenance["predicate_type"] != SLSA_PREDICATE_TYPE
        or provenance["signature_bundle"]
        != f"{expected_provenance}{SIGNATURE_SUFFIX}"
        or provenance["attestation_bundle"]
        != f"{expected}{ATTESTATION_SUFFIX}"
    ):
        fail(f"{mode} provenance metadata is invalid")
    require_sha256(provenance["sha256"], f"{mode} provenance SHA-256")
    require_size(provenance["size"], f"{mode} provenance")
    return entry


def validate_release_manifest(
    manifest: Any,
    *,
    args: argparse.Namespace | None = None,
) -> dict[str, Any]:
    value = require_exact_keys(
        manifest,
        {
            "$schema",
            "format_version",
            "kind",
            "release",
            "release_tag",
            "platform",
            "source",
            "builder",
            "control_release",
            "connector_release",
            "oci_export",
            "consumer_verifier",
            "packages",
            "checksums",
            "signing",
        },
        "server package manifest",
    )
    if (
        value["$schema"] != SCHEMA_ID
        or type(value["format_version"]) is not int
        or value["format_version"] != FORMAT_VERSION
    ):
        fail("server package manifest schema is unsupported")
    if value["kind"] != MANIFEST_KIND:
        fail("server package manifest kind is unsupported")
    release = validate_release(value["release"])
    if value["release_tag"] != f"control-v{release}" or value["platform"] != PLATFORM:
        fail("server package manifest release identity is invalid")
    source = require_exact_keys(
        value["source"], {"repository", "commit", "ref"}, "package source"
    )
    validate_repository(source["repository"])
    validate_commit(source["commit"])
    if source["ref"] != f"refs/tags/{value['release_tag']}":
        fail("server package source ref differs from its tag")
    builder = require_exact_keys(
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
        builder["workflow_identity"], "package builder workflow identity"
    )
    invocation_id = require_string(
        builder["invocation_id"], "package builder invocation id"
    )
    if re.fullmatch(
        rf"{re.escape(source['repository'])}/\.github/workflows/"
        rf"[A-Za-z0-9._-]+\.ya?ml@refs/tags/{re.escape(value['release_tag'])}",
        workflow_identity,
    ) is None:
        fail("package builder workflow identity is invalid")
    if re.fullmatch(
        rf"{re.escape(source['repository'])}/actions/runs/"
        r"[1-9][0-9]*/attempts/[1-9][0-9]*",
        invocation_id,
    ) is None:
        fail("package builder invocation id is invalid")
    if (
        builder["workflow_sha"] != source["commit"]
        or builder["workflow_trigger"] != "push"
    ):
        fail("server package builder identity differs from source")
    builder_cosign_version = validate_tool_version(
        builder["cosign_version"], "package builder Cosign version"
    )
    validate_tool_version(builder["syft_version"], "package builder Syft version")
    control = require_exact_keys(
        value["control_release"],
        {"lock", "bundle", "evidence_sha256s"},
        "Control release binding",
    )
    control_lock = validate_file_record(control["lock"], "Control image lock")
    control_bundle = validate_file_record(
        control["bundle"], "Control image lock bundle"
    )
    if (
        control_lock["filename"] != "control-images.lock.json"
        or control_bundle["filename"] != "control-images.lock.sigstore.json"
    ):
        fail("Control release lock filenames are invalid")
    evidence = control["evidence_sha256s"]
    if not isinstance(evidence, dict) or set(evidence) != CONTROL_EVIDENCE_FILENAMES:
        fail("Control release evidence binding must contain exactly eleven files")
    for name, digest in evidence.items():
        if PurePosixPath(validate_portable_path(name)).parent != PurePosixPath("."):
            fail("Control evidence filename must be one basename")
        require_sha256(digest, f"Control evidence {name}")
    if (
        evidence[control_lock["filename"]] != control_lock["sha256"]
        or evidence[control_bundle["filename"]] != control_bundle["sha256"]
    ):
        fail("Control lock records differ from the exact evidence digest map")
    connector_release = validate_connector_release_record(
        value["connector_release"], "Connector release binding"
    )
    oci_export = validate_file_record(
        value["oci_export"], "OCI export receipt binding"
    )
    if oci_export["filename"] != OCI_EXPORT_RECEIPT_FILENAME:
        fail("OCI export receipt filename is invalid")
    consumer_verifier = validate_file_record(
        value["consumer_verifier"], "standalone consumer verifier"
    )
    if consumer_verifier["filename"] != CONSUMER_VERIFIER_FILENAME:
        fail("standalone consumer verifier filename is invalid")
    packages = require_exact_keys(
        value["packages"], set(MODES), "server package set"
    )
    for mode in MODES:
        validate_package_entry(packages[mode], mode, release)
    checksums = require_exact_keys(
        value["checksums"], {"filename", "signature_bundle"}, "checksums"
    )
    if checksums != {
        "filename": CHECKSUMS_FILENAME,
        "signature_bundle": f"{CHECKSUMS_FILENAME}{SIGNATURE_SUFFIX}",
    }:
        fail("server package checksums metadata is invalid")
    signing = require_exact_keys(
        value["signing"], {"cosign_version", "manifest_bundle"}, "signing"
    )
    signing_cosign_version = validate_tool_version(
        signing["cosign_version"], "package signing Cosign version"
    )
    if signing["manifest_bundle"] != f"{MANIFEST_FILENAME}{SIGNATURE_SUFFIX}":
        fail("server package manifest signature filename is invalid")
    if signing_cosign_version != builder_cosign_version:
        fail("package builder and signing Cosign versions differ")
    if args is not None:
        if (
            source
            != {
                "repository": args.expected_source_repository,
                "commit": args.expected_source_commit,
                "ref": f"refs/tags/{args.expected_release_tag}",
            }
            or value["release_tag"] != args.expected_release_tag
            or builder["workflow_identity"] != args.certificate_identity
            or builder["workflow_sha"] != args.certificate_github_workflow_sha
            or builder["workflow_trigger"]
            != args.certificate_github_workflow_trigger
            or connector_release["source_repository"]
            != args.expected_connector_repository
            or connector_release["source_commit"]
            != args.expected_connector_source_commit
            or connector_release["tag"] != args.expected_connector_tag
            or connector_release["release_id"]
            != args.expected_connector_release_id
            or connector_release["workflow_run_id"]
            != args.expected_connector_workflow_run_id
            or connector_release["workflow_run_attempt"]
            != args.expected_connector_workflow_run_attempt
            or signing["cosign_version"] != args.expected_cosign_version
        ):
            fail("signed server package manifest differs from external trust policy")
    return value


def verify_hash_record(root: Path, record: dict[str, Any], label: str) -> Path:
    path = root / record["filename"]
    handle, metadata = open_regular(path, label, maximum=MAX_PACKAGE_BYTES)
    try:
        digest = sha256_stream(handle)
    finally:
        handle.close()
    if metadata.st_size != record["size"] or digest != record["sha256"]:
        fail(f"{label} size or SHA-256 differs from the signed manifest")
    return path


def validate_package_sbom(
    path: Path,
    archive_record: dict[str, Any],
    *,
    mode: str,
    release: str,
    archive_path: Path | None = None,
) -> None:
    value = strict_json(
        read_regular(path, f"{mode} SPDX SBOM"),
        f"{mode} SPDX SBOM",
        canonical=True,
    )
    if (
        not isinstance(value, dict)
        or value.get("spdxVersion") != "SPDX-2.3"
        or value.get("dataLicense") != "CC0-1.0"
    ):
        fail(f"{mode} package SBOM is not SPDX 2.3 JSON")
    packages = value.get("packages")
    files = value.get("files")
    if not isinstance(packages, list) or len(packages) < 4:
        fail(f"{mode} package SBOM lacks the server and image dependency packages")
    if not isinstance(files, list) or len(files) != 1:
        fail(f"{mode} package SBOM does not describe exactly one package artifact")
    server_packages = [
        item
        for item in packages
        if isinstance(item, dict)
        and item.get("SPDXID") == "SPDXRef-Package-ServerPackage"
    ]
    if len(server_packages) != 1:
        fail(f"{mode} package SBOM must describe exactly one server package")
    package = server_packages[0]
    file_value = files[0]
    if (
        package.get("name") != f"sub2api-codex-control-server-{mode}"
        or package.get("versionInfo") != release
        or package.get("filesAnalyzed") is not True
        or package.get("primaryPackagePurpose") != "INSTALL"
        or file_value.get("fileName") != f"./{archive_record['filename']}"
        or file_value.get("SPDXID") != "SPDXRef-File-ServerPackage"
    ):
        fail(f"{mode} package SBOM identity is invalid")
    checksum_values = file_value.get("checksums")
    if not isinstance(checksum_values, list) or len(checksum_values) != 2:
        fail(f"{mode} package SBOM must bind SHA-1 and SHA-256")
    checksums: dict[str, str] = {}
    for item in checksum_values:
        if not isinstance(item, dict) or set(item) != {"algorithm", "checksumValue"}:
            fail(f"{mode} package SBOM file checksum is invalid")
        algorithm = item["algorithm"]
        checksum = item["checksumValue"]
        if algorithm in checksums:
            fail(f"{mode} package SBOM repeats {algorithm}")
        checksums[algorithm] = checksum
    if (
        checksums.get("SHA256") != archive_record["sha256"]
        or not isinstance(checksums.get("SHA1"), str)
        or re.fullmatch(r"[0-9a-f]{40}", checksums["SHA1"]) is None
    ):
        fail(f"{mode} package SBOM does not bind the archive checksums")
    if archive_path is not None and sha1_file(archive_path) != checksums["SHA1"]:
        fail(f"{mode} package SBOM SHA-1 differs from the package bytes")
    verification = package.get("packageVerificationCode")
    if verification != {
        "packageVerificationCodeValue": spdx_verification_code(checksums["SHA1"])
    }:
        fail(f"{mode} package SPDX verification code is invalid")
    dependency_ids: set[str] = set()
    component_coverage: set[str] = set()
    for dependency in packages:
        if dependency is package:
            continue
        if not isinstance(dependency, dict):
            fail(f"{mode} package SBOM dependency is invalid")
        dependency_id = dependency.get("SPDXID")
        if not isinstance(dependency_id, str) or dependency_id in dependency_ids:
            fail(f"{mode} package SBOM dependency identifier is invalid")
        dependency_ids.add(dependency_id)
        for component in COMPONENTS:
            prefix = f"SPDXRef-Dependency-{component.replace('-', '')}-"
            if dependency_id.startswith(prefix):
                component_coverage.add(component)
    if component_coverage != set(COMPONENTS):
        fail(f"{mode} package SBOM does not cover all three image dependency sets")
    relationships = value.get("relationships")
    if not isinstance(relationships, list):
        fail(f"{mode} package SBOM has no relationships")
    relationship_set = {
        (
            item.get("spdxElementId"),
            item.get("relationshipType"),
            item.get("relatedSpdxElement"),
        )
        for item in relationships
        if isinstance(item, dict)
    }
    required_relationships = {
        (
            "SPDXRef-DOCUMENT",
            "DESCRIBES",
            "SPDXRef-Package-ServerPackage",
        ),
        (
            "SPDXRef-Package-ServerPackage",
            "CONTAINS",
            "SPDXRef-File-ServerPackage",
        ),
        *(
            ("SPDXRef-Package-ServerPackage", "DEPENDS_ON", dependency_id)
            for dependency_id in dependency_ids
        ),
    }
    if relationship_set != required_relationships or len(relationships) != len(
        required_relationships
    ):
        fail(f"{mode} package SBOM dependency relationships are not exact")


def validate_authenticated_package_sbom_dependencies(
    path: Path,
    *,
    mode: str,
    control_release_dir: Path,
    lock: dict[str, Any],
) -> None:
    value = strict_json(
        read_regular(path, f"{mode} SPDX SBOM"),
        f"{mode} SPDX SBOM",
        canonical=True,
    )
    packages = value.get("packages") if isinstance(value, dict) else None
    if not isinstance(packages, list) or not packages:
        fail(f"{mode} package SBOM package inventory is invalid")
    if (
        not isinstance(packages[0], dict)
        or packages[0].get("SPDXID") != "SPDXRef-Package-ServerPackage"
    ):
        fail(f"{mode} package SBOM root package is not first")
    expected = image_sbom_dependencies(control_release_dir, lock)
    if packages[1:] != expected:
        fail(
            f"{mode} package SBOM dependencies differ from the authenticated "
            "Control image SBOMs"
        )


def validate_package_provenance(
    path: Path,
    archive_record: dict[str, Any],
    *,
    mode: str,
    manifest: dict[str, Any],
) -> None:
    value = strict_json(
        read_regular(path, f"{mode} SLSA provenance"),
        f"{mode} SLSA provenance",
        canonical=True,
    )
    if not isinstance(value, dict) or set(value) != {"_type", "subject", "predicateType", "predicate"}:
        fail(f"{mode} package provenance shape is invalid")
    if value["_type"] != "https://in-toto.io/Statement/v1" or value["predicateType"] != SLSA_PREDICATE_TYPE:
        fail(f"{mode} package provenance type is invalid")
    if value["subject"] != [
        {"name": archive_record["filename"], "digest": {"sha256": archive_record["sha256"]}}
    ]:
        fail(f"{mode} package provenance subject is invalid")
    predicate = require_exact_keys(
        value["predicate"], {"buildDefinition", "runDetails"},
        f"{mode} package provenance predicate",
    )
    definition = require_exact_keys(
        predicate["buildDefinition"],
        {
            "buildType",
            "externalParameters",
            "internalParameters",
            "resolvedDependencies",
        },
        f"{mode} package provenance build definition",
    )
    details = require_exact_keys(
        predicate["runDetails"],
        {"builder", "metadata", "byproducts"},
        f"{mode} package provenance run details",
    )
    external = definition.get("externalParameters")
    connector = manifest["connector_release"]
    if external != {
        "mode": mode,
        "platform": PLATFORM,
        "release": manifest["release"],
        "release_tag": manifest["release_tag"],
        "source": manifest["source"],
        "connector_release": {
            key: connector[key]
            for key in (
                "source_repository",
                "source_commit",
                "version",
                "tag",
                "release_id",
                "workflow_run_id",
                "workflow_run_attempt",
            )
        },
    }:
        fail(f"{mode} package provenance parameters differ from the manifest")
    if definition.get("buildType") != BUILD_TYPE:
        fail(f"{mode} package provenance build type is invalid")
    internal = require_exact_keys(
        definition["internalParameters"],
        {"package_manifest_sha256", "source_date_epoch"},
        f"{mode} package provenance internal parameters",
    )
    source_date_epoch = internal["source_date_epoch"]
    if (
        internal["package_manifest_sha256"]
        != archive_record["internal_manifest_sha256"]
        or type(source_date_epoch) is not int
        or not 0 < source_date_epoch <= (1 << 32) - 1
    ):
        fail(f"{mode} package provenance internal parameters are invalid")
    dependencies = definition.get("resolvedDependencies")
    if not isinstance(dependencies, list):
        fail(f"{mode} package provenance has no resolved dependencies")
    dependency_uris = {
        item.get("uri") for item in dependencies if isinstance(item, dict)
    }
    required_uris = {
        f"git+{manifest['source']['repository']}@{manifest['source']['commit']}",
        "file:control-images.lock.json",
        "file:source.tar",
        "file:source-files.manifest",
        "file:source-attestation.json",
        f"file:{CONNECTOR_METADATA_FILENAME}",
        f"file:{CONNECTOR_METADATA_BUNDLE_FILENAME}",
        f"file:{CONNECTOR_AGGREGATE_FILENAME}",
        f"file:{CONNECTOR_AGGREGATE_BUNDLE_FILENAME}",
    }
    if mode == "offline":
        required_uris.add(f"file:{OCI_EXPORT_RECEIPT_FILENAME}")
    if not required_uris.issubset(dependency_uris):
        fail(f"{mode} package provenance lacks required source materials")
    dependency_by_uri = {
        item["uri"]: item
        for item in dependencies
        if isinstance(item, dict) and isinstance(item.get("uri"), str)
    }
    for role in ("metadata", "metadata_bundle", "aggregate", "aggregate_bundle"):
        record = connector[role]
        if dependency_by_uri.get(f"file:{record['filename']}") != {
            "uri": f"file:{record['filename']}",
            "digest": {"sha256": record["sha256"]},
        }:
            fail(f"{mode} package provenance Connector material is invalid: {role}")
    if mode == "offline":
        oci_export = manifest["oci_export"]
        if dependency_by_uri.get(f"file:{OCI_EXPORT_RECEIPT_FILENAME}") != {
            "uri": f"file:{OCI_EXPORT_RECEIPT_FILENAME}",
            "digest": {"sha256": oci_export["sha256"]},
        }:
            fail("offline package provenance OCI export material is invalid")
    if details["builder"] != {"id": manifest["builder"]["workflow_identity"]}:
        fail(f"{mode} package provenance builder is invalid")
    if details["metadata"] != {
        "invocationId": manifest["builder"]["invocation_id"],
        "startedOn": iso8601(source_date_epoch),
        "finishedOn": iso8601(source_date_epoch),
    }:
        fail(f"{mode} package provenance run metadata is invalid")
    if details["byproducts"] != [
        {
            "name": PACKAGE_MANIFEST_FILENAME,
            "digest": {
                "sha256": archive_record["internal_manifest_sha256"]
            },
        }
    ]:
        fail(f"{mode} package provenance byproducts are invalid")


def validate_embedded_provenance_materials(
    path: Path,
    *,
    package_root: Path,
    package_manifest: dict[str, Any],
) -> None:
    mode = package_manifest["mode"]
    statement = strict_json(
        read_regular(path, f"{mode} SLSA provenance"),
        f"{mode} SLSA provenance",
        canonical=True,
    )
    try:
        dependencies = statement["predicate"]["buildDefinition"][
            "resolvedDependencies"
        ]
    except (KeyError, TypeError) as exc:
        raise ServerPackageError(
            f"{mode} package provenance dependencies are invalid"
        ) from exc
    if not isinstance(dependencies, list):
        fail(f"{mode} package provenance dependencies are invalid")
    package_manifest_sha256 = sha256_file(
        package_root / PACKAGE_MANIFEST_FILENAME
    )
    try:
        definition = statement["predicate"]["buildDefinition"]
        details = statement["predicate"]["runDetails"]
    except (KeyError, TypeError) as exc:
        raise ServerPackageError(
            f"{mode} package provenance build details are invalid"
        ) from exc
    if definition.get("internalParameters") != {
        "package_manifest_sha256": package_manifest_sha256,
        "source_date_epoch": package_manifest["source_date_epoch"],
    }:
        fail(f"{mode} package provenance differs from the embedded package identity")
    if details != {
        "builder": {"id": package_manifest["builder"]["workflow_identity"]},
        "metadata": {
            "invocationId": package_manifest["builder"]["invocation_id"],
            "startedOn": iso8601(package_manifest["source_date_epoch"]),
            "finishedOn": iso8601(package_manifest["source_date_epoch"]),
        },
        "byproducts": [
            {
                "name": PACKAGE_MANIFEST_FILENAME,
                "digest": {"sha256": package_manifest_sha256},
            }
        ],
    }:
        fail(f"{mode} package provenance run details differ from the package")
    observed: dict[str, dict[str, Any]] = {}
    for value in dependencies:
        item = require_exact_keys(
            value, {"uri", "digest"}, f"{mode} provenance material"
        )
        uri = require_string(item["uri"], f"{mode} provenance material URI")
        if uri in observed:
            fail(f"{mode} package provenance repeats material {uri}")
        digest = item["digest"]
        if not isinstance(digest, dict) or len(digest) != 1:
            fail(f"{mode} package provenance material digest is invalid: {uri}")
        observed[uri] = item

    expected: dict[str, dict[str, Any]] = {}

    def add(uri: str, algorithm: str, digest: str) -> None:
        if algorithm == "sha256":
            require_sha256(digest, f"provenance material {uri}")
        elif algorithm == "gitCommit":
            validate_commit(digest)
        else:
            fail(f"unsupported provenance digest algorithm: {algorithm}")
        expected[uri] = {"uri": uri, "digest": {algorithm: digest}}

    source = package_manifest["source"]
    add(
        f"git+{source['repository']}@{source['commit']}",
        "gitCommit",
        source["commit"],
    )
    add(
        "file:control-images.lock.json",
        "sha256",
        package_manifest["control_release"]["lock_sha256"],
    )
    for role in ("archive", "manifest", "attestation"):
        record = package_manifest["source_bundle"][role]
        add(f"file:{record['filename']}", "sha256", record["sha256"])
    for role in ("metadata", "metadata_bundle", "aggregate", "aggregate_bundle"):
        record = package_manifest["connector_release"][role]
        add(f"file:{record['filename']}", "sha256", record["sha256"])

    lock = strict_json(
        read_regular(
            package_root / "release/control-images.lock.json",
            "embedded Control image lock",
            maximum=MAX_JSON_BYTES,
        ),
        "embedded Control image lock",
        canonical=True,
    )
    for component in COMPONENTS:
        image = lock["images"][component]
        add(
            f"pkg:oci/{image['repository']}@{image['digest']}",
            "sha256",
            image["digest"].removeprefix("sha256:"),
        )
        if mode == "offline":
            packaged = package_manifest["images"][component]
            add(
                f"file:{packaged['archive']['filename']}",
                "sha256",
                packaged["archive"]["sha256"],
            )
            add(
                f"file:{packaged['identity']['filename']}",
                "sha256",
                packaged["identity"]["sha256"],
            )
            identity = strict_json(
                read_regular(
                    package_root / packaged["identity"]["filename"],
                    f"{component} OCI identity",
                    maximum=MAX_JSON_BYTES,
                ),
                f"{component} OCI identity",
                canonical=True,
            )
            for role in ("manifest", "config"):
                digest = require_string(
                    identity[f"{role}_digest"], f"{component} {role} digest"
                )
                if re.fullmatch(r"sha256:[0-9a-f]{64}", digest) is None:
                    fail(f"{component} OCI {role} digest is invalid")
                add(
                    f"oci:{image['reference']}#{role}",
                    "sha256",
                    digest.removeprefix("sha256:"),
                )
    if mode == "offline":
        record = package_manifest["oci_export"]
        add(f"file:{record['filename']}", "sha256", record["sha256"])
    if observed != expected:
        fail(
            f"{mode} package provenance material closure differs from the "
            "embedded signed package"
        )


def verify_blob_signature(
    args: argparse.Namespace, blob: Path, bundle: Path, label: str
) -> None:
    run_checked(
        [
            args.cosign,
            "verify-blob",
            "--bundle",
            str(bundle),
            *trust_arguments(args),
            str(blob),
        ]
    )


def verify_package_attestation(
    args: argparse.Namespace, package: dict[str, Any], label: str
) -> None:
    release_dir = Path(args.release_dir)
    bundle_path = release_dir / package["provenance"]["attestation_bundle"]
    run_checked(
        [
            args.cosign,
            "verify-blob-attestation",
            "--bundle",
            str(bundle_path),
            *trust_arguments(args),
            "--type",
            "slsaprovenance1",
            "--digest",
            package["sha256"],
            "--digestAlg",
            "sha256",
        ]
    )
    bundle = require_exact_keys(
        strict_json(
            read_regular(bundle_path, f"{label} attestation bundle"),
            f"{label} attestation bundle",
        ),
        {"mediaType", "verificationMaterial", "dsseEnvelope"},
        f"{label} attestation bundle",
    )
    if bundle["mediaType"] != "application/vnd.dev.sigstore.bundle.v0.3+json":
        fail(f"{label} attestation bundle media type is invalid")
    if not isinstance(bundle["verificationMaterial"], dict):
        fail(f"{label} attestation verification material is invalid")
    envelope = require_exact_keys(
        bundle["dsseEnvelope"],
        {"payload", "payloadType", "signatures"},
        f"{label} DSSE envelope",
    )
    if envelope["payloadType"] != "application/vnd.in-toto+json":
        fail(f"{label} DSSE payload type is invalid")
    if not isinstance(envelope["signatures"], list) or not envelope["signatures"]:
        fail(f"{label} DSSE envelope has no signature")
    payload = envelope["payload"]
    if not isinstance(payload, str):
        fail(f"{label} DSSE payload is not base64 text")
    try:
        payload_raw = base64.b64decode(payload, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ServerPackageError(f"{label} DSSE payload is not strict base64") from exc
    statement = strict_json(payload_raw, f"{label} DSSE statement")
    provenance_raw = read_regular(
        release_dir / package["provenance"]["filename"],
        f"{label} provenance statement",
    )
    strict_json(provenance_raw, f"{label} provenance statement", canonical=True)
    if canonical_json(statement) != provenance_raw:
        fail(f"{label} DSSE statement differs from the published provenance")


def validate_single_gzip(path: Path) -> tuple[int, int]:
    source, before = open_regular(path, "server package archive")
    try:
        header = source.read(10)
        if len(header) != 10 or header[:4] != b"\x1f\x8b\x08\x00":
            fail("server package does not have a canonical gzip header")
        epoch = int.from_bytes(header[4:8], "little")
        if header[8:] != b"\x02\xff":
            fail("server package gzip compression metadata is not canonical")
        source.seek(0)
        decoder = zlib.decompressobj(wbits=31)
        expanded = 0
        ended = False
        while block := source.read(1024 * 1024):
            pending = block
            while pending:
                output = decoder.decompress(pending, 1024 * 1024)
                expanded += len(output)
                if expanded > MAX_PACKAGE_EXPANDED_BYTES:
                    fail("server package expanded size exceeds its accepted range")
                pending = decoder.unconsumed_tail
                if decoder.eof:
                    if decoder.unused_data or pending or source.read(1):
                        fail("server package contains concatenated or trailing gzip data")
                    ended = True
                    break
            if ended:
                break
        if not decoder.eof:
            fail("server package gzip stream is truncated")
        after = os.fstat(source.fileno())
        if stable_fields(before) != stable_fields(after):
            fail("server package archive changed while decompressed")
        return epoch, expanded
    finally:
        source.close()


def validate_internal_manifest(
    value: Any,
    *,
    mode: str,
    external_manifest: dict[str, Any],
    actual_records: list[dict[str, Any]],
) -> dict[str, Any]:
    package = require_exact_keys(
        value,
        {
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
        },
        "internal package manifest",
    )
    if (
        package["$schema"] != PACKAGE_SCHEMA_ID
        or type(package["format_version"]) is not int
        or package["format_version"] != FORMAT_VERSION
    ):
        fail("internal package manifest schema is unsupported")
    if (
        package["product"] != "sub2api-codex-control-server"
        or package["release"] != external_manifest["release"]
        or package["release_tag"] != external_manifest["release_tag"]
        or package["mode"] != mode
        or package["platform"] != PLATFORM
        or package["source"] != external_manifest["source"]
        or package["builder"] != external_manifest["builder"]
    ):
        fail("internal package identity differs from the signed release manifest")
    if (
        type(package["source_date_epoch"]) is not int
        or not 0 < package["source_date_epoch"] <= (1 << 32) - 1
    ):
        fail("internal package source epoch is invalid")
    require_sha256(package["common_payload_sha256"], "common payload SHA-256")
    lifecycle = require_exact_keys(
        package["lifecycle"], set(REQUIRED_LIFECYCLE), "package lifecycle"
    )
    if lifecycle != REQUIRED_LIFECYCLE:
        fail("package lifecycle entry points are not the fixed inventory")
    required_paths = package["required_source_paths"]
    if (
        not isinstance(required_paths, list)
        or not required_paths
        or required_paths != sorted(set(required_paths))
    ):
        fail("required source path inventory is invalid")
    for path in required_paths:
        validate_portable_path(path, "required source path")
    files = package["files"]
    if not isinstance(files, list) or not files or len(files) > MAX_PACKAGE_FILES:
        fail("internal package file inventory is invalid")
    validated_files: list[dict[str, Any]] = []
    seen: set[str] = set()
    for record in files:
        item = require_exact_keys(
            record, {"mode", "path", "sha256", "size"}, "package file record"
        )
        path = validate_portable_path(item["path"])
        if path in seen:
            fail(f"internal package manifest repeats {path}")
        seen.add(path)
        if item["mode"] not in {"0444", "0555"}:
            fail(f"internal package file mode is invalid: {path}")
        require_sha256(item["sha256"], f"package file {path}")
        if type(item["size"]) is not int or not 0 <= item["size"] <= MAX_MEMBER_BYTES:
            fail(f"internal package file size is invalid: {path}")
        validated_files.append(item)
    if [item["path"] for item in validated_files] != sorted(seen):
        fail("internal package file inventory is not sorted")
    if validated_files != actual_records:
        fail("server package archive differs from its internal exact inventory")
    if any(f"source/{path}" not in seen for path in required_paths):
        fail("server package lacks required deployment source content")
    verifier_source = next(
        (
            item
            for item in files
            if item["path"]
            == "source/deploy/server-package/server_package.py"
        ),
        None,
    )
    if (
        verifier_source is None
        or verifier_source["sha256"]
        != external_manifest["consumer_verifier"]["sha256"]
        or verifier_source["size"]
        != external_manifest["consumer_verifier"]["size"]
    ):
        fail("standalone verifier differs from the signed package source")
    for entrypoint in REQUIRED_LIFECYCLE.values():
        matching = [item for item in files if item["path"] == entrypoint]
        if len(matching) != 1 or matching[0]["mode"] != "0555":
            fail(f"package lifecycle entry point is missing or non-executable: {entrypoint}")
    if not any(item["path"].startswith("source/migrations/") for item in files):
        fail("server package contains no migrations")
    if not any(item["path"].startswith("source/deploy/nginx/") for item in files):
        fail("server package contains no Nginx inputs")
    control = require_exact_keys(
        package["control_release"],
        {"evidence", "lock_sha256", "bundle_sha256"},
        "embedded Control release",
    )
    if (
        control["lock_sha256"] != external_manifest["control_release"]["lock"]["sha256"]
        or control["bundle_sha256"]
        != external_manifest["control_release"]["bundle"]["sha256"]
    ):
        fail("embedded Control release hashes differ from the release manifest")
    connector_release = validate_connector_release_record(
        package["connector_release"], "embedded Connector release"
    )
    if connector_release != external_manifest["connector_release"]:
        fail("embedded Connector release differs from the signed release manifest")
    for role in ("metadata", "metadata_bundle", "aggregate", "aggregate_bundle"):
        connector_file = connector_release[role]
        matching = next(
            (item for item in files if item["path"] == connector_file["filename"]),
            None,
        )
        if (
            matching is None
            or matching["mode"] != "0444"
            or matching["sha256"] != connector_file["sha256"]
            or matching["size"] != connector_file["size"]
        ):
            fail(f"embedded Connector evidence differs from package bytes: {role}")
    if mode == "online":
        if package["oci_export"] is not None or any(
            item["path"] == OCI_EXPORT_RECEIPT_FILENAME for item in files
        ):
            fail("online server package contains an OCI export receipt")
    else:
        oci_export = validate_file_record(
            package["oci_export"], "embedded OCI export receipt"
        )
        matching_receipt = next(
            (item for item in files if item["path"] == OCI_EXPORT_RECEIPT_FILENAME),
            None,
        )
        if (
            oci_export != external_manifest["oci_export"]
            or oci_export["filename"] != OCI_EXPORT_RECEIPT_FILENAME
            or matching_receipt is None
            or matching_receipt["mode"] != "0444"
            or matching_receipt["sha256"] != oci_export["sha256"]
            or matching_receipt["size"] != oci_export["size"]
        ):
            fail("embedded OCI export receipt differs from the signed release")
    evidence = control["evidence"]
    expected_evidence = external_manifest["control_release"]["evidence_sha256s"]
    if not isinstance(evidence, dict) or set(evidence) != set(expected_evidence):
        fail("embedded Control evidence inventory differs from the release manifest")
    for name, record in evidence.items():
        validate_file_record(record, f"embedded Control evidence {name}")
        matching = next(
            (item for item in files if item["path"] == f"release/{name}"),
            None,
        )
        if (
            record["filename"] != f"release/{name}"
            or record["sha256"] != expected_evidence[name]
            or matching is None
            or record["sha256"] != matching["sha256"]
            or record["size"] != matching["size"]
        ):
            fail(f"embedded Control evidence binding is invalid: {name}")
    image_trust = require_exact_keys(
        package["image_trust"],
        {"trusted_root", "components"},
        "offline-capable image trust closure",
    )
    trusted_root = validate_file_record(
        image_trust["trusted_root"], "Sigstore trusted root"
    )
    if trusted_root["filename"] != "image-trust/trusted_root.json":
        fail("Sigstore trusted root filename is invalid")
    component_trust = require_exact_keys(
        image_trust["components"], set(COMPONENTS), "saved image trust components"
    )
    trust_records: dict[str, dict[str, Any]] = {}
    for component in COMPONENTS:
        records = component_trust[component]
        if not isinstance(records, list) or not records:
            fail(f"saved image trust is empty: {component}")
        previous = ""
        for record_value in records:
            record = require_exact_keys(
                record_value,
                {"mode", "path", "sha256", "size"},
                f"saved image trust record {component}",
            )
            path = validate_portable_path(record["path"], "saved image trust path")
            if not path.startswith(f"image-trust/{component}/") or path <= previous:
                fail(f"saved image trust path is invalid or unsorted: {component}")
            previous = path
            if record["mode"] != "0444":
                fail(f"saved image trust file is not read-only: {path}")
            require_sha256(record["sha256"], f"saved image trust file {path}")
            if type(record["size"]) is not int or not 0 < record["size"] <= MAX_MEMBER_BYTES:
                fail(f"saved image trust file size is invalid: {path}")
            if path in trust_records:
                fail(f"saved image trust repeats {path}")
            trust_records[path] = record
    expected_trust_paths = {trusted_root["filename"], *trust_records}
    actual_trust_files = {
        item["path"]: item
        for item in files
        if item["path"].startswith("image-trust/")
    }
    if set(actual_trust_files) != expected_trust_paths:
        fail("saved image trust metadata does not exactly cover package files")
    root_file = actual_trust_files[trusted_root["filename"]]
    if (
        root_file["sha256"] != trusted_root["sha256"]
        or root_file["size"] != trusted_root["size"]
    ):
        fail("Sigstore trusted root metadata differs from package bytes")
    for path, record in trust_records.items():
        file_value = actual_trust_files[path]
        if (
            file_value["mode"] != record["mode"]
            or file_value["sha256"] != record["sha256"]
            or file_value["size"] != record["size"]
        ):
            fail(f"saved image trust metadata differs from package bytes: {path}")
    images = require_exact_keys(package["images"], set(COMPONENTS), "package images")
    for component in COMPONENTS:
        record = images[component]
        if not isinstance(record, dict):
            fail(f"package image record is invalid: {component}")
        if mode == "online":
            expected_keys = {"acquisition", "repository", "digest", "reference"}
            require_exact_keys(record, expected_keys, f"online image {component}")
            if record["acquisition"] != "registry" or not str(record["reference"]).endswith(
                f"@{record['digest']}"
            ):
                fail(f"online image identity is invalid: {component}")
            if any(item["path"].startswith("images/") for item in files):
                fail("online server package contains offline image files")
        else:
            require_exact_keys(
                record,
                {
                    "acquisition",
                    "archive",
                    "identity",
                    "locked_digest",
                    "locked_reference",
                },
                f"offline image {component}",
            )
            if record["acquisition"] != "offline-oci":
                fail(f"offline image acquisition is invalid: {component}")
            validate_file_record(record["archive"], f"offline archive {component}")
            validate_file_record(record["identity"], f"offline identity {component}")
            if record["archive"]["filename"] != f"images/{component}.oci.tar" or record["identity"]["filename"] != f"images/{component}.identity.json":
                fail(f"offline image filenames are invalid: {component}")
    expected_common = common_payload_sha256(files)
    if package["common_payload_sha256"] != expected_common:
        fail("internal package common payload digest is invalid")
    return package


def verify_package_archive(
    archive_path: Path,
    record: dict[str, Any],
    *,
    mode: str,
    release_manifest: dict[str, Any],
) -> dict[str, Any]:
    gzip_epoch, _ = validate_single_gzip(archive_path)
    source, metadata = open_regular(archive_path, f"{mode} server package")
    archive_digest = sha256_stream(source)
    if archive_digest != record["sha256"] or metadata.st_size != record["size"]:
        source.close()
        fail(f"{mode} server package archive differs from its signed record")
    source.seek(0)
    root_name = record["filename"].removesuffix(".tar.gz")
    actual_records: list[dict[str, Any]] = []
    package_raw: bytes | None = None
    member_metadata: list[tuple[str, int]] = []
    previous = ""
    total = 0
    count = 0
    try:
        try:
            archive = tarfile.open(fileobj=source, mode="r:gz")
        except (OSError, tarfile.TarError) as exc:
            raise ServerPackageError(f"cannot parse {mode} server package: {exc}") from exc
        with archive:
            for member in archive:
                count += 1
                if count > MAX_PACKAGE_FILES + 1:
                    fail("server package has too many members")
                name = member.name
                if not name.startswith(f"{root_name}/"):
                    fail("server package member is outside its single top-level root")
                relative = validate_portable_path(name[len(root_name) + 1 :])
                if name <= previous:
                    fail("server package members are not strictly sorted")
                previous = name
                if member.type != tarfile.REGTYPE or member.islnk() or member.issym():
                    fail(f"server package member is not a regular file: {relative}")
                mode_value = member.mode
                if (
                    mode_value not in {0o444, 0o555}
                    or member.uid != 0
                    or member.gid != 0
                    or member.uname != ""
                    or member.gname != ""
                ):
                    fail(f"server package member metadata is invalid: {relative}")
                if member.size < 0 or member.size > MAX_MEMBER_BYTES:
                    fail(f"server package member size is invalid: {relative}")
                total += member.size
                if total > MAX_PACKAGE_EXPANDED_BYTES:
                    fail("server package expanded size exceeds its accepted range")
                member_metadata.append((relative, member.mtime))
                extracted = archive.extractfile(member)
                if extracted is None:
                    fail(f"server package member cannot be read: {relative}")
                digest = hashlib.sha256()
                captured = bytearray()
                observed = 0
                while block := extracted.read(1024 * 1024):
                    observed += len(block)
                    if observed > member.size:
                        fail(f"server package member exceeds its header: {relative}")
                    digest.update(block)
                    if relative == PACKAGE_MANIFEST_FILENAME:
                        if observed > MAX_JSON_BYTES:
                            fail("internal package manifest is too large")
                        captured.extend(block)
                if observed != member.size:
                    fail(f"server package member is truncated: {relative}")
                if relative == PACKAGE_MANIFEST_FILENAME:
                    if package_raw is not None:
                        fail("server package repeats its internal manifest")
                    package_raw = bytes(captured)
                else:
                    actual_records.append(
                        {
                            "mode": f"{mode_value:04o}",
                            "path": relative,
                            "sha256": digest.hexdigest(),
                            "size": observed,
                        }
                    )
        after = os.fstat(source.fileno())
        if stable_fields(metadata) != stable_fields(after):
            fail("server package archive changed while verified")
    finally:
        source.close()
    if package_raw is None:
        fail("server package lacks its internal manifest")
    if sha256_bytes(package_raw) != record["internal_manifest_sha256"]:
        fail("internal package manifest differs from the signed release manifest")
    package_value = strict_json(
        package_raw, "internal package manifest", canonical=True
    )
    package = validate_internal_manifest(
        package_value,
        mode=mode,
        external_manifest=release_manifest,
        actual_records=actual_records,
    )
    if gzip_epoch != package["source_date_epoch"]:
        fail("server package gzip epoch differs from its internal manifest")
    if any(mtime != gzip_epoch for _, mtime in member_metadata):
        fail("server package member mtime differs from its source epoch")
    return package


def safely_extract_package(
    archive_path: Path,
    destination_parent: Path,
    *,
    expected_sha256: str,
) -> Path:
    if not destination_parent.is_absolute():
        fail("package extraction parent must be absolute")
    require_owned_directory(destination_parent, "package extraction parent")
    root_name = archive_path.name.removesuffix(".tar.gz")
    destination = destination_parent / root_name
    if destination.exists() or destination.is_symlink():
        fail(f"package extraction destination already exists: {destination}")
    destination.mkdir(mode=0o700)
    created_files: list[Path] = []
    created_dirs: set[Path] = set()
    source, before = open_regular(archive_path, "verified package archive")
    try:
        archive = tarfile.open(fileobj=source, mode="r:gz")
        with archive:
            for member in archive:
                prefix = f"{root_name}/"
                if not member.name.startswith(prefix):
                    fail("package member escapes its extraction root")
                relative_text = validate_portable_path(member.name[len(prefix) :])
                if member.type != tarfile.REGTYPE:
                    fail(f"package extraction rejects non-regular member {relative_text}")
                relative = Path(*PurePosixPath(relative_text).parts)
                target = destination / relative
                parent = target.parent
                missing: list[Path] = []
                cursor = parent
                while cursor != destination and not cursor.exists():
                    missing.append(cursor)
                    cursor = cursor.parent
                if cursor != destination and (
                    not cursor.is_dir() or cursor.is_symlink()
                ):
                    fail("package extraction encountered an unsafe existing ancestor")
                for directory in reversed(missing):
                    directory.mkdir(mode=0o700)
                    created_dirs.add(directory)
                if parent == destination:
                    pass
                elif not parent.is_dir() or parent.is_symlink():
                    fail("package extraction parent is not a real directory")
                flags = (
                    os.O_WRONLY
                    | os.O_CREAT
                    | os.O_EXCL
                    | getattr(os, "O_CLOEXEC", 0)
                    | getattr(os, "O_NOFOLLOW", 0)
                )
                descriptor = os.open(target, flags, 0o600)
                created_files.append(target)
                try:
                    extracted = archive.extractfile(member)
                    if extracted is None:
                        fail(f"cannot read package member {relative_text}")
                    digest = hashlib.sha256()
                    total = 0
                    while block := extracted.read(1024 * 1024):
                        total += len(block)
                        if total > member.size:
                            fail(f"package member grew during extraction: {relative_text}")
                        digest.update(block)
                        view = memoryview(block)
                        while view:
                            written = os.write(descriptor, view)
                            if written <= 0:
                                fail("short write during package extraction")
                            view = view[written:]
                    if total != member.size:
                        fail(f"package member truncated during extraction: {relative_text}")
                    os.fchmod(descriptor, member.mode)
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
        after = os.fstat(source.fileno())
        if stable_fields(before) != stable_fields(after):
            fail("package archive changed during extraction")
        source.seek(0)
        if sha256_stream(source) != expected_sha256:
            fail("package archive digest changed during extraction")
        for directory in sorted(created_dirs, key=lambda item: len(item.parts), reverse=True):
            directory.chmod(0o555)
        destination.chmod(0o555)
        return destination
    except BaseException:
        for path in reversed(created_files):
            try:
                path.unlink()
            except FileNotFoundError:
                pass
        for directory in sorted(created_dirs, key=lambda item: len(item.parts), reverse=True):
            try:
                directory.chmod(0o700)
                directory.rmdir()
            except FileNotFoundError:
                pass
        try:
            destination.chmod(0o700)
            destination.rmdir()
        except FileNotFoundError:
            pass
        raise
    finally:
        source.close()


def verify_expanded_source(package_root: Path, lock: dict[str, Any]) -> None:
    _, source_bundle = load_control_tools()
    release = package_root / "release"
    manifest_raw = source_bundle.require_release_file(
        release / source_bundle.MANIFEST_FILENAME,
        "embedded source manifest",
        source_bundle.MAX_MANIFEST_BYTES,
    )
    records = source_bundle.parse_manifest(manifest_raw)
    expected = {record["path"]: record for record in records}
    source_root = package_root / "source"
    require_owned_directory(source_root, "expanded signed source")
    actual: set[str] = set()
    for relative, path, mode in iter_regular_tree(source_root):
        actual.add(relative)
        record = expected.get(relative)
        if record is None:
            fail(f"expanded source has an unlisted file: {relative}")
        if (
            f"{mode:04o}" != record["mode"]
            or path.stat().st_size != record["size"]
            or sha256_file(path) != record["sha256"]
        ):
            fail(f"expanded source differs from its signed manifest: {relative}")
    if actual != set(expected):
        fail(
            "expanded source inventory differs from its signed manifest; "
            f"missing={sorted(set(expected) - actual)}, extra={sorted(actual - set(expected))}"
        )
    for source_relative, package_relative in (
        ("deploy/server-package/server_package.py", "lib/server_package.py"),
        ("deploy/server-package/lifecycle.py", "lib/lifecycle.py"),
        ("deploy/server-package/INSTALL.md", "INSTALL.md"),
        (
            "deploy/server-package/config/operator.env.example",
            "config/operator.env.example",
        ),
        *(
            (f"deploy/server-package/{path}", path)
            for path in REQUIRED_LIFECYCLE.values()
        ),
    ):
        if sha256_file(source_root / source_relative) != sha256_file(
            package_root / package_relative
        ):
            fail(f"package-owned entry differs from signed source: {package_relative}")


def _verify_embedded_package_with_tools(
    args: argparse.Namespace,
    package_root: Path,
    package_manifest: dict[str, Any],
) -> dict[str, Any]:
    expected_uid = 0 if os.geteuid() == 0 else os.geteuid()
    require_owned_directory(
        package_root, "extracted server package", root=expected_uid == 0
    )
    control_images, source_bundle = load_control_tools()
    release_dir = package_root / "release"
    require_owned_directory(
        release_dir, "embedded Control release", root=expected_uid == 0
    )
    lock_path = release_dir / control_images.LOCK_FILENAME
    lock_bundle = release_dir / control_images.BUNDLE_FILENAME
    verify_blob_signature(args, lock_path, lock_bundle, "embedded Control image lock")
    lock = control_images.validate_release_directory(release_dir, expect_bundle=True)
    namespace = control_verify_namespace(args, release_dir)
    control_images.validate_external_trust(namespace, lock)
    source_assets = lock["source_bundle"]
    try:
        source_bundle.verify_bundle(
            release_dir.resolve(),
            release=lock["release"],
            repository=lock["source"]["repository"],
            commit=lock["source"]["commit"],
            attestation_sha256=source_assets["attestation"]["sha256"],
            manifest_sha256=source_assets["manifest"]["sha256"],
            archive_sha256=source_assets["archive"]["sha256"],
        )
    except source_bundle.SourceBundleError as exc:
        raise ServerPackageError(f"embedded source bundle verification failed: {exc}") from exc
    verify_expanded_source(package_root, lock)
    required_source_paths = require_server_source_closure(package_root / "source")
    if package_manifest["required_source_paths"] != required_source_paths:
        fail(
            "embedded required source closure differs from the standalone "
            "consumer policy"
        )
    embedded_args = argparse.Namespace(**vars(args))
    use_connector_inputs_from_directory(embedded_args, package_root)
    connector = verify_connector_release_inputs(embedded_args)
    if connector_release_record(connector) != package_manifest["connector_release"]:
        fail("embedded Connector evidence differs from the package manifest")
    saved = validate_image_trust_directory(package_root / "image-trust")
    verify_offline_image_trust(
        args, lock, saved, release_dir=release_dir
    )
    mode = package_manifest["mode"]
    if mode == "offline":
        packaged_archives = {
            component: package_root
            / package_manifest["images"][component]["archive"]["filename"]
            for component in COMPONENTS
        }
        oci_export_receipt = validate_oci_export_receipt(
            package_root / OCI_EXPORT_RECEIPT_FILENAME,
            image_archives=packaged_archives,
            lock=lock,
        )
        observed_identities: dict[str, dict[str, Any]] = {}
        for component in COMPONENTS:
            record = package_manifest["images"][component]
            archive = package_root / record["archive"]["filename"]
            observed = strict_oci_identity(
                archive, component=component, lock=lock
            )
            identity_path = package_root / record["identity"]["filename"]
            expected_identity = strict_json(
                read_regular(identity_path, f"{component} OCI identity"),
                f"{component} OCI identity",
                canonical=True,
            )
            if observed != expected_identity:
                fail(f"{component} offline OCI identity record differs from the archive")
            observed_identities[component] = observed
        validate_oci_remote_manifest_sizes(
            oci_export_receipt, observed_identities
        )
    else:
        for component in COMPONENTS:
            image = lock["images"][component]
            expected = {
                "acquisition": "registry",
                "digest": image["digest"],
                "reference": image["reference"],
                "repository": image["repository"],
            }
            if package_manifest["images"][component] != expected:
                fail(f"online image record differs from the signed lock: {component}")
    return lock


def verify_embedded_package(
    args: argparse.Namespace,
    package_root: Path,
    package_manifest: dict[str, Any],
) -> dict[str, Any]:
    with package_tool_root(package_root / "source"):
        return _verify_embedded_package_with_tools(
            args, package_root, package_manifest
        )


def write_verification_receipt(
    path: Path,
    *,
    args: argparse.Namespace,
    release_manifest_path: Path,
    package_record: dict[str, Any],
    package_manifest: dict[str, Any],
    extracted_root: Path,
) -> dict[str, Any]:
    receipt = {
        "$schema": RECEIPT_SCHEMA_ID,
        "format_version": FORMAT_VERSION,
        "status": "verified",
        "verified_at": int(time.time()),
        "release": package_manifest["release"],
        "release_tag": package_manifest["release_tag"],
        "mode": package_manifest["mode"],
        "platform": PLATFORM,
        "source": package_manifest["source"],
        "package": {
            "filename": package_record["filename"],
            "sha256": package_record["sha256"],
            "size": package_record["size"],
            "internal_manifest_sha256": package_record[
                "internal_manifest_sha256"
            ],
            "extracted_root": str(extracted_root),
        },
        "release_manifest": {
            "filename": MANIFEST_FILENAME,
            "sha256": sha256_file(release_manifest_path),
            "size": release_manifest_path.stat().st_size,
        },
        "trust": {
            "cosign_version": args.expected_cosign_version,
            "certificate_oidc_issuer": args.certificate_oidc_issuer,
            "certificate_identity": args.certificate_identity,
            "certificate_github_workflow_sha": (
                args.certificate_github_workflow_sha
            ),
            "certificate_github_workflow_trigger": (
                args.certificate_github_workflow_trigger
            ),
            "certificate_github_workflow_repository": (
                args.certificate_github_workflow_repository
            ),
            "certificate_github_workflow_ref": (
                args.certificate_github_workflow_ref
            ),
            "expected_source_repository": args.expected_source_repository,
            "expected_source_commit": args.expected_source_commit,
            "expected_release_tag": args.expected_release_tag,
            "expected_api_repository": args.expected_api_repository,
            "expected_pwa_repository": args.expected_pwa_repository,
            "expected_postgres_tools_repository": (
                args.expected_postgres_tools_repository
            ),
            "connector_certificate_oidc_issuer": (
                args.connector_certificate_oidc_issuer
            ),
            "connector_certificate_identity": (
                args.connector_certificate_identity
            ),
            "connector_certificate_github_workflow_sha": (
                args.connector_certificate_github_workflow_sha
            ),
            "connector_certificate_github_workflow_trigger": (
                args.connector_certificate_github_workflow_trigger
            ),
            "expected_connector_repository": (
                args.expected_connector_repository
            ),
            "expected_connector_source_commit": (
                args.expected_connector_source_commit
            ),
            "expected_connector_tag": args.expected_connector_tag,
            "expected_connector_release_id": (
                args.expected_connector_release_id
            ),
            "expected_connector_workflow_run_id": (
                args.expected_connector_workflow_run_id
            ),
            "expected_connector_workflow_run_attempt": (
                args.expected_connector_workflow_run_attempt
            ),
        },
    }
    atomic_write(path, canonical_json(receipt), mode=0o400)
    return receipt


def verify_directory_inventory(
    directory: Path, expected: set[str], label: str
) -> None:
    require_owned_directory(directory, label)
    actual: set[str] = set()
    for entry in directory.iterdir():
        if entry.name.startswith("."):
            fail(f"{label} contains an unlisted hidden entry: {entry.name}")
        handle, _ = open_regular(entry, f"{label} file {entry.name}")
        handle.close()
        actual.add(entry.name)
    if actual != expected:
        fail(
            f"{label} inventory mismatch; missing={sorted(expected - actual)}, "
            f"extra={sorted(actual - expected)}"
        )


def verify_delivery_parts(
    root: Path,
    package: dict[str, Any],
    *,
    args: argparse.Namespace | None = None,
) -> None:
    for part in package["delivery"]["parts"]:
        verify_hash_record(root, part, f"package part {part['filename']}")
        if args is not None:
            verify_blob_signature(
                args,
                root / part["filename"],
                root / part["signature_bundle"],
                f"package part {part['filename']}",
            )


@contextlib.contextmanager
def materialize_package(root: Path, package: dict[str, Any]) -> Iterator[Path]:
    parts = package["delivery"]["parts"]
    if package["delivery"]["kind"] == "single":
        yield root / parts[0]["filename"]
        return
    with tempfile.TemporaryDirectory(prefix="server-package-reassemble.") as temporary:
        target = Path(temporary) / package["filename"]
        digest = hashlib.sha256()
        total = 0
        with target.open("xb") as destination:
            for part in parts:
                source, metadata = open_regular(
                    root / part["filename"], f"package part {part['filename']}"
                )
                try:
                    while block := source.read(1024 * 1024):
                        total += len(block)
                        if total > package["size"]:
                            fail("reassembled package exceeds its signed size")
                        digest.update(block)
                        destination.write(block)
                    after = os.fstat(source.fileno())
                    if stable_fields(metadata) != stable_fields(after):
                        fail(f"package part changed while read: {part['filename']}")
                finally:
                    source.close()
            destination.flush()
            os.fsync(destination.fileno())
        target.chmod(0o600)
        if total != package["size"] or digest.hexdigest() != package["sha256"]:
            fail("reassembled package differs from its signed logical identity")
        yield target


def validate_unsigned_release_directory(
    directory: Path, manifest: dict[str, Any]
) -> None:
    verify_directory_inventory(
        directory, expected_release_files(manifest, signed=False), "unsigned server release"
    )
    checksums_raw = read_regular(
        directory / CHECKSUMS_FILENAME,
        "server package checksums",
        maximum=MAX_JSON_BYTES,
    )
    checksums = parse_checksums(checksums_raw)
    expected_checksums = set(release_content_names(manifest)) - {CHECKSUMS_FILENAME}
    if set(checksums) != expected_checksums:
        fail("server package checksums do not exactly cover physical content files")
    for name, digest in checksums.items():
        if sha256_file(directory / name) != digest:
            fail(f"server package checksum mismatch: {name}")
    verify_hash_record(
        directory, manifest["oci_export"], "OCI export receipt"
    )
    verify_hash_record(
        directory, manifest["consumer_verifier"], "standalone consumer verifier"
    )
    for mode in MODES:
        package = manifest["packages"][mode]
        verify_delivery_parts(directory, package)
        sbom_path = verify_hash_record(
            directory, package["sbom"], f"{mode} package SBOM"
        )
        verify_hash_record(
            directory, package["provenance"], f"{mode} package provenance"
        )
        validate_package_provenance(
            directory / package["provenance"]["filename"],
            package,
            mode=mode,
            manifest=manifest,
        )
        with materialize_package(directory, package) as archive:
            validate_package_sbom(
                sbom_path,
                package,
                mode=mode,
                release=manifest["release"],
                archive_path=archive,
            )
            verify_package_archive(
                archive,
                package,
                mode=mode,
                release_manifest=manifest,
            )


def sign_server_release(args: argparse.Namespace) -> None:
    output = Path(args.output_dir).resolve()
    require_owned_directory(output, "server package output directory")
    manifest_raw = read_regular(
        output / MANIFEST_FILENAME, "server package manifest", maximum=MAX_JSON_BYTES
    )
    manifest = validate_release_manifest(
        strict_json(manifest_raw, "server package manifest", canonical=True), args=args
    )
    use_connector_inputs_from_directory(args, output)
    connector = verify_connector_release_inputs(args)
    if connector_release_record(connector) != manifest["connector_release"]:
        fail("unsigned server release Connector evidence differs from its manifest")
    validate_unsigned_release_directory(output, manifest)
    control_images, _ = load_control_tools()
    if manifest["signing"]["cosign_version"] != args.expected_cosign_version:
        fail("server package signing version differs from external policy")
    control_images.verify_cosign_version(args.cosign, manifest["signing"]["cosign_version"])
    signed_blobs: set[str] = set()
    for name in signed_content_names(manifest):
        bundle = output / f"{name}{SIGNATURE_SUFFIX}"
        run_checked(
            [
                args.cosign,
                "sign-blob",
                "--yes",
                "--bundle",
                str(bundle),
                str(output / name),
            ],
            timeout=900,
        )
        signed_blobs.add(name)
    for mode in MODES:
        package = manifest["packages"][mode]
        if package["delivery"]["kind"] == "split":
            with materialize_package(output, package) as archive:
                run_checked(
                    [
                        args.cosign,
                        "sign-blob",
                        "--yes",
                        "--bundle",
                        str(output / package["signature_bundle"]),
                        str(archive),
                    ],
                    timeout=900,
                )
        run_checked(
            [
                args.cosign,
                "attest-blob",
                "--yes",
                "--bundle",
                str(output / package["provenance"]["attestation_bundle"]),
                "--statement",
                str(output / package["provenance"]["filename"]),
            ],
            timeout=900,
        )
    verify_directory_inventory(
        output, expected_release_files(manifest, signed=True), "signed server release"
    )
    for name in signed_blobs:
        verify_blob_signature(
            args,
            output / name,
            output / f"{name}{SIGNATURE_SUFFIX}",
            f"signed release asset {name}",
        )
    for mode in MODES:
        package = manifest["packages"][mode]
        args.release_dir = str(output)
        verify_package_attestation(args, package, f"{mode} package provenance")
        if package["delivery"]["kind"] == "split":
            with materialize_package(output, package) as archive:
                verify_blob_signature(
                    args,
                    archive,
                    output / package["signature_bundle"],
                    f"logical {mode} package",
                )


def verify_signed_release(args: argparse.Namespace) -> dict[str, Any]:
    directory = Path(args.release_dir).absolute()
    require_owned_directory(directory, "downloaded server release")
    verify_cosign_version(args.cosign, args.expected_cosign_version)
    manifest_path = directory / MANIFEST_FILENAME
    manifest_bundle = directory / f"{MANIFEST_FILENAME}{SIGNATURE_SUFFIX}"
    # Fixed names let the verifier authenticate this blob before trusting any JSON field.
    verify_blob_signature(
        args, manifest_path, manifest_bundle, "server package release manifest"
    )
    manifest_raw = read_regular(
        manifest_path, "server package release manifest", maximum=MAX_JSON_BYTES
    )
    manifest = validate_release_manifest(
        strict_json(manifest_raw, "server package release manifest", canonical=True),
        args=args,
    )
    if manifest["signing"]["cosign_version"] != args.expected_cosign_version:
        fail("server package manifest Cosign version differs from trusted policy")
    verify_directory_inventory(
        directory,
        expected_release_files(manifest, signed=True),
        "downloaded signed server release",
    )
    checksums_path = directory / CHECKSUMS_FILENAME
    verify_blob_signature(
        args,
        checksums_path,
        directory / f"{CHECKSUMS_FILENAME}{SIGNATURE_SUFFIX}",
        "server package checksums",
    )
    checksums = parse_checksums(
        read_regular(checksums_path, "server package checksums", maximum=MAX_JSON_BYTES)
    )
    expected_checksums = set(release_content_names(manifest)) - {CHECKSUMS_FILENAME}
    if set(checksums) != expected_checksums:
        fail("signed checksums do not exactly cover server release content")
    for name, digest in checksums.items():
        path = directory / name
        if sha256_file(path) != digest:
            fail(f"signed server package checksum mismatch: {name}")
        if name != MANIFEST_FILENAME and name in set(signed_content_names(manifest)):
            verify_blob_signature(
                args,
                path,
                directory / f"{name}{SIGNATURE_SUFFIX}",
                f"server release asset {name}",
            )
    verify_hash_record(
        directory, manifest["oci_export"], "OCI export receipt"
    )
    verify_hash_record(
        directory, manifest["consumer_verifier"], "standalone consumer verifier"
    )
    packages: dict[str, tuple[dict[str, Any], dict[str, Any]]] = {}
    for mode in MODES:
        package = manifest["packages"][mode]
        verify_delivery_parts(directory, package)
        verify_package_attestation(args, package, f"{mode} package provenance")
        sbom_path = verify_hash_record(
            directory, package["sbom"], f"{mode} package SBOM"
        )
        validate_package_provenance(
            verify_hash_record(
                directory, package["provenance"], f"{mode} package provenance"
            ),
            package,
            mode=mode,
            manifest=manifest,
        )
        with materialize_package(directory, package) as archive:
            validate_package_sbom(
                sbom_path,
                package,
                mode=mode,
                release=manifest["release"],
                archive_path=archive,
            )
            verify_blob_signature(
                args,
                archive,
                directory / package["signature_bundle"],
                f"logical {mode} package",
            )
            internal = verify_package_archive(
                archive, package, mode=mode, release_manifest=manifest
            )
            with tempfile.TemporaryDirectory(prefix=f"verify-{mode}-package.") as temporary:
                parent = Path(temporary)
                parent.chmod(0o700)
                extracted = safely_extract_package(
                    archive, parent, expected_sha256=package["sha256"]
                )
                validate_embedded_provenance_materials(
                    directory / package["provenance"]["filename"],
                    package_root=extracted,
                    package_manifest=internal,
                )
                embedded_lock = verify_embedded_package(args, extracted, internal)
                validate_authenticated_package_sbom_dependencies(
                    sbom_path,
                    mode=mode,
                    control_release_dir=extracted / "release",
                    lock=embedded_lock,
                )
        packages[mode] = (package, internal)

    if args.extract_to is not None:
        if args.mode not in MODES:
            fail("--extract-to requires exactly one --mode")
        destination_parent = Path(args.extract_to).resolve()
        package, internal = packages[args.mode]
        with materialize_package(directory, package) as archive:
            extracted = safely_extract_package(
                archive, destination_parent, expected_sha256=package["sha256"]
            )
        if args.verification_receipt is None:
            fail("--extract-to requires --verification-receipt")
        receipt_path = Path(args.verification_receipt).resolve()
        require_owned_directory(receipt_path.parent, "verification receipt parent")
        write_verification_receipt(
            receipt_path,
            args=args,
            release_manifest_path=manifest_path,
            package_record=package,
            package_manifest=internal,
            extracted_root=extracted,
        )
    return manifest


def add_external_trust_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--cosign", required=True)
    parser.add_argument("--expected-cosign-version", required=True)
    parser.add_argument("--certificate-oidc-issuer", required=True)
    parser.add_argument("--certificate-identity", required=True)
    parser.add_argument("--certificate-github-workflow-sha", required=True)
    parser.add_argument(
        "--certificate-github-workflow-trigger", default="push", required=False
    )
    parser.add_argument("--certificate-github-workflow-repository", required=True)
    parser.add_argument("--certificate-github-workflow-ref", required=True)
    parser.add_argument("--expected-source-repository", required=True)
    parser.add_argument("--expected-source-commit", required=True)
    parser.add_argument("--expected-release-tag", required=True)
    parser.add_argument("--expected-api-repository", required=True)
    parser.add_argument("--expected-pwa-repository", required=True)
    parser.add_argument("--expected-postgres-tools-repository", required=True)
    parser.add_argument("--connector-certificate-oidc-issuer", required=True)
    parser.add_argument("--connector-certificate-identity", required=True)
    parser.add_argument(
        "--connector-certificate-github-workflow-sha", required=True
    )
    parser.add_argument(
        "--connector-certificate-github-workflow-trigger",
        default="push",
        required=False,
    )
    parser.add_argument("--expected-connector-repository", required=True)
    parser.add_argument("--expected-connector-source-commit", required=True)
    parser.add_argument("--expected-connector-tag", required=True)
    parser.add_argument("--expected-connector-release-id", type=int, required=True)
    parser.add_argument(
        "--expected-connector-workflow-run-id", type=int, required=True
    )
    parser.add_argument(
        "--expected-connector-workflow-run-attempt", type=int, required=True
    )


def add_connector_input_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--connector-release-metadata", required=True)
    parser.add_argument("--connector-release-metadata-bundle", required=True)
    parser.add_argument("--connector-verification-aggregate", required=True)
    parser.add_argument(
        "--connector-verification-aggregate-bundle", required=True
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)

    build = commands.add_parser(
        "build", help="build deterministic online and offline release assets"
    )
    build.add_argument("--release-dir", required=True)
    build.add_argument("--image-trust-dir", required=True)
    build.add_argument(
        "--oci-export-receipt",
        required=True,
        help="canonical receipt emitted by the pinned OCI export helper",
    )
    build.add_argument(
        "--image-archive",
        action="append",
        default=[],
        metavar="COMPONENT=PATH",
        help="repeat exactly once for control-api, pwa, and postgres-tools",
    )
    build.add_argument("--output-dir", required=True)
    build.add_argument("--release", required=True)
    build.add_argument("--source-date-epoch", type=int, required=True)
    add_external_trust_arguments(build)
    add_connector_input_arguments(build)

    sign = commands.add_parser(
        "sign", help="sign a complete unsigned release and immediately verify it"
    )
    sign.add_argument("--output-dir", required=True)
    add_external_trust_arguments(sign)

    verify = commands.add_parser(
        "verify-release",
        help="verify a signed release without a trusted source checkout",
    )
    verify.add_argument("--release-dir", required=True)
    verify.add_argument("--extract-to")
    verify.add_argument("--mode", choices=MODES)
    verify.add_argument("--verification-receipt")
    add_external_trust_arguments(verify)

    lifecycle = commands.add_parser(
        "lifecycle", help="run one installed-package lifecycle operation"
    )
    lifecycle.add_argument(
        "lifecycle_action",
        choices=("install", "upgrade", "verify", "rollback", "uninstall"),
    )
    lifecycle.add_argument("lifecycle_arguments", nargs=argparse.REMAINDER)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "build":
            result: Any = build_server_packages(args)
        elif args.command == "sign":
            sign_server_release(args)
            result = {"status": "signed-and-verified", "output_dir": args.output_dir}
        elif args.command == "verify-release":
            if (args.extract_to is None) != (args.mode is None):
                fail("--extract-to and --mode must be supplied together")
            if args.verification_receipt is not None and args.extract_to is None:
                fail("--verification-receipt requires --extract-to")
            result = verify_signed_release(args)
        else:
            lifecycle_path = MODULE_DIR / "lifecycle.py"
            lifecycle_module = import_tool(
                lifecycle_path, "server_package_lifecycle_runtime"
            )
            lifecycle_arguments = [
                args.lifecycle_action,
                *args.lifecycle_arguments,
            ]
            return int(lifecycle_module.main(lifecycle_arguments))
    except (OSError, ServerPackageError) as exc:
        print(f"server-package: {exc}", file=sys.stderr)
        return 1
    try:
        sys.stdout.buffer.write(canonical_json(result))
    except BrokenPipeError:
        return 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
