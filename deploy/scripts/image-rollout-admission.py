#!/usr/bin/env python3
"""Fail-closed admission helpers for a bootstrap image-only rollout.

The helper is deliberately side-effect free.  It validates evidence captured by
the rollout wrapper and emits one canonical JSON object on stdout.
"""

from __future__ import annotations

import argparse
import ast
import builtins
import copy
import ctypes
import errno
import hashlib
import json
import os
import re
import stat
import sys
import types
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, NoReturn

FORMAT_VERSION = 1
TARGET_RELEASE = "0.1.0-bootstrap.20260813.1"
TARGET_VCS_REF = "d518538f6d36d0c2ff94b7b895798431ee981d6e585aac4732a6a2a2cf0ab8a9"
TARGET_MANIFEST_SHA256 = "7a5bc6f6a8988039fd9715b1ce1b37e4bc3f46b7d3eb96d772886902bb81e227"
TARGET_TRANSPORT_CHECKSUM_SHA256 = (
    "cd8109d9a3a24d39265221ebf34c69ed75d5eb03b446c8419024412c6bb53d99"
)
TARGET_READY_RECORD_SHA256 = "0ebbddff6ce9124246398402de8a84b05bf681344dedb9e24a7601d447a83851"
TARGET_BUNDLE_ID = "20260812T224530Z"
TARGET_TRANSPORT_SHA256 = "aa69279c8dafe51d596977df1197d1793ea650e52444d5bad0cdcbe987f00fe7"
TARGET_SCHEMA_SHA256 = "3d247f26e2faa54dbf2b9865bfdafa9e5f80bcf2a1a872a0401db0bf4add3e73"
TARGET_TOOL_OWNER_UID = 0
TARGET_COMPOSE_PROJECT = "sub2api-codex-control"
TARGET_SMOKE_CHECK_COUNT = 9
TARGET_SMOKE_CATALOG_SHA256 = (
    "3056c52085fbed3d43437a111ee73be56c051a62df7fd3aceef9fca1c54225a1"
)
TARGET_CLOSURE_VERIFIER_SHA256 = (
    "500b43beb6e9908e8ab63c4f31b07873c4c0eb2c55115dc2e3dc9fb59c7b35c4"
)
TARGET_CLOSURE_SCHEMA_SHA256 = (
    "aca4dce9dd9e3fcf65f021addb5208096f9777de35dca64b11acacb41ef0152b"
)
TOOLS_MANIFEST_BASENAME = "rollout-tools.manifest.json"
TOOLS_MANIFEST_MEMBERS = {
    "deploy/scripts/image-rollout-admission.py": ("image-rollout-admission.py", "0555"),
    "deploy/scripts/image-rollout-smoke.py": ("image-rollout-smoke.py", "0555"),
    "deploy/scripts/rollout-bootstrap-images.sh": ("rollout-bootstrap-images.sh", "0555"),
    "deploy/schemas/image-rollout-record.schema.json": (
        "image-rollout-record.schema.json",
        "0444",
    ),
}
MAX_JSON_BYTES = 32 * 1024 * 1024
MAX_MIGRATION_BYTES = 2 * 1024 * 1024
MAX_MIGRATION_TREE_BYTES = 16 * 1024 * 1024
MAX_ARCHIVE_BYTES = 4 * 1024 * 1024 * 1024
MAX_INVARIANT_TEXT_BYTES = 16 * 1024 * 1024
IMAGE_ID_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
CONTAINER_ID_RE = re.compile(r"^[0-9a-f]{64}$")
REVISION_RE = re.compile(r"^[0-9]{8}_[0-9]{4}$")
MIGRATION_NAME_RE = re.compile(r"^[0-9]{8}_[0-9]{4}_[a-z0-9_]+\.py$")
VCS_REF_RE = re.compile(r"^[0-9a-f]{40,64}$")
DEPLOYMENT_DIRECTORY_RE = re.compile(
    r"^bootstrap-[0-9]{8}T[0-9]{6}Z-"
    r"([0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})$"
)
SERVICE_NAMES = (
    "control-api",
    "control-api-replica",
    "control-migrate",
    "codex-pwa",
    "control-backup",
)
RUNNING_SERVICE_NAMES = ("control-api", "control-api-replica", "codex-pwa")
COMPONENT_SERVICES = {
    "control-api": ("control-api", "control-api-replica", "control-migrate"),
    "pwa": ("codex-pwa",),
    "postgres-tools": ("control-backup",),
}
SERVICE_COMPONENT = {
    service: component
    for component, services in COMPONENT_SERVICES.items()
    for service in services
}
ENV_IDENTITY_SERVICES = (
    "control-api",
    "control-api-replica",
    "control-migrate",
)
OCI_VERSION_LABEL = "org.opencontainers.image.version"
OCI_REVISION_LABEL = "org.opencontainers.image.revision"
OPERATOR_FORBIDDEN_OPERATIONS = ["backup", "database-migration"]
OPERATOR_ALLOWED_OPERATIONS = [
    "codex-pwa-rollout",
    "control-api-replica-rollout",
    "control-api-rollout",
    "image-load",
    "image-only-compose-plan",
    "production-smoke",
    "rollback",
    "runtime-verification",
]
ARCHIVE_NAMES = {
    "control-api": "control-api-linux-amd64.tar",
    "pwa": "pwa-linux-amd64.tar",
    "postgres-tools": "postgres-tools-linux-amd64.tar",
}
TARGET_ARCHIVE_SHA256 = {
    "control-api": "3d15a507c7ee03b9258e8b466cafb5af3db33f9ed5ad0c1a81451c9c8020405b",
    "pwa": "fc2c0b88cf535f0a8531a59c5ceaafe4ab0528a1af926e32c07cccb48d99ccf5",
    "postgres-tools": "07521f878bc1d783843ec7bbd543b623eb35edff788e342f431e86a7e5322fa8",
}
TARGET_IMAGE_IDS = {
    "control-api": "sha256:738950f131467a4a5a7254370899c4994c81886ed9bbcb35a67dfa59cf56e204",
    "postgres-tools": "sha256:c8ce4d3846460ca6411652ac56bee37aab50725d818a76dab29d9c3e5092ae25",
    "pwa": "sha256:725499770248c17ed93fcf9daebb5c80435cfbdd21dd69f0836699f2008aeccf",
}
PROTECTED_CONTAINER_NAMES = {
    "sub2api": "/sub2api",
    "postgres": "/sub2api-postgres",
    "redis": "/sub2api-redis",
}
REDIS_CONFIG_KEYS = {
    "appendfsync",
    "appendonly",
    "databases",
    "maxmemory",
    "maxmemory-policy",
    "notify-keyspace-events",
    "save",
}
POSTGRES_ACL_GRANTEES = {"PUBLIC", "codex_control", "postgres", "sub2api"}
VERIFIER_EVIDENCE_KEYS = {
    "admission",
    "bundle",
    "bundle_file_count",
    "release",
    "source_file_count",
    "source_root_verified",
    "status",
    "vcs_ref",
}


class AdmissionError(RuntimeError):
    """A concise, non-secret admission failure."""


class SchemaValidationError(RuntimeError):
    """A closed-schema validation failure without instance disclosure."""


def fail(message: str) -> NoReturn:
    raise AdmissionError(message)


def canonical_bytes(value: Any) -> bytes:
    try:
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
    except (TypeError, ValueError) as exc:
        fail(f"value cannot be canonically encoded: {exc}")


def canonical_json_bytes(value: Any) -> bytes:
    """Canonical JSON without the record-oriented trailing newline."""
    return canonical_bytes(value)[:-1]


SCHEMA_KEYWORDS = {
    "$defs",
    "$id",
    "$ref",
    "$schema",
    "additionalProperties",
    "allOf",
    "const",
    "else",
    "enum",
    "format",
    "if",
    "items",
    "maxItems",
    "maxLength",
    "maximum",
    "minItems",
    "minLength",
    "minimum",
    "oneOf",
    "pattern",
    "prefixItems",
    "properties",
    "required",
    "then",
    "title",
    "type",
    "uniqueItems",
}


def schema_mismatch(path: str, message: str) -> NoReturn:
    raise SchemaValidationError(f"{path}: {message}")


def schema_equal(left: Any, right: Any) -> bool:
    return type(left) is type(right) and canonical_bytes(left) == canonical_bytes(right)


def schema_type_matches(value: Any, expected: str) -> bool:
    return {
        "array": isinstance(value, list),
        "boolean": isinstance(value, bool),
        "integer": isinstance(value, int) and not isinstance(value, bool),
        "null": value is None,
        "object": isinstance(value, dict),
        "string": isinstance(value, str),
    }.get(expected, False)


def resolve_local_schema_ref(root: dict[str, Any], reference: Any) -> Any:
    if not isinstance(reference, str) or not reference.startswith("#/"):
        schema_mismatch("schema", "only local JSON Pointer references are allowed")
    current: Any = root
    for encoded in reference[2:].split("/"):
        token = encoded.replace("~1", "/").replace("~0", "~")
        if not isinstance(current, dict) or token not in current:
            schema_mismatch("schema", "contains an unresolved local reference")
        current = current[token]
    return current


def validate_schema_instance(
    value: Any,
    schema: Any,
    root: dict[str, Any],
    path: str = "$",
) -> None:
    if isinstance(schema, bool):
        if not schema:
            schema_mismatch(path, "is rejected by a false schema")
        return
    if not isinstance(schema, dict):
        schema_mismatch("schema", "contains a non-object schema")
    unknown = set(schema) - SCHEMA_KEYWORDS
    if unknown:
        schema_mismatch("schema", "contains unsupported keywords")
    if "$ref" in schema:
        validate_schema_instance(
            value,
            resolve_local_schema_ref(root, schema["$ref"]),
            root,
            path,
        )
    expected_type = schema.get("type")
    if expected_type is not None and (
        not isinstance(expected_type, str)
        or not schema_type_matches(value, expected_type)
    ):
        schema_mismatch(path, "has the wrong JSON type")
    if "const" in schema and not schema_equal(value, schema["const"]):
        schema_mismatch(path, "differs from a required constant")
    if "enum" in schema:
        choices = schema["enum"]
        if not isinstance(choices, list) or not any(
            schema_equal(value, choice) for choice in choices
        ):
            schema_mismatch(path, "is outside the allowed enumeration")
    branches = schema.get("allOf", [])
    if not isinstance(branches, list):
        schema_mismatch("schema", "allOf must be an array")
    for branch in branches:
        validate_schema_instance(value, branch, root, path)
    if "oneOf" in schema:
        candidates = schema["oneOf"]
        if not isinstance(candidates, list):
            schema_mismatch("schema", "oneOf must be an array")
        matches = 0
        for candidate in candidates:
            try:
                validate_schema_instance(value, candidate, root, path)
            except SchemaValidationError:
                continue
            matches += 1
        if matches != 1:
            schema_mismatch(path, "does not match exactly one schema branch")
    if "if" in schema:
        try:
            validate_schema_instance(value, schema["if"], root, path)
        except SchemaValidationError:
            conditional = schema.get("else")
        else:
            conditional = schema.get("then")
        if conditional is not None:
            validate_schema_instance(value, conditional, root, path)
    if isinstance(value, dict):
        required = schema.get("required", [])
        if not isinstance(required, list) or any(
            not isinstance(item, str) for item in required
        ):
            schema_mismatch("schema", "required must be a string array")
        missing = [item for item in required if item not in value]
        if missing:
            schema_mismatch(path, "is missing required properties")
        properties = schema.get("properties", {})
        if not isinstance(properties, dict):
            schema_mismatch("schema", "properties must be an object")
        for key, nested in value.items():
            if key in properties:
                validate_schema_instance(nested, properties[key], root, f"{path}.{key}")
            elif schema.get("additionalProperties") is False:
                schema_mismatch(path, "contains an additional property")
            elif isinstance(schema.get("additionalProperties"), dict):
                validate_schema_instance(
                    nested, schema["additionalProperties"], root, f"{path}.{key}"
                )
    if isinstance(value, list):
        minimum_items = schema.get("minItems")
        maximum_items = schema.get("maxItems")
        if minimum_items is not None and len(value) < minimum_items:
            schema_mismatch(path, "contains too few items")
        if maximum_items is not None and len(value) > maximum_items:
            schema_mismatch(path, "contains too many items")
        if schema.get("uniqueItems") is True:
            encoded = [canonical_bytes(item) for item in value]
            if len(encoded) != len(set(encoded)):
                schema_mismatch(path, "contains duplicate items")
        prefix = schema.get("prefixItems", [])
        if not isinstance(prefix, list):
            schema_mismatch("schema", "prefixItems must be an array")
        for index, nested in enumerate(value[: len(prefix)]):
            validate_schema_instance(nested, prefix[index], root, f"{path}[{index}]")
        if len(value) > len(prefix) and "items" in schema:
            items = schema["items"]
            for index, nested in enumerate(value[len(prefix) :], len(prefix)):
                validate_schema_instance(nested, items, root, f"{path}[{index}]")
    if isinstance(value, str):
        minimum_length = schema.get("minLength")
        maximum_length = schema.get("maxLength")
        if minimum_length is not None and len(value) < minimum_length:
            schema_mismatch(path, "is too short")
        if maximum_length is not None and len(value) > maximum_length:
            schema_mismatch(path, "is too long")
        if "pattern" in schema:
            pattern = schema["pattern"]
            if not isinstance(pattern, str):
                schema_mismatch("schema", "pattern must be a string")
            try:
                matched = re.search(pattern, value)
            except re.error:
                schema_mismatch("schema", "contains an invalid pattern")
            if matched is None:
                schema_mismatch(path, "does not match the required pattern")
        if "format" in schema:
            if schema["format"] != "date-time":
                schema_mismatch("schema", "contains an unsupported format")
            try:
                datetime.fromisoformat(value[:-1] + "+00:00" if value.endswith("Z") else value)
            except ValueError:
                schema_mismatch(path, "is not a valid date-time")
    if isinstance(value, int) and not isinstance(value, bool):
        if "minimum" in schema and value < schema["minimum"]:
            schema_mismatch(path, "is below the minimum")
        if "maximum" in schema and value > schema["maximum"]:
            schema_mismatch(path, "is above the maximum")


def validate_closed_record_schema(value: Any, schema: Any) -> dict[str, Any]:
    root = require_object(schema, "image rollout schema")
    if (
        root.get("$schema") != "https://json-schema.org/draft/2020-12/schema"
        or root.get("$id")
        != "https://sub2api-codex.invalid/schemas/image-rollout-record-v1.json"
        or root.get("type") != "object"
        or root.get("additionalProperties") is not False
    ):
        fail("image rollout schema is not the frozen closed Draft 2020-12 schema")
    def audit_schema(node: Any, location: str) -> None:
        if isinstance(node, bool):
            return
        if not isinstance(node, dict):
            schema_mismatch("schema", "contains a non-object schema")
        unknown = set(node) - SCHEMA_KEYWORDS
        if unknown:
            schema_mismatch("schema", "contains unsupported keywords")
        if "$ref" in node:
            resolve_local_schema_ref(root, node["$ref"])
        for keyword in ("allOf", "oneOf", "prefixItems"):
            if keyword in node:
                branches = node[keyword]
                if not isinstance(branches, list):
                    schema_mismatch("schema", f"{keyword} must be an array")
                for index, branch in enumerate(branches):
                    audit_schema(branch, f"{location}.{keyword}[{index}]")
        for keyword in ("if", "then", "else", "items", "additionalProperties"):
            if keyword in node and isinstance(node[keyword], (dict, bool)):
                audit_schema(node[keyword], f"{location}.{keyword}")
            elif keyword in node and keyword in {"if", "then", "else", "items"}:
                schema_mismatch("schema", f"{keyword} must be a schema")
        for keyword in ("$defs", "properties"):
            if keyword in node:
                members = node[keyword]
                if not isinstance(members, dict):
                    schema_mismatch("schema", f"{keyword} must be an object")
                for name, member in members.items():
                    audit_schema(member, f"{location}.{keyword}.{name}")

    try:
        audit_schema(root, "schema")
        validate_schema_instance(value, root, root)
    except SchemaValidationError as error:
        fail(f"image rollout record does not satisfy its schema: {error}")
    return root


def write_canonical(value: Any) -> None:
    sys.stdout.buffer.write(canonical_bytes(value))


def write_all(descriptor: int, content: bytes, label: str) -> None:
    offset = 0
    while offset < len(content):
        try:
            written = os.write(descriptor, content[offset:])
        except InterruptedError:
            continue
        except OSError:
            fail(f"{label} could not be written")
        if written <= 0:
            fail(f"{label} write did not make progress")
        offset += written


def atomic_rename_noreplace(
    directory_descriptor: int, source: str, destination: str
) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    if sys.platform.startswith("linux"):
        function = getattr(libc, "renameat2", None)
        flag = 1  # RENAME_NOREPLACE
    elif sys.platform == "darwin":
        function = getattr(libc, "renameatx_np", None)
        flag = 0x00000004  # RENAME_EXCL
    else:
        function = None
        flag = 0
    if function is None:
        fail("atomic no-replace record publication is unavailable")
    function.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ]
    function.restype = ctypes.c_int
    ctypes.set_errno(0)
    result = function(
        directory_descriptor,
        os.fsencode(source),
        directory_descriptor,
        os.fsencode(destination),
        flag,
    )
    if result == 0:
        return
    error = ctypes.get_errno()
    if error in {errno.EEXIST, errno.ENOTEMPTY}:
        raise FileExistsError(error, "destination exists")
    if error in {errno.ENOSYS, errno.ENOTSUP, errno.EINVAL}:
        fail("atomic no-replace record publication is unsupported")
    fail("atomic no-replace record publication failed")


def read_stdin(label: str, *, maximum: int = MAX_JSON_BYTES) -> bytes:
    raw = sys.stdin.buffer.read(maximum + 1)
    if not raw or len(raw) > maximum:
        fail(f"{label} has an invalid size")
    return raw


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def metadata_signature(value: os.stat_result) -> tuple[int, ...]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_uid,
        value.st_gid,
        value.st_nlink,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def canonical_path(path: Path, label: str) -> Path:
    if not path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        fail(f"{label} path must be absolute and normalized")
    try:
        resolved = path.resolve(strict=True)
    except OSError:
        fail(f"{label} cannot be resolved")
    if resolved != path:
        fail(f"{label} path must not contain symbolic links")
    return path


def read_regular(path: Path, label: str, *, maximum: int = MAX_JSON_BYTES) -> bytes:
    path = canonical_path(path, label)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError:
        fail(f"{label} cannot be opened without following links")
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            fail(f"{label} must be a regular file")
        if before.st_nlink != 1:
            fail(f"{label} must have exactly one filesystem link")
        if before.st_size <= 0 or before.st_size > maximum:
            fail(f"{label} has an invalid size")
        chunks: list[bytes] = []
        remaining = maximum + 1
        while remaining:
            block = os.read(descriptor, min(131_072, remaining))
            if not block:
                break
            chunks.append(block)
            remaining -= len(block)
        raw = b"".join(chunks)
        if len(raw) > maximum or len(raw) != before.st_size:
            fail(f"{label} changed size while it was read")
        after = os.fstat(descriptor)
        if metadata_signature(after) != metadata_signature(before):
            fail(f"{label} changed while it was read")
        try:
            named = os.stat(path, follow_symlinks=False)
        except OSError:
            fail(f"{label} disappeared while it was read")
        if metadata_signature(named) != metadata_signature(before):
            fail(f"{label} changed while it was read")
        return raw
    finally:
        os.close(descriptor)


def hash_regular(
    path: Path,
    label: str,
    *,
    maximum: int = MAX_ARCHIVE_BYTES,
    allow_empty: bool = False,
) -> tuple[str, int]:
    path = canonical_path(path, label)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError:
        fail(f"{label} cannot be opened without following links")
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            fail(f"{label} must be one singly-linked regular file")
        if before.st_size < 0 or (before.st_size == 0 and not allow_empty) or before.st_size > maximum:
            fail(f"{label} has an invalid size")
        digest = hashlib.sha256()
        total = 0
        while True:
            block = os.read(descriptor, 1024 * 1024)
            if not block:
                break
            total += len(block)
            if total > maximum:
                fail(f"{label} exceeds its size limit")
            digest.update(block)
        if total != before.st_size:
            fail(f"{label} changed size while it was read")
        after = os.fstat(descriptor)
        if metadata_signature(after) != metadata_signature(before):
            fail(f"{label} changed while it was read")
        try:
            named = os.stat(path, follow_symlinks=False)
        except OSError:
            fail(f"{label} disappeared while it was read")
        if metadata_signature(named) != metadata_signature(before):
            fail(f"{label} changed while it was read")
        return digest.hexdigest(), total
    finally:
        os.close(descriptor)


def open_record_directory(path: Path) -> tuple[int, os.stat_result]:
    path = canonical_path(path, "record output directory")
    flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(path, flags)
    except OSError:
        fail("record output directory cannot be opened without following links")
    opened = os.fstat(descriptor)
    try:
        named = os.stat(path, follow_symlinks=False)
    except OSError:
        os.close(descriptor)
        fail("record output directory changed while it was opened")
    if (
        not stat.S_ISDIR(opened.st_mode)
        or opened.st_uid != os.geteuid()
        or stat.S_IMODE(opened.st_mode) != 0o700
        or (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino)
    ):
        os.close(descriptor)
        fail("record output directory must be execution-owned mode 0700")
    return descriptor, opened


def read_private_record_at(directory_descriptor: int, basename: str) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(basename, flags, dir_fd=directory_descriptor)
    except OSError:
        fail("published image rollout record cannot be opened without following links")
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.geteuid()
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_size <= 0
            or before.st_size > MAX_JSON_BYTES
        ):
            fail("published image rollout record is not one private regular file")
        chunks: list[bytes] = []
        remaining = MAX_JSON_BYTES + 1
        while remaining:
            block = os.read(descriptor, min(131_072, remaining))
            if not block:
                break
            chunks.append(block)
            remaining -= len(block)
        raw = b"".join(chunks)
        if len(raw) != before.st_size or len(raw) > MAX_JSON_BYTES:
            fail("published image rollout record changed size while it was read")
        after = os.fstat(descriptor)
        try:
            named = os.stat(
                basename, dir_fd=directory_descriptor, follow_symlinks=False
            )
        except OSError:
            fail("published image rollout record disappeared while it was read")
        if (
            metadata_signature(after) != metadata_signature(before)
            or metadata_signature(named) != metadata_signature(before)
        ):
            fail("published image rollout record changed while it was read")
        return raw
    finally:
        os.close(descriptor)


def validate_published_record(
    directory_descriptor: int,
    expected: bytes,
    schema_value: dict[str, Any],
) -> None:
    published = read_private_record_at(
        directory_descriptor, "image-rollout-record.json"
    )
    if published != expected:
        fail("existing image rollout record differs from this exact terminal state")
    published_value = decode_json(published, "published image rollout record")
    validate_record_value(published_value)
    validate_closed_record_schema(published_value, schema_value)


def publish_record_noreplace(
    output: Path,
    raw: bytes,
    schema_value: dict[str, Any],
    *,
    resume_existing: bool,
) -> None:
    if output.name != "image-rollout-record.json":
        fail("record output must use the fixed image-rollout-record.json basename")
    directory_descriptor, directory_metadata = open_record_directory(output.parent)
    temporary_name = (
        f".image-rollout-record.json.tmp-{os.getpid()}-{uuid.uuid4().hex}"
    )
    temporary_descriptor = -1
    renamed = False
    try:
        try:
            os.stat(
                output.name,
                dir_fd=directory_descriptor,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            pass
        except OSError:
            fail("record output cannot be inspected without following links")
        else:
            if not resume_existing:
                fail("image rollout record already exists")
            validate_published_record(directory_descriptor, raw, schema_value)
            os.fsync(directory_descriptor)
            return

        flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        try:
            temporary_descriptor = os.open(
                temporary_name,
                flags,
                0o600,
                dir_fd=directory_descriptor,
            )
        except OSError:
            fail("private temporary image rollout record cannot be created")
        write_all(temporary_descriptor, raw, "private temporary image rollout record")
        os.fsync(temporary_descriptor)
        os.close(temporary_descriptor)
        temporary_descriptor = -1
        try:
            atomic_rename_noreplace(
                directory_descriptor,
                temporary_name,
                output.name,
            )
        except FileExistsError:
            if not resume_existing:
                fail("image rollout record was published concurrently")
            validate_published_record(directory_descriptor, raw, schema_value)
            os.fsync(directory_descriptor)
            return
        renamed = True
        os.fsync(directory_descriptor)
        validate_published_record(directory_descriptor, raw, schema_value)
        after = os.fstat(directory_descriptor)
        try:
            named_after = os.stat(output.parent, follow_symlinks=False)
        except OSError:
            fail("record output directory disappeared during publication")
        if (
            not stat.S_ISDIR(after.st_mode)
            or after.st_uid != directory_metadata.st_uid
            or stat.S_IMODE(after.st_mode) != 0o700
            or (after.st_dev, after.st_ino)
            != (directory_metadata.st_dev, directory_metadata.st_ino)
            or (named_after.st_dev, named_after.st_ino)
            != (directory_metadata.st_dev, directory_metadata.st_ino)
        ):
            fail("record output directory identity changed during publication")
    finally:
        if temporary_descriptor >= 0:
            os.close(temporary_descriptor)
        if not renamed:
            try:
                os.unlink(temporary_name, dir_fd=directory_descriptor)
            except FileNotFoundError:
                pass
            except OSError:
                pass
            try:
                os.fsync(directory_descriptor)
            except OSError:
                pass
        os.close(directory_descriptor)


def trusted_regular_metadata(path: Path, label: str, expected_mode: int) -> os.stat_result:
    path = canonical_path(path, label)
    try:
        metadata = os.stat(path, follow_symlinks=False)
    except OSError:
        fail(f"{label} cannot be inspected")
    expected_uid = TARGET_TOOL_OWNER_UID
    if (
        os.geteuid() != 0
        and os.environ.get("IMAGE_ROLLOUT_TEST_ALLOW_UNPRIVILEGED_TOOLS") == "1"
        and Path("/private/tmp") in path.parents
    ):
        expected_uid = os.geteuid()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_uid != expected_uid
        or stat.S_IMODE(metadata.st_mode) != expected_mode
    ):
        fail(f"{label} is not one root-owned normalized regular file")
    return metadata


def validate_trusted_ancestors(path: Path, stop: Path, label: str) -> None:
    current = canonical_path(path, label)
    stop = canonical_path(stop, f"{label} trust root")
    if stop != current and stop not in current.parents:
        fail(f"{label} is outside its trust root")
    expected_uid = TARGET_TOOL_OWNER_UID
    if (
        os.geteuid() != 0
        and os.environ.get("IMAGE_ROLLOUT_TEST_ALLOW_UNPRIVILEGED_TOOLS") == "1"
        and Path("/private/tmp") in current.parents
    ):
        expected_uid = os.geteuid()
    while True:
        metadata = os.stat(current, follow_symlinks=False)
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != expected_uid
            or stat.S_IMODE(metadata.st_mode) & 0o022
        ):
            fail(f"{label} ancestor is not root-owned and read-only")
        if current == stop:
            return
        current = current.parent


def trusted_schema_path(argument: Path) -> tuple[dict[str, Any], bytes]:
    helper = canonical_path(Path(__file__), "admission helper")
    expected = helper.parent.parent / "schemas" / "image-rollout-record.schema.json"
    if argument != expected:
        fail("image rollout schema must be the admission helper's fixed sibling")
    trusted_regular_metadata(expected, "image rollout schema", 0o444)
    tools_root = helper.parent.parent.parent
    validate_trusted_ancestors(expected.parent, tools_root, "image rollout schema")
    raw = read_regular(expected, "image rollout schema")
    if sha256_bytes(raw) != TARGET_SCHEMA_SHA256:
        fail("image rollout schema differs from the compiled frozen identity")
    return require_object(decode_json(raw, "image rollout schema"), "image rollout schema"), raw


def validate_tools_manifest(path: Path) -> dict[str, Any]:
    manifest_path = canonical_path(path, "rollout tools manifest")
    if manifest_path.name != TOOLS_MANIFEST_BASENAME:
        fail("rollout tools manifest has an unexpected basename")
    tools_root = manifest_path.parent
    trusted_regular_metadata(manifest_path, "rollout tools manifest", 0o444)
    validate_trusted_ancestors(tools_root, tools_root, "rollout tools root")
    value, raw = load_json(manifest_path, "rollout tools manifest")
    manifest = require_object(value, "rollout tools manifest")
    require_exact_keys(
        manifest,
        {"files", "identity_sha256", "schema_version", "type"},
        "rollout tools manifest",
    )
    if (
        manifest.get("schema_version") != 1
        or manifest.get("type") != "image-rollout-tools-manifest-v1"
    ):
        fail("rollout tools manifest header is invalid")
    files = require_object(manifest.get("files"), "rollout tools manifest files")
    require_exact_keys(files, set(TOOLS_MANIFEST_MEMBERS), "rollout tools manifest files")
    projected: dict[str, dict[str, Any]] = {}
    descriptors: dict[str, dict[str, Any]] = {}
    for relative, (basename, mode_text) in TOOLS_MANIFEST_MEMBERS.items():
        descriptor = require_object(files.get(relative), f"rollout tool {relative}")
        require_exact_keys(
            descriptor,
            {"mode", "sha256", "size"},
            f"rollout tool {relative}",
        )
        if descriptor.get("mode") != mode_text:
            fail(f"rollout tool {relative} mode differs from the frozen manifest")
        expected_sha = require_sha256(
            descriptor.get("sha256"), f"rollout tool {relative} hash"
        )
        expected_size = descriptor.get("size")
        if (
            not isinstance(expected_size, int)
            or isinstance(expected_size, bool)
            or expected_size <= 0
        ):
            fail(f"rollout tool {relative} size is invalid")
        member = tools_root / relative
        trusted_regular_metadata(member, f"rollout tool {relative}", int(mode_text, 8))
        validate_trusted_ancestors(member.parent, tools_root, f"rollout tool {relative}")
        observed_sha, observed_size = hash_regular(member, f"rollout tool {relative}")
        if (observed_sha, observed_size) != (expected_sha, expected_size):
            fail(f"rollout tool {relative} bytes differ from the manifest")
        projected[relative] = {
            "mode": mode_text,
            "sha256": observed_sha,
            "size": observed_size,
        }
        descriptors[relative] = {
            "basename": basename,
            "sha256": observed_sha,
            "size": observed_size,
        }
    identity = sha256_bytes(canonical_json_bytes(projected))
    if manifest.get("identity_sha256") != identity:
        fail("rollout tools manifest identity differs from its exact file set")
    helper = canonical_path(Path(__file__), "admission helper")
    if helper != tools_root / "deploy/scripts/image-rollout-admission.py":
        fail("running admission helper is outside the admitted tools root")
    return {
        "admission_helper": descriptors["deploy/scripts/image-rollout-admission.py"],
        "manifest": {
            "basename": manifest_path.name,
            "sha256": sha256_bytes(raw),
            "size": len(raw),
        },
        "record_schema": descriptors["deploy/schemas/image-rollout-record.schema.json"],
        "root_owned_read_only": True,
        "smoke_helper": descriptors["deploy/scripts/image-rollout-smoke.py"],
        "tooling_identity": identity,
        "wrapper": descriptors["deploy/scripts/rollout-bootstrap-images.sh"],
    }


def validate_tools_admission(
    path: Path, manifest_path: Path, tooling: dict[str, Any]
) -> dict[str, Any]:
    path = canonical_path(path, "rollout tools admission")
    manifest_path = canonical_path(manifest_path, "rollout tools manifest")
    trusted_regular_metadata(path, "rollout tools admission", 0o444)
    validate_trusted_ancestors(
        path.parent, manifest_path.parent, "rollout tools admission"
    )
    value, raw = load_json(path, "rollout tools admission")
    admission = require_object(value, "rollout tools admission")
    require_exact_keys(
        admission,
        {
            "archive",
            "command",
            "manifest",
            "members",
            "schema_version",
            "self_sha256",
            "status",
            "tooling_identity",
            "type",
            "external_verifier",
        },
        "rollout tools admission",
    )
    if (
        admission.get("schema_version") != 1
        or admission.get("type") != "image-rollout-tools-admission-v1"
        or admission.get("command") != "extract"
        or admission.get("status") != "extracted"
        or admission.get("tooling_identity") != tooling["tooling_identity"]
    ):
        fail("rollout tools admission header or identity is invalid")
    archive = validate_file_evidence(
        admission.get("archive"), "rollout tools admission archive"
    )
    verifier = validate_file_evidence(
        admission.get("external_verifier"), "rollout tools external verifier"
    )
    manifest = validate_file_evidence(
        admission.get("manifest"), "rollout tools admitted manifest"
    )
    if (
        path.name != "rollout-tools.admission.json"
        or manifest_path.parent != path.parent
        or archive["basename"] != "image-rollout-tools.tar"
        or verifier["basename"] != "build-image-rollout-tools.py"
        or admission.get("self_sha256") != verifier["sha256"]
        or manifest != file_evidence(manifest_path, "rollout tools manifest")
    ):
        fail("rollout tools admission descriptors differ from fixed inputs")
    members = require_object(admission.get("members"), "rollout tools members")
    require_exact_keys(members, set(TOOLS_MANIFEST_MEMBERS), "rollout tools members")
    expected_members = {
        "deploy/scripts/image-rollout-admission.py": tooling["admission_helper"],
        "deploy/scripts/image-rollout-smoke.py": tooling["smoke_helper"],
        "deploy/scripts/rollout-bootstrap-images.sh": tooling["wrapper"],
        "deploy/schemas/image-rollout-record.schema.json": tooling["record_schema"],
    }
    for relative, descriptor in members.items():
        member = require_object(
            descriptor, f"rollout tools admitted member {relative}"
        )
        require_exact_keys(
            member,
            {"basename", "mode", "sha256", "size"},
            f"rollout tools admitted member {relative}",
        )
        mode = TOOLS_MANIFEST_MEMBERS[relative][1]
        validated = validate_file_evidence(
            {key: member[key] for key in ("basename", "sha256", "size")},
            f"rollout tools admitted member {relative}",
        )
        if member.get("mode") != mode or validated != expected_members[relative]:
            fail(f"rollout tools admitted member {relative} differs from the install")
    return {
        **tooling,
        "admission": {
            "basename": path.name,
            "sha256": sha256_bytes(raw),
            "size": len(raw),
        },
        "archive": archive,
        "external_verifier": verifier,
    }


def reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            fail("JSON input contains a duplicate object key")
        result[key] = value
    return result


def reject_constant(value: str) -> NoReturn:
    fail(f"JSON input contains a non-finite number: {value}")


def decode_json(raw: bytes, label: str) -> Any:
    try:
        text = raw.decode("utf-8")
        return json.loads(
            text,
            object_pairs_hook=reject_duplicate_pairs,
            parse_constant=reject_constant,
        )
    except UnicodeDecodeError:
        fail(f"{label} is not UTF-8 JSON")
    except json.JSONDecodeError as exc:
        fail(f"{label} is not valid JSON: line {exc.lineno}, column {exc.colno}")


def load_json(path: Path, label: str) -> tuple[Any, bytes]:
    raw = read_regular(path, label)
    return decode_json(raw, label), raw


def require_object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        fail(f"{label} must be one JSON object")
    return value


def require_exact_keys(value: dict[str, Any], keys: set[str], label: str) -> None:
    if set(value) != keys:
        fail(
            f"{label} keys differ; missing={sorted(keys - set(value))}, "
            f"extra={sorted(set(value) - keys)}"
        )


def require_string(value: Any, label: str, *, maximum: int = 256) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > maximum
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
    ):
        fail(f"{label} must be one bounded non-empty string")
    return value


def require_sha256(value: Any, label: str, *, image: bool = False) -> str:
    pattern = IMAGE_ID_RE if image else SHA256_RE
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        fail(f"{label} must be one lowercase SHA-256 identity")
    return value


def require_release(value: Any, label: str) -> str:
    result = require_string(value, label, maximum=128)
    if result.strip() != result or any(character.isspace() for character in result):
        fail(f"{label} is not a concrete release")
    return result


def require_vcs(value: Any, label: str) -> str:
    if not isinstance(value, str) or VCS_REF_RE.fullmatch(value) is None:
        fail(f"{label} must be one full lowercase source identity")
    return value


def compose_services(value: dict[str, Any], label: str) -> dict[str, dict[str, Any]]:
    services = value.get("services")
    if not isinstance(services, dict) or set(services) != set(SERVICE_NAMES):
        fail(f"{label} must contain exactly the five rollout services")
    if any(not isinstance(services[name], dict) for name in SERVICE_NAMES):
        fail(f"{label} contains a non-object service")
    return services  # type: ignore[return-value]


def service_environment(service: dict[str, Any], name: str) -> dict[str, Any]:
    value = service.get("environment")
    if not isinstance(value, dict):
        fail(f"{name} has no resolved environment object")
    return value


def service_labels(service: dict[str, Any], name: str) -> dict[str, Any]:
    value = service.get("labels")
    if not isinstance(value, dict):
        fail(f"{name} has no resolved labels object")
    return value


def compose_identity(
    value: dict[str, Any], label: str
) -> tuple[str, str, dict[str, str]]:
    services = compose_services(value, label)
    releases: set[str] = set()
    revisions: set[str] = set()
    images: dict[str, str] = {}
    for name in SERVICE_NAMES:
        service = services[name]
        images[name] = require_sha256(
            service.get("image"), f"{label} {name} image", image=True
        )
        labels = service_labels(service, f"{label} {name}")
        releases.add(
            require_release(
                labels.get(OCI_VERSION_LABEL), f"{label} {name} version label"
            )
        )
        revisions.add(
            require_vcs(
                labels.get(OCI_REVISION_LABEL), f"{label} {name} revision label"
            )
        )
        if name in ENV_IDENTITY_SERVICES:
            environment = service_environment(service, f"{label} {name}")
            releases.add(
                require_release(
                    environment.get("CONTROL_BUILD_VERSION"),
                    f"{label} {name} build version",
                )
            )
            revisions.add(
                require_vcs(
                    environment.get("CONTROL_BUILD_VCS_REF"),
                    f"{label} {name} build VCS ref",
                )
            )
    if len(releases) != 1 or len(revisions) != 1:
        fail(f"{label} service release or VCS identities are inconsistent")
    for component, names in COMPONENT_SERVICES.items():
        component_ids = {images[name] for name in names}
        if len(component_ids) != 1:
            fail(f"{label} {component} services do not share one image ID")
    component_images = {
        component: images[names[0]] for component, names in COMPONENT_SERVICES.items()
    }
    if len(set(component_images.values())) != 3:
        fail(f"{label} component image IDs must be distinct")
    return next(iter(releases)), next(iter(revisions)), component_images


def artifact_identity(value: Any) -> tuple[str, str, dict[str, str]]:
    manifest = require_object(value, "artifact manifest")
    if (
        manifest.get("format_version") != 5
        or manifest.get("schema_version") != 1
        or manifest.get("status") != "ready"
        or manifest.get("artifact_kind") != "unsigned-production-bootstrap-images"
        or manifest.get("trust_mode") != "unsigned-first-deployment-v1"
    ):
        fail("artifact manifest is not one ready unsigned bootstrap image set")
    release = require_release(manifest.get("release"), "artifact release")
    vcs_ref = require_vcs(manifest.get("vcs_ref"), "artifact VCS ref")
    source = require_object(manifest.get("source"), "artifact source")
    source_manifest = require_object(
        source.get("canonical_hash_manifest"), "artifact source manifest"
    )
    if (
        source_manifest.get("is_vcs_ref") is not True
        or source_manifest.get("sha256") != vcs_ref
    ):
        fail("artifact source manifest does not bind its VCS ref")
    images = require_object(manifest.get("images"), "artifact images")
    if set(images) != set(COMPONENT_SERVICES):
        fail("artifact manifest must contain exactly three image components")
    result: dict[str, str] = {}
    for component in COMPONENT_SERVICES:
        image = require_object(images[component], f"artifact image {component}")
        if image.get("archive") != ARCHIVE_NAMES[component]:
            fail(f"artifact image {component} has an unexpected archive filename")
        archive_sha = require_sha256(
            image.get("archive_sha256"), f"artifact image {component} archive hash"
        )
        if archive_sha != TARGET_ARCHIVE_SHA256[component]:
            fail(f"artifact image {component} differs from the frozen archive hash")
        archive_size = image.get("archive_size")
        if not isinstance(archive_size, int) or isinstance(archive_size, bool) or archive_size <= 0:
            fail(f"artifact image {component} has no concrete archive size")
        result[component] = require_sha256(
            image.get("daemon_image_id"),
            f"artifact image {component} daemon ID",
            image=True,
        )
        labels = require_object(
            image.get("oci_labels"), f"artifact image {component} labels"
        )
        if (
            labels.get(OCI_VERSION_LABEL) != release
            or labels.get(OCI_REVISION_LABEL) != vcs_ref
        ):
            fail(f"artifact image {component} labels do not bind release and VCS ref")
        require_string(
            labels.get("org.opencontainers.image.source"),
            f"artifact image {component} source",
        )
    if len(set(result.values())) != 3:
        fail("artifact image IDs must be distinct")
    if result != TARGET_IMAGE_IDS:
        fail("artifact image IDs differ from the frozen rollout target")
    return release, vcs_ref, result


def replace_identity_fields(
    old: dict[str, Any], release: str, vcs_ref: str, images: dict[str, str]
) -> dict[str, Any]:
    expected = copy.deepcopy(old)
    services = compose_services(expected, "old resolved Compose")
    for name in SERVICE_NAMES:
        service = services[name]
        service["image"] = images[SERVICE_COMPONENT[name]]
        labels = service_labels(service, f"old resolved Compose {name}")
        labels[OCI_VERSION_LABEL] = release
        labels[OCI_REVISION_LABEL] = vcs_ref
        if name in ENV_IDENTITY_SERVICES:
            environment = service_environment(service, f"old resolved Compose {name}")
            environment["CONTROL_BUILD_VERSION"] = release
            environment["CONTROL_BUILD_VCS_REF"] = vcs_ref
    return expected


def plan(args: argparse.Namespace) -> dict[str, Any]:
    old, old_raw = load_json(args.old_compose, "old resolved Compose config")
    new, new_raw = load_json(args.new_compose, "new resolved Compose config")
    artifact, artifact_raw = load_json(args.artifact_manifest, "artifact manifest")
    old = require_object(old, "old resolved Compose config")
    new = require_object(new, "new resolved Compose config")
    old_release, old_vcs, old_images = compose_identity(old, "old resolved Compose")
    new_release, new_vcs, new_images = compose_identity(new, "new resolved Compose")
    artifact_release, artifact_vcs, artifact_images = artifact_identity(artifact)
    if (
        sha256_bytes(artifact_raw) != TARGET_MANIFEST_SHA256
        or artifact_release != TARGET_RELEASE
        or artifact_vcs != TARGET_VCS_REF
    ):
        fail("artifact manifest differs from the frozen rollout target")
    if (new_release, new_vcs, new_images) != (
        artifact_release,
        artifact_vcs,
        artifact_images,
    ):
        fail(
            "new Compose image, release, or VCS identity differs from the artifact manifest"
        )
    if new != replace_identity_fields(
        old, artifact_release, artifact_vcs, artifact_images
    ):
        fail("resolved Compose configs differ outside the image-only rollout allowlist")
    if old_release == new_release or old_vcs == new_vcs:
        fail("image-only rollout must advance both release and VCS identity")
    unchanged_images = sorted(
        component
        for component in COMPONENT_SERVICES
        if old_images[component] == new_images[component]
    )
    if unchanged_images:
        fail(f"image-only rollout did not replace components: {unchanged_images}")
    return {
        "command": "plan",
        "format_version": FORMAT_VERSION,
        "status": "admitted",
        "artifact_manifest_sha256": sha256_bytes(artifact_raw),
        "old_compose_sha256": sha256_bytes(old_raw),
        "new_compose_sha256": sha256_bytes(new_raw),
        "old": {"images": old_images, "release": old_release, "vcs_ref": old_vcs},
        "new": {"images": new_images, "release": new_release, "vcs_ref": new_vcs},
        "service_components": SERVICE_COMPONENT,
        "allowed_changes": {
            "environment": ["CONTROL_BUILD_VCS_REF", "CONTROL_BUILD_VERSION"],
            "labels": [OCI_REVISION_LABEL, OCI_VERSION_LABEL],
            "service_fields": ["image"],
            "services": list(SERVICE_NAMES),
        },
        "new_compose": new,
    }


def validate_rollout_plan(value: Any) -> dict[str, Any]:
    result = require_object(value, "rollout plan")
    required = {
        "allowed_changes",
        "artifact_manifest_sha256",
        "command",
        "format_version",
        "new",
        "new_compose",
        "new_compose_sha256",
        "old",
        "old_compose_sha256",
        "service_components",
        "status",
    }
    require_exact_keys(result, required, "rollout plan")
    if (
        result.get("command") != "plan"
        or result.get("format_version") != FORMAT_VERSION
        or result.get("status") != "admitted"
    ):
        fail("rollout plan is not admitted")
    for key in ("artifact_manifest_sha256", "old_compose_sha256", "new_compose_sha256"):
        require_sha256(result.get(key), f"rollout plan {key}")
    expected_allowlist = {
        "environment": ["CONTROL_BUILD_VCS_REF", "CONTROL_BUILD_VERSION"],
        "labels": [OCI_REVISION_LABEL, OCI_VERSION_LABEL],
        "service_fields": ["image"],
        "services": list(SERVICE_NAMES),
    }
    if (
        result.get("allowed_changes") != expected_allowlist
        or result.get("service_components") != SERVICE_COMPONENT
        or result.get("artifact_manifest_sha256") != TARGET_MANIFEST_SHA256
    ):
        fail("rollout plan allowlist differs from the image-only contract")
    new_compose = require_object(result.get("new_compose"), "rollout plan new Compose")
    new_release, new_vcs, new_images = compose_identity(
        new_compose, "rollout plan new Compose"
    )
    new_identity = require_object(result.get("new"), "rollout plan new identity")
    old_identity = require_object(result.get("old"), "rollout plan old identity")
    for identity, label in ((new_identity, "new"), (old_identity, "old")):
        require_exact_keys(
            identity, {"images", "release", "vcs_ref"}, f"rollout plan {label} identity"
        )
        images = require_object(identity.get("images"), f"rollout plan {label} images")
        if set(images) != set(COMPONENT_SERVICES):
            fail(f"rollout plan {label} images have an invalid component set")
        for component in COMPONENT_SERVICES:
            require_sha256(
                images[component], f"rollout plan {label} {component}", image=True
            )
        require_release(identity.get("release"), f"rollout plan {label} release")
        require_vcs(identity.get("vcs_ref"), f"rollout plan {label} VCS ref")
    if new_identity != {
        "images": new_images,
        "release": new_release,
        "vcs_ref": new_vcs,
    }:
        fail("rollout plan new identity differs from its embedded Compose config")
    if (
        new_release != TARGET_RELEASE
        or new_vcs != TARGET_VCS_REF
        or new_compose.get("name") != TARGET_COMPOSE_PROJECT
    ):
        fail("rollout plan differs from the fixed release, source, or Compose project")
    return result


def validate_old_admission(
    rollout: dict[str, Any], old_plan: Any, old_images: Any, old_running: Any
) -> tuple[dict[str, str], dict[str, dict[str, str]]]:
    plan_value = require_object(old_plan, "old bootstrap plan")
    images_value = require_object(old_images, "old image evidence")
    running_value = require_object(old_running, "old running evidence")
    if plan_value.get("format_version") != 1 or plan_value.get("status") != "admitted":
        fail("old bootstrap plan is not admitted")
    if (
        images_value.get("format_version") != 1
        or images_value.get("status") != "admitted"
    ):
        fail("old image evidence is not admitted")
    if (
        running_value.get("format_version") != 1
        or running_value.get("status") != "admitted"
    ):
        fail("old running evidence is not admitted")
    rollout_old = require_object(rollout["old"], "rollout plan old identity")
    old_component_images = require_object(
        rollout_old.get("images"), "rollout old images"
    )
    plan_bindings = {
        "control-api": plan_value.get("api_image"),
        "pwa": plan_value.get("pwa_image"),
        "postgres-tools": plan_value.get("backup_image"),
    }
    evidence_bindings: dict[str, Any] = {}
    for component, evidence_name in (
        ("control-api", "api"),
        ("pwa", "pwa"),
        ("postgres-tools", "backup"),
    ):
        evidence = require_object(
            images_value.get(evidence_name), f"old {component} image evidence"
        )
        require_exact_keys(
            evidence, {"image_id", "source"}, f"old {component} image evidence"
        )
        evidence_bindings[component] = evidence.get("image_id")
        require_string(evidence.get("source"), f"old {component} image source")
    if (
        plan_bindings != old_component_images
        or evidence_bindings != old_component_images
    ):
        fail("old plan and image evidence do not bind the rollout's old image IDs")
    if (
        images_value.get("release") != rollout_old.get("release")
        or images_value.get("source_revision") != rollout_old.get("vcs_ref")
        or plan_value.get("release") != rollout_old.get("release")
        or plan_value.get("source_revision") != rollout_old.get("vcs_ref")
    ):
        fail("old admission release or VCS identity differs from the rollout plan")
    containers = require_object(
        running_value.get("containers"), "old running containers"
    )
    if set(containers) != set(RUNNING_SERVICE_NAMES):
        fail("old running evidence has an invalid service set")
    result: dict[str, dict[str, str]] = {}
    container_ids: set[str] = set()
    for name in RUNNING_SERVICE_NAMES:
        item = require_object(containers[name], f"old running {name}")
        require_exact_keys(
            item,
            {"container_id", "health", "image_id", "network", "published_port"},
            f"old running {name}",
        )
        container_id = item.get("container_id")
        if (
            not isinstance(container_id, str)
            or CONTAINER_ID_RE.fullmatch(container_id) is None
            or container_id in container_ids
        ):
            fail(f"old running {name} has an invalid or duplicate container ID")
        container_ids.add(container_id)
        expected_image = old_component_images[SERVICE_COMPONENT[name]]
        if item.get("image_id") != expected_image or item.get("health") != "healthy":
            fail(f"old running {name} is not healthy on the admitted old image")
        network = require_string(item.get("network"), f"old running {name} network")
        port = require_string(item.get("published_port"), f"old running {name} port")
        if not port.isdigit() or not 1 <= int(port) <= 65535:
            fail(f"old running {name} has an invalid published port")
        result[name] = {
            "container_id": container_id,
            "image_id": expected_image,
            "network": network,
            "published_port": port,
        }
    return dict(old_component_images), result


def validate_closed_bootstrap(
    bootstrap: Any,
    bootstrap_raw: bytes,
    closure: Any,
    bootstrap_path: Path,
    closure_path: Path,
) -> tuple[str, str]:
    bootstrap_value = require_object(bootstrap, "bootstrap record")
    closure_value = require_object(closure, "authenticated smoke closure")
    if (
        bootstrap_path.name != "bootstrap-deployment.json"
        or closure_path.name != "authenticated-smoke-closure.json"
        or bootstrap_path.parent != closure_path.parent
    ):
        fail("bootstrap record and closure must be fixed siblings")
    match = DEPLOYMENT_DIRECTORY_RE.fullmatch(bootstrap_path.parent.name)
    if match is None:
        fail("bootstrap deployment directory basename is not canonical")
    try:
        deployment_id = str(uuid.UUID(match.group(1), version=4))
    except ValueError:
        fail("bootstrap deployment directory contains an invalid deployment ID")
    if deployment_id != match.group(1):
        fail("bootstrap deployment directory contains a non-canonical deployment ID")
    deployment_basename = bootstrap_path.parent.name
    if (
        bootstrap_value.get("status") != "bootstrapped-unsigned"
        or bootstrap_value.get("trust_mode") != "unsigned-first-deployment-v1"
        or bootstrap_value.get("authenticated_smoke_pending") is not True
    ):
        fail("bootstrap record is not one pending unsigned bootstrap")
    if (
        closure_value.get("format_version") != 2
        or closure_value.get("status") != "authenticated-smoke-closed"
        or closure_value.get("closure_mode") != "append-only-v1"
        or closure_value.get("closes_authenticated_smoke_pending") is not True
        or closure_value.get("original_bootstrap_record_mutated") is not False
    ):
        fail("authenticated smoke closure is not closed append-only evidence")
    binding = require_object(
        closure_value.get("bootstrap_record"), "closure bootstrap binding"
    )
    if (
        binding.get("sha256") != sha256_bytes(bootstrap_raw)
        or binding.get("size") != len(bootstrap_raw)
        or binding.get("basename") != "bootstrap-deployment.json"
        or binding.get("status") != bootstrap_value.get("status")
        or binding.get("trust_mode") != bootstrap_value.get("trust_mode")
        or binding.get("deployment_id") != deployment_id
        or binding.get("deployment_basename") != deployment_basename
        or binding.get("authenticated_smoke_pending") is not True
    ):
        fail("authenticated smoke closure does not bind the unchanged bootstrap record")
    challenge = require_object(
        closure_value.get("closure_challenge"), "closure challenge binding"
    )
    if (
        challenge.get("bootstrap_record_sha256") != sha256_bytes(bootstrap_raw)
        or challenge.get("deployment_id") != deployment_id
        or challenge.get("deployment_basename") != deployment_basename
    ):
        fail("closure challenge does not bind the unchanged bootstrap deployment")
    smoke = require_object(
        closure_value.get("authenticated_smoke"), "authenticated smoke result"
    )
    if (
        smoke.get("status") != "passed"
        or smoke.get("checks_expected") != 84
        or smoke.get("checks_passed") != 84
        or smoke.get("checks_failed") != 0
        or smoke.get("sequential") is not True
        or smoke.get("tap_plan_observed") is not True
    ):
        fail("authenticated smoke closure does not contain a complete passing plan")
    if (
        closure_value.get("$schema")
        != "https://sub2api-codex.invalid/schemas/authenticated-smoke-closure-v2.json"
        or closure_value.get("revocation_observation") is not None
        or smoke.get("check_catalog_sha256")
        != "099d9f4688d72f6866a9d852c8ab4d6b469bf799dde8e879882d94371be31cf7"
        or smoke.get("challenge_sha256")
        != require_object(challenge.get("evidence"), "closure challenge evidence").get(
            "sha256"
        )
        or smoke.get("target_binding_sha256")
        != require_object(challenge.get("target"), "closure challenge target").get(
            "binding_sha256"
        )
    ):
        fail("authenticated smoke closure semantic bindings are invalid")
    return deployment_id, deployment_basename


def validate_bootstrap_evidence_bindings(
    bootstrap: Any,
    closure: Any,
    bootstrap_directory: Path,
    old_plan_raw: bytes,
    old_images_raw: bytes,
    old_running_raw: bytes,
    old_compose_raw: bytes,
) -> None:
    bootstrap_value = require_object(bootstrap, "bootstrap record")
    evidence = require_object(
        bootstrap_value.get("verified_evidence"), "bootstrap verified evidence"
    )
    expected = {
        "compose_plan": ("plan.json", old_plan_raw),
        "local_images": ("images.json", old_images_raw),
        "running_containers": ("running-containers.json", old_running_raw),
    }
    for name, (basename, raw) in expected.items():
        descriptor = require_object(evidence.get(name), f"bootstrap evidence {name}")
        require_exact_keys(
            descriptor, {"path", "sha256", "size"}, f"bootstrap evidence {name}"
        )
        expected_path = bootstrap_directory / basename
        if (
            descriptor.get("path") != str(expected_path)
            or descriptor.get("sha256") != sha256_bytes(raw)
            or descriptor.get("size") != len(raw)
        ):
            fail(f"bootstrap evidence {name} does not bind its fixed sibling")
        sibling = read_regular(expected_path, f"bootstrap evidence {name}")
        if sibling != raw:
            fail(f"bootstrap evidence {name} sibling bytes changed")
    plan_value = decode_json(old_plan_raw, "old bootstrap plan")
    plan_value = require_object(plan_value, "old bootstrap plan")
    if plan_value.get("compose_sha256") != sha256_bytes(old_compose_raw):
        fail("old bootstrap plan does not bind compose-config.json")
    original = require_object(
        require_object(closure, "authenticated smoke closure").get(
            "original_verified_evidence"
        ),
        "closure original verified evidence",
    )
    entries = require_object(original.get("entries"), "closure evidence entries")
    projection: dict[str, dict[str, Any]] = {}
    for name, descriptor_value in evidence.items():
        descriptor = require_object(descriptor_value, f"bootstrap evidence {name}")
        projection[name] = {
            "basename": Path(require_string(descriptor.get("path"), "evidence path")).name,
            "sha256": descriptor.get("sha256"),
            "size": descriptor.get("size"),
        }
    if (
        entries != {name: projection[name] for name in sorted(projection)}
        or original.get("count") != len(projection)
        or original.get("sha256") != sha256_bytes(canonical_json_bytes(projection))
    ):
        fail("closure does not bind the complete bootstrap evidence catalog")


def validate_verifier_evidence(
    value: Any,
    label: str,
    release: str,
    vcs_ref: str,
    bundle_dir: Path,
    *,
    admission: bool,
) -> dict[str, Any]:
    evidence = require_object(value, label)
    require_exact_keys(evidence, VERIFIER_EVIDENCE_KEYS, label)
    expected_status = "verified" if admission else "archive-verified-non-admission"
    if (
        evidence.get("admission") is not admission
        or evidence.get("status") != expected_status
        or evidence.get("release") != release
        or evidence.get("vcs_ref") != vcs_ref
        or evidence.get("source_root_verified") is not admission
        or evidence.get("bundle") != str(bundle_dir)
    ):
        fail(f"{label} does not bind the exact trusted verifier result")
    for key in ("bundle_file_count", "source_file_count"):
        count = evidence.get(key)
        if not isinstance(count, int) or isinstance(count, bool) or count <= 0:
            fail(f"{label} {key} must be one positive integer")
    return evidence


def validate_verifier_projection(
    value: Any,
    label: str,
    kind: str,
    release: str,
    vcs_ref: str,
) -> dict[str, Any]:
    projection = require_object(value, label)
    require_exact_keys(
        projection,
        {
            "admission",
            "bundle_file_count",
            "bundle_id",
            "kind",
            "release",
            "schema_version",
            "source_file_count",
            "source_root_verified",
            "status",
            "vcs_ref",
        },
        label,
    )
    admission = kind != "archive"
    expected_status = "verified" if admission else "archive-verified-non-admission"
    if (
        projection.get("schema_version") != 1
        or projection.get("kind") != kind
        or projection.get("admission") is not admission
        or projection.get("status") != expected_status
        or projection.get("release") != release
        or projection.get("vcs_ref") != vcs_ref
        or projection.get("bundle_id") != TARGET_BUNDLE_ID
        or projection.get("source_root_verified") is not admission
    ):
        fail(f"{label} differs from the fixed privacy-safe verifier projection")
    for key in ("bundle_file_count", "source_file_count"):
        count = projection.get(key)
        if not isinstance(count, int) or isinstance(count, bool) or count <= 0:
            fail(f"{label} {key} must be one positive integer")
    return projection


def project_verifier(args: argparse.Namespace) -> dict[str, Any]:
    bundle_dir = canonical_directory(args.bundle_dir, "verifier bundle directory")
    if bundle_dir.name != TARGET_BUNDLE_ID:
        fail("verifier bundle directory differs from the fixed bundle ID")
    release = require_release(args.release, "verifier release")
    vcs_ref = require_vcs(args.vcs_ref, "verifier VCS ref")
    if release != TARGET_RELEASE or vcs_ref != TARGET_VCS_REF:
        fail("verifier projection target differs from the frozen rollout")
    raw = read_stdin("trusted verifier evidence")
    evidence = validate_verifier_evidence(
        decode_json(raw, "trusted verifier evidence"),
        "trusted verifier evidence",
        release,
        vcs_ref,
        bundle_dir,
        admission=args.kind != "archive",
    )
    return {
        "admission": evidence["admission"],
        "bundle_file_count": evidence["bundle_file_count"],
        "bundle_id": TARGET_BUNDLE_ID,
        "kind": args.kind,
        "release": release,
        "schema_version": 1,
        "source_file_count": evidence["source_file_count"],
        "source_root_verified": evidence["source_root_verified"],
        "status": evidence["status"],
        "vcs_ref": vcs_ref,
    }


def validate_source_evidence(
    value: Any, release: str, vcs_ref: str, bundle_dir: Path
) -> str:
    del bundle_dir
    validate_verifier_projection(value, "source evidence", "source", release, vcs_ref)
    return "trusted-bundle-verifier-source-root"


def validate_bundle_evidence(
    value: Any, release: str, vcs_ref: str, bundle_dir: Path
) -> None:
    del bundle_dir
    validate_verifier_projection(value, "bundle evidence", "bundle", release, vcs_ref)


def validate_archive_evidence(
    value: Any, release: str, vcs_ref: str, bundle_dir: Path
) -> None:
    del bundle_dir
    validate_verifier_projection(value, "archive evidence", "archive", release, vcs_ref)


def canonical_directory(path: Path, label: str) -> Path:
    path = canonical_path(path, label)
    try:
        metadata = os.stat(path, follow_symlinks=False)
    except OSError:
        fail(f"{label} cannot be inspected")
    if not stat.S_ISDIR(metadata.st_mode):
        fail(f"{label} must be one real directory")
    return path


def source_tree_identity(root: Path, label: str) -> dict[str, Any]:
    root = canonical_directory(root, label)
    records: list[dict[str, Any]] = []
    bytecode = 0
    for directory, names, files in os.walk(root, topdown=True, followlinks=False):
        directory_path = Path(directory)
        names.sort(key=os.fsencode)
        files.sort(key=os.fsencode)
        metadata = os.stat(directory_path, follow_symlinks=False)
        if stat.S_IMODE(metadata.st_mode) != 0o555:
            fail(f"{label} directory is not normalized mode 0555")
        for name in names:
            child = directory_path / name
            child_metadata = os.stat(child, follow_symlinks=False)
            if stat.S_ISLNK(child_metadata.st_mode) or not stat.S_ISDIR(
                child_metadata.st_mode
            ):
                fail(f"{label} contains an unsupported directory entry")
            if name == "__pycache__":
                bytecode += 1
        for name in files:
            path = directory_path / name
            relative = path.relative_to(root).as_posix()
            if name.endswith((".pyc", ".pyo")):
                bytecode += 1
            metadata = os.stat(path, follow_symlinks=False)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_nlink != 1
                or stat.S_IMODE(metadata.st_mode) not in {0o444, 0o555}
            ):
                fail(f"{label} contains a non-normalized source file")
            digest, size = hash_regular(path, f"{label} file", maximum=MAX_JSON_BYTES)
            records.append(
                {
                    "mode": format(stat.S_IMODE(metadata.st_mode), "04o"),
                    "path": relative,
                    "sha256": digest,
                    "size": size,
                }
            )
    if bytecode != 0:
        fail(f"{label} contains Python bytecode or cache directories")
    return {
        "bytecode_files": 0,
        "file_count": len(records),
        "tree_sha256": sha256_bytes(canonical_bytes(records)),
    }


def validate_closure_with_source_verifier(
    source_root: Path,
    bootstrap_path: Path,
    closure_path: Path,
    closure_value: Any,
) -> dict[str, Any]:
    verifier_path = source_root / "deploy/scripts/record-authenticated-smoke-closure.py"
    schema_path = source_root / "deploy/schemas/authenticated-smoke-closure.schema.json"
    trusted_regular_metadata(verifier_path, "trusted closure verifier", 0o555)
    trusted_regular_metadata(schema_path, "trusted closure schema", 0o444)
    validate_trusted_ancestors(
        verifier_path.parent, source_root, "trusted closure verifier"
    )
    validate_trusted_ancestors(schema_path.parent, source_root, "trusted closure schema")
    verifier_raw = read_regular(
        verifier_path, "trusted closure verifier", maximum=4 * 1024 * 1024
    )
    schema_raw = read_regular(schema_path, "trusted closure schema")
    verifier_sha = sha256_bytes(verifier_raw)
    schema_sha = sha256_bytes(schema_raw)
    if (
        verifier_sha != TARGET_CLOSURE_VERIFIER_SHA256
        or schema_sha != TARGET_CLOSURE_SCHEMA_SHA256
    ):
        fail("trusted source closure verifier differs from the frozen d518 verifier")
    if (
        bootstrap_path.parent != closure_path.parent
        or closure_path.name != "authenticated-smoke-closure.json"
    ):
        fail("closure verifier inputs are not fixed bootstrap siblings")
    module_name = "_image_rollout_frozen_closure_verifier"
    module = types.ModuleType(module_name)
    module.__file__ = str(verifier_path)
    module.__package__ = ""
    builtin_namespace = vars(builtins).copy()
    original_import = builtins.__import__
    original_zip = builtins.zip

    def compatible_import(
        name: str,
        globals_value: dict[str, Any] | None = None,
        locals_value: dict[str, Any] | None = None,
        fromlist: tuple[str, ...] = (),
        level: int = 0,
    ) -> Any:
        imported = original_import(
            name, globals_value, locals_value, fromlist, level
        )
        if name == "datetime" and not hasattr(imported, "UTC"):
            proxy = types.ModuleType("datetime")
            proxy.__dict__.update(imported.__dict__)
            proxy.UTC = timezone.utc
            return proxy
        return imported

    def compatible_zip(*iterables: Any, strict: bool = False) -> Any:
        if not strict:
            return original_zip(*iterables)
        materialized = [tuple(iterable) for iterable in iterables]
        if len({len(iterable) for iterable in materialized}) > 1:
            raise ValueError("zip() arguments have different lengths")
        return original_zip(*materialized)

    builtin_namespace["__import__"] = compatible_import
    builtin_namespace["zip"] = compatible_zip
    module.__dict__["__builtins__"] = builtin_namespace
    previous = sys.dont_write_bytecode
    sys.dont_write_bytecode = True
    sys.modules[module_name] = module
    try:
        code = compile(verifier_raw, str(verifier_path), "exec", dont_inherit=True)
        exec(code, module.__dict__)  # noqa: S102 - bytes are frozen and hash-verified.
    except Exception:  # noqa: BLE001 - fail closed without exposing verifier internals.
        fail("trusted closure verifier could not be initialized")
    finally:
        sys.modules.pop(module_name, None)
        sys.dont_write_bytecode = previous
    try:
        directory_descriptor, _ = module.open_private_directory(bootstrap_path.parent)
    except Exception:  # noqa: BLE001 - fail closed without exposing verifier internals.
        fail("bootstrap evidence directory does not satisfy closure ownership policy")
    try:
        try:
            verified = module.validate_closure_document(
                closure_value, directory_descriptor, bootstrap_path.parent
            )
        except Exception:  # noqa: BLE001 - fail closed without exposing verifier internals.
            fail("authenticated smoke closure failed the frozen source verifier")
    finally:
        os.close(directory_descriptor)
    if canonical_json_bytes(verified) != canonical_json_bytes(closure_value):
        fail("authenticated smoke closure verifier returned different evidence")
    return require_object(verified, "verified authenticated smoke closure")


def parse_image_checksums(raw: bytes) -> dict[str, str]:
    try:
        lines = raw.decode("ascii").splitlines()
    except UnicodeDecodeError:
        fail("bootstrap image checksum list is not ASCII")
    values: dict[str, str] = {}
    for line in lines:
        match = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9._-]+)", line)
        if match is None or match.group(2) in values:
            fail("bootstrap image checksum list is malformed or duplicated")
        values[match.group(2)] = match.group(1)
    if set(values) != set(ARCHIVE_NAMES.values()):
        fail("bootstrap image checksum list does not bind exactly three archives")
    return values


def validate_bundle_files(
    manifest: Any, manifest_raw: bytes, bundle_dir: Path, rollout: dict[str, Any]
) -> dict[str, dict[str, Any]]:
    if (
        sha256_bytes(manifest_raw) != rollout.get("artifact_manifest_sha256")
        or sha256_bytes(manifest_raw) != TARGET_MANIFEST_SHA256
    ):
        fail("artifact manifest changed after rollout planning")
    release, vcs_ref, images = artifact_identity(manifest)
    if {"images": images, "release": release, "vcs_ref": vcs_ref} != rollout.get(
        "new"
    ):
        fail("artifact manifest identity changed after rollout planning")
    manifest_value = require_object(manifest, "artifact manifest")
    manifest_images = require_object(manifest_value.get("images"), "artifact images")
    checksum_raw = read_regular(
        bundle_dir / "bootstrap-images.sha256",
        "bootstrap image checksum list",
        maximum=4096,
    )
    checksums = parse_image_checksums(checksum_raw)
    transport_raw = read_regular(
        bundle_dir / "transport-SHA256SUMS",
        "transport checksum closure",
        maximum=4096,
    )
    if sha256_bytes(transport_raw) != TARGET_TRANSPORT_CHECKSUM_SHA256:
        fail("transport checksum closure differs from the frozen rollout target")
    transport = require_object(manifest_value.get("transport"), "artifact transport")
    if (
        transport.get("checksum_file") != "transport-SHA256SUMS"
        or transport.get("checksum_file_sha256") != TARGET_TRANSPORT_CHECKSUM_SHA256
        or transport.get("image_checksum_file") != "bootstrap-images.sha256"
        or transport.get("image_checksum_file_sha256") != sha256_bytes(checksum_raw)
    ):
        fail("artifact transport fields do not bind the frozen checksum closures")
    result: dict[str, dict[str, Any]] = {}
    for component, filename in ARCHIVE_NAMES.items():
        image = require_object(manifest_images.get(component), f"artifact {component}")
        if image.get("archive") != filename:
            fail(f"artifact {component} archive filename is not exact")
        expected_sha = require_sha256(
            image.get("archive_sha256"), f"artifact {component} archive hash"
        )
        expected_size = image.get("archive_size")
        if (
            not isinstance(expected_size, int)
            or isinstance(expected_size, bool)
            or expected_size <= 0
        ):
            fail(f"artifact {component} archive size is invalid")
        observed_sha, observed_size = hash_regular(
            bundle_dir / filename, f"artifact {component} archive"
        )
        if (
            observed_sha != expected_sha
            or observed_size != expected_size
            or checksums.get(filename) != expected_sha
        ):
            fail(f"artifact {component} archive bytes differ from admitted evidence")
        result[component] = {
            "basename": filename,
            "sha256": observed_sha,
            "size": observed_size,
        }
    return result


def validate_ready_record(
    value: Any, raw: bytes, path: Path, bundle_dir: Path
) -> dict[str, Any]:
    record = require_object(value, "immutable READY record")
    require_exact_keys(
        record,
        {
            "artifact_directory",
            "artifact_manifest_sha256",
            "bundle_id",
            "release",
            "schema_version",
            "status",
            "transport",
            "vcs_ref",
        },
        "immutable READY record",
    )
    expected_name = f"production-bootstrap-{TARGET_BUNDLE_ID}.READY.json"
    transport = require_object(record.get("transport"), "READY transport")
    require_exact_keys(transport, {"file", "sha256"}, "READY transport")
    if (
        path.name != expected_name
        or path.parent != bundle_dir.parent
        or bundle_dir.name != TARGET_BUNDLE_ID
        or sha256_bytes(raw) != TARGET_READY_RECORD_SHA256
        or record.get("schema_version") != 1
        or record.get("status") != "ready"
        or record.get("artifact_directory") != TARGET_BUNDLE_ID
        or record.get("bundle_id") != TARGET_BUNDLE_ID
        or record.get("artifact_manifest_sha256") != TARGET_MANIFEST_SHA256
        or record.get("release") != TARGET_RELEASE
        or record.get("vcs_ref") != TARGET_VCS_REF
        or transport
        != {
            "file": f"transport/production-bootstrap-{TARGET_BUNDLE_ID}.tar",
            "sha256": TARGET_TRANSPORT_SHA256,
        }
    ):
        fail("READY record differs from the frozen rollout target")
    return record


def validate_utc_timestamp(value: Any, label: str) -> str:
    result = require_string(value, label, maximum=64)
    match = re.fullmatch(
        r"([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})Z",
        result,
    )
    if match is None:
        fail(f"{label} must be one canonical whole-second UTC timestamp")
    try:
        parsed = datetime.strptime(result, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError:
        fail(f"{label} is not a real UTC timestamp")
    if parsed.strftime("%Y-%m-%dT%H:%M:%SZ") != result:
        fail(f"{label} is not a canonical UTC timestamp")
    return result


def validate_operator_exception(value: Any) -> dict[str, Any]:
    instruction = require_object(value, "operator no-duplicate-backup instruction")
    require_exact_keys(
        instruction,
        {
            "acknowledged_at",
            "allowed_operations",
            "duplicate_backup_prohibited",
            "forbidden_operations",
            "reason",
            "schema_version",
            "scope",
            "type",
        },
        "operator no-duplicate-backup instruction",
    )
    if (
        instruction.get("schema_version") != 1
        or instruction.get("type") != "no-duplicate-backup-operator-instruction-v1"
        or instruction.get("reason") != "operator-prohibited-duplicate-backup"
        or instruction.get("duplicate_backup_prohibited") is not True
        or instruction.get("scope") != "bootstrap-image-only-followup-v1"
        or instruction.get("forbidden_operations") != OPERATOR_FORBIDDEN_OPERATIONS
        or instruction.get("allowed_operations") != OPERATOR_ALLOWED_OPERATIONS
    ):
        fail("operator instruction does not authorize the exact image-only follow-up")
    validate_utc_timestamp(
        instruction.get("acknowledged_at"), "operator acknowledgment"
    )
    return instruction


def migration_assignment(path: Path, raw: bytes) -> tuple[str, str | None]:
    try:
        tree = ast.parse(raw.decode("utf-8"), filename=str(path))
    except (UnicodeDecodeError, SyntaxError):
        fail(f"migration is not valid UTF-8 Python: {path.name}")
    values: dict[str, Any] = {}
    for node in tree.body:
        name: str | None = None
        expression: ast.expr | None = None
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            name, expression = node.target.id, node.value
        elif (
            isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
        ):
            name, expression = node.targets[0].id, node.value
        if name in {"revision", "down_revision"} and expression is not None:
            if name in values:
                fail(f"migration repeats its {name}: {path.name}")
            try:
                values[name] = ast.literal_eval(expression)
            except (ValueError, TypeError, SyntaxError):
                fail(f"migration has a non-literal {name}: {path.name}")
    revision = values.get("revision")
    parent = values.get("down_revision")
    if not isinstance(revision, str) or REVISION_RE.fullmatch(revision) is None:
        fail(f"migration has an invalid revision: {path.name}")
    if parent is not None and (
        not isinstance(parent, str) or REVISION_RE.fullmatch(parent) is None
    ):
        fail(f"migration has an invalid down_revision: {path.name}")
    return revision, parent


def migration_tree(root: Path, label: str) -> tuple[str, list[dict[str, Any]]]:
    root = canonical_path(root, label)
    try:
        metadata = os.stat(root, follow_symlinks=False)
    except OSError:
        fail(f"{label} cannot be inspected")
    if not stat.S_ISDIR(metadata.st_mode):
        fail(f"{label} must be a real directory")
    versions = canonical_path(
        root / "migrations" / "versions", f"{label} migration directory"
    )
    if not stat.S_ISDIR(os.stat(versions, follow_symlinks=False).st_mode):
        fail(f"{label} migration directory is not a directory")
    try:
        names = sorted(item.name for item in versions.iterdir())
    except OSError:
        fail(f"{label} migration directory cannot be listed")
    if any(not MIGRATION_NAME_RE.fullmatch(name) for name in names):
        fail(f"{label} migration directory contains an unexpected entry")
    if len(names) != 8 or len(names) != len(set(names)):
        fail(f"{label} must contain exactly eight migration files")
    records: list[dict[str, Any]] = []
    revisions: dict[str, str | None] = {}
    total = 0
    for name in names:
        path = versions / name
        raw = read_regular(
            path, f"{label} migration {name}", maximum=MAX_MIGRATION_BYTES
        )
        total += len(raw)
        if total > MAX_MIGRATION_TREE_BYTES:
            fail(f"{label} migration tree exceeds its size limit")
        revision, parent = migration_assignment(path, raw)
        if revision in revisions:
            fail(f"{label} migration revisions are duplicated")
        revisions[revision] = parent
        records.append(
            {
                "down_revision": parent,
                "path": f"migrations/versions/{name}",
                "revision": revision,
                "sha256": sha256_bytes(raw),
                "size": len(raw),
            }
        )
    revision_set = set(revisions)
    parents = {parent for parent in revisions.values() if parent is not None}
    if not parents.issubset(revision_set):
        fail(f"{label} migration history references an unknown parent")
    heads = revision_set - parents
    roots = [revision for revision, parent in revisions.items() if parent is None]
    if len(heads) != 1 or len(roots) != 1:
        fail(f"{label} migration history is not one linear chain")
    current = next(iter(heads))
    visited: set[str] = set()
    while current is not None:
        if current in visited:
            fail(f"{label} migration history contains a cycle")
        visited.add(current)
        current = revisions[current]
    if visited != revision_set:
        fail(f"{label} migration history is branched or disconnected")
    return next(iter(heads)), records


def validate_container_projection(
    value: Any, label: str
) -> dict[str, dict[str, Any]]:
    projection = require_object(value, label)
    require_exact_keys(projection, {"containers", "schema_version"}, label)
    if projection.get("schema_version") != 1:
        fail(f"{label} has an unsupported schema version")
    containers = require_object(projection.get("containers"), f"{label} containers")
    if set(containers) != set(RUNNING_SERVICE_NAMES):
        fail(f"{label} must contain exactly the three rollout services")
    ids: set[str] = set()
    result: dict[str, dict[str, Any]] = {}
    for service in RUNNING_SERVICE_NAMES:
        item = require_object(containers[service], f"{label} {service}")
        require_exact_keys(
            item,
            {
                "container_id",
                "health",
                "image_id",
                "networks",
                "ports",
                "project",
                "release",
                "restart_count",
                "running",
                "service",
                "status",
                "vcs_ref",
            },
            f"{label} {service}",
        )
        container_id = item.get("container_id")
        if (
            not isinstance(container_id, str)
            or CONTAINER_ID_RE.fullmatch(container_id) is None
            or container_id in ids
        ):
            fail(f"{label} {service} has an invalid or duplicate container ID")
        ids.add(container_id)
        require_sha256(item.get("image_id"), f"{label} {service} image", image=True)
        require_string(item.get("project"), f"{label} {service} project")
        if item.get("service") != service:
            fail(f"{label} {service} service label is invalid")
        require_release(item.get("release"), f"{label} {service} release")
        require_vcs(item.get("vcs_ref"), f"{label} {service} VCS ref")
        if (
            item.get("running") is not True
            or item.get("status") != "running"
            or item.get("health") != "healthy"
            or item.get("restart_count") != 0
        ):
            fail(f"{label} {service} is not a clean healthy running container")
        validate_string_set(item.get("networks"), f"{label} {service} networks")
        validate_string_set(item.get("ports"), f"{label} {service} ports")
        result[service] = item
    return result


def project_container(args: argparse.Namespace) -> dict[str, Any]:
    raw = read_stdin("Docker container inspection")
    value = decode_json(raw, "Docker container inspection")
    if not isinstance(value, list) or len(value) != 1:
        fail("Docker container inspection must be one single-item array")
    inspection = require_object(value[0], "Docker container inspection")
    config = require_object(inspection.get("Config"), "Docker container Config")
    labels = require_object(config.get("Labels"), "Docker container labels")
    service = args.service
    if labels.get("com.docker.compose.service") != service:
        fail("Docker inspection service label differs from the requested service")
    project = require_string(
        labels.get("com.docker.compose.project"), "Docker Compose project"
    )
    container_id = inspection.get("Id")
    if not isinstance(container_id, str) or CONTAINER_ID_RE.fullmatch(container_id) is None:
        fail("Docker container ID is invalid")
    image_id = require_sha256(
        inspection.get("Image"), "Docker container image", image=True
    )
    state = require_object(inspection.get("State"), "Docker container state")
    health = require_object(state.get("Health"), "Docker container health")
    restart_count = inspection.get("RestartCount")
    if not isinstance(restart_count, int) or isinstance(restart_count, bool) or restart_count < 0:
        fail("Docker container restart count is invalid")
    network_settings = require_object(
        inspection.get("NetworkSettings"), "Docker container network settings"
    )
    networks_value = require_object(
        network_settings.get("Networks"), "Docker container networks"
    )
    networks = sorted(networks_value)
    if not networks:
        fail("Docker container has no network")
    ports_value = require_object(network_settings.get("Ports"), "Docker container ports")
    ports: list[str] = []
    for target in sorted(ports_value):
        bindings = ports_value[target]
        if not isinstance(bindings, list) or len(bindings) != 1:
            fail("Docker container port must have one binding")
        binding = require_object(bindings[0], "Docker container port binding")
        require_exact_keys(binding, {"HostIp", "HostPort"}, "Docker port binding")
        host_ip = binding.get("HostIp")
        host_port = binding.get("HostPort")
        if (
            host_ip != "127.0.0.1"
            or not isinstance(host_port, str)
            or not host_port.isdigit()
            or not 1 <= int(host_port) <= 65535
        ):
            fail("Docker container port is not exact loopback TCP")
        if re.fullmatch(r"[1-9][0-9]{0,4}/tcp", target) is None:
            fail("Docker target port is invalid")
        ports.append(f"{target}=127.0.0.1:{host_port}")
    return {
        "service": service,
        "projection": {
            "container_id": container_id,
            "health": health.get("Status"),
            "image_id": image_id,
            "networks": networks,
            "ports": ports,
            "project": project,
            "release": require_release(
                labels.get(OCI_VERSION_LABEL), "Docker container release"
            ),
            "restart_count": restart_count,
            "running": state.get("Running"),
            "service": service,
            "status": state.get("Status"),
            "vcs_ref": require_vcs(
                labels.get(OCI_REVISION_LABEL), "Docker container VCS ref"
            ),
        },
        "schema_version": 1,
    }


def project_image(args: argparse.Namespace) -> dict[str, Any]:
    del args
    raw = read_stdin("Docker image inspection")
    value = decode_json(raw, "Docker image inspection")
    if not isinstance(value, list) or len(value) != 1:
        fail("Docker image inspection must be one single-item array")
    inspection = require_object(value[0], "Docker image inspection")
    image_id = require_sha256(
        inspection.get("Id"), "Docker image inspection ID", image=True
    )
    config = require_object(inspection.get("Config"), "Docker image Config")
    labels = require_object(config.get("Labels"), "Docker image labels")
    return {
        "image_id": image_id,
        "release": require_release(
            labels.get(OCI_VERSION_LABEL), "Docker image release"
        ),
        "schema_version": 1,
        "vcs_ref": require_vcs(
            labels.get(OCI_REVISION_LABEL), "Docker image VCS ref"
        ),
    }


def validate_current_before_inspect(
    projection: Any,
    rollout: dict[str, Any],
    old_containers: dict[str, dict[str, str]],
) -> dict[str, dict[str, Any]]:
    projected = validate_container_projection(projection, "current-before projection")
    old_identity = require_object(rollout.get("old"), "rollout old identity")
    old_images = require_object(old_identity.get("images"), "rollout old images")
    compose = require_object(rollout.get("new_compose"), "rollout Compose")
    project = require_string(compose.get("name"), "resolved Compose project name")
    result: dict[str, dict[str, Any]] = {}
    for service in RUNNING_SERVICE_NAMES:
        item = projected[service]
        if item.get("project") != project:
            fail(f"current-before {service} belongs to a different Compose project")
        historical = old_containers[service]
        expected_image = old_images[SERVICE_COMPONENT[service]]
        if (
            item.get("container_id") != historical["container_id"]
            or item.get("image_id") != expected_image
        ):
            fail(f"current-before {service} drifted from the admitted old container")
        if (
            item.get("release") != old_identity.get("release")
            or item.get("vcs_ref") != old_identity.get("vcs_ref")
        ):
            fail(f"current-before {service} labels differ from the old identity")
        target, published = compose_port(compose, service)
        expected_network = compose_concrete_network(compose, service)
        if (
            historical["published_port"] != published
            or historical["network"] != expected_network
            or item.get("ports") != [f"{target}=127.0.0.1:{published}"]
            or item.get("networks") != [expected_network]
        ):
            fail(f"current-before {service} ports or networks drifted")
        result[service] = {
            "container_id": historical["container_id"],
            "health": "healthy",
            "image_id": expected_image,
            "network": expected_network,
            "published_port": published,
            "target_port": target,
        }
    return result


def baseline(args: argparse.Namespace) -> dict[str, Any]:
    tooling = validate_tools_manifest(args.tools_manifest)
    tooling = validate_tools_admission(
        args.tools_admission, args.tools_manifest, tooling
    )
    rollout, rollout_raw = load_json(args.plan, "rollout plan")
    rollout = validate_rollout_plan(rollout)
    operator, operator_raw = load_json(
        args.operator_exception, "operator no-duplicate-backup instruction"
    )
    validate_operator_exception(operator)
    old_plan, old_plan_raw = load_json(args.old_plan, "old bootstrap plan")
    old_images, old_images_raw = load_json(args.old_images, "old image evidence")
    old_running, old_running_raw = load_json(args.old_running, "old running evidence")
    old_component_images, old_containers = validate_old_admission(
        rollout, old_plan, old_images, old_running
    )
    current_before, current_before_raw = load_json(
        args.current_before_inspect, "current-before container inspections"
    )
    current_containers = validate_current_before_inspect(
        current_before, rollout, old_containers
    )
    new_identity = require_object(rollout["new"], "rollout plan new identity")
    release = require_release(new_identity.get("release"), "new release")
    vcs_ref = require_vcs(new_identity.get("vcs_ref"), "new VCS ref")
    if release != TARGET_RELEASE or vcs_ref != TARGET_VCS_REF:
        fail("rollout plan differs from the frozen release and source target")
    source, source_raw = load_json(args.source_evidence, "source evidence")
    source_kind = validate_source_evidence(source, release, vcs_ref, args.bundle_dir)
    source_tree = source_tree_identity(args.new_source_root, "new source root")
    bootstrap, bootstrap_raw = load_json(args.bootstrap_record, "bootstrap record")
    closure, closure_raw = load_json(args.closure_record, "authenticated smoke closure")
    closure = validate_closure_with_source_verifier(
        args.new_source_root,
        args.bootstrap_record,
        args.closure_record,
        closure,
    )
    deployment_id, deployment_basename = validate_closed_bootstrap(
        bootstrap,
        bootstrap_raw,
        closure,
        args.bootstrap_record,
        args.closure_record,
    )
    expected_old_compose = args.bootstrap_record.parent / "compose-config.json"
    if args.old_compose != expected_old_compose:
        fail("old Compose must be the fixed bootstrap compose-config.json sibling")
    old_compose, old_compose_raw = load_json(args.old_compose, "old Compose config")
    old_compose = require_object(old_compose, "old Compose config")
    old_release, old_vcs, old_compose_images = compose_identity(
        old_compose, "old Compose config"
    )
    if (old_release, old_vcs, old_compose_images) != (
        rollout["old"]["release"],
        rollout["old"]["vcs_ref"],
        rollout["old"]["images"],
    ):
        fail("old bootstrap Compose identity differs from the rollout plan")
    validate_bootstrap_evidence_bindings(
        bootstrap,
        closure,
        args.bootstrap_record.parent,
        old_plan_raw,
        old_images_raw,
        old_running_raw,
        old_compose_raw,
    )
    bundle_dir = canonical_directory(args.bundle_dir, "bundle directory")
    artifact_path = canonical_path(args.artifact_manifest, "artifact manifest")
    if artifact_path != bundle_dir / "artifact-manifest.json":
        fail("artifact manifest must have its fixed basename inside the bundle")
    artifact, artifact_raw = load_json(artifact_path, "artifact manifest")
    ready, ready_raw = load_json(args.ready_record, "immutable READY record")
    ready = validate_ready_record(ready, ready_raw, args.ready_record, bundle_dir)
    bundle, bundle_raw = load_json(args.bundle_evidence, "bundle evidence")
    archive, archive_raw = load_json(args.archive_evidence, "archive evidence")
    validate_bundle_evidence(bundle, release, vcs_ref, bundle_dir)
    validate_archive_evidence(archive, release, vcs_ref, bundle_dir)
    archives = validate_bundle_files(artifact, artifact_raw, bundle_dir, rollout)
    old_head, old_migrations = migration_tree(args.old_source_root, "old source root")
    new_head, new_migrations = migration_tree(args.new_source_root, "new source root")
    if old_migrations != new_migrations or old_head != new_head:
        fail(
            "old and new source roots do not contain byte-identical migration histories"
        )
    migration_state, migration_state_raw = load_json(
        args.migration_state, "database migration state"
    )
    migration_state = require_object(migration_state, "database migration state")
    require_exact_keys(
        migration_state,
        {"current_revision", "head_revision"},
        "database migration state",
    )
    if (
        migration_state.get("current_revision") != new_head
        or migration_state.get("head_revision") != new_head
    ):
        fail("database migration current revision is not the unchanged source head")
    return {
        "command": "baseline",
        "format_version": FORMAT_VERSION,
        "status": "admitted",
        "no_backup": True,
        "no_migration": True,
        "operator_exception_sha256": sha256_bytes(operator_raw),
        "rollout_plan_sha256": sha256_bytes(rollout_raw),
        "old_admission": {
            "images": old_component_images,
            "containers": old_containers,
            "plan_sha256": sha256_bytes(old_plan_raw),
            "images_sha256": sha256_bytes(old_images_raw),
            "running_sha256": sha256_bytes(old_running_raw),
            "current_before_inspect_sha256": sha256_bytes(current_before_raw),
            "current_containers": current_containers,
        },
        "bootstrap_record_sha256": sha256_bytes(bootstrap_raw),
        "closure_record_sha256": sha256_bytes(closure_raw),
        "closure_target": closure["closure_challenge"]["target"],
        "bootstrap_deployment": {
            "deployment_basename": deployment_basename,
            "deployment_id": deployment_id,
        },
        "source_evidence": {
            "kind": source_kind,
            "sha256": sha256_bytes(source_raw),
            "tree": source_tree,
        },
        "bundle_evidence_sha256": sha256_bytes(bundle_raw),
        "archive_evidence_sha256": sha256_bytes(archive_raw),
        "artifact_manifest_sha256": sha256_bytes(artifact_raw),
        "ready_record": {
            "bundle_id": ready["bundle_id"],
            "sha256": sha256_bytes(ready_raw),
            "transport_sha256": ready["transport"]["sha256"],
        },
        "archives": archives,
        "migration_state_sha256": sha256_bytes(migration_state_raw),
        "migrations": {"count": 8, "head": new_head, "files": new_migrations},
        "tooling": tooling,
    }


def compose_concrete_network(compose: dict[str, Any], service: str) -> str:
    services = compose_services(compose, "rollout plan new Compose")
    networks = services[service].get("networks")
    if not isinstance(networks, dict) or len(networks) != 1:
        fail(f"new Compose {service} must use exactly one network")
    key = next(iter(networks))
    top_networks = compose.get("networks")
    definition = top_networks.get(key) if isinstance(top_networks, dict) else None
    if not isinstance(definition, dict):
        fail(f"new Compose {service} network is unresolved")
    concrete = definition.get("name")
    if not isinstance(concrete, str) or not concrete:
        fail(f"new Compose {service} network has no concrete name")
    return concrete


def compose_port(compose: dict[str, Any], service: str) -> tuple[str, str]:
    services = compose_services(compose, "rollout plan new Compose")
    ports = services[service].get("ports")
    if not isinstance(ports, list) or len(ports) != 1 or not isinstance(ports[0], dict):
        fail(f"new Compose {service} must publish exactly one port")
    port = ports[0]
    target = port.get("target")
    published = port.get("published")
    if isinstance(published, int) and not isinstance(published, bool):
        published = str(published)
    if (
        not isinstance(target, int)
        or isinstance(target, bool)
        or not 1 <= target <= 65535
        or not isinstance(published, str)
        or not published.isdigit()
        or not 1 <= int(published) <= 65535
        or port.get("host_ip") != "127.0.0.1"
        or port.get("protocol") != "tcp"
        or port.get("mode") != "ingress"
    ):
        fail(f"new Compose {service} port is not one exact loopback TCP binding")
    return f"{target}/tcp", published


def running(args: argparse.Namespace) -> dict[str, Any]:
    rollout, rollout_raw = load_json(args.plan, "rollout plan")
    rollout = validate_rollout_plan(rollout)
    projection, projection_raw = load_json(
        args.inspect, "running container projection"
    )
    projected = validate_container_projection(projection, "running projection")
    new_identity = require_object(rollout["new"], "rollout plan new identity")
    images = require_object(new_identity.get("images"), "rollout plan new images")
    compose = require_object(rollout.get("new_compose"), "rollout plan new Compose")
    project = require_string(compose.get("name"), "resolved Compose project name")
    result: dict[str, dict[str, Any]] = {}
    for service in RUNNING_SERVICE_NAMES:
        item = projected[service]
        if item.get("project") != project:
            fail(f"running {service} belongs to a different Compose project")
        container_id = item["container_id"]
        image_id = images[SERVICE_COMPONENT[service]]
        if item.get("image_id") != image_id:
            fail(f"running {service} does not use the admitted new image ID")
        if item.get("release") != new_identity.get("release") or item.get(
            "vcs_ref"
        ) != new_identity.get("vcs_ref"):
            fail(f"running {service} labels do not bind the new release identity")
        target, published = compose_port(compose, service)
        expected_port = [f"{target}=127.0.0.1:{published}"]
        if item.get("ports") != expected_port:
            fail(f"running {service} runtime ports differ from new Compose")
        expected_network = compose_concrete_network(compose, service)
        if item.get("networks") != [expected_network]:
            fail(f"running {service} networks differ from new Compose")
        result[service] = {
            "container_id": container_id,
            "health": "healthy",
            "image_id": image_id,
            "network": expected_network,
            "published_port": published,
            "target_port": target,
        }
    if set(result) != set(RUNNING_SERVICE_NAMES):
        fail("running evidence does not cover the exact service set")
    return {
        "command": "running",
        "format_version": FORMAT_VERSION,
        "status": "admitted",
        "plan_sha256": sha256_bytes(rollout_raw),
        "inspect_sha256": sha256_bytes(projection_raw),
        "containers": result,
    }


def stage(args: argparse.Namespace) -> dict[str, Any]:
    rollout, rollout_raw = load_json(args.plan, "rollout plan")
    rollout = validate_rollout_plan(rollout)
    baseline_value, baseline_raw = load_json(args.baseline, "rollout baseline")
    baseline_value = require_object(baseline_value, "rollout baseline")
    if (
        baseline_value.get("command") != "baseline"
        or baseline_value.get("format_version") != FORMAT_VERSION
        or baseline_value.get("status") != "admitted"
        or baseline_value.get("rollout_plan_sha256") != sha256_bytes(rollout_raw)
    ):
        fail("rollout baseline is not admitted for this plan")
    before_value, before_raw = load_json(args.before, "stage before projection")
    after_value, after_raw = load_json(args.after, "stage after projection")
    before = validate_container_projection(before_value, "stage before projection")
    after = validate_container_projection(after_value, "stage after projection")
    target = args.target
    old_admission = require_object(
        baseline_value.get("old_admission"), "baseline old admission"
    )
    old_current = require_object(
        old_admission.get("current_containers"), "baseline current containers"
    )
    old_identity = require_object(rollout.get("old"), "rollout old identity")
    new_identity = require_object(rollout.get("new"), "rollout new identity")
    target_before = before[target]
    target_after = after[target]
    old_target = require_object(old_current.get(target), "baseline target container")
    expected_old_image = old_identity["images"][SERVICE_COMPONENT[target]]
    expected_new_image = new_identity["images"][SERVICE_COMPONENT[target]]
    if (
        target_before.get("container_id") != old_target.get("container_id")
        or target_before.get("image_id") != expected_old_image
        or target_before.get("release") != old_identity.get("release")
        or target_before.get("vcs_ref") != old_identity.get("vcs_ref")
    ):
        fail("stage target before projection differs from the admitted old container")
    if (
        target_after.get("container_id") == target_before.get("container_id")
        or target_after.get("image_id") != expected_new_image
        or target_after.get("release") != new_identity.get("release")
        or target_after.get("vcs_ref") != new_identity.get("vcs_ref")
        or target_after.get("project") != target_before.get("project")
        or target_after.get("service") != target
        or target_after.get("ports") != target_before.get("ports")
        or target_after.get("networks") != target_before.get("networks")
    ):
        fail("stage target did not become exactly the admitted new container")
    for service in RUNNING_SERVICE_NAMES:
        if service != target and before[service] != after[service]:
            fail(f"stage changed non-target service {service}")
    protected_before, protected_before_raw = load_json(
        args.protected_before, "stage protected before snapshot"
    )
    protected_after, protected_after_raw = load_json(
        args.protected_after, "stage protected after snapshot"
    )
    protected_before = validate_invariant_snapshot(
        protected_before, "stage protected before snapshot"
    )
    protected_after = validate_invariant_snapshot(
        protected_after, "stage protected after snapshot"
    )
    if protected_before != protected_after:
        fail("stage changed a protected container, listener, Nginx, or UFW projection")
    readiness, readiness_raw = load_json(args.readiness, "stage readiness evidence")
    readiness = require_object(readiness, "stage readiness evidence")
    require_exact_keys(
        readiness,
        {
            "container_id",
            "health",
            "image_id",
            "networks",
            "ports",
            "restart_count",
            "schema_version",
            "service",
            "status",
        },
        "stage readiness evidence",
    )
    if readiness != {
        "container_id": target_after["container_id"],
        "health": "healthy",
        "image_id": expected_new_image,
        "networks": target_after["networks"],
        "ports": target_after["ports"],
        "restart_count": 0,
        "schema_version": 1,
        "service": target,
        "status": "ready",
    }:
        fail("stage readiness evidence differs from the target after projection")
    return {
        "after_sha256": sha256_bytes(after_raw),
        "baseline_sha256": sha256_bytes(baseline_raw),
        "before_sha256": sha256_bytes(before_raw),
        "command": "stage",
        "format_version": FORMAT_VERSION,
        "new_container_id": target_after["container_id"],
        "new_image_id": expected_new_image,
        "old_container_id": target_before["container_id"],
        "old_image_id": expected_old_image,
        "plan_sha256": sha256_bytes(rollout_raw),
        "protected_after_sha256": sha256_bytes(protected_after_raw),
        "protected_before_sha256": sha256_bytes(protected_before_raw),
        "readiness_sha256": sha256_bytes(readiness_raw),
        "status": "admitted",
        "target": target,
    }


def validate_string_set(
    value: Any, label: str, *, allow_empty: bool = False
) -> list[str]:
    if (
        not isinstance(value, list)
        or (not value and not allow_empty)
        or any(not isinstance(item, str) or not item for item in value)
        or value != sorted(set(value))
    ):
        fail(f"{label} must be one sorted unique string list")
    return value


def require_nonnegative_integer(value: Any, label: str, *, maximum: int | None = None) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or value < 0
        or (maximum is not None and value > maximum)
    ):
        fail(f"{label} must be one bounded nonnegative integer")
    return value


def normalize_alembic_revision(raw: bytes, label: str) -> str:
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError:
        fail(f"{label} is not ASCII")
    candidates: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        token = stripped.split(maxsplit=1)[0]
        if REVISION_RE.fullmatch(token):
            candidates.append(token)
    candidates = list(dict.fromkeys(candidates))
    if len(candidates) != 1:
        fail(f"{label} did not contain exactly one migration revision")
    return candidates[0]


def digest_tree(root: Path, label: str) -> str:
    root = canonical_directory(root, label)
    records: list[dict[str, Any]] = []
    for directory, names, files in os.walk(root, topdown=True, followlinks=False):
        directory_path = Path(directory)
        names.sort(key=os.fsencode)
        files.sort(key=os.fsencode)
        for name in names + files:
            path = directory_path / name
            relative = path.relative_to(root).as_posix()
            metadata = os.stat(path, follow_symlinks=False)
            mode = stat.S_IMODE(metadata.st_mode)
            if stat.S_ISDIR(metadata.st_mode):
                records.append(
                    {
                        "gid": metadata.st_gid,
                        "kind": "directory",
                        "mode": mode,
                        "path": relative,
                        "uid": metadata.st_uid,
                    }
                )
            elif stat.S_ISREG(metadata.st_mode):
                digest, size = hash_regular(
                    path,
                    f"{label} {relative}",
                    maximum=MAX_INVARIANT_TEXT_BYTES,
                    allow_empty=True,
                )
                records.append(
                    {
                        "kind": "file",
                        "gid": metadata.st_gid,
                        "mode": mode,
                        "path": relative,
                        "sha256": digest,
                        "size": size,
                        "uid": metadata.st_uid,
                    }
                )
            elif stat.S_ISLNK(metadata.st_mode):
                try:
                    target = os.readlink(path)
                except OSError:
                    fail(f"{label} symbolic link cannot be read")
                records.append(
                    {
                        "gid": metadata.st_gid,
                        "kind": "symlink",
                        "mode": mode,
                        "path": relative,
                        "target_sha256": sha256_bytes(os.fsencode(target)),
                        "uid": metadata.st_uid,
                    }
                )
            else:
                fail(f"{label} contains an unsupported entry")
    if not records:
        fail(f"{label} is empty")
    return sha256_bytes(canonical_json_bytes(records))


def normalize_text_lines(
    raw: bytes,
    label: str,
    *,
    require_nonempty: bool = True,
    unordered: bool = False,
) -> list[str]:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        fail(f"{label} is not valid UTF-8")
    if "\x00" in text:
        fail(f"{label} contains a NUL byte")
    lines = [" ".join(line.split()) for line in text.splitlines()]
    lines = [line for line in lines if line]
    if unordered:
        lines = sorted(set(lines))
    if require_nonempty and not lines:
        fail(f"{label} is empty")
    if any(len(line) > 4096 for line in lines):
        fail(f"{label} contains an overlong line")
    return lines


def normalize_ordered_text_bytes(raw: bytes, label: str) -> bytes:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        fail(f"{label} is not valid UTF-8")
    if "\x00" in text:
        fail(f"{label} contains a NUL byte")
    text = text.replace("\r\n", "\n")
    if "\r" in text:
        fail(f"{label} contains a non-canonical carriage return")
    if not text:
        fail(f"{label} is empty")
    return text.encode("utf-8")


def project_listeners(raw: bytes) -> list[str]:
    try:
        lines = raw.decode("utf-8").splitlines()
    except UnicodeDecodeError:
        fail("socket listener snapshot is not valid UTF-8")
    projected: set[str] = set()
    for line in lines:
        fields = line.split()
        if len(fields) < 5:
            fail("socket listener snapshot contains a short row")
        protocol, state, _receive, _send, local = fields[:5]
        if protocol not in {"tcp", "udp"} or state not in {"LISTEN", "UNCONN"}:
            fail("socket listener snapshot contains an unexpected protocol or state")
        if not local or len(local) > 512:
            fail("socket listener snapshot contains an invalid local endpoint")
        projected.add(f"{protocol} {state} {local}")
    if not projected:
        fail("socket listener snapshot is empty")
    return sorted(projected)


def project_invariant_container(value: Any, label: str) -> dict[str, Any]:
    inspection = require_object(value, label)
    container_id = inspection.get("Id")
    if not isinstance(container_id, str) or CONTAINER_ID_RE.fullmatch(container_id) is None:
        fail(f"{label} has an invalid container ID")
    image_id = require_sha256(inspection.get("Image"), f"{label} image", image=True)
    config = require_object(inspection.get("Config"), f"{label} Config")
    host = require_object(inspection.get("HostConfig"), f"{label} HostConfig")
    state = require_object(inspection.get("State"), f"{label} State")
    health = require_object(state.get("Health"), f"{label} health")
    if state.get("Running") is not True or health.get("Status") != "healthy":
        fail(f"{label} is not running and healthy")
    for key in ("Dead", "OOMKilled", "Paused", "Restarting"):
        if state.get(key) is not False:
            fail(f"{label} has an inadmissible State.{key}")
    restart_count = require_nonnegative_integer(
        inspection.get("RestartCount"), f"{label} restart count"
    )
    if host.get("Privileged") is not False:
        fail(f"{label} is privileged")
    read_only = host.get("ReadonlyRootfs")
    if not isinstance(read_only, bool):
        fail(f"{label} read-only root flag is invalid")
    cap_add = host.get("CapAdd") or []
    cap_drop = host.get("CapDrop") or []
    if not isinstance(cap_add, list) or not isinstance(cap_drop, list):
        fail(f"{label} capability lists are invalid")
    cap_add = sorted({require_string(item, f"{label} added capability") for item in cap_add})
    cap_drop = sorted({require_string(item, f"{label} dropped capability") for item in cap_drop})
    security_options = host.get("SecurityOpt") or []
    if not isinstance(security_options, list):
        fail(f"{label} security options are invalid")
    security_options = sorted(
        {
            require_string(item, f"{label} security option", maximum=1024)
            for item in security_options
        }
    )
    no_new_privileges = any(
        item in {"no-new-privileges", "no-new-privileges=true"}
        for item in security_options
    )
    user = config.get("User")
    if not isinstance(user, str):
        fail(f"{label} user is invalid")
    namespace_projection = {
        key: host.get(key) or ""
        for key in ("CgroupnsMode", "IpcMode", "PidMode", "UsernsMode", "UTSMode")
    }
    if any(not isinstance(item, str) for item in namespace_projection.values()):
        fail(f"{label} namespace modes are invalid")
    mounts = inspection.get("Mounts") or []
    if not isinstance(mounts, list):
        fail(f"{label} mounts are invalid")
    mount_projection: list[dict[str, Any]] = []
    for item_value in mounts:
        item = require_object(item_value, f"{label} mount")
        destination = item.get("Destination")
        if not isinstance(destination, str) or not destination.startswith("/"):
            fail(f"{label} mount destination is invalid")
        propagation = item.get("Propagation") or ""
        if not isinstance(propagation, str):
            fail(f"{label} mount propagation is invalid")
        mount_projection.append(
            {
                "destination": destination,
                "mode": require_string(item.get("Mode") or "", f"{label} mount mode"),
                "name_sha256": sha256_bytes(
                    require_string(item.get("Name") or "", f"{label} mount name").encode(
                        "utf-8"
                    )
                ),
                "propagation": propagation,
                "read_write": item.get("RW"),
                "source_sha256": sha256_bytes(
                    require_string(
                        item.get("Source") or "", f"{label} mount source", maximum=4096
                    ).encode("utf-8")
                ),
                "type": require_string(item.get("Type"), f"{label} mount type"),
            }
        )
    if any(not isinstance(item["read_write"], bool) for item in mount_projection):
        fail(f"{label} mount access flag is invalid")
    mount_projection.sort(key=lambda item: canonical_json_bytes(item))
    devices = host.get("Devices") or []
    device_requests = host.get("DeviceRequests") or []
    if not isinstance(devices, list) or not isinstance(device_requests, list):
        fail(f"{label} device access is invalid")
    device_descriptors: list[dict[str, Any]] = []
    for device_value in devices:
        device = require_object(device_value, f"{label} device")
        require_exact_keys(
            device,
            {"CgroupPermissions", "PathInContainer", "PathOnHost"},
            f"{label} device",
        )
        device_descriptors.append(
            {
                "cgroup_permissions": require_string(
                    device.get("CgroupPermissions"), f"{label} device permissions"
                ),
                "container_path_sha256": sha256_bytes(
                    require_string(
                        device.get("PathInContainer"), f"{label} container device path"
                    ).encode("utf-8")
                ),
                "host_path_sha256": sha256_bytes(
                    require_string(
                        device.get("PathOnHost"), f"{label} host device path"
                    ).encode("utf-8")
                ),
            }
        )
    device_descriptors.sort(key=canonical_json_bytes)
    device_projection = {
        "device_count": len(devices),
        "device_descriptors": device_descriptors,
        "device_request_count": len(device_requests),
        "device_requests_sha256": sha256_bytes(canonical_json_bytes(device_requests)),
        "device_request_capabilities": sorted(
            {
                capability
                for request_value in device_requests
                for capability_group in (
                    require_object(request_value, f"{label} device request").get("Capabilities") or []
                )
                if isinstance(capability_group, list)
                for capability in capability_group
                if isinstance(capability, str) and capability
            }
        ),
    }
    resource_projection = {
        key: host.get(key)
        for key in (
            "BlkioDeviceReadBps",
            "BlkioDeviceReadIOps",
            "BlkioDeviceWriteBps",
            "BlkioDeviceWriteIOps",
            "BlkioWeight",
            "BlkioWeightDevice",
            "CpuPeriod",
            "CpuQuota",
            "CpuShares",
            "CpusetCpus",
            "CpusetMems",
            "Memory",
            "MemoryReservation",
            "MemorySwap",
            "NanoCpus",
            "OomKillDisable",
            "PidsLimit",
            "Runtime",
            "ShmSize",
            "Ulimits",
        )
    }
    host_access_projection = {
        "binds": host.get("Binds"),
        "device_cgroup_rules": host.get("DeviceCgroupRules"),
        "network_mode": host.get("NetworkMode"),
        "port_bindings": host.get("PortBindings"),
        "publish_all_ports": host.get("PublishAllPorts"),
        "tmpfs": host.get("Tmpfs"),
        "volumes_from": host.get("VolumesFrom"),
    }
    resource_projection["host_access_sha256"] = sha256_bytes(
        canonical_json_bytes(host_access_projection)
    )
    settings = require_object(
        inspection.get("NetworkSettings"), f"{label} network settings"
    )
    networks_value = require_object(settings.get("Networks"), f"{label} networks")
    networks = sorted(networks_value)
    if not networks:
        fail(f"{label} has no network")
    ports_value = require_object(settings.get("Ports") or {}, f"{label} ports")
    ports: list[str] = []
    for target, bindings in ports_value.items():
        require_string(target, f"{label} port target")
        if bindings in (None, []):
            ports.append(f"{target}=unpublished")
            continue
        if not isinstance(bindings, list):
            fail(f"{label} port bindings are invalid")
        for binding_value in bindings:
            binding = require_object(binding_value, f"{label} port binding")
            require_exact_keys(binding, {"HostIp", "HostPort"}, f"{label} port binding")
            host_ip = require_string(binding.get("HostIp"), f"{label} host IP")
            host_port = require_string(binding.get("HostPort"), f"{label} host port")
            if not host_port.isdigit() or not 1 <= int(host_port) <= 65535:
                fail(f"{label} host port is invalid")
            ports.append(f"{target}={host_ip}:{host_port}")
    ports = sorted(set(ports))
    network_projection = {
        "networks": networks_value,
        "ports": ports_value,
    }
    resource_projection["network_settings_sha256"] = sha256_bytes(
        canonical_json_bytes(network_projection)
    )
    security_projection = {
        "cap_add": cap_add,
        "cap_drop": cap_drop,
        "devices": device_projection,
        "mounts": mount_projection,
        "namespace_modes": namespace_projection,
        "no_new_privileges": no_new_privileges,
        "privileged": False,
        "read_only_rootfs": read_only,
        "resources": resource_projection,
        "security_options": security_options,
        "user_sha256": sha256_bytes(user.encode("utf-8")),
    }
    return {
        "cap_add": cap_add,
        "cap_drop": cap_drop,
        "container_id": container_id,
        "devices_sha256": sha256_bytes(canonical_json_bytes(device_projection)),
        "health": "healthy",
        "image_id": image_id,
        "mounts_sha256": sha256_bytes(canonical_json_bytes(mount_projection)),
        "networks": networks,
        "namespace_modes_sha256": sha256_bytes(canonical_json_bytes(namespace_projection)),
        "no_new_privileges": no_new_privileges,
        "ports": ports,
        "privileged": False,
        "read_only_rootfs": read_only,
        "resource_access_sha256": sha256_bytes(canonical_json_bytes(resource_projection)),
        "restart_count": restart_count,
        "running": True,
        "security_opts_sha256": sha256_bytes(canonical_json_bytes(security_options)),
        "security_sha256": sha256_bytes(canonical_json_bytes(security_projection)),
        "user_sha256": sha256_bytes(user.encode("utf-8")),
    }


def validate_acl_rows(value: Any, label: str, database: str) -> list[dict[str, Any]]:
    if not isinstance(value, list) or len(value) > 10_000:
        fail(f"{label} is not one bounded ACL row list")
    rows: list[dict[str, Any]] = []
    for row_value in value:
        row = require_object(row_value, f"{label} row")
        require_exact_keys(
            row,
            {"database", "grantee", "grantor", "is_grantable", "privilege", "relation", "schema"},
            f"{label} row",
        )
        if row.get("database") != database:
            fail(f"{label} row database is invalid")
        for principal in ("grantee", "grantor"):
            if row.get(principal) not in POSTGRES_ACL_GRANTEES:
                fail(f"{label} row {principal} is outside the fixed principal set")
        privilege = row.get("privilege")
        if not isinstance(privilege, str) or re.fullmatch(r"[A-Z][A-Z ]{0,63}", privilege) is None:
            fail(f"{label} row privilege is invalid")
        for key in ("schema", "relation"):
            nested = row.get(key)
            if nested is not None and (
                not isinstance(nested, str)
                or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_$]{0,62}", nested) is None
            ):
                fail(f"{label} row {key} is invalid")
        if not isinstance(row.get("is_grantable"), bool):
            fail(f"{label} row grantable flag is invalid")
        rows.append(row)
    ordered = sorted(rows, key=canonical_json_bytes)
    if rows != ordered or len({canonical_json_bytes(row) for row in rows}) != len(rows):
        fail(f"{label} rows must be canonical sorted and unique")
    return rows


def project_postgres_invariants(
    value: Any, public_connect_exception: bool
) -> dict[str, Any]:
    postgres = require_object(value, "PostgreSQL invariant result")
    require_exact_keys(
        postgres,
        {
            "control",
            "database",
            "database_owner",
            "role",
            "schema_version",
            "sub2api",
            "transactions",
        },
        "PostgreSQL invariant result",
    )
    if (
        postgres.get("schema_version") != 1
        or postgres.get("database") != "codex_control"
        or postgres.get("database_owner") != "codex_control"
    ):
        fail("PostgreSQL invariant probe was not one fixed read-only transaction")
    transactions = require_object(
        postgres.get("transactions"), "PostgreSQL read-only transactions"
    )
    require_exact_keys(
        transactions,
        {"control", "sub2api"},
        "PostgreSQL read-only transactions",
    )
    for key, database in (("control", "codex_control"), ("sub2api", "sub2api")):
        transaction = require_object(
            transactions.get(key), f"PostgreSQL {key} transaction"
        )
        require_exact_keys(
            transaction,
            {"database", "transaction_isolation", "transaction_read_only"},
            f"PostgreSQL {key} transaction",
        )
        if transaction != {
            "database": database,
            "transaction_isolation": "repeatable read",
            "transaction_read_only": True,
        }:
            fail(f"PostgreSQL {key} probe was not repeatable-read and read-only")
    role = require_object(postgres.get("role"), "PostgreSQL Control role")
    role_keys = {
        "bypass_rls",
        "create_db",
        "create_role",
        "inherit",
        "login",
        "membership_count",
        "name",
        "replication",
        "superuser",
    }
    require_exact_keys(role, role_keys, "PostgreSQL Control role")
    expected_role = {
        "bypass_rls": False,
        "create_db": False,
        "create_role": False,
        "inherit": False,
        "login": True,
        "membership_count": 0,
        "name": "codex_control",
        "replication": False,
        "superuser": False,
    }
    if role != expected_role:
        fail("PostgreSQL Control role differs from the fixed least-privilege role")
    control = require_object(postgres.get("control"), "PostgreSQL Control boundary")
    require_exact_keys(
        control,
        {
            "database_acl_rows",
            "owned_relation_count",
            "owned_schema_count",
            "relation_acl_rows",
            "schema_acl_rows",
        },
        "PostgreSQL Control boundary",
    )
    sub2api = require_object(postgres.get("sub2api"), "PostgreSQL Sub2API boundary")
    sub2api_count_keys = {
        "direct_database_acl_privilege_count",
        "direct_relation_acl_privilege_count",
        "direct_schema_acl_privilege_count",
        "effective_relation_privilege_count",
        "effective_schema_create_privilege_count",
        "effective_sequence_privilege_count",
        "owned_relation_count",
        "owned_schema_count",
    }
    require_exact_keys(
        sub2api,
        {
            "database",
            "database_acl_rows",
            "effective_connect",
            "effective_create",
            "effective_temporary",
        }
        | sub2api_count_keys,
        "PostgreSQL Sub2API boundary",
    )
    if sub2api.get("database") != "sub2api":
        fail("PostgreSQL Sub2API database name is invalid")
    if any(sub2api.get(key) != 0 for key in sub2api_count_keys):
        fail("PostgreSQL Control role crosses the Sub2API database boundary")
    if (
        sub2api.get("effective_connect") is not public_connect_exception
        or sub2api.get("effective_create") is not False
        or sub2api.get("effective_temporary") is not False
    ):
        fail("PostgreSQL effective database access differs from its bootstrap exception")
    control_database_acl = validate_acl_rows(
        control.get("database_acl_rows"), "Control database ACL", "codex_control"
    )
    control_schema_acl = validate_acl_rows(
        control.get("schema_acl_rows"), "Control schema ACL", "codex_control"
    )
    control_relation_acl = validate_acl_rows(
        control.get("relation_acl_rows"), "Control relation ACL", "codex_control"
    )
    sub2api_database_acl = validate_acl_rows(
        sub2api.get("database_acl_rows"), "Sub2API database ACL", "sub2api"
    )
    return {
        "control_database_acl_sha256": sha256_bytes(canonical_json_bytes(control_database_acl)),
        "control_owned_relation_count": require_nonnegative_integer(
            control.get("owned_relation_count"), "Control owned relation count"
        ),
        "control_owned_schema_count": require_nonnegative_integer(
            control.get("owned_schema_count"), "Control owned schema count"
        ),
        "control_relation_acl_sha256": sha256_bytes(canonical_json_bytes(control_relation_acl)),
        "control_schema_acl_sha256": sha256_bytes(canonical_json_bytes(control_schema_acl)),
        "database": "codex_control",
        "database_owner": "codex_control",
        "role": "codex_control",
        "role_bypass_rls": False,
        "role_create_db": False,
        "role_create_role": False,
        "role_inherit": False,
        "role_login": True,
        "role_membership_count": 0,
        "role_replication": False,
        "role_superuser": False,
        "sub2api_database": "sub2api",
        "sub2api_database_acl_sha256": sha256_bytes(canonical_json_bytes(sub2api_database_acl)),
        "sub2api_effective_connect": public_connect_exception,
        "sub2api_effective_create": False,
        "sub2api_effective_temporary": False,
        "sub2api_public_connect": public_connect_exception,
        "public_connect_exception_recorded": public_connect_exception,
        **{f"sub2api_{key}": 0 for key in sub2api_count_keys},
    }


def project_redis_acl(raw: bytes) -> str:
    try:
        lines = [line.strip() for line in raw.decode("utf-8").splitlines()]
    except UnicodeDecodeError:
        fail("Redis ACL result is not valid UTF-8")
    if not lines or any(not line for line in lines):
        fail("Redis ACL result is empty or malformed")
    fields: dict[str, list[str]] = {}
    index = 0
    field_names = {"channels", "commands", "flags", "keys", "passwords", "selectors"}
    while index < len(lines):
        field = lines[index]
        if field not in field_names or field in fields:
            fail("Redis ACL result has an unexpected or duplicate field")
        index += 1
        values: list[str] = []
        while index < len(lines) and lines[index] not in field_names:
            values.append(lines[index])
            index += 1
        fields[field] = values
    if set(fields) != field_names:
        fail("Redis ACL result lacks a fixed field")
    flags = sorted(token for value in fields["flags"] for token in value.split())
    keys = sorted(token for value in fields["keys"] for token in value.split())
    channels = sorted(token for value in fields["channels"] for token in value.split())
    commands = sorted(token for value in fields["commands"] for token in value.split())
    passwords = [token for value in fields["passwords"] for token in value.split()]
    selectors = [token for value in fields["selectors"] for token in value.split()]
    if flags != ["nopass", "on"] or keys != ["~*"] or channels != ["&*"]:
        fail("Redis default ACL differs from the fixed unauthenticated contract")
    if commands != ["+@all"] or passwords or selectors:
        fail("Redis default ACL contains an unexpected command, password, or selector")
    projection = {
        "channels": channels,
        "commands": commands,
        "flags": flags,
        "keys": keys,
        "password_count": 0,
        "selector_count": 0,
    }
    return sha256_bytes(canonical_json_bytes(projection))


def project_redis_config(value: Any) -> str:
    config = require_object(value, "Redis configuration projection")
    require_exact_keys(config, REDIS_CONFIG_KEYS, "Redis configuration projection")
    for key, nested in config.items():
        require_string(nested, f"Redis configuration {key}", maximum=4096)
    if config["appendonly"] not in {"yes", "no"}:
        fail("Redis appendonly configuration is invalid")
    if config["appendfsync"] not in {"always", "everysec", "no"}:
        fail("Redis appendfsync configuration is invalid")
    if config["maxmemory-policy"] not in {
        "allkeys-lfu",
        "allkeys-lru",
        "allkeys-random",
        "noeviction",
        "volatile-lfu",
        "volatile-lru",
        "volatile-random",
        "volatile-ttl",
    }:
        fail("Redis maxmemory policy is invalid")
    if not config["maxmemory"].isdigit() or int(config["maxmemory"]) < 0:
        fail("Redis maxmemory configuration is invalid")
    if not config["databases"].isdigit() or not 1 <= int(config["databases"]) <= 100_000:
        fail("Redis databases configuration is invalid")
    if re.fullmatch(r"[A-Za-z0-9 _-]{0,4096}", config["save"]) is None:
        fail("Redis save configuration is invalid")
    if re.fullmatch(r"[A-Za-z0-9$glKEtmdnxe]{0,256}", config["notify-keyspace-events"]) is None:
        fail("Redis keyspace notification configuration is invalid")
    return sha256_bytes(canonical_json_bytes(config))


def project_invariants(args: argparse.Namespace) -> dict[str, Any]:
    plan_value, plan_raw = load_json(args.plan, "invariant rollout plan")
    plan_value = validate_rollout_plan(plan_value)
    baseline_value, baseline_raw = load_json(args.baseline, "invariant rollout baseline")
    baseline_value = validate_baseline_value(baseline_value, plan_raw)
    bootstrap_value, bootstrap_raw = load_json(
        args.bootstrap_record, "invariant bootstrap record"
    )
    bootstrap_value = require_object(bootstrap_value, "invariant bootstrap record")
    if sha256_bytes(bootstrap_raw) != baseline_value["bootstrap_record_sha256"]:
        fail("invariant bootstrap record changed after baseline admission")
    bootstrap_exceptions = require_object(
        bootstrap_value.get("bootstrap_exceptions"), "bootstrap exceptions"
    )
    require_exact_keys(
        bootstrap_exceptions,
        {"stale_production_backup", "sub2api_public_connect", "unauthenticated_smoke"},
        "bootstrap exceptions",
    )
    if any(not isinstance(item, bool) for item in bootstrap_exceptions.values()):
        fail("bootstrap exception flags are invalid")
    public_connect_exception = bootstrap_exceptions["sub2api_public_connect"]
    old_compose, old_compose_raw = load_json(args.old_compose, "invariant old Compose")
    old_compose = require_object(old_compose, "invariant old Compose")
    if sha256_bytes(old_compose_raw) != plan_value["old_compose_sha256"]:
        fail("invariant old Compose differs from the rollout plan")
    api_environment = service_environment(
        compose_services(old_compose, "invariant old Compose")["control-api"],
        "invariant old Compose control-api",
    )
    if {
        key: api_environment.get(key)
        for key in ("CONTROL_REDIS_AUTH_MODE", "CONTROL_REDIS_PREFIX", "CONTROL_REDIS_USER")
    } != {
        "CONTROL_REDIS_AUTH_MODE": "none",
        "CONTROL_REDIS_PREFIX": "codex-control:",
        "CONTROL_REDIS_USER": "default",
    }:
        fail("old Compose Redis identity differs from the fixed production contract")
    migration_state, migration_state_raw = load_json(
        args.migration_state, "invariant baseline migration state"
    )
    migration_state = require_object(migration_state, "invariant baseline migration state")
    require_exact_keys(
        migration_state,
        {"current_revision", "head_revision"},
        "invariant baseline migration state",
    )
    if sha256_bytes(migration_state_raw) != baseline_value["migration_state_sha256"]:
        fail("baseline migration state changed before invariant projection")
    expected_revision = baseline_value["migrations"]["head"]
    current_raw = read_regular(
        args.migration_current, "fresh Alembic current", maximum=MAX_INVARIANT_TEXT_BYTES
    )
    head_raw = read_regular(
        args.migration_head, "fresh Alembic head", maximum=MAX_INVARIANT_TEXT_BYTES
    )
    current_revision = normalize_alembic_revision(current_raw, "fresh Alembic current")
    head_revision = normalize_alembic_revision(head_raw, "fresh Alembic head")
    if (
        current_revision != expected_revision
        or head_revision != expected_revision
        or migration_state != {
            "current_revision": expected_revision,
            "head_revision": expected_revision,
        }
    ):
        fail("fresh migration state differs from the unchanged baseline head")
    inspections, _ = load_json(args.containers, "protected container inspections")
    if not isinstance(inspections, list) or len(inspections) != 3:
        fail("protected container inspections must contain exactly three containers")
    by_name: dict[str, Any] = {}
    for inspection_value in inspections:
        inspection = require_object(inspection_value, "protected container inspection")
        name = inspection.get("Name")
        if name not in set(PROTECTED_CONTAINER_NAMES.values()) or name in by_name:
            fail("protected container inspection has an unexpected or duplicate name")
        by_name[name] = inspection
    containers = {
        label: project_invariant_container(by_name[name], f"protected {label} container")
        for label, name in PROTECTED_CONTAINER_NAMES.items()
    }
    if len({item["container_id"] for item in containers.values()}) != 3:
        fail("protected container IDs are not distinct")
    listeners_raw = read_regular(
        args.listeners, "socket listener snapshot", maximum=MAX_INVARIANT_TEXT_BYTES
    )
    listeners = project_listeners(listeners_raw)
    nginx_effective_raw = read_regular(
        args.nginx_effective, "effective Nginx configuration", maximum=MAX_INVARIANT_TEXT_BYTES
    )
    nginx_canonical = normalize_ordered_text_bytes(
        nginx_effective_raw, "effective Nginx configuration"
    )
    nginx_state, _ = load_json(args.nginx_state, "Nginx runtime state")
    nginx_state = require_object(nginx_state, "Nginx runtime state")
    require_exact_keys(nginx_state, {"master_pid", "restart_count"}, "Nginx runtime state")
    nginx = {
        "effective_config_sha256": sha256_bytes(nginx_canonical),
        "managed_tree_sha256": digest_tree(args.nginx_managed_root, "managed Nginx tree"),
        "master_pid": require_nonnegative_integer(nginx_state.get("master_pid"), "Nginx master PID"),
        "restart_count": require_nonnegative_integer(nginx_state.get("restart_count"), "Nginx restart count"),
    }
    if nginx["master_pid"] < 1:
        fail("Nginx master PID is invalid")
    ufw_raw = read_regular(args.ufw, "UFW rule snapshot", maximum=MAX_INVARIANT_TEXT_BYTES)
    ufw_lines = normalize_text_lines(ufw_raw, "UFW rule snapshot")
    if not any(line == "Status: active" for line in ufw_lines):
        fail("UFW is not active")
    postgres_value, _ = load_json(args.postgres, "PostgreSQL invariant result")
    postgres = project_postgres_invariants(postgres_value, public_connect_exception)
    redis_acl_raw = read_regular(
        args.redis_acl, "Redis default ACL", maximum=MAX_INVARIANT_TEXT_BYTES
    )
    redis_acl_sha256 = project_redis_acl(redis_acl_raw)
    redis_config_value, _ = load_json(args.redis_config, "Redis configuration projection")
    redis_configuration_sha256 = project_redis_config(redis_config_value)
    redis_namespace, _ = load_json(args.redis_namespace, "Redis namespace observation")
    redis_namespace = require_object(redis_namespace, "Redis namespace observation")
    require_exact_keys(
        redis_namespace,
        {"channel_count", "key_count", "prefix", "scan_complete"},
        "Redis namespace observation",
    )
    if redis_namespace.get("prefix") != "codex-control:" or redis_namespace.get("scan_complete") is not True:
        fail("Redis namespace observation is not one complete fixed-prefix scan")
    namespace = {
        "channel_count": require_nonnegative_integer(
            redis_namespace.get("channel_count"), "Redis channel count", maximum=10_000
        ),
        "key_count": require_nonnegative_integer(
            redis_namespace.get("key_count"), "Redis key count", maximum=10_000
        ),
        "within_bounds": True,
    }
    return {
        "baseline_sha256": sha256_bytes(baseline_raw),
        "containers": containers,
        "format_version": 2,
        "listeners": listeners,
        "migration": {
            "at_expected_head": True,
            "current_revision": current_revision,
            "expected_revision": expected_revision,
            "head_revision": head_revision,
            "state_sha256": sha256_bytes(migration_state_raw),
        },
        "nginx": nginx,
        "postgres": postgres,
        "redis": {
            "auth_mode": "none",
            "configuration_projection_sha256": redis_configuration_sha256,
            "default_acl_sha256": redis_acl_sha256,
            "namespace": namespace,
            "prefix": "codex-control:",
            "runtime_acl_sha256": redis_acl_sha256,
            "runtime_user": "default",
        },
        "schema_version": 1,
        "ufw": {
            "normalized_rules_sha256": sha256_bytes(canonical_json_bytes(ufw_lines)),
            "status": "active",
        },
    }


def validate_invariant_snapshot(value: Any, label: str) -> dict[str, Any]:
    snapshot = require_object(value, label)
    require_exact_keys(
        snapshot,
        {
            "baseline_sha256",
            "containers",
            "format_version",
            "listeners",
            "migration",
            "nginx",
            "postgres",
            "redis",
            "schema_version",
            "ufw",
        },
        label,
    )
    if snapshot.get("format_version") != 2 or snapshot.get("schema_version") != 1:
        fail(f"{label} has an unsupported format version")
    require_sha256(snapshot.get("baseline_sha256"), f"{label} baseline hash")
    validate_string_set(snapshot.get("listeners"), f"{label} listeners")
    containers = require_object(snapshot.get("containers"), f"{label} containers")
    if set(containers) != {"sub2api", "postgres", "redis"}:
        fail(f"{label} must contain exactly the protected dependency containers")
    ids: set[str] = set()
    for name in ("sub2api", "postgres", "redis"):
        item = require_object(containers[name], f"{label} {name}")
        require_exact_keys(
            item,
            {
                "cap_add",
                "cap_drop",
                "container_id",
                "devices_sha256",
                "health",
                "image_id",
                "mounts_sha256",
                "networks",
                "namespace_modes_sha256",
                "no_new_privileges",
                "ports",
                "privileged",
                "read_only_rootfs",
                "resource_access_sha256",
                "restart_count",
                "running",
                "security_opts_sha256",
                "security_sha256",
                "user_sha256",
            },
            f"{label} {name}",
        )
        container_id = item.get("container_id")
        if (
            not isinstance(container_id, str)
            or CONTAINER_ID_RE.fullmatch(container_id) is None
            or container_id in ids
        ):
            fail(f"{label} {name} has an invalid or duplicate container ID")
        ids.add(container_id)
        require_sha256(item.get("image_id"), f"{label} {name} image ID", image=True)
        if item.get("running") is not True or item.get("health") != "healthy":
            fail(f"{label} {name} is not running and healthy")
        if item.get("privileged") is not False:
            fail(f"{label} {name} is privileged")
        if not isinstance(item.get("read_only_rootfs"), bool) or not isinstance(
            item.get("no_new_privileges"), bool
        ):
            fail(f"{label} {name} security flags are invalid")
        require_nonnegative_integer(
            item.get("restart_count"), f"{label} {name} restart count"
        )
        for key in (
            "devices_sha256",
            "mounts_sha256",
            "namespace_modes_sha256",
            "resource_access_sha256",
            "security_opts_sha256",
            "security_sha256",
            "user_sha256",
        ):
            require_sha256(item.get(key), f"{label} {name} {key}")
        validate_string_set(
            item.get("cap_add"), f"{label} {name} added capabilities", allow_empty=True
        )
        validate_string_set(
            item.get("cap_drop"), f"{label} {name} dropped capabilities", allow_empty=True
        )
        validate_string_set(item.get("networks"), f"{label} {name} networks")
        validate_string_set(
            item.get("ports"), f"{label} {name} ports", allow_empty=True
        )
    migration = require_object(snapshot.get("migration"), f"{label} migration")
    require_exact_keys(
        migration,
        {
            "at_expected_head",
            "current_revision",
            "expected_revision",
            "head_revision",
            "state_sha256",
        },
        f"{label} migration",
    )
    revisions = [
        migration.get(key)
        for key in ("current_revision", "expected_revision", "head_revision")
    ]
    if (
        migration.get("at_expected_head") is not True
        or len(set(revisions)) != 1
        or not isinstance(revisions[0], str)
        or REVISION_RE.fullmatch(revisions[0]) is None
    ):
        fail(f"{label} migration is not at the expected head")
    require_sha256(migration.get("state_sha256"), f"{label} migration state hash")
    nginx = require_object(snapshot.get("nginx"), f"{label} Nginx")
    require_exact_keys(
        nginx,
        {"effective_config_sha256", "managed_tree_sha256", "master_pid", "restart_count"},
        f"{label} Nginx",
    )
    for key in ("effective_config_sha256", "managed_tree_sha256"):
        require_sha256(nginx.get(key), f"{label} Nginx {key}")
    if require_nonnegative_integer(nginx.get("master_pid"), f"{label} Nginx PID") < 1:
        fail(f"{label} Nginx PID is invalid")
    require_nonnegative_integer(nginx.get("restart_count"), f"{label} Nginx restarts")
    ufw = require_object(snapshot.get("ufw"), f"{label} UFW")
    require_exact_keys(ufw, {"normalized_rules_sha256", "status"}, f"{label} UFW")
    if ufw.get("status") != "active":
        fail(f"{label} UFW is not active")
    require_sha256(ufw.get("normalized_rules_sha256"), f"{label} UFW rules")
    postgres = require_object(snapshot.get("postgres"), f"{label} PostgreSQL")
    expected_postgres_keys = {
        "control_database_acl_sha256",
        "control_owned_relation_count",
        "control_owned_schema_count",
        "control_relation_acl_sha256",
        "control_schema_acl_sha256",
        "database",
        "database_owner",
        "public_connect_exception_recorded",
        "role",
        "role_bypass_rls",
        "role_create_db",
        "role_create_role",
        "role_inherit",
        "role_login",
        "role_membership_count",
        "role_replication",
        "role_superuser",
        "sub2api_database",
        "sub2api_database_acl_sha256",
        "sub2api_direct_database_acl_privilege_count",
        "sub2api_direct_relation_acl_privilege_count",
        "sub2api_direct_schema_acl_privilege_count",
        "sub2api_effective_connect",
        "sub2api_effective_create",
        "sub2api_effective_relation_privilege_count",
        "sub2api_effective_schema_create_privilege_count",
        "sub2api_effective_sequence_privilege_count",
        "sub2api_effective_temporary",
        "sub2api_owned_relation_count",
        "sub2api_owned_schema_count",
        "sub2api_public_connect",
    }
    require_exact_keys(postgres, expected_postgres_keys, f"{label} PostgreSQL")
    if (
        postgres.get("database") != "codex_control"
        or postgres.get("database_owner") != "codex_control"
        or postgres.get("role") != "codex_control"
        or postgres.get("sub2api_database") != "sub2api"
        or postgres.get("role_login") is not True
        or any(
            postgres.get(key) is not False
            for key in (
                "role_bypass_rls",
                "role_create_db",
                "role_create_role",
                "role_inherit",
                "role_replication",
                "role_superuser",
            )
        )
        or postgres.get("role_membership_count") != 0
    ):
        fail(f"{label} PostgreSQL role contract is invalid")
    zero_postgres = {
        "sub2api_direct_database_acl_privilege_count",
        "sub2api_direct_relation_acl_privilege_count",
        "sub2api_direct_schema_acl_privilege_count",
        "sub2api_effective_relation_privilege_count",
        "sub2api_effective_schema_create_privilege_count",
        "sub2api_effective_sequence_privilege_count",
        "sub2api_owned_relation_count",
        "sub2api_owned_schema_count",
    }
    if any(postgres.get(key) != 0 for key in zero_postgres):
        fail(f"{label} PostgreSQL Sub2API boundary is not isolated")
    public_connect = postgres.get("public_connect_exception_recorded")
    if (
        not isinstance(public_connect, bool)
        or postgres.get("sub2api_public_connect") is not public_connect
        or postgres.get("sub2api_effective_connect") is not public_connect
        or postgres.get("sub2api_effective_create") is not False
        or postgres.get("sub2api_effective_temporary") is not False
    ):
        fail(f"{label} PostgreSQL PUBLIC CONNECT exception binding is invalid")
    for key in (
        "control_database_acl_sha256",
        "control_relation_acl_sha256",
        "control_schema_acl_sha256",
        "sub2api_database_acl_sha256",
    ):
        require_sha256(postgres.get(key), f"{label} PostgreSQL {key}")
    for key in ("control_owned_relation_count", "control_owned_schema_count"):
        require_nonnegative_integer(postgres.get(key), f"{label} PostgreSQL {key}")
    redis = require_object(snapshot.get("redis"), f"{label} Redis")
    require_exact_keys(
        redis,
        {
            "auth_mode",
            "configuration_projection_sha256",
            "default_acl_sha256",
            "namespace",
            "prefix",
            "runtime_acl_sha256",
            "runtime_user",
        },
        f"{label} Redis",
    )
    if (
        redis.get("auth_mode") != "none"
        or redis.get("runtime_user") != "default"
        or redis.get("prefix") != "codex-control:"
        or redis.get("runtime_acl_sha256") != redis.get("default_acl_sha256")
    ):
        fail(f"{label} Redis identity or default ACL binding is invalid")
    for key in (
        "configuration_projection_sha256",
        "default_acl_sha256",
        "runtime_acl_sha256",
    ):
        require_sha256(redis.get(key), f"{label} Redis {key}")
    namespace = require_object(redis.get("namespace"), f"{label} Redis namespace")
    require_exact_keys(
        namespace, {"channel_count", "key_count", "within_bounds"}, f"{label} Redis namespace"
    )
    if namespace.get("within_bounds") is not True:
        fail(f"{label} Redis namespace is not within bounds")
    require_nonnegative_integer(
        namespace.get("channel_count"), f"{label} Redis channels", maximum=10_000
    )
    require_nonnegative_integer(
        namespace.get("key_count"), f"{label} Redis keys", maximum=10_000
    )
    return snapshot


def stable_invariant_projection(snapshot: dict[str, Any]) -> dict[str, Any]:
    projection = copy.deepcopy(snapshot)
    del projection["schema_version"]
    del projection["redis"]["namespace"]
    return projection


def invariants(args: argparse.Namespace) -> dict[str, Any]:
    plan_value, plan_raw = load_json(args.plan, "invariants rollout plan")
    validate_rollout_plan(plan_value)
    baseline_value, baseline_raw = load_json(args.baseline, "invariants rollout baseline")
    validate_baseline_value(baseline_value, plan_raw)
    before, before_raw = load_json(args.before, "before invariant snapshot")
    after, after_raw = load_json(args.after, "after invariant snapshot")
    before = validate_invariant_snapshot(before, "before invariant snapshot")
    after = validate_invariant_snapshot(after, "after invariant snapshot")
    expected_baseline_sha = sha256_bytes(baseline_raw)
    if before["baseline_sha256"] != expected_baseline_sha or after["baseline_sha256"] != expected_baseline_sha:
        fail("invariant snapshots do not bind the admitted baseline")
    before_stable = stable_invariant_projection(before)
    after_stable = stable_invariant_projection(after)
    if after_stable != before_stable:
        fail("the protected production invariant core changed during rollout")
    redis = copy.deepcopy(before["redis"])
    redis["configuration_projection_unchanged"] = True
    redis["default_acl_unchanged"] = True
    redis["max_channel_count"] = 10_000
    redis["max_key_count"] = 10_000
    redis["namespace_before"] = before["redis"]["namespace"]
    redis["namespace_after"] = after["redis"]["namespace"]
    redis["namespace_mutation_attributed_to_rollout"] = False
    redis["runtime_acl_unchanged"] = True
    return {
        "after_sha256": sha256_bytes(after_raw),
        "baseline_sha256": expected_baseline_sha,
        "before_sha256": sha256_bytes(before_raw),
        "command": "invariants",
        "containers": before["containers"],
        "format_version": 2,
        "listeners": before["listeners"],
        "migration": before["migration"],
        "nginx": before["nginx"],
        "postgres": before["postgres"],
        "projection_sha256": sha256_bytes(canonical_json_bytes(before_stable)),
        "redis": redis,
        "status": "admitted",
        "ufw": before["ufw"],
        "unchanged": True,
    }


def validate_timestamp(value: Any, label: str) -> str:
    result = require_string(value, label, maximum=64)
    if re.fullmatch(
        r"[0-9]{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12][0-9]|3[01])T"
        r"(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]"
        r"(?:\.[0-9]{1,6})?Z",
        result,
    ) is None:
        fail(f"{label} must be one UTC RFC3339 timestamp")
    try:
        datetime.fromisoformat(result[:-1] + "+00:00")
    except ValueError:
        fail(f"{label} is not a real UTC timestamp")
    return result


def validate_stage_token(value: Any, label: str) -> str:
    result = require_string(value, label, maximum=64)
    if re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", result) is None:
        fail(f"{label} is not one privacy-safe stage token")
    return result


def timestamp_value(value: str) -> datetime:
    return datetime.fromisoformat(value[:-1] + "+00:00")


def path_from_context(value: Any, label: str, *, nullable: bool = False) -> Path | None:
    if value is None and nullable:
        return None
    return canonical_path(Path(require_string(value, label, maximum=4096)), label)


def file_evidence(path: Path, label: str) -> dict[str, Any]:
    raw = read_regular(path, label)
    if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,191}", path.name) is None:
        fail(f"{label} basename is not record-safe")
    return {"basename": path.name, "sha256": sha256_bytes(raw), "size": len(raw)}


def validate_file_evidence(value: Any, label: str) -> dict[str, Any]:
    evidence = require_object(value, label)
    require_exact_keys(evidence, {"basename", "sha256", "size"}, label)
    basename = require_string(evidence.get("basename"), f"{label} basename", maximum=192)
    if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,191}", basename) is None:
        fail(f"{label} basename is not record-safe")
    require_sha256(evidence.get("sha256"), f"{label} hash")
    size = evidence.get("size")
    if not isinstance(size, int) or isinstance(size, bool) or size <= 0:
        fail(f"{label} size is invalid")
    return evidence


def optional_admission_file(
    path: Path | None, label: str, command: str
) -> tuple[dict[str, Any] | None, bytes | None, dict[str, Any] | None]:
    if path is None:
        return None, None, None
    value, raw = load_json(path, label)
    result = require_object(value, label)
    if (
        result.get("command") != command
        or result.get("format_version") != FORMAT_VERSION
        or result.get("status") != "admitted"
    ):
        fail(f"{label} is not an admitted {command} output")
    return result, raw, file_evidence(path, label)


def validate_baseline_value(value: Any, plan_raw: bytes) -> dict[str, Any]:
    baseline_value = require_object(value, "rollout baseline")
    require_exact_keys(
        baseline_value,
        {
            "archive_evidence_sha256",
            "archives",
            "artifact_manifest_sha256",
            "bootstrap_deployment",
            "bootstrap_record_sha256",
            "bundle_evidence_sha256",
            "closure_record_sha256",
            "closure_target",
            "command",
            "format_version",
            "migration_state_sha256",
            "migrations",
            "no_backup",
            "no_migration",
            "old_admission",
            "operator_exception_sha256",
            "ready_record",
            "rollout_plan_sha256",
            "source_evidence",
            "status",
            "tooling",
        },
        "rollout baseline",
    )
    if (
        baseline_value.get("command") != "baseline"
        or baseline_value.get("format_version") != FORMAT_VERSION
        or baseline_value.get("status") != "admitted"
        or baseline_value.get("no_backup") is not True
        or baseline_value.get("no_migration") is not True
        or baseline_value.get("rollout_plan_sha256") != sha256_bytes(plan_raw)
        or baseline_value.get("artifact_manifest_sha256") != TARGET_MANIFEST_SHA256
    ):
        fail("rollout baseline header or frozen plan binding is invalid")
    for key in (
        "archive_evidence_sha256",
        "bootstrap_record_sha256",
        "bundle_evidence_sha256",
        "closure_record_sha256",
        "migration_state_sha256",
        "operator_exception_sha256",
    ):
        require_sha256(baseline_value.get(key), f"rollout baseline {key}")
    deployment = require_object(
        baseline_value.get("bootstrap_deployment"), "baseline bootstrap deployment"
    )
    require_exact_keys(
        deployment,
        {"deployment_basename", "deployment_id"},
        "baseline bootstrap deployment",
    )
    if DEPLOYMENT_DIRECTORY_RE.fullmatch(
        require_string(deployment.get("deployment_basename"), "deployment basename")
    ) is None:
        fail("baseline bootstrap deployment basename is invalid")
    try:
        parsed_id = str(uuid.UUID(deployment.get("deployment_id"), version=4))
    except (ValueError, TypeError, AttributeError):
        fail("baseline bootstrap deployment ID is invalid")
    if parsed_id != deployment.get("deployment_id"):
        fail("baseline bootstrap deployment ID is non-canonical")
    ready = require_object(baseline_value.get("ready_record"), "baseline READY record")
    require_exact_keys(ready, {"bundle_id", "sha256", "transport_sha256"}, "baseline READY record")
    if (
        ready.get("bundle_id") != TARGET_BUNDLE_ID
        or ready.get("sha256") != TARGET_READY_RECORD_SHA256
        or ready.get("transport_sha256") != TARGET_TRANSPORT_SHA256
    ):
        fail("baseline READY record differs from the frozen target")
    archives = require_object(baseline_value.get("archives"), "baseline archives")
    require_exact_keys(archives, set(COMPONENT_SERVICES), "baseline archives")
    for component in COMPONENT_SERVICES:
        descriptor = validate_file_evidence(
            archives.get(component), f"baseline archive {component}"
        )
        if (
            descriptor["basename"] != ARCHIVE_NAMES[component]
            or descriptor["sha256"] != TARGET_ARCHIVE_SHA256[component]
        ):
            fail(f"baseline archive {component} differs from the frozen target")
    target = require_object(baseline_value.get("closure_target"), "baseline closure target")
    require_exact_keys(
        target,
        {
            "artifact_identity_sha256",
            "binding_sha256",
            "compose_plan_sha256",
            "local_images_sha256",
            "public_origin",
            "running_containers_sha256",
            "runtime_identity_sha256",
            "source_identity_sha256",
        },
        "baseline closure target",
    )
    for key, nested in target.items():
        if key != "public_origin":
            require_sha256(nested, f"baseline closure target {key}")
    tooling = require_object(baseline_value.get("tooling"), "baseline tooling")
    require_exact_keys(
        tooling,
        {
            "admission",
            "admission_helper",
            "archive",
            "external_verifier",
            "manifest",
            "record_schema",
            "root_owned_read_only",
            "smoke_helper",
            "tooling_identity",
            "wrapper",
        },
        "baseline tooling",
    )
    require_sha256(tooling.get("tooling_identity"), "baseline tooling identity")
    if tooling.get("root_owned_read_only") is not True:
        fail("baseline tooling is not root-owned read-only evidence")
    for key in (
        "admission",
        "admission_helper",
        "archive",
        "external_verifier",
        "manifest",
        "record_schema",
        "smoke_helper",
        "wrapper",
    ):
        validate_file_evidence(tooling.get(key), f"baseline tooling {key}")
    return baseline_value


def validate_running_value(
    value: Any, plan_value: dict[str, Any], plan_raw: bytes
) -> dict[str, Any]:
    running_value = require_object(value, "running admission")
    require_exact_keys(
        running_value,
        {
            "command",
            "containers",
            "format_version",
            "inspect_sha256",
            "plan_sha256",
            "status",
        },
        "running admission",
    )
    if (
        running_value.get("command") != "running"
        or running_value.get("format_version") != FORMAT_VERSION
        or running_value.get("status") != "admitted"
        or running_value.get("plan_sha256") != sha256_bytes(plan_raw)
    ):
        fail("running admission header or plan binding is invalid")
    require_sha256(running_value.get("inspect_sha256"), "running inspection hash")
    containers = require_object(running_value.get("containers"), "running containers")
    require_exact_keys(containers, set(RUNNING_SERVICE_NAMES), "running containers")
    identity = require_object(plan_value.get("new"), "running plan identity")
    images = require_object(identity.get("images"), "running plan images")
    ids: set[str] = set()
    for service in RUNNING_SERVICE_NAMES:
        item = require_object(containers.get(service), f"running {service}")
        require_exact_keys(
            item,
            {
                "container_id",
                "health",
                "image_id",
                "network",
                "published_port",
                "target_port",
            },
            f"running {service}",
        )
        container_id = item.get("container_id")
        if (
            not isinstance(container_id, str)
            or CONTAINER_ID_RE.fullmatch(container_id) is None
            or container_id in ids
            or item.get("health") != "healthy"
            or item.get("image_id") != images[SERVICE_COMPONENT[service]]
        ):
            fail(f"running {service} differs from the admitted new runtime")
        ids.add(container_id)
    return running_value


def validate_invariants_value(value: Any) -> dict[str, Any]:
    invariants_value = require_object(value, "invariants admission")
    require_exact_keys(
        invariants_value,
        {
            "after_sha256",
            "baseline_sha256",
            "before_sha256",
            "command",
            "containers",
            "format_version",
            "listeners",
            "migration",
            "nginx",
            "postgres",
            "projection_sha256",
            "redis",
            "status",
            "ufw",
            "unchanged",
        },
        "invariants admission",
    )
    if (
        invariants_value.get("command") != "invariants"
        or invariants_value.get("format_version") != 2
        or invariants_value.get("status") != "admitted"
        or invariants_value.get("unchanged") is not True
    ):
        fail("invariants admission header is invalid")
    for key in ("after_sha256", "baseline_sha256", "before_sha256", "projection_sha256"):
        require_sha256(invariants_value.get(key), f"invariants {key}")
    redis = require_object(invariants_value.get("redis"), "invariants Redis")
    require_exact_keys(
        redis,
        {
            "auth_mode",
            "configuration_projection_sha256",
            "configuration_projection_unchanged",
            "default_acl_sha256",
            "default_acl_unchanged",
            "max_channel_count",
            "max_key_count",
            "namespace_after",
            "namespace_before",
            "namespace_mutation_attributed_to_rollout",
            "prefix",
            "runtime_acl_sha256",
            "runtime_acl_unchanged",
            "runtime_user",
        },
        "invariants Redis",
    )
    for flag in (
        "configuration_projection_unchanged",
        "default_acl_unchanged",
        "runtime_acl_unchanged",
    ):
        if redis.get(flag) is not True:
            fail("invariants Redis stable projection is not unchanged")
    if (
        redis.get("max_channel_count") != 10_000
        or redis.get("max_key_count") != 10_000
        or redis.get("namespace_mutation_attributed_to_rollout") is not False
    ):
        fail("invariants Redis namespace policy is invalid")
    before_namespace = redis.get("namespace_before")
    after_namespace = redis.get("namespace_after")
    snapshot = {
        "baseline_sha256": invariants_value["baseline_sha256"],
        "containers": invariants_value["containers"],
        "format_version": 2,
        "listeners": invariants_value["listeners"],
        "migration": invariants_value["migration"],
        "nginx": invariants_value["nginx"],
        "postgres": invariants_value["postgres"],
        "redis": {
            "auth_mode": redis["auth_mode"],
            "configuration_projection_sha256": redis[
                "configuration_projection_sha256"
            ],
            "default_acl_sha256": redis["default_acl_sha256"],
            "namespace": before_namespace,
            "prefix": redis["prefix"],
            "runtime_acl_sha256": redis["runtime_acl_sha256"],
            "runtime_user": redis["runtime_user"],
        },
        "schema_version": 1,
        "ufw": invariants_value["ufw"],
    }
    validate_invariant_snapshot(snapshot, "invariants admitted projection")
    after_snapshot = copy.deepcopy(snapshot)
    after_snapshot["redis"]["namespace"] = after_namespace
    validate_invariant_snapshot(after_snapshot, "invariants admitted after projection")
    if invariants_value["projection_sha256"] != sha256_bytes(
        canonical_json_bytes(stable_invariant_projection(snapshot))
    ):
        fail("invariants projection hash differs from its canonical snapshot")
    return invariants_value


def validate_context_step(value: Any, order: int, service: str) -> dict[str, Any]:
    step = require_object(value, f"context step {service}")
    require_exact_keys(
        step,
        {
            "after_inspect",
            "completed_at",
            "order",
            "readiness_evidence",
            "recreated",
            "service",
            "started_at",
            "status",
        },
        f"context step {service}",
    )
    if step.get("order") != order or step.get("service") != service:
        fail("context rollout step order or service differs from the contract")
    status_value = step.get("status")
    if status_value not in {"succeeded", "failed", "not-run"}:
        fail(f"context step {service} status is invalid")
    if status_value == "not-run":
        if any(
            step.get(key) is not None
            for key in (
                "started_at",
                "completed_at",
                "after_inspect",
                "readiness_evidence",
            )
        ) or step.get("recreated") is not False:
            fail(f"not-run context step {service} contains execution evidence")
    else:
        validate_timestamp(step.get("started_at"), f"context step {service} start")
        validate_timestamp(step.get("completed_at"), f"context step {service} end")
        if timestamp_value(step["started_at"]) > timestamp_value(step["completed_at"]):
            fail(f"context step {service} completion precedes its start")
        if not isinstance(step.get("recreated"), bool):
            fail(f"context step {service} recreated flag is invalid")
        if status_value == "succeeded" and step.get("recreated") is not True:
            fail(f"successful context step {service} was not recreated")
        if status_value == "succeeded":
            path_from_context(step.get("after_inspect"), f"context step {service} inspect")
            path_from_context(
                step.get("readiness_evidence"), f"context step {service} readiness"
            )
    if step.get("readiness_evidence") is not None:
        path_from_context(
            step.get("readiness_evidence"), f"context step {service} readiness"
        )
    return step


def validate_record_context(value: Any) -> dict[str, Any]:
    context = require_object(value, "rollout record context")
    require_exact_keys(
        context,
        {
            "completed_at",
            "created_at",
            "failure_stage",
            "operations",
            "paths",
            "rollback",
            "rollout_id",
            "schema_version",
            "status",
            "steps",
            "type",
        },
        "rollout record context",
    )
    if (
        context.get("schema_version") != 1
        or context.get("type") != "bootstrap-image-rollout-context-v1"
        or context.get("status") not in {"succeeded", "failed"}
    ):
        fail("rollout record context header is invalid")
    try:
        rollout_id = str(uuid.UUID(require_string(context.get("rollout_id"), "rollout ID"), version=4))
    except ValueError:
        fail("rollout ID is not UUIDv4")
    if rollout_id != context.get("rollout_id"):
        fail("rollout ID is not canonical UUIDv4")
    validate_timestamp(context.get("created_at"), "rollout creation timestamp")
    validate_timestamp(context.get("completed_at"), "rollout completion timestamp")
    if timestamp_value(context["created_at"]) > timestamp_value(context["completed_at"]):
        fail("rollout completion precedes creation")
    if context["status"] == "succeeded":
        if context.get("failure_stage") is not None or context.get("rollback") is not None:
            fail("successful context contains failure or rollback state")
    else:
        validate_stage_token(context.get("failure_stage"), "failure stage")
        if context.get("rollback") is None:
            fail("failed context must contain a rollback result")
    operations = require_object(context.get("operations"), "context operations")
    operation_keys = {
        "archives_loaded",
        "backup_invoked",
        "build_invoked",
        "down_invoked",
        "load_invoked",
        "migrate_invoked",
        "postgres_tools_executed",
        "pull_invoked",
        "python_dont_write_bytecode",
    }
    require_exact_keys(operations, operation_keys, "context operations")
    if any(not isinstance(operations[key], bool) for key in operation_keys):
        fail("context operation flags must be Boolean")
    if any(
        operations[key]
        for key in (
            "backup_invoked",
            "build_invoked",
            "down_invoked",
            "migrate_invoked",
            "postgres_tools_executed",
            "pull_invoked",
        )
    ) or operations["python_dont_write_bytecode"] is not True:
        fail("context records a forbidden rollout operation")
    paths = require_object(context.get("paths"), "context paths")
    path_keys = {
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
        "source_evidence",
        "source_root",
        "ready_record",
        "smoke_challenge",
        "tools_manifest",
        "tools_admission",
    }
    require_exact_keys(paths, path_keys, "context paths")
    for key in path_keys:
        path_from_context(paths[key], f"context {key}", nullable=True)
    steps = context.get("steps")
    services = ("control-api-replica", "control-api", "codex-pwa")
    if not isinstance(steps, list) or len(steps) != 3:
        fail("context must contain exactly three rollout steps")
    validated_steps = [
        validate_context_step(step, index, service)
        for index, (step, service) in enumerate(zip(steps, services), 1)
    ]
    previous_end = timestamp_value(context["created_at"])
    for step in validated_steps:
        if step["status"] == "not-run":
            continue
        if (
            timestamp_value(step["started_at"]) < previous_end
            or timestamp_value(step["completed_at"])
            > timestamp_value(context["completed_at"])
        ):
            fail("context step timestamps are not ordered within rollout")
        previous_end = timestamp_value(step["completed_at"])
    statuses = [step["status"] for step in validated_steps]
    if context["status"] == "succeeded" and statuses != ["succeeded"] * 3:
        fail("successful context does not contain three successful steps")
    if "not-run" in statuses and statuses != sorted(
        statuses, key={"succeeded": 0, "failed": 1, "not-run": 2}.get
    ):
        fail("context steps are not one forward execution prefix")
    rollback = validate_rollback_context(context.get("rollback"))
    if rollback is not None and rollback["trigger_stage"] != context.get("failure_stage"):
        fail("rollback trigger stage differs from the context failure stage")
    if context["status"] == "failed":
        attempted = [
            step["service"]
            for step in validated_steps
            if step["status"] != "not-run" and step["recreated"] is True
        ]
        expected_rollback = list(reversed(attempted))
        actual_rollback = [step["service"] for step in rollback["steps"]]
        if rollback["status"] != "not-required" and actual_rollback != expected_rollback:
            fail("rollback did not attempt the complete exact reverse forward prefix")
        if rollback["status"] == "not-required" and expected_rollback:
            fail("rollback cannot be not-required after a forward mutation attempt")
    return context


def validate_rollback_context(value: Any) -> dict[str, Any] | None:
    if value is None:
        return None
    rollback = require_object(value, "rollback context")
    require_exact_keys(
        rollback,
        {
            "completed_at",
            "evidence",
            "invariants_restored",
            "started_at",
            "status",
            "steps",
            "trigger_stage",
        },
        "rollback context",
    )
    if rollback.get("status") not in {"not-required", "succeeded", "failed"}:
        fail("rollback context status is invalid")
    validate_stage_token(rollback.get("trigger_stage"), "rollback trigger stage")
    validate_timestamp(rollback.get("started_at"), "rollback start")
    validate_timestamp(rollback.get("completed_at"), "rollback completion")
    if timestamp_value(rollback["started_at"]) > timestamp_value(rollback["completed_at"]):
        fail("rollback completion precedes its start")
    if not isinstance(rollback.get("invariants_restored"), bool):
        fail("rollback invariants flag is invalid")
    evidence_path = path_from_context(
        rollback.get("evidence"), "rollback evidence", nullable=True
    )
    steps = rollback.get("steps")
    if not isinstance(steps, list) or len(steps) > 3:
        fail("rollback context steps are invalid")
    seen_services: set[str] = set()
    previous_end = timestamp_value(rollback["started_at"])
    for index, value_step in enumerate(steps, 1):
        step = require_object(value_step, "rollback context step")
        require_exact_keys(
            step,
            {
                "completed_at",
                "evidence",
                "inspect",
                "order",
                "service",
                "started_at",
                "status",
            },
            "rollback context step",
        )
        if (
            step.get("order") != index
            or step.get("service") not in RUNNING_SERVICE_NAMES
            or step.get("service") in seen_services
        ):
            fail("rollback step order or service is invalid")
        seen_services.add(step["service"])
        if step.get("status") not in {"succeeded", "failed"}:
            fail("rollback step status is invalid")
        validate_timestamp(step.get("started_at"), "rollback step start")
        validate_timestamp(step.get("completed_at"), "rollback step completion")
        if (
            timestamp_value(step["started_at"]) > timestamp_value(step["completed_at"])
            or timestamp_value(step["started_at"]) < previous_end
            or timestamp_value(step["completed_at"])
            > timestamp_value(rollback["completed_at"])
        ):
            fail("rollback step timestamps are not ordered within rollback")
        previous_end = timestamp_value(step["completed_at"])
        path_from_context(step.get("inspect"), "rollback step inspect", nullable=True)
        path_from_context(step.get("evidence"), "rollback step evidence", nullable=True)
    if rollback["status"] == "not-required" and (
        steps or evidence_path is not None or rollback["invariants_restored"] is not True
    ):
        fail("not-required rollback context contains rollback execution evidence")
    if rollback["status"] == "succeeded" and (
        not steps
        or evidence_path is None
        or rollback["invariants_restored"] is not True
        or any(step["status"] != "succeeded" for step in steps)
    ):
        fail("successful rollback context is incomplete")
    if rollback["status"] == "failed" and (
        not steps
        or evidence_path is None
        or (
            rollback["invariants_restored"] is True
            and all(step["status"] == "succeeded" for step in steps)
        )
    ):
        fail("failed rollback context lacks a failed step or invariant restoration")
    return rollback


def validate_smoke_result(value: Any) -> dict[str, Any]:
    smoke = require_object(value, "production smoke result")
    require_exact_keys(
        smoke,
        {
            "check_catalog_sha256",
            "check_count",
            "checks_passed",
            "completed_at",
            "challenge_sha256",
            "result_sha256",
            "schema_version",
            "started_at",
            "status",
            "target_binding_sha256",
        },
        "production smoke result",
    )
    status_value = smoke.get("status")
    if smoke.get("schema_version") != "image-rollout-smoke-result-v1" or status_value not in {
        "passed",
        "failed",
        "not-run",
    }:
        fail("production smoke result header is invalid")
    for key in ("check_count", "checks_passed"):
        if (
            not isinstance(smoke.get(key), int)
            or isinstance(smoke.get(key), bool)
            or smoke[key] < 0
        ):
            fail(f"production smoke {key} is invalid")
    if status_value == "not-run":
        if (
            smoke["started_at"] is not None
            or smoke["completed_at"] is not None
            or smoke["check_count"] != 0
            or smoke["checks_passed"] != 0
            or smoke["check_catalog_sha256"] is not None
            or smoke["challenge_sha256"] is not None
            or smoke["target_binding_sha256"] is not None
            or smoke["result_sha256"] is not None
        ):
            fail("not-run production smoke contains execution evidence")
    else:
        validate_timestamp(smoke.get("started_at"), "production smoke start")
        validate_timestamp(smoke.get("completed_at"), "production smoke completion")
        if timestamp_value(smoke["started_at"]) > timestamp_value(smoke["completed_at"]):
            fail("production smoke completion precedes its start")
        require_sha256(smoke.get("check_catalog_sha256"), "production smoke catalog")
        require_sha256(smoke.get("challenge_sha256"), "production smoke challenge hash")
        require_sha256(
            smoke.get("target_binding_sha256"), "production smoke target binding"
        )
        result_sha = require_sha256(smoke.get("result_sha256"), "production smoke result hash")
        result_without_digest = {
            key: nested for key, nested in smoke.items() if key != "result_sha256"
        }
        if result_sha != sha256_bytes(canonical_json_bytes(result_without_digest)):
            fail("production smoke result digest differs from its canonical fields")
        if (
            smoke["check_count"] != TARGET_SMOKE_CHECK_COUNT
            or smoke["check_catalog_sha256"] != TARGET_SMOKE_CATALOG_SHA256
            or smoke["checks_passed"] > smoke["check_count"]
        ):
            fail("production smoke catalog or counts differ from the fixed producer")
        if (status_value == "passed") != (
            smoke["checks_passed"] == smoke["check_count"]
        ):
            fail("production smoke status differs from its counts")
    return smoke


def not_run_smoke_result() -> dict[str, Any]:
    return {
        "check_catalog_sha256": None,
        "check_count": 0,
        "checks_passed": 0,
        "challenge_sha256": None,
        "completed_at": None,
        "result_sha256": None,
        "schema_version": "image-rollout-smoke-result-v1",
        "started_at": None,
        "status": "not-run",
        "target_binding_sha256": None,
    }


def validate_smoke_challenge(
    path: Path,
    rollout_id: str,
    plan_raw: bytes,
    baseline_raw: bytes,
    running_raw: bytes,
    invariants_raw: bytes,
    smoke: dict[str, Any],
) -> dict[str, Any]:
    challenge, raw = load_json(path, "production smoke challenge")
    challenge = require_object(challenge, "production smoke challenge")
    require_exact_keys(
        challenge,
        {"issued_at", "nonce", "rollout_id", "schema_version", "target"},
        "production smoke challenge",
    )
    target = require_object(challenge.get("target"), "production smoke target")
    require_exact_keys(
        target,
        {
            "baseline_sha256",
            "binding_sha256",
            "invariants_sha256",
            "plan_sha256",
            "running_sha256",
        },
        "production smoke target",
    )
    expected_without_binding = {
        "baseline_sha256": sha256_bytes(baseline_raw),
        "invariants_sha256": sha256_bytes(invariants_raw),
        "plan_sha256": sha256_bytes(plan_raw),
        "running_sha256": sha256_bytes(running_raw),
    }
    expected_target = {
        **expected_without_binding,
        "binding_sha256": sha256_bytes(canonical_json_bytes(expected_without_binding)),
    }
    nonce = challenge.get("nonce")
    if (
        challenge.get("schema_version") != 1
        or challenge.get("rollout_id") != rollout_id
        or not isinstance(nonce, str)
        or re.fullmatch(r"[0-9a-f]{64}", nonce) is None
        or target != expected_target
        or smoke.get("challenge_sha256") != sha256_bytes(raw)
        or smoke.get("target_binding_sha256") != expected_target["binding_sha256"]
    ):
        fail("production smoke challenge does not bind the admitted rollout target")
    validate_timestamp(challenge.get("issued_at"), "production smoke challenge time")
    return file_evidence(path, "production smoke challenge")


def image_set(identity: dict[str, Any]) -> dict[str, Any]:
    images = require_object(identity.get("images"), "record image set")
    return {
        "api": {"image_id": images["control-api"], "platform": "linux/amd64"},
        "postgres_tools": {
            "image_id": images["postgres-tools"],
            "platform": "linux/amd64",
        },
        "pwa": {"image_id": images["pwa"], "platform": "linux/amd64"},
    }


def build_record_step(
    context_step: dict[str, Any],
    old: dict[str, Any] | None,
    new: dict[str, Any] | None,
) -> dict[str, Any]:
    service = context_step["service"]
    inspect_path = path_from_context(
        context_step.get("after_inspect"), f"record step {service} inspect", nullable=True
    )
    after_item: dict[str, Any] | None = None
    if inspect_path is not None:
        projection, _ = load_json(inspect_path, f"record step {service} projection")
        after_item = validate_container_projection(
            projection, f"record step {service} projection"
        )[service]
    evidence_path = path_from_context(
        context_step.get("readiness_evidence"),
        f"record step {service} readiness",
        nullable=True,
    )
    old_item = old.get(service) if old is not None else None
    new_image = (
        new["images"][SERVICE_COMPONENT[service]] if new is not None else None
    )
    if context_step["status"] == "succeeded" and (
        after_item is None
        or after_item.get("image_id") != new_image
        or evidence_path is None
    ):
        fail(f"successful record step {service} lacks bound new runtime evidence")
    return {
        "completed_at": context_step["completed_at"],
        "health_after": after_item["health"] if after_item is not None else "not-observed",
        "health_before": old_item["health"] if old_item is not None else "not-observed",
        "new_container_id": after_item["container_id"] if after_item is not None else None,
        "new_image_id": new_image,
        "old_container_id": old_item["container_id"] if old_item is not None else None,
        "old_image_id": old_item["image_id"] if old_item is not None else None,
        "order": context_step["order"],
        "readiness_evidence": (
            file_evidence(evidence_path, f"record step {service} readiness")
            if evidence_path is not None
            else None
        ),
        "recreated": context_step["recreated"],
        "service": service,
        "started_at": context_step["started_at"],
        "status": context_step["status"],
    }


def build_rollback_record(
    value: Any, old: dict[str, Any] | None, new: dict[str, Any] | None
) -> dict[str, Any] | None:
    rollback = validate_rollback_context(value)
    if rollback is None:
        return None
    evidence_path = path_from_context(
        rollback.get("evidence"), "rollback evidence", nullable=True
    )
    steps: list[dict[str, Any]] = []
    for step in rollback["steps"]:
        service = step["service"]
        inspect_path = path_from_context(
            step.get("inspect"), f"rollback {service} inspect", nullable=True
        )
        after_item = None
        if inspect_path is not None:
            projection, _ = load_json(inspect_path, f"rollback {service} projection")
            after_item = validate_container_projection(
                projection, f"rollback {service} projection"
            )[service]
        step_evidence_path = path_from_context(
            step.get("evidence"), f"rollback {service} evidence", nullable=True
        )
        old_image = old["images"][SERVICE_COMPONENT[service]] if old else None
        new_image = new["images"][SERVICE_COMPONENT[service]] if new else None
        if step["status"] == "succeeded" and (
            after_item is None or after_item.get("image_id") != old_image
        ):
            fail(f"successful rollback {service} does not restore the old image")
        steps.append(
            {
                "completed_at": step["completed_at"],
                "container_id_after": after_item["container_id"] if after_item else None,
                "evidence": (
                    file_evidence(step_evidence_path, f"rollback {service} evidence")
                    if step_evidence_path
                    else None
                ),
                "from_image_id": new_image,
                "health_after": after_item["health"] if after_item else "not-observed",
                "order": step["order"],
                "service": service,
                "started_at": step["started_at"],
                "status": step["status"],
                "to_image_id": old_image,
            }
        )
    return {
        "completed_at": rollback["completed_at"],
        "evidence": file_evidence(evidence_path, "rollback evidence") if evidence_path else None,
        "invariants_restored": rollback["invariants_restored"],
        "started_at": rollback["started_at"],
        "status": rollback["status"],
        "steps": steps,
        "trigger_stage": rollback["trigger_stage"],
    }


def record(args: argparse.Namespace) -> dict[str, Any]:
    context_value, context_raw = load_json(args.context, "rollout record context")
    context = validate_record_context(context_value)
    plan_path = args.plan
    baseline_path = args.baseline
    running_path = args.running
    invariants_path = args.invariants
    plan_value, plan_raw, plan_evidence = optional_admission_file(
        plan_path, "rollout plan", "plan"
    )
    if plan_value is not None:
        plan_value = validate_rollout_plan(plan_value)
    baseline_value, baseline_raw, baseline_evidence = optional_admission_file(
        baseline_path, "rollout baseline", "baseline"
    )
    running_value, running_raw, running_evidence = optional_admission_file(
        running_path, "running admission", "running"
    )
    invariants_value, invariants_raw, invariants_evidence = optional_admission_file(
        invariants_path, "invariants admission", "invariants"
    )
    if baseline_value is not None:
        if plan_raw is None:
            fail("rollout baseline lacks its supplied plan")
        baseline_value = validate_baseline_value(baseline_value, plan_raw)
    if running_value is not None:
        if plan_value is None or plan_raw is None:
            fail("running admission lacks its supplied plan")
        running_value = validate_running_value(running_value, plan_value, plan_raw)
    if invariants_value is not None:
        invariants_value = validate_invariants_value(invariants_value)
    if args.smoke is None:
        if context["status"] != "failed":
            fail("successful rollout record requires a production smoke result")
        smoke = not_run_smoke_result()
        smoke_evidence = None
    else:
        smoke_value, _ = load_json(args.smoke, "production smoke result")
        smoke = validate_smoke_result(smoke_value)
        smoke_evidence = file_evidence(args.smoke, "production smoke result")
    success = context["status"] == "succeeded"
    if success and any(
        value is None
        for value in (plan_value, baseline_value, running_value, invariants_value)
    ):
        fail("successful record requires every admission stage")
    if plan_value is None and any(
        value is not None for value in (baseline_value, running_value)
    ):
        fail("partial record contains downstream evidence without a plan")
    if baseline_value is not None and (
        plan_raw is None
        or baseline_value.get("rollout_plan_sha256") != sha256_bytes(plan_raw)
    ):
        fail("baseline record does not bind the supplied plan")
    if running_value is not None and (
        plan_raw is None or running_value.get("plan_sha256") != sha256_bytes(plan_raw)
    ):
        fail("running record does not bind the supplied plan")
    if success and smoke.get("status") != "passed":
        fail("successful rollout record requires passing production smoke")
    smoke_challenge_evidence = None
    if smoke.get("status") != "not-run":
        if any(
            raw is None
            for raw in (plan_raw, baseline_raw, running_raw, invariants_raw)
        ):
            fail("executed production smoke lacks complete admitted target evidence")
        smoke_challenge_path = path_from_context(
            context["paths"].get("smoke_challenge"), "production smoke challenge"
        )
        assert smoke_challenge_path is not None
        smoke_challenge_evidence = validate_smoke_challenge(
            smoke_challenge_path,
            context["rollout_id"],
            plan_raw,
            baseline_raw,
            running_raw,
            invariants_raw,
            smoke,
        )
    elif context["paths"].get("smoke_challenge") is not None:
        fail("not-run production smoke cannot contain a challenge path")
    if invariants_value is not None and invariants_value.get("unchanged") is not True:
        fail("record invariants are not unchanged")
    old_identity = plan_value.get("old") if plan_value else None
    new_identity = plan_value.get("new") if plan_value else None
    old_containers = None
    if baseline_value is not None:
        old_admission = require_object(
            baseline_value.get("old_admission"), "baseline old admission"
        )
        old_containers = require_object(
            old_admission.get("current_containers"), "baseline current containers"
        )
    if success and running_value is not None:
        running_containers = require_object(
            running_value.get("containers"), "successful running containers"
        )
        for step in context["steps"]:
            projection, _ = load_json(
                path_from_context(
                    step.get("after_inspect"),
                    f"successful step {step['service']} projection",
                ),
                f"successful step {step['service']} projection",
            )
            projected = validate_container_projection(
                projection, f"successful step {step['service']} projection"
            )
            if (
                projected[step["service"]]["container_id"]
                != running_containers[step["service"]]["container_id"]
            ):
                fail("successful step container differs from final running admission")
    paths = context["paths"]
    tools_manifest_path = path_from_context(
        paths.get("tools_manifest"), "record tools manifest", nullable=True
    )
    tools_admission_path = path_from_context(
        paths.get("tools_admission"), "record tools admission", nullable=True
    )
    if (tools_manifest_path is None) != (tools_admission_path is None):
        fail("record context contains only one half of the tooling trust evidence")
    tooling_record = None
    if tools_manifest_path is not None and tools_admission_path is not None:
        tooling_record = validate_tools_manifest(tools_manifest_path)
        tooling_record = validate_tools_admission(
            tools_admission_path, tools_manifest_path, tooling_record
        )
        if baseline_value is not None and tooling_record != baseline_value.get("tooling"):
            fail("rollout tooling changed after baseline admission")
    bootstrap_record_path = path_from_context(
        paths.get("bootstrap_record"), "record bootstrap", nullable=True
    )
    closure_record_path = path_from_context(
        paths.get("closure_record"), "record closure", nullable=True
    )
    base_bootstrap = None
    if baseline_value is not None:
        deployment = require_object(
            baseline_value.get("bootstrap_deployment"), "baseline bootstrap deployment"
        )
        if bootstrap_record_path is None or closure_record_path is None:
            fail("baseline record lacks bootstrap source evidence paths")
        bootstrap_descriptor = file_evidence(
            bootstrap_record_path, "record bootstrap record"
        )
        closure_descriptor = file_evidence(
            closure_record_path, "record bootstrap closure"
        )
        if (
            bootstrap_descriptor["sha256"]
            != baseline_value.get("bootstrap_record_sha256")
            or closure_descriptor["sha256"]
            != baseline_value.get("closure_record_sha256")
        ):
            fail("bootstrap or closure evidence changed after baseline admission")
        base_bootstrap = {
            "authenticated_smoke_closure": closure_descriptor,
            "bootstrap_record": bootstrap_descriptor,
            "bootstrap_status": "bootstrapped-unsigned",
            "closure_closes_authenticated_smoke_pending": True,
            "closure_status": "authenticated-smoke-closed",
            "deployment_basename": deployment["deployment_basename"],
            "deployment_id": deployment["deployment_id"],
            "original_bootstrap_record_mutated": False,
        }
    bundle_record = None
    source_record = None
    operator_record = None
    compose_record = None
    images_record = None
    if baseline_value is not None and plan_value is not None:
        archive_evidence_path = path_from_context(
            paths.get("archive_evidence"), "record archive evidence"
        )
        source_evidence_path = path_from_context(
            paths.get("source_evidence"), "record source evidence"
        )
        operator_path = path_from_context(
            paths.get("operator_exception"), "record operator instruction"
        )
        source_root = path_from_context(paths.get("source_root"), "record source root")
        new_compose = path_from_context(paths.get("new_compose"), "record new Compose")
        old_compose = path_from_context(paths.get("old_compose"), "record old Compose")
        assert archive_evidence_path and source_evidence_path and operator_path
        assert source_root and new_compose and old_compose
        old_compose_descriptor = file_evidence(old_compose, "record old Compose")
        new_compose_descriptor = file_evidence(new_compose, "record new Compose")
        if (
            old_compose_descriptor["sha256"] != plan_value["old_compose_sha256"]
            or new_compose_descriptor["sha256"] != plan_value["new_compose_sha256"]
        ):
            fail("resolved Compose evidence changed after rollout planning")
        after_tree = source_tree_identity(source_root, "record source root")
        before_tree = require_object(
            require_object(baseline_value.get("source_evidence"), "baseline source").get(
                "tree"
            ),
            "baseline source tree",
        )
        if after_tree != before_tree:
            fail("trusted source tree changed during image-only rollout")
        ready_record = require_object(
            baseline_value.get("ready_record"), "baseline READY record"
        )
        archives = require_object(baseline_value.get("archives"), "baseline archives")
        bundle_record = {
            "archive_count": 3,
            "archives_loaded": context["operations"]["archives_loaded"],
            "bundle_id": ready_record["bundle_id"],
            "image_archives": {
                "api": archives["control-api"],
                "postgres_tools": archives["postgres-tools"],
                "pwa": archives["pwa"],
            },
            "manifest_sha256": baseline_value["artifact_manifest_sha256"],
            "release": new_identity["release"],
            "transport_sha256": ready_record["transport_sha256"],
            "verification_record": file_evidence(
                archive_evidence_path, "record archive evidence"
            ),
            "verified": True,
        }
        source_record = {
            "bytecode_files_after": after_tree["bytecode_files"],
            "bytecode_files_before": before_tree["bytecode_files"],
            "identity": new_identity["vcs_ref"],
            "python_dont_write_bytecode": context["operations"]["python_dont_write_bytecode"],
            "tree_sha256_after": after_tree["tree_sha256"],
            "tree_sha256_before": before_tree["tree_sha256"],
            "tree_unchanged": True,
            "verification_record": file_evidence(
                source_evidence_path, "record source evidence"
            ),
            "verified": True,
            "verifier_normalized_read_only": True,
        }
        operator_value, operator_raw = load_json(
            operator_path, "record operator instruction"
        )
        operator_value = validate_operator_exception(operator_value)
        if sha256_bytes(operator_raw) != baseline_value.get("operator_exception_sha256"):
            fail("operator instruction changed after baseline admission")
        operator_record = {
            "acknowledged_at": operator_value["acknowledged_at"],
            "backup_command_run": context["operations"]["backup_invoked"],
            "backup_created": False,
            "duplicate_backup_prohibited": True,
            "migration_run": context["operations"]["migrate_invoked"],
            "reason": operator_value["reason"],
            "type": operator_value["type"],
        }
        images_record = {
            "api_changed": True,
            "new": image_set(new_identity),
            "new_ids_distinct": len(set(new_identity["images"].values())) == 3,
            "old": image_set(old_identity),
            "postgres_tools_changed": True,
            "postgres_tools_executed": context["operations"]["postgres_tools_executed"],
            "pwa_changed": True,
        }
        compose_record = {
            "base_config": old_compose_descriptor,
            "build_invoked": context["operations"]["build_invoked"],
            "down_invoked": context["operations"]["down_invoked"],
            "force_recreate": True,
            "load_invoked": context["operations"]["load_invoked"],
            "migrate_invoked": context["operations"]["migrate_invoked"],
            "no_deps": True,
            "only_identity_allowlist_changed": True,
            "project": TARGET_COMPOSE_PROJECT,
            "pull_invoked": context["operations"]["pull_invoked"],
            "pull_policy": "never",
            "rollout_config": new_compose_descriptor,
        }
    record_value = {
        "base_bootstrap": base_bootstrap,
        "bundle": bundle_record,
        "completed_at": context["completed_at"],
        "compose": compose_record,
        "created_at": context["created_at"],
        "evidence": {
            "baseline": baseline_evidence,
            "context": {
                "basename": args.context.name,
                "sha256": sha256_bytes(context_raw),
                "size": len(context_raw),
            },
            "invariants": invariants_evidence,
            "plan": plan_evidence,
            "running": running_evidence,
            "smoke": smoke_evidence,
            "smoke_challenge": smoke_challenge_evidence,
        },
        "failure_stage": context["failure_stage"],
        "images": images_record,
        "invariants": invariants_value,
        "operator_exception": operator_record,
        "rollback": build_rollback_record(context.get("rollback"), old_identity, new_identity),
        "rollout_id": context["rollout_id"],
        "schema_version": 1,
        "smoke": smoke,
        "source": source_record,
        "status": context["status"],
        "steps": [
            build_record_step(step, old_containers, new_identity)
            for step in context["steps"]
        ],
        "tooling": tooling_record,
        "type": "bootstrap-image-only-followup-v1",
    }
    validate_record_value(record_value)
    schema_value, _ = trusted_schema_path(args.schema)
    validate_closed_record_schema(record_value, schema_value)
    raw = canonical_bytes(record_value)
    output = canonical_path(args.output.parent, "record output directory") / args.output.name
    if output != args.output:
        fail("record output must be one normalized absolute path")
    publish_record_noreplace(
        output,
        raw,
        schema_value,
        resume_existing=args.resume_existing,
    )
    return record_value


def validate_nullable_evidence(value: Any, label: str) -> None:
    if value is not None:
        validate_file_evidence(value, label)


def validate_record_value(value: Any) -> dict[str, Any]:
    record_value = require_object(value, "image rollout record")
    keys = {
        "base_bootstrap",
        "bundle",
        "completed_at",
        "compose",
        "created_at",
        "evidence",
        "failure_stage",
        "images",
        "invariants",
        "operator_exception",
        "rollback",
        "rollout_id",
        "schema_version",
        "smoke",
        "source",
        "status",
        "steps",
        "tooling",
        "type",
    }
    require_exact_keys(record_value, keys, "image rollout record")
    if (
        record_value.get("schema_version") != 1
        or record_value.get("type") != "bootstrap-image-only-followup-v1"
        or record_value.get("status") not in {"succeeded", "failed"}
    ):
        fail("image rollout record header is invalid")
    try:
        record_uuid = str(
            uuid.UUID(require_string(record_value.get("rollout_id"), "record rollout ID"), version=4)
        )
    except ValueError:
        fail("record rollout ID is not UUIDv4")
    if record_uuid != record_value.get("rollout_id"):
        fail("record rollout ID is not canonical UUIDv4")
    validate_timestamp(record_value.get("created_at"), "record creation time")
    validate_timestamp(record_value.get("completed_at"), "record completion time")
    if timestamp_value(record_value["created_at"]) > timestamp_value(record_value["completed_at"]):
        fail("record completion precedes creation")
    success = record_value["status"] == "succeeded"
    evidence = require_object(record_value.get("evidence"), "record evidence")
    evidence_keys = {
        "baseline",
        "context",
        "invariants",
        "plan",
        "running",
        "smoke",
        "smoke_challenge",
    }
    require_exact_keys(evidence, evidence_keys, "record evidence")
    for name in evidence_keys:
        validate_nullable_evidence(evidence[name], f"record evidence {name}")
    if evidence["context"] is None:
        fail("record lacks its context descriptor")
    for name in ("base_bootstrap", "bundle", "source", "operator_exception", "images", "compose", "tooling"):
        if success and record_value[name] is None:
            fail(f"successful record lacks {name}")
    if success and any(evidence[name] is None for name in ("baseline", "invariants", "plan", "running", "smoke_challenge")):
        fail("successful record lacks a required admission evidence descriptor")
    if success:
        if record_value.get("failure_stage") is not None or record_value.get("rollback") is not None:
            fail("successful record contains failure or rollback state")
    else:
        validate_stage_token(record_value.get("failure_stage"), "record failure stage")
        if record_value.get("rollback") is None:
            fail("failed record lacks rollback disposition")
    base = record_value.get("base_bootstrap")
    if base is not None:
        base = require_object(base, "record base bootstrap")
        require_exact_keys(
            base,
            {
                "authenticated_smoke_closure",
                "bootstrap_record",
                "bootstrap_status",
                "closure_closes_authenticated_smoke_pending",
                "closure_status",
                "deployment_basename",
                "deployment_id",
                "original_bootstrap_record_mutated",
            },
            "record base bootstrap",
        )
        bootstrap_evidence = validate_file_evidence(
            base["bootstrap_record"], "record bootstrap evidence"
        )
        closure_evidence = validate_file_evidence(
            base["authenticated_smoke_closure"], "record closure evidence"
        )
        if (
            base["bootstrap_status"] != "bootstrapped-unsigned"
            or base["closure_status"] != "authenticated-smoke-closed"
            or base["closure_closes_authenticated_smoke_pending"] is not True
            or base["original_bootstrap_record_mutated"] is not False
            or DEPLOYMENT_DIRECTORY_RE.fullmatch(base["deployment_basename"]) is None
            or bootstrap_evidence["basename"] != "bootstrap-deployment.json"
            or closure_evidence["basename"] != "authenticated-smoke-closure.json"
        ):
            fail("record base bootstrap semantics are invalid")
    bundle = record_value.get("bundle")
    if bundle is not None:
        bundle = require_object(bundle, "record bundle")
        require_exact_keys(
            bundle,
            {
                "archive_count",
                "archives_loaded",
                "bundle_id",
                "image_archives",
                "manifest_sha256",
                "release",
                "transport_sha256",
                "verification_record",
                "verified",
            },
            "record bundle",
        )
        if (
            bundle["archive_count"] != 3
            or bundle["bundle_id"] != TARGET_BUNDLE_ID
            or bundle["manifest_sha256"] != TARGET_MANIFEST_SHA256
            or bundle["transport_sha256"] != TARGET_TRANSPORT_SHA256
            or bundle["release"] != TARGET_RELEASE
            or bundle["verified"] is not True
            or not isinstance(bundle["archives_loaded"], bool)
        ):
            fail("record bundle differs from the frozen target")
        archives = require_object(bundle["image_archives"], "record image archives")
        require_exact_keys(archives, {"api", "postgres_tools", "pwa"}, "record archives")
        for name, component in (("api", "control-api"), ("pwa", "pwa"), ("postgres_tools", "postgres-tools")):
            archive = validate_file_evidence(archives[name], f"record archive {name}")
            if archive["basename"] != ARCHIVE_NAMES[component] or archive["sha256"] != TARGET_ARCHIVE_SHA256[component]:
                fail(f"record archive {name} differs from the frozen target")
        bundle_verifier = validate_file_evidence(
            bundle["verification_record"], "record bundle verifier"
        )
        if bundle_verifier["basename"] != "archive-evidence.json":
            fail("record bundle verifier has an unexpected basename")
    source = record_value.get("source")
    if source is not None:
        source = require_object(source, "record source")
        require_exact_keys(
            source,
            {
                "bytecode_files_after",
                "bytecode_files_before",
                "identity",
                "python_dont_write_bytecode",
                "tree_sha256_after",
                "tree_sha256_before",
                "tree_unchanged",
                "verification_record",
                "verified",
                "verifier_normalized_read_only",
            },
            "record source",
        )
        if (
            source["identity"] != TARGET_VCS_REF
            or source["bytecode_files_before"] != 0
            or source["bytecode_files_after"] != 0
            or source["tree_sha256_before"] != source["tree_sha256_after"]
            or source["tree_unchanged"] is not True
            or source["verified"] is not True
            or source["verifier_normalized_read_only"] is not True
            or source["python_dont_write_bytecode"] is not True
            or source["verification_record"]["basename"]
            != "source-evidence.json"
        ):
            fail("record source semantics are invalid")
        validate_file_evidence(source["verification_record"], "record source verifier")
    operator = record_value.get("operator_exception")
    if operator is not None:
        operator = require_object(operator, "record operator exception")
        require_exact_keys(
            operator,
            {
                "acknowledged_at",
                "backup_command_run",
                "backup_created",
                "duplicate_backup_prohibited",
                "migration_run",
                "reason",
                "type",
            },
            "record operator exception",
        )
        if (
            operator["type"] != "no-duplicate-backup-operator-instruction-v1"
            or operator["reason"] != "operator-prohibited-duplicate-backup"
            or operator["duplicate_backup_prohibited"] is not True
            or operator["backup_created"] is not False
            or operator["backup_command_run"] is not False
            or operator["migration_run"] is not False
        ):
            fail("record operator exception semantics are invalid")
        validate_utc_timestamp(operator["acknowledged_at"], "record operator acknowledgment")
    tooling = record_value.get("tooling")
    if tooling is not None:
        tooling = require_object(tooling, "record tooling")
        require_exact_keys(
            tooling,
            {
                "admission",
                "admission_helper",
                "archive",
                "external_verifier",
                "manifest",
                "record_schema",
                "root_owned_read_only",
                "smoke_helper",
                "tooling_identity",
                "wrapper",
            },
            "record tooling",
        )
        require_sha256(tooling.get("tooling_identity"), "record tooling identity")
        if tooling.get("root_owned_read_only") is not True:
            fail("record tooling is not root-owned read-only evidence")
        for name in (
            "admission",
            "archive",
            "external_verifier",
            "manifest",
            "wrapper",
            "admission_helper",
            "smoke_helper",
            "record_schema",
        ):
            validate_file_evidence(tooling.get(name), f"record tooling {name}")
        if (
            tooling["manifest"]["basename"] != TOOLS_MANIFEST_BASENAME
            or tooling["admission"]["basename"] != "rollout-tools.admission.json"
            or tooling["archive"]["basename"] != "image-rollout-tools.tar"
            or tooling["external_verifier"]["basename"]
            != "build-image-rollout-tools.py"
            or tooling["admission_helper"]["basename"]
            != "image-rollout-admission.py"
            or tooling["smoke_helper"]["basename"] != "image-rollout-smoke.py"
            or tooling["wrapper"]["basename"] != "rollout-bootstrap-images.sh"
            or tooling["record_schema"]["basename"]
            != "image-rollout-record.schema.json"
            or tooling["record_schema"]["sha256"] != TARGET_SCHEMA_SHA256
        ):
            fail("record tooling descriptors differ from the fixed tooling contract")
        tooling_members = {
            "deploy/scripts/image-rollout-admission.py": {
                "mode": "0555",
                "sha256": tooling["admission_helper"]["sha256"],
                "size": tooling["admission_helper"]["size"],
            },
            "deploy/scripts/image-rollout-smoke.py": {
                "mode": "0555",
                "sha256": tooling["smoke_helper"]["sha256"],
                "size": tooling["smoke_helper"]["size"],
            },
            "deploy/scripts/rollout-bootstrap-images.sh": {
                "mode": "0555",
                "sha256": tooling["wrapper"]["sha256"],
                "size": tooling["wrapper"]["size"],
            },
            "deploy/schemas/image-rollout-record.schema.json": {
                "mode": "0444",
                "sha256": tooling["record_schema"]["sha256"],
                "size": tooling["record_schema"]["size"],
            },
        }
        if tooling["tooling_identity"] != sha256_bytes(
            canonical_json_bytes(tooling_members)
        ):
            fail("record tooling identity differs from its exact member descriptors")
    images = record_value.get("images")
    image_ids: dict[str, dict[str, str]] | None = None
    if images is not None:
        images = require_object(images, "record images")
        require_exact_keys(
            images,
            {
                "api_changed",
                "new",
                "new_ids_distinct",
                "old",
                "postgres_tools_changed",
                "postgres_tools_executed",
                "pwa_changed",
            },
            "record images",
        )
        if (
            images["api_changed"] is not True
            or images["pwa_changed"] is not True
            or images["postgres_tools_changed"] is not True
            or images["new_ids_distinct"] is not True
            or images["postgres_tools_executed"] is not False
        ):
            fail("record image operation flags are invalid")
        image_ids = {}
        for generation in ("old", "new"):
            image_set_value = require_object(
                images[generation], f"record {generation} image set"
            )
            require_exact_keys(
                image_set_value,
                {"api", "postgres_tools", "pwa"},
                f"record {generation} image set",
            )
            image_ids[generation] = {}
            for component in ("api", "postgres_tools", "pwa"):
                item = require_object(
                    image_set_value[component],
                    f"record {generation} {component} image",
                )
                require_exact_keys(
                    item,
                    {"image_id", "platform"},
                    f"record {generation} {component} image",
                )
                if item.get("platform") != "linux/amd64":
                    fail("record image platform is not linux/amd64")
                image_ids[generation][component] = require_sha256(
                    item.get("image_id"),
                    f"record {generation} {component} image ID",
                    image=True,
                )
            if len(set(image_ids[generation].values())) != 3:
                fail(f"record {generation} image IDs are not distinct")
        if any(
            image_ids["old"][component] == image_ids["new"][component]
            for component in image_ids["old"]
        ):
            fail("record image set did not replace every component")
        if image_ids["new"] != {
            "api": TARGET_IMAGE_IDS["control-api"],
            "postgres_tools": TARGET_IMAGE_IDS["postgres-tools"],
            "pwa": TARGET_IMAGE_IDS["pwa"],
        }:
            fail("record new image IDs differ from the frozen target")
    compose = record_value.get("compose")
    if compose is not None:
        compose = require_object(compose, "record Compose")
        require_exact_keys(
            compose,
            {
                "base_config",
                "build_invoked",
                "down_invoked",
                "force_recreate",
                "load_invoked",
                "migrate_invoked",
                "no_deps",
                "only_identity_allowlist_changed",
                "project",
                "pull_invoked",
                "pull_policy",
                "rollout_config",
            },
            "record Compose",
        )
        validate_file_evidence(compose["base_config"], "record base Compose")
        validate_file_evidence(compose["rollout_config"], "record rollout Compose")
        if (
            compose["project"] != TARGET_COMPOSE_PROJECT
            or compose["only_identity_allowlist_changed"] is not True
            or compose["pull_policy"] != "never"
            or compose["no_deps"] is not True
            or compose["force_recreate"] is not True
            or any(
                compose[key]
                for key in ("down_invoked", "pull_invoked", "build_invoked", "migrate_invoked")
            )
            or not isinstance(compose["load_invoked"], bool)
        ):
            fail("record Compose operations violate image-only policy")
    steps = record_value.get("steps")
    if not isinstance(steps, list) or len(steps) != 3:
        fail("record must contain exactly three rollout steps")
    services = ("control-api-replica", "control-api", "codex-pwa")
    for index, (step_value, service) in enumerate(zip(steps, services), 1):
        step = require_object(step_value, f"record step {service}")
        require_exact_keys(
            step,
            {
                "completed_at",
                "health_after",
                "health_before",
                "new_container_id",
                "new_image_id",
                "old_container_id",
                "old_image_id",
                "order",
                "readiness_evidence",
                "recreated",
                "service",
                "started_at",
                "status",
            },
            f"record step {service}",
        )
        if step["order"] != index or step["service"] != service or step["status"] not in {"succeeded", "failed", "not-run"}:
            fail("record rollout step sequence is invalid")
        validate_nullable_evidence(step["readiness_evidence"], f"record step {service} readiness")
        for key in (
            "new_container_id",
            "old_container_id",
        ):
            if step[key] is not None and (
                not isinstance(step[key], str)
                or CONTAINER_ID_RE.fullmatch(step[key]) is None
            ):
                fail(f"record step {service} {key} is invalid")
        for key in ("new_image_id", "old_image_id"):
            if step[key] is not None:
                require_sha256(step[key], f"record step {service} {key}", image=True)
        if image_ids is not None:
            component = "pwa" if service == "codex-pwa" else "api"
            if (
                step["old_image_id"] != image_ids["old"][component]
                or step["new_image_id"] != image_ids["new"][component]
            ):
                fail(f"record step {service} image transition differs from image sets")
        if step["status"] != "not-run":
            validate_timestamp(step["started_at"], f"record step {service} start")
            validate_timestamp(step["completed_at"], f"record step {service} completion")
            if timestamp_value(step["started_at"]) > timestamp_value(step["completed_at"]):
                fail(f"record step {service} completion precedes its start")
        if step["status"] == "not-run" and any(
            step[key] is not None
            for key in (
                "started_at",
                "completed_at",
                "new_container_id",
                "readiness_evidence",
            )
        ):
            fail(f"not-run record step {service} contains execution evidence")
        if success and (
            step["status"] != "succeeded"
            or step["recreated"] is not True
            or step["health_before"] != "healthy"
            or step["health_after"] != "healthy"
            or step["readiness_evidence"] is None
        ):
            fail("successful record step is incomplete")
    smoke = validate_smoke_result(record_value.get("smoke"))
    if (smoke["status"] == "not-run") != (evidence["smoke"] is None):
        fail("record smoke execution and evidence descriptor differ")
    if success and smoke["status"] != "passed":
        fail("successful record smoke is not passing")
    invariant_value = record_value.get("invariants")
    if invariant_value is not None:
        invariant_value = validate_invariants_value(invariant_value)
        if evidence["baseline"] is None:
            fail("record invariants lack their baseline evidence descriptor")
        if invariant_value["baseline_sha256"] != evidence["baseline"]["sha256"]:
            fail("record invariants differ from the terminal baseline evidence")
    if record_value.get("rollback") is not None:
        rollback = require_object(record_value["rollback"], "record rollback")
        require_exact_keys(
            rollback,
            {"completed_at", "evidence", "invariants_restored", "started_at", "status", "steps", "trigger_stage"},
            "record rollback",
        )
        if rollback["status"] not in {"not-required", "succeeded", "failed"}:
            fail("record rollback status is invalid")
        validate_nullable_evidence(rollback["evidence"], "record rollback evidence")
        if rollback["trigger_stage"] != record_value.get("failure_stage"):
            fail("record rollback trigger differs from failure stage")
        rollback_steps = rollback.get("steps")
        if not isinstance(rollback_steps, list) or len(rollback_steps) > 3:
            fail("record rollback steps are invalid")
        attempted = [
            step["service"]
            for step in steps
            if step["status"] != "not-run" and step["recreated"] is True
        ]
        expected_services = list(reversed(attempted))
        actual_services: list[str] = []
        for index, step_value in enumerate(rollback_steps, 1):
            step = require_object(step_value, "record rollback step")
            require_exact_keys(
                step,
                {
                    "completed_at",
                    "container_id_after",
                    "evidence",
                    "from_image_id",
                    "health_after",
                    "order",
                    "service",
                    "started_at",
                    "status",
                    "to_image_id",
                },
                "record rollback step",
            )
            if step.get("order") != index or step.get("service") not in RUNNING_SERVICE_NAMES:
                fail("record rollback step sequence is invalid")
            actual_services.append(step["service"])
            if step.get("status") == "succeeded" and (
                step.get("health_after") != "healthy"
                or step.get("container_id_after") is None
                or step.get("evidence") is None
            ):
                fail("successful record rollback step lacks restored runtime evidence")
            if image_ids is not None:
                component = "pwa" if step["service"] == "codex-pwa" else "api"
                if (
                    step.get("from_image_id") != image_ids["new"][component]
                    or step.get("to_image_id") != image_ids["old"][component]
                ):
                    fail("record rollback image direction differs from image sets")
            validate_nullable_evidence(step.get("evidence"), "record rollback step evidence")
        if rollback["status"] != "not-required" and actual_services != expected_services:
            fail("record rollback did not attempt the complete reverse forward prefix")
        if rollback["status"] == "not-required" and (attempted or actual_services):
            fail("record rollback is not-required despite forward mutation evidence")
        if rollback["status"] == "not-required" and rollback["evidence"] is not None:
            fail("not-required record rollback contains execution evidence")
        if rollback["status"] != "not-required" and rollback["evidence"] is None:
            fail("executed record rollback lacks aggregate evidence")
        if (
            rollback["status"] == "failed"
            and rollback["invariants_restored"] is True
            and not any(step.get("status") == "failed" for step in rollback_steps)
        ):
            fail("failed record rollback contains no failed restore or invariant check")
    def reject_private_path_keys(item: Any) -> None:
        if isinstance(item, dict):
            for key, nested in item.items():
                if key in {
                    "path",
                    "source_root",
                    "deployment_directory",
                    "bundle_directory",
                }:
                    fail("record contains a private path field")
                reject_private_path_keys(nested)
        elif isinstance(item, list):
            for nested in item:
                reject_private_path_keys(nested)

    reject_private_path_keys(record_value)
    return record_value


def validate_record(args: argparse.Namespace) -> dict[str, Any]:
    record_value, record_raw = load_json(args.record, "image rollout record")
    validate_record_value(record_value)
    schema_value, schema_raw = trusted_schema_path(args.schema)
    validate_closed_record_schema(record_value, schema_value)
    return {
        "command": "validate-record",
        "format_version": FORMAT_VERSION,
        "record_sha256": sha256_bytes(record_raw),
        "schema_sha256": sha256_bytes(schema_raw),
        "status": "valid",
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)

    plan_parser = commands.add_parser("plan")
    plan_parser.add_argument("--old-compose", type=Path, required=True)
    plan_parser.add_argument("--new-compose", type=Path, required=True)
    plan_parser.add_argument("--artifact-manifest", type=Path, required=True)
    plan_parser.set_defaults(handler=plan)

    baseline_parser = commands.add_parser("baseline")
    baseline_parser.add_argument("--plan", type=Path, required=True)
    baseline_parser.add_argument("--old-plan", type=Path, required=True)
    baseline_parser.add_argument("--old-images", type=Path, required=True)
    baseline_parser.add_argument("--old-running", type=Path, required=True)
    baseline_parser.add_argument("--old-compose", type=Path, required=True)
    baseline_parser.add_argument("--current-before-inspect", type=Path, required=True)
    baseline_parser.add_argument("--bootstrap-record", type=Path, required=True)
    baseline_parser.add_argument("--closure-record", type=Path, required=True)
    baseline_parser.add_argument("--artifact-manifest", type=Path, required=True)
    baseline_parser.add_argument("--ready-record", type=Path, required=True)
    baseline_parser.add_argument("--bundle-dir", type=Path, required=True)
    baseline_parser.add_argument("--source-evidence", type=Path, required=True)
    baseline_parser.add_argument("--bundle-evidence", type=Path, required=True)
    baseline_parser.add_argument("--archive-evidence", type=Path, required=True)
    baseline_parser.add_argument("--old-source-root", type=Path, required=True)
    baseline_parser.add_argument("--new-source-root", type=Path, required=True)
    baseline_parser.add_argument("--migration-state", type=Path, required=True)
    baseline_parser.add_argument("--operator-exception", type=Path, required=True)
    baseline_parser.add_argument("--tools-manifest", type=Path, required=True)
    baseline_parser.add_argument("--tools-admission", type=Path, required=True)
    baseline_parser.set_defaults(handler=baseline)

    running_parser = commands.add_parser("running")
    running_parser.add_argument("--plan", type=Path, required=True)
    running_parser.add_argument("--inspect", type=Path, required=True)
    running_parser.set_defaults(handler=running)

    stage_parser = commands.add_parser("stage")
    stage_parser.add_argument("--plan", type=Path, required=True)
    stage_parser.add_argument("--baseline", type=Path, required=True)
    stage_parser.add_argument("--before", type=Path, required=True)
    stage_parser.add_argument("--after", type=Path, required=True)
    stage_parser.add_argument(
        "--target", choices=RUNNING_SERVICE_NAMES, required=True
    )
    stage_parser.add_argument("--readiness", type=Path, required=True)
    stage_parser.add_argument("--protected-before", type=Path, required=True)
    stage_parser.add_argument("--protected-after", type=Path, required=True)
    stage_parser.set_defaults(handler=stage)

    invariants_parser = commands.add_parser("invariants")
    invariants_parser.add_argument("--plan", type=Path, required=True)
    invariants_parser.add_argument("--baseline", type=Path, required=True)
    invariants_parser.add_argument("--before", type=Path, required=True)
    invariants_parser.add_argument("--after", type=Path, required=True)
    invariants_parser.set_defaults(handler=invariants)

    project_invariants_parser = commands.add_parser("project-invariants")
    for argument in (
        "baseline",
        "bootstrap-record",
        "containers",
        "listeners",
        "migration-current",
        "migration-head",
        "migration-state",
        "nginx-effective",
        "nginx-state",
        "old-compose",
        "plan",
        "postgres",
        "redis-acl",
        "redis-config",
        "redis-namespace",
        "ufw",
    ):
        project_invariants_parser.add_argument(
            f"--{argument}", type=Path, required=True
        )
    project_invariants_parser.add_argument(
        "--nginx-managed-root", type=Path, required=True
    )
    project_invariants_parser.set_defaults(handler=project_invariants)

    project_parser = commands.add_parser("project-container")
    project_parser.add_argument(
        "--service", choices=RUNNING_SERVICE_NAMES, required=True
    )
    project_parser.set_defaults(handler=project_container)

    project_image_parser = commands.add_parser("project-image")
    project_image_parser.set_defaults(handler=project_image)

    verifier_parser = commands.add_parser("project-verifier")
    verifier_parser.add_argument(
        "--kind", choices=("source", "bundle", "archive"), required=True
    )
    verifier_parser.add_argument("--bundle-dir", type=Path, required=True)
    verifier_parser.add_argument("--release", required=True)
    verifier_parser.add_argument("--vcs-ref", required=True)
    verifier_parser.set_defaults(handler=project_verifier)

    record_parser = commands.add_parser("record")
    record_parser.add_argument("--context", type=Path, required=True)
    record_parser.add_argument("--baseline", type=Path)
    record_parser.add_argument("--plan", type=Path)
    record_parser.add_argument("--running", type=Path)
    record_parser.add_argument("--invariants", type=Path)
    record_parser.add_argument("--smoke", type=Path)
    record_parser.add_argument("--schema", type=Path, required=True)
    record_parser.add_argument("--output", type=Path, required=True)
    record_parser.add_argument("--resume-existing", action="store_true")
    record_parser.set_defaults(handler=record)

    validate_parser = commands.add_parser("validate-record")
    validate_parser.add_argument("--record", type=Path, required=True)
    validate_parser.add_argument("--schema", type=Path, required=True)
    validate_parser.set_defaults(handler=validate_record)
    return parser.parse_args()


def main() -> int:
    os.umask(0o077)
    args = parse_args()
    write_canonical(args.handler(args))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except AdmissionError as error:
        print(f"image-rollout-admission: {error}", file=sys.stderr)
        raise SystemExit(1) from None
