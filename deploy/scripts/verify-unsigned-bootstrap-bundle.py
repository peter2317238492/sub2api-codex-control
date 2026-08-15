#!/usr/bin/env python3
"""Independently verify one unsigned production bootstrap bundle offline."""

from __future__ import annotations

import argparse
import dataclasses
import datetime as dt
import hashlib
import json
import os
import re
import stat
import sys
import tarfile
from collections.abc import Sequence
from pathlib import Path, PurePosixPath
from typing import Any, BinaryIO, NoReturn

PLATFORM = "linux/amd64"
COMPONENTS = ("control-api", "pwa", "postgres-tools")
ARCHIVE_NAMES = {
    "control-api": "control-api-linux-amd64.tar",
    "pwa": "pwa-linux-amd64.tar",
    "postgres-tools": "postgres-tools-linux-amd64.tar",
}
IMAGE_TITLES = {
    "control-api": "Sub2API Codex Control API",
    "pwa": "Sub2API Codex Control PWA",
    "postgres-tools": "Sub2API Codex PostgreSQL Tools",
}
EXPECTED_USERS = {
    "control-api": {"10001", "10001:10001"},
    "pwa": {"nginx", "101", "101:101"},
    "postgres-tools": {"postgres"},
}
EXPECTED_POSTGRES_VERSIONS = [
    "pg_dump (PostgreSQL) 18.4",
    "pg_restore (PostgreSQL) 18.4",
]
POSTGRES_SERVER_IMAGE = (
    "postgres:18-alpine@sha256:"
    "9a8afca54e7861fd90fab5fdf4c42477a6b1cb7d293595148e674e0a3181de15"
)
SOURCE_VERIFIER_PATH = "deploy/scripts/verify-unsigned-bootstrap-bundle.py"
BUNDLE_VERIFIER_FILE = "verify-unsigned-bootstrap-bundle.py"

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
RELEASE_RE = re.compile(
    r"^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
    r"(?:-[0-9A-Za-z.-]+)?$"
)
CHECKSUM_LINE_RE = re.compile(r"^([0-9a-f]{64})  ([0-9A-Za-z][0-9A-Za-z._-]*)$")
SOURCE_MANIFEST_LINE_RE = re.compile(r"^(0444|0555) ([0-9]+) ([0-9a-f]{64})  (.+)$")
SOURCE_LIST_LINE_RE = re.compile(r"^(0444|0555) ([0-9]+)  (.+)$")
SOURCE_CHECKSUM_LINE_RE = re.compile(r"^([0-9a-f]{64})  (.+)$")
TAG_RE = re.compile(
    r"^(?:[a-z0-9]+(?:[._-][a-z0-9]+)*(?::[0-9]+)?/)"
    r"*(?:[a-z0-9]+(?:[._-][a-z0-9]+)*):"
    r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$"
)

MAX_JSON_BYTES = 16 * 1024 * 1024
MAX_TEXT_BYTES = 64 * 1024 * 1024
MAX_SOURCE_FILE_BYTES = 128 * 1024 * 1024
MAX_SOURCE_BYTES = 512 * 1024 * 1024
MAX_SOURCE_FILES = 100_000
MAX_BUNDLE_FILES = 256

OCI_INDEX_MEDIA_TYPE = "application/vnd.oci.image.index.v1+json"
MANIFEST_MEDIA_TYPES = {
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
}
CONFIG_MEDIA_TYPES = {
    "application/vnd.oci.image.config.v1+json",
    "application/vnd.docker.container.image.v1+json",
}
LAYER_MEDIA_TYPES = {
    "application/vnd.oci.image.layer.v1.tar",
    "application/vnd.oci.image.layer.v1.tar+gzip",
    "application/vnd.oci.image.layer.v1.tar+zstd",
    "application/vnd.oci.image.layer.nondistributable.v1.tar",
    "application/vnd.oci.image.layer.nondistributable.v1.tar+gzip",
    "application/vnd.oci.image.layer.nondistributable.v1.tar+zstd",
    "application/vnd.docker.image.rootfs.diff.tar.gzip",
    "application/vnd.docker.image.rootfs.foreign.diff.tar.gzip",
}
KNOWN_OCI_TOP_LEVEL_FILES = {
    "index.json",
    "manifest.json",
    "oci-layout",
    "repositories",
}
MAX_OCI_ARCHIVE_BYTES = 8 * 1024 * 1024 * 1024
MAX_OCI_EXPANDED_BYTES = 16 * 1024 * 1024 * 1024
MAX_OCI_MEMBERS = 65_536

# This is deliberately duplicated rather than imported from the builder. A change
# to the release mode policy must be reviewed in both producer and verifier.
EXECUTABLE_SOURCE_FILES = frozenset(
    {
        "connector/release/macos-sign-notarize.sh",
        "connector/release/release.py",
        "deploy/monitoring/verify-rules.sh",
        "deploy/release/control_images.py",
        "deploy/release/verify-control-images.sh",
        "deploy/scripts/backup-control-db.sh",
        "deploy/scripts/backup-production-state.py",
        "deploy/scripts/bootstrap-admission.py",
        "deploy/scripts/bootstrap-production-unsigned.sh",
        "deploy/scripts/bootstrap-unauthenticated-smoke.py",
        "deploy/scripts/build-unsigned-bootstrap-bundle.py",
        "deploy/scripts/control-api-entrypoint.sh",
        "deploy/scripts/deploy-production.sh",
        "deploy/scripts/deployment-admission.py",
        "deploy/scripts/generate-secrets.sh",
        "deploy/scripts/map-oci-image-archive.py",
        "deploy/scripts/pg-restore-via-container.sh",
        "deploy/scripts/probe-sub2api-auth-contract.py",
        "deploy/scripts/record-authenticated-smoke-closure.py",
        "deploy/scripts/provision-nginx-access-log.sh",
        "deploy/scripts/provision-postgres.sh",
        "deploy/scripts/provision-redis-acl.sh",
        "deploy/scripts/verify-sub2api-runtime.py",
        "deploy/scripts/verify-sub2api-runtime.sh",
        "deploy/scripts/verify-unsigned-bootstrap-bundle.py",
        "packages/appserver-schema/scripts/generate.sh",
        "tests/e2e/fake_codex.py",
        "tests/e2e/mock_sub2api.py",
        "tests/e2e/rehearse-backup-restore.sh",
        "tests/e2e/run-backup-restore.sh",
        "tests/e2e/run-local.sh",
        "tests/e2e/run_postgres_approval_guards.py",
        "tests/e2e/smoke.py",
        "tests/e2e/tree_manifest.py",
    }
)

SUB2API_AUTH_CONTRACT_PATH = "docs/contracts/sub2api-auth.v0.1.176.json"
NGINX_REQUIRED_SOURCE_FILES = frozenset(
    {
        "deploy/nginx/api-security-headers.conf",
        "deploy/nginx/browser-security-headers.conf",
        "deploy/nginx/codex-control-access.logrotate",
        "deploy/nginx/hide-upstream-security-headers.conf",
        "deploy/nginx/http-context.conf",
        "deploy/nginx/server-locations.conf",
        "deploy/nginx/sub2api-logout-location.conf",
    }
)
NGINX_PROVISIONER_HELPER_PATH = "deploy/scripts/provision-nginx-access-log.py"
NGINX_PROVISIONING_REQUIRED_SOURCE_FILES = NGINX_REQUIRED_SOURCE_FILES | frozenset(
    {NGINX_PROVISIONER_HELPER_PATH}
)
REQUIRED_SOURCE_FILES = NGINX_PROVISIONING_REQUIRED_SOURCE_FILES | frozenset(
    {
        ".gitignore",
        "deploy/dockerfiles/control-api.Dockerfile",
        "deploy/dockerfiles/postgres-tools.Dockerfile",
        "deploy/dockerfiles/pwa.Dockerfile",
        "deploy/scripts/map-oci-image-archive.py",
        "deploy/schemas/authenticated-smoke-closure.schema.json",
        SUB2API_AUTH_CONTRACT_PATH,
        "versions.lock.json",
    }
)

EXCLUDED_DIRECTORY_NAMES = frozenset(
    {
        ".cache",
        ".git",
        ".idea",
        ".mypy_cache",
        ".pnpm-store",
        ".pytest_cache",
        ".ruff_cache",
        ".venv",
        ".vscode",
        "__pycache__",
        "coverage",
        "dist",
        "htmlcov",
        "node_modules",
    }
)
EXCLUDED_EXACT_FILES = frozenset(
    {
        ".DS_Store",
        "apps/control-api/.coverage",
        "connector/connector",
        "connector/coverage.out",
    }
)
EXCLUDED_DIRECTORY_PREFIXES = (
    "connector/.connector-state/",
    "connector/bin/",
)
PRIVATE_CONTENT_PREFIXES = (
    "deploy/docker-compose/backups/",
    "deploy/docker-compose/secrets/",
    "tests/e2e/reports/",
)
PRIVATE_CONTENT_ALLOWLIST = frozenset({".gitignore", "README.md"})
EXCLUDED_FILE_SUFFIXES = (
    ".bak",
    ".backup",
    ".orig",
    ".pyc",
    ".pyo",
    ".rej",
    ".swp",
    ".tmp",
    ".tsbuildinfo",
    "~",
)
SENSITIVE_EXACT_NAMES = frozenset({".netrc", ".npmrc", ".pypirc"})
SENSITIVE_SSH_PRIVATE_KEY_RE = re.compile(
    r"^id_(?:dsa|ecdsa|ed25519|rsa)(?:[._-].*)?$", re.IGNORECASE
)
SENSITIVE_KEY_SUFFIXES = frozenset({".key", ".p12", ".pem", ".pfx"})
PRIVATE_CONFIG_SUFFIXES = frozenset(
    {
        "",
        ".cfg",
        ".conf",
        ".config",
        ".ini",
        ".json",
        ".properties",
        ".toml",
        ".yaml",
        ".yml",
    }
)
PRIVATE_CONFIG_WORDS = frozenset(
    {"credential", "credentials", "secret", "secrets", "token", "tokens"}
)
PUBLIC_TEMPLATE_WORDS = frozenset({"example", "public", "sample", "schema", "template"})
PUBLIC_PEM_LABELS = frozenset(
    {"CERTIFICATE", "CERTIFICATE REQUEST", "PUBLIC KEY", "RSA PUBLIC KEY", "X509 CRL"}
)
PEM_BLOCK_RE = re.compile(
    rb"-----BEGIN ([A-Z0-9 ]+)-----\r?\n.*?-----END \1-----", re.DOTALL
)


def exclusion_policy() -> dict[str, Any]:
    return {
        "directory_names": sorted(EXCLUDED_DIRECTORY_NAMES),
        "directory_prefixes": list(EXCLUDED_DIRECTORY_PREFIXES),
        "exact_files": sorted(EXCLUDED_EXACT_FILES),
        "file_suffixes": list(EXCLUDED_FILE_SUFFIXES),
        "executable_source_files": sorted(EXECUTABLE_SOURCE_FILES),
        "required_source_files": sorted(REQUIRED_SOURCE_FILES),
        "private_content_allowlist": sorted(PRIVATE_CONTENT_ALLOWLIST),
        "private_content_prefixes": list(PRIVATE_CONTENT_PREFIXES),
        "runtime_environment_rule": ".env and .env.* except .env.example",
        "sensitive_local_files": {
            "exact_names": sorted(SENSITIVE_EXACT_NAMES),
            "key_suffixes": sorted(SENSITIVE_KEY_SUFFIXES),
            "private_config_suffixes": sorted(PRIVATE_CONFIG_SUFFIXES),
            "private_config_words": sorted(PRIVATE_CONFIG_WORDS),
            "public_template_words": sorted(PUBLIC_TEMPLATE_WORDS),
            "rule": "fail closed during source scan; sensitive files are never excluded into silence",
        },
    }


def sensitive_source_reason(relative: str, content: bytes) -> str | None:
    name = PurePosixPath(relative).name
    while True:
        ignored_suffix = next(
            (
                suffix
                for suffix in EXCLUDED_FILE_SUFFIXES
                if name.lower().endswith(suffix) and len(name) > len(suffix)
            ),
            None,
        )
        if ignored_suffix is None:
            break
        name = name[: -len(ignored_suffix)]
    lowered = name.lower()
    if lowered == ".env" or (lowered.startswith(".env.") and lowered != ".env.example"):
        return "runtime-environment"
    if lowered in SENSITIVE_EXACT_NAMES:
        return "private-package-or-network-credentials"
    if SENSITIVE_SSH_PRIVATE_KEY_RE.fullmatch(name) and not lowered.endswith(".pub"):
        return "ssh-private-key-name"
    if re.search(
        rb"-----BEGIN (?:OPENSSH |[A-Z0-9 ]*PRIVATE )?PRIVATE KEY-----", content
    ):
        return "private-key-content"
    suffix = PurePosixPath(lowered).suffix
    if suffix in SENSITIVE_KEY_SUFFIXES:
        if suffix == ".pem":
            blocks = list(PEM_BLOCK_RE.finditer(content))
            outside = PEM_BLOCK_RE.sub(b"", content).strip()
            if (
                blocks
                and not outside
                and all(
                    match.group(1).decode("ascii") in PUBLIC_PEM_LABELS
                    for match in blocks
                )
            ):
                return None
        return "private-key-container-or-file"
    stem = lowered[: -len(suffix)] if suffix else lowered
    words = frozenset(filter(None, re.split(r"[._-]+", stem)))
    if (
        suffix in PRIVATE_CONFIG_SUFFIXES
        and words & PRIVATE_CONFIG_WORDS
        and not words & PUBLIC_TEMPLATE_WORDS
    ):
        return "credential-token-or-secret-config"
    return None


class VerificationError(RuntimeError):
    pass


def fail(message: str) -> NoReturn:
    raise VerificationError(message)


@dataclasses.dataclass(frozen=True)
class SourceRecord:
    path: str
    mode: int
    size: int
    sha256: str


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_stream(handle: BinaryIO) -> str:
    digest = hashlib.sha256()
    while chunk := handle.read(1024 * 1024):
        digest.update(chunk)
    return digest.hexdigest()


def sha256_file(path: Path) -> str:
    with path.open("rb") as handle:
        return sha256_stream(handle)


def validate_relative_path(relative: str) -> None:
    try:
        relative.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise VerificationError(f"path is not valid UTF-8: {relative!r}") from exc
    parts = PurePosixPath(relative).parts
    if (
        not relative
        or relative.startswith("/")
        or "\\" in relative
        or "\x00" in relative
        or "\n" in relative
        or "\r" in relative
        or any(part in {"", ".", ".."} for part in parts)
    ):
        fail(f"path is not canonical or line-safe: {relative!r}")


def stable_fields(value: os.stat_result) -> tuple[int, ...]:
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


def open_regular(
    path: Path, *, maximum: int | None = None
) -> tuple[BinaryIO, os.stat_result]:
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:
        fail("this platform cannot securely verify files without O_NOFOLLOW")
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | nofollow)
    except OSError as exc:
        raise VerificationError(f"cannot securely open {path}: {exc}") from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            fail(f"evidence must be one regular, singly-linked file: {path.name}")
        if metadata.st_uid != os.geteuid():
            fail(f"evidence is not owned by the verification user: {path.name}")
        if stat.S_IMODE(metadata.st_mode) != 0o600:
            fail(f"bundle evidence is not mode 0600: {path.name}")
        if maximum is not None and metadata.st_size > maximum:
            fail(f"evidence exceeds the accepted size: {path.name}")
        return os.fdopen(descriptor, "rb"), metadata
    except BaseException:
        os.close(descriptor)
        raise


def read_regular(path: Path, *, maximum: int) -> bytes:
    handle, before = open_regular(path, maximum=maximum)
    with handle:
        raw = handle.read(maximum + 1)
        if len(raw) != before.st_size or len(raw) > maximum or handle.read(1):
            fail(f"evidence size changed while reading: {path.name}")
        after = os.fstat(handle.fileno())
        if stable_fields(before) != stable_fields(after):
            fail(f"evidence changed while reading: {path.name}")
    return raw


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            fail(f"JSON object repeats key {key!r}")
        result[key] = value
    return result


def decode_json(raw: bytes, label: str) -> Any:
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=reject_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise VerificationError(f"cannot decode {label}: {exc}") from exc


def read_json(bundle: Path, name: str) -> Any:
    return decode_json(read_regular(bundle / name, maximum=MAX_JSON_BYTES), name)


def require_object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        fail(f"{label} must be an object")
    return value


def require_string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        fail(f"{label} must be a non-empty string")
    return value


def require_sha256(value: Any, label: str, *, prefixed: bool = False) -> str:
    if (
        not isinstance(value, str)
        or (DIGEST_RE.fullmatch(value) if prefixed else SHA256_RE.fullmatch(value))
        is None
    ):
        qualifier = "sha256: digest" if prefixed else "SHA-256"
        fail(f"{label} must be a lowercase {qualifier}")
    return value


def require_positive_int(value: Any, label: str, *, allow_zero: bool = False) -> int:
    minimum = 0 if allow_zero else 1
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        fail(f"{label} must be an integer >= {minimum}")
    return value


def require_true(value: Any, label: str) -> None:
    if value is not True and value != "verified":
        fail(f"{label} is not verified")


def parse_checksum_lines(raw: bytes, label: str) -> dict[str, str]:
    try:
        rendered = raw.decode("ascii", errors="strict")
    except UnicodeDecodeError as exc:
        raise VerificationError(f"{label} is not ASCII") from exc
    if not rendered.endswith("\n"):
        fail(f"{label} must end with one LF")
    result: dict[str, str] = {}
    for line in rendered.splitlines():
        match = CHECKSUM_LINE_RE.fullmatch(line)
        if match is None or match.group(2) in result:
            fail(f"{label} is malformed or repeats a filename")
        result[match.group(2)] = match.group(1)
    if not result:
        fail(f"{label} is empty")
    return result


def verify_trusted_bundle_directory(
    bundle: Path,
    *,
    expected_uid: int,
    expected_gid: int,
    trust_anchor: Path,
) -> None:
    nofollow = getattr(os, "O_NOFOLLOW", None)
    directory = getattr(os, "O_DIRECTORY", None)
    if nofollow is None or directory is None:
        fail("this platform cannot securely verify bundle directories")
    bundle = Path(os.path.abspath(bundle))
    trust_anchor = Path(os.path.abspath(trust_anchor))
    if bundle != trust_anchor and trust_anchor not in bundle.parents:
        fail("bundle must be below its trusted ancestor anchor")

    descriptors: list[int] = []
    try:
        current = trust_anchor
        descriptor = os.open(
            current,
            os.O_RDONLY | directory | nofollow | getattr(os, "O_CLOEXEC", 0),
        )
        descriptors.append(descriptor)
        metadata = os.fstat(descriptor)
        components = bundle.relative_to(trust_anchor).parts
        for component in components:
            if (
                not stat.S_ISDIR(metadata.st_mode)
                or metadata.st_uid != expected_uid
                or metadata.st_gid != expected_gid
                or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
            ):
                fail(
                    "bundle and every trusted ancestor must be real directories "
                    "owned by the verification identity and not group or world writable"
                )
            before = os.stat(component, dir_fd=descriptor, follow_symlinks=False)
            child = os.open(
                component,
                os.O_RDONLY | directory | nofollow | getattr(os, "O_CLOEXEC", 0),
                dir_fd=descriptor,
            )
            descriptors.append(child)
            opened = os.fstat(child)
            if stable_fields(before) != stable_fields(opened):
                fail(
                    f"trusted bundle directory changed while opening: {current / component}"
                )
            descriptor = child
            current /= component
            metadata = opened
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != expected_uid
            or metadata.st_gid != expected_gid
            or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        ):
            fail(
                "bundle and every trusted ancestor must be real directories owned by "
                "the verification identity and not group or world writable"
            )
        if stat.S_IMODE(metadata.st_mode) != 0o700:
            fail("bundle directory must be verification-user-owned mode 0700")
    except OSError as exc:
        raise VerificationError(
            f"cannot securely open trusted bundle path: {exc}"
        ) from exc
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def verify_bundle_closure(
    bundle: Path,
    *,
    expected_uid: int,
    expected_gid: int,
    trust_anchor: Path,
) -> dict[str, str]:
    verify_trusted_bundle_directory(
        bundle,
        expected_uid=expected_uid,
        expected_gid=expected_gid,
        trust_anchor=trust_anchor,
    )
    try:
        metadata = bundle.lstat()
    except FileNotFoundError as exc:
        raise VerificationError(f"bundle does not exist: {bundle}") from exc
    if bundle.is_symlink() or not stat.S_ISDIR(metadata.st_mode):
        fail("bundle must be one real directory")
    if (
        metadata.st_uid != expected_uid
        or metadata.st_gid != expected_gid
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        fail("bundle directory must be verification-user-owned mode 0700")
    entries = list(bundle.iterdir())
    if len(entries) > MAX_BUNDLE_FILES:
        fail("bundle file count exceeds the accepted limit")
    names: list[str] = []
    for path in entries:
        member = path.lstat()
        if path.is_symlink() or not stat.S_ISREG(member.st_mode):
            fail(f"bundle contains a non-regular entry: {path.name}")
        if (
            member.st_uid != expected_uid
            or member.st_gid != expected_gid
            or stat.S_IMODE(member.st_mode) != 0o600
        ):
            fail(f"bundle file is not verification-user-owned mode 0600: {path.name}")
        if CHECKSUM_LINE_RE.fullmatch(f"{'0' * 64}  {path.name}") is None:
            fail(f"bundle filename is not checksum-safe: {path.name!r}")
        names.append(path.name)
    if "SHA256SUMS" not in names:
        fail("bundle is missing SHA256SUMS")
    values = parse_checksum_lines(
        read_regular(bundle / "SHA256SUMS", maximum=MAX_TEXT_BYTES), "SHA256SUMS"
    )
    if "SHA256SUMS" in values:
        fail("SHA256SUMS contains a self-referential hash")
    expected_names = sorted(name for name in names if name != "SHA256SUMS")
    if sorted(values) != expected_names:
        fail("SHA256SUMS does not cover the exact bundle file inventory")
    for name, expected in values.items():
        handle, before = open_regular(bundle / name)
        with handle:
            observed = sha256_stream(handle)
            after = os.fstat(handle.fileno())
        if stable_fields(before) != stable_fields(after):
            fail(f"bundle evidence changed while hashing: {name}")
        if observed != expected:
            fail(f"bundle checksum mismatch: {name}")
    return values


def parse_source_manifest(raw: bytes) -> list[SourceRecord]:
    try:
        rendered = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise VerificationError("source-files.manifest is not UTF-8") from exc
    if not rendered.endswith("\n"):
        fail("source-files.manifest must end with one LF")
    records: list[SourceRecord] = []
    paths: set[str] = set()
    total = 0
    for line in rendered.splitlines():
        match = SOURCE_MANIFEST_LINE_RE.fullmatch(line)
        if match is None:
            fail("source-files.manifest has a malformed line")
        mode_text, size_text, digest, relative = match.groups()
        validate_relative_path(relative)
        if exclusion_reason(relative, is_directory=False) is not None:
            fail(
                f"source manifest includes a path excluded by release policy: {relative}"
            )
        if relative in paths:
            fail(f"source-files.manifest repeats a path: {relative}")
        size = int(size_text)
        if size > MAX_SOURCE_FILE_BYTES:
            fail(f"source manifest file exceeds its size limit: {relative}")
        total += size
        if total > MAX_SOURCE_BYTES:
            fail("source manifest exceeds its total size limit")
        mode = int(mode_text, 8)
        expected_mode = 0o555 if relative in EXECUTABLE_SOURCE_FILES else 0o444
        if mode != expected_mode:
            fail(f"source manifest mode violates the static allowlist: {relative}")
        records.append(SourceRecord(relative, mode, size, digest))
        paths.add(relative)
        if len(records) > MAX_SOURCE_FILES:
            fail("source manifest exceeds its file count limit")
    if not records:
        fail("source-files.manifest is empty")
    if records != sorted(records, key=lambda item: item.path.encode("utf-8")):
        fail("source-files.manifest is not sorted by UTF-8 path")
    missing = sorted(EXECUTABLE_SOURCE_FILES - paths)
    if missing:
        fail(f"source manifest is missing static executable inputs: {missing[:10]}")
    missing_required = sorted(REQUIRED_SOURCE_FILES - paths)
    if missing_required:
        fail(f"source manifest is missing required inputs: {missing_required[:10]}")
    if source_manifest_bytes(records) != raw:
        fail("source-files.manifest is not canonically encoded")
    return records


def source_manifest_bytes(records: Sequence[SourceRecord]) -> bytes:
    return "".join(
        f"{record.mode:04o} {record.size} {record.sha256}  {record.path}\n"
        for record in sorted(records, key=lambda item: item.path.encode("utf-8"))
    ).encode("utf-8")


def expected_source_list(records: Sequence[SourceRecord]) -> bytes:
    return "".join(
        f"{record.mode:04o} {record.size}  {record.path}\n" for record in records
    ).encode("utf-8")


def expected_source_checksums(records: Sequence[SourceRecord]) -> bytes:
    return "".join(f"{record.sha256}  {record.path}\n" for record in records).encode(
        "utf-8"
    )


def expected_archive_list(records: Sequence[SourceRecord]) -> bytes:
    return "".join(f"{record.path}\n" for record in records).encode("utf-8")


def verify_one_checksum_file(
    bundle: Path, name: str, expected_target: str, expected_digest: str
) -> None:
    values = parse_checksum_lines(read_regular(bundle / name, maximum=4096), name)
    if values != {expected_target: expected_digest}:
        fail(f"{name} does not bind exactly {expected_target}")


def expected_source_directories(records: Sequence[SourceRecord]) -> set[str]:
    return {
        parent.as_posix()
        for record in records
        for parent in PurePosixPath(record.path).parents
        if parent.as_posix() != "."
    }


def verify_source_archive(
    archive_path: Path, records: Sequence[SourceRecord], epoch: int
) -> None:
    gzip_header = read_regular(
        archive_path, maximum=MAX_SOURCE_BYTES + 64 * 1024 * 1024
    )[:10]
    if len(gzip_header) != 10 or gzip_header[:3] != b"\x1f\x8b\x08":
        fail("source.tar.gz does not have a canonical gzip header")
    if int.from_bytes(gzip_header[4:8], "little") != epoch or gzip_header[3] != 0:
        fail("source.tar.gz gzip header has non-canonical metadata")

    expected_files = {record.path: record for record in records}
    directories = expected_source_directories(records)
    expected_order = [
        *sorted(directories, key=lambda value: value.encode("utf-8")),
        *(record.path for record in records),
    ]
    observed_order: list[str] = []
    observed_files: set[str] = set()
    observed_directories: set[str] = set()
    with tarfile.open(archive_path, mode="r:gz") as archive:
        for member in archive:
            validate_relative_path(member.name)
            observed_order.append(member.name)
            if (
                member.uid != 0
                or member.gid != 0
                or member.uname != "root"
                or member.gname != "root"
                or member.mtime != epoch
            ):
                fail(f"source archive member metadata is not canonical: {member.name}")
            if member.isdir():
                if (
                    member.name not in directories
                    or member.name in observed_directories
                    or member.mode != 0o555
                    or member.size != 0
                ):
                    fail(f"source archive has an invalid directory: {member.name}")
                observed_directories.add(member.name)
                continue
            if (
                not member.isfile()
                or member.name not in expected_files
                or member.name in observed_files
            ):
                fail(
                    f"source archive has an unexpected or repeated file: {member.name}"
                )
            record = expected_files[member.name]
            if member.mode != record.mode or member.size != record.size:
                fail(
                    f"source archive mode or size differs from manifest: {member.name}"
                )
            extracted = archive.extractfile(member)
            if extracted is None:
                fail(f"cannot read source archive member: {member.name}")
            with extracted:
                content = extracted.read(record.size + 1)
            if len(content) != record.size:
                fail(f"source archive file size changed while reading: {member.name}")
            if sensitive_source_reason(member.name, content) is not None:
                fail(f"source archive contains sensitive local material: {member.name}")
            if sha256_bytes(content) != record.sha256:
                fail(f"source archive content differs from manifest: {member.name}")
            observed_files.add(member.name)
    if observed_order != expected_order:
        fail("source archive inventory or ordering differs from the canonical manifest")
    if observed_files != set(expected_files) or observed_directories != directories:
        fail("source archive does not contain the exact source inventory")


def exclusion_reason(relative: str, *, is_directory: bool) -> str | None:
    parts = PurePosixPath(relative).parts
    if any(part in EXCLUDED_DIRECTORY_NAMES for part in parts):
        return "excluded-directory-name"
    if is_directory:
        candidate = relative.rstrip("/") + "/"
        if any(candidate.startswith(prefix) for prefix in EXCLUDED_DIRECTORY_PREFIXES):
            return "excluded-directory-prefix"
        return None
    if relative in EXCLUDED_EXACT_FILES:
        return "excluded-exact-file"
    if any(relative.startswith(prefix) for prefix in EXCLUDED_DIRECTORY_PREFIXES):
        return "excluded-directory-prefix"
    for prefix in PRIVATE_CONTENT_PREFIXES:
        if relative.startswith(prefix):
            remainder = relative[len(prefix) :]
            if remainder not in PRIVATE_CONTENT_ALLOWLIST:
                return "private-runtime-content"
    name = parts[-1]
    if name.startswith("._"):
        return "apple-double"
    if name == ".env" or (name.startswith(".env.") and name != ".env.example"):
        return "runtime-environment"
    if name.endswith(EXCLUDED_FILE_SUFFIXES):
        return "backup-or-temporary-file"
    return None


def scan_source_root(
    root: Path,
    *,
    expected_uid: int = 0,
    expected_gid: int = 0,
    trust_anchor: Path = Path("/"),
) -> tuple[dict[str, tuple[int, int, str]], set[str]]:
    root = Path(os.path.abspath(root))
    trust_anchor = Path(os.path.abspath(trust_anchor))
    if root != trust_anchor and trust_anchor not in root.parents:
        fail("source root must be below its trusted ancestor anchor")
    for ancestor in (root, *root.parents):
        metadata = ancestor.lstat()
        if (
            stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != expected_uid
            or metadata.st_gid != expected_gid
            or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        ):
            fail(
                "source root and every trusted ancestor must be real directories "
                "owned by the expected identity and not group or world writable"
            )
        descriptor = os.open(
            ancestor,
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
        )
        try:
            opened = os.fstat(descriptor)
            if stable_fields(metadata) != stable_fields(opened):
                fail(f"trusted source ancestor changed while opening: {ancestor}")
        finally:
            os.close(descriptor)
        if ancestor == trust_anchor:
            break
    else:
        fail("source trust anchor was not reached")

    metadata = root.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        fail("source root must be one real directory")
    if stat.S_IMODE(metadata.st_mode) != 0o555:
        fail("source root directory must have normalized mode 0555")
    if metadata.st_uid != expected_uid or metadata.st_gid != expected_gid:
        fail("source root directory must be owned by the expected identity")
    observed: dict[str, tuple[int, int, str]] = {}
    directories: set[str] = set()

    def walk(directory: Path) -> None:
        for entry in sorted(
            os.scandir(directory), key=lambda item: item.name.encode("utf-8")
        ):
            path = Path(entry.path)
            relative = path.relative_to(root).as_posix()
            validate_relative_path(relative)
            value = entry.stat(follow_symlinks=False)
            is_directory = stat.S_ISDIR(value.st_mode)
            if stat.S_ISLNK(value.st_mode):
                fail(f"source root contains an unexcluded symbolic link: {relative}")
            if is_directory:
                if value.st_uid != expected_uid or value.st_gid != expected_gid:
                    fail(
                        "source root directory is not owned by the expected "
                        f"identity: {relative}"
                    )
                if stat.S_IMODE(value.st_mode) != 0o555:
                    fail(
                        f"source root directory is not normalized mode 0555: {relative}"
                    )
                directories.add(relative)
                walk(path)
                continue
            if not stat.S_ISREG(value.st_mode) or value.st_nlink != 1:
                fail(f"source root contains an unsupported entry: {relative}")
            if value.st_uid != expected_uid or value.st_gid != expected_gid:
                fail(
                    f"source root file is not owned by the expected identity: {relative}"
                )
            expected_mode = 0o555 if relative in EXECUTABLE_SOURCE_FILES else 0o444
            mode = stat.S_IMODE(value.st_mode)
            if mode != expected_mode:
                fail(
                    f"source root file mode is not normalized: {relative}: "
                    f"expected {expected_mode:04o}"
                )
            content = path.read_bytes()
            if len(content) != value.st_size:
                fail(f"source root file size changed while reading: {relative}")
            if sensitive_source_reason(relative, content) is not None:
                fail(f"source root contains sensitive local material: {relative}")
            observed[relative] = (mode, value.st_size, sha256_bytes(content))

    walk(root)
    return observed, directories


def verify_source_root(
    root: Path,
    records: Sequence[SourceRecord],
    *,
    expected_uid: int = 0,
    expected_gid: int = 0,
    trust_anchor: Path = Path("/"),
) -> None:
    observed, directories = scan_source_root(
        root,
        expected_uid=expected_uid,
        expected_gid=expected_gid,
        trust_anchor=trust_anchor,
    )
    expected = {
        record.path: (record.mode, record.size, record.sha256) for record in records
    }
    if observed != expected:
        added = sorted(set(observed) - set(expected))
        removed = sorted(set(expected) - set(observed))
        changed = sorted(
            path
            for path in set(expected) & set(observed)
            if expected[path] != observed[path]
        )
        fail(
            "source root differs from bundle manifest; "
            f"added={added[:10]}, removed={removed[:10]}, changed={changed[:10]}"
        )
    if directories != expected_source_directories(records):
        added = sorted(directories - expected_source_directories(records))
        removed = sorted(expected_source_directories(records) - directories)
        fail(
            "source root directory inventory differs from the manifest; "
            f"added={added[:10]}, removed={removed[:10]}"
        )


def require_exact_or_optional_keys(
    value: dict[str, Any], required: set[str], optional: set[str], label: str
) -> None:
    missing = sorted(required - set(value))
    extra = sorted(set(value) - required - optional)
    if missing or extra:
        fail(f"{label} keys mismatch; missing={missing}, extra={extra}")


def require_string_mapping(value: Any, label: str) -> dict[str, str]:
    if not isinstance(value, dict):
        fail(f"{label} must be an object")
    result: dict[str, str] = {}
    for key, item in value.items():
        if not isinstance(key, str) or not key or not isinstance(item, str):
            fail(f"{label} must contain only string values")
        result[key] = item
    return result


def normalize_oci_member(member: tarfile.TarInfo) -> str:
    name = member.name.rstrip("/")
    if not name:
        fail("OCI archive contains an empty member name")
    validate_relative_path(name)
    if str(PurePosixPath(*PurePosixPath(name).parts)) != name:
        fail(f"OCI archive member name is not canonical: {member.name!r}")
    return name


def inventory_oci_archive(archive: tarfile.TarFile) -> dict[str, tarfile.TarInfo]:
    inventory: dict[str, tarfile.TarInfo] = {}
    expanded = 0
    for count, member in enumerate(archive, start=1):
        if count > MAX_OCI_MEMBERS:
            fail("OCI archive member count exceeds the accepted limit")
        name = normalize_oci_member(member)
        if name in inventory:
            fail(f"OCI archive repeats member: {name}")
        if member.isdir():
            if name not in {"blobs", "blobs/sha256"}:
                fail(f"OCI archive contains unexpected directory: {name}")
        elif member.isfile():
            if (
                name not in KNOWN_OCI_TOP_LEVEL_FILES
                and re.fullmatch(r"blobs/sha256/[0-9a-f]{64}", name) is None
            ):
                fail(f"OCI archive contains unexpected file: {name}")
            if member.size < 0 or member.size > MAX_OCI_ARCHIVE_BYTES:
                fail(f"OCI archive member size is outside the accepted range: {name}")
            expanded += member.size
            if expanded > MAX_OCI_EXPANDED_BYTES:
                fail("OCI archive expanded size exceeds the accepted limit")
        else:
            fail(f"OCI archive member is neither regular nor directory: {name}")
        inventory[name] = member
    for required in ("index.json", "manifest.json", "oci-layout"):
        member = inventory.get(required)
        if member is None or not member.isfile():
            fail(f"OCI archive is missing regular file {required}")
    return inventory


def read_tar_member(
    archive: tarfile.TarFile, member: tarfile.TarInfo, label: str, maximum: int
) -> bytes:
    if member.size > maximum:
        fail(f"{label} exceeds the accepted size")
    extracted = archive.extractfile(member)
    if extracted is None:
        fail(f"cannot read {label}")
    with extracted:
        raw = extracted.read(maximum + 1)
        if len(raw) != member.size or len(raw) > maximum or extracted.read(1):
            fail(f"{label} size differs from its tar header")
    return raw


def verify_oci_blobs(
    archive: tarfile.TarFile, inventory: dict[str, tarfile.TarInfo]
) -> dict[str, tarfile.TarInfo]:
    blobs: dict[str, tarfile.TarInfo] = {}
    for name, member in sorted(inventory.items()):
        match = re.fullmatch(r"blobs/sha256/([0-9a-f]{64})", name)
        if match is None:
            continue
        extracted = archive.extractfile(member)
        if extracted is None:
            fail(f"cannot read OCI blob: {name}")
        with extracted:
            observed = sha256_stream(extracted)
        if observed != match.group(1):
            fail(f"OCI blob content differs from its sha256 filename: {name}")
        blobs[f"sha256:{match.group(1)}"] = member
    if not blobs:
        fail("OCI archive contains no sha256 blobs")
    return blobs


def require_descriptor(
    value: Any, label: str, media_types: set[str], *, allow_platform: bool = False
) -> dict[str, Any]:
    item = require_object(value, label)
    optional = {"annotations", "urls"}
    if allow_platform:
        optional.add("platform")
    require_exact_or_optional_keys(
        item, {"mediaType", "digest", "size"}, optional, label
    )
    if item.get("mediaType") not in media_types:
        fail(f"{label} has an unsupported media type")
    require_sha256(item.get("digest"), f"{label}.digest", prefixed=True)
    require_positive_int(item.get("size"), f"{label}.size", allow_zero=True)
    if "annotations" in item:
        require_string_mapping(item["annotations"], f"{label}.annotations")
    urls = item.get("urls")
    if urls is not None and (
        not isinstance(urls, list)
        or any(not isinstance(item, str) or not item for item in urls)
    ):
        fail(f"{label}.urls must be a non-empty string array")
    return item


def require_blob(
    blobs: dict[str, tarfile.TarInfo], descriptor: dict[str, Any], label: str
) -> tarfile.TarInfo:
    member = blobs.get(descriptor["digest"])
    if member is None:
        fail(f"OCI archive is missing {label} blob")
    if member.size != descriptor["size"]:
        fail(f"{label} descriptor size differs from its blob")
    return member


def canonical_docker_tag(tag: str) -> str:
    if "/" not in tag:
        return f"docker.io/library/{tag}"
    first = tag.split("/", 1)[0]
    if "." in first or ":" in first or first == "localhost":
        return tag
    return f"docker.io/{tag}"


def validate_oci_index_tag(descriptor: dict[str, Any], expected_tag: str) -> None:
    annotations = require_string_mapping(
        descriptor.get("annotations"), "OCI index manifest annotations"
    )
    if annotations.get("org.opencontainers.image.ref.name") not in {
        expected_tag,
        expected_tag.rsplit(":", 1)[1],
    }:
        fail("OCI index tag annotation differs from the artifact tag")
    containerd_name = annotations.get("io.containerd.image.name")
    if containerd_name is not None and containerd_name != canonical_docker_tag(
        expected_tag
    ):
        fail("OCI index containerd image name differs from the artifact tag")


def validate_descriptor_platform(value: Any) -> None:
    if value is None:
        return
    platform = require_object(value, "OCI descriptor platform")
    require_exact_or_optional_keys(
        platform,
        {"os", "architecture"},
        {"variant", "os.version", "os.features", "features"},
        "OCI descriptor platform",
    )
    if platform != {"os": "linux", "architecture": "amd64"}:
        fail("OCI descriptor platform differs from linux/amd64")


def verify_legacy_manifest(
    raw: bytes, expected_tag: str, config_digest: str, layers: list[str]
) -> None:
    value = decode_json(raw, "OCI manifest.json")
    if not isinstance(value, list) or len(value) != 1:
        fail("OCI manifest.json must describe exactly one image")
    item = require_object(value[0], "OCI manifest.json image")
    require_exact_or_optional_keys(
        item,
        {"Config", "RepoTags", "Layers"},
        {"LayerSources"},
        "OCI manifest.json image",
    )
    if (
        item.get("Config") != f"blobs/sha256/{config_digest.removeprefix('sha256:')}"
        or item.get("RepoTags") != [expected_tag]
        or item.get("Layers")
        != [f"blobs/sha256/{value.removeprefix('sha256:')}" for value in layers]
    ):
        fail("OCI manifest.json differs from the selected image identity")


def verify_oci_archive(
    archive_path: Path,
    *,
    expected_archive_sha: str,
    expected_size: int,
    expected_tag: str,
    expected_labels: dict[str, Any],
    expected_users: set[str],
) -> dict[str, Any]:
    handle, before = open_regular(archive_path)
    if before.st_size != expected_size or before.st_size > MAX_OCI_ARCHIVE_BYTES:
        handle.close()
        fail("OCI archive size differs from the artifact identity")
    try:
        archive_sha = sha256_stream(handle)
        if archive_sha != expected_archive_sha:
            fail("OCI archive hash differs from the artifact identity")
        handle.seek(0)
        with tarfile.open(fileobj=handle, mode="r:*") as archive:
            inventory = inventory_oci_archive(archive)
            blobs = verify_oci_blobs(archive, inventory)
            layout = require_object(
                decode_json(
                    read_tar_member(
                        archive, inventory["oci-layout"], "OCI layout", MAX_JSON_BYTES
                    ),
                    "OCI layout",
                ),
                "OCI layout",
            )
            if layout != {"imageLayoutVersion": "1.0.0"}:
                fail("OCI layout version is unsupported")
            index_raw = read_tar_member(
                archive, inventory["index.json"], "OCI index", MAX_JSON_BYTES
            )
            index = require_object(decode_json(index_raw, "OCI index"), "OCI index")
            require_exact_or_optional_keys(
                index,
                {"schemaVersion", "mediaType", "manifests"},
                {"annotations"},
                "OCI index",
            )
            manifests = index.get("manifests")
            if (
                index.get("schemaVersion") != 2
                or index.get("mediaType") != OCI_INDEX_MEDIA_TYPE
                or not isinstance(manifests, list)
                or len(manifests) != 1
            ):
                fail("OCI index must select exactly one v1 image manifest")
            manifest_descriptor = require_descriptor(
                manifests[0],
                "OCI manifest descriptor",
                MANIFEST_MEDIA_TYPES,
                allow_platform=True,
            )
            validate_oci_index_tag(manifest_descriptor, expected_tag)
            validate_descriptor_platform(manifest_descriptor.get("platform"))
            manifest_raw = read_tar_member(
                archive,
                require_blob(blobs, manifest_descriptor, "manifest"),
                "OCI manifest",
                MAX_JSON_BYTES,
            )
            manifest = require_object(
                decode_json(manifest_raw, "OCI manifest"), "OCI manifest"
            )
            require_exact_or_optional_keys(
                manifest,
                {"schemaVersion", "mediaType", "config", "layers"},
                {"annotations"},
                "OCI manifest",
            )
            if (
                manifest.get("schemaVersion") != 2
                or manifest.get("mediaType") != manifest_descriptor["mediaType"]
            ):
                fail("OCI manifest media identity differs from its descriptor")
            config_descriptor = require_descriptor(
                manifest.get("config"), "OCI config descriptor", CONFIG_MEDIA_TYPES
            )
            config = require_object(
                decode_json(
                    read_tar_member(
                        archive,
                        require_blob(blobs, config_descriptor, "config"),
                        "OCI config",
                        MAX_JSON_BYTES,
                    ),
                    "OCI config",
                ),
                "OCI config",
            )
            if config.get("os") != "linux" or config.get("architecture") != "amd64":
                fail("OCI config platform is not exactly linux/amd64")
            runtime_config = require_object(config.get("config"), "OCI runtime config")
            labels = require_string_mapping(runtime_config.get("Labels"), "OCI labels")
            if labels != expected_labels:
                fail("OCI config labels differ from the artifact identity")
            if runtime_config.get("User") not in expected_users:
                fail("OCI configured user differs from the component runtime policy")
            layer_values = manifest.get("layers")
            if not isinstance(layer_values, list) or not layer_values:
                fail("OCI manifest must contain at least one layer")
            layer_digests: list[str] = []
            for index_value, layer_value in enumerate(layer_values):
                descriptor = require_descriptor(
                    layer_value, f"OCI layer {index_value}", LAYER_MEDIA_TYPES
                )
                require_blob(blobs, descriptor, f"layer {index_value}")
                layer_digests.append(descriptor["digest"])
            verify_legacy_manifest(
                read_tar_member(
                    archive,
                    inventory["manifest.json"],
                    "OCI manifest.json",
                    MAX_JSON_BYTES,
                ),
                expected_tag,
                config_descriptor["digest"],
                layer_digests,
            )
        handle.seek(0)
        if sha256_stream(handle) != archive_sha:
            fail("OCI archive changed while being verified")
        after = os.fstat(handle.fileno())
        if stable_fields(before) != stable_fields(after):
            fail("OCI archive metadata changed while being verified")
    finally:
        handle.close()
    return {
        "archive": {"sha256": archive_sha, "size": before.st_size},
        "image": {
            "config_digest": config_descriptor["digest"],
            "index_sha256": f"sha256:{sha256_bytes(index_raw)}",
            "labels": labels,
            "layer_digests": layer_digests,
            "manifest_digest": manifest_descriptor["digest"],
            "platform": PLATFORM,
            "tag": expected_tag,
            "verified_blob_count": len(blobs),
        },
    }


def exact_file_hash(
    bundle: Path, descriptor: Any, label: str, expected_name: str
) -> tuple[str, dict[str, Any]]:
    value = require_object(descriptor, label)
    require_exact_or_optional_keys(value, {"file", "result", "sha256"}, set(), label)
    name = require_string(value.get("file"), f"{label}.file")
    if name != expected_name:
        fail(f"{label}.file is not {expected_name}")
    expected = require_sha256(value.get("sha256"), f"{label}.sha256")
    if sha256_file(bundle / name) != expected:
        fail(f"{label} evidence hash mismatch")
    result = require_object(value.get("result"), f"{label}.result")
    parsed = require_object(read_json(bundle, name), name)
    if parsed != result:
        fail(f"{label}.result differs from its evidence file")
    return name, result


def verify_image_evidence(
    bundle: Path,
    manifest: dict[str, Any],
    release: str,
    revision: str,
) -> None:
    images = require_object(manifest.get("images"), "images")
    if set(images) != set(COMPONENTS):
        fail("artifact manifest must describe exactly the three bootstrap images")
    image_ids: set[str] = set()
    for component in COMPONENTS:
        image = require_object(images[component], f"images.{component}")
        common_keys = {
            "archive",
            "archive_sha256",
            "archive_size",
            "build_log",
            "build_log_sha256",
            "build_metadata",
            "build_metadata_sha256",
            "config_digest",
            "daemon_image_id",
            "daemon_image_id_kind",
            "index_sha256",
            "manifest_digest",
            "mapper_manifest",
            "mapper_manifest_sha256",
            "oci_labels",
            "platform",
            "tag",
        }
        component_keys = {
            "pwa": {"runtime_verification"},
            "postgres-tools": {"client_versions", "dump_restore_verification"},
            "control-api": set(),
        }[component]
        require_exact_or_optional_keys(
            image, common_keys | component_keys, set(), f"images.{component}"
        )
        archive_name = ARCHIVE_NAMES[component]
        if image.get("archive") != archive_name:
            fail(f"{component} archive filename is invalid")
        archive_digest = require_sha256(
            image.get("archive_sha256"), f"images.{component}.archive_sha256"
        )
        archive_size = require_positive_int(
            image.get("archive_size"), f"images.{component}.archive_size"
        )
        archive_path = bundle / archive_name
        if (
            archive_path.stat().st_size != archive_size
            or sha256_file(archive_path) != archive_digest
        ):
            fail(f"{component} archive identity differs from the artifact manifest")
        if image.get("platform") != PLATFORM:
            fail(f"{component} platform is not exactly {PLATFORM}")
        tag = require_string(image.get("tag"), f"images.{component}.tag")
        if TAG_RE.fullmatch(tag) is None:
            fail(f"{component} tag is not a concrete Docker repository:tag")
        image_id = require_sha256(
            image.get("daemon_image_id"),
            f"images.{component}.daemon_image_id",
            prefixed=True,
        )
        image_ids.add(image_id)
        config_digest = require_sha256(
            image.get("config_digest"),
            f"images.{component}.config_digest",
            prefixed=True,
        )
        manifest_digest = require_sha256(
            image.get("manifest_digest"),
            f"images.{component}.manifest_digest",
            prefixed=True,
        )
        require_sha256(
            image.get("index_sha256"), f"images.{component}.index_sha256", prefixed=True
        )
        kind = image.get("daemon_image_id_kind")
        expected_id = config_digest if kind == "config-digest" else manifest_digest
        if kind not in {"config-digest", "manifest-digest"} or image_id != expected_id:
            fail(f"{component} daemon image ID is not bound to its portable digest")
        labels = require_object(
            image.get("oci_labels"), f"images.{component}.oci_labels"
        )
        expected_labels = {
            "org.opencontainers.image.revision": revision,
            "org.opencontainers.image.title": IMAGE_TITLES[component],
            "org.opencontainers.image.version": release,
        }
        for key, value in expected_labels.items():
            if labels.get(key) != value:
                fail(f"{component} OCI label mismatch: {key}")
        require_string(
            labels.get("org.opencontainers.image.source"), f"{component} source label"
        )

        independently_mapped = verify_oci_archive(
            archive_path,
            expected_archive_sha=archive_digest,
            expected_size=archive_size,
            expected_tag=tag,
            expected_labels=labels,
            expected_users=EXPECTED_USERS[component],
        )
        if independently_mapped["image"].get("config_digest") != config_digest:
            fail(f"{component} independently parsed config digest differs")
        if independently_mapped["image"].get("manifest_digest") != manifest_digest:
            fail(f"{component} independently parsed manifest digest differs")
        if independently_mapped["image"].get("index_sha256") != image.get(
            "index_sha256"
        ):
            fail(f"{component} independently parsed index digest differs")

        map_name = require_string(
            image.get("mapper_manifest"), f"images.{component}.mapper_manifest"
        )
        if map_name != f"{component}-archive-map.json":
            fail(f"{component} mapper evidence filename is invalid")
        map_sha = require_sha256(
            image.get("mapper_manifest_sha256"),
            f"images.{component}.mapper_manifest_sha256",
        )
        if sha256_file(bundle / map_name) != map_sha:
            fail(f"{component} mapper evidence hash mismatch")
        mapped = require_object(read_json(bundle, map_name), map_name)
        require_exact_or_optional_keys(
            mapped,
            {"archive", "daemon", "format_version", "image", "status"},
            set(),
            map_name,
        )
        mapped_archive = require_object(mapped.get("archive"), f"{map_name}.archive")
        mapped_image = require_object(mapped.get("image"), f"{map_name}.image")
        daemon = require_object(mapped.get("daemon"), f"{map_name}.daemon")
        require_exact_or_optional_keys(
            daemon, {"id", "id_kind", "repo_tags"}, set(), f"{map_name}.daemon"
        )
        repo_tags = daemon.get("repo_tags")
        if (
            mapped.get("format_version") != 1
            or mapped.get("status") != "verified"
            or mapped_archive != independently_mapped["archive"]
            or mapped_image != independently_mapped["image"]
            or daemon.get("id") != image_id
            or daemon.get("id_kind") != kind
            or not isinstance(repo_tags, list)
            or tag not in repo_tags
            or len(repo_tags) != len(set(repo_tags))
            or any(not isinstance(item, str) for item in repo_tags)
        ):
            fail(f"{component} mapper evidence differs from the artifact identity")

        inspect_name = f"{component}-image-inspect.json"
        inspected = read_json(bundle, inspect_name)
        if not isinstance(inspected, list) or len(inspected) != 1:
            fail(f"{inspect_name} must contain exactly one image")
        inspection = require_object(inspected[0], f"{inspect_name}[0]")
        config = require_object(inspection.get("Config"), f"{inspect_name}.Config")
        inspect_repo_tags = inspection.get("RepoTags")
        configured_user = config.get("User")
        if (
            not isinstance(inspect_repo_tags, list)
            or any(not isinstance(item, str) for item in inspect_repo_tags)
            or len(inspect_repo_tags) != len(set(inspect_repo_tags))
            or not isinstance(configured_user, str)
        ):
            fail(f"{component} Docker inspect evidence has invalid field types")
        if (
            inspection.get("Id") != image_id
            or inspection.get("Os") != "linux"
            or inspection.get("Architecture") != "amd64"
            or sorted(inspect_repo_tags) != sorted(repo_tags)
            or config.get("Labels") != labels
            or configured_user not in EXPECTED_USERS[component]
        ):
            fail(f"{component} Docker inspect evidence differs from its image identity")

        metadata_name = require_string(
            image.get("build_metadata"), f"images.{component}.build_metadata"
        )
        if metadata_name != f"{component}-build-metadata.json":
            fail(f"{component} build metadata filename is invalid")
        metadata_sha = require_sha256(
            image.get("build_metadata_sha256"),
            f"images.{component}.build_metadata_sha256",
        )
        if sha256_file(bundle / metadata_name) != metadata_sha:
            fail(f"{component} build metadata hash mismatch")
        build = require_object(read_json(bundle, metadata_name), metadata_name)
        require_exact_or_optional_keys(
            build,
            {
                "archive_exporter",
                "build_args",
                "builder",
                "daemon_image_id",
                "daemon_image_id_kind",
                "docker_versions",
                "format_version",
                "platform_identity",
                "release",
                "revision",
                "tag",
            },
            set(),
            metadata_name,
        )
        build_args = require_object(
            build.get("build_args"), f"{metadata_name}.build_args"
        )
        expected_build_args = {
            "CONTROL_RELEASE": release,
            "SOURCE_DATE_EPOCH": str(parse_generated_epoch(manifest)),
            "VCS_REF": revision,
        }
        if component == "pwa":
            expected_build_args["VITE_CONTROL_CSRF_COOKIE_NAME"] = "codex_csrf"
        docker_versions = require_object(
            build.get("docker_versions"), f"{metadata_name}.docker_versions"
        )
        require_exact_or_optional_keys(
            docker_versions,
            {"buildx", "client", "server"},
            set(),
            f"{metadata_name}.docker_versions",
        )
        if any(
            not isinstance(docker_versions[name], str) or not docker_versions[name]
            for name in docker_versions
        ):
            fail(f"{component} Docker version evidence is incomplete")
        platform_identity = require_object(
            build.get("platform_identity"), f"{metadata_name}.platform_identity"
        )
        if (
            build.get("archive_exporter") != "docker"
            or build.get("builder") != "docker buildx"
            or build.get("format_version") != 2
            or build_args != expected_build_args
            or build.get("release") != release
            or build.get("revision") != revision
            or build.get("tag") != tag
            or build.get("daemon_image_id") != image_id
            or build.get("daemon_image_id_kind") != kind
            or platform_identity.get("requested") != PLATFORM
            or platform_identity.get("archive_mapper") != PLATFORM
            or platform_identity.get("daemon_inspect") != PLATFORM
            or platform_identity.get("build_host_platform_is_not_image_evidence")
            is not True
        ):
            fail(f"{component} build metadata differs from its admitted identity")
        build_log = require_string(
            image.get("build_log"), f"images.{component}.build_log"
        )
        if build_log != f"{component}-build.log":
            fail(f"{component} build log filename is invalid")
        build_log_sha = require_sha256(
            image.get("build_log_sha256"), f"images.{component}.build_log_sha256"
        )
        if sha256_file(bundle / build_log) != build_log_sha:
            fail(f"{component} build log hash mismatch")

    if len(image_ids) != len(COMPONENTS):
        fail("the three admitted daemon image IDs are not distinct")


def verify_postgres_roundtrip(
    value: dict[str, Any], tools_image_id: str, tools_image_tag: str
) -> None:
    require_exact_or_optional_keys(
        value,
        {
            "format_version",
            "status",
            "server",
            "tools",
            "dump",
            "fixture",
            "isolation",
            "cleanup",
        },
        set(),
        "PostgreSQL roundtrip evidence",
    )
    if value.get("format_version") != 1 or value.get("status") != "verified":
        fail("PostgreSQL dump/restore evidence header is invalid")
    server = require_object(value.get("server"), "PG server")
    require_exact_or_optional_keys(
        server,
        {"dockerfile_base_image_material", "image_id", "image_tag", "version"},
        set(),
        "PG server",
    )
    base_material = require_string(
        server.get("dockerfile_base_image_material"), "PG Dockerfile base image"
    )
    if (
        base_material != POSTGRES_SERVER_IMAGE
        or server.get("version") != "18.4"
        or server.get("image_id") != tools_image_id
        or server.get("image_tag") != tools_image_tag
    ):
        fail("PostgreSQL roundtrip server identity is not the admitted pinned image")

    tools = require_object(value.get("tools"), "PG tools")
    require_exact_or_optional_keys(
        tools, {"image_id", "image_tag", "client_versions"}, set(), "PG tools"
    )
    if (
        tools.get("image_id") != tools_image_id
        or tools.get("image_tag") != tools_image_tag
        or tools.get("client_versions") != EXPECTED_POSTGRES_VERSIONS
    ):
        fail("PostgreSQL roundtrip tools identity or versions differ")
    dump = require_object(value.get("dump"), "PG dump")
    require_exact_or_optional_keys(
        dump,
        {"format", "list_entry_count", "list_sha256", "sha256", "size"},
        set(),
        "PG dump",
    )
    if dump.get("format") != "custom":
        fail("PostgreSQL roundtrip dump format is not custom")
    require_sha256(dump.get("list_sha256"), "PG dump list SHA-256")
    require_sha256(dump.get("sha256"), "PG dump SHA-256")
    require_positive_int(dump.get("size"), "PG dump size")
    require_positive_int(dump.get("list_entry_count"), "PG dump list entry count")

    fixture = require_object(value.get("fixture"), "PG fixture")
    require_exact_or_optional_keys(
        fixture,
        {
            "restored",
            "schema",
            "sequence",
            "source",
            "source_and_restored_rows_equal",
            "source_and_restored_schema_equal",
            "table",
        },
        set(),
        "PG fixture",
    )
    for name in ("schema", "sequence", "table"):
        require_string(fixture.get(name), f"PG fixture {name}")
    require_true(fixture.get("source_and_restored_rows_equal"), "PG row equality")
    require_true(fixture.get("source_and_restored_schema_equal"), "PG schema equality")
    source = require_object(fixture.get("source"), "PG fixture source")
    restored = require_object(fixture.get("restored"), "PG fixture restored")
    identity_keys = {
        "canonical_rows_sha256",
        "row_count",
        "schema_sha256",
        "sequence_last_value",
    }
    require_exact_or_optional_keys(source, identity_keys, set(), "PG fixture source")
    require_exact_or_optional_keys(
        restored, identity_keys, set(), "PG fixture restored"
    )
    if source != restored:
        fail("PostgreSQL source and restored fixture identities differ")
    require_sha256(source.get("canonical_rows_sha256"), "PG canonical rows")
    require_sha256(source.get("schema_sha256"), "PG schema")
    require_positive_int(source.get("row_count"), "PG fixture row count")
    require_positive_int(source.get("sequence_last_value"), "PG sequence value")

    isolation = require_object(value.get("isolation"), "PG isolation")
    require_exact_or_optional_keys(
        isolation,
        {
            "docker_internal_network",
            "password_authentication_used",
            "persistent_volume_used",
            "server_pgdata",
        },
        set(),
        "PG isolation",
    )
    if (
        isolation.get("docker_internal_network") is not True
        or isolation.get("password_authentication_used") is not False
        or isolation.get("persistent_volume_used") is not False
        or isolation.get("server_pgdata") != "tmpfs"
    ):
        fail("PostgreSQL roundtrip isolation boundary is invalid")

    cleanup = require_object(value.get("cleanup"), "PG cleanup")
    require_exact_or_optional_keys(
        cleanup,
        {"containers_removed", "network_removed", "persistent_volume_created"},
        set(),
        "PG cleanup",
    )
    if (
        cleanup.get("containers_removed") is not True
        or cleanup.get("network_removed") is not True
        or cleanup.get("persistent_volume_created") is not False
    ):
        fail("PostgreSQL roundtrip cleanup evidence is invalid")


def verify_runtime_evidence(bundle: Path, manifest: dict[str, Any]) -> None:
    images = require_object(manifest["images"], "images")
    pwa = require_object(images["pwa"], "images.pwa")
    _, runtime = exact_file_hash(
        bundle,
        pwa.get("runtime_verification"),
        "PWA runtime verification",
        "pwa-runtime-verification.json",
    )
    require_exact_or_optional_keys(
        runtime,
        {
            "cleanup",
            "configured_user",
            "format_version",
            "host_health",
            "image_id",
            "image_tag",
            "network",
            "nginx_config",
            "port_mapping",
            "runtime",
            "runtime_uid",
            "status",
        },
        set(),
        "PWA runtime evidence",
    )
    nginx_config = require_object(runtime.get("nginx_config"), "PWA nginx_config")
    require_exact_or_optional_keys(
        nginx_config,
        {"mode", "path", "readable_by_runtime_user"},
        set(),
        "PWA nginx_config",
    )
    cleanup = require_object(runtime.get("cleanup"), "PWA cleanup")
    require_exact_or_optional_keys(
        cleanup,
        {"containers_removed", "network_removed"},
        set(),
        "PWA cleanup",
    )
    host_health = require_object(runtime.get("host_health"), "PWA host_health")
    require_exact_or_optional_keys(
        host_health,
        {"body", "path", "status_code"},
        set(),
        "PWA host_health",
    )
    network = require_object(runtime.get("network"), "PWA network")
    require_exact_or_optional_keys(
        network,
        {
            "attachable",
            "container_id",
            "driver",
            "enable_ipv6",
            "id",
            "inspect_topology_exact",
            "internal",
            "name",
            "options",
            "sole_member",
        },
        set(),
        "PWA network",
    )
    options = require_string_mapping(network.get("options"), "PWA network options")
    port_mapping = require_object(runtime.get("port_mapping"), "PWA port_mapping")
    require_exact_or_optional_keys(
        port_mapping,
        {
            "container_port",
            "host_ip",
            "host_port",
            "inherited_unpublished_ports",
            "inspect_mapping_exact",
            "protocol",
        },
        set(),
        "PWA port_mapping",
    )
    runtime_status = require_object(runtime.get("runtime"), "PWA runtime")
    require_exact_or_optional_keys(
        runtime_status,
        {
            "container_id",
            "docker_health_status",
            "healthz_body",
            "process_started_from_image_entrypoint",
        },
        set(),
        "PWA runtime status",
    )
    container_id = network.get("container_id")
    if (
        runtime.get("configured_user") != "nginx"
        or runtime.get("format_version") != 3
        or runtime.get("status") != "verified"
        or runtime.get("runtime_uid") != 101
        or runtime.get("image_id") != pwa.get("daemon_image_id")
        or runtime.get("image_tag") != pwa.get("tag")
        or nginx_config.get("path") != "/etc/nginx/nginx.conf"
        or nginx_config.get("mode") != "444"
        or nginx_config.get("readable_by_runtime_user") is not True
        or cleanup.get("containers_removed") is not True
        or cleanup.get("network_removed") is not True
        or host_health.get("body") != "ok"
        or host_health.get("path") != "/healthz"
        or host_health.get("status_code") != 200
        or not isinstance(container_id, str)
        or SHA256_RE.fullmatch(container_id) is None
        or network.get("sole_member") is not True
        or network.get("attachable") is not False
        or network.get("driver") != "bridge"
        or network.get("enable_ipv6") is not False
        or not isinstance(network.get("id"), str)
        or SHA256_RE.fullmatch(network["id"]) is None
        or network.get("inspect_topology_exact") is not True
        or network.get("internal") is not False
        or not isinstance(network.get("name"), str)
        or re.fullmatch(r"sub2api-bundle-pwa-net-[0-9]+-[0-9a-f]{8}", network["name"])
        is None
        or options
        != {
            "com.docker.network.bridge.enable_icc": "false",
            "com.docker.network.bridge.enable_ip_masquerade": "false",
        }
        or port_mapping.get("container_port") != 8080
        or port_mapping.get("host_ip") != "127.0.0.1"
        or isinstance(port_mapping.get("host_port"), bool)
        or not isinstance(port_mapping.get("host_port"), int)
        or not 1 <= port_mapping["host_port"] <= 65535
        or port_mapping.get("inherited_unpublished_ports") != ["80/tcp"]
        or port_mapping.get("inspect_mapping_exact") is not True
        or port_mapping.get("protocol") != "tcp"
        or runtime_status.get("container_id") != container_id
        or runtime_status.get("docker_health_status") != "healthy"
        or runtime_status.get("healthz_body") != "ok"
        or runtime_status.get("process_started_from_image_entrypoint") is not True
    ):
        fail("PWA runtime evidence does not satisfy the admitted gate")

    postgres = require_object(images["postgres-tools"], "images.postgres-tools")
    if postgres.get("client_versions") != EXPECTED_POSTGRES_VERSIONS:
        fail("PostgreSQL tools client versions are not exactly 18.4")
    version_raw = read_regular(bundle / "postgres-tools-version.txt", maximum=4096)
    expected_raw = "".join(f"{line}\n" for line in EXPECTED_POSTGRES_VERSIONS).encode(
        "ascii"
    )
    if version_raw != expected_raw:
        fail("postgres-tools-version.txt is not exactly PostgreSQL 18.4")
    _, roundtrip = exact_file_hash(
        bundle,
        postgres.get("dump_restore_verification"),
        "PostgreSQL dump/restore verification",
        "postgres-tools-dump-restore-verification.json",
    )
    verify_postgres_roundtrip(roundtrip, postgres["daemon_image_id"], postgres["tag"])


def verify_offline_verifier_binding(
    bundle: Path, manifest: dict[str, Any], records: Sequence[SourceRecord]
) -> None:
    descriptor = require_object(manifest.get("offline_verifier"), "offline_verifier")
    require_exact_or_optional_keys(
        descriptor, {"file", "mode", "sha256"}, set(), "offline_verifier"
    )
    bundled_digest = require_sha256(descriptor.get("sha256"), "offline_verifier.sha256")
    if (
        descriptor.get("file") != BUNDLE_VERIFIER_FILE
        or descriptor.get("mode") != "0600"
        or sha256_file(bundle / BUNDLE_VERIFIER_FILE) != bundled_digest
    ):
        fail("offline verifier bundle binding is invalid")
    source_record = next(
        (record for record in records if record.path == SOURCE_VERIFIER_PATH), None
    )
    if (
        source_record is None
        or source_record.mode != 0o555
        or source_record.sha256 != bundled_digest
        or source_record.size != (bundle / BUNDLE_VERIFIER_FILE).stat().st_size
    ):
        fail("offline verifier differs from the canonical source identity")
    executing_digest = sha256_file(Path(__file__).resolve())
    if executing_digest != bundled_digest:
        fail("the executing verifier differs from the verifier admitted by the bundle")


def verify_manifest_binding(
    bundle: Path,
    manifest: dict[str, Any],
    records: Sequence[SourceRecord],
    revision: str,
) -> None:
    if (
        manifest.get("artifact_kind") != "unsigned-production-bootstrap-images"
        or manifest.get("format_version") != 5
        or manifest.get("schema_version") != 1
        or manifest.get("status") != "ready"
        or manifest.get("trust_mode") != "unsigned-first-deployment-v1"
        or manifest.get("vcs_ref") != revision
    ):
        fail("artifact manifest header or VCS_REF is invalid")
    release = require_string(manifest.get("release"), "release")
    if RELEASE_RE.fullmatch(release) is None:
        fail("artifact release is not an exact semantic version")
    require_exact_or_optional_keys(
        manifest,
        {
            "artifact_kind",
            "build",
            "format_version",
            "generated_at",
            "images",
            "offline_verifier",
            "release",
            "schema_version",
            "source",
            "status",
            "transport",
            "trust_mode",
            "vcs_ref",
            "verification",
        },
        set(),
        "artifact manifest",
    )
    source = require_object(manifest.get("source"), "source")
    require_exact_or_optional_keys(
        source,
        {
            "archive",
            "canonical_hash_manifest",
            "canonical_hash_manifest_format",
            "enumeration",
            "explicit_exclusions",
            "file_count",
            "file_list",
            "normalized_modes",
            "sha256sum_compatible_content_manifest",
        },
        set(),
        "source",
    )
    canonical = require_object(
        source.get("canonical_hash_manifest"), "source canonical manifest"
    )
    require_exact_or_optional_keys(
        canonical,
        {"file", "is_vcs_ref", "sha256"},
        set(),
        "source canonical manifest",
    )
    if (
        canonical.get("file") != "source-files.manifest"
        or canonical.get("is_vcs_ref") is not True
        or canonical.get("sha256") != revision
        or source.get("file_count") != len(records)
    ):
        fail("artifact source identity binding is invalid")
    if (
        source.get("canonical_hash_manifest_format")
        != "normalized-mode-space-size-space-sha256-two-spaces-relative-path-lf-sorted-by-utf8-path"
        or source.get("enumeration")
        != "complete filesystem traversal with explicit exclusions"
        or source.get("explicit_exclusions") != exclusion_policy()
        or source.get("normalized_modes")
        != {
            "directories": "0555",
            "executable_allowlist": "0555",
            "other_regular_files": "0444",
        }
    ):
        fail("artifact source enumeration or mode policy differs from the verifier")
    file_list = require_object(source.get("file_list"), "source file_list")
    require_exact_or_optional_keys(
        file_list, {"file", "format", "sha256"}, set(), "source file_list"
    )
    checksums = require_object(
        source.get("sha256sum_compatible_content_manifest"), "source content manifest"
    )
    require_exact_or_optional_keys(
        checksums, {"file", "sha256"}, set(), "source content manifest"
    )
    if (
        file_list.get("file") != "source-files.list"
        or file_list.get("format")
        != "normalized-mode-space-size-two-spaces-relative-path"
        or file_list.get("sha256") != sha256_file(bundle / "source-files.list")
        or checksums.get("file") != "source-files.sha256"
        or checksums.get("sha256") != sha256_file(bundle / "source-files.sha256")
    ):
        fail("artifact source list/checksum binding is invalid")
    archive = require_object(source.get("archive"), "source archive")
    require_exact_or_optional_keys(
        archive,
        {"apple_double_free", "file", "sha256", "size"},
        set(),
        "source archive",
    )
    if (
        archive.get("apple_double_free") is not True
        or archive.get("file") != "source.tar.gz"
        or archive.get("sha256") != sha256_file(bundle / "source.tar.gz")
        or archive.get("size") != (bundle / "source.tar.gz").stat().st_size
    ):
        fail("artifact source archive binding is invalid")
    build = require_object(manifest.get("build"), "build")
    require_exact_or_optional_keys(
        build,
        {
            "archive_exporter",
            "normalized_source_context",
            "platform",
            "platform_evidence",
        },
        set(),
        "build",
    )
    normalized_context = require_object(
        build.get("normalized_source_context"), "build.normalized_source_context"
    )
    if (
        build.get("archive_exporter") != "docker"
        or build.get("platform") != PLATFORM
        or build.get("platform_evidence") != "OCI mapper plus daemon image inspect"
        or normalized_context
        != {
            "content_hashes_verified_after_normalization": True,
            "directory_mode": "0555",
            "regular_file_mode": "0444",
        }
    ):
        fail("artifact build platform is not exactly linux/amd64")
    verification = require_object(manifest.get("verification"), "verification")
    required_true = {
        "bundle_checksum_closure_excludes_only_SHA256SUMS_itself",
        "image_archives_are_docker_loadable",
        "image_archives_map_verified_twice_with_pinned_manifest_and_config_digests",
        "image_ids_platform_tags_and_labels_match",
        "normalized_context_content_matches_source_manifest",
        "postgres_dump_restore_18_4",
        "pwa_non_root_nginx_config_readable_and_runtime_healthy",
        "source_archive_matches_file_list",
        "source_extraction_matches_canonical_hash_manifest",
        "source_tree_unchanged_before_atomic_publish",
    }
    if any(verification.get(name) is not True for name in required_true):
        fail("artifact manifest does not assert every required verification gate")
    if set(verification) != required_true:
        fail("artifact manifest verification gates differ from the supported schema")
    verify_offline_verifier_binding(bundle, manifest, records)
    verify_image_evidence(bundle, manifest, release, revision)
    verify_runtime_evidence(bundle, manifest)


def verify_transport_checksums(bundle: Path, manifest: dict[str, Any]) -> None:
    images_expected = {
        ARCHIVE_NAMES[name]: sha256_file(bundle / ARCHIVE_NAMES[name])
        for name in COMPONENTS
    }
    image_values = parse_checksum_lines(
        read_regular(bundle / "bootstrap-images.sha256", maximum=4096),
        "bootstrap-images.sha256",
    )
    if image_values != images_expected:
        fail("bootstrap-images.sha256 does not bind exactly the three image archives")
    transport_expected = {
        "source.tar.gz": sha256_file(bundle / "source.tar.gz"),
        **images_expected,
    }
    transport_values = parse_checksum_lines(
        read_regular(bundle / "transport-SHA256SUMS", maximum=4096),
        "transport-SHA256SUMS",
    )
    if transport_values != transport_expected:
        fail("transport-SHA256SUMS does not bind source plus three image archives")
    transport = require_object(manifest.get("transport"), "transport")
    require_exact_or_optional_keys(
        transport,
        {
            "apple_double_free",
            "checksum_file",
            "checksum_file_sha256",
            "docker_load_verified",
            "image_checksum_file",
            "image_checksum_file_sha256",
        },
        set(),
        "transport",
    )
    if (
        transport.get("apple_double_free") is not True
        or transport.get("docker_load_verified") is not True
        or transport.get("checksum_file") != "transport-SHA256SUMS"
        or transport.get("checksum_file_sha256")
        != sha256_file(bundle / "transport-SHA256SUMS")
        or transport.get("image_checksum_file") != "bootstrap-images.sha256"
        or transport.get("image_checksum_file_sha256")
        != sha256_file(bundle / "bootstrap-images.sha256")
    ):
        fail("artifact transport checksum binding is invalid")


def parse_generated_epoch(manifest: dict[str, Any]) -> int:
    generated = require_string(manifest.get("generated_at"), "generated_at")
    if not generated.endswith("Z"):
        fail("generated_at must be UTC with a Z suffix")
    try:
        value = dt.datetime.fromisoformat(generated.replace("Z", "+00:00"))
    except ValueError as exc:
        raise VerificationError(f"generated_at is invalid: {exc}") from exc
    if value.tzinfo != dt.UTC or value.microsecond != 0:
        fail("generated_at must be whole-second UTC")
    return int(value.timestamp())


def verify_bundle(
    bundle: Path,
    source_root: Path | None = None,
    *,
    expected_bundle_uid: int | None = None,
    expected_bundle_gid: int | None = None,
    bundle_trust_anchor: Path = Path("/"),
    expected_source_uid: int = 0,
    expected_source_gid: int = 0,
    source_trust_anchor: Path = Path("/"),
) -> dict[str, Any]:
    try:
        bundle = Path(os.path.abspath(bundle))
        if expected_bundle_uid is None:
            expected_bundle_uid = os.geteuid()
        if expected_bundle_gid is None:
            expected_bundle_gid = os.getegid()
        closure = verify_bundle_closure(
            bundle,
            expected_uid=expected_bundle_uid,
            expected_gid=expected_bundle_gid,
            trust_anchor=bundle_trust_anchor,
        )
        identity_raw = read_regular(
            bundle / "source-files.manifest", maximum=MAX_TEXT_BYTES
        )
        records = parse_source_manifest(identity_raw)
        revision = sha256_bytes(identity_raw)
        verify_one_checksum_file(
            bundle,
            "source-files.manifest.sha256",
            "source-files.manifest",
            revision,
        )
        source_list = read_regular(bundle / "source-files.list", maximum=MAX_TEXT_BYTES)
        source_checksums = read_regular(
            bundle / "source-files.sha256", maximum=MAX_TEXT_BYTES
        )
        archive_list = read_regular(
            bundle / "source-archive.list", maximum=MAX_TEXT_BYTES
        )
        if source_list != expected_source_list(records):
            fail("source-files.list differs from the canonical source manifest")
        if source_checksums != expected_source_checksums(records):
            fail("source-files.sha256 differs from the canonical source manifest")
        if archive_list != expected_archive_list(records):
            fail("source-archive.list differs from the canonical source manifest")
        verify_one_checksum_file(
            bundle,
            "source-files.sha256.sha256",
            "source-files.sha256",
            sha256_bytes(source_checksums),
        )
        source_tar_sha = sha256_file(bundle / "source.tar.gz")
        verify_one_checksum_file(
            bundle, "source.tar.gz.sha256", "source.tar.gz", source_tar_sha
        )

        manifest = require_object(
            read_json(bundle, "artifact-manifest.json"), "artifact manifest"
        )
        compatibility = require_object(
            read_json(bundle, "artifacts-manifest.json"), "artifacts manifest"
        )
        if compatibility != manifest:
            fail("artifact-manifest.json and artifacts-manifest.json differ")
        verify_one_checksum_file(
            bundle,
            "artifact-manifest.sha256",
            "artifact-manifest.json",
            sha256_file(bundle / "artifact-manifest.json"),
        )
        verify_one_checksum_file(
            bundle,
            "artifacts-manifest.sha256",
            "artifacts-manifest.json",
            sha256_file(bundle / "artifacts-manifest.json"),
        )
        epoch = parse_generated_epoch(manifest)
        verify_source_archive(bundle / "source.tar.gz", records, epoch)
        expected_log = "".join(f"{record.path}: OK\n" for record in records).encode(
            "utf-8"
        )
        if (
            read_regular(
                bundle / "source-extraction-verify.log", maximum=MAX_TEXT_BYTES
            )
            != expected_log
        ):
            fail("source extraction verification log differs from the manifest")
        verify_manifest_binding(bundle, manifest, records, revision)
        verify_transport_checksums(bundle, manifest)
        if source_root is not None:
            verify_source_root(
                source_root,
                records,
                expected_uid=expected_source_uid,
                expected_gid=expected_source_gid,
                trust_anchor=source_trust_anchor,
            )
        admitted = source_root is not None
        return {
            "admission": admitted,
            "bundle": str(bundle),
            "bundle_file_count": len(closure) + 1,
            "release": manifest["release"],
            "source_file_count": len(records),
            "source_root_verified": source_root is not None,
            "status": "verified" if admitted else "archive-verified-non-admission",
            "vcs_ref": revision,
        }
    except VerificationError:
        raise
    except (
        KeyError,
        OSError,
        tarfile.TarError,
        TypeError,
        UnicodeError,
        ValueError,
    ) as exc:
        raise VerificationError(f"malformed bundle: {exc}") from exc


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Independently verify an unsigned bootstrap bundle offline."
    )
    commands = parser.add_subparsers(dest="command", required=True)
    archive = commands.add_parser(
        "verify-archive",
        help="verify the bundle and source archive before extraction (not admission)",
    )
    archive.add_argument("--bundle", type=Path, required=True)
    archive.add_argument("--bundle-trust-anchor", type=Path, default=Path("/"))
    verify = commands.add_parser("verify")
    verify.add_argument("--bundle", type=Path, required=True)
    verify.add_argument("--bundle-trust-anchor", type=Path, default=Path("/"))
    verify.add_argument(
        "--source-root",
        type=Path,
        required=True,
        help="normalized extracted source root (directories 0555; files 0444/0555)",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    try:
        args = build_parser().parse_args(argv)
        if args.command == "verify-archive":
            result = verify_bundle(
                args.bundle,
                bundle_trust_anchor=args.bundle_trust_anchor,
            )
        elif args.command == "verify":
            result = verify_bundle(
                args.bundle,
                args.source_root,
                bundle_trust_anchor=args.bundle_trust_anchor,
            )
        else:
            fail("unsupported command")
    except (OSError, tarfile.TarError, VerificationError) as exc:
        print(f"verify-unsigned-bootstrap-bundle: {exc}", file=sys.stderr)
        return 1
    sys.stdout.write(json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
