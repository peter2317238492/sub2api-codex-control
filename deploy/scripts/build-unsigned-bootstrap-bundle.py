#!/usr/bin/env python3
"""Build one private, source-bound unsigned production bootstrap bundle."""

from __future__ import annotations

import argparse
import dataclasses
import datetime as dt
import gzip
import hashlib
import http.client
import json
import os
import re
import secrets
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
from collections.abc import Callable, Iterable, Sequence
from pathlib import Path, PurePosixPath
from typing import Any, NoReturn

PLATFORM = "linux/amd64"
POSTGRES_SERVER_IMAGE = (
    "postgres:18-alpine@sha256:"
    "9a8afca54e7861fd90fab5fdf4c42477a6b1cb7d293595148e674e0a3181de15"
)
IMAGE_SOURCE_DEFAULT = "sub2api-codex-control"
COMPONENTS = ("control-api", "pwa", "postgres-tools")
RELEASE_RE = re.compile(
    r"^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
    r"(?:-[0-9A-Za-z.-]+)?$"
)
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
IMAGE_ID_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
SOURCE_MANIFEST_LINE_RE = re.compile(r"^(0444|0555) ([0-9]+) ([0-9a-f]{64})  (.+)$")
SAFE_BUNDLE_ID_RE = re.compile(r"^[0-9]{8}T[0-9]{6}Z$")
SAFE_IMAGE_SOURCE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/:@+-]*$")
MAX_SOURCE_FILE_BYTES = 128 * 1024 * 1024
MAX_SOURCE_BYTES = 512 * 1024 * 1024
MAX_SOURCE_FILES = 100_000
MAX_COMMAND_OUTPUT_BYTES = 16 * 1024 * 1024
BUILD_TIMEOUT_SECONDS = 3600
COMMAND_TIMEOUT_SECONDS = 120

# These are the complete local-only exclusions. Everything else under repo_root
# is source and therefore contributes to the 64-hex VCS_REF.
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

# Modes in the source identity are normalized deliberately. This allowlist is
# static so a stray executable bit in the working tree cannot become executable
# in production. It contains release/build tools and every shipped production
# entrypoint or helper that is intended to be invoked directly.
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

SUB2API_AUTH_CONTRACT_PATH = "docs/contracts/sub2api-auth.v0.2.0.json"
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

IMAGE_TITLES = {
    "control-api": "Sub2API Codex Control API",
    "pwa": "Sub2API Codex Control PWA",
    "postgres-tools": "Sub2API Codex PostgreSQL Tools",
}
DOCKERFILES = {
    "control-api": "deploy/dockerfiles/control-api.Dockerfile",
    "pwa": "deploy/dockerfiles/pwa.Dockerfile",
    "postgres-tools": "deploy/dockerfiles/postgres-tools.Dockerfile",
}
IMAGE_REPOSITORIES = {
    "control-api": "sub2api-codex-control-api",
    "pwa": "sub2api-codex-control-pwa",
    "postgres-tools": "sub2api-codex-postgres-tools",
}
ARCHIVE_NAMES = {
    "control-api": "control-api-linux-amd64.tar",
    "pwa": "pwa-linux-amd64.tar",
    "postgres-tools": "postgres-tools-linux-amd64.tar",
}
EXPECTED_USERS = {
    "control-api": {"10001:10001", "10001"},
    "pwa": {"nginx", "101", "101:101"},
    "postgres-tools": {"postgres"},
}


class BundleError(RuntimeError):
    pass


def fail(message: str) -> NoReturn:
    raise BundleError(message)


@dataclasses.dataclass(frozen=True)
class SourceRecord:
    path: str
    size: int
    mode: int
    uid: int
    gid: int
    sha256: str

    def identity(self) -> tuple[str, int, int, str]:
        return (self.path, self.size, self.normalized_mode, self.sha256)

    @property
    def normalized_mode(self) -> int:
        return 0o555 if self.path in EXECUTABLE_SOURCE_FILES else 0o444


@dataclasses.dataclass(frozen=True)
class CommandResult:
    stdout: bytes
    stderr: bytes
    returncode: int = 0


@dataclasses.dataclass(frozen=True)
class OwnedPath:
    path: Path
    device: int
    inode: int
    is_directory: bool


@dataclasses.dataclass(frozen=True)
class BundleReservation:
    ownership: OwnedPath
    token: str


@dataclasses.dataclass(frozen=True)
class OwnedImageTag:
    tag: str
    expected_image_id: str


def canonical_json(value: Any, *, pretty: bool = False) -> bytes:
    if pretty:
        rendered = json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True)
    else:
        rendered = json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        )
    return (rendered + "\n").encode("ascii")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def make_tree_deletable(root: Path) -> None:
    """Restore directory write bits after the normalized 0555 build context."""
    directories = [root]
    directories.extend(
        path for path in root.rglob("*") if path.is_dir() and not path.is_symlink()
    )
    for directory in sorted(
        directories, key=lambda path: len(path.parts), reverse=True
    ):
        os.chmod(directory, 0o700)


def write_private(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
        0o600,
    )
    try:
        offset = 0
        while offset < len(content):
            written = os.write(descriptor, content[offset:])
            if written <= 0:
                fail(f"short write while creating {path}")
            offset += written
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def require_private_directory(path: Path, *, create: bool) -> None:
    if create and not path.exists():
        path.mkdir(parents=True, mode=0o700)
    try:
        metadata = path.lstat()
    except FileNotFoundError as exc:
        raise BundleError(f"private directory does not exist: {path}") from exc
    if not stat.S_ISDIR(metadata.st_mode) or path.is_symlink():
        fail(f"private path is not a real directory: {path}")
    if metadata.st_uid != os.geteuid():
        fail(f"private directory is not owned by the current user: {path}")
    if stat.S_IMODE(metadata.st_mode) & 0o077:
        fail(f"private directory must have mode 0700 or stricter: {path}")


def stable_file_bytes(path: Path) -> tuple[bytes, os.stat_result]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise BundleError(
            f"cannot open source file without following links: {path}"
        ) from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            fail(f"source entry is not a regular file: {path}")
        if before.st_nlink != 1:
            fail(f"source file must have exactly one filesystem link: {path}")
        if before.st_size > MAX_SOURCE_FILE_BYTES:
            fail(f"source file exceeds the 128 MiB limit: {path}")
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                fail(f"source file became shorter while reading: {path}")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            fail(f"source file became longer while reading: {path}")
        after = os.fstat(descriptor)
        stable_before = (
            before.st_dev,
            before.st_ino,
            before.st_mode,
            before.st_uid,
            before.st_gid,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        stable_after = (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_uid,
            after.st_gid,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        if stable_before != stable_after:
            fail(f"source file changed while reading: {path}")
        return b"".join(chunks), before
    finally:
        os.close(descriptor)


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
    if name.endswith(EXCLUDED_FILE_SUFFIXES):
        return "backup-or-temporary-file"
    return None


def sensitive_source_reason(relative: str, content: bytes) -> str | None:
    """Reject likely local credentials without treating ordinary source as secret."""
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


def validate_relative_path(relative: str) -> None:
    try:
        relative.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise BundleError(f"source path is not valid UTF-8: {relative!r}") from exc
    if (
        not relative
        or relative.startswith("/")
        or "\\" in relative
        or "\x00" in relative
        or "\n" in relative
        or "\r" in relative
        or any(part in {"", ".", ".."} for part in PurePosixPath(relative).parts)
    ):
        fail(f"source path is not canonical or line-safe: {relative!r}")


def scan_source(root: Path) -> list[SourceRecord]:
    root = Path(os.path.abspath(root))
    try:
        root_metadata = root.lstat()
    except FileNotFoundError as exc:
        raise BundleError(f"repository root does not exist: {root}") from exc
    if not stat.S_ISDIR(root_metadata.st_mode) or root.is_symlink():
        fail(f"repository root is not a real directory: {root}")

    records: list[SourceRecord] = []
    total_bytes = 0

    def walk(directory: Path) -> None:
        nonlocal total_bytes
        try:
            entries = sorted(
                os.scandir(directory), key=lambda item: item.name.encode("utf-8")
            )
        except OSError as exc:
            raise BundleError(
                f"cannot enumerate source directory {directory}: {exc}"
            ) from exc
        for entry in entries:
            path = Path(entry.path)
            relative = path.relative_to(root).as_posix()
            validate_relative_path(relative)
            try:
                metadata = entry.stat(follow_symlinks=False)
            except OSError as exc:
                raise BundleError(
                    f"cannot inspect source entry {relative}: {exc}"
                ) from exc
            is_directory = stat.S_ISDIR(metadata.st_mode)
            content: bytes | None = None
            stable: os.stat_result | None = None
            if not is_directory and sensitive_source_reason(relative, b"") is not None:
                if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
                    fail(
                        "source tree contains a sensitive path with an unsupported "
                        f"file type: {relative}"
                    )
                content, stable = stable_file_bytes(path)
                sensitive_reason = sensitive_source_reason(relative, content)
                if sensitive_reason is not None:
                    fail(
                        "source tree contains a sensitive local file "
                        f"({sensitive_reason}): {relative}"
                    )
            excluded = exclusion_reason(relative, is_directory=is_directory)
            if excluded == "private-runtime-content":
                fail(f"source tree contains private runtime content: {relative}")
            if excluded == "backup-or-temporary-file" and not is_directory:
                if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
                    fail(
                        "source tree contains an excluded backup path with an "
                        f"unsupported file type: {relative}"
                    )
                if content is None or stable is None:
                    content, stable = stable_file_bytes(path)
                sensitive_reason = sensitive_source_reason(relative, content)
                if sensitive_reason is not None:
                    fail(
                        "source tree contains a sensitive local file "
                        f"({sensitive_reason}): {relative}"
                    )
            if excluded is not None:
                continue
            if stat.S_ISLNK(metadata.st_mode):
                fail(f"source tree contains an unexcluded symbolic link: {relative}")
            if is_directory:
                walk(path)
                continue
            if not stat.S_ISREG(metadata.st_mode):
                fail(f"source tree contains an unsupported special file: {relative}")
            if content is None or stable is None:
                content, stable = stable_file_bytes(path)
            sensitive_reason = sensitive_source_reason(relative, content)
            if sensitive_reason is not None:
                fail(
                    "source tree contains a sensitive local file "
                    f"({sensitive_reason}): {relative}"
                )
            total_bytes += len(content)
            if total_bytes > MAX_SOURCE_BYTES:
                fail("source tree exceeds the 512 MiB limit")
            records.append(
                SourceRecord(
                    path=relative,
                    size=len(content),
                    mode=stat.S_IMODE(stable.st_mode),
                    uid=stable.st_uid,
                    gid=stable.st_gid,
                    sha256=sha256_bytes(content),
                )
            )
            if len(records) > MAX_SOURCE_FILES:
                fail("source file count exceeds the accepted limit")

    walk(root)
    records.sort(key=lambda record: record.path.encode("utf-8"))
    if not records:
        fail("source tree is empty after explicit exclusions")
    missing = sorted(REQUIRED_SOURCE_FILES - {record.path for record in records})
    if missing:
        fail(f"source tree is missing required release inputs: {missing}")
    missing_executables = sorted(
        EXECUTABLE_SOURCE_FILES - {record.path for record in records}
    )
    if missing_executables:
        fail(f"source tree is missing executable release inputs: {missing_executables}")
    return records


def source_list_bytes(records: Sequence[SourceRecord]) -> bytes:
    return "".join(
        f"{record.normalized_mode:04o} {record.size}  {record.path}\n"
        for record in sorted(records, key=lambda item: item.path.encode("utf-8"))
    ).encode("utf-8")


def source_archive_list_bytes(records: Sequence[SourceRecord]) -> bytes:
    return "".join(
        f"{record.path}\n"
        for record in sorted(records, key=lambda item: item.path.encode("utf-8"))
    ).encode("utf-8")


def source_checksum_bytes(records: Sequence[SourceRecord]) -> bytes:
    return "".join(
        f"{record.sha256}  {record.path}\n"
        for record in sorted(records, key=lambda item: item.path.encode("utf-8"))
    ).encode("utf-8")


def source_hash_manifest_bytes(records: Sequence[SourceRecord]) -> bytes:
    return "".join(
        f"{record.normalized_mode:04o} {record.size} {record.sha256}  {record.path}\n"
        for record in sorted(records, key=lambda item: item.path.encode("utf-8"))
    ).encode("utf-8")


def parse_source_hash_manifest(raw: bytes) -> list[SourceRecord]:
    try:
        rendered = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise BundleError(f"source identity manifest is not UTF-8: {exc}") from exc
    if not rendered.endswith("\n"):
        fail("source identity manifest must end with one LF")
    records: list[SourceRecord] = []
    paths: set[str] = set()
    total_bytes = 0
    for line in rendered.splitlines():
        match = SOURCE_MANIFEST_LINE_RE.fullmatch(line)
        if match is None:
            fail("source identity manifest has a malformed line")
        mode_text, size_text, digest, relative = match.groups()
        validate_relative_path(relative)
        if relative in paths:
            fail(f"source identity manifest repeats a path: {relative}")
        size = int(size_text)
        if size > MAX_SOURCE_FILE_BYTES:
            fail(f"source identity manifest file exceeds size limit: {relative}")
        total_bytes += size
        if total_bytes > MAX_SOURCE_BYTES:
            fail("source identity manifest exceeds the total source size limit")
        mode = int(mode_text, 8)
        expected_mode = 0o555 if relative in EXECUTABLE_SOURCE_FILES else 0o444
        if mode != expected_mode:
            fail(
                f"source identity manifest mode violates the static allowlist: {relative}"
            )
        records.append(SourceRecord(relative, size, mode, 0, 0, digest))
        paths.add(relative)
        if len(records) > MAX_SOURCE_FILES:
            fail("source identity manifest exceeds the file count limit")
    if not records:
        fail("source identity manifest is empty")
    sorted_records = sorted(records, key=lambda item: item.path.encode("utf-8"))
    if records != sorted_records:
        fail("source identity manifest is not sorted by UTF-8 path")
    missing_executables = sorted(EXECUTABLE_SOURCE_FILES - paths)
    if missing_executables:
        fail(
            "source identity manifest is missing static executable inputs: "
            f"{missing_executables}"
        )
    missing_required = sorted(REQUIRED_SOURCE_FILES - paths)
    if missing_required:
        fail(f"source identity manifest is missing required inputs: {missing_required}")
    if source_hash_manifest_bytes(records) != raw:
        fail("source identity manifest is not canonically encoded")
    return records


def compare_source_records(
    expected: Sequence[SourceRecord], observed: Sequence[SourceRecord], label: str
) -> None:
    left = [record.identity() for record in expected]
    right = [record.identity() for record in observed]
    if left != right:
        left_by_path = {record.path: record for record in expected}
        right_by_path = {record.path: record for record in observed}
        added = sorted(set(right_by_path) - set(left_by_path))
        removed = sorted(set(left_by_path) - set(right_by_path))
        changed = sorted(
            path
            for path in set(left_by_path) & set(right_by_path)
            if left_by_path[path].identity() != right_by_path[path].identity()
        )
        fail(
            f"{label} source drift detected; added={added[:10]}, "
            f"removed={removed[:10]}, changed={changed[:10]}"
        )


def copy_normalized_source(
    source_root: Path, destination: Path, records: Sequence[SourceRecord]
) -> None:
    destination.mkdir(mode=0o700)
    directories: set[Path] = {destination}
    for record in records:
        source = source_root / record.path
        content, metadata = stable_file_bytes(source)
        observed = SourceRecord(
            record.path,
            len(content),
            stat.S_IMODE(metadata.st_mode),
            metadata.st_uid,
            metadata.st_gid,
            sha256_bytes(content),
        )
        if observed.identity() != record.identity():
            fail(f"source changed before it could be frozen: {record.path}")
        target = destination / record.path
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        current = target.parent
        while current != destination.parent:
            directories.add(current)
            if current == destination:
                break
            current = current.parent
        write_private(target, content)
        os.chmod(target, record.normalized_mode)
    for directory in sorted(
        directories, key=lambda path: len(path.parts), reverse=True
    ):
        os.chmod(directory, 0o555)


def verify_normalized_source(context: Path, records: Sequence[SourceRecord]) -> None:
    observed: list[tuple[str, int, int, str]] = []
    observed_directories: set[str] = set()
    if context.is_symlink() or not context.is_dir():
        fail("normalized source root must be one real directory")
    for path in sorted(
        context.rglob("*"), key=lambda item: item.as_posix().encode("utf-8")
    ):
        relative = path.relative_to(context).as_posix()
        metadata = path.lstat()
        if stat.S_ISDIR(metadata.st_mode):
            if stat.S_IMODE(metadata.st_mode) != 0o555:
                fail(f"normalized source directory is not mode 0555: {relative}")
            observed_directories.add(relative)
            continue
        if not stat.S_ISREG(metadata.st_mode) or path.is_symlink():
            fail(f"normalized source contains a non-regular entry: {relative}")
        expected_mode = 0o555 if relative in EXECUTABLE_SOURCE_FILES else 0o444
        if stat.S_IMODE(metadata.st_mode) != expected_mode:
            fail(
                f"normalized source file mode mismatch: {relative}: "
                f"expected {expected_mode:04o}"
            )
        content, stable = stable_file_bytes(path)
        observed.append(
            (relative, stable.st_size, expected_mode, sha256_bytes(content))
        )
    expected = [
        (record.path, record.size, record.normalized_mode, record.sha256)
        for record in records
    ]
    if observed != expected:
        fail("normalized source context differs from the frozen source manifest")
    expected_directories = {
        parent.as_posix()
        for record in records
        for parent in PurePosixPath(record.path).parents
        if parent.as_posix() != "."
    }
    if observed_directories != expected_directories:
        fail("normalized source context has a non-canonical directory inventory")


def _tar_info(
    name: str, *, mode: int, size: int, epoch: int, directory: bool
) -> tarfile.TarInfo:
    info = tarfile.TarInfo(name)
    info.type = tarfile.DIRTYPE if directory else tarfile.REGTYPE
    info.mode = mode
    info.uid = 0
    info.gid = 0
    info.uname = "root"
    info.gname = "root"
    info.mtime = epoch
    info.size = 0 if directory else size
    return info


def create_source_archive(
    context: Path, records: Sequence[SourceRecord], destination: Path, epoch: int
) -> None:
    directories = sorted(
        {
            parent.as_posix()
            for record in records
            for parent in PurePosixPath(record.path).parents
            if parent.as_posix() != "."
        },
        key=lambda value: value.encode("utf-8"),
    )
    descriptor = os.open(
        destination,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
        0o600,
    )
    with (
        os.fdopen(descriptor, "wb") as raw,
        gzip.GzipFile(
            filename="", mode="wb", compresslevel=9, fileobj=raw, mtime=epoch
        ) as zipped,
        tarfile.open(fileobj=zipped, mode="w", format=tarfile.PAX_FORMAT) as archive,
    ):
        for directory in directories:
            archive.addfile(
                _tar_info(directory, mode=0o555, size=0, epoch=epoch, directory=True)
            )
        for record in sorted(records, key=lambda item: item.path.encode("utf-8")):
            with (context / record.path).open("rb") as handle:
                archive.addfile(
                    _tar_info(
                        record.path,
                        mode=record.normalized_mode,
                        size=record.size,
                        epoch=epoch,
                        directory=False,
                    ),
                    handle,
                )
        raw.flush()
        os.fsync(raw.fileno())


def verify_source_archive(
    archive_path: Path, records: Sequence[SourceRecord], epoch: int
) -> bytes:
    expected = {record.path: record for record in records}
    expected_directories = {
        parent.as_posix()
        for record in records
        for parent in PurePosixPath(record.path).parents
        if parent.as_posix() != "."
    }
    observed: set[str] = set()
    observed_directories: set[str] = set()
    log: list[str] = []
    with tarfile.open(archive_path, mode="r:gz") as archive:
        for member in archive:
            validate_relative_path(member.name)
            if (
                member.uid != 0
                or member.gid != 0
                or member.uname != "root"
                or member.gname != "root"
            ):
                fail(
                    f"source archive member has non-canonical ownership: {member.name}"
                )
            if member.mtime != epoch:
                fail(f"source archive member has non-canonical mtime: {member.name}")
            if member.isdir():
                if member.mode != 0o555:
                    fail(
                        f"source archive directory has non-canonical mode: {member.name}"
                    )
                if (
                    member.name not in expected_directories
                    or member.name in observed_directories
                ):
                    fail(
                        "source archive has an unexpected or repeated directory: "
                        f"{member.name}"
                    )
                observed_directories.add(member.name)
                continue
            if not member.isfile() or member.name not in expected:
                fail(f"source archive has an unexpected member: {member.name}")
            if member.name in observed:
                fail(f"source archive repeats member: {member.name}")
            record = expected[member.name]
            if member.mode != record.normalized_mode or member.size != record.size:
                fail(f"source archive metadata mismatch: {member.name}")
            extracted = archive.extractfile(member)
            if extracted is None:
                fail(f"cannot read source archive member: {member.name}")
            digest = hashlib.sha256()
            size = 0
            with extracted:
                while chunk := extracted.read(1024 * 1024):
                    digest.update(chunk)
                    size += len(chunk)
            if size != record.size or digest.hexdigest() != record.sha256:
                fail(f"source archive content mismatch: {member.name}")
            observed.add(member.name)
            log.append(f"{member.name}: OK\n")
    missing = sorted(set(expected) - observed)
    if missing:
        fail(f"source archive is missing files: {missing[:10]}")
    if observed_directories != expected_directories:
        missing_directories = sorted(expected_directories - observed_directories)
        fail(f"source archive is missing directories: {missing_directories[:10]}")
    return "".join(log).encode("utf-8")


def run_command(
    arguments: Sequence[str],
    *,
    cwd: Path | None = None,
    timeout: int = COMMAND_TIMEOUT_SECONDS,
    environment: dict[str, str] | None = None,
    input_bytes: bytes | None = None,
    check: bool = True,
) -> CommandResult:
    try:
        completed = subprocess.run(
            list(arguments),
            cwd=cwd,
            env=environment,
            stdin=subprocess.DEVNULL if input_bytes is None else None,
            input=input_bytes,
            capture_output=True,
            check=False,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise BundleError(f"command failed to execute: {arguments[0]}: {exc}") from exc
    if (
        len(completed.stdout) > MAX_COMMAND_OUTPUT_BYTES
        or len(completed.stderr) > MAX_COMMAND_OUTPUT_BYTES
    ):
        fail(f"command output exceeds the 16 MiB evidence limit: {arguments[0]}")
    if check and completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", errors="replace").strip()
        fail(
            f"command failed with exit {completed.returncode}: {arguments[0]}: {detail[-4000:]}"
        )
    return CommandResult(completed.stdout, completed.stderr, completed.returncode)


def run_logged_build(
    arguments: Sequence[str], *, cwd: Path, log_path: Path, epoch: int
) -> None:
    environment = os.environ.copy()
    environment["SOURCE_DATE_EPOCH"] = str(epoch)
    descriptor = os.open(
        log_path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
        0o600,
    )
    try:
        with os.fdopen(descriptor, "wb") as log:
            try:
                completed = subprocess.run(
                    list(arguments),
                    cwd=cwd,
                    env=environment,
                    stdin=subprocess.DEVNULL,
                    stdout=log,
                    stderr=subprocess.STDOUT,
                    check=False,
                    timeout=BUILD_TIMEOUT_SECONDS,
                )
            except (OSError, subprocess.TimeoutExpired) as exc:
                raise BundleError(f"image build failed to execute: {exc}") from exc
            log.flush()
            os.fsync(log.fileno())
        if completed.returncode != 0:
            try:
                with log_path.open("rb") as handle:
                    handle.seek(0, os.SEEK_END)
                    size = handle.tell()
                    handle.seek(max(0, size - 8_192), os.SEEK_SET)
                    tail = handle.read().decode("utf-8", errors="replace").strip()
            except OSError as exc:
                tail = f"<unable to read private build log: {exc}>"
            fail(
                f"image build failed with exit {completed.returncode}: {arguments[-2]}; "
                f"private build log tail:\n{tail}"
            )
    except BaseException:
        if not log_path.exists():
            os.close(descriptor)
        raise


def build_command(
    *,
    docker: str,
    component: str,
    context: Path,
    archive: Path,
    tag: str,
    release: str,
    revision: str,
    epoch: int,
) -> list[str]:
    command = [
        docker,
        "buildx",
        "build",
        "--platform",
        PLATFORM,
        "--pull",
        "--provenance=false",
        "--sbom=false",
        "--progress=plain",
        "--file",
        str(context / DOCKERFILES[component]),
        "--build-arg",
        f"CONTROL_RELEASE={release}",
        "--build-arg",
        f"VCS_REF={revision}",
        "--build-arg",
        f"SOURCE_DATE_EPOCH={epoch}",
    ]
    if component == "pwa":
        command.extend(["--build-arg", "VITE_CONTROL_CSRF_COOKIE_NAME=codex_csrf"])
    command.extend(
        [
            "--tag",
            tag,
            "--output",
            f"type=docker,dest={archive}",
            str(context),
        ]
    )
    return command


def expected_labels(
    component: str, release: str, revision: str, image_source: str
) -> dict[str, str]:
    return {
        "org.opencontainers.image.revision": revision,
        "org.opencontainers.image.source": image_source,
        "org.opencontainers.image.title": IMAGE_TITLES[component],
        "org.opencontainers.image.version": release,
    }


def image_tag_for_build(
    component: str, release: str, revision: str, bundle_id: str
) -> str:
    if component not in COMPONENTS:
        fail(f"unsupported image component: {component}")
    if SHA256_RE.fullmatch(revision) is None:
        fail("image tag revision must be one full 64-hex source identity")
    if RELEASE_RE.fullmatch(release) is None:
        fail("image tag release is not an exact semantic version")
    if SAFE_BUNDLE_ID_RE.fullmatch(bundle_id) is None:
        fail("image tag bundle ID is not canonical")
    tag = f"{IMAGE_REPOSITORIES[component]}:bootstrap-{release}-{revision}-{bundle_id}"
    if len(tag.rsplit(":", 1)[1]) > 128:
        fail("generated Docker image tag exceeds the 128-character limit")
    return tag


def listed_image_ids(
    docker: str,
    tag: str,
    *,
    command: Callable[..., CommandResult] = run_command,
) -> list[str]:
    raw = command([docker, "image", "ls", "--quiet", "--no-trunc", tag]).stdout.decode(
        "ascii", errors="strict"
    )
    values = [line.strip() for line in raw.splitlines() if line.strip()]
    if len(values) != len(set(values)) or any(
        IMAGE_ID_RE.fullmatch(value) is None for value in values
    ):
        fail(f"Docker returned invalid image identities for tag {tag}")
    return values


def require_image_tag_absent(
    docker: str,
    tag: str,
    *,
    command: Callable[..., CommandResult] = run_command,
) -> None:
    if listed_image_ids(docker, tag, command=command):
        fail(f"refusing to reuse a pre-existing Docker image tag: {tag}")


def cleanup_owned_image_tags(
    docker: str,
    owned: Sequence[OwnedImageTag],
    *,
    command: Callable[..., CommandResult] = run_command,
) -> None:
    errors: list[str] = []
    for image in reversed(owned):
        try:
            identities = listed_image_ids(docker, image.tag, command=command)
            if not identities:
                continue
            if identities != [image.expected_image_id]:
                errors.append(f"identity-changed:{image.tag}")
                continue
            command([docker, "image", "rm", image.tag])
            if listed_image_ids(docker, image.tag, command=command):
                errors.append(f"tag-survived:{image.tag}")
        except (BundleError, OSError, UnicodeError, ValueError) as exc:
            errors.append(f"command:{image.tag}:{exc}")
    if errors:
        fail(f"Docker image tag cleanup failed: {errors}")


def mapper_command(
    *,
    python: str,
    mapper: Path,
    archive: Path,
    archive_sha256: str,
    tag: str,
    labels: dict[str, str],
    manifest_digest: str | None = None,
    config_digest: str | None = None,
    inspect_json: Path | None = None,
) -> list[str]:
    command = [
        python,
        str(mapper),
        "--archive",
        str(archive),
        "--expected-archive-sha256",
        archive_sha256,
        "--expected-tag",
        tag,
        "--expected-platform",
        PLATFORM,
    ]
    for key, value in sorted(labels.items()):
        command.extend(["--expected-label", f"{key}={value}"])
    if manifest_digest is not None:
        command.extend(["--expected-manifest-digest", manifest_digest])
    if config_digest is not None:
        command.extend(["--expected-config-digest", config_digest])
    if inspect_json is not None:
        command.extend(["--inspect-json", str(inspect_json)])
    return command


def decode_json_object(raw: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BundleError(f"invalid {label}: {exc}") from exc
    if not isinstance(value, dict):
        fail(f"{label} is not one JSON object")
    return value


def decode_inspect(raw: bytes) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BundleError(f"invalid Docker inspect output: {exc}") from exc
    if not isinstance(value, list) or len(value) != 1 or not isinstance(value[0], dict):
        fail("Docker image inspect must return exactly one image object")
    return value, value[0]


def validate_image_inspect(
    inspection: dict[str, Any], component: str, tag: str, labels: dict[str, str]
) -> str:
    image_id = inspection.get("Id")
    if not isinstance(image_id, str) or IMAGE_ID_RE.fullmatch(image_id) is None:
        fail(f"{component} Docker image ID is invalid")
    if inspection.get("Os") != "linux" or inspection.get("Architecture") != "amd64":
        fail(f"{component} Docker image is not exactly linux/amd64")
    tags = inspection.get("RepoTags")
    if not isinstance(tags, list) or tag not in tags:
        fail(f"{component} Docker image does not expose the expected tag")
    config = inspection.get("Config")
    if not isinstance(config, dict):
        fail(f"{component} Docker inspect Config is invalid")
    observed_labels = config.get("Labels")
    if not isinstance(observed_labels, dict):
        fail(f"{component} Docker image labels are missing")
    for key, value in labels.items():
        if observed_labels.get(key) != value:
            fail(f"{component} Docker image label mismatch: {key}")
    if config.get("User") not in EXPECTED_USERS[component]:
        fail(f"{component} Docker image has an unexpected configured user")
    return image_id


def verify_pinned_mapper(
    *,
    python: str,
    mapper: Path,
    archive: Path,
    tag: str,
    labels: dict[str, str],
    inspect_path: Path,
    first: dict[str, Any],
    command: Callable[..., CommandResult] = run_command,
) -> dict[str, Any]:
    archive_sha = sha256_file(archive)
    image = first.get("image")
    if not isinstance(image, dict):
        fail("first OCI archive map has no image identity")
    manifest_digest = image.get("manifest_digest")
    config_digest = image.get("config_digest")
    if not isinstance(manifest_digest, str) or not isinstance(config_digest, str):
        fail("first OCI archive map lacks portable digests")
    second = decode_json_object(
        command(
            mapper_command(
                python=python,
                mapper=mapper,
                archive=archive,
                archive_sha256=archive_sha,
                tag=tag,
                labels=labels,
                manifest_digest=manifest_digest,
                config_digest=config_digest,
                inspect_json=inspect_path,
            )
        ).stdout,
        "pinned OCI archive map",
    )
    if second.get("archive") != first.get("archive") or second.get(
        "image"
    ) != first.get("image"):
        fail("pinned OCI archive map differs from the first portable identity")
    if not isinstance(second.get("daemon"), dict):
        fail("pinned OCI archive map lacks daemon identity")
    return second


PWA_NETWORK_OPTIONS = {
    "com.docker.network.bridge.enable_icc": "false",
    "com.docker.network.bridge.enable_ip_masquerade": "false",
}


def probe_loopback_health(host_port: int) -> tuple[int, bytes]:
    connection = http.client.HTTPConnection("127.0.0.1", host_port, timeout=3)
    try:
        connection.request("GET", "/healthz", headers={"Connection": "close"})
        response = connection.getresponse()
        body = response.read(4097)
        if len(body) > 4096:
            fail("PWA loopback health response exceeds 4096 bytes")
        return response.status, body
    except (OSError, http.client.HTTPException) as exc:
        raise BundleError(f"PWA loopback health request failed: {exc}") from exc
    finally:
        connection.close()


def verify_pwa_runtime(
    docker: str,
    tag: str,
    *,
    command: Callable[..., CommandResult] = run_command,
    monotonic: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
    host_health_probe: Callable[[int], tuple[int, bytes]] = probe_loopback_health,
) -> dict[str, Any]:
    nonce = f"{os.getpid()}-{secrets.token_hex(4)}"
    network = f"sub2api-bundle-pwa-net-{nonce}"
    container_name = f"sub2api-bundle-pwa-{nonce}"
    container_id: str | None = None
    network_id: str | None = None
    evidence: dict[str, Any] | None = None
    main_error: BaseException | None = None
    cleanup_errors: list[str] = []

    def container_inspect(identifier: str, label: str) -> dict[str, Any]:
        try:
            value = json.loads(
                command([docker, "container", "inspect", identifier]).stdout.decode(
                    "utf-8"
                )
            )
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise BundleError(
                f"invalid {label} container inspect output: {exc}"
            ) from exc
        if (
            not isinstance(value, list)
            or len(value) != 1
            or not isinstance(value[0], dict)
        ):
            fail(f"{label} container inspect did not return one object")
        return value[0]

    def wait_healthy(identifier: str, label: str) -> dict[str, Any]:
        deadline = monotonic() + 90
        while monotonic() < deadline:
            inspection = container_inspect(identifier, label)
            state = inspection.get("State")
            if not isinstance(state, dict):
                fail(f"{label} container state is missing")
            health = state.get("Health")
            status_value = health.get("Status") if isinstance(health, dict) else None
            if status_value == "healthy":
                observed_process = [
                    inspection.get("Path"),
                    *(inspection.get("Args") or []),
                ]
                if observed_process != ["nginx", "-g", "daemon off;"]:
                    fail(f"{label} process did not start from the image entrypoint")
                return inspection
            if status_value == "unhealthy" or state.get("Running") is not True:
                fail(f"{label} runtime stopped or became unhealthy: {status_value!r}")
            sleep(1)
        fail(f"{label} runtime did not become healthy within 90 seconds")

    def run_pwa(name: str) -> str:
        identifier = (
            command(
                [
                    docker,
                    "run",
                    "--detach",
                    "--name",
                    name,
                    "--network",
                    network,
                    "--platform",
                    PLATFORM,
                    "--pull",
                    "never",
                    "--publish",
                    "127.0.0.1::8080/tcp",
                    "--read-only",
                    "--tmpfs",
                    "/tmp:rw,noexec,nosuid,nodev,size=16m",
                    "--cap-drop",
                    "ALL",
                    "--security-opt",
                    "no-new-privileges",
                    tag,
                ]
            )
            .stdout.decode("ascii", errors="strict")
            .strip()
        )
        if re.fullmatch(r"[0-9a-f]{64}", identifier) is None:
            fail("PWA runtime did not return one full container ID")
        return identifier

    try:
        network_id = (
            command(
                [
                    docker,
                    "network",
                    "create",
                    "--driver",
                    "bridge",
                    "--opt",
                    "com.docker.network.bridge.enable_ip_masquerade=false",
                    "--opt",
                    "com.docker.network.bridge.enable_icc=false",
                    network,
                ]
            )
            .stdout.decode("ascii", errors="strict")
            .strip()
        )
        if re.fullmatch(r"[0-9a-f]{64}", network_id) is None:
            fail("PWA runtime network did not return one full network ID")

        container_id = run_pwa(container_name)
        inspection = wait_healthy(container_id, "PWA")

        network_raw = command([docker, "network", "inspect", network]).stdout
        try:
            network_values = json.loads(network_raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise BundleError(f"invalid PWA network inspect output: {exc}") from exc
        if (
            not isinstance(network_values, list)
            or len(network_values) != 1
            or not isinstance(network_values[0], dict)
        ):
            fail("PWA network inspect did not return one object")
        network_inspection = network_values[0]
        network_containers = network_inspection.get("Containers")
        if not isinstance(network_containers, dict):
            fail("PWA network inspect has no container membership")
        if set(network_containers) != {container_id}:
            fail("PWA runtime network does not contain exactly the PWA container")
        endpoint = network_containers.get(container_id)
        if not isinstance(endpoint, dict) or endpoint.get("Name") != container_name:
            fail("PWA runtime network container identity is invalid")
        if (
            network_inspection.get("Name") != network
            or network_inspection.get("Id") != network_id
            or network_inspection.get("Driver") != "bridge"
            or network_inspection.get("Internal") is not False
            or network_inspection.get("Attachable") is not False
            or network_inspection.get("EnableIPv6") is not False
            or network_inspection.get("Options") != PWA_NETWORK_OPTIONS
        ):
            fail("PWA runtime network topology or isolation options are invalid")

        host_config = inspection.get("HostConfig")
        network_settings = inspection.get("NetworkSettings")
        if not isinstance(host_config, dict) or not isinstance(network_settings, dict):
            fail("PWA container inspect lacks host or network settings")
        if host_config.get("NetworkMode") != network:
            fail("PWA container is not attached only through the runtime gate network")
        requested_bindings = host_config.get("PortBindings")
        if not isinstance(requested_bindings, dict) or set(requested_bindings) != {
            "8080/tcp"
        }:
            fail("PWA requested port binding is not exactly container TCP 8080")
        requested = requested_bindings.get("8080/tcp")
        if (
            not isinstance(requested, list)
            or len(requested) != 1
            or not isinstance(requested[0], dict)
        ):
            fail("PWA requested port binding is invalid")
        ports = network_settings.get("Ports")
        if not isinstance(ports, dict) or "8080/tcp" not in ports:
            fail("PWA effective port mapping lacks container TCP 8080")
        if any(
            port != "8080/tcp" and mapping not in (None, [])
            for port, mapping in ports.items()
        ):
            fail("PWA has an unexpected additional effective port mapping")
        effective = ports.get("8080/tcp")
        if (
            not isinstance(effective, list)
            or len(effective) != 1
            or not isinstance(effective[0], dict)
        ):
            fail("PWA effective port mapping is invalid")
        host_ip = effective[0].get("HostIp")
        host_port_text = effective[0].get("HostPort")
        try:
            host_port = int(host_port_text)
        except (TypeError, ValueError) as exc:
            raise BundleError("PWA allocated host port is invalid") from exc
        if (
            host_ip != "127.0.0.1"
            or not 1 <= host_port <= 65535
            or requested[0].get("HostIp") != "127.0.0.1"
            or requested[0].get("HostPort") not in {"", host_port_text}
        ):
            fail("PWA port mapping is not one random loopback publication to TCP 8080")
        attachments = network_settings.get("Networks")
        if not isinstance(attachments, dict) or set(attachments) != {network}:
            fail("PWA container has an unexpected network attachment")
        attachment = attachments.get(network)
        if (
            not isinstance(attachment, dict)
            or attachment.get("NetworkID") != network_id
        ):
            fail("PWA network attachment identity is invalid")

        internal_body = command(
            [
                docker,
                "exec",
                container_id,
                "wget",
                "-q",
                "-O",
                "-",
                "http://127.0.0.1:8080/healthz",
            ]
        ).stdout.decode("ascii", errors="strict")
        host_status, host_body = host_health_probe(host_port)
        if internal_body != "ok\n" or host_status != 200 or host_body != b"ok\n":
            fail("PWA internal or host-published health runtime gate failed")

        uid = (
            command([docker, "exec", container_id, "id", "-u"])
            .stdout.decode("ascii")
            .strip()
        )
        mode = (
            command(
                [
                    docker,
                    "exec",
                    container_id,
                    "stat",
                    "-c",
                    "%a",
                    "/etc/nginx/nginx.conf",
                ]
            )
            .stdout.decode("ascii")
            .strip()
        )
        command([docker, "exec", container_id, "test", "-r", "/etc/nginx/nginx.conf"])
        if uid != "101" or mode != "444":
            fail("PWA non-root/config runtime gate failed")

        evidence = {
            "cleanup": {},
            "configured_user": "nginx",
            "format_version": 3,
            "host_health": {
                "body": host_body.decode("ascii", errors="strict").rstrip("\n"),
                "path": "/healthz",
                "status_code": host_status,
            },
            "network": {
                "attachable": False,
                "container_id": container_id,
                "driver": "bridge",
                "enable_ipv6": False,
                "id": network_id,
                "inspect_topology_exact": True,
                "internal": False,
                "name": network,
                "options": dict(PWA_NETWORK_OPTIONS),
                "sole_member": True,
            },
            "nginx_config": {
                "mode": mode,
                "path": "/etc/nginx/nginx.conf",
                "readable_by_runtime_user": True,
            },
            "port_mapping": {
                "container_port": 8080,
                "host_ip": host_ip,
                "host_port": host_port,
                "inherited_unpublished_ports": sorted(
                    port
                    for port, mapping in ports.items()
                    if port != "8080/tcp" and mapping in (None, [])
                ),
                "inspect_mapping_exact": True,
                "protocol": "tcp",
            },
            "runtime": {
                "container_id": container_id,
                "docker_health_status": "healthy",
                "healthz_body": internal_body.rstrip("\n"),
                "process_started_from_image_entrypoint": True,
            },
            "runtime_uid": int(uid),
            "status": "verified",
        }
    except BaseException as exc:  # noqa: BLE001 - cleanup must also run on interrupts.
        main_error = exc

    def cleanup_call(arguments: Sequence[str]) -> CommandResult | None:
        try:
            return command(arguments, check=False)
        except (BundleError, OSError, UnicodeError, ValueError) as exc:
            cleanup_errors.append(f"command:{arguments[1:]}:{exc}")
            return None

    for name in (container_name,):
        cleanup_call([docker, "container", "rm", "--force", name])
        remaining = cleanup_call([docker, "container", "inspect", name])
        if remaining is not None and remaining.returncode == 0:
            cleanup_errors.append(f"container:{name}")
    cleanup_call([docker, "network", "rm", network])
    remaining_network = cleanup_call([docker, "network", "inspect", network])
    if remaining_network is not None and remaining_network.returncode == 0:
        cleanup_errors.append(f"network:{network}")

    if cleanup_errors:
        detail = f"PWA runtime cleanup failed: {cleanup_errors}"
        if main_error is not None:
            raise BundleError(f"{main_error}; {detail}") from main_error
        fail(detail)
    if main_error is not None:
        raise main_error
    if evidence is None:
        fail("PWA runtime produced no evidence")
    evidence["cleanup"] = {"containers_removed": True, "network_removed": True}
    return evidence


def verify_postgres_roundtrip(
    docker: str,
    tag: str,
    tools_image_id: str,
    *,
    command: Callable[..., CommandResult] = run_command,
    monotonic: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
) -> dict[str, Any]:
    nonce = f"{os.getpid()}-{secrets.token_hex(5)}"
    network = f"sub2api-bundle-pg-net-{nonce}"
    server = f"sub2api-bundle-pg-server-{nonce}"
    client_names: list[str] = []
    cleanup_errors: list[str] = []
    main_error: BaseException | None = None
    evidence: dict[str, Any] | None = None

    def client_run(
        purpose: str,
        entrypoint: str,
        arguments: Sequence[str],
        *,
        input_bytes: bytes | None = None,
    ) -> CommandResult:
        name = f"sub2api-bundle-pg-{purpose}-{nonce}"
        client_names.append(name)
        interactive = ["--interactive"] if input_bytes is not None else []
        return command(
            [
                docker,
                "run",
                "--rm",
                *interactive,
                "--name",
                name,
                "--network",
                network,
                "--platform",
                PLATFORM,
                "--pull",
                "never",
                "--read-only",
                "--tmpfs",
                "/tmp:rw,noexec,nosuid,nodev,size=16m,mode=1777",
                "--cap-drop",
                "ALL",
                "--security-opt",
                "no-new-privileges",
                "--entrypoint",
                entrypoint,
                tools_image_id,
                *arguments,
            ],
            input_bytes=input_bytes,
        )

    def psql(database: str, sql: str) -> bytes:
        return command(
            [
                docker,
                "exec",
                server,
                "psql",
                "--host",
                "127.0.0.1",
                "--username",
                "postgres",
                "--dbname",
                database,
                "--set",
                "ON_ERROR_STOP=1",
                "--tuples-only",
                "--no-align",
                "--command",
                sql,
            ]
        ).stdout

    try:
        network_id = (
            command([docker, "network", "create", "--internal", network])
            .stdout.decode("ascii", errors="strict")
            .strip()
        )
        if re.fullmatch(r"[0-9a-f]{64}", network_id) is None:
            fail("PostgreSQL roundtrip network did not return one full ID")
        server_id = (
            command(
                [
                    docker,
                    "run",
                    "--detach",
                    "--name",
                    server,
                    "--network",
                    network,
                    "--network-alias",
                    "postgres",
                    "--platform",
                    PLATFORM,
                    "--pull",
                    "never",
                    "--user",
                    "0:0",
                    "--tmpfs",
                    "/var/lib/postgresql:rw,nosuid,nodev,size=256m",
                    "--tmpfs",
                    "/tmp:rw,noexec,nosuid,nodev,size=32m,mode=1777",
                    "--env",
                    "POSTGRES_HOST_AUTH_METHOD=trust",
                    "--env",
                    "POSTGRES_DB=source_db",
                    "--env",
                    "POSTGRES_USER=postgres",
                    "--entrypoint",
                    "docker-entrypoint.sh",
                    tools_image_id,
                    "postgres",
                ]
            )
            .stdout.decode("ascii", errors="strict")
            .strip()
        )
        if re.fullmatch(r"[0-9a-f]{64}", server_id) is None:
            fail("PostgreSQL roundtrip server did not return one full container ID")

        deadline = monotonic() + 90
        while monotonic() < deadline:
            readiness = command(
                [
                    docker,
                    "exec",
                    server,
                    "psql",
                    "--host",
                    "127.0.0.1",
                    "--username",
                    "postgres",
                    "--dbname",
                    "source_db",
                    "--set",
                    "ON_ERROR_STOP=1",
                    "--tuples-only",
                    "--no-align",
                    "--command",
                    "SELECT 1",
                ],
                check=False,
            )
            if readiness.returncode == 0 and readiness.stdout == b"1\n":
                break
            sleep(1)
        else:
            fail("PostgreSQL roundtrip server was not ready within 90 seconds")

        server_version = (
            psql("source_db", "SHOW server_version")
            .decode("ascii", errors="strict")
            .strip()
        )
        if server_version != "18.4":
            fail(f"PostgreSQL roundtrip server is not exactly 18.4: {server_version}")

        fixture_sql = """
CREATE SCHEMA bundle_fixture;
CREATE SEQUENCE bundle_fixture.item_seq START WITH 41;
CREATE TABLE bundle_fixture.items (
  id bigint PRIMARY KEY DEFAULT nextval('bundle_fixture.item_seq'),
  label text NOT NULL,
  note text,
  payload bytea NOT NULL
);
INSERT INTO bundle_fixture.items (label, note, payload) VALUES
  ('alpha', NULL, decode('0001ff', 'hex')),
  ('Tokyo-' || chr(26481) || chr(20140), E'line\\nvalue', decode('deadbeef', 'hex'));
"""
        psql("source_db", fixture_sql)
        canonical_query = """
SELECT id::text || '|' || encode(convert_to(label, 'UTF8'), 'hex') || '|' ||
       COALESCE(encode(convert_to(note, 'UTF8'), 'hex'), '<NULL>') || '|' ||
       encode(payload, 'hex')
FROM bundle_fixture.items ORDER BY id;
"""
        schema_query = """
SELECT column_name || ':' || udt_name || ':' || is_nullable
FROM information_schema.columns
WHERE table_schema = 'bundle_fixture' AND table_name = 'items'
ORDER BY ordinal_position;
"""
        source_rows = psql("source_db", canonical_query)
        source_schema = psql("source_db", schema_query)
        source_sequence = (
            psql("source_db", "SELECT last_value::text FROM bundle_fixture.item_seq")
            .decode("ascii", errors="strict")
            .strip()
        )
        expected_schema = (
            b"id:int8:NO\nlabel:text:NO\nnote:text:YES\npayload:bytea:NO\n"
        )
        if source_schema != expected_schema or source_sequence != "42":
            fail("PostgreSQL roundtrip source fixture schema or sequence is invalid")

        version_result = client_run(
            "versions",
            "/bin/sh",
            ["-eu", "-c", "pg_dump --version; pg_restore --version"],
        )
        versions = version_result.stdout.decode("ascii", errors="strict").splitlines()
        expected_versions = [
            "pg_dump (PostgreSQL) 18.4",
            "pg_restore (PostgreSQL) 18.4",
        ]
        if versions != expected_versions:
            fail(f"PostgreSQL tools are not exactly 18.4: {versions!r}")

        dump = client_run(
            "dump",
            "pg_dump",
            [
                "--host",
                "postgres",
                "--username",
                "postgres",
                "--dbname",
                "source_db",
                "--format",
                "custom",
                "--compress",
                "9",
                "--no-owner",
                "--no-acl",
            ],
        ).stdout
        if len(dump) < 5 or dump[:5] != b"PGDMP":
            fail("PostgreSQL roundtrip did not produce a custom-format dump")
        dump_list = client_run(
            "list", "pg_restore", ["--list"], input_bytes=dump
        ).stdout
        dump_list_entries = [
            line
            for line in dump_list.splitlines()
            if line and not line.startswith(b";")
        ]
        if not dump_list_entries:
            fail("PostgreSQL dump list has no TOC entries")
        for expected_entry in (
            b"TABLE bundle_fixture items",
            b"TABLE DATA bundle_fixture items",
            b"SEQUENCE SET bundle_fixture item_seq",
        ):
            if expected_entry not in dump_list:
                fail(f"PostgreSQL dump list lacks fixture entry: {expected_entry!r}")

        psql("postgres", "CREATE DATABASE restored_db")
        client_run(
            "restore",
            "pg_restore",
            [
                "--host",
                "postgres",
                "--username",
                "postgres",
                "--dbname",
                "restored_db",
                "--no-owner",
                "--no-acl",
                "--exit-on-error",
            ],
            input_bytes=dump,
        )
        restored_rows = psql("restored_db", canonical_query)
        restored_schema = psql("restored_db", schema_query)
        restored_sequence = (
            psql("restored_db", "SELECT last_value::text FROM bundle_fixture.item_seq")
            .decode("ascii", errors="strict")
            .strip()
        )
        if (
            restored_rows != source_rows
            or restored_schema != source_schema
            or restored_sequence != source_sequence
        ):
            fail("PostgreSQL restored fixture differs from its source database")
        row_lines = source_rows.decode("utf-8", errors="strict").splitlines()
        if len(row_lines) != 2:
            fail("PostgreSQL roundtrip fixture does not contain exactly two rows")

        evidence = {
            "cleanup": {},
            "dump": {
                "format": "custom",
                "list_entry_count": len(dump_list_entries),
                "list_sha256": sha256_bytes(dump_list),
                "sha256": sha256_bytes(dump),
                "size": len(dump),
            },
            "fixture": {
                "restored": {
                    "canonical_rows_sha256": sha256_bytes(restored_rows),
                    "row_count": len(
                        restored_rows.decode("utf-8", errors="strict").splitlines()
                    ),
                    "schema_sha256": sha256_bytes(restored_schema),
                    "sequence_last_value": int(restored_sequence),
                },
                "schema": "bundle_fixture",
                "sequence": "item_seq",
                "source": {
                    "canonical_rows_sha256": sha256_bytes(source_rows),
                    "row_count": len(row_lines),
                    "schema_sha256": sha256_bytes(source_schema),
                    "sequence_last_value": int(source_sequence),
                },
                "source_and_restored_rows_equal": True,
                "source_and_restored_schema_equal": True,
                "table": "items",
            },
            "format_version": 1,
            "isolation": {
                "docker_internal_network": True,
                "password_authentication_used": False,
                "persistent_volume_used": False,
                "server_pgdata": "tmpfs",
            },
            "server": {
                "dockerfile_base_image_material": POSTGRES_SERVER_IMAGE,
                "image_id": tools_image_id,
                "image_tag": tag,
                "version": server_version,
            },
            "status": "verified",
            "tools": {
                "client_versions": versions,
                "image_id": tools_image_id,
                "image_tag": tag,
            },
        }
    except (BundleError, OSError, UnicodeError, ValueError) as exc:
        main_error = exc

    def cleanup_call(arguments: Sequence[str]) -> CommandResult | None:
        try:
            return command(arguments, check=False)
        except (BundleError, OSError, UnicodeError, ValueError) as exc:
            cleanup_errors.append(f"command:{arguments[1:]}:{exc}")
            return None

    for name in [*reversed(client_names), server]:
        cleanup_call([docker, "container", "rm", "--force", name])
        remaining = cleanup_call([docker, "container", "inspect", name])
        if remaining is not None and remaining.returncode == 0:
            cleanup_errors.append(f"container:{name}")
    cleanup_call([docker, "network", "rm", network])
    remaining_network = cleanup_call([docker, "network", "inspect", network])
    if remaining_network is not None and remaining_network.returncode == 0:
        cleanup_errors.append(f"network:{network}")

    if cleanup_errors:
        detail = f"PostgreSQL roundtrip cleanup failed: {cleanup_errors}"
        if main_error is not None:
            raise BundleError(f"{main_error}; {detail}") from main_error
        fail(detail)
    if main_error is not None:
        raise main_error
    if evidence is None:
        fail("PostgreSQL roundtrip produced no evidence")
    evidence["cleanup"] = {
        "containers_removed": True,
        "network_removed": True,
        "persistent_volume_created": False,
    }
    return evidence


def build_component(
    *,
    component: str,
    tag: str,
    docker: str,
    python: str,
    mapper: Path,
    context: Path,
    bundle: Path,
    release: str,
    revision: str,
    image_source: str,
    epoch: int,
    docker_versions: dict[str, str],
    load_log: Path,
    owned_image_tags: list[OwnedImageTag],
) -> dict[str, Any]:
    require_image_tag_absent(docker, tag)
    archive = bundle / ARCHIVE_NAMES[component]
    build_log = bundle / f"{component}-build.log"
    command = build_command(
        docker=docker,
        component=component,
        context=context,
        archive=archive,
        tag=tag,
        release=release,
        revision=revision,
        epoch=epoch,
    )
    run_logged_build(command, cwd=context, log_path=build_log, epoch=epoch)
    if not archive.is_file() or archive.is_symlink() or archive.stat().st_size <= 0:
        fail(f"{component} build did not produce one regular archive")
    os.chmod(archive, 0o600)
    archive_sha = sha256_file(archive)

    # Parse once before daemon mutation; this pins portable manifest/config IDs.
    first_map = decode_json_object(
        run_command(
            mapper_command(
                python=python,
                mapper=mapper,
                archive=archive,
                archive_sha256=archive_sha,
                tag=tag,
                labels=expected_labels(component, release, revision, image_source),
            )
        ).stdout,
        "first OCI archive map",
    )
    portable = first_map.get("image")
    if not isinstance(portable, dict):
        fail(f"{component} archive has no portable image identity")
    portable_config = portable.get("config_digest")
    if (
        not isinstance(portable_config, str)
        or IMAGE_ID_RE.fullmatch(portable_config) is None
    ):
        fail(f"{component} archive has no canonical config digest")

    # Register the only tag this invocation may remove before docker load, since
    # a failed load can still leave daemon state behind.
    owned_image_tags.append(OwnedImageTag(tag=tag, expected_image_id=portable_config))
    load = run_command([docker, "load", "--input", str(archive)])
    loaded_ids = listed_image_ids(docker, tag)
    if len(loaded_ids) != 1:
        fail(f"{component} Docker load did not create exactly one expected tag")
    if loaded_ids[0] != portable_config:
        fail(f"{component} Docker load identity differs from archive config digest")
    with load_log.open("ab") as handle:
        handle.write(load.stdout)
        handle.write(load.stderr)
        handle.flush()
        os.fsync(handle.fileno())
    inspect_raw = run_command([docker, "image", "inspect", tag]).stdout
    inspect_list, inspection = decode_inspect(inspect_raw)
    image_id = validate_image_inspect(
        inspection,
        component,
        tag,
        expected_labels(component, release, revision, image_source),
    )
    if image_id != loaded_ids[0]:
        fail(f"{component} Docker load identity differs from inspect evidence")
    inspect_path = bundle / f"{component}-image-inspect.json"
    write_private(inspect_path, canonical_json(inspect_list, pretty=True))

    final_map = verify_pinned_mapper(
        python=python,
        mapper=mapper,
        archive=archive,
        tag=tag,
        labels=expected_labels(component, release, revision, image_source),
        inspect_path=inspect_path,
        first=first_map,
    )
    if (
        final_map.get("archive") != first_map.get("archive")
        or final_map.get("image") != portable
    ):
        fail(f"{component} archive identity changed between mapper passes")
    map_path = bundle / f"{component}-archive-map.json"
    write_private(map_path, canonical_json(final_map, pretty=True))

    build_metadata = {
        "archive_exporter": "docker",
        "build_args": {
            "CONTROL_RELEASE": release,
            "SOURCE_DATE_EPOCH": str(epoch),
            "VCS_REF": revision,
            **(
                {"VITE_CONTROL_CSRF_COOKIE_NAME": "codex_csrf"}
                if component == "pwa"
                else {}
            ),
        },
        "builder": "docker buildx",
        "daemon_image_id": image_id,
        "daemon_image_id_kind": final_map["daemon"]["id_kind"],
        "docker_versions": docker_versions,
        "format_version": 2,
        "platform_identity": {
            "archive_mapper": final_map["image"]["platform"],
            "build_host_platform_is_not_image_evidence": True,
            "daemon_inspect": f"{inspection['Os']}/{inspection['Architecture']}",
            "requested": PLATFORM,
        },
        "release": release,
        "revision": revision,
        "tag": tag,
    }
    metadata_path = bundle / f"{component}-build-metadata.json"
    write_private(metadata_path, canonical_json(build_metadata, pretty=True))
    return {
        "archive": archive.name,
        "archive_sha256": archive_sha,
        "archive_size": archive.stat().st_size,
        "build_log": build_log.name,
        "build_log_sha256": sha256_file(build_log),
        "build_metadata": metadata_path.name,
        "build_metadata_sha256": sha256_file(metadata_path),
        "config_digest": final_map["image"]["config_digest"],
        "index_sha256": final_map["image"]["index_sha256"],
        "daemon_image_id": image_id,
        "daemon_image_id_kind": final_map["daemon"]["id_kind"],
        "manifest_digest": final_map["image"]["manifest_digest"],
        "mapper_manifest": map_path.name,
        "mapper_manifest_sha256": sha256_file(map_path),
        "oci_labels": final_map["image"]["labels"],
        "platform": final_map["image"]["platform"],
        "tag": tag,
    }


def checksum_lines(directory: Path, names: Iterable[str]) -> bytes:
    return "".join(
        f"{sha256_file(directory / name)}  {name}\n" for name in names
    ).encode("ascii")


def parse_checksum_file(raw: bytes) -> dict[str, str]:
    result: dict[str, str] = {}
    for line in raw.decode("ascii").splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  ([0-9A-Za-z][0-9A-Za-z._-]*)", line)
        if match is None or match.group(2) in result:
            fail("checksum file is malformed or repeats a filename")
        result[match.group(2)] = match.group(1)
    if not result:
        fail("checksum file is empty")
    return result


def write_bundle_checksums(bundle: Path) -> None:
    names = sorted(
        path.name
        for path in bundle.iterdir()
        if path.is_file() and not path.is_symlink() and path.name != "SHA256SUMS"
    )
    write_private(bundle / "SHA256SUMS", checksum_lines(bundle, names))
    verify_bundle_checksums(bundle)


def verify_bundle_checksums(bundle: Path) -> None:
    checksum_path = bundle / "SHA256SUMS"
    values = parse_checksum_file(checksum_path.read_bytes())
    if "SHA256SUMS" in values:
        fail("SHA256SUMS must not contain a self-referential hash")
    actual = sorted(
        path.name
        for path in bundle.iterdir()
        if path.is_file() and not path.is_symlink() and path.name != "SHA256SUMS"
    )
    if sorted(values) != actual:
        fail("SHA256SUMS does not cover the exact bundle file inventory")
    for name, expected in values.items():
        if sha256_file(bundle / name) != expected:
            fail(f"bundle checksum mismatch: {name}")
    for path in bundle.iterdir():
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode) or path.is_symlink():
            fail(f"bundle contains a non-regular entry: {path.name}")
        if stat.S_IMODE(metadata.st_mode) != 0o600:
            fail(f"bundle file is not mode 0600: {path.name}")


def create_transport_tar(bundle: Path, destination: Path, epoch: int) -> None:
    descriptor = os.open(
        destination,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
        0o600,
    )
    with os.fdopen(descriptor, "wb") as raw:
        with tarfile.open(fileobj=raw, mode="w", format=tarfile.PAX_FORMAT) as archive:
            archive.addfile(
                _tar_info(".", mode=0o700, size=0, epoch=epoch, directory=True)
            )
            for path in sorted(
                bundle.iterdir(), key=lambda item: item.name.encode("utf-8")
            ):
                size = path.stat().st_size
                with path.open("rb") as handle:
                    archive.addfile(
                        _tar_info(
                            path.name,
                            mode=0o600,
                            size=size,
                            epoch=epoch,
                            directory=False,
                        ),
                        fileobj=handle,
                    )
        raw.flush()
        os.fsync(raw.fileno())


def verify_transport_tar(transport: Path, bundle: Path, epoch: int) -> None:
    expected = {
        path.name: (path.stat().st_size, sha256_file(path))
        for path in bundle.iterdir()
        if path.is_file() and not path.is_symlink()
    }
    observed: set[str] = set()
    root_seen = False
    with tarfile.open(transport, mode="r:") as archive:
        for member in archive:
            if member.name == "." and member.isdir():
                if root_seen:
                    fail("transport repeats its root directory")
                if (
                    member.mode != 0o700
                    or member.mtime != epoch
                    or member.uid != 0
                    or member.gid != 0
                    or member.uname != "root"
                    or member.gname != "root"
                ):
                    fail("transport root has non-canonical metadata")
                root_seen = True
                continue
            validate_relative_path(member.name)
            if (
                not member.isfile()
                or member.name not in expected
                or member.name in observed
            ):
                fail(
                    f"transport contains an unexpected or repeated member: {member.name}"
                )
            if (
                member.mode != 0o600
                or member.mtime != epoch
                or member.uid != 0
                or member.gid != 0
                or member.uname != "root"
                or member.gname != "root"
            ):
                fail(f"transport member has non-canonical metadata: {member.name}")
            extracted = archive.extractfile(member)
            if extracted is None:
                fail(f"cannot read transport member: {member.name}")
            digest = hashlib.sha256()
            size = 0
            with extracted:
                while chunk := extracted.read(1024 * 1024):
                    digest.update(chunk)
                    size += len(chunk)
            if (size, digest.hexdigest()) != expected[member.name]:
                fail(f"transport member content mismatch: {member.name}")
            observed.add(member.name)
    if not root_seen or observed != set(expected):
        fail("transport does not contain the exact bundle inventory")


def split_transport(
    transport: Path, part_size: int, output_directory: Path
) -> list[Path]:
    if part_size <= 0:
        fail("transport part size must be positive")
    parts: list[Path] = []
    whole = hashlib.sha256()
    with transport.open("rb") as source:
        index = 0
        while True:
            chunk = source.read(part_size)
            if not chunk:
                break
            whole.update(chunk)
            part = output_directory / f"{transport.name}.part-{index:04d}"
            write_private(part, chunk)
            parts.append(part)
            index += 1
    if not parts or whole.hexdigest() != sha256_file(transport):
        fail("transport split did not preserve the whole archive hash")
    manifest = {
        "format_version": 1,
        "part_size_bytes": part_size,
        "parts": [
            {
                "file": part.name,
                "sha256": sha256_file(part),
                "size": part.stat().st_size,
            }
            for part in parts
        ],
        "transport": {
            "file": transport.name,
            "sha256": sha256_file(transport),
            "size": transport.stat().st_size,
        },
    }
    write_private(
        output_directory / f"{transport.name}.parts.json",
        canonical_json(manifest, pretty=True),
    )
    write_private(
        output_directory / f"{transport.name}.parts.sha256",
        checksum_lines(output_directory, [part.name for part in parts]),
    )
    return parts


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


def docker_version_evidence(docker: str) -> dict[str, str]:
    buildx = (
        run_command([docker, "buildx", "version"])
        .stdout.decode("utf-8", errors="strict")
        .strip()
    )
    client = run_command([docker, "version", "--format", "{{.Client.Version}}"])
    server = run_command([docker, "version", "--format", "{{.Server.Version}}"])
    return {
        "buildx": buildx,
        "client": client.stdout.decode("ascii", errors="strict").strip(),
        "server": server.stdout.decode("ascii", errors="strict").strip(),
    }


def bundle_manifest(
    *,
    release: str,
    revision: str,
    generated_at: str,
    records: Sequence[SourceRecord],
    bundle: Path,
    images: dict[str, dict[str, Any]],
    pwa_runtime: dict[str, Any],
    postgres_roundtrip: dict[str, Any],
) -> dict[str, Any]:
    images = json.loads(json.dumps(images))
    images["pwa"]["runtime_verification"] = {
        "file": "pwa-runtime-verification.json",
        "result": pwa_runtime,
        "sha256": sha256_file(bundle / "pwa-runtime-verification.json"),
    }
    images["postgres-tools"]["client_versions"] = postgres_roundtrip["tools"][
        "client_versions"
    ]
    images["postgres-tools"]["dump_restore_verification"] = {
        "file": "postgres-tools-dump-restore-verification.json",
        "result": postgres_roundtrip,
        "sha256": sha256_file(bundle / "postgres-tools-dump-restore-verification.json"),
    }
    return {
        "artifact_kind": "unsigned-production-bootstrap-images",
        "build": {
            "archive_exporter": "docker",
            "normalized_source_context": {
                "content_hashes_verified_after_normalization": True,
                "directory_mode": "0555",
                "regular_file_mode": "0444",
            },
            "platform": PLATFORM,
            "platform_evidence": "OCI mapper plus daemon image inspect",
        },
        "format_version": 5,
        "generated_at": generated_at,
        "images": images,
        "offline_verifier": {
            "file": "verify-unsigned-bootstrap-bundle.py",
            "mode": "0600",
            "sha256": sha256_file(bundle / "verify-unsigned-bootstrap-bundle.py"),
        },
        "release": release,
        "schema_version": 1,
        "source": {
            "archive": {
                "apple_double_free": True,
                "file": "source.tar.gz",
                "sha256": sha256_file(bundle / "source.tar.gz"),
                "size": (bundle / "source.tar.gz").stat().st_size,
            },
            "canonical_hash_manifest": {
                "file": "source-files.manifest",
                "is_vcs_ref": True,
                "sha256": revision,
            },
            "canonical_hash_manifest_format": (
                "normalized-mode-space-size-space-sha256-two-spaces-relative-path-"
                "lf-sorted-by-utf8-path"
            ),
            "enumeration": "complete filesystem traversal with explicit exclusions",
            "explicit_exclusions": exclusion_policy(),
            "file_count": len(records),
            "file_list": {
                "file": "source-files.list",
                "format": "normalized-mode-space-size-two-spaces-relative-path",
                "sha256": sha256_file(bundle / "source-files.list"),
            },
            "sha256sum_compatible_content_manifest": {
                "file": "source-files.sha256",
                "sha256": sha256_file(bundle / "source-files.sha256"),
            },
            "normalized_modes": {
                "directories": "0555",
                "executable_allowlist": "0555",
                "other_regular_files": "0444",
            },
        },
        "status": "ready",
        "transport": {
            "apple_double_free": True,
            "checksum_file": "transport-SHA256SUMS",
            "checksum_file_sha256": sha256_file(bundle / "transport-SHA256SUMS"),
            "docker_load_verified": True,
            "image_checksum_file": "bootstrap-images.sha256",
            "image_checksum_file_sha256": sha256_file(
                bundle / "bootstrap-images.sha256"
            ),
        },
        "trust_mode": "unsigned-first-deployment-v1",
        "vcs_ref": revision,
        "verification": {
            "bundle_checksum_closure_excludes_only_SHA256SUMS_itself": True,
            "image_archives_are_docker_loadable": True,
            "image_archives_map_verified_twice_with_pinned_manifest_and_config_digests": True,
            "image_ids_platform_tags_and_labels_match": True,
            "normalized_context_content_matches_source_manifest": True,
            "postgres_dump_restore_18_4": True,
            "pwa_non_root_nginx_config_readable_and_runtime_healthy": True,
            "source_archive_matches_file_list": True,
            "source_extraction_matches_canonical_hash_manifest": True,
            "source_tree_unchanged_before_atomic_publish": True,
        },
    }


def owned_path(path: Path, *, is_directory: bool) -> OwnedPath:
    metadata = path.lstat()
    expected = stat.S_ISDIR if is_directory else stat.S_ISREG
    if path.is_symlink() or not expected(metadata.st_mode):
        fail(f"invocation-owned path has an unexpected type: {path}")
    return OwnedPath(path, metadata.st_dev, metadata.st_ino, is_directory)


def path_is_owned(value: OwnedPath) -> bool:
    try:
        metadata = value.path.lstat()
    except FileNotFoundError:
        return False
    expected = stat.S_ISDIR if value.is_directory else stat.S_ISREG
    return (
        not value.path.is_symlink()
        and expected(metadata.st_mode)
        and (metadata.st_dev, metadata.st_ino) == (value.device, value.inode)
    )


def cleanup_owned_paths(paths: Sequence[OwnedPath]) -> None:
    for value in reversed(paths):
        if not path_is_owned(value):
            continue
        try:
            if value.is_directory:
                value.path.rmdir()
            else:
                value.path.unlink()
        except OSError:
            # Never widen failure cleanup into unowned or newly populated paths.
            continue


def finalize_build_cleanup(
    *,
    docker: str,
    image_tags_cleaned: bool,
    owned_image_tags: Sequence[OwnedImageTag],
    staging: Path | None,
    published: bool,
    owned_paths: Sequence[OwnedPath],
    output: Path,
    transport_output: Path,
    active_error: BaseException | None,
) -> None:
    errors: list[str] = []
    if not image_tags_cleaned and owned_image_tags:
        try:
            cleanup_owned_image_tags(docker, owned_image_tags)
        except (BundleError, OSError, UnicodeError, ValueError) as exc:
            errors.append(f"docker-images:{exc}")
    if staging is not None and staging.exists():
        try:
            make_tree_deletable(staging)
            shutil.rmtree(staging)
        except OSError as exc:
            errors.append(f"staging:{exc}")
    if not published:
        cleanup_owned_paths(owned_paths)
        for directory in (output, transport_output):
            try:
                fsync_directory(directory)
            except OSError as exc:
                errors.append(f"fsync:{directory}:{exc}")
    if errors:
        detail = f"build cleanup failed: {errors}"
        if active_error is not None:
            raise BundleError(f"{active_error}; {detail}") from active_error
        fail(detail)


def reserve_bundle_id(output: Path, bundle_id: str) -> BundleReservation:
    token = secrets.token_hex(32)
    path = output / f".production-bootstrap-{bundle_id}.claim.json"
    try:
        write_private(
            path,
            canonical_json(
                {
                    "bundle_id": bundle_id,
                    "owner_pid": os.getpid(),
                    "schema_version": 1,
                    "token": token,
                },
                pretty=True,
            ),
        )
    except FileExistsError as exc:
        raise BundleError(f"bundle id is already reserved: {bundle_id}") from exc
    ownership = owned_path(path, is_directory=False)
    fsync_directory(output)
    return BundleReservation(ownership, token)


def create_publication_directory(path: Path) -> OwnedPath:
    try:
        path.mkdir(mode=0o700)
    except FileExistsError as exc:
        raise BundleError(f"refusing to overwrite an existing output: {path}") from exc
    ownership = owned_path(path, is_directory=True)
    fsync_directory(path.parent)
    return ownership


def publish_file_noreplace(source: Path, destination: Path) -> OwnedPath:
    source_metadata = source.lstat()
    if (
        source.is_symlink()
        or not stat.S_ISREG(source_metadata.st_mode)
        or source_metadata.st_nlink != 1
    ):
        fail(f"publication source is not one singly-linked regular file: {source}")
    try:
        os.link(source, destination, follow_symlinks=False)
    except FileExistsError as exc:
        raise BundleError(
            f"refusing to overwrite an existing output: {destination}"
        ) from exc
    except OSError as exc:
        raise BundleError(
            f"cannot publish output without overwriting: {destination}"
        ) from exc
    ownership = owned_path(destination, is_directory=False)
    try:
        if (ownership.device, ownership.inode) != (
            source_metadata.st_dev,
            source_metadata.st_ino,
        ):
            fail(f"published file identity differs from staging: {destination}")
        source.unlink()
        published_metadata = destination.lstat()
        if (published_metadata.st_dev, published_metadata.st_ino) != (
            ownership.device,
            ownership.inode,
        ) or published_metadata.st_nlink != 1:
            fail(f"published file is not singly linked: {destination}")
    except BaseException:
        cleanup_owned_paths([ownership])
        raise
    return ownership


def publish_bundle_directory(
    source: Path, destination: Path, owned: list[OwnedPath]
) -> None:
    directory_ownership = create_publication_directory(destination)
    owned.append(directory_ownership)
    for path in sorted(source.iterdir(), key=lambda item: item.name.encode("utf-8")):
        published = publish_file_noreplace(path, destination / path.name)
        owned.append(published)
    source.rmdir()
    fsync_directory(destination)
    fsync_directory(destination.parent)


def publish_ready_marker(
    *,
    output: Path,
    bundle_id: str,
    final_bundle: Path,
    final_transport: Path,
    release: str,
    revision: str,
    transport_sha: str,
) -> OwnedPath:
    ready = output / f"production-bootstrap-{bundle_id}.READY.json"
    try:
        write_private(
            ready,
            canonical_json(
                {
                    "artifact_directory": final_bundle.name,
                    "artifact_manifest_sha256": sha256_file(
                        final_bundle / "artifact-manifest.json"
                    ),
                    "bundle_id": bundle_id,
                    "release": release,
                    "schema_version": 1,
                    "status": "ready",
                    "transport": {
                        "file": f"transport/{final_transport.name}",
                        "sha256": transport_sha,
                    },
                    "vcs_ref": revision,
                },
                pretty=True,
            ),
        )
    except FileExistsError as exc:
        raise BundleError(f"refusing to overwrite an existing output: {ready}") from exc
    ownership = owned_path(ready, is_directory=False)
    fsync_directory(output)
    return ownership


def validate_arguments(args: argparse.Namespace) -> tuple[Path, Path, int, str, str]:
    repo = Path(os.path.abspath(args.repo_root))
    raw_output = Path(os.path.abspath(args.output_root))
    if raw_output.is_symlink():
        fail("output root must not be a symbolic link")
    resolved_repo = repo.resolve(strict=False)
    resolved_output = raw_output.resolve(strict=False)
    if resolved_output == resolved_repo or resolved_repo in resolved_output.parents:
        fail("output root must be outside the source repository")
    if RELEASE_RE.fullmatch(args.release) is None:
        fail("release is not an exact semantic version")
    if SAFE_IMAGE_SOURCE_RE.fullmatch(args.image_source) is None:
        fail("image source label is unsafe or empty")
    epoch = args.source_date_epoch
    if epoch < 0 or epoch > int(time.time()) + 300:
        fail("source-date-epoch is negative or implausibly in the future")
    if args.split_size_mib is not None and args.split_size_mib <= 0:
        fail("split-size-mib must be positive")
    bundle_id = args.bundle_id or dt.datetime.fromtimestamp(epoch, tz=dt.UTC).strftime(
        "%Y%m%dT%H%M%SZ"
    )
    if SAFE_BUNDLE_ID_RE.fullmatch(bundle_id) is None:
        fail("bundle-id must use YYYYMMDDTHHMMSSZ")
    generated_at = (
        dt.datetime.fromtimestamp(epoch, tz=dt.UTC).isoformat().replace("+00:00", "Z")
    )
    return repo, resolved_output, epoch, bundle_id, generated_at


def build_bundle(args: argparse.Namespace) -> dict[str, str]:
    repo, output, epoch, bundle_id, generated_at = validate_arguments(args)
    require_private_directory(output, create=True)
    transport_output = output / "transport"
    require_private_directory(transport_output, create=True)
    final_bundle = output / bundle_id
    final_transport = transport_output / f"production-bootstrap-{bundle_id}.tar"
    final_ready = output / f"production-bootstrap-{bundle_id}.READY.json"
    final_outputs = [
        final_bundle,
        final_transport,
        final_transport.with_suffix(".tar.sha256"),
        final_ready,
        transport_output / f"{final_transport.name}.parts.json",
        transport_output / f"{final_transport.name}.parts.sha256",
    ]
    final_outputs.extend(transport_output.glob(f"{final_transport.name}.part-*"))
    staging: Path | None = None
    published = False
    owned_paths: list[OwnedPath] = []
    owned_image_tags: list[OwnedImageTag] = []
    image_tags_cleaned = False
    reservation = reserve_bundle_id(output, bundle_id)
    owned_paths.append(reservation.ownership)
    try:
        for path in final_outputs:
            if path.exists() or path.is_symlink():
                fail(f"refusing to overwrite an existing output: {path}")

        initial_source = scan_source(repo)
        identity_manifest_raw = source_hash_manifest_bytes(initial_source)
        revision = sha256_bytes(identity_manifest_raw)
        if SHA256_RE.fullmatch(revision) is None:
            fail("source manifest did not produce a 64-hex revision")
        staging = Path(tempfile.mkdtemp(prefix=f".building-{bundle_id}-", dir=output))
        os.chmod(staging, 0o700)
        context = staging / "context"
        bundle = staging / "bundle"
        bundle.mkdir(mode=0o700)
        copy_normalized_source(repo, context, initial_source)
        compare_source_records(initial_source, scan_source(repo), "post-freeze")
        verify_normalized_source(context, initial_source)

        write_private(bundle / "source-files.list", source_list_bytes(initial_source))
        write_private(
            bundle / "source-files.sha256", source_checksum_bytes(initial_source)
        )
        write_private(
            bundle / "source-files.sha256.sha256",
            (
                f"{sha256_file(bundle / 'source-files.sha256')}  source-files.sha256\n"
            ).encode("ascii"),
        )
        write_private(bundle / "source-files.manifest", identity_manifest_raw)
        write_private(
            bundle / "source-files.manifest.sha256",
            f"{revision}  source-files.manifest\n".encode("ascii"),
        )
        write_private(
            bundle / "source-archive.list",
            source_archive_list_bytes(initial_source),
        )
        create_source_archive(context, initial_source, bundle / "source.tar.gz", epoch)
        write_private(
            bundle / "source.tar.gz.sha256",
            f"{sha256_file(bundle / 'source.tar.gz')}  source.tar.gz\n".encode("ascii"),
        )
        write_private(
            bundle / "source-extraction-verify.log",
            verify_source_archive(bundle / "source.tar.gz", initial_source, epoch),
        )
        verifier_source = context / "deploy/scripts/verify-unsigned-bootstrap-bundle.py"
        verifier_record = next(
            (
                record
                for record in initial_source
                if record.path == "deploy/scripts/verify-unsigned-bootstrap-bundle.py"
            ),
            None,
        )
        if verifier_record is None:
            fail("frozen source has no offline bundle verifier")
        verifier_raw, verifier_metadata = stable_file_bytes(verifier_source)
        if (
            len(verifier_raw) != verifier_record.size
            or sha256_bytes(verifier_raw) != verifier_record.sha256
            or stat.S_IMODE(verifier_metadata.st_mode) != 0o555
        ):
            fail("frozen offline verifier differs from its source identity")
        write_private(bundle / "verify-unsigned-bootstrap-bundle.py", verifier_raw)

        docker_versions = docker_version_evidence(args.docker)
        load_log = bundle / "docker-load-verification.log"
        write_private(load_log, b"")
        images: dict[str, dict[str, Any]] = {}
        mapper = context / "deploy/scripts/map-oci-image-archive.py"
        for component in COMPONENTS:
            tag = image_tag_for_build(component, args.release, revision, bundle_id)
            images[component] = build_component(
                component=component,
                tag=tag,
                docker=args.docker,
                python=args.python,
                mapper=mapper,
                context=context,
                bundle=bundle,
                release=args.release,
                revision=revision,
                image_source=args.image_source,
                epoch=epoch,
                docker_versions=docker_versions,
                load_log=load_log,
                owned_image_tags=owned_image_tags,
            )
        image_ids = [images[name]["daemon_image_id"] for name in COMPONENTS]
        if len(set(image_ids)) != len(image_ids):
            fail("the three admitted images do not have distinct daemon identities")

        pwa_runtime = verify_pwa_runtime(args.docker, images["pwa"]["daemon_image_id"])
        pwa_runtime["image_id"] = images["pwa"]["daemon_image_id"]
        pwa_runtime["image_tag"] = images["pwa"]["tag"]
        write_private(
            bundle / "pwa-runtime-verification.json",
            canonical_json(pwa_runtime, pretty=True),
        )
        postgres_roundtrip = verify_postgres_roundtrip(
            args.docker,
            images["postgres-tools"]["tag"],
            images["postgres-tools"]["daemon_image_id"],
        )
        write_private(
            bundle / "postgres-tools-version.txt",
            "".join(
                f"{line}\n" for line in postgres_roundtrip["tools"]["client_versions"]
            ).encode("ascii"),
        )
        write_private(
            bundle / "postgres-tools-dump-restore-verification.json",
            canonical_json(postgres_roundtrip, pretty=True),
        )

        write_private(
            bundle / "bootstrap-images.sha256",
            checksum_lines(bundle, [ARCHIVE_NAMES[name] for name in COMPONENTS]),
        )
        write_private(
            bundle / "transport-SHA256SUMS",
            checksum_lines(
                bundle,
                ["source.tar.gz", *(ARCHIVE_NAMES[name] for name in COMPONENTS)],
            ),
        )
        manifest = bundle_manifest(
            release=args.release,
            revision=revision,
            generated_at=generated_at,
            records=initial_source,
            bundle=bundle,
            images=images,
            pwa_runtime=pwa_runtime,
            postgres_roundtrip=postgres_roundtrip,
        )
        write_private(
            bundle / "artifact-manifest.json", canonical_json(manifest, pretty=True)
        )
        write_private(
            bundle / "artifact-manifest.sha256",
            f"{sha256_file(bundle / 'artifact-manifest.json')}  artifact-manifest.json\n".encode(
                "ascii"
            ),
        )
        write_private(
            bundle / "artifacts-manifest.json", canonical_json(manifest, pretty=True)
        )
        write_private(
            bundle / "artifacts-manifest.sha256",
            f"{sha256_file(bundle / 'artifacts-manifest.json')}  artifacts-manifest.json\n".encode(
                "ascii"
            ),
        )
        write_bundle_checksums(bundle)
        verify_normalized_source(context, initial_source)
        compare_source_records(initial_source, scan_source(repo), "pre-package")

        transport_temp = staging / final_transport.name
        create_transport_tar(bundle, transport_temp, epoch)
        verify_transport_tar(transport_temp, bundle, epoch)
        transport_sha = sha256_file(transport_temp)
        checksum_temp = staging / f"{final_transport.name}.sha256"
        write_private(
            checksum_temp,
            f"{transport_sha}  {final_transport.name}\n".encode("ascii"),
        )
        split_paths: list[Path] = []
        if args.split_size_mib is not None:
            split_paths = split_transport(
                transport_temp, args.split_size_mib * 1024 * 1024, staging
            )

        verify_bundle_checksums(bundle)
        verify_transport_tar(transport_temp, bundle, epoch)
        verify_normalized_source(context, initial_source)
        compare_source_records(initial_source, scan_source(repo), "pre-publish")
        cleanup_owned_image_tags(args.docker, owned_image_tags)
        image_tags_cleaned = True

        owned_paths.append(publish_file_noreplace(transport_temp, final_transport))
        owned_paths.append(
            publish_file_noreplace(
                checksum_temp, final_transport.with_suffix(".tar.sha256")
            )
        )
        for part in split_paths:
            destination = transport_output / part.name
            owned_paths.append(publish_file_noreplace(part, destination))
        for suffix in ("parts.json", "parts.sha256"):
            candidate = staging / f"{final_transport.name}.{suffix}"
            if candidate.exists():
                destination = transport_output / candidate.name
                owned_paths.append(publish_file_noreplace(candidate, destination))
        fsync_directory(transport_output)
        publish_bundle_directory(bundle, final_bundle, owned_paths)
        owned_paths.append(
            publish_ready_marker(
                output=output,
                bundle_id=bundle_id,
                final_bundle=final_bundle,
                final_transport=final_transport,
                release=args.release,
                revision=revision,
                transport_sha=transport_sha,
            )
        )
        published = True
        return {
            "artifact_directory": str(final_bundle),
            "ready_marker": str(final_ready),
            "release": args.release,
            "transport": str(final_transport),
            "transport_sha256": transport_sha,
            "vcs_ref": revision,
        }
    finally:
        finalize_build_cleanup(
            docker=args.docker,
            image_tags_cleaned=image_tags_cleaned,
            owned_image_tags=owned_image_tags,
            staging=staging,
            published=published,
            owned_paths=owned_paths,
            output=output,
            transport_output=transport_output,
            active_error=sys.exception(),
        )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Build a private linux/amd64 unsigned bootstrap bundle from one stable source snapshot."
    )
    commands = parser.add_subparsers(dest="command", required=True)
    build = commands.add_parser("build")
    build.add_argument("--repo-root", type=Path, required=True)
    build.add_argument("--output-root", type=Path, required=True)
    build.add_argument("--release", required=True)
    build.add_argument("--source-date-epoch", type=int, required=True)
    build.add_argument("--bundle-id")
    build.add_argument("--image-source", default=IMAGE_SOURCE_DEFAULT)
    build.add_argument("--docker", default="docker")
    build.add_argument("--python", default=sys.executable)
    build.add_argument("--split-size-mib", type=int)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    try:
        args = build_parser().parse_args(argv)
        if args.command != "build":
            fail("unsupported command")
        result = build_bundle(args)
    except BundleError as exc:
        print(f"build-unsigned-bootstrap-bundle: {exc}", file=sys.stderr)
        return 1
    sys.stdout.buffer.write(canonical_json(result, pretty=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
