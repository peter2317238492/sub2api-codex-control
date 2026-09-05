"""Build and verify deterministic, signed-lock-bound source bundles."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import re
import stat
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path, PurePosixPath
from typing import Any, NoReturn

ARCHIVE_FILENAME = "source.tar"
MANIFEST_FILENAME = "source-files.manifest"
ATTESTATION_FILENAME = "source-attestation.json"
SCHEMA_ID = "https://sub2api-codex.invalid/schemas/source-bundle-v1.json"
FORMAT_VERSION = 1
MAX_MANIFEST_BYTES = 32 * 1024 * 1024
MAX_ATTESTATION_BYTES = 64 * 1024
MAX_ARCHIVE_BYTES = 256 * 1024 * 1024
MAX_SOURCE_FILE_BYTES = 64 * 1024 * 1024
MAX_SOURCE_BYTES = 240 * 1024 * 1024
MAX_SOURCE_FILES = 10_000
MAX_SOURCE_DATE_EPOCH = (1 << 32) - 1
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
VERSION_RE = re.compile(
    r"^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
    r"(?:-[0-9A-Za-z.-]+)?$"
)
PORTABLE_PATH_RE = re.compile(r"^[A-Za-z0-9._+@/-]+$")
ALLOWED_TOP_LEVEL = {
    ".editorconfig",
    ".env.example",
    ".gitattributes",
    ".github",
    ".gitignore",
    "CONTRIBUTING.md",
    "LICENSE",
    "NOTICE",
    "README.md",
    "README.zh-CN.md",
    "SECURITY.md",
    "THIRD_PARTY_NOTICES.md",
    "apps",
    "connector",
    "deploy",
    "docs",
    "migrations",
    "package.json",
    "packages",
    "pnpm-lock.yaml",
    "pnpm-workspace.yaml",
    "scripts",
    "security",
    "tests",
    "third_party",
    "tsconfig.base.json",
    "versions.lock.json",
}
FORBIDDEN_COMPONENTS = {
    ".cache",
    ".git",
    ".pnpm-store",
    ".pytest_cache",
    ".ruff_cache",
    ".venv",
    "__pycache__",
    "artifacts",
    "backups",
    "coverage",
    "dist",
    "evidence",
    "node_modules",
    "receipts",
    "reports",
    "secrets",
}
ALLOWED_PLACEHOLDER_PATHS = {
    "deploy/docker-compose/backups/.gitignore",
    "deploy/docker-compose/backups/README.md",
    "deploy/docker-compose/secrets/.gitignore",
    "deploy/docker-compose/secrets/README.md",
    "deploy/monitoring/evidence/.gitignore",
    "tests/e2e/reports/.gitignore",
    "tests/e2e/reports/README.md",
}
REQUIRED_SERVER_SOURCE_PATHS = {
    "LICENSE",
    "NOTICE",
    "THIRD_PARTY_NOTICES.md",
    "apps/control-api/src/control_api/connector_release.py",
    "connector/packaging/verify-package-contents.sh",
    "connector/internal/config/config.go",
    "connector/internal/protocol/protocol.go",
    "connector/release/connector-aggregate-verification-receipt.schema.json",
    "connector/release/connector-platform-verification-receipt.schema.json",
    "connector/release/connector-public-release-descriptor.schema.json",
    "connector/release/connector-release-metadata.schema.json",
    "connector/release/manifest.schema.json",
    "connector/release/release-config.json",
    "connector/release/release.py",
    "deploy/docker-compose/.env.example",
    "deploy/docker-compose/compose.production.yaml",
    "deploy/docker-compose/compose.yaml",
    "deploy/nginx/api-security-headers.conf",
    "deploy/nginx/browser-security-headers.conf",
    "deploy/nginx/codex-control-access.logrotate",
    "deploy/nginx/hide-upstream-security-headers.conf",
    "deploy/nginx/http-context.conf",
    "deploy/nginx/pwa-nginx.conf",
    "deploy/nginx/server-locations.conf",
    "deploy/nginx/smoke-edge-nginx.conf",
    "deploy/nginx/sub2api-logout-location.conf",
    "deploy/release/control-images-config.json",
    "deploy/release/control-images-lock.schema.json",
    "deploy/release/control_images.py",
    "deploy/release/source-bundle.schema.json",
    "deploy/release/source_bundle.py",
    "deploy/release/verify-control-images.sh",
    "deploy/schemas/production-recovery-receipt.schema.json",
    "deploy/scripts/backup-production-state.py",
    "deploy/scripts/bootstrap-admission.py",
    "deploy/scripts/deploy-production.sh",
    "deploy/scripts/deployment-admission.py",
    "deploy/scripts/map-oci-image-archive.py",
    "deploy/scripts/pg-restore-via-container.sh",
    "deploy/scripts/probe-sub2api-auth-contract.py",
    "deploy/scripts/production-recovery.py",
    "deploy/scripts/verify-sub2api-runtime.py",
    "deploy/scripts/verify-sub2api-runtime.sh",
    "deploy/server-package/INSTALL.md",
    "deploy/server-package/OCI-TOOLCHAIN.md",
    "deploy/server-package/bin/sub2api-control-install",
    "deploy/server-package/bin/sub2api-control-rollback",
    "deploy/server-package/bin/sub2api-control-uninstall",
    "deploy/server-package/bin/sub2api-control-upgrade",
    "deploy/server-package/bin/sub2api-control-verify",
    "deploy/server-package/config/operator.env.example",
    "deploy/server-package/lifecycle.py",
    "deploy/server-package/oci_toolchain.py",
    "deploy/server-package/server-packages.schema.json",
    "deploy/server-package/server_package.py",
    "deploy/server-package/toolchain.json",
    "docs/contracts/sub2api-auth.v0.2.0.json",
    "migrations/README.md",
    "migrations/alembic.ini",
    "migrations/env.py",
    "migrations/script.py.mako",
    "migrations/versions/20260713_0001_control_plane.py",
    "migrations/versions/20260713_0002_realtime_control.py",
    "migrations/versions/20260713_0003_durable_outbox.py",
    "migrations/versions/20260723_0004_owner_event_cursors.py",
    "migrations/versions/20260723_0005_retention_indexes.py",
    "migrations/versions/20260730_0006_approval_reconciliation.py",
    "migrations/versions/20260730_0007_retry_safe_pairing.py",
    "migrations/versions/20260731_0008_approval_request_identity.py",
    "packages/appserver-schema/generated/json-schema/codex_app_server_protocol.v2.schemas.json",
    "packages/control-protocol/fixtures/json-budget-vectors.json",
    "packages/control-protocol/fixtures/rpc-policy.json",
    "packages/control-protocol/fixtures/wire-envelopes.json",
    "packages/control-protocol/schema/control-envelope.schema.json",
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
}
REQUIRED_SOURCE_PATHS = REQUIRED_SERVER_SOURCE_PATHS | {
    "LICENSE",
    "NOTICE",
    "THIRD_PARTY_NOTICES.md",
}


class SourceBundleError(RuntimeError):
    pass


def fail(message: str) -> NoReturn:
    raise SourceBundleError(message)


def canonical_json(value: object) -> bytes:
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


def strict_json(raw: bytes, label: str) -> Any:
    def reject_duplicate(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                fail(f"{label} contains duplicate JSON key {key!r}")
            value[key] = item
        return value

    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=reject_duplicate)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise SourceBundleError(f"{label} is not valid JSON") from error


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while block := source.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def require_sha256(value: str, label: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        fail(f"{label} must be one lowercase SHA-256")
    return value


def validate_repository(value: str) -> str:
    if (
        re.fullmatch(r"https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", value)
        is None
    ):
        fail("source repository must be one canonical HTTPS GitHub repository")
    return value


def validate_release(value: str) -> str:
    if VERSION_RE.fullmatch(value) is None:
        fail("source release is invalid")
    return value


def validate_path(value: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or not value.isascii()
        or PORTABLE_PATH_RE.fullmatch(value) is None
        or "\\" in value
    ):
        fail("source path is not portable ASCII")
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or value != path.as_posix()
        or any(component in {"", ".", ".."} for component in path.parts)
    ):
        fail("source path is not canonical and relative")
    if path.parts[0] not in ALLOWED_TOP_LEVEL:
        fail(f"source path has an unexpected top-level entry: {path.parts[0]}")
    if (
        any(component in FORBIDDEN_COMPONENTS for component in path.parts)
        and value not in ALLOWED_PLACEHOLDER_PATHS
    ):
        fail(f"source path enters a forbidden generated/private directory: {value}")
    return value


def require_owned_directory(path: Path, label: str) -> None:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise SourceBundleError(f"cannot inspect {label}") from error
    if not stat.S_ISDIR(metadata.st_mode):
        fail(f"{label} must be one real directory")
    if metadata.st_uid != os.geteuid():
        fail(f"{label} must be owned by the current user")
    if stat.S_IMODE(metadata.st_mode) & 0o022:
        fail(f"{label} must not be group or world writable")


def run_git(repo: Path, *arguments: str) -> bytes:
    environment = {
        key: value for key, value in os.environ.items() if not key.startswith("GIT_")
    }
    environment.update(
        {
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_OPTIONAL_LOCKS": "0",
            "LC_ALL": "C",
        }
    )
    try:
        result = subprocess.run(
            ["git", "--no-replace-objects", "-C", str(repo), *arguments],
            check=False,
            capture_output=True,
            env=environment,
        )
    except OSError as error:
        raise SourceBundleError("git is required to build a source bundle") from error
    if result.returncode != 0:
        fail("git rejected the source checkout")
    return result.stdout


def validate_source_closure(paths: set[str], component_manifest_raw: bytes) -> None:
    missing_required = REQUIRED_SOURCE_PATHS - paths
    if missing_required:
        fail(
            f"source inventory lacks required release files: {sorted(missing_required)}"
        )
    component_manifest = strict_json(
        component_manifest_raw,
        "third-party component manifest",
    )
    if not isinstance(component_manifest, dict) or not isinstance(
        component_manifest.get("components"), list
    ):
        fail("third-party component manifest has an unexpected schema")
    declared_license_paths: set[str] = set()
    for component in component_manifest["components"]:
        if not isinstance(component, dict) or not isinstance(
            component.get("license_files"), list
        ):
            fail("third-party component manifest has an invalid license declaration")
        for license_record in component["license_files"]:
            if not isinstance(license_record, dict) or not isinstance(
                license_record.get("path"), str
            ):
                fail("third-party component manifest has an invalid license path")
            license_path = validate_path(license_record["path"])
            if not license_path.startswith("third_party/licenses/"):
                fail(
                    "third-party component license path is outside the license directory"
                )
            declared_license_paths.add(license_path)
    missing_licenses = declared_license_paths - paths
    if missing_licenses:
        fail(
            f"source inventory lacks declared third-party licenses: {sorted(missing_licenses)}"
        )


def git_source_records(
    repo: Path, expected_commit: str
) -> tuple[list[dict[str, Any]], dict[str, bytes]]:
    root = Path(
        run_git(repo, "rev-parse", "--show-toplevel").decode().strip()
    ).resolve()
    if root != repo.resolve():
        fail("source root is not the Git worktree root")
    commit = run_git(repo, "rev-parse", "HEAD").decode().strip()
    if commit != expected_commit or COMMIT_RE.fullmatch(commit) is None:
        fail("source checkout HEAD differs from the expected commit")
    if run_git(repo, "status", "--porcelain=v1", "--untracked-files=no", "-z"):
        fail("tracked source checkout is dirty")

    raw = run_git(repo, "ls-tree", "-r", "-z", "--full-tree", expected_commit)
    records: list[dict[str, Any]] = []
    content_by_path: dict[str, bytes] = {}
    seen: set[str] = set()
    total = 0
    for item in raw.split(b"\0"):
        if not item:
            continue
        try:
            metadata, path_raw = item.split(b"\t", 1)
            mode_raw, object_type, object_id = metadata.split(b" ", 2)
            path_text = path_raw.decode("ascii")
        except (ValueError, UnicodeDecodeError):
            fail("committed source tree is malformed or non-ASCII")
        if object_type != b"blob" or mode_raw not in {b"100644", b"100755"}:
            fail(
                f"source inventory contains a link, submodule, or unsupported mode: {path_text}"
            )
        path_text = validate_path(path_text)
        if path_text in seen:
            fail(f"source inventory repeats {path_text}")
        seen.add(path_text)
        path = repo / Path(*PurePosixPath(path_text).parts)
        metadata_value = path.lstat()
        expected_executable = mode_raw == b"100755"
        if not stat.S_ISREG(metadata_value.st_mode):
            fail(f"source entry is not a regular file: {path_text}")
        if metadata_value.st_nlink != 1:
            fail(f"source entry has more than one hard link: {path_text}")
        if bool(metadata_value.st_mode & stat.S_IXUSR) != expected_executable:
            fail(f"source executable mode differs from Git: {path_text}")
        if metadata_value.st_size > MAX_SOURCE_FILE_BYTES:
            fail(f"source entry exceeds the per-file size limit: {path_text}")
        worktree_file = path.read_bytes()
        if len(worktree_file) != metadata_value.st_size:
            fail(f"source entry changed while read: {path_text}")
        raw_file = run_git(repo, "cat-file", "blob", object_id.decode("ascii"))
        if worktree_file != raw_file:
            fail(f"source entry differs from the committed Git object: {path_text}")
        final = path.lstat()
        if (
            final.st_dev,
            final.st_ino,
            final.st_mode,
            final.st_nlink,
            final.st_size,
            final.st_mtime_ns,
            final.st_ctime_ns,
        ) != (
            metadata_value.st_dev,
            metadata_value.st_ino,
            metadata_value.st_mode,
            metadata_value.st_nlink,
            metadata_value.st_size,
            metadata_value.st_mtime_ns,
            metadata_value.st_ctime_ns,
        ):
            fail(f"source entry changed while read: {path_text}")
        total += len(raw_file)
        if total > MAX_SOURCE_BYTES or len(records) >= MAX_SOURCE_FILES:
            fail("source inventory exceeds its size or file-count limit")
        records.append(
            {
                "mode": "0555" if expected_executable else "0444",
                "path": path_text,
                "sha256": sha256_bytes(raw_file),
                "size": len(raw_file),
            }
        )
        content_by_path[path_text] = raw_file
    records.sort(key=lambda value: value["path"])
    if not records:
        fail("source inventory is empty")
    component_manifest_raw = content_by_path.get("third_party/components.json")
    if component_manifest_raw is None:
        fail("source inventory lacks the third-party component manifest")
    validate_source_closure(seen, component_manifest_raw)
    if run_git(repo, "status", "--porcelain=v1", "--untracked-files=no", "-z"):
        fail("tracked source checkout changed while the inventory was read")
    if run_git(repo, "rev-parse", "HEAD").decode().strip() != expected_commit:
        fail("source checkout HEAD changed while the inventory was read")
    return records, content_by_path


def manifest_bytes(records: list[dict[str, Any]]) -> bytes:
    return b"".join(canonical_json(record) for record in records)


def _tar_octal(value: int, width: int, label: str) -> bytes:
    if type(value) is not int or value < 0:
        fail(f"source archive {label} is invalid")
    encoded = f"{value:0{width - 1}o}".encode("ascii")
    if len(encoded) != width - 1:
        fail(f"source archive {label} exceeds the USTAR field")
    return encoded + b"\0"


def _ustar_path(value: str) -> tuple[bytes, bytes]:
    encoded = value.encode("ascii")
    if len(encoded) <= 100:
        return encoded, b""
    for index in range(len(encoded) - 1, -1, -1):
        if encoded[index : index + 1] != b"/":
            continue
        prefix = encoded[:index]
        name = encoded[index + 1 :]
        if len(prefix) <= 155 and 0 < len(name) <= 100:
            return name, prefix
    fail(f"source path cannot be represented in canonical USTAR: {value}")


def _ustar_header(record: dict[str, Any], source_date_epoch: int) -> bytes:
    name, prefix = _ustar_path(record["path"])
    header = bytearray(512)
    header[0 : len(name)] = name
    header[100:108] = _tar_octal(int(record["mode"], 8), 8, "mode")
    header[108:116] = _tar_octal(0, 8, "uid")
    header[116:124] = _tar_octal(0, 8, "gid")
    header[124:136] = _tar_octal(record["size"], 12, "size")
    header[136:148] = _tar_octal(source_date_epoch, 12, "mtime")
    header[148:156] = b"        "
    header[156:157] = tarfile.REGTYPE
    header[257:263] = b"ustar\0"
    header[263:265] = b"00"
    header[345 : 345 + len(prefix)] = prefix
    checksum = sum(header)
    checksum_field = f"{checksum:06o}".encode("ascii") + b"\0 "
    if len(checksum_field) != 8:
        fail("source archive checksum exceeds the USTAR field")
    header[148:156] = checksum_field
    return bytes(header)


def write_archive_stream(
    destination: Any,
    records: list[dict[str, Any]],
    content_by_path: dict[str, bytes],
    source_date_epoch: int,
) -> None:
    for record in records:
        content = content_by_path[record["path"]]
        if len(content) != record["size"]:
            fail(f"source content size differs while writing: {record['path']}")
        destination.write(_ustar_header(record, source_date_epoch))
        destination.write(content)
        padding = (-len(content)) % 512
        if padding:
            destination.write(b"\0" * padding)
    destination.write(b"\0" * 1024)


def write_archive(
    target: Path,
    records: list[dict[str, Any]],
    content_by_path: dict[str, bytes],
    source_date_epoch: int,
) -> None:
    with target.open("xb") as destination:
        write_archive_stream(destination, records, content_by_path, source_date_epoch)


def atomic_write(path: Path, content: bytes) -> None:
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as destination:
            destination.write(content)
            destination.flush()
            os.fsync(destination.fileno())
        os.chmod(temporary, 0o644)
        if path.exists():
            fail(f"source bundle output already exists: {path.name}")
        os.replace(temporary, path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def build_bundle(
    repo: Path,
    output: Path,
    *,
    release: str,
    repository: str,
    commit: str,
    source_date_epoch: int,
) -> dict[str, Any]:
    if not repo.is_absolute() or not output.is_absolute():
        fail("source and output paths must be absolute existing directories")
    require_owned_directory(repo, "source repository")
    require_owned_directory(output, "source output directory")
    validate_release(release)
    validate_repository(repository)
    if COMMIT_RE.fullmatch(commit) is None:
        fail("source commit must be one lowercase 40-hex Git commit")
    if not 0 < source_date_epoch <= MAX_SOURCE_DATE_EPOCH:
        fail("source date epoch is outside the portable USTAR range")
    records, content_by_path = git_source_records(repo, commit)
    manifest = manifest_bytes(records)
    if len(manifest) > MAX_MANIFEST_BYTES:
        fail("source manifest exceeds its size limit")
    manifest_path = output / MANIFEST_FILENAME
    archive_path = output / ARCHIVE_FILENAME
    attestation_path = output / ATTESTATION_FILENAME
    for path in (manifest_path, archive_path, attestation_path):
        if path.exists():
            fail(f"source bundle output already exists: {path.name}")
    atomic_write(manifest_path, manifest)
    temporary_archive = output / f".{ARCHIVE_FILENAME}.{os.getpid()}"
    try:
        write_archive(temporary_archive, records, content_by_path, source_date_epoch)
        if temporary_archive.stat().st_size > MAX_ARCHIVE_BYTES:
            fail("source archive exceeds its size limit")
        os.chmod(temporary_archive, 0o644)
        os.replace(temporary_archive, archive_path)
    finally:
        try:
            temporary_archive.unlink()
        except FileNotFoundError:
            pass
    attestation = {
        "$schema": SCHEMA_ID,
        "format_version": FORMAT_VERSION,
        "release": release,
        "source": {"commit": commit, "repository": repository},
        "source_date_epoch": source_date_epoch,
        "file_count": len(records),
        "total_bytes": sum(record["size"] for record in records),
        "manifest": {
            "filename": MANIFEST_FILENAME,
            "sha256": sha256_file(manifest_path),
            "size": manifest_path.stat().st_size,
        },
        "archive": {
            "filename": ARCHIVE_FILENAME,
            "sha256": sha256_file(archive_path),
            "size": archive_path.stat().st_size,
        },
    }
    atomic_write(attestation_path, canonical_json(attestation))
    return attestation


def require_release_file(path: Path, label: str, maximum: int) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise SourceBundleError(f"cannot securely open {label}") from error
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            fail(f"{label} must be one regular non-hard-linked file")
        if metadata.st_uid != os.geteuid():
            fail(f"{label} must be owned by the verification user")
        if metadata.st_mode & 0o022:
            fail(f"{label} must not be group or world writable")
        if metadata.st_size <= 0 or metadata.st_size > maximum:
            fail(f"{label} size is outside the accepted range")
        blocks: list[bytes] = []
        total = 0
        while block := os.read(descriptor, min(1024 * 1024, maximum + 1 - total)):
            total += len(block)
            if total > maximum:
                fail(f"{label} grew past its accepted size while read")
            blocks.append(block)
        final = os.fstat(descriptor)
        before = (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_mode,
            metadata.st_nlink,
            metadata.st_uid,
            metadata.st_size,
            metadata.st_mtime_ns,
            metadata.st_ctime_ns,
        )
        after = (
            final.st_dev,
            final.st_ino,
            final.st_mode,
            final.st_nlink,
            final.st_uid,
            final.st_size,
            final.st_mtime_ns,
            final.st_ctime_ns,
        )
        if before != after or total != metadata.st_size:
            fail(f"{label} changed while read")
        return b"".join(blocks)
    finally:
        os.close(descriptor)


def parse_manifest(raw: bytes) -> list[dict[str, Any]]:
    if not raw.endswith(b"\n") or b"\r" in raw or b"\0" in raw:
        fail("source manifest is not canonical newline-delimited JSON")
    records: list[dict[str, Any]] = []
    seen: set[str] = set()
    for line in raw.splitlines():
        value = strict_json(line, "source manifest entry")
        if not isinstance(value, dict) or set(value) != {
            "mode",
            "path",
            "sha256",
            "size",
        }:
            fail("source manifest entry has an unexpected schema")
        path = validate_path(value["path"])
        if path in seen:
            fail(f"source manifest repeats {path}")
        seen.add(path)
        if value["mode"] not in {"0444", "0555"}:
            fail(f"source manifest mode is invalid: {path}")
        require_sha256(value["sha256"], f"source manifest digest for {path}")
        if (
            type(value["size"]) is not int
            or not 0 <= value["size"] <= MAX_SOURCE_FILE_BYTES
        ):
            fail(f"source manifest size is invalid: {path}")
        if canonical_json(value).rstrip(b"\n") != line:
            fail("source manifest entry is not canonical JSON")
        records.append(value)
    if not records or len(records) > MAX_SOURCE_FILES:
        fail("source manifest file count is outside the accepted range")
    if [record["path"] for record in records] != sorted(seen):
        fail("source manifest entries are not sorted")
    if sum(record["size"] for record in records) > MAX_SOURCE_BYTES:
        fail("source manifest total size exceeds the accepted range")
    return records


def validate_attestation(
    value: Any, *, release: str, repository: str, commit: str
) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {
        "$schema",
        "format_version",
        "release",
        "source",
        "source_date_epoch",
        "file_count",
        "total_bytes",
        "manifest",
        "archive",
    }:
        fail("source attestation has an unexpected schema")
    if value["$schema"] != SCHEMA_ID or value["format_version"] != FORMAT_VERSION:
        fail("source attestation schema or format is unsupported")
    if value["release"] != validate_release(release):
        fail("source attestation release differs from external policy")
    if value["source"] != {
        "commit": commit,
        "repository": validate_repository(repository),
    }:
        fail("source attestation identity differs from external policy")
    if COMMIT_RE.fullmatch(commit) is None:
        fail("expected source commit is invalid")
    if (
        type(value["source_date_epoch"]) is not int
        or not 0 < value["source_date_epoch"] <= MAX_SOURCE_DATE_EPOCH
    ):
        fail("source attestation epoch is invalid")
    if (
        type(value["file_count"]) is not int
        or not 0 < value["file_count"] <= MAX_SOURCE_FILES
    ):
        fail("source attestation file count is invalid")
    if (
        type(value["total_bytes"]) is not int
        or not 0 <= value["total_bytes"] <= MAX_SOURCE_BYTES
    ):
        fail("source attestation byte count is invalid")
    for name, filename, maximum in (
        ("manifest", MANIFEST_FILENAME, MAX_MANIFEST_BYTES),
        ("archive", ARCHIVE_FILENAME, MAX_ARCHIVE_BYTES),
    ):
        record = value[name]
        if not isinstance(record, dict) or set(record) != {
            "filename",
            "sha256",
            "size",
        }:
            fail(f"source attestation {name} record is invalid")
        if record["filename"] != filename:
            fail(f"source attestation {name} filename is invalid")
        require_sha256(record["sha256"], f"source attestation {name} digest")
        if type(record["size"]) is not int or not 0 < record["size"] <= maximum:
            fail(f"source attestation {name} size is invalid")
    return value


def validate_archive(raw: bytes, records: list[dict[str, Any]], epoch: int) -> bytes:
    expected = {record["path"]: record for record in records}
    seen: set[str] = set()
    content_by_path: dict[str, bytes] = {}
    component_manifest_raw: bytes | None = None

    def open_archive() -> tarfile.TarFile:
        try:
            return tarfile.open(fileobj=io.BytesIO(raw), mode="r:")
        except (OSError, tarfile.TarError) as error:
            raise SourceBundleError(
                "source archive is not a valid USTAR archive"
            ) from error

    with open_archive() as archive:
        for index, member in enumerate(archive):
            path = validate_path(member.name)
            if index >= len(records) or path != records[index]["path"]:
                fail("source archive members are not in manifest order")
            if path in seen:
                fail(f"source archive repeats {path}")
            seen.add(path)
            record = expected.get(path)
            if record is None:
                fail(f"source archive has an unlisted member: {path}")
            if member.type != tarfile.REGTYPE:
                fail(f"source archive member is not a regular file: {path}")
            if (
                member.mode != int(record["mode"], 8)
                or member.uid != 0
                or member.gid != 0
                or member.uname != ""
                or member.gname != ""
                or member.mtime != epoch
                or member.size != record["size"]
            ):
                fail(f"source archive metadata differs from the manifest: {path}")
            source = archive.extractfile(member)
            if source is None:
                fail(f"source archive member cannot be read: {path}")
            digest = hashlib.sha256()
            total = 0
            captured: list[bytes] = []
            while block := source.read(1024 * 1024):
                total += len(block)
                if total > record["size"]:
                    fail(f"source archive member exceeds its declared size: {path}")
                digest.update(block)
                captured.append(block)
            if total != record["size"] or digest.hexdigest() != record["sha256"]:
                fail(f"source archive content differs from the manifest: {path}")
            content = b"".join(captured)
            content_by_path[path] = content
            if path == "third_party/components.json":
                component_manifest_raw = content
    if seen != set(expected):
        fail("source archive is missing manifest entries")
    if component_manifest_raw is None:
        fail("source archive lacks the third-party component manifest")
    canonical = io.BytesIO()
    write_archive_stream(canonical, records, content_by_path, epoch)
    if canonical.getvalue() != raw:
        fail("source archive is not the canonical deterministic encoding")
    return component_manifest_raw


def verify_bundle(
    bundle_dir: Path,
    *,
    release: str,
    repository: str,
    commit: str,
    attestation_sha256: str,
    manifest_sha256: str,
    archive_sha256: str,
) -> dict[str, Any]:
    if not bundle_dir.is_absolute():
        fail("source bundle directory must be an absolute existing directory")
    require_owned_directory(bundle_dir, "source bundle directory")
    attestation_path = bundle_dir / ATTESTATION_FILENAME
    manifest_path = bundle_dir / MANIFEST_FILENAME
    archive_path = bundle_dir / ARCHIVE_FILENAME
    attestation_raw = require_release_file(
        attestation_path, "source attestation", MAX_ATTESTATION_BYTES
    )
    manifest_raw = require_release_file(
        manifest_path, "source manifest", MAX_MANIFEST_BYTES
    )
    archive_raw = require_release_file(
        archive_path, "source archive", MAX_ARCHIVE_BYTES
    )
    if sha256_bytes(attestation_raw) != require_sha256(
        attestation_sha256, "expected source attestation digest"
    ):
        fail("source attestation differs from the signed digest")
    if sha256_bytes(manifest_raw) != require_sha256(
        manifest_sha256, "expected source manifest digest"
    ):
        fail("source manifest differs from the signed digest")
    if sha256_bytes(archive_raw) != require_sha256(
        archive_sha256, "expected source archive digest"
    ):
        fail("source archive differs from the signed digest")
    attestation = validate_attestation(
        strict_json(attestation_raw, "source attestation"),
        release=release,
        repository=repository,
        commit=commit,
    )
    if canonical_json(attestation) != attestation_raw:
        fail("source attestation is not canonical JSON")
    if attestation["manifest"] != {
        "filename": MANIFEST_FILENAME,
        "sha256": manifest_sha256,
        "size": len(manifest_raw),
    }:
        fail("source attestation manifest binding differs")
    archive_size = len(archive_raw)
    if attestation["archive"] != {
        "filename": ARCHIVE_FILENAME,
        "sha256": archive_sha256,
        "size": archive_size,
    }:
        fail("source attestation archive binding differs")
    records = parse_manifest(manifest_raw)
    if attestation["file_count"] != len(records) or attestation["total_bytes"] != sum(
        record["size"] for record in records
    ):
        fail("source attestation inventory totals differ")
    component_manifest_raw = validate_archive(
        archive_raw, records, attestation["source_date_epoch"]
    )
    validate_source_closure(
        {record["path"] for record in records}, component_manifest_raw
    )
    return {
        "archive_sha256": archive_sha256,
        "attestation_sha256": attestation_sha256,
        "commit": commit,
        "file_count": len(records),
        "manifest_sha256": manifest_sha256,
        "release": release,
        "repository": repository,
        "source_date_epoch": attestation["source_date_epoch"],
        "total_bytes": attestation["total_bytes"],
    }


def _open_directory_at(parent_fd: int, name: str, *, create: bool) -> int:
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    if create:
        try:
            os.mkdir(name, 0o700, dir_fd=parent_fd)
        except FileExistsError:
            pass
    descriptor = os.open(name, flags, dir_fd=parent_fd)
    metadata = os.fstat(descriptor)
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.geteuid():
        os.close(descriptor)
        fail("source extraction directory ownership or type is unsafe")
    if stat.S_IMODE(metadata.st_mode) & 0o077:
        os.close(descriptor)
        fail("source extraction directory is accessible by another user")
    return descriptor


def _destination_parent(destination: Path, require_root_owner: bool) -> tuple[int, str]:
    if not destination.is_absolute() or destination.name in {"", ".", ".."}:
        fail("source extraction destination must be one absolute child path")
    if destination.exists() or destination.is_symlink():
        fail("source extraction destination must not already exist")
    parent = destination.parent
    if not parent.is_absolute():
        fail("source extraction parent must be absolute")
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = os.open("/", flags)
    try:
        for component in parent.parts[1:]:
            next_descriptor = os.open(component, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
    except OSError as error:
        os.close(descriptor)
        raise SourceBundleError(
            "source extraction parent must contain only real directories"
        ) from error
    metadata = os.fstat(descriptor)
    expected_owner = 0 if require_root_owner else os.geteuid()
    if metadata.st_uid != expected_owner:
        os.close(descriptor)
        fail("source extraction parent has an unexpected owner")
    if require_root_owner and os.geteuid() != 0:
        os.close(descriptor)
        fail("root-owned source extraction requires an effective UID of zero")
    if stat.S_IMODE(metadata.st_mode) & 0o022:
        os.close(descriptor)
        fail("source extraction parent must not be group or world writable")
    return descriptor, destination.name


def extract_verified_bundle(
    bundle_dir: Path,
    destination: Path,
    *,
    release: str,
    repository: str,
    commit: str,
    attestation_sha256: str,
    manifest_sha256: str,
    archive_sha256: str,
    require_root_owner: bool = False,
) -> dict[str, Any]:
    if not destination.is_absolute():
        fail("source extraction destination must be absolute")
    result = verify_bundle(
        bundle_dir,
        release=release,
        repository=repository,
        commit=commit,
        attestation_sha256=attestation_sha256,
        manifest_sha256=manifest_sha256,
        archive_sha256=archive_sha256,
    )
    manifest_raw = require_release_file(
        bundle_dir / MANIFEST_FILENAME, "source manifest", MAX_MANIFEST_BYTES
    )
    if sha256_bytes(manifest_raw) != manifest_sha256:
        fail("source manifest changed after verification")
    records = parse_manifest(manifest_raw)
    archive_raw = require_release_file(
        bundle_dir / ARCHIVE_FILENAME, "source archive", MAX_ARCHIVE_BYTES
    )
    if sha256_bytes(archive_raw) != archive_sha256:
        fail("source archive changed after verification")
    parent_fd, destination_name = _destination_parent(destination, require_root_owner)
    root_fd: int | None = None
    created_files: list[Path] = []
    created_directories: set[Path] = set()
    try:
        os.mkdir(destination_name, 0o700, dir_fd=parent_fd)
        root_fd = _open_directory_at(parent_fd, destination_name, create=False)
        with tarfile.open(fileobj=io.BytesIO(archive_raw), mode="r:") as archive:
            for record in records:
                try:
                    member = archive.next()
                except (OSError, tarfile.TarError) as error:
                    raise SourceBundleError(
                        "source archive changed during extraction"
                    ) from error
                if (
                    member is None
                    or member.name != record["path"]
                    or member.type != tarfile.REGTYPE
                ):
                    fail("source archive order or type changed during extraction")
                parts = PurePosixPath(record["path"]).parts
                directory_fd = os.dup(root_fd)
                relative_parent = Path()
                try:
                    for component in parts[:-1]:
                        next_fd = _open_directory_at(
                            directory_fd, component, create=True
                        )
                        os.close(directory_fd)
                        directory_fd = next_fd
                        relative_parent /= component
                        created_directories.add(relative_parent)
                    flags = (
                        os.O_WRONLY
                        | os.O_CREAT
                        | os.O_EXCL
                        | getattr(os, "O_CLOEXEC", 0)
                        | getattr(os, "O_NOFOLLOW", 0)
                    )
                    output_fd = os.open(parts[-1], flags, 0o600, dir_fd=directory_fd)
                    created_files.append(destination / Path(*parts))
                    try:
                        source = archive.extractfile(member)
                        if source is None:
                            fail(
                                "source archive member cannot be read during extraction"
                            )
                        digest = hashlib.sha256()
                        total = 0
                        while block := source.read(1024 * 1024):
                            total += len(block)
                            if total > record["size"]:
                                fail("source archive member grew during extraction")
                            digest.update(block)
                            view = memoryview(block)
                            while view:
                                written = os.write(output_fd, view)
                                if written <= 0:
                                    fail("short write during source extraction")
                                view = view[written:]
                        if (
                            total != record["size"]
                            or digest.hexdigest() != record["sha256"]
                        ):
                            fail("source archive member changed during extraction")
                        os.fchmod(output_fd, int(record["mode"], 8))
                        os.fsync(output_fd)
                    finally:
                        os.close(output_fd)
                finally:
                    os.close(directory_fd)
            if archive.next() is not None:
                fail("source archive gained an extra member during extraction")

        for relative in sorted(
            created_directories, key=lambda value: len(value.parts), reverse=True
        ):
            os.chmod(destination / relative, 0o555, follow_symlinks=False)
        os.fchmod(root_fd, 0o555)
        os.fsync(root_fd)
    except BaseException:
        if root_fd is not None:
            os.close(root_fd)
            root_fd = None
        for path in reversed(created_files):
            try:
                path.unlink()
            except FileNotFoundError:
                pass
        for relative in sorted(
            created_directories, key=lambda value: len(value.parts), reverse=True
        ):
            path = destination / relative
            try:
                os.chmod(path, 0o700, follow_symlinks=False)
                path.rmdir()
            except FileNotFoundError:
                pass
        try:
            os.chmod(destination, 0o700, follow_symlinks=False)
            destination.rmdir()
        except FileNotFoundError:
            pass
        raise
    finally:
        if root_fd is not None:
            os.close(root_fd)
        os.close(parent_fd)
    return {**result, "extracted": True}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    build = commands.add_parser("build")
    build.add_argument("--repo-root", type=Path, required=True)
    build.add_argument("--output-dir", type=Path, required=True)
    build.add_argument("--release", required=True)
    build.add_argument("--source-repository", required=True)
    build.add_argument("--source-commit", required=True)
    build.add_argument("--source-date-epoch", type=int, required=True)
    verify = commands.add_parser("verify")
    verify.add_argument("--bundle-dir", type=Path, required=True)
    verify.add_argument("--release", required=True)
    verify.add_argument("--source-repository", required=True)
    verify.add_argument("--source-commit", required=True)
    verify.add_argument("--attestation-sha256", required=True)
    verify.add_argument("--manifest-sha256", required=True)
    verify.add_argument("--archive-sha256", required=True)
    verify.add_argument("--extract-to", type=Path)
    verify.add_argument("--require-root-owner", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "build":
            result = build_bundle(
                args.repo_root,
                args.output_dir,
                release=args.release,
                repository=args.source_repository,
                commit=args.source_commit,
                source_date_epoch=args.source_date_epoch,
            )
        else:
            verifier = (
                extract_verified_bundle
                if args.extract_to is not None
                else verify_bundle
            )
            keywords = {
                "release": args.release,
                "repository": args.source_repository,
                "commit": args.source_commit,
                "attestation_sha256": args.attestation_sha256,
                "manifest_sha256": args.manifest_sha256,
                "archive_sha256": args.archive_sha256,
            }
            if args.extract_to is None:
                if args.require_root_owner:
                    fail("--require-root-owner requires --extract-to")
                result = verifier(args.bundle_dir, **keywords)
            else:
                result = verifier(
                    args.bundle_dir,
                    args.extract_to,
                    require_root_owner=args.require_root_owner,
                    **keywords,
                )
    except (OSError, SourceBundleError) as error:
        print(f"source-bundle: {error}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
