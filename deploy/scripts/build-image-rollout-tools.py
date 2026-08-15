#!/usr/bin/env python3
"""Build, verify, and safely install the image-rollout control-plane tools."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import re
import stat
import sys
import tarfile
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, NoReturn

SCHEMA_VERSION = 1
MANIFEST_TYPE = "image-rollout-tools-manifest-v1"
ADMISSION_TYPE = "image-rollout-tools-admission-v1"
ARCHIVE_BASENAME = "image-rollout-tools.tar"
MANIFEST_BASENAME = "rollout-tools.manifest.json"
ADMISSION_BASENAME = "rollout-tools.admission.json"
VERIFIER_BASENAME = "build-image-rollout-tools.py"
MAX_FILE_BYTES = 16 * 1024 * 1024
MAX_ARCHIVE_BYTES = 64 * 1024 * 1024
MAX_TOTAL_FILE_BYTES = 32 * 1024 * 1024
MAX_USTAR_MTIME = 0o77777777777
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
SAFE_BASENAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,191}$")

# These keys and mode strings are consumed verbatim by image-rollout-admission.py.
TOOL_MEMBERS = {
    "deploy/scripts/image-rollout-admission.py": ("admission_helper", "0555"),
    "deploy/scripts/image-rollout-smoke.py": ("smoke_helper", "0555"),
    "deploy/scripts/rollout-bootstrap-images.sh": ("wrapper", "0555"),
    "deploy/schemas/image-rollout-record.schema.json": ("record_schema", "0444"),
}
DIRECTORY_MEMBERS = {
    "deploy": "0555",
    "deploy/schemas": "0555",
    "deploy/scripts": "0555",
}
ARCHIVE_MEMBER_MODES = {
    **{name: mode for name, (_, mode) in TOOL_MEMBERS.items()},
    MANIFEST_BASENAME: "0444",
}
ARCHIVE_MEMBER_ORDER = tuple(
    sorted(
        [*DIRECTORY_MEMBERS, *ARCHIVE_MEMBER_MODES],
        key=lambda value: value.encode("utf-8"),
    )
)


class ToolsBundleError(RuntimeError):
    """A concise failure that does not disclose private filesystem paths."""


class PrivacySafeArgumentParser(argparse.ArgumentParser):
    """Argparse variant that never reflects caller-supplied values in errors."""

    def error(self, message: str) -> NoReturn:
        del message
        self.print_usage(sys.stderr)
        self.exit(2, "build-image-rollout-tools: invalid command-line arguments\n")


@dataclass(frozen=True)
class VerifiedBundle:
    archive_sha256: str
    archive_size: int
    epoch: int
    files: dict[str, bytes]
    manifest: dict[str, Any]
    manifest_raw: bytes


def fail(message: str) -> NoReturn:
    raise ToolsBundleError(message)


def canonical_json(value: Any, *, newline: bool = True) -> bytes:
    try:
        encoded = json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
    except (TypeError, ValueError) as exc:
        raise ToolsBundleError("value cannot be canonically encoded") from exc
    return encoded + (b"\n" if newline else b"")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def require_sha256(value: Any, label: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        fail(f"{label} is not one lowercase SHA-256 digest")
    return value


def require_epoch(value: int) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or value < 0
        or value > MAX_USTAR_MTIME
    ):
        fail("source date epoch is outside the portable USTAR range")
    return value


def parse_epoch_argument(value: str) -> int:
    try:
        return int(value, 10)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be one base-10 integer") from exc


def _stable_fields(value: os.stat_result) -> tuple[int, ...]:
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


def _validate_absolute_path(path: Path, label: str) -> None:
    text = str(path)
    if (
        not path.is_absolute()
        or text != os.path.normpath(text)
        or any(part in {"", ".", ".."} for part in path.parts[1:])
    ):
        fail(f"{label} must be one normalized absolute path")


def _directory_flags() -> int:
    nofollow = getattr(os, "O_NOFOLLOW", None)
    directory = getattr(os, "O_DIRECTORY", None)
    if nofollow is None or directory is None:
        fail("this platform lacks no-follow directory opens")
    return os.O_RDONLY | directory | nofollow | getattr(os, "O_CLOEXEC", 0)


def _file_read_flags() -> int:
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:
        fail("this platform lacks no-follow file opens")
    return os.O_RDONLY | nofollow | getattr(os, "O_CLOEXEC", 0)


def _open_directory(path: Path, label: str) -> int:
    _validate_absolute_path(path, label)
    flags = _directory_flags()
    descriptor = os.open("/", flags)
    try:
        for component in path.parts[1:]:
            try:
                child = os.open(component, flags, dir_fd=descriptor)
            except OSError as exc:
                raise ToolsBundleError(
                    f"{label} has an inaccessible or symlink ancestor"
                ) from exc
            os.close(descriptor)
            descriptor = child
        metadata = os.fstat(descriptor)
        if not stat.S_ISDIR(metadata.st_mode):
            fail(f"{label} is not a directory")
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


def _read_descriptor(descriptor: int, maximum: int, label: str) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = os.read(descriptor, min(1024 * 1024, maximum + 1 - total))
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
        if total > maximum:
            fail(f"{label} exceeds its size limit")
    return b"".join(chunks)


def read_regular(
    path: Path,
    label: str,
    *,
    maximum: int = MAX_FILE_BYTES,
    require_nonempty: bool = True,
) -> tuple[bytes, os.stat_result]:
    _validate_absolute_path(path, label)
    parent = _open_directory(path.parent, f"{label} parent")
    descriptor = -1
    try:
        try:
            descriptor = os.open(path.name, _file_read_flags(), dir_fd=parent)
        except OSError as exc:
            raise ToolsBundleError(f"{label} is inaccessible or is a symlink") from exc
        before = os.fstat(descriptor)
        named = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or (before.st_size == 0 and require_nonempty)
            or before.st_size > maximum
            or (before.st_dev, before.st_ino) != (named.st_dev, named.st_ino)
        ):
            fail(f"{label} is not one bounded singly-linked regular file")
        raw = _read_descriptor(descriptor, maximum, label)
        after = os.fstat(descriptor)
        named_after = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
        if (
            len(raw) != before.st_size
            or _stable_fields(before) != _stable_fields(after)
            or (after.st_dev, after.st_ino)
            != (named_after.st_dev, named_after.st_ino)
        ):
            fail(f"{label} changed while it was read")
        return raw, after
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        os.close(parent)


def _path_within(path: Path, anchor: Path) -> bool:
    path_parts = path.parts
    anchor_parts = anchor.parts
    return path_parts[: len(anchor_parts)] == anchor_parts


def validate_trusted_directory_chain(
    directory: Path, anchor: Path, label: str, *, owner_uid: int
) -> None:
    _validate_absolute_path(directory, label)
    _validate_absolute_path(anchor, f"{label} trust anchor")
    if not _path_within(directory, anchor):
        fail(f"{label} is outside its trust anchor")
    flags = _directory_flags()
    descriptor = os.open("/", flags)
    try:
        if anchor == Path("/"):
            metadata = os.fstat(descriptor)
            if metadata.st_uid != owner_uid or stat.S_IMODE(metadata.st_mode) & 0o022:
                fail(f"{label} trust chain is not owner-controlled and read-only")
        for index, component in enumerate(directory.parts[1:], start=1):
            try:
                child = os.open(component, flags, dir_fd=descriptor)
            except OSError as exc:
                raise ToolsBundleError(f"{label} trust chain contains a symlink") from exc
            os.close(descriptor)
            descriptor = child
            if index >= len(anchor.parts) - 1:
                metadata = os.fstat(descriptor)
                if (
                    not stat.S_ISDIR(metadata.st_mode)
                    or metadata.st_uid != owner_uid
                    or stat.S_IMODE(metadata.st_mode) & 0o022
                ):
                    fail(f"{label} trust chain is not owner-controlled and read-only")
    finally:
        os.close(descriptor)


def validate_trusted_file(
    path: Path,
    anchor: Path,
    label: str,
    *,
    owner_uid: int,
    modes: set[int],
    maximum: int,
) -> tuple[bytes, os.stat_result]:
    validate_trusted_directory_chain(path.parent, anchor, label, owner_uid=owner_uid)
    raw, metadata = read_regular(path, label, maximum=maximum)
    if metadata.st_uid != owner_uid or stat.S_IMODE(metadata.st_mode) not in modes:
        fail(f"{label} is not owner-controlled with its fixed read-only mode")
    validate_trusted_directory_chain(path.parent, anchor, label, owner_uid=owner_uid)
    return raw, metadata


def validate_private_output_parent(path: Path) -> None:
    descriptor = _open_directory(path, "rollout tools output parent")
    try:
        metadata = os.fstat(descriptor)
        if (
            metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o700
        ):
            fail("rollout tools output parent must be current-user-owned mode 0700")
    finally:
        os.close(descriptor)


def reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            fail("rollout tools manifest contains a duplicate object key")
        result[key] = value
    return result


def reject_constant(value: str) -> NoReturn:
    fail("rollout tools manifest contains a non-finite number")


def parse_manifest(raw: bytes) -> dict[str, Any]:
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=reject_duplicate_pairs,
            parse_constant=reject_constant,
        )
    except UnicodeDecodeError as exc:
        raise ToolsBundleError("rollout tools manifest is not UTF-8") from exc
    except json.JSONDecodeError as exc:
        raise ToolsBundleError("rollout tools manifest is not valid JSON") from exc
    if not isinstance(value, dict) or set(value) != {
        "files",
        "identity_sha256",
        "schema_version",
        "type",
    }:
        fail("rollout tools manifest has an invalid top-level shape")
    if value.get("schema_version") != SCHEMA_VERSION or value.get("type") != MANIFEST_TYPE:
        fail("rollout tools manifest has an invalid header")
    files = value.get("files")
    if not isinstance(files, dict) or set(files) != set(TOOL_MEMBERS):
        fail("rollout tools manifest does not describe the exact tool set")
    projected: dict[str, dict[str, Any]] = {}
    total = 0
    for name, (_, expected_mode) in TOOL_MEMBERS.items():
        descriptor = files.get(name)
        if not isinstance(descriptor, dict) or set(descriptor) != {"mode", "sha256", "size"}:
            fail("rollout tools manifest contains an invalid file descriptor")
        digest = require_sha256(descriptor.get("sha256"), "manifest file hash")
        size = descriptor.get("size")
        if (
            not isinstance(size, int)
            or isinstance(size, bool)
            or size <= 0
            or size > MAX_FILE_BYTES
            or descriptor.get("mode") != expected_mode
        ):
            fail("rollout tools manifest contains invalid file metadata")
        total += size
        if total > MAX_TOTAL_FILE_BYTES:
            fail("rollout tools manifest exceeds the aggregate size limit")
        projected[name] = {"mode": expected_mode, "sha256": digest, "size": size}
    identity = sha256_bytes(canonical_json(projected, newline=False))
    if value.get("identity_sha256") != identity:
        fail("rollout tools manifest identity does not bind its exact file set")
    if canonical_json(value) != raw:
        fail("rollout tools manifest is not canonically encoded")
    return value


def build_manifest(files: dict[str, bytes]) -> tuple[dict[str, Any], bytes]:
    if set(files) != set(TOOL_MEMBERS):
        fail("builder did not receive the exact rollout tool set")
    projected = {
        name: {
            "mode": TOOL_MEMBERS[name][1],
            "sha256": sha256_bytes(files[name]),
            "size": len(files[name]),
        }
        for name in TOOL_MEMBERS
    }
    manifest = {
        "files": projected,
        "identity_sha256": sha256_bytes(canonical_json(projected, newline=False)),
        "schema_version": SCHEMA_VERSION,
        "type": MANIFEST_TYPE,
    }
    raw = canonical_json(manifest)
    parse_manifest(raw)
    return manifest, raw


def _tar_info(
    name: str,
    mode: int,
    epoch: int,
    *,
    is_directory: bool,
    size: int = 0,
) -> tarfile.TarInfo:
    info = tarfile.TarInfo(name)
    info.type = tarfile.DIRTYPE if is_directory else tarfile.REGTYPE
    info.mode = mode
    info.uid = 0
    info.gid = 0
    info.uname = "root"
    info.gname = "root"
    info.mtime = epoch
    info.size = 0 if is_directory else size
    info.linkname = ""
    info.devmajor = 0
    info.devminor = 0
    info.pax_headers = {}
    return info


def archive_bytes(files: dict[str, bytes], manifest_raw: bytes, epoch: int) -> bytes:
    require_epoch(epoch)
    if set(files) != set(TOOL_MEMBERS):
        fail("archive input does not contain the exact rollout tool set")
    payloads = {**files, MANIFEST_BASENAME: manifest_raw}
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:", format=tarfile.USTAR_FORMAT) as archive:
        for name in ARCHIVE_MEMBER_ORDER:
            if name in DIRECTORY_MEMBERS:
                archive.addfile(
                    _tar_info(
                        name,
                        int(DIRECTORY_MEMBERS[name], 8),
                        epoch,
                        is_directory=True,
                    )
                )
            else:
                raw = payloads[name]
                archive.addfile(
                    _tar_info(
                        name,
                        int(ARCHIVE_MEMBER_MODES[name], 8),
                        epoch,
                        is_directory=False,
                        size=len(raw),
                    ),
                    io.BytesIO(raw),
                )
    result = output.getvalue()
    if len(result) > MAX_ARCHIVE_BYTES:
        fail("rollout tools archive exceeds its size limit")
    return result


def _read_tar_member(archive: tarfile.TarFile, member: tarfile.TarInfo) -> bytes:
    extracted = archive.extractfile(member)
    if extracted is None:
        fail("rollout tools archive contains an unreadable regular member")
    with extracted:
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = extracted.read(min(1024 * 1024, MAX_FILE_BYTES + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > MAX_FILE_BYTES:
                fail("rollout tools archive member exceeds its size limit")
        return b"".join(chunks)


def verify_archive_bytes(
    raw: bytes,
    *,
    expected_archive_sha256: str,
    epoch: int,
    expected_identity_sha256: str | None = None,
) -> VerifiedBundle:
    expected_archive_sha256 = require_sha256(expected_archive_sha256, "expected archive hash")
    epoch = require_epoch(epoch)
    if len(raw) == 0 or len(raw) > MAX_ARCHIVE_BYTES:
        fail("rollout tools archive is empty or exceeds its size limit")
    observed_archive_sha256 = sha256_bytes(raw)
    if observed_archive_sha256 != expected_archive_sha256:
        fail("rollout tools archive differs from its out-of-band digest")
    try:
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as archive:
            members = archive.getmembers()
            if [member.name for member in members] != list(ARCHIVE_MEMBER_ORDER):
                fail("rollout tools archive member set or order is not canonical")
            payloads: dict[str, bytes] = {}
            for member in members:
                is_directory = member.name in DIRECTORY_MEMBERS
                expected_mode = int(
                    (DIRECTORY_MEMBERS if is_directory else ARCHIVE_MEMBER_MODES)[member.name],
                    8,
                )
                expected_type = tarfile.DIRTYPE if is_directory else tarfile.REGTYPE
                if (
                    member.type != expected_type
                    or stat.S_IMODE(member.mode) != expected_mode
                    or member.uid != 0
                    or member.gid != 0
                    or member.uname != "root"
                    or member.gname != "root"
                    or member.mtime != epoch
                    or member.linkname != ""
                    or member.devmajor != 0
                    or member.devminor != 0
                    or member.pax_headers
                    or (is_directory and member.size != 0)
                    or (not is_directory and (member.size <= 0 or member.size > MAX_FILE_BYTES))
                ):
                    fail("rollout tools archive member metadata is not canonical USTAR")
                if not is_directory:
                    payloads[member.name] = _read_tar_member(archive, member)
    except (tarfile.TarError, EOFError, OSError) as exc:
        raise ToolsBundleError("rollout tools archive is not canonical uncompressed USTAR") from exc
    manifest_raw = payloads.pop(MANIFEST_BASENAME)
    manifest = parse_manifest(manifest_raw)
    descriptors = manifest["files"]
    total = 0
    for name in TOOL_MEMBERS:
        content = payloads.get(name)
        descriptor = descriptors[name]
        if (
            content is None
            or len(content) != descriptor["size"]
            or sha256_bytes(content) != descriptor["sha256"]
        ):
            fail("rollout tools archive member bytes differ from the manifest")
        total += len(content)
    if total > MAX_TOTAL_FILE_BYTES:
        fail("rollout tools archive exceeds the aggregate tool size limit")
    identity = manifest["identity_sha256"]
    if expected_identity_sha256 is not None and identity != require_sha256(
        expected_identity_sha256, "expected tooling identity"
    ):
        fail("rollout tools identity differs from its out-of-band digest")
    if archive_bytes(payloads, manifest_raw, epoch) != raw:
        fail("rollout tools archive bytes are not canonical uncompressed USTAR")
    return VerifiedBundle(
        archive_sha256=observed_archive_sha256,
        archive_size=len(raw),
        epoch=epoch,
        files=payloads,
        manifest=manifest,
        manifest_raw=manifest_raw,
    )


def verify_archive_file(
    path: Path,
    *,
    expected_archive_sha256: str,
    epoch: int,
    expected_identity_sha256: str | None = None,
) -> VerifiedBundle:
    raw, _ = read_regular(path, "rollout tools archive", maximum=MAX_ARCHIVE_BYTES)
    return verify_archive_bytes(
        raw,
        expected_archive_sha256=expected_archive_sha256,
        epoch=epoch,
        expected_identity_sha256=expected_identity_sha256,
    )


def _write_all(descriptor: int, raw: bytes, label: str) -> None:
    view = memoryview(raw)
    offset = 0
    while offset < len(view):
        written = os.write(descriptor, view[offset:])
        if written <= 0:
            fail(f"{label} could not be written completely")
        offset += written


def write_new_regular(path: Path, raw: bytes, mode: int, label: str) -> None:
    _validate_absolute_path(path, label)
    parent = _open_directory(path.parent, f"{label} parent")
    descriptor = -1
    created = False
    try:
        flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        try:
            descriptor = os.open(path.name, flags, mode, dir_fd=parent)
            created = True
        except OSError as exc:
            raise ToolsBundleError(
                f"{label} already exists or cannot be created safely"
            ) from exc
        _write_all(descriptor, raw, label)
        os.fchmod(descriptor, mode)
        os.fsync(descriptor)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_size != len(raw)
            or stat.S_IMODE(metadata.st_mode) != mode
        ):
            fail(f"{label} was not published as one normalized regular file")
        os.fsync(parent)
    except Exception:
        if descriptor >= 0:
            os.close(descriptor)
            descriptor = -1
        if created:
            try:
                os.unlink(path.name, dir_fd=parent)
                os.fsync(parent)
            except OSError:
                pass
        raise
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        os.close(parent)


def remove_owned_publication(path: Path, label: str) -> None:
    parent = _open_directory(path.parent, f"{label} parent cleanup")
    try:
        metadata = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or metadata.st_nlink != 1
        ):
            fail(f"{label} cannot be safely removed after failed verification")
        os.unlink(path.name, dir_fd=parent)
        os.fsync(parent)
    finally:
        os.close(parent)


def file_descriptor(raw: bytes, basename: str) -> dict[str, Any]:
    if SAFE_BASENAME_RE.fullmatch(basename) is None:
        fail("artifact basename is not privacy-safe")
    return {"basename": basename, "sha256": sha256_bytes(raw), "size": len(raw)}


def verifier_descriptor() -> dict[str, Any]:
    path = Path(os.path.abspath(__file__))
    if path.name != VERIFIER_BASENAME:
        fail("running verifier has an unexpected basename")
    raw, _ = read_regular(path, "bundle verifier")
    return file_descriptor(raw, VERIFIER_BASENAME)


def member_descriptors(verified: VerifiedBundle) -> dict[str, dict[str, Any]]:
    descriptors = verified.manifest["files"]
    return {
        name: {
            "basename": PurePosixPath(name).name,
            "mode": descriptors[name]["mode"],
            "sha256": descriptors[name]["sha256"],
            "size": descriptors[name]["size"],
        }
        for name in TOOL_MEMBERS
    }


def result_for(
    verified: VerifiedBundle,
    command: str,
    status_value: str,
    *,
    external_verifier: dict[str, Any] | None = None,
) -> dict[str, Any]:
    expected_status = {
        "build": "built",
        "verify": "verified",
        "extract": "extracted",
    }.get(command)
    if expected_status is None or expected_status != status_value:
        fail("tools admission command and status are inconsistent")
    if external_verifier is None:
        external_verifier = verifier_descriptor()
    if (
        not isinstance(external_verifier, dict)
        or set(external_verifier) != {"basename", "sha256", "size"}
        or external_verifier.get("basename") != VERIFIER_BASENAME
        or not isinstance(external_verifier.get("size"), int)
        or isinstance(external_verifier.get("size"), bool)
        or external_verifier["size"] <= 0
        or external_verifier["size"] > MAX_FILE_BYTES
    ):
        fail("external verifier descriptor is invalid")
    require_sha256(external_verifier.get("sha256"), "external verifier hash")
    return {
        "archive": {
            "basename": ARCHIVE_BASENAME,
            "sha256": verified.archive_sha256,
            "size": verified.archive_size,
        },
        "command": command,
        "external_verifier": external_verifier,
        "manifest": file_descriptor(verified.manifest_raw, MANIFEST_BASENAME),
        "members": member_descriptors(verified),
        "schema_version": SCHEMA_VERSION,
        "self_sha256": external_verifier["sha256"],
        "status": status_value,
        "tooling_identity": verified.manifest["identity_sha256"],
        "type": ADMISSION_TYPE,
    }


def build_bundle(args: argparse.Namespace) -> dict[str, Any]:
    epoch = require_epoch(args.source_date_epoch)
    output = args.output
    if output.name != ARCHIVE_BASENAME:
        fail("rollout tools archive output has an unexpected basename")
    validate_private_output_parent(output.parent)
    files: dict[str, bytes] = {}
    for relative, (argument_name, _) in TOOL_MEMBERS.items():
        source = getattr(args, argument_name)
        if source.name != PurePosixPath(relative).name:
            fail("rollout tool input has an unexpected basename")
        raw, _ = read_regular(source, f"rollout tool {argument_name}")
        files[relative] = raw
    if sum(len(raw) for raw in files.values()) > MAX_TOTAL_FILE_BYTES:
        fail("rollout tool inputs exceed the aggregate size limit")
    manifest, manifest_raw = build_manifest(files)
    raw = archive_bytes(files, manifest_raw, epoch)
    verified = verify_archive_bytes(
        raw,
        expected_archive_sha256=sha256_bytes(raw),
        epoch=epoch,
        expected_identity_sha256=manifest["identity_sha256"],
    )
    result = result_for(verified, "build", "built")
    write_new_regular(output, raw, 0o600, "rollout tools archive output")
    try:
        published = verify_archive_file(
            output,
            expected_archive_sha256=verified.archive_sha256,
            epoch=epoch,
            expected_identity_sha256=manifest["identity_sha256"],
        )
        if published != verified:
            fail("published rollout tools archive differs from the verified build")
    except Exception:
        remove_owned_publication(output, "rollout tools archive output")
        raise
    return result


def verify_bundle(args: argparse.Namespace) -> dict[str, Any]:
    if args.archive.name != ARCHIVE_BASENAME:
        fail("rollout tools archive has an unexpected basename")
    verified = verify_archive_file(
        args.archive,
        expected_archive_sha256=args.expected_archive_sha256,
        epoch=args.source_date_epoch,
        expected_identity_sha256=args.expected_identity_sha256,
    )
    return result_for(verified, "verify", "verified")


def _open_relative_directory(root: int, relative: PurePosixPath) -> int:
    descriptor = os.dup(root)
    try:
        for component in relative.parts:
            child = os.open(component, _directory_flags(), dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


def _remove_partial_install(parent: int, destination_name: str) -> None:
    try:
        root = os.open(destination_name, _directory_flags(), dir_fd=parent)
    except OSError:
        return
    try:
        for name in sorted(
            DIRECTORY_MEMBERS, key=lambda value: value.count("/"), reverse=True
        ):
            try:
                descriptor = _open_relative_directory(root, PurePosixPath(name))
                try:
                    os.fchmod(descriptor, 0o700)
                finally:
                    os.close(descriptor)
            except OSError:
                pass
        try:
            os.fchmod(root, 0o700)
        except OSError:
            pass
        try:
            os.unlink(ADMISSION_BASENAME, dir_fd=root)
        except OSError:
            pass
        for name in sorted(
            ARCHIVE_MEMBER_MODES,
            key=lambda value: value.count("/"),
            reverse=True,
        ):
            relative = PurePosixPath(name)
            try:
                directory = _open_relative_directory(root, relative.parent)
                try:
                    os.unlink(relative.name, dir_fd=directory)
                finally:
                    os.close(directory)
            except OSError:
                pass
        for name in sorted(
            DIRECTORY_MEMBERS,
            key=lambda value: value.count("/"),
            reverse=True,
        ):
            relative = PurePosixPath(name)
            try:
                directory = _open_relative_directory(root, relative.parent)
                try:
                    os.rmdir(relative.name, dir_fd=directory)
                finally:
                    os.close(directory)
            except OSError:
                pass
    finally:
        os.close(root)
    try:
        os.rmdir(destination_name, dir_fd=parent)
        os.fsync(parent)
    except OSError:
        pass


def install_verified_bundle(
    verified: VerifiedBundle,
    destination: Path,
    *,
    owner_uid: int,
    seal_root: bool = True,
) -> None:
    _validate_absolute_path(destination, "tools destination")
    if SAFE_BASENAME_RE.fullmatch(destination.name) is None:
        fail("tools destination basename is not safe")
    parent = _open_directory(destination.parent, "tools destination parent")
    root = -1
    created = False
    try:
        try:
            os.mkdir(destination.name, 0o700, dir_fd=parent)
            created = True
            root = os.open(destination.name, _directory_flags(), dir_fd=parent)
        except OSError as exc:
            raise ToolsBundleError(
                "tools destination already exists or cannot be created safely"
            ) from exc
        for name in sorted(
            DIRECTORY_MEMBERS, key=lambda value: (value.count("/"), value)
        ):
            relative = PurePosixPath(name)
            directory = _open_relative_directory(root, relative.parent)
            try:
                os.mkdir(relative.name, 0o700, dir_fd=directory)
            finally:
                os.close(directory)
        payloads = {**verified.files, MANIFEST_BASENAME: verified.manifest_raw}
        for name in sorted(
            ARCHIVE_MEMBER_MODES, key=lambda value: value.encode("utf-8")
        ):
            relative = PurePosixPath(name)
            directory = _open_relative_directory(root, relative.parent)
            descriptor = -1
            try:
                flags = (
                    os.O_WRONLY
                    | os.O_CREAT
                    | os.O_EXCL
                    | getattr(os, "O_CLOEXEC", 0)
                    | getattr(os, "O_NOFOLLOW", 0)
                )
                descriptor = os.open(relative.name, flags, 0o600, dir_fd=directory)
                raw = payloads[name]
                _write_all(descriptor, raw, "installed rollout tool")
                os.fchown(descriptor, owner_uid, 0 if owner_uid == 0 else os.getegid())
                os.fchmod(descriptor, int(ARCHIVE_MEMBER_MODES[name], 8))
                os.fsync(descriptor)
                metadata = os.fstat(descriptor)
                if (
                    metadata.st_uid != owner_uid
                    or metadata.st_nlink != 1
                    or metadata.st_size != len(raw)
                    or stat.S_IMODE(metadata.st_mode)
                    != int(ARCHIVE_MEMBER_MODES[name], 8)
                ):
                    fail("installed rollout tool metadata is not normalized")
                os.fsync(directory)
            finally:
                if descriptor >= 0:
                    os.close(descriptor)
                os.close(directory)
        for name in sorted(
            DIRECTORY_MEMBERS,
            key=lambda value: value.count("/"),
            reverse=True,
        ):
            descriptor = _open_relative_directory(root, PurePosixPath(name))
            try:
                os.fchown(descriptor, owner_uid, 0 if owner_uid == 0 else os.getegid())
                os.fchmod(descriptor, int(DIRECTORY_MEMBERS[name], 8))
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        os.fchown(root, owner_uid, 0 if owner_uid == 0 else os.getegid())
        os.fchmod(root, 0o555 if seal_root else 0o700)
        os.fsync(root)
        os.fsync(parent)
    except Exception:
        if root >= 0:
            os.close(root)
            root = -1
        if created:
            _remove_partial_install(parent, destination.name)
        raise
    finally:
        if root >= 0:
            os.close(root)
        os.close(parent)


def verify_installed_bundle(
    verified: VerifiedBundle,
    destination: Path,
    *,
    owner_uid: int,
    admission_raw: bytes | None = None,
    root_mode: int = 0o555,
) -> None:
    expected_gid = 0 if owner_uid == 0 else os.getegid()
    root = _open_directory(destination, "installed tools root")
    try:
        metadata = os.fstat(root)
        if (
            metadata.st_uid != owner_uid
            or metadata.st_gid != expected_gid
            or stat.S_IMODE(metadata.st_mode) != root_mode
            or set(os.listdir(root))
            != {
                "deploy",
                MANIFEST_BASENAME,
                *({ADMISSION_BASENAME} if admission_raw is not None else set()),
            }
        ):
            fail("installed tools root metadata is not normalized")
    finally:
        os.close(root)
    for name, mode_text in DIRECTORY_MEMBERS.items():
        descriptor = _open_directory(destination / name, "installed tools directory")
        try:
            metadata = os.fstat(descriptor)
            expected_entries = {
                "deploy": {"schemas", "scripts"},
                "deploy/schemas": {"image-rollout-record.schema.json"},
                "deploy/scripts": {
                    "image-rollout-admission.py",
                    "image-rollout-smoke.py",
                    "rollout-bootstrap-images.sh",
                },
            }[name]
            if (
                metadata.st_uid != owner_uid
                or metadata.st_gid != expected_gid
                or stat.S_IMODE(metadata.st_mode) != int(mode_text, 8)
                or set(os.listdir(descriptor)) != expected_entries
            ):
                fail("installed tools directory metadata is not normalized")
        finally:
            os.close(descriptor)
    payloads = {**verified.files, MANIFEST_BASENAME: verified.manifest_raw}
    for name, mode_text in ARCHIVE_MEMBER_MODES.items():
        raw, metadata = read_regular(destination / name, "installed rollout tool")
        if (
            raw != payloads[name]
            or metadata.st_uid != owner_uid
            or metadata.st_gid != expected_gid
            or stat.S_IMODE(metadata.st_mode) != int(mode_text, 8)
        ):
            fail("installed rollout tool differs from the verified archive")
    if admission_raw is not None:
        raw, metadata = read_regular(
            destination / ADMISSION_BASENAME, "installed rollout tools admission"
        )
        if (
            raw != admission_raw
            or metadata.st_uid != owner_uid
            or metadata.st_gid != expected_gid
            or stat.S_IMODE(metadata.st_mode) != 0o444
        ):
            fail("installed rollout tools admission is not canonical and read-only")


def seal_installed_root(destination: Path, *, owner_uid: int) -> None:
    root = _open_directory(destination, "installed tools root")
    parent = _open_directory(destination.parent, "installed tools parent")
    try:
        os.fchown(root, owner_uid, 0 if owner_uid == 0 else os.getegid())
        os.fchmod(root, 0o555)
        os.fsync(root)
        os.fsync(parent)
    finally:
        os.close(parent)
        os.close(root)


def install_with_admission(
    verified: VerifiedBundle,
    destination: Path,
    admission_output: Path,
    result: dict[str, Any],
    *,
    owner_uid: int,
) -> None:
    if admission_output.name != ADMISSION_BASENAME:
        fail("rollout tools admission output has an unexpected basename")
    if admission_output.parent != destination:
        fail("rollout tools admission must be published beside the installed manifest")
    external_verifier = result.get("external_verifier")
    expected_result = result_for(
        verified,
        "extract",
        "extracted",
        external_verifier=external_verifier,
    )
    if canonical_json(result) != canonical_json(expected_result):
        fail("rollout tools admission result is not the exact extraction result")
    admission_raw = canonical_json(expected_result)
    installed = False
    try:
        install_verified_bundle(
            verified,
            destination,
            owner_uid=owner_uid,
            seal_root=False,
        )
        installed = True
        verify_installed_bundle(
            verified,
            destination,
            owner_uid=owner_uid,
            root_mode=0o700,
        )
        write_new_regular(
            admission_output,
            admission_raw,
            0o444,
            "rollout tools admission output",
        )
        seal_installed_root(destination, owner_uid=owner_uid)
        verify_installed_bundle(
            verified,
            destination,
            owner_uid=owner_uid,
            admission_raw=admission_raw,
        )
    except Exception:
        if installed:
            parent = _open_directory(destination.parent, "tools destination parent cleanup")
            try:
                _remove_partial_install(parent, destination.name)
            finally:
                os.close(parent)
        raise


def verify_trusted_verifier(
    path: Path,
    anchor: Path,
    expected_sha256: str,
    *,
    owner_uid: int,
) -> dict[str, Any]:
    if path.name != VERIFIER_BASENAME:
        fail("running verifier has an unexpected basename")
    raw, _ = validate_trusted_file(
        path,
        anchor,
        "external bundle verifier",
        owner_uid=owner_uid,
        modes={0o555},
        maximum=MAX_FILE_BYTES,
    )
    if sha256_bytes(raw) != require_sha256(expected_sha256, "expected verifier hash"):
        fail("external bundle verifier differs from its out-of-band digest")
    return file_descriptor(raw, VERIFIER_BASENAME)


def extract_bundle(args: argparse.Namespace) -> dict[str, Any]:
    if os.geteuid() != 0:
        fail("extract requires the separately installed verifier to run as root")
    verifier = verify_trusted_verifier(
        Path(os.path.abspath(__file__)),
        args.verifier_trust_anchor,
        args.expected_verifier_sha256,
        owner_uid=0,
    )
    if args.archive.name != ARCHIVE_BASENAME:
        fail("rollout tools archive has an unexpected basename")
    archive_raw, _ = validate_trusted_file(
        args.archive,
        args.archive_trust_anchor,
        "rollout tools archive",
        owner_uid=0,
        modes={0o400, 0o444},
        maximum=MAX_ARCHIVE_BYTES,
    )
    validate_trusted_directory_chain(
        args.destination.parent,
        args.destination_trust_anchor,
        "tools destination parent",
        owner_uid=0,
    )
    verified = verify_archive_bytes(
        archive_raw,
        expected_archive_sha256=args.expected_archive_sha256,
        epoch=args.source_date_epoch,
        expected_identity_sha256=args.expected_identity_sha256,
    )
    result = result_for(
        verified,
        "extract",
        "extracted",
        external_verifier=verifier,
    )
    install_with_admission(
        verified,
        args.destination,
        args.admission_output,
        result,
        owner_uid=0,
    )
    return result


def build_parser() -> argparse.ArgumentParser:
    parser = PrivacySafeArgumentParser(description=__doc__)
    commands = parser.add_subparsers(
        dest="command", required=True, parser_class=PrivacySafeArgumentParser
    )

    build = commands.add_parser("build")
    build.add_argument("--admission-helper", type=Path, required=True)
    build.add_argument("--smoke-helper", type=Path, required=True)
    build.add_argument("--wrapper", type=Path, required=True)
    build.add_argument("--record-schema", type=Path, required=True)
    build.add_argument("--source-date-epoch", type=parse_epoch_argument, required=True)
    build.add_argument("--output", type=Path, required=True)
    build.set_defaults(handler=build_bundle)

    verify = commands.add_parser("verify")
    verify.add_argument("--archive", type=Path, required=True)
    verify.add_argument("--expected-archive-sha256", required=True)
    verify.add_argument("--expected-identity-sha256")
    verify.add_argument("--source-date-epoch", type=parse_epoch_argument, required=True)
    verify.set_defaults(handler=verify_bundle)

    extract = commands.add_parser("extract")
    extract.add_argument("--archive", type=Path, required=True)
    extract.add_argument("--expected-archive-sha256", required=True)
    extract.add_argument("--expected-identity-sha256")
    extract.add_argument("--source-date-epoch", type=parse_epoch_argument, required=True)
    extract.add_argument("--destination", type=Path, required=True)
    extract.add_argument("--admission-output", type=Path, required=True)
    extract.add_argument("--expected-verifier-sha256", required=True)
    extract.add_argument("--verifier-trust-anchor", type=Path, default=Path("/"))
    extract.add_argument("--archive-trust-anchor", type=Path, default=Path("/"))
    extract.add_argument("--destination-trust-anchor", type=Path, default=Path("/"))
    extract.set_defaults(handler=extract_bundle)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    try:
        args = build_parser().parse_args(argv)
        result = args.handler(args)
        sys.stdout.buffer.write(canonical_json(result))
        return 0
    except ToolsBundleError as exc:
        print(f"build-image-rollout-tools: {exc}", file=sys.stderr)
        return 1
    except (OSError, ValueError):
        print(
            "build-image-rollout-tools: secured filesystem operation failed",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
