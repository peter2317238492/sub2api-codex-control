#!/usr/bin/env python3
"""Install the pinned Crane producer and deterministically export OCI images."""

from __future__ import annotations

import argparse
import base64
import binascii
import ctypes
import errno
import hashlib
import json
import os
import platform
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import urllib.parse
import urllib.request
from collections.abc import Callable, Iterable, Mapping, Sequence
from pathlib import Path, PurePosixPath
from typing import Any, BinaryIO


POLICY_PATH = Path(__file__).with_name("toolchain.json")
COMPONENTS = ("control-api", "pwa", "postgres-tools")
ARCHIVE_NAMES = {
    "control-api": "control-api.oci.tar",
    "pwa": "pwa.oci.tar",
    "postgres-tools": "postgres-tools.oci.tar",
}
EXPECTED_ARCHIVE_MEMBERS = frozenset(
    {"LICENSE", "README.md", "crane", "gcrane", "krane"}
)
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
CHECKSUM_LINE_RE = re.compile(r"^([0-9a-f]{64})  ([A-Za-z0-9._-]+)$")
REFERENCE_RE = re.compile(
    r"^(?P<repository>"
    r"[a-z0-9]+(?:[._-][a-z0-9]+)*(?::[0-9]+)?"
    r"(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)+"
    r")@sha256:(?P<digest>[0-9a-f]{64})$"
)
DOWNLOAD_CHUNK = 1024 * 1024
MAX_POLICY_BYTES = 128 * 1024
MAX_METADATA_BYTES = 1024 * 1024
MAX_OCI_MEMBERS = 65536
MAX_OCI_ARCHIVE_BYTES = 8 * 1024 * 1024 * 1024
USTAR_MAX_FILE_BYTES = (1 << 33) - 1
IMAGE_MANIFEST_MEDIA_TYPES = frozenset(
    {
        "application/vnd.oci.image.manifest.v1+json",
        "application/vnd.docker.distribution.manifest.v2+json",
    }
)


class ToolchainError(RuntimeError):
    pass


def fail(message: str) -> None:
    raise ToolchainError(message)


def exact_keys(value: Mapping[str, Any], expected: Iterable[str], label: str) -> None:
    expected_set = set(expected)
    actual_set = set(value)
    if actual_set != expected_set:
        fail(
            f"{label} keys differ: expected {sorted(expected_set)!r}, "
            f"got {sorted(actual_set)!r}"
        )


def mapping(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        fail(f"{label} must be an object")
    return value


def positive_integer(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        fail(f"{label} must be a positive integer")
    return value


def sha256_value(value: Any, label: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        fail(f"{label} must be a lowercase SHA-256 digest")
    return value


def duplicate_rejecting_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            fail(f"JSON contains duplicate key {key!r}")
        result[key] = value
    return result


def reject_nonstandard_json_constant(value: str) -> None:
    fail(f"JSON contains non-standard numeric constant {value!r}")


def parse_json(raw: bytes, label: str) -> Any:
    try:
        text = raw.decode("utf-8", errors="strict")
        return json.loads(
            text,
            object_pairs_hook=duplicate_rejecting_object,
            parse_constant=reject_nonstandard_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"{label} is not strict JSON: {error}")


def safe_path(path: Path, label: str, *, must_exist: bool = True) -> os.stat_result:
    try:
        info = path.lstat()
    except FileNotFoundError:
        if must_exist:
            fail(f"{label} does not exist: {path}")
        raise
    if stat.S_ISLNK(info.st_mode):
        fail(f"{label} must not be a symbolic link: {path}")
    return info


def regular_file(path: Path, label: str) -> os.stat_result:
    info = safe_path(path, label)
    if not stat.S_ISREG(info.st_mode):
        fail(f"{label} must be a regular file: {path}")
    if info.st_uid not in {0, os.geteuid()}:
        fail(f"{label} is not owned by root or the current release user: {path}")
    if info.st_mode & 0o022:
        fail(f"{label} must not be writable by group or other users: {path}")
    if info.st_nlink != 1:
        fail(f"{label} must have exactly one hard link: {path}")
    return info


def real_directory(path: Path, label: str) -> os.stat_result:
    info = safe_path(path, label)
    if not stat.S_ISDIR(info.st_mode):
        fail(f"{label} must be a directory: {path}")
    return info


def absolute_normal_path(path: Path, label: str) -> Path:
    if not path.is_absolute():
        fail(f"{label} must be an absolute path")
    normalized = Path(os.path.normpath(os.fspath(path)))
    if normalized != path:
        fail(f"{label} must be lexically normalized")
    return path


def ensure_real_parent_chain(path: Path, label: str) -> None:
    absolute_normal_path(path, label)
    current = Path(path.anchor)
    real_directory(current, f"{label} root")
    for part in path.parts[1:]:
        current /= part
        real_directory(current, label)


def ensure_owner_controlled_parent_chain(path: Path, label: str) -> None:
    absolute_normal_path(path, label)
    current = Path(path.anchor)
    for part in (None, *path.parts[1:]):
        if part is not None:
            current /= part
        info = real_directory(current, label)
        if info.st_uid not in {0, os.geteuid()}:
            fail(f"{label} is not owned by root or the current release user: {current}")
        if info.st_mode & 0o022:
            fail(f"{label} is writable by group or other users: {current}")


def opened_regular(path: Path, label: str) -> tuple[BinaryIO, os.stat_result]:
    before = regular_file(path, label)
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        fail(f"cannot securely open {label}: {error}")
    after = os.fstat(descriptor)
    if not stat.S_ISREG(after.st_mode) or (
        before.st_dev,
        before.st_ino,
    ) != (after.st_dev, after.st_ino):
        os.close(descriptor)
        fail(f"{label} changed while it was opened")
    return os.fdopen(descriptor, "rb"), after


def file_identity(
    path: Path,
    label: str,
    *,
    maximum_size: int | None = None,
) -> tuple[int, str]:
    stream, info = opened_regular(path, label)
    if maximum_size is not None and info.st_size > maximum_size:
        stream.close()
        fail(f"{label} exceeds its maximum size")
    digest = hashlib.sha256()
    observed = 0
    with stream:
        while chunk := stream.read(DOWNLOAD_CHUNK):
            observed += len(chunk)
            if maximum_size is not None and observed > maximum_size:
                fail(f"{label} exceeds its maximum size")
            digest.update(chunk)
    if observed != info.st_size:
        fail(f"{label} changed while it was read")
    return observed, digest.hexdigest()


def read_regular(path: Path, label: str, maximum_size: int) -> bytes:
    stream, info = opened_regular(path, label)
    if info.st_size > maximum_size:
        stream.close()
        fail(f"{label} exceeds its maximum size")
    with stream:
        raw = stream.read(maximum_size + 1)
    if len(raw) != info.st_size or len(raw) > maximum_size:
        fail(f"{label} changed while it was read or exceeds its maximum size")
    return raw


def validate_policy(value: Any) -> dict[str, Any]:
    policy = mapping(value, "toolchain policy")
    exact_keys(
        policy,
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
        "toolchain policy",
    )
    if policy["format_version"] != 1:
        fail("toolchain policy format_version must be 1")
    if policy["tool"] != "crane" or policy["version"] != "0.21.7":
        fail("toolchain policy must pin crane 0.21.7")

    release = mapping(policy["release"], "release")
    exact_keys(release, {"repository", "tag"}, "release")
    if release != {
        "repository": "https://github.com/google/go-containerregistry",
        "tag": "v0.21.7",
    }:
        fail("toolchain release identity differs from the reviewed upstream release")

    target = mapping(policy["platform"], "platform")
    exact_keys(target, {"os", "architecture", "archive_platform"}, "platform")
    if target != {
        "os": "linux",
        "architecture": "amd64",
        "archive_platform": "Linux_x86_64",
    }:
        fail("toolchain platform must be exactly linux/amd64")

    expected_asset_names = {
        "archive": "go-containerregistry_Linux_x86_64.tar.gz",
        "checksums": "checksums.txt",
        "provenance": "multiple.intoto.jsonl",
    }
    assets = mapping(policy["assets"], "assets")
    exact_keys(assets, expected_asset_names, "assets")
    for role, expected_name in expected_asset_names.items():
        asset = mapping(assets[role], f"assets.{role}")
        exact_keys(asset, {"filename", "url", "size", "sha256"}, f"assets.{role}")
        if asset["filename"] != expected_name:
            fail(f"assets.{role}.filename differs from {expected_name}")
        expected_url = (
            "https://github.com/google/go-containerregistry/releases/download/"
            f"v0.21.7/{expected_name}"
        )
        if asset["url"] != expected_url:
            fail(f"assets.{role}.url differs from the pinned GitHub release URL")
        positive_integer(asset["size"], f"assets.{role}.size")
        sha256_value(asset["sha256"], f"assets.{role}.sha256")

    archive = mapping(policy["archive"], "archive")
    exact_keys(archive, {"members", "binary_member", "binary_sha256"}, "archive")
    members = archive["members"]
    if not isinstance(members, list):
        fail("archive.members must be an array")
    member_names: set[str] = set()
    for index, raw_member in enumerate(members):
        member = mapping(raw_member, f"archive.members[{index}]")
        exact_keys(member, {"name", "mode", "size"}, f"archive.members[{index}]")
        name = member["name"]
        if not isinstance(name, str) or name in member_names:
            fail("archive member names must be unique strings")
        member_names.add(name)
        if member["mode"] not in {"0644", "0755"}:
            fail(f"archive member {name!r} has an unsupported mode")
        positive_integer(member["size"], f"archive member {name!r} size")
    if member_names != EXPECTED_ARCHIVE_MEMBERS:
        fail("archive member inventory differs from the reviewed upstream archive")
    if archive["binary_member"] != "crane":
        fail("archive.binary_member must be crane")
    sha256_value(archive["binary_sha256"], "archive.binary_sha256")

    provenance = mapping(policy["provenance"], "provenance")
    exact_keys(
        provenance,
        {"media_type", "payload_type", "statement_type", "predicate_type"},
        "provenance",
    )
    expected_provenance = {
        "media_type": "application/vnd.dev.sigstore.bundle.v0.3+json",
        "payload_type": "application/vnd.in-toto+json",
        "statement_type": "https://in-toto.io/Statement/v0.1",
        "predicate_type": "https://slsa.dev/provenance/v0.2",
    }
    if provenance != expected_provenance:
        fail("provenance contract differs from the reviewed upstream bundle")
    return policy


def load_policy(path: Path = POLICY_PATH) -> dict[str, Any]:
    raw = read_regular(path, "toolchain policy", MAX_POLICY_BYTES)
    return validate_policy(parse_json(raw, "toolchain policy"))


def verify_asset(path: Path, asset: Mapping[str, Any], label: str) -> None:
    observed_size, observed_digest = file_identity(
        path,
        label,
        maximum_size=int(asset["size"]),
    )
    if observed_size != asset["size"]:
        fail(f"{label} size differs from the pinned value")
    if observed_digest != asset["sha256"]:
        fail(f"{label} SHA-256 differs from the pinned value")


def verify_checksums(raw: bytes, archive_asset: Mapping[str, Any]) -> None:
    try:
        lines = raw.decode("utf-8", errors="strict").splitlines()
    except UnicodeDecodeError as error:
        fail(f"checksums.txt is not UTF-8: {error}")
    records: dict[str, str] = {}
    for line in lines:
        match = CHECKSUM_LINE_RE.fullmatch(line)
        if match is None:
            fail("checksums.txt contains a malformed line")
        digest, filename = match.groups()
        if filename in records:
            fail(f"checksums.txt repeats {filename!r}")
        records[filename] = digest
    expected_name = archive_asset["filename"]
    if records.get(expected_name) != archive_asset["sha256"]:
        fail("checksums.txt does not bind the pinned Linux x86_64 archive")


def verify_provenance(
    raw: bytes,
    archive_asset: Mapping[str, Any],
    contract: Mapping[str, Any],
) -> None:
    bundle = mapping(parse_json(raw, "multiple.intoto.jsonl"), "provenance bundle")
    exact_keys(
        bundle,
        {"mediaType", "verificationMaterial", "dsseEnvelope"},
        "provenance bundle",
    )
    if bundle["mediaType"] != contract["media_type"]:
        fail("provenance bundle media type differs from policy")
    mapping(bundle["verificationMaterial"], "provenance verification material")
    envelope = mapping(bundle["dsseEnvelope"], "provenance DSSE envelope")
    exact_keys(envelope, {"payload", "payloadType", "signatures"}, "DSSE envelope")
    if envelope["payloadType"] != contract["payload_type"]:
        fail("provenance DSSE payload type differs from policy")
    signatures = envelope["signatures"]
    if not isinstance(signatures, list) or not signatures:
        fail("provenance DSSE envelope has no signature")
    payload_text = envelope["payload"]
    if not isinstance(payload_text, str):
        fail("provenance DSSE payload must be base64 text")
    try:
        payload_raw = base64.b64decode(payload_text, validate=True)
    except (binascii.Error, ValueError) as error:
        fail(f"provenance DSSE payload is not strict base64: {error}")
    statement = mapping(parse_json(payload_raw, "provenance statement"), "statement")
    if statement.get("_type") != contract["statement_type"]:
        fail("provenance statement type differs from policy")
    if statement.get("predicateType") != contract["predicate_type"]:
        fail("provenance predicate type differs from policy")
    subjects = statement.get("subject")
    if not isinstance(subjects, list):
        fail("provenance statement subject must be an array")
    by_name: dict[str, str] = {}
    for index, raw_subject in enumerate(subjects):
        subject = mapping(raw_subject, f"provenance subject[{index}]")
        exact_keys(subject, {"name", "digest"}, f"provenance subject[{index}]")
        name = subject["name"]
        if not isinstance(name, str) or name in by_name:
            fail("provenance subjects must have unique string names")
        digest = mapping(subject["digest"], f"provenance subject {name!r} digest")
        exact_keys(digest, {"sha256"}, f"provenance subject {name!r} digest")
        by_name[name] = sha256_value(
            digest["sha256"], f"provenance subject {name!r} SHA-256"
        )
    expected_name = archive_asset["filename"]
    if by_name.get(expected_name) != archive_asset["sha256"]:
        fail("upstream provenance does not bind the pinned Linux x86_64 archive")


def evidence_paths(directory: Path, policy: Mapping[str, Any]) -> dict[str, Path]:
    absolute_normal_path(directory, "evidence directory")
    real_directory(directory, "evidence directory")
    expected = {
        asset["filename"] for asset in mapping(policy["assets"], "assets").values()
    }
    actual: set[str] = set()
    for child in directory.iterdir():
        regular_file(child, "evidence file")
        actual.add(child.name)
    if actual != expected:
        fail(
            f"evidence directory inventory differs: expected {sorted(expected)!r}, "
            f"got {sorted(actual)!r}"
        )
    return {
        role: directory / asset["filename"]
        for role, asset in mapping(policy["assets"], "assets").items()
    }


def verify_evidence(directory: Path, policy: Mapping[str, Any]) -> dict[str, Path]:
    paths = evidence_paths(directory, policy)
    assets = mapping(policy["assets"], "assets")
    verify_asset(paths["archive"], mapping(assets["archive"], "archive"), "archive")
    checksums_raw = read_regular(paths["checksums"], "checksums.txt", MAX_METADATA_BYTES)
    checksums_asset = mapping(assets["checksums"], "checksums asset")
    if (
        len(checksums_raw) != checksums_asset["size"]
        or hashlib.sha256(checksums_raw).hexdigest() != checksums_asset["sha256"]
    ):
        fail("checksums evidence differs from its pinned identity")
    provenance_raw = read_regular(
        paths["provenance"], "multiple.intoto.jsonl", MAX_METADATA_BYTES
    )
    provenance_asset = mapping(assets["provenance"], "provenance asset")
    if (
        len(provenance_raw) != provenance_asset["size"]
        or hashlib.sha256(provenance_raw).hexdigest() != provenance_asset["sha256"]
    ):
        fail("provenance evidence differs from its pinned identity")
    verify_checksums(
        checksums_raw,
        mapping(assets["archive"], "archive asset"),
    )
    verify_provenance(
        provenance_raw,
        mapping(assets["archive"], "archive asset"),
        mapping(policy["provenance"], "provenance contract"),
    )
    return paths


def download_asset(destination: Path, asset: Mapping[str, Any]) -> None:
    if destination.exists() or destination.is_symlink():
        fail(f"download destination already exists: {destination}")
    request = urllib.request.Request(
        str(asset["url"]),
        headers={
            "Accept": "application/octet-stream",
            "User-Agent": "sub2api-control-oci-toolchain/1",
        },
    )
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(destination, flags, 0o600)
    try:
        with urllib.request.urlopen(request, timeout=60) as response:  # noqa: S310
            final_url = urllib.parse.urlparse(response.geturl())
            if final_url.scheme != "https":
                fail("toolchain download was redirected away from HTTPS")
            if getattr(response, "status", 200) != 200:
                fail(f"toolchain download returned HTTP {response.status}")
            header_length = response.headers.get("Content-Length")
            if header_length is not None:
                try:
                    if int(header_length) != asset["size"]:
                        fail("toolchain download Content-Length differs from policy")
                except ValueError:
                    fail("toolchain download Content-Length is malformed")
            observed = 0
            with os.fdopen(descriptor, "wb", closefd=False) as output:
                while chunk := response.read(DOWNLOAD_CHUNK):
                    observed += len(chunk)
                    if observed > asset["size"]:
                        fail("toolchain download exceeds the pinned size")
                    output.write(chunk)
                output.flush()
                os.fsync(output.fileno())
            if observed != asset["size"]:
                fail("toolchain download size differs from policy")
    except Exception:
        os.close(descriptor)
        try:
            destination.unlink()
        except FileNotFoundError:
            pass
        raise
    else:
        os.close(descriptor)
    verify_asset(destination, asset, f"downloaded {asset['filename']}")


def download_evidence(directory: Path, policy: Mapping[str, Any]) -> None:
    real_directory(directory, "download directory")
    if any(directory.iterdir()):
        fail("download directory must be empty")
    assets = mapping(policy["assets"], "assets")
    for role in ("archive", "checksums", "provenance"):
        asset = mapping(assets[role], f"assets.{role}")
        download_asset(directory / asset["filename"], asset)


def validate_tar_name(name: str) -> None:
    if not name or "\\" in name or "\x00" in name:
        fail("toolchain archive contains an invalid member name")
    path = PurePosixPath(name)
    if path.is_absolute() or name != path.as_posix() or any(
        part in {"", ".", ".."} for part in path.parts
    ):
        fail(f"toolchain archive contains unsafe member {name!r}")


def configured_members(policy: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    archive = mapping(policy["archive"], "archive")
    return {
        mapping(member, "archive member")["name"]: mapping(member, "archive member")
        for member in archive["members"]
    }


def write_binary_no_replace(
    source: BinaryIO,
    destination: Path,
    expected_size: int,
    expected_digest: str,
) -> None:
    absolute_normal_path(destination, "crane destination")
    ensure_owner_controlled_parent_chain(destination.parent, "crane destination parent")
    try:
        safe_path(destination, "crane destination", must_exist=False)
    except FileNotFoundError:
        pass
    else:
        fail(f"crane destination already exists: {destination}")

    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.", suffix=".tmp", dir=destination.parent
    )
    temporary = Path(temporary_name)
    digest = hashlib.sha256()
    observed = 0
    try:
        with os.fdopen(descriptor, "wb") as output:
            while chunk := source.read(DOWNLOAD_CHUNK):
                observed += len(chunk)
                if observed > expected_size:
                    fail("crane archive member exceeds the pinned size")
                digest.update(chunk)
                output.write(chunk)
            output.flush()
            os.fsync(output.fileno())
            os.fchmod(output.fileno(), 0o555)
        if observed != expected_size:
            fail("crane archive member size differs from policy")
        if digest.hexdigest() != expected_digest:
            fail("crane archive member SHA-256 differs from policy")
        try:
            os.link(temporary, destination, follow_symlinks=False)
        except FileExistsError:
            fail(f"crane destination already exists: {destination}")
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def extract_crane(
    archive_path: Path,
    destination: Path,
    policy: Mapping[str, Any],
) -> None:
    archive_asset = mapping(mapping(policy["assets"], "assets")["archive"], "archive")
    verify_asset(archive_path, archive_asset, "crane archive")
    expected = configured_members(policy)
    archive_policy = mapping(policy["archive"], "archive")
    binary_name = archive_policy["binary_member"]
    stream, _ = opened_regular(archive_path, "crane archive")
    with stream:
        try:
            with tarfile.open(fileobj=stream, mode="r:gz") as archive:
                observed: dict[str, tarfile.TarInfo] = {}
                for member in archive.getmembers():
                    validate_tar_name(member.name)
                    if member.name in observed:
                        fail(f"toolchain archive repeats member {member.name!r}")
                    if not member.isfile():
                        fail(
                            f"toolchain archive member {member.name!r} is not a regular file"
                        )
                    observed[member.name] = member
                if set(observed) != set(expected):
                    fail("toolchain archive inventory differs from policy")
                for name, member in observed.items():
                    expected_member = expected[name]
                    if member.size != expected_member["size"]:
                        fail(f"toolchain archive member {name!r} size differs from policy")
                    if stat.S_IMODE(member.mode) != int(expected_member["mode"], 8):
                        fail(f"toolchain archive member {name!r} mode differs from policy")
                binary_stream = archive.extractfile(observed[binary_name])
                if binary_stream is None:
                    fail("cannot read the pinned crane archive member")
                with binary_stream:
                    write_binary_no_replace(
                        binary_stream,
                        destination,
                        int(expected[binary_name]["size"]),
                        archive_policy["binary_sha256"],
                    )
        except (tarfile.TarError, OSError) as error:
            fail(f"cannot inspect the pinned crane archive: {error}")


def verify_crane_binary(path: Path, policy: Mapping[str, Any]) -> dict[str, Any]:
    absolute_normal_path(path, "crane path")
    ensure_owner_controlled_parent_chain(path.parent, "crane parent")
    info = regular_file(path, "crane binary")
    if stat.S_IMODE(info.st_mode) != 0o555:
        fail("crane binary mode must be exactly 0555")
    archive_policy = mapping(policy["archive"], "archive")
    members = configured_members(policy)
    binary = members[archive_policy["binary_member"]]
    size, digest = file_identity(path, "crane binary", maximum_size=binary["size"])
    if size != binary["size"] or digest != archive_policy["binary_sha256"]:
        fail("crane binary differs from the pinned archive member")
    return {
        "name": policy["tool"],
        "version": policy["version"],
        "platform": "linux/amd64",
        "size": size,
        "sha256": digest,
    }


def require_linux_amd64() -> None:
    if platform.system().lower() != "linux" or platform.machine().lower() not in {
        "amd64",
        "x86_64",
    }:
        fail("the pinned producer may run only on Linux x86_64")


def parse_image_specs(values: Sequence[str]) -> dict[str, str]:
    result: dict[str, str] = {}
    for value in values:
        if "=" not in value:
            fail("each --image must use COMPONENT=REPOSITORY@sha256:DIGEST")
        component, reference = value.split("=", 1)
        if component not in COMPONENTS:
            fail(f"unsupported image component {component!r}")
        if component in result:
            fail(f"image component {component!r} was provided more than once")
        if REFERENCE_RE.fullmatch(reference) is None:
            fail(f"image {component!r} is not an exact digest reference")
        result[component] = reference
    if set(result) != set(COMPONENTS):
        fail(f"--image must provide exactly {list(COMPONENTS)!r}")
    return result


def prepare_output_destination(path: Path) -> None:
    absolute_normal_path(path, "image output directory")
    ensure_owner_controlled_parent_chain(path.parent, "image output parent")
    try:
        safe_path(path, "image output directory", must_exist=False)
    except FileNotFoundError:
        return
    fail(f"image output directory already exists: {path}")


def private_staging_directory(destination: Path) -> Path:
    prepare_output_destination(destination)
    staging = Path(
        tempfile.mkdtemp(
            prefix=f".{destination.name}.", suffix=".tmp", dir=destination.parent
        )
    )
    os.chmod(staging, 0o700)
    return staging


def remove_private_staging_directory(staging: Path, destination: Path) -> None:
    expected_prefix = f".{destination.name}."
    if (
        staging.parent != destination.parent
        or not staging.name.startswith(expected_prefix)
        or not staging.name.endswith(".tmp")
    ):
        fail("refusing to remove an unexpected staging directory")
    info = real_directory(staging, "private staging directory")
    if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
        fail("refusing to remove a staging directory outside current-user control")
    shutil.rmtree(staging)


def promote_directory_no_replace(staging: Path, destination: Path) -> None:
    prepare_output_destination(destination)
    if sys.platform.startswith("linux"):
        libc = ctypes.CDLL(None, use_errno=True)
        renameat2 = getattr(libc, "renameat2", None)
        if renameat2 is None:
            fail("Linux renameat2 is required for no-replace output promotion")
        renameat2.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        ]
        renameat2.restype = ctypes.c_int
        result = renameat2(
            -100,
            os.fsencode(staging),
            -100,
            os.fsencode(destination),
            1,
        )
        if result != 0:
            error_number = ctypes.get_errno()
            if error_number in {errno.EEXIST, errno.ENOTEMPTY}:
                fail(f"image output directory already exists: {destination}")
            fail(f"cannot atomically promote image output: {os.strerror(error_number)}")
    else:
        # Export itself is Linux-only; this path exists only for mocked unit tests.
        os.rename(staging, destination)


def crane_environment() -> dict[str, str]:
    result = {"LANG": "C", "LC_ALL": "C", "TZ": "UTC"}
    for name in (
        "HOME",
        "DOCKER_CONFIG",
        "SSL_CERT_FILE",
        "SSL_CERT_DIR",
        "XDG_CONFIG_HOME",
        "TMPDIR",
    ):
        value = os.environ.get(name)
        if value:
            result[name] = value
    return result


def run_crane(
    command: list[str],
    timeout_seconds: int,
    runner: Callable[..., Any],
    policy: Mapping[str, Any],
) -> None:
    verify_crane_binary(Path(command[0]), policy)
    try:
        completed = runner(
            command,
            check=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=crane_environment(),
            timeout=timeout_seconds,
        )
    except (OSError, subprocess.SubprocessError) as error:
        fail(f"cannot run the pinned Crane producer: {error}")
    if completed.returncode != 0:
        fail(f"the pinned Crane producer failed with exit code {completed.returncode}")


def capture_crane_stdout(
    command: list[str],
    destination: Path,
    timeout_seconds: int,
    runner: Callable[..., Any],
    policy: Mapping[str, Any],
) -> bytes:
    verify_crane_binary(Path(command[0]), policy)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(destination, flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as output:
            try:
                completed = runner(
                    command,
                    check=False,
                    stdin=subprocess.DEVNULL,
                    stdout=output,
                    stderr=subprocess.DEVNULL,
                    env=crane_environment(),
                    timeout=timeout_seconds,
                )
            except (OSError, subprocess.SubprocessError) as error:
                fail(f"cannot run the pinned Crane producer: {error}")
            output.flush()
            os.fsync(output.fileno())
        if completed.returncode != 0:
            fail(f"the pinned Crane producer failed with exit code {completed.returncode}")
        return read_regular(destination, "remote image manifest", MAX_METADATA_BYTES)
    finally:
        try:
            destination.unlink()
        except FileNotFoundError:
            pass


def inspect_remote_manifest(
    crane: Path,
    reference: str,
    scratch_path: Path,
    timeout_seconds: int,
    runner: Callable[..., Any],
    policy: Mapping[str, Any],
) -> dict[str, Any]:
    match = REFERENCE_RE.fullmatch(reference)
    if match is None:
        fail("remote manifest reference is not an exact digest reference")
    raw = capture_crane_stdout(
        [os.fspath(crane), "manifest", reference],
        scratch_path,
        timeout_seconds,
        runner,
        policy,
    )
    observed_digest = hashlib.sha256(raw).hexdigest()
    if observed_digest != match.group("digest"):
        fail("remote manifest raw SHA-256 differs from the signed lock digest")
    manifest = mapping(parse_json(raw, "remote image manifest"), "remote image manifest")
    if manifest.get("schemaVersion") != 2:
        fail("remote image manifest schemaVersion must be 2")
    media_type = manifest.get("mediaType")
    if media_type not in IMAGE_MANIFEST_MEDIA_TYPES:
        fail(
            "signed image lock resolves to a top-level index or unsupported media type; "
            "this package version requires a direct image manifest digest"
        )
    return {
        "media_type": media_type,
        "sha256": observed_digest,
        "size": len(raw),
    }


def equal_files(first: Path, second: Path) -> bool:
    first_stream, first_info = opened_regular(first, "first OCI export")
    second_stream, second_info = opened_regular(second, "repeated OCI export")
    if first_info.st_size != second_info.st_size:
        first_stream.close()
        second_stream.close()
        return False
    with first_stream, second_stream:
        while True:
            first_chunk = first_stream.read(DOWNLOAD_CHUNK)
            second_chunk = second_stream.read(DOWNLOAD_CHUNK)
            if first_chunk != second_chunk:
                return False
            if not first_chunk:
                return True


def owned_path(path: Path, label: str, *, directory: bool) -> os.stat_result:
    info = real_directory(path, label) if directory else regular_file(path, label)
    if info.st_uid != os.geteuid():
        fail(f"{label} is not owned by the current release user: {path}")
    return info


def scan_oci_layout(layout: Path) -> list[tuple[str, Path, os.stat_result]]:
    owned_path(layout, "OCI layout root", directory=True)
    root_entries = {child.name: child for child in layout.iterdir()}
    if set(root_entries) != {"blobs", "index.json", "oci-layout"}:
        fail("Crane OCI layout root inventory is not exact")

    blobs = root_entries["blobs"]
    owned_path(blobs, "OCI blobs directory", directory=True)
    blob_algorithms = {child.name: child for child in blobs.iterdir()}
    if set(blob_algorithms) != {"sha256"}:
        fail("Crane OCI layout contains an unexpected blob algorithm directory")
    sha_directory = blob_algorithms["sha256"]
    owned_path(sha_directory, "OCI sha256 blob directory", directory=True)

    files: list[tuple[str, Path, os.stat_result]] = []
    for name in ("index.json", "oci-layout"):
        path = root_entries[name]
        files.append((name, path, owned_path(path, f"OCI {name}", directory=False)))

    blob_entries = list(sha_directory.iterdir())
    if not blob_entries:
        fail("Crane OCI layout contains no blobs")
    for blob in blob_entries:
        if SHA256_RE.fullmatch(blob.name) is None:
            fail(f"Crane OCI layout contains invalid blob name {blob.name!r}")
        relative = f"blobs/sha256/{blob.name}"
        files.append(
            (relative, blob, owned_path(blob, f"OCI blob {blob.name}", directory=False))
        )

    if len(files) + 2 > MAX_OCI_MEMBERS:
        fail("Crane OCI layout contains too many members")
    if any(info.st_size > USTAR_MAX_FILE_BYTES for _, _, info in files):
        fail("Crane OCI layout contains a file too large for USTAR")

    layout_value = mapping(
        parse_json(
            read_regular(root_entries["oci-layout"], "oci-layout", MAX_METADATA_BYTES),
            "oci-layout",
        ),
        "oci-layout",
    )
    if layout_value != {"imageLayoutVersion": "1.0.0"}:
        fail("Crane OCI layout version is unsupported")
    index_value = mapping(
        parse_json(
            read_regular(root_entries["index.json"], "index.json", MAX_METADATA_BYTES),
            "index.json",
        ),
        "index.json",
    )
    if index_value.get("schemaVersion") != 2:
        fail("Crane OCI index schemaVersion must be 2")
    manifests = index_value.get("manifests")
    if not isinstance(manifests, list) or len(manifests) != 1:
        fail("Crane OCI index must contain exactly one selected manifest")
    return sorted(files, key=lambda item: item[0].encode("utf-8"))


def normalized_tar_info(name: str, *, directory: bool, size: int = 0) -> tarfile.TarInfo:
    info = tarfile.TarInfo(f"{name}/" if directory else name)
    info.type = tarfile.DIRTYPE if directory else tarfile.REGTYPE
    info.mode = 0o555 if directory else 0o444
    info.uid = 0
    info.gid = 0
    info.uname = ""
    info.gname = ""
    info.mtime = 0
    info.size = 0 if directory else size
    return info


def normalized_tar_size(files: Sequence[tuple[str, Path, os.stat_result]]) -> int:
    member_sizes = [0, 0, *(info.st_size for _, _, info in files)]
    total = sum(512 + ((size + 511) // 512) * 512 for size in member_sizes) + 1024
    return ((total + tarfile.RECORDSIZE - 1) // tarfile.RECORDSIZE) * tarfile.RECORDSIZE


def pack_oci_layout(layout: Path, destination: Path) -> None:
    files = scan_oci_layout(layout)
    if normalized_tar_size(files) > MAX_OCI_ARCHIVE_BYTES:
        fail("normalized OCI archive would exceed the downstream 8 GiB limit")
    absolute_normal_path(destination, "OCI archive destination")
    ensure_real_parent_chain(destination.parent, "OCI archive parent")
    try:
        safe_path(destination, "OCI archive destination", must_exist=False)
    except FileNotFoundError:
        pass
    else:
        fail(f"OCI archive destination already exists: {destination}")

    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.", suffix=".tmp", dir=destination.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as output:
            try:
                with tarfile.open(
                    fileobj=output, mode="w", format=tarfile.USTAR_FORMAT
                ) as archive:
                    archive.addfile(normalized_tar_info("blobs", directory=True))
                    archive.addfile(normalized_tar_info("blobs/sha256", directory=True))
                    for relative, path, scanned_info in files:
                        stream, opened_info = opened_regular(
                            path, f"OCI layout file {relative}"
                        )
                        if (
                            scanned_info.st_dev,
                            scanned_info.st_ino,
                            scanned_info.st_size,
                        ) != (
                            opened_info.st_dev,
                            opened_info.st_ino,
                            opened_info.st_size,
                        ):
                            stream.close()
                            fail(f"OCI layout file changed before packing: {relative}")
                        with stream:
                            archive.addfile(
                                normalized_tar_info(
                                    relative, directory=False, size=opened_info.st_size
                                ),
                                stream,
                            )
            except (tarfile.TarError, ValueError, OverflowError) as error:
                fail(f"cannot normalize OCI layout as USTAR: {error}")
            output.flush()
            os.fsync(output.fileno())
            os.fchmod(output.fileno(), 0o444)
            if output.tell() > MAX_OCI_ARCHIVE_BYTES:
                fail("normalized OCI archive exceeds the downstream 8 GiB limit")
        try:
            os.link(temporary, destination, follow_symlinks=False)
        except FileExistsError:
            fail(f"OCI archive destination already exists: {destination}")
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def remove_verified_layout(
    layout: Path, files: Sequence[tuple[str, Path, os.stat_result]]
) -> None:
    for relative, path, scanned_info in reversed(files):
        current = regular_file(path, f"temporary OCI layout file {relative}")
        if (current.st_dev, current.st_ino) != (scanned_info.st_dev, scanned_info.st_ino):
            fail(f"temporary OCI layout file changed before cleanup: {relative}")
        path.unlink()
    (layout / "blobs/sha256").rmdir()
    (layout / "blobs").rmdir()
    layout.rmdir()


def pack_and_remove_layout(layout: Path, destination: Path) -> None:
    files = scan_oci_layout(layout)
    pack_oci_layout(layout, destination)
    remove_verified_layout(layout, files)


def export_images(
    crane: Path,
    output_directory: Path,
    references: Mapping[str, str],
    policy: Mapping[str, Any],
    *,
    timeout_seconds: int,
    runner: Callable[..., Any] = subprocess.run,
) -> dict[str, Any]:
    require_linux_amd64()
    producer = verify_crane_binary(crane, policy)
    if set(references) != set(COMPONENTS):
        fail("image reference mapping is incomplete")
    for component, reference in references.items():
        if component not in COMPONENTS or REFERENCE_RE.fullmatch(reference) is None:
            fail("image reference mapping contains an invalid entry")
    positive_integer(timeout_seconds, "timeout_seconds")
    staging = private_staging_directory(output_directory)
    records: list[dict[str, Any]] = []
    try:
        for component in COMPONENTS:
            reference = references[component]
            output = staging / ARCHIVE_NAMES[component]
            repeated = staging / f".{ARCHIVE_NAMES[component]}.repeat"
            first_layout = staging / f".{component}.attempt-1.oci-layout"
            repeated_layout = staging / f".{component}.attempt-2.oci-layout"
            remote_manifest = inspect_remote_manifest(
                crane,
                reference,
                staging / f".{component}.remote-manifest.json",
                timeout_seconds,
                runner,
                policy,
            )
            command_prefix = [
                os.fspath(crane),
                "pull",
                "--platform",
                "linux/amd64",
                "--format=oci",
                "--annotate-ref",
                reference,
            ]
            run_crane(
                command_prefix + [os.fspath(first_layout)],
                timeout_seconds,
                runner,
                policy,
            )
            pack_and_remove_layout(first_layout, output)
            run_crane(
                command_prefix + [os.fspath(repeated_layout)],
                timeout_seconds,
                runner,
                policy,
            )
            pack_and_remove_layout(repeated_layout, repeated)
            try:
                if not equal_files(output, repeated):
                    fail(f"{component} OCI export is not byte-for-byte deterministic")
            finally:
                try:
                    repeated.unlink()
                except FileNotFoundError:
                    pass
            size, digest = file_identity(output, f"{component} OCI export")
            if size == 0 or size > MAX_OCI_ARCHIVE_BYTES:
                fail(f"{component} OCI export size is outside the accepted range")
            records.append(
                {
                    "archive": output.name,
                    "component": component,
                    "reference": reference,
                    "remote_manifest": remote_manifest,
                    "repeat_verified": True,
                    "sha256": digest,
                    "size": size,
                }
            )
        actual = {child.name for child in staging.iterdir()}
        expected = set(ARCHIVE_NAMES.values())
        if actual != expected:
            fail("OCI export directory inventory differs after export")
        promote_directory_no_replace(staging, output_directory)
    except Exception:
        if staging.exists():
            remove_private_staging_directory(staging, output_directory)
        raise
    return {
        "format_version": 1,
        "images": records,
        "producer": producer,
    }


def install_crane(
    destination: Path,
    policy: Mapping[str, Any],
    evidence_directory: Path | None,
) -> dict[str, Any]:
    require_linux_amd64()
    if evidence_directory is not None:
        paths = verify_evidence(evidence_directory, policy)
        extract_crane(paths["archive"], destination, policy)
    else:
        with tempfile.TemporaryDirectory(prefix="sub2api-crane-") as temporary:
            directory = Path(temporary)
            download_evidence(directory, policy)
            paths = verify_evidence(directory, policy)
            extract_crane(paths["archive"], destination, policy)
    producer = verify_crane_binary(destination, policy)
    return {
        "format_version": 1,
        "installed": producer,
    }


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Install and use the pinned Linux/amd64 Crane OCI producer."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    install = subparsers.add_parser(
        "install", help="verify upstream evidence and install the pinned crane binary"
    )
    install.add_argument("--destination", type=Path, required=True)
    install.add_argument(
        "--evidence-dir",
        type=Path,
        help="existing directory containing exactly the three pinned upstream assets",
    )

    verify = subparsers.add_parser("verify", help="verify an installed crane binary")
    verify.add_argument("--crane", type=Path, required=True)

    export = subparsers.add_parser(
        "export-images", help="export each digest twice as a Linux/amd64 OCI archive"
    )
    export.add_argument("--crane", type=Path, required=True)
    export.add_argument("--output-dir", type=Path, required=True)
    export.add_argument(
        "--image",
        action="append",
        required=True,
        metavar="COMPONENT=REPOSITORY@sha256:DIGEST",
    )
    export.add_argument("--timeout-seconds", type=int, default=1800)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    try:
        args = build_parser().parse_args(argv)
        policy = load_policy()
        if args.command == "install":
            result = install_crane(args.destination, policy, args.evidence_dir)
        elif args.command == "verify":
            result = {
                "format_version": 1,
                "verified": verify_crane_binary(args.crane, policy),
            }
        elif args.command == "export-images":
            references = parse_image_specs(args.image)
            result = export_images(
                args.crane,
                args.output_dir,
                references,
                policy,
                timeout_seconds=args.timeout_seconds,
            )
        else:  # pragma: no cover - argparse rejects unknown commands.
            fail("unknown command")
        sys.stdout.write(canonical_json(result))
        return 0
    except ToolchainError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
