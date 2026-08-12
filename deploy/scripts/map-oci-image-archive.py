#!/usr/bin/env python3
"""Build a fail-closed identity map for one Docker OCI image archive."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tarfile
from collections.abc import Iterable
from pathlib import Path, PurePosixPath
from typing import Any, BinaryIO, NoReturn

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
DIGEST_RE = re.compile(r"^sha256:([0-9a-f]{64})$")
TAG_RE = re.compile(
    r"^(?:[a-z0-9]+(?:[._-][a-z0-9]+)*(?::[0-9]+)?/)"
    r"*(?:[a-z0-9]+(?:[._-][a-z0-9]+)*):"
    r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$"
)
PLATFORM_PART_RE = re.compile(r"^[a-z0-9_][a-z0-9_.-]*$")
LABEL_KEY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]*$")

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
MAX_ARCHIVE_BYTES = 8 * 1024 * 1024 * 1024
MAX_EXPANDED_BYTES = 16 * 1024 * 1024 * 1024
MAX_MEMBERS = 65536
MAX_JSON_BYTES = 4 * 1024 * 1024
KNOWN_TOP_LEVEL_FILES = {"index.json", "manifest.json", "oci-layout", "repositories"}


class ArchiveIdentityError(RuntimeError):
    pass


def fail(message: str) -> NoReturn:
    raise ArchiveIdentityError(message)


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def sha256_stream(handle: BinaryIO) -> str:
    digest = hashlib.sha256()
    for chunk in iter(lambda: handle.read(1024 * 1024), b""):
        digest.update(chunk)
    return digest.hexdigest()


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


def open_archive(path: Path) -> tuple[BinaryIO, os.stat_result]:
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:
        fail("this platform cannot open the archive without following symlinks")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | nofollow
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        fail(f"cannot securely open archive {path}: {exc}")
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            fail("archive is not a regular file")
        if metadata.st_uid != os.geteuid():
            fail("archive must be owned by the verification user")
        if metadata.st_nlink != 1:
            fail("archive must have exactly one filesystem link")
        if stat.S_IMODE(metadata.st_mode) & 0o022:
            fail("archive must not be writable by group or other")
        if metadata.st_size <= 0 or metadata.st_size > MAX_ARCHIVE_BYTES:
            fail("archive size is outside the accepted range")
        return os.fdopen(descriptor, "rb"), metadata
    except BaseException:
        os.close(descriptor)
        raise


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
        fail(f"cannot decode {label}: {exc}")


def require_object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        fail(f"{label} must be a JSON object")
    return value


def require_exact_or_optional_keys(
    value: dict[str, Any], required: set[str], optional: set[str], label: str
) -> None:
    actual = set(value)
    missing = sorted(required - actual)
    extra = sorted(actual - required - optional)
    if missing or extra:
        fail(f"{label} keys mismatch; missing={missing}, extra={extra}")


def require_sha256_digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or DIGEST_RE.fullmatch(value) is None:
        fail(f"{label} must be a lowercase sha256 digest")
    return value


def require_size(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        fail(f"{label} must be a non-negative integer")
    return value


def require_string_mapping(value: Any, label: str) -> dict[str, str]:
    if not isinstance(value, dict):
        fail(f"{label} must be an object")
    result: dict[str, str] = {}
    for key, item in value.items():
        if not isinstance(key, str) or not key or not isinstance(item, str):
            fail(f"{label} must contain only non-empty string keys and string values")
        result[key] = item
    return result


def normalize_member_name(member: tarfile.TarInfo) -> str:
    name = member.name.rstrip("/")
    if not name or name.startswith("/") or "\\" in name or "\x00" in name:
        fail(f"archive member has an unsafe name: {member.name!r}")
    parts = PurePosixPath(name).parts
    if any(part in {"", ".", ".."} for part in parts):
        fail(f"archive member has an unsafe name: {member.name!r}")
    normalized = str(PurePosixPath(*parts))
    if normalized != name:
        fail(f"archive member name is not canonical: {member.name!r}")
    return normalized


def inventory_archive(archive: tarfile.TarFile) -> dict[str, tarfile.TarInfo]:
    inventory: dict[str, tarfile.TarInfo] = {}
    expanded_bytes = 0
    for member_count, member in enumerate(archive, start=1):
        if member_count > MAX_MEMBERS:
            fail("archive member count exceeds the accepted range")
        name = normalize_member_name(member)
        if name in inventory:
            fail(f"archive repeats member {name}")
        if member.isdir():
            if name not in {"blobs", "blobs/sha256"}:
                fail(f"archive contains unexpected directory {name}")
        elif member.isreg():
            if name not in KNOWN_TOP_LEVEL_FILES and not re.fullmatch(
                r"blobs/sha256/[0-9a-f]{64}", name
            ):
                fail(f"archive contains unexpected file {name}")
            if member.size < 0 or member.size > MAX_ARCHIVE_BYTES:
                fail(f"archive member size is outside the accepted range: {name}")
            expanded_bytes += member.size
            if expanded_bytes > MAX_EXPANDED_BYTES:
                fail("expanded archive size exceeds the accepted range")
        else:
            fail(f"archive member is not a regular file or directory: {name}")
        inventory[name] = member
    if not inventory:
        fail("archive is empty")
    for required in ("index.json", "manifest.json", "oci-layout"):
        member = inventory.get(required)
        if member is None or not member.isreg():
            fail(f"archive is missing regular file {required}")
    return inventory


def read_member(
    archive: tarfile.TarFile, member: tarfile.TarInfo, label: str, maximum: int
) -> bytes:
    if member.size > maximum:
        fail(f"{label} exceeds the accepted size")
    extracted = archive.extractfile(member)
    if extracted is None:
        fail(f"cannot read {label}")
    with extracted:
        raw = extracted.read(maximum + 1)
        if len(raw) != member.size or len(raw) > maximum:
            fail(f"{label} size differs from its tar header")
        if extracted.read(1):
            fail(f"{label} contains data beyond its tar header size")
    return raw


def hash_member(archive: tarfile.TarFile, member: tarfile.TarInfo, label: str) -> str:
    extracted = archive.extractfile(member)
    if extracted is None:
        fail(f"cannot read {label}")
    size = 0
    digest = hashlib.sha256()
    with extracted:
        for chunk in iter(lambda: extracted.read(1024 * 1024), b""):
            size += len(chunk)
            if size > member.size:
                fail(f"{label} contains data beyond its tar header size")
            digest.update(chunk)
    if size != member.size:
        fail(f"{label} size differs from its tar header")
    return digest.hexdigest()


def verify_all_blobs(
    archive: tarfile.TarFile, inventory: dict[str, tarfile.TarInfo]
) -> dict[str, tarfile.TarInfo]:
    blobs: dict[str, tarfile.TarInfo] = {}
    for name, member in sorted(inventory.items()):
        match = re.fullmatch(r"blobs/sha256/([0-9a-f]{64})", name)
        if match is None:
            continue
        expected = match.group(1)
        if hash_member(archive, member, f"blob {expected}") != expected:
            fail(f"blob content does not match its sha256 filename: {expected}")
        blobs[f"sha256:{expected}"] = member
    if not blobs:
        fail("archive has no sha256 blobs")
    return blobs


def descriptor(
    value: Any,
    label: str,
    media_types: set[str],
    *,
    allow_platform: bool = False,
) -> dict[str, Any]:
    result = require_object(value, label)
    optional = {"annotations", "urls"}
    if allow_platform:
        optional.add("platform")
    require_exact_or_optional_keys(
        result, {"mediaType", "digest", "size"}, optional, label
    )
    media_type = result.get("mediaType")
    if media_type not in media_types:
        fail(f"{label} has unsupported media type {media_type!r}")
    require_sha256_digest(result.get("digest"), f"{label}.digest")
    require_size(result.get("size"), f"{label}.size")
    if "annotations" in result:
        require_string_mapping(result["annotations"], f"{label}.annotations")
    urls = result.get("urls")
    if urls is not None and (
        not isinstance(urls, list)
        or any(not isinstance(item, str) or not item for item in urls)
    ):
        fail(f"{label}.urls must be a string array")
    return result


def require_blob(
    blobs: dict[str, tarfile.TarInfo], digest: str, size: int, label: str
) -> tarfile.TarInfo:
    member = blobs.get(digest)
    if member is None:
        fail(f"archive is missing {label} blob {digest}")
    if member.size != size:
        fail(f"{label} descriptor size differs from the blob size")
    return member


def split_platform(value: str) -> tuple[str, str, str | None]:
    parts = value.split("/")
    if len(parts) not in {2, 3} or any(
        PLATFORM_PART_RE.fullmatch(part) is None for part in parts
    ):
        fail("expected platform must be os/architecture or os/architecture/variant")
    return parts[0], parts[1], parts[2] if len(parts) == 3 else None


def platform_from_config(config: dict[str, Any]) -> tuple[str, str, str | None]:
    operating_system = config.get("os")
    architecture = config.get("architecture")
    variant = config.get("variant")
    if (
        not isinstance(operating_system, str)
        or PLATFORM_PART_RE.fullmatch(operating_system) is None
        or not isinstance(architecture, str)
        or PLATFORM_PART_RE.fullmatch(architecture) is None
        or (
            variant is not None
            and (
                not isinstance(variant, str)
                or PLATFORM_PART_RE.fullmatch(variant) is None
            )
        )
    ):
        fail("image config has an invalid platform")
    return operating_system, architecture, variant


def render_platform(value: tuple[str, str, str | None]) -> str:
    operating_system, architecture, variant = value
    return f"{operating_system}/{architecture}" + (f"/{variant}" if variant else "")


def validate_descriptor_platform(
    value: Any, expected: tuple[str, str, str | None], label: str
) -> None:
    if value is None:
        return
    platform = require_object(value, label)
    require_exact_or_optional_keys(
        platform,
        {"os", "architecture"},
        {"variant", "os.version", "os.features", "features"},
        label,
    )
    observed = (
        platform.get("os"),
        platform.get("architecture"),
        platform.get("variant"),
    )
    if observed != expected:
        fail(
            f"{label} differs from the config platform: "
            f"expected {render_platform(expected)!r}, observed {observed!r}"
        )


def tag_component(tag: str) -> str:
    return tag.rsplit(":", 1)[1]


def canonical_docker_tag(tag: str) -> str:
    if "/" not in tag:
        return f"docker.io/library/{tag}"
    first = tag.split("/", 1)[0]
    if "." in first or ":" in first or first == "localhost":
        return tag
    return f"docker.io/{tag}"


def validate_index_tag(descriptor_value: dict[str, Any], expected_tag: str) -> None:
    annotations = require_string_mapping(
        descriptor_value.get("annotations"), "index manifest annotations"
    )
    ref_name = annotations.get("org.opencontainers.image.ref.name")
    if ref_name not in {expected_tag, tag_component(expected_tag)}:
        fail("index manifest ref-name annotation differs from the expected tag")
    containerd_name = annotations.get("io.containerd.image.name")
    if containerd_name is not None and containerd_name != canonical_docker_tag(
        expected_tag
    ):
        fail("index manifest containerd name differs from the expected tag")


def parse_expected_labels(values: Iterable[str]) -> dict[str, str]:
    result: dict[str, str] = {}
    for value in values:
        key, separator, expected = value.partition("=")
        if not separator or LABEL_KEY_RE.fullmatch(key) is None:
            fail(f"expected label must use KEY=VALUE syntax: {value!r}")
        if key in result:
            fail(f"expected label is repeated: {key}")
        result[key] = expected
    if not result:
        fail("at least one expected OCI label is required")
    return result


def validate_labels(
    config: dict[str, Any], expected_labels: dict[str, str]
) -> dict[str, str]:
    runtime_config = require_object(config.get("config"), "image config.config")
    labels_value = runtime_config.get("Labels")
    labels = require_string_mapping(labels_value, "image config labels")
    for key, expected in expected_labels.items():
        if labels.get(key) != expected:
            fail(
                f"OCI label {key} mismatch: expected {expected!r}, "
                f"observed {labels.get(key)!r}"
            )
    return labels


def validate_legacy_manifest(
    raw: bytes,
    *,
    expected_tag: str,
    config_digest: str,
    layer_digests: list[str],
) -> None:
    value = decode_json(raw, "manifest.json")
    if not isinstance(value, list) or len(value) != 1:
        fail("manifest.json must describe exactly one image")
    item = require_object(value[0], "manifest.json image")
    require_exact_or_optional_keys(
        item, {"Config", "RepoTags", "Layers"}, {"LayerSources"}, "manifest.json image"
    )
    expected_config = f"blobs/sha256/{config_digest.removeprefix('sha256:')}"
    if item.get("Config") != expected_config:
        fail("manifest.json config path differs from the OCI manifest config")
    if item.get("RepoTags") != [expected_tag]:
        fail("manifest.json tag differs from the expected tag")
    expected_layers = [
        f"blobs/sha256/{digest.removeprefix('sha256:')}" for digest in layer_digests
    ]
    if item.get("Layers") != expected_layers:
        fail("manifest.json layers differ from the OCI manifest layers")
    if "LayerSources" in item and not isinstance(item["LayerSources"], dict):
        fail("manifest.json LayerSources must be an object")


def parse_inspect(raw: bytes, label: str) -> dict[str, Any]:
    value = decode_json(raw, label)
    if not isinstance(value, list) or len(value) != 1 or not isinstance(value[0], dict):
        fail(f"{label} must contain exactly one image inspect object")
    return value[0]


def read_inspect_file(path: Path) -> bytes:
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:
        fail("this platform cannot read inspect evidence without following symlinks")
    try:
        descriptor_value = os.open(
            path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | nofollow
        )
    except OSError as exc:
        fail(f"cannot open Docker inspect evidence {path}: {exc}")
    try:
        before = os.fstat(descriptor_value)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            fail("Docker inspect evidence must be one regular, singly-linked file")
        if before.st_uid != os.geteuid() or stat.S_IMODE(before.st_mode) & 0o022:
            fail("Docker inspect evidence must be owner-controlled")
        if before.st_size <= 0 or before.st_size > MAX_JSON_BYTES:
            fail("Docker inspect evidence size is outside the accepted range")
        chunks: list[bytes] = []
        remaining = MAX_JSON_BYTES + 1
        while remaining:
            chunk = os.read(descriptor_value, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        after = os.fstat(descriptor_value)
        if len(raw) != before.st_size or len(raw) > MAX_JSON_BYTES:
            fail("Docker inspect evidence size changed while reading")
        if stable_fields(before) != stable_fields(after):
            fail("Docker inspect evidence changed while reading")
        return raw
    finally:
        os.close(descriptor_value)


def inspect_from_docker(binary: str, image: str) -> bytes:
    try:
        result = subprocess.run(
            [binary, "image", "inspect", image],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            check=False,
            timeout=60,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        fail(f"Docker image inspection failed: {exc}")
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", errors="replace").strip()
        fail(f"Docker image inspection failed with exit {result.returncode}: {detail}")
    if not result.stdout or len(result.stdout) > MAX_JSON_BYTES:
        fail("Docker image inspection output size is outside the accepted range")
    return result.stdout


def validate_daemon_inspect(
    inspection: dict[str, Any],
    *,
    expected_tag: str,
    platform: tuple[str, str, str | None],
    labels: dict[str, str],
    manifest_digest: str,
    config_digest: str,
) -> dict[str, Any]:
    image_id = require_sha256_digest(inspection.get("Id"), "Docker image ID")
    if image_id == config_digest:
        identity_kind = "config-digest"
    elif image_id == manifest_digest:
        identity_kind = "manifest-digest"
    else:
        fail("Docker image ID matches neither the OCI manifest nor config digest")
    observed_platform = (
        inspection.get("Os"),
        inspection.get("Architecture"),
        inspection.get("Variant"),
    )
    if observed_platform != platform:
        fail("Docker image inspect platform differs from the archive config")
    docker_config = require_object(inspection.get("Config"), "Docker inspect Config")
    inspect_labels = require_string_mapping(
        docker_config.get("Labels"), "Docker inspect labels"
    )
    if inspect_labels != labels:
        fail("Docker image inspect labels differ from the archive config")
    repo_tags = inspection.get("RepoTags")
    if (
        not isinstance(repo_tags, list)
        or expected_tag not in repo_tags
        or any(
            not isinstance(item, str) or TAG_RE.fullmatch(item) is None
            for item in repo_tags
        )
        or len(repo_tags) != len(set(repo_tags))
    ):
        fail("Docker image inspect does not expose the expected unique tag")
    return {
        "id": image_id,
        "id_kind": identity_kind,
        "repo_tags": sorted(repo_tags),
    }


def build_identity_map(args: argparse.Namespace) -> dict[str, Any]:
    expected_archive_sha256 = args.expected_archive_sha256.removeprefix("sha256:")
    if SHA256_RE.fullmatch(expected_archive_sha256) is None:
        fail("expected archive SHA-256 must be 64 lowercase hexadecimal characters")
    if TAG_RE.fullmatch(args.expected_tag) is None:
        fail("expected tag is not a concrete Docker repository:tag reference")
    expected_platform = split_platform(args.expected_platform)
    expected_labels = parse_expected_labels(args.expected_label)
    for label, value in (
        ("expected manifest digest", args.expected_manifest_digest),
        ("expected config digest", args.expected_config_digest),
    ):
        if value is not None:
            require_sha256_digest(value, label)

    handle, archive_metadata = open_archive(args.archive)
    try:
        archive_sha256 = sha256_stream(handle)
        if archive_sha256 != expected_archive_sha256:
            fail("archive SHA-256 differs from the expected transport checksum")
        handle.seek(0)
        try:
            archive = tarfile.open(fileobj=handle, mode="r:*")  # noqa: SIM115
        except (tarfile.TarError, OSError) as exc:
            fail(f"cannot parse OCI image archive: {exc}")
        with archive:
            inventory = inventory_archive(archive)
            blobs = verify_all_blobs(archive, inventory)

            layout = require_object(
                decode_json(
                    read_member(
                        archive, inventory["oci-layout"], "oci-layout", MAX_JSON_BYTES
                    ),
                    "oci-layout",
                ),
                "oci-layout",
            )
            if layout != {"imageLayoutVersion": "1.0.0"}:
                fail("oci-layout is not the supported OCI image-layout version")

            index_raw = read_member(
                archive, inventory["index.json"], "index.json", MAX_JSON_BYTES
            )
            index = require_object(decode_json(index_raw, "index.json"), "index.json")
            require_exact_or_optional_keys(
                index,
                {"schemaVersion", "mediaType", "manifests"},
                {"annotations"},
                "index.json",
            )
            if (
                index.get("schemaVersion") != 2
                or index.get("mediaType") != OCI_INDEX_MEDIA_TYPE
            ):
                fail("index.json is not an OCI image index v1")
            manifests = index.get("manifests")
            if not isinstance(manifests, list) or len(manifests) != 1:
                fail("index.json must select exactly one image manifest")
            manifest_descriptor = descriptor(
                manifests[0],
                "index manifest descriptor",
                MANIFEST_MEDIA_TYPES,
                allow_platform=True,
            )
            validate_index_tag(manifest_descriptor, args.expected_tag)
            manifest_digest = manifest_descriptor["digest"]
            if (
                args.expected_manifest_digest is not None
                and manifest_digest != args.expected_manifest_digest
            ):
                fail("index manifest digest differs from the expected digest")
            manifest_member = require_blob(
                blobs,
                manifest_digest,
                manifest_descriptor["size"],
                "image manifest",
            )
            manifest_raw = read_member(
                archive, manifest_member, "image manifest", MAX_JSON_BYTES
            )
            manifest = require_object(
                decode_json(manifest_raw, "image manifest"), "image manifest"
            )
            require_exact_or_optional_keys(
                manifest,
                {"schemaVersion", "mediaType", "config", "layers"},
                {"annotations"},
                "image manifest",
            )
            if (
                manifest.get("schemaVersion") != 2
                or manifest.get("mediaType") != manifest_descriptor["mediaType"]
            ):
                fail("image manifest media identity differs from its index descriptor")

            config_descriptor = descriptor(
                manifest.get("config"), "manifest config descriptor", CONFIG_MEDIA_TYPES
            )
            config_digest = config_descriptor["digest"]
            if (
                args.expected_config_digest is not None
                and config_digest != args.expected_config_digest
            ):
                fail("manifest config digest differs from the expected digest")
            config_member = require_blob(
                blobs, config_digest, config_descriptor["size"], "image config"
            )
            config = require_object(
                decode_json(
                    read_member(archive, config_member, "image config", MAX_JSON_BYTES),
                    "image config",
                ),
                "image config",
            )

            layers = manifest.get("layers")
            if not isinstance(layers, list) or not layers:
                fail("image manifest must contain at least one layer")
            layer_digests: list[str] = []
            for index_value, layer_value in enumerate(layers):
                layer = descriptor(
                    layer_value, f"layer descriptor {index_value}", LAYER_MEDIA_TYPES
                )
                require_blob(
                    blobs,
                    layer["digest"],
                    layer["size"],
                    f"image layer {index_value}",
                )
                layer_digests.append(layer["digest"])

            platform = platform_from_config(config)
            if platform != expected_platform:
                fail(
                    "image config platform mismatch: "
                    f"expected {render_platform(expected_platform)!r}, "
                    f"observed {render_platform(platform)!r}"
                )
            validate_descriptor_platform(
                manifest_descriptor.get("platform"), platform, "index manifest platform"
            )
            labels = validate_labels(config, expected_labels)
            validate_legacy_manifest(
                read_member(
                    archive, inventory["manifest.json"], "manifest.json", MAX_JSON_BYTES
                ),
                expected_tag=args.expected_tag,
                config_digest=config_digest,
                layer_digests=layer_digests,
            )
            if "repositories" in inventory:
                require_object(
                    decode_json(
                        read_member(
                            archive,
                            inventory["repositories"],
                            "repositories",
                            MAX_JSON_BYTES,
                        ),
                        "repositories",
                    ),
                    "repositories",
                )

        handle.seek(0)
        if sha256_stream(handle) != archive_sha256:
            fail("archive content changed while it was being verified")
        if stable_fields(os.fstat(handle.fileno())) != stable_fields(archive_metadata):
            fail("archive metadata changed while it was being verified")
    finally:
        handle.close()

    daemon: dict[str, Any] | None = None
    if args.inspect_json is not None:
        inspection = parse_inspect(
            read_inspect_file(args.inspect_json), "Docker inspect evidence"
        )
    elif args.docker_image is not None:
        inspection = parse_inspect(
            inspect_from_docker(args.docker, args.docker_image), "Docker inspect output"
        )
    else:
        inspection = None
    if inspection is not None:
        daemon = validate_daemon_inspect(
            inspection,
            expected_tag=args.expected_tag,
            platform=platform,
            labels=labels,
            manifest_digest=manifest_digest,
            config_digest=config_digest,
        )

    return {
        "archive": {"sha256": archive_sha256, "size": archive_metadata.st_size},
        "daemon": daemon,
        "format_version": 1,
        "image": {
            "config_digest": config_digest,
            "index_sha256": f"sha256:{hashlib.sha256(index_raw).hexdigest()}",
            "labels": labels,
            "layer_digests": layer_digests,
            "manifest_digest": manifest_digest,
            "platform": render_platform(platform),
            "tag": args.expected_tag,
            "verified_blob_count": len(blobs),
        },
        "status": "verified",
    }


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Cryptographically map one Docker OCI image archive to its manifest, "
            "config, and optional daemon-visible image ID."
        )
    )
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--expected-archive-sha256", required=True)
    parser.add_argument("--expected-tag", required=True)
    parser.add_argument("--expected-platform", required=True)
    parser.add_argument("--expected-label", action="append", required=True)
    parser.add_argument("--expected-manifest-digest")
    parser.add_argument("--expected-config-digest")
    inspection = parser.add_mutually_exclusive_group()
    inspection.add_argument("--inspect-json", type=Path)
    inspection.add_argument("--docker-image")
    parser.add_argument("--docker", default="docker")
    return parser.parse_args(argv)


def main() -> int:
    try:
        result = build_identity_map(parse_args())
    except (ArchiveIdentityError, KeyError, OSError, tarfile.TarError) as exc:
        print(f"map-oci-image-archive: {exc}", file=sys.stderr)
        return 1
    sys.stdout.write(canonical_json(result) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
