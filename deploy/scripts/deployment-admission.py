#!/usr/bin/env python3
"""Pure validation helpers for the production deployment admission wrapper."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, NoReturn

DIGEST_REF_RE = re.compile(r"^[^\s@]+@sha256:[0-9a-f]{64}$")
IMAGE_ID_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
CONTAINER_ID_RE = re.compile(r"^[0-9a-f]{64}$")
VCS_REF_RE = re.compile(r"^[0-9a-f]{40}$")
REVISION_RE = re.compile(r"^[0-9A-Za-z][0-9A-Za-z_]{0,127}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
MAX_PRIVATE_INPUT_BYTES = 1_048_576
MAX_BACKUP_METADATA_BYTES = 16 * 1_048_576
MAX_JSON_INPUT_BYTES = 32 * 1_048_576
MAX_PACKAGE_EVIDENCE_BYTES = 16 * 1024 * 1_048_576
SERVER_PACKAGE_MANIFEST_SCHEMA = (
    "https://sub2api-codex.invalid/schemas/server-package-inventory-v1.json"
)
SERVER_PACKAGE_RECEIPT_SCHEMA = (
    "https://sub2api-codex.invalid/schemas/server-package-verification-v1.json"
)
CONNECTOR_METADATA_FILENAME = "connector-release-metadata.json"
CONNECTOR_METADATA_BUNDLE_FILENAME = f"{CONNECTOR_METADATA_FILENAME}.sigstore.json"
CONNECTOR_AGGREGATE_FILENAME = "connector-public-verification-aggregate.json"
CONNECTOR_AGGREGATE_BUNDLE_FILENAME = f"{CONNECTOR_AGGREGATE_FILENAME}.sigstore.json"
OCI_EXPORT_RECEIPT_FILENAME = "oci-export-receipt.json"
LOCAL_DOCKER_HOST = "unix:///var/run/docker.sock"
WRITER_SERVICES = ("control-api-replica", "control-api")
WRITER_UNFREEZE_PLAN_TYPE = "production-writer-unfreeze-plan-v1"
WRITER_FREEZE_TYPE = "production-writer-freeze-v1"
POST_UNFREEZE_VERIFY_TIMEOUT_SECONDS = 120
POST_REVERSE_VERIFY_TIMEOUT_SECONDS = 120
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


def fail(message: str) -> NoReturn:
    raise ValueError(message)


def load_json(path: Path, label: str) -> Any:
    descriptor = -1
    try:
        descriptor, metadata = open_stable_regular_file(
            path, label, max_size=MAX_JSON_INPUT_BYTES
        )
        content = read_descriptor(descriptor, label, MAX_JSON_INPUT_BYTES)
        assert_stable(descriptor, metadata, label)
        return json.loads(content.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        fail(f"cannot read {label} {path}: {exc}")
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def write_json(value: Any) -> None:
    json.dump(value, sys.stdout, sort_keys=True, separators=(",", ":"))
    sys.stdout.write("\n")


def strict_json_bytes(
    content: bytes, label: str, *, canonical: bool = False
) -> Any:
    def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                fail(f"{label} repeats JSON key {key}")
            value[key] = item
        return value

    try:
        value = json.loads(
            content.decode("utf-8"),
            object_pairs_hook=reject_duplicate_keys,
            parse_constant=lambda token: fail(f"{label} contains {token}"),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        fail(f"cannot parse {label}: {exc}")
    if canonical:
        expected = (
            json.dumps(
                value,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
                allow_nan=False,
            ).encode("ascii")
            + b"\n"
        )
        if content != expected:
            fail(f"{label} is not canonical JSON")
    return value


def secure_exact_bytes(
    path: Path,
    label: str,
    *,
    expected_uid: int,
    exact_mode: int,
    maximum: int = MAX_JSON_INPUT_BYTES,
) -> bytes:
    descriptor = -1
    try:
        descriptor, metadata = open_stable_regular_file(
            path,
            label,
            expected_uid=expected_uid,
            exact_mode=exact_mode,
            max_size=maximum,
        )
        if metadata.st_nlink != 1:
            fail(f"{label} must have exactly one hard link")
        content = read_descriptor(descriptor, label, maximum)
        assert_stable(descriptor, metadata, label)
        return content
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def exact_keys(value: Any, expected: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        fail(f"{label} has an unexpected schema")
    return value


def package_file_record(
    package_root: Path,
    files: dict[str, dict[str, Any]],
    path: str,
    label: str,
    *,
    expected_uid: int,
    include_content: bool = True,
) -> tuple[dict[str, Any], bytes]:
    record = files.get(path)
    if not isinstance(record, dict) or set(record) != {"mode", "path", "sha256", "size"}:
        fail(f"server package inventory omits {label}")
    if (
        record.get("path") != path
        or record.get("mode") != "0444"
        or not isinstance(record.get("sha256"), str)
        or SHA256_RE.fullmatch(record["sha256"]) is None
        or type(record.get("size")) is not int
        or not 0
        < record["size"]
        <= (MAX_JSON_INPUT_BYTES if include_content else MAX_PACKAGE_EVIDENCE_BYTES)
    ):
        fail(f"server package inventory record is invalid for {label}")
    descriptor, metadata = open_stable_regular_file(
        package_root / path,
        label,
        expected_uid=expected_uid,
        exact_mode=0o444,
        max_size=record["size"],
    )
    try:
        if metadata.st_nlink != 1 or metadata.st_size != record["size"]:
            fail(f"server package file metadata differs from the inventory for {label}")
        if include_content:
            content = read_descriptor(descriptor, label, record["size"])
            digest = hashlib.sha256(content).hexdigest()
        else:
            content = b""
            digest = hash_descriptor(descriptor)
        assert_stable(descriptor, metadata, label)
    finally:
        os.close(descriptor)
    if digest != record["sha256"]:
        fail(f"server package bytes differ from the inventory for {label}")
    return record, content


def connector_release_metadata(value: Any) -> dict[str, Any]:
    metadata = exact_keys(
        value,
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
    version = metadata.get("version")
    assets = metadata.get("assets")
    if (
        metadata.get("format_version") != 1
        or metadata.get("release_mode") != "release"
        or metadata.get("releasable") is not True
        or not isinstance(metadata.get("source_repository"), str)
        or re.fullmatch(r"https://github\.com/[^/\s]+/[^/\s]+", metadata["source_repository"])
        is None
        or not isinstance(metadata.get("source_commit"), str)
        or VCS_REF_RE.fullmatch(metadata["source_commit"]) is None
        or not isinstance(version, str)
        or re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version) is None
        or metadata.get("tag") != f"connector-v{version}"
        or not isinstance(metadata.get("codex_version"), str)
        or re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", metadata["codex_version"])
        is None
        or not isinstance(metadata.get("schema_digest"), str)
        or SHA256_RE.fullmatch(metadata["schema_digest"]) is None
        or metadata.get("config_path_hint")
        != "~/.config/sub2api-codex-connector/connector.json"
        or metadata.get("pair_command") != "sub2api-codex-connector-ctl pair"
        or metadata.get("start_command") != "sub2api-codex-connector-ctl start"
        or not isinstance(assets, list)
        or len(assets) != 6
    ):
        fail("Connector release metadata is not one complete public release")
    expected_matrix = {
        ("darwin", "amd64", "pkg"),
        ("darwin", "arm64", "pkg"),
        ("linux", "amd64", "deb"),
        ("linux", "amd64", "rpm"),
        ("linux", "arm64", "deb"),
        ("linux", "arm64", "rpm"),
    }
    observed_matrix: set[tuple[str, str, str]] = set()
    for asset in assets:
        if not isinstance(asset, dict):
            fail("Connector release metadata contains an invalid asset")
        identity = (asset.get("os"), asset.get("arch"), asset.get("package_format"))
        if not all(isinstance(item, str) for item in identity):
            fail("Connector release metadata contains an invalid asset identity")
        observed_matrix.add(identity)  # type: ignore[arg-type]
        if (
            not isinstance(asset.get("sha256"), str)
            or SHA256_RE.fullmatch(asset["sha256"]) is None
            or type(asset.get("size")) is not int
            or asset["size"] <= 0
        ):
            fail("Connector release metadata contains invalid asset evidence")
    if observed_matrix != expected_matrix:
        fail("Connector release metadata native package matrix is incomplete")
    return metadata


def server_package_release(args: argparse.Namespace) -> dict[str, Any]:
    manifest_path = args.manifest
    receipt_path = args.verification_receipt
    if not manifest_path.is_absolute() or not receipt_path.is_absolute():
        fail("server package evidence paths must be absolute")
    if os.environ.get("DOCKER_HOST") != LOCAL_DOCKER_HOST:
        fail("server package admission requires the lifecycle-pinned local Docker socket")
    if manifest_path.name != "PACKAGE.json":
        fail("server package manifest must be named PACKAGE.json")
    package_root = manifest_path.parent
    root_metadata = package_root.lstat()
    if (
        stat.S_ISLNK(root_metadata.st_mode)
        or not stat.S_ISDIR(root_metadata.st_mode)
        or root_metadata.st_uid != args.expected_owner_uid
        or stat.S_IMODE(root_metadata.st_mode) != 0o555
    ):
        fail("installed server package root is not immutable and root-owned")
    manifest_raw = secure_exact_bytes(
        manifest_path,
        "server package manifest",
        expected_uid=args.expected_owner_uid,
        exact_mode=0o444,
    )
    manifest_sha256 = hashlib.sha256(manifest_raw).hexdigest()
    if (
        not isinstance(args.expected_manifest_sha256, str)
        or SHA256_RE.fullmatch(args.expected_manifest_sha256) is None
        or manifest_sha256 != args.expected_manifest_sha256
    ):
        fail("server package manifest differs from the lifecycle-owned hash")
    manifest = strict_json_bytes(manifest_raw, "server package manifest", canonical=True)
    required_manifest_keys = {
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
        "connector_release",
        "oci_export",
        "source_bundle",
        "source_verification",
        "image_trust",
        "images",
        "lifecycle",
        "required_source_paths",
        "files",
    }
    manifest = exact_keys(manifest, required_manifest_keys, "server package manifest")
    if (
        manifest.get("$schema") != SERVER_PACKAGE_MANIFEST_SCHEMA
        or manifest.get("format_version") != 1
        or manifest.get("product") != "sub2api-codex-control-server"
        or manifest.get("mode") != args.mode
        or manifest.get("platform") != "linux/amd64"
    ):
        fail("server package identity differs from the lifecycle mode")

    receipt_raw = secure_exact_bytes(
        receipt_path,
        "lifecycle package verification receipt",
        expected_uid=args.expected_owner_uid,
        exact_mode=0o400,
    )
    receipt = strict_json_bytes(
        receipt_raw, "lifecycle package verification receipt", canonical=True
    )
    receipt = exact_keys(
        receipt,
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
        "lifecycle package verification receipt",
    )
    receipt_package = exact_keys(
        receipt.get("package"),
        {"filename", "sha256", "size", "internal_manifest_sha256", "extracted_root"},
        "lifecycle package receipt package binding",
    )
    if (
        receipt.get("$schema") != SERVER_PACKAGE_RECEIPT_SCHEMA
        or receipt.get("format_version") != 1
        or receipt.get("status") != "verified"
        or receipt.get("mode") != args.mode
        or receipt.get("release") != manifest.get("release")
        or receipt.get("release_tag") != manifest.get("release_tag")
        or receipt.get("source") != manifest.get("source")
        or receipt_package.get("extracted_root") != str(package_root)
        or receipt_package.get("internal_manifest_sha256") != manifest_sha256
    ):
        fail("lifecycle verification receipt does not bind this installed package")

    records_value = manifest.get("files")
    if not isinstance(records_value, list) or not records_value:
        fail("server package has no exact file inventory")
    files: dict[str, dict[str, Any]] = {}
    for record in records_value:
        if not isinstance(record, dict) or not isinstance(record.get("path"), str):
            fail("server package file inventory is invalid")
        path = record["path"]
        if (
            path in files
            or Path(path).is_absolute()
            or not Path(path).parts
            or any(part in {"", ".", ".."} for part in Path(path).parts)
        ):
            fail("server package file inventory contains an unsafe or repeated path")
        files[path] = record

    oci_export_value = manifest.get("oci_export")
    oci_export_evidence: dict[str, Any] | None = None
    if args.mode == "online":
        if oci_export_value is not None or OCI_EXPORT_RECEIPT_FILENAME in files:
            fail("online server package must not contain an OCI export receipt")
    else:
        oci_export = exact_keys(
            oci_export_value,
            {"filename", "sha256", "size"},
            "offline server package OCI export binding",
        )
        record, _ = package_file_record(
            package_root,
            files,
            OCI_EXPORT_RECEIPT_FILENAME,
            "offline server package OCI export receipt",
            expected_uid=args.expected_owner_uid,
            include_content=False,
        )
        expected_oci_export = {
            "filename": OCI_EXPORT_RECEIPT_FILENAME,
            "sha256": record["sha256"],
            "size": record["size"],
        }
        if oci_export != expected_oci_export:
            fail("offline server package OCI export binding differs from package bytes")
        oci_export_evidence = expected_oci_export

    connector = exact_keys(
        manifest.get("connector_release"),
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
        "server package Connector release binding",
    )
    connector_names = {
        "metadata": CONNECTOR_METADATA_FILENAME,
        "metadata_bundle": CONNECTOR_METADATA_BUNDLE_FILENAME,
        "aggregate": CONNECTOR_AGGREGATE_FILENAME,
        "aggregate_bundle": CONNECTOR_AGGREGATE_BUNDLE_FILENAME,
    }
    connector_raw: dict[str, bytes] = {}
    connector_records: dict[str, dict[str, Any]] = {}
    for role, filename in connector_names.items():
        package_record, raw = package_file_record(
            package_root,
            files,
            filename,
            f"packaged Connector {role}",
            expected_uid=args.expected_owner_uid,
        )
        bound = connector.get(role)
        expected_bound = {
            "filename": filename,
            "sha256": package_record["sha256"],
            "size": package_record["size"],
        }
        if bound != expected_bound:
            fail(f"Connector {role} binding differs from the package inventory")
        connector_raw[role] = raw
        connector_records[role] = expected_bound

    metadata = connector_release_metadata(
        strict_json_bytes(
            connector_raw["metadata"], "packaged Connector release metadata", canonical=True
        )
    )
    metadata_environment = os.environ.get("CONTROL_CONNECTOR_RELEASE_METADATA_JSON")
    if metadata_environment is None or "\n" in metadata_environment or "\r" in metadata_environment:
        fail("lifecycle-owned Connector release metadata environment is unset or multiline")
    canonical_environment = json.dumps(
        metadata,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    )
    if metadata_environment != canonical_environment:
        fail("Connector release metadata environment differs from packaged canonical bytes")
    identity_fields = (
        "source_repository",
        "source_commit",
        "version",
        "tag",
    )
    if any(connector.get(key) != metadata.get(key) for key in identity_fields):
        fail("Connector release identity differs between metadata and package manifest")
    for key in ("release_id", "workflow_run_id", "workflow_run_attempt"):
        if type(connector.get(key)) is not int or connector[key] <= 0:
            fail("Connector public release identity is invalid")

    aggregate = strict_json_bytes(
        connector_raw["aggregate"], "packaged Connector verification aggregate", canonical=True
    )
    if not isinstance(aggregate, dict):
        fail("Connector verification aggregate is not an object")
    aggregate_release = aggregate.get("release")
    aggregate_run = aggregate.get("verification_run")
    aggregate_public = aggregate.get("public_release")
    if (
        not isinstance(aggregate_release, dict)
        or not isinstance(aggregate_run, dict)
        or not isinstance(aggregate_public, dict)
        or any(aggregate_release.get(key) != connector.get(key) for key in identity_fields)
        or aggregate_run.get("run_id") != connector.get("workflow_run_id")
        or aggregate_run.get("run_attempt") != connector.get("workflow_run_attempt")
        or aggregate_public.get("release_id") != connector.get("release_id")
    ):
        fail("Connector verification aggregate differs from the packaged release identity")

    control = exact_keys(
        manifest.get("control_release"),
        {"evidence", "lock_sha256", "bundle_sha256"},
        "embedded Control release binding",
    )
    evidence_value = control.get("evidence")
    if not isinstance(evidence_value, dict) or not evidence_value:
        fail("embedded Control release evidence inventory is empty")
    evidence_sha256s: dict[str, str] = {}
    for name, bound in evidence_value.items():
        if not isinstance(name, str) or not isinstance(bound, dict):
            fail("embedded Control release evidence inventory is invalid")
        path = f"release/{name}"
        record, _ = package_file_record(
            package_root,
            files,
            path,
            f"embedded Control release evidence {name}",
            expected_uid=args.expected_owner_uid,
            include_content=False,
        )
        if bound != {"filename": path, "sha256": record["sha256"], "size": record["size"]}:
            fail("embedded Control evidence binding differs from package bytes")
        evidence_sha256s[name] = record["sha256"]
    lock_name = "control-images.lock.json"
    bundle_name = "control-images.lock.sigstore.json"
    if (
        control.get("lock_sha256") != evidence_sha256s.get(lock_name)
        or control.get("bundle_sha256") != evidence_sha256s.get(bundle_name)
    ):
        fail("embedded Control lock hashes are inconsistent")
    _, lock_raw = package_file_record(
        package_root,
        files,
        f"release/{lock_name}",
        "embedded Control image lock",
        expected_uid=args.expected_owner_uid,
    )
    lock = strict_json_bytes(lock_raw, "embedded Control image lock", canonical=True)
    lock = exact_keys(
        lock,
        {
            "$schema",
            "format_version",
            "release",
            "release_tag",
            "release_inputs",
            "source",
            "source_bundle",
            "builder",
            "images",
        },
        "embedded Control image lock",
    )
    if (
        lock.get("format_version") != 1
        or lock.get("release") != manifest.get("release")
        or lock.get("release_tag") != manifest.get("release_tag")
        or lock.get("source") != manifest.get("source")
        or lock.get("source_bundle") != manifest.get("source_bundle")
    ):
        fail("embedded Control image lock differs from the package identity")
    source = exact_keys(
        lock.get("source"), {"repository", "commit", "ref"}, "Control release source"
    )
    if (
        source.get("repository") != args.expected_source_repository
        or source.get("commit") != args.expected_source_commit
        or lock.get("release_tag") != args.expected_release_tag
    ):
        fail("server package differs from lifecycle-owned Control release identity")
    release_inputs = exact_keys(
        lock.get("release_inputs"), {"migration_head", "files"}, "Control release inputs"
    )
    input_hashes = release_inputs.get("files")
    if not isinstance(input_hashes, dict) or any(
        not isinstance(path, str)
        or not isinstance(digest, str)
        or SHA256_RE.fullmatch(digest) is None
        for path, digest in input_hashes.items()
    ):
        fail("Control release input inventory is invalid")
    versions_digest = input_hashes.get("versions.lock.json")
    if not isinstance(versions_digest, str):
        fail("Control release does not bind versions.lock.json")
    versions_record, versions_raw = package_file_record(
        package_root,
        files,
        "source/versions.lock.json",
        "packaged versions lock",
        expected_uid=args.expected_owner_uid,
    )
    if versions_record["sha256"] != versions_digest:
        fail("packaged versions lock differs from the Control release input")
    versions = strict_json_bytes(versions_raw, "packaged versions lock")
    codex = versions.get("codex") if isinstance(versions, dict) else None
    if (
        not isinstance(codex, dict)
        or codex.get("cli_version") != metadata.get("codex_version")
        or codex.get("schema_sha256") != metadata.get("schema_digest")
    ):
        fail("Connector metadata Codex contract differs from packaged versions.lock.json")
    auth_paths = sorted(
        path
        for path in input_hashes
        if path.startswith("docs/contracts/sub2api-auth.") and path.endswith(".json")
    )
    if len(auth_paths) != 1:
        fail("Control release input has no unique Sub2API auth contract")
    auth_contract = auth_paths[0]
    auth_record, _ = package_file_record(
        package_root,
        files,
        f"source/{auth_contract}",
        "packaged Sub2API auth contract",
        expected_uid=args.expected_owner_uid,
    )
    if auth_record["sha256"] != input_hashes[auth_contract]:
        fail("packaged Sub2API auth contract differs from the Control release input")

    source_bundle = exact_keys(
        lock.get("source_bundle"),
        {"archive", "manifest", "attestation"},
        "Control source bundle",
    )
    for role, bound in source_bundle.items():
        if not isinstance(bound, dict) or set(bound) != {"filename", "sha256", "size"}:
            fail("Control source bundle record is invalid")
        record, _ = package_file_record(
            package_root,
            files,
            f"release/{bound['filename']}",
            f"Control source bundle {role}",
            expected_uid=args.expected_owner_uid,
            include_content=False,
        )
        if record["sha256"] != bound["sha256"] or record["size"] != bound["size"]:
            fail("Control source bundle differs from the package inventory")

    images = exact_keys(
        lock.get("images"), {"control-api", "pwa", "postgres-tools"}, "Control images"
    )
    package_images = exact_keys(
        manifest.get("images"),
        {"control-api", "pwa", "postgres-tools"},
        "server package images",
    )
    references: dict[str, str] = {}
    package_image_evidence: dict[str, Any] = {}
    for component, image in images.items():
        if not isinstance(image, dict):
            fail("Control image lock contains an invalid image")
        reference = image.get("reference")
        if not isinstance(reference, str) or DIGEST_REF_RE.fullmatch(reference) is None:
            fail("Control image lock contains a mutable image reference")
        package_image = package_images.get(component)
        selected = (
            package_image.get("locked_reference")
            if isinstance(package_image, dict) and args.mode == "offline"
            else package_image.get("reference") if isinstance(package_image, dict) else None
        )
        if selected != reference:
            fail("server package image differs from the signed Control image lock")
        digest = image.get("digest")
        if not isinstance(digest, str) or reference.rsplit("@", 1)[-1] != digest:
            fail("Control image lock digest and reference are inconsistent")
        if args.mode == "offline":
            package_image = exact_keys(
                package_image,
                {
                    "acquisition",
                    "archive",
                    "identity",
                    "locked_digest",
                    "locked_reference",
                },
                f"offline server package image {component}",
            )
            if (
                package_image.get("acquisition") != "offline-oci"
                or package_image.get("locked_digest") != digest
            ):
                fail("offline server package image identity differs from the lock")
            bound_records: dict[str, Any] = {}
            for role, expected_name in (
                ("archive", f"images/{component}.oci.tar"),
                ("identity", f"images/{component}.identity.json"),
            ):
                bound = package_image.get(role)
                if not isinstance(bound, dict) or set(bound) != {"filename", "sha256", "size"}:
                    fail("offline server package image record is invalid")
                record, _ = package_file_record(
                    package_root,
                    files,
                    expected_name,
                    f"offline {component} {role}",
                    expected_uid=args.expected_owner_uid,
                    include_content=role == "identity",
                )
                expected_bound = {
                    "filename": expected_name,
                    "sha256": record["sha256"],
                    "size": record["size"],
                }
                if bound != expected_bound:
                    fail("offline image record differs from exact package bytes")
                bound_records[role] = expected_bound
            package_image_evidence[component] = {
                "locked_reference": reference,
                "locked_digest": digest,
                **bound_records,
            }
        else:
            package_image = exact_keys(
                package_image,
                {"acquisition", "digest", "reference", "repository"},
                f"online server package image {component}",
            )
            if (
                package_image.get("acquisition") != "registry"
                or package_image.get("digest") != digest
            ):
                fail("online server package image identity differs from the lock")
            package_image_evidence[component] = {
                "reference": reference,
                "digest": digest,
            }
        references[component] = reference

    return {
        "CONTROL_API_IMAGE": references["control-api"],
        "CONTROL_MIGRATION_HEAD": release_inputs["migration_head"],
        "CONTROL_POSTGRES_TOOLS_IMAGE": references["postgres-tools"],
        "CONTROL_PWA_IMAGE": references["pwa"],
        "CONTROL_RELEASE": lock["release"],
        "CONTROL_RELEASE_BUNDLE_SHA256": control["bundle_sha256"],
        "CONTROL_RELEASE_EVIDENCE_SHA256S": evidence_sha256s,
        "CONTROL_RELEASE_INPUT_SHA256S": input_hashes,
        "CONTROL_RELEASE_LOCK_SHA256": control["lock_sha256"],
        "CONTROL_SOURCE_REPOSITORY": source["repository"],
        "CONTROL_SOURCE_ARCHIVE_SHA256": source_bundle["archive"]["sha256"],
        "CONTROL_SOURCE_ATTESTATION_SHA256": source_bundle["attestation"]["sha256"],
        "CONTROL_SOURCE_MANIFEST_SHA256": source_bundle["manifest"]["sha256"],
        "CONTROL_SUB2API_AUTH_CONTRACT_PATH": auth_contract,
        "CONTROL_SUB2API_AUTH_CONTRACT_SHA256": input_hashes[auth_contract],
        "CONTROL_VCS_REF": source["commit"],
        "CONTROL_VERSIONS_LOCK_SHA256": versions_digest,
        "CONTROL_CONNECTOR_RELEASE_METADATA_SHA256": connector_records["metadata"]["sha256"],
        "CONTROL_CONNECTOR_RELEASE_METADATA_JSON_SHA256": hashlib.sha256(
            canonical_environment.encode("ascii")
        ).hexdigest(),
        "CONTROL_SERVER_PACKAGE_MANIFEST_SHA256": manifest_sha256,
        "CONTROL_SERVER_PACKAGE_VERIFICATION_RECEIPT_SHA256": hashlib.sha256(
            receipt_raw
        ).hexdigest(),
        "CONTROL_SERVER_PACKAGE_MODE": args.mode,
        "CONTROL_SERVER_PACKAGE_DOCKER_HOST": LOCAL_DOCKER_HOST,
        "_server_package": {
            "manifest_path": str(manifest_path),
            "manifest_sha256": manifest_sha256,
            "verification_receipt_path": str(receipt_path),
            "verification_receipt_sha256": hashlib.sha256(receipt_raw).hexdigest(),
            "archive_sha256": receipt_package["sha256"],
            "mode": args.mode,
            "docker_host": LOCAL_DOCKER_HOST,
            "oci_export": oci_export_evidence,
            "images": package_image_evidence,
            "connector_release": {
                **{key: connector[key] for key in (*identity_fields, "release_id", "workflow_run_id", "workflow_run_attempt")},
                **connector_records,
            },
        },
    }


def service(config: dict[str, Any], name: str) -> dict[str, Any]:
    services = config.get("services")
    if not isinstance(services, dict) or not isinstance(services.get(name), dict):
        fail(f"resolved Compose config has no {name} service")
    return services[name]


def require_hardened_service(value: dict[str, Any], name: str) -> None:
    if value.get("build") is not None:
        fail(f"production service {name} retains a build definition")
    if value.get("pull_policy") != "never":
        fail(f"production service {name} must use pull_policy never")
    if value.get("read_only") is not True:
        fail(f"production service {name} is not read-only")
    cap_drop = value.get("cap_drop")
    if not isinstance(cap_drop, list) or "ALL" not in cap_drop:
        fail(f"production service {name} does not drop all capabilities")
    security_opt = value.get("security_opt")
    if (
        not isinstance(security_opt, list)
        or "no-new-privileges:true" not in security_opt
    ):
        fail(f"production service {name} lacks no-new-privileges")
    if value.get("privileged") not in (None, False):
        fail(f"production service {name} must not be privileged")
    for key in ("cap_add", "devices", "device_cgroup_rules"):
        if value.get(key) not in (None, []):
            fail(f"production service {name} has prohibited {key}")
    for key in ("network_mode", "pid", "ipc"):
        if value.get(key) not in (None, ""):
            fail(f"production service {name} has prohibited {key}")


def require_command(
    value: dict[str, Any], name: str, expected: list[str] | None
) -> None:
    if value.get("command") != expected or value.get("entrypoint") is not None:
        fail(f"production service {name} has an unexpected command or entrypoint")


def secret_bindings(value: dict[str, Any], name: str) -> dict[str, str]:
    bindings: dict[str, str] = {}
    secrets = value.get("secrets")
    if not isinstance(secrets, list):
        fail(f"production service {name} has no resolved secret bindings")
    for item in secrets:
        if not isinstance(item, dict):
            fail(f"production service {name} has an unresolved secret binding")
        source = item.get("source")
        target = item.get("target")
        if not isinstance(source, str) or not source or not isinstance(target, str):
            fail(f"production service {name} has an invalid secret binding")
        if target in bindings:
            fail(f"production service {name} has duplicate secret target {target}")
        bindings[target] = source
    return bindings


def require_networks(value: dict[str, Any], name: str, expected: set[str]) -> None:
    networks = value.get("networks")
    if not isinstance(networks, dict) or set(networks) != expected:
        fail(f"production service {name} is not attached to exactly {sorted(expected)}")


def require_no_ports(value: dict[str, Any], name: str) -> None:
    if value.get("ports") not in (None, []):
        fail(f"production service {name} must not publish host ports")


def require_loopback_port(
    value: dict[str, Any], name: str, *, target: int, port_name: str
) -> str:
    ports = value.get("ports")
    if not isinstance(ports, list) or len(ports) != 1 or not isinstance(ports[0], dict):
        fail(f"production service {name} must publish exactly one port")
    port = ports[0]
    published = port.get("published")
    if isinstance(published, int):
        published = str(published)
    if (
        port.get("name") != port_name
        or port.get("host_ip") != "127.0.0.1"
        or port.get("target") != target
        or port.get("protocol") != "tcp"
        or port.get("mode") != "ingress"
        or not isinstance(published, str)
        or not published.isdigit()
        or not 1 <= int(published) <= 65535
    ):
        fail(f"production service {name} port is not the exact loopback binding")
    return published


def numeric_service_user(value: dict[str, Any], name: str) -> tuple[int, int]:
    user = value.get("user")
    if not isinstance(user, str) or re.fullmatch(r"[0-9]+:[0-9]+", user) is None:
        fail(f"production service {name} must use one explicit numeric UID:GID")
    uid_text, gid_text = user.split(":", 1)
    uid, gid = int(uid_text), int(gid_text)
    if uid == 0 or gid == 0:
        fail(f"production service {name} must not run as root")
    return uid, gid


def repository_regular_file(repo_root: Path, relative: str, label: str) -> Path:
    candidate = Path(relative)
    if (
        candidate.is_absolute()
        or not candidate.parts
        or any(part in {"", ".", ".."} for part in candidate.parts)
    ):
        fail(f"{label} path is not one normalized repository-relative path")
    try:
        root = repo_root.resolve(strict=True)
    except OSError as exc:
        fail(f"cannot resolve repository root {repo_root}: {exc}")
    current = root
    for index, part in enumerate(candidate.parts):
        current /= part
        try:
            metadata = current.lstat()
        except OSError as exc:
            fail(f"cannot inspect {label} {current}: {exc}")
        if stat.S_ISLNK(metadata.st_mode):
            fail(f"{label} path contains a symbolic link")
        if index < len(candidate.parts) - 1:
            if not stat.S_ISDIR(metadata.st_mode):
                fail(f"{label} parent is not a directory")
        elif not stat.S_ISREG(metadata.st_mode):
            fail(f"{label} is not a regular file")
    return current


def signed_sub2api_inputs(
    *,
    versions_lock_path: Path,
    repo_root: Path,
    verified_release: dict[str, Any],
) -> dict[str, str]:
    versions_sha256 = secure_file_sha256(versions_lock_path, "versions lock")
    signed_versions_sha256 = verified_release.get("CONTROL_VERSIONS_LOCK_SHA256")
    release_inputs = verified_release.get("CONTROL_RELEASE_INPUT_SHA256S")
    contract_relative = verified_release.get("CONTROL_SUB2API_AUTH_CONTRACT_PATH")
    signed_contract_sha256 = verified_release.get(
        "CONTROL_SUB2API_AUTH_CONTRACT_SHA256"
    )
    if (
        not isinstance(signed_versions_sha256, str)
        or not SHA256_RE.fullmatch(signed_versions_sha256)
        or versions_sha256 != signed_versions_sha256
    ):
        fail("selected versions lock differs from the signed release input")
    if not isinstance(release_inputs, dict) or any(
        not isinstance(path, str)
        or not isinstance(digest, str)
        or SHA256_RE.fullmatch(digest) is None
        for path, digest in release_inputs.items()
    ):
        fail("signed release input hash inventory is invalid")
    if release_inputs.get("versions.lock.json") != signed_versions_sha256:
        fail("signed versions lock hash is inconsistent with the release inventory")
    if (
        not isinstance(contract_relative, str)
        or not isinstance(signed_contract_sha256, str)
        or SHA256_RE.fullmatch(signed_contract_sha256) is None
        or release_inputs.get(contract_relative) != signed_contract_sha256
    ):
        fail("signed Sub2API auth contract binding is invalid")

    versions_lock = load_json(versions_lock_path, "versions lock")
    if not isinstance(versions_lock, dict) or versions_lock.get("format_version") != 1:
        fail("versions lock has no supported Sub2API section")
    sub2api = versions_lock.get("sub2api")
    if not isinstance(sub2api, dict):
        fail("versions lock has no supported Sub2API section")
    if sub2api.get("auth_contract_file") != contract_relative:
        fail("versions lock selects a different Sub2API auth contract")
    if sub2api.get("auth_contract_sha256") != signed_contract_sha256:
        fail("versions lock embeds a different Sub2API auth contract hash")

    contract_file = repository_regular_file(
        repo_root, contract_relative, "Sub2API auth contract"
    )
    if (
        secure_file_sha256(contract_file, "Sub2API auth contract")
        != signed_contract_sha256
    ):
        fail("selected Sub2API auth contract differs from the signed release input")
    return {
        "versions_lock_sha256": versions_sha256,
        "auth_contract_file": str(contract_file),
        "auth_contract_relative": contract_relative,
        "auth_contract_sha256": signed_contract_sha256,
    }


def compose_plan(args: argparse.Namespace) -> dict[str, Any]:
    compose_sha256 = secure_file_sha256(args.compose_config, "resolved Compose config")
    config = load_json(args.compose_config, "resolved Compose config")
    if (
        secure_file_sha256(args.compose_config, "resolved Compose config")
        != compose_sha256
    ):
        fail("resolved Compose config changed while it was admitted")
    verified_release = load_json(args.release_verification, "verified release output")
    if not isinstance(config, dict):
        fail("resolved Compose config is not an object")
    if not isinstance(verified_release, dict):
        fail("verified release output is not an object")
    signed_sub2api = signed_sub2api_inputs(
        versions_lock_path=args.versions_lock,
        repo_root=args.repo_root,
        verified_release=verified_release,
    )
    api = service(config, "control-api")
    api_replica = service(config, "control-api-replica")
    migrate = service(config, "control-migrate")
    pwa = service(config, "codex-pwa")
    backup = service(config, "control-backup")
    for name, value in (
        ("control-api", api),
        ("control-api-replica", api_replica),
        ("control-migrate", migrate),
        ("codex-pwa", pwa),
        ("control-backup", backup),
    ):
        require_hardened_service(value, name)

    api_image = api.get("image")
    api_replica_image = api_replica.get("image")
    migrate_image = migrate.get("image")
    pwa_image = pwa.get("image")
    if not isinstance(api_image, str) or not DIGEST_REF_RE.fullmatch(api_image):
        fail("CONTROL_API_IMAGE is not an immutable sha256 digest reference")
    if migrate_image != api_image or api_replica_image != api_image:
        fail("all Control API instances and control-migrate must use one image digest")
    if not isinstance(pwa_image, str) or not DIGEST_REF_RE.fullmatch(pwa_image):
        fail("CONTROL_PWA_IMAGE is not an immutable sha256 digest reference")
    if pwa_image == api_image:
        fail("Control API and PWA unexpectedly use the same image reference")
    backup_image = backup.get("image")
    if not isinstance(backup_image, str) or not DIGEST_REF_RE.fullmatch(backup_image):
        fail("CONTROL_POSTGRES_TOOLS_IMAGE is not an immutable sha256 digest reference")
    api_environment = api.get("environment")
    replica_environment = api_replica.get("environment")
    migrate_environment = migrate.get("environment")
    backup_environment = backup.get("environment")
    if not all(
        isinstance(value, dict)
        for value in (
            api_environment,
            replica_environment,
            migrate_environment,
            backup_environment,
        )
    ):
        fail("Control API environment is missing from resolved Compose config")
    if migrate_environment != api_environment or replica_environment != api_environment:
        fail(
            "Control API instances and control-migrate do not have identical environments"
        )
    connector_json = api_environment.get("CONTROL_CONNECTOR_RELEASE_METADATA_JSON")
    if (
        not isinstance(connector_json, str)
        or not connector_json
        or "\n" in connector_json
        or "\r" in connector_json
    ):
        fail("packaged Connector release metadata is not projected into Control API")
    connector_value = connector_release_metadata(
        strict_json_bytes(
            connector_json.encode("utf-8"),
            "projected Connector release metadata",
        )
    )
    canonical_connector_json = json.dumps(
        connector_value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    )
    if connector_json != canonical_connector_json:
        fail("projected Connector release metadata is not canonical JSON")
    connector_json_sha256 = hashlib.sha256(connector_json.encode("ascii")).hexdigest()
    if (
        verified_release.get("CONTROL_CONNECTOR_RELEASE_METADATA_JSON_SHA256")
        != connector_json_sha256
    ):
        fail("projected Connector metadata differs from the verified server package")
    server_package = verified_release.get("_server_package")
    if (
        not isinstance(server_package, dict)
        or server_package.get("mode") not in {"online", "offline"}
        or verified_release.get("CONTROL_SERVER_PACKAGE_MODE")
        != server_package.get("mode")
        or server_package.get("manifest_sha256")
        != verified_release.get("CONTROL_SERVER_PACKAGE_MANIFEST_SHA256")
        or server_package.get("verification_receipt_sha256")
        != verified_release.get("CONTROL_SERVER_PACKAGE_VERIFICATION_RECEIPT_SHA256")
        or server_package.get("docker_host") != LOCAL_DOCKER_HOST
        or verified_release.get("CONTROL_SERVER_PACKAGE_DOCKER_HOST")
        != LOCAL_DOCKER_HOST
    ):
        fail("signed release verification lacks a bound server package receipt")
    if api_environment.get("CONTROL_ENVIRONMENT") != "production":
        fail("CONTROL_ENVIRONMENT must resolve to production")
    if api_environment.get("CONTROL_SUB2API_BASE_URL") != "http://sub2api:8080":
        fail("production Sub2API base URL is not the fixed internal authority")
    if api_environment.get("CONTROL_TRUST_FORWARDED_FOR") != "true":
        fail(
            "production Control API must trust the client IP header overwritten by the "
            "same-host Nginx edge for Sub2API session binding"
        )
    if api_environment.get("CONTROL_REDIS_AUTH_MODE") != "password":
        fail("normal production admission requires the dedicated Redis ACL password")
    control_database_role = api_environment.get("CONTROL_DB_USER")
    control_database_name = api_environment.get("CONTROL_DB_NAME")
    control_redis_user = api_environment.get("CONTROL_REDIS_USER")
    control_redis_prefix = api_environment.get("CONTROL_REDIS_PREFIX")
    if (
        not isinstance(control_database_role, str)
        or REVISION_RE.fullmatch(control_database_role) is None
        or not isinstance(control_database_name, str)
        or REVISION_RE.fullmatch(control_database_name) is None
        or not isinstance(args.sub2api_database, str)
        or REVISION_RE.fullmatch(args.sub2api_database) is None
        or control_database_name == args.sub2api_database
    ):
        fail("production PostgreSQL identities are not isolated safe identifiers")
    if (
        not isinstance(control_redis_user, str)
        or control_redis_user in {"", "default"}
        or re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", control_redis_user) is None
        or not isinstance(control_redis_prefix, str)
        or not control_redis_prefix
        or any(character.isspace() for character in control_redis_prefix)
    ):
        fail("normal production admission requires a dedicated Redis user and prefix")
    database_keys = (
        "CONTROL_DATABASE_PASSWORD_FILE",
        "CONTROL_DB_HOST",
        "CONTROL_DB_PORT",
        "CONTROL_DB_USER",
        "CONTROL_DB_NAME",
    )
    if set(backup_environment) != {"BACKUP_DIR", *database_keys}:
        fail("control-backup has unexpected environment inputs")
    if backup_environment.get("BACKUP_DIR") != "/backups":
        fail("control-backup output path is not the fixed /backups mount")
    for key in database_keys:
        api_value = api_environment.get(key)
        if not isinstance(api_value, str) or not api_value:
            fail(f"production database setting {key} is missing")
        if backup_environment.get(key) != api_value:
            fail(f"control-backup and Control API disagree on {key}")
    if api_environment.get("CONTROL_DATABASE_PASSWORD_FILE") != (
        "/run/secrets/control_db_password"
    ):
        fail("production database password path is not the fixed secret target")
    if api_environment.get("CONTROL_DB_QUERY") not in (None, ""):
        fail("production database query options must be empty for backup equivalence")
    public_origins = api_environment.get("CONTROL_ALLOWED_ORIGINS_CSV")
    if (
        not isinstance(public_origins, str)
        or "," in public_origins
        or not public_origins.startswith("https://")
    ):
        fail("production deployment must have one exact HTTPS public origin")

    release = api_environment.get("CONTROL_BUILD_VERSION")
    source_revision = api_environment.get("CONTROL_BUILD_VCS_REF")
    marker = api_environment.get("CONTROL_SUB2API_CONTRACT_MARKER")
    if (
        not isinstance(release, str)
        or not release
        or release in {"unknown", "replace-me"}
    ):
        fail("CONTROL_RELEASE is not a concrete release identifier")
    if not isinstance(source_revision, str) or not VCS_REF_RE.fullmatch(
        source_revision
    ):
        fail("CONTROL_VCS_REF must be one full 40-character Git commit")
    if not isinstance(marker, str) or marker in {"", "UNVERIFIED"}:
        fail("CONTROL_SUB2API_CONTRACT_MARKER is not admitted")
    verified_values = {
        "CONTROL_API_IMAGE": api_image,
        "CONTROL_PWA_IMAGE": pwa_image,
        "CONTROL_POSTGRES_TOOLS_IMAGE": backup_image,
        "CONTROL_RELEASE": release,
        "CONTROL_VCS_REF": source_revision,
        "CONTROL_SOURCE_REPOSITORY": args.source_repository,
    }
    for key, expected in verified_values.items():
        if verified_release.get(key) != expected:
            fail(
                f"resolved Compose value {key} differs from the signed release verification"
            )
    if not re.fullmatch(r"https://github\.com/[^/\s]+/[^/\s]+", args.source_repository):
        fail(
            "externally trusted source repository must be one HTTPS GitHub repository URL"
        )
    signed_migration_head = verified_release.get("CONTROL_MIGRATION_HEAD")
    if not isinstance(signed_migration_head, str) or not REVISION_RE.fullmatch(
        signed_migration_head
    ):
        fail("signed release verification has no valid migration head")

    for name, value in (
        ("control-api", api),
        ("control-api-replica", api_replica),
        ("control-migrate", migrate),
        ("codex-pwa", pwa),
        ("control-backup", backup),
    ):
        labels = value.get("labels")
        if (
            not isinstance(labels, dict)
            or labels.get("org.opencontainers.image.version") != release
        ):
            fail(f"{name} Compose release label does not match CONTROL_RELEASE")

    require_command(api, "control-api", ["api"])
    require_command(api_replica, "control-api-replica", ["api"])
    require_command(migrate, "control-migrate", ["migrate"])
    require_command(pwa, "codex-pwa", None)
    require_command(backup, "control-backup", None)

    application_secrets = {
        "/run/secrets/control_db_password": "control_db_password",
        "/run/secrets/control_redis_password": "control_redis_password",
        "/run/secrets/control_session_hmac_secret": "control_session_hmac_secret",
    }
    for name, value in (
        ("control-api", api),
        ("control-api-replica", api_replica),
        ("control-migrate", migrate),
    ):
        if secret_bindings(value, name) != application_secrets:
            fail(
                f"production service {name} does not have the exact application secrets"
            )
    if secret_bindings(backup, "control-backup") != {
        "/run/secrets/control_db_password": "control_db_password"
    }:
        fail("control-backup does not share exactly the Control database secret")
    if pwa.get("secrets") not in (None, []):
        fail("codex-pwa must not receive application secrets")

    networks = config.get("networks")
    if not isinstance(networks, dict) or not isinstance(
        networks.get("sub2api-network"), dict
    ):
        fail("resolved Compose config has no external Sub2API network")
    external_network = networks["sub2api-network"]
    network_name = external_network.get("name")
    if (
        external_network.get("external") is not True
        or not isinstance(network_name, str)
        or not network_name
    ):
        fail("Sub2API network must be one named external network")
    pwa_network = networks.get("pwa-network")
    expected_pwa_driver_opts = {
        "com.docker.network.bridge.enable_ip_masquerade": "false",
        "com.docker.network.bridge.enable_icc": "false",
    }
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
            "PWA network must be one named non-internal bridge with exact "
            "masquerading-disabled and ICC-disabled options"
        )

    require_networks(api, "control-api", {"sub2api-network"})
    require_networks(api_replica, "control-api-replica", {"sub2api-network"})
    require_networks(migrate, "control-migrate", {"sub2api-network"})
    require_networks(backup, "control-backup", {"sub2api-network"})
    require_networks(pwa, "codex-pwa", {"pwa-network"})
    require_no_ports(migrate, "control-migrate")
    require_no_ports(backup, "control-backup")
    api_port = require_loopback_port(
        api, "control-api", target=8090, port_name="control-api-loopback"
    )
    replica_port = require_loopback_port(
        api_replica,
        "control-api-replica",
        target=8090,
        port_name="control-api-replica-loopback",
    )
    pwa_port = require_loopback_port(
        pwa, "codex-pwa", target=8080, port_name="pwa-loopback"
    )
    if len({api_port, replica_port, pwa_port}) != 3:
        fail("production host port bindings must be distinct")

    volumes = backup.get("volumes")
    backup_sources = [
        volume.get("source")
        for volume in volumes or []
        if isinstance(volume, dict) and volume.get("target") == "/backups"
    ]
    if (
        len(backup_sources) != 1
        or not isinstance(backup_sources[0], str)
        or len(volumes or []) != 1
        or volumes[0].get("type") != "bind"
        or volumes[0].get("read_only") not in (None, False)
    ):
        fail("control-backup must have exactly one /backups bind mount")
    backup_dir = Path(backup_sources[0])
    if not backup_dir.is_absolute():
        fail("resolved backup directory is not absolute")
    backup_uid, backup_gid = numeric_service_user(backup, "control-backup")
    directory_descriptor, _ = open_stable_directory(
        backup_dir,
        "production backup directory",
        expected_uid=backup_uid,
        exact_mode=0o700,
    )
    os.close(directory_descriptor)
    repo_root = args.repo_root.resolve()
    try:
        backup_dir.resolve(strict=False).relative_to(repo_root)
    except ValueError:
        pass
    else:
        fail("production backup directory must be outside the source checkout")

    project_name = config.get("name")
    if (
        not isinstance(project_name, str)
        or re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,62}", project_name) is None
    ):
        fail("resolved Compose project name is invalid")

    return {
        "format_version": 1,
        "compose_project": project_name,
        "resolved_compose_sha256": compose_sha256,
        "api_image": api_image,
        "pwa_image": pwa_image,
        "backup_image": backup_image,
        "backup_directory": str(backup_dir),
        "backup_owner_uid": backup_uid,
        "backup_owner_gid": backup_gid,
        "release": release,
        "source_revision": source_revision,
        "source_repository": args.source_repository,
        "signed_migration_head": signed_migration_head,
        "sub2api_contract_marker": marker,
        **signed_sub2api,
        "sub2api_network": network_name,
        "pwa_network": pwa_network["name"],
        "pwa_network_driver": "bridge",
        "pwa_network_driver_opts": expected_pwa_driver_opts,
        "public_origin": public_origins,
        "server_package": server_package,
        "connector_release_metadata_sha256": connector_json_sha256,
        "datastores": {
            "postgres": {
                "role": control_database_role,
                "database": control_database_name,
                "sub2api_database": args.sub2api_database,
                "host": api_environment["CONTROL_DB_HOST"],
                "port": api_environment["CONTROL_DB_PORT"],
            },
            "redis": {
                "auth_mode": "password",
                "user": control_redis_user,
                "prefix": control_redis_prefix,
                "host": api_environment.get("CONTROL_REDIS_HOST"),
                "port": api_environment.get("CONTROL_REDIS_PORT"),
            },
        },
        "instances": {
            "control-api": {
                "image_id_key": "api",
                "network": network_name,
                "target_port": 8090,
                "published_port": api_port,
            },
            "control-api-replica": {
                "image_id_key": "api",
                "network": network_name,
                "target_port": 8090,
                "published_port": replica_port,
            },
            "codex-pwa": {
                "image_id_key": "pwa",
                "network": pwa_network["name"],
                "target_port": 8080,
                "published_port": pwa_port,
            },
        },
    }


def inspect_object(path: Path, label: str) -> dict[str, Any]:
    value = load_json(path, label)
    if not isinstance(value, list) or len(value) != 1 or not isinstance(value[0], dict):
        fail(f"{label} must contain exactly one image inspect object")
    return value[0]


def image_evidence(
    image: dict[str, Any],
    *,
    reference: str,
    release: str,
    source_revision: str,
    source_repository: str,
    label: str,
) -> dict[str, Any]:
    image_id = image.get("Id")
    if not isinstance(image_id, str) or not IMAGE_ID_RE.fullmatch(image_id):
        fail(f"{label} image has no full sha256 image ID")
    repo_digests = image.get("RepoDigests")
    if not isinstance(repo_digests, list) or reference not in repo_digests:
        fail(f"{label} image RepoDigests do not contain the exact configured reference")
    config = image.get("Config")
    labels = config.get("Labels") if isinstance(config, dict) else None
    if not isinstance(labels, dict):
        fail(f"{label} image has no OCI labels")
    expected_labels = {
        "org.opencontainers.image.version": release,
        "org.opencontainers.image.revision": source_revision,
        "org.opencontainers.image.source": source_repository,
    }
    for key, expected in expected_labels.items():
        if labels.get(key) != expected:
            fail(f"{label} image OCI label {key} mismatch")
    if image.get("Os") != "linux" or image.get("Architecture") != "amd64":
        fail(f"{label} image platform must be exactly linux/amd64")
    return {
        "reference": reference,
        "image_id": image_id,
        "created": image.get("Created"),
        "architecture": image.get("Architecture"),
        "os": image.get("Os"),
        "oci_labels": expected_labels,
    }


def release_images(args: argparse.Namespace) -> dict[str, Any]:
    plan = load_json(args.plan, "deployment plan")
    if not isinstance(plan, dict):
        fail("deployment plan is not an object")
    api = image_evidence(
        inspect_object(args.api_inspect, "Control API image inspect"),
        reference=plan["api_image"],
        release=plan["release"],
        source_revision=plan["source_revision"],
        source_repository=plan["source_repository"],
        label="Control API",
    )
    pwa = image_evidence(
        inspect_object(args.pwa_inspect, "PWA image inspect"),
        reference=plan["pwa_image"],
        release=plan["release"],
        source_revision=plan["source_revision"],
        source_repository=plan["source_repository"],
        label="PWA",
    )
    if api["image_id"] == pwa["image_id"]:
        fail("Control API and PWA resolve to the same image ID")
    backup_tools = image_evidence(
        inspect_object(args.backup_inspect, "backup tools image inspect"),
        reference=plan["backup_image"],
        release=plan["release"],
        source_revision=plan["source_revision"],
        source_repository=plan["source_repository"],
        label="backup tools",
    )
    if len({api["image_id"], pwa["image_id"], backup_tools["image_id"]}) != 3:
        fail("release components must resolve to three distinct image IDs")
    return {
        "format_version": 1,
        "verified_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "api": api,
        "pwa": pwa,
        "backup_tools": backup_tools,
    }


def metadata_signature(metadata: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def open_stable_regular_file(
    path: Path,
    label: str,
    *,
    expected_uid: int | None = None,
    exact_mode: int | None = None,
    max_size: int | None = None,
) -> tuple[int, os.stat_result]:
    try:
        path_metadata = path.lstat()
    except OSError as exc:
        fail(f"cannot stat {label} {path}: {exc}")
    if stat.S_ISLNK(path_metadata.st_mode) or not stat.S_ISREG(path_metadata.st_mode):
        fail(f"{label} is not a regular file: {path}")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        fail(f"cannot open {label} without following links: {exc}")
    try:
        opened_metadata = os.fstat(descriptor)
        if not stat.S_ISREG(opened_metadata.st_mode) or (
            path_metadata.st_dev,
            path_metadata.st_ino,
        ) != (opened_metadata.st_dev, opened_metadata.st_ino):
            fail(f"{label} changed while it was opened")
        if expected_uid is not None and opened_metadata.st_uid != expected_uid:
            fail(f"{label} is not owned by UID {expected_uid}")
        if (
            exact_mode is not None
            and stat.S_IMODE(opened_metadata.st_mode) != exact_mode
        ):
            fail(f"{label} permissions are not exactly {exact_mode:04o}")
        if max_size is not None and opened_metadata.st_size > max_size:
            fail(f"{label} is larger than {max_size} bytes")
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor, opened_metadata


def open_stable_regular_file_at(
    directory_descriptor: int,
    name: str,
    label: str,
    *,
    expected_uid: int | None = None,
    exact_mode: int | None = None,
    max_size: int | None = None,
) -> tuple[int, os.stat_result]:
    if name in {"", ".", ".."} or "/" in name:
        fail(f"{label} has an invalid relative name")
    try:
        path_metadata = os.stat(
            name,
            dir_fd=directory_descriptor,
            follow_symlinks=False,
        )
    except OSError as exc:
        fail(f"cannot stat {label}: {exc}")
    if stat.S_ISLNK(path_metadata.st_mode) or not stat.S_ISREG(path_metadata.st_mode):
        fail(f"{label} is not a regular file")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(name, flags, dir_fd=directory_descriptor)
    except OSError as exc:
        fail(f"cannot open {label} without following links: {exc}")
    try:
        opened_metadata = os.fstat(descriptor)
        if not stat.S_ISREG(opened_metadata.st_mode) or (
            path_metadata.st_dev,
            path_metadata.st_ino,
        ) != (opened_metadata.st_dev, opened_metadata.st_ino):
            fail(f"{label} changed while it was opened")
        if expected_uid is not None and opened_metadata.st_uid != expected_uid:
            fail(f"{label} is not owned by UID {expected_uid}")
        if (
            exact_mode is not None
            and stat.S_IMODE(opened_metadata.st_mode) != exact_mode
        ):
            fail(f"{label} permissions are not exactly {exact_mode:04o}")
        if max_size is not None and opened_metadata.st_size > max_size:
            fail(f"{label} is larger than {max_size} bytes")
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor, opened_metadata


def open_stable_directory(
    path: Path,
    label: str,
    *,
    expected_uid: int | None = None,
    exact_mode: int | None = None,
) -> tuple[int, os.stat_result]:
    try:
        path_metadata = path.lstat()
    except OSError as exc:
        fail(f"cannot stat {label} {path}: {exc}")
    if stat.S_ISLNK(path_metadata.st_mode) or not stat.S_ISDIR(path_metadata.st_mode):
        fail(f"{label} is not a real directory: {path}")
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_DIRECTORY", 0)
    )
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        fail(f"cannot open {label} without following links: {exc}")
    try:
        opened_metadata = os.fstat(descriptor)
        if not stat.S_ISDIR(opened_metadata.st_mode) or (
            path_metadata.st_dev,
            path_metadata.st_ino,
        ) != (opened_metadata.st_dev, opened_metadata.st_ino):
            fail(f"{label} changed while it was opened")
        if expected_uid is not None and opened_metadata.st_uid != expected_uid:
            fail(f"{label} is not owned by UID {expected_uid}")
        if (
            exact_mode is not None
            and stat.S_IMODE(opened_metadata.st_mode) != exact_mode
        ):
            fail(f"{label} permissions are not exactly {exact_mode:04o}")
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor, opened_metadata


def assert_stable(descriptor: int, initial: os.stat_result, label: str) -> None:
    if metadata_signature(os.fstat(descriptor)) != metadata_signature(initial):
        fail(f"{label} changed while it was being verified")


def read_descriptor(descriptor: int, label: str, maximum: int) -> bytes:
    os.lseek(descriptor, 0, os.SEEK_SET)
    content = bytearray()
    while len(content) <= maximum:
        chunk = os.read(descriptor, min(131_072, maximum + 1 - len(content)))
        if not chunk:
            break
        content.extend(chunk)
    if len(content) > maximum:
        fail(f"{label} is larger than {maximum} bytes")
    return bytes(content)


def hash_descriptor(descriptor: int) -> str:
    os.lseek(descriptor, 0, os.SEEK_SET)
    digest = hashlib.sha256()
    while chunk := os.read(descriptor, 1_048_576):
        digest.update(chunk)
    return digest.hexdigest()


def secure_file_sha256(path: Path, label: str) -> str:
    descriptor, metadata = open_stable_regular_file(path, label)
    try:
        digest = hash_descriptor(descriptor)
        assert_stable(descriptor, metadata, label)
        return digest
    finally:
        os.close(descriptor)


def secure_text_file(
    path: Path, label: str, maximum: int = MAX_PRIVATE_INPUT_BYTES
) -> str:
    descriptor, metadata = open_stable_regular_file(path, label, max_size=maximum)
    try:
        content = read_descriptor(descriptor, label, maximum)
        assert_stable(descriptor, metadata, label)
        return content.decode("utf-8")
    except UnicodeDecodeError as exc:
        fail(f"{label} is not valid UTF-8: {exc}")
    finally:
        os.close(descriptor)


def regular_private_file(path: Path, label: str) -> os.stat_result:
    descriptor, metadata = open_stable_regular_file(path, label, exact_mode=0o600)
    os.close(descriptor)
    return metadata


def read_private_opaque_file(path: Path, label: str) -> str:
    descriptor, opened_metadata = open_stable_regular_file(
        path,
        label,
        expected_uid=os.geteuid(),
        exact_mode=0o600,
        max_size=65_536,
    )
    try:
        content = read_descriptor(descriptor, label, 65_536)
        assert_stable(descriptor, opened_metadata, label)
    except OSError as exc:
        fail(f"cannot read {label}: {exc}")
    finally:
        os.close(descriptor)

    try:
        value = content.decode("utf-8").rstrip("\r\n")
    except UnicodeDecodeError as exc:
        fail(f"{label} is not valid UTF-8: {exc}")
    if not value or any(character.isspace() for character in value):
        fail(f"{label} must contain one opaque value")
    return value


def operator_directory(args: argparse.Namespace) -> dict[str, Any]:
    if not args.directory.is_absolute():
        fail("operator directory must be absolute")
    descriptor, metadata = open_stable_directory(
        args.directory,
        args.label,
        expected_uid=os.geteuid(),
        exact_mode=0o700,
    )
    os.close(descriptor)
    return {
        "format_version": 1,
        "path": str(args.directory),
        "owner_uid": metadata.st_uid,
        "mode": "0700",
    }


def post_success_reverse_admission(args: argparse.Namespace) -> dict[str, Any]:
    record_root = args.record_root
    deployment_directory = args.deployment_directory
    normalized_root = Path(os.path.normpath(str(record_root)))
    normalized_deployment = Path(os.path.normpath(str(deployment_directory)))
    if (
        not record_root.is_absolute()
        or not deployment_directory.is_absolute()
        or record_root != normalized_root
        or deployment_directory != normalized_deployment
        or deployment_directory.parent != record_root
        or re.fullmatch(
            r"deployment-[0-9]{8}T[0-9]{6}Z-[0-9]+", deployment_directory.name
        )
        is None
    ):
        fail("post-success reverse directory is not one normalized deployment child")
    if (
        re.fullmatch(
            r"lifecycle-post-success:[0-9]{8}T[0-9]{6}Z-[0-9]+-[0-9]+-"
            r"(?:install|upgrade|rollback)-[0-9a-f]{32}",
            args.trigger_stage,
        )
        is None
    ):
        fail("post-success reverse trigger is not one lifecycle operation id")

    for path, label in (
        (record_root, "deployment record root"),
        (deployment_directory, "post-success deployment record directory"),
    ):
        descriptor, _ = open_stable_directory(
            path,
            label,
            expected_uid=args.expected_owner_uid,
            exact_mode=0o700,
        )
        os.close(descriptor)

    terminal_path = deployment_directory / "reverse-execution.json"
    if terminal_path.exists() or terminal_path.is_symlink():
        fail("post-success bounded reverse already has terminal evidence")

    def private_json(
        filename: str, label: str, mode: int
    ) -> tuple[dict[str, Any], bytes, Path]:
        path = deployment_directory / filename
        raw = secure_exact_bytes(
            path,
            label,
            expected_uid=args.expected_owner_uid,
            exact_mode=mode,
        )
        value = strict_json_bytes(raw, label, canonical=True)
        if not isinstance(value, dict):
            fail(f"{label} must be an object")
        return value, raw, path

    deployment, deployment_raw, deployment_path = private_json(
        "deployment.json", "successful deployment record", 0o400
    )
    reverse_plan, reverse_raw, reverse_path = private_json(
        "reverse-plan.json", "bounded reverse plan", 0o600
    )
    rollback_compose, rollback_raw, rollback_path = private_json(
        "rollback-compose.json", "rollback Compose snapshot", 0o600
    )
    plan, plan_raw, _ = private_json("plan.json", "deployment plan", 0o600)
    auth_evidence, _, auth_path = private_json(
        "generated-auth-evidence.json", "generated authentication evidence", 0o600
    )
    compose_path = deployment_directory / "compose-config.json"
    compose_raw = secure_exact_bytes(
        compose_path,
        "resolved Compose snapshot",
        expected_uid=args.expected_owner_uid,
        exact_mode=0o600,
    )
    versions_path = deployment_directory / "versions.lock.json"
    versions_raw = secure_exact_bytes(
        versions_path,
        "signed versions lock snapshot",
        expected_uid=args.expected_owner_uid,
        exact_mode=0o600,
    )
    contract_path = deployment_directory / "sub2api-auth-contract.json"
    contract_raw = secure_exact_bytes(
        contract_path,
        "signed Sub2API auth contract snapshot",
        expected_uid=args.expected_owner_uid,
        exact_mode=0o600,
    )

    recovery = deployment.get("recovery")
    reverse_record = (
        recovery.get("bounded_reverse_plan") if isinstance(recovery, dict) else None
    )
    rollback_record = recovery.get("rollback_compose") if isinstance(recovery, dict) else None
    limits = reverse_plan.get("limits")
    bindings = reverse_plan.get("bindings")
    steps = reverse_plan.get("reverse_steps")
    source_revision = deployment.get("source_database_revision")
    target_revision = deployment.get("target_migration_head")
    if (
        deployment.get("format_version") != 1
        or deployment.get("status") != "deployed"
        or not isinstance(source_revision, str)
        or source_revision != target_revision
        or deployment.get("deployed_database_revision") != target_revision
        or not isinstance(reverse_record, dict)
        or reverse_record.get("path") != str(reverse_path)
        or reverse_record.get("sha256") != hashlib.sha256(reverse_raw).hexdigest()
        or reverse_record.get("size") != len(reverse_raw)
        or reverse_record.get("value") != reverse_plan
        or not isinstance(rollback_record, dict)
        or rollback_record.get("path") != str(rollback_path)
        or rollback_record.get("sha256") != hashlib.sha256(rollback_raw).hexdigest()
        or rollback_record.get("size") != len(rollback_raw)
        or rollback_record.get("value") != rollback_compose
        or not isinstance(limits, dict)
        or reverse_plan.get("format_version") != 1
        or limits.get("migration_required") is not False
        or limits.get("automatic_reverse_on_failure") is not True
        or limits.get("database_restore_requires_write_freeze") is not True
        or limits.get("application_reverse_preserves_database") is not True
        or limits.get("writer_exposure_after_database_mutation_allowed") is not False
        or limits.get("database_restore_policy")
        != "only-before-writer-exposure-after-observed-mutation"
        or limits.get("max_attempts_per_step") != 1
        or limits.get("post_reverse_verification_timeout_seconds") != 120
        or type(limits.get("max_reverse_steps")) is not int
        or not 5 <= limits["max_reverse_steps"] <= 8
        or type(limits.get("total_timeout_seconds")) is not int
        or not 1 <= limits["total_timeout_seconds"] <= 900
        or reverse_plan.get("status") != "admitted"
        or reverse_plan.get("type") != "production-bounded-reverse-plan-v1"
        or not isinstance(bindings, dict)
        or bindings.get("deployment_plan_sha256")
        != hashlib.sha256(plan_raw).hexdigest()
        or not isinstance(steps, list)
        or len(steps) != 5
        or any(not isinstance(step, dict) for step in steps)
        or [step.get("ordinal") for step in steps] != [1, 2, 3, 4, 5]
        or [step.get("timeout_seconds") for step in steps]
        != [105, 360, 105, 105, 105]
        or any(step.get("max_attempts") != 1 for step in steps)
        or sum(step["timeout_seconds"] for step in steps) + 120
        > limits["total_timeout_seconds"]
        or steps[0].get("action") != "stop-database-mutators"
        or steps[0].get("services")
        != ["control-api", "control-api-replica", "control-migrate"]
        or steps[1].get("action")
        != "restore-control-database-from-premigration-dump"
        or steps[1].get("condition")
        != "database-mutated-and-writers-never-reexposed"
        or steps[1].get("write_freeze_required") is not True
        or [step.get("service") for step in steps[2:]]
        != ["codex-pwa", "control-api", "control-api-replica"]
        or any(
            step.get("action") not in {"recreate-prior-service", "remove-new-service"}
            for step in steps[2:]
        )
    ):
        fail("post-success record has no admitted application-only bounded reverse")

    sub2api_record = deployment.get("sub2api")
    auth_record = (
        sub2api_record.get("auth_evidence")
        if isinstance(sub2api_record, dict)
        else None
    )
    probe = auth_evidence.get("probe")
    canonical_auth = json.dumps(
        auth_evidence,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")
    if (
        plan.get("resolved_compose_sha256") != hashlib.sha256(compose_raw).hexdigest()
        or deployment.get("resolved_compose_sha256")
        != hashlib.sha256(compose_raw).hexdigest()
        or plan.get("versions_lock_sha256") != hashlib.sha256(versions_raw).hexdigest()
        or plan.get("auth_contract_sha256") != hashlib.sha256(contract_raw).hexdigest()
        or not isinstance(auth_record, dict)
        or not isinstance(probe, dict)
        or auth_record.get("sha256") != hashlib.sha256(canonical_auth).hexdigest()
        or auth_record.get("probe") != probe
        or probe.get("base_url") != "http://127.0.0.1:8080"
        or not isinstance(probe.get("nonce"), str)
        or re.fullmatch(r"[0-9a-f]{64}", probe["nonce"]) is None
        or not isinstance(probe.get("expected_user_id"), str)
        or not probe["expected_user_id"]
        or len(probe["expected_user_id"]) > 256
        or not isinstance(plan.get("compose_project"), str)
        or not plan["compose_project"]
        or not isinstance(plan.get("sub2api_network"), str)
        or not plan["sub2api_network"]
    ):
        fail("post-success runtime evidence is not bound to the successful deployment")

    return {
        "format_version": 1,
        "type": "production-post-success-reverse-admission-v1",
        "status": "admitted",
        "admitted_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "trigger_stage": args.trigger_stage,
        "deployment_record": {
            "path": str(deployment_path),
            "sha256": hashlib.sha256(deployment_raw).hexdigest(),
        },
        "reverse_plan": {
            "path": str(reverse_path),
            "sha256": hashlib.sha256(reverse_raw).hexdigest(),
        },
        "application_only": True,
        "database_restore_allowed": False,
        "database_revision": target_revision,
        "compose_project": plan["compose_project"],
        "sub2api_network": plan["sub2api_network"],
        "auth_evidence": {
            "path": str(auth_path),
            "nonce": probe["nonce"],
            "expected_user_id": probe["expected_user_id"],
            "base_url": probe["base_url"],
        },
    }


def bounded_uninstall_plan(args: argparse.Namespace) -> dict[str, Any]:
    record_root = args.record_root
    deployment_directory = args.deployment_directory
    normalized_root = Path(os.path.normpath(str(record_root)))
    normalized_deployment = Path(os.path.normpath(str(deployment_directory)))
    if (
        not record_root.is_absolute()
        or not deployment_directory.is_absolute()
        or record_root != normalized_root
        or deployment_directory != normalized_deployment
        or deployment_directory.parent != record_root
        or re.fullmatch(
            r"deployment-[0-9]{8}T[0-9]{6}Z-[0-9]+", deployment_directory.name
        )
        is None
    ):
        fail("bounded uninstall directory is not one normalized deployment child")
    if (
        re.fullmatch(
            r"lifecycle-uninstall:[0-9]{8}T[0-9]{6}Z-[0-9]+-[0-9]+-"
            r"uninstall-[0-9a-f]{32}",
            args.trigger_stage,
        )
        is None
    ):
        fail("bounded uninstall trigger is not one lifecycle uninstall operation id")
    for path, label in (
        (record_root, "deployment record root"),
        (deployment_directory, "bounded uninstall deployment record directory"),
    ):
        descriptor, _ = open_stable_directory(
            path,
            label,
            expected_uid=args.expected_owner_uid,
            exact_mode=0o700,
        )
        os.close(descriptor)
    for terminal_name in ("uninstall-plan.json", "uninstall-execution.json"):
        terminal_path = deployment_directory / terminal_name
        if terminal_path.exists() or terminal_path.is_symlink():
            fail(f"bounded uninstall terminal evidence already exists: {terminal_name}")

    status_raw = secure_exact_bytes(
        deployment_directory / "status",
        "active deployment terminal status",
        expected_uid=args.expected_owner_uid,
        exact_mode=0o600,
        maximum=1024,
    )
    if status_raw != b"deployed\n":
        fail("bounded uninstall requires one exact deployed terminal status")
    deployment_path = deployment_directory / "deployment.json"
    deployment_raw = secure_exact_bytes(
        deployment_path,
        "active deployment record",
        expected_uid=args.expected_owner_uid,
        exact_mode=0o400,
    )
    deployment = strict_json_bytes(
        deployment_raw, "active deployment record", canonical=True
    )
    if (
        not isinstance(deployment, dict)
        or deployment.get("format_version") != 1
        or deployment.get("status") != "deployed"
    ):
        fail("bounded uninstall requires one supported deployed record")

    release_path = deployment_directory / "release-verification.json"
    release_raw = secure_exact_bytes(
        release_path,
        "active package release verification",
        expected_uid=args.expected_owner_uid,
        exact_mode=0o600,
    )
    release = strict_json_bytes(
        release_raw, "active package release verification", canonical=True
    )
    signed_release = deployment.get("signed_release")
    if (
        not isinstance(release, dict)
        or not isinstance(signed_release, dict)
        or signed_release.get("values") != release
        or signed_release.get("sha256") != hashlib.sha256(release_raw).hexdigest()
    ):
        fail("active package verification is not bound by the deployment record")
    package = release.get("_server_package")
    if not isinstance(package, dict):
        fail("active deployment has no server package identity")

    manifest_path = args.manifest
    receipt_path = args.verification_receipt
    if (
        not manifest_path.is_absolute()
        or not receipt_path.is_absolute()
        or manifest_path.name != "PACKAGE.json"
    ):
        fail("bounded uninstall package evidence paths are invalid")
    package_root_metadata = manifest_path.parent.lstat()
    if (
        stat.S_ISLNK(package_root_metadata.st_mode)
        or not stat.S_ISDIR(package_root_metadata.st_mode)
        or package_root_metadata.st_uid != args.expected_owner_uid
        or stat.S_IMODE(package_root_metadata.st_mode) != 0o555
    ):
        fail("bounded uninstall package root is not immutable and root-owned")
    manifest_raw = secure_exact_bytes(
        manifest_path,
        "active server package manifest",
        expected_uid=args.expected_owner_uid,
        exact_mode=0o444,
    )
    receipt_raw = secure_exact_bytes(
        receipt_path,
        "active server package verification receipt",
        expected_uid=args.expected_owner_uid,
        exact_mode=0o400,
    )
    manifest_sha256 = hashlib.sha256(manifest_raw).hexdigest()
    receipt_sha256 = hashlib.sha256(receipt_raw).hexdigest()
    manifest = strict_json_bytes(
        manifest_raw, "active server package manifest", canonical=True
    )
    if (
        not isinstance(manifest, dict)
        or args.expected_manifest_sha256 != manifest_sha256
        or package.get("manifest_path") != str(manifest_path)
        or package.get("manifest_sha256") != manifest_sha256
        or package.get("verification_receipt_path") != str(receipt_path)
        or package.get("verification_receipt_sha256") != receipt_sha256
        or package.get("mode") != args.mode
        or package.get("docker_host") != LOCAL_DOCKER_HOST
        or release.get("CONTROL_SERVER_PACKAGE_MANIFEST_SHA256") != manifest_sha256
        or release.get("CONTROL_SERVER_PACKAGE_VERIFICATION_RECEIPT_SHA256")
        != receipt_sha256
        or release.get("CONTROL_SERVER_PACKAGE_MODE") != args.mode
        or release.get("CONTROL_SERVER_PACKAGE_DOCKER_HOST") != LOCAL_DOCKER_HOST
        or deployment.get("release") != manifest.get("release")
        or release.get("CONTROL_RELEASE") != manifest.get("release")
    ):
        fail("active lifecycle package does not own this deployment record")

    running = deployment.get("running")
    terminal_containers = running.get("containers") if isinstance(running, dict) else None
    terminal_network = running.get("pwa_network") if isinstance(running, dict) else None
    if (
        not isinstance(terminal_containers, dict)
        or set(terminal_containers) != set(UNINSTALL_SERVICES)
        or not isinstance(terminal_network, dict)
    ):
        fail("active deployment has no exact uninstall runtime identity")
    compose_project = terminal_network.get("compose_project")
    if (
        not isinstance(compose_project, str)
        or re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,62}", compose_project) is None
    ):
        fail("active deployment has no valid Compose project identity")

    project_inspect_raw = secure_exact_bytes(
        args.project_containers_inspect,
        "bounded uninstall project container inspection",
        expected_uid=args.expected_owner_uid,
        exact_mode=0o600,
    )
    project_inspect = strict_json_bytes(
        project_inspect_raw, "bounded uninstall project container inspection"
    )
    if (
        not isinstance(project_inspect, list)
        or len(project_inspect) != len(UNINSTALL_SERVICES)
        or any(not isinstance(item, dict) for item in project_inspect)
    ):
        fail("bounded uninstall requires exactly three active project containers")
    live_by_service: dict[str, dict[str, Any]] = {}
    observed_ids: set[str] = set()
    for container in project_inspect:
        config = container.get("Config")
        labels = config.get("Labels") if isinstance(config, dict) else None
        service = labels.get("com.docker.compose.service") if isinstance(labels, dict) else None
        container_id = container.get("Id")
        container_name = container.get("Name")
        if (
            service not in UNINSTALL_SERVICES
            or service in live_by_service
            or not isinstance(labels, dict)
            or labels.get("com.docker.compose.project") != compose_project
            or labels.get("com.docker.compose.oneoff") != "False"
            or labels.get("com.docker.compose.container-number") != "1"
            or labels.get("com.docker.compose.project.config_files")
            != str(deployment_directory / "compose-config.json")
            or not all(
                isinstance(key, str) and isinstance(value, str)
                for key, value in labels.items()
            )
            or not isinstance(container_id, str)
            or CONTAINER_ID_RE.fullmatch(container_id) is None
            or container_id in observed_ids
            or not isinstance(container_name, str)
            or not container_name.startswith("/")
            or len(container_name) > 256
        ):
            fail("bounded uninstall found an unowned or duplicate project container")
        live_by_service[service] = container
        observed_ids.add(container_id)
    if set(live_by_service) != set(UNINSTALL_SERVICES):
        fail("bounded uninstall project container set is incomplete")

    container_targets: dict[str, dict[str, Any]] = {}
    for service in UNINSTALL_SERVICES:
        terminal = exact_keys(
            terminal_containers.get(service),
            {
                "container_id",
                "container_name",
                "image_id",
                "health",
                "network",
                "published_port",
                "compose_project",
                "compose_service",
                "compose_oneoff",
                "labels",
            },
            f"active deployment terminal identity for {service}",
        )
        live = live_by_service[service]
        state = live.get("State")
        health = state.get("Health") if isinstance(state, dict) else None
        host_config = live.get("HostConfig")
        network_settings = live.get("NetworkSettings")
        networks = (
            network_settings.get("Networks")
            if isinstance(network_settings, dict)
            else None
        )
        expected_network = terminal.get("network")
        expected_port_bindings = {
            ("8080/tcp" if service == "codex-pwa" else "8090/tcp"): [
                {"HostIp": "127.0.0.1", "HostPort": terminal.get("published_port")}
            ]
        }
        if (
            terminal.get("container_id") != live.get("Id")
            or terminal.get("container_name") != live.get("Name")
            or terminal.get("image_id") != live.get("Image")
            or not isinstance(state, dict)
            or state.get("Running") is not True
            or not isinstance(health, dict)
            or health.get("Status") != terminal.get("health")
            or terminal.get("health") != "healthy"
            or not isinstance(host_config, dict)
            or host_config.get("PortBindings") != expected_port_bindings
            or not isinstance(networks, dict)
            or set(networks) != {expected_network}
            or terminal.get("compose_project") != compose_project
            or terminal.get("compose_service") != service
            or terminal.get("compose_oneoff") is not False
            or terminal.get("labels") != live.get("Config", {}).get("Labels")
        ):
            fail(f"bounded uninstall runtime drifted for {service}")
        container_targets[service] = {
            "container_id": live["Id"],
            "container_name": live["Name"],
            "image_id": live["Image"],
            "compose_project": compose_project,
            "compose_service": service,
            "compose_oneoff": False,
            "network": expected_network,
            "labels": dict(live["Config"]["Labels"]),
        }

    network = require_pwa_network_inspect(
        args.pwa_network_inspect,
        expected_name=terminal_network.get("name"),
        expected_project=compose_project,
        pwa_container=live_by_service["codex-pwa"],
    )
    if network != terminal_network:
        fail("bounded uninstall PWA network differs from terminal deployment evidence")
    pwa_network_inspect = strict_json_bytes(
        secure_exact_bytes(
            args.pwa_network_inspect,
            "bounded uninstall PWA network inspection",
            expected_uid=args.expected_owner_uid,
            exact_mode=0o600,
        ),
        "bounded uninstall PWA network inspection",
    )
    network_labels = pwa_network_inspect[0].get("Labels")
    if not isinstance(network_labels, dict) or not all(
        isinstance(key, str) and isinstance(value, str)
        for key, value in network_labels.items()
    ):
        fail("bounded uninstall PWA network has invalid full labels")

    return {
        "format_version": 1,
        "type": "production-bounded-uninstall-plan-v1",
        "status": "admitted",
        "admitted_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "trigger_stage": args.trigger_stage,
        "deployment_record": {
            "path": str(deployment_path),
            "sha256": hashlib.sha256(deployment_raw).hexdigest(),
        },
        "active_package": {
            "manifest_path": str(manifest_path),
            "manifest_sha256": manifest_sha256,
            "verification_receipt_path": str(receipt_path),
            "verification_receipt_sha256": receipt_sha256,
            "mode": args.mode,
            "release": manifest["release"],
            "release_tag": manifest["release_tag"],
        },
        "compose_project": compose_project,
        "targets": {
            "containers": container_targets,
            "pwa_network": {
                **network,
                "compose_network": "pwa-network",
                "labels": dict(network_labels),
                "member_container_ids": [network["container_id"]],
            },
        },
        "limits": {
            "max_attempts_per_step": 1,
            "total_timeout_seconds": 240,
            "container_stop_timeout_seconds": 30,
            "container_remove_timeout_seconds": 15,
            "network_remove_timeout_seconds": 30,
            "exact_ids_required": True,
            "drift_fail_closed": True,
        },
        "one_off_containers_absent": True,
        "preserved": dict(UNINSTALL_PRESERVED_RESOURCES),
    }


def bounded_uninstall_execution(args: argparse.Namespace) -> dict[str, Any]:
    plan_raw = secure_exact_bytes(
        args.plan,
        "bounded uninstall plan",
        expected_uid=args.expected_owner_uid,
        exact_mode=0o400,
    )
    plan = strict_json_bytes(plan_raw, "bounded uninstall plan", canonical=True)
    if not isinstance(plan, dict):
        fail("bounded uninstall plan must be an object")
    deployment_record = plan.get("deployment_record")
    targets = plan.get("targets")
    containers = targets.get("containers") if isinstance(targets, dict) else None
    network = targets.get("pwa_network") if isinstance(targets, dict) else None
    limits = plan.get("limits")
    if (
        plan.get("format_version") != 1
        or plan.get("type") != "production-bounded-uninstall-plan-v1"
        or plan.get("status") != "admitted"
        or plan.get("trigger_stage") != args.trigger_stage
        or not isinstance(deployment_record, dict)
        or not isinstance(containers, dict)
        or set(containers) != set(UNINSTALL_SERVICES)
        or not isinstance(network, dict)
        or not isinstance(limits, dict)
        or limits.get("max_attempts_per_step") != 1
        or limits.get("total_timeout_seconds") != 240
        or limits.get("container_stop_timeout_seconds") != 30
        or limits.get("container_remove_timeout_seconds") != 15
        or limits.get("network_remove_timeout_seconds") != 30
        or limits.get("exact_ids_required") is not True
        or limits.get("drift_fail_closed") is not True
        or plan.get("one_off_containers_absent") is not True
        or plan.get("preserved") != UNINSTALL_PRESERVED_RESOURCES
        or args.project_containers_absent is not True
        or args.pwa_network_absent is not True
    ):
        fail("bounded uninstall execution does not satisfy its admitted plan")
    deployment_path = Path(deployment_record.get("path", ""))
    if not deployment_path.is_absolute():
        fail("bounded uninstall plan has no absolute deployment record")
    deployment_raw = secure_exact_bytes(
        deployment_path,
        "bounded uninstall deployment record",
        expected_uid=args.expected_owner_uid,
        exact_mode=0o400,
    )
    if deployment_record.get("sha256") != hashlib.sha256(deployment_raw).hexdigest():
        fail("bounded uninstall deployment record changed after admission")

    empty_network_raw = secure_exact_bytes(
        args.empty_network_inspect,
        "bounded uninstall empty PWA network inspection",
        expected_uid=args.expected_owner_uid,
        exact_mode=0o600,
    )
    empty_network_value = strict_json_bytes(
        empty_network_raw, "bounded uninstall empty PWA network inspection"
    )
    if (
        not isinstance(empty_network_value, list)
        or len(empty_network_value) != 1
        or not isinstance(empty_network_value[0], dict)
        or empty_network_value[0].get("Id") != network.get("network_id")
        or empty_network_value[0].get("Name") != network.get("name")
        or empty_network_value[0].get("Labels") != network.get("labels")
        or empty_network_value[0].get("Containers") != {}
    ):
        fail("bounded uninstall did not prove the exact PWA network was empty")

    removed_containers = [
        {
            "service": service,
            "container_id": containers[service]["container_id"],
            "container_name": containers[service]["container_name"],
            "image_id": containers[service]["image_id"],
            "compose_project": containers[service]["compose_project"],
            "compose_service": containers[service]["compose_service"],
            "compose_oneoff": containers[service]["compose_oneoff"],
            "network": containers[service]["network"],
            "labels": dict(containers[service]["labels"]),
        }
        for service in UNINSTALL_SERVICES
    ]
    return {
        "format_version": 1,
        "type": "production-bounded-uninstall-execution-v1",
        "status": "succeeded",
        "trigger_stage": args.trigger_stage,
        "uninstall_plan_path": str(args.plan),
        "uninstall_plan_sha256": hashlib.sha256(plan_raw).hexdigest(),
        "deployment_record": dict(deployment_record),
        "active_package": dict(plan["active_package"]),
        "removed": {
            "containers": removed_containers,
            "pwa_network": {
                "network_id": network["network_id"],
                "name": network["name"],
                "labels": dict(network["labels"]),
                "member_container_ids_at_admission": list(
                    network["member_container_ids"]
                ),
                "members_after_container_removal": [],
            },
        },
        "network_empty_evidence": {
            "path": str(args.empty_network_inspect),
            "sha256": hashlib.sha256(empty_network_raw).hexdigest(),
        },
        "postconditions": {
            "project_containers_absent": True,
            "one_off_containers_absent": True,
            "pwa_network_zero_members_before_removal": True,
            "pwa_network_absent": True,
        },
        "preserved": dict(UNINSTALL_PRESERVED_RESOURCES),
        "bounded": True,
        "max_attempts_per_step": 1,
        "completed_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
    }


def copy_to_private_destination(
    args: argparse.Namespace,
    *,
    exact_source_mode: int | None,
    forbidden_source_mode: int,
    expected_sha256: str | None,
    require_single_link: bool,
) -> dict[str, Any]:
    if not args.source.is_absolute() or not args.destination.is_absolute():
        fail("private input source and destination must be absolute")
    source_descriptor, source_metadata = open_stable_regular_file(
        args.source,
        args.label,
        expected_uid=os.geteuid(),
        exact_mode=exact_source_mode,
        max_size=args.max_bytes,
    )
    destination_parent_descriptor = -1
    destination_descriptor = -1
    created = False
    copy_succeeded = False
    try:
        if require_single_link and source_metadata.st_nlink != 1:
            fail(f"{args.label} must have exactly one hard link")
        if stat.S_IMODE(source_metadata.st_mode) & forbidden_source_mode:
            fail(f"{args.label} is writable by an untrusted group or user")
        content = read_descriptor(source_descriptor, args.label, args.max_bytes)
        if not content or b"\x00" in content:
            fail(f"{args.label} is empty or contains NUL bytes")
        assert_stable(source_descriptor, source_metadata, args.label)
        source_sha256 = hashlib.sha256(content).hexdigest()
        if expected_sha256 is not None and source_sha256 != expected_sha256:
            fail(f"{args.label} differs from its admitted SHA-256")
        destination_parent_descriptor, _ = open_stable_directory(
            args.destination.parent,
            "private input destination directory",
            expected_uid=os.geteuid(),
            exact_mode=0o700,
        )
        flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        destination_descriptor = os.open(
            args.destination.name,
            flags,
            0o600,
            dir_fd=destination_parent_descriptor,
        )
        created = True
        view = memoryview(content)
        while view:
            written = os.write(destination_descriptor, view)
            if written <= 0:
                fail(f"could not write private copy of {args.label}")
            view = view[written:]
        os.fsync(destination_descriptor)
        os.fsync(destination_parent_descriptor)
        assert_stable(source_descriptor, source_metadata, args.label)
        copy_succeeded = True
    except OSError as exc:
        fail(f"cannot securely copy {args.label}: {exc}")
    finally:
        if destination_descriptor >= 0:
            os.close(destination_descriptor)
        if created and not copy_succeeded:
            try:
                os.unlink(args.destination.name, dir_fd=destination_parent_descriptor)
            except OSError:
                pass
        if destination_parent_descriptor >= 0:
            os.close(destination_parent_descriptor)
        os.close(source_descriptor)
    return {
        "format_version": 1,
        "source_sha256": source_sha256,
        "size": len(content),
        "destination": str(args.destination),
    }


def copy_private_file(args: argparse.Namespace) -> dict[str, Any]:
    return copy_to_private_destination(
        args,
        exact_source_mode=0o600,
        forbidden_source_mode=0,
        expected_sha256=None,
        require_single_link=False,
    )


def copy_admitted_file(args: argparse.Namespace) -> dict[str, Any]:
    if not SHA256_RE.fullmatch(args.expected_sha256):
        fail("admitted file SHA-256 must be 64 lowercase hexadecimal characters")
    return copy_to_private_destination(
        args,
        exact_source_mode=None,
        forbidden_source_mode=0o022,
        expected_sha256=args.expected_sha256,
        require_single_link=True,
    )


def backup_evidence(args: argparse.Namespace) -> dict[str, Any]:
    directory = args.directory
    if not directory.is_absolute():
        fail("backup directory must be absolute")
    directory_descriptor, directory_metadata = open_stable_directory(
        directory,
        "backup directory",
        expected_uid=args.expected_owner_uid,
        exact_mode=0o700,
    )
    descriptors: list[int] = []
    try:
        now = datetime.now(UTC).timestamp()
        candidates: list[tuple[str, int, os.stat_result]] = []
        for name in os.listdir(directory_descriptor):
            if re.fullmatch(r"codex-control-[0-9A-Za-zT_-]+\.dump", name) is None:
                continue
            path = directory / name
            descriptor, metadata = open_stable_regular_file_at(
                directory_descriptor,
                name,
                f"backup dump {path}",
                expected_uid=args.expected_owner_uid,
                exact_mode=0o600,
            )
            descriptors.append(descriptor)
            if metadata.st_mtime >= args.not_before:
                candidates.append((name, descriptor, metadata))
        if len(candidates) != 1:
            fail(f"expected exactly one new backup dump, observed {len(candidates)}")
        dump_name, dump_descriptor, dump_metadata = candidates[0]
        dump = directory / dump_name
        if dump_metadata.st_mtime > now + 60:
            fail("backup dump modification time is in the future")
        if now - dump_metadata.st_mtime > args.max_age_seconds:
            fail("backup dump is stale")

        stem = dump_name.removesuffix(".dump")
        manifest_name = f"{stem}.contents.txt"
        checksum_name = f"{stem}.sha256"
        manifest = directory / manifest_name
        checksum = directory / checksum_name
        manifest_descriptor, manifest_metadata = open_stable_regular_file_at(
            directory_descriptor,
            manifest_name,
            "backup manifest",
            expected_uid=args.expected_owner_uid,
            exact_mode=0o600,
            max_size=MAX_BACKUP_METADATA_BYTES,
        )
        descriptors.append(manifest_descriptor)
        checksum_descriptor, checksum_metadata = open_stable_regular_file_at(
            directory_descriptor,
            checksum_name,
            "backup checksum",
            expected_uid=args.expected_owner_uid,
            exact_mode=0o600,
            max_size=1024,
        )
        descriptors.append(checksum_descriptor)
        for label, metadata in (
            ("manifest", manifest_metadata),
            ("checksum", checksum_metadata),
        ):
            if metadata.st_mtime < args.not_before or metadata.st_mtime > now + 60:
                fail(f"backup {label} was not created in this admission window")

        try:
            checksum_lines = (
                read_descriptor(checksum_descriptor, "backup checksum", 1024)
                .decode("ascii")
                .splitlines()
            )
        except UnicodeDecodeError as exc:
            fail(f"backup checksum is not ASCII: {exc}")
        if len(checksum_lines) != 1:
            fail("backup checksum file must contain exactly one line")
        match = re.fullmatch(r"([0-9a-f]{64})  ([^/\s]+)", checksum_lines[0])
        if match is None or match.group(2) != dump_name:
            fail("backup checksum line has an invalid digest or filename")
        observed_sha256 = hash_descriptor(dump_descriptor)
        if observed_sha256 != match.group(1):
            fail("backup dump checksum mismatch")

        descriptor_root = (
            Path("/proc/self/fd") if Path("/proc/self/fd").is_dir() else Path("/dev/fd")
        )
        os.lseek(dump_descriptor, 0, os.SEEK_SET)
        with tempfile.TemporaryFile() as error_output:
            try:
                process = subprocess.Popen(
                    [
                        str(args.pg_restore),
                        "--list",
                        str(descriptor_root / str(dump_descriptor)),
                    ],
                    stdout=subprocess.PIPE,
                    stderr=error_output,
                    pass_fds=(dump_descriptor,),
                )
            except OSError as exc:
                fail(f"pg_restore could not start: {exc}")
            assert process.stdout is not None
            recreated_manifest = bytearray()
            while len(recreated_manifest) <= MAX_BACKUP_METADATA_BYTES:
                chunk = process.stdout.read(
                    min(
                        131_072,
                        MAX_BACKUP_METADATA_BYTES + 1 - len(recreated_manifest),
                    )
                )
                if not chunk:
                    break
                recreated_manifest.extend(chunk)
            if len(recreated_manifest) > MAX_BACKUP_METADATA_BYTES:
                process.kill()
                process.wait()
                fail("pg_restore manifest exceeds the admission size limit")
            return_code = process.wait()
            if return_code != 0:
                error_output.seek(0)
                error_text = error_output.read(4096).decode("utf-8", errors="replace")
                fail(f"pg_restore could not parse the new backup: {error_text.strip()}")

        stored_manifest = read_descriptor(
            manifest_descriptor, "backup manifest", MAX_BACKUP_METADATA_BYTES
        )
        if not stored_manifest or bytes(recreated_manifest) != stored_manifest:
            fail("stored backup manifest differs from pg_restore --list output")

        for descriptor, metadata, label in (
            (dump_descriptor, dump_metadata, "backup dump"),
            (manifest_descriptor, manifest_metadata, "backup manifest"),
            (checksum_descriptor, checksum_metadata, "backup checksum"),
        ):
            assert_stable(descriptor, metadata, label)
        assert_stable(directory_descriptor, directory_metadata, "backup directory")

        return {
            "format_version": 1,
            "verified_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            "dump_path": str(dump),
            "dump_sha256": observed_sha256,
            "dump_size": dump_metadata.st_size,
            "dump_mtime": datetime.fromtimestamp(dump_metadata.st_mtime, UTC)
            .isoformat()
            .replace("+00:00", "Z"),
            "manifest_path": str(manifest),
            "manifest_sha256": hashlib.sha256(stored_manifest).hexdigest(),
            "checksum_path": str(checksum),
            "owner_uid": args.expected_owner_uid,
        }
    finally:
        for descriptor in descriptors:
            os.close(descriptor)
        os.close(directory_descriptor)


def normalize_revision(value: str, label: str) -> str:
    lines = [line.strip() for line in value.splitlines() if line.strip()]
    candidates: list[str] = []
    for line in lines:
        token = line.split(maxsplit=1)[0]
        if REVISION_RE.fullmatch(token):
            candidates.append(token)
    candidates = list(dict.fromkeys(candidates))
    if len(candidates) != 1:
        fail(f"{label} did not contain exactly one migration revision")
    return candidates[0]


def revisions(args: argparse.Namespace) -> dict[str, Any]:
    current = normalize_revision(
        secure_text_file(args.current, "alembic current"), "alembic current"
    )
    head = normalize_revision(
        secure_text_file(args.head, "alembic heads"), "alembic heads"
    )
    if args.plan is not None:
        plan = load_json(args.plan, "deployment plan")
        if not isinstance(plan, dict) or plan.get("signed_migration_head") != head:
            fail("packaged Alembic head differs from the signed release migration head")
    if args.require_current_head and current != head:
        fail("database revision does not match the admitted migration head")
    return {"source_database_revision": current, "target_migration_head": head}


def load_private_evidence(path: Path, label: str) -> tuple[dict[str, Any], str, int]:
    descriptor, metadata = open_stable_regular_file(
        path,
        label,
        expected_uid=os.geteuid(),
        exact_mode=0o600,
        max_size=MAX_JSON_INPUT_BYTES,
    )
    try:
        raw = read_descriptor(descriptor, label, MAX_JSON_INPUT_BYTES)
        digest = hashlib.sha256(raw).hexdigest()
        assert_stable(descriptor, metadata, label)
    finally:
        os.close(descriptor)
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        fail(f"{label} is not valid JSON")
    if not isinstance(value, dict):
        fail(f"{label} is not an object")
    return value, digest, metadata.st_size


def receipt_timestamp(value: Any, label: str, maximum_age: int) -> str:
    if not isinstance(value, str) or not value.endswith("Z"):
        fail(f"{label} has no UTC completion timestamp")
    try:
        parsed = datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except ValueError:
        fail(f"{label} completion timestamp is invalid")
    age = (datetime.now(UTC) - parsed).total_seconds()
    if age < -60 or age > maximum_age:
        fail(f"{label} is not fresh for this deployment admission")
    return value


def current_control_evidence(
    path: Path,
) -> tuple[dict[str, dict[str, Any]], str, int]:
    descriptor, metadata = open_stable_regular_file(
        path,
        "current Control container inspection",
        expected_uid=os.geteuid(),
        exact_mode=0o600,
        max_size=MAX_JSON_INPUT_BYTES,
    )
    try:
        raw = read_descriptor(descriptor, "current Control container inspection", MAX_JSON_INPUT_BYTES)
        digest = hashlib.sha256(raw).hexdigest()
        assert_stable(descriptor, metadata, "current Control container inspection")
    finally:
        os.close(descriptor)
    value = strict_json_bytes(raw, "current Control container inspection")
    if not isinstance(value, list):
        fail("current Control container inspection is not an array")
    allowed = {"control-api", "control-api-replica", "codex-pwa"}
    identities: dict[str, dict[str, Any]] = {}
    for container in value:
        if not isinstance(container, dict):
            fail("current Control container inspection contains a non-object")
        config = container.get("Config")
        labels = config.get("Labels") if isinstance(config, dict) else None
        service_name = (
            labels.get("com.docker.compose.service") if isinstance(labels, dict) else None
        )
        state = container.get("State")
        identity = {
            "container_id": container.get("Id"),
            "image_id": container.get("Image"),
            "running": state.get("Running") if isinstance(state, dict) else None,
            "started_at": state.get("StartedAt") if isinstance(state, dict) else None,
            "restart_count": container.get("RestartCount"),
        }
        if (
            service_name not in allowed
            or service_name in identities
            or not isinstance(identity["container_id"], str)
            or CONTAINER_ID_RE.fullmatch(identity["container_id"]) is None
            or not isinstance(identity["image_id"], str)
            or IMAGE_ID_RE.fullmatch(identity["image_id"]) is None
            or type(identity["running"]) is not bool
            or not isinstance(identity["started_at"], str)
            or not identity["started_at"]
            or type(identity["restart_count"]) is not int
            or identity["restart_count"] < 0
        ):
            fail("current Control container identity is invalid")
        identities[service_name] = identity
    return identities, digest, metadata.st_size


def expected_writer_steps(
    current: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    return [
        {
            "ordinal": ordinal,
            "action": (
                "require-absent"
                if previous is None
                else (
                    "start-exact-prior-container"
                    if previous["running"]
                    else "keep-exact-prior-container-stopped"
                )
            ),
            "service": service_name,
            "previous": previous,
            "max_attempts": 1,
            "timeout_seconds": 60,
        }
        for ordinal, service_name in enumerate(WRITER_SERVICES, start=1)
        for previous in (current.get(service_name),)
    ]


def validate_stopped_writer_evidence(
    current: dict[str, dict[str, Any]],
    observed: dict[str, dict[str, Any]],
    label: str,
) -> None:
    if set(observed) - set(WRITER_SERVICES):
        fail(f"{label} contains a non-writer service")
    for service_name in WRITER_SERVICES:
        previous = current.get(service_name)
        stopped = observed.get(service_name)
        if previous is None:
            if stopped is not None:
                fail(f"{label} created a previously absent writer")
            continue
        if (
            stopped is None
            or stopped.get("container_id") != previous.get("container_id")
            or stopped.get("image_id") != previous.get("image_id")
            or stopped.get("running") is not False
            or stopped.get("started_at") != previous.get("started_at")
            or stopped.get("restart_count") != previous.get("restart_count")
        ):
            fail(f"{label} does not preserve one exact stopped writer identity")


def recovery_chain(args: argparse.Namespace, plan: dict[str, Any]) -> dict[str, Any]:
    full_backup, full_backup_sha, full_backup_size = load_private_evidence(
        args.full_backup, "full production backup admission"
    )
    if (
        full_backup.get("status") != "admitted"
        or full_backup.get("fresh") is not True
        or full_backup.get("admission_mode") != "fresh-production-backup"
        or full_backup.get("owner_uid") != os.geteuid()
    ):
        fail("normal deployment requires one fresh root-owned full backup admission")
    receipt_timestamp(
        full_backup.get("backup_created_at"),
        "full production backup",
        args.recovery_max_age_seconds,
    )
    artifacts = full_backup.get("artifacts")
    required_backup_artifacts = {
        "sub2api-postgres.dump",
        "postgres-additional-databases.json",
        "redis-logical.rdb",
        "release-records.tar.gz",
        "release-records-inventory.json",
        "release-evidence-inventory.json",
        "docker-network-inspect.json",
        "docker-networks.json",
    }
    if not isinstance(artifacts, dict) or not required_backup_artifacts.issubset(artifacts):
        fail("full production backup omits release-record or network recovery metadata")
    restore, restore_sha, restore_size = load_private_evidence(
        args.restore_receipt, "isolated restore receipt"
    )
    isolation, isolation_sha, isolation_size = load_private_evidence(
        args.isolation_receipt, "live datastore isolation receipt"
    )
    unfreeze, unfreeze_sha, unfreeze_size = load_private_evidence(
        args.writer_unfreeze_plan, "writer unfreeze plan"
    )
    freeze, freeze_sha, freeze_size = load_private_evidence(
        args.writer_freeze_receipt, "writer freeze receipt"
    )
    reverse_plan, reverse_plan_sha, reverse_plan_size = load_private_evidence(
        args.reverse_plan, "bounded reverse plan"
    )
    releases, releases_sha, _ = load_private_evidence(
        args.releases, "release image evidence"
    )
    revisions_value, revisions_sha, _ = load_private_evidence(
        args.revisions, "migration revision evidence"
    )
    premigration, premigration_sha, _ = load_private_evidence(
        args.backup, "pre-migration backup evidence"
    )
    rollback_compose, rollback_compose_sha, rollback_compose_size = load_private_evidence(
        args.rollback_compose, "rollback Compose snapshot"
    )
    current, current_sha, current_size = current_control_evidence(
        args.current_control_containers
    )
    stopped_before, stopped_before_sha, stopped_before_size = current_control_evidence(
        args.writers_stopped_before_backup
    )
    stopped_after, stopped_after_sha, stopped_after_size = current_control_evidence(
        args.writers_stopped_after_backup
    )
    plan_sha = secure_file_sha256(args.plan, "deployment plan")
    if (
        restore.get("format_version") != 1
        or restore.get("type") != "production-isolated-restore-v1"
        or restore.get("status") != "succeeded"
        or restore.get("backup_admission_sha256") != full_backup_sha
        or restore.get("backup_receipt_sha256") != full_backup.get("receipt_sha256")
        or restore.get("snapshot_manifest_sha256") != full_backup.get("manifest_sha256")
        or restore.get("isolation", {}).get("docker_network_mode") != "none"
        or restore.get("isolation", {}).get("published_ports") != 0
        or restore.get("isolation", {}).get("temporary_containers_removed") is not True
        or restore.get("postgresql", {}).get("restore_completed") is not True
        or restore.get("redis", {}).get("restore_completed") is not True
    ):
        fail("isolated restore receipt is incomplete or belongs to another backup")
    receipt_timestamp(
        restore.get("completed_at"), "isolated restore receipt", args.recovery_max_age_seconds
    )
    postgres_isolation = isolation.get("postgresql")
    redis_isolation = isolation.get("redis")
    if (
        isolation.get("format_version") != 1
        or isolation.get("type") != "production-datastore-isolation-v1"
        or isolation.get("status") != "passed"
        or isolation.get("deployment_plan_sha256") != plan_sha
        or isolation.get("backup_admission_sha256") != full_backup_sha
        or isolation.get("backup_receipt_sha256") != full_backup.get("receipt_sha256")
        or isolation.get("snapshot_manifest_sha256") != full_backup.get("manifest_sha256")
        or not isinstance(postgres_isolation, dict)
        or any(
            postgres_isolation.get(key) is not True
            for key in (
                "role_flags_exact",
                "database_owner_exact",
                "schema_and_object_owners_exact",
                "public_connect_revoked",
                "control_to_sub2api_connect_denied",
                "control_positive_connection",
            )
        )
        or postgres_isolation.get("membership_count") != 0
        or not isinstance(redis_isolation, dict)
        or any(
            redis_isolation.get(key) is not True
            for key in (
                "authenticated",
                "acl_exact",
                "aclfile_configured",
                "anonymous_access_denied",
                "enabled_nopass_users_absent",
                "inside_prefix_read_write_passed",
                "outside_prefix_read_denied",
                "outside_prefix_write_denied",
                "inside_channel_publish_passed",
                "outside_channel_publish_denied",
                "administrative_command_denied",
            )
        )
    ):
        fail("live datastore isolation receipt is incomplete or belongs to another plan")
    receipt_timestamp(
        isolation.get("completed_at"),
        "live datastore isolation receipt",
        args.recovery_max_age_seconds,
    )
    expected_unfreeze_steps = expected_writer_steps(current)
    unfreeze_limits = unfreeze.get("limits")
    if (
        unfreeze.get("format_version") != 1
        or unfreeze.get("type") != WRITER_UNFREEZE_PLAN_TYPE
        or unfreeze.get("status") != "admitted"
        or not isinstance(unfreeze_limits, dict)
        or unfreeze_limits.get("max_steps") != len(WRITER_SERVICES)
        or unfreeze_limits.get("max_attempts_per_step") != 1
        or unfreeze_limits.get("post_unfreeze_verification_timeout_seconds")
        != POST_UNFREEZE_VERIFY_TIMEOUT_SECONDS
        or not isinstance(unfreeze_limits.get("total_timeout_seconds"), int)
        or unfreeze_limits["total_timeout_seconds"]
        != sum(step["timeout_seconds"] for step in expected_unfreeze_steps)
        + POST_UNFREEZE_VERIFY_TIMEOUT_SECONDS
        or unfreeze_limits.get("database_restore_allowed") is not False
        or unfreeze_limits.get("exact_container_ids_required") is not True
        or unfreeze.get("bindings", {}).get("current_control_containers_sha256")
        != current_sha
        or unfreeze.get("steps") != expected_unfreeze_steps
    ):
        fail("writer unfreeze plan is not bound to the exact prior container IDs")
    receipt_timestamp(
        unfreeze.get("created_at"),
        "writer unfreeze plan",
        args.recovery_max_age_seconds,
    )
    validate_stopped_writer_evidence(current, stopped_before, "pre-backup writer freeze")
    validate_stopped_writer_evidence(current, stopped_after, "post-backup writer freeze")
    if stopped_before != stopped_after:
        fail("one Control writer changed during the final pre-migration backup")
    expected_freeze_writers = {
        service_name: {
            "previous": current.get(service_name),
            "stopped": stopped_after.get(service_name),
        }
        for service_name in WRITER_SERVICES
    }
    if (
        freeze.get("format_version") != 1
        or freeze.get("type") != WRITER_FREEZE_TYPE
        or freeze.get("status") != "passed"
        or freeze.get("bindings")
        != {
            "current_control_containers_sha256": current_sha,
            "unfreeze_plan_sha256": unfreeze_sha,
            "stopped_before_backup_sha256": stopped_before_sha,
            "stopped_after_backup_sha256": stopped_after_sha,
        }
        or freeze.get("no_write_window")
        != {
            "all_writers_stopped": True,
            "container_restart_observed": False,
            "exact_container_ids_preserved": True,
        }
        or freeze.get("writers") != expected_freeze_writers
    ):
        fail("writer freeze receipt does not prove the final backup no-write window")
    receipt_timestamp(
        freeze.get("completed_at"),
        "writer freeze receipt",
        args.recovery_max_age_seconds,
    )
    expected_migration_required = (
        revisions_value.get("source_database_revision")
        != revisions_value.get("target_migration_head")
    )
    limits = reverse_plan.get("limits")
    bindings = reverse_plan.get("bindings")
    forward_steps = reverse_plan.get("forward_steps")
    reverse_steps = reverse_plan.get("reverse_steps")
    if (
        reverse_plan.get("format_version") != 1
        or reverse_plan.get("type") != "production-bounded-reverse-plan-v1"
        or reverse_plan.get("status") != "admitted"
        or not isinstance(limits, dict)
        or limits.get("automatic_reverse_on_failure") is not True
        or limits.get("database_restore_requires_write_freeze") is not True
        or limits.get("database_restore_policy")
        != "only-before-writer-exposure-after-observed-mutation"
        or limits.get("writer_exposure_after_database_mutation_allowed") is not False
        or limits.get("application_reverse_preserves_database") is not True
        or limits.get("migration_required") is not expected_migration_required
        or limits.get("post_reverse_verification_timeout_seconds")
        != POST_REVERSE_VERIFY_TIMEOUT_SECONDS
        or limits.get("max_attempts_per_step") != 1
        or not isinstance(limits.get("max_reverse_steps"), int)
        or not 1 <= limits["max_reverse_steps"] <= 8
        or not isinstance(limits.get("total_timeout_seconds"), int)
        or not 1 <= limits["total_timeout_seconds"] <= 900
        or not isinstance(bindings, dict)
        or bindings.get("deployment_plan_sha256") != plan_sha
        or bindings.get("release_images_sha256")
        != releases_sha
        or bindings.get("revisions_sha256")
        != revisions_sha
        or bindings.get("premigration_backup_sha256")
        != premigration_sha
        or bindings.get("full_backup_admission_sha256") != full_backup_sha
        or bindings.get("isolated_restore_receipt_sha256") != restore_sha
        or bindings.get("datastore_isolation_receipt_sha256") != isolation_sha
        or bindings.get("writer_unfreeze_plan_sha256") != unfreeze_sha
        or bindings.get("writer_freeze_receipt_sha256") != freeze_sha
        or bindings.get("current_control_containers_sha256") != current_sha
        or bindings.get("rollback_compose_sha256")
        != rollback_compose_sha
        or not isinstance(forward_steps, list)
        or len(forward_steps) != 4
        or not isinstance(reverse_steps, list)
        or not 1 <= len(reverse_steps) <= limits["max_reverse_steps"]
        or [step.get("ordinal") for step in forward_steps if isinstance(step, dict)]
        != list(range(1, len(forward_steps) + 1))
        or [step.get("ordinal") for step in reverse_steps if isinstance(step, dict)]
        != list(range(1, len(reverse_steps) + 1))
    ):
        fail("bounded reverse plan is incomplete or belongs to another admission")
    try:
        api_image_id = releases["api"]["image_id"]
        pwa_image_id = releases["pwa"]["image_id"]
        source_revision = revisions_value["source_database_revision"]
        target_revision = revisions_value["target_migration_head"]
        dump_path = premigration["dump_path"]
        dump_sha256 = premigration["dump_sha256"]
    except (KeyError, TypeError):
        fail("bounded reverse plan evidence has no exact release or database identity")
    if (
        not isinstance(api_image_id, str)
        or IMAGE_ID_RE.fullmatch(api_image_id) is None
        or not isinstance(pwa_image_id, str)
        or IMAGE_ID_RE.fullmatch(pwa_image_id) is None
        or not isinstance(source_revision, str)
        or not isinstance(target_revision, str)
        or not isinstance(dump_path, str)
        or not Path(dump_path).is_absolute()
        or not isinstance(dump_sha256, str)
        or SHA256_RE.fullmatch(dump_sha256) is None
    ):
        fail("bounded reverse plan evidence contains an invalid exact identity")
    expected_forward = [
        {
            "ordinal": 1,
            "action": "apply-admitted-migration",
            "from_revision": source_revision,
            "to_revision": target_revision,
            "timeout_seconds": 180,
        },
        {
            "ordinal": 2,
            "action": "recreate-one-service",
            "service": "control-api-replica",
            "new_image_id": api_image_id,
            "timeout_seconds": 120,
        },
        {
            "ordinal": 3,
            "action": "recreate-one-service",
            "service": "control-api",
            "new_image_id": api_image_id,
            "timeout_seconds": 120,
        },
        {
            "ordinal": 4,
            "action": "recreate-one-service",
            "service": "codex-pwa",
            "new_image_id": pwa_image_id,
            "timeout_seconds": 120,
        },
    ]
    expected_reverse: list[dict[str, Any]] = [
        {
            "ordinal": 1,
            "action": "stop-database-mutators",
            "services": ["control-api", "control-api-replica", "control-migrate"],
            "max_attempts": 1,
            "timeout_seconds": 105,
        },
        {
            "ordinal": 2,
            "action": "restore-control-database-from-premigration-dump",
            "max_attempts": 1,
            "timeout_seconds": 360,
            "write_freeze_required": True,
            "condition": "database-mutated-and-writers-never-reexposed",
            "dump_path": dump_path,
            "dump_sha256": dump_sha256,
        },
    ]
    for ordinal, service_name in enumerate(
        ("codex-pwa", "control-api", "control-api-replica"), start=3
    ):
        previous = current.get(service_name)
        expected_reverse.append(
            {
                "ordinal": ordinal,
                "action": "recreate-prior-service" if previous else "remove-new-service",
                "service": service_name,
                "previous": previous,
                "max_attempts": 1,
                "timeout_seconds": 105,
            }
        )
    if forward_steps != expected_forward or reverse_steps != expected_reverse:
        fail("bounded reverse plan steps do not match exact old and new identities")
    if (
        sum(step["timeout_seconds"] for step in expected_reverse)
        + POST_REVERSE_VERIFY_TIMEOUT_SECONDS
        > limits["total_timeout_seconds"]
    ):
        fail("bounded reverse plan timeout does not include post-reverse verification")
    rollback_services = rollback_compose.get("services")
    if not isinstance(rollback_services, dict):
        fail("rollback Compose snapshot has no service map")
    for service_name in ("control-api", "control-api-replica", "codex-pwa"):
        service_value = rollback_services.get(service_name)
        if not isinstance(service_value, dict):
            fail("rollback Compose snapshot omits one Control service")
        previous = current.get(service_name)
        expected_image = (
            previous["image_id"]
            if previous is not None
            else pwa_image_id if service_name == "codex-pwa" else api_image_id
        )
        if service_value.get("image") != expected_image:
            fail("rollback Compose snapshot is not bound to the exact prior image")
    receipt_timestamp(
        reverse_plan.get("created_at"), "bounded reverse plan", args.recovery_max_age_seconds
    )

    def evidence(path: Path, digest: str, size: int, value: dict[str, Any]) -> dict[str, Any]:
        return {"path": str(path), "sha256": digest, "size": size, "value": value}

    return {
        "full_backup": evidence(
            args.full_backup, full_backup_sha, full_backup_size, full_backup
        ),
        "isolated_restore": evidence(
            args.restore_receipt, restore_sha, restore_size, restore
        ),
        "datastore_isolation": evidence(
            args.isolation_receipt, isolation_sha, isolation_size, isolation
        ),
        "writer_unfreeze_plan": evidence(
            args.writer_unfreeze_plan, unfreeze_sha, unfreeze_size, unfreeze
        ),
        "writer_freeze": evidence(
            args.writer_freeze_receipt, freeze_sha, freeze_size, freeze
        ),
        "writers_stopped_before_backup": {
            "path": str(args.writers_stopped_before_backup),
            "sha256": stopped_before_sha,
            "size": stopped_before_size,
            "identities": stopped_before,
        },
        "writers_stopped_after_backup": {
            "path": str(args.writers_stopped_after_backup),
            "sha256": stopped_after_sha,
            "size": stopped_after_size,
            "identities": stopped_after,
        },
        "bounded_reverse_plan": evidence(
            args.reverse_plan, reverse_plan_sha, reverse_plan_size, reverse_plan
        ),
        "current_control_containers": {
            "path": str(args.current_control_containers),
            "sha256": current_sha,
            "size": current_size,
            "identities": current,
        },
        "rollback_compose": evidence(
            args.rollback_compose,
            rollback_compose_sha,
            rollback_compose_size,
            rollback_compose,
        ),
    }


def deployment_record(args: argparse.Namespace) -> dict[str, Any]:
    plan = load_json(args.plan, "deployment plan")
    releases = load_json(args.releases, "release image evidence")
    sub2api = load_json(args.sub2api, "Sub2API attestation")
    backup = load_json(args.backup, "backup evidence")
    revisions_value = load_json(args.revisions, "migration revision evidence")
    signed_release = load_json(args.release_verification, "signed release verification")
    smoke_input_value = load_json(args.smoke_input, "production smoke input evidence")
    for label, value in (
        ("deployment plan", plan),
        ("release image evidence", releases),
        ("Sub2API attestation", sub2api),
        ("backup evidence", backup),
        ("migration revision evidence", revisions_value),
        ("signed release verification", signed_release),
        ("production smoke input evidence", smoke_input_value),
    ):
        if not isinstance(value, dict):
            fail(f"{label} is not an object")
    resolved_compose_sha256 = secure_file_sha256(
        args.compose_config, "resolved Compose config"
    )
    if plan.get("resolved_compose_sha256") != resolved_compose_sha256:
        fail("resolved Compose snapshot changed after admission")
    recovery = recovery_chain(args, plan)
    record = {
        "format_version": 1,
        "status": args.status,
        "recorded_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "release": plan["release"],
        "release_source_revision": plan["source_revision"],
        "source_database_revision": revisions_value["source_database_revision"],
        "target_migration_head": revisions_value["target_migration_head"],
        "signed_release": {
            "values": signed_release,
            "sha256": secure_file_sha256(
                args.release_verification, "signed release verification"
            ),
        },
        "resolved_compose_sha256": resolved_compose_sha256,
        "production_smoke_input": smoke_input_value,
        "images": releases,
        "sub2api": sub2api,
        "backup": backup,
        "recovery": recovery,
    }
    if args.status == "deployed":
        if args.running is None or args.smoke is None or args.deployed_revision is None:
            fail(
                "deployed record requires running, smoke, and deployed revision evidence"
            )
        running = load_json(args.running, "running container evidence")
        deployed_revision = normalize_revision(
            secure_text_file(args.deployed_revision, "deployed alembic current"),
            "deployed alembic current",
        )
        if deployed_revision != revisions_value["target_migration_head"]:
            fail(
                "deployed database revision does not match the admitted migration head"
            )
        smoke_metadata = regular_private_file(args.smoke, "production smoke output")
        if smoke_metadata.st_size == 0:
            fail("production smoke output is empty")
        record["deployed_database_revision"] = deployed_revision
        record["running"] = running
        record["smoke"] = {
            "path": str(args.smoke),
            "sha256": secure_file_sha256(args.smoke, "production smoke output"),
            "size": smoke_metadata.st_size,
        }
    return record


def runtime_match(args: argparse.Namespace) -> dict[str, Any]:
    first = load_json(args.first, "first Sub2API attestation")
    second = load_json(args.second, "second Sub2API attestation")
    plan = load_json(args.plan, "deployment plan")
    if (
        not isinstance(first, dict)
        or not isinstance(second, dict)
        or not isinstance(plan, dict)
    ):
        fail("runtime comparison inputs must be objects")
    identity_fields = (
        "container_id",
        "image_id",
        "image_digest",
        "binary_sha256",
        "runtime_version",
        "runtime_commit",
        "runtime_built_at",
        "contract_sha256",
        "network",
        "network_alias",
    )
    for field in identity_fields:
        if first.get(field) != second.get(field):
            fail(f"Sub2API runtime changed during admission: {field}")
    expected_marker = f"{second['runtime_version']}/{second['runtime_commit'][:7]}"
    if plan.get("sub2api_contract_marker") != expected_marker:
        fail("resolved CONTROL_SUB2API_CONTRACT_MARKER does not match the runtime")
    if second.get("auth_evidence") is None:
        fail("final Sub2API attestation has no authentication evidence")
    return {
        "format_version": 1,
        "matched_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "container_id": second["container_id"],
        "image_id": second["image_id"],
        "contract_marker": expected_marker,
    }


def require_pwa_network_inspect(
    path: Path,
    *,
    expected_name: str,
    expected_project: str,
    pwa_container: dict[str, Any],
) -> dict[str, Any]:
    regular_private_file(path, "PWA Docker network inspection")
    value = load_json(path, "PWA Docker network inspection")
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
        or not all(
            isinstance(key, str) and isinstance(value, str)
            for key, value in labels.items()
        )
    ):
        fail("running PWA network does not retain the admitted bridge boundary")
    container_id = pwa_container.get("Id")
    container_name = pwa_container.get("Name")
    network_settings = pwa_container.get("NetworkSettings")
    attachments = (
        network_settings.get("Networks") if isinstance(network_settings, dict) else None
    )
    attachment = (
        attachments.get(expected_name) if isinstance(attachments, dict) else None
    )
    if (
        not isinstance(container_id, str)
        or not CONTAINER_ID_RE.fullmatch(container_id)
        or not isinstance(container_name, str)
        or not container_name.startswith("/")
        or not isinstance(attachment, dict)
        or attachment.get("NetworkID") != network_id
        or not isinstance(attachment.get("EndpointID"), str)
        or not CONTAINER_ID_RE.fullmatch(attachment["EndpointID"])
    ):
        fail("running PWA container is not bound to the inspected network identity")
    containers = network.get("Containers")
    if not isinstance(containers, dict) or set(containers) != {container_id}:
        fail("running PWA network must contain exactly the admitted PWA container")
    member = containers[container_id]
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
        "enable_ipv6": False,
        "options": expected_options,
        "container_id": container_id,
        "compose_network": "pwa-network",
        "labels": dict(labels),
        "member_container_ids": [container_id],
    }


def running_containers(args: argparse.Namespace) -> dict[str, Any]:
    releases = load_json(args.releases, "release image evidence")
    plan = load_json(args.plan, "deployment plan")
    if not isinstance(releases, dict) or not isinstance(plan, dict):
        fail("running container evidence inputs must be objects")
    expected_instances = plan.get("instances")
    if not isinstance(expected_instances, dict):
        fail("deployment plan has no admitted instance set")
    compose_project = plan.get("compose_project")
    if (
        not isinstance(compose_project, str)
        or re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,62}", compose_project) is None
    ):
        fail("deployment plan has no admitted Compose project")
    result: dict[str, Any] = {"format_version": 1, "containers": {}}
    observed_containers: dict[str, dict[str, Any]] = {}
    observed_ids: set[str] = set()
    for label, path in (
        ("control-api", args.api_inspect),
        ("control-api-replica", args.api_replica_inspect),
        ("codex-pwa", args.pwa_inspect),
    ):
        container = inspect_object(path, f"{label} container inspect")
        expected = expected_instances.get(label)
        if not isinstance(expected, dict):
            fail(f"deployment plan has no admitted {label} instance")
        release_key = expected.get("image_id_key")
        if release_key not in {"api", "pwa"}:
            fail(f"deployment plan has invalid image binding for {label}")
        expected_image_id = releases[release_key]["image_id"]
        if container.get("Image") != expected_image_id:
            fail(f"running {label} does not use the admitted image ID")
        container_id = container.get("Id")
        if not isinstance(container_id, str) or not CONTAINER_ID_RE.fullmatch(
            container_id
        ):
            fail(f"running {label} has no full Docker container ID")
        if container_id in observed_ids:
            fail("two admitted services unexpectedly resolve to one container")
        observed_ids.add(container_id)
        observed_containers[label] = container
        config = container.get("Config")
        labels = config.get("Labels") if isinstance(config, dict) else None
        container_name = container.get("Name")
        if (
            not isinstance(labels, dict)
            or labels.get("com.docker.compose.project") != compose_project
            or labels.get("com.docker.compose.service") != label
            or labels.get("com.docker.compose.oneoff") != "False"
            or labels.get("com.docker.compose.container-number") != "1"
            or labels.get("com.docker.compose.project.config_files")
            != str(args.plan.parent / "compose-config.json")
            or not all(
                isinstance(key, str) and isinstance(value, str)
                for key, value in labels.items()
            )
            or not isinstance(container_name, str)
            or not container_name.startswith("/")
            or len(container_name) > 256
        ):
            fail(f"running {label} has no exact Compose-owned identity")
        host_config = container.get("HostConfig")
        if (
            not isinstance(host_config, dict)
            or host_config.get("ReadonlyRootfs") is not True
        ):
            fail(f"running {label} root filesystem is not read-only")
        if host_config.get("Privileged") not in (None, False) or host_config.get(
            "CapAdd"
        ) not in (None, []):
            fail(f"running {label} has elevated host privileges")
        target_port = expected.get("target_port")
        published_port = expected.get("published_port")
        expected_bindings = {
            f"{target_port}/tcp": [
                {"HostIp": "127.0.0.1", "HostPort": str(published_port)}
            ]
        }
        if host_config.get("PortBindings") != expected_bindings:
            fail(f"running {label} does not have the admitted loopback port binding")
        state = container.get("State")
        if not isinstance(state, dict) or state.get("Running") is not True:
            fail(f"running {label} is stopped")
        health = state.get("Health")
        if not isinstance(health, dict) or health.get("Status") != "healthy":
            fail(f"running {label} is not healthy")
        network_settings = container.get("NetworkSettings")
        attached_networks = (
            network_settings.get("Networks")
            if isinstance(network_settings, dict)
            else None
        )
        if not isinstance(attached_networks, dict) or set(attached_networks) != {
            expected.get("network")
        }:
            fail(f"running {label} is not on exactly the admitted network")
        runtime_ports = network_settings.get("Ports")
        expected_runtime_port = [
            {"HostIp": "127.0.0.1", "HostPort": str(published_port)}
        ]
        if (
            not isinstance(runtime_ports, dict)
            or runtime_ports.get(f"{target_port}/tcp") != expected_runtime_port
            or any(
                value not in (None, [])
                for key, value in runtime_ports.items()
                if key != f"{target_port}/tcp"
            )
        ):
            fail(f"running {label} does not expose exactly the admitted runtime port")
        result["containers"][label] = {
            "container_id": container_id,
            "container_name": container_name,
            "image_id": expected_image_id,
            "health": "healthy",
            "network": expected["network"],
            "published_port": str(published_port),
            "compose_project": compose_project,
            "compose_service": label,
            "compose_oneoff": False,
            "labels": dict(labels),
        }
    pwa_instance = result["containers"].get("codex-pwa")
    pwa_network_name = plan.get("pwa_network")
    if not isinstance(pwa_instance, dict) or not isinstance(pwa_network_name, str):
        fail("deployment plan has no admitted PWA network instance")
    result["pwa_network"] = require_pwa_network_inspect(
        args.pwa_network_inspect,
        expected_name=pwa_network_name,
        expected_project=compose_project,
        pwa_container=observed_containers["codex-pwa"],
    )
    result["verified_at"] = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    return result


def smoke_input(args: argparse.Namespace) -> dict[str, Any]:
    if not args.token_file.is_absolute():
        fail("production smoke access-token file must be absolute")
    token = read_private_opaque_file(
        args.token_file, "production smoke access-token file"
    )
    if (
        not args.expected_user_id
        or len(args.expected_user_id) > 256
        or any(
            character.isspace() or ord(character) < 32
            for character in args.expected_user_id
        )
    ):
        fail("production smoke expected user ID must be one opaque identifier")
    return {
        "format_version": 1,
        "access_token_file_validated": True,
        "access_token_sha256": hashlib.sha256(token.encode()).hexdigest(),
        "expected_user_id": args.expected_user_id,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)

    compose_parser = commands.add_parser("compose-plan")
    compose_parser.add_argument("--compose-config", type=Path, required=True)
    compose_parser.add_argument("--release-verification", type=Path, required=True)
    compose_parser.add_argument("--versions-lock", type=Path, required=True)
    compose_parser.add_argument("--source-repository", required=True)
    compose_parser.add_argument("--repo-root", type=Path, required=True)
    compose_parser.add_argument("--sub2api-database", default="sub2api")
    compose_parser.set_defaults(handler=compose_plan)

    package_parser = commands.add_parser("server-package-release")
    package_parser.add_argument("--manifest", type=Path, required=True)
    package_parser.add_argument("--verification-receipt", type=Path, required=True)
    package_parser.add_argument("--expected-manifest-sha256", required=True)
    package_parser.add_argument("--mode", choices=("online", "offline"), required=True)
    package_parser.add_argument("--expected-source-repository", required=True)
    package_parser.add_argument("--expected-source-commit", required=True)
    package_parser.add_argument("--expected-release-tag", required=True)
    package_parser.add_argument("--expected-owner-uid", type=int, default=0)
    package_parser.set_defaults(handler=server_package_release)

    images_parser = commands.add_parser("release-images")
    images_parser.add_argument("--plan", type=Path, required=True)
    images_parser.add_argument("--api-inspect", type=Path, required=True)
    images_parser.add_argument("--pwa-inspect", type=Path, required=True)
    images_parser.add_argument("--backup-inspect", type=Path, required=True)
    images_parser.set_defaults(handler=release_images)

    backup_parser = commands.add_parser("backup")
    backup_parser.add_argument("--directory", type=Path, required=True)
    backup_parser.add_argument("--not-before", type=float, required=True)
    backup_parser.add_argument("--max-age-seconds", type=int, default=600)
    backup_parser.add_argument("--pg-restore", type=Path, default=Path("pg_restore"))
    backup_parser.add_argument("--expected-owner-uid", type=int, required=True)
    backup_parser.set_defaults(handler=backup_evidence)

    revisions_parser = commands.add_parser("revisions")
    revisions_parser.add_argument("--current", type=Path, required=True)
    revisions_parser.add_argument("--head", type=Path, required=True)
    revisions_parser.add_argument("--plan", type=Path)
    revisions_parser.add_argument("--require-current-head", action="store_true")
    revisions_parser.set_defaults(handler=revisions)

    record_parser = commands.add_parser("record")
    record_parser.add_argument("--plan", type=Path, required=True)
    record_parser.add_argument("--releases", type=Path, required=True)
    record_parser.add_argument("--sub2api", type=Path, required=True)
    record_parser.add_argument("--backup", type=Path, required=True)
    record_parser.add_argument("--revisions", type=Path, required=True)
    record_parser.add_argument("--release-verification", type=Path, required=True)
    record_parser.add_argument("--compose-config", type=Path, required=True)
    record_parser.add_argument("--smoke-input", type=Path, required=True)
    record_parser.add_argument("--full-backup", type=Path, required=True)
    record_parser.add_argument("--restore-receipt", type=Path, required=True)
    record_parser.add_argument("--isolation-receipt", type=Path, required=True)
    record_parser.add_argument("--writer-unfreeze-plan", type=Path, required=True)
    record_parser.add_argument("--writer-freeze-receipt", type=Path, required=True)
    record_parser.add_argument(
        "--writers-stopped-before-backup", type=Path, required=True
    )
    record_parser.add_argument(
        "--writers-stopped-after-backup", type=Path, required=True
    )
    record_parser.add_argument("--reverse-plan", type=Path, required=True)
    record_parser.add_argument("--rollback-compose", type=Path, required=True)
    record_parser.add_argument("--current-control-containers", type=Path, required=True)
    record_parser.add_argument(
        "--recovery-max-age-seconds", type=int, default=1800
    )
    record_parser.add_argument(
        "--status", choices=("admitted_for_migration", "deployed"), required=True
    )
    record_parser.add_argument("--running", type=Path)
    record_parser.add_argument("--smoke", type=Path)
    record_parser.add_argument("--deployed-revision", type=Path)
    record_parser.set_defaults(handler=deployment_record)

    runtime_match_parser = commands.add_parser("runtime-match")
    runtime_match_parser.add_argument("--first", type=Path, required=True)
    runtime_match_parser.add_argument("--second", type=Path, required=True)
    runtime_match_parser.add_argument("--plan", type=Path, required=True)
    runtime_match_parser.set_defaults(handler=runtime_match)

    running_parser = commands.add_parser("running-containers")
    running_parser.add_argument("--releases", type=Path, required=True)
    running_parser.add_argument("--plan", type=Path, required=True)
    running_parser.add_argument("--api-inspect", type=Path, required=True)
    running_parser.add_argument("--api-replica-inspect", type=Path, required=True)
    running_parser.add_argument("--pwa-inspect", type=Path, required=True)
    running_parser.add_argument("--pwa-network-inspect", type=Path, required=True)
    running_parser.set_defaults(handler=running_containers)

    smoke_input_parser = commands.add_parser("smoke-input")
    smoke_input_parser.add_argument("--token-file", type=Path, required=True)
    smoke_input_parser.add_argument("--expected-user-id", required=True)
    smoke_input_parser.set_defaults(handler=smoke_input)

    directory_parser = commands.add_parser("operator-directory")
    directory_parser.add_argument("--directory", type=Path, required=True)
    directory_parser.add_argument("--label", required=True)
    directory_parser.set_defaults(handler=operator_directory)

    reverse_admission_parser = commands.add_parser("post-success-reverse")
    reverse_admission_parser.add_argument(
        "--deployment-directory", type=Path, required=True
    )
    reverse_admission_parser.add_argument("--record-root", type=Path, required=True)
    reverse_admission_parser.add_argument("--trigger-stage", required=True)
    reverse_admission_parser.add_argument(
        "--expected-owner-uid", type=int, required=True
    )
    reverse_admission_parser.set_defaults(handler=post_success_reverse_admission)

    uninstall_plan_parser = commands.add_parser("bounded-uninstall-plan")
    uninstall_plan_parser.add_argument(
        "--deployment-directory", type=Path, required=True
    )
    uninstall_plan_parser.add_argument("--record-root", type=Path, required=True)
    uninstall_plan_parser.add_argument("--trigger-stage", required=True)
    uninstall_plan_parser.add_argument("--manifest", type=Path, required=True)
    uninstall_plan_parser.add_argument(
        "--verification-receipt", type=Path, required=True
    )
    uninstall_plan_parser.add_argument("--expected-manifest-sha256", required=True)
    uninstall_plan_parser.add_argument(
        "--mode", choices=("online", "offline"), required=True
    )
    uninstall_plan_parser.add_argument(
        "--project-containers-inspect", type=Path, required=True
    )
    uninstall_plan_parser.add_argument(
        "--pwa-network-inspect", type=Path, required=True
    )
    uninstall_plan_parser.add_argument(
        "--expected-owner-uid", type=int, required=True
    )
    uninstall_plan_parser.set_defaults(handler=bounded_uninstall_plan)

    uninstall_execution_parser = commands.add_parser("bounded-uninstall-execution")
    uninstall_execution_parser.add_argument("--plan", type=Path, required=True)
    uninstall_execution_parser.add_argument("--trigger-stage", required=True)
    uninstall_execution_parser.add_argument(
        "--empty-network-inspect", type=Path, required=True
    )
    uninstall_execution_parser.add_argument(
        "--project-containers-absent", action="store_true"
    )
    uninstall_execution_parser.add_argument(
        "--pwa-network-absent", action="store_true"
    )
    uninstall_execution_parser.add_argument(
        "--expected-owner-uid", type=int, required=True
    )
    uninstall_execution_parser.set_defaults(handler=bounded_uninstall_execution)

    copy_parser = commands.add_parser("copy-private-file")
    copy_parser.add_argument("--source", type=Path, required=True)
    copy_parser.add_argument("--destination", type=Path, required=True)
    copy_parser.add_argument("--label", required=True)
    copy_parser.add_argument("--max-bytes", type=int, default=MAX_PRIVATE_INPUT_BYTES)
    copy_parser.set_defaults(handler=copy_private_file)

    admitted_copy_parser = commands.add_parser("copy-admitted-file")
    admitted_copy_parser.add_argument("--source", type=Path, required=True)
    admitted_copy_parser.add_argument("--destination", type=Path, required=True)
    admitted_copy_parser.add_argument("--label", required=True)
    admitted_copy_parser.add_argument("--expected-sha256", required=True)
    admitted_copy_parser.add_argument(
        "--max-bytes", type=int, default=MAX_PRIVATE_INPUT_BYTES
    )
    admitted_copy_parser.set_defaults(handler=copy_admitted_file)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        write_json(args.handler(args))
    except (KeyError, OSError, TypeError, ValueError) as exc:
        print(f"deployment-admission: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
