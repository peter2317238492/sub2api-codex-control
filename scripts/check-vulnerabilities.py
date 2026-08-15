#!/usr/bin/env python3
"""Verify complete, fresh, disposition-bound Trivy release evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

SCRIPTS_DIR = Path(__file__).resolve().parent
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import vulnerability_release_roots as release_roots
import vulnerability_scan_evidence as scan_evidence

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
IMAGE_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
TARGET_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")
SPDX_ID_RE = re.compile(r"^SPDXRef-[A-Za-z0-9.-]+$")
REPOSITORY_RE = re.compile(
    r"^https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$"
)
MAX_JSON_BYTES = 64 * 1024 * 1024


class GateError(ValueError):
    """A release-gate input failed closed."""


@dataclass(frozen=True)
class Finding:
    target: str
    vulnerability_id: str
    package: str
    installed_version: str
    fixed_version: str
    severity: str

    @property
    def identity(self) -> tuple[str, str, str, str]:
        return (
            self.target,
            self.vulnerability_id,
            self.package,
            self.installed_version,
        )


def _parse_time(value: Any, label: str) -> datetime:
    if not isinstance(value, str) or not value:
        raise GateError(f"{label} must be a non-empty RFC3339 string")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise GateError(f"{label} is not valid RFC3339: {error}") from error
    if parsed.tzinfo is None:
        raise GateError(f"{label} must include a timezone")
    return parsed.astimezone(UTC)


def _read_json(path: Path, label: str) -> Any:
    try:
        raw = path.read_bytes()
        if len(raw) > MAX_JSON_BYTES:
            raise GateError(f"{label} exceeds the JSON size limit")

        def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
            value: dict[str, Any] = {}
            for key, item in pairs:
                if key in value:
                    raise GateError(f"{label} contains duplicate JSON key {key!r}")
                value[key] = item
            return value

        def reject_constant(value: str) -> Any:
            raise GateError(f"{label} contains non-finite JSON number {value}")

        return json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=reject_duplicates,
            parse_constant=reject_constant,
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise GateError(f"cannot read {label}: {error}") from error


def _input_file(path: Path, label: str) -> Path:
    try:
        metadata = path.lstat()
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise GateError(f"cannot inspect {label}: {error}") from error
    if path.is_symlink() or not path.is_file() or resolved != path.absolute():
        raise GateError(f"{label} must be a regular non-symlink file")
    if metadata.st_size > MAX_JSON_BYTES:
        raise GateError(f"{label} exceeds the file size limit")
    return resolved


def _regular_file(base: Path, relative: Any, label: str) -> Path:
    if not isinstance(relative, str) or not relative or Path(relative).is_absolute():
        raise GateError(f"{label} must be a non-empty relative path")
    candidate = base / relative
    try:
        resolved_base = base.resolve(strict=True)
        resolved = candidate.resolve(strict=True)
    except OSError as error:
        raise GateError(f"cannot resolve {label}: {error}") from error
    if resolved != candidate.absolute():
        raise GateError(f"{label} must not traverse a symlink")
    if resolved_base not in resolved.parents:
        raise GateError(f"{label} escapes the evidence directory")
    if not resolved.is_file():
        raise GateError(f"{label} is not a regular file")
    return resolved


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _expect_sha(value: Any, label: str) -> str:
    if not isinstance(value, str) or not SHA256_RE.fullmatch(value):
        raise GateError(f"{label} must be a lowercase SHA-256")
    return value


def _expect_exact_keys(value: dict[str, Any], keys: set[str], label: str) -> None:
    actual = set(value)
    if actual != keys:
        raise GateError(
            f"{label} keys mismatch: missing={sorted(keys - actual)}, "
            f"unexpected={sorted(actual - keys)}"
        )


def _inventory_item(path: Path, base: Path, role: str, target: str) -> dict[str, Any]:
    try:
        relative = path.relative_to(base).as_posix()
    except ValueError as error:
        raise GateError(f"{role} evidence is outside the evidence directory") from error
    return {
        "path": relative,
        "role": role,
        "sha256": _sha256(path),
        "size": path.stat().st_size,
        "target": target,
    }


def _normalized_derived_target(
    name: str,
    derived: dict[str, Any],
) -> dict[str, Any]:
    if derived.get("target_id") != name:
        raise GateError(f"release root derived the wrong target identity: {name}")
    kind = derived.get("kind")
    identity = derived.get("identity")
    root_id = derived.get("root_id")
    if (
        kind not in {"container", "file"}
        or not isinstance(identity, str)
        or not isinstance(root_id, str)
    ):
        raise GateError(f"release root derived an invalid target: {name}")
    record: dict[str, Any] = {
        "name": name,
        "kind": kind,
        "identity": identity,
        "root_id": root_id,
    }
    sbom = derived.get("sbom")
    if not isinstance(sbom, dict):
        raise GateError(f"release root omitted the target SBOM: {name}")
    if kind == "container":
        image = derived.get("image")
        if not isinstance(image, dict):
            raise GateError(f"release root omitted the image identity: {name}")
        record["image"] = image
        record["release_sbom"] = sbom
        return record

    artifact = derived.get("artifact")
    if not isinstance(artifact, dict):
        raise GateError(f"release root omitted the package artifact: {name}")
    delivery = derived.get("delivery")
    if delivery is None:
        path = artifact.get("path")
        if not isinstance(path, str):
            raise GateError(f"release root omitted the package path: {name}")
        delivery = {
            "kind": "single",
            "parts": [
                {
                    "path": path,
                    "sha256": artifact.get("sha256"),
                    "size": artifact.get("size"),
                    "index": 1,
                    "count": 1,
                }
            ],
        }
    record["artifact"] = {
        "filename": artifact.get("filename"),
        "sha256": artifact.get("sha256"),
        "size": artifact.get("size"),
        "delivery": delivery,
    }
    sbom_sha = sbom.get("sha256")
    if not isinstance(sbom_sha, str) or not SHA256_RE.fullmatch(sbom_sha):
        raise GateError(f"release root derived an invalid package SBOM: {name}")
    record["sbom"] = {
        "path": sbom.get("path"),
        "sha256": sbom_sha,
        "size": sbom.get("size"),
        "format": sbom.get("format"),
        "scan_subject_name": f"{name}.{sbom_sha}.spdx.json",
    }
    return record


def _spdx_checksum(element: dict[str, Any], expected_sha256: str) -> bool:
    checksums = element.get("checksums")
    if not isinstance(checksums, list):
        return False
    return any(
        isinstance(checksum, dict)
        and checksum.get("algorithm") == "SHA256"
        and checksum.get("checksumValue") == expected_sha256
        for checksum in checksums
    )


def _validate_spdx_artifact_binding(
    sbom_path: Path,
    expected_sha256: str,
    target: str,
) -> None:
    sbom = _read_json(sbom_path, f"SPDX SBOM for {target}")
    if not isinstance(sbom, dict):
        raise GateError(f"SPDX SBOM for {target} must be an object")
    if (
        sbom.get("spdxVersion") != "SPDX-2.3"
        or sbom.get("dataLicense") != "CC0-1.0"
        or sbom.get("SPDXID") != "SPDXRef-DOCUMENT"
    ):
        raise GateError(f"target {target} SBOM is not SPDX 2.3 JSON")
    packages = sbom.get("packages")
    files = sbom.get("files")
    relationships = sbom.get("relationships")
    if (
        not isinstance(packages, list)
        or not isinstance(files, list)
        or not isinstance(relationships, list)
    ):
        raise GateError(f"target {target} SBOM lacks packages, files, or relationships")
    elements: dict[str, dict[str, Any]] = {}
    for element in [*packages, *files]:
        if not isinstance(element, dict):
            raise GateError(f"target {target} SBOM contains a malformed element")
        identifier = element.get("SPDXID")
        if not isinstance(identifier, str) or not SPDX_ID_RE.fullmatch(identifier):
            raise GateError(f"target {target} SBOM contains an invalid SPDXID")
        if identifier in elements:
            raise GateError(f"target {target} SBOM contains duplicate SPDXID {identifier}")
        elements[identifier] = element
    described: set[str] = set()
    for relationship in relationships:
        if not isinstance(relationship, dict):
            raise GateError(f"target {target} SBOM contains a malformed relationship")
        if (
            relationship.get("spdxElementId") == "SPDXRef-DOCUMENT"
            and relationship.get("relationshipType") == "DESCRIBES"
            and isinstance(relationship.get("relatedSpdxElement"), str)
        ):
            described.add(relationship["relatedSpdxElement"])
    if not described or any(identifier not in elements for identifier in described):
        raise GateError(f"target {target} SBOM has an invalid DESCRIBES relationship")
    if not any(_spdx_checksum(elements[identifier], expected_sha256) for identifier in described):
        raise GateError(f"target {target} SBOM does not describe the artifact SHA-256")


def _load_policy(path: Path, profile: str) -> tuple[dict[str, Any], dict[str, str]]:
    policy = _read_json(path, "vulnerability policy")
    if not isinstance(policy, dict) or policy.get("format_version") != 1:
        raise GateError("vulnerability policy format_version must be 1")
    scanner = policy.get("scanner")
    gate = policy.get("gate")
    profiles = policy.get("profiles")
    target_kinds = policy.get("target_kinds")
    source_repository = policy.get("source_repository")
    if (
        not isinstance(scanner, dict)
        or not isinstance(gate, dict)
        or not isinstance(profiles, dict)
        or not isinstance(target_kinds, dict)
    ):
        raise GateError(
            "vulnerability policy scanner, gate, target_kinds, and profiles must be objects"
        )
    if not isinstance(source_repository, str) or not REPOSITORY_RE.fullmatch(
        source_repository
    ):
        raise GateError("vulnerability policy source_repository is invalid")
    if not target_kinds or any(
        not isinstance(name, str)
        or not TARGET_RE.fullmatch(name)
        or not isinstance(kind, str)
        or kind not in {"source", "container", "file"}
        for name, kind in target_kinds.items()
    ):
        raise GateError("vulnerability policy target_kinds are invalid")
    used_targets: set[str] = set()
    for policy_profile, policy_targets in profiles.items():
        if (
            not isinstance(policy_profile, str)
            or not isinstance(policy_targets, list)
            or not policy_targets
            or any(not isinstance(item, str) for item in policy_targets)
            or len(policy_targets) != len(set(policy_targets))
            or not set(policy_targets) <= set(target_kinds)
        ):
            raise GateError(f"vulnerability profile {policy_profile!r} is invalid")
        used_targets.update(policy_targets)
    if used_targets != set(target_kinds):
        raise GateError("vulnerability policy has unused or undeclared target kinds")
    required = profiles.get(profile)
    if not isinstance(required, list) or not required:
        raise GateError(f"unknown or empty vulnerability profile: {profile}")
    if any(not isinstance(item, str) or not TARGET_RE.fullmatch(item) for item in required):
        raise GateError(f"profile {profile} contains an invalid target name")
    if len(set(required)) != len(required):
        raise GateError(f"profile {profile} contains duplicate targets")
    return policy, {name: target_kinds[name] for name in required}


def _validate_freshness(
    observed: datetime,
    now: datetime,
    max_age_hours: Any,
    label: str,
) -> None:
    if not isinstance(max_age_hours, int) or not 1 <= max_age_hours <= 168:
        raise GateError(f"invalid {label} maximum age")
    if observed > now + timedelta(minutes=5):
        raise GateError(f"{label} timestamp is in the future")
    if now - observed > timedelta(hours=max_age_hours):
        raise GateError(f"{label} is stale")


def _validate_database_record(
    base: Path,
    record: Any,
    policy_database: dict[str, Any],
    max_age_hours: Any,
    name: str,
    now: datetime,
) -> tuple[Path, str, Path, str, str, datetime, list[tuple[Path, str]]]:
    if not isinstance(record, dict):
        raise GateError(f"manifest scanner {name} database must be an object")
    _expect_exact_keys(
        record,
        {
            "database",
            "metadata",
            "oci",
            "repository",
            "schema_version",
            "tag",
        },
        f"scanner {name} database",
    )
    if (
        record.get("repository") != policy_database.get("repository")
        or record.get("tag") != policy_database.get("tag")
        or record.get("schema_version") != policy_database.get("schema_version")
    ):
        raise GateError(f"scanner {name} database authority does not match policy")
    metadata_record = record.get("metadata")
    database_record = record.get("database")
    if not isinstance(metadata_record, dict) or not isinstance(database_record, dict):
        raise GateError(f"scanner {name} database evidence must be objects")
    _expect_exact_keys(metadata_record, {"path", "sha256", "size"}, f"{name} metadata")
    _expect_exact_keys(database_record, {"path", "sha256", "size"}, f"{name} database")
    if metadata_record.get("path") != policy_database.get("metadata_evidence_name"):
        raise GateError(f"scanner {name} database metadata path does not match policy")
    if database_record.get("path") != policy_database.get("database_evidence_name"):
        raise GateError(f"scanner {name} database file path does not match policy")
    metadata_path = _regular_file(base, metadata_record["path"], f"{name} metadata")
    metadata_sha = _expect_sha(metadata_record.get("sha256"), f"{name} metadata SHA-256")
    database_path = _regular_file(base, database_record["path"], f"{name} database")
    database_sha = _expect_sha(database_record.get("sha256"), f"{name} database SHA-256")
    if (
        _sha256(metadata_path) != metadata_sha
        or metadata_path.stat().st_size != metadata_record.get("size")
        or _sha256(database_path) != database_sha
        or database_path.stat().st_size != database_record.get("size")
    ):
        raise GateError(f"scanner {name} database evidence bytes mismatch")
    metadata = _read_json(metadata_path, f"Trivy {name} database metadata")
    if not isinstance(metadata, dict):
        raise GateError(f"Trivy {name} database metadata must be an object")
    if metadata.get("Version") != policy_database.get("schema_version"):
        raise GateError(f"Trivy {name} database schema does not match policy")
    updated_at = _parse_time(
        metadata.get("UpdatedAt"), f"Trivy {name} database UpdatedAt"
    )
    downloaded_at = _parse_time(
        metadata.get("DownloadedAt"), f"Trivy {name} database DownloadedAt"
    )
    next_update = _parse_time(
        metadata.get("NextUpdate"), f"Trivy {name} database NextUpdate"
    )
    if (
        downloaded_at > now + timedelta(minutes=5)
        or downloaded_at < updated_at - timedelta(minutes=5)
        or next_update <= updated_at
    ):
        raise GateError(f"Trivy {name} database metadata time ordering is invalid")
    _validate_freshness(
        updated_at,
        now,
        max_age_hours,
        f"Trivy {name} database",
    )
    oci = record.get("oci")
    if not isinstance(oci, dict):
        raise GateError(f"scanner {name} database OCI evidence must be an object")
    _expect_exact_keys(oci, {"digest", "files", "layout_path"}, f"scanner {name} OCI")
    try:
        verified_oci = scan_evidence.inspect_database_oci_layout(
            base,
            oci.get("layout_path"),
            policy_database,
            metadata_path,
            database_path,
        )
    except scan_evidence.ScanEvidenceError as error:
        raise GateError(f"scanner {name} database OCI evidence is invalid: {error}") from error
    if oci != verified_oci:
        raise GateError(f"scanner {name} database OCI evidence is not canonical")
    oci_paths = [
        (
            _regular_file(base, item["path"], f"scanner {name} OCI evidence"),
            item["role"],
        )
        for item in verified_oci["files"]
    ]
    return (
        metadata_path,
        metadata_sha,
        database_path,
        database_sha,
        verified_oci["digest"],
        updated_at,
        oci_paths,
    )


def _package_identity(vulnerability: dict[str, Any]) -> str:
    identifier = vulnerability.get("PkgIdentifier")
    if isinstance(identifier, dict):
        purl = identifier.get("PURL")
        if isinstance(purl, str) and purl:
            return purl
    package = vulnerability.get("PkgName")
    if not isinstance(package, str) or not package:
        raise GateError("Trivy vulnerability lacks package identity")
    return package


def _extract_findings(target: str, report: dict[str, Any]) -> tuple[list[Finding], int]:
    results = report.get("Results")
    if not isinstance(results, list) or not results:
        raise GateError(f"Trivy report for {target} has no vulnerability scan results")
    findings: list[Finding] = []
    covered = False
    detected_packages: set[tuple[str, str, str]] = set()
    for result in results:
        if not isinstance(result, dict):
            raise GateError(f"Trivy report for {target} has a malformed result")
        if "Packages" not in result or not isinstance(result["Packages"], list):
            raise GateError(
                f"Trivy result for {target} must explicitly contain a Packages list"
            )
        packages = result["Packages"]
        if not packages:
            raise GateError(f"Trivy result for {target} has no package inventory")
        for package in packages:
            if not isinstance(package, dict):
                raise GateError(f"Trivy report for {target} has a malformed package")
            package_name = package.get("Name")
            package_version = package.get("Version")
            identifier = package.get("Identifier")
            purl = identifier.get("PURL", "") if isinstance(identifier, dict) else ""
            if (
                not isinstance(package_name, str)
                or not package_name
                or not isinstance(package_version, str)
                or not package_version
                or not isinstance(purl, str)
            ):
                raise GateError(f"Trivy report for {target} has an incomplete package")
            detected_packages.add((package_name, package_version, purl))
        covered = True
        if "Vulnerabilities" not in result or not isinstance(
            result["Vulnerabilities"], list
        ):
            raise GateError(
                f"Trivy result for {target} must explicitly contain a Vulnerabilities list"
            )
        vulnerabilities = result["Vulnerabilities"]
        for vulnerability in vulnerabilities:
            if not isinstance(vulnerability, dict):
                raise GateError(f"Trivy report for {target} has a malformed vulnerability")
            vulnerability_id = vulnerability.get("VulnerabilityID")
            installed = vulnerability.get("InstalledVersion")
            severity = vulnerability.get("Severity")
            fixed = vulnerability.get("FixedVersion", "")
            if not isinstance(vulnerability_id, str) or not vulnerability_id:
                raise GateError(f"Trivy vulnerability for {target} lacks an ID")
            if not isinstance(installed, str) or not installed:
                raise GateError(f"Trivy vulnerability {vulnerability_id} lacks installed version")
            if not isinstance(severity, str) or not severity:
                raise GateError(f"Trivy vulnerability {vulnerability_id} lacks severity")
            if not isinstance(fixed, str):
                raise GateError(
                    f"Trivy vulnerability {vulnerability_id} has invalid fixed version"
                )
            findings.append(
                Finding(
                    target=target,
                    vulnerability_id=vulnerability_id,
                    package=_package_identity(vulnerability),
                    installed_version=installed,
                    fixed_version=fixed,
                    severity=severity.upper(),
                )
            )
    if not covered or not detected_packages:
        raise GateError(
            f"Trivy report for {target} lacks --list-all-pkgs vulnerability coverage"
        )
    identities = [finding.identity for finding in findings]
    if len(identities) != len(set(identities)):
        raise GateError(f"Trivy report for {target} contains duplicate findings")
    return findings, len(detected_packages)


def _validate_target(
    base: Path,
    target: dict[str, Any],
    source_commit: str,
    source_repository: str,
    schema_version: Any,
    max_report_age_hours: Any,
    now: datetime,
) -> tuple[str, str, list[Finding], int, list[dict[str, Any]]]:
    required_keys = {
        "name",
        "kind",
        "identity",
        "report_path",
        "report_sha256",
        "scan_execution_path",
        "scan_execution_sha256",
    }
    kind = target.get("kind")
    if kind == "file":
        required_keys |= {"root_id", "artifact", "sbom"}
    elif kind == "container":
        required_keys |= {"root_id", "image", "release_sbom"}
    _expect_exact_keys(
        target,
        required_keys,
        f"target {target.get('name', '<unknown>')}",
    )
    name = target.get("name")
    identity = target.get("identity")
    if not isinstance(name, str) or not TARGET_RE.fullmatch(name):
        raise GateError("manifest target has an invalid name")
    if kind not in {"source", "container", "file"}:
        raise GateError(f"target {name} has unsupported kind {kind!r}")
    if not isinstance(identity, str) or not identity:
        raise GateError(f"target {name} has invalid identity")
    if kind == "source" and identity != f"git:{source_commit}":
        raise GateError(f"target {name} is not bound to the source commit")
    if kind == "container" and not IMAGE_DIGEST_RE.fullmatch(identity):
        raise GateError(f"target {name} container identity must be a sha256 digest")
    inventory: list[dict[str, Any]] = []
    if kind == "file":
        artifact = target["artifact"]
        if not isinstance(artifact, dict):
            raise GateError(f"target {name} artifact must be an object")
        _expect_exact_keys(
            artifact,
            {"filename", "sha256", "size", "delivery"},
            f"target {name} artifact",
        )
        expected_artifact = _expect_sha(
            artifact["sha256"], f"target {name} artifact SHA-256"
        )
        if identity != f"sha256:{expected_artifact}":
            raise GateError(f"target {name} file identity does not match artifact SHA-256")
        artifact_size = artifact.get("size")
        if not isinstance(artifact_size, int) or isinstance(artifact_size, bool):
            raise GateError(f"target {name} artifact size is invalid")
        delivery = artifact.get("delivery")
        if not isinstance(delivery, dict):
            raise GateError(f"target {name} artifact delivery must be an object")
        _expect_exact_keys(delivery, {"kind", "parts"}, f"target {name} delivery")
        parts = delivery.get("parts")
        if (
            delivery.get("kind") not in {"single", "split"}
            or not isinstance(parts, list)
            or not parts
        ):
            raise GateError(f"target {name} artifact delivery is invalid")
        if delivery["kind"] == "single" and len(parts) != 1:
            raise GateError(f"target {name} single delivery must have one part")
        if delivery["kind"] == "split" and len(parts) < 2:
            raise GateError(f"target {name} split delivery must have multiple parts")
        logical = hashlib.sha256()
        observed_size = 0
        for index, part in enumerate(parts, start=1):
            if not isinstance(part, dict):
                raise GateError(f"target {name} artifact part must be an object")
            _expect_exact_keys(
                part,
                {"path", "sha256", "size", "index", "count"},
                f"target {name} artifact part {index}",
            )
            if part.get("index") != index or part.get("count") != len(parts):
                raise GateError(f"target {name} artifact part order is invalid")
            expected_part = _expect_sha(
                part.get("sha256"), f"target {name} artifact part SHA-256"
            )
            expected_size = part.get("size")
            if not isinstance(expected_size, int) or isinstance(expected_size, bool):
                raise GateError(f"target {name} artifact part size is invalid")
            part_path = _regular_file(
                base, part.get("path"), f"target {name} artifact part"
            )
            digest = hashlib.sha256()
            size = 0
            with part_path.open("rb") as source:
                for block in iter(lambda: source.read(1024 * 1024), b""):
                    digest.update(block)
                    logical.update(block)
                    size += len(block)
            if digest.hexdigest() != expected_part or size != expected_size:
                raise GateError(f"target {name} artifact part differs from its root")
            observed_size += size
            role = "artifact" if delivery["kind"] == "single" else "artifact-part"
            inventory.append(_inventory_item(part_path, base, role, name))
        if observed_size != artifact_size or logical.hexdigest() != expected_artifact:
            raise GateError(f"target {name} logical artifact differs from its root")
        sbom = target["sbom"]
        if not isinstance(sbom, dict):
            raise GateError(f"target {name} SBOM must be an object")
        _expect_exact_keys(
            sbom,
            {"path", "sha256", "size", "format", "scan_subject_name"},
            f"target {name} SBOM",
        )
        expected_sbom = _expect_sha(
            sbom["sha256"],
            f"target {name} SBOM SHA-256",
        )
        if sbom.get("format") != "SPDX-2.3-json":
            raise GateError(f"target {name} SBOM format is invalid")
        sbom_path = _regular_file(base, sbom["path"], f"target {name} SBOM")
        if (
            _sha256(sbom_path) != expected_sbom
            or sbom_path.stat().st_size != sbom.get("size")
        ):
            raise GateError(f"target {name} SBOM SHA-256 mismatch")
        expected_scan_subject = f"{name}.{expected_sbom}.spdx.json"
        if sbom["scan_subject_name"] != expected_scan_subject:
            raise GateError(
                f"target {name} scan subject must use content-addressed name "
                f"{expected_scan_subject}"
            )
        _validate_spdx_artifact_binding(sbom_path, expected_artifact, name)
        inventory.append(_inventory_item(sbom_path, base, "sbom", name))
    elif kind == "container":
        release_sbom = target["release_sbom"]
        if not isinstance(release_sbom, dict):
            raise GateError(f"target {name} release SBOM must be an object")
        _expect_exact_keys(
            release_sbom,
            {"path", "sha256", "size"},
            f"target {name} release SBOM",
        )
        release_sbom_path = _regular_file(
            base,
            release_sbom["path"],
            f"target {name} release SBOM",
        )
        if (
            _sha256(release_sbom_path)
            != _expect_sha(
                release_sbom["sha256"], f"target {name} release SBOM SHA-256"
            )
            or release_sbom_path.stat().st_size != release_sbom.get("size")
        ):
            raise GateError(f"target {name} release SBOM differs from its root")
        inventory.append(
            _inventory_item(release_sbom_path, base, "release-sbom", name)
        )

    report_path = _regular_file(base, target["report_path"], f"target {name} report")
    expected_report = _expect_sha(target["report_sha256"], f"target {name} report SHA-256")
    actual_report = _sha256(report_path)
    if actual_report != expected_report:
        raise GateError(f"target {name} report SHA-256 mismatch")
    report = _read_json(report_path, f"Trivy report for {name}")
    if not isinstance(report, dict):
        raise GateError(f"Trivy report for {name} must be an object")
    try:
        scan_evidence.validate_report_structure(
            report, name, schema_version
        )
    except scan_evidence.ScanEvidenceError as error:
        raise GateError(str(error)) from error
    if report.get("SchemaVersion") != schema_version:
        raise GateError(f"Trivy report schema mismatch for {name}")
    created_at = _parse_time(report.get("CreatedAt"), f"Trivy report CreatedAt for {name}")
    _validate_freshness(created_at, now, max_report_age_hours, f"Trivy report for {name}")
    artifact_type = report.get("ArtifactType")
    if kind == "container":
        if artifact_type != "container_image":
            raise GateError(f"target {name} is not a container image report")
        metadata = report.get("Metadata")
        if not isinstance(metadata, dict):
            raise GateError(f"target {name} lacks image metadata")
        repo_digests = metadata.get("RepoDigests", [])
        image_id = metadata.get("ImageID")
        digest_bound = image_id == identity or (
            isinstance(repo_digests, list)
            and any(
                isinstance(item, str) and item.endswith(f"@{identity}")
                for item in repo_digests
            )
        )
        if not digest_bound:
            raise GateError(f"target {name} report is not bound to image digest {identity}")
    elif kind == "file":
        if artifact_type != "spdx":
            raise GateError(f"target {name} is not an SPDX report")
        if report.get("ArtifactName") != target["sbom"]["scan_subject_name"]:
            raise GateError(f"target {name} report is not bound to its SPDX SBOM")
    else:
        if artifact_type != "repository":
            raise GateError(f"target {name} is not a repository report")
        metadata = report.get("Metadata")
        if not isinstance(metadata, dict):
            raise GateError(f"target {name} lacks repository metadata")
        reported_repository = metadata.get("RepoURL")
        if reported_repository not in {source_repository, f"{source_repository}.git"}:
            raise GateError(f"target {name} report is not bound to the source repository")
        if metadata.get("Commit") != source_commit:
            raise GateError(f"target {name} report is not bound to the source commit")
    inventory.append(_inventory_item(report_path, base, "report", name))
    findings, package_count = _extract_findings(name, report)
    return name, actual_report, findings, package_count, inventory


def _load_dispositions(
    path: Path,
    findings: list[Finding],
    target_contexts: dict[str, dict[str, str]],
    source_commit: str,
    gate: dict[str, Any],
    now: datetime,
) -> tuple[str, list[dict[str, Any]]]:
    dispositions = _read_json(path, "vulnerability dispositions")
    if not isinstance(dispositions, dict) or dispositions.get("format_version") != 1:
        raise GateError("vulnerability dispositions format_version must be 1")
    _expect_exact_keys(
        dispositions,
        {"format_version", "findings"},
        "vulnerability dispositions",
    )
    entries = dispositions.get("findings")
    if not isinstance(entries, list):
        raise GateError("vulnerability dispositions findings must be a list")
    allowed = gate.get("allowed_dispositions")
    max_days = gate.get("max_disposition_days")
    if not isinstance(allowed, list) or not allowed or not isinstance(max_days, int):
        raise GateError("vulnerability disposition policy is invalid")
    expected = {finding.identity for finding in findings}
    observed: set[tuple[str, str, str, str]] = set()
    normalized: list[dict[str, Any]] = []
    entry_keys = {
        "target",
        "vulnerability_id",
        "package",
        "installed_version",
        "target_identity",
        "report_sha256",
        "database_metadata_sha256",
        "source_commit",
        "status",
        "owner",
        "rationale",
        "reviewed_at",
        "expires_at",
    }
    for entry in entries:
        if not isinstance(entry, dict):
            raise GateError("vulnerability disposition entry must be an object")
        _expect_exact_keys(entry, entry_keys, "vulnerability disposition entry")
        identity = (
            entry.get("target"),
            entry.get("vulnerability_id"),
            entry.get("package"),
            entry.get("installed_version"),
        )
        if any(not isinstance(value, str) or not value for value in identity):
            raise GateError("vulnerability disposition identity is invalid")
        if identity in observed:
            raise GateError(f"duplicate vulnerability disposition: {identity}")
        observed.add(identity)  # type: ignore[arg-type]
        if identity not in expected:
            raise GateError(f"unused vulnerability disposition: {identity}")
        target_context = target_contexts.get(str(entry.get("target")))
        if not isinstance(target_context, dict) or any(
            entry.get(field) != target_context.get(field)
            for field in (
                "target_identity",
                "report_sha256",
                "database_metadata_sha256",
            )
        ):
            raise GateError(
                f"vulnerability disposition is not bound to current target evidence: {identity}"
            )
        if entry.get("source_commit") != source_commit:
            raise GateError(
                "vulnerability disposition is not bound to "
                f"{source_commit}: {identity}"
            )
        if entry.get("status") not in allowed:
            raise GateError(f"unsupported vulnerability disposition status: {identity}")
        owner = entry.get("owner")
        rationale = entry.get("rationale")
        if (
            not isinstance(owner, str)
            or len(owner.strip()) < 3
            or owner.lower() in {"todo", "tbd", "unknown"}
        ):
            raise GateError(f"vulnerability disposition lacks a named owner: {identity}")
        if not isinstance(rationale, str) or len(rationale.strip()) < 20:
            raise GateError(f"vulnerability disposition rationale is too short: {identity}")
        reviewed = _parse_time(entry.get("reviewed_at"), f"disposition reviewed_at for {identity}")
        expires = _parse_time(entry.get("expires_at"), f"disposition expires_at for {identity}")
        if reviewed > now + timedelta(minutes=5) or expires <= now:
            raise GateError(f"vulnerability disposition is future-dated or expired: {identity}")
        if expires - reviewed > timedelta(days=max_days) or expires <= reviewed:
            raise GateError(f"vulnerability disposition validity is invalid: {identity}")
        normalized.append(entry)
    missing = expected - observed
    if missing:
        raise GateError(f"missing vulnerability dispositions: {sorted(missing)}")
    return _sha256(path), normalized


def verify(
    manifest_path: Path,
    policy_path: Path,
    dispositions_path: Path,
    profile: str,
    source_commit: str,
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    if not COMMIT_RE.fullmatch(source_commit):
        raise GateError("source commit must be a lowercase 40-character Git commit")
    manifest_path = _input_file(manifest_path, "vulnerability manifest")
    policy_path = _input_file(policy_path, "vulnerability policy")
    dispositions_path = _input_file(dispositions_path, "vulnerability dispositions")
    now = (now or datetime.now(UTC)).astimezone(UTC)
    policy, required_targets = _load_policy(policy_path, profile)
    manifest = _read_json(manifest_path, "vulnerability manifest")
    if not isinstance(manifest, dict) or manifest.get("format_version") != 1:
        raise GateError("vulnerability manifest format_version must be 1")
    _expect_exact_keys(
        manifest,
        {
            "format_version",
            "profile",
            "source_commit",
            "source_repository",
            "core_roots",
            "generated_at",
            "scanner",
            "targets",
        },
        "vulnerability manifest",
    )
    if manifest.get("profile") != profile or manifest.get("source_commit") != source_commit:
        raise GateError("vulnerability manifest profile/source commit mismatch")
    source_repository = policy.get("source_repository")
    if manifest.get("source_repository") != source_repository:
        raise GateError("vulnerability manifest source repository mismatch")
    base = manifest_path.resolve(strict=True).parent
    if dispositions_path.parent != base:
        raise GateError("vulnerability dispositions must be staged beside the manifest")
    core_roots = manifest.get("core_roots")
    if not isinstance(core_roots, list):
        raise GateError("vulnerability manifest core_roots must be a list")
    root_descriptors: list[dict[str, Any]] = []
    for root in core_roots:
        if not isinstance(root, dict):
            raise GateError("vulnerability manifest release root must be an object")
        root_descriptors.append(
            {
                "id": root.get("id"),
                "kind": root.get("kind"),
                "path": root.get("path"),
                "signature_bundle_path": root.get("signature_bundle_path"),
            }
        )
    try:
        required_roots, target_mappings = release_roots.policy_requirements(
            policy,
            profile,
            list(required_targets),
        )
        normalized_roots, root_adapters = release_roots.load_release_roots(
            base,
            root_descriptors,
            required_roots,
            source_repository,
            source_commit,
        )
    except release_roots.ReleaseRootError as error:
        raise GateError(f"release root admission failed: {error}") from error
    if core_roots != normalized_roots:
        raise GateError("vulnerability manifest release roots are not canonical")
    generated_at = _parse_time(manifest.get("generated_at"), "manifest generated_at")
    try:
        scanner_policy = scan_evidence.scanner_policy(policy)
    except scan_evidence.ScanEvidenceError as error:
        raise GateError(f"scanner execution policy is invalid: {error}") from error
    _validate_freshness(
        generated_at,
        now,
        scanner_policy.get("max_report_age_hours"),
        "vulnerability manifest",
    )
    scanner = manifest.get("scanner")
    if not isinstance(scanner, dict):
        raise GateError("vulnerability manifest scanner must be an object")
    _expect_exact_keys(
        scanner,
        {
            "binary_sha256",
            "binary_size",
            "configuration",
            "databases",
            "install_receipt_path",
            "install_receipt_sha256",
            "name",
            "version",
        },
        "manifest scanner",
    )
    if (
        scanner.get("name") != scanner_policy.get("name")
        or scanner.get("version") != scanner_policy.get("version")
    ):
        raise GateError("vulnerability scanner name/version does not match policy")
    try:
        install_receipt, install_path = scan_evidence.validate_install_receipt(
            base,
            scanner.get("install_receipt_path"),
            policy_path,
            policy,
        )
    except scan_evidence.ScanEvidenceError as error:
        raise GateError(f"scanner install evidence is invalid: {error}") from error
    if scanner.get("install_receipt_sha256") != _sha256(install_path):
        raise GateError("scanner install receipt SHA-256 mismatch")
    installed_binary = install_receipt["scanner"]["binary"]
    if (
        scanner.get("binary_sha256") != installed_binary["sha256"]
        or scanner.get("binary_size") != installed_binary["size"]
    ):
        raise GateError("manifest scanner binary differs from verified installation")
    configuration = scanner.get("configuration")
    if not isinstance(configuration, dict):
        raise GateError("manifest scanner configuration must be an object")
    _expect_exact_keys(configuration, {"config", "ignorefile"}, "scanner configuration")
    configuration_paths: dict[str, tuple[Path, str]] = {}
    for configuration_name, expected_sha in (
        ("config", scanner_policy["execution"]["config_sha256"]),
        ("ignorefile", scanner_policy["execution"]["ignorefile_sha256"]),
    ):
        record = configuration.get(configuration_name)
        if not isinstance(record, dict):
            raise GateError(f"scanner {configuration_name} must be an object")
        _expect_exact_keys(
            record,
            {"path", "sha256", "size"},
            f"scanner {configuration_name}",
        )
        path = _regular_file(base, record.get("path"), f"scanner {configuration_name}")
        digest = _expect_sha(record.get("sha256"), f"scanner {configuration_name} SHA-256")
        if (
            digest != expected_sha
            or _sha256(path) != digest
            or path.stat().st_size != record.get("size")
        ):
            raise GateError(f"scanner {configuration_name} is not policy-empty")
        configuration_paths[configuration_name] = (path, digest)
    databases = scanner.get("databases")
    if not isinstance(databases, dict):
        raise GateError("manifest scanner databases must be an object")
    _expect_exact_keys(databases, {"java", "vulnerability"}, "manifest scanner databases")
    database_evidence: dict[
        str,
        tuple[Path, str, Path, str, str, datetime, list[tuple[Path, str]]],
    ] = {}
    for database_name in ("vulnerability", "java"):
        database_evidence[database_name] = _validate_database_record(
            base,
            databases.get(database_name),
            scanner_policy["databases"][database_name],
            scanner_policy.get("max_database_age_hours"),
            database_name,
            now,
        )

    targets = manifest.get("targets")
    if not isinstance(targets, list):
        raise GateError("vulnerability manifest targets must be a list")
    names: list[str] = []
    for item in targets:
        if not isinstance(item, dict):
            raise GateError("vulnerability manifest target must be an object")
        name = item.get("name")
        if not isinstance(name, str) or not TARGET_RE.fullmatch(name):
            raise GateError("vulnerability manifest target name is invalid")
        names.append(name)
    if len(names) != len(set(names)):
        raise GateError("vulnerability manifest has duplicate target names")
    if set(names) != set(required_targets):
        raise GateError(
            "vulnerability target inventory mismatch: "
            f"missing={sorted(set(required_targets) - set(names))}, "
            f"unexpected={sorted(set(names) - set(required_targets))}"
        )
    report_digests: dict[str, str] = {}
    scanned_package_counts: dict[str, int] = {}
    target_contexts: dict[str, dict[str, str]] = {}
    findings: list[Finding] = []
    inventory = [
        _inventory_item(manifest_path, base, "manifest", "release"),
        _inventory_item(dispositions_path, base, "dispositions", "release"),
        _inventory_item(install_path, base, "scanner-install", "scanner"),
        _inventory_item(
            configuration_paths["config"][0], base, "scanner-config", "scanner"
        ),
        _inventory_item(
            configuration_paths["ignorefile"][0],
            base,
            "scanner-ignorefile",
            "scanner",
        ),
    ]
    scanner_asset_roles = {
        "archive": "scanner-archive",
        "binary": "scanner-binary",
        "checksums": "scanner-checksums",
        "sigstore_bundle": "scanner-checksums-signature",
    }
    for asset_name, role in scanner_asset_roles.items():
        asset = install_receipt["scanner"][asset_name]
        inventory.append(
            _inventory_item(
                _regular_file(base, asset["path"], f"scanner {asset_name}"),
                base,
                role,
                "scanner",
            )
        )
    for database_name, database_values in database_evidence.items():
        metadata_path, _, database_path, _, _, _, oci_paths = database_values
        inventory.extend(
            (
                _inventory_item(
                    metadata_path,
                    base,
                    "database-metadata",
                    f"{database_name}-database",
                ),
                _inventory_item(
                    database_path,
                    base,
                    "database-file",
                    f"{database_name}-database",
                ),
            )
        )
        for oci_path, oci_role in oci_paths:
            inventory.append(
                _inventory_item(
                    oci_path,
                    base,
                    f"database-oci-{oci_role}",
                    f"{database_name}-database",
                )
            )
    for root in normalized_roots:
        inventory.extend(
            (
                _inventory_item(
                    _regular_file(base, root["path"], f"release root {root['id']}"),
                    base,
                    "release-root",
                    root["id"],
                ),
                _inventory_item(
                    _regular_file(
                        base,
                        root["signature_bundle_path"],
                        f"release root {root['id']} signature bundle",
                    ),
                    base,
                    "release-root-signature",
                    root["id"],
                ),
            )
        )
    for target in targets:
        expected_kind = required_targets[target["name"]]
        if target.get("kind") != expected_kind:
            raise GateError(
                f"target {target['name']} kind must be {expected_kind}, "
                f"got {target.get('kind')!r}"
            )
        if target["name"] == "source":
            expected_target = {
                "name": "source",
                "kind": "source",
                "identity": f"git:{source_commit}",
            }
            authority = {
                "commit": source_commit,
                "repository": source_repository,
                "type": "source",
            }
            expected_subject = scan_evidence.expected_subject(
                "source", source_repository, expected_target["identity"]
            )
        else:
            mapping = target_mappings.get(target["name"])
            if not isinstance(mapping, dict):
                raise GateError(
                    f"release root mapping is missing for {target['name']}"
                )
            try:
                derived = release_roots.derive_target(
                    root_adapters,
                    mapping["root"],
                    mapping["selector"],
                )
            except release_roots.ReleaseRootError as error:
                raise GateError(
                    "release root target admission failed for "
                    f"{target['name']}: {error}"
                ) from error
            expected_target = _normalized_derived_target(target["name"], derived)
            root = next(
                (item for item in normalized_roots if item["id"] == mapping["root"]),
                None,
            )
            if not isinstance(root, dict):
                raise GateError(f"release root is missing for target {target['name']}")
            authority = {
                "root_id": mapping["root"],
                "root_kind": root["kind"],
                "selector": mapping["selector"],
                "type": "release-root",
            }
            if expected_target["kind"] == "container":
                image = expected_target.get("image")
                repository = image.get("repository") if isinstance(image, dict) else None
                if not isinstance(repository, str) or not repository:
                    raise GateError(
                        f"release root omitted image repository for {target['name']}"
                    )
                expected_subject = scan_evidence.expected_subject(
                    "container",
                    f"{repository}@{expected_target['identity']}",
                    expected_target["identity"],
                )
            else:
                sbom = expected_target["sbom"]
                expected_subject = {
                    "argument": sbom["scan_subject_name"],
                    "evidence_path": sbom["path"],
                    "hash_kind": "content",
                    "identity": f"sha256:{sbom['sha256']}",
                    "sha256": sbom["sha256"],
                    "size": sbom["size"],
                }
        observed_target = {
            key: value
            for key, value in target.items()
            if key
            not in {
                "report_path",
                "report_sha256",
                "scan_execution_path",
                "scan_execution_sha256",
            }
        }
        if observed_target != expected_target:
            raise GateError(
                f"target {target['name']} differs from its signed release root"
            )
        try:
            scan_execution = scan_evidence.validate_execution_receipt(
                base,
                target.get("scan_execution_path"),
                policy_path,
                policy,
                expected_target,
                authority,
                expected_subject,
            )
        except scan_evidence.ScanEvidenceError as error:
            raise GateError(
                f"target {target['name']} scan execution is invalid: {error}"
            ) from error
        execution_finished = _parse_time(
            scan_execution["execution"]["finished_at"],
            f"target {target['name']} scan finished_at",
        )
        _validate_freshness(
            execution_finished,
            now,
            scanner_policy.get("max_report_age_hours"),
            f"target {target['name']} scan execution",
        )
        if execution_finished > generated_at + timedelta(minutes=5):
            raise GateError(
                f"target {target['name']} scan completed after the manifest"
            )
        execution_path = scan_execution["execution_path"]
        if _sha256(execution_path) != _expect_sha(
            target.get("scan_execution_sha256"),
            f"target {target['name']} scan execution SHA-256",
        ):
            raise GateError(f"target {target['name']} scan execution SHA-256 mismatch")
        if (
            scan_execution["report_path"].relative_to(base).as_posix()
            != target.get("report_path")
            or scan_execution["report_sha256"] != target.get("report_sha256")
        ):
            raise GateError(f"target {target['name']} report differs from scan execution")
        execution_value = scan_execution["execution"]
        execution_scanner = {
            "configuration": execution_value["configuration"],
            "databases": execution_value["databases"],
            "install_receipt_path": execution_value["scanner"][
                "install_receipt_path"
            ],
            "install_receipt_sha256": execution_value["scanner"][
                "install_receipt_sha256"
            ],
            "binary_sha256": execution_value["scanner"]["binary_sha256"],
            "binary_size": execution_value["scanner"]["binary_size"],
            "name": execution_value["scanner"]["name"],
            "version": execution_value["scanner"]["version"],
        }
        if execution_scanner != scanner:
            raise GateError(
                f"target {target['name']} used a different scanner/database snapshot"
            )
        (
            name,
            report_digest,
            target_findings,
            package_count,
            target_inventory,
        ) = _validate_target(
            base,
            target,
            source_commit,
            source_repository,
            scanner_policy.get("report_schema_version"),
            scanner_policy.get("max_report_age_hours"),
            now,
        )
        report_digests[name] = report_digest
        scanned_package_counts[name] = package_count
        target_contexts[name] = {
            "target_identity": target["identity"],
            "report_sha256": report_digest,
            "database_metadata_sha256": database_evidence["vulnerability"][1],
        }
        findings.extend(target_findings)
        inventory.extend(target_inventory)
        inventory.append(
            _inventory_item(
                scan_execution["raw_report_path"],
                base,
                "raw-report",
                target["name"],
            )
        )
        inventory.append(
            _inventory_item(execution_path, base, "scan-execution", target["name"])
        )

    inventory_paths = [item["path"] for item in inventory]
    if len(inventory_paths) != len(set(inventory_paths)):
        raise GateError("vulnerability evidence inventory reuses a file path")
    inventory.sort(key=lambda item: (item["role"], item["target"], item["path"]))

    gate = policy["gate"]
    blocked = gate.get("blocked_severities")
    reviewed = gate.get("review_required_severities")
    if not isinstance(blocked, list) or not isinstance(reviewed, list):
        raise GateError("vulnerability severity policy is invalid")
    known = set(blocked) | set(reviewed)
    unexpected_severity = sorted({finding.severity for finding in findings} - known)
    if unexpected_severity:
        raise GateError(f"unsupported vulnerability severities: {unexpected_severity}")
    release_blockers = [finding for finding in findings if finding.severity in blocked]
    if release_blockers:
        summary = sorted(
            f"{finding.target}:{finding.vulnerability_id}:{finding.package}:{finding.severity}"
            for finding in release_blockers
        )
        raise GateError(f"release-blocking vulnerabilities: {summary}")
    review_findings = [finding for finding in findings if finding.severity in reviewed]
    disposition_sha, dispositions = _load_dispositions(
        dispositions_path,
        review_findings,
        target_contexts,
        source_commit,
        gate,
        now,
    )
    counts = {severity: 0 for severity in sorted(known)}
    for finding in findings:
        counts[finding.severity] += 1
    return {
        "format_version": 1,
        "status": "passed",
        "profile": profile,
        "source_commit": source_commit,
        "source_repository": source_repository,
        "core_roots": normalized_roots,
        "verified_at": now.isoformat().replace("+00:00", "Z"),
        "manifest_sha256": _sha256(manifest_path),
        "policy_sha256": _sha256(policy_path),
        "dispositions_sha256": disposition_sha,
        "scanner": {
            "name": scanner["name"],
            "version": scanner["version"],
            "binary_sha256": scanner["binary_sha256"],
            "scanner_install_receipt_sha256": scanner[
                "install_receipt_sha256"
            ],
            "config_sha256": configuration_paths["config"][1],
            "ignorefile_sha256": configuration_paths["ignorefile"][1],
            "vulnerability_database_oci_digest": database_evidence[
                "vulnerability"
            ][4],
            "vulnerability_database_metadata_sha256": database_evidence[
                "vulnerability"
            ][1],
            "vulnerability_database_sha256": database_evidence["vulnerability"][3],
            "vulnerability_database_updated_at": database_evidence[
                "vulnerability"
            ][5]
            .isoformat()
            .replace("+00:00", "Z"),
            "java_database_oci_digest": database_evidence["java"][4],
            "java_database_metadata_sha256": database_evidence["java"][1],
            "java_database_sha256": database_evidence["java"][3],
            "java_database_updated_at": database_evidence["java"][5]
            .isoformat()
            .replace("+00:00", "Z"),
        },
        "report_sha256": dict(sorted(report_digests.items())),
        "scanned_package_counts": dict(sorted(scanned_package_counts.items())),
        "evidence_inventory": inventory,
        "finding_counts": counts,
        "reviewed_dispositions": len(dispositions),
    }


def _canonical_receipt(receipt: dict[str, Any]) -> bytes:
    return (
        json.dumps(
            receipt,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
        + b"\n"
    )


def _write_no_replace(path: Path, receipt: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    content = _canonical_receipt(receipt)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    descriptor = os.open(path, flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as destination:
            destination.write(content)
            destination.flush()
            os.fsync(destination.fileno())
    except BaseException:
        try:
            os.close(descriptor)
        except OSError:
            pass
        raise


def verify_recorded_receipt(
    receipt_path: Path,
    manifest_path: Path,
    policy_path: Path,
    dispositions_path: Path,
    profile: str,
    source_commit: str,
    *,
    now: datetime | None = None,
    max_receipt_age_hours: int | None = None,
) -> dict[str, Any]:
    receipt_path = _input_file(receipt_path, "vulnerability receipt")
    recorded = _read_json(receipt_path, "vulnerability receipt")
    if not isinstance(recorded, dict):
        raise GateError("vulnerability receipt must be an object")
    if receipt_path.read_bytes() != _canonical_receipt(recorded):
        raise GateError("vulnerability receipt is not canonical JSON")
    verified_at = _parse_time(recorded.get("verified_at"), "receipt verified_at")
    current = (now or datetime.now(UTC)).astimezone(UTC)
    if verified_at > current + timedelta(minutes=5):
        raise GateError("vulnerability receipt is future-dated")
    if max_receipt_age_hours is not None:
        _validate_freshness(
            verified_at,
            current,
            max_receipt_age_hours,
            "vulnerability receipt",
        )
    expected = verify(
        manifest_path,
        policy_path,
        dispositions_path,
        profile,
        source_commit,
        now=verified_at,
    )
    if recorded != expected:
        raise GateError("vulnerability receipt does not match the verified evidence")
    return recorded


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "command",
        nargs="?",
        choices=("create-receipt", "verify-receipt"),
        default="create-receipt",
    )
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--dispositions", type=Path, required=True)
    parser.add_argument("--profile", required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--max-receipt-age-hours", type=int)
    arguments = parser.parse_args()
    try:
        scan_evidence.require_isolated_python()
        if arguments.command == "verify-receipt":
            receipt = verify_recorded_receipt(
                arguments.receipt,
                arguments.manifest,
                arguments.policy,
                arguments.dispositions,
                arguments.profile,
                arguments.source_commit,
                max_receipt_age_hours=arguments.max_receipt_age_hours,
            )
        else:
            if arguments.max_receipt_age_hours is not None:
                raise GateError("--max-receipt-age-hours applies only to verify-receipt")
            receipt = verify(
                arguments.manifest,
                arguments.policy,
                arguments.dispositions,
                arguments.profile,
                arguments.source_commit,
            )
            _write_no_replace(arguments.receipt, receipt)
    except (GateError, OSError) as error:
        print(f"vulnerability-gate: {error}", file=sys.stderr)
        return 1
    print(
        f"vulnerability-gate: {arguments.command} passed {receipt['profile']} with "
        f"{sum(receipt['finding_counts'].values())} findings"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
