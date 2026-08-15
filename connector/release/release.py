#!/usr/bin/env python3
"""Reproducible Connector release builder and fail-closed verifier.

The local-unsigned mode exists only to exercise deterministic compilation and
metadata validation. It cannot be promoted or signed by this tool.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import datetime as dt
import hashlib
import json
import os
import platform
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path, PurePosixPath
from typing import Any

SCRIPT_PATH = Path(__file__).resolve()
RELEASE_DIR = SCRIPT_PATH.parent
CONNECTOR_DIR = RELEASE_DIR.parent
REPO_ROOT = CONNECTOR_DIR.parent
PACKAGING_DIR = CONNECTOR_DIR / "packaging"
LINUX_PACKAGE_BUILDER = PACKAGING_DIR / "build-linux-packages.sh"
PACKAGE_CONTENT_VERIFIER = PACKAGING_DIR / "verify-package-contents.sh"
THIRD_PARTY_DIR = REPO_ROOT / "third_party"
DEFAULT_CONFIG = RELEASE_DIR / "release-config.json"
WORK_STATE = ".release-work.json"
LOCAL_MARKER = "RELEASE-NOT-FOR-DISTRIBUTION"
MANIFEST = "manifest.json"
CHECKSUMS = "SHA256SUMS"
CONNECTOR_RELEASE_METADATA = "connector-release-metadata.json"
PUBLIC_RELEASE_DESCRIPTOR = "connector-public-release-descriptor.json"
AGGREGATE_RECEIPT = "connector-public-verification-aggregate.json"
AGGREGATE_RECEIPT_BUNDLE = f"{AGGREGATE_RECEIPT}.sigstore.json"
PLATFORM_RECEIPTS = {
    "linux": "connector-public-verification-linux.json",
    "darwin": "connector-public-verification-darwin.json",
}
VULNERABILITY_MANIFEST = "vulnerability-manifest.json"
VULNERABILITY_RECEIPT = "vulnerability-receipt.json"
VULNERABILITY_RECEIPT_BUNDLE = "vulnerability-receipt.sigstore.json"
VULNERABILITY_PUBLIC_PREFIX = "vulnerability-evidence-"
VULNERABILITY_PUBLIC_FIXED_ASSETS = {
    VULNERABILITY_RECEIPT,
    VULNERABILITY_RECEIPT_BUNDLE,
}
CONNECTOR_VULNERABILITY_TARGET_SPECS = {
    "connector-linux-amd64-deb": ("linux", "amd64", "deb"),
    "connector-linux-amd64-rpm": ("linux", "amd64", "rpm"),
    "connector-linux-arm64-deb": ("linux", "arm64", "deb"),
    "connector-linux-arm64-rpm": ("linux", "arm64", "rpm"),
    "connector-darwin-amd64-pkg": ("darwin", "amd64", "pkg"),
    "connector-darwin-arm64-pkg": ("darwin", "arm64", "pkg"),
}
RELEASE_REPOSITORY = "https://github.com/peter2317238492/sub2api-codex-control"
OIDC_ISSUER = "https://token.actions.githubusercontent.com"
SLSA_PREDICATE = "https://slsa.dev/provenance/v1"
IN_TOTO_STATEMENT = "https://in-toto.io/Statement/v1"
HEX_SHA256 = re.compile(r"^[0-9a-f]{64}$")
HEX_SHA1 = re.compile(r"^[0-9a-f]{40}$")
HEX_GIT_COMMIT = re.compile(r"^[0-9a-f]{40}$")
SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
SAFE_PATH_COMPONENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+@-]*$")
APPLE_TEAM_ID = re.compile(r"^[A-Z0-9]{10}$")
RPM_FINGERPRINT = re.compile(r"^[A-F0-9]{40,64}$")
PINNED_GO_ENV = {
    "CGO_ENABLED": "0",
    "GOAMD64": "v1",
    "GOARM64": "v8.0",
    "GOENV": "off",
    "GOEXPERIMENT": "",
    "GOFIPS140": "off",
    "GOTOOLCHAIN": "local",
}


class ReleaseError(RuntimeError):
    pass


def canonical_json(value: Any) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            indent=2,
            separators=(",", ": "),
        )
        + "\n"
    ).encode()


def compact_canonical_json(value: Any) -> bytes:
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


def reject_duplicate_json_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ReleaseError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def reject_nonfinite_json_number(value: str) -> Any:
    raise ReleaseError(f"non-finite JSON number {value!r}")


def read_json(path: Path) -> Any:
    try:
        with path.open("r", encoding="utf-8") as handle:
            return json.load(
                handle,
                object_pairs_hook=reject_duplicate_json_keys,
                parse_constant=reject_nonfinite_json_number,
            )
    except (OSError, json.JSONDecodeError) as exc:
        raise ReleaseError(f"cannot read valid JSON from {path}: {exc}") from exc


def read_canonical_json(path: Path, context: str) -> Any:
    value = read_json(path)
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise ReleaseError(f"cannot read {context} bytes from {path}: {exc}") from exc
    if raw != canonical_json(value):
        raise ReleaseError(f"{context} is not canonical JSON")
    return value


def write_json(path: Path, value: Any) -> None:
    content = canonical_json(value)
    descriptor = -1
    temporary_name = ""
    try:
        descriptor, temporary_name = tempfile.mkstemp(
            dir=path.parent, prefix=f".{path.name}."
        )
        os.fchmod(descriptor, 0o644)
    except OSError as exc:
        raise ReleaseError(f"cannot safely write JSON output {path}: {exc}") from exc
    try:
        with os.fdopen(descriptor, "wb") as destination:
            descriptor = -1
            destination.write(content)
            destination.flush()
            os.fsync(destination.fileno())
        os.replace(temporary_name, path)
        temporary_name = ""
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if temporary_name:
            try:
                Path(temporary_name).unlink()
            except OSError:
                pass


def write_exclusive_canonical_json(path: Path, value: Any) -> None:
    write_exclusive_bytes(path, canonical_json(value))


def write_exclusive_bytes(path: Path, content: bytes, mode: int = 0o644) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags, mode)
    except OSError as exc:
        raise ReleaseError(f"refusing to replace canonical output {path}: {exc}") from exc
    try:
        with os.fdopen(descriptor, "wb") as destination:
            destination.write(content)
            destination.flush()
            os.fsync(destination.fileno())
    except BaseException:
        try:
            path.unlink()
        except OSError:
            pass
        raise


def copy_exclusive_file(source: Path, destination: Path, mode: int = 0o644) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(destination, flags, mode)
    except OSError as exc:
        raise ReleaseError(f"refusing to replace file output {destination}: {exc}") from exc
    try:
        with source.open("rb") as input_file, os.fdopen(descriptor, "wb") as output_file:
            descriptor = -1
            shutil.copyfileobj(input_file, output_file)
            output_file.flush()
            os.fsync(output_file.fileno())
            os.fchmod(output_file.fileno(), mode)
    except BaseException:
        try:
            destination.unlink()
        except OSError:
            pass
        raise
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def release_output_directory(path: Path, *, allow_missing: bool = False) -> Path:
    absolute = path.absolute()
    try:
        mode = absolute.lstat().st_mode
    except FileNotFoundError:
        if not allow_missing:
            raise ReleaseError(f"release output directory does not exist: {absolute}")
        try:
            parent = absolute.parent.resolve(strict=True)
        except OSError as exc:
            raise ReleaseError(f"cannot inspect release output parent: {exc}") from exc
        if not parent.is_dir():
            raise ReleaseError("release output parent must be a directory")
        return parent / absolute.name
    except OSError as exc:
        raise ReleaseError(f"cannot inspect release output directory: {exc}") from exc
    try:
        resolved = absolute.resolve(strict=True)
    except OSError as exc:
        raise ReleaseError(f"cannot resolve release output directory: {exc}") from exc
    if not stat.S_ISDIR(mode) or absolute.is_symlink():
        raise ReleaseError("release output must be a real non-symlink directory")
    return resolved


def read_compact_canonical_json(path: Path, context: str) -> Any:
    value = read_json(path)
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise ReleaseError(f"cannot read {context} bytes from {path}: {exc}") from exc
    if raw != compact_canonical_json(value):
        raise ReleaseError(f"{context} is not compact canonical JSON")
    return value


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def sha1_file(path: Path) -> str:
    digest = hashlib.sha1()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def iso8601(epoch: int) -> str:
    return (
        dt.datetime.fromtimestamp(epoch, tz=dt.timezone.utc)
        .isoformat()
        .replace("+00:00", "Z")
    )


def run(
    command: list[str],
    *,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
    capture: bool = False,
) -> str:
    try:
        result = subprocess.run(
            command,
            cwd=cwd,
            env=env,
            check=True,
            text=True,
            stdout=subprocess.PIPE if capture else None,
            stderr=subprocess.PIPE if capture else None,
        )
    except FileNotFoundError as exc:
        raise ReleaseError(f"required executable is unavailable: {command[0]}") from exc
    except subprocess.CalledProcessError as exc:
        output = "\n".join(
            part.strip() for part in (exc.stdout, exc.stderr) if part and part.strip()
        )
        suffix = f": {output}" if output else ""
        raise ReleaseError(f"command failed ({' '.join(command)}){suffix}") from exc
    return result.stdout.strip() if capture else ""


def run_combined(command: list[str]) -> str:
    try:
        result = subprocess.run(
            command,
            check=True,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
    except FileNotFoundError as exc:
        raise ReleaseError(f"required executable is unavailable: {command[0]}") from exc
    except subprocess.CalledProcessError as exc:
        output = exc.stdout.strip() if exc.stdout else ""
        raise ReleaseError(f"command failed ({' '.join(command)}): {output}") from exc
    return result.stdout.strip()


def validate_apple_identity(team_id: str, signing_identity: str) -> None:
    if not isinstance(team_id, str) or not APPLE_TEAM_ID.fullmatch(team_id):
        raise ReleaseError(
            "expected Apple TeamIdentifier must be exactly 10 uppercase alphanumeric characters"
        )
    if (
        not isinstance(signing_identity, str)
        or "\n" in signing_identity
        or not signing_identity.startswith("Developer ID Application: ")
        or not signing_identity.endswith(f" ({team_id})")
    ):
        raise ReleaseError(
            "expected Apple signing identity must be the full Developer ID Application identity"
        )


def validate_apple_installer_identity(team_id: str, signing_identity: str) -> None:
    if (
        not isinstance(signing_identity, str)
        or "\n" in signing_identity
        or not signing_identity.startswith("Developer ID Installer: ")
        or not signing_identity.endswith(f" ({team_id})")
    ):
        raise ReleaseError(
            "expected Apple installer identity must be the full Developer ID Installer identity"
        )


def validate_rpm_fingerprint(fingerprint: str) -> None:
    if not isinstance(fingerprint, str) or not RPM_FINGERPRINT.fullmatch(fingerprint):
        raise ReleaseError(
            "expected RPM signing fingerprint must be 40 to 64 uppercase hexadecimal characters"
        )


def verify_codesign_identity(
    artifact: Path, team_id: str, signing_identity: str
) -> str:
    validate_apple_identity(team_id, signing_identity)
    run(
        ["codesign", "--verify", "--strict", "--verbose=2", str(artifact)], capture=True
    )
    report = run_combined(["codesign", "-d", "--verbose=4", str(artifact)])
    lines = report.splitlines()
    if (
        f"Authority={signing_identity}" not in lines
        or f"TeamIdentifier={team_id}" not in lines
    ):
        raise ReleaseError(f"Apple signature identity mismatch: {artifact.name}")
    return report


def validate_native_evidence(
    evidence: Any,
    *,
    target_id: str,
    artifact_name_value: str,
    artifact_sha256: str,
    expected_team_id: str,
    expected_signing_identity: str,
) -> None:
    if not isinstance(evidence, dict):
        raise ReleaseError(f"invalid native-signature evidence for {target_id}")
    require_exact_keys(
        evidence,
        {
            "format_version",
            "target",
            "artifact",
            "artifact_sha256",
            "signing_identity",
            "team_identifier",
            "codesign_report",
        },
        "native-signature evidence",
    )
    validate_apple_identity(expected_team_id, expected_signing_identity)
    report = evidence["codesign_report"]
    if (
        evidence["format_version"] != 2
        or evidence["target"] != target_id
        or evidence["artifact"] != artifact_name_value
        or evidence["artifact_sha256"] != artifact_sha256
        or evidence["team_identifier"] != expected_team_id
        or evidence["signing_identity"] != expected_signing_identity
        or not isinstance(report, list)
        or not all(isinstance(line, str) for line in report)
        or f"Authority={expected_signing_identity}" not in report
        or f"TeamIdentifier={expected_team_id}" not in report
        or not any(re.match(r"^flags=.*\(runtime\)", line) for line in report)
        or not any(line.startswith("Timestamp=") for line in report)
    ):
        raise ReleaseError(
            f"native-signature evidence does not match trust policy for {target_id}"
        )


def require_exact_keys(value: dict[str, Any], expected: set[str], context: str) -> None:
    actual = set(value)
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        raise ReleaseError(f"{context} keys mismatch; missing={missing}, extra={extra}")


def load_config(path: Path) -> dict[str, Any]:
    config = read_json(path)
    if not isinstance(config, dict):
        raise ReleaseError("release config must be a JSON object")
    require_exact_keys(
        config,
        {
            "format_version",
            "product",
            "connector_version",
            "control_protocol_version",
            "codex_version",
            "appserver_schema_sha256",
            "server_api_release",
            "go_version",
            "go_build_environment",
            "cosign_version",
            "source_workflow",
            "targets",
        },
        "release config",
    )
    if config["format_version"] != 1 or config["product"] != "sub2api-codex-connector":
        raise ReleaseError("unsupported release config format or product")
    if not re.fullmatch(r"\d+\.\d+\.\d+", config["connector_version"]):
        raise ReleaseError("connector_version must be an exact semantic version")
    if config["control_protocol_version"] != 1:
        raise ReleaseError("only control protocol version 1 is admitted")
    if not HEX_SHA256.fullmatch(config["appserver_schema_sha256"]):
        raise ReleaseError("appserver_schema_sha256 must be lowercase SHA-256")
    if not re.fullmatch(r"go\d+\.\d+\.\d+", config["go_version"]):
        raise ReleaseError("go_version must pin an exact patch release")
    if config["go_build_environment"] != PINNED_GO_ENV:
        raise ReleaseError(
            "go_build_environment must exactly match the admitted portable build environment"
        )
    if not re.fullmatch(r"v\d+\.\d+\.\d+", config["cosign_version"]):
        raise ReleaseError("cosign_version must pin an exact release")
    server_range = config["server_api_release"]
    if not isinstance(server_range, dict):
        raise ReleaseError("server_api_release must be an object")
    require_exact_keys(server_range, {"minimum", "maximum"}, "server_api_release")
    target_ids: set[str] = set()
    for target in config["targets"]:
        if not isinstance(target, dict):
            raise ReleaseError("each target must be an object")
        require_exact_keys(
            target,
            {"id", "goos", "goarch", "native_signature", "packages"},
            "target",
        )
        expected_id = f"{target['goos']}-{target['goarch']}"
        if target["id"] != expected_id or not SAFE_NAME.fullmatch(expected_id):
            raise ReleaseError(f"invalid target id {target['id']!r}")
        if target["id"] in target_ids:
            raise ReleaseError(f"duplicate target {target['id']}")
        target_ids.add(target["id"])
        expected_native = (
            "apple-developer-id-and-notarization"
            if target["goos"] == "darwin"
            else "none"
        )
        if target["native_signature"] != expected_native:
            raise ReleaseError(
                f"target {target['id']} has an invalid native-signature policy"
            )
        packages = target["packages"]
        if not isinstance(packages, list) or not packages:
            raise ReleaseError(f"target {target['id']} has no native packages")
        expected_packages = (
            [
                {"format": "deb", "native_signature": "none"},
                {"format": "rpm", "native_signature": "rpm-openpgp"},
            ]
            if target["goos"] == "linux"
            else [
                {
                    "format": "pkg",
                    "native_signature": "apple-developer-id-installer-notarized-stapled",
                }
            ]
        )
        if packages != expected_packages:
            raise ReleaseError(
                f"target {target['id']} does not contain the complete native package matrix"
            )
    if target_ids != {"linux-amd64", "linux-arm64", "darwin-amd64", "darwin-arm64"}:
        raise ReleaseError(
            "release config must contain the complete supported target matrix"
        )
    validate_source_constants(config)
    return config


def validate_source_constants(config: dict[str, Any]) -> None:
    source = (CONNECTOR_DIR / "internal/config/config.go").read_text(encoding="utf-8")
    expected = {
        "DefaultConnectorVersion": config["connector_version"],
        "DefaultCodexVersion": config["codex_version"],
        "PinnedSchemaDigest": config["appserver_schema_sha256"],
    }
    for constant, value in expected.items():
        if not re.search(rf"\b{constant}\s*=\s*\"{re.escape(value)}\"", source):
            raise ReleaseError(
                f"release config does not match Connector constant {constant}"
            )
    protocol = (CONNECTOR_DIR / "internal/protocol/protocol.go").read_text(
        encoding="utf-8"
    )
    if not re.search(
        rf"\bVersion\s*=\s*{config['control_protocol_version']}\b", protocol
    ):
        raise ReleaseError("release config does not match Connector protocol version")
    schema = read_json(
        REPO_ROOT / "packages/control-protocol/schema/control-envelope.schema.json"
    )
    if (
        schema.get("properties", {}).get("version", {}).get("const")
        != config["control_protocol_version"]
    ):
        raise ReleaseError("release config does not match control-envelope schema")
    lock = read_json(REPO_ROOT / "versions.lock.json")
    if not isinstance(lock, dict) or lock.get("format_version") != 1:
        raise ReleaseError("versions.lock.json has an unsupported format")
    codex_lock = lock.get("codex")
    control_lock = lock.get("control_protocol")
    if not isinstance(codex_lock, dict) or not isinstance(control_lock, dict):
        raise ReleaseError("versions.lock.json lacks Codex or control-protocol locks")
    if (
        codex_lock.get("cli_version") != config["codex_version"]
        or codex_lock.get("schema_sha256") != config["appserver_schema_sha256"]
    ):
        raise ReleaseError("release config does not match the Codex lock")
    appserver_schema = locked_repo_file(
        codex_lock.get("schema_file"), "Codex app-server schema"
    )
    if sha256_file(appserver_schema) != config["appserver_schema_sha256"]:
        raise ReleaseError(
            "pinned Codex app-server schema digest does not match its file"
        )
    if control_lock.get("version") != config["control_protocol_version"]:
        raise ReleaseError("release config does not match the control-protocol lock")
    for key, value in control_lock.items():
        if not key.endswith("_file"):
            continue
        digest_key = f"{key.removesuffix('_file')}_sha256"
        expected_digest = control_lock.get(digest_key)
        if not isinstance(expected_digest, str) or not HEX_SHA256.fullmatch(
            expected_digest
        ):
            raise ReleaseError(
                f"versions.lock.json lacks a valid digest for control_protocol.{key}"
            )
        locked_path = locked_repo_file(value, f"control_protocol.{key}")
        if sha256_file(locked_path) != expected_digest:
            raise ReleaseError(
                f"versions.lock.json digest drift for control_protocol.{key}"
            )


def locked_repo_file(value: Any, context: str) -> Path:
    if not isinstance(value, str) or not value or Path(value).is_absolute():
        raise ReleaseError(f"{context} path is invalid in versions.lock.json")
    path = (REPO_ROOT / value).resolve()
    if REPO_ROOT != path and REPO_ROOT not in path.parents:
        raise ReleaseError(f"{context} escapes the repository")
    if not path.is_file() or path.is_symlink():
        raise ReleaseError(f"{context} is missing or is not a regular file")
    return path


def source_snapshot_sha256() -> str:
    lock = read_json(REPO_ROOT / "versions.lock.json")
    codex_lock = lock.get("codex", {}) if isinstance(lock, dict) else {}
    roots = [
        CONNECTOR_DIR,
        REPO_ROOT / "packages/control-protocol",
        locked_repo_file(codex_lock.get("schema_file"), "Codex app-server schema"),
        REPO_ROOT / "versions.lock.json",
        REPO_ROOT / ".github/workflows/connector-release.yml",
        REPO_ROOT / "LICENSE",
        REPO_ROOT / "NOTICE",
        REPO_ROOT / "THIRD_PARTY_NOTICES.md",
        REPO_ROOT / "third_party",
    ]
    selected: list[Path] = []
    for root in roots:
        if root.is_file():
            selected.append(root)
            continue
        for path in root.rglob("*"):
            if not path.is_file() or path.is_symlink() or ".release-work" in path.parts:
                continue
            if PACKAGING_DIR in path.parents or THIRD_PARTY_DIR in path.parents or path.suffix in {
                ".go",
                ".json",
                ".md",
                ".plist",
                ".py",
                ".service",
                ".sh",
                ".yml",
                ".yaml",
            } or path.name in {"go.mod", "go.sum"}:
                selected.append(path)
    digest = hashlib.sha256()
    for path in sorted(selected, key=lambda item: str(item.relative_to(REPO_ROOT))):
        relative = str(path.relative_to(REPO_ROOT)).replace(os.sep, "/").encode()
        digest.update(len(relative).to_bytes(4, "big"))
        digest.update(relative)
        content = path.read_bytes()
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)
    return digest.hexdigest()


def require_annotated_tag(tag: str, expected_commit: str) -> None:
    if run(["git", "cat-file", "-t", tag], cwd=REPO_ROOT, capture=True) != "tag":
        raise ReleaseError("release tags must be annotated tag objects")
    peeled_commit = run(
        ["git", "rev-parse", f"{tag}^{{commit}}"], cwd=REPO_ROOT, capture=True
    )
    if peeled_commit != expected_commit:
        raise ReleaseError("release tag does not resolve to the expected source commit")


def clean_release_preflight(
    config: dict[str, Any], source_commit: str, repository: str, builder_id: str
) -> None:
    version = config["connector_version"]
    expected_tag = f"connector-v{version}"
    if os.environ.get("GITHUB_ACTIONS") != "true":
        raise ReleaseError(
            "release mode is restricted to the protected GitHub Actions environment"
        )
    expected_repo = os.environ.get("GITHUB_REPOSITORY", "")
    expected_ref = os.environ.get("GITHUB_REF", "")
    if (
        os.environ.get("GITHUB_REF_TYPE") != "tag"
        or os.environ.get("GITHUB_REF_NAME") != expected_tag
    ):
        raise ReleaseError(
            f"release mode requires the exact annotated tag {expected_tag}"
        )
    if expected_ref != f"refs/tags/{expected_tag}":
        raise ReleaseError("release ref is not the expected tag ref")
    if os.environ.get("GITHUB_SHA") != source_commit or not HEX_GIT_COMMIT.fullmatch(
        source_commit
    ):
        raise ReleaseError("release source commit must equal the GitHub event SHA")
    if repository != f"https://github.com/{expected_repo}":
        raise ReleaseError("release source repository does not match GITHUB_REPOSITORY")
    if repository != RELEASE_REPOSITORY:
        raise ReleaseError("release source repository is not the official public repository")
    expected_builder = (
        f"https://github.com/{expected_repo}/{config['source_workflow']}@{expected_ref}"
    )
    if builder_id != expected_builder:
        raise ReleaseError(
            "release builder identity does not match the protected workflow and tag"
        )
    head = run(["git", "rev-parse", "HEAD"], cwd=REPO_ROOT, capture=True)
    if head != source_commit:
        raise ReleaseError("checked-out HEAD does not match the release source commit")
    if run(
        ["git", "status", "--porcelain", "--untracked-files=all"],
        cwd=REPO_ROOT,
        capture=True,
    ):
        raise ReleaseError("release builds require a clean worktree")
    require_annotated_tag(expected_tag, source_commit)


def go_version(go_binary: str) -> str:
    output = run([go_binary, "version"], capture=True)
    match = re.search(r"\b(go\d+\.\d+(?:\.\d+)?)\b", output)
    if not match:
        raise ReleaseError(f"cannot parse Go version from {output!r}")
    return match.group(1)


def build_environment(
    *,
    goos: str | None,
    goarch: str | None,
    source_date_epoch: int,
    module_cache: Path | None,
    build_cache: Path,
) -> dict[str, str]:
    env = os.environ.copy()
    env.update(
        {
            **PINNED_GO_ENV,
            "GOWORK": "off",
            "GOFLAGS": "-mod=readonly -trimpath -buildvcs=false",
            "GOCACHE": str(build_cache),
            "SOURCE_DATE_EPOCH": str(source_date_epoch),
            "TZ": "UTC",
            "LC_ALL": "C",
        }
    )
    if goos:
        env["GOOS"] = goos
    if goarch:
        env["GOARCH"] = goarch
    if module_cache is not None:
        env["GOMODCACHE"] = str(module_cache)
    return env


def artifact_name(config: dict[str, Any], target: dict[str, str]) -> str:
    return f"{config['product']}_{config['connector_version']}_{target['goos']}_{target['goarch']}"


def artifact_provenance_target(target: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": target["id"],
        "goos": target["goos"],
        "goarch": target["goarch"],
        "native_signature": target["native_signature"],
    }


def package_name(
    config: dict[str, Any], target: dict[str, Any], package_format: str
) -> str:
    return f"{artifact_name(config, target)}.{package_format}"


def select_targets(
    config: dict[str, Any], requested: list[str] | None, mode: str
) -> list[dict[str, str]]:
    targets = config["targets"]
    if not requested:
        return targets
    if mode == "release":
        raise ReleaseError("release mode cannot narrow the supported target matrix")
    wanted = set(requested)
    selected = [target for target in targets if target["id"] in wanted]
    if len(selected) != len(wanted):
        raise ReleaseError(
            f"unknown targets: {sorted(wanted - {item['id'] for item in selected})}"
        )
    return selected


def prepare(args: argparse.Namespace) -> None:
    config = load_config(args.config)
    output = release_output_directory(args.output, allow_missing=True)
    if output.exists() and any(output.iterdir()):
        raise ReleaseError(f"output directory must be absent or empty: {output}")
    mode = args.mode
    actual_go = go_version(args.go)
    source_commit = args.source_commit
    source_repository = args.source_repository
    builder_id = args.builder_id
    invocation_id = args.invocation_id
    if mode == "release":
        clean_release_preflight(config, source_commit, source_repository, builder_id)
        if actual_go != config["go_version"]:
            raise ReleaseError(
                f"release requires {config['go_version']}, found {actual_go}"
            )
        expected_invocation = (
            f"https://github.com/{os.environ.get('GITHUB_REPOSITORY', '')}/actions/runs/"
            f"{os.environ.get('GITHUB_RUN_ID', '')}/attempts/{os.environ.get('GITHUB_RUN_ATTEMPT', '')}"
        )
        if invocation_id != expected_invocation:
            raise ReleaseError(
                "release invocation id does not match the GitHub workflow run and attempt"
            )
        build_started_at = (
            dt.datetime.now(tz=dt.timezone.utc).isoformat().replace("+00:00", "Z")
        )
    elif mode == "local-unsigned":
        if source_commit == "":
            source_commit = "local-unsigned"
        if source_repository == "":
            source_repository = "local://sub2api-codex-control"
        if builder_id == "":
            builder_id = "local://sub2api-codex-control/unsigned-builder"
        if invocation_id == "":
            invocation_id = "urn:local-unsigned:deterministic-validation"
        build_started_at = iso8601(args.source_date_epoch)
    else:
        raise ReleaseError(f"unsupported mode {mode!r}")
    targets = select_targets(config, args.targets, mode)
    initial_source_snapshot = source_snapshot_sha256()
    output.mkdir(parents=True, exist_ok=True)
    work = output / ".release-work"
    first = work / "pass-1"
    second = work / "pass-2"
    first.mkdir(parents=True)
    second.mkdir(parents=True)
    module_cache = work / "gomodcache" if mode == "release" else None
    if module_cache is not None:
        module_cache.mkdir()
    test_cache = work / "test-cache"
    test_cache.mkdir()
    test_env = build_environment(
        goos=None,
        goarch=None,
        source_date_epoch=args.source_date_epoch,
        module_cache=module_cache,
        build_cache=test_cache,
    )
    # The shared policy contract test resolves its fixture from runtime.Caller.
    # Candidate binaries still use trimpath; tests retain source paths so the
    # existing cross-package contract is actually exercised.
    test_env["GOFLAGS"] = "-mod=readonly -buildvcs=false"
    if not args.skip_tests:
        run([args.go, "test", "-count=1", "./..."], cwd=CONNECTOR_DIR, env=test_env)
    if source_snapshot_sha256() != initial_source_snapshot:
        raise ReleaseError("source tree changed while release tests were running")
    records: list[dict[str, Any]] = []
    for target in targets:
        filename = artifact_name(config, target)
        candidates: list[Path] = []
        for index, directory in enumerate((first, second), start=1):
            candidate = directory / filename
            cache = work / f"build-cache-{index}-{target['id']}"
            cache.mkdir()
            env = build_environment(
                goos=target["goos"],
                goarch=target["goarch"],
                source_date_epoch=args.source_date_epoch,
                module_cache=module_cache,
                build_cache=cache,
            )
            run(
                [
                    args.go,
                    "build",
                    "-mod=readonly",
                    "-trimpath",
                    "-buildvcs=false",
                    "-ldflags=-buildid=",
                    "-o",
                    str(candidate),
                    "./cmd/connector",
                ],
                cwd=CONNECTOR_DIR,
                env=env,
            )
            candidates.append(candidate)
        if source_snapshot_sha256() != initial_source_snapshot:
            raise ReleaseError(f"source tree changed while building {target['id']}")
        first_hash = sha256_file(candidates[0])
        second_hash = sha256_file(candidates[1])
        if (
            first_hash != second_hash
            or candidates[0].stat().st_size != candidates[1].stat().st_size
        ):
            raise ReleaseError(f"non-reproducible build for {target['id']}")
        final = output / filename
        shutil.copyfile(candidates[0], final)
        final.chmod(0o755)
        package_records: list[dict[str, Any]] = []
        if mode == "release" and target["goos"] == "linux":
            package_passes: list[Path] = []
            for index, candidate in enumerate(candidates, start=1):
                package_output = work / f"package-pass-{index}-{target['id']}"
                package_output.mkdir()
                run(
                    [
                        "sh",
                        str(LINUX_PACKAGE_BUILDER),
                        str(candidate),
                        config["connector_version"],
                        target["goarch"],
                        str(args.source_date_epoch),
                        str(package_output),
                        str(index),
                    ],
                    cwd=REPO_ROOT,
                    env=build_environment(
                        goos=None,
                        goarch=None,
                        source_date_epoch=args.source_date_epoch,
                        module_cache=module_cache,
                        build_cache=work / f"package-build-cache-{index}-{target['id']}",
                    ),
                )
                package_passes.append(package_output)
            for package_config in target["packages"]:
                package_format = package_config["format"]
                package_filename = package_name(config, target, package_format)
                first_package = package_passes[0] / package_filename
                second_package = package_passes[1] / package_filename
                if not first_package.is_file() or not second_package.is_file():
                    raise ReleaseError(
                        f"native package builder omitted {package_filename}"
                    )
                first_package_hash = sha256_file(first_package)
                if (
                    first_package_hash != sha256_file(second_package)
                    or first_package.stat().st_size != second_package.stat().st_size
                ):
                    raise ReleaseError(
                        f"non-reproducible {package_format} package for {target['id']}"
                    )
                run(
                    [
                        "sh",
                        str(PACKAGE_CONTENT_VERIFIER),
                        str(first_package),
                        package_format,
                        target["goarch"],
                        config["connector_version"],
                    ],
                    cwd=REPO_ROOT,
                )
                verify_package_embeds_connector(
                    first_package,
                    package_format,
                    target["goarch"],
                    final,
                )
                packaged = output / package_filename
                shutil.copyfile(first_package, packaged)
                packaged.chmod(0o644)
                package_records.append(
                    {
                        "format": package_format,
                        "filename": package_filename,
                        "native_signature": package_config["native_signature"],
                        "reproducible_candidate_sha256": first_package_hash,
                        "reproducible_candidate_size": packaged.stat().st_size,
                        "native_evidence": None,
                    }
                )
        elif mode == "release" and target["goos"] == "darwin":
            package_config = target["packages"][0]
            package_records.append(
                {
                    "format": package_config["format"],
                    "filename": package_name(
                        config, target, package_config["format"]
                    ),
                    "native_signature": package_config["native_signature"],
                    "reproducible_candidate_sha256": None,
                    "reproducible_candidate_size": None,
                    "native_evidence": None,
                }
            )
        records.append(
            {
                "target": target,
                "filename": filename,
                "unsigned_sha256": first_hash,
                "unsigned_size": final.stat().st_size,
                "packages": package_records,
            }
        )
    build_finished_at = (
        dt.datetime.now(tz=dt.timezone.utc).isoformat().replace("+00:00", "Z")
        if mode == "release"
        else iso8601(args.source_date_epoch)
    )
    state = {
        "format_version": 1,
        "release_mode": mode,
        "config": config,
        "go_version": actual_go,
        "source": {
            "repository": source_repository,
            "commit": source_commit,
            "snapshot_sha256": initial_source_snapshot,
        },
        "source_date_epoch": args.source_date_epoch,
        "builder_id": builder_id,
        "invocation_id": invocation_id,
        "build_started_at": build_started_at,
        "build_finished_at": build_finished_at,
        "targets": records,
    }
    write_json(output / WORK_STATE, state)
    shutil.rmtree(work)
    print(
        f"prepared {len(records)} reproducible {mode} Connector artifacts in {output}"
    )


def target_record(state: dict[str, Any], target_id: str) -> dict[str, Any]:
    for record in state["targets"]:
        if record["target"]["id"] == target_id:
            return record
    raise ReleaseError(f"target {target_id!r} is not present in release state")


def record_native_evidence(args: argparse.Namespace) -> None:
    output = release_output_directory(args.output)
    state = read_json(safe_file(output, WORK_STATE, "release work state"))
    if state.get("release_mode") != "release":
        raise ReleaseError("native signing evidence is accepted only for release mode")
    record = target_record(state, args.target)
    if record["target"]["goos"] != "darwin":
        raise ReleaseError("native signing evidence applies only to Darwin targets")
    artifact = safe_file(
        output, record["filename"], "Darwin artifact", executable=True
    )
    validate_apple_identity(args.expected_team_id, args.expected_signing_identity)
    report_path = regular_external_input_file(args.codesign_report, "codesign report")
    recorded_report_lines = report_lines(report_path, "codesign report")
    fresh_report_lines = verify_codesign_identity(
        artifact,
        args.expected_team_id,
        args.expected_signing_identity,
    ).splitlines()
    if (
        f"Authority={args.expected_signing_identity}" not in recorded_report_lines
        or f"TeamIdentifier={args.expected_team_id}" not in recorded_report_lines
        or f"Authority={args.expected_signing_identity}" not in fresh_report_lines
        or f"TeamIdentifier={args.expected_team_id}" not in fresh_report_lines
    ):
        raise ReleaseError(
            "codesign report does not match the externally pinned Apple identity"
        )
    evidence = {
        "format_version": 2,
        "target": record["target"]["id"],
        "artifact": record["filename"],
        "artifact_sha256": sha256_file(artifact),
        "signing_identity": args.expected_signing_identity,
        "team_identifier": args.expected_team_id,
        "codesign_report": fresh_report_lines,
    }
    evidence_name = f"native-{record['target']['id']}.json"
    write_exclusive_canonical_json(output / evidence_name, evidence)
    print(evidence_name)


def package_record(record: dict[str, Any], package_format: str) -> dict[str, Any]:
    for package in record["packages"]:
        if package["format"] == package_format:
            return package
    raise ReleaseError(
        f"target {record['target']['id']} has no {package_format} package"
    )


def report_lines(path: Path, context: str) -> list[str]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise ReleaseError(f"cannot read {context}: {exc}") from exc
    if not lines or any("\x00" in line for line in lines):
        raise ReleaseError(f"{context} is empty or invalid")
    return lines


def openpgp_key_fingerprints(
    public_key: Path, gpg: str = "gpg"
) -> tuple[str, set[str]]:
    output = run(
        [gpg, "--batch", "--show-keys", "--with-colons", "--fingerprint", str(public_key)],
        capture=True,
    )
    primary_fingerprints: list[str] = []
    all_fingerprints: set[str] = set()
    current_kind = ""
    for line in output.splitlines():
        fields = line.split(":")
        if fields[0] in {"pub", "sub"}:
            current_kind = fields[0]
            continue
        if current_kind and fields[0] == "fpr" and len(fields) > 9:
            fingerprint = fields[9]
            validate_rpm_fingerprint(fingerprint)
            all_fingerprints.add(fingerprint)
            if current_kind == "pub":
                primary_fingerprints.append(fingerprint)
            current_kind = ""
    if len(primary_fingerprints) != 1:
        raise ReleaseError("RPM public key must contain exactly one primary OpenPGP key")
    return primary_fingerprints[0], all_fingerprints


def primary_openpgp_fingerprint(public_key: Path, gpg: str = "gpg") -> str:
    return openpgp_key_fingerprints(public_key, gpg)[0]


def verify_rpm_signature(
    package_path: Path, public_key: Path, expected_fingerprint: str
) -> list[str]:
    validate_rpm_fingerprint(expected_fingerprint)
    actual_fingerprint, admitted_fingerprints = openpgp_key_fingerprints(public_key)
    if actual_fingerprint != expected_fingerprint:
        raise ReleaseError("RPM public key fingerprint does not match external policy")
    with tempfile.TemporaryDirectory(prefix="connector-rpm-verify.") as directory:
        rpm_db = Path(directory) / "rpmdb"
        rpm_db.mkdir(mode=0o700)
        run(["rpm", "--dbpath", str(rpm_db), "--initdb"])
        run(["rpm", "--dbpath", str(rpm_db), "--import", str(public_key)])
        report = run(
            [
                "rpmkeys",
                "--dbpath",
                str(rpm_db),
                "--checksig",
                "--verbose",
                str(package_path),
            ],
            capture=True,
        ).splitlines()
    if not report or not any(
        "ok" in line.lower()
        and ("pgp" in line.lower() or "signature" in line.lower())
        for line in report
    ):
        raise ReleaseError("RPM native signature verification did not pass")
    signer_ids = {
        match.group(1).upper()
        for line in report
        for match in [re.search(r"key ID ([0-9A-Fa-f]{8,64})", line)]
        if match is not None
    }
    if not signer_ids or any(
        not any(fingerprint.endswith(signer_id) for fingerprint in admitted_fingerprints)
        for signer_id in signer_ids
    ):
        raise ReleaseError("RPM signer does not match the admitted OpenPGP key")
    return report


def validate_rpm_package_evidence(
    evidence: Any,
    *,
    target_id: str,
    package_name_value: str,
    package_sha256: str,
    expected_fingerprint: str,
    public_key_name: str,
    public_key_sha256: str,
) -> None:
    if not isinstance(evidence, dict):
        raise ReleaseError(f"invalid RPM native evidence for {target_id}")
    require_exact_keys(
        evidence,
        {
            "format_version",
            "target",
            "format",
            "package",
            "package_sha256",
            "policy",
            "fingerprint",
            "public_key",
            "public_key_sha256",
            "rpm_report",
        },
        "RPM native evidence",
    )
    validate_rpm_fingerprint(expected_fingerprint)
    report = evidence["rpm_report"]
    if (
        evidence["format_version"] != 2
        or evidence["target"] != target_id
        or evidence["format"] != "rpm"
        or evidence["package"] != package_name_value
        or evidence["package_sha256"] != package_sha256
        or evidence["policy"] != "rpm-openpgp"
        or evidence["fingerprint"] != expected_fingerprint
        or evidence["public_key"] != public_key_name
        or evidence["public_key_sha256"] != public_key_sha256
        or not isinstance(report, list)
        or not report
        or not all(isinstance(line, str) and "\x00" not in line for line in report)
        or not any(
            "ok" in line.lower()
            and ("pgp" in line.lower() or "signature" in line.lower())
            for line in report
        )
    ):
        raise ReleaseError(f"RPM native evidence does not match trust policy for {target_id}")


def validate_pkg_package_evidence(
    evidence: Any,
    *,
    target_id: str,
    package_name_value: str,
    package_sha256: str,
    expected_team_id: str,
    expected_application_identity: str,
    expected_installer_identity: str,
) -> None:
    if not isinstance(evidence, dict):
        raise ReleaseError(f"invalid macOS installer evidence for {target_id}")
    require_exact_keys(
        evidence,
        {
            "format_version",
            "target",
            "format",
            "package",
            "package_sha256",
            "policy",
            "team_identifier",
            "application_identity",
            "installer_identity",
            "installer_report",
            "notarization",
            "stapling",
            "gatekeeper",
        },
        "macOS installer evidence",
    )
    validate_apple_identity(expected_team_id, expected_application_identity)
    validate_apple_installer_identity(expected_team_id, expected_installer_identity)
    installer_report = evidence["installer_report"]
    notarization = evidence["notarization"]
    stapling = evidence["stapling"]
    gatekeeper = evidence["gatekeeper"]
    if not isinstance(notarization, dict):
        raise ReleaseError(f"invalid notarization evidence for {target_id}")
    if not isinstance(stapling, dict) or not isinstance(gatekeeper, dict):
        raise ReleaseError(f"invalid macOS installer admission evidence for {target_id}")
    require_exact_keys(
        notarization,
        {"service", "status", "submission_id", "message"},
        "notarization evidence",
    )
    require_exact_keys(stapling, {"status", "report"}, "stapling evidence")
    require_exact_keys(gatekeeper, {"status", "report"}, "Gatekeeper evidence")
    stapler_report = stapling["report"]
    gatekeeper_report = gatekeeper["report"]
    reports_are_valid = all(
        isinstance(report, list)
        and report
        and all(isinstance(line, str) and "\x00" not in line for line in report)
        for report in (installer_report, stapler_report, gatekeeper_report)
    )
    primary_identities = [
        match.group(1)
        for line in installer_report
        for match in [re.fullmatch(r"\s*1\.\s+(.+)", line)]
        if match is not None
    ]
    if (
        evidence["format_version"] != 2
        or evidence["target"] != target_id
        or evidence["format"] != "pkg"
        or evidence["package"] != package_name_value
        or evidence["package_sha256"] != package_sha256
        or evidence["policy"]
        != "apple-developer-id-installer-notarized-stapled"
        or evidence["team_identifier"] != expected_team_id
        or evidence["application_identity"] != expected_application_identity
        or evidence["installer_identity"] != expected_installer_identity
        or not reports_are_valid
        or primary_identities != [expected_installer_identity]
        or notarization["service"] != "apple-notarytool"
        or notarization["status"] != "Accepted"
        or not isinstance(notarization["submission_id"], str)
        or not notarization["submission_id"]
        or not isinstance(notarization["message"], str)
        or stapling["status"] != "validated"
        or not any(
            "validated" in line.lower() or "worked" in line.lower()
            for line in stapler_report
        )
        or gatekeeper["status"] != "accepted"
        or not any(
            "accepted" in line.lower()
            or "source=notarized developer id" in line.lower()
            for line in gatekeeper_report
        )
    ):
        raise ReleaseError(
            f"macOS installer evidence does not match trust policy for {target_id}"
        )


def record_native_package_evidence(args: argparse.Namespace) -> None:
    output = release_output_directory(args.output)
    state = read_json(safe_file(output, WORK_STATE, "release work state"))
    if state.get("release_mode") != "release":
        raise ReleaseError("native package evidence is accepted only for release mode")
    record = target_record(state, args.target)
    package = package_record(record, args.package_format)
    package_path = safe_file(output, package["filename"], "native package")
    connector_artifact = safe_file(
        output, record["filename"], "Connector artifact", executable=True
    )
    run(
        [
            "sh",
            str(PACKAGE_CONTENT_VERIFIER),
            str(package_path),
            args.package_format,
            record["target"]["goarch"],
            state["config"]["connector_version"],
        ],
        cwd=REPO_ROOT,
    )
    verify_package_embeds_connector(
        package_path,
        args.package_format,
        record["target"]["goarch"],
        connector_artifact,
    )
    evidence_name = f"native-package-{args.target}-{args.package_format}.json"
    if (output / evidence_name).exists() or package["native_evidence"] is not None:
        raise ReleaseError("native package evidence already exists")

    if args.package_format == "pkg":
        if record["target"]["goos"] != "darwin":
            raise ReleaseError("pkg evidence applies only to Darwin targets")
        required_paths = (
            args.candidate_package,
            args.installer_report,
            args.notary_json,
            args.stapler_report,
            args.gatekeeper_report,
        )
        if (
            any(path is None for path in required_paths)
            or not args.expected_team_id
            or not args.expected_application_identity
            or not args.expected_installer_identity
        ):
            raise ReleaseError("pkg evidence lacks required external trust inputs")
        validate_apple_identity(args.expected_team_id, args.expected_application_identity)
        validate_apple_installer_identity(
            args.expected_team_id, args.expected_installer_identity
        )
        candidate = regular_external_input_file(
            args.candidate_package, "unsigned pkg candidate"
        )
        candidate_hash = sha256_file(candidate)
        candidate_size = candidate.stat().st_size
        installer_path = regular_external_input_file(
            args.installer_report, "Installer signature report"
        )
        notary_path = regular_external_input_file(args.notary_json, "notary response")
        stapler_path = regular_external_input_file(args.stapler_report, "stapler report")
        gatekeeper_path = regular_external_input_file(
            args.gatekeeper_report, "Gatekeeper report"
        )
        installer = report_lines(installer_path, "Installer signature report")
        notary = read_json(notary_path)
        stapler = report_lines(stapler_path, "stapler report")
        gatekeeper = report_lines(gatekeeper_path, "Gatekeeper report")
        primary_identities = [
            match.group(1)
            for line in installer
            for match in [re.fullmatch(r"\s*1\.\s+(.+)", line)]
            if match is not None
        ]
        if (
            primary_identities != [args.expected_installer_identity]
            or not isinstance(notary, dict)
            or notary.get("status") != "Accepted"
            or not isinstance(notary.get("id"), str)
            or not notary["id"]
            or not any(
                "validated" in line.lower() or "worked" in line.lower()
                for line in stapler
            )
            or not any(
                "accepted" in line.lower()
                or "source=notarized developer id" in line.lower()
                for line in gatekeeper
            )
        ):
            raise ReleaseError("macOS installer trust evidence is incomplete")
        evidence = {
            "format_version": 2,
            "target": args.target,
            "format": "pkg",
            "package": package["filename"],
            "package_sha256": sha256_file(package_path),
            "policy": package["native_signature"],
            "team_identifier": args.expected_team_id,
            "application_identity": args.expected_application_identity,
            "installer_identity": args.expected_installer_identity,
            "installer_report": installer,
            "notarization": {
                "service": "apple-notarytool",
                "status": "Accepted",
                "submission_id": notary["id"],
                "message": str(notary.get("message", "")),
            },
            "stapling": {"status": "validated", "report": stapler},
            "gatekeeper": {"status": "accepted", "report": gatekeeper},
        }
        package["reproducible_candidate_sha256"] = candidate_hash
        package["reproducible_candidate_size"] = candidate_size
    elif args.package_format == "rpm":
        if record["target"]["goos"] != "linux":
            raise ReleaseError("RPM evidence applies only to Linux targets")
        if (
            args.rpm_public_key is None
            or args.rpm_report is None
            or not args.expected_rpm_fingerprint
        ):
            raise ReleaseError("RPM evidence lacks required external trust inputs")
        validate_rpm_fingerprint(args.expected_rpm_fingerprint)
        public_key = regular_external_input_file(args.rpm_public_key, "RPM public key")
        rpm_report_path = regular_external_input_file(
            args.rpm_report, "RPM signature report"
        )
        report_lines(rpm_report_path, "RPM signature report")
        rpm_report = verify_rpm_signature(
            package_path, public_key, args.expected_rpm_fingerprint
        )
        public_key_name = f"rpm-signing-{args.target}.asc"
        public_key_output = output / public_key_name
        copy_exclusive_file(public_key, public_key_output)
        evidence = {
            "format_version": 2,
            "target": args.target,
            "format": "rpm",
            "package": package["filename"],
            "package_sha256": sha256_file(package_path),
            "policy": package["native_signature"],
            "fingerprint": args.expected_rpm_fingerprint,
            "public_key": public_key_name,
            "public_key_sha256": sha256_file(public_key_output),
            "rpm_report": rpm_report,
        }
    else:
        raise ReleaseError("native package evidence supports only pkg and rpm")

    if args.package_format == "pkg":
        validate_pkg_package_evidence(
            evidence,
            target_id=args.target,
            package_name_value=package["filename"],
            package_sha256=sha256_file(package_path),
            expected_team_id=args.expected_team_id,
            expected_application_identity=args.expected_application_identity,
            expected_installer_identity=args.expected_installer_identity,
        )
    else:
        validate_rpm_package_evidence(
            evidence,
            target_id=args.target,
            package_name_value=package["filename"],
            package_sha256=sha256_file(package_path),
            expected_fingerprint=args.expected_rpm_fingerprint,
            public_key_name=public_key_name,
            public_key_sha256=sha256_file(public_key_output),
        )
    write_exclusive_canonical_json(output / evidence_name, evidence)
    package["native_evidence"] = evidence_name
    write_json(output / WORK_STATE, state)
    print(evidence_name)


def parse_go_modules(go_binary: str, artifact: Path) -> list[dict[str, str]]:
    output = run([go_binary, "version", "-m", str(artifact)], capture=True)
    modules: list[dict[str, str]] = []
    for line in output.splitlines():
        fields = line.strip().split("\t")
        if not fields or fields[0] not in {"mod", "dep"} or len(fields) < 3:
            continue
        item = {"kind": fields[0], "path": fields[1], "version": fields[2]}
        if len(fields) > 3 and fields[3].startswith("h1:"):
            item["go_sum"] = fields[3]
        modules.append(item)
    if not any(item["kind"] == "mod" for item in modules):
        raise ReleaseError(f"cannot extract Go module metadata from {artifact.name}")
    return sorted(
        modules, key=lambda item: (item["kind"], item["path"], item["version"])
    )


def spdx_id(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9.-]", "-", value)


GO_STDLIB_SPDX_ID = "SPDXRef-Package-Go-Standard-Library"


def go_stdlib_spdx_package(go_version_value: str) -> dict[str, Any]:
    if not re.fullmatch(r"go\d+\.\d+\.\d+", go_version_value):
        raise ReleaseError("Go standard-library SBOM version is not an exact release")
    version = go_version_value.removeprefix("go")
    return {
        "SPDXID": GO_STDLIB_SPDX_ID,
        "name": "Go standard library",
        "versionInfo": version,
        "downloadLocation": "NOASSERTION",
        "filesAnalyzed": False,
        "licenseConcluded": "BSD-3-Clause",
        "licenseDeclared": "BSD-3-Clause",
        "copyrightText": "Copyright The Go Authors",
        "externalRefs": [
            {
                "referenceCategory": "PACKAGE-MANAGER",
                "referenceType": "purl",
                "referenceLocator": f"pkg:golang/stdlib@{version}",
            }
        ],
    }


def connector_component_spdx_package(
    product: str, connector_version: str
) -> dict[str, Any]:
    return {
        "SPDXID": "SPDXRef-Package-Connector",
        "name": product,
        "versionInfo": connector_version,
        "downloadLocation": "NOASSERTION",
        "filesAnalyzed": False,
        "licenseConcluded": "Apache-2.0",
        "licenseDeclared": "Apache-2.0",
        "copyrightText": "Copyright 2026 Sub2API Codex Control contributors",
    }


def go_dependency_spdx_entries(
    modules: list[dict[str, str]], parent_id: str
) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    packages: list[dict[str, Any]] = []
    relationships: list[dict[str, str]] = []
    seen_ids: set[str] = set()
    for module in modules:
        if module["kind"] != "dep":
            continue
        module_id = (
            f"SPDXRef-Package-{spdx_id(module['path'])}-{spdx_id(module['version'])}"
        )
        if module_id in seen_ids:
            raise ReleaseError(f"duplicate SPDX dependency identifier {module_id}")
        seen_ids.add(module_id)
        package: dict[str, Any] = {
            "SPDXID": module_id,
            "name": module["path"],
            "versionInfo": module["version"],
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": "NOASSERTION",
            "copyrightText": "NOASSERTION",
        }
        if module["version"] not in {"(devel)", "(unknown)"}:
            package["externalRefs"] = [
                {
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": (
                        f"pkg:golang/{module['path']}@{module['version']}"
                    ),
                }
            ]
        packages.append(package)
        relationships.append(
            {
                "spdxElementId": parent_id,
                "relationshipType": "DEPENDS_ON",
                "relatedSpdxElement": module_id,
            }
        )
    return packages, relationships


def make_sbom(
    state: dict[str, Any],
    record: dict[str, Any],
    artifact: Path,
    final_sha: str,
    modules: list[dict[str, str]],
) -> dict[str, Any]:
    config = state["config"]
    package_id = "SPDXRef-Package-Connector"
    file_id = "SPDXRef-File-Connector"
    file_sha1 = sha1_file(artifact)
    package_verification_code = hashlib.sha1(file_sha1.encode("ascii")).hexdigest()
    artifact_checksums = [
        {"algorithm": "SHA1", "checksumValue": file_sha1},
        {"algorithm": "SHA256", "checksumValue": final_sha},
    ]
    packages: list[dict[str, Any]] = [
        {
            "SPDXID": package_id,
            "name": config["product"],
            "versionInfo": config["connector_version"],
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": True,
            "checksums": artifact_checksums,
            "packageVerificationCode": {
                "packageVerificationCodeValue": package_verification_code
            },
            "licenseInfoFromFiles": ["NOASSERTION"],
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": "NOASSERTION",
            "copyrightText": "NOASSERTION",
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
    stdlib_package = go_stdlib_spdx_package(state["go_version"])
    packages.append(stdlib_package)
    relationships.append(
        {
            "spdxElementId": package_id,
            "relationshipType": "DEPENDS_ON",
            "relatedSpdxElement": GO_STDLIB_SPDX_ID,
        }
    )
    dependency_packages, dependency_relationships = go_dependency_spdx_entries(
        modules, package_id
    )
    packages.extend(dependency_packages)
    relationships.extend(dependency_relationships)
    created = iso8601(int(state["source_date_epoch"]))
    namespace_seed = (
        f"{final_sha}:{record['target']['id']}:{config['connector_version']}"
    )
    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"{artifact.name}.spdx",
        "documentNamespace": f"https://sub2api-codex.invalid/spdx/{sha256_bytes(namespace_seed.encode())}",
        "creationInfo": {
            "created": created,
            "creators": ["Tool: sub2api-codex-release/1"],
        },
        "packages": packages,
        "files": [
            {
                "SPDXID": file_id,
                "fileName": artifact.name,
                "checksums": artifact_checksums,
                "licenseConcluded": "NOASSERTION",
                "licenseInfoInFiles": ["NOASSERTION"],
                "copyrightText": "NOASSERTION",
            }
        ],
        "relationships": relationships,
    }


def make_provenance(
    state: dict[str, Any],
    record: dict[str, Any],
    artifact: Path,
    final_sha: str,
    modules: list[dict[str, str]],
) -> dict[str, Any]:
    config = state["config"]
    source = state["source"]
    if HEX_GIT_COMMIT.fullmatch(source["commit"]):
        source_digest = {"gitCommit": source["commit"]}
    else:
        source_digest = {"sha256": source["snapshot_sha256"]}
    resolved: list[dict[str, Any]] = [
        {"uri": source["repository"], "digest": source_digest},
        {"uri": f"pkg:golang/toolchain@{state['go_version'].removeprefix('go')}"},
    ]
    for module in modules:
        if module["kind"] != "dep":
            continue
        dependency: dict[str, Any] = {
            "uri": f"pkg:golang/{module['path']}@{module['version']}"
        }
        if "go_sum" in module:
            try:
                decoded = base64.b64decode(
                    module["go_sum"].removeprefix("h1:"), validate=True
                )
            except (ValueError, binascii.Error) as exc:
                raise ReleaseError(
                    f"invalid Go module checksum for {module['path']}"
                ) from exc
            if len(decoded) != hashlib.sha256().digest_size:
                raise ReleaseError(
                    f"Go module checksum is not SHA-256 for {module['path']}"
                )
            dependency["digest"] = {"dirHash1": decoded.hex()}
        resolved.append(dependency)
    if HEX_GIT_COMMIT.fullmatch(source["commit"]) and source["repository"].startswith(
        "https://github.com/"
    ):
        build_type = f"{source['repository']}/blob/{source['commit']}/connector/release/README.md#release-flow"
    else:
        build_type = "https://sub2api-codex.invalid/buildtypes/connector-release/v1"
    return {
        "_type": IN_TOTO_STATEMENT,
        "subject": [{"name": artifact.name, "digest": {"sha256": final_sha}}],
        "predicateType": SLSA_PREDICATE,
        "predicate": {
            "buildDefinition": {
                "buildType": build_type,
                "externalParameters": {
                    "sourceRepository": source["repository"],
                    "sourceCommit": source["commit"],
                    "connectorVersion": config["connector_version"],
                    "controlProtocolVersion": config["control_protocol_version"],
                    "codexVersion": config["codex_version"],
                    "appserverSchemaSha256": config["appserver_schema_sha256"],
                    "serverApiRelease": config["server_api_release"],
                    "target": artifact_provenance_target(record["target"]),
                },
                "internalParameters": {
                    "cgoEnabled": False,
                    "goAmd64": PINNED_GO_ENV["GOAMD64"],
                    "goArm64": PINNED_GO_ENV["GOARM64"],
                    "goEnv": PINNED_GO_ENV["GOENV"],
                    "goExperiment": PINNED_GO_ENV["GOEXPERIMENT"],
                    "goFips140": PINNED_GO_ENV["GOFIPS140"],
                    "goToolchain": PINNED_GO_ENV["GOTOOLCHAIN"],
                    "trimpath": True,
                    "buildVcs": False,
                    "goBuildId": "",
                },
                "resolvedDependencies": resolved,
            },
            "runDetails": {
                "builder": {"id": state["builder_id"]},
                "metadata": {
                    "invocationId": f"{state['invocation_id']}#{record['target']['id']}",
                    "startedOn": state["build_started_at"],
                    "finishedOn": state["build_finished_at"],
                },
                "byproducts": [
                    {
                        "name": record["filename"],
                        "digest": {"sha256": record["unsigned_sha256"]},
                        "annotations": {
                            "check": "two-pass-byte-for-byte",
                            "passes": 2,
                            "matched": True,
                            "unsignedSize": record["unsigned_size"],
                        },
                    }
                ],
            },
        },
    }


def make_package_sbom(
    state: dict[str, Any],
    record: dict[str, Any],
    package: dict[str, Any],
    package_path: Path,
    modules: list[dict[str, str]],
) -> dict[str, Any]:
    config = state["config"]
    final_sha = sha256_file(package_path)
    final_sha1 = sha1_file(package_path)
    created = iso8601(int(state["source_date_epoch"]))
    package_id = "SPDXRef-Package-ConnectorInstaller"
    file_id = "SPDXRef-File-ConnectorInstaller"
    connector_component = connector_component_spdx_package(
        config["product"], config["connector_version"]
    )
    stdlib_package = go_stdlib_spdx_package(state["go_version"])
    dependency_packages, dependency_relationships = go_dependency_spdx_entries(
        modules, connector_component["SPDXID"]
    )
    contained_packages = [connector_component, stdlib_package, *dependency_packages]
    dependency_relationships.insert(
        0,
        {
            "spdxElementId": connector_component["SPDXID"],
            "relationshipType": "DEPENDS_ON",
            "relatedSpdxElement": GO_STDLIB_SPDX_ID,
        },
    )
    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"{package_path.name}.spdx",
        "documentNamespace": f"https://sub2api-codex.invalid/spdx/{sha256_bytes((final_sha + ':' + record['target']['id'] + ':' + package['format']).encode())}",
        "creationInfo": {
            "created": created,
            "creators": ["Tool: sub2api-codex-release/2"],
        },
        "packages": [
            {
                "SPDXID": package_id,
                "name": config["product"],
                "versionInfo": config["connector_version"],
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": True,
                "checksums": [
                    {"algorithm": "SHA1", "checksumValue": final_sha1},
                    {"algorithm": "SHA256", "checksumValue": final_sha},
                ],
                "packageVerificationCode": {
                    "packageVerificationCodeValue": hashlib.sha1(
                        final_sha1.encode("ascii")
                    ).hexdigest()
                },
                "licenseInfoFromFiles": ["NOASSERTION"],
                "licenseConcluded": "NOASSERTION",
                "licenseDeclared": "NOASSERTION",
                "copyrightText": "NOASSERTION",
                "externalRefs": [
                    {
                        "referenceCategory": "PACKAGE-MANAGER",
                        "referenceType": "purl",
                        "referenceLocator": f"pkg:generic/{config['product']}@{config['connector_version']}?os={record['target']['goos']}&arch={record['target']['goarch']}&type={package['format']}",
                    }
                ],
            },
            *contained_packages,
        ],
        "files": [
            {
                "SPDXID": file_id,
                "fileName": package_path.name,
                "checksums": [
                    {"algorithm": "SHA1", "checksumValue": final_sha1},
                    {"algorithm": "SHA256", "checksumValue": final_sha},
                ],
                "licenseConcluded": "NOASSERTION",
                "licenseInfoInFiles": ["NOASSERTION"],
                "copyrightText": "NOASSERTION",
            }
        ],
        "relationships": [
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
            *[
                {
                    "spdxElementId": package_id,
                    "relationshipType": "CONTAINS",
                    "relatedSpdxElement": contained["SPDXID"],
                }
                for contained in contained_packages
            ],
            *dependency_relationships,
        ],
    }


def make_package_provenance(
    state: dict[str, Any],
    record: dict[str, Any],
    package: dict[str, Any],
    package_path: Path,
    connector_artifact_sha256: str,
) -> dict[str, Any]:
    source = state["source"]
    source_digest = (
        {"gitCommit": source["commit"]}
        if HEX_GIT_COMMIT.fullmatch(source["commit"])
        else {"sha256": source["snapshot_sha256"]}
    )
    return {
        "_type": IN_TOTO_STATEMENT,
        "subject": [
            {
                "name": package_path.name,
                "digest": {"sha256": sha256_file(package_path)},
            }
        ],
        "predicateType": SLSA_PREDICATE,
        "predicate": {
            "buildDefinition": {
                "buildType": "https://sub2api-codex.invalid/buildtypes/connector-native-package/v2",
                "externalParameters": {
                    "sourceRepository": source["repository"],
                    "sourceCommit": source["commit"],
                    "connectorVersion": state["config"]["connector_version"],
                    "target": record["target"]["id"],
                    "packageFormat": package["format"],
                    "nativeSignaturePolicy": package["native_signature"],
                },
                "internalParameters": {
                    "reproducibilityPasses": 2,
                    "packageContentVerified": True,
                    "licenseInventoryVerified": True,
                    "serviceDefinitionIncluded": True,
                    "configurationExampleIncluded": True,
                },
                "resolvedDependencies": [
                    {"uri": source["repository"], "digest": source_digest},
                    {
                        "uri": f"pkg:generic/{state['config']['product']}@{state['config']['connector_version']}",
                        "digest": {"sha256": connector_artifact_sha256},
                    },
                ],
            },
            "runDetails": {
                "builder": {"id": state["builder_id"]},
                "metadata": {
                    "invocationId": f"{state['invocation_id']}#{record['target']['id']}-{package['format']}",
                    "startedOn": state["build_started_at"],
                    "finishedOn": state["build_finished_at"],
                },
                "byproducts": [
                    {
                        "name": f"{package_path.name}.unsigned-candidate",
                        "digest": {
                            "sha256": package["reproducible_candidate_sha256"]
                        },
                        "annotations": {
                            "passes": 2,
                            "matched": True,
                            "candidateSize": package[
                                "reproducible_candidate_size"
                            ],
                        },
                    }
                ],
            },
        },
    }


def safe_file(
    output: Path, name: str, context: str, *, executable: bool | None = None
) -> Path:
    if not isinstance(name, str) or not SAFE_NAME.fullmatch(name):
        raise ReleaseError(f"unsafe {context} filename {name!r}")
    path = output / name
    try:
        mode = path.lstat().st_mode
    except FileNotFoundError as exc:
        raise ReleaseError(f"missing {context}: {name}") from exc
    if not stat.S_ISREG(mode) or path.is_symlink():
        raise ReleaseError(f"{context} must be a regular non-symlink file: {name}")
    if executable is True and not mode & stat.S_IXUSR:
        raise ReleaseError(f"artifact is not executable: {name}")
    return path


def validate_work_state(
    output: Path,
    state: dict[str, Any],
    config: dict[str, Any],
    *,
    require_unsigned_artifacts: bool,
) -> None:
    if not isinstance(state, dict):
        raise ReleaseError("release work state must be a JSON object")
    require_exact_keys(
        state,
        {
            "format_version",
            "release_mode",
            "config",
            "go_version",
            "source",
            "source_date_epoch",
            "builder_id",
            "invocation_id",
            "build_started_at",
            "build_finished_at",
            "targets",
        },
        "release work state",
    )
    mode = state["release_mode"]
    if (
        state["format_version"] != 1
        or mode not in {"release", "local-unsigned"}
        or state["config"] != config
    ):
        raise ReleaseError(
            "release work state is incompatible with the current release config"
        )
    if mode == "release" and state["go_version"] != config["go_version"]:
        raise ReleaseError("release work state does not use the pinned Go version")
    require_exact_keys(
        state["source"],
        {"repository", "commit", "snapshot_sha256"},
        "release work source",
    )
    if not HEX_SHA256.fullmatch(state["source"]["snapshot_sha256"]):
        raise ReleaseError("release work source snapshot digest is invalid")
    if (
        not isinstance(state["source_date_epoch"], int)
        or state["source_date_epoch"] < 0
    ):
        raise ReleaseError("release work source date epoch is invalid")
    for field in (
        "builder_id",
        "invocation_id",
        "build_started_at",
        "build_finished_at",
    ):
        if not isinstance(state[field], str) or not state[field]:
            raise ReleaseError(f"release work {field} is invalid")
    for field in ("build_started_at", "build_finished_at"):
        try:
            dt.datetime.fromisoformat(state[field].replace("Z", "+00:00"))
        except ValueError as exc:
            raise ReleaseError(
                f"release work {field} is not an RFC 3339 timestamp"
            ) from exc
    records = state["targets"]
    if not isinstance(records, list) or not records:
        raise ReleaseError("release work state has no targets")
    config_targets = {target["id"]: target for target in config["targets"]}
    record_ids = [
        record.get("target", {}).get("id")
        for record in records
        if isinstance(record, dict)
    ]
    if len(record_ids) != len(records) or len(set(record_ids)) != len(record_ids):
        raise ReleaseError("release work state has invalid or duplicate targets")
    if mode == "release" and record_ids != [
        target["id"] for target in config["targets"]
    ]:
        raise ReleaseError(
            "release work state does not contain the complete ordered target matrix"
        )
    expected_subset = [
        target["id"] for target in config["targets"] if target["id"] in set(record_ids)
    ]
    if record_ids != expected_subset:
        raise ReleaseError(
            "release work targets are not an ordered subset of the admitted matrix"
        )
    for record in records:
        require_exact_keys(
            record,
            {"target", "filename", "unsigned_sha256", "unsigned_size", "packages"},
            "target record",
        )
        target_id = (
            record["target"].get("id") if isinstance(record["target"], dict) else None
        )
        expected_target = config_targets.get(target_id)
        if expected_target is None or record["target"] != expected_target:
            raise ReleaseError(
                f"release work target {target_id!r} does not match the admitted matrix"
            )
        if record["filename"] != artifact_name(config, expected_target):
            raise ReleaseError(
                f"release work artifact filename is invalid for {target_id}"
            )
        if not HEX_SHA256.fullmatch(record["unsigned_sha256"]):
            raise ReleaseError(
                f"release work unsigned digest is invalid for {target_id}"
            )
        if not isinstance(record["unsigned_size"], int) or record["unsigned_size"] <= 0:
            raise ReleaseError(f"release work unsigned size is invalid for {target_id}")
        artifact = safe_file(
            output, record["filename"], "release work artifact", executable=True
        )
        if require_unsigned_artifacts and (
            artifact.stat().st_size != record["unsigned_size"]
            or sha256_file(artifact) != record["unsigned_sha256"]
        ):
            raise ReleaseError(
                f"unsigned artifact changed after reproducibility check: {target_id}"
            )
        packages = record["packages"]
        if not isinstance(packages, list):
            raise ReleaseError(f"release work packages are invalid for {target_id}")
        if mode == "local-unsigned":
            if packages:
                raise ReleaseError("local unsigned work state must not contain native packages")
            continue
        if [item.get("format") for item in packages] != [
            item["format"] for item in expected_target["packages"]
        ]:
            raise ReleaseError(
                f"release work packages do not match the admitted matrix for {target_id}"
            )
        for package, package_config in zip(
            packages, expected_target["packages"], strict=True
        ):
            require_exact_keys(
                package,
                {
                    "format",
                    "filename",
                    "native_signature",
                    "reproducible_candidate_sha256",
                    "reproducible_candidate_size",
                    "native_evidence",
                },
                "release work package",
            )
            package_format = package_config["format"]
            expected_filename = package_name(config, expected_target, package_format)
            if (
                package["format"] != package_format
                or package["filename"] != expected_filename
                or package["native_signature"]
                != package_config["native_signature"]
            ):
                raise ReleaseError(
                    f"release work package metadata is invalid for {target_id}/{package_format}"
                )
            candidate_hash = package["reproducible_candidate_sha256"]
            candidate_size = package["reproducible_candidate_size"]
            native_evidence = package["native_evidence"]
            if expected_target["goos"] == "linux":
                if (
                    not isinstance(candidate_hash, str)
                    or not HEX_SHA256.fullmatch(candidate_hash)
                    or not isinstance(candidate_size, int)
                    or candidate_size <= 0
                ):
                    raise ReleaseError(
                        f"release work package lacks reproducible candidate metadata for {target_id}/{package_format}"
                    )
                packaged = safe_file(output, expected_filename, "native package")
                if package_format == "deb":
                    if native_evidence is not None:
                        raise ReleaseError("Debian package must not claim a native signature")
                    if (
                        sha256_file(packaged) != candidate_hash
                        or packaged.stat().st_size != candidate_size
                    ):
                        raise ReleaseError(
                            f"Debian package differs from its reproducible candidate for {target_id}"
                        )
                elif native_evidence is not None and (
                    not isinstance(native_evidence, str)
                    or native_evidence
                    != f"native-package-{target_id}-{package_format}.json"
                ):
                    raise ReleaseError(
                        f"RPM package native evidence name is invalid for {target_id}"
                    )
                elif native_evidence is None and (
                    sha256_file(packaged) != candidate_hash
                    or packaged.stat().st_size != candidate_size
                ):
                    raise ReleaseError(
                        f"unsigned RPM package differs from its reproducible candidate for {target_id}"
                    )
            else:
                values_absent = candidate_hash is None and candidate_size is None
                values_present = (
                    isinstance(candidate_hash, str)
                    and HEX_SHA256.fullmatch(candidate_hash) is not None
                    and isinstance(candidate_size, int)
                    and candidate_size > 0
                )
                if not values_absent and not values_present:
                    raise ReleaseError(
                        f"Darwin package candidate state is partial for {target_id}"
                    )
                expected_evidence = f"native-package-{target_id}-pkg.json"
                if values_absent:
                    if native_evidence is not None or (output / expected_filename).exists():
                        raise ReleaseError(
                            f"Darwin package appears before candidate metadata for {target_id}"
                        )
                elif native_evidence != expected_evidence:
                    raise ReleaseError(
                        f"Darwin package lacks native evidence for {target_id}"
                    )
                else:
                    safe_file(output, expected_filename, "signed macOS installer")
                    safe_file(output, expected_evidence, "macOS installer evidence")


def validate_release_context(
    state: dict[str, Any], config: dict[str, Any], go_binary: str
) -> None:
    expected_tag = f"connector-v{config['connector_version']}"
    expected_repo = os.environ.get("GITHUB_REPOSITORY", "")
    expected_ref = f"refs/tags/{expected_tag}"
    expected_builder = (
        f"https://github.com/{expected_repo}/{config['source_workflow']}@{expected_ref}"
    )
    expected_invocation = (
        f"https://github.com/{expected_repo}/actions/runs/{os.environ.get('GITHUB_RUN_ID', '')}/attempts/"
        f"{os.environ.get('GITHUB_RUN_ATTEMPT', '')}"
    )
    if (
        os.environ.get("GITHUB_ACTIONS") != "true"
        or os.environ.get("GITHUB_REF_TYPE") != "tag"
        or os.environ.get("GITHUB_REF_NAME") != expected_tag
        or os.environ.get("GITHUB_REF") != expected_ref
        or state["source"]["repository"] != f"https://github.com/{expected_repo}"
        or state["source"]["commit"] != os.environ.get("GITHUB_SHA")
        or state["builder_id"] != expected_builder
        or state["invocation_id"] != expected_invocation
    ):
        raise ReleaseError(
            "transferred release state does not match the protected GitHub tag context"
        )
    if go_version(go_binary) != config["go_version"]:
        raise ReleaseError(
            f"release requires {config['go_version']} in every metadata-producing job"
        )
    if (
        run(["git", "rev-parse", "HEAD"], cwd=REPO_ROOT, capture=True)
        != state["source"]["commit"]
    ):
        raise ReleaseError("checked-out HEAD does not match transferred release state")
    require_annotated_tag(expected_tag, state["source"]["commit"])
    if run(
        ["git", "status", "--porcelain", "--untracked-files=no"],
        cwd=REPO_ROOT,
        capture=True,
    ):
        raise ReleaseError("tracked source changed in a release metadata job")
    if source_snapshot_sha256() != state["source"]["snapshot_sha256"]:
        raise ReleaseError(
            "checked-out source does not match the transferred source snapshot"
        )


def validate_work_state_command(args: argparse.Namespace) -> None:
    output = release_output_directory(args.output)
    config = load_config(args.config)
    state = read_json(safe_file(output, WORK_STATE, "release work state"))
    validate_work_state(output, state, config, require_unsigned_artifacts=True)
    if state["release_mode"] != "release":
        raise ReleaseError(
            "transferred work-state validation is restricted to release mode"
        )
    validate_release_context(state, config, args.go)
    print(f"validated unsigned release transfer for {len(state['targets'])} targets")


def file_evidence(path: Path) -> dict[str, Any]:
    return {
        "filename": path.name,
        "sha256": sha256_file(path),
        "size": path.stat().st_size,
        "signature_bundle": f"{path.name}.sigstore.json",
    }


def finalize_package_entries(
    state: dict[str, Any],
    record: dict[str, Any],
    output: Path,
    connector_artifact_sha256: str,
    connector_native_signature: dict[str, Any],
    modules: list[dict[str, str]],
) -> tuple[list[dict[str, Any]], list[str]]:
    if state["release_mode"] != "release":
        if record["packages"]:
            raise ReleaseError("local unsigned output cannot contain native packages")
        return [], []
    result: list[dict[str, Any]] = []
    content_names: list[str] = []
    target = record["target"]
    for package in record["packages"]:
        package_path = safe_file(output, package["filename"], "native package")
        package_sha256 = sha256_file(package_path)
        package_size = package_path.stat().st_size
        candidate_sha256 = package["reproducible_candidate_sha256"]
        candidate_size = package["reproducible_candidate_size"]
        package_format = package["format"]
        native: dict[str, Any]
        extra_content: list[str] = []
        if package_format == "deb":
            if (
                package["native_signature"] != "none"
                or package["native_evidence"] is not None
                or package_sha256 != candidate_sha256
                or package_size != candidate_size
            ):
                raise ReleaseError(
                    f"Debian package is not its reproducible unsigned candidate for {target['id']}"
                )
            native = {"policy": "none", "status": "not-required"}
        elif package_format == "rpm":
            evidence_name = f"native-package-{target['id']}-rpm.json"
            if package["native_evidence"] != evidence_name:
                raise ReleaseError(f"RPM package lacks native evidence for {target['id']}")
            evidence_path = safe_file(output, evidence_name, "RPM native evidence")
            evidence = read_json(evidence_path)
            public_key_name = f"rpm-signing-{target['id']}.asc"
            if not isinstance(evidence, dict) or evidence.get("public_key") != public_key_name:
                raise ReleaseError(f"RPM evidence has an invalid public key for {target['id']}")
            public_key_path = safe_file(output, public_key_name, "RPM public key")
            fingerprint = evidence.get("fingerprint")
            validate_rpm_package_evidence(
                evidence,
                target_id=target["id"],
                package_name_value=package_path.name,
                package_sha256=package_sha256,
                expected_fingerprint=fingerprint,
                public_key_name=public_key_name,
                public_key_sha256=sha256_file(public_key_path),
            )
            native = {
                "policy": "rpm-openpgp",
                "status": "verified",
                "fingerprint": fingerprint,
                "evidence": file_evidence(evidence_path),
                "public_key": file_evidence(public_key_path),
            }
            extra_content.extend([evidence_name, public_key_name])
        elif package_format == "pkg":
            evidence_name = f"native-package-{target['id']}-pkg.json"
            if package["native_evidence"] != evidence_name:
                raise ReleaseError(
                    f"macOS installer lacks native evidence for {target['id']}"
                )
            evidence_path = safe_file(output, evidence_name, "macOS installer evidence")
            evidence = read_json(evidence_path)
            if connector_native_signature.get("status") != "verified":
                raise ReleaseError(
                    f"macOS installer cannot be admitted before its executable for {target['id']}"
                )
            installer_identity = (
                evidence.get("installer_identity") if isinstance(evidence, dict) else ""
            )
            validate_pkg_package_evidence(
                evidence,
                target_id=target["id"],
                package_name_value=package_path.name,
                package_sha256=package_sha256,
                expected_team_id=connector_native_signature["team_identifier"],
                expected_application_identity=connector_native_signature[
                    "signing_identity"
                ],
                expected_installer_identity=installer_identity,
            )
            native = {
                "policy": "apple-developer-id-installer-notarized-stapled",
                "status": "verified",
                "team_identifier": connector_native_signature["team_identifier"],
                "application_identity": connector_native_signature[
                    "signing_identity"
                ],
                "installer_identity": installer_identity,
                "evidence": file_evidence(evidence_path),
            }
            extra_content.append(evidence_name)
        else:
            raise ReleaseError(f"unsupported native package format {package_format!r}")

        sbom_name = f"{package_path.name}.spdx.json"
        provenance_name = f"{package_path.name}.intoto.json"
        sbom_path = output / sbom_name
        provenance_path = output / provenance_name
        write_exclusive_canonical_json(
            sbom_path,
            make_package_sbom(state, record, package, package_path, modules),
        )
        write_exclusive_canonical_json(
            provenance_path,
            make_package_provenance(
                state,
                record,
                package,
                package_path,
                connector_artifact_sha256,
            ),
        )
        result.append(
            {
                "format": package_format,
                "artifact": {
                    "filename": package_path.name,
                    "sha256": package_sha256,
                    "size": package_size,
                    "reproducible_candidate_sha256": candidate_sha256,
                    "reproducible_candidate_size": candidate_size,
                    "signature_bundle": f"{package_path.name}.sigstore.json",
                },
                "sbom": {
                    "format": "SPDX-2.3-json",
                    **file_evidence(sbom_path),
                },
                "provenance": {
                    "predicate_type": SLSA_PREDICATE,
                    **file_evidence(provenance_path),
                    "attestation_bundle": f"{package_path.name}.intoto.sigstore.json",
                },
                "native_signature": native,
            }
        )
        content_names.extend(
            [package_path.name, sbom_name, provenance_name, *extra_content]
        )
    return result, content_names


def connector_release_metadata_value(
    manifest: dict[str, Any], manifest_path: Path
) -> dict[str, Any]:
    version = manifest["connector_version"]
    tag = f"connector-v{version}"
    repository = manifest["source"]["repository"]
    assets: list[dict[str, Any]] = []
    for target in manifest["targets"]:
        for package in target["packages"]:
            artifact = package["artifact"]
            assets.append(
                {
                    "os": target["os"],
                    "arch": target["arch"],
                    "package_format": package["format"],
                    "filename": artifact["filename"],
                    "download_url": (
                        f"{repository}/releases/download/{tag}/{artifact['filename']}"
                    ),
                    "sha256": artifact["sha256"],
                    "size": artifact["size"],
                    "signature_bundle": artifact["signature_bundle"],
                    "sbom": package["sbom"],
                    "provenance": package["provenance"],
                }
            )
    return {
        "format_version": 1,
        "release_mode": "release",
        "releasable": True,
        "source_repository": repository,
        "source_commit": manifest["source"]["commit"],
        "version": version,
        "tag": tag,
        "codex_version": manifest["codex_version"],
        "schema_digest": manifest["appserver_schema_sha256"],
        "manifest": {
            "filename": MANIFEST,
            "sha256": sha256_file(manifest_path),
            "size": manifest_path.stat().st_size,
            "signature_bundle": f"{MANIFEST}.sigstore.json",
        },
        "config_path_hint": "~/.config/sub2api-codex-connector/connector.json",
        "pair_command": "sub2api-codex-connector-ctl pair",
        "start_command": "sub2api-codex-connector-ctl start",
        "assets": assets,
    }


def validate_connector_release_metadata(
    metadata: Any, manifest: dict[str, Any], manifest_path: Path
) -> None:
    if not isinstance(metadata, dict):
        raise ReleaseError("Connector self-service release metadata must be an object")
    require_exact_keys(
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
        "Connector self-service release metadata",
    )
    expected = connector_release_metadata_value(manifest, manifest_path)
    if metadata != expected:
        raise ReleaseError(
            "Connector self-service release metadata does not match the signed package matrix"
        )
    if (
        metadata["format_version"] != 1
        or metadata["source_repository"] != RELEASE_REPOSITORY
        or len(metadata["assets"]) != 6
    ):
        raise ReleaseError(
            "Connector self-service release metadata is not the official complete release"
        )


def validate_pre_finalize_inventory(output: Path, state: dict[str, Any]) -> None:
    expected = {WORK_STATE}
    release_mode = state["release_mode"] == "release"
    for record in state["targets"]:
        target_id = record["target"]["id"]
        expected.add(record["filename"])
        if not release_mode:
            continue
        if record["target"]["goos"] == "darwin":
            expected.add(f"native-{target_id}.json")
        for package in record["packages"]:
            expected.add(package["filename"])
            evidence_name = package["native_evidence"]
            if evidence_name is not None:
                expected.add(evidence_name)
                if package["format"] == "rpm":
                    expected.add(f"rpm-signing-{target_id}.asc")
    entries = list(output.iterdir())
    for path in entries:
        try:
            mode = path.lstat().st_mode
        except OSError as exc:
            raise ReleaseError(
                f"cannot inspect pre-finalize entry {path.name}: {exc}"
            ) from exc
        if not stat.S_ISREG(mode) or path.is_symlink():
            raise ReleaseError(
                f"pre-finalize entry must be a regular non-symlink file: {path.name}"
            )
    actual = {path.name for path in entries}
    if actual != expected:
        raise ReleaseError(
            f"pre-finalize release has missing or unlisted entries: {sorted(actual ^ expected)}"
        )


def finalize(args: argparse.Namespace) -> None:
    output = release_output_directory(args.output)
    state = read_json(safe_file(output, WORK_STATE, "release work state"))
    config = load_config(args.config)
    validate_work_state(output, state, config, require_unsigned_artifacts=False)
    validate_pre_finalize_inventory(output, state)
    mode = state.get("release_mode")
    if mode == "release":
        if platform.system() != "Darwin":
            raise ReleaseError(
                "release finalization must run on macOS to verify native signatures"
            )
        validate_release_context(state, config, args.go)
        state["build_finished_at"] = (
            dt.datetime.now(tz=dt.timezone.utc).isoformat().replace("+00:00", "Z")
        )
    manifest_targets: list[dict[str, Any]] = []
    content_names: list[str] = []
    for record in state["targets"]:
        target = record["target"]
        artifact = safe_file(
            output, record["filename"], "artifact", executable=True
        )
        if (mode == "local-unsigned" or target["native_signature"] == "none") and (
            artifact.stat().st_size != record["unsigned_size"]
            or sha256_file(artifact) != record["unsigned_sha256"]
        ):
            raise ReleaseError(
                f"artifact changed after reproducibility check: {target['id']}"
            )
        native: dict[str, Any]
        if target["native_signature"] == "apple-developer-id-and-notarization":
            if mode == "release":
                evidence_name = f"native-{target['id']}.json"
                evidence_path = safe_file(
                    output, evidence_name, "native-signature evidence"
                )
                evidence = read_json(evidence_path)
                expected_team_id = (
                    evidence.get("team_identifier")
                    if isinstance(evidence, dict)
                    else ""
                )
                expected_signing_identity = (
                    evidence.get("signing_identity")
                    if isinstance(evidence, dict)
                    else ""
                )
                validate_native_evidence(
                    evidence,
                    target_id=target["id"],
                    artifact_name_value=artifact.name,
                    artifact_sha256=sha256_file(artifact),
                    expected_team_id=expected_team_id,
                    expected_signing_identity=expected_signing_identity,
                )
                verify_codesign_identity(
                    artifact,
                    expected_team_id,
                    expected_signing_identity,
                )
                native = {
                    "policy": target["native_signature"],
                    "status": "verified",
                    "team_identifier": evidence["team_identifier"],
                    "signing_identity": evidence["signing_identity"],
                    "evidence": {
                        "filename": evidence_name,
                        "sha256": sha256_file(evidence_path),
                        "size": evidence_path.stat().st_size,
                        "signature_bundle": f"{evidence_name}.sigstore.json",
                    },
                }
                content_names.append(evidence_name)
            else:
                native = {
                    "policy": target["native_signature"],
                    "status": "not-performed-local-unsigned",
                }
        else:
            native = {"policy": "none", "status": "not-required"}
        final_sha = sha256_file(artifact)
        modules = parse_go_modules(args.go, artifact)
        sbom_name = f"{artifact.name}.spdx.json"
        provenance_name = f"{artifact.name}.intoto.json"
        sbom_path = output / sbom_name
        provenance_path = output / provenance_name
        write_exclusive_canonical_json(
            sbom_path, make_sbom(state, record, artifact, final_sha, modules)
        )
        write_exclusive_canonical_json(
            provenance_path,
            make_provenance(state, record, artifact, final_sha, modules),
        )
        content_names.extend([artifact.name, sbom_name, provenance_name])
        package_entries, package_content_names = finalize_package_entries(
            state, record, output, final_sha, native, modules
        )
        content_names.extend(package_content_names)
        manifest_targets.append(
            {
                "id": target["id"],
                "os": target["goos"],
                "arch": target["goarch"],
                "artifact": {
                    "filename": artifact.name,
                    "sha256": final_sha,
                    "size": artifact.stat().st_size,
                    "reproducible_candidate_sha256": record["unsigned_sha256"],
                    "reproducible_candidate_size": record["unsigned_size"],
                    "signature_bundle": f"{artifact.name}.sigstore.json",
                },
                "sbom": {
                    "format": "SPDX-2.3-json",
                    "filename": sbom_name,
                    "sha256": sha256_file(sbom_path),
                    "size": sbom_path.stat().st_size,
                    "signature_bundle": f"{sbom_name}.sigstore.json",
                },
                "provenance": {
                    "predicate_type": SLSA_PREDICATE,
                    "filename": provenance_name,
                    "sha256": sha256_file(provenance_path),
                    "size": provenance_path.stat().st_size,
                    "signature_bundle": f"{provenance_name}.sigstore.json",
                    "attestation_bundle": f"{artifact.name}.intoto.sigstore.json",
                },
                "native_signature": native,
                "packages": package_entries,
            }
        )
    marker: str | None = None
    if mode == "local-unsigned":
        marker = LOCAL_MARKER
        write_exclusive_bytes(
            output / marker,
            b"LOCAL UNSIGNED DETERMINISM FIXTURE. NOT A RELEASE. DO NOT DISTRIBUTE OR INSTALL.\n",
        )
        content_names.append(marker)
    release_metadata_entry = (
        {
            "filename": CONNECTOR_RELEASE_METADATA,
            "signature_bundle": f"{CONNECTOR_RELEASE_METADATA}.sigstore.json",
        }
        if mode == "release"
        else None
    )
    manifest = {
        "$schema": "https://sub2api-codex.invalid/schemas/connector-release-manifest-v1.json",
        "format_version": 1,
        "release_mode": mode,
        "releasable": mode == "release",
        "product": config["product"],
        "connector_version": config["connector_version"],
        "control_protocol_version": config["control_protocol_version"],
        "codex_version": config["codex_version"],
        "appserver_schema_sha256": config["appserver_schema_sha256"],
        "server_api_release": config["server_api_release"],
        "source": state["source"],
        "build": {
            "go_version": state["go_version"],
            "source_date_epoch": state["source_date_epoch"],
            "created_at": state["build_finished_at"],
            "builder_id": state["builder_id"],
            "invocation_id": state["invocation_id"],
            "started_at": state["build_started_at"],
            "finished_at": state["build_finished_at"],
            "reproducibility_passes": 2,
        },
        "signing": {
            "cosign_version": config["cosign_version"],
            "certificate_oidc_issuer": OIDC_ISSUER if mode == "release" else None,
            "certificate_identity": state["builder_id"] if mode == "release" else None,
            "certificate_github_workflow_sha": state["source"]["commit"]
            if mode == "release"
            else None,
            "certificate_github_workflow_trigger": "push"
            if mode == "release"
            else None,
            "manifest_bundle": f"{MANIFEST}.sigstore.json",
            "checksums_bundle": f"{CHECKSUMS}.sigstore.json",
        },
        "checksums_file": CHECKSUMS,
        "local_unsigned_marker": marker,
        "connector_release_metadata": release_metadata_entry,
        "targets": manifest_targets,
    }
    manifest_path = output / MANIFEST
    write_exclusive_canonical_json(manifest_path, manifest)
    content_names.append(MANIFEST)
    if mode == "release":
        metadata_path = output / CONNECTOR_RELEASE_METADATA
        write_exclusive_canonical_json(
            metadata_path,
            connector_release_metadata_value(manifest, manifest_path),
        )
        content_names.append(CONNECTOR_RELEASE_METADATA)
    checksum_lines = [
        f"{sha256_file(output / name)}  {name}" for name in sorted(content_names)
    ]
    write_exclusive_bytes(
        output / CHECKSUMS, ("\n".join(checksum_lines) + "\n").encode("ascii")
    )
    (output / WORK_STATE).unlink()
    print(f"finalized {mode} release evidence in {output}")


def expected_content_files(manifest: dict[str, Any]) -> list[str]:
    names: list[str] = []
    marker = manifest.get("local_unsigned_marker")
    if marker is not None:
        names.append(marker)
    release_metadata = manifest.get("connector_release_metadata")
    if release_metadata is not None:
        names.append(release_metadata["filename"])
    for target in manifest["targets"]:
        names.extend(
            [
                target["artifact"]["filename"],
                target["sbom"]["filename"],
                target["provenance"]["filename"],
            ]
        )
        evidence = target["native_signature"].get("evidence")
        if evidence:
            names.append(evidence["filename"])
        for package in target["packages"]:
            names.extend(
                [
                    package["artifact"]["filename"],
                    package["sbom"]["filename"],
                    package["provenance"]["filename"],
                ]
            )
            package_evidence = package["native_signature"].get("evidence")
            if package_evidence:
                names.append(package_evidence["filename"])
            public_key = package["native_signature"].get("public_key")
            if public_key:
                names.append(public_key["filename"])
    names.append(MANIFEST)
    return sorted(names)


def signing_plan(
    manifest: dict[str, Any],
) -> tuple[list[tuple[str, str]], list[tuple[str, str]]]:
    blobs = [
        (MANIFEST, manifest["signing"]["manifest_bundle"]),
        (CHECKSUMS, manifest["signing"]["checksums_bundle"]),
    ]
    release_metadata = manifest.get("connector_release_metadata")
    if release_metadata is not None:
        blobs.append(
            (release_metadata["filename"], release_metadata["signature_bundle"])
        )
    attestations: list[tuple[str, str]] = []
    for target in manifest["targets"]:
        for field in ("artifact", "sbom", "provenance"):
            blobs.append((target[field]["filename"], target[field]["signature_bundle"]))
        native_evidence = target["native_signature"].get("evidence")
        if native_evidence:
            blobs.append(
                (native_evidence["filename"], native_evidence["signature_bundle"])
            )
        attestations.append(
            (
                target["provenance"]["filename"],
                target["provenance"]["attestation_bundle"],
            )
        )
        for package in target["packages"]:
            for field in ("artifact", "sbom", "provenance"):
                blobs.append(
                    (package[field]["filename"], package[field]["signature_bundle"])
                )
            package_evidence = package["native_signature"].get("evidence")
            if package_evidence:
                blobs.append(
                    (
                        package_evidence["filename"],
                        package_evidence["signature_bundle"],
                    )
                )
            public_key = package["native_signature"].get("public_key")
            if public_key:
                blobs.append((public_key["filename"], public_key["signature_bundle"]))
            attestations.append(
                (
                    package["provenance"]["filename"],
                    package["provenance"]["attestation_bundle"],
                )
            )
    return blobs, attestations


def core_release_inventory(
    output: Path, manifest: dict[str, Any]
) -> list[dict[str, Any]]:
    blobs, attestations = signing_plan(manifest)
    names = [
        *expected_content_files(manifest),
        CHECKSUMS,
        *(bundle for _, bundle in blobs),
        *(bundle for _, bundle in attestations),
    ]
    if len(names) != len(set(names)):
        raise ReleaseError("core release inventory contains duplicate filenames")
    inventory: list[dict[str, Any]] = []
    for name in sorted(names):
        path = safe_file(output, name, "core release inventory file")
        inventory.append(
            {"filename": name, "sha256": sha256_file(path), "size": path.stat().st_size}
        )
    return inventory


def validate_inventory_records(
    value: Any, context: str, *, key: str = "filename"
) -> dict[str, dict[str, Any]]:
    if not isinstance(value, list) or not value:
        raise ReleaseError(f"{context} must be a non-empty array")
    result: dict[str, dict[str, Any]] = {}
    order: list[str] = []
    for item in value:
        if not isinstance(item, dict):
            raise ReleaseError(f"{context} contains a non-object entry")
        require_exact_keys(item, {key, "sha256", "size"}, f"{context} entry")
        name = item[key]
        if (
            not isinstance(name, str)
            or not SAFE_NAME.fullmatch(name)
            or name in result
            or not isinstance(item["sha256"], str)
            or not HEX_SHA256.fullmatch(item["sha256"])
            or not isinstance(item["size"], int)
            or isinstance(item["size"], bool)
            or item["size"] < 0
        ):
            raise ReleaseError(f"{context} contains invalid or duplicate evidence")
        result[name] = item
        order.append(name)
    if order != sorted(order):
        raise ReleaseError(f"{context} must be sorted by {key}")
    return result


def receipt_file_evidence(
    path: Path, *, signature_bundle: str | None = None
) -> dict[str, Any]:
    value: dict[str, Any] = {
        "filename": path.name,
        "sha256": sha256_file(path),
        "size": path.stat().st_size,
    }
    if signature_bundle is not None:
        value["signature_bundle"] = signature_bundle
    return value


def validate_receipt_file_evidence(
    value: Any,
    context: str,
    *,
    expected_filename: str,
    expected_signature_bundle: str | None,
) -> None:
    if not isinstance(value, dict):
        raise ReleaseError(f"{context} must be an object")
    keys = {"filename", "sha256", "size"}
    if expected_signature_bundle is not None:
        keys.add("signature_bundle")
    require_exact_keys(value, keys, context)
    if (
        value["filename"] != expected_filename
        or not isinstance(value["sha256"], str)
        or not HEX_SHA256.fullmatch(value["sha256"])
        or not isinstance(value["size"], int)
        or isinstance(value["size"], bool)
        or value["size"] <= 0
        or (
            expected_signature_bundle is not None
            and value["signature_bundle"] != expected_signature_bundle
        )
    ):
        raise ReleaseError(f"{context} is invalid")


def platform_receipt_value(
    output: Path,
    manifest: dict[str, Any],
    platform_name: str,
    args: argparse.Namespace,
) -> dict[str, Any]:
    target_ids = (
        ["linux-amd64", "linux-arm64"]
        if platform_name == "linux"
        else ["darwin-amd64", "darwin-arm64"]
    )
    selected_targets = [
        target for target in manifest["targets"] if target["id"] in target_ids
    ]
    packages = [
        {
            "target_id": target["id"],
            "package_format": package["format"],
            "filename": package["artifact"]["filename"],
            "sha256": package["artifact"]["sha256"],
            "size": package["artifact"]["size"],
        }
        for target in selected_targets
        for package in target["packages"]
    ]
    manifest_path = safe_file(output, MANIFEST, "manifest")
    metadata_path = safe_file(
        output, CONNECTOR_RELEASE_METADATA, "Connector release metadata"
    )
    checksums_path = safe_file(output, CHECKSUMS, "checksums")
    apple_trust = (
        {
            "team_identifier": args.apple_team_id,
            "application_identity": args.apple_signing_identity,
            "installer_identity": args.apple_installer_identity,
        }
        if platform_name == "darwin"
        else None
    )
    rpm_trust = (
        {"signing_fingerprint": args.rpm_signing_fingerprint}
        if platform_name == "linux"
        else None
    )
    return {
        "$schema": "https://sub2api-codex.invalid/schemas/connector-platform-verification-receipt-v1.json",
        "format_version": 1,
        "kind": "sub2api-codex-connector-platform-verification",
        "platform": platform_name,
        "release": {
            "source_repository": manifest["source"]["repository"],
            "source_commit": manifest["source"]["commit"],
            "version": manifest["connector_version"],
            "tag": f"connector-v{manifest['connector_version']}",
            "codex_version": manifest["codex_version"],
            "schema_digest": manifest["appserver_schema_sha256"],
            "control_protocol_version": manifest["control_protocol_version"],
        },
        "evidence": {
            "manifest": receipt_file_evidence(
                manifest_path, signature_bundle=f"{MANIFEST}.sigstore.json"
            ),
            "release_metadata": receipt_file_evidence(
                metadata_path,
                signature_bundle=f"{CONNECTOR_RELEASE_METADATA}.sigstore.json",
            ),
            "checksums": receipt_file_evidence(
                checksums_path, signature_bundle=f"{CHECKSUMS}.sigstore.json"
            ),
        },
        "trust": {
            "sigstore": {
                "certificate_oidc_issuer": args.certificate_oidc_issuer,
                "certificate_identity": args.certificate_identity,
                "certificate_github_workflow_sha": args.certificate_github_workflow_sha,
                "certificate_github_workflow_trigger": args.certificate_github_workflow_trigger,
            },
            "apple": apple_trust,
            "rpm": rpm_trust,
        },
        "verification_run": {
            "repository": RELEASE_REPOSITORY.removeprefix("https://github.com/"),
            "run_id": args.github_run_id,
            "run_attempt": args.github_run_attempt,
        },
        "verified_targets": target_ids,
        "verified_packages": packages,
        "core_inventory": core_release_inventory(output, manifest),
    }


def validate_platform_receipt(
    receipt: Any, expected_platform: str | None = None
) -> dict[str, Any]:
    if not isinstance(receipt, dict):
        raise ReleaseError("platform verification receipt must be an object")
    require_exact_keys(
        receipt,
        {
            "$schema",
            "format_version",
            "kind",
            "platform",
            "release",
            "evidence",
            "trust",
            "verification_run",
            "verified_targets",
            "verified_packages",
            "core_inventory",
        },
        "platform verification receipt",
    )
    platform_name = receipt["platform"]
    if platform_name not in PLATFORM_RECEIPTS or (
        expected_platform is not None and platform_name != expected_platform
    ):
        raise ReleaseError("platform verification receipt has an invalid platform")
    if (
        receipt["$schema"]
        != "https://sub2api-codex.invalid/schemas/connector-platform-verification-receipt-v1.json"
        or receipt["format_version"] != 1
        or receipt["kind"] != "sub2api-codex-connector-platform-verification"
    ):
        raise ReleaseError("platform verification receipt format is invalid")
    release = receipt["release"]
    if not isinstance(release, dict):
        raise ReleaseError("platform receipt release must be an object")
    require_exact_keys(
        release,
        {
            "source_repository",
            "source_commit",
            "version",
            "tag",
            "codex_version",
            "schema_digest",
            "control_protocol_version",
        },
        "platform receipt release",
    )
    if (
        release["source_repository"] != RELEASE_REPOSITORY
        or not isinstance(release["source_commit"], str)
        or not HEX_GIT_COMMIT.fullmatch(release["source_commit"])
        or not isinstance(release["version"], str)
        or not re.fullmatch(r"\d+\.\d+\.\d+", release["version"])
        or release["tag"] != f"connector-v{release['version']}"
        or not isinstance(release["codex_version"], str)
        or not re.fullmatch(r"\d+\.\d+\.\d+", release["codex_version"])
        or not isinstance(release["schema_digest"], str)
        or not HEX_SHA256.fullmatch(release["schema_digest"])
        or release["control_protocol_version"] != 1
    ):
        raise ReleaseError("platform receipt release identity is invalid")
    evidence = receipt["evidence"]
    if not isinstance(evidence, dict):
        raise ReleaseError("platform receipt evidence must be an object")
    require_exact_keys(
        evidence, {"manifest", "release_metadata", "checksums"}, "platform receipt evidence"
    )
    validate_receipt_file_evidence(
        evidence["manifest"],
        "platform receipt manifest",
        expected_filename=MANIFEST,
        expected_signature_bundle=f"{MANIFEST}.sigstore.json",
    )
    validate_receipt_file_evidence(
        evidence["release_metadata"],
        "platform receipt release metadata",
        expected_filename=CONNECTOR_RELEASE_METADATA,
        expected_signature_bundle=f"{CONNECTOR_RELEASE_METADATA}.sigstore.json",
    )
    validate_receipt_file_evidence(
        evidence["checksums"],
        "platform receipt checksums",
        expected_filename=CHECKSUMS,
        expected_signature_bundle=f"{CHECKSUMS}.sigstore.json",
    )
    trust = receipt["trust"]
    if not isinstance(trust, dict):
        raise ReleaseError("platform receipt trust must be an object")
    require_exact_keys(trust, {"sigstore", "apple", "rpm"}, "platform receipt trust")
    sigstore = trust["sigstore"]
    if not isinstance(sigstore, dict):
        raise ReleaseError("platform receipt Sigstore trust must be an object")
    require_exact_keys(
        sigstore,
        {
            "certificate_oidc_issuer",
            "certificate_identity",
            "certificate_github_workflow_sha",
            "certificate_github_workflow_trigger",
        },
        "platform receipt Sigstore trust",
    )
    expected_identity = (
        f"{RELEASE_REPOSITORY}/.github/workflows/connector-release.yml"
        f"@refs/tags/{release['tag']}"
    )
    if sigstore != {
        "certificate_oidc_issuer": OIDC_ISSUER,
        "certificate_identity": expected_identity,
        "certificate_github_workflow_sha": release["source_commit"],
        "certificate_github_workflow_trigger": "push",
    }:
        raise ReleaseError("platform receipt Sigstore trust is invalid")
    verification_run = receipt["verification_run"]
    if not isinstance(verification_run, dict):
        raise ReleaseError("platform receipt verification run must be an object")
    require_exact_keys(
        verification_run,
        {"repository", "run_id", "run_attempt"},
        "platform receipt verification run",
    )
    if (
        verification_run["repository"]
        != RELEASE_REPOSITORY.removeprefix("https://github.com/")
        or not isinstance(verification_run["run_id"], int)
        or isinstance(verification_run["run_id"], bool)
        or verification_run["run_id"] <= 0
        or not isinstance(verification_run["run_attempt"], int)
        or isinstance(verification_run["run_attempt"], bool)
        or verification_run["run_attempt"] <= 0
    ):
        raise ReleaseError("platform receipt verification run is invalid")
    expected_targets = (
        ["linux-amd64", "linux-arm64"]
        if platform_name == "linux"
        else ["darwin-amd64", "darwin-arm64"]
    )
    if receipt["verified_targets"] != expected_targets:
        raise ReleaseError("platform receipt target matrix is incomplete")
    if platform_name == "linux":
        if trust["apple"] is not None or not isinstance(trust["rpm"], dict):
            raise ReleaseError("Linux platform receipt trust is invalid")
        require_exact_keys(trust["rpm"], {"signing_fingerprint"}, "RPM trust")
        validate_rpm_fingerprint(trust["rpm"]["signing_fingerprint"])
        expected_formats = ["deb", "rpm", "deb", "rpm"]
    else:
        if trust["rpm"] is not None or not isinstance(trust["apple"], dict):
            raise ReleaseError("Darwin platform receipt trust is invalid")
        require_exact_keys(
            trust["apple"],
            {"team_identifier", "application_identity", "installer_identity"},
            "Apple trust",
        )
        validate_apple_identity(
            trust["apple"]["team_identifier"], trust["apple"]["application_identity"]
        )
        validate_apple_installer_identity(
            trust["apple"]["team_identifier"], trust["apple"]["installer_identity"]
        )
        expected_formats = ["pkg", "pkg"]
    packages = receipt["verified_packages"]
    if not isinstance(packages, list) or len(packages) != len(expected_formats):
        raise ReleaseError("platform receipt package matrix is incomplete")
    expected_package_pairs = [
        (target, package_format)
        for target in expected_targets
        for package_format in (["deb", "rpm"] if platform_name == "linux" else ["pkg"])
    ]
    inventory = validate_inventory_records(
        receipt["core_inventory"], "platform receipt core inventory"
    )
    if set(inventory) != expected_core_asset_names(release["version"]):
        raise ReleaseError("platform receipt core inventory is not the fixed 92-file matrix")
    for item, expected_pair in zip(packages, expected_package_pairs, strict=True):
        if not isinstance(item, dict):
            raise ReleaseError("platform receipt package entry must be an object")
        require_exact_keys(
            item,
            {"target_id", "package_format", "filename", "sha256", "size"},
            "platform receipt package entry",
        )
        target_id, package_format = expected_pair
        expected_filename = (
            f"sub2api-codex-connector_{release['version']}_"
            f"{target_id.replace('-', '_')}.{package_format}"
        )
        if (
            item["target_id"] != target_id
            or item["package_format"] != package_format
            or item["filename"] != expected_filename
            or item["filename"] not in inventory
            or inventory[item["filename"]]["sha256"] != item["sha256"]
            or inventory[item["filename"]]["size"] != item["size"]
        ):
            raise ReleaseError("platform receipt package evidence is invalid")
    for descriptor in evidence.values():
        file_item = inventory.get(descriptor["filename"])
        bundle_item = inventory.get(descriptor["signature_bundle"])
        if (
            file_item is None
            or bundle_item is None
            or file_item["sha256"] != descriptor["sha256"]
            or file_item["size"] != descriptor["size"]
        ):
            raise ReleaseError("platform receipt evidence is absent from core inventory")
    forbidden = {
        *PLATFORM_RECEIPTS.values(),
        PUBLIC_RELEASE_DESCRIPTOR,
        AGGREGATE_RECEIPT,
        AGGREGATE_RECEIPT_BUNDLE,
    }
    if forbidden & set(inventory):
        raise ReleaseError("platform receipt core inventory contains post-release evidence")
    return receipt


def write_platform_receipt(
    receipt_path: Path,
    output: Path,
    manifest: dict[str, Any],
    platform_name: str,
    args: argparse.Namespace,
) -> None:
    receipt_path = receipt_path.absolute()
    if receipt_path.name != PLATFORM_RECEIPTS[platform_name]:
        raise ReleaseError(
            f"{platform_name} verification receipt must be named {PLATFORM_RECEIPTS[platform_name]}"
        )
    try:
        receipt_parent = receipt_path.parent.resolve(strict=True)
    except OSError as exc:
        raise ReleaseError(f"verification receipt parent is unavailable: {exc}") from exc
    if receipt_parent == output or output in receipt_parent.parents:
        raise ReleaseError("verification receipt must be outside the core release directory")
    receipt = platform_receipt_value(output, manifest, platform_name, args)
    validate_platform_receipt(receipt, platform_name)
    write_exclusive_canonical_json(receipt_path, receipt)


def require_cosign_version(cosign: str, config: dict[str, Any]) -> None:
    output = run([cosign, "version"], capture=True)
    expected = config["cosign_version"].removeprefix("v")
    if not re.search(
        rf"(?:^|[^0-9A-Za-z])v?{re.escape(expected)}(?:$|[^0-9A-Za-z])", output
    ):
        raise ReleaseError(
            f"release requires cosign {config['cosign_version']}, found: {output}"
        )


def sign(args: argparse.Namespace) -> None:
    output = release_output_directory(args.output)
    config = load_config(args.config)
    manifest = read_canonical_json(
        safe_file(output, MANIFEST, "manifest"), "release manifest"
    )
    validate_manifest_shape(manifest, config)
    if (
        manifest.get("release_mode") != "release"
        or manifest.get("releasable") is not True
    ):
        raise ReleaseError("only finalized release-mode output can be signed")
    if (output / LOCAL_MARKER).exists():
        raise ReleaseError("local unsigned output can never be signed")
    validate_apple_identity(args.apple_team_id, args.apple_signing_identity)
    validate_apple_installer_identity(
        args.apple_team_id, args.apple_installer_identity
    )
    validate_rpm_fingerprint(args.rpm_signing_fingerprint)
    validate_manifest_release_context(manifest, config)
    validate_finalized_release_for_signing(
        output,
        manifest,
        args.apple_team_id,
        args.apple_signing_identity,
        args.apple_installer_identity,
        args.rpm_signing_fingerprint,
    )
    require_cosign_version(args.cosign, config)
    blobs, attestations = signing_plan(manifest)
    for filename, bundle_name in [*blobs, *attestations]:
        safe_file(output, filename, "signing input")
        if not isinstance(bundle_name, str) or not SAFE_NAME.fullmatch(bundle_name):
            raise ReleaseError(f"unsafe signature bundle filename {bundle_name!r}")
        bundle = output / bundle_name
        if bundle.exists():
            raise ReleaseError(f"refusing to overwrite signature bundle {bundle_name}")
    env = os.environ.copy()
    env["COSIGN_EXPERIMENTAL"] = "1"
    for filename, bundle_name in blobs:
        run(
            [
                args.cosign,
                "sign-blob",
                "--yes",
                "--bundle",
                str(output / bundle_name),
                str(output / filename),
            ],
            env=env,
        )
    for statement_name, bundle_name in attestations:
        run(
            [
                args.cosign,
                "attest-blob",
                "--yes",
                "--bundle",
                str(output / bundle_name),
                "--statement",
                str(output / statement_name),
            ],
            env=env,
        )
    print(
        f"created {len(blobs)} blob signatures and {len(attestations)} provenance attestations"
    )


def verify_blob(
    cosign: str,
    output: Path,
    filename: str,
    bundle_name: str,
    issuer: str,
    identity: str,
    workflow_sha: str,
    workflow_trigger: str,
) -> None:
    file_path = safe_file(output, filename, "signed file")
    bundle_path = safe_file(output, bundle_name, "signature bundle")
    run(
        [
            cosign,
            "verify-blob",
            str(file_path),
            "--bundle",
            str(bundle_path),
            "--certificate-identity",
            identity,
            "--certificate-oidc-issuer",
            issuer,
            "--certificate-github-workflow-sha",
            workflow_sha,
            "--certificate-github-workflow-trigger",
            workflow_trigger,
        ],
        capture=True,
    )


def verify_attestation(
    cosign: str,
    output: Path,
    artifact: dict[str, Any],
    provenance: dict[str, Any],
    issuer: str,
    identity: str,
    workflow_sha: str,
    workflow_trigger: str,
) -> None:
    bundle = safe_file(output, provenance["attestation_bundle"], "attestation bundle")
    run(
        [
            cosign,
            "verify-blob-attestation",
            "--bundle",
            str(bundle),
            "--certificate-identity",
            identity,
            "--certificate-oidc-issuer",
            issuer,
            "--certificate-github-workflow-sha",
            workflow_sha,
            "--certificate-github-workflow-trigger",
            workflow_trigger,
            "--type",
            "slsaprovenance1",
            "--digest",
            artifact["sha256"],
            "--digestAlg",
            "sha256",
        ],
        capture=True,
    )


def validate_target_shape(
    target: dict[str, Any], config: dict[str, Any], release_mode: str
) -> None:
    if not isinstance(target, dict):
        raise ReleaseError("manifest target must be an object")
    require_exact_keys(
        target,
        {
            "id",
            "os",
            "arch",
            "artifact",
            "sbom",
            "provenance",
            "native_signature",
            "packages",
        },
        "target",
    )
    configured = next(
        (item for item in config["targets"] if item["id"] == target.get("id")), None
    )
    if configured is None or (
        target["os"] != configured["goos"] or target["arch"] != configured["goarch"]
    ):
        raise ReleaseError(
            f"manifest target {target.get('id')!r} does not match the admitted OS/architecture matrix"
        )
    expected_artifact = artifact_name(config, configured)
    artifact = target["artifact"]
    if not isinstance(artifact, dict):
        raise ReleaseError(f"manifest artifact for {target['id']} must be an object")
    require_exact_keys(
        artifact,
        {
            "filename",
            "sha256",
            "size",
            "reproducible_candidate_sha256",
            "reproducible_candidate_size",
            "signature_bundle",
        },
        "artifact",
    )
    if (
        artifact["filename"] != expected_artifact
        or artifact["signature_bundle"] != f"{expected_artifact}.sigstore.json"
        or not HEX_SHA256.fullmatch(artifact["sha256"])
        or not HEX_SHA256.fullmatch(artifact["reproducible_candidate_sha256"])
        or not isinstance(artifact["size"], int)
        or artifact["size"] <= 0
        or not isinstance(artifact["reproducible_candidate_size"], int)
        or artifact["reproducible_candidate_size"] <= 0
    ):
        raise ReleaseError(f"manifest artifact metadata is invalid for {target['id']}")
    sbom = target["sbom"]
    if not isinstance(sbom, dict):
        raise ReleaseError(f"manifest SBOM for {target['id']} must be an object")
    require_exact_keys(
        sbom, {"format", "filename", "sha256", "size", "signature_bundle"}, "SBOM"
    )
    expected_sbom = f"{expected_artifact}.spdx.json"
    if (
        sbom["format"] != "SPDX-2.3-json"
        or sbom["filename"] != expected_sbom
        or sbom["signature_bundle"] != f"{expected_sbom}.sigstore.json"
        or not HEX_SHA256.fullmatch(sbom["sha256"])
        or not isinstance(sbom["size"], int)
        or sbom["size"] <= 0
    ):
        raise ReleaseError(f"manifest SBOM metadata is invalid for {target['id']}")
    provenance = target["provenance"]
    if not isinstance(provenance, dict):
        raise ReleaseError(f"manifest provenance for {target['id']} must be an object")
    require_exact_keys(
        provenance,
        {
            "predicate_type",
            "filename",
            "sha256",
            "size",
            "signature_bundle",
            "attestation_bundle",
        },
        "provenance",
    )
    expected_provenance = f"{expected_artifact}.intoto.json"
    if (
        provenance["predicate_type"] != SLSA_PREDICATE
        or provenance["filename"] != expected_provenance
        or provenance["signature_bundle"] != f"{expected_provenance}.sigstore.json"
        or provenance["attestation_bundle"]
        != f"{expected_artifact}.intoto.sigstore.json"
        or not HEX_SHA256.fullmatch(provenance["sha256"])
        or not isinstance(provenance["size"], int)
        or provenance["size"] <= 0
    ):
        raise ReleaseError(
            f"manifest provenance metadata is invalid for {target['id']}"
        )
    native = target["native_signature"]
    if not isinstance(native, dict):
        raise ReleaseError(
            f"manifest native signature state for {target['id']} must be an object"
        )
    if configured["native_signature"] == "none":
        if native != {"policy": "none", "status": "not-required"}:
            raise ReleaseError(
                f"manifest native signature state is invalid for {target['id']}"
            )
    elif release_mode == "release":
        require_exact_keys(
            native,
            {"policy", "status", "team_identifier", "signing_identity", "evidence"},
            "native signature",
        )
        evidence = native["evidence"]
        try:
            validate_apple_identity(
                native["team_identifier"], native["signing_identity"]
            )
        except ReleaseError as exc:
            raise ReleaseError(
                f"manifest Apple identity is invalid for {target['id']}: {exc}"
            ) from exc
        if (
            native["policy"] != configured["native_signature"]
            or native["status"] != "verified"
        ):
            raise ReleaseError(
                f"manifest native signature state is invalid for {target['id']}"
            )
        if not isinstance(evidence, dict):
            raise ReleaseError(
                f"manifest native evidence for {target['id']} must be an object"
            )
        require_exact_keys(
            evidence,
            {"filename", "sha256", "size", "signature_bundle"},
            "native evidence",
        )
        expected_evidence = f"native-{target['id']}.json"
        if (
            evidence["filename"] != expected_evidence
            or evidence["signature_bundle"] != f"{expected_evidence}.sigstore.json"
            or not HEX_SHA256.fullmatch(evidence["sha256"])
            or not isinstance(evidence["size"], int)
            or evidence["size"] <= 0
        ):
            raise ReleaseError(
                f"manifest native evidence metadata is invalid for {target['id']}"
            )
    elif native != {
        "policy": configured["native_signature"],
        "status": "not-performed-local-unsigned",
    }:
        raise ReleaseError(
            f"manifest local native signature state is invalid for {target['id']}"
        )
    validate_package_shapes(target, configured, config, release_mode)


def validate_package_file_evidence(
    entry: Any, expected_filename: str, context: str
) -> None:
    if not isinstance(entry, dict):
        raise ReleaseError(f"manifest {context} must be an object")
    require_exact_keys(
        entry, {"filename", "sha256", "size", "signature_bundle"}, context
    )
    if (
        entry["filename"] != expected_filename
        or entry["signature_bundle"] != f"{expected_filename}.sigstore.json"
        or not isinstance(entry["sha256"], str)
        or not HEX_SHA256.fullmatch(entry["sha256"])
        or not isinstance(entry["size"], int)
        or entry["size"] <= 0
    ):
        raise ReleaseError(f"manifest {context} metadata is invalid")


def validate_package_shapes(
    target: dict[str, Any],
    configured: dict[str, Any],
    config: dict[str, Any],
    release_mode: str,
) -> None:
    packages = target["packages"]
    if not isinstance(packages, list):
        raise ReleaseError(f"manifest packages for {target['id']} must be an array")
    if release_mode != "release":
        if packages:
            raise ReleaseError("local unsigned manifest cannot contain native packages")
        return
    expected_packages = configured["packages"]
    if [item.get("format") for item in packages if isinstance(item, dict)] != [
        item["format"] for item in expected_packages
    ] or len(packages) != len(expected_packages):
        raise ReleaseError(
            f"manifest packages do not match the admitted matrix for {target['id']}"
        )
    for package, expected in zip(packages, expected_packages, strict=True):
        if not isinstance(package, dict):
            raise ReleaseError(f"manifest package for {target['id']} must be an object")
        require_exact_keys(
            package,
            {"format", "artifact", "sbom", "provenance", "native_signature"},
            "package",
        )
        package_format = expected["format"]
        expected_artifact = package_name(config, configured, package_format)
        artifact = package["artifact"]
        if not isinstance(artifact, dict):
            raise ReleaseError("manifest package artifact must be an object")
        require_exact_keys(
            artifact,
            {
                "filename",
                "sha256",
                "size",
                "reproducible_candidate_sha256",
                "reproducible_candidate_size",
                "signature_bundle",
            },
            "package artifact",
        )
        if (
            artifact["filename"] != expected_artifact
            or artifact["signature_bundle"] != f"{expected_artifact}.sigstore.json"
            or not isinstance(artifact["sha256"], str)
            or not HEX_SHA256.fullmatch(artifact["sha256"])
            or not isinstance(artifact["size"], int)
            or artifact["size"] <= 0
            or not isinstance(artifact["reproducible_candidate_sha256"], str)
            or not HEX_SHA256.fullmatch(artifact["reproducible_candidate_sha256"])
            or not isinstance(artifact["reproducible_candidate_size"], int)
            or artifact["reproducible_candidate_size"] <= 0
        ):
            raise ReleaseError(
                f"manifest package artifact metadata is invalid for {target['id']}/{package_format}"
            )
        sbom = package["sbom"]
        expected_sbom = f"{expected_artifact}.spdx.json"
        if not isinstance(sbom, dict) or sbom.get("format") != "SPDX-2.3-json":
            raise ReleaseError("manifest package SBOM format is invalid")
        require_exact_keys(
            sbom,
            {"format", "filename", "sha256", "size", "signature_bundle"},
            "package SBOM",
        )
        validate_package_file_evidence(
            {
                key: sbom[key]
                for key in ("filename", "sha256", "size", "signature_bundle")
            },
            expected_sbom,
            "package SBOM",
        )
        provenance = package["provenance"]
        expected_provenance = f"{expected_artifact}.intoto.json"
        if (
            not isinstance(provenance, dict)
            or provenance.get("predicate_type") != SLSA_PREDICATE
            or provenance.get("attestation_bundle")
            != f"{expected_artifact}.intoto.sigstore.json"
        ):
            raise ReleaseError("manifest package provenance format is invalid")
        require_exact_keys(
            provenance,
            {
                "predicate_type",
                "filename",
                "sha256",
                "size",
                "signature_bundle",
                "attestation_bundle",
            },
            "package provenance",
        )
        validate_package_file_evidence(
            {
                key: provenance[key]
                for key in ("filename", "sha256", "size", "signature_bundle")
            },
            expected_provenance,
            "package provenance",
        )
        native = package["native_signature"]
        if not isinstance(native, dict):
            raise ReleaseError("manifest package native signature must be an object")
        policy = expected["native_signature"]
        if policy == "none":
            if native != {"policy": "none", "status": "not-required"}:
                raise ReleaseError("manifest Debian native signature state is invalid")
            if (
                artifact["sha256"] != artifact["reproducible_candidate_sha256"]
                or artifact["size"] != artifact["reproducible_candidate_size"]
            ):
                raise ReleaseError("manifest Debian package is not reproducible")
        elif policy == "rpm-openpgp":
            require_exact_keys(
                native,
                {"policy", "status", "fingerprint", "evidence", "public_key"},
                "RPM native signature",
            )
            validate_rpm_fingerprint(native["fingerprint"])
            if native["policy"] != policy or native["status"] != "verified":
                raise ReleaseError("manifest RPM native signature state is invalid")
            validate_package_file_evidence(
                native["evidence"],
                f"native-package-{target['id']}-rpm.json",
                "RPM native evidence",
            )
            validate_package_file_evidence(
                native["public_key"],
                f"rpm-signing-{target['id']}.asc",
                "RPM public key",
            )
        else:
            require_exact_keys(
                native,
                {
                    "policy",
                    "status",
                    "team_identifier",
                    "application_identity",
                    "installer_identity",
                    "evidence",
                },
                "macOS installer native signature",
            )
            validate_apple_identity(
                native["team_identifier"], native["application_identity"]
            )
            validate_apple_installer_identity(
                native["team_identifier"], native["installer_identity"]
            )
            if (
                native["policy"] != policy
                or native["status"] != "verified"
                or native["team_identifier"]
                != target["native_signature"].get("team_identifier")
                or native["application_identity"]
                != target["native_signature"].get("signing_identity")
            ):
                raise ReleaseError("manifest macOS installer trust state is invalid")
            validate_package_file_evidence(
                native["evidence"],
                f"native-package-{target['id']}-pkg.json",
                "macOS installer evidence",
            )


def validate_manifest_shape(manifest: dict[str, Any], config: dict[str, Any]) -> None:
    require_exact_keys(
        manifest,
        {
            "$schema",
            "format_version",
            "release_mode",
            "releasable",
            "product",
            "connector_version",
            "control_protocol_version",
            "codex_version",
            "appserver_schema_sha256",
            "server_api_release",
            "source",
            "build",
            "signing",
            "checksums_file",
            "local_unsigned_marker",
            "connector_release_metadata",
            "targets",
        },
        "manifest",
    )
    expected = {
        "format_version": 1,
        "product": config["product"],
        "connector_version": config["connector_version"],
        "control_protocol_version": config["control_protocol_version"],
        "codex_version": config["codex_version"],
        "appserver_schema_sha256": config["appserver_schema_sha256"],
        "server_api_release": config["server_api_release"],
        "checksums_file": CHECKSUMS,
    }
    for key, value in expected.items():
        if manifest.get(key) != value:
            raise ReleaseError(
                f"manifest {key} does not match the admitted release matrix"
            )
    if (
        manifest.get("$schema")
        != "https://sub2api-codex.invalid/schemas/connector-release-manifest-v1.json"
    ):
        raise ReleaseError("manifest schema identifier is invalid")
    require_exact_keys(
        manifest["source"],
        {"repository", "commit", "snapshot_sha256"},
        "manifest source",
    )
    if not HEX_SHA256.fullmatch(manifest["source"]["snapshot_sha256"]):
        raise ReleaseError("manifest source snapshot digest is invalid")
    require_exact_keys(
        manifest["build"],
        {
            "go_version",
            "source_date_epoch",
            "created_at",
            "builder_id",
            "invocation_id",
            "started_at",
            "finished_at",
            "reproducibility_passes",
        },
        "manifest build",
    )
    if (
        not isinstance(manifest["build"]["source_date_epoch"], int)
        or manifest["build"]["source_date_epoch"] < 0
        or manifest["build"]["reproducibility_passes"] != 2
        or manifest["build"]["created_at"] != manifest["build"]["finished_at"]
    ):
        raise ReleaseError("manifest build metadata is invalid")
    for field in ("created_at", "started_at", "finished_at"):
        try:
            dt.datetime.fromisoformat(manifest["build"][field].replace("Z", "+00:00"))
        except (TypeError, ValueError) as exc:
            raise ReleaseError(
                f"manifest build {field} is not an RFC 3339 timestamp"
            ) from exc
    require_exact_keys(
        manifest["signing"],
        {
            "cosign_version",
            "certificate_oidc_issuer",
            "certificate_identity",
            "certificate_github_workflow_sha",
            "certificate_github_workflow_trigger",
            "manifest_bundle",
            "checksums_bundle",
        },
        "manifest signing",
    )
    if (
        manifest["signing"]["cosign_version"] != config["cosign_version"]
        or manifest["signing"]["manifest_bundle"] != f"{MANIFEST}.sigstore.json"
        or manifest["signing"]["checksums_bundle"] != f"{CHECKSUMS}.sigstore.json"
    ):
        raise ReleaseError("manifest signing configuration is invalid")
    if not isinstance(manifest["targets"], list) or not manifest["targets"]:
        raise ReleaseError("manifest has no targets")
    if manifest["release_mode"] not in {"release", "local-unsigned"}:
        raise ReleaseError("manifest release mode is invalid")
    if manifest["release_mode"] == "release":
        release_metadata = manifest["connector_release_metadata"]
        if not isinstance(release_metadata, dict):
            raise ReleaseError("manifest Connector release metadata descriptor is invalid")
        require_exact_keys(
            release_metadata,
            {"filename", "signature_bundle"},
            "Connector release metadata descriptor",
        )
        if release_metadata != {
            "filename": CONNECTOR_RELEASE_METADATA,
            "signature_bundle": f"{CONNECTOR_RELEASE_METADATA}.sigstore.json",
        }:
            raise ReleaseError("manifest Connector release metadata descriptor is invalid")
    elif manifest["connector_release_metadata"] is not None:
        raise ReleaseError(
            "local unsigned manifest cannot advertise Connector release metadata"
        )
    if not all(isinstance(target, dict) for target in manifest["targets"]):
        raise ReleaseError("manifest targets must be objects")
    target_ids = [target.get("id") for target in manifest["targets"]]
    if len(set(target_ids)) != len(target_ids):
        raise ReleaseError("manifest contains duplicate targets")
    expected_subset = [
        target["id"] for target in config["targets"] if target["id"] in set(target_ids)
    ]
    if target_ids != expected_subset:
        raise ReleaseError(
            "manifest targets are not an ordered subset of the admitted matrix"
        )
    for target in manifest["targets"]:
        validate_target_shape(target, config, manifest["release_mode"])
    if manifest["release_mode"] == "release":
        expected_ids = [target["id"] for target in config["targets"]]
        if target_ids != expected_ids:
            raise ReleaseError(
                "release manifest does not contain the complete ordered target matrix"
            )
        if manifest["build"]["go_version"] != config["go_version"]:
            raise ReleaseError("release manifest does not use the pinned Go version")
        if not HEX_GIT_COMMIT.fullmatch(manifest["source"]["commit"]):
            raise ReleaseError(
                "release manifest source commit is not a full Git commit"
            )
        if not re.fullmatch(
            r"https://github\.com/[^/]+/[^/]+", manifest["source"]["repository"]
        ):
            raise ReleaseError(
                "release manifest source repository is not an exact GitHub repository URL"
            )
        expected_identity = (
            f"{manifest['source']['repository']}/{config['source_workflow']}"
            f"@refs/tags/connector-v{config['connector_version']}"
        )
        expected_invocation_pattern = rf"{re.escape(manifest['source']['repository'])}/actions/runs/[1-9][0-9]*/attempts/[1-9][0-9]*"
        if (
            manifest["releasable"] is not True
            or manifest["local_unsigned_marker"] is not None
            or manifest["build"]["builder_id"] != expected_identity
            or not re.fullmatch(
                expected_invocation_pattern, manifest["build"]["invocation_id"]
            )
            or manifest["signing"]["certificate_oidc_issuer"] != OIDC_ISSUER
            or manifest["signing"]["certificate_identity"] != expected_identity
            or manifest["signing"]["certificate_github_workflow_sha"]
            != manifest["source"]["commit"]
            or manifest["signing"]["certificate_github_workflow_trigger"] != "push"
        ):
            raise ReleaseError("release manifest trust metadata is invalid")
    elif (
        manifest["releasable"] is not False
        or manifest["local_unsigned_marker"] != LOCAL_MARKER
        or manifest["signing"]["certificate_oidc_issuer"] is not None
        or manifest["signing"]["certificate_identity"] is not None
        or manifest["signing"]["certificate_github_workflow_sha"] is not None
        or manifest["signing"]["certificate_github_workflow_trigger"] is not None
    ):
        raise ReleaseError("local unsigned manifest trust metadata is invalid")


def validate_manifest_release_context(
    manifest: dict[str, Any], config: dict[str, Any]
) -> None:
    expected_tag = f"connector-v{config['connector_version']}"
    expected_ref = f"refs/tags/{expected_tag}"
    expected_repo = os.environ.get("GITHUB_REPOSITORY", "")
    expected_identity = (
        f"https://github.com/{expected_repo}/{config['source_workflow']}@{expected_ref}"
    )
    expected_invocation = (
        f"https://github.com/{expected_repo}/actions/runs/{os.environ.get('GITHUB_RUN_ID', '')}/attempts/"
        f"{os.environ.get('GITHUB_RUN_ATTEMPT', '')}"
    )
    if (
        os.environ.get("GITHUB_ACTIONS") != "true"
        or os.environ.get("GITHUB_REF_TYPE") != "tag"
        or os.environ.get("GITHUB_REF_NAME") != expected_tag
        or os.environ.get("GITHUB_REF") != expected_ref
        or manifest["source"]["repository"] != f"https://github.com/{expected_repo}"
        or manifest["source"]["commit"] != os.environ.get("GITHUB_SHA")
        or manifest["build"]["builder_id"] != expected_identity
        or manifest["build"]["invocation_id"] != expected_invocation
        or manifest["signing"]["certificate_identity"] != expected_identity
        or manifest["signing"]["certificate_github_workflow_sha"]
        != os.environ.get("GITHUB_SHA")
        or manifest["signing"]["certificate_github_workflow_trigger"] != "push"
    ):
        raise ReleaseError(
            "finalized release does not match the protected GitHub tag context"
        )
    if (
        run(["git", "rev-parse", "HEAD"], cwd=REPO_ROOT, capture=True)
        != manifest["source"]["commit"]
    ):
        raise ReleaseError("checked-out HEAD does not match finalized release source")
    require_annotated_tag(expected_tag, manifest["source"]["commit"])
    if run(
        ["git", "status", "--porcelain", "--untracked-files=no"],
        cwd=REPO_ROOT,
        capture=True,
    ):
        raise ReleaseError("tracked source changed in the signing job")
    if source_snapshot_sha256() != manifest["source"]["snapshot_sha256"]:
        raise ReleaseError(
            "checked-out source does not match finalized release snapshot"
        )


def verify_hash_entry(
    output: Path, entry: dict[str, Any], context: str, *, executable: bool = False
) -> Path:
    require_exact_keys(
        entry, {"filename", "sha256", "size", "signature_bundle"}, context
    )
    if not HEX_SHA256.fullmatch(entry["sha256"]):
        raise ReleaseError(f"{context} has an invalid SHA-256")
    path = safe_file(output, entry["filename"], context, executable=executable)
    if path.stat().st_size != entry["size"] or sha256_file(path) != entry["sha256"]:
        raise ReleaseError(f"{context} size or SHA-256 mismatch: {path.name}")
    return path


def verify_package_sbom(
    path: Path,
    package_path: Path,
    package: dict[str, Any],
    target: dict[str, Any],
    manifest: dict[str, Any],
) -> None:
    sbom = read_json(path)
    packages = sbom.get("packages") if isinstance(sbom, dict) else None
    files = sbom.get("files") if isinstance(sbom, dict) else None
    if (
        sbom.get("spdxVersion") != "SPDX-2.3"
        or sbom.get("dataLicense") != "CC0-1.0"
        or not isinstance(packages, list)
        or not packages
        or not isinstance(files, list)
        or len(files) != 1
    ):
        raise ReleaseError(f"package SBOM is not SPDX 2.3 JSON: {path.name}")
    artifact = package["artifact"]
    sha1 = sha1_file(package_path)
    checksums = [
        {"algorithm": "SHA1", "checksumValue": sha1},
        {"algorithm": "SHA256", "checksumValue": artifact["sha256"]},
    ]
    expected_purl = (
        f"pkg:generic/{manifest['product']}@{manifest['connector_version']}"
        f"?os={target['os']}&arch={target['arch']}&type={package['format']}"
    )
    described = packages[0]
    package_file = files[0]
    external_refs = described.get("externalRefs")
    connector_sbom_path = safe_file(
        path.parent, target["sbom"]["filename"], "Connector SBOM"
    )
    connector_sbom = read_json(connector_sbom_path)
    if not isinstance(connector_sbom, dict):
        raise ReleaseError(f"Connector SBOM dependency closure is invalid: {path.name}")
    connector_packages = connector_sbom.get("packages")
    connector_relationships = connector_sbom.get("relationships")
    if not isinstance(connector_packages, list) or not isinstance(
        connector_relationships, list
    ):
        raise ReleaseError(f"Connector SBOM dependency closure is invalid: {path.name}")
    dependency_ids = [
        relationship.get("relatedSpdxElement")
        for relationship in connector_relationships
        if isinstance(relationship, dict)
        and relationship.get("spdxElementId") == "SPDXRef-Package-Connector"
        and relationship.get("relationshipType") == "DEPENDS_ON"
    ]
    dependency_by_id = {
        item.get("SPDXID"): item
        for item in connector_packages
        if isinstance(item, dict) and isinstance(item.get("SPDXID"), str)
    }
    if len(dependency_ids) != len(set(dependency_ids)) or any(
        dependency_id not in dependency_by_id for dependency_id in dependency_ids
    ):
        raise ReleaseError(f"Connector SBOM dependency closure is invalid: {path.name}")
    expected_dependency_packages = [
        dependency_by_id[dependency_id] for dependency_id in dependency_ids
    ]
    expected_stdlib = go_stdlib_spdx_package(manifest["build"]["go_version"])
    if (
        dependency_ids.count(GO_STDLIB_SPDX_ID) != 1
        or dependency_by_id.get(GO_STDLIB_SPDX_ID) != expected_stdlib
    ):
        raise ReleaseError(f"Connector SBOM Go standard library is invalid: {path.name}")
    connector_component = connector_component_spdx_package(
        manifest["product"], manifest["connector_version"]
    )
    contained_packages = [connector_component, *expected_dependency_packages]
    expected_relationships = [
        {
            "spdxElementId": "SPDXRef-DOCUMENT",
            "relationshipType": "DESCRIBES",
            "relatedSpdxElement": "SPDXRef-Package-ConnectorInstaller",
        },
        {
            "spdxElementId": "SPDXRef-Package-ConnectorInstaller",
            "relationshipType": "CONTAINS",
            "relatedSpdxElement": "SPDXRef-File-ConnectorInstaller",
        },
        *[
            {
                "spdxElementId": "SPDXRef-Package-ConnectorInstaller",
                "relationshipType": "CONTAINS",
                "relatedSpdxElement": contained["SPDXID"],
            }
            for contained in contained_packages
        ],
        *[
            {
                "spdxElementId": "SPDXRef-Package-Connector",
                "relationshipType": "DEPENDS_ON",
                "relatedSpdxElement": dependency_id,
            }
            for dependency_id in dependency_ids
        ],
    ]
    if (
        described.get("SPDXID") != "SPDXRef-Package-ConnectorInstaller"
        or described.get("name") != manifest["product"]
        or described.get("versionInfo") != manifest["connector_version"]
        or described.get("filesAnalyzed") is not True
        or described.get("checksums") != checksums
        or described.get("packageVerificationCode")
        != {"packageVerificationCodeValue": hashlib.sha1(sha1.encode("ascii")).hexdigest()}
        or described.get("licenseInfoFromFiles") != ["NOASSERTION"]
        or described.get("licenseConcluded") != "NOASSERTION"
        or described.get("licenseDeclared") != "NOASSERTION"
        or described.get("copyrightText") != "NOASSERTION"
        or external_refs
        != [
            {
                "referenceCategory": "PACKAGE-MANAGER",
                "referenceType": "purl",
                "referenceLocator": expected_purl,
            }
        ]
        or package_file.get("SPDXID") != "SPDXRef-File-ConnectorInstaller"
        or package_file.get("fileName") != artifact["filename"]
        or package_file.get("checksums") != checksums
        or package_file.get("licenseConcluded") != "NOASSERTION"
        or package_file.get("licenseInfoInFiles") != ["NOASSERTION"]
        or package_file.get("copyrightText") != "NOASSERTION"
        or packages[1:] != contained_packages
        or sbom.get("relationships") != expected_relationships
    ):
        raise ReleaseError(f"package SBOM subject does not match artifact: {path.name}")


def verify_package_provenance(
    path: Path,
    package: dict[str, Any],
    target: dict[str, Any],
    manifest: dict[str, Any],
    trusted_identity: str | None,
) -> None:
    statement = read_json(path)
    artifact = package["artifact"]
    if (
        not isinstance(statement, dict)
        or statement.get("_type") != IN_TOTO_STATEMENT
        or statement.get("predicateType") != SLSA_PREDICATE
        or statement.get("subject")
        != [{"name": artifact["filename"], "digest": {"sha256": artifact["sha256"]}}]
    ):
        raise ReleaseError(f"package provenance subject mismatch: {path.name}")
    predicate = statement.get("predicate")
    if not isinstance(predicate, dict):
        raise ReleaseError(f"package provenance predicate is invalid: {path.name}")
    definition = predicate.get("buildDefinition")
    details = predicate.get("runDetails")
    if not isinstance(definition, dict) or not isinstance(details, dict):
        raise ReleaseError(f"package provenance structure is invalid: {path.name}")
    expected_external = {
        "sourceRepository": manifest["source"]["repository"],
        "sourceCommit": manifest["source"]["commit"],
        "connectorVersion": manifest["connector_version"],
        "target": target["id"],
        "packageFormat": package["format"],
        "nativeSignaturePolicy": package["native_signature"]["policy"],
    }
    expected_internal = {
        "reproducibilityPasses": 2,
        "packageContentVerified": True,
        "licenseInventoryVerified": True,
        "serviceDefinitionIncluded": True,
        "configurationExampleIncluded": True,
    }
    source_digest = (
        {"gitCommit": manifest["source"]["commit"]}
        if HEX_GIT_COMMIT.fullmatch(manifest["source"]["commit"])
        else {"sha256": manifest["source"]["snapshot_sha256"]}
    )
    expected_dependencies = [
        {"uri": manifest["source"]["repository"], "digest": source_digest},
        {
            "uri": f"pkg:generic/{manifest['product']}@{manifest['connector_version']}",
            "digest": {"sha256": target["artifact"]["sha256"]},
        },
    ]
    if (
        definition.get("buildType")
        != "https://sub2api-codex.invalid/buildtypes/connector-native-package/v2"
        or definition.get("externalParameters") != expected_external
        or definition.get("internalParameters") != expected_internal
        or definition.get("resolvedDependencies") != expected_dependencies
    ):
        raise ReleaseError(f"package provenance build definition mismatch: {path.name}")
    builder = details.get("builder")
    metadata = details.get("metadata")
    byproducts = details.get("byproducts")
    expected_builder = {"id": manifest["build"]["builder_id"]}
    expected_metadata = {
        "invocationId": f"{manifest['build']['invocation_id']}#{target['id']}-{package['format']}",
        "startedOn": manifest["build"]["started_at"],
        "finishedOn": manifest["build"]["finished_at"],
    }
    expected_byproducts = [
        {
            "name": f"{artifact['filename']}.unsigned-candidate",
            "digest": {"sha256": artifact["reproducible_candidate_sha256"]},
            "annotations": {
                "passes": 2,
                "matched": True,
                "candidateSize": artifact["reproducible_candidate_size"],
            },
        }
    ]
    if (
        builder != expected_builder
        or (trusted_identity is not None and builder != {"id": trusted_identity})
        or metadata != expected_metadata
        or byproducts != expected_byproducts
    ):
        raise ReleaseError(f"package provenance run details mismatch: {path.name}")


def validate_package_native_files(
    output: Path,
    target: dict[str, Any],
    package: dict[str, Any],
    *,
    expected_apple_team_id: str | None,
    expected_apple_application_identity: str | None,
    expected_apple_installer_identity: str | None,
    expected_rpm_fingerprint: str | None,
) -> tuple[Path | None, Path | None]:
    native = package["native_signature"]
    artifact = package["artifact"]
    if native["policy"] == "none":
        return None, None
    evidence_entry = native["evidence"]
    evidence_path = verify_hash_entry(output, evidence_entry, "package native evidence")
    evidence = read_json(evidence_path)
    if native["policy"] == "rpm-openpgp":
        if not expected_rpm_fingerprint:
            raise ReleaseError("RPM verification lacks an external signing fingerprint")
        public_key_entry = native["public_key"]
        public_key_path = verify_hash_entry(output, public_key_entry, "RPM public key")
        if native["fingerprint"] != expected_rpm_fingerprint:
            raise ReleaseError(f"RPM trust policy mismatch for {target['id']}")
        validate_rpm_package_evidence(
            evidence,
            target_id=target["id"],
            package_name_value=artifact["filename"],
            package_sha256=artifact["sha256"],
            expected_fingerprint=expected_rpm_fingerprint,
            public_key_name=public_key_entry["filename"],
            public_key_sha256=public_key_entry["sha256"],
        )
        return evidence_path, public_key_path
    if (
        not expected_apple_team_id
        or not expected_apple_application_identity
        or not expected_apple_installer_identity
    ):
        raise ReleaseError("macOS installer verification lacks external Apple trust policy")
    if (
        native["team_identifier"] != expected_apple_team_id
        or native["application_identity"] != expected_apple_application_identity
        or native["installer_identity"] != expected_apple_installer_identity
    ):
        raise ReleaseError(f"macOS installer trust policy mismatch for {target['id']}")
    validate_pkg_package_evidence(
        evidence,
        target_id=target["id"],
        package_name_value=artifact["filename"],
        package_sha256=artifact["sha256"],
        expected_team_id=expected_apple_team_id,
        expected_application_identity=expected_apple_application_identity,
        expected_installer_identity=expected_apple_installer_identity,
    )
    return evidence_path, None


def verify_package_embeds_connector(
    package_path: Path,
    package_format: str,
    target_arch: str,
    connector_artifact_path: Path,
) -> None:
    if package_format == "rpm":
        digest_algorithm = run(
            ["rpm", "-qp", "--qf", "%{FILEDIGESTALGO}", str(package_path)],
            capture=True,
        )
        listing = run(
            [
                "rpm",
                "-qp",
                "--qf",
                "[%{FILENAMES}\\t%{FILEDIGESTS}\\n]",
                str(package_path),
            ],
            capture=True,
        )
        embedded_digests = [
            line.split("\t", 1)[1]
            for line in listing.splitlines()
            if line.startswith("/usr/bin/sub2api-codex-connector\t")
            and "\t" in line
        ]
        if (
            digest_algorithm != "8"
            or embedded_digests != [sha256_file(connector_artifact_path)]
        ):
            raise ReleaseError(
                f"RPM package embeds a different Connector binary for {target_arch}"
            )
        return

    with tempfile.TemporaryDirectory(
        prefix=f"connector-package-binary-{package_format}-{target_arch}."
    ) as directory:
        temporary = Path(directory)
        if package_format == "deb":
            root = temporary / "root"
            root.mkdir(mode=0o700)
            run(["dpkg-deb", "-x", str(package_path), str(root)])
            embedded = safe_file(
                root / "usr/bin", "sub2api-codex-connector", "embedded Connector"
            )
        elif package_format == "pkg":
            if platform.system() != "Darwin":
                raise ReleaseError("macOS package payload inspection must run on macOS")
            expanded = temporary / "expanded"
            run(["pkgutil", "--expand-full", str(package_path), str(expanded)])
            payloads = sorted(
                path
                for path in expanded.rglob("Payload")
                if path.is_dir() and not path.is_symlink()
            )
            if len(payloads) != 1:
                raise ReleaseError("macOS package has an ambiguous payload inventory")
            embedded = safe_file(
                payloads[0] / "usr/local/bin",
                "sub2api-codex-connector",
                "embedded Connector",
            )
        else:
            raise ReleaseError(f"unsupported native package format {package_format!r}")
        if (
            embedded.stat().st_size != connector_artifact_path.stat().st_size
            or sha256_file(embedded) != sha256_file(connector_artifact_path)
        ):
            raise ReleaseError(
                f"{package_format} package embeds a different Connector binary for {target_arch}"
            )


def verify_package_platform_trust(
    package_path: Path,
    package: dict[str, Any],
    target: dict[str, Any],
    connector_artifact_path: Path,
    public_key_path: Path | None,
    version: str,
    *,
    expected_installer_identity: str | None,
    expected_rpm_fingerprint: str | None,
) -> None:
    run(
        [
            "sh",
            str(PACKAGE_CONTENT_VERIFIER),
            str(package_path),
            package["format"],
            target["arch"],
            version,
        ],
        cwd=REPO_ROOT,
    )
    verify_package_embeds_connector(
        package_path,
        package["format"],
        target["arch"],
        connector_artifact_path,
    )
    if package["format"] == "rpm":
        if public_key_path is None or not expected_rpm_fingerprint:
            raise ReleaseError("RPM verification lacks public-key trust material")
        verify_rpm_signature(
            package_path, public_key_path, expected_rpm_fingerprint
        )
    elif package["format"] == "pkg":
        if platform.system() != "Darwin" or not expected_installer_identity:
            raise ReleaseError("macOS installer verification must run on macOS")
        installer_report = run_combined(
            ["pkgutil", "--check-signature", str(package_path)]
        )
        primary_identities = [
            match.group(1)
            for line in installer_report.splitlines()
            for match in [re.fullmatch(r"\s*1\.\s+(.+)", line)]
            if match is not None
        ]
        if primary_identities != [expected_installer_identity]:
            raise ReleaseError("macOS installer signature identity mismatch")
        stapler_report = run_combined(
            ["xcrun", "stapler", "validate", "-v", str(package_path)]
        )
        if not any(
            "validated" in line.lower() or "worked" in line.lower()
            for line in stapler_report.splitlines()
        ):
            raise ReleaseError("macOS installer lacks a valid notarization ticket")
        gatekeeper_report = run_combined(
            ["spctl", "--assess", "--type", "install", "--verbose=4", str(package_path)]
        )
        if not any(
            "accepted" in line.lower()
            or "source=notarized developer id" in line.lower()
            for line in gatekeeper_report.splitlines()
        ):
            raise ReleaseError("macOS installer is not accepted by Gatekeeper")


def verify_sbom(
    path: Path, artifact_path: Path, artifact: dict[str, Any], manifest: dict[str, Any]
) -> None:
    sbom = read_json(path)
    if sbom.get("spdxVersion") != "SPDX-2.3" or sbom.get("dataLicense") != "CC0-1.0":
        raise ReleaseError(f"SBOM is not SPDX 2.3 JSON: {path.name}")
    packages = sbom.get("packages")
    files = sbom.get("files")
    relationships = sbom.get("relationships")
    if (
        not isinstance(packages, list)
        or not isinstance(files, list)
        or not isinstance(relationships, list)
    ):
        raise ReleaseError(f"SBOM lacks packages or files: {path.name}")
    connector = next(
        (
            item
            for item in packages
            if item.get("SPDXID") == "SPDXRef-Package-Connector"
        ),
        None,
    )
    binary = next(
        (item for item in files if item.get("fileName") == artifact["filename"]), None
    )
    file_sha1 = sha1_file(artifact_path)
    expected_checksums = [
        {"algorithm": "SHA1", "checksumValue": file_sha1},
        {"algorithm": "SHA256", "checksumValue": artifact["sha256"]},
    ]
    expected_verification_code = hashlib.sha1(file_sha1.encode("ascii")).hexdigest()
    expected_stdlib = go_stdlib_spdx_package(manifest["build"]["go_version"])
    stdlib_packages = [
        item
        for item in packages
        if isinstance(item, dict) and item.get("SPDXID") == GO_STDLIB_SPDX_ID
    ]
    stdlib_relationship = {
        "spdxElementId": "SPDXRef-Package-Connector",
        "relationshipType": "DEPENDS_ON",
        "relatedSpdxElement": GO_STDLIB_SPDX_ID,
    }
    if (
        connector is None
        or connector.get("name") != manifest["product"]
        or connector.get("versionInfo") != manifest["connector_version"]
        or connector.get("filesAnalyzed") is not True
        or connector.get("checksums") != expected_checksums
        or connector.get("packageVerificationCode")
        != {"packageVerificationCodeValue": expected_verification_code}
        or connector.get("licenseInfoFromFiles") != ["NOASSERTION"]
        or connector.get("licenseConcluded") != "NOASSERTION"
        or connector.get("licenseDeclared") != "NOASSERTION"
        or binary is None
        or binary.get("checksums") != expected_checksums
        or binary.get("licenseConcluded") != "NOASSERTION"
        or binary.get("licenseInfoInFiles") != ["NOASSERTION"]
        or stdlib_packages != [expected_stdlib]
        or relationships.count(stdlib_relationship) != 1
    ):
        raise ReleaseError(f"SBOM subject does not match artifact: {path.name}")


def verify_provenance(
    path: Path,
    artifact: dict[str, Any],
    target: dict[str, Any],
    manifest: dict[str, Any],
    trusted_identity: str | None,
) -> None:
    statement = read_json(path)
    if (
        statement.get("_type") != IN_TOTO_STATEMENT
        or statement.get("predicateType") != SLSA_PREDICATE
    ):
        raise ReleaseError(
            f"provenance is not an in-toto v1 SLSA v1 statement: {path.name}"
        )
    if statement.get("subject") != [
        {"name": artifact["filename"], "digest": {"sha256": artifact["sha256"]}}
    ]:
        raise ReleaseError(f"provenance subject mismatch: {path.name}")
    predicate = statement.get("predicate", {})
    definition = predicate.get("buildDefinition", {})
    details = predicate.get("runDetails", {})
    external = definition.get("externalParameters", {})
    expected_external = {
        "sourceRepository": manifest["source"]["repository"],
        "sourceCommit": manifest["source"]["commit"],
        "connectorVersion": manifest["connector_version"],
        "controlProtocolVersion": manifest["control_protocol_version"],
        "codexVersion": manifest["codex_version"],
        "appserverSchemaSha256": manifest["appserver_schema_sha256"],
        "serverApiRelease": manifest["server_api_release"],
        "target": {
            "id": target["id"],
            "goos": target["os"],
            "goarch": target["arch"],
            "native_signature": target["native_signature"]["policy"],
        },
    }
    if HEX_GIT_COMMIT.fullmatch(manifest["source"]["commit"]) and manifest["source"][
        "repository"
    ].startswith("https://github.com/"):
        expected_build_type = (
            f"{manifest['source']['repository']}/blob/{manifest['source']['commit']}"
            "/connector/release/README.md#release-flow"
        )
    else:
        expected_build_type = (
            "https://sub2api-codex.invalid/buildtypes/connector-release/v1"
        )
    if definition.get("buildType") != expected_build_type:
        raise ReleaseError(f"provenance build type mismatch: {path.name}")
    if external != expected_external:
        raise ReleaseError(f"provenance external parameters mismatch: {path.name}")
    resolved_dependencies = definition.get("resolvedDependencies")
    if not isinstance(resolved_dependencies, list) or len(resolved_dependencies) < 2:
        raise ReleaseError(f"provenance has no resolved dependencies: {path.name}")
    source_digest_key = (
        "gitCommit"
        if HEX_GIT_COMMIT.fullmatch(manifest["source"]["commit"])
        else "sha256"
    )
    source_digest_value = (
        manifest["source"]["commit"]
        if source_digest_key == "gitCommit"
        else manifest["source"]["snapshot_sha256"]
    )
    if not any(
        dependency.get("uri") == manifest["source"]["repository"]
        and dependency.get("digest") == {source_digest_key: source_digest_value}
        for dependency in resolved_dependencies
    ):
        raise ReleaseError(
            f"provenance lacks the resolved source dependency: {path.name}"
        )
    expected_toolchain = {
        "uri": f"pkg:golang/toolchain@{manifest['build']['go_version'].removeprefix('go')}"
    }
    if expected_toolchain not in resolved_dependencies:
        raise ReleaseError(f"provenance lacks the resolved Go toolchain: {path.name}")
    seen_dependency_uris: set[str] = set()
    for dependency in resolved_dependencies:
        if not isinstance(dependency, dict) or not isinstance(
            dependency.get("uri"), str
        ):
            raise ReleaseError(
                f"provenance has an invalid resolved dependency: {path.name}"
            )
        uri = dependency["uri"]
        if uri in seen_dependency_uris:
            raise ReleaseError(
                f"provenance has duplicate resolved dependencies: {path.name}"
            )
        seen_dependency_uris.add(uri)
        if uri in {manifest["source"]["repository"], expected_toolchain["uri"]}:
            continue
        if not uri.startswith("pkg:golang/"):
            raise ReleaseError(
                f"provenance has an unexpected resolved dependency: {path.name}"
            )
        digest = dependency.get("digest")
        if digest is not None and (
            not isinstance(digest, dict)
            or set(digest) != {"dirHash1"}
            or not isinstance(digest["dirHash1"], str)
            or not HEX_SHA256.fullmatch(digest["dirHash1"])
        ):
            raise ReleaseError(
                f"provenance has an invalid Go dirHash1 digest: {path.name}"
            )
    internal = definition.get("internalParameters", {})
    if (
        internal.get("cgoEnabled") is not False
        or internal.get("goAmd64") != PINNED_GO_ENV["GOAMD64"]
        or internal.get("goArm64") != PINNED_GO_ENV["GOARM64"]
        or internal.get("goEnv") != PINNED_GO_ENV["GOENV"]
        or internal.get("goExperiment") != PINNED_GO_ENV["GOEXPERIMENT"]
        or internal.get("goFips140") != PINNED_GO_ENV["GOFIPS140"]
        or internal.get("goToolchain") != PINNED_GO_ENV["GOTOOLCHAIN"]
        or internal.get("trimpath") is not True
        or internal.get("buildVcs") is not False
        or internal.get("goBuildId") != ""
        or set(internal)
        != {
            "cgoEnabled",
            "goAmd64",
            "goArm64",
            "goEnv",
            "goExperiment",
            "goFips140",
            "goToolchain",
            "trimpath",
            "buildVcs",
            "goBuildId",
        }
    ):
        raise ReleaseError(
            f"provenance reproducible build parameters mismatch: {path.name}"
        )
    builder = details.get("builder", {}).get("id")
    if builder != manifest["build"]["builder_id"] or (
        trusted_identity is not None and builder != trusted_identity
    ):
        raise ReleaseError(f"provenance builder identity mismatch: {path.name}")
    expected_metadata = {
        "invocationId": f"{manifest['build']['invocation_id']}#{target['id']}",
        "startedOn": manifest["build"]["started_at"],
        "finishedOn": manifest["build"]["finished_at"],
    }
    if details.get("metadata") != expected_metadata:
        raise ReleaseError(f"provenance invocation metadata mismatch: {path.name}")
    expected_byproduct = {
        "name": artifact["filename"],
        "digest": {"sha256": artifact["reproducible_candidate_sha256"]},
        "annotations": {
            "check": "two-pass-byte-for-byte",
            "passes": 2,
            "matched": True,
            "unsignedSize": artifact["reproducible_candidate_size"],
        },
    }
    byproducts = details.get("byproducts")
    if byproducts != [expected_byproduct]:
        raise ReleaseError(
            f"provenance reproducibility byproduct mismatch: {path.name}"
        )


def parse_checksums(path: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    for number, line in enumerate(
        path.read_text(encoding="ascii").splitlines(), start=1
    ):
        match = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9][A-Za-z0-9._-]*)", line)
        if not match or match.group(2) in result:
            raise ReleaseError(
                f"invalid or duplicate SHA256SUMS entry on line {number}"
            )
        result[match.group(2)] = match.group(1)
    return result


def validate_finalized_release_for_signing(
    output: Path,
    manifest: dict[str, Any],
    expected_apple_team_id: str,
    expected_apple_application_identity: str,
    expected_apple_installer_identity: str,
    expected_rpm_fingerprint: str,
) -> None:
    checksums_path = safe_file(output, CHECKSUMS, "checksums")
    expected_names = expected_content_files(manifest)
    checksum_map = parse_checksums(checksums_path)
    if sorted(checksum_map) != expected_names:
        raise ReleaseError("SHA256SUMS does not exactly cover finalized release files")
    for name in expected_names:
        path = safe_file(output, name, "finalized release file")
        if sha256_file(path) != checksum_map[name]:
            raise ReleaseError(f"SHA256SUMS mismatch: {name}")
    metadata_entry = manifest["connector_release_metadata"]
    metadata_path = safe_file(
        output,
        metadata_entry["filename"],
        "Connector self-service release metadata",
    )
    validate_connector_release_metadata(
        read_canonical_json(metadata_path, "Connector self-service release metadata"),
        manifest,
        safe_file(output, MANIFEST, "manifest"),
    )
    for target in manifest["targets"]:
        artifact = target["artifact"]
        artifact_path = safe_file(
            output, artifact["filename"], "artifact", executable=True
        )
        if (
            artifact_path.stat().st_size != artifact["size"]
            or sha256_file(artifact_path) != artifact["sha256"]
        ):
            raise ReleaseError(
                f"artifact size or SHA-256 mismatch: {artifact_path.name}"
            )
        if target["native_signature"]["policy"] == "none" and (
            artifact["sha256"] != artifact["reproducible_candidate_sha256"]
            or artifact["size"] != artifact["reproducible_candidate_size"]
        ):
            raise ReleaseError(
                f"unsigned artifact differs from its reproducible candidate: {target['id']}"
            )
        sbom = target["sbom"]
        sbom_path = verify_hash_entry(
            output,
            {
                key: sbom[key]
                for key in ("filename", "sha256", "size", "signature_bundle")
            },
            "SBOM",
        )
        provenance = target["provenance"]
        provenance_path = verify_hash_entry(
            output,
            {
                key: provenance[key]
                for key in ("filename", "sha256", "size", "signature_bundle")
            },
            "provenance",
        )
        verify_sbom(sbom_path, artifact_path, artifact, manifest)
        verify_provenance(
            provenance_path, artifact, target, manifest, manifest["build"]["builder_id"]
        )
        native = target["native_signature"]
        if native["policy"] == "apple-developer-id-and-notarization":
            if (
                native["team_identifier"] != expected_apple_team_id
                or native["signing_identity"]
                != expected_apple_application_identity
            ):
                raise ReleaseError(f"Apple trust policy mismatch for {target['id']}")
            evidence_entry = native["evidence"]
            evidence_path = verify_hash_entry(output, evidence_entry, "native evidence")
            evidence = read_json(evidence_path)
            validate_native_evidence(
                evidence,
                target_id=target["id"],
                artifact_name_value=artifact["filename"],
                artifact_sha256=artifact["sha256"],
                expected_team_id=expected_apple_team_id,
                expected_signing_identity=expected_apple_application_identity,
            )
            if platform.system() != "Darwin":
                raise ReleaseError(
                    "release signing must validate Darwin artifacts on macOS"
                )
            verify_codesign_identity(
                artifact_path,
                expected_apple_team_id,
                expected_apple_application_identity,
            )
        for package in target["packages"]:
            package_artifact = package["artifact"]
            package_path = verify_hash_entry(
                output,
                {
                    key: package_artifact[key]
                    for key in ("filename", "sha256", "size", "signature_bundle")
                },
                "native package",
            )
            package_sbom = package["sbom"]
            package_sbom_path = verify_hash_entry(
                output,
                {
                    key: package_sbom[key]
                    for key in ("filename", "sha256", "size", "signature_bundle")
                },
                "package SBOM",
            )
            package_provenance = package["provenance"]
            package_provenance_path = verify_hash_entry(
                output,
                {
                    key: package_provenance[key]
                    for key in ("filename", "sha256", "size", "signature_bundle")
                },
                "package provenance",
            )
            if package["native_signature"]["policy"] == "none" and (
                package_artifact["sha256"]
                != package_artifact["reproducible_candidate_sha256"]
                or package_artifact["size"]
                != package_artifact["reproducible_candidate_size"]
            ):
                raise ReleaseError(
                    f"unsigned package differs from its reproducible candidate: {package_path.name}"
                )
            verify_package_sbom(
                package_sbom_path, package_path, package, target, manifest
            )
            verify_package_provenance(
                package_provenance_path,
                package,
                target,
                manifest,
                manifest["build"]["builder_id"],
            )
            validate_package_native_files(
                output,
                target,
                package,
                expected_apple_team_id=expected_apple_team_id,
                expected_apple_application_identity=expected_apple_application_identity,
                expected_apple_installer_identity=expected_apple_installer_identity,
                expected_rpm_fingerprint=expected_rpm_fingerprint,
            )
    allowed = set(expected_names) | {CHECKSUMS}
    entries = list(output.iterdir())
    for path in entries:
        mode = path.lstat().st_mode
        if not stat.S_ISREG(mode) or path.is_symlink():
            raise ReleaseError(
                f"release directory entry is not a regular non-symlink file: {path.name}"
            )
    actual = {path.name for path in entries}
    if actual != allowed:
        raise ReleaseError(
            f"finalized release has missing or unlisted entries: {sorted(actual ^ allowed)}"
        )


def verify(args: argparse.Namespace) -> None:
    output = release_output_directory(args.output)
    config = load_config(args.config)
    marker_exists = (output / LOCAL_MARKER).exists()
    if marker_exists and not args.allow_local_unsigned:
        raise ReleaseError(
            "local unsigned output is non-releasable; pass --allow-local-unsigned only for deterministic tests"
        )
    release_mode = not marker_exists
    if release_mode:
        requested_requires_apple = not args.targets or any(
            target.startswith("darwin-") for target in args.targets
        )
        requested_requires_rpm = not args.targets or any(
            target.startswith("linux-") for target in args.targets
        )
        if (
            not args.certificate_oidc_issuer
            or not args.certificate_identity
            or not args.certificate_github_workflow_sha
            or not args.certificate_github_workflow_trigger
            or (requested_requires_apple and not args.apple_team_id)
            or (requested_requires_apple and not args.apple_signing_identity)
            or (requested_requires_apple and not args.apple_installer_identity)
            or (requested_requires_rpm and not args.rpm_signing_fingerprint)
        ):
            raise ReleaseError(
                "release verification lacks required external trust policy"
            )
        if args.certificate_oidc_issuer != OIDC_ISSUER:
            raise ReleaseError(
                f"unexpected OIDC issuer; this release admits only {OIDC_ISSUER}"
            )
        if not HEX_GIT_COMMIT.fullmatch(args.certificate_github_workflow_sha):
            raise ReleaseError(
                "expected GitHub workflow SHA must be a full lowercase commit"
            )
        if args.certificate_github_workflow_trigger != "push":
            raise ReleaseError("expected GitHub workflow trigger must be push")
        if requested_requires_apple:
            validate_apple_identity(args.apple_team_id, args.apple_signing_identity)
            validate_apple_installer_identity(
                args.apple_team_id, args.apple_installer_identity
            )
        if requested_requires_rpm:
            validate_rpm_fingerprint(args.rpm_signing_fingerprint)
        require_cosign_version(args.cosign, config)
        verify_blob(
            args.cosign,
            output,
            MANIFEST,
            f"{MANIFEST}.sigstore.json",
            args.certificate_oidc_issuer,
            args.certificate_identity,
            args.certificate_github_workflow_sha,
            args.certificate_github_workflow_trigger,
        )
    manifest_path = safe_file(output, MANIFEST, "manifest")
    manifest = read_canonical_json(manifest_path, "release manifest")
    validate_manifest_shape(manifest, config)
    if release_mode:
        if (
            manifest["release_mode"] != "release"
            or manifest["releasable"] is not True
            or manifest["local_unsigned_marker"] is not None
        ):
            raise ReleaseError(
                "signed release manifest is not releasable release-mode output"
            )
        if (
            manifest["signing"]["certificate_oidc_issuer"]
            != args.certificate_oidc_issuer
        ):
            raise ReleaseError(
                "manifest OIDC issuer does not match external trust policy"
            )
        if manifest["signing"]["certificate_identity"] != args.certificate_identity:
            raise ReleaseError(
                "manifest certificate identity does not match external trust policy"
            )
        if (
            manifest["signing"]["certificate_github_workflow_sha"]
            != args.certificate_github_workflow_sha
            or manifest["source"]["commit"] != args.certificate_github_workflow_sha
        ):
            raise ReleaseError(
                "manifest source does not match the external workflow SHA policy"
            )
        if (
            manifest["signing"]["certificate_github_workflow_trigger"]
            != args.certificate_github_workflow_trigger
        ):
            raise ReleaseError("manifest trigger does not match external trust policy")
    else:
        if (
            manifest["release_mode"] != "local-unsigned"
            or manifest["releasable"] is not False
            or manifest["local_unsigned_marker"] != LOCAL_MARKER
            or manifest["signing"]["certificate_oidc_issuer"] is not None
            or manifest["signing"]["certificate_identity"] is not None
            or manifest["signing"]["certificate_github_workflow_sha"] is not None
            or manifest["signing"]["certificate_github_workflow_trigger"] is not None
        ):
            raise ReleaseError("local unsigned manifest is incorrectly marked")
    requested_target_ids = args.targets or [
        target["id"] for target in manifest["targets"]
    ]
    if len(requested_target_ids) != len(set(requested_target_ids)):
        raise ReleaseError("verification targets must not contain duplicates")
    selected_ids = set(requested_target_ids)
    available_ids = {target["id"] for target in manifest["targets"]}
    if not selected_ids or not selected_ids.issubset(available_ids):
        raise ReleaseError(
            f"unknown verification targets: {sorted(selected_ids - available_ids)}"
        )
    receipt_platform: str | None = None
    if args.verification_receipt is not None:
        if not release_mode:
            raise ReleaseError("local unsigned verification cannot issue a public receipt")
        if (
            args.github_run_id is None
            or args.github_run_attempt is None
            or args.github_run_id <= 0
            or args.github_run_attempt <= 0
        ):
            raise ReleaseError(
                "a public verification receipt requires the GitHub run id and attempt"
            )
        if selected_ids == {"linux-amd64", "linux-arm64"}:
            receipt_platform = "linux"
        elif selected_ids == {"darwin-amd64", "darwin-arm64"}:
            receipt_platform = "darwin"
        else:
            raise ReleaseError(
                "a public verification receipt requires exactly one complete platform"
            )
    expected_names = expected_content_files(manifest)
    allowed = set(expected_names) | {CHECKSUMS}
    if release_mode:
        blobs, attestations = signing_plan(manifest)
        allowed.update(bundle for _, bundle in [*blobs, *attestations])
    entries = list(output.iterdir())
    for path in entries:
        mode = path.lstat().st_mode
        if not stat.S_ISREG(mode) or path.is_symlink():
            raise ReleaseError(
                f"release directory entry is not a regular non-symlink file: {path.name}"
            )
    actual = {path.name for path in entries}
    if actual != allowed:
        raise ReleaseError(
            f"release directory has missing or unlisted files: {sorted(actual ^ allowed)}"
        )
    checksums_path = safe_file(output, CHECKSUMS, "checksums")
    if release_mode:
        verify_blob(
            args.cosign,
            output,
            CHECKSUMS,
            manifest["signing"]["checksums_bundle"],
            args.certificate_oidc_issuer,
            args.certificate_identity,
            args.certificate_github_workflow_sha,
            args.certificate_github_workflow_trigger,
        )
    checksum_map = parse_checksums(checksums_path)
    if sorted(checksum_map) != expected_names:
        raise ReleaseError("SHA256SUMS does not exactly cover manifest content files")
    for name in expected_names:
        path = safe_file(output, name, "checksummed file")
        if sha256_file(path) != checksum_map[name]:
            raise ReleaseError(f"SHA256SUMS mismatch: {name}")
    if release_mode:
        release_metadata = manifest["connector_release_metadata"]
        metadata_path = safe_file(
            output,
            release_metadata["filename"],
            "Connector self-service release metadata",
        )
        validate_connector_release_metadata(
            read_canonical_json(
                metadata_path, "Connector self-service release metadata"
            ),
            manifest,
            manifest_path,
        )
        verify_blob(
            args.cosign,
            output,
            release_metadata["filename"],
            release_metadata["signature_bundle"],
            args.certificate_oidc_issuer,
            args.certificate_identity,
            args.certificate_github_workflow_sha,
            args.certificate_github_workflow_trigger,
        )
    for target in manifest["targets"]:
        artifact = target["artifact"]
        artifact_path = safe_file(
            output, artifact["filename"], "artifact", executable=True
        )
        if (
            artifact_path.stat().st_size != artifact["size"]
            or sha256_file(artifact_path) != artifact["sha256"]
        ):
            raise ReleaseError(
                f"artifact size or SHA-256 mismatch: {artifact_path.name}"
            )
        if (not release_mode or target["native_signature"]["policy"] == "none") and (
            artifact["sha256"] != artifact["reproducible_candidate_sha256"]
            or artifact["size"] != artifact["reproducible_candidate_size"]
        ):
            raise ReleaseError(
                f"artifact differs from its reproducible candidate: {target['id']}"
            )
        verify_hash_entry(
            output,
            {
                key: target["sbom"][key]
                for key in ("filename", "sha256", "size", "signature_bundle")
            },
            "SBOM",
        )
        verify_hash_entry(
            output,
            {
                key: target["provenance"][key]
                for key in ("filename", "sha256", "size", "signature_bundle")
            },
            "provenance",
        )
        native_evidence = target["native_signature"].get("evidence")
        if native_evidence is not None:
            verify_hash_entry(output, native_evidence, "native evidence")
        for package in target["packages"]:
            for field, context in (
                ("artifact", "native package"),
                ("sbom", "package SBOM"),
                ("provenance", "package provenance"),
            ):
                entry = package[field]
                verify_hash_entry(
                    output,
                    {
                        key: entry[key]
                        for key in ("filename", "sha256", "size", "signature_bundle")
                    },
                    context,
                )
            package_native = package["native_signature"]
            package_evidence = package_native.get("evidence")
            if package_evidence is not None:
                verify_hash_entry(output, package_evidence, "package native evidence")
            public_key = package_native.get("public_key")
            if public_key is not None:
                verify_hash_entry(output, public_key, "RPM public key")
    for target in manifest["targets"]:
        if target["id"] not in selected_ids:
            continue
        require_exact_keys(
            target,
            {
                "id",
                "os",
                "arch",
                "artifact",
                "sbom",
                "provenance",
                "native_signature",
                "packages",
            },
            "target",
        )
        artifact_entry = target["artifact"]
        require_exact_keys(
            artifact_entry,
            {
                "filename",
                "sha256",
                "size",
                "reproducible_candidate_sha256",
                "reproducible_candidate_size",
                "signature_bundle",
            },
            "artifact",
        )
        if (
            not HEX_SHA256.fullmatch(artifact_entry["reproducible_candidate_sha256"])
            or not isinstance(artifact_entry["reproducible_candidate_size"], int)
            or artifact_entry["reproducible_candidate_size"] <= 0
        ):
            raise ReleaseError("artifact reproducible candidate metadata is invalid")
        artifact_path = safe_file(
            output, artifact_entry["filename"], "artifact", executable=True
        )
        if (
            artifact_path.stat().st_size != artifact_entry["size"]
            or sha256_file(artifact_path) != artifact_entry["sha256"]
        ):
            raise ReleaseError(
                f"artifact size or SHA-256 mismatch: {artifact_path.name}"
            )
        if (not release_mode or target["native_signature"]["policy"] == "none") and (
            artifact_entry["sha256"] != artifact_entry["reproducible_candidate_sha256"]
            or artifact_entry["size"] != artifact_entry["reproducible_candidate_size"]
        ):
            raise ReleaseError(
                f"artifact differs from its reproducible candidate: {target['id']}"
            )
        sbom_entry = target["sbom"]
        if sbom_entry.get("format") != "SPDX-2.3-json":
            raise ReleaseError("unsupported SBOM format")
        sbom_path = verify_hash_entry(
            output,
            {
                key: sbom_entry[key]
                for key in ("filename", "sha256", "size", "signature_bundle")
            },
            "SBOM",
        )
        provenance_entry = target["provenance"]
        if (
            provenance_entry.get("predicate_type") != SLSA_PREDICATE
            or "attestation_bundle" not in provenance_entry
        ):
            raise ReleaseError("unsupported provenance format")
        provenance_path = verify_hash_entry(
            output,
            {
                key: provenance_entry[key]
                for key in ("filename", "sha256", "size", "signature_bundle")
            },
            "provenance",
        )
        verify_sbom(sbom_path, artifact_path, artifact_entry, manifest)
        verify_provenance(
            provenance_path,
            artifact_entry,
            target,
            manifest,
            args.certificate_identity if release_mode else None,
        )
        native = target["native_signature"]
        if release_mode and target["os"] == "darwin":
            if (
                native.get("policy") != "apple-developer-id-and-notarization"
                or native.get("status") != "verified"
            ):
                raise ReleaseError(
                    f"Darwin target {target['id']} lacks verified native signature state"
                )
            evidence_entry = native.get("evidence")
            evidence_path = verify_hash_entry(output, evidence_entry, "native evidence")
            evidence = read_json(evidence_path)
            if (
                native.get("team_identifier") != args.apple_team_id
                or native.get("signing_identity") != args.apple_signing_identity
            ):
                raise ReleaseError(f"Apple trust policy mismatch for {target['id']}")
            validate_native_evidence(
                evidence,
                target_id=target["id"],
                artifact_name_value=artifact_entry["filename"],
                artifact_sha256=artifact_entry["sha256"],
                expected_team_id=args.apple_team_id,
                expected_signing_identity=args.apple_signing_identity,
            )
            if platform.system() != "Darwin":
                raise ReleaseError(
                    "Darwin release artifacts require verification on macOS with codesign"
                )
            verify_codesign_identity(
                artifact_path,
                args.apple_team_id,
                args.apple_signing_identity,
            )
            verify_blob(
                args.cosign,
                output,
                evidence_entry["filename"],
                evidence_entry["signature_bundle"],
                args.certificate_oidc_issuer,
                args.certificate_identity,
                args.certificate_github_workflow_sha,
                args.certificate_github_workflow_trigger,
            )
        elif release_mode and native != {"policy": "none", "status": "not-required"}:
            raise ReleaseError(f"unexpected native-signature policy for {target['id']}")
        if release_mode:
            issuer = args.certificate_oidc_issuer
            identity = args.certificate_identity
            workflow_sha = args.certificate_github_workflow_sha
            workflow_trigger = args.certificate_github_workflow_trigger
            verify_blob(
                args.cosign,
                output,
                artifact_entry["filename"],
                artifact_entry["signature_bundle"],
                issuer,
                identity,
                workflow_sha,
                workflow_trigger,
            )
            verify_blob(
                args.cosign,
                output,
                sbom_entry["filename"],
                sbom_entry["signature_bundle"],
                issuer,
                identity,
                workflow_sha,
                workflow_trigger,
            )
            verify_blob(
                args.cosign,
                output,
                provenance_entry["filename"],
                provenance_entry["signature_bundle"],
                issuer,
                identity,
                workflow_sha,
                workflow_trigger,
            )
            verify_attestation(
                args.cosign,
                output,
                artifact_entry,
                provenance_entry,
                issuer,
                identity,
                workflow_sha,
                workflow_trigger,
            )
        for package in target["packages"]:
            package_artifact = package["artifact"]
            package_path = verify_hash_entry(
                output,
                {
                    key: package_artifact[key]
                    for key in ("filename", "sha256", "size", "signature_bundle")
                },
                "native package",
            )
            package_sbom = package["sbom"]
            package_sbom_path = verify_hash_entry(
                output,
                {
                    key: package_sbom[key]
                    for key in ("filename", "sha256", "size", "signature_bundle")
                },
                "package SBOM",
            )
            package_provenance = package["provenance"]
            package_provenance_path = verify_hash_entry(
                output,
                {
                    key: package_provenance[key]
                    for key in ("filename", "sha256", "size", "signature_bundle")
                },
                "package provenance",
            )
            verify_package_sbom(
                package_sbom_path, package_path, package, target, manifest
            )
            verify_package_provenance(
                package_provenance_path,
                package,
                target,
                manifest,
                args.certificate_identity if release_mode else None,
            )
            evidence_path: Path | None = None
            public_key_path: Path | None = None
            if release_mode:
                evidence_path, public_key_path = validate_package_native_files(
                    output,
                    target,
                    package,
                    expected_apple_team_id=args.apple_team_id,
                    expected_apple_application_identity=args.apple_signing_identity,
                    expected_apple_installer_identity=args.apple_installer_identity,
                    expected_rpm_fingerprint=args.rpm_signing_fingerprint,
                )
                verify_package_platform_trust(
                    package_path,
                    package,
                    target,
                    artifact_path,
                    public_key_path,
                    manifest["connector_version"],
                    expected_installer_identity=args.apple_installer_identity,
                    expected_rpm_fingerprint=args.rpm_signing_fingerprint,
                )
                for entry in (package_artifact, package_sbom, package_provenance):
                    verify_blob(
                        args.cosign,
                        output,
                        entry["filename"],
                        entry["signature_bundle"],
                        args.certificate_oidc_issuer,
                        args.certificate_identity,
                        args.certificate_github_workflow_sha,
                        args.certificate_github_workflow_trigger,
                    )
                if evidence_path is not None:
                    evidence_entry = package["native_signature"]["evidence"]
                    verify_blob(
                        args.cosign,
                        output,
                        evidence_entry["filename"],
                        evidence_entry["signature_bundle"],
                        args.certificate_oidc_issuer,
                        args.certificate_identity,
                        args.certificate_github_workflow_sha,
                        args.certificate_github_workflow_trigger,
                    )
                if public_key_path is not None:
                    public_key_entry = package["native_signature"]["public_key"]
                    verify_blob(
                        args.cosign,
                        output,
                        public_key_entry["filename"],
                        public_key_entry["signature_bundle"],
                        args.certificate_oidc_issuer,
                        args.certificate_identity,
                        args.certificate_github_workflow_sha,
                        args.certificate_github_workflow_trigger,
                    )
                verify_attestation(
                    args.cosign,
                    output,
                    package_artifact,
                    package_provenance,
                    args.certificate_oidc_issuer,
                    args.certificate_identity,
                    args.certificate_github_workflow_sha,
                    args.certificate_github_workflow_trigger,
                )
    if args.verification_receipt is not None:
        assert receipt_platform is not None
        write_platform_receipt(
            args.verification_receipt,
            output,
            manifest,
            receipt_platform,
            args,
        )
    print(
        f"verified {manifest['release_mode']} Connector evidence for {len(selected_ids)} selected targets"
    )


def regular_input_file(path: Path, expected_name: str, context: str) -> Path:
    if path.name != expected_name:
        raise ReleaseError(f"{context} must be named {expected_name}")
    absolute = path.absolute()
    try:
        mode = absolute.lstat().st_mode
        resolved = absolute.resolve(strict=True)
    except OSError as exc:
        raise ReleaseError(f"cannot inspect {context}: {exc}") from exc
    if not stat.S_ISREG(mode) or absolute.is_symlink():
        raise ReleaseError(f"{context} must be a regular non-symlink file")
    return resolved


def regular_external_input_file(path: Path, context: str) -> Path:
    absolute = path.absolute()
    try:
        mode = absolute.lstat().st_mode
        resolved = absolute.resolve(strict=True)
    except OSError as exc:
        raise ReleaseError(f"cannot inspect {context}: {exc}") from exc
    if not stat.S_ISREG(mode) or absolute.is_symlink():
        raise ReleaseError(f"{context} must be a regular non-symlink file")
    return resolved


def parse_rfc3339(value: Any, context: str) -> str:
    if not isinstance(value, str) or not value or not value.endswith("Z"):
        raise ReleaseError(f"{context} must be a UTC RFC 3339 timestamp")
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ReleaseError(f"{context} must be a UTC RFC 3339 timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != dt.timedelta(0):
        raise ReleaseError(f"{context} must be a UTC RFC 3339 timestamp")
    return value


def expected_core_asset_names(version: str) -> set[str]:
    names = {MANIFEST, CONNECTOR_RELEASE_METADATA, CHECKSUMS}
    blob_inputs = {MANIFEST, CONNECTOR_RELEASE_METADATA, CHECKSUMS}
    attestation_bundles: set[str] = set()
    for os_name, arch in (
        ("linux", "amd64"),
        ("linux", "arm64"),
        ("darwin", "amd64"),
        ("darwin", "arm64"),
    ):
        target_id = f"{os_name}-{arch}"
        artifact = f"sub2api-codex-connector_{version}_{os_name}_{arch}"
        target_files = {artifact, f"{artifact}.spdx.json", f"{artifact}.intoto.json"}
        names.update(target_files)
        blob_inputs.update(target_files)
        attestation_bundles.add(f"{artifact}.intoto.sigstore.json")
        if os_name == "darwin":
            native = f"native-{target_id}.json"
            names.add(native)
            blob_inputs.add(native)
            formats = ("pkg",)
        else:
            formats = ("deb", "rpm")
        for package_format in formats:
            package = f"{artifact}.{package_format}"
            package_files = {
                package,
                f"{package}.spdx.json",
                f"{package}.intoto.json",
            }
            names.update(package_files)
            blob_inputs.update(package_files)
            attestation_bundles.add(f"{package}.intoto.sigstore.json")
            if package_format in {"rpm", "pkg"}:
                native_package = (
                    f"native-package-{target_id}-{package_format}.json"
                )
                names.add(native_package)
                blob_inputs.add(native_package)
            if package_format == "rpm":
                public_key = f"rpm-signing-{target_id}.asc"
                names.add(public_key)
                blob_inputs.add(public_key)
    names.update(f"{name}.sigstore.json" for name in blob_inputs)
    names.update(attestation_bundles)
    if len(names) != 92:
        raise ReleaseError("internal core asset inventory is not the fixed 92-file matrix")
    return names


def regular_json_input(path: Path, context: str) -> Path:
    absolute = path.absolute()
    try:
        mode = absolute.lstat().st_mode
        resolved = absolute.resolve(strict=True)
    except OSError as exc:
        raise ReleaseError(f"cannot inspect {context}: {exc}") from exc
    if not stat.S_ISREG(mode) or absolute.is_symlink():
        raise ReleaseError(f"{context} must be a regular non-symlink file")
    return resolved


def create_public_release_descriptor(args: argparse.Namespace) -> None:
    response_path = regular_json_input(
        args.github_release_response, "GitHub release API response"
    )
    response = read_json(response_path)
    if not isinstance(response, dict):
        raise ReleaseError("GitHub release API response must be an object")
    if (
        not isinstance(args.source_commit, str)
        or not HEX_GIT_COMMIT.fullmatch(args.source_commit)
        or args.github_run_id <= 0
        or args.github_run_attempt <= 0
    ):
        raise ReleaseError("public release descriptor external source/run policy is invalid")
    release_id = response.get("id")
    tag = response.get("tag_name")
    if (
        not isinstance(release_id, int)
        or isinstance(release_id, bool)
        or release_id <= 0
        or not isinstance(tag, str)
        or not re.fullmatch(r"connector-v\d+\.\d+\.\d+", tag)
        or response.get("draft") is not False
        or response.get("prerelease") is not False
        or response.get("immutable") is not True
        or response.get("url")
        != (
            "https://api.github.com/repos/"
            f"{RELEASE_REPOSITORY.removeprefix('https://github.com/')}/releases/{release_id}"
        )
    ):
        raise ReleaseError("GitHub release API response is not the official immutable release")
    published_at = parse_rfc3339(
        response.get("published_at"), "GitHub release published_at"
    )
    version = tag.removeprefix("connector-v")
    vulnerability_receipt_path = regular_input_file(
        args.vulnerability_receipt,
        VULNERABILITY_RECEIPT,
        "public vulnerability receipt",
    )
    vulnerability_receipt = read_compact_canonical_json(
        vulnerability_receipt_path, "public vulnerability receipt"
    )
    vulnerability_inventory = validate_vulnerability_receipt(
        vulnerability_receipt,
        None,
        None,
        args.source_commit,
        version,
    )
    expected_vulnerability = expected_public_vulnerability_asset_names(
        vulnerability_inventory
    )
    assets_value = response.get("assets")
    if not isinstance(assets_value, list):
        raise ReleaseError("GitHub release API response lacks assets")
    assets = [
        validate_public_asset(asset, tag, "GitHub release asset")
        for asset in assets_value
    ]
    names = [asset["name"] for asset in assets]
    ids = [asset["id"] for asset in assets]
    if len(names) != len(set(names)) or len(ids) != len(set(ids)):
        raise ReleaseError("GitHub release API response repeats an asset")
    by_name = {asset["name"]: asset for asset in assets}
    expected_core = expected_core_asset_names(version)
    expected_all = expected_core | expected_vulnerability
    if set(by_name) != expected_all or expected_core & expected_vulnerability:
        raise ReleaseError(
            "GitHub release assets are not the exact core and vulnerability union"
        )
    core_assets = [by_name[name] for name in sorted(expected_core)]
    vulnerability_assets = [
        by_name[name] for name in sorted(expected_vulnerability)
    ]
    descriptor = {
        "$schema": "https://sub2api-codex.invalid/schemas/connector-public-release-descriptor-v1.json",
        "format_version": 1,
        "kind": "github-public-immutable-release",
        "source_repository": RELEASE_REPOSITORY,
        "source_commit": args.source_commit,
        "version": version,
        "tag": tag,
        "release_id": release_id,
        "workflow_run_id": args.github_run_id,
        "workflow_run_attempt": args.github_run_attempt,
        "published_at": published_at,
        "draft": False,
        "prerelease": False,
        "immutable": True,
        "core_assets": core_assets,
        "vulnerability_assets": vulnerability_assets,
        "assets": [by_name[name] for name in sorted(expected_all)],
    }
    validate_public_release_descriptor(descriptor)
    output = args.output.absolute()
    if output.name != PUBLIC_RELEASE_DESCRIPTOR:
        raise ReleaseError(
            f"public release descriptor must be named {PUBLIC_RELEASE_DESCRIPTOR}"
        )
    write_exclusive_canonical_json(output, descriptor)
    print(f"created canonical descriptor for immutable release {release_id}")


def validate_public_asset(
    asset: Any, release_tag: str, context: str
) -> dict[str, Any]:
    if not isinstance(asset, dict):
        raise ReleaseError(f"{context} must be an object")
    require_exact_keys(
        asset,
        {"id", "name", "size", "digest", "state", "browser_download_url"},
        context,
    )
    name = asset["name"]
    if (
        not isinstance(asset["id"], int)
        or isinstance(asset["id"], bool)
        or asset["id"] <= 0
        or not isinstance(name, str)
        or not SAFE_NAME.fullmatch(name)
        or not isinstance(asset["size"], int)
        or isinstance(asset["size"], bool)
        or asset["size"] < 0
        or not isinstance(asset["digest"], str)
        or not re.fullmatch(r"sha256:[0-9a-f]{64}", asset["digest"])
        or asset["state"] != "uploaded"
        or asset["browser_download_url"]
        != f"{RELEASE_REPOSITORY}/releases/download/{release_tag}/{name}"
    ):
        raise ReleaseError(f"{context} is invalid")
    return asset


def validate_public_release_descriptor(descriptor: Any) -> dict[str, Any]:
    if not isinstance(descriptor, dict):
        raise ReleaseError("public release descriptor must be an object")
    require_exact_keys(
        descriptor,
        {
            "$schema",
            "format_version",
            "kind",
            "source_repository",
            "source_commit",
            "version",
            "tag",
            "release_id",
            "workflow_run_id",
            "workflow_run_attempt",
            "published_at",
            "draft",
            "prerelease",
            "immutable",
            "core_assets",
            "vulnerability_assets",
            "assets",
        },
        "public release descriptor",
    )
    if (
        descriptor["$schema"]
        != "https://sub2api-codex.invalid/schemas/connector-public-release-descriptor-v1.json"
        or descriptor["format_version"] != 1
        or descriptor["kind"] != "github-public-immutable-release"
        or descriptor["source_repository"] != RELEASE_REPOSITORY
        or not isinstance(descriptor["source_commit"], str)
        or not HEX_GIT_COMMIT.fullmatch(descriptor["source_commit"])
        or not isinstance(descriptor["version"], str)
        or not re.fullmatch(r"\d+\.\d+\.\d+", descriptor["version"])
        or descriptor["tag"] != f"connector-v{descriptor['version']}"
        or not isinstance(descriptor["release_id"], int)
        or isinstance(descriptor["release_id"], bool)
        or descriptor["release_id"] <= 0
        or not isinstance(descriptor["workflow_run_id"], int)
        or isinstance(descriptor["workflow_run_id"], bool)
        or descriptor["workflow_run_id"] <= 0
        or not isinstance(descriptor["workflow_run_attempt"], int)
        or isinstance(descriptor["workflow_run_attempt"], bool)
        or descriptor["workflow_run_attempt"] <= 0
        or descriptor["draft"] is not False
        or descriptor["prerelease"] is not False
        or descriptor["immutable"] is not True
    ):
        raise ReleaseError("public release descriptor identity or immutable state is invalid")
    parse_rfc3339(descriptor["published_at"], "public release published_at")

    lists: dict[str, list[dict[str, Any]]] = {}
    for field in ("core_assets", "vulnerability_assets", "assets"):
        value = descriptor[field]
        if not isinstance(value, list) or not value:
            raise ReleaseError(f"public release descriptor {field} must be non-empty")
        validated = [
            validate_public_asset(item, descriptor["tag"], f"{field} entry")
            for item in value
        ]
        names = [item["name"] for item in validated]
        ids = [item["id"] for item in validated]
        if names != sorted(names) or len(names) != len(set(names)) or len(ids) != len(
            set(ids)
        ):
            raise ReleaseError(f"public release descriptor {field} is not unique and sorted")
        lists[field] = validated
    core_names = {item["name"] for item in lists["core_assets"]}
    vulnerability_names = {
        item["name"] for item in lists["vulnerability_assets"]
    }
    expected_core = expected_core_asset_names(descriptor["version"])
    if core_names != expected_core:
        raise ReleaseError("public release descriptor core asset matrix is invalid")
    evidence_names = vulnerability_names - VULNERABILITY_PUBLIC_FIXED_ASSETS
    if (
        VULNERABILITY_PUBLIC_FIXED_ASSETS - vulnerability_names
        or len(evidence_names) != 41
        or any(
            not re.fullmatch(
                rf"{re.escape(VULNERABILITY_PUBLIC_PREFIX)}[0-9a-f]{{16}}-[A-Za-z0-9][A-Za-z0-9._-]*",
                name,
            )
            for name in evidence_names
        )
    ):
        raise ReleaseError(
            "public release descriptor vulnerability asset matrix is invalid"
        )
    if core_names & vulnerability_names:
        raise ReleaseError("public release asset classifications must be disjoint")
    expected_assets = sorted(
        [*lists["core_assets"], *lists["vulnerability_assets"]],
        key=lambda item: item["name"],
    )
    if lists["assets"] != expected_assets:
        raise ReleaseError("public release assets are not the exact classified union")
    all_ids = [item["id"] for item in lists["assets"]]
    if len(all_ids) != len(set(all_ids)):
        raise ReleaseError("public release assets reuse a GitHub asset id")
    return descriptor


def public_assets_as_inventory(assets: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "filename": asset["name"],
            "sha256": asset["digest"].removeprefix("sha256:"),
            "size": asset["size"],
        }
        for asset in assets
    ]


def vulnerability_relative_path(value: Any, context: str) -> str:
    if not isinstance(value, str) or not value or not value.isascii() or "\\" in value:
        raise ReleaseError(f"{context} must be a portable relative path")
    parsed = PurePosixPath(value)
    if (
        parsed.is_absolute()
        or parsed.as_posix() != value
        or any(
            component in {"", ".", ".."}
            or not SAFE_PATH_COMPONENT.fullmatch(component)
            for component in parsed.parts
        )
    ):
        raise ReleaseError(f"{context} must be one canonical relative path")
    return value


def vulnerability_file(directory: Path, relative: Any, context: str) -> Path:
    name = vulnerability_relative_path(relative, context)
    base = directory.absolute()
    try:
        base_mode = base.lstat().st_mode
    except OSError as exc:
        raise ReleaseError(f"cannot inspect vulnerability evidence directory: {exc}") from exc
    if not stat.S_ISDIR(base_mode) or base.is_symlink():
        raise ReleaseError("vulnerability evidence directory must be real and non-symlinked")
    current = base
    for component in PurePosixPath(name).parts[:-1]:
        current /= component
        try:
            mode = current.lstat().st_mode
        except OSError as exc:
            raise ReleaseError(f"cannot inspect {context}: {name}: {exc}") from exc
        if not stat.S_ISDIR(mode) or current.is_symlink():
            raise ReleaseError(f"{context} parent must be a real directory: {name}")
    path = base.joinpath(*PurePosixPath(name).parts)
    try:
        mode = path.lstat().st_mode
        resolved_base = base.resolve(strict=True)
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise ReleaseError(f"cannot inspect {context}: {name}: {exc}") from exc
    if (
        not stat.S_ISREG(mode)
        or path.is_symlink()
        or resolved != path.absolute()
        or resolved_base not in resolved.parents
    ):
        raise ReleaseError(f"{context} must be a regular non-symlink file: {name}")
    return resolved


def validate_vulnerability_core_roots(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list) or len(value) != 1:
        raise ReleaseError("vulnerability receipt must name exactly one Connector release root")
    root = value[0]
    if not isinstance(root, dict):
        raise ReleaseError("vulnerability Connector release root must be an object")
    require_exact_keys(
        root,
        {
            "id",
            "kind",
            "path",
            "sha256",
            "size",
            "signature_bundle_path",
            "signature_bundle_sha256",
            "signature_bundle_size",
        },
        "vulnerability Connector release root",
    )
    root_path = vulnerability_relative_path(
        root["path"], "vulnerability Connector release root path"
    )
    bundle_path = vulnerability_relative_path(
        root["signature_bundle_path"],
        "vulnerability Connector release root signature bundle path",
    )
    if (
        root["id"] != "connector"
        or root["kind"] != "connector-manifest-v1"
        or root_path != f"connector/{MANIFEST}"
        or bundle_path != f"connector/{MANIFEST}.sigstore.json"
        or not isinstance(root["sha256"], str)
        or not HEX_SHA256.fullmatch(root["sha256"])
        or not isinstance(root["size"], int)
        or isinstance(root["size"], bool)
        or root["size"] <= 0
        or not isinstance(root["signature_bundle_sha256"], str)
        or not HEX_SHA256.fullmatch(root["signature_bundle_sha256"])
        or not isinstance(root["signature_bundle_size"], int)
        or isinstance(root["signature_bundle_size"], bool)
        or root["signature_bundle_size"] <= 0
    ):
        raise ReleaseError("vulnerability Connector release root is invalid")
    return value


def vulnerability_public_asset_name(path: Any) -> str:
    relative = vulnerability_relative_path(path, "public vulnerability receipt path")
    basename = PurePosixPath(relative).name
    if not SAFE_NAME.fullmatch(basename):
        raise ReleaseError("public vulnerability evidence basename is not release-safe")
    path_digest = hashlib.sha256(relative.encode("ascii")).hexdigest()[:16]
    name = f"{VULNERABILITY_PUBLIC_PREFIX}{path_digest}-{basename}"
    if not SAFE_NAME.fullmatch(name):
        raise ReleaseError("derived public vulnerability asset name is invalid")
    return name


def vulnerability_public_asset_map(
    inventory: list[dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    public: dict[str, dict[str, Any]] = {}
    for item in inventory:
        path = item["path"]
        if path.startswith("connector/"):
            continue
        name = vulnerability_public_asset_name(path)
        if name in public:
            raise ReleaseError("public vulnerability asset derivation is not injective")
        public[name] = item
    if len(public) != 41:
        raise ReleaseError("public vulnerability evidence must contain exactly 41 files")
    return public


def expected_public_vulnerability_asset_names(
    inventory: list[dict[str, Any]],
) -> set[str]:
    names = set(vulnerability_public_asset_map(inventory)) | VULNERABILITY_PUBLIC_FIXED_ASSETS
    if len(names) != 43:
        raise ReleaseError("public vulnerability asset projection is not the fixed 43-file set")
    return names


def validate_vulnerability_scanner(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ReleaseError("vulnerability receipt scanner must be an object")
    digest_fields = {
        "binary_sha256",
        "scanner_install_receipt_sha256",
        "config_sha256",
        "ignorefile_sha256",
        "vulnerability_database_metadata_sha256",
        "vulnerability_database_sha256",
        "java_database_metadata_sha256",
        "java_database_sha256",
    }
    require_exact_keys(
        value,
        {
            "name",
            "version",
            *digest_fields,
            "vulnerability_database_oci_digest",
            "vulnerability_database_updated_at",
            "java_database_oci_digest",
            "java_database_updated_at",
        },
        "vulnerability receipt scanner",
    )
    if (
        value["name"] != "trivy"
        or value["version"] != "0.74.0"
        or any(
            not isinstance(value[field], str) or not HEX_SHA256.fullmatch(value[field])
            for field in digest_fields
        )
        or any(
            not isinstance(value[field], str)
            or not re.fullmatch(r"sha256:[0-9a-f]{64}", value[field])
            for field in (
                "vulnerability_database_oci_digest",
                "java_database_oci_digest",
            )
        )
    ):
        raise ReleaseError("vulnerability receipt scanner evidence is invalid")
    parse_rfc3339(
        value["vulnerability_database_updated_at"],
        "vulnerability database updated_at",
    )
    parse_rfc3339(value["java_database_updated_at"], "Java database updated_at")
    return value


def validate_vulnerability_inventory(
    receipt: dict[str, Any],
    version: str,
    evidence_directory: Path | None = None,
) -> list[dict[str, Any]]:
    inventory = receipt["evidence_inventory"]
    if not isinstance(inventory, list) or len(inventory) != 55:
        raise ReleaseError("vulnerability receipt must inventory exactly 55 files")
    order: list[tuple[str, str, str]] = []
    result: list[dict[str, Any]] = []
    seen: set[str] = set()
    by_role_target: dict[tuple[str, str], dict[str, Any]] = {}
    for item in inventory:
        if not isinstance(item, dict):
            raise ReleaseError("vulnerability evidence inventory entry must be an object")
        require_exact_keys(
            item, {"path", "role", "sha256", "size", "target"}, "vulnerability evidence"
        )
        path_name = vulnerability_relative_path(item["path"], "vulnerability evidence path")
        role = item["role"]
        target = item["target"]
        size = item["size"]
        if (
            path_name in seen
            or not isinstance(role, str)
            or not SAFE_PATH_COMPONENT.fullmatch(role)
            or not isinstance(target, str)
            or not SAFE_PATH_COMPONENT.fullmatch(target)
            or not isinstance(item["sha256"], str)
            or not HEX_SHA256.fullmatch(item["sha256"])
            or not isinstance(size, int)
            or isinstance(size, bool)
            or size < 0
            or (size == 0 and role not in {"scanner-config", "scanner-ignorefile"})
        ):
            raise ReleaseError("vulnerability evidence inventory entry is invalid")
        identity = (role, target)
        if identity in by_role_target:
            raise ReleaseError("vulnerability evidence repeats a role and target")
        if evidence_directory is not None:
            path = vulnerability_file(
                evidence_directory, path_name, "vulnerability evidence"
            )
            if path.stat().st_size != size or sha256_file(path) != item["sha256"]:
                raise ReleaseError(f"vulnerability evidence hash mismatch: {path_name}")
        seen.add(path_name)
        by_role_target[identity] = item
        order.append((role, target, path_name))
        result.append(item)
    if order != sorted(order):
        raise ReleaseError("vulnerability evidence inventory is not canonically sorted")

    expected_pairs = {
        ("manifest", "release"),
        ("dispositions", "release"),
        ("scanner-install", "scanner"),
        ("scanner-archive", "scanner"),
        ("scanner-binary", "scanner"),
        ("scanner-checksums", "scanner"),
        ("scanner-checksums-signature", "scanner"),
        ("scanner-config", "scanner"),
        ("scanner-ignorefile", "scanner"),
        ("release-root", "connector"),
        ("release-root-signature", "connector"),
    }
    database_roles = {
        "database-metadata",
        "database-file",
        "database-oci-layout",
        "database-oci-index",
        "database-oci-manifest",
        "database-oci-config",
        "database-oci-layer",
    }
    for database_target in ("vulnerability-database", "java-database"):
        expected_pairs.update((role, database_target) for role in database_roles)
    for target_name in CONNECTOR_VULNERABILITY_TARGET_SPECS:
        expected_pairs.update(
            (role, target_name)
            for role in ("artifact", "sbom", "report", "raw-report", "scan-execution")
        )
    if set(by_role_target) != expected_pairs:
        raise ReleaseError("vulnerability receipt role/target closure is not exact")

    scanner = validate_vulnerability_scanner(receipt["scanner"])
    fixed = {
        ("manifest", "release"): VULNERABILITY_MANIFEST,
        ("dispositions", "release"): "vulnerability-dispositions.json",
        ("scanner-install", "scanner"): "trivy-install-receipt.json",
        ("scanner-archive", "scanner"): "trivy_0.74.0_Linux-64bit.tar.gz",
        ("scanner-binary", "scanner"): "trivy-linux-amd64",
        ("scanner-checksums", "scanner"): "trivy_0.74.0_checksums.txt",
        (
            "scanner-checksums-signature",
            "scanner",
        ): "trivy_0.74.0_checksums.txt.sigstore.json",
        ("scanner-config", "scanner"): "trivy-empty.yaml",
        ("scanner-ignorefile", "scanner"): "trivy-empty.ignore",
        ("database-metadata", "vulnerability-database"): "trivy-db-metadata.json",
        ("database-file", "vulnerability-database"): "trivy.db",
        ("database-metadata", "java-database"): "trivy-java-db-metadata.json",
        ("database-file", "java-database"): "trivy-java.db",
    }
    for identity, expected_path in fixed.items():
        if by_role_target[identity]["path"] != expected_path:
            raise ReleaseError("vulnerability receipt fixed evidence path is invalid")
    hash_bindings = {
        ("manifest", "release"): receipt["manifest_sha256"],
        ("dispositions", "release"): receipt["dispositions_sha256"],
        ("scanner-install", "scanner"): scanner["scanner_install_receipt_sha256"],
        ("scanner-binary", "scanner"): scanner["binary_sha256"],
        ("scanner-config", "scanner"): scanner["config_sha256"],
        ("scanner-ignorefile", "scanner"): scanner["ignorefile_sha256"],
        ("database-metadata", "vulnerability-database"): scanner[
            "vulnerability_database_metadata_sha256"
        ],
        ("database-file", "vulnerability-database"): scanner[
            "vulnerability_database_sha256"
        ],
        ("database-metadata", "java-database"): scanner[
            "java_database_metadata_sha256"
        ],
        ("database-file", "java-database"): scanner["java_database_sha256"],
    }
    for identity, expected_digest in hash_bindings.items():
        if by_role_target[identity]["sha256"] != expected_digest:
            raise ReleaseError("vulnerability receipt scanner/hash projection is incomplete")

    for database_name, prefix in (
        ("vulnerability", "trivy-db-oci"),
        ("java", "trivy-java-db-oci"),
    ):
        target = f"{database_name}-database"
        expected_paths = {
            "database-oci-layout": f"{prefix}/oci-layout",
            "database-oci-index": f"{prefix}/index.json",
        }
        for role, expected_path in expected_paths.items():
            if by_role_target[(role, target)]["path"] != expected_path:
                raise ReleaseError("vulnerability database OCI root path is invalid")
        for role in ("database-oci-manifest", "database-oci-config", "database-oci-layer"):
            item = by_role_target[(role, target)]
            expected_prefix = f"{prefix}/blobs/sha256/"
            if (
                not item["path"].startswith(expected_prefix)
                or PurePosixPath(item["path"]).name != item["sha256"]
            ):
                raise ReleaseError("vulnerability database OCI blob binding is invalid")
        oci_digest = scanner[f"{database_name}_database_oci_digest"]
        if by_role_target[("database-oci-manifest", target)]["sha256"] != oci_digest.removeprefix(
            "sha256:"
        ):
            raise ReleaseError("vulnerability database manifest digest is not receipt-bound")

    roots = validate_vulnerability_core_roots(receipt["core_roots"])
    root = roots[0]
    root_item = by_role_target[("release-root", "connector")]
    root_bundle_item = by_role_target[("release-root-signature", "connector")]
    if (
        root_item["path"] != root["path"]
        or root_item["sha256"] != root["sha256"]
        or root_item["size"] != root["size"]
        or root_bundle_item["path"] != root["signature_bundle_path"]
        or root_bundle_item["sha256"] != root["signature_bundle_sha256"]
        or root_bundle_item["size"] != root["signature_bundle_size"]
    ):
        raise ReleaseError("vulnerability receipt does not bind its signed Connector root")
    root_parent = PurePosixPath(root["path"]).parent

    def root_sibling(filename: str) -> str:
        path = root_parent / filename
        return filename if root_parent == PurePosixPath(".") else path.as_posix()

    for target_name, (os_name, arch, package_format) in CONNECTOR_VULNERABILITY_TARGET_SPECS.items():
        artifact = by_role_target[("artifact", target_name)]
        sbom = by_role_target[("sbom", target_name)]
        report = by_role_target[("report", target_name)]
        raw_report = by_role_target[("raw-report", target_name)]
        execution = by_role_target[("scan-execution", target_name)]
        expected_artifact = (
            f"sub2api-codex-connector_{version}_{os_name}_{arch}.{package_format}"
        )
        if (
            artifact["path"] != root_sibling(expected_artifact)
            or sbom["path"] != root_sibling(f"{expected_artifact}.spdx.json")
            or report["path"] != f"vulnerability-{target_name}.json"
            or report["sha256"] != receipt["report_sha256"][target_name]
            or raw_report["path"] != f"vulnerability-{target_name}.raw.json"
            or execution["path"] != f"scan-execution-{target_name}.json"
        ):
            raise ReleaseError(
                f"vulnerability receipt target evidence is incomplete: {target_name}"
            )
    connector_paths = [item for item in result if item["path"].startswith("connector/")]
    if len(connector_paths) != 14:
        raise ReleaseError("vulnerability receipt must bind exactly 14 Connector core paths")
    vulnerability_public_asset_map(result)
    return result


def validate_vulnerability_receipt(
    receipt: Any,
    manifest_path: Path | None,
    evidence_directory: Path | None,
    source_commit: str,
    version: str,
) -> list[dict[str, Any]]:
    if not isinstance(receipt, dict):
        raise ReleaseError("vulnerability receipt must be an object")
    require_exact_keys(
        receipt,
        {
            "format_version",
            "status",
            "profile",
            "source_commit",
            "source_repository",
            "core_roots",
            "verified_at",
            "manifest_sha256",
            "policy_sha256",
            "dispositions_sha256",
            "scanner",
            "report_sha256",
            "scanned_package_counts",
            "evidence_inventory",
            "finding_counts",
            "reviewed_dispositions",
        },
        "vulnerability receipt",
    )
    if (
        receipt["format_version"] != 1
        or receipt["status"] != "passed"
        or receipt["profile"] != "connector-release"
        or not isinstance(source_commit, str)
        or not HEX_GIT_COMMIT.fullmatch(source_commit)
        or not isinstance(version, str)
        or not re.fullmatch(r"\d+\.\d+\.\d+", version)
        or receipt["source_commit"] != source_commit
        or receipt["source_repository"] != RELEASE_REPOSITORY
        or not isinstance(receipt["manifest_sha256"], str)
        or not HEX_SHA256.fullmatch(receipt["manifest_sha256"])
        or (
            manifest_path is not None
            and receipt["manifest_sha256"] != sha256_file(manifest_path)
        )
        or not isinstance(receipt["policy_sha256"], str)
        or not HEX_SHA256.fullmatch(receipt["policy_sha256"])
        or not isinstance(receipt["dispositions_sha256"], str)
        or not HEX_SHA256.fullmatch(receipt["dispositions_sha256"])
        or not isinstance(receipt["reviewed_dispositions"], int)
        or isinstance(receipt["reviewed_dispositions"], bool)
        or receipt["reviewed_dispositions"] < 0
    ):
        raise ReleaseError("vulnerability receipt identity or admission status is invalid")
    parse_rfc3339(receipt["verified_at"], "vulnerability receipt verified_at")
    validate_vulnerability_core_roots(receipt["core_roots"])
    validate_vulnerability_scanner(receipt["scanner"])
    expected_targets = set(CONNECTOR_VULNERABILITY_TARGET_SPECS)
    reports = receipt["report_sha256"]
    if (
        not isinstance(reports, dict)
        or set(reports) != expected_targets
        or any(
            not isinstance(value, str) or not HEX_SHA256.fullmatch(value)
            for value in reports.values()
        )
    ):
        raise ReleaseError("vulnerability receipt report matrix is incomplete")
    package_counts = receipt["scanned_package_counts"]
    if (
        not isinstance(package_counts, dict)
        or set(package_counts) != expected_targets
        or any(
            not isinstance(value, int) or isinstance(value, bool) or value <= 0
            for value in package_counts.values()
        )
    ):
        raise ReleaseError("vulnerability receipt scanned package matrix is incomplete")
    counts = receipt["finding_counts"]
    finding_severities = {"CRITICAL", "HIGH", "LOW", "MEDIUM", "UNKNOWN"}
    if (
        not isinstance(counts, dict)
        or set(counts) != finding_severities
        or any(
            not isinstance(value, int) or isinstance(value, bool) or value < 0
            for value in counts.values()
        )
        or any(counts[severity] != 0 for severity in ("CRITICAL", "HIGH", "UNKNOWN"))
        or receipt["reviewed_dispositions"] != counts["LOW"] + counts["MEDIUM"]
    ):
        raise ReleaseError("vulnerability receipt finding counts are invalid")
    result = validate_vulnerability_inventory(receipt, version, evidence_directory)
    if manifest_path is not None:
        manifest_item = next(
            item
            for item in result
            if item["role"] == "manifest" and item["target"] == "release"
        )
        if manifest_item["size"] != manifest_path.stat().st_size:
            raise ReleaseError("vulnerability receipt does not bind its manifest size")
    return result


def validate_vulnerability_manifest_bindings(
    manifest: Any,
    receipt: dict[str, Any],
    evidence_inventory: list[dict[str, Any]],
    core_inventory: list[dict[str, Any]],
    packages: list[dict[str, Any]],
) -> None:
    if not isinstance(manifest, dict):
        raise ReleaseError("vulnerability manifest must be an object")
    require_exact_keys(
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
    if (
        manifest["format_version"] != 1
        or manifest["profile"] != "connector-release"
        or manifest["source_commit"] != receipt["source_commit"]
        or manifest["source_repository"] != RELEASE_REPOSITORY
        or manifest["core_roots"] != receipt["core_roots"]
    ):
        raise ReleaseError("vulnerability manifest release identity is invalid")
    parse_rfc3339(manifest["generated_at"], "vulnerability manifest generated_at")
    evidence_by_path = {item["path"]: item for item in evidence_inventory}

    def manifest_file_record(
        value: Any,
        role: str,
        target: str,
        context: str,
    ) -> dict[str, Any]:
        if not isinstance(value, dict):
            raise ReleaseError(f"{context} must be an object")
        require_exact_keys(value, {"path", "sha256", "size"}, context)
        path = vulnerability_relative_path(value["path"], f"{context} path")
        item = evidence_by_path.get(path)
        if (
            not isinstance(value["sha256"], str)
            or not HEX_SHA256.fullmatch(value["sha256"])
            or not isinstance(value["size"], int)
            or isinstance(value["size"], bool)
            or value["size"] < 0
            or item is None
            or item["role"] != role
            or item["target"] != target
            or item["sha256"] != value["sha256"]
            or item["size"] != value["size"]
        ):
            raise ReleaseError(f"{context} is not vulnerability-inventory-bound")
        return value

    scanner = manifest["scanner"]
    if not isinstance(scanner, dict):
        raise ReleaseError("vulnerability manifest scanner must be an object")
    require_exact_keys(
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
        "vulnerability manifest scanner",
    )
    install_item = evidence_by_path.get(scanner["install_receipt_path"])
    binary_item = next(
        (
            item
            for item in evidence_inventory
            if item["role"] == "scanner-binary" and item["target"] == "scanner"
        ),
        None,
    )
    if (
        scanner["name"] != receipt["scanner"]["name"]
        or scanner["version"] != receipt["scanner"]["version"]
        or scanner["binary_sha256"] != receipt["scanner"]["binary_sha256"]
        or not isinstance(scanner["binary_size"], int)
        or isinstance(scanner["binary_size"], bool)
        or scanner["binary_size"] <= 0
        or scanner["install_receipt_path"] != "trivy-install-receipt.json"
        or scanner["install_receipt_sha256"]
        != receipt["scanner"]["scanner_install_receipt_sha256"]
        or install_item is None
        or install_item["role"] != "scanner-install"
        or install_item["target"] != "scanner"
        or install_item["sha256"] != scanner["install_receipt_sha256"]
        or binary_item is None
        or binary_item["sha256"] != scanner["binary_sha256"]
        or binary_item["size"] != scanner["binary_size"]
    ):
        raise ReleaseError("vulnerability manifest scanner evidence is invalid")
    configuration = scanner["configuration"]
    if not isinstance(configuration, dict):
        raise ReleaseError("vulnerability manifest scanner configuration must be an object")
    require_exact_keys(
        configuration, {"config", "ignorefile"}, "vulnerability manifest configuration"
    )
    for name, role, digest_field in (
        ("config", "scanner-config", "config_sha256"),
        ("ignorefile", "scanner-ignorefile", "ignorefile_sha256"),
    ):
        record = manifest_file_record(
            configuration[name], role, "scanner", f"vulnerability scanner {name}"
        )
        if record["sha256"] != receipt["scanner"][digest_field]:
            raise ReleaseError("vulnerability scanner configuration digest differs")
    databases = scanner["databases"]
    if not isinstance(databases, dict):
        raise ReleaseError("vulnerability manifest databases must be an object")
    require_exact_keys(
        databases, {"java", "vulnerability"}, "vulnerability manifest databases"
    )
    database_contracts = {
        "vulnerability": {
            "target": "vulnerability-database",
            "repository": "ghcr.io/aquasecurity/trivy-db",
            "tag": "2",
            "schema_version": 2,
            "layout_path": "trivy-db-oci",
        },
        "java": {
            "target": "java-database",
            "repository": "ghcr.io/aquasecurity/trivy-java-db",
            "tag": "1",
            "schema_version": 1,
            "layout_path": "trivy-java-db-oci",
        },
    }
    for database_name, contract in database_contracts.items():
        database = databases[database_name]
        if not isinstance(database, dict):
            raise ReleaseError("vulnerability manifest database must be an object")
        require_exact_keys(
            database,
            {"database", "metadata", "oci", "repository", "schema_version", "tag"},
            f"vulnerability manifest {database_name} database",
        )
        database_record = manifest_file_record(
            database["database"],
            "database-file",
            contract["target"],
            f"vulnerability manifest {database_name} database file",
        )
        metadata_record = manifest_file_record(
            database["metadata"],
            "database-metadata",
            contract["target"],
            f"vulnerability manifest {database_name} database metadata",
        )
        if (
            database["repository"] != contract["repository"]
            or database["tag"] != contract["tag"]
            or database["schema_version"] != contract["schema_version"]
            or database_record["sha256"]
            != receipt["scanner"][f"{database_name}_database_sha256"]
            or metadata_record["sha256"]
            != receipt["scanner"][f"{database_name}_database_metadata_sha256"]
        ):
            raise ReleaseError("vulnerability manifest database authority is invalid")
        oci = database["oci"]
        if not isinstance(oci, dict):
            raise ReleaseError("vulnerability manifest database OCI evidence must be an object")
        require_exact_keys(
            oci, {"digest", "files", "layout_path"}, "vulnerability manifest database OCI"
        )
        files = oci["files"]
        expected_roles = ["layout", "index", "manifest", "config", "layer"]
        if (
            oci["digest"]
            != receipt["scanner"][f"{database_name}_database_oci_digest"]
            or oci["layout_path"] != contract["layout_path"]
            or not isinstance(files, list)
            or [item.get("role") for item in files if isinstance(item, dict)]
            != expected_roles
        ):
            raise ReleaseError("vulnerability manifest database OCI closure is invalid")
        for file_record, oci_role in zip(files, expected_roles, strict=True):
            if not isinstance(file_record, dict):
                raise ReleaseError("vulnerability manifest OCI file must be an object")
            require_exact_keys(
                file_record,
                {"path", "role", "sha256", "size"},
                "vulnerability manifest OCI file",
            )
            projected = {
                key: file_record[key] for key in ("path", "sha256", "size")
            }
            manifest_file_record(
                projected,
                f"database-oci-{oci_role}",
                contract["target"],
                f"vulnerability manifest OCI {oci_role}",
            )
    targets = manifest["targets"]
    if not isinstance(targets, list) or len(targets) != 6:
        raise ReleaseError("vulnerability manifest target matrix is incomplete")
    expected_names = [
        "connector-darwin-amd64-pkg",
        "connector-darwin-arm64-pkg",
        "connector-linux-amd64-deb",
        "connector-linux-amd64-rpm",
        "connector-linux-arm64-deb",
        "connector-linux-arm64-rpm",
    ]
    if [target.get("name") for target in targets if isinstance(target, dict)] != expected_names:
        raise ReleaseError("vulnerability manifest targets are not canonically ordered")
    core_by_name = {item["filename"]: item for item in core_inventory}
    root = validate_vulnerability_core_roots(receipt["core_roots"])[0]
    root_item = evidence_by_path.get(root["path"])
    root_bundle_item = evidence_by_path.get(root["signature_bundle_path"])
    core_root = core_by_name.get(PurePosixPath(root["path"]).name)
    core_root_bundle = core_by_name.get(
        PurePosixPath(root["signature_bundle_path"]).name
    )
    if (
        root_item is None
        or root_item["role"] != "release-root"
        or root_item["target"] != root["id"]
        or root_item["sha256"] != root["sha256"]
        or root_item["size"] != root["size"]
        or root_bundle_item is None
        or root_bundle_item["role"] != "release-root-signature"
        or root_bundle_item["target"] != root["id"]
        or root_bundle_item["sha256"] != root["signature_bundle_sha256"]
        or root_bundle_item["size"] != root["signature_bundle_size"]
        or core_root is None
        or core_root["sha256"] != root["sha256"]
        or core_root["size"] != root["size"]
        or core_root_bundle is None
        or core_root_bundle["sha256"] != root["signature_bundle_sha256"]
        or core_root_bundle["size"] != root["signature_bundle_size"]
    ):
        raise ReleaseError("vulnerability manifest signed Connector root is not core-bound")
    root_parent = PurePosixPath(root["path"]).parent

    def root_sibling(filename: str) -> str:
        path = root_parent / filename
        return filename if root_parent == PurePosixPath(".") else path.as_posix()

    package_by_target = {
        f"connector-{package['target_id']}-{package['package_format']}": package
        for package in packages
    }
    for target in targets:
        if not isinstance(target, dict):
            raise ReleaseError("vulnerability manifest target must be an object")
        require_exact_keys(
            target,
            {
                "name",
                "kind",
                "identity",
                "root_id",
                "report_path",
                "report_sha256",
                "scan_execution_path",
                "scan_execution_sha256",
                "artifact",
                "sbom",
            },
            "vulnerability manifest file target",
        )
        package = package_by_target.get(target["name"])
        if package is None:
            raise ReleaseError("vulnerability manifest names an unknown package")
        formal_sbom = core_by_name.get(f"{package['filename']}.spdx.json")
        if formal_sbom is None:
            raise ReleaseError("vulnerability manifest package lacks a core SBOM")
        artifact = target["artifact"]
        sbom = target["sbom"]
        if not isinstance(artifact, dict) or not isinstance(sbom, dict):
            raise ReleaseError("vulnerability manifest package evidence must be objects")
        require_exact_keys(
            artifact,
            {"filename", "sha256", "size", "delivery"},
            "vulnerability manifest package artifact",
        )
        require_exact_keys(
            sbom,
            {"path", "sha256", "size", "format", "scan_subject_name"},
            "vulnerability manifest package SBOM",
        )
        delivery = artifact["delivery"]
        if not isinstance(delivery, dict):
            raise ReleaseError("vulnerability manifest package delivery must be an object")
        require_exact_keys(
            delivery, {"kind", "parts"}, "vulnerability manifest package delivery"
        )
        parts = delivery["parts"]
        if delivery["kind"] != "single" or not isinstance(parts, list) or len(parts) != 1:
            raise ReleaseError("Connector vulnerability package delivery must be single-file")
        part = parts[0]
        if not isinstance(part, dict):
            raise ReleaseError("Connector vulnerability package part must be an object")
        require_exact_keys(
            part,
            {"path", "sha256", "size", "index", "count"},
            "Connector vulnerability package part",
        )
        expected_artifact_path = root_sibling(package["filename"])
        expected_sbom_path = root_sibling(f"{package['filename']}.spdx.json")
        expected_scan_subject = f"{target['name']}.{formal_sbom['sha256']}.spdx.json"
        report_item = evidence_by_path.get(target["report_path"])
        execution_item = evidence_by_path.get(target["scan_execution_path"])
        artifact_item = evidence_by_path.get(part["path"])
        sbom_item = evidence_by_path.get(sbom["path"])
        if (
            target["kind"] != "file"
            or target["root_id"] != root["id"]
            or target["identity"] != f"sha256:{package['sha256']}"
            or artifact["filename"] != package["filename"]
            or artifact["sha256"] != package["sha256"]
            or artifact["size"] != package["size"]
            or part
            != {
                "path": expected_artifact_path,
                "sha256": package["sha256"],
                "size": package["size"],
                "index": 1,
                "count": 1,
            }
            or sbom["path"] != expected_sbom_path
            or sbom["sha256"] != formal_sbom["sha256"]
            or sbom["size"] != formal_sbom["size"]
            or sbom["format"] != "SPDX-2.3-json"
            or sbom["scan_subject_name"] != expected_scan_subject
            or sbom["path"] == sbom["scan_subject_name"]
            or target["report_path"] != f"vulnerability-{target['name']}.json"
            or target["report_sha256"] != receipt["report_sha256"][target["name"]]
            or target["scan_execution_path"]
            != f"scan-execution-{target['name']}.json"
            or not isinstance(target["scan_execution_sha256"], str)
            or not HEX_SHA256.fullmatch(target["scan_execution_sha256"])
            or artifact_item is None
            or artifact_item["role"] != "artifact"
            or artifact_item["target"] != target["name"]
            or artifact_item["sha256"] != package["sha256"]
            or artifact_item["size"] != package["size"]
            or sbom_item is None
            or sbom_item["role"] != "sbom"
            or sbom_item["target"] != target["name"]
            or sbom_item["sha256"] != formal_sbom["sha256"]
            or sbom_item["size"] != formal_sbom["size"]
            or report_item is None
            or report_item["role"] != "report"
            or report_item["target"] != target["name"]
            or report_item["sha256"] != target["report_sha256"]
            or execution_item is None
            or execution_item["role"] != "scan-execution"
            or execution_item["target"] != target["name"]
            or execution_item["sha256"] != target["scan_execution_sha256"]
        ):
            raise ReleaseError(
                f"vulnerability manifest target is not core-bound: {target['name']}"
            )


def validate_vulnerability_evidence_directory(
    directory: Path, expected_names: set[str]
) -> None:
    try:
        resolved = directory.resolve(strict=True)
    except OSError as exc:
        raise ReleaseError(f"cannot inspect vulnerability evidence directory: {exc}") from exc
    if not resolved.is_dir() or resolved != directory.absolute():
        raise ReleaseError("vulnerability evidence directory must be real and non-symlinked")
    expected_files = {
        vulnerability_relative_path(name, "expected vulnerability evidence path")
        for name in expected_names
    }
    expected_directories: set[str] = set()
    for name in expected_files:
        parent = PurePosixPath(name).parent
        while parent != PurePosixPath("."):
            expected_directories.add(parent.as_posix())
            parent = parent.parent
    actual_files: set[str] = set()
    actual_directories: set[str] = set()
    for current, directories, files in os.walk(resolved, topdown=True, followlinks=False):
        current_path = Path(current)
        for directory_name in directories:
            path = current_path / directory_name
            relative = path.relative_to(resolved).as_posix()
            mode = path.lstat().st_mode
            vulnerability_relative_path(relative, "vulnerability evidence directory")
            if not stat.S_ISDIR(mode) or path.is_symlink():
                raise ReleaseError(
                    "vulnerability evidence directory entry is not a real directory: "
                    f"{relative}"
                )
            actual_directories.add(relative)
        for filename in files:
            path = current_path / filename
            relative = path.relative_to(resolved).as_posix()
            mode = path.lstat().st_mode
            vulnerability_relative_path(relative, "vulnerability evidence entry")
            if not stat.S_ISREG(mode) or path.is_symlink():
                raise ReleaseError(
                    "vulnerability evidence entry is not a regular non-symlink file: "
                    f"{relative}"
                )
            actual_files.add(relative)
    if actual_files != expected_files or actual_directories != expected_directories:
        raise ReleaseError(
            "vulnerability evidence has missing or unlisted paths: "
            f"files={sorted(actual_files ^ expected_files)}, "
            f"directories={sorted(actual_directories ^ expected_directories)}"
        )


def empty_real_directory(path: Path, context: str) -> Path:
    directory = release_output_directory(path)
    try:
        entries = list(directory.iterdir())
    except OSError as exc:
        raise ReleaseError(f"cannot inspect {context}: {exc}") from exc
    if entries:
        raise ReleaseError(f"{context} must be empty")
    return directory


def public_release_files(directory: Path) -> set[str]:
    names: set[str] = set()
    try:
        entries = list(directory.iterdir())
    except OSError as exc:
        raise ReleaseError(f"cannot inspect public release directory: {exc}") from exc
    for path in entries:
        try:
            mode = path.lstat().st_mode
        except OSError as exc:
            raise ReleaseError(f"cannot inspect public release asset: {exc}") from exc
        if (
            not stat.S_ISREG(mode)
            or path.is_symlink()
            or not SAFE_NAME.fullmatch(path.name)
        ):
            raise ReleaseError("public release directory contains a non-asset entry")
        names.add(path.name)
    return names


def copy_verified_vulnerability_file(
    source: Path,
    destination: Path,
    item: dict[str, Any],
    output_directory: Path,
) -> None:
    source = regular_external_input_file(source, "public vulnerability evidence")
    if source.stat().st_size != item["size"] or sha256_file(source) != item["sha256"]:
        raise ReleaseError(f"public vulnerability evidence hash mismatch: {source.name}")
    try:
        relative = destination.relative_to(output_directory)
    except ValueError as exc:
        raise ReleaseError("vulnerability reconstruction escaped its output") from exc
    current = output_directory
    for component in relative.parts[:-1]:
        current /= component
        try:
            current.mkdir(mode=0o700)
        except FileExistsError:
            pass
        try:
            mode = current.lstat().st_mode
        except OSError as exc:
            raise ReleaseError("cannot inspect vulnerability reconstruction parent") from exc
        if not stat.S_ISDIR(mode) or current.is_symlink():
            raise ReleaseError("vulnerability reconstruction parent is unsafe")
    copy_exclusive_file(source, destination)
    if (
        destination.stat().st_size != item["size"]
        or sha256_file(destination) != item["sha256"]
    ):
        raise ReleaseError("reconstructed vulnerability evidence changed during copy")


def stage_public_vulnerability_assets(args: argparse.Namespace) -> None:
    evidence_directory = release_output_directory(args.evidence_directory)
    output_directory = release_output_directory(args.output_directory)
    receipt_path = regular_input_file(
        args.receipt, VULNERABILITY_RECEIPT, "vulnerability receipt"
    )
    bundle_path = regular_input_file(
        args.receipt_bundle,
        VULNERABILITY_RECEIPT_BUNDLE,
        "vulnerability receipt signature bundle",
    )
    manifest_path = regular_input_file(
        args.manifest, VULNERABILITY_MANIFEST, "vulnerability manifest"
    )
    if any(
        path.parent != evidence_directory
        for path in (receipt_path, bundle_path, manifest_path)
    ):
        raise ReleaseError("public vulnerability inputs must share one evidence directory")
    receipt = read_compact_canonical_json(receipt_path, "vulnerability receipt")
    inventory = validate_vulnerability_receipt(
        receipt,
        manifest_path,
        evidence_directory,
        args.source_commit,
        args.version,
    )
    expected_evidence = {
        *(item["path"] for item in inventory),
        VULNERABILITY_RECEIPT,
        VULNERABILITY_RECEIPT_BUNDLE,
    }
    validate_vulnerability_evidence_directory(evidence_directory, expected_evidence)
    public = vulnerability_public_asset_map(inventory)
    for name, item in sorted(public.items()):
        copy_verified_vulnerability_file(
            vulnerability_file(
                evidence_directory, item["path"], "vulnerability evidence"
            ),
            output_directory / name,
            item,
            output_directory,
        )
    copy_exclusive_file(receipt_path, output_directory / VULNERABILITY_RECEIPT)
    copy_exclusive_file(bundle_path, output_directory / VULNERABILITY_RECEIPT_BUNDLE)
    print("staged the exact 43-file public vulnerability evidence projection")


def reconstruct_public_vulnerability_release(args: argparse.Namespace) -> None:
    public_directory = release_output_directory(args.public_directory)
    core_directory = empty_real_directory(args.core_output_directory, "core output")
    evidence_directory = empty_real_directory(
        args.evidence_output_directory, "vulnerability evidence output"
    )
    receipt_path = regular_input_file(
        public_directory / VULNERABILITY_RECEIPT,
        VULNERABILITY_RECEIPT,
        "public vulnerability receipt",
    )
    bundle_path = regular_input_file(
        public_directory / VULNERABILITY_RECEIPT_BUNDLE,
        VULNERABILITY_RECEIPT_BUNDLE,
        "public vulnerability receipt signature bundle",
    )
    receipt = read_compact_canonical_json(receipt_path, "public vulnerability receipt")
    inventory = validate_vulnerability_receipt(
        receipt,
        None,
        None,
        args.source_commit,
        args.version,
    )
    public = vulnerability_public_asset_map(inventory)
    expected_core = expected_core_asset_names(args.version)
    expected_public = expected_core | set(public) | VULNERABILITY_PUBLIC_FIXED_ASSETS
    if len(expected_public) != 135 or public_release_files(public_directory) != expected_public:
        raise ReleaseError("public release is not the exact 92 + 43 asset union")
    for name in sorted(expected_core):
        copy_exclusive_file(public_directory / name, core_directory / name)
    for item in inventory:
        path = item["path"]
        public_name = (
            PurePosixPath(path).name
            if path.startswith("connector/")
            else vulnerability_public_asset_name(path)
        )
        destination = evidence_directory.joinpath(*PurePosixPath(path).parts)
        copy_verified_vulnerability_file(
            public_directory / public_name,
            destination,
            item,
            evidence_directory,
        )
    copy_exclusive_file(receipt_path, evidence_directory / VULNERABILITY_RECEIPT)
    copy_exclusive_file(bundle_path, evidence_directory / VULNERABILITY_RECEIPT_BUNDLE)
    expected_evidence = {
        *(item["path"] for item in inventory),
        VULNERABILITY_RECEIPT,
        VULNERABILITY_RECEIPT_BUNDLE,
    }
    validate_vulnerability_evidence_directory(evidence_directory, expected_evidence)
    validate_vulnerability_receipt(
        receipt,
        evidence_directory / VULNERABILITY_MANIFEST,
        evidence_directory,
        args.source_commit,
        args.version,
    )
    print("reconstructed the signed 55-file vulnerability evidence closure")


def validate_aggregate_receipt(aggregate: Any) -> dict[str, Any]:
    if not isinstance(aggregate, dict):
        raise ReleaseError("aggregate verification receipt must be an object")
    require_exact_keys(
        aggregate,
        {
            "$schema",
            "format_version",
            "kind",
            "release",
            "evidence",
            "trust",
            "verification_run",
            "public_release",
            "platform_receipts",
            "vulnerability_evidence",
            "verified_targets",
            "verified_packages",
            "core_inventory",
            "vulnerability_inventory",
            "release_inventory",
            "signature_bundle",
        },
        "aggregate verification receipt",
    )
    if (
        aggregate["$schema"]
        != "https://sub2api-codex.invalid/schemas/connector-aggregate-verification-receipt-v1.json"
        or aggregate["format_version"] != 1
        or aggregate["kind"]
        != "sub2api-codex-connector-public-verification-aggregate"
        or aggregate["signature_bundle"] != AGGREGATE_RECEIPT_BUNDLE
    ):
        raise ReleaseError("aggregate verification receipt format is invalid")
    release = aggregate["release"]
    if not isinstance(release, dict):
        raise ReleaseError("aggregate release must be an object")
    require_exact_keys(
        release,
        {
            "source_repository",
            "source_commit",
            "version",
            "tag",
            "codex_version",
            "schema_digest",
            "control_protocol_version",
        },
        "aggregate release",
    )
    if (
        release["source_repository"] != RELEASE_REPOSITORY
        or not isinstance(release["source_commit"], str)
        or not HEX_GIT_COMMIT.fullmatch(release["source_commit"])
        or not isinstance(release["version"], str)
        or not re.fullmatch(r"\d+\.\d+\.\d+", release["version"])
        or release["tag"] != f"connector-v{release['version']}"
        or not isinstance(release["codex_version"], str)
        or not re.fullmatch(r"\d+\.\d+\.\d+", release["codex_version"])
        or release["control_protocol_version"] != 1
        or not isinstance(release["schema_digest"], str)
        or not HEX_SHA256.fullmatch(release["schema_digest"])
    ):
        raise ReleaseError("aggregate release identity is invalid")
    for field, filename, bundle in (
        ("manifest", MANIFEST, f"{MANIFEST}.sigstore.json"),
        (
            "release_metadata",
            CONNECTOR_RELEASE_METADATA,
            f"{CONNECTOR_RELEASE_METADATA}.sigstore.json",
        ),
        ("checksums", CHECKSUMS, f"{CHECKSUMS}.sigstore.json"),
    ):
        validate_receipt_file_evidence(
            aggregate["evidence"].get(field)
            if isinstance(aggregate["evidence"], dict)
            else None,
            f"aggregate {field}",
            expected_filename=filename,
            expected_signature_bundle=bundle,
        )
    if not isinstance(aggregate["evidence"], dict) or set(
        aggregate["evidence"]
    ) != {"manifest", "release_metadata", "checksums"}:
        raise ReleaseError("aggregate evidence keys are invalid")
    trust = aggregate["trust"]
    if not isinstance(trust, dict):
        raise ReleaseError("aggregate trust must be an object")
    require_exact_keys(trust, {"sigstore", "apple", "rpm"}, "aggregate trust")
    expected_identity = (
        f"{RELEASE_REPOSITORY}/.github/workflows/connector-release.yml"
        f"@refs/tags/{release['tag']}"
    )
    if trust["sigstore"] != {
        "certificate_oidc_issuer": OIDC_ISSUER,
        "certificate_identity": expected_identity,
        "certificate_github_workflow_sha": release["source_commit"],
        "certificate_github_workflow_trigger": "push",
    }:
        raise ReleaseError("aggregate Connector Sigstore trust is invalid")
    if not isinstance(trust["apple"], dict) or not isinstance(trust["rpm"], dict):
        raise ReleaseError("aggregate native trust is incomplete")
    require_exact_keys(
        trust["apple"],
        {"team_identifier", "application_identity", "installer_identity"},
        "aggregate Apple trust",
    )
    validate_apple_identity(
        trust["apple"]["team_identifier"], trust["apple"]["application_identity"]
    )
    validate_apple_installer_identity(
        trust["apple"]["team_identifier"], trust["apple"]["installer_identity"]
    )
    require_exact_keys(trust["rpm"], {"signing_fingerprint"}, "aggregate RPM trust")
    validate_rpm_fingerprint(trust["rpm"]["signing_fingerprint"])
    verification_run = aggregate["verification_run"]
    if not isinstance(verification_run, dict):
        raise ReleaseError("aggregate verification run must be an object")
    require_exact_keys(
        verification_run,
        {"repository", "run_id", "run_attempt"},
        "aggregate verification run",
    )
    if (
        verification_run["repository"]
        != RELEASE_REPOSITORY.removeprefix("https://github.com/")
        or not isinstance(verification_run["run_id"], int)
        or isinstance(verification_run["run_id"], bool)
        or verification_run["run_id"] <= 0
        or not isinstance(verification_run["run_attempt"], int)
        or isinstance(verification_run["run_attempt"], bool)
        or verification_run["run_attempt"] <= 0
    ):
        raise ReleaseError("aggregate verification run is invalid")
    if aggregate["verified_targets"] != [
        "linux-amd64",
        "linux-arm64",
        "darwin-amd64",
        "darwin-arm64",
    ]:
        raise ReleaseError("aggregate target matrix is incomplete")
    packages = aggregate["verified_packages"]
    if not isinstance(packages, list) or len(packages) != 6:
        raise ReleaseError("aggregate package matrix is incomplete")
    expected_pairs = [
        ("linux-amd64", "deb"),
        ("linux-amd64", "rpm"),
        ("linux-arm64", "deb"),
        ("linux-arm64", "rpm"),
        ("darwin-amd64", "pkg"),
        ("darwin-arm64", "pkg"),
    ]
    for item, pair in zip(packages, expected_pairs, strict=True):
        if not isinstance(item, dict) or set(item) != {
            "target_id",
            "package_format",
            "filename",
            "sha256",
            "size",
        }:
            raise ReleaseError("aggregate package entry is invalid")
        expected_filename = (
            f"sub2api-codex-connector_{release['version']}_"
            f"{pair[0].replace('-', '_')}.{pair[1]}"
        )
        if (
            (item["target_id"], item["package_format"]) != pair
            or item["filename"] != expected_filename
            or not isinstance(item["sha256"], str)
            or not HEX_SHA256.fullmatch(item["sha256"])
            or not isinstance(item["size"], int)
            or isinstance(item["size"], bool)
            or item["size"] <= 0
        ):
            raise ReleaseError("aggregate package matrix order is invalid")
    core = validate_inventory_records(aggregate["core_inventory"], "aggregate core inventory")
    vulnerability = validate_inventory_records(
        aggregate["vulnerability_inventory"], "aggregate vulnerability inventory"
    )
    release_inventory = validate_inventory_records(
        aggregate["release_inventory"], "aggregate release inventory"
    )
    if set(core) & set(vulnerability) or release_inventory != {
        **core,
        **vulnerability,
    }:
        raise ReleaseError("aggregate public inventory is not the exact classified union")
    if (
        set(core) != expected_core_asset_names(release["version"])
        or len(vulnerability) != 43
        or len(release_inventory) != 135
    ):
        raise ReleaseError("aggregate public inventory is not the fixed release matrix")
    for descriptor in aggregate["evidence"].values():
        file_item = core.get(descriptor["filename"])
        bundle_item = core.get(descriptor["signature_bundle"])
        if (
            file_item is None
            or bundle_item is None
            or file_item["sha256"] != descriptor["sha256"]
            or file_item["size"] != descriptor["size"]
        ):
            raise ReleaseError("aggregate root evidence is absent from core inventory")
    for package in packages:
        inventory_item = core.get(package["filename"])
        if (
            inventory_item is None
            or inventory_item["sha256"] != package["sha256"]
            or inventory_item["size"] != package["size"]
        ):
            raise ReleaseError("aggregate package is absent from core inventory")
    public_release = aggregate["public_release"]
    if not isinstance(public_release, dict):
        raise ReleaseError("aggregate public release must be an object")
    require_exact_keys(
        public_release,
        {
            "release_id",
            "workflow_run_id",
            "workflow_run_attempt",
            "draft",
            "prerelease",
            "immutable",
            "published_at",
            "descriptor",
        },
        "aggregate public release",
    )
    if (
        not isinstance(public_release["release_id"], int)
        or isinstance(public_release["release_id"], bool)
        or public_release["release_id"] <= 0
        or public_release["workflow_run_id"] != verification_run["run_id"]
        or public_release["workflow_run_attempt"]
        != verification_run["run_attempt"]
        or public_release["draft"] is not False
        or public_release["prerelease"] is not False
        or public_release["immutable"] is not True
    ):
        raise ReleaseError("aggregate public release is not immutable")
    parse_rfc3339(public_release["published_at"], "aggregate published_at")
    validate_receipt_file_evidence(
        public_release["descriptor"],
        "aggregate public release descriptor",
        expected_filename=PUBLIC_RELEASE_DESCRIPTOR,
        expected_signature_bundle=None,
    )
    platform_receipts = aggregate["platform_receipts"]
    if not isinstance(platform_receipts, dict):
        raise ReleaseError("aggregate platform receipts must be an object")
    require_exact_keys(platform_receipts, {"linux", "darwin"}, "aggregate platform receipts")
    for platform_name in ("linux", "darwin"):
        validate_receipt_file_evidence(
            platform_receipts[platform_name],
            f"aggregate {platform_name} receipt",
            expected_filename=PLATFORM_RECEIPTS[platform_name],
            expected_signature_bundle=None,
        )
    vulnerability_evidence = aggregate["vulnerability_evidence"]
    if not isinstance(vulnerability_evidence, dict):
        raise ReleaseError("aggregate vulnerability evidence must be an object")
    require_exact_keys(
        vulnerability_evidence,
        {
            "profile",
            "verified_at",
            "receipt",
            "manifest",
            "sigstore",
            "core_roots",
            "scanner",
            "report_sha256",
            "scanned_package_counts",
            "evidence_inventory",
        },
        "aggregate vulnerability evidence",
    )
    if vulnerability_evidence["profile"] != "connector-release":
        raise ReleaseError("aggregate vulnerability profile is invalid")
    parse_rfc3339(
        vulnerability_evidence["verified_at"], "aggregate vulnerability verified_at"
    )
    vulnerability_roots = validate_vulnerability_core_roots(
        vulnerability_evidence["core_roots"]
    )
    vulnerability_scanner = validate_vulnerability_scanner(
        vulnerability_evidence["scanner"]
    )
    expected_vulnerability_targets = {
        f"connector-{package['target_id']}-{package['package_format']}"
        for package in packages
    }
    vulnerability_reports = vulnerability_evidence["report_sha256"]
    vulnerability_package_counts = vulnerability_evidence["scanned_package_counts"]
    if (
        not isinstance(vulnerability_reports, dict)
        or set(vulnerability_reports) != expected_vulnerability_targets
        or any(
            not isinstance(value, str) or not HEX_SHA256.fullmatch(value)
            for value in vulnerability_reports.values()
        )
        or not isinstance(vulnerability_package_counts, dict)
        or set(vulnerability_package_counts) != expected_vulnerability_targets
        or any(
            not isinstance(value, int) or isinstance(value, bool) or value <= 0
            for value in vulnerability_package_counts.values()
        )
    ):
        raise ReleaseError("aggregate vulnerability scan matrix is incomplete")
    validate_receipt_file_evidence(
        vulnerability_evidence["receipt"],
        "aggregate vulnerability receipt",
        expected_filename=VULNERABILITY_RECEIPT,
        expected_signature_bundle=VULNERABILITY_RECEIPT_BUNDLE,
    )
    validate_receipt_file_evidence(
        vulnerability_evidence["manifest"],
        "aggregate vulnerability manifest",
        expected_filename=VULNERABILITY_MANIFEST,
        expected_signature_bundle=None,
    )
    sigstore = vulnerability_evidence["sigstore"]
    if not isinstance(sigstore, dict):
        raise ReleaseError("aggregate vulnerability Sigstore trust must be an object")
    require_exact_keys(
        sigstore,
        {
            "certificate_oidc_issuer",
            "certificate_identity",
            "certificate_github_workflow_sha",
            "certificate_github_workflow_trigger",
        },
        "aggregate vulnerability Sigstore trust",
    )
    if (
        sigstore["certificate_oidc_issuer"] != OIDC_ISSUER
        or sigstore["certificate_identity"] != expected_identity
        or sigstore["certificate_github_workflow_sha"] != release["source_commit"]
        or sigstore["certificate_github_workflow_trigger"] != "push"
    ):
        raise ReleaseError("aggregate vulnerability Sigstore trust is invalid")
    evidence_inventory = vulnerability_evidence["evidence_inventory"]
    if not isinstance(evidence_inventory, list):
        raise ReleaseError("aggregate vulnerability evidence inventory is invalid")
    evidence_by_path = {
        item["path"]: item for item in evidence_inventory if isinstance(item, dict)
    }
    manifest_descriptor = vulnerability_evidence["manifest"]
    receipt_descriptor = vulnerability_evidence["receipt"]
    disposition_item = next(
        (
            item
            for item in evidence_inventory
            if isinstance(item, dict)
            and item.get("role") == "dispositions"
            and item.get("target") == "release"
        ),
        None,
    )
    if disposition_item is None:
        raise ReleaseError("aggregate vulnerability dispositions are missing")
    projected_receipt = {
        "core_roots": vulnerability_roots,
        "scanner": vulnerability_scanner,
        "manifest_sha256": manifest_descriptor["sha256"],
        "dispositions_sha256": disposition_item["sha256"],
        "report_sha256": vulnerability_reports,
        "evidence_inventory": evidence_inventory,
    }
    validate_vulnerability_inventory(projected_receipt, release["version"])
    public_mapping = vulnerability_public_asset_map(evidence_inventory)
    if set(vulnerability) != set(public_mapping) | VULNERABILITY_PUBLIC_FIXED_ASSETS:
        raise ReleaseError("aggregate vulnerability public projection is not exact")
    manifest_public = vulnerability.get(vulnerability_public_asset_name(VULNERABILITY_MANIFEST))
    receipt_public = vulnerability.get(VULNERABILITY_RECEIPT)
    receipt_bundle_public = vulnerability.get(VULNERABILITY_RECEIPT_BUNDLE)
    if (
        manifest_public is None
        or receipt_public is None
        or receipt_bundle_public is None
        or manifest_public["sha256"] != manifest_descriptor["sha256"]
        or manifest_public["size"] != manifest_descriptor["size"]
        or receipt_public["sha256"] != receipt_descriptor["sha256"]
        or receipt_public["size"] != receipt_descriptor["size"]
        or receipt_descriptor["signature_bundle"]
        != VULNERABILITY_RECEIPT_BUNDLE
    ):
        raise ReleaseError("aggregate vulnerability roots are not public inventory assets")
    manifest_inventory = evidence_by_path.get(VULNERABILITY_MANIFEST)
    if (
        manifest_inventory is None
        or manifest_inventory["role"] != "manifest"
        or manifest_inventory["target"] != "release"
        or manifest_inventory["sha256"] != manifest_descriptor["sha256"]
        or manifest_inventory["size"] != manifest_descriptor["size"]
    ):
        raise ReleaseError("aggregate vulnerability manifest is not inventory-bound")
    vulnerability_root = vulnerability_roots[0]
    root_inventory = evidence_by_path.get(vulnerability_root["path"])
    root_bundle_inventory = evidence_by_path.get(
        vulnerability_root["signature_bundle_path"]
    )
    root_public = core.get(PurePosixPath(vulnerability_root["path"]).name)
    root_bundle_public = core.get(
        PurePosixPath(vulnerability_root["signature_bundle_path"]).name
    )
    if (
        root_inventory is None
        or root_inventory["role"] != "release-root"
        or root_inventory["target"] != vulnerability_root["id"]
        or root_inventory["sha256"] != vulnerability_root["sha256"]
        or root_inventory["size"] != vulnerability_root["size"]
        or root_bundle_inventory is None
        or root_bundle_inventory["role"] != "release-root-signature"
        or root_bundle_inventory["target"] != vulnerability_root["id"]
        or root_bundle_inventory["sha256"]
        != vulnerability_root["signature_bundle_sha256"]
        or root_bundle_inventory["size"]
        != vulnerability_root["signature_bundle_size"]
        or root_public is None
        or root_public["sha256"] != vulnerability_root["sha256"]
        or root_public["size"] != vulnerability_root["size"]
        or root_bundle_public is None
        or root_bundle_public["sha256"]
        != vulnerability_root["signature_bundle_sha256"]
        or root_bundle_public["size"]
        != vulnerability_root["signature_bundle_size"]
    ):
        raise ReleaseError("aggregate signed Connector root is not core-bound")
    for public_name, evidence_item in public_mapping.items():
        public_item = vulnerability.get(public_name)
        if (
            public_item is None
            or evidence_item["sha256"] != public_item["sha256"]
            or evidence_item["size"] != public_item["size"]
        ):
            raise ReleaseError("aggregate public vulnerability evidence is not inventory-bound")
    for package in packages:
        target_name = f"connector-{package['target_id']}-{package['package_format']}"
        root_parent = PurePosixPath(vulnerability_root["path"]).parent
        artifact_path = root_parent / package["filename"]
        sbom_path = root_parent / f"{package['filename']}.spdx.json"
        if root_parent == PurePosixPath("."):
            artifact_path = PurePosixPath(package["filename"])
            sbom_path = PurePosixPath(f"{package['filename']}.spdx.json")
        artifact_item = evidence_by_path.get(artifact_path.as_posix())
        formal_sbom = core.get(f"{package['filename']}.spdx.json")
        if formal_sbom is None:
            raise ReleaseError("aggregate core inventory lacks a package SBOM")
        sbom_item = evidence_by_path.get(sbom_path.as_posix())
        report_item = evidence_by_path.get(f"vulnerability-{target_name}.json")
        report_public_name = vulnerability_public_asset_name(
            f"vulnerability-{target_name}.json"
        )
        if (
            artifact_item is None
            or artifact_item["role"] != "artifact"
            or artifact_item["target"] != target_name
            or artifact_item["sha256"] != package["sha256"]
            or artifact_item["size"] != package["size"]
            or sbom_item is None
            or sbom_item["role"] != "sbom"
            or sbom_item["target"] != target_name
            or sbom_item["sha256"] != formal_sbom["sha256"]
            or sbom_item["size"] != formal_sbom["size"]
            or report_item is None
            or report_item["role"] != "report"
            or report_item["target"] != target_name
            or report_item["sha256"] != vulnerability_reports[target_name]
            or report_public_name not in vulnerability
        ):
            raise ReleaseError("aggregate vulnerability package evidence is incomplete")
        public_report = vulnerability[report_public_name]
        if (
            public_report["sha256"] != report_item["sha256"]
            or public_report["size"] != report_item["size"]
        ):
            raise ReleaseError("aggregate vulnerability report differs from public asset")
    return aggregate


def aggregate_verification_receipts(args: argparse.Namespace) -> None:
    config = load_config(args.config)
    require_cosign_version(args.cosign, config)
    linux_path = regular_input_file(
        args.linux_receipt, PLATFORM_RECEIPTS["linux"], "Linux verification receipt"
    )
    darwin_path = regular_input_file(
        args.darwin_receipt, PLATFORM_RECEIPTS["darwin"], "Darwin verification receipt"
    )
    descriptor_path = regular_input_file(
        args.public_release_descriptor,
        PUBLIC_RELEASE_DESCRIPTOR,
        "public release descriptor",
    )
    linux = validate_platform_receipt(
        read_canonical_json(linux_path, "Linux verification receipt"), "linux"
    )
    darwin = validate_platform_receipt(
        read_canonical_json(darwin_path, "Darwin verification receipt"), "darwin"
    )
    if (
        linux["release"] != darwin["release"]
        or linux["evidence"] != darwin["evidence"]
        or linux["trust"]["sigstore"] != darwin["trust"]["sigstore"]
        or linux["verification_run"] != darwin["verification_run"]
        or linux["core_inventory"] != darwin["core_inventory"]
    ):
        raise ReleaseError("platform verification receipts do not describe the same release")
    descriptor = validate_public_release_descriptor(
        read_canonical_json(descriptor_path, "public release descriptor")
    )
    release = linux["release"]
    if (
        descriptor["source_repository"] != release["source_repository"]
        or descriptor["source_commit"] != release["source_commit"]
        or descriptor["version"] != release["version"]
        or descriptor["tag"] != release["tag"]
        or descriptor["workflow_run_id"]
        != linux["verification_run"]["run_id"]
        or descriptor["workflow_run_attempt"]
        != linux["verification_run"]["run_attempt"]
    ):
        raise ReleaseError("public release descriptor does not match platform receipts")
    core_public_inventory = public_assets_as_inventory(descriptor["core_assets"])
    if core_public_inventory != linux["core_inventory"]:
        raise ReleaseError("public core assets do not match verified core inventory")

    evidence_directory = args.vulnerability_evidence_directory.absolute()
    vulnerability_receipt_path = regular_input_file(
        args.vulnerability_receipt,
        VULNERABILITY_RECEIPT,
        "vulnerability receipt",
    )
    vulnerability_bundle_path = regular_input_file(
        args.vulnerability_receipt_bundle,
        VULNERABILITY_RECEIPT_BUNDLE,
        "vulnerability receipt bundle",
    )
    vulnerability_manifest_path = regular_input_file(
        args.vulnerability_manifest,
        VULNERABILITY_MANIFEST,
        "vulnerability manifest",
    )
    if any(
        path.parent != evidence_directory
        for path in (
            vulnerability_receipt_path,
            vulnerability_bundle_path,
            vulnerability_manifest_path,
        )
    ):
        raise ReleaseError("vulnerability inputs must be in the exact evidence directory")
    vulnerability_manifest = read_canonical_json(
        vulnerability_manifest_path, "vulnerability manifest"
    )
    if (
        not isinstance(vulnerability_manifest, dict)
        or vulnerability_manifest.get("format_version") != 1
        or vulnerability_manifest.get("profile") != "connector-release"
        or vulnerability_manifest.get("source_commit") != release["source_commit"]
    ):
        raise ReleaseError("vulnerability manifest does not match the Connector release")
    vulnerability_receipt = read_compact_canonical_json(
        vulnerability_receipt_path, "vulnerability receipt"
    )
    vulnerability_inventory = validate_vulnerability_receipt(
        vulnerability_receipt,
        vulnerability_manifest_path,
        evidence_directory,
        release["source_commit"],
        release["version"],
    )
    expected_vulnerability_identity = (
        f"{RELEASE_REPOSITORY}/.github/workflows/connector-release.yml"
        f"@refs/tags/{release['tag']}"
    )
    if (
        args.vulnerability_certificate_oidc_issuer != OIDC_ISSUER
        or args.vulnerability_certificate_identity != expected_vulnerability_identity
        or args.vulnerability_certificate_github_workflow_sha
        != release["source_commit"]
        or args.vulnerability_certificate_github_workflow_trigger != "push"
    ):
        raise ReleaseError("vulnerability receipt external Sigstore policy is invalid")
    verify_blob(
        args.cosign,
        evidence_directory,
        vulnerability_receipt_path.name,
        vulnerability_bundle_path.name,
        args.vulnerability_certificate_oidc_issuer,
        args.vulnerability_certificate_identity,
        args.vulnerability_certificate_github_workflow_sha,
        args.vulnerability_certificate_github_workflow_trigger,
    )
    vulnerability_expected_names = {
        *(item["path"] for item in vulnerability_inventory),
        VULNERABILITY_RECEIPT,
        VULNERABILITY_RECEIPT_BUNDLE,
    }
    validate_vulnerability_evidence_directory(
        evidence_directory, vulnerability_expected_names
    )
    platform_packages = [
        *linux["verified_packages"],
        *darwin["verified_packages"],
    ]
    validate_vulnerability_manifest_bindings(
        vulnerability_manifest,
        vulnerability_receipt,
        vulnerability_inventory,
        linux["core_inventory"],
        platform_packages,
    )
    vulnerability_by_path = {
        item["path"]: item for item in vulnerability_inventory
    }
    core_by_name = {item["filename"]: item for item in linux["core_inventory"]}
    vulnerability_root = validate_vulnerability_core_roots(
        vulnerability_receipt["core_roots"]
    )[0]
    core_bound_paths = {
        vulnerability_root["path"],
        vulnerability_root["signature_bundle_path"],
    }
    root_parent = PurePosixPath(vulnerability_root["path"]).parent
    for package in platform_packages:
        artifact_path = root_parent / package["filename"]
        sbom_name = f"{package['filename']}.spdx.json"
        sbom_path = root_parent / sbom_name
        if root_parent == PurePosixPath("."):
            artifact_path = PurePosixPath(package["filename"])
            sbom_path = PurePosixPath(sbom_name)
        core_bound_paths.update((artifact_path.as_posix(), sbom_path.as_posix()))
    for path in core_bound_paths:
        vulnerability_item = vulnerability_by_path.get(path)
        core_item = core_by_name.get(PurePosixPath(path).name)
        if (
            vulnerability_item is None
            or core_item is None
            or vulnerability_item["sha256"] != core_item["sha256"]
            or vulnerability_item["size"] != core_item["size"]
        ):
            raise ReleaseError("vulnerability release-root evidence differs from core release")
    if len(core_bound_paths) != 14:
        raise ReleaseError("vulnerability evidence does not bind 14 Connector core paths")
    public_mapping = vulnerability_public_asset_map(vulnerability_inventory)
    vulnerability_public_names = set(public_mapping) | VULNERABILITY_PUBLIC_FIXED_ASSETS
    descriptor_vulnerability_names = {
        item["name"] for item in descriptor["vulnerability_assets"]
    }
    if descriptor_vulnerability_names != vulnerability_public_names:
        raise ReleaseError(
            "public vulnerability assets do not match replayed vulnerability evidence"
        )
    actual_by_name = {
        public_name: {"sha256": item["sha256"], "size": item["size"]}
        for public_name, item in public_mapping.items()
    }
    actual_by_name[VULNERABILITY_RECEIPT] = {
        "sha256": sha256_file(vulnerability_receipt_path),
        "size": vulnerability_receipt_path.stat().st_size,
    }
    actual_by_name[VULNERABILITY_RECEIPT_BUNDLE] = {
        "sha256": sha256_file(vulnerability_bundle_path),
        "size": vulnerability_bundle_path.stat().st_size,
    }
    for asset in descriptor["vulnerability_assets"]:
        actual = actual_by_name.get(asset["name"])
        if (
            actual is None
            or actual["sha256"] != asset["digest"].removeprefix("sha256:")
            or actual["size"] != asset["size"]
        ):
            raise ReleaseError(
                f"public vulnerability asset does not match evidence: {asset['name']}"
            )
    # The aggregate projects only already-authenticated inputs; it never inventories
    # itself or its future signature bundle, so the signed graph remains acyclic.
    aggregate = {
        "$schema": "https://sub2api-codex.invalid/schemas/connector-aggregate-verification-receipt-v1.json",
        "format_version": 1,
        "kind": "sub2api-codex-connector-public-verification-aggregate",
        "release": release,
        "evidence": linux["evidence"],
        "trust": {
            "sigstore": linux["trust"]["sigstore"],
            "apple": darwin["trust"]["apple"],
            "rpm": linux["trust"]["rpm"],
        },
        "verification_run": linux["verification_run"],
        "public_release": {
            "release_id": descriptor["release_id"],
            "workflow_run_id": descriptor["workflow_run_id"],
            "workflow_run_attempt": descriptor["workflow_run_attempt"],
            "draft": descriptor["draft"],
            "prerelease": descriptor["prerelease"],
            "immutable": descriptor["immutable"],
            "published_at": descriptor["published_at"],
            "descriptor": receipt_file_evidence(descriptor_path),
        },
        "platform_receipts": {
            "linux": receipt_file_evidence(linux_path),
            "darwin": receipt_file_evidence(darwin_path),
        },
        "vulnerability_evidence": {
            "profile": vulnerability_receipt["profile"],
            "verified_at": vulnerability_receipt["verified_at"],
            "receipt": receipt_file_evidence(
                vulnerability_receipt_path,
                signature_bundle=VULNERABILITY_RECEIPT_BUNDLE,
            ),
            "manifest": receipt_file_evidence(vulnerability_manifest_path),
            "sigstore": {
                "certificate_oidc_issuer": args.vulnerability_certificate_oidc_issuer,
                "certificate_identity": args.vulnerability_certificate_identity,
                "certificate_github_workflow_sha": args.vulnerability_certificate_github_workflow_sha,
                "certificate_github_workflow_trigger": args.vulnerability_certificate_github_workflow_trigger,
            },
            "core_roots": vulnerability_receipt["core_roots"],
            "scanner": vulnerability_receipt["scanner"],
            "report_sha256": vulnerability_receipt["report_sha256"],
            "scanned_package_counts": vulnerability_receipt[
                "scanned_package_counts"
            ],
            "evidence_inventory": vulnerability_inventory,
        },
        "verified_targets": [
            "linux-amd64",
            "linux-arm64",
            "darwin-amd64",
            "darwin-arm64",
        ],
        "verified_packages": platform_packages,
        "core_inventory": linux["core_inventory"],
        "vulnerability_inventory": public_assets_as_inventory(
            descriptor["vulnerability_assets"]
        ),
        "release_inventory": public_assets_as_inventory(descriptor["assets"]),
        "signature_bundle": AGGREGATE_RECEIPT_BUNDLE,
    }
    validate_aggregate_receipt(aggregate)
    output = args.output.absolute()
    if output.name != AGGREGATE_RECEIPT:
        raise ReleaseError(f"aggregate output must be named {AGGREGATE_RECEIPT}")
    write_exclusive_canonical_json(output, aggregate)
    print(f"aggregated complete immutable Connector release {descriptor['release_id']}")


def verify_aggregate(args: argparse.Namespace) -> None:
    config = load_config(args.config)
    require_cosign_version(args.cosign, config)
    aggregate_path = regular_input_file(
        args.aggregate, AGGREGATE_RECEIPT, "aggregate verification receipt"
    )
    bundle_path = regular_input_file(
        args.bundle, AGGREGATE_RECEIPT_BUNDLE, "aggregate signature bundle"
    )
    if bundle_path.parent != aggregate_path.parent:
        raise ReleaseError("aggregate and signature bundle must be in one directory")
    aggregate = validate_aggregate_receipt(
        read_canonical_json(aggregate_path, "aggregate verification receipt")
    )
    release = aggregate["release"]
    public_release = aggregate["public_release"]
    expected_identity = (
        f"{RELEASE_REPOSITORY}/.github/workflows/connector-release.yml"
        f"@refs/tags/{release['tag']}"
    )
    if (
        args.expected_release_id != public_release["release_id"]
        or args.expected_workflow_run_id != public_release["workflow_run_id"]
        or args.expected_workflow_run_attempt
        != public_release["workflow_run_attempt"]
        or args.expected_tag != release["tag"]
        or args.expected_source_commit != release["source_commit"]
        or args.certificate_oidc_issuer != OIDC_ISSUER
        or args.certificate_identity != expected_identity
        or args.certificate_github_workflow_sha != release["source_commit"]
        or args.certificate_github_workflow_trigger != "push"
    ):
        raise ReleaseError("aggregate verification external release policy mismatch")
    verify_blob(
        args.cosign,
        aggregate_path.parent,
        aggregate_path.name,
        bundle_path.name,
        args.certificate_oidc_issuer,
        args.certificate_identity,
        args.certificate_github_workflow_sha,
        args.certificate_github_workflow_trigger,
    )
    print(
        f"verified complete immutable Connector release {public_release['release_id']} aggregate"
    )


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description=__doc__)
    root.set_defaults(func=None)
    sub = root.add_subparsers(dest="command")

    common_config = argparse.ArgumentParser(add_help=False)
    common_config.add_argument("--config", type=Path, default=DEFAULT_CONFIG)

    prepare_parser = sub.add_parser(
        "prepare", parents=[common_config], help="build every artifact twice"
    )
    prepare_parser.add_argument("--output", type=Path, required=True)
    prepare_parser.add_argument(
        "--mode", choices=("release", "local-unsigned"), required=True
    )
    prepare_parser.add_argument("--go", default="go")
    prepare_parser.add_argument("--source-commit", default="")
    prepare_parser.add_argument("--source-repository", default="")
    prepare_parser.add_argument("--builder-id", default="")
    prepare_parser.add_argument("--invocation-id", default="")
    prepare_parser.add_argument("--source-date-epoch", type=int, default=0)
    prepare_parser.add_argument("--target", dest="targets", action="append")
    prepare_parser.add_argument(
        "--skip-tests",
        action="store_true",
        help="local test optimization; forbidden for release",
    )
    prepare_parser.set_defaults(func=prepare)

    state_parser = sub.add_parser(
        "validate-work-state",
        parents=[common_config],
        help="validate an unsigned release transfer before native signing",
    )
    state_parser.add_argument("--output", type=Path, required=True)
    state_parser.add_argument("--go", default="go")
    state_parser.set_defaults(func=validate_work_state_command)

    finalize_parser = sub.add_parser(
        "finalize", parents=[common_config], help="write SBOM, provenance, and manifest"
    )
    finalize_parser.add_argument("--output", type=Path, required=True)
    finalize_parser.add_argument("--go", default="go")
    finalize_parser.set_defaults(func=finalize)

    native_parser = sub.add_parser(
        "record-native-evidence", help="canonicalize Apple executable evidence"
    )
    native_parser.add_argument("--output", type=Path, required=True)
    native_parser.add_argument("--target", required=True)
    native_parser.add_argument("--codesign-report", type=Path, required=True)
    native_parser.add_argument("--expected-team-id", required=True)
    native_parser.add_argument("--expected-signing-identity", required=True)
    native_parser.set_defaults(func=record_native_evidence)

    package_native_parser = sub.add_parser(
        "record-native-package-evidence",
        help="canonicalize verified RPM or macOS installer evidence",
    )
    package_native_parser.add_argument("--output", type=Path, required=True)
    package_native_parser.add_argument("--target", required=True)
    package_native_parser.add_argument(
        "--package-format", choices=("rpm", "pkg"), required=True
    )
    package_native_parser.add_argument("--candidate-package", type=Path)
    package_native_parser.add_argument("--installer-report", type=Path)
    package_native_parser.add_argument("--notary-json", type=Path)
    package_native_parser.add_argument("--stapler-report", type=Path)
    package_native_parser.add_argument("--gatekeeper-report", type=Path)
    package_native_parser.add_argument("--expected-team-id")
    package_native_parser.add_argument("--expected-application-identity")
    package_native_parser.add_argument("--expected-installer-identity")
    package_native_parser.add_argument("--rpm-public-key", type=Path)
    package_native_parser.add_argument("--rpm-report", type=Path)
    package_native_parser.add_argument("--expected-rpm-fingerprint")
    package_native_parser.set_defaults(func=record_native_package_evidence)

    sign_parser = sub.add_parser(
        "sign", parents=[common_config], help="create keyless Sigstore bundles"
    )
    sign_parser.add_argument("--output", type=Path, required=True)
    sign_parser.add_argument("--cosign", default="cosign")
    sign_parser.add_argument("--apple-team-id")
    sign_parser.add_argument("--apple-signing-identity")
    sign_parser.add_argument("--apple-installer-identity")
    sign_parser.add_argument("--rpm-signing-fingerprint")
    sign_parser.set_defaults(func=sign)

    verify_parser = sub.add_parser(
        "verify", parents=[common_config], help="fail-closed release verification"
    )
    verify_parser.add_argument("--output", type=Path, required=True)
    verify_parser.add_argument("--cosign", default="cosign")
    verify_parser.add_argument("--certificate-oidc-issuer")
    verify_parser.add_argument("--certificate-identity")
    verify_parser.add_argument("--certificate-github-workflow-sha")
    verify_parser.add_argument("--certificate-github-workflow-trigger")
    verify_parser.add_argument("--apple-team-id")
    verify_parser.add_argument("--apple-signing-identity")
    verify_parser.add_argument("--apple-installer-identity")
    verify_parser.add_argument("--rpm-signing-fingerprint")
    verify_parser.add_argument("--target", dest="targets", action="append")
    verify_parser.add_argument("--verification-receipt", type=Path)
    verify_parser.add_argument("--github-run-id", type=int)
    verify_parser.add_argument("--github-run-attempt", type=int)
    verify_parser.add_argument("--allow-local-unsigned", action="store_true")
    verify_parser.set_defaults(func=verify)

    descriptor_parser = sub.add_parser(
        "create-public-release-descriptor",
        help="canonicalize the official immutable GitHub release API response",
    )
    descriptor_parser.add_argument(
        "--github-release-response", type=Path, required=True
    )
    descriptor_parser.add_argument("--vulnerability-receipt", type=Path, required=True)
    descriptor_parser.add_argument("--source-commit", required=True)
    descriptor_parser.add_argument("--github-run-id", type=int, required=True)
    descriptor_parser.add_argument("--github-run-attempt", type=int, required=True)
    descriptor_parser.add_argument("--output", type=Path, required=True)
    descriptor_parser.set_defaults(func=create_public_release_descriptor)

    public_vulnerability_parser = sub.add_parser(
        "stage-public-vulnerability-assets",
        help="flatten the signed vulnerability evidence for GitHub Release",
    )
    public_vulnerability_parser.add_argument(
        "--evidence-directory", type=Path, required=True
    )
    public_vulnerability_parser.add_argument("--receipt", type=Path, required=True)
    public_vulnerability_parser.add_argument(
        "--receipt-bundle", type=Path, required=True
    )
    public_vulnerability_parser.add_argument("--manifest", type=Path, required=True)
    public_vulnerability_parser.add_argument("--source-commit", required=True)
    public_vulnerability_parser.add_argument("--version", required=True)
    public_vulnerability_parser.add_argument(
        "--output-directory", type=Path, required=True
    )
    public_vulnerability_parser.set_defaults(func=stage_public_vulnerability_assets)

    reconstruct_vulnerability_parser = sub.add_parser(
        "reconstruct-public-vulnerability-release",
        help="rebuild signed vulnerability paths from flat public assets",
    )
    reconstruct_vulnerability_parser.add_argument(
        "--public-directory", type=Path, required=True
    )
    reconstruct_vulnerability_parser.add_argument(
        "--core-output-directory", type=Path, required=True
    )
    reconstruct_vulnerability_parser.add_argument(
        "--evidence-output-directory", type=Path, required=True
    )
    reconstruct_vulnerability_parser.add_argument("--source-commit", required=True)
    reconstruct_vulnerability_parser.add_argument("--version", required=True)
    reconstruct_vulnerability_parser.set_defaults(
        func=reconstruct_public_vulnerability_release
    )

    aggregate_parser = sub.add_parser(
        "aggregate-verification-receipts",
        parents=[common_config],
        help="aggregate public platform and vulnerability verification evidence",
    )
    aggregate_parser.add_argument("--linux-receipt", type=Path, required=True)
    aggregate_parser.add_argument("--darwin-receipt", type=Path, required=True)
    aggregate_parser.add_argument(
        "--public-release-descriptor", type=Path, required=True
    )
    aggregate_parser.add_argument(
        "--vulnerability-evidence-directory", type=Path, required=True
    )
    aggregate_parser.add_argument(
        "--vulnerability-receipt", type=Path, required=True
    )
    aggregate_parser.add_argument(
        "--vulnerability-receipt-bundle", type=Path, required=True
    )
    aggregate_parser.add_argument(
        "--vulnerability-manifest", type=Path, required=True
    )
    aggregate_parser.add_argument("--cosign", default="cosign")
    aggregate_parser.add_argument(
        "--vulnerability-certificate-oidc-issuer", required=True
    )
    aggregate_parser.add_argument(
        "--vulnerability-certificate-identity", required=True
    )
    aggregate_parser.add_argument(
        "--vulnerability-certificate-github-workflow-sha", required=True
    )
    aggregate_parser.add_argument(
        "--vulnerability-certificate-github-workflow-trigger", required=True
    )
    aggregate_parser.add_argument("--output", type=Path, required=True)
    aggregate_parser.set_defaults(func=aggregate_verification_receipts)

    aggregate_verify_parser = sub.add_parser(
        "verify-aggregate",
        parents=[common_config],
        help="verify the signed complete public Connector release aggregate",
    )
    aggregate_verify_parser.add_argument("--aggregate", type=Path, required=True)
    aggregate_verify_parser.add_argument("--bundle", type=Path, required=True)
    aggregate_verify_parser.add_argument("--cosign", default="cosign")
    aggregate_verify_parser.add_argument("--certificate-oidc-issuer", required=True)
    aggregate_verify_parser.add_argument("--certificate-identity", required=True)
    aggregate_verify_parser.add_argument(
        "--certificate-github-workflow-sha", required=True
    )
    aggregate_verify_parser.add_argument(
        "--certificate-github-workflow-trigger", required=True
    )
    aggregate_verify_parser.add_argument(
        "--expected-release-id", type=int, required=True
    )
    aggregate_verify_parser.add_argument(
        "--expected-workflow-run-id", type=int, required=True
    )
    aggregate_verify_parser.add_argument(
        "--expected-workflow-run-attempt", type=int, required=True
    )
    aggregate_verify_parser.add_argument("--expected-tag", required=True)
    aggregate_verify_parser.add_argument(
        "--expected-source-commit", required=True
    )
    aggregate_verify_parser.set_defaults(func=verify_aggregate)
    return root


def main() -> int:
    args = parser().parse_args()
    if args.func is None:
        parser().print_help(sys.stderr)
        return 2
    if getattr(args, "mode", None) == "release" and getattr(args, "skip_tests", False):
        print("release: --skip-tests is forbidden in release mode", file=sys.stderr)
        return 2
    try:
        args.func(args)
    except ReleaseError as exc:
        print(f"release: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
