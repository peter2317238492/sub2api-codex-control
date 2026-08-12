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
from pathlib import Path
from typing import Any

SCRIPT_PATH = Path(__file__).resolve()
RELEASE_DIR = SCRIPT_PATH.parent
CONNECTOR_DIR = RELEASE_DIR.parent
REPO_ROOT = CONNECTOR_DIR.parent
DEFAULT_CONFIG = RELEASE_DIR / "release-config.json"
WORK_STATE = ".release-work.json"
LOCAL_MARKER = "RELEASE-NOT-FOR-DISTRIBUTION"
MANIFEST = "manifest.json"
CHECKSUMS = "SHA256SUMS"
OIDC_ISSUER = "https://token.actions.githubusercontent.com"
SLSA_PREDICATE = "https://slsa.dev/provenance/v1"
IN_TOTO_STATEMENT = "https://in-toto.io/Statement/v1"
HEX_SHA256 = re.compile(r"^[0-9a-f]{64}$")
HEX_SHA1 = re.compile(r"^[0-9a-f]{40}$")
HEX_GIT_COMMIT = re.compile(r"^[0-9a-f]{40}$")
SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
APPLE_TEAM_ID = re.compile(r"^[A-Z0-9]{10}$")
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
        json.dumps(value, sort_keys=True, indent=2, separators=(",", ": ")) + "\n"
    ).encode()


def read_json(path: Path) -> Any:
    try:
        with path.open("r", encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        raise ReleaseError(f"cannot read valid JSON from {path}: {exc}") from exc


def write_json(path: Path, value: Any) -> None:
    path.write_bytes(canonical_json(value))


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
            "notarization",
        },
        "native-signature evidence",
    )
    validate_apple_identity(expected_team_id, expected_signing_identity)
    report = evidence["codesign_report"]
    notary = evidence["notarization"]
    if not isinstance(notary, dict):
        raise ReleaseError(f"invalid notarization evidence for {target_id}")
    require_exact_keys(
        notary,
        {"service", "status", "submission_id", "message"},
        "notarization evidence",
    )
    if (
        evidence["format_version"] != 1
        or evidence["target"] != target_id
        or evidence["artifact"] != artifact_name_value
        or evidence["artifact_sha256"] != artifact_sha256
        or evidence["team_identifier"] != expected_team_id
        or evidence["signing_identity"] != expected_signing_identity
        or not isinstance(report, list)
        or not all(isinstance(line, str) for line in report)
        or f"Authority={expected_signing_identity}" not in report
        or f"TeamIdentifier={expected_team_id}" not in report
        or notary["service"] != "apple-notarytool"
        or notary["status"] != "Accepted"
        or not isinstance(notary["submission_id"], str)
        or not notary["submission_id"]
        or not isinstance(notary["message"], str)
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
            target, {"id", "goos", "goarch", "native_signature"}, "target"
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
    ]
    selected: list[Path] = []
    for root in roots:
        if root.is_file():
            selected.append(root)
            continue
        for path in root.rglob("*"):
            if not path.is_file() or ".release-work" in path.parts:
                continue
            if path.suffix in {
                ".go",
                ".json",
                ".py",
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
    output = args.output.resolve()
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
        records.append(
            {
                "target": target,
                "filename": filename,
                "unsigned_sha256": first_hash,
                "unsigned_size": final.stat().st_size,
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
    output = args.output.resolve()
    state = read_json(output / WORK_STATE)
    if state.get("release_mode") != "release":
        raise ReleaseError("native signing evidence is accepted only for release mode")
    record = target_record(state, args.target)
    if record["target"]["goos"] != "darwin":
        raise ReleaseError("native signing evidence applies only to Darwin targets")
    artifact = safe_file(output, record["filename"], "Darwin artifact")
    validate_apple_identity(args.expected_team_id, args.expected_signing_identity)
    notary = read_json(args.notary_json)
    if (
        not isinstance(notary, dict)
        or notary.get("status") != "Accepted"
        or not notary.get("id")
    ):
        raise ReleaseError(
            "Apple notarization did not return Accepted with a submission id"
        )
    report = args.codesign_report.read_text(encoding="utf-8")
    report_lines = report.splitlines()
    fresh_report_lines = verify_codesign_identity(
        artifact,
        args.expected_team_id,
        args.expected_signing_identity,
    ).splitlines()
    if (
        f"Authority={args.expected_signing_identity}" not in report_lines
        or f"TeamIdentifier={args.expected_team_id}" not in report_lines
        or f"Authority={args.expected_signing_identity}" not in fresh_report_lines
        or f"TeamIdentifier={args.expected_team_id}" not in fresh_report_lines
    ):
        raise ReleaseError(
            "codesign report does not match the externally pinned Apple identity"
        )
    evidence = {
        "format_version": 1,
        "target": record["target"]["id"],
        "artifact": record["filename"],
        "artifact_sha256": sha256_file(artifact),
        "signing_identity": args.expected_signing_identity,
        "team_identifier": args.expected_team_id,
        "codesign_report": fresh_report_lines,
        "notarization": {
            "service": "apple-notarytool",
            "status": "Accepted",
            "submission_id": str(notary["id"]),
            "message": str(notary.get("message", "")),
        },
    }
    evidence_name = f"native-{record['target']['id']}.json"
    write_json(output / evidence_name, evidence)
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
    for module in modules:
        if module["kind"] != "dep":
            continue
        module_id = (
            f"SPDXRef-Package-{spdx_id(module['path'])}-{spdx_id(module['version'])}"
        )
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
                    "referenceLocator": f"pkg:golang/{module['path']}@{module['version']}",
                }
            ]
        packages.append(package)
        relationships.append(
            {
                "spdxElementId": package_id,
                "relationshipType": "DEPENDS_ON",
                "relatedSpdxElement": module_id,
            }
        )
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
                    "target": record["target"],
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
            {"target", "filename", "unsigned_sha256", "unsigned_size"},
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
        artifact = safe_file(output, record["filename"], "release work artifact")
        if require_unsigned_artifacts and (
            artifact.stat().st_size != record["unsigned_size"]
            or sha256_file(artifact) != record["unsigned_sha256"]
        ):
            raise ReleaseError(
                f"unsigned artifact changed after reproducibility check: {target_id}"
            )


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
    output = args.output.resolve()
    config = load_config(args.config)
    state = read_json(output / WORK_STATE)
    validate_work_state(output, state, config, require_unsigned_artifacts=True)
    if state["release_mode"] != "release":
        raise ReleaseError(
            "transferred work-state validation is restricted to release mode"
        )
    validate_release_context(state, config, args.go)
    print(f"validated unsigned release transfer for {len(state['targets'])} targets")


def finalize(args: argparse.Namespace) -> None:
    output = args.output.resolve()
    state = read_json(output / WORK_STATE)
    config = load_config(args.config)
    validate_work_state(output, state, config, require_unsigned_artifacts=False)
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
        artifact = safe_file(output, record["filename"], "artifact")
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
        write_json(sbom_path, make_sbom(state, record, artifact, final_sha, modules))
        write_json(
            provenance_path,
            make_provenance(state, record, artifact, final_sha, modules),
        )
        content_names.extend([artifact.name, sbom_name, provenance_name])
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
            }
        )
    marker: str | None = None
    if mode == "local-unsigned":
        marker = LOCAL_MARKER
        (output / marker).write_text(
            "LOCAL UNSIGNED DETERMINISM FIXTURE. NOT A RELEASE. DO NOT DISTRIBUTE OR INSTALL.\n",
            encoding="utf-8",
        )
        content_names.append(marker)
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
        "targets": manifest_targets,
    }
    write_json(output / MANIFEST, manifest)
    content_names.append(MANIFEST)
    checksum_lines = [
        f"{sha256_file(output / name)}  {name}" for name in sorted(content_names)
    ]
    (output / CHECKSUMS).write_text("\n".join(checksum_lines) + "\n", encoding="ascii")
    (output / WORK_STATE).unlink()
    print(f"finalized {mode} release evidence in {output}")


def expected_content_files(manifest: dict[str, Any]) -> list[str]:
    names: list[str] = []
    marker = manifest.get("local_unsigned_marker")
    if marker is not None:
        names.append(marker)
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
    names.append(MANIFEST)
    return sorted(names)


def signing_plan(
    manifest: dict[str, Any],
) -> tuple[list[tuple[str, str]], list[tuple[str, str]]]:
    blobs = [
        (MANIFEST, manifest["signing"]["manifest_bundle"]),
        (CHECKSUMS, manifest["signing"]["checksums_bundle"]),
    ]
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
    return blobs, attestations


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
    output = args.output.resolve()
    config = load_config(args.config)
    manifest = read_json(safe_file(output, MANIFEST, "manifest"))
    validate_manifest_shape(manifest, config)
    if (
        manifest.get("release_mode") != "release"
        or manifest.get("releasable") is not True
    ):
        raise ReleaseError("only finalized release-mode output can be signed")
    if (output / LOCAL_MARKER).exists():
        raise ReleaseError("local unsigned output can never be signed")
    validate_apple_identity(args.apple_team_id, args.apple_signing_identity)
    validate_manifest_release_context(manifest, config)
    validate_finalized_release_for_signing(
        output,
        manifest,
        args.apple_team_id,
        args.apple_signing_identity,
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
        {"id", "os", "arch", "artifact", "sbom", "provenance", "native_signature"},
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


def verify_sbom(
    path: Path, artifact_path: Path, artifact: dict[str, Any], manifest: dict[str, Any]
) -> None:
    sbom = read_json(path)
    if sbom.get("spdxVersion") != "SPDX-2.3" or sbom.get("dataLicense") != "CC0-1.0":
        raise ReleaseError(f"SBOM is not SPDX 2.3 JSON: {path.name}")
    packages = sbom.get("packages")
    files = sbom.get("files")
    if not isinstance(packages, list) or not isinstance(files, list):
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
    if (
        connector is None
        or connector.get("name") != manifest["product"]
        or connector.get("versionInfo") != manifest["connector_version"]
        or connector.get("filesAnalyzed") is not True
        or connector.get("checksums") != expected_checksums
        or connector.get("packageVerificationCode")
        != {"packageVerificationCodeValue": expected_verification_code}
        or connector.get("licenseInfoFromFiles") != ["NOASSERTION"]
        or binary is None
        or binary.get("checksums") != expected_checksums
        or binary.get("licenseInfoInFiles") != ["NOASSERTION"]
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
    expected_apple_signing_identity: str,
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
    for target in manifest["targets"]:
        artifact = target["artifact"]
        artifact_path = safe_file(output, artifact["filename"], "artifact")
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
                or native["signing_identity"] != expected_apple_signing_identity
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
                expected_signing_identity=expected_apple_signing_identity,
            )
            if platform.system() != "Darwin":
                raise ReleaseError(
                    "release signing must validate Darwin artifacts on macOS"
                )
            verify_codesign_identity(
                artifact_path,
                expected_apple_team_id,
                expected_apple_signing_identity,
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
    output = args.output.resolve()
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
        if (
            not args.certificate_oidc_issuer
            or not args.certificate_identity
            or not args.certificate_github_workflow_sha
            or not args.certificate_github_workflow_trigger
            or (requested_requires_apple and not args.apple_team_id)
            or (requested_requires_apple and not args.apple_signing_identity)
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
    manifest = read_json(manifest_path)
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
    selected_ids = set(args.targets or [target["id"] for target in manifest["targets"]])
    available_ids = {target["id"] for target in manifest["targets"]}
    if not selected_ids or not selected_ids.issubset(available_ids):
        raise ReleaseError(
            f"unknown verification targets: {sorted(selected_ids - available_ids)}"
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
    expected_names = expected_content_files(manifest)
    checksum_map = parse_checksums(checksums_path)
    if sorted(checksum_map) != expected_names:
        raise ReleaseError("SHA256SUMS does not exactly cover manifest content files")
    for name in expected_names:
        path = safe_file(output, name, "checksummed file")
        if sha256_file(path) != checksum_map[name]:
            raise ReleaseError(f"SHA256SUMS mismatch: {name}")
    for target in manifest["targets"]:
        artifact = target["artifact"]
        artifact_path = safe_file(output, artifact["filename"], "artifact")
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
    for target in manifest["targets"]:
        if target["id"] not in selected_ids:
            continue
        require_exact_keys(
            target,
            {"id", "os", "arch", "artifact", "sbom", "provenance", "native_signature"},
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
        artifact_path = safe_file(output, artifact_entry["filename"], "artifact")
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
    print(
        f"verified {manifest['release_mode']} Connector evidence for {len(selected_ids)} selected targets"
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
        "record-native-evidence", help="canonicalize accepted Apple evidence"
    )
    native_parser.add_argument("--output", type=Path, required=True)
    native_parser.add_argument("--target", required=True)
    native_parser.add_argument("--notary-json", type=Path, required=True)
    native_parser.add_argument("--codesign-report", type=Path, required=True)
    native_parser.add_argument("--expected-team-id", required=True)
    native_parser.add_argument("--expected-signing-identity", required=True)
    native_parser.set_defaults(func=record_native_evidence)

    sign_parser = sub.add_parser(
        "sign", parents=[common_config], help="create keyless Sigstore bundles"
    )
    sign_parser.add_argument("--output", type=Path, required=True)
    sign_parser.add_argument("--cosign", default="cosign")
    sign_parser.add_argument("--apple-team-id", required=True)
    sign_parser.add_argument("--apple-signing-identity", required=True)
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
    verify_parser.add_argument("--target", dest="targets", action="append")
    verify_parser.add_argument("--allow-local-unsigned", action="store_true")
    verify_parser.set_defaults(func=verify)
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
