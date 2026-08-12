#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ast
import base64
import contextlib
import hashlib
import importlib.util
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import tomllib

REPO_ROOT = Path(__file__).resolve().parents[2]
CONFIG_PATH = Path(__file__).with_name("control-images-config.json")
LOCK_FILENAME = "control-images.lock.json"
BUNDLE_FILENAME = "control-images.lock.sigstore.json"
LOCK_SCHEMA = "https://sub2api-codex.invalid/schemas/control-images-lock-v1.json"
SPDX_PREDICATE_TYPE = "https://spdx.dev/Document"
SLSA_PREDICATE_TYPE = "https://slsa.dev/provenance/v1"
IN_TOTO_STATEMENT_TYPES = {
    "https://in-toto.io/Statement/v0.1",
    "https://in-toto.io/Statement/v1",
}
COMPONENTS = ("control-api", "pwa", "postgres-tools")
VERSION_RE = re.compile(
    r"^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
    r"(?:-[0-9A-Za-z.-]+)?$"
)
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
DIGEST_RE = re.compile(r"^sha256:([0-9a-f]{64})$")
REPOSITORY_RE = re.compile(
    r"^[a-z0-9]+(?:[._-][a-z0-9]+)*(?::[0-9]+)?/"
    r"[a-z0-9]+(?:[._/-][a-z0-9]+)*$"
)
FILENAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
MAX_RELEASE_FILE_BYTES = 128 * 1024 * 1024
MAX_RELEASE_DIRECTORY_BYTES = 512 * 1024 * 1024
SOURCE_BUNDLE_PATH = Path(__file__).with_name("source_bundle.py")
SOURCE_BUNDLE_SPEC = importlib.util.spec_from_file_location(
    "control_release_source_bundle", SOURCE_BUNDLE_PATH
)
if SOURCE_BUNDLE_SPEC is None or SOURCE_BUNDLE_SPEC.loader is None:
    raise RuntimeError("cannot load the source bundle verifier")
source_bundle_tool = importlib.util.module_from_spec(SOURCE_BUNDLE_SPEC)
SOURCE_BUNDLE_SPEC.loader.exec_module(source_bundle_tool)


class ReleaseError(RuntimeError):
    pass


def fail(message: str) -> None:
    raise ReleaseError(message)


def load_config() -> dict[str, Any]:
    return load_json(CONFIG_PATH, "release configuration")


def require_regular_file(path: Path, label: str) -> None:
    try:
        mode = path.lstat().st_mode
    except FileNotFoundError as exc:
        raise ReleaseError(f"missing {label}: {path}") from exc
    if not stat.S_ISREG(mode):
        fail(f"{label} is not a regular non-symlink file: {path}")


def require_directory(path: Path, label: str) -> None:
    try:
        mode = path.lstat().st_mode
    except FileNotFoundError as exc:
        raise ReleaseError(f"missing {label}: {path}") from exc
    if not stat.S_ISDIR(mode):
        fail(f"{label} is not a directory or is a symlink: {path}")


@contextlib.contextmanager
def secure_release_snapshot(source: Path):
    """Copy one stable, owner-controlled release directory through no-follow FDs."""
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        directory_fd = os.open(source, flags)
    except OSError as exc:
        raise ReleaseError(
            f"cannot securely open release directory {source}: {exc}"
        ) from exc
    try:
        directory_metadata = os.fstat(directory_fd)
        if not stat.S_ISDIR(directory_metadata.st_mode):
            fail(f"release directory is not a real directory: {source}")
        if directory_metadata.st_uid != os.geteuid():
            fail("release directory must be owned by the verification user")
        if stat.S_IMODE(directory_metadata.st_mode) & 0o022:
            fail("release directory must not be writable by group or other")

        try:
            names_before = sorted(os.listdir(directory_fd))
        except OSError as exc:
            raise ReleaseError(
                f"cannot list release directory {source}: {exc}"
            ) from exc
        if not names_before:
            fail("release directory is empty")
        if len(names_before) != len(set(names_before)):
            fail("release directory contains duplicate entries")

        with tempfile.TemporaryDirectory(
            prefix="control-release-snapshot."
        ) as temporary:
            snapshot = Path(temporary)
            os.chmod(snapshot, 0o700)
            total_bytes = 0
            for name in names_before:
                validate_filename(name, "release directory entry")
                file_flags = (
                    os.O_RDONLY
                    | getattr(os, "O_CLOEXEC", 0)
                    | getattr(os, "O_NOFOLLOW", 0)
                )
                try:
                    source_fd = os.open(name, file_flags, dir_fd=directory_fd)
                except OSError as exc:
                    raise ReleaseError(
                        f"cannot securely open release file {name}: {exc}"
                    ) from exc
                try:
                    metadata_before = os.fstat(source_fd)
                    if not stat.S_ISREG(metadata_before.st_mode):
                        fail(f"release file is not a regular non-symlink file: {name}")
                    if metadata_before.st_uid != os.geteuid():
                        fail(
                            f"release file must be owned by the verification user: {name}"
                        )
                    if metadata_before.st_nlink != 1:
                        fail(f"release file must have exactly one hard link: {name}")
                    if stat.S_IMODE(metadata_before.st_mode) & 0o022:
                        fail(
                            f"release file must not be writable by group or other: {name}"
                        )
                    if metadata_before.st_size > MAX_RELEASE_FILE_BYTES:
                        fail(f"release file exceeds the 128 MiB limit: {name}")
                    total_bytes += metadata_before.st_size
                    if total_bytes > MAX_RELEASE_DIRECTORY_BYTES:
                        fail("release directory exceeds the 512 MiB limit")

                    destination_fd = os.open(
                        snapshot / name,
                        os.O_WRONLY
                        | os.O_CREAT
                        | os.O_EXCL
                        | getattr(os, "O_CLOEXEC", 0),
                        0o600,
                    )
                    try:
                        while True:
                            chunk = os.read(source_fd, 1024 * 1024)
                            if not chunk:
                                break
                            view = memoryview(chunk)
                            while view:
                                written = os.write(destination_fd, view)
                                if written <= 0:
                                    fail(
                                        f"short write while snapshotting release file: {name}"
                                    )
                                view = view[written:]
                        os.fsync(destination_fd)
                    finally:
                        os.close(destination_fd)

                    metadata_after = os.fstat(source_fd)
                    stable_fields_before = (
                        metadata_before.st_dev,
                        metadata_before.st_ino,
                        metadata_before.st_size,
                        metadata_before.st_mtime_ns,
                        metadata_before.st_ctime_ns,
                    )
                    stable_fields_after = (
                        metadata_after.st_dev,
                        metadata_after.st_ino,
                        metadata_after.st_size,
                        metadata_after.st_mtime_ns,
                        metadata_after.st_ctime_ns,
                    )
                    if stable_fields_before != stable_fields_after:
                        fail(f"release file changed while it was snapshotted: {name}")
                finally:
                    os.close(source_fd)

            try:
                names_after = sorted(os.listdir(directory_fd))
            except OSError as exc:
                raise ReleaseError(
                    f"cannot re-list release directory {source}: {exc}"
                ) from exc
            if names_after != names_before:
                fail("release directory inventory changed while it was snapshotted")
            snapshot_fd = os.open(
                snapshot,
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_CLOEXEC", 0),
            )
            try:
                os.fsync(snapshot_fd)
            finally:
                os.close(snapshot_fd)
            yield snapshot
    finally:
        os.close(directory_fd)


def load_json(path: Path, label: str) -> dict[str, Any]:
    require_regular_file(path, label)
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReleaseError(f"invalid {label}: {path}: {exc}") from exc
    if not isinstance(value, dict):
        fail(f"{label} must contain one JSON object: {path}")
    return value


def canonical_json(value: Any) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode("ascii")


def write_atomic(path: Path, content: bytes, mode: int = 0o644) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() or path.is_symlink():
        require_regular_file(path, "output file")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def sha256_file(path: Path) -> str:
    require_regular_file(path, "release evidence")
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def require_exact_keys(value: dict[str, Any], expected: set[str], label: str) -> None:
    actual = set(value)
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        fail(f"{label} keys mismatch; missing={missing}, extra={extra}")


def require_string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        fail(f"{label} must be a non-empty string")
    return value


def validate_repository(value: str, label: str) -> str:
    if not REPOSITORY_RE.fullmatch(value):
        fail(
            f"{label} must be a lowercase OCI repository without a tag or digest: {value!r}"
        )
    return value


def validate_digest(value: str, label: str) -> str:
    if not DIGEST_RE.fullmatch(value):
        fail(f"{label} must be an immutable sha256 digest")
    return value


def validate_commit(value: str, label: str) -> str:
    if not COMMIT_RE.fullmatch(value):
        fail(f"{label} must be a full lowercase 40-character Git commit")
    return value


def validate_version(value: str) -> str:
    if not VERSION_RE.fullmatch(value):
        fail(f"release must be an exact semantic version: {value!r}")
    return value


def validate_filename(value: str, label: str) -> str:
    if not FILENAME_RE.fullmatch(value) or value in {".", ".."}:
        fail(f"{label} must be one safe basename")
    return value


def github_repository_name(source_repository: str) -> str:
    prefix = "https://github.com/"
    if not source_repository.startswith(prefix):
        fail("source repository must be an https://github.com/OWNER/REPOSITORY URL")
    name = source_repository[len(prefix) :]
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", name):
        fail("source repository must contain exactly one GitHub owner/repository pair")
    return name


def expected_workflow_identity(
    source_repository: str, source_ref: str, config: dict[str, Any]
) -> str:
    workflow = require_string(config.get("source_workflow"), "source_workflow")
    return f"{source_repository}/{workflow}@{source_ref}"


def run_checked(
    arguments: Sequence[str], *, cwd: Path = REPO_ROOT
) -> subprocess.CompletedProcess[str]:
    try:
        result = subprocess.run(
            list(arguments),
            cwd=cwd,
            text=True,
            capture_output=True,
            check=False,
        )
    except OSError as exc:
        fail(f"cannot execute {arguments[0]}: {exc}")
    if result.returncode != 0:
        command = " ".join(arguments[:2])
        detail = (
            result.stderr.strip()
            or result.stdout.strip()
            or f"exit {result.returncode}"
        )
        fail(f"{command} failed: {detail}")
    return result


def validate_source(args: argparse.Namespace) -> None:
    config = load_config()
    release = validate_version(args.release)
    expected_ref = f"refs/tags/control-v{release}"
    if args.ref != expected_ref:
        fail(f"release ref must be exactly {expected_ref}")
    commit = validate_commit(args.commit, "source commit")

    package = load_json(REPO_ROOT / "package.json", "root package.json")
    if package.get("version") != release:
        fail("root package version does not match the release tag")
    pwa_package = load_json(REPO_ROOT / "apps/pwa/package.json", "PWA package.json")
    if pwa_package.get("version") != release:
        fail("PWA package version does not match the release tag")
    try:
        api_package = tomllib.loads(
            (REPO_ROOT / "apps/control-api/pyproject.toml").read_text(encoding="utf-8")
        )
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise ReleaseError(f"cannot parse Control API pyproject.toml: {exc}") from exc
    if api_package.get("project", {}).get("version") != release:
        fail("Control API package version does not match the release tag")
    if config.get("release_version") != release:
        fail(
            "control image release configuration version does not match the release tag"
        )

    tag_type = run_checked(["git", "cat-file", "-t", args.ref]).stdout.strip()
    if tag_type != "tag":
        fail("release tags must be annotated Git tag objects")
    peeled = run_checked(["git", "rev-list", "-n", "1", args.ref]).stdout.strip()
    if peeled != commit:
        fail("release tag does not resolve to the externally supplied source commit")
    head = run_checked(["git", "rev-parse", "HEAD"]).stdout.strip()
    if head != commit:
        fail("checked-out HEAD does not equal the release source commit")
    if run_checked(
        ["git", "status", "--porcelain", "--untracked-files=no"]
    ).stdout.strip():
        fail("tracked source tree is dirty")

    components = config.get("components")
    if not isinstance(components, dict) or set(components) != set(COMPONENTS):
        fail("release configuration must define exactly the admitted components")
    for component in COMPONENTS:
        item = components[component]
        if not isinstance(item, dict):
            fail(f"invalid component configuration: {component}")
        dockerfile = REPO_ROOT / require_string(
            item.get("dockerfile"), f"{component} dockerfile"
        )
        require_regular_file(dockerfile, f"{component} Dockerfile")
        text = dockerfile.read_text(encoding="utf-8")
        image_arguments = re.findall(
            r"^ARG\s+[A-Z0-9_]*IMAGE=([^\s]+)$", text, flags=re.MULTILINE
        )
        if not image_arguments:
            fail(f"{component} Dockerfile has no pinned base-image ARG")
        for image in image_arguments:
            if not re.fullmatch(r"[^\s:@]+(?::[^\s@]+)?@sha256:[0-9a-f]{64}", image):
                fail(f"{component} Dockerfile base image is not digest pinned: {image}")
        argument_names = {
            match.group(1): match.group(2)
            for match in re.finditer(
                r"^ARG\s+([A-Z0-9_]*IMAGE)=([^\s]+)$", text, flags=re.MULTILINE
            )
        }
        from_images = re.findall(r"^FROM\s+([^\s]+)", text, flags=re.MULTILINE)
        if not from_images:
            fail(f"{component} Dockerfile has no build stages")
        for image in from_images:
            variable = re.fullmatch(r"\$\{([A-Z0-9_]+)\}", image)
            if variable:
                if variable.group(1) not in argument_names:
                    fail(
                        f"{component} Dockerfile FROM uses an unpinned image ARG: {image}"
                    )
            elif not re.fullmatch(r"[^\s:@]+(?::[^\s@]+)?@sha256:[0-9a-f]{64}", image):
                fail(f"{component} Dockerfile FROM is not digest pinned: {image}")


def migration_head() -> str:
    versions_dir = REPO_ROOT / "migrations/versions"
    revisions: set[str] = set()
    parents: set[str] = set()
    for path in sorted(versions_dir.glob("*.py")):
        require_regular_file(path, "migration revision")
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except (OSError, UnicodeDecodeError, SyntaxError) as exc:
            raise ReleaseError(
                f"cannot parse migration revision {path}: {exc}"
            ) from exc
        values: dict[str, Any] = {}
        for node in tree.body:
            if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
                if node.target.id in {"revision", "down_revision"}:
                    values[node.target.id] = ast.literal_eval(node.value)
            elif isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and target.id in {
                        "revision",
                        "down_revision",
                    }:
                        values[target.id] = ast.literal_eval(node.value)
        revision = values.get("revision")
        down_revision = values.get("down_revision")
        if not isinstance(revision, str) or not re.fullmatch(
            r"[0-9]{8}_[0-9]{4}", revision
        ):
            fail(f"migration has an invalid revision identifier: {path}")
        if down_revision is not None and not isinstance(down_revision, str):
            fail(f"branched migration histories are not admitted: {path}")
        revisions.add(revision)
        if down_revision is not None:
            parents.add(down_revision)
    heads = revisions - parents
    if len(heads) != 1:
        fail(f"release requires exactly one migration head, observed {sorted(heads)}")
    return next(iter(heads))


def release_input_hashes(config: dict[str, Any]) -> dict[str, str]:
    configured = config.get("release_input_files")
    if (
        not isinstance(configured, list)
        or not configured
        or any(not isinstance(item, str) for item in configured)
    ):
        fail("release_input_files must be a non-empty list of repository paths")
    paths = list(configured)
    paths.extend(
        config["components"][component]["dockerfile"] for component in COMPONENTS
    )
    if len(paths) != len(set(paths)):
        fail("release input files contain duplicates")
    result: dict[str, str] = {}
    for relative in paths:
        path = Path(relative)
        if path.is_absolute() or ".." in path.parts:
            fail(f"release input path escapes the repository: {relative}")
        result[relative] = sha256_file(REPO_ROOT / path)
    return result


def dockerfile_materials(
    component: str, config: dict[str, Any]
) -> list[dict[str, Any]]:
    path = REPO_ROOT / config["components"][component]["dockerfile"]
    text = path.read_text(encoding="utf-8")
    images = re.findall(r"^ARG\s+[A-Z0-9_]*IMAGE=([^\s]+)$", text, flags=re.MULTILINE)
    materials: list[dict[str, Any]] = []
    for image in images:
        name, separator, digest = image.rpartition("@sha256:")
        if not separator or not re.fullmatch(r"[0-9a-f]{64}", digest):
            fail(f"{component} base image is not digest pinned: {image}")
        materials.append(
            {"uri": f"docker://{name}@sha256:{digest}", "digest": {"sha256": digest}}
        )
    if not materials:
        fail(f"{component} has no admitted base-image materials")
    return materials


def validate_sbom(value: dict[str, Any], component: str) -> None:
    if not re.fullmatch(
        r"SPDX-2\.[0-9]+", require_string(value.get("spdxVersion"), "SPDX version")
    ):
        fail(f"{component} SBOM is not SPDX 2.x JSON")
    if value.get("SPDXID") != "SPDXRef-DOCUMENT":
        fail(f"{component} SBOM has an invalid document SPDXID")
    require_string(
        value.get("documentNamespace"), f"{component} SBOM document namespace"
    )
    packages = value.get("packages")
    if not isinstance(packages, list) or not packages:
        fail(f"{component} SBOM must describe at least one package")


def provenance_predicate(
    *,
    component: str,
    repository: str,
    digest: str,
    release: str,
    source_repository: str,
    source_commit: str,
    source_ref: str,
    workflow_identity: str,
    invocation_id: str,
    config: dict[str, Any],
) -> dict[str, Any]:
    component_config = config["components"][component]
    return {
        "buildDefinition": {
            "buildType": "https://sub2api-codex.invalid/buildtypes/dockerfile/v1",
            "externalParameters": {
                "component": component,
                "dockerfile": component_config["dockerfile"],
                "image_repository": repository,
                "image_digest": digest,
                "platforms": config["platforms"],
                "release": release,
                "fixed_build_parameters": component_config["fixed_build_parameters"],
            },
            "internalParameters": {},
            "resolvedDependencies": [
                {
                    "uri": f"git+{source_repository}@{source_ref}",
                    "digest": {"gitCommit": source_commit},
                },
                *dockerfile_materials(component, config),
            ],
        },
        "runDetails": {
            "builder": {"id": workflow_identity},
            "metadata": {"invocationId": invocation_id},
        },
    }


def validate_provenance(
    value: dict[str, Any],
    *,
    component: str,
    image: dict[str, Any],
    lock: dict[str, Any],
) -> None:
    config = load_config()
    expected = provenance_predicate(
        component=component,
        repository=image["repository"],
        digest=image["digest"],
        release=lock["release"],
        source_repository=lock["source"]["repository"],
        source_commit=lock["source"]["commit"],
        source_ref=lock["source"]["ref"],
        workflow_identity=lock["builder"]["workflow_identity"],
        invocation_id=lock["builder"]["invocation_id"],
        config=config,
    )
    if value != expected:
        fail(f"{component} SLSA provenance predicate does not match the release inputs")


def command_create_provenance(args: argparse.Namespace) -> None:
    config = load_config()
    if args.component not in COMPONENTS:
        fail("component is not admitted")
    release, source_ref, identity = validate_release_identity_inputs(args, config)
    repository = validate_repository(args.repository, "image repository")
    digest = validate_digest(args.digest, "image digest")
    value = provenance_predicate(
        component=args.component,
        repository=repository,
        digest=digest,
        release=release,
        source_repository=args.source_repository,
        source_commit=args.source_commit,
        source_ref=source_ref,
        workflow_identity=identity,
        invocation_id=args.invocation_id,
        config=config,
    )
    write_atomic(Path(args.output), canonical_json(value))


def validate_release_identity_inputs(
    args: argparse.Namespace, config: dict[str, Any]
) -> tuple[str, str, str]:
    release = validate_version(args.release)
    expected_tag = f"control-v{release}"
    if args.release_tag != expected_tag:
        fail(f"release tag must be exactly {expected_tag}")
    source_ref = f"refs/tags/{args.release_tag}"
    github_repository_name(args.source_repository)
    validate_commit(args.source_commit, "source commit")
    identity = expected_workflow_identity(args.source_repository, source_ref, config)
    if args.workflow_identity != identity:
        fail(
            "workflow identity does not match the exact repository, workflow, and tag ref"
        )
    if args.workflow_sha != args.source_commit:
        fail("workflow SHA must equal the release source commit")
    if args.workflow_trigger != "push":
        fail("release workflow trigger must be push")
    expected_invocation_prefix = f"{args.source_repository}/actions/runs/"
    if not re.fullmatch(
        re.escape(expected_invocation_prefix) + r"[0-9]+/attempts/[0-9]+",
        args.invocation_id,
    ):
        fail("invocation ID must identify a concrete GitHub Actions run attempt")
    return release, source_ref, identity


def evidence_record(path: Path, predicate_type: str) -> dict[str, str]:
    return {
        "filename": validate_filename(path.name, "evidence filename"),
        "sha256": sha256_file(path),
        "predicate_type": predicate_type,
    }


def source_asset_record(path: Path, expected_filename: str) -> dict[str, Any]:
    if path.name != expected_filename:
        fail(f"source asset must be named exactly {expected_filename}")
    require_regular_file(path, f"source asset {expected_filename}")
    metadata = path.stat()
    if metadata.st_nlink != 1 or stat.S_IMODE(metadata.st_mode) & 0o022:
        fail(
            f"source asset is hard-linked or writable by another user: {expected_filename}"
        )
    return {
        "filename": expected_filename,
        "sha256": sha256_file(path),
        "size": metadata.st_size,
    }


def verify_source_bundle(directory: Path, lock: dict[str, Any]) -> dict[str, Any]:
    assets = lock["source_bundle"]
    try:
        return source_bundle_tool.verify_bundle(
            directory.resolve(),
            release=lock["release"],
            repository=lock["source"]["repository"],
            commit=lock["source"]["commit"],
            attestation_sha256=assets["attestation"]["sha256"],
            manifest_sha256=assets["manifest"]["sha256"],
            archive_sha256=assets["archive"]["sha256"],
        )
    except (OSError, source_bundle_tool.SourceBundleError) as exc:
        raise ReleaseError(f"source bundle verification failed: {exc}") from exc


def command_create_lock(args: argparse.Namespace) -> None:
    config = load_config()
    release, source_ref, identity = validate_release_identity_inputs(args, config)
    output_dir = Path(args.output_dir)
    if not output_dir.is_dir():
        fail("release output directory does not exist")

    source_paths = {
        "archive": Path(args.source_archive),
        "manifest": Path(args.source_manifest),
        "attestation": Path(args.source_attestation),
    }
    expected_source_names = {
        "archive": source_bundle_tool.ARCHIVE_FILENAME,
        "manifest": source_bundle_tool.MANIFEST_FILENAME,
        "attestation": source_bundle_tool.ATTESTATION_FILENAME,
    }
    if any(
        path.parent.resolve() != output_dir.resolve() for path in source_paths.values()
    ):
        fail(
            "all source assets must be direct children of the release output directory"
        )
    source_assets = {
        name: source_asset_record(source_paths[name], expected_source_names[name])
        for name in ("archive", "manifest", "attestation")
    }

    images: dict[str, Any] = {}
    for component in COMPONENTS:
        repository = validate_repository(
            getattr(args, f"{component.replace('-', '_')}_repository"),
            f"{component} repository",
        )
        digest = validate_digest(
            getattr(args, f"{component.replace('-', '_')}_digest"),
            f"{component} digest",
        )
        sbom_path = Path(getattr(args, f"{component.replace('-', '_')}_sbom"))
        provenance_path = Path(
            getattr(args, f"{component.replace('-', '_')}_provenance")
        )
        if (
            sbom_path.parent.resolve() != output_dir.resolve()
            or provenance_path.parent.resolve() != output_dir.resolve()
        ):
            fail(
                "all evidence files must be direct children of the release output directory"
            )
        sbom = load_json(sbom_path, f"{component} SBOM")
        validate_sbom(sbom, component)
        image = {
            "repository": repository,
            "digest": digest,
            "reference": f"{repository}@{digest}",
            "platforms": config["platforms"],
            "dockerfile": config["components"][component]["dockerfile"],
            "sbom": evidence_record(sbom_path, SPDX_PREDICATE_TYPE),
            "provenance": evidence_record(provenance_path, SLSA_PREDICATE_TYPE),
        }
        images[component] = image

    lock = {
        "$schema": LOCK_SCHEMA,
        "format_version": 1,
        "release": release,
        "release_tag": args.release_tag,
        "release_inputs": {
            "migration_head": migration_head(),
            "files": release_input_hashes(config),
        },
        "source": {
            "repository": args.source_repository,
            "commit": args.source_commit,
            "ref": source_ref,
        },
        "source_bundle": source_assets,
        "builder": {
            "workflow_identity": identity,
            "workflow_sha": args.workflow_sha,
            "workflow_trigger": args.workflow_trigger,
            "invocation_id": args.invocation_id,
            "cosign_version": config["cosign_version"],
            "syft_version": config["syft_version"],
        },
        "images": images,
    }
    for component in COMPONENTS:
        provenance_path = output_dir / images[component]["provenance"]["filename"]
        provenance = load_json(provenance_path, f"{component} provenance")
        validate_provenance(
            provenance, component=component, image=images[component], lock=lock
        )
    validate_lock(lock)
    verify_source_bundle(output_dir, lock)
    write_atomic(output_dir / LOCK_FILENAME, canonical_json(lock))


def validate_lock(lock: dict[str, Any]) -> None:
    require_exact_keys(
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
        "release lock",
    )
    if lock["$schema"] != LOCK_SCHEMA or lock["format_version"] != 1:
        fail("unsupported release lock schema or format version")
    release = validate_version(require_string(lock["release"], "release"))
    if lock["release_tag"] != f"control-v{release}":
        fail("release lock tag does not match its release version")

    release_inputs = lock["release_inputs"]
    if not isinstance(release_inputs, dict):
        fail("release inputs must be an object")
    require_exact_keys(release_inputs, {"migration_head", "files"}, "release inputs")
    if not re.fullmatch(
        r"[0-9]{8}_[0-9]{4}",
        require_string(release_inputs["migration_head"], "migration head"),
    ):
        fail("release migration head is invalid")
    files = release_inputs["files"]
    config = load_config()
    expected_paths = set(config["release_input_files"])
    expected_paths.update(
        config["components"][component]["dockerfile"] for component in COMPONENTS
    )
    if not isinstance(files, dict) or set(files) != expected_paths:
        fail("release input file inventory differs from the admitted configuration")
    for relative, digest in files.items():
        if Path(relative).is_absolute() or ".." in Path(relative).parts:
            fail(f"release input path escapes the repository: {relative}")
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            fail(f"release input digest is invalid: {relative}")

    source = lock["source"]
    if not isinstance(source, dict):
        fail("release lock source must be an object")
    require_exact_keys(source, {"repository", "commit", "ref"}, "release source")
    source_repository = require_string(source["repository"], "source repository")
    github_repository_name(source_repository)
    source_commit = validate_commit(source["commit"], "source commit")
    if source["ref"] != f"refs/tags/{lock['release_tag']}":
        fail("source ref does not match the release tag")

    source_assets = lock["source_bundle"]
    if not isinstance(source_assets, dict):
        fail("release source bundle must be an object")
    require_exact_keys(
        source_assets, {"archive", "manifest", "attestation"}, "source bundle"
    )
    expected_source_names = {
        "archive": source_bundle_tool.ARCHIVE_FILENAME,
        "manifest": source_bundle_tool.MANIFEST_FILENAME,
        "attestation": source_bundle_tool.ATTESTATION_FILENAME,
    }
    maximum_sizes = {
        "archive": source_bundle_tool.MAX_ARCHIVE_BYTES,
        "manifest": source_bundle_tool.MAX_MANIFEST_BYTES,
        "attestation": source_bundle_tool.MAX_ATTESTATION_BYTES,
    }
    for name in ("archive", "manifest", "attestation"):
        asset = source_assets[name]
        if not isinstance(asset, dict):
            fail(f"source bundle {name} record must be an object")
        require_exact_keys(
            asset, {"filename", "sha256", "size"}, f"source bundle {name}"
        )
        if asset["filename"] != expected_source_names[name]:
            fail(f"source bundle {name} filename is invalid")
        if not isinstance(asset["sha256"], str) or not re.fullmatch(
            r"[0-9a-f]{64}", asset["sha256"]
        ):
            fail(f"source bundle {name} SHA-256 is invalid")
        if (
            type(asset["size"]) is not int
            or not 0 < asset["size"] <= maximum_sizes[name]
        ):
            fail(f"source bundle {name} size is invalid")

    builder = lock["builder"]
    if not isinstance(builder, dict):
        fail("release lock builder must be an object")
    require_exact_keys(
        builder,
        {
            "workflow_identity",
            "workflow_sha",
            "workflow_trigger",
            "invocation_id",
            "cosign_version",
            "syft_version",
        },
        "release builder",
    )
    if builder["workflow_identity"] != expected_workflow_identity(
        source_repository, source["ref"], config
    ):
        fail("release lock workflow identity is not the exact protected tag identity")
    if builder["workflow_sha"] != source_commit:
        fail("release lock workflow SHA differs from the source commit")
    if builder["workflow_trigger"] != "push":
        fail("release lock workflow trigger is not push")
    if builder["cosign_version"] != config["cosign_version"]:
        fail("release lock Cosign version is not admitted")
    if builder["syft_version"] != config["syft_version"]:
        fail("release lock Syft version is not admitted")
    invocation_id = require_string(builder["invocation_id"], "invocation ID")
    invocation_prefix = f"{source_repository}/actions/runs/"
    if not re.fullmatch(
        re.escape(invocation_prefix) + r"[0-9]+/attempts/[0-9]+", invocation_id
    ):
        fail(
            "release lock invocation ID is not one concrete GitHub Actions run attempt"
        )

    images = lock["images"]
    if not isinstance(images, dict) or set(images) != set(COMPONENTS):
        fail("release lock must contain exactly the admitted images")
    for component in COMPONENTS:
        image = images[component]
        if not isinstance(image, dict):
            fail(f"{component} image lock must be an object")
        require_exact_keys(
            image,
            {
                "repository",
                "digest",
                "reference",
                "platforms",
                "dockerfile",
                "sbom",
                "provenance",
            },
            f"{component} image",
        )
        repository = validate_repository(image["repository"], f"{component} repository")
        digest = validate_digest(image["digest"], f"{component} digest")
        if image["reference"] != f"{repository}@{digest}":
            fail(f"{component} reference is not the exact immutable repository digest")
        if image["platforms"] != config["platforms"]:
            fail(f"{component} platforms differ from the admitted release matrix")
        if image["dockerfile"] != config["components"][component]["dockerfile"]:
            fail(
                f"{component} Dockerfile differs from the admitted release configuration"
            )
        for evidence_name, predicate_type in (
            ("sbom", SPDX_PREDICATE_TYPE),
            ("provenance", SLSA_PREDICATE_TYPE),
        ):
            evidence = image[evidence_name]
            if not isinstance(evidence, dict):
                fail(f"{component} {evidence_name} evidence must be an object")
            require_exact_keys(
                evidence,
                {"filename", "sha256", "predicate_type"},
                f"{component} {evidence_name}",
            )
            validate_filename(
                evidence["filename"], f"{component} {evidence_name} filename"
            )
            if not re.fullmatch(r"[0-9a-f]{64}", evidence["sha256"]):
                fail(f"{component} {evidence_name} SHA-256 is invalid")
            if evidence["predicate_type"] != predicate_type:
                fail(f"{component} {evidence_name} predicate type is invalid")


def validate_release_directory(
    release_dir: Path, *, expect_bundle: bool
) -> dict[str, Any]:
    require_directory(release_dir, "release directory")
    require_regular_file(release_dir / LOCK_FILENAME, "release lock")
    lock = load_json(release_dir / LOCK_FILENAME, "release lock")
    validate_lock(lock)
    expected = {LOCK_FILENAME}
    if expect_bundle:
        require_regular_file(
            release_dir / BUNDLE_FILENAME, "release lock Sigstore bundle"
        )
        expected.add(BUNDLE_FILENAME)
    for name in ("archive", "manifest", "attestation"):
        asset = lock["source_bundle"][name]
        path = release_dir / asset["filename"]
        require_regular_file(path, f"source bundle {name}")
        expected.add(asset["filename"])
        metadata = path.stat()
        if metadata.st_size != asset["size"] or sha256_file(path) != asset["sha256"]:
            fail(f"source bundle {name} does not match the signed lock")
    verify_source_bundle(release_dir, lock)
    for component in COMPONENTS:
        image = lock["images"][component]
        for evidence_name in ("sbom", "provenance"):
            evidence = image[evidence_name]
            path = release_dir / evidence["filename"]
            require_regular_file(path, f"{component} {evidence_name}")
            expected.add(evidence["filename"])
            if sha256_file(path) != evidence["sha256"]:
                fail(
                    f"{component} {evidence_name} SHA-256 does not match the signed lock"
                )
        sbom = load_json(release_dir / image["sbom"]["filename"], f"{component} SBOM")
        validate_sbom(sbom, component)
        provenance = load_json(
            release_dir / image["provenance"]["filename"], f"{component} provenance"
        )
        validate_provenance(provenance, component=component, image=image, lock=lock)
    expected_file_count = 4 + (1 if expect_bundle else 0) + (len(COMPONENTS) * 2)
    if len(expected) != expected_file_count:
        fail("release lock reuses or collides evidence filenames")
    actual: set[str] = set()
    for entry in release_dir.iterdir():
        if entry.name.startswith("."):
            fail(f"release directory contains an unlisted hidden entry: {entry.name}")
        require_regular_file(entry, "release file")
        actual.add(entry.name)
    if actual != expected:
        fail(
            f"release directory inventory mismatch; missing={sorted(expected - actual)}, extra={sorted(actual - expected)}"
        )
    return lock


def command_validate_release(args: argparse.Namespace) -> None:
    with secure_release_snapshot(Path(args.release_dir)) as release_dir:
        lock = validate_release_directory(release_dir, expect_bundle=args.expect_bundle)
    config = load_config()
    if lock["release_inputs"]["files"] != release_input_hashes(config):
        fail("release input hashes do not match the exact checked-out source")
    if lock["release_inputs"]["migration_head"] != migration_head():
        fail("release migration head does not match the exact checked-out source")
    print(f"validated unsigned release evidence for {lock['release_tag']}")


def cosign_trust_arguments(args: argparse.Namespace) -> list[str]:
    return [
        "--certificate-oidc-issuer",
        args.certificate_oidc_issuer,
        "--certificate-identity",
        args.certificate_identity,
        "--certificate-github-workflow-sha",
        args.certificate_github_workflow_sha,
        "--certificate-github-workflow-trigger",
        args.certificate_github_workflow_trigger,
        "--certificate-github-workflow-repository",
        args.certificate_github_workflow_repository,
        "--certificate-github-workflow-ref",
        args.certificate_github_workflow_ref,
    ]


def parse_json_output(output: str, label: str) -> list[dict[str, Any]]:
    text = output.strip()
    if not text:
        fail(f"{label} returned no verified JSON claims")
    values: list[Any]
    try:
        decoded = json.loads(text)
        values = decoded if isinstance(decoded, list) else [decoded]
    except json.JSONDecodeError:
        values = []
        for line in text.splitlines():
            if not line.strip():
                continue
            try:
                values.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise ReleaseError(f"{label} returned invalid JSON") from exc
    if not values or any(not isinstance(value, dict) for value in values):
        fail(f"{label} returned no verified JSON objects")
    return values


def decode_attestation_statements(output: str, label: str) -> list[dict[str, Any]]:
    statements: list[dict[str, Any]] = []
    for envelope in parse_json_output(output, label):
        payload = envelope.get("payload")
        if not isinstance(payload, str):
            fail(f"{label} returned an envelope without a payload")
        try:
            decoded = base64.b64decode(payload, validate=True)
            statement = json.loads(decoded)
        except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ReleaseError(f"{label} returned an invalid DSSE payload") from exc
        if not isinstance(statement, dict):
            fail(f"{label} returned a non-object in-toto statement")
        statements.append(statement)
    return statements


def statement_matches(
    statement: dict[str, Any],
    *,
    repository: str,
    digest: str,
    predicate_type: str,
    predicate: dict[str, Any],
) -> bool:
    if statement.get("_type") not in IN_TOTO_STATEMENT_TYPES:
        return False
    if (
        statement.get("predicateType") != predicate_type
        or statement.get("predicate") != predicate
    ):
        return False
    subjects = statement.get("subject")
    if (
        not isinstance(subjects, list)
        or len(subjects) != 1
        or not isinstance(subjects[0], dict)
    ):
        return False
    subject = subjects[0]
    return subject.get("name") == repository and subject.get("digest") == {
        "sha256": digest.removeprefix("sha256:")
    }


def verify_cosign_version(cosign: str, expected_version: str) -> None:
    result = run_checked([cosign, "version"])
    combined = f"{result.stdout}\n{result.stderr}"
    versions = set(re.findall(r"v[0-9]+\.[0-9]+\.[0-9]+", combined))
    if versions != {expected_version}:
        fail(
            f"Cosign version mismatch: expected only {expected_version}, observed {sorted(versions)}"
        )


def validate_external_trust(args: argparse.Namespace, lock: dict[str, Any]) -> None:
    expected_source_commit = validate_commit(
        args.expected_source_commit, "expected source commit"
    )
    expected_tag = require_string(args.expected_release_tag, "expected release tag")
    expected_ref = f"refs/tags/{expected_tag}"
    if lock["source"] != {
        "repository": args.expected_source_repository,
        "commit": expected_source_commit,
        "ref": expected_ref,
    }:
        fail(
            "signed release source does not match the externally supplied source policy"
        )
    if lock["release_tag"] != expected_tag:
        fail("signed release tag does not match external policy")
    if lock["builder"]["workflow_identity"] != args.certificate_identity:
        fail(
            "signed lock workflow identity does not match the external certificate policy"
        )
    if lock["builder"]["workflow_sha"] != args.certificate_github_workflow_sha:
        fail("signed lock workflow SHA does not match the external certificate policy")
    if lock["builder"]["workflow_trigger"] != args.certificate_github_workflow_trigger:
        fail("signed lock trigger does not match the external certificate policy")
    if lock["source"]["ref"] != args.certificate_github_workflow_ref:
        fail("signed lock ref does not match the external certificate policy")
    if (
        github_repository_name(lock["source"]["repository"])
        != args.certificate_github_workflow_repository
    ):
        fail("signed lock repository does not match the external certificate policy")
    for component, expected_repository in (
        ("control-api", args.expected_api_repository),
        ("pwa", args.expected_pwa_repository),
        ("postgres-tools", args.expected_postgres_tools_repository),
    ):
        validate_repository(expected_repository, f"expected {component} repository")
        if lock["images"][component]["repository"] != expected_repository:
            fail(f"signed {component} repository does not match external policy")


def verify_release_snapshot(
    args: argparse.Namespace,
    release_dir: Path,
    *,
    config: dict[str, Any],
    trust: list[str],
) -> dict[str, Any]:
    lock_path = release_dir / LOCK_FILENAME
    bundle_path = release_dir / BUNDLE_FILENAME
    require_regular_file(lock_path, "release lock")
    require_regular_file(bundle_path, "release lock Sigstore bundle")

    # The lock is untrusted until this exact-identity blob verification succeeds.
    run_checked(
        [
            args.cosign,
            "verify-blob",
            "--bundle",
            str(bundle_path),
            *trust,
            str(lock_path),
        ]
    )
    lock = validate_release_directory(release_dir, expect_bundle=True)
    validate_external_trust(args, lock)

    for component in COMPONENTS:
        image = lock["images"][component]
        annotations = [
            "-a",
            f"component={component}",
            "-a",
            f"release_tag={lock['release_tag']}",
            "-a",
            f"source_commit={lock['source']['commit']}",
        ]
        signature = run_checked(
            [args.cosign, "verify", *trust, *annotations, image["reference"]]
        )
        claims = parse_json_output(
            signature.stdout, f"{component} image signature verification"
        )
        matching_signature = False
        for claim in claims:
            critical = claim.get("critical") or claim.get("Critical")
            if not isinstance(critical, dict):
                continue
            image_claim = critical.get("image") or critical.get("Image")
            if not isinstance(image_claim, dict):
                continue
            observed = image_claim.get("docker-manifest-digest") or image_claim.get(
                "Docker-manifest-digest"
            )
            if observed == image["digest"]:
                matching_signature = True
        if not matching_signature:
            fail(f"{component} signature claims do not bind the admitted image digest")

        for evidence_name, cosign_type in (
            ("sbom", "spdxjson"),
            ("provenance", "slsaprovenance1"),
        ):
            evidence = image[evidence_name]
            verified = run_checked(
                [
                    args.cosign,
                    "verify-attestation",
                    "--type",
                    cosign_type,
                    *trust,
                    *annotations,
                    image["reference"],
                ]
            )
            statements = decode_attestation_statements(
                verified.stdout, f"{component} {evidence_name} attestation verification"
            )
            predicate = load_json(
                release_dir / evidence["filename"], f"{component} {evidence_name}"
            )
            if not any(
                statement_matches(
                    statement,
                    repository=image["repository"],
                    digest=image["digest"],
                    predicate_type=evidence["predicate_type"],
                    predicate=predicate,
                )
                for statement in statements
            ):
                fail(
                    f"{component} {evidence_name} attestation does not match the signed release evidence"
                )

    release_inputs = lock["release_inputs"]["files"]
    versions_lock_sha256 = release_inputs.get("versions.lock.json")
    if not isinstance(versions_lock_sha256, str):
        fail("signed release inputs do not contain versions.lock.json")
    auth_contract_paths = sorted(
        path
        for path in release_inputs
        if path.startswith("docs/contracts/sub2api-auth.") and path.endswith(".json")
    )
    if len(auth_contract_paths) != 1:
        fail("signed release inputs must contain exactly one Sub2API auth contract")
    auth_contract_path = auth_contract_paths[0]
    evidence_sha256s = {
        entry.name: sha256_file(entry)
        for entry in sorted(release_dir.iterdir(), key=lambda value: value.name)
    }
    return {
        "CONTROL_API_IMAGE": lock["images"]["control-api"]["reference"],
        "CONTROL_MIGRATION_HEAD": lock["release_inputs"]["migration_head"],
        "CONTROL_POSTGRES_TOOLS_IMAGE": lock["images"]["postgres-tools"]["reference"],
        "CONTROL_PWA_IMAGE": lock["images"]["pwa"]["reference"],
        "CONTROL_RELEASE": lock["release"],
        "CONTROL_RELEASE_BUNDLE_SHA256": evidence_sha256s[BUNDLE_FILENAME],
        "CONTROL_RELEASE_EVIDENCE_SHA256S": evidence_sha256s,
        "CONTROL_RELEASE_INPUT_SHA256S": release_inputs,
        "CONTROL_RELEASE_LOCK_SHA256": evidence_sha256s[LOCK_FILENAME],
        "CONTROL_SOURCE_REPOSITORY": lock["source"]["repository"],
        "CONTROL_SOURCE_ARCHIVE_SHA256": lock["source_bundle"]["archive"]["sha256"],
        "CONTROL_SOURCE_ATTESTATION_SHA256": lock["source_bundle"]["attestation"][
            "sha256"
        ],
        "CONTROL_SOURCE_MANIFEST_SHA256": lock["source_bundle"]["manifest"]["sha256"],
        "CONTROL_SUB2API_AUTH_CONTRACT_PATH": auth_contract_path,
        "CONTROL_SUB2API_AUTH_CONTRACT_SHA256": release_inputs[auth_contract_path],
        "CONTROL_VCS_REF": lock["source"]["commit"],
        "CONTROL_VERSIONS_LOCK_SHA256": versions_lock_sha256,
    }


def command_verify(args: argparse.Namespace) -> None:
    config = load_config()
    trust = cosign_trust_arguments(args)
    with secure_release_snapshot(Path(args.release_dir)) as release_dir:
        verify_cosign_version(args.cosign, config["cosign_version"])
        result = verify_release_snapshot(
            args,
            release_dir,
            config=config,
            trust=trust,
        )
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))


def add_identity_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--release", required=True)
    parser.add_argument("--release-tag", required=True)
    parser.add_argument("--source-repository", required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--workflow-identity", required=True)
    parser.add_argument("--workflow-sha", required=True)
    parser.add_argument("--workflow-trigger", required=True)
    parser.add_argument("--invocation-id", required=True)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Build and verify immutable Control image release evidence"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    source = subparsers.add_parser("validate-source")
    source.add_argument("--release", required=True)
    source.add_argument("--ref", required=True)
    source.add_argument("--commit", required=True)
    source.set_defaults(func=validate_source)

    provenance = subparsers.add_parser("create-provenance")
    add_identity_arguments(provenance)
    provenance.add_argument("--component", choices=COMPONENTS, required=True)
    provenance.add_argument("--repository", required=True)
    provenance.add_argument("--digest", required=True)
    provenance.add_argument("--output", required=True)
    provenance.set_defaults(func=command_create_provenance)

    lock = subparsers.add_parser("create-lock")
    add_identity_arguments(lock)
    lock.add_argument("--output-dir", required=True)
    lock.add_argument("--source-archive", required=True)
    lock.add_argument("--source-manifest", required=True)
    lock.add_argument("--source-attestation", required=True)
    for component in COMPONENTS:
        prefix = component.replace("-", "_")
        lock.add_argument(
            f"--{component}-repository", dest=f"{prefix}_repository", required=True
        )
        lock.add_argument(
            f"--{component}-digest", dest=f"{prefix}_digest", required=True
        )
        lock.add_argument(f"--{component}-sbom", dest=f"{prefix}_sbom", required=True)
        lock.add_argument(
            f"--{component}-provenance", dest=f"{prefix}_provenance", required=True
        )
    lock.set_defaults(func=command_create_lock)

    validate = subparsers.add_parser("validate-release")
    validate.add_argument("--release-dir", required=True)
    validate.add_argument("--expect-bundle", action="store_true")
    validate.set_defaults(func=command_validate_release)

    verify = subparsers.add_parser("verify")
    verify.add_argument("--release-dir", required=True)
    verify.add_argument("--cosign", default="cosign")
    verify.add_argument("--certificate-oidc-issuer", required=True)
    verify.add_argument("--certificate-identity", required=True)
    verify.add_argument("--certificate-github-workflow-sha", required=True)
    verify.add_argument("--certificate-github-workflow-trigger", required=True)
    verify.add_argument("--certificate-github-workflow-repository", required=True)
    verify.add_argument("--certificate-github-workflow-ref", required=True)
    verify.add_argument("--expected-source-repository", required=True)
    verify.add_argument("--expected-source-commit", required=True)
    verify.add_argument("--expected-release-tag", required=True)
    verify.add_argument("--expected-api-repository", required=True)
    verify.add_argument("--expected-pwa-repository", required=True)
    verify.add_argument("--expected-postgres-tools-repository", required=True)
    verify.set_defaults(func=command_verify)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        args.func(args)
    except ReleaseError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
