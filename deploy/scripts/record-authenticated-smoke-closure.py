#!/usr/bin/env python3
"""Append an authenticated-smoke closure to an unsigned bootstrap record."""

from __future__ import annotations

import argparse
import ctypes
import errno
import hashlib
import json
import os
import re
import secrets
import stat
import sys
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, NoReturn
from urllib.parse import urlsplit

SCHEMA_ID = "https://sub2api-codex.invalid/schemas/authenticated-smoke-closure-v2.json"
CHALLENGE_SCHEMA_ID = (
    "https://sub2api-codex.invalid/schemas/authenticated-smoke-challenge-v2.json"
)
CLOSURE_FILENAME = "authenticated-smoke-closure.json"
CHALLENGE_FILENAME = "authenticated-smoke-challenge.json"
SMOKE_EVIDENCE_FILENAME = "authenticated-smoke.log"
REVOCATION_EVIDENCE_FILENAME = "sub2api-session-revocation.log"
EXPECTED_CHECKS = 84
MAX_BOOTSTRAP_RECORD_BYTES = 4 * 1024 * 1024
MAX_EVIDENCE_BYTES = 32 * 1024 * 1024
MAX_SMOKE_LOG_BYTES = 256 * 1024
MAX_CHALLENGE_BYTES = 16 * 1024
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
EVIDENCE_NAME_RE = re.compile(r"^[a-z][a-z0-9_]{0,127}$")
TAP_OK_RE = re.compile(r"^ok ([1-9][0-9]*) - ([^\x00-\x1f\x7f]{1,512})$")
TAP_PLAN_RE = re.compile(
    r"^1\.\.84 # closure-challenge-sha256=([0-9a-f]{64}) "
    r"target-binding-sha256=([0-9a-f]{64})$"
)
DEPLOYMENT_DIRECTORY_RE = re.compile(
    r"^bootstrap-([0-9]{8}T[0-9]{6}Z)-"
    r"([0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})$"
)
NONCE_RE = re.compile(r"^[0-9a-f]{64}$")
IMAGE_ID_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
CONTAINER_ID_RE = re.compile(r"^[0-9a-f]{64}$")
SOURCE_REVISION_RE = re.compile(r"^[0-9a-f]{40,64}$")
TARGET_EVIDENCE_BASENAMES = {
    "compose_plan": "plan.json",
    "local_images": "images.json",
    "running_containers": "running-containers.json",
}
CHALLENGE_MAX_AGE = timedelta(hours=24)
FUTURE_CLOCK_SKEW = timedelta(minutes=5)

# This catalog deliberately pins the no-device production acceptance run. It
# prevents an arbitrary set of 84 successful-looking TAP lines from closing the
# bootstrap acceptance item.
EXPECTED_CHECK_DESCRIPTIONS = (
    "PWA shell is reachable at /codex/",
    "PWA shell is HTML",
    "CSP contains default-src 'none'",
    "CSP contains connect-src 'self'",
    "CSP contains frame-ancestors 'none'",
    "CSP contains script-src 'self'",
    "CSP contains style-src 'self'",
    "CSP contains worker-src 'self'",
    "CSP forbids unsafe script/style execution",
    "nosniff is enabled",
    "framing is denied",
    "referrers are suppressed",
    "HSTS policy is emitted",
    "PWA emits no CORS grant",
    "PWA emits exactly one Content-Security-Policy header",
    "PWA emits exactly one Cross-Origin-Opener-Policy header",
    "PWA emits exactly one Cross-Origin-Resource-Policy header",
    "PWA emits exactly one Permissions-Policy header",
    "PWA emits exactly one Referrer-Policy header",
    "PWA emits exactly one Strict-Transport-Security header",
    "PWA emits exactly one X-Content-Type-Options header",
    "PWA emits exactly one X-Frame-Options header",
    "manifest is reachable",
    "manifest scope is /codex/",
    "manifest start URL is /codex/",
    "manifest has installable PNG icon sizes",
    "service worker is reachable",
    "service worker scope is restricted to /codex/",
    "service worker update is not cached",
    "liveness route is healthy",
    "readiness route is healthy",
    "readiness confirms PostgreSQL, Redis, and every declared contract",
    "API responses are not cached",
    "API emits exactly one Cache-Control header",
    "API emits exactly one Content-Security-Policy header",
    "API emits exactly one Cross-Origin-Opener-Policy header",
    "API emits exactly one Cross-Origin-Resource-Policy header",
    "API emits exactly one Permissions-Policy header",
    "API emits exactly one Pragma header",
    "API emits exactly one Referrer-Policy header",
    "API emits exactly one Strict-Transport-Security header",
    "API emits exactly one X-Content-Type-Options header",
    "API emits exactly one X-Frame-Options header",
    "session data requires authentication",
    "unauthenticated users cannot read devices",
    "unauthenticated users cannot read control bootstrap",
    "unauthenticated users cannot read approvals",
    "unauthenticated users cannot read device models",
    "unauthenticated users cannot read device threads",
    "unauthenticated users cannot read thread detail",
    "unauthenticated users cannot enqueue commands",
    "unauthenticated users cannot decide approvals",
    "cross-origin session exchange is denied",
    "denial does not grant CORS",
    "cross-origin preflight is not accepted",
    "preflight receives no CORS grant",
    "invalid Sub2API access token is rejected",
    "access token is not reflected",
    "unauthenticated browser WebSocket is not upgraded",
    "unauthenticated device WebSocket is not upgraded",
    "unknown WebSocket routes fail closed",
    "internal metrics are not exposed publicly",
    "valid Sub2API token exchanges for a Control session",
    "successful exchange does not reflect access token",
    "Control session cookie is HttpOnly",
    "Control session cookie is SameSite=Strict",
    "Control session cookie is Secure",
    "Control session cookie authenticates a same-origin request",
    "Control session is bound to the Sub2API identity",
    "authenticated same-origin browser WebSocket upgrades",
    "browser WebSocket upgrade header is preserved",
    "exchange issued a CSRF cookie",
    "mutating request without CSRF header is denied",
    "dangerous raw route fails closed: /codex-api/v1/thread/shellCommand",
    "dangerous raw route fails closed: /codex-api/v1/command/exec",
    "dangerous raw route fails closed: /codex-api/v1/fs/read",
    "dangerous raw route fails closed: /codex-api/v1/process/list",
    "dangerous raw route fails closed: /codex-api/v1/config/value/write",
    "dangerous raw route fails closed: /codex-api/v1/plugin/install",
    "dangerous raw route fails closed: /codex-api/v1/account/login",
    "dangerous raw route fails closed: /codex-api/v1/oauth/authorize",
    "dangerous raw route fails closed: /codex-api/v1/raw-rpc",
    "same-origin CSRF-protected logout succeeds",
    "logout revokes the Control session",
)


class ClosureError(RuntimeError):
    """A concise fail-closed validation error."""


def fail(message: str) -> NoReturn:
    raise ClosureError(message)


def canonical_json(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")
    ).encode("ascii")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def metadata_signature(value: os.stat_result) -> tuple[int, ...]:
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


def directory_signature(value: os.stat_result) -> tuple[int, ...]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_uid,
        value.st_gid,
    )


@dataclass
class PrivateInput:
    path: Path | None
    label: str
    descriptor: int
    metadata: os.stat_result
    content: bytes
    parent_descriptor: int | None = None
    basename: str | None = None

    def assert_stable(self) -> None:
        try:
            opened = os.fstat(self.descriptor)
        except OSError:
            fail(f"{self.label} could not be re-inspected")
        expected = metadata_signature(self.metadata)
        if metadata_signature(opened) != expected:
            fail(f"{self.label} changed while the closure was recorded")
        if self.parent_descriptor is not None and self.basename is not None:
            try:
                named = os.stat(
                    self.basename,
                    dir_fd=self.parent_descriptor,
                    follow_symlinks=False,
                )
            except OSError:
                fail(f"{self.label} could not be re-inspected")
            if metadata_signature(named) != expected:
                fail(f"{self.label} changed while the closure was recorded")

    def close(self) -> None:
        try:
            os.close(self.descriptor)
        except OSError:
            pass
        if self.parent_descriptor is not None:
            try:
                os.close(self.parent_descriptor)
            except OSError:
                pass
            self.parent_descriptor = None

    def evidence(self, basename: str) -> dict[str, object]:
        return {
            "basename": basename,
            "sha256": sha256_bytes(self.content),
            "size": len(self.content),
        }


def open_private_input(path: Path, label: str, *, maximum: int) -> PrivateInput:
    path = canonical_absolute_path(path, label)
    parent_descriptor, _ = open_directory_nofollow(path.parent, label)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path.name, flags, dir_fd=parent_descriptor)
    except OSError:
        os.close(parent_descriptor)
        fail(f"{label} cannot be opened without following links")
    try:
        opened = os.fstat(descriptor)
        named = os.stat(path.name, dir_fd=parent_descriptor, follow_symlinks=False)
        if metadata_signature(opened) != metadata_signature(named):
            fail(f"{label} changed while it was opened")
        if not stat.S_ISREG(opened.st_mode):
            fail(f"{label} must be a regular non-symlink file")
        if opened.st_uid != os.geteuid():
            fail(f"{label} must be owned by the closure UID")
        if stat.S_IMODE(opened.st_mode) != 0o600:
            fail(f"{label} mode must be exactly 0600")
        if opened.st_nlink != 1:
            fail(f"{label} must have exactly one filesystem link")
        if opened.st_size <= 0 or opened.st_size > maximum:
            fail(f"{label} has an invalid size")
        chunks: list[bytes] = []
        remaining = maximum + 1
        while remaining:
            block = os.read(descriptor, min(131_072, remaining))
            if not block:
                break
            chunks.append(block)
            remaining -= len(block)
        content = b"".join(chunks)
        if len(content) > maximum:
            fail(f"{label} exceeds its size limit")
        value = PrivateInput(
            path,
            label,
            descriptor,
            opened,
            content,
            parent_descriptor,
            path.name,
        )
        value.assert_stable()
        return value
    except BaseException:
        os.close(descriptor)
        os.close(parent_descriptor)
        raise


def open_private_input_at(
    directory_descriptor: int,
    basename: str,
    label: str,
    *,
    maximum: int,
) -> PrivateInput:
    if (
        not basename
        or basename in {".", ".."}
        or "/" in basename
        or os.path.sep in basename
    ):
        fail(f"{label} basename is not canonical")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    parent_copy = -1
    try:
        descriptor = os.open(basename, flags, dir_fd=directory_descriptor)
    except OSError:
        fail(f"{label} cannot be opened without following links")
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode):
            fail(f"{label} must be a regular file")
        if opened.st_uid != os.geteuid():
            fail(f"{label} must be owned by the closure UID")
        if stat.S_IMODE(opened.st_mode) != 0o600:
            fail(f"{label} mode must be exactly 0600")
        if opened.st_nlink != 1:
            fail(f"{label} must have exactly one filesystem link")
        if opened.st_size <= 0 or opened.st_size > maximum:
            fail(f"{label} has an invalid size")
        chunks: list[bytes] = []
        remaining = maximum + 1
        while remaining:
            block = os.read(descriptor, min(131_072, remaining))
            if not block:
                break
            chunks.append(block)
            remaining -= len(block)
        content = b"".join(chunks)
        if len(content) > maximum:
            fail(f"{label} exceeds its size limit")
        parent_copy = os.dup(directory_descriptor)
        value = PrivateInput(
            None,
            label,
            descriptor,
            opened,
            content,
            parent_copy,
            basename,
        )
        value.assert_stable()
        return value
    except BaseException:
        os.close(descriptor)
        if parent_copy >= 0:
            os.close(parent_copy)
        raise


def strict_json(raw: bytes, label: str) -> Any:
    def reject_duplicate(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                fail(f"{label} contains a duplicate JSON key")
            value[key] = item
        return value

    def reject_constant(_value: str) -> NoReturn:
        fail(f"{label} contains a non-finite JSON number")

    try:
        return json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=reject_duplicate,
            parse_constant=reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError):
        fail(f"{label} is not strict UTF-8 JSON")


def exact_keys(value: Any, expected: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        fail(f"{label} has an unexpected schema")
    return value


def exact_int(value: Any, expected: int, label: str) -> None:
    if not isinstance(value, int) or isinstance(value, bool) or value != expected:
        fail(f"{label} must be exactly {expected}")


def validate_descriptor(value: Any, label: str) -> dict[str, Any]:
    descriptor = exact_keys(value, {"path", "sha256", "size"}, label)
    path = descriptor["path"]
    digest = descriptor["sha256"]
    size = descriptor["size"]
    if not isinstance(path, str) or not Path(path).is_absolute():
        fail(f"{label}.path must be absolute")
    if not isinstance(digest, str) or SHA256_RE.fullmatch(digest) is None:
        fail(f"{label}.sha256 is invalid")
    if not isinstance(size, int) or isinstance(size, bool) or size < 0:
        fail(f"{label}.size is invalid")
    return descriptor


def deployment_identity(deployment_directory: Path) -> tuple[str, str]:
    match = DEPLOYMENT_DIRECTORY_RE.fullmatch(deployment_directory.name)
    if match is None:
        fail("bootstrap deployment directory name is not canonical")
    try:
        deployment_id = str(uuid.UUID(match.group(2), version=4))
    except ValueError:
        fail("bootstrap deployment directory has an invalid deployment ID")
    if deployment_id != match.group(2):
        fail("bootstrap deployment directory has a non-canonical deployment ID")
    return deployment_id, deployment_directory.name


def validate_bootstrap_record(
    value: Any, deployment_directory: Path
) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    record = exact_keys(
        value,
        {
            "format_version",
            "status",
            "trust_mode",
            "recorded_at",
            "signed_release_verified",
            "authenticated_smoke_pending",
            "bootstrap_exceptions",
            "production_backup_admissions",
            "verified_evidence",
            "normal_signed_deployment_required_for_next_release",
        },
        "bootstrap deployment record",
    )
    exact_int(record["format_version"], 1, "bootstrap format_version")
    if record["status"] != "bootstrapped-unsigned":
        fail("bootstrap record is not a successful unsigned bootstrap")
    if record["trust_mode"] != "unsigned-first-deployment-v1":
        fail("bootstrap record has an unexpected trust mode")
    if not isinstance(record["recorded_at"], str) or not record["recorded_at"]:
        fail("bootstrap record has no recorded_at timestamp")
    try:
        recorded_at = datetime.fromisoformat(
            record["recorded_at"].replace("Z", "+00:00")
        )
    except ValueError:
        fail("bootstrap record has an invalid recorded_at timestamp")
    if recorded_at.tzinfo is None or recorded_at.utcoffset() != UTC.utcoffset(
        recorded_at
    ):
        fail("bootstrap record recorded_at must be UTC")
    if record["signed_release_verified"] is not False:
        fail("bootstrap record unexpectedly claims a signed release")
    if record["authenticated_smoke_pending"] is not True:
        fail("bootstrap record has no pending authenticated smoke acceptance item")
    if record["normal_signed_deployment_required_for_next_release"] is not True:
        fail("bootstrap record does not require the normal signed deployment path")
    exceptions = exact_keys(
        record["bootstrap_exceptions"],
        {"sub2api_public_connect", "unauthenticated_smoke", "stale_production_backup"},
        "bootstrap exceptions",
    )
    if any(type(item) is not bool for item in exceptions.values()):
        fail("bootstrap exception flags must be booleans")
    if exceptions["unauthenticated_smoke"] is not True:
        fail("bootstrap record did not use the pending authenticated-smoke exception")
    admissions = exact_keys(
        record["production_backup_admissions"],
        {"initial", "before_migration", "after_bootstrap"},
        "production backup admissions",
    )
    admission_bindings: list[dict[str, Any]] = []
    for name, item in admissions.items():
        admission = exact_keys(
            item,
            {
                "admission_binding_sha256",
                "admission_mode",
                "fresh",
                "manifest_sha256",
                "snapshot_directory",
                "stale_exception",
            },
            f"production backup admission {name}",
        )
        if (
            not isinstance(admission["admission_binding_sha256"], str)
            or SHA256_RE.fullmatch(admission["admission_binding_sha256"]) is None
            or not isinstance(admission["manifest_sha256"], str)
            or SHA256_RE.fullmatch(admission["manifest_sha256"]) is None
        ):
            fail(f"production backup admission {name} contains an invalid digest")
        if (
            not isinstance(admission["snapshot_directory"], str)
            or not Path(admission["snapshot_directory"]).is_absolute()
        ):
            fail(f"production backup admission {name} has an invalid snapshot path")
        if type(admission["fresh"]) is not bool:
            fail(f"production backup admission {name}.fresh must be boolean")
        mode = admission["admission_mode"]
        if mode not in {"fresh-backup-v1", "stale-production-backup-exception-v1"}:
            fail(f"production backup admission {name} has an unexpected mode")
        if mode == "fresh-backup-v1":
            if (
                admission["fresh"] is not True
                or admission["stale_exception"] is not None
            ):
                fail(f"production backup admission {name} has inconsistent freshness")
        elif admission["fresh"] is not False or not isinstance(
            admission["stale_exception"], dict
        ):
            fail(f"production backup admission {name} has inconsistent stale exception")
        admission_bindings.append(admission)
    stable_fields = (
        "admission_binding_sha256",
        "admission_mode",
        "fresh",
        "manifest_sha256",
        "snapshot_directory",
        "stale_exception",
    )
    first = admission_bindings[0]
    if any(
        any(item[field] != first[field] for field in stable_fields)
        for item in admission_bindings[1:]
    ):
        fail("production backup admissions changed across validation stages")
    if exceptions["stale_production_backup"] is not (
        first["admission_mode"] == "stale-production-backup-exception-v1"
    ):
        fail("bootstrap stale-backup exception flag differs from its admissions")

    evidence = record["verified_evidence"]
    if not isinstance(evidence, dict) or not evidence:
        fail("bootstrap record has no verified evidence")
    validated: dict[str, dict[str, Any]] = {}
    paths: set[str] = set()
    for name, item in evidence.items():
        if not isinstance(name, str) or EVIDENCE_NAME_RE.fullmatch(name) is None:
            fail("bootstrap evidence contains an invalid name")
        descriptor = validate_descriptor(item, f"verified_evidence.{name}")
        path = canonical_absolute_path(
            Path(descriptor["path"]), f"verified_evidence.{name}"
        )
        if path.parent != deployment_directory:
            fail(f"verified_evidence.{name} is outside the bootstrap directory")
        if str(path) in paths:
            fail("bootstrap evidence contains duplicate paths")
        paths.add(str(path))
        validated[name] = descriptor
    if "production_smoke" not in validated:
        fail("bootstrap record does not bind its original production smoke")
    return record, validated


def validate_original_evidence(
    descriptors: dict[str, dict[str, Any]],
    bootstrap_basename: str,
    directory_descriptor: int,
) -> list[PrivateInput]:
    opened: list[PrivateInput] = []
    identities: set[tuple[int, int]] = set()
    try:
        for name, descriptor in descriptors.items():
            basename = Path(descriptor["path"]).name
            item = open_private_input_at(
                directory_descriptor,
                basename,
                f"verified evidence {name}",
                maximum=MAX_EVIDENCE_BYTES,
            )
            if basename == bootstrap_basename:
                fail("bootstrap record cannot include itself as verified evidence")
            identity = (item.metadata.st_dev, item.metadata.st_ino)
            if identity in identities:
                fail("bootstrap evidence aliases the same filesystem object")
            identities.add(identity)
            if len(item.content) != descriptor["size"]:
                fail(f"verified evidence {name} size differs from the bootstrap record")
            if sha256_bytes(item.content) != descriptor["sha256"]:
                fail(
                    f"verified evidence {name} SHA-256 differs from the bootstrap record"
                )
            opened.append(item)
        return opened
    except BaseException:
        for item in opened:
            item.close()
        raise


def parse_utc_timestamp(value: object, label: str) -> datetime:
    if not isinstance(value, str) or not value:
        fail(f"{label} is missing")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        fail(f"{label} is invalid")
    if parsed.tzinfo is None or parsed.utcoffset() != UTC.utcoffset(parsed):
        fail(f"{label} must be UTC")
    return parsed


def canonical_public_origin(value: object) -> str:
    if not isinstance(value, str) or not value or not value.isascii():
        fail("bootstrap target public_origin is invalid")
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError:
        fail("bootstrap target public_origin is invalid")
    hostname = parsed.hostname
    if (
        parsed.scheme != "https"
        or hostname is None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path
        or parsed.query
        or parsed.fragment
    ):
        fail("bootstrap target public_origin must be one canonical HTTPS origin")
    canonical_host = f"[{hostname.lower()}]" if ":" in hostname else hostname.lower()
    canonical = f"https://{canonical_host}"
    if port is not None and port != 443:
        canonical += f":{port}"
    if value != canonical:
        fail("bootstrap target public_origin must be canonical")
    return canonical


def target_binding(
    descriptors: dict[str, dict[str, Any]], opened: list[PrivateInput]
) -> dict[str, str]:
    by_name = dict(zip(descriptors, opened, strict=True))
    for name, basename in TARGET_EVIDENCE_BASENAMES.items():
        descriptor = descriptors.get(name)
        item = by_name.get(name)
        if (
            descriptor is None
            or item is None
            or Path(str(descriptor["path"])).name != basename
        ):
            fail(f"bootstrap record lacks fixed {name} target evidence")

    plan = strict_json(by_name["compose_plan"].content, "bootstrap Compose plan")
    images = strict_json(by_name["local_images"].content, "bootstrap image evidence")
    running = strict_json(
        by_name["running_containers"].content, "bootstrap runtime evidence"
    )
    if (
        not isinstance(plan, dict)
        or plan.get("format_version") != 1
        or plan.get("status") != "admitted"
    ):
        fail("bootstrap Compose plan is not admitted target evidence")
    public_origin = canonical_public_origin(plan.get("public_origin"))
    release = plan.get("release")
    source_revision = plan.get("source_revision")
    if (
        not isinstance(release, str)
        or not release
        or any(character.isspace() for character in release)
        or not isinstance(source_revision, str)
        or SOURCE_REVISION_RE.fullmatch(source_revision) is None
    ):
        fail("bootstrap Compose plan has an invalid source identity")
    artifact_identity: dict[str, str] = {}
    for name in ("api", "pwa", "backup"):
        image_id = plan.get(f"{name}_image")
        if not isinstance(image_id, str) or IMAGE_ID_RE.fullmatch(image_id) is None:
            fail("bootstrap Compose plan has an invalid artifact identity")
        artifact_identity[name] = image_id
    if len(set(artifact_identity.values())) != 3:
        fail("bootstrap Compose plan artifact identities are not distinct")

    if (
        not isinstance(images, dict)
        or images.get("format_version") != 1
        or images.get("status") != "admitted"
        or images.get("release") != release
        or images.get("source_revision") != source_revision
    ):
        fail("bootstrap image evidence differs from the admitted target")
    source_identity: dict[str, object] = {
        "release": release,
        "source_revision": source_revision,
        "sources": {},
    }
    sources = source_identity["sources"]
    assert isinstance(sources, dict)
    for name, expected_image_id in artifact_identity.items():
        item = images.get(name)
        if not isinstance(item, dict) or item.get("image_id") != expected_image_id:
            fail("bootstrap image evidence has an invalid artifact binding")
        source = item.get("source")
        if (
            not isinstance(source, str)
            or not source
            or source.strip() != source
            or any(character in source for character in "\r\n\x00")
        ):
            fail("bootstrap image evidence has an invalid source binding")
        sources[name] = source

    if (
        not isinstance(running, dict)
        or running.get("format_version") != 1
        or running.get("status") != "admitted"
    ):
        fail("bootstrap runtime evidence is not admitted")
    containers = running.get("containers")
    expected_runtime_images = {
        "control-api": artifact_identity["api"],
        "control-api-replica": artifact_identity["api"],
        "codex-pwa": artifact_identity["pwa"],
    }
    if not isinstance(containers, dict) or set(containers) != set(
        expected_runtime_images
    ):
        fail("bootstrap runtime evidence has an invalid container set")
    runtime_identity: dict[str, dict[str, str]] = {}
    container_ids: set[str] = set()
    for name, expected_image_id in expected_runtime_images.items():
        item = containers.get(name)
        container_id = item.get("container_id") if isinstance(item, dict) else None
        image_id = item.get("image_id") if isinstance(item, dict) else None
        if (
            not isinstance(container_id, str)
            or CONTAINER_ID_RE.fullmatch(container_id) is None
            or container_id in container_ids
            or image_id != expected_image_id
        ):
            fail("bootstrap runtime evidence has an invalid runtime identity")
        container_ids.add(container_id)
        runtime_identity[name] = {
            "container_id": container_id,
            "image_id": expected_image_id,
        }

    binding_without_digest = {
        "public_origin": public_origin,
        "compose_plan_sha256": descriptors["compose_plan"]["sha256"],
        "artifact_identity_sha256": sha256_bytes(canonical_json(artifact_identity)),
        "runtime_identity_sha256": sha256_bytes(canonical_json(runtime_identity)),
        "source_identity_sha256": sha256_bytes(canonical_json(source_identity)),
        "local_images_sha256": descriptors["local_images"]["sha256"],
        "running_containers_sha256": descriptors["running_containers"]["sha256"],
    }
    return {
        **binding_without_digest,
        "binding_sha256": sha256_bytes(canonical_json(binding_without_digest)),
    }


def parse_smoke_log(
    raw: bytes, challenge_sha256: str, target_binding_sha256: str
) -> dict[str, object]:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        fail("authenticated smoke log is not UTF-8")
    if not text.endswith("\n") or "\r" in text or "\x00" in text:
        fail("authenticated smoke log is not canonical newline-delimited text")
    lines = text[:-1].split("\n")
    if len(lines) != EXPECTED_CHECKS + 1:
        fail(
            "authenticated smoke log does not contain exactly 84 checks and one TAP plan"
        )
    descriptions: list[str] = []
    for expected_number, line in enumerate(lines[:-1], 1):
        match = TAP_OK_RE.fullmatch(line)
        if match is None or int(match.group(1)) != expected_number:
            fail(
                "authenticated smoke TAP checks are failed, duplicated, or out of sequence"
            )
        descriptions.append(match.group(2))
    if tuple(descriptions) != EXPECTED_CHECK_DESCRIPTIONS:
        fail(
            "authenticated smoke TAP check catalog differs from the admitted 84 checks"
        )
    plan = TAP_PLAN_RE.fullmatch(lines[-1])
    if plan is None:
        fail("authenticated smoke TAP plan or closure challenge is absent")
    if plan.group(1) != challenge_sha256:
        fail("authenticated smoke was produced for a different closure challenge")
    if plan.group(2) != target_binding_sha256:
        fail("authenticated smoke was produced for a different target binding")
    catalog_sha256 = sha256_bytes(canonical_json(list(descriptions)))
    return {
        "format": "sub2api-control-authenticated-smoke-tap-plan-v2",
        "status": "passed",
        "checks_expected": EXPECTED_CHECKS,
        "checks_passed": EXPECTED_CHECKS,
        "checks_failed": 0,
        "sequential": True,
        "tap_plan_observed": True,
        "challenge_sha256": challenge_sha256,
        "target_binding_sha256": target_binding_sha256,
        "check_catalog_sha256": catalog_sha256,
    }


def canonical_absolute_path(path: Path | str, label: str) -> Path:
    raw = os.fspath(path)
    if not raw.startswith("/") or raw.startswith("//") or raw != os.path.normpath(raw):
        fail(f"{label} path must be canonical and absolute")
    canonical = Path(raw)
    if any(part in {".", "..", ""} for part in canonical.parts[1:]):
        fail(f"{label} path contains a forbidden component")
    return canonical


def open_directory_nofollow(path: Path, label: str) -> tuple[int, os.stat_result]:
    path = canonical_absolute_path(path, f"{label} parent directory")
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_DIRECTORY", 0)
    )
    descriptor = -1
    try:
        descriptor = os.open("/", flags)
        for component in path.parts[1:]:
            next_descriptor = os.open(component, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
    except OSError:
        if descriptor >= 0:
            os.close(descriptor)
        fail(f"{label} has an inaccessible or symlink ancestor")
    opened = os.fstat(descriptor)
    if not stat.S_ISDIR(opened.st_mode):
        os.close(descriptor)
        fail(f"{label} parent is not a directory")
    return descriptor, opened


def open_private_directory(path: Path) -> tuple[int, os.stat_result]:
    descriptor, opened = open_directory_nofollow(path, "bootstrap deployment directory")
    if opened.st_uid != os.geteuid() or stat.S_IMODE(opened.st_mode) != 0o700:
        os.close(descriptor)
        fail("bootstrap deployment directory must be closure-owned mode 0700")
    return descriptor, opened


def challenge_value(
    *,
    deployment_id: str,
    deployment_basename: str,
    bootstrap_sha256: str,
    nonce: str,
    issued_at: str,
    target: dict[str, str],
) -> dict[str, object]:
    return {
        "$schema": CHALLENGE_SCHEMA_ID,
        "format_version": 2,
        "deployment_id": deployment_id,
        "deployment_basename": deployment_basename,
        "bootstrap_record_sha256": bootstrap_sha256,
        "issued_at": issued_at,
        "nonce": nonce,
        "target": target,
    }


def validate_challenge(
    raw: bytes,
    *,
    deployment_id: str,
    deployment_basename: str,
    bootstrap_sha256: str,
    expected_target: dict[str, str],
    reference_time: datetime | None = None,
) -> dict[str, object]:
    value = exact_keys(
        strict_json(raw, "authenticated smoke challenge"),
        {
            "$schema",
            "format_version",
            "deployment_id",
            "deployment_basename",
            "bootstrap_record_sha256",
            "issued_at",
            "nonce",
            "target",
        },
        "authenticated smoke challenge",
    )
    if value["$schema"] != CHALLENGE_SCHEMA_ID:
        fail("authenticated smoke challenge has an unexpected schema ID")
    exact_int(
        value["format_version"], 2, "authenticated smoke challenge format_version"
    )
    if (
        not isinstance(value["deployment_id"], str)
        or value["deployment_id"] != deployment_id
    ):
        fail("authenticated smoke challenge belongs to a different deployment ID")
    if (
        not isinstance(value["deployment_basename"], str)
        or value["deployment_basename"] != deployment_basename
    ):
        fail(
            "authenticated smoke challenge belongs to a different deployment directory"
        )
    if (
        not isinstance(value["bootstrap_record_sha256"], str)
        or SHA256_RE.fullmatch(value["bootstrap_record_sha256"]) is None
        or value["bootstrap_record_sha256"] != bootstrap_sha256
    ):
        fail("authenticated smoke challenge belongs to a different bootstrap record")
    if (
        not isinstance(value["nonce"], str)
        or NONCE_RE.fullmatch(value["nonce"]) is None
    ):
        fail("authenticated smoke challenge nonce is invalid")
    issued_at = parse_utc_timestamp(
        value["issued_at"], "authenticated smoke challenge issued_at"
    )
    current = reference_time or datetime.now(UTC)
    future_limit = (
        current if reference_time is not None else current + FUTURE_CLOCK_SKEW
    )
    if issued_at > future_limit or current - issued_at > CHALLENGE_MAX_AGE:
        fail("authenticated smoke challenge is outside its freshness window")
    target = value["target"]
    if not isinstance(target, dict) or target != expected_target:
        fail("authenticated smoke challenge belongs to a different target binding")
    return value


def write_all(descriptor: int, content: bytes) -> None:
    offset = 0
    while offset < len(content):
        try:
            written = os.write(descriptor, content[offset:])
        except OSError:
            fail("private append-only record could not be written")
        if written <= 0:
            fail("private append-only record write made no progress")
        offset += written


def atomic_rename_noreplace(
    directory_descriptor: int, source: str, destination: str
) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    if sys.platform.startswith("linux"):
        function = getattr(libc, "renameat2", None)
        flag = 1  # RENAME_NOREPLACE
    elif sys.platform == "darwin":
        function = getattr(libc, "renameatx_np", None)
        flag = 0x00000004  # RENAME_EXCL
    else:
        function = None
        flag = 0
    if function is None:
        fail("atomic no-replace rename is unavailable on this platform")
    function.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ]
    function.restype = ctypes.c_int
    ctypes.set_errno(0)
    result = function(
        directory_descriptor,
        os.fsencode(source),
        directory_descriptor,
        os.fsencode(destination),
        flag,
    )
    if result == 0:
        return
    error = ctypes.get_errno()
    if error in {errno.EEXIST, errno.ENOTEMPTY}:
        raise FileExistsError(error, "destination exists")
    if error in {errno.ENOSYS, errno.ENOTSUP, errno.EINVAL}:
        fail("atomic no-replace rename is unsupported by this filesystem")
    fail("atomic no-replace rename failed")


def publish_noreplace(
    directory_descriptor: int,
    directory: Path,
    basename: str,
    content: bytes,
    label: str,
    *,
    maximum: int = MAX_BOOTSTRAP_RECORD_BYTES,
) -> Path:
    temporary_name = f".{basename}.tmp-{os.getpid()}-{uuid.uuid4().hex}"
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    temporary_descriptor = -1
    renamed = False
    try:
        temporary_descriptor = os.open(
            temporary_name, flags, 0o600, dir_fd=directory_descriptor
        )
        write_all(temporary_descriptor, content)
        os.fsync(temporary_descriptor)
        os.close(temporary_descriptor)
        temporary_descriptor = -1
        try:
            atomic_rename_noreplace(directory_descriptor, temporary_name, basename)
        except FileExistsError:
            fail(f"{label} already exists and will not be replaced")
        renamed = True
        os.fsync(directory_descriptor)
        target = directory / basename
        published = open_private_input_at(
            directory_descriptor,
            basename,
            label,
            maximum=maximum,
        )
        try:
            if published.content != content:
                fail(f"published {label} differs from its input")
        finally:
            published.close()
        return target
    finally:
        if temporary_descriptor >= 0:
            os.close(temporary_descriptor)
        if not renamed:
            try:
                os.unlink(temporary_name, dir_fd=directory_descriptor)
            except FileNotFoundError:
                pass
            except OSError:
                pass
            try:
                os.fsync(directory_descriptor)
            except OSError:
                pass


def import_evidence_noreplace(
    directory_descriptor: int,
    directory: Path,
    source: PrivateInput,
    basename: str,
    label: str,
) -> tuple[Path, PrivateInput, bool]:
    if basename != SMOKE_EVIDENCE_FILENAME:
        fail("only authenticated smoke evidence can be imported by this closure")
    maximum = MAX_SMOKE_LOG_BYTES
    try:
        os.stat(basename, dir_fd=directory_descriptor, follow_symlinks=False)
    except FileNotFoundError:
        existing = False
    except OSError:
        fail(f"{label} fixed sibling could not be inspected")
    else:
        existing = True
    if existing:
        imported = open_private_input_at(
            directory_descriptor, basename, label, maximum=maximum
        )
        if imported.content != source.content:
            imported.close()
            fail(f"existing {label} conflicts with this closure attempt")
        return directory / basename, imported, False

    target = publish_noreplace(
        directory_descriptor,
        directory,
        basename,
        source.content,
        label,
        maximum=maximum,
    )
    imported = open_private_input_at(
        directory_descriptor,
        basename,
        label,
        maximum=maximum,
    )
    if imported.content != source.content:
        imported.close()
        fail(f"imported {label} differs from its source")
    return target, imported, True


def build_closure(
    bootstrap: PrivateInput,
    bootstrap_record: dict[str, Any],
    verified_evidence: dict[str, dict[str, Any]],
    smoke: PrivateInput,
    smoke_result: dict[str, object],
    challenge: PrivateInput,
    challenge_value_parsed: dict[str, object],
    deployment_id: str,
    deployment_basename: str,
) -> dict[str, object]:
    verified_projection = {
        name: {
            "basename": Path(str(descriptor["path"])).name,
            "sha256": descriptor["sha256"],
            "size": descriptor["size"],
        }
        for name, descriptor in sorted(verified_evidence.items())
    }
    smoke_value = {
        "evidence": smoke.evidence(SMOKE_EVIDENCE_FILENAME),
        **smoke_result,
    }
    return {
        "$schema": SCHEMA_ID,
        "format_version": 2,
        "status": "authenticated-smoke-closed",
        "closure_mode": "append-only-v1",
        "recorded_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "bootstrap_record": {
            **bootstrap.evidence("bootstrap-deployment.json"),
            "deployment_id": deployment_id,
            "deployment_basename": deployment_basename,
            "status": bootstrap_record["status"],
            "trust_mode": bootstrap_record["trust_mode"],
            "recorded_at": bootstrap_record["recorded_at"],
            "authenticated_smoke_pending": True,
        },
        "original_verified_evidence": {
            "count": len(verified_projection),
            "sha256": sha256_bytes(canonical_json(verified_projection)),
            "entries": verified_projection,
        },
        "authenticated_smoke": smoke_value,
        "revocation_observation": None,
        "closure_challenge": {
            "evidence": challenge.evidence(CHALLENGE_FILENAME),
            "format": "sub2api-control-authenticated-smoke-challenge-v2",
            "deployment_id": deployment_id,
            "deployment_basename": deployment_basename,
            "bootstrap_record_sha256": challenge_value_parsed[
                "bootstrap_record_sha256"
            ],
            "issued_at": challenge_value_parsed["issued_at"],
            "nonce_sha256": sha256_bytes(
                str(challenge_value_parsed["nonce"]).encode("ascii")
            ),
            "target": challenge_value_parsed["target"],
        },
        "closes_authenticated_smoke_pending": True,
        "original_bootstrap_record_mutated": False,
    }


def validate_closure_structure(value: Any) -> dict[str, object]:
    if not isinstance(value, dict):
        fail("authenticated smoke closure is not an object")
    try:
        bootstrap = value["bootstrap_record"]
        original = value["original_verified_evidence"]
        smoke = value["authenticated_smoke"]
        revocation = value["revocation_observation"]
        challenge = value["closure_challenge"]
        entries = original["entries"]
        target = challenge["target"]
    except (KeyError, TypeError):
        fail("authenticated smoke closure is missing semantic bindings")
    if (
        not isinstance(bootstrap, dict)
        or not isinstance(original, dict)
        or not isinstance(smoke, dict)
        or not isinstance(challenge, dict)
        or not isinstance(entries, dict)
        or not isinstance(target, dict)
    ):
        fail("authenticated smoke closure has invalid semantic bindings")
    if bootstrap.get("basename") != "bootstrap-deployment.json":
        fail("authenticated smoke closure has an invalid bootstrap basename")
    if bootstrap.get("sha256") != challenge.get("bootstrap_record_sha256"):
        fail("authenticated smoke closure bootstrap SHA binding differs")
    if bootstrap.get("deployment_id") != challenge.get(
        "deployment_id"
    ) or bootstrap.get("deployment_basename") != challenge.get("deployment_basename"):
        fail("authenticated smoke closure deployment binding differs")
    challenge_evidence = challenge.get("evidence")
    smoke_evidence = smoke.get("evidence")
    if (
        not isinstance(challenge_evidence, dict)
        or challenge_evidence.get("basename") != CHALLENGE_FILENAME
        or not isinstance(smoke_evidence, dict)
        or smoke_evidence.get("basename") != SMOKE_EVIDENCE_FILENAME
    ):
        fail("authenticated smoke closure has an invalid fixed evidence basename")
    challenge_sha256 = challenge_evidence.get("sha256")
    if challenge_sha256 != smoke.get("challenge_sha256"):
        fail("authenticated smoke closure challenge SHA binding differs")
    target_keys = {
        "public_origin",
        "compose_plan_sha256",
        "artifact_identity_sha256",
        "runtime_identity_sha256",
        "source_identity_sha256",
        "local_images_sha256",
        "running_containers_sha256",
        "binding_sha256",
    }
    if set(target) != target_keys:
        fail("authenticated smoke closure target binding has unexpected fields")
    canonical_public_origin(target.get("public_origin"))
    if any(
        not isinstance(target.get(name), str)
        or SHA256_RE.fullmatch(str(target.get(name))) is None
        for name in target_keys - {"public_origin"}
    ):
        fail("authenticated smoke closure target binding has an invalid digest")
    target_without_digest = {
        key: target[key] for key in sorted(target) if key != "binding_sha256"
    }
    if target["binding_sha256"] != sha256_bytes(canonical_json(target_without_digest)):
        fail("authenticated smoke closure target binding digest differs")
    if smoke.get("target_binding_sha256") != target["binding_sha256"]:
        fail("authenticated smoke closure smoke target binding differs")
    for name, basename in TARGET_EVIDENCE_BASENAMES.items():
        entry = entries.get(name)
        digest_key = {
            "compose_plan": "compose_plan_sha256",
            "local_images": "local_images_sha256",
            "running_containers": "running_containers_sha256",
        }[name]
        if (
            not isinstance(entry, dict)
            or entry.get("basename") != basename
            or entry.get("sha256") != target[digest_key]
        ):
            fail("authenticated smoke closure target evidence binding differs")
    if original.get("count") != len(entries):
        fail("authenticated smoke closure evidence count differs")
    if original.get("sha256") != sha256_bytes(canonical_json(entries)):
        fail("authenticated smoke closure evidence catalog digest differs")
    expected_catalog = sha256_bytes(canonical_json(list(EXPECTED_CHECK_DESCRIPTIONS)))
    if smoke.get("check_catalog_sha256") != expected_catalog:
        fail("authenticated smoke closure check catalog digest differs")
    if revocation is not None:
        fail("authenticated smoke closure cannot claim untrusted revocation evidence")
    return value


def reject_revocation_sibling(directory_descriptor: int) -> None:
    try:
        os.stat(
            REVOCATION_EVIDENCE_FILENAME,
            dir_fd=directory_descriptor,
            follow_symlinks=False,
        )
    except FileNotFoundError:
        return
    except OSError:
        fail("unsupported revocation evidence sibling could not be inspected")
    fail("unsupported revocation evidence sibling already exists")


def validate_closure_document(
    value: Any, directory_descriptor: int, directory: Path
) -> dict[str, object]:
    validate_closure_structure(value)
    try:
        recorded_at_value = value["recorded_at"]
    except (KeyError, TypeError):
        fail("authenticated smoke closure recorded_at is missing")
    recorded_at = parse_utc_timestamp(
        recorded_at_value, "authenticated smoke closure recorded_at"
    )
    if recorded_at > datetime.now(UTC) + FUTURE_CLOCK_SKEW:
        fail("authenticated smoke closure recorded_at is in the future")

    opened: list[PrivateInput] = []
    original_evidence: list[PrivateInput] = []
    try:
        deployment_id, deployment_basename = deployment_identity(directory)
        bootstrap = open_private_input_at(
            directory_descriptor,
            "bootstrap-deployment.json",
            "bootstrap deployment record",
            maximum=MAX_BOOTSTRAP_RECORD_BYTES,
        )
        opened.append(bootstrap)
        record, descriptors = validate_bootstrap_record(
            strict_json(bootstrap.content, "bootstrap deployment record"), directory
        )
        original_evidence = validate_original_evidence(
            descriptors, "bootstrap-deployment.json", directory_descriptor
        )
        target = target_binding(descriptors, original_evidence)

        challenge = open_private_input_at(
            directory_descriptor,
            CHALLENGE_FILENAME,
            "authenticated smoke challenge",
            maximum=MAX_CHALLENGE_BYTES,
        )
        opened.append(challenge)
        challenge_parsed = validate_challenge(
            challenge.content,
            deployment_id=deployment_id,
            deployment_basename=deployment_basename,
            bootstrap_sha256=sha256_bytes(bootstrap.content),
            expected_target=target,
            reference_time=recorded_at,
        )
        smoke = open_private_input_at(
            directory_descriptor,
            SMOKE_EVIDENCE_FILENAME,
            "authenticated smoke evidence",
            maximum=MAX_SMOKE_LOG_BYTES,
        )
        opened.append(smoke)
        smoke_result = parse_smoke_log(
            smoke.content,
            sha256_bytes(challenge.content),
            target["binding_sha256"],
        )
        reject_revocation_sibling(directory_descriptor)

        expected = build_closure(
            bootstrap,
            record,
            descriptors,
            smoke,
            smoke_result,
            challenge,
            challenge_parsed,
            deployment_id,
            deployment_basename,
        )
        expected["recorded_at"] = recorded_at_value
        if canonical_json(value) != canonical_json(expected):
            fail("authenticated smoke closure differs from its fixed evidence")
        for item in [bootstrap, challenge, smoke, *original_evidence]:
            item.assert_stable()
        return value
    finally:
        for item in original_evidence:
            item.close()
        for item in opened:
            item.close()


def prepare_challenge(bootstrap_path: Path | str) -> Path:
    bootstrap_path = canonical_absolute_path(bootstrap_path, "bootstrap record")
    directory = bootstrap_path.parent
    directory_descriptor, directory_metadata = open_private_directory(directory)
    inputs: list[PrivateInput] = []
    original_evidence: list[PrivateInput] = []
    try:
        if bootstrap_path.name != "bootstrap-deployment.json":
            fail("bootstrap record must be named bootstrap-deployment.json")
        deployment_id, deployment_basename = deployment_identity(directory)
        bootstrap = open_private_input_at(
            directory_descriptor,
            bootstrap_path.name,
            "bootstrap deployment record",
            maximum=MAX_BOOTSTRAP_RECORD_BYTES,
        )
        inputs.append(bootstrap)
        _, descriptors = validate_bootstrap_record(
            strict_json(bootstrap.content, "bootstrap deployment record"), directory
        )
        original_evidence = validate_original_evidence(
            descriptors, bootstrap_path.name, directory_descriptor
        )
        target = target_binding(descriptors, original_evidence)
        reject_revocation_sibling(directory_descriptor)
        challenge = challenge_value(
            deployment_id=deployment_id,
            deployment_basename=deployment_basename,
            bootstrap_sha256=sha256_bytes(bootstrap.content),
            nonce=secrets.token_hex(32),
            issued_at=datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            target=target,
        )
        content = canonical_json(challenge) + b"\n"
        for item in [bootstrap, *original_evidence]:
            item.assert_stable()
        if directory_signature(os.fstat(directory_descriptor)) != directory_signature(
            directory_metadata
        ):
            fail("bootstrap deployment directory identity changed")
        return publish_noreplace(
            directory_descriptor,
            directory,
            CHALLENGE_FILENAME,
            content,
            "authenticated smoke challenge",
            maximum=MAX_CHALLENGE_BYTES,
        )
    finally:
        for item in original_evidence:
            item.close()
        for item in inputs:
            item.close()
        try:
            os.close(directory_descriptor)
        except OSError:
            pass


def record_closure(
    bootstrap_path: Path | str,
    smoke_path: Path | str,
    revocation_path: Path | str | None = None,
) -> Path:
    if revocation_path is not None:
        fail("revocation evidence is unsupported until a trusted bound producer exists")
    bootstrap_path = canonical_absolute_path(bootstrap_path, "bootstrap record")
    smoke_path = canonical_absolute_path(smoke_path, "authenticated smoke log")
    directory = bootstrap_path.parent
    directory_descriptor, directory_metadata = open_private_directory(directory)
    inputs: list[PrivateInput] = []
    original_evidence: list[PrivateInput] = []
    imported: list[PrivateInput] = []
    try:
        if bootstrap_path.name != "bootstrap-deployment.json":
            fail("bootstrap record must be named bootstrap-deployment.json")
        deployment_id, deployment_basename = deployment_identity(directory)
        bootstrap = open_private_input_at(
            directory_descriptor,
            bootstrap_path.name,
            "bootstrap deployment record",
            maximum=MAX_BOOTSTRAP_RECORD_BYTES,
        )
        inputs.append(bootstrap)
        bootstrap_sha256 = sha256_bytes(bootstrap.content)
        record, descriptors = validate_bootstrap_record(
            strict_json(bootstrap.content, "bootstrap deployment record"), directory
        )
        original_evidence = validate_original_evidence(
            descriptors, bootstrap_path.name, directory_descriptor
        )
        expected_target = target_binding(descriptors, original_evidence)

        try:
            os.stat(
                CLOSURE_FILENAME,
                dir_fd=directory_descriptor,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            pass
        except OSError:
            fail("authenticated smoke closure could not be inspected")
        else:
            fail("authenticated smoke closure already exists and will not be replaced")

        challenge = open_private_input_at(
            directory_descriptor,
            CHALLENGE_FILENAME,
            "authenticated smoke challenge",
            maximum=MAX_CHALLENGE_BYTES,
        )
        inputs.append(challenge)
        challenge_parsed = validate_challenge(
            challenge.content,
            deployment_id=deployment_id,
            deployment_basename=deployment_basename,
            bootstrap_sha256=bootstrap_sha256,
            expected_target=expected_target,
        )
        challenge_sha256 = sha256_bytes(challenge.content)

        smoke = open_private_input(
            smoke_path, "authenticated smoke log", maximum=MAX_SMOKE_LOG_BYTES
        )
        inputs.append(smoke)
        smoke_result = parse_smoke_log(
            smoke.content, challenge_sha256, expected_target["binding_sha256"]
        )
        if (smoke.metadata.st_dev, smoke.metadata.st_ino) in {
            (item.metadata.st_dev, item.metadata.st_ino) for item in original_evidence
        }:
            fail("authenticated smoke log must be new append-only evidence")

        reject_revocation_sibling(directory_descriptor)

        _, imported_smoke, _ = import_evidence_noreplace(
            directory_descriptor,
            directory,
            smoke,
            SMOKE_EVIDENCE_FILENAME,
            "authenticated smoke evidence",
        )
        imported.append(imported_smoke)
        closure = build_closure(
            bootstrap,
            record,
            descriptors,
            imported_smoke,
            smoke_result,
            challenge,
            challenge_parsed,
            deployment_id,
            deployment_basename,
        )
        validate_closure_document(closure, directory_descriptor, directory)
        content = canonical_json(closure) + b"\n"
        for item in [*inputs, *original_evidence, *imported]:
            item.assert_stable()
        try:
            directory_before_publish = os.fstat(directory_descriptor)
        except OSError:
            fail("bootstrap deployment directory could not be re-inspected")
        if (
            directory_before_publish.st_dev != directory_metadata.st_dev
            or directory_before_publish.st_ino != directory_metadata.st_ino
            or directory_before_publish.st_uid != directory_metadata.st_uid
            or stat.S_IMODE(directory_before_publish.st_mode) != 0o700
        ):
            fail("bootstrap deployment directory identity changed")
        target = publish_noreplace(
            directory_descriptor,
            directory,
            CLOSURE_FILENAME,
            content,
            "authenticated smoke closure",
        )
        return target
    finally:
        for item in imported:
            item.close()
        for item in original_evidence:
            item.close()
        for item in inputs:
            item.close()
        try:
            os.close(directory_descriptor)
        except OSError:
            pass


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Append an immutable authenticated-smoke closure beside one unsigned "
            "bootstrap record. The command accepts no credential or token value."
        )
    )
    parser.add_argument("--bootstrap-record", required=True)
    parser.add_argument(
        "--prepare-challenge",
        action="store_true",
        help="append the one-use non-secret challenge before running smoke.py",
    )
    parser.add_argument("--smoke-log")
    args = parser.parse_args(argv)
    if args.prepare_challenge:
        if args.smoke_log is not None:
            parser.error("--prepare-challenge does not accept evidence inputs")
    elif args.smoke_log is None:
        parser.error("--smoke-log is required unless --prepare-challenge is used")
    return args


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        if args.prepare_challenge:
            target = prepare_challenge(args.bootstrap_record)
        else:
            target = record_closure(
                args.bootstrap_record,
                args.smoke_log,
            )
    except (ClosureError, OSError) as error:
        print(f"record-authenticated-smoke-closure: {error}", file=sys.stderr)
        return 1
    print(target.name)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
