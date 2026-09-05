"""Destructive, operator-started canary for a real production Connector.

This module deliberately reuses :mod:`smoke` for the HTTP cookie jar, secure
file reader, WebSocket framing, and cursor validation.  It has no production
defaults and is not called by automated CI or deployment scripts.
"""

from __future__ import annotations

import argparse
import collections
import hashlib
import json
import os
import re
import secrets
import shlex
import shutil
import signal
import stat
import subprocess
import sys
import threading
import time
import urllib.parse
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from smoke import (
    Result,
    Smoke,
    WebSocketStream,
    canonical_absolute_path,
)

CANARY_FORMAT_VERSION = 1
CANARY_USER_AGENT = "sub2api-codex-control-production-canary/1"
CONNECTOR_VERSION = "0.1.11"
CANARY_CONNECTOR_BINARY_VERSION = CONNECTOR_VERSION + "+productioncanary"
CODEX_VERSION = "0.147.0"
SCHEMA_DIGEST = "511c1b3ca038a80740a5a41ca10a7f925c0f744e582fb9aaa03cc46c6e98b80b"
PAIRING_CODE_RE = re.compile(r"^[23456789A-HJ-NP-Z]{4}(?:-[23456789A-HJ-NP-Z]{4}){3}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
TERMINAL_COMMAND_STATES = frozenset(
    {"succeeded", "failed", "denied", "cancelled", "expired"}
)
EXPECTED_RPC_METHODS = frozenset(
    {
        "model/list",
        "thread/start",
        "thread/list",
        "thread/read",
        "thread/resume",
        "turn/start",
        "turn/steer",
        "turn/interrupt",
    }
)
DANGEROUS_HTTP_PATHS = (
    "/codex-api/v1/thread/shellCommand",
    "/codex-api/v1/command/exec",
    "/codex-api/v1/fs/read",
    "/codex-api/v1/process/list",
    "/codex-api/v1/config/value/write",
    "/codex-api/v1/plugin/install",
    "/codex-api/v1/account/login",
    "/codex-api/v1/oauth/authorize",
    "/codex-api/v1/raw-rpc",
)


@dataclass(repr=False)
class AuthMaterial:
    username: str
    password: str

    def __repr__(self) -> str:
        return "AuthMaterial(<redacted>)"

    def clear(self) -> None:
        self.username = ""
        self.password = ""


@dataclass
class CanaryEvidence:
    started_at: str = field(
        default_factory=lambda: datetime.now(UTC).isoformat(timespec="seconds")
    )
    finished_at: str | None = None
    outcome: str = "running"
    connector_version: str = CONNECTOR_VERSION
    codex_version: str = CODEX_VERSION
    schema_sha256: str = SCHEMA_DIGEST
    checks: dict[str, bool] = field(default_factory=dict)
    rpc_methods: list[str] = field(default_factory=list)
    approvals: dict[str, object] = field(
        default_factory=lambda: {
            "status": "externally_blocked",
            "verified": False,
            "reason": "real_approval_not_deterministically_triggered",
        }
    )
    cleanup: dict[str, bool] = field(default_factory=dict)
    binary_sha256: dict[str, str] = field(default_factory=dict)

    def mark(self, name: str, passed: bool = True) -> None:
        if not re.fullmatch(r"[a-z][a-z0-9_]{0,63}", name):
            raise ValueError("evidence check name is invalid")
        self.checks[name] = bool(passed)

    def rpc(self, method: str) -> None:
        if method not in EXPECTED_RPC_METHODS:
            raise ValueError("evidence method is outside the exact RPC allowlist")
        if method not in self.rpc_methods:
            self.rpc_methods.append(method)

    def approvals_blocked(
        self, reason: str = "real_approval_not_deterministically_triggered"
    ) -> None:
        self.approvals = {
            "status": "externally_blocked",
            "verified": False,
            "reason": reason,
        }

    def finish(self, outcome: str) -> None:
        if outcome not in {"passed", "failed", "externally_blocked"}:
            raise ValueError("canary outcome is invalid")
        self.outcome = outcome
        self.finished_at = datetime.now(UTC).isoformat(timespec="seconds")

    def serializable(self) -> dict[str, object]:
        return {
            "format_version": CANARY_FORMAT_VERSION,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "outcome": self.outcome,
            "connector_version": self.connector_version,
            "codex_version": self.codex_version,
            "schema_sha256": self.schema_sha256,
            "checks": dict(sorted(self.checks.items())),
            "rpc_methods": sorted(self.rpc_methods),
            "approvals": self.approvals,
            "cleanup": dict(sorted(self.cleanup.items())),
            "binary_sha256": dict(sorted(self.binary_sha256.items())),
        }


class ExternalVerificationBlocked(RuntimeError):
    """A real, non-synthetic verification could not be made deterministic."""


class ApprovalTriggerUnavailable(ExternalVerificationBlocked):
    """The text-only public API did not produce one safely attributable approval."""


@dataclass(frozen=True)
class FileIdentity:
    sha256: str
    size: int
    mode: int
    uid: int
    gid: int


@dataclass
class FrozenFile:
    path: Path
    descriptor: int
    identity: FileIdentity
    signature: tuple[int, ...]

    def verify(self, label: str, maximum: int = 256 << 20) -> None:
        if self.descriptor < 0:
            raise ValueError(f"{label} frozen descriptor is closed")
        opened = os.fstat(self.descriptor)
        named = os.stat(self.path, follow_symlinks=False)
        if _file_signature(opened) != self.signature or _file_signature(named) != (
            self.signature
        ):
            raise ValueError(f"{label} identity changed after it was frozen")
        if _hash_descriptor(self.descriptor, maximum) != self.identity.sha256:
            raise ValueError(f"{label} content changed after it was frozen")

    def close(self) -> None:
        if self.descriptor >= 0:
            os.close(self.descriptor)
            self.descriptor = -1


def _file_signature(metadata: os.stat_result) -> tuple[int, ...]:
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


def _hash_descriptor(descriptor: int, maximum: int) -> str:
    digest = hashlib.sha256()
    offset = 0
    remaining = maximum + 1
    while remaining:
        chunk = os.pread(descriptor, min(1 << 20, remaining), offset)
        if not chunk:
            break
        digest.update(chunk)
        offset += len(chunk)
        remaining -= len(chunk)
    if offset > maximum:
        raise ValueError("frozen file exceeds its size limit")
    return digest.hexdigest()


def open_frozen_file(
    path: Path | str,
    label: str,
    *,
    require_executable: bool = False,
    maximum: int = 256 << 20,
) -> FrozenFile:
    lexical = canonical_absolute_path(path, label)
    try:
        resolved = canonical_absolute_path(lexical.resolve(strict=True), label)
    except OSError:
        raise ValueError(f"{label} cannot be resolved") from None
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(resolved, flags)
    except OSError:
        raise ValueError(f"cannot open {label} without following links") from None
    try:
        opened = os.fstat(descriptor)
        named = os.stat(resolved, follow_symlinks=False)
        signature = _file_signature(opened)
        if not stat.S_ISREG(opened.st_mode) or signature != _file_signature(named):
            raise ValueError(f"{label} is not a stable regular file")
        if opened.st_nlink != 1:
            raise ValueError(f"{label} must have one filesystem link")
        if opened.st_mode & 0o022:
            raise ValueError(f"{label} must not be group- or other-writable")
        if opened.st_size <= 0 or opened.st_size > maximum:
            raise ValueError(f"{label} has an invalid size")
        if require_executable and opened.st_mode & 0o111 == 0:
            raise ValueError(f"{label} is not executable")
        identity = FileIdentity(
            sha256=_hash_descriptor(descriptor, maximum),
            size=opened.st_size,
            mode=stat.S_IMODE(opened.st_mode),
            uid=opened.st_uid,
            gid=opened.st_gid,
        )
        frozen = FrozenFile(resolved, descriptor, identity, signature)
        frozen.verify(label, maximum)
        return frozen
    except Exception:
        os.close(descriptor)
        raise


def read_regular_file_identity(
    path: Path | str,
    label: str,
    *,
    require_executable: bool = False,
    maximum: int = 256 << 20,
) -> FileIdentity:
    frozen = open_frozen_file(
        path,
        label,
        require_executable=require_executable,
        maximum=maximum,
    )
    try:
        return frozen.identity
    finally:
        frozen.close()


def _json_bytes(raw: bytes, label: str) -> object:
    try:
        return json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ValueError(f"{label} is not valid UTF-8 JSON") from None


def _read_owned_private_fd(descriptor: int, label: str, maximum: int) -> bytearray:
    if isinstance(descriptor, bool) or descriptor < 3:
        raise ValueError(f"{label} descriptor is invalid")
    try:
        duplicate = os.dup(descriptor)
    except OSError:
        raise ValueError(f"{label} descriptor is unavailable") from None
    try:
        before = os.fstat(duplicate)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.geteuid()
            or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_nlink != 1
            or before.st_size <= 0
            or before.st_size > maximum
        ):
            raise ValueError(f"{label} descriptor is not one owned 0600 regular file")
        os.lseek(duplicate, 0, os.SEEK_SET)
        raw = bytearray()
        remaining = maximum + 1
        while remaining:
            chunk = os.read(duplicate, min(4096, remaining))
            if not chunk:
                break
            raw.extend(chunk)
            remaining -= len(chunk)
        after = os.fstat(duplicate)

        def signature(item: os.stat_result) -> tuple[int, ...]:
            return (
                item.st_dev,
                item.st_ino,
                item.st_mode,
                item.st_uid,
                item.st_gid,
                item.st_nlink,
                item.st_size,
                item.st_mtime_ns,
                item.st_ctime_ns,
            )

        if signature(before) != signature(after) or len(raw) > maximum:
            raise ValueError(f"{label} changed while it was read")
        return raw
    finally:
        os.close(duplicate)


def read_auth_material_fd(descriptor: int) -> AuthMaterial:
    raw = _read_owned_private_fd(descriptor, "authentication file", 65_536)
    try:
        value = _json_bytes(raw, "authentication file")
    finally:
        raw[:] = b"\0" * len(raw)
    if not isinstance(value, dict) or set(value) != {
        "OPENAI_API_KEY",
        "password",
        "username",
    }:
        raise ValueError("authentication file has an unexpected schema")
    for name in ("username", "password", "OPENAI_API_KEY"):
        raw = value.get(name)
        if (
            not isinstance(raw, str)
            or not raw
            or len(raw.encode("utf-8")) > 16_384
            or any(ord(character) < 0x20 or ord(character) == 0x7F for character in raw)
        ):
            raise ValueError("authentication file contains an invalid secret value")
    username = value["username"]
    password = value["password"]
    for name in ("username", "password", "OPENAI_API_KEY"):
        value[name] = ""
    return AuthMaterial(username=username, password=password)


def read_pairing_code(path: Path | str) -> str:
    from smoke import read_private_bytes

    value = _json_bytes(
        read_private_bytes(path, "pairing code file", 4096), "pairing code file"
    )
    if not isinstance(value, dict) or set(value) != {"code", "expires_at"}:
        raise ValueError("pairing code file has an unexpected schema")
    code = value.get("code")
    if not isinstance(code, str) or PAIRING_CODE_RE.fullmatch(code) is None:
        raise ValueError("pairing code file contains an invalid pairing code")
    return code


def build_connector_argv(binary: Path, config: Path) -> list[str]:
    return [str(binary), "-config", str(config)]


def build_connector_environment(
    source: dict[str, str] | os._Environ[str],
) -> dict[str, str]:
    permitted = (
        "CODEX_HOME",
        "HOME",
        "LANG",
        "LC_ALL",
        "PATH",
        "SSL_CERT_FILE",
        "TMPDIR",
    )
    return {name: source[name] for name in permitted if source.get(name)}


def _verify_frozen_files(
    connector: FrozenFile, codex: FrozenFile, config: FrozenFile
) -> None:
    connector.verify("Connector binary")
    codex.verify("Codex binary")
    config.verify("Connector config", 65_536)


def choose_dynamic_model(catalog: object) -> str | None:
    if not isinstance(catalog, dict) or not isinstance(catalog.get("items"), list):
        return None
    for item in catalog["items"]:
        if isinstance(item, dict) and isinstance(item.get("id"), str):
            model = item["id"].strip()
            if model and len(model) <= 128:
                return model
    return None


def _ensure_private_directory(path: Path, *, create: bool) -> Path:
    path = canonical_absolute_path(path, "private directory")
    if create:
        try:
            path.mkdir(mode=0o700, exist_ok=False)
        except FileExistsError:
            pass
    metadata = path.stat(follow_symlinks=False)
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.geteuid():
        raise ValueError("private directory must be an owned directory")
    if stat.S_IMODE(metadata.st_mode) != 0o700:
        raise ValueError("private directory mode must be exactly 0700")
    return path


def create_private_run_directory(path: Path | str) -> Path:
    target = canonical_absolute_path(path, "private run directory")
    parent = _ensure_private_directory(target.parent, create=False)
    directory = _open_directory_nofollow(parent)
    try:
        os.mkdir(target.name, 0o700, dir_fd=directory)
        os.fsync(directory)
    except FileExistsError:
        raise ValueError("private run directory must not already exist") from None
    finally:
        os.close(directory)
    return _ensure_private_directory(target, create=False)


def _open_directory_nofollow(path: Path | str) -> int:
    path = canonical_absolute_path(path, "directory")
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_DIRECTORY", 0)
    )
    descriptor = os.open("/", flags)
    try:
        for component in path.parts[1:]:
            next_descriptor = os.open(component, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
        return descriptor
    except OSError:
        os.close(descriptor)
        raise ValueError("directory has an inaccessible or symlink ancestor") from None


def _write_exclusive_file(destination: Path, payload: bytes, mode: int = 0o600) -> None:
    parent = _open_directory_nofollow(destination.parent)
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(destination.name, flags, mode, dir_fd=parent)
        try:
            os.fchmod(descriptor, mode)
            view = memoryview(payload)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise OSError("private file write made no progress")
                view = view[written:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.fsync(parent)
    finally:
        os.close(parent)


def write_redacted_evidence(directory: Path | str, evidence: CanaryEvidence) -> Path:
    root = _ensure_private_directory(Path(directory), create=False)
    payload = (
        json.dumps(
            evidence.serializable(),
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    )
    destination = root / "production-connector-canary.json"
    _write_exclusive_file(destination, payload.encode("ascii"))
    return destination


def _node_digest(parent: int, name: str) -> bytes:
    try:
        metadata = os.stat(name, dir_fd=parent, follow_symlinks=False)
    except FileNotFoundError:
        return hashlib.sha256(b"missing\0" + name.encode()).digest()
    digest = hashlib.sha256()
    digest.update(name.encode("utf-8") + b"\0")
    digest.update(
        repr(
            (
                metadata.st_mode,
                metadata.st_uid,
                metadata.st_gid,
                metadata.st_nlink,
                metadata.st_size,
                metadata.st_mtime_ns,
                metadata.st_ctime_ns,
            )
        ).encode("ascii")
    )
    digest.update(b"\0")
    if stat.S_ISLNK(metadata.st_mode):
        digest.update(b"link\0" + os.readlink(name, dir_fd=parent).encode("utf-8"))
    elif stat.S_ISREG(metadata.st_mode):
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(name, flags, dir_fd=parent)
        try:
            opened = os.fstat(descriptor)
            if (opened.st_dev, opened.st_ino, opened.st_mode) != (
                metadata.st_dev,
                metadata.st_ino,
                metadata.st_mode,
            ):
                raise ValueError("protected file changed while it was opened")
            digest.update(b"file\0")
            while chunk := os.read(descriptor, 1 << 20):
                digest.update(chunk)
            final = os.fstat(descriptor)
            if (
                final.st_size,
                final.st_mtime_ns,
                final.st_ctime_ns,
            ) != (metadata.st_size, metadata.st_mtime_ns, metadata.st_ctime_ns):
                raise ValueError("protected file changed while it was hashed")
        finally:
            os.close(descriptor)
    elif stat.S_ISDIR(metadata.st_mode):
        flags = (
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_DIRECTORY", 0)
        )
        descriptor = os.open(name, flags, dir_fd=parent)
        try:
            digest.update(b"directory\0")
            for child in sorted(os.listdir(descriptor)):
                digest.update(_node_digest(descriptor, child))
        finally:
            os.close(descriptor)
    else:
        digest.update(b"other")
    return digest.digest()


def snapshot_protected_files(codex_home: Path) -> dict[str, str]:
    root = _open_directory_nofollow(codex_home)
    try:
        return {
            name: _node_digest(root, name).hex()
            for name in ("auth.json", "config.toml", "plugins")
        }
    finally:
        os.close(root)


def read_spool_meta(state_dir: Path) -> tuple[int, int, int]:
    from smoke import read_private_bytes

    value = _json_bytes(
        read_private_bytes(state_dir / "spool" / "meta.json", "spool metadata", 4096),
        "spool metadata",
    )
    if not isinstance(value, dict) or set(value) != {
        "version",
        "next_sequence",
        "last_acked",
        "last_received",
    }:
        raise ValueError("spool metadata has an unexpected schema")
    numbers = tuple(
        value[name] for name in ("next_sequence", "last_acked", "last_received")
    )
    if not all(
        isinstance(item, int) and not isinstance(item, bool) and item >= 0
        for item in numbers
    ):
        raise ValueError("spool metadata has an invalid cursor")
    return numbers  # type: ignore[return-value]


def read_spool_records(state_dir: Path) -> dict[int, tuple[str, str, str | None]]:
    from smoke import read_private_bytes

    spool = state_dir / "spool"
    directory = _open_directory_nofollow(spool)
    names = sorted(os.listdir(directory))
    os.close(directory)
    records: dict[int, tuple[str, str, str | None]] = {}
    for name in names:
        if name == "meta.json" or re.fullmatch(r"[0-9]{20}\.json", name) is None:
            continue
        value = _json_bytes(
            read_private_bytes(spool / name, "spool record", 256 << 10),
            "spool record",
        )
        if not isinstance(value, dict):
            raise ValueError(  # noqa: TRY004 - malformed persisted state.
                "spool record is not an object"
            )
        sequence = value.get("seq")
        event_id = value.get("id")
        envelope_type = value.get("type")
        payload = value.get("payload")
        command_id = payload.get("command_id") if isinstance(payload, dict) else None
        if (
            isinstance(sequence, bool)
            or not isinstance(sequence, int)
            or sequence <= 0
            or not isinstance(event_id, str)
            or not event_id
            or not isinstance(envelope_type, str)
            or not envelope_type
        ):
            raise ValueError("spool record has an invalid identity projection")
        if sequence != int(name.removesuffix(".json")):
            raise ValueError("spool record filename and sequence differ")
        if command_id is not None and (
            not isinstance(command_id, str) or not command_id
        ):
            raise ValueError("spool record has an invalid command identity")
        records[sequence] = (event_id, envelope_type, command_id)
    return records


def wait_for_unacked_command_record(
    state_dir: Path, command_id: str, timeout: float = 30
) -> tuple[int, str]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        _, last_acked, _ = read_spool_meta(state_dir)
        matches = [
            (sequence, event_id)
            for sequence, (event_id, envelope_type, candidate_command) in (
                read_spool_records(state_dir).items()
            )
            if sequence > last_acked
            and envelope_type == "command_ack"
            and candidate_command == command_id
        ]
        if len(matches) == 1:
            return matches[0]
        if len(matches) > 1:
            raise AssertionError("more than one unacknowledged ACK matches the command")
        time.sleep(0.01)
    raise ExternalVerificationBlocked(
        "no observable unacknowledged command ACK was available for crash replay"
    )


def wait_for_replayed_record_ack(
    state_dir: Path,
    sequence: int,
    event_id: str,
    command_id: str,
    timeout: float = 30,
) -> tuple[int, int, int]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        metadata = read_spool_meta(state_dir)
        record = read_spool_records(state_dir).get(sequence)
        if metadata[1] >= sequence and record is None:
            return metadata
        if record is not None and record != (event_id, "command_ack", command_id):
            raise AssertionError(
                "replayed spool record changed identity before server ACK"
            )
        time.sleep(0.02)
    raise AssertionError("server did not ACK and prune the exact replayed spool record")


def read_token_reconnects(state_dir: Path) -> int:
    from smoke import read_private_bytes

    value = _json_bytes(
        read_private_bytes(
            state_dir / "connector-metrics.json", "Connector metrics state", 1 << 20
        ),
        "Connector metrics state",
    )
    reconnects = value.get("reconnects") if isinstance(value, dict) else None
    if (
        not isinstance(reconnects, list)
        or len(reconnects) != 4
        or any(
            isinstance(item, bool) or not isinstance(item, int) or item < 0
            for item in reconnects
        )
    ):
        raise ValueError("Connector metrics reconnect counters are invalid")
    return reconnects[0]


def assert_refresh_only_credentials(state_dir: Path) -> None:
    from smoke import read_private_bytes

    value = _json_bytes(
        read_private_bytes(
            state_dir / "device-credentials.json", "device credentials", 16 << 10
        ),
        "device credentials",
    )
    if (
        not isinstance(value, dict)
        or set(value) != {"version", "device_id", "refresh_credential"}
        or value.get("version") != 1
        or not isinstance(value.get("device_id"), str)
        or not value["device_id"]
        or not isinstance(value.get("refresh_credential"), str)
        or not value["refresh_credential"]
    ):
        raise ValueError("device credential state is not refresh-only")


def _read_crash_marker(state_dir: Path) -> object | None:
    from smoke import read_private_bytes

    marker = state_dir / "production-canary-crash-armed.json"
    try:
        metadata = marker.stat(follow_symlinks=False)
    except FileNotFoundError:
        return None
    if not stat.S_ISREG(metadata.st_mode):
        raise ValueError("production canary crash marker is not a regular file")
    try:
        value = _json_bytes(
            read_private_bytes(
                marker,
                "production canary crash marker",
                4096,
            ),
            "production canary crash marker",
        )
    except ValueError:
        try:
            marker.stat(follow_symlinks=False)
        except FileNotFoundError:
            return None
        raise
    return True if value == {"armed": True, "version": 1} else None


def _descendant_processes(parent_pid: int) -> set[int]:
    if parent_pid <= 0:
        return set()
    completed = subprocess.run(
        ["ps", "-axo", "pid=,ppid=,sid="],
        env=build_connector_environment(os.environ),
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    if completed.returncode != 0:
        raise OSError("cannot enumerate Connector-owned processes")
    children: dict[int, set[int]] = {}
    session_members: set[int] = set()
    for line in completed.stdout.splitlines():
        fields = line.split()
        if len(fields) != 3 or not all(field.isdigit() for field in fields):
            continue
        pid, ppid, session_id = (int(field) for field in fields)
        children.setdefault(ppid, set()).add(pid)
        if session_id == parent_pid and pid != parent_pid:
            session_members.add(pid)
    result: set[int] = set()
    pending = list(children.get(parent_pid, ()))
    while pending:
        pid = pending.pop()
        if pid in result:
            continue
        result.add(pid)
        pending.extend(children.get(pid, ()))
    return result | session_members


def _terminate_owned_processes(
    processes: set[int], *, owner_session: int | None = None
) -> bool:
    own_pid = os.getpid()
    targets = sorted(
        pid
        for pid in processes
        if pid > 1
        and pid != own_pid
        and (owner_session is None or _process_session(pid) == owner_session)
    )
    for pid in targets:
        try:
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            continue
    deadline = time.monotonic() + 5
    remaining = set(targets)
    while remaining and time.monotonic() < deadline:
        for pid in tuple(remaining):
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                remaining.remove(pid)
        if remaining:
            time.sleep(0.05)
    for pid in remaining:
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    return all(
        _process_absent(pid, owner_session=owner_session) for pid in targets
    )


def _process_session(pid: int) -> int | None:
    try:
        return os.getsid(pid)
    except ProcessLookupError:
        return None
    except PermissionError:
        return -1


def _process_absent(pid: int, *, owner_session: int | None = None) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return True
    except PermissionError:
        return False
    return owner_session is not None and _process_session(pid) != owner_session


class ProductionCanary(Smoke):
    def __init__(self, base_url: str, evidence: CanaryEvidence) -> None:
        self._leak_sentinel = "canary_" + secrets.token_hex(32)
        self.proxy_policy = "disabled"
        super().__init__(
            base_url,
            insecure=False,
            expect_secure_cookie=True,
            provider_key_canary=self._leak_sentinel,
        )
        self.opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            urllib.request.HTTPCookieProcessor(self.cookies),
            urllib.request.HTTPSHandler(context=self.ssl_context),
        )
        self.evidence = evidence
        self.opener.addheaders = [("User-Agent", CANARY_USER_AGENT)]
        self.command_states: dict[str, dict[str, object]] = {}
        self.session_mutating_headers: dict[str, str] | None = None
        self._browser_backlog: collections.deque[dict[str, object]] = (
            collections.deque()
        )
        self._browser_lock = threading.Lock()

    def clear_leak_sentinel(self) -> None:
        self.provider_key_canary = None
        self._leak_sentinel = ""

    def wait_browser_event(
        self,
        stream: WebSocketStream,
        description: str,
        predicate: Callable[[dict[str, object]], bool],
        *,
        timeout: float = 15,
    ) -> dict[str, object]:
        deadline = time.monotonic() + timeout
        with self._browser_lock:
            for candidate in tuple(self._browser_backlog):
                if predicate(candidate):
                    self._browser_backlog.remove(candidate)
                    self.check(True, description)
                    return candidate
            while time.monotonic() < deadline:
                try:
                    raw = stream.receive_text(
                        min(1.0, max(0.01, deadline - time.monotonic()))
                    )
                except TimeoutError:
                    continue
                if raw is None:
                    raise AssertionError(
                        f"browser WebSocket closed before {description}"
                    )
                if (
                    self.provider_key_canary is not None
                    and self.provider_key_canary in raw
                ):
                    raise AssertionError(
                        "raw Sub2API provider key reached the browser WebSocket"
                    )
                candidate = json.loads(raw)
                if not isinstance(candidate, dict):
                    raise AssertionError(  # noqa: TRY004 - acceptance assertion.
                        "browser WebSocket delivered a non-object event"
                    )
                raw_cursor = candidate.get("cursor")
                if not isinstance(raw_cursor, str) or not raw_cursor.isdigit():
                    raise AssertionError(
                        "browser WebSocket delivered an invalid event cursor"
                    )
                cursor = int(raw_cursor)
                if (
                    self.browser_event_cursors
                    and cursor <= self.browser_event_cursors[-1]
                ):
                    raise AssertionError(
                        "browser WebSocket event cursor was duplicated or moved backward"
                    )
                self.browser_event_cursors.append(cursor)
                if predicate(candidate):
                    self.check(True, description)
                    return candidate
                self._browser_backlog.append(candidate)
            raise AssertionError(f"timed out waiting for {description}")

    def command_event(
        self,
        stream: WebSocketStream,
        command_id: str,
        method: str,
        description: str,
        *,
        timeout: float = 120,
    ) -> dict[str, object]:
        def terminal(event: dict[str, object]) -> bool:
            if event.get("type") != "command.updated" or not isinstance(
                event.get("data"), dict
            ):
                return False
            command = event["data"].get("command")
            if not isinstance(command, dict):
                return False
            if command.get("id") != command_id or command.get("method") != method:
                return False
            state = command.get("state")
            if isinstance(state, str):
                self.command_states[command_id] = command
            return state in TERMINAL_COMMAND_STATES

        self.wait_browser_event(stream, description, terminal, timeout=timeout)
        command = self.command_states[command_id]
        if command.get("state") != "succeeded":
            raise AssertionError(f"{method} reached terminal state without succeeding")
        self.evidence.rpc(method)
        return command

    def accepted_command(self, response: Result, method: str) -> str:
        body = response.json()
        if (
            response.status != 202
            or not isinstance(body, dict)
            or not isinstance(body.get("id"), str)
            or body.get("method") != method
        ):
            raise AssertionError(f"{method} was not accepted")
        return body["id"]

    def pending_approval_ids(self, device_id: str, remote_thread_id: str) -> set[str]:
        response = self.request("/codex-api/v1/approvals?state=pending")
        body = response.json() if response.status == 200 else None
        items = body.get("items") if isinstance(body, dict) else None
        if not isinstance(items, list):
            raise ValueError(  # noqa: TRY004 - malformed API projection.
                "pending approval list is invalid"
            )
        return {
            approval_id
            for item in items
            if isinstance(item, dict)
            and item.get("device_id") == device_id
            and isinstance(item.get("details"), dict)
            and item["details"].get("threadId") == remote_thread_id
            and isinstance((approval_id := item.get("approval_id")), str)
        }

    def unique_pending_approval(
        self,
        kind: str,
        device_id: str,
        remote_thread_id: str,
        baseline_ids: set[str],
        event_approval_id: str,
        timeout: float = 45,
    ) -> dict[str, object]:
        def probe() -> object | None:
            response = self.request("/codex-api/v1/approvals?state=pending")
            body = response.json() if response.status == 200 else None
            items = body.get("items") if isinstance(body, dict) else None
            if not isinstance(items, list):
                return None
            candidates = [
                item
                for item in items
                if isinstance(item, dict)
                and item.get("kind") == kind
                and item.get("device_id") == device_id
                and isinstance(item.get("details"), dict)
                and item["details"].get("threadId") == remote_thread_id
                and isinstance(item.get("approval_id"), str)
                and item["approval_id"] not in baseline_ids
            ]
            if len(candidates) > 1:
                raise ApprovalTriggerUnavailable(
                    "more than one new approval exists for this canary device"
                )
            if not candidates:
                return None
            if candidates[0].get("approval_id") != event_approval_id:
                raise ApprovalTriggerUnavailable(
                    "approval event and unique pending record differ"
                )
            return candidates[0]

        try:
            value = self.eventually(
                f"real {kind} approval reaches the browser surface",
                probe,
                timeout=timeout,
            )
        except AssertionError as error:
            if str(error) != (
                f"timed out waiting for real {kind} approval reaches the browser surface"
            ):
                raise
            raise ApprovalTriggerUnavailable(
                "approval event had no unique matching pending projection"
            ) from None
        if not isinstance(value, dict):
            raise ValueError(  # noqa: TRY004 - malformed API projection.
                "approval projection is invalid"
            )
        return value


def _login_to_sub2api(client: ProductionCanary, auth: AuthMaterial) -> tuple[str, str]:
    response = client.request(
        "/api/v1/auth/login",
        method="POST",
        headers={"Origin": client.origin, "User-Agent": CANARY_USER_AGENT},
        body={"email": auth.username, "password": auth.password},
    )
    if response.status != 200:
        raise AssertionError("Sub2API login failed")
    body = response.json()
    data = body.get("data") if isinstance(body, dict) else None
    if not isinstance(data, dict):
        raise AssertionError(  # noqa: TRY004 - acceptance contract assertion.
            "Sub2API login returned an invalid response"
        )
    if data.get("requires_2fa") is True:
        raise AssertionError("Sub2API login requires interactive 2FA")
    access_token = data.get("access_token")
    user = data.get("user")
    user_id = user.get("id") if isinstance(user, dict) else None
    if not isinstance(access_token, str) or not access_token:
        raise AssertionError("Sub2API login returned no access token")
    if isinstance(user_id, bool) or user_id is None or not str(user_id):
        raise AssertionError("Sub2API login returned no user identity")
    return access_token, str(user_id)


def _session_exchange(
    client: ProductionCanary, access_token: str, expected_user_id: str
) -> tuple[dict[str, str], WebSocketStream]:
    exchange = client.request(
        "/codex-api/v1/session/exchange",
        method="POST",
        headers={"Origin": client.origin, "User-Agent": CANARY_USER_AGENT},
        body={"access_token": access_token},
    )
    if exchange.status != 201 or access_token.encode() in exchange.body:
        raise AssertionError("Control session exchange failed or reflected its token")
    client.evidence.cleanup["control_session"] = False
    csrf_cookie = next(
        (cookie for cookie in client.cookies if "csrf" in cookie.name.lower()), None
    )
    if csrf_cookie is None:
        raise AssertionError("Control session has no CSRF cookie")
    mutating_headers = {
        "Origin": client.origin,
        "x-csrf-token": csrf_cookie.value,
    }
    client.session_mutating_headers = mutating_headers
    body = exchange.json()
    header_name = (
        str(body.get("csrf_header_name"))
        if isinstance(body, dict) and body.get("csrf_header_name")
        else "x-csrf-token"
    )
    # Refresh the cleanup handle from the validated exchange contract. A default
    # handle was already published above in case response decoding itself fails.
    mutating_headers = {
        "Origin": client.origin,
        header_name: csrf_cookie.value,
    }
    client.session_mutating_headers = mutating_headers
    if (
        not isinstance(body, dict)
        or not isinstance(body.get("user"), dict)
        or str(body["user"].get("id")) != expected_user_id
    ):
        raise AssertionError("Control session is not bound to the login identity")
    current = client.request("/codex-api/v1/session")
    current_body = current.json() if current.status == 200 else None
    if (
        not isinstance(current_body, dict)
        or not isinstance(current_body.get("user"), dict)
        or str(current_body["user"].get("id")) != expected_user_id
        or current_body.get("csrf_header_name") != header_name
    ):
        raise AssertionError("Control session readback differs from its exchange")
    cookie_header = "; ".join(
        f"{cookie.name}={cookie.value}" for cookie in client.cookies
    )
    status, _, stream = client.open_websocket(
        "/codex-ws/browser?cursor=0", origin=client.origin, cookie=cookie_header
    )
    if status != 101 or stream is None:
        raise AssertionError("authenticated browser WebSocket did not upgrade")
    client.evidence.cleanup["browser_websocket"] = False
    return mutating_headers, stream


def _wait_for_file(path: Path, timeout: float) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.is_file():
            return
        time.sleep(0.1)
    raise AssertionError("Connector did not publish its private pairing-code file")


def _wait_device(
    client: ProductionCanary, device_id: str, status: str, timeout: float = 60
) -> dict[str, object]:
    def probe() -> object | None:
        response = client.request("/codex-api/v1/devices")
        body = response.json() if response.status == 200 else None
        items = body.get("items") if isinstance(body, dict) else None
        if isinstance(items, list):
            for item in items:
                if (
                    isinstance(item, dict)
                    and item.get("id") == device_id
                    and item.get("status") == status
                ):
                    return item
        return None

    value = client.eventually(
        f"Connector device becomes {status}", probe, timeout=timeout
    )
    assert isinstance(value, dict)
    return value


def _thread_snapshot(
    client: ProductionCanary, thread_id: str
) -> tuple[int, dict[str, object]]:
    response = client.request(f"/codex-api/v1/threads/{thread_id}")
    body = response.json() if response.status == 200 else None
    if (
        not isinstance(body, dict)
        or not isinstance(body.get("event_cursor"), str)
        or not body["event_cursor"].isdigit()
        or not isinstance(body.get("thread"), dict)
    ):
        raise AssertionError("thread detail did not return an atomic snapshot")
    return int(body["event_cursor"]), body["thread"]


def _managed_remote_thread_id(state_dir: Path, workspace: Path) -> str:
    from smoke import read_private_bytes

    value = _json_bytes(
        read_private_bytes(
            state_dir / "managed-threads.json", "managed thread state", 192 << 20
        ),
        "managed thread state",
    )
    if not isinstance(value, dict) or set(value) != {"version", "device_id", "threads"}:
        raise ValueError("managed thread state has an unexpected schema")
    threads = value.get("threads")
    if value.get("version") != 2 or not isinstance(threads, dict):
        raise ValueError("managed thread state is invalid")
    candidates = [
        remote_id
        for remote_id, item in threads.items()
        if isinstance(remote_id, str)
        and remote_id
        and isinstance(item, dict)
        and item.get("id") == remote_id
        and item.get("cwd") == str(workspace)
    ]
    if len(candidates) != 1:
        raise AssertionError("canary workspace is not bound to one remote thread")
    return candidates[0]


def _ordinary_cli(binary: FrozenFile, workspace: Path) -> str:
    binary.verify("Codex binary")
    completed = subprocess.run(
        [str(binary.path), "features", "list"],
        cwd=workspace,
        env=build_connector_environment(os.environ),
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    if completed.returncode != 0:
        raise AssertionError("ordinary Codex CLI coexistence probe failed")
    binary.verify("Codex binary")
    return hashlib.sha256(completed.stdout.encode()).hexdigest()


def _verify_binary_version(
    binary: FrozenFile, arguments: list[str], expected: str
) -> None:
    binary.verify("binary")
    completed = subprocess.run(
        [str(binary.path), *arguments],
        env=build_connector_environment(os.environ),
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    if completed.returncode != 0 or completed.stderr:
        raise AssertionError("binary version probe failed")
    if completed.stdout.strip() != expected:
        raise AssertionError("binary version differs from the frozen contract")
    binary.verify("binary")


def _stop_process(process: subprocess.Popen[bytes], timeout: float = 15) -> bool:
    descendants = _descendant_processes(process.pid)
    if process.poll() is None:
        process.send_signal(signal.SIGTERM)
        try:
            process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
    return _terminate_owned_processes(
        descendants, owner_session=process.pid
    )


def _connector_process(
    binary: FrozenFile, config: FrozenFile, codex: FrozenFile
) -> subprocess.Popen[bytes]:
    _verify_frozen_files(binary, codex, config)
    process = subprocess.Popen(
        build_connector_argv(binary.path, config.path),
        env=build_connector_environment(os.environ),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    try:
        _verify_frozen_files(binary, codex, config)
    except (OSError, ValueError):
        _stop_process(process)
        raise
    return process


def _device_absent(client: ProductionCanary, device_id: str) -> object | None:
    response = client.request("/codex-api/v1/devices")
    body = response.json() if response.status == 200 else None
    items = body.get("items") if isinstance(body, dict) else None
    if not isinstance(items, list):
        return None
    return (
        True
        if all(
            not isinstance(item, dict) or item.get("id") != device_id for item in items
        )
        else None
    )


def _approval_disappeared(client: ProductionCanary, approval_id: str) -> object | None:
    response = client.request("/codex-api/v1/approvals?state=pending")
    body = response.json() if response.status == 200 else None
    items = body.get("items") if isinstance(body, dict) else None
    if not isinstance(items, list):
        return None
    return (
        True
        if all(
            not isinstance(item, dict) or item.get("approval_id") != approval_id
            for item in items
        )
        else None
    )


def _wait_turn_delta(
    client: ProductionCanary,
    stream: WebSocketStream,
    thread_id: str,
    description: str,
) -> None:
    client.wait_browser_event(
        stream,
        description,
        lambda event: (
            event.get("type") == "turn.delta"
            and isinstance(event.get("data"), dict)
            and event["data"].get("thread_id") == thread_id
            and isinstance(event["data"].get("delta"), str)
            and bool(event["data"]["delta"])
        ),
        timeout=120,
    )


def _wait_turn_started(
    client: ProductionCanary,
    stream: WebSocketStream,
    thread_id: str,
) -> None:
    client.wait_browser_event(
        stream,
        "real turn/started is durable before steering",
        lambda event: (
            event.get("type") == "thread.updated"
            and isinstance(event.get("data"), dict)
            and event["data"].get("thread_id") == thread_id
            and event["data"].get("method") == "turn/started"
            and event["data"].get("status") == "running"
        ),
        timeout=60,
    )


def _read_canary_side_effect(path: Path, maximum: int = 64) -> bytes:
    parent = _open_directory_nofollow(path.parent)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path.name, flags, dir_fd=parent)
        try:
            opened = os.fstat(descriptor)
            named = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
            if (
                not stat.S_ISREG(opened.st_mode)
                or opened.st_uid != os.geteuid()
                or opened.st_nlink != 1
                or _file_signature(opened) != _file_signature(named)
                or opened.st_size > maximum
            ):
                raise AssertionError(
                    "approval side effect is not one safe regular file"
                )
            data = os.pread(descriptor, maximum + 1, 0)
            if len(data) > maximum or _file_signature(os.fstat(descriptor)) != (
                _file_signature(opened)
            ):
                raise AssertionError("approval side effect changed while it was read")
            return data
        finally:
            os.close(descriptor)
    finally:
        os.close(parent)


def _canary_path_absent(path: Path) -> bool:
    try:
        path.stat(follow_symlinks=False)
    except FileNotFoundError:
        return True
    return False


def _approval_prompt(kind: str, action: str, path: Path) -> str:
    quoted = shlex.quote(str(path))
    if kind == "command" and action == "approve":
        return (
            "Use the shell exactly once to run `printf approved > "
            f"{quoted}`. Do not use any other tool or path."
        )
    if kind == "file_change":
        return (
            "Use the patch/file editing tool exactly once to create the file "
            f"{quoted} containing exactly `denied`. Do not use the shell."
        )
    if kind == "command":
        return (
            "Use the shell exactly once to run `printf timeout > "
            f"{quoted}`. Do not use any other tool or path."
        )
    return (
        "Request an additional turn-scoped filesystem permission for the existing "
        f"directory {quoted}, then stop. Do not read, create, or change any file."
    )


def _wait_thread_idle(
    client: ProductionCanary, thread_id: str, description: str
) -> None:
    client.eventually(
        description,
        lambda: (
            thread
            if (thread := _thread_snapshot(client, thread_id)[1]).get("status")
            == "idle"
            else None
        ),
        timeout=120,
    )


def _is_expected_timeout(error: AssertionError, description: str) -> bool:
    return str(error) == f"timed out waiting for {description}"


def _verify_real_approvals(
    *,
    client: ProductionCanary,
    browser_stream: WebSocketStream,
    device_id: str,
    thread_id: str,
    remote_thread_id: str,
    workspace: Path,
    mutating_headers: dict[str, str],
) -> bool:
    scenarios = (
        ("command", "approve", workspace / "approval-approved.txt"),
        ("file_change", "deny", workspace / "approval-denied.txt"),
        ("command", "timeout", workspace / "approval-timeout.txt"),
        ("permission", "deny", workspace / "approval-permission-marker.txt"),
    )
    verified: dict[str, bool] = {
        "command_approve": False,
        "file_change_deny": False,
        "command_timeout": False,
        "permission_deny": False,
    }
    for index, (kind, action, target) in enumerate(scenarios, start=1):
        scenario = f"{kind}_{action}"
        _wait_thread_idle(client, thread_id, "approval scenario begins from idle")
        baseline_ids = client.pending_approval_ids(device_id, remote_thread_id)
        scenario_cursor = (
            client.browser_event_cursors[-1] if client.browser_event_cursors else 0
        )
        turn = client.request(
            f"/codex-api/v1/threads/{thread_id}/turns",
            method="POST",
            headers={
                **mutating_headers,
                "Idempotency-Key": f"real-canary-approval-turn-{index}",
            },
            body={"text": _approval_prompt(kind, action, target)},
        )
        turn_command_id = client.accepted_command(turn, "turn/start")
        description = f"new real {kind} approval is emitted by this canary device"
        try:
            event = client.wait_browser_event(
                browser_stream,
                description,
                lambda candidate, expected_kind=kind, baseline=frozenset(baseline_ids), after_cursor=scenario_cursor: (
                    candidate.get("type") == "approval.created"
                    and isinstance(candidate.get("cursor"), str)
                    and candidate["cursor"].isdigit()
                    and int(candidate["cursor"]) > after_cursor
                    and isinstance(candidate.get("data"), dict)
                    and candidate["data"].get("kind") == expected_kind
                    and candidate["data"].get("device_id") == device_id
                    and isinstance(candidate["data"].get("details"), dict)
                    and candidate["data"]["details"].get("threadId") == remote_thread_id
                    and isinstance(candidate["data"].get("approval_id"), str)
                    and candidate["data"]["approval_id"] not in baseline
                ),
                timeout=45,
            )
            event_approval = event.get("data")
            if not isinstance(event_approval, dict):
                raise AssertionError(  # noqa: TRY004 - acceptance assertion.
                    "approval event projection is invalid"
                )
            event_approval_id = event_approval.get("approval_id")
            if not isinstance(event_approval_id, str):
                raise AssertionError(  # noqa: TRY004 - acceptance assertion.
                    "approval event has no dynamic identity"
                )
            approval = client.unique_pending_approval(
                kind,
                device_id,
                remote_thread_id,
                baseline_ids,
                event_approval_id,
            )
        except ApprovalTriggerUnavailable:
            _wait_thread_idle(
                client,
                thread_id,
                "ambiguous approval scenario returns to idle by default deny",
            )
            client.command_event(
                browser_stream,
                turn_command_id,
                "turn/start",
                "ambiguous approval turn reaches a terminal state",
            )
            continue
        except AssertionError as error:
            if not _is_expected_timeout(error, description):
                raise
            _wait_thread_idle(
                client,
                thread_id,
                "untriggered approval scenario returns to idle",
            )
            client.command_event(
                browser_stream,
                turn_command_id,
                "turn/start",
                "untriggered approval turn reaches a terminal state",
            )
            continue
        approval_id = approval.get("approval_id")
        if not isinstance(approval_id, str):
            raise AssertionError(  # noqa: TRY004 - acceptance contract assertion.
                "approval has no dynamic identity"
            )
        if action in {"approve", "deny"}:
            decision = client.request(
                f"/codex-api/v1/approvals/{approval_id}/decision",
                method="POST",
                headers=mutating_headers,
                body={"decision": action},
            )
            if decision.status != 204:
                raise AssertionError("approval decision was rejected")
            conflict = client.request(
                f"/codex-api/v1/approvals/{approval_id}/decision",
                method="POST",
                headers=mutating_headers,
                body={"decision": "deny" if action == "approve" else "approve"},
            )
            if conflict.status != 409:
                raise AssertionError(
                    "conflicting one-shot approval decision was accepted"
                )
        else:
            client.eventually(
                "real command approval defaults to deny on timeout",
                lambda approval_id=approval_id: _approval_disappeared(
                    client, approval_id
                ),
                timeout=45,
            )
            stale = client.request(
                f"/codex-api/v1/approvals/{approval_id}/decision",
                method="POST",
                headers=mutating_headers,
                body={"decision": "approve"},
            )
            if stale.status not in {404, 409, 410}:
                raise AssertionError("timed-out approval accepted a stale decision")
        _wait_thread_idle(client, thread_id, "approval turn returns to idle")
        client.command_event(
            browser_stream,
            turn_command_id,
            "turn/start",
            "approval turn/start reaches a terminal state",
        )
        if (
            kind == "command"
            and action == "approve"
            and _read_canary_side_effect(target) != b"approved"
        ):
            raise AssertionError("approved command side effect differs")
        if kind == "file_change" and not _canary_path_absent(target):
            raise AssertionError("denied file-change side effect occurred")
        if action == "timeout" and not _canary_path_absent(target):
            raise AssertionError("timed-out command side effect occurred")
        if kind == "permission" and not _canary_path_absent(target):
            raise AssertionError("permission denial produced an unexpected side effect")
        verified[scenario] = True
    complete = all(verified.values())
    client.evidence.approvals = {
        "status": "verified" if complete else "externally_blocked",
        "verified": complete,
        "command_approve": verified["command_approve"],
        "file_change_deny": verified["file_change_deny"],
        "command_timeout": verified["command_timeout"],
        "permission_deny": verified["permission_deny"],
    }
    if not complete:
        client.evidence.approvals["reason"] = (
            "one_or_more_real_approval_classes_not_verified"
        )
    return complete


def _run_control_flow(
    *,
    client: ProductionCanary,
    connector_binary: FrozenFile,
    connector_config: FrozenFile,
    state_dir: Path,
    workspace: Path,
    codex_binary: FrozenFile,
    codex_home: Path,
    mutating_headers: dict[str, str],
    browser_stream: WebSocketStream,
) -> None:
    process: subprocess.Popen[bytes] | None = None
    device_id = ""
    thread_id = ""
    crash_children: set[int] = set()
    try:
        before_protected = snapshot_protected_files(codex_home)
        before_cli = _ordinary_cli(codex_binary, workspace)
        process = _connector_process(
            connector_binary, connector_config, codex_binary
        )
        client.evidence.cleanup["connector_processes"] = False
        code_path = state_dir / "pairing-code.json"
        _wait_for_file(code_path, 60)
        pairing_code = read_pairing_code(code_path)
        claim = client.request(
            "/codex-api/v1/pairings/claim",
            method="POST",
            headers=mutating_headers,
            body={"code": pairing_code},
        )
        claim_body = claim.json() if claim.status == 200 else None
        if not isinstance(claim_body, dict) or not isinstance(
            claim_body.get("device_id"), str
        ):
            raise AssertionError(  # noqa: TRY004 - acceptance contract assertion.
                "authenticated pairing claim failed"
            )
        device_id = claim_body["device_id"]
        pairing_code = ""
        client.evidence.cleanup["device"] = False
        client.evidence.mark("pair_claim")
        device = _wait_device(client, device_id, "online")
        if (
            device.get("connector_version") != CONNECTOR_VERSION
            or device.get("codex_version") != CODEX_VERSION
            or device.get("workspace_roots") != [str(workspace)]
        ):
            raise AssertionError("device Hello does not match the pinned canary")
        client.evidence.mark("device_wss")

        sync = client.request(
            f"/codex-api/v1/devices/{device_id}/models/sync",
            method="POST",
            headers={**mutating_headers, "Idempotency-Key": "real-canary-model-sync"},
        )
        command_id = client.accepted_command(sync, "model/list")
        client.command_event(
            browser_stream, command_id, "model/list", "real model/list succeeds"
        )

        def models() -> object | None:
            response = client.request(f"/codex-api/v1/devices/{device_id}/models")
            body = response.json() if response.status == 200 else None
            return body if choose_dynamic_model(body) is not None else None

        catalog = client.eventually("real model catalog is cached", models, timeout=60)
        model = choose_dynamic_model(catalog)
        if model is None:
            raise AssertionError("real Codex returned no usable model")
        client.evidence.mark("dynamic_model_sync")

        thread_list = client.request(
            f"/codex-api/v1/devices/{device_id}/threads/sync",
            method="POST",
            headers={**mutating_headers, "Idempotency-Key": "real-canary-thread-list"},
        )
        command_id = client.accepted_command(thread_list, "thread/list")
        client.command_event(
            browser_stream, command_id, "thread/list", "real thread/list succeeds"
        )
        cached_threads = client.request(f"/codex-api/v1/devices/{device_id}/threads")
        if cached_threads.status != 200:
            raise AssertionError("managed thread cache is unreadable")

        started = client.request(
            f"/codex-api/v1/devices/{device_id}/threads",
            method="POST",
            headers={**mutating_headers, "Idempotency-Key": "real-canary-thread-start"},
            body={"cwd": str(workspace), "model": model},
        )
        started_body = started.json() if started.status == 202 else None
        if not isinstance(started_body, dict) or not isinstance(
            started_body.get("id"), str
        ):
            raise AssertionError(  # noqa: TRY004 - acceptance contract assertion.
                "thread/start did not create a managed binding"
            )
        thread_id = started_body["id"]

        def idle_thread() -> object | None:
            try:
                _, thread = _thread_snapshot(client, thread_id)
            except AssertionError:
                return None
            return thread if thread.get("status") == "idle" else None

        client.eventually("real thread/start succeeds", idle_thread, timeout=120)
        client.evidence.rpc("thread/start")
        _, bound = _thread_snapshot(client, thread_id)
        if bound.get("cwd") != str(workspace) or bound.get("model") != model:
            raise AssertionError("managed thread lost its dynamic model or workspace")

        remote_thread_id = _managed_remote_thread_id(state_dir, workspace)
        read = client.request(
            f"/codex-api/v1/threads/{thread_id}/sync",
            method="POST",
            headers={**mutating_headers, "Idempotency-Key": "real-canary-thread-read"},
        )
        command_id = client.accepted_command(read, "thread/read")
        client.command_event(
            browser_stream, command_id, "thread/read", "real thread/read succeeds"
        )

        turn = client.request(
            f"/codex-api/v1/threads/{thread_id}/turns",
            method="POST",
            headers={**mutating_headers, "Idempotency-Key": "real-canary-turn-start"},
            body={
                "text": (
                    "Reply with a brief explanation of the text in this prompt. "
                    "Do not call tools and do not read or change files. Continue until interrupted."
                )
            },
        )
        turn_command_id = client.accepted_command(turn, "turn/start")

        _wait_turn_started(client, browser_stream, thread_id)

        def steer_when_active() -> object | None:
            response = client.request(
                f"/codex-api/v1/threads/{thread_id}/turns/current/steer",
                method="POST",
                headers={
                    **mutating_headers,
                    "Idempotency-Key": "real-canary-turn-steer",
                },
                body={"text": "Continue producing text until I interrupt this turn."},
            )
            if response.status == 202:
                return response
            if response.status == 409:
                return None
            raise AssertionError("turn/steer returned an unexpected status")

        steer = client.eventually(
            "real turn/steer is accepted while turn/started is active",
            steer_when_active,
            timeout=30,
        )
        assert isinstance(steer, Result)
        steer_id = client.accepted_command(steer, "turn/steer")
        _wait_turn_delta(
            client,
            browser_stream,
            thread_id,
            "real assistant delta streams over browser WebSocket",
        )
        client.evidence.mark("turn_streaming")
        interrupt = client.request(
            f"/codex-api/v1/threads/{thread_id}/turns/current/interrupt",
            method="POST",
            headers={
                **mutating_headers,
                "Idempotency-Key": "real-canary-turn-interrupt",
            },
        )
        interrupt_id = client.accepted_command(interrupt, "turn/interrupt")
        client.command_event(
            browser_stream, steer_id, "turn/steer", "real turn/steer succeeds"
        )
        client.command_event(
            browser_stream,
            interrupt_id,
            "turn/interrupt",
            "real turn/interrupt succeeds",
        )
        client.command_event(
            browser_stream,
            turn_command_id,
            "turn/start",
            "real turn/start reaches a successful terminal state",
        )

        resume = client.request(
            f"/codex-api/v1/threads/{thread_id}/resume",
            method="POST",
            headers={
                **mutating_headers,
                "Idempotency-Key": "real-canary-thread-resume",
            },
        )
        command_id = client.accepted_command(resume, "thread/resume")
        client.command_event(
            browser_stream, command_id, "thread/resume", "real thread/resume succeeds"
        )

        approvals_complete = _verify_real_approvals(
            client=client,
            browser_stream=browser_stream,
            device_id=device_id,
            thread_id=thread_id,
            remote_thread_id=remote_thread_id,
            workspace=workspace,
            mutating_headers=mutating_headers,
        )

        cursor_before = client.browser_event_cursors[-1]
        try:
            browser_stream.close()
        finally:
            client.evidence.cleanup["browser_websocket"] = True
        offline_read = client.request(
            f"/codex-api/v1/threads/{thread_id}/sync",
            method="POST",
            headers={
                **mutating_headers,
                "Idempotency-Key": "real-canary-browser-offline-read",
            },
        )
        offline_command_id = client.accepted_command(offline_read, "thread/read")
        client.eventually(
            "offline browser command completes in the durable thread cache",
            lambda: (
                thread
                if (thread := _thread_snapshot(client, thread_id)[1]).get("status")
                == "idle"
                else None
            ),
            timeout=120,
        )
        cookie_header = "; ".join(
            f"{cookie.name}={cookie.value}" for cookie in client.cookies
        )
        status, _, resumed_browser = client.open_websocket(
            f"/codex-ws/browser?cursor={cursor_before}",
            origin=client.origin,
            cookie=cookie_header,
        )
        if status != 101 or resumed_browser is None:
            raise AssertionError("browser cursor reconnect did not upgrade")
        browser_stream = resumed_browser
        client.command_event(
            browser_stream,
            offline_command_id,
            "thread/read",
            "browser cursor replays the exact command missed while disconnected",
        )
        if client.browser_event_cursors[-1] <= cursor_before:
            raise AssertionError("browser replay did not advance the durable cursor")
        client.evidence.mark("cross_replica_browser_cursor_replay")

        cli_during = _ordinary_cli(codex_binary, workspace)
        if cli_during != before_cli:
            raise AssertionError("ordinary CLI changed while Connector was active")
        client.evidence.mark("ordinary_cli_during")

        assert_refresh_only_credentials(state_dir)
        spool_before = read_spool_meta(state_dir)
        crash_children = _descendant_processes(process.pid)
        if not crash_children:
            raise AssertionError("Connector has no owned app-server process to clean")
        process.send_signal(signal.SIGUSR1)
        client.eventually(
            "production canary crash hook is armed",
            lambda: _read_crash_marker(state_dir),
            timeout=10,
        )
        replay_read = client.request(
            f"/codex-api/v1/threads/{thread_id}/sync",
            method="POST",
            headers={
                **mutating_headers,
                "Idempotency-Key": "real-canary-exact-ack-replay",
            },
        )
        replay_command_id = client.accepted_command(replay_read, "thread/read")
        replay_sequence, replay_event_id = wait_for_unacked_command_record(
            state_dir, replay_command_id
        )
        if process.wait(timeout=15) != 86:
            raise AssertionError(
                "canary Connector did not crash at the frozen ACK point"
            )
        if not _terminate_owned_processes(crash_children):
            raise AssertionError("crashed Connector left an owned app-server process")
        crash_children.clear()
        frozen_record = read_spool_records(state_dir).get(replay_sequence)
        if frozen_record != (replay_event_id, "command_ack", replay_command_id):
            raise AssertionError("exact unacknowledged ACK record was not preserved")
        spool_crashed = read_spool_meta(state_dir)
        if (
            spool_crashed[0] <= spool_before[0]
            or spool_crashed[1] >= replay_sequence
            or replay_sequence != spool_crashed[0] - 1
        ):
            raise AssertionError(
                "crash point did not preserve one assigned unacked ACK"
            )

        restart_cursor = client.browser_event_cursors[-1]
        process = _connector_process(connector_binary, connector_config, codex_binary)
        client.wait_browser_event(
            browser_stream,
            "restart obtains a new authenticated device WSS connection",
            lambda event: (
                event.get("type") == "device.updated"
                and isinstance(event.get("cursor"), str)
                and event["cursor"].isdigit()
                and int(event["cursor"]) > restart_cursor
                and isinstance(event.get("data"), dict)
                and event["data"].get("id") == device_id
                and event["data"].get("status") == "online"
            ),
            timeout=60,
        )
        client.wait_browser_event(
            browser_stream,
            "server reconciles the old-epoch command before terminal replay",
            lambda event: (
                event.get("type") == "command.updated"
                and isinstance(event.get("data"), dict)
                and isinstance(event["data"].get("command"), dict)
                and event["data"]["command"].get("id") == replay_command_id
                and event["data"]["command"].get("state") == "failed"
                and event["data"]["command"].get("error_code")
                == "epoch_replaced_indeterminate"
            ),
            timeout=60,
        )
        reconciliation_cursor = client.browser_event_cursors[-1]
        replay_terminal = client.command_event(
            browser_stream,
            replay_command_id,
            "thread/read",
            "server commits the terminal ACK replay for the exact command",
        )
        replay_terminal_cursor = client.browser_event_cursors[-1]
        if (
            replay_terminal.get("state") != "succeeded"
            or replay_terminal_cursor <= reconciliation_cursor
        ):
            raise AssertionError("server ACK replay terminal evidence is invalid")
        spool_after = wait_for_replayed_record_ack(
            state_dir,
            replay_sequence,
            replay_event_id,
            replay_command_id,
        )
        if (
            spool_after[0] < spool_crashed[0]
            or spool_after[1] < replay_sequence
            or spool_after[2] <= spool_before[2]
        ):
            raise AssertionError("Connector cursors did not continue across ACK replay")
        assert_refresh_only_credentials(state_dir)
        client.evidence.mark("connector_restart_exact_ack_replay")
        client.evidence.mark("connector_restart_sequence_continuity")
        client.evidence.mark("restart_refresh_credential_new_wss")

        for path in DANGEROUS_HTTP_PATHS:
            denied = client.request(
                path, method="POST", headers=mutating_headers, body={}
            )
            if denied.status != 404:
                raise AssertionError("dangerous raw RPC HTTP route did not fail closed")
        client.evidence.mark("dangerous_rpc_http_404")

        revoke = client.request(
            f"/codex-api/v1/devices/{device_id}",
            method="DELETE",
            headers=mutating_headers,
        )
        if revoke.status != 204:
            raise AssertionError("device revocation failed")
        client.wait_browser_event(
            browser_stream,
            "device revocation is committed to the durable browser stream",
            lambda event: (
                event.get("type") == "device.updated"
                and isinstance(event.get("data"), dict)
                and event["data"].get("id") == device_id
                and event["data"].get("status") == "revoked"
            ),
            timeout=30,
        )
        _stop_process(process)
        reconnects_before = read_token_reconnects(state_dir)
        process = _connector_process(connector_binary, connector_config, codex_binary)
        client.eventually(
            "revoked refresh credential is rejected by the token endpoint",
            lambda: (
                value
                if (value := read_token_reconnects(state_dir)) > reconnects_before
                else None
            ),
            timeout=15,
        )
        client.eventually(
            "revoked device remains absent after reconnect attempts",
            lambda: _device_absent(client, device_id),
            timeout=15,
        )
        _stop_process(process)
        client.evidence.mark("revoke_rejects_old_credential")
        client.evidence.cleanup["device"] = True
        device_id = ""

        after_cli = _ordinary_cli(codex_binary, workspace)
        if after_cli != before_cli:
            raise AssertionError("ordinary CLI changed after Connector cleanup")
        client.evidence.mark("ordinary_cli_before_during_after")
        if snapshot_protected_files(codex_home) != before_protected:
            raise AssertionError("Codex auth, config, or plugin state changed")
        client.evidence.mark("codex_protected_hashes_unchanged")
        if set(client.evidence.rpc_methods) != EXPECTED_RPC_METHODS:
            raise AssertionError("the exact eight-method RPC canary was incomplete")
        if not approvals_complete:
            raise ExternalVerificationBlocked(
                "permission approval cannot be deterministically requested through the public text-only RPC"
            )
    finally:
        process_clean = process is None or _stop_process(process)
        processes_clean = not crash_children or _terminate_owned_processes(
            crash_children
        )
        client.evidence.cleanup["connector_processes"] = (
            process_clean
            and (process is None or process.poll() is not None)
            and processes_clean
        )
        if device_id:
            try:
                cleanup = client.request(
                    f"/codex-api/v1/devices/{device_id}",
                    method="DELETE",
                    headers=mutating_headers,
                )
                client.evidence.cleanup["device"] = cleanup.status == 204
            except (OSError, ValueError):
                client.evidence.cleanup["device"] = False
        browser_stream.close()


def _write_connector_config(
    destination: Path,
    *,
    origin: str,
    state_dir: Path,
    workspace: Path,
    codex_binary: Path,
) -> None:
    parsed = urllib.parse.urlsplit(origin)
    wss_scheme = "wss" if parsed.scheme == "https" else "ws"
    value = {
        "control_url": f"{wss_scheme}://{parsed.netloc}/codex-ws/device",
        "pairing_url": f"{origin}/codex-api/v1/device-pairings/start",
        "token_url": f"{origin}/codex-api/v1/device/connect-token",
        "display_name": "Disposable production canary",
        "state_dir": str(state_dir),
        "workspace_roots": [str(workspace)],
        "sandbox_cap": "workspace-write",
        "codex_binary": str(codex_binary),
        "codex_version": CODEX_VERSION,
        "schema_digest": SCHEMA_DIGEST,
        "heartbeat_interval": "5s",
        "approval_timeout": "30s",
        "pairing_poll_interval": "500ms",
        "reconnect_min": "250ms",
        "reconnect_max": "5s",
    }
    _write_exclusive_file(
        destination,
        (
            json.dumps(
                value,
                ensure_ascii=True,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        ).encode("ascii"),
    )


def _fsync_created_directory(path: Path) -> None:
    descriptor = _open_directory_nofollow(path)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    parent = _open_directory_nofollow(path.parent)
    try:
        os.fsync(parent)
    finally:
        os.close(parent)


def _remove_private_run_directory(run_dir: Path | None) -> bool:
    if run_dir is None:
        return True
    try:
        metadata = run_dir.stat(follow_symlinks=False)
        if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.geteuid():
            return False
        shutil.rmtree(run_dir)
        parent = _open_directory_nofollow(run_dir.parent)
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
    except FileNotFoundError:
        return True
    except (OSError, ValueError):
        return False
    return not run_dir.exists()


def _clear_control_client(client: ProductionCanary | None) -> None:
    if client is None:
        return
    for cookie in tuple(client.cookies):
        try:
            client.cookies.clear(cookie.domain, cookie.path, cookie.name)
        except KeyError:
            pass
    client.opener.addheaders = []
    if client.session_mutating_headers is not None:
        client.session_mutating_headers.clear()
        client.session_mutating_headers = None
    client.clear_leak_sentinel()


def _close_auth_descriptor(descriptor: int) -> bool:
    try:
        os.close(descriptor)
    except OSError:
        return False
    return True


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Operator-started real production Connector canary (destructive cleanup)"
    )
    parser.add_argument("--base-url", required=True)
    parser.add_argument(
        "--auth-fd",
        required=True,
        type=int,
        help="inherited descriptor for one owned 0600 auth JSON file",
    )
    parser.add_argument("--connector-binary", required=True)
    parser.add_argument("--expected-connector-sha256", required=True)
    parser.add_argument("--codex-binary", required=True)
    parser.add_argument("--expected-codex-sha256", required=True)
    parser.add_argument("--codex-home", required=True)
    parser.add_argument("--private-run-dir", required=True)
    parser.add_argument("--evidence-dir", required=True)
    parser.add_argument(
        "--confirm-real-production-canary",
        action="store_true",
        help="required acknowledgement that this pairs and revokes a real device",
    )
    args = parser.parse_args(argv)
    evidence = CanaryEvidence()
    evidence.cleanup = {
        "auth_descriptor": False,
        "browser_websocket": True,
        "config": True,
        "connector_processes": True,
        "control_session": True,
        "device": True,
        "run_directory": True,
        "state": True,
        "workspace": True,
    }
    destination: Path | None = None
    client: ProductionCanary | None = None
    mutating_headers: dict[str, str] | None = None
    run_dir: Path | None = None
    evidence_dir: Path | None = None
    auth: AuthMaterial | None = None
    connector_binary: FrozenFile | None = None
    codex_binary: FrozenFile | None = None
    connector_config: FrozenFile | None = None
    access_token = ""
    user_id = ""
    auth_descriptor_open = True
    result = 1
    try:
        if not args.confirm_real_production_canary:
            raise ValueError("real production canary requires explicit confirmation")
        origin = args.base_url.rstrip("/")
        parsed = urllib.parse.urlsplit(origin)
        if (
            parsed.scheme != "https"
            or not parsed.netloc
            or parsed.path
            or parsed.query
            or parsed.fragment
            or parsed.username is not None
            or parsed.password is not None
        ):
            raise ValueError("--base-url must be one credential-free HTTPS origin")
        try:
            auth = read_auth_material_fd(args.auth_fd)
        finally:
            evidence.cleanup["auth_descriptor"] = _close_auth_descriptor(args.auth_fd)
            auth_descriptor_open = False
        if (
            SHA256_RE.fullmatch(args.expected_connector_sha256) is None
            or SHA256_RE.fullmatch(args.expected_codex_sha256) is None
        ):
            raise ValueError("expected binary SHA-256 values are invalid")
        connector_binary = open_frozen_file(
            args.connector_binary,
            "Connector binary",
            require_executable=True,
        )
        codex_binary = open_frozen_file(
            args.codex_binary,
            "Codex binary",
            require_executable=True,
        )
        if connector_binary.identity.sha256 != args.expected_connector_sha256:
            raise ValueError("Connector binary SHA-256 differs")
        if codex_binary.identity.sha256 != args.expected_codex_sha256:
            raise ValueError("Codex binary SHA-256 differs")
        evidence.binary_sha256 = {
            "connector": connector_binary.identity.sha256,
            "codex": codex_binary.identity.sha256,
        }
        _verify_binary_version(
            connector_binary,
            ["-version"],
            CANARY_CONNECTOR_BINARY_VERSION,
        )
        _verify_binary_version(
            codex_binary, ["--version"], f"codex-cli {CODEX_VERSION}"
        )
        evidence.mark("binary_identity_and_version")
        codex_home = canonical_absolute_path(args.codex_home, "Codex home")
        run_dir = create_private_run_directory(args.private_run_dir)
        for name in ("config", "run_directory", "state", "workspace"):
            evidence.cleanup[name] = False
        evidence_dir = _ensure_private_directory(Path(args.evidence_dir), create=False)
        state_dir = run_dir / "state"
        workspace = run_dir / "workspace"
        state_dir.mkdir(mode=0o700, exist_ok=False)
        workspace.mkdir(mode=0o700, exist_ok=False)
        _fsync_created_directory(state_dir)
        _fsync_created_directory(workspace)
        config = run_dir / "connector.json"
        _write_connector_config(
            config,
            origin=origin,
            state_dir=state_dir,
            workspace=workspace,
            codex_binary=codex_binary.path,
        )
        connector_config = open_frozen_file(
            config,
            "Connector config",
            maximum=65_536,
        )
        client = ProductionCanary(origin, evidence)
        if auth is None:
            raise ValueError("authentication material is unavailable")
        access_token, user_id = _login_to_sub2api(client, auth)
        auth.clear()
        auth = None
        mutating_headers, browser_stream = _session_exchange(
            client, access_token, user_id
        )
        evidence.cleanup["control_session"] = False
        access_token = ""
        user_id = ""
        _run_control_flow(
            client=client,
            connector_binary=connector_binary,
            connector_config=connector_config,
            state_dir=state_dir,
            workspace=workspace,
            codex_binary=codex_binary,
            codex_home=codex_home,
            mutating_headers=mutating_headers,
            browser_stream=browser_stream,
        )
        if evidence.approvals.get("verified") is not True:
            raise ExternalVerificationBlocked("approval verification is incomplete")
        result = 0
    except ExternalVerificationBlocked:
        result = 2
    except (AssertionError, OSError, ValueError, json.JSONDecodeError):
        result = 1
    finally:
        access_token = ""
        user_id = ""
        if auth_descriptor_open:
            evidence.cleanup["auth_descriptor"] = _close_auth_descriptor(args.auth_fd)
        if auth is not None:
            auth.clear()
        if client is not None and mutating_headers is not None:
            try:
                logout = client.request(
                    "/codex-api/v1/session/logout",
                    method="POST",
                    headers=mutating_headers,
                )
                evidence.cleanup["control_session"] = logout.status in {204, 401}
            except (OSError, ValueError):
                evidence.cleanup["control_session"] = False
        elif client is not None and client.session_mutating_headers is not None:
            try:
                logout = client.request(
                    "/codex-api/v1/session/logout",
                    method="POST",
                    headers=client.session_mutating_headers,
                )
                evidence.cleanup["control_session"] = logout.status in {204, 401}
            except (OSError, ValueError):
                evidence.cleanup["control_session"] = False
        if connector_binary is not None and codex_binary is not None:
            try:
                if connector_config is not None:
                    _verify_frozen_files(
                        connector_binary,
                        codex_binary,
                        connector_config,
                    )
                else:
                    connector_binary.verify("Connector binary")
                    codex_binary.verify("Codex binary")
                evidence.mark("binary_config_identity_final")
            except (OSError, ValueError):
                result = 1
        for frozen in (connector_config, codex_binary, connector_binary):
            if frozen is not None:
                frozen.close()
        removed = _remove_private_run_directory(run_dir)
        evidence.cleanup["state"] = removed
        evidence.cleanup["workspace"] = removed
        evidence.cleanup["config"] = removed
        evidence.cleanup["run_directory"] = removed
        if run_dir is None:
            evidence.cleanup["connector_processes"] = True
            evidence.cleanup["device"] = True
        _clear_control_client(client)
        mutating_headers = None
        cleanup_complete = all(evidence.cleanup.values())
        if not cleanup_complete:
            result = 1
        evidence.finish(
            "passed"
            if result == 0
            else "externally_blocked"
            if result == 2
            else "failed"
        )
        try:
            if evidence_dir is None:
                evidence_dir = _ensure_private_directory(
                    Path(args.evidence_dir), create=False
                )
            destination = write_redacted_evidence(evidence_dir, evidence)
        except (OSError, ValueError):
            destination = None
    if result == 1:
        print("not ok - production Connector canary failed", file=sys.stderr)
        return 1
    if result == 2:
        print(
            "blocked - production Connector canary has unverified real approvals",
            file=sys.stderr,
        )
        return 2
    print("ok - redacted real production Connector canary passed")
    if destination is not None:
        print("ok - redacted evidence written")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
