#!/usr/bin/env python3
"""Fixed, privacy-safe production smoke checks for an image-only rollout."""

from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import os
import re
import signal
import ssl
import stat
import sys
import uuid
from datetime import datetime, timezone
from pathlib import PurePosixPath
from typing import Any, Callable, NamedTuple, NoReturn
from urllib.parse import SplitResult, urlsplit

SCHEMA_VERSION = "image-rollout-smoke-result-v1"
TARGET_RELEASE = "0.1.0-bootstrap.20260813.1"
TARGET_VCS_REF = "d518538f6d36d0c2ff94b7b895798431ee981d6e585aac4732a6a2a2cf0ab8a9"
CHECK_CATALOG = (
    {"method": "GET", "name": "pwa_root", "path": "/codex/", "status": [200]},
    {
        "method": "GET",
        "name": "pwa_manifest",
        "path": "/codex/manifest.webmanifest",
        "status": [200],
    },
    {
        "method": "GET",
        "name": "control_live",
        "path": "/codex-api/v1/health/live",
        "status": [200],
    },
    {
        "method": "GET",
        "name": "control_ready",
        "path": "/codex-api/v1/health/ready",
        "status": [200],
    },
    {
        "method": "GET",
        "name": "anonymous_session_rejection",
        "path": "/codex-api/v1/session",
        "status": [401, 403],
    },
    {
        "method": "GET",
        "name": "anonymous_browser_websocket_rejection",
        "path": "/codex-ws/browser",
        "status": [401, 403],
    },
    {
        "method": "GET",
        "name": "anonymous_device_websocket_rejection",
        "path": "/codex-ws/device",
        "status": [401, 403],
    },
    {
        "method": "GET",
        "name": "websocket_root_guard",
        "path": "/codex-ws",
        "status": [404],
    },
    {
        "method": "GET",
        "name": "websocket_adjacent_guard",
        "path": "/codex-ws/adjacent",
        "status": [404],
    },
)
CHECK_COUNT = len(CHECK_CATALOG)
CHECK_CATALOG_SHA256 = "3056c52085fbed3d43437a111ee73be56c051a62df7fd3aceef9fca1c54225a1"
EXPECTED_READY_CHECKS = {
    "database": "ok",
    "database_migrations": "ok",
    "redis": "ok",
    "sub2api_contract": "ok",
}
MAX_ORIGIN_BYTES = 4096
MAX_CHALLENGE_BYTES = 64 * 1024
MAX_EVIDENCE_BYTES = 32 * 1024 * 1024
MAX_RESPONSE_BYTES = 256 * 1024
REQUEST_TIMEOUT_SECONDS = 5.0
USER_AGENT = "sub2api-codex-control-image-rollout-smoke/1"
GENERIC_ERROR = "image-rollout-smoke: failed"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
TIMESTAMP_RE = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.[0-9]{1,6})?Z$"
)


class SmokeError(RuntimeError):
    """A deliberately detail-free smoke failure."""


class PrivateArgumentParser(argparse.ArgumentParser):
    """Reject invalid arguments without echoing user-controlled values."""

    def error(self, _message: str) -> NoReturn:
        fail()


class Origin(NamedTuple):
    host: str
    port: int
    authority: str
    value: str


class Response(NamedTuple):
    status: int
    headers: dict[str, tuple[str, ...]]
    body: bytes


class Inputs(NamedTuple):
    origin: Origin
    challenge_sha256: str
    target_binding_sha256: str


def fail() -> NoReturn:
    raise SmokeError(GENERIC_ERROR)


def canonical_json_bytes(value: Any, *, newline: bool = False) -> bytes:
    try:
        encoded = json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError):
        fail()
    return encoded + (b"\n" if newline else b"")


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="microseconds").replace(
        "+00:00", "Z"
    )


def parse_timestamp(value: Any) -> datetime:
    if not isinstance(value, str) or TIMESTAMP_RE.fullmatch(value) is None:
        fail()
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        fail()
    if parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        fail()
    return parsed


def _reject_constant(_value: str) -> NoReturn:
    fail()


def _bounded_integer(value: str) -> int:
    if len(value) > 20:
        fail()
    return int(value)


def _reject_float(_value: str) -> NoReturn:
    fail()


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            fail()
        result[key] = value
    return result


def decode_canonical_json(raw: bytes) -> Any:
    try:
        value = json.loads(
            raw.decode("ascii"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
            parse_float=_reject_float,
            parse_int=_bounded_integer,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, SmokeError):
        fail()
    if raw != canonical_json_bytes(value, newline=True):
        fail()
    return value


def _validate_file_metadata(metadata: os.stat_result, maximum: int) -> None:
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_nlink != 1
        or metadata.st_uid != os.geteuid()
        or metadata.st_size <= 0
        or metadata.st_size > maximum
    ):
        fail()


def _validate_directory_metadata(metadata: os.stat_result) -> None:
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid not in {0, os.geteuid()}
        or stat.S_IMODE(metadata.st_mode) & 0o022
    ):
        fail()


def _stable_metadata(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def secure_read(path_value: str, maximum: int) -> bytes:
    if (
        not path_value.startswith("/")
        or path_value.startswith("//")
        or "\x00" in path_value
    ):
        fail()
    pure = PurePosixPath(path_value)
    if str(pure) != path_value or not pure.name or any(
        part in {"", ".", ".."} for part in pure.parts[1:]
    ):
        fail()
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    directory = getattr(os, "O_DIRECTORY", 0)
    if nofollow == 0 or directory == 0:
        fail()
    parent_fd = os.open("/", flags | directory)
    file_fd: int | None = None
    try:
        _validate_directory_metadata(os.fstat(parent_fd))
        for component in pure.parts[1:-1]:
            parent_before = os.fstat(parent_fd)
            _validate_directory_metadata(parent_before)
            next_fd = os.open(
                component,
                flags | directory | nofollow,
                dir_fd=parent_fd,
            )
            child_metadata = os.fstat(next_fd)
            _validate_directory_metadata(child_metadata)
            parent_after = os.fstat(parent_fd)
            _validate_directory_metadata(parent_after)
            if _stable_metadata(parent_before) != _stable_metadata(parent_after):
                os.close(next_fd)
                fail()
            os.close(parent_fd)
            parent_fd = next_fd
        parent_before = os.fstat(parent_fd)
        _validate_directory_metadata(parent_before)
        file_fd = os.open(pure.name, flags | nofollow, dir_fd=parent_fd)
        before = os.fstat(file_fd)
        _validate_file_metadata(before, maximum)
        chunks: list[bytes] = []
        remaining = maximum + 1
        while remaining > 0:
            chunk = os.read(file_fd, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        after = os.fstat(file_fd)
        _validate_file_metadata(after, maximum)
        parent_after = os.fstat(parent_fd)
        _validate_directory_metadata(parent_after)
        if (
            len(raw) != before.st_size
            or len(raw) > maximum
            or _stable_metadata(before) != _stable_metadata(after)
            or _stable_metadata(parent_before) != _stable_metadata(parent_after)
        ):
            fail()
        return raw
    except (OSError, SmokeError):
        fail()
    finally:
        if file_fd is not None:
            os.close(file_fd)
        os.close(parent_fd)


def require_object(value: Any, keys: set[str]) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        fail()
    return value


def require_sha(value: Any) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        fail()
    return value


def parse_origin(value: Any) -> Origin:
    if not isinstance(value, str) or not value or not value.isascii():
        fail()
    parsed: SplitResult = urlsplit(value)
    if (
        parsed.scheme != "https"
        or parsed.username is not None
        or parsed.password is not None
        or parsed.hostname is None
        or parsed.path
        or parsed.query
        or parsed.fragment
        or parsed.netloc != parsed.netloc.lower()
    ):
        fail()
    try:
        port = parsed.port or 443
    except ValueError:
        fail()
    if not 1 <= port <= 65535 or (port == 443 and parsed.netloc.endswith(":443")):
        fail()
    canonical = f"https://{parsed.netloc}"
    if value != canonical:
        fail()
    return Origin(parsed.hostname, port, parsed.netloc, canonical)


def _load_argument(path_value: str, maximum: int) -> tuple[Any, bytes]:
    raw = secure_read(path_value, maximum)
    return decode_canonical_json(raw), raw


def validate_inputs(args: argparse.Namespace, now: datetime) -> Inputs:
    challenge, challenge_raw = _load_argument(args.challenge, MAX_CHALLENGE_BYTES)
    plan, plan_raw = _load_argument(args.plan, MAX_EVIDENCE_BYTES)
    baseline, baseline_raw = _load_argument(args.baseline, MAX_EVIDENCE_BYTES)
    running, running_raw = _load_argument(args.running, MAX_EVIDENCE_BYTES)
    invariants, invariants_raw = _load_argument(args.invariants, MAX_EVIDENCE_BYTES)
    origin_value, _origin_raw = _load_argument(args.origin_file, MAX_ORIGIN_BYTES)

    plan = require_object(
        plan,
        {
            "allowed_changes",
            "artifact_manifest_sha256",
            "command",
            "format_version",
            "new",
            "new_compose",
            "new_compose_sha256",
            "old",
            "old_compose_sha256",
            "service_components",
            "status",
        },
    )
    new_identity = require_object(plan.get("new"), {"images", "release", "vcs_ref"})
    images = require_object(
        new_identity.get("images"), {"control-api", "postgres-tools", "pwa"}
    )
    for image_id in images.values():
        if (
            not isinstance(image_id, str)
            or re.fullmatch(r"sha256:[0-9a-f]{64}", image_id) is None
        ):
            fail()
    if (
        plan.get("command") != "plan"
        or plan.get("format_version") != 1
        or plan.get("status") != "admitted"
        or new_identity.get("release") != TARGET_RELEASE
        or new_identity.get("vcs_ref") != TARGET_VCS_REF
    ):
        fail()

    plan_sha = sha256(plan_raw)
    if not isinstance(baseline, dict) or not isinstance(running, dict) or not isinstance(
        invariants, dict
    ):
        fail()
    if (
        baseline.get("command") != "baseline"
        or baseline.get("format_version") != 1
        or baseline.get("status") != "admitted"
        or baseline.get("rollout_plan_sha256") != plan_sha
        or running.get("command") != "running"
        or running.get("format_version") != 1
        or running.get("status") != "admitted"
        or running.get("plan_sha256") != plan_sha
        or invariants.get("command") != "invariants"
        or invariants.get("format_version") != 1
        or invariants.get("status") != "admitted"
        or invariants.get("unchanged") is not True
    ):
        fail()
    containers = require_object(
        running.get("containers"), {"control-api", "control-api-replica", "codex-pwa"}
    )
    expected_images = {
        "control-api": images["control-api"],
        "control-api-replica": images["control-api"],
        "codex-pwa": images["pwa"],
    }
    for service, image_id in expected_images.items():
        container = containers.get(service)
        if not isinstance(container, dict) or container.get("image_id") != image_id:
            fail()

    challenge = require_object(
        challenge, {"issued_at", "nonce", "rollout_id", "schema_version", "target"}
    )
    target = require_object(
        challenge.get("target"),
        {
            "baseline_sha256",
            "binding_sha256",
            "invariants_sha256",
            "plan_sha256",
            "running_sha256",
        },
    )
    expected_without_binding = {
        "baseline_sha256": sha256(baseline_raw),
        "invariants_sha256": sha256(invariants_raw),
        "plan_sha256": plan_sha,
        "running_sha256": sha256(running_raw),
    }
    expected_binding = sha256(canonical_json_bytes(expected_without_binding, newline=True))
    issued_at = parse_timestamp(challenge.get("issued_at"))
    try:
        rollout_id = uuid.UUID(str(challenge.get("rollout_id")))
    except (ValueError, AttributeError):
        fail()
    nonce = challenge.get("nonce")
    if (
        challenge.get("schema_version") != 1
        or rollout_id.version != 4
        or str(rollout_id) != challenge.get("rollout_id")
        or not isinstance(nonce, str)
        or SHA256_RE.fullmatch(nonce) is None
        or target != {**expected_without_binding, "binding_sha256": expected_binding}
        or issued_at > now.replace(tzinfo=timezone.utc)
        or (now.replace(tzinfo=timezone.utc) - issued_at).total_seconds() > 300
    ):
        fail()

    origin_record = require_object(origin_value, {"origin", "schema_version"})
    if origin_record.get("schema_version") != 1:
        fail()
    return Inputs(
        parse_origin(origin_record.get("origin")),
        sha256(challenge_raw),
        expected_binding,
    )


def load_compiled_system_certs(context: ssl.SSLContext) -> None:
    defaults = ssl.get_default_verify_paths()
    cafile = defaults.openssl_cafile
    capath = defaults.openssl_capath
    usable_cafile = cafile if cafile and os.path.isfile(cafile) else None
    usable_capath = capath if capath and os.path.isdir(capath) else None
    if usable_cafile is None and usable_capath is None:
        fail()
    try:
        context.load_verify_locations(cafile=usable_cafile, capath=usable_capath)
    except (OSError, ssl.SSLError):
        fail()


class RequestDeadline:
    """Bound DNS, connect, TLS, headers, and body under one wall-clock timeout."""

    def __enter__(self) -> None:
        if (
            not hasattr(signal, "SIGALRM")
            or not hasattr(signal, "ITIMER_REAL")
            or signal.getitimer(signal.ITIMER_REAL) != (0.0, 0.0)
        ):
            fail()
        self.previous_handler = signal.signal(signal.SIGALRM, self._expired)
        signal.setitimer(signal.ITIMER_REAL, REQUEST_TIMEOUT_SECONDS)

    def __exit__(self, _kind: Any, _value: Any, _traceback: Any) -> None:
        signal.setitimer(signal.ITIMER_REAL, 0.0)
        signal.signal(signal.SIGALRM, self.previous_handler)

    @staticmethod
    def _expired(_signum: int, _frame: Any) -> NoReturn:
        fail()


class DirectHTTPSClient:
    """HTTPS transport that never consults environment or system proxy settings."""

    def __init__(self, origin: Origin) -> None:
        self.origin = origin
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        self.context.minimum_version = ssl.TLSVersion.TLSv1_2
        self.context.check_hostname = True
        self.context.verify_mode = ssl.CERT_REQUIRED
        load_compiled_system_certs(self.context)
        self.context.keylog_filename = None

    def get(self, path: str, headers: dict[str, str] | None = None) -> Response:
        request_headers = {
            "Accept": "application/json",
            "Connection": "close",
            "Host": self.origin.authority,
            "User-Agent": USER_AGENT,
        }
        request_headers.update(headers or {})
        connection = http.client.HTTPSConnection(
            self.origin.host,
            self.origin.port,
            timeout=REQUEST_TIMEOUT_SECONDS,
            context=self.context,
        )
        try:
            with RequestDeadline():
                connection.request("GET", path, headers=request_headers)
                response = connection.getresponse()
                response_headers: dict[str, list[str]] = {}
                for name, value in response.getheaders():
                    response_headers.setdefault(name.lower(), []).append(value.strip())
                body = response.read(MAX_RESPONSE_BYTES + 1)
                if len(body) > MAX_RESPONSE_BYTES:
                    fail()
                return Response(
                    response.status,
                    {name: tuple(values) for name, values in response_headers.items()},
                    body,
                )
        except SmokeError:
            raise
        except (OSError, ssl.SSLError, http.client.HTTPException):
            fail()
        finally:
            connection.close()


def _json_body(response: Response) -> Any:
    try:
        return json.loads(
            response.body.decode("utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
            parse_float=_reject_float,
            parse_int=_bounded_integer,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, SmokeError):
        fail()


def _require_status(response: Response, allowed: tuple[int, ...] | list[int]) -> None:
    if response.status not in allowed or 300 <= response.status < 400:
        fail()


def run_checks(origin: Origin, client: Any, progress: list[int] | None = None) -> int:
    passed = 0
    if progress is None:
        progress = [0]

    def completed() -> None:
        nonlocal passed
        passed += 1
        progress[0] = passed

    pwa = client.get("/codex/", {"Accept": "text/html"})
    _require_status(pwa, [200])
    content_types = pwa.headers.get("content-type", ())
    if (
        len(content_types) != 1
        or "text/html" not in content_types[0].lower()
        or b"<title>Codex Control</title>" not in pwa.body
    ):
        fail()
    completed()

    manifest = client.get(
        "/codex/manifest.webmanifest", {"Accept": "application/manifest+json"}
    )
    _require_status(manifest, [200])
    manifest_value = _json_body(manifest)
    if (
        not isinstance(manifest_value, dict)
        or manifest_value.get("name") != "Sub2API Codex Control"
        or manifest_value.get("start_url") != "/codex/"
        or manifest_value.get("scope") != "/codex/"
    ):
        fail()
    completed()

    live = client.get("/codex-api/v1/health/live")
    _require_status(live, [200])
    if _json_body(live) != {"status": "ok"}:
        fail()
    completed()

    ready = client.get("/codex-api/v1/health/ready")
    _require_status(ready, [200])
    ready_value = _json_body(ready)
    if ready_value != {"checks": EXPECTED_READY_CHECKS, "status": "ready"}:
        fail()
    completed()

    session = client.get("/codex-api/v1/session")
    _require_status(session, [401, 403])
    completed()

    websocket_headers = {
        "Accept": "*/*",
        "Connection": "Upgrade",
        "Sec-WebSocket-Key": "MDEyMzQ1Njc4OWFiY2RlZg==",
        "Sec-WebSocket-Version": "13",
        "Upgrade": "websocket",
    }
    browser_headers = {**websocket_headers, "Origin": origin.value}
    browser = client.get("/codex-ws/browser", browser_headers)
    _require_status(browser, [401, 403])
    completed()

    device = client.get("/codex-ws/device", websocket_headers)
    _require_status(device, [401, 403])
    completed()

    root_guard = client.get("/codex-ws")
    _require_status(root_guard, [404])
    completed()

    adjacent_guard = client.get("/codex-ws/adjacent")
    _require_status(adjacent_guard, [404])
    completed()
    return passed


def make_result(
    *,
    status_value: str,
    started_at: datetime,
    completed_at: datetime,
    checks_passed: int,
    inputs: Inputs,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "challenge_sha256": inputs.challenge_sha256,
        "check_catalog_sha256": CHECK_CATALOG_SHA256,
        "check_count": CHECK_COUNT,
        "checks_passed": checks_passed,
        "completed_at": timestamp(completed_at),
        "schema_version": SCHEMA_VERSION,
        "started_at": timestamp(started_at),
        "status": status_value,
        "target_binding_sha256": inputs.target_binding_sha256,
    }
    result["result_sha256"] = sha256(canonical_json_bytes(result))
    return result


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    raw_argv = list(sys.argv[1:] if argv is None else argv)
    fixed_flags = [
        "--origin-file",
        "--challenge",
        "--plan",
        "--baseline",
        "--running",
        "--invariants",
    ]
    if len(raw_argv) != len(fixed_flags) * 2 or raw_argv[::2] != fixed_flags:
        fail()
    parser = PrivateArgumentParser(add_help=False, allow_abbrev=False)
    parser.add_argument("--origin-file", required=True)
    parser.add_argument("--challenge", required=True)
    parser.add_argument("--plan", required=True)
    parser.add_argument("--baseline", required=True)
    parser.add_argument("--running", required=True)
    parser.add_argument("--invariants", required=True)
    return parser.parse_args(raw_argv)


def execute(
    args: argparse.Namespace,
    *,
    client_factory: Callable[[Origin], Any] = DirectHTTPSClient,
    clock: Callable[[], datetime] = utc_now,
) -> tuple[dict[str, Any], bool]:
    started = clock()
    inputs = validate_inputs(args, started)
    if (
        CHECK_COUNT != 9
        or sha256(canonical_json_bytes(CHECK_CATALOG)) != CHECK_CATALOG_SHA256
    ):
        fail()
    progress = [0]
    success = False
    try:
        run_checks(inputs.origin, client_factory(inputs.origin), progress)
        success = progress[0] == CHECK_COUNT
    except Exception:
        pass
    result = make_result(
        status_value="passed" if success else "failed",
        started_at=started,
        completed_at=clock(),
        checks_passed=progress[0],
        inputs=inputs,
    )
    return result, success


def main(argv: list[str] | None = None) -> int:
    os.umask(0o077)
    try:
        args = parse_args(argv)
        result, success = execute(args)
    except Exception:
        print(GENERIC_ERROR, file=sys.stderr)
        return 1
    try:
        sys.stdout.buffer.write(canonical_json_bytes(result, newline=True))
    except Exception:
        print(GENERIC_ERROR, file=sys.stderr)
        return 1
    if not success:
        print(GENERIC_ERROR, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
