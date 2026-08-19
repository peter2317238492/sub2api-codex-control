#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import hashlib
import http.cookiejar
import json
import os
import re
import socket
import ssl
import stat
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from email.message import Message
from pathlib import Path

CHALLENGE_UUID4_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
CHALLENGE_DEPLOYMENT_RE = re.compile(
    r"^bootstrap-[0-9]{8}T[0-9]{6}Z-"
    r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
AUTHENTICATED_CATALOG_SHA256 = (
    "099d9f4688d72f6866a9d852c8ab4d6b469bf799dde8e879882d94371be31cf7"
)
CLOSURE_DEVICE_FLOW_OPTIONS = (
    ("pairing_code", "--pairing-code"),
    ("expected_device_id", "--expected-device-id"),
    ("workspace_root", "--workspace-root"),
    ("keep_device", "--keep-device"),
    ("reconnect_only", "--reconnect-only"),
    ("device_id_file", "--device-id-file"),
    ("expected_thread_id", "--expected-thread-id"),
    ("thread_id_file", "--thread-id-file"),
    ("provider_key_canary_file", "--provider-key-canary-file"),
    ("expect_cross_instance_fanout", "--expect-cross-instance-fanout"),
)
CLOSURE_ALLOWED_ARGUMENTS = frozenset(
    {
        "base_url",
        "access_token_file",
        "expected_user_id_file",
        "expect_secure_cookie",
        "closure_challenge_file",
    }
)


@dataclass(frozen=True)
class ClosureChallenge:
    challenge_sha256: str
    public_origin: str
    target_binding_sha256: str


@dataclass
class Result:
    status: int
    headers: Message
    body: bytes

    def json(self) -> object:
        return json.loads(self.body)


def canonical_absolute_path(path: Path | str, label: str) -> Path:
    raw = os.fspath(path)
    if not raw.startswith("/") or raw.startswith("//") or raw != os.path.normpath(raw):
        raise ValueError(f"{label} path must be canonical and absolute")
    value = Path(raw)
    if any(part in {"", ".", ".."} for part in value.parts[1:]):
        raise ValueError(f"{label} path contains a forbidden component")
    return value


def read_private_bytes(path: Path | str, label: str, maximum: int) -> bytes:
    path = canonical_absolute_path(path, label)
    directory_flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_DIRECTORY", 0)
    )
    parent_descriptor = -1
    try:
        parent_descriptor = os.open("/", directory_flags)
        for component in path.parent.parts[1:]:
            next_descriptor = os.open(
                component, directory_flags, dir_fd=parent_descriptor
            )
            os.close(parent_descriptor)
            parent_descriptor = next_descriptor
    except OSError:
        if parent_descriptor >= 0:
            os.close(parent_descriptor)
        raise ValueError(f"{label} has an inaccessible or symlink ancestor") from None
    file_flags = (
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(path.name, file_flags, dir_fd=parent_descriptor)
    except OSError:
        os.close(parent_descriptor)
        raise ValueError(f"cannot open {label} without following links") from None
    try:
        opened_metadata = os.fstat(descriptor)
        named_metadata = os.stat(
            path.name, dir_fd=parent_descriptor, follow_symlinks=False
        )
        opened_signature = (
            opened_metadata.st_dev,
            opened_metadata.st_ino,
            opened_metadata.st_mode,
            opened_metadata.st_uid,
            opened_metadata.st_gid,
            opened_metadata.st_nlink,
            opened_metadata.st_size,
            opened_metadata.st_mtime_ns,
            opened_metadata.st_ctime_ns,
        )
        named_signature = (
            named_metadata.st_dev,
            named_metadata.st_ino,
            named_metadata.st_mode,
            named_metadata.st_uid,
            named_metadata.st_gid,
            named_metadata.st_nlink,
            named_metadata.st_size,
            named_metadata.st_mtime_ns,
            named_metadata.st_ctime_ns,
        )
        if (
            not stat.S_ISREG(opened_metadata.st_mode)
            or opened_signature != named_signature
        ):
            raise ValueError(f"{label} changed while it was opened")
        if opened_metadata.st_uid != os.geteuid():
            raise ValueError(f"{label} must be owned by the deployment user")
        if stat.S_IMODE(opened_metadata.st_mode) != 0o600:
            raise ValueError(f"{label} mode must be exactly 0600")
        if opened_metadata.st_nlink != 1:
            raise ValueError(f"{label} must have one filesystem link")
        if opened_metadata.st_size <= 0:
            raise ValueError(f"{label} is empty")
        if opened_metadata.st_size > maximum:
            raise ValueError(f"{label} is larger than 64 KiB")
        chunks: list[bytes] = []
        remaining = maximum + 1
        while remaining:
            block = os.read(descriptor, min(4096, remaining))
            if not block:
                break
            chunks.append(block)
            remaining -= len(block)
        raw = b"".join(chunks)
        final_metadata = os.fstat(descriptor)
        final_named = os.stat(
            path.name, dir_fd=parent_descriptor, follow_symlinks=False
        )
        final_signature = (
            final_metadata.st_dev,
            final_metadata.st_ino,
            final_metadata.st_mode,
            final_metadata.st_uid,
            final_metadata.st_gid,
            final_metadata.st_nlink,
            final_metadata.st_size,
            final_metadata.st_mtime_ns,
            final_metadata.st_ctime_ns,
        )
        final_named_signature = (
            final_named.st_dev,
            final_named.st_ino,
            final_named.st_mode,
            final_named.st_uid,
            final_named.st_gid,
            final_named.st_nlink,
            final_named.st_size,
            final_named.st_mtime_ns,
            final_named.st_ctime_ns,
        )
        if (
            final_signature != opened_signature
            or final_named_signature != opened_signature
        ):
            raise ValueError(f"{label} changed while it was read")
    finally:
        os.close(descriptor)
        os.close(parent_descriptor)
    if len(raw) > maximum:
        raise ValueError(f"{label} exceeds its size limit")
    return raw


def read_private_opaque_file(path: Path | str, label: str) -> str:
    raw = read_private_bytes(path, label, 65_536)
    try:
        value = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError(f"{label} is not UTF-8") from None
    if len(raw) > 65_536:
        raise ValueError(f"{label} is larger than 64 KiB")
    value = value.rstrip("\r\n")
    if not value or any(character.isspace() for character in value):
        raise ValueError(f"{label} must contain one opaque value")
    return value


def canonical_https_origin(value: object, label: str) -> str:
    if not isinstance(value, str) or not value or not value.isascii():
        raise ValueError(f"{label} is invalid")
    try:
        parsed = urllib.parse.urlsplit(value)
        port = parsed.port
    except ValueError:
        raise ValueError(f"{label} is invalid") from None
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
        raise ValueError(f"{label} must be one canonical HTTPS origin")
    host = f"[{hostname.lower()}]" if ":" in hostname else hostname.lower()
    canonical = f"https://{host}"
    if port is not None and port != 443:
        canonical += f":{port}"
    if value != canonical:
        raise ValueError(f"{label} must be canonical")
    return canonical


def validate_closure_mode_arguments(args: argparse.Namespace) -> None:
    if args.access_token is not None:
        raise ValueError("closure challenge mode rejects --access-token")
    if "SUB2API_ACCESS_TOKEN" in os.environ:
        raise ValueError(
            "closure challenge mode rejects SUB2API_ACCESS_TOKEN environment input"
        )
    if args.expected_user_id is not None:
        raise ValueError("closure challenge mode rejects --expected-user-id")
    if "SUB2API_EXPECTED_USER_ID" in os.environ:
        raise ValueError(
            "closure challenge mode rejects SUB2API_EXPECTED_USER_ID environment input"
        )
    option_names = dict(CLOSURE_DEVICE_FLOW_OPTIONS)
    for attribute, value in vars(args).items():
        if attribute not in CLOSURE_ALLOWED_ARGUMENTS and value not in (None, False):
            option = option_names.get(attribute, f"--{attribute.replace('_', '-')}")
            raise ValueError(f"closure challenge mode rejects {option}")
    if not args.access_token_file:
        raise ValueError("closure challenge mode requires --access-token-file")
    if not args.expected_user_id_file:
        raise ValueError("closure challenge mode requires --expected-user-id-file")
    if not args.base_url:
        raise ValueError("closure challenge mode requires explicit --base-url")
    if args.insecure:
        raise ValueError("closure challenge mode rejects --insecure")
    if not args.expect_secure_cookie:
        raise ValueError("closure challenge mode requires --expect-secure-cookie")


def read_closure_challenge(path: Path | str) -> ClosureChallenge:
    raw = read_private_bytes(path, "closure challenge file", 16 * 1024)
    if (
        len(raw) > 16 * 1024
        or not raw.endswith(b"\n")
        or b"\r" in raw
        or b"\x00" in raw
    ):
        raise ValueError("closure challenge is not canonical newline-delimited JSON")
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError("closure challenge is not valid JSON") from exc
    expected_keys = {
        "$schema",
        "format_version",
        "deployment_id",
        "deployment_basename",
        "bootstrap_record_sha256",
        "issued_at",
        "nonce",
        "target",
    }
    if not isinstance(value, dict) or set(value) != expected_keys:
        raise ValueError("closure challenge has an unexpected schema")
    if value["format_version"] != 2:
        raise ValueError("closure challenge has an unexpected format version")
    if value["$schema"] != (
        "https://sub2api-codex.invalid/schemas/authenticated-smoke-challenge-v2.json"
    ):
        raise ValueError("closure challenge has an unexpected schema ID")
    deployment_id = value["deployment_id"]
    deployment_basename = value["deployment_basename"]
    bootstrap_sha256 = value["bootstrap_record_sha256"]
    nonce = value["nonce"]
    if (
        not isinstance(deployment_id, str)
        or CHALLENGE_UUID4_RE.fullmatch(deployment_id) is None
    ):
        raise ValueError("closure challenge deployment_id is invalid")
    if (
        not isinstance(deployment_basename, str)
        or CHALLENGE_DEPLOYMENT_RE.fullmatch(deployment_basename) is None
        or not deployment_basename.endswith(deployment_id)
    ):
        raise ValueError("closure challenge deployment_basename is invalid")
    if (
        not isinstance(bootstrap_sha256, str)
        or SHA256_RE.fullmatch(bootstrap_sha256) is None
    ):
        raise ValueError("closure challenge bootstrap_record_sha256 is invalid")
    if not isinstance(nonce, str) or SHA256_RE.fullmatch(nonce) is None:
        raise ValueError("closure challenge nonce is invalid")
    issued_at = value["issued_at"]
    if not isinstance(issued_at, str) or not issued_at.endswith("Z"):
        raise ValueError("closure challenge issued_at is invalid")
    target = value["target"]
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
    if not isinstance(target, dict) or set(target) != target_keys:
        raise ValueError("closure challenge target has an unexpected schema")
    public_origin = canonical_https_origin(
        target["public_origin"], "closure challenge public_origin"
    )
    for name in target_keys - {"public_origin"}:
        if (
            not isinstance(target[name], str)
            or SHA256_RE.fullmatch(target[name]) is None
        ):
            raise ValueError("closure challenge target digest is invalid")
    binding_value = {
        key: target[key] for key in sorted(target) if key != "binding_sha256"
    }
    binding_sha256 = hashlib.sha256(
        json.dumps(
            binding_value,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
    ).hexdigest()
    if binding_sha256 != target["binding_sha256"]:
        raise ValueError("closure challenge target binding digest differs")
    return ClosureChallenge(
        challenge_sha256=hashlib.sha256(raw).hexdigest(),
        public_origin=public_origin,
        target_binding_sha256=binding_sha256,
    )


def read_closure_challenge_sha256(path: Path | str) -> str:
    return read_closure_challenge(path).challenge_sha256


class WebSocketStream:
    def __init__(self, connection: socket.socket, initial: bytes = b"") -> None:
        self.connection = connection
        self.buffer = bytearray(initial)

    def _recv_exact(self, length: int) -> bytes:
        while len(self.buffer) < length:
            chunk = self.connection.recv(max(4096, length - len(self.buffer)))
            if not chunk:
                raise OSError("WebSocket closed while receiving a frame")
            self.buffer.extend(chunk)
        value = bytes(self.buffer[:length])
        del self.buffer[:length]
        return value

    def _send_control(self, opcode: int, payload: bytes = b"") -> None:
        if len(payload) > 125:
            raise ValueError("WebSocket control payload is too large")
        mask = os.urandom(4)
        masked = bytes(value ^ mask[index % 4] for index, value in enumerate(payload))
        self.connection.sendall(
            bytes((0x80 | opcode, 0x80 | len(payload))) + mask + masked
        )

    def receive_text(self, timeout: float) -> str | None:
        self.connection.settimeout(timeout)
        while True:
            first, second = self._recv_exact(2)
            final = bool(first & 0x80)
            opcode = first & 0x0F
            masked = bool(second & 0x80)
            length = second & 0x7F
            if first & 0x70:
                raise OSError("WebSocket frame uses unsupported reserved bits")
            if masked:
                raise OSError("server WebSocket frame must not be masked")
            if length == 126:
                length = int.from_bytes(self._recv_exact(2), "big")
            elif length == 127:
                length = int.from_bytes(self._recv_exact(8), "big")
            if length > 1_048_576:
                raise OSError("WebSocket event frame exceeds the acceptance limit")
            payload = self._recv_exact(length)
            if opcode == 0x8:
                return None
            if opcode == 0x9:
                self._send_control(0xA, payload)
                continue
            if opcode == 0xA:
                continue
            if opcode != 0x1 or not final:
                raise OSError("acceptance client expected one complete text frame")
            return payload.decode("utf-8")

    def close(self) -> None:
        try:
            self._send_control(0x8, (1000).to_bytes(2, "big"))
        except OSError:
            pass
        self.connection.close()


class Smoke:
    def __init__(
        self,
        base_url: str,
        insecure: bool,
        expect_secure_cookie: bool,
        provider_key_canary: str | None,
        closure_catalog_required: bool = False,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        parsed = urllib.parse.urlsplit(self.base_url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc or parsed.path:
            raise ValueError(
                "base URL must be an origin such as https://control.example.com"
            )
        self.origin = self.base_url
        self.parsed_origin = parsed
        self.expect_secure_cookie = expect_secure_cookie
        self.ssl_context = (
            ssl._create_unverified_context()
            if insecure
            else ssl.create_default_context()
        )
        self.cookies = http.cookiejar.CookieJar()
        handlers: list[urllib.request.BaseHandler] = [
            urllib.request.HTTPCookieProcessor(self.cookies)
        ]
        if insecure:
            handlers.append(
                urllib.request.HTTPSHandler(context=ssl._create_unverified_context())
            )
        self.opener = urllib.request.build_opener(*handlers)
        self.passed = 0
        self.closure_catalog_required = closure_catalog_required
        self.closure_descriptions: list[str] = []
        self.browser_event_cursors: list[int] = []
        self.provider_key_canary = provider_key_canary

    def request(
        self,
        path: str,
        *,
        method: str = "GET",
        body: object | None = None,
        headers: dict[str, str] | None = None,
    ) -> Result:
        payload = None
        request_headers = dict(headers or {})
        if body is not None:
            payload = json.dumps(body, separators=(",", ":")).encode()
            request_headers.setdefault("Content-Type", "application/json")
        request = urllib.request.Request(
            f"{self.base_url}{path}",
            data=payload,
            headers=request_headers,
            method=method,
        )
        try:
            response = self.opener.open(request, timeout=10)
        except urllib.error.HTTPError as error:
            result = Result(error.code, error.headers, error.read())
        else:
            with response:
                result = Result(response.status, response.headers, response.read())
        if (
            self.provider_key_canary is not None
            and self.provider_key_canary.encode() in result.body
        ):
            raise AssertionError(
                f"raw Sub2API provider key reached browser-visible HTTP response {path}"
            )
        return result

    def check(self, condition: bool, description: str) -> None:
        if not condition:
            raise AssertionError(description)
        self.passed += 1
        if self.closure_catalog_required:
            self.closure_descriptions.append(description)
        print(f"ok {self.passed} - {description}")

    def validate_closure_catalog(self) -> None:
        catalog = json.dumps(
            self.closure_descriptions,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
        if (
            self.passed != 84
            or len(self.closure_descriptions) != 84
            or hashlib.sha256(catalog).hexdigest() != AUTHENTICATED_CATALOG_SHA256
        ):
            raise AssertionError(
                "closure challenge requires the exact 84-check authenticated smoke catalog"
            )

    def eventually(
        self,
        description: str,
        probe: Callable[[], object | None],
        *,
        timeout: float = 30,
    ) -> object:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            value = probe()
            if value is not None:
                self.check(True, description)
                return value
            time.sleep(0.2)
        raise AssertionError(f"timed out waiting for {description}")

    def open_websocket(
        self,
        path: str,
        *,
        origin: str,
        cookie: str,
    ) -> tuple[int, dict[str, str], WebSocketStream | None]:
        host = self.parsed_origin.hostname
        if host is None:
            raise ValueError("base URL has no host")
        secure = self.parsed_origin.scheme == "https"
        port = self.parsed_origin.port or (443 if secure else 80)
        connection = socket.create_connection((host, port), timeout=10)
        if secure:
            connection = self.ssl_context.wrap_socket(connection, server_hostname=host)
        key = base64.b64encode(os.urandom(16)).decode()
        request = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {self.parsed_origin.netloc}\r\n"
            "Connection: Upgrade\r\n"
            "Upgrade: websocket\r\n"
            "Sec-WebSocket-Version: 13\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            f"Origin: {origin}\r\n"
            f"Cookie: {cookie}\r\n"
            "\r\n"
        ).encode()
        connection.sendall(request)
        response = bytearray()
        while b"\r\n\r\n" not in response:
            chunk = connection.recv(4096)
            if not chunk:
                break
            response.extend(chunk)
            if len(response) > 65536:
                connection.close()
                raise OSError("WebSocket handshake response is too large")

        head_bytes, separator, remainder = bytes(response).partition(b"\r\n\r\n")
        head = head_bytes.decode("iso-8859-1")
        lines = head.split("\r\n")
        if not lines or len(lines[0].split()) < 2:
            connection.close()
            raise OSError("invalid WebSocket handshake response")
        status = int(lines[0].split()[1])
        response_headers: dict[str, str] = {}
        for line in lines[1:]:
            if ":" not in line:
                continue
            name, value = line.split(":", 1)
            response_headers[name.strip().lower()] = value.strip()
        if status == 101:
            expected_accept = base64.b64encode(
                hashlib.sha1(
                    f"{key}258EAFA5-E914-47DA-95CA-C5AB0DC85B11".encode()
                ).digest()
            ).decode()
            if response_headers.get("sec-websocket-accept") != expected_accept:
                connection.close()
                raise OSError("invalid Sec-WebSocket-Accept")
            if not separator:
                connection.close()
                raise OSError("incomplete WebSocket handshake response")
            return status, response_headers, WebSocketStream(connection, remainder)
        connection.close()
        return status, response_headers, None

    def wait_browser_event(
        self,
        stream: WebSocketStream,
        description: str,
        predicate: Callable[[dict[str, object]], bool],
        *,
        timeout: float = 15,
    ) -> dict[str, object]:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                raw = stream.receive_text(
                    min(1.0, max(0.01, deadline - time.monotonic()))
                )
            except TimeoutError:
                continue
            if raw is None:
                raise AssertionError(f"browser WebSocket closed before {description}")
            if self.provider_key_canary is not None and self.provider_key_canary in raw:
                raise AssertionError(
                    "raw Sub2API provider key reached the browser WebSocket"
                )
            candidate = json.loads(raw)
            if not isinstance(candidate, dict):
                raise AssertionError(  # noqa: TRY004 - this is an acceptance assertion.
                    "browser WebSocket delivered a non-object event"
                )
            raw_cursor = candidate.get("cursor")
            if not isinstance(raw_cursor, str) or not raw_cursor.isdigit():
                raise AssertionError(
                    "browser WebSocket delivered an invalid event cursor"
                )
            cursor = int(raw_cursor)
            if self.browser_event_cursors and cursor <= self.browser_event_cursors[-1]:
                raise AssertionError(
                    "browser WebSocket event cursor was duplicated or moved backward: "
                    f"{cursor} after {self.browser_event_cursors[-1]}"
                )
            self.browser_event_cursors.append(cursor)
            if predicate(candidate):
                self.check(True, description)
                return candidate
        raise AssertionError(f"timed out waiting for {description}")

    def exercise_control(
        self,
        *,
        pairing_code: str | None,
        expected_device_id: str | None,
        workspace_root: str | None,
        csrf_headers: dict[str, str],
        keep_device: bool,
        reconnect_only: bool,
        device_id_file: str | None,
        expected_thread_id: str | None,
        thread_id_file: str | None,
        browser_stream: WebSocketStream | None,
        expect_cross_instance_fanout: bool,
    ) -> None:
        device_id = expected_device_id
        if pairing_code is not None:
            claim = self.request(
                "/codex-api/v1/pairings/claim",
                method="POST",
                headers=csrf_headers,
                body={"code": pairing_code},
            )
            self.check(
                claim.status == 200,
                "authenticated user claims the Connector pairing code",
            )
            claim_body = claim.json()
            self.check(
                isinstance(claim_body, dict)
                and claim_body.get("status") == "claimed"
                and isinstance(claim_body.get("device_id"), str),
                "pairing claim returns one bound device identity",
            )
            device_id = str(claim_body["device_id"])

        if device_id is None:
            return
        if device_id_file is not None:
            Path(device_id_file).write_text(device_id + "\n", encoding="utf-8")

        def online_device() -> object | None:
            response = self.request("/codex-api/v1/devices")
            if response.status != 200:
                return None
            body = response.json()
            if not isinstance(body, dict) or not isinstance(body.get("items"), list):
                return None
            for item in body["items"]:
                if (
                    isinstance(item, dict)
                    and item.get("id") == device_id
                    and item.get("status") == "online"
                ):
                    return item
            return None

        device = self.eventually(
            "paired Connector completes signed token exchange and authenticated WSS Hello",
            online_device,
        )
        assert isinstance(device, dict)
        self.check(
            device.get("connector_version") == "0.1.2"
            and device.get("codex_version") == "0.147.0",
            "online device reports the pinned Connector and Codex versions",
        )
        if workspace_root is not None:
            self.check(
                device.get("workspace_roots") == [workspace_root],
                "server binds the device to the Connector canonical workspace root",
            )

        model_sync = self.request(
            f"/codex-api/v1/devices/{device_id}/models/sync",
            method="POST",
            headers={**csrf_headers, "Idempotency-Key": "e2e-model-sync"},
        )
        self.check(
            model_sync.status == 202,
            "explicit model sync queues model/list through the deployed edge",
        )
        if browser_stream is not None:
            self.wait_browser_event(
                browser_stream,
                (
                    "device-instance result fans out live to the browser-instance WebSocket"
                    if expect_cross_instance_fanout
                    else "device result is delivered over the live browser WebSocket"
                ),
                lambda event: (
                    event.get("type") == "command.updated"
                    and isinstance(event.get("data"), dict)
                    and isinstance(event["data"].get("command"), dict)
                    and event["data"]["command"].get("method") == "model/list"
                    and event["data"]["command"].get("state") == "succeeded"
                ),
            )

        def populated_model_catalog() -> object | None:
            response = self.request(f"/codex-api/v1/devices/{device_id}/models")
            if response.status != 200:
                return None
            body = response.json()
            if not isinstance(body, dict) or not isinstance(body.get("items"), list):
                return None
            if any(
                isinstance(item, dict) and item.get("id") == "gpt-5.5-e2e"
                for item in body["items"]
            ):
                if (
                    self.provider_key_canary is not None
                    and self.provider_key_canary in json.dumps(body, sort_keys=True)
                ):
                    raise AssertionError(
                        "model catalog retained the provider-key canary"
                    )
                return body
            return None

        model_catalog = self.eventually(
            "cached models reflect model/list from the real Connector and stdio app-server",
            populated_model_catalog,
        )
        if self.provider_key_canary is not None:
            self.check(
                self.provider_key_canary
                not in json.dumps(model_catalog, sort_keys=True),
                "real Connector strips the raw Sub2API provider-key canary from the PWA model catalog",
            )

        def parse_thread_snapshot(
            body: object,
        ) -> tuple[int, dict[str, object]] | None:
            if not isinstance(body, dict):
                return None
            raw_cursor = body.get("event_cursor")
            thread = body.get("thread")
            if (
                not isinstance(raw_cursor, str)
                or not raw_cursor.isdigit()
                or not isinstance(thread, dict)
            ):
                return None
            return int(raw_cursor), thread

        if reconnect_only:
            if expected_thread_id is None or workspace_root is None:
                raise ValueError(
                    "reconnect checks require an expected thread id and workspace root"
                )
            if browser_stream is None:
                raise AssertionError(
                    "reconnect checks require the browser event stream"
                )

            def accepted_command(response: Result, method: str) -> str:
                body = response.json()
                self.check(
                    response.status == 202
                    and isinstance(body, dict)
                    and isinstance(body.get("id"), str)
                    and body.get("method") == method,
                    f"post-restart {method} is accepted for the managed thread",
                )
                return str(body["id"])

            def wait_succeeded(command_id: str, method: str, description: str) -> None:
                self.wait_browser_event(
                    browser_stream,
                    description,
                    lambda event: (
                        event.get("type") == "command.updated"
                        and isinstance(event.get("data"), dict)
                        and isinstance(event["data"].get("command"), dict)
                        and event["data"]["command"].get("id") == command_id
                        and event["data"]["command"].get("method") == method
                        and event["data"]["command"].get("state") == "succeeded"
                    ),
                )

            resumed = self.request(
                f"/codex-api/v1/threads/{expected_thread_id}/resume",
                method="POST",
                headers={
                    **csrf_headers,
                    "Idempotency-Key": "e2e-thread-resume-after-app-server-restart",
                },
            )
            resume_command_id = accepted_command(resumed, "thread/resume")
            wait_succeeded(
                resume_command_id,
                "thread/resume",
                "thread/resume succeeds after the Connector app-server child restarts",
            )

            refreshed = self.request(
                f"/codex-api/v1/threads/{expected_thread_id}/sync",
                method="POST",
                headers={
                    **csrf_headers,
                    "Idempotency-Key": "e2e-thread-read-after-app-server-restart",
                },
            )
            read_command_id = accepted_command(refreshed, "thread/read")
            wait_succeeded(
                read_command_id,
                "thread/read",
                "thread/read succeeds against persisted state after app-server restart",
            )

            restored_detail = self.request(
                f"/codex-api/v1/threads/{expected_thread_id}"
            )
            restored_snapshot = (
                parse_thread_snapshot(restored_detail.json())
                if restored_detail.status == 200
                else None
            )
            restored_thread = restored_snapshot[1] if restored_snapshot else None
            restored_messages = (
                restored_thread.get("messages")
                if isinstance(restored_thread, dict)
                else None
            )
            self.check(
                isinstance(restored_thread, dict)
                and restored_thread.get("status") == "idle"
                and restored_thread.get("cwd") == workspace_root
                and isinstance(restored_messages, list)
                and any(
                    isinstance(message, dict)
                    and message.get("role") == "assistant"
                    and "E2E approved response" in str(message.get("text", ""))
                    for message in restored_messages
                ),
                "post-restart thread snapshot retains identity, idle state, cwd, and history",
            )

        if not reconnect_only:
            if workspace_root is None:
                raise ValueError(
                    "--workspace-root is required for full Connector control checks"
                )
            thread_list_sync = self.request(
                f"/codex-api/v1/devices/{device_id}/threads/sync",
                method="POST",
                headers={**csrf_headers, "Idempotency-Key": "e2e-thread-list-sync"},
            )
            self.check(
                thread_list_sync.status == 202,
                "explicit thread-list sync queues thread/list through the real Connector",
            )
            threads = self.request(f"/codex-api/v1/devices/{device_id}/threads")
            self.check(
                threads.status == 200, "thread list is read from the durable cache"
            )

            started = self.request(
                f"/codex-api/v1/devices/{device_id}/threads",
                method="POST",
                headers={**csrf_headers, "Idempotency-Key": "e2e-thread-start"},
                body={"cwd": workspace_root, "model": "gpt-5.5-e2e"},
            )
            started_body = started.json()
            self.check(
                started.status == 202
                and isinstance(started_body, dict)
                and isinstance(started_body.get("id"), str),
                "thread/start creates a server binding for the allowlisted cwd",
            )
            thread_id = str(started_body["id"])

            def thread_with_status(status: str) -> Callable[[], object | None]:
                def probe() -> object | None:
                    response = self.request(f"/codex-api/v1/threads/{thread_id}")
                    if response.status != 200:
                        return None
                    body = response.json()
                    snapshot = parse_thread_snapshot(body)
                    if snapshot is not None and snapshot[1].get("status") == status:
                        return body
                    return None

                return probe

            bound_snapshot = self.eventually(
                "thread/start ACK binds the Connector-owned app-server thread",
                thread_with_status("idle"),
            )
            parsed_bound_snapshot = parse_thread_snapshot(bound_snapshot)
            assert parsed_bound_snapshot is not None
            detail_event_cursor, bound_thread = parsed_bound_snapshot
            self.check(
                bound_thread.get("cwd") == workspace_root,
                "managed thread retains the exact canonical workspace root",
            )
            self.check(
                detail_event_cursor >= 0,
                "thread detail includes an atomic owner-event watermark",
            )
            if thread_id_file is not None:
                Path(thread_id_file).write_text(thread_id + "\n", encoding="utf-8")

            resumed = self.request(
                f"/codex-api/v1/threads/{thread_id}/resume",
                method="POST",
                headers={**csrf_headers, "Idempotency-Key": "e2e-thread-resume"},
            )
            self.check(
                resumed.status == 202,
                "thread/resume is accepted for the managed thread",
            )

            refreshed = self.request(
                f"/codex-api/v1/threads/{thread_id}/sync",
                method="POST",
                headers={**csrf_headers, "Idempotency-Key": "e2e-thread-read-sync"},
            )
            self.check(
                refreshed.status == 202,
                "explicit thread-detail sync queues thread/read for the managed thread",
            )
            cached_detail = self.request(f"/codex-api/v1/threads/{thread_id}")
            self.check(
                cached_detail.status == 200
                and parse_thread_snapshot(cached_detail.json()) is not None,
                "thread detail remains an atomic read-only cached GET",
            )

            turn = self.request(
                f"/codex-api/v1/threads/{thread_id}/turns",
                method="POST",
                headers={**csrf_headers, "Idempotency-Key": "e2e-turn-start"},
                body={"text": "Run the deterministic acceptance turn"},
            )
            self.check(
                turn.status == 202, "turn/start is accepted with text-only input"
            )

            if browser_stream is not None:
                live_approval_event = self.wait_browser_event(
                    browser_stream,
                    "an approval event follows the atomic thread-detail watermark",
                    lambda event: (
                        event.get("type") == "approval.created"
                        and isinstance(event.get("data"), dict)
                        and event["data"].get("device_id") == device_id
                        and event["data"].get("kind") == "command"
                    ),
                )
                live_cursor = int(str(live_approval_event["cursor"]))
                self.check(
                    live_cursor > detail_event_cursor,
                    "live approval cursor advances beyond the thread-detail snapshot",
                )
                self.check(
                    len(self.browser_event_cursors)
                    == len(set(self.browser_event_cursors)),
                    "browser catch-up and live fanout deliver no duplicate event cursor",
                )

            def pending_approval(kind: str) -> Callable[[], object | None]:
                def probe() -> object | None:
                    response = self.request("/codex-api/v1/approvals?state=pending")
                    if response.status != 200:
                        return None
                    body = response.json()
                    if not isinstance(body, dict) or not isinstance(
                        body.get("items"), list
                    ):
                        return None
                    for item in body["items"]:
                        if (
                            isinstance(item, dict)
                            and item.get("device_id") == device_id
                            and item.get("kind") == kind
                        ):
                            return item
                    return None

                return probe

            command_approval = self.eventually(
                "command approval reaches the authenticated browser surface",
                pending_approval("command"),
            )
            assert isinstance(command_approval, dict)
            details = command_approval.get("details")
            self.check(
                command_approval.get("kind") == "command"
                and isinstance(details, dict)
                and details.get("command") == "printf e2e-approved",
                "command approval projection exposes only bounded decision context",
            )
            encoded_details = json.dumps(details, sort_keys=True)
            self.check(
                not any(
                    forbidden in encoded_details
                    for forbidden in (
                        "COMMAND-SECRET-MUST-NOT-CROSS",
                        "COMMAND-OUTPUT-MUST-NOT-CROSS",
                        '"commandActions"',
                        '"availableDecisions"',
                    )
                ),
                "command approval excludes local parsed-action context",
            )
            approval_id = command_approval.get("approval_id")
            decision = self.request(
                f"/codex-api/v1/approvals/{approval_id}/decision",
                method="POST",
                headers=csrf_headers,
                body={"decision": "approve"},
            )
            self.check(
                decision.status == 204, "command approval is explicitly approved"
            )

            file_approval = self.eventually(
                "file-change approval reaches the authenticated browser surface",
                pending_approval("file_change"),
            )
            assert isinstance(file_approval, dict)
            file_details = file_approval.get("details")
            self.check(
                isinstance(file_details, dict)
                and file_details.get("grantRoot") == "/workspace"
                and file_details.get("reason")
                == "Review deterministic E2E file operations",
                "file-change projection exposes bounded frozen-schema context",
            )
            encoded_file_details = json.dumps(file_details, sort_keys=True)
            self.check(
                not any(
                    forbidden in encoded_file_details
                    for forbidden in (
                        '"fileChanges"',
                        '"content"',
                        '"unified_diff"',
                        '"diff"',
                    )
                ),
                "file-change approval contains no schema-external contents or diffs",
            )
            file_decision = self.request(
                f"/codex-api/v1/approvals/{file_approval.get('approval_id')}/decision",
                method="POST",
                headers=csrf_headers,
                body={"decision": "deny"},
            )
            self.check(
                file_decision.status == 204, "file-change approval is explicitly denied"
            )

            permission_approval = self.eventually(
                "permission approval reaches the authenticated browser surface",
                pending_approval("permission"),
            )
            assert isinstance(permission_approval, dict)
            permission_details = permission_approval.get("details")
            permissions = (
                permission_details.get("permissions")
                if isinstance(permission_details, dict)
                else None
            )
            self.check(
                isinstance(permissions, dict)
                and permissions.get("network") == {"enabled": False}
                and permissions.get("fileSystem")
                == {
                    "read": ["/workspace/ordinary-codex-state"],
                    "write": ["/workspace"],
                },
                "permission projection is canonical, workspace-bound, and network-disabled",
            )
            encoded_permission_details = json.dumps(permission_details, sort_keys=True)
            self.check(
                "PERMISSION-ENVIRONMENT-ID-MUST-NOT-CROSS"
                not in encoded_permission_details
                and '"environmentId"' not in encoded_permission_details,
                "permission approval excludes the local environment identifier",
            )
            permission_id = permission_approval.get("approval_id")

            def permission_default_denied() -> object | None:
                response = self.request("/codex-api/v1/approvals?state=pending")
                if response.status != 200:
                    return None
                body = response.json()
                if not isinstance(body, dict) or not isinstance(
                    body.get("items"), list
                ):
                    return None
                if any(
                    isinstance(item, dict) and item.get("approval_id") == permission_id
                    for item in body["items"]
                ):
                    return None
                return True

            self.eventually(
                "permission approval times out and disappears from the pending surface",
                permission_default_denied,
                timeout=15,
            )

            def steer_when_active() -> object | None:
                response = self.request(
                    f"/codex-api/v1/threads/{thread_id}/turns/current/steer",
                    method="POST",
                    headers={**csrf_headers, "Idempotency-Key": "e2e-turn-steer"},
                    body={"text": "Continue with the accepted E2E response"},
                )
                if response.status == 202:
                    return response
                if response.status == 409:
                    return None
                raise AssertionError(f"unexpected turn/steer status {response.status}")

            self.eventually(
                "turn/steer targets the Connector-bound active turn", steer_when_active
            )

            def thread_with_delta() -> object | None:
                response = self.request(f"/codex-api/v1/threads/{thread_id}")
                if response.status != 200:
                    return None
                body = response.json()
                snapshot = parse_thread_snapshot(body)
                if snapshot is None:
                    return None
                messages = snapshot[1].get("messages")
                if isinstance(messages, list) and any(
                    isinstance(message, dict)
                    and message.get("role") == "assistant"
                    and "E2E approved response" in str(message.get("text", ""))
                    for message in messages
                ):
                    return body
                return None

            self.eventually(
                "streamed agent delta is projected into the managed thread",
                thread_with_delta,
            )

            interrupted = self.request(
                f"/codex-api/v1/threads/{thread_id}/turns/current/interrupt",
                method="POST",
                headers={**csrf_headers, "Idempotency-Key": "e2e-turn-interrupt"},
            )
            self.check(
                interrupted.status == 202,
                "turn/interrupt targets the active bound turn",
            )
            self.eventually(
                "turn completion returns the managed thread to idle",
                thread_with_status("idle"),
            )

            refreshed_history = self.request(
                f"/codex-api/v1/threads/{thread_id}/sync",
                method="POST",
                headers={**csrf_headers, "Idempotency-Key": "e2e-thread-history-sync"},
            )
            self.check(
                refreshed_history.status == 202,
                "post-turn thread/read sync remains available after interruption",
            )
            cached_history = self.request(f"/codex-api/v1/threads/{thread_id}")
            self.check(
                cached_history.status == 200
                and parse_thread_snapshot(cached_history.json()) is not None,
                "post-turn history is read from an atomic cached snapshot",
            )

        if not keep_device:
            revoked = self.request(
                f"/codex-api/v1/devices/{device_id}",
                method="DELETE",
                headers=csrf_headers,
            )
            self.check(
                revoked.status == 204,
                "device revocation invalidates the Connector credential",
            )

            def revoked_device_is_hidden() -> object | None:
                response = self.request("/codex-api/v1/devices")
                if response.status != 200:
                    return None
                body = response.json()
                if not isinstance(body, dict) or not isinstance(
                    body.get("items"), list
                ):
                    return None
                return (
                    True
                    if all(
                        not isinstance(item, dict) or item.get("id") != device_id
                        for item in body["items"]
                    )
                    else None
                )

            self.eventually(
                "revoked device is no longer an online control target",
                revoked_device_is_hidden,
            )

    def run(
        self,
        access_token: str | None,
        *,
        expected_user_id: str = "42",
        pairing_code: str | None = None,
        expected_device_id: str | None = None,
        workspace_root: str | None = None,
        keep_device: bool = False,
        reconnect_only: bool = False,
        device_id_file: str | None = None,
        expected_thread_id: str | None = None,
        thread_id_file: str | None = None,
        expect_cross_instance_fanout: bool = False,
    ) -> None:
        shell = self.request("/codex/")
        self.check(shell.status == 200, "PWA shell is reachable at /codex/")
        self.check(
            "text/html" in shell.headers.get("Content-Type", ""), "PWA shell is HTML"
        )

        csp = shell.headers.get("Content-Security-Policy", "")
        for directive in (
            "default-src 'none'",
            "connect-src 'self'",
            "frame-ancestors 'none'",
            "script-src 'self'",
            "style-src 'self'",
            "worker-src 'self'",
        ):
            self.check(directive in csp, f"CSP contains {directive}")
        self.check(
            "'unsafe-inline'" not in csp and "'unsafe-eval'" not in csp,
            "CSP forbids unsafe script/style execution",
        )
        self.check(
            shell.headers.get("X-Content-Type-Options") == "nosniff",
            "nosniff is enabled",
        )
        self.check(shell.headers.get("X-Frame-Options") == "DENY", "framing is denied")
        self.check(
            shell.headers.get("Referrer-Policy") == "no-referrer",
            "referrers are suppressed",
        )
        self.check(
            "max-age=" in shell.headers.get("Strict-Transport-Security", ""),
            "HSTS policy is emitted",
        )
        self.check(
            shell.headers.get("Access-Control-Allow-Origin") is None,
            "PWA emits no CORS grant",
        )
        for header_name in (
            "Content-Security-Policy",
            "Cross-Origin-Opener-Policy",
            "Cross-Origin-Resource-Policy",
            "Permissions-Policy",
            "Referrer-Policy",
            "Strict-Transport-Security",
            "X-Content-Type-Options",
            "X-Frame-Options",
        ):
            self.check(
                len(shell.headers.get_all(header_name, [])) == 1,
                f"PWA emits exactly one {header_name} header",
            )

        manifest = self.request("/codex/manifest.webmanifest")
        self.check(manifest.status == 200, "manifest is reachable")
        manifest_body = manifest.json()
        self.check(
            isinstance(manifest_body, dict) and manifest_body.get("scope") == "/codex/",
            "manifest scope is /codex/",
        )
        self.check(
            isinstance(manifest_body, dict)
            and manifest_body.get("start_url") == "/codex/",
            "manifest start URL is /codex/",
        )
        icons = (
            manifest_body.get("icons", []) if isinstance(manifest_body, dict) else []
        )
        icon_sizes = {
            icon.get("sizes")
            for icon in icons
            if isinstance(icon, dict) and icon.get("type") == "image/png"
        }
        self.check(
            {"192x192", "512x512"}.issubset(icon_sizes),
            "manifest has installable PNG icon sizes",
        )

        worker = self.request("/codex/sw.js")
        self.check(worker.status == 200, "service worker is reachable")
        self.check(
            worker.headers.get("Service-Worker-Allowed") == "/codex/",
            "service worker scope is restricted to /codex/",
        )
        self.check(
            "no-cache" in worker.headers.get("Cache-Control", ""),
            "service worker update is not cached",
        )

        live = self.request("/codex-api/v1/health/live")
        self.check(
            live.status == 200 and live.json() == {"status": "ok"},
            "liveness route is healthy",
        )
        ready = self.request("/codex-api/v1/health/ready")
        ready_body = ready.json()
        self.check(ready.status == 200, "readiness route is healthy")
        self.check(
            isinstance(ready_body, dict)
            and isinstance(ready_body.get("checks"), dict)
            and ready_body["checks"].get("database") == "ok"
            and ready_body["checks"].get("redis") == "ok"
            and all(value == "ok" for value in ready_body["checks"].values()),
            "readiness confirms PostgreSQL, Redis, and every declared contract",
        )
        self.check(
            "no-store" in ready.headers.get("Cache-Control", ""),
            "API responses are not cached",
        )
        for header_name in (
            "Cache-Control",
            "Content-Security-Policy",
            "Cross-Origin-Opener-Policy",
            "Cross-Origin-Resource-Policy",
            "Permissions-Policy",
            "Pragma",
            "Referrer-Policy",
            "Strict-Transport-Security",
            "X-Content-Type-Options",
            "X-Frame-Options",
        ):
            self.check(
                len(ready.headers.get_all(header_name, [])) == 1,
                f"API emits exactly one {header_name} header",
            )

        unauthenticated = self.request("/codex-api/v1/session")
        self.check(
            unauthenticated.status == 401, "session data requires authentication"
        )
        zero_uuid = "00000000-0000-0000-0000-000000000000"
        for path, description in (
            ("/codex-api/v1/devices", "devices"),
            ("/codex-api/v1/bootstrap", "control bootstrap"),
            ("/codex-api/v1/approvals?state=pending", "approvals"),
            (f"/codex-api/v1/devices/{zero_uuid}/models", "device models"),
            (f"/codex-api/v1/devices/{zero_uuid}/threads", "device threads"),
            (f"/codex-api/v1/threads/{zero_uuid}", "thread detail"),
        ):
            response = self.request(path)
            self.check(
                response.status == 401,
                f"unauthenticated users cannot read {description}",
            )
        unauthenticated_command = self.request(
            f"/codex-api/v1/threads/{zero_uuid}/turns",
            method="POST",
            headers={"Origin": self.origin},
            body={"text": "must not be queued"},
        )
        self.check(
            unauthenticated_command.status == 401,
            "unauthenticated users cannot enqueue commands",
        )
        unauthenticated_approval = self.request(
            f"/codex-api/v1/approvals/{zero_uuid}/decision",
            method="POST",
            headers={"Origin": self.origin},
            body={"decision": "approve"},
        )
        self.check(
            unauthenticated_approval.status == 401,
            "unauthenticated users cannot decide approvals",
        )

        bad_origin = self.request(
            "/codex-api/v1/session/exchange",
            method="POST",
            headers={"Origin": "https://evil.example"},
            body={"access_token": "invalid-access-token-value"},
        )
        self.check(bad_origin.status == 403, "cross-origin session exchange is denied")
        self.check(
            bad_origin.headers.get("Access-Control-Allow-Origin") is None,
            "denial does not grant CORS",
        )

        preflight = self.request(
            "/codex-api/v1/session/exchange",
            method="OPTIONS",
            headers={
                "Origin": "https://evil.example",
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "content-type",
            },
        )
        self.check(
            preflight.status in {403, 405}, "cross-origin preflight is not accepted"
        )
        self.check(
            preflight.headers.get("Access-Control-Allow-Origin") is None,
            "preflight receives no CORS grant",
        )

        invalid = self.request(
            "/codex-api/v1/session/exchange",
            method="POST",
            headers={"Origin": self.origin},
            body={"access_token": "invalid-access-token-value"},
        )
        self.check(invalid.status == 401, "invalid Sub2API access token is rejected")
        self.check(
            b"invalid-access-token-value" not in invalid.body,
            "access token is not reflected",
        )

        browser_ws = self.request(
            "/codex-ws/browser",
            headers=self.websocket_headers(origin=self.origin),
        )
        self.check(
            browser_ws.status != 101,
            "unauthenticated browser WebSocket is not upgraded",
        )
        device_ws = self.request(
            "/codex-ws/device",
            headers=self.websocket_headers(),
        )
        self.check(
            device_ws.status != 101, "unauthenticated device WebSocket is not upgraded"
        )
        unknown_ws = self.request("/codex-ws/raw-rpc")
        self.check(unknown_ws.status == 404, "unknown WebSocket routes fail closed")
        metrics = self.request("/codex-api/internal/metrics")
        self.check(metrics.status == 404, "internal metrics are not exposed publicly")

        if access_token is None:
            print("skip - authenticated exchange checks (no --access-token provided)")
            return

        exchange = self.request(
            "/codex-api/v1/session/exchange",
            method="POST",
            headers={"Origin": self.origin},
            body={"access_token": access_token},
        )
        self.check(
            exchange.status == 201,
            "valid Sub2API token exchanges for a Control session",
        )
        self.check(
            access_token.encode() not in exchange.body,
            "successful exchange does not reflect access token",
        )
        set_cookies = exchange.headers.get_all("Set-Cookie", [])
        session_cookie = next(
            (value for value in set_cookies if "csrf" not in value.lower()), ""
        )
        session_cookie_lower = session_cookie.lower()
        self.check(
            "httponly" in session_cookie_lower, "Control session cookie is HttpOnly"
        )
        self.check(
            "samesite=strict" in session_cookie_lower,
            "Control session cookie is SameSite=Strict",
        )
        if self.expect_secure_cookie:
            self.check(
                "secure" in session_cookie_lower, "Control session cookie is Secure"
            )

        current = self.request("/codex-api/v1/session")
        self.check(
            current.status == 200,
            "Control session cookie authenticates a same-origin request",
        )
        current_body = current.json()
        self.check(
            isinstance(current_body, dict)
            and isinstance(current_body.get("user"), dict)
            and current_body["user"].get("id") == expected_user_id,
            "Control session is bound to the Sub2API identity",
        )

        cookie_header = "; ".join(
            f"{cookie.name}={cookie.value}" for cookie in self.cookies
        )
        browser_status, browser_headers, browser_stream = self.open_websocket(
            "/codex-ws/browser?cursor=0",
            origin=self.origin,
            cookie=cookie_header,
        )
        self.check(
            browser_status == 101,
            "authenticated same-origin browser WebSocket upgrades",
        )
        self.check(
            browser_headers.get("upgrade", "").lower() == "websocket",
            "browser WebSocket upgrade header is preserved",
        )
        if browser_stream is None:
            raise AssertionError("browser WebSocket did not remain open")

        csrf_cookie = next(
            (cookie for cookie in self.cookies if "csrf" in cookie.name.lower()), None
        )
        self.check(csrf_cookie is not None, "exchange issued a CSRF cookie")
        rejected_logout = self.request(
            "/codex-api/v1/session/logout",
            method="POST",
            headers={"Origin": self.origin},
        )
        self.check(
            rejected_logout.status == 403,
            "mutating request without CSRF header is denied",
        )

        csrf_header_name = (
            str(current_body.get("csrf_header_name"))
            if isinstance(current_body, dict) and current_body.get("csrf_header_name")
            else "x-csrf-token"
        )
        dangerous_headers = {
            "Origin": self.origin,
            csrf_header_name: csrf_cookie.value if csrf_cookie else "",
        }
        for path in (
            "/codex-api/v1/thread/shellCommand",
            "/codex-api/v1/command/exec",
            "/codex-api/v1/fs/read",
            "/codex-api/v1/process/list",
            "/codex-api/v1/config/value/write",
            "/codex-api/v1/plugin/install",
            "/codex-api/v1/account/login",
            "/codex-api/v1/oauth/authorize",
            "/codex-api/v1/raw-rpc",
        ):
            response = self.request(
                path, method="POST", headers=dangerous_headers, body={}
            )
            self.check(
                response.status == 404, f"dangerous raw route fails closed: {path}"
            )

        try:
            self.exercise_control(
                pairing_code=pairing_code,
                expected_device_id=expected_device_id,
                workspace_root=workspace_root,
                csrf_headers=dangerous_headers,
                keep_device=keep_device,
                reconnect_only=reconnect_only,
                device_id_file=device_id_file,
                expected_thread_id=expected_thread_id,
                thread_id_file=thread_id_file,
                browser_stream=browser_stream,
                expect_cross_instance_fanout=expect_cross_instance_fanout,
            )
        finally:
            browser_stream.close()

        logout = self.request(
            "/codex-api/v1/session/logout",
            method="POST",
            headers=dangerous_headers,
        )
        self.check(logout.status == 204, "same-origin CSRF-protected logout succeeds")
        revoked = self.request("/codex-api/v1/session")
        self.check(revoked.status == 401, "logout revokes the Control session")

    @staticmethod
    def websocket_headers(origin: str | None = None) -> dict[str, str]:
        headers = {
            "Connection": "Upgrade",
            "Upgrade": "websocket",
            "Sec-WebSocket-Version": "13",
            "Sec-WebSocket-Key": base64.b64encode(os.urandom(16)).decode(),
        }
        if origin is not None:
            headers["Origin"] = origin
        return headers


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Sub2API Codex Control deployment smoke test"
    )
    parser.add_argument(
        "--base-url",
        help="same-origin edge URL, without a path",
    )
    parser.add_argument("--access-token")
    parser.add_argument(
        "--access-token-file",
        help="private 0600 file containing one Sub2API access token",
    )
    parser.add_argument(
        "--expected-user-id",
        help="exact Sub2API identity expected after exchange",
    )
    parser.add_argument(
        "--expected-user-id-file",
        help="private 0600 file containing the expected Sub2API identity",
    )
    parser.add_argument(
        "--insecure", action="store_true", help="accept a self-signed TLS certificate"
    )
    parser.add_argument(
        "--expect-secure-cookie",
        action="store_true",
        help="require Secure on the Control session cookie",
    )
    parser.add_argument(
        "--pairing-code", help="claim a waiting Connector and run control checks"
    )
    parser.add_argument(
        "--expected-device-id", help="wait for an already-paired Connector device"
    )
    parser.add_argument(
        "--workspace-root", help="expected canonical Connector workspace root"
    )
    parser.add_argument(
        "--keep-device",
        action="store_true",
        help="leave the exercised device active for a reconnect test",
    )
    parser.add_argument(
        "--reconnect-only",
        action="store_true",
        help="verify an existing device reconnected, then revoke it",
    )
    parser.add_argument(
        "--device-id-file", help="write the exercised device id to this file"
    )
    parser.add_argument(
        "--expected-thread-id",
        help="managed Control thread id that must survive a Connector app-server restart",
    )
    parser.add_argument(
        "--thread-id-file",
        help="write the exercised managed Control thread id to this file",
    )
    parser.add_argument(
        "--provider-key-canary-file",
        help="file containing the raw provider-key canary that must never reach browser payloads",
    )
    parser.add_argument(
        "--expect-cross-instance-fanout",
        action="store_true",
        help="require the deterministic two-API-instance E2E topology",
    )
    parser.add_argument(
        "--closure-challenge-file",
        help="non-secret challenge created beside the bootstrap deployment record",
    )
    args = parser.parse_args(argv)

    try:
        challenge = None
        if args.closure_challenge_file is not None:
            validate_closure_mode_arguments(args)
            origin = canonical_https_origin(args.base_url, "--base-url")
            challenge = read_closure_challenge(args.closure_challenge_file)
            if origin != challenge.public_origin:
                raise ValueError(
                    "--base-url differs from the closure challenge public origin"
                )
        if not args.base_url:
            raise ValueError("--base-url is required; smoke has no default target")
        base_url = args.base_url
        expected_user_id = args.expected_user_id or os.environ.get(
            "SUB2API_EXPECTED_USER_ID", "42"
        )
        if args.expected_user_id_file:
            if (
                args.expected_user_id is not None
                or "SUB2API_EXPECTED_USER_ID" in os.environ
            ):
                raise ValueError("use only one expected-user-id input")
            expected_user_id = read_private_opaque_file(
                args.expected_user_id_file, "expected user id file"
            )
        access_token = args.access_token or os.environ.get("SUB2API_ACCESS_TOKEN")
        if args.access_token_file:
            if access_token is not None:
                raise ValueError("use only one access-token input")
            access_token = read_private_opaque_file(
                args.access_token_file, "access token file"
            )
        if not expected_user_id or any(
            character.isspace() for character in expected_user_id
        ):
            raise ValueError(
                "--expected-user-id must be one non-empty opaque identifier"
            )
        if args.reconnect_only and not args.expected_device_id:
            raise ValueError("--reconnect-only requires --expected-device-id")
        if args.reconnect_only and not args.expected_thread_id:
            raise ValueError("--reconnect-only requires --expected-thread-id")
        provider_key_canary = None
        if args.provider_key_canary_file:
            provider_key_canary = (
                Path(args.provider_key_canary_file).read_text(encoding="utf-8").strip()
            )
            if not provider_key_canary:
                raise ValueError("--provider-key-canary-file is empty")
        smoke = Smoke(
            base_url,
            args.insecure,
            args.expect_secure_cookie,
            provider_key_canary,
            closure_catalog_required=challenge is not None,
        )
        smoke.run(
            access_token,
            expected_user_id=expected_user_id,
            pairing_code=args.pairing_code,
            expected_device_id=args.expected_device_id,
            workspace_root=args.workspace_root,
            keep_device=args.keep_device,
            reconnect_only=args.reconnect_only,
            device_id_file=args.device_id_file,
            expected_thread_id=args.expected_thread_id,
            thread_id_file=args.thread_id_file,
            expect_cross_instance_fanout=args.expect_cross_instance_fanout,
        )
        if challenge is not None:
            smoke.validate_closure_catalog()
    except (AssertionError, OSError, ValueError, json.JSONDecodeError) as error:
        print(f"not ok - {error}", file=sys.stderr)
        return 1
    challenge_suffix = ""
    if challenge is not None:
        challenge_suffix = (
            f" # closure-challenge-sha256={challenge.challenge_sha256}"
            f" target-binding-sha256={challenge.target_binding_sha256}"
        )
    print(f"1..{smoke.passed}{challenge_suffix}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
