#!/usr/bin/env python3
"""Exercise the pinned Sub2API auth contract with disposable fixture tokens."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, NoReturn

MAX_BODY_BYTES = 1024 * 1024
MAX_TOKEN_BYTES = 64 * 1024
MAX_EVIDENCE_BYTES = 4 * 1024 * 1024
EXPECTED_AUTH_ORIGIN = "http://127.0.0.1:8080"
CONTAINER_ID_RE = re.compile(r"^[0-9a-f]{64}$")
IMAGE_ID_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
IMAGE_DIGEST_RE = re.compile(r"^[^\s@]+@sha256:[0-9a-f]{64}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
NONCE_RE = re.compile(r"^[0-9a-f]{64}$")


def fail(message: str) -> NoReturn:
    raise ValueError(message)


def read_stable_file(
    path: Path,
    label: str,
    *,
    max_bytes: int,
    private: bool,
) -> bytes:
    try:
        path_metadata = path.lstat()
    except OSError as exc:
        fail(f"cannot inspect {label}: {exc}")
    if stat.S_ISLNK(path_metadata.st_mode) or not stat.S_ISREG(path_metadata.st_mode):
        fail(f"{label} must be a regular non-symlink file")

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        fail(f"cannot securely open {label}: {exc}")
    try:
        opened_metadata = os.fstat(descriptor)
        if not stat.S_ISREG(opened_metadata.st_mode):
            fail(f"{label} is not a regular file")
        if (path_metadata.st_dev, path_metadata.st_ino) != (
            opened_metadata.st_dev,
            opened_metadata.st_ino,
        ):
            fail(f"{label} changed while it was opened")
        if opened_metadata.st_uid != os.geteuid():
            fail(f"{label} must be owned by the probe user")
        if opened_metadata.st_nlink != 1:
            fail(f"{label} must have exactly one hard link")
        forbidden_mode = 0o077 if private else 0o022
        if stat.S_IMODE(opened_metadata.st_mode) & forbidden_mode:
            requirement = "0600" if private else "not group/other writable"
            fail(f"{label} permissions must be {requirement}")
        if opened_metadata.st_size > max_bytes:
            fail(f"{label} exceeds its {max_bytes}-byte limit")

        content = bytearray()
        while len(content) <= max_bytes:
            chunk = os.read(descriptor, min(64 * 1024, max_bytes + 1 - len(content)))
            if not chunk:
                break
            content.extend(chunk)
        metadata_after = os.fstat(descriptor)
        stable_before = (
            opened_metadata.st_dev,
            opened_metadata.st_ino,
            opened_metadata.st_size,
            opened_metadata.st_mtime_ns,
            opened_metadata.st_ctime_ns,
        )
        stable_after = (
            metadata_after.st_dev,
            metadata_after.st_ino,
            metadata_after.st_size,
            metadata_after.st_mtime_ns,
            metadata_after.st_ctime_ns,
        )
        if stable_before != stable_after:
            fail(f"{label} changed while it was read")
    except OSError as exc:
        fail(f"cannot read {label}: {exc}")
    finally:
        os.close(descriptor)
    if len(content) > max_bytes:
        fail(f"{label} exceeds its {max_bytes}-byte limit")
    return bytes(content)


def decode_json_object(raw: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        fail(f"{label} is not one valid UTF-8 JSON object: {exc}")
    if not isinstance(value, dict):
        fail(f"{label} must contain one JSON object")
    return value


def read_token(path: Path, label: str) -> str:
    raw = read_stable_file(
        path, f"{label} file", max_bytes=MAX_TOKEN_BYTES, private=True
    )
    try:
        value = raw.decode("utf-8").rstrip("\r\n")
    except UnicodeDecodeError as exc:
        fail(f"{label} file is not valid UTF-8: {exc}")
    if not value or any(character.isspace() for character in value):
        fail(f"{label} file does not contain one opaque token")
    return value


def load_runtime(path: Path) -> dict[str, str]:
    value = decode_json_object(
        read_stable_file(
            path,
            "runtime attestation",
            max_bytes=MAX_EVIDENCE_BYTES,
            private=False,
        ),
        "runtime attestation",
    )
    fields = {
        "container_id": value.get("container_id"),
        "image_id": value.get("image_id"),
        "image_digest": value.get("image_digest"),
        "binary_sha256": value.get("binary_sha256"),
        "version": value.get("runtime_version"),
        "commit": value.get("runtime_commit"),
        "contract_sha256": value.get("contract_sha256"),
    }
    if any(not isinstance(field, str) or not field for field in fields.values()):
        fail("runtime attestation is incomplete")
    typed = fields  # Preserve a narrow string-only mapping after the check above.
    if not CONTAINER_ID_RE.fullmatch(typed["container_id"]):
        fail("runtime attestation container ID is invalid")
    if not IMAGE_ID_RE.fullmatch(typed["image_id"]):
        fail("runtime attestation image ID is invalid")
    if not IMAGE_DIGEST_RE.fullmatch(typed["image_digest"]):
        fail("runtime attestation image digest is invalid")
    if not SHA256_RE.fullmatch(typed["binary_sha256"]):
        fail("runtime attestation binary hash is invalid")
    if not COMMIT_RE.fullmatch(typed["commit"]):
        fail("runtime attestation commit is invalid")
    if not SHA256_RE.fullmatch(typed["contract_sha256"]):
        fail("runtime attestation contract hash is invalid")
    return typed  # type: ignore[return-value]


def exact_keys(value: dict[str, Any], expected: set[str], label: str) -> None:
    if set(value) != expected:
        fail(f"{label} keys differ from the pinned contract")


def endpoint_path(value: Any, *, method: str, label: str) -> str:
    if not isinstance(value, dict) or value.get("method") != method:
        fail(f"{label} endpoint method differs from the pinned contract")
    path = value.get("path")
    if (
        not isinstance(path, str)
        or not path.startswith("/api/v1/auth/")
        or urllib.parse.urlsplit(path).query
        or urllib.parse.urlsplit(path).fragment
    ):
        fail(f"{label} endpoint path differs from the pinned contract")
    return path


def auth_error(value: Any, label: str) -> tuple[int, str]:
    if (
        not isinstance(value, dict)
        or set(value) != {"status", "code"}
        or value.get("status") != 401
        or not isinstance(value.get("code"), str)
        or not value["code"]
    ):
        fail(f"{label} error semantics differ from the pinned contract")
    return value["status"], value["code"]


def load_contract(path: Path, runtime: dict[str, str]) -> tuple[dict[str, Any], str]:
    raw = read_stable_file(
        path,
        "Sub2API auth contract",
        max_bytes=MAX_EVIDENCE_BYTES,
        private=False,
    )
    observed_sha256 = hashlib.sha256(raw).hexdigest()
    if observed_sha256 != runtime["contract_sha256"]:
        fail("Sub2API auth contract hash differs from the runtime attestation")
    contract = decode_json_object(raw, "Sub2API auth contract")
    exact_keys(
        contract,
        {
            "format_version",
            "runtime",
            "source",
            "local_storage",
            "endpoints",
            "control_boundary",
        },
        "Sub2API auth contract",
    )
    if contract.get("format_version") != 1:
        fail("Sub2API auth contract format version is unsupported")
    contract_runtime = contract.get("runtime")
    if not isinstance(contract_runtime, dict) or (
        contract_runtime.get("version") != runtime["version"]
        or contract_runtime.get("commit") != runtime["commit"]
    ):
        fail("Sub2API auth contract runtime tuple differs from the attested runtime")
    endpoints = contract.get("endpoints")
    if not isinstance(endpoints, dict) or set(endpoints) != {
        "identity",
        "refresh",
        "logout",
    }:
        fail("Sub2API auth contract endpoint inventory is invalid")
    identity = endpoints["identity"]
    refresh = endpoints["refresh"]
    logout = endpoints["logout"]
    identity_path = endpoint_path(identity, method="GET", label="identity")
    refresh_path = endpoint_path(refresh, method="POST", label="refresh")
    logout_path = endpoint_path(logout, method="POST", label="logout")
    if identity.get("authorization") != "bearer_access_token":
        fail("identity endpoint authorization differs from the pinned contract")
    disabled_status, disabled_code = auth_error(
        identity.get("disabled_user_error"), "disabled-user"
    )
    revoked_status, revoked_code = auth_error(
        identity.get("revoked_token_error"), "revoked-token"
    )
    session_binding_mismatch_status, session_binding_mismatch_code = auth_error(
        identity.get("session_binding_mismatch_error"),
        "session-binding-mismatch",
    )
    if disabled_code != "USER_INACTIVE" or revoked_code != "TOKEN_REVOKED":
        fail("identity rejection codes differ from the pinned runtime middleware")
    if session_binding_mismatch_code != "SESSION_BINDING_MISMATCH":
        fail("session-binding rejection code must be SESSION_BINDING_MISMATCH")
    session_binding_request = identity.get("session_binding_request")
    if not isinstance(session_binding_request, dict) or session_binding_request != {
        "client_ip_header": "X-Forwarded-For",
        "user_agent_header": "User-Agent",
    }:
        fail("session-binding request headers differ from the pinned contract")
    if (
        refresh.get("request_required") != ["refresh_token"]
        or refresh.get("response_envelope")
        != {
            "required": ["code", "message", "data"],
            "code": 0,
            "message": "success",
            "data_required": [
                "access_token",
                "refresh_token",
                "expires_in",
                "token_type",
            ],
        }
        or refresh.get("token_type") != "Bearer"
        or refresh.get("rotates_refresh_token") is not True
    ):
        fail("refresh endpoint semantics differ from the pinned contract")
    if logout.get("authorization") != "optional_bearer_access_token" or logout.get(
        "request_required"
    ) != ["refresh_token"]:
        fail("logout endpoint semantics differ from the pinned contract")
    boundary = contract.get("control_boundary")
    if not isinstance(boundary, dict) or (
        boundary.get("accepted_sub2api_fields") != ["access_token"]
        or boundary.get("forbidden_sub2api_fields") != ["refresh_token"]
    ):
        fail("control boundary differs from the pinned contract")
    return {
        "identity": identity_path,
        "refresh": refresh_path,
        "logout": logout_path,
        "disabled_status": disabled_status,
        "disabled_code": disabled_code,
        "revoked_status": revoked_status,
        "revoked_code": revoked_code,
        "session_binding_mismatch_status": session_binding_mismatch_status,
        "session_binding_mismatch_code": session_binding_mismatch_code,
        "session_binding_client_ip_header": session_binding_request["client_ip_header"],
        "session_binding_user_agent_header": session_binding_request[
            "user_agent_header"
        ],
    }, observed_sha256


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str
    ) -> None:
        return None


def request(
    opener: urllib.request.OpenerDirector,
    url: str,
    *,
    method: str,
    bearer: str | None = None,
    payload: dict[str, Any] | None = None,
    additional_headers: dict[str, str] | None = None,
    timeout: float,
) -> tuple[int, Any | None]:
    headers = {"Accept": "application/json"}
    body = None
    if bearer is not None:
        headers["Authorization"] = f"Bearer {bearer}"
    if payload is not None:
        headers["Content-Type"] = "application/json"
        body = json.dumps(payload, separators=(",", ":")).encode()
    if additional_headers is not None:
        headers.update(additional_headers)
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        response = opener.open(req, timeout=timeout)
    except urllib.error.HTTPError as exc:
        response = exc
    except (OSError, urllib.error.URLError) as exc:
        fail(f"auth fixture request failed before an HTTP response: {exc}")
    with response:
        final_url = response.geturl()
        raw = response.read(MAX_BODY_BYTES + 1)
        status = response.status
    if final_url != url:
        fail("auth fixture request changed endpoint")
    if len(raw) > MAX_BODY_BYTES:
        fail("auth fixture response exceeded 1 MiB")
    if not raw:
        return status, None
    try:
        return status, json.loads(raw)
    except json.JSONDecodeError:
        return status, None


def identity_value(body: Any) -> str | None:
    if not isinstance(body, dict):
        return None
    candidate = body.get("data", body)
    if isinstance(candidate, dict) and isinstance(candidate.get("user"), dict):
        candidate = candidate["user"]
    if not isinstance(candidate, dict):
        return None
    value = candidate.get("id", candidate.get("user_id", candidate.get("userId")))
    if value is None or isinstance(value, bool):
        return None
    normalized = str(value).strip()
    return normalized or None


def response_error_code(body: Any) -> str | None:
    if not isinstance(body, dict) or not isinstance(body.get("code"), str):
        return None
    return body["code"]


def refresh_response_data(body: Any) -> dict[str, Any]:
    if not isinstance(body, dict) or set(body) != {"code", "message", "data"}:
        fail("refresh fixture response envelope differs from the pinned contract")
    if body.get("code") != 0 or body.get("message") != "success":
        fail("refresh fixture response envelope is not a pinned success response")
    data = body.get("data")
    if not isinstance(data, dict) or set(data) != {
        "access_token",
        "refresh_token",
        "expires_in",
        "token_type",
    }:
        fail("refresh fixture response data differs from the pinned contract")
    return data


def run(args: argparse.Namespace) -> dict[str, Any]:
    base_url = args.base_url.rstrip("/")
    if base_url != EXPECTED_AUTH_ORIGIN:
        fail(f"auth probe origin must be exactly {EXPECTED_AUTH_ORIGIN}")
    if not NONCE_RE.fullmatch(args.probe_nonce):
        fail("probe nonce must be 64 lowercase hexadecimal characters")
    expected_user_id = args.expected_user_id
    if (
        not isinstance(expected_user_id, str)
        or not expected_user_id
        or len(expected_user_id) > 256
        or expected_user_id.strip() != expected_user_id
        or any(character.isspace() for character in expected_user_id)
    ):
        fail(
            "expected user ID must be one non-whitespace value of at most 256 characters"
        )

    runtime = load_runtime(args.runtime_attestation)
    endpoint_paths, contract_sha256 = load_contract(args.contract_file, runtime)
    active_access = read_token(args.active_access_token_file, "active access token")
    active_refresh = read_token(args.active_refresh_token_file, "active refresh token")
    disabled_access = read_token(
        args.disabled_access_token_file, "disabled access token"
    )
    revoked_access = read_token(args.revoked_access_token_file, "revoked access token")
    if len({active_access, active_refresh, disabled_access, revoked_access}) != 4:
        fail("auth fixture token files must contain four distinct values")

    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    me_url = f"{base_url}{endpoint_paths['identity']}"
    refresh_url = f"{base_url}{endpoint_paths['refresh']}"
    logout_url = f"{base_url}{endpoint_paths['logout']}"

    me_status, me_body = request(
        opener, me_url, method="GET", bearer=active_access, timeout=args.timeout
    )
    active_user_id = identity_value(me_body)
    if me_status != 200 or active_user_id != expected_user_id:
        fail("active identity fixture did not return the exact expected user")
    disabled_status, disabled_body = request(
        opener, me_url, method="GET", bearer=disabled_access, timeout=args.timeout
    )
    disabled_code = response_error_code(disabled_body)
    if (
        disabled_status != endpoint_paths["disabled_status"]
        or disabled_code != endpoint_paths["disabled_code"]
    ):
        fail("disabled identity fixture did not prove USER_INACTIVE semantics")
    revoked_status, revoked_body = request(
        opener, me_url, method="GET", bearer=revoked_access, timeout=args.timeout
    )
    revoked_code = response_error_code(revoked_body)
    if (
        revoked_status != endpoint_paths["revoked_status"]
        or revoked_code != endpoint_paths["revoked_code"]
    ):
        fail("revoked identity fixture did not prove TOKEN_REVOKED semantics")

    refresh_status, refresh_body = request(
        opener,
        refresh_url,
        method="POST",
        payload={"refresh_token": active_refresh},
        timeout=args.timeout,
    )
    if refresh_status != 200:
        fail("refresh fixture failed")
    refresh_data = refresh_response_data(refresh_body)
    new_access = refresh_data.get("access_token")
    new_refresh = refresh_data.get("refresh_token")
    expires_in = refresh_data.get("expires_in")
    token_type = refresh_data.get("token_type")
    if (
        not isinstance(new_access, str)
        or not new_access
        or new_access == active_access
        or not isinstance(new_refresh, str)
        or not new_refresh
        or new_refresh == active_refresh
        or isinstance(expires_in, bool)
        or not isinstance(expires_in, int)
        or expires_in <= 0
        or token_type != "Bearer"
    ):
        fail("refresh fixture returned an invalid or non-rotating token pair")

    refreshed_status, refreshed_body = request(
        opener, me_url, method="GET", bearer=new_access, timeout=args.timeout
    )
    if refreshed_status != 200 or identity_value(refreshed_body) != active_user_id:
        fail("refreshed access token did not preserve the exact active identity")
    old_refresh_status, _ = request(
        opener,
        refresh_url,
        method="POST",
        payload={"refresh_token": active_refresh},
        timeout=args.timeout,
    )
    if old_refresh_status not in {401, 403}:
        fail("rotated refresh fixture still accepts the old token")

    binding_status, binding_body = request(
        opener,
        me_url,
        method="GET",
        bearer=new_access,
        additional_headers={
            endpoint_paths["session_binding_client_ip_header"]: "203.0.113.254",
            endpoint_paths["session_binding_user_agent_header"]: (
                f"sub2api-auth-contract-probe/{args.probe_nonce}"
            ),
        },
        timeout=args.timeout,
    )
    binding_code = response_error_code(binding_body)
    if (
        binding_status != endpoint_paths["session_binding_mismatch_status"]
        or binding_code != endpoint_paths["session_binding_mismatch_code"]
    ):
        fail("session-binding fixture did not prove IP/User-Agent mismatch semantics")

    logout_status, _ = request(
        opener,
        logout_url,
        method="POST",
        bearer=new_access,
        payload={"refresh_token": new_refresh},
        timeout=args.timeout,
    )
    if logout_status not in {200, 204}:
        fail("logout fixture failed")
    post_logout_status, _ = request(
        opener,
        refresh_url,
        method="POST",
        payload={"refresh_token": new_refresh},
        timeout=args.timeout,
    )
    if post_logout_status not in {401, 403}:
        fail("logout fixture did not revoke the rotated refresh token")

    return {
        "format_version": 4,
        "captured_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "probe": {
            "base_url": base_url,
            "nonce": args.probe_nonce,
            "expected_user_id": expected_user_id,
            "network_namespace_container_id": runtime["container_id"],
            "proxy_environment_disabled": True,
        },
        "runtime": runtime,
        "contract_sha256": contract_sha256,
        "fixtures": {
            "auth_me_success": {
                "status": me_status,
                "identity_present": True,
                "user_id": active_user_id,
            },
            "auth_me_disabled": {
                "status": disabled_status,
                "code": disabled_code,
            },
            "auth_me_revoked": {
                "status": revoked_status,
                "code": revoked_code,
            },
            "auth_me_session_binding_mismatch": {
                "status": binding_status,
                "code": binding_code,
                "ip_and_user_agent_changed": True,
            },
            "refresh_rotation": {
                "status": refresh_status,
                "access_token_present": True,
                "refresh_token_present": True,
                "expires_in_positive": True,
                "token_type": "Bearer",
                "refresh_rotated": True,
                "refreshed_identity_status": refreshed_status,
                "same_identity": True,
                "old_refresh_rejected_status": old_refresh_status,
            },
            "logout": {
                "status": logout_status,
                "refresh_after_logout_status": post_logout_status,
            },
        },
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--active-access-token-file", type=Path, required=True)
    parser.add_argument("--active-refresh-token-file", type=Path, required=True)
    parser.add_argument("--disabled-access-token-file", type=Path, required=True)
    parser.add_argument("--revoked-access-token-file", type=Path, required=True)
    parser.add_argument("--runtime-attestation", type=Path, required=True)
    parser.add_argument("--contract-file", type=Path, required=True)
    parser.add_argument("--probe-nonce", required=True)
    parser.add_argument("--expected-user-id", required=True)
    parser.add_argument("--timeout", type=float, default=5.0)
    args = parser.parse_args()
    if args.timeout <= 0:
        parser.error("--timeout must be positive")
    return args


def main() -> int:
    try:
        value = run(parse_args())
    except (KeyError, TypeError, ValueError) as exc:
        print(f"probe-sub2api-auth-contract: {exc}", file=sys.stderr)
        return 1
    json.dump(value, sys.stdout, sort_keys=True, separators=(",", ":"))
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
