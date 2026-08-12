from __future__ import annotations

import base64
import hashlib
import hmac
import posixpath
import re
import secrets
import struct
import uuid
from dataclasses import dataclass
from urllib.parse import urlsplit

from fastapi import HTTPException, Request, status

from .config import Settings

_REQUEST_ID_PATTERN = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_PAIRING_CODE_PATTERN = re.compile(
    r"^[23456789ABCDEFGHJKLMNPQRSTUVWXYZ]{4}"
    r"(?:-[23456789ABCDEFGHJKLMNPQRSTUVWXYZ]{4}){3}$"
)
PAIRING_START_PROOF_DOMAIN = b"sub2api-codex-control/pairing-start/v2\0"


class TokenDigester:
    def __init__(self, secret: str) -> None:
        self._secret = secret.encode("utf-8")

    def digest(self, purpose: str, value: str) -> str:
        message = f"{purpose}\0{value}".encode()
        return hmac.new(self._secret, message, hashlib.sha256).hexdigest()

    def matches(self, purpose: str, value: str, expected_digest: str) -> bool:
        return secrets.compare_digest(self.digest(purpose, value), expected_digest)


def random_token(byte_count: int = 32) -> str:
    return secrets.token_urlsafe(byte_count)


def pairing_secret_commitment(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def pairing_start_proof(
    *,
    pairing_id: uuid.UUID,
    created_at: str,
    audience: str,
    public_key: str,
    code_commitment: str,
    poll_token_commitment: str,
    refresh_credential_commitment: str,
    display_name: str,
    connector_version: str,
    codex_version: str,
    workspace_roots: list[str],
) -> bytes:
    fields = (
        str(pairing_id),
        created_at,
        audience,
        public_key,
        code_commitment,
        poll_token_commitment,
        refresh_credential_commitment,
        display_name,
        connector_version,
        codex_version,
    )
    proof = bytearray(PAIRING_START_PROOF_DOMAIN)
    for value in fields:
        proof.extend(hashlib.sha256(value.encode("utf-8")).digest())
    proof.extend(struct.pack(">I", len(workspace_roots)))
    for root in workspace_roots:
        proof.extend(hashlib.sha256(root.encode("utf-8")).digest())
    return bytes(proof)


def normalize_pairing_code(code: str) -> str:
    if _PAIRING_CODE_PATTERN.fullmatch(code) is None:
        raise ValueError("pairing code is not canonical")
    return code.replace("-", "")


def canonicalize_ed25519_public_key(value: str) -> str:
    encoded = value.strip()
    if encoded.startswith("ed25519:"):
        encoded = encoded.removeprefix("ed25519:")
    try:
        padding = "=" * (-len(encoded) % 4)
        raw = base64.urlsafe_b64decode(encoded + padding)
    except (ValueError, base64.binascii.Error) as exc:
        raise ValueError("public_key must be base64url-encoded Ed25519 key material") from exc
    if len(raw) != 32:
        raise ValueError("public_key must decode to exactly 32 bytes")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def canonicalize_workspace_roots(roots: list[str]) -> list[str]:
    if not roots:
        raise ValueError("workspace_roots must contain at least one directory")
    if len(roots) > 32:
        raise ValueError("workspace_roots cannot contain more than 32 directories")

    canonical: list[str] = []
    seen: set[str] = set()
    for index, root in enumerate(roots):
        if not root or len(root.encode("utf-8")) > 4096:
            raise ValueError(f"workspace_roots[{index}] has an invalid length")
        if any(ord(character) < 32 for character in root):
            raise ValueError(f"workspace_roots[{index}] contains a control character")
        if not root.startswith("/") or root.startswith("//"):
            raise ValueError(f"workspace_roots[{index}] must be an absolute POSIX path")
        if root == "/":
            raise ValueError("the filesystem root cannot be a workspace root")
        if posixpath.normpath(root) != root:
            raise ValueError(f"workspace_roots[{index}] must be canonical")
        if root in seen:
            raise ValueError(f"workspace root {root!r} is duplicated")
        seen.add(root)
        canonical.append(root)
    return canonical


def validate_origin(request: Request, settings: Settings) -> None:
    origin = request.headers.get("origin")
    if origin is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="origin_required",
        )
    if not origin_is_allowed(origin, settings):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="origin_not_allowed",
        )
    fetch_site = request.headers.get("sec-fetch-site")
    if fetch_site is not None and fetch_site.lower() not in {"same-origin", "none"}:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="fetch_metadata_not_allowed",
        )


def origin_is_allowed(origin: str, settings: Settings) -> bool:
    normalized = origin.rstrip("/")
    parsed = urlsplit(normalized)
    return not (
        parsed.scheme not in {"http", "https"}
        or not parsed.netloc
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
        or normalized not in settings.allowed_origins
    )


def client_ip(request: Request, settings: Settings) -> str:
    if settings.trust_forwarded_for:
        forwarded_for = request.headers.get("x-forwarded-for", "")
        if forwarded_for:
            candidate = forwarded_for.split(",", 1)[0].strip()
            if candidate:
                return candidate[:64]
    if request.client is None:
        return "unknown"
    return request.client.host[:64]


def request_id(request: Request) -> str | None:
    value = getattr(request.state, "request_id", None)
    return value if isinstance(value, str) and _REQUEST_ID_PATTERN.fullmatch(value) else None


@dataclass(frozen=True)
class CookieTokens:
    session_token: str
    csrf_token: str
