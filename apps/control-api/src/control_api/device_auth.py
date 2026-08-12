from __future__ import annotations

import base64
import binascii
import hashlib
import json
import secrets
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from sqlalchemy.ext.asyncio import AsyncSession

from .config import Settings
from .models import AuditEvent, AuditOutcome, Device, DeviceStatus
from .schemas import DeviceConnectTokenRequest
from .security import (
    TokenDigester,
    canonicalize_ed25519_public_key,
    pairing_secret_commitment,
    random_token,
)
from .services import RequestMetadata
from .storage import KeyValueStore


class DeviceAuthenticationError(Exception):
    pass


class DeviceCredentialRejected(DeviceAuthenticationError):
    pass


class DeviceProofRejected(DeviceAuthenticationError):
    pass


class DeviceProofReplay(DeviceAuthenticationError):
    pass


@dataclass(frozen=True)
class IssuedDeviceToken:
    value: str
    expires_at: datetime


def _decode_base64url(value: str, expected_length: int, field: str) -> bytes:
    try:
        raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, binascii.Error) as exc:
        raise DeviceProofRejected(f"{field} is not valid base64url") from exc
    if len(raw) != expected_length:
        raise DeviceProofRejected(f"{field} has an invalid length")
    return raw


def _parse_rfc3339(value: str) -> datetime:
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise DeviceProofRejected("timestamp must be RFC3339") from exc
    if parsed.tzinfo is None:
        raise DeviceProofRejected("timestamp must include a timezone")
    return parsed.astimezone(UTC)


class DeviceTokenService:
    def __init__(
        self,
        settings: Settings,
        store: KeyValueStore,
        digester: TokenDigester,
    ) -> None:
        self._settings = settings
        self._store = store
        self._digester = digester

    async def issue(
        self,
        db: AsyncSession,
        authorization: str | None,
        payload: DeviceConnectTokenRequest,
        metadata: RequestMetadata,
    ) -> IssuedDeviceToken:
        refresh_credential = self._device_authorization(authorization)
        device = await db.get(Device, payload.device_id)
        if device is None or device.status != DeviceStatus.ACTIVE:
            await self._audit_denied(
                db,
                payload.device_id,
                metadata,
                "device_unavailable",
                actor_exists=device is not None,
            )
            raise DeviceCredentialRejected("device credential was rejected")
        credential_matches = False
        if device.refresh_credential_hash is not None:
            if device.credential_scheme == 1:
                credential_matches = self._digester.matches(
                    "device-refresh", refresh_credential, device.refresh_credential_hash
                )
            elif device.credential_scheme == 2:
                credential_matches = self._digester.matches(
                    "device-refresh-v2",
                    pairing_secret_commitment(refresh_credential),
                    device.refresh_credential_hash,
                )
        if not credential_matches:
            await self._audit_denied(db, device.id, metadata, "invalid_refresh_credential")
            raise DeviceCredentialRejected("device credential was rejected")

        try:
            canonical_key = canonicalize_ed25519_public_key(payload.public_key)
        except ValueError as exc:
            await self._audit_denied(db, device.id, metadata, "invalid_public_key")
            raise DeviceProofRejected(str(exc)) from exc
        if not secrets.compare_digest(canonical_key, device.public_key):
            await self._audit_denied(db, device.id, metadata, "public_key_mismatch")
            raise DeviceProofRejected("device proof was rejected")

        proof_time = _parse_rfc3339(payload.timestamp)
        now = datetime.now(UTC)
        if abs((now - proof_time).total_seconds()) > self._settings.device_proof_max_skew_seconds:
            await self._audit_denied(db, device.id, metadata, "timestamp_outside_window")
            raise DeviceProofRejected("device proof timestamp is outside the allowed window")
        nonce = _decode_base64url(payload.nonce, 24, "nonce")
        signature = _decode_base64url(payload.signature, 64, "signature")
        public_key = _decode_base64url(canonical_key, 32, "public_key")
        proof = f"{payload.device_id}\n{payload.timestamp}\n{payload.nonce}".encode()
        try:
            Ed25519PublicKey.from_public_bytes(public_key).verify(signature, proof)
        except InvalidSignature as exc:
            await self._audit_denied(db, device.id, metadata, "invalid_signature")
            raise DeviceProofRejected("device proof was rejected") from exc

        nonce_digest = hashlib.sha256(nonce).hexdigest()
        claimed = await self._store.set_if_absent(
            f"device-proof-nonce:{device.id}:{nonce_digest}",
            "1",
            self._settings.device_nonce_ttl_seconds,
        )
        if not claimed:
            await self._audit_denied(db, device.id, metadata, "nonce_replay")
            raise DeviceProofReplay("device proof nonce was already used")

        access_token = f"dca_{random_token(48)}"
        token_hash = self._digester.digest("device-access", access_token)
        current_key = f"device-access-current:{device.id}"
        previous_hash = await self._store.get(current_key)
        if previous_hash:
            await self._store.delete(f"device-access:{previous_hash}")
        token_data = json.dumps(
            {
                "device_id": str(device.id),
                "credential_version": device.credential_version,
            },
            separators=(",", ":"),
        )
        ttl = self._settings.device_access_token_ttl_seconds
        await self._store.set(f"device-access:{token_hash}", token_data, ttl)
        await self._store.set(current_key, token_hash, ttl)
        expires_at = now + timedelta(seconds=ttl)
        db.add(
            AuditEvent(
                actor_user_id=device.owner_user_id,
                actor_device_id=device.id,
                action="device.connect_token.issue",
                outcome=AuditOutcome.SUCCEEDED,
                resource_type="device",
                resource_id=str(device.id),
                request_id=metadata.request_id,
                source_ip=metadata.source_ip,
                user_agent=metadata.user_agent,
                details={"credential_version": device.credential_version},
            )
        )
        await db.commit()
        return IssuedDeviceToken(access_token, expires_at)

    async def authenticate_access_token(
        self,
        db: AsyncSession,
        access_token: str,
    ) -> Device | None:
        token_hash = self._digester.digest("device-access", access_token)
        raw = await self._store.get(f"device-access:{token_hash}")
        if raw is None:
            return None
        try:
            data = json.loads(raw)
            device_id = uuid.UUID(str(data["device_id"]))
            credential_version = int(data["credential_version"])
        except (ValueError, TypeError, KeyError, json.JSONDecodeError):
            await self._store.delete(f"device-access:{token_hash}")
            return None
        current_hash = await self._store.get(f"device-access-current:{device_id}")
        if current_hash is None or not secrets.compare_digest(current_hash, token_hash):
            return None
        device = await db.get(Device, device_id)
        if (
            device is None
            or device.status != DeviceStatus.ACTIVE
            or device.credential_version != credential_version
        ):
            return None
        return device

    async def revoke_access_token(self, device_id: uuid.UUID) -> None:
        current_key = f"device-access-current:{device_id}"
        token_hash = await self._store.get(current_key)
        if token_hash:
            await self._store.delete(f"device-access:{token_hash}")
        await self._store.delete(current_key)

    @staticmethod
    def _device_authorization(authorization: str | None) -> str:
        if authorization is None or not authorization.startswith("Device "):
            raise DeviceCredentialRejected("device authorization is required")
        credential = authorization.removeprefix("Device ").strip()
        if not credential:
            raise DeviceCredentialRejected("device authorization is required")
        return credential

    @staticmethod
    async def _audit_denied(
        db: AsyncSession,
        device_id: uuid.UUID,
        metadata: RequestMetadata,
        reason: str,
        *,
        actor_exists: bool = True,
    ) -> None:
        db.add(
            AuditEvent(
                actor_device_id=device_id if actor_exists else None,
                action="device.connect_token.issue",
                outcome=AuditOutcome.DENIED,
                resource_type="device",
                resource_id=str(device_id),
                request_id=metadata.request_id,
                source_ip=metadata.source_ip,
                user_agent=metadata.user_agent,
                details={"reason": reason},
            )
        )
        await db.commit()
