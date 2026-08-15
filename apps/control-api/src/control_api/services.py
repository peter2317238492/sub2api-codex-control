from __future__ import annotations

import asyncio
import base64
import binascii
import logging
import secrets
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from weakref import WeakValueDictionary

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from sqlalchemy import delete, func, or_, select, text, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from .capacity import (
    OwnerCapacityExceeded,
    active_device_count,
    ensure_device_projection_fits,
    total_device_count,
)
from .config import Settings
from .events import EventService
from .models import (
    AuditEvent,
    AuditOutcome,
    ControlSession,
    Device,
    DevicePairing,
    DeviceStatus,
    PairingStatus,
)
from .security import (
    CONTROL_SESSION_DIGEST_PURPOSE,
    CookieTokens,
    SessionCredentialProtector,
    TokenDigester,
    canonicalize_ed25519_public_key,
    canonicalize_workspace_roots,
    normalize_pairing_code,
    pairing_secret_commitment,
    pairing_start_proof,
    random_token,
)
from .storage import KeyValueStore
from .sub2api import (
    DisabledSub2APIUser,
    InvalidSub2APIToken,
    RevokedSub2APIToken,
    Sub2APIIdentityVerifier,
    Sub2APIRequestIdentity,
    Sub2APIUser,
)

CONTROL_SESSION_REVOCATION_CHANNEL_PREFIX = "control-session-revoked"
MAX_LIVE_PAIRINGS_GLOBAL = 2_048
MAX_LIVE_PAIRINGS_PER_SOURCE = 16
MAX_RETAINED_PAIRINGS_GLOBAL = 10_000
MAX_RETAINED_PAIRINGS_PER_SOURCE = 100
_LOGGER = logging.getLogger(__name__)


def control_session_revocation_channel(session_id: uuid.UUID) -> str:
    return f"{CONTROL_SESSION_REVOCATION_CHANNEL_PREFIX}:{session_id}"


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


@dataclass(frozen=True)
class RequestMetadata:
    source_ip: str | None
    user_agent: str | None
    request_id: str | None


@dataclass(frozen=True)
class CreatedSession:
    record: ControlSession
    cookies: CookieTokens


@dataclass(frozen=True)
class StartedPairing:
    record: DevicePairing


@dataclass(frozen=True)
class PairingPollResult:
    record: DevicePairing
    device: Device | None = None


class PairingError(Exception):
    pass


class PairingNotFound(PairingError):
    pass


class PairingUnauthorized(PairingError):
    pass


class PairingExpired(PairingError):
    pass


class PairingConflict(PairingError):
    pass


class PairingProofRejected(PairingError):
    pass


class PairingCapacityExceeded(PairingError):
    pass


class RateLimitExceeded(Exception):
    def __init__(self, retry_after: int) -> None:
        self.retry_after = retry_after
        super().__init__("rate limit exceeded")


class SessionCapacityExceeded(Exception):
    pass


class RateLimiter:
    def __init__(self, store: KeyValueStore, window_seconds: int) -> None:
        self._store = store
        self._window_seconds = window_seconds

    async def check(self, scope: str, identity: str, limit: int) -> None:
        count = await self._store.increment(
            f"rate:{scope}:{identity}",
            ttl_seconds=self._window_seconds,
        )
        if count > limit:
            raise RateLimitExceeded(self._window_seconds)


class SessionService:
    def __init__(
        self,
        settings: Settings,
        store: KeyValueStore,
        digester: TokenDigester,
        identity_verifier: Sub2APIIdentityVerifier,
        credential_protector: SessionCredentialProtector,
    ) -> None:
        self._settings = settings
        self._store = store
        self._digester = digester
        self._identity_verifier = identity_verifier
        self._credential_protector = credential_protector
        self._creation_locks: dict[str, asyncio.Lock] = {}
        self._upstream_verification_locks: WeakValueDictionary[uuid.UUID, asyncio.Lock] = (
            WeakValueDictionary()
        )
        self._invalidation_tasks: set[asyncio.Task[None]] = set()

    async def create(
        self,
        db: AsyncSession,
        user: Sub2APIUser,
        metadata: RequestMetadata,
        access_token: str,
    ) -> CreatedSession:
        lock = self._creation_locks.setdefault(user.user_id, asyncio.Lock())
        async with lock:
            return await self._create_serialized(db, user, metadata, access_token)

    async def _create_serialized(
        self,
        db: AsyncSession,
        user: Sub2APIUser,
        metadata: RequestMetadata,
        access_token: str,
    ) -> CreatedSession:
        now = datetime.now(UTC)
        if db.get_bind().dialect.name == "postgresql":
            await db.execute(
                text("SELECT pg_advisory_xact_lock(hashtext(:lock_key))"),
                {"lock_key": f"sub2api-control:session-create:{user.user_id}"},
            )
        active_count = int(
            await db.scalar(
                select(func.count(ControlSession.id)).where(
                    ControlSession.sub2api_user_id == user.user_id,
                    ControlSession.revoked_at.is_(None),
                    ControlSession.expires_at > now,
                )
            )
            or 0
        )
        if active_count >= self._settings.owner_max_active_sessions:
            raise SessionCapacityExceeded("active control session limit reached")

        total_count = int(
            await db.scalar(
                select(func.count(ControlSession.id)).where(
                    ControlSession.sub2api_user_id == user.user_id
                )
            )
            or 0
        )
        if total_count >= self._settings.owner_max_session_records:
            prune_count = total_count - self._settings.owner_max_session_records + 1
            terminal_ids = (
                select(ControlSession.id)
                .where(
                    ControlSession.sub2api_user_id == user.user_id,
                    or_(
                        ControlSession.revoked_at.is_not(None),
                        ControlSession.expires_at <= now,
                    ),
                )
                .order_by(ControlSession.expires_at, ControlSession.id)
                .limit(prune_count)
            )
            await db.execute(delete(ControlSession).where(ControlSession.id.in_(terminal_ids)))
            await db.flush()
            total_count = int(
                await db.scalar(
                    select(func.count(ControlSession.id)).where(
                        ControlSession.sub2api_user_id == user.user_id
                    )
                )
                or 0
            )
            if total_count >= self._settings.owner_max_session_records:
                raise SessionCapacityExceeded("retained control session limit reached")

        session_id = uuid.uuid4()
        session_token = self._credential_protector.seal(session_id, access_token)
        csrf_token = random_token(32)
        record = ControlSession(
            id=session_id,
            token_hash=self._digester.digest(CONTROL_SESSION_DIGEST_PURPOSE, session_token),
            csrf_token_hash=self._digester.digest("csrf", csrf_token),
            sub2api_user_id=user.user_id,
            username=user.username,
            email=user.email,
            display_name=user.display_name,
            token_version=user.token_version,
            issued_at=now,
            expires_at=now + timedelta(seconds=self._settings.session_ttl_seconds),
            last_seen_at=now,
            request_ip=metadata.source_ip,
            user_agent=metadata.user_agent,
        )
        db.add(record)
        await db.flush()
        db.add(
            AuditEvent(
                actor_user_id=user.user_id,
                actor_session_id=record.id,
                action="session.exchange",
                outcome=AuditOutcome.SUCCEEDED,
                resource_type="control_session",
                resource_id=str(record.id),
                request_id=metadata.request_id,
                source_ip=metadata.source_ip,
                user_agent=metadata.user_agent,
                details={},
            )
        )
        await db.commit()
        await self._cache_set(
            f"session:{record.token_hash}",
            str(record.id),
            ttl_seconds=self._settings.session_ttl_seconds,
        )
        await self._cache_upstream_verification(record)
        return CreatedSession(record, CookieTokens(session_token, csrf_token))

    async def resolve(
        self,
        db: AsyncSession,
        raw_token: str | None,
        *,
        touch: bool = True,
        verify_upstream: bool = True,
        force_upstream: bool = False,
    ) -> ControlSession | None:
        if not raw_token:
            return None
        token_hash = self._digester.digest(CONTROL_SESSION_DIGEST_PURPOSE, raw_token)
        cached_id = await self._cache_get(f"session:{token_hash}")
        record: ControlSession | None = None
        if cached_id is not None:
            try:
                cached_uuid = uuid.UUID(cached_id)
            except ValueError:
                cached_uuid = None
            cached_record = (
                await db.get(ControlSession, cached_uuid) if cached_uuid is not None else None
            )
            cached_hash = cached_record.token_hash if cached_record is not None else "0" * 64
            if secrets.compare_digest(cached_hash, token_hash):
                record = cached_record
            else:
                await self._cache_delete(f"session:{token_hash}")
        if record is None:
            record = await db.scalar(
                select(ControlSession).where(ControlSession.token_hash == token_hash)
            )
        if record is None or record.revoked_at is not None:
            await self._cache_delete(f"session:{token_hash}")
            return None
        now = datetime.now(UTC)
        if _utc(record.expires_at) <= now:
            await self._cache_delete(f"session:{token_hash}")
            return None

        credential = self._credential_protector.unseal(raw_token)
        if credential is None or credential.session_id != record.id:
            await self._cache_delete(f"session:{token_hash}")
            return None

        if verify_upstream and not await self._verify_upstream_identity(
            db,
            record,
            credential.access_token,
            force=force_upstream,
        ):
            return None
        if verify_upstream:
            await db.refresh(record, attribute_names=["revoked_at", "expires_at"])
            now = datetime.now(UTC)
            if record.revoked_at is not None or _utc(record.expires_at) <= now:
                await self._cache_delete(f"session:{token_hash}")
                return None

        remaining = max(1, int((_utc(record.expires_at) - now).total_seconds()))
        await self._cache_set(f"session:{token_hash}", str(record.id), ttl_seconds=remaining)
        if touch and (now - _utc(record.last_seen_at)).total_seconds() >= 30:
            record.last_seen_at = now
            await db.commit()
        return record

    async def _verify_upstream_identity(
        self,
        db: AsyncSession,
        record: ControlSession,
        access_token: str,
        *,
        force: bool,
    ) -> bool:
        marker_key = self._upstream_marker_key(record.id)
        if not force:
            cached_marker = await self._cache_get(marker_key)
            if self._valid_upstream_marker(record, cached_marker):
                return True

        lock = self._upstream_verification_locks.setdefault(record.id, asyncio.Lock())
        async with lock:
            if not force:
                cached_marker = await self._cache_get(marker_key)
                if self._valid_upstream_marker(record, cached_marker):
                    return True
            try:
                user = await self._identity_verifier.verify_access_token(
                    access_token,
                    Sub2APIRequestIdentity(
                        client_ip=record.request_ip or "unknown",
                        user_agent=record.user_agent or "",
                    ),
                )
            except DisabledSub2APIUser:
                await self._revoke_for_upstream_rejection(db, record, "USER_INACTIVE")
                return False
            except RevokedSub2APIToken:
                await self._revoke_for_upstream_rejection(db, record, "TOKEN_REVOKED")
                return False
            except InvalidSub2APIToken:
                await self._revoke_for_upstream_rejection(db, record, "TOKEN_INVALID")
                return False

            if user.user_id != record.sub2api_user_id:
                await self._revoke_for_upstream_rejection(db, record, "USER_MISMATCH")
                return False
            if not secrets.compare_digest(user.token_version or "", record.token_version or ""):
                await self._revoke_for_upstream_rejection(db, record, "TOKEN_VERSION_MISMATCH")
                return False

            await self._cache_upstream_verification(record)
            return True

    async def _cache_upstream_verification(self, record: ControlSession) -> None:
        remaining = max(
            1,
            int((_utc(record.expires_at) - datetime.now(UTC)).total_seconds()),
        )
        await self._cache_set(
            self._upstream_marker_key(record.id),
            self._upstream_marker(record),
            ttl_seconds=min(self._settings.session_upstream_recheck_seconds, remaining),
        )

    def _upstream_marker(self, record: ControlSession) -> str:
        verified_at = int(datetime.now(UTC).timestamp())
        signature = self._upstream_marker_signature(record, verified_at)
        return f"v1.{verified_at}.{signature}"

    def _valid_upstream_marker(
        self,
        record: ControlSession,
        marker: str | None,
    ) -> bool:
        if marker is None:
            return False
        try:
            version, raw_verified_at, signature = marker.split(".", 2)
            if version != "v1" or not raw_verified_at.isascii() or not raw_verified_at.isdigit():
                return False
            if len(signature) != 64 or any(
                character not in "0123456789abcdef" for character in signature
            ):
                return False
            verified_at = int(raw_verified_at)
        except ValueError:
            return False
        age = datetime.now(UTC).timestamp() - verified_at
        if age < 0 or age >= self._settings.session_upstream_recheck_seconds:
            return False
        return secrets.compare_digest(
            signature,
            self._upstream_marker_signature(record, verified_at),
        )

    def _upstream_marker_signature(
        self,
        record: ControlSession,
        verified_at: int,
    ) -> str:
        value = "\0".join(
            (
                str(record.id),
                record.token_hash,
                record.sub2api_user_id,
                record.token_version or "",
                str(verified_at),
            )
        )
        return self._digester.digest("session-upstream-verification", value)

    @staticmethod
    def _upstream_marker_key(session_id: uuid.UUID) -> str:
        return f"session-upstream-ok:{session_id}"

    async def _revoke_for_upstream_rejection(
        self,
        db: AsyncSession,
        record: ControlSession,
        reason: str,
    ) -> None:
        now = datetime.now(UTC)
        revoked_id = await db.scalar(
            update(ControlSession)
            .where(
                ControlSession.id == record.id,
                ControlSession.revoked_at.is_(None),
            )
            .values(revoked_at=now)
            .returning(ControlSession.id)
        )
        if revoked_id is not None:
            db.add(
                AuditEvent(
                    actor_user_id=record.sub2api_user_id,
                    actor_session_id=record.id,
                    action="session.upstream_revoke",
                    outcome=AuditOutcome.DENIED,
                    resource_type="control_session",
                    resource_id=str(record.id),
                    source_ip=record.request_ip,
                    user_agent=record.user_agent,
                    details={"reason": reason},
                )
            )
        await db.commit()
        record.revoked_at = now
        self._schedule_revoked_session_invalidation(record)

    def _schedule_revoked_session_invalidation(self, record: ControlSession) -> None:
        task = asyncio.create_task(self._invalidate_revoked_session(record))
        self._invalidation_tasks.add(task)
        task.add_done_callback(self._invalidation_tasks.discard)

    async def close(self) -> None:
        if self._invalidation_tasks:
            await asyncio.gather(*tuple(self._invalidation_tasks), return_exceptions=True)

    async def _cache_get(self, key: str) -> str | None:
        try:
            async with asyncio.timeout(self._settings.redis_command_timeout_seconds):
                return await self._store.get(key)
        except Exception as exc:
            _LOGGER.warning(
                "control session Redis cache read failed; bypassing Redis cache",
                extra={"error_type": type(exc).__name__},
            )
            return None

    async def _cache_set(self, key: str, value: str, *, ttl_seconds: int) -> None:
        try:
            async with asyncio.timeout(self._settings.redis_command_timeout_seconds):
                await self._store.set(key, value, ttl_seconds=ttl_seconds)
        except Exception as exc:
            _LOGGER.warning(
                "control session Redis cache write failed; using PostgreSQL authority",
                extra={"error_type": type(exc).__name__},
            )

    async def _cache_delete(self, key: str) -> None:
        try:
            async with asyncio.timeout(self._settings.redis_command_timeout_seconds):
                await self._store.delete(key)
        except Exception as exc:
            _LOGGER.warning(
                "control session Redis cache delete failed; using PostgreSQL authority",
                extra={"error_type": type(exc).__name__},
            )

    def valid_csrf(self, record: ControlSession, cookie_token: str, header_token: str) -> bool:
        if not secrets.compare_digest(cookie_token, header_token):
            return False
        return self._digester.matches("csrf", header_token, record.csrf_token_hash)

    async def revoke(
        self,
        db: AsyncSession,
        record: ControlSession,
        metadata: RequestMetadata,
    ) -> None:
        if record.revoked_at is None:
            record.revoked_at = datetime.now(UTC)
        db.add(
            AuditEvent(
                actor_user_id=record.sub2api_user_id,
                actor_session_id=record.id,
                action="session.logout",
                outcome=AuditOutcome.SUCCEEDED,
                resource_type="control_session",
                resource_id=str(record.id),
                request_id=metadata.request_id,
                source_ip=metadata.source_ip,
                user_agent=metadata.user_agent,
                details={},
            )
        )
        await db.commit()
        invalidation = asyncio.create_task(self._invalidate_revoked_session(record))
        try:
            await asyncio.shield(invalidation)
        except asyncio.CancelledError:
            await invalidation
            raise

    async def _invalidate_revoked_session(self, record: ControlSession) -> None:
        try:
            async with asyncio.timeout(self._settings.redis_command_timeout_seconds):
                results = await asyncio.gather(
                    self._store.publish(
                        control_session_revocation_channel(record.id),
                        str(record.id),
                    ),
                    self._store.delete(f"session:{record.token_hash}"),
                    self._store.delete(self._upstream_marker_key(record.id)),
                    return_exceptions=True,
                )
        except TimeoutError:
            _LOGGER.warning(
                "control session Redis invalidation timed out after durable revocation",
                extra={"error_type": "TimeoutError"},
            )
            return
        for result in results:
            if isinstance(result, BaseException):
                _LOGGER.warning(
                    "control session Redis invalidation failed after durable revocation",
                    extra={"error_type": type(result).__name__},
                )


class PairingService:
    def __init__(
        self,
        settings: Settings,
        digester: TokenDigester,
        events: EventService,
    ) -> None:
        self._settings = settings
        self._digester = digester
        self._events = events

    async def start(
        self,
        db: AsyncSession,
        *,
        pairing_id: uuid.UUID,
        proof_created_at: datetime,
        audience: str,
        public_key: str,
        device_name: str,
        device_metadata: dict[str, object],
        workspace_roots: list[str],
        code_commitment: str,
        poll_token_commitment: str,
        refresh_credential_commitment: str,
        signature: str,
        request_metadata: RequestMetadata,
    ) -> StartedPairing:
        canonical_key = canonicalize_ed25519_public_key(public_key)
        canonical_roots = canonicalize_workspace_roots(workspace_roots)
        if proof_created_at.tzinfo is None:
            raise PairingProofRejected("pairing proof timestamp must include a timezone")
        proof_created_at = proof_created_at.astimezone(UTC).replace(microsecond=0)
        proof_created_at_text = proof_created_at.isoformat().replace("+00:00", "Z")
        expected_audiences = {
            f"{origin}{self._settings.pairing_poll_path_prefix}/device-pairings/start"
            for origin in self._settings.allowed_origins
        }
        if audience not in expected_audiences:
            raise PairingProofRejected("pairing proof audience is invalid")
        self._verify_start_proof(
            pairing_id=pairing_id,
            proof_created_at=proof_created_at_text,
            audience=audience,
            public_key=canonical_key,
            code_commitment=code_commitment,
            poll_token_commitment=poll_token_commitment,
            refresh_credential_commitment=refresh_credential_commitment,
            device_name=device_name,
            device_metadata=device_metadata,
            workspace_roots=canonical_roots,
            signature=signature,
        )
        code_hash = self._digester.digest("pairing-code-v2", code_commitment)
        poll_token_hash = self._digester.digest("pairing-poll-v2", poll_token_commitment)
        refresh_credential_hash = self._digester.digest(
            "device-refresh-v2", refresh_credential_commitment
        )
        now = datetime.now(UTC)

        # Reject payloads that could never fit in the browser bootstrap before
        # anonymous start traffic can retain them in PostgreSQL.
        candidate_device = Device(
            id=pairing_id,
            owner_user_id="pairing-candidate",
            name=device_name,
            public_key=canonical_key,
            status=DeviceStatus.ACTIVE,
            device_metadata=device_metadata,
            workspace_roots=canonical_roots,
        )
        try:
            ensure_device_projection_fits(candidate_device)
        except OwnerCapacityExceeded as exc:
            raise PairingCapacityExceeded(exc.code) from exc

        existing = await db.scalar(
            select(DevicePairing).where(DevicePairing.id == pairing_id).with_for_update()
        )
        if existing is not None:
            if not self._same_start_intent(
                existing,
                proof_created_at=proof_created_at,
                audience=audience,
                public_key=canonical_key,
                device_name=device_name,
                device_metadata=device_metadata,
                workspace_roots=canonical_roots,
                code_hash=code_hash,
                poll_token_hash=poll_token_hash,
                refresh_credential_hash=refresh_credential_hash,
            ):
                raise PairingConflict("pairing id was reused with a different intent")
            if existing.status in {PairingStatus.EXPIRED, PairingStatus.CANCELLED}:
                raise PairingExpired("pairing is no longer active")
            if existing.status != PairingStatus.COMPLETED and _utc(existing.expires_at) <= now:
                expired_event = await self._expire_unactivated(db, existing, now, request_metadata)
                await db.commit()
                if expired_event is not None:
                    await self._events.publish(*expired_event)
                raise PairingExpired("pairing has expired")
            return StartedPairing(existing)

        recovery_device = await db.scalar(
            select(Device).where(Device.id == pairing_id).with_for_update()
        )
        if recovery_device is not None:
            if (
                recovery_device.status != DeviceStatus.ACTIVE
                or not secrets.compare_digest(recovery_device.public_key, canonical_key)
                or not secrets.compare_digest(
                    recovery_device.refresh_credential_hash or "",
                    refresh_credential_hash,
                )
            ):
                raise PairingConflict("pairing id conflicts with an existing device")
            record = DevicePairing(
                id=pairing_id,
                code_hash=code_hash,
                poll_token_hash=poll_token_hash,
                refresh_credential_hash=refresh_credential_hash,
                protocol_version=2,
                proof_created_at=proof_created_at,
                audience=audience,
                public_key=canonical_key,
                device_name=device_name,
                device_metadata=device_metadata,
                workspace_roots=canonical_roots,
                status=PairingStatus.COMPLETED,
                claimed_by_user_id=recovery_device.owner_user_id,
                device_id=recovery_device.id,
                created_at=now,
                expires_at=now + timedelta(seconds=self._settings.pairing_ttl_seconds),
                claimed_at=now,
                credential_delivered_at=now,
                completed_at=now,
                source_ip=request_metadata.source_ip,
            )
            db.add(record)
            db.add(
                AuditEvent(
                    actor_user_id=recovery_device.owner_user_id,
                    actor_device_id=recovery_device.id,
                    action="pairing.recover",
                    outcome=AuditOutcome.SUCCEEDED,
                    resource_type="device_pairing",
                    resource_id=str(record.id),
                    request_id=request_metadata.request_id,
                    source_ip=request_metadata.source_ip,
                    user_agent=request_metadata.user_agent,
                    details={"reason": "completed_pairing_record_missing"},
                )
            )
            try:
                await db.commit()
            except IntegrityError:
                await db.rollback()
                concurrent = await db.scalar(
                    select(DevicePairing).where(DevicePairing.id == pairing_id).with_for_update()
                )
                if concurrent is not None and self._same_start_intent(
                    concurrent,
                    proof_created_at=proof_created_at,
                    audience=audience,
                    public_key=canonical_key,
                    device_name=device_name,
                    device_metadata=device_metadata,
                    workspace_roots=canonical_roots,
                    code_hash=code_hash,
                    poll_token_hash=poll_token_hash,
                    refresh_credential_hash=refresh_credential_hash,
                ):
                    return StartedPairing(concurrent)
                raise PairingConflict("pairing recovery conflicts with existing state") from None
            return StartedPairing(record)

        credential_device = await db.scalar(
            select(Device)
            .where(Device.refresh_credential_hash == refresh_credential_hash)
            .with_for_update()
        )
        if credential_device is not None:
            raise PairingConflict("refresh credential is already bound to a device")

        if proof_created_at < now - timedelta(seconds=self._settings.pairing_ttl_seconds):
            raise PairingExpired("pairing start proof has expired")
        if proof_created_at > now + timedelta(seconds=60):
            raise PairingProofRejected("pairing proof timestamp is in the future")

        expired_events: list[tuple[str, object]] = []
        live_pairings = list(
            (
                await db.scalars(
                    select(DevicePairing)
                    .where(
                        DevicePairing.public_key == canonical_key,
                        DevicePairing.status.in_((PairingStatus.PENDING, PairingStatus.CLAIMED)),
                    )
                    .with_for_update()
                )
            ).all()
        )
        for live_pairing in live_pairings:
            if _utc(live_pairing.expires_at) > now:
                raise PairingConflict("device public key already has an active pairing")
        for live_pairing in live_pairings:
            expired_event = await self._expire_unactivated(db, live_pairing, now, request_metadata)
            if expired_event is not None:
                expired_events.append(expired_event)

        active_device = await db.scalar(
            select(Device).where(
                Device.public_key == canonical_key,
                Device.status == DeviceStatus.ACTIVE,
            )
        )
        if active_device is not None:
            if expired_events:
                await db.commit()
                for expired_event in expired_events:
                    await self._events.publish(*expired_event)
            raise PairingConflict("device public key is already paired")

        await self._ensure_start_capacity(db, request_metadata.source_ip)

        record = DevicePairing(
            id=pairing_id,
            code_hash=code_hash,
            poll_token_hash=poll_token_hash,
            refresh_credential_hash=refresh_credential_hash,
            protocol_version=2,
            proof_created_at=proof_created_at,
            audience=audience,
            public_key=canonical_key,
            device_name=device_name,
            device_metadata=device_metadata,
            workspace_roots=canonical_roots,
            status=PairingStatus.PENDING,
            created_at=now,
            expires_at=now + timedelta(seconds=self._settings.pairing_ttl_seconds),
            source_ip=request_metadata.source_ip,
        )
        db.add(record)
        try:
            await db.flush()
        except IntegrityError:
            await db.rollback()
            concurrent = await db.scalar(
                select(DevicePairing).where(DevicePairing.id == pairing_id).with_for_update()
            )
            if concurrent is not None and self._same_start_intent(
                concurrent,
                proof_created_at=proof_created_at,
                audience=audience,
                public_key=canonical_key,
                device_name=device_name,
                device_metadata=device_metadata,
                workspace_roots=canonical_roots,
                code_hash=code_hash,
                poll_token_hash=poll_token_hash,
                refresh_credential_hash=refresh_credential_hash,
            ):
                if concurrent.status in {
                    PairingStatus.EXPIRED,
                    PairingStatus.CANCELLED,
                }:
                    raise PairingExpired("pairing is no longer active") from None
                if (
                    concurrent.status != PairingStatus.COMPLETED
                    and _utc(concurrent.expires_at) <= now
                ):
                    event = await self._expire_unactivated(db, concurrent, now, request_metadata)
                    await db.commit()
                    if event is not None:
                        await self._events.publish(*event)
                    raise PairingExpired("pairing has expired") from None
                return StartedPairing(concurrent)
            raise PairingConflict("pairing start conflicts with existing state") from None
        db.add(
            AuditEvent(
                action="pairing.start",
                outcome=AuditOutcome.SUCCEEDED,
                resource_type="device_pairing",
                resource_id=str(record.id),
                request_id=request_metadata.request_id,
                source_ip=request_metadata.source_ip,
                user_agent=request_metadata.user_agent,
                details={"device_name": device_name, "workspace_root_count": len(canonical_roots)},
            )
        )
        await db.commit()
        for expired_event in expired_events:
            await self._events.publish(*expired_event)
        return StartedPairing(record)

    async def claim(
        self,
        db: AsyncSession,
        *,
        code: str,
        session: ControlSession,
        request_metadata: RequestMetadata,
    ) -> DevicePairing:
        normalized_code = normalize_pairing_code(code)
        code_hash = self._digester.digest(
            "pairing-code-v2", pairing_secret_commitment(normalized_code)
        )
        pairing = await db.scalar(
            select(DevicePairing).where(DevicePairing.code_hash == code_hash).with_for_update()
        )
        if pairing is None:
            await self._audit_denied_claim(db, session, request_metadata, "code_not_found")
            raise PairingNotFound("pairing code was not found")

        now = datetime.now(UTC)
        if pairing.status == PairingStatus.COMPLETED:
            if pairing.claimed_by_user_id == session.sub2api_user_id and pairing.device_id:
                device = await self._lock_device(db, pairing.device_id)
                if device is not None and device.status == DeviceStatus.ACTIVE:
                    return pairing
            await self._audit_denied_claim(
                db,
                session,
                request_metadata,
                "status_completed",
                pairing_id=pairing.id,
            )
            raise PairingConflict("pairing is no longer claimable")
        if _utc(pairing.expires_at) <= now:
            expired_event = await self._expire_unactivated(db, pairing, now, request_metadata)
            await self._audit_denied_claim(
                db, session, request_metadata, "expired", pairing_id=pairing.id
            )
            if expired_event is not None:
                await self._events.publish(*expired_event)
            raise PairingExpired("pairing has expired")
        if pairing.status == PairingStatus.CLAIMED:
            if pairing.claimed_by_user_id == session.sub2api_user_id:
                return pairing
            await self._audit_denied_claim(
                db,
                session,
                request_metadata,
                "status_claimed",
                pairing_id=pairing.id,
            )
            raise PairingConflict("pairing is no longer claimable")
        if pairing.status != PairingStatus.PENDING:
            await self._audit_denied_claim(
                db,
                session,
                request_metadata,
                f"status_{pairing.status.value}",
                pairing_id=pairing.id,
            )
            raise PairingConflict("pairing is no longer claimable")
        if not pairing.workspace_roots:
            await self._audit_denied_claim(
                db,
                session,
                request_metadata,
                "workspace_roots_missing",
                pairing_id=pairing.id,
            )
            raise PairingConflict("pairing has no registered workspace roots")

        existing_device = await db.scalar(
            select(Device).where(
                Device.public_key == pairing.public_key,
                Device.status == DeviceStatus.ACTIVE,
            )
        )
        if existing_device is not None:
            await self._audit_denied_claim(
                db, session, request_metadata, "public_key_already_paired", pairing_id=pairing.id
            )
            raise PairingConflict("device public key is already paired")

        await self._events.lock_owner_cursor(db, session.sub2api_user_id)
        reservations = int(
            await db.scalar(
                select(func.count(DevicePairing.id)).where(
                    DevicePairing.claimed_by_user_id == session.sub2api_user_id,
                    DevicePairing.status == PairingStatus.CLAIMED,
                )
            )
            or 0
        )
        if (
            await active_device_count(db, session.sub2api_user_id) + reservations
            >= self._settings.bootstrap_max_devices
        ):
            raise PairingCapacityExceeded("active_device_limit_exceeded")
        if (
            await total_device_count(db, session.sub2api_user_id) + reservations
            >= self._settings.owner_max_device_records
        ):
            raise PairingCapacityExceeded("device_record_limit_exceeded")

        candidate_device = Device(
            id=pairing.id,
            owner_user_id=session.sub2api_user_id,
            name=pairing.device_name,
            public_key=pairing.public_key,
            status=DeviceStatus.ACTIVE,
            device_metadata=pairing.device_metadata,
            workspace_roots=pairing.workspace_roots,
        )
        try:
            ensure_device_projection_fits(candidate_device)
        except OwnerCapacityExceeded as exc:
            raise PairingCapacityExceeded(exc.code) from exc
        pairing.claimed_by_user_id = session.sub2api_user_id
        pairing.claimed_by_session_id = session.id
        pairing.claimed_at = now
        pairing.status = PairingStatus.CLAIMED
        db.add(
            AuditEvent(
                actor_user_id=session.sub2api_user_id,
                actor_session_id=session.id,
                action="pairing.claim",
                outcome=AuditOutcome.SUCCEEDED,
                resource_type="device_pairing",
                resource_id=str(pairing.id),
                request_id=request_metadata.request_id,
                source_ip=request_metadata.source_ip,
                user_agent=request_metadata.user_agent,
                details={"future_device_id": str(pairing.id)},
            )
        )
        await db.commit()
        return pairing

    async def poll(
        self,
        db: AsyncSession,
        *,
        pairing_id: uuid.UUID,
        poll_token: str,
        request_metadata: RequestMetadata,
    ) -> PairingPollResult:
        pairing = await db.scalar(
            select(DevicePairing).where(DevicePairing.id == pairing_id).with_for_update()
        )
        if pairing is None:
            raise PairingNotFound("pairing was not found")
        if pairing.protocol_version != 2 or not self._digester.matches(
            "pairing-poll-v2",
            pairing_secret_commitment(poll_token),
            pairing.poll_token_hash,
        ):
            db.add(
                AuditEvent(
                    action="pairing.poll",
                    outcome=AuditOutcome.DENIED,
                    resource_type="device_pairing",
                    resource_id=str(pairing.id),
                    request_id=request_metadata.request_id,
                    source_ip=request_metadata.source_ip,
                    user_agent=request_metadata.user_agent,
                    details={"reason": "invalid_poll_token"},
                )
            )
            await db.commit()
            raise PairingUnauthorized("invalid pairing poll token")

        now = datetime.now(UTC)
        if pairing.status == PairingStatus.COMPLETED:
            if pairing.device_id is None:
                raise PairingConflict("completed pairing has no device")
            device = await self._lock_device(db, pairing.device_id)
            if (
                device is None
                or device.status != DeviceStatus.ACTIVE
                or pairing.refresh_credential_hash is None
                or not secrets.compare_digest(
                    device.refresh_credential_hash or "",
                    pairing.refresh_credential_hash,
                )
            ):
                raise PairingConflict("completed pairing device is unavailable")
            return PairingPollResult(pairing, device)
        if _utc(pairing.expires_at) <= now:
            expired_event = await self._expire_unactivated(db, pairing, now, request_metadata)
            await db.commit()
            if expired_event is not None:
                await self._events.publish(*expired_event)
            raise PairingExpired("pairing has expired")
        if pairing.status == PairingStatus.PENDING:
            return PairingPollResult(pairing)
        if pairing.status in {PairingStatus.EXPIRED, PairingStatus.CANCELLED}:
            raise PairingExpired("pairing is no longer active")
        if pairing.status != PairingStatus.CLAIMED:
            raise PairingConflict("pairing is in an invalid state")
        if (
            pairing.claimed_by_user_id is None
            or pairing.device_id is not None
            or pairing.refresh_credential_hash is None
        ):
            raise PairingConflict("pairing claim is incomplete")

        existing_device = await db.scalar(
            select(Device)
            .where(
                Device.public_key == pairing.public_key,
                Device.status == DeviceStatus.ACTIVE,
            )
            .with_for_update()
        )
        if existing_device is not None:
            raise PairingConflict("device public key is already paired")

        device = Device(
            id=pairing.id,
            owner_user_id=pairing.claimed_by_user_id,
            name=pairing.device_name,
            public_key=pairing.public_key,
            refresh_credential_hash=pairing.refresh_credential_hash,
            credential_version=1,
            credential_scheme=2,
            status=DeviceStatus.ACTIVE,
            device_metadata=pairing.device_metadata,
            workspace_roots=pairing.workspace_roots,
            created_at=now,
            updated_at=now,
        )
        try:
            ensure_device_projection_fits(device)
        except OwnerCapacityExceeded as exc:
            raise PairingConflict(exc.code) from exc
        db.add(device)
        await db.flush()
        pairing.device_id = device.id
        pairing.credential_delivered_at = now
        pairing.completed_at = now
        pairing.status = PairingStatus.COMPLETED
        db.add(
            AuditEvent(
                actor_user_id=device.owner_user_id,
                actor_device_id=device.id,
                action="pairing.complete",
                outcome=AuditOutcome.SUCCEEDED,
                resource_type="device",
                resource_id=str(device.id),
                request_id=request_metadata.request_id,
                source_ip=request_metadata.source_ip,
                user_agent=request_metadata.user_agent,
                details={
                    "pairing_id": str(pairing.id),
                    "credential_version": device.credential_version,
                    "credential_scheme": 2,
                },
            )
        )
        metadata = device.device_metadata or {}
        event = await self._events.append(
            db,
            owner_user_id=device.owner_user_id,
            device_id=device.id,
            event_type="device.updated",
            data={
                "id": str(device.id),
                "name": device.name,
                "status": "offline",
                "connector_version": str(metadata.get("connector_version", "")),
                "codex_version": str(metadata.get("codex_version", "")),
                "last_seen_at": None,
                "workspace_roots": device.workspace_roots or [],
            },
        )
        await db.commit()
        await self._events.publish(device.owner_user_id, event)
        return PairingPollResult(pairing, device)

    async def _ensure_start_capacity(
        self,
        db: AsyncSession,
        source_ip: str | None,
    ) -> None:
        bind = db.get_bind()
        if bind.dialect.name == "postgresql":
            await db.execute(
                text(
                    "SELECT pg_advisory_xact_lock("
                    "hashtext('sub2api-control:pairing-start-capacity'))"
                )
            )

        retained_global = int(await db.scalar(select(func.count(DevicePairing.id))) or 0)
        live_global = int(
            await db.scalar(
                select(func.count(DevicePairing.id)).where(
                    DevicePairing.status.in_((PairingStatus.PENDING, PairingStatus.CLAIMED))
                )
            )
            or 0
        )
        if retained_global >= MAX_RETAINED_PAIRINGS_GLOBAL:
            raise PairingCapacityExceeded("retained_pairing_limit_exceeded")
        if live_global >= MAX_LIVE_PAIRINGS_GLOBAL:
            raise PairingCapacityExceeded("live_pairing_limit_exceeded")

        if source_ip is None:
            return
        retained_source = int(
            await db.scalar(
                select(func.count(DevicePairing.id)).where(DevicePairing.source_ip == source_ip)
            )
            or 0
        )
        live_source = int(
            await db.scalar(
                select(func.count(DevicePairing.id)).where(
                    DevicePairing.source_ip == source_ip,
                    DevicePairing.status.in_((PairingStatus.PENDING, PairingStatus.CLAIMED)),
                )
            )
            or 0
        )
        if retained_source >= MAX_RETAINED_PAIRINGS_PER_SOURCE:
            raise PairingCapacityExceeded("source_retained_pairing_limit_exceeded")
        if live_source >= MAX_LIVE_PAIRINGS_PER_SOURCE:
            raise PairingCapacityExceeded("source_live_pairing_limit_exceeded")

    async def expire_due(
        self,
        db: AsyncSession,
        now: datetime | None = None,
        *,
        limit: int | None = None,
    ) -> int:
        now = now or datetime.now(UTC)
        limit = limit or self._settings.retention_sweep_batch_size
        candidate_ids = list(
            (
                await db.scalars(
                    select(DevicePairing.id)
                    .where(
                        DevicePairing.status.in_((PairingStatus.PENDING, PairingStatus.CLAIMED)),
                        DevicePairing.expires_at <= now,
                    )
                    .order_by(DevicePairing.expires_at, DevicePairing.id)
                    .limit(limit)
                )
            ).all()
        )
        await db.rollback()
        expired = 0
        metadata = RequestMetadata(None, None, None)
        for pairing_id in candidate_ids:
            pairing = await db.scalar(
                select(DevicePairing)
                .where(
                    DevicePairing.id == pairing_id,
                    DevicePairing.status.in_((PairingStatus.PENDING, PairingStatus.CLAIMED)),
                    DevicePairing.expires_at <= now,
                )
                .with_for_update(skip_locked=True)
            )
            if pairing is None:
                await db.rollback()
                continue
            event = await self._expire_unactivated(db, pairing, now, metadata)
            await db.commit()
            expired += 1
            if event is not None:
                await self._events.publish(*event)
        return expired

    def _verify_start_proof(
        self,
        *,
        pairing_id: uuid.UUID,
        proof_created_at: str,
        audience: str,
        public_key: str,
        code_commitment: str,
        poll_token_commitment: str,
        refresh_credential_commitment: str,
        device_name: str,
        device_metadata: dict[str, object],
        workspace_roots: list[str],
        signature: str,
    ) -> None:
        try:
            signature_bytes = base64.b64decode(
                signature + "=" * (-len(signature) % 4),
                altchars=b"-_",
                validate=True,
            )
            public_key_bytes = base64.b64decode(
                public_key + "=" * (-len(public_key) % 4),
                altchars=b"-_",
                validate=True,
            )
        except (ValueError, binascii.Error) as exc:
            raise PairingProofRejected("pairing proof is invalid") from exc
        if len(signature_bytes) != 64 or len(public_key_bytes) != 32:
            raise PairingProofRejected("pairing proof is invalid")
        proof = pairing_start_proof(
            pairing_id=pairing_id,
            created_at=proof_created_at,
            audience=audience,
            public_key=public_key,
            code_commitment=code_commitment,
            poll_token_commitment=poll_token_commitment,
            refresh_credential_commitment=refresh_credential_commitment,
            display_name=device_name,
            connector_version=str(device_metadata.get("connector_version", "")),
            codex_version=str(device_metadata.get("codex_version", "")),
            workspace_roots=workspace_roots,
        )
        try:
            Ed25519PublicKey.from_public_bytes(public_key_bytes).verify(signature_bytes, proof)
        except InvalidSignature as exc:
            raise PairingProofRejected("pairing proof is invalid") from exc

    @staticmethod
    def _same_start_intent(
        pairing: DevicePairing,
        *,
        proof_created_at: datetime,
        audience: str,
        public_key: str,
        device_name: str,
        device_metadata: dict[str, object],
        workspace_roots: list[str],
        code_hash: str,
        poll_token_hash: str,
        refresh_credential_hash: str,
    ) -> bool:
        return (
            pairing.protocol_version == 2
            and pairing.proof_created_at is not None
            and _utc(pairing.proof_created_at) == proof_created_at
            and pairing.audience == audience
            and secrets.compare_digest(pairing.public_key, public_key)
            and pairing.device_name == device_name
            and pairing.device_metadata == device_metadata
            and pairing.workspace_roots == workspace_roots
            and secrets.compare_digest(pairing.code_hash, code_hash)
            and secrets.compare_digest(pairing.poll_token_hash, poll_token_hash)
            and secrets.compare_digest(
                pairing.refresh_credential_hash or "", refresh_credential_hash
            )
        )

    async def _expire_unactivated(
        self,
        db: AsyncSession,
        pairing: DevicePairing,
        now: datetime,
        request_metadata: RequestMetadata,
    ) -> tuple[str, object] | None:
        if pairing.status == PairingStatus.COMPLETED:
            raise PairingConflict("completed pairing cannot be expired")
        pairing.status = PairingStatus.EXPIRED
        db.add(
            AuditEvent(
                action="pairing.expire",
                outcome=AuditOutcome.SUCCEEDED,
                resource_type="device_pairing",
                resource_id=str(pairing.id),
                request_id=request_metadata.request_id,
                source_ip=request_metadata.source_ip,
                user_agent=request_metadata.user_agent,
                details={"unactivated_device_created": False},
            )
        )
        return None

    @staticmethod
    async def _lock_device(db: AsyncSession, device_id: uuid.UUID) -> Device | None:
        return await db.scalar(select(Device).where(Device.id == device_id).with_for_update())

    async def _audit_denied_claim(
        self,
        db: AsyncSession,
        session: ControlSession,
        request_metadata: RequestMetadata,
        reason: str,
        *,
        pairing_id: uuid.UUID | None = None,
    ) -> None:
        db.add(
            AuditEvent(
                actor_user_id=session.sub2api_user_id,
                actor_session_id=session.id,
                action="pairing.claim",
                outcome=AuditOutcome.DENIED,
                resource_type="device_pairing" if pairing_id else None,
                resource_id=str(pairing_id) if pairing_id else None,
                request_id=request_metadata.request_id,
                source_ip=request_metadata.source_ip,
                user_agent=request_metadata.user_agent,
                details={"reason": reason},
            )
        )
        await db.commit()
