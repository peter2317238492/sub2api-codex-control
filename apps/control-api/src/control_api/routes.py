from __future__ import annotations

import asyncio
import time
import uuid
from collections.abc import Awaitable
from datetime import UTC, timedelta

from fastapi import APIRouter, Depends, Header, HTTPException, Request, Response, status
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession

from .config import Settings
from .connector_release import admitted_connector_release, connector_release_metadata_sha256
from .db import get_db_session
from .dependencies import (
    require_logout_session,
    require_origin,
    require_recent_mutating_session,
    require_session,
)
from .models import AuditEvent, AuditOutcome, ControlSession
from .schemas import (
    ExchangeRequest,
    HealthResponse,
    PairingClaimRequest,
    PairingClaimResponse,
    PairingCompletedResponse,
    PairingPendingResponse,
    PairingStartRequest,
    PairingStartResponse,
    ReadinessResponse,
    SessionView,
    UserView,
)
from .security import CookieTokens, SessionCredentialTooLarge, client_ip, request_id
from .services import (
    PairingCapacityExceeded,
    PairingConflict,
    PairingExpired,
    PairingNotFound,
    PairingProofRejected,
    PairingUnauthorized,
    RateLimitExceeded,
    RequestMetadata,
    SessionCapacityExceeded,
)
from .sub2api import (
    DisabledSub2APIUser,
    InvalidSub2APIToken,
    Sub2APIProtocolError,
    Sub2APIRequestIdentity,
    Sub2APIUnavailable,
)

router = APIRouter()


def _metadata(request: Request) -> RequestMetadata:
    settings: Settings = request.app.state.settings
    return RequestMetadata(
        source_ip=client_ip(request, settings),
        user_agent=request.headers.get("user-agent", "")[:512] or None,
        request_id=request_id(request),
    )


def _session_view(record: ControlSession, settings: Settings) -> SessionView:
    issued_at = record.issued_at
    expires_at = record.expires_at
    if issued_at.tzinfo is None:
        issued_at = issued_at.replace(tzinfo=UTC)
    else:
        issued_at = issued_at.astimezone(UTC)
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=UTC)
    else:
        expires_at = expires_at.astimezone(UTC)
    return SessionView(
        id=record.id,
        user=UserView(
            id=record.sub2api_user_id,
            username=record.username,
            email=record.email,
            display_name=record.display_name,
        ),
        issued_at=issued_at,
        expires_at=expires_at,
        reauth_at=min(
            expires_at,
            issued_at + timedelta(seconds=settings.recent_auth_max_age_seconds),
        ),
        csrf_header_name=settings.csrf_header_name,
    )


def _set_control_cookies(
    response: Response,
    record: ControlSession,
    tokens: CookieTokens,
    settings: Settings,
) -> None:
    max_age = settings.session_ttl_seconds
    response.set_cookie(
        key=settings.cookie_name,
        value=tokens.session_token,
        max_age=max_age,
        expires=record.expires_at.astimezone(UTC),
        path="/",
        secure=settings.cookie_secure,
        httponly=True,
        samesite=settings.cookie_samesite,
    )
    response.set_cookie(
        key=settings.csrf_cookie_name,
        value=tokens.csrf_token,
        max_age=max_age,
        expires=record.expires_at.astimezone(UTC),
        path="/",
        secure=settings.cookie_secure,
        httponly=False,
        samesite=settings.cookie_samesite,
    )


def _clear_control_cookies(response: Response, settings: Settings) -> None:
    for cookie_name, httponly in (
        (settings.cookie_name, True),
        (settings.csrf_cookie_name, False),
    ):
        response.delete_cookie(
            key=cookie_name,
            path="/",
            secure=settings.cookie_secure,
            httponly=httponly,
            samesite=settings.cookie_samesite,
        )


async def _audit_exchange_failure(
    db: AsyncSession,
    request: Request,
    reason: str,
) -> None:
    metadata = _metadata(request)
    db.add(
        AuditEvent(
            action="session.exchange",
            outcome=AuditOutcome.DENIED,
            request_id=metadata.request_id,
            source_ip=metadata.source_ip,
            user_agent=metadata.user_agent,
            details={"reason": reason},
        )
    )
    await db.commit()


@router.get("/health/live", response_model=HealthResponse, tags=["health"])
async def live() -> HealthResponse:
    return HealthResponse()


@router.get(
    "/health/ready",
    response_model=ReadinessResponse,
    responses={503: {"model": ReadinessResponse}},
    tags=["health"],
)
async def ready(request: Request) -> ReadinessResponse | JSONResponse:
    async def observe(dependency: str, operation: Awaitable[object]) -> bool:
        started = time.monotonic()
        try:
            result = await operation
            succeeded = result is not False
        except Exception:
            succeeded = False
        request.app.state.operational_metrics.dependency_check(
            dependency,
            "ok" if succeeded else "failed",
            time.monotonic() - started,
        )
        return succeeded

    database_ok, migrations_ok, redis_ok = await asyncio.gather(
        observe("database", request.app.state.database.ping()),
        observe("database_migrations", request.app.state.database.schema_is_current()),
        observe("redis", request.app.state.store.ping()),
    )
    settings: Settings = request.app.state.settings
    current_connector_release = admitted_connector_release(settings)
    connector_release_required = getattr(
        request.app.state,
        "connector_release_required",
        settings.environment == "production",
    )
    startup_connector_release = getattr(
        request.app.state,
        "connector_release_admission",
        None,
    )
    startup_connector_release_raw_sha256 = getattr(
        request.app.state,
        "connector_release_raw_sha256_admission",
        None,
    )
    current_connector_release_raw = settings.connector_release_metadata_json
    current_connector_release_raw_sha256 = connector_release_metadata_sha256(
        current_connector_release_raw
    )
    if not connector_release_required and not current_connector_release_raw.strip():
        connector_release_ok = (
            current_connector_release is None
            and startup_connector_release is None
            and current_connector_release_raw_sha256 is not None
            and current_connector_release_raw_sha256
            == startup_connector_release_raw_sha256
        )
    else:
        connector_release_ok = (
            current_connector_release is not None
            and current_connector_release == startup_connector_release
            and current_connector_release_raw_sha256 is not None
            and current_connector_release_raw_sha256
            == startup_connector_release_raw_sha256
        )

    checks = {
        "database": "ok" if database_ok else "failed",
        "database_migrations": "ok" if migrations_ok else "failed",
        "redis": "ok" if redis_ok else "failed",
        "sub2api_contract": (
            "ok" if settings.sub2api_contract_ready else "failed"
        ),
        "connector_release": "ok" if connector_release_ok else "failed",
    }
    if "failed" in checks.values():
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={"status": "not_ready", "checks": checks},
        )
    return ReadinessResponse(status="ready", checks=checks)


@router.post(
    "/session/exchange",
    response_model=SessionView,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_origin)],
    tags=["session"],
)
async def exchange_session(
    request: Request,
    response: Response,
    payload: ExchangeRequest | None = None,
    authorization: str | None = Header(default=None),
    db: AsyncSession = Depends(get_db_session),
) -> SessionView:
    settings: Settings = request.app.state.settings
    try:
        await request.app.state.rate_limiter.check(
            "session-exchange-ip",
            client_ip(request, settings),
            settings.session_exchange_limit,
        )
    except RateLimitExceeded as exc:
        request.app.state.operational_metrics.session_exchange("rate_limited")
        raise HTTPException(
            status_code=429,
            detail="session_exchange_rate_limited",
            headers={"Retry-After": str(exc.retry_after)},
        ) from None

    body_token = payload.access_token if payload is not None else None
    header_token = None
    if authorization is not None and authorization.startswith("Bearer "):
        header_token = authorization.removeprefix("Bearer ").strip() or None
    if body_token and header_token and body_token != header_token:
        request.app.state.operational_metrics.session_exchange("conflicting_token")
        raise HTTPException(status_code=400, detail="conflicting_access_tokens")
    access_token = body_token or header_token
    if access_token is None:
        request.app.state.operational_metrics.session_exchange("missing_token")
        raise HTTPException(status_code=401, detail="sub2api_access_token_required")
    try:
        user = await request.app.state.sub2api.verify_access_token(
            access_token,
            Sub2APIRequestIdentity(
                client_ip=client_ip(request, settings),
                user_agent=request.headers.get("user-agent", ""),
            ),
        )
    except InvalidSub2APIToken:
        request.app.state.operational_metrics.session_exchange("invalid_token")
        await _audit_exchange_failure(db, request, "invalid_access_token")
        raise HTTPException(status_code=401, detail="invalid_sub2api_access_token") from None
    except DisabledSub2APIUser:
        request.app.state.operational_metrics.session_exchange("disabled_user")
        await _audit_exchange_failure(db, request, "disabled_user")
        raise HTTPException(status_code=403, detail="sub2api_user_disabled") from None
    except Sub2APIUnavailable:
        request.app.state.operational_metrics.session_exchange("upstream_unavailable")
        raise HTTPException(status_code=503, detail="sub2api_auth_unavailable") from None
    except Sub2APIProtocolError:
        request.app.state.operational_metrics.session_exchange("upstream_protocol_error")
        raise HTTPException(status_code=502, detail="sub2api_auth_contract_error") from None

    try:
        created = await request.app.state.session_service.create(
            db,
            user,
            _metadata(request),
            access_token,
        )
    except SessionCapacityExceeded:
        request.app.state.operational_metrics.session_exchange("capacity_exceeded")
        await db.rollback()
        raise HTTPException(status_code=429, detail="control_session_capacity_exceeded") from None
    except SessionCredentialTooLarge:
        request.app.state.operational_metrics.session_exchange("credential_too_large")
        await db.rollback()
        await _audit_exchange_failure(db, request, "access_token_too_large")
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="sub2api_access_token_too_large",
        ) from None
    _set_control_cookies(response, created.record, created.cookies, request.app.state.settings)
    request.app.state.operational_metrics.session_exchange("succeeded")
    return _session_view(created.record, request.app.state.settings)


@router.get("/session", response_model=SessionView, tags=["session"])
async def current_session(
    request: Request,
    record: ControlSession = Depends(require_session),
) -> SessionView:
    return _session_view(record, request.app.state.settings)


@router.delete("/session", status_code=status.HTTP_204_NO_CONTENT, tags=["session"])
@router.post("/session/logout", status_code=status.HTTP_204_NO_CONTENT, tags=["session"])
async def logout_session(
    request: Request,
    response: Response,
    record: ControlSession = Depends(require_logout_session),
    db: AsyncSession = Depends(get_db_session),
) -> Response:
    await request.app.state.session_service.revoke(db, record, _metadata(request))
    _clear_control_cookies(response, request.app.state.settings)
    response.status_code = status.HTTP_204_NO_CONTENT
    return response


@router.post(
    "/device-pairings/start",
    response_model=PairingStartResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["pairing"],
)
async def start_device_pairing(
    payload: PairingStartRequest,
    request: Request,
    db: AsyncSession = Depends(get_db_session),
) -> PairingStartResponse:
    settings: Settings = request.app.state.settings
    try:
        await request.app.state.rate_limiter.check(
            "pairing-start",
            client_ip(request, settings),
            settings.pairing_start_limit,
        )
    except RateLimitExceeded as exc:
        request.app.state.operational_metrics.pairing("start", "rate_limited")
        raise HTTPException(
            status_code=429,
            detail="pairing_start_rate_limited",
            headers={"Retry-After": str(exc.retry_after)},
        ) from None
    try:
        started = await request.app.state.pairing_service.start(
            db,
            pairing_id=payload.pairing_id,
            proof_created_at=payload.created_at,
            audience=payload.audience,
            public_key=payload.public_key,
            device_name=payload.display_name,
            device_metadata={
                "connector_version": payload.connector_version,
                "codex_version": payload.codex_version,
            },
            workspace_roots=payload.workspace_roots,
            code_commitment=payload.code_commitment,
            poll_token_commitment=payload.poll_token_commitment,
            refresh_credential_commitment=payload.refresh_credential_commitment,
            signature=payload.signature,
            request_metadata=_metadata(request),
        )
    except PairingProofRejected:
        request.app.state.operational_metrics.pairing("start", "unauthorized")
        raise HTTPException(status_code=401, detail="invalid_pairing_proof") from None
    except PairingExpired:
        request.app.state.operational_metrics.pairing("start", "expired")
        raise HTTPException(status_code=410, detail="pairing_expired") from None
    except PairingConflict:
        request.app.state.operational_metrics.pairing("start", "conflict")
        raise HTTPException(status_code=409, detail="pairing_not_startable") from None
    except PairingCapacityExceeded:
        request.app.state.operational_metrics.pairing("start", "capacity_exceeded")
        raise HTTPException(
            status_code=429,
            detail="pairing_capacity_exceeded",
            headers={"Retry-After": "60"},
        ) from None
    except ValueError as exc:
        request.app.state.operational_metrics.pairing("start", "invalid_input")
        raise HTTPException(status_code=422, detail=str(exc)) from None
    request.app.state.operational_metrics.pairing("start", "succeeded")
    return PairingStartResponse(
        pairing_id=started.record.id,
        expires_at=started.record.expires_at.astimezone(UTC)
        if started.record.expires_at.tzinfo is not None
        else started.record.expires_at.replace(tzinfo=UTC),
        poll_url=(f"{settings.pairing_poll_path_prefix}/device-pairings/{started.record.id}/poll"),
    )


@router.post(
    "/pairings/claim",
    response_model=PairingClaimResponse,
    tags=["pairing"],
)
async def claim_device_pairing(
    payload: PairingClaimRequest,
    request: Request,
    record: ControlSession = Depends(require_recent_mutating_session),
    db: AsyncSession = Depends(get_db_session),
) -> PairingClaimResponse:
    settings: Settings = request.app.state.settings
    try:
        await request.app.state.rate_limiter.check(
            "pairing-claim",
            record.sub2api_user_id,
            settings.pairing_claim_limit,
        )
        pairing = await request.app.state.pairing_service.claim(
            db,
            code=payload.code,
            session=record,
            request_metadata=_metadata(request),
        )
    except RateLimitExceeded as exc:
        request.app.state.operational_metrics.pairing("claim", "rate_limited")
        raise HTTPException(
            status_code=429,
            detail="pairing_claim_rate_limited",
            headers={"Retry-After": str(exc.retry_after)},
        ) from None
    except PairingNotFound:
        request.app.state.operational_metrics.pairing("claim", "not_found")
        raise HTTPException(status_code=404, detail="pairing_not_found") from None
    except PairingExpired:
        request.app.state.operational_metrics.pairing("claim", "expired")
        raise HTTPException(status_code=410, detail="pairing_expired") from None
    except PairingConflict:
        request.app.state.operational_metrics.pairing("claim", "conflict")
        raise HTTPException(status_code=409, detail="pairing_not_claimable") from None
    except PairingCapacityExceeded:
        request.app.state.operational_metrics.pairing("claim", "capacity_exceeded")
        raise HTTPException(status_code=409, detail="device_capacity_exceeded") from None
    request.app.state.operational_metrics.pairing("claim", "succeeded")
    return PairingClaimResponse(
        pairing_id=pairing.id,
        device_id=pairing.id,
        device_name=pairing.device_name,
    )


@router.get(
    "/device-pairings/{pairing_id}/poll",
    response_model=PairingPendingResponse | PairingCompletedResponse,
    tags=["pairing"],
)
async def poll_device_pairing(
    pairing_id: uuid.UUID,
    request: Request,
    authorization: str | None = Header(default=None),
    db: AsyncSession = Depends(get_db_session),
) -> PairingPendingResponse | PairingCompletedResponse | JSONResponse:
    if authorization is None or not authorization.startswith("Pairing "):
        request.app.state.operational_metrics.pairing("poll", "unauthorized")
        raise HTTPException(
            status_code=401,
            detail="pairing_authorization_required",
            headers={"WWW-Authenticate": "Pairing"},
        )
    poll_token = authorization.removeprefix("Pairing ").strip()
    if not poll_token:
        request.app.state.operational_metrics.pairing("poll", "unauthorized")
        raise HTTPException(status_code=401, detail="invalid_pairing_poll_token")

    settings: Settings = request.app.state.settings
    try:
        await request.app.state.rate_limiter.check(
            "pairing-poll-ip",
            client_ip(request, settings),
            settings.pairing_poll_ip_limit,
        )
        await request.app.state.rate_limiter.check(
            "pairing-poll",
            f"{pairing_id}:{client_ip(request, settings)}",
            settings.pairing_poll_limit,
        )
        result = await request.app.state.pairing_service.poll(
            db,
            pairing_id=pairing_id,
            poll_token=poll_token,
            request_metadata=_metadata(request),
        )
    except RateLimitExceeded as exc:
        request.app.state.operational_metrics.pairing("poll", "rate_limited")
        raise HTTPException(
            status_code=429,
            detail="pairing_poll_rate_limited",
            headers={"Retry-After": str(exc.retry_after)},
        ) from None
    except PairingNotFound:
        request.app.state.operational_metrics.pairing("poll", "not_found")
        raise HTTPException(status_code=404, detail="pairing_not_found") from None
    except PairingUnauthorized:
        request.app.state.operational_metrics.pairing("poll", "unauthorized")
        raise HTTPException(
            status_code=401,
            detail="invalid_pairing_poll_token",
            headers={"WWW-Authenticate": "Pairing"},
        ) from None
    except PairingExpired:
        request.app.state.operational_metrics.pairing("poll", "expired")
        raise HTTPException(status_code=410, detail="pairing_expired") from None
    except PairingConflict:
        request.app.state.operational_metrics.pairing("poll", "conflict")
        raise HTTPException(status_code=409, detail="pairing_invalid_state") from None

    if result.device is None:
        request.app.state.operational_metrics.pairing("poll", "pending")
        response = PairingPendingResponse(
            pairing_id=result.record.id,
            expires_at=result.record.expires_at.astimezone(UTC)
            if result.record.expires_at.tzinfo is not None
            else result.record.expires_at.replace(tzinfo=UTC),
        )
        return JSONResponse(
            status_code=status.HTTP_202_ACCEPTED,
            content=response.model_dump(mode="json"),
            headers={"Retry-After": "2"},
        )
    request.app.state.operational_metrics.pairing("poll", "succeeded")
    return PairingCompletedResponse(
        device_id=result.device.id,
    )
