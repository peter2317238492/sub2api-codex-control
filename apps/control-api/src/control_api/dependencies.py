from __future__ import annotations

from datetime import UTC, datetime, timedelta

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from .config import Settings
from .db import get_db_session
from .models import ControlSession
from .security import validate_origin


def app_settings(request: Request) -> Settings:
    return request.app.state.settings


async def require_origin(
    request: Request,
    settings: Settings = Depends(app_settings),
) -> None:
    validate_origin(request, settings)


async def require_session(
    request: Request,
    db: AsyncSession = Depends(get_db_session),
) -> ControlSession:
    settings: Settings = request.app.state.settings
    raw_token = request.cookies.get(settings.cookie_name)
    record = await request.app.state.session_service.resolve(db, raw_token)
    if record is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="control_session_required",
        )
    return record


async def require_mutating_session(
    request: Request,
    db: AsyncSession = Depends(get_db_session),
) -> ControlSession:
    settings: Settings = request.app.state.settings
    validate_origin(request, settings)
    raw_token = request.cookies.get(settings.cookie_name)
    record = await request.app.state.session_service.resolve(db, raw_token)
    if record is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="control_session_required",
        )
    csrf_cookie = request.cookies.get(settings.csrf_cookie_name)
    csrf_header = request.headers.get(settings.csrf_header_name)
    if (
        not csrf_cookie
        or not csrf_header
        or not request.app.state.session_service.valid_csrf(record, csrf_cookie, csrf_header)
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="csrf_validation_failed",
        )
    return record


async def require_recent_mutating_session(
    request: Request,
    record: ControlSession = Depends(require_mutating_session),
) -> ControlSession:
    settings: Settings = request.app.state.settings
    issued_at = record.issued_at
    if issued_at.tzinfo is None:
        issued_at = issued_at.replace(tzinfo=UTC)
    else:
        issued_at = issued_at.astimezone(UTC)
    if datetime.now(UTC) >= issued_at + timedelta(seconds=settings.recent_auth_max_age_seconds):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="reauth_required",
            headers={"WWW-Authenticate": "Sub2API"},
        )
    return record
