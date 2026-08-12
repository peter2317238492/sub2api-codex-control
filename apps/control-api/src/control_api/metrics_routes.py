from __future__ import annotations

import secrets

from fastapi import APIRouter, Depends, Header, HTTPException, Request, Response, status
from sqlalchemy.ext.asyncio import AsyncSession

from .db import get_db_session

router = APIRouter()


@router.get("/internal/metrics", include_in_schema=False)
async def metrics(
    request: Request,
    authorization: str | None = Header(default=None),
    db: AsyncSession = Depends(get_db_session),
) -> Response:
    expected = request.app.state.settings.metrics_bearer_token.get_secret_value()
    supplied = ""
    if authorization is not None and authorization.startswith("Bearer "):
        supplied = authorization.removeprefix("Bearer ").strip()
    if not supplied or not secrets.compare_digest(supplied, expected):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="metrics_authentication_required",
            headers={"WWW-Authenticate": "Bearer", "Cache-Control": "no-store"},
        )
    try:
        body = await request.app.state.metrics.render(db)
    except TimeoutError:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="metrics_snapshot_timeout",
            headers={"Cache-Control": "no-store", "Retry-After": "15"},
        ) from None
    return Response(
        content=body,
        media_type="text/plain; version=0.0.4",
        headers={"Cache-Control": "no-store"},
    )
