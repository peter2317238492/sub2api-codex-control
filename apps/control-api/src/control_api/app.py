from __future__ import annotations

import asyncio
import logging
import re
import time
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from .approvals import ApprovalService
from .command_budget import CommandPayloadTooLarge
from .commands import CommandService
from .config import Settings, get_settings
from .connector_release import admitted_connector_release, connector_release_metadata_sha256
from .control_routes import router as control_router
from .db import Database
from .device_auth import DeviceTokenService
from .events import EventService
from .metrics import MetricsService
from .metrics_routes import router as metrics_router
from .operational_metrics import OperationalMetrics, elapsed_seconds
from .realtime import RealtimeService
from .retention import RetentionService
from .routes import router
from .security import SessionCredentialProtector, TokenDigester
from .services import PairingService, RateLimiter, SessionService
from .storage import KeyValueStore, create_key_value_store
from .sub2api import HTTPSub2APIClient, Sub2APIIdentityVerifier
from .thread_snapshot import ThreadSnapshotTooLarge
from .websocket_routes import router as websocket_router

_REQUEST_ID_PATTERN = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_LOGGER = logging.getLogger(__name__)


def create_app(
    settings: Settings | None = None,
    *,
    database: Database | None = None,
    store: KeyValueStore | None = None,
    sub2api_client: Sub2APIIdentityVerifier | None = None,
) -> FastAPI:
    settings = settings or get_settings()
    connector_release_required = settings.environment == "production"

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        connector_release_raw = settings.connector_release_metadata_json
        connector_release_admission = admitted_connector_release(settings)
        connector_release_raw_sha256 = connector_release_metadata_sha256(connector_release_raw)
        if connector_release_raw_sha256 is None or (
            connector_release_admission is None
            and (connector_release_required or connector_release_raw.strip())
        ):
            raise RuntimeError(
                "startup requires empty development metadata or an admitted Connector release"
            )
        app.state.connector_release_required = connector_release_required
        app.state.connector_release_raw_sha256_admission = connector_release_raw_sha256
        app.state.connector_release_admission = connector_release_admission
        owns_database = database is None
        owns_store = store is None
        owns_sub2api = sub2api_client is None
        app.state.database = database or Database(settings)
        app.state.store = store or create_key_value_store(settings)
        app.state.sub2api = sub2api_client or HTTPSub2APIClient(settings)
        route_templates = {
            route.path for route in app.routes if isinstance(getattr(route, "path", None), str)
        }
        app.state.operational_metrics = OperationalMetrics(route_templates)
        session_secret = settings.session_hmac_secret.get_secret_value()
        digester = TokenDigester(session_secret)
        credential_protector = SessionCredentialProtector(
            session_secret,
            random_handle_bytes=settings.session_token_bytes,
        )
        app.state.session_service = SessionService(
            settings,
            app.state.store,
            digester,
            app.state.sub2api,
            credential_protector,
        )
        app.state.events = EventService(settings, app.state.store)
        app.state.pairing_service = PairingService(settings, digester, app.state.events)
        app.state.metrics = MetricsService(
            settings.metrics_cache_seconds,
            settings.metrics_query_timeout_seconds,
            settings.build_version,
            settings.build_vcs_ref,
            app.state.operational_metrics,
            app.state.database,
        )
        app.state.commands = CommandService(
            settings,
            app.state.store,
            app.state.events,
            app.state.operational_metrics,
        )
        app.state.approvals = ApprovalService(
            app.state.store,
            app.state.events,
            app.state.operational_metrics,
        )
        app.state.retention = RetentionService(settings)
        app.state.device_tokens = DeviceTokenService(settings, app.state.store, digester)
        app.state.realtime = RealtimeService(
            settings,
            app.state.database,
            app.state.store,
            app.state.device_tokens,
            app.state.session_service,
            app.state.events,
            app.state.commands,
            app.state.approvals,
            str(uuid.uuid4()),
            app.state.operational_metrics,
        )
        app.state.rate_limiter = RateLimiter(app.state.store, settings.rate_limit_window_seconds)
        sweeper = asyncio.create_task(_sweep_expired_state(app))
        try:
            yield
        finally:
            sweeper.cancel()
            await asyncio.gather(sweeper, return_exceptions=True)
            await app.state.session_service.close()
            if owns_sub2api:
                await app.state.sub2api.close()
            if owns_store:
                await app.state.store.close()
            if owns_database:
                await app.state.database.close()

    app = FastAPI(
        title=settings.app_name,
        version="0.1.0",
        lifespan=lifespan,
        docs_url=None if settings.environment == "production" else "/docs",
        redoc_url=None,
        openapi_url=None if settings.environment == "production" else "/openapi.json",
    )
    app.state.settings = settings
    app.include_router(router, prefix=settings.api_prefix)
    app.include_router(control_router, prefix=settings.api_prefix)
    app.include_router(websocket_router)
    app.include_router(metrics_router)

    @app.middleware("http")
    async def security_headers(
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        started = time.monotonic()
        status_code = 500
        incoming_request_id = request.headers.get("x-request-id", "")
        request.state.request_id = (
            incoming_request_id
            if _REQUEST_ID_PATTERN.fullmatch(incoming_request_id)
            else str(uuid.uuid4())
        )
        try:
            response = await call_next(request)
            status_code = response.status_code
            response.headers["X-Request-ID"] = request.state.request_id
            response.headers["X-Content-Type-Options"] = "nosniff"
            response.headers["Referrer-Policy"] = "no-referrer"
            if (
                request.url.path.startswith(f"{settings.api_prefix}/session")
                or "pairing" in request.url.path
            ):
                response.headers["Cache-Control"] = "no-store"
                response.headers["Pragma"] = "no-cache"
            return response
        finally:
            duration = elapsed_seconds(started)
            route = getattr(request.scope.get("route"), "path", "_unmatched")
            operational = getattr(request.app.state, "operational_metrics", None)
            if operational is not None:
                operational.http_request(request.method, route, status_code, duration)
            _LOGGER.info(
                "http request completed",
                extra={
                    "event": "http.request",
                    "request_id": request.state.request_id,
                    "method": request.method,
                    "route": route,
                    "status_code": status_code,
                    "duration_ms": round(duration * 1000, 3),
                },
            )

    @app.exception_handler(RequestValidationError)
    async def validation_error_handler(
        _request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        errors = []
        for error in exc.errors():
            sanitized = {key: value for key, value in error.items() if key not in {"input", "ctx"}}
            errors.append(sanitized)
        return JSONResponse(status_code=422, content={"detail": errors})

    @app.exception_handler(CommandPayloadTooLarge)
    async def command_payload_too_large_handler(
        _request: Request, _exc: CommandPayloadTooLarge
    ) -> JSONResponse:
        return JSONResponse(status_code=422, content={"detail": "command_payload_too_large"})

    @app.exception_handler(ThreadSnapshotTooLarge)
    async def thread_snapshot_too_large_handler(
        _request: Request, _exc: ThreadSnapshotTooLarge
    ) -> JSONResponse:
        return JSONResponse(status_code=422, content={"detail": "thread_snapshot_too_large"})

    return app


async def _sweep_expired_state(app: FastAPI) -> None:
    last_retention_sweep = 0.0
    while True:
        await asyncio.sleep(app.state.settings.state_sweep_interval_seconds)
        try:
            acquired, last_retention_sweep = await _run_sweep_cycle(
                app,
                last_retention_sweep,
            )
            if not acquired:
                continue
        except Exception:
            # Readiness exposes dependency failures; the sweep retries without stopping the API.
            _LOGGER.exception("expired-state sweep failed")


async def _run_sweep_cycle(
    app: FastAPI,
    last_retention_sweep: float,
    *,
    lease_ttl_seconds: int = 30,
) -> tuple[bool, float]:
    lease_key = "state-sweep-lease"
    lease_value = str(uuid.uuid4())
    acquired = await app.state.store.set_if_absent(
        lease_key,
        lease_value,
        lease_ttl_seconds,
    )
    if not acquired:
        return False, last_retention_sweep

    stop_renewal = asyncio.Event()
    renewal = asyncio.create_task(
        _renew_sweep_lease(
            app.state.store,
            lease_key,
            lease_value,
            lease_ttl_seconds,
            stop_renewal,
        )
    )
    sweep = asyncio.create_task(_perform_sweep(app, last_retention_sweep))
    try:
        done, _ = await asyncio.wait(
            {renewal, sweep},
            return_when=asyncio.FIRST_COMPLETED,
        )
        if renewal in done:
            renewal_error = renewal.exception()
            if renewal_error is not None:
                sweep.cancel()
                await asyncio.gather(sweep, return_exceptions=True)
                raise renewal_error
        return True, await sweep
    finally:
        stop_renewal.set()
        await asyncio.gather(renewal, return_exceptions=True)
        await app.state.store.compare_delete(lease_key, lease_value)


async def _renew_sweep_lease(
    store: KeyValueStore,
    lease_key: str,
    lease_value: str,
    lease_ttl_seconds: int,
    stop: asyncio.Event,
) -> None:
    interval = max(0.1, lease_ttl_seconds / 3)
    while not stop.is_set():
        try:
            await asyncio.wait_for(stop.wait(), timeout=interval)
        except TimeoutError:
            if not await store.compare_refresh(
                lease_key,
                lease_value,
                lease_ttl_seconds,
            ):
                raise RuntimeError("state sweep lease ownership was lost")


async def _perform_sweep(app: FastAPI, last_retention_sweep: float) -> float:
    async with app.state.database.session_factory() as db:
        await _observe_maintenance_phase(
            app,
            "pairing_expiry",
            app.state.pairing_service.expire_due(db),
        )
    async with app.state.database.session_factory() as db:
        await _observe_maintenance_phase(
            app,
            "command_expiry",
            app.state.commands.expire_due(db),
        )
    async with app.state.database.session_factory() as db:
        await _observe_maintenance_phase(
            app,
            "approval_expiry",
            app.state.approvals.expire_due(db),
            limit=500,
        )
    async with app.state.database.session_factory() as db:
        await _observe_maintenance_phase(
            app,
            "approval_reconcile",
            app.state.approvals.reconcile_undispatched(
                db,
                limit=app.state.settings.retention_sweep_batch_size,
            ),
        )
    if time.monotonic() - last_retention_sweep >= 60:
        async with app.state.database.session_factory() as db:
            await _observe_maintenance_phase(
                app,
                "event_prune",
                app.state.events.prune(db),
                limit=0,
            )
        async with app.state.database.session_factory() as db:
            await _observe_maintenance_phase(
                app,
                "outbox_prune",
                app.state.realtime.prune_outbox(db),
                limit=0,
            )
        async with app.state.database.session_factory() as db:
            started = time.monotonic()
            try:
                result = await app.state.retention.sweep(db)
            except BaseException:
                _record_maintenance(
                    app,
                    "retention_sweep",
                    "failed",
                    0,
                    elapsed_seconds(started),
                    0,
                )
                raise
            duration = elapsed_seconds(started)
            _record_maintenance(
                app,
                "retention_sweep",
                "succeeded",
                result.total,
                duration,
                0,
            )
            for field, phase in (
                ("control_sessions", "retention_control_sessions"),
                ("device_pairings", "retention_device_pairings"),
                ("approvals", "retention_approvals"),
                ("commands", "retention_commands"),
                ("device_connections", "retention_device_connections"),
                ("thread_bindings", "retention_thread_bindings"),
                ("devices", "retention_devices"),
                ("audit_events", "retention_audit_events"),
            ):
                _record_maintenance(
                    app,
                    phase,
                    "succeeded",
                    getattr(result, field, 0),
                    duration,
                    app.state.settings.retention_sweep_batch_size,
                )
        if result.total:
            _LOGGER.info(
                "terminal-state retention sweep removed rows",
                extra={"retention_removed_total": result.total},
            )
        return time.monotonic()
    return last_retention_sweep


async def _observe_maintenance_phase(
    app: FastAPI,
    phase: str,
    operation: Awaitable[int],
    *,
    limit: int | None = None,
) -> int:
    started = time.monotonic()
    batch_limit = app.state.settings.retention_sweep_batch_size if limit is None else limit
    try:
        items = await operation
    except BaseException:
        _record_maintenance(
            app,
            phase,
            "failed",
            0,
            elapsed_seconds(started),
            batch_limit,
        )
        raise
    _record_maintenance(
        app,
        phase,
        "succeeded",
        items,
        elapsed_seconds(started),
        batch_limit,
    )
    return items


def _record_maintenance(
    app: FastAPI,
    phase: str,
    outcome: str,
    items: int,
    duration: float,
    limit: int,
) -> None:
    metrics = getattr(app.state, "operational_metrics", None)
    if metrics is not None:
        metrics.maintenance(phase, outcome, items, duration, limit)
