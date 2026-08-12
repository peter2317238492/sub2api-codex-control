from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import httpx
import pytest_asyncio
from fastapi import FastAPI

from control_api.app import create_app
from control_api.config import Settings
from control_api.db import Base, Database
from control_api.storage import InMemoryKeyValueStore
from control_api.sub2api import Sub2APIRequestIdentity, Sub2APIUser

ORIGIN = "https://control.example.test"


class FakeSub2API:
    def __init__(self) -> None:
        self.result: Sub2APIUser | Exception = Sub2APIUser(
            user_id="42",
            username="alice",
            email="alice@example.test",
            display_name="Alice",
            token_version="7",
        )
        self.seen_tokens: list[str] = []
        self.seen_request_identities: list[Sub2APIRequestIdentity] = []

    async def verify_access_token(
        self,
        access_token: str,
        request_identity: Sub2APIRequestIdentity,
    ) -> Sub2APIUser:
        self.seen_tokens.append(access_token)
        self.seen_request_identities.append(request_identity)
        if isinstance(self.result, Exception):
            raise self.result
        return self.result

    async def close(self) -> None:
        return None


@dataclass
class Harness:
    client: httpx.AsyncClient
    app: FastAPI
    database: Database
    settings: Settings
    sub2api: FakeSub2API
    store: InMemoryKeyValueStore


@pytest_asyncio.fixture
async def harness(tmp_path: Path):
    settings = Settings(
        environment="test",
        database_url=f"sqlite+aiosqlite:///{tmp_path / 'control.db'}",
        redis_url="memory://",
        redis_prefix="test:",
        session_hmac_secret="a-test-secret-that-is-long-and-never-production",
        cookie_secure=False,
        allowed_origins_csv=ORIGIN,
        external_api_base_path="/codex-api",
    )
    database = Database(settings)
    async with database.engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)

    store = InMemoryKeyValueStore(settings.redis_prefix)
    sub2api = FakeSub2API()
    app = create_app(
        settings,
        database=database,
        store=store,
        sub2api_client=sub2api,
    )
    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(
            transport=transport,
            base_url=ORIGIN,
        ) as client:
            yield Harness(client, app, database, settings, sub2api, store)

    await store.close()
    async with database.engine.begin() as connection:
        await connection.run_sync(Base.metadata.drop_all)
    await database.close()


async def exchange(harness: Harness, access_token: str = "sub2api-access-token-value"):
    return await harness.client.post(
        "/v1/session/exchange",
        headers={"Origin": ORIGIN},
        json={"access_token": access_token},
    )
