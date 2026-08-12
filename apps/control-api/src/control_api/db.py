from __future__ import annotations

from collections.abc import AsyncIterator

from fastapi import Request
from sqlalchemy import MetaData, text
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy.pool import NullPool

from .config import Settings

DATABASE_SCHEMA_REVISION = "20260731_0008"

NAMING_CONVENTION = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


class Base(DeclarativeBase):
    metadata = MetaData(naming_convention=NAMING_CONVENTION)


class Database:
    def __init__(self, settings: Settings) -> None:
        self._pool_capacity = settings.database_pool_size + settings.database_max_overflow
        engine_kwargs: dict[str, object] = {"pool_pre_ping": True}
        if settings.database_url.startswith("postgresql+"):
            engine_kwargs.update(
                pool_size=settings.database_pool_size,
                max_overflow=settings.database_max_overflow,
                pool_timeout=settings.database_pool_timeout_seconds,
                connect_args={
                    "timeout": settings.database_connect_timeout_seconds,
                    "command_timeout": settings.database_command_timeout_seconds,
                },
            )
        elif settings.database_url.startswith("sqlite+"):
            engine_kwargs["poolclass"] = NullPool
        self.engine: AsyncEngine = create_async_engine(settings.database_url, **engine_kwargs)
        self.session_factory = async_sessionmaker(
            self.engine,
            class_=AsyncSession,
            expire_on_commit=False,
            autoflush=False,
        )

    async def ping(self) -> None:
        async with self.engine.connect() as connection:
            await connection.execute(text("SELECT 1"))

    async def schema_is_current(self) -> bool:
        if self.engine.dialect.name != "postgresql":
            return True
        async with self.engine.connect() as connection:
            revisions = list(
                (await connection.scalars(text("SELECT version_num FROM alembic_version"))).all()
            )
        return revisions == [DATABASE_SCHEMA_REVISION]

    def pool_snapshot(self) -> dict[str, int]:
        pool = self.engine.sync_engine.pool

        def pool_value(name: str) -> int:
            method = getattr(pool, name, None)
            if not callable(method):
                return 0
            try:
                return max(0, int(method()))
            except (NotImplementedError, TypeError, ValueError):
                return 0

        return {
            "size": pool_value("size"),
            "checked_in": pool_value("checkedin"),
            "checked_out": pool_value("checkedout"),
            "overflow": pool_value("overflow"),
            "capacity": self._pool_capacity,
        }

    async def close(self) -> None:
        await self.engine.dispose()


async def get_db_session(request: Request) -> AsyncIterator[AsyncSession]:
    database: Database = request.app.state.database
    async with database.session_factory() as session:
        yield session
