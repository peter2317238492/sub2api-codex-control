from __future__ import annotations

import json
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import delete, func, select, update
from sqlalchemy.dialects.postgresql import insert as postgresql_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.ext.asyncio import AsyncSession

from .config import Settings
from .models import Device, EventLog, EventOwnerCursor
from .schemas import BrowserEvent
from .storage import KeyValueStore

MAX_EVENT_CURSOR = (1 << 63) - 1
DEFAULT_BROWSER_EVENT_CATCHUP_MAX_BYTES = 1024 * 1024


@dataclass(frozen=True, slots=True)
class BrowserEventPage:
    events: tuple[BrowserEvent, ...]
    has_more: bool
    serialized_bytes: int


class EventService:
    def __init__(self, settings: Settings, store: KeyValueStore) -> None:
        self._settings = settings
        self._store = store

    async def append(
        self,
        db: AsyncSession,
        *,
        owner_user_id: str,
        device_id: uuid.UUID,
        event_type: str,
        data: dict[str, object],
        thread_binding_id: uuid.UUID | None = None,
        occurred_at: datetime | None = None,
    ) -> BrowserEvent:
        # Device is the first durable lock in every append path; the owner cursor
        # is always acquired second so concurrent devices cannot invert lock order.
        device_sequence = await db.scalar(
            update(Device)
            .where(
                Device.id == device_id,
                Device.owner_user_id == owner_user_id,
            )
            .values(last_event_sequence=Device.last_event_sequence + 1)
            .returning(Device.last_event_sequence)
        )
        if device_sequence is None:
            raise ValueError("event device ownership mismatch")
        owner_cursor = await self._allocate_owner_cursor(db, owner_user_id)
        occurred_at = occurred_at or datetime.now(UTC)
        record = EventLog(
            owner_user_id=owner_user_id,
            owner_cursor=owner_cursor,
            device_id=device_id,
            thread_binding_id=thread_binding_id,
            sequence=device_sequence,
            event_type=event_type,
            payload=data,
            occurred_at=occurred_at,
            ingested_at=datetime.now(UTC),
        )
        db.add(record)
        await db.flush()
        event = BrowserEvent(
            cursor=str(record.owner_cursor),
            type=event_type,
            occurred_at=occurred_at,
            data=data,
        )
        return event

    @staticmethod
    def _insert_factory(db: AsyncSession) -> Any:
        bind = db.get_bind()
        if bind.dialect.name == "postgresql":
            return postgresql_insert
        if bind.dialect.name == "sqlite":
            return sqlite_insert
        # Production is PostgreSQL; SQLite is the supported test backend.
        raise RuntimeError(f"unsupported event cursor dialect: {bind.dialect.name}")

    @classmethod
    async def _allocate_owner_cursor(cls, db: AsyncSession, owner_user_id: str) -> int:
        """Allocate a cursor while holding its owner row lock until transaction end."""

        statement = (
            cls._insert_factory(db)(EventOwnerCursor)
            .values(owner_user_id=owner_user_id, last_cursor=1)
            .on_conflict_do_update(
                index_elements=[EventOwnerCursor.owner_user_id],
                set_={"last_cursor": EventOwnerCursor.last_cursor + 1},
                where=EventOwnerCursor.last_cursor < MAX_EVENT_CURSOR,
            )
            .returning(EventOwnerCursor.last_cursor)
        )
        cursor = await db.scalar(statement)
        if cursor is None:
            raise EventCursorExhausted("event owner cursor exhausted signed bigint capacity")
        return int(cursor)

    @classmethod
    async def lock_owner_cursor(cls, db: AsyncSession, owner_user_id: str) -> int:
        """Lock an owner's event head until the surrounding transaction ends."""

        await db.execute(
            cls._insert_factory(db)(EventOwnerCursor)
            .values(owner_user_id=owner_user_id, last_cursor=0)
            .on_conflict_do_nothing(index_elements=[EventOwnerCursor.owner_user_id])
        )
        cursor = await db.scalar(
            select(EventOwnerCursor.last_cursor)
            .where(EventOwnerCursor.owner_user_id == owner_user_id)
            .with_for_update()
        )
        if cursor is None:
            raise RuntimeError("event owner cursor lock returned no value")
        return int(cursor)

    @classmethod
    async def lock_snapshot_cursor(cls, db: AsyncSession, owner_user_id: str) -> int:
        """Lock an owner's event barrier before reading an authoritative snapshot."""

        return await cls.lock_owner_cursor(db, owner_user_id)

    async def publish(self, owner_user_id: str, event: BrowserEvent) -> None:
        await self._store.publish(
            f"browser:{owner_user_id}",
            event.model_dump_json(),
        )

    async def emit(
        self,
        db: AsyncSession,
        *,
        owner_user_id: str,
        device_id: uuid.UUID,
        event_type: str,
        data: dict[str, object],
        thread_binding_id: uuid.UUID | None = None,
        occurred_at: datetime | None = None,
    ) -> BrowserEvent:
        event = await self.append(
            db,
            owner_user_id=owner_user_id,
            device_id=device_id,
            event_type=event_type,
            data=data,
            thread_binding_id=thread_binding_id,
            occurred_at=occurred_at,
        )
        await db.commit()
        await self.publish(owner_user_id, event)
        return event

    async def catch_up(
        self,
        db: AsyncSession,
        owner_user_id: str,
        cursor: int,
    ) -> list[BrowserEvent]:
        page = await self.catch_up_page(db, owner_user_id, cursor)
        return list(page.events)

    async def catch_up_page(
        self,
        db: AsyncSession,
        owner_user_id: str,
        cursor: int,
    ) -> BrowserEventPage:
        state = await db.scalar(
            select(EventOwnerCursor)
            .where(EventOwnerCursor.owner_user_id == owner_user_id)
            .with_for_update(read=True)
        )
        if state is None:
            if cursor != 0:
                raise BrowserCursorResetRequired("event cursor is ahead of the owner stream")
            return BrowserEventPage(events=(), has_more=False, serialized_bytes=0)
        if cursor < state.minimum_resume_cursor:
            raise BrowserCursorResetRequired("event cursor is older than retained history")
        if cursor > state.last_cursor:
            raise BrowserCursorResetRequired("event cursor is ahead of the owner stream")

        row_limit = int(self._settings.browser_event_catchup_limit)
        byte_limit = int(
            getattr(
                self._settings,
                "browser_event_catchup_max_bytes",
                DEFAULT_BROWSER_EVENT_CATCHUP_MAX_BYTES,
            )
        )
        if row_limit <= 0:
            raise ValueError("browser event catch-up row limit must be positive")
        if byte_limit <= 0:
            raise ValueError("browser event catch-up byte limit must be positive")

        rows = await db.stream_scalars(
            select(EventLog)
            .where(
                EventLog.owner_user_id == owner_user_id,
                EventLog.owner_cursor > cursor,
            )
            .order_by(EventLog.owner_cursor)
            .limit(row_limit + 1)
            .execution_options(yield_per=1)
        )

        events: list[BrowserEvent] = []
        serialized_bytes = 0
        has_more = False
        try:
            row_index = 0
            async for row in rows:
                if row_index == row_limit:
                    has_more = True
                    break
                row_index += 1
                event = BrowserEvent(
                    cursor=str(row.owner_cursor),
                    type=row.event_type,
                    occurred_at=row.occurred_at,
                    data=row.payload,
                )
                event_bytes = len(event.model_dump_json().encode("utf-8"))
                if serialized_bytes + event_bytes > byte_limit:
                    if not events:
                        raise BrowserEventTooLarge(
                            cursor=row.owner_cursor,
                            serialized_bytes=event_bytes,
                            byte_limit=byte_limit,
                        )
                    has_more = True
                    break
                events.append(event)
                serialized_bytes += event_bytes
        finally:
            await rows.close()

        return BrowserEventPage(
            events=tuple(events),
            has_more=has_more,
            serialized_bytes=serialized_bytes,
        )

    async def publish_existing(self, owner_user_id: str, event: BrowserEvent) -> None:
        await self._store.publish(
            f"browser:{owner_user_id}", json.dumps(event.model_dump(mode="json"))
        )

    async def prune(self, db: AsyncSession, now: datetime | None = None) -> int:
        now = now or datetime.now(UTC)
        removed = 0
        owners = list((await db.scalars(select(EventOwnerCursor.owner_user_id))).all())
        for owner_user_id in owners:
            state = await db.scalar(
                select(EventOwnerCursor)
                .where(EventOwnerCursor.owner_user_id == owner_user_id)
                .with_for_update()
            )
            if state is None:
                await db.rollback()
                continue
            discarded_through = state.minimum_resume_cursor
            expired_through = await db.scalar(
                select(func.max(EventLog.owner_cursor)).where(
                    EventLog.owner_user_id == owner_user_id,
                    EventLog.ingested_at
                    < now - timedelta(days=self._settings.browser_event_retention_days),
                )
            )
            expired = await db.execute(
                delete(EventLog).where(
                    EventLog.owner_user_id == owner_user_id,
                    EventLog.ingested_at
                    < now - timedelta(days=self._settings.browser_event_retention_days),
                )
            )
            removed += int(expired.rowcount or 0)
            if expired_through is not None:
                discarded_through = max(discarded_through, int(expired_through))
            threshold = await db.scalar(
                select(EventLog.owner_cursor)
                .where(EventLog.owner_user_id == owner_user_id)
                .order_by(EventLog.owner_cursor.desc())
                .offset(self._settings.browser_event_max_per_owner - 1)
                .limit(1)
            )
            if threshold is not None:
                overflow_through = await db.scalar(
                    select(func.max(EventLog.owner_cursor)).where(
                        EventLog.owner_user_id == owner_user_id,
                        EventLog.owner_cursor < threshold,
                    )
                )
                overflow = await db.execute(
                    delete(EventLog).where(
                        EventLog.owner_user_id == owner_user_id,
                        EventLog.owner_cursor < threshold,
                    )
                )
                removed += int(overflow.rowcount or 0)
                if overflow_through is not None:
                    discarded_through = max(discarded_through, int(overflow_through))
            state.minimum_resume_cursor = discarded_through
            await db.commit()
        return removed


class BrowserCursorResetRequired(Exception):
    pass


class BrowserEventTooLarge(BrowserCursorResetRequired):
    def __init__(self, *, cursor: int, serialized_bytes: int, byte_limit: int) -> None:
        self.cursor = cursor
        self.serialized_bytes = serialized_bytes
        self.byte_limit = byte_limit
        super().__init__(f"event at cursor {cursor} exceeds the browser catch-up byte budget")


class EventCursorExhausted(Exception):
    pass
