from __future__ import annotations

import asyncio
import time
from collections import defaultdict
from collections.abc import AsyncIterator
from dataclasses import dataclass
from typing import Protocol

from .config import Settings


class KeyValueStore(Protocol):
    async def get(self, key: str) -> str | None: ...

    async def set(self, key: str, value: str, ttl_seconds: int) -> None: ...

    async def set_if_absent(self, key: str, value: str, ttl_seconds: int) -> bool: ...

    async def compare_refresh(self, key: str, expected_value: str, ttl_seconds: int) -> bool: ...

    async def compare_delete(self, key: str, expected_value: str) -> bool: ...

    async def delete(self, key: str) -> None: ...

    async def increment(self, key: str, ttl_seconds: int) -> int: ...

    async def publish(self, channel: str, value: str) -> int: ...

    def subscribe(self, channel: str, ready: asyncio.Event | None = None) -> AsyncIterator[str]: ...

    async def ping(self) -> None: ...

    async def close(self) -> None: ...


@dataclass
class _MemoryValue:
    value: str
    expires_at: float


class InMemoryKeyValueStore:
    """A deterministic test backend. It is rejected by production settings."""

    def __init__(self, prefix: str = "") -> None:
        self._prefix = prefix
        self._values: dict[str, _MemoryValue] = {}
        self._lock = asyncio.Lock()
        self._subscribers: dict[str, set[asyncio.Queue[str]]] = defaultdict(set)

    def _key(self, key: str) -> str:
        return f"{self._prefix}{key}"

    def _purge_expired(self, key: str, now: float) -> None:
        value = self._values.get(key)
        if value is not None and value.expires_at <= now:
            self._values.pop(key, None)

    async def get(self, key: str) -> str | None:
        key = self._key(key)
        async with self._lock:
            self._purge_expired(key, time.monotonic())
            value = self._values.get(key)
            return value.value if value is not None else None

    async def set(self, key: str, value: str, ttl_seconds: int) -> None:
        key = self._key(key)
        async with self._lock:
            self._values[key] = _MemoryValue(value, time.monotonic() + ttl_seconds)

    async def set_if_absent(self, key: str, value: str, ttl_seconds: int) -> bool:
        key = self._key(key)
        async with self._lock:
            now = time.monotonic()
            self._purge_expired(key, now)
            if key in self._values:
                return False
            self._values[key] = _MemoryValue(value, now + ttl_seconds)
            return True

    async def compare_refresh(self, key: str, expected_value: str, ttl_seconds: int) -> bool:
        key = self._key(key)
        async with self._lock:
            now = time.monotonic()
            self._purge_expired(key, now)
            current = self._values.get(key)
            if current is None or current.value != expected_value:
                return False
            self._values[key] = _MemoryValue(current.value, now + ttl_seconds)
            return True

    async def compare_delete(self, key: str, expected_value: str) -> bool:
        key = self._key(key)
        async with self._lock:
            self._purge_expired(key, time.monotonic())
            current = self._values.get(key)
            if current is None or current.value != expected_value:
                return False
            self._values.pop(key, None)
            return True

    async def delete(self, key: str) -> None:
        async with self._lock:
            self._values.pop(self._key(key), None)

    async def increment(self, key: str, ttl_seconds: int) -> int:
        key = self._key(key)
        async with self._lock:
            now = time.monotonic()
            self._purge_expired(key, now)
            current = self._values.get(key)
            count = int(current.value) + 1 if current is not None else 1
            expires_at = current.expires_at if current is not None else now + ttl_seconds
            self._values[key] = _MemoryValue(str(count), expires_at)
            return count

    async def publish(self, channel: str, value: str) -> int:
        async with self._lock:
            subscribers = tuple(self._subscribers[self._key(channel)])
        for queue in subscribers:
            queue.put_nowait(value)
        return len(subscribers)

    async def _subscribe(
        self, channel: str, ready: asyncio.Event | None = None
    ) -> AsyncIterator[str]:
        channel = self._key(channel)
        queue: asyncio.Queue[str] = asyncio.Queue(maxsize=1000)
        async with self._lock:
            self._subscribers[channel].add(queue)
        if ready is not None:
            ready.set()
        try:
            while True:
                yield await queue.get()
        finally:
            async with self._lock:
                self._subscribers[channel].discard(queue)
                if not self._subscribers[channel]:
                    self._subscribers.pop(channel, None)

    def subscribe(self, channel: str, ready: asyncio.Event | None = None) -> AsyncIterator[str]:
        return self._subscribe(channel, ready)

    async def ping(self) -> None:
        return None

    async def close(self) -> None:
        async with self._lock:
            self._values.clear()


class RedisKeyValueStore:
    def __init__(self, client: object, prefix: str) -> None:
        self._client = client
        self._prefix = prefix

    def _key(self, key: str) -> str:
        return f"{self._prefix}{key}"

    async def get(self, key: str) -> str | None:
        value = await self._client.get(self._key(key))
        if value is None:
            return None
        return value.decode() if isinstance(value, bytes) else str(value)

    async def set(self, key: str, value: str, ttl_seconds: int) -> None:
        await self._client.set(self._key(key), value, ex=ttl_seconds)

    async def set_if_absent(self, key: str, value: str, ttl_seconds: int) -> bool:
        result = await self._client.set(self._key(key), value, ex=ttl_seconds, nx=True)
        return bool(result)

    async def compare_refresh(self, key: str, expected_value: str, ttl_seconds: int) -> bool:
        script = """
        if redis.call('GET', KEYS[1]) == ARGV[1] then
          redis.call('EXPIRE', KEYS[1], ARGV[2])
          return 1
        end
        return 0
        """
        result = await self._client.eval(
            script,
            1,
            self._key(key),
            expected_value,
            ttl_seconds,
        )
        return bool(result)

    async def compare_delete(self, key: str, expected_value: str) -> bool:
        script = """
        if redis.call('GET', KEYS[1]) == ARGV[1] then
          return redis.call('DEL', KEYS[1])
        end
        return 0
        """
        result = await self._client.eval(script, 1, self._key(key), expected_value)
        return bool(result)

    async def delete(self, key: str) -> None:
        await self._client.delete(self._key(key))

    async def increment(self, key: str, ttl_seconds: int) -> int:
        redis_key = self._key(key)
        script = """
        local count = redis.call('INCR', KEYS[1])
        if count == 1 then
          redis.call('EXPIRE', KEYS[1], ARGV[1])
        end
        return count
        """
        return int(await self._client.eval(script, 1, redis_key, ttl_seconds))

    async def publish(self, channel: str, value: str) -> int:
        return int(await self._client.publish(self._key(channel), value))

    async def _subscribe(
        self, channel: str, ready: asyncio.Event | None = None
    ) -> AsyncIterator[str]:
        pubsub = self._client.pubsub()
        redis_channel = self._key(channel)
        subscribed = False
        try:
            await pubsub.subscribe(redis_channel)
            subscribed = True
            while True:
                acknowledgement = await pubsub.get_message(
                    ignore_subscribe_messages=False,
                    timeout=1.0,
                )
                if acknowledgement is None:
                    await asyncio.sleep(0)
                    continue
                if not self._is_subscription_acknowledgement(
                    acknowledgement,
                    redis_channel,
                ):
                    raise RuntimeError("unexpected Redis SUBSCRIBE acknowledgement")
                break
            if ready is not None:
                ready.set()

            while True:
                message = await pubsub.get_message(
                    ignore_subscribe_messages=True,
                    timeout=1.0,
                )
                if message is None:
                    await asyncio.sleep(0)
                    continue
                value = message.get("data")
                yield value.decode() if isinstance(value, bytes) else str(value)
        finally:
            try:
                if subscribed:
                    await pubsub.unsubscribe(redis_channel)
            finally:
                await pubsub.aclose()

    @staticmethod
    def _is_subscription_acknowledgement(message: object, channel: str) -> bool:
        if not isinstance(message, dict):
            return False

        message_type = message.get("type")
        acknowledged_channel = message.get("channel")
        subscription_count = message.get("data")
        if isinstance(message_type, bytes):
            message_type = message_type.decode()
        if isinstance(acknowledged_channel, bytes):
            acknowledged_channel = acknowledged_channel.decode()
        try:
            count = int(subscription_count)
        except (TypeError, ValueError):
            return False
        return message_type == "subscribe" and acknowledged_channel == channel and count == 1

    def subscribe(self, channel: str, ready: asyncio.Event | None = None) -> AsyncIterator[str]:
        return self._subscribe(channel, ready)

    async def ping(self) -> None:
        if not await self._client.ping():
            raise RuntimeError("Redis ping returned false")

    async def close(self) -> None:
        await self._client.aclose()


def create_key_value_store(settings: Settings) -> KeyValueStore:
    if settings.redis_url.startswith("memory://"):
        return InMemoryKeyValueStore(settings.redis_prefix)

    from redis.asyncio import Redis

    client = Redis.from_url(
        settings.redis_url,
        decode_responses=True,
        socket_connect_timeout=settings.redis_connect_timeout_seconds,
        socket_timeout=settings.redis_command_timeout_seconds,
    )
    return RedisKeyValueStore(client, settings.redis_prefix)
