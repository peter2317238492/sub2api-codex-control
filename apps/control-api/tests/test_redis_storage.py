from __future__ import annotations

import asyncio

import pytest
from redis.asyncio import Redis

from control_api.config import Settings
from control_api.storage import RedisKeyValueStore, create_key_value_store


class FakePubSub:
    """Minimal redis-py PubSub double that preserves acknowledgement ordering."""

    def __init__(self, *, subscribe_error: BaseException | None = None) -> None:
        self.subscribe_error = subscribe_error
        self.subscribe_called = asyncio.Event()
        self.responses: asyncio.Queue[object] = asyncio.Queue()
        self.subscribed_channels: list[str] = []
        self.unsubscribe_calls: list[tuple[str, ...]] = []
        self.get_message_calls: list[tuple[bool, float | None]] = []
        self.closed = False

    async def subscribe(self, *channels: str) -> None:
        self.subscribed_channels.extend(channels)
        self.subscribe_called.set()
        if self.subscribe_error is not None:
            raise self.subscribe_error

    async def get_message(
        self,
        ignore_subscribe_messages: bool = False,
        timeout: float | None = 0.0,
    ) -> dict[str, object] | None:
        self.get_message_calls.append((ignore_subscribe_messages, timeout))
        response = await self.responses.get()
        if isinstance(response, BaseException):
            raise response
        if response is None:
            return None
        assert isinstance(response, dict)
        return response

    async def unsubscribe(self, *channels: str) -> None:
        self.unsubscribe_calls.append(channels)

    async def aclose(self) -> None:
        self.closed = True

    def feed(self, response: object) -> None:
        self.responses.put_nowait(response)


class FakeRedis:
    def __init__(self, pubsub: FakePubSub) -> None:
        self._pubsub = pubsub

    def pubsub(self) -> FakePubSub:
        return self._pubsub


def test_redis_client_uses_configured_connect_and_command_timeouts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}
    client = object()

    def fake_from_url(url: str, **kwargs: object) -> object:
        captured["url"] = url
        captured.update(kwargs)
        return client

    monkeypatch.setattr(Redis, "from_url", staticmethod(fake_from_url))
    settings = Settings(
        redis_url="redis://cache.internal:6379/4",
        redis_connect_timeout_seconds=1.25,
        redis_command_timeout_seconds=2.5,
    )

    store = create_key_value_store(settings)

    assert isinstance(store, RedisKeyValueStore)
    assert store._client is client  # noqa: SLF001 - verifies the factory boundary
    assert captured == {
        "url": "redis://cache.internal:6379/4",
        "decode_responses": True,
        "socket_connect_timeout": 1.25,
        "socket_timeout": 2.5,
    }


async def test_subscription_ready_waits_for_exact_prefixed_acknowledgement() -> None:
    pubsub = FakePubSub()
    store = RedisKeyValueStore(FakeRedis(pubsub), "control:")
    ready = asyncio.Event()
    subscription = store.subscribe("browser:user-1", ready)
    next_message = asyncio.create_task(anext(subscription))

    await asyncio.wait_for(pubsub.subscribe_called.wait(), timeout=1)
    await asyncio.sleep(0)
    assert not ready.is_set()
    assert pubsub.subscribed_channels == ["control:browser:user-1"]

    pubsub.feed(
        {
            "type": "subscribe",
            "pattern": None,
            "channel": b"control:browser:user-1",
            "data": 1,
        }
    )
    pubsub.feed(
        {
            "type": "message",
            "pattern": None,
            "channel": "control:browser:user-1",
            "data": b'{"cursor":42}',
        }
    )

    await asyncio.wait_for(ready.wait(), timeout=1)
    assert await asyncio.wait_for(next_message, timeout=1) == '{"cursor":42}'
    assert pubsub.get_message_calls == [(False, 1.0), (True, 1.0)]

    await subscription.aclose()
    assert pubsub.unsubscribe_calls == [("control:browser:user-1",)]
    assert pubsub.closed


@pytest.mark.parametrize(
    "acknowledgement",
    [
        {
            "type": "subscribe",
            "pattern": None,
            "channel": "control:browser:someone-else",
            "data": 1,
        },
        {
            "type": "psubscribe",
            "pattern": None,
            "channel": "control:browser:user-1",
            "data": 1,
        },
        {
            "type": "subscribe",
            "pattern": None,
            "channel": "control:browser:user-1",
            "data": 2,
        },
    ],
)
async def test_subscription_rejects_wrong_or_unrelated_acknowledgement(
    acknowledgement: dict[str, object],
) -> None:
    pubsub = FakePubSub()
    store = RedisKeyValueStore(FakeRedis(pubsub), "control:")
    ready = asyncio.Event()
    subscription = store.subscribe("browser:user-1", ready)
    pubsub.feed(acknowledgement)

    with pytest.raises(RuntimeError, match="unexpected Redis SUBSCRIBE acknowledgement"):
        await anext(subscription)

    assert not ready.is_set()
    assert pubsub.unsubscribe_calls == [("control:browser:user-1",)]
    assert pubsub.closed


async def test_subscription_closes_pubsub_when_acknowledgement_read_fails() -> None:
    pubsub = FakePubSub()
    store = RedisKeyValueStore(FakeRedis(pubsub), "control:")
    ready = asyncio.Event()
    subscription = store.subscribe("device-dispatch:device-1", ready)
    pubsub.feed(ConnectionError("Redis connection lost before SUBSCRIBE acknowledgement"))

    with pytest.raises(ConnectionError, match="connection lost"):
        await anext(subscription)

    assert not ready.is_set()
    assert pubsub.unsubscribe_calls == [("control:device-dispatch:device-1",)]
    assert pubsub.closed


async def test_subscription_closes_pubsub_when_subscribe_command_fails() -> None:
    pubsub = FakePubSub(subscribe_error=ConnectionError("Redis SUBSCRIBE send failed"))
    store = RedisKeyValueStore(FakeRedis(pubsub), "control:")
    ready = asyncio.Event()
    subscription = store.subscribe("device-dispatch:device-1", ready)

    with pytest.raises(ConnectionError, match="SUBSCRIBE send failed"):
        await anext(subscription)

    assert not ready.is_set()
    assert pubsub.unsubscribe_calls == []
    assert pubsub.closed
