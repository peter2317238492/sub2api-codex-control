from __future__ import annotations

import pytest
from conftest import Harness

from control_api.models import ThreadBinding, ThreadBindingStatus
from control_api.protocol import ensure_ascii_json_byte_length
from control_api.thread_snapshot import (
    MAX_THREAD_SNAPSHOT_BYTES,
    MAX_THREAD_SNAPSHOT_MESSAGES,
    ThreadSnapshotTooLarge,
    compact_thread_snapshot,
    serialized_json_byte_length,
)


def _message(message_id: str, text: str = "x") -> dict[str, object]:
    return {
        "id": message_id,
        "role": "user",
        "text": text,
        "created_at": "2026-07-23T00:00:00+00:00",
        "pending": False,
    }


def test_snapshot_deterministically_keeps_the_newest_thousand_messages() -> None:
    snapshot = {
        "messages": [
            _message(f"message-{index}") for index in range(MAX_THREAD_SNAPSHOT_MESSAGES + 2)
        ]
    }
    compacted = compact_thread_snapshot(
        snapshot,
        max_bytes=MAX_THREAD_SNAPSHOT_BYTES,
        required_message_id=f"message-{MAX_THREAD_SNAPSHOT_MESSAGES + 1}",
    )
    assert len(compacted["messages"]) == MAX_THREAD_SNAPSHOT_MESSAGES
    assert compacted["messages"][0]["id"] == "message-2"
    assert compacted["messages"][-1]["id"] == "message-1001"


def test_snapshot_uses_ensure_ascii_and_serialized_unicode_budgets() -> None:
    required = _message("required", "😀" * 100 + "界" * 100)
    required_only = {"messages": [required]}
    max_bytes = ensure_ascii_json_byte_length(required_only)
    snapshot = {
        "messages": [
            _message("oldest", "界" * 200),
            _message("older", "😀" * 100),
            required,
        ]
    }
    compacted = compact_thread_snapshot(
        snapshot,
        max_bytes=max_bytes,
        required_message_id="required",
    )
    assert compacted == required_only
    assert ensure_ascii_json_byte_length(compacted) == max_bytes
    assert serialized_json_byte_length(compacted) <= max_bytes


def test_snapshot_rejects_instead_of_dropping_the_required_message() -> None:
    snapshot = {"messages": [_message("required", "😀" * 400)]}
    with pytest.raises(ThreadSnapshotTooLarge, match="required thread message"):
        compact_thread_snapshot(
            snapshot,
            max_bytes=4_096,
            required_message_id="required",
        )


async def test_realtime_thread_read_and_delta_use_the_shared_snapshot_compactor(
    harness: Harness,
) -> None:
    realtime = harness.app.state.realtime
    result = {
        "thread": {
            "turns": [
                {
                    "items": [
                        {"id": f"item-{index}", "role": "assistant", "text": "x"}
                        for index in range(MAX_THREAD_SNAPSHOT_MESSAGES + 2)
                    ]
                }
            ]
        }
    }
    snapshot = realtime._snapshot_from_result(result, {"messages": []})
    assert len(snapshot["messages"]) == MAX_THREAD_SNAPSHOT_MESSAGES
    assert snapshot["messages"][0]["id"] == "item-2"

    harness.settings.device_max_result_bytes = 4_096
    binding = ThreadBinding(
        owner_user_id="42",
        device_id="ffffffff-ffff-ffff-ffff-ffffffffffff",
        remote_thread_id="remote-thread",
        status=ThreadBindingStatus.RUNNING,
        cwd="/workspace",
        title="Realtime compaction",
        model="gpt-5.5",
        appserver_epoch="epoch-0123456789abcdef",
        snapshot={"messages": [_message("old-history", "o" * 3_500)]},
    )
    assert realtime._append_delta(
        binding,
        {"itemId": "assistant-current", "delta": "😀" * 50},
    ) == ("assistant-current", "😀" * 50)
    assert [message["id"] for message in binding.snapshot["messages"]] == ["assistant-current"]
    assert ensure_ascii_json_byte_length(binding.snapshot) <= 4_096
