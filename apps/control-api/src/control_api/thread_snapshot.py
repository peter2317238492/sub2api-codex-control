from __future__ import annotations

import json
from typing import Any

from .protocol import ensure_ascii_json_byte_length

MAX_THREAD_SNAPSHOT_BYTES = 512 * 1024
MAX_THREAD_SNAPSHOT_MESSAGES = 1_000


class ThreadSnapshotTooLarge(ValueError):
    pass


def serialized_json_byte_length(value: Any) -> int:
    try:
        encoded = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
        return len(encoded.encode("utf-8"))
    except (TypeError, UnicodeEncodeError, ValueError) as exc:
        raise ThreadSnapshotTooLarge("thread snapshot is not serializable") from exc


def compact_thread_snapshot(
    snapshot: dict[str, Any],
    *,
    max_bytes: int,
    required_message_id: str | None = None,
    max_messages: int = MAX_THREAD_SNAPSHOT_MESSAGES,
) -> dict[str, Any]:
    effective_max_bytes = min(max_bytes, MAX_THREAD_SNAPSHOT_BYTES)
    if effective_max_bytes <= 0 or max_messages <= 0:
        raise ThreadSnapshotTooLarge("thread snapshot budget is invalid")

    compacted = dict(snapshot)
    raw_messages = snapshot.get("messages", [])
    messages = [dict(item) for item in raw_messages if isinstance(item, dict)]

    required_index: int | None = None
    if required_message_id is not None:
        required_index = next(
            (
                index
                for index in range(len(messages) - 1, -1, -1)
                if messages[index].get("id") == required_message_id
            ),
            None,
        )
        if required_index is None:
            raise ThreadSnapshotTooLarge("required thread message is missing")

    removable = [index for index in range(len(messages)) if index != required_index]
    minimum_drop = max(0, len(messages) - max_messages)
    if minimum_drop > len(removable):
        raise ThreadSnapshotTooLarge("required thread message exceeds the history limit")

    def candidate(drop_count: int) -> dict[str, Any]:
        dropped = set(removable[:drop_count])
        result = dict(compacted)
        result["messages"] = [
            message for index, message in enumerate(messages) if index not in dropped
        ]
        return result

    def fits(value: dict[str, Any]) -> bool:
        try:
            return (
                ensure_ascii_json_byte_length(value) <= effective_max_bytes
                and serialized_json_byte_length(value) <= effective_max_bytes
            )
        except ValueError as exc:
            if isinstance(exc, ThreadSnapshotTooLarge):
                raise
            raise ThreadSnapshotTooLarge("thread snapshot is not serializable") from exc

    if not fits(candidate(len(removable))):
        raise ThreadSnapshotTooLarge("required thread message exceeds the snapshot byte limit")

    low = minimum_drop
    high = len(removable)
    while low < high:
        middle = (low + high) // 2
        if fits(candidate(middle)):
            high = middle
        else:
            low = middle + 1
    return candidate(low)
