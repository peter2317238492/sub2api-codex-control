from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable
from typing import Any

from pydantic import ValidationError

from .config import BOOTSTRAP_CONNECTOR_RELEASE_MAX_BYTES, Settings
from .schemas import ConnectorReleaseMetadata


class _DuplicateJsonKey(ValueError):
    pass


def connector_release_metadata_sha256(raw: str) -> str | None:
    try:
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()
    except UnicodeError:
        return None


def _strict_object(pairs: Iterable[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise _DuplicateJsonKey(key)
        value[key] = item
    return value


def admitted_connector_release(settings: Settings) -> ConnectorReleaseMetadata | None:
    raw = settings.connector_release_metadata_json
    if len(raw) > BOOTSTRAP_CONNECTOR_RELEASE_MAX_BYTES:
        return None
    raw = raw.strip()
    if not raw:
        return None
    try:
        if len(raw.encode("utf-8")) > BOOTSTRAP_CONNECTOR_RELEASE_MAX_BYTES:
            return None
        decoded = json.loads(raw, object_pairs_hook=_strict_object)
        metadata = ConnectorReleaseMetadata.model_validate(decoded)
    except (
        UnicodeError,
        json.JSONDecodeError,
        _DuplicateJsonKey,
        RecursionError,
        ValidationError,
    ):
        return None

    if (
        metadata.version != settings.connector_expected_version
        or metadata.codex_version != settings.codex_expected_version
        or metadata.schema_digest != settings.appserver_schema_digest
    ):
        return None
    return metadata
