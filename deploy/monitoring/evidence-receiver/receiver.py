#!/usr/bin/env python3
"""Authenticated append receiver and strict controlled-delivery verifier."""

from __future__ import annotations

import argparse
import fcntl
import hmac
import json
import os
import re
import stat
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple

from common import open_parent, read_secret_file, require_parent_stable

LISTEN_ADDRESS = "127.0.0.1"
LISTEN_PORT = 19094
MAX_BODY_BYTES = 1024 * 1024
MAX_EVIDENCE_BYTES = 64 * 1024 * 1024
ALERT_NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_:]{0,127}$")
FINGERPRINT_RE = re.compile(r"^[0-9a-f]{1,128}$")
NONCE_RE = re.compile(r"^[0-9a-f]{32}$")
RECORD_KEYS = {
    "received_at",
    "group_status",
    "alert_status",
    "alertname",
    "fingerprint",
    "controlled_nonce",
    "starts_at",
    "ends_at",
}


def _timestamp() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_timestamp(value: Any, *, allow_empty: bool = False) -> Optional[datetime]:
    if allow_empty and value == "":
        return None
    if not isinstance(value, str) or len(value) > 64 or not value.endswith("Z"):
        raise ValueError("invalid timestamp")
    parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    if parsed.tzinfo is None:
        raise ValueError("timestamp is not timezone aware")
    return parsed.astimezone(timezone.utc)


def normalize_payload(payload: Mapping[str, Any]) -> List[Dict[str, str]]:
    group_status = payload.get("status")
    if group_status not in {"firing", "resolved"}:
        raise ValueError("invalid group status")
    alerts = payload.get("alerts")
    if not isinstance(alerts, list) or not alerts or len(alerts) > 256:
        raise ValueError("invalid alert list")
    received_at = _timestamp()
    records: List[Dict[str, str]] = []
    for alert in alerts:
        if not isinstance(alert, dict):
            raise ValueError("invalid alert")
        alert_status = alert.get("status")
        if alert_status not in {"firing", "resolved"}:
            raise ValueError("invalid alert status")
        labels = alert.get("labels")
        if not isinstance(labels, dict):
            raise ValueError("missing labels")
        alert_name = labels.get("alertname")
        controlled_nonce = labels.get("controlled_nonce")
        fingerprint = alert.get("fingerprint")
        starts_at = alert.get("startsAt", "")
        ends_at = alert.get("endsAt", "")
        if not isinstance(alert_name, str) or not ALERT_NAME_RE.fullmatch(alert_name):
            raise ValueError("invalid alert name")
        if not isinstance(controlled_nonce, str) or not NONCE_RE.fullmatch(controlled_nonce):
            raise ValueError("missing or invalid controlled nonce")
        if not isinstance(fingerprint, str) or not FINGERPRINT_RE.fullmatch(fingerprint):
            raise ValueError("invalid fingerprint")
        _parse_timestamp(starts_at)
        _parse_timestamp(ends_at, allow_empty=alert_status == "firing")
        records.append(
            {
                "received_at": received_at,
                "group_status": group_status,
                "alert_status": alert_status,
                "alertname": alert_name,
                "fingerprint": fingerprint,
                "controlled_nonce": controlled_nonce,
                "starts_at": starts_at,
                "ends_at": ends_at,
            }
        )
    return records


def append_records(path: Path, records: Iterable[Mapping[str, str]]) -> None:
    absolute, parent_fd, parent_identity = open_parent(path)
    descriptor = -1
    existed = True
    try:
        try:
            os.stat(absolute.name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            existed = False
        flags = os.O_APPEND | os.O_CREAT | os.O_WRONLY | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(absolute.name, flags, 0o600, dir_fd=parent_fd)
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o600
        ):
            raise ValueError("evidence destination identity, owner, or mode is invalid")
        payload = b"".join(
            (json.dumps(dict(record), sort_keys=True, separators=(",", ":")) + "\n").encode(
                "ascii"
            )
            for record in records
        )
        if metadata.st_size + len(payload) > MAX_EVIDENCE_BYTES:
            raise ValueError("evidence destination exceeds size limit")
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("short append to evidence destination")
            view = view[written:]
        os.fsync(descriptor)
        final = os.fstat(descriptor)
        named = os.stat(absolute.name, dir_fd=parent_fd, follow_symlinks=False)
        if (final.st_dev, final.st_ino, final.st_nlink) != (
            named.st_dev,
            named.st_ino,
            1,
        ):
            raise ValueError("evidence destination identity changed")
        require_parent_stable(parent_fd, absolute.parent, parent_identity)
        if not existed:
            os.fsync(parent_fd)
    finally:
        if descriptor >= 0:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            except OSError:
                pass
            os.close(descriptor)
        os.close(parent_fd)


def _validate_record(record: Any) -> Dict[str, str]:
    if not isinstance(record, dict) or set(record) != RECORD_KEYS:
        raise ValueError("invalid evidence record schema")
    if record["group_status"] not in {"firing", "resolved"}:
        raise ValueError("invalid group status")
    if record["alert_status"] not in {"firing", "resolved"}:
        raise ValueError("invalid alert status")
    if record["group_status"] != record["alert_status"]:
        raise ValueError("group and alert status differ")
    if not isinstance(record["alertname"], str) or not ALERT_NAME_RE.fullmatch(
        record["alertname"]
    ):
        raise ValueError("invalid alert name")
    if not isinstance(record["fingerprint"], str) or not FINGERPRINT_RE.fullmatch(
        record["fingerprint"]
    ):
        raise ValueError("invalid fingerprint")
    if not isinstance(record["controlled_nonce"], str) or not NONCE_RE.fullmatch(
        record["controlled_nonce"]
    ):
        raise ValueError("invalid controlled nonce")
    _parse_timestamp(record["received_at"])
    _parse_timestamp(record["starts_at"])
    _parse_timestamp(record["ends_at"], allow_empty=record["alert_status"] == "firing")
    return record


def _read_records(path: Path) -> List[Dict[str, str]]:
    absolute, parent_fd, parent_identity = open_parent(path)
    descriptor = -1
    try:
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(absolute.name, flags, dir_fd=parent_fd)
        fcntl.flock(descriptor, fcntl.LOCK_SH)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_size > MAX_EVIDENCE_BYTES
        ):
            raise ValueError("evidence file identity, owner, mode, or size is invalid")
        named = os.stat(absolute.name, dir_fd=parent_fd, follow_symlinks=False)
        if (metadata.st_dev, metadata.st_ino) != (named.st_dev, named.st_ino):
            raise ValueError("evidence file identity changed")
        with os.fdopen(os.dup(descriptor), "r", encoding="ascii", errors="strict") as handle:
            records = [_validate_record(json.loads(line)) for line in handle if line.strip()]
        final = os.fstat(descriptor)
        final_named = os.stat(absolute.name, dir_fd=parent_fd, follow_symlinks=False)
        if (
            not stat.S_ISREG(final.st_mode)
            or final.st_uid != metadata.st_uid
            or stat.S_IMODE(final.st_mode) != 0o600
            or final.st_nlink != 1
            or final.st_size > MAX_EVIDENCE_BYTES
            or (final.st_dev, final.st_ino, final.st_size)
            != (final_named.st_dev, final_named.st_ino, final_named.st_size)
        ):
            raise ValueError("evidence file identity changed during read")
        require_parent_stable(parent_fd, absolute.parent, parent_identity)
        return records
    finally:
        if descriptor >= 0:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            except OSError:
                pass
            os.close(descriptor)
        os.close(parent_fd)


def verify_delivery(path: Path, alert_name: str, controlled_nonce: str) -> str:
    if not NONCE_RE.fullmatch(controlled_nonce):
        raise ValueError("controlled nonce is required")
    firing: Dict[Tuple[str, str], Dict[str, str]] = {}
    resolved: Dict[Tuple[str, str], Dict[str, str]] = {}
    for record in _read_records(path):
        if record["alertname"] != alert_name or record["controlled_nonce"] != controlled_nonce:
            continue
        key = (record["controlled_nonce"], record["fingerprint"])
        if record["alert_status"] == "firing":
            firing[key] = record
        else:
            resolved[key] = record
    for key in sorted(set(firing).intersection(resolved)):
        fired = firing[key]
        cleared = resolved[key]
        firing_received = _parse_timestamp(fired["received_at"])
        resolved_received = _parse_timestamp(cleared["received_at"])
        firing_started = _parse_timestamp(fired["starts_at"])
        resolved_ended = _parse_timestamp(cleared["ends_at"])
        resolved_started = _parse_timestamp(cleared["starts_at"])
        if not (
            firing_received is not None
            and resolved_received is not None
            and firing_started is not None
            and resolved_ended is not None
            and resolved_started == firing_started
            and firing_started < firing_received < resolved_ended <= resolved_received
        ):
            continue
        return json.dumps(
            {
                "scope": "local-authenticated-receiver-only",
                "external_operator_delivery_verified": False,
                "alertname": alert_name,
                "controlled_nonce": controlled_nonce,
                "fingerprint": key[1],
                "firing_received_at": fired["received_at"],
                "resolved_received_at": cleared["received_at"],
            },
            sort_keys=True,
        )
    raise ValueError("no valid nonce-bound firing and resolved pair")


class ReceiverHandler(BaseHTTPRequestHandler):
    evidence_file = Path("/evidence/alert-delivery.jsonl")
    bearer = ""

    def do_GET(self) -> None:
        if self.path != "/healthz":
            self._respond(404, b"not found\n")
            return
        self._respond(200, b"ok\n")

    def do_POST(self) -> None:
        if self.path != "/v1/alerts":
            self._respond(404, b"not found\n")
            return
        if not hmac.compare_digest(
            self.headers.get("Authorization", ""), f"Bearer {self.bearer}"
        ):
            self._respond(401, b"unauthorized\n")
            return
        try:
            length = int(self.headers.get("Content-Length", "-1"))
        except ValueError:
            self._respond(400, b"invalid content length\n")
            return
        if length < 1 or length > MAX_BODY_BYTES:
            self._respond(413, b"invalid body size\n")
            return
        try:
            raw = self.rfile.read(length)
            payload = json.loads(raw.decode("utf-8"))
            if not isinstance(payload, dict):
                raise ValueError("payload must be an object")
            append_records(self.evidence_file, normalize_payload(payload))
        except (OSError, UnicodeError, ValueError, json.JSONDecodeError):
            self._respond(400, b"invalid alert payload\n")
            return
        self._respond(200, b"accepted\n")

    def _respond(self, status_code: int, payload: bytes) -> None:
        self.send_response(status_code)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, format: str, *args: object) -> None:
        return


def main() -> None:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    serve = subparsers.add_parser("serve")
    serve.add_argument("--evidence-file", type=Path, required=True)
    serve.add_argument("--bearer-file", type=Path, required=True)
    verify = subparsers.add_parser("verify")
    verify.add_argument("--evidence-file", type=Path, required=True)
    verify.add_argument("--alert-name", default="CodexControlLocalDeliveryTest")
    verify.add_argument("--controlled-nonce", required=True)
    arguments = parser.parse_args()
    if arguments.command == "verify":
        print(
            verify_delivery(
                arguments.evidence_file,
                arguments.alert_name,
                arguments.controlled_nonce,
            )
        )
        return
    bearer = read_secret_file(arguments.bearer_file).strip().decode("ascii")
    if len(bearer) != 64:
        raise ValueError("receiver bearer must be 64 ASCII bytes")
    ReceiverHandler.evidence_file = arguments.evidence_file
    ReceiverHandler.bearer = bearer
    ThreadingHTTPServer((LISTEN_ADDRESS, LISTEN_PORT), ReceiverHandler).serve_forever()


if __name__ == "__main__":
    main()
