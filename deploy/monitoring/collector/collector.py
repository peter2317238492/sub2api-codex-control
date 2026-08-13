#!/usr/bin/env python3
"""Fail-closed loopback collector for pre-produced, bounded evidence files."""

from __future__ import annotations

import math
import os
import re
import stat
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Dict, FrozenSet, Iterable, List, Mapping, NamedTuple, Optional, Tuple

LISTEN_ADDRESS = "127.0.0.1"
LISTEN_PORT = 19091
MAX_FILE_BYTES = 128 * 1024
RELEASE_RE = re.compile(r"^[0-9A-Za-z][0-9A-Za-z._+-]{0,63}$")
VCS_RE = re.compile(r"^[0-9a-f]{7,64}$")
SAMPLE_RE = re.compile(
    r"^(?P<name>[a-zA-Z_:][a-zA-Z0-9_:]*)(?:\{(?P<labels>[^{}]*)\})?[ \t]+(?P<value>[^ \t]+)$"
)
LABEL_RE = re.compile(r'(?:^|,)([a-zA-Z_][a-zA-Z0-9_]*)="((?:[^"\\]|\\.)*)"')
NONCE_RE = re.compile(r"^[0-9a-f]{32}$")
BOOLEAN_FAMILIES = {
    "codex_control_local_delivery_test",
    "codex_control_external_delivery_test",
    "codex_control_synthetic_probe_success",
    "codex_control_external_postgresql_up",
    "codex_control_external_redis_up",
    "codex_control_external_migration_revision_match",
    "codex_control_external_policy_check_ok",
    "codex_control_external_backup_checksum_ok",
    "codex_control_connector_up",
    "codex_control_external_operator_delivery_verified",
    "codex_control_release_gate_snapshot_ok",
    "codex_control_production_stability_window_ok",
    "codex_control_post_release_backup_verified",
    "codex_control_release_observability_receipt_current",
}
TIMESTAMP_FAMILIES = {
    "codex_control_external_backup_last_success_timestamp_seconds",
    "codex_control_external_restore_rehearsal_last_success_timestamp_seconds",
    "codex_control_connector_last_update_timestamp_seconds",
    "codex_control_connector_contract_last_failure_timestamp_seconds",
    "codex_control_external_operator_delivery_verified_timestamp_seconds",
    "codex_control_release_gate_snapshot_timestamp_seconds",
    "codex_control_production_stability_window_end_timestamp_seconds",
    "codex_control_post_release_backup_verified_timestamp_seconds",
    "codex_control_release_observability_verified_timestamp_seconds",
}


class SourcePolicy(NamedTuple):
    max_age_seconds: int
    families: Mapping[str, Tuple[FrozenSet[str], Mapping[str, FrozenSet[str]]]]


NO_LABELS: Tuple[FrozenSet[str], Mapping[str, FrozenSet[str]]] = (frozenset(), {})
POLICIES: Mapping[str, SourcePolicy] = {
    "release-observability.prom": SourcePolicy(
        300,
        {
            "codex_control_release_observability_identity": (
                frozenset({"version", "vcs_ref"}),
                {"version": frozenset(), "vcs_ref": frozenset()},
            ),
            "codex_control_external_operator_delivery_verified": NO_LABELS,
            "codex_control_external_operator_delivery_verified_timestamp_seconds": NO_LABELS,
            "codex_control_release_gate_snapshot_ok": NO_LABELS,
            "codex_control_release_gate_snapshot_timestamp_seconds": NO_LABELS,
            "codex_control_production_stability_window_ok": NO_LABELS,
            "codex_control_production_stability_window_end_timestamp_seconds": NO_LABELS,
            "codex_control_post_release_backup_verified": NO_LABELS,
            "codex_control_post_release_backup_verified_timestamp_seconds": NO_LABELS,
            "codex_control_release_observability_receipt_current": NO_LABELS,
            "codex_control_release_observability_verified_timestamp_seconds": NO_LABELS,
        },
    ),
    "delivery-test.prom": SourcePolicy(
        120,
        {
            "codex_control_local_delivery_test": (
                frozenset({"controlled_nonce"}),
                {"controlled_nonce": frozenset()},
            ),
            "codex_control_external_delivery_test": (
                frozenset({"controlled_nonce"}),
                {"controlled_nonce": frozenset()},
            ),
        },
    ),
    "synthetics.prom": SourcePolicy(
        180,
        {
            "codex_control_synthetic_probe_success": (
                frozenset({"probe"}),
                {"probe": frozenset({"live", "ready", "pwa", "session_exchange"})},
            )
        },
    ),
    "infrastructure.prom": SourcePolicy(
        300,
        {
            "codex_control_external_postgresql_up": NO_LABELS,
            "codex_control_external_redis_up": NO_LABELS,
            "codex_control_external_redis_evicted_keys_total": NO_LABELS,
            "codex_control_external_redis_memory_used_bytes": NO_LABELS,
            "codex_control_external_redis_memory_max_bytes": NO_LABELS,
            "codex_control_external_migration_revision_match": NO_LABELS,
            "codex_control_external_policy_check_ok": (
                frozenset({"check"}),
                {
                    "check": frozenset(
                        {"postgres_role", "redis_acl", "redis_pubsub_fanout", "secret_file_mode"}
                    )
                },
            ),
        },
    ),
    "backup.prom": SourcePolicy(
        300,
        {
            "codex_control_external_backup_last_success_timestamp_seconds": NO_LABELS,
            "codex_control_external_backup_checksum_ok": NO_LABELS,
        },
    ),
    "restore.prom": SourcePolicy(
        300,
        {"codex_control_external_restore_rehearsal_last_success_timestamp_seconds": NO_LABELS},
    ),
    "connector.prom": SourcePolicy(
        60,
        {
            "codex_control_connector_up": NO_LABELS,
            "codex_control_connector_last_update_timestamp_seconds": NO_LABELS,
            "codex_control_connector_reconnects_total": (
                frozenset({"reason"}),
                {"reason": frozenset({"token", "dial", "handshake", "connection_io"})},
            ),
            "codex_control_connector_spool_bytes": NO_LABELS,
            "codex_control_connector_spool_capacity_bytes": NO_LABELS,
            "codex_control_connector_spool_events": NO_LABELS,
            "codex_control_connector_spool_oldest_unacknowledged_age_seconds": NO_LABELS,
            "codex_control_connector_app_server_restarts_total": (
                frozenset({"reason"}),
                {
                    "reason": frozenset(
                        {"start_failure", "notification_failure", "child_exit"}
                    )
                },
            ),
            "codex_control_connector_contract_failures_total": (
                frozenset({"kind"}),
                {"kind": frozenset({"version", "schema"})},
            ),
            "codex_control_connector_contract_last_failure_timestamp_seconds": (
                frozenset({"kind"}),
                {"kind": frozenset({"version", "schema"})},
            ),
            "codex_control_connector_policy_denials_total": (
                frozenset({"reason"}),
                {"reason": frozenset({"command"})},
            ),
        },
    ),
}


def _parse_labels(raw: Optional[str]) -> Dict[str, str]:
    if raw is None or raw == "":
        return {}
    labels: Dict[str, str] = {}
    position = 0
    for match in LABEL_RE.finditer(raw):
        if match.start() != position:
            raise ValueError("invalid label syntax")
        key, value = match.groups()
        if key in labels or "\\" in value:
            raise ValueError("duplicate or escaped labels are not accepted")
        labels[key] = value
        position = match.end()
    if position != len(raw):
        raise ValueError("invalid trailing label data")
    return labels


def _validate_sample(line: str, policy: SourcePolicy, now: float) -> str:
    match = SAMPLE_RE.fullmatch(line)
    if match is None:
        raise ValueError("only one-sample-per-line Prometheus text is accepted")
    name = match.group("name")
    family_policy = policy.families.get(name)
    if family_policy is None:
        raise ValueError("metric family is not permitted for this source")
    labels = _parse_labels(match.group("labels"))
    expected_labels, allowed_values = family_policy
    if frozenset(labels) != expected_labels:
        raise ValueError("metric labels do not match the bounded contract")
    for key, value in labels.items():
        if key == "controlled_nonce":
            if not NONCE_RE.fullmatch(value):
                raise ValueError("controlled nonce is invalid")
        elif allowed_values[key] and value not in allowed_values[key]:
            raise ValueError("metric label value is outside the bounded contract")
        elif key == "version" and not RELEASE_RE.fullmatch(value):
            raise ValueError("release identity label is invalid")
        elif key == "vcs_ref" and not VCS_RE.fullmatch(value):
            raise ValueError("VCS identity label is invalid")
    try:
        value = float(match.group("value"))
    except ValueError as exc:
        raise ValueError("metric value is not numeric") from exc
    if not math.isfinite(value):
        raise ValueError("non-finite metric values are not accepted")
    if value < 0:
        raise ValueError("negative metric values are not accepted")
    if name in BOOLEAN_FAMILIES and value not in {0.0, 1.0}:
        raise ValueError("boolean metric values must be exactly zero or one")
    if name in TIMESTAMP_FAMILIES and value > now + 30:
        raise ValueError("timestamp metric is implausibly future-dated")
    return line


def _read_source(path: Path, policy: SourcePolicy, now: float) -> List[str]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(str(path), flags)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise ValueError("evidence source is not a regular file")
        if metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) != 0o600:
            raise ValueError("evidence source must be owner-only 0600")
        if metadata.st_size > MAX_FILE_BYTES:
            raise ValueError("evidence source exceeds the size limit")
        named = path.lstat()
        if (metadata.st_dev, metadata.st_ino) != (named.st_dev, named.st_ino):
            raise ValueError("evidence source identity changed")
        age = now - metadata.st_mtime
        if age < -30 or age > policy.max_age_seconds:
            raise ValueError("evidence source is stale or implausibly future-dated")
        with os.fdopen(descriptor, "r", encoding="ascii", errors="strict") as handle:
            descriptor = -1
            lines = []
            for raw_line in handle:
                line = raw_line.strip()
                if not line or line.startswith("#"):
                    continue
                lines.append(_validate_sample(line, policy, now))
            final = os.fstat(handle.fileno())
            final_named = path.lstat()
            if (
                not stat.S_ISREG(final.st_mode)
                or final.st_uid != metadata.st_uid
                or stat.S_IMODE(final.st_mode) != 0o600
                or final.st_nlink != 1
                or final.st_size > MAX_FILE_BYTES
                or (final.st_dev, final.st_ino) != (final_named.st_dev, final_named.st_ino)
            ):
                raise ValueError("evidence source identity changed during read")
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if not lines:
        raise ValueError("evidence source contains no samples")
    return lines


def validate_evidence_directory(path: Path) -> Tuple[int, int]:
    absolute = path.absolute()
    current = absolute
    while True:
        metadata = current.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise ValueError("evidence directory chain must contain only directories")
        sticky_root_directory = metadata.st_uid == 0 and bool(metadata.st_mode & stat.S_ISVTX)
        if metadata.st_mode & 0o022 and not sticky_root_directory:
            raise ValueError("evidence directory chain must not be group/other writable")
        if metadata.st_uid not in {0, os.geteuid()}:
            raise ValueError("evidence directory chain has an untrusted owner")
        if current == absolute and (
            metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) != 0o700
        ):
            raise ValueError("evidence directory must be collector-owned 0700")
        if current.parent == current:
            break
        current = current.parent
    final = absolute.stat()
    return final.st_dev, final.st_ino


def _escape_label(value: str) -> str:
    return value.replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')


def _render_sources(
    evidence_dir: Path,
    filenames: Iterable[str],
    now: float,
) -> List[str]:
    lines = [
        "# HELP codex_control_monitoring_evidence_file_valid "
        "Whether an optional evidence file passed all checks.",
        "# TYPE codex_control_monitoring_evidence_file_valid gauge",
    ]
    for filename in filenames:
        policy = POLICIES[filename]
        try:
            source_lines = _read_source(evidence_dir / filename, policy, now)
        except (FileNotFoundError, OSError, UnicodeError, ValueError):
            lines.append(
                f'codex_control_monitoring_evidence_file_valid{{source="{filename}"}} 0'
            )
            continue
        lines.append(f'codex_control_monitoring_evidence_file_valid{{source="{filename}"}} 1')
        lines.extend(source_lines)
    return lines


def render_metrics(
    evidence_dir: Path,
    release: str,
    vcs_ref: str,
    now: Optional[float] = None,
) -> str:
    normalized_release = release.lower()
    if (
        not RELEASE_RE.fullmatch(release)
        or normalized_release in {"unknown", "unborn", "dirty"}
        or "replace" in normalized_release
    ):
        raise ValueError("expected release is not concrete")
    if not VCS_RE.fullmatch(vcs_ref):
        raise ValueError("expected VCS revision must be 7-64 lowercase hexadecimal characters")
    current_time = time.time() if now is None else now
    lines = [
        "# HELP codex_control_monitoring_expected_build_info Exact admitted Control API identity.",
        "# TYPE codex_control_monitoring_expected_build_info gauge",
        (
            "codex_control_monitoring_expected_build_info"
            f'{{version="{_escape_label(release)}",vcs_ref="{_escape_label(vcs_ref)}"}} 1'
        ),
    ]
    lines.extend(
        _render_sources(
            evidence_dir,
            (filename for filename in POLICIES if filename != "connector.prom"),
            current_time,
        )
    )
    release_identity = (
        "codex_control_release_observability_identity"
        f'{{version="{_escape_label(release)}",vcs_ref="{_escape_label(vcs_ref)}"}} 1'
    )
    if release_identity not in lines:
        lines = [
            line
            for line in lines
            if not line.startswith("codex_control_release_observability_")
            and not line.startswith("codex_control_external_operator_delivery_verified")
            and not line.startswith("codex_control_release_gate_snapshot_")
            and not line.startswith("codex_control_production_stability_window_")
            and not line.startswith("codex_control_post_release_backup_")
        ]
    lines.append("")
    return "\n".join(lines)


def render_connector_metrics(evidence_dir: Path, now: Optional[float] = None) -> str:
    current_time = time.time() if now is None else now
    return "\n".join([*_render_sources(evidence_dir, ("connector.prom",), current_time), ""])


class CollectorHandler(BaseHTTPRequestHandler):
    evidence_dir = Path("/evidence")
    release = ""
    vcs_ref = ""
    evidence_identity = (0, 0)

    def do_GET(self) -> None:
        if self.path == "/healthz":
            self._respond(200, b"ok\n", "text/plain; charset=utf-8")
            return
        if self.path not in {"/metrics", "/metrics/connector"}:
            self._respond(404, b"not found\n", "text/plain; charset=utf-8")
            return
        try:
            current_identity = self.evidence_dir.stat()
            if (current_identity.st_dev, current_identity.st_ino) != self.evidence_identity:
                raise ValueError("evidence directory identity changed")
            if self.path == "/metrics/connector":
                rendered = render_connector_metrics(self.evidence_dir)
            else:
                rendered = render_metrics(self.evidence_dir, self.release, self.vcs_ref)
            payload = rendered.encode("ascii")
        except ValueError:
            self._respond(503, b"collector configuration invalid\n", "text/plain; charset=utf-8")
            return
        self._respond(200, payload, "text/plain; version=0.0.4; charset=utf-8")

    def _respond(self, status_code: int, payload: bytes, content_type: str) -> None:
        self.send_response(status_code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, format: str, *args: object) -> None:
        return


def main() -> None:
    release = os.environ.get("CONTROL_MONITORING_EXPECTED_RELEASE", "")
    vcs_ref = os.environ.get("CONTROL_MONITORING_EXPECTED_VCS_REF", "")
    evidence_dir = Path(os.environ.get("CONTROL_MONITORING_EVIDENCE_DIR", "/evidence")).absolute()
    evidence_identity = validate_evidence_directory(evidence_dir)
    render_metrics(evidence_dir, release, vcs_ref)
    CollectorHandler.release = release
    CollectorHandler.vcs_ref = vcs_ref
    CollectorHandler.evidence_dir = evidence_dir
    CollectorHandler.evidence_identity = evidence_identity
    server = ThreadingHTTPServer((LISTEN_ADDRESS, LISTEN_PORT), CollectorHandler)
    server.serve_forever()


if __name__ == "__main__":
    main()
