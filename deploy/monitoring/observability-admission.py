#!/usr/bin/env python3
"""Render fail-closed Alertmanager config and admit release observability evidence."""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import re
import secrets
import stat
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, Mapping, NoReturn, Optional, Tuple
from urllib.parse import urlsplit

from common import open_parent, read_secret_file, require_parent_stable

FORMAT_VERSION = 1
DELIVERY_KIND = "codex-control-external-operator-delivery"
RELEASE_KIND = "codex-control-release-observability"
DELIVERY_CONFIG_KEYS = {"format_version", "receiver_id", "webhook_url"}
RECEIVER_ID_RE = re.compile(r"^[a-z][a-z0-9-]{2,63}$")
RELEASE_RE = re.compile(r"^[0-9A-Za-z][0-9A-Za-z._+-]{0,63}$")
VCS_RE = re.compile(r"^[0-9a-f]{40,64}$")
DEPLOYMENT_ID_RE = re.compile(r"^[0-9A-Za-z][0-9A-Za-z._:-]{2,127}$")
NONCE_RE = re.compile(r"^[0-9a-f]{32}$")
FINGERPRINT_RE = re.compile(r"^[0-9a-f]{1,128}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
EVIDENCE_NAME_RE = re.compile(r"^[0-9A-Za-z][0-9A-Za-z._-]{0,127}$")
RECEIPT_ID_RE = re.compile(r"^[0-9A-Za-z][0-9A-Za-z._:-]{2,127}$")
MAX_JSON_BYTES = 1024 * 1024
MAX_BOUND_EVIDENCE_BYTES = 16 * 1024 * 1024
DEFAULT_MINIMUM_STABILITY_SECONDS = 24 * 60 * 60
MAX_RECEIPT_AGE = timedelta(minutes=5)
MAX_DELIVERY_RECEIPT_AGE = timedelta(days=30)
MAX_GATE_SNAPSHOT_AGE = timedelta(minutes=3)
MAX_POST_RELEASE_BACKUP_AGE = timedelta(hours=8)
FUTURE_SKEW = timedelta(seconds=30)

REQUIRED_RELEASE_GATE_SIGNALS = frozenset(
    {
        "alertmanager-current",
        "api-build-identity-exact",
        "api-replica-18090-up",
        "api-replica-18093-up",
        "authenticated-session-exchange",
        "backup-current",
        "connector-current",
        "external-operator-delivery",
        "migration-head-current",
        "policy-checks-current",
        "postgresql-current",
        "public-live-synthetic",
        "public-ready-synthetic",
        "pwa-synthetic",
        "redis-current",
        "restore-rehearsal-current",
    }
)

DELIVERY_RECEIPT_KEYS = {
    "format_version",
    "kind",
    "release",
    "vcs_ref",
    "deployment_id",
    "receiver_id",
    "controlled_nonce",
    "fingerprint",
    "firing_started_at",
    "firing_received_at",
    "resolved_at",
    "resolved_received_at",
    "operator_acknowledged_at",
    "operator_receipt_id",
    "verified_at",
    "evidence",
}
DELIVERY_EVIDENCE_KEYS = {"firing", "resolved", "operator_ack"}
DESCRIPTOR_KEYS = {"basename", "sha256"}
RELEASE_RECEIPT_KEYS = {
    "format_version",
    "kind",
    "release",
    "vcs_ref",
    "deployment_id",
    "deployed_at",
    "verified_at",
    "external_delivery",
    "release_gate_snapshot",
    "stability_window",
    "post_release_backup",
}
RELEASE_GATE_KEYS = {
    "observed_at",
    "signals",
    "pending_release_gate_alerts",
    "firing_release_gate_alerts",
    "unexplained_container_restarts",
    "resource_headroom_ok",
}
STABILITY_KEYS = {
    "started_at",
    "ended_at",
    "session_renewal_ok",
    "connector_reconnect_ok",
    "scheduled_monitoring_cycles",
    "scheduled_backup_cycles",
    "unresolved_p0_p1",
}
POST_RELEASE_BACKUP_KEYS = {
    "completed_at",
    "checksum_verified",
    "backup_receipt",
    "restore_receipt",
}


def _fail(message: str) -> NoReturn:
    raise ValueError(message)


def _object_pairs(pairs: Iterable[Tuple[str, Any]]) -> Dict[str, Any]:
    value: Dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            _fail("duplicate JSON key")
        value[key] = item
    return value


def _load_json(path: Path, *, maximum: int = MAX_JSON_BYTES) -> Dict[str, Any]:
    raw = read_secret_file(path, maximum=maximum)
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_object_pairs)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ValueError("invalid JSON evidence") from error
    if not isinstance(value, dict):
        _fail("JSON evidence must be an object")
    return value


def _exact_object(value: Any, keys: set[str], label: str) -> Mapping[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        _fail(f"{label} does not match the exact schema")
    return value


def _timestamp(value: Any, label: str) -> datetime:
    if not isinstance(value, str) or len(value) != 20 or not value.endswith("Z"):
        _fail(f"{label} must be a canonical UTC timestamp")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError as error:
        raise ValueError(f"{label} must be a canonical UTC timestamp") from error
    return parsed


def _now(value: Optional[str]) -> datetime:
    return datetime.now(timezone.utc) if value is None else _timestamp(value, "now")


def _bounded_string(value: Any, pattern: re.Pattern[str], label: str) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        _fail(f"{label} is invalid")
    return value


def _nonnegative_int(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        _fail(f"{label} must be a nonnegative integer")
    return value


def _true(value: Any, label: str) -> None:
    if value is not True:
        _fail(f"{label} must be true")


def _validate_identity(
    value: Mapping[str, Any], release: str, vcs_ref: str, deployment_id: str
) -> None:
    _bounded_string(release, RELEASE_RE, "expected release")
    _bounded_string(vcs_ref, VCS_RE, "expected VCS revision")
    _bounded_string(deployment_id, DEPLOYMENT_ID_RE, "expected deployment id")
    if (
        value.get("release") != release
        or value.get("vcs_ref") != vcs_ref
        or value.get("deployment_id") != deployment_id
    ):
        _fail("receipt release identity differs from the admitted deployment")


def validate_delivery_config(value: Mapping[str, Any]) -> Tuple[str, str]:
    _exact_object(value, DELIVERY_CONFIG_KEYS, "delivery config")
    if value["format_version"] != FORMAT_VERSION:
        _fail("unsupported delivery config version")
    receiver_id = _bounded_string(value["receiver_id"], RECEIVER_ID_RE, "receiver id")
    webhook_url = value["webhook_url"]
    if not isinstance(webhook_url, str) or len(webhook_url) > 512 or not webhook_url.isascii():
        _fail("external webhook URL is invalid")
    parsed = urlsplit(webhook_url)
    if (
        parsed.scheme != "https"
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.hostname is None
        or parsed.hostname != parsed.hostname.lower()
        or parsed.port not in {None, 443}
        or not parsed.path.startswith("/")
        or parsed.path.startswith("//")
    ):
        _fail("external webhook must be canonical HTTPS without embedded credentials or query")
    hostname = parsed.hostname
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        pass
    else:
        _fail("external webhook hostname must not be an IP literal")
    if (
        "." not in hostname
        or hostname == "localhost"
        or hostname.endswith((".localhost", ".local", ".internal", ".invalid", ".test"))
        or "replace" in hostname
    ):
        _fail("external webhook hostname is not externally routable")
    return receiver_id, webhook_url


def render_alertmanager(value: Mapping[str, Any]) -> bytes:
    receiver_id, _ = validate_delivery_config(value)
    external_receiver = f"external-operator-{receiver_id}"
    return f"""global:
  resolve_timeout: 1m

route:
  receiver: {external_receiver}
  group_by:
    - alertname
    - service
  group_wait: 1s
  group_interval: 10s
  repeat_interval: 4h
  routes:
    - receiver: local-append-only-evidence
      matchers:
        - alertname=\"CodexControlLocalDeliveryTest\"
    - receiver: local-append-only-evidence
      matchers:
        - alertname=\"CodexControlExternalDeliveryTest\"
      continue: true
    - receiver: {external_receiver}
      matchers:
        - alertname=\"CodexControlExternalDeliveryTest\"

receivers:
  - name: {external_receiver}
    webhook_configs:
      - url: http://external-delivery-relay:19095/v1/alerts
        send_resolved: true
        max_alerts: 0
        http_config:
          follow_redirects: false
  - name: local-append-only-evidence
    webhook_configs:
      - url: http://127.0.0.1:19094/v1/alerts
        send_resolved: true
        max_alerts: 0
        http_config:
          authorization:
            type: Bearer
            credentials_file: /run/secrets/evidence_receiver_bearer
""".encode("ascii")


def _atomic_publish(path: Path, payload: bytes) -> None:
    absolute, parent_fd, parent_identity = open_parent(path)
    temp_name = f".{absolute.name}.{os.getpid()}.{secrets.token_hex(8)}.tmp"
    descriptor = -1
    try:
        try:
            existing = os.stat(absolute.name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            existing = None
        if existing is not None and (
            not stat.S_ISREG(existing.st_mode)
            or existing.st_uid != os.geteuid()
            or existing.st_nlink != 1
            or stat.S_IMODE(existing.st_mode) != 0o600
        ):
            _fail("existing output is not a safe owner-only regular file")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(temp_name, flags, 0o600, dir_fd=parent_fd)
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("short output write")
            view = view[written:]
        os.fsync(descriptor)
        metadata = os.fstat(descriptor)
        if (
            metadata.st_uid != os.geteuid()
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != 0o600
        ):
            _fail("output identity changed before publication")
        os.close(descriptor)
        descriptor = -1
        require_parent_stable(parent_fd, absolute.parent, parent_identity)
        os.replace(temp_name, absolute.name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
        os.fsync(parent_fd)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            os.unlink(temp_name, dir_fd=parent_fd)
        except FileNotFoundError:
            pass
        os.close(parent_fd)


def _descriptor(value: Any, path: Path, label: str) -> None:
    descriptor = _exact_object(value, DESCRIPTOR_KEYS, label)
    basename = _bounded_string(descriptor["basename"], EVIDENCE_NAME_RE, f"{label} basename")
    wanted = _bounded_string(descriptor["sha256"], SHA256_RE, f"{label} SHA-256")
    if path.name != basename:
        _fail(f"{label} basename differs from the bound evidence")
    raw = read_secret_file(path, maximum=MAX_BOUND_EVIDENCE_BYTES)
    if hashlib.sha256(raw).hexdigest() != wanted:
        _fail(f"{label} SHA-256 differs from the bound evidence")


def verify_external_delivery(
    receipt: Mapping[str, Any],
    delivery_config: Mapping[str, Any],
    evidence_paths: Mapping[str, Path],
    *,
    release: str,
    vcs_ref: str,
    deployment_id: str,
    controlled_nonce: str,
    now: datetime,
) -> datetime:
    _exact_object(receipt, DELIVERY_RECEIPT_KEYS, "external delivery receipt")
    if receipt["format_version"] != FORMAT_VERSION or receipt["kind"] != DELIVERY_KIND:
        _fail("external delivery receipt kind or version is invalid")
    _validate_identity(receipt, release, vcs_ref, deployment_id)
    receiver_id, _ = validate_delivery_config(delivery_config)
    if receipt["receiver_id"] != receiver_id:
        _fail("external delivery receiver differs from the admitted config")
    _bounded_string(controlled_nonce, NONCE_RE, "controlled nonce")
    if receipt["controlled_nonce"] != controlled_nonce:
        _fail("external delivery receipt has the wrong controlled nonce")
    _bounded_string(receipt["fingerprint"], FINGERPRINT_RE, "alert fingerprint")
    _bounded_string(receipt["operator_receipt_id"], RECEIPT_ID_RE, "operator receipt id")
    evidence = _exact_object(receipt["evidence"], DELIVERY_EVIDENCE_KEYS, "delivery evidence")
    if set(evidence_paths) != DELIVERY_EVIDENCE_KEYS:
        _fail("all external delivery evidence files are required")
    for name in sorted(DELIVERY_EVIDENCE_KEYS):
        _descriptor(evidence[name], evidence_paths[name], f"delivery {name}")
    firing_started = _timestamp(receipt["firing_started_at"], "firing start")
    firing_received = _timestamp(receipt["firing_received_at"], "firing receipt")
    resolved_at = _timestamp(receipt["resolved_at"], "resolution")
    resolved_received = _timestamp(receipt["resolved_received_at"], "resolved receipt")
    acknowledged = _timestamp(receipt["operator_acknowledged_at"], "operator acknowledgement")
    verified = _timestamp(receipt["verified_at"], "delivery verification")
    if not (
        firing_started < firing_received < resolved_at <= resolved_received <= verified
        and firing_received <= acknowledged <= verified
    ):
        _fail("external delivery timing is not a valid firing/resolved/operator sequence")
    if verified > now + FUTURE_SKEW or now - verified > MAX_DELIVERY_RECEIPT_AGE:
        _fail("external delivery receipt is stale or future-dated")
    return verified


def _validate_release_gate(value: Any, now: datetime) -> datetime:
    gate = _exact_object(value, RELEASE_GATE_KEYS, "release gate snapshot")
    observed = _timestamp(gate["observed_at"], "release gate observation")
    signals = gate["signals"]
    if not isinstance(signals, dict) or set(signals) != REQUIRED_RELEASE_GATE_SIGNALS:
        _fail("release gate signal inventory is incomplete or unknown")
    if any(item is not True for item in signals.values()):
        _fail("every required release gate signal must be present and healthy")
    for field in (
        "pending_release_gate_alerts",
        "firing_release_gate_alerts",
        "unexplained_container_restarts",
    ):
        if _nonnegative_int(gate[field], field) != 0:
            _fail(f"{field} must be zero")
    _true(gate["resource_headroom_ok"], "resource headroom")
    if observed > now + FUTURE_SKEW or now - observed > MAX_GATE_SNAPSHOT_AGE:
        _fail("release gate snapshot is stale or future-dated")
    return observed


def _validate_stability(
    value: Any, deployed_at: datetime, now: datetime, minimum_seconds: int
) -> Tuple[datetime, datetime]:
    stability = _exact_object(value, STABILITY_KEYS, "stability window")
    started = _timestamp(stability["started_at"], "stability start")
    ended = _timestamp(stability["ended_at"], "stability end")
    if not deployed_at <= started < ended:
        _fail("stability window is not ordered after deployment")
    if (ended - started).total_seconds() < minimum_seconds:
        _fail("stability window is shorter than the admitted minimum")
    if ended > now + FUTURE_SKEW:
        _fail("stability window end is future-dated")
    _true(stability["session_renewal_ok"], "stability session renewal")
    _true(stability["connector_reconnect_ok"], "stability Connector reconnect")
    if _nonnegative_int(stability["scheduled_monitoring_cycles"], "monitoring cycles") < 2:
        _fail("stability window requires at least two scheduled monitoring cycles")
    if _nonnegative_int(stability["scheduled_backup_cycles"], "backup cycles") < 1:
        _fail("stability window requires at least one scheduled backup cycle")
    if _nonnegative_int(stability["unresolved_p0_p1"], "unresolved P0/P1") != 0:
        _fail("stability window has unresolved P0/P1 incidents")
    return started, ended


def verify_release_observability(
    receipt: Mapping[str, Any],
    external_receipt: Mapping[str, Any],
    delivery_config: Mapping[str, Any],
    paths: Mapping[str, Path],
    *,
    release: str,
    vcs_ref: str,
    deployment_id: str,
    controlled_nonce: str,
    now: datetime,
    minimum_stability_seconds: int = DEFAULT_MINIMUM_STABILITY_SECONDS,
) -> bytes:
    _exact_object(receipt, RELEASE_RECEIPT_KEYS, "release observability receipt")
    if receipt["format_version"] != FORMAT_VERSION or receipt["kind"] != RELEASE_KIND:
        _fail("release observability receipt kind or version is invalid")
    _validate_identity(receipt, release, vcs_ref, deployment_id)
    if minimum_stability_seconds < 3600:
        _fail("minimum stability window cannot be shorter than one hour")
    deployed = _timestamp(receipt["deployed_at"], "deployment time")
    verified = _timestamp(receipt["verified_at"], "release verification")
    if deployed >= verified:
        _fail("release verification must follow deployment")
    if verified > now + FUTURE_SKEW or now - verified > MAX_RECEIPT_AGE:
        _fail("release observability receipt is stale or future-dated")
    external_verified = verify_external_delivery(
        external_receipt,
        delivery_config,
        {
            "firing": paths["firing"],
            "resolved": paths["resolved"],
            "operator_ack": paths["operator_ack"],
        },
        release=release,
        vcs_ref=vcs_ref,
        deployment_id=deployment_id,
        controlled_nonce=controlled_nonce,
        now=now,
    )
    if external_verified <= deployed:
        _fail("external delivery evidence predates this deployment")
    _descriptor(
        receipt["external_delivery"],
        paths["external_delivery_receipt"],
        "external delivery receipt",
    )
    observed = _validate_release_gate(receipt["release_gate_snapshot"], now)
    _, stability_end = _validate_stability(
        receipt["stability_window"], deployed, now, minimum_stability_seconds
    )
    backup = _exact_object(
        receipt["post_release_backup"], POST_RELEASE_BACKUP_KEYS, "post-release backup"
    )
    completed = _timestamp(backup["completed_at"], "post-release backup completion")
    _true(backup["checksum_verified"], "post-release backup checksum")
    _descriptor(backup["backup_receipt"], paths["backup_receipt"], "backup receipt")
    _descriptor(backup["restore_receipt"], paths["restore_receipt"], "restore receipt")
    if not deployed < completed <= verified:
        _fail("post-release backup did not complete after this deployment")
    if completed > now + FUTURE_SKEW or now - completed > MAX_POST_RELEASE_BACKUP_AGE:
        _fail("post-release backup is stale or future-dated")
    if max(external_verified, observed, stability_end, completed) > verified:
        _fail("release receipt was verified before its required evidence")
    timestamp = int(verified.timestamp())
    external_timestamp = int(external_verified.timestamp())
    gate_timestamp = int(observed.timestamp())
    stability_timestamp = int(stability_end.timestamp())
    backup_timestamp = int(completed.timestamp())
    lines = [
        "# HELP codex_control_release_observability_identity Exact admitted release receipt identity.",
        "# TYPE codex_control_release_observability_identity gauge",
        (
            "codex_control_release_observability_identity"
            f'{{version="{release}",vcs_ref="{vcs_ref}"}} 1'
        ),
        "codex_control_external_operator_delivery_verified 1",
        f"codex_control_external_operator_delivery_verified_timestamp_seconds {external_timestamp}",
        "codex_control_release_gate_snapshot_ok 1",
        f"codex_control_release_gate_snapshot_timestamp_seconds {gate_timestamp}",
        "codex_control_production_stability_window_ok 1",
        f"codex_control_production_stability_window_end_timestamp_seconds {stability_timestamp}",
        "codex_control_post_release_backup_verified 1",
        f"codex_control_post_release_backup_verified_timestamp_seconds {backup_timestamp}",
        "codex_control_release_observability_receipt_current 1",
        f"codex_control_release_observability_verified_timestamp_seconds {timestamp}",
        "",
    ]
    return "\n".join(lines).encode("ascii")


def main() -> None:
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    render = commands.add_parser("render-alertmanager")
    render.add_argument("--delivery-config", type=Path, required=True)
    render.add_argument("--output", type=Path, required=True)
    verify_config = commands.add_parser("verify-alertmanager")
    verify_config.add_argument("--delivery-config", type=Path, required=True)
    verify_config.add_argument("--alertmanager-config", type=Path, required=True)
    admit = commands.add_parser("admit-release")
    admit.add_argument("--receipt", type=Path, required=True)
    admit.add_argument("--external-delivery-receipt", type=Path, required=True)
    admit.add_argument("--delivery-config", type=Path, required=True)
    admit.add_argument("--firing-receipt", type=Path, required=True)
    admit.add_argument("--resolved-receipt", type=Path, required=True)
    admit.add_argument("--operator-ack-receipt", type=Path, required=True)
    admit.add_argument("--backup-receipt", type=Path, required=True)
    admit.add_argument("--restore-receipt", type=Path, required=True)
    admit.add_argument("--release", required=True)
    admit.add_argument("--vcs-ref", required=True)
    admit.add_argument("--deployment-id", required=True)
    admit.add_argument("--controlled-nonce", required=True)
    admit.add_argument(
        "--minimum-stability-seconds",
        type=int,
        default=DEFAULT_MINIMUM_STABILITY_SECONDS,
    )
    admit.add_argument("--now", help=argparse.SUPPRESS)
    admit.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    delivery_config = _load_json(arguments.delivery_config)
    if arguments.command == "render-alertmanager":
        _atomic_publish(arguments.output, render_alertmanager(delivery_config))
        return
    if arguments.command == "verify-alertmanager":
        actual = read_secret_file(arguments.alertmanager_config, maximum=64 * 1024)
        if actual != render_alertmanager(delivery_config):
            _fail("Alertmanager config differs from the admitted external delivery contract")
        return
    external_path = arguments.external_delivery_receipt
    external_receipt = _load_json(external_path)
    receipt = _load_json(arguments.receipt)
    payload = verify_release_observability(
        receipt,
        external_receipt,
        delivery_config,
        {
            "external_delivery_receipt": external_path,
            "firing": arguments.firing_receipt,
            "resolved": arguments.resolved_receipt,
            "operator_ack": arguments.operator_ack_receipt,
            "backup_receipt": arguments.backup_receipt,
            "restore_receipt": arguments.restore_receipt,
        },
        release=arguments.release,
        vcs_ref=arguments.vcs_ref,
        deployment_id=arguments.deployment_id,
        controlled_nonce=arguments.controlled_nonce,
        now=_now(arguments.now),
        minimum_stability_seconds=arguments.minimum_stability_seconds,
    )
    _atomic_publish(arguments.output, payload)


if __name__ == "__main__":
    main()
