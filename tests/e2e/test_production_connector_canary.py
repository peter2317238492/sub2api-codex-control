from __future__ import annotations

import copy
import hashlib
import json
import os
import shlex
import signal
import subprocess
import sys
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

import production_connector_canary as canary
import pytest
from production_connector_canary import (
    CANARY_CONNECTOR_BINARY_VERSION,
    CODEX_VERSION,
    CONNECTOR_VERSION,
    ApprovalTriggerUnavailable,
    CanaryEvidence,
    ProductionCanary,
    _remove_private_run_directory,
    _write_connector_config,
    build_connector_argv,
    build_connector_environment,
    choose_dynamic_model,
    create_private_run_directory,
    open_frozen_file,
    read_auth_material_fd,
    read_pairing_code,
    read_spool_records,
    snapshot_protected_files,
    wait_for_replayed_record_ack,
    write_redacted_evidence,
)
from smoke import Result


def test_canary_versions_match_the_release_contract() -> None:
    root = Path(__file__).resolve().parents[2]
    config = json.loads((root / "connector/release/release-config.json").read_text())
    assert CONNECTOR_VERSION == config["connector_version"]
    assert (
        CANARY_CONNECTOR_BINARY_VERSION
        == config["connector_version"] + "+productioncanary"
    )
    assert CODEX_VERSION == config["codex_version"]


def test_command_approval_only_allows_the_exact_marker_command(tmp_path: Path) -> None:
    target = tmp_path / "space in marker.txt"
    command = f"printf approved > {shlex.quote(str(target))}"
    assert canary._is_marker_command(command, target)
    assert canary._is_marker_command(["/bin/sh", "-c", command], target)
    assert canary._is_marker_command("/bin/zsh -lc " + shlex.quote(command), target)
    for unexpected in (
        command + "; printf unexpected > /outside",
        command + "\nprintf unexpected",
        command.replace("approved", "$(printf approved)"),
        command.replace("approved", "`printf approved`"),
        command.replace(str(target), "/outside"),
        ["/usr/bin/env", "sh", command],
        [{}, "-c", command],
        None,
    ):
        assert not canary._is_marker_command(unexpected, target)


def test_approval_binding_rejects_other_turns_commands_items_and_expiry(
    tmp_path: Path,
) -> None:
    target = tmp_path / "marker"
    record = {
        "approval_id": "outer",
        "device_id": "device",
        "kind": "command",
        "expires_at": (datetime.now(UTC) + timedelta(minutes=1)).isoformat(),
        "details": {
            "threadId": "native-thread",
            "turnId": "native-turn",
            "itemId": "item",
            "cwd": str(tmp_path),
            "command": f"printf approved > {shlex.quote(str(target))}",
        },
    }
    arguments = dict(
        device_id="device",
        thread_id="native-thread",
        turn_id="native-turn",
        kind="command",
        workspace=tmp_path,
        target=target,
    )
    assert canary._approval_is_bound(record, copy.deepcopy(record), **arguments)
    for field, value in (
        ("turnId", "previous-turn"),
        ("itemId", "other-item"),
        ("cwd", "/outside"),
        ("command", record["details"]["command"] + "; printf other"),
    ):
        changed = copy.deepcopy(record)
        changed["details"][field] = value
        assert not canary._approval_is_bound(record, changed, **arguments)
    expired = copy.deepcopy(record)
    expired["expires_at"] = (datetime.now(UTC) - timedelta(seconds=1)).isoformat()
    assert not canary._approval_is_bound(expired, expired, **arguments)
    missing = copy.deepcopy(record)
    del missing["details"]["command"]
    assert not canary._approval_is_bound(missing, missing, **arguments)


def test_portable_process_cleanup_leaves_an_unrelated_process_running() -> None:
    child_code = "import time; time.sleep(20)"
    parent_code = f"import subprocess,sys,time; subprocess.Popen([sys.executable,'-c',{child_code!r}]); time.sleep(20)"
    unrelated = subprocess.Popen(
        [sys.executable, "-c", child_code], start_new_session=True
    )
    process = canary.CanaryProcess(
        [sys.executable, "-c", parent_code], start_new_session=True
    )
    try:
        deadline = time.monotonic() + 5
        descendants = set()
        while not descendants and time.monotonic() < deadline:
            descendants = canary._descendant_processes(process)
            time.sleep(0.02)
        assert descendants
        assert unrelated.pid not in {item.pid for item in descendants}
        assert canary._stop_process(process)
        assert unrelated.poll() is None
        assert not any(item.is_running() for item in descendants)
    finally:
        canary._cleanup_canary_processes()
        unrelated.terminate()
        unrelated.wait(timeout=5)


def test_negative_approvals_are_bound_to_the_actual_requested_target(
    tmp_path: Path,
) -> None:
    target = tmp_path / "marker"
    record = {
        "approval_id": "outer",
        "device_id": "device",
        "kind": "command",
        "expires_at": (datetime.now(UTC) + timedelta(minutes=1)).isoformat(),
        "details": {
            "threadId": "native-thread",
            "turnId": "native-turn",
            "itemId": "item",
            "cwd": str(tmp_path),
        },
    }
    arguments = dict(
        device_id="device",
        thread_id="native-thread",
        turn_id="native-turn",
        workspace=tmp_path,
        target=target,
    )
    record["details"]["command"] = f"printf timeout > {shlex.quote(str(target))}"
    assert canary._approval_is_bound(
        record, record, kind="command", command_value="timeout", **arguments
    )
    record["details"]["command"] = "printf timeout > /outside"
    assert not canary._approval_is_bound(
        record, record, kind="command", command_value="timeout", **arguments
    )
    record["kind"] = "file_change"
    record["details"]["fileChanges"] = {str(target): {"type": "add"}}
    assert canary._approval_is_bound(record, record, kind="file_change", **arguments)
    record["details"]["fileChanges"] = {"/outside": {"type": "add"}}
    assert not canary._approval_is_bound(
        record, record, kind="file_change", **arguments
    )
    record["kind"] = "permission"
    record["details"]["permissions"] = {"fileSystem": {"read": [str(tmp_path)]}}
    assert canary._approval_is_bound(record, record, kind="permission", **arguments)
    for permissions in (
        {"fileSystem": {"read": ["/outside"]}},
        {"fileSystem": {"write": [str(tmp_path)]}},
        {"fileSystem": {"read": [str(tmp_path)]}, "network": {"enabled": True}},
        {},
    ):
        record["details"]["permissions"] = permissions
        assert not canary._approval_is_bound(
            record, record, kind="permission", **arguments
        )


def test_process_identity_is_rechecked_before_sigkill(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Process:
        pid = 12345
        running = True
        signals = []

        def is_running(self):
            return self.running

        def send_signal(self, sig):
            self.signals.append(sig)
            self.running = False

    process = Process()
    monkeypatch.setattr(canary, "_process_session", lambda pid: 99)
    monkeypatch.setattr(
        canary.psutil, "wait_procs", lambda processes, timeout: ([], processes)
    )
    assert canary._terminate_owned_processes({process}, owner_session=99)
    assert process.signals == [signal.SIGTERM]


def test_child_spawned_during_shutdown_is_collected(tmp_path: Path) -> None:
    marker = tmp_path / "late-child.json"
    code = (
        "import signal,subprocess,sys,time,json,psutil\n"
        "def stop(*args):\n"
        " p=subprocess.Popen([sys.executable,'-c','import time; time.sleep(20)'])\n"
        f" open({str(marker)!r},'w').write(json.dumps([p.pid,psutil.Process(p.pid).create_time()]))\n"
        " raise SystemExit(0)\n"
        "signal.signal(signal.SIGTERM,stop)\n"
        "print('ready',flush=True)\n"
        "time.sleep(20)\n"
    )
    process = canary.CanaryProcess(
        [sys.executable, "-c", code], start_new_session=True, stdout=subprocess.PIPE
    )
    try:
        assert process.stdout.readline() == b"ready\n"
        assert canary._stop_process(process)
        pid, created = json.loads(marker.read_text())
        try:
            assert canary.psutil.Process(pid).create_time() != created
        except canary.psutil.NoSuchProcess:
            pass
    finally:
        if marker.exists():
            pid, created = json.loads(marker.read_text())
            try:
                child = canary.psutil.Process(pid)
                if child.create_time() == created:
                    child.kill()
            except canary.psutil.NoSuchProcess:
                pass
        canary._cleanup_canary_processes()


def test_approval_scenarios_do_not_consume_a_terminal_event_twice(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class Client:
        browser_event_cursors = []
        evidence = CanaryEvidence()

        def __init__(self):
            self.count = 0
            self.seen = set()

        def pending_approval_ids(self, *args):
            return set()

        def request(self, *args, **kwargs):
            return None

        def accepted_command(self, *args):
            self.count += 1
            return str(self.count)

        def command_event(self, stream, command, method, description):
            assert command not in self.seen
            self.seen.add(command)
            return {"state": "succeeded", "result": {"turn": {"id": "turn-" + command}}}

        def wait_browser_event(self, stream, description, predicate, **kwargs):
            raise AssertionError("timed out waiting for " + description)

    client = Client()
    monkeypatch.setattr(canary, "_wait_thread_idle", lambda *args: None)
    assert not canary._verify_real_approvals(
        client=client,
        browser_stream=object(),
        device_id="device",
        thread_id="thread",
        remote_thread_id="native",
        workspace=tmp_path,
        mutating_headers={},
    )
    assert len(client.seen) == 4


def test_expired_primary_budget_blocks_work_but_allows_logout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = ProductionCanary("https://control.invalid", CanaryEvidence())
    client._run_deadline = time.monotonic() - 1
    calls = []
    monkeypatch.setattr(
        canary.Smoke,
        "request",
        lambda self, path, **kwargs: calls.append(path) or Result(204, {}, b""),
    )
    with pytest.raises(AssertionError, match="budget is exhausted"):
        client.request("/codex-api/v1/devices")
    assert calls == []
    assert client.request("/codex-api/v1/session/logout", method="POST").status == 204


def test_codex_home_mismatch_is_rejected_before_launch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        canary,
        "build_connector_environment",
        lambda source: {"CODEX_HOME": str(tmp_path / "actual")},
    )
    with pytest.raises(ValueError, match="effective child"):
        canary._validate_codex_home(tmp_path / "other")


def test_privileged_action_uses_and_closes_an_independent_fresh_session(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = ProductionCanary("https://control.invalid", CanaryEvidence())
    client._reauth_access_token = "fixture-access"
    client._reauth_user_id = "fixture-user"
    old_headers = {"Origin": client.origin, "x-csrf-token": "old"}
    client.session_mutating_headers = old_headers
    exchanges, requests = [], []

    def exchange(temporary, token, user):
        assert temporary is not client
        assert (token, user) == ("fixture-access", "fixture-user")
        temporary.session_mutating_headers = {
            "Origin": client.origin,
            "x-csrf-token": "fresh",
        }
        exchanges.append(temporary)
        return temporary.session_mutating_headers

    def request(temporary, path, **kwargs):
        requests.append((path, kwargs["headers"].copy()))
        return Result(204, {}, b"")

    monkeypatch.setattr(canary, "_exchange_control_session", exchange)
    monkeypatch.setattr(ProductionCanary, "request", request)
    path = "/codex-api/v1/devices/00000000-0000-4000-8000-000000000001"
    assert client.privileged_request(path, method="DELETE").status == 204
    assert len(exchanges) == 1
    assert [item[0] for item in requests] == [path, "/codex-api/v1/session/logout"]
    assert all(item[1]["x-csrf-token"] == "fresh" for item in requests)
    assert client.session_mutating_headers is old_headers
    canary._clear_control_client(client)
    assert client._reauth_access_token == ""


def test_privileged_session_cleanup_failure_is_not_hidden(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = ProductionCanary("https://control.invalid", CanaryEvidence())
    client._reauth_access_token = "fixture-access"
    client._reauth_user_id = "fixture-user"

    def exchange(temporary, token, user):
        temporary.session_mutating_headers = {"x-csrf-token": "fresh"}
        return temporary.session_mutating_headers

    monkeypatch.setattr(canary, "_exchange_control_session", exchange)
    monkeypatch.setattr(
        ProductionCanary,
        "request",
        lambda self, path, **kwargs: Result(
            500 if path.endswith("logout") else 204, {}, b""
        ),
    )
    with pytest.raises(AssertionError, match="session cleanup failed"):
        client.privileged_request(
            "/codex-api/v1/devices/00000000-0000-4000-8000-000000000001",
            method="DELETE",
        )
    assert client.evidence.cleanup["privileged_sessions"] is False


def test_generic_reconnect_metrics_cannot_prove_credential_rejection(
    tmp_path: Path,
) -> None:
    private_json(tmp_path / "connector-metrics.json", {"reconnects": [100, 0, 0, 0]})
    assert canary._read_credential_rejection(tmp_path) is None
    marker = private_json(
        tmp_path / "production-canary-credential-rejected.json",
        {"credential_rejected": True, "version": 1},
    )
    assert canary._read_credential_rejection(tmp_path) is True
    private_json(marker, {"credential_rejected": 1, "version": True})
    with pytest.raises(ValueError, match="invalid"):
        canary._read_credential_rejection(tmp_path)


def test_evidence_collision_cannot_return_success(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    auth_path = private_json(
        tmp_path / "auth.json",
        {
            "username": "fixture@example.invalid",
            "password": "fixture-password",
            "OPENAI_API_KEY": "unused-fixture-provider",
        },
    )
    binary = tmp_path / "binary"
    binary.write_bytes(b"frozen binary fixture")
    binary.chmod(0o700)
    home = tmp_path / "codex-home"
    home.mkdir(mode=0o700)
    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir(mode=0o700)
    old = CanaryEvidence()
    old.finish("passed")
    evidence_path = write_redacted_evidence(evidence_dir, old)
    before = evidence_path.read_bytes()
    monkeypatch.setattr(canary, "_verify_binary_version", lambda *args: None)
    monkeypatch.setattr(canary, "_validate_codex_home", lambda path: None)
    monkeypatch.setattr(
        canary, "_login_to_sub2api", lambda *args: ("fixture-access", "fixture-user")
    )
    monkeypatch.setattr(
        canary,
        "_session_exchange",
        lambda *args: ({"x-csrf-token": "fixture"}, object()),
    )
    monkeypatch.setattr(
        ProductionCanary, "request", lambda *args, **kwargs: Result(204, {}, b"")
    )

    def flow(**kwargs):
        evidence = kwargs["client"].evidence
        evidence.approvals = {"verified": True}
        evidence.cleanup.update({key: True for key in evidence.cleanup})

    monkeypatch.setattr(canary, "_run_control_flow", flow)
    publications = []
    original_publish = canary.write_redacted_evidence

    def publish(directory, evidence):
        publications.append(evidence.outcome)
        return original_publish(directory, evidence)

    monkeypatch.setattr(canary, "write_redacted_evidence", publish)
    digest = hashlib.sha256(binary.read_bytes()).hexdigest()
    result = canary.main(
        [
            "--base-url",
            "https://control.invalid",
            "--auth-fd",
            str(auth_fd(auth_path)),
            "--connector-binary",
            str(binary),
            "--expected-connector-sha256",
            digest,
            "--codex-binary",
            str(binary),
            "--expected-codex-sha256",
            digest,
            "--codex-home",
            str(home),
            "--private-run-dir",
            str(tmp_path / "run"),
            "--evidence-dir",
            str(evidence_dir),
            "--confirm-real-production-canary",
        ]
    )
    assert result == 1
    assert publications == ["passed"]
    assert evidence_path.read_bytes() == before


def private_json(path: Path, value: object) -> Path:
    path.write_text(json.dumps(value), encoding="utf-8")
    path.chmod(0o600)
    return path


def auth_fd(path: Path) -> int:
    return os.open(path, os.O_RDONLY)


def test_auth_material_uses_private_fd_discards_provider_and_redacts_repr(
    tmp_path: Path,
) -> None:
    path = private_json(
        tmp_path / "auth.json",
        {
            "username": "private-user@example.invalid",
            "password": "private-password",
            "OPENAI_API_KEY": "provider-value-never-retained",
        },
    )
    descriptor = auth_fd(path)
    try:
        material = read_auth_material_fd(descriptor)
    finally:
        os.close(descriptor)

    assert material.username == "private-user@example.invalid"
    assert material.password == "private-password"
    assert not hasattr(material, "provider_key")
    encoded = repr(material) + repr(material.__dict__)
    assert "private-user" not in repr(material)
    assert "private-password" not in repr(material)
    assert "provider-value-never-retained" not in encoded
    material.clear()
    assert material.username == ""
    assert material.password == ""

    path.chmod(0o644)
    descriptor = auth_fd(path)
    try:
        with pytest.raises(ValueError, match="owned 0600 regular file"):
            read_auth_material_fd(descriptor)
    finally:
        os.close(descriptor)


def test_auth_and_pairing_files_reject_unknown_or_unsafe_values(
    tmp_path: Path,
) -> None:
    auth = private_json(
        tmp_path / "auth.json",
        {"username": "u@example.invalid", "password": "p", "extra": "secret"},
    )
    descriptor = auth_fd(auth)
    try:
        with pytest.raises(ValueError, match="unexpected schema"):
            read_auth_material_fd(descriptor)
    finally:
        os.close(descriptor)

    pairing = private_json(
        tmp_path / "pairing-code.json",
        {"code": "ABCD-EFGH-JKLM-NPQR", "expires_at": "2026-08-13T12:00:00Z"},
    )
    assert read_pairing_code(pairing) == "ABCD-EFGH-JKLM-NPQR"

    private_json(
        pairing,
        {"code": "not a code", "expires_at": "2026-08-13T12:00:00Z"},
    )
    with pytest.raises(ValueError, match="invalid pairing code"):
        read_pairing_code(pairing)


def test_connector_process_receives_no_remote_auth_material() -> None:
    secrets = {
        "SUB2API_ACCESS_TOKEN": "access-secret",
        "SUB2API_EXPECTED_USER_ID": "user-secret",
        "SUB2API_PASSWORD": "password-secret",
        "OPENAI_API_KEY": "provider-secret",
    }
    inherited = {"PATH": "/usr/bin", "HOME": "/private/home", **secrets}

    argv = build_connector_argv(Path("/opt/canary/connector"), Path("/tmp/config"))
    environment = build_connector_environment(inherited)
    encoded = json.dumps({"argv": argv, "environment": environment})

    assert argv == ["/opt/canary/connector", "-config", "/tmp/config"]
    for key, value in secrets.items():
        assert key not in environment
        assert value not in encoded


def test_http_client_explicitly_disables_proxies(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "urllib.request.getproxies",
        lambda: {"https": "http://secret.invalid:3128"},
    )
    client = ProductionCanary("https://control.example.invalid", CanaryEvidence())

    assert client.proxy_policy == "disabled"
    assert not any(
        handler.__class__.__name__ == "ProxyHandler"
        for handler in client.opener.handlers
    )


def test_pending_approval_is_bound_to_canary_device_and_new_identity() -> None:
    client = ProductionCanary("https://control.example.invalid", CanaryEvidence())
    client.eventually = lambda _description, probe, **_kwargs: probe()  # type: ignore[method-assign]
    client.request = lambda *_args, **_kwargs: Result(  # type: ignore[method-assign]
        200,
        {},  # type: ignore[arg-type]
        json.dumps(
            {
                "items": [
                    {
                        "approval_id": "old-canary",
                        "device_id": "canary-device",
                        "kind": "command",
                        "details": {"threadId": "remote-thread"},
                    },
                    {
                        "approval_id": "other-device",
                        "device_id": "unrelated-device",
                        "kind": "command",
                        "details": {"threadId": "remote-thread"},
                    },
                    {
                        "approval_id": "other-thread",
                        "device_id": "canary-device",
                        "kind": "command",
                        "details": {"threadId": "unrelated-thread"},
                    },
                    {
                        "approval_id": "new-canary",
                        "device_id": "canary-device",
                        "kind": "command",
                        "details": {"threadId": "remote-thread"},
                    },
                ]
            }
        ).encode(),
    )

    selected = client.unique_pending_approval(
        "command",
        "canary-device",
        "remote-thread",
        {"old-canary", "other-device", "other-thread"},
        "new-canary",
    )

    assert selected["approval_id"] == "new-canary"


def test_pending_approval_rejects_ambiguous_new_diff() -> None:
    client = ProductionCanary("https://control.example.invalid", CanaryEvidence())
    client.eventually = lambda _description, probe, **_kwargs: probe()  # type: ignore[method-assign]
    items = [
        {
            "approval_id": approval_id,
            "device_id": "canary-device",
            "kind": "permission",
            "details": {"threadId": "remote-thread"},
        }
        for approval_id in ("new-one", "new-two")
    ]
    client.request = lambda *_args, **_kwargs: Result(  # type: ignore[method-assign]
        200,
        {},
        json.dumps({"items": items}).encode(),  # type: ignore[arg-type]
    )

    with pytest.raises(ApprovalTriggerUnavailable, match="more than one"):
        client.unique_pending_approval(
            "permission",
            "canary-device",
            "remote-thread",
            set(),
            "new-one",
        )


def test_dynamic_model_selection_never_assumes_fixture_id() -> None:
    catalog = {
        "items": [
            {"id": "current-production-model", "display_name": "Current"},
            {"id": "fallback-production-model", "display_name": "Fallback"},
        ]
    }

    assert choose_dynamic_model(catalog) == "current-production-model"
    assert choose_dynamic_model({"items": []}) is None
    assert choose_dynamic_model({"items": [{"id": ""}]}) is None


class FakeBrowserStream:
    def __init__(self, events: list[dict[str, object]]) -> None:
        self.events = [json.dumps(event) for event in events]

    def receive_text(self, _timeout: float) -> str | None:
        if not self.events:
            raise TimeoutError
        return self.events.pop(0)


def command_event(cursor: int, command_id: str, method: str) -> dict[str, object]:
    return {
        "cursor": str(cursor),
        "type": "command.updated",
        "data": {
            "command": {
                "id": command_id,
                "method": method,
                "state": "succeeded",
            }
        },
    }


def test_browser_backlog_preserves_interleaved_command_terminals() -> None:
    client = ProductionCanary("https://control.example.invalid", CanaryEvidence())
    stream = FakeBrowserStream(
        [
            command_event(1, "turn-start", "turn/start"),
            command_event(2, "turn-steer", "turn/steer"),
        ]
    )

    client.command_event(
        stream,  # type: ignore[arg-type]
        "turn-steer",
        "turn/steer",
        "steer terminal",
    )
    client.command_event(
        stream,  # type: ignore[arg-type]
        "turn-start",
        "turn/start",
        "start terminal retained in backlog",
    )

    assert client.browser_event_cursors == [1, 2]
    assert client.evidence.rpc_methods == ["turn/steer", "turn/start"]


def test_frozen_file_detects_named_identity_replacement(tmp_path: Path) -> None:
    binary = tmp_path / "connector"
    binary.write_bytes(b"original")
    binary.chmod(0o700)
    frozen = open_frozen_file(binary, "test binary", require_executable=True)
    replacement = tmp_path / "replacement"
    replacement.write_bytes(b"replacement")
    replacement.chmod(0o700)
    replacement.replace(binary)
    try:
        with pytest.raises(ValueError, match="identity changed"):
            frozen.verify("test binary")
    finally:
        frozen.close()


def test_spool_ack_replay_binds_sequence_event_and_command(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = tmp_path / "state"
    spool = state / "spool"
    spool.mkdir(parents=True, mode=0o700)
    private_json(
        spool / "meta.json",
        {
            "version": 1,
            "next_sequence": 3,
            "last_acked": 1,
            "last_received": 4,
        },
    )
    private_json(
        spool / "00000000000000000002.json",
        {
            "version": 1,
            "id": "event-id",
            "device_id": "device-id",
            "epoch": "epoch-identity-value",
            "seq": 2,
            "ack": 4,
            "type": "command_ack",
            "sent_at": "2026-08-13T00:00:00Z",
            "payload": {"command_id": "command-id", "state": "completed"},
        },
    )
    assert read_spool_records(state)[2] == (
        "event-id",
        "command_ack",
        "command-id",
    )

    calls = iter(
        [
            (3, 1, 4),
            (3, 2, 5),
        ]
    )
    monkeypatch.setattr(
        "production_connector_canary.read_spool_meta", lambda _state: next(calls)
    )
    records = iter(
        [
            {2: ("event-id", "command_ack", "command-id")},
            {},
        ]
    )
    monkeypatch.setattr(
        "production_connector_canary.read_spool_records", lambda _state: next(records)
    )
    monkeypatch.setattr("production_connector_canary.time.sleep", lambda _seconds: None)

    assert wait_for_replayed_record_ack(
        state,
        2,
        "event-id",
        "command-id",
        timeout=1,
    ) == (3, 2, 5)


def test_evidence_writer_is_no_replace_private_and_redacted(tmp_path: Path) -> None:
    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir(mode=0o700)
    evidence = CanaryEvidence()
    evidence.mark("pair_claim")
    evidence.approvals_blocked("permission_not_deterministic")
    evidence.finish("externally_blocked")
    forbidden = (
        "private-user@example.invalid",
        "private-password",
        "provider-value-never-retained",
        "access-token",
        "ABCD-EFGH-JKLM-NPQR",
        "device-uuid",
        "thread-uuid",
        "/Users/example/private-workspace",
        "https://private.example.invalid",
    )

    destination = write_redacted_evidence(evidence_dir, evidence)
    content = destination.read_text(encoding="utf-8")
    parsed = json.loads(content)

    assert destination.stat().st_mode & 0o777 == 0o600
    assert parsed["outcome"] == "externally_blocked"
    assert parsed["approvals"] == {
        "status": "externally_blocked",
        "verified": False,
        "reason": "permission_not_deterministic",
    }
    for value in forbidden:
        assert value not in content
    with pytest.raises(FileExistsError):
        write_redacted_evidence(evidence_dir, evidence)


def test_evidence_writer_rejects_symlink_and_public_directory(tmp_path: Path) -> None:
    public = tmp_path / "public"
    public.mkdir(mode=0o755)
    with pytest.raises(ValueError, match="mode must be exactly 0700"):
        write_redacted_evidence(public, CanaryEvidence())

    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    victim = private / "victim"
    victim.write_text("unchanged", encoding="utf-8")
    (private / "production-connector-canary.json").symlink_to(victim)
    with pytest.raises(FileExistsError):
        write_redacted_evidence(private, CanaryEvidence())
    assert victim.read_text(encoding="utf-8") == "unchanged"


def test_config_writer_is_exclusive_and_run_directory_cleanup_is_complete(
    tmp_path: Path,
) -> None:
    tmp_path.chmod(0o700)
    run_dir = create_private_run_directory(tmp_path / "run")
    state = run_dir / "state"
    workspace = run_dir / "workspace"
    state.mkdir(mode=0o700)
    workspace.mkdir(mode=0o700)
    destination = run_dir / "connector.json"

    _write_connector_config(
        destination,
        origin="https://control.example.invalid",
        state_dir=state,
        workspace=workspace,
        codex_binary=Path("/opt/codex"),
    )

    assert destination.stat().st_mode & 0o777 == 0o600
    with pytest.raises(FileExistsError):
        _write_connector_config(
            destination,
            origin="https://control.example.invalid",
            state_dir=state,
            workspace=workspace,
            codex_binary=Path("/opt/codex"),
        )
    assert _remove_private_run_directory(run_dir)
    assert not run_dir.exists()


def test_protected_snapshot_tracks_metadata_and_does_not_follow_links(
    tmp_path: Path,
) -> None:
    home = tmp_path / "codex"
    home.mkdir(mode=0o700)
    auth = private_json(home / "auth.json", {"token": "value"})
    private_json(home / "config.toml", {"setting": "value"})
    plugins = home / "plugins"
    plugins.mkdir(mode=0o700)
    target = private_json(plugins / "target", {"plugin": True})
    (plugins / "latest").symlink_to(target.name)

    before = snapshot_protected_files(home)
    target.write_text('{"plugin":false}', encoding="utf-8")
    after_content = snapshot_protected_files(home)
    assert before != after_content

    target.write_text('{"plugin":true}', encoding="utf-8")
    auth.chmod(0o400)
    after_metadata = snapshot_protected_files(home)
    assert before != after_metadata


def test_no_secret_environment_is_required(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in (
        "SUB2API_ACCESS_TOKEN",
        "SUB2API_EXPECTED_USER_ID",
        "SUB2API_PASSWORD",
        "OPENAI_API_KEY",
    ):
        monkeypatch.delenv(name, raising=False)
    assert not any(
        name in os.environ
        for name in (
            "SUB2API_ACCESS_TOKEN",
            "SUB2API_EXPECTED_USER_ID",
            "SUB2API_PASSWORD",
            "OPENAI_API_KEY",
        )
    )
