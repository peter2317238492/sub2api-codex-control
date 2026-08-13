from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from production_connector_canary import (
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
        "/Users/private/workspace",
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
