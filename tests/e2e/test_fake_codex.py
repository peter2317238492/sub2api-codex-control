from __future__ import annotations

import json
import os
import pathlib
import stat
import subprocess
import sys
from typing import Any

SCRIPT = pathlib.Path(__file__).with_name("fake_codex.py")


def fake_environment(
    tmp_path: pathlib.Path,
) -> tuple[dict[str, str], pathlib.Path, pathlib.Path]:
    audit = tmp_path / "audit"
    codex_home = tmp_path / "codex-home"
    audit.mkdir()
    codex_home.mkdir()
    provider_key = audit / "provider-key"
    provider_key.write_text("provider-key-canary\n", encoding="utf-8")
    state_file = audit / "thread-state.json"
    environment = {
        **os.environ,
        "CODEX_HOME": str(codex_home),
        "FAKE_CODEX_AUDIT_LOG": str(audit / "methods.log"),
        "FAKE_CODEX_APPROVAL_AUDIT_LOG": str(audit / "approvals.jsonl"),
        "FAKE_CODEX_STATE_FILE": str(state_file),
        "FAKE_SUB2API_PROVIDER_KEY_FILE": str(provider_key),
    }
    return environment, state_file, codex_home


def run_fake(
    environment: dict[str, str], requests: list[dict[str, Any]]
) -> subprocess.CompletedProcess[str]:
    input_text = "".join(json.dumps(request) + "\n" for request in requests)
    return subprocess.run(
        [sys.executable, str(SCRIPT), "app-server", "--listen", "stdio://"],
        input=input_text,
        text=True,
        capture_output=True,
        check=False,
        env=environment,
    )


def responses(
    process: subprocess.CompletedProcess[str],
) -> dict[object, dict[str, Any]]:
    messages = [json.loads(line) for line in process.stdout.splitlines() if line]
    return {message["id"]: message for message in messages if "id" in message}


def request(request_id: int, method: str, params: dict[str, Any]) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "method": method, "params": params}


def test_fake_codex_persists_bounded_thread_state_across_child_restart(
    tmp_path: pathlib.Path,
) -> None:
    environment, state_file, codex_home = fake_environment(tmp_path)
    first = run_fake(
        environment,
        [
            request(1, "initialize", {}),
            request(2, "thread/start", {"cwd": "/workspace"}),
        ],
    )
    assert first.returncode == 0, first.stderr
    first_responses = responses(first)
    assert first_responses[2]["result"]["thread"]["id"] == "e2e-thread-1"
    assert stat.S_IMODE(state_file.stat().st_mode) == 0o600
    assert state_file.stat().st_size <= 1 << 20
    assert not any(codex_home.iterdir())

    second = run_fake(
        environment,
        [
            request(1, "initialize", {}),
            request(2, "thread/list", {}),
            request(3, "thread/read", {"threadId": "e2e-thread-1"}),
            request(4, "thread/resume", {"threadId": "e2e-thread-1"}),
            request(5, "thread/start", {"cwd": "/workspace"}),
        ],
    )
    assert second.returncode == 0, second.stderr
    second_responses = responses(second)
    assert [thread["id"] for thread in second_responses[2]["result"]["data"]] == [
        "e2e-thread-1"
    ]
    assert second_responses[3]["result"]["thread"]["id"] == "e2e-thread-1"
    assert second_responses[4]["result"]["thread"]["id"] == "e2e-thread-1"
    assert second_responses[5]["result"]["thread"]["id"] == "e2e-thread-2"
    state_text = state_file.read_text(encoding="utf-8")
    assert "provider-key-canary" not in state_text
    assert not any(codex_home.iterdir())


def test_fake_codex_emits_frozen_0147_approval_request_shapes(
    tmp_path: pathlib.Path,
) -> None:
    environment, _, _ = fake_environment(tmp_path)
    process = run_fake(
        environment,
        [
            request(1, "initialize", {}),
            request(2, "thread/start", {"cwd": "/workspace"}),
            request(
                3,
                "turn/start",
                {
                    "threadId": "e2e-thread-1",
                    "input": [{"type": "text", "text": "approval fixture"}],
                },
            ),
            {
                "jsonrpc": "2.0",
                "id": "e2e-command-approval-e2e-turn-1",
                "result": {"decision": "accept"},
            },
            {
                "jsonrpc": "2.0",
                "id": "e2e-file_change-approval-e2e-turn-1",
                "result": {"decision": "decline"},
            },
            {
                "jsonrpc": "2.0",
                "id": "e2e-permission-approval-e2e-turn-1",
                "error": {"code": -32001, "message": "approval timed out"},
            },
        ],
    )
    assert process.returncode == 0, process.stderr
    messages = [json.loads(line) for line in process.stdout.splitlines() if line]
    approvals = {
        message["method"]: message["params"]
        for message in messages
        if message.get("method", "").endswith("/requestApproval")
    }

    command = approvals["item/commandExecution/requestApproval"]
    assert set(command) == {
        "threadId",
        "turnId",
        "itemId",
        "startedAtMs",
        "cwd",
        "reason",
        "command",
        "commandActions",
        "availableDecisions",
    }
    assert isinstance(command["startedAtMs"], int)
    assert isinstance(command["command"], str)
    assert command["availableDecisions"] == ["accept", "decline"]
    assert all(
        set(action) == {"type", "command"} and action["type"] == "unknown"
        for action in command["commandActions"]
    )

    file_change = approvals["item/fileChange/requestApproval"]
    assert set(file_change) == {
        "threadId",
        "turnId",
        "itemId",
        "startedAtMs",
        "reason",
        "grantRoot",
    }
    assert isinstance(file_change["startedAtMs"], int)
    assert "fileChanges" not in file_change and "diff" not in file_change

    permission = approvals["item/permissions/requestApproval"]
    assert set(permission) == {
        "threadId",
        "turnId",
        "itemId",
        "startedAtMs",
        "cwd",
        "environmentId",
        "reason",
        "permissions",
    }
    assert isinstance(permission["startedAtMs"], int)
    assert permission["cwd"] == "/workspace"
    assert set(permission["permissions"]) == {"fileSystem", "network"}
    assert "rawToken" not in permission


def test_fake_codex_rejects_state_inside_codex_home(tmp_path: pathlib.Path) -> None:
    environment, _, codex_home = fake_environment(tmp_path)
    state_file = codex_home / "thread-state.json"
    environment["FAKE_CODEX_STATE_FILE"] = str(state_file)
    process = run_fake(environment, [])
    assert process.returncode != 0
    assert "state file must be outside CODEX_HOME" in process.stderr
    assert not state_file.exists()


def test_fake_codex_rejects_oversized_state_file(tmp_path: pathlib.Path) -> None:
    environment, state_file, _ = fake_environment(tmp_path)
    state_file.write_bytes(b"x" * ((1 << 20) + 1))
    state_file.chmod(0o600)
    process = run_fake(environment, [])
    assert process.returncode != 0
    assert "state file exceeds size limit" in process.stderr
