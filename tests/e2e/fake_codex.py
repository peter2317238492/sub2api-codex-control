#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import stat
import sys
import time
from pathlib import Path
from typing import Any

CODEX_VERSION = "0.147.0"
STATE_SCHEMA_VERSION = 1
MAX_STATE_BYTES = 1 << 20
MAX_THREADS = 64
MAX_TURNS_PER_THREAD = 64
MAX_ITEMS_PER_TURN = 128
MAX_TEXT_BYTES = 64 << 10
APPROVAL_STARTED_AT_MS = 1785945600000


class FakeAppServer:
    def __init__(self) -> None:
        self.audit_log = Path(os.environ["FAKE_CODEX_AUDIT_LOG"])
        self.approval_audit_log = Path(os.environ["FAKE_CODEX_APPROVAL_AUDIT_LOG"])
        self.state_file = Path(os.environ["FAKE_CODEX_STATE_FILE"])
        self.assert_state_outside_codex_home()
        provider_key_file = Path(os.environ["FAKE_SUB2API_PROVIDER_KEY_FILE"])
        self.provider_key_canary = provider_key_file.read_text(encoding="utf-8").strip()
        if not self.provider_key_canary:
            raise RuntimeError("fake Sub2API provider-key canary is empty")
        self.threads: dict[str, dict[str, Any]] = {}
        self.next_thread = 1
        self.next_turn = 1
        self.pending_approval: dict[str, Any] | None = None
        self.load_state()

    def assert_state_outside_codex_home(self) -> None:
        codex_home = Path(os.environ.get("CODEX_HOME", "/tmp/fake-codex-home"))
        try:
            self.state_file.resolve(strict=False).relative_to(
                codex_home.resolve(strict=False)
            )
        except ValueError:
            return
        raise RuntimeError("fake state file must be outside CODEX_HOME")

    @staticmethod
    def bounded_string(value: Any, field: str, *, limit: int = 4096) -> str:
        if not isinstance(value, str) or len(value.encode("utf-8")) > limit:
            raise RuntimeError(f"invalid persisted {field}")
        return value

    @classmethod
    def validate_item(cls, item: Any) -> None:
        if not isinstance(item, dict):
            raise TypeError("invalid persisted thread item")
        item_type = item.get("type")
        cls.bounded_string(item.get("id"), "item id", limit=256)
        if item_type == "userMessage":
            if set(item) != {"id", "type", "content"}:
                raise RuntimeError("invalid persisted user item")
            content = item.get("content")
            if not isinstance(content, list) or len(content) != 1:
                raise RuntimeError("invalid persisted user content")
            part = content[0]
            if not isinstance(part, dict) or set(part) != {"type", "text"}:
                raise RuntimeError("invalid persisted user content")
            if part.get("type") != "text":
                raise RuntimeError("invalid persisted user content type")
            cls.bounded_string(part.get("text"), "user text", limit=MAX_TEXT_BYTES)
            return
        if item_type == "agentMessage":
            if set(item) != {"id", "type", "text"}:
                raise RuntimeError("invalid persisted agent item")
            cls.bounded_string(item.get("text"), "agent text", limit=MAX_TEXT_BYTES)
            return
        raise RuntimeError("invalid persisted item type")

    @classmethod
    def validate_thread(cls, thread: Any) -> tuple[str, int, int]:
        expected_fields = {
            "id",
            "cwd",
            "name",
            "preview",
            "status",
            "turns",
            "active_turn_id",
            "created_at",
            "updated_at",
            "session_id",
        }
        if not isinstance(thread, dict) or set(thread) != expected_fields:
            raise RuntimeError("invalid persisted thread")
        thread_id = cls.bounded_string(thread.get("id"), "thread id", limit=256)
        prefix = "e2e-thread-"
        if not thread_id.startswith(prefix) or not thread_id[len(prefix) :].isdigit():
            raise RuntimeError("invalid persisted thread id")
        thread_sequence = int(thread_id[len(prefix) :])
        if thread_sequence < 1:
            raise RuntimeError("invalid persisted thread sequence")
        cls.bounded_string(thread.get("cwd"), "thread cwd")
        cls.bounded_string(thread.get("name"), "thread name")
        cls.bounded_string(thread.get("preview"), "thread preview")
        cls.bounded_string(thread.get("session_id"), "thread session id", limit=256)
        for field in ("created_at", "updated_at"):
            value = thread.get(field)
            if type(value) is not int or value < 0:
                raise RuntimeError(f"invalid persisted {field}")
        status_value = thread.get("status")
        if status_value not in {"active", "idle"}:
            raise RuntimeError("invalid persisted thread status")
        turns = thread.get("turns")
        if not isinstance(turns, list) or len(turns) > MAX_TURNS_PER_THREAD:
            raise RuntimeError("invalid persisted thread turns")
        active_turn_id = thread.get("active_turn_id")
        if active_turn_id is not None:
            cls.bounded_string(active_turn_id, "active turn id", limit=256)
        max_turn_sequence = 0
        turn_ids: set[str] = set()
        for turn in turns:
            if not isinstance(turn, dict) or set(turn) != {"id", "status", "items"}:
                raise RuntimeError("invalid persisted turn")
            turn_id = cls.bounded_string(turn.get("id"), "turn id", limit=256)
            turn_prefix = "e2e-turn-"
            if (
                not turn_id.startswith(turn_prefix)
                or not turn_id[len(turn_prefix) :].isdigit()
            ):
                raise RuntimeError("invalid persisted turn id")
            turn_sequence = int(turn_id[len(turn_prefix) :])
            if turn_sequence < 1 or turn_id in turn_ids:
                raise RuntimeError("invalid persisted turn sequence")
            turn_ids.add(turn_id)
            max_turn_sequence = max(max_turn_sequence, turn_sequence)
            if turn.get("status") not in {"inProgress", "completed"}:
                raise RuntimeError("invalid persisted turn status")
            items = turn.get("items")
            if not isinstance(items, list) or len(items) > MAX_ITEMS_PER_TURN:
                raise RuntimeError("invalid persisted turn items")
            for item in items:
                cls.validate_item(item)
        if status_value == "active":
            if active_turn_id not in turn_ids:
                raise RuntimeError("active persisted thread has no matching turn")
        elif active_turn_id is not None:
            raise RuntimeError("idle persisted thread has an active turn")
        return thread_id, thread_sequence, max_turn_sequence

    def load_state(self) -> None:
        try:
            state_stat = self.state_file.lstat()
        except FileNotFoundError:
            return
        if not stat.S_ISREG(state_stat.st_mode):
            raise RuntimeError("fake state path is not a regular file")
        if state_stat.st_mode & 0o077:
            raise RuntimeError("fake state file must be owner-only")
        if state_stat.st_size > MAX_STATE_BYTES:
            raise RuntimeError("fake state file exceeds size limit")
        try:
            payload = json.loads(self.state_file.read_bytes())
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
            raise RuntimeError("invalid fake state file") from error
        if not isinstance(payload, dict) or set(payload) != {
            "schema_version",
            "next_thread",
            "next_turn",
            "threads",
        }:
            raise RuntimeError("invalid fake state document")
        if payload.get("schema_version") != STATE_SCHEMA_VERSION:
            raise RuntimeError("unsupported fake state schema")
        next_thread = payload.get("next_thread")
        next_turn = payload.get("next_turn")
        if type(next_thread) is not int or next_thread < 1:
            raise RuntimeError("invalid next thread sequence")
        if type(next_turn) is not int or next_turn < 1:
            raise RuntimeError("invalid next turn sequence")
        raw_threads = payload.get("threads")
        if not isinstance(raw_threads, list) or len(raw_threads) > MAX_THREADS:
            raise RuntimeError("invalid persisted thread collection")
        threads: dict[str, dict[str, Any]] = {}
        max_thread_sequence = 0
        max_turn_sequence = 0
        for thread in raw_threads:
            thread_id, thread_sequence, turn_sequence = self.validate_thread(thread)
            if thread_id in threads:
                raise RuntimeError("duplicate persisted thread id")
            threads[thread_id] = thread
            max_thread_sequence = max(max_thread_sequence, thread_sequence)
            max_turn_sequence = max(max_turn_sequence, turn_sequence)
        if next_thread <= max_thread_sequence or next_turn <= max_turn_sequence:
            raise RuntimeError("persisted sequence would reuse an existing id")
        self.threads = threads
        self.next_thread = next_thread
        self.next_turn = next_turn

    def persist_state(self) -> None:
        document = {
            "schema_version": STATE_SCHEMA_VERSION,
            "next_thread": self.next_thread,
            "next_turn": self.next_turn,
            "threads": list(self.threads.values()),
        }
        payload = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
        if len(payload) > MAX_STATE_BYTES:
            raise RuntimeError("fake state exceeds size limit")
        self.state_file.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        temporary = self.state_file.with_name(
            f".{self.state_file.name}.{os.getpid()}.tmp"
        )
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        flags |= getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(temporary, flags, 0o600)
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, self.state_file)
            directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
            directory = os.open(self.state_file.parent, directory_flags)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            temporary.unlink(missing_ok=True)

    def send(self, message: dict[str, Any]) -> None:
        if "method" in message and "id" not in message:
            message = {**message, "emittedAtMs": int(time.time() * 1000)}
        sys.stdout.write(json.dumps(message, separators=(",", ":")) + "\n")
        sys.stdout.flush()

    def audit(self, method: str) -> None:
        with self.audit_log.open("a", encoding="utf-8") as handle:
            handle.write(method + "\n")

    def audit_approval(self, kind: str, outcome: str) -> None:
        with self.approval_audit_log.open("a", encoding="utf-8") as handle:
            record = json.dumps({"kind": kind, "outcome": outcome}, sort_keys=True)
            handle.write(record + "\n")

    def response(self, request_id: Any, result: Any) -> None:
        self.send({"jsonrpc": "2.0", "id": request_id, "result": result})

    def error(self, request_id: Any, message: str) -> None:
        self.send(
            {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -32601, "message": message},
            }
        )

    def wire_thread(self, thread: dict[str, Any]) -> dict[str, Any]:
        status = (
            {"type": "active", "activeFlags": []}
            if thread["status"] == "active"
            else {"type": "idle"}
        )
        return {
            "id": thread["id"],
            "preview": thread["preview"],
            "modelProvider": "sub2api",
            "createdAt": thread["created_at"],
            "updatedAt": thread["updated_at"],
            "status": status,
            "cwd": thread["cwd"],
            "source": "appServer",
            "cliVersion": CODEX_VERSION,
            "turns": thread["turns"],
            "sessionId": thread["session_id"],
            "ephemeral": False,
            "name": thread["name"],
        }

    def thread_result(self, thread: dict[str, Any]) -> dict[str, Any]:
        return {
            "thread": self.wire_thread(thread),
            "model": "gpt-5.5-e2e",
            "modelProvider": "sub2api",
            "cwd": thread["cwd"],
            "approvalPolicy": "on-request",
            "approvalsReviewer": "user",
            "sandbox": {
                "type": "workspaceWrite",
                "writableRoots": [thread["cwd"]],
                "networkAccess": False,
            },
        }

    def handle_request(self, message: dict[str, Any]) -> None:
        method = message.get("method")
        request_id = message.get("id")
        params = message.get("params")
        if (
            not isinstance(method, str)
            or request_id is None
            or not isinstance(params, dict)
        ):
            self.error(request_id, "invalid fake app-server request")
            return

        if method == "initialize":
            self.response(
                request_id,
                {
                    "codexHome": os.environ.get("CODEX_HOME", "/tmp/fake-codex-home"),
                    "platformFamily": "unix",
                    "platformOs": "linux",
                    "userAgent": "e2e-fake-codex",
                },
            )
            return

        self.audit(method)
        if method == "model/list":
            self.response(
                request_id,
                {
                    "data": [
                        {
                            "id": "gpt-5.5-e2e",
                            "displayName": "GPT-5.5 E2E",
                            "description": "Deterministic full-stack acceptance model",
                            "model": "gpt-5.5-e2e",
                            "isDefault": True,
                            "hidden": False,
                            "defaultReasoningEffort": "medium",
                            "supportedReasoningEfforts": [
                                {
                                    "reasoningEffort": "medium",
                                    "description": "Deterministic E2E effort",
                                }
                            ],
                            "providerKey": self.provider_key_canary,
                        }
                    ],
                    "provider": self.provider_key_canary,
                },
            )
            return

        if method == "thread/list":
            self.response(
                request_id,
                {
                    "data": [
                        self.wire_thread(thread) for thread in self.threads.values()
                    ]
                },
            )
            return

        if method == "thread/start":
            cwd = params.get("cwd")
            if not isinstance(cwd, str):
                self.error(request_id, "thread/start requires cwd")
                return
            if len(cwd.encode("utf-8")) > 4096:
                self.error(request_id, "thread/start cwd exceeds fake state limit")
                return
            if len(self.threads) >= MAX_THREADS:
                self.error(request_id, "fake app-server thread capacity exceeded")
                return
            thread_id = f"e2e-thread-{self.next_thread}"
            self.next_thread += 1
            thread = {
                "id": thread_id,
                "cwd": cwd,
                "name": "E2E managed thread",
                "preview": "",
                "status": "idle",
                "turns": [],
                "active_turn_id": None,
                "created_at": 0,
                "updated_at": 0,
                "session_id": f"e2e-session-{self.next_thread - 1}",
            }
            self.threads[thread_id] = thread
            self.persist_state()
            self.response(request_id, self.thread_result(thread))
            return

        thread_id = params.get("threadId")
        thread = self.threads.get(thread_id) if isinstance(thread_id, str) else None
        if thread is None:
            self.error(request_id, "unknown managed thread")
            return

        if method == "thread/read":
            self.response(request_id, self.thread_result(thread))
            return

        if method == "thread/resume":
            self.response(request_id, self.thread_result(thread))
            return

        if method == "turn/start":
            if (
                self.pending_approval is not None
                or thread["active_turn_id"] is not None
            ):
                self.error(request_id, "turn already active")
                return
            input_items = params.get("input")
            text = ""
            if isinstance(input_items, list) and input_items:
                first = input_items[0]
                if isinstance(first, dict) and isinstance(first.get("text"), str):
                    text = first["text"]
            if len(text.encode("utf-8")) > MAX_TEXT_BYTES:
                self.error(request_id, "turn/start text exceeds fake state limit")
                return
            if len(thread["turns"]) >= MAX_TURNS_PER_THREAD:
                self.error(request_id, "fake app-server turn capacity exceeded")
                return
            turn_id = f"e2e-turn-{self.next_turn}"
            self.next_turn += 1
            thread["status"] = "active"
            thread["active_turn_id"] = turn_id
            thread["turns"].append(
                {
                    "id": turn_id,
                    "status": "inProgress",
                    "items": [
                        {
                            "id": f"user-{turn_id}",
                            "type": "userMessage",
                            "content": [{"type": "text", "text": text}],
                        }
                    ],
                }
            )
            self.persist_state()
            self.send(
                {
                    "jsonrpc": "2.0",
                    "method": "turn/started",
                    "params": {
                        "threadId": thread_id,
                        "turn": {"id": turn_id, "items": [], "status": "inProgress"},
                    },
                }
            )
            self.pending_approval = {
                "request_id": request_id,
                "thread_id": thread_id,
                "turn_id": turn_id,
            }
            self.request_approval("command")
            return

        if self.handle_turn_request(method, request_id, params, thread):
            return
        self.error(request_id, f"unsupported fake app-server method: {method}")

    def request_approval(self, kind: str) -> None:
        pending = self.pending_approval
        if pending is None:
            raise RuntimeError("approval sequence has no pending turn")
        turn_id = pending["turn_id"]
        thread_id = pending["thread_id"]
        thread = self.threads[thread_id]
        rpc_id = f"e2e-{kind}-approval-{turn_id}"
        pending["kind"] = kind
        pending["rpc_id"] = rpc_id
        if kind == "command":
            self.send(
                {
                    "jsonrpc": "2.0",
                    "id": rpc_id,
                    "method": "item/commandExecution/requestApproval",
                    "params": {
                        "threadId": thread_id,
                        "turnId": turn_id,
                        "itemId": f"command-{turn_id}",
                        "startedAtMs": APPROVAL_STARTED_AT_MS,
                        "cwd": thread["cwd"],
                        "reason": "Approve the deterministic E2E command",
                        "command": "printf e2e-approved",
                        "commandActions": [
                            {
                                "type": "unknown",
                                "command": "COMMAND-SECRET-MUST-NOT-CROSS",
                            },
                            {
                                "type": "unknown",
                                "command": "COMMAND-OUTPUT-MUST-NOT-CROSS",
                            },
                        ],
                        "availableDecisions": ["accept", "decline"],
                    },
                }
            )
            return
        if kind == "file_change":
            self.send(
                {
                    "jsonrpc": "2.0",
                    "id": rpc_id,
                    "method": "item/fileChange/requestApproval",
                    "params": {
                        "threadId": thread_id,
                        "turnId": turn_id,
                        "itemId": f"file-{turn_id}",
                        "startedAtMs": APPROVAL_STARTED_AT_MS,
                        "reason": "Review deterministic E2E file operations",
                        "grantRoot": thread["cwd"],
                    },
                }
            )
            return
        if kind == "permission":
            self.send(
                {
                    "jsonrpc": "2.0",
                    "id": rpc_id,
                    "method": "item/permissions/requestApproval",
                    "params": {
                        "threadId": thread_id,
                        "turnId": turn_id,
                        "itemId": f"permission-{turn_id}",
                        "startedAtMs": APPROVAL_STARTED_AT_MS,
                        "cwd": thread["cwd"],
                        "environmentId": "PERMISSION-ENVIRONMENT-ID-MUST-NOT-CROSS",
                        "reason": "Read and write only inside the E2E workspace",
                        "permissions": {
                            "fileSystem": {
                                "read": ["/workspace/ordinary-codex-state"],
                                "write": ["/workspace"],
                            },
                            "network": {"enabled": False},
                        },
                    },
                }
            )
            return
        raise RuntimeError(f"unknown fake approval kind: {kind}")

    def complete_turn_start(self) -> None:
        pending = self.pending_approval
        if pending is None:
            raise RuntimeError("approval sequence has no pending turn")
        thread = self.threads[pending["thread_id"]]
        self.response(
            pending["request_id"],
            {
                "turn": {
                    "id": pending["turn_id"],
                    "items": thread["turns"][-1]["items"],
                    "status": "inProgress",
                }
            },
        )
        self.pending_approval = None

    def handle_turn_request(
        self,
        method: str,
        request_id: Any,
        params: dict[str, Any],
        thread: dict[str, Any],
    ) -> bool:
        thread_id = thread["id"]
        if method == "turn/steer":
            turn_id = thread["active_turn_id"]
            if not isinstance(turn_id, str) or params.get("expectedTurnId") != turn_id:
                self.error(request_id, "turn/steer targeted the wrong turn")
                return True
            if len(thread["turns"][-1]["items"]) >= MAX_ITEMS_PER_TURN:
                self.error(request_id, "fake app-server item capacity exceeded")
                return True
            item_id = f"agent-{turn_id}"
            delta = "E2E approved response"
            thread["turns"][-1]["items"].append(
                {"id": item_id, "type": "agentMessage", "text": delta}
            )
            self.persist_state()
            self.send(
                {
                    "jsonrpc": "2.0",
                    "method": "item/agentMessage/delta",
                    "params": {
                        "threadId": thread_id,
                        "turnId": turn_id,
                        "itemId": item_id,
                        "delta": delta,
                    },
                }
            )
            self.response(request_id, {"turnId": turn_id})
            return True

        if method == "turn/interrupt":
            turn_id = thread["active_turn_id"]
            if not isinstance(turn_id, str) or params.get("turnId") != turn_id:
                self.error(request_id, "turn/interrupt targeted the wrong turn")
                return True
            thread["status"] = "idle"
            thread["active_turn_id"] = None
            thread["turns"][-1]["status"] = "completed"
            self.persist_state()
            self.send(
                {
                    "jsonrpc": "2.0",
                    "method": "turn/completed",
                    "params": {
                        "threadId": thread_id,
                        "turn": {
                            "id": turn_id,
                            "items": thread["turns"][-1]["items"],
                            "status": "completed",
                        },
                    },
                }
            )
            self.response(request_id, {})
            return True
        return False

    def handle_response(self, message: dict[str, Any]) -> None:
        pending = self.pending_approval
        if pending is None or message.get("id") != pending["rpc_id"]:
            return
        kind = pending["kind"]
        result = message.get("result")
        error = message.get("error")
        if kind == "command":
            if not isinstance(result, dict) or result.get("decision") != "accept":
                self.error(
                    pending["request_id"], "E2E command approval was not accepted"
                )
                self.pending_approval = None
                return
            self.audit_approval("command", "approved")
            self.request_approval("file_change")
            return
        if kind == "file_change":
            if not isinstance(result, dict) or result.get("decision") != "decline":
                self.error(
                    pending["request_id"], "E2E file-change approval was not denied"
                )
                self.pending_approval = None
                return
            self.audit_approval("file_change", "denied")
            self.request_approval("permission")
            return
        if kind == "permission":
            if not isinstance(error, dict) or error.get("code") != -32001:
                self.error(
                    pending["request_id"],
                    "E2E permission approval did not default deny",
                )
                self.pending_approval = None
                return
            self.audit_approval("permission", "timeout_default_deny")
            self.complete_turn_start()
            return
        self.error(pending["request_id"], "unknown E2E approval response")
        self.pending_approval = None

    def run(self) -> int:
        for line in sys.stdin:
            try:
                message = json.loads(line)
            except json.JSONDecodeError:
                return 2
            if not isinstance(message, dict) or message.get("jsonrpc") != "2.0":
                return 2
            if "method" in message and "id" in message:
                self.handle_request(message)
            elif "id" in message:
                self.handle_response(message)
        return 0


def main() -> int:
    if sys.argv[1:] == ["--version"]:
        print(f"codex-cli {CODEX_VERSION}")
        return 0
    if sys.argv[1:] != ["app-server", "--listen", "stdio://"]:
        print("unsupported fake Codex invocation", file=sys.stderr)
        return 2
    return FakeAppServer().run()


if __name__ == "__main__":
    raise SystemExit(main())
