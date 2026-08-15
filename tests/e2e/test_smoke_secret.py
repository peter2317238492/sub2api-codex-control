from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from unittest import mock

import pytest
import smoke
from smoke import (
    read_closure_challenge,
    read_closure_challenge_sha256,
    read_private_opaque_file,
)


def challenge_content() -> bytes:
    target_without_digest = {
        "public_origin": "https://control.example.com",
        "compose_plan_sha256": "1" * 64,
        "artifact_identity_sha256": "2" * 64,
        "runtime_identity_sha256": "3" * 64,
        "source_identity_sha256": "4" * 64,
        "local_images_sha256": "5" * 64,
        "running_containers_sha256": "6" * 64,
    }
    binding = hashlib.sha256(
        json.dumps(
            target_without_digest, sort_keys=True, separators=(",", ":")
        ).encode()
    ).hexdigest()
    value = {
        "$schema": "https://sub2api-codex.invalid/schemas/authenticated-smoke-challenge-v2.json",
        "format_version": 2,
        "deployment_id": "12345678-1234-4123-8123-123456789abc",
        "deployment_basename": (
            "bootstrap-20260812T000000Z-12345678-1234-4123-8123-123456789abc"
        ),
        "bootstrap_record_sha256": "a" * 64,
        "issued_at": "2026-08-13T00:00:00Z",
        "nonce": "b" * 64,
        "target": {**target_without_digest, "binding_sha256": binding},
    }
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def test_private_smoke_token_file_is_accepted(tmp_path: Path) -> None:
    path = tmp_path / "access-token"
    path.write_text("short-lived-token\n", encoding="utf-8")
    os.chmod(path, 0o600)

    assert read_private_opaque_file(path, "access token") == "short-lived-token"


def test_smoke_token_file_rejects_broad_mode_symlink_and_whitespace(
    tmp_path: Path,
) -> None:
    path = tmp_path / "access-token"
    path.write_text("token\n", encoding="utf-8")
    os.chmod(path, 0o644)
    with pytest.raises(ValueError, match="mode must be exactly 0600"):
        read_private_opaque_file(path, "access token")

    os.chmod(path, 0o600)
    alias = tmp_path / "alias"
    alias.symlink_to(path)
    with pytest.raises(ValueError, match="without following links"):
        read_private_opaque_file(alias, "access token")

    path.write_text("two values\n", encoding="utf-8")
    with pytest.raises(ValueError, match="opaque"):
        read_private_opaque_file(path, "access token")


def test_smoke_token_file_rejects_non_file_and_oversized_value(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="changed while it was opened"):
        read_private_opaque_file(tmp_path, "access token")

    path = tmp_path / "access-token"
    path.write_text("x" * 65_537, encoding="utf-8")
    os.chmod(path, 0o600)
    with pytest.raises(ValueError, match="64 KiB"):
        read_private_opaque_file(path, "access token")


def test_closure_challenge_reader_hashes_exact_private_producer_input(
    tmp_path: Path,
) -> None:
    path = tmp_path / "challenge.json"
    content = challenge_content()
    path.write_bytes(content)
    os.chmod(path, 0o600)

    import hashlib

    assert read_closure_challenge_sha256(path) == hashlib.sha256(content).hexdigest()
    assert read_closure_challenge(path).public_origin == "https://control.example.com"


def test_closure_challenge_reader_rejects_broad_mode_and_unknown_fields(
    tmp_path: Path,
) -> None:
    path = tmp_path / "challenge.json"
    path.write_text("{}\n", encoding="utf-8")
    os.chmod(path, 0o644)
    with pytest.raises(ValueError, match="mode must be exactly 0600"):
        read_closure_challenge_sha256(path)

    path.write_text('{"format_version":1,"unexpected":true}\n', encoding="utf-8")
    os.chmod(path, 0o600)
    with pytest.raises(ValueError, match="unexpected schema"):
        read_closure_challenge_sha256(path)


def test_token_file_rejects_noncanonical_symlink_ancestor_and_hardlink(
    tmp_path: Path,
) -> None:
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    path = private / "token"
    path.write_text("secret\n", encoding="utf-8")
    path.chmod(0o600)

    alias = tmp_path / "alias"
    alias.symlink_to(private, target_is_directory=True)
    with pytest.raises(ValueError, match="symlink ancestor"):
        read_private_opaque_file(alias / "token", "access token")
    with pytest.raises(ValueError, match="canonical and absolute"):
        read_private_opaque_file(
            str(private / ".." / "private" / "token"), "access token"
        )
    with pytest.raises(ValueError, match="canonical and absolute"):
        read_private_opaque_file("relative-token", "access token")
    with pytest.raises(ValueError, match="canonical and absolute"):
        read_private_opaque_file("//" + str(path).lstrip("/"), "access token")

    second = private / "second-link"
    os.link(path, second)
    with pytest.raises(ValueError, match="one filesystem link"):
        read_private_opaque_file(path, "access token")


def test_token_file_rejects_name_replacement_while_open(tmp_path: Path) -> None:
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    path = private / "token"
    path.write_text("original-secret\n", encoding="utf-8")
    path.chmod(0o600)
    displaced = private / "displaced"
    real_read = os.read
    replaced = False

    def read_then_replace(descriptor: int, maximum: int) -> bytes:
        nonlocal replaced
        block = real_read(descriptor, maximum)
        if not replaced:
            replaced = True
            path.rename(displaced)
            path.write_text("replacement-secret\n", encoding="utf-8")
            path.chmod(0o600)
        return block

    with (
        mock.patch.object(smoke.os, "read", side_effect=read_then_replace),
        pytest.raises(ValueError, match="changed while it was read"),
    ):
        read_private_opaque_file(path, "access token")


def test_challenge_mode_requires_private_inputs_before_any_read_or_network(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    challenge = tmp_path / "challenge.json"
    challenge.write_bytes(challenge_content())
    challenge.chmod(0o600)
    token = tmp_path / "token"
    token.write_text("private-token-value\n", encoding="utf-8")
    token.chmod(0o600)
    user_id = tmp_path / "expected-user-id"
    user_id.write_text("fixture-user\n", encoding="utf-8")
    user_id.chmod(0o600)
    base = [
        "--base-url",
        "https://control.example.com",
        "--access-token-file",
        str(token),
        "--expected-user-id-file",
        str(user_id),
        "--expect-secure-cookie",
        "--closure-challenge-file",
        str(challenge),
    ]
    cases = {
        "argv token": [*base, "--access-token", "private-token-value"],
        "argv user id": [*base, "--expected-user-id", "fixture-user"],
        "missing token file": [
            item for item in base if item not in {"--access-token-file", str(token)}
        ],
        "missing base": [
            item
            for item in base
            if item not in {"--base-url", "https://control.example.com"}
        ],
        "missing user id file": [
            item
            for item in base
            if item not in {"--expected-user-id-file", str(user_id)}
        ],
        "insecure": [*base, "--insecure"],
        "missing secure-cookie requirement": [
            item for item in base if item != "--expect-secure-cookie"
        ],
    }
    for label, arguments in cases.items():
        monkeypatch.delenv("SUB2API_ACCESS_TOKEN", raising=False)
        monkeypatch.delenv("SUB2API_EXPECTED_USER_ID", raising=False)
        with (
            mock.patch.object(smoke, "read_closure_challenge") as challenge_reader,
            mock.patch.object(smoke, "read_private_opaque_file") as private_reader,
            mock.patch.object(smoke, "Smoke") as producer,
        ):
            assert smoke.main(arguments) == 1, label
            challenge_reader.assert_not_called()
            private_reader.assert_not_called()
            producer.assert_not_called()
        captured = capsys.readouterr()
        assert captured.out == "", label
        assert "private-token-value" not in captured.err, label
        assert "1..84" not in captured.err, label

    monkeypatch.setenv("SUB2API_ACCESS_TOKEN", "private-token-value")
    with (
        mock.patch.object(smoke, "read_closure_challenge") as challenge_reader,
        mock.patch.object(smoke, "read_private_opaque_file") as private_reader,
        mock.patch.object(smoke, "Smoke") as producer,
    ):
        assert smoke.main(base) == 1
        challenge_reader.assert_not_called()
        private_reader.assert_not_called()
        producer.assert_not_called()
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "private-token-value" not in captured.err
    assert "1..84" not in captured.err

    monkeypatch.delenv("SUB2API_ACCESS_TOKEN")
    monkeypatch.setenv("SUB2API_EXPECTED_USER_ID", "private-user-value")
    with (
        mock.patch.object(smoke, "read_closure_challenge") as challenge_reader,
        mock.patch.object(smoke, "read_private_opaque_file") as private_reader,
        mock.patch.object(smoke, "Smoke") as producer,
    ):
        assert smoke.main(base) == 1
        challenge_reader.assert_not_called()
        private_reader.assert_not_called()
        producer.assert_not_called()
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "private-user-value" not in captured.err
    assert "1..84" not in captured.err


def test_challenge_mode_rejects_every_device_flow_option_before_io(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.delenv("SUB2API_ACCESS_TOKEN", raising=False)
    monkeypatch.delenv("SUB2API_EXPECTED_USER_ID", raising=False)
    device_id_file = tmp_path / "must-not-write-device-id"
    thread_id_file = tmp_path / "must-not-write-thread-id"
    cases = {
        "--pairing-code": ["--pairing-code", "pairing-value"],
        "--expected-device-id": ["--expected-device-id", "device-value"],
        "--workspace-root": ["--workspace-root", "/private/workspace"],
        "--keep-device": ["--keep-device"],
        "--reconnect-only": ["--reconnect-only"],
        "--device-id-file": ["--device-id-file", str(device_id_file)],
        "--expected-thread-id": ["--expected-thread-id", "thread-value"],
        "--thread-id-file": ["--thread-id-file", str(thread_id_file)],
        "--provider-key-canary-file": [
            "--provider-key-canary-file",
            str(tmp_path / "must-not-read-canary"),
        ],
        "--expect-cross-instance-fanout": ["--expect-cross-instance-fanout"],
    }
    assert {option for _, option in smoke.CLOSURE_DEVICE_FLOW_OPTIONS} == set(cases)
    base = [
        "--base-url",
        "https://control.example.com",
        "--access-token-file",
        str(tmp_path / "must-not-read-token"),
        "--expected-user-id-file",
        str(tmp_path / "must-not-read-user-id"),
        "--expect-secure-cookie",
        "--closure-challenge-file",
        str(tmp_path / "must-not-read-challenge"),
    ]

    for option, extra in cases.items():
        with (
            mock.patch.object(smoke, "read_closure_challenge") as challenge_reader,
            mock.patch.object(smoke, "read_private_opaque_file") as private_reader,
            mock.patch.object(smoke.Path, "read_text") as canary_reader,
            mock.patch.object(smoke, "Smoke") as producer,
        ):
            assert smoke.main([*base, *extra]) == 1, option
            challenge_reader.assert_not_called()
            private_reader.assert_not_called()
            canary_reader.assert_not_called()
            producer.assert_not_called()
        captured = capsys.readouterr()
        assert captured.out == "", option
        assert option in captured.err
        assert "pairing-value" not in captured.err
        assert "device-value" not in captured.err
        assert "thread-value" not in captured.err
        assert not device_id_file.exists()
        assert not thread_id_file.exists()


def test_challenge_mode_reads_expected_user_id_only_from_private_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.delenv("SUB2API_ACCESS_TOKEN", raising=False)
    monkeypatch.delenv("SUB2API_EXPECTED_USER_ID", raising=False)
    challenge = tmp_path / "challenge.json"
    challenge.write_bytes(challenge_content())
    challenge.chmod(0o600)
    token = tmp_path / "token"
    token.write_text("private-token-value\n", encoding="utf-8")
    token.chmod(0o600)
    user_id = tmp_path / "expected-user-id"
    user_id.write_text("private-user-value\n", encoding="utf-8")
    user_id.chmod(0o600)

    with mock.patch.object(smoke, "Smoke") as producer:
        instance = producer.return_value
        instance.passed = 84
        assert (
            smoke.main(
                [
                    "--base-url",
                    "https://control.example.com",
                    "--access-token-file",
                    str(token),
                    "--expected-user-id-file",
                    str(user_id),
                    "--expect-secure-cookie",
                    "--closure-challenge-file",
                    str(challenge),
                ]
            )
            == 0
        )
    run_arguments, run_keywords = instance.run.call_args
    assert run_arguments == ("private-token-value",)
    assert run_keywords["expected_user_id"] == "private-user-value"
    assert all(
        run_keywords[attribute] in (None, False)
        for attribute, _ in smoke.CLOSURE_DEVICE_FLOW_OPTIONS
        if attribute in run_keywords
    )
    captured = capsys.readouterr()
    assert captured.out.startswith("1..84 # closure-challenge-sha256=")
    combined = captured.out + captured.err
    assert "private-token-value" not in combined
    assert "private-user-value" not in combined
    assert str(token) not in combined
    assert str(user_id) not in combined


def test_challenge_mode_rejects_user_id_file_symlink_ancestor_before_network(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.delenv("SUB2API_ACCESS_TOKEN", raising=False)
    monkeypatch.delenv("SUB2API_EXPECTED_USER_ID", raising=False)
    challenge = tmp_path / "challenge.json"
    challenge.write_bytes(challenge_content())
    challenge.chmod(0o600)
    token = tmp_path / "token"
    token.write_text("private-token-value\n", encoding="utf-8")
    token.chmod(0o600)
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    user_id = private / "expected-user-id"
    user_id.write_text("private-user-value\n", encoding="utf-8")
    user_id.chmod(0o600)
    alias = tmp_path / "private-alias"
    alias.symlink_to(private, target_is_directory=True)

    with mock.patch.object(smoke, "Smoke") as producer:
        assert (
            smoke.main(
                [
                    "--base-url",
                    "https://control.example.com",
                    "--access-token-file",
                    str(token),
                    "--expected-user-id-file",
                    str(alias / "expected-user-id"),
                    "--expect-secure-cookie",
                    "--closure-challenge-file",
                    str(challenge),
                ]
            )
            == 1
        )
        producer.assert_not_called()
    captured = capsys.readouterr()
    assert captured.out == ""
    combined = captured.out + captured.err
    assert "symlink ancestor" in combined
    assert "private-token-value" not in combined
    assert "private-user-value" not in combined
    assert str(token) not in combined
    assert str(user_id) not in combined


def test_challenge_mode_rejects_wrong_origin_without_leaking_secret(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    challenge = tmp_path / "challenge.json"
    challenge.write_bytes(challenge_content())
    challenge.chmod(0o600)
    token = tmp_path / "sensitive-private-token-path"
    token.write_text("private-token-value\n", encoding="utf-8")
    token.chmod(0o600)
    user_id = tmp_path / "sensitive-private-user-path"
    user_id.write_text("private-user-value\n", encoding="utf-8")
    user_id.chmod(0o600)
    result = smoke.main(
        [
            "--base-url",
            "https://other.example.com",
            "--access-token-file",
            str(token),
            "--expected-user-id-file",
            str(user_id),
            "--expect-secure-cookie",
            "--closure-challenge-file",
            str(challenge),
        ]
    )
    captured = capsys.readouterr()
    assert result == 1
    assert captured.out == ""
    combined = captured.out + captured.err
    assert "private-token-value" not in combined
    assert "private-user-value" not in combined
    assert str(token) not in combined
    assert str(user_id) not in combined
