from __future__ import annotations

import os
from pathlib import Path

import pytest
from smoke import read_private_opaque_file


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
        read_private_opaque_file(str(private / ".." / "private" / "token"), "access token")
    with pytest.raises(ValueError, match="canonical and absolute"):
        read_private_opaque_file("relative-token", "access token")
    with pytest.raises(ValueError, match="canonical and absolute"):
        read_private_opaque_file("//" + str(path).lstrip("/"), "access token")

    second = private / "second-link"
    os.link(path, second)
    with pytest.raises(ValueError, match="one filesystem link"):
        read_private_opaque_file(path, "access token")
