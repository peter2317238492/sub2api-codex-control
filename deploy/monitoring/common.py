"""Security helpers shared by monitoring provisioning and evidence tooling."""

from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import Optional, Tuple


def validate_directory_chain(
    path: Path,
    *,
    leaf_mode: Optional[int] = 0o700,
    leaf_owner_uid: Optional[int] = None,
) -> Tuple[int, int]:
    absolute = path.absolute()
    expected_leaf_owner = os.geteuid() if leaf_owner_uid is None else leaf_owner_uid
    current = absolute
    while True:
        metadata = current.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise ValueError("directory chain must contain only real directories")
        sticky_root = metadata.st_uid == 0 and bool(metadata.st_mode & stat.S_ISVTX)
        if metadata.st_mode & 0o022 and not sticky_root:
            raise ValueError("directory chain must not be group/other writable")
        allowed_owners = {0, os.geteuid()}
        if current == absolute:
            allowed_owners.add(expected_leaf_owner)
        if metadata.st_uid not in allowed_owners:
            raise ValueError("directory chain has an untrusted owner")
        if current == absolute and leaf_mode is not None and (
            metadata.st_uid != expected_leaf_owner or stat.S_IMODE(metadata.st_mode) != leaf_mode
        ):
            raise ValueError("leaf directory owner or mode is invalid")
        if current.parent == current:
            break
        current = current.parent
    final = absolute.stat()
    return final.st_dev, final.st_ino


def open_parent(
    path: Path,
    *,
    leaf_mode: Optional[int] = 0o700,
    leaf_owner_uid: Optional[int] = None,
) -> Tuple[Path, int, Tuple[int, int]]:
    absolute = path.absolute()
    parent = absolute.parent
    expected = validate_directory_chain(
        parent,
        leaf_mode=leaf_mode,
        leaf_owner_uid=leaf_owner_uid,
    )
    descriptor = os.open(
        str(parent),
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_DIRECTORY", 0),
    )
    opened = os.fstat(descriptor)
    if (opened.st_dev, opened.st_ino) != expected:
        os.close(descriptor)
        raise ValueError("parent identity changed")
    return absolute, descriptor, expected


def require_parent_stable(parent_fd: int, parent_path: Path, expected: Tuple[int, int]) -> None:
    leaf_owner_uid = parent_path.lstat().st_uid
    validate_directory_chain(
        parent_path,
        leaf_mode=None,
        leaf_owner_uid=leaf_owner_uid,
    )
    opened = os.fstat(parent_fd)
    named = parent_path.lstat()
    if (opened.st_dev, opened.st_ino) != expected or (
        named.st_dev,
        named.st_ino,
    ) != expected:
        raise ValueError("parent identity changed")


def read_secret_file(path: Path, *, maximum: int = 4096) -> bytes:
    absolute, parent_fd, parent_identity = open_parent(path, leaf_mode=None)
    descriptor = -1
    try:
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(absolute.name, flags, dir_fd=parent_fd)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_size > maximum
        ):
            raise ValueError("secret file identity, owner, mode, or size is invalid")
        named = os.stat(absolute.name, dir_fd=parent_fd, follow_symlinks=False)
        if (metadata.st_dev, metadata.st_ino) != (named.st_dev, named.st_ino):
            raise ValueError("secret file identity changed")
        chunks = []
        remaining = maximum + 1
        while remaining:
            chunk = os.read(descriptor, min(4096, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        if len(payload) > maximum:
            raise ValueError("secret file exceeds limit")
        final = os.fstat(descriptor)
        final_named = os.stat(absolute.name, dir_fd=parent_fd, follow_symlinks=False)
        if (
            not stat.S_ISREG(final.st_mode)
            or final.st_uid != metadata.st_uid
            or stat.S_IMODE(final.st_mode) != 0o600
            or final.st_nlink != 1
            or final.st_size > maximum
            or (final.st_dev, final.st_ino) != (final_named.st_dev, final_named.st_ino)
        ):
            raise ValueError("secret file identity changed during read")
        require_parent_stable(parent_fd, absolute.parent, parent_identity)
        return payload
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        os.close(parent_fd)
