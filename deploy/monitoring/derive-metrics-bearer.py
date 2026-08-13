#!/usr/bin/env python3
"""Domain-separated provisioning directly into a new owner-only file."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import os
from pathlib import Path

from common import open_parent, read_secret_file, require_parent_stable

DOMAINS = {
    "control-metrics": b"control-metrics-v1",
    "alertmanager-proxy": b"codex-control-alertmanager-proxy-v1",
    "evidence-receiver": b"codex-control-evidence-receiver-v1",
    "external-operator-delivery": b"codex-control-external-operator-delivery-v1",
}


def _write_all(descriptor: int, payload: bytes) -> None:
    view = memoryview(payload)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise OSError("short write while provisioning bearer")
        view = view[written:]


def derive(
    source: Path,
    destination: Path,
    owner_uid: int,
    owner_gid: int,
    domain: bytes = DOMAINS["control-metrics"],
) -> None:
    secret = read_secret_file(source).rstrip(b"\r\n")
    if len(secret) < 32:
        raise ValueError("root secret is too short")
    bearer = hmac.new(secret, domain, hashlib.sha256).hexdigest().encode("ascii")

    absolute, parent_fd, parent_identity = open_parent(
        destination,
        leaf_owner_uid=owner_uid,
    )
    destination_fd = -1
    created = False
    try:
        flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        destination_fd = os.open(absolute.name, flags, 0o600, dir_fd=parent_fd)
        created = True
        os.fchown(destination_fd, owner_uid, owner_gid)
        os.fchmod(destination_fd, 0o600)
        _write_all(destination_fd, bearer + b"\n")
        os.fsync(destination_fd)
        final_stat = os.fstat(destination_fd)
        named_stat = os.stat(absolute.name, dir_fd=parent_fd, follow_symlinks=False)
        if (
            final_stat.st_dev,
            final_stat.st_ino,
            final_stat.st_nlink,
        ) != (named_stat.st_dev, named_stat.st_ino, 1):
            raise ValueError("bearer destination identity changed")
        require_parent_stable(parent_fd, absolute.parent, parent_identity)
        os.fsync(parent_fd)
    except Exception:
        if created:
            try:
                os.unlink(absolute.name, dir_fd=parent_fd)
                os.fsync(parent_fd)
            except OSError:
                pass
        raise
    finally:
        if destination_fd >= 0:
            os.close(destination_fd)
        os.close(parent_fd)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root-secret-file", type=Path, required=True)
    parser.add_argument("--output-file", type=Path, required=True)
    parser.add_argument("--domain", choices=tuple(DOMAINS), required=True)
    parser.add_argument("--owner-uid", type=int, default=65532)
    parser.add_argument("--owner-gid", type=int, default=65532)
    arguments = parser.parse_args()
    derive(
        arguments.root_secret_file,
        arguments.output_file,
        arguments.owner_uid,
        arguments.owner_gid,
        DOMAINS[arguments.domain],
    )


if __name__ == "__main__":
    main()
