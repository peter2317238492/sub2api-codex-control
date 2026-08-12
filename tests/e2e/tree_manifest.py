#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import os
import pathlib
import stat
import sys


def entry_record(root: pathlib.Path, path: pathlib.Path) -> dict[str, object]:
    metadata = path.lstat()
    relative = "." if path == root else path.relative_to(root).as_posix()
    record: dict[str, object] = {
        "path": relative,
        "mode": stat.S_IMODE(metadata.st_mode),
    }
    if stat.S_ISDIR(metadata.st_mode):
        record["type"] = "directory"
    elif stat.S_ISREG(metadata.st_mode):
        content = path.read_bytes()
        record.update(
            type="file",
            size=len(content),
            sha256=hashlib.sha256(content).hexdigest(),
        )
    elif stat.S_ISLNK(metadata.st_mode):
        record.update(type="symlink", target=os.readlink(path))
    else:
        record["type"] = "other"
    return record


def tree_manifest(root: pathlib.Path) -> list[dict[str, object]]:
    root = root.absolute()
    if not root.is_dir() or root.is_symlink():
        raise ValueError("manifest root must be a real directory")
    paths = [root, *root.rglob("*")]
    paths.sort(
        key=lambda path: "." if path == root else path.relative_to(root).as_posix()
    )
    return [entry_record(root, path) for path in paths]


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: tree_manifest.py DIRECTORY", file=sys.stderr)
        return 2
    try:
        manifest = tree_manifest(pathlib.Path(sys.argv[1]))
    except (OSError, ValueError) as error:
        print(f"tree_manifest: {error}", file=sys.stderr)
        return 1
    canonical = json.dumps(
        manifest, ensure_ascii=True, separators=(",", ":"), sort_keys=True
    )
    print(hashlib.sha256(canonical.encode("utf-8")).hexdigest())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
