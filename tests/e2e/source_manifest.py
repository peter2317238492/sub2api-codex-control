from __future__ import annotations

import hashlib
import pathlib
import sys

INPUTS = (
    "apps/control-api/README.md",
    "apps/control-api/pyproject.toml",
    "apps/control-api/src",
    "apps/pwa/index.html",
    "apps/pwa/package.json",
    "apps/pwa/public",
    "apps/pwa/src",
    "apps/pwa/tsconfig.json",
    "apps/pwa/vite.config.ts",
    "connector",
    "deploy",
    "migrations",
    "packages/appserver-schema",
    "packages/control-protocol",
    "tests/e2e",
    ".env.example",
    "package.json",
    "pnpm-lock.yaml",
    "pnpm-workspace.yaml",
    "tsconfig.base.json",
    "versions.lock.json",
)
EXCLUDED_PARTS = {
    ".pytest_cache",
    ".ruff_cache",
    "__pycache__",
    "dist",
    "node_modules",
    "reports",
}


def source_files(root: pathlib.Path) -> list[pathlib.Path]:
    files: list[pathlib.Path] = []
    for entry in INPUTS:
        path = root / entry
        if not path.exists():
            raise FileNotFoundError(f"source-manifest input is missing: {entry}")
        if path.is_file():
            files.append(path)
            continue
        for candidate in path.rglob("*"):
            relative = candidate.relative_to(root)
            if any(part in EXCLUDED_PARTS for part in relative.parts):
                continue
            if candidate.is_file() and not candidate.is_symlink():
                files.append(candidate)
    return sorted(set(files), key=lambda item: item.relative_to(root).as_posix())


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: source_manifest.py REPOSITORY_ROOT", file=sys.stderr)
        return 2
    root = pathlib.Path(sys.argv[1]).resolve()
    digest = hashlib.sha256()
    for path in source_files(root):
        relative = path.relative_to(root).as_posix().encode("utf-8")
        digest.update(len(relative).to_bytes(8, "big"))
        digest.update(relative)
        digest.update((path.stat().st_mode & 0o777).to_bytes(2, "big"))
        content = path.read_bytes()
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)
    print(digest.hexdigest())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
