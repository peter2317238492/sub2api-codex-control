"""Fail closed when the public source tree contains private or generated data."""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import stat
import subprocess
import sys
from pathlib import Path, PurePosixPath

FORBIDDEN_NAMES = {
    ".appledouble",
    ".DS_Store",
    ".env",
    ".lsoverride",
    "desktop.ini",
    "goal.md",
    "thumbs.db",
}
FORBIDDEN_PARTS = {
    ".cache",
    ".connector-state",
    ".git",
    ".idea",
    ".mypy_cache",
    ".nox",
    ".pnpm-store",
    ".pytest_cache",
    ".ruff_cache",
    ".tox",
    ".venv",
    ".vscode",
    "__pycache__",
    "artifacts",
    "build",
    "credentials",
    "coverage",
    "deployments",
    "dist",
    "evidence",
    "htmlcov",
    "node_modules",
    "private",
    ".private",
    "receipts",
    "reports",
    "secrets",
    "venv",
}
FORBIDDEN_SUFFIXES = {
    ".7z",
    ".db",
    ".dump",
    ".jsonl",
    ".jks",
    ".keystore",
    ".key",
    ".log",
    ".mobileprovision",
    ".p12",
    ".pem",
    ".pfx",
    ".pyc",
    ".pyo",
    ".rdb",
    ".secret",
    ".sqlite",
    ".sqlite3",
    ".tar",
    ".tgz",
    ".token",
    ".zip",
    ".asc",
    ".gpg",
    ".age",
    ".bak",
    ".backup",
    ".receipt.json",
    ".attestation.json",
    ".provenance.json",
    ".spdx.json",
}
FORBIDDEN_TEXT = {
    "non-example home path": re.compile(
        r"(?i)/(?:Users|home)/(?!example(?:/|\b)|alice(?:/|\b)|me(?:/|\b)|test(?:/|\b))[^/\s]+/"
    ),
}
TEXT_BYTES_LIMIT = 8 * 1024 * 1024
BINARY_FILE_SHA256 = {
    "apps/pwa/public/icon-192.png": "e72b29aa445c29b8777654d84168e2c018674fa052dffe0d99c296d9f8a26bd6",
    "apps/pwa/public/icon-512.png": "f4ecb06141bc73b90448ec6774e2d0400f2083efefe6b7ee94cda23d5c064f33",
}
PORTABLE_PATH_RE = re.compile(r"^[A-Za-z0-9._+@/-]+$")
PLACEHOLDER_DIRECTORIES = {
    "deploy/docker-compose/backups": {".gitignore", "readme.md"},
    "deploy/docker-compose/secrets": {".gitignore", "readme.md"},
    "tests/e2e/reports": {".gitignore", "readme.md"},
}


def relative(path: Path, root: Path) -> str:
    return path.relative_to(root).as_posix()


def load_external_literals(path: Path | None) -> tuple[str, ...]:
    if path is None:
        return ()
    if not path.is_absolute():
        raise ValueError("deny literals file must be absolute")
    try:
        metadata = path.stat(follow_symlinks=False)
    except OSError as error:
        raise ValueError("deny literals file cannot be inspected") from error
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise ValueError("deny literals file must be one regular file")
    if metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) != 0o600:
        raise ValueError("deny literals file must be owned by this user with mode 0600")
    try:
        values = tuple(
            value for value in path.read_text(encoding="utf-8").splitlines() if value
        )
    except (OSError, UnicodeDecodeError) as error:
        raise ValueError("deny literals file cannot be read as UTF-8") from error
    if not values:
        raise ValueError("deny literals file is empty")
    if any(len(value) < 4 or len(value) > 4096 for value in values):
        raise ValueError("deny literals must contain between 4 and 4096 characters")
    return values


def path_policy_failures(value: str, *, is_directory: bool) -> list[str]:
    failures: list[str] = []
    folded = value.casefold()
    if (
        not value
        or not value.isascii()
        or PORTABLE_PATH_RE.fullmatch(value) is None
        or "\\" in value
        or value != PurePosixPath(value).as_posix()
        or any(part in {"", ".", ".."} for part in PurePosixPath(value).parts)
    ):
        return ["path is not portable canonical ASCII"]

    parts = folded.split("/")
    name = parts[-1]
    for directory, admitted_names in PLACEHOLDER_DIRECTORIES.items():
        if folded == directory:
            return (
                [] if is_directory else ["reserved placeholder path has the wrong type"]
            )
        prefix = f"{directory}/"
        if folded.startswith(prefix):
            remainder = folded[len(prefix) :]
            if (
                "/" not in remainder
                and remainder in admitted_names
                and not is_directory
            ):
                return []
            return ["runtime-private placeholder directory contains an unadmitted path"]

    if any(part in FORBIDDEN_PARTS for part in parts):
        failures.append("generated/private path component is forbidden")
    if name in {item.casefold() for item in FORBIDDEN_NAMES} or name.startswith("._"):
        failures.append("forbidden private or generated file name")
    env_example = name.endswith(".env.example")
    if not env_example and (
        name == ".env"
        or name.startswith(".env.")
        or name.endswith(".env")
        or ".env." in name
    ):
        failures.append("environment data file is forbidden")
    if re.fullmatch(r"(?:auth-export|credentials).*\.json", name):
        failures.append("credential or authentication export is forbidden")
    if any(name.endswith(suffix) for suffix in FORBIDDEN_SUFFIXES):
        failures.append("generated/private file suffix is forbidden")
    if ".tar." in name:
        failures.append("archive file suffix is forbidden")
    if name.endswith(".tsbuildinfo") or name in {".coverage", "coverage.xml"}:
        failures.append("generated coverage/build file is forbidden")
    if folded == "connector/connector" or folded.startswith("connector/bin/"):
        failures.append("built Connector artifact is forbidden")
    return failures


def _display_path(value: str, deny_literals: tuple[str, ...]) -> tuple[str, bool]:
    folded = value.casefold()
    denied = any(literal.casefold() in folded for literal in deny_literals)
    return ("<redacted-path>" if denied else value, denied)


def _finding(scope: str, display: str, message: str) -> str:
    return f"{scope + ' ' if scope else ''}{display}: {message}"


def scan_bytes(
    value: str,
    raw: bytes,
    deny_literals: tuple[str, ...],
    *,
    scope: str = "",
    include_path_policy: bool = True,
) -> list[str]:
    display, denied_path = _display_path(value, deny_literals)
    failures = [
        _finding(scope, display, message)
        for message in (
            path_policy_failures(value, is_directory=False)
            if include_path_policy
            else []
        )
    ]
    if denied_path:
        failures.append(
            _finding(
                scope, display, "relative path contains an externally denied literal"
            )
        )
    if len(raw) > TEXT_BYTES_LIMIT:
        failures.append(
            _finding(scope, display, "file exceeds the public text size limit")
        )
        return failures
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        expected_binary_digest = BINARY_FILE_SHA256.get(value)
        if (
            expected_binary_digest is None
            or hashlib.sha256(raw).hexdigest() != expected_binary_digest
        ):
            failures.append(
                _finding(
                    scope, display, "non-UTF-8 file is not an admitted binary asset"
                )
            )
        return failures
    for label, pattern in FORBIDDEN_TEXT.items():
        if pattern.search(text):
            failures.append(_finding(scope, display, f"contains {label}"))
    folded_text = text.casefold()
    if any(literal.casefold() in folded_text for literal in deny_literals):
        failures.append(
            _finding(scope, display, "contains an externally denied literal")
        )
    return failures


def run_git(root: Path, *arguments: str) -> subprocess.CompletedProcess[bytes]:
    environment = {
        key: value for key, value in os.environ.items() if not key.startswith("GIT_")
    }
    environment.update(
        {
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_OPTIONAL_LOCKS": "0",
            "LC_ALL": "C",
        }
    )
    try:
        return subprocess.run(
            ["git", "--no-replace-objects", "-C", str(root), *arguments],
            check=False,
            capture_output=True,
            env=environment,
        )
    except OSError as error:
        raise RuntimeError(
            "Git cannot be executed for tracked-source scanning"
        ) from error


def _scan_git_entry(
    root: Path,
    raw_path: bytes,
    mode: bytes,
    object_id: bytes,
    scope: str,
    deny_literals: tuple[str, ...],
) -> list[str]:
    try:
        value = raw_path.decode("utf-8")
        oid = object_id.decode("ascii")
    except (UnicodeDecodeError, ValueError):
        return [f"{scope}: tracked path or object ID is not valid UTF-8/ASCII"]
    display, denied_path = _display_path(value, deny_literals)
    failures = [
        _finding(scope, display, message)
        for message in path_policy_failures(value, is_directory=False)
    ]
    if denied_path:
        failures.append(
            _finding(
                scope, display, "relative path contains an externally denied literal"
            )
        )
    if (
        mode not in {b"100644", b"100755"}
        or re.fullmatch(r"[0-9a-f]{40,64}", oid) is None
    ):
        failures.append(
            _finding(scope, display, "tracked entry is not a regular source file")
        )
        return failures
    size_result = run_git(root, "cat-file", "-s", oid)
    try:
        size = int(size_result.stdout.strip()) if size_result.returncode == 0 else -1
    except ValueError:
        size = -1
    if size < 0:
        failures.append(_finding(scope, display, "tracked blob cannot be inspected"))
        return failures
    if size > TEXT_BYTES_LIMIT:
        failures.append(
            _finding(scope, display, "file exceeds the public text size limit")
        )
        return failures
    blob_result = run_git(root, "cat-file", "blob", oid)
    if blob_result.returncode != 0 or len(blob_result.stdout) != size:
        failures.append(
            _finding(scope, display, "tracked blob cannot be read completely")
        )
        return failures
    failures.extend(
        scan_bytes(
            value,
            blob_result.stdout,
            deny_literals,
            scope=scope,
            include_path_policy=False,
        )
    )
    return failures


def scan_git_sources(root: Path, deny_literals: tuple[str, ...]) -> list[str]:
    marker = root / ".git"
    try:
        marker.lstat()
    except FileNotFoundError:
        return []
    except OSError:
        return ["Git metadata cannot be inspected"]
    try:
        repository = run_git(root, "rev-parse", "--is-inside-work-tree")
    except RuntimeError as error:
        return [str(error)]
    if repository.returncode != 0 or repository.stdout.strip() != b"true":
        return ["Git metadata exists but is not a readable worktree"]

    failures: list[str] = []
    index = run_git(root, "ls-files", "--stage", "-z")
    if index.returncode != 0:
        failures.append("Git index cannot be enumerated")
    else:
        for item in index.stdout.split(b"\0"):
            if not item:
                continue
            try:
                metadata, raw_path = item.split(b"\t", 1)
                mode, object_id, stage = metadata.split(b" ", 2)
            except ValueError:
                failures.append("Git index contains a malformed entry")
                continue
            if stage != b"0":
                failures.append("Git index contains an unresolved entry")
                continue
            failures.extend(
                _scan_git_entry(
                    root, raw_path, mode, object_id, "Git index", deny_literals
                )
            )

    head = run_git(root, "rev-parse", "--verify", "-q", "HEAD^{commit}")
    if head.returncode not in {0, 1}:
        failures.append("Git HEAD cannot be resolved")
    elif head.returncode == 0:
        commit = head.stdout.strip()
        tree = run_git(
            root, "ls-tree", "-r", "-z", "--full-tree", commit.decode("ascii")
        )
        if tree.returncode != 0:
            failures.append("Git HEAD tree cannot be enumerated")
        else:
            for item in tree.stdout.split(b"\0"):
                if not item:
                    continue
                try:
                    metadata, raw_path = item.split(b"\t", 1)
                    mode, object_type, object_id = metadata.split(b" ", 2)
                except ValueError:
                    failures.append("Git HEAD contains a malformed entry")
                    continue
                if object_type != b"blob":
                    failures.append("Git HEAD contains a non-blob source entry")
                    continue
                failures.extend(
                    _scan_git_entry(
                        root, raw_path, mode, object_id, "Git HEAD", deny_literals
                    )
                )
    return failures


def scan(root: Path, deny_literals: tuple[str, ...] = ()) -> list[str]:
    failures: list[str] = []
    if not root.is_absolute() or not root.is_dir():
        return ["root must be an existing absolute directory"]

    def traversal_error(error: OSError) -> None:
        failures.append(
            f"directory traversal failed: {error.strerror or error.__class__.__name__}"
        )

    for current, directories, filenames in os.walk(
        root, followlinks=False, onerror=traversal_error
    ):
        current_path = Path(current)
        directories.sort()
        filenames.sort()
        admitted_directories: list[str] = []
        for name in directories:
            path = current_path / name
            rel = relative(path, root)
            display, denied_path = _display_path(rel, deny_literals)
            if current_path == root and name == ".git":
                try:
                    metadata = path.lstat()
                except OSError:
                    failures.append("Git metadata cannot be inspected")
                else:
                    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(
                        metadata.st_mode
                    ):
                        failures.append(
                            "Git metadata must be a real directory or worktree file"
                        )
                continue
            try:
                metadata = path.lstat()
            except OSError:
                failures.append(f"{display}: cannot inspect path metadata")
                continue
            if stat.S_ISLNK(metadata.st_mode):
                failures.append(f"{display}: symbolic links are forbidden")
                if denied_path:
                    failures.append(
                        f"{display}: relative path contains an externally denied literal"
                    )
                continue
            if not stat.S_ISDIR(metadata.st_mode):
                failures.append(
                    f"{display}: only regular files and directories are allowed"
                )
                if denied_path:
                    failures.append(
                        f"{display}: relative path contains an externally denied literal"
                    )
                continue
            path_failures = path_policy_failures(rel, is_directory=True)
            failures.extend(_finding("", display, message) for message in path_failures)
            if denied_path:
                failures.append(
                    _finding(
                        "",
                        display,
                        "relative path contains an externally denied literal",
                    )
                )
            if path_failures or denied_path:
                continue
            admitted_directories.append(name)
        directories[:] = admitted_directories

        for name in filenames:
            path = current_path / name
            rel = relative(path, root)
            display, denied_path = _display_path(rel, deny_literals)
            if current_path == root and name == ".git":
                try:
                    metadata = path.lstat()
                except OSError:
                    failures.append("Git metadata cannot be inspected")
                else:
                    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(
                        metadata.st_mode
                    ):
                        failures.append(
                            "Git metadata must be a real directory or worktree file"
                        )
                continue
            try:
                metadata = path.lstat()
            except OSError:
                failures.append(f"{display}: cannot inspect path metadata")
                continue
            if stat.S_ISLNK(metadata.st_mode):
                failures.append(f"{display}: symbolic links are forbidden")
                if denied_path:
                    failures.append(
                        f"{display}: relative path contains an externally denied literal"
                    )
                continue
            if not stat.S_ISREG(metadata.st_mode):
                failures.append(
                    f"{display}: only regular files and directories are allowed"
                )
                if denied_path:
                    failures.append(
                        f"{display}: relative path contains an externally denied literal"
                    )
                continue
            if metadata.st_nlink != 1:
                failures.append(f"{display}: hard-linked files are forbidden")
            if metadata.st_size > TEXT_BYTES_LIMIT:
                failures.extend(
                    _finding("", display, message)
                    for message in path_policy_failures(rel, is_directory=False)
                )
                failures.append(f"{display}: file exceeds the public text size limit")
                continue
            try:
                raw = path.read_bytes()
            except OSError:
                failures.append(f"{display}: cannot read file")
                continue
            if len(raw) != metadata.st_size:
                failures.append(f"{display}: file changed while being scanned")
                continue
            failures.extend(scan_bytes(rel, raw, deny_literals))

    failures.extend(scan_git_sources(root, deny_literals))
    return failures


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", nargs="?", default=Path(__file__).resolve().parents[1])
    parser.add_argument("--deny-literals-file", type=Path)
    args = parser.parse_args()
    root = Path(args.root).resolve()
    try:
        literals = load_external_literals(args.deny_literals_file)
    except (OSError, UnicodeDecodeError, ValueError) as error:
        print(f"public-tree: {error}", file=sys.stderr)
        return 1
    failures = scan(root, literals)
    for failure in failures:
        print(f"public-tree: {failure}", file=sys.stderr)
    if failures:
        return 1
    print("public-tree: clean")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
