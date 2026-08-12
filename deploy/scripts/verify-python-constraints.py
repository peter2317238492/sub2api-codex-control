from __future__ import annotations

import importlib.metadata
import re
import sys
from pathlib import Path


def canonical_name(value: str) -> str:
    return re.sub(r"[-_.]+", "-", value).lower()


def load_constraints(path: Path) -> dict[str, str]:
    expected: dict[str, str] = {}
    for line_number, raw_line in enumerate(path.read_text().splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if "==" not in line:
            raise ValueError(
                f"{path}:{line_number}: only exact == constraints are allowed"
            )
        name, version = line.split("==", 1)
        expected[canonical_name(name)] = version
    return expected


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: verify-python-constraints.py CONSTRAINT_FILE", file=sys.stderr)
        return 2

    expected = load_constraints(Path(sys.argv[1]))
    ignored = {"pip", "setuptools", "sub2api-codex-control-api"}
    installed = {
        canonical_name(distribution.metadata["Name"]): distribution.version
        for distribution in importlib.metadata.distributions()
        if canonical_name(distribution.metadata["Name"]) not in ignored
    }

    missing = sorted(set(expected) - set(installed))
    unexpected = sorted(set(installed) - set(expected))
    mismatched = sorted(
        name
        for name in set(expected) & set(installed)
        if expected[name] != installed[name]
    )
    if not missing and not unexpected and not mismatched:
        print(f"Verified {len(expected)} exact Python runtime dependencies.")
        return 0

    if missing:
        print(f"missing: {', '.join(missing)}", file=sys.stderr)
    if unexpected:
        print(f"unexpected: {', '.join(unexpected)}", file=sys.stderr)
    for name in mismatched:
        print(
            f"version mismatch: {name} expected {expected[name]} installed {installed[name]}",
            file=sys.stderr,
        )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
