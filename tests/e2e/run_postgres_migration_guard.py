from __future__ import annotations

import asyncio
import importlib.util
import os
import re
import sys
import types
import urllib.parse
from pathlib import Path
from types import TracebackType
from typing import Any, Self


class Raises:
    def __init__(self, expected: type[BaseException], match: str | None) -> None:
        self.expected = expected
        self.match = match

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exception_type: type[BaseException] | None,
        exception: BaseException | None,
        traceback: TracebackType | None,
    ) -> bool:
        del traceback
        if exception_type is None or exception is None:
            raise AssertionError(f"expected {self.expected.__name__} to be raised")
        if not issubclass(exception_type, self.expected):
            return False
        if self.match is not None and re.search(self.match, str(exception)) is None:
            raise AssertionError(
                f"exception {exception!r} did not match expected pattern {self.match!r}"
            )
        return True


class Mark:
    @staticmethod
    def skipif(condition: bool, *, reason: str) -> tuple[bool, str]:
        return condition, reason


def install_pytest_contract() -> None:
    module = types.ModuleType("pytest")
    module.__dict__["mark"] = Mark()
    module.__dict__["raises"] = lambda expected, match=None: Raises(expected, match)
    sys.modules["pytest"] = module


def database_dsn() -> str:
    password_file = Path(os.environ["CONTROL_DATABASE_PASSWORD_FILE"])
    password = urllib.parse.quote(
        password_file.read_text(encoding="utf-8").strip(), safe=""
    )
    user = urllib.parse.quote(
        os.environ.get("CONTROL_DB_USER", "codex_control"), safe=""
    )
    host = os.environ.get("CONTROL_DB_HOST", "postgres")
    port = os.environ.get("CONTROL_DB_PORT", "5432")
    database = urllib.parse.quote(
        os.environ.get("CONTROL_DB_NAME", "codex_control"), safe=""
    )
    return f"postgresql://{user}:{password}@{host}:{port}/{database}"


def load_test(path: Path) -> Any:
    spec = importlib.util.spec_from_file_location("e2e_postgres_migration_guard", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load migration guard test from {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: run_postgres_migration_guard.py TEST_FILE", file=sys.stderr)
        return 2
    os.environ["CONTROL_TEST_POSTGRES_DSN"] = database_dsn()
    install_pytest_contract()
    module = load_test(Path(sys.argv[1]))
    asyncio.run(module.test_real_postgres_upgrade_and_downgrade_cursor_guards())
    asyncio.run(module.test_real_postgres_owner_cursor_blocks_reverse_commit())
    asyncio.run(module.test_real_postgres_device_send_barrier_serializes_revocation())
    asyncio.run(module.test_real_postgres_snapshot_barrier_catches_late_event_once())
    asyncio.run(
        module.test_real_postgres_owner_capacity_serializes_last_slot_across_devices()
    )
    asyncio.run(
        module.test_real_postgres_catchup_share_lock_blocks_retention_floor_advance()
    )
    asyncio.run(
        module.test_real_postgres_retention_preserves_unacked_and_fk_audit_history()
    )
    print(
        "Real PostgreSQL migration guards, cursor ordering, device send/revoke "
        "serialization, owner capacity, retention-floor locking, and "
        "terminal-state retention passed."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
