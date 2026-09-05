#!/usr/bin/env python3
"""Create fail-closed restore, isolation, writer-freeze, and reverse receipts."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import secrets
import stat
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, NoReturn


SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
IMAGE_ID_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,62}$")
CONTAINER_ID_RE = re.compile(r"^[0-9a-f]{64}$")
MAX_JSON_BYTES = 32 * 1024 * 1024
MAX_SECRET_BYTES = 65_536
RECEIPT_VERSION = 1
RESTORE_TYPE = "production-isolated-restore-v1"
ISOLATION_TYPE = "production-datastore-isolation-v1"
REVERSE_PLAN_TYPE = "production-bounded-reverse-plan-v1"
WRITER_UNFREEZE_PLAN_TYPE = "production-writer-unfreeze-plan-v1"
WRITER_FREEZE_TYPE = "production-writer-freeze-v1"
WRITER_UNFREEZE_PROOF_TYPE = "production-writer-unfreeze-proof-v1"
WRITER_SERVICES = ("control-api-replica", "control-api")
POST_UNFREEZE_VERIFY_TIMEOUT_SECONDS = 120
POST_REVERSE_VERIFY_TIMEOUT_SECONDS = 120


class RecoveryError(RuntimeError):
    """A deliberately low-detail recovery admission failure."""


def fail(message: str) -> NoReturn:
    raise RecoveryError(message)


def utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as source:
            for block in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(block)
    except OSError:
        fail(f"cannot hash {path.name}")
    return digest.hexdigest()


def private_regular_bytes(
    path: Path,
    label: str,
    *,
    expected_uid: int,
    max_bytes: int = MAX_JSON_BYTES,
    accepted_modes: frozenset[int] = frozenset({0o600}),
) -> bytes:
    if not path.is_absolute():
        fail(f"{label} path must be absolute")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        before = path.lstat()
        descriptor = os.open(path, flags)
    except OSError:
        fail(f"{label} is not accessible")
    try:
        opened = os.fstat(descriptor)
        if (
            stat.S_ISLNK(before.st_mode)
            or not stat.S_ISREG(opened.st_mode)
            or (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino)
            or opened.st_uid != expected_uid
            or stat.S_IMODE(opened.st_mode) not in accepted_modes
            or opened.st_nlink != 1
            or opened.st_size <= 0
            or opened.st_size > max_bytes
        ):
            fail(f"{label} must be one private regular file")
        content = bytearray()
        while len(content) <= max_bytes:
            block = os.read(descriptor, min(131_072, max_bytes + 1 - len(content)))
            if not block:
                break
            content.extend(block)
        if len(content) > max_bytes:
            fail(f"{label} is too large")
        after = os.fstat(descriptor)
        signature = lambda value: (
            value.st_dev,
            value.st_ino,
            value.st_mode,
            value.st_uid,
            value.st_gid,
            value.st_size,
            value.st_mtime_ns,
            value.st_ctime_ns,
        )
        if signature(opened) != signature(after):
            fail(f"{label} changed while it was read")
        return bytes(content)
    finally:
        os.close(descriptor)


def load_private_json(path: Path, label: str, *, expected_uid: int) -> tuple[dict[str, Any], bytes]:
    raw = private_regular_bytes(path, label, expected_uid=expected_uid)
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        fail(f"{label} is not valid JSON")
    if not isinstance(value, dict):
        fail(f"{label} must be a JSON object")
    return value, raw


def private_secret(path: Path | None, label: str, *, expected_uid: int) -> bytes:
    if path is None:
        return b""
    raw = private_regular_bytes(
        path, label, expected_uid=expected_uid, max_bytes=MAX_SECRET_BYTES,
        accepted_modes=frozenset({0o400, 0o600}),
    ).rstrip(b"\r\n")
    if not raw or b"\x00" in raw or b"\r" in raw or b"\n" in raw:
        fail(f"{label} must contain one non-empty line")
    return raw


def private_directory(path: Path, label: str, *, expected_uid: int) -> None:
    if not path.is_absolute():
        fail(f"{label} path must be absolute")
    try:
        metadata = path.lstat()
    except OSError:
        fail(f"{label} is not accessible")
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != expected_uid
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        fail(f"{label} must be a private directory owned by UID {expected_uid}")


def write_receipt(path: Path, value: dict[str, Any], *, expected_uid: int) -> None:
    if not path.is_absolute():
        fail("receipt path must be absolute")
    private_directory(path.parent, "receipt parent", expected_uid=expected_uid)
    payload = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode(
        "utf-8"
    )
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError:
        fail("refusing to replace or follow the receipt path")
    try:
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                fail("could not write receipt")
            view = view[written:]
        os.fsync(descriptor)
    except BaseException:
        try:
            path.unlink()
        except OSError:
            pass
        raise
    finally:
        os.close(descriptor)
    parent = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(parent)
    finally:
        os.close(parent)


def run(
    command: list[str],
    *,
    label: str,
    input_bytes: bytes | None = None,
    check: bool = True,
    timeout: int = 60,
) -> subprocess.CompletedProcess[bytes]:
    try:
        result = subprocess.run(
            command,
            input=input_bytes,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=timeout,
            env={
                **os.environ,
                "LC_ALL": "C",
                "LANG": "C",
                "PGPASSWORD": "",
                "REDISCLI_AUTH": "",
            },
        )
    except (OSError, subprocess.TimeoutExpired):
        fail(f"failed during {label}")
    if check and result.returncode != 0:
        fail(f"failed during {label}")
    if len(result.stdout) > MAX_JSON_BYTES or len(result.stderr) > MAX_JSON_BYTES:
        fail(f"output exceeded the limit during {label}")
    return result


def docker_exec_with_password(
    docker: str,
    container: str,
    password: bytes,
    command: list[str],
    *,
    label: str,
    check: bool = True,
) -> subprocess.CompletedProcess[bytes]:
    shell = r"""
set -eu
IFS= read -r credential || credential=
if [ -n "$credential" ]; then
  export PGPASSWORD="$credential"
  export REDISCLI_AUTH="$credential"
else
  unset PGPASSWORD REDISCLI_AUTH 2>/dev/null || true
fi
exec "$@"
"""
    return run(
        [docker, "exec", "-i", container, "sh", "-c", shell, "recovery", *command],
        label=label,
        input_bytes=password + b"\n",
        check=check,
    )


def scalar(result: subprocess.CompletedProcess[bytes], label: str) -> str:
    try:
        value = result.stdout.decode("utf-8").strip()
    except UnicodeDecodeError:
        fail(f"{label} returned non-UTF-8 output")
    if not value or "\n" in value or "\r" in value or len(value) > 4096:
        fail(f"{label} did not return one scalar")
    return value


def validate_backup_binding(
    args: argparse.Namespace,
) -> tuple[dict[str, Any], str, Path, str, str]:
    admission, admission_raw = load_private_json(
        args.backup_admission,
        "full backup admission",
        expected_uid=args.expected_owner_uid,
    )
    if (
        admission.get("status") != "admitted"
        or admission.get("fresh") is not True
        or admission.get("admission_mode") != "fresh-production-backup"
        or admission.get("owner_uid") != args.expected_owner_uid
    ):
        fail("normal deployment requires one fresh root-owned full backup admission")
    receipt_path_value = admission.get("receipt_path")
    receipt_sha256 = admission.get("receipt_sha256")
    manifest_sha256 = admission.get("manifest_sha256")
    snapshot_value = admission.get("snapshot_directory")
    if (
        not isinstance(receipt_path_value, str)
        or not isinstance(receipt_sha256, str)
        or SHA256_RE.fullmatch(receipt_sha256) is None
        or not isinstance(manifest_sha256, str)
        or SHA256_RE.fullmatch(manifest_sha256) is None
        or not isinstance(snapshot_value, str)
        or not Path(snapshot_value).is_absolute()
    ):
        fail("full backup admission has invalid bindings")
    receipt_path = Path(receipt_path_value)
    receipt_raw = private_regular_bytes(
        receipt_path,
        "full backup receipt",
        expected_uid=args.expected_owner_uid,
    )
    if sha256_bytes(receipt_raw) != receipt_sha256:
        fail("full backup receipt differs from its admission")
    snapshot = Path(snapshot_value)
    private_directory(snapshot, "full backup snapshot", expected_uid=args.expected_owner_uid)
    manifest = snapshot / "manifest.sha256"
    manifest_raw = private_regular_bytes(
        manifest,
        "full backup manifest",
        expected_uid=args.expected_owner_uid,
        max_bytes=16 * 1024 * 1024,
    )
    if sha256_bytes(manifest_raw) != manifest_sha256:
        fail("full backup manifest differs from its admission")
    required = {
        "sub2api-postgres.dump",
        "postgres-additional-databases.json",
        "redis-logical.rdb",
        "release-records.tar.gz",
        "release-records-inventory.json",
        "release-evidence-inventory.json",
        "docker-network-inspect.json",
        "docker-networks.json",
    }
    artifacts = admission.get("artifacts")
    if not isinstance(artifacts, dict) or not required.issubset(artifacts):
        fail("full backup admission omits a recovery domain")
    for name in required:
        item = artifacts.get(name)
        path = snapshot / name
        if (
            not isinstance(item, dict)
            or not isinstance(item.get("sha256"), str)
            or item.get("sha256") != sha256_file(path)
        ):
            fail("one full backup artifact differs from its admission")
    return admission, sha256_bytes(admission_raw), snapshot, receipt_sha256, manifest_sha256


def validate_identifier(value: Any, label: str) -> str:
    if not isinstance(value, str) or IDENTIFIER_RE.fullmatch(value) is None:
        fail(f"{label} is not one safe identifier")
    return value


def plan_datastores(plan: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    datastores = plan.get("datastores")
    if not isinstance(datastores, dict):
        fail("deployment plan has no admitted datastore projection")
    postgres = datastores.get("postgres")
    redis = datastores.get("redis")
    if not isinstance(postgres, dict) or not isinstance(redis, dict):
        fail("deployment plan datastore projection is invalid")
    validate_identifier(postgres.get("role"), "Control PostgreSQL role")
    validate_identifier(postgres.get("database"), "Control PostgreSQL database")
    validate_identifier(postgres.get("sub2api_database"), "Sub2API PostgreSQL database")
    if postgres["database"] == postgres["sub2api_database"]:
        fail("Control and Sub2API databases must differ")
    if (
        redis.get("auth_mode") != "password"
        or not isinstance(redis.get("user"), str)
        or redis.get("user") in {"", "default"}
        or not isinstance(redis.get("prefix"), str)
        or not redis["prefix"]
        or any(character.isspace() for character in redis["prefix"])
    ):
        fail("deployment plan does not use a dedicated authenticated Redis namespace")
    return postgres, redis


def remove_and_prove_absent(docker: str, names: list[str], volumes: list[str]) -> None:
    for name in names:
        run([docker, "rm", "-f", "--volumes", name], label="isolated restore cleanup", check=False)
    result = run(
        [docker, "container", "ls", "--all", "--format", "{{.Names}}"],
        label="isolated restore cleanup proof",
    )
    try:
        remaining = set(result.stdout.decode("utf-8").splitlines())
    except UnicodeDecodeError:
        fail("isolated restore cleanup proof is not UTF-8")
    if remaining.intersection(names):
        fail("one isolated restore container remains after cleanup")
    for volume in volumes:
        run([docker, "volume", "rm", volume], label="isolated restore volume cleanup", check=False)
    result = run(
        [docker, "volume", "ls", "--format", "{{.Name}}"],
        label="isolated restore volume cleanup proof",
    )
    if set(result.stdout.decode("utf-8").splitlines()).intersection(volumes):
        fail("one isolated restore volume remains after cleanup")


def wait_for_command(command: list[str], *, label: str, timeout_seconds: int) -> None:
    deadline = time.monotonic() + timeout_seconds
    while True:
        result = run(command, label=label, check=False, timeout=10)
        if result.returncode == 0:
            return
        if time.monotonic() >= deadline:
            fail(f"timed out during {label}")
        time.sleep(1)


def isolated_restore(args: argparse.Namespace) -> dict[str, Any]:
    admission, admission_sha256, snapshot, receipt_sha256, manifest_sha256 = (
        validate_backup_binding(args)
    )
    containers = admission.get("containers")
    if not isinstance(containers, dict):
        fail("full backup admission has no container identities")
    try:
        postgres_image = containers["postgres"]["image_id"]
        redis_image = containers["redis"]["image_id"]
    except (KeyError, TypeError):
        fail("full backup admission has no datastore image identities")
    if (
        not isinstance(postgres_image, str)
        or IMAGE_ID_RE.fullmatch(postgres_image) is None
        or not isinstance(redis_image, str)
        or IMAGE_ID_RE.fullmatch(redis_image) is None
    ):
        fail("full backup datastore image identities are invalid")
    additional, _ = load_private_json(
        snapshot / "postgres-additional-databases.json",
        "additional PostgreSQL database inventory",
        expected_uid=args.expected_owner_uid,
    )
    database_dumps: list[tuple[str, Path]] = [("sub2api_restore", snapshot / "sub2api-postgres.dump")]
    for database, status_value in sorted(additional.items()):
        validate_identifier(database, "additional PostgreSQL database")
        if status_value == "backed_up":
            dump_name = f"postgres-{database}.dump"
            if dump_name not in admission.get("artifacts", {}):
                fail("additional PostgreSQL database dump is absent from the admission")
            database_dumps.append((f"restore_{database}", snapshot / dump_name))
        elif status_value != "absent":
            fail("additional PostgreSQL database inventory is invalid")
    token = secrets.token_hex(8)
    postgres_name = f"codex-control-restore-pg-{token}"
    redis_name = f"codex-control-restore-redis-{token}"
    postgres_volume = f"codex-control-restore-data-{token}"
    names = [postgres_name, redis_name]
    if any(character in str(snapshot) for character in (",", "\n", "\r")):
        fail("backup snapshot path is not Docker-mount safe")
    snapshot_mount = f"type=bind,src={snapshot},dst=/restore,readonly"
    started_at = utc_now()
    postgres_results: list[dict[str, Any]] = []
    redis_key_count = -1
    try:
        run(
            [args.docker, "volume", "create", "--label", "com.sub2api-codex.recovery=isolated", postgres_volume],
            label="create isolated PostgreSQL restore volume",
        )
        run(
            [
                args.docker,
                "run",
                "--pull",
                "never",
                "-d",
                "--name",
                postgres_name,
                "--network",
                "none",
                "--read-only",
                "--mount",
                f"type=volume,src={postgres_volume},dst=/var/lib/postgresql",
                "--mount",
                snapshot_mount,
                "--tmpfs",
                "/run/postgresql:rw,nosuid,nodev,mode=0755",
                "--tmpfs",
                "/tmp:rw,noexec,nosuid,nodev,mode=1777",
                "--label",
                "com.sub2api-codex.recovery=isolated",
                "--env",
                "POSTGRES_HOST_AUTH_METHOD=trust",
                "--env",
                "POSTGRES_USER=recovery_admin",
                "--env",
                "PGDATA=/var/lib/postgresql/recovery",
                postgres_image,
            ],
            label="start isolated PostgreSQL restore",
        )
        # The entrypoint's temporary init server only listens on a Unix socket.
        wait_for_command(
            [args.docker, "exec", postgres_name, "pg_isready", "-h", "127.0.0.1", "-U", "recovery_admin", "-d", "postgres"],
            label="isolated PostgreSQL readiness",
            timeout_seconds=args.timeout_seconds,
        )
        disk = run(
            [args.docker, "exec", postgres_name, "df", "-Pk", "/var/lib/postgresql"],
            label="isolated PostgreSQL restore disk budget",
        )
        try:
            available_bytes = int(disk.stdout.decode("ascii").splitlines()[-1].split()[3]) * 1024
        except (UnicodeDecodeError, IndexError, ValueError):
            fail("isolated PostgreSQL restore disk budget is invalid")
        # Compressed dumps need expansion and index space on the Docker disk.
        minimum_bytes = 3 * sum(dump.stat().st_size for _, dump in database_dumps) + 1024**3
        if available_bytes < minimum_bytes:
            fail("insufficient Docker disk space for isolated PostgreSQL restore")
        for database, dump in database_dumps:
            if not dump.is_file() or sha256_file(dump) != admission["artifacts"][dump.name]["sha256"]:
                fail("one PostgreSQL restore artifact differs from the admitted backup")
            run(
                [args.docker, "exec", postgres_name, "createdb", "-U", "recovery_admin", database],
                label="create isolated PostgreSQL restore database",
            )
            run(
                [
                    args.docker,
                    "exec",
                    postgres_name,
                    "pg_restore",
                    "--exit-on-error",
                    "--no-owner",
                    "--no-acl",
                    "--jobs",
                    "2",
                    "-U",
                    "recovery_admin",
                    "-d",
                    database,
                    f"/restore/{dump.name}",
                ],
                label="restore isolated PostgreSQL database",
                timeout=args.timeout_seconds,
            )
            inventory = scalar(
                run(
                    [
                        args.docker,
                        "exec",
                        postgres_name,
                        "psql",
                        "-U",
                        "recovery_admin",
                        "-d",
                        database,
                        "--no-psqlrc",
                        "--tuples-only",
                        "--no-align",
                        "--command",
                        "SELECT count(*)::text || '|' || "
                        "(SELECT count(*) FROM pg_class WHERE relkind IN ('r','p') "
                        "AND relnamespace NOT IN (SELECT oid FROM pg_namespace "
                        "WHERE nspname LIKE 'pg_%' OR nspname='information_schema'))::text || '|' || "
                        "(SELECT count(*) FROM pg_class WHERE relkind='S' "
                        "AND relnamespace NOT IN (SELECT oid FROM pg_namespace "
                        "WHERE nspname LIKE 'pg_%' OR nspname='information_schema'))::text "
                        "FROM pg_namespace WHERE nspname NOT LIKE 'pg_%' "
                        "AND nspname <> 'information_schema'",
                    ],
                    label="inventory isolated PostgreSQL restore",
                ),
                "isolated PostgreSQL inventory",
            )
            pieces = inventory.split("|")
            if len(pieces) != 3 or any(not item.isdigit() for item in pieces):
                fail("isolated PostgreSQL inventory is invalid")
            postgres_results.append(
                {
                    "database": database,
                    "dump": dump.name,
                    "dump_sha256": admission["artifacts"][dump.name]["sha256"],
                    "schema_count": int(pieces[0]),
                    "table_count": int(pieces[1]),
                    "sequence_count": int(pieces[2]),
                }
            )

        run(
            [
                args.docker,
                "run",
                "--pull",
                "never",
                "-d",
                "--name",
                redis_name,
                "--network",
                "none",
                "--read-only",
                "--tmpfs",
                "/data:rw,nosuid,nodev,mode=0700",
                "--mount",
                snapshot_mount,
                "--tmpfs",
                "/tmp:rw,noexec,nosuid,nodev,mode=1777",
                "--label",
                "com.sub2api-codex.recovery=isolated",
                "--entrypoint",
                "sh",
                redis_image,
                "-c",
                "trap 'exit 0' TERM INT; while :; do sleep 3600 & wait $!; done",
            ],
            label="start isolated Redis restore container",
        )
        redis_dump = snapshot / "redis-logical.rdb"
        if sha256_file(redis_dump) != admission["artifacts"][redis_dump.name]["sha256"]:
            fail("Redis restore artifact differs from the admitted backup")
        run(
            [args.docker, "exec", redis_name, "cp", f"/restore/{redis_dump.name}", "/data/dump.rdb"],
            label="copy isolated Redis restore artifact",
        )
        run(
            [args.docker, "exec", redis_name, "redis-check-rdb", "/data/dump.rdb"],
            label="validate isolated Redis restore artifact",
        )
        run(
            [
                args.docker,
                "exec",
                "-d",
                redis_name,
                "redis-server",
                "--bind",
                "127.0.0.1",
                "--protected-mode",
                "yes",
                "--port",
                "6379",
                "--dir",
                "/data",
                "--dbfilename",
                "dump.rdb",
                "--save",
                "",
                "--appendonly",
                "no",
            ],
            label="load isolated Redis restore",
        )
        wait_for_command(
            [args.docker, "exec", redis_name, "redis-cli", "-h", "127.0.0.1", "--raw", "PING"],
            label="isolated Redis readiness",
            timeout_seconds=args.timeout_seconds,
        )
        redis_size = scalar(
            run(
                [args.docker, "exec", redis_name, "redis-cli", "-h", "127.0.0.1", "--raw", "DBSIZE"],
                label="inventory isolated Redis restore",
            ),
            "isolated Redis inventory",
        )
        if not redis_size.isdigit():
            fail("isolated Redis key count is invalid")
        redis_key_count = int(redis_size)
    finally:
        remove_and_prove_absent(args.docker, names, [postgres_volume])

    receipt = {
        "format_version": RECEIPT_VERSION,
        "type": RESTORE_TYPE,
        "status": "succeeded",
        "started_at": started_at,
        "completed_at": utc_now(),
        "backup_admission_path": str(args.backup_admission),
        "backup_admission_sha256": admission_sha256,
        "backup_receipt_sha256": receipt_sha256,
        "snapshot_directory": str(snapshot),
        "snapshot_manifest_sha256": manifest_sha256,
        "isolation": {
            "docker_network_mode": "none",
            "published_ports": 0,
            "temporary_containers_removed": True,
        },
        "postgresql": {
            "image_id": postgres_image,
            "restore_completed": True,
            "databases": postgres_results,
        },
        "redis": {
            "image_id": redis_image,
            "restore_completed": True,
            "rdb_sha256": admission["artifacts"]["redis-logical.rdb"]["sha256"],
            "key_count": redis_key_count,
        },
    }
    write_receipt(args.output, receipt, expected_uid=args.expected_owner_uid)
    return receipt


def pg_scalar(
    args: argparse.Namespace,
    password: bytes,
    user: str,
    database: str,
    sql: str,
    label: str,
    *,
    check: bool = True,
) -> subprocess.CompletedProcess[bytes]:
    return docker_exec_with_password(
        args.docker,
        args.postgres_container,
        password,
        [
            "psql",
            "--username",
            user,
            "--dbname",
            database,
            "--no-psqlrc",
            "--set",
            "ON_ERROR_STOP=1",
            "--tuples-only",
            "--no-align",
            "--command",
            sql,
        ],
        label=label,
        check=check,
    )


def redis_command(
    args: argparse.Namespace,
    password: bytes,
    user: str,
    command: list[str],
    label: str,
    *,
    check: bool = True,
) -> subprocess.CompletedProcess[bytes]:
    return docker_exec_with_password(
        args.docker,
        args.redis_container,
        password,
        ["redis-cli", "--user", user, "--no-auth-warning", "--raw", *command],
        label=label,
        check=check,
    )


def expect_pg_scalar(
    args: argparse.Namespace,
    password: bytes,
    user: str,
    database: str,
    sql: str,
    expected: str,
    label: str,
) -> None:
    value = scalar(pg_scalar(args, password, user, database, sql, label), label)
    if value != expected:
        fail(f"{label} did not prove the required boundary")


def live_isolation(args: argparse.Namespace) -> dict[str, Any]:
    admission, admission_sha256, _, receipt_sha256, manifest_sha256 = (
        validate_backup_binding(args)
    )
    plan, plan_raw = load_private_json(
        args.plan, "deployment plan", expected_uid=args.expected_owner_uid
    )
    postgres, redis = plan_datastores(plan)
    control_role = postgres["role"]
    control_database = postgres["database"]
    sub2api_database = postgres["sub2api_database"]
    control_redis_user = redis["user"]
    redis_prefix = redis["prefix"]
    admin_pg_password = private_secret(
        args.postgres_admin_password_file,
        "PostgreSQL administrative password",
        expected_uid=args.expected_owner_uid,
    )
    control_pg_password = private_secret(
        args.control_postgres_password_file,
        "Control PostgreSQL password",
        expected_uid=args.expected_owner_uid,
    )
    admin_redis_password = private_secret(
        args.redis_admin_password_file,
        "Redis administrative password",
        expected_uid=args.expected_owner_uid,
    )
    control_redis_password = private_secret(
        args.control_redis_password_file,
        "Control Redis password",
        expected_uid=args.expected_owner_uid,
    )

    quoted_role = control_role.replace("'", "''")
    quoted_control_db = control_database.replace("'", "''")
    quoted_sub2api_db = sub2api_database.replace("'", "''")
    admin_db = args.postgres_admin_database
    expect_pg_scalar(
        args,
        admin_pg_password,
        args.postgres_admin_user,
        admin_db,
        "SELECT (rolcanlogin AND NOT rolsuper AND NOT rolcreatedb AND NOT rolcreaterole "
        "AND NOT rolinherit AND NOT rolreplication AND NOT rolbypassrls)::text "
        f"FROM pg_roles WHERE rolname='{quoted_role}'",
        "true",
        "Control PostgreSQL role flags",
    )
    expect_pg_scalar(
        args,
        admin_pg_password,
        args.postgres_admin_user,
        admin_db,
        "SELECT count(*)::text FROM pg_auth_members membership "
        "JOIN pg_roles member_role ON member_role.oid=membership.member "
        "JOIN pg_roles granted_role ON granted_role.oid=membership.roleid "
        f"WHERE member_role.rolname='{quoted_role}' OR granted_role.rolname='{quoted_role}'",
        "0",
        "Control PostgreSQL role memberships",
    )
    expect_pg_scalar(
        args,
        admin_pg_password,
        args.postgres_admin_user,
        admin_db,
        "SELECT (pg_get_userbyid(datdba)='" + quoted_role + "' AND "
        "NOT EXISTS (SELECT 1 FROM aclexplode(COALESCE(datacl, acldefault('d', datdba))) acl "
        "WHERE acl.grantee=0 AND acl.privilege_type IN ('CONNECT','TEMPORARY')))::text "
        f"FROM pg_database WHERE datname='{quoted_control_db}'",
        "true",
        "Control PostgreSQL database ownership and PUBLIC ACL",
    )
    expect_pg_scalar(
        args,
        admin_pg_password,
        args.postgres_admin_user,
        admin_db,
        "SELECT (NOT EXISTS (SELECT 1 FROM aclexplode(COALESCE(datacl, acldefault('d', datdba))) acl "
        "WHERE acl.grantee=0 AND acl.privilege_type='CONNECT') AND "
        "NOT has_database_privilege('" + quoted_role + "', datname, 'CONNECT'))::text "
        f"FROM pg_database WHERE datname='{quoted_sub2api_db}'",
        "true",
        "Sub2API PostgreSQL database isolation",
    )
    expect_pg_scalar(
        args,
        admin_pg_password,
        args.postgres_admin_user,
        control_database,
        "SELECT (pg_get_userbyid(nspowner)='" + quoted_role + "' AND "
        "NOT EXISTS (SELECT 1 FROM aclexplode(COALESCE(nspacl, acldefault('n', nspowner))) acl "
        "WHERE acl.grantee=0 AND acl.privilege_type IN ('USAGE','CREATE')))::text "
        "FROM pg_namespace WHERE nspname='public'",
        "true",
        "Control PostgreSQL schema ownership and PUBLIC ACL",
    )
    expect_pg_scalar(
        args,
        admin_pg_password,
        args.postgres_admin_user,
        control_database,
        "SELECT ((SELECT count(*) FROM pg_class class JOIN pg_namespace namespace "
        "ON namespace.oid=class.relnamespace WHERE namespace.nspname='public' "
        "AND class.relkind IN ('r','p','S','v','m') "
        "AND pg_get_userbyid(class.relowner) <> '" + quoted_role + "') + "
        "(SELECT count(*) FROM pg_proc procedure JOIN pg_namespace namespace "
        "ON namespace.oid=procedure.pronamespace WHERE namespace.nspname='public' "
        "AND pg_get_userbyid(procedure.proowner) <> '" + quoted_role + "') + "
        "(SELECT count(*) FROM pg_type type JOIN pg_namespace namespace "
        "ON namespace.oid=type.typnamespace WHERE namespace.nspname='public' "
        "AND pg_get_userbyid(type.typowner) <> '" + quoted_role + "'))::text",
        "0",
        "Control PostgreSQL object ownership",
    )
    own_connection = scalar(
        pg_scalar(
            args,
            control_pg_password,
            control_role,
            control_database,
            "SELECT current_user || '|' || current_database()",
            "Control PostgreSQL positive connection",
        ),
        "Control PostgreSQL positive connection",
    )
    if own_connection != f"{control_role}|{control_database}":
        fail("Control PostgreSQL positive connection returned another identity")
    denied_connection = pg_scalar(
        args,
        control_pg_password,
        control_role,
        sub2api_database,
        "SELECT 1",
        "Control PostgreSQL denied Sub2API connection",
        check=False,
    )
    if denied_connection.returncode == 0:
        fail("Control PostgreSQL role connected to the Sub2API database")

    acl_result = redis_command(
        args,
        admin_redis_password,
        args.redis_admin_user,
        ["ACL", "LIST"],
        "Redis ACL inventory",
    )
    try:
        acl_lines = acl_result.stdout.decode("utf-8").splitlines()
    except UnicodeDecodeError:
        fail("Redis ACL inventory is not UTF-8")
    acl_users: dict[str, set[str]] = {}
    for line in acl_lines:
        parts = line.split()
        if len(parts) < 3 or parts[0] != "user" or parts[1] in acl_users:
            fail("Redis ACL inventory is malformed or contains a duplicate user")
        acl_users[parts[1]] = set(parts[2:])
    if not acl_users or any(
        "on" in user_tokens and "nopass" in user_tokens
        for user_tokens in acl_users.values()
    ):
        fail("Redis has an enabled nopass user")
    selected = [
        line.split()
        for line in acl_lines
        if line.startswith(f"user {control_redis_user} ")
    ]
    if len(selected) != 1:
        fail("Redis ACL inventory has no unique dedicated Control user")
    tokens = selected[0]
    expected_tokens = {
        "on",
        f"~{redis_prefix}*",
        f"&{redis_prefix}*",
        "-@all",
        "+ping",
        "+get",
        "+set",
        "+del",
        "+incrby",
        "+expire",
        "+eval",
        "+publish",
        "+subscribe",
        "+unsubscribe",
        "+client|setinfo",
    }
    # Redis normalizes INCR to INCRBY in ACL LIST on supported releases.
    normalized = {"+incrby" if token == "+incr" else token for token in tokens[2:]}
    password_hashes = {token for token in normalized if token.startswith("#")}
    # These Redis 7+ tokens describe the reset/default hardening state.
    non_password_tokens = normalized - password_hashes - {"sanitize-payload", "resetchannels"}
    if (
        len(password_hashes) != 1
        or not all(re.fullmatch(r"#[0-9a-f]{64}", item) for item in password_hashes)
        or non_password_tokens != expected_tokens
        or "nopass" in normalized
        or "+@all" in normalized
    ):
        fail("dedicated Control Redis ACL is not exact")

    aclfile_result = redis_command(
        args,
        admin_redis_password,
        args.redis_admin_user,
        ["CONFIG", "GET", "aclfile"],
        "Redis ACL persistence configuration",
    )
    try:
        aclfile_lines = aclfile_result.stdout.decode("utf-8").splitlines()
    except UnicodeDecodeError:
        fail("Redis ACL persistence configuration is not UTF-8")
    if (
        len(aclfile_lines) != 2
        or aclfile_lines[0] != "aclfile"
        or not aclfile_lines[1]
    ):
        fail("Redis has no configured ACL persistence file")

    anonymous_ping = docker_exec_with_password(
        args.docker,
        args.redis_container,
        b"",
        ["redis-cli", "--no-auth-warning", "--raw", "PING"],
        label="anonymous Redis denial",
        check=False,
    )
    anonymous_output = anonymous_ping.stdout + anonymous_ping.stderr
    if b"NOAUTH" not in anonymous_output or b"PONG" in anonymous_ping.stdout:
        fail("Redis accepts an unauthenticated command")

    if scalar(
        redis_command(
            args,
            control_redis_password,
            control_redis_user,
            ["PING"],
            "Control Redis positive authentication",
        ),
        "Control Redis positive authentication",
    ) != "PONG":
        fail("dedicated Control Redis user did not authenticate")
    probe_token = secrets.token_hex(8)
    inside_key = f"{redis_prefix}isolation-probe-{probe_token}"
    probe_value = "recovery-isolation"
    if scalar(
        redis_command(
            args,
            control_redis_password,
            control_redis_user,
            ["SET", inside_key, probe_value, "EX", "30"],
            "Control Redis prefix write",
        ),
        "Control Redis prefix write",
    ) != "OK":
        fail("dedicated Control Redis user cannot write inside its prefix")
    if scalar(
        redis_command(
            args,
            control_redis_password,
            control_redis_user,
            ["GET", inside_key],
            "Control Redis prefix read",
        ),
        "Control Redis prefix read",
    ) != probe_value:
        fail("dedicated Control Redis user cannot read inside its prefix")
    if scalar(
        redis_command(
            args,
            control_redis_password,
            control_redis_user,
            ["DEL", inside_key],
            "Control Redis prefix cleanup",
        ),
        "Control Redis prefix cleanup",
    ) != "1":
        fail("dedicated Control Redis isolation probe could not be removed")
    outside_leader = "?" if redis_prefix.startswith("!") else "!"
    outside_key = f"{outside_leader}recovery-isolation-denied:{probe_token}"
    outside_read = redis_command(
        args,
        control_redis_password,
        control_redis_user,
        ["GET", outside_key],
        "Control Redis outside-prefix denial",
        check=False,
    )
    if b"NOPERM" not in outside_read.stdout + outside_read.stderr:
        fail("dedicated Control Redis user can read outside its prefix")
    outside_write = redis_command(
        args,
        control_redis_password,
        control_redis_user,
        ["SET", outside_key, "denied"],
        "Control Redis outside-prefix write denial",
        check=False,
    )
    if b"NOPERM" not in outside_write.stdout + outside_write.stderr:
        fail("dedicated Control Redis user can write outside its prefix")
    inside_publish = redis_command(
        args,
        control_redis_password,
        control_redis_user,
        ["PUBLISH", f"{redis_prefix}isolation-probe-{probe_token}", probe_value],
        "Control Redis prefix channel publish",
    )
    if not scalar(inside_publish, "Control Redis prefix channel publish").isdigit():
        fail("dedicated Control Redis user cannot publish inside its prefix")
    outside_publish = redis_command(
        args,
        control_redis_password,
        control_redis_user,
        ["PUBLISH", outside_key, "denied"],
        "Control Redis outside-prefix channel denial",
        check=False,
    )
    if b"NOPERM" not in outside_publish.stdout + outside_publish.stderr:
        fail("dedicated Control Redis user can publish outside its prefix")
    administrative = redis_command(
        args,
        control_redis_password,
        control_redis_user,
        ["CONFIG", "GET", "dir"],
        "Control Redis administrative denial",
        check=False,
    )
    if b"NOPERM" not in administrative.stdout + administrative.stderr:
        fail("dedicated Control Redis user retains an administrative command")

    receipt = {
        "format_version": RECEIPT_VERSION,
        "type": ISOLATION_TYPE,
        "status": "passed",
        "completed_at": utc_now(),
        "deployment_plan_sha256": sha256_bytes(plan_raw),
        "backup_admission_sha256": admission_sha256,
        "backup_receipt_sha256": receipt_sha256,
        "snapshot_manifest_sha256": manifest_sha256,
        "postgresql": {
            "container": args.postgres_container,
            "admin_database": admin_db,
            "control_role": control_role,
            "control_database": control_database,
            "sub2api_database": sub2api_database,
            "role_flags_exact": True,
            "membership_count": 0,
            "database_owner_exact": True,
            "schema_and_object_owners_exact": True,
            "public_connect_revoked": True,
            "control_to_sub2api_connect_denied": True,
            "control_positive_connection": True,
        },
        "redis": {
            "container": args.redis_container,
            "control_user": control_redis_user,
            "prefix": redis_prefix,
            "authenticated": True,
            "acl_exact": True,
            "aclfile_configured": True,
            "anonymous_access_denied": True,
            "enabled_nopass_users_absent": True,
            "inside_prefix_read_write_passed": True,
            "outside_prefix_read_denied": True,
            "outside_prefix_write_denied": True,
            "inside_channel_publish_passed": True,
            "outside_channel_publish_denied": True,
            "administrative_command_denied": True,
        },
    }
    write_receipt(args.output, receipt, expected_uid=args.expected_owner_uid)
    return receipt


def current_control_identities(
    path: Path, *, expected_uid: int
) -> tuple[dict[str, dict[str, Any]], bytes]:
    raw = private_regular_bytes(
        path, "current Control container inspection", expected_uid=expected_uid
    )
    try:
        values = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        fail("current Control container inspection is not valid JSON")
    if not isinstance(values, list):
        fail("current Control container inspection must be a JSON array")
    result: dict[str, dict[str, Any]] = {}
    allowed = {"control-api", "control-api-replica", "codex-pwa"}
    for value in values:
        if not isinstance(value, dict):
            fail("one current Control container inspection is invalid")
        labels = value.get("Config", {}).get("Labels")
        service = labels.get("com.docker.compose.service") if isinstance(labels, dict) else None
        if service not in allowed:
            fail("one current Control container is not an admitted rollback service")
        identifier = value.get("Id")
        image_id = value.get("Image")
        running = value.get("State", {}).get("Running")
        started_at = value.get("State", {}).get("StartedAt")
        restart_count = value.get("RestartCount")
        if (
            service in result
            or not isinstance(identifier, str)
            or CONTAINER_ID_RE.fullmatch(identifier) is None
            or not isinstance(image_id, str)
            or IMAGE_ID_RE.fullmatch(image_id) is None
            or type(running) is not bool
            or not isinstance(started_at, str)
            or not started_at
            or type(restart_count) is not int
            or restart_count < 0
        ):
            fail("one current Control container identity is invalid")
        result[service] = {
            "container_id": identifier,
            "image_id": image_id,
            "running": running,
            "started_at": started_at,
            "restart_count": restart_count,
        }
    return result, raw


def writer_steps(current: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "ordinal": ordinal,
            "action": (
                "require-absent"
                if prior is None
                else (
                    "start-exact-prior-container"
                    if prior["running"]
                    else "keep-exact-prior-container-stopped"
                )
            ),
            "service": service,
            "previous": prior,
            "max_attempts": 1,
            "timeout_seconds": 60,
        }
        for ordinal, service in enumerate(WRITER_SERVICES, start=1)
        for prior in (current.get(service),)
    ]


def writer_unfreeze_plan(args: argparse.Namespace) -> dict[str, Any]:
    current, current_raw = current_control_identities(
        args.current_control_containers, expected_uid=args.expected_owner_uid
    )
    steps = writer_steps(current)
    value = {
        "format_version": RECEIPT_VERSION,
        "type": WRITER_UNFREEZE_PLAN_TYPE,
        "status": "admitted",
        "created_at": utc_now(),
        "limits": {
            "max_steps": len(WRITER_SERVICES),
            "max_attempts_per_step": 1,
            "total_timeout_seconds": args.total_timeout_seconds,
            "post_unfreeze_verification_timeout_seconds": (
                POST_UNFREEZE_VERIFY_TIMEOUT_SECONDS
            ),
            "database_restore_allowed": False,
            "exact_container_ids_required": True,
        },
        "bindings": {
            "current_control_containers_sha256": sha256_bytes(current_raw),
        },
        "steps": steps,
    }
    required_timeout = (
        sum(step["timeout_seconds"] for step in steps)
        + POST_UNFREEZE_VERIFY_TIMEOUT_SECONDS
    )
    if required_timeout != args.total_timeout_seconds:
        fail("writer unfreeze plan must exactly cover every bounded action")
    write_receipt(args.output, value, expected_uid=args.expected_owner_uid)
    return value


def writer_state_matches(
    previous: dict[str, Any], stopped: dict[str, Any]
) -> bool:
    return (
        stopped.get("container_id") == previous.get("container_id")
        and stopped.get("image_id") == previous.get("image_id")
        and stopped.get("running") is False
        and stopped.get("started_at") == previous.get("started_at")
        and stopped.get("restart_count") == previous.get("restart_count")
    )


def validate_stopped_writers(
    current: dict[str, dict[str, Any]],
    observed: dict[str, dict[str, Any]],
    label: str,
) -> None:
    if set(observed) - set(WRITER_SERVICES):
        fail(f"{label} contains a non-writer Control service")
    for service in WRITER_SERVICES:
        previous = current.get(service)
        stopped = observed.get(service)
        if previous is None:
            if stopped is not None:
                fail(f"{label} created a previously absent writer")
        elif stopped is None or not writer_state_matches(previous, stopped):
            fail(f"{label} does not preserve one exact stopped writer identity")


def writer_freeze_receipt(args: argparse.Namespace) -> dict[str, Any]:
    current, current_raw = current_control_identities(
        args.current_control_containers, expected_uid=args.expected_owner_uid
    )
    stopped_before, stopped_before_raw = current_control_identities(
        args.stopped_before_backup, expected_uid=args.expected_owner_uid
    )
    stopped_after, stopped_after_raw = current_control_identities(
        args.stopped_after_backup, expected_uid=args.expected_owner_uid
    )
    unfreeze, unfreeze_raw = load_private_json(
        args.unfreeze_plan,
        "writer unfreeze plan",
        expected_uid=args.expected_owner_uid,
    )
    expected_steps = writer_steps(current)
    if (
        unfreeze.get("format_version") != RECEIPT_VERSION
        or unfreeze.get("type") != WRITER_UNFREEZE_PLAN_TYPE
        or unfreeze.get("status") != "admitted"
        or unfreeze.get("bindings", {}).get("current_control_containers_sha256")
        != sha256_bytes(current_raw)
        or unfreeze.get("steps") != expected_steps
        or unfreeze.get("limits", {}).get("database_restore_allowed") is not False
        or unfreeze.get("limits", {}).get("exact_container_ids_required") is not True
    ):
        fail("writer unfreeze plan is not bound to the exact prior containers")
    validate_stopped_writers(current, stopped_before, "pre-backup writer freeze")
    validate_stopped_writers(current, stopped_after, "post-backup writer freeze")
    if stopped_before != stopped_after:
        fail("one writer identity changed during the final pre-migration backup")
    value = {
        "format_version": RECEIPT_VERSION,
        "type": WRITER_FREEZE_TYPE,
        "status": "passed",
        "completed_at": utc_now(),
        "bindings": {
            "current_control_containers_sha256": sha256_bytes(current_raw),
            "unfreeze_plan_sha256": sha256_bytes(unfreeze_raw),
            "stopped_before_backup_sha256": sha256_bytes(stopped_before_raw),
            "stopped_after_backup_sha256": sha256_bytes(stopped_after_raw),
        },
        "no_write_window": {
            "all_writers_stopped": True,
            "container_restart_observed": False,
            "exact_container_ids_preserved": True,
        },
        "writers": {
            service: {"previous": current.get(service), "stopped": stopped_after.get(service)}
            for service in WRITER_SERVICES
        },
    }
    write_receipt(args.output, value, expected_uid=args.expected_owner_uid)
    return value


def writer_unfreeze_proof(args: argparse.Namespace) -> dict[str, Any]:
    current, current_raw = current_control_identities(
        args.current_control_containers, expected_uid=args.expected_owner_uid
    )
    observed, observed_raw = current_control_identities(
        args.observed_control_containers, expected_uid=args.expected_owner_uid
    )
    unfreeze, unfreeze_raw = load_private_json(
        args.unfreeze_plan,
        "writer unfreeze plan",
        expected_uid=args.expected_owner_uid,
    )
    expected = {service: current[service] for service in WRITER_SERVICES if service in current}
    actual = {service: observed[service] for service in WRITER_SERVICES if service in observed}
    restored_exactly = set(actual) == set(expected)
    for service, previous in expected.items():
        restored = actual.get(service, {})
        restored_exactly = restored_exactly and (
            restored.get("container_id") == previous.get("container_id")
            and restored.get("image_id") == previous.get("image_id")
            and restored.get("running") is previous.get("running")
            and restored.get("restart_count") == previous.get("restart_count")
            and (
                previous.get("running") is True
                or restored.get("started_at") == previous.get("started_at")
            )
        )
    if (
        set(observed) - set(WRITER_SERVICES)
        or not restored_exactly
        or unfreeze.get("type") != WRITER_UNFREEZE_PLAN_TYPE
        or unfreeze.get("status") != "admitted"
        or unfreeze.get("bindings", {}).get("current_control_containers_sha256")
        != sha256_bytes(current_raw)
        or unfreeze.get("steps") != writer_steps(current)
    ):
        fail("writer unfreeze did not restore the exact prior container identities")
    value = {
        "format_version": RECEIPT_VERSION,
        "type": WRITER_UNFREEZE_PROOF_TYPE,
        "status": "passed",
        "completed_at": utc_now(),
        "unfreeze_plan_sha256": sha256_bytes(unfreeze_raw),
        "expected_containers_sha256": sha256_bytes(current_raw),
        "observed_containers_sha256": sha256_bytes(observed_raw),
        "exact_container_ids_restored": True,
        "database_restore_performed": False,
        "writers": actual,
    }
    write_receipt(args.output, value, expected_uid=args.expected_owner_uid)
    return value


def reverse_plan(args: argparse.Namespace) -> dict[str, Any]:
    plan, plan_raw = load_private_json(
        args.plan, "deployment plan", expected_uid=args.expected_owner_uid
    )
    releases, releases_raw = load_private_json(
        args.releases, "release image evidence", expected_uid=args.expected_owner_uid
    )
    revisions, revisions_raw = load_private_json(
        args.revisions, "migration revision evidence", expected_uid=args.expected_owner_uid
    )
    backup, backup_raw = load_private_json(
        args.backup_admission,
        "full backup admission",
        expected_uid=args.expected_owner_uid,
    )
    restore, restore_raw = load_private_json(
        args.restore_receipt,
        "isolated restore receipt",
        expected_uid=args.expected_owner_uid,
    )
    isolation, isolation_raw = load_private_json(
        args.isolation_receipt,
        "datastore isolation receipt",
        expected_uid=args.expected_owner_uid,
    )
    premigration, premigration_raw = load_private_json(
        args.premigration_backup,
        "pre-migration Control backup evidence",
        expected_uid=args.expected_owner_uid,
    )
    if (
        backup.get("fresh") is not True
        or restore.get("type") != RESTORE_TYPE
        or restore.get("status") != "succeeded"
        or restore.get("isolation", {}).get("temporary_containers_removed") is not True
        or isolation.get("type") != ISOLATION_TYPE
        or isolation.get("status") != "passed"
    ):
        fail("reverse plan inputs are not admitted recovery receipts")
    backup_sha = sha256_bytes(backup_raw)
    if (
        restore.get("backup_admission_sha256") != backup_sha
        or isolation.get("backup_admission_sha256") != backup_sha
        or isolation.get("deployment_plan_sha256") != sha256_bytes(plan_raw)
    ):
        fail("recovery receipts are not bound to this deployment")
    current, current_raw = current_control_identities(
        args.current_control_containers, expected_uid=args.expected_owner_uid
    )
    unfreeze, unfreeze_raw = load_private_json(
        args.unfreeze_plan,
        "writer unfreeze plan",
        expected_uid=args.expected_owner_uid,
    )
    freeze, freeze_raw = load_private_json(
        args.writer_freeze_receipt,
        "writer freeze receipt",
        expected_uid=args.expected_owner_uid,
    )
    if (
        unfreeze.get("type") != WRITER_UNFREEZE_PLAN_TYPE
        or unfreeze.get("status") != "admitted"
        or unfreeze.get("bindings", {}).get("current_control_containers_sha256")
        != sha256_bytes(current_raw)
        or unfreeze.get("steps") != writer_steps(current)
        or freeze.get("type") != WRITER_FREEZE_TYPE
        or freeze.get("status") != "passed"
        or freeze.get("bindings", {}).get("current_control_containers_sha256")
        != sha256_bytes(current_raw)
        or freeze.get("bindings", {}).get("unfreeze_plan_sha256")
        != sha256_bytes(unfreeze_raw)
        or freeze.get("no_write_window", {}).get("all_writers_stopped") is not True
        or freeze.get("no_write_window", {}).get("container_restart_observed") is not False
        or freeze.get("no_write_window", {}).get("exact_container_ids_preserved") is not True
    ):
        fail("reverse plan has no exact writer-freeze recovery boundary")
    dump_path_value = premigration.get("dump_path")
    dump_sha256 = premigration.get("dump_sha256")
    if (
        not isinstance(dump_path_value, str)
        or not Path(dump_path_value).is_absolute()
        or not isinstance(dump_sha256, str)
        or SHA256_RE.fullmatch(dump_sha256) is None
        or sha256_file(Path(dump_path_value)) != dump_sha256
    ):
        fail("pre-migration Control backup evidence is invalid")
    try:
        api_image = releases["api"]["image_id"]
        pwa_image = releases["pwa"]["image_id"]
    except (KeyError, TypeError):
        fail("release image evidence has no admitted image identities")
    if IMAGE_ID_RE.fullmatch(str(api_image)) is None or IMAGE_ID_RE.fullmatch(str(pwa_image)) is None:
        fail("release image evidence has invalid image identities")
    source_revision = revisions.get("source_database_revision")
    target_revision = revisions.get("target_migration_head")
    if not isinstance(source_revision, str) or not isinstance(target_revision, str):
        fail("migration revision evidence is invalid")
    services = ("control-api-replica", "control-api", "codex-pwa")
    forward = [
        {
            "ordinal": 1,
            "action": "apply-admitted-migration",
            "from_revision": source_revision,
            "to_revision": target_revision,
            "timeout_seconds": 180,
        }
    ]
    for ordinal, service in enumerate(services, start=2):
        forward.append(
            {
                "ordinal": ordinal,
                "action": "recreate-one-service",
                "service": service,
                "new_image_id": pwa_image if service == "codex-pwa" else api_image,
                "timeout_seconds": 120,
            }
        )
    reverse: list[dict[str, Any]] = [
        {
            "ordinal": 1,
            "action": "stop-database-mutators",
            "services": ["control-api", "control-api-replica", "control-migrate"],
            "max_attempts": 1,
            "timeout_seconds": 105,
        },
        {
            "ordinal": 2,
            "action": "restore-control-database-from-premigration-dump",
            "max_attempts": 1,
            "timeout_seconds": 360,
            "write_freeze_required": True,
            "condition": "database-mutated-and-writers-never-reexposed",
            "dump_path": dump_path_value,
            "dump_sha256": dump_sha256,
        },
    ]
    for ordinal, service in enumerate(reversed(services), start=3):
        prior = current.get(service)
        reverse.append(
            {
                "ordinal": ordinal,
                "action": "recreate-prior-service" if prior else "remove-new-service",
                "service": service,
                "previous": prior,
                "max_attempts": 1,
                "timeout_seconds": 105,
            }
        )
    if len(reverse) > args.max_reverse_steps:
        fail("reverse plan exceeds the admitted step bound")
    reverse_timeout = sum(int(step["timeout_seconds"]) for step in reverse)
    if reverse_timeout + POST_REVERSE_VERIFY_TIMEOUT_SECONDS > args.total_timeout_seconds:
        fail("reverse plan exceeds the admitted total timeout")
    value = {
        "format_version": RECEIPT_VERSION,
        "type": REVERSE_PLAN_TYPE,
        "status": "admitted",
        "created_at": utc_now(),
        "limits": {
            "max_reverse_steps": args.max_reverse_steps,
            "max_attempts_per_step": 1,
            "total_timeout_seconds": args.total_timeout_seconds,
            "post_reverse_verification_timeout_seconds": (
                POST_REVERSE_VERIFY_TIMEOUT_SECONDS
            ),
            "automatic_reverse_on_failure": True,
            "database_restore_requires_write_freeze": True,
            "database_restore_policy": (
                "only-before-writer-exposure-after-observed-mutation"
            ),
            "writer_exposure_after_database_mutation_allowed": False,
            "application_reverse_preserves_database": True,
            "migration_required": source_revision != target_revision,
        },
        "bindings": {
            "deployment_plan_sha256": sha256_bytes(plan_raw),
            "release_images_sha256": sha256_bytes(releases_raw),
            "revisions_sha256": sha256_bytes(revisions_raw),
            "premigration_backup_sha256": sha256_bytes(premigration_raw),
            "full_backup_admission_sha256": backup_sha,
            "isolated_restore_receipt_sha256": sha256_bytes(restore_raw),
            "datastore_isolation_receipt_sha256": sha256_bytes(isolation_raw),
            "writer_unfreeze_plan_sha256": sha256_bytes(unfreeze_raw),
            "writer_freeze_receipt_sha256": sha256_bytes(freeze_raw),
            "current_control_containers_sha256": sha256_bytes(current_raw),
        },
        "forward_steps": forward,
        "reverse_steps": reverse,
    }
    rollback_compose, _ = load_private_json(
        args.compose_config,
        "resolved Compose config",
        expected_uid=args.expected_owner_uid,
    )
    services_value = rollback_compose.get("services")
    if not isinstance(services_value, dict):
        fail("resolved Compose config has no services")
    for service in ("control-api", "control-api-replica", "codex-pwa"):
        service_value = services_value.get(service)
        if not isinstance(service_value, dict):
            fail("resolved Compose config omits one rollback service")
        prior = current.get(service)
        if prior is not None:
            service_value["image"] = prior["image_id"]
    write_receipt(
        args.rollback_compose_output,
        rollback_compose,
        expected_uid=args.expected_owner_uid,
    )
    value["bindings"]["rollback_compose_sha256"] = sha256_file(
        args.rollback_compose_output
    )
    write_receipt(args.output, value, expected_uid=args.expected_owner_uid)
    return value


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)

    def common_receipt(command: argparse.ArgumentParser) -> None:
        command.add_argument("--backup-admission", required=True, type=Path)
        command.add_argument("--output", required=True, type=Path)
        command.add_argument("--expected-owner-uid", type=int, default=0)

    restore = commands.add_parser("isolated-restore")
    common_receipt(restore)
    restore.add_argument("--docker", default="docker")
    restore.add_argument("--timeout-seconds", type=int, default=120)
    restore.set_defaults(handler=isolated_restore)

    isolation = commands.add_parser("live-isolation")
    common_receipt(isolation)
    isolation.add_argument("--plan", required=True, type=Path)
    isolation.add_argument("--docker", default="docker")
    isolation.add_argument("--postgres-container", required=True)
    isolation.add_argument("--postgres-admin-user", required=True)
    isolation.add_argument("--postgres-admin-database", required=True)
    isolation.add_argument("--postgres-admin-password-file", type=Path)
    isolation.add_argument("--control-postgres-password-file", required=True, type=Path)
    isolation.add_argument("--redis-container", required=True)
    isolation.add_argument("--redis-admin-user", required=True)
    isolation.add_argument("--redis-admin-password-file", type=Path)
    isolation.add_argument("--control-redis-password-file", required=True, type=Path)
    isolation.set_defaults(handler=live_isolation)

    unfreeze = commands.add_parser("writer-unfreeze-plan")
    unfreeze.add_argument("--current-control-containers", required=True, type=Path)
    unfreeze.add_argument("--output", required=True, type=Path)
    unfreeze.add_argument("--expected-owner-uid", type=int, default=0)
    unfreeze.add_argument("--total-timeout-seconds", type=int, default=240)
    unfreeze.set_defaults(handler=writer_unfreeze_plan)

    freeze = commands.add_parser("writer-freeze-receipt")
    freeze.add_argument("--current-control-containers", required=True, type=Path)
    freeze.add_argument("--stopped-before-backup", required=True, type=Path)
    freeze.add_argument("--stopped-after-backup", required=True, type=Path)
    freeze.add_argument("--unfreeze-plan", required=True, type=Path)
    freeze.add_argument("--output", required=True, type=Path)
    freeze.add_argument("--expected-owner-uid", type=int, default=0)
    freeze.set_defaults(handler=writer_freeze_receipt)

    unfreeze_proof = commands.add_parser("writer-unfreeze-proof")
    unfreeze_proof.add_argument("--current-control-containers", required=True, type=Path)
    unfreeze_proof.add_argument("--observed-control-containers", required=True, type=Path)
    unfreeze_proof.add_argument("--unfreeze-plan", required=True, type=Path)
    unfreeze_proof.add_argument("--output", required=True, type=Path)
    unfreeze_proof.add_argument("--expected-owner-uid", type=int, default=0)
    unfreeze_proof.set_defaults(handler=writer_unfreeze_proof)

    plan = commands.add_parser("reverse-plan")
    common_receipt(plan)
    plan.add_argument("--plan", required=True, type=Path)
    plan.add_argument("--releases", required=True, type=Path)
    plan.add_argument("--revisions", required=True, type=Path)
    plan.add_argument("--premigration-backup", required=True, type=Path)
    plan.add_argument("--restore-receipt", required=True, type=Path)
    plan.add_argument("--isolation-receipt", required=True, type=Path)
    plan.add_argument("--unfreeze-plan", required=True, type=Path)
    plan.add_argument("--writer-freeze-receipt", required=True, type=Path)
    plan.add_argument("--current-control-containers", required=True, type=Path)
    plan.add_argument("--compose-config", required=True, type=Path)
    plan.add_argument("--rollback-compose-output", required=True, type=Path)
    plan.add_argument("--max-reverse-steps", type=int, default=5)
    plan.add_argument("--total-timeout-seconds", type=int, default=900)
    plan.set_defaults(handler=reverse_plan)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    os.umask(0o077)
    if args.expected_owner_uid < 0 or os.geteuid() != args.expected_owner_uid:
        fail(f"recovery admission must run as UID {args.expected_owner_uid}")
    if not 0 < getattr(args, "timeout_seconds", 1) <= 86400:
        fail("restore timeout must be between 1 and 86400 seconds")
    if not 0 < getattr(args, "max_reverse_steps", 1) <= 8:
        fail("reverse step bound must be between 1 and 8")
    if not 0 < getattr(args, "total_timeout_seconds", 1) <= 900:
        fail("reverse timeout bound must be between 1 and 900 seconds")
    value = args.handler(args)
    print(json.dumps(value, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except RecoveryError as error:
        print(f"production-recovery: {error}", file=sys.stderr)
        raise SystemExit(1) from None
