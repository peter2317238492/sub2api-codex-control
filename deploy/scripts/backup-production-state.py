#!/usr/bin/env python3
"""Create one fail-closed snapshot before the first production mutation."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import BinaryIO, NoReturn


class BackupError(RuntimeError):
    """A deliberately low-detail production backup failure."""


def fail(message: str) -> NoReturn:
    raise BackupError(message)


def private_directory(path: Path, label: str) -> None:
    try:
        info = path.lstat()
    except OSError:
        fail(f"{label} is not accessible")
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        fail(f"{label} must be a real directory")
    if info.st_uid != os.geteuid():
        fail(f"{label} must be owned by the runtime UID")
    if stat.S_IMODE(info.st_mode) != 0o700:
        fail(f"{label} mode must be exactly 0700")


def private_secret(path: Path, label: str) -> bytes:
    try:
        info = path.lstat()
    except OSError:
        fail(f"{label} is not accessible")
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        fail(f"{label} must be a real regular file")
    if info.st_uid not in {0, os.geteuid()} or stat.S_IMODE(info.st_mode) & 0o077:
        fail(f"{label} ownership or mode is not private")
    if info.st_size <= 0 or info.st_size > 65_536:
        fail(f"{label} size is invalid")
    try:
        value = path.read_bytes()
    except OSError:
        fail(f"{label} cannot be read")
    value = value.rstrip(b"\r\n")
    if not value or b"\x00" in value or b"\r" in value or b"\n" in value:
        fail(f"{label} must contain one non-empty line")
    return value


def source_path(path: Path, label: str, *, directory: bool | None = None) -> None:
    if not path.is_absolute():
        fail(f"{label} must be absolute")
    try:
        info = path.lstat()
    except OSError:
        fail(f"{label} is not accessible")
    if stat.S_ISLNK(info.st_mode):
        fail(f"{label} must not be a symlink")
    if directory is True and not stat.S_ISDIR(info.st_mode):
        fail(f"{label} must be a directory")
    if directory is False and not stat.S_ISREG(info.st_mode):
        fail(f"{label} must be a regular file")


def require_command(value: str, label: str) -> str:
    if os.path.sep in value:
        candidate = Path(value)
        if not candidate.is_file() or not os.access(candidate, os.X_OK):
            fail(f"{label} is not executable")
        return str(candidate)
    resolved = shutil.which(value)
    if resolved is None:
        fail(f"{label} is required")
    return resolved


def open_private(path: Path) -> BinaryIO:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    return os.fdopen(descriptor, "wb")


def run_capture(
    command: list[str],
    *,
    stage: str,
    input_bytes: bytes | None = None,
    output: Path | None = None,
) -> bytes:
    try:
        if output is None:
            result = subprocess.run(
                command,
                input=input_bytes,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                check=False,
            )
            payload = result.stdout
        else:
            with open_private(output) as destination:
                result = subprocess.run(
                    command,
                    input=input_bytes,
                    stdout=destination,
                    stderr=subprocess.DEVNULL,
                    check=False,
                )
                destination.flush()
                os.fsync(destination.fileno())
            payload = b""
    except (OSError, ValueError):
        fail(f"failed during {stage}")
    if result.returncode != 0:
        if output is not None:
            output.unlink(missing_ok=True)
        fail(f"failed during {stage}")
    return payload


def write_bytes(path: Path, value: bytes) -> None:
    with open_private(path) as destination:
        destination.write(value)
        destination.flush()
        os.fsync(destination.fileno())


def write_json(path: Path, value: object) -> None:
    write_bytes(
        path,
        (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8"),
    )


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def require_nonempty(path: Path, label: str) -> None:
    try:
        info = path.lstat()
    except OSError:
        fail(f"{label} was not created")
    if not stat.S_ISREG(info.st_mode) or info.st_size <= 0:
        fail(f"{label} is empty or invalid")
    os.chmod(path, 0o600)


def container_identity(docker: str, name: str, label: str) -> dict[str, str]:
    template = "{{.Id}}|{{.Image}}|{{.Name}}|{{.State.Running}}|{{.State.Pid}}"
    raw = run_capture(
        [docker, "inspect", "--type", "container", "--format", template, name],
        stage=f"{label} container inspection",
    )
    try:
        container_id, image_id, actual_name, running, pid = (
            raw.decode("utf-8").strip().split("|")
        )
    except (UnicodeDecodeError, ValueError):
        fail(f"{label} container inspection was invalid")
    if running != "true" or not container_id or not image_id or not pid.isdecimal():
        fail(f"{label} container is not running")
    return {
        "container_id": container_id,
        "image_id": image_id,
        "name": actual_name.removeprefix("/"),
        "pid": pid,
    }


def validate_postgres_dump(
    docker: str,
    container: str,
    dump: Path,
    listing: Path,
    pg_restore: str | None,
    stage: str,
) -> None:
    if pg_restore is not None:
        run_capture(
            [pg_restore, "--list", str(dump)],
            output=listing,
            stage=stage,
        )
    else:
        try:
            with dump.open("rb") as source, open_private(listing) as destination:
                result = subprocess.run(
                    [docker, "exec", "-i", container, "pg_restore", "--list"],
                    stdin=source,
                    stdout=destination,
                    stderr=subprocess.DEVNULL,
                    check=False,
                )
                destination.flush()
                os.fsync(destination.fileno())
        except OSError:
            fail(f"failed during {stage}")
        if result.returncode != 0:
            listing.unlink(missing_ok=True)
            fail(f"failed during {stage}")
    require_nonempty(listing, "PostgreSQL pg_restore listing")


def running_executable_evidence(proc_root: Path, pid: int) -> dict[str, object]:
    executable = proc_root / str(pid) / "exe"
    observations: list[dict[str, object]] = []
    for _ in range(2):
        try:
            target = os.readlink(executable)
            info_before = executable.stat()
            digest = sha256(executable)
            info_after = executable.stat()
        except OSError:
            fail("running Sub2API executable is not readable from host procfs")
        if (info_before.st_dev, info_before.st_ino, info_before.st_size) != (
            info_after.st_dev,
            info_after.st_ino,
            info_after.st_size,
        ):
            fail("running Sub2API executable changed during backup")
        observations.append(
            {
                "target": target,
                "sha256": digest,
                "device": info_after.st_dev,
                "inode": info_after.st_ino,
                "size": info_after.st_size,
            }
        )
    if observations[0] != observations[1]:
        fail("running Sub2API executable evidence was not stable")
    return {"pid": pid, "proc_path": str(executable), "observations": observations}


def password_input(path: Path | None, label: str) -> bytes:
    if path is None:
        return b"\n"
    return private_secret(path, label) + b"\n"


POSTGRES_DUMP_SCRIPT = r"""
set -eu
IFS= read -r PGPASSWORD
if [ -n "$PGPASSWORD" ]; then export PGPASSWORD; else unset PGPASSWORD; fi
exec pg_dump --username "$1" --dbname "$2" --format=custom --compress=9
"""


POSTGRES_GLOBALS_SCRIPT = r"""
set -eu
IFS= read -r PGPASSWORD
if [ -n "$PGPASSWORD" ]; then export PGPASSWORD; else unset PGPASSWORD; fi
exec pg_dumpall --username "$1" --globals-only --no-role-passwords
"""


POSTGRES_METADATA_SCRIPT = r"""
set -eu
IFS= read -r PGPASSWORD
if [ -n "$PGPASSWORD" ]; then export PGPASSWORD; else unset PGPASSWORD; fi
exec psql --no-psqlrc --no-align --tuples-only --username "$1" --dbname "$2" \
  --command "SELECT current_database(), current_setting('server_version'), pg_get_userbyid(datdba), datacl FROM pg_database WHERE datname = current_database();"
"""


POSTGRES_DATABASE_EXISTS_SCRIPT = r"""
set -eu
IFS= read -r PGPASSWORD
if [ -n "$PGPASSWORD" ]; then export PGPASSWORD; else unset PGPASSWORD; fi
exec psql --no-psqlrc --no-align --tuples-only --username "$1" --dbname postgres \
  --command "SELECT EXISTS (SELECT 1 FROM pg_database WHERE datname = '$2');"
"""


REDIS_COMMAND_SCRIPT = r"""
set -eu
IFS= read -r REDISCLI_AUTH
if [ -n "$REDISCLI_AUTH" ]; then export REDISCLI_AUTH; else unset REDISCLI_AUTH; fi
exec redis-cli --raw --user "$1" -h 127.0.0.1 -p "$2" "$3" ${4+"$4"}
"""


REDIS_METADATA_SCRIPT = r"""
set -eu
IFS= read -r REDISCLI_AUTH
if [ -n "$REDISCLI_AUTH" ]; then export REDISCLI_AUTH; else unset REDISCLI_AUTH; fi
redis_cli() { redis-cli --raw --user "$1" -h 127.0.0.1 -p "$2" "$3" ${4+"$4"}; }
redis_cli "$1" "$2" INFO persistence
redis_cli "$1" "$2" CONFIG GET dir
redis_cli "$1" "$2" CONFIG GET dbfilename
redis_cli "$1" "$2" CONFIG GET appendonly
redis_cli "$1" "$2" CONFIG GET appenddirname
redis_cli "$1" "$2" CONFIG GET aclfile
redis_cli "$1" "$2" ACL LIST
"""


REDIS_SNAPSHOT_SCRIPT = r"""
set -eu
IFS= read -r REDISCLI_AUTH
if [ -n "$REDISCLI_AUTH" ]; then export REDISCLI_AUTH; else unset REDISCLI_AUTH; fi
temporary=$(mktemp /tmp/sub2api-control-rdb.XXXXXX)
trap 'rm -f "$temporary"' EXIT HUP INT TERM
redis-cli --raw --user "$1" -h 127.0.0.1 -p "$2" --rdb "$temporary" >/dev/null
test -s "$temporary"
cat "$temporary"
"""


REDIS_VALIDATE_SCRIPT = r"""
set -eu
temporary=$(mktemp /tmp/sub2api-control-rdb-check.XXXXXX)
trap 'rm -f "$temporary"' EXIT HUP INT TERM
cat > "$temporary"
test -s "$temporary"
exec redis-check-rdb "$temporary"
"""


SUB2API_RUNTIME_ARCHIVE_SCRIPT = r"""
set -eu
exec tar -C / -cf - app/sub2api
"""


def validate_redis_rdb(docker: str, container: str, rdb: Path, validation: Path) -> str:
    try:
        with rdb.open("rb") as source, open_private(validation) as destination:
            result = subprocess.run(
                [docker, "exec", "-i", container, "sh", "-c", REDIS_VALIDATE_SCRIPT],
                stdin=source,
                stdout=destination,
                stderr=subprocess.DEVNULL,
                check=False,
            )
            destination.flush()
            os.fsync(destination.fileno())
    except OSError:
        fail("failed during Redis RDB validation")
    if result.returncode == 0:
        require_nonempty(validation, "Redis RDB validation")
        return "redis-check-rdb"
    validation.unlink(missing_ok=True)

    local_validator = shutil.which("redis-check-rdb")
    if local_validator is not None:
        run_capture(
            [local_validator, str(rdb)],
            stage="Redis RDB validation",
            output=validation,
        )
        require_nonempty(validation, "Redis RDB validation")
        return "local redis-check-rdb"
    fail("Redis RDB validation requires redis-check-rdb")


def tar_listing_is_safe(path: Path) -> None:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError):
        fail("tar listing is not valid UTF-8 metadata")
    if not lines:
        fail("tar listing is empty")
    for name in lines:
        normalized = name.removeprefix("./")
        if name.startswith("/") or ".." in Path(normalized).parts:
            fail("tar listing contains an unsafe member")


def relative_archive_name(path: Path) -> str:
    return str(path).removeprefix("/")


def parse_nginx_tls_paths(configuration: Path) -> tuple[list[Path], list[Path]]:
    certificates: set[Path] = set()
    keys: set[Path] = set()
    pattern = re.compile(
        r"^\s*(ssl_certificate|ssl_trusted_certificate|ssl_client_certificate|ssl_certificate_key)\s+(.+?)\s*;\s*$"
    )
    try:
        lines = configuration.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError):
        fail("Nginx effective configuration is unreadable")
    for line in lines:
        match = pattern.match(line)
        if match is None:
            continue
        try:
            values = shlex.split(match.group(2))
        except ValueError:
            fail("Nginx TLS path syntax is invalid")
        if len(values) != 1 or "$" in values[0]:
            fail("Nginx TLS path must be one static path")
        selected = Path(values[0])
        if not selected.is_absolute():
            fail("Nginx TLS path must be absolute")
        if match.group(1) == "ssl_certificate_key":
            keys.add(selected)
        else:
            certificates.add(selected)
    if not certificates or not keys:
        fail("Nginx effective configuration has no complete TLS certificate pair")
    return sorted(certificates), sorted(keys)


def file_metadata(path: Path, *, include_sha256: bool) -> dict[str, object]:
    try:
        link_info = path.lstat()
        resolved = path.resolve(strict=True)
        target_info = resolved.stat()
    except OSError:
        fail("one Nginx TLS file is not accessible")
    if not stat.S_ISREG(target_info.st_mode):
        fail("one Nginx TLS target is not a regular file")
    value: dict[str, object] = {
        "path": str(path),
        "is_symlink": stat.S_ISLNK(link_info.st_mode),
        "resolved_path": str(resolved),
        "mode": f"{stat.S_IMODE(target_info.st_mode):04o}",
        "uid": target_info.st_uid,
        "gid": target_info.st_gid,
        "size": target_info.st_size,
        "mtime_ns": target_info.st_mtime_ns,
    }
    if include_sha256:
        value["sha256"] = sha256(resolved)
    return value


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Create and validate a comprehensive production preflight backup."
    )
    parser.add_argument("--backup-root", required=True, type=Path)
    parser.add_argument("--result-file", type=Path)
    parser.add_argument("--sub2api-container", required=True)
    parser.add_argument("--postgres-container", required=True)
    parser.add_argument("--postgres-user", required=True)
    parser.add_argument("--postgres-database", required=True)
    parser.add_argument("--additional-postgres-database", action="append", default=[])
    parser.add_argument("--postgres-password-file", type=Path)
    parser.add_argument("--redis-container", required=True)
    parser.add_argument("--redis-user", required=True)
    parser.add_argument("--redis-port", type=int, default=6379)
    parser.add_argument("--redis-password-file", type=Path)
    parser.add_argument("--redis-data-path", default="/data")
    parser.add_argument("--sub2api-data", required=True, type=Path)
    parser.add_argument("--sub2api-config", required=True, type=Path)
    parser.add_argument("--sub2api-compose", required=True, type=Path)
    parser.add_argument("--sub2api-environment", required=True, type=Path)
    parser.add_argument("--nginx-config", required=True, type=Path)
    parser.add_argument("--proc-root", type=Path, default=Path("/proc"))
    parser.add_argument("--docker", default="docker")
    parser.add_argument("--pg-restore")
    parser.add_argument("--tar", default="tar")
    parser.add_argument("--nginx", default="nginx")
    parser.add_argument("--openssl", default="openssl")
    return parser


def main() -> int:
    arguments = build_parser().parse_args()
    os.umask(0o077)
    backup_root: Path = arguments.backup_root
    if not backup_root.is_absolute():
        fail("backup root must be absolute")
    private_directory(backup_root, "backup root")
    if arguments.result_file is not None and not arguments.result_file.is_absolute():
        fail("result file must be absolute")
    if not (1 <= arguments.redis_port <= 65_535):
        fail("Redis port is invalid")
    if (
        not arguments.redis_data_path.startswith("/")
        or "\n" in arguments.redis_data_path
    ):
        fail("Redis data path must be one absolute container path")
    database_names = [
        arguments.postgres_database,
        *arguments.additional_postgres_database,
    ]
    for database_name in database_names:
        if not re.fullmatch(r"[A-Za-z0-9_]{1,63}", database_name):
            fail("PostgreSQL database names must be simple identifiers")
    if len(set(database_names)) != len(database_names):
        fail("PostgreSQL database names must be unique")

    sources = {
        "sub2api_data": arguments.sub2api_data,
        "sub2api_config": arguments.sub2api_config,
        "sub2api_compose": arguments.sub2api_compose,
        "sub2api_environment": arguments.sub2api_environment,
        "nginx_config": arguments.nginx_config,
    }
    source_path(arguments.sub2api_data, "Sub2API data path", directory=True)
    source_path(arguments.sub2api_config, "Sub2API config path")
    source_path(arguments.sub2api_compose, "Sub2API Compose file", directory=False)
    source_path(
        arguments.sub2api_environment, "Sub2API environment file", directory=False
    )
    source_path(arguments.nginx_config, "Nginx config path", directory=True)
    source_path(arguments.proc_root, "host procfs root", directory=True)
    root_resolved = backup_root.resolve()
    for value in sources.values():
        try:
            value.resolve().relative_to(root_resolved)
        except ValueError:
            continue
        fail("a production source path is inside the backup root")

    docker = require_command(arguments.docker, "docker")
    pg_restore = (
        require_command(arguments.pg_restore, "pg_restore")
        if arguments.pg_restore is not None
        else None
    )
    tar = require_command(arguments.tar, "tar")
    nginx = require_command(arguments.nginx, "nginx")
    openssl = require_command(arguments.openssl, "openssl")

    postgres_password = password_input(
        arguments.postgres_password_file, "PostgreSQL password file"
    )
    redis_password = password_input(
        arguments.redis_password_file, "Redis password file"
    )

    started = datetime.now(UTC)
    timestamp = started.strftime("%Y%m%dT%H%M%SZ")
    incomplete = Path(
        tempfile.mkdtemp(prefix=f".production-preflight-{timestamp}-", dir=backup_root)
    )
    os.chmod(incomplete, 0o700)
    final = backup_root / incomplete.name.removeprefix(".")
    try:
        if final.exists() or final.is_symlink():
            fail("refusing to overwrite a production backup")

        identities = {
            "sub2api": container_identity(
                docker, arguments.sub2api_container, "Sub2API"
            ),
            "postgres": container_identity(
                docker, arguments.postgres_container, "PostgreSQL"
            ),
            "redis": container_identity(docker, arguments.redis_container, "Redis"),
        }
        container_inspect = incomplete / "docker-container-inspect.json"
        run_capture(
            [
                docker,
                "inspect",
                arguments.sub2api_container,
                arguments.postgres_container,
                arguments.redis_container,
            ],
            output=container_inspect,
            stage="full Docker container inspection",
        )
        require_nonempty(container_inspect, "full Docker container inspection")
        image_inspect = incomplete / "docker-image-inspect.json"
        run_capture(
            [
                docker,
                "image",
                "inspect",
                *sorted({identity["image_id"] for identity in identities.values()}),
            ],
            output=image_inspect,
            stage="full Docker image inspection",
        )
        require_nonempty(image_inspect, "full Docker image inspection")
        running_executable = running_executable_evidence(
            arguments.proc_root, int(identities["sub2api"]["pid"])
        )
        write_json(incomplete / "sub2api-running-executable.json", running_executable)

        postgres_dump = incomplete / "sub2api-postgres.dump"
        run_capture(
            [
                docker,
                "exec",
                "-i",
                arguments.postgres_container,
                "sh",
                "-c",
                POSTGRES_DUMP_SCRIPT,
                "production-backup",
                arguments.postgres_user,
                arguments.postgres_database,
            ],
            input_bytes=postgres_password,
            output=postgres_dump,
            stage="PostgreSQL dump",
        )
        require_nonempty(postgres_dump, "PostgreSQL dump")

        postgres_contents = incomplete / "sub2api-postgres.contents.txt"
        validate_postgres_dump(
            docker,
            arguments.postgres_container,
            postgres_dump,
            postgres_contents,
            pg_restore,
            "PostgreSQL pg_restore validation",
        )

        postgres_globals = incomplete / "postgres-globals.sql"
        run_capture(
            [
                docker,
                "exec",
                "-i",
                arguments.postgres_container,
                "sh",
                "-c",
                POSTGRES_GLOBALS_SCRIPT,
                "production-backup",
                arguments.postgres_user,
            ],
            input_bytes=postgres_password,
            output=postgres_globals,
            stage="PostgreSQL globals dump",
        )
        require_nonempty(postgres_globals, "PostgreSQL globals dump")

        postgres_metadata = incomplete / "postgres-database-metadata.txt"
        run_capture(
            [
                docker,
                "exec",
                "-i",
                arguments.postgres_container,
                "sh",
                "-c",
                POSTGRES_METADATA_SCRIPT,
                "production-backup",
                arguments.postgres_user,
                arguments.postgres_database,
            ],
            input_bytes=postgres_password,
            output=postgres_metadata,
            stage="PostgreSQL metadata capture",
        )
        require_nonempty(postgres_metadata, "PostgreSQL metadata")

        additional_databases: dict[str, str] = {}
        for database_name in arguments.additional_postgres_database:
            exists = run_capture(
                [
                    docker,
                    "exec",
                    "-i",
                    arguments.postgres_container,
                    "sh",
                    "-c",
                    POSTGRES_DATABASE_EXISTS_SCRIPT,
                    "production-backup",
                    arguments.postgres_user,
                    database_name,
                ],
                input_bytes=postgres_password,
                stage="additional PostgreSQL database discovery",
            ).strip()
            if exists == b"f":
                additional_databases[database_name] = "absent"
                continue
            if exists != b"t":
                fail("additional PostgreSQL database discovery was invalid")
            database_dump = incomplete / f"postgres-{database_name}.dump"
            run_capture(
                [
                    docker,
                    "exec",
                    "-i",
                    arguments.postgres_container,
                    "sh",
                    "-c",
                    POSTGRES_DUMP_SCRIPT,
                    "production-backup",
                    arguments.postgres_user,
                    database_name,
                ],
                input_bytes=postgres_password,
                output=database_dump,
                stage="additional PostgreSQL database dump",
            )
            require_nonempty(database_dump, "additional PostgreSQL database dump")
            database_contents = incomplete / f"postgres-{database_name}.contents.txt"
            validate_postgres_dump(
                docker,
                arguments.postgres_container,
                database_dump,
                database_contents,
                pg_restore,
                "additional PostgreSQL pg_restore validation",
            )
            additional_databases[database_name] = "backed_up"
        write_json(
            incomplete / "postgres-additional-databases.json", additional_databases
        )

        ping = run_capture(
            [
                docker,
                "exec",
                "-i",
                arguments.redis_container,
                "sh",
                "-c",
                REDIS_COMMAND_SCRIPT,
                "production-backup",
                arguments.redis_user,
                str(arguments.redis_port),
                "PING",
            ],
            input_bytes=redis_password,
            stage="Redis PING",
        )
        if ping.strip() != b"PONG":
            fail("Redis PING did not return PONG")

        redis_metadata = incomplete / "redis-config-acl.txt"
        run_capture(
            [
                docker,
                "exec",
                "-i",
                arguments.redis_container,
                "sh",
                "-c",
                REDIS_METADATA_SCRIPT,
                "production-backup",
                arguments.redis_user,
                str(arguments.redis_port),
            ],
            input_bytes=redis_password,
            output=redis_metadata,
            stage="Redis configuration and ACL capture",
        )
        require_nonempty(redis_metadata, "Redis configuration and ACL metadata")

        redis_rdb = incomplete / "redis-logical.rdb"
        run_capture(
            [
                docker,
                "exec",
                "-i",
                arguments.redis_container,
                "sh",
                "-c",
                REDIS_SNAPSHOT_SCRIPT,
                "production-backup",
                arguments.redis_user,
                str(arguments.redis_port),
            ],
            input_bytes=redis_password,
            output=redis_rdb,
            stage="Redis logical snapshot",
        )
        require_nonempty(redis_rdb, "Redis logical snapshot")
        redis_validation = incomplete / "redis-rdb-validation.txt"
        redis_validator = validate_redis_rdb(
            docker, arguments.redis_container, redis_rdb, redis_validation
        )
        require_nonempty(redis_validation, "Redis RDB validation")

        redis_files = incomplete / "redis-persistence.tar"
        run_capture(
            [
                docker,
                "cp",
                f"{arguments.redis_container}:{arguments.redis_data_path}",
                "-",
            ],
            output=redis_files,
            stage="Redis persistence archive",
        )
        require_nonempty(redis_files, "Redis persistence archive")
        redis_files_contents = incomplete / "redis-persistence.contents.txt"
        run_capture(
            [tar, "-tf", str(redis_files)],
            output=redis_files_contents,
            stage="Redis persistence tar validation",
        )
        require_nonempty(redis_files_contents, "Redis persistence tar listing")
        tar_listing_is_safe(redis_files_contents)

        sub2api_files = incomplete / "sub2api-host-files.tar.gz"
        run_capture(
            [
                tar,
                "-C",
                "/",
                "-czf",
                str(sub2api_files),
                "--exclude",
                f"{relative_archive_name(arguments.sub2api_data)}/logs",
                *[
                    relative_archive_name(path)
                    for path in sources.values()
                    if path != arguments.nginx_config
                ],
            ],
            output=None,
            stage="Sub2API host files archive",
        )
        require_nonempty(sub2api_files, "Sub2API host files archive")
        sub2api_files_contents = incomplete / "sub2api-host-files.contents.txt"
        run_capture(
            [tar, "-tzf", str(sub2api_files)],
            output=sub2api_files_contents,
            stage="Sub2API host files tar validation",
        )
        require_nonempty(sub2api_files_contents, "Sub2API host files tar listing")
        tar_listing_is_safe(sub2api_files_contents)

        sub2api_runtime = incomplete / "sub2api-runtime.txt"
        run_capture(
            [
                docker,
                "exec",
                arguments.sub2api_container,
                "sh",
                "-c",
                "set -eu; /app/sub2api --version; sha256sum /app/sub2api",
            ],
            output=sub2api_runtime,
            stage="Sub2API runtime capture",
        )
        require_nonempty(sub2api_runtime, "Sub2API runtime evidence")
        sub2api_runtime_files = incomplete / "sub2api-runtime-files.tar"
        run_capture(
            [
                docker,
                "exec",
                arguments.sub2api_container,
                "sh",
                "-c",
                SUB2API_RUNTIME_ARCHIVE_SCRIPT,
            ],
            output=sub2api_runtime_files,
            stage="Sub2API runtime files archive",
        )
        require_nonempty(sub2api_runtime_files, "Sub2API runtime files archive")
        sub2api_runtime_contents = incomplete / "sub2api-runtime-files.contents.txt"
        run_capture(
            [tar, "-tf", str(sub2api_runtime_files)],
            output=sub2api_runtime_contents,
            stage="Sub2API runtime files tar validation",
        )
        require_nonempty(sub2api_runtime_contents, "Sub2API runtime files tar listing")
        tar_listing_is_safe(sub2api_runtime_contents)
        sub2api_diff = incomplete / "sub2api-container-diff.txt"
        run_capture(
            [docker, "diff", arguments.sub2api_container],
            output=sub2api_diff,
            stage="Sub2API container diff capture",
        )
        # An unchanged container has a valid empty diff.

        nginx_effective = incomplete / "nginx-effective-config.txt"
        run_capture(
            [nginx, "-T"],
            output=nginx_effective,
            stage="Nginx effective configuration validation",
        )
        require_nonempty(nginx_effective, "Nginx effective configuration")
        certificate_paths, key_paths = parse_nginx_tls_paths(nginx_effective)

        nginx_files = incomplete / "nginx-config.tar.gz"
        run_capture(
            [
                tar,
                "-C",
                "/",
                "-czf",
                str(nginx_files),
                relative_archive_name(arguments.nginx_config),
            ],
            stage="Nginx configuration archive",
        )
        require_nonempty(nginx_files, "Nginx configuration archive")
        nginx_files_contents = incomplete / "nginx-config.contents.txt"
        run_capture(
            [tar, "-tzf", str(nginx_files)],
            output=nginx_files_contents,
            stage="Nginx configuration tar validation",
        )
        require_nonempty(nginx_files_contents, "Nginx configuration tar listing")
        tar_listing_is_safe(nginx_files_contents)

        certificate_details = incomplete / "nginx-certificates.txt"
        with open_private(certificate_details) as destination:
            for certificate in certificate_paths:
                result = subprocess.run(
                    [
                        openssl,
                        "x509",
                        "-in",
                        str(certificate),
                        "-noout",
                        "-subject",
                        "-issuer",
                        "-serial",
                        "-dates",
                        "-fingerprint",
                        "-sha256",
                    ],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    check=False,
                )
                if result.returncode != 0:
                    fail("failed during Nginx certificate validation")
                destination.write(f"certificate={certificate}\n".encode())
                destination.write(result.stdout)
                destination.write(b"\n")
            destination.flush()
            os.fsync(destination.fileno())
        require_nonempty(certificate_details, "Nginx certificate metadata")

        tls_metadata = {
            "certificates": [
                file_metadata(path, include_sha256=True) for path in certificate_paths
            ],
            "private_keys": [
                file_metadata(path, include_sha256=False) for path in key_paths
            ],
        }
        write_json(incomplete / "nginx-tls-files.json", tls_metadata)
        tls_sources = sorted(
            {
                path
                for configured in [*certificate_paths, *key_paths]
                for path in (configured, configured.resolve(strict=True))
            }
        )
        tls_archive = incomplete / "nginx-tls-private.tar.gz"
        run_capture(
            [
                tar,
                "-C",
                "/",
                "-czf",
                str(tls_archive),
                *[relative_archive_name(path) for path in tls_sources],
            ],
            stage="Nginx TLS recovery archive",
        )
        require_nonempty(tls_archive, "Nginx TLS recovery archive")
        tls_archive_contents = incomplete / "nginx-tls-private.contents.txt"
        run_capture(
            [tar, "-tzf", str(tls_archive)],
            output=tls_archive_contents,
            stage="Nginx TLS recovery tar validation",
        )
        require_nonempty(tls_archive_contents, "Nginx TLS recovery tar listing")
        tar_listing_is_safe(tls_archive_contents)

        ending_identities = {
            "sub2api": container_identity(
                docker, arguments.sub2api_container, "Sub2API"
            ),
            "postgres": container_identity(
                docker, arguments.postgres_container, "PostgreSQL"
            ),
            "redis": container_identity(docker, arguments.redis_container, "Redis"),
        }
        if ending_identities != identities:
            fail("one production container changed during the backup")
        if (
            running_executable_evidence(
                arguments.proc_root, int(identities["sub2api"]["pid"])
            )
            != running_executable
        ):
            fail("running Sub2API executable changed during the backup")

        artifact_names = sorted(
            path.name
            for path in incomplete.iterdir()
            if path.is_file() and path.name not in {"manifest.sha256", "READY.json"}
        )
        artifacts = [
            {
                "path": name,
                "sha256": sha256(incomplete / name),
                "size": (incomplete / name).stat().st_size,
            }
            for name in artifact_names
        ]
        record = {
            "schema_version": 1,
            "status": "ready",
            "created_at": started.isoformat().replace("+00:00", "Z"),
            "snapshot_directory": final.name,
            "containers": {
                role: {
                    "container_id": identity["container_id"],
                    "image_id": identity["image_id"],
                    "name": identity["name"],
                }
                for role, identity in identities.items()
            },
            "sources": {key: str(value) for key, value in sorted(sources.items())},
            "redis": {
                "logical_rdb_validator": redis_validator,
                "persistence_path": arguments.redis_data_path,
            },
            "artifacts": artifacts,
        }
        record_path = incomplete / "backup-record.json"
        write_json(record_path, record)
        artifact_names.append(record_path.name)
        artifact_names.sort()

        manifest_lines = [
            f"{sha256(incomplete / name)}  {name}\n" for name in artifact_names
        ]
        manifest = incomplete / "manifest.sha256"
        write_bytes(manifest, "".join(manifest_lines).encode("ascii"))
        for line in manifest_lines:
            expected, name = line.rstrip("\n").split("  ", 1)
            if sha256(incomplete / name) != expected:
                fail("SHA-256 manifest verification failed")
        manifest_digest = sha256(manifest)
        write_json(
            incomplete / "READY.json",
            {
                "schema_version": 1,
                "status": "ready",
                "manifest": "manifest.sha256",
                "manifest_sha256": manifest_digest,
            },
        )
        for path in incomplete.iterdir():
            if path.is_file():
                os.chmod(path, 0o600)
                with path.open("rb") as source:
                    os.fsync(source.fileno())
        os.rename(incomplete, final)
        root_fd = os.open(backup_root, os.O_RDONLY)
        try:
            os.fsync(root_fd)
        finally:
            os.close(root_fd)

        result_value = {
            "schema_version": 1,
            "status": "ready",
            "snapshot_directory": str(final),
            "manifest_sha256": manifest_digest,
        }
        if arguments.result_file is not None:
            result_parent = arguments.result_file.parent
            private_directory(result_parent, "result file parent")
            temporary_result = (
                result_parent / f".{arguments.result_file.name}.tmp-{os.getpid()}"
            )
            if arguments.result_file.exists() or arguments.result_file.is_symlink():
                fail("refusing to overwrite the result file")
            write_json(temporary_result, result_value)
            os.replace(temporary_result, arguments.result_file)
        print(f"Production preflight backup ready: {final}")
        return 0
    except BaseException:
        if incomplete.exists():
            shutil.rmtree(incomplete, ignore_errors=True)
        raise


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except BackupError as error:
        print(f"production-state-backup: {error}", file=sys.stderr)
        raise SystemExit(1) from None
