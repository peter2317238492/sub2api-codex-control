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


def private_directory(path: Path, label: str, *, expected_uid: int | None = None) -> None:
    try:
        info = path.lstat()
    except OSError:
        fail(f"{label} is not accessible")
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        fail(f"{label} must be a real directory")
    owner_uid = os.geteuid() if expected_uid is None else expected_uid
    if info.st_uid != owner_uid:
        fail(f"{label} must be owned by UID {owner_uid}")
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


def stat_identity(value: os.stat_result) -> tuple[int, ...]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_uid,
        value.st_gid,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def stable_copy(source: Path, destination: Path, label: str) -> dict[str, object]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(source, flags)
        before = os.fstat(descriptor)
    except OSError:
        fail(f"{label} is not accessible")
    try:
        if not stat.S_ISREG(before.st_mode) or before.st_size > 32 * 1024 * 1024:
            fail(f"{label} must be one bounded regular file")
        digest = hashlib.sha256()
        size = 0
        with open_private(destination) as output:
            for block in iter(lambda: os.read(descriptor, 1024 * 1024), b""):
                digest.update(block)
                size += len(block)
                output.write(block)
            output.flush()
            os.fsync(output.fileno())
        if stat_identity(os.fstat(descriptor)) != stat_identity(before):
            fail(f"{label} changed while it was copied")
    finally:
        os.close(descriptor)
    return {
        "source": str(source),
        "artifact": destination.name,
        "sha256": digest.hexdigest(),
        "size": size,
    }


# bootstrap-production-unsigned.sh records one-shot stale-backup exception
# claims in this hidden directory beside the deployment records. They are
# anti-replay markers, so they belong in the snapshot; every other nested
# dot-prefixed entry is still treated as a stray temporary file.
STALE_BACKUP_CLAIM_DIRECTORY = ".stale-backup-exception-claims"


def release_record_inventory(
    root: Path, excluded_top_level: set[str]
) -> tuple[dict[str, object], list[str]]:
    entries: list[dict[str, object]] = []
    top_level: list[str] = []
    try:
        root_info = root.lstat()
        children = sorted(root.iterdir(), key=lambda item: item.name)
    except OSError:
        fail("release record path cannot be inventoried")
    for child in children:
        if (
            child.name in excluded_top_level
            or child.name.startswith(".")
            or child.name == "auth-probe-inputs"
        ):
            continue
        if "\n" in child.name or "\r" in child.name:
            fail("one release record name is invalid")
        top_level.append(child.name)
        pending = [child]
        while pending:
            path = pending.pop()
            relative = path.relative_to(root)
            if "auth-probe-inputs" in relative.parts:
                fail("release records retain sensitive authentication probe inputs")
            if any(
                part.startswith(".") and part != STALE_BACKUP_CLAIM_DIRECTORY
                for part in relative.parts
            ):
                fail("release records retain one nested temporary entry")
            try:
                info = path.lstat()
            except OSError:
                fail("one release record changed while it was inventoried")
            if stat.S_ISLNK(info.st_mode):
                fail("release records must not contain symlinks")
            item: dict[str, object] = {
                "path": relative.as_posix(),
                "mode": f"{stat.S_IMODE(info.st_mode):04o}",
                "uid": info.st_uid,
                "gid": info.st_gid,
                "mtime_ns": info.st_mtime_ns,
            }
            if stat.S_ISDIR(info.st_mode):
                item["type"] = "directory"
                try:
                    pending.extend(
                        sorted(path.iterdir(), key=lambda value: value.name, reverse=True)
                    )
                except OSError:
                    fail("one release record directory changed while it was inventoried")
            elif stat.S_ISREG(info.st_mode):
                item.update(type="file", size=info.st_size, sha256=sha256(path))
            else:
                fail("release records contain an unsupported file type")
            entries.append(item)
    entries.sort(key=lambda item: str(item["path"]))
    return (
        {
            "root": str(root),
            "root_mode": f"{stat.S_IMODE(root_info.st_mode):04o}",
            "root_uid": root_info.st_uid,
            "excluded_top_level": sorted(excluded_top_level),
            "excluded_transient_names": [".*", ".tmp*", "auth-probe-inputs"],
            "entries": entries,
        },
        top_level,
    )


def normalize_docker_networks(
    raw_networks: bytes,
    raw_containers: bytes,
    expected_names: list[str],
) -> list[dict[str, object]]:
    try:
        network_values = json.loads(raw_networks.decode("utf-8"))
        container_values = json.loads(raw_containers.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        fail("Docker network metadata is not valid JSON")
    if not isinstance(network_values, list) or not isinstance(container_values, list):
        fail("Docker network metadata has an unexpected shape")
    networks: dict[str, dict[str, object]] = {}
    for value in network_values:
        if not isinstance(value, dict) or not isinstance(value.get("Name"), str):
            fail("one Docker network inspection is invalid")
        name = value["Name"]
        identifier = value.get("Id")
        members = value.get("Containers")
        if (
            name in networks
            or not isinstance(identifier, str)
            or re.fullmatch(r"[0-9a-f]{64}", identifier) is None
            or not isinstance(members, dict)
        ):
            fail("one Docker network inspection is invalid")
        normalized_members: list[dict[str, str]] = []
        for container_id, member in sorted(members.items()):
            if (
                not isinstance(container_id, str)
                or re.fullmatch(r"[0-9a-f]{64}", container_id) is None
                or not isinstance(member, dict)
                or not isinstance(member.get("Name"), str)
                or not isinstance(member.get("EndpointID"), str)
            ):
                fail("one Docker network member is invalid")
            normalized_members.append(
                {
                    "container_id": container_id,
                    "name": member["Name"],
                    "endpoint_id": member["EndpointID"],
                }
            )
        networks[name] = {
            "name": name,
            "id": identifier,
            "driver": value.get("Driver"),
            "scope": value.get("Scope"),
            "internal": value.get("Internal"),
            "attachable": value.get("Attachable"),
            "ingress": value.get("Ingress"),
            "enable_ipv6": value.get("EnableIPv6"),
            "ipam": value.get("IPAM"),
            "options": value.get("Options") or {},
            "containers": normalized_members,
        }
    if set(networks) != set(expected_names):
        fail("Docker network inspection differs from the requested networks")

    attached_names: set[str] = set()
    expected_container_ids: set[str] = set()
    for value in container_values:
        if not isinstance(value, dict) or not isinstance(value.get("Id"), str):
            fail("one Docker container inspection is invalid")
        container_id = value["Id"]
        expected_container_ids.add(container_id)
        settings = value.get("NetworkSettings")
        attached = settings.get("Networks") if isinstance(settings, dict) else None
        if not isinstance(attached, dict) or not attached:
            fail("one production container has no inspected Docker network")
        for name, endpoint in attached.items():
            if name not in networks or not isinstance(endpoint, dict):
                fail("one production container uses an unrecorded Docker network")
            if endpoint.get("NetworkID") != networks[name]["id"]:
                fail("one production container has a mismatched Docker network ID")
            attached_names.add(name)
    if not attached_names or not attached_names.issubset(set(expected_names)):
        fail("production container attachments are not covered by the requested networks")
    recorded_ids = {
        item["container_id"]
        for network in networks.values()
        for item in network["containers"]
        if isinstance(item, dict)
    }
    if not expected_container_ids.issubset(recorded_ids):
        fail("Docker network membership omits one production container")
    return [networks[name] for name in sorted(networks)]


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
set -- app/sub2api
for candidate in app/sub2api.backup app/sub2api.backup.backup; do
  if [ -e "/$candidate" ]; then set -- "$@" "$candidate"; fi
done
exec tar -C / -cf - "$@"
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
    parser.add_argument("--release-records", required=True, type=Path)
    parser.add_argument("--release-record-exclude", action="append", default=[])
    parser.add_argument("--release-evidence", action="append", required=True, type=Path)
    parser.add_argument("--docker-network", action="append", required=True)
    parser.add_argument("--expected-owner-uid", type=int, default=0)
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
    if arguments.expected_owner_uid < 0:
        fail("expected owner UID is invalid")
    if os.geteuid() != arguments.expected_owner_uid:
        fail(f"production backup must run as UID {arguments.expected_owner_uid}")
    backup_root: Path = arguments.backup_root
    if not backup_root.is_absolute():
        fail("backup root must be absolute")
    private_directory(
        backup_root, "backup root", expected_uid=arguments.expected_owner_uid
    )
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
        "release_records": arguments.release_records,
    }
    source_path(arguments.sub2api_data, "Sub2API data path", directory=True)
    source_path(arguments.sub2api_config, "Sub2API config path")
    source_path(arguments.sub2api_compose, "Sub2API Compose file", directory=False)
    source_path(
        arguments.sub2api_environment, "Sub2API environment file", directory=False
    )
    source_path(arguments.nginx_config, "Nginx config path", directory=True)
    source_path(arguments.release_records, "release record path", directory=True)
    for evidence in arguments.release_evidence:
        source_path(evidence, "release evidence", directory=False)
    source_path(arguments.proc_root, "host procfs root", directory=True)
    root_resolved = backup_root.resolve()
    for value in sources.values():
        try:
            value.resolve().relative_to(root_resolved)
        except ValueError:
            continue
        fail("a production source path is inside the backup root")
    evidence_names = [path.name for path in arguments.release_evidence]
    if len(set(evidence_names)) != len(evidence_names) or any(
        re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", name) is None
        for name in evidence_names
    ):
        fail("release evidence file names are invalid or duplicated")
    excluded_release_records = set(arguments.release_record_exclude)
    if any(
        not name
        or name in {".", ".."}
        or "/" in name
        or "\x00" in name
        or "\n" in name
        or "\r" in name
        for name in excluded_release_records
    ):
        fail("release record exclusions must be top-level names")

    docker = require_command(arguments.docker, "docker")
    pg_restore = (
        require_command(arguments.pg_restore, "pg_restore")
        if arguments.pg_restore is not None
        else None
    )
    tar = require_command(arguments.tar, "tar")
    nginx = require_command(arguments.nginx, "nginx")
    openssl = require_command(arguments.openssl, "openssl")
    docker_networks = sorted(set(arguments.docker_network))
    if not docker_networks or any(
        not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", name)
        for name in docker_networks
    ):
        fail("Docker network names are invalid")

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
        network_inspect = incomplete / "docker-network-inspect.json"
        run_capture(
            [docker, "network", "inspect", *docker_networks],
            output=network_inspect,
            stage="Docker network inspection",
        )
        require_nonempty(network_inspect, "Docker network inspection")
        normalized_networks = normalize_docker_networks(
            network_inspect.read_bytes(),
            container_inspect.read_bytes(),
            docker_networks,
        )
        write_json(incomplete / "docker-networks.json", normalized_networks)
        initial_release_inventory, release_record_names = release_record_inventory(
            arguments.release_records, excluded_release_records
        )
        write_json(incomplete / "release-records-inventory.json", initial_release_inventory)
        release_evidence_inventory = [
            stable_copy(
                source,
                incomplete / f"release-evidence-{source.name}",
                f"release evidence {source.name}",
            )
            for source in arguments.release_evidence
        ]
        write_json(
            incomplete / "release-evidence-inventory.json", release_evidence_inventory
        )
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

        release_records = incomplete / "release-records.tar.gz"
        if release_record_names:
            run_capture(
                [
                    tar,
                    "-C",
                    str(arguments.release_records),
                    "-czf",
                    str(release_records),
                    *release_record_names,
                ],
                stage="release records archive",
            )
        else:
            run_capture(
                [
                    tar,
                    "-C",
                    str(arguments.release_records),
                    "-czf",
                    str(release_records),
                    "-T",
                    "/dev/null",
                ],
                stage="release records archive",
            )
        require_nonempty(release_records, "release records archive")
        release_records_contents = incomplete / "release-records.contents.txt"
        run_capture(
            [tar, "-tzf", str(release_records)],
            output=release_records_contents,
            stage="release records tar validation",
        )
        require_nonempty(release_records_contents, "release records tar listing")
        tar_listing_is_safe(release_records_contents)

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
        ending_network_inspect = incomplete / ".docker-network-inspect-after.json"
        run_capture(
            [docker, "network", "inspect", *docker_networks],
            output=ending_network_inspect,
            stage="ending Docker network inspection",
        )
        if normalize_docker_networks(
            ending_network_inspect.read_bytes(),
            container_inspect.read_bytes(),
            docker_networks,
        ) != normalized_networks:
            fail("one production Docker network changed during the backup")
        ending_network_inspect.unlink()
        ending_release_inventory, ending_release_names = release_record_inventory(
            arguments.release_records, excluded_release_records
        )
        if (
            ending_release_inventory != initial_release_inventory
            or ending_release_names != release_record_names
        ):
            fail("one release record changed during the backup")
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
            "release_evidence": release_evidence_inventory,
            "docker_networks": normalized_networks,
            "owner_uid": arguments.expected_owner_uid,
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
            private_directory(
                result_parent,
                "result file parent",
                expected_uid=arguments.expected_owner_uid,
            )
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
