#!/bin/sh
set -eu

action=${1:-}
case "$action" in
  apply)
    [ "$#" -eq 1 ] || { echo "usage: $0 apply" >&2; exit 2; }
    ;;
  rollback)
    [ "$#" -eq 2 ] || { echo "usage: $0 rollback RESULT.json" >&2; exit 2; }
    rollback_receipt=$2
    ;;
  *)
    echo "usage: $0 {apply|rollback RESULT.json}" >&2
    exit 2
    ;;
esac

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
lock_file=${VERSIONS_LOCK_FILE:-$script_dir/../../versions.lock.json}
runtime_verifier=${SUB2API_RUNTIME_VERIFIER:-$script_dir/verify-sub2api-runtime.sh}
container=${SUB2API_CONTAINER:-sub2api}
data_source=${SUB2API_DATA_BIND_SOURCE:-}
backup_root=${SUB2API_IMMUTABLE_BACKUP_ROOT:-}
operation_lock_path=$backup_root/.sub2api-immutable-operation.lock
expected_network=${SUB2API_EXPECTED_NETWORK:-sub2api-deploy_sub2api-network}
expected_alias=${SUB2API_EXPECTED_NETWORK_ALIAS:-sub2api}
expected_uid=${SUB2API_EXPECTED_DATA_BIND_UID:-1000}
expected_gid=${SUB2API_EXPECTED_DATA_BIND_GID:-1000}
expected_mode=${SUB2API_EXPECTED_DATA_BIND_MODE:-0755}
health_timeout=${SUB2API_IMMUTABLE_HEALTH_TIMEOUT_SECONDS:-120}
compose_file=${SUB2API_COMPOSE_FILE:-}
compose_candidate=${SUB2API_IMMUTABLE_COMPOSE_CANDIDATE:-}
compose_candidate_sha256=${SUB2API_IMMUTABLE_COMPOSE_SHA256:-}
compose_environment=${SUB2API_COMPOSE_ENV_FILE:-}
compose_environment_sha256=${SUB2API_COMPOSE_ENV_SHA256:-}
compose_project=${SUB2API_COMPOSE_PROJECT:-sub2api-deploy}
compose_service=${SUB2API_COMPOSE_SERVICE:-sub2api}

fail() {
  echo "migrate-sub2api-immutable: $*" >&2
  exit 1
}

[ "$(id -u)" = "0" ] || fail "must run as root"
command -v docker >/dev/null 2>&1 || fail "docker is required"
docker compose version >/dev/null 2>&1 || fail "Docker Compose v2 is required"
command -v python3 >/dev/null 2>&1 || fail "python3 is required"
command -v sha256sum >/dev/null 2>&1 || fail "sha256sum is required"
command -v tar >/dev/null 2>&1 || fail "tar is required"
[ -x "$runtime_verifier" ] || fail "runtime verifier is not executable"
[ -r "$lock_file" ] || fail "version lock is not readable"
[ -n "$data_source" ] || fail "SUB2API_DATA_BIND_SOURCE is required"
[ -n "$backup_root" ] || fail "SUB2API_IMMUTABLE_BACKUP_ROOT is required"
[ -n "$expected_network" ] || fail "SUB2API_EXPECTED_NETWORK is required"
[ -n "$expected_alias" ] || fail "SUB2API_EXPECTED_NETWORK_ALIAS is required"
[ -n "$compose_file" ] || fail "SUB2API_COMPOSE_FILE is required"
[ -n "$compose_candidate" ] || fail "SUB2API_IMMUTABLE_COMPOSE_CANDIDATE is required"
[ -n "$compose_environment" ] || fail "SUB2API_COMPOSE_ENV_FILE is required"
[ -n "$compose_project" ] || fail "SUB2API_COMPOSE_PROJECT is required"
[ -n "$compose_service" ] || fail "SUB2API_COMPOSE_SERVICE is required"
case "$compose_project" in
  *[!A-Za-z0-9_.-]*|'') fail "Compose project name is not canonical" ;;
esac
case "$compose_service" in
  *[!A-Za-z0-9_.-]*|'') fail "Compose service name is not canonical" ;;
esac
case "$compose_candidate_sha256" in
  *[!0-9a-f]*|'') fail "SUB2API_IMMUTABLE_COMPOSE_SHA256 must be lowercase SHA-256" ;;
esac
[ "${#compose_candidate_sha256}" -eq 64 ] \
  || fail "SUB2API_IMMUTABLE_COMPOSE_SHA256 must be lowercase SHA-256"
case "$compose_environment_sha256" in
  *[!0-9a-f]*|'') fail "SUB2API_COMPOSE_ENV_SHA256 must be lowercase SHA-256" ;;
esac
[ "${#compose_environment_sha256}" -eq 64 ] \
  || fail "SUB2API_COMPOSE_ENV_SHA256 must be lowercase SHA-256"
case "$expected_uid" in ''|*[!0-9]*|0) fail "bind UID must be positive" ;; esac
case "$expected_gid" in ''|*[!0-9]*|0) fail "bind GID must be positive" ;; esac
case "$expected_mode" in 0700|0750|0755) ;; *) fail "bind mode must be 0700, 0750, or 0755" ;; esac
case "$health_timeout" in ''|*[!0-9]*|0) fail "health timeout must be positive" ;; esac

umask 077

acquire_operation_lock() {
  operation=$1
  receipt_identity=$2
  python3 -I - "$operation_lock_path" "$backup_root" "$operation" \
    "$receipt_identity" "$$" <<'PY'
import json
import os
import re
import stat
import sys
from datetime import UTC, datetime
from pathlib import Path

path = Path(sys.argv[1])
backup_root = Path(sys.argv[2])
operation = sys.argv[3]
receipt_identity = sys.argv[4]
shell_pid = sys.argv[5]
if path != backup_root / ".sub2api-immutable-operation.lock":
    raise SystemExit("operation lock must use the fixed backup-root path")
if operation not in {"apply", "rollback"}:
    raise SystemExit("operation lock has an invalid operation")
if not receipt_identity.startswith(str(backup_root) + "/") or "\n" in receipt_identity:
    raise SystemExit("operation lock receipt identity is outside the backup root")
if re.fullmatch(r"[1-9][0-9]*", shell_pid) is None:
    raise SystemExit("operation lock shell PID is invalid")
payload = {
    "format_version": 1,
    "acquired_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
    "operation": operation,
    "receipt_identity": receipt_identity,
    "shell_pid": int(shell_pid),
}
flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
descriptor = os.open(path, flags, 0o600)
with os.fdopen(descriptor, "w", encoding="utf-8") as output:
    json.dump(payload, output, indent=2, sort_keys=True)
    output.write("\n")
    output.flush()
    os.fsync(output.fileno())
info = path.lstat()
if (
    not stat.S_ISREG(info.st_mode)
    or stat.S_ISLNK(info.st_mode)
    or info.st_uid != 0
    or info.st_gid != 0
    or info.st_nlink != 1
    or stat.S_IMODE(info.st_mode) != 0o600
):
    raise SystemExit("operation lock was not created with the required identity")
directory = os.open(backup_root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
try:
    os.fsync(directory)
finally:
    os.close(directory)
print(f"{info.st_dev}:{info.st_ino}")
PY
}

release_operation_lock() {
  [ "${operation_lock_held:-0}" = "1" ] || return 0
  python3 -I - "$operation_lock_path" "$backup_root" \
    "$operation_lock_identity" <<'PY'
import os
import re
import stat
import sys
from pathlib import Path

path = Path(sys.argv[1])
backup_root = Path(sys.argv[2])
identity = sys.argv[3]
if path != backup_root / ".sub2api-immutable-operation.lock":
    raise SystemExit("operation lock path drifted")
match = re.fullmatch(r"([0-9]+):([0-9]+)", identity)
if match is None:
    raise SystemExit("operation lock identity is invalid")
flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
descriptor = os.open(path, flags)
try:
    info = os.fstat(descriptor)
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != 0
        or info.st_gid != 0
        or info.st_nlink != 1
        or stat.S_IMODE(info.st_mode) != 0o600
        or (info.st_dev, info.st_ino) != (int(match.group(1)), int(match.group(2)))
    ):
        raise SystemExit("operation lock identity drifted; lock retained")
finally:
    os.close(descriptor)
current = path.lstat()
if (current.st_dev, current.st_ino) != (info.st_dev, info.st_ino):
    raise SystemExit("operation lock changed before release; lock retained")
path.unlink()
directory = os.open(backup_root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
try:
    os.fsync(directory)
finally:
    os.close(directory)
PY
  operation_lock_held=0
}

validate_paths_and_lock() {
  output=$1
  python3 -I - "$backup_root" "$data_source" "$expected_uid" "$expected_gid" \
    "$expected_mode" "$lock_file" "$script_dir/verify-sub2api-runtime.py" \
    "$compose_file" "$compose_candidate" "$compose_candidate_sha256" \
    "$compose_environment" "$compose_environment_sha256" > "$output" <<'PY'
import importlib.util
import hashlib
import json
import os
import stat
import sys
from pathlib import Path

backup_root = Path(sys.argv[1])
data_source = sys.argv[2]
uid = int(sys.argv[3])
gid = int(sys.argv[4])
mode = int(sys.argv[5], 8)
lock_path = Path(sys.argv[6])
verifier_path = Path(sys.argv[7])
compose_file = Path(sys.argv[8])
compose_candidate = Path(sys.argv[9])
compose_candidate_sha256 = sys.argv[10]
compose_environment = Path(sys.argv[11])
compose_environment_sha256 = sys.argv[12]

def safe_ancestors(path, label):
    current = Path("/")
    for component in path.parts[1:-1]:
        current /= component
        info = current.lstat()
        if (
            stat.S_ISLNK(info.st_mode)
            or not stat.S_ISDIR(info.st_mode)
            or info.st_uid != 0
            or stat.S_IMODE(info.st_mode) & 0o022
        ):
            raise SystemExit(f"{label} has an unsafe ancestor: {current}")

def safe_file(path, label, modes, expected_sha256=None, max_bytes=4 * 1024 * 1024):
    if not path.is_absolute() or os.path.realpath(path, strict=True) != str(path):
        raise SystemExit(f"{label} must be one canonical absolute path")
    safe_ancestors(path, label)
    info = path.lstat()
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISREG(info.st_mode)
        or info.st_uid != 0
        or info.st_nlink != 1
        or stat.S_IMODE(info.st_mode) not in modes
        or info.st_size <= 0
        or info.st_size > max_bytes
    ):
        raise SystemExit(f"{label} ownership, type, link count, or mode is unsafe")
    payload = path.read_bytes()
    observed = hashlib.sha256(payload).hexdigest()
    if expected_sha256 is not None and observed != expected_sha256:
        raise SystemExit(f"{label} SHA-256 does not match the admitted value")
    return observed

if not backup_root.is_absolute() or os.path.realpath(backup_root, strict=True) != str(backup_root):
    raise SystemExit("backup root must be one canonical absolute path")
root_info = backup_root.lstat()
if not stat.S_ISDIR(root_info.st_mode) or stat.S_ISLNK(root_info.st_mode):
    raise SystemExit("backup root must be a real directory")
if root_info.st_uid != 0 or root_info.st_gid != 0 or stat.S_IMODE(root_info.st_mode) != 0o700:
    raise SystemExit("backup root must be root:root mode 0700")
safe_ancestors(backup_root / "placeholder", "backup root")

spec = importlib.util.spec_from_file_location("verify_sub2api_runtime", verifier_path)
if spec is None or spec.loader is None:
    raise SystemExit("cannot load runtime verifier")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
module.validate_bind_source(
    data_source,
    expected_uid=uid,
    expected_gid=gid,
    expected_mode=mode,
)

if compose_file == compose_candidate:
    raise SystemExit("immutable Compose candidate must be staged separately")
safe_file(compose_file, "active Compose file", {0o400, 0o440, 0o444, 0o600, 0o640, 0o644})
safe_file(
    compose_candidate,
    "immutable Compose candidate",
    {0o444},
    compose_candidate_sha256,
)
safe_file(
    compose_environment,
    "Compose environment file",
    {0o400, 0o600},
    compose_environment_sha256,
    1024 * 1024,
)

lock_info = lock_path.lstat()
if not stat.S_ISREG(lock_info.st_mode) or stat.S_ISLNK(lock_info.st_mode):
    raise SystemExit("version lock must be a real regular file")
lock = json.loads(lock_path.read_text(encoding="utf-8"))
sub2api = lock.get("sub2api") if isinstance(lock, dict) else None
if not isinstance(sub2api, dict):
    raise SystemExit("version lock has no Sub2API object")
if sub2api.get("production_admission_profile") != "immutable-image-v1":
    raise SystemExit("version lock does not admit immutable-image-v1")
image = sub2api.get("container_image")
image_id = sub2api.get("container_image_id")
if not isinstance(image, str) or "@sha256:" not in image:
    raise SystemExit("version lock has no immutable Sub2API image")
if not isinstance(image_id, str) or not image_id.startswith("sha256:"):
    raise SystemExit("version lock has no immutable Sub2API image ID")
print(image)
print(image_id)
PY
}

render_and_validate_compose() {
  resolved=$1
  uninterpolated=$2
  hash_output=$3
  compose_directory=$(dirname -- "$compose_file")
  clean_path=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
  env -i PATH="$clean_path" HOME=/root \
    docker compose \
    --project-name "$compose_project" \
    --project-directory "$compose_directory" \
    --env-file "$compose_environment" \
    --file "$compose_candidate" \
    config --format json > "$resolved"
  env -i PATH="$clean_path" HOME=/root \
    docker compose \
    --project-name "$compose_project" \
    --project-directory "$compose_directory" \
    --env-file "$compose_environment" \
    --file "$compose_candidate" \
    config --no-interpolate --format json > "$uninterpolated"
  chmod 0600 "$resolved" "$uninterpolated"
  python3 -I - "$resolved" "$uninterpolated" "$compose_service" "$container" \
    "$locked_image" "$data_source" "$expected_uid" "$expected_gid" \
    "$expected_network" > "$hash_output" <<'PY'
import hashlib
import json
import sys

resolved_path, raw_path, service_name, container_name, image, source, uid, gid, network = sys.argv[1:]

def validate(path, label):
    value = json.load(open(path, encoding="utf-8"))
    if not isinstance(value, dict):
        raise SystemExit(f"{label} Compose projection is not an object")
    services = value.get("services")
    if not isinstance(services, dict) or service_name not in services:
        raise SystemExit(f"{label} Compose projection has no admitted Sub2API service")
    service = services[service_name]
    if not isinstance(service, dict):
        raise SystemExit(f"{label} Sub2API service is invalid")
    exact = {
        "image": image,
        "container_name": container_name,
        "read_only": True,
        "user": f"{uid}:{gid}",
        "restart": "unless-stopped",
        "pull_policy": "never",
    }
    for key, expected in exact.items():
        if service.get(key) != expected:
            raise SystemExit(f"{label} Sub2API service {key} does not match the immutable policy")
    if service.get("cap_drop") != ["ALL"]:
        raise SystemExit(f"{label} Sub2API service must drop exactly ALL capabilities")
    if service.get("security_opt") not in (["no-new-privileges"], ["no-new-privileges:true"]):
        raise SystemExit(f"{label} Sub2API service must enable only no-new-privileges")
    for key in ("build", "cap_add", "devices", "ipc", "pid", "network_mode", "tmpfs", "volumes_from"):
        if service.get(key) not in (None, [], {}):
            raise SystemExit(f"{label} Sub2API service has prohibited {key}")
    if service.get("privileged") not in (None, False):
        raise SystemExit(f"{label} Sub2API service is privileged")
    if service.get("command") is not None or service.get("entrypoint") is not None:
        raise SystemExit(f"{label} Sub2API service overrides the immutable process")
    ports = service.get("ports")
    expected_port = {
        "mode": "ingress",
        "target": 8080,
        "published": "8080",
        "protocol": "tcp",
        "host_ip": "127.0.0.1",
    }
    if ports != [expected_port]:
        raise SystemExit(f"{label} Sub2API service does not publish only loopback 8080")
    volumes = service.get("volumes")
    if not isinstance(volumes, list) or len(volumes) != 1 or not isinstance(volumes[0], dict):
        raise SystemExit(f"{label} Sub2API service must have one data mount")
    volume = volumes[0]
    if (
        volume.get("type") != "bind"
        or volume.get("source") != source
        or volume.get("target") != "/app/data"
        or volume.get("read_only") not in (None, False)
    ):
        raise SystemExit(f"{label} Sub2API service data bind does not match")
    bind = volume.get("bind")
    if not isinstance(bind, dict) or bind.get("propagation") != "rprivate" or bind.get("create_host_path") is not False:
        raise SystemExit(f"{label} Sub2API bind must be rprivate and must not create its source")
    service_networks = service.get("networks")
    if not isinstance(service_networks, dict) or len(service_networks) != 1:
        raise SystemExit(f"{label} Sub2API service must use exactly one Compose network")
    logical_network = next(iter(service_networks))
    networks = value.get("networks")
    network_config = networks.get(logical_network) if isinstance(networks, dict) else None
    if (
        not isinstance(network_config, dict)
        or network_config.get("name") != network
        or network_config.get("external") is not True
    ):
        raise SystemExit(f"{label} Sub2API network is not the exact external network")
    for key in ("configs", "secrets"):
        if service.get(key) not in (None, [], {}):
            raise SystemExit(f"{label} Sub2API service has additional {key} mounts")
    return service

resolved_service = validate(resolved_path, "resolved")
raw_service = validate(raw_path, "uninterpolated")
if raw_service.get("image") != image or raw_service.get("volumes", [{}])[0].get("source") != source:
    raise SystemExit("Sub2API image and bind source must be literal in the immutable Compose file")
print(hashlib.sha256(json.dumps(resolved_service, sort_keys=True, separators=(",", ":")).encode()).hexdigest())
PY
  chmod 0600 "$hash_output"
}

wait_healthy() {
  target_id=$1
  elapsed=0
  while [ "$elapsed" -lt "$health_timeout" ]; do
    status=$(docker container inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}missing{{end}}' "$target_id") \
      || return 1
    [ "$status" = "healthy" ] && return 0
    [ "$status" = "unhealthy" ] && return 1
    sleep 1
    elapsed=$((elapsed + 1))
  done
  return 1
}

create_data_archive() {
  archive=$1
  listing=$2
  checksum=$3
  [ ! -e "$archive" ] && [ ! -L "$archive" ] || fail "refusing to overwrite data archive"
  tar --create --file "$archive" --format=posix --numeric-owner --one-file-system \
    --directory "$data_source" .
  chmod 0600 "$archive"
  tar --list --file "$archive" > "$listing"
  chmod 0600 "$listing"
  sha256sum "$archive" > "$checksum"
  chmod 0600 "$checksum"
  sha256sum -c "$checksum" >/dev/null
  python3 -I - "$archive" "$listing" "$checksum" "$(dirname -- "$archive")" <<'PY'
import os
import sys
for value in sys.argv[1:]:
    descriptor = os.open(value, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
PY
}

stable_copy_file() {
  source=$1
  destination=$2
  python3 -I - "$source" "$destination" <<'PY'
import hashlib
import os
import stat
import sys
from pathlib import Path

source, destination = map(Path, sys.argv[1:])
read_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
descriptor = os.open(source, read_flags)
try:
    before = os.fstat(descriptor)
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        raise SystemExit("stable-copy source is not a single-link regular file")
    write_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    output_descriptor = os.open(destination, write_flags, 0o600)
    digest = hashlib.sha256()
    try:
        while True:
            block = os.read(descriptor, 1024 * 1024)
            if not block:
                break
            digest.update(block)
            pending = memoryview(block)
            while pending:
                written = os.write(output_descriptor, pending)
                pending = pending[written:]
        os.fsync(output_descriptor)
    finally:
        os.close(output_descriptor)
    after = os.fstat(descriptor)
    fields = ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")
    if any(getattr(before, field) != getattr(after, field) for field in fields):
        raise SystemExit("stable-copy source changed during capture")
finally:
    os.close(descriptor)
print(digest.hexdigest())
print(f"{stat.S_IMODE(before.st_mode):04o}")
PY
}

atomic_install_file() {
  source=$1
  destination=$2
  mode=$3
  expected_sha=$4
  expected_current_sha=$5
  python3 -I - "$source" "$destination" "$mode" "$expected_sha" \
    "$expected_current_sha" <<'PY'
import hashlib
import os
import stat
import sys
from pathlib import Path

source = Path(sys.argv[1])
destination = Path(sys.argv[2])
mode = int(sys.argv[3], 8)
expected = sys.argv[4]
expected_current = sys.argv[5]
flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
source_descriptor = os.open(source, flags)
try:
    before = os.fstat(source_descriptor)
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        raise SystemExit("atomic-install source is not a single-link regular file")
    payload = bytearray()
    while True:
        block = os.read(source_descriptor, 1024 * 1024)
        if not block:
            break
        payload.extend(block)
    after = os.fstat(source_descriptor)
    fields = ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")
    if any(getattr(before, field) != getattr(after, field) for field in fields):
        raise SystemExit("atomic-install source changed during read")
finally:
    os.close(source_descriptor)
if hashlib.sha256(payload).hexdigest() != expected:
    raise SystemExit("atomic-install source digest mismatch")
destination_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
destination_descriptor = os.open(destination, destination_flags)
try:
    current = os.fstat(destination_descriptor)
    if (
        not stat.S_ISREG(current.st_mode)
        or current.st_uid != 0
        or current.st_nlink != 1
    ):
        raise SystemExit("atomic-install destination is unsafe")
    current_digest = hashlib.sha256()
    while True:
        block = os.read(destination_descriptor, 1024 * 1024)
        if not block:
            break
        current_digest.update(block)
finally:
    os.close(destination_descriptor)
if current_digest.hexdigest() != expected_current:
    raise SystemExit("atomic-install destination digest mismatch")
if stat.S_ISLNK(destination.lstat().st_mode):
    raise SystemExit("atomic-install destination is unsafe")
temporary = destination.parent / f".{destination.name}.immutable-{os.getpid()}"
write_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
descriptor = os.open(temporary, write_flags, mode)
try:
    pending = memoryview(payload)
    while pending:
        written = os.write(descriptor, pending)
        pending = pending[written:]
    os.fchmod(descriptor, mode)
    os.fsync(descriptor)
finally:
    os.close(descriptor)
os.replace(temporary, destination)
directory = os.open(destination.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
try:
    os.fsync(directory)
finally:
    os.close(directory)
PY
}

write_rollback_override() {
  destination=$1
  image_id=$2
  python3 -I - "$destination" "$compose_service" "$image_id" <<'PY'
import hashlib
import json
import os
import re
import sys
from pathlib import Path

destination = Path(sys.argv[1])
service = sys.argv[2]
image_id = sys.argv[3]
if re.fullmatch(r"[A-Za-z0-9_.-]+", service) is None:
    raise SystemExit("rollback Compose service is not canonical")
if re.fullmatch(r"sha256:[0-9a-f]{64}", image_id) is None:
    raise SystemExit("rollback image ID is not canonical")
payload = (
    json.dumps(
        {
            "services": {
                service: {"image": image_id, "pull_policy": "never"},
            }
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    + "\n"
).encode("ascii")
flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
descriptor = os.open(destination, flags, 0o600)
with os.fdopen(descriptor, "wb") as output:
    output.write(payload)
    output.flush()
    os.fsync(output.fileno())
print(hashlib.sha256(payload).hexdigest())
PY
}

compose_up_service() {
  primary=$1
  override=${2:-}
  selected_environment=${3:-$compose_environment}
  clean_path=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
  if [ -n "$override" ]; then
    env -i PATH="$clean_path" HOME=/root \
      docker compose \
      --project-name "$compose_project" \
      --project-directory "$(dirname -- "$compose_file")" \
      --env-file "$selected_environment" \
      --file "$primary" \
      --file "$override" \
      up --detach --no-deps --pull never --force-recreate "$compose_service"
  else
    env -i PATH="$clean_path" HOME=/root \
      docker compose \
      --project-name "$compose_project" \
      --project-directory "$(dirname -- "$compose_file")" \
      --env-file "$selected_environment" \
      --file "$primary" \
      up --detach --no-deps --pull never --force-recreate "$compose_service"
  fi
}

write_backup_ready() {
  destination=$1
  transaction_id=$2
  old_id=$3
  old_inspect=$4
  live_archive=$5
  live_listing=$6
  active_compose_backup=$7
  candidate_compose_backup=$8
  environment_backup=$9
  shift 9
  resolved_compose=$1
  python3 -I - "$destination" "$transaction_id" "$old_id" "$old_inspect" \
    "$live_archive" "$live_listing" "$data_source" "$active_compose_backup" \
    "$candidate_compose_backup" "$environment_backup" "$resolved_compose" <<'PY'
import hashlib
import json
import os
import sys
from datetime import UTC, datetime
from pathlib import Path

destination = Path(sys.argv[1])
transaction_id, old_id = sys.argv[2:4]
old_inspect, archive, listing, source, active, candidate, environment, resolved = map(
    Path, sys.argv[4:12]
)

def digest(path):
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()

payload = {
    "format_version": 1,
    "transaction_id": transaction_id,
    "created_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
    "status": "backup_ready_before_mutation",
    "old_container_id": old_id,
    "data_source": str(source),
    "container_inspect_sha256": digest(old_inspect),
    "data_archive": archive.name,
    "data_archive_sha256": digest(archive),
    "data_listing_sha256": digest(listing),
    "active_compose_backup": active.name,
    "active_compose_backup_sha256": digest(active),
    "immutable_compose_candidate": candidate.name,
    "immutable_compose_candidate_sha256": digest(candidate),
    "compose_environment_backup": environment.name,
    "compose_environment_backup_sha256": digest(environment),
    "resolved_compose": resolved.name,
    "resolved_compose_sha256": digest(resolved),
}
flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
fd = os.open(destination, flags, 0o600)
with os.fdopen(fd, "w", encoding="utf-8") as output:
    json.dump(payload, output, indent=2, sort_keys=True)
    output.write("\n")
    output.flush()
    os.fsync(output.fileno())
PY
}

write_result() {
  destination=$1
  transaction_id=$2
  old_id=$3
  old_image_id=$4
  rollback_image_id=$5
  new_id=$6
  locked_image=$7
  locked_image_id=$8
  backup_ready=$9
  shift 9
  live_archive=$1
  quiesced_archive=$2
  attestation=$3
  runtime_environment=$4
  container_name=$5
  candidate_inspect=$6
  locked_image_inspect=$7
  rollback_image_inspect=$8
  active_compose_backup=$9
  shift 9
  candidate_compose_backup=$1
  environment_backup=$2
  resolved_compose=$3
  compose_file_path=$4
  active_compose_sha=$5
  active_compose_mode_value=$6
  candidate_compose_sha=$7
  environment_sha=$8
  rollback_override_file=$9
  shift 9
  rollback_override_sha=$1
  project_name=$2
  service_name=$3
  service_hash=$4
  python3 -I - "$destination" "$transaction_id" "$old_id" "$old_image_id" \
    "$rollback_image_id" "$new_id" "$locked_image" "$locked_image_id" \
    "$backup_ready" "$live_archive" "$quiesced_archive" "$attestation" \
    "$runtime_environment" "$container_name" "$candidate_inspect" \
    "$locked_image_inspect" "$rollback_image_inspect" "$active_compose_backup" \
    "$candidate_compose_backup" "$environment_backup" "$resolved_compose" \
    "$compose_file_path" "$active_compose_sha" "$active_compose_mode_value" \
    "$candidate_compose_sha" "$environment_sha" "$rollback_override_file" \
    "$rollback_override_sha" "$project_name" "$service_name" "$service_hash" \
    "$data_source" "$expected_uid" "$expected_gid" \
    "$expected_mode" "$expected_network" "$expected_alias" \
    "$operation_lock_path" "$operation_lock_identity" <<'PY'
import hashlib
import json
import os
import sys
from datetime import UTC, datetime
from pathlib import Path

(
    destination,
    transaction_id,
    old_id,
    old_image_id,
    rollback_image_id,
    new_id,
    image,
    image_id,
    backup_ready,
    live_archive,
    quiesced_archive,
    attestation,
    runtime_environment,
    container_name,
    candidate_inspect,
    locked_image_inspect,
    rollback_image_inspect,
    active_compose_backup,
    candidate_compose_backup,
    environment_backup,
    resolved_compose,
    compose_file_path,
    active_compose_sha,
    active_compose_mode,
    candidate_compose_sha,
    environment_sha,
    rollback_override_file,
    rollback_override_sha,
    project_name,
    service_name,
    service_hash,
    source,
    uid,
    gid,
    mode,
    network,
    alias,
    operation_lock_path,
    operation_lock_identity,
) = sys.argv[1:]

def digest(value):
    result = hashlib.sha256()
    with Path(value).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(block)
    return result.hexdigest()

payload = {
    "format_version": 1,
    "transaction_id": transaction_id,
    "completed_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
    "status": "immutable_candidate_running",
    "old_container": {
        "id": old_id,
        "image_id": old_image_id,
        "rollback_image_id": rollback_image_id,
        "state": "snapshotted_and_removed",
    },
    "new_container": {
        "id": new_id,
        "name": container_name,
        "image": image,
        "image_id": image_id,
        "state": "healthy",
    },
    "data_mount": {
        "type": "bind",
        "source": source,
        "destination": "/app/data",
        "read_write": True,
        "propagation": "rprivate",
        "source_uid": int(uid),
        "source_gid": int(gid),
        "source_mode": mode,
    },
    "network": {"name": network, "alias": alias, "published_endpoint": "127.0.0.1:8080"},
    "operation_lock": {
        "path": operation_lock_path,
        "identity": operation_lock_identity,
        "held_while_receipt_written": True,
    },
    "backup": {
        "ready_receipt": Path(backup_ready).name,
        "ready_receipt_sha256": digest(backup_ready),
        "live_archive": Path(live_archive).name,
        "live_archive_sha256": digest(live_archive),
        "quiesced_archive": Path(quiesced_archive).name,
        "quiesced_archive_sha256": digest(quiesced_archive),
        "runtime_environment": Path(runtime_environment).name,
        "runtime_environment_sha256": digest(runtime_environment),
    },
    "compose": {
        "active_path": compose_file_path,
        "previous_artifact": Path(active_compose_backup).name,
        "previous_sha256": active_compose_sha,
        "previous_mode": active_compose_mode,
        "installed_artifact": Path(candidate_compose_backup).name,
        "installed_sha256": candidate_compose_sha,
        "environment_artifact": Path(environment_backup).name,
        "environment_sha256": environment_sha,
        "resolved_artifact": Path(resolved_compose).name,
        "resolved_sha256": digest(resolved_compose),
        "project": project_name,
        "service": service_name,
        "service_projection_sha256": service_hash,
        "rollback_override_artifact": Path(rollback_override_file).name,
        "rollback_override_sha256": rollback_override_sha,
    },
    "runtime_attestation": {
        "path": Path(attestation).name,
        "sha256": digest(attestation),
        "container_inspect": Path(candidate_inspect).name,
        "container_inspect_sha256": digest(candidate_inspect),
        "image_inspect": Path(locked_image_inspect).name,
        "image_inspect_sha256": digest(locked_image_inspect),
        "rollback_image_inspect": Path(rollback_image_inspect).name,
        "rollback_image_inspect_sha256": digest(rollback_image_inspect),
    },
    "rollback": {
        "automatic_data_restore": False,
        "candidate_id_must_match": new_id,
        "rollback_image_id_must_match": rollback_image_id,
    },
}
flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
fd = os.open(destination, flags, 0o600)
with os.fdopen(fd, "w", encoding="utf-8") as output:
    json.dump(payload, output, indent=2, sort_keys=True)
    output.write("\n")
    output.flush()
    os.fsync(output.fileno())
PY
}

if [ "$action" = "rollback" ]; then
  rollback_preflight=$(mktemp "${TMPDIR:-/tmp}/sub2api-immutable-rollback.XXXXXX")
  trap 'rm -f "$rollback_preflight"' EXIT
  trap 'exit 129' HUP
  trap 'exit 130' INT
  trap 'exit 143' TERM
  validate_paths_and_lock "$rollback_preflight" \
    || fail "rollback path or release-lock preflight failed"
  rm -f "$rollback_preflight"
  trap - EXIT HUP INT TERM
  operation_lock_held=0
  rollback_pre_mutation_abort() {
    status=$?
    trap - EXIT HUP INT TERM
    release_operation_lock \
      || echo "migrate-sub2api-immutable: operation lock retained after preflight failure" >&2
    exit "$status"
  }
  trap rollback_pre_mutation_abort EXIT
  trap 'exit 129' HUP
  trap 'exit 130' INT
  trap 'exit 143' TERM
  operation_lock_identity=$(acquire_operation_lock rollback "$rollback_receipt") \
    || fail "another immutable migration operation is active or lock creation failed"
  operation_lock_held=1
  [ -f "$rollback_receipt" ] && [ ! -L "$rollback_receipt" ] \
    || fail "rollback receipt must be a real regular file"
  rollback_dir=$(CDPATH= cd -- "$(dirname -- "$rollback_receipt")" && pwd)
  [ ! -e "$rollback_dir/ROLLBACK.json" ] && [ ! -L "$rollback_dir/ROLLBACK.json" ] \
    || fail "rollback receipt already exists"
  values_file=$(mktemp "$rollback_dir/.rollback-values.XXXXXX")
  python3 -I - "$rollback_receipt" "$data_source" "$backup_root" \
    "$compose_file" "$compose_project" "$compose_service" \
    "$compose_environment" "$compose_environment_sha256" "$expected_network" \
    "$expected_alias" > "$values_file" <<'PY'
import hashlib
import json
import os
import re
import stat
import sys
from pathlib import Path

path = Path(sys.argv[1])
if path.name != "RESULT.json" or not path.is_absolute() or os.path.realpath(path, strict=True) != str(path):
    raise SystemExit("rollback receipt must be one canonical absolute path")
if path.parent.parent != Path(sys.argv[3]):
    raise SystemExit("rollback receipt must be in one direct transaction directory")
directory_info = path.parent.lstat()
if directory_info.st_uid != 0 or stat.S_IMODE(directory_info.st_mode) != 0o700:
    raise SystemExit("rollback transaction directory must be root-owned mode 0700")
info = path.lstat()
if info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1:
    raise SystemExit("rollback receipt must be root-owned, single-link, mode 0600")
value = json.loads(path.read_text(encoding="utf-8"))
expected_keys = {
    "format_version", "transaction_id", "completed_at", "status", "old_container",
    "new_container", "data_mount", "network", "operation_lock", "backup", "compose",
    "runtime_attestation", "rollback",
}
if not isinstance(value, dict) or set(value) != expected_keys:
    raise SystemExit("rollback receipt has unexpected fields")
if value.get("format_version") != 1 or value.get("status") != "immutable_candidate_running":
    raise SystemExit("rollback receipt is not an eligible immutable migration result")
transaction_id = value.get("transaction_id")
if not isinstance(transaction_id, str) or re.fullmatch(r"[0-9]{8}T[0-9]{6}Z-[1-9][0-9]*", transaction_id) is None:
    raise SystemExit("rollback receipt has an invalid transaction ID")
if path.parent.name != "sub2api-immutable-" + transaction_id:
    raise SystemExit("rollback transaction directory does not match its receipt")
data_mount = value.get("data_mount", {})
if set(data_mount) != {
    "type", "source", "destination", "read_write", "propagation",
    "source_uid", "source_gid", "source_mode",
} or data_mount.get("source") != sys.argv[2]:
    raise SystemExit("rollback data source does not match the receipt")
network = value.get("network", {})
if set(network) != {"name", "alias", "published_endpoint"} or (
    network.get("name") != sys.argv[9]
    or network.get("alias") != sys.argv[10]
    or network.get("published_endpoint") != "127.0.0.1:8080"
):
    raise SystemExit("rollback network does not match the admitted topology")
historical_lock = value.get("operation_lock", {})
if set(historical_lock) != {"path", "identity", "held_while_receipt_written"} or (
    historical_lock.get("path") != str(Path(sys.argv[3]) / ".sub2api-immutable-operation.lock")
    or re.fullmatch(r"[0-9]+:[0-9]+", historical_lock.get("identity", "")) is None
    or historical_lock.get("held_while_receipt_written") is not True
):
    raise SystemExit("rollback receipt has invalid historical operation-lock evidence")
old = value.get("old_container", {})
new = value.get("new_container", {})
if set(old) != {"id", "image_id", "rollback_image_id", "state"} or old.get("state") != "snapshotted_and_removed":
    raise SystemExit("rollback receipt has invalid snapshot fields")
if set(new) != {"id", "name", "image", "image_id", "state"} or new.get("state") != "healthy":
    raise SystemExit("rollback receipt has invalid candidate-container fields")
if re.fullmatch(r"[0-9a-f]{64}", old.get("id", "")) is None or re.fullmatch(r"[0-9a-f]{64}", new.get("id", "")) is None:
    raise SystemExit("rollback receipt has a non-canonical container ID")
for image_id in (old.get("image_id"), old.get("rollback_image_id"), new.get("image_id")):
    if not isinstance(image_id, str) or re.fullmatch(r"sha256:[0-9a-f]{64}", image_id) is None:
        raise SystemExit("rollback receipt has a non-canonical image ID")
if not isinstance(new.get("name"), str) or "\n" in new["name"]:
    raise SystemExit("rollback receipt has an invalid candidate name")
backup = value.get("backup", {})
if set(backup) != {
    "ready_receipt", "ready_receipt_sha256", "live_archive", "live_archive_sha256",
    "quiesced_archive", "quiesced_archive_sha256", "runtime_environment",
    "runtime_environment_sha256",
}:
    raise SystemExit("rollback receipt has invalid backup fields")
compose = value.get("compose", {})
if set(compose) != {
    "active_path", "previous_artifact", "previous_sha256", "previous_mode",
    "installed_artifact", "installed_sha256", "environment_artifact",
    "environment_sha256", "resolved_artifact", "resolved_sha256", "project",
    "service", "service_projection_sha256", "rollback_override_artifact",
    "rollback_override_sha256",
}:
    raise SystemExit("rollback receipt has invalid Compose fields")
if (
    compose.get("active_path") != sys.argv[4]
    or compose.get("project") != sys.argv[5]
    or compose.get("service") != sys.argv[6]
    or compose.get("environment_sha256") != sys.argv[8]
):
    raise SystemExit("rollback Compose identity does not match the operator input")
rollback = value.get("rollback", {})
if set(rollback) != {
    "automatic_data_restore", "candidate_id_must_match", "rollback_image_id_must_match",
} or rollback.get("automatic_data_restore") is not False:
    raise SystemExit("rollback receipt has invalid rollback constraints")
if rollback.get("candidate_id_must_match") != new["id"] or rollback.get("rollback_image_id_must_match") != old["rollback_image_id"]:
    raise SystemExit("rollback receipt identity constraints are inconsistent")
runtime = value.get("runtime_attestation", {})
if set(runtime) != {
    "path", "sha256", "container_inspect", "container_inspect_sha256",
    "image_inspect", "image_inspect_sha256", "rollback_image_inspect",
    "rollback_image_inspect_sha256",
}:
    raise SystemExit("rollback receipt has invalid runtime evidence fields")

artifact_re = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")
sha_re = re.compile(r"[0-9a-f]{64}")

def digest(candidate):
    result = hashlib.sha256()
    with candidate.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(block)
    return result.hexdigest()

def artifact(name, expected_digest):
    if not isinstance(name, str) or artifact_re.fullmatch(name) is None:
        raise SystemExit("rollback receipt contains an invalid artifact name")
    if not isinstance(expected_digest, str) or sha_re.fullmatch(expected_digest) is None:
        raise SystemExit("rollback receipt contains an invalid artifact digest")
    candidate = path.parent / name
    candidate_info = candidate.lstat()
    if (
        not stat.S_ISREG(candidate_info.st_mode)
        or stat.S_ISLNK(candidate_info.st_mode)
        or candidate_info.st_uid != 0
        or candidate_info.st_nlink != 1
        or stat.S_IMODE(candidate_info.st_mode) != 0o600
        or digest(candidate) != expected_digest
    ):
        raise SystemExit("rollback artifact does not match its root-only receipt")
    return candidate

previous = artifact(compose["previous_artifact"], compose["previous_sha256"])
installed = artifact(compose["installed_artifact"], compose["installed_sha256"])
environment = artifact(compose["environment_artifact"], compose["environment_sha256"])
override = artifact(compose["rollback_override_artifact"], compose["rollback_override_sha256"])
artifact(compose["resolved_artifact"], compose["resolved_sha256"])
runtime_environment = artifact(
    backup["runtime_environment"], backup["runtime_environment_sha256"]
)
if compose.get("previous_mode") not in {"0400", "0440", "0444", "0600", "0640", "0644"}:
    raise SystemExit("rollback previous Compose mode is invalid")
if digest(Path(sys.argv[4])) != compose["installed_sha256"]:
    raise SystemExit("active immutable Compose file drifted after migration")
if digest(Path(sys.argv[7])) != compose["environment_sha256"] or digest(environment) != sys.argv[8]:
    raise SystemExit("rollback Compose environment drifted after migration")
print(old["id"])
print(old["rollback_image_id"])
print(new["id"])
print(new["image_id"])
print(new["name"])
print(transaction_id)
print(previous)
print(compose["previous_sha256"])
print(compose["previous_mode"])
print(installed)
print(compose["installed_sha256"])
print(override)
print(compose["rollback_override_sha256"])
print(runtime_environment)
PY
  chmod 0600 "$values_file"
  old_id=$(sed -n '1p' "$values_file")
  rollback_image_id=$(sed -n '2p' "$values_file")
  new_id=$(sed -n '3p' "$values_file")
  candidate_image_id=$(sed -n '4p' "$values_file")
  receipt_container=$(sed -n '5p' "$values_file")
  transaction_id=$(sed -n '6p' "$values_file")
  active_compose_backup=$(sed -n '7p' "$values_file")
  active_compose_sha256=$(sed -n '8p' "$values_file")
  active_compose_mode=$(sed -n '9p' "$values_file")
  candidate_compose_backup=$(sed -n '10p' "$values_file")
  compose_candidate_sha256=$(sed -n '11p' "$values_file")
  rollback_override=$(sed -n '12p' "$values_file")
  rollback_override_sha256=$(sed -n '13p' "$values_file")
  rollback_runtime_environment=$(sed -n '14p' "$values_file")
  rm -f "$values_file"
  [ "$receipt_container" = "$container" ] || fail "rollback container name mismatch"
  current_inspect="$rollback_dir/candidate-before-rollback.json"
  [ ! -e "$current_inspect" ] && [ ! -L "$current_inspect" ] \
    || fail "candidate rollback inspect evidence already exists"
  docker container inspect "$container" > "$current_inspect" \
    || fail "candidate container is missing"
  chmod 0600 "$current_inspect"
  python3 -I - "$current_inspect" "$new_id" "$candidate_image_id" "$container" \
    "$compose_project" "$compose_service" <<'PY'
import json
import sys
value = json.load(open(sys.argv[1], encoding="utf-8"))
if not isinstance(value, list) or len(value) != 1 or not isinstance(value[0], dict):
    raise SystemExit("candidate rollback inspect is invalid")
candidate = value[0]
labels = candidate.get("Config", {}).get("Labels") or {}
if (
    candidate.get("Id") != sys.argv[2]
    or candidate.get("Image") != sys.argv[3]
    or candidate.get("Name") != "/" + sys.argv[4]
    or labels.get("com.docker.compose.project") != sys.argv[5]
    or labels.get("com.docker.compose.service") != sys.argv[6]
    or labels.get("com.docker.compose.oneoff") != "False"
):
    raise SystemExit("candidate container identity or Compose ownership drifted")
PY
  rollback_image_inspect="$rollback_dir/rollback-image-before-rollback.json"
  [ ! -e "$rollback_image_inspect" ] && [ ! -L "$rollback_image_inspect" ] \
    || fail "rollback image inspect evidence already exists"
  docker image inspect "$rollback_image_id" > "$rollback_image_inspect" \
    || fail "rollback snapshot image is missing"
  chmod 0600 "$rollback_image_inspect"
  python3 -I - "$rollback_image_inspect" "$rollback_image_id" <<'PY'
import json
import sys
value = json.load(open(sys.argv[1], encoding="utf-8"))
if not isinstance(value, list) or len(value) != 1 or value[0].get("Id") != sys.argv[2]:
    raise SystemExit("rollback snapshot image identity drifted")
PY
  rollback_succeeded=0
  candidate_removed=0
  compose_restored=0
  rollback_abort() {
    status=$?
    trap - EXIT HUP INT TERM
    [ "$rollback_succeeded" = "1" ] && exit "$status"
    set +e
    recovery_status=manual_rollback_failed
    recovery_complete=0
    recovered_id=
    if [ "$candidate_removed" = "0" ]; then
      observed_candidate=$(docker container inspect --format '{{.Id}}' "$container" 2>/dev/null)
      if [ "$observed_candidate" = "$new_id" ]; then
        docker container start "$new_id" >/dev/null 2>&1
        if wait_healthy "$new_id" >/dev/null 2>&1; then
          recovery_status=immutable_candidate_restart_complete
          recovery_complete=1
          recovered_id=$new_id
        fi
      fi
    else
      observed_image=$(docker container inspect --format '{{.Image}}' "$container" 2>/dev/null)
      observed_project=$(docker container inspect --format '{{index .Config.Labels "com.docker.compose.project"}}' "$container" 2>/dev/null)
      observed_service=$(docker container inspect --format '{{index .Config.Labels "com.docker.compose.service"}}' "$container" 2>/dev/null)
      if [ "$observed_image" = "$rollback_image_id" ] \
        && [ "$observed_project" = "$compose_project" ] \
        && [ "$observed_service" = "$compose_service" ]; then
        observed_id=$(docker container inspect --format '{{.Id}}' "$container" 2>/dev/null)
        docker container stop "$observed_id" >/dev/null 2>&1
        docker container rm "$observed_id" >/dev/null 2>&1
      fi
      if ! docker container inspect "$container" >/dev/null 2>&1; then
        if [ "$compose_restored" = "1" ]; then
          atomic_install_file "$candidate_compose_backup" "$compose_file" 0444 \
            "$compose_candidate_sha256" "$active_compose_sha256" >/dev/null 2>&1
        fi
        if compose_up_service "$compose_file" "" >/dev/null 2>&1; then
          recovered_id=$(docker container inspect --format '{{.Id}}' "$container" 2>/dev/null)
          recovered_image=$(docker container inspect --format '{{.Image}}' "$container" 2>/dev/null)
          if [ "$recovered_image" = "$candidate_image_id" ] \
            && wait_healthy "$recovered_id" >/dev/null 2>&1; then
            recovery_status=immutable_candidate_recreated
            recovery_complete=1
          else
            recovered_id=
          fi
        fi
      fi
    fi
    python3 -I - "$rollback_dir/ROLLBACK-FAILED.json" "$transaction_id" \
      "$recovery_status" "$old_id" "$new_id" "$recovered_id" <<'PY' >/dev/null 2>&1
import json
import os
import sys
from datetime import UTC, datetime
path, transaction_id, status, old_id, candidate_id, recovered_id = sys.argv[1:]
payload = {
    "format_version": 1,
    "completed_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
    "transaction_id": transaction_id,
    "status": status,
    "old_container_id": old_id,
    "candidate_container_id": candidate_id,
    "recovered_container_id": recovered_id or None,
    "data_restored": False,
}
fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
with os.fdopen(fd, "w", encoding="utf-8") as output:
    json.dump(payload, output, indent=2, sort_keys=True)
    output.write("\n")
    output.flush()
    os.fsync(output.fileno())
PY
    if [ "$recovery_complete" = "1" ]; then
      if ! release_operation_lock; then
        recovery_status="${recovery_status}_lock_retained"
      fi
    fi
    echo "migrate-sub2api-immutable: rollback failed; $recovery_status; data was not restored" >&2
    exit "$status"
  }
  trap rollback_abort EXIT
  trap 'exit 129' HUP
  trap 'exit 130' INT
  trap 'exit 143' TERM
  docker container stop "$new_id" >/dev/null
  stopped_id=$(docker container inspect --format '{{.Id}} {{.State.Running}}' "$container")
  [ "$stopped_id" = "$new_id false" ] || fail "candidate did not stop under its original identity"
  docker container rm "$new_id" >/dev/null
  candidate_removed=1
  atomic_install_file "$active_compose_backup" "$compose_file" \
    "$active_compose_mode" "$active_compose_sha256" "$compose_candidate_sha256"
  compose_restored=1
  compose_up_service "$compose_file" "$rollback_override" \
    "$rollback_runtime_environment"
  restored_id=$(docker container inspect --format '{{.Id}}' "$container")
  restored_inspect="$rollback_dir/restored-container.json"
  docker container inspect "$restored_id" > "$restored_inspect"
  chmod 0600 "$restored_inspect"
  python3 -I - "$restored_inspect" "$restored_id" "$rollback_image_id" \
    "$container" "$compose_project" "$compose_service" "$compose_file" \
    "$rollback_override" <<'PY'
import json
import sys
value = json.load(open(sys.argv[1], encoding="utf-8"))
if not isinstance(value, list) or len(value) != 1 or not isinstance(value[0], dict):
    raise SystemExit("restored container inspect is invalid")
restored = value[0]
labels = restored.get("Config", {}).get("Labels") or {}
config_files = set(labels.get("com.docker.compose.project.config_files", "").split(","))
if (
    restored.get("Id") != sys.argv[2]
    or restored.get("Image") != sys.argv[3]
    or restored.get("Name") != "/" + sys.argv[4]
    or labels.get("com.docker.compose.project") != sys.argv[5]
    or labels.get("com.docker.compose.service") != sys.argv[6]
    or labels.get("com.docker.compose.oneoff") != "False"
    or config_files != {sys.argv[7], sys.argv[8]}
):
    raise SystemExit("restored container does not match the rollback Compose identity")
PY
  wait_healthy "$restored_id" || fail "snapshot rollback container did not become healthy"
  python3 -I - "$rollback_dir/ROLLBACK.json" "$rollback_receipt" "$old_id" \
    "$rollback_image_id" "$new_id" "$restored_id" "$compose_file" \
    "$active_compose_sha256" "$rollback_override" \
    "$rollback_override_sha256" <<'PY'
import hashlib
import json
import os
import sys
from datetime import UTC, datetime
from pathlib import Path

destination = Path(sys.argv[1])
source = Path(sys.argv[2])
(
    old_id,
    rollback_image_id,
    candidate_id,
    restored_id,
    compose_path,
    compose_sha256,
    override_path,
    override_sha256,
) = sys.argv[3:]
payload = {
    "format_version": 1,
    "completed_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
    "status": "compose_snapshot_rollback_complete",
    "migration_receipt": source.name,
    "migration_receipt_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
    "old_container_id": old_id,
    "rollback_image_id": rollback_image_id,
    "removed_candidate_id": candidate_id,
    "restored_container_id": restored_id,
    "restored_compose_path": compose_path,
    "restored_compose_sha256": compose_sha256,
    "rollback_override": Path(override_path).name,
    "rollback_override_sha256": override_sha256,
    "data_restored": False,
}
flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
fd = os.open(destination, flags, 0o600)
with os.fdopen(fd, "w", encoding="utf-8") as output:
    json.dump(payload, output, indent=2, sort_keys=True)
    output.write("\n")
    output.flush()
    os.fsync(output.fileno())
PY
  rollback_succeeded=1
  if ! release_operation_lock; then
    trap - EXIT HUP INT TERM
    fail "rollback completed but operation lock release failed; lock retained"
  fi
  trap - EXIT HUP INT TERM
  echo "Sub2API Compose snapshot rollback completed without restoring data: $rollback_dir/ROLLBACK.json"
  exit 0
fi

preflight_values=$(mktemp "${TMPDIR:-/tmp}/sub2api-immutable-lock.XXXXXX")
cleanup_preflight() { rm -f "$preflight_values" "$preflight_values.image"; }
trap cleanup_preflight EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
validate_paths_and_lock "$preflight_values" || fail "path or release-lock preflight failed"
locked_image=$(sed -n '1p' "$preflight_values")
locked_image_id=$(sed -n '2p' "$preflight_values")
[ -n "$locked_image" ] && [ -n "$locked_image_id" ] || fail "release lock preflight returned no image"
transaction_id=$(date -u '+%Y%m%dT%H%M%SZ')-$$
transaction_dir="$backup_root/sub2api-immutable-$transaction_id"
operation_lock_held=0
apply_pre_mutation_abort() {
  status=$?
  trap - EXIT HUP INT TERM
  cleanup_preflight
  release_operation_lock \
    || echo "migrate-sub2api-immutable: operation lock retained after preflight failure" >&2
  exit "$status"
}
trap apply_pre_mutation_abort EXIT
operation_lock_identity=$(acquire_operation_lock apply "$transaction_dir/RESULT.json") \
  || fail "another immutable migration operation is active or lock creation failed"
operation_lock_held=1

docker image inspect "$locked_image" > "$preflight_values.image"
python3 -I - "$preflight_values.image" "$locked_image" "$locked_image_id" <<'PY'
import json
import sys
value = json.load(open(sys.argv[1], encoding="utf-8"))
if not isinstance(value, list) or len(value) != 1 or not isinstance(value[0], dict):
    raise SystemExit("locked image inspect did not return exactly one object")
if value[0].get("Id") != sys.argv[3] or sys.argv[2] not in value[0].get("RepoDigests", []):
    raise SystemExit("preloaded image does not match the version lock")
PY
rm -f "$preflight_values.image"

mkdir -m 0700 "$transaction_dir" || fail "cannot create no-replace transaction directory"
compose_resolved="$transaction_dir/immutable-compose.resolved.json"
compose_uninterpolated="$transaction_dir/immutable-compose.uninterpolated.json"
compose_hash_file="$transaction_dir/immutable-compose.service.sha256"
render_and_validate_compose "$compose_resolved" "$compose_uninterpolated" \
  "$compose_hash_file"
compose_service_hash=$(sed -n '1p' "$compose_hash_file")
case "$compose_service_hash" in (*[!0-9a-f]*|'') fail "invalid immutable Compose service hash" ;; esac
[ "${#compose_service_hash}" -eq 64 ] || fail "invalid immutable Compose service hash"
old_inspect="$transaction_dir/old-container-before.json"
old_image_inspect="$transaction_dir/old-image.json"
locked_image_inspect="$transaction_dir/locked-image.json"
runtime_env="$transaction_dir/runtime.env"
docker container inspect "$container" > "$old_inspect"
chmod 0600 "$old_inspect"

python3 -I - "$old_inspect" "$container" "$data_source" "$expected_network" \
  "$expected_alias" "$runtime_env" "$compose_project" "$compose_service" \
  "$compose_file" > "$transaction_dir/old-values.txt" <<'PY'
import json
import os
import re
import sys
from pathlib import Path

inspect = json.load(open(sys.argv[1], encoding="utf-8"))
if not isinstance(inspect, list) or len(inspect) != 1 or not isinstance(inspect[0], dict):
    raise SystemExit("current container inspect did not return exactly one object")
value = inspect[0]
container_id = value.get("Id")
if not isinstance(container_id, str) or re.fullmatch(r"[0-9a-f]{64}", container_id) is None:
    raise SystemExit("current container has no full immutable ID")
if value.get("Name") != "/" + sys.argv[2] or value.get("State", {}).get("Running") is not True:
    raise SystemExit("current Sub2API container is not the expected running container")
mounts = value.get("Mounts")
if not isinstance(mounts, list) or len(mounts) != 1:
    raise SystemExit("current Sub2API must have exactly one data mount")
mount = mounts[0]
if (
    mount.get("Type") != "bind"
    or mount.get("Source") != sys.argv[3]
    or mount.get("Destination") != "/app/data"
    or mount.get("RW") is not True
    or mount.get("Propagation") != "rprivate"
):
    raise SystemExit("current Sub2API does not use the exact admitted data bind")
ports = {"8080/tcp": [{"HostIp": "127.0.0.1", "HostPort": "8080"}]}
if value.get("HostConfig", {}).get("PortBindings") != ports:
    raise SystemExit("current Sub2API is not bound only to loopback 127.0.0.1:8080")
networks = value.get("NetworkSettings", {}).get("Networks")
if not isinstance(networks, dict) or set(networks) != {sys.argv[4]}:
    raise SystemExit("current Sub2API network does not match the explicit network")
aliases = networks[sys.argv[4]].get("Aliases")
if not isinstance(aliases, list) or sys.argv[5] not in aliases:
    raise SystemExit("current Sub2API lacks the required network alias")
labels = value.get("Config", {}).get("Labels")
if not isinstance(labels, dict):
    raise SystemExit("current Sub2API has no Compose labels")
if (
    labels.get("com.docker.compose.project") != sys.argv[7]
    or labels.get("com.docker.compose.service") != sys.argv[8]
    or labels.get("com.docker.compose.oneoff") != "False"
):
    raise SystemExit("current Sub2API is outside the admitted Compose project/service")
config_files = labels.get("com.docker.compose.project.config_files", "").split(",")
if config_files != [sys.argv[9]]:
    raise SystemExit("current Sub2API must be owned by exactly the active Compose file")
if labels.get("com.docker.compose.project.working_dir") != str(Path(sys.argv[9]).parent):
    raise SystemExit("current Sub2API Compose working directory drifted")
environment = value.get("Config", {}).get("Env") or []
if not isinstance(environment, list):
    raise SystemExit("current Sub2API environment is invalid")
seen = set()
lines = []
for item in environment:
    if not isinstance(item, str) or "=" not in item or "\x00" in item or "\n" in item or "\r" in item:
        raise SystemExit("current Sub2API environment contains an unsafe value")
    key = item.split("=", 1)[0]
    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key) is None or key in seen:
        raise SystemExit("current Sub2API environment contains an unsafe or duplicate key")
    seen.add(key)
    lines.append(item)
destination = Path(sys.argv[6])
flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
fd = os.open(destination, flags, 0o600)
with os.fdopen(fd, "w", encoding="utf-8") as output:
    for line in lines:
        output.write(line + "\n")
    output.flush()
    os.fsync(output.fileno())
print(container_id)
print(value.get("Image", ""))
PY
chmod 0600 "$transaction_dir/old-values.txt" "$runtime_env"
old_id=$(sed -n '1p' "$transaction_dir/old-values.txt")
old_image_id=$(sed -n '2p' "$transaction_dir/old-values.txt")
docker image inspect "$old_image_id" > "$old_image_inspect"
chmod 0600 "$old_image_inspect"
docker image inspect "$locked_image" > "$locked_image_inspect"
chmod 0600 "$locked_image_inspect"

active_compose_backup="$transaction_dir/active-compose-before.yaml"
candidate_compose_backup="$transaction_dir/immutable-compose-candidate.yaml"
compose_environment_backup="$transaction_dir/compose-environment-before.env"
stable_copy_file "$compose_file" "$active_compose_backup" \
  > "$transaction_dir/active-compose-copy.txt"
stable_copy_file "$compose_candidate" "$candidate_compose_backup" \
  > "$transaction_dir/candidate-compose-copy.txt"
stable_copy_file "$compose_environment" "$compose_environment_backup" \
  > "$transaction_dir/compose-environment-copy.txt"
chmod 0600 "$transaction_dir/active-compose-copy.txt" \
  "$transaction_dir/candidate-compose-copy.txt" \
  "$transaction_dir/compose-environment-copy.txt"
active_compose_sha256=$(sed -n '1p' "$transaction_dir/active-compose-copy.txt")
active_compose_mode=$(sed -n '2p' "$transaction_dir/active-compose-copy.txt")
copied_candidate_sha256=$(sed -n '1p' "$transaction_dir/candidate-compose-copy.txt")
copied_environment_sha256=$(sed -n '1p' "$transaction_dir/compose-environment-copy.txt")
[ "$copied_candidate_sha256" = "$compose_candidate_sha256" ] \
  || fail "immutable Compose candidate changed after preflight"
[ "$copied_environment_sha256" = "$compose_environment_sha256" ] \
  || fail "Compose environment changed after preflight"

live_archive="$transaction_dir/data-live-before-mutation.tar"
live_listing="$transaction_dir/data-live-before-mutation.list"
live_checksum="$transaction_dir/data-live-before-mutation.sha256"
create_data_archive "$live_archive" "$live_listing" "$live_checksum"
backup_ready="$transaction_dir/BACKUP-READY.json"
write_backup_ready "$backup_ready" "$transaction_id" "$old_id" "$old_inspect" \
  "$live_archive" "$live_listing" "$active_compose_backup" \
  "$candidate_compose_backup" "$compose_environment_backup" "$compose_resolved"
pre_mutation_recheck="$transaction_dir/pre-mutation-lock-values.txt"
validate_paths_and_lock "$pre_mutation_recheck" \
  || fail "path or release lock changed before mutation"
chmod 0600 "$pre_mutation_recheck"
[ "$(sed -n '1p' "$pre_mutation_recheck")" = "$locked_image" ] \
  && [ "$(sed -n '2p' "$pre_mutation_recheck")" = "$locked_image_id" ] \
  || fail "locked Sub2API image changed before mutation"

mutation_started=0
compose_replaced=0
new_id=
rollback_image_id=
rollback_override=
rollback_override_sha256=
apply_succeeded=0

automatic_rollback() {
  status=$?
  trap - EXIT HUP INT TERM
  cleanup_preflight
  [ "$apply_succeeded" = "1" ] && exit "$status"
  [ "$mutation_started" = "1" ] || exit "$status"
  set +e
  rollback_status="automatic_rollback_failed"
  recovery_complete=0
  restored_id=
  candidate_seen_id=
  observed_name_id=$(docker container inspect --format '{{.Id}}' "$container" 2>/dev/null)
  if [ "$observed_name_id" = "$old_id" ]; then
      docker container start "$old_id" >/dev/null 2>&1
      if wait_healthy "$old_id" >/dev/null 2>&1; then
        rollback_status="automatic_original_container_restart_complete"
        recovery_complete=1
        restored_id=$old_id
      fi
  elif [ -n "$rollback_image_id" ] && [ -n "$rollback_override" ]; then
      observed_image=$(docker container inspect --format '{{.Image}}' "$container" 2>/dev/null)
      observed_project=$(docker container inspect --format '{{index .Config.Labels "com.docker.compose.project"}}' "$container" 2>/dev/null)
      observed_service=$(docker container inspect --format '{{index .Config.Labels "com.docker.compose.service"}}' "$container" 2>/dev/null)
      if [ -n "$observed_name_id" ] \
        && [ "$observed_image" = "$locked_image_id" ] \
        && [ "$observed_project" = "$compose_project" ] \
        && [ "$observed_service" = "$compose_service" ]; then
        candidate_seen_id=$observed_name_id
        docker container stop "$observed_name_id" >/dev/null 2>&1
        docker container rm "$observed_name_id" >/dev/null 2>&1
      fi
      if ! docker container inspect "$container" >/dev/null 2>&1; then
        restore_ready=1
        if [ "$compose_replaced" = "1" ]; then
          atomic_install_file "$active_compose_backup" "$compose_file" \
            "$active_compose_mode" "$active_compose_sha256" \
            "$compose_candidate_sha256" >/dev/null 2>&1 \
            || restore_ready=0
        fi
        current_compose_sha=$(sha256sum "$compose_file" 2>/dev/null | sed -n 's/[[:space:]].*//p')
        [ "$current_compose_sha" = "$active_compose_sha256" ] || restore_ready=0
        if [ "$restore_ready" = "1" ] \
          && compose_up_service "$compose_file" "$rollback_override" \
            "$runtime_env" >/dev/null 2>&1; then
          restored_id=$(docker container inspect --format '{{.Id}}' "$container" 2>/dev/null)
          restored_image=$(docker container inspect --format '{{.Image}}' "$container" 2>/dev/null)
          if [ "$restored_image" = "$rollback_image_id" ] \
            && wait_healthy "$restored_id" >/dev/null 2>&1; then
            rollback_status="automatic_compose_snapshot_rollback_complete"
            recovery_complete=1
          else
            restored_id=
          fi
        fi
      fi
      if [ "$rollback_status" != "automatic_compose_snapshot_rollback_complete" ]; then
        observed_image=$(docker container inspect --format '{{.Image}}' "$container" 2>/dev/null)
        observed_project=$(docker container inspect --format '{{index .Config.Labels "com.docker.compose.project"}}' "$container" 2>/dev/null)
        observed_service=$(docker container inspect --format '{{index .Config.Labels "com.docker.compose.service"}}' "$container" 2>/dev/null)
        if [ "$observed_image" = "$rollback_image_id" ] \
          && [ "$observed_project" = "$compose_project" ] \
          && [ "$observed_service" = "$compose_service" ]; then
          observed_id=$(docker container inspect --format '{{.Id}}' "$container" 2>/dev/null)
          docker container stop "$observed_id" >/dev/null 2>&1
          docker container rm "$observed_id" >/dev/null 2>&1
        fi
        if ! docker container inspect "$container" >/dev/null 2>&1; then
          current_compose_sha=$(sha256sum "$compose_file" 2>/dev/null | sed -n 's/[[:space:]].*//p')
          if [ "$current_compose_sha" = "$active_compose_sha256" ]; then
            atomic_install_file "$candidate_compose_backup" "$compose_file" 0444 \
              "$compose_candidate_sha256" "$active_compose_sha256" >/dev/null 2>&1
          fi
          if compose_up_service "$compose_file" "" >/dev/null 2>&1; then
            restored_id=$(docker container inspect --format '{{.Id}}' "$container" 2>/dev/null)
            restored_image=$(docker container inspect --format '{{.Image}}' "$container" 2>/dev/null)
            if [ "$restored_image" = "$locked_image_id" ] \
              && wait_healthy "$restored_id" >/dev/null 2>&1; then
              rollback_status="automatic_immutable_candidate_recreated"
              recovery_complete=1
            else
              restored_id=
            fi
          fi
        fi
      fi
  fi
  python3 -I - "$transaction_dir/AUTOMATIC-ROLLBACK.json" "$transaction_id" \
    "$rollback_status" "$old_id" "$new_id" "$candidate_seen_id" \
    "$rollback_image_id" "$restored_id" <<'PY' >/dev/null 2>&1
import json, os, sys
from datetime import UTC, datetime
(
    path,
    transaction_id,
    status,
    old_id,
    new_id,
    candidate_seen_id,
    rollback_image_id,
    restored_id,
) = sys.argv[1:]
payload = {
    "format_version": 1,
    "completed_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
    "transaction_id": transaction_id,
    "status": status,
    "old_container_id": old_id,
    "candidate_container_id": new_id or None,
    "observed_candidate_id": candidate_seen_id or None,
    "rollback_image_id": rollback_image_id or None,
    "restored_container_id": restored_id or None,
    "data_restored": False,
}
fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
with os.fdopen(fd, "w", encoding="utf-8") as output:
    json.dump(payload, output, indent=2, sort_keys=True)
    output.write("\n")
    output.flush()
    os.fsync(output.fileno())
PY
  if [ "$recovery_complete" = "1" ]; then
    if ! release_operation_lock; then
      rollback_status="${rollback_status}_lock_retained"
    fi
  fi
  echo "migrate-sub2api-immutable: rollout failed; $rollback_status; evidence retained at $transaction_dir" >&2
  exit "$status"
}
trap automatic_rollback EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

mutation_started=1
docker container stop "$old_id" >/dev/null
stopped_identity=$(docker container inspect --format '{{.Id}} {{.State.Running}}' "$container")
[ "$stopped_identity" = "$old_id false" ] || fail "old container did not stop under its original identity"

quiesced_archive="$transaction_dir/data-quiesced.tar"
quiesced_listing="$transaction_dir/data-quiesced.list"
quiesced_checksum="$transaction_dir/data-quiesced.sha256"
create_data_archive "$quiesced_archive" "$quiesced_listing" "$quiesced_checksum"

rollback_image_id=$(docker container commit --pause=false "$old_id")
case "$rollback_image_id" in (sha256:*) ;; (*) fail "rollback snapshot returned an invalid image ID" ;; esac
[ "${#rollback_image_id}" -eq 71 ] || fail "rollback snapshot did not return a full image ID"
rollback_image_inspect="$transaction_dir/rollback-image.json"
docker image inspect "$rollback_image_id" > "$rollback_image_inspect"
chmod 0600 "$rollback_image_inspect"
rollback_override="$transaction_dir/rollback-compose.override.json"
rollback_override_sha256=$(write_rollback_override \
  "$rollback_override" "$rollback_image_id")
case "$rollback_override_sha256" in
  *[!0-9a-f]*|'') fail "rollback Compose override digest is invalid" ;;
esac
[ "${#rollback_override_sha256}" -eq 64 ] \
  || fail "rollback Compose override digest is invalid"
docker container rm "$old_id" >/dev/null

atomic_install_file "$candidate_compose_backup" "$compose_file" 0444 \
  "$compose_candidate_sha256" "$active_compose_sha256"
compose_replaced=1
compose_up_service "$compose_file" ""
new_id=$(docker container inspect --format '{{.Id}}' "$container")
case "$new_id" in (*[!0-9a-f]*|'') fail "Compose returned an invalid candidate ID" ;; esac
[ "${#new_id}" -eq 64 ] || fail "Compose did not return a full candidate ID"
candidate_inspect="$transaction_dir/candidate-container.json"
docker container inspect "$new_id" > "$candidate_inspect"
chmod 0600 "$candidate_inspect"
python3 -I - "$candidate_inspect" "$locked_image_inspect" "$compose_resolved" \
  "$new_id" "$container" "$compose_project" "$compose_service" "$compose_file" \
  "$compose_service_hash" <<'PY'
import json
import re
import sys

candidate = json.load(open(sys.argv[1], encoding="utf-8"))[0]
image = json.load(open(sys.argv[2], encoding="utf-8"))[0]
compose = json.load(open(sys.argv[3], encoding="utf-8"))
if candidate.get("Id") != sys.argv[4] or candidate.get("Name") != "/" + sys.argv[5]:
    raise SystemExit("candidate container identity does not match Compose")

def environment_map(value, label):
    if not isinstance(value, list):
        raise SystemExit(f"{label} environment is not a list")
    result = {}
    for item in value:
        if not isinstance(item, str) or "=" not in item:
            raise SystemExit(f"{label} environment contains an invalid entry")
        key, entry_value = item.split("=", 1)
        if key in result:
            raise SystemExit(f"{label} environment contains a duplicate key")
        result[key] = entry_value
    return result

expected_environment = environment_map(image.get("Config", {}).get("Env") or [], "image")
compose_environment = compose.get("services", {}).get(sys.argv[7], {}).get("environment") or {}
if not isinstance(compose_environment, dict) or any(
    not isinstance(key, str) or value is not None and not isinstance(value, (str, int, float, bool))
    for key, value in compose_environment.items()
):
    raise SystemExit("resolved Compose environment is invalid")
expected_environment.update(
    {key: "" if value is None else str(value) for key, value in compose_environment.items()}
)
candidate_environment = environment_map(
    candidate.get("Config", {}).get("Env") or [], "candidate"
)
if candidate_environment != expected_environment:
    raise SystemExit("candidate environment differs from the locked image plus captured overrides")
if candidate.get("HostConfig", {}).get("RestartPolicy") != {
    "Name": "unless-stopped",
    "MaximumRetryCount": 0,
}:
    raise SystemExit("candidate container restart policy is not the fixed policy")
labels = candidate.get("Config", {}).get("Labels")
if not isinstance(labels, dict):
    raise SystemExit("candidate container has no Compose labels")
expected_labels = {
    "com.docker.compose.project": sys.argv[6],
    "com.docker.compose.service": sys.argv[7],
    "com.docker.compose.oneoff": "False",
    "com.docker.compose.container-number": "1",
    "com.docker.compose.project.config_files": sys.argv[8],
    "com.docker.compose.project.working_dir": str(__import__("pathlib").Path(sys.argv[8]).parent),
}
for key, expected in expected_labels.items():
    if labels.get(key) != expected:
        raise SystemExit(f"candidate Compose label {key} drifted")
config_hash = labels.get("com.docker.compose.config-hash")
if not isinstance(config_hash, str) or re.fullmatch(r"[0-9a-f]{64}", config_hash) is None:
    raise SystemExit("candidate Compose config hash label is invalid")
compose_image = labels.get("com.docker.compose.image")
if not isinstance(compose_image, str) or re.fullmatch(r"[0-9a-f]{64}", compose_image) is None:
    raise SystemExit("candidate Compose image label is invalid")
if re.fullmatch(r"[0-9a-f]{64}", sys.argv[9]) is None:
    raise SystemExit("admitted Compose service projection hash is invalid")
PY
wait_healthy "$new_id" || fail "immutable candidate did not become healthy within the bound"

attestation="$transaction_dir/immutable-runtime-attestation.json"
SUB2API_CONTAINER="$container" \
VERSIONS_LOCK_FILE="$lock_file" \
SUB2API_ATTESTATION_FILE="$attestation" \
SUB2API_EXPECTED_NETWORK="$expected_network" \
SUB2API_EXPECTED_NETWORK_ALIAS="$expected_alias" \
SUB2API_EXPECTED_DATA_BIND_SOURCE="$data_source" \
SUB2API_EXPECTED_DATA_BIND_UID="$expected_uid" \
SUB2API_EXPECTED_DATA_BIND_GID="$expected_gid" \
SUB2API_EXPECTED_DATA_BIND_MODE="$expected_mode" \
  "$runtime_verifier" > "$transaction_dir/runtime-verifier.log"
chmod 0600 "$transaction_dir/runtime-verifier.log"

result="$transaction_dir/RESULT.json"
write_result "$result" "$transaction_id" "$old_id" "$old_image_id" \
  "$rollback_image_id" "$new_id" "$locked_image" "$locked_image_id" \
  "$backup_ready" "$live_archive" "$quiesced_archive" "$attestation" \
  "$runtime_env" "$container" "$candidate_inspect" "$locked_image_inspect" \
  "$rollback_image_inspect" "$active_compose_backup" \
  "$candidate_compose_backup" "$compose_environment_backup" "$compose_resolved" \
  "$compose_file" "$active_compose_sha256" "$active_compose_mode" \
  "$compose_candidate_sha256" "$compose_environment_sha256" \
  "$rollback_override" "$rollback_override_sha256" "$compose_project" \
  "$compose_service" "$compose_service_hash"
apply_succeeded=1
cleanup_preflight
if ! release_operation_lock; then
  trap - EXIT HUP INT TERM
  fail "candidate is healthy but operation lock release failed; lock retained"
fi
trap - EXIT HUP INT TERM
echo "Sub2API immutable candidate is healthy and attested: $result"
echo "The previous runtime is preserved as rollback image $rollback_image_id; no data restore is automatic."
