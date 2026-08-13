#!/bin/sh
set -euC

umask 077
export PYTHONDONTWRITEBYTECODE=1
export PYTHONNOUSERSITE=1
export PYTHONSAFEPATH=1
export LC_ALL=C
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
unset PYTHONHOME PYTHONPATH

TARGET_RELEASE=0.1.0-bootstrap.20260813.1
TARGET_VCS_REF=d518538f6d36d0c2ff94b7b895798431ee981d6e585aac4732a6a2a2cf0ab8a9
TARGET_BUNDLE_ID=20260812T224530Z
TARGET_MANIFEST_SHA256=7a5bc6f6a8988039fd9715b1ce1b37e4bc3f46b7d3eb96d772886902bb81e227
TARGET_READY_SHA256=0ebbddff6ce9124246398402de8a84b05bf681344dedb9e24a7601d447a83851
TARGET_TRANSPORT_LIST_SHA256=cd8109d9a3a24d39265221ebf34c69ed75d5eb03b446c8419024412c6bb53d99
TARGET_TRANSPORT_SHA256=aa69279c8dafe51d596977df1197d1793ea650e52444d5bad0cdcbe987f00fe7
TARGET_API_ARCHIVE_SHA256=3d15a507c7ee03b9258e8b466cafb5af3db33f9ed5ad0c1a81451c9c8020405b
TARGET_PWA_ARCHIVE_SHA256=fc2c0b88cf535f0a8531a59c5ceaafe4ab0528a1af926e32c07cccb48d99ccf5
TARGET_TOOLS_ARCHIVE_SHA256=07521f878bc1d783843ec7bbd543b623eb35edff788e342f431e86a7e5322fa8
TARGET_PROJECT=sub2api-codex-control

confirm=${CONTROL_IMAGE_ROLLOUT_CONFIRM:-}
record_root=${CONTROL_DEPLOYMENT_RECORD_DIR:-}
base_bootstrap_dir=${CONTROL_BASE_BOOTSTRAP_DIR:-}
bundle_dir=${CONTROL_BUNDLE_DIR:-}
ready_record=${CONTROL_BUNDLE_READY_RECORD:-}
source_root=${CONTROL_TRUSTED_SOURCE_ROOT:-}
old_source_root=${CONTROL_OLD_SOURCE_ROOT:-}
old_compose=${CONTROL_OLD_COMPOSE_SNAPSHOT:-}
migration_state=${CONTROL_MIGRATION_STATE_FILE:-}
operator_exception=${CONTROL_OPERATOR_NO_DUPLICATE_BACKUP_EXCEPTION_FILE:-}
public_origin_file=${CONTROL_PUBLIC_ORIGIN_FILE:-}
trusted_verifier=${CONTROL_TRUSTED_BUNDLE_VERIFIER:-}
trusted_verifier_sha256=${CONTROL_TRUSTED_BUNDLE_VERIFIER_SHA256:-}
tools_root=${CONTROL_ROLLOUT_TOOLS_ROOT:-}
tools_admission=${CONTROL_ROLLOUT_TOOLS_ADMISSION:-}
expected_tools_archive_sha256=${CONTROL_EXPECTED_TOOLS_ARCHIVE_SHA256:-}
expected_tools_verifier_sha256=${CONTROL_EXPECTED_TOOLS_VERIFIER_SHA256:-}
project=${CONTROL_COMPOSE_PROJECT_NAME:-$TARGET_PROJECT}
wait_timeout=${CONTROL_IMAGE_ROLLOUT_WAIT_TIMEOUT_SECONDS:-120}
docker_bin=/usr/bin/docker
ufw_bin=/usr/sbin/ufw
ss_bin=/usr/bin/ss
nginx_root=${CONTROL_NGINX_ROOT:-/etc/nginx}
sub2api_container=sub2api
postgres_container=sub2api-postgres
redis_container=sub2api-redis

admission_helper=
smoke_producer=
record_schema=
tools_manifest=
lock_file=$record_root/.image-rollout.lock
rollout_dir=
runtime_dir=
journal_dir=
rollout_id=
created_at=
stage=initializing
event_sequence=0
completed=0
finalizing=0
archives_loaded=0
loads_attempted=0
context_file=
rollback_summary_file=
terminal_commit_started=0
lock_owned=0

fail() {
  echo "rollout-bootstrap-images: $*" >&2
  exit 1
}

python() {
  /usr/bin/env -u PYTHONHOME -u PYTHONPATH \
    PYTHONDONTWRITEBYTECODE=1 PYTHONNOUSERSITE=1 PYTHONSAFEPATH=1 \
    /usr/bin/python3 -B -I "$@"
}

now() {
  /usr/bin/date -u '+%Y-%m-%dT%H:%M:%SZ'
}

require_absolute() {
  case $1 in
    /*) ;;
    *) fail "$2 must be absolute" ;;
  esac
}

require_sha256() {
  case $1 in
    ''|*[!0-9a-f]*) fail "$2 must be one lowercase SHA-256" ;;
  esac
  [ "${#1}" -eq 64 ] || fail "$2 must be one lowercase SHA-256"
}

fsync_directory() {
  python - "$1" <<'PY'
import os
import sys

fd = os.open(
    sys.argv[1],
    os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0),
)
try:
    os.fsync(fd)
finally:
    os.close(fd)
PY
}

remove_incomplete_lock_publications() {
  python - "$record_root" <<'PY'
import os
import pathlib
import re
import stat
import sys

root = pathlib.Path(sys.argv[1])
root_fd = os.open(root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0))
changed = False
try:
    names = os.listdir(root_fd)
    if ".image-rollout.lock" in names:
        raise SystemExit("a rollout lock appeared while checking incomplete publications")
    temporary_prefix = ".image-rollout.lock.tmp-"
    temporary_pattern = re.compile(
        r"\.image-rollout\.lock\.tmp-([0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})"
    )
    rollout_pattern = re.compile(
        r"image-rollout-[0-9]{8}T[0-9]{6}Z-([0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})"
    )
    temporary_names = [name for name in names if name.startswith(temporary_prefix)]
    if any(temporary_pattern.fullmatch(name) is None for name in temporary_names):
        raise SystemExit("unknown incomplete rollout lock publication")
    for name in sorted(temporary_names):
        match = temporary_pattern.fullmatch(name)
        if match is None:
            raise SystemExit("invalid incomplete rollout lock publication")
        rollout_uuid = match.group(1)
        meta = os.stat(name, dir_fd=root_fd, follow_symlinks=False)
        if (
            not stat.S_ISREG(meta.st_mode) or meta.st_uid != 0 or meta.st_gid != 0 or
            stat.S_IMODE(meta.st_mode) != 0o600 or meta.st_nlink != 1 or
            meta.st_size > 1024 * 1024
        ):
            raise SystemExit("unsafe incomplete rollout lock publication")
        matching_rollouts = [
            candidate for candidate in names
            if (rollout_match := rollout_pattern.fullmatch(candidate)) is not None
            and rollout_match.group(1) == rollout_uuid
        ]
        if len(matching_rollouts) != 1:
            raise SystemExit("incomplete lock is not bound to one rollout directory")
        rollout_name = matching_rollouts[0]
        rollout_meta = os.stat(rollout_name, dir_fd=root_fd, follow_symlinks=False)
        if (
            not stat.S_ISDIR(rollout_meta.st_mode) or rollout_meta.st_uid != 0 or
            rollout_meta.st_gid != 0 or stat.S_IMODE(rollout_meta.st_mode) != 0o700 or
            rollout_meta.st_dev != meta.st_dev
        ):
            raise SystemExit("incomplete lock has an unsafe rollout directory")
        rollout_fd = os.open(
            rollout_name,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0) |
            getattr(os, "O_NOFOLLOW", 0),
            dir_fd=root_fd,
        )
        try:
            journal_meta = os.stat("journal", dir_fd=rollout_fd, follow_symlinks=False)
            if (
                not stat.S_ISDIR(journal_meta.st_mode) or journal_meta.st_uid != 0 or
                journal_meta.st_gid != 0 or stat.S_IMODE(journal_meta.st_mode) != 0o700 or
                journal_meta.st_dev != meta.st_dev
            ):
                raise SystemExit("incomplete lock has an unsafe journal directory")
        finally:
            os.close(rollout_fd)
        os.unlink(name, dir_fd=root_fd)
        changed = True
    if changed:
        os.fsync(root_fd)
finally:
    os.close(root_fd)
PY
}

write_capsule() {
  CREATED_AT=$created_at ROLLOUT_ID=$rollout_id \
  EXPECTED_TOOLS_ARCHIVE_SHA256=$expected_tools_archive_sha256 \
  EXPECTED_TOOLS_VERIFIER_SHA256=$expected_tools_verifier_sha256 \
  TRUSTED_VERIFIER_SHA256=$trusted_verifier_sha256 WAIT_TIMEOUT=$wait_timeout \
  python - \
    "$lock_file" "$rollout_dir" "$journal_dir" "$runtime_dir" \
    "$record_root" "$base_bootstrap_dir" "$bundle_dir" "$ready_record" \
    "$source_root" "$old_source_root" "$old_compose" "$migration_state" \
    "$operator_exception" "$public_origin_file" "$trusted_verifier" \
    "$tools_root" "$tools_manifest" "$tools_admission" "$admission_helper" \
    "$smoke_producer" "$record_schema" "$nginx_root" <<PY
import ctypes
import errno
import hashlib
import json
import os
import pathlib
import stat
import sys

keys = (
    "rollout_dir", "journal_dir", "runtime_dir", "record_root", "base_bootstrap_dir",
    "bundle_dir", "ready_record", "source_root", "old_source_root",
    "old_compose", "migration_state", "operator_exception", "public_origin_file",
    "trusted_verifier", "tools_root", "tools_manifest", "tools_admission",
    "admission_helper", "smoke_producer", "record_schema", "nginx_root",
)
target = pathlib.Path(sys.argv[1])
if len(keys) != len(sys.argv[2:]):
    raise SystemExit("recovery capsule path argument count is invalid")
paths = dict(zip(keys, sys.argv[2:]))
if any(any(ord(character) < 0x20 or ord(character) > 0x7e for character in value) for value in paths.values()):
    raise SystemExit("recovery capsule paths must be printable ASCII")
def read_evidence(path_s):
    path = pathlib.Path(path_s)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or before.st_nlink != 1:
            raise SystemExit(f"unsafe capsule input: {path.name}")
        digest = hashlib.sha256()
        size = 0
        while True:
            try:
                block = os.read(fd, 1024 * 1024)
            except InterruptedError:
                continue
            if not block:
                break
            digest.update(block)
            size += len(block)
        after = os.fstat(fd)
        identity = lambda value: (
            value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid,
            value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns,
        )
        if identity(before) != identity(after) or size != before.st_size:
            raise SystemExit(f"capsule input changed while hashing: {path.name}")
        return {
            "device": before.st_dev,
            "inode": before.st_ino,
            "mode": f"{stat.S_IMODE(before.st_mode):04o}",
            "sha256": digest.hexdigest(),
            "size": size,
        }
    finally:
        os.close(fd)

def directory_evidence(path_s):
    path = pathlib.Path(path_s)
    meta = os.stat(path, follow_symlinks=False)
    if not stat.S_ISDIR(meta.st_mode) or meta.st_uid != 0 or stat.S_IMODE(meta.st_mode) & 0o022:
        raise SystemExit(f"unsafe capsule directory: {path.name}")
    return {
        "device": meta.st_dev,
        "inode": meta.st_ino,
        "mode": f"{stat.S_IMODE(meta.st_mode):04o}",
    }

evidence_paths = {
    "admission_helper": paths["admission_helper"],
    "artifact_manifest": str(pathlib.Path(paths["bundle_dir"]) / "artifact-manifest.json"),
    "base_bootstrap_record": str(pathlib.Path(paths["base_bootstrap_dir"]) / "bootstrap-deployment.json"),
    "base_closure_record": str(pathlib.Path(paths["base_bootstrap_dir"]) / "authenticated-smoke-closure.json"),
    "base_images": str(pathlib.Path(paths["base_bootstrap_dir"]) / "images.json"),
    "base_plan": str(pathlib.Path(paths["base_bootstrap_dir"]) / "plan.json"),
    "base_running": str(pathlib.Path(paths["base_bootstrap_dir"]) / "running-containers.json"),
    "control_api_archive": str(pathlib.Path(paths["bundle_dir"]) / "control-api-linux-amd64.tar"),
    "migration_state": paths["migration_state"],
    "old_compose": paths["old_compose"],
    "operator_exception": paths["operator_exception"],
    "public_origin": paths["public_origin_file"],
    "pwa_archive": str(pathlib.Path(paths["bundle_dir"]) / "pwa-linux-amd64.tar"),
    "ready_record": paths["ready_record"],
    "record_schema": paths["record_schema"],
    "smoke_producer": paths["smoke_producer"],
    "tools_admission": paths["tools_admission"],
    "tools_manifest": paths["tools_manifest"],
    "transport_sums": str(pathlib.Path(paths["bundle_dir"]) / "transport-SHA256SUMS"),
    "trusted_verifier": paths["trusted_verifier"],
    "postgres_tools_archive": str(pathlib.Path(paths["bundle_dir"]) / "postgres-tools-linux-amd64.tar"),
}
evidence = {key: read_evidence(path) for key, path in sorted(evidence_paths.items())}
directories = {
    key: directory_evidence(paths[key])
    for key in (
        "base_bootstrap_dir", "bundle_dir", "nginx_root", "old_source_root",
        "record_root", "rollout_dir", "journal_dir", "source_root", "tools_root",
    )
}

value = {
    "configuration": {
        "expected_tools_archive_sha256": os.environ["EXPECTED_TOOLS_ARCHIVE_SHA256"],
        "expected_tools_verifier_sha256": os.environ["EXPECTED_TOOLS_VERIFIER_SHA256"],
        "trusted_verifier_sha256": os.environ["TRUSTED_VERIFIER_SHA256"],
        "wait_timeout_seconds": int(os.environ["WAIT_TIMEOUT"]),
    },
    "created_at": os.environ["CREATED_AT"],
    "directories": directories,
    "evidence": evidence,
    "paths": paths,
    "rollout_id": os.environ["ROLLOUT_ID"],
    "schema_version": 1,
    "target": {
        "api_archive_sha256": "$TARGET_API_ARCHIVE_SHA256",
        "bundle_id": "$TARGET_BUNDLE_ID",
        "manifest_sha256": "$TARGET_MANIFEST_SHA256",
        "postgres_tools_archive_sha256": "$TARGET_TOOLS_ARCHIVE_SHA256",
        "project": "$TARGET_PROJECT",
        "pwa_archive_sha256": "$TARGET_PWA_ARCHIVE_SHA256",
        "ready_sha256": "$TARGET_READY_SHA256",
        "release": "$TARGET_RELEASE",
        "transport_list_sha256": "$TARGET_TRANSPORT_LIST_SHA256",
        "transport_sha256": "$TARGET_TRANSPORT_SHA256",
        "vcs_ref": "$TARGET_VCS_REF",
    },
    "type": "bootstrap-image-rollout-recovery-capsule-v1",
}
raw = (json.dumps(value, allow_nan=False, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
temporary = target.with_name(f"{target.name}.tmp-{os.environ['ROLLOUT_ID']}")
flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
fd = os.open(temporary, flags, 0o600)
try:
    offset = 0
    while offset < len(raw):
        try:
            written = os.write(fd, raw[offset:])
        except InterruptedError:
            continue
        if written <= 0:
            raise SystemExit("recovery capsule write did not make progress")
        offset += written
    os.fsync(fd)
finally:
    os.close(fd)

libc = ctypes.CDLL(None, use_errno=True)
renameat2 = getattr(libc, "renameat2", None)
if renameat2 is None:
    temporary.unlink(missing_ok=True)
    raise SystemExit("renameat2 is required for atomic lock acquisition")
renameat2.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint)
renameat2.restype = ctypes.c_int
if renameat2(-100, os.fsencode(temporary), -100, os.fsencode(target), 1) != 0:
    error = ctypes.get_errno()
    temporary.unlink(missing_ok=True)
    if error == errno.EEXIST:
        raise SystemExit("stale or active rollout lock exists")
    raise OSError(error, os.strerror(error), str(target))
PY
  fsync_directory "$record_root" || return
}

read_recovery_capsule() {
  EXPECTED_TOOLS_ARCHIVE_SHA256=$expected_tools_archive_sha256 \
  EXPECTED_TOOLS_VERIFIER_SHA256=$expected_tools_verifier_sha256 \
  TRUSTED_VERIFIER_SHA256=$trusted_verifier_sha256 WAIT_TIMEOUT=$wait_timeout \
  python - \
    "$lock_file" "$record_root" "$base_bootstrap_dir" "$bundle_dir" \
    "$ready_record" "$source_root" "$old_source_root" "$old_compose" \
    "$migration_state" "$operator_exception" "$public_origin_file" \
    "$trusted_verifier" "$tools_root" "$tools_manifest" "$tools_admission" \
    "$admission_helper" "$smoke_producer" "$record_schema" "$nginx_root" <<PY
import hashlib
import json
import os
import pathlib
import re
import stat
import sys

(
    lock_s, record_root_s, base_s, bundle_s, ready_s, source_s, old_source_s,
    old_compose_s, migration_s, operator_s, origin_s, verifier_s, tools_root_s,
    manifest_s, tools_admission_s, helper_s, smoke_s, schema_s, nginx_s,
) = sys.argv[1:]
lock = pathlib.Path(lock_s)
record_root = pathlib.Path(record_root_s)
if lock != record_root / ".image-rollout.lock":
    raise SystemExit("recovery lock is not at its fixed path")

def pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result

def identity(meta):
    return (
        meta.st_dev, meta.st_ino, meta.st_mode, meta.st_uid, meta.st_gid,
        meta.st_nlink, meta.st_size, meta.st_mtime_ns, meta.st_ctime_ns,
    )

root_fd = os.open(
    record_root,
    os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0) |
    getattr(os, "O_NOFOLLOW", 0),
)
try:
    fd = os.open(
        lock.name,
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        dir_fd=root_fd,
    )
    try:
        before = os.fstat(fd)
        if (
            not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or
            before.st_gid != 0 or stat.S_IMODE(before.st_mode) != 0o600 or
            before.st_nlink != 1 or before.st_size <= 0 or before.st_size > 1024 * 1024
        ):
            raise SystemExit("unsafe recovery capsule metadata")
        chunks = []
        total = 0
        while True:
            try:
                block = os.read(fd, min(65536, 1024 * 1024 + 1 - total))
            except InterruptedError:
                continue
            if not block:
                break
            chunks.append(block)
            total += len(block)
            if total > 1024 * 1024:
                raise SystemExit("recovery capsule is too large")
        after = os.fstat(fd)
    finally:
        os.close(fd)
    named = os.stat(lock.name, dir_fd=root_fd, follow_symlinks=False)
finally:
    os.close(root_fd)
if identity(before) != identity(after) or identity(after) != identity(named):
    raise SystemExit("recovery capsule changed while it was read")
raw = b"".join(chunks)
try:
    value = json.loads(
        raw.decode("ascii"), object_pairs_hook=pairs,
        parse_constant=lambda token: (_ for _ in ()).throw(ValueError(token)),
    )
except (UnicodeDecodeError, ValueError, json.JSONDecodeError) as exc:
    raise SystemExit(f"invalid recovery capsule JSON: {exc}")
canonical = (json.dumps(value, allow_nan=False, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
if raw != canonical:
    raise SystemExit("recovery capsule is not canonical JSON")
if set(value) != {
    "configuration", "created_at", "directories", "evidence", "paths",
    "rollout_id", "schema_version", "target", "type",
} or value.get("schema_version") != 1 or value.get("type") != "bootstrap-image-rollout-recovery-capsule-v1":
    raise SystemExit("recovery capsule has an invalid closed schema")

configuration = {
    "expected_tools_archive_sha256": os.environ["EXPECTED_TOOLS_ARCHIVE_SHA256"],
    "expected_tools_verifier_sha256": os.environ["EXPECTED_TOOLS_VERIFIER_SHA256"],
    "trusted_verifier_sha256": os.environ["TRUSTED_VERIFIER_SHA256"],
    "wait_timeout_seconds": int(os.environ["WAIT_TIMEOUT"]),
}
if value.get("configuration") != configuration:
    raise SystemExit("recovery configuration differs from the acquired capsule")
target = {
    "api_archive_sha256": "$TARGET_API_ARCHIVE_SHA256",
    "bundle_id": "$TARGET_BUNDLE_ID",
    "manifest_sha256": "$TARGET_MANIFEST_SHA256",
    "postgres_tools_archive_sha256": "$TARGET_TOOLS_ARCHIVE_SHA256",
    "project": "$TARGET_PROJECT",
    "pwa_archive_sha256": "$TARGET_PWA_ARCHIVE_SHA256",
    "ready_sha256": "$TARGET_READY_SHA256",
    "release": "$TARGET_RELEASE",
    "transport_list_sha256": "$TARGET_TRANSPORT_LIST_SHA256",
    "transport_sha256": "$TARGET_TRANSPORT_SHA256",
    "vcs_ref": "$TARGET_VCS_REF",
}
if value.get("target") != target:
    raise SystemExit("recovery target differs from the compiled target")

rollout_id = value.get("rollout_id")
created_at = value.get("created_at")
if not isinstance(rollout_id, str) or re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}", rollout_id) is None:
    raise SystemExit("recovery rollout id is invalid")
if not isinstance(created_at, str) or re.fullmatch(r"20[0-9]{2}-[01][0-9]-[0-3][0-9]T[0-2][0-9]:[0-5][0-9]:[0-5][0-9]Z", created_at) is None:
    raise SystemExit("recovery creation time is invalid")
paths = value.get("paths")
path_keys = {
    "admission_helper", "base_bootstrap_dir", "bundle_dir", "journal_dir",
    "migration_state", "nginx_root", "old_compose", "old_source_root",
    "operator_exception", "public_origin_file", "ready_record", "record_root",
    "record_schema", "rollout_dir", "runtime_dir", "smoke_producer", "source_root",
    "tools_admission", "tools_manifest", "tools_root", "trusted_verifier",
}
if not isinstance(paths, dict) or set(paths) != path_keys:
    raise SystemExit("recovery capsule paths have an invalid closed schema")
for key, path_s in paths.items():
    if not isinstance(path_s, str) or not path_s.startswith("/") or any(ord(character) < 0x20 or ord(character) > 0x7e for character in path_s):
        raise SystemExit(f"invalid recovery path: {key}")

expected_paths = {
    "admission_helper": helper_s,
    "base_bootstrap_dir": base_s,
    "bundle_dir": bundle_s,
    "migration_state": migration_s,
    "nginx_root": nginx_s,
    "old_compose": old_compose_s,
    "old_source_root": old_source_s,
    "operator_exception": operator_s,
    "public_origin_file": origin_s,
    "ready_record": ready_s,
    "record_root": record_root_s,
    "record_schema": schema_s,
    "smoke_producer": smoke_s,
    "source_root": source_s,
    "tools_admission": tools_admission_s,
    "tools_manifest": manifest_s,
    "tools_root": tools_root_s,
    "trusted_verifier": verifier_s,
}
for key, expected in expected_paths.items():
    if paths.get(key) != expected:
        raise SystemExit(f"recovery path differs from current trusted input: {key}")
rollout_dir = pathlib.Path(paths["rollout_dir"])
journal_dir = pathlib.Path(paths["journal_dir"])
runtime_dir = pathlib.Path(paths["runtime_dir"])
if rollout_dir.parent != record_root or re.fullmatch(rf"image-rollout-[0-9]{{8}}T[0-9]{{6}}Z-{re.escape(rollout_id)}", rollout_dir.name) is None:
    raise SystemExit("recovery rollout directory is invalid")
if journal_dir != rollout_dir / "journal":
    raise SystemExit("recovery journal path is invalid")
if runtime_dir != pathlib.Path(f"/run/sub2api-image-rollout-{rollout_id}"):
    raise SystemExit("recovery runtime path is invalid")

def regular_evidence(path_s):
    path = pathlib.Path(path_s)
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0))
    try:
        first = os.fstat(fd)
        if not stat.S_ISREG(first.st_mode) or first.st_uid != 0 or first.st_nlink != 1:
            raise SystemExit(f"unsafe recovery input: {path.name}")
        digest = hashlib.sha256()
        size = 0
        while True:
            try:
                block = os.read(fd, 1024 * 1024)
            except InterruptedError:
                continue
            if not block:
                break
            digest.update(block)
            size += len(block)
        last = os.fstat(fd)
    finally:
        os.close(fd)
    if identity(first) != identity(last) or size != first.st_size:
        raise SystemExit(f"recovery input changed while hashing: {path.name}")
    return {
        "device": first.st_dev, "inode": first.st_ino,
        "mode": f"{stat.S_IMODE(first.st_mode):04o}",
        "sha256": digest.hexdigest(), "size": size,
    }

def directory_evidence(path_s):
    path = pathlib.Path(path_s)
    if path.resolve(strict=True) != path:
        raise SystemExit(f"recovery directory is not canonical: {path.name}")
    meta = os.stat(path, follow_symlinks=False)
    if not stat.S_ISDIR(meta.st_mode) or meta.st_uid != 0 or stat.S_IMODE(meta.st_mode) & 0o022:
        raise SystemExit(f"unsafe recovery directory: {path.name}")
    return {"device": meta.st_dev, "inode": meta.st_ino, "mode": f"{stat.S_IMODE(meta.st_mode):04o}"}

evidence_paths = {
    "admission_helper": helper_s,
    "artifact_manifest": str(pathlib.Path(bundle_s) / "artifact-manifest.json"),
    "base_bootstrap_record": str(pathlib.Path(base_s) / "bootstrap-deployment.json"),
    "base_closure_record": str(pathlib.Path(base_s) / "authenticated-smoke-closure.json"),
    "base_images": str(pathlib.Path(base_s) / "images.json"),
    "base_plan": str(pathlib.Path(base_s) / "plan.json"),
    "base_running": str(pathlib.Path(base_s) / "running-containers.json"),
    "control_api_archive": str(pathlib.Path(bundle_s) / "control-api-linux-amd64.tar"),
    "migration_state": migration_s,
    "old_compose": old_compose_s,
    "operator_exception": operator_s,
    "postgres_tools_archive": str(pathlib.Path(bundle_s) / "postgres-tools-linux-amd64.tar"),
    "public_origin": origin_s,
    "pwa_archive": str(pathlib.Path(bundle_s) / "pwa-linux-amd64.tar"),
    "ready_record": ready_s,
    "record_schema": schema_s,
    "smoke_producer": smoke_s,
    "tools_admission": tools_admission_s,
    "tools_manifest": manifest_s,
    "transport_sums": str(pathlib.Path(bundle_s) / "transport-SHA256SUMS"),
    "trusted_verifier": verifier_s,
}
observed_evidence = {key: regular_evidence(path) for key, path in sorted(evidence_paths.items())}
if value.get("evidence") != observed_evidence:
    raise SystemExit("recovery evidence differs from the acquired capsule")
directory_paths = {
    "base_bootstrap_dir": base_s, "bundle_dir": bundle_s,
    "journal_dir": str(journal_dir), "nginx_root": nginx_s,
    "old_source_root": old_source_s, "record_root": record_root_s,
    "rollout_dir": str(rollout_dir), "source_root": source_s,
    "tools_root": tools_root_s,
}
observed_directories = {key: directory_evidence(path) for key, path in sorted(directory_paths.items())}
if value.get("directories") != observed_directories:
    raise SystemExit("recovery directory identity differs from the acquired capsule")

def read_journal_file(directory_fd, name):
    fd = os.open(
        name,
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        dir_fd=directory_fd,
    )
    try:
        first = os.fstat(fd)
        if (
            not stat.S_ISREG(first.st_mode) or first.st_uid != 0 or first.st_gid != 0 or
            stat.S_IMODE(first.st_mode) != 0o600 or first.st_nlink != 1 or
            first.st_size <= 0 or first.st_size > 1024 * 1024
        ):
            raise SystemExit(f"unsafe journal event metadata: {name}")
        chunks = []
        total = 0
        while True:
            try:
                block = os.read(fd, min(65536, 1024 * 1024 + 1 - total))
            except InterruptedError:
                continue
            if not block:
                break
            chunks.append(block)
            total += len(block)
            if total > 1024 * 1024:
                raise SystemExit(f"journal event is too large: {name}")
        last = os.fstat(fd)
    finally:
        os.close(fd)
    named = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    if identity(first) != identity(last) or identity(last) != identity(named):
        raise SystemExit(f"journal event changed while it was read: {name}")
    event_raw = b"".join(chunks)
    try:
        event = json.loads(
            event_raw.decode("ascii"), object_pairs_hook=pairs,
            parse_constant=lambda token: (_ for _ in ()).throw(ValueError(token)),
        )
    except (UnicodeDecodeError, ValueError, json.JSONDecodeError) as exc:
        raise SystemExit(f"invalid journal JSON in {name}: {exc}")
    event_canonical = (json.dumps(event, allow_nan=False, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
    if event_raw != event_canonical:
        raise SystemExit(f"journal event is not canonical JSON: {name}")
    return event

journal_fd = os.open(
    journal_dir,
    os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0) |
    getattr(os, "O_NOFOLLOW", 0),
)
try:
    names = os.listdir(journal_fd)
    event_pattern = re.compile(r"([0-9]{6})-(load|forward|rollback)-(intent|result)-([a-z0-9-]+)\.json")
    temporary_pattern = re.compile(r"\.([0-9]{6})-(load|forward|rollback)-(intent|result)-([a-z0-9-]+)\.json\.tmp")
    event_names = []
    temporary_names = []
    for name in names:
        if event_pattern.fullmatch(name):
            event_names.append(name)
        elif temporary_pattern.fullmatch(name):
            temporary_names.append(name)
        else:
            raise SystemExit(f"unexpected journal entry: {name}")
    if len(temporary_names) > 1:
        raise SystemExit("multiple incomplete journal publications exist")
    event_names.sort()
    events = []
    event_keys = {
        "admission", "after_projection", "attempt", "completed_at", "direction",
        "phase", "readiness", "recreated", "rollout_id", "schema_version",
        "sequence", "service", "stage", "started_at", "status", "type",
    }
    for expected_sequence, name in enumerate(event_names, 1):
        match = event_pattern.fullmatch(name)
        if match is None or int(match.group(1)) != expected_sequence:
            raise SystemExit("journal sequence is not contiguous")
        event = read_journal_file(journal_fd, name)
        if set(event) != event_keys or event.get("schema_version") != 1 or event.get("type") != "bootstrap-image-rollout-journal-event-v1":
            raise SystemExit(f"journal event has an invalid closed schema: {name}")
        if (
            event.get("sequence") != expected_sequence or
            event.get("direction") != match.group(2) or
            event.get("phase") != match.group(3) or
            event.get("service") != match.group(4) or
            event.get("rollout_id") != rollout_id
        ):
            raise SystemExit(f"journal filename or rollout binding is invalid: {name}")
        events.append(event)
    if temporary_names:
        temporary_name = temporary_names[0]
        match = temporary_pattern.fullmatch(temporary_name)
        meta = os.stat(temporary_name, dir_fd=journal_fd, follow_symlinks=False)
        if (
            match is None or int(match.group(1)) != len(events) + 1 or
            not stat.S_ISREG(meta.st_mode) or meta.st_uid != 0 or meta.st_gid != 0 or
            stat.S_IMODE(meta.st_mode) != 0o600 or meta.st_nlink != 1 or
            meta.st_size > 1024 * 1024
        ):
            raise SystemExit("unsafe incomplete journal publication")
        os.unlink(temporary_name, dir_fd=journal_fd)
        os.fsync(journal_fd)
finally:
    os.close(journal_fd)

timestamp_pattern = re.compile(r"20[0-9]{2}-[01][0-9]-[0-3][0-9]T[0-2][0-9]:[0-5][0-9]:[0-5][0-9]Z")
forward_order = ("control-api-replica", "control-api", "codex-pwa")
load_order = ("control-api", "pwa", "postgres-tools")
forward_intents = []
successful_rollbacks = set()
open_forward = None
open_rollback = None
load_index = 0
open_load = None
load_failed = False
successful_loads = []
rollback_seen = False
last_rollback_attempt = 0
rollback_round = ()
rollback_index = 0
for event in events:
    direction = event["direction"]
    phase = event["phase"]
    service = event["service"]
    status = event["status"]
    started = event["started_at"]
    completed_at = event["completed_at"]
    if not isinstance(started, str) or timestamp_pattern.fullmatch(started) is None:
        raise SystemExit("journal event has an invalid start time")
    if completed_at is not None and (not isinstance(completed_at, str) or timestamp_pattern.fullmatch(completed_at) is None):
        raise SystemExit("journal event has an invalid completion time")
    for key in ("after_projection", "readiness", "admission"):
        path_s = event[key]
        if path_s is not None:
            path = pathlib.Path(path_s)
            if path.parent != rollout_dir or path.resolve(strict=True) != path:
                raise SystemExit(f"journal evidence path is outside the rollout directory: {key}")
            evidence_meta = os.stat(path, follow_symlinks=False)
            if not stat.S_ISREG(evidence_meta.st_mode) or evidence_meta.st_uid != 0 or evidence_meta.st_nlink != 1 or stat.S_IMODE(evidence_meta.st_mode) not in (0o400, 0o600):
                raise SystemExit(f"journal evidence has unsafe metadata: {key}")
    if direction == "load":
        if rollback_seen or forward_intents or load_failed:
            raise SystemExit("load journal event appears after service switching")
        if event["stage"] != "load-images" or event["recreated"] is not False or event["readiness"] is not None or event["admission"] is not None or event["attempt"] is not None:
            raise SystemExit("load journal event semantics are invalid")
        if phase == "intent":
            if open_load is not None or load_index >= len(load_order) or service != load_order[load_index] or status != "pending" or completed_at is not None or event["after_projection"] is not None:
                raise SystemExit("load intent journal sequence is invalid")
            open_load = (service, started)
        elif phase == "result":
            if open_load is None or open_load != (service, started) or status not in ("succeeded", "failed") or completed_at is None:
                raise SystemExit("load result journal sequence is invalid")
            if status == "succeeded" and event["after_projection"] is None:
                raise SystemExit("successful load lacks projected image evidence")
            if status == "failed" and event["after_projection"] is not None:
                raise SystemExit("failed load unexpectedly has projected image evidence")
            if status == "succeeded":
                successful_loads.append(service)
            else:
                load_failed = True
            open_load = None
            load_index += 1
        else:
            raise SystemExit("invalid load journal phase")
    elif direction == "forward":
        if (
            rollback_seen or open_load is not None or load_failed or
            tuple(successful_loads) != load_order or load_index != len(load_order)
        ):
            raise SystemExit("forward journal event appears in an invalid state")
        if event["stage"] != f"switch-{service}" or event["recreated"] is not True or event["attempt"] is not None:
            raise SystemExit("forward journal event semantics are invalid")
        if phase == "intent":
            if open_forward is not None or len(forward_intents) >= len(forward_order) or service != forward_order[len(forward_intents)] or status != "pending" or completed_at is not None or any(event[key] is not None for key in ("after_projection", "readiness", "admission")):
                raise SystemExit("forward intent journal sequence is invalid")
            forward_intents.append(service)
            open_forward = (service, started)
        elif phase == "result":
            if open_forward is None or open_forward != (service, started) or status not in ("succeeded", "failed") or completed_at is None:
                raise SystemExit("forward result journal sequence is invalid")
            if status == "succeeded" and any(event[key] is None for key in ("after_projection", "readiness", "admission")):
                raise SystemExit("successful forward result lacks evidence")
            open_forward = None
        else:
            raise SystemExit("invalid forward journal phase")
    elif direction == "rollback":
        rollback_seen = True
        reverse_prefix = tuple(reversed(forward_intents))
        if not rollback_round or rollback_index >= len(rollback_round):
            rollback_round = tuple(
                candidate for candidate in reverse_prefix
                if candidate not in successful_rollbacks
            )
            rollback_index = 0
        if (
            rollback_index >= len(rollback_round) or service != rollback_round[rollback_index] or
            event["stage"] != f"rollback-{service}" or event["recreated"] is not True or
            not isinstance(event["attempt"], int) or isinstance(event["attempt"], bool) or
            event["attempt"] < 1
        ):
            raise SystemExit("rollback journal event semantics are invalid")
        if phase == "intent":
            if service in successful_rollbacks or status != "pending" or completed_at is not None or any(event[key] is not None for key in ("after_projection", "readiness", "admission")):
                raise SystemExit("rollback intent journal sequence is invalid")
            if open_rollback is not None and open_rollback[0] != service:
                raise SystemExit("rollback changed service with an incomplete prior attempt")
            if event["attempt"] <= last_rollback_attempt:
                raise SystemExit("rollback attempt is not strictly monotonic")
            last_rollback_attempt = event["attempt"]
            open_rollback = (service, started, event["attempt"])
        elif phase == "result":
            if open_rollback != (service, started, event["attempt"]) or status not in ("succeeded", "failed") or completed_at is None or event["admission"] is not None:
                raise SystemExit("rollback result journal sequence is invalid")
            if status == "succeeded":
                if event["after_projection"] is None or event["readiness"] is None:
                    raise SystemExit("successful rollback result lacks evidence")
                successful_rollbacks.add(service)
            open_rollback = None
            rollback_index += 1
        else:
            raise SystemExit("invalid rollback journal phase")
    else:
        raise SystemExit("invalid journal direction")

recovery_runtime = pathlib.Path(f"/run/sub2api-image-rollout-recovery-{rollout_id}-{os.urandom(16).hex()}")
os.mkdir(recovery_runtime, 0o700)
state = {
    "archives_loaded": (
        load_index == len(load_order) and open_load is None and
        all(
            any(
                event["direction"] == "load" and event["phase"] == "result" and
                event["service"] == component and event["status"] == "succeeded"
                for event in events
            )
            for component in load_order
        )
    ),
    "created_at": created_at,
    "event_sequence": len(events),
    "journal_dir": str(journal_dir),
    "original_runtime_dir": str(runtime_dir),
    "rollout_dir": str(rollout_dir),
    "rollout_id": rollout_id,
    "schema_version": 1,
    "load_invoked": any(
        event["direction"] == "load" and event["phase"] == "intent"
        for event in events
    ),
}
state_raw = (json.dumps(state, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
state_path = recovery_runtime / "state.json"
state_fd = os.open(state_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0), 0o600)
try:
    offset = 0
    while offset < len(state_raw):
        try:
            written = os.write(state_fd, state_raw[offset:])
        except InterruptedError:
            continue
        if written <= 0:
            raise SystemExit("recovery state write did not make progress")
        offset += written
    os.fsync(state_fd)
finally:
    os.close(state_fd)
runtime_fd = os.open(recovery_runtime, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0))
try:
    os.fsync(runtime_fd)
finally:
    os.close(runtime_fd)
sys.stdout.write(str(recovery_runtime) + "\n")
PY
}

load_capsule_value() {
  python - "$runtime_dir/state.json" "$1" <<'PY'
import json
import os
import pathlib
import stat
import sys

path = pathlib.Path(sys.argv[1])
fd = os.open(path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0))
try:
    meta = os.fstat(fd)
    if not stat.S_ISREG(meta.st_mode) or meta.st_uid != 0 or meta.st_gid != 0 or stat.S_IMODE(meta.st_mode) != 0o600 or meta.st_nlink != 1 or meta.st_size > 16384:
        raise SystemExit("unsafe recovery state")
    raw = b""
    while len(raw) <= 16384:
        try:
            block = os.read(fd, 16385 - len(raw))
        except InterruptedError:
            continue
        if not block:
            break
        raw += block
finally:
    os.close(fd)
value = json.loads(raw.decode("ascii"))
if set(value) != {"archives_loaded", "created_at", "event_sequence", "journal_dir", "load_invoked", "original_runtime_dir", "rollout_dir", "rollout_id", "schema_version"} or value.get("schema_version") != 1:
    raise SystemExit("invalid recovery state")
key = sys.argv[2]
if key not in value:
    raise SystemExit("unknown recovery state field")
result = value[key]
if isinstance(result, bool):
    result = 1 if result else 0
elif not isinstance(result, (str, int)):
    raise SystemExit("invalid recovery state value")
sys.stdout.write(str(result) + "\n")
PY
}

initialize_event_sequence() {
  event_sequence=$(load_capsule_value event_sequence) || return
}

publish_canonical_json() {
  source_path=$1
  target_path=$2
  target_mode=$3
  ROLLOUT_ID=$rollout_id python - "$source_path" "$target_path" "$target_mode" <<'PY'
import ctypes
import errno
import json
import os
import pathlib
import stat
import sys

source = pathlib.Path(sys.argv[1])
target = pathlib.Path(sys.argv[2])
mode = int(sys.argv[3], 8)
if mode not in (0o400, 0o600):
    raise SystemExit("unsupported evidence mode")
fd = os.open(source, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0))
try:
    before = os.fstat(fd)
    if (
        not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or before.st_gid != 0 or
        stat.S_IMODE(before.st_mode) != 0o600 or before.st_nlink != 1 or
        before.st_size <= 0 or before.st_size > 64 * 1024 * 1024
    ):
        raise SystemExit("unsafe transient evidence metadata")
    chunks = []
    total = 0
    while True:
        try:
            block = os.read(fd, min(1024 * 1024, 64 * 1024 * 1024 + 1 - total))
        except InterruptedError:
            continue
        if not block:
            break
        chunks.append(block)
        total += len(block)
        if total > 64 * 1024 * 1024:
            raise SystemExit("transient evidence is too large")
    after = os.fstat(fd)
finally:
    os.close(fd)
identity = lambda value: (
    value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid,
    value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns,
)
if identity(before) != identity(after) or total != before.st_size:
    raise SystemExit("transient evidence changed while it was read")
raw = b"".join(chunks)

def pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result

try:
    value = json.loads(
        raw.decode("ascii"), object_pairs_hook=pairs,
        parse_constant=lambda token: (_ for _ in ()).throw(ValueError(token)),
    )
except (UnicodeDecodeError, ValueError, json.JSONDecodeError) as exc:
    raise SystemExit(f"transient evidence is not valid JSON: {exc}")
canonical = (json.dumps(value, allow_nan=False, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
if raw != canonical:
    raise SystemExit("transient evidence is not canonical JSON")
temporary = target.with_name(f".{target.name}.tmp-{os.environ['ROLLOUT_ID']}")
out_fd = os.open(
    temporary,
    os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) |
    getattr(os, "O_NOFOLLOW", 0),
    mode,
)
try:
    offset = 0
    while offset < len(raw):
        try:
            written = os.write(out_fd, raw[offset:])
        except InterruptedError:
            continue
        if written <= 0:
            raise SystemExit("evidence write did not make progress")
        offset += written
    os.fsync(out_fd)
finally:
    os.close(out_fd)
libc = ctypes.CDLL(None, use_errno=True)
renameat2 = getattr(libc, "renameat2", None)
if renameat2 is None:
    temporary.unlink(missing_ok=True)
    raise SystemExit("renameat2 is required for evidence publication")
renameat2.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint)
renameat2.restype = ctypes.c_int
if renameat2(-100, os.fsencode(temporary), -100, os.fsencode(target), 1) != 0:
    error = ctypes.get_errno()
    temporary.unlink(missing_ok=True)
    if error == errno.EEXIST:
        raise SystemExit("evidence target already exists")
    raise OSError(error, os.strerror(error), str(target))
directory_fd = os.open(target.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0))
try:
    os.fsync(directory_fd)
finally:
    os.close(directory_fd)
PY
}

journal_event() {
  next_sequence=$((event_sequence + 1))
  sequence=$(printf '%06d' "$next_sequence")
  direction=$1
  phase=$2
  service=$3
  status_value=$4
  started_value=${5:-}
  completed_value=${6:-}
  recreated_value=${7:-false}
  after_value=${8:-}
  readiness_value=${9:-}
  shift 9
  admission_value=${1:-}
  attempt_value=${2:-}
  target="$journal_dir/$sequence-$direction-$phase-$service.json"
  STAGE_VALUE=$stage ROLLOUT_ID=$rollout_id python - "$target" "$next_sequence" "$direction" "$phase" \
    "$service" "$status_value" "$started_value" "$completed_value" \
    "$recreated_value" "$after_value" "$readiness_value" "$admission_value" \
    "$attempt_value" <<'PY'
import json
import os
import pathlib
import ctypes
import errno
import sys

def nullable(value):
    return value if value else None

target = pathlib.Path(sys.argv[1])
value = {
    "admission": nullable(sys.argv[12]),
    "after_projection": nullable(sys.argv[10]),
    "attempt": int(sys.argv[13]) if sys.argv[13] else None,
    "completed_at": nullable(sys.argv[8]),
    "direction": sys.argv[3],
    "phase": sys.argv[4],
    "readiness": nullable(sys.argv[11]),
    "recreated": sys.argv[9] == "true",
    "rollout_id": os.environ["ROLLOUT_ID"],
    "schema_version": 1,
    "sequence": int(sys.argv[2]),
    "service": sys.argv[5],
    "stage": os.environ["STAGE_VALUE"],
    "started_at": nullable(sys.argv[7]),
    "status": sys.argv[6],
    "type": "bootstrap-image-rollout-journal-event-v1",
}
raw = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
temporary = target.with_name(f".{target.name}.tmp")
flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
fd = os.open(temporary, flags, 0o600)
try:
    offset = 0
    while offset < len(raw):
        try:
            written = os.write(fd, raw[offset:])
        except InterruptedError:
            continue
        if written <= 0:
            raise SystemExit("journal event write did not make progress")
        offset += written
    os.fsync(fd)
finally:
    os.close(fd)
libc = ctypes.CDLL(None, use_errno=True)
renameat2 = getattr(libc, "renameat2", None)
if renameat2 is None:
    temporary.unlink(missing_ok=True)
    raise SystemExit("renameat2 is required for durable journal publication")
renameat2.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint)
renameat2.restype = ctypes.c_int
if renameat2(-100, os.fsencode(temporary), -100, os.fsencode(target), 1) != 0:
    error = ctypes.get_errno()
    temporary.unlink(missing_ok=True)
    if error == errno.EEXIST:
        raise SystemExit("journal event already exists")
    raise OSError(error, os.strerror(error), str(target))
PY
  fsync_directory "$journal_dir" || return
  event_sequence=$next_sequence
}

verify_trust_boundary() {
  [ "$(/usr/bin/id -u)" = 0 ] || fail "the rollout wrapper must run as root"
  [ "$confirm" = IMAGE_ONLY_FOLLOWUP ] || fail "CONTROL_IMAGE_ROLLOUT_CONFIRM must equal IMAGE_ONLY_FOLLOWUP"
  [ "$project" = "$TARGET_PROJECT" ] || fail "Compose project differs from the frozen project"
  case $wait_timeout in
    ''|*[!0-9]*|0) fail "CONTROL_IMAGE_ROLLOUT_WAIT_TIMEOUT_SECONDS must be positive" ;;
  esac

  for pair in \
    "$record_root|CONTROL_DEPLOYMENT_RECORD_DIR" \
    "$base_bootstrap_dir|CONTROL_BASE_BOOTSTRAP_DIR" \
    "$bundle_dir|CONTROL_BUNDLE_DIR" \
    "$ready_record|CONTROL_BUNDLE_READY_RECORD" \
    "$source_root|CONTROL_TRUSTED_SOURCE_ROOT" \
    "$old_source_root|CONTROL_OLD_SOURCE_ROOT" \
    "$old_compose|CONTROL_OLD_COMPOSE_SNAPSHOT" \
    "$migration_state|CONTROL_MIGRATION_STATE_FILE" \
    "$operator_exception|CONTROL_OPERATOR_NO_DUPLICATE_BACKUP_EXCEPTION_FILE" \
    "$public_origin_file|CONTROL_PUBLIC_ORIGIN_FILE" \
    "$trusted_verifier|CONTROL_TRUSTED_BUNDLE_VERIFIER" \
    "$tools_root|CONTROL_ROLLOUT_TOOLS_ROOT" \
    "$tools_admission|CONTROL_ROLLOUT_TOOLS_ADMISSION" \
    "$nginx_root|CONTROL_NGINX_ROOT"; do
    value=${pair%%|*}
    label=${pair#*|}
    [ -n "$value" ] || fail "$label is required"
    require_absolute "$value" "$label"
  done
  require_sha256 "$trusted_verifier_sha256" CONTROL_TRUSTED_BUNDLE_VERIFIER_SHA256
  require_sha256 "$expected_tools_archive_sha256" CONTROL_EXPECTED_TOOLS_ARCHIVE_SHA256
  require_sha256 "$expected_tools_verifier_sha256" CONTROL_EXPECTED_TOOLS_VERIFIER_SHA256

  admission_helper=$tools_root/deploy/scripts/image-rollout-admission.py
  smoke_producer=$tools_root/deploy/scripts/image-rollout-smoke.py
  record_schema=$tools_root/deploy/schemas/image-rollout-record.schema.json
  tools_manifest=$tools_root/rollout-tools.manifest.json

  python - "$0" "$tools_root" "$tools_manifest" "$tools_admission" \
    "$expected_tools_archive_sha256" "$expected_tools_verifier_sha256" \
    "$trusted_verifier" "$trusted_verifier_sha256" "$record_root" \
    "$base_bootstrap_dir" "$bundle_dir" "$ready_record" "$source_root" \
    "$old_source_root" "$old_compose" "$migration_state" "$operator_exception" \
    "$public_origin_file" "$docker_bin" "$ufw_bin" "$ss_bin" "$nginx_root" <<'PY'
import hashlib
import json
import os
import pathlib
import stat
import sys

(
    invoked, tools_root_s, manifest_s, admission_s, expected_archive,
    expected_verifier, bundle_verifier_s, bundle_verifier_sha, record_root_s,
    base_s, bundle_s, ready_s, source_s, old_source_s, old_compose_s,
    migration_s, operator_s, origin_s, docker_s, ufw_s, ss_s, nginx_s,
) = sys.argv[1:]

def canonical(path_s, label):
    path = pathlib.Path(path_s)
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise SystemExit(f"{label} is unavailable: {exc}")
    if not path.is_absolute() or resolved != path:
        raise SystemExit(f"{label} must be one canonical absolute path")
    return path

def chain(path, label, stop=pathlib.Path("/")):
    current = canonical(path, label)
    stop = canonical(stop, f"{label} trust root")
    if stop != current and stop not in current.parents:
        raise SystemExit(f"{label} is outside its trust root")
    while True:
        meta = os.stat(current, follow_symlinks=False)
        if not stat.S_ISDIR(meta.st_mode) or meta.st_uid != 0 or stat.S_IMODE(meta.st_mode) & 0o022:
            raise SystemExit(f"{label} has an untrusted ancestor")
        if current == stop:
            return
        current = current.parent

def regular(path_s, label, modes, owner=0, maximum=4 * 1024 * 1024 * 1024):
    path = canonical(path_s, label)
    meta = os.stat(path, follow_symlinks=False)
    if (
        not stat.S_ISREG(meta.st_mode) or meta.st_uid != owner or
        stat.S_IMODE(meta.st_mode) not in modes or meta.st_nlink != 1 or
        meta.st_size <= 0 or meta.st_size > maximum
    ):
        raise SystemExit(f"{label} has unsafe metadata")
    return path, meta

def digest(path):
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()

tools_root = canonical(tools_root_s, "rollout tools root")
chain(tools_root, "rollout tools root")
if stat.S_IMODE(tools_root.stat().st_mode) != 0o555:
    raise SystemExit("rollout tools root must have mode 0555")
expected_invoked = tools_root / "deploy/scripts/rollout-bootstrap-images.sh"
if canonical(invoked, "running wrapper") != expected_invoked:
    raise SystemExit("wrapper is not executing from the admitted tools root")

manifest_path, _ = regular(manifest_s, "rollout tools manifest", {0o444})
admission_path, _ = regular(admission_s, "rollout tools admission", {0o444})
if manifest_path != tools_root / "rollout-tools.manifest.json" or admission_path != tools_root / "rollout-tools.admission.json":
    raise SystemExit("rollout tools evidence is not at its fixed path")
manifest_raw = manifest_path.read_bytes()
admission_raw = admission_path.read_bytes()
manifest = json.loads(manifest_raw)
admission = json.loads(admission_raw)
members = {
    "deploy/scripts/image-rollout-admission.py": ("image-rollout-admission.py", "0555"),
    "deploy/scripts/image-rollout-smoke.py": ("image-rollout-smoke.py", "0555"),
    "deploy/scripts/rollout-bootstrap-images.sh": ("rollout-bootstrap-images.sh", "0555"),
    "deploy/schemas/image-rollout-record.schema.json": ("image-rollout-record.schema.json", "0444"),
}
if set(manifest) != {"files", "identity_sha256", "schema_version", "type"} or manifest.get("schema_version") != 1 or manifest.get("type") != "image-rollout-tools-manifest-v1" or set(manifest.get("files", {})) != set(members):
    raise SystemExit("rollout tools manifest has an invalid closed schema")
projected = {}
admitted_members = {}
for relative, (basename, mode_text) in members.items():
    descriptor = manifest["files"][relative]
    if set(descriptor) != {"mode", "sha256", "size"} or descriptor.get("mode") != mode_text:
        raise SystemExit("rollout tools manifest member is invalid")
    member, meta = regular(tools_root / relative, relative, {int(mode_text, 8)})
    observed = digest(member)
    if descriptor.get("sha256") != observed or descriptor.get("size") != meta.st_size:
        raise SystemExit("rollout tools member differs from its manifest")
    projected[relative] = {"mode": mode_text, "sha256": observed, "size": meta.st_size}
    admitted_members[relative] = {"basename": basename, **projected[relative]}
identity = hashlib.sha256(json.dumps(projected, sort_keys=True, separators=(",", ":")).encode("ascii")).hexdigest()
if manifest.get("identity_sha256") != identity:
    raise SystemExit("rollout tools identity is invalid")
admission_keys = {"archive", "command", "external_verifier", "manifest", "members", "schema_version", "self_sha256", "status", "tooling_identity", "type"}
if set(admission) != admission_keys or admission.get("schema_version") != 1 or admission.get("type") != "image-rollout-tools-admission-v1" or admission.get("command") != "extract" or admission.get("status") != "extracted" or admission.get("tooling_identity") != identity:
    raise SystemExit("rollout tools admission has an invalid closed schema")
if admission.get("members") != admitted_members:
    raise SystemExit("rollout tools admission does not bind the live members")
manifest_descriptor = {"basename": manifest_path.name, "sha256": hashlib.sha256(manifest_raw).hexdigest(), "size": len(manifest_raw)}
if admission.get("manifest") != manifest_descriptor:
    raise SystemExit("rollout tools admission does not bind its manifest")
archive = admission.get("archive")
verifier = admission.get("external_verifier")
if not isinstance(archive, dict) or not isinstance(verifier, dict) or archive.get("basename") != "image-rollout-tools.tar" or verifier.get("basename") != "build-image-rollout-tools.py" or archive.get("sha256") != expected_archive or verifier.get("sha256") != expected_verifier or admission.get("self_sha256") != expected_verifier:
    raise SystemExit("rollout tools admission differs from the external trust anchors")

bundle_verifier, _ = regular(bundle_verifier_s, "trusted bundle verifier", {0o555})
chain(bundle_verifier.parent, "trusted bundle verifier")
if digest(bundle_verifier) != bundle_verifier_sha:
    raise SystemExit("trusted bundle verifier hash differs from its external anchor")

record_root = canonical(record_root_s, "deployment record root")
if record_root.stat().st_uid != 0 or stat.S_IMODE(record_root.stat().st_mode) != 0o700:
    raise SystemExit("deployment record root must be root-owned mode 0700")
base = canonical(base_s, "base bootstrap directory")
bundle = canonical(bundle_s, "bundle directory")
source = canonical(source_s, "trusted source root")
old_source = canonical(old_source_s, "old source root")
for path, label in ((base, "base bootstrap"), (bundle, "bundle"), (source, "trusted source"), (old_source, "old source")):
    if not path.is_dir():
        raise SystemExit(f"{label} is not a directory")
old_compose, _ = regular(old_compose_s, "old Compose snapshot", {0o400, 0o444}, maximum=32 * 1024 * 1024)
if old_compose != base / "compose-config.json":
    raise SystemExit("old Compose snapshot is not the fixed bootstrap sibling")
regular(ready_s, "READY record", {0o400, 0o444}, maximum=4 * 1024 * 1024)
regular(migration_s, "migration state", {0o600}, maximum=4 * 1024 * 1024)
regular(operator_s, "operator instruction", {0o600}, maximum=4 * 1024 * 1024)
regular(origin_s, "public origin input", {0o600}, maximum=4096)
for executable, label in ((docker_s, "Docker"), (ufw_s, "UFW"), (ss_s, "ss")):
    path = canonical(executable, label)
    meta = os.stat(path, follow_symlinks=False)
    if not stat.S_ISREG(meta.st_mode) or meta.st_uid != 0 or meta.st_mode & 0o022 or not meta.st_mode & 0o100:
        raise SystemExit(f"{label} executable is not trusted")
nginx = canonical(nginx_s, "Nginx root")
if not nginx.is_dir():
    raise SystemExit("Nginx root is not a directory")
PY

  python "$admission_helper" record --help >/dev/null
  python "$admission_helper" validate-record --help >/dev/null
  python "$admission_helper" project-verifier --help >/dev/null
  python "$admission_helper" project-image --help >/dev/null
  "$docker_bin" compose version >/dev/null 2>&1 || fail "Docker Compose v2 is required"
}

verify_fixed_artifact() {
  python - "$bundle_dir" "$ready_record" <<PY
import hashlib
import json
import pathlib
import stat
import sys

bundle = pathlib.Path(sys.argv[1])
ready = pathlib.Path(sys.argv[2])
expected = {
    "artifact-manifest.json": "$TARGET_MANIFEST_SHA256",
    "transport-SHA256SUMS": "$TARGET_TRANSPORT_LIST_SHA256",
    "control-api-linux-amd64.tar": "$TARGET_API_ARCHIVE_SHA256",
    "pwa-linux-amd64.tar": "$TARGET_PWA_ARCHIVE_SHA256",
    "postgres-tools-linux-amd64.tar": "$TARGET_TOOLS_ARCHIVE_SHA256",
}
if bundle.name != "$TARGET_BUNDLE_ID" or ready.name != "production-bootstrap-$TARGET_BUNDLE_ID.READY.json":
    raise SystemExit("bundle or READY basename differs from the frozen target")
for name, wanted in expected.items():
    path = bundle / name
    meta = os.stat(path, follow_symlinks=False)
    if not stat.S_ISREG(meta.st_mode) or meta.st_uid != 0 or meta.st_nlink != 1:
        raise SystemExit(f"unsafe bundle member: {name}")
    digest_value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest_value.update(block)
    observed = digest_value.hexdigest()
    if observed != wanted:
        raise SystemExit(f"frozen bundle member changed: {name}")
ready_raw = ready.read_bytes()
if hashlib.sha256(ready_raw).hexdigest() != "$TARGET_READY_SHA256":
    raise SystemExit("READY record changed")
value = json.loads(ready_raw)
if value.get("bundle_id") != "$TARGET_BUNDLE_ID" or value.get("release") != "$TARGET_RELEASE" or value.get("vcs_ref") != "$TARGET_VCS_REF" or value.get("artifact_manifest_sha256") != "$TARGET_MANIFEST_SHA256" or value.get("transport") != {"file": "transport/production-bootstrap-$TARGET_BUNDLE_ID.tar", "sha256": "$TARGET_TRANSPORT_SHA256"}:
    raise SystemExit("READY record semantics differ from the frozen target")
PY
}

compose_with() {
  snapshot=$1
  shift
  project_directory=$source_root/deploy/docker-compose
  if [ "$snapshot" = "$old_compose" ]; then
    project_directory=$old_source_root/deploy/docker-compose
  fi
  "$docker_bin" compose \
    -p "$project" \
    --project-directory "$project_directory" \
    --profile ops \
    --profile multi-instance \
    -f "$snapshot" \
    "$@"
}

service_container() {
  compose_with "$1" ps --status running -q "$2"
}

capture_control_projection() {
  output=$1
  snapshot=$2
  fragments=$runtime_dir/control-fragments-$event_sequence
  /usr/bin/mkdir "$fragments"
  /usr/bin/chmod 0700 "$fragments"
  for service in control-api control-api-replica codex-pwa; do
    container=$(service_container "$snapshot" "$service")
    [ -n "$container" ] || fail "$service has no running container"
    "$docker_bin" container inspect "$container" \
      | python "$admission_helper" project-container --service "$service" \
        > "$fragments/$service.json"
    /usr/bin/chmod 0600 "$fragments/$service.json"
  done
  python - "$output" \
    "$fragments/control-api.json" \
    "$fragments/control-api-replica.json" \
    "$fragments/codex-pwa.json" <<'PY'
import json
import os
import pathlib
import sys

containers = {}
for source in sys.argv[2:]:
    value = json.loads(pathlib.Path(source).read_text(encoding="ascii"))
    if set(value) != {"projection", "schema_version", "service"} or value.get("schema_version") != 1:
        raise SystemExit("invalid container projection fragment")
    service = value["service"]
    if service in containers:
        raise SystemExit("duplicate container projection")
    containers[service] = value["projection"]
if set(containers) != {"control-api", "control-api-replica", "codex-pwa"}:
    raise SystemExit("container projection has an invalid service set")
target = pathlib.Path(sys.argv[1])
raw = (json.dumps({"containers": containers, "schema_version": 1}, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0), 0o600)
try:
    offset = 0
    while offset < len(raw):
        try: written = os.write(fd, raw[offset:])
        except InterruptedError: continue
        if written <= 0: raise SystemExit("projection write did not make progress")
        offset += written
    os.fsync(fd)
finally:
    os.close(fd)
PY
  /usr/bin/rm -rf "$fragments"
  fsync_directory "$(/usr/bin/dirname "$output")"
}

capture_invariants() {
  output=$1
  "$docker_bin" container inspect "$sub2api_container" "$postgres_container" "$redis_container" \
    | python -c '
import hashlib, json, os, pathlib, stat, subprocess, sys
def canonical(value): return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
def digest(raw): return hashlib.sha256(raw).hexdigest()
def tree_digest(root):
    root = pathlib.Path(root); entries = []
    for path in sorted(root.rglob("*"), key=lambda item: os.fsencode(str(item.relative_to(root)))):
        meta = path.lstat(); relative = path.relative_to(root).as_posix()
        if stat.S_ISREG(meta.st_mode): kind, content = "file", path.read_bytes()
        elif stat.S_ISDIR(meta.st_mode): kind, content = "directory", b""
        elif stat.S_ISLNK(meta.st_mode): kind, content = "symlink", os.readlink(path).encode("utf-8")
        else: raise SystemExit("unsupported Nginx tree entry")
        entries.append({"content_sha256": digest(content), "gid": meta.st_gid, "kind": kind, "mode": stat.S_IMODE(meta.st_mode), "path": relative, "uid": meta.st_uid})
    return digest(canonical(entries))
values = json.load(sys.stdin)
if not isinstance(values, list) or len(values) != 3: raise SystemExit("protected inspect set is invalid")
projection = {}
for name, value in zip(("sub2api", "postgres", "redis"), values):
    state = value.get("State") or {}; health = state.get("Health") or {}; settings = value.get("NetworkSettings") or {}; networks = settings.get("Networks") or {}; ports = []
    for target, bindings in sorted((settings.get("Ports") or {}).items()):
        if bindings in (None, []): ports.append(f"{target}=unpublished")
        else:
            for binding in bindings:
                host_ip = binding.get("HostIp", "")
                host_port = binding.get("HostPort", "")
                ports.append(f"{target}={host_ip}:{host_port}")
    projection[name] = {"container_id": value.get("Id"), "health": health.get("Status"), "image_id": value.get("Image"), "networks": sorted(networks), "ports": sorted(set(ports)), "running": state.get("Running")}
env = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"}
ufw = subprocess.run([sys.argv[2], "status", "verbose"], check=True, capture_output=True, text=True, env=env).stdout
listeners = subprocess.run([sys.argv[3], "-Hlnptu"], check=True, capture_output=True, text=True, env=env).stdout
normalized = sorted(set(" ".join(line.split()[:5]) for line in listeners.splitlines() if len(line.split()) >= 5))
result = {"containers": projection, "format_version": 1, "listeners": normalized, "nginx_sha256": tree_digest(sys.argv[4]), "ufw_sha256": digest(("\n".join(line.rstrip() for line in ufw.splitlines()) + "\n").encode())}
target = pathlib.Path(sys.argv[1]); raw = canonical(result) + b"\n"
fd = os.open(target, os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,"O_CLOEXEC",0)|getattr(os,"O_NOFOLLOW",0), 0o600)
try:
    offset = 0
    while offset < len(raw):
        try: written = os.write(fd, raw[offset:])
        except InterruptedError: continue
        if written <= 0: raise SystemExit("invariant write did not make progress")
        offset += written
    os.fsync(fd)
finally: os.close(fd)
' "$output" "$ufw_bin" "$ss_bin" "$nginx_root"
  fsync_directory "$(/usr/bin/dirname "$output")"
}

capture_readiness() {
  projection=$1
  compose=$2
  service=$3
  output=$4
  python - "$projection" "$compose" "$service" "$output" <<'PY'
import http.client
import json
import os
import pathlib
import re
import sys

projection = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="ascii"))
compose = json.loads(pathlib.Path(sys.argv[2]).read_text(encoding="ascii"))
service = sys.argv[3]
item = projection["containers"][service]
expected_image = compose["services"][service]["image"]
if item.get("image_id") != expected_image or item.get("running") is not True or item.get("status") != "running" or item.get("health") != "healthy" or item.get("restart_count") != 0:
    raise SystemExit("target container is not ready on the expected image")
ports = item.get("ports")
if not isinstance(ports, list) or len(ports) != 1:
    raise SystemExit("target has an invalid port projection")
match = re.fullmatch(r"[1-9][0-9]{0,4}/tcp=127\.0\.0\.1:([1-9][0-9]{0,4})", ports[0])
if match is None:
    raise SystemExit("target is not bound to one loopback TCP port")
port = int(match.group(1))
path = "/healthz" if service == "codex-pwa" else "/v1/health/ready"
connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
try:
    connection.request("GET", path, headers={"Accept": "application/json", "Connection": "close"})
    response = connection.getresponse(); body = response.read(262145)
finally:
    connection.close()
if response.status != 200 or len(body) > 262144:
    raise SystemExit("direct readiness request failed")
if service == "codex-pwa":
    if body != b"ok\n": raise SystemExit("PWA readiness body is invalid")
else:
    value = json.loads(body)
    checks = value.get("checks") if isinstance(value, dict) else None
    if value.get("status") != "ready" or not isinstance(checks, dict) or set(checks) != {"database", "database_migrations", "redis", "sub2api_contract"} or set(checks.values()) != {"ok"}:
        raise SystemExit("API readiness body is invalid")
result = {"container_id": item["container_id"], "health": "healthy", "image_id": item["image_id"], "networks": item["networks"], "ports": item["ports"], "restart_count": 0, "schema_version": 1, "service": service, "status": "ready"}
target = pathlib.Path(sys.argv[4]); raw = (json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
fd = os.open(target, os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,"O_CLOEXEC",0)|getattr(os,"O_NOFOLLOW",0), 0o600)
try:
    offset = 0
    while offset < len(raw):
        try: written = os.write(fd, raw[offset:])
        except InterruptedError: continue
        if written <= 0: raise SystemExit("readiness write did not make progress")
        offset += written
    os.fsync(fd)
finally: os.close(fd)
PY
  fsync_directory "$(/usr/bin/dirname "$output")"
}

create_new_compose() {
  python - "$old_compose" "$bundle_dir/artifact-manifest.json" "$rollout_dir/new-compose.json" <<'PY'
import copy
import json
import os
import pathlib
import sys

old = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="ascii"))
manifest = json.loads(pathlib.Path(sys.argv[2]).read_text(encoding="ascii"))
images = manifest["images"]
ids = {"api": images["control-api"]["daemon_image_id"], "pwa": images["pwa"]["daemon_image_id"], "tools": images["postgres-tools"]["daemon_image_id"]}
new = copy.deepcopy(old); services = new.get("services")
if not isinstance(services, dict): raise SystemExit("old Compose services are invalid")
release = manifest["release"]; revision = manifest["vcs_ref"]
for service in ("control-migrate", "control-api", "control-api-replica"):
    value = services[service]; value["image"] = ids["api"]
    if not isinstance(value.get("environment"), dict) or not isinstance(value.get("labels"), dict): raise SystemExit("API Compose identity fields are invalid")
    value["environment"]["CONTROL_BUILD_VERSION"] = release; value["environment"]["CONTROL_BUILD_VCS_REF"] = revision
    value["labels"]["org.opencontainers.image.version"] = release; value["labels"]["org.opencontainers.image.revision"] = revision
for service, key in (("codex-pwa", "pwa"), ("control-backup", "tools")):
    value = services[service]; value["image"] = ids[key]
    if not isinstance(value.get("labels"), dict): raise SystemExit("Compose labels are invalid")
    value["labels"]["org.opencontainers.image.version"] = release; value["labels"]["org.opencontainers.image.revision"] = revision
target = pathlib.Path(sys.argv[3]); raw = (json.dumps(new, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
fd = os.open(target, os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,"O_CLOEXEC",0)|getattr(os,"O_NOFOLLOW",0), 0o400)
try:
    offset = 0
    while offset < len(raw):
        try: written = os.write(fd, raw[offset:])
        except InterruptedError: continue
        if written <= 0: raise SystemExit("Compose snapshot write did not make progress")
        offset += written
    os.fsync(fd)
finally: os.close(fd)
PY
  fsync_directory "$rollout_dir"
}

capture_verifier_projections() {
  archive_raw=$runtime_dir/archive-verifier.raw
  archive_projection=$runtime_dir/archive-verifier.json
  source_raw=$runtime_dir/source-verifier.raw
  source_projection=$runtime_dir/source-verifier.json
  bundle_projection=$runtime_dir/bundle-verifier.json
  python "$trusted_verifier" verify-archive --bundle "$bundle_dir" --bundle-trust-anchor / > "$archive_raw"
  /usr/bin/chmod 0600 "$archive_raw"
  python "$admission_helper" project-verifier --kind archive --bundle-dir "$bundle_dir" \
    --release "$TARGET_RELEASE" --vcs-ref "$TARGET_VCS_REF" \
    < "$archive_raw" > "$archive_projection"
  /usr/bin/chmod 0600 "$archive_projection"
  publish_canonical_json "$archive_projection" "$rollout_dir/archive-verifier.json" 0600
  /usr/bin/rm -f "$archive_raw" "$archive_projection"

  python "$trusted_verifier" verify --bundle "$bundle_dir" --bundle-trust-anchor / \
    --source-root "$source_root" > "$source_raw"
  /usr/bin/chmod 0600 "$source_raw"
  python "$admission_helper" project-verifier --kind source --bundle-dir "$bundle_dir" \
    --release "$TARGET_RELEASE" --vcs-ref "$TARGET_VCS_REF" \
    < "$source_raw" > "$source_projection"
  python "$admission_helper" project-verifier --kind bundle --bundle-dir "$bundle_dir" \
    --release "$TARGET_RELEASE" --vcs-ref "$TARGET_VCS_REF" \
    < "$source_raw" > "$bundle_projection"
  /usr/bin/chmod 0600 "$source_projection" "$bundle_projection"
  publish_canonical_json "$source_projection" "$rollout_dir/source-verifier.json" 0600
  publish_canonical_json "$bundle_projection" "$rollout_dir/bundle-verifier.json" 0600
  /usr/bin/rm -f "$source_raw" "$source_projection" "$bundle_projection"
  fsync_directory "$rollout_dir"
}

create_plan_and_baseline() {
  create_new_compose
  plan_transient=$runtime_dir/plan.json
  baseline_transient=$runtime_dir/baseline.json
  python "$admission_helper" plan \
    --old-compose "$old_compose" \
    --new-compose "$rollout_dir/new-compose.json" \
    --artifact-manifest "$bundle_dir/artifact-manifest.json" \
    > "$plan_transient"
  /usr/bin/chmod 0600 "$plan_transient"
  publish_canonical_json "$plan_transient" "$rollout_dir/plan.json" 0600
  /usr/bin/rm -f "$plan_transient"
  python "$admission_helper" baseline \
    --plan "$rollout_dir/plan.json" \
    --old-plan "$base_bootstrap_dir/plan.json" \
    --old-images "$base_bootstrap_dir/images.json" \
    --old-running "$base_bootstrap_dir/running-containers.json" \
    --old-compose "$old_compose" \
    --current-before-inspect "$rollout_dir/current-before.json" \
    --bootstrap-record "$base_bootstrap_dir/bootstrap-deployment.json" \
    --closure-record "$base_bootstrap_dir/authenticated-smoke-closure.json" \
    --artifact-manifest "$bundle_dir/artifact-manifest.json" \
    --ready-record "$ready_record" \
    --bundle-dir "$bundle_dir" \
    --source-evidence "$rollout_dir/source-verifier.json" \
    --bundle-evidence "$rollout_dir/bundle-verifier.json" \
    --archive-evidence "$rollout_dir/archive-verifier.json" \
    --old-source-root "$old_source_root" \
    --new-source-root "$source_root" \
    --migration-state "$migration_state" \
    --operator-exception "$operator_exception" \
    --tools-manifest "$tools_manifest" \
    --tools-admission "$tools_admission" \
    > "$baseline_transient"
  /usr/bin/chmod 0600 "$baseline_transient"
  publish_canonical_json "$baseline_transient" "$rollout_dir/baseline.json" 0600
  /usr/bin/rm -f "$baseline_transient"
  fsync_directory "$rollout_dir"
}

load_images() {
  stage=load-images
  for item in \
    "control-api|control-api-linux-amd64.tar|$TARGET_API_ARCHIVE_SHA256" \
    "pwa|pwa-linux-amd64.tar|$TARGET_PWA_ARCHIVE_SHA256" \
    "postgres-tools|postgres-tools-linux-amd64.tar|$TARGET_TOOLS_ARCHIVE_SHA256"; do
    component=${item%%|*}; rest=${item#*|}; archive=${rest%%|*}; wanted=${rest#*|}
    observed=$(python - "$bundle_dir/$archive" <<'PY'
import hashlib, pathlib, sys
value=hashlib.sha256()
with pathlib.Path(sys.argv[1]).open("rb") as stream:
    for chunk in iter(lambda: stream.read(1024*1024), b""): value.update(chunk)
print(value.hexdigest())
PY
)
    [ "$observed" = "$wanted" ] || fail "$archive changed immediately before load"
    started=$(now) || return
    journal_event load intent "$component" pending "$started" '' false '' '' '' '' || return
    loads_attempted=1
    if ! "$docker_bin" load --input "$bundle_dir/$archive" >/dev/null; then
      completed_at=$(now) || return
      journal_event load result "$component" failed "$started" "$completed_at" false '' '' '' '' || return
      return 1
    fi
    reference=$(python - "$bundle_dir/artifact-manifest.json" "$component" <<'PY'
import json, pathlib, sys
print(json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="ascii"))["images"][sys.argv[2]]["tag"])
PY
    ) || return
    transient_projection=$runtime_dir/image-$component-$event_sequence.json
    if ! "$docker_bin" image inspect "$reference" \
      | python "$admission_helper" project-image \
        > "$transient_projection"; then
      /usr/bin/rm -f "$transient_projection" || return
      completed_at=$(now) || return
      journal_event load result "$component" failed "$started" "$completed_at" false '' '' '' '' || return
      return 1
    fi
    /usr/bin/chmod 0600 "$transient_projection" || return
    projection=$rollout_dir/image-$component.json
    publish_canonical_json "$transient_projection" "$projection" 0600 || return
    /usr/bin/rm -f "$transient_projection" || return
    completed_at=$(now) || return
    journal_event load result "$component" succeeded "$started" "$completed_at" false \
      "$projection" '' '' '' || return
  done
  python - "$bundle_dir/artifact-manifest.json" \
    "$rollout_dir/image-control-api.json" "$rollout_dir/image-pwa.json" \
    "$rollout_dir/image-postgres-tools.json" <<'PY'
import json, pathlib, sys
manifest=json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="ascii"))
for component, path in zip(("control-api","pwa","postgres-tools"), sys.argv[2:]):
    value=json.loads(pathlib.Path(path).read_text(encoding="ascii")); expected=manifest["images"][component]
    if value != {"image_id":expected["daemon_image_id"],"release":manifest["release"],"schema_version":1,"vcs_ref":manifest["vcs_ref"]}: raise SystemExit("loaded image differs from the admitted artifact")
PY
  archives_loaded=1
  fsync_directory "$rollout_dir" || return
}

switch_service() {
  service=$1
  order=$2
  before=$3
  protected_before=$rollout_dir/stage-$order-protected-before.json
  after=$rollout_dir/stage-$order-after.json
  protected_after=$rollout_dir/stage-$order-protected-after.json
  readiness=$rollout_dir/stage-$order-readiness.json
  admission=$rollout_dir/stage-$order-admission.json
  admission_transient=$runtime_dir/stage-$order-admission.json
  started=$(now)
  stage=switch-$service
  capture_invariants "$protected_before" || return
  journal_event forward intent "$service" pending "$started" '' true '' '' '' '' || return
  if ! compose_with "$rollout_dir/new-compose.json" up -d \
    --no-deps --force-recreate --no-build --pull never --wait \
    --wait-timeout "$wait_timeout" "$service"; then
    completed_at=$(now) || return
    journal_event forward result "$service" failed "$started" "$completed_at" true '' '' '' '' || return
    return 1
  fi
  if ! (capture_control_projection "$after" "$rollout_dir/new-compose.json") \
    || ! (capture_readiness "$after" "$rollout_dir/new-compose.json" "$service" "$readiness") \
    || ! (capture_invariants "$protected_after") \
    || ! python "$admission_helper" stage \
      --plan "$rollout_dir/plan.json" \
      --baseline "$rollout_dir/baseline.json" \
      --before "$before" \
      --after "$after" \
      --target "$service" \
      --readiness "$readiness" \
      --protected-before "$protected_before" \
      --protected-after "$protected_after" > "$admission_transient"; then
    /usr/bin/rm -f "$admission_transient"
    completed_at=$(now) || return
    journal_event forward result "$service" failed "$started" "$completed_at" true \
      "$([ -f "$after" ] && echo "$after")" \
      "$([ -f "$readiness" ] && echo "$readiness")" '' '' || return
    return 1
  fi
  /usr/bin/chmod 0600 "$admission_transient" || return
  publish_canonical_json "$admission_transient" "$admission" 0600 || return
  /usr/bin/rm -f "$admission_transient" || return
  fsync_directory "$rollout_dir" || return
  completed_at=$(now) || return
  journal_event forward result "$service" succeeded "$started" "$completed_at" true \
    "$after" "$readiness" "$admission" '' || return
  return 0
}

journal_has_forward_intent() {
  python - "$journal_dir" "$1" <<'PY'
import json, pathlib, sys
for path in pathlib.Path(sys.argv[1]).glob("*.json"):
    value=json.loads(path.read_text(encoding="ascii"))
    if value.get("direction")=="forward" and value.get("phase")=="intent" and value.get("service")==sys.argv[2]: raise SystemExit(0)
raise SystemExit(1)
PY
}

journal_has_successful_rollback() {
  python - "$journal_dir" "$1" <<'PY'
import json, pathlib, sys
for path in pathlib.Path(sys.argv[1]).glob("*.json"):
    value=json.loads(path.read_text(encoding="ascii"))
    if value.get("direction")=="rollback" and value.get("phase")=="result" and value.get("service")==sys.argv[2] and value.get("status")=="succeeded": raise SystemExit(0)
raise SystemExit(1)
PY
}

restore_service() {
  service=$1
  order=$2
  started=$(now) || return 2
  stage=rollback-$service
  attempt=$((event_sequence + 1))
  journal_event rollback intent "$service" pending "$started" '' true '' '' '' "$attempt" || return 2
  projection=$rollout_dir/rollback-$order-projection-$event_sequence.json
  readiness=$rollout_dir/rollback-$order-readiness-$event_sequence.json
  status_value=succeeded
  if ! compose_with "$old_compose" up -d \
    --no-deps --force-recreate --no-build --pull never --wait \
    --wait-timeout "$wait_timeout" "$service"; then
    status_value=failed
  elif ! (capture_control_projection "$projection" "$old_compose") \
    || ! (capture_readiness "$projection" "$old_compose" "$service" "$readiness"); then
    status_value=failed
  fi
  projection_value=
  readiness_value=
  [ -f "$projection" ] && projection_value=$projection
  [ -f "$readiness" ] && readiness_value=$readiness
  completed_at=$(now) || return 2
  journal_event rollback result "$service" "$status_value" "$started" "$completed_at" true \
    "$projection_value" "$readiness_value" '' "$attempt" || return 2
  if [ "$status_value" = succeeded ]; then
    return 0
  fi
  return 1
}

rollback_engine() {
  rollback_ok=1
  rollback_count=0
  for service in codex-pwa control-api control-api-replica; do
    if journal_has_forward_intent "$service"; then
      rollback_count=$((rollback_count + 1))
      if ! journal_has_successful_rollback "$service"; then
        restore_status=0
        restore_service "$service" "$rollback_count" || restore_status=$?
        case $restore_status in
          0) ;;
          1) rollback_ok=0 ;;
          *) return 2 ;;
        esac
      fi
    fi
  done
  invariants_restored=0
  if [ -f "$rollout_dir/invariants-before.json" ]; then
    after=$rollout_dir/invariants-restored-after-$event_sequence.json
    admission=$rollout_dir/invariants-restored-$event_sequence.json
    admission_transient=$runtime_dir/invariants-restored-$event_sequence.json
    if (capture_invariants "$after") \
      && python "$admission_helper" invariants \
        --plan "$rollout_dir/plan.json" \
        --baseline "$rollout_dir/baseline.json" \
        --before "$rollout_dir/invariants-before.json" --after "$after" \
        > "$admission_transient" \
      && /usr/bin/chmod 0600 "$admission_transient" \
      && publish_canonical_json "$admission_transient" "$admission" 0600 \
      && /usr/bin/rm -f "$admission_transient"; then
      fsync_directory "$rollout_dir"
      invariants_restored=1
      restored_invariants_file=$admission
    else
      /usr/bin/rm -f "$admission_transient"
      rollback_ok=0
      restored_invariants_file=
    fi
  else
    rollback_ok=0
    restored_invariants_file=
  fi
  create_rollback_summary "$rollback_ok" "$invariants_restored"
  [ "$rollback_ok" = 1 ] && [ "$invariants_restored" = 1 ]
}

create_rollback_summary() {
  ok=$1
  restored=$2
  ROLLBACK_OK=$ok INVARIANTS_RESTORED=$restored python - \
    "$journal_dir" "$rollout_dir/rollback-summary.json" "$stage" <<'PY'
import json, os, pathlib, sys
journal=pathlib.Path(sys.argv[1]); events=[]
for path in sorted(journal.glob("*.json")):
    value=json.loads(path.read_text(encoding="ascii"))
    if value.get("direction")=="rollback" and value.get("phase")=="result":
        events.append({"service":value["service"],"status":value["status"]})
result={"invariants_restored":os.environ["INVARIANTS_RESTORED"]=="1","schema_version":1,"status":"succeeded" if os.environ["ROLLBACK_OK"]=="1" else "failed","steps":events,"trigger_stage":sys.argv[3]}
target=pathlib.Path(sys.argv[2]); raw=(json.dumps(result,sort_keys=True,separators=(",",":"))+"\n").encode("ascii")
fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,"O_CLOEXEC",0)|getattr(os,"O_NOFOLLOW",0),0o600)
try: os.write(fd,raw);os.fsync(fd)
finally: os.close(fd)
PY
  fsync_directory "$rollout_dir"
}

create_challenge() {
  python - "$rollout_dir/smoke-challenge.json" "$rollout_id" \
    "$rollout_dir/plan.json" "$rollout_dir/baseline.json" \
    "$rollout_dir/running.json" "$rollout_dir/invariants.json" <<'PY'
import hashlib,json,os,pathlib,secrets,sys
from datetime import datetime,timezone
def digest(path): return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()
without={"baseline_sha256":digest(sys.argv[4]),"invariants_sha256":digest(sys.argv[6]),"plan_sha256":digest(sys.argv[3]),"running_sha256":digest(sys.argv[5])}
binding=hashlib.sha256((json.dumps(without,sort_keys=True,separators=(",",":"))+"\n").encode("ascii")).hexdigest()
value={"issued_at":datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00","Z"),"nonce":secrets.token_hex(32),"rollout_id":sys.argv[2],"schema_version":1,"target":{**without,"binding_sha256":binding}}
target=pathlib.Path(sys.argv[1]);raw=(json.dumps(value,sort_keys=True,separators=(",",":"))+"\n").encode("ascii")
fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,"O_CLOEXEC",0)|getattr(os,"O_NOFOLLOW",0),0o600)
try:os.write(fd,raw);os.fsync(fd)
finally:os.close(fd)
PY
  fsync_directory "$rollout_dir"
}

run_smoke() {
  stage=production-smoke
  smoke_stderr=$runtime_dir/smoke.stderr
  smoke_transient=$runtime_dir/smoke.json
  set +e
  python "$smoke_producer" \
    --origin-file "$public_origin_file" \
    --challenge "$rollout_dir/smoke-challenge.json" \
    --plan "$rollout_dir/plan.json" \
    --baseline "$rollout_dir/baseline.json" \
    --running "$rollout_dir/running.json" \
    --invariants "$rollout_dir/invariants.json" \
    > "$smoke_transient" 2> "$smoke_stderr"
  smoke_status=$?
  set -e
  /usr/bin/chmod 0600 "$smoke_transient" "$smoke_stderr"
  if [ "$smoke_status" -eq 0 ]; then
    [ ! -s "$smoke_stderr" ] || fail "fixed smoke producer wrote unexpected stderr"
  else
    [ "$(/bin/cat "$smoke_stderr")" = "image-rollout-smoke: failed" ] \
      || fail "fixed smoke producer failed outside its closed error contract"
  fi
  publish_canonical_json "$smoke_transient" "$rollout_dir/smoke.json" 0600
  /usr/bin/rm -f "$smoke_transient"
  /usr/bin/rm -f "$smoke_stderr"
  fsync_directory "$rollout_dir"
  return "$smoke_status"
}

create_context() {
  context_status=$1
  failure_stage=$2
  invariants_path=${3:-}
  CONTEXT_STATUS=$context_status FAILURE_STAGE=$failure_stage ARCHIVES_LOADED=$archives_loaded \
  LOADS_ATTEMPTED=$loads_attempted \
  python - "$rollout_dir/context.json" "$journal_dir" "$rollout_id" "$created_at" \
    "$rollout_dir/rollback-summary.json" "$invariants_path" \
    "$base_bootstrap_dir/bootstrap-deployment.json" \
    "$base_bootstrap_dir/authenticated-smoke-closure.json" \
    "$bundle_dir/artifact-manifest.json" "$ready_record" "$bundle_dir" \
    "$rollout_dir/archive-verifier.json" "$rollout_dir/bundle-verifier.json" \
    "$rollout_dir/source-verifier.json" "$rollout_dir/current-before.json" \
    "$rollout_dir/new-compose.json" "$old_compose" "$operator_exception" \
    "$source_root" "$rollout_dir/smoke-challenge.json" "$tools_manifest" \
    "$tools_admission" <<'PY'
import json,os,pathlib,sys
from datetime import datetime,timezone
target=pathlib.Path(sys.argv[1]); journal=pathlib.Path(sys.argv[2]); rollout_id=sys.argv[3]; created=sys.argv[4]
rollback_summary=pathlib.Path(sys.argv[5]); invariants_path=sys.argv[6]
events=[]
for path in sorted(journal.glob("*.json")):
    events.append(json.loads(path.read_text(encoding="ascii")))
services=("control-api-replica","control-api","codex-pwa")
steps=[]
for order,service in enumerate(services,1):
    intents=[v for v in events if v.get("direction")=="forward" and v.get("phase")=="intent" and v.get("service")==service]
    results=[v for v in events if v.get("direction")=="forward" and v.get("phase")=="result" and v.get("service")==service]
    if results:
        value=results[-1]; status=value["status"]
        steps.append({"after_inspect":value.get("after_projection"),"completed_at":value.get("completed_at"),"order":order,"readiness_evidence":value.get("readiness"),"recreated":True,"service":service,"started_at":value.get("started_at"),"status":status})
    elif intents:
        steps.append({"after_inspect":None,"completed_at":datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00","Z"),"order":order,"readiness_evidence":None,"recreated":True,"service":service,"started_at":intents[-1]["started_at"],"status":"failed"})
    else:
        steps.append({"after_inspect":None,"completed_at":None,"order":order,"readiness_evidence":None,"recreated":False,"service":service,"started_at":None,"status":"not-run"})
rollback=None
if os.environ["CONTEXT_STATUS"]=="failed":
    summary=json.loads(rollback_summary.read_text(encoding="ascii")); rb_results=[]
    for service in reversed(services):
        values=[v for v in events if v.get("direction")=="rollback" and v.get("phase")=="result" and v.get("service")==service]
        if values:
            value=values[-1]
            rb_results.append({"completed_at":value["completed_at"],"evidence":value.get("readiness"),"inspect":value.get("after_projection"),"order":len(rb_results)+1,"service":service,"started_at":value["started_at"],"status":value["status"]})
    rb_intents=[v for v in events if v.get("direction")=="rollback" and v.get("phase")=="intent"]
    started=min((v["started_at"] for v in rb_intents),default=datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00","Z"))
    rollback={"completed_at":datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00","Z"),"evidence":str(rollback_summary),"invariants_restored":summary["invariants_restored"],"started_at":started,"status":summary["status"],"steps":rb_results,"trigger_stage":os.environ["FAILURE_STAGE"]}
path_values=sys.argv[7:]
keys=("bootstrap_record","closure_record","artifact_manifest","ready_record","bundle_dir","archive_evidence","bundle_evidence","source_evidence","current_before_inspect","new_compose","old_compose","operator_exception","source_root","smoke_challenge","tools_manifest","tools_admission")
if len(keys) != len(path_values): raise SystemExit("context path argument count is invalid")
paths=dict(zip(keys,path_values))
for key,value in list(paths.items()):
    if not pathlib.Path(value).exists(): paths[key]=None
if os.environ["CONTEXT_STATUS"]=="failed" and not pathlib.Path(paths.get("smoke_challenge") or "").exists(): paths["smoke_challenge"]=None
operations={"archives_loaded":os.environ["ARCHIVES_LOADED"]=="1","backup_invoked":False,"build_invoked":False,"down_invoked":False,"load_invoked":os.environ["LOADS_ATTEMPTED"]=="1","migrate_invoked":False,"postgres_tools_executed":False,"pull_invoked":False,"python_dont_write_bytecode":True}
value={"completed_at":datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00","Z"),"created_at":created,"failure_stage":None if os.environ["CONTEXT_STATUS"]=="succeeded" else os.environ["FAILURE_STAGE"],"operations":operations,"paths":paths,"rollback":rollback,"rollout_id":rollout_id,"schema_version":1,"status":os.environ["CONTEXT_STATUS"],"steps":steps,"type":"bootstrap-image-rollout-context-v1"}
raw=(json.dumps(value,sort_keys=True,separators=(",",":"))+"\n").encode("ascii")
fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,"O_CLOEXEC",0)|getattr(os,"O_NOFOLLOW",0),0o600)
try:os.write(fd,raw);os.fsync(fd)
finally:os.close(fd)
PY
  fsync_directory "$rollout_dir"
}

optional_record_args() {
  [ -f "$rollout_dir/plan.json" ] && printf '%s\n' --plan "$rollout_dir/plan.json"
  [ -f "$rollout_dir/baseline.json" ] && printf '%s\n' --baseline "$rollout_dir/baseline.json"
  [ -f "$rollout_dir/running.json" ] && printf '%s\n' --running "$rollout_dir/running.json"
  [ -n "${record_invariants_file:-}" ] && [ -f "$record_invariants_file" ] && printf '%s\n' --invariants "$record_invariants_file"
  [ -f "$rollout_dir/smoke.json" ] && printf '%s\n' --smoke "$rollout_dir/smoke.json"
}

publish_terminal_record() {
  validation_transient=$runtime_dir/record-validation.json
  set --
  if [ -f "$rollout_dir/plan.json" ]; then set -- "$@" --plan "$rollout_dir/plan.json"; fi
  if [ -f "$rollout_dir/baseline.json" ]; then set -- "$@" --baseline "$rollout_dir/baseline.json"; fi
  if [ -f "$rollout_dir/running.json" ]; then set -- "$@" --running "$rollout_dir/running.json"; fi
  if [ -n "${record_invariants_file:-}" ] && [ -f "$record_invariants_file" ]; then set -- "$@" --invariants "$record_invariants_file"; fi
  if [ -f "$rollout_dir/smoke.json" ]; then set -- "$@" --smoke "$rollout_dir/smoke.json"; fi
  python "$admission_helper" record \
    --context "$rollout_dir/context.json" \
    "$@" \
    --schema "$record_schema" \
    --output "$rollout_dir/image-rollout-record.json" >/dev/null
  python "$admission_helper" validate-record \
    --record "$rollout_dir/image-rollout-record.json" \
    --schema "$record_schema" > "$validation_transient"
  /usr/bin/chmod 0600 "$validation_transient"
  publish_canonical_json "$validation_transient" "$rollout_dir/record-validation.json" 0600
  /usr/bin/rm -f "$validation_transient"
  python - "$rollout_dir/image-rollout-record.json" "$rollout_dir/terminal-sha256.json" <<'PY'
import hashlib,json,os,pathlib,sys
record=pathlib.Path(sys.argv[1]);raw=record.read_bytes()
value={"record_basename":record.name,"record_sha256":hashlib.sha256(raw).hexdigest(),"record_size":len(raw),"schema_version":1}
target=pathlib.Path(sys.argv[2]);payload=(json.dumps(value,sort_keys=True,separators=(",",":"))+"\n").encode("ascii")
fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,"O_CLOEXEC",0)|getattr(os,"O_NOFOLLOW",0),0o600)
try:os.write(fd,payload);os.fsync(fd)
finally:os.close(fd)
if hashlib.sha256(record.read_bytes()).hexdigest()!=value["record_sha256"]:raise SystemExit("terminal record changed after validation")
PY
  fsync_directory "$rollout_dir"
}

remove_lock() {
  [ "$lock_owned" = 1 ] || return 1
  ROLLOUT_ID=$rollout_id python - "$record_root" "$lock_file" <<'PY'
import json
import os
import pathlib
import stat
import sys

root = pathlib.Path(sys.argv[1])
lock = pathlib.Path(sys.argv[2])
if lock != root / ".image-rollout.lock":
    raise SystemExit("refusing to remove a non-fixed rollout lock")
root_fd = os.open(root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0))
try:
    fd = os.open(lock.name, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0), dir_fd=root_fd)
    try:
        meta = os.fstat(fd)
        if not stat.S_ISREG(meta.st_mode) or meta.st_uid != 0 or meta.st_gid != 0 or stat.S_IMODE(meta.st_mode) != 0o600 or meta.st_nlink != 1 or meta.st_size > 1024 * 1024:
            raise SystemExit("refusing to remove an unsafe rollout lock")
        raw = b""
        while len(raw) <= 1024 * 1024:
            try:
                block = os.read(fd, min(65536, 1024 * 1024 + 1 - len(raw)))
            except InterruptedError:
                continue
            if not block:
                break
            raw += block
    finally:
        os.close(fd)
    value = json.loads(raw.decode("ascii"))
    if value.get("rollout_id") != os.environ["ROLLOUT_ID"]:
        raise SystemExit("refusing to remove a different rollout lock")
    os.unlink(lock.name, dir_fd=root_fd)
    os.fsync(root_fd)
finally:
    os.close(root_fd)
PY
  lock_owned=0
  lock_file=
}

cleanup_runtime() {
  if [ -n "$runtime_dir" ] && [ -d "$runtime_dir" ]; then
    /usr/bin/rm -rf "$runtime_dir"
    runtime_dir=
  fi
}

finalize_failure() {
  failure_code=$1
  [ "$finalizing" = 0 ] || return
  finalizing=1
  trap - EXIT HUP INT TERM QUIT
  set +e
  if [ -z "$rollout_dir" ] || [ ! -d "$rollout_dir" ] || [ -z "$journal_dir" ]; then
    cleanup_runtime
    return
  fi
  failure_stage=$stage
  rollback_engine
  rollback_status=$?
  if [ "$rollback_status" -eq 0 ]; then
    if [ -f "$rollout_dir/smoke.json" ]; then
      record_invariants_file=$rollout_dir/invariants.json
    else
      record_invariants_file=${restored_invariants_file:-}
    fi
    /usr/bin/rm -f "$rollout_dir/context.json"
    create_context failed "$failure_stage" "$record_invariants_file"
    if publish_terminal_record; then
      remove_lock
    fi
  fi
  cleanup_runtime
  return "$failure_code"
}

on_exit() {
  code=$?
  if [ "$completed" != 1 ]; then
    finalize_failure "$code" || :
  else
    cleanup_runtime
  fi
  exit "$code"
}

recover_main() {
  [ "$#" -eq 3 ] && [ "$1" = recover ] && [ "$2" = --confirm ] \
    && [ "$3" = RECOVER-BOOTSTRAP-IMAGE-ROLLOUT ] \
    || fail "recovery requires: recover --confirm RECOVER-BOOTSTRAP-IMAGE-ROLLOUT"
  [ -e "$lock_file" ] || fail "no stale image rollout lock exists"
  runtime_dir=$(read_recovery_capsule) || fail "recovery capsule or journal validation failed"
  rollout_dir=$(load_capsule_value rollout_dir) || fail "could not load validated rollout directory"
  journal_dir=$(load_capsule_value journal_dir) || fail "could not load validated journal directory"
  rollout_id=$(load_capsule_value rollout_id) || fail "could not load validated rollout id"
  created_at=$(load_capsule_value created_at) || fail "could not load validated creation time"
  initialize_event_sequence || fail "could not load validated journal sequence"
  original_runtime_dir=$(load_capsule_value original_runtime_dir) || fail "could not load validated original runtime directory"
  loads_attempted=$(load_capsule_value load_invoked) || fail "could not load validated load invocation state"
  archives_loaded=$(load_capsule_value archives_loaded) || fail "could not load validated load completion state"
  lock_owned=1
  if [ -d "$original_runtime_dir" ]; then
    /usr/bin/rm -rf "$original_runtime_dir" || fail "could not remove the original private runtime directory"
  fi
  if [ -f "$rollout_dir/image-rollout-record.json" ]; then
    python "$admission_helper" validate-record --record "$rollout_dir/image-rollout-record.json" --schema "$record_schema" >/dev/null
    completed=1
    remove_lock
    cleanup_runtime
    return 0
  fi
  stage=recovery
  set +e
  rollback_engine
  rollback_status=$?
  set -e
  [ "$rollback_status" -eq 0 ] || fail "recovery remains incomplete; lock and journal retained"
  record_invariants_file=${restored_invariants_file:-}
  create_context failed recovery "$record_invariants_file"
  publish_terminal_record || fail "recovery terminal record validation failed; lock retained"
  completed=1
  remove_lock
  cleanup_runtime
  echo "Image rollout recovery completed: $rollout_dir/image-rollout-record.json"
}

normal_main() {
  [ "$#" -eq 0 ] || fail "normal rollout accepts no positional arguments"
  if [ -e "$lock_file" ]; then
    fail "stale or active rollout lock exists; use explicit recover mode after review"
  fi
  remove_incomplete_lock_publications || fail "could not clean an incomplete unpublished lock"
  timestamp=$(/usr/bin/date -u '+%Y%m%dT%H%M%SZ')
  rollout_id=$(python -c 'import uuid;print(uuid.uuid4())')
  created_at=$(now)
  rollout_dir=$record_root/image-rollout-$timestamp-$rollout_id
  journal_dir=$rollout_dir/journal
  runtime_dir=/run/sub2api-image-rollout-$rollout_id
  /usr/bin/mkdir "$rollout_dir" "$journal_dir" "$runtime_dir"
  /usr/bin/chmod 0700 "$rollout_dir" "$journal_dir" "$runtime_dir"
  fsync_directory "$record_root"
  fsync_directory "$rollout_dir"
  trap on_exit EXIT
  trap 'exit 129' HUP
  trap 'exit 130' INT
  trap 'exit 131' QUIT
  trap 'exit 143' TERM
  write_capsule
  lock_owned=1

  stage=verify-fixed-artifact
  verify_fixed_artifact
  capture_verifier_projections
  stage=capture-current
  capture_control_projection "$rollout_dir/current-before.json" "$old_compose"
  stage=admit-baseline
  create_plan_and_baseline
  stage=capture-invariants
  capture_invariants "$rollout_dir/invariants-before.json"
  load_images

  before=$rollout_dir/current-before.json
  switch_service control-api-replica 1 "$before"
  before=$rollout_dir/stage-1-after.json
  switch_service control-api 2 "$before"
  before=$rollout_dir/stage-2-after.json
  switch_service codex-pwa 3 "$before"

  stage=verify-running
  capture_control_projection "$rollout_dir/running-projection.json" "$rollout_dir/new-compose.json"
  running_transient=$runtime_dir/running.json
  python "$admission_helper" running --plan "$rollout_dir/plan.json" \
    --inspect "$rollout_dir/running-projection.json" > "$running_transient"
  /usr/bin/chmod 0600 "$running_transient"
  publish_canonical_json "$running_transient" "$rollout_dir/running.json" 0600
  /usr/bin/rm -f "$running_transient"
  capture_invariants "$rollout_dir/invariants-after.json"
  invariants_transient=$runtime_dir/invariants.json
  python "$admission_helper" invariants \
    --plan "$rollout_dir/plan.json" \
    --baseline "$rollout_dir/baseline.json" \
    --before "$rollout_dir/invariants-before.json" \
    --after "$rollout_dir/invariants-after.json" > "$invariants_transient"
  /usr/bin/chmod 0600 "$invariants_transient"
  publish_canonical_json "$invariants_transient" "$rollout_dir/invariants.json" 0600
  /usr/bin/rm -f "$invariants_transient"
  fsync_directory "$rollout_dir"
  create_challenge
  run_smoke

  stage=record-success
  record_invariants_file=$rollout_dir/invariants.json
  create_context succeeded '' "$record_invariants_file"
  publish_terminal_record
  completed=1
  remove_lock
  cleanup_runtime
  trap - EXIT HUP INT TERM QUIT
  echo "Image-only rollout completed: $rollout_dir/image-rollout-record.json"
}

verify_trust_boundary

case ${1:-} in
  recover) recover_main "$@" ;;
  '') normal_main "$@" ;;
  *) fail "unsupported command; use no arguments or explicit recover mode" ;;
esac
