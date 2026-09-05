#!/bin/sh
CONTROL_SERVER_PACKAGE_OFFLINE_CONTRACT=1
CONTROL_SERVER_PACKAGE_POST_SUCCESS_REVERSE_CONTRACT=1
CONTROL_SERVER_PACKAGE_BOUNDED_UNINSTALL_CONTRACT=1
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/../.." && pwd)
compose_dir="$repo_root/deploy/docker-compose"
compose_file="$compose_dir/compose.yaml"
production_overlay="$compose_dir/compose.production.yaml"
checks="$script_dir/deployment-admission.py"
runtime_verifier="$script_dir/verify-sub2api-runtime.sh"
production_state_backup="$script_dir/backup-production-state.py"
production_recovery="$script_dir/production-recovery.py"
pg_restore_validator="$script_dir/pg-restore-via-container.sh"
source_bundle_verifier="$repo_root/deploy/release/source_bundle.py"
smoke_test="$repo_root/tests/e2e/smoke.py"
backup_admission="$script_dir/bootstrap-admission.py"

env_file=${CONTROL_COMPOSE_ENV_FILE:-}
record_root=${CONTROL_DEPLOYMENT_RECORD_DIR:-}
project=${CONTROL_COMPOSE_PROJECT_NAME:-}
sub2api_container=${SUB2API_CONTAINER:-sub2api}
versions_lock=${VERSIONS_LOCK_FILE:-$repo_root/versions.lock.json}
auth_evidence=
auth_max_age=${SUB2API_AUTH_EVIDENCE_MAX_AGE_SECONDS:-900}
backup_max_age=${CONTROL_PREMIGRATION_BACKUP_MAX_AGE_SECONDS:-600}
wait_timeout=${CONTROL_DEPLOYMENT_WAIT_TIMEOUT_SECONDS:-120}
smoke_access_token_file=${CONTROL_SMOKE_ACCESS_TOKEN_FILE:-}
smoke_expected_user_id=${CONTROL_SMOKE_EXPECTED_USER_ID:-}
stage=initializing
completed=0
freeze_started=0
database_mutated=0
application_mutated=0
writer_exposure_started=0
migration_required=0
recovery_executed=0
release_deployment_lock=1
lock_dir=
deployment_dir=
source_stage=
compose_snapshot=
compose_project=
auth_probe_nonce=
auth_probe_user_id=
auth_probe_base_url=http://127.0.0.1:8080
auth_contract_file=
production_backup_root=${CONTROL_PRODUCTION_BACKUP_ROOT:-}
production_backup_max_age=${CONTROL_PRODUCTION_BACKUP_MAX_AGE_SECONDS:-1800}
recovery_receipt_max_age=${CONTROL_RECOVERY_RECEIPT_MAX_AGE_SECONDS:-1800}
recovery_restore_timeout=${CONTROL_RECOVERY_RESTORE_TIMEOUT_SECONDS:-180}
sub2api_postgres_container=${SUB2API_POSTGRES_CONTAINER:-sub2api-postgres}
sub2api_postgres_user=${SUB2API_POSTGRES_USER:-sub2api}
sub2api_postgres_database=${SUB2API_DB_NAME:-sub2api}
sub2api_postgres_password_file=${SUB2API_POSTGRES_PASSWORD_FILE:-}
sub2api_redis_container=${SUB2API_REDIS_CONTAINER:-sub2api-redis}
sub2api_redis_user=${SUB2API_REDIS_USER:-default}
sub2api_redis_password_file=${SUB2API_REDIS_PASSWORD_FILE:-}
sub2api_redis_data_path=${SUB2API_REDIS_DATA_PATH:-/data}
sub2api_data_path=${SUB2API_HOST_DATA_PATH:-}
sub2api_config_path=${SUB2API_HOST_CONFIG_PATH:-}
sub2api_compose_file=${SUB2API_HOST_COMPOSE_FILE:-}
sub2api_environment_file=${SUB2API_HOST_ENV_FILE:-}
nginx_config_path=${CONTROL_NGINX_CONFIG_PATH:-/etc/nginx}
timeout_bin=${CONTROL_TIMEOUT_BIN:-timeout}
server_package_mode=${CONTROL_SERVER_PACKAGE_MODE:-}
server_package_manifest=${CONTROL_SERVER_PACKAGE_MANIFEST_PATH:-}
server_package_manifest_sha256=${CONTROL_SERVER_PACKAGE_MANIFEST_SHA256:-}
server_package_verification_receipt=${CONTROL_SERVER_PACKAGE_VERIFICATION_RECEIPT:-}
connector_release_metadata_json=${CONTROL_CONNECTOR_RELEASE_METADATA_JSON:-}
lifecycle_post_success_reverse=0
lifecycle_reverse_deployment_dir=
lifecycle_reverse_trigger=
lifecycle_bounded_uninstall=0
lifecycle_uninstall_deployment_dir=
lifecycle_uninstall_trigger=
post_success_reverse_admitted=0
post_success_terminal_status_written=0
bounded_uninstall_admitted=0
bounded_uninstall_terminal_status_written=0

umask 077

fail() {
  echo "deploy-production: $*" >&2
  exit 1
}

case $# in
  0) ;;
  3)
    case "$1" in
      --lifecycle-bounded-reverse-after-success)
        lifecycle_post_success_reverse=1
        lifecycle_reverse_deployment_dir=$2
        lifecycle_reverse_trigger=$3
        ;;
      --lifecycle-bounded-uninstall)
        lifecycle_bounded_uninstall=1
        lifecycle_uninstall_deployment_dir=$2
        lifecycle_uninstall_trigger=$3
        ;;
      *) fail "unsupported lifecycle production interface" ;;
    esac
    ;;
  *) fail "unexpected production deployment arguments" ;;
esac

case "$server_package_mode" in
  online|offline) ;;
  *) fail "CONTROL_SERVER_PACKAGE_MODE must be lifecycle-owned online or offline" ;;
esac
for required_package_input in \
  "$server_package_manifest" \
  "$server_package_manifest_sha256" \
  "$server_package_verification_receipt" \
  "$connector_release_metadata_json"
do
  [ -n "$required_package_input" ] \
    || fail "all lifecycle-owned server package and Connector inputs are required"
done
case "$server_package_manifest" in /*) ;; *) fail "server package manifest must be absolute" ;; esac
case "$server_package_verification_receipt" in
  /*) ;;
  *) fail "server package verification receipt must be absolute" ;;
esac
case "${DOCKER_HOST:-}" in
  unix:///var/run/docker.sock) ;;
  *) fail "lifecycle must pin DOCKER_HOST to unix:///var/run/docker.sock" ;;
esac
for prohibited_docker_override in \
  "${DOCKER_CONTEXT:-}" "${DOCKER_TLS_VERIFY:-}" "${DOCKER_CERT_PATH:-}"
do
  [ -z "$prohibited_docker_override" ] \
    || fail "server package deployment rejects Docker context and TLS overrides"
done
if [ "$server_package_mode" = offline ]; then
  for prohibited_network_input in \
    "${HTTP_PROXY:-}" "${HTTPS_PROXY:-}" "${ALL_PROXY:-}" "${FTP_PROXY:-}" \
    "${http_proxy:-}" "${https_proxy:-}" "${all_proxy:-}" "${ftp_proxy:-}"
  do
    [ -z "$prohibited_network_input" ] \
      || fail "offline server package deployment rejects proxy inputs"
  done
fi

case "$backup_max_age" in
  ''|*[!0-9]*|0) fail "CONTROL_PREMIGRATION_BACKUP_MAX_AGE_SECONDS must be positive" ;;
esac
case "$production_backup_max_age" in
  ''|*[!0-9]*|0) fail "CONTROL_PRODUCTION_BACKUP_MAX_AGE_SECONDS must be positive" ;;
esac
case "$recovery_receipt_max_age" in
  ''|*[!0-9]*|0) fail "CONTROL_RECOVERY_RECEIPT_MAX_AGE_SECONDS must be positive" ;;
esac
case "$recovery_restore_timeout" in
  ''|*[!0-9]*|0) fail "CONTROL_RECOVERY_RESTORE_TIMEOUT_SECONDS must be positive" ;;
esac
case "$wait_timeout" in
  ''|*[!0-9]*|0) fail "CONTROL_DEPLOYMENT_WAIT_TIMEOUT_SECONDS must be positive" ;;
esac
[ -n "$env_file" ] || fail "set CONTROL_COMPOSE_ENV_FILE to the production Compose env file"
case "$env_file" in
  /*) ;;
  *) fail "CONTROL_COMPOSE_ENV_FILE must be absolute" ;;
esac
[ -n "$record_root" ] || fail "set CONTROL_DEPLOYMENT_RECORD_DIR to a private absolute directory"
case "$record_root" in
  /*) ;;
  *) fail "CONTROL_DEPLOYMENT_RECORD_DIR must be absolute" ;;
esac
command -v docker >/dev/null 2>&1 || fail "docker is required"
docker compose version >/dev/null 2>&1 || fail "Docker Compose v2 is required"
command -v python3 >/dev/null 2>&1 || fail "python3 is required"
python3 "$checks" operator-directory \
  --directory "$record_root" \
  --label "deployment record directory" \
  >/dev/null

lock_dir="$record_root/.deployment.lock"
mkdir "$lock_dir" 2>/dev/null \
  || fail "another deployment is active, or stale lock requires review: $lock_dir"
if [ "$lifecycle_post_success_reverse" = "1" ] \
  || [ "$lifecycle_bounded_uninstall" = "1" ]; then
  if [ "$lifecycle_post_success_reverse" = "1" ]; then
    deployment_dir=$lifecycle_reverse_deployment_dir
    lifecycle_directory_label="post-success deployment record directory"
  else
    deployment_dir=$lifecycle_uninstall_deployment_dir
    lifecycle_directory_label="bounded uninstall deployment record directory"
  fi
  python3 "$checks" operator-directory \
    --directory "$deployment_dir" \
    --label "$lifecycle_directory_label" \
    >/dev/null || {
      rmdir "$lock_dir" || :
      fail "lifecycle deployment directory is not private"
    }
  release_deployment_lock=0
else
  timestamp=$(date -u '+%Y%m%dT%H%M%SZ')
  deployment_dir="$record_root/deployment-${timestamp}-$$"
  mkdir "$deployment_dir"
  chmod 0700 "$deployment_dir"
fi

write_status() {
  status_value=$1
  status_tmp="$deployment_dir/.status.tmp.$$"
  printf '%s\n' "$status_value" > "$status_tmp"
  chmod 0600 "$status_tmp"
  mv "$status_tmp" "$deployment_dir/status"
}

cleanup() {
  status=$?
  trap - EXIT HUP INT TERM
  failure_stage=$stage
  if [ "$completed" != "1" ]; then
    if [ "$freeze_started" = "1" ] && [ "$recovery_executed" != "1" ]; then
      recovery_executed=1
      recovery_status=0
      if [ "$database_mutated" = "1" ] || [ "$application_mutated" = "1" ]; then
        recovery_kind=reverse
        run_bounded_reverse "$failure_stage" || recovery_status=$?
      else
        recovery_kind=unfreeze
        run_bounded_unfreeze "$failure_stage" || recovery_status=$?
      fi
      if [ "$recovery_status" -eq 0 ]; then
        write_status "failed:$failure_stage:$recovery_kind-succeeded" || :
      else
        release_deployment_lock=0
        write_status "failed:$failure_stage:$recovery_kind-failed:lock-retained" || :
      fi
    elif [ "$lifecycle_post_success_reverse" != "1" ] \
      && [ "$lifecycle_bounded_uninstall" != "1" ]; then
      write_status "failed:$failure_stage" || :
    elif [ "$post_success_reverse_admitted" = "1" ] \
      && [ "$post_success_terminal_status_written" != "1" ]; then
      write_status "failed:$failure_stage" || :
    elif [ "$bounded_uninstall_admitted" = "1" ] \
      && [ "$bounded_uninstall_terminal_status_written" != "1" ]; then
      release_deployment_lock=0
      write_status "failed:$failure_stage:lock-retained" || :
    fi
  fi
  if [ "$release_deployment_lock" = "1" ] \
    && [ -n "$lock_dir" ] && [ -d "$lock_dir" ]; then
    rmdir "$lock_dir" || :
  fi
  exit "$status"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
if [ "$lifecycle_post_success_reverse" != "1" ] \
  && [ "$lifecycle_bounded_uninstall" != "1" ]; then
  write_status "in-progress:$stage"
fi

compose_source() {
  if [ -n "$project" ]; then
    docker compose \
      --project-name "$project" \
      --project-directory "$compose_dir" \
      --profile ops \
      --profile multi-instance \
      --env-file "$env_file" \
      -f "$compose_file" \
      -f "$production_overlay" \
      "$@"
  else
    docker compose \
      --project-directory "$compose_dir" \
      --profile ops \
      --profile multi-instance \
      --env-file "$env_file" \
      -f "$compose_file" \
      -f "$production_overlay" \
      "$@"
  fi
}

compose() {
  [ -n "$compose_snapshot" ] || fail "resolved Compose snapshot is not pinned"
  if [ -n "$project" ]; then
    docker compose \
      --project-name "$project" \
      --project-directory "$compose_dir" \
      --profile ops \
      --profile multi-instance \
      -f "$compose_snapshot" \
      "$@"
  else
    docker compose \
      --project-directory "$compose_dir" \
      --profile ops \
      --profile multi-instance \
      -f "$compose_snapshot" \
      "$@"
  fi
}

json_field() {
  python3 -c '
import json, sys
value = json.load(open(sys.argv[1], encoding="utf-8"))
for key in sys.argv[2:]:
    value = value[key]
if not isinstance(value, str) or not value or "\n" in value or "\r" in value:
    raise SystemExit("requested JSON field is not one non-empty string")
print(value)
' "$@"
}

json_integer() {
  python3 -c '
import json, sys
value = json.load(open(sys.argv[1], encoding="utf-8"))
for key in sys.argv[2:]:
    value = value[key]
if not isinstance(value, int) or isinstance(value, bool) or value < 0:
    raise SystemExit("requested JSON field is not one non-negative integer")
print(value)
' "$@"
}

atomic_json() {
  destination=$1
  shift
  temporary="$deployment_dir/.json.tmp.$$"
  "$@" > "$temporary"
  chmod 0600 "$temporary"
  mv "$temporary" "$destination"
}

no_replace_json() {
  destination=$1
  shift
  temporary="$deployment_dir/.terminal.tmp.$$"
  "$@" > "$temporary"
  chmod 0600 "$temporary"
  python3 - "$temporary" "$destination" <<'PY'
import json
import os
import pathlib
import stat
import sys

source = pathlib.Path(sys.argv[1])
destination = pathlib.Path(sys.argv[2])
payload = source.read_bytes()
json.loads(payload.decode("utf-8"))
parent = destination.parent
parent_info = parent.lstat()
if (
    stat.S_ISLNK(parent_info.st_mode)
    or not stat.S_ISDIR(parent_info.st_mode)
    or parent_info.st_uid != os.geteuid()
    or stat.S_IMODE(parent_info.st_mode) != 0o700
):
    raise SystemExit("terminal record parent is not private")
flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
descriptor = os.open(destination, flags, 0o400)
try:
    view = memoryview(payload)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise SystemExit("terminal record write failed")
        view = view[written:]
    os.fsync(descriptor)
finally:
    os.close(descriptor)
parent_descriptor = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
try:
    os.fsync(parent_descriptor)
finally:
    os.close(parent_descriptor)
PY
  rm -f "$temporary"
}

run_compose_bounded() {
  timeout_seconds=$1
  selected_snapshot=$2
  shift 2
  if [ -n "$project" ]; then
    "$timeout_bin" "$timeout_seconds" docker compose \
      --project-name "$project" \
      --project-directory "$compose_dir" \
      --profile ops \
      --profile multi-instance \
      -f "$selected_snapshot" \
      "$@"
  else
    "$timeout_bin" "$timeout_seconds" docker compose \
      --project-directory "$compose_dir" \
      --profile ops \
      --profile multi-instance \
      -f "$selected_snapshot" \
      "$@"
  fi
}

capture_project_containers() {
  destination=$1
  project_name=$2
  project_container_ids=$(
    "$timeout_bin" 15 docker container ls -a --no-trunc \
      --filter "label=com.docker.compose.project=$project_name" -q
  ) || return 1
  if [ -n "$project_container_ids" ]; then
    # The IDs come one-per-line from Docker and are revalidated before mutation.
    # shellcheck disable=SC2086
    set -- $project_container_ids
    "$timeout_bin" 15 docker container inspect "$@" > "$destination" \
      || return 1
  else
    printf '[]\n' > "$destination"
  fi
  chmod 0600 "$destination"
}

capture_writer_containers() {
  destination=$1
  writer_ids=$(run_compose_bounded 15 "$compose_snapshot" ps -a -q \
    control-api control-api-replica) || return 1
  if [ -n "$writer_ids" ]; then
    # shellcheck disable=SC2086
    "$timeout_bin" 15 docker inspect $writer_ids > "$destination" || return 1
  else
    printf '[]\n' > "$destination" || return 1
  fi
  chmod 0600 "$destination"
}

prove_writer_containers_stopped() {
  "$timeout_bin" 15 python3 - "$1" <<'PY'
import json
import sys

values = json.load(open(sys.argv[1], encoding="utf-8"))
if not isinstance(values, list):
    raise SystemExit("writer inspection is not an array")
allowed = {"control-api", "control-api-replica"}
seen = set()
for value in values:
    labels = value.get("Config", {}).get("Labels") if isinstance(value, dict) else None
    service = labels.get("com.docker.compose.service") if isinstance(labels, dict) else None
    running = value.get("State", {}).get("Running") if isinstance(value, dict) else None
    if service not in allowed or service in seen or running is not False:
        raise SystemExit("one Control writer is not proven stopped")
    seen.add(service)
PY
}

capture_reverse_mutators() {
  destination=$1
  [ -n "$compose_project" ] || return 1
  mutator_ids=$("$timeout_bin" 15 docker container ls --all --quiet \
    --filter "label=com.docker.compose.project=$compose_project") || return 1
  if [ -n "$mutator_ids" ]; then
    # shellcheck disable=SC2086
    "$timeout_bin" 15 docker inspect $mutator_ids > "$destination" || return 1
  else
    printf '[]\n' > "$destination" || return 1
  fi
  chmod 0600 "$destination"
}

prove_reverse_mutators_stopped() {
  "$timeout_bin" 15 python3 - "$1" "$2" "$3" <<'PY'
import json
import sys

values = json.load(open(sys.argv[1], encoding="utf-8"))
if not isinstance(values, list):
    raise SystemExit("reverse mutator inspection is not an array")
allowed = {"control-api", "control-api-replica", "control-migrate"}
seen = set()
for value in values:
    labels = value.get("Config", {}).get("Labels") if isinstance(value, dict) else None
    service = labels.get("com.docker.compose.service") if isinstance(labels, dict) else None
    running = value.get("State", {}).get("Running") if isinstance(value, dict) else None
    if service not in allowed:
        continue
    if service in seen or running is not False:
        raise SystemExit("one production database mutator is not proven stopped")
    seen.add(service)

if sys.argv[3] == "1":
    baseline = json.load(open(sys.argv[2], encoding="utf-8"))
    if not isinstance(baseline, list):
        raise SystemExit("post-backup writer inspection is not an array")

    def writer_identities(items):
        identities = {}
        for item in items:
            labels = item.get("Config", {}).get("Labels") if isinstance(item, dict) else None
            service = labels.get("com.docker.compose.service") if isinstance(labels, dict) else None
            if service not in {"control-api", "control-api-replica"}:
                continue
            if service in identities:
                raise SystemExit("writer exposure proof contains a duplicate service")
            identities[service] = {
                "container_id": item.get("Id"),
                "image_id": item.get("Image"),
                "running": item.get("State", {}).get("Running"),
                "started_at": item.get("State", {}).get("StartedAt"),
                "restart_count": item.get("RestartCount"),
            }
        return identities

    if writer_identities(values) != writer_identities(baseline):
        raise SystemExit("a Control writer was exposed after the frozen backup")
PY
}

unfreeze_service_identity() {
  "$timeout_bin" 5 python3 - \
    "$deployment_dir/writer-unfreeze-plan.json" \
    "$deployment_dir/current-control-containers.json" \
    "$1" <<'PY'
import hashlib
import json
import sys

plan_path, current_path, service = sys.argv[1:]
value = json.load(open(plan_path, encoding="utf-8"))
current_raw = open(current_path, "rb").read()
current_digest = hashlib.sha256(current_raw).hexdigest()
if (
    value.get("bindings", {}).get("current_control_containers_sha256")
    != current_digest
):
    raise SystemExit("writer unfreeze plan does not bind current containers")
matches = [step for step in value["steps"] if step.get("service") == service]
if len(matches) != 1:
    raise SystemExit("writer unfreeze plan has no unique service step")
previous = matches[0].get("previous")
current_matches = [
    container
    for container in json.loads(current_raw.decode("utf-8"))
    if container.get("Config", {}).get("Labels", {}).get(
        "com.docker.compose.service"
    )
    == service
]
if len(current_matches) > 1:
    raise SystemExit("current container evidence has a duplicate writer")
current_previous = None
if current_matches:
    container = current_matches[0]
    current_previous = {
        "container_id": container.get("Id"),
        "image_id": container.get("Image"),
        "running": container.get("State", {}).get("Running"),
        "started_at": container.get("State", {}).get("StartedAt"),
        "restart_count": container.get("RestartCount"),
    }
if previous != current_previous:
    raise SystemExit("writer unfreeze plan prior identity differs from inspection")
expected_action = (
    "require-absent"
    if previous is None
    else (
        "start-exact-prior-container"
        if previous.get("running") is True
        else "keep-exact-prior-container-stopped"
    )
)
if matches[0].get("action") != expected_action:
    raise SystemExit("writer unfreeze plan action does not match the prior state")
if previous is None:
    print("absent|")
elif previous.get("running") is True:
    print(f"running|{previous['container_id']}")
elif previous.get("running") is False:
    print(f"stopped|{previous['container_id']}")
else:
    raise SystemExit("writer unfreeze plan has an invalid prior state")
PY
}

write_unfreeze_execution() {
  result_value=$1
  trigger_stage=$2
  proof_path=$3
  no_replace_json "$deployment_dir/writer-unfreeze-execution.json" \
    python3 -c '
import hashlib,json,pathlib,sys
from datetime import datetime,timezone
plan=pathlib.Path(sys.argv[1])
proof=pathlib.Path(sys.argv[4]) if sys.argv[4] else None
value={
  "format_version":1,
  "type":"production-writer-unfreeze-execution-v1",
  "status":sys.argv[3],
  "trigger_stage":sys.argv[2],
  "unfreeze_plan_path":str(plan),
  "unfreeze_plan_sha256":hashlib.sha256(plan.read_bytes()).hexdigest(),
  "proof":None if proof is None or not proof.is_file() else {
    "path":str(proof),"sha256":hashlib.sha256(proof.read_bytes()).hexdigest()
  },
  "bounded":True,
  "max_attempts_per_step":1,
  "database_restore_performed":False,
  "exact_container_ids_required":True,
  "completed_at":datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00","Z"),
}
print(json.dumps(value,sort_keys=True,separators=(",",":")))
' "$deployment_dir/writer-unfreeze-plan.json" "$trigger_stage" "$result_value" "$proof_path"
}

run_bounded_unfreeze() {
  trigger_stage=$1
  unfreeze_ok=1
  for service in control-api-replica control-api; do
    stage="unfreeze-$service"
    prior_identity=$(unfreeze_service_identity "$service") || {
      unfreeze_ok=0
      continue
    }
    prior_state=${prior_identity%%|*}
    prior_id=${prior_identity#*|}
    case "$prior_state" in
      running)
        "$timeout_bin" 60 docker container start "$prior_id" \
          >/dev/null 2>&1 || unfreeze_ok=0
        ;;
      stopped|absent) : ;;
      *) unfreeze_ok=0 ;;
    esac
  done
  stage=unfreeze-prove-exact-identities
  observed="$deployment_dir/writers-after-unfreeze.json"
  proof="$deployment_dir/writer-unfreeze-proof.json"
  if capture_writer_containers "$observed"; then
    "$timeout_bin" 30 python3 "$production_recovery" writer-unfreeze-proof \
      --current-control-containers "$deployment_dir/current-control-containers.json" \
      --observed-control-containers "$observed" \
      --unfreeze-plan "$deployment_dir/writer-unfreeze-plan.json" \
      --output "$proof" \
      --expected-owner-uid 0 \
      >/dev/null 2>&1 || unfreeze_ok=0
  else
    unfreeze_ok=0
  fi
  if [ "$unfreeze_ok" = "1" ]; then
    write_unfreeze_execution succeeded "$trigger_stage" "$proof" || return 1
    return 0
  fi
  write_unfreeze_execution failed "$trigger_stage" "$proof" || :
  return 1
}

reverse_service_state() {
  "$timeout_bin" 5 python3 - "$deployment_dir/reverse-plan.json" "$1" <<'PY'
import json
import sys

value = json.load(open(sys.argv[1], encoding="utf-8"))
matches = [
    step for step in value["reverse_steps"]
    if step.get("service") == sys.argv[2]
]
if len(matches) != 1:
    raise SystemExit("reverse plan has no unique service step")
previous = matches[0].get("previous")
if previous is None:
    print("absent")
elif previous.get("running") is True:
    print("running")
elif previous.get("running") is False:
    print("stopped")
else:
    raise SystemExit("reverse plan has an invalid prior service state")
PY
}

restore_control_database() {
  dump_path=$("$timeout_bin" 5 python3 - "$deployment_dir/reverse-plan.json" <<'PY'
import json
import sys

value = json.load(open(sys.argv[1], encoding="utf-8"))
matches = [
    step for step in value["reverse_steps"]
    if step.get("action") == "restore-control-database-from-premigration-dump"
]
if len(matches) != 1:
    raise SystemExit("reverse plan has no unique database restore step")
print(matches[0]["dump_path"])
PY
  ) || return 1
  "$timeout_bin" 55 python3 - \
    "$deployment_dir/reverse-plan.json" \
    "$deployment_dir/backup.json" \
    "$dump_path" <<'PY'
import hashlib
import json
import os
import pathlib
import stat
import sys

plan = json.load(open(sys.argv[1], encoding="utf-8"))
backup = json.load(open(sys.argv[2], encoding="utf-8"))
path = pathlib.Path(sys.argv[3])
steps = [
    step for step in plan["reverse_steps"]
    if step.get("action") == "restore-control-database-from-premigration-dump"
]
if (
    len(steps) != 1
    or not path.is_absolute()
    or backup.get("dump_path") != str(path)
    or backup.get("dump_sha256") != steps[0].get("dump_sha256")
):
    raise SystemExit("reverse database dump path is invalid")
descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0))
try:
    before = os.fstat(descriptor)
    if (
        not stat.S_ISREG(before.st_mode)
        or stat.S_IMODE(before.st_mode) != 0o600
        or before.st_uid != backup.get("owner_uid")
        or before.st_size <= 0
    ):
        raise SystemExit("reverse database dump is not the admitted private file")
    digest_value = hashlib.sha256()
    while block := os.read(descriptor, 1024 * 1024):
        digest_value.update(block)
    after = os.fstat(descriptor)
    identity = lambda value: (
        value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid,
        value.st_size, value.st_mtime_ns, value.st_ctime_ns,
    )
    if identity(before) != identity(after):
        raise SystemExit("reverse database dump changed while it was verified")
    digest = digest_value.hexdigest()
finally:
    os.close(descriptor)
if digest != steps[0].get("dump_sha256"):
    raise SystemExit("reverse database dump changed after admission")
PY
  dump_name=${dump_path##*/}
  recreate_script='
set -eu
IFS= read -r credential || credential=
if [ -n "$credential" ]; then export PGPASSWORD="$credential"; else unset PGPASSWORD 2>/dev/null || true; fi
exec psql --username "$1" --dbname "$2" --no-psqlrc --set ON_ERROR_STOP=1 \
  --set control_database="$3" --set control_role="$4" <<'"'"'RECOVERY_SQL'"'"'
SELECT pg_terminate_backend(pid) FROM pg_stat_activity
 WHERE datname = :'"'"'control_database'"'"' AND pid <> pg_backend_pid();
SELECT format('"'"'DROP DATABASE IF EXISTS %I'"'"', :'"'"'control_database'"'"')
\gexec
SELECT format('"'"'CREATE DATABASE %I OWNER %I'"'"', :'"'"'control_database'"'"', :'"'"'control_role'"'"')
\gexec
SELECT format('"'"'REVOKE ALL ON DATABASE %I FROM PUBLIC'"'"', :'"'"'control_database'"'"')
\gexec
SELECT format('"'"'GRANT CONNECT, TEMPORARY ON DATABASE %I TO %I'"'"', :'"'"'control_database'"'"', :'"'"'control_role'"'"')
\gexec
RECOVERY_SQL
  '
  if [ -n "$sub2api_postgres_password_file" ]; then
    "$timeout_bin" 90 docker exec -i "$sub2api_postgres_container" \
      sh -c "$recreate_script" recovery \
      "$sub2api_postgres_user" "$sub2api_postgres_database" \
      "$control_database" "$(json_field "$deployment_dir/plan.json" datastores postgres role)" \
      < "$sub2api_postgres_password_file" \
      || return 1
  else
    printf '\n' | "$timeout_bin" 90 docker exec -i "$sub2api_postgres_container" \
      sh -c "$recreate_script" recovery \
      "$sub2api_postgres_user" "$sub2api_postgres_database" \
      "$control_database" "$(json_field "$deployment_dir/plan.json" datastores postgres role)" \
      || return 1
  fi
  run_compose_bounded 210 "$compose_snapshot" run --rm --no-deps --pull never \
    --env "RECOVERY_DUMP=/backups/$dump_name" \
    --entrypoint sh control-backup -ec '
      PGPASSWORD=$(tr -d "\r\n" < "$CONTROL_DATABASE_PASSWORD_FILE")
      export PGPASSWORD
      pg_restore --exit-on-error --single-transaction --no-owner --no-acl \
        --host "$CONTROL_DB_HOST" --port "$CONTROL_DB_PORT" \
        --username "$CONTROL_DB_USER" --dbname "$CONTROL_DB_NAME" \
        "$RECOVERY_DUMP"
      psql --host "$CONTROL_DB_HOST" --port "$CONTROL_DB_PORT" \
        --username "$CONTROL_DB_USER" --dbname "$CONTROL_DB_NAME" \
        --no-psqlrc --set ON_ERROR_STOP=1 --command \
        "ALTER SCHEMA public OWNER TO $CONTROL_DB_USER;
         REVOKE ALL ON SCHEMA public FROM PUBLIC;
         GRANT USAGE, CREATE ON SCHEMA public TO $CONTROL_DB_USER"
    '
}

write_reverse_execution() {
  result_value=$1
  trigger_stage=$2
  database_restored_value=$3
  writers_frozen_value=$4
  freeze_evidence=$5
  no_writer_exposure_value=$6
  no_replace_json "$deployment_dir/reverse-execution.json" \
    python3 -c '
import hashlib,json,pathlib,sys
from datetime import datetime,timezone
plan=pathlib.Path(sys.argv[1])
freeze=pathlib.Path(sys.argv[6]) if sys.argv[6] else None
value={
  "format_version":1,
  "type":"production-bounded-reverse-execution-v1",
  "status":sys.argv[3],
  "trigger_stage":sys.argv[2],
  "reverse_plan_path":str(plan),
  "reverse_plan_sha256":hashlib.sha256(plan.read_bytes()).hexdigest(),
  "bounded":True,
  "max_attempts_per_step":1,
  "database_mutators_frozen":sys.argv[5] == "1",
  "mutator_freeze":None if freeze is None or not freeze.is_file() else {
    "path":str(freeze),"sha256":hashlib.sha256(freeze.read_bytes()).hexdigest()
  },
  "post_success_admission":None if not (plan.parent / "post-success-reverse-admission.json").is_file() else {
    "path":str(plan.parent / "post-success-reverse-admission.json"),
    "sha256":hashlib.sha256((plan.parent / "post-success-reverse-admission.json").read_bytes()).hexdigest()
  },
  "database_mutation_observed":sys.argv[7] == "1",
  "application_mutation_observed":sys.argv[9] == "1",
  "writer_exposure_started":sys.argv[8] == "1",
  "writer_exposure_after_database_mutation":sys.argv[7] == "1" and sys.argv[8] == "1",
  "no_writer_exposure_since_backup_proven":None if sys.argv[10] == "not-applicable" else sys.argv[10] == "1",
  "database_restore_policy":"only-before-writer-exposure-after-observed-mutation",
  "database_restore_performed":sys.argv[4] == "1",
  "completed_at":datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00","Z"),
}
print(json.dumps(value,sort_keys=True,separators=(",",":")))
  ' "$deployment_dir/reverse-plan.json" "$trigger_stage" "$result_value" \
    "$database_restored_value" "$writers_frozen_value" "$freeze_evidence" \
    "$database_mutated" "$writer_exposure_started" "$application_mutated" \
    "$no_writer_exposure_value"
}

run_bounded_reverse() {
  trigger_stage=$1
  rollback_ok=1
  writers_frozen=1
  database_restored=0
  no_writer_exposure_proven=not-applicable
  reverse_freeze_evidence="$deployment_dir/reverse-database-mutators-stopped.json"
  stage=reverse-stop-database-mutators
  run_compose_bounded 60 "$compose_snapshot" stop -t 30 \
    control-api control-api-replica control-migrate >/dev/null 2>&1 || :
  capture_reverse_mutators "$reverse_freeze_evidence" \
    && prove_reverse_mutators_stopped \
      "$reverse_freeze_evidence" \
      "$deployment_dir/writers-stopped-after-backup.json" \
      "$database_mutated" \
    || {
      writers_frozen=0
      rollback_ok=0
    }
  if [ "$database_mutated" = "1" ]; then
    if [ "$writers_frozen" = "1" ]; then
      no_writer_exposure_proven=1
    else
      no_writer_exposure_proven=0
    fi
    if [ "$writers_frozen" = "1" ] && [ "$writer_exposure_started" = "0" ]; then
      stage=reverse-restore-database
      if restore_control_database >/dev/null 2>&1; then
        database_restored=1
      else
        rollback_ok=0
      fi
    else
      rollback_ok=0
    fi
  fi
  if [ "$database_mutated" != "1" ] || [ "$database_restored" = "1" ]; then
    for service in codex-pwa control-api control-api-replica; do
      stage="reverse-$service"
      prior_state=$(reverse_service_state "$service") || {
        rollback_ok=0
        continue
      }
      case "$prior_state" in
        running)
          run_compose_bounded 100 "$deployment_dir/rollback-compose.json" up -d \
            --no-build --no-deps --pull never --force-recreate \
            --wait --wait-timeout "$wait_timeout" "$service" \
            >/dev/null 2>&1 || rollback_ok=0
          ;;
        stopped)
          run_compose_bounded 100 "$deployment_dir/rollback-compose.json" up \
            --no-start --no-build --no-deps --pull never --force-recreate "$service" \
            >/dev/null 2>&1 || rollback_ok=0
          ;;
        absent)
          run_compose_bounded 100 "$compose_snapshot" rm -sf "$service" \
            >/dev/null 2>&1 || rollback_ok=0
          ;;
        *) rollback_ok=0 ;;
      esac
    done
  fi
  if [ -n "$auth_evidence" ] && [ -f "$auth_evidence" ]; then
    SUB2API_CONTAINER="$sub2api_container" \
      VERSIONS_LOCK_FILE="$versions_lock" \
      SUB2API_AUTH_CONTRACT_FILE="$auth_contract_file" \
      SUB2API_ATTESTATION_FILE="$deployment_dir/sub2api-after-reverse.json" \
      SUB2API_EXPECTED_NETWORK="$sub2api_network" \
      SUB2API_EXPECTED_NETWORK_ALIAS=sub2api \
      SUB2API_AUTH_EVIDENCE_FILE="$auth_evidence" \
      SUB2API_REQUIRE_AUTH_EVIDENCE=1 \
      SUB2API_AUTH_EVIDENCE_MAX_AGE_SECONDS="$auth_max_age" \
      SUB2API_AUTH_EVIDENCE_NONCE="$auth_probe_nonce" \
      SUB2API_AUTH_EVIDENCE_EXPECTED_USER_ID="$auth_probe_user_id" \
      SUB2API_AUTH_EVIDENCE_BASE_URL="$auth_probe_base_url" \
      "$timeout_bin" 120 "$runtime_verifier" >/dev/null 2>&1 || rollback_ok=0
  else
    rollback_ok=0
  fi
  if [ "$rollback_ok" = "1" ]; then
    write_reverse_execution succeeded "$trigger_stage" \
      "$database_restored" "$writers_frozen" "$reverse_freeze_evidence" \
      "$no_writer_exposure_proven" || return 1
    return 0
  fi
  write_reverse_execution failed "$trigger_stage" \
    "$database_restored" "$writers_frozen" "$reverse_freeze_evidence" \
    "$no_writer_exposure_proven" || :
  return 1
}

run_runtime_verifier() {
  output=$1
  evidence=$2
  require_evidence=$3
  SUB2API_CONTAINER="$sub2api_container" \
    VERSIONS_LOCK_FILE="$versions_lock" \
    SUB2API_AUTH_CONTRACT_FILE="$auth_contract_file" \
    SUB2API_ATTESTATION_FILE="$output" \
    SUB2API_EXPECTED_NETWORK="$sub2api_network" \
    SUB2API_EXPECTED_NETWORK_ALIAS=sub2api \
    SUB2API_AUTH_EVIDENCE_FILE="$evidence" \
    SUB2API_REQUIRE_AUTH_EVIDENCE="$require_evidence" \
    SUB2API_AUTH_EVIDENCE_MAX_AGE_SECONDS="$auth_max_age" \
    SUB2API_AUTH_EVIDENCE_NONCE="$auth_probe_nonce" \
    SUB2API_AUTH_EVIDENCE_EXPECTED_USER_ID="$auth_probe_user_id" \
    SUB2API_AUTH_EVIDENCE_BASE_URL="$auth_probe_base_url" \
    "$runtime_verifier"
}

run_production_state_backup() {
  set -- \
    python3 "$production_state_backup" \
    --backup-root "$production_backup_root" \
    --result-file "$deployment_dir/production-state-backup.json" \
    --sub2api-container "$sub2api_container" \
    --postgres-container "$sub2api_postgres_container" \
    --postgres-user "$sub2api_postgres_user" \
    --postgres-database "$sub2api_postgres_database" \
    --additional-postgres-database "$control_database" \
    --redis-container "$sub2api_redis_container" \
    --redis-user "$sub2api_redis_user" \
    --redis-data-path "$sub2api_redis_data_path" \
    --sub2api-data "$sub2api_data_path" \
    --sub2api-config "$sub2api_config_path" \
    --sub2api-compose "$sub2api_compose_file" \
    --sub2api-environment "$sub2api_environment_file" \
    --nginx-config "$nginx_config_path" \
    --release-records "$record_root" \
    --release-record-exclude "$(basename "$deployment_dir")" \
    --release-record-exclude "$(basename "$lock_dir")" \
    --release-evidence "$deployment_dir/release-verification.json" \
    --release-evidence "$deployment_dir/source-verification.json" \
    --release-evidence "$deployment_dir/versions-lock-input.json" \
    --release-evidence "$server_package_manifest" \
    --release-evidence "$server_package_verification_receipt" \
    --release-evidence "$(dirname "$server_package_manifest")/connector-release-metadata.json" \
    --release-evidence "$(dirname "$server_package_manifest")/connector-release-metadata.json.sigstore.json" \
    --release-evidence "$(dirname "$server_package_manifest")/connector-public-verification-aggregate.json" \
    --release-evidence "$(dirname "$server_package_manifest")/connector-public-verification-aggregate.json.sigstore.json" \
    --docker-network "$sub2api_network" \
    --docker-network "$pwa_network" \
    --expected-owner-uid 0
  if [ -n "$sub2api_postgres_password_file" ]; then
    set -- "$@" --postgres-password-file "$sub2api_postgres_password_file"
  fi
  if [ -n "$sub2api_redis_password_file" ]; then
    set -- "$@" --redis-password-file "$sub2api_redis_password_file"
  fi
  "$@"
}

if [ "$lifecycle_bounded_uninstall" = "1" ]; then
  stage=inspect-lifecycle-bounded-uninstall
  for uninstall_evidence_name in \
    uninstall-project-containers-inspect.json \
    uninstall-pwa-network-inspect.json \
    uninstall-pwa-network-empty-inspect.json \
    uninstall-plan.json \
    uninstall-execution.json
  do
    uninstall_evidence_path="$deployment_dir/$uninstall_evidence_name"
    if [ -e "$uninstall_evidence_path" ] || [ -L "$uninstall_evidence_path" ]; then
      fail "bounded uninstall evidence already exists: $uninstall_evidence_name"
    fi
  done
  compose_project=$(
    json_field "$deployment_dir/deployment.json" running pwa_network compose_project
  )
  pwa_network=$(
    json_field "$deployment_dir/deployment.json" running pwa_network name
  )
  pwa_network_id=$(
    json_field "$deployment_dir/deployment.json" running pwa_network network_id
  )
  capture_project_containers \
    "$deployment_dir/uninstall-project-containers-inspect.json" \
    "$compose_project"
  "$timeout_bin" 15 docker network inspect "$pwa_network_id" \
    > "$deployment_dir/uninstall-pwa-network-inspect.json"
  chmod 0600 "$deployment_dir/uninstall-pwa-network-inspect.json"

  stage=admit-lifecycle-bounded-uninstall
  no_replace_json "$deployment_dir/uninstall-plan.json" \
    python3 "$checks" bounded-uninstall-plan \
    --deployment-directory "$deployment_dir" \
    --record-root "$record_root" \
    --trigger-stage "$lifecycle_uninstall_trigger" \
    --manifest "$server_package_manifest" \
    --verification-receipt "$server_package_verification_receipt" \
    --expected-manifest-sha256 "$server_package_manifest_sha256" \
    --mode "$server_package_mode" \
    --project-containers-inspect \
      "$deployment_dir/uninstall-project-containers-inspect.json" \
    --pwa-network-inspect "$deployment_dir/uninstall-pwa-network-inspect.json" \
    --expected-owner-uid 0
  bounded_uninstall_admitted=1
  write_status "in-progress:$stage"

  for service in control-api-replica control-api codex-pwa; do
    target_container_id=$(
      json_field "$deployment_dir/uninstall-plan.json" \
        targets containers "$service" container_id
    )
    stage="bounded-uninstall-stop-$service"
    write_status "in-progress:$stage"
    "$timeout_bin" 30 docker container stop --time 25 "$target_container_id" \
      >/dev/null
    stage="bounded-uninstall-remove-$service"
    write_status "in-progress:$stage"
    "$timeout_bin" 15 docker container rm "$target_container_id" >/dev/null
  done

  stage=bounded-uninstall-prove-pwa-network-empty
  write_status "in-progress:$stage"
  "$timeout_bin" 15 docker network inspect "$pwa_network_id" \
    > "$deployment_dir/uninstall-pwa-network-empty-inspect.json"
  chmod 0600 "$deployment_dir/uninstall-pwa-network-empty-inspect.json"

  stage=bounded-uninstall-remove-pwa-network
  write_status "in-progress:$stage"
  "$timeout_bin" 30 docker network rm "$pwa_network_id" >/dev/null

  stage=verify-lifecycle-bounded-uninstall
  write_status "in-progress:$stage"
  "$timeout_bin" 15 docker info --format '{{json .ServerVersion}}' >/dev/null
  remaining_project_containers=$(
    "$timeout_bin" 15 docker container ls -a --no-trunc \
      --filter "label=com.docker.compose.project=$compose_project" -q
  )
  [ -z "$remaining_project_containers" ] \
    || fail "bounded uninstall left a Compose project container"
  remaining_network_ids=$(
    "$timeout_bin" 15 docker network ls --no-trunc \
      --filter "id=$pwa_network_id" -q
  )
  [ -z "$remaining_network_ids" ] \
    || fail "bounded uninstall left the admitted PWA network ID"
  remaining_named_networks=$(
    "$timeout_bin" 15 docker network ls --no-trunc \
      --filter "name=^${pwa_network}$" -q
  )
  [ -z "$remaining_named_networks" ] \
    || fail "bounded uninstall found a replacement PWA network with the admitted name"

  stage=record-lifecycle-bounded-uninstall
  no_replace_json "$deployment_dir/uninstall-execution.json" \
    python3 "$checks" bounded-uninstall-execution \
    --plan "$deployment_dir/uninstall-plan.json" \
    --trigger-stage "$lifecycle_uninstall_trigger" \
    --empty-network-inspect \
      "$deployment_dir/uninstall-pwa-network-empty-inspect.json" \
    --project-containers-absent \
    --pwa-network-absent \
    --expected-owner-uid 0
  write_status "uninstalled:$lifecycle_uninstall_trigger"
  completed=1
  release_deployment_lock=1
  echo "Bounded uninstall recorded at $deployment_dir/uninstall-execution.json"
  exit 0
fi

if [ "$lifecycle_post_success_reverse" = "1" ]; then
  stage=admit-lifecycle-post-success-reverse
  no_replace_json "$deployment_dir/post-success-reverse-admission.json" \
    python3 "$checks" post-success-reverse \
    --deployment-directory "$deployment_dir" \
    --record-root "$record_root" \
    --trigger-stage "$lifecycle_reverse_trigger" \
    --expected-owner-uid 0
  post_success_reverse_admitted=1

  compose_snapshot="$deployment_dir/compose-config.json"
  project=$(json_field "$deployment_dir/post-success-reverse-admission.json" compose_project)
  compose_project=$project
  sub2api_network=$(
    json_field "$deployment_dir/post-success-reverse-admission.json" sub2api_network
  )
  versions_lock="$deployment_dir/versions.lock.json"
  auth_contract_file="$deployment_dir/sub2api-auth-contract.json"
  auth_evidence=$(
    json_field "$deployment_dir/post-success-reverse-admission.json" \
      auth_evidence path
  )
  auth_probe_nonce=$(
    json_field "$deployment_dir/post-success-reverse-admission.json" \
      auth_evidence nonce
  )
  auth_probe_user_id=$(
    json_field "$deployment_dir/post-success-reverse-admission.json" \
      auth_evidence expected_user_id
  )
  auth_probe_base_url=$(
    json_field "$deployment_dir/post-success-reverse-admission.json" \
      auth_evidence base_url
  )

  database_mutated=0
  application_mutated=1
  writer_exposure_started=1
  recovery_executed=1
  stage=lifecycle-post-success-bounded-reverse
  write_status "in-progress:$stage"
  if run_bounded_reverse "$lifecycle_reverse_trigger"; then
    completed=1
    release_deployment_lock=1
    write_status "reversed:$lifecycle_reverse_trigger" || :
    echo "Post-success bounded reverse recorded at $deployment_dir/reverse-execution.json"
    exit 0
  fi
  release_deployment_lock=0
  write_status "failed:$stage:reverse-failed:lock-retained" || :
  post_success_terminal_status_written=1
  fail "post-success bounded reverse failed; production deployment lock retained"
fi

stage=validate-smoke-input
write_status "in-progress:$stage"
[ -z "${SUB2API_ACCESS_TOKEN+x}" ] \
  || fail "raw SUB2API_ACCESS_TOKEN environment input is prohibited in production deployment"
[ -z "${SUB2API_AUTH_EVIDENCE_FILE+x}" ] \
  || fail "external SUB2API_AUTH_EVIDENCE_FILE is prohibited in production deployment"
[ -z "${SUB2API_AUTH_FIXTURE_BASE_URL+x}" ] \
  || fail "the Sub2API auth fixture origin is fixed by the deployment"
[ -n "$smoke_access_token_file" ] \
  || fail "set CONTROL_SMOKE_ACCESS_TOKEN_FILE to a private short-lived token file"
[ -n "$smoke_expected_user_id" ] \
  || fail "set CONTROL_SMOKE_EXPECTED_USER_ID to the exact fixture identity"
atomic_json "$deployment_dir/smoke-input.json" \
  python3 "$checks" smoke-input \
  --token-file "$smoke_access_token_file" \
  --expected-user-id "$smoke_expected_user_id"

stage=pin-compose-environment
write_status "in-progress:$stage"
env_file_copy="$deployment_dir/compose.env"
atomic_json "$deployment_dir/compose-env-input.json" \
  python3 "$checks" copy-private-file \
  --source "$env_file" \
  --destination "$env_file_copy" \
  --label "production Compose environment file"
env_file="$env_file_copy"

release_dir=${CONTROL_RELEASE_EVIDENCE_DIR:-}
expected_source_repository=${CONTROL_RELEASE_EXPECTED_SOURCE_REPOSITORY:-}
expected_source_commit=${CONTROL_RELEASE_EXPECTED_SOURCE_COMMIT:-}
expected_release_tag=${CONTROL_RELEASE_EXPECTED_TAG:-}
stage=admit-verified-server-package
write_status "in-progress:$stage"
for required_value in \
  "$release_dir" \
  "$expected_source_repository" \
  "$expected_source_commit" \
  "$expected_release_tag"
do
  [ -n "$required_value" ] || fail "all lifecycle-owned Control release inputs are required"
done

atomic_json "$deployment_dir/release-verification.json" \
  python3 "$checks" server-package-release \
  --manifest "$server_package_manifest" \
  --verification-receipt "$server_package_verification_receipt" \
  --expected-manifest-sha256 "$server_package_manifest_sha256" \
  --mode "$server_package_mode" \
  --expected-source-repository "$expected_source_repository" \
  --expected-source-commit "$expected_source_commit" \
  --expected-release-tag "$expected_release_tag" \
  --expected-owner-uid 0

stage=extract-signed-source
write_status "in-progress:$stage"
source_archive_sha256=$(
  json_field "$deployment_dir/release-verification.json" \
    CONTROL_SOURCE_ARCHIVE_SHA256
)
source_attestation_sha256=$(
  json_field "$deployment_dir/release-verification.json" \
    CONTROL_SOURCE_ATTESTATION_SHA256
)
source_manifest_sha256=$(
  json_field "$deployment_dir/release-verification.json" \
    CONTROL_SOURCE_MANIFEST_SHA256
)
source_stage="$deployment_dir/source"
atomic_json "$deployment_dir/source-verification.json" \
  python3 "$source_bundle_verifier" verify \
  --bundle-dir "$release_dir" \
  --release "${expected_release_tag#control-v}" \
  --source-repository "$expected_source_repository" \
  --source-commit "$expected_source_commit" \
  --attestation-sha256 "$source_attestation_sha256" \
  --manifest-sha256 "$source_manifest_sha256" \
  --archive-sha256 "$source_archive_sha256" \
  --extract-to "$source_stage" \
  --require-root-owner
repo_root="$source_stage"
script_dir="$repo_root/deploy/scripts"
compose_dir="$repo_root/deploy/docker-compose"
compose_file="$compose_dir/compose.yaml"
production_overlay="$compose_dir/compose.production.yaml"
checks="$script_dir/deployment-admission.py"
backup_admission="$script_dir/bootstrap-admission.py"
runtime_verifier="$script_dir/verify-sub2api-runtime.sh"
production_state_backup="$script_dir/backup-production-state.py"
production_recovery="$script_dir/production-recovery.py"
pg_restore_validator="$script_dir/pg-restore-via-container.sh"
smoke_test="$repo_root/tests/e2e/smoke.py"

stage=pin-signed-versions-lock
write_status "in-progress:$stage"
signed_versions_lock_sha256=$(
  json_field "$deployment_dir/release-verification.json" \
    CONTROL_VERSIONS_LOCK_SHA256
)
versions_lock_source="$repo_root/versions.lock.json"
atomic_json "$deployment_dir/versions-lock-input.json" \
  python3 "$checks" copy-admitted-file \
  --source "$versions_lock_source" \
  --destination "$deployment_dir/versions.lock.json" \
  --label "signed versions lock" \
  --expected-sha256 "$signed_versions_lock_sha256"
versions_lock="$deployment_dir/versions.lock.json"

stage=resolve-compose
write_status "in-progress:$stage"
compose_snapshot="$deployment_dir/compose-config.json"
compose_source config --format json > "$compose_snapshot"
chmod 0600 "$compose_snapshot"
atomic_json "$deployment_dir/plan.json" \
  python3 "$checks" compose-plan \
  --compose-config "$deployment_dir/compose-config.json" \
  --release-verification "$deployment_dir/release-verification.json" \
  --versions-lock "$versions_lock" \
  --source-repository "$expected_source_repository" \
  --repo-root "$repo_root" \
  --sub2api-database "$sub2api_postgres_database"
api_image=$(json_field "$deployment_dir/plan.json" api_image)
pwa_image=$(json_field "$deployment_dir/plan.json" pwa_image)
backup_image=$(json_field "$deployment_dir/plan.json" backup_image)
backup_dir=$(json_field "$deployment_dir/plan.json" backup_directory)
backup_owner_uid=$(json_integer "$deployment_dir/plan.json" backup_owner_uid)
sub2api_network=$(json_field "$deployment_dir/plan.json" sub2api_network)
pwa_network=$(json_field "$deployment_dir/plan.json" pwa_network)
compose_project=$(json_field "$deployment_dir/plan.json" compose_project)
public_origin=$(json_field "$deployment_dir/plan.json" public_origin)
auth_contract_source=$(json_field "$deployment_dir/plan.json" auth_contract_file)
auth_contract_sha256=$(json_field "$deployment_dir/plan.json" auth_contract_sha256)
auth_contract_file="$deployment_dir/sub2api-auth-contract.json"
atomic_json "$deployment_dir/auth-contract-input.json" \
  python3 "$checks" copy-admitted-file \
  --source "$auth_contract_source" \
  --destination "$auth_contract_file" \
  --label "signed Sub2API auth contract" \
  --expected-sha256 "$auth_contract_sha256" \
  --read-only
control_database=$(
  json_field "$compose_snapshot" services control-api environment CONTROL_DB_NAME
)
control_database_password_file=$(
  json_field "$compose_snapshot" secrets control_db_password file
)
control_redis_password_file=$(
  json_field "$compose_snapshot" secrets control_redis_password file
)
# The Compose secret sources are owned by the service users that read them
# inside the containers; the root-only recovery checks consume private
# root-owned copies instead.
atomic_json "$deployment_dir/control-db-password-input.json" \
  python3 "$checks" copy-service-secret \
  --source "$control_database_password_file" \
  --destination "$deployment_dir/control-db-password" \
  --label "Control PostgreSQL password secret"
control_database_password_file="$deployment_dir/control-db-password"
atomic_json "$deployment_dir/control-redis-password-input.json" \
  python3 "$checks" copy-service-secret \
  --source "$control_redis_password_file" \
  --destination "$deployment_dir/control-redis-password" \
  --label "Control Redis password secret"
control_redis_password_file="$deployment_dir/control-redis-password"

stage=create-production-state-backup
write_status "in-progress:$stage"
run_production_state_backup
docker inspect \
  "$sub2api_container" \
  "$sub2api_postgres_container" \
  "$sub2api_redis_container" \
  > "$deployment_dir/production-state-current-containers.json"
chmod 0600 "$deployment_dir/production-state-current-containers.json"
atomic_json "$deployment_dir/production-state-backup-admission.json" \
  python3 "$backup_admission" backup-receipt \
  --result-file "$deployment_dir/production-state-backup.json" \
  --max-age-seconds "$production_backup_max_age" \
  --expected-owner-uid 0 \
  --current-identities "$deployment_dir/production-state-current-containers.json"

stage=prove-isolated-restore
write_status "in-progress:$stage"
python3 "$production_recovery" isolated-restore \
  --backup-admission "$deployment_dir/production-state-backup-admission.json" \
  --output "$deployment_dir/isolated-restore-receipt.json" \
  --timeout-seconds "$recovery_restore_timeout" \
  --expected-owner-uid 0 \
  >/dev/null

stage=prove-live-datastore-isolation
write_status "in-progress:$stage"
set -- \
  python3 "$production_recovery" live-isolation \
  --backup-admission "$deployment_dir/production-state-backup-admission.json" \
  --plan "$deployment_dir/plan.json" \
  --output "$deployment_dir/datastore-isolation-receipt.json" \
  --postgres-container "$sub2api_postgres_container" \
  --postgres-admin-user "$sub2api_postgres_user" \
  --postgres-admin-database "$sub2api_postgres_database" \
  --control-postgres-password-file "$control_database_password_file" \
  --redis-container "$sub2api_redis_container" \
  --redis-admin-user "$sub2api_redis_user" \
  --control-redis-password-file "$control_redis_password_file" \
  --expected-owner-uid 0
if [ -n "$sub2api_postgres_password_file" ]; then
  set -- "$@" --postgres-admin-password-file "$sub2api_postgres_password_file"
fi
if [ -n "$sub2api_redis_password_file" ]; then
  set -- "$@" --redis-admin-password-file "$sub2api_redis_password_file"
fi
"$@" >/dev/null

stage=acquire-release-images
write_status "in-progress:$stage"
if [ "$server_package_mode" = online ]; then
  docker pull "$api_image"
  docker pull "$pwa_image"
  docker pull "$backup_image"
fi
docker image inspect "$api_image" > "$deployment_dir/api-image-inspect.json"
docker image inspect "$pwa_image" > "$deployment_dir/pwa-image-inspect.json"
docker image inspect "$backup_image" > "$deployment_dir/backup-image-inspect.json"
atomic_json "$deployment_dir/release-images.json" \
  python3 "$checks" release-images \
  --plan "$deployment_dir/plan.json" \
  --api-inspect "$deployment_dir/api-image-inspect.json" \
  --pwa-inspect "$deployment_dir/pwa-image-inspect.json" \
  --backup-inspect "$deployment_dir/backup-image-inspect.json"

stage=verify-sub2api
write_status "in-progress:$stage"
active_access_file=${SUB2API_FIXTURE_ACTIVE_ACCESS_TOKEN_FILE:-}
active_refresh_file=${SUB2API_FIXTURE_ACTIVE_REFRESH_TOKEN_FILE:-}
disabled_access_file=${SUB2API_FIXTURE_DISABLED_ACCESS_TOKEN_FILE:-}
revoked_access_file=${SUB2API_FIXTURE_REVOKED_ACCESS_TOKEN_FILE:-}
[ -n "$active_access_file" ] \
  && [ -n "$active_refresh_file" ] \
  && [ -n "$disabled_access_file" ] \
  && [ -n "$revoked_access_file" ] \
  || fail "all disposable Sub2API auth fixture token files are required"
run_runtime_verifier "$deployment_dir/sub2api-probe-runtime.json" "" 0
sub2api_id=$(json_field "$deployment_dir/sub2api-probe-runtime.json" container_id)
probe_input_dir="$deployment_dir/auth-probe-inputs"
mkdir "$probe_input_dir"
chmod 0700 "$probe_input_dir"

atomic_json "$deployment_dir/auth-probe-active-access-input.json" \
  python3 "$checks" copy-private-file \
  --source "$active_access_file" \
  --destination "$probe_input_dir/active-access" \
  --label "active Sub2API access token"
atomic_json "$deployment_dir/auth-probe-active-refresh-input.json" \
  python3 "$checks" copy-private-file \
  --source "$active_refresh_file" \
  --destination "$probe_input_dir/active-refresh" \
  --label "active Sub2API refresh token"
atomic_json "$deployment_dir/auth-probe-disabled-access-input.json" \
  python3 "$checks" copy-private-file \
  --source "$disabled_access_file" \
  --destination "$probe_input_dir/disabled-access" \
  --label "disabled-user Sub2API access token"
atomic_json "$deployment_dir/auth-probe-revoked-access-input.json" \
  python3 "$checks" copy-private-file \
  --source "$revoked_access_file" \
  --destination "$probe_input_dir/revoked-access" \
  --label "revoked Sub2API access token"
atomic_json "$deployment_dir/auth-probe-runtime-input.json" \
  python3 "$checks" copy-private-file \
  --source "$deployment_dir/sub2api-probe-runtime.json" \
  --destination "$probe_input_dir/runtime.json" \
  --label "Sub2API runtime attestation"
atomic_json "$deployment_dir/auth-probe-contract-input.json" \
  python3 "$checks" copy-admitted-file \
  --source "$auth_contract_file" \
  --destination "$probe_input_dir/contract.json" \
  --label "pinned Sub2API auth contract" \
  --expected-sha256 "$auth_contract_sha256"

probe_nonce=$(python3 -c 'import secrets; print(secrets.token_hex(32))')
fixture_expected_user_id=${SUB2API_FIXTURE_EXPECTED_USER_ID:-$smoke_expected_user_id}
auth_probe_nonce=$probe_nonce
auth_probe_user_id=$fixture_expected_user_id
probe_user=$(id -u):$(id -g)
atomic_json "$deployment_dir/generated-auth-evidence.json" \
  docker container run --rm \
  --pull never \
  --network "container:$sub2api_id" \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --pids-limit 64 \
  --memory 128m \
  --cpus 0.5 \
  --user "$probe_user" \
  --mount "type=bind,source=$probe_input_dir,target=/run/control-auth-probe,readonly" \
  --env PYTHONDONTWRITEBYTECODE=1 \
  --env HTTP_PROXY= \
  --env HTTPS_PROXY= \
  --env ALL_PROXY= \
  --env NO_PROXY='*' \
  --env http_proxy= \
  --env https_proxy= \
  --env all_proxy= \
  --env no_proxy='*' \
  --entrypoint /opt/venv/bin/python \
  "$api_image" \
  /usr/local/bin/probe-sub2api-auth-contract.py \
  --base-url "$auth_probe_base_url" \
  --active-access-token-file /run/control-auth-probe/active-access \
  --active-refresh-token-file /run/control-auth-probe/active-refresh \
  --disabled-access-token-file /run/control-auth-probe/disabled-access \
  --revoked-access-token-file /run/control-auth-probe/revoked-access \
  --runtime-attestation /run/control-auth-probe/runtime.json \
  --contract-file /run/control-auth-probe/contract.json \
  --probe-nonce "$probe_nonce" \
  --expected-user-id "$fixture_expected_user_id"
auth_evidence="$deployment_dir/generated-auth-evidence.json"
run_runtime_verifier "$deployment_dir/sub2api-first.json" "$auth_evidence" 1

stage=read-migration-revisions
write_status "in-progress:$stage"
compose run --rm --no-deps --pull never control-api \
  /opt/venv/bin/alembic -c /app/migrations/alembic.ini current \
  > "$deployment_dir/alembic-current-before.txt"
compose run --rm --no-deps --pull never control-api \
  /opt/venv/bin/alembic -c /app/migrations/alembic.ini heads \
  > "$deployment_dir/alembic-head.txt"
atomic_json "$deployment_dir/revisions.json" \
  python3 "$checks" revisions \
  --current "$deployment_dir/alembic-current-before.txt" \
  --head "$deployment_dir/alembic-head.txt" \
  --plan "$deployment_dir/plan.json"
source_database_revision=$(
  json_field "$deployment_dir/revisions.json" source_database_revision
)
target_database_revision=$(
  json_field "$deployment_dir/revisions.json" target_migration_head
)
if [ "$source_database_revision" != "$target_database_revision" ]; then
  migration_required=1
fi

stage=recheck-admission
write_status "in-progress:$stage"
atomic_json "$deployment_dir/plan-before-migration.json" \
  python3 "$checks" compose-plan \
  --compose-config "$compose_snapshot" \
  --release-verification "$deployment_dir/release-verification.json" \
  --versions-lock "$versions_lock" \
  --source-repository "$expected_source_repository" \
  --repo-root "$repo_root" \
  --sub2api-database "$sub2api_postgres_database"
cmp -s "$deployment_dir/plan.json" "$deployment_dir/plan-before-migration.json" \
  || fail "pinned Compose deployment plan changed during admission"
run_runtime_verifier "$deployment_dir/sub2api-before-migration.json" "$auth_evidence" 1
atomic_json "$deployment_dir/sub2api-match.json" \
  python3 "$checks" runtime-match \
  --first "$deployment_dir/sub2api-first.json" \
  --second "$deployment_dir/sub2api-before-migration.json" \
  --plan "$deployment_dir/plan.json"

command -v "$timeout_bin" >/dev/null 2>&1 \
  || fail "a bounded timeout command is required before freezing production writers"

stage=capture-current-control-identities
write_status "in-progress:$stage"
current_control_ids=$(compose ps -a -q control-api control-api-replica codex-pwa)
if [ -n "$current_control_ids" ]; then
  # shellcheck disable=SC2086
  docker inspect $current_control_ids > "$deployment_dir/current-control-containers.json"
else
  printf '[]\n' > "$deployment_dir/current-control-containers.json"
fi
chmod 0600 "$deployment_dir/current-control-containers.json"

stage=admit-exact-writer-unfreeze
write_status "in-progress:$stage"
python3 "$production_recovery" writer-unfreeze-plan \
  --current-control-containers "$deployment_dir/current-control-containers.json" \
  --output "$deployment_dir/writer-unfreeze-plan.json" \
  --total-timeout-seconds 240 \
  --expected-owner-uid 0 \
  >/dev/null

freeze_started=1
stage=freeze-control-writers
write_status "in-progress:$stage"
run_compose_bounded 60 "$compose_snapshot" stop -t 30 \
  control-api control-api-replica

stage=capture-writers-stopped-before-backup
write_status "in-progress:$stage"
capture_writer_containers "$deployment_dir/writers-stopped-before-backup.json"
prove_writer_containers_stopped "$deployment_dir/writers-stopped-before-backup.json"

stage=recheck-frozen-database-revision
write_status "in-progress:$stage"
compose run --rm --no-deps --pull never control-api \
  /opt/venv/bin/alembic -c /app/migrations/alembic.ini current \
  > "$deployment_dir/alembic-current-before-migration.txt"
atomic_json "$deployment_dir/revisions-before-migration.json" \
  python3 "$checks" revisions \
  --current "$deployment_dir/alembic-current-before-migration.txt" \
  --head "$deployment_dir/alembic-head.txt" \
  --plan "$deployment_dir/plan.json"
cmp -s "$deployment_dir/revisions.json" "$deployment_dir/revisions-before-migration.json" \
  || fail "database migration revision changed during admission"

stage=create-final-premigration-backup
write_status "in-progress:$stage"
not_before=$(python3 -c 'import time; print(time.time())')
compose run --rm --no-deps --pull never control-backup
PG_RESTORE_IMAGE=$backup_image
export PG_RESTORE_IMAGE
atomic_json "$deployment_dir/backup.json" \
  python3 "$checks" backup \
  --directory "$backup_dir" \
  --not-before "$not_before" \
  --max-age-seconds "$backup_max_age" \
  --pg-restore "$pg_restore_validator" \
  --expected-owner-uid "$backup_owner_uid"
unset PG_RESTORE_IMAGE

stage=capture-writers-stopped-after-backup
write_status "in-progress:$stage"
capture_writer_containers "$deployment_dir/writers-stopped-after-backup.json"
prove_writer_containers_stopped "$deployment_dir/writers-stopped-after-backup.json"

stage=admit-writer-freeze-window
write_status "in-progress:$stage"
python3 "$production_recovery" writer-freeze-receipt \
  --current-control-containers "$deployment_dir/current-control-containers.json" \
  --stopped-before-backup "$deployment_dir/writers-stopped-before-backup.json" \
  --stopped-after-backup "$deployment_dir/writers-stopped-after-backup.json" \
  --unfreeze-plan "$deployment_dir/writer-unfreeze-plan.json" \
  --output "$deployment_dir/writer-freeze-receipt.json" \
  --expected-owner-uid 0 \
  >/dev/null

stage=admit-bounded-reverse-plan
write_status "in-progress:$stage"
python3 "$production_recovery" reverse-plan \
  --backup-admission "$deployment_dir/production-state-backup-admission.json" \
  --plan "$deployment_dir/plan.json" \
  --releases "$deployment_dir/release-images.json" \
  --revisions "$deployment_dir/revisions.json" \
  --premigration-backup "$deployment_dir/backup.json" \
  --restore-receipt "$deployment_dir/isolated-restore-receipt.json" \
  --isolation-receipt "$deployment_dir/datastore-isolation-receipt.json" \
  --unfreeze-plan "$deployment_dir/writer-unfreeze-plan.json" \
  --writer-freeze-receipt "$deployment_dir/writer-freeze-receipt.json" \
  --current-control-containers "$deployment_dir/current-control-containers.json" \
  --compose-config "$deployment_dir/compose-config.json" \
  --rollback-compose-output "$deployment_dir/rollback-compose.json" \
  --output "$deployment_dir/reverse-plan.json" \
  --expected-owner-uid 0 \
  >/dev/null

stage=record-final-pre-migration-admission
write_status "in-progress:$stage"
atomic_json "$deployment_dir/pre-migration-admission.json" \
  python3 "$checks" record \
  --plan "$deployment_dir/plan.json" \
  --releases "$deployment_dir/release-images.json" \
  --sub2api "$deployment_dir/sub2api-before-migration.json" \
  --backup "$deployment_dir/backup.json" \
  --revisions "$deployment_dir/revisions.json" \
  --release-verification "$deployment_dir/release-verification.json" \
  --compose-config "$deployment_dir/compose-config.json" \
  --smoke-input "$deployment_dir/smoke-input.json" \
  --full-backup "$deployment_dir/production-state-backup-admission.json" \
  --restore-receipt "$deployment_dir/isolated-restore-receipt.json" \
  --isolation-receipt "$deployment_dir/datastore-isolation-receipt.json" \
  --writer-unfreeze-plan "$deployment_dir/writer-unfreeze-plan.json" \
  --writer-freeze-receipt "$deployment_dir/writer-freeze-receipt.json" \
  --writers-stopped-before-backup "$deployment_dir/writers-stopped-before-backup.json" \
  --writers-stopped-after-backup "$deployment_dir/writers-stopped-after-backup.json" \
  --reverse-plan "$deployment_dir/reverse-plan.json" \
  --rollback-compose "$deployment_dir/rollback-compose.json" \
  --current-control-containers "$deployment_dir/current-control-containers.json" \
  --recovery-max-age-seconds "$recovery_receipt_max_age" \
  --status admitted_for_migration

stage=migrate
write_status "in-progress:$stage"
if [ "$migration_required" = "1" ]; then
  database_mutated=1
fi
run_compose_bounded 180 "$compose_snapshot" run --rm --no-deps --pull never control-migrate
run_compose_bounded 60 "$compose_snapshot" run --rm --no-deps --pull never control-api \
  /opt/venv/bin/alembic -c /app/migrations/alembic.ini current \
  > "$deployment_dir/alembic-current-after.txt"
atomic_json "$deployment_dir/revisions-after-migration.json" \
  python3 "$checks" revisions \
  --current "$deployment_dir/alembic-current-after.txt" \
  --head "$deployment_dir/alembic-head.txt" \
  --plan "$deployment_dir/plan.json" \
  --require-current-head

if [ "$database_mutated" = "1" ]; then
  stage=reject-uncontrolled-migration-writer-exposure
  write_status "in-progress:$stage"
  fail "schema migration reached the target while writers remain frozen; a controlled traffic maintenance gate is required before any new API may be exposed"
fi

application_mutated=1
writer_exposure_started=1
for service in control-api-replica control-api codex-pwa; do
  stage="start-$service"
  write_status "in-progress:$stage"
  run_compose_bounded 120 "$compose_snapshot" up -d \
    --no-build \
    --no-deps \
    --pull never \
    --force-recreate \
    --wait \
    --wait-timeout "$wait_timeout" \
    "$service"
done
api_container=$(compose ps --status running -q control-api)
api_replica_container=$(compose ps --status running -q control-api-replica)
pwa_container=$(compose ps --status running -q codex-pwa)
[ -n "$api_container" ] || fail "Compose did not return one running control-api container"
[ -n "$api_replica_container" ] \
  || fail "Compose did not return one running control-api-replica container"
[ -n "$pwa_container" ] || fail "Compose did not return one running codex-pwa container"
docker container inspect "$api_container" > "$deployment_dir/api-container-inspect.json"
docker container inspect "$api_replica_container" \
  > "$deployment_dir/api-replica-container-inspect.json"
docker container inspect "$pwa_container" > "$deployment_dir/pwa-container-inspect.json"
docker network inspect "$pwa_network" > "$deployment_dir/pwa-network-inspect.json"
chmod 0600 \
  "$deployment_dir/api-container-inspect.json" \
  "$deployment_dir/api-replica-container-inspect.json" \
  "$deployment_dir/pwa-container-inspect.json" \
  "$deployment_dir/pwa-network-inspect.json"
atomic_json "$deployment_dir/running-containers.json" \
  python3 "$checks" running-containers \
  --releases "$deployment_dir/release-images.json" \
  --plan "$deployment_dir/plan.json" \
  --api-inspect "$deployment_dir/api-container-inspect.json" \
  --api-replica-inspect "$deployment_dir/api-replica-container-inspect.json" \
  --pwa-inspect "$deployment_dir/pwa-container-inspect.json" \
  --pwa-network-inspect "$deployment_dir/pwa-network-inspect.json"

stage=production-smoke
write_status "in-progress:$stage"
atomic_json "$deployment_dir/smoke-input-before-run.json" \
  python3 "$checks" smoke-input \
  --token-file "$smoke_access_token_file" \
  --expected-user-id "$smoke_expected_user_id"
cmp -s "$deployment_dir/smoke-input.json" "$deployment_dir/smoke-input-before-run.json" \
  || fail "production smoke identity changed during deployment"
python3 "$smoke_test" \
  --base-url "$public_origin" \
  --access-token-file "$smoke_access_token_file" \
  --expected-user-id "$smoke_expected_user_id" \
  --expect-secure-cookie \
  > "$deployment_dir/production-smoke.txt" 2>&1
chmod 0600 "$deployment_dir/production-smoke.txt"
run_runtime_verifier "$deployment_dir/sub2api-after-deploy.json" "$auth_evidence" 1
atomic_json "$deployment_dir/sub2api-after-match.json" \
  python3 "$checks" runtime-match \
  --first "$deployment_dir/sub2api-first.json" \
  --second "$deployment_dir/sub2api-after-deploy.json" \
  --plan "$deployment_dir/plan.json"

stage=record-success
write_status "in-progress:$stage"
no_replace_json "$deployment_dir/deployment.json" \
  python3 "$checks" record \
  --plan "$deployment_dir/plan.json" \
  --releases "$deployment_dir/release-images.json" \
  --sub2api "$deployment_dir/sub2api-after-deploy.json" \
  --backup "$deployment_dir/backup.json" \
  --revisions "$deployment_dir/revisions.json" \
  --release-verification "$deployment_dir/release-verification.json" \
  --compose-config "$deployment_dir/compose-config.json" \
  --smoke-input "$deployment_dir/smoke-input.json" \
  --full-backup "$deployment_dir/production-state-backup-admission.json" \
  --restore-receipt "$deployment_dir/isolated-restore-receipt.json" \
  --isolation-receipt "$deployment_dir/datastore-isolation-receipt.json" \
  --writer-unfreeze-plan "$deployment_dir/writer-unfreeze-plan.json" \
  --writer-freeze-receipt "$deployment_dir/writer-freeze-receipt.json" \
  --writers-stopped-before-backup "$deployment_dir/writers-stopped-before-backup.json" \
  --writers-stopped-after-backup "$deployment_dir/writers-stopped-after-backup.json" \
  --reverse-plan "$deployment_dir/reverse-plan.json" \
  --rollback-compose "$deployment_dir/rollback-compose.json" \
  --current-control-containers "$deployment_dir/current-control-containers.json" \
  --recovery-max-age-seconds "$recovery_receipt_max_age" \
  --running "$deployment_dir/running-containers.json" \
  --smoke "$deployment_dir/production-smoke.txt" \
  --deployed-revision "$deployment_dir/alembic-current-after.txt" \
  --status deployed
completed=1
write_status deployed || :
echo "Production deployment admitted and recorded at $deployment_dir/deployment.json"
