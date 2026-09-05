#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/../.." && pwd)
compose_dir="$repo_root/deploy/docker-compose"
compose_file="$compose_dir/compose.yaml"
production_overlay="$compose_dir/compose.production.yaml"
bootstrap_checks="$script_dir/bootstrap-admission.py"
deployment_checks="$script_dir/deployment-admission.py"
runtime_verifier="$script_dir/verify-sub2api-runtime.sh"
bootstrap_sql="$repo_root/deploy/postgres/bootstrap-first-deployment.sql"
smoke_test="$repo_root/tests/e2e/smoke.py"
unauthenticated_smoke_test="$script_dir/bootstrap-unauthenticated-smoke.py"

confirm=${CONTROL_BOOTSTRAP_CONFIRM:-}
env_file=${CONTROL_COMPOSE_ENV_FILE:-}
record_root=${CONTROL_DEPLOYMENT_RECORD_DIR:-}
backup_result=${CONTROL_PRODUCTION_BACKUP_RESULT_FILE:-}
backup_max_age=${CONTROL_PRODUCTION_BACKUP_MAX_AGE_SECONDS:-1800}
stale_backup_exception_source=${CONTROL_STALE_PRODUCTION_BACKUP_EXCEPTION_FILE:-}
requested_deployment_id=${CONTROL_BOOTSTRAP_DEPLOYMENT_ID:-}
project=${CONTROL_COMPOSE_PROJECT_NAME:-sub2api-codex-control}
sub2api_container=${SUB2API_CONTAINER:-sub2api}
postgres_container=${SUB2API_POSTGRES_CONTAINER:-sub2api-postgres}
postgres_admin_user=${SUB2API_POSTGRES_ADMIN_USER:-}
redis_container=${SUB2API_REDIS_CONTAINER:-sub2api-redis}
sub2api_database=${SUB2API_DB_NAME:-sub2api}
control_role=${CONTROL_DB_USER:-codex_control}
control_database=${CONTROL_DB_NAME:-codex_control}
database_password_file=${CONTROL_DATABASE_PASSWORD_FILE:-}
versions_lock=${VERSIONS_LOCK_FILE:-$repo_root/versions.lock.json}
auth_contract=${SUB2API_AUTH_CONTRACT_FILE:-$repo_root/docs/contracts/sub2api-auth.v0.2.1.json}
smoke_access_token_file=${CONTROL_SMOKE_ACCESS_TOKEN_FILE:-}
smoke_expected_user_id=${CONTROL_SMOKE_EXPECTED_USER_ID:-}
allow_sub2api_public_connect=${CONTROL_BOOTSTRAP_ALLOW_SUB2API_PUBLIC_CONNECT:-0}
allow_unauthenticated_smoke=${CONTROL_BOOTSTRAP_ALLOW_UNAUTHENTICATED_SMOKE:-0}
wait_timeout=${CONTROL_DEPLOYMENT_WAIT_TIMEOUT_SECONDS:-120}
control_api_uid=10001
control_api_gid=10001

stage=initializing
completed=0
writes_started=0
postgres_provisioned=0
authenticated_smoke_pending=0
redis_namespace_mutated=0
redis_cleanup_count=0
redis_prefix=
pwa_network=
pwa_network_removed=0
stale_backup_exception_enabled=0
stale_backup_exception_file=
stale_backup_exception_claim=
compose_snapshot=
deployment_dir=
deployment_id=
lock_dir=

umask 077

fail() {
  echo "bootstrap-production-unsigned: $*" >&2
  exit 1
}

write_status() {
  status_value=$1
  status_tmp="$deployment_dir/.status.tmp.$$"
  printf '%s\n' "$status_value" > "$status_tmp"
  chmod 0600 "$status_tmp"
  mv "$status_tmp" "$deployment_dir/status"
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

sha256_file() {
  python3 -c '
import hashlib, pathlib, sys
digest = hashlib.sha256()
with pathlib.Path(sys.argv[1]).open("rb") as source:
    for block in iter(lambda: source.read(1024 * 1024), b""):
        digest.update(block)
print(digest.hexdigest())
' "$1"
}

require_private_file() {
  require_single_link=${3:-0}
  python3 -c '
import os, pathlib, stat, sys
path = pathlib.Path(sys.argv[1])
label = sys.argv[2]
require_single_link = sys.argv[3] == "1"
try:
    value = path.lstat()
except OSError as exc:
    raise SystemExit(f"{label} is not accessible: {exc}")
if not path.is_absolute() or stat.S_ISLNK(value.st_mode) or not stat.S_ISREG(value.st_mode):
    raise SystemExit(f"{label} must be one absolute regular non-symlink file")
if value.st_uid != os.geteuid() or stat.S_IMODE(value.st_mode) != 0o600:
    raise SystemExit(f"{label} must be owned by the deployment UID with mode 0600")
if require_single_link and value.st_nlink != 1:
    raise SystemExit(f"{label} must have exactly one hard link")
if value.st_size <= 0 or value.st_size > 1048576:
    raise SystemExit(f"{label} has an invalid size")
' "$1" "$2" "$require_single_link"
}

require_immutable_contract_file() {
  python3 -c '
import os, pathlib, stat, sys
path = pathlib.Path(sys.argv[1])
label = sys.argv[2]
try:
    value = path.lstat()
except OSError as exc:
    raise SystemExit(f"{label} is not accessible: {exc}")
if not path.is_absolute() or stat.S_ISLNK(value.st_mode) or not stat.S_ISREG(value.st_mode):
    raise SystemExit(f"{label} must be one absolute regular non-symlink file")
if value.st_uid != os.geteuid() or stat.S_IMODE(value.st_mode) != 0o444:
    raise SystemExit(f"{label} must be owned by the deployment UID with mode 0444")
if value.st_nlink != 1:
    raise SystemExit(f"{label} must have exactly one hard link")
if value.st_size <= 0 or value.st_size > 4194304:
    raise SystemExit(f"{label} has an invalid size")
' "$1" "$2"
}

validate_identifier() {
  identifier=$1
  label=$2
  case "$identifier" in
    ''|*[!A-Za-z0-9_]*) fail "$label must contain only letters, digits, and underscores" ;;
  esac
  [ "${#identifier}" -le 63 ] || fail "$label exceeds 63 bytes"
}

compose_source() {
  docker compose \
    --project-name "$project" \
    --project-directory "$compose_dir" \
    --profile ops \
    --profile multi-instance \
    --env-file "$env_file" \
    -f "$compose_file" \
    -f "$production_overlay" \
    "$@"
}

compose() {
  [ -n "$compose_snapshot" ] || fail "resolved Compose snapshot is unavailable"
  docker compose \
    --project-name "$project" \
    --project-directory "$compose_dir" \
    --profile ops \
    --profile multi-instance \
    -f "$compose_snapshot" \
    "$@"
}

admit_production_backup() {
  current_identities=$1
  current_runtime_attestation=$2
  set -- backup-receipt \
    --result-file "$backup_result" \
    --max-age-seconds "$backup_max_age" \
    --current-identities "$current_identities" \
    --expected-control-database "$control_database" \
    --expected-control-role "$control_role" \
    --expected-redis-prefix "$redis_prefix" \
    --expected-pwa-network "$pwa_network" \
    --deployment-id "$deployment_id" \
    --current-runtime-attestation "$current_runtime_attestation"
  if [ "$stale_backup_exception_enabled" = "1" ]; then
    set -- "$@" --stale-exception-file "$stale_backup_exception_file"
  fi
  python3 "$bootstrap_checks" "$@"
}

postgres_psql() {
  database=$1
  shift
  docker container exec -i "$postgres_container" sh -eu -c '
admin_user=$1
database=$2
shift 2
if [ -z "$admin_user" ]; then
  admin_user=${POSTGRES_USER:?POSTGRES_USER is unavailable in PostgreSQL container}
fi
exec psql --no-psqlrc --set ON_ERROR_STOP=1 --username "$admin_user" --dbname "$database" "$@"
' bootstrap-postgres "$postgres_admin_user" "$database" "$@"
}

redis_noauth() {
  docker container exec "$redis_container" sh -eu -c '
unset REDISCLI_AUTH
exec redis-cli --raw --user default "$@"
' bootstrap-redis "$@"
}

redis_namespace_count() {
  [ "$redis_prefix" = "codex-control:" ] \
    || fail "Redis namespace cleanup requires the exact admitted prefix"
  redis_noauth EVAL '
local cursor = "0"
local count = 0
repeat
  local result = redis.call("SCAN", cursor, "MATCH", ARGV[1] .. "*", "COUNT", 1000)
  cursor = result[1]
  count = count + #result[2]
  if count > 10000 then
    return redis.error_reply("bootstrap namespace count limit exceeded")
  end
until cursor == "0"
return count
' 0 "$redis_prefix"
}

redis_namespace_channel_count() {
  [ "$redis_prefix" = "codex-control:" ] \
    || fail "Redis channel count requires the exact admitted prefix"
  channels=$(redis_noauth PUBSUB CHANNELS "${redis_prefix}*") || return 1
  if [ -z "$channels" ]; then
    printf '0\n'
  else
    printf '%s\n' "$channels" | awk 'END { print NR + 0 }'
  fi
}

cleanup_redis_namespace() {
  [ "$redis_prefix" = "codex-control:" ] || return 1
  redis_noauth EVAL '
local cursor = "0"
local keys = {}
repeat
  local result = redis.call("SCAN", cursor, "MATCH", ARGV[1] .. "*", "COUNT", 1000)
  cursor = result[1]
  for _, key in ipairs(result[2]) do
    keys[#keys + 1] = key
    if #keys > 10000 then
      return redis.error_reply("bootstrap namespace cleanup limit exceeded")
    end
  end
until cursor == "0"
for _, key in ipairs(keys) do
  redis.call("UNLINK", key)
end
return #keys
' 0 "$redis_prefix"
}

probe_secret_read() {
  image=$1
  user=$2
  secret_file=$3
  secret_target=$4
  label=$5
  expected_tuple=$6
  docker run --rm \
    --pull never \
    --network none \
    --read-only \
    --cap-drop ALL \
    --security-opt no-new-privileges \
    --user "$user" \
    --pids-limit 32 \
    --memory 64m \
    --log-driver none \
    --mount "type=bind,src=$secret_file,dst=$secret_target,readonly" \
    --entrypoint /bin/sh \
    "$image" -eu -c '
secret=$1
expected=$2
test -r "$secret"
test ! -w "$secret"
[ "$(stat -c "%u:%g:%a" "$secret")" = "$expected" ]
wc -c < "$secret" >/dev/null
' bootstrap-secret-probe "$secret_target" "$expected_tuple"
  printf '%s=readable\n' "$label"
}

probe_secret_denied() {
  image=$1
  user=$2
  secret_file=$3
  secret_target=$4
  label=$5
  expected_tuple=$6
  docker run --rm \
    --pull never \
    --network none \
    --read-only \
    --cap-drop ALL \
    --security-opt no-new-privileges \
    --user "$user" \
    --pids-limit 32 \
    --memory 64m \
    --log-driver none \
    --mount "type=bind,src=$secret_file,dst=$secret_target,readonly" \
    --entrypoint /bin/sh \
    "$image" -eu -c '
secret=$1
expected=$2
test ! -r "$secret"
test ! -w "$secret"
[ "$(stat -c "%u:%g:%a" "$secret")" = "$expected" ]
' bootstrap-secret-probe "$secret_target" "$expected_tuple"
  printf '%s=denied\n' "$label"
}

drop_bootstrap_database() {
  postgres_psql postgres --quiet --command \
    "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = '$control_database' AND pid <> pg_backend_pid();" \
    >/dev/null 2>&1 || return 1
  postgres_psql postgres --quiet --command \
    "DROP DATABASE IF EXISTS \"$control_database\";" \
    >/dev/null 2>&1 || return 1
  postgres_psql postgres --quiet --command \
    "DROP ROLE IF EXISTS \"$control_role\";" \
    >/dev/null 2>&1 || return 1
}

write_rollback_record() {
  rollback_status=$1
  rollback_detail=$2
  ROLLBACK_STATUS=$rollback_status \
  ROLLBACK_DETAIL=$rollback_detail \
  ROLLBACK_STAGE=$stage \
  ROLLBACK_POSTGRES_PROVISIONED=$postgres_provisioned \
  ROLLBACK_REDIS_NAMESPACE_MUTATED=$redis_namespace_mutated \
  ROLLBACK_REDIS_CLEANUP_COUNT=$redis_cleanup_count \
  ROLLBACK_PWA_NETWORK_REMOVED=$pwa_network_removed \
  ROLLBACK_PUBLIC_CONNECT_EXCEPTION=$allow_sub2api_public_connect \
  ROLLBACK_UNAUTHENTICATED_SMOKE_EXCEPTION=$allow_unauthenticated_smoke \
  ROLLBACK_STALE_BACKUP_EXCEPTION=$stale_backup_exception_enabled \
  ROLLBACK_STALE_BACKUP_EXCEPTION_FILE=$stale_backup_exception_file \
  ROLLBACK_STALE_BACKUP_EXCEPTION_CLAIM=$stale_backup_exception_claim \
  python3 - "$deployment_dir/rollback.json" <<'PY'
import json
import os
import pathlib
import sys
from datetime import UTC, datetime

target = pathlib.Path(sys.argv[1])
exception_file = pathlib.Path(os.environ["ROLLBACK_STALE_BACKUP_EXCEPTION_FILE"])
claim_file = pathlib.Path(os.environ["ROLLBACK_STALE_BACKUP_EXCEPTION_CLAIM"])
record_root = target.parent

def optional_evidence(path: pathlib.Path) -> dict[str, object] | None:
    if not str(path) or not path.is_file():
        return None
    return {
        "path": str(path),
        "sha256": __import__("hashlib").sha256(path.read_bytes()).hexdigest(),
        "size": path.stat().st_size,
    }

value = {
    "format_version": 1,
    "trust_mode": "unsigned-first-deployment-v1",
    "status": os.environ["ROLLBACK_STATUS"],
    "detail": os.environ["ROLLBACK_DETAIL"],
    "failed_stage": os.environ["ROLLBACK_STAGE"],
    "postgres_provisioned": os.environ["ROLLBACK_POSTGRES_PROVISIONED"] == "1",
    "redis_namespace_mutation_attempted": os.environ["ROLLBACK_REDIS_NAMESPACE_MUTATED"] == "1",
    "redis_namespace_cleanup_count": int(os.environ["ROLLBACK_REDIS_CLEANUP_COUNT"]),
    "dedicated_pwa_network_removed": os.environ["ROLLBACK_PWA_NETWORK_REMOVED"] == "1",
    "bootstrap_exceptions": {
        "sub2api_public_connect": os.environ["ROLLBACK_PUBLIC_CONNECT_EXCEPTION"] == "1",
        "unauthenticated_smoke": os.environ["ROLLBACK_UNAUTHENTICATED_SMOKE_EXCEPTION"] == "1",
        "stale_production_backup": os.environ["ROLLBACK_STALE_BACKUP_EXCEPTION"] == "1",
    },
    "stale_production_backup_exception": optional_evidence(exception_file),
    "stale_production_backup_claim": optional_evidence(claim_file),
    "production_backup_admissions": {
        "initial": optional_evidence(record_root / "backup-admission.json"),
        "before_migration": optional_evidence(
            record_root / "backup-admission-before-migration.json"
        ),
        "after_bootstrap": optional_evidence(
            record_root / "backup-admission-after-bootstrap.json"
        ),
    },
    "recorded_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
    "scope": [
        "control-api",
        "control-api-replica",
        "codex-pwa",
        "dedicated PWA network",
        "codex_control database",
        "codex_control role",
    ],
    "sub2api_mutation_attempted": False,
    "redis_mutation_attempted": os.environ["ROLLBACK_REDIS_NAMESPACE_MUTATED"] == "1",
    "redis_acl_or_configuration_mutation_attempted": False,
    "nginx_mutation_attempted": False,
}
temporary = target.with_name(f".{target.name}.tmp-{os.getpid()}")
temporary.write_text(json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
temporary.chmod(0o600)
temporary.replace(target)
PY
}

rollback_bootstrap() {
  rollback_failed=0
  if [ -n "$compose_snapshot" ]; then
    compose rm -sf control-api control-api-replica codex-pwa control-migrate \
      >/dev/null 2>&1 || rollback_failed=1
  fi
  if [ -n "$pwa_network" ] && docker network inspect "$pwa_network" >/dev/null 2>&1; then
    pwa_network_container_count=$(
      docker network inspect "$pwa_network" --format '{{len .Containers}}'
    ) || rollback_failed=1
    if [ "$pwa_network_container_count" = "0" ]; then
      if docker network rm "$pwa_network" >/dev/null 2>&1; then
        pwa_network_removed=1
      else
        rollback_failed=1
      fi
    else
      rollback_failed=1
    fi
  fi
  if [ "$redis_namespace_mutated" = "1" ]; then
    redis_cleanup_result=$(cleanup_redis_namespace) || rollback_failed=1
    case "$redis_cleanup_result" in
      ''|*[!0-9]*) rollback_failed=1 ;;
      *) redis_cleanup_count=$redis_cleanup_result ;;
    esac
  fi
  if [ "$postgres_provisioned" = "1" ]; then
    drop_bootstrap_database || rollback_failed=1
  fi
  if [ "$rollback_failed" = "0" ]; then
    write_rollback_record succeeded \
      "new Control containers, empty dedicated PWA bridge, database, role, and bounded Redis namespace were removed"
  else
    write_rollback_record failed \
      "automatic rollback was incomplete; inspect this private deployment record"
  fi
}

cleanup() {
  status=$?
  trap - EXIT HUP INT TERM
  if [ "$completed" != "1" ] && [ -n "$deployment_dir" ]; then
    if [ "$writes_started" = "1" ]; then
      set +e
      rollback_bootstrap
      set -e
    else
      write_rollback_record not-required "no production mutation was attempted" || :
    fi
    write_status "failed:$stage" || :
  fi
  if [ -n "$lock_dir" ] && [ -d "$lock_dir" ]; then
    rmdir "$lock_dir" 2>/dev/null || :
  fi
  exit "$status"
}

[ "$confirm" = "UNSIGNED_FIRST_DEPLOYMENT_ONLY" ] \
  || fail "set CONTROL_BOOTSTRAP_CONFIRM=UNSIGNED_FIRST_DEPLOYMENT_ONLY"
case "$backup_max_age" in
  ''|*[!0-9]*|0) fail "CONTROL_PRODUCTION_BACKUP_MAX_AGE_SECONDS must be positive" ;;
esac
[ "$backup_max_age" -le 1800 ] \
  || fail "CONTROL_PRODUCTION_BACKUP_MAX_AGE_SECONDS cannot exceed the fresh-backup limit of 1800; use the explicit stale exception file"
case "$wait_timeout" in
  ''|*[!0-9]*|0) fail "CONTROL_DEPLOYMENT_WAIT_TIMEOUT_SECONDS must be positive" ;;
esac
case "$allow_sub2api_public_connect" in
  0|1) ;;
  *) fail "CONTROL_BOOTSTRAP_ALLOW_SUB2API_PUBLIC_CONNECT must be exactly 0 or 1" ;;
esac
case "$allow_unauthenticated_smoke" in
  0|1) ;;
  *) fail "CONTROL_BOOTSTRAP_ALLOW_UNAUTHENTICATED_SMOKE must be exactly 0 or 1" ;;
esac
validate_identifier "$control_role" CONTROL_DB_USER
validate_identifier "$control_database" CONTROL_DB_NAME
validate_identifier "$sub2api_database" SUB2API_DB_NAME
[ "$control_database" != "$sub2api_database" ] \
  || fail "Control and Sub2API database names must differ"
[ -n "$env_file" ] && [ -n "$record_root" ] && [ -n "$backup_result" ] \
  || fail "CONTROL_COMPOSE_ENV_FILE, CONTROL_DEPLOYMENT_RECORD_DIR, and CONTROL_PRODUCTION_BACKUP_RESULT_FILE are required"
[ -n "$database_password_file" ] \
  || fail "CONTROL_DATABASE_PASSWORD_FILE is required for first provisioning"
require_private_file "$env_file" "production Compose environment file"
if [ "$allow_unauthenticated_smoke" = "1" ]; then
  [ -z "$smoke_access_token_file" ] && [ -z "$smoke_expected_user_id" ] \
    || fail "unauthenticated smoke bootstrap must not silently ignore authenticated smoke inputs"
  [ -x "$unauthenticated_smoke_test" ] \
    || fail "unauthenticated bootstrap smoke helper is unavailable"
  authenticated_smoke_pending=1
else
  [ -n "$smoke_access_token_file" ] && [ -n "$smoke_expected_user_id" ] \
    || fail "CONTROL_SMOKE_ACCESS_TOKEN_FILE and CONTROL_SMOKE_EXPECTED_USER_ID are required unless the explicit unauthenticated bootstrap exception is enabled"
  require_private_file "$smoke_access_token_file" "production smoke token file"
fi
[ -r "$versions_lock" ] || fail "versions lock is not readable"
require_immutable_contract_file "$auth_contract" "Sub2API auth contract"
for command_name in docker python3 nginx; do
  command -v "$command_name" >/dev/null 2>&1 || fail "$command_name is required"
done
if [ -n "$stale_backup_exception_source" ]; then
  [ -n "$requested_deployment_id" ] \
    || fail "CONTROL_BOOTSTRAP_DEPLOYMENT_ID is required with a stale production backup exception"
  [ "$(id -u)" = "0" ] \
    || fail "stale production backup exception bootstrap must run as root"
  require_private_file "$stale_backup_exception_source" \
    "stale production backup exception" 1
elif [ -n "$requested_deployment_id" ]; then
  fail "CONTROL_BOOTSTRAP_DEPLOYMENT_ID is reserved for a stale production backup exception"
fi
if [ -n "$requested_deployment_id" ]; then
  deployment_id=$(python3 -c '
import sys, uuid
try:
    value = str(uuid.UUID(sys.argv[1], version=4))
except (ValueError, AttributeError):
    raise SystemExit("CONTROL_BOOTSTRAP_DEPLOYMENT_ID must be one canonical UUIDv4")
if value != sys.argv[1]:
    raise SystemExit("CONTROL_BOOTSTRAP_DEPLOYMENT_ID must be one canonical UUIDv4")
print(value)
' "$requested_deployment_id")
else
  deployment_id=$(python3 -c 'import uuid; print(uuid.uuid4())')
fi
docker compose version >/dev/null 2>&1 || fail "Docker Compose v2 is required"
[ -x "$bootstrap_checks" ] || fail "bootstrap admission helper is unavailable"
[ -x "$runtime_verifier" ] || fail "Sub2API runtime verifier is unavailable"

python3 "$deployment_checks" operator-directory \
  --directory "$record_root" \
  --label "bootstrap deployment record directory" \
  >/dev/null

lock_dir="$record_root/.unsigned-bootstrap.lock"
mkdir "$lock_dir" 2>/dev/null \
  || fail "another unsigned bootstrap is active, or a stale lock needs review"
timestamp=$(date -u '+%Y%m%dT%H%M%SZ')
deployment_dir="$record_root/bootstrap-${timestamp}-${deployment_id}"
mkdir "$deployment_dir"
chmod 0700 "$deployment_dir"
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
write_status "in-progress:$stage"

stage=pin-compose-environment
write_status "in-progress:$stage"
python3 "$deployment_checks" copy-private-file \
  --source "$env_file" \
  --destination "$deployment_dir/compose.env" \
  --label "unsigned bootstrap Compose environment" \
  > "$deployment_dir/compose-env-input.json"
chmod 0600 "$deployment_dir/compose-env-input.json"
env_file="$deployment_dir/compose.env"
if [ -n "$stale_backup_exception_source" ]; then
  stale_backup_exception_file="$deployment_dir/stale-production-backup-exception.json"
  python3 "$deployment_checks" copy-private-file \
    --source "$stale_backup_exception_source" \
    --destination "$stale_backup_exception_file" \
    --label "stale production backup exception" \
    > "$deployment_dir/stale-backup-exception-input.json"
  chmod 0600 "$deployment_dir/stale-backup-exception-input.json"
  stale_backup_exception_enabled=1
fi

stage=resolve-and-admit-compose
write_status "in-progress:$stage"
compose_snapshot="$deployment_dir/compose-config.json"
compose_source config --format json > "$compose_snapshot"
chmod 0400 "$compose_snapshot"
python3 "$bootstrap_checks" compose-plan \
  --compose-config "$compose_snapshot" \
  --repo-root "$repo_root" \
  --expected-backup-user 70:70 \
  > "$deployment_dir/plan.json"
chmod 0600 "$deployment_dir/plan.json"

api_image=$(json_field "$deployment_dir/plan.json" api_image)
pwa_image=$(json_field "$deployment_dir/plan.json" pwa_image)
backup_image=$(json_field "$deployment_dir/plan.json" backup_image)
sub2api_network=$(json_field "$deployment_dir/plan.json" sub2api_network)
pwa_network=$(json_field "$deployment_dir/plan.json" pwa_network)
public_origin=$(json_field "$deployment_dir/plan.json" public_origin)
redis_prefix=$(json_field "$deployment_dir/plan.json" redis_prefix)
backup_user=$(json_field "$deployment_dir/plan.json" backup_user)
compose_db_secret=$(json_field "$deployment_dir/plan.json" secret_files control_db_password)
compose_redis_secret=$(json_field "$deployment_dir/plan.json" secret_files control_redis_password)
compose_session_secret=$(json_field "$deployment_dir/plan.json" secret_files control_session_hmac_secret)
[ "$backup_user" = "70:70" ] \
  || fail "control-backup must use the admitted 70:70 identity"
[ "$compose_db_secret" = "$database_password_file" ] \
  || fail "provisioning database password file differs from the pinned Compose secret"
python3 "$bootstrap_checks" runtime-secrets \
  --database-secret "$compose_db_secret" \
  --redis-secret "$compose_redis_secret" \
  --session-secret "$compose_session_secret" \
  --api-uid "$control_api_uid" \
  --api-gid "$control_api_gid" \
  --backup-uid 70 \
  --parent-uid 0 \
  --parent-gid 0 \
  > "$deployment_dir/runtime-secrets.json"
chmod 0600 "$deployment_dir/runtime-secrets.json"

docker image inspect "$api_image" > "$deployment_dir/api-image-inspect.json"
docker image inspect "$pwa_image" > "$deployment_dir/pwa-image-inspect.json"
docker image inspect "$backup_image" > "$deployment_dir/backup-image-inspect.json"
python3 "$bootstrap_checks" images \
  --plan "$deployment_dir/plan.json" \
  --api-inspect "$deployment_dir/api-image-inspect.json" \
  --pwa-inspect "$deployment_dir/pwa-image-inspect.json" \
  --backup-inspect "$deployment_dir/backup-image-inspect.json" \
  > "$deployment_dir/images.json"
chmod 0600 "$deployment_dir/images.json"

stage=verify-api-image-embedded-contract
write_status "in-progress:$stage"
docker run --rm \
  --pull never \
  --network none \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --user 10001:10001 \
  --pids-limit 32 \
  --memory 64m \
  --log-driver none \
  --entrypoint python \
  "$api_image" -c '
import json

from control_api.config import Settings

names = (
    "appserver_schema_digest",
    "codex_expected_version",
    "sub2api_expected_commit",
    "sub2api_expected_version",
)
values = {name: Settings.model_fields[name].default for name in names}
if any(type(value) is not str or not value for value in values.values()):
    raise SystemExit("API image embedded contract fields are not concrete strings")
print(json.dumps(values, sort_keys=True, separators=(",", ":")))
' > "$deployment_dir/api-image-embedded-contract-observed.json"
chmod 0600 "$deployment_dir/api-image-embedded-contract-observed.json"
python3 "$bootstrap_checks" api-image-contract \
  --observed "$deployment_dir/api-image-embedded-contract-observed.json" \
  --images "$deployment_dir/images.json" \
  --versions-lock "$versions_lock" \
  --expected-image "$api_image" \
  > "$deployment_dir/api-image-embedded-contract.json"
chmod 0600 "$deployment_dir/api-image-embedded-contract.json"

stage=verify-sub2api-before-bootstrap
write_status "in-progress:$stage"
SUB2API_CONTAINER="$sub2api_container" \
VERSIONS_LOCK_FILE="$versions_lock" \
SUB2API_AUTH_CONTRACT_FILE="$auth_contract" \
SUB2API_ATTESTATION_FILE="$deployment_dir/sub2api-before.json" \
SUB2API_EXPECTED_NETWORK="$sub2api_network" \
SUB2API_EXPECTED_NETWORK_ALIAS=sub2api \
SUB2API_REQUIRE_AUTH_EVIDENCE=0 \
  "$runtime_verifier" > "$deployment_dir/sub2api-before.txt"
chmod 0600 "$deployment_dir/sub2api-before.txt"

stage=validate-nginx-and-smoke-input
write_status "in-progress:$stage"
nginx -t > "$deployment_dir/nginx-test.txt" 2>&1
nginx -T > "$deployment_dir/nginx-effective.txt" 2>&1
for expected_nginx_value in '/codex/' '127.0.0.1:18090' '127.0.0.1:18091' '127.0.0.1:18093'; do
  grep -Fq "$expected_nginx_value" "$deployment_dir/nginx-effective.txt" \
    || fail "effective Nginx configuration is missing $expected_nginx_value"
done
if [ "$allow_unauthenticated_smoke" = "1" ]; then
  python3 - "$deployment_dir/smoke-input.json" <<'PY'
import json
import pathlib
import sys

target = pathlib.Path(sys.argv[1])
target.write_text(json.dumps({
    "format_version": 1,
    "mode": "unauthenticated-bootstrap",
    "explicit_exception": True,
    "authenticated_smoke_pending": True,
}, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
target.chmod(0o600)
PY
else
  python3 "$deployment_checks" smoke-input \
    --token-file "$smoke_access_token_file" \
    --expected-user-id "$smoke_expected_user_id" \
    > "$deployment_dir/smoke-input.json"
fi
chmod 0600 "$deployment_dir/smoke-input.json"

stage=verify-production-backup-admission
write_status "in-progress:$stage"
docker container inspect \
  "$sub2api_container" "$postgres_container" "$redis_container" \
  > "$deployment_dir/current-production-identities.json"
admit_production_backup \
  "$deployment_dir/current-production-identities.json" \
  "$deployment_dir/sub2api-before.json" \
  > "$deployment_dir/backup-admission.json"
chmod 0600 "$deployment_dir/backup-admission.json"
if [ "$stale_backup_exception_enabled" = "1" ]; then
  exception_id=$(json_field "$deployment_dir/backup-admission.json" stale_exception exception_id)
  stale_backup_claim_root="$record_root/.stale-backup-exception-claims"
  if ! mkdir "$stale_backup_claim_root" 2>/dev/null; then
    [ -d "$stale_backup_claim_root" ] \
      || fail "stale backup exception claim path is not a directory"
  fi
  chmod 0700 "$stale_backup_claim_root"
  python3 "$deployment_checks" operator-directory \
    --directory "$stale_backup_claim_root" \
    --label "stale backup exception claim directory" \
    >/dev/null
  stale_backup_exception_claim="$stale_backup_claim_root/$exception_id-$deployment_id.json"
  python3 - \
    "$stale_backup_exception_claim" "$exception_id" "$deployment_id" \
    "$deployment_dir/backup-admission.json" \
    "$stale_backup_exception_file" <<'PY'
import hashlib
import json
import os
import pathlib
import sys
from datetime import UTC, datetime

target = pathlib.Path(sys.argv[1])
admission = pathlib.Path(sys.argv[4])
exception = pathlib.Path(sys.argv[5])
value = {
    "schema_version": 1,
    "status": "claimed",
    "type": "stale-production-backup-exception-claim-v1",
    "exception_id": sys.argv[2],
    "deployment_id": sys.argv[3],
    "claimed_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
    "backup_admission_sha256": hashlib.sha256(admission.read_bytes()).hexdigest(),
    "exception_sha256": hashlib.sha256(exception.read_bytes()).hexdigest(),
}
flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
try:
    descriptor = os.open(target, flags, 0o600)
except FileExistsError:
    raise SystemExit("stale production backup exception was already claimed")
try:
    payload = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
    view = memoryview(payload)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise SystemExit("could not persist stale backup exception claim")
        view = view[written:]
    os.fsync(descriptor)
finally:
    os.close(descriptor)
parent = os.open(target.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
try:
    os.fsync(parent)
finally:
    os.close(parent)
PY
  cp "$stale_backup_exception_claim" "$deployment_dir/stale-backup-exception-claim.json"
  chmod 0600 "$deployment_dir/stale-backup-exception-claim.json"
fi

stage=verify-first-deployment-runtime-boundary
write_status "in-progress:$stage"
docker ps -aq --filter "label=com.docker.compose.project=$project" \
  > "$deployment_dir/existing-project-containers.txt"
docker network ls -q --filter "label=com.docker.compose.project=$project" \
  > "$deployment_dir/existing-project-networks.txt"
docker volume ls -q --filter "label=com.docker.compose.project=$project" \
  > "$deployment_dir/existing-project-volumes.txt"
chmod 0600 \
  "$deployment_dir/existing-project-containers.txt" \
  "$deployment_dir/existing-project-networks.txt" \
  "$deployment_dir/existing-project-volumes.txt"
for resource_file in \
  "$deployment_dir/existing-project-containers.txt" \
  "$deployment_dir/existing-project-networks.txt" \
  "$deployment_dir/existing-project-volumes.txt"; do
  [ ! -s "$resource_file" ] \
    || fail "first deployment requires no existing Compose project resources"
done
if docker network inspect "$pwa_network" >/dev/null 2>&1; then
  fail "first deployment requires the dedicated PWA network to be absent"
fi
docker network inspect "$sub2api_network" \
  > "$deployment_dir/sub2api-network-inspect.json"
python3 - \
  "$deployment_dir/current-production-identities.json" \
  "$deployment_dir/sub2api-network-inspect.json" \
  "$sub2api_container" "$postgres_container" "$redis_container" \
  "$sub2api_network" "$pwa_network" \
  > "$deployment_dir/first-deployment-runtime-boundary.json" <<'PY'
import json
import socket
import sys

containers = json.load(open(sys.argv[1], encoding="utf-8"))
networks = json.load(open(sys.argv[2], encoding="utf-8"))
names = tuple(sys.argv[3:6])
network_name = sys.argv[6]
pwa_network = sys.argv[7]
if not isinstance(containers, list) or len(containers) != 3:
    raise SystemExit("production container evidence is incomplete")
by_name = {item.get("Name", "").removeprefix("/"): item for item in containers}
if set(by_name) != set(names):
    raise SystemExit("production container identity set is unexpected")
aliases = {
    names[0]: "sub2api",
    names[1]: "postgres",
    names[2]: "redis",
}
container_ids = set()
for name, alias in aliases.items():
    item = by_name[name]
    if item.get("State", {}).get("Running") is not True:
        raise SystemExit(f"{name} is not running")
    container_id = item.get("Id")
    if not isinstance(container_id, str) or len(container_id) != 64:
        raise SystemExit(f"{name} has an invalid container ID")
    container_ids.add(container_id)
    attachment = item.get("NetworkSettings", {}).get("Networks", {}).get(network_name)
    if not isinstance(attachment, dict) or alias not in (attachment.get("Aliases") or []):
        raise SystemExit(f"{name} is missing the required {alias} network alias")
if not isinstance(networks, list) or len(networks) != 1:
    raise SystemExit("external Sub2API network evidence is invalid")
network = networks[0]
if (
    network.get("Name") != network_name
    or network.get("Driver") != "bridge"
    or network.get("Internal") is not False
):
    raise SystemExit("external Sub2API network has an unexpected boundary")
attached = set((network.get("Containers") or {}).keys())
if not container_ids.issubset(attached):
    raise SystemExit("one production container is absent from the external network")

sockets = []
try:
    for port in (18090, 18091, 18093):
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("127.0.0.1", port))
        sockets.append(listener)
except OSError as exc:
    raise SystemExit(f"one admitted loopback port is unavailable: {exc}") from exc
finally:
    for listener in sockets:
        listener.close()

print(json.dumps({
    "format_version": 1,
    "status": "admitted",
    "compose_project_resources": {"containers": 0, "networks": 0, "volumes": 0},
    "external_network": network_name,
    "absent_dedicated_pwa_network": pwa_network,
    "aliases": aliases,
    "available_loopback_ports": [18090, 18091, 18093],
}, sort_keys=True, separators=(",", ":")))
PY
chmod 0600 "$deployment_dir/first-deployment-runtime-boundary.json"

stage=verify-tools-and-runtime-secret-access
write_status "in-progress:$stage"
server_version_num=$(postgres_psql postgres --quiet --tuples-only --no-align \
  --command "SHOW server_version_num;")
pg_dump_version=$(docker run --rm --pull never --network none --read-only \
  --cap-drop ALL --security-opt no-new-privileges --pids-limit 32 --memory 64m \
  --log-driver none --entrypoint pg_dump "$backup_image" --version)
pg_restore_version=$(docker run --rm --pull never --network none --read-only \
  --cap-drop ALL --security-opt no-new-privileges --pids-limit 32 --memory 64m \
  --log-driver none --entrypoint pg_restore "$backup_image" --version)
python3 - "$server_version_num" "$pg_dump_version" "$pg_restore_version" \
  > "$deployment_dir/postgres-tools-version.json" <<'PY'
import json
import re
import sys

server = sys.argv[1].strip()
if re.fullmatch(r"[0-9]+", server) is None:
    raise SystemExit("live PostgreSQL version number is invalid")
server_major = int(server) // 10000
versions = {}
for name, value in (("pg_dump", sys.argv[2]), ("pg_restore", sys.argv[3])):
    match = re.search(r"\b([0-9]+)(?:\.[0-9]+)*\b", value)
    if match is None:
        raise SystemExit(f"{name} version output is invalid")
    versions[name] = {"output": value, "major": int(match.group(1))}
    if versions[name]["major"] != server_major:
        raise SystemExit(f"{name} major does not match live PostgreSQL")
print(json.dumps({
    "format_version": 1,
    "status": "admitted",
    "server_version_num": server,
    "server_major": server_major,
    "tools": versions,
}, sort_keys=True, separators=(",", ":")))
PY
chmod 0600 "$deployment_dir/postgres-tools-version.json"
{
  probe_secret_read "$api_image" "$control_api_uid:$control_api_gid" \
    "$compose_db_secret" /run/secrets/control_db_password \
    api_database_secret "70:$control_api_gid:440"
  probe_secret_read "$api_image" "$control_api_uid:$control_api_gid" \
    "$compose_redis_secret" /run/secrets/control_redis_password api_redis_secret \
    "$control_api_uid:$control_api_gid:400"
  probe_secret_read "$api_image" "$control_api_uid:$control_api_gid" \
    "$compose_session_secret" /run/secrets/control_session_hmac_secret \
    api_session_secret \
    "$control_api_uid:$control_api_gid:400"
  probe_secret_read "$backup_image" "$backup_user" \
    "$compose_db_secret" /run/secrets/control_db_password \
    backup_database_secret "70:$control_api_gid:440"
  probe_secret_denied "$backup_image" "$backup_user" \
    "$compose_redis_secret" /run/secrets/control_redis_password \
    backup_redis_secret \
    "$control_api_uid:$control_api_gid:400"
  probe_secret_denied "$backup_image" "$backup_user" \
    "$compose_session_secret" /run/secrets/control_session_hmac_secret \
    backup_session_secret \
    "$control_api_uid:$control_api_gid:400"
} > "$deployment_dir/runtime-secret-probe.txt" 2>&1
chmod 0600 "$deployment_dir/runtime-secret-probe.txt"

stage=verify-pristine-target-and-redis
write_status "in-progress:$stage"
before_state=$(postgres_psql postgres --quiet --tuples-only --no-align \
  --field-separator='|' --command \
  "SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '$control_role'), EXISTS (SELECT 1 FROM pg_database WHERE datname = '$control_database'), EXISTS (SELECT 1 FROM pg_database AS database CROSS JOIN LATERAL aclexplode(COALESCE(database.datacl, acldefault('d', database.datdba))) AS privilege WHERE database.datname = '$sub2api_database' AND privilege.grantee = 0 AND privilege.privilege_type = 'CONNECT');")
postgres_psql postgres --quiet --tuples-only --no-align --command \
  "SELECT COALESCE(datacl::text, 'NULL') FROM pg_database WHERE datname = '$sub2api_database';" \
  > "$deployment_dir/sub2api-database-acl-before.txt"
chmod 0600 "$deployment_dir/sub2api-database-acl-before.txt"
case "$before_state" in
  'f|f|f')
    [ "$allow_sub2api_public_connect" = "0" ] \
      || fail "PUBLIC CONNECT exception was enabled but the live database does not require it"
    sub2api_public_connect=false
    ;;
  'f|f|t')
    [ "$allow_sub2api_public_connect" = "1" ] \
      || fail "live Sub2API grants PUBLIC CONNECT; set CONTROL_BOOTSTRAP_ALLOW_SUB2API_PUBLIC_CONNECT=1 only for this one bootstrap"
    sub2api_public_connect=true
    ;;
  *)
    fail "first deployment requires an absent Control role and database"
    ;;
esac

redis_noauth ACL GETUSER default \
  > "$deployment_dir/redis-default-acl-before.txt"
chmod 0600 "$deployment_dir/redis-default-acl-before.txt"
for required_rule in on nopass '~*' '&*' '+@all'; do
  grep -Fxq "$required_rule" "$deployment_dir/redis-default-acl-before.txt" \
    || fail "existing Redis default user does not match the explicit nopass bootstrap contract"
done
[ "$(redis_noauth PING)" = "PONG" ] \
  || fail "existing unauthenticated Redis default user is not usable"
redis_key_count=$(redis_namespace_count)
redis_channel_count=$(redis_namespace_channel_count)
[ "$redis_key_count" = "0" ] && [ "$redis_channel_count" = "0" ] \
  || fail "first deployment requires an empty Control Redis namespace"
python3 - "$redis_prefix" "$redis_key_count" "$redis_channel_count" \
  > "$deployment_dir/redis-namespace-before.json" <<'PY'
import json
import sys

if sys.argv[1] != "codex-control:" or sys.argv[2:] != ["0", "0"]:
    raise SystemExit("Redis namespace baseline is not empty and admitted")
print(json.dumps({
    "format_version": 1,
    "status": "admitted",
    "prefix": sys.argv[1],
    "keys": 0,
    "channels": 0,
    "acl_or_configuration_mutation_allowed": False,
    "namespace_mutation_allowed_after_sidecar_start": True,
}, sort_keys=True, separators=(",", ":")))
PY
chmod 0600 "$deployment_dir/redis-namespace-before.json"

python3 - "$deployment_dir/rollback-plan.json" \
  "$deployment_dir/backup-admission.json" "$deployment_dir/plan.json" \
  "$control_database" "$control_role" "$sub2api_public_connect" \
  "$allow_unauthenticated_smoke" \
  "$deployment_dir/stale-backup-exception-claim.json" <<'PY'
import hashlib
import json
import pathlib
import sys
from datetime import UTC, datetime

target = pathlib.Path(sys.argv[1])
backup_path = pathlib.Path(sys.argv[2])
plan_path = pathlib.Path(sys.argv[3])
database = sys.argv[4]
role = sys.argv[5]
claim_path = pathlib.Path(sys.argv[8])

def digest(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()

def optional_evidence(path: pathlib.Path) -> dict[str, object] | None:
    if not path.is_file():
        return None
    return {"path": str(path), "sha256": digest(path), "size": path.stat().st_size}

backup = json.loads(backup_path.read_text(encoding="utf-8"))

value = {
    "format_version": 1,
    "trust_mode": "unsigned-first-deployment-v1",
    "created_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
    "verified_production_backup": {
        "path": str(backup_path),
        "sha256": digest(backup_path),
        "fresh": backup["fresh"],
        "admission_mode": backup["admission_mode"],
        "stale_exception": backup["stale_exception"],
    },
    "stale_production_backup_claim": optional_evidence(claim_path),
    "admitted_plan": {"path": str(plan_path), "sha256": digest(plan_path)},
    "new_resources": {
        "database": database,
        "role": role,
        "services": ["control-api", "control-api-replica", "codex-pwa"],
    },
    "rollback_policy": "remove-only-new-control-resources-and-bounded-redis-namespace",
    "bootstrap_exceptions": {
        "sub2api_public_connect": sys.argv[6] == "true",
        "unauthenticated_smoke": sys.argv[7] == "1",
        "authenticated_smoke_pending": sys.argv[7] == "1",
        "stale_production_backup": backup["stale_exception"] is not None,
    },
    "sub2api_mutation_allowed": False,
    "redis_namespace_mutation_allowed": True,
    "redis_acl_or_configuration_mutation_allowed": False,
    "nginx_mutation_allowed": False,
}
target.write_text(
    json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n",
    encoding="utf-8",
)
target.chmod(0o600)
PY

stage=provision-control-postgres
write_status "in-progress:$stage"
control_password=$(tr -d '\r\n' < "$database_password_file")
case "$control_password" in
  ''|*[!A-Za-z0-9._~+-]*) fail "Control database password is not bootstrap-safe" ;;
esac
writes_started=1
postgres_provisioned=1
{
  printf "\\set control_password '%s'\n" "$control_password"
  cat "$bootstrap_sql"
} | postgres_psql postgres \
  --set "control_role=$control_role" \
  --set "control_database=$control_database" \
  --file - \
  > "$deployment_dir/postgres-provision.txt"
unset control_password
chmod 0600 "$deployment_dir/postgres-provision.txt"

post_state=$(postgres_psql postgres --quiet --tuples-only --no-align \
  --field-separator='|' --command \
  "SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '$control_role'), EXISTS (SELECT 1 FROM pg_database WHERE datname = '$control_database'), (SELECT count(*) FROM pg_auth_members AS membership JOIN pg_roles AS member_role ON member_role.oid = membership.member JOIN pg_roles AS granted_role ON granted_role.oid = membership.roleid WHERE member_role.rolname = '$control_role' OR granted_role.rolname = '$control_role'), (SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname = '$control_database'), EXISTS (SELECT 1 FROM pg_database AS database CROSS JOIN LATERAL aclexplode(COALESCE(database.datacl, acldefault('d', database.datdba))) AS privilege WHERE database.datname = '$sub2api_database' AND privilege.grantee = 0 AND privilege.privilege_type = 'CONNECT');")

sub2api_privilege_state=$(postgres_psql "$sub2api_database" --quiet --tuples-only --no-align \
  --field-separator='|' --command \
  "WITH target_role AS (SELECT oid FROM pg_roles WHERE rolname = '$control_role') SELECT (SELECT count(*) FROM pg_database AS database CROSS JOIN target_role AS target CROSS JOIN LATERAL aclexplode(database.datacl) AS privilege WHERE database.datname = '$sub2api_database' AND privilege.grantee = target.oid), (SELECT count(*) FROM pg_namespace AS namespace CROSS JOIN target_role AS target CROSS JOIN LATERAL aclexplode(namespace.nspacl) AS privilege WHERE namespace.nspname !~ '^pg_' AND namespace.nspname <> 'information_schema' AND privilege.grantee = target.oid), (SELECT count(*) FROM pg_class AS class JOIN pg_namespace AS namespace ON namespace.oid = class.relnamespace CROSS JOIN target_role AS target CROSS JOIN LATERAL aclexplode(class.relacl) AS privilege WHERE namespace.nspname !~ '^pg_' AND namespace.nspname <> 'information_schema' AND privilege.grantee = target.oid), (SELECT count(*) FROM pg_namespace AS namespace CROSS JOIN target_role AS target WHERE namespace.nspname !~ '^pg_' AND namespace.nspname <> 'information_schema' AND namespace.nspowner = target.oid), (SELECT count(*) FROM pg_class AS class JOIN pg_namespace AS namespace ON namespace.oid = class.relnamespace CROSS JOIN target_role AS target WHERE namespace.nspname !~ '^pg_' AND namespace.nspname <> 'information_schema' AND class.relowner = target.oid), (SELECT count(*) FROM pg_class AS class JOIN pg_namespace AS namespace ON namespace.oid = class.relnamespace WHERE namespace.nspname !~ '^pg_' AND namespace.nspname <> 'information_schema' AND CASE WHEN class.relkind IN ('r','p','v','m','f') THEN has_table_privilege('$control_role', class.oid, 'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') ELSE false END), (SELECT count(*) FROM pg_class AS class JOIN pg_namespace AS namespace ON namespace.oid = class.relnamespace WHERE namespace.nspname !~ '^pg_' AND namespace.nspname <> 'information_schema' AND CASE WHEN class.relkind = 'S' THEN has_sequence_privilege('$control_role', class.oid, 'SELECT,USAGE,UPDATE') ELSE false END), (SELECT count(*) FROM pg_namespace AS namespace WHERE namespace.nspname !~ '^pg_' AND namespace.nspname <> 'information_schema' AND has_schema_privilege('$control_role', namespace.oid, 'CREATE')); ")
postgres_psql postgres --quiet --tuples-only --no-align --command \
  "SELECT COALESCE(datacl::text, 'NULL') FROM pg_database WHERE datname = '$sub2api_database';" \
  > "$deployment_dir/sub2api-database-acl-after.txt"
chmod 0600 "$deployment_dir/sub2api-database-acl-after.txt"
printf 'before=%s\npost=%s\nsub2api_privileges=%s\n' \
  "$before_state" "$post_state" "$sub2api_privilege_state" \
  > "$deployment_dir/postgres-boundary-raw.txt"
chmod 0600 "$deployment_dir/postgres-boundary-raw.txt"

python3 - "$deployment_dir/postgres-boundary-evidence.json" \
  "$control_database" "$control_role" "$sub2api_database" \
  "$sub2api_public_connect" "$allow_sub2api_public_connect" \
  "$post_state" "$sub2api_privilege_state" \
  "$deployment_dir/sub2api-database-acl-before.txt" \
  "$deployment_dir/sub2api-database-acl-after.txt" <<'PY'
import hashlib
import json
import pathlib
import sys

target = pathlib.Path(sys.argv[1])
post = sys.argv[7].split("|")
privileges = sys.argv[8].split("|")
if len(post) != 5 or len(privileges) != 8:
    raise SystemExit("PostgreSQL boundary evidence has unexpected fields")

def digest(path: str) -> str:
    return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()

names = (
    "direct_database_acl_privileges",
    "direct_schema_acl_privileges",
    "direct_relation_acl_privileges",
    "owned_schemas",
    "owned_relations",
    "effective_relation_privileges",
    "effective_sequence_privileges",
    "effective_schema_create_privileges",
)
try:
    counts = {name: int(value) for name, value in zip(names, privileges, strict=True)}
except ValueError as exc:
    raise SystemExit("PostgreSQL privilege evidence is not numeric") from exc
public_connect = sys.argv[5] == "true"
value = {
    "schema_version": 1,
    "database": sys.argv[2],
    "role": sys.argv[3],
    "sub2api_database": sys.argv[4],
    "allow_sub2api_public_connect": sys.argv[6] == "1",
    "before": {
        "database_exists": False,
        "role_exists": False,
        "sub2api_public_connect": public_connect,
        "sub2api_database_acl_sha256": digest(sys.argv[9]),
    },
    "after": {
        "database_exists": post[0] == "t",
        "role_exists": post[1] == "t",
        "role_memberships": int(post[2]),
        "database_owner": post[3],
        "sub2api_public_connect": post[4] == "t",
        "sub2api_database_acl_sha256": digest(sys.argv[10]),
        **counts,
    },
}
target.write_text(json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
target.chmod(0o600)
PY
python3 "$bootstrap_checks" postgres-boundary \
  --evidence "$deployment_dir/postgres-boundary-evidence.json" \
  > "$deployment_dir/postgres-boundary-admission.json"
chmod 0600 "$deployment_dir/postgres-boundary-admission.json"

stage=prove-pristine-control-database
write_status "in-progress:$stage"
postgres_psql "$control_database" --quiet --tuples-only --no-align --command \
  "SELECT json_build_object('alembic_version_exists', to_regclass('public.alembic_version') IS NOT NULL, 'tables', COALESCE((SELECT json_agg(class.relname ORDER BY class.relname) FROM pg_class AS class JOIN pg_namespace AS namespace ON namespace.oid = class.relnamespace WHERE namespace.nspname = 'public' AND class.relkind IN ('r','p')), '[]'::json), 'views', COALESCE((SELECT json_agg(class.relname ORDER BY class.relname) FROM pg_class AS class JOIN pg_namespace AS namespace ON namespace.oid = class.relnamespace WHERE namespace.nspname = 'public' AND class.relkind IN ('v','m')), '[]'::json), 'sequences', COALESCE((SELECT json_agg(class.relname ORDER BY class.relname) FROM pg_class AS class JOIN pg_namespace AS namespace ON namespace.oid = class.relnamespace WHERE namespace.nspname = 'public' AND class.relkind = 'S'), '[]'::json));" \
  > "$deployment_dir/pristine-objects.json"

compose run --rm --no-deps --pull never control-api \
  /opt/venv/bin/alembic -c /app/migrations/alembic.ini heads \
  > "$deployment_dir/alembic-head.txt"
target_head=$(python3 -c '
import re, sys
lines = [line.strip() for line in open(sys.argv[1], encoding="utf-8") if line.strip()]
values = []
for line in lines:
    token = line.split(maxsplit=1)[0]
    if re.fullmatch(r"[0-9A-Za-z][0-9A-Za-z_]{0,127}", token):
        values.append(token)
values = list(dict.fromkeys(values))
if len(values) != 1:
    raise SystemExit("packaged migration set did not expose exactly one head")
print(values[0])
' "$deployment_dir/alembic-head.txt")

python3 - "$deployment_dir/pristine-objects.json" \
  "$deployment_dir/pristine-db-evidence.json" \
  "$control_database" "$control_role" "$target_head" <<'PY'
import json
import pathlib
import sys

objects = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
value = {
    "schema_version": 1,
    "database": sys.argv[3],
    "role": sys.argv[4],
    "before": {"database_exists": False, "role_exists": False},
    "after": {
        "database_exists": True,
        "role_exists": True,
        **objects,
    },
    "target_migration_head": sys.argv[5],
}
target = pathlib.Path(sys.argv[2])
target.write_text(json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
target.chmod(0o600)
PY
python3 "$bootstrap_checks" pristine-db \
  --evidence "$deployment_dir/pristine-db-evidence.json" \
  > "$deployment_dir/pristine-db-admission.json"
chmod 0600 "$deployment_dir/pristine-db-admission.json"

stage=recheck-before-migration
write_status "in-progress:$stage"
docker container inspect \
  "$sub2api_container" "$postgres_container" "$redis_container" \
  > "$deployment_dir/current-production-identities-before-migration.json"
SUB2API_CONTAINER="$sub2api_container" \
VERSIONS_LOCK_FILE="$versions_lock" \
SUB2API_AUTH_CONTRACT_FILE="$auth_contract" \
SUB2API_ATTESTATION_FILE="$deployment_dir/sub2api-before-migration.json" \
SUB2API_EXPECTED_NETWORK="$sub2api_network" \
SUB2API_EXPECTED_NETWORK_ALIAS=sub2api \
SUB2API_REQUIRE_AUTH_EVIDENCE=0 \
  "$runtime_verifier" > "$deployment_dir/sub2api-before-migration.txt"

python3 - "$deployment_dir/sub2api-before.json" \
  "$deployment_dir/sub2api-before-migration.json" <<'PY'
import json
import sys

first = json.load(open(sys.argv[1], encoding="utf-8"))
second = json.load(open(sys.argv[2], encoding="utf-8"))
fields = (
    "container_id", "image_id", "image_digest", "binary_sha256",
    "runtime_version", "runtime_commit", "runtime_built_at",
    "contract_sha256", "network", "network_alias",
)
changed = [field for field in fields if first.get(field) != second.get(field)]
if changed:
    raise SystemExit(f"Sub2API changed before migration: {changed}")
PY
admit_production_backup \
  "$deployment_dir/current-production-identities-before-migration.json" \
  "$deployment_dir/sub2api-before-migration.json" \
  > "$deployment_dir/backup-admission-before-migration.json"
python3 - "$deployment_dir/backup-admission.json" \
  "$deployment_dir/backup-admission-before-migration.json" <<'PY'
import json
import sys

first = json.load(open(sys.argv[1], encoding="utf-8"))
second = json.load(open(sys.argv[2], encoding="utf-8"))
fields = ("admission_binding_sha256",)
changed = [field for field in fields if first.get(field) != second.get(field)]
if changed:
    raise SystemExit(f"production backup identity changed before migration: {changed}")
PY

stage=migrate-pristine-database
write_status "in-progress:$stage"
compose run --rm --no-deps --pull never control-migrate \
  > "$deployment_dir/migration.txt" 2>&1
compose run --rm --no-deps --pull never control-api \
  /opt/venv/bin/alembic -c /app/migrations/alembic.ini current \
  > "$deployment_dir/alembic-current-after.txt"
python3 "$deployment_checks" revisions \
  --current "$deployment_dir/alembic-current-after.txt" \
  --head "$deployment_dir/alembic-head.txt" \
  --require-current-head \
  > "$deployment_dir/revisions-after-migration.json"
chmod 0600 "$deployment_dir/revisions-after-migration.json"

stage=start-sidecars
write_status "in-progress:$stage"
redis_namespace_mutated=1
compose up -d \
  --no-build \
  --no-deps \
  --pull never \
  --force-recreate \
  --wait \
  --wait-timeout "$wait_timeout" \
  control-api control-api-replica codex-pwa

api_container=$(compose ps --status running -q control-api)
api_replica_container=$(compose ps --status running -q control-api-replica)
pwa_container=$(compose ps --status running -q codex-pwa)
[ -n "$api_container" ] && [ -n "$api_replica_container" ] && [ -n "$pwa_container" ] \
  || fail "one or more unsigned bootstrap sidecars are not running"
docker container inspect "$api_container" > "$deployment_dir/api-container-inspect.json"
docker container inspect "$api_replica_container" > "$deployment_dir/api-replica-container-inspect.json"
docker container inspect "$pwa_container" > "$deployment_dir/pwa-container-inspect.json"
docker network inspect "$pwa_network" > "$deployment_dir/pwa-network-inspect.json"
chmod 0600 \
  "$deployment_dir/api-container-inspect.json" \
  "$deployment_dir/api-replica-container-inspect.json" \
  "$deployment_dir/pwa-container-inspect.json" \
  "$deployment_dir/pwa-network-inspect.json"

python3 "$bootstrap_checks" running \
  --plan "$deployment_dir/plan.json" \
  --images "$deployment_dir/images.json" \
  --api-inspect "$deployment_dir/api-container-inspect.json" \
  --api-replica-inspect "$deployment_dir/api-replica-container-inspect.json" \
  --pwa-inspect "$deployment_dir/pwa-container-inspect.json" \
  --pwa-network-inspect "$deployment_dir/pwa-network-inspect.json" \
  > "$deployment_dir/running-containers.json"
chmod 0600 "$deployment_dir/running-containers.json"

stage=wait-host-loopback-routes
write_status "in-progress:$stage"
python3 - "$deployment_dir/host-loopback-readiness.json" "$wait_timeout" <<'PY'
import http.client
import json
import pathlib
import sys
import time

target = pathlib.Path(sys.argv[1])
timeout = int(sys.argv[2])
routes = (
    ("control-api", 18090, "/v1/health/ready"),
    ("control-api-replica", 18093, "/v1/health/ready"),
    ("codex-pwa", 18091, "/healthz"),
)
deadline = time.monotonic() + timeout
attempts = 0
observed = {}

while time.monotonic() < deadline:
    attempts += 1
    observed = {}
    ready = True
    for name, port, path in routes:
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
        try:
            connection.request("GET", path, headers={"Connection": "close"})
            response = connection.getresponse()
            body = response.read(65537)
            if response.status != 200 or len(body) > 65536:
                ready = False
            observed[name] = {
                "body_bytes": len(body),
                "path": path,
                "port": port,
                "status": response.status,
            }
        except (OSError, http.client.HTTPException) as exc:
            ready = False
            observed[name] = {
                "error": f"{type(exc).__name__}: {exc}"[:512],
                "path": path,
                "port": port,
            }
        finally:
            connection.close()
    if ready:
        result = {
            "attempts": attempts,
            "format_version": 1,
            "routes": observed,
            "status": "ready",
        }
        break
    time.sleep(0.25)
else:
    result = {
        "attempts": attempts,
        "format_version": 1,
        "routes": observed,
        "status": "timeout",
    }

target.write_text(
    json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n",
    encoding="utf-8",
)
target.chmod(0o600)
if result["status"] != "ready":
    raise SystemExit("host loopback routes did not become ready before public smoke")
PY
chmod 0600 "$deployment_dir/host-loopback-readiness.json"

stage=production-smoke
write_status "in-progress:$stage"
if [ "$allow_unauthenticated_smoke" = "1" ]; then
  python3 "$unauthenticated_smoke_test" \
    --base-url "$public_origin" \
    > "$deployment_dir/production-smoke.txt" 2>&1
else
  python3 "$smoke_test" \
    --base-url "$public_origin" \
    --access-token-file "$smoke_access_token_file" \
    --expected-user-id "$smoke_expected_user_id" \
    --expect-secure-cookie \
    > "$deployment_dir/production-smoke.txt" 2>&1
fi
chmod 0600 "$deployment_dir/production-smoke.txt"

stage=verify-sub2api-after-bootstrap
write_status "in-progress:$stage"
SUB2API_CONTAINER="$sub2api_container" \
VERSIONS_LOCK_FILE="$versions_lock" \
SUB2API_AUTH_CONTRACT_FILE="$auth_contract" \
SUB2API_ATTESTATION_FILE="$deployment_dir/sub2api-after.json" \
SUB2API_EXPECTED_NETWORK="$sub2api_network" \
SUB2API_EXPECTED_NETWORK_ALIAS=sub2api \
SUB2API_REQUIRE_AUTH_EVIDENCE=0 \
  "$runtime_verifier" > "$deployment_dir/sub2api-after.txt"
python3 - "$deployment_dir/sub2api-before.json" \
  "$deployment_dir/sub2api-after.json" <<'PY'
import json
import sys

first = json.load(open(sys.argv[1], encoding="utf-8"))
second = json.load(open(sys.argv[2], encoding="utf-8"))
fields = (
    "container_id", "image_id", "image_digest", "binary_sha256",
    "runtime_version", "runtime_commit", "runtime_built_at",
    "contract_sha256", "network", "network_alias",
)
changed = [field for field in fields if first.get(field) != second.get(field)]
if changed:
    raise SystemExit(f"Sub2API changed during unsigned bootstrap: {changed}")
PY

stage=revalidate-production-boundary-after-bootstrap
write_status "in-progress:$stage"
docker container inspect \
  "$sub2api_container" "$postgres_container" "$redis_container" \
  > "$deployment_dir/current-production-identities-after-bootstrap.json"
admit_production_backup \
  "$deployment_dir/current-production-identities-after-bootstrap.json" \
  "$deployment_dir/sub2api-after.json" \
  > "$deployment_dir/backup-admission-after-bootstrap.json"
python3 - "$deployment_dir/backup-admission.json" \
  "$deployment_dir/backup-admission-after-bootstrap.json" <<'PY'
import json
import sys

first = json.load(open(sys.argv[1], encoding="utf-8"))
second = json.load(open(sys.argv[2], encoding="utf-8"))
fields = ("admission_binding_sha256",)
changed = [field for field in fields if first.get(field) != second.get(field)]
if changed:
    raise SystemExit(f"production backup identity changed after bootstrap: {changed}")
PY
redis_noauth ACL GETUSER default \
  > "$deployment_dir/redis-default-acl-after.txt"
chmod 0600 "$deployment_dir/redis-default-acl-after.txt"
cmp "$deployment_dir/redis-default-acl-before.txt" \
  "$deployment_dir/redis-default-acl-after.txt" \
  || fail "Redis default ACL changed during unsigned bootstrap"
redis_key_count_after=$(redis_namespace_count)
redis_channel_count_after=$(redis_namespace_channel_count)
python3 - "$redis_prefix" "$redis_key_count_after" "$redis_channel_count_after" \
  > "$deployment_dir/production-boundary-after-bootstrap.json" <<'PY'
import json
import sys

try:
    keys = int(sys.argv[2])
    channels = int(sys.argv[3])
except ValueError as exc:
    raise SystemExit("Redis namespace evidence is not numeric") from exc
if sys.argv[1] != "codex-control:" or keys < 0 or keys > 10000 or channels < 0:
    raise SystemExit("Redis namespace after bootstrap is outside the admitted boundary")
print(json.dumps({
    "format_version": 1,
    "status": "admitted",
    "production_container_identities_revalidated": True,
    "redis_default_acl_unchanged": True,
    "redis_prefix": sys.argv[1],
    "redis_namespace_keys": keys,
    "redis_namespace_channels": channels,
    "redis_acl_or_configuration_mutation_attempted": False,
}, sort_keys=True, separators=(",", ":")))
PY
chmod 0600 \
  "$deployment_dir/backup-admission-after-bootstrap.json" \
  "$deployment_dir/production-boundary-after-bootstrap.json"

stage=record-success
write_status "in-progress:$stage"
DEPLOYMENT_DIR="$deployment_dir" \
AUTHENTICATED_SMOKE_PENDING="$authenticated_smoke_pending" \
ALLOW_SUB2API_PUBLIC_CONNECT="$allow_sub2api_public_connect" \
ALLOW_UNAUTHENTICATED_SMOKE="$allow_unauthenticated_smoke" \
python3 - "$deployment_dir/bootstrap-deployment.json" <<'PY'
import hashlib
import json
import os
import pathlib
import sys
from datetime import UTC, datetime

root = pathlib.Path(os.environ["DEPLOYMENT_DIR"])

def evidence(name: str) -> dict[str, object]:
    path = root / name
    return {
        "path": str(path),
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "size": path.stat().st_size,
    }

backup_admissions = {
    name: json.loads((root / filename).read_text(encoding="utf-8"))
    for name, filename in {
        "initial": "backup-admission.json",
        "before_migration": "backup-admission-before-migration.json",
        "after_bootstrap": "backup-admission-after-bootstrap.json",
    }.items()
}
stale_exceptions = [item["stale_exception"] for item in backup_admissions.values()]
if stale_exceptions[1:] != stale_exceptions[:-1]:
    raise SystemExit("stale production backup exception changed across validation stages")

evidence_files = {
    "production_backup": "backup-admission.json",
    "production_backup_before_migration": "backup-admission-before-migration.json",
    "production_backup_after": "backup-admission-after-bootstrap.json",
    "compose_plan": "plan.json",
    "local_images": "images.json",
    "api_image_embedded_contract_observed": "api-image-embedded-contract-observed.json",
    "api_image_embedded_contract": "api-image-embedded-contract.json",
    "runtime_secrets": "runtime-secrets.json",
    "runtime_secret_probe": "runtime-secret-probe.txt",
    "first_deployment_runtime_boundary": "first-deployment-runtime-boundary.json",
    "postgres_tools_version": "postgres-tools-version.json",
    "redis_namespace_before": "redis-namespace-before.json",
    "pristine_database": "pristine-db-admission.json",
    "postgres_boundary": "postgres-boundary-admission.json",
    "migration": "revisions-after-migration.json",
    "running_containers": "running-containers.json",
    "production_smoke": "production-smoke.txt",
    "sub2api_before": "sub2api-before.json",
    "sub2api_after": "sub2api-after.json",
    "production_boundary_after": "production-boundary-after-bootstrap.json",
    "rollback_plan": "rollback-plan.json",
}
if stale_exceptions[0] is not None:
    evidence_files.update({
        "stale_backup_exception": "stale-production-backup-exception.json",
        "stale_backup_exception_input": "stale-backup-exception-input.json",
        "stale_backup_exception_claim": "stale-backup-exception-claim.json",
    })

value = {
    "format_version": 1,
    "status": "bootstrapped-unsigned",
    "trust_mode": "unsigned-first-deployment-v1",
    "recorded_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
    "signed_release_verified": False,
    "authenticated_smoke_pending": os.environ["AUTHENTICATED_SMOKE_PENDING"] == "1",
    "bootstrap_exceptions": {
        "sub2api_public_connect": os.environ["ALLOW_SUB2API_PUBLIC_CONNECT"] == "1",
        "unauthenticated_smoke": os.environ["ALLOW_UNAUTHENTICATED_SMOKE"] == "1",
        "stale_production_backup": stale_exceptions[0] is not None,
    },
    "production_backup_admissions": {
        name: {
            "admission_binding_sha256": admission["admission_binding_sha256"],
            "admission_mode": admission["admission_mode"],
            "fresh": admission["fresh"],
            "manifest_sha256": admission["manifest_sha256"],
            "snapshot_directory": admission["snapshot_directory"],
            "stale_exception": admission["stale_exception"],
        }
        for name, admission in backup_admissions.items()
    },
    "verified_evidence": {
        name: evidence(filename)
        for name, filename in evidence_files.items()
    },
    "normal_signed_deployment_required_for_next_release": True,
}
target = pathlib.Path(sys.argv[1])
target.write_text(json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
target.chmod(0o600)
PY
write_rollback_record not-required \
  "bootstrap succeeded; rollback plan remains recorded for operator use"
write_status bootstrapped-unsigned
completed=1
rmdir "$lock_dir"
lock_dir=
echo "Unsigned first deployment completed and recorded at $deployment_dir/bootstrap-deployment.json"
