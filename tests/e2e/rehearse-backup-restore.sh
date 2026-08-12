#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/../.." && pwd)
compose_file="$repo_root/deploy/docker-compose/compose.yaml"
overlay_file="$script_dir/compose.yaml"

project=${E2E_COMPOSE_PROJECT_NAME:-}
env_file=${E2E_COMPOSE_ENV_FILE:-}
backup_dir=${E2E_BACKUP_REHEARSAL_DIR:-}
expected_device_id=${E2E_EXPECTED_DEVICE_ID:-}
source_database=${CONTROL_DB_NAME:-codex_control}
database_user=${CONTROL_DB_USER:-codex_control}
database_admin_user=${E2E_POSTGRES_ADMIN_USER:-postgres}
restore_database="${source_database}_restore_$(date -u '+%Y%m%d%H%M%S')_$$"
restore_created=0

fail() {
  echo "rehearse-backup-restore: $*" >&2
  exit 1
}

validate_identifier() {
  identifier=$1
  label=$2
  case "$identifier" in
    ''|[0-9]*|*[!A-Za-z0-9_]*) fail "$label is not a safe PostgreSQL identifier" ;;
  esac
}

[ -n "$project" ] || fail "set E2E_COMPOSE_PROJECT_NAME"
[ -n "$env_file" ] || fail "set E2E_COMPOSE_ENV_FILE"
[ -r "$env_file" ] || fail "Compose environment file is not readable: $env_file"
[ -n "$backup_dir" ] || fail "set E2E_BACKUP_REHEARSAL_DIR to an isolated empty directory"
validate_identifier "$source_database" "CONTROL_DB_NAME"
validate_identifier "$database_user" "CONTROL_DB_USER"
validate_identifier "$database_admin_user" "E2E_POSTGRES_ADMIN_USER"
validate_identifier "$restore_database" "restore database name"
[ "${#restore_database}" -le 63 ] || fail "restore database name exceeds PostgreSQL's 63-byte identifier limit"
case "$restore_database" in
  "${source_database}_restore_"*) ;;
  *) fail "restore database does not use the required disposable prefix" ;;
esac
[ "$restore_database" != "$source_database" ] || fail "restore database equals source database"

if [ -e "$backup_dir" ] && [ -L "$backup_dir" ]; then
  fail "refusing symlink backup directory: $backup_dir"
fi
mkdir -p "$backup_dir"
chmod 0700 "$backup_dir"
if find "$backup_dir" -mindepth 1 -print -quit | grep -q .; then
  fail "backup rehearsal directory must be empty: $backup_dir"
fi

compose() {
  docker compose --project-name "$project" --env-file "$env_file" \
    -f "$compose_file" -f "$overlay_file" \
    --profile smoke --profile multi-instance --profile ops "$@"
}

database_command() {
  compose exec -T postgres "$@"
}

backup_tool_command() {
  entrypoint=$1
  shift
  (
    export CONTROL_BACKUP_DIR="$backup_dir"
    export CONTROL_BACKUP_UID_GID="$(id -u):$(id -g)"
    compose run --rm --no-deps -T --entrypoint "$entrypoint" control-backup "$@"
  )
}

cleanup() {
  status=$?
  trap - EXIT HUP INT TERM
  if [ "$restore_created" = "1" ]; then
    database_command dropdb \
      --username "$database_admin_user" \
      --force \
      --if-exists \
      "$restore_database" >/dev/null 2>&1 || {
        echo "rehearse-backup-restore: failed to drop disposable database $restore_database" >&2
        status=1
      }
  fi
  exit "$status"
}
trap cleanup EXIT HUP INT TERM

command -v docker >/dev/null 2>&1 || fail "docker is required"
docker compose version >/dev/null 2>&1 || fail "Docker Compose v2 is required"
[ -n "$(compose ps --status running -q postgres)" ] || fail "the E2E postgres service is not running"

running_api=$(compose ps --status running -q control-api)
running_api_replica=$(compose ps --status running -q control-api-replica)
running_connector=$(compose ps --status running -q connector)
if [ -n "$running_api" ] || [ -n "$running_api_replica" ] || [ -n "$running_connector" ]; then
  fail "stop every control-api instance and connector before the restore rehearsal so source validation is stable"
fi

source_revision=$(database_command psql \
  --username "$database_user" \
  --dbname "$source_database" \
  --no-psqlrc --tuples-only --no-align \
  --command 'SELECT version_num FROM alembic_version' | tr -d '[:space:]')
[ -n "$source_revision" ] || fail "source database has no Alembic revision"

source_snapshot=$(database_command psql \
  --username "$database_user" \
  --dbname "$source_database" \
  --no-psqlrc --tuples-only --no-align --field-separator '|' \
  --command "SELECT
      (SELECT count(*) FROM control_sessions),
      (SELECT count(*) FROM devices),
      (SELECT count(*) FROM commands),
      (SELECT count(*) FROM approvals),
      (SELECT count(*) FROM event_log),
      (SELECT count(*) FROM audit_events)")
source_snapshot=$(printf '%s' "$source_snapshot" | tr -d '[:space:]')

if [ -n "$expected_device_id" ]; then
  case "$expected_device_id" in
    *[!A-Fa-f0-9-]*) fail "E2E_EXPECTED_DEVICE_ID is not a UUID-like value" ;;
  esac
  source_device_present=$(database_command psql \
    --username "$database_user" \
    --dbname "$source_database" \
    --no-psqlrc --tuples-only --no-align \
    --command "SELECT count(*) FROM devices WHERE id = '$expected_device_id'::uuid" | tr -d '[:space:]')
  [ "$source_device_present" = "1" ] || fail "expected device is absent from the source database"
fi

(
  export CONTROL_BACKUP_DIR="$backup_dir"
  export CONTROL_BACKUP_UID_GID="$(id -u):$(id -g)"
  compose run --rm --no-deps --build control-backup
)

set -- "$backup_dir"/codex-control-*.dump
[ "$#" -eq 1 ] && [ -f "$1" ] || fail "backup job did not produce exactly one dump"
dump_file=$1
base=${dump_file%.dump}
manifest_file="${base}.contents.txt"
checksum_file="${base}.sha256"
[ -s "$manifest_file" ] || fail "backup manifest is missing or empty"
[ -s "$checksum_file" ] || fail "backup checksum is missing or empty"

expected_checksum=$(awk 'NR == 1 {print $1}' "$checksum_file")
actual_checksum=$(openssl dgst -sha256 "$dump_file" | awk 'NR == 1 {print $NF}')
[ -n "$expected_checksum" ] && [ "$expected_checksum" = "$actual_checksum" ] \
  || fail "backup checksum verification failed"

archive_listing="$backup_dir/restore-archive.contents.txt"
backup_tool_command pg_restore --list > "$archive_listing" < "$dump_file"
cmp -s "$manifest_file" "$archive_listing" \
  || fail "stored manifest differs from the archive table of contents"

if database_command psql \
  --username "$database_admin_user" \
  --dbname postgres \
  --no-psqlrc --tuples-only --no-align \
  --command "SELECT 1 FROM pg_database WHERE datname = '$restore_database'" \
  | grep -q 1; then
  fail "refusing to reuse existing database $restore_database"
fi

database_command createdb \
  --username "$database_admin_user" \
  --owner "$database_user" \
  --template template0 \
  "$restore_database"
restore_created=1

database_command psql \
  --username "$database_admin_user" \
  --dbname postgres \
  --no-psqlrc --set ON_ERROR_STOP=1 \
  --command "REVOKE ALL ON DATABASE \"$restore_database\" FROM PUBLIC" \
  --command "GRANT CONNECT, TEMPORARY ON DATABASE \"$restore_database\" TO \"$database_user\""

backup_tool_command sh -ec '
  export PGPASSWORD="$(tr -d "\r\n" < /run/secrets/control_db_password)"
  exec pg_restore \
    --host "$CONTROL_DB_HOST" \
    --port "$CONTROL_DB_PORT" \
    --username "$CONTROL_DB_USER" \
    --dbname "$1" \
    --exit-on-error \
    --no-owner \
    --no-acl
' sh "$restore_database" < "$dump_file"

database_command psql \
  --username "$database_admin_user" \
  --dbname "$restore_database" \
  --no-psqlrc --set ON_ERROR_STOP=1 \
  --command 'REVOKE ALL ON SCHEMA public FROM PUBLIC' \
  --command "ALTER SCHEMA public OWNER TO \"$database_user\"" \
  --command "GRANT USAGE, CREATE ON SCHEMA public TO \"$database_user\""

# A restore from an older recovery point must prove it can reach the current
# application revision before its contents are accepted.
(
  export CONTROL_DB_NAME="$restore_database"
  compose run --rm --no-deps control-migrate
)

restored_revision=$(database_command psql \
  --username "$database_user" \
  --dbname "$restore_database" \
  --no-psqlrc --tuples-only --no-align \
  --command 'SELECT version_num FROM alembic_version' | tr -d '[:space:]')
head_revision=$(compose run --rm --no-deps \
  --entrypoint /opt/venv/bin/alembic control-api \
  -c /app/migrations/alembic.ini heads | awk 'NR == 1 {print $1}')
[ -n "$head_revision" ] || fail "could not determine the packaged Alembic head"
[ "$restored_revision" = "$head_revision" ] \
  || fail "restored revision $restored_revision does not match packaged head $head_revision"

restored_snapshot=$(database_command psql \
  --username "$database_user" \
  --dbname "$restore_database" \
  --no-psqlrc --tuples-only --no-align --field-separator '|' \
  --command "SELECT
      (SELECT count(*) FROM control_sessions),
      (SELECT count(*) FROM devices),
      (SELECT count(*) FROM commands),
      (SELECT count(*) FROM approvals),
      (SELECT count(*) FROM event_log),
      (SELECT count(*) FROM audit_events)")
restored_snapshot=$(printf '%s' "$restored_snapshot" | tr -d '[:space:]')
[ "$restored_snapshot" = "$source_snapshot" ] \
  || fail "restored row-count snapshot differs: source=$source_snapshot restored=$restored_snapshot"

restore_database_owner=$(database_command psql \
  --username "$database_admin_user" \
  --dbname postgres \
  --no-psqlrc --tuples-only --no-align \
  --command "SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname = '$restore_database'" \
  | tr -d '[:space:]')
[ "$restore_database_owner" = "$database_user" ] \
  || fail "restored database owner is $restore_database_owner, expected $database_user"

public_database_privileges=$(database_command psql \
  --username "$database_admin_user" \
  --dbname postgres \
  --no-psqlrc --tuples-only --no-align \
  --command "SELECT count(*)
    FROM pg_database AS database
    CROSS JOIN LATERAL aclexplode(COALESCE(database.datacl, acldefault('d', database.datdba))) AS privilege
    WHERE database.datname = '$restore_database'
      AND privilege.grantee = 0
      AND privilege.privilege_type IN ('CONNECT', 'TEMPORARY')" | tr -d '[:space:]')
[ "$public_database_privileges" = "0" ] \
  || fail "restored database grants CONNECT or TEMPORARY to PUBLIC"

public_schema_privileges=$(database_command psql \
  --username "$database_admin_user" \
  --dbname "$restore_database" \
  --no-psqlrc --tuples-only --no-align \
  --command "SELECT count(*)
    FROM pg_namespace AS namespace
    CROSS JOIN LATERAL aclexplode(COALESCE(namespace.nspacl, acldefault('n', namespace.nspowner))) AS privilege
    WHERE namespace.nspname = 'public' AND privilege.grantee = 0" | tr -d '[:space:]')
[ "$public_schema_privileges" = "0" ] \
  || fail "restored public schema grants privileges to PUBLIC"

wrong_object_owners=$(database_command psql \
  --username "$database_admin_user" \
  --dbname "$restore_database" \
  --no-psqlrc --tuples-only --no-align \
  --command "SELECT count(*)
    FROM pg_class AS relation
    JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace
    WHERE namespace.nspname = 'public'
      AND relation.relkind IN ('r', 'p', 'S', 'v', 'm')
      AND pg_get_userbyid(relation.relowner) <> '$database_user'" | tr -d '[:space:]')
[ "$wrong_object_owners" = "0" ] \
  || fail "restored database contains public objects not owned by $database_user"

core_tables='control_sessions device_pairings devices device_connections device_outbox thread_bindings commands approvals event_log event_owner_cursors audit_events'
for table_name in $core_tables; do
  table_present=$(database_command psql \
    --username "$database_user" \
    --dbname "$restore_database" \
    --no-psqlrc --tuples-only --no-align \
    --command "SELECT count(*) FROM pg_class WHERE oid = to_regclass('public.$table_name')" | tr -d '[:space:]')
  [ "$table_present" = "1" ] || fail "restored database is missing core table $table_name"
done

if [ -n "$expected_device_id" ]; then
  restored_device_present=$(database_command psql \
    --username "$database_user" \
    --dbname "$restore_database" \
    --no-psqlrc --tuples-only --no-align \
    --command "SELECT count(*) FROM devices WHERE id = '$expected_device_id'::uuid" | tr -d '[:space:]')
  [ "$restored_device_present" = "1" ] || fail "expected device is absent from the restored database"
fi

# Exercise the release image and all application dependencies against the
# restored database before the database is eligible as a recovery point.
compose run --rm --no-deps \
  --env "CONTROL_DB_NAME=$restore_database" \
  --volume "$script_dir/restore_canary.py:/tmp/restore_canary.py:ro" \
  control-api python /tmp/restore_canary.py

echo "Backup restore rehearsal passed from revision $source_revision to $restored_revision with row counts $restored_snapshot."
