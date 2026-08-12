#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/../.." && pwd)
compose_file="$repo_root/deploy/docker-compose/compose.yaml"
overlay_file="$script_dir/compose.yaml"
suffix="$$"
project="sub2api-codex-backup-e2e-$suffix"
network="sub2api-codex-backup-e2e-$suffix"
temporary=$(mktemp -d "${TMPDIR:-/tmp}/sub2api-codex-backup-e2e.XXXXXX")
env_file="$temporary/e2e.env"
secret_dir="$temporary/secrets"
backup_dir="$temporary/backups"
expected_device_id=00000000-0000-4000-8000-000000000001
started=0

cleanup() {
  status=$?
  trap - EXIT HUP INT TERM
  if [ "${KEEP_E2E:-0}" = "1" ]; then
    echo "Keeping backup E2E project $project and network $network for inspection."
    echo "Environment file: $env_file"
    exit "$status"
  fi
  if [ "$started" = "1" ]; then
    docker compose --project-name "$project" --env-file "$env_file" \
      -f "$compose_file" -f "$overlay_file" \
      --profile smoke --profile multi-instance --profile ops \
      down --volumes --remove-orphans >/dev/null 2>&1 || true
  fi
  docker network rm "$network" >/dev/null 2>&1 || true
  rm -rf "$temporary"
  exit "$status"
}
trap cleanup EXIT HUP INT TERM

for command_name in docker openssl; do
  if ! command -v "$command_name" >/dev/null 2>&1; then
    echo "run-backup-restore: $command_name is required" >&2
    exit 1
  fi
done
docker compose version >/dev/null 2>&1 || {
  echo "run-backup-restore: Docker Compose v2 is required" >&2
  exit 1
}

mkdir -p "$secret_dir" "$backup_dir"
SECRET_DIR="$secret_dir" "$repo_root/deploy/scripts/generate-secrets.sh"
umask 077
openssl rand -hex 32 > "$secret_dir/e2e_postgres_admin_password"
openssl rand -hex 32 > "$secret_dir/e2e_redis_admin_password"
chmod 0600 "$secret_dir/e2e_postgres_admin_password" "$secret_dir/e2e_redis_admin_password"

cat > "$env_file" <<EOF
CONTROL_RELEASE=0.1.0-backup-e2e
CONTROL_VCS_REF=backup-e2e
CONTROL_PUBLIC_ORIGIN=https://127.0.0.1:18092
CONTROL_BIND_ADDRESS=127.0.0.1
CONTROL_API_IMAGE=sub2api-codex-control-api:backup-e2e
CONTROL_PWA_IMAGE=sub2api-codex-control-pwa:backup-e2e
CONTROL_SMOKE_EDGE_IMAGE=sub2api-codex-control-smoke-edge:backup-e2e
SUB2API_NETWORK_NAME=$network
SUB2API_INTERNAL_URL=http://sub2api:8080
CONTROL_DB_HOST=postgres
CONTROL_DB_PORT=5432
CONTROL_DB_USER=codex_control
CONTROL_DB_NAME=codex_control
CONTROL_REDIS_SCHEME=redis
CONTROL_REDIS_HOST=redis
CONTROL_REDIS_PORT=6379
CONTROL_REDIS_USER=default
CONTROL_REDIS_DATABASE=0
CONTROL_REDIS_PREFIX=codex-control:
CONTROL_DATABASE_PASSWORD_SECRET_FILE=$secret_dir/control_db_password
CONTROL_REDIS_PASSWORD_SECRET_FILE=$secret_dir/control_redis_password
CONTROL_SESSION_HMAC_SECRET_FILE=$secret_dir/control_session_hmac_secret
E2E_POSTGRES_ADMIN_PASSWORD_SECRET_FILE=$secret_dir/e2e_postgres_admin_password
E2E_REDIS_ADMIN_PASSWORD_SECRET_FILE=$secret_dir/e2e_redis_admin_password
E2E_ROOT=$repo_root
E2E_TLS_CERT=$temporary/unused.crt
E2E_TLS_KEY=$temporary/unused.key
E2E_CONNECTOR_BINARY=$temporary/unused-connector
E2E_CONNECTOR_CONFIG=$temporary/unused-connector.json
E2E_CONNECTOR_CODEX_HOME=$temporary/unused-codex-home
E2E_CONNECTOR_WORKSPACE=$temporary/unused-workspace
E2E_FAKE_CODEX=$temporary/unused-codex
E2E_FAKE_CODEX_AUDIT_DIR=$temporary/unused-audit
EOF
chmod 0600 "$env_file"

docker network create "$network" >/dev/null
started=1

compose() {
  docker compose --project-name "$project" --env-file "$env_file" \
    -f "$compose_file" -f "$overlay_file" \
    --profile smoke --profile multi-instance --profile ops "$@"
}

compose config --quiet
compose up -d --wait postgres redis sub2api

compose exec -T postgres psql \
  --username postgres \
  --dbname postgres \
  --no-psqlrc --set ON_ERROR_STOP=1 \
  --command 'GRANT CONNECT ON DATABASE sub2api TO PUBLIC'
if compose run --rm postgres-provision; then
  echo "run-backup-restore: PostgreSQL provision accepted PUBLIC CONNECT on Sub2API" >&2
  exit 1
fi
unsafe_provision_objects=$(compose exec -T postgres psql \
  --username postgres \
  --dbname postgres \
  --no-psqlrc --tuples-only --no-align \
  --command "SELECT
      (SELECT count(*) FROM pg_roles WHERE rolname = 'codex_control')
      + (SELECT count(*) FROM pg_database WHERE datname = 'codex_control')" \
  | tr -d '[:space:]')
[ "$unsafe_provision_objects" = "0" ] || {
  echo "run-backup-restore: rejected PostgreSQL provision left role or database state behind" >&2
  exit 1
}
compose exec -T postgres psql \
  --username postgres \
  --dbname postgres \
  --no-psqlrc --set ON_ERROR_STOP=1 \
  --command 'REVOKE CONNECT ON DATABASE sub2api FROM PUBLIC'
compose run --rm postgres-provision
compose run --rm postgres-provision
if compose exec -T postgres psql \
  --username codex_control \
  --dbname sub2api \
  --no-psqlrc \
  --command 'SELECT 1' >/dev/null 2>&1; then
  echo "run-backup-restore: Control role connected to the Sub2API database" >&2
  exit 1
fi
if compose run --rm \
  --env REDIS_ADMIN_URL=redis://default@redis:6379/0 \
  redis-provision; then
  echo "run-backup-restore: Redis provision accepted ambiguous URL userinfo" >&2
  exit 1
fi
compose run --rm redis-provision
compose run --rm redis-provision
compose run --rm --no-deps \
  --entrypoint sh \
  redis-provision -ec '
    export REDISCLI_AUTH="$(tr -d "\r\n" < /run/secrets/control_redis_password)"
    allowed=$(redis-cli -h redis --user codex_control --raw SET codex-control:restore-rehearsal ok)
    [ "$allowed" = "OK" ] || {
      echo "run-backup-restore: Control Redis user could not write its prefix" >&2
      exit 1
    }
    forbidden=$(redis-cli -h redis --user codex_control --raw SET outside-prefix denied)
    case "$forbidden" in
      NOPERM*) ;;
      *)
        echo "run-backup-restore: Control Redis user wrote outside its prefix" >&2
        exit 1
        ;;
    esac
    redis-cli -h redis --user codex_control --raw DEL codex-control:restore-rehearsal >/dev/null
  '
compose up --build --exit-code-from control-migrate control-migrate

compose exec -T postgres psql \
  --username codex_control \
  --dbname codex_control \
  --no-psqlrc \
  --set ON_ERROR_STOP=1 \
  --command "INSERT INTO devices (id, owner_user_id, name, public_key)
    VALUES ('$expected_device_id'::uuid, 'restore-owner', 'Restore sentinel', 'restore-sentinel-public-key')"

E2E_COMPOSE_PROJECT_NAME="$project" \
E2E_COMPOSE_ENV_FILE="$env_file" \
E2E_BACKUP_REHEARSAL_DIR="$backup_dir" \
E2E_EXPECTED_DEVICE_ID="$expected_device_id" \
  "$script_dir/rehearse-backup-restore.sh"

leftover_databases=$(compose exec -T postgres psql \
  --username postgres \
  --dbname postgres \
  --no-psqlrc --tuples-only --no-align \
  --command "SELECT count(*) FROM pg_database WHERE datname LIKE 'codex_control_restore_%'" \
  | tr -d '[:space:]')
[ "$leftover_databases" = "0" ] || {
  echo "run-backup-restore: disposable restore database was not removed" >&2
  exit 1
}

echo "Disposable backup and restore acceptance test passed."
