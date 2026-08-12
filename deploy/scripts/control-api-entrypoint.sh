#!/bin/sh
set -eu

required_secret() {
  variable_name=$1
  secret_file=$2
  if [ ! -r "$secret_file" ]; then
    echo "control-api-entrypoint: required secret is not readable: $secret_file" >&2
    exit 1
  fi
  secret_value=$(tr -d '\r\n' < "$secret_file")
  if [ -z "$secret_value" ]; then
    echo "control-api-entrypoint: required secret is empty: $secret_file" >&2
    exit 1
  fi
  export "$variable_name=$secret_value"
}

urlencode_secret() {
  secret_file=$1
  python -c 'import sys; from urllib.parse import quote; print(quote(sys.stdin.read().rstrip("\r\n"), safe=""))' < "$secret_file"
}

database_password_file=${CONTROL_DATABASE_PASSWORD_FILE:-/run/secrets/control_db_password}
redis_password_file=${CONTROL_REDIS_PASSWORD_FILE:-/run/secrets/control_redis_password}
session_secret_file=${CONTROL_SESSION_HMAC_SECRET_FILE:-/run/secrets/control_session_hmac_secret}
redis_auth_mode=${CONTROL_REDIS_AUTH_MODE:-password}

for secret_file in "$database_password_file"; do
  if [ ! -r "$secret_file" ]; then
    echo "control-api-entrypoint: required secret is not readable: $secret_file" >&2
    exit 1
  fi
done

database_password=$(urlencode_secret "$database_password_file")

database_user=${CONTROL_DB_USER:-codex_control}
database_host=${CONTROL_DB_HOST:-postgres}
database_port=${CONTROL_DB_PORT:-5432}
database_name=${CONTROL_DB_NAME:-codex_control}
database_query=${CONTROL_DB_QUERY:-}

redis_scheme=${CONTROL_REDIS_SCHEME:-redis}
redis_user=${CONTROL_REDIS_USER:-codex_control}
redis_host=${CONTROL_REDIS_HOST:-redis}
redis_port=${CONTROL_REDIS_PORT:-6379}
redis_database=${CONTROL_REDIS_DATABASE:-0}
redis_query=${CONTROL_REDIS_QUERY:-}

export CONTROL_DATABASE_URL="postgresql+asyncpg://${database_user}:${database_password}@${database_host}:${database_port}/${database_name}${database_query}"
case "$redis_auth_mode" in
  password)
    if [ ! -r "$redis_password_file" ]; then
      echo "control-api-entrypoint: required secret is not readable: $redis_password_file" >&2
      exit 1
    fi
    redis_password=$(urlencode_secret "$redis_password_file")
    export CONTROL_REDIS_URL="${redis_scheme}://${redis_user}:${redis_password}@${redis_host}:${redis_port}/${redis_database}${redis_query}"
    ;;
  none)
    if [ "$redis_user" != "default" ]; then
      echo "control-api-entrypoint: unauthenticated Redis requires the default user" >&2
      exit 1
    fi
    export CONTROL_REDIS_URL="${redis_scheme}://${redis_host}:${redis_port}/${redis_database}${redis_query}"
    ;;
  *)
    echo "control-api-entrypoint: unsupported CONTROL_REDIS_AUTH_MODE" >&2
    exit 1
    ;;
esac
required_secret CONTROL_SESSION_HMAC_SECRET "$session_secret_file"
export CONTROL_METRICS_BEARER_TOKEN="$(python -c '
import hashlib
import hmac
import pathlib
import sys

secret = pathlib.Path(sys.argv[1]).read_bytes().rstrip(b"\r\n")
print(hmac.new(secret, b"control-metrics-v1", hashlib.sha256).hexdigest())
' "$session_secret_file")"

command_name=${1:-api}
if [ "$#" -gt 0 ]; then
  shift
fi

case "$command_name" in
  api)
    exec uvicorn control_api.main:app \
      --host 0.0.0.0 \
      --port "${CONTROL_API_PORT:-8090}" \
      --workers "${CONTROL_API_WORKERS:-1}" \
      --timeout-keep-alive 5 \
      --no-access-log \
      --no-proxy-headers \
      "$@"
    ;;
  migrate)
    exec alembic -c /app/migrations/alembic.ini upgrade head "$@"
    ;;
  *)
    exec "$command_name" "$@"
    ;;
esac
