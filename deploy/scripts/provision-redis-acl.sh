#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
password_file=${CONTROL_REDIS_PASSWORD_FILE:-$script_dir/../docker-compose/secrets/control_redis_password}
redis_user=${CONTROL_REDIS_USER:-codex_control}
redis_prefix=${CONTROL_REDIS_PREFIX:-codex-control:}
admin_url=${REDIS_ADMIN_URL:-}
admin_user=${REDIS_ADMIN_USER:-}
admin_password_file=${REDIS_ADMIN_PASSWORD_FILE:-}

if [ -z "$admin_url" ]; then
  echo "provision-redis-acl: set REDIS_ADMIN_URL to an administrative Redis URL" >&2
  exit 1
fi
if [ ! -r "$password_file" ]; then
  echo "provision-redis-acl: password file is not readable: $password_file" >&2
  exit 1
fi
if ! command -v redis-cli >/dev/null 2>&1; then
  echo "provision-redis-acl: redis-cli is required" >&2
  exit 1
fi
if [ -n "$admin_password_file" ]; then
  case "$admin_url" in
    *://*@*)
      echo "provision-redis-acl: REDIS_ADMIN_URL must not contain userinfo when REDIS_ADMIN_PASSWORD_FILE is set; use REDIS_ADMIN_USER" >&2
      exit 1
      ;;
  esac
  if [ ! -r "$admin_password_file" ]; then
    echo "provision-redis-acl: admin password file is not readable: $admin_password_file" >&2
    exit 1
  fi
  REDISCLI_AUTH=$(tr -d '\r\n' < "$admin_password_file")
  if [ -z "$REDISCLI_AUTH" ]; then
    echo "provision-redis-acl: admin password file is empty: $admin_password_file" >&2
    exit 1
  fi
  export REDISCLI_AUTH
fi
case "$admin_user" in
  *[!A-Za-z0-9_.-]*)
    echo "provision-redis-acl: Redis admin user contains unsupported characters" >&2
    exit 1
    ;;
esac
case "$redis_user" in
  ''|*[!A-Za-z0-9_.-]*)
    echo "provision-redis-acl: Redis user contains unsupported characters" >&2
    exit 1
    ;;
esac
case "$redis_prefix" in
  ''|*[[:space:]]*)
    echo "provision-redis-acl: Redis prefix must be non-empty and contain no whitespace" >&2
    exit 1
    ;;
esac

redis_password=$(tr -d '\r\n' < "$password_file")
if [ -z "$redis_password" ]; then
  echo "provision-redis-acl: password is empty" >&2
  exit 1
fi

redis_admin_cli() {
  if [ -n "$admin_user" ]; then
    redis-cli -u "$admin_url" --user "$admin_user" --no-auth-warning "$@"
  else
    redis-cli -u "$admin_url" --no-auth-warning "$@"
  fi
}

setuser_response=$(printf '>%s' "$redis_password" | redis_admin_cli \
  --raw -x ACL SETUSER "$redis_user" \
  reset on \
  "~${redis_prefix}*" \
  "&${redis_prefix}*" \
  +ping +get +set +del +incr +expire +eval \
  +publish +subscribe +psubscribe +unsubscribe +punsubscribe \
  '+client|setinfo')
if [ "$setuser_response" != "OK" ]; then
  echo "provision-redis-acl: ACL SETUSER did not return OK" >&2
  exit 1
fi

save_response=$(redis_admin_cli --raw ACL SAVE)
if [ "$save_response" != "OK" ]; then
  echo "provision-redis-acl: ACL was changed in memory but ACL SAVE failed; configure an aclfile and retry" >&2
  exit 1
fi

getuser_response=$(redis_admin_cli --raw ACL GETUSER "$redis_user")
if ! printf '%s\n' "$getuser_response" | grep -Fxq flags \
  || ! printf '%s\n' "$getuser_response" | grep -Fxq on; then
  echo "provision-redis-acl: ACL GETUSER did not confirm an enabled user" >&2
  exit 1
fi

unset REDISCLI_AUTH 2>/dev/null || true
echo "Provisioned Redis ACL user $redis_user for keys and channels matching ${redis_prefix}*."
