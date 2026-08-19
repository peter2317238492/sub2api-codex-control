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
  +publish +subscribe +unsubscribe \
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

acl_line=$(redis_admin_cli --raw ACL LIST | awk -v selected="$redis_user" \
  '$1 == "user" && $2 == selected { print; found = 1 } END { if (!found) exit 1 }')
set -- $acl_line
[ "$#" -ge 8 ] && [ "$1" = user ] && [ "$2" = "$redis_user" ] || {
  echo "provision-redis-acl: ACL LIST did not return the dedicated user" >&2
  exit 1
}
shift 2
seen_on=0 seen_password=0 seen_keys=0 seen_channels=0 seen_reset=0
seen_ping=0 seen_get=0 seen_set=0 seen_del=0 seen_incr=0 seen_expire=0
seen_eval=0 seen_publish=0 seen_subscribe=0 seen_unsubscribe=0 seen_setinfo=0
seen_sanitize=0 seen_resetchannels=0
for token in "$@"; do
  case "$token" in
    on) seen_on=$((seen_on + 1)) ;;
    # Redis 7+ prints these informational hardening tokens in ACL LIST:
    # sanitize-payload is the default payload check, and resetchannels is
    # exactly the deny-then-allow channel baseline this user is built on.
    sanitize-payload) seen_sanitize=$((seen_sanitize + 1)) ;;
    resetchannels) seen_resetchannels=$((seen_resetchannels + 1)) ;;
    \#*) seen_password=$((seen_password + 1)) ;;
    "~${redis_prefix}*") seen_keys=$((seen_keys + 1)) ;;
    "&${redis_prefix}*") seen_channels=$((seen_channels + 1)) ;;
    -@all) seen_reset=$((seen_reset + 1)) ;;
    +ping) seen_ping=$((seen_ping + 1)) ;;
    +get) seen_get=$((seen_get + 1)) ;;
    +set) seen_set=$((seen_set + 1)) ;;
    +del) seen_del=$((seen_del + 1)) ;;
    +incr) seen_incr=$((seen_incr + 1)) ;;
    +expire) seen_expire=$((seen_expire + 1)) ;;
    +eval) seen_eval=$((seen_eval + 1)) ;;
    +publish) seen_publish=$((seen_publish + 1)) ;;
    +subscribe) seen_subscribe=$((seen_subscribe + 1)) ;;
    +unsubscribe) seen_unsubscribe=$((seen_unsubscribe + 1)) ;;
    '+client|setinfo') seen_setinfo=$((seen_setinfo + 1)) ;;
    *)
      echo "provision-redis-acl: dedicated user has an unexpected ACL token" >&2
      exit 1
      ;;
  esac
done
for count in \
  "$seen_on" "$seen_password" "$seen_keys" "$seen_channels" "$seen_reset" \
  "$seen_ping" "$seen_get" "$seen_set" "$seen_del" "$seen_incr" \
  "$seen_expire" "$seen_eval" "$seen_publish" "$seen_subscribe" \
  "$seen_unsubscribe" "$seen_setinfo"; do
  [ "$count" = 1 ] || {
    echo "provision-redis-acl: dedicated user ACL is not exact" >&2
    exit 1
  }
done
for count in "$seen_sanitize" "$seen_resetchannels"; do
  [ "$count" = 0 ] || [ "$count" = 1 ] || {
    echo "provision-redis-acl: dedicated user ACL is not exact" >&2
    exit 1
  }
done

REDISCLI_AUTH=$redis_password
export REDISCLI_AUTH
redis_control_cli() {
  redis-cli -u "$admin_url" --user "$redis_user" --no-auth-warning --raw "$@"
}
canary_key="${redis_prefix}acl-provision-check"
[ "$(redis_control_cli SET "$canary_key" verified)" = OK ] \
  && [ "$(redis_control_cli GET "$canary_key")" = verified ] || {
  echo "provision-redis-acl: dedicated user cannot use its key prefix" >&2
  exit 1
}
redis_control_cli DEL "$canary_key" >/dev/null
outside_key="redis-acl-denied:${redis_user}"
outside_key_result=$(redis_control_cli SET "$outside_key" denied 2>&1 || true)
case "$outside_key_result" in *NOPERM*) ;; *)
  echo "provision-redis-acl: dedicated user can write outside its key prefix" >&2
  exit 1
esac
[ "$(redis_control_cli PUBLISH "${redis_prefix}acl-provision-check" verified)" = 0 ] || {
  echo "provision-redis-acl: dedicated user cannot publish to its channel prefix" >&2
  exit 1
}
outside_channel_result=$(redis_control_cli PUBLISH "$outside_key" denied 2>&1 || true)
case "$outside_channel_result" in *NOPERM*) ;; *)
  echo "provision-redis-acl: dedicated user can publish outside its channel prefix" >&2
  exit 1
esac
admin_result=$(redis_control_cli CONFIG GET dir 2>&1 || true)
case "$admin_result" in *NOPERM*) ;; *)
  echo "provision-redis-acl: dedicated user has an administrative Redis command" >&2
  exit 1
esac

unset REDISCLI_AUTH 2>/dev/null || true
echo "Provisioned Redis ACL user $redis_user for keys and channels matching ${redis_prefix}*."
