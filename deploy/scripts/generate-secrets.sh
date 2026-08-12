#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
default_secret_dir=$(CDPATH= cd -- "$script_dir/../docker-compose" && pwd)/secrets
secret_dir=${SECRET_DIR:-$default_secret_dir}
force=${FORCE:-0}

if ! command -v openssl >/dev/null 2>&1; then
  echo "generate-secrets: openssl is required" >&2
  exit 1
fi

mkdir -p "$secret_dir"
chmod 0700 "$secret_dir"
umask 077

write_secret() {
  target=$1
  value=$2
  if [ -e "$target" ] && [ "$force" != "1" ]; then
    echo "generate-secrets: refusing to overwrite $target (set FORCE=1 to rotate)" >&2
    exit 1
  fi
  temporary="${target}.tmp.$$"
  printf '%s\n' "$value" > "$temporary"
  chmod 0600 "$temporary"
  mv "$temporary" "$target"
}

write_secret "$secret_dir/control_db_password" "$(openssl rand -hex 32)"
write_secret "$secret_dir/control_redis_password" "$(openssl rand -hex 32)"
write_secret "$secret_dir/control_session_hmac_secret" "$(openssl rand -hex 64)"

echo "Generated three mode-0600 secrets in $secret_dir. Values were not printed."
echo "Provision the PostgreSQL role and Redis ACL with the matching password files before starting the stack."
