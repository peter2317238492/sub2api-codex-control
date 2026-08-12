#!/bin/sh
set -eu

backup_dir=${BACKUP_DIR:-./backups}
password_file=${CONTROL_DATABASE_PASSWORD_FILE:-./deploy/docker-compose/secrets/control_db_password}
database_host=${CONTROL_DB_HOST:-postgres}
database_port=${CONTROL_DB_PORT:-5432}
database_user=${CONTROL_DB_USER:-codex_control}
database_name=${CONTROL_DB_NAME:-codex_control}

if [ ! -r "$password_file" ]; then
  echo "backup-control-db: database password file is not readable: $password_file" >&2
  exit 1
fi
for command_name in pg_dump pg_restore mktemp stat id sync; do
  if ! command -v "$command_name" >/dev/null 2>&1; then
    echo "backup-control-db: $command_name is required" >&2
    exit 1
  fi
done
if command -v sha256sum >/dev/null 2>&1; then
  checksum_command=sha256sum
elif command -v shasum >/dev/null 2>&1; then
  checksum_command=shasum
else
  echo "backup-control-db: sha256sum or shasum is required" >&2
  exit 1
fi

umask 077
[ -d "$backup_dir" ] || {
  echo "backup-control-db: backup directory must be provisioned before use: $backup_dir" >&2
  exit 1
}
if [ -L "$backup_dir" ]; then
  echo "backup-control-db: refusing symlink backup directory: $backup_dir" >&2
  exit 1
fi
backup_owner=$(stat -c '%u' "$backup_dir" 2>/dev/null || stat -f '%u' "$backup_dir")
backup_mode=$(stat -c '%a' "$backup_dir" 2>/dev/null || stat -f '%Lp' "$backup_dir")
current_uid=$(id -u)
if [ "$backup_owner" != "$current_uid" ]; then
  echo "backup-control-db: backup directory is not owned by runtime UID $current_uid" >&2
  exit 1
fi
if [ "$backup_mode" != "700" ]; then
  echo "backup-control-db: backup directory mode must be exactly 0700" >&2
  exit 1
fi

timestamp=$(date -u '+%Y%m%dT%H%M%SZ')
temporary=$(mktemp "$backup_dir/.codex-control-${timestamp}.XXXXXX")
suffix=${temporary##*.codex-control-${timestamp}.}
base="$backup_dir/codex-control-${timestamp}-${suffix}"
final="${base}.dump"
manifest="${base}.contents.txt"
checksum="${base}.sha256"
manifest_temporary="${manifest}.tmp"
checksum_temporary="${checksum}.tmp"

cleanup() {
  rm -f "$temporary" "$manifest_temporary" "$checksum_temporary"
}
trap cleanup EXIT HUP INT TERM

for target in "$final" "$manifest" "$checksum"; do
  if [ -e "$target" ] || [ -L "$target" ]; then
    echo "backup-control-db: refusing to overwrite $target" >&2
    exit 1
  fi
done

PGPASSWORD=$(tr -d '\r\n' < "$password_file")
[ -n "$PGPASSWORD" ] || {
  echo "backup-control-db: database password file is empty: $password_file" >&2
  exit 1
}
export PGPASSWORD

pg_dump \
  --host "$database_host" \
  --port "$database_port" \
  --username "$database_user" \
  --dbname "$database_name" \
  --format custom \
  --compress 9 \
  --no-owner \
  --no-acl \
  --file "$temporary"

pg_restore --list "$temporary" > "$manifest_temporary"

final_name=${final##*/}
temporary_name=${temporary##*/}
if [ "$checksum_command" = "sha256sum" ]; then
  digest=$(cd "$backup_dir" && sha256sum "$temporary_name" | awk 'NR == 1 {print $1}')
else
  digest=$(cd "$backup_dir" && shasum -a 256 "$temporary_name" | awk 'NR == 1 {print $1}')
fi
printf '%s  %s\n' "$digest" "$final_name" > "$checksum_temporary"

expected_checksum=$(awk 'NR == 1 {print $1}' "$checksum_temporary")
if [ "$checksum_command" = "sha256sum" ]; then
  actual_checksum=$(sha256sum "$temporary" | awk 'NR == 1 {print $1}')
else
  actual_checksum=$(shasum -a 256 "$temporary" | awk 'NR == 1 {print $1}')
fi
if [ -z "$expected_checksum" ] || [ "$expected_checksum" != "$actual_checksum" ]; then
  echo "backup-control-db: generated archive checksum verification failed" >&2
  exit 1
fi

chmod 0600 "$temporary" "$manifest_temporary" "$checksum_temporary"
sync "$temporary"
sync "$manifest_temporary"
sync "$checksum_temporary"
mv "$temporary" "$final"
mv "$manifest_temporary" "$manifest"
mv "$checksum_temporary" "$checksum"
sync "$final"
sync "$manifest"
sync "$checksum"
sync -f "$backup_dir"
trap - EXIT HUP INT TERM
unset PGPASSWORD
echo "Created $final, $manifest, and $checksum"
