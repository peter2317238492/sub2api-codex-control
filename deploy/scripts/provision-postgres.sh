#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
bootstrap_sql="$script_dir/../postgres/bootstrap.sql"
password_file=${CONTROL_DATABASE_PASSWORD_FILE:-$script_dir/../docker-compose/secrets/control_db_password}
control_role=${CONTROL_DB_USER:-codex_control}
control_database=${CONTROL_DB_NAME:-codex_control}
sub2api_database=${SUB2API_DB_NAME:-sub2api}
admin_url=${POSTGRES_ADMIN_URL:-}
admin_password_file=${POSTGRES_ADMIN_PASSWORD_FILE:-}

if [ -z "$admin_url" ]; then
  echo "provision-postgres: set POSTGRES_ADMIN_URL to an administrative PostgreSQL DSN" >&2
  exit 1
fi
if [ ! -r "$password_file" ]; then
  echo "provision-postgres: password file is not readable: $password_file" >&2
  exit 1
fi
if ! command -v psql >/dev/null 2>&1; then
  echo "provision-postgres: psql is required" >&2
  exit 1
fi
if [ -n "$admin_password_file" ]; then
  if [ ! -r "$admin_password_file" ]; then
    echo "provision-postgres: admin password file is not readable: $admin_password_file" >&2
    exit 1
  fi
  PGPASSWORD=$(tr -d '\r\n' < "$admin_password_file")
  if [ -z "$PGPASSWORD" ]; then
    echo "provision-postgres: admin password file is empty: $admin_password_file" >&2
    exit 1
  fi
  export PGPASSWORD
fi

validate_identifier() {
  identifier=$1
  label=$2
  case "$identifier" in
    ''|*[!A-Za-z0-9_]*)
      echo "provision-postgres: $label must contain only letters, digits, and underscores" >&2
      exit 1
      ;;
  esac
}

validate_identifier "$control_role" "CONTROL_DB_USER"
validate_identifier "$control_database" "CONTROL_DB_NAME"
validate_identifier "$sub2api_database" "SUB2API_DB_NAME"
for identifier in "$control_role" "$control_database" "$sub2api_database"; do
  if [ "${#identifier}" -gt 63 ]; then
    echo "provision-postgres: PostgreSQL identifiers must not exceed 63 bytes" >&2
    exit 1
  fi
done
if [ "$control_database" = "$sub2api_database" ]; then
  echo "provision-postgres: control and Sub2API database names must be different" >&2
  exit 1
fi

existing_owner=$(psql \
  --dbname "$admin_url" \
  --tuples-only --no-align \
  --command "SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname = '$control_database'" \
  | tr -d '[:space:]')
if [ -n "$existing_owner" ] && [ "$existing_owner" != "$control_role" ]; then
  echo "provision-postgres: existing database $control_database is owned by $existing_owner, not $control_role" >&2
  exit 1
fi

existing_role_memberships=$(psql \
  --dbname "$admin_url" \
  --tuples-only --no-align \
  --command "SELECT count(*)
    FROM pg_auth_members AS membership
    JOIN pg_roles AS member_role ON member_role.oid = membership.member
    JOIN pg_roles AS granted_role ON granted_role.oid = membership.roleid
    WHERE member_role.rolname = '$control_role'
       OR granted_role.rolname = '$control_role'" \
  | tr -d '[:space:]')
if [ "$existing_role_memberships" != "0" ]; then
  echo "provision-postgres: Control role must not participate in inherited or SET ROLE memberships" >&2
  exit 1
fi

sub2api_public_connect=$(psql \
  --dbname "$admin_url" \
  --tuples-only --no-align \
  --command "SELECT EXISTS (
      SELECT 1
      FROM pg_database AS database
      CROSS JOIN LATERAL aclexplode(COALESCE(database.datacl, acldefault('d', database.datdba))) AS privilege
      WHERE database.datname = '$sub2api_database'
        AND privilege.grantee = 0
        AND privilege.privilege_type = 'CONNECT'
    )" | tr -d '[:space:]')
if [ "$sub2api_public_connect" != "f" ]; then
  echo "provision-postgres: Sub2API database must revoke CONNECT from PUBLIC before creating the Control role" >&2
  exit 1
fi

control_password=$(tr -d '\r\n' < "$password_file")
case "$control_password" in
  ''|*[!A-Za-z0-9._~+-]*)
    echo "provision-postgres: password must be non-empty and shell-safe; generated secrets satisfy this rule" >&2
    exit 1
    ;;
esac

umask 077
temporary=$(mktemp "${TMPDIR:-/tmp}/codex-control-bootstrap.XXXXXX")
cleanup() {
  rm -f "$temporary"
}
trap cleanup EXIT HUP INT TERM

{
  printf "\\set control_password '%s'\n" "$control_password"
  cat "$bootstrap_sql"
} > "$temporary"

psql \
  --dbname "$admin_url" \
  --set "control_role=$control_role" \
  --set "control_database=$control_database" \
  --set "sub2api_database=$sub2api_database" \
  --file "$temporary"

control_can_connect_sub2api=$(psql \
  --dbname "$admin_url" \
  --tuples-only --no-align \
  --command "SELECT has_database_privilege('$control_role', '$sub2api_database', 'CONNECT')" \
  | tr -d '[:space:]')
if [ "$control_can_connect_sub2api" != "f" ]; then
  echo "provision-postgres: Control role still has CONNECT on the Sub2API database" >&2
  exit 1
fi

unset PGPASSWORD 2>/dev/null || true
echo "Provisioned PostgreSQL role $control_role and database $control_database."
