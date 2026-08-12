#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/../.." && pwd)
compose_dir="$repo_root/deploy/docker-compose"
compose_file="$compose_dir/compose.yaml"
production_overlay="$compose_dir/compose.production.yaml"
checks="$script_dir/deployment-admission.py"
runtime_verifier="$script_dir/verify-sub2api-runtime.sh"
production_state_backup="$script_dir/backup-production-state.py"
pg_restore_validator="$script_dir/pg-restore-via-container.sh"
release_verifier="$repo_root/deploy/release/verify-control-images.sh"
source_bundle_verifier="$repo_root/deploy/release/source_bundle.py"
smoke_test="$repo_root/tests/e2e/smoke.py"

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
lock_dir=
deployment_dir=
source_stage=
compose_snapshot=
auth_probe_nonce=
auth_probe_user_id=
auth_probe_base_url=http://127.0.0.1:8080
auth_contract_file=
production_backup_root=${CONTROL_PRODUCTION_BACKUP_ROOT:-}
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

umask 077

fail() {
  echo "deploy-production: $*" >&2
  exit 1
}

case "$backup_max_age" in
  ''|*[!0-9]*|0) fail "CONTROL_PREMIGRATION_BACKUP_MAX_AGE_SECONDS must be positive" ;;
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
timestamp=$(date -u '+%Y%m%dT%H%M%SZ')
deployment_dir="$record_root/deployment-${timestamp}-$$"
mkdir "$deployment_dir"
chmod 0700 "$deployment_dir"

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
  if [ "$completed" != "1" ]; then
    write_status "failed:$stage" || :
  fi
  if [ -n "$lock_dir" ] && [ -d "$lock_dir" ]; then
    rmdir "$lock_dir" || :
  fi
  exit "$status"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
write_status "in-progress:$stage"

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
    --nginx-config "$nginx_config_path"
  if [ -n "$sub2api_postgres_password_file" ]; then
    set -- "$@" --postgres-password-file "$sub2api_postgres_password_file"
  fi
  if [ -n "$sub2api_redis_password_file" ]; then
    set -- "$@" --redis-password-file "$sub2api_redis_password_file"
  fi
  "$@"
}

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
certificate_oidc_issuer=${CONTROL_RELEASE_CERTIFICATE_OIDC_ISSUER:-}
certificate_identity=${CONTROL_RELEASE_CERTIFICATE_IDENTITY:-}
certificate_workflow_sha=${CONTROL_RELEASE_CERTIFICATE_WORKFLOW_SHA:-}
certificate_workflow_trigger=${CONTROL_RELEASE_CERTIFICATE_WORKFLOW_TRIGGER:-}
certificate_workflow_repository=${CONTROL_RELEASE_CERTIFICATE_WORKFLOW_REPOSITORY:-}
certificate_workflow_ref=${CONTROL_RELEASE_CERTIFICATE_WORKFLOW_REF:-}
expected_source_repository=${CONTROL_RELEASE_EXPECTED_SOURCE_REPOSITORY:-}
expected_source_commit=${CONTROL_RELEASE_EXPECTED_SOURCE_COMMIT:-}
expected_release_tag=${CONTROL_RELEASE_EXPECTED_TAG:-}
expected_api_repository=${CONTROL_RELEASE_EXPECTED_API_REPOSITORY:-}
expected_pwa_repository=${CONTROL_RELEASE_EXPECTED_PWA_REPOSITORY:-}
expected_postgres_tools_repository=${CONTROL_RELEASE_EXPECTED_POSTGRES_TOOLS_REPOSITORY:-}
cosign_bin=${CONTROL_RELEASE_COSIGN_BIN:-cosign}
stage=verify-signed-release
write_status "in-progress:$stage"
for required_value in \
  "$release_dir" \
  "$certificate_oidc_issuer" \
  "$certificate_identity" \
  "$certificate_workflow_sha" \
  "$certificate_workflow_trigger" \
  "$certificate_workflow_repository" \
  "$certificate_workflow_ref" \
  "$expected_source_repository" \
  "$expected_source_commit" \
  "$expected_release_tag" \
  "$expected_api_repository" \
  "$expected_pwa_repository" \
  "$expected_postgres_tools_repository"
do
  [ -n "$required_value" ] || fail "all CONTROL_RELEASE_* trust inputs are required"
done

atomic_json "$deployment_dir/release-verification.json" \
  "$release_verifier" \
  --release-dir "$release_dir" \
  --cosign "$cosign_bin" \
  --certificate-oidc-issuer "$certificate_oidc_issuer" \
  --certificate-identity "$certificate_identity" \
  --certificate-github-workflow-sha "$certificate_workflow_sha" \
  --certificate-github-workflow-trigger "$certificate_workflow_trigger" \
  --certificate-github-workflow-repository "$certificate_workflow_repository" \
  --certificate-github-workflow-ref "$certificate_workflow_ref" \
  --expected-source-repository "$expected_source_repository" \
  --expected-source-commit "$expected_source_commit" \
  --expected-release-tag "$expected_release_tag" \
  --expected-api-repository "$expected_api_repository" \
  --expected-pwa-repository "$expected_pwa_repository" \
  --expected-postgres-tools-repository "$expected_postgres_tools_repository"

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
runtime_verifier="$script_dir/verify-sub2api-runtime.sh"
production_state_backup="$script_dir/backup-production-state.py"
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
chmod 0400 "$compose_snapshot"
atomic_json "$deployment_dir/plan.json" \
  python3 "$checks" compose-plan \
  --compose-config "$deployment_dir/compose-config.json" \
  --release-verification "$deployment_dir/release-verification.json" \
  --versions-lock "$versions_lock" \
  --source-repository "$expected_source_repository" \
  --repo-root "$repo_root"
api_image=$(json_field "$deployment_dir/plan.json" api_image)
pwa_image=$(json_field "$deployment_dir/plan.json" pwa_image)
backup_image=$(json_field "$deployment_dir/plan.json" backup_image)
backup_dir=$(json_field "$deployment_dir/plan.json" backup_directory)
backup_owner_uid=$(json_integer "$deployment_dir/plan.json" backup_owner_uid)
sub2api_network=$(json_field "$deployment_dir/plan.json" sub2api_network)
pwa_network=$(json_field "$deployment_dir/plan.json" pwa_network)
public_origin=$(json_field "$deployment_dir/plan.json" public_origin)
auth_contract_source=$(json_field "$deployment_dir/plan.json" auth_contract_file)
auth_contract_sha256=$(json_field "$deployment_dir/plan.json" auth_contract_sha256)
auth_contract_file="$deployment_dir/sub2api-auth-contract.json"
atomic_json "$deployment_dir/auth-contract-input.json" \
  python3 "$checks" copy-admitted-file \
  --source "$auth_contract_source" \
  --destination "$auth_contract_file" \
  --label "signed Sub2API auth contract" \
  --expected-sha256 "$auth_contract_sha256"
control_database=$(
  json_field "$compose_snapshot" services control-api environment CONTROL_DB_NAME
)

stage=create-production-state-backup
write_status "in-progress:$stage"
run_production_state_backup

stage=pull-release-images
write_status "in-progress:$stage"
docker pull "$api_image"
docker pull "$pwa_image"
docker pull "$backup_image"
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
  python3 "$checks" copy-private-file \
  --source "$auth_contract_file" \
  --destination "$probe_input_dir/contract.json" \
  --label "pinned Sub2API auth contract"

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

stage=create-premigration-backup
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

stage=recheck-admission
write_status "in-progress:$stage"
atomic_json "$deployment_dir/plan-before-migration.json" \
  python3 "$checks" compose-plan \
  --compose-config "$compose_snapshot" \
  --release-verification "$deployment_dir/release-verification.json" \
  --versions-lock "$versions_lock" \
  --source-repository "$expected_source_repository" \
  --repo-root "$repo_root"
cmp -s "$deployment_dir/plan.json" "$deployment_dir/plan-before-migration.json" \
  || fail "pinned Compose deployment plan changed during admission"
run_runtime_verifier "$deployment_dir/sub2api-before-migration.json" "$auth_evidence" 1
atomic_json "$deployment_dir/sub2api-match.json" \
  python3 "$checks" runtime-match \
  --first "$deployment_dir/sub2api-first.json" \
  --second "$deployment_dir/sub2api-before-migration.json" \
  --plan "$deployment_dir/plan.json"
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
  --status admitted_for_migration

stage=migrate
write_status "in-progress:$stage"
compose run --rm --no-deps --pull never control-migrate
compose run --rm --no-deps --pull never control-api \
  /opt/venv/bin/alembic -c /app/migrations/alembic.ini current \
  > "$deployment_dir/alembic-current-after.txt"
atomic_json "$deployment_dir/revisions-after-migration.json" \
  python3 "$checks" revisions \
  --current "$deployment_dir/alembic-current-after.txt" \
  --head "$deployment_dir/alembic-head.txt" \
  --plan "$deployment_dir/plan.json" \
  --require-current-head

stage=start-sidecars
write_status "in-progress:$stage"
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
atomic_json "$deployment_dir/deployment.json" \
  python3 "$checks" record \
  --plan "$deployment_dir/plan.json" \
  --releases "$deployment_dir/release-images.json" \
  --sub2api "$deployment_dir/sub2api-after-deploy.json" \
  --backup "$deployment_dir/backup.json" \
  --revisions "$deployment_dir/revisions.json" \
  --release-verification "$deployment_dir/release-verification.json" \
  --compose-config "$deployment_dir/compose-config.json" \
  --smoke-input "$deployment_dir/smoke-input.json" \
  --running "$deployment_dir/running-containers.json" \
  --smoke "$deployment_dir/production-smoke.txt" \
  --deployed-revision "$deployment_dir/alembic-current-after.txt" \
  --status deployed
write_status deployed
completed=1
echo "Production deployment admitted and recorded at $deployment_dir/deployment.json"
