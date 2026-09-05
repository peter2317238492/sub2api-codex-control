#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/../.." && pwd)
compose_file="$repo_root/deploy/docker-compose/compose.yaml"
overlay_file="$script_dir/compose.yaml"
port=${CONTROL_SMOKE_EDGE_BIND_PORT:-18092}
suffix="$$"
project="sub2api-codex-e2e-$suffix"
network="sub2api-codex-e2e-$suffix"
temporary=$(mktemp -d "${TMPDIR:-/tmp}/sub2api-codex-e2e.XXXXXX")
started_at=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
report_dir=${CONTROL_E2E_REPORT_DIR:-$repo_root/tests/e2e/reports}
report_file=${CONTROL_E2E_REPORT_FILE:-$report_dir/acceptance-$(date -u '+%Y%m%dT%H%M%SZ')-$suffix.json}
checks_file="$temporary/passed-checks.txt"
env_file="$temporary/e2e.env"
secret_dir="$temporary/secrets"
postgres_admin_password_file="$secret_dir/e2e_postgres_admin_password"
redis_admin_password_file="$secret_dir/e2e_redis_admin_password"
tls_dir="$temporary/tls"
tls_cert="$tls_dir/tls.crt"
tls_key="$tls_dir/tls.key"
workspace="$temporary/workspace"
codex_home="$temporary/codex-home"
connector_binary="$temporary/sub2api-codex-connector"
connector_config="$temporary/connector.json"
fake_codex="$temporary/codex"
fake_codex_audit_dir="$temporary/audit"
fake_codex_audit="$fake_codex_audit_dir/methods.log"
fake_codex_approval_audit="$fake_codex_audit_dir/approvals.jsonl"
fake_codex_state="$fake_codex_audit_dir/thread-state.json"
provider_key_canary_file="$fake_codex_audit_dir/sub2api-provider-key-canary"
device_id_file="$temporary/device-id"
thread_id_file="$temporary/thread-id"
workspace_sentinel="$workspace/ordinary-codex-state"
backup_dir="$temporary/backups"
started=0
stage=initialization
docker_version=unavailable
go_version=unavailable
connector_sha256=unavailable
source_revision=unavailable
source_manifest_sha256=unavailable
versions_lock_sha256=unavailable
control_protocol_sha256=unavailable
sub2api_auth_contract_sha256=unavailable
control_api_image_id=unavailable
pwa_image_id=unavailable
smoke_edge_image=sub2api-codex-control-smoke-edge:e2e

mkdir -p "$report_dir"
: > "$checks_file"

record_check() {
  printf '%s\n' "$1" >> "$checks_file"
}

write_report() {
  exit_status=$1
  report_status=failed
  [ "$exit_status" -eq 0 ] && report_status=passed
  finished_at=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
  if python3 "$script_dir/write_acceptance_report.py" \
    --output "$report_file" \
    --status "$report_status" \
    --stage "$stage" \
    --started-at "$started_at" \
    --finished-at "$finished_at" \
    --project "$project" \
    --checks-file "$checks_file" \
    --docker-version "$docker_version" \
    --go-version "$go_version" \
    --connector-sha256 "$connector_sha256" \
    --source-revision "$source_revision" \
    --source-manifest-sha256 "$source_manifest_sha256" \
    --versions-lock-sha256 "$versions_lock_sha256" \
    --control-protocol-sha256 "$control_protocol_sha256" \
    --sub2api-auth-contract-sha256 "$sub2api_auth_contract_sha256" \
    --control-api-image-id "$control_api_image_id" \
    --pwa-image-id "$pwa_image_id"; then
    return 0
  fi
  echo "run-local: could not write acceptance report $report_file" >&2
  return 1
}

cleanup() {
  status=$?
  trap - EXIT HUP INT TERM
  if ! write_report "$status"; then
    status=1
  fi
  echo "Acceptance report: $report_file"
  if [ "${KEEP_E2E:-0}" = "1" ]; then
    echo "Keeping E2E project $project and network $network for inspection."
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

if ! command -v docker >/dev/null 2>&1; then
  echo "run-local: docker is required" >&2
  exit 1
fi
if ! command -v python3 >/dev/null 2>&1; then
  echo "run-local: python3 is required" >&2
  exit 1
fi
if ! command -v go >/dev/null 2>&1; then
  echo "run-local: Go 1.24 or newer is required for the real Connector smoke" >&2
  exit 1
fi
if ! command -v openssl >/dev/null 2>&1; then
  echo "run-local: openssl is required for the local TLS edge" >&2
  exit 1
fi

pwa_port=${CONTROL_E2E_PWA_BIND_PORT:-}
if [ -z "$pwa_port" ]; then
  # Zero asks Docker to allocate the loopback port atomically when the
  # container starts; reading it back after `compose up` avoids a TOCTOU race.
  pwa_port=0
fi
case "$pwa_port" in
  ''|*[!0-9]*)
    echo "run-local: CONTROL_E2E_PWA_BIND_PORT must be a numeric TCP port" >&2
    exit 1
    ;;
esac
if [ "$pwa_port" -lt 0 ] || [ "$pwa_port" -gt 65535 ]; then
  echo "run-local: CONTROL_E2E_PWA_BIND_PORT must be between 0 and 65535" >&2
  exit 1
fi

docker_version=$(docker version --format '{{.Server.Version}}/{{.Server.Arch}}')
go_version=$(go version)
source_revision=$(git -C "$repo_root" rev-parse --verify HEAD 2>/dev/null \
  || printf '%s' 'unborn-uncommitted-worktree')
source_manifest_sha256=$(python3 "$script_dir/source_manifest.py" "$repo_root")
versions_lock_sha256=$(openssl dgst -sha256 "$repo_root/versions.lock.json" | awk 'NR == 1 {print $NF}')
control_protocol_sha256=$(openssl dgst -sha256 \
  "$repo_root/packages/control-protocol/schema/control-envelope.schema.json" \
  | awk 'NR == 1 {print $NF}')
sub2api_auth_contract_sha256=$(openssl dgst -sha256 \
  "$repo_root/docs/contracts/sub2api-auth.v0.2.1.json" \
  | awk 'NR == 1 {print $NF}')

mkdir -p \
  "$secret_dir" "$tls_dir" "$workspace" "$codex_home" \
  "$fake_codex_audit_dir" "$backup_dir"
SECRET_DIR="$secret_dir" "$repo_root/deploy/scripts/generate-secrets.sh"
umask 077
openssl rand -hex 32 > "$postgres_admin_password_file"
openssl rand -hex 32 > "$redis_admin_password_file"
chmod 0600 "$postgres_admin_password_file" "$redis_admin_password_file"
openssl req -x509 -newkey rsa:2048 -sha256 -days 1 -nodes \
  -subj "/CN=127.0.0.1" \
  -addext "subjectAltName=IP:127.0.0.1,DNS:smoke-edge" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,digitalSignature,keyEncipherment,keyCertSign" \
  -keyout "$tls_key" -out "$tls_cert" >/dev/null 2>&1
chmod 0644 "$tls_cert"
chmod 0600 "$tls_key"

cp "$script_dir/fake_codex.py" "$fake_codex"
chmod 0755 "$fake_codex"
: > "$fake_codex_audit"
: > "$fake_codex_approval_audit"
printf 'sub2api-provider-key-e2e-%s\n' "$(openssl rand -hex 24)" > "$provider_key_canary_file"
chmod 0600 "$provider_key_canary_file"
provider_key_canary=$(tr -d '\r\n' < "$provider_key_canary_file")
mkdir -p "$codex_home/plugins/diagnostic-plugin" "$codex_home/providers" "$codex_home/cache-empty"
printf '%s\n' \
  '[model_providers.sub2api]' \
  'base_url = "https://sub2api.invalid/v1"' \
  'env_key = "SUB2API_API_KEY"' \
  > "$codex_home/config.toml"
printf '%s\n' '{"OPENAI_API_KEY":"ordinary-auth-canary"}' > "$codex_home/auth.json"
printf '%s\n' '{"provider":"sub2api","credential":"ordinary-provider-canary"}' \
  > "$codex_home/providers/sub2api.json"
printf '%s\n' '{"name":"diagnostic-plugin","enabled":true}' \
  > "$codex_home/plugins/diagnostic-plugin/manifest.json"
ln -s plugins/diagnostic-plugin "$codex_home/active-plugin"
chmod 0700 "$codex_home" "$codex_home/plugins" "$codex_home/plugins/diagnostic-plugin" \
  "$codex_home/providers" "$codex_home/cache-empty"
chmod 0600 "$codex_home/config.toml" "$codex_home/auth.json" \
  "$codex_home/providers/sub2api.json" "$codex_home/plugins/diagnostic-plugin/manifest.json"
codex_home_manifest_before=$(python3 "$script_dir/tree_manifest.py" "$codex_home")
printf '%s\n' "ordinary Codex state must remain unchanged" > "$workspace_sentinel"
sentinel_before=$(openssl dgst -sha256 "$workspace_sentinel")

docker_arch=$(docker version --format '{{.Server.Arch}}')
case "$docker_arch" in
  arm64 | aarch64) go_arch=arm64 ;;
  amd64 | x86_64) go_arch=amd64 ;;
  *)
    echo "run-local: unsupported Docker architecture $docker_arch" >&2
    exit 1
    ;;
esac
stage=connector-approval-policy-tests-and-build
(
  cd "$repo_root/connector"
  go test -race -count=1 \
    -run '^(TestApprovalIsBoundToEpoch|TestApprovalTimeoutDefaultsToDecline|TestPermissionApprovalReturnsValidatedTurnGrant|TestDisconnectDeniesPendingAndNewApprovals|TestOversizedOrDeepApprovalFailsBeforeEmission|TestFileChangeApprovalProjectsOperationsWithoutContentsOrDiffs|TestApprovalPayloadBudgetIncludesEnvelope)$' \
    ./internal/approval
)
record_check connector-approval-epoch-timeout-disconnect-and-redacted-projection-guards
(
  cd "$repo_root/connector"
  CGO_ENABLED=0 GOOS=linux GOARCH="$go_arch" go build -trimpath \
    -o "$connector_binary" ./cmd/connector
)
connector_sha256=$(openssl dgst -sha256 "$connector_binary" | awk 'NR == 1 {print $NF}')

cat > "$connector_config" <<EOF
{
  "control_url": "wss://smoke-edge:8443/codex-ws/device",
  "pairing_url": "https://smoke-edge:8443/codex-api/v1/device-pairings/start",
  "token_url": "https://smoke-edge:8443/codex-api/v1/device/connect-token",
  "display_name": "E2E Connector",
  "state_dir": "/state",
  "workspace_roots": ["/workspace"],
  "sandbox_cap": "workspace-write",
  "codex_binary": "/e2e/codex",
  "codex_version": "0.147.0",
  "schema_digest": "511c1b3ca038a80740a5a41ca10a7f925c0f744e582fb9aaa03cc46c6e98b80b",
  "heartbeat_interval": "5s",
  "approval_timeout": "6s",
  "pairing_poll_interval": "500ms",
  "reconnect_min": "200ms",
  "reconnect_max": "2s"
}
EOF
chmod 0600 "$connector_config"

# The base Compose file requires packaged Connector release metadata; give the
# stack a shape-valid Linux-matrix fixture so the real admission path runs.
connector_release_metadata=$(python3 - <<'E2E_METADATA_PY'
import json

repository = "https://github.com/peter2317238492/sub2api-codex-control"
version = "0.1.11"
tag = f"connector-v{version}"
assets = []
for index, (arch, package_format) in enumerate(
    (("amd64", "deb"), ("amd64", "rpm"), ("arm64", "deb"), ("arm64", "rpm")),
    start=1,
):
    filename = f"sub2api-codex-connector_{version}_linux_{arch}.{package_format}"
    assets.append(
        {
            "os": "linux",
            "arch": arch,
            "package_format": package_format,
            "filename": filename,
            "download_url": f"{repository}/releases/download/{tag}/{filename}",
            "sha256": f"{index:064x}",
            "size": 1000 + index,
            "signature_bundle": f"{filename}.sigstore.json",
            "sbom": {
                "format": "SPDX-2.3-json",
                "filename": f"{filename}.spdx.json",
                "sha256": f"{index + 10:064x}",
                "size": 2000 + index,
                "signature_bundle": f"{filename}.spdx.json.sigstore.json",
            },
            "provenance": {
                "predicate_type": "https://slsa.dev/provenance/v1",
                "filename": f"{filename}.intoto.json",
                "sha256": f"{index + 20:064x}",
                "size": 3000 + index,
                "signature_bundle": f"{filename}.intoto.json.sigstore.json",
                "attestation_bundle": f"{filename}.intoto.sigstore.json",
            },
        }
    )
print(
    json.dumps(
        {
            "format_version": 1,
            "release_mode": "release",
            "releasable": True,
            "source_repository": repository,
            "source_commit": "a" * 40,
            "version": version,
            "tag": tag,
            "codex_version": "0.147.0",
            "schema_digest": "511c1b3ca038a80740a5a41ca10a7f925c0f744e582fb9aaa03cc46c6e98b80b",
            "manifest": {
                "filename": "manifest.json",
                "sha256": "b" * 64,
                "size": 4000,
                "signature_bundle": "manifest.json.sigstore.json",
            },
            "config_path_hint": "~/.config/sub2api-codex-connector/connector.json",
            "pair_command": "sub2api-codex-connector-ctl pair",
            "start_command": "sub2api-codex-connector-ctl start",
            "assets": assets,
        },
        separators=(",", ":"),
    )
)
E2E_METADATA_PY
)

cat > "$env_file" <<EOF
CONTROL_RELEASE=0.1.0-e2e
CONTROL_CONNECTOR_RELEASE_METADATA_JSON=$connector_release_metadata
CONTROL_VCS_REF=e2e
CONTROL_PUBLIC_ORIGIN=https://127.0.0.1:$port
CONTROL_BIND_ADDRESS=127.0.0.1
CONTROL_PWA_BIND_PORT=$pwa_port
CONTROL_SMOKE_EDGE_BIND_PORT=$port
CONTROL_API_IMAGE=sub2api-codex-control-api:e2e
CONTROL_PWA_IMAGE=sub2api-codex-control-pwa:e2e
CONTROL_SMOKE_EDGE_IMAGE=$smoke_edge_image
SUB2API_NETWORK_NAME=$network
SUB2API_INTERNAL_URL=http://sub2api:8080
CONTROL_DB_HOST=postgres
CONTROL_DB_PORT=5432
CONTROL_DB_USER=codex_control
CONTROL_DB_NAME=codex_control
CONTROL_REDIS_SCHEME=redis
CONTROL_REDIS_HOST=redis
CONTROL_REDIS_PORT=6379
CONTROL_REDIS_USER=codex_control
CONTROL_REDIS_DATABASE=0
CONTROL_REDIS_PREFIX=codex-control:
CONTROL_BACKUP_DIR=$backup_dir
CONTROL_DATABASE_PASSWORD_SECRET_FILE=$secret_dir/control_db_password
CONTROL_REDIS_PASSWORD_SECRET_FILE=$secret_dir/control_redis_password
CONTROL_SESSION_HMAC_SECRET_FILE=$secret_dir/control_session_hmac_secret
E2E_POSTGRES_ADMIN_PASSWORD_SECRET_FILE=$postgres_admin_password_file
E2E_REDIS_ADMIN_PASSWORD_SECRET_FILE=$redis_admin_password_file
E2E_ROOT=$repo_root
E2E_TLS_CERT=$tls_cert
E2E_TLS_KEY=$tls_key
E2E_CONNECTOR_BINARY=$connector_binary
E2E_CONNECTOR_CONFIG=$connector_config
E2E_CONNECTOR_CODEX_HOME=$codex_home
E2E_CONNECTOR_WORKSPACE=$workspace
E2E_FAKE_CODEX=$fake_codex
E2E_FAKE_CODEX_AUDIT_DIR=$fake_codex_audit_dir
EOF
chmod 0600 "$env_file"

docker network create "$network" >/dev/null
started=1

compose() {
  docker compose --project-name "$project" --env-file "$env_file" \
    -f "$compose_file" -f "$overlay_file" \
    --profile smoke --profile multi-instance --profile ops "$@"
}

assert_connector_no_tcp_listeners() {
  compose exec -T connector python - <<'PY'
import os
from pathlib import Path

owned_socket_inodes = set()
for process_dir in Path("/proc").glob("[0-9]*"):
    fd_dir = process_dir / "fd"
    try:
        descriptors = list(fd_dir.iterdir())
    except (FileNotFoundError, PermissionError):
        continue
    for descriptor in descriptors:
        try:
            target = os.readlink(descriptor)
        except (FileNotFoundError, PermissionError):
            continue
        if target.startswith("socket:[") and target.endswith("]"):
            owned_socket_inodes.add(target[8:-1])

listeners = []
for source in ("/proc/net/tcp", "/proc/net/tcp6"):
    path = Path(source)
    if not path.exists():
        continue
    for line in path.read_text(encoding="ascii").splitlines()[1:]:
        fields = line.split()
        # Docker's 127.0.0.11 DNS proxy appears in the namespace tables but has
        # no file descriptor in the container. Only process-owned sockets can
        # represent an inbound listener opened by the Connector or its child.
        if len(fields) >= 10 and fields[3] == "0A" and fields[9] in owned_socket_inodes:
            listeners.append({"source": source, "local": fields[1], "inode": fields[9]})
if listeners:
    raise SystemExit(f"Connector network namespace has TCP listeners: {listeners}")
print("Connector network namespace has no TCP listeners.")
PY
}

read_connector_pairing_code() {
  compose exec -T connector python - <<'PY'
import json
import pathlib
import stat

path = pathlib.Path("/state/pairing-code.json")
if stat.S_IMODE(path.stat().st_mode) != 0o600:
    raise SystemExit("pairing-code.json is not mode 0600")
payload = json.loads(path.read_text(encoding="utf-8"))
code = payload.get("code")
expires_at = payload.get("expires_at")
if not isinstance(code, str) or not code or not isinstance(expires_at, str) or not expires_at:
    raise SystemExit("invalid pairing-code.json")
print(code)
PY
}

connector_pairing_file_state() {
  compose exec -T connector python - <<'PY'
import pathlib

print(
    "present"
    if any(
        pathlib.Path(path).exists()
        for path in ("/state/pairing-code.json", "/state/pairing-code.json.tmp")
    )
    else "absent"
)
PY
}

stage=configuration-validation
compose config --quiet
docker run --rm --read-only --tmpfs /tmp:rw,noexec,nosuid,nodev,size=16m \
  --tmpfs /var/log/sub2api-codex-control:rw,noexec,nosuid,nodev,size=1m \
  --volume "$repo_root/deploy/nginx:/etc/nginx/codex:ro" \
  --volume "$script_dir/nginx-production.conf:/etc/nginx/nginx.conf:ro" \
  nginx:1.28-alpine@sha256:a8b39bd9cf0f83869a2162827a0caf6137ddf759d50a171451b335cecc87d236 nginx -t
docker run --rm --read-only --tmpfs /tmp:rw,noexec,nosuid,nodev,size=16m \
  --tmpfs /var/log/sub2api-codex-control:rw,noexec,nosuid,nodev,size=1m \
  --entrypoint nginx \
  --add-host control-api:127.0.0.1 \
  --add-host control-api-replica:127.0.0.1 \
  --add-host codex-pwa:127.0.0.1 \
  --volume "$repo_root/deploy/nginx:/etc/nginx/codex:ro" \
  --volume "$script_dir/nginx-tls.conf:/etc/nginx/nginx.conf:ro" \
  --volume "$tls_dir:/run/e2e-tls:ro" \
  nginx:1.28-alpine@sha256:a8b39bd9cf0f83869a2162827a0caf6137ddf759d50a171451b335cecc87d236 -t
sh "$script_dir/test-sub2api-logout-nginx.sh"
record_check "authenticated logout multi-header proxy-buffer regression"

# The source-mounted checks above validate the complete Nginx configuration.
# These image checks ensure every referenced include was actually packaged.
compose build smoke-edge
smoke_edge_image_id=$(docker image inspect --format '{{.Id}}' "$smoke_edge_image")
[ -n "$smoke_edge_image_id" ] || {
  echo "run-local: Docker did not return the built smoke-edge image ID" >&2
  exit 1
}
docker run --rm --read-only --tmpfs /tmp:rw,noexec,nosuid,nodev,size=16m \
  --entrypoint nginx \
  --add-host control-api:127.0.0.1 \
  --add-host control-api-replica:127.0.0.1 \
  --add-host codex-pwa:127.0.0.1 \
  "$smoke_edge_image_id" -t
docker run --rm --read-only --tmpfs /tmp:rw,noexec,nosuid,nodev,size=16m \
  --entrypoint nginx \
  --add-host control-api:127.0.0.1 \
  --add-host control-api-replica:127.0.0.1 \
  --add-host codex-pwa:127.0.0.1 \
  --volume "$script_dir/nginx-tls.conf:/etc/nginx/nginx.conf:ro" \
  --volume "$tls_dir:/run/e2e-tls:ro" \
  "$smoke_edge_image_id" -t
record_check compose-source-and-packaged-nginx-configuration

stage=datastore-provisioning
compose up -d --wait postgres redis sub2api
compose run --rm postgres-provision
compose run --rm redis-provision

postgres_security=$(compose run --rm --no-deps --entrypoint sh postgres-provision -ec '
  export PGPASSWORD="$(tr -d "\r\n" < /run/secrets/e2e_postgres_admin_password)"
  psql --no-psqlrc --set ON_ERROR_STOP=1 --tuples-only --no-align \
    --host postgres --username postgres --dbname postgres --command \
  "SELECT rolsuper, rolcreaterole, rolcreatedb, rolreplication, rolbypassrls, rolinherit,
            (SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname = '\''codex_control'\''),
            (SELECT count(*) FROM pg_auth_members
              WHERE member = (SELECT oid FROM pg_roles WHERE rolname = '\''codex_control'\'')
                 OR roleid = (SELECT oid FROM pg_roles WHERE rolname = '\''codex_control'\'')),
            has_database_privilege('\''codex_control'\'', '\''sub2api'\'', '\''CONNECT'\'')
       FROM pg_roles WHERE rolname = '\''codex_control'\'';"
')
if [ "$postgres_security" != "f|f|f|f|f|f|codex_control|0|f" ]; then
  echo "PostgreSQL Control role/database isolation assertion failed: $postgres_security" >&2
  exit 1
fi
if compose run --rm --no-deps --entrypoint sh postgres-provision -ec '
  export PGPASSWORD="$(tr -d "\r\n" < /run/secrets/control_db_password)"
  exec psql --no-psqlrc --set ON_ERROR_STOP=1 --host postgres \
    --username codex_control --dbname sub2api --command "SELECT 1"
' >/dev/null 2>&1; then
  echo "PostgreSQL Control role unexpectedly connected to the Sub2API database" >&2
  exit 1
fi
control_identity=$(compose run --rm --no-deps --entrypoint sh postgres-provision -ec '
  export PGPASSWORD="$(tr -d "\r\n" < /run/secrets/control_db_password)"
  exec psql --no-psqlrc --set ON_ERROR_STOP=1 --tuples-only --no-align \
    --host postgres --username codex_control --dbname codex_control \
    --command "SELECT current_user"
')
if [ "$control_identity" != "codex_control" ]; then
  echo "PostgreSQL runtime identity assertion failed: $control_identity" >&2
  exit 1
fi
record_check postgres-dedicated-role-database-and-sub2api-denial

redis_acl=$(compose run --rm --no-deps --entrypoint sh redis-provision -ec '
  export REDISCLI_AUTH="$(tr -d "\r\n" < /run/secrets/e2e_redis_admin_password)"
  exec redis-cli -h redis --user default --no-auth-warning ACL GETUSER codex_control
')
case "$redis_acl" in
  *'~codex-control:'*'&codex-control:'*) ;;
  *)
    echo "Redis ACL does not contain the dedicated key/channel namespace" >&2
    exit 1
    ;;
esac
redis_runtime_check=$(compose run --rm --no-deps --entrypoint sh redis-provision -ec '
  export REDISCLI_AUTH="$(tr -d "\r\n" < /run/secrets/control_redis_password)"
  allowed=$(redis-cli -h redis --user codex_control --no-auth-warning --raw \
    SET codex-control:e2e-isolation allowed)
  value=$(redis-cli -h redis --user codex_control --no-auth-warning --raw \
    GET codex-control:e2e-isolation)
  denied_key=$(redis-cli -h redis --user codex_control --no-auth-warning --raw \
    SET outside-prefix denied 2>&1 || true)
  denied_channel=$(redis-cli -h redis --user codex_control --no-auth-warning --raw \
    PUBLISH outside-prefix denied 2>&1 || true)
  if [ "$allowed" != OK ] || [ "$value" != allowed ]; then
    exit 2
  fi
  case "$denied_key" in *NOPERM*) ;; *) exit 3 ;; esac
  case "$denied_channel" in *NOPERM*) ;; *) exit 4 ;; esac
  printf dedicated-acl-enforced
')
if [ "$redis_runtime_check" != "dedicated-acl-enforced" ]; then
  echo "Redis runtime ACL isolation assertion failed" >&2
  exit 1
fi
record_check redis-dedicated-acl-key-and-channel-prefix

stage=migration-and-service-start
compose up --build --exit-code-from control-migrate control-migrate
compose up -d --build --wait control-api control-api-replica codex-pwa smoke-edge
pwa_container=$(compose ps --status running -q codex-pwa)
if [ -z "$pwa_container" ]; then
  echo "Compose did not return the running PWA container" >&2
  exit 1
fi
if [ "$pwa_port" -eq 0 ]; then
  pwa_port=$(docker inspect --format '{{(index (index .NetworkSettings.Ports "8080/tcp") 0).HostPort}}' "$pwa_container")
fi
case "$pwa_port" in
  ''|*[!0-9]*)
    echo "Docker did not return a numeric PWA loopback port" >&2
    exit 1
    ;;
esac
if [ "$pwa_port" -lt 1 ] || [ "$pwa_port" -gt 65535 ]; then
  echo "Docker returned an out-of-range PWA loopback port" >&2
  exit 1
fi
python3 - "$pwa_port" <<'PY'
import http.client
import sys

connection = http.client.HTTPConnection("127.0.0.1", int(sys.argv[1]), timeout=5)
try:
    connection.request("GET", "/healthz", headers={"Connection": "close"})
    response = connection.getresponse()
    body = response.read(65_537)
finally:
    connection.close()
if response.status != 200 or body != b"ok\n":
    raise SystemExit(
        f"PWA loopback health contract failed: status={response.status}, body={body!r}"
    )
PY
record_check pwa-random-loopback-host-port-healthz
primary_api_container=$(compose ps --status running -q control-api)
replica_api_container=$(compose ps --status running -q control-api-replica)
control_api_image_id=$(docker inspect --format '{{.Image}}' "$primary_api_container")
replica_api_image_id=$(docker inspect --format '{{.Image}}' "$replica_api_container")
pwa_image_id=$(docker inspect --format '{{.Image}}' "$pwa_container")
if [ "$control_api_image_id" != "$replica_api_image_id" ]; then
  echo "Control API instances are not running the same image" >&2
  exit 1
fi
if compose exec -T codex-pwa sh -ec '
  needle=$(cat)
  grep -R -F -q "$needle" /usr/share/nginx/html/codex
' < "$provider_key_canary_file"; then
  echo "Raw Sub2API provider-key canary was embedded in the built PWA" >&2
  exit 1
fi
metrics_output=$(compose exec -T control-api python -c '
import hashlib
import hmac
import os
import pathlib
import sys
import urllib.request

secret_file = pathlib.Path(os.environ["CONTROL_SESSION_HMAC_SECRET_FILE"])
secret = secret_file.read_bytes().rstrip(b"\r\n")
token = hmac.new(secret, b"control-metrics-v1", hashlib.sha256).hexdigest()
request = urllib.request.Request(
    "http://127.0.0.1:8090/internal/metrics",
    headers={"Authorization": f"Bearer {token}"},
)
with urllib.request.urlopen(request, timeout=5) as response:
    if response.status != 200 or response.headers.get("Cache-Control") != "no-store":
        raise SystemExit("internal metrics response contract failed")
    sys.stdout.write(response.read().decode())
')
printf '%s\n' "$metrics_output" | grep -Fq 'codex_control_build_info{vcs_ref="e2e",version="0.1.0-e2e"} 1'
printf '%s\n' "$metrics_output" | grep -Fq 'codex_control_sessions_active 0'
echo "Authenticated internal metrics scrape passed through the loopback API."
record_check authenticated-internal-metrics-and-public-denial
compose run --rm --no-deps \
  --entrypoint /opt/venv/bin/python \
  --volume "$repo_root:/workspace:ro" \
  control-api \
  /workspace/tests/e2e/run_postgres_migration_guard.py \
  /workspace/apps/control-api/tests/test_postgres_migration_guards.py
record_check real-postgresql-migration-guards
record_check real-postgresql-retention-preserves-unacked-outbox-and-fk-audit-history

stage=connector-pairing
compose up -d --no-deps connector

pairing_code=""
attempts=0
while [ -z "$pairing_code" ] && [ "$attempts" -lt 200 ]; do
  if [ "$(compose ps --status exited -q connector)" ]; then
    echo "Connector exited before pairing:" >&2
    compose logs --no-color connector >&2
    exit 1
  fi
  pairing_code=$(read_connector_pairing_code 2>/dev/null || true)
  attempts=$((attempts + 1))
  [ -n "$pairing_code" ] || sleep 0.1
done
if [ -z "$pairing_code" ]; then
  echo "Timed out waiting for Connector pairing code" >&2
  compose logs --no-color connector >&2
  exit 1
fi

if compose logs --no-color connector 2>&1 | grep -Fq "$pairing_code"; then
  echo "Connector leaked the one-time pairing code into routine logs" >&2
  exit 1
fi
record_check private-mode0600-pairing-code-file-with-no-log-leak

sleep 0.2
connector_container=$(compose ps --status running -q connector)
if [ -z "$connector_container" ]; then
  echo "Connector exited after creating the pairing ticket:" >&2
  compose logs --no-color connector >&2
  exit 1
fi
connector_ports=$(docker inspect --format '{{json .NetworkSettings.Ports}}' "$connector_container")
if [ "$connector_ports" != "{}" ] && [ "$connector_ports" != "null" ]; then
  echo "Connector container unexpectedly publishes a port" >&2
  exit 1
fi
assert_connector_no_tcp_listeners
record_check connector-no-published-or-actual-tcp-listeners

stage=two-instance-control-flow
python3 "$script_dir/smoke.py" \
  --base-url "https://127.0.0.1:$port" \
  --access-token e2e-access-token-value \
  --insecure \
  --expect-secure-cookie \
  --pairing-code "$pairing_code" \
  --workspace-root /workspace \
  --keep-device \
  --expect-cross-instance-fanout \
  --provider-key-canary-file "$provider_key_canary_file" \
  --device-id-file "$device_id_file" \
  --thread-id-file "$thread_id_file"
record_check same-origin-session-csrf-csp-service-worker-and-dangerous-routes-fail-closed
record_check unauthenticated-session-device-thread-command-and-approval-surfaces-denied
record_check dangerous-shell-exec-fs-process-config-plugin-account-oauth-and-raw-rpc-routes-fail-closed

attempts=0
pairing_file_state=$(connector_pairing_file_state)
while [ "$pairing_file_state" = "present" ]; do
  attempts=$((attempts + 1))
  if [ "$attempts" -ge 100 ]; then
    echo "Connector did not remove the one-time pairing code file after claim" >&2
    exit 1
  fi
  sleep 0.1
  pairing_file_state=$(connector_pairing_file_state)
done
[ "$pairing_file_state" = "absent" ] || {
  echo "Connector returned an invalid pairing-file state" >&2
  exit 1
}
record_check pairing-code-file-removed-after-claim
assert_connector_no_tcp_listeners
device_id=$(tr -d '\r\n' < "$device_id_file")
thread_id=$(tr -d '\r\n' < "$thread_id_file")

python3 - "$fake_codex_audit" <<'PY'
import pathlib
import sys
import time

expected = {
    "model/list",
    "thread/start",
    "thread/list",
    "thread/read",
    "thread/resume",
    "turn/start",
    "turn/steer",
    "turn/interrupt",
}
path = pathlib.Path(sys.argv[1])
deadline = time.monotonic() + 10
observed = set()
while time.monotonic() < deadline:
    observed = {line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()}
    if expected <= observed:
        break
    time.sleep(0.2)
missing = sorted(expected - observed)
unexpected = sorted(observed - expected)
if missing or unexpected:
    raise SystemExit(f"fake Codex RPC audit mismatch: missing={missing}, unexpected={unexpected}")
print("Real Connector dispatched exactly the eight admitted RPC method classes to the fake stdio fixture.")
PY

python3 - "$fake_codex_state" "$provider_key_canary_file" "$codex_home" <<'PY'
import json
import pathlib
import stat
import sys

state_path = pathlib.Path(sys.argv[1])
provider_key = pathlib.Path(sys.argv[2]).read_text(encoding="utf-8").strip()
codex_home = pathlib.Path(sys.argv[3])
try:
    state_path.resolve(strict=True).relative_to(codex_home.resolve(strict=True))
except ValueError:
    pass
else:
    raise SystemExit("fake Codex thread state was stored inside CODEX_HOME")
metadata = state_path.lstat()
if not stat.S_ISREG(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o600:
    raise SystemExit("fake Codex thread state is not a private regular file")
if metadata.st_size > 1 << 20:
    raise SystemExit("fake Codex thread state exceeded its one-MiB bound")
raw = state_path.read_text(encoding="utf-8")
for forbidden in (
    provider_key,
    "COMMAND-SECRET-MUST-NOT-CROSS",
    "COMMAND-OUTPUT-MUST-NOT-CROSS",
    "PERMISSION-ENVIRONMENT-ID-MUST-NOT-CROSS",
):
    if forbidden and forbidden in raw:
        raise SystemExit("fake Codex thread state persisted a protected canary")
payload = json.loads(raw)
if not isinstance(payload, dict):
    raise SystemExit("fake Codex thread state was not a JSON object")
threads = payload.get("threads")
if (
    payload.get("schema_version") != 1
    or payload.get("next_thread") != 2
    or payload.get("next_turn") != 2
    or not isinstance(threads, list)
    or len(threads) != 1
    or threads[0].get("id") != "e2e-thread-1"
    or threads[0].get("status") != "idle"
    or threads[0].get("active_turn_id") is not None
    or len(threads[0].get("turns", [])) != 1
    or threads[0]["turns"][0].get("status") != "completed"
):
    raise SystemExit("fake Codex thread state did not contain the completed managed thread")
print("Fake Codex persisted one bounded, completed managed thread outside CODEX_HOME.")
PY
record_check bounded-private-fake-thread-state-outside-codex-home-without-protected-canaries
record_check exact-eight-rpc-classes-through-real-connector-and-fake-stdio
record_check deterministic-two-instance-device-dispatch-and-browser-fanout
record_check atomic-thread-detail-watermark-and-duplicate-free-browser-event-cursors

python3 - "$fake_codex_approval_audit" <<'PY'
import json
import pathlib
import sys
import time

expected = [
    {"kind": "command", "outcome": "approved"},
    {"kind": "file_change", "outcome": "denied"},
    {"kind": "permission", "outcome": "timeout_default_deny"},
]
path = pathlib.Path(sys.argv[1])
deadline = time.monotonic() + 10
observed = []
while time.monotonic() < deadline:
    observed = [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    if observed == expected:
        break
    time.sleep(0.2)
if observed != expected:
    raise SystemExit(f"fake Codex approval audit mismatch: {observed!r}")
print("Fake Codex received explicit approve, explicit deny, and timeout default-deny outcomes.")
PY

expected_approval_state=$(printf '%s\n' \
  'command|approved|user_approved|true' \
  'file_change|denied|user_denied|true' \
  'permission|denied|timeout_default_deny|true')
approval_state=""
attempts=0
while [ "$approval_state" != "$expected_approval_state" ] && [ "$attempts" -lt 100 ]; do
  approval_state=$(compose exec -T postgres psql \
    --username codex_control --dbname codex_control \
    --no-psqlrc --tuples-only --no-align \
    --command "SELECT approval_kind || '|' || status || '|' || decision_reason || '|' ||
      (decision_dispatched_at IS NOT NULL)::text
      FROM approvals
      WHERE device_id = '$device_id'::uuid
      ORDER BY approval_kind" | tr -d '\r')
  attempts=$((attempts + 1))
  [ "$approval_state" = "$expected_approval_state" ] || sleep 0.1
done
if [ "$approval_state" != "$expected_approval_state" ]; then
  echo "Approval lifecycle persistence mismatch:" >&2
  printf '%s\n' "$approval_state" >&2
  exit 1
fi
record_check command-approval-bounded-redacted-pending-and-explicit-approve
record_check file-change-approval-bounded-redacted-pending-and-explicit-deny
record_check permission-approval-bounded-redacted-pending-and-timeout-default-deny

compose run --rm --no-deps \
  --entrypoint /opt/venv/bin/python \
  --volume "$repo_root:/workspace:ro" \
  control-api \
  /workspace/tests/e2e/run_postgres_approval_guards.py "$device_id"
record_check postgresql-stale-epoch-default-deny-is-atomic-and-single-claim
record_check postgresql-disconnect-default-deny-is-idempotent-and-preserves-dispatched-decisions

database_dump="$temporary/control.sql"
compose run --rm --no-deps --entrypoint sh postgres-provision -ec \
  'export PGPASSWORD="$(cat /run/secrets/control_db_password)"; exec pg_dump -h postgres -U codex_control -d codex_control' \
  > "$database_dump"
if grep -Fq "e2e-access-token-value" "$database_dump"; then
  echo "Raw Sub2API access token was persisted in the Control database" >&2
  exit 1
fi
record_check database-does-not-persist-raw-sub2api-access-token
if grep -Fq "$provider_key_canary" "$database_dump"; then
  echo "Raw Sub2API provider-key canary was persisted in the Control database" >&2
  exit 1
fi
for approval_secret in \
  COMMAND-SECRET-MUST-NOT-CROSS \
  COMMAND-OUTPUT-MUST-NOT-CROSS \
  PERMISSION-ENVIRONMENT-ID-MUST-NOT-CROSS; do
  if grep -Fq "$approval_secret" "$database_dump"; then
    echo "Unprojected approval content was persisted in the Control database" >&2
    exit 1
  fi
done
record_check approval-projections-do-not-persist-local-command-actions-or-environment-identifiers

inspect_file="$temporary/containers.json"
docker inspect $(compose ps -q postgres redis sub2api control-api control-api-replica codex-pwa smoke-edge connector) > "$inspect_file"
if grep -Fq "$provider_key_canary" "$inspect_file"; then
  echo "Raw Sub2API provider-key canary was exposed in container metadata" >&2
  exit 1
fi
for secret_file in "$secret_dir"/*; do
  secret_value=$(tr -d '\r\n' < "$secret_file")
  if [ -n "$secret_value" ] && grep -Fq "$secret_value" "$inspect_file"; then
    echo "A generated secret was exposed in container metadata" >&2
    exit 1
  fi
done
record_check generated-secrets-absent-from-container-metadata
record_check provider-key-canary-absent-from-pwa-http-websocket-database-and-container-metadata

stage=backup-and-disposable-restore
compose stop -t 15 connector control-api control-api-replica >/dev/null
E2E_COMPOSE_PROJECT_NAME="$project" \
E2E_COMPOSE_ENV_FILE="$env_file" \
E2E_BACKUP_REHEARSAL_DIR="$backup_dir" \
E2E_EXPECTED_DEVICE_ID="$device_id" \
  "$script_dir/rehearse-backup-restore.sh"
record_check checksummed-backup-and-disposable-restore-rehearsal

compose up -d --wait control-api control-api-replica smoke-edge >/dev/null
# The API containers can be recreated by the restore rehearsal. Nginx resolves
# Compose service names when its workers start, so restart it after the new API
# containers are healthy before collecting deterministic upstream evidence.
compose restart smoke-edge >/dev/null
compose up -d --wait smoke-edge >/dev/null
compose up -d --no-deps connector >/dev/null
attempts=0
connected_count=0
while [ "$connected_count" != "1" ] && [ "$attempts" -lt 100 ]; do
  connected_count=$(compose exec -T postgres psql \
    --username codex_control --dbname codex_control \
    --no-psqlrc --tuples-only --no-align \
    --command "SELECT count(*) FROM devices
      WHERE id = '$device_id'::uuid AND active_connection_nonce IS NOT NULL" \
    | tr -d '[:space:]')
  attempts=$((attempts + 1))
  [ "$connected_count" = "1" ] || sleep 0.2
done
if [ "$connected_count" != "1" ]; then
  echo "Connector did not reconnect after the backup maintenance stop" >&2
  compose logs --no-color connector control-api-replica >&2
  exit 1
fi
record_check connector-reconnect-after-backup-maintenance-stop

stage=replica-kill-and-device-reconnect
compose restart control-api-replica >/dev/null
compose up -d --wait control-api-replica smoke-edge >/dev/null
python3 "$script_dir/smoke.py" \
  --base-url "https://127.0.0.1:$port" \
  --access-token e2e-access-token-value \
  --insecure \
  --expect-secure-cookie \
  --expected-device-id "$device_id" \
  --expected-thread-id "$thread_id" \
  --workspace-root /workspace \
  --expect-cross-instance-fanout \
  --provider-key-canary-file "$provider_key_canary_file" \
  --reconnect-only
revoked_device_state=$(compose exec -T postgres psql \
  --username codex_control --dbname codex_control \
  --no-psqlrc --tuples-only --no-align \
  --command "SELECT status::text || '|' ||
    (refresh_credential_hash IS NULL)::text || '|' ||
    (active_epoch IS NULL)::text || '|' ||
    (active_connection_nonce IS NULL)::text || '|' ||
    (SELECT count(*) FROM device_connections
      WHERE device_id = devices.id AND status = 'connected')::text
    FROM devices WHERE id = '$device_id'::uuid" | tr -d '[:space:]')
if [ "$revoked_device_state" != "revoked|true|true|true|0" ]; then
  echo "Revoked device retained an active credential or connection: $revoked_device_state" >&2
  exit 1
fi
record_check device-reconnect-after-device-api-replica-restart
record_check thread-resume-and-read-succeed-after-connector-app-server-child-restart
record_check post-restart-thread-identity-cwd-idle-state-and-history-preserved
record_check revoked-device-hidden-with-credentials-and-connections-cleared

stage=connector-coexistence-and-edge-log-audit
compose stop -t 15 connector >/dev/null
if [ "$(compose ps --status running -q connector)" ]; then
  echo "Connector did not stop cleanly" >&2
  exit 1
fi
sentinel_after=$(openssl dgst -sha256 "$workspace_sentinel")
if [ "$sentinel_before" != "$sentinel_after" ]; then
  echo "Connector modified ordinary Codex/workspace state" >&2
  exit 1
fi
codex_home_manifest_after=$(python3 "$script_dir/tree_manifest.py" "$codex_home")
if [ "$codex_home_manifest_before" != "$codex_home_manifest_after" ]; then
  echo "Connector modified the ordinary Codex home tree" >&2
  echo "Started with: $codex_home_manifest_before" >&2
  echo "Finished with: $codex_home_manifest_after" >&2
  exit 1
fi
if [ "$(FAKE_CODEX_AUDIT_LOG="$fake_codex_audit" "$fake_codex" --version)" != "codex-cli 0.147.0" ]; then
  echo "Stopping Connector affected the ordinary Codex executable" >&2
  exit 1
fi
record_check stopping-connector-preserves-workspace-and-complete-codex-home-tree

nginx_log_probe="$temporary/nginx-access-log-probe.json"
python3 - "$port" "$nginx_log_probe" <<'PY'
import json
import pathlib
import secrets
import ssl
import sys
import urllib.error
import urllib.request

context = ssl._create_unverified_context()
nonce = secrets.token_hex(16)
markers = {
    "query": f"acceptance_query_secret-{nonce}",
    "referer": f"acceptance_referer_secret-{nonce}",
    "user_agent": f"acceptance_user_agent_secret-{nonce}",
    "authorization": f"acceptance_authorization_secret-{nonce}",
    "cookie": f"acceptance_cookie_secret-{nonce}",
    "exact_ws": f"acceptance_exact_ws_secret-{nonce}",
    "catchall": f"acceptance_codex_catchall_secret-{nonce}",
}
probe_uris = {
    "exact_ws": "/codex-ws",
    "catchall": f"/codex-redaction-probe-{nonce}",
}

for path, marker in (
    (probe_uris["exact_ws"], markers["exact_ws"]),
    (probe_uris["catchall"], markers["catchall"]),
):
    try:
        urllib.request.urlopen(
            f"https://127.0.0.1:{sys.argv[1]}{path}?probe={marker}",
            context=context,
            timeout=5,
        )
    except urllib.error.HTTPError as error:
        if error.code != 404:
            raise SystemExit(f"{path} returned {error.code}, expected 404") from error
    else:
        raise SystemExit(f"{path} unexpectedly succeeded")

request = urllib.request.Request(
    f"https://127.0.0.1:{sys.argv[1]}/codex-api/v1/health/live?probe={markers['query']}",
    headers={
        "Referer": f"https://referrer.invalid/?probe={markers['referer']}",
        "User-Agent": markers["user_agent"],
        "Authorization": f"Bearer {markers['authorization']}",
        "Cookie": f"acceptance_cookie={markers['cookie']}",
    },
)
with urllib.request.urlopen(
    request,
    context=context,
    timeout=5,
) as response:
    if response.status != 200:
        raise SystemExit("query-log probe did not reach the Control API")
    request_id = response.headers.get("X-Request-ID", "")
    if not request_id or len(request_id) > 128:
        raise SystemExit("query-log probe did not return a bounded X-Request-ID")
pathlib.Path(sys.argv[2]).write_text(
    json.dumps(
        {"markers": markers, "request_id": request_id, "uris": probe_uris},
        sort_keys=True,
        separators=(",", ":"),
    )
    + "\n",
    encoding="utf-8",
)
PY

edge_container=$(compose ps --status running -q smoke-edge)
primary_container=$(compose ps --status running -q control-api)
replica_container=$(compose ps --status running -q control-api-replica)
edge_log="$temporary/smoke-edge.log"
route_inspect="$temporary/api-routes.json"
nginx_probe_request_id=$(python3 -c '
import json, sys
print(json.load(open(sys.argv[1], encoding="utf-8"))["request_id"])
' "$nginx_log_probe")
nginx_log_ready=0
nginx_log_attempt=0
while [ "$nginx_log_attempt" -lt 50 ]; do
  docker logs "$edge_container" > "$edge_log" 2>&1
  if grep -Fq "\"request_id\":\"$nginx_probe_request_id\"" "$edge_log"; then
    nginx_log_ready=1
    break
  fi
  nginx_log_attempt=$((nginx_log_attempt + 1))
  sleep 0.1
done
if [ "$nginx_log_ready" != "1" ]; then
  echo "Nginx access log did not emit the probe's unique request ID" >&2
  exit 1
fi
docker inspect "$primary_container" "$replica_container" > "$route_inspect"
python3 - "$edge_log" "$route_inspect" "$network" "$nginx_log_probe" <<'PY'
import json
import pathlib
import sys

log_path = pathlib.Path(sys.argv[1])
inspect_path = pathlib.Path(sys.argv[2])
network = sys.argv[3]
probe = json.loads(pathlib.Path(sys.argv[4]).read_text(encoding="utf-8"))
raw = log_path.read_text(encoding="utf-8")
secret_markers = set(probe["markers"].values())
leaked = sorted(marker for marker in secret_markers if marker in raw)
if leaked:
    raise SystemExit(
        "Nginx access log included query, header, or cookie secret markers: "
        + ", ".join(leaked)
    )
entries = []
for line in raw.splitlines():
    line = line.strip()
    if not line.startswith("{"):
        continue
    try:
        candidate = json.loads(line)
    except json.JSONDecodeError:
        continue
    if isinstance(candidate, dict):
        entries.append(candidate)
if not entries:
    raise SystemExit("Nginx JSON access logging was not active")
probe_entries = [
    entry for entry in entries if entry.get("request_id") == probe["request_id"]
]
if len(probe_entries) != 1:
    raise SystemExit(
        "Nginx access-log probe did not correlate to exactly one JSON row: "
        f"{len(probe_entries)}"
    )
probe_entry = probe_entries[0]
if (
    probe_entry.get("method") != "GET"
    or probe_entry.get("uri") != "/codex-api/v1/health/live"
    or probe_entry.get("status") != 200
):
    raise SystemExit("Nginx access-log probe correlated to the wrong request")
for label, uri in probe["uris"].items():
    denial_entries = [
        entry
        for entry in entries
        if entry.get("method") == "GET"
        and entry.get("uri") == uri
        and entry.get("status") == 404
    ]
    if len(denial_entries) != 1:
        raise SystemExit(
            f"Nginx {label} denial did not correlate to exactly one JSON row: "
            f"{len(denial_entries)}"
        )
required_fields = {
    "time", "remote_addr", "method", "uri", "status", "bytes",
    "request_time", "upstream_time", "upstream_status", "upstream_addr", "request_id",
}
if any(not required_fields.issubset(entry) for entry in entries):
    raise SystemExit("Nginx JSON access log is missing required fields")
if any("?" in str(entry.get("uri", "")) for entry in entries):
    raise SystemExit("Nginx JSON access log uses request_uri instead of uri")

containers = json.loads(pathlib.Path(inspect_path).read_text(encoding="utf-8"))
addresses = []
for container in containers:
    networks = container["NetworkSettings"]["Networks"]
    if network not in networks:
        raise SystemExit(f"API container is not attached to {network}")
    addresses.append(networks[network]["IPAddress"])
primary, replica = addresses
http_routed = any(
    str(entry.get("uri", "")).startswith("/codex-api/")
    and f"{primary}:8090" in str(entry.get("upstream_addr", ""))
    for entry in entries
)
device_routed = any(
    entry.get("uri") == "/codex-ws/device"
    and f"{replica}:8090" in str(entry.get("upstream_addr", ""))
    for entry in entries
)
browser_routed = any(
    entry.get("uri") == "/codex-ws/browser"
    and f"{primary}:8090" in str(entry.get("upstream_addr", ""))
    for entry in entries
)
if not http_routed or not device_routed or not browser_routed:
    raise SystemExit(
        "Nginx did not prove deterministic HTTP/browser-primary and device-replica routing"
    )
print(f"Validated {len(entries)} structured Nginx access entries and deterministic upstreams.")
PY
record_check nginx-json-access-log-unique-row-prefix-coverage-redaction-and-upstream-routing

final_source_manifest_sha256=$(python3 "$script_dir/source_manifest.py" "$repo_root")
if [ "$final_source_manifest_sha256" != "$source_manifest_sha256" ]; then
  stage=source-manifest-drift
  echo "Repository acceptance inputs changed during the E2E run" >&2
  echo "Started with: $source_manifest_sha256" >&2
  echo "Finished with: $final_source_manifest_sha256" >&2
  exit 1
fi
record_check source-manifest-remained-stable-throughout-acceptance

stage=completed
echo "Local deployment acceptance passed with a real Connector and deterministic fake Codex stdio fixture."
