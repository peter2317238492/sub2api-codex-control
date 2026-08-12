#!/bin/sh
set -eu

container=${SUB2API_CONTAINER:-sub2api}
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
lock_file=${VERSIONS_LOCK_FILE:-$script_dir/../../versions.lock.json}
contract_file=${SUB2API_AUTH_CONTRACT_FILE:-}
attestation_file=${SUB2API_ATTESTATION_FILE:-}
auth_evidence_file=${SUB2API_AUTH_EVIDENCE_FILE:-}
require_auth_evidence=${SUB2API_REQUIRE_AUTH_EVIDENCE:-0}
auth_max_age=${SUB2API_AUTH_EVIDENCE_MAX_AGE_SECONDS:-900}
auth_probe_nonce=${SUB2API_AUTH_EVIDENCE_NONCE:-}
auth_probe_user_id=${SUB2API_AUTH_EVIDENCE_EXPECTED_USER_ID:-}
auth_probe_base_url=${SUB2API_AUTH_EVIDENCE_BASE_URL:-}
expected_network=${SUB2API_EXPECTED_NETWORK:-${SUB2API_NETWORK_NAME:-sub2api-network}}
expected_alias=${SUB2API_EXPECTED_NETWORK_ALIAS:-sub2api}

fail() {
  echo "verify-sub2api-runtime: $*" >&2
  exit 1
}

[ -r "$lock_file" ] || fail "version lock is not readable: $lock_file"
command -v python3 >/dev/null 2>&1 || fail "python3 is required"
command -v docker >/dev/null 2>&1 || fail "docker is required"
case "$require_auth_evidence" in
  0|1) ;;
  *) fail "SUB2API_REQUIRE_AUTH_EVIDENCE must be 0 or 1" ;;
esac
case "$auth_max_age" in
  ''|*[!0-9]*|0) fail "SUB2API_AUTH_EVIDENCE_MAX_AGE_SECONDS must be positive" ;;
esac
if [ "$require_auth_evidence" = "1" ] && [ -z "$auth_evidence_file" ]; then
  fail "SUB2API_AUTH_EVIDENCE_FILE is required"
fi
if [ -n "$auth_evidence_file" ]; then
  [ -n "$auth_probe_nonce" ] \
    || fail "SUB2API_AUTH_EVIDENCE_NONCE is required with auth evidence"
  [ -n "$auth_probe_user_id" ] \
    || fail "SUB2API_AUTH_EVIDENCE_EXPECTED_USER_ID is required with auth evidence"
  [ "$auth_probe_base_url" = "http://127.0.0.1:8080" ] \
    || fail "SUB2API_AUTH_EVIDENCE_BASE_URL must be exactly http://127.0.0.1:8080"
fi
[ -n "$expected_network" ] || fail "SUB2API_EXPECTED_NETWORK is required"
[ -n "$expected_alias" ] || fail "SUB2API_EXPECTED_NETWORK_ALIAS is required"

umask 077
work_dir=$(mktemp -d "${TMPDIR:-/tmp}/verify-sub2api-runtime.XXXXXX")
cleanup() {
  status=$?
  trap - EXIT HUP INT TERM
  rm -rf "$work_dir"
  exit "$status"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

# Resolve the name once, then use the immutable full container ID for every
# subsequent operation. A name replacement cannot splice evidence from two
# different containers into one attestation.
docker container inspect "$container" > "$work_dir/container-before.json"
container_id=$(python3 -c '
import json, re, sys
value = json.load(open(sys.argv[1], encoding="utf-8"))
if not isinstance(value, list) or len(value) != 1:
    raise SystemExit("inspect did not resolve exactly one container")
container_id = value[0].get("Id", "")
if not isinstance(container_id, str) or re.fullmatch(r"[0-9a-f]{64}", container_id) is None:
    raise SystemExit("inspect did not return a full bare Docker container ID")
print(container_id)
' "$work_dir/container-before.json")

image_id=$(python3 -c '
import json, re, sys
image_id = json.load(open(sys.argv[1], encoding="utf-8"))[0].get("Image", "")
if not isinstance(image_id, str) or re.fullmatch(r"sha256:[0-9a-f]{64}", image_id) is None:
    raise SystemExit("inspect did not return a full Docker image ID")
print(image_id)
' "$work_dir/container-before.json")
docker image inspect "$image_id" > "$work_dir/image.json"

pid1_host_pid=$(python3 -c '
import json, sys
state = json.load(open(sys.argv[1], encoding="utf-8"))[0].get("State")
pid = state.get("Pid") if isinstance(state, dict) else None
if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0:
    raise SystemExit("inspect did not return one positive host PID")
print(pid)
' "$work_dir/container-before.json")

docker container exec "$container_id" sha256sum /app/sub2api > "$work_dir/binary-sha256.txt"
actual_binary_sha256=$(awk 'NR == 1 && NF >= 1 {print $1}' "$work_dir/binary-sha256.txt")
[ -n "$actual_binary_sha256" ] || fail "could not hash /app/sub2api"
pid1_executable=$(readlink "/proc/$pid1_host_pid/exe")
[ "$pid1_executable" = "/app/sub2api" ] \
  || fail "container PID 1 does not resolve to /app/sub2api"
sha256sum "/proc/$pid1_host_pid/exe" > "$work_dir/pid1-sha256.txt"
pid1_binary_sha256=$(awk 'NR == 1 && NF >= 1 {print $1}' "$work_dir/pid1-sha256.txt")
[ "$pid1_binary_sha256" = "$actual_binary_sha256" ] \
  || fail "container PID 1 executable hash differs from /app/sub2api"
docker container exec "$container_id" /app/sub2api --version > "$work_dir/version.txt" 2>&1
docker container diff "$container_id" > "$work_dir/diff.txt"
docker container inspect "$container_id" > "$work_dir/container-after.json"
docker container inspect "$container" > "$work_dir/container-name-after.json"
pid1_executable_after=$(readlink "/proc/$pid1_host_pid/exe")
[ "$pid1_executable_after" = "$pid1_executable" ] \
  || fail "container PID 1 executable changed during verification"
sha256sum "/proc/$pid1_host_pid/exe" > "$work_dir/pid1-sha256-after.txt"
pid1_binary_sha256_after=$(awk 'NR == 1 && NF >= 1 {print $1}' "$work_dir/pid1-sha256-after.txt")
[ "$pid1_binary_sha256_after" = "$pid1_binary_sha256" ] \
  || fail "container PID 1 executable hash changed during verification"

set -- \
  --lock "$lock_file" \
  --container-inspect "$work_dir/container-before.json" \
  --container-inspect-after "$work_dir/container-after.json" \
  --container-name-inspect-after "$work_dir/container-name-after.json" \
  --image-inspect "$work_dir/image.json" \
  --binary-sha256 "$actual_binary_sha256" \
  --pid1-host-pid "$pid1_host_pid" \
  --pid1-path "$pid1_executable" \
  --pid1-sha256 "$pid1_binary_sha256" \
  --version-output "$work_dir/version.txt" \
  --diff "$work_dir/diff.txt" \
  --auth-max-age-seconds "$auth_max_age" \
  --expected-network "$expected_network" \
  --expected-alias "$expected_alias"
if [ -n "$contract_file" ]; then
  set -- "$@" --contract-file "$contract_file"
fi
if [ -n "$auth_evidence_file" ]; then
  set -- "$@" \
    --auth-evidence "$auth_evidence_file" \
    --auth-probe-nonce "$auth_probe_nonce" \
    --auth-probe-user-id "$auth_probe_user_id" \
    --auth-probe-base-url "$auth_probe_base_url"
fi
if [ "$require_auth_evidence" = "1" ]; then
  set -- "$@" --require-auth-evidence
fi

python3 "$script_dir/verify-sub2api-runtime.py" "$@" > "$work_dir/attestation.json"

if [ -n "$attestation_file" ]; then
  attestation_dir=$(dirname -- "$attestation_file")
  [ -d "$attestation_dir" ] || fail "attestation directory does not exist: $attestation_dir"
  [ ! -L "$attestation_dir" ] || fail "refusing symlink attestation directory"
  [ ! -e "$attestation_file" ] && [ ! -L "$attestation_file" ] \
    || fail "refusing to overwrite attestation: $attestation_file"
  attestation_temporary=$(mktemp "$attestation_dir/.sub2api-attestation.XXXXXX")
  cp "$work_dir/attestation.json" "$attestation_temporary"
  chmod 0600 "$attestation_temporary"
  mv "$attestation_temporary" "$attestation_file"
fi

marker=$(python3 -c '
import json, sys
value = json.load(open(sys.argv[1], encoding="utf-8"))
print("{}/{}".format(
    value["runtime_version"],
    value["runtime_commit"][:7],
))
' "$work_dir/attestation.json")
if [ -n "$auth_evidence_file" ]; then
  evidence_status="and authentication evidence"
else
  evidence_status="without authentication evidence"
fi
echo "Sub2API immutable runtime, OCI identity, and mount policy are admitted $evidence_status."
echo "CONTROL_SUB2API_CONTRACT_MARKER=$marker"
