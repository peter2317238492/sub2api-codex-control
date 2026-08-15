#!/bin/sh
set -eu

export PYTHONDONTWRITEBYTECODE=1

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PYTHON_BIN=${PYTHON_BIN:-python3}
PROMTOOL_BIN=${PROMTOOL_BIN:-promtool}
RUFF_BIN=${RUFF_BIN:-ruff}
STRICT=0

case "${1:-}" in
  --strict) STRICT=1 ;;
  --print-helper-source-sha256) ;;
  "") ;;
  *) echo "usage: $0 [--strict|--print-helper-source-sha256]" >&2; exit 2 ;;
esac

require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "required command is unavailable: $1" >&2
    exit 127
  fi
}

require_command "$PYTHON_BIN"

helper_source_sha256=$(
  "$PYTHON_BIN" - "$SCRIPT_DIR" <<'PY'
import hashlib
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
digest = hashlib.sha256()
for relative in (
    ".dockerignore",
    "helper.Dockerfile",
    "common.py",
    "alertmanager-proxy.py",
    "external-delivery-relay.py",
    "observability-admission.py",
    "collector/collector.py",
    "evidence-receiver/receiver.py",
    "external-delivery-relay.py",
    "schemas/external-operator-delivery-receipt.schema.json",
    "schemas/release-observability-receipt.schema.json",
):
    data = (root / relative).read_bytes()
    digest.update(relative.encode("ascii"))
    digest.update(b"\0")
    digest.update(str(len(data)).encode("ascii"))
    digest.update(b"\0")
    digest.update(data)
print(digest.hexdigest())
PY
)

if [ "${1:-}" = "--print-helper-source-sha256" ]; then
  printf '%s\n' "$helper_source_sha256"
  exit 0
fi

if [ "$STRICT" -eq 1 ]; then
  require_command "$RUFF_BIN"
  require_command "$PROMTOOL_BIN"
  require_command docker
  docker info >/dev/null
  docker compose version >/dev/null
  identity_conflict=0
  if command -v getent >/dev/null 2>&1; then
    getent passwd 65532 >/dev/null && identity_conflict=1
    getent group 65532 >/dev/null && identity_conflict=1
  elif command -v dscl >/dev/null 2>&1; then
    dscl . -list /Users UniqueID | awk '$2 == 65532 { found=1 } END { exit !found }' && identity_conflict=1
    dscl . -list /Groups PrimaryGroupID | awk '$2 == 65532 { found=1 } END { exit !found }' && identity_conflict=1
  else
    echo "cannot prove dedicated monitoring uid/gid 65532 is unused" >&2
    exit 1
  fi
  if [ "$identity_conflict" -ne 0 ]; then
    echo "dedicated monitoring uid/gid 65532 conflicts with a host account" >&2
    exit 1
  fi
  if ps -eo uid= | awk '$1 == 65532 { found=1 } END { exit !found }'; then
    echo "dedicated monitoring uid 65532 is already used by a host process" >&2
    exit 1
  fi
fi

"$PYTHON_BIN" -c 'import sys; assert sys.version_info >= (3, 9), "Python 3.9 or newer is required"'
"$PYTHON_BIN" - "$SCRIPT_DIR" <<'PY'
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
for relative in (
    "common.py",
    "alertmanager-proxy.py",
    "collector/collector.py",
    "derive-metrics-bearer.py",
    "evidence-receiver/receiver.py",
    "observability-admission.py",
    "tests/test_monitoring.py",
):
    source = (root / relative).read_text(encoding="utf-8")
    compile(source, str(root / relative), "exec")
PY
"$PYTHON_BIN" -m unittest discover -s "$SCRIPT_DIR/tests" -p 'test_*.py' -v

if command -v "$RUFF_BIN" >/dev/null 2>&1; then
  "$RUFF_BIN" check --config "$SCRIPT_DIR/ruff.toml" \
    "$SCRIPT_DIR/common.py" \
    "$SCRIPT_DIR/alertmanager-proxy.py" \
    "$SCRIPT_DIR/collector" \
    "$SCRIPT_DIR/derive-metrics-bearer.py" \
    "$SCRIPT_DIR/evidence-receiver" \
    "$SCRIPT_DIR/external-delivery-relay.py" \
    "$SCRIPT_DIR/observability-admission.py" \
    "$SCRIPT_DIR/tests"
elif [ "$STRICT" -eq 1 ]; then
  exit 127
else
  echo "SKIP(dev): ruff is not installed"
fi

if command -v "$PROMTOOL_BIN" >/dev/null 2>&1; then
  "$SCRIPT_DIR/verify-rules.sh"
  "$PROMTOOL_BIN" check config --syntax-only "$SCRIPT_DIR/prometheus/prometheus.yml"
elif [ "$STRICT" -eq 1 ]; then
  exit 127
else
  echo "SKIP(dev): promtool is not installed"
fi

if ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1 || \
   ! docker compose version >/dev/null 2>&1; then
  if [ "$STRICT" -eq 1 ]; then
    echo "Docker daemon and Compose are mandatory in strict mode" >&2
    exit 127
  fi
  echo "SKIP(dev): Docker daemon or Compose is unavailable"
  exit 0
fi

root=$(mktemp -d)
cleanup() {
  find "$root" -depth -delete 2>/dev/null || true
}
trap cleanup EXIT HUP INT TERM

bearer_file="$root/metrics-bearer"
proxy_bearer_file="$root/proxy-bearer"
receiver_bearer_file="$root/receiver-bearer"
external_bearer_file="$root/external-bearer"
delivery_config="$root/external-delivery.json"
alertmanager_config="$root/alertmanager.yml"
evidence_dir="$root/evidence"
delivery_dir="$root/delivery"
prometheus_dir="$root/prometheus"
alertmanager_dir="$root/alertmanager"
bridge_dir="$root/bridge"
mkdir "$evidence_dir" "$delivery_dir" "$prometheus_dir" "$alertmanager_dir" "$bridge_dir"
printf '%064d\n' 0 >"$bearer_file"
printf '%064d\n' 1 >"$proxy_bearer_file"
printf '%064d\n' 2 >"$receiver_bearer_file"
printf '%064d\n' 3 >"$external_bearer_file"
printf '%s\n' '{"format_version":1,"receiver_id":"operator-primary","webhook_url":"https://alerts.example.com/codex-control"}' >"$delivery_config"
chmod 0600 "$bearer_file" "$proxy_bearer_file" "$receiver_bearer_file" \
  "$external_bearer_file" "$delivery_config"
chmod 0700 "$root" "$evidence_dir" "$delivery_dir" "$prometheus_dir" \
  "$alertmanager_dir" "$bridge_dir"
"$PYTHON_BIN" "$SCRIPT_DIR/observability-admission.py" render-alertmanager \
  --delivery-config "$delivery_config" --output "$alertmanager_config"
"$PYTHON_BIN" "$SCRIPT_DIR/observability-admission.py" verify-alertmanager \
  --delivery-config "$delivery_config" --alertmanager-config "$alertmanager_config"

compose() {
  CONTROL_RELEASE=1.2.3 \
  CONTROL_VCS_REF=0123456789abcdef0123456789abcdef01234567 \
  CONTROL_MONITORING_HELPER_SOURCE_SHA256="$helper_source_sha256" \
  CONTROL_MONITORING_METRICS_BEARER_FILE="$bearer_file" \
  CONTROL_MONITORING_ALERTMANAGER_PROXY_BEARER_FILE="$proxy_bearer_file" \
  CONTROL_MONITORING_RECEIVER_BEARER_FILE="$receiver_bearer_file" \
  CONTROL_MONITORING_EXTERNAL_OPERATOR_BEARER_FILE="$external_bearer_file" \
  CONTROL_MONITORING_EXTERNAL_OPERATOR_CONFIG="$delivery_config" \
  CONTROL_MONITORING_ALERTMANAGER_CONFIG="$alertmanager_config" \
  CONTROL_MONITORING_EVIDENCE_DIR="$evidence_dir" \
  CONTROL_MONITORING_DELIVERY_EVIDENCE_DIR="$delivery_dir" \
  CONTROL_MONITORING_PROMETHEUS_DATA_DIR="$prometheus_dir" \
  CONTROL_MONITORING_ALERTMANAGER_DATA_DIR="$alertmanager_dir" \
  CONTROL_MONITORING_ALERTMANAGER_BRIDGE_DIR="$bridge_dir" \
    docker compose -f "$SCRIPT_DIR/compose.yaml" "$@"
}

compose config --format json >"$root/compose.json"
"$PYTHON_BIN" - "$root/compose.json" <<'PY'
import json
import pathlib
import sys

config = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
services = config["services"]
assert set(services) == {
    "prometheus",
    "collector",
    "alertmanager",
    "external-delivery-relay",
    "alertmanager-auth-proxy",
    "alertmanager-relay",
    "evidence-receiver",
}
for name, service in services.items():
    assert service["platform"] == "linux/amd64", name
    assert service["user"] == "65532:65532", name
    assert service["read_only"] is True, name
    assert service["cap_drop"] == ["ALL"], name
    assert service["security_opt"] == ["no-new-privileges:true"], name
    assert int(service["pids_limit"]) > 0, name
    assert int(service["mem_limit"]) > 0, name
    assert float(service["cpus"]) > 0, name
    assert "ports" not in service, name
    assert "expose" not in service, name
    assert "privileged" not in service, name
    assert all("docker.sock" not in str(item) for item in service.get("volumes", [])), name
for name in ("prometheus", "collector", "alertmanager-auth-proxy"):
    assert services[name]["network_mode"] == "host", name
for name in ("alertmanager-relay", "evidence-receiver"):
    assert services[name]["network_mode"] == "service:alertmanager", name
assert "network_mode" not in services["alertmanager"]
assert config["networks"]["alertmanager-private"]["internal"] is True
assert config["networks"]["external-operator-egress"].get("internal", False) is False
assert set(services["external-delivery-relay"]["networks"]) == {
    "alertmanager-private",
    "external-operator-egress",
}
for name, service in services.items():
    if name != "external-delivery-relay":
        assert "external-operator-egress" not in service.get("networks", {}), name
alertmanager_command = services["alertmanager"]["command"]
assert "--web.listen-address=127.0.0.1:9093" in alertmanager_command
assert "127.0.0.1:19093:19093" not in json.dumps(config)
PY

compose build collector
helper_image="codex-control-monitoring-helper:$helper_source_sha256"
recorded_closure=$(docker image inspect \
  --format '{{ index .Config.Labels "org.opencontainers.image.source-closure-sha256" }}' \
  "$helper_image")
[ "$recorded_closure" = "$helper_source_sha256" ] || {
  echo "helper image source-closure label mismatch" >&2
  exit 1
}

for relative in common.py alertmanager-proxy.py external-delivery-relay.py observability-admission.py collector/collector.py evidence-receiver/receiver.py; do
  expected=$("$PYTHON_BIN" -c \
    'import hashlib,pathlib,sys; print(hashlib.sha256(pathlib.Path(sys.argv[1]).read_bytes()).hexdigest())' \
    "$SCRIPT_DIR/$relative")
  embedded="/opt/monitoring/$(basename "$relative")"
  actual=$(docker run --rm --platform linux/amd64 --network none --read-only \
    --user 65532:65532 --cap-drop ALL --security-opt no-new-privileges \
    --pids-limit 32 --memory 64m "$helper_image" sha256sum "$embedded" | awk '{print $1}')
  [ "$expected" = "$actual" ] || { echo "embedded source mismatch: $relative" >&2; exit 1; }
done

docker run --rm --platform linux/amd64 --network none --read-only \
  --user 65532:65532 --cap-drop ALL --security-opt no-new-privileges \
  --pids-limit 64 --memory 256m -v "$SCRIPT_DIR/prometheus:/etc/prometheus:ro" \
  --entrypoint /bin/promtool \
  prom/prometheus:v3.13.2@sha256:1147c92841726a6fef55fe6124491d6f85480f8de204f7d420304ca5bbd0a8f7 \
  check rules /etc/prometheus/native-alerts.yml /etc/prometheus/external-alerts.yml \
    /etc/prometheus/production-integrity.yml

docker run --rm --platform linux/amd64 --network none --read-only \
  --user 65532:65532 --cap-drop ALL --security-opt no-new-privileges \
  --pids-limit 64 --memory 256m -v "$SCRIPT_DIR/prometheus:/etc/prometheus:ro" \
  -v "$bearer_file:/run/secrets/control_metrics_bearer:ro" \
  -v "$proxy_bearer_file:/run/secrets/alertmanager_proxy_bearer:ro" \
  --entrypoint /bin/promtool \
  prom/prometheus:v3.13.2@sha256:1147c92841726a6fef55fe6124491d6f85480f8de204f7d420304ca5bbd0a8f7 \
  check config /etc/prometheus/prometheus.yml

docker run --rm --platform linux/amd64 --network none --read-only \
  --user 65532:65532 --cap-drop ALL --security-opt no-new-privileges \
  --pids-limit 64 --memory 256m \
  -v "$receiver_bearer_file:/run/secrets/evidence_receiver_bearer:ro" \
  -v "$alertmanager_config:/etc/alertmanager/alertmanager.yml:ro" \
  --entrypoint /bin/amtool \
  prom/alertmanager:v0.33.1@sha256:a89f8d4520954079275441eecdb71444328bd90633dd4eddfc33b9ed657f349b \
  check-config /etc/alertmanager/alertmanager.yml

docker run --rm --platform linux/amd64 --network none --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=32m --user 0:0 --cap-drop ALL \
  --security-opt no-new-privileges --pids-limit 64 --memory 256m \
  -e PYTHONDONTWRITEBYTECODE=1 -e CONTROL_MONITORING_TEST_TMPDIR=/tmp \
  -v "$SCRIPT_DIR/../..:/workspace:ro" -w /workspace \
  python:3.9.23-alpine3.22@sha256:7840735992b585fc50444ff15ad60bf9b6c5868d45ebf522a9b99b754dea308a \
  python3 -m unittest discover -s deploy/monitoring/tests -p 'test_*.py' -v
