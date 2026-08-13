#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PROMTOOL_BIN=${PROMTOOL_BIN:-promtool}

if ! command -v "$PROMTOOL_BIN" >/dev/null 2>&1; then
  echo "promtool was not found; install the Prometheus version used in production" >&2
  exit 127
fi

"$PROMTOOL_BIN" check rules \
  "$SCRIPT_DIR/prometheus/native-alerts.yml" \
  "$SCRIPT_DIR/prometheus/external-alerts.yml" \
  "$SCRIPT_DIR/prometheus/production-integrity.yml"
(
  cd "$SCRIPT_DIR/prometheus"
  "$PROMTOOL_BIN" test rules tests/alerts.test.yml
)
