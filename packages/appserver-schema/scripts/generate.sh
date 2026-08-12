#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PACKAGE_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
GENERATED_DIR="${PACKAGE_DIR}/generated"
CONNECTOR_SCHEMA_DIR="${PACKAGE_DIR}/../../connector/internal/appserver/contracts"
CONNECTOR_SCHEMAS=(
  "codex_app_server_protocol.v2.schemas.json"
  "JSONRPCResponse.json"
  "JSONRPCError.json"
  "ServerRequest.json"
  "CommandExecutionRequestApprovalResponse.json"
  "FileChangeRequestApprovalResponse.json"
  "PermissionsRequestApprovalResponse.json"
  "ApplyPatchApprovalResponse.json"
  "ExecCommandApprovalResponse.json"
  "v1/InitializeResponse.json"
)
EXPECTED_VERSION="$(<"${PACKAGE_DIR}/codex-version.txt")"
CODEX_BIN="${CODEX_BIN:-codex}"
MODE="${1:-generate}"

case "${MODE}" in
  generate|check) ;;
  *)
    echo "usage: $0 [generate|check]" >&2
    exit 2
    ;;
esac

for command in "${CODEX_BIN}" jq diff mktemp; do
  if ! command -v "${command}" >/dev/null 2>&1; then
    echo "required command not found: ${command}" >&2
    exit 1
  fi
done

ACTUAL_VERSION="$("${CODEX_BIN}" --version 2>/dev/null)"
if [[ "${ACTUAL_VERSION}" != "codex-cli ${EXPECTED_VERSION}" ]]; then
  echo "Codex version mismatch: expected codex-cli ${EXPECTED_VERSION}, got ${ACTUAL_VERSION}" >&2
  exit 1
fi

WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/codex-appserver-schema.XXXXXX")"
trap 'rm -rf "${WORK_DIR}"' EXIT
mkdir -p "${WORK_DIR}/codex-home" "${WORK_DIR}/generated"

CODEX_HOME="${WORK_DIR}/codex-home" "${CODEX_BIN}" app-server generate-json-schema \
  --experimental \
  --out "${WORK_DIR}/generated/json-schema"
CODEX_HOME="${WORK_DIR}/codex-home" "${CODEX_BIN}" app-server generate-ts \
  --experimental \
  --out "${WORK_DIR}/generated/typescript"

# The aggregate schema contains map-backed definitions whose emission order can
# vary between runs. Canonical key ordering preserves the generated schema while
# making byte-for-byte checks reproducible.
while IFS= read -r -d '' schema_file; do
  canonical_file="${schema_file}.canonical"
  jq --sort-keys . "${schema_file}" >"${canonical_file}"
  mv "${canonical_file}" "${schema_file}"
done < <(find "${WORK_DIR}/generated/json-schema" -type f -name '*.json' -print0)

if [[ "${MODE}" == "generate" ]]; then
  rm -rf "${GENERATED_DIR}"
  mv "${WORK_DIR}/generated" "${GENERATED_DIR}"
  for schema in "${CONNECTOR_SCHEMAS[@]}"; do
    mkdir -p "$(dirname "${CONNECTOR_SCHEMA_DIR}/${schema}")"
    install -m 0644 "${GENERATED_DIR}/json-schema/${schema}" "${CONNECTOR_SCHEMA_DIR}/${schema}"
  done
  echo "Generated Codex ${EXPECTED_VERSION} app-server contract in ${GENERATED_DIR}"
else
  if [[ ! -d "${GENERATED_DIR}" ]]; then
    echo "generated contract is missing; run $0 generate" >&2
    exit 1
  fi
  diff -ru "${GENERATED_DIR}" "${WORK_DIR}/generated"
  for schema in "${CONNECTOR_SCHEMAS[@]}"; do
    diff -u "${GENERATED_DIR}/json-schema/${schema}" "${CONNECTOR_SCHEMA_DIR}/${schema}"
  done
  echo "Generated contract matches Codex ${EXPECTED_VERSION}"
fi
