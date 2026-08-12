#!/bin/sh
set -eu

if [ "$#" -ne 1 ]; then
  echo "usage: $0 RELEASE_DIRECTORY" >&2
  exit 2
fi
if [ "$(uname -s)" != "Darwin" ]; then
  echo "macos-sign-notarize: must run on macOS" >&2
  exit 1
fi

for command in codesign security xcrun ditto python3 openssl; do
  if ! command -v "$command" >/dev/null 2>&1; then
    echo "macos-sign-notarize: missing required command: $command" >&2
    exit 1
  fi
done

required_secret() {
  variable=$1
  eval "value=\${$variable:-}"
  if [ -z "$value" ]; then
    echo "macos-sign-notarize: protected environment variable $variable is required" >&2
    exit 1
  fi
}

required_secret MACOS_CERTIFICATE_P12_BASE64
required_secret MACOS_CERTIFICATE_PASSWORD
required_secret MACOS_DEVELOPER_ID_APPLICATION
required_secret MACOS_EXPECTED_TEAM_ID
required_secret MACOS_EXPECTED_SIGNING_IDENTITY
required_secret MACOS_NOTARY_KEY_BASE64
required_secret MACOS_NOTARY_KEY_ID
required_secret MACOS_NOTARY_ISSUER_ID

if [ "$MACOS_DEVELOPER_ID_APPLICATION" != "$MACOS_EXPECTED_SIGNING_IDENTITY" ]; then
  echo "macos-sign-notarize: signing selector does not match the pinned signing identity" >&2
  exit 1
fi

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
release_dir=$(CDPATH= cd -- "$1" && pwd)
temporary=$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/connector-native-sign.XXXXXX")
keychain="$temporary/connector-release.keychain-db"
keychain_password=$(openssl rand -hex 32)
certificate="$temporary/developer-id.p12"
notary_key="$temporary/AuthKey_${MACOS_NOTARY_KEY_ID}.p8"

cleanup() {
  status=$?
  trap - EXIT HUP INT TERM
  security delete-keychain "$keychain" >/dev/null 2>&1 || true
  rm -rf "$temporary"
  exit "$status"
}
trap cleanup EXIT HUP INT TERM

printf '%s' "$MACOS_CERTIFICATE_P12_BASE64" | /usr/bin/base64 -D > "$certificate"
printf '%s' "$MACOS_NOTARY_KEY_BASE64" | /usr/bin/base64 -D > "$notary_key"
chmod 0600 "$certificate" "$notary_key"

security create-keychain -p "$keychain_password" "$keychain"
security set-keychain-settings -lut 21600 "$keychain"
security unlock-keychain -p "$keychain_password" "$keychain"
security import "$certificate" -k "$keychain" -P "$MACOS_CERTIFICATE_PASSWORD" -T /usr/bin/codesign
security set-key-partition-list -S apple-tool:,apple: -s -k "$keychain_password" "$keychain" >/dev/null
security list-keychains -d user -s "$keychain"
unset MACOS_CERTIFICATE_P12_BASE64 MACOS_CERTIFICATE_PASSWORD MACOS_NOTARY_KEY_BASE64

version=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["config"]["connector_version"])' "$release_dir/.release-work.json")

for target in darwin-amd64 darwin-arm64; do
  arch=${target#darwin-}
  artifact="$release_dir/sub2api-codex-connector_${version}_darwin_${arch}"
  if [ ! -f "$artifact" ]; then
    echo "macos-sign-notarize: missing Darwin artifact $artifact" >&2
    exit 1
  fi
  chmod 0755 "$artifact"
  codesign --force --options runtime --timestamp --keychain "$keychain" \
    --sign "$MACOS_DEVELOPER_ID_APPLICATION" "$artifact"
  codesign --verify --strict --verbose=2 "$artifact"

  report="$temporary/${target}.codesign.txt"
  codesign -d --verbose=4 "$artifact" > "$report" 2>&1
  archive="$temporary/${target}.zip"
  ditto -c -k --keepParent "$artifact" "$archive"
  notary_json="$temporary/${target}.notary.json"
  xcrun notarytool submit "$archive" \
    --key "$notary_key" \
    --key-id "$MACOS_NOTARY_KEY_ID" \
    --issuer "$MACOS_NOTARY_ISSUER_ID" \
    --wait \
    --output-format json > "$notary_json"
  python3 "$script_dir/release.py" record-native-evidence \
    --output "$release_dir" \
    --target "$target" \
    --notary-json "$notary_json" \
    --codesign-report "$report" \
    --expected-team-id "$MACOS_EXPECTED_TEAM_ID" \
    --expected-signing-identity "$MACOS_EXPECTED_SIGNING_IDENTITY"
done

echo "macos-sign-notarize: Developer ID signatures and accepted notarization recorded"
