#!/bin/sh
set -eu

fail() {
  printf '%s\n' "macos-sign-notarize: $*" >&2
  exit 1
}

[ "$#" -eq 1 ] || fail "usage: $0 RELEASE_DIRECTORY"
[ "$(uname -s)" = Darwin ] || fail "must run on macOS"

for command in codesign security xcrun pkgbuild productsign pkgutil spctl jq openssl install shasum python3; do
  command -v "$command" >/dev/null 2>&1 || fail "missing required command: $command"
done

required_secret() {
  variable=$1
  eval "value=\${$variable:-}"
  [ -n "$value" ] || fail "protected environment variable $variable is required"
}

required_secret MACOS_APPLICATION_CERTIFICATE_P12_BASE64
required_secret MACOS_APPLICATION_CERTIFICATE_PASSWORD
required_secret MACOS_INSTALLER_CERTIFICATE_P12_BASE64
required_secret MACOS_INSTALLER_CERTIFICATE_PASSWORD
required_secret MACOS_DEVELOPER_ID_APPLICATION
required_secret MACOS_DEVELOPER_ID_INSTALLER
required_secret MACOS_EXPECTED_TEAM_ID
required_secret MACOS_EXPECTED_APPLICATION_IDENTITY
required_secret MACOS_EXPECTED_INSTALLER_IDENTITY
required_secret MACOS_NOTARY_KEY_BASE64
required_secret MACOS_NOTARY_KEY_ID
required_secret MACOS_NOTARY_ISSUER_ID

[ "$MACOS_DEVELOPER_ID_APPLICATION" = "$MACOS_EXPECTED_APPLICATION_IDENTITY" ] || \
  fail "Application signing selector does not match the pinned identity"
[ "$MACOS_DEVELOPER_ID_INSTALLER" = "$MACOS_EXPECTED_INSTALLER_IDENTITY" ] || \
  fail "Installer signing selector does not match the pinned identity"
case "$MACOS_EXPECTED_APPLICATION_IDENTITY" in
  "Developer ID Application: "*" ($MACOS_EXPECTED_TEAM_ID)") ;;
  *) fail "invalid pinned Developer ID Application identity" ;;
esac
case "$MACOS_EXPECTED_INSTALLER_IDENTITY" in
  "Developer ID Installer: "*" ($MACOS_EXPECTED_TEAM_ID)") ;;
  *) fail "invalid pinned Developer ID Installer identity" ;;
esac

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/../.." && pwd)
packaging_dir="$repo_root/connector/packaging"
release_dir=$(CDPATH= cd -- "$1" && pwd)
temporary=$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/connector-native-sign.XXXXXX")
keychain="$temporary/connector-release.keychain-db"
keychain_password=$(openssl rand -hex 32)
application_certificate="$temporary/developer-id-application.p12"
installer_certificate="$temporary/developer-id-installer.p12"
notary_key="$temporary/AuthKey_${MACOS_NOTARY_KEY_ID}.p8"

cleanup() {
  status=$?
  trap - EXIT HUP INT TERM
  security delete-keychain "$keychain" >/dev/null 2>&1 || true
  rm -rf -- "$temporary"
  exit "$status"
}
trap cleanup EXIT HUP INT TERM

printf '%s' "$MACOS_APPLICATION_CERTIFICATE_P12_BASE64" | /usr/bin/base64 -D > "$application_certificate"
printf '%s' "$MACOS_INSTALLER_CERTIFICATE_P12_BASE64" | /usr/bin/base64 -D > "$installer_certificate"
printf '%s' "$MACOS_NOTARY_KEY_BASE64" | /usr/bin/base64 -D > "$notary_key"
chmod 0600 "$application_certificate" "$installer_certificate" "$notary_key"

security create-keychain -p "$keychain_password" "$keychain"
security set-keychain-settings -lut 21600 "$keychain"
security unlock-keychain -p "$keychain_password" "$keychain"
security import "$application_certificate" -k "$keychain" \
  -P "$MACOS_APPLICATION_CERTIFICATE_PASSWORD" -T /usr/bin/codesign
security import "$installer_certificate" -k "$keychain" \
  -P "$MACOS_INSTALLER_CERTIFICATE_PASSWORD" -T /usr/bin/productsign -T /usr/bin/pkgbuild
security set-key-partition-list -S apple-tool:,apple: -s -k "$keychain_password" "$keychain" >/dev/null
security list-keychains -d user -s "$keychain"
unset MACOS_APPLICATION_CERTIFICATE_P12_BASE64 MACOS_APPLICATION_CERTIFICATE_PASSWORD
unset MACOS_INSTALLER_CERTIFICATE_P12_BASE64 MACOS_INSTALLER_CERTIFICATE_PASSWORD
unset MACOS_NOTARY_KEY_BASE64

version=$(jq -er '.config.connector_version' "$release_dir/.release-work.json")
source_epoch=$(jq -er '.source_date_epoch | select(type == "number" and . >= 0) | floor' "$release_dir/.release-work.json")
timestamp=$(date -u -r "$source_epoch" +%Y%m%d%H%M.%S)

populate_payload() {
  root=$1
  artifact=$2
  install -d -m 0755 \
    "$root/usr/local/bin" \
    "$root/usr/local/libexec/sub2api-codex-connector" \
    "$root/usr/local/share/doc/sub2api-codex-connector/third_party/licenses" \
    "$root/Library/LaunchAgents"
  install -m 0755 "$artifact" "$root/usr/local/bin/sub2api-codex-connector"
  install -m 0755 "$packaging_dir/common/sub2api-codex-connector-ctl" \
    "$root/usr/local/bin/sub2api-codex-connector-ctl"
  install -m 0755 "$packaging_dir/common/package-lifecycle" \
    "$root/usr/local/libexec/sub2api-codex-connector/package-lifecycle"
  install -m 0755 "$packaging_dir/macos/uninstall-macos.sh" \
    "$root/usr/local/libexec/sub2api-codex-connector/uninstall-macos"
  install -m 0644 "$packaging_dir/macos/org.sub2api.codex-connector.plist" \
    "$root/Library/LaunchAgents/org.sub2api.codex-connector.plist"
  install -m 0644 "$packaging_dir/common/connector.example.json" \
    "$root/usr/local/share/doc/sub2api-codex-connector/connector.example.json"
  install -m 0644 "$packaging_dir/INSTALL.md" \
    "$root/usr/local/share/doc/sub2api-codex-connector/INSTALL.md"
  install -m 0644 "$repo_root/LICENSE" \
    "$root/usr/local/share/doc/sub2api-codex-connector/LICENSE"
  install -m 0644 "$repo_root/NOTICE" \
    "$root/usr/local/share/doc/sub2api-codex-connector/NOTICE"
  install -m 0644 "$repo_root/THIRD_PARTY_NOTICES.md" \
    "$root/usr/local/share/doc/sub2api-codex-connector/THIRD_PARTY_NOTICES.md"
  install -m 0644 "$repo_root/third_party/components.json" \
    "$root/usr/local/share/doc/sub2api-codex-connector/third_party/components.json"
  for license in "$repo_root"/third_party/licenses/*; do
    [ -f "$license" ] && [ ! -L "$license" ] || fail "invalid third-party license input: $license"
    install -m 0644 "$license" \
      "$root/usr/local/share/doc/sub2api-codex-connector/third_party/licenses/$(basename "$license")"
  done
  find "$root" -exec touch -h -t "$timestamp" {} +
}

for target in darwin-amd64 darwin-arm64; do
  arch=${target#darwin-}
  artifact="$release_dir/sub2api-codex-connector_${version}_darwin_${arch}"
  package="$release_dir/sub2api-codex-connector_${version}_darwin_${arch}.pkg"
  [ -f "$artifact" ] && [ ! -L "$artifact" ] || fail "missing Darwin artifact $artifact"
  [ ! -e "$package" ] || fail "refusing to overwrite pre-existing installer $package"

  chmod 0755 "$artifact"
  codesign --force --options runtime --timestamp --keychain "$keychain" \
    --sign "$MACOS_DEVELOPER_ID_APPLICATION" "$artifact"
  codesign --verify --strict --verbose=2 "$artifact"
  application_report="$temporary/${target}.codesign.txt"
  codesign -d --verbose=4 "$artifact" > "$application_report" 2>&1
  grep -F "Authority=$MACOS_EXPECTED_APPLICATION_IDENTITY" "$application_report" >/dev/null
  grep -F "TeamIdentifier=$MACOS_EXPECTED_TEAM_ID" "$application_report" >/dev/null
  grep -E '^flags=.*\(runtime\)' "$application_report" >/dev/null
  grep -E '^Timestamp=' "$application_report" >/dev/null

  candidate_one="$temporary/${target}.candidate-1.pkg"
  candidate_two="$temporary/${target}.candidate-2.pkg"
  pass=1
  for candidate in "$candidate_one" "$candidate_two"; do
    root="$temporary/${target}.root-$pass"
    scripts="$temporary/${target}.scripts-$pass"
    mkdir -p "$root" "$scripts"
    populate_payload "$root" "$artifact"
    for hook in preinstall postinstall; do
      sed "s/@VERSION@/$version/g" "$packaging_dir/macos/scripts/$hook" > "$scripts/$hook"
      chmod 0755 "$scripts/$hook"
      touch -h -t "$timestamp" "$scripts/$hook"
    done
    pkgbuild \
      --root "$root" \
      --scripts "$scripts" \
      --identifier org.sub2api.codex-connector \
      --version "$version" \
      --install-location / \
      --ownership recommended \
      --min-os-version 12.0 \
      "$candidate"
    pass=$((pass + 1))
  done
  candidate_one_sha=$(shasum -a 256 "$candidate_one" | awk '{print $1}')
  candidate_two_sha=$(shasum -a 256 "$candidate_two" | awk '{print $1}')
  [ "$candidate_one_sha" = "$candidate_two_sha" ] || fail "non-reproducible unsigned pkg for $target"
  [ "$(stat -f %z "$candidate_one")" = "$(stat -f %z "$candidate_two")" ] || \
    fail "unsigned pkg size differs for $target"

  productsign --sign "$MACOS_DEVELOPER_ID_INSTALLER" --keychain "$keychain" --timestamp \
    "$candidate_one" "$package"
  installer_report="$temporary/${target}.installer-signature.txt"
  pkgutil --check-signature "$package" > "$installer_report" 2>&1
  grep -F "$MACOS_EXPECTED_INSTALLER_IDENTITY" "$installer_report" >/dev/null

  notary_json="$temporary/${target}.notary.json"
  xcrun notarytool submit "$package" \
    --key "$notary_key" \
    --key-id "$MACOS_NOTARY_KEY_ID" \
    --issuer "$MACOS_NOTARY_ISSUER_ID" \
    --wait \
    --output-format json > "$notary_json"
  jq -e '.status == "Accepted" and (.id | type == "string" and length > 0)' "$notary_json" >/dev/null

  staple_report="$temporary/${target}.staple.txt"
  xcrun stapler staple -v "$package" > "$staple_report" 2>&1
  xcrun stapler validate -v "$package" >> "$staple_report" 2>&1
  grep -E 'validated|worked' "$staple_report" >/dev/null

  gatekeeper_report="$temporary/${target}.gatekeeper.txt"
  spctl --assess --type install --verbose=4 "$package" > "$gatekeeper_report" 2>&1
  grep -E 'accepted|source=Notarized Developer ID' "$gatekeeper_report" >/dev/null

  python3 "$script_dir/release.py" record-native-evidence \
    --output "$release_dir" \
    --target "$target" \
    --codesign-report "$application_report" \
    --expected-team-id "$MACOS_EXPECTED_TEAM_ID" \
    --expected-signing-identity "$MACOS_EXPECTED_APPLICATION_IDENTITY"
  python3 "$script_dir/release.py" record-native-package-evidence \
    --output "$release_dir" \
    --target "$target" \
    --package-format pkg \
    --candidate-package "$candidate_one" \
    --installer-report "$installer_report" \
    --notary-json "$notary_json" \
    --stapler-report "$staple_report" \
    --gatekeeper-report "$gatekeeper_report" \
    --expected-team-id "$MACOS_EXPECTED_TEAM_ID" \
    --expected-application-identity "$MACOS_EXPECTED_APPLICATION_IDENTITY" \
    --expected-installer-identity "$MACOS_EXPECTED_INSTALLER_IDENTITY"
done

echo "macos-sign-notarize: signed binaries and signed/notarized/stapled/Gatekeeper-approved installers recorded"
