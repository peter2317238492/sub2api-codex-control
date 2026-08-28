#!/bin/sh
set -eu

fail() {
  printf '%s\n' "install-trivy: $*" >&2
  exit 1
}

[ "$#" -eq 3 ] || fail \
  "usage: install-trivy.sh POLICY_JSON DESTINATION_DIR INSTALL_RECEIPT_JSON"

policy=$1
destination=$2
receipt=$3
[ -f "$policy" ] || fail "policy is not a regular file"
[ ! -L "$policy" ] || fail "policy must not be a symlink"
[ -d "$(dirname "$receipt")" ] || fail "receipt parent directory must exist"
[ ! -L "$(dirname "$receipt")" ] || fail "receipt parent must not be a symlink"
[ ! -e "$receipt" ] || fail "install receipt already exists"
[ ! -L "$receipt" ] || fail "install receipt must not be a symlink"
command -v jq >/dev/null 2>&1 || fail "jq is required"
command -v curl >/dev/null 2>&1 || fail "curl is required"
command -v cosign >/dev/null 2>&1 || fail "a preverified cosign is required"

version=$(jq -er '.scanner.version' "$policy")
archive=$(jq -er '.scanner.linux_amd64_archive.name' "$policy")
archive_sha=$(jq -er '.scanner.linux_amd64_archive.sha256' "$policy")
checksums=$(jq -er '.scanner.checksums.name' "$policy")
checksums_sha=$(jq -er '.scanner.checksums.sha256' "$policy")
bundle=$(jq -er '.scanner.checksums.sigstore_bundle_name' "$policy")
bundle_sha=$(jq -er '.scanner.checksums.sigstore_bundle_sha256' "$policy")
identity=$(jq -er '.scanner.certificate_identity' "$policy")
issuer=$(jq -er '.scanner.certificate_oidc_issuer' "$policy")
binary_evidence=$(jq -er '.scanner.binary_evidence_name' "$policy")

case "$version:$archive_sha:$checksums_sha:$bundle_sha" in
  *[!0-9a-zA-Z._:-]*) fail "policy contains invalid scanner fields" ;;
esac
for asset_name in "$archive" "$checksums" "$bundle" "$binary_evidence"; do
  case "$asset_name" in
    ''|*[!0-9a-zA-Z._-]*) fail "policy contains an invalid asset name" ;;
  esac
done
for digest in "$archive_sha" "$checksums_sha" "$bundle_sha"; do
  case "$digest" in
    *[!0-9a-f]*) fail "policy contains an invalid SHA-256" ;;
  esac
  [ "${#digest}" -eq 64 ] || fail "policy contains an invalid SHA-256"
done

[ ! -e "$destination" ] || fail "destination already exists"
umask 077
mkdir -p "$destination"
base_url="https://github.com/aquasecurity/trivy/releases/download/v$version"

curl --fail --silent --show-error --location --proto '=https' \
  --output "$destination/$archive" "$base_url/$archive"
curl --fail --silent --show-error --location --proto '=https' \
  --output "$destination/$checksums" "$base_url/$checksums"
curl --fail --silent --show-error --location --proto '=https' \
  --output "$destination/$bundle" "$base_url/$bundle"

actual_archive=$(sha256sum "$destination/$archive" | awk '{print $1}')
actual_checksums=$(sha256sum "$destination/$checksums" | awk '{print $1}')
actual_bundle=$(sha256sum "$destination/$bundle" | awk '{print $1}')
[ "$actual_archive" = "$archive_sha" ] || fail "scanner archive SHA-256 mismatch"
[ "$actual_checksums" = "$checksums_sha" ] || fail "checksums SHA-256 mismatch"
[ "$actual_bundle" = "$bundle_sha" ] || fail "Sigstore bundle SHA-256 mismatch"

cosign verify-blob \
  --bundle "$destination/$bundle" \
  --certificate-identity "$identity" \
  --certificate-oidc-issuer "$issuer" \
  "$destination/$checksums" >/dev/null

recorded_sha=$(awk -v name="$archive" '$2 == name {print $1}' "$destination/$checksums")
[ "$recorded_sha" = "$archive_sha" ] || fail "signed checksums do not bind the scanner archive"

tar -xzf "$destination/$archive" -C "$destination" trivy
[ -f "$destination/trivy" ] || fail "scanner archive did not contain a regular binary"
[ ! -L "$destination/trivy" ] || fail "scanner binary must not be a symlink"
chmod 0755 "$destination/trivy"
observed=$(
  "$destination/trivy" version --format json |
    jq -er '.Version // .version'
)
[ "$observed" = "$version" ] || fail "scanner binary version mismatch"

policy_sha=$(sha256sum "$policy" | awk '{print $1}')
binary_sha=$(sha256sum "$destination/trivy" | awk '{print $1}')
archive_size=$(wc -c < "$destination/$archive" | tr -d ' ')
checksums_size=$(wc -c < "$destination/$checksums" | tr -d ' ')
bundle_size=$(wc -c < "$destination/$bundle" | tr -d ' ')
binary_size=$(wc -c < "$destination/trivy" | tr -d ' ')
verified_at=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
receipt_parent=$(dirname "$receipt")
stage_asset() {
  source_path=$1
  evidence_name=$2
  target_path=$receipt_parent/$evidence_name
  if [ "$source_path" != "$target_path" ]; then
    [ ! -e "$target_path" ] || fail "scanner evidence asset already exists: $evidence_name"
    [ ! -L "$target_path" ] || fail "scanner evidence asset is a symlink: $evidence_name"
    asset_temp=$(mktemp "$receipt_parent/.trivy-evidence.XXXXXX")
    if ! cp "$source_path" "$asset_temp"; then
      rm -f "$asset_temp"
      fail "cannot copy scanner evidence: $evidence_name"
    fi
    chmod 0600 "$asset_temp"
    if ! ln "$asset_temp" "$target_path"; then
      rm -f "$asset_temp"
      fail "scanner evidence asset already exists: $evidence_name"
    fi
    rm "$asset_temp"
    cmp -s "$source_path" "$target_path" ||
      fail "staged scanner evidence differs: $evidence_name"
  fi
}
stage_asset "$destination/$archive" "$archive"
stage_asset "$destination/$checksums" "$checksums"
stage_asset "$destination/$bundle" "$bundle"
stage_asset "$destination/trivy" "$binary_evidence"
receipt_temp=$(mktemp "$receipt_parent/.trivy-install-receipt.XXXXXX")
trap 'rm -f "$receipt_temp"' EXIT HUP INT TERM
jq -cnS \
  --arg archive "$archive" \
  --arg archive_sha "$archive_sha" \
  --argjson archive_size "$archive_size" \
  --arg binary_sha "$binary_sha" \
  --arg binary_evidence "$binary_evidence" \
  --argjson binary_size "$binary_size" \
  --arg bundle "$bundle" \
  --arg bundle_sha "$bundle_sha" \
  --argjson bundle_size "$bundle_size" \
  --arg checksums "$checksums" \
  --arg checksums_sha "$checksums_sha" \
  --argjson checksums_size "$checksums_size" \
  --arg identity "$identity" \
  --arg issuer "$issuer" \
  --arg policy_sha "$policy_sha" \
  --arg release_url "$(jq -er '.scanner.release_url' "$policy")" \
  --arg verified_at "$verified_at" \
  --arg version "$version" '
    {
      format_version: 1,
      kind: "trivy-install-receipt-v1",
      policy_sha256: $policy_sha,
      scanner: {
        archive: {path: $archive, sha256: $archive_sha, size: $archive_size},
        binary: {path: $binary_evidence, sha256: $binary_sha, size: $binary_size},
        checksums: {
          path: $checksums,
          sha256: $checksums_sha,
          size: $checksums_size
        },
        name: "trivy",
        sigstore_bundle: {path: $bundle, sha256: $bundle_sha, size: $bundle_size},
        trust: {
          certificate_identity: $identity,
          certificate_oidc_issuer: $issuer,
          release_url: $release_url,
          signed_archive_sha256: $archive_sha
        },
        version: $version
      },
      verified_at: $verified_at
    }
  ' > "$receipt_temp"
chmod 0600 "$receipt_temp"
ln "$receipt_temp" "$receipt" || fail "install receipt already exists"
rm "$receipt_temp"
trap - EXIT HUP INT TERM
printf '%s\n' "$destination/trivy"
