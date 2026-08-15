#!/bin/sh
set -eu

fail() {
  printf '%s\n' "linux-sign-rpm: $*" >&2
  exit 1
}

[ "$#" -eq 1 ] || fail "usage: $0 RELEASE_DIRECTORY"
[ "$(uname -s)" = Linux ] || fail "must run on Linux"
for command in gpg rpm rpmsign rpmkeys jq openssl; do
  command -v "$command" >/dev/null 2>&1 || fail "missing required command: $command"
done

required_secret() {
  variable=$1
  eval "value=\${$variable:-}"
  [ -n "$value" ] || fail "protected environment variable $variable is required"
}

required_secret RPM_SIGNING_PRIVATE_KEY_BASE64
required_secret RPM_SIGNING_PUBLIC_KEY_BASE64
required_secret RPM_SIGNING_KEY_PASSWORD
required_secret RPM_EXPECTED_SIGNING_FINGERPRINT
case "$RPM_EXPECTED_SIGNING_FINGERPRINT" in
  *[!A-F0-9]*|'') fail "RPM fingerprint must be uppercase hexadecimal" ;;
esac
fingerprint_length=${#RPM_EXPECTED_SIGNING_FINGERPRINT}
[ "$fingerprint_length" -ge 40 ] && [ "$fingerprint_length" -le 64 ] || \
  fail "RPM fingerprint must contain 40 to 64 hexadecimal characters"

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
release_dir=$(CDPATH= cd -- "$1" && pwd)
temporary=$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/connector-rpm-sign.XXXXXX")
cleanup() {
  status=$?
  trap - EXIT HUP INT TERM
  rm -rf -- "$temporary"
  exit "$status"
}
trap cleanup EXIT HUP INT TERM
export GNUPGHOME="$temporary/signing-gnupg"
verify_gnupg="$temporary/verification-gnupg"
mkdir -m 0700 "$GNUPGHOME" "$verify_gnupg"
private_key="$temporary/private.asc"
public_key="$temporary/public.asc"
passphrase="$temporary/passphrase"
printf '%s' "$RPM_SIGNING_PRIVATE_KEY_BASE64" | base64 --decode > "$private_key"
printf '%s' "$RPM_SIGNING_PUBLIC_KEY_BASE64" | base64 --decode > "$public_key"
printf '%s' "$RPM_SIGNING_KEY_PASSWORD" > "$passphrase"
chmod 0600 "$private_key" "$public_key" "$passphrase"
unset RPM_SIGNING_PRIVATE_KEY_BASE64 RPM_SIGNING_PUBLIC_KEY_BASE64 RPM_SIGNING_KEY_PASSWORD

gpg --batch --import "$private_key" >/dev/null 2>&1
actual_fingerprint=$(gpg --batch --with-colons --fingerprint "$RPM_EXPECTED_SIGNING_FINGERPRINT" | \
  awk -F: '$1 == "fpr" { print $10; exit }')
[ "$actual_fingerprint" = "$RPM_EXPECTED_SIGNING_FINGERPRINT" ] || \
  fail "private signing key fingerprint does not match the protected trust value"
public_fingerprint=$(GNUPGHOME="$verify_gnupg" gpg --batch --import-options show-only --with-colons --import "$public_key" | \
  awk -F: '$1 == "fpr" { print $10; exit }')
[ "$public_fingerprint" = "$RPM_EXPECTED_SIGNING_FINGERPRINT" ] || \
  fail "public verification key fingerprint does not match the protected trust value"

wrapper="$temporary/gpg-wrapper"
cat > "$wrapper" <<EOF
#!/bin/sh
exec gpg --batch --no-tty --pinentry-mode loopback --passphrase-file '$passphrase' "\$@"
EOF
chmod 0700 "$wrapper"

version=$(jq -er '.config.connector_version' "$release_dir/.release-work.json")
for target in linux-amd64 linux-arm64; do
  arch=${target#linux-}
  package="$release_dir/sub2api-codex-connector_${version}_linux_${arch}.rpm"
  [ -f "$package" ] && [ ! -L "$package" ] || fail "missing RPM package $package"
  rpmsign --addsign \
    --define "_signature gpg" \
    --define "_gpg_name $RPM_EXPECTED_SIGNING_FINGERPRINT" \
    --define "__gpg $wrapper" \
    "$package"

  rpm_db="$temporary/rpmdb-$target"
  mkdir -m 0700 "$rpm_db"
  rpm --dbpath "$rpm_db" --initdb
  rpm --dbpath "$rpm_db" --import "$public_key"
  report="$temporary/$target.rpm-signature.txt"
  rpmkeys --dbpath "$rpm_db" --checksig --verbose "$package" > "$report" 2>&1
  grep -Ei 'pgp.*ok|signature.*ok' "$report" >/dev/null || fail "RPM signature verification failed for $target"

  python3 "$script_dir/release.py" record-native-package-evidence \
    --output "$release_dir" \
    --target "$target" \
    --package-format rpm \
    --rpm-public-key "$public_key" \
    --rpm-report "$report" \
    --expected-rpm-fingerprint "$RPM_EXPECTED_SIGNING_FINGERPRINT"
done

echo "linux-sign-rpm: signed and independently verified both RPM packages"
