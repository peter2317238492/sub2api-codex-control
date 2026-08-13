#!/bin/sh
set -eu

fail() {
  printf '%s\n' "verify-package-contents: $*" >&2
  exit 1
}

[ "$#" -eq 3 ] || fail "usage: $0 PACKAGE FORMAT ARCH"
package=$1
format=$2
arch=$3
[ -f "$package" ] && [ ! -L "$package" ] || fail "package must be a regular non-symlink file"
case "$format" in deb|rpm|pkg) ;; *) fail "unsupported package format" ;; esac
case "$arch" in amd64|arm64) ;; *) fail "unsupported architecture" ;; esac

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/../.." && pwd)
temporary=$(mktemp -d "${TMPDIR:-/tmp}/connector-package-verify.XXXXXX")
cleanup() {
  status=$?
  trap - EXIT HUP INT TERM
  rm -rf -- "$temporary"
  exit "$status"
}
trap cleanup EXIT HUP INT TERM
root="$temporary/root"
mkdir -p "$root"

case "$format" in
  deb)
    command -v dpkg-deb >/dev/null 2>&1 || fail "dpkg-deb is required"
    expected_arch=$arch
    actual_arch=$(dpkg-deb -f "$package" Architecture)
    [ "$actual_arch" = "$expected_arch" ] || fail "Debian architecture is $actual_arch, expected $expected_arch"
    dpkg-deb -x "$package" "$root"
    prefix=usr/share/doc/sub2api-codex-connector
    ;;
  rpm)
    command -v rpm >/dev/null 2>&1 || fail "rpm is required"
    command -v rpm2cpio >/dev/null 2>&1 || fail "rpm2cpio is required"
    command -v cpio >/dev/null 2>&1 || fail "cpio is required"
    case "$arch" in amd64) expected_arch=x86_64 ;; arm64) expected_arch=aarch64 ;; esac
    actual_arch=$(rpm -qp --qf '%{ARCH}' "$package")
    [ "$actual_arch" = "$expected_arch" ] || fail "RPM architecture is $actual_arch, expected $expected_arch"
    rpm2cpio "$package" > "$temporary/package.cpio"
    (cd "$root" && cpio --quiet -idm --no-absolute-filenames < "$temporary/package.cpio")
    prefix=usr/share/doc/sub2api-codex-connector
    ;;
  pkg)
    [ "$(uname -s)" = Darwin ] || fail "macOS pkg inspection must run on macOS"
    command -v pkgutil >/dev/null 2>&1 || fail "pkgutil is required"
    pkgutil --expand-full "$package" "$temporary/expanded"
    payload=$(find "$temporary/expanded" -type d -name Payload -print | head -n 1)
    [ -n "$payload" ] || fail "macOS package has no expanded Payload"
    cp -R "$payload/." "$root/"
    prefix=usr/local/share/doc/sub2api-codex-connector
    command -v lipo >/dev/null 2>&1 || fail "lipo is required"
    lipo_output=$(lipo -info "$root/usr/local/bin/sub2api-codex-connector")
    case "$arch:$lipo_output" in
      amd64:*x86_64*) ;;
      arm64:*arm64*) ;;
      *) fail "macOS package Connector architecture mismatch" ;;
    esac
    ;;
esac

if find "$root" -type l -print | grep . >/dev/null 2>&1; then
  fail "package payload contains symlinks"
fi
if find "$root" \( -path '*/.codex/*' -o -path '*/CODEX_HOME/*' -o -name 'auth.json' -o -name 'config.toml' \) -print | grep . >/dev/null 2>&1; then
  fail "package payload contains a forbidden Codex path"
fi

required_file() {
  relative=$1
  source=${2:-}
  target="$root/$relative"
  [ -f "$target" ] && [ ! -L "$target" ] || fail "package is missing $relative"
  if [ -n "$source" ]; then
    cmp -s "$source" "$target" || fail "package content differs for $relative"
  fi
}

case "$format" in
  deb|rpm)
    required_file usr/bin/sub2api-codex-connector
    required_file usr/bin/sub2api-codex-connector-ctl "$script_dir/common/sub2api-codex-connector-ctl"
    required_file usr/libexec/sub2api-codex-connector/package-lifecycle "$script_dir/common/package-lifecycle"
    required_file usr/lib/systemd/user/sub2api-codex-connector.service "$script_dir/linux/sub2api-codex-connector.service"
    ;;
  pkg)
    required_file usr/local/bin/sub2api-codex-connector
    required_file usr/local/bin/sub2api-codex-connector-ctl "$script_dir/common/sub2api-codex-connector-ctl"
    required_file usr/local/libexec/sub2api-codex-connector/package-lifecycle "$script_dir/common/package-lifecycle"
    required_file usr/local/libexec/sub2api-codex-connector/uninstall-macos "$script_dir/macos/uninstall-macos.sh"
    required_file Library/LaunchAgents/org.sub2api.codex-connector.plist "$script_dir/macos/org.sub2api.codex-connector.plist"
    ;;
esac

required_file "$prefix/connector.example.json" "$script_dir/common/connector.example.json"
required_file "$prefix/INSTALL.md" "$script_dir/INSTALL.md"
required_file "$prefix/LICENSE" "$repo_root/LICENSE"
required_file "$prefix/NOTICE" "$repo_root/NOTICE"
required_file "$prefix/THIRD_PARTY_NOTICES.md" "$repo_root/THIRD_PARTY_NOTICES.md"
required_file "$prefix/third_party/components.json" "$repo_root/third_party/components.json"

for license in "$repo_root"/third_party/licenses/*; do
  [ -f "$license" ] && [ ! -L "$license" ] || fail "invalid source license input"
  required_file "$prefix/third_party/licenses/$(basename "$license")" "$license"
done

find "$root/$prefix/third_party/licenses" -type f -print | \
  sed "s#^$root/$prefix/third_party/licenses/##" | LC_ALL=C sort > "$temporary/actual-licenses"
for license in "$repo_root"/third_party/licenses/*; do
  [ -f "$license" ] && [ ! -L "$license" ] || fail "invalid source license input"
  basename "$license"
done | LC_ALL=C sort > "$temporary/expected-licenses"
cmp -s "$temporary/expected-licenses" "$temporary/actual-licenses" || \
  fail "package third-party license inventory is incomplete or contains extras"

printf '%s\n' "verified $format package content and license inventory for $arch"
