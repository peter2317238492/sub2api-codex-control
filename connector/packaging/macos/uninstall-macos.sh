#!/bin/sh
set -eu

fail() {
  printf '%s\n' "connector-uninstall: $*" >&2
  exit 1
}

[ "$(id -u)" -eq 0 ] || fail "macOS package uninstall requires root"
[ "$(uname -s)" = Darwin ] || fail "this uninstaller is for macOS only"

for path in \
  /usr/local/bin/sub2api-codex-connector \
  /usr/local/bin/sub2api-codex-connector-ctl \
  "/Library/LaunchAgents/org.sub2api.codex-connector.plist" \
  "/usr/local/share/doc/sub2api-codex-connector/connector.example.json" \
  "/usr/local/share/doc/sub2api-codex-connector/INSTALL.md"
do
  if [ -e "$path" ] || [ -L "$path" ]; then
    [ ! -d "$path" ] || fail "refusing to remove unexpected directory: $path"
    rm -f -- "$path"
  fi
done

rm -f -- "/usr/local/libexec/sub2api-codex-connector/package-lifecycle"
rm -f -- "/usr/local/libexec/sub2api-codex-connector/uninstall-macos"
rmdir "/usr/local/libexec/sub2api-codex-connector" 2>/dev/null || true
rmdir "/usr/local/share/doc/sub2api-codex-connector" 2>/dev/null || true
pkgutil --forget org.sub2api.codex-connector >/dev/null 2>&1 || true

printf '%s\n' "Removed only package-owned Connector files."
printf '%s\n' "Per-user configuration, pairing credentials, and state were preserved."
