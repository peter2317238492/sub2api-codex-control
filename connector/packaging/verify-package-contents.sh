#!/bin/sh
set -eu

fail() {
  printf '%s\n' "verify-package-contents: $*" >&2
  exit 1
}

[ "$#" -eq 4 ] || fail "usage: $0 PACKAGE FORMAT ARCH VERSION"
package=$1
format=$2
arch=$3
version=$4
[ -f "$package" ] && [ ! -L "$package" ] || fail "package must be a regular non-symlink file"
case "$format" in deb|rpm|pkg) ;; *) fail "unsupported package format" ;; esac
case "$arch" in amd64|arm64) ;; *) fail "unsupported architecture" ;; esac
printf '%s\n' "$version" | awk -F. '
  NF != 3 { exit 1 }
  { for (i = 1; i <= NF; i++) if ($i !~ /^[0-9]+$/) exit 1 }
' || fail "version must be an exact three-component semantic version"

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

mode_of() {
  case "$(uname -s)" in
    Darwin) stat -f '%Lp' "$1" ;;
    *) stat -c '%a' "$1" ;;
  esac
}

case "$format" in
  deb)
    command -v dpkg-deb >/dev/null 2>&1 || fail "dpkg-deb is required"
    expected_arch=$arch
    [ "$(dpkg-deb -f "$package" Package)" = sub2api-codex-connector ] || fail "unexpected Debian package name"
    [ "$(dpkg-deb -f "$package" Version)" = "$version" ] || fail "unexpected Debian package version"
    actual_arch=$(dpkg-deb -f "$package" Architecture)
    [ "$actual_arch" = "$expected_arch" ] || fail "Debian architecture is $actual_arch, expected $expected_arch"
    if ! dpkg-deb -c "$package" | awk 'NF > 0 && $2 != "root/root" { exit 1 }'; then
      fail "Debian payload ownership is not root/root"
    fi
    dpkg-deb -x "$package" "$root"
    control="$temporary/debian-control"
    dpkg-deb -e "$package" "$control"
    if find "$control" -type l -print | grep . >/dev/null 2>&1; then
      fail "Debian control archive contains symlinks"
    fi
    if find "$control" ! -type d ! -type f -print | grep . >/dev/null 2>&1; then
      fail "Debian control archive contains non-regular entries"
    fi
    (cd "$control" && find . -type f -print | sed 's#^\./##' | LC_ALL=C sort) > "$temporary/debian-control-files"
    printf '%s\n' control postinst preinst prerm | LC_ALL=C sort > "$temporary/expected-debian-control-files"
    cmp -s "$temporary/expected-debian-control-files" "$temporary/debian-control-files" || \
      fail "Debian control archive inventory is not exact"
    cat > "$temporary/expected-debian-control" <<EOF
Package: sub2api-codex-connector
Version: $version
Section: net
Priority: optional
Architecture: $expected_arch
Maintainer: Sub2API Codex Control release automation
Depends: systemd | systemd-standalone-sysusers
Description: outbound-only user Connector for Sub2API Codex Control
 The package installs no Codex files and exposes no inbound network listener.
EOF
    cmp -s "$temporary/expected-debian-control" "$control/control" || \
      fail "Debian control metadata differs from release policy"
    for hook in preinst postinst prerm; do
      sed "s/@VERSION@/$version/g" "$script_dir/linux/debian/$hook" > "$temporary/expected-debian-$hook"
      cmp -s "$temporary/expected-debian-$hook" "$control/$hook" || \
        fail "Debian $hook differs from the canonical lifecycle script"
      [ "$(mode_of "$control/$hook")" = 755 ] || fail "Debian $hook mode is not 755"
    done
    [ "$(mode_of "$control/control")" = 644 ] || fail "Debian control mode is not 644"
    prefix=usr/share/doc/sub2api-codex-connector
    ;;
  rpm)
    command -v rpm >/dev/null 2>&1 || fail "rpm is required"
    command -v rpm2cpio >/dev/null 2>&1 || fail "rpm2cpio is required"
    command -v cpio >/dev/null 2>&1 || fail "cpio is required"
    case "$arch" in amd64) expected_arch=x86_64 ;; arm64) expected_arch=aarch64 ;; esac
    [ "$(rpm -qp --qf '%{NAME}' "$package")" = sub2api-codex-connector ] || fail "unexpected RPM package name"
    [ "$(rpm -qp --qf '%{VERSION}' "$package")" = "$version" ] || fail "unexpected RPM package version"
    [ "$(rpm -qp --qf '%{RELEASE}' "$package")" = 1 ] || fail "unexpected RPM release"
    [ "$(rpm -qp --qf '%{SUMMARY}' "$package")" = \
      'Outbound-only user Connector for Sub2API Codex Control' ] || \
      fail "unexpected RPM summary"
    [ "$(rpm -qp --qf '%{LICENSE}' "$package")" = Apache-2.0 ] || \
      fail "unexpected RPM license"
    [ "$(rpm -qp --qf '%{BUILDHOST}' "$package")" = reproducible.invalid ] || \
      fail "unexpected RPM build host"
    [ "$(rpm -qp --qf '%{OS}' "$package")" = linux ] || fail "unexpected RPM operating system"
    actual_arch=$(rpm -qp --qf '%{ARCH}' "$package")
    [ "$actual_arch" = "$expected_arch" ] || fail "RPM architecture is $actual_arch, expected $expected_arch"
    if rpm -qp --qf '[%{FILEUSERNAME}:%{FILEGROUPNAME}\n]' "$package" | \
      awk 'NF > 0 && $0 != "root:root" { exit 1 }'; then
      :
    else
      fail "RPM payload ownership is not root/root"
    fi
    cat > "$temporary/expected-rpm-prein" <<'EOF'
if [ -x /usr/libexec/sub2api-codex-connector/package-lifecycle ]; then
  /usr/libexec/sub2api-codex-connector/package-lifecycle prepare-upgrade
elif [ -f /usr/bin/sub2api-codex-connector ] && [ ! -L /usr/bin/sub2api-codex-connector ]; then
  install -d -m 0700 /var/lib/sub2api-codex-connector/package-rollback
  cp -p /usr/bin/sub2api-codex-connector /var/lib/sub2api-codex-connector/package-rollback/previous
  chmod 0755 /var/lib/sub2api-codex-connector/package-rollback/previous
fi
EOF
    cat > "$temporary/expected-rpm-postin" <<EOF
/usr/libexec/sub2api-codex-connector/package-lifecycle verify-install "$version"
echo "Run sub2api-codex-connector-ctl init as each Connector user; no Codex files were changed."
EOF
    cat > "$temporary/expected-rpm-preun" <<'EOF'
if [ $1 -eq 0 ]; then
  /usr/libexec/sub2api-codex-connector/package-lifecycle uninstall
fi
EOF
    [ "$(rpm -qp --qf '%{PREIN}' "$package")" = "$(cat "$temporary/expected-rpm-prein")" ] || \
      fail "RPM preinstall script differs from release policy"
    [ "$(rpm -qp --qf '%{POSTIN}' "$package")" = "$(cat "$temporary/expected-rpm-postin")" ] || \
      fail "RPM postinstall script differs from release policy"
    [ "$(rpm -qp --qf '%{PREUN}' "$package")" = "$(cat "$temporary/expected-rpm-preun")" ] || \
      fail "RPM preuninstall script differs from release policy"
    # The aggregate *SCRIPTS tags cover every trigger type and, unlike the
    # per-type aliases, are understood by rpm 4.18 on the release runners.
    for tag in \
      POSTUN PRETRANS POSTTRANS VERIFYSCRIPT TRIGGERSCRIPTS \
      FILETRIGGERSCRIPTS TRANSFILETRIGGERSCRIPTS
    do
      value=$(rpm -qp --qf "%{$tag}" "$package")
      [ -z "$value" ] || [ "$value" = '(none)' ] || fail "RPM contains an unapproved $tag script"
    done
    for tag in PREINPROG POSTINPROG PREUNPROG; do
      [ "$(rpm -qp --qf "%{$tag}" "$package")" = /bin/sh ] || fail "RPM $tag interpreter is not /bin/sh"
    done
    rpm -qp --requires "$package" | \
      awk '$0 !~ /^rpmlib\(/ { print }' | LC_ALL=C sort -u > "$temporary/rpm-requires"
    printf '%s\n' /bin/sh systemd | LC_ALL=C sort > "$temporary/expected-rpm-requires"
    cmp -s "$temporary/expected-rpm-requires" "$temporary/rpm-requires" || \
      fail "RPM dependency header is not the exact admitted set"
    # rpm marks %_docdir payloads as documentation (flag 2) on its own; that
    # marking is accepted only there, while ghost/config/missingok and every
    # other flag stay rejected everywhere.
    if rpm -qp --qf '[%{FILEFLAGS}\t%{FILENAMES}\n]' "$package" | awk -F '\t' '
      NF == 0 { next }
      $1 == "0" { next }
      $1 == "2" && index($2, "/usr/share/doc/") == 1 { next }
      { exit 1 }
    '; then
      :
    else
      fail "RPM contains ghost/config/missingok or other flagged file entries"
    fi
    if rpm -qp --qf '[%{FILECAPS}\n]' "$package" | awk 'NF > 0 && $0 != "(none)" { exit 1 }'; then
      :
    else
      fail "RPM payload declares file capabilities"
    fi
    rpm2cpio "$package" > "$temporary/package.cpio"
    (cd "$root" && cpio --quiet -idm --no-absolute-filenames < "$temporary/package.cpio")
    prefix=usr/share/doc/sub2api-codex-connector
    ;;
  pkg)
    [ "$(uname -s)" = Darwin ] || fail "macOS pkg inspection must run on macOS"
    command -v pkgutil >/dev/null 2>&1 || fail "pkgutil is required"
    [ -x /usr/bin/python3 ] || fail "/usr/bin/python3 is required"
    command -v lsbom >/dev/null 2>&1 || fail "lsbom is required"
    pkgutil --expand-full "$package" "$temporary/expanded"
    (cd "$temporary/expanded" && find . -mindepth 1 -maxdepth 1 -print | sed 's#^\./##' | LC_ALL=C sort) > "$temporary/pkg-top-level"
    printf '%s\n' Bom PackageInfo Payload Scripts | LC_ALL=C sort > "$temporary/expected-pkg-top-level"
    cmp -s "$temporary/expected-pkg-top-level" "$temporary/pkg-top-level" || \
      fail "macOS package top-level component inventory is not exact"
    find "$temporary/expanded" -type d -name Payload -print | LC_ALL=C sort > "$temporary/pkg-payloads"
    [ "$(wc -l < "$temporary/pkg-payloads" | tr -d ' ')" -eq 1 ] || fail "macOS package must contain exactly one payload"
    payload=$(sed -n '1p' "$temporary/pkg-payloads")
    find "$temporary/expanded" -type f -name PackageInfo -print | LC_ALL=C sort > "$temporary/pkg-info-files"
    [ "$(wc -l < "$temporary/pkg-info-files" | tr -d ' ')" -eq 1 ] || fail "macOS package must contain exactly one PackageInfo"
    package_info=$(sed -n '1p' "$temporary/pkg-info-files")
    /usr/bin/python3 -I - "$package_info" "$version" <<'PY'
import sys
import xml.etree.ElementTree as ET

root = ET.parse(sys.argv[1]).getroot()
expected = {
    "identifier": "org.sub2api.codex-connector",
    "version": sys.argv[2],
    "install-location": "/",
    "auth": "root",
    "format-version": "2",
    "overwrite-permissions": "true",
    "relocatable": "false",
    "postinstall-action": "none",
    "minimumSystemVersion": "12.0",
}
if (
    root.tag != "pkg-info"
    or any(root.get(key) != value for key, value in expected.items())
    or set(root.attrib) != {*expected, "generator-version"}
):
    raise SystemExit("macOS PackageInfo identity or install policy mismatch")
expected_children = [
    "payload",
    "bundle-version",
    "upgrade-bundle",
    "update-bundle",
    "atomic-update-bundle",
    "strict-identifier",
    "relocate",
    "scripts",
]
if [child.tag for child in root] != expected_children:
    raise SystemExit("macOS PackageInfo component inventory mismatch")
scripts_nodes = root.findall("scripts")
if len(scripts_nodes) != 1:
    raise SystemExit("macOS PackageInfo scripts mapping is ambiguous")
scripts = scripts_nodes[0]
expected_scripts = {
    "preinstall": {"file": "./preinstall", "timeout": "600"},
    "postinstall": {"file": "./postinstall", "timeout": "600"},
}
if (
    [child.tag for child in scripts] != ["preinstall", "postinstall"]
    or any(child.attrib != expected_scripts[child.tag] for child in scripts)
):
    raise SystemExit("macOS PackageInfo lifecycle script mapping mismatch")
PY
    find "$temporary/expanded" -type d -name Scripts -print | LC_ALL=C sort > "$temporary/pkg-script-directories"
    [ "$(wc -l < "$temporary/pkg-script-directories" | tr -d ' ')" -eq 1 ] || fail "macOS package must contain exactly one Scripts directory"
    scripts=$(sed -n '1p' "$temporary/pkg-script-directories")
    if find "$scripts" -type l -print | grep . >/dev/null 2>&1; then
      fail "macOS installer Scripts contains symlinks"
    fi
    if find "$scripts" ! -type d ! -type f -print | grep . >/dev/null 2>&1; then
      fail "macOS installer Scripts contains non-regular entries"
    fi
    (cd "$scripts" && find . -type f -print | sed 's#^\./##' | LC_ALL=C sort) > "$temporary/pkg-script-files"
    printf '%s\n' postinstall preinstall | LC_ALL=C sort > "$temporary/expected-pkg-script-files"
    cmp -s "$temporary/expected-pkg-script-files" "$temporary/pkg-script-files" || \
      fail "macOS installer lifecycle script inventory is not exact"
    for hook in preinstall postinstall; do
      sed "s/@VERSION@/$version/g" "$script_dir/macos/scripts/$hook" > "$temporary/expected-pkg-$hook"
      cmp -s "$temporary/expected-pkg-$hook" "$scripts/$hook" || \
        fail "macOS $hook differs from the canonical lifecycle script"
      [ "$(mode_of "$scripts/$hook")" = 755 ] || fail "macOS $hook mode is not 755"
    done
    find "$temporary/expanded" -type f -name Bom -print | LC_ALL=C sort > "$temporary/pkg-bom-files"
    [ "$(wc -l < "$temporary/pkg-bom-files" | tr -d ' ')" -eq 1 ] || fail "macOS package must contain exactly one BOM"
    bom=$(sed -n '1p' "$temporary/pkg-bom-files")
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
if find "$root" ! -type d ! -type f -print | grep . >/dev/null 2>&1; then
  fail "package payload contains non-regular entries"
fi
if find "$root" -type f -links +1 -print | grep . >/dev/null 2>&1; then
  fail "package payload contains hard-linked files"
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

required_mode() {
  relative=$1
  expected=$2
  target="$root/$relative"
  case "$(uname -s)" in
    Darwin) actual=$(stat -f '%Lp' "$target") ;;
    *) actual=$(stat -c '%a' "$target") ;;
  esac
  [ "$actual" = "$expected" ] || fail "package mode for $relative is $actual, expected $expected"
}

case "$format" in
  deb|rpm)
    required_file usr/bin/sub2api-codex-connector
    required_file usr/bin/sub2api-codex-connector-ctl "$script_dir/common/sub2api-codex-connector-ctl"
    required_file usr/libexec/sub2api-codex-connector/package-lifecycle "$script_dir/common/package-lifecycle"
    required_file usr/lib/systemd/user/sub2api-codex-connector.service "$script_dir/linux/sub2api-codex-connector.service"
    required_mode usr/bin/sub2api-codex-connector 755
    required_mode usr/bin/sub2api-codex-connector-ctl 755
    required_mode usr/libexec/sub2api-codex-connector/package-lifecycle 755
    required_mode usr/lib/systemd/user/sub2api-codex-connector.service 644
    ;;
  pkg)
    required_file usr/local/bin/sub2api-codex-connector
    required_file usr/local/bin/sub2api-codex-connector-ctl "$script_dir/common/sub2api-codex-connector-ctl"
    required_file usr/local/libexec/sub2api-codex-connector/package-lifecycle "$script_dir/common/package-lifecycle"
    required_file usr/local/libexec/sub2api-codex-connector/uninstall-macos "$script_dir/macos/uninstall-macos.sh"
    required_file Library/LaunchAgents/org.sub2api.codex-connector.plist "$script_dir/macos/org.sub2api.codex-connector.plist"
    required_mode usr/local/bin/sub2api-codex-connector 755
    required_mode usr/local/bin/sub2api-codex-connector-ctl 755
    required_mode usr/local/libexec/sub2api-codex-connector/package-lifecycle 755
    required_mode usr/local/libexec/sub2api-codex-connector/uninstall-macos 755
    required_mode Library/LaunchAgents/org.sub2api.codex-connector.plist 644
    ;;
esac

required_file "$prefix/connector.example.json" "$script_dir/common/connector.example.json"
required_file "$prefix/INSTALL.md" "$script_dir/INSTALL.md"
required_file "$prefix/LICENSE" "$repo_root/LICENSE"
required_file "$prefix/NOTICE" "$repo_root/NOTICE"
required_file "$prefix/THIRD_PARTY_NOTICES.md" "$repo_root/THIRD_PARTY_NOTICES.md"
required_file "$prefix/third_party/components.json" "$repo_root/third_party/components.json"
for document in connector.example.json INSTALL.md LICENSE NOTICE THIRD_PARTY_NOTICES.md third_party/components.json; do
  required_mode "$prefix/$document" 644
done

expected_payload="$temporary/expected-payload-files"
{
  case "$format" in
    deb|rpm)
      printf '%s\n' \
        usr/bin/sub2api-codex-connector \
        usr/bin/sub2api-codex-connector-ctl \
        usr/libexec/sub2api-codex-connector/package-lifecycle \
        usr/lib/systemd/user/sub2api-codex-connector.service
      ;;
    pkg)
      printf '%s\n' \
        usr/local/bin/sub2api-codex-connector \
        usr/local/bin/sub2api-codex-connector-ctl \
        usr/local/libexec/sub2api-codex-connector/package-lifecycle \
        usr/local/libexec/sub2api-codex-connector/uninstall-macos \
        Library/LaunchAgents/org.sub2api.codex-connector.plist
      ;;
  esac
  printf '%s\n' \
    "$prefix/connector.example.json" \
    "$prefix/INSTALL.md" \
    "$prefix/LICENSE" \
    "$prefix/NOTICE" \
    "$prefix/THIRD_PARTY_NOTICES.md" \
    "$prefix/third_party/components.json"
  for license in "$repo_root"/third_party/licenses/*; do
    basename_value=$(basename "$license")
    printf '%s\n' "$prefix/third_party/licenses/$basename_value"
  done
} | LC_ALL=C sort > "$expected_payload"
(cd "$root" && find . -type f -print | sed 's#^\./##' | LC_ALL=C sort) > "$temporary/actual-payload-files"
cmp -s "$expected_payload" "$temporary/actual-payload-files" || \
  fail "package payload file inventory is not exact"

if [ "$format" = rpm ]; then
  rpm -qp --qf '[%{FILENAMES}\n]' "$package" | \
    sed -e 's#^/##' -e '/^$/d' | LC_ALL=C sort > "$temporary/rpm-header-files"
  cmp -s "$expected_payload" "$temporary/rpm-header-files" || \
    fail "RPM header filename inventory differs from the payload"
fi

awk -F/ '{
  path = ""
  for (i = 1; i < NF; i++) {
    path = (path == "" ? $i : path "/" $i)
    print path
  }
}' "$expected_payload" | LC_ALL=C sort -u > "$temporary/expected-payload-directories"
(cd "$root" && find . -type d -print | sed -e 's#^\./##' -e '/^\.$/d' | LC_ALL=C sort) > "$temporary/actual-payload-directories"
cmp -s "$temporary/expected-payload-directories" "$temporary/actual-payload-directories" || \
  fail "package payload directory inventory is not exact"

while IFS= read -r directory; do
  [ "$(mode_of "$root/$directory")" = 755 ] || \
    fail "package directory mode is not 755: $directory"
done < "$temporary/expected-payload-directories"

if [ "$format" = pkg ]; then
  if lsbom -l -s "$bom" | grep . >/dev/null 2>&1 || \
     lsbom -b -s "$bom" | grep . >/dev/null 2>&1 || \
     lsbom -c -s "$bom" | grep . >/dev/null 2>&1; then
    fail "macOS BOM contains a link or device entry"
  fi
  lsbom -f -p f "$bom" | sed -e 's#^\./##' -e '/^\.$/d' | \
    LC_ALL=C sort > "$temporary/bom-files"
  cmp -s "$expected_payload" "$temporary/bom-files" || \
    fail "macOS BOM file inventory differs from the payload"
  lsbom -d -p f "$bom" | sed -e 's#^\./##' -e '/^\.$/d' | \
    LC_ALL=C sort > "$temporary/bom-directories"
  cmp -s "$temporary/expected-payload-directories" "$temporary/bom-directories" || \
    fail "macOS BOM directory inventory differs from the payload"
  printf '%s\n' \
    usr/local/bin/sub2api-codex-connector \
    usr/local/bin/sub2api-codex-connector-ctl \
    usr/local/libexec/sub2api-codex-connector/package-lifecycle \
    usr/local/libexec/sub2api-codex-connector/uninstall-macos \
    > "$temporary/bom-executables"
  lsbom -f -p fmug "$bom" > "$temporary/bom-file-metadata"
  awk -F '\t' '
    NR == FNR { executable[$0] = 1; next }
    {
      path = $1
      sub(/^\.\//, "", path)
      expected = (path in executable ? "100755" : "100644")
      mode = $2
      sub(/^0/, "", mode)
      if (mode != expected || $3 != "0" || $4 != "0") exit 1
    }
  ' "$temporary/bom-executables" "$temporary/bom-file-metadata" || \
    fail "macOS BOM file modes or ownership differ from policy"
  lsbom -d -p fmug "$bom" | awk -F '\t' '
    {
      mode = $2
      sub(/^0/, "", mode)
      if (mode != "40755" || $3 != "0" || $4 != "0") exit 1
    }
  ' || fail "macOS BOM directory modes or ownership differ from policy"
fi

for license in "$repo_root"/third_party/licenses/*; do
  [ -f "$license" ] && [ ! -L "$license" ] || fail "invalid source license input"
  required_file "$prefix/third_party/licenses/$(basename "$license")" "$license"
  required_mode "$prefix/third_party/licenses/$(basename "$license")" 644
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
