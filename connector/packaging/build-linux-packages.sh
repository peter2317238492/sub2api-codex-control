#!/bin/sh
set -eu

fail() {
  printf '%s\n' "build-linux-packages: $*" >&2
  exit 1
}

if [ "$#" -ne 6 ]; then
  fail "usage: $0 BINARY VERSION GOARCH SOURCE_DATE_EPOCH OUTPUT_DIR ITERATION"
fi

binary=$1
version=$2
goarch=$3
source_date_epoch=$4
output_dir=$5
iteration=$6

[ -f "$binary" ] && [ ! -L "$binary" ] || fail "binary must be a regular non-symlink file"
case "$version" in *[!0-9.]*|.*|*..*|*.) fail "invalid version" ;; esac
case "$goarch" in amd64) deb_arch=amd64; rpm_arch=x86_64 ;; arm64) deb_arch=arm64; rpm_arch=aarch64 ;; *) fail "unsupported architecture" ;; esac
case "$source_date_epoch" in ''|*[!0-9]*) fail "SOURCE_DATE_EPOCH must be numeric" ;; esac
case "$iteration" in ''|*[!0-9]*) fail "iteration must be numeric" ;; esac

for command in dpkg-deb rpmbuild install sed find touch mktemp; do
  command -v "$command" >/dev/null 2>&1 || fail "missing required command: $command"
done

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
connector_dir=$(CDPATH= cd -- "$script_dir/.." && pwd)
repo_root=$(CDPATH= cd -- "$connector_dir/.." && pwd)
temporary=$(mktemp -d "${TMPDIR:-/tmp}/connector-linux-package.XXXXXX")
cleanup() {
  status=$?
  trap - EXIT HUP INT TERM
  rm -rf -- "$temporary"
  exit "$status"
}
trap cleanup EXIT HUP INT TERM

mkdir -p -- "$output_dir"
deb_name="sub2api-codex-connector_${version}_linux_${goarch}.deb"
rpm_name="sub2api-codex-connector_${version}_linux_${goarch}.rpm"

populate_root() {
  root=$1
  install -d -m 0755 \
    "$root/usr/bin" \
    "$root/usr/libexec/sub2api-codex-connector" \
    "$root/usr/lib/systemd/user" \
    "$root/usr/share/doc/sub2api-codex-connector/third_party/licenses"
  install -m 0755 "$binary" "$root/usr/bin/sub2api-codex-connector"
  install -m 0755 "$script_dir/common/sub2api-codex-connector-ctl" \
    "$root/usr/bin/sub2api-codex-connector-ctl"
  install -m 0755 "$script_dir/common/package-lifecycle" \
    "$root/usr/libexec/sub2api-codex-connector/package-lifecycle"
  install -m 0644 "$script_dir/linux/sub2api-codex-connector.service" \
    "$root/usr/lib/systemd/user/sub2api-codex-connector.service"
  install -m 0644 "$script_dir/common/connector.example.json" \
    "$root/usr/share/doc/sub2api-codex-connector/connector.example.json"
  install -m 0644 "$script_dir/INSTALL.md" \
    "$root/usr/share/doc/sub2api-codex-connector/INSTALL.md"
  install -m 0644 "$repo_root/LICENSE" \
    "$root/usr/share/doc/sub2api-codex-connector/LICENSE"
  install -m 0644 "$repo_root/NOTICE" \
    "$root/usr/share/doc/sub2api-codex-connector/NOTICE"
  install -m 0644 "$repo_root/THIRD_PARTY_NOTICES.md" \
    "$root/usr/share/doc/sub2api-codex-connector/THIRD_PARTY_NOTICES.md"
  install -m 0644 "$repo_root/third_party/components.json" \
    "$root/usr/share/doc/sub2api-codex-connector/third_party/components.json"
  for license in "$repo_root"/third_party/licenses/*; do
    [ -f "$license" ] && [ ! -L "$license" ] || fail "invalid third-party license input: $license"
    install -m 0644 "$license" \
      "$root/usr/share/doc/sub2api-codex-connector/third_party/licenses/$(basename "$license")"
  done
  find "$root" -exec touch -h -d "@$source_date_epoch" {} +
}

deb_root="$temporary/deb-root"
populate_root "$deb_root"
install -d -m 0755 "$deb_root/DEBIAN"
cat >"$deb_root/DEBIAN/control" <<EOF
Package: sub2api-codex-connector
Version: $version
Section: net
Priority: optional
Architecture: $deb_arch
Maintainer: Sub2API Codex Control release automation
Depends: systemd | systemd-standalone-sysusers
Description: outbound-only user Connector for Sub2API Codex Control
 The package installs no Codex files and exposes no inbound network listener.
EOF
for hook in preinst postinst prerm; do
  sed "s/@VERSION@/$version/g" "$script_dir/linux/debian/$hook" >"$deb_root/DEBIAN/$hook"
  chmod 0755 "$deb_root/DEBIAN/$hook"
done
find "$deb_root/DEBIAN" -exec touch -h -d "@$source_date_epoch" {} +
SOURCE_DATE_EPOCH=$source_date_epoch TZ=UTC LC_ALL=C \
  dpkg-deb --root-owner-group -Zxz -z9 --build "$deb_root" "$output_dir/$deb_name"

rpm_top="$temporary/rpmbuild"
install -d -m 0755 "$rpm_top/BUILD" "$rpm_top/BUILDROOT" "$rpm_top/RPMS" "$rpm_top/SOURCES" "$rpm_top/SPECS" "$rpm_top/SRPMS"
rpm_root="$rpm_top/SOURCES/root"
populate_root "$rpm_root"
spec="$rpm_top/SPECS/sub2api-codex-connector.spec"
cat >"$spec" <<EOF
%global debug_package %{nil}
%global _build_id_links none
%global __os_install_post %{nil}
Name: sub2api-codex-connector
Version: $version
Release: 1
Summary: Outbound-only user Connector for Sub2API Codex Control
License: Apache-2.0
Requires: systemd

%description
The package installs no Codex files and exposes no inbound network listener.

%prep

%build

%install
rm -rf %{buildroot}
cp -a "$rpm_root/." %{buildroot}/

%pre
if [ -x /usr/libexec/sub2api-codex-connector/package-lifecycle ]; then
  /usr/libexec/sub2api-codex-connector/package-lifecycle prepare-upgrade
elif [ -f /usr/bin/sub2api-codex-connector ] && [ ! -L /usr/bin/sub2api-codex-connector ]; then
  install -d -m 0700 /var/lib/sub2api-codex-connector/package-rollback
  cp -p /usr/bin/sub2api-codex-connector /var/lib/sub2api-codex-connector/package-rollback/previous
  chmod 0755 /var/lib/sub2api-codex-connector/package-rollback/previous
fi

%post
/usr/libexec/sub2api-codex-connector/package-lifecycle verify-install "$version"
echo "Run sub2api-codex-connector-ctl init as each Connector user; no Codex files were changed."

%preun
if [ \$1 -eq 0 ]; then
  /usr/libexec/sub2api-codex-connector/package-lifecycle uninstall
fi

%files
%attr(0755,root,root) /usr/bin/sub2api-codex-connector
%attr(0755,root,root) /usr/bin/sub2api-codex-connector-ctl
%attr(0755,root,root) /usr/libexec/sub2api-codex-connector/package-lifecycle
%attr(0644,root,root) /usr/lib/systemd/user/sub2api-codex-connector.service
%attr(0644,root,root) /usr/share/doc/sub2api-codex-connector/connector.example.json
%attr(0644,root,root) /usr/share/doc/sub2api-codex-connector/INSTALL.md
%attr(0644,root,root) /usr/share/doc/sub2api-codex-connector/LICENSE
%attr(0644,root,root) /usr/share/doc/sub2api-codex-connector/NOTICE
%attr(0644,root,root) /usr/share/doc/sub2api-codex-connector/THIRD_PARTY_NOTICES.md
%attr(0644,root,root) /usr/share/doc/sub2api-codex-connector/third_party/components.json
%attr(0644,root,root) /usr/share/doc/sub2api-codex-connector/third_party/licenses/*

%changelog
* Tue Nov 14 2023 Sub2API Codex Control release automation - $version-1
- Immutable release build
EOF
touch -d "@$source_date_epoch" "$spec"
SOURCE_DATE_EPOCH=$source_date_epoch TZ=UTC LC_ALL=C \
  rpmbuild -bb "$spec" \
    --define "_topdir $rpm_top" \
    --define "_buildhost reproducible.invalid" \
    --define "_source_filedigest_algorithm 8" \
    --define "_binary_filedigest_algorithm 8" \
    --define "clamp_mtime_to_source_date_epoch 1" \
    --define "use_source_date_epoch_as_buildtime 1" \
    --define "source_date_epoch_from_changelog 0" \
    --define "_binary_payload w9.xzdio" \
    --target "$rpm_arch"

rpm_built=$(find "$rpm_top/RPMS" -type f -name '*.rpm' -print)
[ -n "$rpm_built" ] && [ "$(printf '%s\n' "$rpm_built" | wc -l | tr -d ' ')" -eq 1 ] || fail "rpmbuild produced an unexpected inventory"
install -m 0644 "$rpm_built" "$output_dir/$rpm_name"
touch -d "@$source_date_epoch" "$output_dir/$deb_name" "$output_dir/$rpm_name"
printf '%s\n' "$output_dir/$deb_name" "$output_dir/$rpm_name"
