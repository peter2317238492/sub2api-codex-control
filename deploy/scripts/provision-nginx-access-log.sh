#!/bin/sh
set -eu
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
LC_ALL=C
export LC_ALL
unset PYTHONHOME PYTHONPATH

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
staging_root=$(CDPATH= cd -- "$script_dir/../.." && pwd)

[ "$(id -u)" -eq 0 ] || {
  echo "provision-nginx-access-log: must run as root" >&2
  exit 1
}
[ -x /usr/bin/python3 ] || {
  echo "provision-nginx-access-log: python3 is required" >&2
  exit 1
}

directory_contract() {
  path=$1
  expected_mode=${2:-}
  actual=$(stat -c '%u:%g:%a:%F' "$path" 2>/dev/null) || {
    echo "provision-nginx-access-log: cannot stat trusted staging path: $path" >&2
    exit 1
  }
  old_ifs=$IFS
  IFS=:
  set -- $actual
  IFS=$old_ifs
  uid=$1 gid=$2 mode=$3 kind=$4
  case "$mode" in
    [0-7][0-7][0-7]|[0-7][0-7][0-7][0-7]) ;;
    *) mode=777 ;;
  esac
  [ "$uid:$gid:$kind" = '0:0:directory' ] \
    && [ $((0$mode & 022)) -eq 0 ] \
    && { [ -z "$expected_mode" ] || [ "$mode" = "$expected_mode" ]; } || {
    echo "provision-nginx-access-log: untrusted staging path: $path" >&2
    exit 1
  }
}

file_contract() {
  path=$1
  expected=$2
  actual=$(stat -c '%u:%g:%a:%h:%F' "$path" 2>/dev/null) || {
    echo "provision-nginx-access-log: cannot stat trusted staging file: $path" >&2
    exit 1
  }
  [ "$actual" = "$expected" ] || {
    echo "provision-nginx-access-log: untrusted staging file: $path" >&2
    exit 1
  }
}

ancestor=$staging_root
while :; do
  directory_contract "$ancestor" "$( [ "$ancestor" = "$staging_root" ] && printf 555 )"
  [ "$ancestor" = / ] && break
  ancestor=$(dirname -- "$ancestor")
done
directory_contract "$staging_root/deploy" 555
directory_contract "$staging_root/deploy/scripts" 555
directory_contract "$staging_root/deploy/nginx" 555
file_contract "$script_dir/provision-nginx-access-log.sh" '0:0:555:1:regular file'
file_contract "$script_dir/provision-nginx-access-log.py" '0:0:444:1:regular file'
file_contract "$staging_root/deploy/nginx/codex-control-access.logrotate" \
  '0:0:444:1:regular file'

exec /usr/bin/python3 -I "$script_dir/provision-nginx-access-log.py"
