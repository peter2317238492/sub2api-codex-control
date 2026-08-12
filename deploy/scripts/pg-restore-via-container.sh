#!/bin/sh
set -eu

image=${PG_RESTORE_IMAGE:-}

fail() {
  echo "pg-restore-via-container: $*" >&2
  exit 1
}

[ "$#" -eq 2 ] && [ "$1" = "--list" ] \
  || fail "only pg_restore --list INPUT is supported"
case "$image" in
  ?*@sha256:*)
    digest=${image##*@sha256:}
    case "$digest" in
      ''|*[!0-9a-f]*) fail "PG_RESTORE_IMAGE has an invalid sha256 digest" ;;
    esac
    [ "${#digest}" -eq 64 ] \
      || fail "PG_RESTORE_IMAGE has an invalid sha256 digest length"
    ;;
  *) fail "PG_RESTORE_IMAGE must be one immutable sha256 digest reference" ;;
esac
[ -r "$2" ] || fail "the inherited dump descriptor is not readable"
command -v docker >/dev/null 2>&1 || fail "docker is required"

exec docker run --rm -i \
  --pull never \
  --network none \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --pids-limit 32 \
  --memory 128m \
  --cpus 0.5 \
  --entrypoint pg_restore \
  "$image" \
  --list \
  < "$2"
