#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/../.." && pwd)
suffix="$$"
fixture="sub2api-logout-header-fixture-$suffix"
edge="sub2api-logout-header-nginx-$suffix"
python_image=python:3.12-alpine@sha256:6d43704baacd1bfbe7c295d7f13079d5d8104ed33568873133f8fc69980419df
nginx_image=nginx:1.28-alpine@sha256:a8b39bd9cf0f83869a2162827a0caf6137ddf759d50a171451b335cecc87d236

cleanup() {
    docker container rm --force "$edge" "$fixture" >/dev/null 2>&1 || true
}
trap cleanup EXIT HUP INT TERM

docker run --rm --read-only \
    --tmpfs /tmp:rw,noexec,nosuid,nodev,size=16m \
    --tmpfs /var/log/sub2api-codex-control:rw,noexec,nosuid,nodev,size=1m \
    --volume "$repo_root/deploy/nginx:/etc/nginx/codex:ro" \
    --volume "$script_dir/nginx-sub2api-logout.conf:/etc/nginx/nginx.conf:ro" \
    --volume "$script_dir/nginx-sub2api-proxy-location.conf:/etc/nginx/sub2api-proxy-location.conf:ro" \
    "$nginx_image" nginx -t

docker run --detach --name "$fixture" --read-only \
    --tmpfs /tmp:rw,noexec,nosuid,nodev,size=16m \
    --volume "$script_dir/sub2api_logout_header_fixture.py:/fixture.py:ro" \
    "$python_image" python /fixture.py serve >/dev/null

docker run --detach --name "$edge" --network "container:$fixture" --read-only \
    --tmpfs /tmp:rw,noexec,nosuid,nodev,size=16m \
    --tmpfs /var/log/sub2api-codex-control:rw,noexec,nosuid,nodev,size=1m \
    --volume "$repo_root/deploy/nginx:/etc/nginx/codex:ro" \
    --volume "$script_dir/nginx-sub2api-logout.conf:/etc/nginx/nginx.conf:ro" \
    --volume "$script_dir/nginx-sub2api-proxy-location.conf:/etc/nginx/sub2api-proxy-location.conf:ro" \
    "$nginx_image" >/dev/null

docker exec "$fixture" python /fixture.py probe
