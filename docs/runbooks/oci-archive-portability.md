# OCI archive identity across Docker daemons

Docker daemons may expose either the image config digest or the OCI manifest
digest as `docker image inspect .Id` after loading the same archive. Do not
compare that field directly across daemon versions. Instead, map both IDs back
to the transported archive with
[`map-oci-image-archive.py`](../../deploy/scripts/map-oci-image-archive.py).

The verifier requires an out-of-band archive SHA-256, one exact tag and
platform, and at least one expected OCI label. It then fails closed unless:

- every `blobs/sha256/*` filename matches the SHA-256 of its content;
- `index.json` selects exactly one manifest and its digest and size match the
  manifest blob;
- the manifest config and layer descriptors match their blobs;
- `manifest.json`, the index annotations, and the requested tag agree;
- the image config platform and expected labels agree; and
- optional Docker inspect evidence has the same platform and complete label
  map, exposes the tag, and uses either the verified config digest or verified
  manifest digest as its image ID.

The archive must be a verification-user-owned, non-symlink regular file that
is not writable by group or other. The verifier rehashes it after parsing and
rejects metadata changes during verification.

```sh
python3 deploy/scripts/map-oci-image-archive.py \
  --archive control-api-linux-amd64.tar \
  --expected-archive-sha256 "$archive_sha256" \
  --expected-tag sub2api-codex-control-api:release-tag \
  --expected-platform linux/amd64 \
  --expected-label org.opencontainers.image.version="$release" \
  --expected-label org.opencontainers.image.revision="$revision" \
  --expected-label org.opencontainers.image.source="$source" \
  --expected-manifest-digest "sha256:$manifest_hex" \
  --expected-config-digest "sha256:$config_hex" \
  --inspect-json api-image-inspect.json \
  > api-archive-identity.json
```

`--expected-manifest-digest` and `--expected-config-digest` are optional when
creating the first map from an already pinned archive checksum. Supply both on
subsequent hosts. `--docker-image` may replace `--inspect-json` to invoke a
read-only `docker image inspect` directly.

The output is canonical, ASCII JSON with sorted keys and no timestamp or host
path. `image.manifest_digest` and `image.config_digest` are the portable pair;
`daemon.id_kind` states which member of that pair the current daemon exposes.
The same archive produces the same non-daemon portion of the evidence map on
every host.
