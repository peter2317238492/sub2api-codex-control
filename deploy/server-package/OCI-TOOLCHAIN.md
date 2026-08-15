# Pinned OCI export toolchain

`oci_toolchain.py` installs only the reviewed Linux x86_64 `crane` binary from
go-containerregistry `v0.21.7`. The policy pins the release archive, upstream
checksums, upstream Sigstore provenance bundle, complete tar member inventory,
and extracted binary digest. A download is never extracted until all three
assets and both archive subject bindings pass.

The helper treats the committed SHA-256 of `multiple.intoto.jsonl` as a reviewed
policy input and checks its DSSE payload subject. It does not independently
authenticate that bundle's certificate, transparency-log entry, source URI, or
tag. A workflow may claim upstream SLSA provenance verification only after an
independently pinned verifier has checked the bundle for source
`github.com/google/go-containerregistry` and tag `v0.21.7`. The fixed archive
and extracted-binary SHA-256 values, not an unauthenticated signature field,
are the installer's extraction trust root.

Run on a Linux x86_64 release host. The destination file and export directory
must not already exist:

```sh
python3 -I deploy/server-package/oci_toolchain.py install \
  --destination /opt/sub2api-release-tools/crane

python3 -I deploy/server-package/oci_toolchain.py verify \
  --crane /opt/sub2api-release-tools/crane
```

For a network-isolated install, put exactly these three original upstream
assets in one directory and add `--evidence-dir /secure/crane-v0.21.7`:

```text
checksums.txt
go-containerregistry_Linux_x86_64.tar.gz
multiple.intoto.jsonl
```

Export the three locked images. Every value must be a digest reference; tags
and URLs are rejected:

```sh
python3 -I deploy/server-package/oci_toolchain.py export-images \
  --crane /opt/sub2api-release-tools/crane \
  --output-dir /secure/release/control-images-oci \
  --image control-api=ghcr.io/owner/control-api@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \
  --image pwa=ghcr.io/owner/control-pwa@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \
  --image postgres-tools=ghcr.io/owner/postgres-tools@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \
  > "$PRIVATE_TEMP_RECEIPT"
```

`PRIVATE_TEMP_RECEIPT` must name a newly created private sibling temporary file.
The release workflow must capture stdout in that temporary file first,
verify that the exporter succeeded, set mode `0444`, fsync it, and promote it
without replacement to the fixed `oci-export-receipt.json` name. A failed
export must not leave that final name. The receipt is a sibling of the new
`control-images-oci` directory because the export directory itself must not
exist before the command starts.

Before each pull, the helper runs `crane manifest` on the locked reference and
requires the exact returned bytes to hash to the locked digest. The media type
must be a direct OCI or Docker image manifest. A top-level multi-platform index
is rejected because Crane resolves it to a child when `--platform` is set and
does not preserve the registry index bytes in the local layout. Supporting such
an index requires a separately authenticated index-to-platform resolution
proof; an annotation alone is not that proof.

The exact Crane invocation for each attempt is:

```text
crane pull --platform linux/amd64 --format=oci --annotate-ref REPOSITORY@sha256:DIGEST PRIVATE_LAYOUT_DIRECTORY
```

Crane v0.21.7 writes an OCI layout directory for `--format=oci`; it does not
write a tar file. The helper therefore validates the layout inventory and
normalizes it into a sorted USTAR archive with fixed modes, owners, and
timestamps. Each image export and normalization is run twice. The command fails
unless both archives are byte-for-byte equal, then retains only
`control-api.oci.tar`, `pwa.oci.tar`, and `postgres-tools.oci.tar`. Canonical
JSON on stdout records every reference, archive size and SHA-256, and the pinned
producer identity. The server package builder remains responsible for proving
each OCI layout's manifest, config, layer closure, labels, platform, and lock
digest before publication.

All work occurs in a current-user-only sibling staging directory. No
final-named directory is visible until all three archives pass, and Linux
promotion uses no-replace atomic rename. Failures remove the private staging
tree. The pinned executable is re-hashed before every subprocess launch; its
path ancestry must be root/current-user owned and not group/world writable.
Normalized archives are rejected before publication if USTAR encoding or the
downstream 8 GiB archive limit cannot represent them.
