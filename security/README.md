# Vulnerability release gate

Formal releases use the pinned Trivy build in `vulnerability-policy.json` and
retain its JSON reports, database metadata, manifest, disposition file, and
verification receipt as signed release evidence.

The gate has four coverage profiles:

- `source-ci` covers the unchanged source checkout;
- `control-release` covers source, three Control images, and both server
  packages;
- `connector-release` covers every advertised native Connector package; and
- `formal-release` requires the exact union of all release targets.

Every non-source target is derived from an authenticated release root. The
closed mapping accepts only the signed Connector `manifest.json`, the signed
Control `control-images.lock.json`, and the signed
`server-packages.manifest.json`. A workflow-supplied artifact hash, image
digest, package selector, or SBOM path is not an authority. The caller must
verify each root's adjacent Sigstore bundle with the pinned workflow identity
before running the builder or consumer gate.

`CRITICAL`, `HIGH`, and unclassified findings block release without an
exception path. Every `MEDIUM` or `LOW` finding must have a current entry in
`vulnerability-dispositions.json`, bound to the exact source commit and target.
Each entry requires a named owner, a substantive rationale, review time, and an
expiry no more than 90 days after review. It also binds the target identity,
report SHA-256, and vulnerability database metadata SHA-256; a disposition for
an older build or scan cannot silently carry forward. Stale or unused
dispositions fail.

Run the consumer gate after producing a manifest and Trivy JSON reports:

```sh
python3 -I scripts/check-vulnerabilities.py \
  create-receipt \
  --manifest /private/release-evidence/vulnerability-manifest.json \
  --policy security/vulnerability-policy.json \
  --dispositions /private/release-evidence/vulnerability-dispositions.json \
  --profile formal-release \
  --source-commit "$RELEASE_COMMIT" \
  --receipt /private/release-evidence/vulnerability-receipt.json
```

After authenticating the receipt's Sigstore bundle, public consumers replay the
historical admission at the recorded verification time:

```sh
python3 -I scripts/check-vulnerabilities.py \
  verify-receipt \
  --manifest /private/release-evidence/vulnerability-manifest.json \
  --policy security/vulnerability-policy.json \
  --dispositions /private/release-evidence/vulnerability-dispositions.json \
  --profile formal-release \
  --source-commit "$RELEASE_COMMIT" \
  --receipt /private/release-evidence/vulnerability-receipt.json \
  --max-receipt-age-hours 24
```

The release workflow installs the scanner through `scripts/install-trivy.sh`.
That helper verifies the pinned archive, signed checksums, Sigstore bundle,
Fulcio certificate identity, and OIDC issuer. It now writes a canonical,
no-replace `trivy-install-receipt.json` that binds the policy, archive,
checksums, bundle, extracted binary hash/size, version, trust identity, and
verification time:

```sh
scanner=$(scripts/install-trivy.sh \
  security/vulnerability-policy.json \
  /private/tools/trivy \
  /private/release-evidence/trivy-install-receipt.json)
```

Do not invoke Trivy directly to scan release targets. Install and verify the
repository-pinned Crane 0.21.7 producer through
`deploy/server-package/oci_toolchain.py`, then use exact commands of the form
`crane pull --format=oci --annotate-ref REPOSITORY:TAG LAYOUT` to retain the
complete OCI layouts for the vulnerability DB and Java DB repository/tags fixed
by policy. Crane preserves the custom DB layer media types; the gate requires
those media types exactly and requires the index ref-name annotation to equal
the complete policy `REPOSITORY:TAG`. Preserve the resolved manifest digests,
then copy both cache metadata files and both actual database files into the
evidence directory using the policy-fixed names. The gate re-hashes every
index, manifest, config, layer, metadata, and database file; it also proves each
layer yields the staged SQLite DB and the immutable metadata projection. Also
stage zero-byte `trivy-empty.yaml` and `trivy-empty.ignore` files. Run each
target only through `run-vulnerability-scan.py`; for example, a source scan is:

```sh
python3 -I deploy/server-package/oci_toolchain.py install \
  --destination /private/tools/crane
python3 -I deploy/server-package/oci_toolchain.py verify \
  --crane /private/tools/crane
/private/tools/crane pull --format=oci --annotate-ref \
  ghcr.io/aquasecurity/trivy-db:2 /private/release-evidence/trivy-db-oci
/private/tools/crane pull --format=oci --annotate-ref \
  ghcr.io/aquasecurity/trivy-java-db:1 \
  /private/release-evidence/trivy-java-db-oci

: > /private/release-evidence/trivy-empty.yaml
: > /private/release-evidence/trivy-empty.ignore
"$scanner" --cache-dir /private/tools/trivy-cache \
  --config /private/release-evidence/trivy-empty.yaml image \
  --db-repository ghcr.io/aquasecurity/trivy-db:2 \
  --download-db-only --no-progress
"$scanner" --cache-dir /private/tools/trivy-cache \
  --config /private/release-evidence/trivy-empty.yaml image \
  --java-db-repository ghcr.io/aquasecurity/trivy-java-db:1 \
  --download-java-db-only --no-progress
```

The protected job must use Crane with the same allowlisted environment and
timeouts enforced by its toolchain wrapper, verify the binary immediately
before acquisition, and reject pre-existing layout destinations. It copies the
four resulting cache files into their policy-fixed evidence names before the
controlled scans.

The retained OCI layout proves the tag-selected manifest digest, layer bytes,
and resulting local database bytes. It does not invent an upstream signature:
the Trivy DB publishers currently distribute these database artifacts through
registries without a DB-specific Sigstore bundle. The protected release job
must therefore create each layout itself in a new empty directory by pulling
the exact policy repository and tag over HTTPS; it must never accept a
caller-uploaded layout or digest. The signed project vulnerability receipt then
authenticates that workflow's closed evidence. A policy requiring independent
upstream cryptographic provenance must remain blocked until the publisher adds
a verifiable DB signature or the project adds a separately trusted acquisition
attestation.

```sh
python3 -I scripts/run-vulnerability-scan.py \
  --policy security/vulnerability-policy.json \
  --scanner "$scanner" \
  --scanner-install-receipt /private/release-evidence/trivy-install-receipt.json \
  --cache-dir /private/tools/trivy-cache \
  --config /private/release-evidence/trivy-empty.yaml \
  --ignorefile /private/release-evidence/trivy-empty.ignore \
  --vulnerability-db-metadata /private/release-evidence/trivy-db-metadata.json \
  --vulnerability-db /private/release-evidence/trivy.db \
  --vulnerability-db-oci-layout /private/release-evidence/trivy-db-oci \
  --java-db-metadata /private/release-evidence/trivy-java-db-metadata.json \
  --java-db /private/release-evidence/trivy-java.db \
  --java-db-oci-layout /private/release-evidence/trivy-java-db-oci \
  --target-name source \
  --target-kind source \
  --target-identity "git:$RELEASE_COMMIT" \
  --subject "https://github.com/$GITHUB_REPOSITORY" \
  --source-repository "https://github.com/$GITHUB_REPOSITORY" \
  --source-commit "$RELEASE_COMMIT" \
  --raw-report /private/release-evidence/vulnerability-source.raw.json \
  --report /private/release-evidence/vulnerability-source.json \
  --execution-receipt /private/release-evidence/scan-execution-source.json
```

For a non-source target, replace the source authority arguments with the exact
policy mapping: `--release-root-id`, `--release-root-kind`, and a canonical JSON
`--release-root-selector`. File targets also pass `--subject-file`; its relative
path must be the content-addressed scan subject derived from the root SBOM.
Container subjects must be the root repository plus immutable digest.

The runner re-hashes the installed binary at execution time, proves both staged
database files match the cache used by Trivy, and fixes the complete normalized
argv. It removes every inherited `TRIVY_*` environment override before launch.
Severity filtering, `--ignore-unfixed`, mutable DB updates, configuration, and
ignore rules cannot be added. For file targets it creates its own no-replace,
read-only subject copy, checks it before and after scanning, then removes it. It
creates a retained raw report, a canonical normalized report, and one canonical,
no-replace execution receipt. The receipt binds target authority, root selector,
subject identity/content hash, scanner archive and binary bytes, both DB OCI
layouts/digests and local hashes, empty config hashes, start/finish times, exit
status, both report hashes/sizes, normalization policy, and exact argv.

Native Trivy clean JSON may omit `Vulnerabilities` or encode it as `null`. The
controlled runner normalizes only those two representations to an explicit
empty list and retains the untouched raw report. Every normalized result must
explicitly contain non-empty `Packages` and a `Vulnerabilities` list. The gate
recomputes canonical normalized bytes from the raw report, so a caller cannot
submit a missing or `null` field directly as a clean final report.
Vulnerability package identities must also occur in that result's complete
`--list-all-pkgs` inventory.

Stage reports, execution receipts, verified roots and bundles, their exact
release assets, scanner receipt, databases, and fixed empty files in one private
directory. The inputs JSON contains only the selected profile, source identity,
root descriptors, and each report/execution-receipt path. The root policy derives
all target identities and asset paths. Then create the digest-bearing manifest:

```sh
python3 -I scripts/build-vulnerability-manifest.py \
  --inputs /private/release-evidence/vulnerability-inputs.json \
  --policy security/vulnerability-policy.json \
  --output /private/release-evidence/vulnerability-manifest.json
```

Each target input has exactly `name`, `report_path`, and
`scan_execution_path`. The builder never starts or queries the scanner. It
independently validates every execution receipt and requires every target to use
one binary and one database snapshot.

The manifest, dispositions, and every referenced evidence file must be regular
non-symlink files in one private evidence directory. The manifest records
SHA-256 for the Trivy database metadata and each report. File-package targets
also carry a comprehensive SPDX 2.3 JSON SBOM. The verifier proves that the
SBOM's `DESCRIBES` subject has the package artifact SHA-256. The manifest keeps
the published SBOM path and separately derives the Trivy scan subject name
`<target>.<sbom-sha256>.spdx.json`; the report must name that exact subject.
Public replay therefore uses the released SBOM bytes without requiring a
temporary alias to be another release asset. The policy also fixes every
target's kind (`source`, `container`, or `file`); a required image or source
target cannot be substituted with a different report type. Container targets
bind the expected image digest to the report's image metadata. The receipt
records each target's detected package count as coverage evidence.

The root descriptor array uses this exact shape; `path` values are relative to
the private evidence directory:

```json
{
  "id": "connector",
  "kind": "connector-manifest-v1",
  "path": "connector/manifest.json",
  "signature_bundle_path": "connector/manifest.json.sigstore.json"
}
```

`source-ci` has an empty root array. `connector-release` requires the Connector
root. `control-release` requires both the Control and server-package roots, and
`formal-release` requires all three. A split offline server package is verified
by streaming its ordered physical parts and comparing their combined size and
SHA-256 with the logical package declared by the signed server manifest; the
receipt inventories the published parts rather than inventing an archive path.

The canonical, no-replace receipt lists the exact release roots and signature
bundles, manifest, dispositions, scanner install receipt, scanner archive,
signed checksums, checksums Sigstore bundle, extracted scanner binary, empty
configuration, both complete OCI layouts, database metadata/database files,
every scan execution, raw and normalized reports, physical package parts, file
artifacts, and SBOMs with their paths, sizes, roles, and SHA-256 values.
`verify-receipt` recomputes the entire admission at the signed receipt's
`verified_at` timestamp and requires byte-canonical JSON.
Use `--max-receipt-age-hours` in the immediate post-publication job; long-term
consumers can validate the historically signed admission without pretending
that the original database snapshot is still current.

The inventory has a fixed 23-file common core: manifest and dispositions;
scanner install receipt, archive, extracted binary, checksums, checksums
Sigstore bundle, config, and ignorefile; and for each of the two databases its
metadata, SQLite file, OCI layout marker, index, manifest, config, and layer.
Each target adds exactly `report`, `raw-report`, and `scan-execution`. Each
authenticated release root adds its root and signature bundle. A container adds
one `release-sbom`; a file target adds one `sbom` plus one inventory entry per
physical artifact part. Therefore `source-ci` has 26 entries and
`connector-release` has 55. With the current two-part offline server package,
`control-release` has 53 and `formal-release` has 85; in general those two
counts are `51 + offline_part_count` and `83 + offline_part_count`.

GitHub Release assets are flat, while the authenticated inventory contains
nested OCI paths and may repeat basenames. The Connector and Control workflows
therefore publish each non-root inventory item as
`vulnerability-evidence-<first-16-hex-of-SHA256(receipt-path)>-<basename>`, plus
`vulnerability-receipt.json` and its Sigstore bundle. Each current public
projection has 43 assets: 41 receipt-derived evidence files and the two receipt
files. A public replay must authenticate the receipt before deriving names,
reject collisions, extras, and omissions, verify every recorded hash and size,
and reconstruct the original relative paths with no replacement before running
`verify-receipt`.

OCI inventory roles are individually closed as `database-oci-layout`,
`database-oci-index`, `database-oci-manifest`, `database-oci-config`, and
`database-oci-layer`, once for each database. The two layout roots are fixed by
policy, while manifest/config/layer filenames are their lowercase SHA-256 blob
names. Scanner asset paths and database cache-evidence paths are also fixed by
policy. Raw/final report and execution-receipt paths are target-specific input
paths and must be unique regular files inside the evidence directory.

After separately authenticating the formal receipt's Sigstore bundle, an
aggregation workflow can replay the exact union without enabling publication:

```sh
scripts/verify-formal-vulnerability-release.sh \
  /private/release-evidence \
  security/vulnerability-policy.json \
  "$RELEASE_COMMIT"
```

This aggregation entry point enforces a 24-hour receipt age. Historical
auditors can invoke `verify-receipt` directly without that immediate-release
freshness option after authenticating the archived signature bundle.

All vulnerability Python CLIs fail unless invoked with isolated, safe-path
semantics (`python3 -I`). The verifier and its imported helper modules must come
from the same authenticated project checkout or source bundle; authenticating
only the evidence directory does not authenticate executable verifier code.

Do not use `.trivyignore`, severity filtering, `--ignore-unfixed`, or a mutable
scanner tag for release evidence. A disposition explains a lower-severity
finding; it does not remove the finding from the signed report.
