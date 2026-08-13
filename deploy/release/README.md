# Control image-set release

This directory is the executable trust boundary for the Control API, PWA, and
PostgreSQL backup-tools images. Production never admits one image independently:
`control-images.lock.json` binds all three immutable OCI digests to one annotated
tag, full source commit, migration head, contract/schema locks, dependency lock
inputs, Dockerfiles, a deterministic full-source archive and manifest, SPDX
SBOMs, and SLSA provenance predicates.

## Repository controls

Before creating a release, configure all of these controls:

1. Protect `control-v*` tags from update/deletion and allow creation only by
   release maintainers. The workflow rejects lightweight tags.
2. Protect the `control-images-release-sigstore` environment with required
   reviewers, self-review disabled, and deployment limited to `control-v*`.
   It has no stored signing key; its job receives only GitHub OIDC plus the
   package permission needed to attach signatures and attestations.
3. Protect `control-images-release-publish` the same way. Give it only the
   `IMMUTABLE_RELEASES_READ_TOKEN` described by the Connector release process.
4. Enable GitHub immutable releases and registry retention that prevents
   deletion or garbage collection of admitted image manifests and Sigstore
   referrers. A GitHub Release cannot make GHCR retention immutable by itself.
5. Require review for this workflow, this directory, all three runtime
   Dockerfiles, dependency locks, migration files, and the production Compose
   overlay.

Every third-party action is pinned to a full commit. Validation/build jobs have
no OIDC. The signing job is separated behind a protected environment, and the
publication job receives no OIDC and executes no checked-out repository code.

## Release flow

An annotated `control-v<package version>` tag triggers these fail-closed stages:

1. Verify the annotated tag, exact clean commit, release version, public-source
   and license policy, tests, contracts, digest-pinned base images, the exact
   Hatchling build backend, and the SHA-512-bound pnpm/Corepack distribution.
2. Build `source.tar`, `source-files.manifest`, and
   `source-attestation.json` deterministically from the committed Git tree,
   then independently verify their paths, modes, hashes, metadata, and required
   release-source inventory before any registry credential is used.
3. Build each Linux/amd64 image once from its pinned Dockerfile and push it to
   GHCR under a run-scoped candidate locator. All later operations use the
   returned digest, never that mutable locator.
4. Scan those exact digests with pinned Syft and create SPDX JSON SBOMs. Create
   SLSA v1 predicates whose materials include the exact Git commit and every
   digest-pinned base image. Build an atomic image-set lock that binds the three
   source-bundle assets and reject any extra, missing, symlinked, or mutated
   evidence file.
5. In the protected OIDC job, keylessly sign all three image digests, attach
   signed SPDX and SLSA v1 attestations, sign the image-set lock as a blob, and
   immediately run the consumer verifier with exact issuer/workflow/SHA/ref
   claims. Only after that verification succeeds, promote the three digests to
   their final `control-v*` image tags and read each tag back to require the
   expected digest.
6. Re-read the remote annotated tag through the GitHub API immediately before
   draft creation, before publication, and after publication; require it still
   resolves to the event commit and require immutable releases.
7. In a new read-only job, resolve the tag anonymously, download every asset
   through its public `browser_download_url` into a new empty directory, verify
   GitHub's immutable-release attestation for the release and each asset, then
   re-run the exact-identity Cosign consumer verifier on those public bytes.

This is SLSA v1-compatible provenance. It does not claim a SLSA build level;
runner isolation, branch/tag policy, environment review, and registry retention
remain deployment controls.

The release matrix intentionally contains only `linux/amd64`. Do not advertise
or deploy an ARM image using this evidence. Add a separately evidenced platform
digest and platform-specific SBOM before expanding the matrix.

## Independent verification

The workflow performs this check automatically after publication. Independent
consumers should also download all eleven immutable release assets into one
otherwise empty directory:

```text
control-images.lock.json
control-images.lock.sigstore.json
source.tar
source-files.manifest
source-attestation.json
control-api.spdx.json
control-api.provenance.json
pwa.spdx.json
pwa.provenance.json
postgres-tools.spdx.json
postgres-tools.provenance.json
```

Run the verifier from a separately trusted checkout. Every expected value below
is external policy input from the approved tag/commit record, not a value copied
from the downloaded lock:

```sh
deploy/release/verify-control-images.sh \
  --release-dir /secure/download/control-images \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity \
    https://github.com/OWNER/REPOSITORY/.github/workflows/control-images-release.yml@refs/tags/control-v0.1.0 \
  --certificate-github-workflow-sha 0123456789abcdef0123456789abcdef01234567 \
  --certificate-github-workflow-trigger push \
  --certificate-github-workflow-repository OWNER/REPOSITORY \
  --certificate-github-workflow-ref refs/tags/control-v0.1.0 \
  --expected-source-repository https://github.com/OWNER/REPOSITORY \
  --expected-source-commit 0123456789abcdef0123456789abcdef01234567 \
  --expected-release-tag control-v0.1.0 \
  --expected-api-repository ghcr.io/owner/sub2api-codex-control-api \
  --expected-pwa-repository ghcr.io/owner/sub2api-codex-control-pwa \
  --expected-postgres-tools-repository ghcr.io/owner/sub2api-codex-postgres-tools
```

Verification first authenticates the lock bundle before parsing the lock. It
then requires the exact file inventory and hashes, the source archive/manifest/
attestation binding, atomic release inputs, immutable repository digests, exact
certificate claims, image signatures, and remote attestation predicates
byte-for-JSON equivalent to the immutable local evidence. Missing Cosign,
network/registry failure, malformed output, a tag in place of a digest, or any
mismatch is fatal. Success emits authenticated image, release, source,
migration, contract, release-input, and evidence digest values. Failure never
emits deployable values. The deployment wrapper consumes those values,
independently verifies the source assets with the trusted checkout's
`source_bundle.py`, extracts a new root-owned read-only staging tree, and uses
that tree for Compose and contract admission. It never executes a verifier from
inside the downloaded archive.

## Production Compose

Local E2E continues to use `compose.yaml` and its local builds. Production must
use the separate overlay, after the verifier succeeds and all three verified
digests have been pulled:

```sh
docker pull "$CONTROL_API_IMAGE"
docker pull "$CONTROL_PWA_IMAGE"
docker pull "$CONTROL_POSTGRES_TOOLS_IMAGE"
docker compose --env-file .env \
  -f deploy/docker-compose/compose.yaml \
  -f deploy/docker-compose/compose.production.yaml \
  config --format json > /secure/admission/rendered-compose.json
```

The admission/deployment wrapper must inspect that rendered JSON and reject any
remaining `build`, non-digest image, API/migration digest mismatch, `:local`,
`unknown` revision, unsafe runtime setting, or platform mismatch. It must then
use `--no-build --pull never`; the overlay alone does not replace the admission
wrapper, backup/restore canary, Sub2API runtime verification, or post-start
container inspection.

## Remaining external controls

No release can exist until the repository has a real reviewed Git commit and
annotated protected tag. Keyless signing requires the protected environments,
GitHub OIDC, public Sigstore services, and registry write/retention policy.
Production admission also remains blocked by the independently tracked mutable
Sub2API image/runtime drift and must not be weakened to admit that state.
