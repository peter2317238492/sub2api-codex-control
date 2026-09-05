# Control server release and verification guide

The public Control server release provides both an online package and a complete
offline package for Linux `amd64`. This directory is the executable image trust
boundary behind those packages. Production never admits one image independently:
`control-images.lock.json` binds all three immutable OCI digests to one annotated
tag, full source commit, migration head, contract/schema locks, dependency lock
inputs, Dockerfiles, a deterministic full-source archive and manifest, SPDX
SBOMs, and SLSA provenance predicates.

The server package adds lifecycle commands, the complete reviewed source tree,
offline image layouts, detached image trust, vulnerability admission, and the
signed Connector compatibility aggregate. Operators verify the downloaded
package with a separately trusted checkout before extracting or running any
package-owned code.

> **Release status:** the workflow is deliberately source-only and fail-closed.
> It exposes only `workflow_dispatch`, and its unconditional guard fails before
> validation, registry writes, signing, or publication. Do not add the
> `control-v*` tag trigger until the server-package CLI, vulnerability closure,
> protected environments, clean-host online/offline rehearsals, and production
> admission gates all pass for one reviewed commit.

## Repository controls

Before creating a release, configure all of these controls:

1. Protect `control-v*` tags from update/deletion and allow creation only by
   release maintainers. The workflow rejects lightweight tags.
2. Protect the `control-images-release-sigstore` environment with required
   reviewers, self-review disabled, and deployment limited to `control-v*`.
   It has no stored signing key; its job receives only GitHub OIDC plus the
   package permission needed to attach signatures and attestations. Store no
   secret in this environment.
3. Protect `control-server-release-compatibility` the same way, but give it no
   OIDC and no secret. Set these five public environment variables from one
   reviewed Connector release authorization:
   `CONNECTOR_RELEASE_SOURCE_COMMIT`, `CONNECTOR_RELEASE_TAG`,
   `CONNECTOR_RELEASE_ID`, `CONNECTOR_RELEASE_WORKFLOW_RUN_ID`, and
   `CONNECTOR_RELEASE_WORKFLOW_RUN_ATTEMPT`. The workflow rejects malformed
   values, re-peels the annotated Connector tag, authenticates the signed
   aggregate before parsing it, and reconstructs the current immutable GitHub
   Release descriptor before using its generated metadata.
4. Protect `control-server-release-sigstore` with the same reviewer/tag rules.
   Store no secret or long-lived key in it. Only this package-signing job gets
   OIDC; it receives the Connector trust values as fixed outputs of the
   compatibility authorization job and rechecks both annotated tags before
   signing.
5. Protect `control-images-release-publish` the same way. Give it only the
   `IMMUTABLE_RELEASES_READ_TOKEN` described by the Connector release process.
6. Protect `control-images-release-promote` with the same reviewer/tag rules.
   Store no secret in it. Its job receives only `contents: read` and
   `packages: write`, and may create the three final `control-v*` GHCR tags only
   after the immutable public Release and its complete anonymous replay succeed.
7. Enable GitHub immutable releases and registry retention that prevents
   deletion or garbage collection of admitted image manifests and Sigstore
   referrers. A GitHub Release cannot make GHCR retention immutable by itself.
8. Require review for this workflow, this directory, all three runtime
   Dockerfiles, dependency locks, migration files, and the production Compose
   overlay.
9. Record the exact pinned `crane` producer version and binary digest used for
   offline OCI exports. The package job must prove each archive's platform,
   manifest/config/layer closure, labels, and digest against the signed image
   lock, then repeat the export and require byte equality.
10. Approve one Connector public-verification aggregate before the Control tag is
   authorized. The input must bind the immutable Connector Release ID, tag,
   asset inventory, Linux/macOS platform receipts, source commit, schema, and
   package metadata. Fetch it from the exact completed workflow run recorded by
   the release authorization; never accept a hand-written metadata file or a
   mutable “latest” lookup.
11. Protect this workflow, `deploy/server-package/`, `security/`, vulnerability
   tooling, lifecycle wrappers, production deployment/admission scripts,
   migrations, recovery tooling, and both release READMEs under required review.

Every third-party action is pinned to a full commit. Validation/build and
compatibility jobs have no OIDC. Image and server-package signing use separate
protected environments, and the publication job receives no OIDC and executes
no checked-out repository code. No job combines Connector approval, native
signing keys, Sigstore identity, and GitHub Release write permission.

## Release flow

After the source-only guard is replaced by the reviewed protected-tag trigger,
an annotated `control-v<package version>` tag will run these fail-closed stages:

1. Verify the annotated tag, exact clean commit, release version, public-source
   and license policy, tests, contracts, digest-pinned base images, the exact
   Hatchling build backend, and the SHA-512-bound pnpm/Corepack distribution.
2. Build `source.tar`, `source-files.manifest`, and
   `source-attestation.json` deterministically from the committed Git tree,
   then independently verify their paths, modes, hashes, metadata, and required
   release-source inventory before any registry credential is used. That
   explicit inventory includes the five server lifecycle entry points,
   deployment/admission/recovery tools, the Sub2API runtime verifier, auth
   contract/probe, formal smoke, Compose and Nginx inputs, every current
   migration, the OCI toolchain policy, Connector aggregate schemas, and the
   frozen vulnerability scanner/policy/license helpers used by release gates.
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
   claims. Export a pinned Sigstore trusted root and one `cosign save` OCI
   layout per component, then verify the signature and both attestations with
   `--offline --local-image` before packaging. This stage does not create any
   final `control-v*` GHCR tag.
6. Install the pinned, hash-verified `crane` producer. Export each digest twice
   as Linux `amd64` OCI archives and require byte equality. The package verifier
   closes each descriptor/blob graph, rejects external URLs and unreferenced
   blobs, and binds the top-level manifest/config/layers back to the signed lock.
   Its canonical `oci-export-receipt.json` records the locked producer, direct
   remote manifest identity, archive digest/size, and successful repeated export;
   the server manifest, checksums, Sigstore signatures, provenance, and offline
   package all bind that receipt. The workflow writes it first to a private
   temporary file, makes it read-only and durable, then promotes it without
   replacing an existing final receipt.
7. Authenticate the approved Connector metadata, public Release descriptor,
   Linux/macOS receipts, and signed aggregate. Build deterministic online and
   offline server archives from the verified source, original eleven image-set
   files, detached image trust, lifecycle commands, and this compatibility
   evidence. Every physical archive part stays below GitHub's per-asset limit;
   manifests and checksums bind the logical package and every part.
8. Authenticate the Control lock and server manifest bundles before parsing
   either root. The vulnerability inputs contain only those fixed root
   descriptors plus target names and report paths; artifact identities, package
   parts, and SBOMs are derived from the signed roots rather than self-reported
   by the scanner job. Scan the exact source repository, three immutable image
   digests, and both logical server packages with the policy-pinned Trivy build.
   Block unreviewed findings and sign the canonical receipt that closes the
   roots, database metadata, reports, dispositions, artifacts, and SBOMs.
9. Independently verify every package, split part, SBOM, provenance predicate,
   Connector aggregate, vulnerability receipt, and Sigstore bundle. The workflow
   also signs fixed pre-publication online/offline verification receipts, then
   regenerates both receipts from anonymous public bytes and compares every
   stable field. A separate clean-host gate must still install, admit, start,
   verify, upgrade, rollback, and uninstall. That harness is not implemented yet,
   so the source-only guard must remain. The offline harness must use a fresh
   Docker data root with network disabled, load all OCI archives, resolve each
   exact `repository@sha256` reference, and run Compose with `--pull never`; a
   mutable-tag fallback is forbidden.
10. Re-read the remote annotated tag through the GitHub API immediately before
    draft creation, before publication, and after publication; require it still
    resolves to the event commit and require immutable releases.
11. In a new read-only job, resolve the tag anonymously, download every asset
    through its public `browser_download_url` into a new empty directory, verify
    GitHub's immutable-release attestation for the release and each asset, split
    the fixed image/package/vulnerability/compatibility inventories, and replay
    every verifier using externally fixed trust inputs. Image replay addresses
    only the authenticated `repository@sha256` values; it does not depend on a
    final image tag that has not yet been admitted.
12. Only after the complete anonymous replay succeeds, enter the separately
    protected promotion environment, check out and re-peel the exact annotated
    Control tag, recheck the remote tag, and authenticate to GHCR. Preflight all
    three source digests and any existing final tags, create only missing
    `control-v*` tags, and read all three back by digest. A retry is idempotent;
    an existing tag at any different digest fails closed instead of being
    replaced.

## Published asset boundary

The immutable Control Release is one flat, collision-free union of four exact
sub-inventories:

- the eleven Control image-root files listed below;
- the server manifest/checksums, online and offline package or split parts,
  content-addressed package SBOMs, provenance, Connector metadata and aggregate,
  `oci-export-receipt.json`, `server-package-verify.py`, and every declared
  Sigstore bundle;
- fixed signed online/offline package-verification receipts; and
- the vulnerability manifest, reviewed dispositions, Trivy database metadata,
  six reports, canonical receipt, and receipt bundle.

An unknown filename is routed into the server sub-inventory and rejected by its
signed manifest. The public job verifies GitHub's immutable-release attestation
for every asset, reconstructs all four directories, and replays each verifier.
The two pre-publication package receipts are historical evidence; installation
uses a new receipt generated against the exact extracted path on that host.

This is SLSA v1-compatible provenance. It does not claim a SLSA build level;
runner isolation, branch/tag policy, environment review, and registry retention
remain deployment controls.

The release matrix intentionally contains only `linux/amd64`. Do not advertise
or deploy an ARM image using this evidence. Add a separately evidenced platform
digest and platform-specific SBOM before expanding the matrix.

## Image-set verification

The eleven image-set files remain an exact sub-inventory of the larger server
Release. The workflow verifies them before packaging and again after public
download. Independent consumers can stage these eleven files in one otherwise
empty directory:

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
    https://github.com/OWNER/REPOSITORY/.github/workflows/control-images-release.yml@refs/tags/control-v0.1.11 \
  --certificate-github-workflow-sha 0123456789abcdef0123456789abcdef01234567 \
  --certificate-github-workflow-trigger push \
  --certificate-github-workflow-repository OWNER/REPOSITORY \
  --certificate-github-workflow-ref refs/tags/control-v0.1.11 \
  --expected-source-repository https://github.com/OWNER/REPOSITORY \
  --expected-source-commit 0123456789abcdef0123456789abcdef01234567 \
  --expected-release-tag control-v0.1.11 \
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

## Server package use

Choose one logical package for Linux `amd64`:

- **Online** carries the complete verified source, lifecycle tooling, signed
  image-set evidence, detached image trust, and compatibility evidence. During
  admission it retrieves only the three exact digest references already bound
  by the package.
- **Offline** carries the same material plus the three exact OCI archives and
  their identities. Installation and verification must succeed with registry
  access disabled; it is not an online package with a cache hint.

Download every public asset, then partition the flat Release into the four exact
sub-inventories above. The server-only directory contains the package manifest,
checksums, all parts named by that manifest, package SBOM/provenance, Connector
aggregate, `server-package-verify.py`, and every server-declared Sigstore bundle.
Keep vulnerability evidence and historical package receipts in their own
directories; either would be an invalid extra file in `--release-dir`. Before
executing the downloaded verifier, use an independently installed Cosign and external
issuer/workflow/tag/commit policy to verify the fixed manifest bundle. Only then
parse the authenticated `consumer_verifier` record, require the verifier's exact
filename/hash/size, and verify its own blob bundle. A separately trusted checkout
may instead provide the same reviewed verifier. Only an authenticated verifier
may reassemble and extract the archive. The release directory and extraction
parent must be separate. Create the extraction parent as an empty private
directory; the package root beneath it and the verification receipt must not
already exist. The standalone verifier requires `/usr/bin/python3` 3.11 or
newer and must run in isolated safe-path mode (`-I`):

```sh
install -d -m 0700 /secure/staging/control-v0.1.11-offline-parent
/usr/bin/python3 -I /secure/download/control-v0.1.11/server/server-package-verify.py verify-release \
  --release-dir /secure/download/control-v0.1.11/server \
  --extract-to /secure/staging/control-v0.1.11-offline-parent \
  --mode offline \
  --verification-receipt /secure/receipts/control-v0.1.11-offline.json \
  --cosign /usr/local/bin/cosign \
  --expected-cosign-version v3.0.6 \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity \
    https://github.com/OWNER/REPOSITORY/.github/workflows/control-images-release.yml@refs/tags/control-v0.1.11 \
  --certificate-github-workflow-sha CONTROL_COMMIT_40_HEX \
  --certificate-github-workflow-trigger push \
  --certificate-github-workflow-repository OWNER/REPOSITORY \
  --certificate-github-workflow-ref refs/tags/control-v0.1.11 \
  --expected-source-repository https://github.com/OWNER/REPOSITORY \
  --expected-source-commit CONTROL_COMMIT_40_HEX \
  --expected-release-tag control-v0.1.11 \
  --expected-api-repository ghcr.io/owner/sub2api-codex-control-api \
  --expected-pwa-repository ghcr.io/owner/sub2api-codex-control-pwa \
  --expected-postgres-tools-repository ghcr.io/owner/sub2api-codex-postgres-tools \
  --connector-certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --connector-certificate-identity \
    https://github.com/OWNER/REPOSITORY/.github/workflows/connector-release.yml@refs/tags/connector-v0.1.0 \
  --connector-certificate-github-workflow-sha CONNECTOR_COMMIT_40_HEX \
  --connector-certificate-github-workflow-trigger push \
  --expected-connector-repository https://github.com/OWNER/REPOSITORY \
  --expected-connector-source-commit CONNECTOR_COMMIT_40_HEX \
  --expected-connector-tag connector-v0.1.0 \
  --expected-connector-release-id CONNECTOR_RELEASE_ID \
  --expected-connector-workflow-run-id CONNECTOR_WORKFLOW_RUN_ID \
  --expected-connector-workflow-run-attempt CONNECTOR_WORKFLOW_RUN_ATTEMPT
```

Use `--mode online` and a different new extraction/receipt path for the online
package. Do not obtain any expected value from the downloaded package itself.
The command authenticates both package modes and the full signed release
closure before it extracts the selected mode. Then follow
`deploy/server-package/INSTALL.md` for root-owned install, upgrade, verify,
rollback, and uninstall operations.

The lifecycle receipt admits one exact extracted tree. It never authorizes a
later replacement in place, and uninstall deliberately preserves databases,
secrets, backups, audit records, and user data. Online/offline selection does
not change the application contract.

After deployment, administrators do not have to create or operate each user's
Connector. An ordinary signed-in user opens the Control PWA, downloads the
platform package selected from signed `connector-release-metadata.json`, runs
the displayed per-user initialization and pairing commands, then starts,
checks, stops, or re-pairs their own outbound Connector. Pairing credentials and
runtime state remain private to that user; package installation is the only
machine-wide administrator step.

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
