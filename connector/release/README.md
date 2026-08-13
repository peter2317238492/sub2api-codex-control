# Connector release pipeline

This directory is the executable release boundary for the Connector. Runtime
code does not import it. The admitted matrix and exact Go/Cosign versions live
in `release-config.json`.

## Trust boundary

Production releases are created only by the annotated tag
`connector-v<exact Connector version>` in
`.github/workflows/connector-release.yml`. Configure these controls before the
first tag is pushed:

1. A repository tag rule for `connector-v*` that blocks updates/deletion and
   restricts creation to release maintainers.
2. A protected `connector-release-apple` environment with required reviewers,
   self-review disabled, deployment restricted to `connector-v*` tags, and only
   the six Apple Developer ID/App Store Connect secrets named in the workflow.
   Set public variables `MACOS_EXPECTED_TEAM_ID` and
   `MACOS_EXPECTED_SIGNING_IDENTITY` to the approved 10-character Apple Team ID
   and full `Developer ID Application: ... (TEAMID)` identity.
3. A separate protected `connector-release-sigstore` environment with the same
   tag/reviewer controls and the same two public Apple trust variables, but no
   Apple private credentials. Its job has OIDC and read-only repository access.
4. A third protected `connector-release-publish` environment with the same
   tag/reviewer controls and an `IMMUTABLE_RELEASES_READ_TOKEN`. That fine-grained
   token needs only repository Administration read permission and is used solely
   to prove release immutability is enabled before publication.
5. GitHub immutable releases enabled for the repository. The workflow creates a
   draft, uploads every asset, publishes it, and requires `isImmutable=true`.
6. Review protection for this workflow, `release.py`,
   `macos-sign-notarize.sh`, `release-config.json`, `go.mod`, and `go.sum`.

The build job has neither environment secrets nor OIDC. The native-signing job
has Apple credentials but no OIDC or write token. The Sigstore job has OIDC but
only read access. The publication job has write access but no OIDC and executes
no repository code. No job combines these authorities, and no long-lived
Cosign key is stored.

The expected Sigstore identity is external trust input, not data learned from
the downloaded release:

```text
issuer:   https://token.actions.githubusercontent.com
identity: https://github.com/OWNER/REPOSITORY/.github/workflows/connector-release.yml@refs/tags/connector-v0.1.0
workflow SHA: 0123456789abcdef0123456789abcdef01234567
workflow trigger: push
Apple Team ID: ABCDE12345
Apple identity: Developer ID Application: Example Company (ABCDE12345)
```

Replace the repository, exact tag, full reviewed commit, and Apple values.
Obtain them from an independently trusted source-control/release-approval
record. Never use `.*`, a branch identity, or an identity/SHA/Apple value
learned only from `manifest.json`, the release assets, or the tag being verified
as the verifier's trust policy.

## Release flow

The protected workflow performs these operations in order:

1. Validate the exact annotated tag, clean source commit, pinned constants,
   complete target matrix, Go `1.26.5`, and Cosign `v3.0.6`.
2. Test the Connector, then build Linux and macOS `amd64`/`arm64` candidates
   twice with `CGO_ENABLED=0`, `GOAMD64=v1`, `GOARM64=v8.0`, `GOFIPS140=off`,
   `GOENV=off`, `GOTOOLCHAIN=local`, an empty `GOEXPERIMENT`, `-trimpath`, VCS
   metadata disabled, and an empty Go build ID. A hash or size difference stops
   the release.
3. Transfer the hash-checked candidates to a separate pinned macOS job. Before
   Apple credentials are exposed, revalidate the source snapshot, exact tag,
   work-state matrix, and every unsigned candidate hash and size. Then import
   the protected Developer ID identity into
   an ephemeral keychain, sign both macOS binaries, and require Apple
   `notarytool` to return `Accepted`. The keychain and private material are
   removed before the job ends.
4. Generate deterministic SPDX 2.3 JSON SBOMs and in-toto Statement v1 / SLSA
   provenance v1 for every final artifact. The provenance records the
   pre-signing reproducible digest for macOS as a byproduct, then write canonical
   `manifest.json` and `SHA256SUMS`.
5. Transfer the finalized evidence to a third job that has GitHub OIDC but no
   Apple environment. Revalidate the complete unsigned file inventory before
   requesting an identity. Keylessly sign the
   manifest, checksums, every artifact, every SBOM, and every provenance file.
   Each provenance statement also receives a Sigstore DSSE attestation bundle.
6. Run the fail-closed verifier with the exact protected workflow identity,
   source/workflow SHA, and `push` trigger, including native `codesign`
   verification. Transfer the verified set to a fourth job with publication
   permission but no OIDC. Publish all assets through a draft only after
   repository immutability and the remote peeled tag SHA are confirmed, then
   assert that the published release is immutable. A final protected read-only
   macOS job anonymously downloads every public asset into a new empty directory,
   verifies GitHub's immutable-release attestation for the release and each
   asset, and re-runs the complete Sigstore, inventory, provenance, and native
   `codesign` consumer verifier on those downloaded bytes.

This emits SLSA v1-compatible provenance. It does not claim a SLSA build level:
the hosted runner and workflow controls must be assessed separately.

## Consumer verification

Select the artifact being installed. The verifier always authenticates the full
manifest, signed checksums, and exact release inventory, then deeply verifies
the selected artifact's SBOM, provenance, signatures, and attestation. This lets
a Linux host verify a Linux artifact even though the same release also contains
macOS assets. Run `release.py` from a separately trusted, reviewed source
checkout, never from files bundled beside an untrusted download.

```sh
python3 connector/release/release.py verify \
  --output /path/to/downloaded-release \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity \
    https://github.com/OWNER/REPOSITORY/.github/workflows/connector-release.yml@refs/tags/connector-v0.1.0 \
  --certificate-github-workflow-sha \
    0123456789abcdef0123456789abcdef01234567 \
  --certificate-github-workflow-trigger push \
  --target linux-amd64
```

For `darwin-amd64` or `darwin-arm64`, run on macOS and also supply externally
pinned Apple trust values:

```sh
  --apple-team-id ABCDE12345 \
  --apple-signing-identity \
    'Developer ID Application: Example Company (ABCDE12345)'
```

Verification authenticates the manifest before parsing it, then checks the
exact version matrix, complete file inventory, checksums, SPDX subjects, SLSA
subjects/builder, certificate workflow SHA/trigger, per-file signatures,
provenance attestations, and, for macOS, a fresh `codesign` report matching the
external Team ID/full identity plus notarization evidence. Missing, extra, symlinked,
tampered, or mismatched evidence fails. File mode is deliberately not part of
download verification because raw GitHub assets normally arrive as `0644`;
installation sets the verified binary to `0755` afterward.

## Install and rollback

Never run or stage an artifact until the verifier above succeeds against trust
input maintained outside the download directory. Then install explicitly:

1. Copy the verified binary to a temporary path on the same filesystem as the
   installed Connector and set its owner/mode to the service account and
   `0755`.
2. Keep the previous verified binary as the rollback candidate.
3. Stop only the Connector service, atomically rename the staged binary into
   place, and run `sub2api-codex-connector -version`.
4. Start it with the existing private Connector config/state directory. Do not
   edit Codex configuration, credentials, workspace files, or firewall rules.
5. Require heartbeat plus one managed read-only command during the observation
   window; atomically restore the prior verified binary on failure.

There is no unattended updater in this release. A signed artifact is not
automatically admitted by the server version matrix or rollout policy.

## Identity revocation

The trusted workflow identity and issuer belong in the operator's external
policy store. On workflow, repository, Apple identity, or Sigstore compromise:

1. Halt tag creation and release publication; revoke the affected repository
   environment credentials and Apple certificate where applicable.
2. Remove the compromised identity from external verifier policy and deny the
   affected artifact SHA-256 values in server admission.
3. Retain evidence for incident response; do not make an unsigned replacement
   or weaken identity matching to a regular expression.
4. Review and publish from a separately authorized recovery workflow/identity,
   then stage rollback or replacement through the normal verified process.

GitHub OIDC identity, Apple Developer ID, and Connector device credentials are
separate trust domains. Rotate only the affected domain, but require a new full
release verification after any signing-policy change.

## Local deterministic validation

Local mode never requests OIDC, never signs, never notarizes, sets
`releasable=false`, and writes `RELEASE-NOT-FOR-DISTRIBUTION`. The production
verifier rejects it unless the explicit test-only flag is supplied.

```sh
out=$(mktemp -d)
python3 connector/release/release.py prepare \
  --mode local-unsigned \
  --output "$out" \
  --source-date-epoch 1700000000
python3 connector/release/release.py finalize --output "$out"
python3 connector/release/release.py verify \
  --output "$out" \
  --allow-local-unsigned
python3 -m unittest discover -s connector/release/tests -v
```

Local output is a determinism fixture only. It must not be distributed,
installed, promoted, or manually supplied with signature files.
