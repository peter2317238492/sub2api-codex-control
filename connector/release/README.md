# Connector release and verification guide

This directory turns the outbound-only Connector into native packages that an
operator can verify once and ordinary users can then configure for themselves.
It is also the executable release boundary: runtime code does not import it,
and the admitted target matrix and exact Go/Cosign versions live in
`release-config.json`.

> **Release status:** the workflow is deliberately source-only and fail-closed.
> It exposes only `workflow_dispatch`, and its unconditional guard fails before
> any build, signing, or publication job. Do not add the `connector-v*` tag
> trigger until every environment below exists, the complete package verifier
> passes on Linux and macOS, and a reviewed release authorization records the
> exact workflow commit.

## Trust boundary

When the source-only guard is replaced by the reviewed protected-tag trigger,
production releases will be created only by the annotated tag
`connector-v<exact Connector version>` in
`.github/workflows/connector-release.yml`. Configure these controls before the
first tag is pushed:

1. A repository tag rule for `connector-v*` that blocks updates/deletion and
   restricts creation to release maintainers.
2. A protected `connector-release-linux` environment with required reviewers,
   self-review disabled, and deployment restricted to `connector-v*`. Store
   only `RPM_SIGNING_PRIVATE_KEY_BASE64` and `RPM_SIGNING_KEY_PASSWORD` as
   secrets. Set `RPM_SIGNING_PUBLIC_KEY_BASE64` and the uppercase full
   `RPM_EXPECTED_SIGNING_FINGERPRINT` as public environment variables.
3. A protected `connector-release-apple` environment with the same controls.
   Store only these Apple private inputs as secrets:
   `MACOS_APPLICATION_CERTIFICATE_P12_BASE64`,
   `MACOS_APPLICATION_CERTIFICATE_PASSWORD`,
   `MACOS_INSTALLER_CERTIFICATE_P12_BASE64`,
   `MACOS_INSTALLER_CERTIFICATE_PASSWORD`, `MACOS_NOTARY_KEY_BASE64`,
   `MACOS_NOTARY_KEY_ID`, and `MACOS_NOTARY_ISSUER_ID`. Set public variables
   `MACOS_EXPECTED_TEAM_ID`, `MACOS_EXPECTED_APPLICATION_IDENTITY`, and
   `MACOS_EXPECTED_INSTALLER_IDENTITY` to the approved 10-character Team ID and
   the full `Developer ID Application: ... (TEAMID)` and
   `Developer ID Installer: ... (TEAMID)` identities.
4. A separate protected `connector-release-sigstore` environment with the same
   tag/reviewer controls and all four public trust values
   (`RPM_EXPECTED_SIGNING_FINGERPRINT` plus the three `MACOS_EXPECTED_*`
   values), but no Apple or RPM private credentials. Only its signing job gets
   GitHub OIDC; its Linux/macOS verification jobs remain read-only.
5. A protected `connector-release-publish` environment with the same
   tag/reviewer controls and an `IMMUTABLE_RELEASES_READ_TOKEN`. That fine-grained
   token needs only repository Administration read permission and is used solely
   to prove release immutability is enabled before publication.
6. GitHub immutable releases enabled for the repository. The workflow creates a
   draft, uploads every asset, publishes it, and requires `isImmutable=true`.
7. Review protection for this workflow, `release.py`, both native-signing
   scripts, `release-config.json`, the complete `connector/packaging/` tree,
   `go.mod`, `go.sum`, `security/`, and the vulnerability tooling in `scripts/`.

The build job has neither environment secrets nor OIDC. Linux and Apple native
signing use different protected environments and neither has OIDC or a write
token. The Sigstore job has OIDC but no native private key and only read access.
The publication job has write access but no OIDC and executes no checked-out
repository code. No job combines these authorities, and no long-lived Cosign
key is stored.

The expected Sigstore identity is external trust input, not data learned from
the downloaded release:

```text
issuer:   https://token.actions.githubusercontent.com
identity: https://github.com/OWNER/REPOSITORY/.github/workflows/connector-release.yml@refs/tags/connector-v0.1.0
workflow SHA: 0123456789abcdef0123456789abcdef01234567
workflow trigger: push
Apple Team ID: ABCDE12345
Apple application identity: Developer ID Application: Example Company (ABCDE12345)
Apple installer identity: Developer ID Installer: Example Company (ABCDE12345)
RPM signing fingerprint: 0123456789ABCDEF0123456789ABCDEF01234567
```

Replace the repository, exact tag, full reviewed commit, Apple values, and RPM
fingerprint.
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
3. Build reproducible Linux `amd64`/`arm64` `.deb` and `.rpm` packages containing
   the binary, user `systemd` unit, lifecycle helper, safe configuration example,
   licensing, and operations guide. In the separate Linux environment, recheck
   the remote peeled tag and complete work-state before exposing the RPM key;
   sign and independently verify both RPM packages. Debian packages have no
   native signature and therefore rely on their Sigstore package signatures.
4. Transfer that exact state to the separate pinned macOS job. Before Apple
   credentials are exposed, revalidate the source snapshot, remote peeled tag,
   work-state matrix, and every candidate hash and size. Import separate
   Developer ID Application and Installer identities into an ephemeral
   keychain, sign both executables, create/sign both `.pkg` installers, require
   `notarytool` acceptance, staple the ticket, and require Gatekeeper acceptance.
   The keychain and private material are removed before the job ends.
5. Generate deterministic SPDX 2.3 JSON SBOMs and in-toto Statement v1 / SLSA
   provenance v1 for every executable and native package. The SBOMs derive the
   Go standard library version from signed `build.go_version`, declare that
   component as `BSD-3-Clause`, and bind it to the Connector with `DEPENDS_ON`.
   Native-package roots use `NOASSERTION` for their mixed aggregate license and
   enumerate separately licensed components with `CONTAINS`. Write canonical
   `manifest.json` and `SHA256SUMS` that include the complete six-package matrix,
   native evidence, public RPM key, and exact signature bundle names. Generate
   `connector-release-metadata.json` from that authenticated matrix; it is never
   hand-written. The Control API uses this metadata to show each ordinary user
   the correct package, checksum, configuration location, pairing command, and
   start command.
6. Transfer the finalized evidence to a third job that has GitHub OIDC but no
   Apple environment. Revalidate the complete unsigned file inventory before
   requesting an identity. Keylessly sign the
   manifest, checksums, every artifact, every SBOM, and every provenance file.
   Each provenance statement also receives a Sigstore DSSE attestation bundle.
7. Run the fail-closed verifier on macOS and Linux with the exact protected
   workflow identity, source/workflow SHA, `push` trigger, Apple identities, and
   RPM fingerprint. Before vulnerability target construction, authenticate the
   Connector `manifest.json` bundle with those external claims. Vulnerability
   inputs contain only that fixed root descriptor plus target names, report
   paths, and scan-execution paths; package identities and SBOMs are derived from
   the signed manifest, not
   self-reported by the scan job. Scan all six authenticated package SBOMs with
   the policy-pinned Trivy build, retain the database metadata and full JSON
   reports, enforce reviewed dispositions, and keylessly sign the canonical
   admission receipt.
8. Transfer the same verified bytes to a publication job with
   publication permission but no OIDC. Publish all assets through a draft only
   after repository immutability and the remote peeled tag SHA are confirmed,
   then assert that the published release is immutable.
9. In fresh read-only Linux and macOS jobs, anonymously download every public
   asset into empty directories, verify GitHub's immutable-release attestation
   for the release and every asset, split the fixed core/vulnerability asset
   union, and re-run exact inventory, hash, Sigstore, provenance, vulnerability,
   package-content, RPM, codesign, installer, notarization, staple, and
   Gatekeeper verification on those public bytes. Each platform writes a
   canonical no-replace verification receipt outside the core asset directory.
10. After both public checks pass, an OIDC-only job binds the Linux and macOS
    receipts to one canonical public Release descriptor and signs an aggregate
    receipt. GitHub immutable Releases cannot be modified after publication, so
    this aggregate is deliberately not written back to the Connector Release.
    The subsequent Control server Release consumes, verifies, signs, and
    publishes it as cross-release compatibility evidence.

This emits SLSA v1-compatible provenance. It does not claim a SLSA build level:
the hosted runner and workflow controls must be assessed separately.

## Published asset boundary

The immutable Connector Release is one exact union with two independently
verified parts:

- **Core assets:** six native packages, `manifest.json`, `SHA256SUMS`, generated
  self-service metadata, executable/package SBOMs and provenance, native signing
  evidence, the RPM public key, and every declared Sigstore bundle.
- **Vulnerability assets:** 41 non-Connector files from the exact 55-file signed
  closure, plus the canonical receipt and its Sigstore bundle. The closure keeps
  the scanner install evidence, binary and signed upstream assets, empty config,
  both SQLite databases and complete OCI layouts, and every target's raw report,
  normalized report, and execution receipt. The 14 Connector root/package/SBOM
  files are not duplicated. Each public evidence name is deterministically
  derived from its signed receipt path as
  `vulnerability-evidence-<path-hash>-<basename>`; replay rejects collisions and
  reconstructs the original nested paths without replacement. Content-addressed
  SBOM aliases exist only while Trivy is running and are not release assets.

An unknown filename is not an extension point. The public jobs require exactly
92 core assets and the receipt-derived 43 vulnerability assets, so an extra or
missing asset fails the union. The later
Linux/macOS aggregate receipt is a workflow artifact for the Control release,
not a mutable addition to this Release.

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
  --apple-team-id ABCDE12345 \
  --apple-signing-identity \
    'Developer ID Application: Example Company (ABCDE12345)' \
  --apple-installer-identity \
    'Developer ID Installer: Example Company (ABCDE12345)' \
  --rpm-signing-fingerprint \
    0123456789ABCDEF0123456789ABCDEF01234567 \
  --target linux-amd64
```

For `darwin-amd64` or `darwin-arm64`, run on macOS. For Linux targets, run on
Linux with `dpkg-deb`, `rpmkeys`, GnuPG, and the package-content verifier
available. Before invoking `release.py`, authenticate the vulnerability receipt,
derive its exact 43-file public projection, reconstruct its signed 55-file
closure, and copy the exact 92 core assets into a separate empty directory. The
complete core directory and all external trust inputs
are required on both platforms; `--target` narrows deep native verification but
does not weaken global inventory, hashes, signatures, or provenance checks.

Authenticate `vulnerability-receipt.sigstore.json` with the same exact issuer,
workflow identity, workflow SHA, trigger, repository, and tag ref. Create a
private `connector/` directory below the vulnerability evidence directory, copy
the authenticated `manifest.json`, its bundle, all six authenticated package
files, and their authenticated SBOMs into it using the original filenames, then
replay the historical admission. The root bundle must be verified before the
checker derives any package identity:

```sh
python3 -I scripts/check-vulnerabilities.py verify-receipt \
  --manifest /path/to/vulnerability/vulnerability-manifest.json \
  --policy security/vulnerability-policy.json \
  --dispositions /path/to/vulnerability/vulnerability-dispositions.json \
  --profile connector-release \
  --source-commit 0123456789abcdef0123456789abcdef01234567 \
  --receipt /path/to/vulnerability/vulnerability-receipt.json
```

Immediate post-publication automation also requires the receipt to be no more
than 24 hours old. Long-term verification replays the signed historical time;
it does not claim that the old vulnerability database is current today.

Verification authenticates the manifest before parsing it, then checks the
exact executable and native-package matrices, complete file inventory,
checksums, SPDX subjects, SLSA subjects/builder, certificate workflow
SHA/trigger, per-file signatures, and provenance attestations. Linux deep
verification also checks package contents and the native RPM signature against
the externally pinned fingerprint. macOS deep verification checks the
executable and installer identities, hardened runtime, notarization, staple,
Gatekeeper evidence, and current native verification. Missing, extra,
symlinked, tampered, or mismatched evidence fails. File mode is deliberately
not part of download verification because raw GitHub assets normally arrive as
`0644`; native package installation applies the admitted modes.

## Install and rollback

Never install an asset until the verifier above succeeds against trust input
maintained outside the download directory. Install the verified `.deb`, `.rpm`,
or `.pkg` with the native package manager. Keep the immediately previous
verified native package for rollback and follow `connector/packaging/INSTALL.md`.

Package installation is the only administrator-owned step. Each ordinary user
then initializes, pairs, starts, inspects, and stops their own Connector with
`sub2api-codex-connector-ctl`; their configuration and pairing credentials stay
in private per-user XDG/macOS state and survive package upgrades. The package
and control command do not write Codex configuration, Codex authentication,
workspaces, shell profiles, or firewall rules.

For rollback, stop only the affected user's Connector, verify and reinstall the
previous native package, then prove heartbeat and one managed read-only command.
For uninstall, use the native package manager (and the package-owned macOS
uninstaller) so only package-owned files are removed. User state remains until
that user explicitly runs `sub2api-codex-connector-ctl purge-user-state --yes`.
After install, upgrade, rollback, and uninstall, verify ordinary Codex App/CLI
operation and unchanged Codex config/auth hashes.

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
