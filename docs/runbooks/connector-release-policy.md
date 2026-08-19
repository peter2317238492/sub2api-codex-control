# Connector signing and update policy

## Release inputs

A Connector release is built only from a reviewed, immutable source commit with
a clean worktree. Pin and record:

- Connector semantic version and control protocol version;
- Go toolchain and module checksums;
- Codex CLI `0.147.0` and the pinned app-server schema SHA-256;
- supported server API release range and OS/architecture targets;
- threat-model and allowlist revision.

The build uses the exact values in
`connector/release/release-config.json`: Go `1.26.5`, `CGO_ENABLED=0`,
portable `GOAMD64=v1`/`GOARM64=v8.0`, `GOENV=off`, `GOTOOLCHAIN=local`,
`GOFIPS140=off`, an empty `GOEXPERIMENT`, `-trimpath`, disabled VCS injection,
an empty Go build ID, reproducible timestamps, and a fresh module/build cache in
protected CI. Every target is
built twice and compared before native signing. Generate an SPDX 2.3 JSON SBOM
and in-toto Statement v1 / SLSA provenance v1 attestation for every final
artifact. Both executable and native-package SBOMs derive the Go standard
library version from the signed `build.go_version` value (and therefore the
release configuration), declare that component as `BSD-3-Clause`, and bind it
to the Connector with `DEPENDS_ON`. Native-package roots use `NOASSERTION` for
their aggregate license because they contain separately licensed Connector,
standard-library, and module components; `CONTAINS` relationships preserve that
component boundary. A missing `go.sum`, unreviewed dependency change, dirty
tree, schema digest change, or differing candidate digest blocks release.

## Artifact signing

Produce separate artifacts for each supported OS and architecture. Publish a
manifest containing filename, size, SHA-256, Connector version, control
protocol version, Codex version, schema digest, source commit, build toolchain,
minimum/maximum server release, and creation time.

The protected tag workflow keylessly signs the manifest, checksums, every
artifact, every SBOM, and every provenance file with Cosign `v3.0.6`; it also
creates a DSSE Sigstore bundle for each provenance statement. Verification
requires the exact GitHub workflow/tag identity and
`https://token.actions.githubusercontent.com` issuer, the full reviewed GitHub
workflow/source commit, and the `push` trigger supplied from an external trust
policy. It never learns trust roots from the downloaded manifest, tag, or
release assets.

macOS is not in this release's target matrix. Its installer would require
Developer ID Application and Developer ID Installer signing plus an Apple
`notarytool` submission returning `Accepted`, and no such credential exists, so
the workflow publishes no macOS artifact and rejects any Apple input reaching
it. Adding macOS back means restoring the `darwin-*` targets in
`connector/release/release-config.json`, reinstating the Apple signing and
macOS public-verification jobs, and holding the signing and App Store Connect
credentials in a protected `connector-release-apple` environment whose approved
Team ID and full Developer ID Application identity are duplicated as public
trust variables in the separate `connector-release-sigstore` environment.
Windows artifacts would require Authenticode if Windows becomes supported. The
Sigstore job has short-lived GitHub OIDC and read-only contents; the distinct
`connector-release-publish` job has contents write and a read-only
Administration token used to require repository release immutability,
but no OIDC. No job combines Apple credentials, Sigstore issuance, and release
publication authority.

Verification order is fail-closed:

1. verify the manifest bundle against the external exact issuer, identity,
   source/workflow SHA, and `push` trigger;
2. enforce the pinned version matrix and complete file inventory;
3. verify signed checksums, artifact SHA-256, and size;
4. verify SPDX subjects and SLSA subjects/builder plus DSSE attestations;
5. verify every selected artifact/evidence signature and platform-native status,
   including the externally pinned RPM OpenPGP signing fingerprint;
6. only then stage the replacement binary.

`connector/release/release.py verify` implements this order and rejects
missing, extra, symlinked, tampered, or mismatched files. The adjacent README
documents protected tag/environment setup and consumer commands. Local unsigned
mode is deliberately marked non-releasable and is accepted only with
`--allow-local-unsigned` for deterministic tests.

Consumers pass `--target` for the artifact they intend to install. Full
manifest/checksum authentication and inventory validation still cover the
whole release; target-specific artifact/SBOM/provenance/signature verification
is limited to the selection. An RPM target additionally requires the external
pinned OpenPGP signing fingerprint and its public key.

Publication uses GitHub's immutable-release flow: preflight the repository
setting, create a draft, attach the complete verified asset set, publish once,
and require the resulting release to report `isImmutable=true`.

## Current admission status

The repository contains the complete release automation and local rejection
tests. That is not proof that a release has been signed. Production admission
still requires an actual protected-tag run whose GitHub OIDC identity matches
the externally pinned repository/tag and whose RPM OpenPGP signing step
succeeds. The workflow fails closed if those external identities or credentials
are unavailable.

## Update behavior

The MVP has no unattended self-updater. Updates are explicit and atomic:

1. Confirm the server admits the new Connector/version tuple.
2. Download to the same filesystem as the installed binary and verify it.
3. Keep the last signed binary as the rollback candidate.
4. Stop only the Connector service; do not stop or edit Codex.
5. Atomically rename the verified binary into place.
6. Run `sub2api-codex-connector -version`, start it with the existing private
   config/state directory, and verify device reconnect plus one read-only turn.
7. Roll back automatically if version/schema validation, startup, heartbeat, or
   canary command fails within the observation window.

The updater must never modify `config.toml`, Codex auth/provider state,
workspace files, plugins, shell profiles, or the device firewall. It must never
open an inbound port. Connector state migrations, if introduced, require a
separately versioned backup and downgrade plan; pairing credentials are not
silently regenerated.

## Rollout

Use staged cohorts: CI smoke, internal devices, 1 percent, 10 percent, 50
percent, then full rollout. Hold each stage long enough to observe heartbeat,
reconnect, spool, approval, command-idempotency, app-server restart, and Codex
CLI coexistence metrics. One operator must be able to halt rollout immediately.

Automatic rollback triggers include signature/provenance failure, unsupported
matrix tuple, schema mismatch, crash loop, repeated stale-epoch events,
unexpected policy allow, spool corruption, or any impact on ordinary Codex
App/CLI behavior.

## Key compromise and revocation

Maintain an offline revocation procedure and a second trusted signing identity.
On suspected compromise, halt publication, revoke the identity, remove affected
manifests, deny compromised artifact hashes at the server admission layer, and
publish a signed incident manifest from the recovery identity. Device refresh
credentials and Connector signing identities are independent; rotate only the
trust domain affected by the incident.
