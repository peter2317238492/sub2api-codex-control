# Server package build, verification, and lifecycle

The public server release contains two logical Linux `amd64` packages:

- `server-online-linux-amd64` contains the verified deployment source and
  evidence. Its lifecycle pulls only the three image digest references bound by
  the signed release.
- `server-offline-linux-amd64` contains the same common payload plus the three
  exact OCI archives and their local signature, SPDX, and SLSA evidence.

Both packages bind the signed Control image release and a separately signed
Connector public-verification aggregate. The packages do not contain an
administrator credential, a user's Sub2API credential, or a user's Connector
runtime state.

The JSON Schema describes the outer manifest shape, but it is not an admission
tool. `server_package.py verify-release` also authenticates Sigstore claims,
checks cross-field equality, enforces exact directory and archive inventories,
reassembles split artifacts, and verifies the embedded source with the tools
carried by that signed source.

Build, signing, standalone verification, and lifecycle commands require Python
3.11 or newer. Public verification and every root lifecycle operation must use
the fixed system interpreter in isolated safe-path mode as shown below.

## Release contents

`server-packages.manifest.json` is canonical JSON with kind
`server-packages-manifest-v1` and format version `1`. Its `packages` object
always contains exactly `online` and `offline`.

A complete server-package verification subdirectory contains no undeclared
files and includes:

- the manifest, `server-packages.sha256`, and their Sigstore bundles;
- the signed `oci-export-receipt.json`, which binds the pinned Crane producer
  and all three deterministic OCI archive outputs;
- the fixed `server-package-verify.py` consumer verifier and its Sigstore
  bundle;
- the original Connector metadata, Connector aggregate, and the original
  Sigstore bundle for each;
- every physical part listed in each package's `delivery.parts` and its
  signature bundle;
- the logical package signature, including when the logical archive was split;
- a content-addressed SPDX 2.3 JSON document and its signature for each target;
- SLSA v1 provenance, its blob signature, and its blob-attestation bundle for
  each target.

The GitHub Release also contains separately routed Control image, Connector,
client-package, vulnerability, and public-verification evidence. Do not mix
those assets into this directory: `verify-release` deliberately rejects every
file outside the signed server-package sub-inventory.

An archive strictly smaller than GitHub's 2 GiB asset limit is delivered as
`kind: single`. An archive at or above that limit is delivered as ordered
`part-NNN-of-NNN` files. Every
non-final part is exactly 1,900 MiB, the final part is at most 1,900 MiB, and a
logical archive can require no more than nine parts. Download every part named
by the signed manifest. Do not concatenate or extract parts manually; the
verifier checks every physical part, rebuilds the logical archive, and verifies
the logical archive signature.

## Trust policy

Never derive expected identity, repository, commit, tag, image repository, or
Connector run IDs from the downloaded manifest. Obtain them from the protected
release approval or another independent channel and pass them as command-line
policy.

The examples below use a Bash array so the same policy is supplied without
editing it between build, sign, and verification. Replace every value. The
workflow repository claim is `OWNER/REPOSITORY`; source repositories are
canonical HTTPS URLs.

```bash
CONTROL_REPOSITORY=https://github.com/OWNER/REPOSITORY
CONTROL_REPOSITORY_CLAIM=OWNER/REPOSITORY
CONTROL_COMMIT=0000000000000000000000000000000000000000
CONTROL_TAG=control-v1.0.0
CONTROL_REF=refs/tags/$CONTROL_TAG
CONTROL_IDENTITY="$CONTROL_REPOSITORY/.github/workflows/control-images-release.yml@$CONTROL_REF"

CONNECTOR_COMMIT=1111111111111111111111111111111111111111
CONNECTOR_TAG=connector-v1.0.0
CONNECTOR_IDENTITY="$CONTROL_REPOSITORY/.github/workflows/connector-release.yml@refs/tags/$CONNECTOR_TAG"

policy=(
  --cosign /absolute/path/to/cosign
  --expected-cosign-version v3.0.6
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
  --certificate-identity "$CONTROL_IDENTITY"
  --certificate-github-workflow-sha "$CONTROL_COMMIT"
  --certificate-github-workflow-trigger push
  --certificate-github-workflow-repository "$CONTROL_REPOSITORY_CLAIM"
  --certificate-github-workflow-ref "$CONTROL_REF"
  --expected-source-repository "$CONTROL_REPOSITORY"
  --expected-source-commit "$CONTROL_COMMIT"
  --expected-release-tag "$CONTROL_TAG"
  --expected-api-repository ghcr.io/owner/control-api
  --expected-pwa-repository ghcr.io/owner/control-pwa
  --expected-postgres-tools-repository ghcr.io/owner/postgres-tools
  --connector-certificate-oidc-issuer https://token.actions.githubusercontent.com
  --connector-certificate-identity "$CONNECTOR_IDENTITY"
  --connector-certificate-github-workflow-sha "$CONNECTOR_COMMIT"
  --connector-certificate-github-workflow-trigger push
  --expected-connector-repository "$CONTROL_REPOSITORY"
  --expected-connector-source-commit "$CONNECTOR_COMMIT"
  --expected-connector-tag "$CONNECTOR_TAG"
  --expected-connector-release-id 123456789
  --expected-connector-workflow-run-id 1234567890
  --expected-connector-workflow-run-attempt 1
)
```

The Cosign version is an exact policy input. Use the version recorded by the
release workflow; do not retain the example value when the pinned version has
changed.

## Build an unsigned closure

Build only in the protected release workflow from the exact Control tag. The
build host needs:

- the already authenticated, complete Control release evidence directory;
- the detached image-trust directory produced for that Control release;
- deterministic OCI archives for `control-api`, `pwa`, and `postgres-tools`;
- the canonical `oci-export-receipt.json` emitted alongside those archives by
  the pinned exporter;
- the Connector release metadata and public aggregate plus both original
  Sigstore bundles;
- an empty, private, caller-owned output directory.

The pinned OCI exporter and its trust boundary are documented in
`OCI-TOOLCHAIN.md`.

```bash
install -d -m 0700 /secure/server-package-output

python3 -I deploy/server-package/server_package.py build \
  --release-dir /secure/control-release-evidence \
  --image-trust-dir /secure/control-image-trust \
  --oci-export-receipt /secure/oci/oci-export-receipt.json \
  --image-archive control-api=/secure/oci/images/control-api.oci.tar \
  --image-archive pwa=/secure/oci/images/pwa.oci.tar \
  --image-archive postgres-tools=/secure/oci/images/postgres-tools.oci.tar \
  --output-dir /secure/server-package-output \
  --release 1.0.0 \
  --source-date-epoch 1786723200 \
  --connector-release-metadata /secure/connector/connector-release-metadata.json \
  --connector-release-metadata-bundle /secure/connector/connector-release-metadata.json.sigstore.json \
  --connector-verification-aggregate /secure/connector/connector-public-verification-aggregate.json \
  --connector-verification-aggregate-bundle /secure/connector/connector-public-verification-aggregate.json.sigstore.json \
  "${policy[@]}"
```

The builder creates both targets with canonical gzip/USTAR metadata. It first
builds and validates a private staging closure, then transfers the complete
unsigned result into the empty output directory. A build result is not public
release content until the separate signing step succeeds.

The OCI export receipt is a signed outer release asset. Its exact record is
also embedded in the offline package and included as a material in offline SLSA
provenance; the online internal package records `oci_export` as `null` because
it does not carry the archives. Offline provenance also binds every archive and
identity file plus the selected manifest and config digests; the consumer
recomputes that exact material closure from the extracted signed package.

## Sign and verify before publication

Signing requires the protected GitHub OIDC identity named in `policy`. It signs
the fixed manifest, checksums, OCI receipt, consumer verifier, physical package
parts, logical archives, SPDX files, and provenance, produces SLSA blob
attestations, then immediately verifies the complete result. The four Connector
files retain their two original Connector-workflow signatures; the signed
server manifest and checksums authenticate their exact bytes without replacing
that identity.

```bash
python3 -I deploy/server-package/server_package.py sign \
  --output-dir /secure/server-package-output \
  "${policy[@]}"
```

Publish the directory only after this command exits successfully. Preserve the
original Connector Sigstore bundles: they prove the Connector workflow
identity, while the server manifest and checksums bind their exact bytes into
the server release.

## Verify without a repository checkout

Use an exact approved Cosign binary and the independent policy values above.
The release publishes `server-package-verify.py` from the signed source
snapshot as a fixed-name consumer asset. Authenticate that file directly with
Cosign before executing it; the full verifier then proves that the same bytes
are named by the signed manifest and checksums. A source checkout is not needed:
after the outer manifest and archive are authenticated, the verifier switches
to the Control and Connector verification tools contained in the signed
package source.

Verification checks both logical targets even when only one is selected for
extraction. After the standalone verifier has passed its independent Sigstore
check, place the exact downloaded inventory in a real root-owned quarantine
directory with no group/world-writable ancestor. Every asset must be a
root-owned, singly linked regular file. Create root-owned private extraction
and receipt parent directories. Do not pre-create the extracted package
directory or receipt file; lifecycle deliberately rejects a user-owned tree or
receipt.

```bash
sudo install -d -o root -g root -m 0700 /secure/control-download
sudo install -d -o root -g root -m 0700 /secure/control-extracted
sudo install -d -o root -g root -m 0700 /secure/control-receipts

sudo /absolute/path/to/cosign verify-blob \
  --bundle /secure/control-download/server-package-verify.py.sigstore.json \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity "$CONTROL_IDENTITY" \
  --certificate-github-workflow-sha "$CONTROL_COMMIT" \
  --certificate-github-workflow-trigger push \
  --certificate-github-workflow-repository "$CONTROL_REPOSITORY_CLAIM" \
  --certificate-github-workflow-ref "$CONTROL_REF" \
  /secure/control-download/server-package-verify.py

sudo /usr/bin/python3 -I /secure/control-download/server-package-verify.py verify-release \
  --release-dir /secure/control-download \
  --mode online \
  --extract-to /secure/control-extracted \
  --verification-receipt /secure/control-receipts/online.verification.json \
  "${policy[@]}"
```

For offline installation, change both `online` occurrences to `offline`. The
receipt is canonical JSON, mode `0400`, and binds the release manifest, logical
archive, internal manifest, extracted root, Control trust policy, image
repositories, and Connector trust policy. Moving or replacing the extracted
tree invalidates that binding.

Never unpack the downloaded archive with a generic `tar` command and then run
its lifecycle entry points. Never execute a verifier directly from unauthenticated
downloaded content.

## Prepare operator configuration

Copy the field names from `config/operator.env.example` into a file outside the
package. Replace every placeholder, make every path absolute, and protect the
file and each referenced secret file as root-owned mode `0600`.

Referenced host Compose and environment files must also be private (mode
`0400` or `0600`, one hard link), even when the Compose file contains no inline
secrets. A world-readable `0444` Compose file fails operator admission.

`CONTROL_RECOVERY_RESTORE_TIMEOUT_SECONDS` accepts 1 through 86400 seconds per
restore operation. Set `--deployment-timeout-seconds` to a larger total budget
that also covers backup, all database restores, verification, and rollout.
Recovery uses a temporary Docker volume on disk, with two PostgreSQL restore
workers. It requires at least three times the compressed dump sizes plus 1 GiB
free on that disk; allow more for highly compressed data and indexes. The
networkless restore mounts the admitted backup read-only and proves its
temporary containers and restore volume have been removed on completion.

The parser reads literal `NAME=value` lines and performs no shell expansion.
Raw passwords, access tokens, and authentication evidence are rejected from
the operator environment; use the defined `*_FILE` paths. Lifecycle-owned
release, receipt, image, Connector, and rollback variables are reserved and
cannot be overridden by the operator file.

## Install and operate

Lifecycle mutation is supported only as root on Linux `amd64` with
`/usr/bin/python3` version 3.11 or newer. Every verifier and lifecycle entry
uses isolated safe-path mode (`-I`). It uses fixed
production roots:

- immutable package trees: `/opt/sub2api-codex-control/releases`;
- receipts, release records, operation records, lock, and activation pointer:
  `/var/lib/sub2api-codex-control`.

Docker operations are pinned to the local root daemon at
`unix:///var/run/docker.sock`; an inherited or configured remote Docker context
is not accepted as the deployment target.

Set `PACKAGE_ROOT` to the directory created by `verify-release`, not its parent.

```bash
PACKAGE_ROOT=/secure/control-extracted/sub2api-codex-control-server-1.0.0-linux-amd64-online
RECEIPT=/secure/control-receipts/online.verification.json
OPERATOR_ENV=/secure/codex-control/operator.env

sudo "$PACKAGE_ROOT/bin/sub2api-control-install" \
  --verification-receipt "$RECEIPT" \
  --operator-env-file "$OPERATOR_ENV"

sudo "$PACKAGE_ROOT/bin/sub2api-control-verify" \
  --verification-receipt "$RECEIPT"
```

`install` requires no active version. A later verified package is activated
with `upgrade`:

```bash
sudo "$NEW_PACKAGE_ROOT/bin/sub2api-control-upgrade" \
  --verification-receipt "$NEW_RECEIPT" \
  --operator-env-file "$OPERATOR_ENV" \
  --deployment-timeout-seconds 1800
```

Activation changes only after the signed production deployment wrapper
succeeds and lifecycle has identified its one private `deployment.json` record.
Before lifecycle creates or reconstructs an immutable package tree, its two
verification receipts, or its append-only release record, it writes a
root-only `started` receipt that binds the candidate manifest, archive,
verification receipt, trust policy, Connector metadata, and fixed destination.
The activation pointer and succeeded receipt then bind the lifecycle operation
to the authenticated deployment directory, exact `deployment.json` SHA-256,
and exact `deployed` terminal status. Lifecycle never finds an active target by
scanning for a recent deployment directory.

If activation or the succeeded lifecycle receipt cannot be committed after that
point, lifecycle must invoke the same signed wrapper's
`--lifecycle-bounded-reverse-after-success` interface and authenticate its
successful reverse evidence before restoring the prior activation pointer. A
wrapper without the exact
`CONTROL_SERVER_PACKAGE_POST_SUCCESS_REVERSE_CONTRACT=1` contract, a failed
reverse, or incomplete evidence leaves the lifecycle lock in place for operator
review. Lifecycle never treats a JSON pointer rewrite as runtime or database
recovery.

Lifecycle does not silently run an Alembic downgrade or select an arbitrary
prior package. An explicit rollback selects only the recorded previous release:

Before migration, the wrapper freezes both API writers and creates the final
database backup inside that no-write window. A failure in this frozen but
unmigrated state starts only the exact prior container IDs and never restores
the database. Once migration starts, the database reverse path is permitted only
after another bounded writer stop. Both branches publish a root-only,
no-replace recovery receipt; a failed recovery retains the deployment lock.

If the bounded reverse itself fails, the production deployment lock remains in
place and the recorded recovery evidence requires operator review. Do not
remove that lock or start another mutation until the recorded invariants have
been restored independently.

```bash
ACTIVE_PACKAGE_ROOT=/opt/sub2api-codex-control/releases/<active-release-id>

sudo "$ACTIVE_PACKAGE_ROOT/bin/sub2api-control-rollback" \
  --operator-env-file "$OPERATOR_ENV" \
  --deployment-timeout-seconds 1800
```

`rollback` must be launched from the current activation-installed package, not
from the previous target package, a downloaded extraction, or an arbitrary old
installed release. Lifecycle authenticates that invoking tree against the
current activation record before it reads the recorded previous release.

Read-only verification accepts no operator environment. Lifecycle operation
records are append-only and distinguish started, succeeded, and failed states.
Review the production backup and migration receipts before every upgrade or
rollback.

Uninstall must likewise be launched from the current authenticated
activation-installed package and requires the operator file. It accepts only
the deployment directory and `deployment.json` hash bound by the active
activation pointer and that operation's append-only succeeded receipt:

```bash
sudo "$ACTIVE_PACKAGE_ROOT/bin/sub2api-control-uninstall" \
  --operator-env-file "$OPERATOR_ENV"
```

The current signed deployment wrapper must expose the exact
`CONTROL_SERVER_PACKAGE_BOUNDED_UNINSTALL_CONTRACT=1` contract. Lifecycle calls
it with exact arguments
`--lifecycle-bounded-uninstall <active-deployment-dir> lifecycle-uninstall:<operation-id>`.
The wrapper admits only the exact terminal
container identities for `control-api`, `control-api-replica`, and `codex-pwa`,
proves all one-off migration and backup containers absent, and removes the
exact package-owned PWA network only after proving its sole member was the
admitted PWA container.

Both `uninstall-plan.json` and `uninstall-execution.json` are canonical,
root-only, no-replace mode `0400` records in that active deployment directory.
Before deleting the activation pointer or any validated package tree,
lifecycle authenticates the plan and execution hashes, full container and
network identities and labels, exact
`uninstalled:lifecycle-uninstall:<operation-id>` status, successful bounded
postconditions, and release of the production lock. Missing historical
activation bindings, an unsupported wrapper, runtime drift, incomplete
evidence, a retained `.deployment.lock`, a terminal status ending in
`lock-retained`, or a failed bounded reverse all fail closed. The activation
and package trees remain, and the lifecycle lock is retained for review;
deleting either lock by hand is not recovery.

Bounded uninstall deliberately preserves the Sub2API runtime, PostgreSQL,
Redis, application data, operator configuration and secrets, backups,
deployment and lifecycle records, release records and verification receipts,
container images, Connector user state, Nginx configuration, and logrotate
policy. It does not reload or remove shared Nginx or logrotate configuration.
Removing preserved resources is a separate, explicit data-recovery or
retirement operation. A later install of the exact same authenticated package
may reconstruct its immutable package tree only when it matches the preserved
release record and receipts byte for byte.

## Connector self-service

The server package binds and deploys the public Connector metadata consumed by
the Control PWA. Installing the server package is the only machine-wide
administrator action. An ordinary authenticated user can select the signed
package for their own platform, initialize and pair their own outbound
Connector, and start, inspect, stop, or re-pair it without an administrator
creating or operating that user's Connector. Pairing credentials and runtime
state remain scoped to that user.

The Connector aggregate is not a filename index alone. Verification binds its
release ID, source commit, tag, workflow run ID and attempt, six native package
targets, core inventory, SBOMs, provenance, vulnerability evidence, and public
release metadata before the server package accepts it.

## Offline acceptance boundary

The offline target carries the three authenticated OCI archives, and lifecycle
loads the locked Linux `amd64` images locally rather than pulling them from a
registry. The signed deployment wrapper must explicitly consume the package
mode, package manifest path and digest, verification receipt, and fixed offline
contract marker; lifecycle fails closed if that contract is absent.

This repository has not thereby proven a full clean-host, network-isolated
production installation. Before describing a release as air-gap validated,
run the formal offline acceptance test on a fresh Linux `amd64` host with
registry access disabled and retain the verifier, image-load, Compose,
migration, health, rollback, and reboot evidence. Until that evidence exists,
describe the target as an authenticated offline payload, not a verified
clean-host deployment.
