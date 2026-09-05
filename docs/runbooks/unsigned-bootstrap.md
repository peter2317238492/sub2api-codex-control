# Unsigned first-production bootstrap

This runbook is the narrow, one-time path for creating the first Control
deployment when no signed release bundle exists yet. It does not convert local
images into a trusted release and it is not an alternative release channel.
Use it only for an absent `codex_control` role/database and only after the
production backup admission succeeds. Normal admission requires a fresh
receipt; the explicitly documented historical-receipt exception below exists
only for this bootstrap because the operator prohibited a duplicate backup.

The normal [`deploy-production.sh`](../../deploy/scripts/deploy-production.sh)
path remains signed and fail closed. Do not add a signature bypass, local-image
override, or `SKIP_*` switch to that wrapper. The release after this bootstrap
must use the normal signed path described in [deployment.md](deployment.md).

## Safety boundary

The bootstrap is allowed to:

- create the dedicated `codex_control` PostgreSQL login and database;
- migrate that initially empty database;
- start `control-api`, `control-api-replica`, and `codex-pwa` on their admitted
  loopback ports; and
- use the existing Redis `default` user without authentication only under the
  explicit bootstrap mode described below.

It is not allowed to write the Sub2API database, change the Sub2API container,
change Redis ACLs or persistence, or install/reload Nginx. Nginx is a separate
operator action and must occur only after the production snapshot is complete.
The bootstrap records `trust_mode=unsigned-first-deployment-v1` and
`signed_release_verified=false`; those values are expected and must never be
rewritten as signed evidence.

The admitted topology is fixed:

| Component | Boundary |
|---|---|
| Existing network | `sub2api-deploy_sub2api-network` |
| Control API primary | `127.0.0.1:18090` |
| Control API replica | `127.0.0.1:18093` |
| PWA | `127.0.0.1:18091` |
| PostgreSQL | new role and database, both named `codex_control` |
| Redis | alias `redis`, database `0`, prefix `codex-control:` |

## 1. Stage inputs without changing production

Transfer the reviewed unsigned bootstrap bundle, including its canonical
`source.tar.gz`, the three `linux/amd64` image archives, and their out-of-band
checksums to the host. Do not build images on the production host.

Before the first `sudo`, root shell, Docker-socket command, production
credential read, or production script, run the complete
[immutable source staging](deployment.md#immutable-source-staging) procedure.
Use the independently installed, root-owned verifier and approved verifier and
bundle-closure SHA-256 values. `verify-archive` must pass before extraction;
then `verify --source-root` must report both `"admission":true` and
`"source_root_verified":true`. Set these values for every later command:

```sh
export CONTROL_UNSIGNED_BUNDLE=/secure/codex-control/release-bundle
stage=/opt/sub2api-control/REPLACE_WITH_VERIFIED_64_HEX_VCS_REF/source
bundle=${CONTROL_UNSIGNED_BUNDLE:?set the verified bundle}
```

Set `stage` to the exact absolute `source` path from the admitted verifier
result, not to a working checkout or an unchecked pointer value. During the
immutable staging root shell, require
`/opt/sub2api-control/ACTIVE_SOURCE` to be a root-owned, mode-`0444`,
single-link regular file whose one canonical newline-delimited value is this
exact `stage`. Re-run `verify --source-root "$stage"` after that comparison,
then keep this literal absolute path for every later command. The verifier must
also accept every ancestor from `/` through `stage` as a real, root-owned,
non-group/world-writable directory and every source member as root-owned with
its normalized read-only mode. Do not execute a helper from the transferred
checkout or re-resolve a mutable path after this verification.

Never execute a production command from the transferred working checkout or
from a bundle-only non-admission result. Clear `PYTHONHOME` and `PYTHONPATH`, set
`PYTHONNOUSERSITE=1` and `PYTHONSAFEPATH=1`, and use
`PATH=/usr/sbin:/usr/bin:/sbin:/bin` for root wrappers. Direct Python commands
below use `/usr/bin/python3 -I`.

Prepare private storage outside the source checkout. The deployment-record
directory must be owned by the user that runs the bootstrap and have mode
`0700`. The Control backup directory must match `CONTROL_BACKUP_UID_GID`
(default `70:70`) and also have mode `0700`.

```sh
sudo install -d -o root -g root -m 0700 /secure/codex-control
sudo install -d -o root -g root -m 0700 /secure/codex-control/deployments
sudo install -d -o root -g root -m 0700 /secure/codex-control/secrets
sudo install -d -o 70 -g 70 -m 0700 /secure/codex-control/backups
sudo install -d -o root -g root -m 0700 /root/sub2api-control-backups
```

The examples assume the bootstrap runs as root. Use the actual deployment UID
consistently if it runs as another operator.

## 2. Select and revalidate the existing production snapshot

Do not create another backup for this bootstrap. Use the already completed
historical receipt and snapshot exactly as recorded:

```text
receipt: /root/sub2api-control-preflight/final-bootstrap-backup-result.json
snapshot: /root/sub2api-control-backups/production-preflight-20260805T140709Z-l773gtk5
created_at: 2026-08-05T14:07:09.791085Z
manifest_sha256: 29a5651070c7d42ee8780013d6cbecb712f749f826226ff08c88293c99ff4408
```

This evidence is historical/stale, not current/fresh. It predates both the
subsequently observed mutable Sub2API `0.1.175` runtime and the formal `0.1.176`
lock, and cannot represent the current data RPO. Those known mismatches are
explicitly carried as `current_sub2api_runtime` and `current_data_rpo`; neither
is hidden or treated as restored state.

The following check is read-only. It does not create a backup:

```sh
receipt=/root/sub2api-control-preflight/final-bootstrap-backup-result.json
snapshot=/root/sub2api-control-backups/production-preflight-20260805T140709Z-l773gtk5

test "$(stat -c '%U:%G:%a' "$receipt")" = root:root:600
test "$(stat -c '%U:%G:%a' "$snapshot")" = root:root:700
test -f "$snapshot/READY.json"
test "$(sha256sum "$snapshot/manifest.sha256" | awk '{print $1}')" = \
  29a5651070c7d42ee8780013d6cbecb712f749f826226ff08c88293c99ff4408
(cd "$snapshot" && sha256sum -c manifest.sha256)
```

The wrapper still uses a normal fresh maximum age of 1800 seconds. Staleness is
admitted only through the separate exception in section 6, whose hard backup
age is exactly 691200 seconds. All three admissions must finish before
`2026-08-13T14:07:09.791085Z`; reaching that deadline is a hard stop.

## 3. Load and pin exact local image IDs

After the snapshot passes, load the three prebuilt archives. Verify their
transport checksums first; `sha256:<64 hex>` Docker image IDs provide exact
local content identity but do not prove publisher authenticity.

```sh
(cd "$bundle" && /usr/bin/sha256sum -c bootstrap-images.sha256)
docker load --input "$bundle/control-api-linux-amd64.tar"
docker load --input "$bundle/codex-pwa-linux-amd64.tar"
docker load --input "$bundle/postgres-tools-linux-amd64.tar"

api_id=$(docker image inspect --format '{{.Id}}' '<loaded-api-reference>')
pwa_id=$(docker image inspect --format '{{.Id}}' '<loaded-pwa-reference>')
tools_id=$(docker image inspect --format '{{.Id}}' '<loaded-postgres-tools-reference>')
printf '%s\n' "$api_id" "$pwa_id" "$tools_id"
```

All three values must be distinct, exact local image IDs matching
`sha256:[0-9a-f]{64}`. The admission helper also requires all three images to be
`linux/amd64` and requires matching non-placeholder OCI `version`, `revision`,
and `source` labels. The revision must be a 40- or 64-character lowercase hex
source identity. Record the archive checksums and provenance next to the
deployment evidence because this path deliberately has no Sigstore verification.
The PostgreSQL-tools image must expose `pg_dump` and `pg_restore` with the same
major version as the live PostgreSQL server. The wrapper proves this before
provisioning; an older client image is not admissible merely because it loads.

The production Compose overlay removes every local build and sets
`pull_policy: never`. The wrapper also uses `--no-build --pull never`; it neither
pulls a replacement nor builds source on the host.

## 4. Create secrets and the bootstrap Compose environment

Generate private files without placing secret values in environment variables
or command arguments. The PostgreSQL password is consumed by both provisioning
and Compose and must contain only letters, digits, `.`, `_`, `~`, `+`, or `-`.

```sh
umask 077
openssl rand -hex 32 > /secure/codex-control/secrets/control_db_password
openssl rand -hex 32 > /secure/codex-control/secrets/control_redis_password_unused
openssl rand -hex 48 > /secure/codex-control/secrets/control_session_hmac_secret
chown 70:10001 /secure/codex-control/secrets/control_db_password
chmod 0440 /secure/codex-control/secrets/control_db_password
chown 10001:10001 \
  /secure/codex-control/secrets/control_redis_password_unused \
  /secure/codex-control/secrets/control_session_hmac_secret
chmod 0400 \
  /secure/codex-control/secrets/control_redis_password_unused \
  /secure/codex-control/secrets/control_session_hmac_secret
```

The Redis secret file is deliberately random and unused in bootstrap mode. It
exists only because the fixed Compose secret boundary still mounts the file; do
not copy a shared Redis credential into it.

Standalone Compose mounts `file:` secrets as their original Linux inodes; it
does not remap their UID, GID, or mode. The database secret therefore has owner
UID `70` for `control-backup` and group GID `10001` for the Control API. The
API-only secrets use owner `10001`. The enclosing secrets directory remains
`root:root 0700`, so those numeric host identities cannot traverse it outside a
Docker bind mount. Before any PostgreSQL write, the wrapper validates every
tuple and uses the admitted images with `network=none` to prove the intended
read and deny matrix.

Create an absolute, deployment-user-owned, mode-`0600` environment file. Set
the release and revision to the OCI label values already present on all three
loaded images.

```dotenv
CONTROL_RELEASE=<matching-OCI-version>
CONTROL_VCS_REF=<matching-40-or-64-hex-OCI-revision>
CONTROL_API_IMAGE=sha256:<exact-local-api-image-id>
CONTROL_PWA_IMAGE=sha256:<exact-local-pwa-image-id>
CONTROL_POSTGRES_TOOLS_IMAGE=sha256:<exact-local-tools-image-id>

SUB2API_NETWORK_NAME=sub2api-deploy_sub2api-network
CONTROL_PUBLIC_ORIGIN=https://control.example.com
CONTROL_BIND_ADDRESS=127.0.0.1
CONTROL_API_BIND_PORT=18090
CONTROL_API_REPLICA_BIND_PORT=18093
CONTROL_PWA_BIND_PORT=18091

CONTROL_BACKUP_DIR=/secure/codex-control/backups
CONTROL_BACKUP_UID_GID=70:70
CONTROL_DB_HOST=postgres
CONTROL_DB_PORT=5432
CONTROL_DB_USER=codex_control
CONTROL_DB_NAME=codex_control
CONTROL_DB_QUERY=

CONTROL_REDIS_AUTH_MODE=none
CONTROL_REDIS_SCHEME=redis
CONTROL_REDIS_HOST=redis
CONTROL_REDIS_PORT=6379
CONTROL_REDIS_USER=default
CONTROL_REDIS_DATABASE=0
CONTROL_REDIS_QUERY=
CONTROL_REDIS_PREFIX=codex-control:

CONTROL_API_WORKERS=1
CONTROL_SUB2API_EXPECTED_VERSION=0.2.0
CONTROL_SUB2API_EXPECTED_COMMIT=aa23648
CONTROL_SUB2API_CONTRACT_MARKER=0.2.0/aa23648
CONTROL_TRUST_FORWARDED_FOR=true

CONTROL_DATABASE_PASSWORD_SECRET_FILE=/secure/codex-control/secrets/control_db_password
CONTROL_REDIS_PASSWORD_SECRET_FILE=/secure/codex-control/secrets/control_redis_password_unused
CONTROL_SESSION_HMAC_SECRET_FILE=/secure/codex-control/secrets/control_session_hmac_secret
```

Save it as `/secure/codex-control/bootstrap.env` and set mode `0600`. The
Sub2API version, commit, and contract marker above are the currently admitted
values; do not reuse them after a runtime change. Run
`$stage/deploy/scripts/verify-sub2api-runtime.sh` and use its emitted marker if the live
runtime differs. The bootstrap independently verifies that runtime again.

## 5. Stage Nginx only after the snapshot

Follow [deployment.md](deployment.md#nginx-integration) to install the supplied
Nginx includes into the existing HTTPS server, validate with `nginx -t`, inspect
the effective configuration, and reload. This must happen after section 2 so
the verified full snapshot contains the pre-change Nginx state.

The effective configuration must expose same-origin `/codex/`, `/codex-api/`,
`/codex-ws/browser`, and `/codex-ws/device` routes and contain the three admitted
loopback ports `18090`, `18091`, and `18093`. The bootstrap only validates this
state; it does not edit or reload Nginx. Preserve the pre-change Nginx files in
the full snapshot because automatic bootstrap rollback never changes Nginx.

The bootstrap creates the PWA on a dedicated, non-internal Docker bridge so
the daemon can publish container port `8080` to host loopback `127.0.0.1:18091`.
The bridge is configured with Docker's masquerading and inter-container
communication (ICC) options disabled, IPv6 is disabled, and runtime admission
requires the PWA to be the only attached container. The sole-member check is
the enforced container-isolation boundary; the driver options are recorded
configuration and are not treated as cross-daemon packet-filter proof. This
does not claim an absolute host-level outbound firewall boundary.

## 6. Choose the narrow bootstrap exceptions

The preferred run has neither exception: the Sub2API database has already
revoked `PUBLIC CONNECT`, and a private short-lived Sub2API access token plus
its exact user ID are available for authenticated production smoke.

Three explicit exceptions exist only to unblock this one bootstrap. Omit each
unless its stated condition is true. The two boolean opt-ins accept only the
exact strings `0` (disabled) and `1` (enabled). The stale-backup exception uses
the strict JSON artifact below rather than a boolean bypass.

### Existing historical production backup (no duplicate backup)

This exception is valid only for unsigned first bootstrap and only for the
exact receipt, snapshot, manifest, current Sub2API runtime, deployment UUID,
and new-resource set in its JSON. Generate a current runtime attestation and
the exception artifact with read-only commands:

```sh
umask 077
stage=/opt/sub2api-control/REPLACE_WITH_VERIFIED_64_HEX_VCS_REF/source
receipt=/root/sub2api-control-preflight/final-bootstrap-backup-result.json
deployment_id=$(/usr/bin/python3 -I -c 'import uuid; print(uuid.uuid4())')
runtime_attestation="/secure/codex-control/sub2api-runtime-${deployment_id}.json"
exception_file="/secure/codex-control/stale-backup-exception-${deployment_id}.json"

# The digest-locked auth contract is immutable bundle input, not a secret.
test "$(stat -f '%Lp' "$stage/docs/contracts/sub2api-auth.v0.2.0.json" 2>/dev/null || stat -c '%a' "$stage/docs/contracts/sub2api-auth.v0.2.0.json")" = 444

SUB2API_CONTAINER=sub2api \
VERSIONS_LOCK_FILE="$stage/versions.lock.json" \
SUB2API_AUTH_CONTRACT_FILE="$stage/docs/contracts/sub2api-auth.v0.2.0.json" \
SUB2API_ATTESTATION_FILE="$runtime_attestation" \
SUB2API_EXPECTED_NETWORK=sub2api-deploy_sub2api-network \
SUB2API_EXPECTED_NETWORK_ALIAS=sub2api \
SUB2API_REQUIRE_AUTH_EVIDENCE=0 \
  env -u PYTHONHOME -u PYTHONPATH PATH=/usr/sbin:/usr/bin:/sbin:/bin \
  PYTHONNOUSERSITE=1 PYTHONSAFEPATH=1 \
  "$stage/deploy/scripts/verify-sub2api-runtime.sh"

/usr/bin/python3 -I "$stage/deploy/scripts/bootstrap-admission.py" \
  stale-backup-exception-template \
  --result-file "$receipt" \
  --deployment-id "$deployment_id" \
  --current-runtime-attestation "$runtime_attestation" \
  --valid-for-seconds 1800 \
  --expected-control-database codex_control \
  --expected-control-role codex_control \
  --expected-redis-prefix codex-control: \
  --expected-pwa-network sub2api-codex-control_pwa-network \
  > "$exception_file"
chown root:root "$exception_file"
chmod 0600 "$exception_file"

export CONTROL_BOOTSTRAP_DEPLOYMENT_ID="$deployment_id"
export CONTROL_STALE_PRODUCTION_BACKUP_EXCEPTION_FILE="$exception_file"
```

The generator emits the exact `stale-production-backup-exception-v1` schema.
It fixes `max_age_seconds=691200`, limits approval validity to at most one hour,
and sets `reason=user-prohibited-repeat-backup`,
`scope=unsigned-first-deployment-only`,
`rollback_strategy=delete-only-new-control-resources`, and
`automatic_restore=false`. The exact allowed resources are the four bootstrap
Compose services, the admitted PWA network, the `codex_control` role/database,
and `codex-control:*` Redis keys/channels. Mutations to Sub2API, its database,
other PostgreSQL resources, Redis ACL/configuration or other keys, existing
containers, Nginx, and UFW are forbidden.

The exception file must be absolute, root-owned, mode `0600`, a regular
non-symlink file with exactly one hard link, and strict JSON without duplicate
keys or non-finite numbers. Its expiry cannot exceed either one hour from issue
or `2026-08-13T14:07:09.791085Z`. The wrapper revalidates its full binding three
times and records `fresh=false` with
`admission_mode=stale-production-backup-exception-v1` each time.

After the first successful admission, the wrapper atomically creates a
permanent `O_EXCL` claim under
`$CONTROL_DEPLOYMENT_RECORD_DIR/.stale-backup-exception-claims`. The exception
is consumed even if a later stage fails. A retry before the hard cutoff requires
a new deployment UUID and newly generated exception; it does not require or
authorize a duplicate backup.

### Existing Sub2API `PUBLIC CONNECT`

If changing the existing Sub2API database ACL is outside this bootstrap's
approved scope, set:

```sh
export CONTROL_BOOTSTRAP_ALLOW_SUB2API_PUBLIC_CONNECT=1
```

This does not change the Sub2API database or grant `codex_control` table/schema
privileges. It does acknowledge that the stronger database-connect isolation
gate is not yet satisfied because PostgreSQL still grants database connection
through `PUBLIC`. The deployment record must preserve the observed ACL, the
explicit opt-in, and the post-provision role-membership/ownership checks. Treat
this as a temporary bootstrap exception, not proof of full datastore isolation.

Without that exact opt-in, observed `PUBLIC CONNECT` must stop the bootstrap.

### Authenticated smoke not yet available

Prefer a mode-`0600`, deployment-user-owned access-token file and its exact
Sub2API user ID:

```sh
export CONTROL_SMOKE_ACCESS_TOKEN_FILE=/secure/fixtures/smoke-access
export CONTROL_SMOKE_EXPECTED_USER_ID=<exact-sub2api-user-id>
```

If no short-lived token can be issued before first start, set:

```sh
export CONTROL_BOOTSTRAP_ALLOW_UNAUTHENTICATED_SMOKE=1
```

The wrapper may then run only its unauthenticated reachability/security checks.
Its evidence must set `authenticated_smoke_pending=true` and record the exact
opt-in. A healthy container or unauthenticated smoke result is not production
acceptance. Create the short-lived token and complete the authenticated session
exchange smoke immediately afterward; retain that output with the bootstrap
record. The normal signed deployment remains blocked without authenticated
smoke evidence.

Do not combine a missing token with fake, expired, disabled-user, or arbitrary
invalid credentials. Either provide the real bound identity or use the explicit
pending-state opt-in.

## 7. Run the one-time wrapper

Export only paths and public identifiers. Keep secrets in their files.

```sh
export CONTROL_BOOTSTRAP_CONFIRM=UNSIGNED_FIRST_DEPLOYMENT_ONLY
stage=/opt/sub2api-control/REPLACE_WITH_VERIFIED_64_HEX_VCS_REF/source
export CONTROL_COMPOSE_ENV_FILE=/secure/codex-control/bootstrap.env
export CONTROL_DEPLOYMENT_RECORD_DIR=/secure/codex-control/deployments
export CONTROL_PRODUCTION_BACKUP_RESULT_FILE="$receipt"
export CONTROL_PRODUCTION_BACKUP_MAX_AGE_SECONDS=1800
export CONTROL_DATABASE_PASSWORD_FILE=/secure/codex-control/secrets/control_db_password

export SUB2API_CONTAINER=sub2api
export SUB2API_POSTGRES_CONTAINER=sub2api-postgres
export SUB2API_DB_NAME=sub2api
export SUB2API_REDIS_CONTAINER=sub2api-redis

env -u PYTHONHOME -u PYTHONPATH PATH=/usr/sbin:/usr/bin:/sbin:/bin \
  PYTHONNOUSERSITE=1 PYTHONSAFEPATH=1 \
  "$stage/deploy/scripts/bootstrap-production-unsigned.sh"
```

Set `SUB2API_POSTGRES_ADMIN_USER` only when the PostgreSQL container's
`POSTGRES_USER` is not the correct administrator. Do not run
`provision-postgres.sh`, `provision-redis-acl.sh`, `alembic upgrade`, or `docker
compose up` separately. The wrapper uses tools inside the existing containers,
proves the target role/database were absent, provisions only `codex_control`,
proves that database is pristine, migrates it, and starts all three sidecars
from the admitted local image IDs.

In `CONTROL_REDIS_AUTH_MODE=none`, the wrapper accepts only the existing Redis
`default` user with the exact broad passwordless contract `on`, `nopass`, `~*`,
`&*`, and `+@all`, plus an unauthenticated `PING`. It does not run `ACL SETUSER`
or `ACL SAVE`. The `codex-control:` key and channel namespace must be empty
before first start. The application may then write only that namespace. On
failure the wrapper stops the new containers and removes at most 10,000 keys
from that previously empty prefix; it never changes Redis ACL or configuration.
If the live default user or namespace baseline differs, stop; do not weaken or
delete unrelated Redis state to make this runbook pass.

## 8. Accept the result and retain evidence

The command prints the absolute path to `bootstrap-deployment.json`. Preserve
the complete enclosing mode-`0700` directory. At minimum, review:

- `status` is `bootstrapped-unsigned`;
- `trust_mode` is `unsigned-first-deployment-v1`;
- `signed_release_verified` is `false`;
- all three `production_backup_admissions` use the same binding hash and show
  `fresh=false` plus `stale-production-backup-exception-v1` for this run;
- the exception input, immutable copy, and permanent one-use claim hashes are
  present in the deployment record;
- the admitted production-backup receipt still matches current container and
  image IDs;
- the three running containers use the exact admitted local image IDs and
  loopback ports;
- the migration reached the single packaged Alembic head;
- `sub2api-before.json` and `sub2api-after.json` bind the same Sub2API runtime;
- `rollback-plan.json` lists only the new Control resources and bounded Redis
  namespace cleanup;
- each requested exception is explicitly present in evidence; and
- `authenticated_smoke_pending` is `false`, or it remains an open acceptance
  item with the operator, token issuance, and follow-up deadline recorded.

The success record is deliberately an unsigned bootstrap record. Archive it
with the image archive checksums, Nginx change record, authenticated smoke
output, and off-host backup-verification result. Do not relabel it as a normal
release admission record.

### Close a pending authenticated smoke item

Do not edit `bootstrap-deployment.json` after the unsigned bootstrap. When that
record has `authenticated_smoke_pending=true`, first append its one-use,
non-secret challenge:

```sh
stage=/opt/sub2api-control/REPLACE_WITH_VERIFIED_64_HEX_VCS_REF/source
/usr/bin/python3 -I "$stage/deploy/scripts/record-authenticated-smoke-closure.py" \
  --bootstrap-record /secure/codex-control/deployments/bootstrap-.../bootstrap-deployment.json \
  --prepare-challenge
```

This creates `authenticated-smoke-challenge.json` beside the unchanged
bootstrap record through an `O_EXCL` private temporary file and a native atomic
no-replace rename. It binds a random nonce to the canonical
deployment UUID, deployment-directory basename, exact bootstrap-record SHA-256,
canonical public HTTPS origin, admitted image artifact identities, source
revision identity, and running container identities from the bootstrap record's
verified `plan.json`, `images.json`, and `running-containers.json`. Never copy a
challenge between deployments.

Run the real authenticated production smoke with that challenge, a private
token file, and a separate private expected-user-id file as described above.
Both inputs must use canonical absolute paths, be owned by the deployment UID,
have mode exactly `0600` and one filesystem link, and have no symlink in any
ancestor. Capture only the smoke program's stdout in an external mode-`0600`,
deployment-UID-owned log:

```sh
umask 077
unset SUB2API_ACCESS_TOKEN CONTROL_BASE_URL SUB2API_EXPECTED_USER_ID
stage=/opt/sub2api-control/REPLACE_WITH_VERIFIED_64_HEX_VCS_REF/source
/usr/bin/python3 -I "$stage/tests/e2e/smoke.py" \
  --base-url https://control.example.com \
  --access-token-file /secure/evidence/sub2api-access-token \
  --expected-user-id-file /secure/evidence/sub2api-expected-user-id \
  --expect-secure-cookie \
  --closure-challenge-file /secure/codex-control/deployments/bootstrap-.../authenticated-smoke-challenge.json \
  > /secure/evidence/authenticated-smoke.log
```

Challenge mode rejects token and expected-user-id values supplied through argv
or environment variables. It also rejects every device-flow option before
reading either private input or making a network request. The expected identity
is retained only in process memory and is not copied into the smoke log,
challenge, closure, or bootstrap deployment directory.

A valid closure log contains the exact sequential 84-check production catalog
followed by the producer's real TAP plan:

```text
1..84 # closure-challenge-sha256=<sha256> target-binding-sha256=<sha256>
```

Then append the formal closure next to the bootstrap record:

```sh
stage=/opt/sub2api-control/REPLACE_WITH_VERIFIED_64_HEX_VCS_REF/source
/usr/bin/python3 -I "$stage/deploy/scripts/record-authenticated-smoke-closure.py" \
  --bootstrap-record /secure/codex-control/deployments/bootstrap-.../bootstrap-deployment.json \
  --smoke-log /secure/evidence/authenticated-smoke.log
```

This closure version does not accept a revocation-observation input and always
records `revocation_observation=null`. There is not yet a trusted producer that
can bind a Sub2API login/logout/refresh observation to the exact Control smoke
session, so an operator-authored status file cannot close or strengthen this
acceptance item. Keep any logout/refresh result as separate diagnostic evidence
without copying it into the bootstrap deployment directory or presenting it as
part of this closure.

The closure command accepts no token value or token-file argument. It rejects
non-canonical paths, `..`, and symlinks in every ancestor through a directory-FD
`O_NOFOLLOW` walk. It reopens and hashes every file in the bootstrap record's
`verified_evidence`, checks owner, mode, single-link identity, size, and
stability, and binds their complete original descriptor projection.

The external smoke evidence is imported byte for byte into the bootstrap
deployment directory as the fixed sibling `authenticated-smoke.log`. The
closure JSON records only its relative basename, SHA-256, size, TAP counts, the
deployment binding, and the challenge SHA-256. It never records or prints an
external evidence source path, user identity, credential, token, or raw
challenge nonce. A pre-existing `sub2api-session-revocation.log` sibling is a
hard conflict and must not be deleted or replaced by this command.

Publication is append-only: every challenge, imported smoke file, and closure
uses a fsynced `O_EXCL` private temporary file plus native no-replace rename
(`renameat2(RENAME_NOREPLACE)` on Linux), directory `fsync`, and byte-for-byte
re-read. Missing operating-system or filesystem support fails closed. If the
process is killed after the fixed
smoke sibling is durable but before closure publication, rerun the same command
with the same external bytes. It reuses only an owner/mode/link-valid fixed
sibling whose bytes exactly match this attempt and whose embedded
challenge/deployment binding still validates; a conflict fails without deletion
or replacement. A second invocation after the closure exists fails. Failed,
duplicated, missing, reordered, renamed, or extra checks, an unbound TAP plan,
changed bootstrap record, or replayed challenge all fail without a closure.
Preserve the unchanged bootstrap record and its fixed-name siblings together.
The closure resolves the pending item without pretending that the historical
bootstrap JSON was mutable or signed.

## 9. Failure and rollback

Before writes begin, a failure records that no persistent production mutation
was attempted. After provisioning starts, the wrapper's failure trap
stops/removes only new Control containers, drops only the new `codex_control`
database and role, and removes only keys under the proven-empty
`codex-control:` baseline. It records the result and cleanup count in
`rollback.json`. It never changes Sub2API, Redis ACL/configuration, or Nginx.
For the stale-backup exception this is strictly delete-only rollback of new
Control resources. `automatic_restore=false`: the historical snapshot is not
automatically restored because it does not represent the current runtime or
data RPO. `rollback.json` retains every admission produced before failure plus
the exception and permanent claim hashes.

If automatic rollback is incomplete, stop and inspect the private record before
taking further action. Use `rollback-plan.json` to identify the exact new
resources; do not run a broad Compose `down`, drop the Sub2API database, flush
Redis, or restore the whole host. Restore the pre-bootstrap Nginx files from the
verified snapshot only when the Nginx change itself must be reverted, then run
`nginx -t` before reload.

After a successful bootstrap has accepted real users or devices, back up the
Control database before any manual rollback. Its data is then authoritative and
must not be discarded merely because the initial deployment was unsigned.

## 10. Move immediately to the signed release path

This bootstrap cannot be repeated as an upgrade. Before the next release:

1. Complete any pending authenticated smoke and append the formal
   `authenticated-smoke-closure.json` record described above.
2. Remove the `PUBLIC CONNECT` exception through a separately reviewed,
   backup-first PostgreSQL ACL change, then prove `codex_control` cannot connect
   to the Sub2API database.
3. Provision the restricted Redis ACL user described in
   [deployment.md](deployment.md), switch to
   `CONTROL_REDIS_AUTH_MODE=password`, and stop using the passwordless default
   user for Control.
4. Publish and verify the signed release bundle, repository digest references,
   SBOM/provenance, source commit, and migration head.
5. Unset `CONTROL_BOOTSTRAP_CONFIRM`,
   `CONTROL_BOOTSTRAP_ALLOW_SUB2API_PUBLIC_CONNECT`, and
   `CONTROL_BOOTSTRAP_ALLOW_UNAUTHENTICATED_SMOKE`.
6. Download the complete signed server-package asset set from one GitHub
   Release, authenticate the standalone verifier, run `verify-release`, and
   invoke the verified package's `sub2api-control-upgrade` lifecycle wrapper with
   its root-only verification receipt and operator environment. The lifecycle
   wrapper is the only supported formal upgrade path. It invokes the signed
   `deploy-production.sh` internally after binding package, image, Connector,
   backup, and authenticated acceptance evidence; never execute that script
   through the historical `ACTIVE_SOURCE` pointer.
