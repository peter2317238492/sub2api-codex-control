# Deployment runbook

## Scope and topology

This deployment adds `control-api` and `codex-pwa` sidecars without modifying
Sub2API. The target must already run the exact immutable `0.1.178` tuple in
`versions.lock.json`; this runbook provides no in-place updater or legacy
compatibility path. Only the Control API joins the existing external Docker
network named by `SUB2API_NETWORK_NAME` (default
`sub2api-deploy_sub2api-network`); the PWA remains on a dedicated static-serving
bridge. That bridge is non-internal so Docker can publish the PWA port to the
host, while the bridge is configured with Docker's masquerading and
inter-container communication (ICC) options disabled. Runtime admission also
requires the PWA to be the network's sole member. Both services publish
loopback-only ports for the host Nginx, and no
device-side inbound port is added. This network setting specifically disables
Docker bridge masquerading; it is not documented as an absolute host-level
outbound firewall boundary.

The public routes are:

| Public route | Default loopback upstream | Internal route |
| --- | --- | --- |
| `/codex/` | `127.0.0.1:18091` | `/codex/` |
| `/codex-api/` | `127.0.0.1:18090` | prefix stripped to `/` |
| `/codex-ws/browser` | `127.0.0.1:18090` | `/ws/browser` |
| `/codex-ws/device` | `127.0.0.1:18093` | `/ws/device` |

Production admission always enables the `multi-instance` profile and publishes
a second API at `127.0.0.1:18093`. The release edge routes
`/codex-ws/device` to that replica
while retaining HTTP and `/codex-ws/browser` on the primary. The disposable
acceptance harness uses exactly that deterministic split, drives a real
Connector against a deterministic fake Codex stdio fixture, and covers Redis
cross-dispatch/fanout, heartbeat, replica kill/reconnect, and credential
revocation. It never describes the fake fixture as a real Codex canary. The local harness is
not a substitute for release evidence against the immutable production images;
retain the corresponding production smoke output with the release matrix.

## Preconditions

1. Prove the live Sub2API matches the exact `0.1.178` manifest, image ID, labels,
   PID 1 SHA-256, read-only rootfs, empty Docker diff, admitted `/app/data` mount,
   and locked auth fixture. Record that attestation with the immutable image
   digests, source commit, migration revision, Connector version, Codex version,
   and app-server schema digest.
2. Confirm the existing Sub2API, PostgreSQL, and Redis service names are
   reachable on the external network. The defaults are `sub2api`, `postgres`,
   and `redis`; override their host variables if the real aliases differ.
3. Ensure the public origin has a valid TLS certificate. `CONTROL_PUBLIC_ORIGIN`
   is one exact origin such as `https://control.example.com`, with no path.
4. Install Docker Engine with Compose v2, Nginx, `openssl`, PostgreSQL client
   tools, and `redis-cli` on the administrative host.

### Formal server-package lifecycle

Formal install, upgrade, and rollback begin with the complete server-package
asset set from one GitHub Release. First authenticate the downloaded standalone
`server-package-verify.py` with the approved public Sigstore policy. Then run its
`verify-release` command against the exact release directory, a new extraction
directory, and a new root-only verification-receipt path. Only the extracted
package and receipt produced by that command may enter the installed lifecycle.
Follow [the server package installation guide](../../deploy/server-package/INSTALL.md)
for the exact online/offline asset inventories and commands.

`verify-release` creates exactly one package root. Pin that literal path for all
remaining read-only checks, configuration templates, and acceptance commands;
do not rediscover it through a mutable pointer:

```sh
PACKAGE_ROOT=/secure/control-extracted/sub2api-codex-control-server-RELEASE-linux-amd64-online
stage="$PACKAGE_ROOT/source"
```

Operators invoke only the verified package's
`sub2api-control-install`, `sub2api-control-upgrade`, or
`sub2api-control-rollback` wrapper. `deploy-production.sh` is a signed,
package-internal implementation detail. The lifecycle injects its package
manifest, verification receipt, Connector public-release metadata, local Docker
endpoint, and release policy; direct execution cannot reproduce that trust
chain. If deployment succeeds but activation or the lifecycle receipt cannot be
committed, lifecycle calls the internal post-success bounded-reverse interface.
That reverse must publish authenticated no-replace evidence and release the
production deployment lock; any failure retains both recovery evidence and the
lock for review.

Formal uninstall uses only the current activation-installed package's
`sub2api-control-uninstall` wrapper. Lifecycle authenticates the active package
and its exact successful deployment binding before invoking the signed internal
`--lifecycle-bounded-uninstall` interface. That interface acquires the production
deployment lock, rejects any container or network drift, and writes immutable
`uninstall-plan.json` and `uninstall-execution.json` records before lifecycle may
remove activation or installed package trees. It stops and removes only the
three exact recorded `control-api`, `control-api-replica`, and `codex-pwa`
container IDs and the exact package-owned PWA network. A successful deployment
must have no remaining `control-migrate`, `control-backup`, or other Compose
project container; any such one-off residue is a hard refusal rather than an
unowned deletion.

Uninstall preserves Sub2API, PostgreSQL, Redis, application data, secrets,
backups, deployment and lifecycle records, container images, Connector user
state, Nginx configuration, and logrotate policy. Nginx and logrotate are shared
host integration in this release and have no package ownership receipt, so the
uninstaller must not edit, delete, test, or reload them. A legacy deployment
without the exact package/container/network binding is not uninstallable through
the formal wrapper and requires a separately reviewed recovery procedure. Any
admission, removal, postcondition, or runtime execution-receipt failure retains
both lifecycle and production locks for review. Once bounded runtime uninstall
succeeds and its execution receipt is durable, the production lock is released.
A later lifecycle activation/package cleanup or terminal lifecycle-receipt
failure retains only the lifecycle lock.

## Production admission preconditions

The 2026-08-12 read-only inspection found this legacy self-updated state:

- image digest `weishaw/sub2api@sha256:2ca591c2af97eb0e2797cfc7fb7bd587194d94cebdac76f73d677eeab1d4d6c8`;
- image labels `0.1.151` and commit `deff3123`;
- running `/app/sub2api` version `0.1.175`, commit
  `93c32fa1a2450351561abc46156d2e28cb5f74ca`, build time
  `2026-08-12T10:57:38Z`, SHA-256
  `14b2e5b2a7b98be51226d1a9fe12c561780bf9fe257ff5a5ba13a5861daca44c`;
- writable-layer changes to `/app/sub2api`, `/app/sub2api.backup`,
  `/app/sub2api.backup.backup`, and `/root/.ash_history`.

That state is historical drift evidence only. It is not accepted by the formal
release gate and must not be encoded as a production compatibility exception.
Before Control services start, the Sub2API container must run the locked
`0.1.178` linux/amd64 manifest
`weishaw/sub2api@sha256:989c1a56f3598b4e907fc23c80377db1ad22d024f673e6725d80b970d43b6c00`
with image/config ID
`sha256:40d807a98dbd6c56dd5838ca1a2efe4f60bf2dd88c3621f11eab090c98d38742`.
Run the fail-closed verifier against that immutable container:

```sh
stage="$PACKAGE_ROOT/source"
VERSIONS_LOCK_FILE="$stage/versions.lock.json" \
  SUB2API_EXPECTED_DATA_BIND_SOURCE=/root/sub2api-deploy/data \
  SUB2API_EXPECTED_DATA_BIND_UID=1000 \
  SUB2API_EXPECTED_DATA_BIND_GID=1000 \
  SUB2API_EXPECTED_DATA_BIND_MODE=0755 \
  "$stage/deploy/scripts/verify-sub2api-runtime.sh"
```

The preflight resolves the container name once and uses that full container ID
for every subsequent read. Only the explicit `immutable-image-v1` profile is
accepted. It requires a read-only root filesystem, digest-only `Config.Image`,
exact RepoDigest/image ID/OCI labels, all capabilities dropped,
no-new-privileges, no writable-layer drift, and exactly one writable data mount
at `/app/data`. A named volume is accepted. A bind is accepted only when its
canonical source, numeric owner/group, mode, and `rprivate` propagation are
explicitly supplied and every path component is a real directory without group
or other write access; every ancestor before the final data directory must be
root-owned. An unadmitted bind, updater backup, mutable tag, missing
profile, compatibility field, stopped or unhealthy container, binary mismatch,
container replacement, restart, network expansion, or mount expansion fails.
The container must carry the `sub2api` alias on the exact external network used
by Control API.

Production admission additionally requires fresh, runtime-bound evidence for
`/auth/me` success, exact `401/USER_INACTIVE` disabled-user rejection, exact
`401/TOKEN_REVOKED` TokenVersion rejection, refresh rotation and old-token
rejection, and logout followed by refresh rejection. The deployment wrapper
always creates a fresh nonce and runs the probe from the signed Control API
image in the verified Sub2API container's exact network namespace. Four
disposable mode-`0600` token files are copied into a private read-only probe
mount; raw tokens and token hashes never enter the evidence. Prebuilt external
authentication evidence and alternate probe origins are prohibited.

The immutable gate pins the exact 0.1.178 manifest/image ID, container
`Config.Image`, entrypoint/Cmd, loopback `8080` binding, external network,
admitted `/app/data` storage identity, runtime tuple, and empty writable diff. It verifies
that the live PID 1 binary equals the official archive/image binary. A
successful check produces `CONTROL_SUB2API_CONTRACT_MARKER=0.1.178/e0c48a1`;
any different value or `UNVERIFIED` blocks deployment.

## Mandatory pre-mutation snapshot

Before `provision-postgres.sh`, `provision-redis-acl.sh`, any Nginx file install
or reload, any authentication probe, or `deploy-production.sh`, create one fresh
snapshot of the existing production state. A prior scheduled backup or an older
baseline is not the cutover gate. The backup root must already be an encrypted,
root-owned, mode-`0700` directory outside the checkout; the script never widens
permissions or creates the root for the operator.

Run this on the production host, substituting the actual config and environment
file paths if the existing Sub2API layout differs:

```sh
sudo install -d -o root -g root -m 0700 /root/sub2api-control-backups
cutover_id=$(date -u '+%Y%m%dT%H%M%SZ')
receipt="/root/sub2api-control-backups/cutover-${cutover_id}.json"

stage="$PACKAGE_ROOT/source"
sudo env -u PYTHONHOME -u PYTHONPATH /usr/bin/python3 -I \
  "$stage/deploy/scripts/backup-production-state.py" \
  --backup-root /root/sub2api-control-backups \
  --result-file "$receipt" \
  --sub2api-container sub2api \
  --postgres-container sub2api-postgres \
  --postgres-user sub2api \
  --postgres-database sub2api \
  --additional-postgres-database codex_control \
  --redis-container sub2api-redis \
  --redis-user default \
  --redis-data-path /data \
  --sub2api-data /root/sub2api-deploy/data \
  --sub2api-config /root/sub2api-deploy/data/config.yaml \
  --sub2api-compose /root/sub2api-deploy/docker-compose.local.yml \
  --sub2api-environment /root/sub2api-deploy/.env \
  --nginx-config /etc/nginx

snapshot=$(sudo env -u PYTHONHOME -u PYTHONPATH /usr/bin/python3 -I -c \
  'import json,sys; print(json.load(open(sys.argv[1]))["snapshot_directory"])' \
  "$receipt")
sudo test -f "$snapshot/READY.json"
sudo env PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C \
  /bin/sh -c 'cd "$1" && /usr/bin/sha256sum -c manifest.sha256' sh "$snapshot"
```

Omit the optional PostgreSQL or Redis password-file argument when the local
container socket/default Redis user is intentionally passwordless. When a
password is required, pass only a root-readable file with
`--postgres-password-file` or `--redis-password-file`; never put the value in an
environment variable or command argument. The Redis commands explicitly unset
an inherited `REDISCLI_AUTH` when no password file is supplied.

The script fails closed unless it can produce and validate all of these in one
private timestamped directory:

- a custom-format Sub2API PostgreSQL dump, globals/roles/ACL metadata and a
  `pg_restore --list` generated inside the PostgreSQL container; an existing
  `codex_control` database is dumped too, while a first-deploy absence is
  recorded explicitly;
- a logical Redis RDB accepted by `redis-check-rdb`, Redis persistence files,
  and private ACL/config metadata;
- the Sub2API data/config/Compose/environment files, full container and image
  inspect output, container diff, runtime binary, and two stable host
  `/proc/<pid>/exe` hashes; formal admission requires an empty diff and no
  legacy updater files, while historical snapshots may retain earlier drift;
- `/etc/nginx`, the validated `nginx -T` output, certificate metadata, and a
  root-only recovery archive containing certificate and private-key material;
- tar listings, per-artifact SHA-256 values, `manifest.sha256`, and `READY.json`.

No partial directory is renamed into the ready namespace, and no `READY.json`
is created if any dump, RDB check, tar listing, procfs identity check, TLS read,
or checksum fails. Treat the snapshot as secret material: it contains database
data, Redis ACL hashes, environment files, Docker inspect data, and TLS private
keys. Verify an encrypted off-host copy before accepting a destructive change.
Keep the receipt path in the change record. If any provision or cutover step is
retried, create a new snapshot first; do not reuse the old receipt.

## Datastore isolation

Generate secrets without printing them:

```sh
stage="$PACKAGE_ROOT/source"
SECRET_DIR=/secure/codex-control/secrets \
  "$stage/deploy/scripts/generate-secrets.sh"
```

Provision an independent PostgreSQL login and database from an administrative
environment that can reach the existing server:

```sh
POSTGRES_ADMIN_URL='postgresql://postgres@postgres:5432/postgres' \
  POSTGRES_ADMIN_PASSWORD_FILE=/secure/postgres_admin_password \
  CONTROL_DB_USER=codex_control \
  CONTROL_DB_NAME=codex_control \
  SUB2API_DB_NAME=sub2api \
  CONTROL_DATABASE_PASSWORD_FILE=/secure/codex-control/secrets/control_db_password \
  "$stage/deploy/scripts/provision-postgres.sh"
```

The script creates a non-superuser, non-inheriting, membership-free role, a
database owned by that role, removes public database/schema privileges, and
grants no Sub2API database privileges. It rejects an existing Control role that
is either a member of another role or has members of its own, since `SET ROLE`
would otherwise weaken the dedicated boundary. PostgreSQL has no per-role `DENY` that overrides a
`PUBLIC CONNECT` grant, so the provisioner first requires the existing Sub2API
database to have already revoked `CONNECT` from `PUBLIC`; it fails before
creating the role or database otherwise. Coordinate explicit grants for the
existing Sub2API login and other legitimate clients, or use a separate
PostgreSQL cluster. The Control provisioner does not change the existing
Sub2API database ACL. Verify `has_database_privilege` is false and an actual
Control-role connection to the Sub2API database is rejected before admission.

Provision a Redis ACL user. `CONTROL_REDIS_PREFIX` must exactly match Compose:

```sh
REDIS_ADMIN_URL='redis://redis:6379/0' \
  REDIS_ADMIN_USER=default \
  REDIS_ADMIN_PASSWORD_FILE=/secure/redis_admin_password \
  CONTROL_REDIS_USER=codex_control \
  CONTROL_REDIS_PREFIX='codex-control:' \
  CONTROL_REDIS_PASSWORD_FILE=/secure/codex-control/secrets/control_redis_password \
  "$stage/deploy/scripts/provision-redis-acl.sh"
```

The ACL permits only required key commands, scripting, and prefixed Pub/Sub
channels. `ACL SAVE` must succeed so the user survives a Redis restart. Do not
rely on a Redis database number as an authorization boundary. When an admin
password file is used, the URL must not contain userinfo; this prevents an
ambiguous `redis-cli` authentication path from being accepted as successful.
The provisioner assumes the administrative user is already protected; it does
not silently change or disable an existing external Redis administrator. If the
current server still has `user default on nopass`, first use a separately
authorized maintenance change to configure an ACL file and either protect that
administrator with a file-backed password or create a protected administrator
and disable `default`. Persist the change with `ACL SAVE`, prove a credentialless
`PING` returns `NOAUTH`, then run the dedicated Control-user provisioner above.
Any enabled `nopass` user, a successful credentialless command, or a missing
dedicated ACL user is a formal deployment rejection even when Redis has no
published host port. The normal deployment wrapper never provisions or broadens
Redis ACLs. After every authorized ACL mutation, create a new full production
snapshot; do not reuse the snapshot taken before provisioning as the cutover
gate.

## Compose deployment

Create the environment file and keep it mode `0600`:

```sh
stage="$PACKAGE_ROOT/source"
install -m 0600 "$stage/deploy/docker-compose/.env.example" \
  /secure/codex-control/control.env
# Edit only the private runtime copy, never the verified source tree.
docker network inspect "$(sed -n 's/^SUB2API_NETWORK_NAME=//p' \
  /secure/codex-control/control.env)"
docker compose --env-file /secure/codex-control/control.env \
  -f "$stage/deploy/docker-compose/compose.yaml" config --quiet
```

Production uses both `compose.yaml` and `compose.production.yaml`. The latter
removes local builds, sets `pull_policy: never`, and requires immutable digest
references for the API, PWA, and PostgreSQL backup-tools image. Local E2E uses
only the base file and is unaffected.

Do not run `pull`, `control-migrate`, `up`, or `deploy-production.sh` manually.
The formal production entry points are the installed lifecycle wrappers listed
above. Lifecycle calls the signed internal deployment script only after it has
verified the server package and injected the fixed API/PWA/backup-tools and
Connector release evidence. The internal script then performs every read-only
gate, backup, migration, start, and smoke operation under one exclusive
deployment lock.
Complete the Nginx integration below before the first invocation so the final
same-origin smoke can reach `CONTROL_PUBLIC_ORIGIN`.

Formal release precondition: the live Control database must already be at the
signed migration head. If the revisions differ, this candidate intentionally
applies and verifies the migration only inside the frozen recovery window, then
fails and reverses before exposing an API. A migration-bearing production
release remains blocked until a controlled-traffic maintenance gate can prove
that real users cannot reach either API from the frozen snapshot through final
commit.

Set the immutable image values in `.env`, use an encrypted backup directory
outside the checkout, and provide a private deployment-record directory. The
release policy values are external trust inputs from the approved release
record; never copy issuer, identity, repository, commit, or ref out of the
downloaded lock itself.

Provision both operator paths before invoking the wrapper. The deployment
record directory must be owned by the deployment EUID with mode `0700`; the
backup directory must be owned by the numeric UID:GID configured in
`CONTROL_BACKUP_UID_GID` (default `70:70`) with mode `0700`. The wrapper and
backup job reject missing, symlinked, mis-owned, or broader-mode directories and
never repair them with `chmod`.

```sh
PACKAGE_ROOT=/secure/control-extracted/sub2api-codex-control-server-RELEASE-linux-amd64-online
RECEIPT=/secure/control-receipts/online.verification.json
OPERATOR_ENV=/secure/codex-control/operator.env

sudo "$PACKAGE_ROOT/bin/sub2api-control-install" \
  --verification-receipt "$RECEIPT" \
  --operator-env-file "$OPERATOR_ENV"

# For a later independently verified package, use its upgrade wrapper.
sudo "$NEW_PACKAGE_ROOT/bin/sub2api-control-upgrade" \
  --verification-receipt "$NEW_RECEIPT" \
  --operator-env-file "$OPERATOR_ENV" \
  --deployment-timeout-seconds 1800
```

Create `OPERATOR_ENV` from the verified package's
`config/operator.env.example`. It is a literal root-owned mode-`0600` file, not
a shell script. Do not add lifecycle-owned package, release, image, Connector,
Docker endpoint, or rollback values; lifecycle rejects operator attempts to
override them.

The active refresh fixture is consumed by rotation/logout and must be newly
issued for each run. `SUB2API_AUTH_EVIDENCE_FILE` and
`SUB2API_AUTH_FIXTURE_BASE_URL` are rejected rather than treated as overrides.
The disabled and revoked fixtures must be genuine tokens that produce the
distinct frozen middleware codes; arbitrary invalid tokens do not pass.
`CONTROL_SMOKE_ACCESS_TOKEN_FILE` is separately required for the final
authenticated Control session smoke. It must be an absolute, regular,
non-symlink file owned by the deployment EUID, with no group/other permissions,
no more than 64 KiB, and one opaque short-lived access token. The admission
reader opens it with no-follow semantics and rejects an inode change between
inspection and open. `CONTROL_SMOKE_EXPECTED_USER_ID` binds the exchange to the
exact fixture identity. Missing, broad-mode, symlinked, oversized, or malformed
input stops the wrapper before any pull, backup, migration, or service start.

The wrapper securely copies the private absolute Compose environment file once,
binds the selected `versions.lock.json` and Sub2API auth contract byte-for-byte
to hashes from the verified signed release, snapshots both inputs privately,
resolves Compose once with the `ops` and `multi-instance` profiles, and uses only
that private resolved JSON snapshot for every subsequent operation. It verifies
the signed three-image lock, Sigstore identity and attestations, resolved Compose
values and the signed versus packaged migration head. Before pulling release
images or running the authentication probe, it creates another full production
state snapshot using the mandatory host paths above. The isolated PostgreSQL and
Redis restore containers use the backup-bound local image IDs with
`--network none --pull never`; an absent image fails instead of being acquired.
It then verifies pulled
image IDs/OCI labels and Sub2API runtime/auth identity. The runtime attestation
must report `admission_profile=immutable-image-v1`, exact `0.1.178/e0c48a19...`
identity, and no writable-layer drift. The wrapper then records the live
database revision and rechecks Compose, Sub2API, and the database revision.
Immediately before the destructive window, it records the exact API container
IDs, images, start timestamps, restart counts, and prior running states in a
bounded no-database-restore unfreeze plan. It stops both API writers, proves the
exact containers are stopped, creates exactly one new pre-migration dump, and
proves the same stopped identities again after the dump. Only then does it
independently recompute the dump SHA-256 and `pg_restore --list` manifest using
the immutable PostgreSQL-tools image (no host PostgreSQL client is required),
create the bounded database reverse plan, and write the final pre-migration
admission record.
Service startup uses `--no-build --pull never --no-deps`; actual running image
IDs, loopback bindings, exact networks, health for both API instances, the
production smoke result, and final Sub2API identity are recorded afterward.

Every attempt has a private directory containing a status file and sanitized
evidence. A failure before writer freeze leaves the database and services
unchanged. A failure after writer freeze but before migration starts restores
only the exact prior API container IDs and running states; it never restores the
database. Once migration starts, a failure enters the bounded reverse plan: it
must stop both API writers and any one-off migration container successfully
before restoring the fresh frozen-window dump, then recreates the prior
immutable service images. A database restore is permitted only while no new API
has been re-exposed after the observed schema mutation. The current candidate
therefore fails closed immediately after verifying a real schema migration and
reverses while writers remain frozen; a future release must add an independently
verified controlled-traffic maintenance gate before migration cutover can be
enabled. When the source database is already at the signed head, application
replacement may proceed. Any later application rollback recreates the prior
images without restoring PostgreSQL, preserving writes accepted by the
same-schema candidate. Both recovery paths write a
mode-`0400`, no-replace execution receipt. If recovery or receipt publication
fails, the deployment lock is retained for manual review rather than silently
allowing another mutation. No path runs `alembic downgrade`.

When no schema change is required, both API instances start only after the
no-op migration command exits successfully and an independent revision check
proves the database is already at the signed packaged head. All root filesystems
are read-only, all Linux capabilities are dropped, resource and
PID limits are set, logs rotate, and public bindings default to `127.0.0.1`.
Cross-instance device/browser fanout and connection ownership use Redis, while
PostgreSQL retains durable command, cursor, and outbox state. Each instance keeps
`CONTROL_API_WORKERS=1`; the replica publishes `CONTROL_API_REPLICA_BIND_PORT`
(default `18093`). Update the `codex_control_device_api` upstream in
`http-context.conf` to that port before the first production deployment. Admit
the exact release only after deterministic cross-dispatch, browser fanout, load,
and kill/reconnect results are recorded in the version matrix.

Redis connection establishment and individual commands are bounded by
`CONTROL_REDIS_CONNECT_TIMEOUT_SECONDS` and
`CONTROL_REDIS_COMMAND_TIMEOUT_SECONDS` (both default to 3 seconds). PostgreSQL
pool acquisition, connection establishment, and commands are bounded
by `CONTROL_DATABASE_POOL_TIMEOUT_SECONDS` (3 seconds),
`CONTROL_DATABASE_CONNECT_TIMEOUT_SECONDS` (5 seconds), and
`CONTROL_DATABASE_COMMAND_TIMEOUT_SECONDS` (10 seconds). Control Sessions,
command history, and per-device connection history have explicit active or
retained record ceilings; crossing a non-prunable ceiling fails closed before
new durable state is appended. Browser event replay is bounded by
`CONTROL_BROWSER_EVENT_CATCHUP_MAX_BYTES` per page
(1 MiB by default). `CONTROL_BROWSER_MAX_CONNECTIONS_PER_SESSION` defaults to
four and `CONTROL_BROWSER_MAX_CONNECTIONS_PER_USER` defaults to eight across
all replicas. Each slot uses a 60-second renewable lease controlled by
`CONTROL_BROWSER_CONNECTION_LEASE_TTL_SECONDS` so a killed worker cannot
consume capacity permanently.

## Nginx integration

Review the upstream ports in the verified source root established before all
privileged actions, then install with absolute paths. A missing final
`source_root_verified=true` and `admission=true` result is a hard stop:

```sh
stage="$PACKAGE_ROOT/source"
sudo install -d -o root -g root -m 0755 /etc/nginx/codex
for file in http-context.conf server-locations.conf sub2api-logout-location.conf \
  browser-security-headers.conf api-security-headers.conf \
  hide-upstream-security-headers.conf; do
  sudo install -o root -g root -m 0644 "$stage/deploy/nginx/$file" \
    "/etc/nginx/codex/$file"
done
sudo "$stage/deploy/scripts/provision-nginx-access-log.sh"
```

The provisioner creates the dedicated directory
`/var/log/sub2api-codex-control` as `root:root` mode `0755` and
`nginx-access.log` inside it as `www-data:adm` mode `0640`. It validates and
installs the supplied policy at `/etc/logrotate.d/codex-control-access`, and
refuses unsafe directories, symlinks, or multiply linked targets. The policy
rotates daily or at 10 MiB, retains 14 compressed rotations, and signals only a
verified Nginx master with `USR1` after rotation so workers reopen the newly
created file. Run it before validating a configuration that names the dedicated
log. The launcher and Python helper independently reject a non-root-owned or
non-normalized staging tree and policy before touching the log or rotation
targets.

Include `http-context.conf` once inside the global `http` block and include
`server-locations.conf` inside the existing HTTPS `server` block:

```nginx
http {
    include /etc/nginx/codex/http-context.conf;

    server {
        listen 443 ssl http2;
        server_name control.example.com;
        include /etc/nginx/codex/server-locations.conf;
    }
}
```

The location policy overwrites forwarded client IP headers, strips the API
prefix, restricts browser WebSockets to the exact same Origin, limits body and
connection sizes, disables proxy buffering for upgrades, emits a CSP without
inline or third-party script permission, and returns `404` for any other
`/codex-ws/` route. Exact `/codex-ws` and a final `^~ /codex` guard also return
`404`; the guard ensures adjacent or malformed `/codex*` paths cannot fall back
to a host location and inherit its access-log format.
`server-locations.conf` includes `sub2api-logout-location.conf` once at server
context. The snippet contains exactly three directives: it raises the server's
proxy response-header buffer to `16k`, provides four `16k` response buffers,
and sets a `32k` busy-buffer ceiling. It therefore applies to every proxy
location in this HTTPS server, not only Sub2API logout. It does not define or
change locations, upstreams, forwarded headers, upgrade behavior, buffering
mode, cache policy, logging, or timeouts. Install the snippet before replacing
or reloading `server-locations.conf`; no additional host `server` include is
required.
`http-context.conf` defines `codex_control_json`. Every location in
`server-locations.conf` selects
`/var/log/sub2api-codex-control/nginx-access.log` with that format, overriding
an inherited host log that might otherwise record
`$request`, Referer, or User-Agent. Do not add another `access_log` inside these
locations: Nginx would write both logs and the second format could reintroduce
secret-bearing fields.
`CONTROL_TRUST_FORWARDED_FOR=true` is admitted only with this overwrite policy
and loopback-only published API port; otherwise leave it disabled.

Validate and reload atomically:

```sh
sudo nginx -t
sudo nginx -T | sed -n '/codex_control_api/,/codex_control_json/p'
sudo nginx -s reload
```

After the first request, verify ownership and exercise one rotation/reopen on a
maintenance host before admitting the configuration:

```sh
sudo stat -c '%U:%G %a %h %F' /var/log/sub2api-codex-control
sudo stat -c '%U:%G %a %h %F' /var/log/sub2api-codex-control/nginx-access.log
sudo logrotate --debug /etc/logrotate.d/codex-control-access
sudo logrotate --force /etc/logrotate.d/codex-control-access
curl --fail --silent --show-error https://control.example.com/codex-api/v1/health/live >/dev/null
sudo stat -c '%U:%G %a %h %F' /var/log/sub2api-codex-control/nginx-access.log
sudo tail -n 1 /var/log/sub2api-codex-control/nginx-access.log
```

The directory `stat` must report `root:root 755` and a non-symlink directory;
both file `stat` calls must report `www-data:adm 640 1 regular file`. The final
line must be JSON for `/codex-api/v1/health/live` with no query, Referer, or
User-Agent field. Treat a missing post-rotation line as a reopen failure.
This validation covers the dedicated access log only. Nginx can include a full
request target in `error_log` output on exceptional paths, so query parameters
must never carry credentials or reusable secrets and the host error log must be
access-restricted and rotated separately.

## Acceptance

Run the unauthenticated production smoke test first:

```sh
stage="$PACKAGE_ROOT/source"
/usr/bin/python3 -I "$stage/tests/e2e/smoke.py" \
  --base-url https://control.example.com \
  --expect-secure-cookie
```

For the authenticated path, use a private short-lived token file and bind the
expected identity explicitly:

```bash
/usr/bin/python3 -I "$stage/tests/e2e/smoke.py" \
  --base-url https://control.example.com \
  --access-token-file /secure/fixtures/smoke-access \
  --expected-user-id smoke-fixture-user-id \
  --expect-secure-cookie
```

Also confirm:

- the final Sub2API runtime attestation reports `immutable-image-v1`, the exact
  `0.1.178` manifest/image ID/PID 1 binary, no writable-layer drift, and the
  locked `sub2api-auth.v0.1.178.json` digest with fresh identity-bound auth
  evidence; a banner or smoke response alone is insufficient;
- `docker inspect` shows no raw Sub2API key, database password, Redis password,
  or session HMAC value in Compose environment metadata.
- Only the intended loopback ports were added on the server.
- An unauthenticated user cannot enumerate devices, sessions, or commands.
- Unknown and dangerous RPC-shaped HTTP paths return `404`.
- Stopping a Connector leaves the ordinary Codex app and CLI unchanged.

The disposable full-stack test requires Go 1.24 or newer in addition to Docker
and `openssl`; production hosts do not need Go unless they run this harness.
`tests/e2e/run-local.sh` creates a unique external Docker network, an
administrator-initialized PostgreSQL instance, a dedicated non-superuser
Control role/database, a dedicated Redis ACL namespace, mock Sub2API authority,
two API instances, the PWA, and a TLS edge. It builds and starts the real
Connector against a protocol-faithful fake Codex app-server; exercises pairing,
all eight admitted RPC classes, approval, cross-instance device dispatch/live
browser fanout, API-replica kill/reconnect, and revocation. It also checks live
PostgreSQL migration guards, protected metrics, actual `/proc` TCP listeners,
structured Nginx routing logs, query-string redaction, secret/token absence,
and a checksummed backup restored into a disposable database at Alembic head.
The environment is destroyed on exit, while a mode-`0600` machine-readable
report remains under `tests/e2e/reports/`. The report states explicitly that
the Connector is real but Codex and Sub2API are fixtures. Preserve a passing
report plus release artifact digests; the script itself is only coverage.

## Appendix A: Historical source staging (development only)

The following `source.tar.gz` procedure is retained solely to explain the former
bootstrap and for isolated development inspection. It is not a formal public
release, installation, upgrade, rollback, or production-admission route. Do not
use its `ACTIVE_SOURCE` pointer or directly invoke scripts from that tree on a
production host.

Before any command below uses root privileges, a Docker socket, or a production
credential, establish one immutable source root from the reviewed release
bundle. Never execute a privileged command from a working checkout. The
independently installed verifier and every directory above it must already be
root-owned and not group or world writable; its digest must match the approved
out-of-band release record. Run the complete preparation in one root shell so
root-only path checks and expansions do not happen in the invoking user's
shell:

```sh
sudo /bin/sh -eu <<'ROOT_STAGE'
unset PYTHONHOME PYTHONPATH
export PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C
bundle=/secure/codex-control/release-bundle
trusted_verifier=/secure/codex-control/tools/verify-unsigned-bootstrap-bundle.py
approved_verifier_sha256='REPLACE_WITH_APPROVED_64_HEX_SHA256'
approved_bundle_closure_sha256='REPLACE_WITH_APPROVED_64_HEX_SHA256'
stage_root=/opt/sub2api-control

for approved in "$approved_verifier_sha256" "$approved_bundle_closure_sha256"; do
  case "$approved" in *[!0-9a-f]*|'') exit 1 ;; esac
  [ "${#approved}" -eq 64 ] || exit 1
done

check_directory_chain() {
  current=$1
  while :; do
    value=$(/usr/bin/stat -c '%u:%g:%a:%F' "$current")
    case "$value" in
      0:0:*:directory) ;;
      *) echo "untrusted directory: $current" >&2; exit 1 ;;
    esac
    mode=${value#0:0:}; mode=${mode%:directory}
    [ $((0$mode & 022)) -eq 0 ] || exit 1
    [ "$current" = / ] && break
    current=$(/usr/bin/dirname -- "$current")
  done
}

check_directory_chain "$bundle"
check_directory_chain "$(/usr/bin/dirname -- "$trusted_verifier")"
check_directory_chain /opt
[ "$(/usr/bin/readlink -e -- "$bundle")" = "$bundle" ]
[ "$(/usr/bin/readlink -e -- "$trusted_verifier")" = "$trusted_verifier" ]
[ "$(/usr/bin/stat -c '%u:%g:%a:%h:%F' "$trusted_verifier")" = \
  '0:0:555:1:regular file' ]
[ "$(/usr/bin/sha256sum "$trusted_verifier" | /usr/bin/cut -d' ' -f1)" = \
  "$approved_verifier_sha256" ]
[ "$(/usr/bin/sha256sum "$bundle/SHA256SUMS" | /usr/bin/cut -d' ' -f1)" = \
  "$approved_bundle_closure_sha256" ]
/usr/bin/python3 -I "$trusted_verifier" verify-archive --bundle "$bundle" \
  --bundle-trust-anchor / \
  | /usr/bin/tee /root/sub2api-control-archive-verification.json
/usr/bin/python3 -I -c '
import json,sys
value=json.load(open(sys.argv[1], encoding="utf-8"))
assert value["admission"] is False
assert value["source_root_verified"] is False
assert value["status"] == "archive-verified-non-admission"
' /root/sub2api-control-archive-verification.json

[ "$(/usr/bin/stat -c '%u:%g:%a:%F' "$stage_root" 2>/dev/null || true)" = \
  '0:0:755:directory' ] || [ ! -e "$stage_root" ]
revision=$(/usr/bin/python3 -I -c '
import json,sys
print(json.load(open(sys.argv[1], encoding="utf-8"))["vcs_ref"])
' /root/sub2api-control-archive-verification.json)
case "$revision" in
  *[!0-9a-f]*|'') exit 1 ;;
esac
stage_parent="$stage_root/$revision"
stage="$stage_parent/source"
[ ! -e "$stage_parent" ]
/usr/bin/install -d -o root -g root -m 0755 "$stage_root"
/usr/bin/install -d -o root -g root -m 0755 "$stage_parent"
/usr/bin/install -d -o root -g root -m 0755 "$stage"
/usr/bin/tar --extract --gzip --file "$bundle/source.tar.gz" \
  --directory "$stage" --no-same-owner
/usr/bin/chown -R root:root "$stage"
/usr/bin/find "$stage" -type d -exec /usr/bin/chmod 0555 {} +
# Archive file modes are canonical 0444/0555 and are rechecked below.
/usr/bin/python3 -I "$trusted_verifier" verify \
  --bundle "$bundle" --bundle-trust-anchor / --source-root "$stage" \
  | /usr/bin/tee /root/sub2api-control-source-verification.json
/usr/bin/python3 -I -c '
import json,sys
value=json.load(open(sys.argv[1], encoding="utf-8"))
assert value["admission"] is True
assert value["source_root_verified"] is True
assert value["status"] == "verified"
' /root/sub2api-control-source-verification.json
pointer_tmp=/root/sub2api-control-ACTIVE_SOURCE.tmp
/usr/bin/printf '%s\n' "$stage" > "$pointer_tmp"
/usr/bin/chown root:root "$pointer_tmp"
/usr/bin/chmod 0400 "$pointer_tmp"
/usr/bin/install -o root -g root -m 0444 "$pointer_tmp" \
  "$stage_root/ACTIVE_SOURCE"
/usr/bin/rm -f "$pointer_tmp"
[ "$(/usr/bin/stat -c '%u:%g:%a:%h:%F' "$stage_root/ACTIVE_SOURCE")" = \
  '0:0:444:1:regular file' ]
[ "$(/usr/bin/readlink -e -- "$stage_root/ACTIVE_SOURCE")" = \
  "$stage_root/ACTIVE_SOURCE" ]
pointer_value=$(/usr/bin/python3 -I - "$stage_root/ACTIVE_SOURCE" <<'PY'
import os
import sys

path = sys.argv[1]
flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
descriptor = os.open(path, flags)
try:
    raw = os.read(descriptor, 4097)
    if os.read(descriptor, 1):
        raise SystemExit(1)
finally:
    os.close(descriptor)
if not raw.endswith(b"\n") or raw.count(b"\n") != 1 or b"\r" in raw or b"\0" in raw:
    raise SystemExit(1)
value = raw[:-1].decode("ascii")
if not value.startswith("/opt/sub2api-control/") or not value.endswith("/source"):
    raise SystemExit(1)
print(value)
PY
)
[ "$pointer_value" = "$stage" ]
/usr/bin/python3 -I "$trusted_verifier" verify \
  --bundle "$bundle" --bundle-trust-anchor / --source-root "$stage" \
  > /root/sub2api-control-source-verification-final.json
/usr/bin/python3 -I -c '
import json,sys
value=json.load(open(sys.argv[1], encoding="utf-8"))
assert value["admission"] is True
assert value["source_root_verified"] is True
assert value["status"] == "verified"
' /root/sub2api-control-source-verification-final.json
ROOT_STAGE
```

Every remaining command uses the literal absolute `stage` admitted above and
recorded in the root-owned, mode-`0444`
`/opt/sub2api-control/ACTIVE_SOURCE` file only after final source admission. Its
value is exactly `/opt/sub2api-control/<vcs_ref>/source`. Never
reuse or overwrite a prior revision directory. Public source files are traversable but read-only; secrets, `.env`,
deployment records, backup data, and release evidence remain in their separate
private paths. A bundle-only `verify-archive` result is explicitly non-admitting
and must never authorize a production command.

Before leaving `ROOT_STAGE`, require the pointer to remain a root-owned,
mode-`0444`, single-link regular file with one canonical newline-delimited value
equal to the literal `stage` already admitted above; re-run `verify
--source-root "$stage"` after that comparison. Export or transcribe that exact
absolute `/opt/sub2api-control/<64-hex-vcs-ref>/source` path for the later
commands. Do not re-read `ACTIVE_SOURCE` between verification and execution,
and do not execute a launcher, helper, or policy from an ordinary checkout.
The verifier's source-root gate checks the source root, every member, and every
ancestor from `/` to the source root for root ownership, normalized read-only
modes, no symlink, and no group/world write bit.
