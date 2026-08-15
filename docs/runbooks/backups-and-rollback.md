# Backups and rollback

## Backup policy

The Control PostgreSQL database is authoritative for sessions, device
ownership, commands, approvals, thread bindings, event history, and audit
records. Back it up independently from the Sub2API database. Redis contains
short-lived coordination and rate-limit state; persistence is useful for
continuity but is not a substitute for PostgreSQL backup.

Minimum schedule:

- PostgreSQL custom-format dump every 6 hours into encrypted-at-rest storage;
- daily encrypted off-host copy with immutable retention;
- 30 daily and 12 monthly recovery points, adjusted to policy;
- quarterly restore rehearsal into an isolated database;
- immediate backup before every schema migration or secret rotation.

Create a backup with the `ops` profile. The host directory must exist and be
writable by the image's `postgres` user:

```sh
cd deploy/docker-compose
sudo install -d -o 70 -g 70 -m 0700 backups
docker compose --env-file .env -f compose.yaml --profile ops \
  run --rm control-backup
```

If the image's `postgres` UID/GID differs, set `CONTROL_BACKUP_UID_GID` and make
the host directory owned by the same numeric pair before running the job.
For production, set `CONTROL_BACKUP_DIR` to an encrypted path outside the source
checkout; the in-repository directory is only a Git-ignored local staging area.

Each run writes an unencrypted custom-format dump, a `pg_restore --list`
manifest, and a SHA-256 file with mode `0600`. The destination filesystem must
provide encryption at rest; additionally encrypt the artifact before any
off-host transfer unless the transport and destination provide an equivalent
approved envelope. Never place dumps in a public object-store prefix; audit and
identity records are sensitive even though raw Sub2API keys are forbidden.
The job syncs all three temporary files before rename, then syncs the final files
and containing filesystem before reporting success. Production admission reads
the artifacts relative to one no-follow directory descriptor, streams the dump
hash, bounds metadata reads, and gives the same inherited dump descriptor to
`pg_restore`; pathname replacement cannot substitute a different artifact.

Verify every scheduled run by checking the checksum, parsing the manifest, and
alerting on age. A restore rehearsal must run migrations and the smoke test
against the restored database, not merely execute `pg_restore --list`.

The disposable local rehearsal is available independently:

```sh
tests/e2e/run-backup-restore.sh
```

It provisions a dedicated role/database, inserts a sentinel, creates the
custom-format dump, verifies its manifest and checksum, restores into a fresh
randomly named database, runs migrations to packaged Alembic head, compares
core table/row snapshots and ownership/ACLs, then runs the release Control API
image against that restored database through readiness, session exchange,
session read, bootstrap, and logout before dropping the restore database.
The full `tests/e2e/run-local.sh` acceptance run invokes the same helper after
real Connector traffic has populated the source database.

## Pre-release checkpoint

There are two required checkpoints. Before any datastore provision, Nginx
change, authentication probe, or deployment wrapper, run
`deploy/scripts/backup-production-state.py` as described in
[deployment.md](deployment.md#mandatory-pre-mutation-snapshot). It captures the
existing Sub2API PostgreSQL and Redis state, host data/config/Compose/environment
files, mutable runtime binaries, full Docker inspection evidence, Nginx config,
and TLS recovery material. It creates a timestamped mode-`0700` snapshot and
`READY.json` only after the PostgreSQL, Redis, tar, procfs, TLS, and SHA-256
checks all pass. Existing Control data is included when the database exists;
absence on a first deployment is recorded rather than mistaken for a backup.

`deploy/scripts/deploy-production.sh` creates a fresh full snapshot again before
its authentication probe. For the narrower Control PostgreSQL checkpoint, it
first records a bounded unfreeze plan containing the exact current writer
container IDs and states, stops both API writers, and captures their image,
start-time, and restart-count evidence. It then creates exactly one new Control
dump and captures the stopped identities again. A changed ID, image, start time,
restart count, or running state rejects the no-write window. The migration gate
also validates private file/directory modes, recomputes the dump SHA-256, and
reproduces its stored table-of-contents with `pg_restore --list`. When the host
has no PostgreSQL client, the dump descriptor is streamed to `pg_restore` in the
immutable PostgreSQL-tools image with no network. The production Compose overlay
requires that image by immutable digest and removes its local build definition.
The earlier live-isolation receipt also proves the dedicated Redis ACL, rejects
every enabled `nopass` user, and requires a credentialless `PING` to return
`NOAUTH`. An anonymous Redis baseline cannot enter the writer-freeze or migration
window. Provision and persist the ACL boundary under a separate authorized
maintenance change, then create a fresh snapshot before invoking the wrapper.

The resulting mode-`0600` admission record includes:

- current API, PWA, and PostgreSQL backup-tools image digests and OCI identity;
- signed release values, source commit, migration head, and release-file hash;
- resolved production Compose hash;
- `alembic current` revision and target revision;
- PostgreSQL backup path, size, checksum, and manifest hash;
- exact pre-freeze writer identities, pre/post-backup stopped-state hashes, the
  no-database-restore unfreeze plan, and the bounded reverse-plan hash;
- full production backup, isolated restore, PostgreSQL/Redis live-isolation,
  and writer-freeze receipt hashes;
- Sub2API runtime, mount, OCI, binary, and authentication evidence;
- production smoke-input identity/hash and, after deployment, running container
  identity plus the smoke-output hash.

It also binds the signed release source commit and signed migration head to the
head packaged inside the admitted API image, and records the Sub2API container
ID, image ID/digest, binary hash, OCI tuple, mount policy, and authentication
fixture digest. Keep the record next to the backup in encrypted,
access-controlled storage outside the source checkout.

If a failure occurs after writers stop but before migration starts, the wrapper
starts only the exact previously running container IDs and proves the old IDs,
images, start timestamps, restart counts, and states before releasing the lock.
It does not restore PostgreSQL in this branch. After migration starts, database
restore is allowed only if the reverse path proves both API writers and every
one-off migration container stopped and proves that no new API was exposed after
the schema mutation. The current candidate deliberately rejects a migrated
cutover before starting an API and reverses under that frozen boundary until a
controlled-traffic maintenance gate exists. For a same-schema application
replacement, rollback recreates the prior images without restoring PostgreSQL,
so candidate-era user writes are retained. Failure to freeze all mutators skips
the restore. A failed or skipped restore never restarts the prior API images.
Either case records a failed no-replace recovery receipt and retains the
deployment lock for review.

If the internal deployment returns success but lifecycle cannot commit the
activation pointer or terminal lifecycle receipt, lifecycle reacquires the same
production deployment lock and invokes the signed post-success bounded-reverse
interface against that exact deployment directory. Only a same-schema deployed
record is eligible: the prior application images are recreated without a
database restore, so writes accepted after deployment are preserved. The
terminal mode-`0400` reverse receipt binds the original reverse plan and the
no-replace post-success admission. Success releases the production lock before
lifecycle restores the prior activation; any admission, reverse, verification,
or receipt failure retains the lock for operator review.

The formal uninstall path is a separate authenticated bounded operation, not a
Compose project teardown. Lifecycle must bind the current activation-installed
package to one exact successful `deployment.json`, then invoke that signed
package's internal uninstall interface. The operation removes only the three
terminal-record container IDs and the exact isolated PWA network after proving
that no migration, backup, or other one-off project container remains. Its
mode-`0400`, no-replace plan and execution receipts bind the active package,
deployment record, container IDs, image IDs, Compose labels, network ID, and
post-removal absence checks. Drift or partial removal retains both locks and
prevents lifecycle from deleting activation or package trees.

Uninstall does not restore or remove PostgreSQL or Redis, and it preserves
Sub2API, application data, secrets, backups, deployment records, lifecycle
records, container images, and Connector user state. It also preserves Nginx
configuration and logrotate policy: those are shared host integration in this
release and are not owned by the server package. Removing them requires a
separately authenticated ownership and restoration plan.

The comprehensive snapshot contains raw database and Redis data, environment
files, Docker inspect output, and TLS private keys. It must remain root-only and
encrypted at rest. Copy it to the encrypted off-host recovery location and
verify `manifest.sha256` there before accepting a destructive cutover step.

Do not start a migration unless the previous application can tolerate the new
schema or a tested restore window is available. Destructive column/table
changes require an expand-migrate-contract sequence across separate releases.

## Application rollback

1. Stop rollout and preserve logs, request IDs, and the failed image digest.
2. Use only the current activation-installed package's lifecycle rollback
   wrapper. It selects the one recorded previous release and authenticates the
   installed package, prior activation, deployment evidence, and bounded reverse
   result. Do not select old image digests manually or invoke Compose directly:

```sh
ACTIVE_PACKAGE_ROOT=/opt/sub2api-codex-control/releases/REPLACE_WITH_ACTIVE_RELEASE_ID
OPERATOR_ENV=/secure/codex-control/operator.env

sudo "$ACTIVE_PACKAGE_ROOT/bin/sub2api-control-rollback" \
  --operator-env-file "$OPERATOR_ENV" \
  --deployment-timeout-seconds 1800
```

The rollback wrapper is package-internally constrained to `--pull never` and a
bounded reverse plan. A same-schema application rollback preserves PostgreSQL
and therefore preserves writes accepted after activation. A migration-bearing
deployment cannot reach successful activation under the current formal gate; it
fails and reverses while writers remain frozen. No rollback path runs an
implicit Alembic downgrade.

The current session generation stores lookup digests under the fixed
`control-session-v2` purpose; the pre-AEAD image uses `control-session`. Neither
generation falls back to the other's purpose. Consequently, a prior image
cannot resolve sessions issued by the current image, and the current image
cannot resolve legacy sessions. Do not add a compatibility fallback or rewrite
session hashes during rollback. Browsers that crossed the image boundary must
perform a fresh Sub2API exchange. A client that never reached the newer image
can still hold a same-generation legacy cookie; when an incident requires a
global logout rather than generation isolation, explicitly revoke all session
rows or rotate the session secret.

3. Restore the previous Nginx files only if routing changed, then run
   `nginx -t` before reload.
4. Run the unauthenticated smoke test, authenticated session exchange, device
   reconnect, command idempotency, and approval-expiry checks.

Do not run `alembic downgrade` by default. A downgrade is allowed only when the
specific revision has a reviewed downgrade path and was restored successfully
in rehearsal.

## Database restore

A database restore is destructive and requires an announced write freeze.
Revoke or stop API writers, retain the failed database under a new name, then
create a fresh empty database with the same private database boundary:

```sql
CREATE DATABASE codex_control_restore OWNER codex_control;
REVOKE ALL ON DATABASE codex_control_restore FROM PUBLIC;
GRANT CONNECT, TEMPORARY ON DATABASE codex_control_restore TO codex_control;
```

Restore while connected as a PostgreSQL administrator that may `SET ROLE` to
`codex_control`:

```sh
pg_restore \
  --exit-on-error \
  --no-owner \
  --no-acl \
  --role=codex_control \
  --dbname=codex_control_restore \
  /secure/path/codex-control-TIMESTAMP.dump
```

Because the backup deliberately uses `--no-acl`, reassert the private schema
boundary after restore:

```sql
-- Run in codex_control_restore as a PostgreSQL administrator.
ALTER SCHEMA public OWNER TO codex_control;
REVOKE ALL ON SCHEMA public FROM PUBLIC;
GRANT USAGE, CREATE ON SCHEMA public TO codex_control;
```

Before admitting a canary, verify that `codex_control` owns the database,
schema, tables, sequences, and migration objects; that `PUBLIC` has neither
database `CONNECT`/`TEMPORARY` nor schema privileges; and that the application
role can connect and run the Alembic and core-table queries. For example, the
database-owner and public-ACL checks can be inspected from the administrator
database with:

```sql
SELECT datname, pg_get_userbyid(datdba) AS owner, datacl
FROM pg_database
WHERE datname = 'codex_control_restore';
```

Point a single canary API instance at the restored database, verify migration
revision and row counts, then run the full smoke suite. Cut over only after the
canary succeeds. Keep the failed database and incident evidence until review is
complete.

## Secret rotation

Rotate one dependency at a time:

1. Create a second PostgreSQL or Redis credential with the same restricted
   privileges, or update the password during a maintenance window.
2. Write the new value to a new mode-`0600` file and atomically replace the
   Compose secret source.
3. Recreate API and migration containers; verify readiness and session flow.
4. Revoke the old credential after all old containers have exited.

Rotating `control_session_hmac_secret` invalidates every digest derived from it:
Control sessions and CSRF tokens, active pairing codes and poll tokens, device
refresh credentials, and unconsumed short-lived device access tokens. It also
changes the derived internal metrics bearer token. Treat this as a user-visible
logout plus mandatory Connector re-pairing, and update trusted scrapers at the
same time. Device Ed25519 key files and Codex configuration or credentials
remain untouched.

Production configuration admission and the container entrypoint reject the
published development, test, and `.env.example` placeholder values. Generate a
fresh random file-backed value; never make a blocked placeholder pass by padding
or changing its letter case.

## Connector rollback

Connector releases are independent of the server image rollback. Retain the
last signed binary, stop only the Connector process, atomically restore that
binary, verify its signature and version, and start it with the unchanged
private config/state directory. Never roll back by restoring or rewriting the
user's Codex `config.toml`, provider, auth, or plugin files.
