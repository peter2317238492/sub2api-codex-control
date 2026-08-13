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
its authentication probe and then creates the narrower Control PostgreSQL
checkpoint immediately before migration. It will not run a migration unless it
can identify exactly one new Control dump from the current admission window,
validate private file/directory modes, recompute its SHA-256, and reproduce its
stored table-of-contents with `pg_restore --list`. When the host has no
PostgreSQL client, the dump descriptor is streamed to `pg_restore` in the
immutable PostgreSQL-tools image with no network. The production Compose overlay
requires that image by immutable digest and removes its local build definition.

The resulting mode-`0600` admission record includes:

- current API, PWA, and PostgreSQL backup-tools image digests and OCI identity;
- signed release values, source commit, migration head, and release-file hash;
- resolved production Compose hash;
- `alembic current` revision and target revision;
- PostgreSQL backup path, size, checksum, and manifest hash;
- Sub2API runtime, mount, OCI, binary, and authentication evidence;
- production smoke-input identity/hash and, after deployment, running container
  identity plus the smoke-output hash.

It also binds the signed release source commit and signed migration head to the
head packaged inside the admitted API image, and records the Sub2API container
ID, image ID/digest, binary hash, OCI tuple, mount policy, and authentication
fixture digest. Keep the record next to the backup in encrypted,
access-controlled storage outside the source checkout.

The comprehensive snapshot contains raw database and Redis data, environment
files, Docker inspect output, and TLS private keys. It must remain root-only and
encrypted at rest. Copy it to the encrypted off-host recovery location and
verify `manifest.sha256` there before accepting a destructive cutover step.

Do not start a migration unless the previous application can tolerate the new
schema or a tested restore window is available. Destructive column/table
changes require an expand-migrate-contract sequence across separate releases.

## Application rollback

1. Stop rollout and preserve logs, request IDs, and the failed image digest.
2. If the schema remains backward compatible, set the prior immutable API and
   PWA image digests in `.env` and run:

```sh
docker compose --env-file .env -f compose.yaml up -d --no-build --no-deps control-api codex-pwa
```

`--no-deps` is mandatory here: `control-api` depends on `control-migrate`, and
rolling an application image back must never execute an older migration image
against the newer database. Re-enable normal dependency startup only after the
schema compatibility check and rollback rehearsal have passed.

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

## Connector rollback

Connector releases are independent of the server image rollback. Retain the
last signed binary, stop only the Connector process, atomically restore that
binary, verify its signature and version, and start it with the unchanged
private config/state directory. Never roll back by restoring or rewriting the
user's Codex `config.toml`, provider, auth, or plugin files.
