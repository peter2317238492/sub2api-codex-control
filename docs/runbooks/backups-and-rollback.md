# Backups and rollback

## Recovery policy

The Control PostgreSQL database is authoritative for sessions, devices,
commands, approvals, managed threads, event history, and audit records. Back it
up independently of the Sub2API database. Redis contains short-lived
coordination and rate-limit state; persistence helps continuity but does not
replace PostgreSQL recovery.

Store recovery material encrypted at rest outside the source checkout. Apply a
schedule appropriate to the operator's recovery objectives, retain an encrypted
off-host copy, alert on age and checksum failures, and rehearse restore into an
isolated environment. A dump that only passes `pg_restore --list` is not a
complete restore rehearsal.

## Change-window checkpoint

Use one coordinated change window and avoid duplicate snapshots of unchanged
state. The future signed deployment entry point records:

1. one comprehensive pre-change recovery point covering Sub2API and Control
   PostgreSQL state, required Redis persistence/ACL metadata, private host
   integration, Nginx configuration, and release/deployment identity;
2. one narrow Control PostgreSQL dump at the actual migration boundary.

The second record protects the immediately pre-migration Control schema; it is
not a duplicate of the broader host recovery point. Do not separately run the
same full-snapshot tool immediately before the deployment wrapper. Never
overwrite a ready record or claim an old recovery point belongs to a new state.

Every ready recovery record must bind immutable artifact identities, contain a
complete checksum manifest, be mode-restricted, and be copied to protected
off-host storage. If state changed after capture, the attempt partially
mutated services, or validation is incomplete, start a new identified change
window and capture new evidence.

## Scheduled Control database backup

The `control-backup` Compose profile writes a PostgreSQL custom-format dump,
`pg_restore --list` manifest, and SHA-256 record through temporary files and
atomic rename. Production must use the signed PostgreSQL-tools image by digest
and an encrypted host destination outside the checkout. The directory owner
must match the image's configured backup UID/GID.

For every scheduled run:

- recompute the dump checksum;
- reproduce and compare the table-of-contents;
- check age, ownership, mode, hard-link count, and expected directory identity;
- copy the encrypted artifact off host;
- periodically restore into a fresh private database, run migrations, compare
  core records and ACLs, and execute session and logout checks.

The isolated `tests/e2e/run-backup-restore.sh` exercises the repository's
backup/restore path with disposable infrastructure. It is development evidence,
not proof that an operator's production recovery storage works.

## Application rollback

1. Stop the rollout and preserve logs, request IDs, deployment records, and
   exact failed artifact identities.
2. Confirm the database schema remains compatible with the prior admitted API.
3. Restore only the prior signed image digests; do not run an older migration
   image against a newer schema.
4. Restore Nginx files only when routing changed, test the complete
   configuration, then reload and verify log reopen.
5. Repeat authenticated HTTP, browser/device WSS, Connector, approval,
   idempotency, reconnect, revocation, logout, and monitoring checks.

Do not run an Alembic downgrade by default. A downgrade is allowed only when
that exact revision has a reviewed downgrade path and a successful isolated
restore rehearsal.

## Database restore

A restore is destructive. Announce a write freeze, stop API writers, retain the
failed database under a separate name, and restore into a fresh private
database owned by the dedicated Control role. Reassert that `PUBLIC` has no
database or schema privileges and that the application role owns the schema,
tables, sequences, and migration objects.

Before cutover, verify checksums, migration revision, core row counts and
constraints, database/schema ownership, negative access to the Sub2API
database, readiness, session exchange, pairing, WSS, and logout through a
single canary API. Keep the failed database and incident evidence until review
is complete.

## Secret rotation

Rotate one dependency at a time. Write the new value to a new private file,
atomically replace the Compose secret source, recreate only affected services,
verify the complete auth and WSS path, and revoke the old credential only after
old containers have exited.

Rotating the Control session HMAC invalidates Control sessions, CSRF state,
pairing and poll credentials, device refresh credentials, and unconsumed device
access tokens. It also changes the derived internal metrics token. Treat this
as a user-visible logout and mandatory Connector re-pairing. It must not modify
Codex configuration or credentials.

## Connector rollback

Connector rollback is independent of server rollback. Retain the last admitted
binary, stop only the ordinary user's Connector, verify the old artifact and
platform signature again, atomically restore it, and restart it with the
unchanged private configuration and state directory. Never roll back by
rewriting Codex account, provider, plugin, auth, or configuration files.
