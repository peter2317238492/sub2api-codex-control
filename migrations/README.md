# Database migrations

The Control API owns these tables and must use an independent PostgreSQL role
and database (or schema) from Sub2API. The role must not have access to Sub2API
authentication tables.

From the repository root:

```bash
CONTROL_DATABASE_URL='postgresql+asyncpg://...' \
  alembic -c migrations/alembic.ini upgrade head
```

Generate migrations only after importing all models through `migrations/env.py`.
Review generated revisions before deployment, especially destructive changes and
JSONB or enum conversions.

Revision `20260713_0003` must run while device dispatch is quiesced. Before an
upgrade from `0002`, stop Control API workers and Connectors, then verify:

```sql
SELECT count(*)
FROM devices
WHERE last_server_sequence <> last_server_acked_sequence;
```

The result must be zero. The migration raises and rolls back otherwise because
the old Redis-only payloads cannot be reconstructed into the PostgreSQL outbox.
A downgrade has the same cursor guard and also rejects any `device_outbox` row
whose `acked_at` is null. Do not bypass either guard; drain acknowledgements or
restore the matching application revision first.

The live PostgreSQL guard regression can be run against an isolated test
database with:

```bash
CONTROL_TEST_POSTGRES_DSN='postgresql://user:password@host/database' \
  pytest apps/control-api/tests/test_postgres_migration_guards.py
```

The test creates and drops a uniquely named schema; never point it at a role
that cannot create isolated schemas.

Revision `20260723_0004` adds a commit-ordered signed-bigint browser cursor per
owner. Existing `event_log.id` values are preserved as the initial owner
cursors, so deployed browser cursors remain valid. Cursor allocation stops
before `2^63`; it never wraps or reuses a value. Event pruning advances the
owner's durable `minimum_resume_cursor` while holding the same owner row lock
used by catch-up. Browsers presenting a pruned or future cursor are closed with
WebSocket code `4409` and must call `/v1/bootstrap`; malformed, negative, or
out-of-int64 cursors are closed with `4400`.

Revision `20260723_0005` adds the composite indexes used by bounded
terminal-state retention and converts audit actor session/device references to
immutable historical soft IDs. Apply it with ordinary Control API workers quiesced
so PostgreSQL can build the indexes without competing with command, approval,
or connection writes. Its downgrade removes only those indexes; it never
deletes retained control or audit rows. Its downgrade refuses to restore the
old `ON DELETE SET NULL` foreign keys after retention has created any historical
orphan ID. Retention eligibility and defaults are defined in
`docs/adr/0004-control-data-retention.md`.

Revision `20260730_0006` adds the composite approval index used by the bounded
undispatched-decision reconciliation scan. Apply it with ordinary Control API
workers quiesced. The downgrade removes only that index and does not mutate
approval decisions, audit evidence, or browser events.

Revision `20260730_0007` switches pairing credential delivery to retry-safe
protocol v2. Apply it with Control API workers and Connectors quiesced. Before
upgrading, verify that no protocol-v1 pairing is live:

```sql
SELECT count(*)
FROM device_pairings
WHERE status IN ('pending', 'claimed');
```

The result must be zero. The migration deliberately raises and rolls back for
any pending or claimed v1 pairing because its raw, server-generated credential
cannot be reconstructed under the Connector-generated commitment protocol.
Let those attempts finish or expire under the old application before retrying;
do not bypass the guard.

The revision adds pairing proof/commitment metadata and an explicit device
credential scheme, and changes public-key uniqueness so only an active Device
holds a key while revoked history remains retained. Its downgrade refuses to
remove the v2 columns while any protocol-v2 pairing or v2 device credential
exists, or when retained device rows could not satisfy the old global public-key
constraint. Restore the matching application revision or retire that v2 state
through supported lifecycle and retention paths before downgrade.

Revision `20260731_0008` binds each approval ID to a canonical SHA-256 hash of
the complete device request. A replay with the same ID but different command,
kind, summary, details, or expiry is rejected before any decision is reused.
Historical approvals receive an all-zero sentinel during migration because the
discarded details of default-deny rows cannot be reconstructed; that sentinel
is never generated for a new request, so historical rows fail closed on replay.
