# ADR 0004: Bound control-plane data retention

- Status: Accepted
- Date: 2026-07-23

## Context

ADR 0003 requires explicit retention for session, pairing, command, approval,
and audit records. Browser events and the durable device outbox already have
separate bounded policies, but the remaining control tables otherwise grow for
the lifetime of the deployment. Several of these rows contain token hashes,
remote-control parameters, approval details, or thread snapshots.

Deletion must not break idempotency while a command is live, discard an
undelivered approval decision, remove a resumable device frame, or erase state
that an active connection or turn still relies on.

## Decision

The singleton state-sweep lease also owns retention. Each run deletes at most
`CONTROL_RETENTION_SWEEP_BATCH_SIZE` rows from each eligible table and commits
one table at a time. A failed batch is retried by a later lease holder. The
default windows are:

| Table | Default window | Eligibility after the window |
|---|---:|---|
| `control_sessions` | 7 days | expired, and any revocation is also older than the window |
| `device_pairings` | 7 days | status is completed, expired, or cancelled, and pairing expiry is older than the window |
| `device_connections` | 30 days | explicitly disconnected with a terminal timestamp |
| `commands` | 30 days | terminal with `completed_at`, no approval reference, and no unacknowledged device outbox frame |
| `approvals` | 30 days | decided and dispatched, or an explicit non-dispatchable default denial, and no unacknowledged device outbox frame |
| `thread_bindings` | 90 days | closed/stale, no active turn, command, retained event, unresolved approval, or unacknowledged frame |
| `devices` | 365 days | revoked, credentials and live identity cleared, sequences fully acknowledged, and no retained dependent control state |
| `audit_events` | 365 days | event timestamp is older than the window |

All windows and the batch size are configurable but have validated lower and
upper bounds. Terminal rows with missing terminal timestamps are preserved as
inconsistent security state for operator investigation. Active, pending,
undispatched, and unacknowledged records are never aged away. In particular,
retention never deletes a pending or claimed pairing directly: the bounded
pairing-expiry sweep first locks and transitions it to explicit `expired` state
with audit evidence. A completed pairing remains poll-replayable throughout its
retention window. After its row is removed, only the exact signed v2 start
intent may reconstruct completed state, and only when its fixed Device ID,
public key, and refresh-credential digest still match an active Device.

Admission also enforces hard active and retained Control Session ceilings per
owner, retained command ceilings per device and owner, approval ceilings per
device and owner, and thread-binding ceilings per owner. Pairing starts have
global and source-specific live/retained ceilings. Device connection history is
pruned to a fixed per-device ceiling using only the oldest disconnected rows.
A request that would cross a non-prunable ceiling fails before it can append
new durable control state.
Default-denied approvals retain only the minimum terminal reason and identity
needed for audit and reconciliation. Safe explicit thread archival releases
active bootstrap capacity only when the thread is idle or failed and has no
active turn, outstanding command, pending approval, or unacknowledged device
frame; archival never shortens the configured retention window.

Terminal approval decisions are committed with their audit and browser events
before Redis notifications are attempted. The singleton sweep periodically
re-wakes current-epoch terminal decisions whose durable dispatch timestamp is
still null, so a transient Redis failure cannot strand user intent. Explicit
non-dispatchable default denials, including device revocation, remain directly
eligible for ordinary retention after their configured window.

Audit events are append-only and immutable during their retention window. No
HTTP API can update or delete them. Age-based deletion by the singleton
retention worker is the sole mutation exception; it emits only aggregate
operational counts, not a replacement audit event, to avoid recursive growth.
Encrypted off-host backups retain audit evidence according to the deployment's
legal and incident-response policy.

`actor_session_id` and `actor_device_id` are deliberately immutable historical
soft identifiers rather than foreign keys. Session and device tombstones can
expire before their audit evidence; an `ON DELETE SET NULL` relationship would
silently rewrite an append-only audit row. The owning application validates
these identifiers when it appends each event.

`event_log` and `device_outbox` retain their existing specialized policies.
`event_owner_cursors` are deliberately retained as small per-principal
monotonic tombstones: deleting them could reuse a browser cursor and make a
stale client mistake new events for already observed events.

## Consequences

Command idempotency keys can be reused only after the command retention window
and all dependent approval state are gone. A permanently unacknowledged device
frame deliberately blocks deletion of related command, approval, thread, and
device records; existing outbox capacity limits bound that fail-closed state.
Revoked device history remains for the full device window. Its public key can
be bound to a new active Device only through a new authenticated one-time
pairing flow and while retained-record capacity permits it; the old row is not
reactivated or deleted early.

Operators must alert on sustained nonzero batch-sized sweep results because
they mean deletion is falling behind ingestion. Changing a window is a privacy
and incident-response policy change and requires a reviewed deployment change.
Operators must also alert before retained approval or thread counts approach
their configured hard ceilings; age-based retention and explicit safe archival
are the supported ways to recover capacity.
