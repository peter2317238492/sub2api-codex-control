# Control API

FastAPI control plane for same-origin `/codex/` clients and outbound device
Connectors. It exchanges a current Sub2API access token for a short-lived,
revocable control session. It never accepts a Sub2API refresh token and never
stores a raw Sub2API access token.

## Security model

- `POST /v1/session/exchange` calls the internal Sub2API
  `/api/v1/auth/me` endpoint with `Authorization: Bearer <access_token>`.
- Only a keyed SHA-256 digest of the opaque control token is stored. The control
  cookie is an AEAD-sealed, size-bounded envelope carrying the session UUID and
  upstream access token; it is `HttpOnly`, `SameSite=Strict`, `Path=/`, and
  secure in production. PostgreSQL and Redis never store the upstream token.
- Every authorization-bearing browser mutation except logout rechecks
  `/auth/me` immediately with the original Sub2API session-binding
  IP/User-Agent. Read-only HTTP and browser WebSocket checks may reuse a
  timestamped, keyed success marker for at most 15 seconds. Disabled
  users, revoked tokens, identity drift, and token-version drift durably revoke
  the Control session; upstream uncertainty returns `503`/`502` or closes the
  socket with retryable `1013` without granting access.
- Browser mutations require an exact configured `Origin` plus a session-bound
  `codex_csrf` cookie and `X-CSRF-Token` header. Validation responses omit input
  values so bearer tokens are not reflected.
- PostgreSQL remains authoritative for expiry, revocation, sequence, command,
  thread, approval, browser-event, and durable outbox state. Redis coordinates
  token rotation, nonces, connection ownership, pub/sub wakeups, and rate limits.
- Redis connect and command timeouts default to three seconds. Browser sockets
  use expiring Redis lease slots to enforce configured per-session and per-user
  caps across API replicas; abandoned slots recover automatically.
- Browser event catch-up is paged and capped by both row count and serialized
  bytes. Authoritative invalid sessions close with `4401`, while temporary
  Redis/PostgreSQL failures close with retryable `1013`.
- `memory://` is an explicit test backend, not an automatic production fallback.
- Session exchange and device connect-token issuance are IP-rate-limited before
  external token verification or device credential/signature verification.
  Pairing polls use both per-pairing/IP and global IP counters so rotating
  pairing identifiers cannot bypass the limit.
- Pairing protocol v2 accepts only an Ed25519-signed start whose pairing ID,
  creation time, exact audience, device identity/configuration, and three
  SHA-256 secret commitments match the signature. The API stores only keyed
  digests of the code, poll token, and Connector-generated refresh credential.
- Claiming a code reserves the authenticated owner but creates no `devices`
  row. The first valid Connector poll creates the active Device, links and
  completes the pairing, and commits its credential digest atomically. A lost
  completion response can be replayed with the same poll token.
- Device connection tokens require a fresh Ed25519 proof and rotate the previous
  short-lived token. Only keyed token digests and nonce digests are retained.
- `hello`/`hello_ack` are direct, unspooled `seq=0` handshake frames. All other
  device frames use persistent monotonically increasing sequence numbers. Gaps
  fail closed, duplicates are acknowledged without reapplying effects, and
  server frames remain in the PostgreSQL `device_outbox` until ACKed. One exact
  ACKed frame is retained so duplicates can reuse a sequence without growth.
  Active-device unacknowledged rows are never aged away; the retention sweep
  removes expired ACKed rows and all rows belonging to revoked devices.
- Pairing binds one or more canonical absolute workspace roots. Hello must
  attest the same root set, Connector/Codex versions, complete capability set,
  and frozen app-server schema digest or the connection is rejected.
- After a new-epoch hello, all visible old-epoch thread bindings become failed
  with an explicit resume requirement. Contiguous old-epoch backlog is schema
  validated and advances the durable cursor without projecting events, errors,
  approvals, or heartbeats. A terminal command acknowledgement may only refine
  a command already marked `epoch_replaced_indeterminate`; it never migrates the
  old thread projection into the new epoch.
- No raw RPC endpoint exists. REST handlers construct only the eight allowlisted
  methods and strict parameter objects. Shell, filesystem, process, config,
  account, plugin, and arbitrary method/field injection is rejected.
- Approvals are bound to the current app-server epoch and default-deny after at
  most 120 seconds. New epochs, disconnects, expired-on-arrival requests, and
  approval-capacity overflow all fail closed.
- The singleton state sweep removes terminal control-plane records in bounded
  batches after explicit table-specific windows. Pending commands, undelivered
  approvals, unacknowledged outbox state, active turns/connections, and their
  dependent thread/device records are never aged away. Audit events are
  append-only until their configured 365-day default retention expires; see
  [ADR 0004](../../docs/adr/0004-control-data-retention.md).

The `__Host-` cookie prefix requires HTTPS, `Secure`, `Path=/`, and no `Domain`
attribute. Keep TLS termination and API routing on the same origin as the PWA.

## Endpoints

| Method | Path | Authentication |
| --- | --- | --- |
| `GET` | `/v1/health/live` | none |
| `GET` | `/v1/health/ready` | none; checks PostgreSQL, Redis, frozen Sub2API marker, and startup-admitted Connector release metadata |
| `GET` | `/internal/metrics` | direct loopback/internal access + metrics Bearer token; public Nginx path denied |
| `POST` | `/v1/session/exchange` | allowed Origin + Sub2API access token body; rate-limited |
| `GET` | `/v1/session` | control cookie |
| `DELETE` | `/v1/session` | control cookie + Origin + CSRF |
| `POST` | `/v1/session/logout` | compatibility logout alias |
| `POST` | `/v1/device-pairings/start` | unauthenticated, rate-limited |
| `GET` | `/v1/device-pairings/{id}/poll` | `Authorization: Pairing <poll_token>`; rate-limited |
| `POST` | `/v1/pairings/claim` | control cookie + Origin + CSRF |
| `POST` | `/v1/device/connect-token` | `Device` credential + signed Ed25519 proof; rate-limited |
| `GET` | `/v1/bootstrap` | control cookie; atomic event cursor plus bounded device/thread-summary/approval/model caches |
| `GET` | `/v1/devices` | control cookie; user-scoped active-device cache |
| `DELETE` | `/v1/devices/{id}` | control cookie + Origin + CSRF |
| `GET` | `/v1/devices/{id}/models` | control cookie; cache only |
| `POST` | `/v1/devices/{id}/models/sync` | control cookie + Origin + CSRF + optional `Idempotency-Key`; queue typed `model/list` |
| `GET` | `/v1/devices/{id}/threads` | control cookie; bounded managed-thread cache only |
| `POST` | `/v1/devices/{id}/threads/sync` | control cookie + Origin + CSRF + optional `Idempotency-Key`; queue typed `thread/list` |
| `POST` | `/v1/devices/{id}/threads` | control cookie + Origin + CSRF; queue typed `thread/start` |
| `GET` | `/v1/threads/{id}` | control cookie; atomic `{event_cursor, thread}` cached detail watermark; never queues RPC |
| `POST` | `/v1/threads/{id}/sync` | control cookie + Origin + CSRF + optional `Idempotency-Key`; queue typed `thread/read` |
| `POST` | `/v1/threads/{id}/resume` | control cookie + Origin + CSRF |
| `DELETE` | `/v1/threads/{id}` | control cookie + Origin + CSRF; archive only idle/failed threads with no pending command, approval, or unacknowledged device frame |
| `POST` | `/v1/threads/{id}/turns` | control cookie + Origin + CSRF |
| `POST` | `/v1/threads/{id}/turns/current/steer` | control cookie + Origin + CSRF |
| `POST` | `/v1/threads/{id}/turns/current/interrupt` | control cookie + Origin + CSRF |
| `GET` | `/v1/approvals?state=pending` | control cookie; user-scoped |
| `POST` | `/v1/approvals/{id}/decision` | control cookie + Origin + CSRF |
| `WSS` | `/codex-ws/device` (internal alias `/ws/device`) | short-lived device Bearer token |
| `WSS` | `/codex-ws/browser` (internal alias `/ws/browser`) | control cookie + allowed Origin |

The v2 start body contains `protocol_version=2`, a Connector-generated pairing
UUID and creation time, the exact pairing endpoint audience, the canonical
Ed25519 public key and device configuration, SHA-256 commitments for the code,
poll token, and refresh credential, and an Ed25519 signature over that complete
intent. Retrying the same signed intent is idempotent; reusing its pairing UUID
with different fields is rejected. Raw pairing secrets are not accepted by the
start endpoint.

The first device WebSocket frame is an unsequenced hello with `seq=0`, the
current app-server epoch, paired workspace roots, the eight exact capabilities,
the frozen schema digest, `ack` set to the last received server sequence, and
`resumed_from_seq` set to the last device sequence acknowledged by the server.
The direct `hello_ack` echoes protocol version, device, epoch, schema digest,
and the server's durable receive cursor before any sequenced backlog or command
traffic is sent.

A pending poll returns HTTP `202`. The first authenticated poll after claim
atomically creates the active Device and returns:

```json
{
  "status": "claimed",
  "device_id": "<pairing uuid>"
}
```

The refresh credential is the value already held in Connector pending state;
the API never returns it. Repeating a completed poll returns the same Device so
response loss is recoverable. After terminal pairing retention removes that
row, replaying the same signed v2 start can reconstruct only a completed pairing
whose active Device has the same fixed ID, public key, and refresh-credential
digest; it cannot mint or reassign a Device.

The connection-token proof signs the exact UTF-8 string
`device_id + "\n" + timestamp + "\n" + nonce`. The timestamp is RFC3339 UTC,
the nonce is an unpadded base64url 24-byte random value, and the signature is an
unpadded base64url Ed25519 signature. A proof nonce is accepted once.

Production requires `CONTROL_SUB2API_CONTRACT_MARKER=0.1.178/e0c48a1`. This
marker is supplied only after an external deployment check verifies the pinned
Sub2API binary contract; the Control API does not trust an unauthenticated
remote version guess.

## Development

Python 3.12 or newer is required.

```bash
cd apps/control-api
python -m venv .venv
. .venv/bin/activate
pip install -e '.[dev]'
pytest
uvicorn control_api.main:app --reload
```

Copy values from `.env.example` into a local `.env`. For a fully isolated test
run, pytest creates a temporary SQLite database and uses the in-memory key-value
backend. Runtime startup does not create tables; apply the owned Alembic
migration before starting the service:

From the repository root:

```bash
CONTROL_DATABASE_URL='postgresql+asyncpg://...' \
  alembic -c migrations/alembic.ini upgrade head
```

When crossing revision `20260713_0003`, follow the quiescence and cursor checks
in `migrations/README.md`. Upgrade and downgrade intentionally fail while any
server-to-device sequence is unacknowledged.

Production configuration validation rejects the bundled development HMAC and
metrics secrets, non-secure or non-`SameSite=Strict` cookies, non-PostgreSQL databases, `memory://`
Redis URLs, and a missing or mismatched frozen Sub2API contract marker.

Device receive cursors, command/event/approval projections, and browser event
records commit atomically in PostgreSQL. Server-to-device frames are retained in
the `device_outbox` table until acknowledged; Redis is used only for connection
ownership/leases, dispatch wakeups, rate limits, and browser notifications. Size,
depth, rate, active/retained session, outstanding/retained command, connection
history, approval, outbox, and event-retention ceilings are explicit `CONTROL_*`
settings in `.env.example`. Connector command-journal identities are a
domain-separated digest of the API's resource scope plus the user idempotency
key, so the same user key on different managed threads cannot collide locally.

An approval decision is successful once its Approval row, audit record, and
browser event commit. Redis and browser publication happen afterward and cannot
turn that durable success into an HTTP 500. Replaying the same decision for the
same owner remains idempotent across Control Session rotation; the opposite
decision returns 409. The singleton sweep re-wakes current-epoch undispatched
decisions, and browser WebSockets periodically read the durable event log even
when a Redis wake-up is lost.

The bootstrap response has a startup-validated closed size bound. Each accepted
write is projected with compact `ensure_ascii` JSON and capped at 16 KiB per
`DeviceSummary`, 12 KiB per `ManagedThreadSummary`, 24 KiB per device model
catalog, and 68 KiB per pending `ApprovalItem`. With the defaults `D=100`
active devices, `T=100` non-closed threads, and `A=32` pending approvals, the
conservative bound is:

```text
4096 + D*(16384 + 24576 + 128) + T*(12288 + 1) + A*(69632 + 1)
= 7,570,052 bytes < 8,388,608 bytes
```

Configuration startup fails if a quota combination exceeds the response cap.
Creation paths serialize owner quotas on the durable event-owner row; device
writers take locks in `Device -> Owner` order. Revoked devices and closed/stale
threads are excluded from active lists. Device, thread, and approval records
have hard retained-row ceilings (`CONTROL_OWNER_MAX_DEVICE_RECORDS`,
`CONTROL_OWNER_MAX_THREAD_RECORDS`, `CONTROL_DEVICE_MAX_APPROVAL_RECORDS`, and
`CONTROL_OWNER_MAX_APPROVAL_RECORDS`). Approval admission fails closed before
writing an approval, audit row, or browser event when either retained-row limit
is reached. Idle or failed threads can be explicitly archived to release active
capacity without deleting their retained record.
Thread detail history is layered outside bootstrap, capped at 512 KiB and 1000
messages, and returned with a same-transaction event watermark so browser replay
can discard only events at or below that thread snapshot.
