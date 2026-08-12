# ADR 0002: Map typed Connector commands to pinned app-server JSON-RPC

- Status: Accepted
- Date: 2026-07-13
- Updated: 2026-08-12 (Codex 0.147.0 contract refresh)

## Context

The Connector must control the device's existing Codex installation without
changing its configuration, provider credentials, or inbound network surface.
Codex 0.147.0 exposes a broad bidirectional app-server contract: the generated
bundle contains 133 client-request methods and app-server can initiate approval
and tool-related requests back to its client.

## Decision

The Connector pins `codex-cli 0.147.0`, verifies that version immediately
before every child start (including each restart),
and launches one child process with:

```sh
codex app-server --listen stdio://
```

It uses the device's existing Codex environment and credentials, while the
Connector itself never edits `config.toml`, auth files, providers, or plugins.
Stdout is parsed only as JSON-RPC protocol traffic; stderr is separate
diagnostic output with bounded, redacted capture. No local listener is opened.

The Connector owns `initialize` and `initialized`, request IDs, response
correlation, and child lifecycle. Each child start creates a random
`app_server_epoch`; commands, events, pending approvals, and responses carry
that epoch. A restart fails pending calls and invalidates all responses from an
older epoch.

The Control API and Connector use a separate versioned command envelope over
the device's outbound WSS connection. The envelope contains a command ID,
monotonic sequence, device ID, kind, typed payload, deadline, and protocol
version. The Connector maps only these kinds to app-server requests:
`model/list`, `thread/start`, `thread/list`, `thread/read`, `thread/resume`,
`turn/start`, `turn/steer`, and `turn/interrupt`. It never accepts a raw RPC
method, raw request ID, or arbitrary params object.

Each WSS connection starts with a direct, unspooled `hello` frame at `seq=0`.
It declares the device, current app-server epoch, frozen versions/schema,
capabilities, canonical workspace roots, and durable receive cursors. The
Control API validates the complete tuple against the pairing record before
returning a direct `hello_ack` at `seq=0`. Only then may either side send normal
sequenced frames (`seq>=1`) or replay a durable backlog. A receive cursor is
advanced in the same durable transaction as the frame's side effects. Frames
from an older epoch are strictly decoded but cannot project events, errors,
heartbeats, or approval traffic. A stale terminal command acknowledgement may
only replace an API-generated `epoch_replaced_indeterminate` command result and
cannot mutate a thread binding, model catalog, or current-epoch projection.

Each mapping constructs a new params value from allowed fields, enforces device
and thread ownership, canonicalizes paths under configured local roots, and
prevents sandbox, permission, approval, environment, dynamic-tool, or config
relaxation. The maximum sandbox is `workspace-write`. The Control API derives
the Connector journal key from its complete device/method/resource idempotency
scope plus the user key. Command IDs are idempotent across WSS retries;
sequence/ACK state and a bounded local spool of
projected, redacted envelopes recover events after reconnect without replaying
completed mutations. Spool directories and records are private to the local
Connector account (`0700`/`0600`) and acknowledged records are deleted.

App-server results are projected before they enter the command journal or
outbound spool. The projection retains only bounded model metadata, managed
thread summaries and text history, turn lifecycle metadata, agent-message
deltas, bounded plans, and sanitized errors. Command output, diffs, reasoning,
tool arguments/results, rollout paths, Git metadata, local image paths, and
unmanaged thread or inactive-turn events are dropped. Frame, payload, depth,
list, history, string, and local storage quotas fail closed.

Successful app-server responses are correlated with their request method and
validated against that method's frozen generated response schema. JSON-RPC
error responses and app-server notifications are schema-validated against the
frozen aggregate contract. Contract drift cancels the current child epoch
before the message reaches projection or persistence. Notifications are size-limited, tagged with the
epoch and sequence, and forwarded as typed events. Server-initiated requests
are denied unless an explicit handler exists. Remote approvals are single-use
and bound to device, user, thread, turn, request ID, epoch, and a 120-second
deadline; timeout, disconnect, restart, or mismatch means denial.

## Consequences

Generated TypeScript types aid decoding but do not grant authority. New Codex
methods remain unreachable until the command protocol, field projector, tests,
and ADR are updated. Exact-version pinning trades automatic compatibility for
a reviewable upgrade boundary. Child restarts are visible and deterministic
instead of allowing stale approvals or responses to cross process lifetimes.
