# ADR 0003: Enforce fail-closed remote-control boundaries

- Status: Accepted
- Date: 2026-07-13

## Context

Remote Codex control crosses a browser, Control API, database/Redis, outbound
device WSS, Connector, app-server, and the device filesystem. Threats include a
stolen browser token or cookie, PWA XSS, a malicious prompt or model output, a
compromised device or Connector, cross-user object access, replayed commands,
stale approvals, path traversal/symlink races, protocol drift, secret leakage,
and resource exhaustion.

## Decision

The following boundaries are mandatory:

1. The Control API authenticates users through the exchange in ADR 0001 and
   performs object authorization on every device, thread, turn, command, and
   approval. Every authorization-bearing mutation except logout revalidates the
   sealed Sub2API access token; reads and browser WebSockets begin revalidation
   within 15 seconds. Upstream rejection durably revokes the Control session,
   while upstream uncertainty authorizes nothing. Database and Redis access use
   a dedicated role/schema and prefix.
2. Devices authenticate with an Ed25519 key created locally, a one-time pairing
   flow, and short-lived connection credentials. Pairing protocol v2 persists
   the Connector-generated pairing ID, code, poll token, and refresh credential
   before network I/O, then signs their commitments with the exact audience and
   device configuration. Claiming reserves an owner but creates no Device; only
   an authenticated poll atomically creates the active Device and completes the
   credential binding. Completed polls remain replayable after response loss.
   WSS is outbound-only over TLS. Sequence numbers, ACKs, command IDs,
   deadlines, and replay records are checked before dispatch.
3. The Connector accepts only the eight typed MVP commands in ADR 0002. Every
   unknown or newly generated method is denied. `thread/shellCommand`,
   `command/exec*`, `process/*`, `fs/*`, config mutation, plugin/marketplace
   mutation, account/OAuth login, MCP tool calls, remote-control nesting, and
   raw RPC pass-through are prohibited.
4. Allowed methods receive field-level projection. `cwd` is canonicalized and
   checked against local allowlisted roots, including symlink resolution at use
   time. Thread IDs must be bound to the requesting user and device. Callers
   cannot override config, runtime roots, permissions, environments, dynamic
   tools, sandbox, or approval policy. The effective sandbox is never more
   permissive than `workspace-write`.
5. Server-initiated requests default to denial. Approval UI displays the exact
   device, cwd, command or file operation, and requested escalation. Decisions
   are one-shot, audited, epoch-bound, and expire after 120 seconds; ambiguity,
   restart, disconnect, or timeout denies the request.
6. Protocol input is schema-validated with limits on frame size, nesting,
   strings, event rate, outstanding calls, spool size, and child restarts.
   Browser output is treated as untrusted text, escaped, and never used as HTML.
   Logs redact tokens, provider keys, prompts or output marked sensitive, and
   approval secrets.
7. Control storage contains no raw Sub2API provider key or refresh token.
   Session, pairing, command, approval, and audit records have explicit
   retention and revocation behavior. Security-relevant state changes append an
   immutable audit event with actor, target, result, and correlation IDs. ADR
   0004 defines the only age-based deletion exception and its fail-closed
   dependency rules.

The boundary does not claim that `workspace-write` prevents all reads outside a
workspace, that model output is trustworthy, or that a compromised device can
be made safe remotely. Existing Codex configuration and local credentials
remain part of the device trust base. Stopping the Connector must leave the
ordinary Codex app and CLI unchanged.

## Consequences

Some generated app-server capabilities are intentionally unusable through the
remote product. Adding one requires a threat review, typed protocol revision,
field policy, authorization tests, and audit coverage. Operations fail closed
during version/schema mismatch or loss of identity, device, epoch, or thread
binding. The principal residual risks are device compromise, same-origin XSS,
and the filesystem visibility inherent in the selected Codex sandbox; these
must be stated to operators rather than hidden behind the method allowlist.
