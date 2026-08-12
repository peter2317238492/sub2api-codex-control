# ADR 0001: Exchange Sub2API access tokens for Control sessions

- Status: Accepted
- Date: 2026-07-13

## Context

Sub2API authenticates browser requests with a short-lived access JWT and a
refresh token stored by its existing frontend. The same-origin Codex PWA reuses
and, when required, rotates those existing Sub2API browser credentials. It must
not create a separate Control-owned refresh credential, send one to the Control
API or Connector, or receive a Sub2API provider key. Cross-origin PWA preflight
is currently rejected, so the first deployment is same-origin under `/codex/`.

## Decision

The PWA sends its current access token once to
`POST /codex-api/v1/session/exchange`. The Control API validates it by calling
the internal Sub2API endpoint `GET /api/v1/auth/me`; it does not implement a
second, potentially divergent JWT validator. A successful check creates a
server-side, revocable session with a 5-10 minute absolute lifetime.

The browser receives an opaque high-entropy session identifier in a
`__Host-codex_control` cookie with `Secure`, `HttpOnly`, `SameSite=Strict`, and
`Path=/`. Only a hash of the identifier is stored. Unsafe requests also require
a per-session double-submit value in the readable `codex_csrf` cookie (also
`Secure`, `SameSite=Strict`, and `Path=/`), the same value in the custom header
named by `csrf_header_name` in the session response, and valid same-origin
`Origin`/Fetch Metadata. Only a keyed digest of the CSRF value is stored by the
server. The refresh token is never sent to or stored by the Control API.

The PWA calls the documented Sub2API refresh endpoint directly and persists the
rotated access/refresh pair in the existing Sub2API localStorage keys, sending only
the new access token to a fresh exchange. Pairing, device revocation, and
approval decisions require a recently issued Control session; an older session
receives a reauthentication error and the PWA re-runs `/auth/me` through
exchange. Logout revokes the current Control session even if the parallel
Sub2API logout call fails. A failed exchange, disabled user, or token-version
mismatch creates no new Control session. An already issued Control session is
not asynchronously revoked by that failed exchange; unless explicitly logged
out or revoked, it can remain valid only until its 5-10 minute absolute expiry.

Authenticated browser WebSockets subscribe to an internal, per-session
revocation channel before rechecking the durable Control session row. Logout
commits the revocation first, then publishes only the non-secret session UUID as
a wake-up signal. Redis publication and cache deletion are bounded best-effort
work after the durable commit, so a Redis outage cannot turn a successful logout
into an HTTP error or prevent cookie clearing. PostgreSQL remains authoritative:
every signal triggers a row check, and a 15-second fallback check plus the exact
session expiry closes gaps caused by a lost publish. An authoritative missing,
revoked, or expired row closes the socket with `4401`; transient Redis or
PostgreSQL failures close it with retryable `1013` rather than misclassifying an
infrastructure outage as an invalid credential.

Browser WebSocket admission uses short-lived Redis lease slots keyed by the
non-secret Control session UUID and a digest of the owner identifier. This
enforces cross-replica per-session and per-user caps; each live socket refreshes
its own leases, releases them on clean shutdown, and abandoned leases expire
automatically. A capacity rejection uses `4429`; lease-store acquisition,
renewal, or ownership failure uses retryable `1013`. Event catch-up is paged and bounded by
both row count and exact serialized byte count before anything is sent.

The same-origin PWA uses a strict CSP, no third-party scripts, escaped untrusted
output, and a Service Worker scoped to `/codex/`. Control API responses use
`Cache-Control: no-store` and never expose raw Sub2API access or refresh tokens.
The PWA accesses only the existing same-origin Sub2API authentication keys and
creates no separate browser storage for a Control token.

## Consequences

Sub2API remains the authority for user state and token version. The Control API
can revoke its own sessions immediately and never handles refresh credentials.
Cookie authentication adds CSRF controls, while same-origin deployment makes
XSS the dominant browser risk and therefore requires a narrow CSP and careful
rendering. A brief Sub2API outage prevents new exchanges but does not silently
extend existing sessions beyond their short absolute lifetime.
