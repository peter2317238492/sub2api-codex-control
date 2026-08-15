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

The browser receives an opaque high-entropy session credential in a
`__Host-codex_control` cookie with `Secure`, `HttpOnly`, `SameSite=Strict`, and
`Path=/`. Its value is an AEAD-sealed envelope containing a random handle, the
Control session UUID, and the access token used for exchange. Only a keyed hash
of the complete envelope is stored by Control; neither PostgreSQL nor Redis
stores the access token in plaintext or ciphertext. The sealed value is bounded
below the common 4096-byte cookie limit, and an access token that cannot fit is
rejected without creating a session. Unsafe requests also require
a per-session double-submit value in the readable `codex_csrf` cookie (also
`Secure`, `SameSite=Strict`, and `Path=/`), the same value in the custom header
named by `csrf_header_name` in the session response, and valid same-origin
`Origin`/Fetch Metadata. Only a keyed digest of the CSRF value is stored by the
server. The refresh token is never sent to or stored by the Control API.

The session lookup digest has the fixed purpose `control-session-v2`. The
current image does not fall back to the legacy `control-session` purpose. A
legacy image therefore cannot locate a row created for a current cookie, and
the current image cannot locate a legacy row; crossing either image generation
requires a fresh exchange. This rollback boundary relies on digest-domain
separation that the legacy image already enforces, rather than expecting the
legacy image to understand a new cookie field. Production settings admission
and the container entrypoint also reject bundled development, test, and example
secret values before they can become cookie or digest keys.

The PWA calls the documented Sub2API refresh endpoint directly and persists the
rotated access/refresh pair in the existing Sub2API localStorage keys, sending only
the new access token to a fresh exchange. Pairing, device revocation, and
approval decisions require a recently issued Control session; an older session
receives a reauthentication error and the PWA re-runs `/auth/me` through
exchange. Logout revokes the current Control session even if the parallel
Sub2API logout call fails. A failed exchange, disabled user, or token-version
mismatch creates no new Control session.

Sub2API remains authoritative throughout an issued Control session. Every
authorization-bearing unsafe Control request except logout repeats `/auth/me`
with the sealed access token and the original browser IP/User-Agent binding
before authorization. Read-only HTTP requests may reuse a timestamped, keyed
Redis success marker for at most 15 seconds. A Redis
read failure bypasses that optimization and performs the upstream check rather
than extending trust. `USER_INACTIVE`, `TOKEN_REVOKED`, a generic credential
rejection, user-ID drift, or token-version drift atomically revokes the durable
Control session and publishes the normal revocation wake-up. A temporary
Sub2API failure or invalid response authorizes nothing, does not misclassify the
session as revoked, and returns retryable `503` or `502`. Logout is intentionally
authorized against the local cookie, CSRF value, and durable row so a user can
always terminate a session during an upstream or Redis outage.

Authenticated browser WebSockets subscribe to an internal, per-session
revocation channel before rechecking the durable Control session row. Logout
commits the revocation first, then publishes only the non-secret session UUID as
a wake-up signal. Redis publication and cache deletion are bounded best-effort
work after the durable commit, so a Redis outage cannot turn a successful logout
into an HTTP error or prevent cookie clearing. PostgreSQL remains authoritative:
every signal triggers a row and bounded Sub2API identity check, and a fallback
check no slower than the configured 15-second upstream interval plus the exact
session expiry closes gaps caused by a lost publish. When a check becomes due,
the event-delivery gate closes before verification and reopens only after a
successful result. An in-flight browser send and the complete upstream check
each have a hard wall-clock bound, so a slow peer or slow-drip dependency cannot
extend authorization indefinitely. An authoritative missing, revoked, expired,
or upstream-rejected session closes the socket with `4401`; transient Redis,
PostgreSQL, or Sub2API failures and verification timeouts close it with retryable
`1013` rather than misclassifying an infrastructure outage as an invalid
credential.

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

Sub2API remains the authority for user state and token version. Revoked tokens
and disabled users lose mutation access on the next request; read and WebSocket
sessions begin an authoritative recheck no later than 15 seconds after their
last successful check. The Control API can revoke its own
sessions immediately and never handles refresh credentials.
Cookie authentication adds CSRF controls, while same-origin deployment makes
XSS the dominant browser risk and therefore requires a narrow CSP and careful
rendering. A brief Sub2API outage prevents exchanges and mutations immediately;
cached reads end at the bounded recheck deadline and never silently extend to
the Control session's absolute lifetime. Image rollback does not weaken the
session lookup domain: sessions issued by another generation fail closed and
must be exchanged again.
