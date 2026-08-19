# Sub2API runtime contract

Status: formally frozen at Sub2API `0.1.178`; production admission accepts only
the explicit `immutable-image-v1` profile.

The upstream `v0.1.178` annotated tag object
`15290e66c66801a7ce435a6d24b178ee9486f284` resolves to commit
`e0c48a19ed794a565e3858662520afe0a1f9f0ba`. The release was published at
`2026-08-18T10:03:00Z`. Its linux/amd64 archive SHA-256 is
`ae2d10ccb923cdd15fe537dace5fd0cb5f3c52178403aa5df5878c25f6ddc28b`;
the extracted `/app/sub2api` binary is 118476962 bytes with SHA-256
`3d76ba8505b5b089d609726a966774a1312117e2e865845403ed28fdce7c5d0e`
and reports build time `2026-08-18T09:52:21Z`.

Exact runtime and image values are machine-readable in `versions.lock.json`.
The pinned refresh/logout/session-binding/storage shape is in
`sub2api-auth.v0.1.178.json`, whose SHA-256
`a4b3b4804f30347255478c5772a6a6ee25b5c484d688b0a78a980ee4279709e2`
is locked there. A blob-level comparison from `v0.1.176` to `v0.1.178`
found no change in the frozen frontend auth, JWT middleware, session-binding
middleware, refresh handler, or response wrapper, so the contract carries
over verbatim.

## Historical rejected runtime

A read-only production audit on 2026-08-12 found a mutable, self-updated
container based on image `sha256:2ca591...d6c8` with `0.1.151/deff3123` labels,
while its modified executable reported `0.1.175/93c32fa1`. `docker diff` also
showed two updater backups and root shell history. That evidence remains useful
for incident history, but neither the old image nor its formerly exact writable
shape is an accepted production compatibility profile. It must fail the
current gate.

The frozen `0.1.178` authentication contract is:

- access token localStorage key: `auth_token`
- refresh token localStorage key: `refresh_token`
- authoritative identity endpoint: `GET /api/v1/auth/me`
- inactive-user rejection: HTTP `401` with code `USER_INACTIVE`
- TokenVersion-revoked rejection: HTTP `401` with code `TOKEN_REVOKED`
- session-binding rejection: HTTP `401` with code
  `SESSION_BINDING_MISMATCH`
- session-binding identity: forward the original browser IP in
  `X-Forwarded-For` and the exact browser `User-Agent` when calling `/auth/me`
- API authentication: `Authorization: Bearer <access token>`
- token rotation endpoint: `POST /api/v1/auth/refresh` with JSON
  `{"refresh_token":"..."}`; success is the exact
  `{"code":0,"message":"success","data":{...}}` envelope whose `data` contains
  string `access_token`, rotated string `refresh_token`, positive numeric
  `expires_in`, and `token_type: "Bearer"`
- logout endpoint: `POST /api/v1/auth/logout` with JSON
  `{"refresh_token":"..."}` and the access-token Bearer header when available;
  the PWA does not depend on a response body

Only `auth_token` may be sent to `POST /codex-api/v1/session/exchange`.
`refresh_token` is never read by Control API code, sent over the control
protocol, or stored in the control database. The PWA uses the refresh and
logout endpoints directly and rotates the existing Sub2API localStorage keys.

## Production freeze gate

The only admitted linux/amd64 manifest is
`weishaw/sub2api@sha256:12021771416425cc99516215fb54089c23edc846bd7316bd91a5cf4ca15148d1`;
under the production containerd image store the daemon reports that manifest
digest as the image ID. The `0.1.178` multi-platform tag resolves first to the
distinct index digest
`sha256:e0f019383025679bd3b0f912c21fe7d8afdba8e42613391fa7fa208cc0762e60`;
the index must not be substituted for the amd64 RepoDigest. The image was
created at `2026-08-18T10:01:23.430283417Z`, and its version, revision, source,
and maintainer labels match the lock (the `0.1.178` image no longer carries a
description label).

Admission requires digest-only `Config.Image`, the exact RepoDigest/image ID,
read-only rootfs, all Linux capabilities dropped, no-new-privileges, PID 1 at
`/app/sub2api`, no writable-layer diff, and exactly one writable data mount at
`/app/data`. That mount may be a named Docker volume or an explicitly admitted
canonical bind. A bind must match its exact expected source, numeric owner/group,
mode, and `rprivate` propagation; every path component must be a real directory
with no group/other write bit, and every ancestor before the final data source
must be root-owned. Unadmitted binds, updater artifacts, mutable tags,
compatibility exceptions, or a missing/unknown profile fail closed. Container identity,
process metadata, network identity, PID, restart count, and PID 1 hash must stay
stable throughout verification.

Release evidence must also capture success and rejection fixtures for
`/auth/me`, `/auth/refresh`, and `/auth/logout`, including refresh rotation,
old-refresh rejection, and refresh rejection after logout. Evidence contains
only status, frozen rejection codes, and shape booleans, never raw tokens, and
is accepted only while fresh and bound to a deployment-generated nonce, exact
user, container network namespace, image/binary identity, and release-bound
locked contract hash. Random invalid tokens return a different code and cannot stand in for
disabled or revoked fixtures. Any mismatch blocks migration and deployment
promotion until the authentication contract is re-audited.
