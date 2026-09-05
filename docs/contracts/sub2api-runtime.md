# Sub2API runtime contract

Status: frozen at Sub2API `0.2.1`; production admission accepts only
the explicit `immutable-image-v1` profile.

The upstream `v0.2.1` annotated tag object
`adc26f68f687685e847bfb997559f48e79cac475` resolves to commit
`578785ee7fb35030b094b69624efe25670a36f5f`. The release was published at
`2026-09-05T09:45:01Z`. Its linux/amd64 archive SHA-256 is
`06d5ce6e4be7c2042635d455d6ae1b5990a3fc7692416908d0db395879306363`;
the extracted binary is 119656608 bytes with SHA-256
`b709a61c22bfb6b662619658444e20186fdfd8d1850984fa9a909572c0a5026a`
and reports build time `2026-09-05T09:34:19Z`. On 2026-09-05 the production
container had already been upgraded to this release; its `/app/sub2api`
matched the independently downloaded, checksum-verified release archive.
This source freeze does not replace the fresh runtime and authentication
acceptance required during deployment.

Exact runtime and image values are machine-readable in `versions.lock.json`.
The pinned refresh/logout/session-binding/storage shape is in
`sub2api-auth.v0.2.1.json`, whose SHA-256
`3affbb6ade0b4d6d97df9f2ea3834049e94f64798267763c0c2353cd1f494594`
is locked there. A blob-level comparison from `v0.2.0` to `v0.2.1`
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

The frozen `0.2.1` authentication contract is:

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

The admitted Docker reference is the immutable multi-platform index
`weishaw/sub2api@sha256:b3845aad81d728a5e4efa4d677a638f27947be286ed9a17788a42a1f07fe7e50`.
The production containerd image store reports this index digest as the image
ID and RepoDigest. Its selected linux/amd64 child manifest is
`sha256:86d605217e7ebdb60a70316a458446cd51c2da207a8b2128661a2cb9caaf9aab`.
Admission also pins the exact amd64 binary, preventing a different platform
from satisfying this tuple. The image was created at
`2026-09-05T09:43:41.268535999Z`, and its version, revision, source, and
maintainer labels match the lock.

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
