# Sub2API runtime contract

Status: formally frozen at Sub2API `0.1.176`; production admission accepts only
the explicit `immutable-image-v1` profile.

The upstream `v0.1.176` annotated tag object
`14e6d7ee7bdb1e4cb6bc59129a7ee1dd1110c52a` resolves to commit
`e803e3851c0a7e222cfadeafad7b8636ab959d11`. The release was published at
`2026-08-13T01:46:35Z`. Its linux/amd64 archive SHA-256 is
`ff639ed55f7d940ab86ab75242fe915d8bc3b067d63a95239628f75c20716ba5`;
the extracted `/app/sub2api` binary is 117797026 bytes with SHA-256
`ee2505964d8614388591b7cd98157ae6e3b7edad2489b83a0baef601834038e4`
and reports build time `2026-08-13T01:36:58Z`.

Exact runtime and image values are machine-readable in `versions.lock.json`.
The pinned refresh/logout/session-binding/storage shape is in
`sub2api-auth.v0.1.176.json`, whose SHA-256
`a02d18e193d66a8607c09078d9d90e8883b8d660c587e52b015f9e51401f6e04`
is locked there. A byte-for-byte comparison from `v0.1.175` to `v0.1.176`
found no change in the frozen frontend auth, JWT middleware, session-binding
middleware, refresh handler, or response wrapper.

## Historical rejected runtime

A read-only production audit on 2026-08-12 found a mutable, self-updated
container based on image `sha256:2ca591...d6c8` with `0.1.151/deff3123` labels,
while its modified executable reported `0.1.175/93c32fa1`. `docker diff` also
showed two updater backups and root shell history. That evidence remains useful
for incident history, but neither the old image nor its formerly exact writable
shape is an accepted production compatibility profile. It must fail the
current gate.

The frozen `0.1.176` authentication contract is:

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
`weishaw/sub2api@sha256:989c1a56f3598b4e907fc23c80377db1ad22d024f673e6725d80b970d43b6c00`,
with image/config ID
`sha256:40d807a98dbd6c56dd5838ca1a2efe4f60bf2dd88c3621f11eab090c98d38742`.
The `0.1.176` multi-platform tag resolves first to the distinct index digest
`sha256:905baf250580334dacd902471f61da7b8b1e5da57e3c8c1769489952d51771a1`;
the index must not be substituted for the amd64 RepoDigest. The image was
created at `2026-08-13T01:45:34.06109435Z`, and its version, revision, source,
description, and maintainer labels match the lock.

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
