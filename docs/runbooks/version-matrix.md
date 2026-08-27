# Version matrix

## Current development tuple

This table records the current repository contracts and their production gates;
it is not proof that the production host already satisfies them.
`versions.lock.json` is the machine-readable source for the Codex/Sub2API tuple.

| Component | Development value | Production admission rule |
| --- | --- | --- |
| Control API | `0.1.0` | API image digest and source commit recorded |
| PWA | `0.1.0` | PWA image digest built from the same release commit |
| Connector | `0.1.6` (`connector-v0.1.0` through `connector-v0.1.5` burned: their pipeline runs failed — v0.1.0 on a missing output parent, v0.1.1 on a mawk-incompatible awk expression, v0.1.2 on rpmbuild's brp-strip mutating the packaged binary, v0.1.3 on removing the read-only release module cache, v0.1.4 on artifact transfers stripping the executable bit into a pipeline whose macOS finalize stage had been removed without a Linux replacement, v0.1.5 on the sign stage unconditionally validating Apple identity inputs the Linux matrix never provides — and formal tags are immutable); executable protected-tag pipeline and local fail-closed tests in `connector/release/` | selected artifact passes the verifier against externally pinned GitHub issuer/identity/source SHA/trigger and the pinned RPM OpenPGP fingerprint; immutable release and all required bundles/evidence exist; no trusted release run is recorded yet |
| Control envelope | version `1` | unknown versions rejected before dispatch |
| Codex CLI | exactly `0.147.0` | Connector version check succeeds before app-server start |
| app-server v2 schema | SHA-256 `511c1b3ca038a80740a5a41ca10a7f925c0f744e582fb9aaa03cc46c6e98b80b` | generated bundle reproduces and Connector config carries this digest |
| Sub2API official image | linux/amd64 `weishaw/sub2api@sha256:12021771416425cc99516215fb54089c23edc846bd7316bd91a5cf4ca15148d1` (reported as the image ID under the containerd image store), multi-platform index `sha256:e0f019383025679bd3b0f912c21fe7d8afdba8e42613391fa7fa208cc0762e60`, Docker Created `2026-08-18T10:01:23.430283417Z`, labels `0.1.178/e0c48a19` | `immutable-image-v1` only; exact platform manifest, image ID, labels, digest-only `Config.Image`, and stable live container identity |
| Sub2API runtime binary | `0.1.178`, commit `e0c48a19ed794a565e3858662520afe0a1f9f0ba`, build `2026-08-18T09:52:21Z`, size `118476962`, SHA-256 `3d76ba8505b5b089d609726a966774a1312117e2e865845403ed28fdce7c5d0e` | official amd64 image and release archive are byte-identical; production admission must separately prove the live PID 1 executable matches |
| Sub2API writable layer and data | no image-layer drift; exactly one writable data mount at `/app/data` | named volume, or an explicitly admitted canonical bind whose source/owner/group/mode and `rprivate` propagation match exactly; every ancestor before the final source is root-owned; symlinks, group/other-writable path components, updater artifacts, unexpected diff, or any additional mount fail |
| Sub2API browser token keys | access `auth_token`, refresh `refresh_token` | PWA sends only access token to exchange; refresh never enters Control API |
| Sub2API auth contract | `docs/contracts/sub2api-auth.v0.1.178.json`, SHA-256 `a4b3b4804f30347255478c5772a6a6ee25b5c484d688b0a78a980ee4279709e2`; `GET /api/v1/auth/me`, `POST /api/v1/auth/refresh`, and `POST /api/v1/auth/logout`; disabled, TokenVersion-revoked, and session-binding failures use frozen `USER_INACTIVE`, `TOKEN_REVOKED`, and `SESSION_BINDING_MISMATCH` codes | lock and contract hashes match; exchange forwards the browser IP/User-Agent through the same-host Nginx overwrite policy |
| PostgreSQL tools | `0.1.0`, built from `postgres:18-alpine@sha256:9a8afca54e7861fd90fab5fdf4c42477a6b1cb7d293595148e674e0a3181de15` for compatibility with the production PostgreSQL 18.4 dump format | PostgreSQL-tools image digest is in the same signed atomic release lock as API/PWA; exact repository policy, signature, SPDX SBOM, SLSA provenance, OCI labels, `pg_dump`/`pg_restore` major version, and `linux/amd64` platform verify before backup/restore rehearsal |
| Redis test dependency | `redis:7-alpine@sha256:6ab0b6e7381779332f97b8ca76193e45b0756f38d4c0dcda72dbb3c32061ab99` | production Redis exact version separately recorded; ACL isolation passes |
| Nginx | `nginx:1.28-alpine@sha256:a8b39bd9cf0f83869a2162827a0caf6137ddf759d50a171451b335cecc87d236` | `nginx -t` and security smoke pass |
| Python | `python:3.12-slim-bookworm@sha256:8a7e7cc04fd3e2bd787f7f24e22d5d119aa590d429b50c95dfe12b3abe52f48b`; constraints in `deploy/constraints/control-api.txt` | constraints update is explicit and locked dependency/SBOM scan passes |
| Node/pnpm | `node:22-alpine@sha256:16e22a550f3863206a3f701448c45f7912c6896a62de43add43bb9c86130c3e2`, pnpm `11.7.0` | frozen lockfile build reproduces PWA assets |
| Go | exactly `1.26.5` for Connector releases (`go.mod` retains the `1.24.0` language baseline); portable levels `GOAMD64=v1`, `GOARM64=v8.0`; `GOENV=off`, `GOFIPS140=off`, `GOTOOLCHAIN=local` | `go.sum`, two-pass reproducible candidates, tests, per-artifact SPDX/SLSA evidence, and signed manifest verification pass |

## Dated production drift evidence

The 2026-08-12 read-only audit observed base image
`sha256:2ca591c2...d6c8` with labels `0.1.151/deff3123`, a self-updated
`0.1.175/93c32fa1` executable, and writable updater artifacts. This is retained
as non-admitting historical evidence. It must fail the formal gate and does not
prove the current production host runs the `0.1.178` immutable tuple.

## Feature admission

| Capability | Current implementation evidence | Production release evidence required |
| --- | --- | --- |
| Same-origin PWA and HTTP session exchange | implemented, including CSRF/session revocation and renewal through the observed Sub2API refresh contract; refresh credentials never enter the Control API | authenticated identity/refresh/logout smoke against the admitted Sub2API image and machine-readable refresh-contract lock |
| PostgreSQL/Redis readiness | implemented with PostgreSQL as the durable authority and Redis as namespaced coordination | dedicated production role/ACL verification and failure injection |
| `/codex-ws/browser` | implemented with authenticated, user-scoped catch-up and Redis Pub/Sub fanout; automated edge and scope coverage exists | production same-origin smoke plus reconnect cursor/load result |
| `/codex-ws/device` | implemented with signed auth, persistent outbox, replay/ACK, gap close, heartbeat, reconnect, and revocation; the disposable TLS harness drives a real Connector | production TLS/heartbeat/reconnect/revocation result against the release artifacts |
| Multiple API workers/replicas | cross-instance browser/device fanout, atomic connection ownership, replacement, and durable dispatch are implemented; production starts two API services with one worker each | deterministic two-replica test with device WSS on one replica and HTTP/browser WSS on the other, followed by load and kill/reconnect results, before increasing `CONTROL_API_WORKERS` |
| Remote turn control | implemented for exactly the eight typed commands with ownership, field projection, idempotency, restart recovery, and dangerous-method denial; the disposable harness audits the dispatched method set | authenticated production canary against the pinned Codex release |
| Remote approvals | implemented with bounded projection, one-shot decisions, epoch/ownership binding, disconnect handling, and a maximum 120-second fail-closed timeout | production command/file/permission approval and timeout result |
| Observability | bounded Control API HTTP, authentication, pairing, WebSocket, command, reconciliation, maintenance, dependency, and pool metrics plus the private atomic Connector textfile metrics are implemented | wire and verify production Prometheus targets, external synthetic/datastore/migration/backup/restore/policy collectors, Alertmanager delivery, and controlled firing/recovery evidence |
| Connector automatic updates | prohibited in MVP | signed manifest, atomic rollback, staged rollout, and key-revocation drill |

## Release review

For each release, copy the development tuple into a dated, immutable release
record and attach:

- source commit and clean-tree evidence;
- API/PWA/PostgreSQL-tools image digests, signatures, SBOMs, provenance, and
  vulnerability disposition;
- Connector artifact digests, signatures, provenance, and native package signatures;
- Sub2API image digest, binary-reported version, commit, and captured `/auth/me`
  success/disabled/revoked fixtures;
- app-server schema regeneration result and aggregate digest;
- Alembic current/head revisions plus pre-migration backup checksum;
- authenticated smoke, dangerous-path denial, WebSocket, reconnect, approval,
  and ordinary Codex App/CLI coexistence results.

Any mismatch is a hard failure. Do not silently widen ranges, fall back to raw
RPC, or start app-server when Codex/schema verification fails.
