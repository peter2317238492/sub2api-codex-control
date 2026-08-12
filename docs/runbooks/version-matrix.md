# Version matrix

## Current development tuple

The machine-readable values are authoritative in `versions.lock.json` and the
referenced schemas. This table is a human review index.

| Component | Pinned contract | Admission rule |
| --- | --- | --- |
| Control source | first public `0.1.0` source line | one immutable revision with matching signed release evidence |
| Control images | API, PWA, PostgreSQL tools; `linux/amd64` | digest-pinned images, signatures, provenance, SBOMs, source binding |
| Connector | `0.1.0`; Go 1.24+ source build | no supported prebuilt binary yet; platform release must pass consumer verification |
| Codex CLI | `0.147.0` | exact banner and pinned app-server schema digest |
| Control protocol | version `1` | schema, policy, budget-vector, and wire-fixture hashes must match |
| Sub2API | `0.1.175` locked upstream tuple | immutable-image-v1 only; exact digest/image ID/binary/auth contract |
| PostgreSQL | deployment-provided supported service | separate non-superuser role and private Control database |
| Redis | deployment-provided supported service | separate ACL user and key/channel prefix; database number is not isolation |

The public Sub2API lock contains upstream release identity only. It intentionally
contains no live container identity, account data, host path, or compatibility
exception. See [the runtime contract](../contracts/sub2api-runtime.md).

## Feature admission

| Feature | Source status | Additional release evidence required |
| --- | --- | --- |
| Same-origin PWA and Control session | implemented and covered by unit/integration tests | real authenticated exchange, refresh, logout, cookie, CSRF, and revocation checks |
| Browser and device WebSockets | implemented, including bounded replay and multi-instance dispatch | public TLS, exact Origin checks, real browser WSS and Connector reconnect/revocation canary |
| Remote Codex RPC | explicit allowlist and schema projection implemented | real `codex-cli 0.147.0` canary for admitted methods and denial classes |
| Approvals | expiry and default-denial implemented | real approval, timeout, disconnect, stale epoch, and read-only denial checks |
| Datastore isolation | PostgreSQL provisioner and Redis ACL provisioner implemented | role/ACL inspection and negative cross-database/cross-prefix tests on target services |
| Nginx integration | same-origin routes and dedicated redacted access log implemented | full `nginx -t`, route probes, rotation/reopen, query-secret negative test, listener inspection |
| Recovery | backup and restore tooling plus isolated rehearsal implemented | one current verified recovery point and restore rehearsal for the admitted release |
| Monitoring | bounded metrics and Prometheus rules implemented | target reachability, rule health, controlled alert delivery, external collector coverage |
| Signed Control release | workflow and consumer policy present | **blocked:** no supported signed public image set has been published |
| Signed Connector release | release tooling and platform policy present | **blocked:** no supported public binary has been published |

The isolated `tests/e2e/run-local.sh` path uses a mock Sub2API authority and a
protocol-faithful fake Codex app-server. Its report must identify those fixtures
and cannot close the real-account or real-Codex rows above.

## Release review

Before changing a blocker to admitted, retain all of the following for one
exact revision outside the checkout:

1. source identity and clean source-manifest verification;
2. Control image digests, signatures, provenance, SBOMs, and consumer-verifier
   output;
3. Connector platform artifact identity, signature/notarization where
   applicable, provenance, SBOM, and consumer-verifier output;
4. immutable Sub2API runtime and fresh authentication-contract evidence;
5. migration head, isolated datastore policy, and one verified recovery point;
6. Nginx, TLS, UFW, loopback listener, log rotation/reopen, and secret-redaction
   evidence;
7. authenticated same-origin HTTP, browser WSS, device WSS, real Connector,
   pinned Codex RPC, approval, reconnect, revocation, and logout evidence;
8. monitoring target health and controlled alert recovery.

Readiness, an anonymous API response, a local source build, or an isolated E2E
report cannot replace these gates.
