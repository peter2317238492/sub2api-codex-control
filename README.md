# Sub2API Codex Control

Same-origin remote control for user-owned Codex installations. The Control API
exchanges a current Sub2API access token for a short-lived, revocable HttpOnly
session. Devices connect outbound through the Connector, which speaks the pinned
Codex app-server protocol over stdio and enforces a fail-closed RPC policy.

## Security invariants

- The browser and control database never receive a raw Sub2API provider key.
- A Connector never opens an inbound device port and never rewrites Codex config.
- The Sub2API refresh token is never sent to or stored by the Control API.
- Remote RPC is an explicit allowlist; shell, process, filesystem, account,
  config, plugin, and raw pass-through methods are denied.
- Connector working directories must be inside a local allowlist and remote
  sandbox requests cannot exceed `workspace-write`.
- Approval requests expire after 120 seconds and default to denial.

## Repository layout

```text
apps/control-api/       FastAPI control plane
apps/pwa/               Vue 3 same-origin PWA
connector/              Go outbound connector
packages/control-protocol/ shared wire types and policy
packages/appserver-schema/ pinned Codex 0.147.0 schema
migrations/             database migrations
deploy/                 Compose and Nginx integration
tests/e2e/              system acceptance tests
docs/adr/               frozen decisions and threat model
```

## Local development

Prerequisites are Node.js 22+, pnpm 11+, Python 3.12+, PostgreSQL 16+, Redis 7+,
Go 1.24+, and `codex-cli 0.147.0`.

```bash
pnpm install
pnpm test
pnpm dev
```

Backend and Connector commands are documented in their respective directories.
Production routes are `/codex/`, `/codex-api/`, `/codex-ws/browser`, and
`/codex-ws/device`.

The disposable full-stack acceptance harness is `tests/e2e/run-local.sh`. It
builds and runs the real Connector through a local TLS edge against PostgreSQL,
Redis, a mock Sub2API authority, and a protocol-faithful fake Codex app-server.
It exercises pairing, all eight admitted RPC classes, approval, reconnect,
revocation, no published Connector port, no raw bearer in the Control database,
no generated secret in container metadata, and the coexistence sentinel.

Production admission remains deliberately fail-closed: the observed Sub2API
container has an executable replaced in its writable layer. It must be rebuilt
as one immutable, read-only image matching `versions.lock.json`; the repository
does not modify or whitelist that existing deployment. See
`docs/runbooks/version-matrix.md` and `docs/runbooks/deployment.md`.
