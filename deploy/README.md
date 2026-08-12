# Deployment assets

These files implement the intended deployment boundary; they are not a
published production release.

- `docker-compose/compose.yaml` defines the Control API, PWA, optional smoke
  edge, and PostgreSQL backup job. It connects the API to an external Sub2API
  network while keeping the PWA on a separate bridge.
- `docker-compose/compose.production.yaml` removes local builds and requires
  digest-pinned release images.
- `dockerfiles/` contains non-root, read-only-compatible `linux/amd64` image
  definitions.
- `nginx/` contains same-origin routes, security headers, a query-redacted
  access-log format, and a dedicated logrotate policy.
- `scripts/` contains secret generation, datastore isolation, immutable
  Sub2API verification, signed release verification, recovery, and the
  fail-closed production deployment entry point.
- `release/` verifies the signed Control image set, provenance, SBOMs, and
  source/revision bindings used by the deployment wrapper.

The first public repository version is source-only. It has no supported signed
Control image set and no supported prebuilt Connector, so production admission
is currently blocked. Do not replace missing release evidence with local
builds, mutable tags, or manually edited receipts.

For the runnable isolated source path, follow
[Installation](../docs/installation.md#isolated-full-stack-verification). The
smoke edge is a disposable test fixture, not a public reverse proxy. For the
future signed deployment boundary, see the
[deployment runbook](../docs/runbooks/deployment.md).
