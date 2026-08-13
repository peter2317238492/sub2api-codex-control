# Operations runbooks

- [Deployment](deployment.md): datastore isolation, secrets, Compose, Nginx, and acceptance checks.
- [Unsigned first-production bootstrap](unsigned-bootstrap.md): one-time, backup-first startup from exact local image IDs before the first signed release.
- [Backups and rollback](backups-and-rollback.md): backup cadence, restore rehearsal, release rollback, and secret rotation.
- [Observability](observability.md): health signals, metrics, structured logs, retention, and alerts.
- [Connector release policy](connector-release-policy.md): reproducible artifacts, signing, staged updates, and rollback.
- [Version matrix](version-matrix.md): pinned contracts and production admission gates.

Treat the version matrix and a successful authenticated smoke test as release
artifacts. A green container healthcheck alone is not production acceptance.
For an unsigned bootstrap that started with unauthenticated smoke, use the
append-only closure procedure in [unsigned-bootstrap.md](unsigned-bootstrap.md)
instead of editing the original bootstrap record.
