# Operations runbooks

The first public repository version is source-only. Production installation is
blocked until one exact source revision has a complete signed Control image and
Connector evidence set. These runbooks define the gates that a future release
must satisfy; they do not turn a local build into an admitted release.

- [Deployment](deployment.md): topology, immutable release admission,
  datastore isolation, Nginx, firewall, and acceptance.
- [Backups and rollback](backups-and-rollback.md): non-duplicative recovery
  checkpoints, restore rehearsal, rollback, and secret rotation.
- [Observability](observability.md): health signals, metrics, redacted logs,
  retention, and alerts.
- [Connector release policy](connector-release-policy.md): reproducible source
  builds, platform signing, provenance, staged updates, and rollback.
- [Version matrix](version-matrix.md): pinned contracts and release blockers.
- [OCI archive portability](oci-archive-portability.md): offline image transport
  identity and daemon mapping rules.

A healthy container or a ready endpoint is never sufficient acceptance. A
release also needs authenticated same-origin HTTP, browser WSS, device WSS, a
real Connector against the pinned Codex version, approval, reconnect,
revocation, logout, and recovery evidence.
