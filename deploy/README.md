# Deployment assets

- `docker-compose/compose.yaml` adds the Control API and PWA to the configurable
  external Sub2API network. PostgreSQL and Redis remain external shared
  services but use a dedicated login/database and ACL user/prefix.
- `dockerfiles/` contains non-root, read-only-compatible runtime images plus a
  PostgreSQL backup image and an optional smoke-test edge.
- `nginx/` contains the host Nginx `http` and HTTPS `server` includes, strict
  browser/API headers, and PWA/static configs for the dedicated bridge.
- `scripts/` generates file-backed secrets, provisions datastore isolation,
  binds signed release inputs, verifies immutable Sub2API/auth evidence from the
  target container network namespace, creates a fail-closed full production
  snapshot before the first datastore/Nginx/auth mutation, creates a second
  checksummed Control database dump before migration, maps transported OCI image
  archives to both manifest- and config-digest daemon identities, and provides
  the only admitted production deployment entry point.

Start with [the deployment runbook](../docs/runbooks/deployment.md). Do not use
the smoke-edge profile as the public production proxy; it exists only to test
the same route include against local disposable services.

Local tests use `docker-compose/compose.yaml`. Production must additionally use
`docker-compose/compose.production.yaml` through
`scripts/deploy-production.sh`; invoking migration or service startup directly
bypasses required signed-release, runtime, backup, and revision gates.

## Local unsigned bootstrap bundle

Run this workflow only from a frozen source tree: no file may change from the
initial source scan through final publication. Set `BUNDLE_OUTPUT_ROOT` to a
private absolute directory outside this repository and `SOURCE_DATE_EPOCH` to
the Unix epoch assigned to that frozen source, then run from the repository
root:

Before freezing, move every historical generated file under
`tests/e2e/reports/` into a private evidence directory outside the repository;
leave only its tracked documentation/ignore placeholders. Set
`CONTROL_E2E_REPORT_DIR` to that external directory for subsequent E2E runs.
The builder rejects generated report content that remains in the source tree;
it does not silently include or exempt it.

```sh
python3 deploy/scripts/build-unsigned-bootstrap-bundle.py build \
  --repo-root "$PWD" \
  --output-root "$BUNDLE_OUTPUT_ROOT" \
  --release 0.1.0-bootstrap.20260812.5 \
  --source-date-epoch "$SOURCE_DATE_EPOCH"
```

To also produce fixed-size transport parts, append
`--split-size-mib 1024` (or another positive MiB size) to that command. The
builder creates exactly the Control API, PWA, and PostgreSQL-tools
`linux/amd64` image archives and publishes a private unsigned bundle. It does
not produce signed-release evidence. Publication is complete only when the
external `production-bootstrap-<bundle-id>.READY.json` marker exists beside the
artifact directory; if it is absent, treat every output for that bundle ID as
incomplete and do not admit or transport it.

For offline verification, set `BUNDLE_DIR` to the emitted
`artifact_directory`, change into it, and run the verifier shipped in the
bundle:

```sh
cd "$BUNDLE_DIR"
python3 ./verify-unsigned-bootstrap-bundle.py verify-archive --bundle . \
  --bundle-trust-anchor .
```

`verify-archive` validates the complete bundle and canonical source archive but
reports `"admission":false`; it is the required pre-extraction structural gate,
not production admission. To bind verification to an extracted source tree,
use the production command below. It requires `--source-root` and accepts only a
root-owned normalized tree whose trusted ancestor chain is not group or world
writable:

```sh
python3 ./verify-unsigned-bootstrap-bundle.py verify \
  --bundle . \
  --bundle-trust-anchor / \
  --source-root /absolute/path/to/extracted/source
```

Build and verification are local-only operations: they must not access the
production host, deploy services, or run a backup. The required production data
backup is already complete; do not repeat it as part of this workflow.
