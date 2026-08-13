# Image-only follow-up for the unsigned bootstrap

This runbook replaces only the running Control API and PWA image IDs after the
one-time unsigned bootstrap has been closed. It is not another bootstrap, a
database deployment, a backup operation, or a general Compose upgrade. The
only permitted persistent changes are recreation of, in order,
`control-api-replica`, `control-api`, and `codex-pwa` with the already admitted
image IDs.

The final record must validate against
[`image-rollout-record.schema.json`](../../deploy/schemas/image-rollout-record.schema.json).
It is a new append-only sibling record with
`type=bootstrap-image-only-followup-v1`; it never edits or replaces the original
`bootstrap-deployment.json` or `authenticated-smoke-closure.json`.

## Hard boundary

The operator explicitly prohibited a duplicate backup. Do not invoke a backup
wrapper, the `control-backup` service, `pg_dump`, a snapshot command, or any
command whose side effect is a backup. Record this narrow exception as
`operator_exception.type=no-duplicate-backup-operator-instruction-v1`, with
`backup_created=false` and `backup_command_run=false`. Existing historical
backup evidence remains historical and is not relabelled as current.

This rollout also must not:

- run `control-migrate`, Alembic, DDL, DML, Redis writes, or secret rotation;
- run `docker compose down`, `docker compose pull`, `docker pull`, a build, an
  unscoped `docker compose up`, or load any image outside the three exact
  verified archives;
- stop or recreate PostgreSQL, Redis, Sub2API, the dashboard, or any unrelated
  container;
- edit or reload Nginx, edit UFW, or change host listeners, networks, volumes,
  mounts, ACLs, routes, or firewall rules; or
- reuse an old rollout directory, overwrite evidence, or write generated files
  into the admitted source tree.

Load exactly the three verified API, PWA, and PostgreSQL-tools archives from the
admitted bundle, then bind their resulting image IDs to the verified bundle and
source before any service recreation begins. No fourth archive or registry
reference is permitted.
`pull_policy=never`, `--pull never`, `--no-build`, and `--no-deps` are mandatory
for every service recreation and rollback command, and every recreation must
also use `--force-recreate`.

## 1. Bind the closed baseline

Create a new unpredictable directory such as
`/secure/codex-control/image-rollouts/image-rollout-<UTC>-<UUID>` with owner
`root:root` and mode `0700`. Creation must fail if the path already exists. Do
not place it under the original bootstrap directory and do not copy a previous
rollout record into it.

Before touching a container, validate the original bootstrap record and its
append-only authenticated-smoke closure with their respective schemas and
closure verifier. Require all of the following:

- the original record is `bootstrapped-unsigned`;
- the closure is `authenticated-smoke-closed`, closes the original pending
  smoke, and records `original_bootstrap_record_mutated=false`;
- the paths, sizes, and SHA-256 values of both files are captured in
  `base_bootstrap`; and
- neither baseline file changes between preflight and final publication.

A missing, mutable, mismatched, or not-yet-closed baseline is a hard stop. Never
"fix" it in place and never publish rollout evidence into that old record.

## 2. Prove bundle, source, and image identity

Use only the independently verified bundle and the admitted root-owned,
read-only source directory. Record the bundle path, ID, release, transport and
manifest SHA-256 values, and its verification-record descriptor. Re-run the
trusted verifier against the literal admitted source path and record the source
identity plus verification evidence.

Production helpers must execute from that literal verified path with a clean
interpreter environment:

```sh
env -u PYTHONHOME -u PYTHONPATH \
  PATH=/usr/sbin:/usr/bin:/sbin:/bin \
  PYTHONDONTWRITEBYTECODE=1 \
  PYTHONNOUSERSITE=1 \
  PYTHONSAFEPATH=1 \
  /usr/bin/python3 -I /opt/sub2api-control/<source-id>/source/<helper> ...
```

Before and after the rollout, hash the canonical source projection and require
the hashes to match. Both scans must find zero `__pycache__` directories,
`*.pyc`, and `*.pyo` files. Any source mutation fails the rollout; do not clean
it up and pretend the tree was pristine.

Verify the recorded SHA-256 of each of the three archive files immediately
before loading it. Run `docker load --input` exactly once for each admitted API,
PWA, and PostgreSQL-tools archive, then inspect the resulting `linux/amd64`
image IDs without using a registry. Record the three archive descriptors and
all six IDs under `images.old` and `images.new`: API, PWA, and PostgreSQL tools.
Every new ID must differ from its corresponding old ID, and the three new IDs
must be distinct. The PostgreSQL-tools image is loaded and inspected for bundle
closure only; it must not be executed during this rollout.

## 3. Freeze the Compose and invariant projections

Derive a private rollout Compose snapshot from the active bootstrap snapshot.
The allowlist of differences is exact:

- the API image may change for `control-migrate`, `control-api`, and
  `control-api-replica`;
- API `CONTROL_BUILD_VERSION`, `CONTROL_BUILD_VCS_REF`, and OCI version/revision
  labels may change consistently with the admitted release and source;
- the PWA image and OCI version/revision labels may change for `codex-pwa`;
- the PostgreSQL-tools image and OCI version/revision labels may change for
  `control-backup`; and
- no other field may change.

The project name, service set, commands, profiles, ports, networks, volumes,
secrets, security settings, and every field outside that allowlist must be
byte-for-byte or structurally identical. Store and hash both snapshots outside
the source tree. The wider five-service config allowlist does not authorize
starting `control-migrate` or `control-backup`; forward recreation remains
limited to the three running services below.

Capture deterministic, secret-free preflight projections for:

- PostgreSQL container/image/config identity and the Control database Alembic
  revision read in an explicitly read-only transaction;
- Redis container/image/config identity, ACL projection, and bounded Control
  namespace counts without reading values;
- Sub2API container/image/config identity and health;
- the effective Nginx configuration, master PID/restart counter, and managed
  file hashes; and
- UFW status and normalized rule hashes.

Do not capture environment-variable values, secret bytes, tokens, credentials,
request bodies, or user identifiers. Check all seven production containers are
healthy and record each target's full old container and image ID. Ensure neither
deployment lock exists before proceeding. A preflight mismatch is recorded as
a failed rollout with an empty, successful rollback; it does not authorize a
mutation.

## 4. Roll out one service at a time

Use the private image-only Compose snapshot and the existing project name. For
each step, the only permitted mutation command has this shape:

```sh
docker compose --project-name sub2api-codex-control \
  --profile multi-instance \
  --file "$rollout_compose" \
  up -d --wait --no-deps --force-recreate --no-build --pull never <one-service>
```

Execute exactly this order:

1. `control-api-replica`
2. `control-api`
3. `codex-pwa`

After every step, require exactly one new target container ID, the expected new
image ID, `healthy` state, zero restart failures, the original loopback binding,
and a successful target readiness request. The replica check is a direct
loopback request to port `18093`; it is not evidence that public Nginx traffic
uses the replica. Prove all non-target container IDs and all invariant
projections are unchanged before continuing. Never run both API services in one
Compose command, and never let Compose start `control-migrate` through a
dependency.

Once all three stages pass, run the bounded production smoke suite. Through the
existing public edge it must cover PWA readiness, primary API routing,
browser-WebSocket routing, adjacent-path denial, logout behavior, and the
authenticated no-device catalog when credentials are supplied out of band.
Verify replica readiness separately and directly on loopback port `18093`; do
not claim the current Nginx upstream sends public requests to the replica.
The smoke artifact must contain no credential, token, cookie, user ID, private
path, or request body. A successful record requires a non-empty smoke evidence
descriptor and zero failed checks.

Recompute every preflight projection, the database revision, source-tree hash,
and baseline record hashes before publication. PostgreSQL, Redis, Sub2API,
Nginx, and UFW must each have equal before/after projection SHA-256 values. The
database revision must also be identical and `migration_run=false`.

## 5. Failure and reverse rollback

Any failed health, readiness, smoke, identity, source-pristine, or invariant
check stops forward rollout. Roll back every service that may have been
recreated, in the exact reverse subset of the forward order:

1. `codex-pwa`, if its stage was attempted;
2. `control-api`, if its stage was attempted;
3. `control-api-replica`, if its stage was attempted.

Use a separately hashed rollback Compose snapshot containing the original image
IDs and the same one-service command shape with `--no-deps --force-recreate
--no-build --pull never`. Do not use `down`, restore a backup, run a migration,
reload Nginx, or change UFW as part of rollback. After each reverse step, require a new container
using the exact old image ID, healthy state, original loopback binding, and
readiness. Continue recording the reverse sequence even if a rollback step
fails; an incomplete rollback must have `rollback.status=failed` and remains an
operator incident rather than permission for broader recovery commands.

A failure before any container mutation records `rollback.status=succeeded`,
an empty rollback step array, and unchanged invariants. A failure after mutation
records every attempted reverse step and an evidence descriptor. Never delete
the failed record or reuse its rollout ID for a retry.

## 6. Publish one append-only terminal record

Publish exactly one terminal `image-rollout-record.json` in the new rollout
directory. Build it under a private temporary name, validate it with Draft
2020-12 JSON Schema including format checking, `fsync` it, and publish with an
OS-level no-replace operation. Then `fsync` the directory and re-read the bytes
and SHA-256. A pre-existing terminal name is a hard conflict; do not truncate,
unlink, rename over, or amend it.

For `status=succeeded`, all three fixed `steps` are `succeeded`, smoke is
`passed`, every invariant is unchanged, and `rollback` is JSON `null`. For
`status=failed`, `completed_at` is still mandatory, forward steps form a valid
prefix ending in `failed` (or all succeeded when a later check failed), and a
rollback object with `status=succeeded|failed` is mandatory.

Validate a completed record with an isolated interpreter, for example:

```sh
env -u PYTHONHOME -u PYTHONPATH \
  PYTHONDONTWRITEBYTECODE=1 PYTHONNOUSERSITE=1 PYTHONSAFEPATH=1 \
  /usr/bin/python3 -I - <<'PY' "$schema" "$record"
import json
import sys

from jsonschema import Draft202012Validator, FormatChecker

schema = json.loads(open(sys.argv[1], encoding="utf-8").read())
record = json.loads(open(sys.argv[2], encoding="utf-8").read())
Draft202012Validator.check_schema(schema)
Draft202012Validator(schema, format_checker=FormatChecker()).validate(record)
PY
```

Schema validation is necessary but not sufficient: the rollout wrapper must
also compare paired hashes/IDs, enforce timestamp ordering and smoke counts,
bind rollback entries to the services actually attempted, reject duplicate JSON
keys, and perform the filesystem ownership/link/no-replace checks that JSON
Schema cannot express.
