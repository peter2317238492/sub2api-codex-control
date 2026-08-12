# Deployment runbook

## Scope and release status

The deployment adds Control API and PWA sidecars to an existing Sub2API
environment. It does not replace, patch, or reconfigure Sub2API. The Connector
runs on each user device and initiates outbound WSS; no inbound device port is
required.

The first public repository version is source-only. No supported signed
Control image set or prebuilt Connector has been published, so the production
procedure is **blocked at release admission**. This runbook defines the future
boundary. It does not authorize production use of local builds, mutable tags,
or hand-written evidence.

## Topology

Only the Control API joins the existing external Sub2API network. The PWA uses
a dedicated bridge and publishes only a loopback port to host Nginx.

| Public route | Loopback upstream | Internal route |
| --- | --- | --- |
| `/codex/` | `127.0.0.1:18091` | `/codex/` |
| `/codex-api/` | `127.0.0.1:18090` | prefix stripped to `/` |
| `/codex-ws/browser` | `127.0.0.1:18090` | `/ws/browser` |
| `/codex-ws/device` | `127.0.0.1:18093` | `/ws/device` |

The second API is the deterministic device-WebSocket replica. Port `18092` is
reserved for the disposable E2E smoke edge and is not a production proxy.

## Admission prerequisites

Do not begin a production change until one exact source revision has:

- signed, digest-pinned `linux/amd64` Control API, PWA, and PostgreSQL-tools
  images;
- verified Sigstore workflow identity, provenance, SBOMs, source identity, and
  migration-head binding;
- a supported Connector release with platform signature/notarization where
  applicable, provenance, SBOM, and passing consumer verification;
- the exact Codex CLI and app-server schema recorded in `versions.lock.json`;
- an immutable Sub2API image and fresh authentication-contract evidence as
  defined in [the runtime contract](../contracts/sub2api-runtime.md);
- a private PostgreSQL role/database and Redis ACL user/prefix for Control;
- a valid TLS certificate for one exact origin such as
  `https://control.example.com`;
- one complete, verified recovery point for the change window;
- a reviewed Nginx integration and minimal host firewall policy;
- a plan to verify authenticated HTTP, browser WSS, device WSS, real Connector,
  approval, reconnect, revocation, logout, monitoring, and restore.

Every secret, release record, recovery artifact, Compose environment file, and
acceptance report belongs in a private path outside the source checkout.

## Trusted release staging

Privileged or production commands must execute only from an immutable,
root-owned staging tree extracted from the reviewed signed source release. The
installed release consumer must verify the artifact before extraction and bind
the extracted source manifest to the same signed revision before admission.
The verifier itself and every ancestor directory must be trusted, root-owned,
and not group or world writable.

Never execute a production script from a mutable Git checkout. Never edit the
staged tree, reuse a revision directory for different bytes, or substitute a
locally built image for a missing signed digest. Keep the active revision
pointer root-owned and read-only. A structural archive check without extracted
source binding is not production admission.

## Immutable Sub2API gate

The verifier admits only `immutable-image-v1`: exact digest reference and image
ID, read-only root filesystem, empty Docker diff, one identity-bearing Docker
volume at `/app/data`, exact network alias, and a stable container ID across
the check. There is no mutable-runtime compatibility exception.

Fresh authentication evidence must be generated from the admitted Control API
image in the verified Sub2API network namespace. Use disposable private token
files; raw tokens and token hashes must not enter evidence, environment
metadata, command arguments, logs, or Git.

## Recovery checkpoint

Use the signed release's single deployment entry point to create and bind the
required recovery evidence. Do not run a separate manual full snapshot and
then ask the wrapper to create the same snapshot again. The admitted workflow
has two different records:

- one comprehensive pre-change recovery point covering the existing service
  state and host integration;
- one narrow Control PostgreSQL dump at the migration boundary, created only
  after the Control database exists and immediately before schema migration.

These are not interchangeable. If a failed attempt made no protected-state
change and both records remain current and valid, stop for review instead of
blindly duplicating them. If state changed or a record is incomplete, create a
new identified change window rather than overwriting evidence. See
[Backups and rollback](backups-and-rollback.md).

## Datastore isolation

Generate the three Control secrets into mode-`0600` files in a mode-`0700`
private directory. Do not place their values in Compose environment variables
or image metadata.

The PostgreSQL provisioner requires a dedicated non-superuser,
non-inheriting, membership-free role and a separately owned Control database.
`PUBLIC` must have no database or schema privilege, and the Control role must
be unable to connect to the Sub2API database. PostgreSQL database numbers or
schema names alone are not authorization boundaries.

The Redis provisioner requires a dedicated ACL user restricted to the exact
Control key and Pub/Sub prefix. `ACL SAVE` must succeed, and an actual
cross-prefix operation must be rejected. A Redis database number is not an
authorization boundary.

## Compose and release entry point

The private environment file starts from
`deploy/docker-compose/.env.example`. Replace every placeholder, keep
`CONTROL_PUBLIC_ORIGIN` to one HTTPS origin, keep every published address at
`127.0.0.1`, and use immutable image digest references. Production combines
`compose.yaml` with `compose.production.yaml`, which removes local build
definitions and disallows pulling an unverified replacement.

Do not invoke migrations or `docker compose up` directly. Once a supported
release exists, `deploy/scripts/deploy-production.sh` is the only admitted
entry point. It must verify the release evidence before resolving Compose,
then bind the runtime, auth evidence, recovery records, migration, running
container identities, and final smoke output under one deployment lock.

The script's presence in source is not permission to bypass its missing trust
inputs. A local E2E report is not signed release evidence.

## Nginx integration

Install the reviewed files from `deploy/nginx/` into a root-owned directory
outside the checkout. Include `http-context.conf` once inside the global Nginx
`http` block and `server-locations.conf` once inside the existing HTTPS server
for `control.example.com`.

The policy must preserve these properties:

- exact same-origin browser WebSocket checking;
- body, request-rate, and connection limits;
- loopback-only upstreams and overwritten forwarding headers;
- `404` for `/codex-ws`, unknown WebSocket paths, internal metrics, and
  adjacent or malformed `/codex*` paths;
- CSP and strict browser/API response headers;
- a dedicated access-log format that omits query strings, Referer, and
  User-Agent;
- a dedicated root-owned log directory, private log file, exact logrotate
  target, and verified Nginx master reopen after rotation.

The response-buffer include applies at HTTPS server context so large upstream
logout headers do not produce a proxy error. It must not change routing,
logging, caching, forwarding, or upgrade behavior.

Before reload, test the complete Nginx configuration. After reload, probe every
public and rejected route, inspect the effective configuration, exercise one
log rotation/reopen, and confirm a nonce-bearing request produces one redacted
JSON line without appearing in another inherited access log. Query parameters
must never carry credentials; exceptional Nginx error paths may include a full
request target and the error log requires separate protection.

## Firewall and listeners

Publicly permit TCP `443`. Permit TCP `80` only for a required redirect or ACME
challenge. Restrict SSH to an administrative source range. Do not expose
`18090`, `18091`, `18092`, `18093`, PostgreSQL, or Redis. Verify that each
Control port is bound to `127.0.0.1` after every deployment. Connectors require
outbound HTTPS/WSS only.

See [Operations](../operations.md#public-and-private-ports) for an illustrative
UFW policy. Adapt it without deleting unrelated required host rules.

## Acceptance

A release is accepted only when all evidence refers to the same revision and
origin. At minimum verify:

1. exact signed image and running container identities, read-only/capability
   restrictions, migration head, and no secrets in container metadata;
2. liveness and readiness on both loopback API instances plus PWA delivery;
3. authenticated same-origin session exchange, renewal, CSRF, revocation, and
   coordinated logout with no credential disclosure;
4. browser and device WSS, a real ordinary-user Connector, the pinned Codex
   app-server, one admitted RPC, dangerous-method denial, and approval
   default-denial;
5. replica loss/reconnect, token revocation, device revocation, and command
   idempotency;
6. Nginx route rejection, header policy, log redaction, rotation/reopen, UFW,
   and loopback listener state;
7. current monitoring targets, controlled alert fire/recovery, backup checksum,
   and restore rehearsal.

`/health/ready` proves only the dependencies implemented by that endpoint. It
does not prove authentication, WSS, Connector, Codex, or release identity. The
isolated E2E harness uses mock Sub2API and fake Codex and cannot close these
production gates.

## Upgrade and removal

Never change a digest, binary, schema, migration head, or lock file in place
under an existing release identifier. Admit a new signed revision, retain the
prior one until acceptance, and use a tested rollback path.

Removal must target only Control containers, Nginx includes, user Connectors,
and Control-specific scheduler entries. Retain databases, Redis state, secrets,
release records, and recovery evidence by default. Do not remove the external
Sub2API services, Docker network, shared TLS configuration, or generic firewall
rules used by other applications.
