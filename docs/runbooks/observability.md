# Observability

## Health and availability

Use these signals independently:

| Signal | Meaning | Alert threshold |
| --- | --- | --- |
| `/codex-api/v1/health/live` | API process serves requests | 2 consecutive failures |
| `/codex-api/v1/health/ready` | PostgreSQL/Redis are reachable and Alembic is at the packaged head | any failure for 2 minutes |
| `/codex/` synthetic | PWA, host Nginx, and CSP path work | 2 consecutive failures |
| authenticated exchange synthetic | Sub2API auth contract and Control session work | 3 failures outside maintenance |
| device heartbeat age | outbound Connector channel remains active | greater than 3 heartbeat intervals |

Readiness is not proof that the Sub2API `/auth/me` contract, WebSocket fanout,
or app-server integration works. Run a synthetic session exchange with a
dedicated, minimally privileged test user and never log its access token.

## Metrics

The Control API exposes a database-backed Prometheus snapshot at
`http://127.0.0.1:18090/internal/metrics` on the loopback API port. The supplied
Nginx policy returns `404` for `/codex-api/internal/*`, so this endpoint is not
part of the public same-origin surface. Scrape it from the host or a trusted
local collector using a pre-derived dedicated metrics bearer consumed through a
secret-file interface. Keep the published API port loopback-only even
though the endpoint also requires this token. It combines durable aggregate
state with process-local bounded counters, gauges, and histograms for HTTP,
session exchange, pairing, WebSockets, command transitions and latency,
idempotency, approval outcomes, RPC allowlist decisions, stale-epoch
reconciliation, expiry/retention phases, readiness dependencies, and the
SQLAlchemy pool. It never labels by user, device, thread, command, request,
prompt, or raw path. Process-local counters reset when a replica restarts;
aggregate rates by `job`, retain `instance` for diagnosis, and use durable gauges
when a restart must not erase state. The database snapshot is cached for 15
seconds and aborted after 3 seconds by default; scrape no more frequently than
the cache interval.

Derive each bearer once in a root-only provisioning context directly into a new
owner-only file. The supplied tool refuses an existing or symlink output,
creates with `O_EXCL`/`O_NOFOLLOW`, fsyncs the file and parent directory, and
never writes the bearer to stdout, argv, or an environment variable:

```sh
install -d -o 65532 -g 65532 -m 0700 \
  /var/lib/codex-control-monitoring/secrets
python3 deploy/monitoring/derive-metrics-bearer.py \
  --root-secret-file deploy/docker-compose/secrets/control_session_hmac_secret \
  --output-file /var/lib/codex-control-monitoring/secrets/control_metrics_bearer \
  --domain control-metrics \
  --owner-uid 65532 --owner-gid 65532
python3 deploy/monitoring/derive-metrics-bearer.py \
  --root-secret-file /root/provisioning/monitoring_root_secret \
  --output-file /var/lib/codex-control-monitoring/secrets/alertmanager_proxy_bearer \
  --domain alertmanager-proxy \
  --owner-uid 65532 --owner-gid 65532
python3 deploy/monitoring/derive-metrics-bearer.py \
  --root-secret-file /root/provisioning/monitoring_root_secret \
  --output-file /var/lib/codex-control-monitoring/secrets/evidence_receiver_bearer \
  --domain evidence-receiver \
  --owner-uid 65532 --owner-gid 65532
```

The production monitoring stack reads only those derived files. It must never
mount, open, or derive from `control_session_hmac_secret` at runtime. The exact
Control release must also consume the matching pre-derived metrics credential
through its secret-file interface; an entrypoint that exports the bearer into
the process environment is not production-admissible. Do not probe by putting a
bearer in `curl -H`, a curl config, an environment variable, a shell variable,
or command output. Prometheus and Alertmanager `credentials_file` are the
supported consumers. Compromise of monitoring must not disclose either root
secret.

## Hardened production stack

`deploy/monitoring/compose.yaml` is an independent Compose project.
It does not modify the application Compose, UFW, PostgreSQL, Redis, Sub2API,
Control API, or backup/restore implementation. Prometheus `3.13.2` and
Alertmanager `0.33.1` are pinned to the audited linux/amd64 manifest digests in
that file. Every service runs nonroot with a read-only root filesystem, all
capabilities dropped, `no-new-privileges`, bounded tmpfs, CPU, memory, and PID
limits. All containers use the dedicated uid/gid `65532`; strict admission must
prove the host has no account, group, or process using that identity. It
publishes no Compose ports and has no Docker socket or privileged access.

Host networking is used by Prometheus and the collector, and by the narrow
Alertmanager auth proxy. Host listeners are `127.0.0.1:19090` (Prometheus),
`:19091` (collector), and `:19093` (authenticated proxy). Raw Alertmanager
`127.0.0.1:9093`, the relay, and authenticated receiver `127.0.0.1:19094` share
an isolated network namespace and have no host listener. The proxy allows only
Prometheus alert submission, metrics, and readiness over a stable owner-only
Unix socket; it cannot reach silence or other management routes. Before
starting, run:

```sh
deploy/monitoring/verify-stack.sh --strict
docker compose --env-file /var/lib/codex-control-monitoring/monitoring.env \
  -f deploy/monitoring/compose.yaml config --quiet
```

The default verifier mode is developer-only and may skip missing tools.
Production accepts only `--strict`, where missing Ruff, promtool, Docker,
Compose, a failed image/container validation, or a uid collision is fatal.
After starting, prove with `ss -lntp` that only the three documented loopback
ports exist on the host and neither `9093` nor `19094` is host-bound. Query
`http://127.0.0.1:19090/api/v1/targets` and require
the `codex-control-api` job to contain exactly and only
`127.0.0.1:18090` and `127.0.0.1:18093`, both healthy.

### Release and VCS identity

The monitoring environment's `CONTROL_RELEASE` and `CONTROL_VCS_REF` must come
from the same immutable release admission record as the two Control API
replicas. The collector publishes that exact expected pair, and
`production-integrity.yml` fails admission if either API target omits
`codex_control_build_info`, reports any different version or VCS revision, or
the configured two-target set is incomplete. `unknown`, `unborn`, `dirty`,
placeholder VCS values, and non-hex VCS revisions fail closed.

No monitoring source-identity manifest is valid in this working tree. Generate
one only after these sources are committed at the final public HEAD and its
public source asset is built and independently hashed. Do not bind to an older
`READY.json`, `.10` candidate, pre-freeze commit, or helper image tag.
Production remains **BLOCKED** until the final public HEAD/source asset and its
new identity manifest exist.

### Fail-closed evidence collection

The loopback collector is not a probe simulator. It accepts a small allowlist of
pre-produced Prometheus text files only after verifying regular-file type,
non-symlink access, uid ownership, exact `0600` mode, size, freshness, family,
labels, and bounded label values. See `deploy/monitoring/README.md` for the
per-file contract.

Missing Connector evidence, missing authenticated session-exchange synthetic,
missing backup success/checksum evidence, and missing restore-rehearsal success
must stay absent or explicitly failing. Do not initialize these metrics to `1`,
reuse old timestamps, copy evidence from another host, or silence their absence
alerts. A green value may be published only by its real producer after the
corresponding operation completes successfully.

### Local firing and resolved evidence

The bundled Alertmanager receiver authenticates every POST with an independent
derived bearer, then writes a bounded subset to a local `O_APPEND`/fsync JSONL
file. Use the short-lived `delivery-test.prom` procedure in
`deploy/monitoring/README.md` to capture both `firing` and `resolved` records
with the same fingerprint and the freshly generated controlled nonce. The
verifier requires owner `0600`, one link, a stable ancestor/fd/name identity,
strict schema and size, and `start < firing receipt < end <= resolved receipt`.

This is local pipeline evidence only. It proves Prometheus rule evaluation,
Alertmanager routing, webhook delivery, and resolution to the same host. It is
not evidence that an external operator received, acknowledged, or acted on an
alert. `CodexControlExternalOperatorDeliveryUnconfigured` therefore remains
firing by design. Keep the production release gate open until a separately
configured, credentialed external receiver has controlled firing/resolved and
operator-delivery evidence; never treat the local receiver as satisfying it.

Release-required signals are listed below. The native `/internal/metrics`
snapshot now supplies HTTP rates and latency, session/pairing/approval outcomes,
WebSocket lifecycle, command transition/latency/idempotency, RPC allowlist
decisions, reconciliation, maintenance, readiness, pool, durable
status/outbox/heartbeat/event counts, and retained audit-row gauges. External
collectors remain mandatory for Connector
local state, public synthetics, deep PostgreSQL/Redis health, backup/restore,
and deployment policy checks. Treat any missing signal as a release gate, not
as an implied native metric.

- HTTP requests, status, latency, and body-limit/rate-limit rejections by route
  template, never raw URL query;
- active browser and device WebSockets, reconnects, bounded close outcomes, heartbeat age,
  and per-device connection replacement;
- commands created, dispatched, ACKed, expired, retried, and failed, including
  end-to-end latency and idempotency conflicts;
- approvals requested, accepted, denied, timed out, and rejected for stale
  epoch or ownership mismatch;
- Connector spool bytes/events, oldest unacknowledged age, app-server restarts,
  schema/version mismatch, and policy denials;
- PostgreSQL pool saturation, transaction failures, migration revision, backup
  age, and restore-rehearsal age;
- Redis latency, errors, evictions, memory pressure, ACL denials, and Pub/Sub
  subscriber/fanout health, especially when multiple API replicas are enabled.

Do not label metrics by user ID, device ID, thread ID, command ID, prompt text,
or request ID; those create unbounded cardinality and privacy exposure.

### Native metric contract

The exact bounded families and labels consumed by the executable rules are
listed in `deploy/monitoring/README.md`. HTTP `route` is a framework route
template or `_unmatched`, never `$uri` or `$request_uri`. WebSocket `reason` is
one of the fixed semantic values enforced by the API, such as `invalid_auth`,
`invalid_cursor`, `capacity_exceeded`, or `dependency_unavailable`; it is not a
free-form exception or peer-supplied close reason.

Initialized gauge families have absence alerts. Counters and histograms remain
sparse until their first event, so release synthetics must exercise every
domain and the resulting scrape must contain each expected `# TYPE` family.
The retained audit family is `codex_control_audit_events_retained`; it is a
gauge because retention can make the value decrease. Do not calculate event
rates from it.

For browser WebSockets, alert separately on `4401` (the durable session row is
missing, revoked, or expired), `4409` (the cursor requires a fresh bootstrap),
`4429` (the per-session or per-user connection cap is full), and `1013`
(temporary Redis/PostgreSQL failure or connection-lease admission infrastructure
failure). Clients may reauthenticate after `4401`, must bootstrap after `4409`,
and should use bounded backoff/retry after `4429` or `1013`. Repeated `1013` is an
infrastructure-health signal, not an authentication-failure signal.

### External collector contract

Load `deploy/monitoring/prometheus/external-alerts.yml` only with the normalized
collector contract in `deploy/monitoring/README.md`. Its absence alerts are
intentional: they keep an unwired collector from looking healthy. Production
still requires all of the following:

- blackbox or equivalent probes for liveness, readiness, the PWA, and an
  authenticated session exchange;
- PostgreSQL and Redis exporters plus checks for the dedicated database role,
  Redis ACL isolation, memory/evictions, and multi-replica Pub/Sub fanout;
- an Alembic current-versus-packaged-head deployment probe;
- backup checksum and last-success publication, plus a timestamp only after a
  complete isolated restore rehearsal passes migrations and smoke tests;
- a trusted host-local node-exporter textfile collector reading the Connector's
  private atomic `state_dir/connector.prom` for process freshness, reconnect
  reasons, spool bytes/events/capacity/oldest age, app-server restarts,
  version/schema mismatch, and policy denials;
- a secret-file mode policy check.

The Connector updates its textfile independently every 15 seconds and
coalesces state-change notifications to at most one rewrite per second without
opening a listener or touching `CODEX_HOME`. Counter increments are fsynced
before their recording calls return; contract failures persist their bounded
last-failure timestamp in the same atomic state. Policy-denial replay is
deduplicated through private SHA-256 command receipts with a 4096-entry,
24-hour horizon. Expired receipts are pruned at startup after the command
journal and lazily on a later distinct denial; they are not exported. Configure
the collector as the same owner or an explicitly trusted privileged service
because `state_dir` is `0700` and both metrics files are `0600`; use
`job="codex-control-connector"` for the supplied inventory rules. A graceful
exit publishes `up 0`; after a hard kill, the retained `up 1` is stale, so
`codex_control_connector_last_update_timestamp_seconds` must remain within 60
seconds of Prometheus time. The supplied down alert rejects both stale and
implausibly future timestamps.

The fixed label sets are reconnect `reason` = `token`, `dial`, `handshake`, or
`connection_io`; app-server restart `reason` = `start_failure`,
`notification_failure`, or `child_exit`; contract `kind` = `version` or
`schema`; and policy denial `reason` = `command`. The collector must not export
raw Go errors, app-server stderr, device identifiers, paths, URLs, pairing
material, prompts, outputs, or credentials.

## Logs

`deploy/nginx/http-context.conf` defines a JSON format that logs `$uri`, not
`$request_uri`, so query tokens/cursors are excluded, and it omits Referer and
User-Agent. Each controlled location in `server-locations.conf` enables that
format, overriding any inherited host access log. Do not configure a second
access log in those locations because Nginx would write both. The format records
request and upstream timing, status, bytes, and the validated upstream request
ID.
The exact `/codex-ws` route and final `^~ /codex` guard use the same dedicated
log, so no `/codex*` request can inherit a parent `combined` format. Provision
the host file and `/etc/logrotate.d/codex-control-access` with
`deploy/scripts/provision-nginx-access-log.sh`: the file is `www-data:adm`
`0640` under the dedicated `root:root` mode-`0755` directory
`/var/log/sub2api-codex-control`. It rotates daily or at 10 MiB with 14 retained
compressed files, and the post-rotation hook sends `USR1` only after verifying
the Nginx master identity. Validate one forced rotation and a correlated request
as described in the deployment runbook.

This guarantee is scoped to the dedicated access log. Nginx error messages can
include the complete request target, including its query string, when proxying,
rate limiting, request parsing, or other exceptional paths fail. Never put
credentials or reusable secrets in query parameters, restrict and rotate the
host error log, and treat it as sensitive operational data. The access-log
redaction policy does not sanitize an inherited or separately configured
`error_log`.
Container logs rotate at 10 MiB with five files as a local safety bound; ship
them to centralized storage before rotation.

Application and Connector logs must never include:

- `Authorization`, `Cookie`, `Set-Cookie`, CSRF, poll, device, or refresh token
  values;
- raw Sub2API provider keys or access/refresh tokens;
- Connector private keys, pending pairing codes, poll tokens, refresh
  credentials, signed nonces, or approval secrets. The Connector may report the
  private `pairing-code.json` path, but never the code value; the file is removed
  when the attempt ends and access to `state_dir` must remain restricted;
- prompt/output bodies marked sensitive or arbitrary app-server stderr.

Use stable event names and fields: timestamp, severity, component, release,
request ID, command ID, device ID hash, app-server epoch hash, outcome, reason,
and duration. Hash identifiers with an operations-only key if correlation is
needed. Keep security audit records in PostgreSQL; centralized logs are not the
authoritative audit ledger.

Recommended retention is 14 days for high-volume request logs, 30-90 days for
operational events, and the policy-required period for immutable audit events.
Access to device/approval logs should be narrower than general service logs.

## Alert catalog

Executable recording and alerting rules are in
`deploy/monitoring/prometheus/native-alerts.yml` and
`deploy/monitoring/prometheus/external-alerts.yml`. They cover scrape freshness,
immutable release identity, five-percent HTTP 5xx, auth/pairing rejection
surges, browser WebSocket admission and dependency failures, stale heartbeat and
outbox ACKs, command terminal failures and idempotency conflicts, approval
default-deny/stale-epoch outcomes, prohibited RPC attempts or acceptance,
failed/stale or batch-saturated maintenance, reconciliation, dependency
readiness, database pool saturation, synthetics, datastore availability, Redis
eviction/memory, migration match, backup/restore, infrastructure policy, and
Connector health.

No correct rate alert can be derived from the retained audit-row gauge. Native
approval and RPC-policy counters now cover timeout, stale epoch,
not-found-or-not-owned decisions, denied prohibited-RPC attempts, and the
expected-zero prohibited/accepted state. Actual duplicate execution still needs
Connector-side evidence rather than treating an idempotency conflict as a
duplicate. Connector evidence and every unwired external collector remain
production release gates.

The default thresholds implement the initial policy:

- any database migration failure or schema revision mismatch;
- readiness failure for 2 minutes, or five-percent HTTP 5xx for 5 minutes;
- authentication exchange 401/403 spike above established baseline;
- any successful request to a prohibited RPC family (expected value is zero);
- approval timeout/denial surge, stale-epoch response, or duplicate command
  execution;
- device reconnect loop, heartbeat age over 60 seconds, spool over 70 percent,
  or app-server crash loop;
- backup older than 8 hours, checksum failure, or restore rehearsal overdue;
- Redis eviction, ACL change, PostgreSQL role escalation, or secret-file mode
  wider than `0600`.

Every alert must link to the release matrix row, recent deploy event, and a
request/command correlation path that does not expose credentials.

Set the Prometheus external labels `deploy_event_url` and `log_search_url` to
access-controlled destinations. The log-search entry point must require the
operator to add a request ID or command ID; the alert itself carries neither an
unbounded identifier nor a credential.

Verify rule syntax and threshold behavior with the same `promtool` major version
used in production:

```sh
deploy/monitoring/verify-rules.sh
```

This runs `promtool check rules` for both files and the deterministic unit tests
in `deploy/monitoring/prometheus/tests/alerts.test.yml`. Before release, also
record Prometheus target health, rule evaluation health, a controlled
firing/recovery delivery, the current deploy link, and evidence that no
`release_gate` alert is pending or firing.
