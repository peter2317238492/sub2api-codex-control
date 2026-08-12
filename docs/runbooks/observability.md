# Observability

The first public repository version is source-only. The metrics implementation
and rule files can be tested from source, but production monitoring remains a
release gate until signed artifacts, real target reachability, and controlled
alert delivery have all been verified for one admitted revision.

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
local collector using the bearer token derived by the container entrypoint from
the file-backed session secret. Keep the published API port loopback-only even
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

For a one-time local verification, derive the bearer token without printing the
session secret, place the header in a private temporary curl configuration, and
remove it immediately afterward. Substitute the admitted external secret path;
never read production secrets from the source checkout:

```sh
umask 077
metrics_curl_config=$(mktemp "${TMPDIR:-/tmp}/codex-control-metrics.XXXXXX")
trap 'rm -f -- "$metrics_curl_config"' EXIT HUP INT TERM
CONTROL_SESSION_HMAC_SECRET_FILE=/secure/codex-control/secrets/control_session_hmac_secret \
METRICS_CURL_CONFIG="$metrics_curl_config" python3 -c '
import hashlib
import hmac
import os
import pathlib

secret = pathlib.Path(os.environ["CONTROL_SESSION_HMAC_SECRET_FILE"]).read_bytes().rstrip(b"\r\n")
token = hmac.new(secret, b"control-metrics-v1", hashlib.sha256).hexdigest()
quote = chr(34)
pathlib.Path(os.environ["METRICS_CURL_CONFIG"]).write_text(
    f"header = {quote}Authorization: Bearer {token}{quote}\n", encoding="utf-8"
)
'
curl --config "$metrics_curl_config" --fail --silent --show-error \
  http://127.0.0.1:18090/internal/metrics
rm -f -- "$metrics_curl_config"
trap - EXIT HUP INT TERM
unset metrics_curl_config
```

For continuous scraping, provision an equivalent private token file directly
to the trusted local collector instead of deriving it for every scrape.

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
