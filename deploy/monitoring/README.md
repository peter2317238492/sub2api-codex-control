# Monitoring artifacts

This directory contains the executable rules and a standalone, hardened
production monitoring stack. It is deliberately separate from the Control
deployment: do not merge it into the root Compose project, grant it Docker
socket access, or use it to alter Nginx, UFW, PostgreSQL, Redis, Sub2API, the
Control API, or backup jobs.

The stack pins linux/amd64 Prometheus `3.13.2` and Alertmanager `0.33.1` by
platform manifest digest. Its network boundary is deliberately asymmetric:

| Port | Process |
| --- | --- |
| `127.0.0.1:19090` | Prometheus |
| `127.0.0.1:19091` | fail-closed evidence collector |
| `127.0.0.1:19093` | authenticated, allowlisted Alertmanager proxy |
| isolated netns `127.0.0.1:9093` | raw Alertmanager API; not host reachable |
| isolated netns `127.0.0.1:19094` | authenticated local evidence receiver; not host reachable |

All services run as the dedicated uid/gid `65532`, with a read-only root filesystem,
`cap_drop: ALL`, `no-new-privileges`, bounded tmpfs, CPU, memory, and PID
limits. The Compose file has no `ports`, `expose`, Docker socket, or privileged
mode. Strict verification refuses a host account, group, or process already
using `65532`; reserve this identity exclusively for monitoring. Run
`verify-stack.sh --strict` before any production installation. The default mode
is only a developer convenience and may skip unavailable container checks.

The Python helpers are a controlled local build, not an immutable registry
artifact. Their Dockerfile pins the exact linux/amd64 base manifest. The helper
image tag and OCI label must equal the canonical SHA-256 closure of
`.dockerignore`, `helper.Dockerfile`, `common.py`, `alertmanager-proxy.py`,
`collector/collector.py`, and `evidence-receiver/receiver.py`;
`verify-stack.sh` computes it, builds the image, checks the label, and compares
all four embedded source-file hashes. Record
the resulting local image ID with release evidence. A later registry promotion
must replace this closure with a signed immutable image digest.

## Production inputs

Copy `.env.example` to a host-private environment file and replace every
placeholder. `CONTROL_RELEASE` and `CONTROL_VCS_REF` must be copied from the
same admitted release record used to configure both Control API replicas. The
collector rejects placeholder/non-hex VCS values at startup. Prometheus then
requires both exact targets, `127.0.0.1:18090` and `127.0.0.1:18093`, to export
the exact same `codex_control_build_info{version,vcs_ref}` pair.

Three credentials are required: Control metrics, the Alertmanager proxy, and
the evidence receiver. They are domain-separated and stored in different
`0600` files. Use `derive-metrics-bearer.py --root-secret-file ... --domain ...`
in a root-only, short-lived provisioning context. The tool writes directly to
a new file with no bearer on stdout, argv, or in the environment. The
long-running collector and monitoring containers never mount or read the
Control session HMAC. Prometheus and Alertmanager consume only the derived
files through `credentials_file`; the proxy and receiver read only their own
files. Never reuse a receiver or proxy bearer as the metrics bearer.

The raw Alertmanager API listens at `127.0.0.1:9093` inside its private network
namespace. A same-namespace relay owns a `0600` Unix socket in a dedicated
`0700` bind directory. The host-network proxy mounts that directory read-only,
authenticates its own bearer, and permits only `POST /api/v2/alerts`,
`GET /metrics`, and `GET /-/ready`. Silence and all other management routes are
unreachable through it. The receiver shares the isolated namespace and requires
a separate bearer on every webhook POST.

The collector accepts only fixed source filenames, metric families, labels,
label values, owner/mode, size, and freshness windows. Invalid, missing, stale,
future-dated, symlinked, group-readable, or unknown evidence is omitted and
reported as `codex_control_monitoring_evidence_file_valid{source=...} 0`.
Importantly, it never invents success for Connector state, authenticated
session exchange, backup, or restore rehearsal. Until real producers atomically
publish valid evidence, the existing absence/failure alerts stay active.

The optional evidence files are:

| File | Maximum age | Producer |
| --- | --- | --- |
| `synthetics.prom` | 180 seconds | public and authenticated synthetic runner |
| `infrastructure.prom` | 300 seconds | datastore, migration, and policy checks |
| `backup.prom` | 300 seconds | backup scheduler after checksum success |
| `restore.prom` | 300 seconds | isolated restore rehearsal after complete success |
| `connector.prom` | 60 seconds | Connector's existing atomic textfile writer |
| `delivery-test.prom` | 120 seconds | operator-controlled local delivery test only |

Each file and the two host directories must be owned by uid/gid `65532`; files
are exactly `0600`, single-link regular files and directories are `0700`.
Every ancestor must be root/65532-owned, non-symlinked, and not group/other
writable. A root-run producer must explicitly `chown 65532:65532` before the
final rename. Producers should write a `0600` temporary file in the same
directory, fsync it, atomically rename it, and fsync the directory. The
collector fixes the mounted directory's device/inode identity at startup and
returns `503` if it changes.

Prometheus and Alertmanager data use explicit host bind directories, not
implicitly root-owned named volumes. Before startup create the evidence,
delivery-evidence, Prometheus, Alertmanager, and secrets directories under
`/var/lib/codex-control-monitoring` as `65532:65532` mode `0700`.

Production verification is strict and must complete before any start command:

```sh
deploy/monitoring/verify-stack.sh --strict
docker compose --env-file /var/lib/codex-control-monitoring/monitoring.env \
  -f deploy/monitoring/compose.yaml config --quiet
docker compose --env-file /var/lib/codex-control-monitoring/monitoring.env \
  -f deploy/monitoring/compose.yaml up -d --build
```

Verify the three host listeners (`19090`, `19091`, `19093`) with `ss -lntp`;
`19094` and raw `9093` must not exist in the host network namespace. Query Prometheus
`/api/v1/targets`, and require exactly two healthy `codex-control-api` targets
with the expected target strings. A missing Connector, authenticated session
synthetic, backup, or restore signal is an expected failing release gate until
the corresponding real producer is installed; never suppress those alerts to
make admission green.

## Local delivery evidence

Alertmanager currently routes to the loopback append-only receiver only. This
proves Alertmanager sent one controlled alert and its resolved update to a
local receiver; it does **not** prove paging, email, chat, ticketing, or any
external operator delivery.

Generate a fresh 32-lowercase-hex nonce without putting it in an environment
variable, then atomically install this exact sample as uid `65532`:

```sh
umask 077
nonce_file=$(mktemp /var/lib/codex-control-monitoring/evidence/.nonce.XXXXXXXX)
openssl rand -hex 16 >"$nonce_file"
test "$(wc -c <"$nonce_file")" -eq 33
sample_file=$(mktemp /var/lib/codex-control-monitoring/evidence/.delivery.XXXXXXXX)
awk '{print "codex_control_local_delivery_test{controlled_nonce=\"" $1 "\"} 1"}' \
  "$nonce_file" >"$sample_file"
chown 65532:65532 "$sample_file"
chmod 0600 "$sample_file"
mv "$sample_file" /var/lib/codex-control-monitoring/evidence/delivery-test.prom
```

Wait for a firing record, then remove the file or let its 120-second freshness
window expire. After Alertmanager sends the resolved update, verify the pair:

```sh
python3 deploy/monitoring/evidence-receiver/receiver.py verify \
  --evidence-file /var/lib/codex-control-monitoring/delivery-evidence/alert-delivery.jsonl \
  --controlled-nonce "$(cat "$nonce_file")"
rm -f "$nonce_file"
```

The verifier always emits `external_operator_delivery_verified: false`.
Production admission still requires a separately configured, access-controlled
external receiver and independently captured operator-delivery evidence. Until
that source and credential exist, the always-firing
`CodexControlExternalOperatorDeliveryUnconfigured` release gate is intentional;
do not silence or relabel it as success.

## Source identity freeze

This working tree is not a production source identity. Do not create a
monitoring source-identity manifest until these files are committed at the
final public HEAD and the corresponding public source asset has been generated
and independently hashed. In particular, do not bind monitoring to an older
`READY.json`, `.10` candidate, pre-freeze commit, or helper image tag. Production
admission is **BLOCKED** until that final public HEAD/source asset exists and the
manifest is generated from it.

## Rule configuration

Load both rule files only after setting the Prometheus external label
`deploy_event_url` to the current deployment record and configuring external
Alertmanager routing for `severity` and `release_gate`.

```yaml
global:
  external_labels:
    deploy_event_url: https://deployments.example.invalid/codex-control/current
    log_search_url: https://logs.example.invalid/codex-control

rule_files:
  - /etc/prometheus/rules/codex-control/native-alerts.yml
  - /etc/prometheus/rules/codex-control/external-alerts.yml
```

The placeholder URLs above are illustrative. A production configuration must
point to a real, access-controlled deploy record and a log-search entry point.
The operator adds a request ID or command ID after following that link; the
alert does not carry either high-cardinality value. Alert receivers must not add
bearer tokens, cookies, prompts, output, raw device identifiers, or raw request
URLs to notifications.

## Native metric contract

`native-alerts.yml` consumes Control API metrics. Labels are intentionally
bounded:

| Family | Required bounded labels |
| --- | --- |
| `codex_control_http_requests_total` | `method`, normalized `route`, `status_class` (`1xx` through `5xx`) |
| `codex_control_http_request_duration_seconds` | `method`, normalized `route` |
| `codex_control_session_exchange_total` | `outcome` |
| `codex_control_pairing_operations_total` | `operation`, `outcome` |
| `codex_control_websocket_events_total` | `kind`, `event`, `reason` |
| `codex_control_websocket_connections_active` | `kind` |
| `codex_control_command_transitions_total` | `from_status`, `to_status` |
| `codex_control_command_duration_seconds` | `outcome` |
| `codex_control_command_idempotency_total` | `outcome` |
| `codex_control_approval_outcomes_total` | `outcome`, `reason` |
| `codex_control_rpc_policy_total` | `method_class` (`allowlisted` or `prohibited`), `outcome` (`accepted` or `denied`) |
| `codex_control_reconciliation_runs_total` | `phase`, `outcome` |
| `codex_control_reconciliation_items_total` | `phase`, `outcome` |
| `codex_control_reconciliation_duration_seconds` | `phase` |
| `codex_control_maintenance_runs_total` | `phase`, `outcome` |
| `codex_control_maintenance_items_total` | `phase` |
| `codex_control_maintenance_duration_seconds` | `phase` |
| `codex_control_maintenance_batch_saturated` | `phase`; value `0` or `1` |
| `codex_control_maintenance_last_success_timestamp_seconds` | `phase` |
| `codex_control_dependency_checks_total` | `dependency`, `outcome` |
| `codex_control_dependency_check_duration_seconds` | `dependency` |
| `codex_control_dependency_ready` | `dependency`; value `0` or `1` |
| `codex_control_database_pool_connections` | `state` (`size`, `checked_in`, `checked_out`, `overflow`, or `capacity`) |

Initialized gauge families have runtime absence alerts. Counter and histogram
families are sparse until their first bounded event, so PromQL cannot distinguish
a quiet process from missing instrumentation for those families. The admission
synthetics must exercise one HTTP request, session exchange, pairing attempt,
browser/device WebSocket lifecycle, command terminal transition, idempotency
replay/conflict fixture, approval request/decision/default-deny, prohibited-RPC
denial, reconciliation, maintenance run, and readiness check;
then verify every `# TYPE` family is present in the scrape. Prometheus adds `job`
and `instance`; configure the scrape job name exactly as `codex-control-api`.

Never place user, device, thread, command, request, prompt, pairing-code, token,
or raw path values in metric labels. A route label must be a template such as
`/v1/devices/{device_id}`, never the actual request URI.

## External collector contract

`external-alerts.yml` intentionally uses normalized `codex_control_external_*`
and `codex_control_connector_*` names. Exporter-specific metrics must be mapped
to this contract with recording rules or a trusted collector. The rules include
absence alerts, so installing the rule file before wiring collectors produces a
visible release gate instead of silently passing.

Required sources are:

- a blackbox or equivalent synthetic runner for `live`, `ready`, `pwa`, and an
  authenticated `session_exchange` probe;
- PostgreSQL and Redis exporters for availability, latency, memory, eviction,
  pool, and transaction health;
- a deployment probe comparing `alembic current` with the packaged head;
- the backup scheduler and restore-rehearsal job publishing success timestamps,
  checksum state, and the last full rehearsal result;
- policy probes for the dedicated PostgreSQL role, Redis ACL and Pub/Sub fanout,
  and secret-file modes;
- a host-local Connector collector or sidecar publishing process health,
  reconnect reason, spool occupancy and age, app-server restart reason,
  schema/version failures, and policy denials.

The normalized external families are:

| Family | Labels or value |
| --- | --- |
| `codex_control_synthetic_probe_success` | `probe`; value `0` or `1` |
| `codex_control_external_postgresql_up` | value `0` or `1` |
| `codex_control_external_redis_up` | value `0` or `1` |
| `codex_control_external_redis_evicted_keys_total` | monotonic counter |
| `codex_control_external_redis_memory_used_bytes` | gauge |
| `codex_control_external_redis_memory_max_bytes` | gauge; `0` means no configured ceiling |
| `codex_control_external_migration_revision_match` | value `0` or `1` |
| `codex_control_external_backup_last_success_timestamp_seconds` | Unix timestamp |
| `codex_control_external_backup_checksum_ok` | value `0` or `1` |
| `codex_control_external_restore_rehearsal_last_success_timestamp_seconds` | Unix timestamp |
| `codex_control_external_policy_check_ok` | bounded `check`; value `0` or `1` |
| `codex_control_connector_up` | value `0` or `1` |
| `codex_control_connector_last_update_timestamp_seconds` | Unix timestamp; must remain within 60 seconds of Prometheus time |
| `codex_control_connector_reconnects_total` | `reason`: `token`, `dial`, `handshake`, or `connection_io` |
| `codex_control_connector_spool_bytes` | gauge |
| `codex_control_connector_spool_capacity_bytes` | gauge |
| `codex_control_connector_spool_events` | gauge |
| `codex_control_connector_spool_oldest_unacknowledged_age_seconds` | gauge |
| `codex_control_connector_app_server_restarts_total` | `reason`: `start_failure`, `notification_failure`, or `child_exit` |
| `codex_control_connector_contract_failures_total` | bounded `kind` (`version` or `schema`) |
| `codex_control_connector_contract_last_failure_timestamp_seconds` | Unix timestamp by bounded `kind` (`version` or `schema`); `0` means no failure |
| `codex_control_connector_policy_denials_total` | `reason`: `command` |

The Connector itself atomically writes all of these families to
`state_dir/connector.prom` every 15 seconds and coalesces state-change
notifications to at most one rewrite per second; its persistent counters are
in `state_dir/connector-metrics.json`. Counter increments are fsynced before
their recording calls return, including the last contract-failure timestamps
used to time-qualify a first observed nonzero counter. Policy-denial replay is
deduplicated by a private SHA-256 command receipt, capped at 4096 entries and
pruned after its 24-hour horizon at startup or on a later distinct denial;
receipts are never exported as labels or samples. Both files are owner-only
`0600`, the state directory is `0700`, and no listener is opened. Point a
trusted same-owner or privileged node-exporter textfile collector at the state
directory and scrape one target per host Connector with
`job="codex-control-connector"`. A hard kill retains the last `up 1`, so `up`
alone is not process-liveness evidence: the supplied alert treats a last-update
timestamp more than 60 seconds old or more than 60 seconds in the future as
down. A graceful stop writes `up 0`.

Connector collectors must expose only the fixed codes listed above. Do not
export a raw Go error string, app-server stderr, device/thread/command ID, path,
URL, prompt, output, pairing material, or credential as a label or annotation.

## Verification

Install Python 3.9+, Ruff, matching `promtool`, Docker, and Compose, then run:

```sh
deploy/monitoring/verify-stack.sh --strict
```

Strict mode fails rather than skips when any required tool, daemon, Compose
expansion, image build/identity check, pinned-container `promtool`/`amtool`, or
Python 3.9 container test is unavailable or fails. It does not prove production
reachability or external operator delivery.
