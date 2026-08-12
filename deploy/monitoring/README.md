# Monitoring artifacts

This directory contains executable Prometheus rules, not a production
Prometheus or Alertmanager deployment. Load both rule files only after setting
the Prometheus external label `deploy_event_url` to the current deployment
record and configuring Alertmanager routing for `severity` and `release_gate`.

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

Install a Prometheus `promtool` version matching production, then run:

```sh
deploy/monitoring/verify-rules.sh
```

The script performs `promtool check rules` on both rule files and
`promtool test rules` on the deterministic unit-test file. This proves parsing,
recording-rule evaluation, threshold behavior, and `for` timing. It does not
prove scrape reachability, Alertmanager delivery, or production collector
coverage. Before admission, capture a Prometheus targets page or API response,
rule health, one controlled firing/recovery notification, and links to the
release matrix and current deploy record.
