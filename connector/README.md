# Connector

The Connector is the only device-side component. It opens an outbound WSS
connection and starts `codex app-server --listen stdio://`; it never listens on
a local port and never edits Codex configuration or credentials.

## Security boundary

- An Ed25519 identity, pending pairing state, and claimed device credential are
  stored under `state_dir` with directory mode `0700` and file mode `0600`.
- Before every app-server child start or restart, the Connector runs the same
  configured binary with `--version` and requires the exact pinned
  `codex-cli 0.147.0` banner. A changed binary never reaches app-server launch.
- Before the first network request, pairing protocol v2 generates and persists
  the pairing UUID, a 16-character base32 code (shown as four groups), poll
  token, and refresh credential in `pending-pairing.json`. The signed start
  request binds their SHA-256 commitments to the exact audience, Ed25519 key,
  device metadata, versions, workspace roots, and creation time; it never sends
  those three raw secrets.
- `pairing-code.json` exposes only the code and expiry long enough for a trusted
  operator to enter it in the authenticated same-origin PWA. Stderr reports the
  private file path, not the code. Restrict journal and state-directory access,
  and treat the code as sensitive until it expires or is claimed.
- A transient start or poll failure keeps the same pending intent, so a restart
  retries without rotating secrets or stranding a server-side claim. The
  completed poll response is replayable after response loss. The Connector
  writes `device-credentials.json` before removing pending state; terminal
  expiry removes both pending state and the published code. A pairing-specific
  cross-process lock covers identity preparation, pairing, credential commit,
  and cleanup, so a second pairing caller cannot race those files.
- On the supported Linux and macOS targets, a non-blocking OS lock is acquired
  on the opened `state_dir` directory inode before any identity, credential,
  pairing, spool, managed-thread, or command-journal state is read or changed,
  and is held for the complete Connector lifetime, including `-pair-only`.
  Replacing the private mode `0600` `connector.lock` marker cannot split the
  authoritative directory lock. A second process using the same canonical
  `state_dir` fails closed immediately; normal exit releases the lock explicitly
  and the OS releases it after process termination.
- Lock acquisition walks the canonical absolute path through directory handles.
  Every ancestor must be owned by root or the Connector EUID, must not grant
  access through an allow ACL, and must not be group/other writable unless the
  sticky bit prevents untrusted replacement. The final directory must be owned
  by the Connector EUID, ACL-safe, and mode `0700`; state files must have the
  same owner/ACL guarantees and owner-only permissions. Darwin deny-only ACLs
  are accepted. An ACL inspection error, including an unsupported ACL query,
  fails closed rather than degrading to mode-bit checks. Processes running
  under the same EUID are inside this local trust boundary.
- Device WSS access tokens are short-lived. The refresh credential is used only
  at `token_url`, while each exchange includes a signed nonce and timestamp.
- Only `model/list`, managed `thread/*`, and managed `turn/*` methods in the
  documented allowlist reach app-server. Shell, exec, filesystem, process,
  config, plugin, login, and raw RPC methods fail closed.
- A remotely created thread must start in an existing directory under one of
  `workspace_roots`. Its sandbox cannot exceed `sandbox_cap`, whose strongest
  permitted value is `workspace-write`.
- `state_dir` cannot overlap a workspace root or the effective `CODEX_HOME`,
  and a workspace root cannot overlap that protected Codex home. Turn input is
  projected to text items only; local images, skills, mentions, raw event
  flags, config maps, environments, permissions, runtime roots, and
  caller-selected sandbox or approval overrides are rejected before JSON-RPC
  dispatch.
- Thread and turn operations are bound to IDs returned by this Connector's
  app-server process. Lists are filtered so unrelated local Codex threads are
  never returned. The durable managed-thread projection is also bound to the
  claimed `device_id`; a new pairing identity and legacy unscoped state both
  reset that projection before any thread can be listed. This never deletes or
  edits the underlying local Codex threads.
- App-server JSON-RPC success/error envelopes, all successful results, and all
  server notifications are validated against the embedded frozen 0.147.0
  generated schemas before routing. The 0.147.0 `emittedAtMs` notification
  envelope field is accepted only with its frozen integer schema; every other
  unrecognized top-level field still fails closed. Contract drift cancels the child epoch.
  Valid results and notifications are then projected into bounded public shapes
  before persistence. Command output, diffs, reasoning, tool payloads, rollout
  paths, and unrelated item types never enter the remote event spool.
- Approval requests are tied to one app-server epoch. Missing, expired, stale,
  disconnected, or unknown decisions return `decline`; the timeout cannot
  exceed 120 seconds. A `read-only` sandbox cap also rejects every file-change
  approval and every filesystem write permission, including write grants nested
  in command approvals.
- Every WSS session starts with an unsequenced Hello/Hello ACK exchange. The
  Connector validates the device, protocol, app-server epoch, pinned schema,
  and server receive cursor before replaying durable records.
- Outbound envelopes are fsynced before transmission and retained until ACKed.
  Sequence and receive cursors survive reconnects and process restarts. Spool,
  command journal, frame, event, and concurrent app-server request limits fail
  closed instead of allowing unbounded local growth.
- Each app-server is placed in a Connector-owned process group on supported
  Linux and macOS targets. Shutdown first closes stdio for a bounded graceful
  exit, then terminates the complete group on timeout, parent cancellation, or
  protocol failure; residual descendants are removed when the direct child
  exits. The Connector never scans for or signals unrelated Codex processes.

## Metrics textfile

The running Connector publishes `state_dir/connector.prom` for a trusted
node-exporter textfile collector. It does not open an HTTP or other inbound
listener and never writes under `CODEX_HOME`. The textfile and its durable
counter state, `connector-metrics.json`, are atomically replaced, fsynced, and
mode `0600` under the mode `0700` state directory. A collector running as a
different unprivileged account cannot read them; run the host collector as the
Connector owner or as an explicitly trusted privileged service.

The textfile refreshes independently every 15 seconds and coalesces relevant
state-change notifications to at most one rewrite per second.
`codex_control_connector_up 0` is evidence of a graceful stop only: a hard
process kill leaves the last atomic file intact. Monitoring must therefore
require `codex_control_connector_last_update_timestamp_seconds` to remain
within 60 seconds of Prometheus time; both stale and implausibly future values
are unhealthy. The supplied external Prometheus rules enforce this.

Reconnect, app-server restart, contract-failure, and policy-denial counter
increments are fsynced before the recording call returns, so they survive a
kill before the next textfile refresh. Contract failures also update a durable
`codex_control_connector_contract_last_failure_timestamp_seconds` gauge, so a
failure remains time-qualified even when its first Prometheus scrape observes
an already nonzero counter. Policy-denial replay uses only a SHA-256 command
receipt in the private counter state, bounded to 4096 receipts with the same
24-hour horizon as the command journal. Expired receipts are removed at startup
after command-journal pruning and lazily on later distinct denials; neither a
receipt nor a command ID is exported. Their complete fixed label sets are:

- reconnect `reason`: `token`, `dial`, `handshake`, `connection_io`;
- app-server restart `reason`: `start_failure`, `notification_failure`,
  `child_exit`;
- contract failure `kind`: `version`, `schema`;
- policy denial `reason`: `command`.

All series are initialized, including zero-valued counters. There are no device,
thread, command, path, URL, error, credential, or user-content labels. Configure
one scrape target per host Connector with
`job="codex-control-connector"` so Prometheus supplies bounded `job` and
`instance` labels without changing the local textfile.

## Run

Copy `connector.example.json` to a private location, replace all example values,
then build and run with Go 1.24 or newer:

```sh
go test ./...
go build -o sub2api-codex-connector ./cmd/connector
./sub2api-codex-connector -config /absolute/path/to/connector.json
```

Use `-pair-only` to complete the one-time pairing without starting app-server.
Read the code from the private `pairing-code.json` path reported on stderr and
enter it in the authenticated same-origin PWA.

The supported Connector runtime targets are Linux and macOS, matching the
release matrix. Other operating systems are unsupported and are not release
artifacts.

## Release artifacts

Do not distribute an ad hoc `go build` result. The executable release pipeline,
supported target matrix, consumer verifier, and local non-release determinism
mode are documented in [release/README.md](release/README.md). Production
artifacts require the protected tag workflow, exact Sigstore workflow identity,
per-artifact SPDX/SLSA evidence, and Developer ID/notarization for macOS.
