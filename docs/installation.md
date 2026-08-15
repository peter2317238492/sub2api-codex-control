# Installation

[简体中文](installation.zh-CN.md) | [Documentation index](../README.md#documentation)

## Choose the correct path

There are three distinct installation paths:

1. The isolated E2E path is available now and verifies the source in disposable
   infrastructure.
2. After a signed `connector-v*` Release is published, ordinary users install
   its native Connector package and complete setup from the PWA.
3. A production Control deployment is not available from the first public
   source release. It requires a complete signed release evidence set that has
   not yet been published.

The Connector can currently be built from source for development and
evaluation. Until the signed Release described above exists, no prebuilt
Connector binary is supported.

Commands in this guide assume a POSIX shell on Linux or macOS. The Connector
source supports those targets; Windows is not a supported runtime target in
this source version.

## Isolated full-stack verification

Use a development machine with:

- Git;
- Docker Engine and Docker Compose v2;
- Go 1.24 or newer;
- a C toolchain supported by Go's race detector;
- Python 3 and OpenSSL;
- an `amd64` or `arm64` Docker daemon;
- enough local capacity to build and run PostgreSQL, Redis, the Control API,
  the PWA, Nginx, and test fixtures.

Clone the public repository and keep generated acceptance evidence outside the
working tree:

```sh
git clone https://github.com/peter2317238492/sub2api-codex-control.git
cd sub2api-codex-control
install -d -m 0700 "$HOME/.local/state/sub2api-codex-control/e2e-reports"
CONTROL_E2E_REPORT_DIR="$HOME/.local/state/sub2api-codex-control/e2e-reports" \
  ./tests/e2e/run-local.sh
```

The harness creates its own credentials and temporary Docker resources. It
uses a mock Sub2API authority and a protocol-faithful fake Codex app-server; it
does not use a real account or a real provider key. Cleanup runs automatically
unless `KEEP_E2E=1` is set for debugging.

Passing the harness checks the same-origin routes, pairing, admitted RPCs,
approvals, reconnect behavior, revocation, datastore isolation, and secret
handling. It does not prove real-account authentication, a real Codex canary,
public TLS, production WSS connectivity, or release authenticity.

## Install a signed Connector package

Use this path only after the repository publishes an immutable, signed
`connector-v*` GitHub Release and the Control PWA displays that exact release.
Click the download icon in the PWA device rail, or choose **Install Connector**
in its empty state. Select the operating system and architecture, download the
package, and run the checksum-and-install command shown by the PWA. Continue
only when the downloaded file's SHA-256 matches exactly.

| Platform | Package | Installation command |
| --- | --- | --- |
| Debian / Ubuntu `amd64`, `arm64` | `.deb` | `sudo apt install ./sub2api-codex-connector_*.deb` |
| Fedora / RHEL `amd64`, `arm64` | `.rpm` | `sudo dnf install ./sub2api-codex-connector_*.rpm` |
| macOS Intel, Apple silicon | signed and notarized `.pkg` | `open ./sub2api-codex-connector_*.pkg` |

The package installs only the Connector, its user service, and its management
command; it does not install or upgrade Codex. Run every command below as the
ordinary user who owns Codex and the intended workspace.

## Create private configuration

The formal wizard initializes one workspace. Enter the device name and an
existing absolute workspace path in the PWA, then run its displayed management
command as the ordinary Codex user. The equivalent form is:

```sh
sub2api-codex-connector-ctl init \
  --origin https://control.example.com \
  --workspace /absolute/path/to/workspace \
  --display-name "My workstation"
```

The command writes a mode-`0600` configuration at:

```text
${XDG_CONFIG_HOME:-$HOME/.config}/sub2api-codex-connector/connector.json
```

Print the effective path with:

```sh
sub2api-codex-connector-ctl config-path
```

The private configuration is created and kept on the device. Do not commit it,
send it in chat, or give it to an operator. For advanced multi-root use, edit
this local file after initialization and set `workspace_roots` to 1 to 32
existing absolute directories. You may also lower `sandbox_cap` to `read-only`;
its maximum is `workspace-write`. Preserve mode `0600`. State, workspaces, and
`CODEX_HOME` must not contain one another.

## Pair and start

After creating the configuration, begin pairing:

```sh
sub2api-codex-connector-ctl pair
```

Keep `pair` running. It reports a mode-`0600` file containing a one-time code.
Select **Pair existing Connector** in the authenticated PWA and enter that
code. Keep the command running until it confirms the browser claim and exits.
Only then start the user service, as the same ordinary user, and confirm its
status:

```sh
sub2api-codex-connector-ctl start
sub2api-codex-connector-ctl status
```

The package installs a user-level `systemd` service on Linux or a `launchd`
agent on macOS. Package upgrades and removal preserve the user's private
Connector state. Revoke the device in the PWA before explicitly deleting that
state with `sub2api-codex-connector-ctl purge-user-state --yes`.

## Build a Connector from source for development

This path is for development and evaluation, not production installation.
Install Go 1.24 or newer and `codex-cli 0.147.0`. Run the Connector as the same
ordinary user who owns the intended Codex installation and workspace roots;
do not run it as root.

```sh
cd connector
go test ./...
CGO_ENABLED=0 go build -trimpath -buildvcs=false \
  -o sub2api-codex-connector ./cmd/connector
```

Create a private configuration directory and start from the example:

```sh
install -d -m 0700 "$HOME/.config/sub2api-codex-connector"
install -m 0600 connector.example.json \
  "$HOME/.config/sub2api-codex-connector/connector.json"
```

Edit the private copy. Replace `control.example.com`, `display_name`,
`state_dir`, and `workspace_roots`. Every path must be absolute. Each workspace
root must already exist. The state directory must not overlap a workspace root
or `CODEX_HOME`.

The three URLs must remain on the same host:

```json
{
  "control_url": "wss://control.example.com/codex-ws/device",
  "pairing_url": "https://control.example.com/codex-api/v1/device-pairings/start",
  "token_url": "https://control.example.com/codex-api/v1/device/connect-token"
}
```

Keep `codex_version` and `schema_digest` unchanged unless the source contract is
updated together. A changed or unexpected Codex version fails closed before
the app-server starts.

With the Control plane already available, begin pairing:

```sh
./sub2api-codex-connector \
  -config "$HOME/.config/sub2api-codex-connector/connector.json" \
  -pair-only
```

Leave the process running, open the authenticated PWA, and claim the code from
the private `pairing-code.json` path reported on stderr. After the command
confirms the claim and exits, start the long-lived Connector without
`-pair-only`.

## Production prerequisites

Do not attempt a production installation from a mutable checkout or ad hoc
local images. Production remains blocked until all of the following exist for
one exact source revision:

- signed, digest-pinned `linux/amd64` Control API, PWA, and PostgreSQL-tools
  images;
- verified source identity, Sigstore identity, provenance, and SBOM evidence;
- a supported Connector release whose platform signature and evidence pass the
  consumer verifier;
- an immutable, contract-matched Sub2API runtime;
- isolated PostgreSQL credentials/database and Redis ACL user/prefix;
- a valid TLS certificate for one origin such as
  `https://control.example.com`;
- a reviewed Nginx integration, one verified pre-change recovery snapshot, and
  private deployment records outside the source tree;
- successful authenticated HTTP, browser WSS, device WSS, Connector, approval,
  reconnect, and revocation checks against the intended origin.

The repository contains deployment machinery and policy documentation, but
their presence is not a release. See [the deployment runbook](runbooks/deployment.md)
for the admission boundary.

## Network boundary

The host Nginx edge is the only public entry point. Publicly allow TCP `443`.
Allow TCP `80` only when it is needed for an HTTP redirect or ACME challenge,
and restrict SSH to an administrative source range. Keep loopback ports
`18090`, `18091`, `18092`, and `18093` closed externally. Do not expose
PostgreSQL or Redis. Connectors require outbound HTTPS/WSS only.
