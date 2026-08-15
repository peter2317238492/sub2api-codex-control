# Installation

[简体中文](installation.zh-CN.md) | [Documentation index](../README.md#documentation)

## Choose the correct path

There are three distinct installation paths:

1. The isolated E2E path is available now and verifies the source in disposable
   infrastructure.
2. After a signed `connector-v*` Release is published, ordinary users select its
   native Connector package and complete post-install setup from the PWA. Native
   installation may require local operating-system administrator approval.
3. A production Control deployment is not available from the first public
   source release. It requires a complete signed release evidence set that has
   not yet been published.

The Connector can currently be built from source for development and
evaluation. Until the signed Release described above exists, no prebuilt
Connector binary is supported.

Supported release assets will appear only on the repository's
[GitHub Releases page](https://github.com/peter2317238492/sub2api-codex-control/releases).
Do not use GitHub's automatically generated source archives as installers.

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
Open the [Releases page](https://github.com/peter2317238492/sub2api-codex-control/releases),
select that exact `connector-v*` tag, and confirm the PWA points to the same
tag, filename, and SHA-256. The release notes identify the six supported native
assets; do not substitute an asset from another tag.
Click the download icon in the PWA device rail, or choose **Install Connector**
in its empty state. Select the operating system and architecture, download the
package, and run the checksum-and-install command shown by the PWA. Continue
only when the downloaded file's SHA-256 matches exactly.

| Platform | Package | Installation command |
| --- | --- | --- |
| Debian / Ubuntu `amd64`, `arm64` | `.deb` | `sudo apt install ./sub2api-codex-connector_*.deb` |
| Fedora / RHEL `amd64`, `arm64` | `.rpm` | `sudo dnf install ./sub2api-codex-connector_*.rpm` |
| macOS Intel, Apple silicon | signed and notarized `.pkg` | `open ./sub2api-codex-connector_*.pkg` |

This package step does not require a Sub2API administrator. It does use local
`sudo` on Linux, and macOS Installer may request a local administrator credential.

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
$HOME/.config/sub2api-codex-connector/connector.json
```

This is the fixed formal configuration path. A non-empty `XDG_CONFIG_HOME`
override is rejected so the interactive command and packaged user service cannot
select different files.

Print the effective path with:

```sh
sub2api-codex-connector-ctl config-path
```

The private configuration is created and kept on the device. Do not commit it,
send it in chat, or give it to an operator. New initialization resolves the
current `codex` command to an absolute executable path and binds the resulting
file's SHA-256 to a private v2 managed layout. Do not edit `connector.json` in
place: pair, start, and service startup fail closed when its digest changes.
The formal command currently initializes one workspace and does not provide a
controlled multi-root or sandbox-cap update. To choose a different workspace,
revoke the device in the PWA, stop it, purge its v2 managed state, then run a
fresh `init`, `pair`, and `start`.

### Migrate a legacy configuration without losing state

An older private configuration already at the fixed path but without a managed
layout remains usable by `pair`, `start`, and `run-service`; the Connector still
validates the configuration structure and uses the current valid `CODEX_HOME`.
`purge-user-state` refuses that legacy configuration because it has no verified
deletion boundary. Run `sub2api-codex-connector-ctl start` interactively once:
it creates a private binding between the unchanged configuration digest and the
current absolute Codex path. Background startup fails closed if that binding is
missing or no longer matches.

If an older installation used a non-empty `XDG_CONFIG_HOME`, first stop the
Connector and make mode-`0600` backups of its `connector.json` and the state
directory named by `state_dir`. Confirm that
`$HOME/.config/sub2api-codex-connector` does not already exist. Then copy, rather
than move, the old configuration to the fixed path; set its directory to mode
`0700` and `connector.json` to `0600`; unset `XDG_CONFIG_HOME`; and run `pair`
and `start`. Keep the original and both backups until the device is online and
its preserved state is confirmed. Never overwrite an existing fixed-path
configuration; leave both copies untouched and resolve that conflict manually.

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
Connector state. For a v2 managed configuration, revoke the device in the PWA
before explicitly deleting that state with
`sub2api-codex-connector-ctl purge-user-state --yes`. Legacy configurations
without a verified layout must follow the non-destructive migration guidance
above instead.

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

## Install the Control server package

Server operators use the matching signed `control-v*` entry on the
[GitHub Releases page](https://github.com/peter2317238492/sub2api-codex-control/releases),
not a repository checkout or generated source archive. Download the online or
offline server package together with its manifest, standalone verifier, and
signature evidence. Authenticate the verifier before executing it, verify the
exact release directory, and install only the extracted verified package.

The complete commands and trust inputs are maintained in the
[server package installation guide](../deploy/server-package/INSTALL.md). The
production [deployment runbook](runbooks/deployment.md) treats the verified
package lifecycle wrapper as the only supported entry point.

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
  reconnect, revocation, and logout checks against the intended origin.

The repository contains deployment machinery and policy documentation, but
their presence is not a release. See [the deployment runbook](runbooks/deployment.md)
for the admission boundary.

## Network boundary

The host Nginx edge is the only public entry point. Publicly allow TCP `443`.
Allow TCP `80` only when it is needed for an HTTP redirect or ACME challenge,
and restrict SSH to an administrative source range. Keep loopback ports
`18090`, `18091`, `18092`, and `18093` closed externally. Do not expose
PostgreSQL or Redis. Connectors require outbound HTTPS/WSS only.
