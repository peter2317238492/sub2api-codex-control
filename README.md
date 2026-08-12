# Sub2API Codex Control

[简体中文](README.zh-CN.md)

Sub2API Codex Control is a same-origin web control plane for user-owned Codex
installations. A browser uses a short-lived Control session derived from an
existing Sub2API login. A Connector on each device opens an outbound WSS
connection and talks to the pinned Codex app-server over stdio. The Connector
does not expose an inbound device port or rewrite Codex configuration.

## Release status

This first public version is **source-only**. There are currently no supported
prebuilt Connector binaries and no signed Control image release to download.
Production installation remains blocked until the release workflow has
produced and verified signatures, provenance, and SBOMs for the exact source
revision. Do not treat a locally built binary or image as an official release.

The repository includes an isolated full-stack E2E harness. It uses a mock
Sub2API authority and a protocol-faithful fake Codex app-server. A passing run
validates the repository's integration path, but it is not evidence that a real
Sub2API account, a real Codex installation, or a production deployment works.

## Topology

The application shares one HTTPS origin with Sub2API:

| Route | Purpose |
| --- | --- |
| `/` and `/api/` | Existing Sub2API UI and API |
| `/codex/` | Control PWA |
| `/codex-api/` | Control HTTP API |
| `/codex-ws/browser` | Browser WebSocket |
| `/codex-ws/device` | Outbound Connector WebSocket |

The Control services bind only to host loopback ports `18090`, `18091`, and
`18093`. Port `18092` is reserved for the disposable smoke edge. None of these
ports, PostgreSQL, or Redis should be opened in the host firewall. The public
edge needs TCP `443`; TCP `80` is optional only for HTTP-to-HTTPS redirects or
an ACME challenge. Keep SSH restricted to an administrative source range.

## Verify the source

Prerequisites: Git, Docker Engine with Compose v2, Go 1.24 or newer, a C
toolchain supported by Go's race detector, Python 3, OpenSSL, and an `amd64` or
`arm64` Docker daemon. The harness creates disposable containers, networks,
volumes, and credentials. Run it on an isolated development host, not a
production server.

```sh
git clone https://github.com/peter2317238492/sub2api-codex-control.git
cd sub2api-codex-control
install -d -m 0700 "$HOME/.local/state/sub2api-codex-control/e2e-reports"
CONTROL_E2E_REPORT_DIR="$HOME/.local/state/sub2api-codex-control/e2e-reports" \
  ./tests/e2e/run-local.sh
```

The acceptance report is written outside the checkout. A successful run is
still isolated test evidence only.

## Build the Connector from source

The Connector is intended to run as the ordinary user who owns the Codex
installation and approved workspaces. The current contract requires
`codex-cli 0.147.0` exactly.

```sh
cd connector
go test ./...
CGO_ENABLED=0 go build -trimpath -buildvcs=false \
  -o sub2api-codex-connector ./cmd/connector
./sub2api-codex-connector \
  -config /absolute/path/to/connector.json -pair-only
```

`-pair-only` waits for an authenticated operator to claim the private pairing
code in the PWA and then exits. See the installation and usage guides before
creating the configuration or running a long-lived Connector.

## Documentation

- [Installation](docs/installation.md) / [安装](docs/installation.zh-CN.md)
- [Usage](docs/usage.md) / [使用](docs/usage.zh-CN.md)
- [Operations](docs/operations.md) / [运维](docs/operations.zh-CN.md)
- [Security decisions](docs/adr/)
- [Production runbooks](docs/runbooks/README.md)
- [Connector security boundary](connector/README.md)

## Security invariants

- The browser and Control database never receive a raw Sub2API provider key.
- A Sub2API refresh token is never sent to or stored by the Control API.
- The Connector initiates every device connection and opens no listener.
- Remote RPC is an explicit allowlist; raw pass-through, account, config,
  plugin, process, and arbitrary filesystem methods fail closed.
- Workspace roots are local allowlists, and the remote sandbox cannot exceed
  `workspace-write`.
- Approval requests expire after at most 120 seconds and default to denial.

## License and independence

Licensed under the [Apache License 2.0](LICENSE). See [NOTICE](NOTICE) and
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) for attribution and bundled
dependency notices.

This is an independent community project. It is not affiliated with, endorsed
by, or sponsored by OpenAI or the Sub2API project. OpenAI, Codex, and Sub2API
names belong to their respective owners.
