# Codex app-server contract

This package freezes the complete contract emitted by `codex-cli 0.147.0`:

- JSON Schema draft-07 under `generated/json-schema/`
- TypeScript bindings under `generated/typescript/`
- experimental methods and fields included deliberately

The full bundle is retained because security enforcement must know about every
method the pinned binary can expose, including experimental `process/*`
methods. Consumers must not treat generated types as an authorization policy.

## Origin and license

The files under `generated/` are generated from the app-server schema emitted
by [OpenAI Codex 0.147.0](https://github.com/openai/codex/tree/rust-v0.147.0).
The synchronized JSON files under `connector/internal/appserver/contracts/`
are byte-for-byte copies or subsets of that generated material. They remain
covered by upstream's Apache-2.0 license and NOTICE, reproduced in
`third_party/licenses/Codex-LICENSE.txt` and
`third_party/licenses/Codex-NOTICE.txt`. See `third_party/components.json` for
the fixed source URLs and SHA-256 digests.

This independent project is not affiliated with, endorsed by, or sponsored by
OpenAI. The Codex name is used only to identify the compatible upstream
protocol.

## Reproduce and check

Generation uses an empty temporary `CODEX_HOME`, requires the exact pinned
version, and canonicalizes JSON object key order. Canonicalization is needed
because the aggregate schema's definition order is not stable between process
runs; it does not change schema semantics.

```sh
make -C packages/appserver-schema generate
make -C packages/appserver-schema check
```

Equivalent generator commands are:

```sh
codex app-server generate-json-schema --experimental --out generated/json-schema
codex app-server generate-ts --experimental --out generated/typescript
```

The frozen contract contains 133 client requests, 11 server requests, one
client notification, and 70 server notifications. The aggregate entry points
are `ClientRequest.json`, `ServerRequest.json`, `ClientNotification.json`, and
`ServerNotification.json`.

Generation also synchronizes the exact v2 aggregate, JSON-RPC success/error
envelopes, and v1 initialize response into
`connector/internal/appserver/contracts/`. The Connector embeds those files so
runtime validation does not depend on the current working directory or mutable
files beside the executable. `check` verifies that the embedded copies remain
byte-for-byte identical to this package's generated sources.

## Remote MVP allowlist

Only these request methods may be selected by a remote Control API command:

```text
model/list
thread/start
thread/list
thread/read
thread/resume
turn/start
turn/steer
turn/interrupt
```

`initialize` and the `initialized` notification are required protocol
bootstrap messages, but only the Connector may create them. They are not
remote commands. Unknown methods and every generated method not listed above
must fail closed. The Control API must send typed command envelopes rather than
raw JSON-RPC `method` and `params` values.

Method checks are not sufficient. The Connector must project allowed fields
into fresh parameter objects and enforce connector-owned values:

- `thread/start`: reject caller-provided `config`, `dynamicTools`,
  `environments`, `permissions`, `runtimeWorkspaceRoots`, raw event flags, and
  sandbox or approval relaxations; canonicalize `cwd` under a configured root.
- `thread/resume`: require an authorized thread binding; reject `path` and the
  same config, path, sandbox, permissions, runtime-root, and approval overrides.
- `thread/list`: constrain `cwd` to configured roots and filter returned
  threads by device ownership and root containment.
- `turn/start`: reject caller-provided `cwd`, `environments`, `permissions`,
  `runtimeWorkspaceRoots`, `sandboxPolicy`, and approval-policy overrides.
- `thread/read`, `turn/steer`, and `turn/interrupt`: require a device/thread
  binding and, where present, the current turn identifier.

The effective sandbox may never be more permissive than `workspace-write`.

## Dangerous generated families

These methods are present in the 0.147.0 generated client-request contract and
are explicitly out of scope for remote dispatch:

| Capability | Generated methods to deny |
| --- | --- |
| Shell and command execution | `thread/shellCommand`, `command/exec`, `command/exec/write`, `command/exec/terminate`, `command/exec/resize` |
| Experimental process control | `process/spawn`, `process/writeStdin`, `process/kill`, `process/resizePty` |
| Filesystem access | every `fs/*` method: read, metadata, directory, watch, copy, create, write, and remove operations |
| Configuration and capability mutation | `config/value/write`, `config/batchWrite`, `config/mcpServer/reload`, `skills/config/write`, `skills/extraRoots/set`, `experimentalFeature/enablement/set`, `externalAgentConfig/import`, `environment/add`, `thread/settings/update`, `thread/memoryMode/set`, `memory/reset` |
| Plugins and marketplaces | every `plugin/*` and `marketplace/*` method, especially search, install, uninstall, add, remove, and upgrade |
| Account and OAuth state | `account/login/start`, `account/login/cancel`, `account/logout`, `mcpServer/oauth/login` |
| Tool and environment expansion | `mcpServer/tool/call`, `windowsSandbox/setupStart`, every `remoteControl/*` method, section mutation/listing (`thread/section/move` and `threadSection/*`), and background-terminal or realtime thread methods |

Codex 0.147.0 adds `plugin/search`, `thread/section/move`, and
`threadSection/create`, `threadSection/delete`, `threadSection/list`, and
`threadSection/update`. They remain outside the remote allowlist and must fail
closed, together with previously denied `app/read`, `app/installed`,
`environment/status`, `externalAgentConfig/import/recordHistory`, and
`thread/searchOccurrences`. The `thread/environment/connected` and
`thread/environment/disconnected` notifications remain dropped by the event
projection.

The 0.147.0 response additions (`modelSpecialty`, thread section metadata,
read-only hints, and transparent-image metadata) remain outside the bounded
browser projection. `initialize` adds only an optional MCP `extensions`
capability; the Connector's empty capabilities object remains valid.

The server-request direction is also active. App-server can request command,
file-change, or permission approval, user input, MCP elicitation, a dynamic
tool call, auth-token refresh, attestation, current time, or legacy patch/exec
approval. Until a request type has an explicit handler, the Connector must
return an error or denial. Approval responses must be one-shot, expire after
120 seconds, and be bound to the current app-server process epoch.
