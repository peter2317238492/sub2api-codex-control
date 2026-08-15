# User Guide

[简体中文](usage.zh-CN.md) | [Back to README](../README.md)

> [!IMPORTANT]
> This guide describes the user flow after a signed Connector release exists.
> The public repository is still a source release candidate. Do not treat an ad
> hoc build as a supported package until GitHub has an immutable
> `connector-v*` Release.

## Before you start

An ordinary user needs the following. A Sub2API administrator does not need to
create the device or issue its pairing code:

- a working Sub2API account;
- the same HTTPS site with Control enabled;
- a Linux or macOS device with exactly `codex-cli 0.147.0`;
- at least one existing absolute workspace path;
- outbound TCP 443 access from the device to the Control site.

The Sub2API operator deploys the site, publishes trusted packages, and maintains
the service. Each user handles post-install configuration, pairing, startup,
daily operation, diagnosis, and revocation. Installing the native package may
still require local `sudo` or macOS administrator approval.

## Interface map

| Area | What it does |
| --- | --- |
| Header | Shows live state and provides approvals, session renewal, and sign-out |
| Device rail | Installs or pairs a Connector, switches devices, shows status, and revokes |
| Thread list | Searches, creates, selects, and archives threads on the selected device |
| Conversation | Sends messages, steers or interrupts a running turn, and resumes failed threads |
| Approval drawer | Shows the type, origin, projected details, and expiry of one-shot requests |

On a narrow screen, use the device and thread icons in the header to open the
corresponding sidebars.

## First-time setup

### 1. Sign in and open Control

The PWA is not a separate login page. Sign in at the Sub2API site root first:

```text
https://control.example.com/
```

Then open Control on the same host:

```text
https://control.example.com/codex/
```

The browser exchanges the current Sub2API access session for a short-lived
HttpOnly Control session. The Sub2API refresh credential stays in the existing
browser login flow and is not sent to the Control API.

### 2. Install the Connector

Click the download icon at the top of the device rail, or choose **Install
Connector** in the empty state. Select the operating system, architecture, and
package format, download it, then run the checksum-and-install command shown by
the PWA. Continue only when the SHA-256 matches exactly.

The same asset must appear under the exact `connector-v*` tag on the
[GitHub Releases page](https://github.com/peter2317238492/sub2api-codex-control/releases).
Do not install an automatically generated source archive or mix assets from
different tags. Stop if the PWA tag, filename, or checksum differs.

This does not require Sub2API administrator assistance. Linux package installation
uses local `sudo`; macOS Installer may request local administrator approval.

See [Installation](installation.md) for package commands and the source-only
evaluation path. The package does not install or upgrade Codex, and it does not
modify Codex configuration, login files, workspaces, plugins, shell profiles,
or firewall rules.

### 3. Create configuration

The formal wizard initializes one workspace. Enter its existing absolute path
and a device name, then run the displayed command as the ordinary user who owns
Codex and that workspace:

```sh
sub2api-codex-connector-ctl init \
  --origin https://control.example.com \
  --workspace /absolute/path/to/workspace \
  --display-name "My workstation"
```

This creates a mode-`0600` private configuration on the device. Its fixed path is:

```text
$HOME/.config/sub2api-codex-connector/connector.json
```

A non-empty `XDG_CONFIG_HOME` override is rejected so interactive commands and
the packaged background service always resolve the same configuration.

Print the effective path with:

```sh
sub2api-codex-connector-ctl config-path
```

Configuration, state, workspaces, and `CODEX_HOME` must not contain one another.
The management command also rejects symlinks, unexpected owners, and shared
writable ancestors. The browser does not need this file. Never commit
`connector.json`, send it in chat, or give it to an operator. New initialization
records an absolute Codex executable path and binds the configuration SHA-256
to a private v2 managed layout.

### 4. Pair the device

Run the command and leave it waiting:

```sh
sub2api-codex-connector-ctl pair
```

The Connector reports a private, mode-`0600` `pairing-code.json` path on
stderr. Read the 16-character one-time code only from that file. In the PWA,
select **Pair existing Connector** and enter the code. Keep `pair` running; it
exits only after the browser claim is confirmed.

The pairing code is a temporary credential. Do not screenshot it, paste it in
chat, or write it to logs. Generate a new code if it expires, is denied, or has
already been used.

### 5. Start and confirm online

Only after `pair` has completed, start the background service as the same
ordinary user:

```sh
sub2api-codex-connector-ctl start
sub2api-codex-connector-ctl status
```

Return to the PWA and confirm that the device is **Online**. The Connector makes
an outbound WSS connection only and does not listen on an inbound device port.

## Daily use

### Select a device and create a thread

1. Select an online device in the device rail.
2. Click the new-thread icon in the thread list.
3. Choose a working directory from the device's local allowlist.
4. Select a model or keep the device default.
5. Select **Create**.

The server cannot select a path outside the local allowlist or raise the sandbox
above the cap in Connector configuration.

### Send, steer, and interrupt

- Sending text while a thread is idle starts a new turn.
- While a turn is running, the composer becomes **Steer current turn**. Sending
  there steers the active turn instead of starting a concurrent one.
- Use the stop icon in the conversation header to interrupt the current turn.
- When the device is offline, recent synchronized content remains readable, but
  sending, steering, interrupting, and resuming are unavailable.

### Handle approvals

The bell in the header shows the pending count. Open the approval drawer and
review the device, request kind, summary, projected details, and expiry before
choosing **Approve** or **Deny**.

An approval is one-shot, expiring, and bound to the current connection epoch.
Timeout, disconnect, duplicate handling, device revocation, or an epoch change
invalidates it and fails closed. Deny anything whose impact you cannot confirm.

### Resume and archive

- A failed thread shows a resume icon when the device is online.
- Only idle or failed threads can be archived. A running thread or one waiting
  for approval cannot be archived.
- Archiving in Control removes the managed remote view and does not delete the
  original Codex thread on the device.

## Change workspace or sandbox

The local device owns workspace and sandbox boundaries; the browser cannot
silently expand them. Do not edit a v2 managed `connector.json`: its SHA-256 is
checked by `pair`, `start`, and `run-service`, and drift fails closed. The formal
command currently supports one workspace only and has no controlled multi-root
or sandbox-cap update.

To replace the workspace, revoke the existing device in the PWA, then run:

```sh
sub2api-codex-connector-ctl stop
sub2api-codex-connector-ctl purge-user-state --yes
sub2api-codex-connector-ctl init --origin https://control.example.com \
  --workspace /new/absolute/workspace --display-name "My workstation"
sub2api-codex-connector-ctl pair
sub2api-codex-connector-ctl start
sub2api-codex-connector-ctl status
```

The new workspace must already exist and use an absolute path. A future
controlled command is required before multi-root or sandbox-cap changes are
supported.

### Legacy fixed-path and XDG migration

A safe private legacy `connector.json` at the fixed path but without a managed
layout remains usable by `pair`, `start`, and `run-service`; the Connector
validates its structure and uses the current valid `CODEX_HOME`.
`purge-user-state` refuses it because no verified deletion boundary exists.

For an older non-empty `XDG_CONFIG_HOME`, stop the service and back up both its
configuration and the state directory named by `state_dir`. Copy, never move or
overwrite, the old configuration to the fixed path only after confirming that
the destination does not exist. Use mode `0700` on the destination directory
and `0600` on the file, unset `XDG_CONFIG_HOME`, then pair and start. Retain the
old files and backups until the device is online and its state is confirmed.

## Everyday commands

```sh
# Configuration location
sub2api-codex-connector-ctl config-path

# Service lifecycle
sub2api-codex-connector-ctl start
sub2api-codex-connector-ctl stop
sub2api-codex-connector-ctl restart
sub2api-codex-connector-ctl status

# Recent user-service logs
sub2api-codex-connector-ctl logs
```

Run every command as the ordinary Codex user. `connector-ctl` rejects root.

## Revoke, sign out, and uninstall

### Revoke a device

If a device is lost, transferred, or retired, open its action menu and select
**Revoke device**. Revocation prevents future token exchange and closes the
useful remote path. Reusing that device requires a new pairing.

### Sign out safely

Use the sign-out icon in the header to end the Control session and coordinate
Sub2API logout. Closing the browser tab is not an explicit logout. Always sign
out on a shared browser.

### Uninstall and remove state

Native package removal preserves private Connector state for investigation or
reinstallation. Revoke the device first. When the state is no longer needed,
remove it explicitly as the same ordinary user:

```sh
sub2api-codex-connector-ctl purge-user-state --yes
```

For a v2 managed configuration, this command rejects root and revalidates the
configuration SHA-256, ownership, permissions, symlinks, and every recorded
configuration/state/workspace/`CODEX_HOME` overlap before it removes the two
Connector-owned directories. It refuses legacy configurations without a
verified layout. It does not delete Codex configuration, login state, or
workspaces.

## Troubleshooting

| Symptom | Resolution order |
| --- | --- |
| PWA says Sub2API sign-in is required | Sign in at `/` on the same host, then reopen `/codex/`; do not mix hostnames |
| Formal package is unavailable | Release metadata is absent or failed validation; do not substitute an untrusted binary |
| `init` rejects a path | Use an owned, non-symlink absolute workspace with no shared-writable ancestor or overlap with configuration, state, or `CODEX_HOME`; unset `XDG_CONFIG_HOME` |
| Managed configuration changed | Do not edit it; revoke the device in the PWA, then stop, purge, and re-initialize |
| `XDG_CONFIG_HOME` is rejected | Follow the non-destructive migration above; back up configuration and state, never overwrite the fixed path, and preserve mode `0700`/`0600` |
| Pairing never completes | Keep `pair` running; check system time, HTTPS origin, outbound TCP 443/WSS, and code expiry |
| Codex version is rejected | Install exactly `codex-cli 0.147.0`; do not bypass `codex_version` or `schema_digest` |
| Service does not start | Run `connector-ctl status` and `connector-ctl logs`; check the configuration path and JSON |
| Device is offline | Check the user service, system time, and outbound TLS; an old metrics file is not process proof |
| Thread cannot be created | Select an online device and a directory in its `workspace_roots` |
| Thread cannot be archived | Wait for the turn and approvals to finish, or interrupt the turn first |
| Approval disappeared | It expired, was resolved, belongs to another user, or became stale after reconnect |
| Readiness is healthy but control fails | Readiness covers dependencies, not login, browser WSS, device WSS, or Connector policy |

When reporting a problem to an operator, provide only the time, visible symptom,
HTTP status, and a redacted error category. Never send access or refresh tokens,
cookies, pairing codes, device credentials, private paths, command output, or
workspace content.

## Remote data boundary

Control permits only `model/list`, `thread/start`, `thread/list`,
`thread/read`, `thread/resume`, `turn/start`, `turn/steer`, and
`turn/interrupt`. The browser does not receive a raw RPC channel, arbitrary
shell, arbitrary file or process access, Codex configuration, account login,
plugin management, environment variables, complete command output, or
unprojected local data. Anything not explicitly admitted is denied.

See [Operations](operations.md) for server-side incidents and the
[threat-model ADRs](adr/) for the complete security rationale.
