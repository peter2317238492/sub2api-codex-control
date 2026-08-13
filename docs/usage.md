# Usage

[简体中文](usage.zh-CN.md) | [Documentation index](../README.md#documentation)

This guide assumes an admitted Control deployment and a signed `connector-v*`
Release already exist. The current repository state is a source release
candidate; do not treat its ad hoc builds as supported production packages.

## Sign in before opening the PWA

The PWA is not a separate login page. Sign in to Sub2API at the root of the
same origin, for example `https://control.example.com/`, and then open
`https://control.example.com/codex/`. The browser exchanges the current
Sub2API access session for a short-lived, HttpOnly Control session. Refresh
credentials stay in the Sub2API browser flow and never enter the Control API.

## Pair a device

1. In the PWA, open **Devices -> Set up Connector**, install the package for
   your platform, and generate or initialize the private configuration as
   described in [Installation](installation.md#install-a-signed-connector-package).
2. Run `sub2api-codex-connector-ctl pair` and leave it running.
3. Read the code only from the mode-`0600` `pairing-code.json` path printed on
   stderr. Treat it as a temporary credential.
4. In the PWA, choose **Pair device**, enter the 16-character code, and confirm
   the displayed device and workspace information.
5. Wait for the Connector to confirm the claim and exit. An expired or rejected
   code must be paired again; do not share it over an untrusted channel.

Start the user service as the ordinary Codex user:

```sh
sub2api-codex-connector-ctl start
sub2api-codex-connector-ctl status
```

The Connector opens an outbound connection only. The native package manages it
with a user-level service and keeps its state private to that user.

Useful lifecycle and diagnostic commands are:

```sh
sub2api-codex-connector-ctl stop
sub2api-codex-connector-ctl restart
sub2api-codex-connector-ctl status
sub2api-codex-connector-ctl logs
```

## Work with Codex

1. Select an online device in the PWA.
2. Start a thread by choosing one of that device's configured workspace roots.
   The server cannot select a path outside the local allowlist.
3. Choose an admitted model, create the thread, and send text input.
4. Review approval dialogs carefully. Missing, stale, disconnected, or timed-out
   approvals are denied. A read-only Connector cannot approve writes.
5. Archive an idle or failed managed thread when it is no longer needed.

The remote projection intentionally omits raw command output, diffs, local
images, skills, arbitrary configuration, environment variables, and unrelated
local Codex threads. A method that is not explicitly admitted is denied.

## Revoke access and sign out

Use the device menu to revoke a lost or retired Connector. Revocation prevents
future token exchanges and closes the useful remote path; remove the private
Connector state directory on the device only after preserving any evidence
required by your incident policy.

Native package removal preserves the user's private Connector state. After
revocation, explicitly remove it only when it is no longer needed:

```sh
sub2api-codex-connector-ctl purge-user-state --yes
```

Use the PWA sign-out action when finished. It coordinates Control-session and
Sub2API logout. Closing a browser tab alone is not an explicit logout.

## Troubleshooting

- **The PWA returns to Sub2API:** sign in at `/` first, then reopen `/codex/`.
- **Pairing never completes:** confirm all three Connector URLs use the same
  public host, the system clock is correct, and outbound WSS is permitted.
- **Codex version rejected:** install exactly `codex-cli 0.147.0`; the Connector
  deliberately rejects contract drift.
- **Workspace rejected:** use an existing absolute directory that does not
  overlap the Connector state directory or `CODEX_HOME`.
- **Device is offline:** check the user-owned Connector process, outbound TLS,
  and the freshness of `state_dir/connector.prom`. A stale metrics file is not
  proof that the process is currently running.
- **Health is ready but controls fail:** readiness covers dependencies only. It
  does not prove authentication, browser WSS, device WSS, or Connector policy.

See [Operations](operations.md) for server-side checks and incident handling.
