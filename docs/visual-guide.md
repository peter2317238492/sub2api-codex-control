# Visual usage guide

[简体中文](visual-guide.zh-CN.md) · Full text references: [User guide](usage.md) · [Installation](installation.md)

This guide walks you from zero to daily use of Sub2API Codex Control with a diagram for every stage, followed by copy-paste commands. Run every command as the ordinary user who owns Codex; `connector-ctl` refuses root.

## 1. Architecture at a glance

The Connector opens an **outbound** WSS connection only — your device exposes no inbound port, and the browser never talks to your device directly.

```mermaid
flowchart LR
    subgraph browser["Your browser (computer or phone)"]
        PWA["Control PWA<br/>https://your-site/codex/"]
    end
    subgraph server["Sub2API server (operator-deployed)"]
        S2A["Sub2API site login"]
        API["Control API"]
        DB[("PostgreSQL / Redis")]
    end
    subgraph device["Your device (Linux amd64 / arm64)"]
        CONN["Connector<br/>sub2api-codex-connector"]
        CODEX["Your own Codex installation"]
    end
    PWA -- "HTTPS (short-lived HttpOnly session)" --> API
    PWA -. "same-origin login" .-> S2A
    API --- DB
    CONN == "outbound WSS (no inbound port)" ==> API
    CONN -- "local calls" --> CODEX
```

Remote capability is fixed to **eight RPC classes** — there is no raw remote shell:

| Class | RPCs |
| --- | --- |
| Models | `model/list` |
| Threads | `thread/start` · `thread/list` · `thread/read` · `thread/resume` |
| Turns | `turn/start` · `turn/steer` · `turn/interrupt` |

## 2. First-time setup journey (5 steps)

```mermaid
flowchart TD
    A["① Sign in and open Control<br/>log in at the Sub2API site root,<br/>then open /codex/ on the same origin"] --> B
    B["② Install the Connector<br/>download the .deb / .rpm from the PWA,<br/>verify the SHA-256 matches the GitHub Release exactly"] --> C
    C["③ Create the configuration<br/>connector-ctl init<br/>writes a private 0600 connector.json"] --> D
    D["④ Pair the device<br/>keep connector-ctl pair running,<br/>read the 16-digit code from the private file into the PWA"] --> E
    E["⑤ Start and confirm online<br/>connector-ctl start<br/>the device shows Online in the PWA"]
```

Commands per step (replace `https://control.example.com` with your site and use a real absolute workspace path):

```sh
# ③ create the configuration
sub2api-codex-connector-ctl init \
  --origin https://control.example.com \
  --workspace /absolute/path/to/workspace \
  --display-name "My workstation"

# ④ pair (keep it running until the web claim completes and it exits)
sub2api-codex-connector-ctl pair

# ⑤ start and confirm
sub2api-codex-connector-ctl start
sub2api-codex-connector-ctl status
```

> Safety: install only when the tag, filename, and SHA-256 shown by the PWA agree exactly with the [GitHub Releases page](https://github.com/peter2317238492/sub2api-codex-control/releases); read the pairing code only from the mode `0600` `pairing-code.json` — never screenshot it or paste it into chat; never commit or share `connector.json`.

## 3. How pairing completes (sequence)

```mermaid
sequenceDiagram
    autonumber
    participant T as Device terminal
    participant F as pairing-code.json (0600)
    participant U as You
    participant P as Control PWA
    participant A as Control API
    T->>T: sub2api-codex-connector-ctl pair
    T->>F: write one-time 16-digit code
    T-->>A: wait for the claim (keep running)
    U->>F: read the code from the private file only
    U->>P: click "Pair existing Connector" and enter it
    P->>A: submit the code
    A-->>T: claim accepted
    T->>T: pair exits on its own
    Note over U,A: codes are one-time and short-lived — expired, rejected, or used codes must be regenerated
```

## 4. Daily use: threads and turns

```mermaid
flowchart TD
    S["Pick an online device"] --> N["New thread: choose a workspace (local allowlist only) + a model"]
    N --> I["Thread idle"]
    I -- "type and send" --> R["Turn running"]
    R -- "send again = steer the running turn" --> R
    R -- "stop icon" --> X["Interrupted"]
    R --> DN["Completed"]
    R --> FL["Failed"]
    FL -- "resume icon while the device is online" --> R
    X --> I
    DN --> I
    I -- "archive when idle or failed" --> AR["Archived (removes the remote view only — the on-device Codex thread stays)"]
    FL --> AR
```

- The server can never choose a path outside the device-local allowlist, nor raise the sandbox above the Connector's configured cap.
- While a device is offline you can still read recently synced content, but not send, steer, interrupt, or resume.

## 5. How approvals flow (sequence)

```mermaid
sequenceDiagram
    autonumber
    participant C as Codex (your device)
    participant K as Connector
    participant A as Control API
    participant P as PWA (bell icon)
    participant U as You
    C->>K: request a privileged action
    K->>A: report the pending approval
    A->>P: bell shows the pending count
    U->>P: open the approvals drawer
    P->>U: device, request type, summary, projected details, expiry
    alt understood and impact confirmed
        U->>P: Approve
    else unclear or unverifiable
        U->>P: Deny
    end
    P->>A: submit the decision
    A->>K: deliver (one-time, time-boxed, bound to the connection generation)
    Note over C,U: timeout / disconnect / duplicate handling / revocation / generation change ⇒ invalid, denied by default
```

## 6. When something goes wrong (decision tree)

```mermaid
flowchart TD
    Q["Device not Online in the PWA?"] --> S1["sub2api-codex-connector-ctl status"]
    S1 -- "service not running" --> S2["sub2api-codex-connector-ctl start"]
    S1 -- "running but offline" --> S3["sub2api-codex-connector-ctl logs<br/>inspect the recent user-service log"]
    S3 --> S4{"Log points at pairing or credentials?"}
    S4 -- "yes" --> S5["revoke the device in the PWA,<br/>then pair + start again"]
    S4 -- "no" --> S6["check outbound network and the site origin,<br/>then see the user guide's troubleshooting section"]
    S2 --> OK["confirm Online in the PWA"]
    S5 --> OK
    S6 --> OK
```

Handy commands:

```sh
sub2api-codex-connector-ctl config-path   # where the configuration lives
sub2api-codex-connector-ctl restart       # restart the service
sub2api-codex-connector-ctl logs          # recent logs
```

## 7. Changing workspace, revoking, uninstalling

The formal commands support one workspace at a time; changing it means revoke-and-recreate:

```mermaid
flowchart LR
    R1["PWA: revoke the device"] --> R2["stop"] --> R3["purge-user-state --yes"] --> R4["init (new workspace)"] --> R5["pair"] --> R6["start + status"]
```

```sh
sub2api-codex-connector-ctl stop
sub2api-codex-connector-ctl purge-user-state --yes
sub2api-codex-connector-ctl init --origin https://control.example.com \
  --workspace /new/absolute/workspace --display-name "My workstation"
sub2api-codex-connector-ctl pair
sub2api-codex-connector-ctl start
sub2api-codex-connector-ctl status
```

To remove everything: **revoke the device** in the PWA first, uninstall the native package (which keeps the private state by default), and only when you are sure you no longer need it, run `purge-user-state --yes` as the same ordinary user. It never deletes Codex configuration, login files, or your workspace.

On shared devices, always sign out with the top-bar logout icon rather than just closing the tab.

---

For the full details (XDG migration, approval semantics, security boundaries, complete troubleshooting) see the [user guide](usage.md) and the [installation guide](installation.md).
