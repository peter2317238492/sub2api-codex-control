# Installation on Windows

[简体中文](installation.windows.zh-CN.md) | [Documentation index](../README.md#documentation)

This guide covers the Windows Connector only. For Linux and macOS use
[installation.md](installation.md); those are the supported release targets and
this one is not.

## Support status

Windows is outside the release matrix in
`connector/release/release-config.json`. The archive produced by
`connector/packaging/windows/build-windows-package.ps1` is **not a
reproducible-release artifact**. It carries none of the evidence the Linux and
macOS packages carry:

- no Sigstore signature and no OIDC workflow identity;
- no SLSA provenance and no SPDX SBOM;
- no reproducible build inputs and no `SOURCE_DATE_EPOCH` normalization;
- no protected-tag release workflow and no immutable GitHub Release.

Build it yourself from a source revision you trust, on the host that will run
it. Do not accept this archive from anyone else, and do not redistribute it.
See [connector/release/README.md](../connector/release/README.md) for the
release boundary that does apply.

## Prerequisites

- Windows 10 1809 or Windows 11, `amd64` or `arm64`.
- Windows PowerShell 5.1 or PowerShell 7. No administrator rights are needed
  for the default installation path.
- The `ScheduledTasks` module, present by default.
- **`codex-cli` exactly `0.147.0`.** The Connector runs the configured binary
  with `--version` before every app-server start and requires the exact banner
  `codex-cli 0.147.0`; the pinned app-server schema digest is bound to that
  release. Check with `codex --version` and upgrade if it differs:

  ```powershell
  npm install -g @openai/codex@0.147.0
  ```

  Upgrading Codex is a prerequisite. Nothing in the Connector works around a
  version mismatch.
- An NTFS volume for the state directory. See the next section.
- Go 1.24 or newer, only if you are building the package yourself.

The Connector never installs or updates Codex, never writes to `CODEX_HOME`,
and never opens an inbound listener.

## Where the state directory may live

The Connector stores its Ed25519 device identity, the paired device credential,
the pairing state, the command journal, and the metrics textfile under
`state_dir`. On Linux and macOS these are protected by owner-only mode `0700`
and `0600`. On Windows the same guarantee is expressed with ACLs, and two host
facts constrain where the directory can be.

### It must be on an NTFS volume

The installer queries `GetVolumeInformationW` and refuses any volume whose
flags lack `FILE_PERSISTENT_ACLS (0x8)`:

| Volume | File system | Flags | `FILE_PERSISTENT_ACLS` |
| --- | --- | --- | --- |
| `C:\` | NTFS | `0x3E72EFF` | yes |
| `D:\` | NTFS | `0x3E72EFF` | yes |
| `E:\` | exFAT | `0x20206` | no |

exFAT and FAT32 record no ownership and no ACLs, so the owner-only guarantee is
unenforceable there. This is a hard error, not a downgrade to "skip the check" —
the Connector fails closed on an ACL question it cannot answer, exactly as it
does on Linux and macOS when an ACL query is unsupported.

### It must not be under `C:\Users`

The user profile on this host carries these entries:

```text
C:\Users\peter heosdee\CodexSandboxUsers:(OI)(CI)(M,DC)
               S-1-5-21-984626594-3510769894-950914987-1305431254:(OI)(CI)(M,DC)
               NT AUTHORITY\SYSTEM:(OI)(CI)(F)
               BUILTIN\Administrators:(OI)(CI)(F)
               HEOSDEE\peter:(OI)(CI)(F)
```

`CodexSandboxUsers` and a second non-local SID both hold `DC`
(`FILE_DELETE_CHILD`) on the profile. Any principal in either group can delete
and replace a direct child of `C:\Users\peter`, including a state directory
placed there. The Connector's ancestor validation rejects that at startup with
`connector: state_dir or a directory above it is reachable by another
principal`. It does not name the ancestor: terminal error detail is suppressed
because an error can carry a workspace path, a token, or a pairing code. Run
`install.ps1`, which does name the offending directory, or start the Connector
in a console with `sub2api-codex-connector-ctl.ps1 pair`. `DC` on a directory
is the exact Windows analogue of a POSIX parent that is group-writable without
the sticky bit, which upstream also rejects.

The installer refuses `C:\Users` before creating anything. **Do not move
`state_dir` under `%LOCALAPPDATA%` or `%USERPROFILE%` on this host.**

### Why `D:\` works

```text
D:\ BUILTIN\Administrators:(OI)(CI)(F)
    NT AUTHORITY\SYSTEM:(OI)(CI)(F)
    BUILTIN\Users:(OI)(CI)(RX)
    NT AUTHORITY\Authenticated Users:(OI)(CI)(IO)(M)
    NT AUTHORITY\Authenticated Users:(AD)
```

On `D:\` itself `Authenticated Users` holds only `(AD)`
(`FILE_ADD_SUBDIRECTORY`). It can create new entries in the volume root but
cannot delete or rename an existing one, because it has neither
`FILE_DELETE_CHILD` on `D:\` nor `DELETE` on the child. `D:\` is therefore a
trusted ancestor.

The other two entries are inheritable, so anything created under `D:\` with
default inheritance would be readable by every local user and writable by every
authenticated user. The installer therefore severs inheritance on both
`D:\sub2api-codex-connector` and its `state` child and grants only three
trustees:

```powershell
$sid = ([Security.Principal.WindowsIdentity]::GetCurrent()).User.Value
icacls <path> /inheritance:r `
  /grant:r "*${sid}:(OI)(CI)F" "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F"
```

The trustees are SIDs, not names: `SYSTEM` and `Administrators` are translated
on a localized Windows and would not resolve.

It hardens the install root **before** creating `state` inside it, so the state
directory never exists, even briefly, with the volume root's inheritable
`Authenticated Users` grant applied. It then re-reads the resulting descriptor
and fails if the DACL is not protected, if the owner is not the installing user,
if any inherited rule survived, or if any trustee outside those three appears.

## Build the package

```powershell
cd <repo>\connector\packaging\windows
.\build-windows-package.ps1 -OutputDir C:\temp\connector-dist
```

This cross-compiles `windows/amd64` and `windows/arm64`, stages the three
operator scripts, the configuration template, the licence files, a `SHA256SUMS`
file, and a `RELEASE-NOT-FOR-DISTRIBUTION` marker, and writes a zip. The
command prints the zip's own SHA-256 and repeats the not-a-release warning.

Pass `-GoExe` if the pinned Go toolchain is not on `PATH`.

Extract the zip somewhere you control and run the scripts from there.

## Install

```powershell
.\install.ps1 `
  -WorkspaceRoot D:\code `
  -InstallRoot D:\sub2api-codex-connector `
  -Origin https://sub2api.wyswd.top `
  -DisplayName "My workstation"
```

The installer:

1. validates the origin, the workspace roots, the state volume, and the state
   path shape (an NTFS alternate data stream such as `state:hidden` and any
   wildcard character are rejected);
2. creates and protects `D:\sub2api-codex-connector` and
   `D:\sub2api-codex-connector\state`, then verifies the result;
3. copies `sub2api-codex-connector.exe` into `D:\sub2api-codex-connector\bin`;
4. locates the vendored `codex.exe` by resolving `npm prefix -g` and checks its
   `--version` banner against the pin;
5. writes `D:\sub2api-codex-connector\connector.json` from the template if it
   does not already exist;
6. registers a scheduled task named `sub2api-codex-connector` that runs at
   logon as the current user.

Re-running the installer converges: it re-applies and re-verifies the DACLs,
overwrites the task in place rather than duplicating it, and **never overwrites
an existing `connector.json`**.

Useful switches:

| Switch | Effect |
| --- | --- |
| `-StateDir DIR` | put the state directory somewhere other than `INSTALLROOT\state` |
| `-CodexBinary PATH` | skip npm resolution and use this `codex.exe` |
| `-ConnectorBinary PATH` | install a Connector executable from outside the package |
| `-SkipTask` | do everything except register the scheduled task |
| `-AllowCodexVersionMismatch` | stage the install before upgrading Codex; the Connector still refuses to start app-server |

### The scheduled task

The task runs at logon as the interactive user with `-LogonType Interactive`,
so **no password is stored**. It restarts up to 3 times at 1-minute intervals,
has no execution time limit, and uses `IgnoreNew` for multiple instances so a
second Connector cannot fight the first for the `state_dir` lock.

Running as the real interactive account is deliberate: the Connector needs that
user's `CODEX_HOME` credentials, and the owner-only ACL model is most natural
when the owner is a real logged-on account.

### `codex_binary` must be `codex.exe`

The npm install exposes `codex` and `codex.cmd` shims, but the real executable
is:

```text
C:\Users\<you>\AppData\Roaming\npm\node_modules\@openai\codex\node_modules\@openai\codex-win32-x64\vendor\x86_64-pc-windows-msvc\bin\codex.exe
```

The installer resolves this from `npm prefix -g` rather than hard-coding a user
name, and picks the `arm64` vendor directory on ARM hosts. A `.cmd` or `.bat`
shim is rejected: it launches `cmd.exe`, which breaks the `--version` check's
process identity, inserts a batch-argument parsing layer between the Connector
and Codex, and leaves the real Codex process one generation further from the
handle the Job Object was built around.

## Pair

Pair before starting the task. Pairing needs the `state_dir` lock, so the
Connector must not already be running.

```powershell
.\sub2api-codex-connector-ctl.ps1 pair
```

The command runs the Connector with `-pair-only`, waits for the private
`pairing-code.json` to appear inside `state_dir`, and prints the code and its
expiry. Open the authenticated Control PWA, choose **Pair existing Connector**,
and enter the code. Leave the command running until it confirms the browser
claim and exits.

**Treat the code as sensitive until it expires or is claimed.** Enter it only
in the authenticated same-origin PWA. The Connector itself never writes the
code to its log — only the path of `pairing-code.json` — so restrict access to
the state directory and to any console transcript that captured the code.

If `pair` reports that the Connector is already running, stop it first:

```powershell
.\sub2api-codex-connector-ctl.ps1 stop
```

## Start and verify

```powershell
.\sub2api-codex-connector-ctl.ps1 start
.\sub2api-codex-connector-ctl.ps1 status
```

`status` prints three independent facts and exits non-zero if any is unhealthy:

```text
task:    \sub2api-codex-connector Running, last run 2026-08-20 11:04:12, last result 0x0
process: D:\sub2api-codex-connector\bin\sub2api-codex-connector.exe pid 24188
metrics: D:\sub2api-codex-connector\state\connector.prom last update 7s ago
config:  D:\sub2api-codex-connector\connector.json
state:   D:\sub2api-codex-connector\state
```

Metrics freshness is the real health signal, not
`codex_control_connector_up`. That gauge reads `0` only after a *graceful*
stop; a hard process kill leaves the last atomically written textfile intact
with `up 1`. `status` therefore requires
`codex_control_connector_last_update_timestamp_seconds` to be within 60 seconds
of now, and treats both stale and implausibly future values as unhealthy —
matching the external Prometheus rules shipped for Linux and macOS.

On Windows the textfile is consumed by
`windows_exporter --collector.textfile`. The collector must run as the
Connector's own account or as an explicitly trusted privileged service; the
protected DACL means no other unprivileged account can read it.

## How workspace roots appear in the PWA

The Control API refuses anything that is not an absolute POSIX path, and the
server is not modifiable in this deployment. Windows paths therefore never
leave the host: the Connector projects them at the network boundary using the
Git-Bash form.

```text
D:\code\app        ->  /d/code/app
C:\Users\me\proj   ->  /c/Users/me/proj
\\nas\share\proj   ->  /unc/nas/share/proj
```

So a workspace root configured as `D:\code\app` is displayed in the PWA as
`/d/code/app`, and every `cwd`, approval `path`, and grant root in the PWA uses
that same projected form. **This is not a bug.** Configure `workspace_roots` in
`connector.json` with ordinary local Windows paths; the projection happens on
the way out and is reversed on the way in.

Details that matter when reading a projected path:

- The drive letter is lower-case in the projected form. The local path keeps the
  canonical casing the filesystem reports.
- `\` becomes `/`. The projected form is always already normalised, and a path
  that does not round-trip back to the identical original is rejected.
- A UNC path `\\host\share\...` becomes `/unc/host/share/...`.
- A volume root alone cannot be a workspace root: `/c` and `/unc/host` are
  refused, matching the existing rule that the filesystem root cannot be a
  workspace root.
- Components that are `.`, `..`, empty, end in a space or a dot, or name a
  reserved DOS device (`CON`, `PRN`, `AUX`, `NUL`, `COM1`–`COM9`,
  `LPT1`–`LPT9`) are refused, because they do not name real directories.
- Matching an incoming path against the configured roots is case-insensitive on
  Windows.

## Logs

Under a scheduled task there is no console to read, so the Connector also
writes its stderr to a rotating log file inside the state directory, created
with the same protected DACL as every other state object:

```text
D:\sub2api-codex-connector\state\connector.log
```

```powershell
.\sub2api-codex-connector-ctl.ps1 logs
.\sub2api-codex-connector-ctl.ps1 logs -Tail 500
.\sub2api-codex-connector-ctl.ps1 logs -Follow
```

Pass `-LogPath` if the log lives somewhere other than `state\connector.log`.

The pairing code is never written to the log — only the path of
`pairing-code.json`.

## Upgrade

Upgrading preserves `connector.json` and the whole state directory, so the
device stays paired.

```powershell
.\sub2api-codex-connector-ctl.ps1 stop
# extract the new package, then from the new package directory:
.\install.ps1 -WorkspaceRoot D:\code -InstallRoot D:\sub2api-codex-connector
.\sub2api-codex-connector-ctl.ps1 start
.\sub2api-codex-connector-ctl.ps1 status
```

The installer replaces the executable and the scheduled task and leaves the
existing configuration untouched.

To upgrade Codex, stop the Connector first and run
`npm install -g @openai/codex@<version>`. Re-running `install.ps1` does **not**
update `connector.json`: it never overwrites an existing configuration, and it
validates the binary it resolves rather than the `codex_binary` already
recorded. If the upgrade moved the vendored `codex.exe`, edit `codex_binary`
yourself. A Codex upgrade
that moves away from the pinned `0.147.0` will make the Connector fail closed
before app-server starts.

## Uninstall

```powershell
.\uninstall.ps1
```

This removes the scheduled task and stops the process. It **keeps
`state_dir`**, because that directory holds the paired device credential and
deleting it silently would force a re-pair.

To remove the state as well, revoke the device in the Control PWA first, then:

```powershell
.\uninstall.ps1 -PurgeState
```

`-PurgeState` prompts for the word `purge` before deleting anything. Add
`-Force` to skip the prompt in an automated context. Codex configuration, Codex
credentials, and workspace files are never touched.

## Troubleshooting

**`does not report FILE_PERSISTENT_ACLS`** — the chosen volume is exFAT or
FAT32. Pick an NTFS volume. The source tree living on an exFAT volume is fine;
only `state_dir` and the install root are constrained.

**`refusing to install under C:\Users`** — see
[It must not be under `C:\Users`](#it-must-not-be-under-cusers). Use
`D:\sub2api-codex-connector`.

**`grants access to S-1-5-…; only the Connector user, SYSTEM, and
Administrators are allowed`** — the directory already existed and carries an
explicit ACE for another trustee. `icacls /grant:r` replaces the rights of the
trustees it names and leaves every other explicit ACE in place, so the
installer cannot assume it removed it. Establish why that trustee was granted
access, remove it with the `icacls … /remove:g` command the error prints, and
run the installer again. This is deliberately a hard failure: an unexpected ACE
is an error, never something to skip past.

**`is owned by … not by the Connector user`** — the directory was created by a
different account, or by an elevated shell under a policy that makes
`Administrators` the owner of objects it creates. Take ownership as the
Connector user, or delete the empty directory and let the installer create it.

**`codex reports 'codex-cli 0.145.0' but the Connector pins 'codex-cli
0.147.0'`** — run `npm install -g @openai/codex@0.147.0`. Nothing else fixes
this.

**`connector: state directory is already in use`** — another Connector process
holds the `state_dir` lock. Run `sub2api-codex-connector-ctl.ps1 stop`, confirm
with `status` that no process remains, then retry. This is the usual cause of a
failed `pair` while the scheduled task is running.

**`connector: state_dir is on a volume that cannot record access control
lists; choose an NTFS volume`** — the same condition the installer refuses, seen
at run time because `connector.json` was edited by hand afterwards. See
[It must be on an NTFS volume](#it-must-be-on-an-ntfs-volume).

**`connector: state_dir or a directory above it is reachable by another
principal; choose a private location`** — some directory in the `state_dir` path
grants a foreign trustee the right to replace what sits beneath it. On a host
with Codex installed this is almost always a `state_dir` under `C:\Users`; see
[It must not be under `C:\Users`](#it-must-not-be-under-cusers).

Every other failure prints `connector: terminated with an error (details
suppressed)`. That is deliberate: an error message can carry a workspace path,
a bearer token, or a pairing code, and under the scheduled task it would land in
the log file. The two messages above are exceptions because they are fixed
strings that describe a placement mistake without describing your machine. To
see the underlying error, stop the task and run the Connector in a console with
`sub2api-codex-connector-ctl.ps1 pair`, which reports failures directly.

**A console window appears at logon** — the task runs interactively so the
Connector's console is attached to your session. It is harmless; the same
output is in `state\connector.log`. Minimise it, or stop the task and start the
Connector by hand when you do not want it.

**Task state is `Ready` but nothing is running** — the process exited. Check
`state\connector.log` and the task's last result in `status`. The task restarts
up to 3 times at 1-minute intervals before giving up; `start` re-runs it.

**`status` shows a running process but stale metrics** — the Connector is alive
but has not refreshed its textfile within 60 seconds. Treat this as unhealthy
and read `state\connector.log`; the textfile refreshes every 15 seconds
independently of connection state, so staleness means the process is wedged,
not merely disconnected.

**The PWA shows `/d/code/app` instead of `D:\code\app`** — expected. See
[How workspace roots appear in the PWA](#how-workspace-roots-appear-in-the-pwa).
