# Windows Connector — port design

This document is the single source of truth for the Windows Connector port. It
records the constraints that were measured on a real Windows 11 host, the
security model that replaces the POSIX one, and the exact boundary at which
Windows paths are projected into the POSIX form the Control API requires.

Read this before changing any file under `connector/`.

## 1. What was already true before the port

The Connector compiles for `windows/amd64` today. It does not run:

| File | State before the port |
| --- | --- |
| `internal/statelock/lock_windows.go` | Stub. `checkPlatform` returns `connector state locking is unsupported on Windows`. |
| `internal/securefile/access_windows.go` | Stub. `ownerID`/`validateACL` return `secure state files are unsupported on Windows`. |
| `internal/appserver/process_tree_windows.go` | **Real** Job Object implementation. Kept, hardened. |
| `internal/pairing/state_lock_windows.go` | **Real** exclusive-`CreateFile` implementation. Kept. |
| `internal/transport/production_canary_crash_unsupported.go` | Already covers `windows` via `!(darwin || linux)`. Unchanged. |

Baseline `go test ./...` on `windows/amd64`: 13 of 16 packages fail, every
failure rooted in the `securefile` stub. Only `approval`, `config`, and
`protocol` pass. Making that suite green natively on Windows is the acceptance
criterion for this port.

## 2. Measured host constraints

These were measured, not assumed. Re-measure before changing any rule derived
from them.

### 2.1 Volumes

```
C:\  NTFS   flags=0x3E72EFF  FILE_PERSISTENT_ACLS=True
D:\  NTFS   flags=0x3E72EFF  FILE_PERSISTENT_ACLS=True
E:\  exFAT  flags=0x20206    FILE_PERSISTENT_ACLS=False
```

The source tree lives on `E:` (exFAT). exFAT stores no ownership and no ACLs,
so the entire Windows security model is unenforceable there. `state_dir` must
therefore refuse any volume whose `GetVolumeInformationW` flags lack
`FILE_PERSISTENT_ACLS (0x8)`, and it must refuse it as a hard error rather than
degrading to "no checks". This mirrors the upstream rule that an ACL inspection
error fails closed instead of falling back to mode bits.

### 2.2 `D:\` — the chosen state volume

```
D:\ BUILTIN\Administrators:(OI)(CI)(F)
    NT AUTHORITY\SYSTEM:(OI)(CI)(F)
    BUILTIN\Users:(OI)(CI)(RX)
    NT AUTHORITY\Authenticated Users:(OI)(CI)(IO)(M)
    NT AUTHORITY\Authenticated Users:(AD)
```

Three facts drive the design:

- `Authenticated Users` holds only `(AD)` — `FILE_ADD_SUBDIRECTORY` — on `D:\`
  itself. It can create *new* entries in the volume root but cannot delete or
  rename an existing one, because it has neither `FILE_DELETE_CHILD` on `D:\`
  nor `DELETE` on the child. `D:\` is therefore a **trusted ancestor**.
- `Users:(OI)(CI)(RX)` and `Authenticated Users:(OI)(CI)(IO)(M)` are
  *inheritable*. Anything created under `D:\` with default inheritance is
  readable by every local user and writable by every authenticated user. The
  state directory and every state file must therefore carry a **protected**
  DACL (`SE_DACL_PROTECTED`, inheritance severed), not merely a restrictive one.
- **Both volume roots are owned by `NT SERVICE\TrustedInstaller`**, SID
  `S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464` — measured
  with `(Get-Acl 'D:\').GetOwner([SecurityIdentifier])`, same value for `C:\`.
  Not SYSTEM, not Administrators. See §3's owner rule, which had to account for
  this: an earlier draft of that rule made the Connector unable to start
  anywhere on a stock Windows install.

Note the intermediate directory matters too. `D:\sub2api-codex-build` inherits
`Authenticated Users:(I)(M)` from the volume root, and Modify includes `DELETE`,
so an authenticated user could delete that directory and substitute their own.
Any directory between the volume root and `state_dir` must therefore have its
inheritance severed as well — which is why `install.ps1` protects the install
root, not just `state`.

### 2.3 `C:\Users\peter` — why the user profile is not usable

```
C:\Users\peter heosdee\CodexSandboxUsers:(OI)(CI)(M,DC)
               S-1-5-21-984626594-3510769894-950914987-1305431254:(OI)(CI)(M,DC)
               NT AUTHORITY\SYSTEM:(OI)(CI)(F)
               BUILTIN\Administrators:(OI)(CI)(F)
               HEOSDEE\peter:(OI)(CI)(F)
```

`CodexSandboxUsers` and a second non-local SID both hold `DC`
(`FILE_DELETE_CHILD`) on the profile directory. A principal in either group can
delete and replace any direct child of `C:\Users\peter`, including a state
directory placed there. Ancestor validation must — and does — reject it. This
is why the default `state_dir` is on `D:`, not under `%LOCALAPPDATA%`.

Operator-visible consequence: **do not move `state_dir` under the user profile
on this host.** The Connector will refuse to start and the message will name the
offending ancestor.

### 2.4 Process identity

Interactive user is `heosdee\peter`, SID
`S-1-5-21-2331274031-401781635-4243295545-1001`. The Connector runs as this
user (scheduled task at logon), so the owner SID it enforces is the token user
SID, resolved at run time — never hard-coded.

### 2.5 Codex CLI

The npm install exposes `codex` and `codex.cmd` shims, but the real executable is

```
C:\Users\peter\AppData\Roaming\npm\node_modules\@openai\codex\node_modules\@openai\codex-win32-x64\vendor\x86_64-pc-windows-msvc\bin\codex.exe
```

`codex_binary` must point at that `.exe`. A `.cmd`/`.bat` shim is rejected: it
launches `cmd.exe`, which breaks the `--version` pin check's process identity,
adds a batch-argument parsing layer between the Connector and Codex, and leaves
the real Codex process one generation further from the handle the Job Object
was built around.

Installed version at the time of writing is `codex-cli 0.145.0`; the Connector
pins `0.147.0` and the pinned schema digest is bound to that release. Upgrading
Codex is a prerequisite, not something the port can work around.

## 3. Security model: POSIX rules and their Windows equivalents

The upstream guarantee is: *state objects are reachable only by the Connector's
own principal and by fully privileged system principals; anything else fails
closed.* The port preserves the guarantee and changes only the mechanism.

| POSIX rule (`access_unix.go`, `lock_unix.go`) | Windows equivalent |
| --- | --- |
| `stat.Uid == geteuid()` | Object owner SID equals the process token user SID. |
| `allowRoot` permits `uid == 0` for ancestors | `allowRoot` permits owner `S-1-5-18` (LocalSystem), `S-1-5-32-544` (Administrators), or `NT SERVICE\TrustedInstaller`. **The TrustedInstaller entry is load-bearing, not a convenience** — see below. |
| ACL must not grant access to others | DACL must be present and non-NULL; every non-inherit-only **allow** ACE must name the owner SID, `S-1-5-18`, `S-1-5-32-544`, or `NT SERVICE\TrustedInstaller`. Any other allow trustee fails closed. TrustedInstaller is in this set for the same reason it is in the owner set below: it is a fully privileged OS-managed principal that an unprivileged account cannot assume, so admitting its ACE grants no access the set did not already imply. |
| Darwin deny-only ACLs are accepted | **Deny** ACEs are accepted regardless of trustee: they only subtract access. |
| Final dir mode `0700`, files `0600` | DACL is *protected* (`SE_DACL_PROTECTED`) and contains exactly owner-full, `SYSTEM`-full, `Administrators`-full. Inheritance is severed so §2.2's inheritable ACEs cannot apply. |
| Ancestor must not be group/other writable **unless the sticky bit is set** | No foreign trustee may hold `FILE_DELETE_CHILD` on the ancestor, and no foreign trustee may hold `DELETE`, `WRITE_DAC`, or `WRITE_OWNER` on the child being descended into. The sticky bit means exactly "non-owners cannot delete children", so this is a faithful mapping — and it is why `D:\`'s `(AD)`-only grant passes while a `DC` grant fails. |
| ACL query error fails closed | Same. A failed `GetSecurityInfo`, an unsupported query, or a volume without `FILE_PERSISTENT_ACLS` is an error, never a downgrade. |
| Symlink components rejected | Any component with `FILE_ATTRIBUTE_REPARSE_POINT` is rejected — this covers symlinks, directory junctions, and mount points, all of which redirect like a POSIX symlink. |
| `Nlink == 1` on the lock file | `FILE_STANDARD_INFORMATION.NumberOfLinks == 1` via `GetFileInformationByHandle`. |

### 3.0 Why TrustedInstaller is in the `allowRoot` set

The first draft of the table above mapped `allowRoot` to LocalSystem and
Administrators only. That was wrong, and wrong in a way that made the port
unusable rather than merely inconvenient: on a stock Windows install the volume
roots are owned by `NT SERVICE\TrustedInstaller`, so the ancestor walk rejected
its very first component and no `state_dir` could be validated anywhere — on any
machine, not just this one. Three independent implementations hit it and
reported it rather than working around it.

TrustedInstaller is the faithful analogue of a root-owned `/`:

- It owns the OS-managed filesystem (volume roots, `Windows`, `Program Files`)
  by default.
- Its SID is derived from the service name, so it is the same constant on every
  Windows install — it can be pinned, not discovered.
- An unprivileged principal cannot assume it. Only SYSTEM or Administrators can
  take ownership away from it, and both are already in the trusted set, so
  admitting TrustedInstaller grants no capability that the set did not already
  imply.

The whole `S-1-5-80` service-SID class is deliberately **not** trusted: every
installed service receives a SID in that class, so trusting the class would let
any third-party service's ownership pass as privileged. Only the one pinned SID
is accepted.

### 3.1 Creation must be atomic with respect to the DACL

On POSIX, `os.Mkdir(path, 0o700)` and `os.OpenFile(..., 0o600)` create the
object already private. On Windows, creating an object and then calling
`SetSecurityInfo` leaves a window in which the inherited `Authenticated
Users:(M)` ACE from §2.2 applies. Every state object must therefore be created
by passing a `SECURITY_ATTRIBUTES` with the protected DACL to
`CreateFileW`/`CreateDirectoryW`. Post-hoc hardening is only acceptable when
adopting an object that already existed, and it must be followed by a
re-validation of the resulting descriptor.

### 3.2 Alternate data streams

`state_dir\file:stream` is a distinct writable object on NTFS. Reject any state
path component containing `:` beyond the drive-letter prefix, and reject
wildcard characters, so a configured path cannot name a stream.

## 4. Path projection — why it exists and where it lives

The Control API refuses anything that is not an absolute POSIX path.
`apps/control-api/src/control_api/security.py:204`:

```python
if not root.startswith("/") or root.startswith("//"):
    raise ValueError(f"workspace_roots[{index}] must be an absolute POSIX path")
if root == "/": ...
if posixpath.normpath(root) != root: ...
```

Both the pairing-start body (`schemas.py`) and the WSS Hello payload
(`protocol.py`) run it, and `realtime.py::_cwd_in_roots` runs it again on every
`cwd`. The Connector's own `internal/protocol/protocol.go` already enforces the
same POSIX shape on Hello. The server is not modifiable in this deployment.

Windows paths therefore never leave the host. A new package,
`internal/wspath`, owns a total, reversible mapping and every conversion happens
at exactly two boundaries.

### 4.1 Mapping (Git-Bash form)

```
C:\Users\peter\code\app   <->  /c/Users/peter/code/app
\\nas\share\proj          <->  /unc/nas/share/proj
```

Rules:

- Drive letters lower-case in the remote form; the local form keeps the
  canonical Windows casing returned by the filesystem.
- `\` becomes `/`. The remote form must satisfy `path.Clean(r) == r`, must start
  with a single `/`, and must not be `/`.
- A remote path is rejected unless it round-trips: `Remote(Local(r)) == r`.
- Reject any component that is `.`, `..`, empty, ends in a space or dot, or is a
  reserved DOS device name (`CON`, `PRN`, `AUX`, `NUL`, `COM1`–`COM9`,
  `LPT1`–`LPT9`), since those do not name real directories.
- Reject `/c` and `/unc/host` alone: a volume root cannot be a workspace root,
  matching the existing "filesystem root cannot be a workspace root" rule.
- Matching a remote path against configured roots is case-insensitive on
  Windows and case-sensitive elsewhere.

### 4.2 The mapper is identity on Linux and macOS

`wspath.Mapper` must be a no-op on non-Windows targets so the existing 20k-line
test suite keeps its current behaviour exactly. Build-tag the platform half;
never branch on `runtime.GOOS` inside shared logic.

### 4.3 The two boundaries

Inbound (server → app-server), remote POSIX becomes a local Windows path:

- `policy.Guard` is the only inbound converter. `Guard.CanonicalCWD` accepts the
  remote form, maps it to local, resolves and containment-checks it, and returns
  the **local** path. `policy.go` then stores that local path back into
  `params["cwd"]`, which is what app-server receives.
- Everything downstream of the guard — `control/router.go`,
  `localstate.Thread.CWD`, `runtime.go` — keeps working in **local** paths, so
  `Guard.ContainsCWD(thread.CWD)` continues to receive what it expects.

Outbound (app-server → server), local becomes remote POSIX:

- `policy/projection.go` converts `result["cwd"]` and the thread `cwd` field.
- `policy.go`'s approval validation and `approval/broker.go` convert before the
  payload is spooled, so the PWA never displays a Windows path and never
  receives one it would reject. Every path the payload carries is covered, not
  just the obvious three:
  - the `cwd`, `grantRoot`, and `path` detail fields;
  - the **keys** of `fileChanges` — the map is keyed by the changed file, so the
    keys are paths — and each change's `move_path`;
  - every filesystem path inside `permissions`, via
    `policy.RemotePermissions`. That one needs a deep copy: the validated
    profile is the same map instance handed back to app-server, so projecting
    it in place would corrupt what app-server receives. `RemotePermissions`
    also accepts both the concrete `[]string` slices `Guard.ValidatePermissions`
    builds and the `[]any` a JSON decode produces, because the Broker takes its
    permission validator as an interface.
  - Deny globs inside `permissions.fileSystem.entries` go through
    `wspath.Mapper.RemotePattern` rather than `Remote`: a pattern is matched,
    never opened, so its components legitimately carry `*` and `?`, which
    `Remote` rejects. Traversal and control characters are still refused.

  A path that cannot be projected fails the whole payload and the approval is
  declined, which is the same posture the rest of this function already takes.
  Declining is safe: decline is the default outcome everywhere in this codebase.

  The Control API does not validate these fields — `ApprovalItem.details` is
  `dict[str, Any]` — so an unprojected path would not have broken the flow. It
  would have shown the operator `D:\code\app\main.go` in one field and
  `/d/code/app` in another, which reads as a bug and undermines trust in what
  they are approving.
- `runtime.go`'s Hello `WorkspaceRoots` and `cmd/connector/main.go`'s pairing
  `WorkspaceRoots` send the remote form.

`policy.NewGuard` keeps receiving **local** roots from the config.

### 4.4 One upstream validation must be generalised

`pairing.Client.initialize` validates roots with `filepath.IsAbs` and
`filepath.Clean`. On Windows `filepath.IsAbs("/c/Users/peter")` is **false**, so
projected roots would be rejected locally before ever reaching the network.
Replace that check with the POSIX rules already used by
`internal/protocol/protocol.go` for Hello — `strings.HasPrefix(root, "/")`, not
`//`, not `/`, `path.Clean(root) == root`. On Linux and macOS `path` and
`filepath` agree, so this is behaviour-preserving there and correct on Windows.

## 5. Child process

`process_tree_windows.go` already creates a Job Object with
`JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` and assigns the child. Two gaps remain:

- **Assignment race.** The child is assigned to the job only after it starts, so
  a grandchild spawned in that window escapes the job and survives shutdown.
  Start the child `CREATE_SUSPENDED`, assign it to the job, then `ResumeThread`.
- **Console window.** `SysProcAttr.HideWindow` must be set, and
  `CREATE_NO_WINDOW` used, or a console flashes on every app-server restart
  under the scheduled task.

`VerifyVersion` keeps running the configured binary with `--version` and
requiring the exact pinned banner, and refuses a `.cmd`/`.bat` shim per §2.5.

### 5.1 `WaitDelay` has to outlast the graceful window

Running against the real Codex 0.147.0 surfaced something the fake CLI never
did: a clean shutdown returned `exec: WaitDelay expired before I/O complete`,
and took a fixed two seconds to do it.

The mechanism is a timing invariant, not a Windows API mistake:

- `Cmd.WaitDelay` starts counting when the **child exits**, and bounds how long
  `Wait` tolerates I/O pipes that are still open.
- The Connector closes stdio, waits `ShutdownGracePeriod` for a graceful exit,
  and only then escalates to terminating the process tree.
- Both values were two seconds. Codex exits in milliseconds but leaves a
  descendant holding the pipes, so `Wait` gave up at the same moment the
  Connector was escalating — before the descendants holding those pipes had
  been killed.

`WaitDelay` is therefore derived as `ShutdownGracePeriod + forcedShutdownWait`:
`Wait` may only abandon the pipes after the Connector's own escalation has had
its full window. The read loop also closes the stdout pipe when it finishes,
since an unclosed pipe is exactly what `WaitDelay` is bounding.

A residual remains and is deliberate. `CREATE_NO_WINDOW` hides the console but
still allocates one, and the `conhost.exe` that the console subsystem creates is
not a job member, so it can briefly outlive `TerminateJobObject` holding the
child's stderr. `DETACHED_PROCESS` avoids the console entirely and measured
5-of-6 clean shutdowns against 4-of-6 — inside the noise, and it denies Codex a
console it may legitimately want, so it was not adopted.

What matters is that the residual is confined to pipe timing. The termination
guarantee is independent: the job object carries
`JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`, and a measured shutdown leaves no process
from the tree alive. The live test therefore asserts *that* — via
`assertProcessTreeTerminated` — and tolerates `exec.ErrWaitDelay`, which by
definition reports a process that already exited.

### 5.2 Listener admission

`connector/README.md` claims the Connector never listens on a local port. The
live test proves it by polling the process tree for inbound sockets. The POSIX
probe uses `lsof -g <pgid>`; neither the tool nor the concept of a process group
exists on Windows, so the Windows probe:

- rebuilds the tree from the parent links in a `CreateToolhelp32Snapshot`, since
  the Connector owns a job object rather than a process group;
- reads listening sockets from `GetExtendedTcpTable`
  (`TCP_TABLE_OWNER_PID_LISTENER`) and `GetExtendedUdpTable`, for both IPv4 and
  IPv6.

It deliberately does not parse `netstat`: that output's state column is
localized, and the target host runs a Chinese Windows, so `LISTENING` would not
appear as that string.

## 6. Run mode, logging, packaging

- **Scheduled task at logon, running as the interactive user.** The Connector
  needs the user's `CODEX_HOME` credentials, and the owner-only ACL model is
  most natural when the owner is a real interactive account. No service account
  password is stored.
- Under a scheduled task there is no console, so stderr must also go to a
  rotating log file inside `state_dir`, created with the same protected DACL as
  every other state object. The pairing code is still never written to the log —
  only the path of `pairing-code.json`, exactly as upstream does on stderr.
- `packaging/windows/` provides `install.ps1`, `uninstall.ps1`, and
  `sub2api-codex-connector-ctl.ps1` (`start`/`stop`/`status`/`pair`/`logs`),
  mirroring the Linux `sub2api-codex-connector-ctl`.
- The metrics textfile `connector.prom` is unchanged; on Windows it is consumed
  by `windows_exporter --collector.textfile`.

## 7. Non-goals

- The upstream release pipeline (Sigstore, SLSA, Developer ID notarization) is
  not extended to Windows here. Windows artifacts are built by
  `packaging/windows/build-windows-package.ps1` and are explicitly not
  reproducible-release artifacts.
- No server-side change. Everything in §4 exists precisely because the server
  cannot be modified in this deployment.
