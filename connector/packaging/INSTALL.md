# Connector native package operations

The native packages install only the Connector executable, the user control
command, a service definition, a safe configuration example, documentation, and
package lifecycle helpers. They do not install or update Codex and never write
to `CODEX_HOME`, Codex authentication, workspaces, shell profiles, or firewall
configuration. The Connector has no inbound listener.

After signature verification and native package installation, each ordinary
user initializes and pairs their own Connector without Sub2API administrator
assistance. Installing the native package may still require local `sudo` or
macOS administrator approval:

```sh
sub2api-codex-connector-ctl init \
  --origin https://sub2api.wyswd.top \
  --workspace /absolute/path/to/workspace \
  --display-name "My device"
sub2api-codex-connector-ctl pair
sub2api-codex-connector-ctl start
sub2api-codex-connector-ctl status
```

The configuration is created with mode `0600` at the fixed path
`$HOME/.config/sub2api-codex-connector/connector.json`; a non-empty
`XDG_CONFIG_HOME` override is rejected. State and pairing credentials remain in
the user's private state directory. Package upgrades preserve both. New
initialization resolves `codex` to an absolute executable path and records the
configuration SHA-256 in a private v2 managed layout. Do not edit the managed
configuration. The formal command currently initializes one workspace only;
changing it requires PWA revocation followed by `stop`,
`purge-user-state --yes`, and a fresh `init`/`pair`/`start`. Multi-root and
sandbox-cap changes do not yet have a supported management command.

An older private mode-`0600` configuration at the fixed path can still be
paired and started without a layout; the Connector validates its own structure
and uses the current valid `CODEX_HOME`. Destructive purge is intentionally
refused for that legacy case. Run `connector-ctl start` interactively once so it
can privately bind the unchanged configuration digest to the current absolute
Codex path; a missing or changed binding makes background startup fail closed.
Back up `connector.json` and the `state_dir` it references before migration or
re-initialization.

If an older installation used `XDG_CONFIG_HOME`, do not move or delete it in
place. Stop the service, make a private backup of both its configuration and the
referenced state directory, verify that the fixed destination does not already
exist, then copy the configuration to
`$HOME/.config/sub2api-codex-connector/connector.json`. Set the destination
directory to mode `0700` and the file to `0600`, unset `XDG_CONFIG_HOME`, and
run `pair` and `start`. Keep the original and backup until the device is online
and its state is confirmed. If the fixed destination already exists, leave both
copies untouched and resolve the conflict manually; never overwrite it.
The package hook retains the immediately previous package-owned Connector
binary as a local emergency rollback candidate. An administrator can run the
package lifecycle helper's `rollback` command, then must reinstall the matching
previous verified native package so package-manager metadata again matches the
binary.

For a normal rollback, verify and install the immediately previous `.deb`,
`.rpm`, or `.pkg` through the same native package flow. Stop only this Connector
first; do not stop or edit Codex. On uninstall, the package manager removes only
package-owned files. User configuration, pairing credentials, and state remain
unless that user explicitly runs. Linux users use their distribution package
manager. On macOS, run the package-owned uninstaller before removing the package:

```sh
sudo /usr/local/libexec/sub2api-codex-connector/uninstall-macos
```

Each user can then explicitly remove only their own retained Connector data:

```sh
sub2api-codex-connector-ctl purge-user-state --yes
```

For a v2 managed configuration, that command rejects root execution and
revalidates the configuration SHA-256, canonical ownership, permissions,
symlinks, and every overlap among the recorded configuration, state, workspace,
and `CODEX_HOME` paths before deleting the two Connector-owned directories. It
refuses legacy configurations without a verified layout. Verify ordinary Codex
App/CLI operation and unchanged Codex config/auth hashes after install, upgrade,
rollback, and uninstall.
