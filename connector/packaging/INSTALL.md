# Connector native package operations

The native packages install only the Connector executable, the user control
command, a service definition, a safe configuration example, documentation, and
package lifecycle helpers. They do not install or update Codex and never write
to `CODEX_HOME`, Codex authentication, workspaces, shell profiles, or firewall
configuration. The Connector has no inbound listener.

After signature verification and native package installation, each ordinary
user initializes and pairs their own Connector:

```sh
sub2api-codex-connector-ctl init \
  --origin https://sub2api.wyswd.top \
  --workspace /absolute/path/to/workspace \
  --display-name "My device"
sub2api-codex-connector-ctl pair
sub2api-codex-connector-ctl start
sub2api-codex-connector-ctl status
```

The configuration is created with mode `0600`; state and pairing credentials
remain in the user's private state directory. Package upgrades preserve both.
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

That command rejects root execution and refuses paths overlapping
`CODEX_HOME`. Verify ordinary Codex App/CLI operation and unchanged Codex
config/auth hashes after install, upgrade, rollback, and uninstall.
