# Third-Party Notices

Sub2API Codex Control is licensed under Apache-2.0. That license applies only
to material owned by this project's contributors. Third-party material retains
its original copyright and license terms.

This source distribution includes generated Codex app-server schemas and
embedded contract copies derived from OpenAI Codex 0.147.0, which is licensed
under Apache-2.0. It also includes a compatibility contract recording public
Sub2API 0.1.175 interfaces; Sub2API is licensed under LGPL-3.0-or-later. No
upstream source code from Sub2API is vendored here.

The project depends on packages obtained separately by the package managers.
The selected direct or security-relevant dependencies below are recorded so
the source snapshot can be audited without guessing their versions. Each
package's own distribution remains authoritative for its complete notices.

| Component | Version | Relationship | License |
| --- | --- | --- | --- |
| OpenAI Codex | 0.147.0 | Generated protocol material | Apache-2.0 |
| Sub2API | 0.1.175 | Compatibility contract | LGPL-3.0-or-later |
| Alembic | 1.18.5 | Python runtime dependency | MIT |
| Vue | 3.5.39 | PWA runtime dependency | MIT |
| Pinia | 3.0.4 | PWA runtime dependency | MIT |
| Lucide | 1.24.0 | PWA icon dependency | ISC and MIT |
| Go standard library | 1.24.0 | Connector build/runtime dependency | BSD-3-Clause |
| coder/websocket | 1.8.14 | Connector dependency | ISC |
| santhosh-tekuri/jsonschema | 6.0.2 | Connector dependency | Apache-2.0 |
| dlclark/regexp2 | 1.11.0 | Test-only transitive Connector dependency | MIT |
| golang.org/x/text | 0.14.0 | Transitive Connector dependency | BSD-3-Clause |

Exact upstream URLs, relationships, license files, and SHA-256 digests are in
[`third_party/components.json`](third_party/components.json). Verbatim license
and notice texts are stored below `third_party/`.

## Trademark and affiliation

OpenAI, Codex, Sub2API, and other names are trademarks of their respective
owners. This is an independent community project. It is not affiliated with,
endorsed by, or sponsored by OpenAI or the Sub2API project.

## Source-only release status

This initial public snapshot is source-only. It does not publish or support a
prebuilt Connector binary. The `connector-v*` and `control-v*` tag release
workflows are disabled and must remain disabled until complete artifact SBOM
license data, provenance, signing, and platform trust gates are implemented and
independently audited. No prebuilt asset may be published before then. The
repository's release documentation is design material, not evidence that a
public binary release exists.
