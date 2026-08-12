# Operations

[简体中文](operations.zh-CN.md) | [Documentation index](../README.md#documentation)

This document describes the intended operating boundary. Production rollout
from the first public source version is blocked until a signed release evidence
set exists.

## Public and private ports

Nginx is the only public listener for Control traffic. A minimal UFW policy is:

```sh
ADMIN_CIDR='203.0.113.0/24'
SSH_PORT='22'
sudo ufw default deny incoming
sudo ufw allow from "$ADMIN_CIDR" to any port "$SSH_PORT" proto tcp \
  comment 'restricted administrative SSH'
sudo ufw allow 443/tcp comment 'HTTPS'
# Enable this only for an HTTP redirect or ACME challenge:
sudo ufw allow 80/tcp comment 'HTTP redirect or ACME'
sudo ufw enable
sudo ufw status numbered
```

Replace the documentation address range and SSH port before applying the
policy. Preserve any other explicitly required host rules. Do not add rules for
`18090`, `18091`, `18092`, or `18093`; those listeners must remain bound to
`127.0.0.1`. Do not expose PostgreSQL or Redis. A Connector needs outbound TCP
`443` and opens no inbound port.

Verify both the bind address and firewall state after every network change:

```sh
sudo ss -lntp
sudo ufw status verbose
```

## Health and acceptance

Loopback checks distinguish process liveness from dependency readiness:

```sh
curl --fail --silent --show-error \
  http://127.0.0.1:18090/v1/health/live
curl --fail --silent --show-error \
  http://127.0.0.1:18090/v1/health/ready
curl --fail --silent --show-error \
  http://127.0.0.1:18091/codex/
```

A ready response is necessary but insufficient. Production acceptance also
requires an authenticated same-origin session exchange, browser WSS, device
WSS, a real Connector using the pinned Codex version, an admitted RPC, approval
default-denial, reconnect, revocation, and logout checks. Retain evidence by
release revision outside the checkout without storing tokens or cookies.

Metrics are served from `/internal/metrics` on the loopback API and require a
dedicated bearer token. Never route that endpoint publicly. Connector metrics
are written to the private `state_dir/connector.prom` textfile; require a recent
update timestamp rather than trusting the last `up` sample alone.

## Logs and secrets

Use the dedicated Nginx JSON access log, whose format omits query strings,
Referer, and User-Agent. Keep it outside broad host logrotate wildcards and
verify rotation plus Nginx reopen behavior. Application logs must not contain
access tokens, refresh credentials, cookies, provider keys, pairing codes, or
secret-file contents.

Keep Compose environment files, generated secret files, deployment records,
release evidence, and recovery material outside the source tree with the
narrowest practical ownership and mode. Never place raw credentials in command
arguments, image metadata, URLs, Git, or issue reports.

## Recovery snapshot

Before a state-changing production window, create one complete, verified,
encrypted recovery snapshot outside the checkout. It should cover the Control
database, required Redis persistence and ACL/configuration, Control secrets,
the admitted deployment record, Nginx configuration, and any host integration
needed for recovery. Verify checksums and a protected off-host copy.

Do not create redundant snapshots during the same unchanged window. Create a
new one only when the protected state has changed, the prior attempt was
incomplete, or policy requires a newer recovery point. Rehearse restore in an
isolated environment; a backup file that has not been parsed and restored is
not verified recovery evidence.

## Upgrade

An upgrade remains blocked unless the new revision has a complete signed image
and Connector evidence set. For an admitted revision:

1. review schema, database migration, Sub2API, and Codex compatibility;
2. freeze the change window and take one verified recovery snapshot;
3. verify source identity, signatures, provenance, SBOMs, image digests, and
   platform signatures before any migration;
4. run the migration and services through the release's single admitted
   deployment entry point;
5. verify loopback listeners, Nginx configuration, UFW, authenticated HTTP/WSS,
   Connector policy, reconnect, revocation, and logout;
6. retain the prior admitted release and rollback instructions until the new
   evidence is accepted.

Never replace an image digest, binary, lock file, or migration revision in
place while calling it the same release.

## Uninstall

An uninstall should remove only the Control components:

1. revoke paired devices and stop user-owned Connectors;
2. stop and remove the Control API, PWA, and Control-only migration/backup
   containers;
3. remove the Control Nginx include, test the complete Nginx configuration,
   and reload it;
4. retain the Control PostgreSQL database, Redis namespace, secrets, deployment
   records, and recovery evidence by default;
5. remove retained data only under a separate, explicit destruction decision;
6. do not remove or modify the external Sub2API containers, database, Redis
   service, Docker network, TLS assets, or unrelated host routes;
7. do not remove UFW `80` or `443` rules automatically because other services
   on the same host may still require them.

See the detailed [operations runbooks](runbooks/README.md) for the release and
recovery contracts.
