# Sub2API immutable Compose migration

This runbook replaces the mutable production Sub2API service with the exact
linux/amd64 `0.2.1` image recorded in `versions.lock.json`. The migration is
separate from the Control deployment wrapper: it does not deploy Control,
change PostgreSQL or Redis, edit Nginx, publish a release, or pull an image.
The locked image must already be independently verified and present locally.

The successful state remains owned by the original Docker Compose project and
service. The script atomically replaces the active Compose file at the same path
with an authenticated, complete immutable candidate. It does not use a direct
`docker run` replacement and therefore does not discard Compose ownership or
allow the next ordinary Compose operation to return to `latest`.

This source is a migration mechanism, not a production receipt. It is admitted
only after an operator executes it in the maintenance window, validates its
root-only receipts, and completes the separate Sub2API authentication and
public-edge acceptance gates. Static review alone is not production admission.

## Storage and source policy

The existing bind-mounted data directory may be retained. A named volume is not
required. For the observed production path `/root/sub2api-deploy/data`, the
verifier requires:

- `/`, `/root`, and `/root/sub2api-deploy` are real, root-owned directories and
  are not group- or other-writable;
- the final data source is a real directory, not a symlink, with exact owner
  `1000:1000` and mode `0755`;
- Docker reports that exact source at writable `/app/data`, with `rprivate`
  propagation, and no other mount;
- the container user is the admitted numeric data owner and group.

Recheck these facts immediately before the change. Do not change ownership or
permissions merely to make the gate pass.

## Compose candidate

Stage a complete Compose file separately from the active file. It must be a
canonical root-owned, single-link regular file with mode `0444`; every ancestor
must be root-owned and not group- or other-writable. Record its exact SHA-256.
The referenced Compose environment file must be canonical, root-owned, mode
`0400` or `0600`, and separately hash-bound.

Both the resolved and `--no-interpolate` Compose projections must contain the
same exact service policy:

- the literal digest from `versions.lock.json` and `pull_policy: never`;
- the original container name, project, service, and external network;
- user `1000:1000`, read-only root filesystem, `cap_drop: [ALL]`, only
  `no-new-privileges`, and restart policy `unless-stopped`;
- one literal bind source at `/app/data`, writable, `rprivate`, with
  `create_host_path: false`;
- only `127.0.0.1:8080` published;
- exactly the tmpfs mounts pinned by `sub2api.runtime_tmpfs` in
  `versions.lock.json` (today one bounded `nosuid,nodev,noexec` `/tmp`, which
  the gateway needs for its response spool on a read-only root filesystem) and
  no other tmpfs;
- no build, process override, added capability, device, host namespace,
  extra mount, config, or secret.

The official image launches PID 1 through `/app/docker-entrypoint.sh`, which
`exec`s `/app/sub2api` once it is not running as root. The runtime verifier
therefore admits that wrapper only under the exact hash pinned by
`sub2api.runtime_entrypoint_sha256`, hashes it inside the running container,
and still requires the host `/proc` PID 1 executable to be the locked binary.

The script rejects semantic interpolation of the image or bind path. It also
requires the running legacy service to be owned by exactly this one active
Compose file, then captures that file, the supplied environment, and the full
running container environment before mutation. Multi-file legacy projects must
first be converted to a separately reviewed complete active file.

## Apply

Run as root from a verified release source. The backup root must already be a
canonical root-owned `0700` directory on encrypted storage. All hashes below
are operator inputs, not values discovered by the migration script.

Apply and rollback both acquire the fixed no-replace lock
`$SUB2API_IMMUTABLE_BACKUP_ROOT/.sub2api-immutable-operation.lock` before they
inspect or mutate the managed runtime. The root-only lock records the shell PID,
operation, and intended receipt path and is released only when its device/inode
still match. Never delete a lock merely because its PID is no longer running.
A retained lock means a previous process did not prove successful recovery;
inspect its transaction evidence and obtain a separate incident review before
any manual lock removal.

```sh
stage=/opt/sub2api-control/REPLACE_WITH_VERIFIED_64_HEX_VCS_REF/source
sudo install -d -o root -g root -m 0700 /root/sub2api-immutable-backups

sudo env -u PYTHONHOME -u PYTHONPATH \
  PATH=/usr/sbin:/usr/bin:/sbin:/bin \
  VERSIONS_LOCK_FILE="$stage/versions.lock.json" \
  SUB2API_CONTAINER=sub2api \
  SUB2API_DATA_BIND_SOURCE=/root/sub2api-deploy/data \
  SUB2API_EXPECTED_DATA_BIND_UID=1000 \
  SUB2API_EXPECTED_DATA_BIND_GID=1000 \
  SUB2API_EXPECTED_DATA_BIND_MODE=0755 \
  SUB2API_EXPECTED_NETWORK=sub2api-deploy_sub2api-network \
  SUB2API_EXPECTED_NETWORK_ALIAS=sub2api \
  SUB2API_COMPOSE_PROJECT=sub2api-deploy \
  SUB2API_COMPOSE_SERVICE=sub2api \
  SUB2API_COMPOSE_FILE=/root/sub2api-deploy/compose.yaml \
  SUB2API_IMMUTABLE_COMPOSE_CANDIDATE=/root/sub2api-deploy/compose.immutable.candidate.yaml \
  SUB2API_IMMUTABLE_COMPOSE_SHA256=REPLACE_WITH_64_HEX \
  SUB2API_COMPOSE_ENV_FILE=/root/sub2api-deploy/.env \
  SUB2API_COMPOSE_ENV_SHA256=REPLACE_WITH_64_HEX \
  SUB2API_IMMUTABLE_BACKUP_ROOT=/root/sub2api-immutable-backups \
  /bin/sh "$stage/deploy/scripts/migrate-sub2api-immutable.sh" apply
```

Before the first stop, `apply` creates and verifies a live data archive, copies
the active/candidate/environment Compose inputs, and writes
`BACKUP-READY.json`. After stopping the exact original container ID it creates a
quiesced archive, commits the stopped container to an exact rollback image, and
writes a root-only Compose override pinned to that image ID. Only then may it
remove the old container, atomically replace the active Compose file, and
recreate the service through the original project and service.

The new service must become healthy within the configured bound and pass
`verify-sub2api-runtime.sh`. `RESULT.json` binds the old ID and snapshot image,
new ID and locked image, bind/network policy, live and quiesced backups,
previous and installed Compose bytes, environment bytes, rollback override, and
runtime attestation. Keep the transaction directory and rollback image until
the acceptance window closes. The receipt records the exact operation-lock
inode that was held while `RESULT.json` was written; successful completion then
releases that inode.

## Bounded rollback

Rollback never restores data automatically because the immutable candidate may
have accepted writes. It proceeds only if all receipt hashes, the active
immutable Compose bytes, current environment bytes, candidate ID/image and
Compose project/service labels, and rollback image ID still match.

Use the same operator inputs and add the absolute receipt path:

```sh
transaction=/root/sub2api-immutable-backups/sub2api-immutable-REPLACE

sudo env -u PYTHONHOME -u PYTHONPATH \
  PATH=/usr/sbin:/usr/bin:/sbin:/bin \
  VERSIONS_LOCK_FILE="$stage/versions.lock.json" \
  SUB2API_CONTAINER=sub2api \
  SUB2API_DATA_BIND_SOURCE=/root/sub2api-deploy/data \
  SUB2API_EXPECTED_DATA_BIND_UID=1000 \
  SUB2API_EXPECTED_DATA_BIND_GID=1000 \
  SUB2API_EXPECTED_DATA_BIND_MODE=0755 \
  SUB2API_EXPECTED_NETWORK=sub2api-deploy_sub2api-network \
  SUB2API_EXPECTED_NETWORK_ALIAS=sub2api \
  SUB2API_COMPOSE_PROJECT=sub2api-deploy \
  SUB2API_COMPOSE_SERVICE=sub2api \
  SUB2API_COMPOSE_FILE=/root/sub2api-deploy/compose.yaml \
  SUB2API_IMMUTABLE_COMPOSE_CANDIDATE=/root/sub2api-deploy/compose.immutable.candidate.yaml \
  SUB2API_IMMUTABLE_COMPOSE_SHA256=REPLACE_WITH_64_HEX \
  SUB2API_COMPOSE_ENV_FILE=/root/sub2api-deploy/.env \
  SUB2API_COMPOSE_ENV_SHA256=REPLACE_WITH_64_HEX \
  SUB2API_IMMUTABLE_BACKUP_ROOT=/root/sub2api-immutable-backups \
  /bin/sh "$stage/deploy/scripts/migrate-sub2api-immutable.sh" \
  rollback "$transaction/RESULT.json"
```

The rollback stops and removes only the exact candidate ID, restores the exact
previous Compose bytes at the original path, and recreates the old runtime from
the receipt-bound snapshot image using the original project/service plus the
recorded `pull_policy: never` override. It writes no-replace `ROLLBACK.json` with
`data_restored=false`. If rollback fails after candidate removal, the failure
trap attempts to reinstall the authenticated immutable Compose candidate and
recreate its locked image. Identity drift stops destructive actions.

Concurrent apply/rollback attempts fail at the fixed operation lock. A failed
operation releases the lock only after the original container, snapshot
rollback, or immutable candidate is healthy again. If recovery is not proven,
the lock remains as a fail-closed incident marker.

A snapshot rollback is an emergency, non-admitted state: the restored legacy
Compose file may still name `latest`. Every Compose operation while rolled back
must include the receipt-bound override recorded in `ROLLBACK.json`, or the
operator must immediately reapply the immutable candidate. Do not run the
legacy Compose file alone.

On an apply failure, `AUTOMATIC-ROLLBACK.json` records whether the exact original
container restarted, the snapshot was recreated through Compose, the immutable
candidate was recovered, or recovery failed. Any recovery status other than a
complete state is an incident. If data restoration is required, keep all writers
stopped and follow a separately reviewed recovery plan based on the quiesced
archive; never extract an archive over live data.

Transaction files contain sensitive runtime configuration. Keep them root-only,
encrypted at rest, and copy them to the approved off-host recovery location.
