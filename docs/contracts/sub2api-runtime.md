# Sub2API runtime contract

Control authentication depends on the Sub2API runtime and its authentication
contract. Production admission therefore binds one immutable Sub2API image and
runtime tuple from `versions.lock.json`; it never infers compatibility from a
mutable tag or version string alone.

## Locked identity

The public lock records:

- the upstream release tag and release metadata;
- the exact `linux/amd64` image manifest digest, image/config ID, and immutable
  digest reference;
- the runtime version, commit, build timestamp, executable size, and SHA-256;
- the exact image label tuple;
- the authentication contract file and SHA-256;
- the browser token-storage key names and auth endpoint paths.

These are upstream release inputs, not a statement about any particular live
server. Before admitting a future Control release, independently verify the
upstream source and artifacts and update the lock through review. Never add
host paths, account identifiers, container IDs, writable-layer exceptions, or
deployment snapshots to the public lock.

## Immutable container profile

`deploy/scripts/verify-sub2api-runtime.py` admits only
`immutable-image-v1`. The named Sub2API container must:

- use exactly the digest reference and image ID in the lock;
- be running and healthy with a read-only root filesystem;
- have an empty Docker writable-layer diff;
- have exactly one writable Docker named volume mounted at `/app/data` and no
  other mount;
- expose only the expected loopback application binding and carry the
  `sub2api` alias on the exact external network selected for Control;
- preserve the locked entrypoint, command, OCI labels, binary identity, and
  runtime tuple across the complete verification window;
- remain the same named container and full container ID before and after the
  check.

Bind mounts, anonymous or identity-less volumes, mutable image tags, a writable
root, masked executable paths, any Docker diff, or container replacement fail
closed. The verifier also rejects the presence of retired compatibility keys
such as `production_admission_profile` and `production_compatibility`; there is
no legacy mutable-container exception.

## Authentication evidence

Runtime identity does not prove the auth API. Production admission additionally
requires fresh, nonce-bound evidence from the admitted Control API image in the
verified Sub2API network namespace. The evidence must cover:

- successful `/auth/me` for an active user;
- disabled-user and revoked-token rejection;
- refresh rotation and rejection of the old refresh credential;
- logout followed by refresh rejection;
- exact response shapes from the locked auth contract.

Use disposable, mode-`0600` token files from a private directory. Raw tokens,
token hashes, cookies, and refresh credentials must not enter the evidence,
environment, command arguments, image metadata, logs, or Git. External cached
evidence and alternate probe origins are not admission evidence.

## Change policy

Any change to the Sub2API image digest, runtime binary, auth shape, token keys,
network policy, or mount contract requires a new reviewed lock, contract tests,
and fresh authenticated evidence. A passing healthcheck alone cannot authorize
the change.
