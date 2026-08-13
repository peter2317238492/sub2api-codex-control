# Production Connector canary

This operator-only canary is deliberately excluded from CI and has no default
production target. It uses a disposable Connector state directory and workspace,
then revokes the paired device and deletes both on every exit path. Never run it
from an unfrozen checkout or with a shared Connector state directory.

## Freeze gate

Before any production execution:

1. Review and freeze `tests/e2e/production_connector_canary.py` and its tests.
2. Run the targeted pytest and Ruff gates from the exact frozen source.
3. Build a disposable unsigned Connector from that source and record its SHA-256.
4. Resolve the real Codex executable to the native `0.147.0` binary and record its
   SHA-256. The npm launcher is not an acceptable identity because it delegates to
   a second executable.
5. Create a new empty `0700` evidence directory. Evidence is no-replace; use a new
   directory for every run.
6. Keep the authentication JSON at `0600`, owned by the operator, with exactly
   `username`, `password`, and `OPENAI_API_KEY`. The provider value is schema-
   checked and discarded; it is never sent to Control.

Production execution remains blocked until an independent reviewer reports no
P0/P1 finding against the frozen source and hashes.

## Invocation

The credential is inherited on a file descriptor. Its value and path are absent
from the Python and Connector argument vectors and environment. Do not enable
shell tracing.

```sh
set +x
umask 077

auth=/private/path/sub2apiauth.json
run_parent=/private/path/canary-runs
evidence=/private/path/canary-evidence/run-001
connector=/private/path/sub2api-codex-connector
codex=/private/path/codex-native-0.147.0

mkdir -m 700 "$evidence"
connector_sha256=$(shasum -a 256 "$connector" | awk '{print $1}')
codex_sha256=$(shasum -a 256 "$codex" | awk '{print $1}')
exec 3<"$auth"

PYTHONPATH=tests/e2e python3 -I tests/e2e/production_connector_canary.py \
  --base-url https://control.example.com \
  --auth-fd 3 \
  --connector-binary "$connector" \
  --expected-connector-sha256 "$connector_sha256" \
  --codex-binary "$codex" \
  --expected-codex-sha256 "$codex_sha256" \
  --codex-home "$HOME/.codex" \
  --private-run-dir "$run_parent/run-001" \
  --evidence-dir "$evidence" \
  --confirm-real-production-canary
status=$?
exec 3<&-
exit "$status"
```

Exit `0` means all required checks passed. Exit `1` is a failed check or cleanup.
Exit `2` means implementable checks ran but at least one real approval class could
not be deterministically triggered through the public text-only RPC, so the result
is `externally_blocked`, never PASS.

## Evidence boundary

`production-connector-canary.json` contains only fixed version/schema values,
binary hashes, boolean checks, the eight method names, approval status, cleanup
status, and timestamps. It contains no origin, user, token, cookie, CSRF value,
pairing code, device/thread/turn/approval ID, model ID, command output, local path,
or workspace contents. Connector and Codex stdout/stderr are discarded and the
script itself prints only fixed status text.

The canary verifies command approval (approve and timeout) and file-change denial
only when real Codex emits those requests. Permission approval cannot be directly
requested by the typed public API; if real Codex does not emit it, evidence records
that boundary and exit `2` prevents a full-pass claim.
