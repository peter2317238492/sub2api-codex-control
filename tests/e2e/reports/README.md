# Local acceptance reports

`tests/e2e/run-local.sh` writes one mode-0600 JSON report here on every run,
including failed runs. Generated reports are intentionally ignored because they
contain machine-specific timestamps, container project names, and runtime
versions.

The report distinguishes the real Connector binary from the deterministic fake
Codex stdio fixture and mock Sub2API contract. It is evidence for local
transport, policy, persistence, isolation, restore, and cross-instance routing;
it is not evidence that a real Codex release or the immutable production
Sub2API image passed a canary.
