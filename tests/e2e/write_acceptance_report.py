from __future__ import annotations

import argparse
import json
import os
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Write the durable local acceptance report"
    )
    parser.add_argument("--output", required=True)
    parser.add_argument("--status", required=True, choices=("passed", "failed"))
    parser.add_argument("--stage", required=True)
    parser.add_argument("--started-at", required=True)
    parser.add_argument("--finished-at", required=True)
    parser.add_argument("--project", required=True)
    parser.add_argument("--checks-file", required=True)
    parser.add_argument("--docker-version", required=True)
    parser.add_argument("--go-version", required=True)
    parser.add_argument("--connector-sha256", required=True)
    parser.add_argument("--source-revision", required=True)
    parser.add_argument("--source-manifest-sha256", required=True)
    parser.add_argument("--versions-lock-sha256", required=True)
    parser.add_argument("--control-protocol-sha256", required=True)
    parser.add_argument("--sub2api-auth-contract-sha256", required=True)
    parser.add_argument("--control-api-image-id", required=True)
    parser.add_argument("--pwa-image-id", required=True)
    args = parser.parse_args()

    checks_path = Path(args.checks_file)
    checks = [
        {"name": line.strip(), "status": "passed"}
        for line in checks_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    report = {
        "schema_version": 1,
        "suite": "sub2api-codex-control-local-acceptance",
        "status": args.status,
        "completed_or_failed_stage": args.stage,
        "started_at": args.started_at,
        "finished_at": args.finished_at,
        "compose_project": args.project,
        "source": {
            "revision": args.source_revision,
            "manifest_sha256": args.source_manifest_sha256,
            "manifest_scope": "build, deployment, protocol, and E2E inputs; generated outputs and caches excluded",
            "versions_lock_sha256": args.versions_lock_sha256,
            "control_protocol_sha256": args.control_protocol_sha256,
            "sub2api_auth_contract_sha256": args.sub2api_auth_contract_sha256,
        },
        "subjects": {
            "control_api": {
                "kind": "local image built from the source manifest",
                "image_id": args.control_api_image_id,
            },
            "pwa": {
                "kind": "local image built from the source manifest",
                "image_id": args.pwa_image_id,
            },
            "connector": {
                "kind": "real binary built from the current worktree",
                "sha256": args.connector_sha256,
            },
            "codex_app_server": {
                "kind": "deterministic fake stdio fixture, not a real Codex runtime",
                "claimed_contract_version": "0.147.0",
                "schema_sha256": "511c1b3ca038a80740a5a41ca10a7f925c0f744e582fb9aaa03cc46c6e98b80b",
            },
            "sub2api": {
                "kind": "deterministic authentication contract fixture",
                "claimed_contract_marker": "0.2.1/578785e",
            },
        },
        "topology": {
            "http_and_browser_instance": "control-api",
            "device_websocket_instance": "control-api-replica",
            "coordination": "shared dedicated Redis ACL namespace",
            "durability": "shared dedicated PostgreSQL role and database",
            "edge": "TLS Nginx with deterministic upstream routing",
        },
        "runtime": {
            "docker": args.docker_version,
            "go": args.go_version,
        },
        "limitations": [
            "Codex app-server behavior uses a deterministic fake stdio fixture, not a real Codex runtime.",
            "Sub2API authentication uses a deterministic mock contract, not the admitted production image.",
            "Connector coexistence checks cover an isolated workspace and fake Codex executable; real Codex App and CLI coexistence still requires a live canary.",
            "Local Docker image IDs are exact local build subjects, not signed registry release digests.",
        ],
        "checks": checks,
    }

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_name(f".{output.name}.tmp.{os.getpid()}")
    with temporary.open("w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2, sort_keys=True)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    temporary.replace(output)
    output.chmod(0o600)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
