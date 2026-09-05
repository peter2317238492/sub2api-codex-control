from __future__ import annotations

import json
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[3]
MIGRATION = REPO_ROOT / "deploy/scripts/migrate-sub2api-immutable.sh"
SCHEMA = REPO_ROOT / "deploy/schemas/sub2api-immutable-migration-receipt.schema.json"


class ImmutableSub2APIMigrationStaticTests(unittest.TestCase):
    def setUp(self) -> None:
        self.script = MIGRATION.read_text(encoding="utf-8")

    def test_apply_is_backup_first_and_snapshots_before_compose_replacement(self) -> None:
        apply_flow = self.script[self.script.index("preflight_values=") :]
        live_backup = apply_flow.index(
            'create_data_archive "$live_archive" "$live_listing" "$live_checksum"'
        )
        backup_ready = apply_flow.index("write_backup_ready", live_backup)
        mutation = apply_flow.index("mutation_started=1", backup_ready)
        stop = apply_flow.index('docker container stop "$old_id"', mutation)
        quiesced = apply_flow.index(
            'create_data_archive "$quiesced_archive"', stop
        )
        snapshot = apply_flow.index(
            'rollback_image_id=$(docker container commit "$old_id")',
            quiesced,
        )
        override = apply_flow.index("write_rollback_override", snapshot)
        remove = apply_flow.index('docker container rm "$old_id"', override)
        replace = apply_flow.index(
            'atomic_install_file "$candidate_compose_backup" "$compose_file"',
            remove,
        )
        candidate = apply_flow.index(
            'compose_up_service "$compose_file" ""', replace
        )
        self.assertLess(live_backup, backup_ready)
        self.assertLess(backup_ready, mutation)
        self.assertLess(mutation, stop)
        self.assertLess(stop, quiesced)
        self.assertLess(quiesced, snapshot)
        self.assertLess(snapshot, override)
        self.assertLess(override, remove)
        self.assertLess(remove, replace)
        self.assertLess(replace, candidate)

    def test_rollback_snapshot_captures_only_the_image_id(self) -> None:
        # Docker CLI 29 prints a deprecation notice on stdout for the pause
        # flags, so the commit must run bare against the already-stopped
        # container and its output must be validated as a full image ID.
        self.assertIn('rollback_image_id=$(docker container commit "$old_id")', self.script)
        self.assertNotIn("commit --pause", self.script)
        self.assertNotIn("commit --no-pause", self.script)
        self.assertIn(
            'case "$rollback_image_id" in (sha256:*) ;; (*) fail "rollback snapshot returned an invalid image ID" ;; esac',
            self.script,
        )
        self.assertIn('[ "${#rollback_image_id}" -eq 71 ]', self.script)

    def test_health_polling_preserves_the_trap_exit_status(self) -> None:
        # Every abort handler captures `status=$?` and later calls wait_healthy;
        # the poller must not reuse that name or the handler exits with a
        # non-numeric value such as "healthy".
        start = self.script.index("wait_healthy() {")
        end = self.script.index("\n}\n", start)
        body = self.script[start:end]
        self.assertNotIn("status=$(", body)
        self.assertIn("observed_health=$(docker container inspect", body)

    def test_candidate_admits_only_the_locked_tmpfs_policy(self) -> None:
        # The lock's sub2api.runtime_tmpfs is the only admitted tmpfs shape:
        # the release lock preflight projects it, the pre-mutation recheck
        # re-binds it, and both Compose projections must list exactly it.
        for required in (
            'tmpfs = sub2api.get("runtime_tmpfs")',
            'print(json.dumps(tmpfs, sort_keys=True, separators=(",", ":")))',
            "locked_tmpfs=$(sed -n '3p' \"$preflight_values\")",
            "&& [ \"$(sed -n '3p' \"$pre_mutation_recheck\")\" = \"$locked_tmpfs\" ]",
            '"$expected_network" "$locked_tmpfs" > "$hash_output"',
            'expected_tmpfs_list = [f"{path}:{options}" for path, options in sorted(expected_tmpfs.items())]',
            "if tmpfs != expected_tmpfs_list:",
            'raise SystemExit(f"{label} Sub2API service has prohibited tmpfs")',
        ):
            self.assertIn(required, self.script)
        self.assertNotIn('"network_mode", "tmpfs", "volumes_from"', self.script)

    def test_candidate_image_label_binds_the_locked_image_across_compose_generations(self) -> None:
        # Compose 5 labels the container with the sha256:-prefixed image ID
        # where Compose 2 wrote the bare hex; both must resolve to the locked
        # image rather than merely looking like a digest.
        for required in (
            'compose_image_hex = compose_image[len("sha256:"):] if compose_image.startswith("sha256:") else compose_image',
            'if re.fullmatch(r"[0-9a-f]{64}", compose_image_hex) is None:',
            'if "sha256:" + compose_image_hex != image.get("Id"):',
            'raise SystemExit("candidate Compose image label does not name the locked image")',
        ):
            self.assertIn(required, self.script)

    def test_candidate_compose_is_hash_bound_and_hardened(self) -> None:
        for required in (
            "SUB2API_COMPOSE_FILE",
            "SUB2API_IMMUTABLE_COMPOSE_CANDIDATE",
            "SUB2API_IMMUTABLE_COMPOSE_SHA256",
            "SUB2API_COMPOSE_ENV_FILE",
            "SUB2API_COMPOSE_ENV_SHA256",
            'safe_file(\n    compose_candidate,',
            'safe_file(\n    compose_environment,',
            'config --no-interpolate --format json',
            '"image": image',
            '"read_only": True',
            '"user": f"{uid}:{gid}"',
            '"cap_drop") != ["ALL"]',
            '["no-new-privileges"]',
            '"pull_policy": "never"',
            '"host_ip": "127.0.0.1"',
            'bind.get("propagation") != "rprivate"',
            'bind.get("create_host_path") is not False',
            "--pull never",
        ):
            self.assertIn(required, self.script)
        self.assertNotIn("docker pull", self.script)
        self.assertNotIn("docker run", self.script)
        self.assertNotIn("rm -rf", self.script)

    def test_original_compose_project_and_active_path_are_persistently_replaced(self) -> None:
        for required in (
            '--project-name "$compose_project"',
            '--project-directory "$(dirname -- "$compose_file")"',
            '--env-file "$selected_environment"',
            'atomic_install_file "$candidate_compose_backup" "$compose_file" 0444',
            '"com.docker.compose.project.config_files": sys.argv[8]',
            'labels.get("com.docker.compose.project") != sys.argv[7]',
            'labels.get("com.docker.compose.service") != sys.argv[8]',
        ):
            self.assertIn(required, self.script)

    def test_bind_policy_is_explicit_and_matches_the_production_shape(self) -> None:
        for variable in (
            "SUB2API_DATA_BIND_SOURCE",
            "SUB2API_EXPECTED_DATA_BIND_UID:-1000",
            "SUB2API_EXPECTED_DATA_BIND_GID:-1000",
            "SUB2API_EXPECTED_DATA_BIND_MODE:-0755",
        ):
            self.assertIn(variable, self.script)
        self.assertIn('mount.get("Destination") != "/app/data"', self.script)
        self.assertIn('mount.get("Source") != sys.argv[3]', self.script)

    def test_apply_and_rollback_hold_one_inode_bound_operation_lock(self) -> None:
        for required in (
            'operation_lock_path=$backup_root/.sub2api-immutable-operation.lock',
            "os.O_EXCL",
            'operation_lock_identity=$(acquire_operation_lock apply',
            'operation_lock_identity=$(acquire_operation_lock rollback',
            '(info.st_dev, info.st_ino)',
            'release_operation_lock',
            '"held_while_receipt_written": True',
        ):
            self.assertIn(required, self.script)
        apply_flow = self.script[self.script.index("preflight_values=") :]
        self.assertLess(
            apply_flow.index("acquire_operation_lock apply"),
            apply_flow.index("mutation_started=1"),
        )
        self.assertIn(
            'if [ "$recovery_complete" = "1" ]; then',
            self.script,
        )

    def test_rollback_restores_previous_compose_with_exact_snapshot_override(self) -> None:
        for required in (
            'rollback.get("candidate_id_must_match") != new["id"]',
            'rollback.get("rollback_image_id_must_match") != old["rollback_image_id"]',
            'docker container rm "$new_id"',
            'atomic_install_file "$active_compose_backup" "$compose_file"',
            'compose_up_service "$compose_file" "$rollback_override"',
            'restored.get("Image") != sys.argv[3]',
            'config_files != {sys.argv[7], sys.argv[8]}',
            '"status": "compose_snapshot_rollback_complete"',
            '"data_restored": False',
            '"automatic_data_restore": False',
        ):
            self.assertIn(required, self.script)
        self.assertNotIn("tar --extract", self.script)

    def test_receipt_schema_is_closed_and_binds_backup_and_runtime_evidence(self) -> None:
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        self.assertFalse(schema["additionalProperties"])
        self.assertEqual(schema["properties"]["status"]["const"], "immutable_candidate_running")
        self.assertFalse(schema["properties"]["backup"]["additionalProperties"])
        self.assertFalse(schema["properties"]["compose"]["additionalProperties"])
        self.assertFalse(
            schema["properties"]["operation_lock"]["additionalProperties"]
        )
        self.assertFalse(schema["properties"]["runtime_attestation"]["additionalProperties"])
        self.assertEqual(
            schema["properties"]["old_container"]["properties"]["state"]["const"],
            "snapshotted_and_removed",
        )
        self.assertIn(
            "rollback_override_sha256",
            schema["properties"]["compose"]["required"],
        )
        self.assertFalse(
            schema["properties"]["rollback"]["properties"]["automatic_data_restore"]["const"]
        )


if __name__ == "__main__":
    unittest.main()
