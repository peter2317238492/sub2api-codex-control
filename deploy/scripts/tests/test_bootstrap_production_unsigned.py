import subprocess
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
BOOTSTRAP = REPO_ROOT / "deploy/scripts/bootstrap-production-unsigned.sh"
NORMAL_DEPLOY = REPO_ROOT / "deploy/scripts/deploy-production.sh"


class UnsignedBootstrapScriptTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.script = BOOTSTRAP.read_text(encoding="utf-8")

    def test_backup_is_admitted_before_any_provisioning_write(self) -> None:
        backup = self.script.index("stage=verify-production-backup-admission")
        secret_probe = self.script.index("stage=verify-tools-and-runtime-secret-access")
        image_contract = self.script.index("stage=verify-api-image-embedded-contract")
        write = self.script.index("stage=provision-control-postgres")
        self.assertLess(backup, write)
        self.assertLess(secret_probe, write)
        self.assertLess(image_contract, write)

    def test_immutable_auth_contract_is_admitted_before_claim_or_record_write(
        self,
    ) -> None:
        admission = self.script.index(
            'require_immutable_contract_file "$auth_contract"'
        )
        lock = self.script.index('mkdir "$lock_dir"')
        record = self.script.index('mkdir "$deployment_dir"')
        self.assertLess(admission, lock)
        self.assertLess(admission, record)

        helper_start = self.script.index("require_immutable_contract_file()")
        helper_end = self.script.index("\n}\n", helper_start)
        helper = self.script[helper_start:helper_end]
        for required in (
            "path.is_absolute()",
            "stat.S_ISLNK",
            "stat.S_ISREG",
            "value.st_uid != os.geteuid()",
            "stat.S_IMODE(value.st_mode) != 0o444",
            "value.st_nlink != 1",
            "value.st_size <= 0",
        ):
            self.assertIn(required, helper)

    def test_api_image_contract_probe_uses_the_admitted_isolated_image(self) -> None:
        stage = self.script.index("stage=verify-api-image-embedded-contract")
        admission = self.script.index(
            'python3 "$bootstrap_checks" api-image-contract', stage
        )
        probe = self.script[stage:admission]
        for argument in (
            "--pull never",
            "--network none",
            "--read-only",
            "--cap-drop ALL",
            "--security-opt no-new-privileges",
            "--user 10001:10001",
            "--entrypoint python",
            '"$api_image"',
        ):
            self.assertIn(argument, probe)
        self.assertIn("Settings.model_fields[name].default", probe)
        self.assertIn('--images "$deployment_dir/images.json"', self.script[admission:])
        self.assertIn('--versions-lock "$versions_lock"', self.script[admission:])
        self.assertIn("api-image-embedded-contract.json", self.script[admission:])
        self.assertIn(
            '"api_image_embedded_contract": "api-image-embedded-contract.json"',
            self.script[admission:],
        )

    def test_public_connect_exception_is_explicit_and_evidenced(self) -> None:
        self.assertIn("CONTROL_BOOTSTRAP_ALLOW_SUB2API_PUBLIC_CONNECT", self.script)
        self.assertIn("postgres-boundary-admission.json", self.script)
        self.assertIn("direct_schema_acl_privileges", self.script)
        self.assertIn("effective_relation_privileges", self.script)

    def test_unauthenticated_smoke_exception_records_pending_state(self) -> None:
        self.assertIn("CONTROL_BOOTSTRAP_ALLOW_UNAUTHENTICATED_SMOKE", self.script)
        self.assertIn("bootstrap-unauthenticated-smoke.py", self.script)
        self.assertIn('"authenticated_smoke_pending"', self.script)

    def test_normal_signed_deploy_has_no_bootstrap_bypass(self) -> None:
        normal = NORMAL_DEPLOY.read_text(encoding="utf-8")
        self.assertNotIn("CONTROL_BOOTSTRAP_ALLOW_SUB2API_PUBLIC_CONNECT", normal)
        self.assertNotIn("CONTROL_BOOTSTRAP_ALLOW_UNAUTHENTICATED_SMOKE", normal)
        self.assertNotIn("UNSIGNED_FIRST_DEPLOYMENT_ONLY", normal)

    def test_redis_bootstrap_is_read_only(self) -> None:
        self.assertIn("ACL GETUSER default", self.script)
        self.assertNotIn("ACL SETUSER", self.script)
        self.assertNotIn("ACL SAVE", self.script)

    def test_redis_checks_clear_inherited_authentication(self) -> None:
        self.assertIn("redis_noauth()", self.script)
        self.assertIn("unset REDISCLI_AUTH", self.script)
        self.assertEqual(self.script.count("redis_noauth ACL GETUSER default"), 2)
        self.assertNotIn("$(redis_noauth ACL GETUSER default)", self.script)
        self.assertIn(
            'grep -Fxq "$required_rule" "$deployment_dir/redis-default-acl-before.txt"',
            self.script,
        )
        self.assertIn('cmp "$deployment_dir/redis-default-acl-before.txt"', self.script)
        self.assertIn('"$(redis_noauth PING)"', self.script)

    def test_redis_acl_capture_preserves_and_compares_trailing_empty_line(
        self,
    ) -> None:
        payload = (
            b"flags\non\nnopass\nsanitize-payload\npasswords\n\ncommands\n"
            b"+@all\nkeys\n~*\nchannels\n&*\nselectors\n\n"
        )
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            before = root / "before.txt"
            after = root / "after.txt"
            script = f"""
set -eu
redis_noauth() {{ printf '%s' '{payload.decode()}'; }}
redis_noauth ACL GETUSER default > '{before}'
redis_noauth ACL GETUSER default > '{after}'
cmp '{before}' '{after}'
printf '\\n' >> '{after}'
if cmp '{before}' '{after}' >/dev/null 2>&1; then
  exit 1
fi
"""
            subprocess.run(["sh", "-c", script], check=True)
            self.assertEqual(before.read_bytes(), payload)
            self.assertEqual(after.read_bytes(), payload + b"\n")

    def test_runtime_secrets_are_exact_and_probed_without_loading_values(self) -> None:
        self.assertIn('"$bootstrap_checks" runtime-secrets', self.script)
        self.assertIn("--expected-backup-user 70:70", self.script)
        self.assertIn("/run/secrets/control_db_password", self.script)
        self.assertIn("/run/secrets/control_redis_password", self.script)
        self.assertIn("/run/secrets/control_session_hmac_secret", self.script)
        self.assertIn('api_database_secret "70:$control_api_gid:440"', self.script)
        self.assertIn('backup_database_secret "70:$control_api_gid:440"', self.script)
        self.assertIn('probe_secret_denied "$backup_image"', self.script)
        self.assertIn('stat -c "%u:%g:%a"', self.script)
        self.assertIn('wc -c < "$secret" >/dev/null', self.script)
        self.assertNotIn("value=$(tr -d", self.script)

    def test_first_deployment_preflight_is_before_postgres_write(self) -> None:
        preflight = self.script.index("stage=verify-first-deployment-runtime-boundary")
        write = self.script.index("stage=provision-control-postgres")
        self.assertLess(preflight, write)
        self.assertIn("label=com.docker.compose.project=$project", self.script)
        self.assertIn(
            "first deployment requires the dedicated PWA network to be absent",
            self.script,
        )
        self.assertIn('"dedicated PWA network"', self.script)
        self.assertNotIn('"internal PWA network"', self.script)
        self.assertIn("available_loopback_ports", self.script)
        self.assertIn("is missing the required {alias} network alias", self.script)

    def test_postgres_tools_major_must_match_live_server_before_write(self) -> None:
        version_check = self.script.index("server_version_num=$(postgres_psql")
        write = self.script.index("stage=provision-control-postgres")
        self.assertLess(version_check, write)
        self.assertIn("major does not match live PostgreSQL", self.script)

    def test_redis_namespace_is_empty_and_has_bounded_rollback(self) -> None:
        baseline = self.script.index("redis_key_count=$(redis_namespace_count)")
        write = self.script.index("stage=provision-control-postgres")
        self.assertLess(baseline, write)
        self.assertIn("if #keys > 10000 then", self.script)
        self.assertIn('redis.call("UNLINK", key)', self.script)
        self.assertIn("redis_namespace_mutation_attempted", self.script)
        self.assertIn("redis_acl_or_configuration_mutation_attempted", self.script)

    def test_success_revalidates_all_production_identities(self) -> None:
        self.assertIn(
            "stage=revalidate-production-boundary-after-bootstrap", self.script
        )
        self.assertIn("current-production-identities-after-bootstrap.json", self.script)
        self.assertIn("backup-admission-after-bootstrap.json", self.script)
        self.assertIn(
            "Redis default ACL changed during unsigned bootstrap", self.script
        )

    def test_stale_backup_exception_is_unsigned_only_claimed_and_bound_three_times(
        self,
    ) -> None:
        self.assertIn("CONTROL_STALE_PRODUCTION_BACKUP_EXCEPTION_FILE", self.script)
        self.assertIn("CONTROL_BOOTSTRAP_DEPLOYMENT_ID", self.script)
        self.assertIn("stale-production-backup-exception-claim", self.script)
        self.assertIn("os.O_EXCL", self.script)
        self.assertIn('"$(id -u)" = "0"', self.script)
        self.assertIn("must have exactly one hard link", self.script)
        self.assertEqual(self.script.count("admit_production_backup"), 4)
        self.assertIn('"$deployment_dir/sub2api-before.json"', self.script)
        self.assertIn('"$deployment_dir/sub2api-before-migration.json"', self.script)
        self.assertIn('"$deployment_dir/sub2api-after.json"', self.script)
        self.assertIn('"production_backup_before_migration"', self.script)
        self.assertIn('"admission_binding_sha256"', self.script)
        self.assertIn('"production_backup_admissions"', self.script)
        claim_assignment = 'stale_backup_exception_claim="$stale_backup_claim_root/'
        claim = self.script.index(claim_assignment)
        write = self.script.index("writes_started=1")
        self.assertLess(claim, write)
        claim_flow = self.script[claim:write]
        self.assertIn(
            '"$stale_backup_exception_claim" "$exception_id" "$deployment_id"',
            claim_flow,
        )
        self.assertIn(
            'cp "$stale_backup_exception_claim" '
            '"$deployment_dir/stale-backup-exception-claim.json"',
            claim_flow,
        )
        rollback_record = self.script[
            self.script.index("write_rollback_record()") : claim
        ]
        self.assertIn(
            "ROLLBACK_STALE_BACKUP_EXCEPTION_CLAIM=$stale_backup_exception_claim",
            rollback_record,
        )
        self.assertIn(
            "optional_evidence(claim_file)",
            rollback_record,
        )
        self.assertNotIn("\n  stale_backup_claim=", self.script)
        normal = NORMAL_DEPLOY.read_text(encoding="utf-8")
        self.assertNotIn("CONTROL_STALE_PRODUCTION_BACKUP_EXCEPTION_FILE", normal)

    def test_fresh_backup_age_stays_bounded_when_exception_exists(self) -> None:
        self.assertIn("cannot exceed the fresh-backup limit of 1800", self.script)
        self.assertNotIn(
            "backup_max_age=${CONTROL_PRODUCTION_BACKUP_MAX_AGE_SECONDS:-691200}",
            self.script,
        )


if __name__ == "__main__":
    unittest.main()
