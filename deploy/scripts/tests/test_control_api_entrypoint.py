from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
ENTRYPOINT = REPO_ROOT / "deploy/scripts/control-api-entrypoint.sh"


class ControlAPIEntrypointTests(unittest.TestCase):
    def invoke(
        self,
        auth_mode: str,
        *,
        redis_user: str = "default",
        session_secret: str = "5a" * 32,
    ) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            database = root / "database"
            redis = root / "redis"
            session = root / "session"
            database.write_text("db-secret\n", encoding="utf-8")
            redis.write_text("redis secret\n", encoding="utf-8")
            session.write_text(session_secret + "\n", encoding="utf-8")
            for path in (database, redis, session):
                path.chmod(0o600)
            binary_dir = root / "bin"
            binary_dir.mkdir()
            (binary_dir / "python").symlink_to(sys.executable)
            environment = {
                **os.environ,
                "PATH": f"{binary_dir}{os.pathsep}{os.environ['PATH']}",
                "CONTROL_DATABASE_PASSWORD_FILE": str(database),
                "CONTROL_REDIS_PASSWORD_FILE": str(redis),
                "CONTROL_SESSION_HMAC_SECRET_FILE": str(session),
                "CONTROL_REDIS_AUTH_MODE": auth_mode,
                "CONTROL_REDIS_USER": redis_user,
                "CONTROL_REDIS_HOST": "redis.internal",
                "CONTROL_REDIS_PORT": "6380",
                "CONTROL_REDIS_DATABASE": "4",
            }
            return subprocess.run(
                [str(ENTRYPOINT), "env"],
                env=environment,
                text=True,
                capture_output=True,
                check=False,
            )

    def test_password_mode_keeps_credentialed_url(self) -> None:
        result = self.invoke("password", redis_user="codex_control")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(
            "CONTROL_REDIS_URL=redis://codex_control:redis%20secret@redis.internal:6380/4",
            result.stdout,
        )

    def test_none_mode_omits_authentication(self) -> None:
        result = self.invoke("none")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("CONTROL_REDIS_URL=redis://redis.internal:6380/4", result.stdout)
        self.assertNotIn("redis%20secret", result.stdout)

    def test_none_mode_rejects_non_default_user(self) -> None:
        result = self.invoke("none", redis_user="codex_control")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unauthenticated Redis requires the default user", result.stderr)

    def test_unknown_mode_fails_closed(self) -> None:
        result = self.invoke("optional")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unsupported CONTROL_REDIS_AUTH_MODE", result.stderr)

    def test_short_session_secret_fails_closed(self) -> None:
        result = self.invoke("none", session_secret="too-short")

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("session secret must contain at least 32 bytes", result.stderr)

    def test_known_session_secret_placeholders_fail_closed(self) -> None:
        insecure_values = (
            "development-only-change-this-session-secret",
            "replace-with-at-least-32-random-bytes",
            "  REPLACE-WITH-AT-LEAST-32-RANDOM-BYTES  ",
            "a-test-secret-that-is-long-and-never-production",
            "device-send-barrier-secret-with-at-least-32-bytes",
            "production-secret-that-is-longer-than-32-bytes",
        )
        for index, session_secret in enumerate(insecure_values):
            with self.subTest(case=index):
                result = self.invoke("none", session_secret=session_secret)

                self.assertNotEqual(result.returncode, 0)
                self.assertIn(
                    "session secret uses a known development, test, or example value",
                    result.stderr,
                )


if __name__ == "__main__":
    unittest.main()
