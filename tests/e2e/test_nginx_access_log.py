import os
import re
import stat
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
NGINX_ROOT = REPO_ROOT / "deploy" / "nginx"
SAFE_ACCESS_LOG = (
    "access_log /var/log/sub2api-codex-control/nginx-access.log codex_control_json;"
)


class NginxAccessLogPolicyTests(unittest.TestCase):
    @staticmethod
    def postrotate_script(rotation: str, *, test_path: str | None = None) -> str:
        match = re.search(
            r"^    postrotate\n(?P<body>.*?)^    endscript$",
            rotation,
            re.DOTALL | re.MULTILINE,
        )
        if match is None:
            raise AssertionError("logrotate postrotate block is missing")
        script = textwrap.dedent(match.group("body"))
        if test_path is not None:
            script = script.replace(
                "PATH=/usr/sbin:/usr/bin:/sbin:/bin", f"PATH={test_path}", 1
            )
        return script

    def test_every_codex_location_overrides_inherited_access_log(self) -> None:
        locations = (NGINX_ROOT / "server-locations.conf").read_text(encoding="utf-8")
        declared = re.findall(
            r"^location\s+([^\{]+)\{\n\s+([^\n]+)", locations, re.MULTILINE
        )
        selectors = {selector.strip() for selector, _ in declared}

        self.assertTrue(
            {
                "= /codex",
                "^~ /codex/",
                "= /codex-api",
                "^~ /codex-api/internal/",
                "^~ /codex-api/",
                "= /codex-ws",
                "= /codex-ws/browser",
                "= /codex-ws/device",
                "^~ /codex-ws/",
                "^~ /codex",
            }.issubset(selectors)
        )
        self.assertEqual(len(selectors), len(declared), "duplicate location selector")
        self.assertTrue(all("/codex" in selector for selector in selectors))
        self.assertTrue(
            all(
                first_directive.strip() == SAFE_ACCESS_LOG
                for _, first_directive in declared
            )
        )

    def test_catchall_prevents_any_codex_prefix_from_inheriting_host_log(
        self,
    ) -> None:
        locations = (NGINX_ROOT / "server-locations.conf").read_text(encoding="utf-8")
        match = re.search(
            r"^location \^~ /codex \{\n(?P<body>.*?)^\}",
            locations,
            re.DOTALL | re.MULTILINE,
        )
        self.assertIsNotNone(match)
        body = match.group("body")
        self.assertIn(SAFE_ACCESS_LOG, body)
        self.assertIn("return 404;", body)

        exact_ws = re.search(
            r"^location = /codex-ws \{\n(?P<body>.*?)^\}",
            locations,
            re.DOTALL | re.MULTILINE,
        )
        self.assertIsNotNone(exact_ws)
        self.assertIn(SAFE_ACCESS_LOG, exact_ws.group("body"))

    def test_smoke_edge_context_packages_every_referenced_include(self) -> None:
        dockerignore = (
            REPO_ROOT / "deploy/dockerfiles/smoke-edge.Dockerfile.dockerignore"
        ).read_text(encoding="utf-8")
        allowed = {line for line in dockerignore.splitlines() if line.startswith("!")}
        locations = (NGINX_ROOT / "server-locations.conf").read_text(encoding="utf-8")
        includes = set(re.findall(r"include /etc/nginx/codex/([^;]+);", locations))
        for include in includes:
            self.assertIn(f"!deploy/nginx/{include}", allowed)

    def test_structured_format_omits_secret_bearing_request_fields(self) -> None:
        http_context = (NGINX_ROOT / "http-context.conf").read_text(encoding="utf-8")
        match = re.search(
            r"log_format\s+codex_control_json\s+escape=json\n(?P<body>.*?);",
            http_context,
            re.DOTALL,
        )
        self.assertIsNotNone(match)
        body = match.group("body")
        self.assertIn('"uri":"$uri"', body)
        variables = set(re.findall(r"\$[A-Za-z0-9_]+", body))
        self.assertTrue(
            {
                "$uri",
                "$request_method",
                "$remote_addr",
                "$upstream_http_x_request_id",
            }.issubset(variables)
        )
        self.assertTrue(
            variables.isdisjoint(
                {
                    "$request",
                    "$request_uri",
                    "$args",
                    "$query_string",
                    "$http_referer",
                    "$http_user_agent",
                }
            )
        )

    def test_host_log_provisioning_and_rotation_contract(self) -> None:
        launcher = (
            REPO_ROOT / "deploy/scripts/provision-nginx-access-log.sh"
        ).read_text(encoding="utf-8")
        provisioner = (
            REPO_ROOT / "deploy/scripts/provision-nginx-access-log.py"
        ).read_text(encoding="utf-8")
        rotation = (NGINX_ROOT / "codex-control-access.logrotate").read_text(
            encoding="utf-8"
        )

        self.assertIn("unset PYTHONHOME PYTHONPATH", launcher)
        self.assertIn(
            'exec /usr/bin/python3 -I "$script_dir/provision-nginx-access-log.py"',
            launcher,
        )
        self.assertEqual(
            stat.S_IMODE(
                (REPO_ROOT / "deploy/scripts/provision-nginx-access-log.sh")
                .stat()
                .st_mode
            ),
            0o755,
        )
        self.assertIn("OPEN_NOFOLLOW", provisioner)
        self.assertIn('pathlib.Path("/var/log/sub2api-codex-control")', provisioner)
        self.assertIn("exact_mode=0o755", provisioner)
        self.assertIn("live_log_identity", provisioner)
        self.assertIn("pass_fds=(descriptor,)", provisioner)
        self.assertIn("os.replace(", provisioner)
        self.assertIn("stat.S_IWGRP | stat.S_IWOTH", provisioner)
        self.assertIn("os.fchmod(descriptor, 0o640)", provisioner)
        self.assertIn("os.fchmod(snapshot_fd, 0o644)", provisioner)
        self.assertIn("create 0640 www-data adm", rotation)
        self.assertTrue(
            rotation.startswith("/var/log/sub2api-codex-control/nginx-access.log {\n")
        )
        self.assertNotIn("*", rotation.splitlines()[0])
        self.assertNotIn("/var/log/nginx/codex-control-access.log", rotation)
        self.assertIn("daily", rotation)
        self.assertIn("rotate 14", rotation)
        self.assertIn("maxsize 10M", rotation)
        self.assertIn("compress", rotation)
        self.assertIn("sharedscripts", rotation)
        self.assertIn("PATH=/usr/sbin:/usr/bin:/sbin:/bin", rotation)
        self.assertIn("LC_ALL=C", rotation)
        self.assertIn("systemctl show --property MainPID --value", rotation)
        self.assertIn("systemctl kill --help", rotation)
        self.assertIn("*--kill-whom=*) kill_selector=--kill-whom=main", rotation)
        self.assertIn("*--kill-who=*) kill_selector=--kill-who=main", rotation)
        self.assertIn('systemctl kill -s USR1 "$kill_selector" nginx.service', rotation)
        self.assertIn('[ -r "/proc/$nginx_pid/cmdline" ] || exit 1', rotation)
        self.assertIn('[ -L "/proc/$nginx_pid/exe" ] || exit 1', rotation)
        self.assertIn('"${nginx_exe##*/}" = nginx', rotation)
        self.assertIn("nginx: master process", rotation)
        self.assertIn('kill -USR1 "$nginx_pid"', rotation)

    def test_retired_access_log_path_is_absent_from_runtime_policy(self) -> None:
        retired = "/var/log/nginx/codex-control-access.log"
        checked = (
            NGINX_ROOT / "server-locations.conf",
            NGINX_ROOT / "codex-control-access.logrotate",
            REPO_ROOT / "deploy/scripts/provision-nginx-access-log.py",
            REPO_ROOT / "deploy/dockerfiles/smoke-edge.Dockerfile",
            REPO_ROOT / "docs/runbooks/deployment.md",
            REPO_ROOT / "docs/runbooks/observability.md",
        )
        for path in checked:
            self.assertNotIn(retired, path.read_text(encoding="utf-8"), path)

    def test_postrotate_rejects_stale_or_inactive_systemd_identity(self) -> None:
        rotation = (NGINX_ROOT / "codex-control-access.logrotate").read_text(
            encoding="utf-8"
        )
        with tempfile.TemporaryDirectory(prefix="nginx-postrotate.") as temporary:
            root = Path(temporary)
            postrotate = self.postrotate_script(
                rotation, test_path=f"{root}:/bin:/usr/bin"
            )
            calls = root / "calls"
            systemctl = root / "systemctl"
            systemctl.write_text(
                textwrap.dedent(
                    """\
                    #!/bin/sh
                    printf '%s\\n' "$*" >> "$FAKE_SYSTEMCTL_CALLS"
                    case "$1" in
                        show) printf '%s\\n' "$FAKE_MAIN_PID" ;;
                        is-active) [ "$FAKE_ACTIVE" = 1 ] ;;
                        kill)
                            [ "${2:-}" = --help ] && printf '%s\\n' "$FAKE_KILL_HELP" \
                                || printf 'signaled\\n' >> "$FAKE_SYSTEMCTL_CALLS"
                            ;;
                        *) exit 64 ;;
                    esac
                    """
                ),
                encoding="utf-8",
            )
            systemctl.chmod(0o755)
            base_environment = {
                "FAKE_SYSTEMCTL_CALLS": str(calls),
                "PATH": f"{root}:/bin:/usr/bin",
            }
            for main_pid, active in (("0", "1"), ("1234", "0"), ("stale", "1")):
                calls.unlink(missing_ok=True)
                result = subprocess.run(
                    ("sh", "-eu", "-c", postrotate),
                    check=False,
                    env={
                        **os.environ,
                        **base_environment,
                        "FAKE_ACTIVE": active,
                        "FAKE_KILL_HELP": "--kill-whom=WHOM --kill-who=WHO",
                        "FAKE_MAIN_PID": main_pid,
                    },
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                self.assertNotEqual(result.returncode, 0, (main_pid, active))
                self.assertNotIn("signaled", calls.read_text(encoding="utf-8"))

    def test_postrotate_detects_supported_systemd_kill_selector(self) -> None:
        rotation = (NGINX_ROOT / "codex-control-access.logrotate").read_text(
            encoding="utf-8"
        )
        with tempfile.TemporaryDirectory(prefix="nginx-postrotate.") as temporary:
            root = Path(temporary)
            postrotate = self.postrotate_script(
                rotation, test_path=f"{root}:/bin:/usr/bin"
            )
            calls = root / "calls"
            systemctl = root / "systemctl"
            systemctl.write_text(
                "#!/bin/sh\n"
                'printf \'%s\\n\' "$*" >> "$FAKE_SYSTEMCTL_CALLS"\n'
                'case "$1" in\n'
                "  show) printf '4321\\n' ;;\n"
                "  is-active) exit 0 ;;\n"
                "  kill)\n"
                '    if [ "${2:-}" = --help ]; then printf \'%s\\n\' "$FAKE_KILL_HELP"; '
                "    else printf 'signaled\\n' >> \"$FAKE_SYSTEMCTL_CALLS\"; fi ;;\n"
                "  *) exit 64 ;;\n"
                "esac\n",
                encoding="utf-8",
            )
            systemctl.chmod(0o755)
            for help_text, expected in (
                ("--kill-whom=WHOM --kill-who=WHO", "--kill-whom=main"),
                ("--kill-who=WHO", "--kill-who=main"),
            ):
                calls.unlink(missing_ok=True)
                result = subprocess.run(
                    ("sh", "-eu", "-c", postrotate),
                    check=False,
                    env={
                        **os.environ,
                        "FAKE_KILL_HELP": help_text,
                        "FAKE_SYSTEMCTL_CALLS": str(calls),
                        "PATH": f"{root}:/bin:/usr/bin",
                    },
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                transcript = calls.read_text(encoding="utf-8")
                self.assertIn(
                    "show --property MainPID --value nginx.service", transcript
                )
                self.assertIn("is-active --quiet nginx.service", transcript)
                self.assertIn(f"kill -s USR1 {expected} nginx.service", transcript)
                self.assertEqual(transcript.count("signaled"), 1)

            calls.unlink(missing_ok=True)
            result = subprocess.run(
                ("sh", "-eu", "-c", postrotate),
                check=False,
                env={
                    **os.environ,
                    "FAKE_KILL_HELP": "systemctl kill unsupported-selector",
                    "FAKE_SYSTEMCTL_CALLS": str(calls),
                    "PATH": f"{root}:/bin:/usr/bin",
                },
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn("signaled", calls.read_text(encoding="utf-8"))

    def test_postrotate_does_not_execute_from_inherited_path(self) -> None:
        rotation = (NGINX_ROOT / "codex-control-access.logrotate").read_text(
            encoding="utf-8"
        )
        postrotate = self.postrotate_script(rotation)
        with tempfile.TemporaryDirectory(prefix="nginx-hostile-path.") as temporary:
            root = Path(temporary)
            marker = root / "executed"
            hostile = root / "systemctl"
            hostile.write_text(
                f"#!/bin/sh\n: > {marker!s}\nexit 0\n",
                encoding="utf-8",
            )
            hostile.chmod(0o755)
            subprocess.run(
                ("/bin/sh", "-eu", "-c", postrotate),
                check=False,
                env={**os.environ, "PATH": str(root)},
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertFalse(marker.exists())


if __name__ == "__main__":
    unittest.main()
