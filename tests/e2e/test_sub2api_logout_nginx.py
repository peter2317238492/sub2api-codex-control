import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
OVERLAY = REPO_ROOT / "deploy/nginx/sub2api-logout-location.conf"
FIXED_CONFIG = REPO_ROOT / "tests/e2e/nginx-sub2api-logout.conf"
PROXY_LOCATION = REPO_ROOT / "tests/e2e/nginx-sub2api-proxy-location.conf"
SERVER_LOCATIONS = REPO_ROOT / "deploy/nginx/server-locations.conf"
SMOKE_DOCKERFILE = REPO_ROOT / "deploy/dockerfiles/smoke-edge.Dockerfile"
SMOKE_DOCKERIGNORE = REPO_ROOT / "deploy/dockerfiles/smoke-edge.Dockerfile.dockerignore"

BUFFER_DIRECTIVES = (
    "proxy_buffer_size 16k;",
    "proxy_buffers 4 16k;",
    "proxy_busy_buffers_size 32k;",
)


class Sub2APILogoutNginxTests(unittest.TestCase):
    def test_snippet_contains_exactly_three_server_buffer_directives(self) -> None:
        directives = tuple(OVERLAY.read_text(encoding="utf-8").splitlines())
        self.assertEqual(directives, BUFFER_DIRECTIVES)

    def test_server_locations_includes_overlay_exactly_once(self) -> None:
        locations = SERVER_LOCATIONS.read_text(encoding="utf-8")
        include = "include /etc/nginx/codex/sub2api-logout-location.conf;"
        self.assertEqual(locations.count(include), 1)

    def test_smoke_edge_packages_overlay(self) -> None:
        dockerfile = SMOKE_DOCKERFILE.read_text(encoding="utf-8")
        dockerignore = SMOKE_DOCKERIGNORE.read_text(encoding="utf-8")
        self.assertIn(
            "COPY --chmod=0444 deploy/nginx/sub2api-logout-location.conf "
            "/etc/nginx/codex/sub2api-logout-location.conf",
            dockerfile,
        )
        self.assertIn(
            "!deploy/nginx/sub2api-logout-location.conf", dockerignore.splitlines()
        )

    def test_fixed_and_baseline_share_one_exact_proxy_location_include(self) -> None:
        config = FIXED_CONFIG.read_text(encoding="utf-8")
        shared = "include /etc/nginx/sub2api-proxy-location.conf;"
        snippet = "include /etc/nginx/codex/sub2api-logout-location.conf;"
        self.assertEqual(config.count(shared), 2)
        self.assertEqual(config.count(snippet), 1)
        self.assertFalse(
            any(line.lstrip().startswith("location ") for line in config.splitlines())
        )

        proxy_location = PROXY_LOCATION.read_text(encoding="utf-8")
        self.assertEqual(proxy_location.count("location / {"), 1)
        self.assertNotIn("sub2api-logout-location.conf", proxy_location)
        self.assertIn("proxy_buffering off;", proxy_location)


if __name__ == "__main__":
    unittest.main()
