from __future__ import annotations

import unittest
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
CONTROL_COMMAND = (
    REPOSITORY_ROOT
    / "connector/packaging/common/sub2api-codex-connector-ctl"
)
SYSTEMD_SERVICE = (
    REPOSITORY_ROOT
    / "connector/packaging/linux/sub2api-codex-connector.service"
)
LAUNCH_AGENT = (
    REPOSITORY_ROOT
    / "connector/packaging/macos/org.sub2api.codex-connector.plist"
)


def function_body(source: str, name: str, end_marker: str) -> str:
    start = source.index(f"{name}() {{")
    end = source.index(end_marker, start)
    return source[start:end]


class PackagingSelfServiceContractTests(unittest.TestCase):
    def test_control_command_uses_one_fixed_private_configuration(self) -> None:
        command = CONTROL_COMMAND.read_text(encoding="utf-8")

        self.assertIn(
            "XDG_CONFIG_HOME overrides are unsupported", command
        )
        self.assertIn(
            'printf \'%s\\n\' "$canonical_home/.config/$product"', command
        )
        self.assertNotIn('$XDG_CONFIG_HOME/$product', command)
        self.assertIn("assert_managed_directory", command)
        self.assertIn("assert_private_file", command)
        self.assertIn("sub2api-codex-connector-managed-layout-v2", command)
        self.assertIn("config_sha256=%s", command)
        self.assertIn("sha256sum", command)
        self.assertIn("shasum -a 256", command)
        self.assertIn("command -v codex", command)
        self.assertNotIn('"codex_binary": "codex"', command)
        self.assertNotIn(".tmp.$$", command)
        self.assertNotIn("mv -f", command)

    def test_init_and_purge_admit_paths_before_side_effects(self) -> None:
        command = CONTROL_COMMAND.read_text(encoding="utf-8")
        initial = function_body(command, "write_initial_config", "\nlinux_service() {")
        purge = function_body(command, "purge_user_state", "\nrequire_regular_user\n")

        first_admission = initial.index('admit_initial_layout "$workspace"')
        creation = initial.index('mkdir -p -- "$cfg_root" "$state"')
        second_admission = initial.index(
            'admit_initial_layout "$workspace"', first_admission + 1
        )
        self.assertLess(first_admission, creation)
        self.assertLess(creation, second_admission)
        self.assertIn('ln "$temporary_layout" "$layout"', initial)
        self.assertIn('ln "$temporary_config" "$cfg"', initial)
        self.assertIn("cleanup_layout_identity=$temporary_layout_identity", initial)
        self.assertIn("cleanup_config_identity=$temporary_config_identity", initial)
        self.assertIn(
            'remove_tracked_path_if_unchanged "$cfg" "${cleanup_config_identity:-}"',
            initial,
        )
        self.assertIn(
            'remove_tracked_path_if_unchanged "$layout" "${cleanup_layout_identity:-}"',
            initial,
        )
        self.assertIn("trap 'cleanup_initial_write 130' INT", initial)
        self.assertIn("trap 'cleanup_initial_write 143' TERM", initial)
        self.assertIn("codex_home=%s", initial)

        first_purge_admission = purge.index("read_managed_layout")
        stop = purge.index("service_stop")
        second_purge_admission = purge.index(
            "read_managed_layout", first_purge_admission + 1
        )
        deletion = purge.index(
            'rm -rf -- "$admitted_state_root" "$admitted_config_root"'
        )
        self.assertLess(first_purge_admission, stop)
        self.assertLess(stop, second_purge_admission)
        self.assertLess(second_purge_admission, deletion)

        for pair in (
            '"configuration directory" "$admitted_config_root" "state directory"',
            '"configuration directory" "$admitted_config_root" "CODEX_HOME"',
            '"configuration directory" "$admitted_config_root" "workspace"',
            '"state directory" "$admitted_state_root" "CODEX_HOME"',
            '"state directory" "$admitted_state_root" "workspace"',
            '"CODEX_HOME" "$admitted_codex_home" "workspace"',
        ):
            self.assertIn(pair, command)

    def test_pair_start_and_service_revalidate_the_managed_layout(self) -> None:
        command = CONTROL_COMMAND.read_text(encoding="utf-8")
        existing = function_body(
            command, "admitted_existing_config", "\nread_managed_layout() {"
        )
        managed = function_body(
            command, "read_managed_layout", "\nwrite_initial_config() {"
        )
        start = function_body(command, "service_start", "\nservice_stop() {")

        self.assertIn("read_managed_layout", existing)
        self.assertIn('assert_managed_directory "state directory"', existing)
        self.assertIn('assert_private_file "legacy Connector configuration"', existing)
        self.assertIn('assert_private_file "Connector configuration"', managed)
        self.assertIn('actual_config_sha=$(sha256_file "$admitted_config_path")', managed)
        self.assertIn('actual_config_sha" = "$recorded_config_sha', managed)
        self.assertIn("configuration_mode=legacy", existing)
        self.assertIn("admitted_existing_config", start)
        self.assertIn("write_legacy_service_binding", start)
        self.assertIn("sub2api-codex-connector-legacy-service-path-v1", command)
        self.assertIn("read_legacy_service_binding", command)
        self.assertIn('PATH="$legacy_codex_dir:/usr/local/bin:/usr/bin:/bin"', command)
        self.assertIn("legacy_actual_config_sha=$(sha256_file", command)
        self.assertIn("legacy service binding is missing", command)
        self.assertGreaterEqual(command.count("CODEX_HOME=$admitted_codex_home"), 2)

    def test_legacy_purge_is_non_destructive(self) -> None:
        command = CONTROL_COMMAND.read_text(encoding="utf-8")
        purge = function_body(command, "purge_user_state", "\nrequire_regular_user\n")

        refusal = purge.index("purge refused because this legacy configuration")
        stop = purge.index("service_stop")
        deletion = purge.index('rm -rf -- "$admitted_state_root"')
        self.assertLess(refusal, stop)
        self.assertLess(stop, deletion)
        self.assertIn("no files were changed", purge)

    def test_packaged_services_clear_xdg_config_override(self) -> None:
        systemd = SYSTEMD_SERVICE.read_text(encoding="utf-8")
        launchd = LAUNCH_AGENT.read_text(encoding="utf-8")

        self.assertIn("Environment=XDG_CONFIG_HOME=", systemd)
        self.assertIn(
            "ConditionPathExists=%h/.config/sub2api-codex-connector/connector.json",
            systemd,
        )
        self.assertIn("<key>XDG_CONFIG_HOME</key>", launchd)
        self.assertIn("<string></string>", launchd)

    def test_public_guides_use_the_fixed_path_and_separate_admin_roles(self) -> None:
        guides = (
            REPOSITORY_ROOT / "README.md",
            REPOSITORY_ROOT / "README.zh-CN.md",
            REPOSITORY_ROOT / "docs/installation.md",
            REPOSITORY_ROOT / "docs/installation.zh-CN.md",
            REPOSITORY_ROOT / "docs/usage.md",
            REPOSITORY_ROOT / "docs/usage.zh-CN.md",
        )
        contents = [guide.read_text(encoding="utf-8") for guide in guides]

        for content in contents:
            self.assertNotIn("${XDG_CONFIG_HOME", content)
            self.assertIn(
                "$HOME/.config/sub2api-codex-connector/connector.json", content
            )
            self.assertIn("Sub2API", content)

        self.assertIn("local `sudo`", contents[0])
        self.assertIn("本机 `sudo`", contents[1])
        self.assertIn("Do not edit", contents[0])
        self.assertIn("不要直接编辑", contents[1])
        self.assertIn("without losing state", contents[2])
        self.assertIn("无损迁移", contents[3])


if __name__ == "__main__":
    unittest.main()
