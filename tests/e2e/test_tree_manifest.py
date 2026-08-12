from __future__ import annotations

import os
import pathlib
import subprocess
import sys

SCRIPT = pathlib.Path(__file__).with_name("tree_manifest.py")


def manifest(root: pathlib.Path) -> str:
    return subprocess.check_output(
        [sys.executable, str(SCRIPT), str(root)],
        text=True,
    ).strip()


def test_tree_manifest_is_stable_and_detects_protected_state_changes(
    tmp_path: pathlib.Path,
) -> None:
    root = tmp_path / "codex-home"
    plugin = root / "plugins" / "example"
    plugin.mkdir(parents=True)
    config = root / "config.toml"
    config.write_text("model = 'pinned'\n", encoding="utf-8")
    os.chmod(config, 0o600)
    (root / "active-plugin").symlink_to("plugins/example")

    baseline = manifest(root)
    assert manifest(root) == baseline

    config.write_text("model = 'changed'\n", encoding="utf-8")
    assert manifest(root) != baseline
    config.write_text("model = 'pinned'\n", encoding="utf-8")
    assert manifest(root) == baseline

    os.chmod(config, 0o640)
    assert manifest(root) != baseline
    os.chmod(config, 0o600)
    assert manifest(root) == baseline

    added = plugin / "manifest.json"
    added.write_text("{}\n", encoding="utf-8")
    assert manifest(root) != baseline
    added.unlink()
    assert manifest(root) == baseline

    (root / "active-plugin").unlink()
    (root / "active-plugin").symlink_to("plugins/other")
    assert manifest(root) != baseline
