from __future__ import annotations

import importlib.util
import os
import signal
import stat
import sys
import tempfile
import textwrap
import unittest
from collections.abc import Callable
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[3]
PROVISIONER_PATH = REPO_ROOT / "deploy/scripts/provision-nginx-access-log.py"
SPEC = importlib.util.spec_from_file_location(
    "provision_nginx_access_log", PROVISIONER_PATH
)
assert SPEC is not None and SPEC.loader is not None
PROVISIONER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = PROVISIONER
SPEC.loader.exec_module(PROVISIONER)

POLICY = b"""/var/log/sub2api-codex-control/nginx-access.log {
    daily
    rotate 14
}
"""
REPLACEMENT = b"""/var/log/sub2api-codex-control/nginx-access.log {
    hourly
    rotate 1
}
"""


class NginxAccessLogProvisionerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="nginx-log-provisioner.")
        self.root = Path(self.temporary.name)
        self.source = self.root / "codex-control-access.logrotate"
        self.source.write_bytes(POLICY)
        self.source.chmod(0o444)
        self.rotation_parent = self.root / "etc"
        self.rotation_parent.mkdir(mode=0o755)
        self.rotation_directory = self.rotation_parent / "logrotate.d"
        self.rotation_directory.mkdir(mode=0o755)
        self.log_root = self.root / "log-root"
        self.log_root.mkdir(mode=0o755)
        self.log_directory = self.log_root / "sub2api-codex-control"
        self.paths = PROVISIONER.ProvisionPaths(
            rotation_source=self.source,
            rotation_directory=self.rotation_directory,
            rotation_name="codex-control-access",
            log_directory=self.log_directory,
            log_name="nginx-access.log",
            rotation_trust_anchor=self.root,
        )
        self.validator_log = self.root / "validator.log"
        self.validator = self.write_validator()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write_validator(self) -> Path:
        path = self.root / "fake-logrotate"
        path.write_text(
            textwrap.dedent(
                """\
                #!/usr/bin/env python3
                import os
                import pathlib
                import sys

                assert sys.argv[1] == "--debug"
                policy = pathlib.Path(sys.argv[2]).read_bytes()
                pathlib.Path(os.environ["VALIDATOR_LOG"]).write_bytes(policy)
                action = os.environ.get("VALIDATOR_ACTION")
                if action == "swap-source":
                    source = pathlib.Path(os.environ["ROTATION_SOURCE"])
                    replacement = source.with_name(source.name + ".replacement")
                    replacement.write_bytes(os.environ["REPLACEMENT"].encode())
                    os.replace(replacement, source)
                elif action == "swap-target":
                    target = pathlib.Path(os.environ["ROTATION_TARGET"])
                    replacement = target.with_name(target.name + ".replacement")
                    replacement.write_text("attacker target\\n", encoding="ascii")
                    os.replace(replacement, target)
                elif action == "swap-log":
                    target = pathlib.Path(os.environ["LOG_TARGET"])
                    replacement = target.with_name(target.name + ".replacement")
                    replacement.write_text("attacker log\\n", encoding="ascii")
                    os.replace(replacement, target)
                elif action == "append-log":
                    target = pathlib.Path(os.environ["LOG_TARGET"])
                    with target.open("ab") as handle:
                        handle.write(b"concurrent nginx append\\n")
                raise SystemExit(23 if action == "reject" else 0)
                """
            ),
            encoding="utf-8",
        )
        path.chmod(0o755)
        return path

    def environment(self, action: str | None = None) -> dict[str, str]:
        value = os.environ.copy()
        value.update(
            {
                "VALIDATOR_LOG": str(self.validator_log),
                "ROTATION_SOURCE": str(self.source),
                "ROTATION_TARGET": str(self.paths.rotation_target),
                "LOG_TARGET": str(self.paths.log_path),
                "REPLACEMENT": REPLACEMENT.decode(),
            }
        )
        if action is not None:
            value["VALIDATOR_ACTION"] = action
        return value

    def run_provision(self, action: str | None = None) -> None:
        previous = os.environ.copy()
        desired = self.environment(action)
        try:
            os.environ.clear()
            os.environ.update(desired)
            PROVISIONER.provision(
                self.paths,
                expected_root_uid=os.getuid(),
                expected_root_gid=os.getgid(),
                log_uid=os.getuid(),
                log_gid=os.getgid(),
                logrotate_command=(str(self.validator),),
            )
        finally:
            os.environ.clear()
            os.environ.update(previous)

    def assert_no_snapshots(self) -> None:
        self.assertEqual(
            list(self.rotation_directory.glob("codex-control-access.*.disabled")), []
        )

    def patch_log_metadata_failure(
        self, operation: str
    ) -> tuple[mock._patch[object], dict[str, bool]]:
        original = getattr(PROVISIONER.os, operation)
        fired = {"value": False}

        def is_log_descriptor(descriptor: int) -> bool:
            try:
                opened = os.fstat(descriptor)
                named = os.lstat(self.paths.log_path)
            except (FileNotFoundError, OSError):
                return False
            return stat.S_ISREG(opened.st_mode) and (opened.st_dev, opened.st_ino) == (
                named.st_dev,
                named.st_ino,
            )

        def inject(*args: object, **kwargs: object) -> object:
            if operation == "stat":
                result = original(*args, **kwargs)
                if (
                    not fired["value"]
                    and args
                    and args[0] == self.paths.log_name
                    and kwargs.get("dir_fd") is not None
                    and stat.S_IMODE(result.st_mode) == 0o640
                ):
                    fired["value"] = True
                    raise OSError("injected post-metadata stat failure")
                return result
            descriptor = args[0]
            if not fired["value"] and is_log_descriptor(descriptor):
                if operation == "fchmod":
                    original(*args, **kwargs)
                fired["value"] = True
                raise OSError(f"injected {operation} failure")
            return original(*args, **kwargs)

        return mock.patch.object(PROVISIONER.os, operation, side_effect=inject), fired

    def test_real_fixture_provisions_atomically_and_is_idempotent(self) -> None:
        self.run_provision()
        first_inode = self.paths.log_path.stat().st_ino
        first_policy_inode = self.paths.rotation_target.stat().st_ino

        self.assertEqual(self.validator_log.read_bytes(), POLICY)
        self.assertEqual(self.paths.rotation_target.read_bytes(), POLICY)
        self.assertEqual(stat.S_IMODE(self.paths.rotation_target.stat().st_mode), 0o644)
        self.assertEqual(stat.S_IMODE(self.paths.log_path.stat().st_mode), 0o640)
        self.assertEqual(stat.S_IMODE(self.log_directory.stat().st_mode), 0o755)
        self.assertEqual(self.paths.rotation_target.stat().st_nlink, 1)
        self.assertEqual(self.paths.log_path.stat().st_nlink, 1)
        self.assert_no_snapshots()

        self.run_provision()

        self.assertEqual(self.paths.log_path.stat().st_ino, first_inode)
        self.assertNotEqual(
            self.paths.rotation_target.stat().st_ino, first_policy_inode
        )
        self.assertEqual(self.paths.rotation_target.read_bytes(), POLICY)
        self.assert_no_snapshots()

    def test_concurrent_append_does_not_change_live_log_identity(self) -> None:
        self.log_directory.mkdir(mode=0o755)
        self.paths.log_path.write_bytes(b"existing log\n")

        original = PROVISIONER.provision_log_file

        def append_before_open(*args: object, **kwargs: object) -> object:
            with self.paths.log_path.open("ab") as handle:
                handle.write(b"concurrent nginx append\n")
            return original(*args, **kwargs)

        with mock.patch.object(
            PROVISIONER,
            "provision_log_file",
            side_effect=append_before_open,
        ):
            self.run_provision()

        self.assertEqual(
            self.paths.log_path.read_bytes(),
            b"existing log\nconcurrent nginx append\n",
        )
        self.assertEqual(stat.S_IMODE(self.paths.log_path.stat().st_mode), 0o640)
        self.assertEqual(self.paths.log_path.stat().st_nlink, 1)
        self.assertEqual(self.paths.rotation_target.read_bytes(), POLICY)

    def test_concurrent_mode_change_blocks_publish_and_restores_existing_log(
        self,
    ) -> None:
        self.log_directory.mkdir(mode=0o700)
        self.log_directory.chmod(0o700)
        self.paths.log_path.write_bytes(b"existing log\n")
        self.paths.log_path.chmod(0o600)
        original = PROVISIONER.provision_log_file

        def mutate_after_provision(*args: object, **kwargs: object) -> object:
            result = original(*args, **kwargs)
            self.paths.log_path.chmod(0o666)
            return result

        with (
            mock.patch.object(
                PROVISIONER,
                "provision_log_file",
                side_effect=mutate_after_provision,
            ),
            self.assertRaisesRegex(
                PROVISIONER.ProvisionError,
                "access log changed during validation",
            ),
        ):
            self.run_provision()

        self.assertEqual(self.paths.log_path.read_bytes(), b"existing log\n")
        self.assertEqual(stat.S_IMODE(self.paths.log_path.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(self.log_directory.stat().st_mode), 0o700)
        self.assertFalse(self.paths.rotation_target.exists())
        self.assert_no_snapshots()

    def test_new_log_internal_metadata_failures_leave_no_artifacts(self) -> None:
        for operation in ("fchown", "fchmod", "stat"):
            with self.subTest(operation=operation):
                patcher, fired = self.patch_log_metadata_failure(operation)
                with (
                    patcher,
                    self.assertRaisesRegex(
                        PROVISIONER.ProvisionError,
                        "injected",
                    ),
                ):
                    self.run_provision()

                self.assertTrue(fired["value"])
                self.assertFalse(self.paths.log_path.exists())
                self.assertFalse(self.log_directory.exists())
                self.assertFalse(self.paths.rotation_target.exists())
                self.assert_no_snapshots()

    def test_existing_log_internal_metadata_failures_restore_metadata(self) -> None:
        for operation in ("fchown", "fchmod", "stat"):
            with self.subTest(operation=operation):
                self.log_directory.mkdir(mode=0o700, exist_ok=True)
                self.log_directory.chmod(0o700)
                self.paths.log_path.write_bytes(b"existing log\n")
                self.paths.log_path.chmod(0o600)
                before = self.paths.log_path.stat()
                patcher, fired = self.patch_log_metadata_failure(operation)

                with (
                    patcher,
                    self.assertRaisesRegex(
                        PROVISIONER.ProvisionError,
                        "injected",
                    ),
                ):
                    self.run_provision()

                after = self.paths.log_path.stat()
                self.assertTrue(fired["value"])
                self.assertEqual(self.paths.log_path.read_bytes(), b"existing log\n")
                self.assertEqual(
                    (
                        after.st_dev,
                        after.st_ino,
                        after.st_uid,
                        after.st_gid,
                        stat.S_IMODE(after.st_mode),
                    ),
                    (
                        before.st_dev,
                        before.st_ino,
                        before.st_uid,
                        before.st_gid,
                        0o600,
                    ),
                )
                self.assertEqual(stat.S_IMODE(self.log_directory.stat().st_mode), 0o700)
                self.assertFalse(self.paths.rotation_target.exists())
                self.assert_no_snapshots()
                self.paths.log_path.unlink()
                self.log_directory.rmdir()

    def test_post_mkdir_failure_removes_the_inode_created_by_this_run(self) -> None:
        original_fsync = PROVISIONER.os.fsync
        parent_inode = self.log_root.stat().st_ino

        def fail_after_mkdir(descriptor: int) -> None:
            metadata = os.fstat(descriptor)
            if (
                stat.S_ISDIR(metadata.st_mode)
                and metadata.st_ino == parent_inode
                and self.log_directory.exists()
            ):
                raise OSError("injected post-mkdir failure")
            original_fsync(descriptor)

        with (
            mock.patch.object(PROVISIONER.os, "fsync", side_effect=fail_after_mkdir),
            self.assertRaisesRegex(
                PROVISIONER.ProvisionError,
                "injected post-mkdir failure",
            ),
        ):
            self.run_provision()

        self.assertFalse(self.log_directory.exists())
        self.assertFalse(self.paths.rotation_target.exists())
        self.assert_no_snapshots()

    def test_post_chmod_failure_restores_existing_directory_mode(self) -> None:
        self.log_directory.mkdir(mode=0o700)
        self.log_directory.chmod(0o700)
        original_validate = PROVISIONER.SecureDirectory._validate

        def fail_after_chmod(
            directory: object,
            metadata: os.stat_result,
            **kwargs: object,
        ) -> None:
            original_validate(directory, metadata, **kwargs)
            if (
                getattr(directory, "path", None) == self.log_directory
                and stat.S_IMODE(metadata.st_mode) == 0o755
                and not kwargs
            ):
                raise PROVISIONER.ProvisionError("injected post-chmod failure")

        with (
            mock.patch.object(
                PROVISIONER.SecureDirectory,
                "_validate",
                autospec=True,
                side_effect=fail_after_chmod,
            ),
            self.assertRaisesRegex(
                PROVISIONER.ProvisionError,
                "injected post-chmod failure",
            ),
        ):
            self.run_provision()

        self.assertEqual(stat.S_IMODE(self.log_directory.stat().st_mode), 0o700)
        self.assertFalse(self.paths.rotation_target.exists())
        self.assert_no_snapshots()

    def test_source_swap_after_snapshot_validation_fails_closed(self) -> None:
        self.log_directory.mkdir(mode=0o755)
        self.paths.rotation_target.write_bytes(b"existing policy\n")
        self.paths.log_path.write_bytes(b"existing log\n")

        with self.assertRaisesRegex(
            PROVISIONER.ProvisionError, "source changed during validation"
        ):
            self.run_provision("swap-source")

        self.assertEqual(self.validator_log.read_bytes(), POLICY)
        self.assertEqual(self.source.read_bytes(), REPLACEMENT)
        self.assertEqual(self.paths.rotation_target.read_bytes(), b"existing policy\n")
        self.assertEqual(self.paths.log_path.read_bytes(), b"existing log\n")
        self.assert_no_snapshots()

    def test_target_swap_after_snapshot_validation_fails_closed(self) -> None:
        self.log_directory.mkdir(mode=0o755)
        self.paths.rotation_target.write_bytes(b"existing policy\n")
        self.paths.log_path.write_bytes(b"existing log\n")

        with self.assertRaisesRegex(
            PROVISIONER.ProvisionError, "policy target changed during validation"
        ):
            self.run_provision("swap-target")

        self.assertEqual(self.paths.rotation_target.read_bytes(), b"attacker target\n")
        self.assertEqual(self.paths.log_path.read_bytes(), b"existing log\n")
        self.assert_no_snapshots()

    def test_log_swap_after_snapshot_validation_fails_closed(self) -> None:
        self.log_directory.mkdir(mode=0o755)
        self.paths.rotation_target.write_bytes(b"existing policy\n")
        self.paths.log_path.write_bytes(b"existing log\n")

        original = PROVISIONER.provision_log_file

        def swap_before_open(*args: object, **kwargs: object) -> object:
            replacement = self.paths.log_path.with_suffix(".replacement")
            replacement.write_text("attacker log\n", encoding="ascii")
            os.replace(replacement, self.paths.log_path)
            return original(*args, **kwargs)

        with (
            mock.patch.object(
                PROVISIONER,
                "provision_log_file",
                side_effect=swap_before_open,
            ),
            self.assertRaisesRegex(
                PROVISIONER.ProvisionError,
                "access log changed before it was opened",
            ),
        ):
            self.run_provision()

        self.assertEqual(self.paths.rotation_target.read_bytes(), b"existing policy\n")
        self.assertEqual(self.paths.log_path.read_bytes(), b"attacker log\n")
        self.assert_no_snapshots()

    def test_unsafe_parent_directory_fails_before_validation_or_write(self) -> None:
        self.rotation_directory.chmod(0o775)

        with self.assertRaisesRegex(
            PROVISIONER.ProvisionError, "must not be group or world writable"
        ):
            self.run_provision()

        self.assertFalse(self.validator_log.exists())
        self.assertFalse(self.paths.rotation_target.exists())
        self.assertFalse(self.paths.log_path.exists())

    def test_unsafe_or_symlink_log_directory_is_rejected(self) -> None:
        self.log_directory.mkdir(mode=0o775)
        self.log_directory.chmod(0o775)

        with self.assertRaisesRegex(
            PROVISIONER.ProvisionError, "must not be group or world writable"
        ):
            self.run_provision()

        self.log_directory.rmdir()
        outside = self.root / "outside-log-directory"
        outside.mkdir(mode=0o755)
        self.log_directory.symlink_to(outside, target_is_directory=True)
        with self.assertRaisesRegex(
            PROVISIONER.ProvisionError, "non-symlink directory"
        ):
            self.run_provision()
        self.assertEqual(list(outside.iterdir()), [])

    def test_symlink_and_multiply_linked_targets_are_rejected(self) -> None:
        outside = self.root / "outside"
        outside.write_bytes(b"outside\n")
        self.paths.rotation_target.symlink_to(outside)

        with self.assertRaisesRegex(
            PROVISIONER.ProvisionError, "regular, singly linked file"
        ):
            self.run_provision()
        self.assertEqual(outside.read_bytes(), b"outside\n")

        self.paths.rotation_target.unlink()
        self.paths.rotation_target.write_bytes(b"existing\n")
        linked = self.root / "linked"
        os.link(self.paths.rotation_target, linked)
        with self.assertRaisesRegex(
            PROVISIONER.ProvisionError, "regular, singly linked file"
        ):
            self.run_provision()
        self.assertEqual(linked.read_bytes(), b"existing\n")

        self.paths.rotation_target.unlink()
        linked.unlink()
        self.log_directory.mkdir(mode=0o755, exist_ok=True)
        self.paths.log_path.symlink_to(outside)
        with self.assertRaisesRegex(
            PROVISIONER.ProvisionError, "regular, singly linked file"
        ):
            self.run_provision()
        self.assertEqual(outside.read_bytes(), b"outside\n")

    def test_rejected_snapshot_is_not_published(self) -> None:
        self.paths.rotation_target.write_bytes(b"existing policy\n")

        with self.assertRaisesRegex(
            PROVISIONER.ProvisionError, "rejected the stable policy snapshot"
        ):
            self.run_provision("reject")

        self.assertEqual(self.validator_log.read_bytes(), POLICY)
        self.assertEqual(self.paths.rotation_target.read_bytes(), b"existing policy\n")
        self.assertFalse(self.paths.log_path.exists())
        self.assertFalse(self.log_directory.exists())
        self.assert_no_snapshots()

    def test_rejected_snapshot_does_not_modify_existing_directory(self) -> None:
        self.log_directory.mkdir(mode=0o700)
        self.log_directory.chmod(0o700)
        before = self.log_directory.stat()

        with self.assertRaisesRegex(
            PROVISIONER.ProvisionError, "rejected the stable policy snapshot"
        ):
            self.run_provision("reject")

        after = self.log_directory.stat()
        self.assertEqual(stat.S_IMODE(after.st_mode), 0o700)
        self.assertEqual(
            (after.st_dev, after.st_ino, after.st_uid, after.st_gid),
            (before.st_dev, before.st_ino, before.st_uid, before.st_gid),
        )
        self.assertFalse(self.paths.log_path.exists())
        self.assertFalse(self.paths.rotation_target.exists())
        self.assert_no_snapshots()

    def test_failure_after_log_provision_restores_existing_metadata(self) -> None:
        self.log_directory.mkdir(mode=0o700)
        self.log_directory.chmod(0o700)
        self.paths.log_path.write_bytes(b"existing log\n")
        self.paths.log_path.chmod(0o600)
        original_directory = self.log_directory.stat()
        original_log = self.paths.log_path.stat()

        with (
            mock.patch.object(
                PROVISIONER,
                "publish_snapshot",
                side_effect=PROVISIONER.ProvisionError("publish failed"),
            ),
            self.assertRaisesRegex(PROVISIONER.ProvisionError, "publish failed"),
        ):
            self.run_provision()

        directory = self.log_directory.stat()
        log = self.paths.log_path.stat()
        self.assertEqual(stat.S_IMODE(directory.st_mode), 0o700)
        self.assertEqual(
            (directory.st_uid, directory.st_gid),
            (
                original_directory.st_uid,
                original_directory.st_gid,
            ),
        )
        self.assertEqual(stat.S_IMODE(log.st_mode), 0o600)
        self.assertEqual(
            (log.st_uid, log.st_gid),
            (
                original_log.st_uid,
                original_log.st_gid,
            ),
        )
        self.assertEqual(self.paths.log_path.read_bytes(), b"existing log\n")
        self.assertFalse(self.paths.rotation_target.exists())
        self.assert_no_snapshots()

    def test_failure_after_new_log_provision_removes_file_and_directory(self) -> None:
        with (
            mock.patch.object(
                PROVISIONER,
                "publish_snapshot",
                side_effect=PROVISIONER.ProvisionError("publish failed"),
            ),
            self.assertRaisesRegex(PROVISIONER.ProvisionError, "publish failed"),
        ):
            self.run_provision()

        self.assertFalse(self.paths.log_path.exists())
        self.assertFalse(self.log_directory.exists())
        self.assertFalse(self.paths.rotation_target.exists())
        self.assert_no_snapshots()

    def test_missing_transactional_signal_mask_fails_before_mutation(self) -> None:
        with (
            mock.patch.object(PROVISIONER.signal, "pthread_sigmask", None),
            self.assertRaisesRegex(
                PROVISIONER.ProvisionError, "signal masking is unavailable"
            ),
        ):
            self.run_provision()

        self.assertFalse(self.validator_log.exists())
        self.assertFalse(self.log_directory.exists())
        self.assertFalse(self.paths.rotation_target.exists())
        self.assert_no_snapshots()

    def test_transaction_masks_sigquit_with_other_termination_signals(self) -> None:
        original = PROVISIONER.signal.pthread_sigmask
        calls: list[tuple[object, set[signal.Signals] | set[int]]] = []

        def capture_mask(operation: object, signals: object) -> object:
            calls.append((operation, set(signals)))  # type: ignore[arg-type]
            return original(operation, signals)  # type: ignore[arg-type]

        with mock.patch.object(
            PROVISIONER.signal, "pthread_sigmask", side_effect=capture_mask
        ):
            self.run_provision()

        blocked = next(
            signals
            for operation, signals in calls
            if operation == PROVISIONER.signal.SIG_BLOCK
        )
        self.assertTrue(
            {
                PROVISIONER.signal.SIGINT,
                PROVISIONER.signal.SIGTERM,
                PROVISIONER.signal.SIGHUP,
                PROVISIONER.signal.SIGQUIT,
            }.issubset(blocked)
        )

    @unittest.skipUnless(hasattr(os, "fork"), "requires fork and POSIX signals")
    def test_real_sigquit_is_delivered_only_after_a_consistent_commit(self) -> None:
        ready_read, ready_write = os.pipe()
        resume_read, resume_write = os.pipe()
        child = os.fork()
        if child == 0:
            try:
                os.close(ready_read)
                os.close(resume_write)
                original_mkdir = PROVISIONER.os.mkdir

                def mkdir_then_pause(*args: object, **kwargs: object) -> object:
                    result = original_mkdir(*args, **kwargs)
                    if args and args[0] == self.log_directory.name:
                        os.write(ready_write, b"1")
                        os.read(resume_read, 1)
                    return result

                with mock.patch.object(
                    PROVISIONER.os, "mkdir", side_effect=mkdir_then_pause
                ):
                    self.run_provision()
                os._exit(0)
            except PROVISIONER.ROLLBACK_FAILURES:
                os._exit(97)

        os.close(ready_write)
        os.close(resume_read)
        try:
            self.assertEqual(os.read(ready_read, 1), b"1")
            os.kill(child, signal.SIGQUIT)
            os.write(resume_write, b"1")
            _, status = os.waitpid(child, 0)
        finally:
            os.close(ready_read)
            os.close(resume_write)

        self.assertTrue(os.WIFSIGNALED(status), status)
        self.assertEqual(os.WTERMSIG(status), signal.SIGQUIT)
        self.assertEqual(self.paths.rotation_target.read_bytes(), POLICY)
        self.assertEqual(stat.S_IMODE(self.log_directory.stat().st_mode), 0o755)
        self.assertEqual(stat.S_IMODE(self.paths.log_path.stat().st_mode), 0o640)
        self.assert_no_snapshots()

    def test_interrupt_after_mkdir_rolls_back_created_directory(self) -> None:
        original = PROVISIONER.os.mkdir

        def mkdir_then_interrupt(*args: object, **kwargs: object) -> object:
            result = original(*args, **kwargs)
            if args and args[0] == self.log_directory.name:
                raise KeyboardInterrupt("injected after mkdir")
            return result

        with (
            mock.patch.object(
                PROVISIONER.os, "mkdir", side_effect=mkdir_then_interrupt
            ),
            self.assertRaisesRegex(KeyboardInterrupt, "injected after mkdir"),
        ):
            self.run_provision()

        self.assertFalse(self.log_directory.exists())
        self.assertFalse(self.paths.rotation_target.exists())
        self.assert_no_snapshots()

    def test_interrupt_after_log_metadata_mutation_rolls_back(self) -> None:
        for existing in (False, True):
            with self.subTest(existing=existing):
                if existing:
                    self.log_directory.mkdir(mode=0o700)
                    self.log_directory.chmod(0o700)
                    self.paths.log_path.write_bytes(b"existing log\n")
                    self.paths.log_path.chmod(0o600)
                original = PROVISIONER.os.fchmod
                fired = {"value": False}

                def chmod_then_interrupt(
                    descriptor: int,
                    mode: int,
                    *args: object,
                    _original: Callable[..., object] = original,
                    _fired: dict[str, bool] = fired,
                    **kwargs: object,
                ) -> object:
                    result = _original(descriptor, mode, *args, **kwargs)
                    try:
                        opened = os.fstat(descriptor)
                        named = os.lstat(self.paths.log_path)
                    except (FileNotFoundError, OSError):
                        return result
                    if (
                        not _fired["value"]
                        and mode == 0o640
                        and (opened.st_dev, opened.st_ino)
                        == (named.st_dev, named.st_ino)
                    ):
                        _fired["value"] = True
                        raise KeyboardInterrupt("injected after log chmod")
                    return result

                with (
                    mock.patch.object(
                        PROVISIONER.os, "fchmod", side_effect=chmod_then_interrupt
                    ),
                    self.assertRaisesRegex(
                        KeyboardInterrupt, "injected after log chmod"
                    ),
                ):
                    self.run_provision()

                self.assertTrue(fired["value"])
                if existing:
                    self.assertEqual(
                        self.paths.log_path.read_bytes(), b"existing log\n"
                    )
                    self.assertEqual(
                        stat.S_IMODE(self.paths.log_path.stat().st_mode), 0o600
                    )
                    self.assertEqual(
                        stat.S_IMODE(self.log_directory.stat().st_mode), 0o700
                    )
                    self.paths.log_path.unlink()
                    self.log_directory.rmdir()
                else:
                    self.assertFalse(self.paths.log_path.exists())
                    self.assertFalse(self.log_directory.exists())
                self.assertFalse(self.paths.rotation_target.exists())
                self.assert_no_snapshots()

    def test_interrupt_after_snapshot_sync_removes_disabled_snapshot(self) -> None:
        original = PROVISIONER.os.fsync
        fired = {"value": False}

        def sync_then_interrupt(descriptor: int) -> None:
            original(descriptor)
            metadata = os.fstat(descriptor)
            if (
                not fired["value"]
                and stat.S_ISREG(metadata.st_mode)
                and stat.S_IMODE(metadata.st_mode) == 0o600
                and metadata.st_size == len(POLICY)
            ):
                fired["value"] = True
                raise KeyboardInterrupt("injected after snapshot fsync")

        with (
            mock.patch.object(PROVISIONER.os, "fsync", side_effect=sync_then_interrupt),
            self.assertRaisesRegex(KeyboardInterrupt, "injected after snapshot fsync"),
        ):
            self.run_provision()

        self.assertTrue(fired["value"])
        self.assertFalse(self.log_directory.exists())
        self.assertFalse(self.paths.rotation_target.exists())
        self.assert_no_snapshots()

    def test_interrupt_after_replace_fails_forward_with_committed_state(self) -> None:
        original = PROVISIONER.os.replace

        def replace_then_interrupt(*args: object, **kwargs: object) -> object:
            result = original(*args, **kwargs)
            if args and str(args[0]).endswith(".disabled"):
                raise KeyboardInterrupt("injected after replace")
            return result

        with (
            mock.patch.object(
                PROVISIONER.os, "replace", side_effect=replace_then_interrupt
            ),
            self.assertRaisesRegex(
                PROVISIONER.CommittedProvisionError,
                "policy was committed.*durability could not be confirmed",
            ),
        ):
            self.run_provision()

        self.assertEqual(self.paths.rotation_target.read_bytes(), POLICY)
        self.assertTrue(self.paths.log_path.exists())
        self.assertEqual(stat.S_IMODE(self.paths.log_path.stat().st_mode), 0o640)
        self.assertEqual(stat.S_IMODE(self.log_directory.stat().st_mode), 0o755)
        self.assert_no_snapshots()

    def test_post_replace_directory_sync_failure_fails_forward(self) -> None:
        original = PROVISIONER.os.fsync
        rotation_inode = self.rotation_directory.stat().st_ino

        def fail_committed_directory_sync(descriptor: int) -> None:
            if (
                os.fstat(descriptor).st_ino == rotation_inode
                and self.paths.rotation_target.exists()
            ):
                raise OSError("injected post-replace directory fsync")
            original(descriptor)

        with (
            mock.patch.object(
                PROVISIONER.os, "fsync", side_effect=fail_committed_directory_sync
            ),
            self.assertRaisesRegex(
                PROVISIONER.ProvisionError,
                "policy was committed.*durability could not be confirmed",
            ),
        ):
            self.run_provision()

        self.assertEqual(self.paths.rotation_target.read_bytes(), POLICY)
        self.assertTrue(self.paths.log_path.exists())
        self.assertEqual(stat.S_IMODE(self.log_directory.stat().st_mode), 0o755)
        self.assert_no_snapshots()

    def test_rotation_ancestor_swap_blocks_detached_policy_publish(self) -> None:
        detached = self.root / "etc.detached"
        original = PROVISIONER.publish_snapshot

        def swap_ancestor_before_publish(*args: object, **kwargs: object) -> object:
            self.rotation_parent.rename(detached)
            self.rotation_parent.mkdir(mode=0o755)
            (self.rotation_parent / "logrotate.d").mkdir(mode=0o755)
            return original(*args, **kwargs)

        with (
            mock.patch.object(
                PROVISIONER,
                "publish_snapshot",
                side_effect=swap_ancestor_before_publish,
            ),
            self.assertRaisesRegex(
                PROVISIONER.ProvisionError,
                "trusted directory chain changed during provisioning",
            ),
        ):
            self.run_provision()

        self.assertFalse(self.paths.rotation_target.exists())
        self.assertFalse(self.paths.log_path.exists())
        self.assertFalse(self.log_directory.exists())
        detached_rotation = detached / "logrotate.d"
        self.assertFalse((detached_rotation / self.paths.rotation_name).exists())
        self.assertEqual(
            list(detached_rotation.glob("codex-control-access.*.disabled")), []
        )

    def test_unsafe_rotation_ancestor_fails_before_validation(self) -> None:
        self.rotation_parent.chmod(0o775)

        with self.assertRaisesRegex(
            PROVISIONER.ProvisionError, "must not be group or world writable"
        ):
            self.run_provision()

        self.assertFalse(self.validator_log.exists())
        self.assertFalse(self.paths.rotation_target.exists())
        self.assertFalse(self.log_directory.exists())


if __name__ == "__main__":
    unittest.main()
