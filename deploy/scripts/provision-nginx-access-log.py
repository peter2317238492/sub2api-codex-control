"""Safely provision the host Nginx access log and its rotation policy."""

from __future__ import annotations

import dataclasses
import grp
import os
import pathlib
import pwd
import secrets
import signal
import stat
import subprocess
import sys
from collections.abc import Sequence
from typing import Self

MAX_POLICY_BYTES = 1024 * 1024
DIRECTORY_WRITE_MASK = stat.S_IWGRP | stat.S_IWOTH
OPEN_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
OPEN_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
OPEN_DIRECTORY = getattr(os, "O_DIRECTORY", 0)


class ProvisionError(RuntimeError):
    pass


class CommittedProvisionError(ProvisionError):
    """The runtime policy was committed, but completion was interrupted."""


@dataclasses.dataclass(frozen=True)
class ProvisionPaths:
    rotation_source: pathlib.Path
    rotation_directory: pathlib.Path
    rotation_name: str
    log_directory: pathlib.Path
    log_name: str
    rotation_trust_anchor: pathlib.Path = pathlib.Path("/")

    @property
    def rotation_target(self) -> pathlib.Path:
        return self.rotation_directory / self.rotation_name

    @property
    def log_path(self) -> pathlib.Path:
        return self.log_directory / self.log_name


def metadata_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def inode_identity(metadata: os.stat_result) -> tuple[int, int]:
    return metadata.st_dev, metadata.st_ino


def live_log_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_nlink,
    )


def live_log_object_identity(metadata: os.stat_result) -> tuple[int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        stat.S_IFMT(metadata.st_mode),
        metadata.st_nlink,
    )


def validate_leaf_name(name: str, *, label: str) -> None:
    if (
        not isinstance(name, str)
        or name in {"", ".", ".."}
        or "\x00" in name
        or pathlib.Path(name).name != name
    ):
        raise ProvisionError(f"{label} must be a single path component")


def describe_os_error(label: str, error: OSError) -> ProvisionError:
    return ProvisionError(f"cannot access {label}: {error.strerror or error}")


def verify_trusted_directory(
    path: pathlib.Path,
    *,
    expected_uid: int,
    expected_gid: int,
    allowed_modes: frozenset[int] | None = None,
) -> None:
    try:
        before = os.lstat(path)
        descriptor = os.open(
            path,
            os.O_RDONLY | OPEN_DIRECTORY | OPEN_NOFOLLOW | OPEN_CLOEXEC,
        )
    except OSError as error:
        raise describe_os_error(f"trusted directory {path}", error) from error
    try:
        opened = os.fstat(descriptor)
        mode = stat.S_IMODE(opened.st_mode)
        if (
            not stat.S_ISDIR(opened.st_mode)
            or opened.st_uid != expected_uid
            or opened.st_gid != expected_gid
            or mode & DIRECTORY_WRITE_MASK
            or (allowed_modes is not None and mode not in allowed_modes)
            or inode_identity(before) != inode_identity(opened)
        ):
            raise ProvisionError(
                f"trusted directory {path} must be root-owned, non-symlink, "
                "and not group or world writable"
            )
    finally:
        os.close(descriptor)


def verify_trusted_file(
    path: pathlib.Path,
    *,
    expected_uid: int,
    expected_gid: int,
    expected_mode: int,
) -> None:
    try:
        before = os.lstat(path)
        descriptor = os.open(path, os.O_RDONLY | OPEN_NOFOLLOW | OPEN_CLOEXEC)
    except OSError as error:
        raise describe_os_error(f"trusted file {path}", error) from error
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or opened.st_uid != expected_uid
            or opened.st_gid != expected_gid
            or stat.S_IMODE(opened.st_mode) != expected_mode
            or metadata_identity(before) != metadata_identity(opened)
        ):
            raise ProvisionError(
                f"trusted file {path} must be singly linked, owned by the "
                f"configured root identity, and mode {expected_mode:04o}"
            )
    finally:
        os.close(descriptor)


def verify_trusted_ancestors(
    path: pathlib.Path,
    *,
    expected_uid: int,
    expected_gid: int,
) -> None:
    for directory in (path.parent, *path.parent.parents):
        verify_trusted_directory(
            directory,
            expected_uid=expected_uid,
            expected_gid=expected_gid,
        )


def verify_privileged_runtime(
    repo_root: pathlib.Path, script_path: pathlib.Path
) -> None:
    expected_script = repo_root / "deploy/scripts/provision-nginx-access-log.py"
    if script_path != expected_script:
        raise ProvisionError("provisioner must run from its canonical staging layout")
    for directory in (repo_root, *repo_root.parents):
        verify_trusted_directory(
            directory,
            expected_uid=0,
            expected_gid=0,
            allowed_modes=frozenset({0o555, 0o700}) if directory == repo_root else None,
        )
    for directory in (
        repo_root / "deploy",
        repo_root / "deploy/scripts",
        repo_root / "deploy/nginx",
    ):
        verify_trusted_directory(
            directory,
            expected_uid=0,
            expected_gid=0,
            allowed_modes=frozenset({0o555}),
        )
    verify_trusted_file(
        repo_root / "deploy/scripts/provision-nginx-access-log.sh",
        expected_uid=0,
        expected_gid=0,
        expected_mode=0o555,
    )
    verify_trusted_file(
        script_path,
        expected_uid=0,
        expected_gid=0,
        expected_mode=0o444,
    )
    verify_trusted_file(
        repo_root / "deploy/nginx/codex-control-access.logrotate",
        expected_uid=0,
        expected_gid=0,
        expected_mode=0o444,
    )


class SecureDirectory:
    def __init__(
        self,
        path: pathlib.Path,
        *,
        expected_uid: int,
        expected_gid: int,
        allow_group_write: bool = False,
        create: bool = False,
        exact_mode: int | None = None,
        platform_log_parent_gids: frozenset[int] | None = None,
        trust_anchor: pathlib.Path | None = None,
    ) -> None:
        self.path = path
        self.expected_uid = expected_uid
        self.expected_gid = expected_gid
        self.allow_group_write = allow_group_write
        self.create = create
        self.exact_mode = exact_mode
        self.platform_log_parent_gids = platform_log_parent_gids
        self.trust_anchor = trust_anchor
        self.fd = -1
        self.identity: tuple[int, int] | None = None
        self.parent: SecureDirectory | None = None
        self.parent_anchor: SecureDirectory | None = None
        self.parent_identity: tuple[int, int] | None = None
        self.entry_name: str | None = None
        self.created = False
        self.committed = False
        self.original_mode: int | None = None
        self.target_identity: tuple[int, int] | None = None
        self.trusted_chain: list[tuple[int, pathlib.Path, tuple[int, int]]] = []

    def __enter__(self) -> Self:
        if self.create:
            return self._enter_created_directory()
        if self.trust_anchor is not None:
            return self._enter_trusted_chain()
        try:
            before = os.lstat(self.path)
        except OSError as error:
            raise describe_os_error(str(self.path), error) from error
        self._validate(before)
        try:
            self.fd = os.open(
                self.path,
                os.O_RDONLY | OPEN_DIRECTORY | OPEN_NOFOLLOW | OPEN_CLOEXEC,
            )
        except OSError as error:
            raise describe_os_error(str(self.path), error) from error
        try:
            opened = os.fstat(self.fd)
            self._validate(opened)
            if inode_identity(before) != inode_identity(opened):
                raise ProvisionError(f"{self.path} changed while it was opened")
            self.identity = inode_identity(opened)
        except BaseException:
            os.close(self.fd)
            self.fd = -1
            raise
        return self

    def _enter_trusted_chain(self) -> Self:
        anchor = pathlib.Path(os.path.abspath(self.trust_anchor))
        target = pathlib.Path(os.path.abspath(self.path))
        if target != anchor and anchor not in target.parents:
            raise ProvisionError(f"{target} must be below its trusted anchor {anchor}")
        relative_parts = target.relative_to(anchor).parts
        current_path = anchor
        try:
            descriptor = os.open(
                anchor,
                os.O_RDONLY | OPEN_DIRECTORY | OPEN_NOFOLLOW | OPEN_CLOEXEC,
            )
            self.trusted_chain.append((descriptor, current_path, (-1, -1)))
            anchor_metadata = os.fstat(descriptor)
            self._validate(anchor_metadata, require_exact_mode=False)
            self.trusted_chain[-1] = (
                descriptor,
                current_path,
                inode_identity(anchor_metadata),
            )
            for component in relative_parts:
                parent_fd = descriptor
                before = os.stat(
                    component,
                    dir_fd=parent_fd,
                    follow_symlinks=False,
                )
                self._validate(before, require_exact_mode=False)
                descriptor = os.open(
                    component,
                    os.O_RDONLY | OPEN_DIRECTORY | OPEN_NOFOLLOW | OPEN_CLOEXEC,
                    dir_fd=parent_fd,
                )
                current_path /= component
                self.trusted_chain.append((descriptor, current_path, (-1, -1)))
                opened = os.fstat(descriptor)
                self._validate(opened, require_exact_mode=False)
                if inode_identity(before) != inode_identity(opened):
                    raise ProvisionError(
                        f"trusted directory component changed while opening: {component}"
                    )
                self.trusted_chain[-1] = (
                    descriptor,
                    current_path,
                    inode_identity(opened),
                )
            self.fd = descriptor
            final = os.fstat(self.fd)
            self._validate(final)
            self.identity = inode_identity(final)
            return self
        except BaseException:
            self._close_trusted_chain()
            raise

    def _close_trusted_chain(self) -> None:
        descriptors = [item[0] for item in self.trusted_chain]
        self.trusted_chain.clear()
        self.fd = -1
        for descriptor in reversed(descriptors):
            try:
                os.close(descriptor)
            except OSError:
                pass

    def _enter_created_directory(self) -> Self:
        platform_parent = self.platform_log_parent_gids is not None
        if platform_parent and self.path != pathlib.Path(
            "/var/log/sub2api-codex-control"
        ):
            raise ProvisionError(
                "platform log parent policy is restricted to the dedicated log path"
            )
        if platform_parent:
            self.parent_anchor = SecureDirectory(
                pathlib.Path("/var"),
                expected_uid=self.expected_uid,
                expected_gid=self.expected_gid,
            )
            self.parent_anchor.__enter__()
        self.parent = SecureDirectory(
            self.path.parent,
            expected_uid=self.expected_uid,
            expected_gid=self.expected_gid,
        )
        try:
            if platform_parent:
                self._enter_platform_log_parent()
            else:
                self.parent.__enter__()
            self.entry_name = self.path.name
            if (
                self.entry_name in {"", ".", ".."}
                or self.path.parent / self.entry_name != self.path
            ):
                raise ProvisionError("dedicated log directory name is invalid")
            created = False
            try:
                before = os.stat(
                    self.entry_name,
                    dir_fd=self.parent.fd,
                    follow_symlinks=False,
                )
            except FileNotFoundError:
                try:
                    os.mkdir(
                        self.entry_name,
                        self.exact_mode or 0o755,
                        dir_fd=self.parent.fd,
                    )
                    created = True
                    self.created = True
                    before = os.stat(
                        self.entry_name,
                        dir_fd=self.parent.fd,
                        follow_symlinks=False,
                    )
                    self.target_identity = inode_identity(before)
                    os.fsync(self.parent.fd)
                except BaseException as error:
                    try:
                        created_entry = os.stat(
                            self.entry_name,
                            dir_fd=self.parent.fd,
                            follow_symlinks=False,
                        )
                        self._validate(created_entry, require_exact_mode=False)
                        if stat.S_IMODE(created_entry.st_mode) != (
                            self.exact_mode or 0o755
                        ):
                            raise ProvisionError(
                                f"{self.path} has an unexpected post-create mode"
                            )
                        created = True
                        self.created = True
                        self.target_identity = inode_identity(created_entry)
                    except FileNotFoundError:
                        pass
                    if isinstance(error, OSError):
                        raise describe_os_error(str(self.path), error) from error
                    raise
            except OSError as error:
                raise describe_os_error(str(self.path), error) from error
            self.target_identity = inode_identity(before)
            self._validate(before, require_exact_mode=False)
            try:
                self.fd = os.open(
                    self.entry_name,
                    os.O_RDONLY | OPEN_DIRECTORY | OPEN_NOFOLLOW | OPEN_CLOEXEC,
                    dir_fd=self.parent.fd,
                )
            except OSError as error:
                raise describe_os_error(str(self.path), error) from error
            opened = os.fstat(self.fd)
            self._validate(opened, require_exact_mode=False)
            if inode_identity(before) != inode_identity(opened):
                raise ProvisionError(f"{self.path} changed while it was opened")
            self.created = created
            self.original_mode = stat.S_IMODE(opened.st_mode)
            if self.exact_mode is not None:
                os.fchmod(self.fd, self.exact_mode)
                opened = os.fstat(self.fd)
            self._validate(opened)
            os.fsync(self.fd)
            self.identity = inode_identity(opened)
        except BaseException as error:
            self._cleanup(
                rollback=self.fd >= 0 or self.created,
                original=error,
            )
            raise
        return self

    def __exit__(
        self,
        _exc_type: type[BaseException] | None = None,
        exc: BaseException | None = None,
        _traceback: object | None = None,
    ) -> None:
        self._cleanup(
            rollback=self.create and not self.committed and self.fd >= 0,
            original=exc,
        )

    def _cleanup(
        self,
        *,
        rollback: bool,
        original: BaseException | None,
    ) -> None:
        cleanup_errors: list[BaseException] = []
        if rollback:
            try:
                self._rollback_directory()
            except BaseException as error:
                cleanup_errors.append(error)
        if self.trusted_chain:
            descriptors = [item[0] for item in self.trusted_chain]
            self.trusted_chain.clear()
            self.fd = -1
            for descriptor in reversed(descriptors):
                try:
                    os.close(descriptor)
                except OSError as error:
                    cleanup_errors.append(error)
        elif self.fd >= 0:
            descriptor = self.fd
            self.fd = -1
            try:
                os.close(descriptor)
            except OSError as error:
                cleanup_errors.append(error)
        if self.parent is not None:
            parent = self.parent
            self.parent = None
            try:
                parent.__exit__()
            except BaseException as error:
                cleanup_errors.append(error)
        if self.parent_anchor is not None:
            parent_anchor = self.parent_anchor
            self.parent_anchor = None
            try:
                parent_anchor.__exit__()
            except BaseException as error:
                cleanup_errors.append(error)
        if cleanup_errors:
            details = "; ".join(
                f"{type(error).__name__}: {error}" for error in cleanup_errors
            )
            if original is not None:
                raise ProvisionError(
                    f"{original}; cleanup also failed: {details}"
                ) from original
            raise ProvisionError(f"secure directory cleanup failed: {details}")

    def _enter_platform_log_parent(self) -> None:
        if self.parent is None or self.parent_anchor is None:
            raise ProvisionError("platform log parent is not configured")
        try:
            before = os.stat(
                "log",
                dir_fd=self.parent_anchor.fd,
                follow_symlinks=False,
            )
            self.parent.fd = os.open(
                "log",
                os.O_RDONLY | OPEN_DIRECTORY | OPEN_NOFOLLOW | OPEN_CLOEXEC,
                dir_fd=self.parent_anchor.fd,
            )
            opened = os.fstat(self.parent.fd)
        except OSError as error:
            raise describe_os_error("/var/log", error) from error
        self._validate_platform_log_parent(opened)
        if inode_identity(before) != inode_identity(opened):
            raise ProvisionError("/var/log changed while it was opened")
        self.parent.identity = inode_identity(opened)
        self.parent_identity = inode_identity(opened)

    def _validate_platform_log_parent(self, metadata: os.stat_result) -> None:
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != self.expected_uid
            or metadata.st_gid not in self.platform_log_parent_gids
            or stat.S_IMODE(metadata.st_mode) not in {0o755, 0o775}
        ):
            raise ProvisionError(
                "/var/log must be a root-owned non-symlink directory with an "
                "admitted group and mode 0755 or 0775"
            )

    def _verify_creation_parent(self) -> None:
        if self.parent is None or self.parent.fd < 0:
            raise ProvisionError("creation parent directory is not open")
        if self.platform_log_parent_gids is None:
            self.parent.verify()
            return
        if self.parent_anchor is None or self.parent_identity is None:
            raise ProvisionError("platform log parent anchor is not open")
        self.parent_anchor.verify()
        opened = os.fstat(self.parent.fd)
        current = os.stat(
            "log",
            dir_fd=self.parent_anchor.fd,
            follow_symlinks=False,
        )
        self._validate_platform_log_parent(opened)
        self._validate_platform_log_parent(current)
        if (
            inode_identity(opened) != self.parent_identity
            or inode_identity(current) != self.parent_identity
        ):
            raise ProvisionError("/var/log changed during provisioning")

    def _rollback_directory(self) -> None:
        if self.parent is None or self.entry_name is None:
            return
        self._verify_creation_parent()
        named = os.stat(
            self.entry_name,
            dir_fd=self.parent.fd,
            follow_symlinks=False,
        )
        named_identity = inode_identity(named)
        if self.target_identity is not None and named_identity != self.target_identity:
            raise ProvisionError(f"{self.path} changed before rollback")
        if self.fd >= 0 and inode_identity(os.fstat(self.fd)) != named_identity:
            raise ProvisionError(f"{self.path} changed before rollback")
        if self.created:
            os.rmdir(self.entry_name, dir_fd=self.parent.fd)
            os.fsync(self.parent.fd)
        elif self.fd >= 0 and self.original_mode is not None:
            os.fchmod(self.fd, self.original_mode)
            os.fsync(self.fd)

    def _validate(
        self,
        metadata: os.stat_result,
        *,
        require_owner: bool = True,
        require_exact_mode: bool = True,
    ) -> None:
        if not stat.S_ISDIR(metadata.st_mode):
            raise ProvisionError(f"{self.path} must be a non-symlink directory")
        if require_owner and (
            metadata.st_uid != self.expected_uid or metadata.st_gid != self.expected_gid
        ):
            raise ProvisionError(
                f"{self.path} must be owned by the configured root identity"
            )
        forbidden_write_mask = stat.S_IWOTH
        if not self.allow_group_write:
            forbidden_write_mask |= stat.S_IWGRP
        if metadata.st_mode & forbidden_write_mask:
            raise ProvisionError(f"{self.path} must not be group or world writable")
        if (
            require_exact_mode
            and self.exact_mode is not None
            and stat.S_IMODE(metadata.st_mode) != self.exact_mode
        ):
            raise ProvisionError(f"{self.path} must have mode {self.exact_mode:04o}")

    def verify(self) -> None:
        if self.fd < 0 or self.identity is None:
            raise ProvisionError(f"secure directory is not open: {self.path}")
        if self.trusted_chain:
            self._verify_trusted_chain()
            return
        try:
            opened = os.fstat(self.fd)
            if self.parent is not None and self.entry_name is not None:
                self._verify_creation_parent()
                current = os.stat(
                    self.entry_name,
                    dir_fd=self.parent.fd,
                    follow_symlinks=False,
                )
            else:
                current = os.lstat(self.path)
        except OSError as error:
            raise describe_os_error(str(self.path), error) from error
        self._validate(opened)
        self._validate(current)
        if (
            inode_identity(opened) != self.identity
            or inode_identity(current) != self.identity
        ):
            raise ProvisionError(f"{self.path} changed during provisioning")

    def _verify_trusted_chain(self) -> None:
        for index, (descriptor, path, expected_identity) in enumerate(
            self.trusted_chain
        ):
            try:
                opened = os.fstat(descriptor)
                if index == 0:
                    named = os.lstat(path)
                else:
                    parent_fd = self.trusted_chain[index - 1][0]
                    named = os.stat(
                        path.name,
                        dir_fd=parent_fd,
                        follow_symlinks=False,
                    )
            except OSError as error:
                raise describe_os_error(f"trusted directory {path}", error) from error
            self._validate(opened, require_exact_mode=False)
            self._validate(named, require_exact_mode=False)
            if (
                inode_identity(opened) != expected_identity
                or inode_identity(named) != expected_identity
            ):
                raise ProvisionError(
                    f"trusted directory chain changed during provisioning: {path}"
                )
        final = os.fstat(self.fd)
        self._validate(final)
        if inode_identity(final) != self.identity:
            raise ProvisionError(f"{self.path} changed during provisioning")


def read_exact_fd(descriptor: int, expected_size: int, *, label: str) -> bytes:
    if expected_size > MAX_POLICY_BYTES:
        raise ProvisionError(f"{label} exceeds the 1 MiB safety limit")
    chunks: list[bytes] = []
    offset = 0
    while offset < expected_size:
        chunk = os.pread(descriptor, min(64 * 1024, expected_size - offset), offset)
        if not chunk:
            raise ProvisionError(f"{label} became shorter while reading")
        chunks.append(chunk)
        offset += len(chunk)
    if os.pread(descriptor, 1, expected_size):
        raise ProvisionError(f"{label} became longer while reading")
    return b"".join(chunks)


def open_stable_source(
    path: pathlib.Path,
    *,
    expected_uid: int,
    expected_gid: int,
) -> tuple[int, os.stat_result, bytes]:
    try:
        before = os.lstat(path)
        descriptor = os.open(path, os.O_RDONLY | OPEN_NOFOLLOW | OPEN_CLOEXEC)
    except OSError as error:
        raise describe_os_error("logrotate policy source", error) from error
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or opened.st_uid != expected_uid
            or opened.st_gid != expected_gid
            or stat.S_IMODE(opened.st_mode) != 0o444
        ):
            raise ProvisionError(
                "logrotate policy source must be a regular, singly linked file "
                "owned by the configured root identity with mode 0444"
            )
        if metadata_identity(before) != metadata_identity(opened):
            raise ProvisionError("logrotate policy source changed while it was opened")
        content = read_exact_fd(
            descriptor, opened.st_size, label="logrotate policy source"
        )
        after = os.fstat(descriptor)
        if metadata_identity(opened) != metadata_identity(after):
            raise ProvisionError("logrotate policy source changed while reading")
        return descriptor, opened, content
    except BaseException:
        os.close(descriptor)
        raise


def verify_source_unchanged(
    path: pathlib.Path,
    descriptor: int,
    expected: os.stat_result,
    expected_content: bytes,
) -> None:
    try:
        opened = os.fstat(descriptor)
        current = os.lstat(path)
    except OSError as error:
        raise describe_os_error("logrotate policy source", error) from error
    if metadata_identity(opened) != metadata_identity(expected) or metadata_identity(
        current
    ) != metadata_identity(expected):
        raise ProvisionError("logrotate policy source changed during validation")
    if (
        read_exact_fd(descriptor, expected.st_size, label="logrotate policy source")
        != expected_content
    ):
        raise ProvisionError(
            "logrotate policy source content changed during validation"
        )


def capture_entry(
    directory: SecureDirectory,
    name: str,
    *,
    label: str,
) -> os.stat_result | None:
    try:
        metadata = os.stat(name, dir_fd=directory.fd, follow_symlinks=False)
    except FileNotFoundError:
        return None
    except OSError as error:
        raise describe_os_error(label, error) from error
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise ProvisionError(f"{label} must be a regular, singly linked file")
    return metadata


def verify_entry_unchanged(
    directory: SecureDirectory,
    name: str,
    expected: os.stat_result | None,
    *,
    label: str,
) -> None:
    current = capture_entry(directory, name, label=label)
    if expected is None:
        if current is not None:
            raise ProvisionError(f"{label} appeared during validation")
        return
    if current is None or metadata_identity(current) != metadata_identity(expected):
        raise ProvisionError(f"{label} changed during validation")


def verify_live_log_unchanged(
    directory: SecureDirectory,
    name: str,
    expected: os.stat_result | None,
) -> None:
    current = capture_entry(directory, name, label="dedicated Nginx access log")
    if expected is None:
        if current is not None:
            raise ProvisionError(
                "dedicated Nginx access log appeared during validation"
            )
        return
    if current is None or live_log_identity(current) != live_log_identity(expected):
        raise ProvisionError("dedicated Nginx access log changed during validation")


def create_snapshot(
    directory: SecureDirectory,
    content: bytes,
    *,
    expected_uid: int,
    expected_gid: int,
) -> tuple[str, int, os.stat_result]:
    for _attempt in range(16):
        # .disabled is in logrotate's default taboo extension set, so a daemon
        # scanning /etc/logrotate.d cannot load this pre-commit snapshot.
        name = f"codex-control-access.{secrets.token_hex(12)}.disabled"
        try:
            descriptor = os.open(
                name,
                os.O_RDWR | os.O_CREAT | os.O_EXCL | OPEN_NOFOLLOW | OPEN_CLOEXEC,
                0o600,
                dir_fd=directory.fd,
            )
            break
        except FileExistsError:
            continue
        except OSError as error:
            raise describe_os_error("logrotate policy snapshot", error) from error
    else:
        raise ProvisionError("cannot allocate a unique logrotate policy snapshot")

    try:
        os.fchown(descriptor, expected_uid, expected_gid)
        os.fchmod(descriptor, 0o600)
        written = 0
        while written < len(content):
            written += os.write(descriptor, content[written:])
        os.fsync(descriptor)
        metadata = os.fstat(descriptor)
        named = os.stat(name, dir_fd=directory.fd, follow_symlinks=False)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_uid != expected_uid
            or metadata.st_gid != expected_gid
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata_identity(metadata) != metadata_identity(named)
        ):
            raise ProvisionError("logrotate policy snapshot is not a root-only file")
        if (
            read_exact_fd(descriptor, len(content), label="logrotate policy snapshot")
            != content
        ):
            raise ProvisionError("logrotate policy snapshot content is invalid")
        return name, descriptor, metadata
    except BaseException:
        os.close(descriptor)
        try:
            os.unlink(name, dir_fd=directory.fd)
        except FileNotFoundError:
            pass
        raise


def snapshot_fd_path(descriptor: int) -> str:
    for root in ("/proc/self/fd", "/dev/fd"):
        if pathlib.Path(root).is_dir():
            return f"{root}/{descriptor}"
    raise ProvisionError("the platform does not expose inherited file descriptors")


def validate_snapshot(
    command: Sequence[str],
    descriptor: int,
) -> None:
    if not command:
        raise ProvisionError("logrotate validation command is empty")
    os.lseek(descriptor, 0, os.SEEK_SET)
    result = subprocess.run(
        [*command, "--debug", snapshot_fd_path(descriptor)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        pass_fds=(descriptor,),
        check=False,
    )
    if result.returncode != 0:
        raise ProvisionError("logrotate rejected the stable policy snapshot")


def verify_snapshot(
    directory: SecureDirectory,
    name: str,
    descriptor: int,
    expected: os.stat_result,
    expected_content: bytes,
) -> None:
    try:
        opened = os.fstat(descriptor)
        named = os.stat(name, dir_fd=directory.fd, follow_symlinks=False)
    except OSError as error:
        raise describe_os_error("logrotate policy snapshot", error) from error
    if (
        metadata_identity(opened) != metadata_identity(expected)
        or metadata_identity(named) != metadata_identity(expected)
        or read_exact_fd(
            descriptor, expected.st_size, label="logrotate policy snapshot"
        )
        != expected_content
    ):
        raise ProvisionError("validated logrotate policy snapshot changed")


def provision_log_file(
    directory: SecureDirectory,
    name: str,
    *,
    expected_uid: int,
    expected_gid: int,
    expected_entry: os.stat_result | None,
) -> tuple[bool, os.stat_result, os.stat_result]:
    flags = os.O_WRONLY | os.O_APPEND | OPEN_NOFOLLOW | OPEN_CLOEXEC
    created = expected_entry is None
    try:
        if created:
            descriptor = os.open(
                name,
                flags | os.O_CREAT | os.O_EXCL,
                0o640,
                dir_fd=directory.fd,
            )
        else:
            descriptor = os.open(name, flags, dir_fd=directory.fd)
    except OSError as error:
        raise describe_os_error("dedicated Nginx access log", error) from error
    original: os.stat_result | None = None
    metadata_mutation_started = False
    try:
        original = os.fstat(descriptor)
        if not stat.S_ISREG(original.st_mode) or original.st_nlink != 1:
            raise ProvisionError(
                "dedicated Nginx access log must be a regular, singly linked file"
            )
        if expected_entry is not None and live_log_identity(
            original
        ) != live_log_identity(expected_entry):
            raise ProvisionError(
                "dedicated Nginx access log changed before it was opened"
            )
        metadata_mutation_started = True
        os.fchown(descriptor, expected_uid, expected_gid)
        os.fchmod(descriptor, 0o640)
        final = os.fstat(descriptor)
        named = os.stat(name, dir_fd=directory.fd, follow_symlinks=False)
        if (
            not stat.S_ISREG(final.st_mode)
            or final.st_nlink != 1
            or final.st_uid != expected_uid
            or final.st_gid != expected_gid
            or stat.S_IMODE(final.st_mode) != 0o640
            or inode_identity(final) != inode_identity(named)
        ):
            raise ProvisionError(
                "dedicated Nginx access log ownership or mode is invalid"
            )
        os.fsync(descriptor)
        if created:
            os.fsync(directory.fd)
        return created, original, final
    except BaseException as error:
        if created or metadata_mutation_started:
            try:
                opened = os.fstat(descriptor)
                named = os.stat(
                    name,
                    dir_fd=directory.fd,
                    follow_symlinks=False,
                )
                if (
                    not stat.S_ISREG(opened.st_mode)
                    or opened.st_nlink != 1
                    or live_log_object_identity(opened)
                    != live_log_object_identity(named)
                ):
                    raise ProvisionError(
                        "dedicated Nginx access log changed before rollback"
                    )
                if created:
                    os.unlink(name, dir_fd=directory.fd)
                    os.fsync(directory.fd)
                elif original is not None:
                    os.fchown(descriptor, original.st_uid, original.st_gid)
                    os.fchmod(descriptor, stat.S_IMODE(original.st_mode))
                    os.fsync(descriptor)
            except BaseException as cleanup_error:
                raise ProvisionError(
                    "dedicated Nginx access log provisioning failed: "
                    f"{error}; rollback also failed: {cleanup_error}"
                ) from error
        if isinstance(error, OSError):
            raise describe_os_error("dedicated Nginx access log", error) from error
        raise
    finally:
        os.close(descriptor)


def rollback_log_file(
    directory: SecureDirectory,
    name: str,
    provisioned: tuple[bool, os.stat_result, os.stat_result],
) -> None:
    created, original, final = provisioned
    current = capture_entry(directory, name, label="dedicated Nginx access log")
    if current is None or live_log_object_identity(current) != live_log_object_identity(
        final
    ):
        raise ProvisionError("dedicated Nginx access log changed before rollback")
    if created:
        os.unlink(name, dir_fd=directory.fd)
        os.fsync(directory.fd)
        return
    descriptor = os.open(
        name,
        os.O_WRONLY | os.O_APPEND | OPEN_NOFOLLOW | OPEN_CLOEXEC,
        dir_fd=directory.fd,
    )
    try:
        if live_log_object_identity(os.fstat(descriptor)) != live_log_object_identity(
            final
        ):
            raise ProvisionError("dedicated Nginx access log changed before rollback")
        os.fchown(descriptor, original.st_uid, original.st_gid)
        os.fchmod(descriptor, stat.S_IMODE(original.st_mode))
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def publish_snapshot(
    directory: SecureDirectory,
    commit_directory: SecureDirectory,
    snapshot_name: str,
    snapshot_fd: int,
    target_name: str,
    content: bytes,
    *,
    expected_uid: int,
    expected_gid: int,
    expected_target: os.stat_result | None,
) -> None:
    os.fchown(snapshot_fd, expected_uid, expected_gid)
    os.fchmod(snapshot_fd, 0o644)
    os.fsync(snapshot_fd)
    directory.verify()
    verify_entry_unchanged(
        directory,
        target_name,
        expected_target,
        label="logrotate policy target",
    )
    try:
        final = os.fstat(snapshot_fd)
        named = os.stat(
            snapshot_name,
            dir_fd=directory.fd,
            follow_symlinks=False,
        )
    except OSError as error:
        raise describe_os_error("validated logrotate policy snapshot", error) from error
    if (
        not stat.S_ISREG(final.st_mode)
        or final.st_nlink != 1
        or final.st_uid != expected_uid
        or final.st_gid != expected_gid
        or stat.S_IMODE(final.st_mode) != 0o644
        or inode_identity(final) != inode_identity(named)
        or read_exact_fd(snapshot_fd, len(content), label="published logrotate policy")
        != content
    ):
        raise ProvisionError(
            "validated logrotate policy ownership, mode, or content is invalid"
        )
    # Persist the prepared snapshot name before the atomic runtime commit. The
    # replacement is deliberately the final fallible operation: a post-rename
    # directory fsync could report failure after the new policy is already
    # active, when rolling back the congruent log state would be incorrect.
    os.fsync(directory.fd)
    try:
        os.replace(
            snapshot_name,
            target_name,
            src_dir_fd=directory.fd,
            dst_dir_fd=directory.fd,
        )
        commit_directory.committed = True
    except BaseException as error:
        try:
            target = os.stat(
                target_name,
                dir_fd=directory.fd,
                follow_symlinks=False,
            )
            committed = inode_identity(target) == inode_identity(os.fstat(snapshot_fd))
        except (FileNotFoundError, OSError):
            committed = False
        if committed:
            commit_directory.committed = True
            raise CommittedProvisionError(
                "logrotate policy was committed, but completion was interrupted; "
                "directory durability could not be confirmed"
            ) from error
        if isinstance(error, OSError):
            raise describe_os_error("logrotate policy target", error) from error
        raise


def _provision_blocked(
    paths: ProvisionPaths,
    *,
    expected_root_uid: int,
    expected_root_gid: int,
    log_uid: int,
    log_gid: int,
    logrotate_command: Sequence[str],
    platform_log_parent_gids: frozenset[int] | None = None,
) -> None:
    source_fd = -1
    snapshot_fd = -1
    snapshot_name: str | None = None
    try:
        source_fd, source_metadata, source_content = open_stable_source(
            paths.rotation_source,
            expected_uid=expected_root_uid,
            expected_gid=expected_root_gid,
        )
        with SecureDirectory(
            paths.rotation_directory,
            expected_uid=expected_root_uid,
            expected_gid=expected_root_gid,
            trust_anchor=paths.rotation_trust_anchor,
        ) as rotation_directory:
            rotation_target_before = capture_entry(
                rotation_directory,
                paths.rotation_name,
                label="logrotate policy target",
            )
            snapshot_name, snapshot_fd, snapshot_metadata = create_snapshot(
                rotation_directory,
                source_content,
                expected_uid=expected_root_uid,
                expected_gid=expected_root_gid,
            )
            try:
                validate_snapshot(logrotate_command, snapshot_fd)
                verify_snapshot(
                    rotation_directory,
                    snapshot_name,
                    snapshot_fd,
                    snapshot_metadata,
                    source_content,
                )
                verify_source_unchanged(
                    paths.rotation_source,
                    source_fd,
                    source_metadata,
                    source_content,
                )
                rotation_directory.verify()
                verify_entry_unchanged(
                    rotation_directory,
                    paths.rotation_name,
                    rotation_target_before,
                    label="logrotate policy target",
                )
                with SecureDirectory(
                    paths.log_directory,
                    expected_uid=expected_root_uid,
                    expected_gid=expected_root_gid,
                    create=True,
                    exact_mode=0o755,
                    platform_log_parent_gids=platform_log_parent_gids,
                ) as log_directory:
                    log_before = capture_entry(
                        log_directory,
                        paths.log_name,
                        label="dedicated Nginx access log",
                    )
                    verify_live_log_unchanged(
                        log_directory,
                        paths.log_name,
                        log_before,
                    )
                    provisioned_log = None
                    try:
                        provisioned_log = provision_log_file(
                            log_directory,
                            paths.log_name,
                            expected_uid=log_uid,
                            expected_gid=log_gid,
                            expected_entry=log_before,
                        )
                        verify_source_unchanged(
                            paths.rotation_source,
                            source_fd,
                            source_metadata,
                            source_content,
                        )
                        verify_live_log_unchanged(
                            log_directory,
                            paths.log_name,
                            provisioned_log[2],
                        )
                        log_directory.verify()
                        publish_snapshot(
                            rotation_directory,
                            log_directory,
                            snapshot_name,
                            snapshot_fd,
                            paths.rotation_name,
                            source_content,
                            expected_uid=expected_root_uid,
                            expected_gid=expected_root_gid,
                            expected_target=rotation_target_before,
                        )
                        snapshot_name = None
                    except BaseException as error:
                        if log_directory.committed:
                            snapshot_name = None
                            if isinstance(error, CommittedProvisionError):
                                raise
                            raise CommittedProvisionError(
                                "logrotate policy was committed, but completion was "
                                "interrupted; directory durability could not be confirmed"
                            ) from error
                        if provisioned_log is not None:
                            rollback_log_file(
                                log_directory,
                                paths.log_name,
                                provisioned_log,
                            )
                        raise
                    try:
                        os.fsync(rotation_directory.fd)
                    except OSError as error:
                        raise CommittedProvisionError(
                            "logrotate policy was committed, but directory "
                            "durability could not be confirmed"
                        ) from error
            finally:
                if snapshot_name is not None:
                    try:
                        os.unlink(snapshot_name, dir_fd=rotation_directory.fd)
                    except FileNotFoundError:
                        pass
    finally:
        if snapshot_fd >= 0:
            os.close(snapshot_fd)
        if source_fd >= 0:
            os.close(source_fd)


def provision(
    paths: ProvisionPaths,
    *,
    expected_root_uid: int,
    expected_root_gid: int,
    log_uid: int,
    log_gid: int,
    logrotate_command: Sequence[str],
    platform_log_parent_gids: frozenset[int] | None = None,
) -> None:
    validate_leaf_name(paths.rotation_name, label="logrotate policy name")
    validate_leaf_name(paths.log_name, label="dedicated Nginx access log name")
    pthread_sigmask = getattr(signal, "pthread_sigmask", None)
    if not callable(pthread_sigmask):
        raise ProvisionError(
            "transactional signal masking is unavailable; refusing to mutate host state"
        )
    blocked_signals = {
        candidate
        for candidate in (
            signal.SIGINT,
            signal.SIGTERM,
            signal.SIGHUP,
            signal.SIGQUIT,
        )
        if candidate in signal.valid_signals()
    }
    previous_mask = pthread_sigmask(signal.SIG_BLOCK, blocked_signals)
    try:
        _provision_blocked(
            paths,
            expected_root_uid=expected_root_uid,
            expected_root_gid=expected_root_gid,
            log_uid=log_uid,
            log_gid=log_gid,
            logrotate_command=logrotate_command,
            platform_log_parent_gids=platform_log_parent_gids,
        )
    finally:
        pthread_sigmask(signal.SIG_SETMASK, previous_mask)


def main() -> int:
    if os.geteuid() != 0:
        raise ProvisionError("must run as root")
    script_path = pathlib.Path(os.path.abspath(__file__))
    script_dir = script_path.parent
    repo_root = script_dir.parent.parent
    verify_privileged_runtime(repo_root, script_path)
    logrotate = pathlib.Path("/usr/sbin/logrotate")
    verify_trusted_ancestors(logrotate, expected_uid=0, expected_gid=0)
    verify_trusted_file(
        logrotate,
        expected_uid=0,
        expected_gid=0,
        expected_mode=0o755,
    )
    paths = ProvisionPaths(
        rotation_source=repo_root / "deploy/nginx/codex-control-access.logrotate",
        rotation_directory=pathlib.Path("/etc/logrotate.d"),
        rotation_name="codex-control-access",
        log_directory=pathlib.Path("/var/log/sub2api-codex-control"),
        log_name="nginx-access.log",
    )
    allowed_log_parent_gids = {0}
    try:
        allowed_log_parent_gids.add(grp.getgrnam("syslog").gr_gid)
    except KeyError:
        pass
    provision(
        paths,
        expected_root_uid=0,
        expected_root_gid=0,
        log_uid=pwd.getpwnam("www-data").pw_uid,
        log_gid=grp.getgrnam("adm").gr_gid,
        logrotate_command=(str(logrotate),),
        platform_log_parent_gids=frozenset(allowed_log_parent_gids),
    )
    print(f"Provisioned {paths.log_path} and {paths.rotation_target}.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ProvisionError, KeyError) as error:
        print(f"provision-nginx-access-log: {error}", file=sys.stderr)
        raise SystemExit(1) from None
