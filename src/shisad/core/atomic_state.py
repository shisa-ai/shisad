"""Restrictive same-directory atomic publication for small state snapshots."""

from __future__ import annotations

import contextlib
import errno
import hashlib
import hmac
import json
import os
import stat
import uuid
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any, BinaryIO


class AtomicWriteStage(StrEnum):
    """Observable publication boundaries used by typed errors and fault tests."""

    TARGET_VALIDATE = "target_validate"
    DIRECTORY_PREPARE = "directory_prepare"
    TEMP_OPEN = "temp_open"
    WRITE = "write"
    FILE_FSYNC = "file_fsync"
    REPLACE = "replace"
    PARENT_FSYNC = "parent_fsync"
    CLEANUP = "cleanup"


AtomicWriteFaultInjector = Callable[[AtomicWriteStage], None]


class DurableAppendStage(StrEnum):
    """Observable boundaries for owner-only append publication."""

    TARGET_VALIDATE = "target_validate"
    DIRECTORY_PREPARE = "directory_prepare"
    FILE_OPEN = "file_open"
    WRITE = "write"
    FILE_FSYNC = "file_fsync"
    PARENT_FSYNC = "parent_fsync"


DurableAppendFaultInjector = Callable[[DurableAppendStage], None]


class StateLoadStatus(StrEnum):
    """Finite load outcomes for security-relevant state snapshots."""

    OK = "ok"
    MISSING = "missing"
    CORRUPT = "corrupt"
    UNSUPPORTED_SCHEMA = "unsupported_schema"


@dataclass(frozen=True, slots=True)
class StateLoadResult:
    """Typed snapshot load status without discarding the original bytes."""

    status: StateLoadStatus
    reason: str = ""
    schema_version: int | None = None
    legacy: bool = False


class AtomicWriteError(RuntimeError):
    """State publication failed at a known durability boundary."""

    def __init__(
        self,
        *,
        path: Path,
        stage: AtomicWriteStage,
        publication_may_have_committed: bool,
    ) -> None:
        self.path = path
        self.stage = stage
        self.publication_may_have_committed = publication_may_have_committed
        commitment = "commit uncertain" if publication_may_have_committed else "not committed"
        super().__init__(f"atomic state write failed at {stage.value} ({commitment}): {path}")


class DurableAppendError(RuntimeError):
    """Append publication failed at a known durability boundary."""

    def __init__(
        self,
        *,
        path: Path,
        stage: DurableAppendStage,
        publication_may_have_committed: bool,
        authority_changed: bool = False,
    ) -> None:
        self.path = path
        self.stage = stage
        self.publication_may_have_committed = publication_may_have_committed
        self.authority_changed = authority_changed
        commitment = "commit uncertain" if publication_may_have_committed else "not committed"
        super().__init__(f"durable append failed at {stage.value} ({commitment}): {path}")


class StatePersistenceDegradedError(RuntimeError):
    """A state authority is blocked until explicit process recovery."""

    def __init__(
        self,
        *,
        authority: str,
        transition: str,
        stage: str,
        reason: str,
    ) -> None:
        self.authority = authority
        self.transition = transition
        self.stage = stage
        self.reason = reason
        super().__init__(
            f"{authority} persistence is degraded: transition={transition} "
            f"stage={stage} reason={reason}"
        )


def _absolute_normalized_path(path: Path) -> Path:
    return Path(os.path.abspath(os.fspath(path)))


def _directory_open_flags() -> int:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    return flags | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)


def _open_directory_chain(
    path: Path,
    *,
    create: bool,
    require_safe_ancestry: bool = False,
) -> tuple[Path, int, list[Path]]:
    """Descriptor-walk *path* without following any directory symlink."""

    absolute = _absolute_normalized_path(path)
    components = absolute.parts[1:]
    current = Path(absolute.anchor)
    current_fd = os.open(current, _directory_open_flags())
    created_directories: list[Path] = []
    creation_boundary = False
    try:
        for component in components:
            current /= component
            created = False
            try:
                next_fd = os.open(component, _directory_open_flags(), dir_fd=current_fd)
            except FileNotFoundError:
                if not create:
                    raise
                creation_boundary = True
                try:
                    os.mkdir(component, 0o700, dir_fd=current_fd)
                    created = True
                except FileExistsError:
                    pass
                try:
                    next_fd = os.open(component, _directory_open_flags(), dir_fd=current_fd)
                except OSError as exc:
                    raise OSError(
                        errno.ELOOP,
                        f"state path cannot be opened without symlink traversal: {current}",
                    ) from exc
            except OSError as exc:
                if exc.errno in {errno.ELOOP, errno.ENOTDIR}:
                    raise OSError(
                        errno.ELOOP,
                        f"state path has symlink or non-directory ancestry: {current}",
                    ) from exc
                raise
            current_stat = os.fstat(next_fd)
            try:
                if not stat.S_ISDIR(current_stat.st_mode):
                    raise OSError(f"state path ancestor is not a directory: {current}")
                if require_safe_ancestry:
                    owner_uid = current_stat.st_uid
                    if owner_uid not in {0, os.geteuid()}:
                        raise PermissionError(f"unsafe parent ancestry is foreign-owned: {current}")
                    if current_stat.st_mode & 0o022:
                        shared_sticky_ancestor = (
                            owner_uid == 0
                            and bool(current_stat.st_mode & stat.S_ISVTX)
                            and current != absolute
                        )
                        if not shared_sticky_ancestor:
                            raise PermissionError(
                                f"unsafe parent ancestry is writable by another uid: {current}"
                            )
                if creation_boundary and current_stat.st_uid != os.geteuid():
                    raise PermissionError(
                        f"created state ancestry is not owner-controlled: {current}"
                    )
                if creation_boundary and current_stat.st_mode & 0o022:
                    raise PermissionError(
                        f"created state ancestry is writable by another uid: {current}"
                    )
                if created:
                    os.fchmod(next_fd, 0o700)
                    os.fsync(next_fd)
                    os.fsync(current_fd)
                    created_directories.append(current)
            except BaseException:
                os.close(next_fd)
                raise
            os.close(current_fd)
            current_fd = next_fd
        return absolute, current_fd, created_directories
    except BaseException:
        os.close(current_fd)
        raise


def validate_directory_ancestry(path: Path) -> bool:
    """Return whether *path* exists as a no-follow directory chain.

    Missing paths are valid for later secure creation. Symlinked or
    non-directory ancestry raises ``OSError`` instead of being treated as
    missing authority.
    """

    directory_fd = -1
    try:
        _absolute, directory_fd, _created = _open_directory_chain(path, create=False)
    except FileNotFoundError:
        return False
    finally:
        if directory_fd >= 0:
            os.close(directory_fd)
    return True


def ensure_owner_only_directory(path: Path) -> None:
    """Securely create/admit a directory and restrict its final inode to 0700."""

    absolute, directory_fd, _created = _open_directory_chain(path, create=True)
    try:
        directory_stat = os.fstat(directory_fd)
        if directory_stat.st_uid != os.geteuid():
            raise PermissionError(f"state directory is not owner-controlled: {absolute}")
        os.fchmod(directory_fd, 0o700)
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def _remove_directory_fd_contents(
    directory_fd: int,
    *,
    allow_nested_directories: bool,
    root_device: int,
) -> int:
    entries: list[tuple[str, os.stat_result]] = []
    for name in os.listdir(directory_fd):
        entry_stat = os.stat(
            name,
            dir_fd=directory_fd,
            follow_symlinks=False,
        )
        if stat.S_ISDIR(entry_stat.st_mode) and not allow_nested_directories:
            raise OSError(f"state reset refuses unexpected nested directory: {name}")
        entries.append((name, entry_stat))

    removed = 0
    for name, entry_stat in entries:
        if stat.S_ISDIR(entry_stat.st_mode):
            child_fd = os.open(name, _directory_open_flags(), dir_fd=directory_fd)
            try:
                child_stat = os.fstat(child_fd)
                if (child_stat.st_dev, child_stat.st_ino) != (
                    entry_stat.st_dev,
                    entry_stat.st_ino,
                ):
                    raise OSError(f"state reset directory identity changed: {name}")
                if child_stat.st_dev != root_device:
                    raise OSError(f"state reset refuses a nested mount: {name}")
                removed += _remove_directory_fd_contents(
                    child_fd,
                    allow_nested_directories=True,
                    root_device=root_device,
                )
            finally:
                os.close(child_fd)
            os.rmdir(name, dir_fd=directory_fd)
        else:
            os.unlink(name, dir_fd=directory_fd)
        removed += 1
    if entries:
        os.fsync(directory_fd)
    return removed


def remove_owner_controlled_directory_contents(
    path: Path,
    *,
    allow_nested_directories: bool,
    unlink_non_directory: bool = False,
) -> int:
    """Delete a state domain through held no-follow directory descriptors."""

    absolute = _absolute_normalized_path(path)
    parent_fd = -1
    target_fd = -1
    try:
        try:
            _absolute, parent_fd, _created = _open_directory_chain(
                absolute.parent,
                create=False,
            )
        except FileNotFoundError:
            return 0
        try:
            target_stat = os.stat(
                absolute.name,
                dir_fd=parent_fd,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            return 0
        if target_stat.st_uid != os.geteuid():
            raise PermissionError(f"state reset target is not owner-controlled: {absolute}")
        if not stat.S_ISDIR(target_stat.st_mode):
            if not unlink_non_directory:
                raise OSError(f"state reset target is a symlink or not a directory: {absolute}")
            os.unlink(absolute.name, dir_fd=parent_fd)
            os.fsync(parent_fd)
            return 1

        target_fd = os.open(
            absolute.name,
            _directory_open_flags(),
            dir_fd=parent_fd,
        )
        opened_stat = os.fstat(target_fd)
        if (opened_stat.st_dev, opened_stat.st_ino) != (
            target_stat.st_dev,
            target_stat.st_ino,
        ):
            raise OSError(f"state reset target identity changed: {absolute}")
        if opened_stat.st_uid != os.geteuid():
            raise PermissionError(f"state reset target is not owner-controlled: {absolute}")
        return _remove_directory_fd_contents(
            target_fd,
            allow_nested_directories=allow_nested_directories,
            root_device=opened_stat.st_dev,
        )
    finally:
        if target_fd >= 0:
            os.close(target_fd)
        if parent_fd >= 0:
            os.close(parent_fd)


def remove_owner_controlled_file_entries(
    directory: Path,
    names: tuple[str, ...],
    *,
    expected_directory_identity: tuple[int, int] | None = None,
) -> int:
    """Remove selected non-directory entries through one verified directory fd."""

    for name in names:
        if not name or Path(name).name != name or name in {".", ".."}:
            raise ValueError("state reset names must be single path components")
    absolute = _absolute_normalized_path(directory)
    directory_fd = -1
    try:
        _absolute, directory_fd, _created = _open_directory_chain(
            absolute,
            create=False,
        )
        directory_stat = os.fstat(directory_fd)
        directory_identity = (directory_stat.st_dev, directory_stat.st_ino)
        if (
            expected_directory_identity is not None
            and directory_identity != expected_directory_identity
        ):
            raise OSError(f"state reset directory identity changed: {absolute}")
        removed = 0
        for name in names:
            try:
                entry_stat = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            except FileNotFoundError:
                continue
            if stat.S_ISDIR(entry_stat.st_mode):
                raise OSError(f"state reset refuses directory entry: {absolute / name}")
            os.unlink(name, dir_fd=directory_fd)
            removed += 1
        if removed:
            os.fsync(directory_fd)
        _verify_directory_path_identity(absolute, expected=directory_identity)
        return removed
    finally:
        if directory_fd >= 0:
            os.close(directory_fd)


def _validate_sibling_cleanup_prefix(name_prefix: str) -> None:
    if not name_prefix or Path(name_prefix).name != name_prefix:
        raise ValueError("sibling cleanup prefix must be one path component")


def _remove_sibling_entries_fd(parent_fd: int, *, name_prefix: str) -> int:
    matches: list[str] = []
    for name in os.listdir(parent_fd):
        if not name.startswith(name_prefix):
            continue
        entry_stat = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if stat.S_ISDIR(entry_stat.st_mode):
            raise OSError(f"state cleanup refuses matching directory: {name}")
        matches.append(name)
    for name in matches:
        os.unlink(name, dir_fd=parent_fd)
    if matches:
        os.fsync(parent_fd)
    return len(matches)


def _verify_directory_path_identity(
    path: Path,
    *,
    expected: tuple[int, int],
    require_safe_ancestry: bool = False,
) -> None:
    current_fd = -1
    try:
        _absolute, current_fd, _created = _open_directory_chain(
            path,
            create=False,
            require_safe_ancestry=require_safe_ancestry,
        )
        current_stat = os.fstat(current_fd)
        if (current_stat.st_dev, current_stat.st_ino) != expected:
            raise OSError(f"state cleanup parent identity changed: {path}")
    finally:
        if current_fd >= 0:
            os.close(current_fd)


def validate_owner_controlled_parent_ancestry(path: Path) -> None:
    """Require existing file-parent ancestry to be safe for external authority."""

    parent_fd = -1
    try:
        try:
            _absolute, parent_fd, _created = _open_directory_chain(
                _absolute_normalized_path(path).parent,
                create=False,
                require_safe_ancestry=True,
            )
        except FileNotFoundError:
            return
    finally:
        if parent_fd >= 0:
            os.close(parent_fd)


@contextlib.contextmanager
def open_owned_regular_file(
    path: Path,
    *,
    required_mode: int | None = None,
    normalize_mode: int | None = None,
    unlink_on_success: bool = False,
) -> Iterator[BinaryIO | None]:
    """Open an owner-controlled regular file through a no-follow parent.

    When ``unlink_on_success`` is set, remove only the exact opened inode through
    the held parent descriptor after the context body returns successfully.
    """

    absolute = _absolute_normalized_path(path)
    parent_fd = -1
    file_fd = -1
    handle: BinaryIO | None = None
    parent_identity = (-1, -1)
    file_identity = (-1, -1)
    try:
        try:
            _absolute, parent_fd, _created = _open_directory_chain(
                absolute.parent,
                create=False,
            )
        except FileNotFoundError:
            yield None
            return
        parent_stat = os.fstat(parent_fd)
        parent_identity = (parent_stat.st_dev, parent_stat.st_ino)
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        try:
            file_fd = os.open(absolute.name, flags, dir_fd=parent_fd)
        except FileNotFoundError:
            yield None
            return
        file_stat = os.fstat(file_fd)
        if not stat.S_ISREG(file_stat.st_mode):
            raise OSError(f"state target is not a regular file: {absolute}")
        if file_stat.st_uid != os.geteuid():
            raise PermissionError(f"state target is not owner-controlled: {absolute}")
        if file_stat.st_nlink != 1:
            raise PermissionError(f"state target must have exactly one link: {absolute}")
        file_identity = (file_stat.st_dev, file_stat.st_ino)
        if required_mode is not None and stat.S_IMODE(file_stat.st_mode) != required_mode:
            raise PermissionError(
                f"state target must have mode {required_mode:04o}: {absolute} "
                f"has {stat.S_IMODE(file_stat.st_mode):04o}"
            )
        if normalize_mode is not None:
            os.fchmod(file_fd, normalize_mode)
        handle = os.fdopen(file_fd, "rb", closefd=True)
        file_fd = -1
        yield handle
        if unlink_on_success:
            current_stat = os.stat(
                absolute.name,
                dir_fd=parent_fd,
                follow_symlinks=False,
            )
            if (current_stat.st_dev, current_stat.st_ino) != file_identity:
                raise OSError(f"state target identity changed: {absolute}")
            os.unlink(absolute.name, dir_fd=parent_fd)
            os.fsync(parent_fd)
            _verify_directory_path_identity(absolute.parent, expected=parent_identity)
    finally:
        if handle is not None:
            handle.close()
        if file_fd >= 0:
            os.close(file_fd)
        if parent_fd >= 0:
            os.close(parent_fd)


def read_owned_regular_file(
    path: Path,
    *,
    required_mode: int | None = None,
    normalize_mode: int | None = None,
    max_bytes: int | None = None,
) -> bytes | None:
    """Read an existing owner-controlled regular file through a no-follow parent."""

    with open_owned_regular_file(
        path,
        required_mode=required_mode,
        normalize_mode=normalize_mode,
    ) as handle:
        if handle is None:
            return None
        chunks: list[bytes] = []
        bytes_read = 0
        while max_bytes is None or bytes_read < max_bytes:
            remaining = None if max_bytes is None else max_bytes - bytes_read
            read_size = 1024 * 1024 if remaining is None else min(1024 * 1024, remaining)
            if not (chunk := handle.read(read_size)):
                break
            chunks.append(chunk)
            bytes_read += len(chunk)
        return b"".join(chunks)


def read_owner_only_regular_file(path: Path) -> bytes | None:
    """Read an existing mode-0600 owner-controlled regular file."""

    return read_owned_regular_file(path, required_mode=0o600)


def _fsync_directory_path(path: Path) -> None:
    _absolute, fd, _created = _open_directory_chain(path, create=False)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _inject_fault(
    fault_injector: AtomicWriteFaultInjector | None,
    stage: AtomicWriteStage,
) -> None:
    if fault_injector is not None:
        fault_injector(stage)


def _validate_existing_target(path: Path) -> None:
    try:
        target_stat = path.lstat()
    except FileNotFoundError:
        return
    except OSError as exc:
        raise AtomicWriteError(
            path=path,
            stage=AtomicWriteStage.TARGET_VALIDATE,
            publication_may_have_committed=False,
        ) from exc
    if not stat.S_ISREG(target_stat.st_mode):
        raise AtomicWriteError(
            path=path,
            stage=AtomicWriteStage.TARGET_VALIDATE,
            publication_may_have_committed=False,
        )


def _canonical_json_bytes(payload: Any) -> bytes:
    return json.dumps(
        payload,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _snapshot_integrity_bytes(*, version: int, payload: Any) -> bytes:
    return _canonical_json_bytes({"payload": payload, "version": version})


def encode_versioned_json_snapshot(payload: Any, *, version: int = 1) -> bytes:
    """Encode a deterministic checksum-bound JSON snapshot envelope."""

    if isinstance(version, bool) or not isinstance(version, int) or version < 1:
        raise ValueError("snapshot version must be a positive integer")
    checksum = hashlib.sha256(
        _snapshot_integrity_bytes(version=version, payload=payload)
    ).hexdigest()
    envelope = {
        "version": version,
        "checksum": checksum,
        "payload": payload,
    }
    return (
        json.dumps(
            envelope,
            allow_nan=False,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")


def decode_versioned_json_snapshot(
    raw_bytes: bytes,
    *,
    supported_version: int = 1,
) -> tuple[StateLoadResult, Any | None]:
    """Decode a checksum-bound envelope into a typed non-throwing load result."""

    try:
        raw = json.loads(raw_bytes.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError, RecursionError):
        return StateLoadResult(StateLoadStatus.CORRUPT, reason="invalid_json"), None
    if not isinstance(raw, dict):
        return StateLoadResult(StateLoadStatus.CORRUPT, reason="invalid_envelope"), None
    version = raw.get("version")
    if isinstance(version, bool) or not isinstance(version, int) or version < 1:
        return StateLoadResult(StateLoadStatus.CORRUPT, reason="invalid_schema_version"), None
    if version != supported_version:
        return (
            StateLoadResult(
                StateLoadStatus.UNSUPPORTED_SCHEMA,
                reason="unsupported_schema",
                schema_version=version,
            ),
            None,
        )
    checksum = raw.get("checksum")
    if not isinstance(checksum, str) or not checksum:
        return (
            StateLoadResult(
                StateLoadStatus.CORRUPT,
                reason="missing_checksum",
                schema_version=version,
            ),
            None,
        )
    if "payload" not in raw:
        return (
            StateLoadResult(
                StateLoadStatus.CORRUPT,
                reason="missing_payload",
                schema_version=version,
            ),
            None,
        )
    payload = raw["payload"]
    try:
        integrity_input = _snapshot_integrity_bytes(version=version, payload=payload)
    except (TypeError, ValueError, RecursionError):
        return (
            StateLoadResult(
                StateLoadStatus.CORRUPT,
                reason="invalid_payload",
                schema_version=version,
            ),
            None,
        )
    if not checksum.isascii():
        return (
            StateLoadResult(
                StateLoadStatus.CORRUPT,
                reason="invalid_checksum",
                schema_version=version,
            ),
            None,
        )
    actual_checksum = hashlib.sha256(integrity_input).hexdigest()
    if not hmac.compare_digest(checksum, actual_checksum):
        return (
            StateLoadResult(
                StateLoadStatus.CORRUPT,
                reason="checksum_mismatch",
                schema_version=version,
            ),
            None,
        )
    return (
        StateLoadResult(StateLoadStatus.OK, schema_version=version),
        payload,
    )


def _atomic_write_bytes(
    path: Path,
    payload: bytes,
    *,
    fault_injector: AtomicWriteFaultInjector | None = None,
    preserve_existing_parent_mode: bool = False,
    require_safe_parent_ancestry: bool = False,
    cleanup_sibling_prefix: str | None = None,
) -> tuple[int, tuple[int, int]]:
    """Publish owner-only bytes and return cleanup count plus exact identity.

    Existing daemon-owned parents are restricted by default. Arbitrary-path
    callers may preserve an existing parent mode; newly created parents remain
    owner-only. Optional sibling cleanup shares the publication's held parent
    descriptor and returns the number of removed entries.
    """

    if cleanup_sibling_prefix is not None:
        _validate_sibling_cleanup_prefix(cleanup_sibling_prefix)
    target = Path(path)
    _validate_existing_target(target)
    absolute_target = _absolute_normalized_path(target)
    parent = absolute_target.parent
    target_name = absolute_target.name
    missing_directories: list[Path] = []
    parent_fd = -1
    parent_identity = (-1, -1)
    try:
        _absolute_parent, parent_fd, created_directories = _open_directory_chain(
            parent,
            create=True,
            require_safe_ancestry=require_safe_parent_ancestry,
        )
        missing_directories = list(reversed(created_directories))
        try:
            target_stat = os.stat(target_name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            target_stat = None
        if target_stat is not None and not stat.S_ISREG(target_stat.st_mode):
            raise AtomicWriteError(
                path=target,
                stage=AtomicWriteStage.TARGET_VALIDATE,
                publication_may_have_committed=False,
            )
        if not preserve_existing_parent_mode or missing_directories:
            parent_stat = os.fstat(parent_fd)
            if parent_stat.st_uid != os.geteuid():
                raise PermissionError(f"state parent is not owner-controlled: {parent}")
            os.fchmod(parent_fd, 0o700)
        parent_stat = os.fstat(parent_fd)
        parent_identity = (parent_stat.st_dev, parent_stat.st_ino)
    except AtomicWriteError:
        if parent_fd >= 0:
            os.close(parent_fd)
        raise
    except OSError as exc:
        if parent_fd >= 0:
            os.close(parent_fd)
        raise AtomicWriteError(
            path=target,
            stage=AtomicWriteStage.DIRECTORY_PREPARE,
            publication_may_have_committed=False,
        ) from exc

    temp_name = f".{target_name}.{uuid.uuid4().hex}.tmp"
    file_fd = -1
    replaced = False
    removed_siblings = 0
    published_identity = (-1, -1)
    stage = AtomicWriteStage.TEMP_OPEN
    try:
        _inject_fault(fault_injector, stage)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        flags |= getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        file_fd = os.open(temp_name, flags, 0o600, dir_fd=parent_fd)
        os.fchmod(file_fd, 0o600)
        temp_stat = os.fstat(file_fd)
        published_identity = (temp_stat.st_dev, temp_stat.st_ino)

        stage = AtomicWriteStage.WRITE
        _inject_fault(fault_injector, stage)
        remaining = memoryview(payload)
        while remaining:
            written = os.write(file_fd, remaining)
            if written <= 0:
                raise OSError("atomic state write made no progress")
            remaining = remaining[written:]

        stage = AtomicWriteStage.FILE_FSYNC
        _inject_fault(fault_injector, stage)
        os.fsync(file_fd)
        os.close(file_fd)
        file_fd = -1

        stage = AtomicWriteStage.REPLACE
        _inject_fault(fault_injector, stage)
        os.replace(
            temp_name,
            target_name,
            src_dir_fd=parent_fd,
            dst_dir_fd=parent_fd,
        )
        replaced = True

        stage = AtomicWriteStage.PARENT_FSYNC
        _inject_fault(fault_injector, stage)
        os.fsync(parent_fd)
        for created_directory in reversed(missing_directories):
            _fsync_directory_path(created_directory.parent)
        if cleanup_sibling_prefix is not None:
            stage = AtomicWriteStage.CLEANUP
            _inject_fault(fault_injector, stage)
            removed_siblings = _remove_sibling_entries_fd(
                parent_fd,
                name_prefix=cleanup_sibling_prefix,
            )
        published_stat = os.stat(
            target_name,
            dir_fd=parent_fd,
            follow_symlinks=False,
        )
        if (
            published_identity != (published_stat.st_dev, published_stat.st_ino)
            or not stat.S_ISREG(published_stat.st_mode)
            or published_stat.st_uid != os.geteuid()
            or published_stat.st_nlink != 1
            or stat.S_IMODE(published_stat.st_mode) != 0o600
        ):
            raise OSError("atomic write target identity changed before acknowledgement")
        _verify_directory_path_identity(
            parent,
            expected=parent_identity,
            require_safe_ancestry=require_safe_parent_ancestry,
        )
    except AtomicWriteError:
        raise
    except OSError as exc:
        raise AtomicWriteError(
            path=target,
            stage=stage,
            publication_may_have_committed=replaced,
        ) from exc
    finally:
        if file_fd >= 0:
            with contextlib.suppress(OSError):
                os.close(file_fd)
        if not replaced:
            with contextlib.suppress(OSError):
                os.unlink(temp_name, dir_fd=parent_fd)
        os.close(parent_fd)
    return removed_siblings, published_identity


def atomic_write_bytes(
    path: Path,
    payload: bytes,
    *,
    fault_injector: AtomicWriteFaultInjector | None = None,
    preserve_existing_parent_mode: bool = False,
    require_safe_parent_ancestry: bool = False,
    cleanup_sibling_prefix: str | None = None,
) -> int:
    """Publish owner-only bytes old-or-new and fsync the containing directory.

    Existing daemon-owned parents are restricted by default. Arbitrary-path
    callers may preserve an existing parent mode; newly created parents remain
    owner-only. Optional sibling cleanup shares the publication's held parent
    descriptor and returns the number of removed entries.
    """

    removed_siblings, _published_identity = _atomic_write_bytes(
        path,
        payload,
        fault_injector=fault_injector,
        preserve_existing_parent_mode=preserve_existing_parent_mode,
        require_safe_parent_ancestry=require_safe_parent_ancestry,
        cleanup_sibling_prefix=cleanup_sibling_prefix,
    )
    return removed_siblings


def atomic_write_bytes_with_identity(
    path: Path,
    payload: bytes,
    *,
    fault_injector: AtomicWriteFaultInjector | None = None,
    preserve_existing_parent_mode: bool = False,
    require_safe_parent_ancestry: bool = False,
    cleanup_sibling_prefix: str | None = None,
) -> tuple[int, int]:
    """Publish owner-only bytes and return the exact acknowledged file identity."""

    _removed_siblings, published_identity = _atomic_write_bytes(
        path,
        payload,
        fault_injector=fault_injector,
        preserve_existing_parent_mode=preserve_existing_parent_mode,
        require_safe_parent_ancestry=require_safe_parent_ancestry,
        cleanup_sibling_prefix=cleanup_sibling_prefix,
    )
    return published_identity


def durable_append_bytes(
    path: Path,
    payload: bytes,
    *,
    fault_injector: DurableAppendFaultInjector | None = None,
    expected_identity: tuple[int, int] | None = None,
    require_missing: bool = False,
) -> tuple[int, int]:
    """Append owner-only bytes, returning the exact acknowledged file identity.

    The containing directory is fsynced before every acknowledgement, including
    retries that may be recovering a first publication. Append failures after
    any byte is written are typed as commit-uncertain; the caller must not assume
    it is safe to retry an effect-bearing record. When ``expected_identity`` is
    provided, reject a different opened inode before writing. When
    ``require_missing`` is true, atomically create a new authority rather than
    adopting a file that appeared after an earlier absence observation.
    """

    if expected_identity is not None and require_missing:
        raise ValueError("expected_identity and require_missing are mutually exclusive")

    target = Path(path)
    absolute_target = _absolute_normalized_path(target)
    parent = absolute_target.parent
    target_name = absolute_target.name
    target_existed = False
    parent_fd = -1
    try:
        preliminary_stat = target.lstat()
    except FileNotFoundError as exc:
        if expected_identity is not None:
            raise DurableAppendError(
                path=target,
                stage=DurableAppendStage.TARGET_VALIDATE,
                publication_may_have_committed=False,
                authority_changed=True,
            ) from exc
    except OSError as exc:
        raise DurableAppendError(
            path=target,
            stage=DurableAppendStage.TARGET_VALIDATE,
            publication_may_have_committed=False,
        ) from exc
    else:
        if require_missing:
            raise DurableAppendError(
                path=target,
                stage=DurableAppendStage.TARGET_VALIDATE,
                publication_may_have_committed=False,
                authority_changed=True,
            )
        if not stat.S_ISREG(preliminary_stat.st_mode):
            raise DurableAppendError(
                path=target,
                stage=DurableAppendStage.TARGET_VALIDATE,
                publication_may_have_committed=False,
                authority_changed=expected_identity is not None,
            )

    try:
        if fault_injector is not None:
            fault_injector(DurableAppendStage.DIRECTORY_PREPARE)
        _absolute_parent, parent_fd, created_directories = _open_directory_chain(
            parent,
            create=True,
        )
    except OSError as exc:
        if parent_fd >= 0:
            os.close(parent_fd)
        raise DurableAppendError(
            path=target,
            stage=DurableAppendStage.DIRECTORY_PREPARE,
            publication_may_have_committed=False,
        ) from exc

    try:
        try:
            target_stat = os.stat(target_name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            target_stat = None
        if target_stat is None:
            if expected_identity is not None:
                raise DurableAppendError(
                    path=target,
                    stage=DurableAppendStage.TARGET_VALIDATE,
                    publication_may_have_committed=False,
                    authority_changed=True,
                )
        elif require_missing:
            raise DurableAppendError(
                path=target,
                stage=DurableAppendStage.TARGET_VALIDATE,
                publication_may_have_committed=False,
                authority_changed=True,
            )
        elif not stat.S_ISREG(target_stat.st_mode):
            raise DurableAppendError(
                path=target,
                stage=DurableAppendStage.TARGET_VALIDATE,
                publication_may_have_committed=False,
                authority_changed=expected_identity is not None,
            )
        else:
            target_existed = True
    except DurableAppendError:
        os.close(parent_fd)
        raise
    except OSError as exc:
        os.close(parent_fd)
        raise DurableAppendError(
            path=target,
            stage=DurableAppendStage.TARGET_VALIDATE,
            publication_may_have_committed=False,
        ) from exc
    missing_directories = list(reversed(created_directories))
    parent_identity = (-1, -1)
    try:
        parent_stat = os.fstat(parent_fd)
        if parent_stat.st_uid != os.geteuid():
            raise PermissionError(f"state parent is not owner-controlled: {parent}")
        os.fchmod(parent_fd, 0o700)
        parent_identity = (parent_stat.st_dev, parent_stat.st_ino)
    except OSError as exc:
        os.close(parent_fd)
        raise DurableAppendError(
            path=target,
            stage=DurableAppendStage.DIRECTORY_PREPARE,
            publication_may_have_committed=False,
        ) from exc

    file_fd = -1
    created_file = False
    wrote_payload = False
    completed = False
    authority_changed = False
    opened_identity: tuple[int, int] | None = None
    stage = DurableAppendStage.FILE_OPEN
    try:
        if fault_injector is not None:
            fault_injector(stage)
        flags = os.O_WRONLY | os.O_APPEND
        if require_missing or not target_existed:
            flags |= os.O_CREAT | os.O_EXCL
        flags |= getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        try:
            file_fd = os.open(target_name, flags, 0o600, dir_fd=parent_fd)
        except FileExistsError:
            authority_changed = require_missing
            raise
        except OSError:
            authority_changed = expected_identity is not None
            raise
        created_file = not target_existed
        opened_stat = os.fstat(file_fd)
        if not stat.S_ISREG(opened_stat.st_mode):
            authority_changed = expected_identity is not None
            raise OSError("durable append target is not a regular file")
        if opened_stat.st_uid != os.geteuid():
            authority_changed = expected_identity is not None
            raise PermissionError("durable append target is not owner-controlled")
        if opened_stat.st_nlink != 1:
            authority_changed = expected_identity is not None
            raise PermissionError("durable append target must have exactly one link")
        opened_identity = (opened_stat.st_dev, opened_stat.st_ino)
        if expected_identity is not None and opened_identity != expected_identity:
            authority_changed = True
            raise PermissionError("durable append target identity changed")
        os.fchmod(file_fd, 0o600)

        stage = DurableAppendStage.WRITE
        if fault_injector is not None:
            fault_injector(stage)
        remaining = memoryview(payload)
        while remaining:
            written = os.write(file_fd, remaining)
            if written <= 0:
                raise OSError("durable append made no progress")
            wrote_payload = True
            remaining = remaining[written:]

        stage = DurableAppendStage.FILE_FSYNC
        if fault_injector is not None:
            fault_injector(stage)
        os.fsync(file_fd)

        stage = DurableAppendStage.PARENT_FSYNC
        if fault_injector is not None:
            fault_injector(stage)
        os.fsync(parent_fd)
        for created_directory in reversed(missing_directories):
            _fsync_directory_path(created_directory.parent)
        try:
            published_stat = os.stat(
                target_name,
                dir_fd=parent_fd,
                follow_symlinks=False,
            )
        except OSError:
            authority_changed = True
            raise
        if (
            opened_identity != (published_stat.st_dev, published_stat.st_ino)
            or not stat.S_ISREG(published_stat.st_mode)
            or published_stat.st_uid != os.geteuid()
            or published_stat.st_nlink != 1
            or stat.S_IMODE(published_stat.st_mode) != 0o600
        ):
            authority_changed = True
            raise OSError("durable append target identity changed before acknowledgement")
        _verify_directory_path_identity(parent, expected=parent_identity)
        completed = True
    except DurableAppendError:
        raise
    except OSError as exc:
        raise DurableAppendError(
            path=target,
            stage=stage,
            publication_may_have_committed=wrote_payload,
            authority_changed=authority_changed,
        ) from exc
    finally:
        if file_fd >= 0:
            with contextlib.suppress(OSError):
                os.close(file_fd)
        if created_file and not wrote_payload and not completed:
            current_stat: os.stat_result | None
            try:
                current_stat = os.stat(
                    target_name,
                    dir_fd=parent_fd,
                    follow_symlinks=False,
                )
            except OSError:
                current_stat = None
            if current_stat is not None and opened_identity == (
                current_stat.st_dev,
                current_stat.st_ino,
            ):
                with contextlib.suppress(OSError):
                    os.unlink(target_name, dir_fd=parent_fd)
            with contextlib.suppress(OSError):
                os.fsync(parent_fd)
        os.close(parent_fd)
    if opened_identity is None:
        raise AssertionError("durable append completed without an opened identity")
    return opened_identity
