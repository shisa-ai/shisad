"""Platform-neutral rooted-directory interface and POSIX implementation."""

from __future__ import annotations

import errno
import os
import stat
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from types import TracebackType
from typing import TYPE_CHECKING, Any, Self

Identity = tuple[int, int]
_ROOT = PurePosixPath(".")
_POSIX_REQUIRED_DIR_FD = (os.open, os.stat, os.mkdir, os.unlink, os.rmdir, os.link)


class RootHandleError(RuntimeError):
    """A rooted filesystem operation was unavailable or became unsafe."""


class RootHandleNotFound(RootHandleError):
    """A direct rooted child did not exist."""


@dataclass(frozen=True, slots=True)
class EntryMetadata:
    """Stable fields used to revalidate one rooted entry."""

    identity: Identity
    mode: int
    size: int
    mtime_ns: int
    is_directory: bool


class _RootContext:
    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        _exc_type: type[BaseException] | None,
        _exc_value: BaseException | None,
        _traceback: TracebackType | None,
    ) -> None:
        self.close()

    def close(self) -> None:
        raise NotImplementedError


def open_root(path: Path, *, expected_identity: Identity | None = None) -> RootHandle:
    """Open a non-link directory with a fail-closed supported backend."""

    if os.name == "nt":
        from shisad.core.data_root_windows import open_windows_root

        return open_windows_root(Path(path), expected_identity)
    if os.name != "posix":
        raise RootHandleError("root-relative filesystem operations are unavailable")
    return _PosixRootHandle.open(Path(path), expected_identity)


class _PosixRootHandle(_RootContext):
    def __init__(
        self,
        path: Path,
        descriptor: int,
        identity: Identity,
        *,
        anchor: _PosixRootHandle | None = None,
        anchor_name: PurePosixPath | None = None,
    ) -> None:
        self.path = path
        self._descriptor = descriptor
        self.identity = identity
        self._anchor = anchor
        self._anchor_name = anchor_name

    @classmethod
    def open(cls, path: Path, expected_identity: Identity | None) -> _PosixRootHandle:
        if (
            not all(function in os.supports_dir_fd for function in _POSIX_REQUIRED_DIR_FD)
            or os.listdir not in os.supports_fd
            or not all(getattr(os, flag, 0) for flag in ("O_DIRECTORY", "O_NOFOLLOW"))
        ):
            raise RootHandleError("root-relative filesystem operations are unavailable")
        descriptor = -1
        try:
            descriptor = os.open(path, _directory_flags())
            metadata = os.fstat(descriptor)
            identity = _identity(metadata)
            if not stat.S_ISDIR(metadata.st_mode) or (
                expected_identity is not None and identity != expected_identity
            ):
                raise RootHandleError("root directory identity changed or was replaced")
            return cls(path, descriptor, identity)
        except RootHandleError:
            if descriptor >= 0:
                os.close(descriptor)
            raise
        except (NotImplementedError, OSError) as exc:
            if descriptor >= 0:
                os.close(descriptor)
            raise RootHandleError("root directory is unsafe or could not be opened") from exc

    def close(self) -> None:
        if self._descriptor >= 0:
            descriptor, self._descriptor = self._descriptor, -1
            with suppress(OSError):
                os.close(descriptor)

    @property
    def supports_atomic_cleanup(self) -> bool:
        return False

    def require_path_identity(self) -> None:
        if self._anchor is not None and self._anchor_name is not None:
            try:
                current = self._anchor.metadata(self._anchor_name)
            except RootHandleError as exc:
                raise RootHandleError("root directory identity changed or was replaced") from exc
            if current.identity != self.identity:
                raise RootHandleError("root directory identity changed or was replaced")
            return
        try:
            metadata = self.path.stat(follow_symlinks=False)
        except OSError as exc:
            raise RootHandleError("root directory identity changed or was replaced") from exc
        if not stat.S_ISDIR(metadata.st_mode) or _identity(metadata) != self.identity:
            raise RootHandleError("root directory identity changed or was replaced")

    def listdir(self, relative: PurePosixPath = _ROOT) -> tuple[str, ...]:
        descriptor = self._open_directory(relative)
        try:
            return tuple(sorted(os.listdir(descriptor)))
        except OSError as exc:
            raise RootHandleError("rooted directory could not be enumerated") from exc
        finally:
            os.close(descriptor)

    def open_child_directory(
        self,
        relative: PurePosixPath,
        *,
        expected_identity: Identity | None = None,
    ) -> _PosixRootHandle:
        name = _single_name(relative)
        descriptor = self._open_entry(PurePosixPath(name), os.O_RDONLY, directory=True)
        try:
            metadata = os.fstat(descriptor)
            identity = _identity(metadata)
            if expected_identity is not None and identity != expected_identity:
                raise RootHandleError("root directory identity changed or was replaced")
            return _PosixRootHandle(
                self.path / name,
                descriptor,
                identity,
                anchor=self,
                anchor_name=PurePosixPath(name),
            )
        except Exception:
            os.close(descriptor)
            raise

    def metadata(self, relative: PurePosixPath) -> EntryMetadata:
        if relative == _ROOT:
            return _entry_metadata(os.fstat(self._descriptor))
        with self._parent(relative) as (name, parent):
            try:
                metadata = os.stat(name, dir_fd=parent, follow_symlinks=False)
            except FileNotFoundError as exc:
                raise RootHandleNotFound(f"rooted entry does not exist: {relative}") from exc
            except OSError as exc:
                raise RootHandleError(f"rooted entry could not be inspected: {relative}") from exc
        if not (stat.S_ISREG(metadata.st_mode) or stat.S_ISDIR(metadata.st_mode)):
            raise RootHandleError(f"rooted entry is a link or special file: {relative}")
        return _entry_metadata(metadata)

    def open_file(
        self,
        relative: PurePosixPath,
        flags: int,
        *,
        expected_identity: Identity | None = None,
        for_publication: bool = False,
    ) -> int:
        del for_publication
        descriptor = self._open_entry(relative, flags, directory=False)
        metadata = os.fstat(descriptor)
        if expected_identity is not None and _identity(metadata) != expected_identity:
            os.close(descriptor)
            raise RootHandleError(f"rooted entry changed during operation: {relative}")
        return descriptor

    def descriptor_identity(self, descriptor: int) -> Identity:
        """Return the backend identity for an already-open rooted descriptor."""

        return _identity(os.fstat(descriptor))

    def open_directory(
        self,
        relative: PurePosixPath,
        *,
        expected_identity: Identity | None = None,
    ) -> int:
        descriptor = self._open_directory(relative)
        metadata = os.fstat(descriptor)
        if expected_identity is not None and _identity(metadata) != expected_identity:
            os.close(descriptor)
            raise RootHandleError(f"rooted directory changed during operation: {relative}")
        return descriptor

    def create_file(self, relative: PurePosixPath, mode: int) -> int:
        return self._open_entry(
            relative,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            mode=mode,
            directory=False,
        )

    def ensure_file(self, relative: PurePosixPath, mode: int) -> int:
        return self._open_entry(
            relative,
            os.O_WRONLY | os.O_CREAT,
            mode=mode,
            directory=False,
        )

    def create_directory(self, relative: PurePosixPath, mode: int) -> Identity:
        with self._parent(relative) as (name, parent):
            try:
                os.mkdir(name, mode=mode, dir_fd=parent)
                descriptor = os.open(name, _directory_flags(), dir_fd=parent)
            except FileExistsError:
                raise
            except (NotImplementedError, OSError) as exc:
                raise RootHandleError(f"rooted directory could not be created: {relative}") from exc
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISDIR(metadata.st_mode):
                raise RootHandleError(f"created rooted directory became unsafe: {relative}")
            return _identity(metadata)
        finally:
            os.close(descriptor)

    def chmod(
        self,
        relative: PurePosixPath,
        mode: int,
        *,
        expected_identity: Identity | None = None,
    ) -> str:
        descriptor = (
            os.dup(self._descriptor)
            if relative == _ROOT
            else self._open_entry(relative, os.O_RDONLY, directory=None)
        )
        try:
            if (
                expected_identity is not None
                and _identity(os.fstat(descriptor)) != expected_identity
            ):
                raise RootHandleError(f"rooted entry changed during operation: {relative}")
            try:
                os.fchmod(descriptor, mode)  # type: ignore[attr-defined, unused-ignore]
            except (AttributeError, NotImplementedError):
                return "unsupported"
            except OSError:
                return "failed"
            return "supported"
        finally:
            os.close(descriptor)

    def unlink(self, relative: PurePosixPath, *, expected_identity: Identity | None = None) -> None:
        self._remove(relative, expected_identity, directory=False)

    def rmdir(self, relative: PurePosixPath, *, expected_identity: Identity | None = None) -> None:
        self._remove(relative, expected_identity, directory=True)

    def publish(
        self,
        temporary: PurePosixPath,
        destination: PurePosixPath,
        *,
        expected_identity: Identity,
        verified_descriptor: int,
    ) -> None:
        del verified_descriptor
        temporary_name = _single_name(temporary)
        destination_name = _single_name(destination)
        self.require_path_identity()
        try:
            os.link(
                temporary_name,
                destination_name,
                src_dir_fd=self._descriptor,
                dst_dir_fd=self._descriptor,
                follow_symlinks=False,
            )
        except FileExistsError:
            raise
        except OSError as exc:
            raise RootHandleError("verified artifact could not be published atomically") from exc
        if self.metadata(destination).identity != expected_identity:
            raise RootHandleError("published artifact is not the verified file")
        self.unlink(temporary, expected_identity=expected_identity)
        self.require_path_identity()

    def sync(self) -> str:
        try:
            os.fsync(self._descriptor)
        except OSError as exc:
            unsupported = {
                errno.EINVAL,
                errno.ENOSYS,
                getattr(errno, "ENOTSUP", errno.EINVAL),
                getattr(errno, "EOPNOTSUPP", errno.EINVAL),
            }
            if exc.errno in unsupported:
                return "unsupported"
            raise RootHandleError("root directory synchronization failed") from exc
        return "supported"

    def _open_directory(self, relative: PurePosixPath) -> int:
        if relative == _ROOT:
            return os.dup(self._descriptor)
        return self._open_entry(relative, os.O_RDONLY, directory=True)

    def _open_entry(
        self,
        relative: PurePosixPath,
        flags: int,
        *,
        mode: int = 0o777,
        directory: bool | None,
    ) -> int:
        with self._parent(relative) as (name, parent):
            open_flags = flags | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)  # type: ignore[attr-defined, unused-ignore]
            if directory is True:
                open_flags |= os.O_DIRECTORY  # type: ignore[attr-defined, unused-ignore]
            try:
                descriptor = os.open(name, open_flags, mode, dir_fd=parent)
            except FileNotFoundError as exc:
                raise RootHandleNotFound(f"rooted entry does not exist: {relative}") from exc
            except FileExistsError:
                raise
            except (NotImplementedError, OSError) as exc:
                raise RootHandleError(f"rooted entry is unsafe or unavailable: {relative}") from exc
        metadata = os.fstat(descriptor)
        valid = (
            stat.S_ISDIR(metadata.st_mode)
            if directory is True
            else stat.S_ISREG(metadata.st_mode)
            if directory is False
            else stat.S_ISDIR(metadata.st_mode) or stat.S_ISREG(metadata.st_mode)
        )
        if not valid:
            os.close(descriptor)
            raise RootHandleError(f"rooted entry has an unsafe type: {relative}")
        return descriptor

    @contextmanager
    def _parent(self, relative: PurePosixPath) -> Iterator[tuple[str, int]]:
        parts = _relative_parts(relative)
        descriptor = os.dup(self._descriptor)
        try:
            for part in parts[:-1]:
                child = os.open(part, _directory_flags(), dir_fd=descriptor)
                os.close(descriptor)
                descriptor = child
            yield parts[-1], descriptor
        except (NotImplementedError, OSError) as exc:
            raise RootHandleError(f"rooted path contains an unsafe component: {relative}") from exc
        finally:
            with suppress(OSError):
                os.close(descriptor)

    def _remove(
        self,
        relative: PurePosixPath,
        expected_identity: Identity | None,
        *,
        directory: bool,
    ) -> None:
        with self._parent(relative) as (name, parent):
            metadata = os.stat(name, dir_fd=parent, follow_symlinks=False)
            if expected_identity is not None and _identity(metadata) != expected_identity:
                raise RootHandleError(f"rooted cleanup identity changed: {relative}")
            expected_type = stat.S_ISDIR if directory else stat.S_ISREG
            if not expected_type(metadata.st_mode):
                raise RootHandleError(f"rooted cleanup target is unsafe: {relative}")
            if directory:
                os.rmdir(name, dir_fd=parent)
            else:
                os.unlink(name, dir_fd=parent)


def _directory_flags() -> int:
    return int(
        os.O_RDONLY
        | os.O_DIRECTORY  # type: ignore[attr-defined, unused-ignore]
        | os.O_NOFOLLOW  # type: ignore[attr-defined, unused-ignore]
        | getattr(os, "O_CLOEXEC", 0)
    )


def _relative_parts(relative: PurePosixPath) -> tuple[str, ...]:
    if not isinstance(relative, PurePosixPath):
        raise RootHandleError("rooted path must use canonical POSIX components")
    parts = relative.parts
    if not parts or relative.is_absolute() or any(part in {"", ".", ".."} for part in parts):
        raise RootHandleError("rooted path is not a safe relative path")
    return parts


def _single_name(relative: PurePosixPath) -> str:
    parts = _relative_parts(relative)
    if len(parts) != 1:
        raise RootHandleError("publication target must be a direct rooted child")
    return parts[0]


def _identity(metadata: os.stat_result) -> Identity:
    return metadata.st_dev, metadata.st_ino


def _entry_metadata(metadata: os.stat_result) -> EntryMetadata:
    return EntryMetadata(
        _identity(metadata),
        stat.S_IMODE(metadata.st_mode) & 0o700,
        metadata.st_size,
        metadata.st_mtime_ns,
        stat.S_ISDIR(metadata.st_mode),
    )


if TYPE_CHECKING:
    from shisad.core.data_root_windows import _WindowsRootHandle

    type RootHandle = _PosixRootHandle | _WindowsRootHandle
else:
    RootHandle = Any
