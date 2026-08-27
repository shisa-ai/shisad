"""Root-bound adapter for the existing single-file lifecycle lock."""

from __future__ import annotations

import errno
import os
import stat
from pathlib import Path, PurePosixPath

from filelock import BaseFileLock

from shisad.core.data_root_handle import Identity, RootHandle, RootHandleError, open_root

_LOCK_NAME = PurePosixPath(".shisad.lock")


class RootedFileLock(BaseFileLock):
    """Use BaseFileLock semantics while opening the lock through a pinned root."""

    def __init__(
        self,
        data_root: Path,
        *,
        root: RootHandle | None = None,
        timeout: float = -1,
    ) -> None:
        self._data_root = Path(data_root)
        self._borrowed_root = root
        self._active_root: RootHandle | None = None
        self._identity: Identity | None = None
        super().__init__(self._data_root / _LOCK_NAME.name, timeout=timeout, mode=0o600)

    @property
    def identity(self) -> Identity | None:
        """Return the acquired rooted lock identity, when held."""

        return self._identity

    def _acquire(self) -> None:
        root = self._borrowed_root
        owns_root = root is None
        descriptor = -1
        locked = False
        try:
            if root is None:
                root = open_root(self._data_root)
            descriptor = root.ensure_file(_LOCK_NAME, 0o600)
            metadata = os.fstat(descriptor)
            identity = root.descriptor_identity(descriptor)
            if not stat.S_ISREG(metadata.st_mode):
                raise OSError("rooted lifecycle-lock child is not a regular file")
            permission = root.chmod(_LOCK_NAME, 0o600, expected_identity=identity)
            if permission == "failed":
                raise OSError("rooted lifecycle-lock permissions could not be tightened")
            self._lock_descriptor(descriptor)
            locked = True
            current = root.metadata(_LOCK_NAME)
            if current.is_directory or current.identity != identity or metadata.st_nlink == 0:
                raise OSError("rooted lifecycle-lock identity changed or was replaced")
            self._context.lock_file_fd = descriptor
            self._identity = identity
            if owns_root:
                self._active_root = root
            descriptor = -1
        except BlockingIOError:
            return
        except RootHandleError as exc:
            raise OSError(f"rooted lifecycle-lock acquisition failed: {exc}") from exc
        finally:
            if descriptor >= 0:
                if locked:
                    self._unlock_descriptor(descriptor)
                os.close(descriptor)
            if owns_root and root is not None and self._active_root is not root:
                root.close()

    def _release(self) -> None:
        descriptor = self._context.lock_file_fd
        self._context.lock_file_fd = None
        self._identity = None
        if descriptor is not None:
            try:
                self._unlock_descriptor(descriptor)
            finally:
                os.close(descriptor)
        if self._active_root is not None:
            root, self._active_root = self._active_root, None
            root.close()

    @staticmethod
    def _lock_descriptor(descriptor: int) -> None:
        if os.name == "posix":
            import fcntl

            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as exc:
                if exc.errno in {errno.EACCES, errno.EAGAIN}:
                    raise BlockingIOError from None
                if exc.errno == errno.ENOSYS:
                    raise OSError("hard lifecycle locking is unavailable") from exc
                raise
            return
        if os.name == "nt":
            import msvcrt

            try:
                os.lseek(descriptor, 0, os.SEEK_SET)
                msvcrt.locking(  # type: ignore[attr-defined, unused-ignore]
                    descriptor,
                    msvcrt.LK_NBLCK,  # type: ignore[attr-defined, unused-ignore]
                    1,
                )
            except OSError as exc:
                if exc.errno in {errno.EACCES, errno.EAGAIN}:
                    raise BlockingIOError from None
                raise
            return
        raise OSError("hard lifecycle locking is unavailable")

    @staticmethod
    def _unlock_descriptor(descriptor: int) -> None:
        if os.name == "posix":
            import fcntl

            fcntl.flock(descriptor, fcntl.LOCK_UN)
            return
        if os.name == "nt":
            import msvcrt

            os.lseek(descriptor, 0, os.SEEK_SET)
            msvcrt.locking(  # type: ignore[attr-defined, unused-ignore]
                descriptor,
                msvcrt.LK_UNLCK,  # type: ignore[attr-defined, unused-ignore]
                1,
            )
