"""Owner-only filesystem admission for daemon-owned SQLite databases."""

from __future__ import annotations

import contextlib
import errno
import os
import sqlite3
import stat
from pathlib import Path

_COMPANION_SUFFIXES = ("-journal", "-wal", "-shm")


class SQLitePathSecurityError(RuntimeError):
    """A SQLite database or companion path is not owner-controlled."""


def _current_euid() -> int:
    return os.geteuid() if hasattr(os, "geteuid") else os.getuid()


def _lstat(path: Path) -> os.stat_result:
    return path.lstat()


def _lexical_absolute(path: Path) -> Path:
    return Path(os.path.abspath(os.fspath(path.expanduser())))


def _is_shared_sticky_directory(path_stat: os.stat_result) -> bool:
    return bool(path_stat.st_mode & stat.S_ISVTX) and bool(path_stat.st_mode & 0o002)


def _open_owner_directory(path: Path, *, reject_writable_final: bool = False) -> int:
    expected_uid = _current_euid()
    directory_flags = getattr(os, "O_PATH", os.O_RDONLY) | getattr(
        os,
        "O_DIRECTORY",
        0,
    )
    directory_flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    current = Path(path.anchor)
    current_fd = os.open(current, directory_flags)
    try:
        for index, component in enumerate(path.parts[1:]):
            current /= component
            try:
                visible_stat = _lstat(current)
            except FileNotFoundError:
                visible_stat = None
            if visible_stat is not None and stat.S_ISLNK(visible_stat.st_mode):
                raise SQLitePathSecurityError(
                    f"SQLite path has symlink ancestry: {current}"
                )
            if visible_stat is not None and not stat.S_ISDIR(visible_stat.st_mode):
                raise SQLitePathSecurityError(
                    f"SQLite parent is not a directory: {current}"
                )
            if visible_stat is None:
                with contextlib.suppress(FileExistsError):
                    os.mkdir(component, 0o700, dir_fd=current_fd)
            try:
                next_fd = os.open(component, directory_flags, dir_fd=current_fd)
            except OSError as exc:
                if exc.errno in {errno.ELOOP, errno.ENOTDIR}:
                    raise SQLitePathSecurityError(
                        f"SQLite path has symlink ancestry: {current}"
                    ) from exc
                raise SQLitePathSecurityError(
                    f"SQLite directory cannot be opened safely: {current}"
                ) from exc
            current_stat = os.fstat(next_fd)
            try:
                if not stat.S_ISDIR(current_stat.st_mode):
                    raise SQLitePathSecurityError(
                        f"SQLite parent is not a directory: {current}"
                    )
                is_final = index == len(path.parts[1:]) - 1
                if is_final:
                    if current_stat.st_uid != expected_uid:
                        raise SQLitePathSecurityError(
                            f"SQLite parent is owned by uid {current_stat.st_uid}, "
                            f"expected {expected_uid}: {current}"
                        )
                    if reject_writable_final and current_stat.st_mode & 0o022:
                        raise SQLitePathSecurityError(
                            f"SQLite root is writable by another uid: {current}"
                        )
                    os.chmod(_verified_descriptor_path(next_fd), 0o700)
                elif current_stat.st_mode & 0o022 and not _is_shared_sticky_directory(
                    current_stat
                ):
                    raise SQLitePathSecurityError(
                        f"SQLite ancestry is writable by another uid: {current}"
                    )
            except BaseException:
                os.close(next_fd)
                raise
            os.close(current_fd)
            current_fd = next_fd
        return current_fd
    except BaseException:
        os.close(current_fd)
        raise


def _validate_owner_regular(path: Path, path_stat: os.stat_result) -> None:
    if stat.S_ISLNK(path_stat.st_mode):
        raise SQLitePathSecurityError(f"SQLite path is a symlink: {path}")
    if not stat.S_ISREG(path_stat.st_mode):
        raise SQLitePathSecurityError(f"SQLite path is not a regular file: {path}")
    expected_uid = _current_euid()
    if path_stat.st_uid != expected_uid:
        raise SQLitePathSecurityError(
            f"SQLite path is owned by uid {path_stat.st_uid}, expected {expected_uid}: {path}"
        )
    if path_stat.st_nlink != 1:
        raise SQLitePathSecurityError(f"SQLite path has multiple hard links: {path}")


def _open_and_restrict_regular(path: Path, *, parent_fd: int, create: bool) -> int:
    try:
        visible_stat = _lstat(path)
    except FileNotFoundError:
        visible_stat = None
    if visible_stat is not None:
        _validate_owner_regular(path, visible_stat)

    try:
        path_stat = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        path_stat = None
    if path_stat is not None:
        _validate_owner_regular(path, path_stat)

    flags = os.O_RDWR | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    create_exclusive = create and path_stat is None
    if create_exclusive:
        flags |= os.O_CREAT | os.O_EXCL
    try:
        fd = os.open(path.name, flags, 0o600, dir_fd=parent_fd)
    except FileExistsError:
        if not create_exclusive:
            raise
        try:
            fd = os.open(path.name, flags & ~(os.O_CREAT | os.O_EXCL), dir_fd=parent_fd)
        except OSError as exc:
            raise SQLitePathSecurityError(
                f"SQLite path cannot be opened safely: {path}"
            ) from exc
    except OSError as exc:
        if exc.errno in {errno.ELOOP, errno.EMLINK}:
            raise SQLitePathSecurityError(f"SQLite path is a symlink: {path}") from exc
        raise SQLitePathSecurityError(f"SQLite path cannot be opened safely: {path}") from exc
    try:
        opened_stat = os.fstat(fd)
        _validate_owner_regular(path, opened_stat)
        os.fchmod(fd, 0o600)
        current_stat = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
        _validate_owner_regular(path, current_stat)
        if (opened_stat.st_dev, opened_stat.st_ino) != (
            current_stat.st_dev,
            current_stat.st_ino,
        ):
            raise SQLitePathSecurityError(f"SQLite path identity changed during open: {path}")
        return fd
    except BaseException:
        os.close(fd)
        raise


def _restrict_existing_companions(database: Path, *, parent_fd: int) -> None:
    for suffix in _COMPANION_SUFFIXES:
        companion = Path(f"{database}{suffix}")
        try:
            os.stat(companion.name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            continue
        companion_fd = _open_and_restrict_regular(
            companion,
            parent_fd=parent_fd,
            create=False,
        )
        os.close(companion_fd)


def _verified_descriptor_path(fd: int) -> Path:
    for root in (Path("/proc/self/fd"), Path("/dev/fd")):
        candidate = root / str(fd)
        if candidate.exists():
            return candidate
    raise SQLitePathSecurityError("verified SQLite descriptor path is unavailable")


def _connection_main_path(connection: sqlite3.Connection) -> Path:
    for _sequence, name, raw_path in connection.execute("PRAGMA database_list").fetchall():
        if str(name) == "main":
            return _lexical_absolute(Path(str(raw_path)))
    raise SQLitePathSecurityError("SQLite connection did not report its main database")


def prepare_secure_sqlite_path(path: Path) -> Path:
    """Create or repair an owner-controlled SQLite database path."""

    database = _lexical_absolute(path)
    parent_fd = _open_owner_directory(database.parent)
    try:
        database_fd = _open_and_restrict_regular(
            database,
            parent_fd=parent_fd,
            create=True,
        )
        os.close(database_fd)
        _restrict_existing_companions(database, parent_fd=parent_fd)
    finally:
        os.close(parent_fd)
    return database


def prepare_secure_sqlite_directory(path: Path) -> Path:
    """Create or repair an owner-controlled root before adding SQLite stores."""

    directory = _lexical_absolute(path)
    directory_fd = _open_owner_directory(directory, reject_writable_final=True)
    os.close(directory_fd)
    return directory


def secure_sqlite_connect(path: Path) -> sqlite3.Connection:
    """Open SQLite only after restrictive, symlink-safe path admission."""

    database = _lexical_absolute(path)
    parent_fd = _open_owner_directory(database.parent)
    database_fd: int | None = None
    connection: sqlite3.Connection | None = None
    try:
        database_fd = _open_and_restrict_regular(
            database,
            parent_fd=parent_fd,
            create=True,
        )
        _restrict_existing_companions(database, parent_fd=parent_fd)
        connection = sqlite3.connect(_verified_descriptor_path(database_fd))
        if _connection_main_path(connection) != database:
            raise SQLitePathSecurityError(
                f"SQLite connection identity changed during open: {database}"
            )
        opened_stat = os.fstat(database_fd)
        current_stat = os.stat(database.name, dir_fd=parent_fd, follow_symlinks=False)
        _validate_owner_regular(database, current_stat)
        if (opened_stat.st_dev, opened_stat.st_ino) != (
            current_stat.st_dev,
            current_stat.st_ino,
        ):
            raise SQLitePathSecurityError(
                f"SQLite connection identity changed during open: {database}"
            )
        _restrict_existing_companions(database, parent_fd=parent_fd)
    except BaseException:
        if connection is not None:
            connection.close()
        raise
    finally:
        if database_fd is not None:
            os.close(database_fd)
        os.close(parent_fd)
    assert connection is not None
    return connection
