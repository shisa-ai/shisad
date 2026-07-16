"""Owner-only filesystem admission for daemon-owned SQLite databases."""

from __future__ import annotations

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


def _prepare_owner_directory(path: Path) -> None:
    expected_uid = _current_euid()
    current = Path(path.anchor)
    for component in path.parts[1:]:
        current /= component
        try:
            current_stat = _lstat(current)
        except FileNotFoundError:
            try:
                os.mkdir(current, 0o700)
            except FileExistsError:
                current_stat = _lstat(current)
            else:
                current_stat = _lstat(current)
        if stat.S_ISLNK(current_stat.st_mode):
            raise SQLitePathSecurityError(f"SQLite path has symlink ancestry: {current}")
        if not stat.S_ISDIR(current_stat.st_mode):
            raise SQLitePathSecurityError(f"SQLite parent is not a directory: {current}")
        if current == path:
            if current_stat.st_uid != expected_uid:
                raise SQLitePathSecurityError(
                    f"SQLite parent is owned by uid {current_stat.st_uid}, "
                    f"expected {expected_uid}: {current}"
                )
            current.chmod(0o700)
        elif (
            current_stat.st_uid != expected_uid
            and current_stat.st_mode & 0o022
            and not _is_shared_sticky_directory(current_stat)
        ):
            raise SQLitePathSecurityError(
                f"SQLite ancestry is writable by another uid: {current}"
            )


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


def _open_and_restrict_regular(path: Path, *, create: bool) -> None:
    try:
        path_stat = _lstat(path)
    except FileNotFoundError:
        path_stat = None
    if path_stat is not None:
        _validate_owner_regular(path, path_stat)

    flags = os.O_RDWR | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    if create:
        flags |= os.O_CREAT
    try:
        fd = os.open(path, flags, 0o600)
    except OSError as exc:
        if exc.errno in {errno.ELOOP, errno.EMLINK}:
            raise SQLitePathSecurityError(f"SQLite path is a symlink: {path}") from exc
        raise SQLitePathSecurityError(f"SQLite path cannot be opened safely: {path}") from exc
    try:
        opened_stat = os.fstat(fd)
        _validate_owner_regular(path, opened_stat)
        os.fchmod(fd, 0o600)
        current_stat = _lstat(path)
        _validate_owner_regular(path, current_stat)
        if (opened_stat.st_dev, opened_stat.st_ino) != (
            current_stat.st_dev,
            current_stat.st_ino,
        ):
            raise SQLitePathSecurityError(f"SQLite path identity changed during open: {path}")
    finally:
        os.close(fd)


def _restrict_existing_companions(database: Path) -> None:
    for suffix in _COMPANION_SUFFIXES:
        companion = Path(f"{database}{suffix}")
        try:
            _lstat(companion)
        except FileNotFoundError:
            continue
        _open_and_restrict_regular(companion, create=False)


def prepare_secure_sqlite_path(path: Path) -> Path:
    """Create or repair an owner-controlled SQLite database path."""

    database = _lexical_absolute(path)
    _prepare_owner_directory(database.parent)
    _open_and_restrict_regular(database, create=True)
    _restrict_existing_companions(database)
    return database


def secure_sqlite_connect(path: Path) -> sqlite3.Connection:
    """Open SQLite only after restrictive, symlink-safe path admission."""

    database = prepare_secure_sqlite_path(path)
    try:
        connection = sqlite3.connect(database)
    except sqlite3.Error:
        _restrict_existing_companions(database)
        raise
    try:
        _open_and_restrict_regular(database, create=False)
        _restrict_existing_companions(database)
    except BaseException:
        connection.close()
        raise
    return connection
