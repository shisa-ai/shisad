"""F3 owner-only SQLite path and companion-file regressions."""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

import shisad.memory.sqlite_security as sqlite_security
from shisad.memory.sqlite_security import SQLitePathSecurityError, secure_sqlite_connect


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.lstat().st_mode)


def test_f3_secure_sqlite_first_create_is_owner_only_under_permissive_umask(
    tmp_path: Path,
) -> None:
    database = tmp_path / "state" / "memory.sqlite3"
    previous_umask = os.umask(0)
    try:
        with secure_sqlite_connect(database) as connection:
            connection.execute("CREATE TABLE records (value TEXT NOT NULL)")
    finally:
        os.umask(previous_umask)

    assert _mode(database.parent) == 0o700
    assert _mode(database) == 0o600


def test_f3_secure_sqlite_wal_and_shm_are_owner_only_under_permissive_umask(
    tmp_path: Path,
) -> None:
    database = tmp_path / "state" / "memory.sqlite3"
    previous_umask = os.umask(0)
    try:
        connection = secure_sqlite_connect(database)
        assert connection.execute("PRAGMA journal_mode=WAL").fetchone()[0] == "wal"
        connection.execute("CREATE TABLE records (value TEXT NOT NULL)")
        connection.execute("INSERT INTO records VALUES ('secret')")
        connection.commit()
        wal = Path(f"{database}-wal")
        shm = Path(f"{database}-shm")
        assert wal.exists()
        assert shm.exists()
        assert _mode(wal) == 0o600
        assert _mode(shm) == 0o600
        connection.close()
    finally:
        os.umask(previous_umask)


def test_f3_secure_sqlite_repairs_owner_controlled_reopen_modes(tmp_path: Path) -> None:
    database = tmp_path / "state" / "memory.sqlite3"
    database.parent.mkdir()
    database.write_bytes(b"")
    database.parent.chmod(0o777)
    database.chmod(0o666)

    with secure_sqlite_connect(database) as connection:
        connection.execute("CREATE TABLE records (value TEXT NOT NULL)")

    assert _mode(database.parent) == 0o700
    assert _mode(database) == 0o600


def test_f3_secure_sqlite_rejects_symlink_target_without_touching_destination(
    tmp_path: Path,
) -> None:
    outside = tmp_path / "outside.sqlite3"
    outside.write_bytes(b"trusted")
    database = tmp_path / "state" / "memory.sqlite3"
    database.parent.mkdir()
    database.symlink_to(outside)

    with pytest.raises(SQLitePathSecurityError, match="symlink"):
        secure_sqlite_connect(database)

    assert outside.read_bytes() == b"trusted"


def test_f3_secure_sqlite_rejects_foreign_owner_without_mode_repair(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = tmp_path / "state" / "memory.sqlite3"
    database.parent.mkdir()
    database.write_bytes(b"")
    database.chmod(0o666)
    real_lstat = sqlite_security._lstat

    def _foreign_database(path: Path) -> os.stat_result:
        result = real_lstat(path)
        if path == database:
            values = list(result)
            values[4] = os.geteuid() + 1
            return os.stat_result(values)
        return result

    monkeypatch.setattr(sqlite_security, "_lstat", _foreign_database)

    with pytest.raises(SQLitePathSecurityError, match="owned by uid"):
        secure_sqlite_connect(database)

    assert _mode(database) == 0o666
