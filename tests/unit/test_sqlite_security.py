"""F3 owner-only SQLite path and companion-file regressions."""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

import shisad.memory.sqlite_security as sqlite_security
from shisad.memory.sqlite_security import (
    SQLitePathSecurityError,
    prepare_secure_sqlite_directory,
    secure_sqlite_connect,
)


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


def test_f3_secure_sqlite_prepares_caller_owned_state_root_before_nested_store(
    tmp_path: Path,
) -> None:
    state_root = tmp_path / "state"
    state_root.mkdir(mode=0o775)
    state_root.chmod(0o775)

    prepare_secure_sqlite_directory(state_root)
    database = state_root / "memory_entries" / "memory.sqlite3"
    with secure_sqlite_connect(database) as connection:
        connection.execute("CREATE TABLE records (value TEXT NOT NULL)")

    assert _mode(state_root) == 0o700
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


def test_f3_secure_sqlite_rejects_owner_writable_ancestor(tmp_path: Path) -> None:
    writable_ancestor = tmp_path / "writable"
    database_parent = writable_ancestor / "state"
    database_parent.mkdir(parents=True)
    writable_ancestor.chmod(0o777)
    database_parent.chmod(0o700)

    with pytest.raises(SQLitePathSecurityError, match="writable by another uid"):
        secure_sqlite_connect(database_parent / "memory.sqlite3")

    assert not (database_parent / "memory.sqlite3").exists()


def test_f3_secure_sqlite_allows_execute_only_ancestry_and_repairs_final_directory(
    tmp_path: Path,
) -> None:
    traverse_only = tmp_path / "traverse-only"
    database_parent = traverse_only / "state"
    database_parent.mkdir(parents=True)
    traverse_only.chmod(0o711)
    database_parent.chmod(0o300)

    with secure_sqlite_connect(database_parent / "memory.sqlite3") as connection:
        connection.execute("CREATE TABLE records (value TEXT NOT NULL)")

    assert _mode(traverse_only) == 0o711
    assert _mode(database_parent) == 0o700
    assert _mode(database_parent / "memory.sqlite3") == 0o600


def test_f3_secure_sqlite_rejects_symlinked_ancestor_without_mutation(
    tmp_path: Path,
) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    linked = tmp_path / "linked"
    linked.symlink_to(outside, target_is_directory=True)

    with pytest.raises(SQLitePathSecurityError, match="symlink ancestry"):
        secure_sqlite_connect(linked / "state" / "memory.sqlite3")

    assert list(outside.iterdir()) == []


def test_f3_secure_sqlite_binds_connection_to_verified_inode_during_substitution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = tmp_path / "state" / "memory.sqlite3"
    substitute = tmp_path / "substitute.sqlite3"
    with secure_sqlite_connect(database) as connection:
        connection.execute("CREATE TABLE original_marker (value TEXT)")
    with sqlite_security.sqlite3.connect(substitute) as connection:
        connection.execute("CREATE TABLE substitute_marker (value TEXT)")

    real_connect = sqlite_security.sqlite3.connect
    retained = tmp_path / "retained.sqlite3"

    def _swap_around_connect(path: object, *args: object, **kwargs: object):
        database.rename(retained)
        substitute.rename(database)
        try:
            connection = real_connect(path, *args, **kwargs)
        finally:
            database.rename(substitute)
            retained.rename(database)
        return connection

    monkeypatch.setattr(sqlite_security.sqlite3, "connect", _swap_around_connect)

    with pytest.raises(SQLitePathSecurityError, match="identity changed"):
        connection = secure_sqlite_connect(database)
        connection.close()

    with real_connect(database) as connection:
        assert connection.execute(
            "SELECT name FROM sqlite_master WHERE name = 'original_marker'"
        ).fetchone()
        assert connection.execute(
            "SELECT name FROM sqlite_master WHERE name = 'substitute_marker'"
        ).fetchone() is None
    with real_connect(substitute) as connection:
        assert connection.execute(
            "SELECT name FROM sqlite_master WHERE name = 'substitute_marker'"
        ).fetchone()
        assert connection.execute(
            "SELECT name FROM sqlite_master WHERE name = 'original_marker'"
        ).fetchone() is None


def test_f3_secure_sqlite_rejects_hardlink_without_touching_source(tmp_path: Path) -> None:
    source = tmp_path / "source.sqlite3"
    source.write_bytes(b"trusted")
    database = tmp_path / "state" / "memory.sqlite3"
    database.parent.mkdir()
    database.hardlink_to(source)

    with pytest.raises(SQLitePathSecurityError, match="multiple hard links"):
        secure_sqlite_connect(database)

    assert source.read_bytes() == b"trusted"
