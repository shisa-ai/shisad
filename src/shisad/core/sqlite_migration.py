"""Shared lifecycle for one physically versioned SQLite database."""

from __future__ import annotations

import contextlib
import hashlib
import os
import sqlite3
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

from shisad.core.storage_platform import sync_parent_directory, tighten_permissions

SQLiteSchemaCallback = Callable[[sqlite3.Connection], None]


class SQLiteMigrationStage(StrEnum):
    """Injectable boundaries in the native SQLite migration lifecycle."""

    BACKUP_PRESERVED = "backup_preserved"
    MIGRATION_APPLIED = "migration_applied"
    BEFORE_COMMIT = "before_commit"


SQLiteMigrationFaultInjector = Callable[[SQLiteMigrationStage], None]


class SQLiteMigrationError(RuntimeError):
    """A physical SQLite database could not be admitted safely."""


@dataclass(frozen=True, slots=True)
class SQLiteMigrationResult:
    """Typed initialization or migration outcome for one physical database."""

    path: Path
    initialized: bool
    migrated: bool
    from_version: int
    to_version: int
    backup_path: Path | None
    permissions: str
    parent_sync: str


def prepare_versioned_sqlite_database(
    path: Path,
    *,
    label: str,
    current_version: int,
    initialize: SQLiteSchemaCallback,
    migrations: Mapping[int, SQLiteSchemaCallback],
    validate_current: SQLiteSchemaCallback,
    validate_legacy: SQLiteSchemaCallback,
    fault_injector: SQLiteMigrationFaultInjector | None = None,
) -> SQLiteMigrationResult:
    """Initialize, validate, or migrate one database under native transactions."""

    if current_version < 1:
        raise ValueError("current SQLite schema version must be positive")
    database_path = Path(path)
    existed = _prepare_database_path(database_path, label=label)
    if not existed and _migration_backup_exists(database_path):
        raise SQLiteMigrationError(
            f"{label} migration backup exists without its database; "
            "restore or relocate it before fresh initialization"
        )
    if existed and database_path.stat().st_size == 0:
        raise SQLiteMigrationError(f"existing {label} database is empty or unversioned")

    connection: sqlite3.Connection | None = None
    in_transaction = False
    committed = False
    stage: SQLiteMigrationStage | None = None
    inject = fault_injector or (lambda _stage: None)
    try:
        connection = sqlite3.connect(database_path, timeout=5.0, isolation_level=None)
        connection.execute("PRAGMA busy_timeout = 5000")
        connection.execute("PRAGMA synchronous = FULL")
        if existed:
            _checkpoint_wal(connection, label=label)
        connection.execute("BEGIN IMMEDIATE")
        in_transaction = True
        version = int(connection.execute("PRAGMA user_version").fetchone()[0])
        _require_integrity(connection, label=label)

        if not existed:
            if version != 0 or _database_objects(connection):
                raise SQLiteMigrationError(f"fresh {label} database is not empty")
            initialize(connection)
            connection.execute(f"PRAGMA user_version = {current_version}")
            validate_current(connection)
            _require_integrity(connection, label=label)
            stage = SQLiteMigrationStage.BEFORE_COMMIT
            inject(stage)
            connection.commit()
            in_transaction = False
            committed = True
            permissions = _require_permissions(database_path, label=label)
            parent_sync = sync_parent_directory(database_path.parent)
            return SQLiteMigrationResult(
                path=database_path,
                initialized=True,
                migrated=False,
                from_version=0,
                to_version=current_version,
                backup_path=None,
                permissions=permissions,
                parent_sync=parent_sync,
            )

        if version > current_version:
            raise SQLiteMigrationError(
                f"{label} database uses schema version {version}; this build supports "
                f"version {current_version} and will not downgrade"
            )
        if version == current_version:
            validate_current(connection)
            connection.rollback()
            in_transaction = False
            return SQLiteMigrationResult(
                path=database_path,
                initialized=False,
                migrated=False,
                from_version=version,
                to_version=version,
                backup_path=None,
                permissions=_require_permissions(database_path, label=label),
                parent_sync="not_applicable",
            )
        if version not in migrations:
            raise SQLiteMigrationError(
                f"{label} database has no ordered migration from schema version {version}"
            )

        validate_legacy(connection)
        backup_path, backup_permissions, backup_parent_sync = _preserve_exact_backup(
            database_path,
            label=label,
            expected_version=version,
        )
        stage = SQLiteMigrationStage.BACKUP_PRESERVED
        inject(stage)
        migrated_from = version
        while version < current_version:
            migrate = migrations.get(version)
            if migrate is None:
                raise SQLiteMigrationError(
                    f"{label} database has no ordered migration from schema version {version}"
                )
            migrate(connection)
            version += 1
            connection.execute(f"PRAGMA user_version = {version}")
            stage = SQLiteMigrationStage.MIGRATION_APPLIED
            inject(stage)
        validate_current(connection)
        _require_integrity(connection, label=label)
        stage = SQLiteMigrationStage.BEFORE_COMMIT
        inject(stage)
        connection.commit()
        in_transaction = False
        committed = True
        permissions = _require_permissions(database_path, label=label)
        return SQLiteMigrationResult(
            path=database_path,
            initialized=False,
            migrated=True,
            from_version=migrated_from,
            to_version=version,
            backup_path=backup_path,
            permissions=_combine_capabilities(backup_permissions, permissions),
            parent_sync=backup_parent_sync,
        )
    except SQLiteMigrationError:
        if in_transaction and connection is not None:
            with contextlib.suppress(sqlite3.Error):
                connection.rollback()
        raise
    except (OSError, sqlite3.Error) as exc:
        if in_transaction and connection is not None:
            with contextlib.suppress(sqlite3.Error):
                connection.rollback()
        boundary = stage.value if stage is not None else "admission"
        raise SQLiteMigrationError(
            f"{label} database migration failed at {boundary}: {exc.__class__.__name__}"
        ) from exc
    finally:
        if connection is not None:
            with contextlib.suppress(sqlite3.Error):
                connection.close()
        if not existed and not committed:
            for candidate in (
                database_path,
                database_path.with_name(f"{database_path.name}-journal"),
                database_path.with_name(f"{database_path.name}-wal"),
                database_path.with_name(f"{database_path.name}-shm"),
            ):
                with contextlib.suppress(OSError):
                    candidate.unlink()


def _prepare_database_path(path: Path, *, label: str) -> bool:
    if path.is_symlink():
        raise SQLiteMigrationError(f"selected {label} database is a symlink")
    if path.exists() and not path.is_file():
        raise SQLiteMigrationError(f"selected {label} database is not a regular file")
    parent = path.parent
    if parent.is_symlink():
        raise SQLiteMigrationError(f"selected {label} database parent is a symlink")
    try:
        parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    except OSError as exc:
        raise SQLiteMigrationError(
            f"cannot prepare {label} database parent: {exc.__class__.__name__}"
        ) from exc
    if parent.is_symlink() or not parent.is_dir():
        raise SQLiteMigrationError(f"selected {label} database parent is unsafe")
    return path.exists()


def _migration_backup_exists(path: Path) -> bool:
    prefix = f"{path.name}.pre-v"
    for candidate in path.parent.iterdir():
        name = candidate.name
        version = name.removeprefix(prefix).removesuffix(".bak")
        if name.startswith(prefix) and name.endswith(".bak") and version.isdecimal():
            return True
    return False


def _checkpoint_wal(connection: sqlite3.Connection, *, label: str) -> None:
    row = connection.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
    if row is not None and int(row[0]) != 0:
        raise SQLiteMigrationError(f"{label} database WAL checkpoint is busy")


def _require_integrity(connection: sqlite3.Connection, *, label: str) -> None:
    row = connection.execute("PRAGMA quick_check").fetchone()
    if row is None or str(row[0]) != "ok":
        raise SQLiteMigrationError(f"{label} database integrity check failed")


def _database_objects(connection: sqlite3.Connection) -> set[tuple[str, str]]:
    return {
        (str(row[0]), str(row[1]))
        for row in connection.execute(
            """
            SELECT type, name FROM sqlite_master
            WHERE name NOT LIKE 'sqlite_%'
            """
        ).fetchall()
    }


def _preserve_exact_backup(
    source: Path,
    *,
    label: str,
    expected_version: int,
) -> tuple[Path, str, str]:
    backup = source.with_name(f"{source.name}.pre-v{expected_version + 1}.bak")
    if backup.is_symlink() or (backup.exists() and not backup.is_file()):
        raise SQLiteMigrationError(f"existing {label} migration backup is unsafe")
    if backup.exists():
        if not _files_match(source, backup):
            raise SQLiteMigrationError(
                f"existing {label} migration backup does not match the legacy database"
            )
        _validate_backup(backup, label=label, expected_version=expected_version)
        return (
            backup,
            _require_permissions(backup, label=f"{label} migration backup"),
            "not_applicable",
        )

    descriptor = -1
    created = False
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(backup, flags, 0o600)
        created = True
        with source.open("rb") as source_handle:
            while chunk := source_handle.read(1024 * 1024):
                remaining = memoryview(chunk)
                while remaining:
                    written = os.write(descriptor, remaining)
                    if written <= 0:
                        raise OSError("SQLite migration backup write made no progress")
                    remaining = remaining[written:]
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        if not _files_match(source, backup):
            raise SQLiteMigrationError(f"{label} migration backup is not an exact copy")
        _validate_backup(backup, label=label, expected_version=expected_version)
        permissions = _require_permissions(backup, label=f"{label} migration backup")
        parent_sync = sync_parent_directory(source.parent)
        return backup, permissions, parent_sync
    except (OSError, sqlite3.Error) as exc:
        if descriptor >= 0:
            with contextlib.suppress(OSError):
                os.close(descriptor)
        if created:
            with contextlib.suppress(OSError):
                backup.unlink()
        raise SQLiteMigrationError(
            f"cannot preserve {label} migration backup: {exc.__class__.__name__}"
        ) from exc
    except SQLiteMigrationError:
        if descriptor >= 0:
            with contextlib.suppress(OSError):
                os.close(descriptor)
        if created:
            with contextlib.suppress(OSError):
                backup.unlink()
        raise


def _validate_backup(path: Path, *, label: str, expected_version: int) -> None:
    try:
        uri = f"{path.resolve().as_uri()}?mode=ro"
        with sqlite3.connect(uri, uri=True) as connection:
            _require_integrity(connection, label=f"{label} migration backup")
            version = int(connection.execute("PRAGMA user_version").fetchone()[0])
    except (OSError, sqlite3.Error) as exc:
        raise SQLiteMigrationError(
            f"cannot validate {label} migration backup: {exc.__class__.__name__}"
        ) from exc
    if version != expected_version:
        raise SQLiteMigrationError(
            f"{label} migration backup has unexpected schema version {version}"
        )


def _files_match(left: Path, right: Path) -> bool:
    if left.stat().st_size != right.stat().st_size:
        return False
    with left.open("rb") as left_handle, right.open("rb") as right_handle:
        return (
            hashlib.file_digest(left_handle, "sha256").digest()
            == hashlib.file_digest(right_handle, "sha256").digest()
        )


def _require_permissions(path: Path, *, label: str) -> str:
    permissions = tighten_permissions(path, 0o600)
    if permissions == "failed":
        raise SQLiteMigrationError(f"{label} permissions could not be tightened")
    return permissions


def _combine_capabilities(*states: str) -> str:
    return (
        "supported" if states and all(state == "supported" for state in states) else "unsupported"
    )
