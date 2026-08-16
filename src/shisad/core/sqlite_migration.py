"""Shared lifecycle for one physically versioned SQLite database."""

from __future__ import annotations

import contextlib
import hashlib
import os
import re
import sqlite3
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

from shisad.core.storage_platform import (
    combine_permission_capabilities,
    sync_parent_directory,
    tighten_permissions,
)

SQLiteSchemaCallback = Callable[[sqlite3.Connection], None]
_SCHEMA_CONSTRAINT_KEYWORDS = (
    "CHECK",
    "COLLATE",
    "CONFLICT",
    "CONSTRAINT",
    "FOREIGN",
    "GENERATED",
    "REFERENCES",
    "STRICT",
    "UNIQUE",
    "WITHOUT",
)


class SQLiteMigrationStage(StrEnum):
    """Finite boundaries in the native SQLite migration lifecycle."""

    ADMISSION = "admission"
    BACKUP = "backup"
    BACKUP_PRESERVED = "backup_preserved"
    MIGRATION_APPLIED = "migration_applied"
    BEFORE_COMMIT = "before_commit"
    PERMISSIONS = "permissions"
    PARENT_SYNC = "parent_sync"


SQLiteMigrationFaultInjector = Callable[[SQLiteMigrationStage], None]


class SQLiteMigrationError(RuntimeError):
    """A physical SQLite database could not be admitted safely."""

    def __init__(
        self,
        reason: str,
        *,
        path: Path | None = None,
        stage: SQLiteMigrationStage = SQLiteMigrationStage.ADMISSION,
        transaction_committed: bool = False,
        from_version: int | None = None,
        to_version: int | None = None,
        backup_path: Path | None = None,
        permissions: str = "not_attempted",
        parent_sync: str = "not_attempted",
    ) -> None:
        super().__init__(reason)
        self.reason = reason
        self.path = path
        self.stage = stage
        self.transaction_committed = transaction_committed
        self.from_version = from_version
        self.to_version = to_version
        self.backup_path = backup_path
        self.permissions = permissions
        self.parent_sync = parent_sync


@dataclass(frozen=True, slots=True)
class SQLiteMigrationResult:
    """Typed initialization or migration outcome for one physical database."""

    path: Path
    initialized: bool
    migrated: bool
    transaction_committed: bool
    from_version: int
    to_version: int
    backup_path: Path | None
    permissions: str
    parent_sync: str


@dataclass(frozen=True, slots=True)
class SQLiteIndexStructure:
    """Finite semantic shape of one SQLite index."""

    name: str
    unique: bool
    origin: str
    partial: bool
    columns: tuple[tuple[str | None, bool, str, bool], ...]


@dataclass(frozen=True, slots=True)
class SQLiteTableStructure:
    """Constraint/index semantics not represented by table column metadata."""

    without_rowid: bool
    strict: bool
    foreign_keys: tuple[tuple[object, ...], ...]
    constraint_keywords: tuple[str, ...]
    indexes: tuple[SQLiteIndexStructure, ...]


def sqlite_table_structure_matches(
    connection: sqlite3.Connection,
    expected_connection: sqlite3.Connection,
    table: str,
    *,
    require_complete: bool,
) -> bool:
    """Compare finite SQLite constraint/index metadata for one known table."""

    actual = _sqlite_table_structure(connection, table)
    expected = _sqlite_table_structure(expected_connection, table)
    if (
        actual.without_rowid != expected.without_rowid
        or actual.strict != expected.strict
        or actual.foreign_keys != expected.foreign_keys
        or actual.constraint_keywords != expected.constraint_keywords
    ):
        return False
    actual_indexes = {index.name: index for index in actual.indexes}
    expected_indexes = {index.name: index for index in expected.indexes}
    if require_complete:
        return actual_indexes == expected_indexes
    return all(expected_indexes.get(name) == index for name, index in actual_indexes.items())


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
    existed: bool | None = None
    connection: sqlite3.Connection | None = None
    in_transaction = False
    committed = False
    stage = SQLiteMigrationStage.ADMISSION
    from_version: int | None = None
    backup_path: Path | None = None
    permissions = "not_attempted"
    parent_sync = "not_attempted"
    inject = fault_injector or (lambda _stage: None)
    try:
        existed = _prepare_database_path(database_path, label=label)
        if not existed and _migration_backup_exists(database_path):
            raise SQLiteMigrationError(
                f"{label} migration backup exists without its database; "
                "restore or relocate it before fresh initialization"
            )
        if existed and database_path.stat().st_size == 0:
            raise SQLiteMigrationError(f"existing {label} database is empty or unversioned")

        connection = sqlite3.connect(database_path, timeout=5.0, isolation_level=None)
        connection.execute("PRAGMA busy_timeout = 5000")
        connection.execute("PRAGMA synchronous = FULL")
        if existed:
            _checkpoint_wal(connection, label=label)
        connection.execute("BEGIN IMMEDIATE")
        in_transaction = True
        version = int(connection.execute("PRAGMA user_version").fetchone()[0])
        from_version = version
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
            stage = SQLiteMigrationStage.PERMISSIONS
            permissions = _require_permissions(database_path, label=label)
            stage = SQLiteMigrationStage.PARENT_SYNC
            parent_sync = sync_parent_directory(database_path.parent)
            return SQLiteMigrationResult(
                path=database_path,
                initialized=True,
                migrated=False,
                transaction_committed=True,
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
            stage = SQLiteMigrationStage.PERMISSIONS
            permissions = _require_permissions(database_path, label=label)
            return SQLiteMigrationResult(
                path=database_path,
                initialized=False,
                migrated=False,
                transaction_committed=False,
                from_version=version,
                to_version=version,
                backup_path=None,
                permissions=permissions,
                parent_sync="not_applicable",
            )
        if version not in migrations:
            raise SQLiteMigrationError(
                f"{label} database has no ordered migration from schema version {version}"
            )

        validate_legacy(connection)
        backup_path = database_path.with_name(f"{database_path.name}.pre-v{version + 1}.bak")
        stage = SQLiteMigrationStage.BACKUP
        backup_path, permissions, parent_sync = _preserve_exact_backup(
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
        stage = SQLiteMigrationStage.PERMISSIONS
        backup_permissions = permissions
        permissions = _require_permissions(database_path, label=label)
        return SQLiteMigrationResult(
            path=database_path,
            initialized=False,
            migrated=True,
            transaction_committed=True,
            from_version=migrated_from,
            to_version=version,
            backup_path=backup_path,
            permissions=combine_permission_capabilities(backup_permissions, permissions),
            parent_sync=parent_sync,
        )
    except SQLiteMigrationError as exc:
        if in_transaction and connection is not None:
            with contextlib.suppress(sqlite3.Error):
                connection.rollback()
        raise _enrich_migration_error(
            exc,
            path=database_path,
            stage=stage,
            transaction_committed=committed,
            from_version=from_version,
            to_version=current_version,
            backup_path=backup_path,
            permissions=permissions,
            parent_sync=parent_sync,
        ) from exc
    except (OSError, sqlite3.Error) as exc:
        if in_transaction and connection is not None:
            with contextlib.suppress(sqlite3.Error):
                connection.rollback()
        raise SQLiteMigrationError(
            f"{label} database migration failed at {stage.value}: {exc.__class__.__name__}",
            path=database_path,
            stage=stage,
            transaction_committed=committed,
            from_version=from_version,
            to_version=current_version,
            backup_path=backup_path,
            permissions=permissions,
            parent_sync=("failed" if stage is SQLiteMigrationStage.PARENT_SYNC else parent_sync),
        ) from exc
    finally:
        if connection is not None:
            with contextlib.suppress(sqlite3.Error):
                connection.close()
        if existed is False and not committed:
            for candidate in (
                database_path,
                database_path.with_name(f"{database_path.name}-journal"),
                database_path.with_name(f"{database_path.name}-wal"),
                database_path.with_name(f"{database_path.name}-shm"),
            ):
                with contextlib.suppress(OSError):
                    candidate.unlink()


def _enrich_migration_error(
    error: SQLiteMigrationError,
    *,
    path: Path,
    stage: SQLiteMigrationStage,
    transaction_committed: bool,
    from_version: int | None,
    to_version: int,
    backup_path: Path | None,
    permissions: str,
    parent_sync: str,
) -> SQLiteMigrationError:
    return SQLiteMigrationError(
        error.reason,
        path=path,
        stage=stage,
        transaction_committed=transaction_committed,
        from_version=from_version,
        to_version=to_version,
        backup_path=error.backup_path or backup_path,
        permissions=(error.permissions if error.permissions != "not_attempted" else permissions),
        parent_sync=(error.parent_sync if error.parent_sync != "not_attempted" else parent_sync),
    )


def _sqlite_table_structure(
    connection: sqlite3.Connection,
    table: str,
) -> SQLiteTableStructure:
    table_row = next(
        (
            row
            for row in connection.execute("PRAGMA table_list").fetchall()
            if str(row[0]) == "main" and str(row[1]) == table
        ),
        None,
    )
    if table_row is None:
        raise SQLiteMigrationError(f"SQLite table structure is missing for {table}")
    quoted_table = _quote_sqlite_identifier(table)
    foreign_keys = tuple(
        tuple(row) for row in connection.execute(f"PRAGMA foreign_key_list({quoted_table})")
    )
    sql_row = connection.execute(
        "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?",
        (table,),
    ).fetchone()
    sql = "" if sql_row is None or sql_row[0] is None else str(sql_row[0])
    constraint_keywords = tuple(
        keyword
        for keyword in _SCHEMA_CONSTRAINT_KEYWORDS
        if re.search(rf"(?i)(?<![A-Z0-9_]){keyword}(?![A-Z0-9_])", sql)
    )
    indexes: list[SQLiteIndexStructure] = []
    for row in connection.execute(f"PRAGMA index_list({quoted_table})").fetchall():
        name = str(row[1])
        quoted_index = _quote_sqlite_identifier(name)
        columns = tuple(
            (
                None if detail[2] is None else str(detail[2]),
                bool(detail[3]),
                str(detail[4]),
                bool(detail[5]),
            )
            for detail in connection.execute(f"PRAGMA index_xinfo({quoted_index})").fetchall()
        )
        indexes.append(
            SQLiteIndexStructure(
                name=name,
                unique=bool(row[2]),
                origin=str(row[3]),
                partial=bool(row[4]),
                columns=columns,
            )
        )
    return SQLiteTableStructure(
        without_rowid=bool(table_row[4]),
        strict=bool(table_row[5]),
        foreign_keys=foreign_keys,
        constraint_keywords=constraint_keywords,
        indexes=tuple(sorted(indexes, key=lambda index: index.name)),
    )


def _quote_sqlite_identifier(value: str) -> str:
    return '"' + value.replace('"', '""') + '"'


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
        try:
            parent_sync = sync_parent_directory(source.parent)
        except OSError as exc:
            raise SQLiteMigrationError(
                f"cannot preserve {label} migration backup: {exc.__class__.__name__}",
                backup_path=backup,
                permissions=permissions,
                parent_sync="failed",
            ) from exc
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
        raise SQLiteMigrationError(
            f"{label} permissions could not be tightened",
            permissions="failed",
        )
    return permissions
