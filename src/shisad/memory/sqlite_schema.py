"""Single physical schema authority for the shared memory SQLite database."""

from __future__ import annotations

import sqlite3
from pathlib import Path

from shisad.core.sqlite_migration import (
    SQLiteMigrationError,
    SQLiteMigrationFaultInjector,
    SQLiteMigrationResult,
    prepare_versioned_sqlite_database,
)

MEMORY_DATABASE_SCHEMA_VERSION = 1
_DERIVED_SEARCH_OBJECTS = frozenset(
    {
        ("table", "retrieval_fts"),
        ("table", "retrieval_fts_config"),
        ("table", "retrieval_fts_content"),
        ("table", "retrieval_fts_data"),
        ("table", "retrieval_fts_docsize"),
        ("table", "retrieval_fts_idx"),
        ("table", "retrieval_lexical"),
    }
)


def prepare_memory_database(
    path: Path,
    *,
    fault_injector: SQLiteMigrationFaultInjector | None = None,
) -> SQLiteMigrationResult:
    """Prepare the complete stable schema shared by all memory wrappers."""

    return prepare_versioned_sqlite_database(
        path,
        label="memory",
        current_version=MEMORY_DATABASE_SCHEMA_VERSION,
        initialize=_apply_memory_schema_v1,
        migrations={0: _apply_memory_schema_v1},
        validate_current=_validate_current_memory_schema,
        validate_legacy=_validate_legacy_memory_schema,
        fault_injector=fault_injector,
    )


def _apply_memory_schema_v1(connection: sqlite3.Connection) -> None:
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS retrieval_records (
            chunk_id TEXT PRIMARY KEY,
            source_id TEXT NOT NULL,
            source_type TEXT NOT NULL,
            collection TEXT NOT NULL,
            created_at TEXT NOT NULL,
            content_sanitized TEXT NOT NULL,
            extracted_facts_json TEXT NOT NULL,
            risk_score REAL NOT NULL,
            original_hash TEXT NOT NULL,
            source_origin TEXT,
            channel_trust TEXT,
            confirmation_status TEXT,
            scope TEXT,
            user_id TEXT,
            workspace_id TEXT,
            taint_labels_json TEXT NOT NULL,
            quarantined INTEGER NOT NULL,
            citation_count INTEGER NOT NULL DEFAULT 0,
            last_cited_at TEXT,
            original_payload BLOB NOT NULL
        )
        """
    )
    _add_missing_columns(
        connection,
        table="retrieval_records",
        columns={
            "citation_count": "citation_count INTEGER NOT NULL DEFAULT 0",
            "last_cited_at": "last_cited_at TEXT",
            "source_origin": "source_origin TEXT",
            "channel_trust": "channel_trust TEXT",
            "confirmation_status": "confirmation_status TEXT",
            "scope": "scope TEXT",
            "user_id": "user_id TEXT",
            "workspace_id": "workspace_id TEXT",
        },
    )
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS retrieval_vectors (
            chunk_id TEXT PRIMARY KEY,
            embedding_json TEXT NOT NULL
        )
        """
    )
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS retrieval_keys (
            key_id TEXT PRIMARY KEY,
            created_at TEXT NOT NULL,
            salt_b64 TEXT NOT NULL,
            nonce_b64 TEXT NOT NULL,
            wrapped_key_b64 TEXT NOT NULL
        )
        """
    )
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS retrieval_metadata (
            key TEXT PRIMARY KEY,
            value_text TEXT NOT NULL
        )
        """
    )
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS memory_events (
            event_id TEXT PRIMARY KEY,
            entry_id TEXT NOT NULL,
            event_type TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            actor TEXT NOT NULL,
            ingress_handle_id TEXT,
            metadata_json TEXT NOT NULL
        )
        """
    )
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS memory_entries (
            id TEXT PRIMARY KEY,
            version INTEGER NOT NULL,
            supersedes TEXT,
            superseded_by TEXT,
            entry_type TEXT NOT NULL,
            key TEXT NOT NULL,
            value_json TEXT NOT NULL,
            predicate TEXT,
            strength TEXT NOT NULL DEFAULT 'moderate',
            source_json TEXT NOT NULL,
            source_origin TEXT NOT NULL,
            channel_trust TEXT NOT NULL,
            confirmation_status TEXT NOT NULL,
            source_id TEXT NOT NULL,
            created_at TEXT NOT NULL,
            valid_from TEXT,
            valid_to TEXT,
            last_verified_at TEXT,
            expires_at TEXT,
            confidence REAL NOT NULL,
            taint_labels_json TEXT NOT NULL,
            citation_count INTEGER NOT NULL,
            last_cited_at TEXT,
            decay_score REAL NOT NULL,
            importance_weight REAL NOT NULL,
            status TEXT NOT NULL,
            workflow_state TEXT,
            scope TEXT NOT NULL,
            invocation_eligible INTEGER NOT NULL,
            ingress_handle_id TEXT,
            content_digest TEXT,
            conflict_entry_ids_json TEXT NOT NULL DEFAULT '[]',
            user_verified INTEGER NOT NULL,
            deleted_at TEXT,
            quarantined INTEGER NOT NULL
        )
        """
    )
    _add_missing_columns(
        connection,
        table="memory_entries",
        columns={
            "predicate": "predicate TEXT",
            "strength": "strength TEXT NOT NULL DEFAULT 'moderate'",
            "conflict_entry_ids_json": ("conflict_entry_ids_json TEXT NOT NULL DEFAULT '[]'"),
        },
    )
    for name, table, columns in (
        ("idx_retrieval_records_collection_created", "retrieval_records", "collection, created_at"),
        ("idx_retrieval_records_source_created", "retrieval_records", "source_id, created_at"),
        ("idx_retrieval_records_quarantined", "retrieval_records", "quarantined, created_at"),
        ("idx_retrieval_records_owner", "retrieval_records", "user_id, workspace_id, created_at"),
        ("idx_memory_events_entry_timestamp", "memory_events", "entry_id, timestamp"),
        ("idx_memory_events_type_timestamp", "memory_events", "event_type, timestamp"),
        ("idx_memory_entries_type_created", "memory_entries", "entry_type, created_at"),
        ("idx_memory_entries_status_created", "memory_entries", "status, created_at"),
        (
            "idx_memory_entries_workflow_created",
            "memory_entries",
            "workflow_state, created_at",
        ),
        (
            "idx_memory_entries_trust",
            "memory_entries",
            "source_origin, channel_trust, confirmation_status",
        ),
        ("idx_memory_entries_scope_created", "memory_entries", "scope, created_at"),
        ("idx_memory_entries_key_type", "memory_entries", "entry_type, key"),
        ("idx_memory_entries_supersedes", "memory_entries", "supersedes"),
        ("idx_memory_entries_superseded_by", "memory_entries", "superseded_by"),
    ):
        connection.execute(f"CREATE INDEX IF NOT EXISTS {name} ON {table} ({columns})")


def _add_missing_columns(
    connection: sqlite3.Connection,
    *,
    table: str,
    columns: dict[str, str],
) -> None:
    existing = {str(row[1]) for row in connection.execute(f"PRAGMA table_info({table})").fetchall()}
    for name, declaration in columns.items():
        if name not in existing:
            connection.execute(f"ALTER TABLE {table} ADD COLUMN {declaration}")


def _validate_legacy_memory_schema(connection: sqlite3.Connection) -> None:
    _validate_memory_schema(connection, require_complete=False)


def _validate_current_memory_schema(connection: sqlite3.Connection) -> None:
    _validate_memory_schema(connection, require_complete=True)


def _validate_memory_schema(
    connection: sqlite3.Connection,
    *,
    require_complete: bool,
) -> None:
    expected = _expected_schema()
    actual = _schema_objects(connection)
    unknown = {
        item for item in actual if item not in expected and not _is_derived_search_object(item)
    }
    if unknown:
        prefix = "current" if require_complete else "unrecognized legacy"
        raise SQLiteMigrationError(f"memory database has {prefix} schema objects")
    stable_actual = actual & expected
    if require_complete and stable_actual != expected:
        raise SQLiteMigrationError("memory database current schema is incomplete")
    for object_type, name in stable_actual:
        if object_type != "table":
            continue
        actual_columns = _column_shape(connection, name)
        expected_columns = _expected_column_shape(name)
        if require_complete:
            valid = actual_columns == expected_columns
        else:
            valid = bool(actual_columns) and all(
                expected_columns.get(column) == shape for column, shape in actual_columns.items()
            )
        if not valid:
            prefix = "current" if require_complete else "unrecognized legacy"
            raise SQLiteMigrationError(f"memory database has {prefix} schema for {name}")


def _expected_connection() -> sqlite3.Connection:
    connection = sqlite3.connect(":memory:")
    _apply_memory_schema_v1(connection)
    return connection


def _expected_schema() -> set[tuple[str, str]]:
    with _expected_connection() as connection:
        return _schema_objects(connection)


def _expected_column_shape(table: str) -> dict[str, tuple[str, int, object, int]]:
    with _expected_connection() as connection:
        return _column_shape(connection, table)


def _schema_objects(connection: sqlite3.Connection) -> set[tuple[str, str]]:
    return {
        (str(row[0]), str(row[1]))
        for row in connection.execute(
            "SELECT type, name FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'"
        ).fetchall()
    }


def _column_shape(
    connection: sqlite3.Connection,
    table: str,
) -> dict[str, tuple[str, int, object, int]]:
    return {
        str(row[1]): (str(row[2]).upper(), int(row[3]), row[4], int(row[5]))
        for row in connection.execute(f"PRAGMA table_info({table})").fetchall()
    }


def _is_derived_search_object(item: tuple[str, str]) -> bool:
    return item in _DERIVED_SEARCH_OBJECTS
