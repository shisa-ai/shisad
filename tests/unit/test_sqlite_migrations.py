"""O4B physical SQLite version and migration contracts."""

from __future__ import annotations

import os
import sqlite3
from pathlib import Path

import pytest

import shisad.core.sqlite_migration as sqlite_migration
from shisad.core.sqlite_migration import SQLiteMigrationError, SQLiteMigrationStage
from shisad.memory.sqlite_schema import prepare_memory_database
from shisad.memory.timeline import prepare_timeline_database


def _create_legacy_memory_database(path: Path) -> bytes:
    path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(path) as connection:
        connection.execute(
            """
            CREATE TABLE memory_events (
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
            INSERT INTO memory_events (
                event_id, entry_id, event_type, timestamp, actor,
                ingress_handle_id, metadata_json
            ) VALUES ('event-1', 'entry-1', 'created', '2026-08-16T00:00:00+00:00',
                      'test', NULL, '{}')
            """
        )
    return path.read_bytes()


def _create_legacy_timeline_database(path: Path) -> bytes:
    path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(path) as connection:
        connection.execute(
            """
            CREATE TABLE timeline_rows (
                handle TEXT PRIMARY KEY,
                session_id TEXT NOT NULL,
                episode_id TEXT NOT NULL,
                episode_index INTEGER NOT NULL,
                entry_id TEXT NOT NULL,
                role TEXT NOT NULL,
                content TEXT NOT NULL,
                snippet TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                user_id TEXT NOT NULL,
                workspace_id TEXT NOT NULL,
                channel TEXT NOT NULL,
                visibility TEXT NOT NULL,
                content_digest TEXT NOT NULL,
                evidence_ref_id TEXT NOT NULL,
                taint_labels TEXT NOT NULL,
                metadata_json TEXT NOT NULL,
                thread_id TEXT NOT NULL,
                related_memory_ids TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            INSERT INTO timeline_rows VALUES (
                'handle-1', 'session-1', 'episode-1', 1, 'entry-1', 'user',
                'durable content', 'durable content', '2026-08-16T00:00:00+00:00',
                'alice', 'default', 'cli', 'private', 'digest-1', 'evidence-1',
                '[]', '{}', 'thread-1', '[]'
            )
            """
        )
    return path.read_bytes()


def _user_version(path: Path) -> int:
    with sqlite3.connect(path) as connection:
        return int(connection.execute("PRAGMA user_version").fetchone()[0])


def test_o4b_fresh_memory_and_timeline_initialize_at_explicit_version_one(
    tmp_path: Path,
) -> None:
    memory = tmp_path / "memory" / "memory.sqlite3"
    timeline = tmp_path / "timeline" / "timeline.sqlite3"

    memory_result = prepare_memory_database(memory)
    timeline_result = prepare_timeline_database(timeline)

    assert memory_result.initialized is True
    assert memory_result.migrated is False
    assert memory_result.transaction_committed is True
    assert memory_result.backup_path is None
    assert timeline_result.initialized is True
    assert timeline_result.migrated is False
    assert timeline_result.transaction_committed is True
    assert timeline_result.backup_path is None
    assert _user_version(memory) == 1
    assert _user_version(timeline) == 1


def test_o4b_interrupted_fresh_initialization_removes_partial_database(
    tmp_path: Path,
) -> None:
    path = tmp_path / "memory" / "memory.sqlite3"

    def _interrupt(stage: SQLiteMigrationStage) -> None:
        if stage is SQLiteMigrationStage.BEFORE_COMMIT:
            raise OSError("simulated fresh initialization interruption")

    with pytest.raises(SQLiteMigrationError, match="before_commit"):
        prepare_memory_database(path, fault_injector=_interrupt)

    assert not path.exists()
    result = prepare_memory_database(path)
    assert result.initialized is True
    assert _user_version(path) == 1


def test_o4b_memory_legacy_migration_preserves_rows_and_exact_backup(
    tmp_path: Path,
) -> None:
    path = tmp_path / "memory" / "memory.sqlite3"
    original = _create_legacy_memory_database(path)

    result = prepare_memory_database(path)

    backup = path.with_name("memory.sqlite3.pre-v1.bak")
    assert result.initialized is False
    assert result.migrated is True
    assert result.transaction_committed is True
    assert result.from_version == 0
    assert result.to_version == 1
    assert result.backup_path == backup
    assert backup.read_bytes() == original
    assert _user_version(backup) == 0
    assert _user_version(path) == 1
    with sqlite3.connect(path) as connection:
        tables = {
            str(row[0])
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
            )
        }
        row = connection.execute(
            "SELECT entry_id, metadata_json FROM memory_events WHERE event_id='event-1'"
        ).fetchone()
    assert {
        "memory_entries",
        "memory_events",
        "retrieval_keys",
        "retrieval_metadata",
        "retrieval_records",
        "retrieval_vectors",
    } <= tables
    assert row == ("entry-1", "{}")


def test_o4b_timeline_legacy_migration_preserves_rows_and_defaults(
    tmp_path: Path,
) -> None:
    path = tmp_path / "timeline" / "timeline.sqlite3"
    original = _create_legacy_timeline_database(path)

    result = prepare_timeline_database(path)

    backup = path.with_name("timeline.sqlite3.pre-v1.bak")
    assert result.migrated is True
    assert result.backup_path == backup
    assert backup.read_bytes() == original
    assert _user_version(path) == 1
    with sqlite3.connect(path) as connection:
        row = connection.execute(
            """
            SELECT content, channel_binding, source_surface, provenance
            FROM timeline_rows WHERE handle='handle-1'
            """
        ).fetchone()
    assert row == ("durable content", "", "transcript", "transcript")


def test_o4b_interrupted_memory_migration_rolls_back_and_retry_reuses_backup(
    tmp_path: Path,
) -> None:
    path = tmp_path / "memory" / "memory.sqlite3"
    original = _create_legacy_memory_database(path)

    def _interrupt(stage: SQLiteMigrationStage) -> None:
        if stage is SQLiteMigrationStage.MIGRATION_APPLIED:
            raise OSError("simulated migration interruption")

    with pytest.raises(SQLiteMigrationError, match="migration_applied"):
        prepare_memory_database(path, fault_injector=_interrupt)

    backup = path.with_name("memory.sqlite3.pre-v1.bak")
    assert path.read_bytes() == original
    assert backup.read_bytes() == original
    assert _user_version(path) == 0

    result = prepare_memory_database(path)

    assert result.migrated is True
    assert result.backup_path == backup
    assert backup.read_bytes() == original
    assert _user_version(path) == 1


@pytest.mark.parametrize("kind", ["memory", "timeline"])
def test_o4b_newer_database_refuses_without_downgrade_or_backup(
    tmp_path: Path,
    kind: str,
) -> None:
    path = tmp_path / kind / f"{kind}.sqlite3"
    prepare = prepare_memory_database if kind == "memory" else prepare_timeline_database
    prepare(path)
    before = path.read_bytes()
    with sqlite3.connect(path) as connection:
        connection.execute("PRAGMA user_version = 2")
    newer = path.read_bytes()

    with pytest.raises(SQLiteMigrationError, match="will not downgrade"):
        prepare(path)

    assert newer != before
    assert path.read_bytes() == newer
    assert not path.with_name(f"{path.name}.pre-v1.bak").exists()


@pytest.mark.parametrize("kind", ["memory", "timeline"])
def test_o4b_unknown_unversioned_database_refuses_without_mutation(
    tmp_path: Path,
    kind: str,
) -> None:
    path = tmp_path / kind / f"{kind}.sqlite3"
    path.parent.mkdir(parents=True)
    with sqlite3.connect(path) as connection:
        connection.execute("CREATE TABLE unrelated_state(value TEXT)")
    before = path.read_bytes()
    prepare = prepare_memory_database if kind == "memory" else prepare_timeline_database

    with pytest.raises(SQLiteMigrationError, match="unrecognized legacy schema"):
        prepare(path)

    assert path.read_bytes() == before
    assert not path.with_name(f"{path.name}.pre-v1.bak").exists()


@pytest.mark.parametrize("derived_only", [False, True])
def test_o4b_memory_legacy_requires_a_recognized_stable_object(
    tmp_path: Path,
    derived_only: bool,
) -> None:
    path = tmp_path / "memory" / "memory.sqlite3"
    path.parent.mkdir()
    with sqlite3.connect(path) as connection:
        if derived_only:
            connection.execute("CREATE TABLE retrieval_lexical(chunk_id TEXT)")
        else:
            connection.execute("CREATE TABLE discarded(value TEXT)")
            connection.execute("DROP TABLE discarded")
    before = path.read_bytes()

    with pytest.raises(SQLiteMigrationError, match="unrecognized legacy schema"):
        prepare_memory_database(path)

    assert path.read_bytes() == before
    assert not path.with_name("memory.sqlite3.pre-v1.bak").exists()


@pytest.mark.parametrize("kind", ["memory", "timeline"])
def test_o4b_legacy_same_named_index_with_wrong_target_is_refused(
    tmp_path: Path,
    kind: str,
) -> None:
    path = tmp_path / kind / f"{kind}.sqlite3"
    if kind == "memory":
        _create_legacy_memory_database(path)
        index_sql = (
            "CREATE INDEX idx_memory_events_entry_timestamp ON memory_events(actor, timestamp)"
        )
        prepare = prepare_memory_database
    else:
        _create_legacy_timeline_database(path)
        index_sql = "CREATE INDEX idx_timeline_owner_time ON timeline_rows(session_id, timestamp)"
        prepare = prepare_timeline_database
    with sqlite3.connect(path) as connection:
        connection.execute(index_sql)
    before = path.read_bytes()

    with pytest.raises(SQLiteMigrationError, match="unrecognized legacy schema"):
        prepare(path)

    assert path.read_bytes() == before
    assert not path.with_name(f"{path.name}.pre-v1.bak").exists()


@pytest.mark.parametrize("constraint", ["UNIQUE", "CHECK(length(actor) > 0)"])
def test_o4b_memory_legacy_with_extra_constraint_is_refused(
    tmp_path: Path,
    constraint: str,
) -> None:
    path = tmp_path / "memory" / "memory.sqlite3"
    path.parent.mkdir()
    with sqlite3.connect(path) as connection:
        connection.execute(
            f"""
            CREATE TABLE memory_events (
                event_id TEXT PRIMARY KEY,
                entry_id TEXT NOT NULL,
                event_type TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                actor TEXT NOT NULL {constraint},
                ingress_handle_id TEXT,
                metadata_json TEXT NOT NULL
            )
            """
        )
    before = path.read_bytes()

    with pytest.raises(SQLiteMigrationError, match="unrecognized legacy schema"):
        prepare_memory_database(path)

    assert path.read_bytes() == before
    assert not path.with_name("memory.sqlite3.pre-v1.bak").exists()


def test_o4b_timeline_legacy_with_extra_check_constraint_is_refused(
    tmp_path: Path,
) -> None:
    template = tmp_path / "template.sqlite3"
    _create_legacy_timeline_database(template)
    with sqlite3.connect(template) as connection:
        create_sql = str(
            connection.execute(
                "SELECT sql FROM sqlite_master WHERE name = 'timeline_rows'"
            ).fetchone()[0]
        )
    path = tmp_path / "timeline" / "timeline.sqlite3"
    path.parent.mkdir()
    with sqlite3.connect(path) as connection:
        connection.execute(
            create_sql.replace(
                "content TEXT NOT NULL",
                "content TEXT NOT NULL CHECK(length(content) > 0)",
            )
        )
    before = path.read_bytes()

    with pytest.raises(SQLiteMigrationError, match="unrecognized legacy schema"):
        prepare_timeline_database(path)

    assert path.read_bytes() == before
    assert not path.with_name("timeline.sqlite3.pre-v1.bak").exists()


def test_o4b_current_same_named_unique_index_with_wrong_semantics_is_refused(
    tmp_path: Path,
) -> None:
    path = tmp_path / "memory" / "memory.sqlite3"
    prepare_memory_database(path)
    with sqlite3.connect(path) as connection:
        connection.execute("DROP INDEX idx_memory_events_entry_timestamp")
        connection.execute(
            "CREATE UNIQUE INDEX idx_memory_events_entry_timestamp "
            "ON memory_events(entry_id, timestamp)"
        )
    before = path.read_bytes()

    with pytest.raises(SQLiteMigrationError, match="current schema"):
        prepare_memory_database(path)

    assert path.read_bytes() == before
    assert not path.with_name("memory.sqlite3.pre-v1.bak").exists()


def test_o4b_existing_empty_or_symlink_database_is_refused(tmp_path: Path) -> None:
    empty = tmp_path / "empty" / "memory.sqlite3"
    empty.parent.mkdir()
    empty.write_bytes(b"")
    with pytest.raises(SQLiteMigrationError, match="empty or unversioned"):
        prepare_memory_database(empty)
    assert empty.read_bytes() == b""

    target = tmp_path / "target.sqlite3"
    target.write_bytes(b"not sqlite")
    linked = tmp_path / "linked.sqlite3"
    linked.symlink_to(target)
    with pytest.raises(SQLiteMigrationError, match="symlink"):
        prepare_memory_database(linked)
    assert target.read_bytes() == b"not sqlite"


def test_o4b_orphan_migration_backup_refuses_fresh_initialization(
    tmp_path: Path,
) -> None:
    path = tmp_path / "memory" / "memory.sqlite3"
    path.parent.mkdir()
    backup = path.with_name("memory.sqlite3.pre-v1.bak")
    backup.write_bytes(b"retained legacy evidence")

    with pytest.raises(SQLiteMigrationError, match="backup exists without its database"):
        prepare_memory_database(path)

    assert not path.exists()
    assert backup.read_bytes() == b"retained legacy evidence"


def test_o4b_symlink_migration_backup_is_refused_without_mutation(tmp_path: Path) -> None:
    path = tmp_path / "memory" / "memory.sqlite3"
    before = _create_legacy_memory_database(path)
    target = tmp_path / "unsafe-backup-target"
    target.write_bytes(b"not a rollback copy")
    backup = path.with_name("memory.sqlite3.pre-v1.bak")
    backup.symlink_to(target)

    with pytest.raises(SQLiteMigrationError, match="backup is unsafe"):
        prepare_memory_database(path)

    assert path.read_bytes() == before
    assert target.read_bytes() == b"not a rollback copy"
    assert _user_version(path) == 0


def test_o4b_mismatched_migration_backup_is_refused_without_mutation(
    tmp_path: Path,
) -> None:
    path = tmp_path / "memory" / "memory.sqlite3"
    before = _create_legacy_memory_database(path)
    backup = path.with_name("memory.sqlite3.pre-v1.bak")
    backup.write_bytes(b"not the selected legacy database")

    with pytest.raises(
        SQLiteMigrationError,
        match="does not match the legacy database",
    ) as excinfo:
        prepare_memory_database(path)

    assert excinfo.value.stage is SQLiteMigrationStage.BACKUP
    assert excinfo.value.transaction_committed is False
    assert excinfo.value.from_version == 0
    assert excinfo.value.to_version == 1
    assert excinfo.value.backup_path == backup
    assert path.read_bytes() == before
    assert backup.read_bytes() == b"not the selected legacy database"
    assert _user_version(path) == 0


def test_o4b_corrupt_database_is_refused_without_mutation_or_backup(tmp_path: Path) -> None:
    path = tmp_path / "memory" / "memory.sqlite3"
    path.parent.mkdir()
    before = b"not a SQLite database"
    path.write_bytes(before)

    with pytest.raises(SQLiteMigrationError, match="migration failed at admission"):
        prepare_memory_database(path)

    assert path.read_bytes() == before
    assert not path.with_name("memory.sqlite3.pre-v1.bak").exists()


def test_o4b_post_commit_failure_exposes_typed_lifecycle_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "memory" / "memory.sqlite3"

    def _fail_parent_sync(_parent: Path) -> str:
        raise OSError("simulated parent sync failure")

    monkeypatch.setattr(sqlite_migration, "sync_parent_directory", _fail_parent_sync)

    with pytest.raises(SQLiteMigrationError, match="parent_sync") as excinfo:
        prepare_memory_database(path)

    error = excinfo.value
    assert error.path == path
    assert error.stage is SQLiteMigrationStage.PARENT_SYNC
    assert error.transaction_committed is True
    assert error.from_version == 0
    assert error.to_version == 1
    assert error.backup_path is None
    assert error.permissions in {"supported", "unsupported"}
    assert error.parent_sync == "failed"
    assert _user_version(path) == 1


def test_o4b_post_commit_permission_failure_exposes_typed_lifecycle_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "memory" / "memory.sqlite3"
    monkeypatch.setattr(sqlite_migration, "tighten_permissions", lambda _path, _mode: "failed")

    with pytest.raises(SQLiteMigrationError, match="permissions") as excinfo:
        prepare_memory_database(path)

    error = excinfo.value
    assert error.path == path
    assert error.stage is SQLiteMigrationStage.PERMISSIONS
    assert error.transaction_committed is True
    assert error.from_version == 0
    assert error.to_version == 1
    assert error.backup_path is None
    assert error.permissions == "failed"
    assert error.parent_sync == "not_attempted"
    assert _user_version(path) == 1


def test_o4b_admission_oserror_is_wrapped_with_typed_lifecycle_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "memory" / "memory.sqlite3"

    def _fail_backup_scan(_path: Path) -> bool:
        raise OSError("simulated directory read failure")

    monkeypatch.setattr(sqlite_migration, "_migration_backup_exists", _fail_backup_scan)

    with pytest.raises(SQLiteMigrationError, match="migration failed at admission") as excinfo:
        prepare_memory_database(path)

    error = excinfo.value
    assert error.path == path
    assert error.stage is SQLiteMigrationStage.ADMISSION
    assert error.transaction_committed is False
    assert error.from_version is None
    assert error.to_version == 1
    assert error.backup_path is None
    assert error.permissions == "not_attempted"
    assert error.parent_sync == "not_attempted"
    assert not path.exists()


def test_o4b_current_database_is_validated_without_backup_or_mutation(tmp_path: Path) -> None:
    path = tmp_path / "memory" / "memory.sqlite3"
    prepare_memory_database(path)
    before = path.read_bytes()

    result = prepare_memory_database(path)

    assert result.initialized is False
    assert result.migrated is False
    assert result.transaction_committed is False
    assert result.from_version == result.to_version == 1
    assert result.backup_path is None
    assert path.read_bytes() == before
    assert result.permissions in {"supported", "unsupported"}
    assert result.parent_sync in {"supported", "unsupported", "not_applicable"}
    if os.name == "posix":
        assert path.stat().st_mode & 0o777 == 0o600
