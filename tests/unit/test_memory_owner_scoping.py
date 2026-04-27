"""C2 memory (user, workspace) scoping: schema + recall filtering.

See planning/PLAN-lockdown-no-deadend.md §4.4 and
planning/v0.7/IMPLEMENTATION-v0.7.1.md memory-scoping punchlist.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

from shisad.memory.backend import RetrievalBackendRow
from shisad.memory.backend.sqlite import SQLiteRetrievalBackend
from shisad.memory.ingestion import IngestionPipeline, RetrievalResult
from shisad.memory.schema import MemoryEntry


def test_memory_entry_round_trips_owner_fields() -> None:
    entry = MemoryEntry.model_validate(
        {
            "entry_type": "note",
            "key": "k",
            "value": "v",
            "source": {
                "origin": "user",
                "source_id": "sid",
                "extraction_method": "t",
            },
            "source_origin": "user_direct",
            "channel_trust": "command",
            "confirmation_status": "user_asserted",
            "user_id": "ops",
            "workspace_id": "default",
        }
    )
    assert entry.user_id == "ops"
    assert entry.workspace_id == "default"
    payload = entry.model_dump(mode="json")
    assert payload["user_id"] == "ops"
    assert payload["workspace_id"] == "default"


def test_retrieval_result_round_trips_owner_fields() -> None:
    result = RetrievalResult.model_validate(
        {
            "chunk_id": "c",
            "source_id": "s",
            "source_type": "user",
            "collection": "user_curated",
            "created_at": "2026-04-27T00:00:00+00:00",
            "content_sanitized": "x",
            "risk_score": 0.0,
            "original_hash": "h",
            "user_id": "ops",
            "workspace_id": "default",
        }
    )
    assert result.user_id == "ops"
    assert result.workspace_id == "default"


def test_sqlite_migration_adds_owner_columns_idempotently(tmp_path: Path) -> None:
    db_path = tmp_path / "retrieval.sqlite3"
    # First init creates schema with owner columns.
    SQLiteRetrievalBackend(db_path)
    with sqlite3.connect(db_path) as conn:
        columns_before = {
            str(row[1])
            for row in conn.execute("PRAGMA table_info(retrieval_records)").fetchall()
        }
    assert "user_id" in columns_before
    assert "workspace_id" in columns_before

    # Re-initializing is a no-op (migration is idempotent).
    SQLiteRetrievalBackend(db_path)
    with sqlite3.connect(db_path) as conn:
        columns_after = {
            str(row[1])
            for row in conn.execute("PRAGMA table_info(retrieval_records)").fetchall()
        }
    assert columns_after == columns_before


def test_sqlite_migration_adds_owner_columns_to_prerework_table(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "retrieval.sqlite3"
    # Emulate a pre-C2 database: table without user_id/workspace_id.
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """
            CREATE TABLE retrieval_records (
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
                taint_labels_json TEXT NOT NULL,
                quarantined INTEGER NOT NULL,
                citation_count INTEGER NOT NULL DEFAULT 0,
                last_cited_at TEXT,
                original_payload BLOB NOT NULL
            )
            """
        )

    SQLiteRetrievalBackend(db_path)
    with sqlite3.connect(db_path) as conn:
        columns = {
            str(row[1])
            for row in conn.execute("PRAGMA table_info(retrieval_records)").fetchall()
        }
    assert "user_id" in columns
    assert "workspace_id" in columns


def test_compile_recall_filters_to_session_owner(tmp_path: Path) -> None:
    pipeline = IngestionPipeline(tmp_path / "memory")
    pipeline.ingest(
        source_id="ops-entry",
        source_type="user",
        content="ops-scoped note about preferred shell",
        collection="user_curated",
        user_id="ops",
        workspace_id="default",
    )
    pipeline.ingest(
        source_id="eval-entry",
        source_type="user",
        content="eval-scoped note about preferred shell",
        collection="user_curated",
        user_id="lus9-eval-fresh",
        workspace_id="local",
    )

    ops_pack = pipeline.compile_recall(
        "preferred shell",
        limit=5,
        user_id="ops",
        workspace_id="default",
    )
    ops_sources = {result.source_id for result in ops_pack.results}
    assert "ops-entry" in ops_sources
    assert "eval-entry" not in ops_sources

    eval_pack = pipeline.compile_recall(
        "preferred shell",
        limit=5,
        user_id="lus9-eval-fresh",
        workspace_id="local",
    )
    eval_sources = {result.source_id for result in eval_pack.results}
    assert "eval-entry" in eval_sources
    assert "ops-entry" not in eval_sources


def test_compile_recall_excludes_legacy_null_owner_rows_by_default(
    tmp_path: Path,
) -> None:
    pipeline = IngestionPipeline(tmp_path / "memory")
    # Legacy write: no owner fields (simulates pre-migration data).
    pipeline.ingest(
        source_id="legacy",
        source_type="user",
        content="legacy unowned note about shells",
        collection="user_curated",
    )

    # Scoped session must not see the legacy row.
    scoped_pack = pipeline.compile_recall(
        "shells",
        limit=5,
        user_id="ops",
        workspace_id="default",
    )
    assert scoped_pack.results == []

    # Explicit opt-in surfaces the legacy row — used for maintenance only.
    maint_pack = pipeline.compile_recall(
        "shells",
        limit=5,
        user_id="ops",
        workspace_id="default",
        include_unowned=True,
    )
    assert maint_pack.results
    assert maint_pack.results[0].source_id == "legacy"


def test_compile_recall_without_owner_args_preserves_prerework_behavior(
    tmp_path: Path,
) -> None:
    pipeline = IngestionPipeline(tmp_path / "memory")
    pipeline.ingest(
        source_id="legacy",
        source_type="user",
        content="legacy unowned note about shells",
        collection="user_curated",
    )
    pipeline.ingest(
        source_id="owned",
        source_type="user",
        content="ops-scoped note about shells",
        collection="user_curated",
        user_id="ops",
        workspace_id="default",
    )
    # No owner args -> filter is a no-op; both rows surface.
    pack = pipeline.compile_recall("shells", limit=5)
    sources = {r.source_id for r in pack.results}
    assert "legacy" in sources
    assert "owned" in sources


def test_retrieval_backend_row_round_trip_persists_owner(tmp_path: Path) -> None:
    db_path = tmp_path / "retrieval.sqlite3"
    backend = SQLiteRetrievalBackend(db_path)
    backend.upsert_record(
        row=RetrievalBackendRow(
            chunk_id="c1",
            source_id="s",
            source_type="user",
            collection="user_curated",
            created_at="2026-04-27T00:00:00+00:00",
            content_sanitized="hello",
            extracted_facts_json="[]",
            risk_score=0.0,
            original_hash="h",
            source_origin="user_direct",
            channel_trust="command",
            confirmation_status="user_asserted",
            scope="user",
            user_id="ops",
            workspace_id="default",
            taint_labels_json="[]",
            quarantined=False,
            citation_count=0,
            last_cited_at=None,
            embedding=[0.1, 0.2, 0.3],
        ),
        original_payload=b"payload",
    )
    rows = backend.list_records()
    assert len(rows) == 1
    assert rows[0].user_id == "ops"
    assert rows[0].workspace_id == "default"
