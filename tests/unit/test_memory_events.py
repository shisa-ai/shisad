"""Unit coverage for the append-only memory event store."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from shisad.memory.events import MemoryEvent, MemoryEventStore


def test_m1_memory_event_store_persists_events_in_sqlite_table(tmp_path: Path) -> None:
    db_path = tmp_path / "memory_events.sqlite3"
    store = MemoryEventStore(db_path)

    first = store.append(
        MemoryEvent(
            entry_id="entry-1",
            event_type="created",
            ingress_handle_id="handle-1",
            metadata_json={"status": "active"},
        )
    )
    second = store.append(
        MemoryEvent(
            entry_id="entry-1",
            event_type="workflow_state_changed",
            metadata_json={"from": "active", "to": "waiting"},
        )
    )

    assert db_path.exists()
    listed = store.list(entry_id="entry-1", limit=10)
    assert [event.event_id for event in listed] == [first.event_id, second.event_id]
    assert [event.event_type for event in listed] == ["created", "workflow_state_changed"]

    conn = sqlite3.connect(db_path)
    try:
        columns = [row[1] for row in conn.execute("PRAGMA table_info(memory_events)")]
        assert columns == [
            "event_id",
            "entry_id",
            "event_type",
            "timestamp",
            "actor",
            "ingress_handle_id",
            "metadata_json",
        ]
        row = conn.execute(
            "SELECT metadata_json FROM memory_events WHERE event_id = ?",
            (first.event_id,),
        ).fetchone()
    finally:
        conn.close()

    assert row is not None
    assert json.loads(str(row[0])) == {"status": "active"}


def test_m1_memory_event_store_imports_legacy_jsonl_records(tmp_path: Path) -> None:
    db_path = tmp_path / "memory_events.sqlite3"
    legacy_path = tmp_path / "memory_events.jsonl"
    legacy_event = MemoryEvent(
        entry_id="entry-legacy",
        event_type="verified",
        metadata_json={"source": "legacy-jsonl"},
    )
    legacy_path.write_text(legacy_event.model_dump_json() + "\n", encoding="utf-8")

    store = MemoryEventStore(db_path)

    listed = store.list(entry_id="entry-legacy", limit=10)
    assert [event.event_id for event in listed] == [legacy_event.event_id]
    assert listed[0].metadata_json == {"source": "legacy-jsonl"}

    conn = sqlite3.connect(db_path)
    try:
        count = conn.execute("SELECT COUNT(*) FROM memory_events").fetchone()
    finally:
        conn.close()

    assert count is not None
    assert count[0] == 1


def test_m1_memory_event_store_returns_latest_entry_snapshots(tmp_path: Path) -> None:
    db_path = tmp_path / "memory_events.sqlite3"
    store = MemoryEventStore(db_path)

    store.append(
        MemoryEvent(
            entry_id="entry-1",
            event_type="created",
            metadata_json={"entry_snapshot": {"id": "entry-1", "status": "active", "version": 1}},
        )
    )
    store.append(
        MemoryEvent(
            entry_id="entry-1",
            event_type="quarantined",
            metadata_json={
                "entry_snapshot": {"id": "entry-1", "status": "quarantined", "version": 1}
            },
        )
    )
    store.append(
        MemoryEvent(
            entry_id="entry-2",
            event_type="created",
            metadata_json={"entry_snapshot": {"id": "entry-2", "status": "active", "version": 1}},
        )
    )

    snapshots = store.latest_entry_snapshots()

    assert snapshots == [
        {"id": "entry-1", "status": "quarantined", "version": 1},
        {"id": "entry-2", "status": "active", "version": 1},
    ]
