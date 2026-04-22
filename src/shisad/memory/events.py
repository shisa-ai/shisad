"""Append-only memory event log primitives."""

from __future__ import annotations

import json
import sqlite3
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field, ValidationError


class MemoryEvent(BaseModel):
    """Canonical append-only memory event record."""

    event_id: str = Field(default_factory=lambda: uuid.uuid4().hex)
    entry_id: str
    event_type: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    actor: str = "memory_manager"
    ingress_handle_id: str | None = None
    metadata_json: dict[str, Any] = Field(default_factory=dict)


class MemoryEventStore:
    """SQLite-backed append-only event store for memory lifecycle events."""

    def __init__(self, path: Path) -> None:
        self._path = path
        self._legacy_jsonl_path = path.with_suffix(".jsonl")
        self._path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            self._ensure_schema(conn)
            self._import_legacy_jsonl_if_needed(conn)

    def append(self, event: MemoryEvent) -> MemoryEvent:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO memory_events (
                    event_id,
                    entry_id,
                    event_type,
                    timestamp,
                    actor,
                    ingress_handle_id,
                    metadata_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event.event_id,
                    event.entry_id,
                    event.event_type,
                    event.timestamp.isoformat(),
                    event.actor,
                    event.ingress_handle_id,
                    json.dumps(event.metadata_json, sort_keys=True),
                ),
            )
        return event

    def list(
        self,
        *,
        entry_id: str | None = None,
        event_type: str | None = None,
        limit: int = 100,
    ) -> list[MemoryEvent]:
        if limit <= 0 or not self._path.exists():
            return []
        predicates: list[str] = []
        params: list[Any] = []
        if entry_id is not None:
            predicates.append("entry_id = ?")
            params.append(entry_id)
        if event_type is not None:
            predicates.append("event_type = ?")
            params.append(event_type)
        where = f"WHERE {' AND '.join(predicates)}" if predicates else ""
        query = f"""
            SELECT
                event_id,
                entry_id,
                event_type,
                timestamp,
                actor,
                ingress_handle_id,
                metadata_json
            FROM memory_events
            {where}
            ORDER BY timestamp DESC, rowid DESC
            LIMIT ?
        """
        params.append(limit)
        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        events: list[MemoryEvent] = []
        for row in reversed(rows):
            try:
                events.append(
                    MemoryEvent(
                        event_id=str(row["event_id"]),
                        entry_id=str(row["entry_id"]),
                        event_type=str(row["event_type"]),
                        timestamp=datetime.fromisoformat(str(row["timestamp"])),
                        actor=str(row["actor"]),
                        ingress_handle_id=(
                            str(row["ingress_handle_id"])
                            if row["ingress_handle_id"] is not None
                            else None
                        ),
                        metadata_json=json.loads(str(row["metadata_json"])),
                    )
                )
            except (TypeError, ValueError, ValidationError, json.JSONDecodeError):
                continue
        return events

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._path)
        conn.row_factory = sqlite3.Row
        return conn

    @staticmethod
    def _ensure_schema(conn: sqlite3.Connection) -> None:
        conn.execute(
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
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_memory_events_entry_timestamp
            ON memory_events (entry_id, timestamp)
            """
        )
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_memory_events_type_timestamp
            ON memory_events (event_type, timestamp)
            """
        )

    def _import_legacy_jsonl_if_needed(self, conn: sqlite3.Connection) -> None:
        if not self._legacy_jsonl_path.exists():
            return
        row = conn.execute("SELECT COUNT(*) FROM memory_events").fetchone()
        existing = int(row[0]) if row is not None else 0
        if existing:
            return
        with self._legacy_jsonl_path.open(encoding="utf-8") as handle:
            for line in handle:
                payload = line.strip()
                if not payload:
                    continue
                try:
                    event = MemoryEvent.model_validate_json(payload)
                except ValidationError:
                    continue
                conn.execute(
                    """
                    INSERT OR IGNORE INTO memory_events (
                        event_id,
                        entry_id,
                        event_type,
                        timestamp,
                        actor,
                        ingress_handle_id,
                        metadata_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        event.event_id,
                        event.entry_id,
                        event.event_type,
                        event.timestamp.isoformat(),
                        event.actor,
                        event.ingress_handle_id,
                        json.dumps(event.metadata_json, sort_keys=True),
                    ),
                )
