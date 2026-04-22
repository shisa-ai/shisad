"""Append-only memory event log primitives."""

from __future__ import annotations

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
    """Lightweight append-only JSONL event store for memory lifecycle events."""

    def __init__(self, path: Path) -> None:
        self._path = path

    def append(self, event: MemoryEvent) -> MemoryEvent:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        with self._path.open("a", encoding="utf-8") as handle:
            handle.write(event.model_dump_json() + "\n")
        return event

    def list(
        self,
        *,
        entry_id: str | None = None,
        event_type: str | None = None,
        limit: int = 100,
    ) -> list[MemoryEvent]:
        if not self._path.exists():
            return []

        events: list[MemoryEvent] = []
        with self._path.open(encoding="utf-8") as handle:
            for line in handle:
                row = line.strip()
                if not row:
                    continue
                try:
                    event = MemoryEvent.model_validate_json(row)
                except ValidationError:
                    continue
                if entry_id is not None and event.entry_id != entry_id:
                    continue
                if event_type is not None and event.event_type != event_type:
                    continue
                events.append(event)
        if limit <= 0:
            return []
        return events[-limit:]
