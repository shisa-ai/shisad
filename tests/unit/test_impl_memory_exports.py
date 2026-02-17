"""Regression tests for memory export type-aware slicing."""

from __future__ import annotations

from typing import Any

import pytest

from shisad.daemon.handlers._impl_memory import MemoryImplMixin


class _StubEntry:
    def __init__(self, *, entry_type: str) -> None:
        self.entry_type = entry_type

    def model_dump(self, *, mode: str) -> dict[str, Any]:
        _ = mode
        return {
            "id": "entry-1",
            "entry_type": self.entry_type,
            "key": "k",
            "value": {"title": "t", "status": "open", "due_date": ""},
            "created_at": "2026-02-17T00:00:00+00:00",
            "user_verified": True,
            "deleted_at": "",
        }


class _SpyMemoryManager:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    def list_entries(self, **kwargs: Any) -> list[_StubEntry]:
        self.calls.append(dict(kwargs))
        return [_StubEntry(entry_type=str(kwargs.get("entry_type", "")))]


class _StubMemoryHandler(MemoryImplMixin):
    def __init__(self) -> None:
        self._memory_manager = _SpyMemoryManager()


@pytest.mark.asyncio
async def test_note_export_uses_type_aware_limit_query() -> None:
    handler = _StubMemoryHandler()

    payload = await handler.do_note_export({"format": "json"})

    assert payload["format"] == "json"
    assert handler._memory_manager.calls[0]["entry_type"] == "note"
    assert handler._memory_manager.calls[0]["include_deleted"] is True
    assert handler._memory_manager.calls[0]["limit"] == 2000


@pytest.mark.asyncio
async def test_todo_export_uses_type_aware_limit_query() -> None:
    handler = _StubMemoryHandler()

    payload = await handler.do_todo_export({"format": "json"})

    assert payload["format"] == "json"
    assert handler._memory_manager.calls[0]["entry_type"] == "todo"
    assert handler._memory_manager.calls[0]["include_deleted"] is True
    assert handler._memory_manager.calls[0]["limit"] == 2000
