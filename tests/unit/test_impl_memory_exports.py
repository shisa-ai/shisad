"""Regression tests for memory export type-aware slicing."""

from __future__ import annotations

import json
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

    # HDL-L2: pin the output payload shape, not just the call arguments.
    # Previously a regression that returned an empty/malformed `data` field
    # would still pass because only the call-side arguments were asserted.
    assert isinstance(payload.get("data"), str)
    entries = json.loads(payload["data"])
    assert isinstance(entries, list) and len(entries) == 1
    exported = entries[0]
    assert exported["entry_type"] == "note"
    assert exported["id"] == "entry-1"
    assert exported["key"] == "k"


@pytest.mark.asyncio
async def test_todo_export_uses_type_aware_limit_query() -> None:
    handler = _StubMemoryHandler()

    payload = await handler.do_todo_export({"format": "json"})

    assert payload["format"] == "json"
    assert handler._memory_manager.calls[0]["entry_type"] == "todo"
    assert handler._memory_manager.calls[0]["include_deleted"] is True
    assert handler._memory_manager.calls[0]["limit"] == 2000

    # HDL-L2: pin the output payload shape, not just the call arguments.
    assert isinstance(payload.get("data"), str)
    entries = json.loads(payload["data"])
    assert isinstance(entries, list) and len(entries) == 1
    exported = entries[0]
    assert exported["entry_type"] == "todo"
    assert exported["value"] == {"title": "t", "status": "open", "due_date": ""}


# HDL-L2: CSV output has its own code path that mixes header construction,
# per-field value lookup, and CSV escaping. Prior tests only exercised JSON.


@pytest.mark.asyncio
async def test_note_export_csv_renders_header_and_row_fields() -> None:
    handler = _StubMemoryHandler()

    payload = await handler.do_note_export({"format": "csv"})

    assert payload["format"] == "csv"
    data = payload["data"].splitlines()
    assert data[0] == "id,key,value,created_at,user_verified,deleted_at"
    assert data[1].startswith("entry-1,k,")
    # `created_at` value ends up in the row exactly as stored.
    assert "2026-02-17T00:00:00+00:00" in data[1]


@pytest.mark.asyncio
async def test_todo_export_csv_flattens_value_dict_into_title_status_due_date() -> None:
    handler = _StubMemoryHandler()

    payload = await handler.do_todo_export({"format": "csv"})

    assert payload["format"] == "csv"
    data = payload["data"].splitlines()
    assert data[0] == "id,title,status,due_date,created_at,user_verified,deleted_at"
    # Todo CSV MUST flatten the value dict rather than serialize it.
    row = data[1]
    assert row.startswith("entry-1,t,open,,")
    assert "2026-02-17T00:00:00+00:00" in row


@pytest.mark.asyncio
async def test_note_export_rejects_unsupported_format() -> None:
    handler = _StubMemoryHandler()

    with pytest.raises(ValueError, match="Unsupported export format"):
        await handler.do_note_export({"format": "xml"})
