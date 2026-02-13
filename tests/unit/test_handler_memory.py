"""Unit checks for memory handler wrappers."""

from __future__ import annotations

import pytest

from shisad.core.api.schema import (
    MemoryEntryParams,
    MemoryIngestParams,
    MemoryListParams,
    MemoryRotateKeyParams,
)
from shisad.daemon.context import RequestContext
from shisad.daemon.handlers.memory import MemoryHandlers


class _StubImpl:
    async def do_memory_ingest(self, payload: dict[str, object]) -> dict[str, object]:
        return {
            "chunk_id": "ing-1",
            "source_id": str(payload["source_id"]),
            "source_type": "user",
            "collection": "user_curated",
            "created_at": "2026-02-13T00:00:00+00:00",
            "content_sanitized": "safe",
            "risk_score": 0.1,
            "original_hash": "hash-1",
        }

    async def do_memory_retrieve(self, _payload: dict[str, object]) -> dict[str, object]:
        return {"results": [{"entry_id": "e1"}], "count": 1}

    async def do_memory_write(self, _payload: dict[str, object]) -> dict[str, object]:
        return {"written": True}

    async def do_memory_list(self, _payload: dict[str, object]) -> dict[str, object]:
        return {"entries": [{"entry_id": "e1"}], "count": 1}

    async def do_memory_get(self, _payload: dict[str, object]) -> dict[str, object]:
        return {"entry": {"entry_id": "e1"}}

    async def do_memory_delete(self, payload: dict[str, object]) -> dict[str, object]:
        return {"deleted": True, "entry_id": str(payload["entry_id"])}

    async def do_memory_export(self, _payload: dict[str, object]) -> dict[str, object]:
        return {"format": "json", "data": {}}

    async def do_memory_verify(self, payload: dict[str, object]) -> dict[str, object]:
        return {"verified": True, "entry_id": str(payload["entry_id"])}

    async def do_memory_rotate_key(self, payload: dict[str, object]) -> dict[str, object]:
        return {
            "rotated": True,
            "active_key_id": "k1",
            "reencrypt_existing": bool(payload["reencrypt_existing"]),
        }


@pytest.mark.asyncio
async def test_memory_ingest_and_list_wrappers() -> None:
    handlers = MemoryHandlers(_StubImpl(), internal_ingress_marker=object())  # type: ignore[arg-type]
    ingest = await handlers.handle_memory_ingest(
        MemoryIngestParams(source_id="src-1", content="hello"),
        RequestContext(),
    )
    listing = await handlers.handle_memory_list(MemoryListParams(limit=10), RequestContext())
    assert ingest.model_dump(mode="json")["source_id"] == "src-1"
    assert listing.count == 1


@pytest.mark.asyncio
async def test_memory_verify_and_rotate_wrappers() -> None:
    handlers = MemoryHandlers(_StubImpl(), internal_ingress_marker=object())  # type: ignore[arg-type]
    verify = await handlers.handle_memory_verify(
        MemoryEntryParams(entry_id="e1"),
        RequestContext(),
    )
    rotated = await handlers.handle_memory_rotate_key(
        MemoryRotateKeyParams(reencrypt_existing=False),
        RequestContext(),
    )
    assert verify.verified is True
    assert rotated.active_key_id == "k1"
