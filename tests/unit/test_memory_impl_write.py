"""Unit coverage for handle-based memory writes."""

from __future__ import annotations

from pathlib import Path

import pytest

from shisad.daemon.handlers._impl_memory import MemoryImplMixin
from shisad.memory.ingress import IngressContextRegistry
from shisad.memory.manager import MemoryManager
from shisad.memory.trust import TrustGateViolation


class _MemoryWriteHarness(MemoryImplMixin):
    def __init__(self, tmp_path: Path) -> None:
        self._memory_manager = MemoryManager(tmp_path / "memory")
        self._memory_ingress_registry = IngressContextRegistry()


@pytest.mark.asyncio
async def test_memory_write_accepts_handle_bound_direct_payload(tmp_path: Path) -> None:
    harness = _MemoryWriteHarness(tmp_path)
    context = harness._memory_ingress_registry.mint(
        source_origin="user_direct",
        channel_trust="command",
        confirmation_status="user_asserted",
        scope="user",
        source_id="turn-1",
        content="remember this",
    )

    result = await harness.do_memory_write(
        {
            "ingress_context": context.handle_id,
            "entry_type": "fact",
            "key": "profile.note",
            "value": "remember this",
            "confidence": 0.99,
        }
    )

    assert result["kind"] == "allow"
    entry = result["entry"]
    assert entry is not None
    assert entry["source_origin"] == "user_direct"
    assert entry["channel_trust"] == "command"
    assert entry["confirmation_status"] == "user_asserted"
    assert entry["scope"] == "user"
    assert entry["ingress_handle_id"] == context.handle_id
    assert entry["content_digest"] == context.content_digest
    assert entry["confidence"] == pytest.approx(0.95)


@pytest.mark.asyncio
async def test_memory_write_rejects_mismatched_handle_binding(tmp_path: Path) -> None:
    harness = _MemoryWriteHarness(tmp_path)
    context = harness._memory_ingress_registry.mint(
        source_origin="user_direct",
        channel_trust="command",
        confirmation_status="user_asserted",
        scope="user",
        source_id="turn-2",
        content="trusted payload",
    )

    with pytest.raises(TrustGateViolation):
        await harness.do_memory_write(
            {
                "ingress_context": context.handle_id,
                "entry_type": "fact",
                "key": "profile.note",
                "value": "different payload",
            }
        )


@pytest.mark.asyncio
async def test_memory_write_legacy_source_path_still_works(tmp_path: Path) -> None:
    harness = _MemoryWriteHarness(tmp_path)

    result = await harness.do_memory_write(
        {
            "source": {
                "origin": "user",
                "source_id": "legacy-1",
                "extraction_method": "manual",
            },
            "entry_type": "fact",
            "key": "profile.name",
            "value": "alice",
        }
    )

    assert result["kind"] == "allow"
    entry = result["entry"]
    assert entry is not None
    assert entry["source_origin"] == "user_direct"
    assert entry["confirmation_status"] == "auto_accepted"

