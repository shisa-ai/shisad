"""Unit coverage for handle-based memory ingest paths."""

from __future__ import annotations

from pathlib import Path

import pytest

from shisad.daemon.handlers._impl_memory import MemoryImplMixin
from shisad.memory.ingestion import IngestionPipeline
from shisad.memory.ingress import IngressContextRegistry
from shisad.memory.trust import TrustGateViolation


class _MemoryIngestHarness(MemoryImplMixin):
    def __init__(self, tmp_path: Path) -> None:
        self._ingestion = IngestionPipeline(tmp_path / "retrieval")
        self._memory_ingress_registry = IngressContextRegistry()


@pytest.mark.asyncio
async def test_memory_ingest_accepts_handle_bound_direct_payload(tmp_path: Path) -> None:
    harness = _MemoryIngestHarness(tmp_path)
    context = harness._memory_ingress_registry.mint(
        source_origin="user_direct",
        channel_trust="command",
        confirmation_status="user_asserted",
        scope="user",
        source_id="turn-1",
        content="remember this retrieval input",
    )

    result = await harness.do_memory_ingest(
        {
            "ingress_context": context.handle_id,
            "content": "remember this retrieval input",
        }
    )

    assert result["source_id"] == "turn-1"
    assert result["source_type"] == "user"
    assert result["collection"] == "user_curated"


@pytest.mark.asyncio
async def test_memory_ingest_maps_tool_output_handle_to_tool_source_type(tmp_path: Path) -> None:
    harness = _MemoryIngestHarness(tmp_path)
    context = harness._memory_ingress_registry.mint(
        source_origin="tool_output",
        channel_trust="tool_passed",
        confirmation_status="pep_approved",
        scope="workspace",
        source_id="tool-1",
        content="tool produced reliable output",
    )

    result = await harness.do_memory_ingest(
        {
            "ingress_context": context.handle_id,
            "content": "tool produced reliable output",
        }
    )

    assert result["source_id"] == "tool-1"
    assert result["source_type"] == "tool"
    assert result["collection"] == "tool_outputs"


@pytest.mark.asyncio
async def test_memory_ingest_rejects_mismatched_handle_binding(tmp_path: Path) -> None:
    harness = _MemoryIngestHarness(tmp_path)
    context = harness._memory_ingress_registry.mint(
        source_origin="external_web",
        channel_trust="web_passed",
        confirmation_status="auto_accepted",
        scope="workspace",
        source_id="fetch-1",
        content="trusted fetch payload",
    )

    with pytest.raises(TrustGateViolation):
        await harness.do_memory_ingest(
            {
                "ingress_context": context.handle_id,
                "content": "different payload",
            }
        )


@pytest.mark.asyncio
async def test_memory_ingest_control_api_path_mints_handle_and_maps_external_source(
    tmp_path: Path,
) -> None:
    harness = _MemoryIngestHarness(tmp_path)

    result = await harness.do_memory_ingest(
        {
            "_control_api_authenticated_write": True,
            "source_id": "fetch-2",
            "source_type": "external",
            "content": "fetched external context",
        }
    )

    assert result["source_id"] == "fetch-2"
    assert result["source_type"] == "external"
    assert result["collection"] == "external_web"
