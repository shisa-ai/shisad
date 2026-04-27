"""Unit coverage for handle-based memory ingest paths."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from shisad.core.types import Capability
from shisad.daemon.handlers._impl_memory import MemoryImplMixin
from shisad.memory.ingestion import IngestionPipeline
from shisad.memory.ingress import IngressContextRegistry
from shisad.memory.surfaces.recall import build_recall_pack
from shisad.memory.trust import TrustGateViolation


class _MemoryIngestHarness(MemoryImplMixin):
    def __init__(self, tmp_path: Path, *, audit_hook=None) -> None:
        self._ingestion = IngestionPipeline(tmp_path / "retrieval", audit_hook=audit_hook)
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
async def test_memory_ingest_preserves_handle_provenance_and_scope_for_recall(
    tmp_path: Path,
) -> None:
    harness = _MemoryIngestHarness(tmp_path)
    context = harness._memory_ingress_registry.mint(
        source_origin="user_direct",
        channel_trust="owner_observed",
        confirmation_status="auto_accepted",
        scope="channel",
        source_id="discord:msg-1",
        content="Owner-observed recall items must keep their canonical scope and trust fields.",
    )

    result = await harness.do_memory_ingest(
        {
            "ingress_context": context.handle_id,
            "content": (
                "Owner-observed recall items must keep their canonical scope and trust fields."
            ),
        }
    )

    assert result["source_origin"] == "user_direct"
    assert result["channel_trust"] == "owner_observed"
    assert result["confirmation_status"] == "auto_accepted"
    assert result["scope"] == "channel"
    assert result["trust_band"] == "untrusted"
    assert str(result["trust_caveat"]).strip()


@pytest.mark.asyncio
async def test_memory_ingest_preserves_non_user_handle_provenance_under_collection_override(
    tmp_path: Path,
) -> None:
    harness = _MemoryIngestHarness(tmp_path)
    context = harness._memory_ingress_registry.mint(
        source_origin="external_web",
        channel_trust="web_passed",
        confirmation_status="auto_accepted",
        scope="session",
        source_id="fetch-collection-override",
        content="Fetched evidence should not become elevated when stored in user_curated.",
    )

    result = await harness.do_memory_ingest(
        {
            "ingress_context": context.handle_id,
            "content": "Fetched evidence should not become elevated when stored in user_curated.",
            "collection": "user_curated",
        }
    )

    assert result["collection"] == "user_curated"
    assert result["source_origin"] == "external_web"
    assert result["channel_trust"] == "web_passed"
    assert result["confirmation_status"] == "auto_accepted"
    assert result["trust_band"] == "untrusted"


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


@pytest.mark.asyncio
async def test_memory_ingest_rejects_unauthenticated_raw_source_shape(tmp_path: Path) -> None:
    harness = _MemoryIngestHarness(tmp_path)

    with pytest.raises(ValueError, match="ingress_context is required"):
        await harness.do_memory_ingest(
            {
                "source_id": "legacy-source",
                "source_type": "external",
                "content": "legacy payload",
            }
        )


@pytest.mark.asyncio
async def test_m2_memory_retrieve_uses_recall_surface(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    harness = _MemoryIngestHarness(tmp_path)
    stored = harness._ingestion.ingest(
        source_id="doc-recall-api",
        source_type="external",
        content="Memory retrieve RPC should route through compile_recall.",
    )
    calls: list[tuple[str, int, set[Capability]]] = []

    def _fail_legacy_retrieve(*_args: object, **_kwargs: object) -> list[object]:
        raise AssertionError("do_memory_retrieve should not call the legacy retrieve alias")

    def _fake_compile_recall(
        query: str,
        *,
        limit: int = 5,
        capabilities: set[Capability] | None = None,
        **_kwargs: object,
    ) -> object:
        calls.append((query, limit, set(capabilities or set())))
        return build_recall_pack(query=query, results=[stored])

    monkeypatch.setattr(harness._ingestion, "retrieve", _fail_legacy_retrieve)
    monkeypatch.setattr(harness._ingestion, "compile_recall", _fake_compile_recall)

    result = await harness.do_memory_retrieve(
        {
            "query": "recall rpc",
            "limit": 1,
            "capabilities": [Capability.MEMORY_READ.value],
        }
    )

    assert calls == [("recall rpc", 1, {Capability.MEMORY_READ})]
    assert result["count"] == 1
    assert result["results"][0]["chunk_id"] == stored.chunk_id


@pytest.mark.asyncio
async def test_m2_memory_retrieve_passes_scope_filter_to_recall_surface(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    harness = _MemoryIngestHarness(tmp_path)
    stored = harness._ingestion.ingest(
        source_id="doc-scope-rpc",
        source_type="user",
        content="Scoped recall RPC should forward the explicit scope filter.",
    )
    calls: list[tuple[str, int, set[Capability], set[str] | None]] = []

    def _fake_compile_recall(
        query: str,
        *,
        limit: int = 5,
        capabilities: set[Capability] | None = None,
        scope_filter: set[str] | None = None,
        **_kwargs: object,
    ) -> object:
        calls.append((query, limit, set(capabilities or set()), scope_filter))
        return build_recall_pack(query=query, results=[stored])

    monkeypatch.setattr(harness._ingestion, "compile_recall", _fake_compile_recall)

    result = await harness.do_memory_retrieve(
        {
            "query": "scoped recall",
            "limit": 1,
            "capabilities": [Capability.MEMORY_READ.value],
            "scope_filter": ["session"],
        }
    )

    assert calls == [("scoped recall", 1, {Capability.MEMORY_READ}, {"session"})]
    assert result["count"] == 1


@pytest.mark.asyncio
async def test_c2_memory_retrieve_scopes_user_curated_results_to_owner_tuple(
    tmp_path: Path,
) -> None:
    harness = _MemoryIngestHarness(tmp_path)
    same_owner = harness._ingestion.ingest(
        source_id="same-owner-rpc",
        source_type="user",
        collection="user_curated",
        content="C2 memory retrieve owner scope token same-owner-blue.",
        user_id="user-1",
        workspace_id="ws-1",
    )
    harness._ingestion.ingest(
        source_id="other-owner-rpc",
        source_type="user",
        collection="user_curated",
        content="C2 memory retrieve owner scope token other-owner-red.",
        user_id="user-2",
        workspace_id="ws-2",
    )
    legacy_unowned = harness._ingestion.ingest(
        source_id="legacy-unowned-rpc",
        source_type="user",
        collection="user_curated",
        content="C2 memory retrieve owner scope token legacy-unowned-green.",
    )

    scoped = await harness.do_memory_retrieve(
        {
            "query": "memory retrieve owner scope token",
            "limit": 10,
            "user_id": "user-1",
            "workspace_id": "ws-1",
        }
    )
    scoped_text = json.dumps(scoped, sort_keys=True)

    assert scoped["count"] == 1
    assert same_owner.chunk_id in scoped_text
    assert "same-owner-blue" in scoped_text
    assert "other-owner-red" not in scoped_text
    assert "legacy-unowned-green" not in scoped_text

    scoped_with_legacy = await harness.do_memory_retrieve(
        {
            "query": "memory retrieve owner scope token",
            "limit": 10,
            "user_id": "user-1",
            "workspace_id": "ws-1",
            "include_unowned": True,
        }
    )
    scoped_with_legacy_text = json.dumps(scoped_with_legacy, sort_keys=True)

    assert legacy_unowned.chunk_id in scoped_with_legacy_text
    assert "other-owner-red" not in scoped_with_legacy_text


@pytest.mark.asyncio
async def test_m2_memory_retrieve_records_citations(tmp_path: Path) -> None:
    harness = _MemoryIngestHarness(tmp_path)
    stored = harness._ingestion.ingest(
        source_id="doc-citation-rpc",
        source_type="external",
        content="Memory retrieve RPC should record citation usage.",
    )

    result = await harness.do_memory_retrieve({"query": "citation usage", "limit": 1})

    assert result["count"] == 1
    with sqlite3.connect(tmp_path / "retrieval" / "memory.sqlite3") as conn:
        row = conn.execute(
            "SELECT citation_count, last_cited_at FROM retrieval_records WHERE chunk_id = ?",
            (stored.chunk_id,),
        ).fetchone()

    assert row is not None
    assert int(row[0]) == 1
    assert str(row[1]).strip()


@pytest.mark.asyncio
async def test_m2_memory_retrieve_citation_failures_do_not_break_response(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    harness = _MemoryIngestHarness(tmp_path)
    stored = harness._ingestion.ingest(
        source_id="doc-citation-best-effort",
        source_type="external",
        collection="project_docs",
        content="Citation persistence failures should not break memory.retrieve.",
    )

    def _raise_operational_error(*_args: object, **_kwargs: object) -> int:
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(harness._ingestion._backend, "record_citations", _raise_operational_error)

    result = await harness.do_memory_retrieve({"query": "citation persistence", "limit": 1})

    assert result["count"] == 1
    assert result["results"][0]["chunk_id"] == stored.chunk_id


@pytest.mark.asyncio
async def test_memory_read_original_returns_content_and_forwards_rpc_peer(
    tmp_path: Path,
) -> None:
    audits: list[tuple[str, dict[str, object]]] = []

    def _audit(action: str, payload: dict[str, object]) -> None:
        audits.append((action, payload))

    harness = _MemoryIngestHarness(tmp_path, audit_hook=_audit)
    stored = harness._ingestion.ingest(
        source_id="doc-read-original",
        source_type="external",
        content="Original retrieval payload for explicit inspection.",
    )

    result = await harness.do_memory_read_original(
        {
            "chunk_id": stored.chunk_id,
            "_rpc_peer": {"host": "127.0.0.1", "port": 4100},
        }
    )

    assert result == {
        "chunk_id": stored.chunk_id,
        "found": True,
        "content": "Original retrieval payload for explicit inspection.",
    }
    assert audits == [
        (
            "memory.evidence_read",
            {
                "chunk_id": stored.chunk_id,
                "found": True,
                "caller_context": {
                    "method": "memory.read_original",
                    "rpc_peer": {"host": "127.0.0.1", "port": 4100},
                },
            },
        )
    ]
