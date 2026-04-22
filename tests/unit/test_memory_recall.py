"""M2 recall surface compatibility checks."""

from __future__ import annotations

from pathlib import Path

import pytest

from shisad.core.types import Capability
from shisad.memory.ingestion import IngestionPipeline, RetrieveRagTool
from shisad.memory.surfaces.recall import build_recall_pack


def test_m2_compile_recall_preserves_legacy_retrieve_results(tmp_path: Path) -> None:
    pipeline = IngestionPipeline(tmp_path / "memory")
    stored = pipeline.ingest(
        source_id="doc-recall",
        source_type="external",
        content="Remembered preferences should keep flowing through the recall surface.",
    )

    pack = pipeline.compile_recall("remembered preferences", limit=5)
    legacy = pipeline.retrieve("remembered preferences", limit=5)

    assert pack.count == 1
    assert [item.chunk_id for item in pack.results] == [item.chunk_id for item in legacy]
    assert pack.results[0].chunk_id == stored.chunk_id

    payload = pack.legacy_payload()
    assert payload["count"] == 1
    assert payload["results"][0]["chunk_id"] == stored.chunk_id
    assert payload["results"][0]["content_sanitized"] == stored.content_sanitized


def test_m2_compile_recall_preserves_capability_scoping(tmp_path: Path) -> None:
    pipeline = IngestionPipeline(tmp_path / "memory")
    pipeline.ingest(
        source_id="doc-external-web",
        source_type="external",
        content="External web recall must stay out of side-effectful turns.",
        collection="external_web",
    )

    pack = pipeline.compile_recall(
        "external web recall",
        limit=5,
        capabilities={Capability.HTTP_REQUEST},
    )

    assert pack.results == []
    assert pack.count == 0


def test_m2_compile_recall_legacy_payload_matches_current_runtime_shape(tmp_path: Path) -> None:
    pipeline = IngestionPipeline(tmp_path / "memory")
    pipeline.ingest(
        source_id="doc-shape",
        source_type="user",
        content="Recall payloads should keep the existing runtime fields.",
    )

    payload = pipeline.compile_recall("runtime fields", limit=5).legacy_payload()

    assert payload["count"] == 1
    result = payload["results"][0]
    assert set(result) >= {
        "chunk_id",
        "source_id",
        "source_type",
        "collection",
        "created_at",
        "content_sanitized",
        "risk_score",
        "original_hash",
    }


def test_m2_retrieve_rag_tool_executes_recall_surface(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    pipeline = IngestionPipeline(tmp_path / "memory")
    stored = pipeline.ingest(
        source_id="doc-tool",
        source_type="external",
        content="Runtime retrieve_rag calls should flow through compile_recall.",
    )
    calls: list[tuple[str, int, set[Capability] | None]] = []

    def _fail_legacy_retrieve(*_args: object, **_kwargs: object) -> list[object]:
        raise AssertionError("RetrieveRagTool should not call the legacy retrieve alias")

    def _fake_compile_recall(
        query: str,
        *,
        limit: int = 5,
        capabilities: set[Capability] | None = None,
        **_kwargs: object,
    ) -> object:
        calls.append((query, limit, capabilities))
        return build_recall_pack(query=query, results=[stored])

    monkeypatch.setattr(pipeline, "retrieve", _fail_legacy_retrieve)
    monkeypatch.setattr(pipeline, "compile_recall", _fake_compile_recall)

    results = RetrieveRagTool(pipeline).execute(
        query="runtime recall",
        limit=1,
        capabilities={Capability.MEMORY_READ},
    )

    assert calls == [("runtime recall", 1, {Capability.MEMORY_READ})]
    assert [item.chunk_id for item in results] == [stored.chunk_id]
