"""M2 recall surface compatibility checks."""

from __future__ import annotations

import sqlite3
from datetime import UTC, datetime
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


def test_m2_compile_recall_prioritizes_user_curated_over_untrusted_matches(tmp_path: Path) -> None:
    pipeline = IngestionPipeline(tmp_path / "memory")
    pipeline.ingest(
        source_id="doc-user-ranked",
        source_type="user",
        content="The release codename is nebula and the user confirmed it directly.",
    )
    pipeline.ingest(
        source_id="doc-web-ranked",
        source_type="external",
        collection="external_web",
        content="The release codename is nebula according to an untrusted web mirror.",
    )

    pack = pipeline.compile_recall("release codename nebula", limit=2)

    assert pack.count == 2
    assert pack.results[0].collection == "user_curated"
    assert pack.results[0].effective_score >= pack.results[1].effective_score
    assert pack.results[1].collection == "external_web"
    assert pack.results[1].verification_gap is True


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


def test_m2_compile_recall_supports_as_of_filtering(tmp_path: Path) -> None:
    storage = tmp_path / "memory"
    pipeline = IngestionPipeline(storage)
    older = pipeline.ingest(
        source_id="doc-older",
        source_type="external",
        collection="project_docs",
        content="Project roadmap snapshot from January.",
    )
    newer = pipeline.ingest(
        source_id="doc-newer",
        source_type="external",
        collection="project_docs",
        content="Project roadmap snapshot from February.",
    )

    with sqlite3.connect(storage / "memory.sqlite3") as conn:
        conn.execute(
            "UPDATE retrieval_records SET created_at = ? WHERE chunk_id = ?",
            ("2026-01-10T00:00:00+00:00", older.chunk_id),
        )
        conn.execute(
            "UPDATE retrieval_records SET created_at = ? WHERE chunk_id = ?",
            ("2026-02-10T00:00:00+00:00", newer.chunk_id),
        )

    pack = pipeline.compile_recall(
        "project roadmap snapshot",
        limit=5,
        as_of=datetime(2026, 1, 20, tzinfo=UTC),
    )

    assert [item.chunk_id for item in pack.results] == [older.chunk_id]
    assert pack.as_of == datetime(2026, 1, 20, tzinfo=UTC)


def test_m2_compile_recall_auto_widens_into_archive_with_annotations(tmp_path: Path) -> None:
    storage = tmp_path / "memory"
    pipeline = IngestionPipeline(storage)
    stored = pipeline.ingest(
        source_id="doc-archive",
        source_type="external",
        collection="external_web",
        content="Archived nebula status note from a stale web snapshot.",
    )

    with sqlite3.connect(storage / "memory.sqlite3") as conn:
        conn.execute(
            "UPDATE retrieval_records SET created_at = ? WHERE chunk_id = ?",
            ("2025-01-01T00:00:00+00:00", stored.chunk_id),
        )

    pack = pipeline.compile_recall("nebula status note", limit=5)

    assert pack.count == 1
    assert pack.include_archived is True
    result = pack.results[0]
    assert result.chunk_id == stored.chunk_id
    assert result.archived is True
    assert result.stale is True
    assert result.verification_gap is True
    assert result.decay_score < 1.0
    assert result.effective_score > 0.0


def test_m2_compile_recall_default_class_budgets_preserve_user_curated_hits(tmp_path: Path) -> None:
    pipeline = IngestionPipeline(tmp_path / "memory")
    pipeline.ingest(
        source_id="doc-user",
        source_type="user",
        content="My release checklist notebook mentions the canary rollout.",
    )
    for idx in range(4):
        pipeline.ingest(
            source_id=f"doc-web-{idx}",
            source_type="external",
            collection="external_web",
            content=(
                "release checklist canary rollout release checklist canary rollout "
                f"external report {idx}"
            ),
        )

    pack = pipeline.compile_recall("release checklist canary rollout", limit=2)

    assert pack.count == 2
    assert {item.collection for item in pack.results} == {"user_curated", "external_web"}


def test_m2_compile_recall_marks_revision_churn_and_respects_max_tokens(tmp_path: Path) -> None:
    pipeline = IngestionPipeline(tmp_path / "memory")
    pipeline.ingest(
        source_id="doc-revisioned",
        source_type="external",
        collection="project_docs",
        content="release plan revision alpha beta gamma",
    )
    pipeline.ingest(
        source_id="doc-revisioned",
        source_type="external",
        collection="project_docs",
        content="release plan revision delta epsilon zeta",
    )

    pack = pipeline.compile_recall(
        "release plan revision",
        limit=5,
        max_tokens=6,
    )

    assert pack.count == 1
    assert pack.max_tokens == 6
    assert pack.results[0].revision_churn is True


def test_m2_compile_recall_marks_conflicting_results(tmp_path: Path) -> None:
    pipeline = IngestionPipeline(tmp_path / "memory")
    pipeline.ingest(
        source_id="doc-positive",
        source_type="external",
        collection="project_docs",
        content="Favorite color is blue for this profile note.",
    )
    pipeline.ingest(
        source_id="doc-negative",
        source_type="external",
        collection="project_docs",
        content="Favorite color is not blue for this profile note.",
    )

    pack = pipeline.compile_recall("favorite color blue", limit=5)

    assert pack.count == 2
    assert all(item.conflict for item in pack.results)
