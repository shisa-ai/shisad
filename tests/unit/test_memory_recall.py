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


def test_c2_legacy_retrieve_alias_forwards_owner_scope(tmp_path: Path) -> None:
    pipeline = IngestionPipeline(tmp_path / "memory")
    same_owner = pipeline.ingest(
        source_id="alias-same-owner",
        source_type="user",
        collection="user_curated",
        content="Legacy retrieve alias owner scope token same-owner-blue.",
        user_id="alice",
        workspace_id="ws1",
    )
    pipeline.ingest(
        source_id="alias-other-owner",
        source_type="user",
        collection="user_curated",
        content="Legacy retrieve alias owner scope token other-owner-red.",
        user_id="bob",
        workspace_id="ws2",
    )
    public = pipeline.ingest(
        source_id="alias-public",
        source_type="external",
        collection="project_docs",
        content="Legacy retrieve alias owner scope token public-green.",
    )

    results = pipeline.retrieve(
        "retrieve alias owner scope token",
        limit=10,
        user_id="alice",
        workspace_id="ws1",
    )

    sources = {item.source_id for item in results}
    assert same_owner.source_id in sources
    assert public.source_id in sources
    assert "alias-other-owner" not in sources


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


def test_m2_compile_recall_uses_canonical_trust_band_for_user_curated_hits(
    tmp_path: Path,
) -> None:
    pipeline = IngestionPipeline(tmp_path / "memory")
    elevated = pipeline.ingest(
        source_id="doc-user-elevated",
        source_type="user",
        content="The release owner handle is shisa-ai according to the user.",
        source_origin="user_direct",
        channel_trust="command",
        confirmation_status="user_asserted",
        scope="user",
        user_id="user-1",
        workspace_id="ws-1",
    )
    observed = pipeline.ingest(
        source_id="doc-user-observed",
        source_type="user",
        content="The release owner handle is shisa-ai from an owner-observed channel sync.",
        source_origin="user_direct",
        channel_trust="owner_observed",
        confirmation_status="auto_accepted",
        scope="channel",
        user_id="user-1",
        workspace_id="ws-1",
    )

    pack = pipeline.compile_recall(
        "release owner handle shisa-ai",
        limit=2,
        user_id="user-1",
        workspace_id="ws-1",
    )

    assert [item.chunk_id for item in pack.results] == [elevated.chunk_id, observed.chunk_id]
    assert pack.results[0].trust_band == "elevated"
    assert pack.results[0].trust_caveat is None
    assert pack.results[1].trust_band == "untrusted"
    assert pack.results[1].trust_caveat
    assert pack.results[1].verification_gap is True


def test_m2_compile_recall_prioritizes_user_curated_over_untrusted_matches(tmp_path: Path) -> None:
    pipeline = IngestionPipeline(tmp_path / "memory")
    pipeline.ingest(
        source_id="doc-user-ranked",
        source_type="user",
        content="The release codename is nebula and the user confirmed it directly.",
        user_id="user-1",
        workspace_id="ws-1",
    )
    pipeline.ingest(
        source_id="doc-web-ranked",
        source_type="external",
        collection="external_web",
        content="The release codename is nebula according to an untrusted web mirror.",
    )

    pack = pipeline.compile_recall(
        "release codename nebula",
        limit=2,
        user_id="user-1",
        workspace_id="ws-1",
    )

    assert pack.count == 2
    assert pack.results[0].collection == "user_curated"
    assert pack.results[0].effective_score >= pack.results[1].effective_score
    assert pack.results[1].collection == "external_web"
    assert pack.results[1].verification_gap is True


def test_m2_compile_recall_filters_by_scope(tmp_path: Path) -> None:
    pipeline = IngestionPipeline(tmp_path / "memory")
    session_entry = pipeline.ingest(
        source_id="doc-session-scope",
        source_type="user",
        content="Deployment checklist item for the active session only.",
        source_origin="user_direct",
        channel_trust="command",
        confirmation_status="user_asserted",
        scope="session",
        user_id="user-1",
        workspace_id="ws-1",
    )
    pipeline.ingest(
        source_id="doc-user-scope",
        source_type="user",
        content="Deployment checklist item for the long-term user profile.",
        source_origin="user_direct",
        channel_trust="command",
        confirmation_status="user_asserted",
        scope="user",
        user_id="user-1",
        workspace_id="ws-1",
    )

    pack = pipeline.compile_recall(
        "deployment checklist item",
        limit=5,
        scope_filter={"session"},
        user_id="user-1",
        workspace_id="ws-1",
    )

    assert [item.chunk_id for item in pack.results] == [session_entry.chunk_id]
    assert pack.results[0].scope == "session"


def test_m2_compile_recall_legacy_payload_matches_current_runtime_shape(tmp_path: Path) -> None:
    pipeline = IngestionPipeline(tmp_path / "memory")
    pipeline.ingest(
        source_id="doc-shape",
        source_type="user",
        content="Recall payloads should keep the existing runtime fields.",
        user_id="user-1",
        workspace_id="ws-1",
    )

    payload = pipeline.compile_recall(
        "runtime fields",
        limit=5,
        user_id="user-1",
        workspace_id="ws-1",
    ).legacy_payload()

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
    calls: list[tuple[str, int, set[Capability] | None, str | None, str | None]] = []

    def _fail_legacy_retrieve(*_args: object, **_kwargs: object) -> list[object]:
        raise AssertionError("RetrieveRagTool should not call the legacy retrieve alias")

    def _fake_compile_recall(
        query: str,
        *,
        limit: int = 5,
        capabilities: set[Capability] | None = None,
        user_id: str | None = None,
        workspace_id: str | None = None,
        **_kwargs: object,
    ) -> object:
        calls.append((query, limit, capabilities, user_id, workspace_id))
        return build_recall_pack(query=query, results=[stored])

    monkeypatch.setattr(pipeline, "retrieve", _fail_legacy_retrieve)
    monkeypatch.setattr(pipeline, "compile_recall", _fake_compile_recall)

    results = RetrieveRagTool(pipeline).execute(
        query="runtime recall",
        limit=1,
        capabilities={Capability.MEMORY_READ},
        user_id="user-1",
        workspace_id="ws-1",
    )

    assert calls == [("runtime recall", 1, {Capability.MEMORY_READ}, "user-1", "ws-1")]
    assert [item.chunk_id for item in results] == [stored.chunk_id]


def test_c2_retrieve_rag_tool_scopes_user_curated_by_owner(tmp_path: Path) -> None:
    pipeline = IngestionPipeline(tmp_path / "memory")
    pipeline.ingest(
        source_id="same-owner",
        source_type="user",
        collection="user_curated",
        content="C2 retrieve rag facade scoped token same-owner-blue.",
        user_id="user-1",
        workspace_id="ws-1",
    )
    pipeline.ingest(
        source_id="other-owner",
        source_type="user",
        collection="user_curated",
        content="C2 retrieve rag facade scoped token other-owner-red.",
        user_id="user-2",
        workspace_id="ws-2",
    )

    results = RetrieveRagTool(pipeline).execute(
        query="retrieve rag facade scoped token",
        limit=10,
        capabilities={Capability.MEMORY_READ},
        user_id="user-1",
        workspace_id="ws-1",
    )

    sources = {item.source_id for item in results}
    assert "same-owner" in sources
    assert "other-owner" not in sources


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


def test_m2_compile_recall_excludes_archived_when_current_result_suffices(
    tmp_path: Path,
) -> None:
    storage = tmp_path / "memory"
    pipeline = IngestionPipeline(storage)
    current = pipeline.ingest(
        source_id="doc-current",
        source_type="external",
        collection="external_web",
        content="Current nebula status note from this week.",
    )
    archived = pipeline.ingest(
        source_id="doc-archived-strong",
        source_type="external",
        collection="external_web",
        content=(
            "Archived nebula status note with many nebula status note references "
            "from a stale web snapshot."
        ),
    )

    with sqlite3.connect(storage / "memory.sqlite3") as conn:
        conn.execute(
            "UPDATE retrieval_records SET created_at = ? WHERE chunk_id = ?",
            ("2026-04-20T00:00:00+00:00", current.chunk_id),
        )
        conn.execute(
            "UPDATE retrieval_records SET created_at = ? WHERE chunk_id = ?",
            ("2025-01-01T00:00:00+00:00", archived.chunk_id),
        )

    default_pack = pipeline.compile_recall("nebula status note", limit=5)

    assert default_pack.include_archived is False
    assert [item.chunk_id for item in default_pack.results] == [current.chunk_id]
    assert default_pack.results[0].archived is False

    explicit_pack = pipeline.compile_recall(
        "nebula status note",
        limit=5,
        include_archived=True,
    )

    assert explicit_pack.include_archived is True
    assert {item.chunk_id for item in explicit_pack.results} == {
        current.chunk_id,
        archived.chunk_id,
    }
    assert any(
        item.chunk_id == archived.chunk_id and item.archived for item in explicit_pack.results
    )


def test_m2_compile_recall_default_class_budgets_preserve_user_curated_hits(tmp_path: Path) -> None:
    pipeline = IngestionPipeline(tmp_path / "memory")
    pipeline.ingest(
        source_id="doc-user",
        source_type="user",
        content="My release checklist notebook mentions the canary rollout.",
        user_id="user-1",
        workspace_id="ws-1",
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

    pack = pipeline.compile_recall(
        "release checklist canary rollout",
        limit=2,
        user_id="user-1",
        workspace_id="ws-1",
    )

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


def test_m2_compile_recall_ignores_pending_review_siblings_for_revision_churn(
    tmp_path: Path,
) -> None:
    pipeline = IngestionPipeline(tmp_path / "memory")
    visible = pipeline.ingest(
        source_id="doc-visible",
        source_type="external",
        collection="project_docs",
        content="Visible release plan revision alpha beta gamma",
    )
    pipeline.ingest(
        source_id="doc-visible",
        source_type="external",
        collection="project_docs",
        content="Pending-review release plan revision delta epsilon zeta",
        source_origin="external_message",
        channel_trust="shared_participant",
        confirmation_status="pending_review",
        scope="user",
    )

    pack = pipeline.compile_recall("visible release plan revision", limit=5)

    assert [item.chunk_id for item in pack.results] == [visible.chunk_id]
    assert pack.results[0].revision_churn is False


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


def test_m2_record_citations_is_best_effort_on_operational_error(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    pipeline = IngestionPipeline(tmp_path / "memory")
    stored = pipeline.ingest(
        source_id="doc-best-effort",
        source_type="external",
        collection="project_docs",
        content="Citation persistence should not break a successful recall read.",
    )

    def _raise_operational_error(*_args: object, **_kwargs: object) -> int:
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(pipeline._backend, "record_citations", _raise_operational_error)

    assert pipeline.record_citations([stored.chunk_id]) == 0


def test_m2_compile_recall_backfills_null_provenance_for_legacy_rows(
    tmp_path: Path,
) -> None:
    storage = tmp_path / "memory"
    pipeline = IngestionPipeline(storage)
    stored = pipeline.ingest(
        source_id="doc-legacy-null-backfill",
        source_type="external",
        collection="external_web",
        content="Legacy recall rows should survive nullable provenance schema upgrades.",
    )

    with sqlite3.connect(storage / "memory.sqlite3") as conn:
        conn.execute(
            """
            UPDATE retrieval_records
            SET source_origin = NULL,
                channel_trust = NULL,
                confirmation_status = NULL,
                scope = NULL
            WHERE chunk_id = ?
            """,
            (stored.chunk_id,),
        )

    restarted = IngestionPipeline(storage)
    pack = restarted.compile_recall("nullable provenance schema upgrades", limit=5)

    assert [item.chunk_id for item in pack.results] == [stored.chunk_id]
    assert pack.results[0].source_origin == "external_web"
    assert pack.results[0].channel_trust == "web_passed"
    assert pack.results[0].confirmation_status == "auto_accepted"
    assert pack.results[0].scope == "user"
