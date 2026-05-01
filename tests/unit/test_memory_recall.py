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


def test_m7_compile_recall_verifies_sufficiency_and_expands_missing_task_terms(
    tmp_path: Path,
) -> None:
    pipeline = IngestionPipeline(tmp_path / "memory")
    launch = pipeline.ingest(
        source_id="m7-launch",
        source_type="tool",
        collection="project_docs",
        content="Launch checklist includes the canary deploy steps.",
    )
    rollback = pipeline.ingest(
        source_id="m7-rollback",
        source_type="tool",
        collection="project_docs",
        content="Rollback owner is Nina and the rollback rehearsal is complete.",
    )

    pack = pipeline.compile_recall(
        "launch checklist",
        task="rollback owner",
        limit=1,
        verify_sufficiency=True,
        expand_on_insufficient=True,
    )

    assert pack.sufficiency is not None
    assert pack.sufficiency.expanded is True
    assert pack.sufficiency.sufficient is True
    assert "rollback" in pack.sufficiency.covered_terms
    assert pack.sufficiency.missing_terms == []
    assert any("rollback owner" in query for query in pack.sufficiency.expanded_queries)
    assert {item.chunk_id for item in pack.results} == {launch.chunk_id, rollback.chunk_id}


def test_m7_sufficiency_uses_configured_coverage_threshold(tmp_path: Path) -> None:
    pipeline = IngestionPipeline(tmp_path / "memory")
    pipeline.ingest(
        source_id="m7-coverage",
        source_type="tool",
        collection="project_docs",
        content="Alpha beta gamma are present in the project notes.",
    )

    relaxed = pipeline.compile_recall(
        "alpha beta gamma delta epsilon",
        limit=1,
        verify_sufficiency=True,
        min_sufficiency_coverage=0.6,
    )
    strict = pipeline.compile_recall(
        "alpha beta gamma delta epsilon",
        limit=1,
        verify_sufficiency=True,
        min_sufficiency_coverage=0.8,
    )

    assert relaxed.sufficiency is not None
    assert relaxed.sufficiency.sufficient is True
    assert relaxed.sufficiency.reason == "sufficient_partial_coverage"
    assert relaxed.sufficiency.missing_terms
    assert strict.sufficiency is not None
    assert strict.sufficiency.sufficient is False
    assert strict.sufficiency.reason == "low_coverage"


def test_m7_sufficiency_rejects_invalid_coverage_threshold(tmp_path: Path) -> None:
    pipeline = IngestionPipeline(tmp_path / "memory")
    pipeline.ingest(
        source_id="m7-invalid-coverage",
        source_type="tool",
        collection="project_docs",
        content="Release recall threshold validation note.",
    )

    with pytest.raises(ValueError, match="min_sufficiency_coverage"):
        pipeline.compile_recall(
            "release recall",
            verify_sufficiency=True,
            min_sufficiency_coverage=-0.1,
        )
    with pytest.raises(ValueError, match="min_sufficiency_coverage"):
        pipeline.compile_recall(
            "release recall",
            verify_sufficiency=True,
            min_sufficiency_coverage=1.1,
        )


def test_m7_sufficiency_reports_early_empty_recall_paths(tmp_path: Path) -> None:
    pipeline = IngestionPipeline(tmp_path / "memory")

    empty_store = pipeline.compile_recall(
        "security escalation owner",
        verify_sufficiency=True,
    )
    assert empty_store.sufficiency is not None
    assert empty_store.sufficiency.sufficient is False
    assert empty_store.sufficiency.reason == "not_enough_results"

    pipeline.ingest(
        source_id="m7-empty-paths",
        source_type="tool",
        collection="project_docs",
        content="Deployment notes are indexed.",
    )
    empty_collections = pipeline.compile_recall(
        "deployment notes",
        allowed_collections=set(),
        verify_sufficiency=True,
    )
    empty_scope = pipeline.compile_recall(
        "deployment notes",
        scope_filter=set(),
        verify_sufficiency=True,
    )
    no_rows = pipeline.compile_recall(
        "deployment notes",
        allowed_collections={"external_web"},
        verify_sufficiency=True,
    )

    for pack in (empty_collections, empty_scope, no_rows):
        assert pack.sufficiency is not None
        assert pack.sufficiency.sufficient is False
        assert pack.sufficiency.reason == "not_enough_results"


def test_m7_sufficiency_expansion_reapplies_max_token_budget(tmp_path: Path) -> None:
    pipeline = IngestionPipeline(tmp_path / "memory")
    launch = pipeline.ingest(
        source_id="m7-budget-launch",
        source_type="tool",
        collection="project_docs",
        content="Launch checklist includes the canary deploy sequence.",
    )
    rollback = pipeline.ingest(
        source_id="m7-budget-rollback",
        source_type="tool",
        collection="project_docs",
        content="Rollback owner Nina coordinates release rollback escalation.",
    )

    pack = pipeline.compile_recall(
        "launch checklist",
        task="rollback owner",
        limit=1,
        max_tokens=6,
        verify_sufficiency=True,
        expand_on_insufficient=True,
    )

    assert [item.chunk_id for item in pack.results] == [launch.chunk_id]
    assert rollback.chunk_id not in {item.chunk_id for item in pack.results}
    assert pack.sufficiency is not None
    assert pack.sufficiency.expanded is True
    assert pack.sufficiency.sufficient is False
    assert "rollback" in pack.sufficiency.missing_terms


def test_m7_sufficiency_expansion_recomputes_final_verification_gaps(
    tmp_path: Path,
) -> None:
    pipeline = IngestionPipeline(tmp_path / "memory")
    launch = pipeline.ingest(
        source_id="m7-final-gap-launch",
        source_type="tool",
        collection="project_docs",
        content="Launch checklist includes the canary deploy sequence.",
    )
    pipeline.ingest(
        source_id="m7-final-gap-rollback",
        source_type="tool",
        collection="tool_outputs",
        content="Rollback owner Nina coordinates release rollback escalation.",
    )

    pack = pipeline.compile_recall(
        "launch checklist",
        task="rollback owner",
        limit=1,
        max_tokens=6,
        require_corroboration=True,
        verify_sufficiency=True,
        expand_on_insufficient=True,
    )

    assert [item.chunk_id for item in pack.results] == [launch.chunk_id]
    assert pack.results[0].verification_gap is True
    assert pack.sufficiency is not None
    assert pack.sufficiency.verification_gap_result_ids == [launch.chunk_id]


def test_m7_recall_finalizes_corroboration_after_token_trim_without_expansion(
    tmp_path: Path,
) -> None:
    pipeline = IngestionPipeline(tmp_path / "memory")
    primary = pipeline.ingest(
        source_id="m7-trim-corrob-primary",
        source_type="tool",
        collection="project_docs",
        content="Feature flag enabled status comes from project notes.",
    )
    pipeline.ingest(
        source_id="m7-trim-corrob-secondary",
        source_type="tool",
        collection="tool_outputs",
        content="Feature flag enabled status comes from tool output.",
    )

    pack = pipeline.compile_recall(
        "feature flag enabled",
        limit=2,
        max_tokens=7,
        require_corroboration=True,
    )

    assert [item.chunk_id for item in pack.results] == [primary.chunk_id]
    assert pack.results[0].corroborated is False
    assert pack.results[0].verification_gap is True


def test_m7_recall_clears_stale_conflict_after_token_trim(tmp_path: Path) -> None:
    pipeline = IngestionPipeline(tmp_path / "memory")
    pipeline.ingest(
        source_id="m7-trim-conflict-primary",
        source_type="tool",
        collection="project_docs",
        content="Feature flag enabled status comes from project notes.",
    )
    pipeline.ingest(
        source_id="m7-trim-conflict-secondary",
        source_type="tool",
        collection="project_docs",
        content="Feature flag is not enabled according to a stale project note.",
    )

    pack = pipeline.compile_recall(
        "feature flag enabled",
        limit=2,
        max_tokens=7,
    )

    assert len(pack.results) == 1
    assert pack.results[0].conflict is False


def test_m7_task_terms_drive_final_conflict_annotation(tmp_path: Path) -> None:
    pipeline = IngestionPipeline(tmp_path / "memory")
    pipeline.ingest(
        source_id="m7-task-conflict-launch",
        source_type="tool",
        collection="project_docs",
        content="Launch checklist includes the canary deploy sequence.",
    )
    pipeline.ingest(
        source_id="m7-task-conflict-owner",
        source_type="tool",
        collection="project_docs",
        content="Rollback owner Nina handles release rollback.",
    )
    pipeline.ingest(
        source_id="m7-task-conflict-negated",
        source_type="tool",
        collection="tool_outputs",
        content="Rollback owner is not Nina according to the latest runbook.",
    )

    pack = pipeline.compile_recall(
        "launch checklist",
        task="rollback owner",
        limit=4,
        verify_sufficiency=True,
        expand_on_insufficient=True,
    )

    rollback_hits = [
        item
        for item in pack.results
        if item.source_id in {"m7-task-conflict-owner", "m7-task-conflict-negated"}
    ]
    assert len(rollback_hits) == 2
    assert {item.conflict for item in rollback_hits} == {True}


def test_m7_task_conflict_annotation_normalizes_punctuation(tmp_path: Path) -> None:
    pipeline = IngestionPipeline(tmp_path / "memory")
    pipeline.ingest(
        source_id="m7-punctuation-conflict-launch",
        source_type="tool",
        collection="project_docs",
        content="Launch checklist includes the canary deploy sequence.",
    )
    pipeline.ingest(
        source_id="m7-punctuation-conflict-owner",
        source_type="tool",
        collection="project_docs",
        content="Rollback owner: Nina handles release rollback.",
    )
    pipeline.ingest(
        source_id="m7-punctuation-conflict-negated",
        source_type="tool",
        collection="tool_outputs",
        content="Rollback owner, not Nina according to the latest runbook.",
    )

    pack = pipeline.compile_recall(
        "launch checklist",
        task="who is the rollback owner?",
        limit=4,
        verify_sufficiency=True,
        expand_on_insufficient=True,
    )

    conflict_sources = {
        "m7-punctuation-conflict-owner",
        "m7-punctuation-conflict-negated",
    }
    rollback_hits = [item for item in pack.results if item.source_id in conflict_sources]
    assert len(rollback_hits) == 2
    assert {item.conflict for item in rollback_hits} == {True}


def test_m7_sufficiency_identifier_query_requires_identifier_coverage(
    tmp_path: Path,
) -> None:
    pipeline = IngestionPipeline(tmp_path / "memory")
    pipeline.ingest(
        source_id="m7-identifier-unrelated",
        source_type="tool",
        collection="project_docs",
        content="General release note about rollback owners and deployment checks.",
    )

    pack = pipeline.compile_recall(
        "M7",
        limit=1,
        verify_sufficiency=True,
    )

    assert pack.sufficiency is not None
    assert pack.sufficiency.query_terms == ["m7"]
    assert pack.sufficiency.coverage == 0.0
    assert pack.sufficiency.sufficient is False
    assert pack.sufficiency.reason == "low_coverage"
    assert pack.sufficiency.missing_terms == ["m7"]


def test_m7_sufficiency_identifier_query_uses_term_boundaries(tmp_path: Path) -> None:
    pipeline = IngestionPipeline(tmp_path / "memory")
    pipeline.ingest(
        source_id="m7-identifier-prefix-collision",
        source_type="tool",
        collection="project_docs",
        content="M70 and XM7A are unrelated release identifiers.",
    )

    pack = pipeline.compile_recall(
        "M7",
        limit=1,
        verify_sufficiency=True,
    )

    assert pack.sufficiency is not None
    assert pack.sufficiency.query_terms == ["m7"]
    assert pack.sufficiency.covered_terms == []
    assert pack.sufficiency.sufficient is False
    assert pack.sufficiency.missing_terms == ["m7"]


def test_m7_sufficiency_version_identifier_uses_full_dotted_token(
    tmp_path: Path,
) -> None:
    pipeline = IngestionPipeline(tmp_path / "memory")
    pipeline.ingest(
        source_id="m7-version-adjacent",
        source_type="tool",
        collection="project_docs",
        content="v0.7.1 and v0.7.20 are adjacent release identifiers.",
    )

    pack = pipeline.compile_recall(
        "v0.7.2",
        limit=1,
        verify_sufficiency=True,
    )

    assert pack.sufficiency is not None
    assert pack.sufficiency.query_terms == ["v0.7.2"]
    assert pack.sufficiency.covered_terms == []
    assert pack.sufficiency.sufficient is False
    assert pack.sufficiency.missing_terms == ["v0.7.2"]


def test_m7_identifier_terms_drive_conflict_annotation(tmp_path: Path) -> None:
    pipeline = IngestionPipeline(tmp_path / "memory")
    pipeline.ingest(
        source_id="m7-identifier-conflict-owner",
        source_type="tool",
        collection="project_docs",
        content="M7 owner Nina handles the M7 release.",
    )
    pipeline.ingest(
        source_id="m7-identifier-conflict-negated",
        source_type="tool",
        collection="tool_outputs",
        content="M7 owner is not Nina according to the release note.",
    )

    pack = pipeline.compile_recall(
        "M7 owner",
        limit=2,
    )

    assert len(pack.results) == 2
    assert {item.conflict for item in pack.results} == {True}


def test_m7_identifier_only_query_drives_conflict_annotation(tmp_path: Path) -> None:
    pipeline = IngestionPipeline(tmp_path / "memory")
    pipeline.ingest(
        source_id="m7-identifier-only-positive",
        source_type="tool",
        collection="project_docs",
        content="M7 is the release with owner Nina.",
    )
    pipeline.ingest(
        source_id="m7-identifier-only-negated",
        source_type="tool",
        collection="tool_outputs",
        content="M7 is not the release with owner Nina.",
    )

    pack = pipeline.compile_recall(
        "M7",
        limit=2,
    )

    assert len(pack.results) == 2
    assert {item.conflict for item in pack.results} == {True}


def test_m7_sufficiency_expansion_keeps_owner_scope_and_low_confidence_defaults(
    tmp_path: Path,
) -> None:
    pipeline = IngestionPipeline(tmp_path / "memory")
    launch = pipeline.ingest(
        source_id="m7-scope-launch",
        source_type="tool",
        collection="project_docs",
        content="Launch checklist includes the canary deploy steps.",
    )
    owned = pipeline.ingest(
        source_id="m7-scope-owned",
        source_type="user",
        collection="user_curated",
        content="Rollback owner is Nina and rollback escalation goes to release ops.",
        user_id="alice",
        workspace_id="ws1",
    )
    pipeline.ingest(
        source_id="m7-scope-other-owner",
        source_type="user",
        collection="user_curated",
        content="Rollback owner is Mallory in another workspace.",
        user_id="bob",
        workspace_id="ws2",
    )
    pipeline.ingest(
        source_id="m7-scope-low-confidence-web",
        source_type="external",
        collection="external_web",
        content="Rollback owner rumors from an untrusted web mirror.",
    )

    pack = pipeline.compile_recall(
        "launch checklist",
        task="rollback owner",
        limit=1,
        user_id="alice",
        workspace_id="ws1",
        verify_sufficiency=True,
        expand_on_insufficient=True,
    )

    sources = {item.source_id for item in pack.results}
    assert sources == {launch.source_id, owned.source_id}
    assert pack.sufficiency is not None
    assert pack.sufficiency.sufficient is True
    assert pack.sufficiency.expanded is True


def test_m7_compile_recall_reports_insufficient_uncovered_query(tmp_path: Path) -> None:
    pipeline = IngestionPipeline(tmp_path / "memory")
    pipeline.ingest(
        source_id="m7-unrelated",
        source_type="external",
        collection="project_docs",
        content="Release notes mention only deployment status.",
    )

    pack = pipeline.compile_recall(
        "security escalation owner",
        limit=1,
        verify_sufficiency=True,
    )

    assert pack.sufficiency is not None
    assert pack.sufficiency.sufficient is False
    assert "escalation" in pack.sufficiency.missing_terms
    payload = pack.legacy_payload()
    assert payload["sufficiency"]["sufficient"] is False
    assert payload["sufficiency"]["missing_terms"]


def test_m7_private_user_content_cannot_be_indexed_as_public_without_owner(
    tmp_path: Path,
) -> None:
    pipeline = IngestionPipeline(tmp_path / "memory")

    with pytest.raises(ValueError, match="owner scope"):
        pipeline.ingest(
            source_id="m7-private-public",
            source_type="user",
            collection="project_docs",
            content="Private user note should not become unowned public retrieval state.",
            source_origin="user_direct",
            channel_trust="command",
            confirmation_status="user_asserted",
        )

    owned = pipeline.ingest(
        source_id="m7-private-owned",
        source_type="user",
        collection="project_docs",
        content="Private user note may be indexed with owner scope.",
        source_origin="user_direct",
        channel_trust="command",
        confirmation_status="user_asserted",
        user_id="alice",
        workspace_id="ws1",
    )

    scoped = pipeline.compile_recall("private user note", user_id="alice", workspace_id="ws1")
    unscoped = pipeline.compile_recall("private user note")
    assert [item.chunk_id for item in scoped.results] == [owned.chunk_id]
    assert unscoped.results == []
