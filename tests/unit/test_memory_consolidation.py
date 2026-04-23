from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

from shisad.memory.consolidation import ConsolidationConfig, ConsolidationWorker
from shisad.memory.manager import MemoryManager
from shisad.memory.schema import MemoryEntry, MemorySource


def _write_entry(
    manager: MemoryManager,
    *,
    entry_type: str,
    key: str,
    value: str,
    predicate: str | None = None,
    confidence: float = 0.70,
    source_origin: str = "user_direct",
    channel_trust: str = "command",
    confirmation_status: str = "user_asserted",
    source_id: str = "consolidation-test",
) -> MemoryEntry:
    decision = manager.write_with_provenance(
        entry_type=entry_type,
        key=key,
        value=value,
        predicate=predicate,
        source=MemorySource(origin="user", source_id=source_id, extraction_method="manual"),
        source_origin=source_origin,  # type: ignore[arg-type]
        channel_trust=channel_trust,  # type: ignore[arg-type]
        confirmation_status=confirmation_status,  # type: ignore[arg-type]
        source_id=source_id,
        scope="user",
        confidence=confidence,
        confirmation_satisfied=True,
    )
    assert decision.entry is not None
    return decision.entry


def _write_owner_observed_episode(
    manager: MemoryManager,
    *,
    value: str,
    source_id: str,
) -> MemoryEntry:
    return _write_entry(
        manager,
        entry_type="episode",
        key=f"episode:{source_id}",
        value=value,
        confidence=0.30,
        source_origin="user_direct",
        channel_trust="owner_observed",
        confirmation_status="auto_accepted",
        source_id=source_id,
    )


def test_m5_consolidation_worker_scope_is_sandboxed(tmp_path: Path) -> None:
    worker = ConsolidationWorker(MemoryManager(tmp_path / "memory"))

    assert worker.capability_scope.network is False
    assert worker.capability_scope.tool_recursion is False
    assert worker.capability_scope.self_invocation is False
    assert worker.capability_scope.write_scope == "memory_substrate"


def test_m5_decay_recompute_updates_rank_and_emits_event(tmp_path: Path) -> None:
    manager = MemoryManager(tmp_path / "memory")
    now = datetime(2026, 4, 23, tzinfo=UTC)
    stale = _write_entry(manager, entry_type="fact", key="fact:stale", value="Old unused fact")
    fresh = _write_entry(manager, entry_type="fact", key="fact:fresh", value="Fresh cited fact")
    stale.created_at = now - timedelta(days=120)
    stale.citation_count = 0
    fresh.created_at = now - timedelta(days=1)
    fresh.citation_count = 5
    fresh.last_cited_at = now - timedelta(hours=1)
    manager._persist_entry(stale)
    manager._persist_entry(fresh)

    result = ConsolidationWorker(manager).recompute_decay_scores(now=now)

    assert stale.id in result.updated_entry_ids
    refreshed_stale = manager.get_entry(stale.id)
    refreshed_fresh = manager.get_entry(fresh.id)
    assert refreshed_stale is not None
    assert refreshed_fresh is not None
    assert refreshed_stale.decay_score < refreshed_fresh.decay_score
    assert manager.list_events(entry_id=stale.id, event_type="score_recomputed")


def test_m5_corroboration_and_contradiction_update_confidence_with_events(
    tmp_path: Path,
) -> None:
    manager = MemoryManager(tmp_path / "memory")
    coffee = _write_entry(
        manager,
        entry_type="preference",
        key="pref:drink",
        value="I prefer coffee.",
        predicate="prefers(coffee)",
        confidence=0.70,
    )
    support = _write_owner_observed_episode(
        manager,
        value="At breakfast I said I like coffee.",
        source_id="support-coffee",
    )
    tea = _write_entry(
        manager,
        entry_type="preference",
        key="pref:drink",
        value="I prefer tea now.",
        predicate="prefers(tea)",
        confidence=0.80,
    )
    old_confidence = coffee.confidence

    result = ConsolidationWorker(manager).apply_confidence_updates()

    refreshed_coffee = manager.get_entry(coffee.id)
    refreshed_tea = manager.get_entry(tea.id)
    assert refreshed_coffee is not None
    assert refreshed_tea is not None
    assert support.id in result.corroborating_entry_ids
    corroborated = manager.list_events(entry_id=coffee.id, event_type="corroborated")
    assert corroborated
    assert corroborated[-1].metadata_json["new_value"] > old_confidence
    assert tea.id in refreshed_coffee.conflict_entry_ids
    assert coffee.id in refreshed_tea.conflict_entry_ids
    assert manager.list_events(entry_id=coffee.id, event_type="contradicted")


def test_m5_strong_invalidation_and_identity_candidate_accumulation(
    tmp_path: Path,
) -> None:
    manager = MemoryManager(tmp_path / "memory")
    acme = _write_entry(
        manager,
        entry_type="persona_fact",
        key="work:acme",
        value="I work at ACME as VP Eng.",
        confidence=0.95,
    )
    signal = _write_owner_observed_episode(
        manager,
        value="I no longer work at ACME.",
        source_id="left-acme",
    )
    _write_owner_observed_episode(manager, value="I like ramen for lunch.", source_id="ramen-1")
    _write_owner_observed_episode(
        manager,
        value="I prefer ramen when traveling.",
        source_id="ramen-2",
    )
    _write_owner_observed_episode(
        manager,
        value="Ramen is my favorite comfort food.",
        source_id="ramen-3",
    )

    worker = ConsolidationWorker(
        manager,
        config=ConsolidationConfig(identity_candidate_threshold=3, surface_limit=2),
    )
    invalidations = worker.propose_strong_invalidations()
    candidates = worker.accumulate_identity_candidates()

    assert invalidations
    assert invalidations[0].target_entry_id == acme.id
    assert invalidations[0].signal_entry_id == signal.id
    assert manager.list_events(entry_id=acme.id, event_type="strong_invalidation_proposed")

    assert len(candidates) == 1
    candidate = candidates[0]
    assert candidate.confirmation_status == "pending_review"
    assert candidate.entry_type == "preference"
    assert candidate.predicate == "prefers(ramen)"
    assert candidate.trust_band == "untrusted"
    assert {entry.id for entry in manager.list_review_queue()} == {candidate.id}
    assert manager.list_events(entry_id=candidate.id, event_type="candidate_proposed")
