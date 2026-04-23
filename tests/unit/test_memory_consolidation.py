from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from shisad.daemon.handlers._impl_memory import MemoryImplMixin
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
    scope: str = "user",
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
        scope=scope,
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
    _write_owner_observed_episode(
        manager,
        value="At breakfast I said I like coffee.",
        source_id="support-coffee-repeat",
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


def test_m5_quarantined_entries_do_not_drive_confidence_updates_or_identity_candidates(
    tmp_path: Path,
) -> None:
    manager = MemoryManager(tmp_path / "memory")
    preference = _write_entry(
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
        source_id="support-coffee-quarantined",
    )
    ramen = _write_owner_observed_episode(
        manager,
        value="I like ramen for lunch.",
        source_id="ramen-quarantined",
    )
    assert manager.quarantine(support.id, reason="test_quarantine")
    assert manager.quarantine(ramen.id, reason="test_quarantine")

    updates = ConsolidationWorker(manager).apply_confidence_updates()
    candidates = ConsolidationWorker(
        manager,
        config=ConsolidationConfig(identity_candidate_threshold=1),
    ).accumulate_identity_candidates()

    refreshed = manager.get_entry(preference.id)
    assert refreshed is not None
    assert refreshed.confidence == preference.confidence
    assert updates.corroborating_entry_ids == []
    assert manager.list_events(entry_id=preference.id, event_type="corroborated") == []
    assert candidates == []


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


def test_m5_quarantined_entries_do_not_drive_or_resolve_strong_invalidations(
    tmp_path: Path,
) -> None:
    manager = MemoryManager(tmp_path / "memory")
    active_target = _write_entry(
        manager,
        entry_type="persona_fact",
        key="work:acme",
        value="I work at ACME as VP Eng.",
        confidence=0.95,
        source_id="active-target",
    )
    quarantined_target = _write_entry(
        manager,
        entry_type="persona_fact",
        key="work:contoso",
        value="I work at Contoso as CTO.",
        confidence=0.95,
        source_id="quarantined-target",
    )
    active_signal = _write_owner_observed_episode(
        manager,
        value="I no longer work at ACME.",
        source_id="active-signal",
    )
    quarantined_signal = _write_owner_observed_episode(
        manager,
        value="I no longer work at Contoso.",
        source_id="quarantined-signal",
    )
    assert manager.quarantine(quarantined_target.id, reason="test_quarantine")
    assert manager.quarantine(quarantined_signal.id, reason="test_quarantine")

    worker = ConsolidationWorker(manager)
    proposals = worker.propose_strong_invalidations()

    assert [(proposal.target_entry_id, proposal.signal_entry_id) for proposal in proposals] == [
        (active_target.id, active_signal.id)
    ]
    assert worker.confirm_strong_invalidation(
        target_entry_id=quarantined_target.id,
        signal_entry_id=active_signal.id,
        new_value="I no longer work at Contoso.",
        ingress_handle_id="test-ingress",
    ) is None
    assert worker.confirm_strong_invalidation(
        target_entry_id=active_target.id,
        signal_entry_id=quarantined_signal.id,
        new_value="I no longer work at ACME.",
        ingress_handle_id="test-ingress",
    ) is None


def test_m5_strong_invalidation_requires_specific_entity_or_topic_match(
    tmp_path: Path,
) -> None:
    manager = MemoryManager(tmp_path / "memory")
    _write_entry(
        manager,
        entry_type="persona_fact",
        key="work:acme",
        value="I work at ACME as VP Eng.",
        confidence=0.95,
    )
    _write_owner_observed_episode(
        manager,
        value="I left work early today.",
        source_id="generic-work-left",
    )

    proposals = ConsolidationWorker(manager).propose_strong_invalidations()

    assert proposals == []
    assert manager.list_events(event_type="strong_invalidation_proposed") == []


def test_m5_identity_candidate_uses_per_pattern_threshold(tmp_path: Path) -> None:
    manager = MemoryManager(tmp_path / "memory")
    _write_owner_observed_episode(manager, value="I like ramen for lunch.", source_id="ramen-1")
    _write_owner_observed_episode(
        manager,
        value="I prefer ramen when traveling.",
        source_id="ramen-2",
    )

    candidates = ConsolidationWorker(
        manager,
        config=ConsolidationConfig(identity_candidate_threshold=3),
    ).accumulate_identity_candidates()

    assert len(candidates) == 1
    assert candidates[0].predicate == "prefers(ramen)"
    proposed = manager.list_events(entry_id=candidates[0].id, event_type="candidate_proposed")
    assert proposed[-1].metadata_json["threshold"] == 2
    assert proposed[-1].metadata_json["threshold_category"] == "dietary"


def test_m5_strong_invalidations_do_not_cross_scopes(tmp_path: Path) -> None:
    manager = MemoryManager(tmp_path / "memory")
    _write_entry(
        manager,
        entry_type="persona_fact",
        key="work:acme",
        value="I work at ACME as VP Eng.",
        confidence=0.95,
        scope="user",
    )
    _write_entry(
        manager,
        entry_type="episode",
        key="episode:left-acme",
        value="I no longer work at ACME.",
        source_origin="user_direct",
        channel_trust="owner_observed",
        confirmation_status="auto_accepted",
        source_id="left-acme-channel",
        scope="channel",
    )
    _write_entry(
        manager,
        entry_type="persona_fact",
        key="work:globex",
        value="I work at Globex as VP Product.",
        confidence=0.95,
        scope="channel",
    )
    _write_entry(
        manager,
        entry_type="episode",
        key="episode:left-globex",
        value="I no longer work at Globex.",
        source_origin="user_direct",
        channel_trust="owner_observed",
        confirmation_status="auto_accepted",
        source_id="left-globex-channel",
        scope="channel",
    )

    proposals = ConsolidationWorker(
        manager,
        scope_filter={"user", "channel"},
    ).propose_strong_invalidations()

    assert proposals == []
    assert manager.list_events(event_type="strong_invalidation_proposed") == []


def test_m5_dedup_and_identity_candidates_do_not_cross_scopes(tmp_path: Path) -> None:
    manager = MemoryManager(tmp_path / "memory")
    user_duplicate = _write_entry(
        manager,
        entry_type="fact",
        key="fact:scoped-duplicate",
        value="Scoped duplicate fact",
        confidence=0.40,
        source_origin="consolidation_derived",
        channel_trust="consolidation",
        confirmation_status="auto_accepted",
        source_id="scoped-dup-user",
        scope="user",
    )
    channel_duplicate = _write_entry(
        manager,
        entry_type="fact",
        key="fact:scoped-duplicate",
        value="Scoped duplicate fact",
        confidence=0.55,
        source_origin="consolidation_derived",
        channel_trust="consolidation",
        confirmation_status="auto_accepted",
        source_id="scoped-dup-channel",
        scope="channel",
    )
    _write_entry(
        manager,
        entry_type="episode",
        key="episode:ramen-channel-1",
        value="I like ramen for lunch.",
        confidence=0.30,
        source_origin="user_direct",
        channel_trust="owner_observed",
        confirmation_status="auto_accepted",
        source_id="ramen-channel-1",
        scope="channel",
    )
    _write_entry(
        manager,
        entry_type="episode",
        key="episode:ramen-channel-2",
        value="I prefer ramen when traveling.",
        confidence=0.30,
        source_origin="user_direct",
        channel_trust="owner_observed",
        confirmation_status="auto_accepted",
        source_id="ramen-channel-2",
        scope="channel",
    )
    worker = ConsolidationWorker(manager, scope_filter={"user", "channel"})

    dedup = worker.deduplicate_entries()
    candidates = worker.accumulate_identity_candidates()

    assert dedup.merged_entry_ids == []
    assert manager.get_entry(user_duplicate.id) is not None
    assert manager.get_entry(channel_duplicate.id) is not None
    assert candidates == []


def test_m5_repeated_consolidation_is_idempotent_for_conflicts_and_proposals(
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
    _write_entry(
        manager,
        entry_type="preference",
        key="pref:drink",
        value="I prefer tea now.",
        predicate="prefers(tea)",
        confidence=0.80,
    )
    acme = _write_entry(
        manager,
        entry_type="persona_fact",
        key="work:acme",
        value="I work at ACME as VP Eng.",
        confidence=0.95,
    )
    _write_owner_observed_episode(
        manager,
        value="I no longer work at ACME.",
        source_id="left-acme-repeat",
    )
    worker = ConsolidationWorker(manager)

    worker.run_once()
    after_first = manager.get_entry(coffee.id)
    assert after_first is not None
    first_confidence = after_first.confidence
    first_proposals = manager.list_events(
        entry_id=acme.id,
        event_type="strong_invalidation_proposed",
    )
    assert len(first_proposals) == 1

    worker.run_once()
    after_second = manager.get_entry(coffee.id)
    assert after_second is not None
    second_proposals = manager.list_events(
        entry_id=acme.id,
        event_type="strong_invalidation_proposed",
    )
    assert after_second.confidence == first_confidence
    assert len(second_proposals) == 1


def test_m5_dedup_merge_retention_and_reverification_paths(tmp_path: Path) -> None:
    manager = MemoryManager(tmp_path / "memory")
    now = datetime(2026, 4, 23, tzinfo=UTC)
    duplicate_a = _write_entry(
        manager,
        entry_type="fact",
        key="fact:derived-duplicate",
        value="Derived duplicate fact",
        confidence=0.40,
        source_origin="consolidation_derived",
        channel_trust="consolidation",
        confirmation_status="auto_accepted",
        source_id="dup-a",
    )
    duplicate_b = _write_entry(
        manager,
        entry_type="fact",
        key="fact:derived-duplicate",
        value="Derived duplicate fact",
        confidence=0.55,
        source_origin="consolidation_derived",
        channel_trust="consolidation",
        confirmation_status="auto_accepted",
        source_id="dup-b",
    )
    stale = _write_entry(
        manager,
        entry_type="fact",
        key="fact:stale-derived",
        value="Very old unverified derived fact",
        confidence=0.35,
        source_origin="consolidation_derived",
        channel_trust="consolidation",
        confirmation_status="auto_accepted",
        source_id="stale-derived",
    )
    stale.created_at = now - timedelta(days=400)
    stale.decay_score = 0.01
    manager._persist_entry(stale)
    stale_for_reverify = _write_entry(
        manager,
        entry_type="fact",
        key="fact:stale-reverify",
        value="Very old unverified derived fact to reverify",
        confidence=0.35,
        source_origin="consolidation_derived",
        channel_trust="consolidation",
        confirmation_status="auto_accepted",
        source_id="stale-reverify",
    )
    stale_for_reverify.created_at = now - timedelta(days=400)
    stale_for_reverify.decay_score = 0.01
    manager._persist_entry(stale_for_reverify)

    worker = ConsolidationWorker(
        manager,
        config=ConsolidationConfig(archive_threshold=0.05, max_unused_days=180),
    )
    dedup = worker.deduplicate_entries()
    retention = worker.enforce_retention(now=now)

    assert duplicate_a.id in dedup.merged_entry_ids or duplicate_b.id in dedup.merged_entry_ids
    merged = manager.get_entry(duplicate_a.id, include_deleted=True)
    if merged is not None and merged.status != "tombstoned":
        merged = manager.get_entry(duplicate_b.id, include_deleted=True)
    assert merged is not None
    assert merged.status == "tombstoned"
    assert manager.list_events(entry_id=merged.id, event_type="merged")

    assert stale.id in retention.archive_candidate_ids
    assert stale.id in retention.quarantined_entry_ids
    quarantined = manager.get_entry(stale.id, include_quarantined=True)
    assert quarantined is not None
    assert quarantined.status == "quarantined"
    assert manager.list_events(entry_id=stale.id, event_type="archive_review_candidate")
    assert stale_for_reverify.id in retention.archive_candidate_ids
    assert stale_for_reverify.id in retention.quarantined_entry_ids

    assert manager.record_citations([stale.id], cited_at=now) == 1
    cited_rejoined = manager.get_entry(stale.id)
    assert cited_rejoined is not None
    assert cited_rejoined.status == "active"
    assert manager.list_events(entry_id=stale.id, event_type="unquarantined")

    assert worker.reverify_entry(stale_for_reverify.id) is True
    verified_rejoined = manager.get_entry(stale_for_reverify.id)
    assert verified_rejoined is not None
    assert verified_rejoined.status == "active"
    assert manager.list_events(entry_id=stale_for_reverify.id, event_type="unquarantined")

    verified = _write_entry(
        manager,
        entry_type="fact",
        key="fact:reverify",
        value="Reverification raises confidence toward the cap.",
        confidence=0.50,
    )
    assert worker.reverify_entry(verified.id) is True
    refreshed = manager.get_entry(verified.id)
    assert refreshed is not None
    assert refreshed.confidence == 0.60
    assert refreshed.last_verified_at is not None
    assert manager.list_events(entry_id=verified.id, event_type="verified")


def test_m5_strong_invalidation_resolution_and_two_phase_extraction(tmp_path: Path) -> None:
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
        source_id="left-acme-resolution",
    )
    worker = ConsolidationWorker(manager)

    confirmed = worker.confirm_strong_invalidation(
        target_entry_id=acme.id,
        signal_entry_id=signal.id,
        new_value="I no longer work at ACME.",
        ingress_handle_id="user-confirmed-strong-invalid",
    )
    assert confirmed is not None
    assert confirmed.supersedes == acme.id
    assert confirmed.confirmation_status == "user_confirmed"
    assert confirmed.trust_band == "elevated"
    assert manager.list_events(entry_id=confirmed.id, event_type="strong_invalidation_confirmed")

    reject_target = _write_entry(
        manager,
        entry_type="persona_fact",
        key="work:globex",
        value="I work at Globex.",
        confidence=0.95,
    )
    assert worker.reject_strong_invalidation(
        target_entry_id=reject_target.id,
        signal_entry_id=signal.id,
        ingress_handle_id="user-rejected-strong-invalid",
    )
    assert manager.list_events(
        entry_id=reject_target.id,
        event_type="strong_invalidation_rejected",
    )
    assert worker.expire_strong_invalidation(
        target_entry_id=reject_target.id,
        signal_entry_id=signal.id,
    )
    assert manager.list_events(entry_id=reject_target.id, event_type="strong_invalidation_expired")

    extracted = worker.two_phase_extract(
        "Decision: Use MemoryPack for recall. Todo: run release behavioral tests."
    )
    assert [item.phase for item in extracted] == ["cheap", "cheap"]
    assert {item.entry_type for item in extracted} == {"decision", "todo"}


class _ConsolidationHarness(MemoryImplMixin):
    def __init__(self, manager: MemoryManager) -> None:
        self._memory_manager = manager


@pytest.mark.asyncio
async def test_m5_partial_consolidation_flags_keep_dedup_and_retention(
    tmp_path: Path,
) -> None:
    manager = MemoryManager(tmp_path / "memory")
    now = datetime(2026, 4, 23, tzinfo=UTC)
    duplicate_a = _write_entry(
        manager,
        entry_type="fact",
        key="fact:partial-duplicate",
        value="Partial duplicate fact",
        confidence=0.40,
        source_origin="consolidation_derived",
        channel_trust="consolidation",
        confirmation_status="auto_accepted",
        source_id="partial-dup-a",
    )
    duplicate_b = _write_entry(
        manager,
        entry_type="fact",
        key="fact:partial-duplicate",
        value="Partial duplicate fact",
        confidence=0.55,
        source_origin="consolidation_derived",
        channel_trust="consolidation",
        confirmation_status="auto_accepted",
        source_id="partial-dup-b",
    )
    stale = _write_entry(
        manager,
        entry_type="fact",
        key="fact:partial-stale",
        value="Stale partial derived fact",
        confidence=0.35,
        source_origin="consolidation_derived",
        channel_trust="consolidation",
        confirmation_status="auto_accepted",
        source_id="partial-stale",
    )
    stale.created_at = now - timedelta(days=400)
    stale.decay_score = 0.01
    manager._persist_entry(stale)

    result = await _ConsolidationHarness(manager).do_memory_consolidate(
        {"propose_strong_invalidations": False}
    )

    assert set(result["merged_entry_ids"]) == {duplicate_a.id} or set(
        result["merged_entry_ids"]
    ) == {duplicate_b.id}
    assert stale.id in result["archive_candidate_ids"]
    assert stale.id in result["quarantined_entry_ids"]
