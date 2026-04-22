from __future__ import annotations

from pathlib import Path

from shisad.memory.manager import MemoryManager
from shisad.memory.schema import MemoryEntry, MemorySource


def _write_entry(
    manager: MemoryManager,
    *,
    entry_type: str,
    key: str,
    value: object,
    source_legacy_origin: str = "user",
    source_origin: str = "user_direct",
    channel_trust: str = "command",
    confirmation_status: str = "user_asserted",
    scope: str = "user",
    predicate: str | None = None,
    workflow_state: str | None = None,
    confirmation_satisfied: bool = False,
) -> MemoryEntry:
    source = MemorySource(origin=source_legacy_origin, source_id=key, extraction_method="manual")
    decision = manager.write_with_provenance(
        entry_type=entry_type,
        key=key,
        value=value,
        predicate=predicate,
        source=source,
        source_origin=source_origin,
        channel_trust=channel_trust,
        confirmation_status=confirmation_status,
        source_id=key,
        scope=scope,
        workflow_state=workflow_state,
        confirmation_satisfied=confirmation_satisfied,
    )
    assert decision.kind == "allow"
    assert decision.entry is not None
    return decision.entry


def test_m3_compile_identity_filters_to_elevated_identity_entries(tmp_path: Path) -> None:
    manager = MemoryManager(tmp_path / "memory")
    preferred = _write_entry(
        manager,
        entry_type="preference",
        key="pref:food",
        value="sushi",
        predicate="likes(food)",
    )
    preferred.importance_weight = 2.0
    preferred.decay_score = 0.8

    timezone = _write_entry(
        manager,
        entry_type="persona_fact",
        key="persona:timezone",
        value="UTC",
    )
    timezone.importance_weight = 1.0
    timezone.decay_score = 0.7

    observed = _write_entry(
        manager,
        entry_type="persona_fact",
        key="persona:observed-habit",
        value="Likes late-night deploy windows.",
        channel_trust="owner_observed",
        confirmation_status="auto_accepted",
    )
    fact = _write_entry(
        manager,
        entry_type="fact",
        key="project:codename",
        value="nebula",
    )

    pack = manager.compile_identity(max_tokens=64)

    assert [entry.id for entry in pack.entries] == [preferred.id, timezone.id]
    assert pack.count == 2
    assert all(entry.trust_band == "elevated" for entry in pack.entries)
    assert observed.id not in {entry.id for entry in pack.entries}
    assert fact.id not in {entry.id for entry in pack.entries}


def test_m3_compile_identity_respects_token_budget(tmp_path: Path) -> None:
    manager = MemoryManager(tmp_path / "memory")
    concise = _write_entry(
        manager,
        entry_type="persona_fact",
        key="persona:timezone",
        value="UTC",
    )
    concise.importance_weight = 2.0
    concise.decay_score = 1.0

    verbose = _write_entry(
        manager,
        entry_type="persona_fact",
        key="persona:deploy-window-note",
        value="Morning deploy windows are easiest to review.",
    )
    verbose.importance_weight = 1.0
    verbose.decay_score = 1.0

    pack = manager.compile_identity(max_tokens=3)

    assert [entry.id for entry in pack.entries] == [concise.id]
    assert pack.count == 1


def test_m3_compile_active_attention_filters_scope_workflow_and_channel_trust(
    tmp_path: Path,
) -> None:
    manager = MemoryManager(tmp_path / "memory")
    session_thread = _write_entry(
        manager,
        entry_type="open_thread",
        key="thread:session-followup",
        value="Follow up on the active session thread.",
        scope="session",
        workflow_state="active",
    )
    waiting_channel = _write_entry(
        manager,
        entry_type="waiting_on",
        key="thread:channel-blocker",
        value="Waiting on a reply in the current channel.",
        scope="channel",
        workflow_state="waiting",
    )
    _write_entry(
        manager,
        entry_type="scheduled",
        key="thread:closed-reminder",
        value="This reminder is already closed.",
        scope="session",
        workflow_state="closed",
    )
    _write_entry(
        manager,
        entry_type="open_thread",
        key="thread:workspace-blocker",
        value="Workspace-wide blocker that should be excluded by scope.",
        scope="workspace",
        workflow_state="blocked",
    )
    _write_entry(
        manager,
        entry_type="open_thread",
        key="thread:shared-participant",
        value="Shared participant channel item should not be in the CLI default.",
        source_legacy_origin="external",
        source_origin="external_message",
        scope="channel",
        workflow_state="active",
        channel_trust="shared_participant",
        confirmation_status="auto_accepted",
        confirmation_satisfied=True,
    )
    _write_entry(
        manager,
        entry_type="fact",
        key="fact:ignore-me",
        value="Not an active-agenda entry.",
    )

    pack = manager.compile_active_attention(
        max_tokens=64,
        scope_filter={"session", "channel"},
        allowed_channel_trusts={"command", "owner_observed"},
    )

    assert {entry.id for entry in pack.entries} == {
        session_thread.id,
        waiting_channel.id,
    }
    assert pack.count == 2
    assert pack.scope_filter == {"session", "channel"}
    assert {entry.workflow_state for entry in pack.entries} == {"active", "waiting"}
