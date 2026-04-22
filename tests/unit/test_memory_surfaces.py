from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from shisad.memory.manager import MemoryManager
from shisad.memory.participation import InboxItemValue, inbox_item_key
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


def test_m3_compile_active_attention_channel_binding_limits_channel_scoped_entries(
    tmp_path: Path,
) -> None:
    manager = MemoryManager(tmp_path / "memory")
    session_thread = _write_entry(
        manager,
        entry_type="open_thread",
        key="thread:session-followup",
        value="Follow up on the current conversation.",
        scope="session",
        workflow_state="active",
    )
    user_thread = _write_entry(
        manager,
        entry_type="waiting_on",
        key="thread:user-followup",
        value="Remember to answer the owner later.",
        scope="user",
        workflow_state="waiting",
    )
    general_inbox = _write_entry(
        manager,
        entry_type="inbox_item",
        key=inbox_item_key(owner_id="owner-1", item_id="msg-general"),
        value=InboxItemValue(
            owner_id="owner-1",
            sender_id="guest-1",
            channel_id="discord:guild/general",
            body="Question from #general",
        ).model_dump(mode="python"),
        source_legacy_origin="external",
        source_origin="external_message",
        channel_trust="shared_participant",
        confirmation_status="auto_accepted",
        scope="channel",
        confirmation_satisfied=True,
    )
    _write_entry(
        manager,
        entry_type="inbox_item",
        key=inbox_item_key(owner_id="owner-1", item_id="msg-private"),
        value=InboxItemValue(
            owner_id="owner-1",
            sender_id="guest-2",
            channel_id="discord:guild/private",
            body="Question from #private",
        ).model_dump(mode="python"),
        source_legacy_origin="external",
        source_origin="external_message",
        channel_trust="shared_participant",
        confirmation_status="auto_accepted",
        scope="channel",
        confirmation_satisfied=True,
    )
    _write_entry(
        manager,
        entry_type="open_thread",
        key="thread:unbound-channel-entry",
        value="Channel-scoped item without a bound channel id should fail closed.",
        source_legacy_origin="external",
        source_origin="external_message",
        channel_trust="external_incoming",
        confirmation_status="auto_accepted",
        scope="channel",
        workflow_state="active",
        confirmation_satisfied=True,
    )

    pack = manager.compile_active_attention(
        max_tokens=128,
        scope_filter={"session", "user", "channel"},
        channel_binding="general",
    )

    assert {entry.id for entry in pack.entries} == {
        session_thread.id,
        user_thread.id,
        general_inbox.id,
    }
    assert pack.count == 3
    assert pack.channel_binding == "general"


def test_m3_surface_compiler_citation_ids_drive_usage_updates(tmp_path: Path) -> None:
    manager = MemoryManager(tmp_path / "memory")
    identity_entry = _write_entry(
        manager,
        entry_type="persona_fact",
        key="persona:timezone",
        value="UTC",
    )
    attention_entry = _write_entry(
        manager,
        entry_type="open_thread",
        key="thread:session-followup",
        value="Follow up on the current conversation.",
        scope="session",
        workflow_state="active",
    )

    identity_pack = manager.compile_identity(max_tokens=64)
    attention_pack = manager.compile_active_attention(
        max_tokens=64,
        scope_filter={"session"},
    )
    cited_at = datetime(2026, 4, 22, 22, 15, tzinfo=UTC)

    changed = manager.record_citations(
        identity_pack.citation_ids + attention_pack.citation_ids,
        cited_at=cited_at,
    )

    assert identity_pack.citation_ids == [identity_entry.id]
    assert attention_pack.citation_ids == [attention_entry.id]
    assert changed == 2

    updated_identity = manager.get_entry(identity_entry.id)
    updated_attention = manager.get_entry(attention_entry.id)

    assert updated_identity is not None
    assert updated_attention is not None
    assert updated_identity.citation_count == 1
    assert updated_attention.citation_count == 1
    assert updated_identity.last_cited_at == cited_at
    assert updated_attention.last_cited_at == cited_at

    identity_events = manager.list_events(entry_id=identity_entry.id, event_type="cited", limit=5)
    attention_events = manager.list_events(entry_id=attention_entry.id, event_type="cited", limit=5)

    assert len(identity_events) == 1
    assert len(attention_events) == 1
    assert identity_events[0].metadata_json["cited_at"] == cited_at.isoformat()
    assert attention_events[0].metadata_json["cited_at"] == cited_at.isoformat()
