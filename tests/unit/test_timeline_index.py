from __future__ import annotations

from datetime import UTC, datetime

from shisad.core.session import SessionManager
from shisad.core.transcript import TranscriptStore
from shisad.core.types import SessionId, TaintLabel, UserId, WorkspaceId
from shisad.memory.timeline import TimelineIndex


def _append(
    store: TranscriptStore,
    session_id: SessionId,
    *,
    role: str,
    content: str,
    timestamp: datetime,
    evidence_ref_id: str | None = None,
    taint_labels: set[TaintLabel] | None = None,
    metadata: dict[str, object] | None = None,
) -> str:
    entry = store.append(
        session_id,
        role=role,
        content=content,
        taint_labels=taint_labels,
        timestamp=timestamp,
        evidence_ref_id=evidence_ref_id,
        metadata=metadata or {},
    )
    return entry.entry_id


def test_m5_timeline_index_projects_rows_and_searches_owner_scope(tmp_path) -> None:
    sessions = SessionManager(state_dir=tmp_path / "sessions")
    transcripts = TranscriptStore(tmp_path / "transcripts")
    timeline = TimelineIndex(
        tmp_path / "timeline",
        transcript_store=transcripts,
        session_lookup=sessions.get,
    )
    transcripts.add_append_observer(timeline.index_transcript_entry)
    alice = sessions.create(
        channel="cli",
        user_id=UserId("alice"),
        workspace_id=WorkspaceId("ws1"),
    )
    bob = sessions.create(
        channel="cli",
        user_id=UserId("bob"),
        workspace_id=WorkspaceId("ws1"),
    )
    when = datetime(2026, 5, 5, 10, 0, tzinfo=UTC)
    _append(
        transcripts,
        alice.id,
        role="user",
        content="We decided the Ledger issue should use the uuid override.",
        timestamp=when,
        evidence_ref_id="ev-ledger",
        metadata={"selected_thread_id": "thread-ledger"},
    )
    _append(
        transcripts,
        bob.id,
        role="user",
        content="Bob also mentioned the Ledger issue.",
        timestamp=when,
    )

    result = timeline.search(
        query="Ledger issue",
        user_id="alice",
        workspace_id="ws1",
        context_channel="cli",
        now=datetime(2026, 5, 8, 12, 0, tzinfo=UTC),
    )

    assert result.resolver.timezone_source == "utc_default"
    assert result.results_count == 1
    hit = result.results[0]
    assert hit.session_id == str(alice.id)
    assert hit.user_id == "alice"
    assert hit.workspace_id == "ws1"
    assert hit.role == "user"
    assert hit.evidence_ref_id == "ev-ledger"
    assert hit.thread_id == "thread-ledger"
    assert hit.label == "ARCHIVAL SEARCH RESULT"
    assert hit.trust_boundary == "archival_untrusted_content"
    assert "uuid override" in hit.snippet
    assert "Bob also mentioned" not in hit.snippet


def test_m5_timeline_search_fuzzy_last_time_uses_most_recent_sort(tmp_path) -> None:
    sessions = SessionManager(state_dir=tmp_path / "sessions")
    transcripts = TranscriptStore(tmp_path / "transcripts")
    timeline = TimelineIndex(
        tmp_path / "timeline",
        transcript_store=transcripts,
        session_lookup=sessions.get,
    )
    transcripts.add_append_observer(timeline.index_transcript_entry)
    session = sessions.create(
        channel="cli",
        user_id=UserId("alice"),
        workspace_id=WorkspaceId("ws1"),
    )
    older = datetime(2026, 5, 1, 9, 0, tzinfo=UTC)
    newer = datetime(2026, 5, 6, 9, 0, tzinfo=UTC)
    _append(
        transcripts,
        session.id,
        role="user",
        content="We reached out to Alice about the venue.",
        timestamp=older,
    )
    _append(
        transcripts,
        session.id,
        role="assistant",
        content="Last follow-up to Alice was about the restaurant deposit.",
        timestamp=newer,
    )

    result = timeline.search(
        query="when did we last reach out to Alice?",
        user_id="alice",
        workspace_id="ws1",
        context_channel="cli",
        now=datetime(2026, 5, 8, 12, 0, tzinfo=UTC),
    )

    assert result.resolver.sort == "most_recent"
    assert result.resolver.confidence >= 0.6
    assert [hit.timestamp for hit in result.results] == sorted(
        [hit.timestamp for hit in result.results],
        reverse=True,
    )
    assert "restaurant deposit" in result.results[0].snippet


def test_m5_timeline_search_explicit_range_uses_chronological_sort(tmp_path) -> None:
    sessions = SessionManager(state_dir=tmp_path / "sessions")
    transcripts = TranscriptStore(tmp_path / "transcripts")
    timeline = TimelineIndex(
        tmp_path / "timeline",
        transcript_store=transcripts,
        session_lookup=sessions.get,
    )
    transcripts.add_append_observer(timeline.index_transcript_entry)
    session = sessions.create(
        channel="cli",
        user_id=UserId("alice"),
        workspace_id=WorkspaceId("ws1"),
    )
    older = datetime(2026, 5, 1, 9, 0, tzinfo=UTC)
    newer = datetime(2026, 5, 6, 9, 0, tzinfo=UTC)
    _append(
        transcripts,
        session.id,
        role="user",
        content="Venue review started with the short list.",
        timestamp=older,
    )
    _append(
        transcripts,
        session.id,
        role="assistant",
        content="Venue review ended with the restaurant deposit.",
        timestamp=newer,
    )

    result = timeline.search(
        query="venue review",
        user_id="alice",
        workspace_id="ws1",
        context_channel="cli",
        since=datetime(2026, 5, 1, tzinfo=UTC),
        until=datetime(2026, 5, 7, tzinfo=UTC),
    )

    assert result.resolver.sort == "chronological"
    assert [hit.timestamp for hit in result.results] == sorted(
        [hit.timestamp for hit in result.results]
    )


def test_m5_timeline_search_blocks_private_history_in_shared_context(tmp_path) -> None:
    sessions = SessionManager(state_dir=tmp_path / "sessions")
    transcripts = TranscriptStore(tmp_path / "transcripts")
    timeline = TimelineIndex(
        tmp_path / "timeline",
        transcript_store=transcripts,
        session_lookup=sessions.get,
    )
    transcripts.add_append_observer(timeline.index_transcript_entry)
    private_session = sessions.create(
        channel="cli",
        user_id=UserId("alice"),
        workspace_id=WorkspaceId("ws1"),
    )
    _append(
        transcripts,
        private_session.id,
        role="user",
        content="Private lunch note: we ordered soba last time.",
        timestamp=datetime(2026, 5, 4, 12, 0, tzinfo=UTC),
    )

    blocked = timeline.search(
        query="lunch last time",
        user_id="alice",
        workspace_id="ws1",
        context_channel="discord",
        now=datetime(2026, 5, 8, 12, 0, tzinfo=UTC),
    )
    assert blocked.results == []
    assert blocked.publication_policy["private_history_blocked_count"] == 1

    confirmed = timeline.search(
        query="lunch last time",
        user_id="alice",
        workspace_id="ws1",
        context_channel="discord",
        allow_private_history=True,
        now=datetime(2026, 5, 8, 12, 0, tzinfo=UTC),
    )
    assert confirmed.results_count == 1
    assert confirmed.results[0].publication_state == "private_history_share_confirmed"


def test_m5_timeline_redacts_high_sensitivity_rows(tmp_path) -> None:
    sessions = SessionManager(state_dir=tmp_path / "sessions")
    transcripts = TranscriptStore(tmp_path / "transcripts")
    timeline = TimelineIndex(
        tmp_path / "timeline",
        transcript_store=transcripts,
        session_lookup=sessions.get,
    )
    transcripts.add_append_observer(timeline.index_transcript_entry)
    session = sessions.create(
        channel="cli",
        user_id=UserId("alice"),
        workspace_id=WorkspaceId("ws1"),
    )
    _append(
        transcripts,
        session.id,
        role="tool",
        content="credential payload sk-live-secret should not be timeline-searchable",
        timestamp=datetime(2026, 5, 4, 12, 0, tzinfo=UTC),
        taint_labels={TaintLabel.USER_CREDENTIALS},
        metadata={"visibility": "owner_private"},
    )

    secret_search = timeline.search(
        query="sk-live-secret",
        user_id="alice",
        workspace_id="ws1",
        context_channel="cli",
    )
    redacted_search = timeline.search(
        query="redacted",
        user_id="alice",
        workspace_id="ws1",
        context_channel="cli",
    )

    assert secret_search.results == []
    assert redacted_search.results_count == 1
    assert redacted_search.results[0].snippet == "[REDACTED:timeline_sensitive]"
    read = timeline.read(
        redacted_search.results[0].handle,
        user_id="alice",
        workspace_id="ws1",
        context_channel="cli",
    )
    assert read.selected_content == "[REDACTED:timeline_sensitive]"


def test_m5_timeline_read_rejects_deleted_or_stale_rows(tmp_path) -> None:
    sessions = SessionManager(state_dir=tmp_path / "sessions")
    transcripts = TranscriptStore(tmp_path / "transcripts")
    timeline = TimelineIndex(
        tmp_path / "timeline",
        transcript_store=transcripts,
        session_lookup=sessions.get,
    )
    transcripts.add_append_observer(timeline.index_transcript_entry)
    session = sessions.create(
        channel="cli",
        user_id=UserId("alice"),
        workspace_id=WorkspaceId("ws1"),
    )
    entry_id = _append(
        transcripts,
        session.id,
        role="user",
        content="Archive result should disappear if the transcript is deleted.",
        timestamp=datetime(2026, 5, 2, 8, 0, tzinfo=UTC),
    )
    result = timeline.search(
        query="archive result",
        user_id="alice",
        workspace_id="ws1",
        context_channel="cli",
    )
    assert result.results_count == 1
    assert result.results[0].entry_id == entry_id

    transcripts.delete_session(session.id)

    read = timeline.read(
        result.results[0].handle,
        user_id="alice",
        workspace_id="ws1",
        context_channel="cli",
    )
    assert read.found is False
    assert read.reason == "timeline_row_stale"
    assert timeline.search(
        query="archive result",
        user_id="alice",
        workspace_id="ws1",
        context_channel="cli",
    ).results == []


def test_m5_timeline_relative_anchor_requires_clarification(tmp_path) -> None:
    sessions = SessionManager(state_dir=tmp_path / "sessions")
    transcripts = TranscriptStore(tmp_path / "transcripts")
    timeline = TimelineIndex(
        tmp_path / "timeline",
        transcript_store=transcripts,
        session_lookup=sessions.get,
    )

    result = timeline.search(
        query="since we got back",
        user_id="alice",
        workspace_id="ws1",
        context_channel="cli",
    )

    assert result.results == []
    assert result.resolver.clarification_required is True
    assert "relative_anchor_unresolved" in result.resolver.caveats


def test_m5_timeline_resolver_records_supported_fuzzy_windows(tmp_path) -> None:
    sessions = SessionManager(state_dir=tmp_path / "sessions")
    transcripts = TranscriptStore(tmp_path / "transcripts")
    timeline = TimelineIndex(
        tmp_path / "timeline",
        transcript_store=transcripts,
        session_lookup=sessions.get,
    )
    now = datetime(2026, 5, 8, 12, 0, tzinfo=UTC)

    cases = [
        ("what did we do recently", "default_30d"),
        ("what did we do this month", "calendar_month"),
        ("what did we do last week", "calendar_week"),
        ("what happened last tuesday", "calendar_day"),
    ]
    for query, source in cases:
        result = timeline.search(
            query=query,
            user_id="alice",
            workspace_id="ws1",
            context_channel="cli",
            now=now,
        )
        assert result.resolver.since is not None
        assert result.resolver.until is not None
        assert result.resolver.recency_window_source == source
        assert result.resolver.timezone_source == "utc_default"
