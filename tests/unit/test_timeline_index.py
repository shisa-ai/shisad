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


def test_m5_timeline_search_fuzzy_bounded_window_uses_chronological_sort(tmp_path) -> None:
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
    older = datetime(2026, 4, 29, 9, 0, tzinfo=UTC)
    newer = datetime(2026, 5, 2, 9, 0, tzinfo=UTC)
    _append(
        transcripts,
        session.id,
        role="user",
        content="Venue review opened with the short list.",
        timestamp=older,
    )
    _append(
        transcripts,
        session.id,
        role="assistant",
        content="Venue review closed with the restaurant deposit.",
        timestamp=newer,
    )

    for query in ("venue review last week", "last week venue review"):
        result = timeline.search(
            query=query,
            user_id="alice",
            workspace_id="ws1",
            context_channel="cli",
            now=datetime(2026, 5, 8, 12, 0, tzinfo=UTC),
        )

        assert result.resolver.recency_window_source == "calendar_week"
        assert result.resolver.sort == "chronological"
        assert [hit.timestamp for hit in result.results] == sorted(
            [hit.timestamp for hit in result.results]
        )


def test_m5_timeline_search_fuzzy_weekday_prefix_uses_chronological_sort(tmp_path) -> None:
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
    older = datetime(2026, 5, 5, 9, 0, tzinfo=UTC)
    newer = datetime(2026, 5, 5, 16, 0, tzinfo=UTC)
    _append(
        transcripts,
        session.id,
        role="user",
        content="Venue review began with the Tuesday notes.",
        timestamp=older,
    )
    _append(
        transcripts,
        session.id,
        role="assistant",
        content="Venue review ended with the Tuesday action list.",
        timestamp=newer,
    )

    result = timeline.search(
        query="last tuesday venue review",
        user_id="alice",
        workspace_id="ws1",
        context_channel="cli",
        now=datetime(2026, 5, 8, 12, 0, tzinfo=UTC),
    )

    assert result.resolver.recency_window_source == "calendar_day"
    assert result.resolver.sort == "chronological"
    assert [hit.timestamp for hit in result.results] == sorted(
        [hit.timestamp for hit in result.results]
    )


def test_m5_timeline_search_open_topic_uses_relevance_sort(tmp_path) -> None:
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
        content="Ledger issue follow-up selected the uuid override.",
        timestamp=older,
    )
    _append(
        transcripts,
        session.id,
        role="assistant",
        content="The venue issue was unrelated.",
        timestamp=newer,
    )

    result = timeline.search(
        query="Ledger issue",
        user_id="alice",
        workspace_id="ws1",
        context_channel="cli",
        now=datetime(2026, 5, 8, 12, 0, tzinfo=UTC),
    )

    assert result.resolver.sort == "relevance"
    assert result.results_count == 2
    assert "uuid override" in result.results[0].snippet
    assert result.results[0].timestamp < result.results[1].timestamp


def test_m5_timeline_search_stopword_only_unbounded_requires_clarification(
    tmp_path,
) -> None:
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
        role="user",
        content="Private transcript row must not be browseable by stopwords.",
        timestamp=datetime(2026, 5, 1, 9, 0, tzinfo=UTC),
    )

    result = timeline.search(
        query="what the",
        user_id="alice",
        workspace_id="ws1",
        context_channel="cli",
        now=datetime(2026, 5, 8, 12, 0, tzinfo=UTC),
    )

    assert result.results == []
    assert result.resolver.clarification_required is True
    assert "meaningful_query_required" in result.resolver.caveats


def test_m5_timeline_search_last_tuesday_talk_question_does_not_require_talk_token(
    tmp_path,
) -> None:
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
        role="user",
        content="Alice mentioned the Ledger issue over lunch.",
        timestamp=datetime(2026, 5, 5, 12, 0, tzinfo=UTC),
    )

    result = timeline.search(
        query="Who did I talk to last Tuesday?",
        user_id="alice",
        workspace_id="ws1",
        context_channel="cli",
        now=datetime(2026, 5, 8, 12, 0, tzinfo=UTC),
    )

    assert result.resolver.recency_window_source == "calendar_day"
    assert result.results_count == 1
    assert "Alice mentioned" in result.results[0].snippet


def test_m5_timeline_search_lately_uses_default_recency_window(tmp_path) -> None:
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
        role="user",
        content="We went to Bar Neko for ramen.",
        timestamp=datetime(2026, 5, 1, 12, 0, tzinfo=UTC),
    )
    _append(
        transcripts,
        session.id,
        role="user",
        content="We went to Bar Neko before the old launch.",
        timestamp=datetime(2026, 2, 1, 12, 0, tzinfo=UTC),
    )

    result = timeline.search(
        query="Have we been to Bar Neko lately?",
        user_id="alice",
        workspace_id="ws1",
        context_channel="cli",
        now=datetime(2026, 5, 8, 12, 0, tzinfo=UTC),
    )

    assert result.resolver.recency_window_source == "default_30d"
    assert result.results_count == 1
    assert "ramen" in result.results[0].snippet

    temporal_only = timeline.search(
        query="What happened lately?",
        user_id="alice",
        workspace_id="ws1",
        context_channel="cli",
        now=datetime(2026, 5, 8, 12, 0, tzinfo=UTC),
    )

    assert temporal_only.resolver.recency_window_source == "default_30d"
    assert temporal_only.results_count == 1
    assert "ramen" in temporal_only.results[0].snippet


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
    assert blocked.publication_policy["private_history_excluded"] is True

    unbound_confirmed = timeline.search(
        query="lunch last time",
        user_id="alice",
        workspace_id="ws1",
        context_channel="discord",
        allow_private_history=True,
        now=datetime(2026, 5, 8, 12, 0, tzinfo=UTC),
    )
    assert unbound_confirmed.results == []
    assert unbound_confirmed.publication_policy["context_binding_present"] is False

    confirmed = timeline.search(
        query="lunch last time",
        user_id="alice",
        workspace_id="ws1",
        context_channel="discord",
        context_delivery_target={
            "channel": "discord",
            "recipient": "room-a",
            "workspace_hint": "guild-1",
            "thread_id": "thread-1",
        },
        allow_private_history=True,
        now=datetime(2026, 5, 8, 12, 0, tzinfo=UTC),
    )
    assert confirmed.results_count == 1
    assert confirmed.results[0].publication_state == "private_history_share_confirmed"
    assert confirmed.publication_policy["private_history_excluded"] is False
    assert confirmed.publication_policy["context_binding_present"] is True

    mismatched_channel = timeline.search(
        query="lunch last time",
        user_id="alice",
        workspace_id="ws1",
        context_channel="slack",
        context_delivery_target={
            "channel": "discord",
            "recipient": "room-a",
            "workspace_hint": "guild-1",
            "thread_id": "thread-1",
        },
        allow_private_history=True,
        now=datetime(2026, 5, 8, 12, 0, tzinfo=UTC),
    )
    assert mismatched_channel.results == []

    unbound_read = timeline.read(
        confirmed.results[0].handle,
        user_id="alice",
        workspace_id="ws1",
        context_channel="discord",
        allow_private_history=True,
    )
    assert unbound_read.found is False

    bound_read = timeline.read(
        confirmed.results[0].handle,
        user_id="alice",
        workspace_id="ws1",
        context_channel="discord",
        context_delivery_target={
            "channel": "discord",
            "recipient": "room-a",
            "workspace_hint": "guild-1",
            "thread_id": "thread-1",
        },
        allow_private_history=True,
    )
    assert bound_read.found is True

    mismatched_read = timeline.read(
        confirmed.results[0].handle,
        user_id="alice",
        workspace_id="ws1",
        context_channel="slack",
        context_delivery_target={
            "channel": "discord",
            "recipient": "room-a",
            "workspace_hint": "guild-1",
            "thread_id": "thread-1",
        },
        allow_private_history=True,
    )
    assert mismatched_read.found is False


def test_m5_timeline_search_includes_authorized_channel_shared_rows(tmp_path) -> None:
    sessions = SessionManager(state_dir=tmp_path / "sessions")
    transcripts = TranscriptStore(tmp_path / "transcripts")
    timeline = TimelineIndex(
        tmp_path / "timeline",
        transcript_store=transcripts,
        session_lookup=sessions.get,
    )
    transcripts.add_append_observer(timeline.index_transcript_entry)
    shared_session = sessions.create(
        channel="discord",
        user_id=UserId("alice"),
        workspace_id=WorkspaceId("ws1"),
    )
    _append(
        transcripts,
        shared_session.id,
        role="user",
        content="Shared channel lunch note: tempura was the group order.",
        timestamp=datetime(2026, 5, 4, 12, 0, tzinfo=UTC),
        metadata={
            "delivery_target": {
                "channel": "discord",
                "recipient": "room-a",
                "workspace_hint": "guild-1",
                "thread_id": "thread-1",
            },
            "visibility": "channel_shared",
            "related_memory_ids": ["mem-lunch"],
            "retrieval_chunk_id": "chunk-lunch",
            "selected_thread_id": "thread-lunch",
        },
    )

    result = timeline.search(
        query="tempura lunch",
        user_id="alice",
        workspace_id="ws1",
        context_channel="cli",
    )

    assert result.results_count == 1
    hit = result.results[0]
    assert hit.publication_state == "channel_visible"
    assert hit.thread_id == "thread-lunch"
    assert hit.content_digest
    assert hit.related_memory_ids == ["chunk-lunch", "mem-lunch"]
    assert hit.channel_binding
    assert hit.source_surface == "channel_message"
    assert hit.provenance == "external_message:discord"

    unbound_shared_context = timeline.search(
        query="tempura lunch",
        user_id="alice",
        workspace_id="ws1",
        context_channel="discord",
    )
    assert unbound_shared_context.results == []

    same_room = timeline.search(
        query="tempura lunch",
        user_id="alice",
        workspace_id="ws1",
        context_channel="discord",
        context_delivery_target={
            "channel": "discord",
            "recipient": "room-a",
            "workspace_hint": "guild-1",
            "thread_id": "thread-1",
        },
    )
    assert same_room.results_count == 1

    different_room = timeline.search(
        query="tempura lunch",
        user_id="alice",
        workspace_id="ws1",
        context_channel="discord",
        context_delivery_target={
            "channel": "discord",
            "recipient": "room-b",
            "workspace_hint": "guild-1",
            "thread_id": "thread-1",
        },
    )
    assert different_room.results == []

    cross_channel = timeline.search(
        query="tempura lunch",
        user_id="alice",
        workspace_id="ws1",
        context_channel="slack",
    )
    assert cross_channel.results == []


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
    assert (
        timeline.search(
            query="archive result",
            user_id="alice",
            workspace_id="ws1",
            context_channel="cli",
        ).results
        == []
    )


def test_m5_timeline_read_filters_surrounding_rows_per_publication_policy(tmp_path) -> None:
    sessions = SessionManager(state_dir=tmp_path / "sessions")
    transcripts = TranscriptStore(tmp_path / "transcripts")
    timeline = TimelineIndex(
        tmp_path / "timeline",
        transcript_store=transcripts,
        session_lookup=sessions.get,
    )
    transcripts.add_append_observer(timeline.index_transcript_entry)
    session = sessions.create(
        channel="discord",
        user_id=UserId("alice"),
        workspace_id=WorkspaceId("ws1"),
    )
    _append(
        transcripts,
        session.id,
        role="user",
        content="Shared channel launch decision: use the blue banner.",
        timestamp=datetime(2026, 5, 2, 8, 0, tzinfo=UTC),
        metadata={
            "delivery_target": {
                "channel": "discord",
                "recipient": "room-a",
                "workspace_hint": "guild-1",
                "thread_id": "thread-1",
            },
        },
    )
    _append(
        transcripts,
        session.id,
        role="user",
        content="Private note: the launch password is not for the channel.",
        timestamp=datetime(2026, 5, 2, 8, 1, tzinfo=UTC),
        metadata={"visibility": "owner_private"},
    )
    search = timeline.search(
        query="launch decision",
        user_id="alice",
        workspace_id="ws1",
        context_channel="discord",
        context_delivery_target={
            "channel": "discord",
            "recipient": "room-a",
            "workspace_hint": "guild-1",
            "thread_id": "thread-1",
        },
    )
    assert search.results_count == 1

    read = timeline.read(
        search.results[0].handle,
        user_id="alice",
        workspace_id="ws1",
        context_channel="discord",
        context_delivery_target={
            "channel": "discord",
            "recipient": "room-a",
            "workspace_hint": "guild-1",
            "thread_id": "thread-1",
        },
        surrounding=1,
    )

    assert read.found is True
    assert len(read.rows) == 1
    assert "blue banner" in read.packet
    assert "source=channel_message" in read.packet
    assert "provenance=external_message:discord" in read.packet
    assert "launch password" not in read.packet


def test_m5_timeline_search_rejects_truncated_rows(tmp_path) -> None:
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
        role="user",
        content="Truncated timeline row should disappear.",
        timestamp=datetime(2026, 5, 2, 8, 0, tzinfo=UTC),
    )
    assert (
        timeline.search(
            query="truncated timeline",
            user_id="alice",
            workspace_id="ws1",
            context_channel="cli",
        ).results_count
        == 1
    )

    transcripts.truncate(session.id, keep_entries=0)

    assert (
        timeline.search(
            query="truncated timeline",
            user_id="alice",
            workspace_id="ws1",
            context_channel="cli",
        ).results
        == []
    )


def test_m5_timeline_session_scope_overrides_imported_row_metadata(tmp_path) -> None:
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
        role="user",
        content="Imported archive scope must stay with Alice workspace one.",
        timestamp=datetime(2026, 5, 2, 8, 0, tzinfo=UTC),
        metadata={
            "channel": "discord",
            "user_id": "bob",
            "workspace_id": "ws2",
            "visibility": "channel_shared",
        },
    )

    bob = timeline.search(
        query="archive scope",
        user_id="bob",
        workspace_id="ws2",
        context_channel="discord",
    )
    assert bob.results == []

    shared = timeline.search(
        query="archive scope",
        user_id="alice",
        workspace_id="ws1",
        context_channel="discord",
    )
    assert shared.results == []
    assert shared.publication_policy["private_history_excluded"] is True

    owner = timeline.search(
        query="archive scope",
        user_id="alice",
        workspace_id="ws1",
        context_channel="cli",
    )
    assert owner.results_count == 1
    hit = owner.results[0]
    assert hit.user_id == "alice"
    assert hit.workspace_id == "ws1"
    assert hit.channel == "cli"
    assert hit.visibility == "owner_private"


def test_m5_timeline_relative_anchor_requires_clarification(tmp_path) -> None:
    sessions = SessionManager(state_dir=tmp_path / "sessions")
    transcripts = TranscriptStore(tmp_path / "transcripts")
    timeline = TimelineIndex(
        tmp_path / "timeline",
        transcript_store=transcripts,
        session_lookup=sessions.get,
    )

    for query in (
        "since we got back",
        "what did we do since we got back",
        "what did we do this month since we got back",
        "what did we do since we got back this month",
        "what did we do since we moved last week",
        "what did we do since last weekday",
        "what did we do since this monthly review",
        "what did we do since last week's deploy",
        "what did we do since this month's launch",
        "what did we do since last-week deploy",
        "what did we do since last week-end deploy",
    ):
        result = timeline.search(
            query=query,
            user_id="alice",
            workspace_id="ws1",
            context_channel="cli",
        )

        assert result.results == []
        assert result.resolver.clarification_required is True
        assert "relative_anchor_unresolved" in result.resolver.caveats

    resolved_time_phrase = timeline.search(
        query="what did we do since last week",
        user_id="alice",
        workspace_id="ws1",
        context_channel="cli",
        now=datetime(2026, 5, 8, 12, 0, tzinfo=UTC),
    )
    assert resolved_time_phrase.resolver.clarification_required is False
    assert resolved_time_phrase.resolver.recency_window_source == "calendar_week"


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

    for query in (
        "what happened last weekday",
        "what happened last week's deploy",
        "what happened last-week deploy",
        "what happened last week-end deploy",
    ):
        prefix_collision = timeline.search(
            query=query,
            user_id="alice",
            workspace_id="ws1",
            context_channel="cli",
            now=now,
        )
        assert prefix_collision.resolver.recency_window_source == ""
        assert prefix_collision.resolver.since is None
        assert prefix_collision.resolver.until is None


def test_m5_timeline_fuzzy_time_words_do_not_block_retrieval(tmp_path) -> None:
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
        role="user",
        content="We picked soba for the release lunch.",
        timestamp=datetime(2026, 5, 5, 12, 0, tzinfo=UTC),
    )

    result = timeline.search(
        query="what happened last tuesday",
        user_id="alice",
        workspace_id="ws1",
        context_channel="cli",
        now=datetime(2026, 5, 8, 12, 0, tzinfo=UTC),
    )

    assert result.results_count == 1
    assert "soba" in result.results[0].snippet


def test_m5_timeline_explicit_timezone_offsets_fuzzy_day_boundaries(tmp_path) -> None:
    sessions = SessionManager(state_dir=tmp_path / "sessions")
    transcripts = TranscriptStore(tmp_path / "transcripts")
    timeline = TimelineIndex(
        tmp_path / "timeline",
        transcript_store=transcripts,
        session_lookup=sessions.get,
    )
    result = timeline.search(
        query="what did we do this month",
        user_id="alice",
        workspace_id="ws1",
        context_channel="cli",
        now=datetime(2026, 5, 1, 1, 0, tzinfo=UTC),
        timezone="America/Los_Angeles",
    )

    assert result.resolver.timezone_source == "explicit"
    assert result.resolver.since == datetime(2026, 4, 1, 7, 0, tzinfo=UTC)
    assert result.resolver.until == datetime(2026, 5, 1, 1, 0, tzinfo=UTC)

    malformed = timeline.search(
        query="what did we do this month",
        user_id="alice",
        workspace_id="ws1",
        context_channel="cli",
        now=datetime(2026, 5, 1, 1, 0, tzinfo=UTC),
        timezone="/tmp/not-a-zone",
    )
    assert malformed.resolver.timezone_source == "utc_default"
    assert "timezone_unavailable" in malformed.resolver.caveats
