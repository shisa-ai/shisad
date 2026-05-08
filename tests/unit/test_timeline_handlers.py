from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from shisad.core.session import SessionManager
from shisad.core.transcript import TranscriptStore
from shisad.core.types import UserId, WorkspaceId
from shisad.daemon.handlers._impl_memory import MemoryImplMixin
from shisad.memory.ingress import IngressContextRegistry
from shisad.memory.manager import MemoryManager
from shisad.memory.timeline import TimelineIndex


class _TimelineHarness(MemoryImplMixin):
    def __init__(self, tmp_path: Path) -> None:
        self.audit_events: list[tuple[str, dict[str, object]]] = []
        self._session_manager = SessionManager(state_dir=tmp_path / "sessions")
        self._transcript_store = TranscriptStore(tmp_path / "transcripts")
        self._timeline_index = TimelineIndex(
            tmp_path / "timeline",
            transcript_store=self._transcript_store,
            session_lookup=self._session_manager.get,
        )
        self._transcript_store.add_append_observer(
            self._timeline_index.index_transcript_entry
        )
        self._memory_manager = MemoryManager(
            tmp_path / "memory",
            audit_hook=lambda action, payload: self.audit_events.append((action, payload)),
        )
        self._memory_ingress_registry = IngressContextRegistry()


def _seed_session(harness: _TimelineHarness):
    session = harness._session_manager.create(
        channel="cli",
        user_id=UserId("alice"),
        workspace_id=WorkspaceId("ws1"),
    )
    entry = harness._transcript_store.append(
        session.id,
        role="user",
        content="We chose Bar Neko for lunch last time.",
        timestamp=datetime(2026, 5, 5, 12, 0, tzinfo=UTC),
        evidence_ref_id="ev-lunch",
        metadata={"selected_thread_id": "thread-food"},
    )
    return session, entry


def _seed_channel_session(harness: _TimelineHarness):
    session = harness._session_manager.create(
        channel="discord",
        user_id=UserId("alice"),
        workspace_id=WorkspaceId("ws1"),
        metadata={
            "delivery_target": {
                "channel": "discord",
                "recipient": "room-a",
                "workspace_hint": "guild-1",
                "thread_id": "thread-1",
            }
        },
    )
    entry = harness._transcript_store.append(
        session.id,
        role="user",
        content="Shared room note: tempura was the group order.",
        timestamp=datetime(2026, 5, 5, 12, 0, tzinfo=UTC),
        metadata={
            "delivery_target": {
                "channel": "discord",
                "recipient": "room-a",
                "workspace_hint": "guild-1",
                "thread_id": "thread-1",
            },
            "visibility": "channel_shared",
        },
    )
    return session, entry


@pytest.mark.asyncio
async def test_memory_timeline_search_and_read_return_archival_packet(tmp_path: Path) -> None:
    harness = _TimelineHarness(tmp_path)
    _seed_session(harness)

    search = await harness.do_memory_timeline_search(
        {
            "query": "lunch last time",
            "user_id": "alice",
            "workspace_id": "ws1",
            "context_channel": "cli",
            "now": datetime(2026, 5, 8, 12, 0, tzinfo=UTC),
        }
    )

    assert search["label"] == "ARCHIVAL SEARCH RESULTS"
    assert search["results_count"] == 1
    hit = search["results"][0]
    assert hit["label"] == "ARCHIVAL SEARCH RESULT"
    assert hit["trust_boundary"] == "archival_untrusted_content"
    assert hit["evidence_ref_id"] == "ev-lunch"

    read = await harness.do_memory_timeline_read(
        {
            "handle": hit["handle"],
            "user_id": "alice",
            "workspace_id": "ws1",
            "context_channel": "cli",
        }
    )

    assert read["found"] is True
    assert read["label"] == "ARCHIVAL SEARCH RESULTS"
    assert "not current user intent" in read["packet"]
    assert "evidence=ev-lunch" in read["packet"]
    assert "source=transcript" in read["packet"]
    assert "provenance=evidence_ref:ev-lunch" in read["packet"]
    assert "trust=archival_untrusted_content" in read["packet"]
    assert read["selected_content"] == "We chose Bar Neko for lunch last time."
    assert read["grouping"]["mode"] == "thread_membership"

    assert harness.audit_events[0][0] == "memory.timeline_search"
    search_audit = harness.audit_events[0][1]
    assert search_audit["query_hash"]
    assert "lunch last time" not in str(search_audit)
    assert search_audit["results_count"] == 1
    assert harness.audit_events[1][0] == "memory.timeline_read"
    read_audit = harness.audit_events[1][1]
    assert read_audit["handle"] == hit["handle"]
    assert read_audit["found"] is True
    assert read_audit["row_count"] == 1


@pytest.mark.asyncio
async def test_memory_timeline_uses_context_session_delivery_target(
    tmp_path: Path,
) -> None:
    harness = _TimelineHarness(tmp_path)
    session, _ = _seed_channel_session(harness)

    without_context = await harness.do_memory_timeline_search(
        {
            "query": "tempura group order",
            "user_id": "alice",
            "workspace_id": "ws1",
            "context_channel": "discord",
        }
    )
    assert without_context["results"] == []

    with_context = await harness.do_memory_timeline_search(
        {
            "query": "tempura group order",
            "user_id": "alice",
            "workspace_id": "ws1",
            "context_channel": "discord",
            "context_session_id": str(session.id),
        }
    )
    assert with_context["results_count"] == 1

    read = await harness.do_memory_timeline_read(
        {
            "handle": with_context["results"][0]["handle"],
            "user_id": "alice",
            "workspace_id": "ws1",
            "context_channel": "discord",
            "context_session_id": str(session.id),
        }
    )
    assert read["found"] is True
    assert "tempura" in read["packet"]


@pytest.mark.asyncio
async def test_memory_timeline_search_requires_complete_owner_scope(tmp_path: Path) -> None:
    harness = _TimelineHarness(tmp_path)
    _seed_session(harness)

    with pytest.raises(ValueError, match="user_id and workspace_id are required"):
        await harness.do_memory_timeline_search(
            {
                "query": "lunch",
                "user_id": "alice",
                "workspace_id": "",
                "context_channel": "cli",
            }
        )


@pytest.mark.asyncio
async def test_memory_timeline_promote_routes_through_memory_write_gate(
    tmp_path: Path,
) -> None:
    harness = _TimelineHarness(tmp_path)
    _seed_session(harness)
    search = await harness.do_memory_timeline_search(
        {
            "query": "Bar Neko",
            "user_id": "alice",
            "workspace_id": "ws1",
            "context_channel": "cli",
        }
    )
    hit = search["results"][0]
    ingress = harness._memory_ingress_registry.mint(
        source_origin="user_confirmed",
        channel_trust="command",
        confirmation_status="user_confirmed",
        scope="user",
        source_id="timeline-promote",
        content="We chose Bar Neko for lunch last time.",
    )

    promoted = await harness.do_memory_timeline_promote(
        {
            "handle": hit["handle"],
            "ingress_context": ingress.handle_id,
            "entry_type": "fact",
            "key": "timeline:lunch:last_time",
            "user_id": "alice",
            "workspace_id": "ws1",
            "context_channel": "cli",
        }
    )

    assert promoted["kind"] == "allow"
    timeline_promote_audits = [
        payload
        for action, payload in harness.audit_events
        if action == "memory.timeline_promote"
    ]
    assert timeline_promote_audits
    assert timeline_promote_audits[-1]["handle"] == hit["handle"]
    assert timeline_promote_audits[-1]["decision"] == "allow"
    assert "Bar Neko" not in str(timeline_promote_audits[-1])
    entry = promoted["entry"]
    assert entry["value"] == "We chose Bar Neko for lunch last time."
    assert entry["source_origin"] == "user_confirmed"
    assert entry["source_id"] == "timeline-promote"
    assert entry["content_digest"] == ingress.content_digest
