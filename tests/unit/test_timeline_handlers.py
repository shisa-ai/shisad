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
        self._memory_manager = MemoryManager(tmp_path / "memory")
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
    assert "trust=archival_untrusted_content" in read["packet"]
    assert read["selected_content"] == "We chose Bar Neko for lunch last time."
    assert read["grouping"]["mode"] == "thread_membership"


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
    entry = promoted["entry"]
    assert entry["value"] == "We chose Bar Neko for lunch last time."
    assert entry["source_origin"] == "user_confirmed"
    assert entry["source_id"] == "timeline-promote"
    assert entry["content_digest"] == ingress.content_digest
