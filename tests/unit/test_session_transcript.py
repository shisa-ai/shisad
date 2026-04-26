"""Session enhancements, transcript store, and alarm tool tests."""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import pytest

from shisad.core.audit import AuditLog
from shisad.core.events import EventBus
from shisad.core.session import SessionManager
from shisad.core.tools.builtin.alarm import AlarmTool, AnomalyReportInput
from shisad.core.transcript import TranscriptStore
from shisad.core.types import Capability, SessionId, UserId, WorkspaceId


def test_m1_session_identity_binding_and_key_format() -> None:
    manager = SessionManager()
    session = manager.create(
        channel="cli",
        user_id=UserId("alice"),
        workspace_id=WorkspaceId("ws1"),
    )

    assert session.session_key.startswith("ws1:alice:")
    assert manager.validate_identity_binding(
        session.id,
        channel="cli",
        user_id=UserId("alice"),
        workspace_id=WorkspaceId("ws1"),
    )
    assert not manager.validate_identity_binding(
        session.id,
        channel="discord",
        user_id=UserId("alice"),
        workspace_id=WorkspaceId("ws1"),
    )


def test_m1_session_capabilities_cannot_be_self_granted() -> None:
    events: list[tuple[str, dict[str, object]]] = []

    def hook(action: str, data: dict[str, object]) -> None:
        events.append((action, data))

    manager = SessionManager(audit_hook=hook)
    session = manager.create(user_id=UserId("alice"), workspace_id=WorkspaceId("ws1"))

    assert not manager.grant_capabilities(
        session.id,
        {Capability.HTTP_REQUEST},
        actor="agent",
    )

    assert manager.grant_capabilities(
        session.id,
        {Capability.HTTP_REQUEST},
        actor="uid:1000",
    )
    assert events
    assert events[0][0] == "session.capability_granted"


def test_m1_session_capabilities_reject_untrusted_actor_strings() -> None:
    manager = SessionManager()
    session = manager.create(user_id=UserId("alice"), workspace_id=WorkspaceId("ws1"))

    granted = manager.grant_capabilities(
        session.id,
        {Capability.HTTP_REQUEST},
        actor="planner",
    )
    assert not granted


def test_m1_transcript_store_uses_blob_reference_for_large_content(tmp_path: Path) -> None:
    store = TranscriptStore(tmp_path / "transcripts", blob_threshold_bytes=16)
    payload = "x" * 64

    entry = store.append(
        SessionId("s1"),
        role="user",
        content=payload,
        taint_labels=set(),
    )

    assert entry.blob_ref is not None
    assert entry.entry_id.startswith("tx-")
    assert store.read_blob(entry.blob_ref) == payload


def test_m1_transcript_store_persists_entry_ids_across_reload(tmp_path: Path) -> None:
    store = TranscriptStore(tmp_path / "sessions")
    session_id = SessionId("persist-entry-id")

    created = store.append(
        session_id,
        role="user",
        content="remember this exact turn",
        taint_labels=set(),
    )

    reloaded = TranscriptStore(tmp_path / "sessions")
    entries = reloaded.list_entries(session_id)

    assert len(entries) == 1
    assert entries[0].entry_id == created.entry_id


def test_m1_transcript_store_backfills_legacy_entry_ids_deterministically(
    tmp_path: Path,
) -> None:
    store = TranscriptStore(tmp_path / "sessions")
    session_id = SessionId("legacy-entry-id")
    transcript_path = tmp_path / "sessions" / "transcripts" / f"{session_id}.jsonl"
    transcript_path.parent.mkdir(parents=True, exist_ok=True)
    transcript_path.write_text(
        json.dumps(
            {
                "role": "user",
                "content_hash": "deadbeef",
                "taint_labels": [],
                "timestamp": "2026-04-22T00:00:00+00:00",
                "blob_ref": None,
                "content_preview": "legacy turn",
                "evidence_ref_id": None,
                "metadata": {"timestamp_utc": "2026-04-22T00:00:00+00:00"},
            }
        )
        + "\n",
        encoding="utf-8",
    )

    first = store.list_entries(session_id)
    second = store.list_entries(session_id)

    assert len(first) == 1
    assert first[0].entry_id.startswith("tx-")
    assert second[0].entry_id == first[0].entry_id


def test_leak_source_scoping_limits_to_recent_user_entries(tmp_path: Path) -> None:
    """`_session_source_text_by_id` must scope to the most recent N user
    entries so the cross-thread leak detector does not widen its source
    window as session history grows (v0.7.1 C2 finding #3).
    """
    from shisad.daemon.handlers._impl import HandlerImplementation

    store = TranscriptStore(tmp_path / "sessions")
    session_id = SessionId("s-recent-window")
    window = HandlerImplementation._LEAK_SOURCE_RECENT_USER_ENTRIES
    # Write window+5 distinct user entries so the older five must be dropped.
    for index in range(window + 5):
        store.append(
            session_id,
            role="user",
            content=f"user turn {index}",
        )
    # Assistant entries must not count toward the window.
    for index in range(3):
        store.append(
            session_id,
            role="assistant",
            content=f"assistant turn {index}",
        )

    class _Stub:
        _transcript_store = store
        _LEAK_SOURCE_RECENT_USER_ENTRIES = window

    scoped = HandlerImplementation._session_source_text_by_id(
        _Stub(),  # type: ignore[arg-type]
        session_id,
    )

    assert len(scoped) == window
    assert all("user turn" in preview for preview in scoped.values())
    assert "user turn 0" not in set(scoped.values())
    assert "user turn 4" not in set(scoped.values())
    assert f"user turn {window + 4}" in set(scoped.values())


def test_m6_transcript_store_writes_secure_permissions(tmp_path: Path) -> None:
    store = TranscriptStore(tmp_path / "sessions", blob_threshold_bytes=16)
    entry = store.append(
        SessionId("s1"),
        role="assistant",
        content="x" * 64,
        taint_labels=set(),
    )
    transcript_path = tmp_path / "sessions" / "transcripts" / "s1.jsonl"
    blob_path = tmp_path / "sessions" / "blobs" / f"{entry.blob_ref}.txt"

    transcript_mode = stat.S_IMODE(os.stat(transcript_path).st_mode)
    blob_mode = stat.S_IMODE(os.stat(blob_path).st_mode)
    assert transcript_mode == 0o600
    assert blob_mode == 0o600


def test_m2_transcript_store_truncate_discards_tail_entries(tmp_path: Path) -> None:
    store = TranscriptStore(tmp_path / "sessions")
    session_id = SessionId("m2-session")
    store.append(session_id, role="user", content="first", taint_labels=set())
    store.append(session_id, role="assistant", content="second", taint_labels=set())
    store.append(session_id, role="user", content="third", taint_labels=set())

    removed = store.truncate(session_id, keep_entries=1)
    entries = store.list_entries(session_id)

    assert removed == 2
    assert len(entries) == 1
    assert entries[0].content_preview == "first"


@pytest.mark.asyncio
async def test_m1_t15_report_anomaly_tool_always_succeeds_and_logs(tmp_path: Path) -> None:
    audit = AuditLog(tmp_path / "audit.jsonl")
    bus = EventBus(persister=audit)
    tool = AlarmTool(bus)

    result = await tool.execute(
        session_id=SessionId("s1"),
        actor="planner",
        payload=AnomalyReportInput(
            anomaly_type="prompt_injection",
            description="Untrusted content asked for secret exfiltration",
            recommended_action="lockdown",
            confidence=0.9,
        ),
    )

    assert result == {"status": "recorded"}

    events = audit.query(event_type="AnomalyReported")
    assert len(events) == 1
    assert "prompt_injection" in events[0]["data"]["description"]
