"""Session enhancements, transcript store, and alarm tool tests."""

from __future__ import annotations

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
    assert store.read_blob(entry.blob_ref) == payload


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
