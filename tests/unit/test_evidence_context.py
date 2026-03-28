"""Evidence-ref transcript, context, and PEP coverage."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from shisad.core.evidence import EvidenceStore
from shisad.core.tools.registry import ToolRegistry
from shisad.core.tools.schema import ToolDefinition, ToolParameter
from shisad.core.transcript import TranscriptStore
from shisad.core.types import Capability, SessionId, TaintLabel, ToolName
from shisad.daemon.handlers._impl import (
    _structured_evidence_promote,
    _structured_evidence_read,
)
from shisad.daemon.handlers._impl_session import (
    _build_evidence_supplemental_entries,
    _build_planner_conversation_context,
    _wrap_serialized_tool_outputs_with_evidence,
)
from shisad.security.firewall import ContentFirewall
from shisad.security.pep import PEP, PolicyContext
from shisad.security.policy import PolicyBundle


def _registry_for_evidence() -> ToolRegistry:
    registry = ToolRegistry()
    registry.register(
        ToolDefinition(
            name=ToolName("evidence.read"),
            description="read evidence",
            parameters=[ToolParameter(name="ref_id", type="string", required=True)],
            capabilities_required=[Capability.MEMORY_READ],
        )
    )
    registry.register(
        ToolDefinition(
            name=ToolName("evidence.promote"),
            description="promote evidence",
            parameters=[ToolParameter(name="ref_id", type="string", required=True)],
            capabilities_required=[Capability.MEMORY_READ],
        )
    )
    return registry


def test_wrap_serialized_tool_outputs_replaces_large_untrusted_content_with_stub(tmp_path) -> None:
    store = EvidenceStore(tmp_path / "evidence", salt=b"a" * 32)
    records = [
        {
            "tool_name": "web.fetch",
            "success": True,
            "payload": {
                "ok": True,
                "url": "https://example.com/article",
                "content": "A" * 400,
            },
            "taint_labels": ["untrusted"],
        }
    ]

    ref_ids = _wrap_serialized_tool_outputs_with_evidence(
        session_id=SessionId("sess-a"),
        records=records,
        evidence_store=store,
        firewall=ContentFirewall(),
    )

    assert len(ref_ids) == 1
    content = records[0]["payload"]["content"]
    assert isinstance(content, str)
    assert content.startswith("[EVIDENCE ref=ev-")
    assert store.read(SessionId("sess-a"), ref_ids[0]) == "A" * 400


def test_build_planner_conversation_context_skips_ephemeral_evidence_entries(tmp_path) -> None:
    store = TranscriptStore(tmp_path / "sessions")
    sid = SessionId("sess-a")
    store.append(sid, role="assistant", content="normal answer")
    store.append(
        sid,
        role="assistant",
        content="secret evidence contents",
        taint_labels={TaintLabel.UNTRUSTED},
        metadata={"ephemeral_evidence_read": True},
    )

    rendered, taints = _build_planner_conversation_context(
        transcript_store=store,
        session_id=sid,
        context_window=10,
        exclude_latest_turn=False,
    )

    assert "normal answer" in rendered
    assert "secret evidence contents" not in rendered
    assert TaintLabel.UNTRUSTED not in taints


def test_build_planner_conversation_context_reads_promoted_blob_content(tmp_path) -> None:
    store = TranscriptStore(tmp_path / "sessions", blob_threshold_bytes=16)
    sid = SessionId("sess-a")
    promoted = "promoted summary " + ("x" * 40) + " tail-marker"
    store.append(
        sid,
        role="assistant",
        content=promoted,
        taint_labels={TaintLabel.USER_REVIEWED},
        metadata={"promoted_evidence": True, "promoted_ref_id": "ev-promoted"},
        evidence_ref_id="ev-promoted",
    )

    rendered, taints = _build_planner_conversation_context(
        transcript_store=store,
        session_id=sid,
        context_window=10,
        exclude_latest_turn=False,
    )

    assert "tail-marker" in rendered
    assert TaintLabel.USER_REVIEWED in taints


def test_build_evidence_supplemental_entries_marks_read_ephemeral_and_promote_persistent() -> None:
    records = [
        {
            "tool_name": "evidence.read",
            "success": True,
            "payload": {
                "ok": True,
                "ref_id": "ev-read",
                "source": "web.fetch:example.com",
                "content": "full read content",
                "taint_labels": ["untrusted"],
            },
            "taint_labels": ["untrusted"],
        },
        {
            "tool_name": "evidence.promote",
            "success": True,
            "payload": {
                "ok": True,
                "ref_id": "ev-promote",
                "source": "web.fetch:example.com",
                "content": "promoted content",
                "taint_labels": ["user_reviewed"],
            },
            "taint_labels": ["user_reviewed"],
        },
    ]

    supplemental, chat_records = _build_evidence_supplemental_entries(
        records=records,
        channel="cli",
        session_mode=SimpleNamespace(value="default"),
    )

    assert len(supplemental) == 2
    assert supplemental[0]["metadata"]["ephemeral_evidence_read"] is True
    assert supplemental[1]["metadata"]["promoted_evidence"] is True
    assert "content" not in chat_records[0]["payload"]
    assert "content" not in chat_records[1]["payload"]


def test_pep_allows_valid_evidence_read_and_rejects_forged_ref(tmp_path) -> None:
    store = EvidenceStore(tmp_path / "evidence", salt=b"a" * 32)
    sid = SessionId("sess-a")
    ref = store.store(
        sid,
        "hello",
        taint_labels={TaintLabel.UNTRUSTED},
        source="web.fetch:example.com",
        summary="hello",
    )
    pep = PEP(
        PolicyBundle(default_require_confirmation=False),
        _registry_for_evidence(),
        evidence_store=store,
    )

    allowed = pep.evaluate(
        ToolName("evidence.read"),
        {"ref_id": ref.ref_id},
        PolicyContext(capabilities={Capability.MEMORY_READ}, session_id=sid),
    )
    rejected = pep.evaluate(
        ToolName("evidence.read"),
        {"ref_id": "ev-0000000000000000"},
        PolicyContext(capabilities={Capability.MEMORY_READ}, session_id=sid),
    )

    assert allowed.kind.value == "allow"
    assert rejected.kind.value == "reject"
    assert rejected.reason == "invalid or unknown evidence reference"


def test_pep_requires_confirmation_for_valid_evidence_promote(tmp_path) -> None:
    store = EvidenceStore(tmp_path / "evidence", salt=b"a" * 32)
    sid = SessionId("sess-a")
    ref = store.store(
        sid,
        "hello",
        taint_labels={TaintLabel.UNTRUSTED},
        source="web.fetch:example.com",
        summary="hello",
    )
    pep = PEP(
        PolicyBundle(default_require_confirmation=False),
        _registry_for_evidence(),
        evidence_store=store,
    )

    decision = pep.evaluate(
        ToolName("evidence.promote"),
        {"ref_id": ref.ref_id},
        PolicyContext(capabilities={Capability.MEMORY_READ}, session_id=sid),
    )

    assert decision.kind.value == "require_confirmation"


@pytest.mark.asyncio
async def test_structured_evidence_handlers_return_expected_content_and_taints(tmp_path) -> None:
    store = EvidenceStore(tmp_path / "evidence", salt=b"a" * 32)
    sid = SessionId("sess-a")
    ref = store.store(
        sid,
        "full body",
        taint_labels={TaintLabel.UNTRUSTED},
        source="web.fetch:example.com",
        summary="full body",
    )
    handler = SimpleNamespace(_evidence_store=store)
    context = SimpleNamespace(session_id=sid)

    read_payload = await _structured_evidence_read(handler, {"ref_id": ref.ref_id}, context)
    promote_payload = await _structured_evidence_promote(handler, {"ref_id": ref.ref_id}, context)

    assert read_payload["ok"] is True
    assert read_payload["content"] == "full body"
    assert read_payload["taint_labels"] == [TaintLabel.UNTRUSTED.value]
    assert promote_payload["ok"] is True
    assert promote_payload["content"] == "full body"
    assert promote_payload["taint_labels"] == [TaintLabel.USER_REVIEWED.value]
