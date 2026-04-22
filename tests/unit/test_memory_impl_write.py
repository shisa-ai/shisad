"""Unit coverage for handle-based memory writes."""

from __future__ import annotations

from pathlib import Path

import pytest

from shisad.daemon.handlers._impl_memory import MemoryImplMixin
from shisad.memory.ingress import IngressContextRegistry
from shisad.memory.manager import MemoryManager
from shisad.memory.remap import digest_memory_value
from shisad.memory.trust import TrustGateViolation


class _MemoryWriteHarness(MemoryImplMixin):
    def __init__(self, tmp_path: Path) -> None:
        self._memory_manager = MemoryManager(tmp_path / "memory")
        self._memory_ingress_registry = IngressContextRegistry()


@pytest.mark.asyncio
async def test_memory_write_accepts_handle_bound_direct_payload(tmp_path: Path) -> None:
    harness = _MemoryWriteHarness(tmp_path)
    context = harness._memory_ingress_registry.mint(
        source_origin="user_direct",
        channel_trust="command",
        confirmation_status="user_asserted",
        scope="user",
        source_id="turn-1",
        content="remember this",
    )

    result = await harness.do_memory_write(
        {
            "ingress_context": context.handle_id,
            "entry_type": "fact",
            "key": "profile.note",
            "value": "remember this",
            "confidence": 0.99,
        }
    )

    assert result["kind"] == "allow"
    entry = result["entry"]
    assert entry is not None
    assert entry["source_origin"] == "user_direct"
    assert entry["channel_trust"] == "command"
    assert entry["confirmation_status"] == "user_asserted"
    assert entry["scope"] == "user"
    assert entry["ingress_handle_id"] == context.handle_id
    assert entry["content_digest"] == context.content_digest
    assert entry["confidence"] == pytest.approx(0.95)


@pytest.mark.asyncio
async def test_memory_write_rejects_mismatched_handle_binding(tmp_path: Path) -> None:
    harness = _MemoryWriteHarness(tmp_path)
    context = harness._memory_ingress_registry.mint(
        source_origin="user_direct",
        channel_trust="command",
        confirmation_status="user_asserted",
        scope="user",
        source_id="turn-2",
        content="trusted payload",
    )

    with pytest.raises(TrustGateViolation):
        await harness.do_memory_write(
            {
                "ingress_context": context.handle_id,
                "entry_type": "fact",
                "key": "profile.note",
                "value": "different payload",
            }
        )


@pytest.mark.asyncio
async def test_note_create_accepts_handle_bound_extracted_payload(tmp_path: Path) -> None:
    harness = _MemoryWriteHarness(tmp_path)
    context = harness._memory_ingress_registry.mint(
        source_origin="user_direct",
        channel_trust="command",
        confirmation_status="user_asserted",
        scope="user",
        source_id="turn-3",
        content="remember that my favorite color is blue",
    )

    result = await harness.do_note_create(
        {
            "ingress_context": context.handle_id,
            "key": "note:favorite-color",
            "content": "my favorite color is blue",
            "content_digest": digest_memory_value("my favorite color is blue"),
            "derivation_path": "extracted",
            "parent_digest": context.content_digest,
        }
    )

    assert result["kind"] == "allow"
    entry = result["entry"]
    assert entry is not None
    assert entry["entry_type"] == "note"
    assert entry["source_origin"] == "user_direct"
    assert entry["channel_trust"] == "command"
    assert entry["confirmation_status"] == "user_asserted"
    assert entry["ingress_handle_id"] == context.handle_id
    assert entry["content_digest"] == digest_memory_value("my favorite color is blue")


@pytest.mark.asyncio
async def test_todo_create_accepts_handle_bound_extracted_payload(tmp_path: Path) -> None:
    harness = _MemoryWriteHarness(tmp_path)
    context = harness._memory_ingress_registry.mint(
        source_origin="user_direct",
        channel_trust="command",
        confirmation_status="user_asserted",
        scope="user",
        source_id="turn-4",
        content="add a todo: review PRs tomorrow",
    )

    todo_payload = {
        "title": "review PRs",
        "details": "",
        "status": "open",
        "due_date": "tomorrow",
    }
    result = await harness.do_todo_create(
        {
            **todo_payload,
            "ingress_context": context.handle_id,
            "content_digest": digest_memory_value(todo_payload),
            "derivation_path": "extracted",
            "parent_digest": context.content_digest,
        }
    )

    assert result["kind"] == "allow"
    entry = result["entry"]
    assert entry is not None
    assert entry["entry_type"] == "todo"
    assert entry["source_origin"] == "user_direct"
    assert entry["channel_trust"] == "command"
    assert entry["confirmation_status"] == "user_asserted"
    assert entry["ingress_handle_id"] == context.handle_id
    assert entry["content_digest"] == digest_memory_value(todo_payload)
    assert entry["value"]["title"] == "review PRs"


@pytest.mark.asyncio
async def test_memory_write_legacy_source_path_still_works_for_internal_fallbacks(
    tmp_path: Path,
) -> None:
    harness = _MemoryWriteHarness(tmp_path)

    result = await harness.do_memory_write(
        {
            "source": {
                "origin": "user",
                "source_id": "legacy-1",
                "extraction_method": "manual",
            },
            "entry_type": "fact",
            "key": "profile.name",
            "value": "alice",
        }
    )

    assert result["kind"] == "allow"
    entry = result["entry"]
    assert entry is not None
    assert entry["source_origin"] == "user_direct"
    assert entry["confirmation_status"] == "auto_accepted"
    assert entry["ingress_handle_id"]
    assert entry["content_digest"]


@pytest.mark.asyncio
async def test_memory_write_legacy_external_path_respects_confirmation_override(
    tmp_path: Path,
) -> None:
    harness = _MemoryWriteHarness(tmp_path)

    result = await harness.do_memory_write(
        {
            "source": {
                "origin": "external",
                "source_id": "doc-1",
                "extraction_method": "extract",
            },
            "entry_type": "fact",
            "key": "project.note",
            "value": "external fact",
            "user_confirmed": True,
        }
    )

    assert result["kind"] == "allow"
    entry = result["entry"]
    assert entry is not None
    assert entry["source_origin"] == "external_web"
    assert entry["confirmation_status"] == "auto_accepted"
    assert entry["ingress_handle_id"]


@pytest.mark.asyncio
async def test_memory_write_accepts_procedural_install_triple(tmp_path: Path) -> None:
    harness = _MemoryWriteHarness(tmp_path)
    context = harness._memory_ingress_registry.mint(
        source_origin="tool_output",
        channel_trust="tool_passed",
        confirmation_status="pep_approved",
        scope="user",
        source_id="tool-install-1",
        content="skill demo v1",
    )

    result = await harness.do_memory_write(
        {
            "ingress_context": context.handle_id,
            "entry_type": "skill",
            "key": "skill:demo",
            "value": "skill demo v1",
            "invocation_eligible": True,
        }
    )

    assert result["kind"] == "allow"
    entry = result["entry"]
    assert entry is not None
    assert entry["invocation_eligible"] is True
    assert entry["source_origin"] == "tool_output"
    assert entry["channel_trust"] == "tool_passed"
    assert entry["confirmation_status"] == "pep_approved"


@pytest.mark.asyncio
async def test_memory_write_rejects_invalid_install_triple_for_procedural_entry(
    tmp_path: Path,
) -> None:
    harness = _MemoryWriteHarness(tmp_path)
    context = harness._memory_ingress_registry.mint(
        source_origin="user_direct",
        channel_trust="command",
        confirmation_status="auto_accepted",
        scope="user",
        source_id="turn-5",
        content="skill from command channel",
    )

    result = await harness.do_memory_write(
        {
            "ingress_context": context.handle_id,
            "entry_type": "skill",
            "key": "skill:command",
            "value": "skill from command channel",
            "invocation_eligible": True,
        }
    )

    assert result["kind"] == "reject"
    assert result["reason"] == "invocation_eligible_requires_install_triple"


@pytest.mark.asyncio
async def test_memory_write_supports_supersedes_chain(tmp_path: Path) -> None:
    harness = _MemoryWriteHarness(tmp_path)
    context = harness._memory_ingress_registry.mint(
        source_origin="user_direct",
        channel_trust="command",
        confirmation_status="user_asserted",
        scope="user",
        source_id="turn-6",
        content="draft one",
    )
    first = await harness.do_memory_write(
        {
            "ingress_context": context.handle_id,
            "entry_type": "note",
            "key": "note:chain",
            "value": "draft one",
        }
    )
    assert first["entry"] is not None

    next_context = harness._memory_ingress_registry.mint(
        source_origin="user_direct",
        channel_trust="command",
        confirmation_status="user_asserted",
        scope="user",
        source_id="turn-7",
        content="draft two",
    )
    second = await harness.do_memory_write(
        {
            "ingress_context": next_context.handle_id,
            "entry_type": "note",
            "key": "note:chain",
            "value": "draft two",
            "supersedes": first["entry"]["id"],
        }
    )

    assert second["kind"] == "allow"
    assert second["entry"] is not None
    assert second["entry"]["version"] == 2
    assert second["entry"]["supersedes"] == first["entry"]["id"]


@pytest.mark.asyncio
async def test_memory_supersede_impl_reuses_write_path(tmp_path: Path) -> None:
    harness = _MemoryWriteHarness(tmp_path)
    context = harness._memory_ingress_registry.mint(
        source_origin="user_direct",
        channel_trust="command",
        confirmation_status="user_asserted",
        scope="user",
        source_id="turn-8",
        content="first draft",
    )
    first = await harness.do_memory_write(
        {
            "ingress_context": context.handle_id,
            "entry_type": "note",
            "key": "note:supersede-api",
            "value": "first draft",
        }
    )

    assert first["entry"] is not None

    next_context = harness._memory_ingress_registry.mint(
        source_origin="user_direct",
        channel_trust="command",
        confirmation_status="user_asserted",
        scope="user",
        source_id="turn-9",
        content="second draft",
    )
    second = await harness.do_memory_supersede(
        {
            "ingress_context": next_context.handle_id,
            "entry_type": "note",
            "key": "note:supersede-api",
            "value": "second draft",
            "supersedes": first["entry"]["id"],
        }
    )

    assert second["kind"] == "allow"
    assert second["entry"] is not None
    assert second["entry"]["version"] == 2
    assert second["entry"]["supersedes"] == first["entry"]["id"]
    original = harness._memory_manager.get_entry(str(first["entry"]["id"]), include_deleted=True)
    assert original is not None
    assert original.superseded_by == second["entry"]["id"]


@pytest.mark.asyncio
async def test_memory_set_workflow_state_updates_active_agenda_entry(tmp_path: Path) -> None:
    harness = _MemoryWriteHarness(tmp_path)
    context = harness._memory_ingress_registry.mint(
        source_origin="user_direct",
        channel_trust="command",
        confirmation_status="user_asserted",
        scope="user",
        source_id="turn-open-thread",
        content="follow up with vendor tomorrow",
    )

    created = await harness.do_memory_write(
        {
            "ingress_context": context.handle_id,
            "entry_type": "open_thread",
            "key": "thread:vendor-followup",
            "value": "follow up with vendor tomorrow",
        }
    )

    assert created["entry"] is not None
    entry_id = str(created["entry"]["id"])

    updated = await harness.do_memory_set_workflow_state(
        {
            "entry_id": entry_id,
            "workflow_state": "closed",
        }
    )

    assert updated["changed"] is True
    assert updated["workflow_state"] == "closed"
    entry = harness._memory_manager.get_entry(entry_id)
    assert entry is not None
    assert entry.workflow_state == "closed"
    assert entry.status == "active"


@pytest.mark.asyncio
async def test_memory_quarantine_cycle_preserves_workflow_state_via_impl(tmp_path: Path) -> None:
    harness = _MemoryWriteHarness(tmp_path)
    context = harness._memory_ingress_registry.mint(
        source_origin="user_direct",
        channel_trust="command",
        confirmation_status="user_asserted",
        scope="user",
        source_id="turn-waiting-thread",
        content="waiting on customer response",
    )

    created = await harness.do_memory_write(
        {
            "ingress_context": context.handle_id,
            "entry_type": "open_thread",
            "key": "thread:customer-response",
            "value": "waiting on customer response",
            "workflow_state": "waiting",
        }
    )

    assert created["entry"] is not None
    entry_id = str(created["entry"]["id"])

    quarantined = await harness.do_memory_quarantine(
        {
            "entry_id": entry_id,
            "reason": "manual-review",
        }
    )
    restored = await harness.do_memory_unquarantine(
        {
            "entry_id": entry_id,
            "reason": "review-cleared",
        }
    )

    assert quarantined["changed"] is True
    assert restored["changed"] is True
    entry = harness._memory_manager.get_entry(entry_id)
    assert entry is not None
    assert entry.workflow_state == "waiting"
    assert entry.status == "active"


@pytest.mark.asyncio
async def test_memory_write_control_api_path_mints_user_asserted_handle(tmp_path: Path) -> None:
    harness = _MemoryWriteHarness(tmp_path)

    result = await harness.do_memory_write(
        {
            "_control_api_authenticated_write": True,
            "entry_type": "fact",
            "key": "profile.note",
            "value": "typed directly in CLI",
        }
    )

    assert result["kind"] == "allow"
    entry = result["entry"]
    assert entry is not None
    assert entry["source_origin"] == "user_direct"
    assert entry["channel_trust"] == "command"
    assert entry["confirmation_status"] == "user_asserted"
    assert entry["ingress_handle_id"]


@pytest.mark.asyncio
async def test_note_create_control_api_path_mints_user_asserted_handle(tmp_path: Path) -> None:
    harness = _MemoryWriteHarness(tmp_path)

    result = await harness.do_note_create(
        {
            "_control_api_authenticated_write": True,
            "key": "note:cli",
            "content": "direct note command",
        }
    )

    assert result["kind"] == "allow"
    entry = result["entry"]
    assert entry is not None
    assert entry["source_origin"] == "user_direct"
    assert entry["confirmation_status"] == "user_asserted"
    assert entry["ingress_handle_id"]


@pytest.mark.asyncio
async def test_note_create_control_api_path_respects_user_confirmed_flag(tmp_path: Path) -> None:
    harness = _MemoryWriteHarness(tmp_path)

    result = await harness.do_note_create(
        {
            "_control_api_authenticated_write": True,
            "key": "note:confirmed",
            "content": "confirmed note command",
            "user_confirmed": True,
        }
    )

    assert result["kind"] == "allow"
    entry = result["entry"]
    assert entry is not None
    assert entry["source_origin"] == "user_confirmed"
    assert entry["confirmation_status"] == "user_confirmed"
    assert entry["ingress_handle_id"]


@pytest.mark.asyncio
async def test_note_create_legacy_fallback_mints_compat_handle(tmp_path: Path) -> None:
    harness = _MemoryWriteHarness(tmp_path)

    result = await harness.do_note_create(
        {
            "key": "note:legacy",
            "content": "legacy note path",
            "origin": "user",
            "source_id": "legacy-note-1",
        }
    )

    assert result["kind"] == "allow"
    entry = result["entry"]
    assert entry is not None
    assert entry["source_origin"] == "user_direct"
    assert entry["ingress_handle_id"]


@pytest.mark.asyncio
async def test_todo_create_control_api_path_mints_user_asserted_handle(tmp_path: Path) -> None:
    harness = _MemoryWriteHarness(tmp_path)

    result = await harness.do_todo_create(
        {
            "_control_api_authenticated_write": True,
            "title": "review queue",
            "details": "",
            "status": "open",
            "due_date": "",
        }
    )

    assert result["kind"] == "allow"
    entry = result["entry"]
    assert entry is not None
    assert entry["source_origin"] == "user_direct"
    assert entry["confirmation_status"] == "user_asserted"
    assert entry["ingress_handle_id"]


@pytest.mark.asyncio
async def test_todo_create_legacy_fallback_mints_compat_handle(tmp_path: Path) -> None:
    harness = _MemoryWriteHarness(tmp_path)

    result = await harness.do_todo_create(
        {
            "title": "legacy todo",
            "details": "",
            "status": "open",
            "due_date": "",
            "origin": "user",
            "source_id": "legacy-todo-1",
        }
    )

    assert result["kind"] == "allow"
    entry = result["entry"]
    assert entry is not None
    assert entry["source_origin"] == "user_direct"
    assert entry["ingress_handle_id"]
