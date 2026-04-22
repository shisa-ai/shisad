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
async def test_memory_write_legacy_source_path_still_works(tmp_path: Path) -> None:
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
async def test_memory_write_control_api_path_mints_user_asserted_handle(tmp_path: Path) -> None:
    harness = _MemoryWriteHarness(tmp_path)

    result = await harness.do_memory_write(
        {
            "_control_api_authenticated_write": True,
            "entry_type": "fact",
            "key": "profile.note",
            "value": "typed directly in CLI",
            "source": {
                "origin": "external",
                "source_id": "cli-1",
                "extraction_method": "cli",
            },
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
            "origin": "external",
            "source_id": "cli-note-1",
        }
    )

    assert result["kind"] == "allow"
    entry = result["entry"]
    assert entry is not None
    assert entry["source_origin"] == "user_direct"
    assert entry["confirmation_status"] == "user_asserted"
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
            "origin": "external",
            "source_id": "cli-todo-1",
        }
    )

    assert result["kind"] == "allow"
    entry = result["entry"]
    assert entry is not None
    assert entry["source_origin"] == "user_direct"
    assert entry["confirmation_status"] == "user_asserted"
    assert entry["ingress_handle_id"]
