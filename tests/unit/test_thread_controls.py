"""M2 thread UX control API regression tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from shisad.daemon.handlers._impl_memory import MemoryImplMixin
from shisad.memory.ingress import IngressContextRegistry
from shisad.memory.manager import MemoryManager
from shisad.memory.schema import MemoryEntry, MemorySource


class _ThreadControlHarness(MemoryImplMixin):
    def __init__(self, storage_dir: Path) -> None:
        self._memory_manager = MemoryManager(storage_dir)
        self._memory_ingress_registry = IngressContextRegistry()


def _write_thread(
    manager: MemoryManager,
    *,
    key: str,
    title: str,
    summary: str,
    user_id: str,
    workspace_id: str,
    workflow_state: str = "active",
    source_origin: str = "user_direct",
    channel_trust: str = "command",
    confirmation_status: str = "user_asserted",
    scope: str = "user",
    channel_id: str = "",
) -> MemoryEntry:
    value = {
        "title": title,
        "summary": summary,
        "unresolved_state": f"{title} still needs a next step.",
        "evidence_refs": [f"ev-{key.rsplit(':', 1)[-1]}"],
        "evidence_snippets": [summary],
    }
    if channel_id:
        value["channel_id"] = channel_id
    decision = manager.write_with_provenance(
        entry_type="open_thread",
        key=key,
        value=value,
        source=MemorySource(origin="user", source_id=key, extraction_method="test"),
        source_origin=source_origin,
        channel_trust=channel_trust,
        confirmation_status=confirmation_status,
        source_id=key,
        scope=scope,
        confidence=0.9,
        confirmation_satisfied=True,
        workflow_state=workflow_state,  # type: ignore[arg-type]
        user_id=user_id,
        workspace_id=workspace_id,
    )
    assert decision.kind == "allow"
    assert decision.entry is not None
    return decision.entry


@pytest.mark.asyncio
async def test_m2_thread_list_filters_owner_and_state(tmp_path: Path) -> None:
    harness = _ThreadControlHarness(tmp_path / "memory")
    active = _write_thread(
        harness._memory_manager,
        key="thread:nebula-launch",
        title="Nebula launch",
        summary="Nebula launch readiness and rollback ownership.",
        user_id="alice",
        workspace_id="ws1",
    )
    stale = _write_thread(
        harness._memory_manager,
        key="thread:atlas-budget",
        title="Atlas budget",
        summary="Atlas budget procurement timing.",
        user_id="alice",
        workspace_id="ws1",
        workflow_state="stale",
    )
    _write_thread(
        harness._memory_manager,
        key="thread:other-owner",
        title="Other owner",
        summary="Other owner thread must not be listed.",
        user_id="bob",
        workspace_id="ws2",
    )

    default_result = await harness.do_thread_list({"user_id": "alice", "workspace_id": "ws1"})
    assert [row["id"] for row in default_result["threads"]] == [active.id]
    assert default_result["filters"]["state"] == "open"

    stale_result = await harness.do_thread_list(
        {"state": "stale", "user_id": "alice", "workspace_id": "ws1"}
    )
    assert [row["id"] for row in stale_result["threads"]] == [stale.id]
    assert stale_result["threads"][0]["workflow_state"] == "stale"


@pytest.mark.asyncio
async def test_m2_thread_inspect_returns_packet_for_closed_thread(tmp_path: Path) -> None:
    harness = _ThreadControlHarness(tmp_path / "memory")
    closed = _write_thread(
        harness._memory_manager,
        key="thread:closed-audit",
        title="Closed audit",
        summary="Closed audit remains inspectable for user review.",
        user_id="alice",
        workspace_id="ws1",
        workflow_state="closed",
    )

    result = await harness.do_thread_inspect(
        {"thread_id": closed.id, "user_id": "alice", "workspace_id": "ws1"}
    )

    assert result["found"] is True
    assert result["thread"]["id"] == closed.id
    assert result["thread"]["workflow_state"] == "closed"
    assert result["packet"]["title"] == "Closed audit"
    assert "Closed audit remains inspectable" in result["packet"]["summary"]
    assert result["selection"]["status"] == "inspect_only"


@pytest.mark.asyncio
async def test_m2_thread_summary_uses_canonical_channel_binding(tmp_path: Path) -> None:
    harness = _ThreadControlHarness(tmp_path / "memory")
    channel_binding = "discord:workspace-1:channel-99"
    thread = _write_thread(
        harness._memory_manager,
        key="thread:channel-audit",
        title="Channel audit",
        summary="Channel audit should report canonical channel metadata.",
        user_id="alice",
        workspace_id="ws1",
        scope="channel",
        source_origin="user_direct",
        channel_trust="owner_observed",
        confirmation_status="auto_accepted",
        channel_id=channel_binding,
    )

    result = await harness.do_thread_inspect(
        {"thread_id": thread.id, "user_id": "alice", "workspace_id": "ws1"}
    )

    assert result["found"] is True
    assert result["thread"]["channel_binding"] == channel_binding
    assert result["thread"]["channel_binding"] != thread.source_id
    assert result["thread"]["channel_trust"] == "owner_observed"


@pytest.mark.asyncio
async def test_m2_thread_resume_and_close_mutate_workflow_state_not_status(
    tmp_path: Path,
) -> None:
    harness = _ThreadControlHarness(tmp_path / "memory")
    thread = _write_thread(
        harness._memory_manager,
        key="thread:mutable",
        title="Mutable thread",
        summary="Mutable thread workflow metadata changes only.",
        user_id="alice",
        workspace_id="ws1",
        workflow_state="closed",
    )
    other_owner = _write_thread(
        harness._memory_manager,
        key="thread:other-owner-mutate",
        title="Other owner mutate",
        summary="Other owner thread must not be mutated.",
        user_id="bob",
        workspace_id="ws2",
    )

    resume = await harness.do_thread_resume(
        {"thread_id": thread.id, "user_id": "alice", "workspace_id": "ws1"}
    )
    assert resume["changed"] is True
    assert resume["thread"]["workflow_state"] == "active"

    resumed = harness._memory_manager.get_entry(
        thread.id,
        user_id="alice",
        workspace_id="ws1",
    )
    assert resumed is not None
    assert resumed.workflow_state == "active"
    assert resumed.status == "active"

    denied = await harness.do_thread_close(
        {
            "thread_id": other_owner.id,
            "reason": "wrong owner should fail closed",
            "user_id": "alice",
            "workspace_id": "ws1",
        }
    )
    assert denied["changed"] is False
    unchanged_other = harness._memory_manager.get_entry(
        other_owner.id,
        user_id="bob",
        workspace_id="ws2",
    )
    assert unchanged_other is not None
    assert unchanged_other.workflow_state == "active"

    close = await harness.do_thread_close(
        {
            "thread_id": thread.id,
            "reason": "resolved by user",
            "user_id": "alice",
            "workspace_id": "ws1",
        }
    )
    assert close["changed"] is True
    assert close["thread"]["workflow_state"] == "closed"
    assert close["thread"]["status"] == "active"
    events = harness._memory_manager.list_events(
        entry_id=thread.id,
        event_type="workflow_state_changed",
    )
    assert [event.metadata_json["to"] for event in events[:2]] == ["closed", "active"]
    assert all(event.metadata_json["status"] == "active" for event in events[:2])


@pytest.mark.asyncio
async def test_m2_thread_why_scopes_selector_to_owner(tmp_path: Path) -> None:
    harness = _ThreadControlHarness(tmp_path / "memory")
    visible = _write_thread(
        harness._memory_manager,
        key="thread:nebula-launch",
        title="Nebula launch",
        summary="Nebula launch readiness and rollback ownership.",
        user_id="alice",
        workspace_id="ws1",
    )
    hidden = _write_thread(
        harness._memory_manager,
        key="thread:atlas-budget",
        title="Atlas budget",
        summary="Atlas budget thread belongs to another owner.",
        user_id="bob",
        workspace_id="ws2",
    )

    hidden_result = await harness.do_thread_why(
        {
            "query": "Please resume the Atlas budget thread.",
            "thread_id": hidden.id,
            "user_id": "alice",
            "workspace_id": "ws1",
        }
    )
    assert hidden_result["selected"] is False
    assert hidden_result["selection"]["status"] == "no_match"
    assert hidden.id not in hidden_result["selection"]["candidate_ids"]

    visible_result = await harness.do_thread_why(
        {
            "query": "Please resume the Nebula launch thread.",
            "thread_id": visible.id,
            "user_id": "alice",
            "workspace_id": "ws1",
        }
    )
    assert visible_result["selected"] is True
    assert visible_result["selection"]["selected_id"] == visible.id
    assert visible_result["selection"]["confidence"] >= 0.55
    assert "explicit_continuation_signal" in visible_result["selection"]["rationale"]


@pytest.mark.asyncio
async def test_m2_thread_why_uses_cli_channel_filter_defaults(tmp_path: Path) -> None:
    harness = _ThreadControlHarness(tmp_path / "memory")
    channel_binding = "discord:workspace-1:shared-channel"
    shared = _write_thread(
        harness._memory_manager,
        key="thread:shared-channel-budget",
        title="Shared channel budget",
        summary="Shared participant channel thread should not match trusted CLI why.",
        user_id="alice",
        workspace_id="ws1",
        workflow_state="active",
        scope="channel",
        source_origin="external_message",
        channel_trust="shared_participant",
        confirmation_status="auto_accepted",
        channel_id=channel_binding,
    )

    cli_default = await harness.do_thread_why(
        {
            "query": "Please resume the Shared channel budget thread.",
            "thread_id": shared.id,
            "user_id": "alice",
            "workspace_id": "ws1",
        }
    )
    assert cli_default["selected"] is False
    assert shared.id not in cli_default["selection"]["candidate_ids"]

    channel_scoped = await harness.do_thread_why(
        {
            "query": "Please resume the Shared channel budget thread.",
            "thread_id": shared.id,
            "scope_filter": ["channel"],
            "allowed_channel_trusts": ["shared_participant"],
            "channel_binding": channel_binding,
            "user_id": "alice",
            "workspace_id": "ws1",
        }
    )
    assert channel_scoped["selected"] is True
    assert channel_scoped["selection"]["selected_id"] == shared.id
