"""Unit checks for memory handler wrappers."""

from __future__ import annotations

import pytest

from shisad.core.api.schema import (
    MemoryEntryParams,
    MemoryExportParams,
    MemoryIngestParams,
    MemoryInvokeSkillParams,
    MemoryLifecycleParams,
    MemoryListParams,
    MemoryMintIngressParams,
    MemoryPromoteIdentityCandidateParams,
    MemoryPromoteSkillParams,
    MemoryReadOriginalParams,
    MemoryRejectIdentityCandidateParams,
    MemoryReviewQueueParams,
    MemoryRotateKeyParams,
    MemorySupersedeParams,
    MemoryWorkflowStateParams,
    NoteEntryParams,
    NoteExportParams,
    NoteListParams,
    NoteSearchParams,
    TodoCompleteParams,
    TodoEntryParams,
    TodoExportParams,
    TodoListParams,
)
from shisad.daemon.context import RequestContext
from shisad.daemon.handlers.memory import MemoryHandlers


class _StubImpl:
    def __init__(self) -> None:
        self.last_memory_mint_ingress_payload: dict[str, object] | None = None
        self.last_memory_ingest_payload: dict[str, object] | None = None
        self.last_memory_supersede_payload: dict[str, object] | None = None
        self.last_memory_promote_identity_candidate_payload: dict[str, object] | None = None
        self.last_memory_promote_skill_payload: dict[str, object] | None = None
        self.last_memory_reject_identity_candidate_payload: dict[str, object] | None = None
        self.last_memory_list_review_queue_payload: dict[str, object] | None = None
        self.last_memory_list_payload: dict[str, object] | None = None
        self.last_memory_invoke_skill_payload: dict[str, object] | None = None
        self.last_memory_read_original_payload: dict[str, object] | None = None
        self.last_memory_get_payload: dict[str, object] | None = None
        self.last_memory_delete_payload: dict[str, object] | None = None
        self.last_memory_export_payload: dict[str, object] | None = None
        self.last_memory_verify_payload: dict[str, object] | None = None
        self.last_memory_quarantine_payload: dict[str, object] | None = None
        self.last_memory_unquarantine_payload: dict[str, object] | None = None
        self.last_memory_set_workflow_state_payload: dict[str, object] | None = None
        self.last_note_list_payload: dict[str, object] | None = None
        self.last_note_search_payload: dict[str, object] | None = None
        self.last_note_get_payload: dict[str, object] | None = None
        self.last_note_delete_payload: dict[str, object] | None = None
        self.last_note_verify_payload: dict[str, object] | None = None
        self.last_note_export_payload: dict[str, object] | None = None
        self.last_todo_list_payload: dict[str, object] | None = None
        self.last_todo_complete_payload: dict[str, object] | None = None
        self.last_todo_get_payload: dict[str, object] | None = None
        self.last_todo_delete_payload: dict[str, object] | None = None
        self.last_todo_verify_payload: dict[str, object] | None = None
        self.last_todo_export_payload: dict[str, object] | None = None

    async def do_memory_mint_ingress_context(self, payload: dict[str, object]) -> dict[str, object]:
        self.last_memory_mint_ingress_payload = payload
        return {
            "ingress_context": "handle-1",
            "content_digest": "digest-1",
            "source_origin": "user_direct",
            "channel_trust": "command",
            "confirmation_status": "user_asserted",
            "scope": "user",
            "source_id": str(payload.get("source_id", "cli")),
        }

    async def do_memory_ingest(self, payload: dict[str, object]) -> dict[str, object]:
        self.last_memory_ingest_payload = payload
        return {
            "chunk_id": "ing-1",
            "source_id": "src-1",
            "source_type": "user",
            "collection": "user_curated",
            "created_at": "2026-02-13T00:00:00+00:00",
            "content_sanitized": "safe",
            "risk_score": 0.1,
            "original_hash": "hash-1",
        }

    async def do_memory_retrieve(self, _payload: dict[str, object]) -> dict[str, object]:
        return {"results": [{"entry_id": "e1"}], "count": 1}

    async def do_memory_write(self, _payload: dict[str, object]) -> dict[str, object]:
        return {"written": True}

    async def do_memory_supersede(self, payload: dict[str, object]) -> dict[str, object]:
        self.last_memory_supersede_payload = payload
        return {"kind": "allow", "entry": {"id": "e2", "supersedes": str(payload["supersedes"])}}

    async def do_memory_promote_identity_candidate(
        self, payload: dict[str, object]
    ) -> dict[str, object]:
        self.last_memory_promote_identity_candidate_payload = payload
        return {"kind": "allow", "entry": {"id": "e3", "supersedes": str(payload["candidate_id"])}}

    async def do_memory_promote_skill(self, payload: dict[str, object]) -> dict[str, object]:
        self.last_memory_promote_skill_payload = payload
        return {
            "kind": "allow",
            "entry": {
                "id": "e4",
                "supersedes": str(payload["entry_id"]),
                "invocation_eligible": True,
            },
        }

    async def do_memory_reject_identity_candidate(
        self, payload: dict[str, object]
    ) -> dict[str, object]:
        self.last_memory_reject_identity_candidate_payload = payload
        return {
            "changed": True,
            "candidate_id": str(payload["candidate_id"]),
            "reason": "candidate_rejected",
        }

    async def do_memory_list(self, payload: dict[str, object]) -> dict[str, object]:
        self.last_memory_list_payload = payload
        return {"entries": [{"entry_id": "e1"}], "count": 1}

    async def do_memory_list_review_queue(self, payload: dict[str, object]) -> dict[str, object]:
        self.last_memory_list_review_queue_payload = payload
        return {"entries": [{"entry_id": "review-1"}], "count": 1}

    async def do_memory_invoke_skill(self, payload: dict[str, object]) -> dict[str, object]:
        self.last_memory_invoke_skill_payload = payload
        return {
            "skill_id": str(payload["skill_id"]),
            "found": True,
            "invoked": True,
            "artifact": {
                "id": str(payload["skill_id"]),
                "entry_type": "skill",
                "name": "release-close",
                "description": "Release close checklist",
                "content": "Run behavioral validation before release close.",
                "trust_band": "elevated",
                "source_origin": "user_direct",
                "channel_trust": "command",
                "confirmation_status": "user_asserted",
                "size_bytes": 45,
                "invocation_eligible": True,
            },
        }

    async def do_memory_read_original(self, payload: dict[str, object]) -> dict[str, object]:
        self.last_memory_read_original_payload = payload
        return {
            "chunk_id": str(payload["chunk_id"]),
            "found": True,
            "content": "original retrieval payload",
        }

    async def do_memory_get(self, payload: dict[str, object]) -> dict[str, object]:
        self.last_memory_get_payload = payload
        return {"entry": {"entry_id": "e1"}}

    async def do_memory_delete(self, payload: dict[str, object]) -> dict[str, object]:
        self.last_memory_delete_payload = payload
        return {"deleted": True, "entry_id": str(payload["entry_id"])}

    async def do_memory_export(self, payload: dict[str, object]) -> dict[str, object]:
        self.last_memory_export_payload = payload
        return {"format": "json", "data": {}}

    async def do_memory_verify(self, payload: dict[str, object]) -> dict[str, object]:
        self.last_memory_verify_payload = payload
        return {"verified": True, "entry_id": str(payload["entry_id"])}

    async def do_memory_rotate_key(self, payload: dict[str, object]) -> dict[str, object]:
        return {
            "rotated": True,
            "active_key_id": "k1",
            "reencrypt_existing": bool(payload["reencrypt_existing"]),
        }

    async def do_memory_quarantine(self, payload: dict[str, object]) -> dict[str, object]:
        self.last_memory_quarantine_payload = payload
        return {
            "changed": True,
            "entry_id": str(payload["entry_id"]),
            "reason": str(payload["reason"]),
        }

    async def do_memory_unquarantine(self, payload: dict[str, object]) -> dict[str, object]:
        self.last_memory_unquarantine_payload = payload
        return {
            "changed": True,
            "entry_id": str(payload["entry_id"]),
            "reason": str(payload["reason"]),
        }

    async def do_memory_set_workflow_state(self, payload: dict[str, object]) -> dict[str, object]:
        self.last_memory_set_workflow_state_payload = payload
        return {
            "changed": True,
            "entry_id": str(payload["entry_id"]),
            "workflow_state": str(payload["workflow_state"]),
        }

    async def do_note_list(self, payload: dict[str, object]) -> dict[str, object]:
        self.last_note_list_payload = payload
        return {"entries": [{"id": "note-1", "entry_type": "note"}], "count": 1}

    async def do_note_search(self, payload: dict[str, object]) -> dict[str, object]:
        self.last_note_search_payload = payload
        return {"query": str(payload["query"]), "entries": [{"id": "note-1"}], "count": 1}

    async def do_note_get(self, payload: dict[str, object]) -> dict[str, object]:
        self.last_note_get_payload = payload
        return {"entry": {"id": str(payload["entry_id"]), "entry_type": "note"}}

    async def do_note_delete(self, payload: dict[str, object]) -> dict[str, object]:
        self.last_note_delete_payload = payload
        return {"deleted": True, "entry_id": str(payload["entry_id"])}

    async def do_note_verify(self, payload: dict[str, object]) -> dict[str, object]:
        self.last_note_verify_payload = payload
        return {"verified": True, "entry_id": str(payload["entry_id"])}

    async def do_note_export(self, payload: dict[str, object]) -> dict[str, object]:
        self.last_note_export_payload = payload
        return {"format": str(payload["format"]), "data": "[]"}

    async def do_todo_list(self, payload: dict[str, object]) -> dict[str, object]:
        self.last_todo_list_payload = payload
        return {"entries": [{"id": "todo-1", "entry_type": "todo"}], "count": 1}

    async def do_todo_complete(self, payload: dict[str, object]) -> dict[str, object]:
        self.last_todo_complete_payload = payload
        return {
            "completed": True,
            "entry_id": "todo-1",
            "entry": {"id": "todo-1", "entry_type": "todo"},
            "reason": "",
            "matches": [],
        }

    async def do_todo_get(self, payload: dict[str, object]) -> dict[str, object]:
        self.last_todo_get_payload = payload
        return {"entry": {"id": str(payload["entry_id"]), "entry_type": "todo"}}

    async def do_todo_delete(self, payload: dict[str, object]) -> dict[str, object]:
        self.last_todo_delete_payload = payload
        return {"deleted": True, "entry_id": str(payload["entry_id"])}

    async def do_todo_verify(self, payload: dict[str, object]) -> dict[str, object]:
        self.last_todo_verify_payload = payload
        return {"verified": True, "entry_id": str(payload["entry_id"])}

    async def do_todo_export(self, payload: dict[str, object]) -> dict[str, object]:
        self.last_todo_export_payload = payload
        return {"format": str(payload["format"]), "data": "[]"}


@pytest.mark.asyncio
async def test_memory_ingest_and_list_wrappers() -> None:
    impl = _StubImpl()
    handlers = MemoryHandlers(impl, internal_ingress_marker=object())  # type: ignore[arg-type]
    minted = await handlers.handle_memory_mint_ingress_context(
        MemoryMintIngressParams(content="hello", source_id="src-1"),
        RequestContext(),
    )
    ingest = await handlers.handle_memory_ingest(
        MemoryIngestParams(ingress_context="handle-1", content="hello"),
        RequestContext(),
    )
    listing = await handlers.handle_memory_list(
        MemoryListParams(
            limit=10,
            user_id="alice",
            workspace_id="ws1",
            include_unowned=True,
        ),
        RequestContext(),
    )
    review_queue = await handlers.handle_memory_list_review_queue(
        MemoryReviewQueueParams(
            limit=10,
            user_id="alice",
            workspace_id="ws1",
            include_unowned=True,
        ),
        RequestContext(),
    )
    assert minted.ingress_context == "handle-1"
    assert ingest.model_dump(mode="json")["source_id"] == "src-1"
    assert impl.last_memory_mint_ingress_payload is not None
    assert impl.last_memory_ingest_payload is not None
    assert impl.last_memory_ingest_payload["_control_api_authenticated_write"] is True
    assert listing.count == 1
    assert impl.last_memory_list_payload is not None
    assert impl.last_memory_list_payload["user_id"] == "alice"
    assert impl.last_memory_list_payload["workspace_id"] == "ws1"
    assert impl.last_memory_list_payload["include_unowned"] is True
    assert review_queue.entries[0].id == "review-1"
    assert impl.last_memory_list_review_queue_payload is not None
    assert impl.last_memory_list_review_queue_payload["user_id"] == "alice"
    assert impl.last_memory_list_review_queue_payload["workspace_id"] == "ws1"
    assert impl.last_memory_list_review_queue_payload["include_unowned"] is True


@pytest.mark.asyncio
async def test_memory_supersede_wrapper_forwards_authenticated_payload() -> None:
    impl = _StubImpl()
    handlers = MemoryHandlers(impl, internal_ingress_marker=object())  # type: ignore[arg-type]

    result = await handlers.handle_memory_supersede(
        MemorySupersedeParams(
            ingress_context="handle-1",
            entry_type="note",
            key="note:chain",
            value="updated",
            supersedes="e1",
            user_id="alice",
            workspace_id="ws1",
        ),
        RequestContext(),
    )

    assert result.kind == "allow"
    assert result.entry is not None
    assert result.entry["supersedes"] == "e1"
    assert impl.last_memory_supersede_payload is not None
    assert impl.last_memory_supersede_payload["supersedes"] == "e1"
    assert impl.last_memory_supersede_payload["user_id"] == "alice"
    assert impl.last_memory_supersede_payload["workspace_id"] == "ws1"
    assert impl.last_memory_supersede_payload["_control_api_authenticated_write"] is True


@pytest.mark.asyncio
async def test_memory_identity_candidate_wrappers_forward_authenticated_payload() -> None:
    impl = _StubImpl()
    handlers = MemoryHandlers(impl, internal_ingress_marker=object())  # type: ignore[arg-type]

    promoted = await handlers.handle_memory_promote_identity_candidate(
        MemoryPromoteIdentityCandidateParams(
            ingress_context="handle-1",
            candidate_id="candidate-1",
            value="I prefer green tea.",
            user_id="alice",
            workspace_id="ws1",
            include_unowned=True,
        ),
        RequestContext(),
    )
    rejected = await handlers.handle_memory_reject_identity_candidate(
        MemoryRejectIdentityCandidateParams(
            ingress_context="handle-2",
            candidate_id="candidate-2",
            user_id="alice",
            workspace_id="ws1",
            include_unowned=True,
        ),
        RequestContext(),
    )

    assert promoted.kind == "allow"
    assert promoted.entry is not None
    assert promoted.entry["supersedes"] == "candidate-1"
    assert impl.last_memory_promote_identity_candidate_payload is not None
    assert impl.last_memory_promote_identity_candidate_payload["candidate_id"] == "candidate-1"
    assert impl.last_memory_promote_identity_candidate_payload["user_id"] == "alice"
    assert impl.last_memory_promote_identity_candidate_payload["workspace_id"] == "ws1"
    assert impl.last_memory_promote_identity_candidate_payload["include_unowned"] is True
    assert (
        impl.last_memory_promote_identity_candidate_payload["_control_api_authenticated_write"]
        is True
    )

    assert rejected.changed is True
    assert rejected.candidate_id == "candidate-2"
    assert impl.last_memory_reject_identity_candidate_payload is not None
    assert impl.last_memory_reject_identity_candidate_payload["candidate_id"] == "candidate-2"
    assert impl.last_memory_reject_identity_candidate_payload["user_id"] == "alice"
    assert impl.last_memory_reject_identity_candidate_payload["workspace_id"] == "ws1"
    assert impl.last_memory_reject_identity_candidate_payload["include_unowned"] is True
    assert (
        impl.last_memory_reject_identity_candidate_payload["_control_api_authenticated_write"]
        is True
    )


@pytest.mark.asyncio
async def test_memory_verify_and_rotate_wrappers() -> None:
    impl = _StubImpl()
    handlers = MemoryHandlers(impl, internal_ingress_marker=object())  # type: ignore[arg-type]
    verify = await handlers.handle_memory_verify(
        MemoryEntryParams(entry_id="e1", user_id="alice", workspace_id="ws1"),
        RequestContext(),
    )
    rotated = await handlers.handle_memory_rotate_key(
        MemoryRotateKeyParams(reencrypt_existing=False),
        RequestContext(),
    )
    assert verify.verified is True
    assert rotated.active_key_id == "k1"
    assert impl.last_memory_verify_payload is not None
    assert impl.last_memory_verify_payload["user_id"] == "alice"
    assert impl.last_memory_verify_payload["workspace_id"] == "ws1"


@pytest.mark.asyncio
async def test_memory_read_original_wrapper_forwards_rpc_peer() -> None:
    impl = _StubImpl()
    handlers = MemoryHandlers(impl, internal_ingress_marker=object())  # type: ignore[arg-type]

    result = await handlers.handle_memory_read_original(
        MemoryReadOriginalParams(chunk_id="chunk-1"),
        RequestContext(rpc_peer={"host": "127.0.0.1", "port": 31337}),
    )

    assert result.found is True
    assert result.chunk_id == "chunk-1"
    assert result.content == "original retrieval payload"
    assert impl.last_memory_read_original_payload is not None
    assert impl.last_memory_read_original_payload["chunk_id"] == "chunk-1"
    assert impl.last_memory_read_original_payload["_rpc_peer"] == {
        "host": "127.0.0.1",
        "port": 31337,
    }


@pytest.mark.asyncio
async def test_memory_invoke_skill_wrapper_forwards_rpc_peer() -> None:
    impl = _StubImpl()
    handlers = MemoryHandlers(impl, internal_ingress_marker=object())  # type: ignore[arg-type]

    result = await handlers.handle_memory_invoke_skill(
        MemoryInvokeSkillParams(skill_id="skill-1"),
        RequestContext(rpc_peer={"host": "127.0.0.1", "port": 31337}),
    )

    assert result.found is True
    assert result.invoked is True
    assert result.skill_id == "skill-1"
    assert result.artifact is not None
    assert result.artifact.id == "skill-1"
    assert impl.last_memory_invoke_skill_payload is not None
    assert impl.last_memory_invoke_skill_payload["skill_id"] == "skill-1"
    assert impl.last_memory_invoke_skill_payload["_rpc_peer"] == {
        "host": "127.0.0.1",
        "port": 31337,
    }


@pytest.mark.asyncio
async def test_memory_promote_skill_wrapper_marks_authenticated_write() -> None:
    impl = _StubImpl()
    handlers = MemoryHandlers(impl, internal_ingress_marker=object())  # type: ignore[arg-type]

    result = await handlers.handle_memory_promote_skill(
        MemoryPromoteSkillParams(ingress_context="handle-1", entry_id="skill-1"),
        RequestContext(),
    )

    assert result.kind == "allow"
    assert result.entry is not None
    assert result.entry["invocation_eligible"] is True
    assert impl.last_memory_promote_skill_payload is not None
    assert impl.last_memory_promote_skill_payload["ingress_context"] == "handle-1"
    assert impl.last_memory_promote_skill_payload["entry_id"] == "skill-1"
    assert impl.last_memory_promote_skill_payload["_control_api_authenticated_write"] is True


@pytest.mark.asyncio
async def test_memory_lifecycle_wrappers_forward_payloads() -> None:
    impl = _StubImpl()
    handlers = MemoryHandlers(impl, internal_ingress_marker=object())  # type: ignore[arg-type]

    quarantined = await handlers.handle_memory_quarantine(
        MemoryLifecycleParams(
            entry_id="e1",
            reason="manual-review",
            user_id="alice",
            workspace_id="ws1",
        ),
        RequestContext(),
    )
    unquarantined = await handlers.handle_memory_unquarantine(
        MemoryLifecycleParams(
            entry_id="e1",
            reason="review-cleared",
            user_id="alice",
            workspace_id="ws1",
            include_unowned=True,
        ),
        RequestContext(),
    )
    updated = await handlers.handle_memory_set_workflow_state(
        MemoryWorkflowStateParams(
            entry_id="e1",
            workflow_state="closed",
            user_id="alice",
            workspace_id="ws1",
        ),
        RequestContext(),
    )

    assert quarantined.changed is True
    assert unquarantined.changed is True
    assert updated.workflow_state == "closed"
    assert impl.last_memory_quarantine_payload is not None
    assert impl.last_memory_quarantine_payload["reason"] == "manual-review"
    assert impl.last_memory_quarantine_payload["user_id"] == "alice"
    assert impl.last_memory_quarantine_payload["workspace_id"] == "ws1"
    assert impl.last_memory_unquarantine_payload is not None
    assert impl.last_memory_unquarantine_payload["reason"] == "review-cleared"
    assert impl.last_memory_unquarantine_payload["include_unowned"] is True
    assert impl.last_memory_set_workflow_state_payload is not None
    assert impl.last_memory_set_workflow_state_payload["workflow_state"] == "closed"
    assert impl.last_memory_set_workflow_state_payload["user_id"] == "alice"
    assert impl.last_memory_set_workflow_state_payload["workspace_id"] == "ws1"


@pytest.mark.asyncio
async def test_memory_list_and_get_wrappers_forward_history_flags() -> None:
    impl = _StubImpl()
    handlers = MemoryHandlers(impl, internal_ingress_marker=object())  # type: ignore[arg-type]

    await handlers.handle_memory_list(
        MemoryListParams(
            limit=5,
            include_deleted=True,
            include_quarantined=True,
            confirmed=True,
            user_id="alice",
            workspace_id="ws1",
            include_unowned=True,
        ),
        RequestContext(),
    )
    await handlers.handle_memory_get(
        MemoryEntryParams(
            entry_id="e1",
            include_deleted=True,
            include_quarantined=True,
            confirmed=True,
            user_id="alice",
            workspace_id="ws1",
            include_unowned=True,
        ),
        RequestContext(),
    )

    assert impl.last_memory_list_payload is not None
    assert impl.last_memory_list_payload["include_deleted"] is True
    assert impl.last_memory_list_payload["include_quarantined"] is True
    assert impl.last_memory_list_payload["confirmed"] is True
    assert impl.last_memory_list_payload["user_id"] == "alice"
    assert impl.last_memory_list_payload["workspace_id"] == "ws1"
    assert impl.last_memory_list_payload["include_unowned"] is True
    assert impl.last_memory_get_payload is not None
    assert impl.last_memory_get_payload["include_deleted"] is True
    assert impl.last_memory_get_payload["include_quarantined"] is True
    assert impl.last_memory_get_payload["confirmed"] is True
    assert impl.last_memory_get_payload["user_id"] == "alice"
    assert impl.last_memory_get_payload["workspace_id"] == "ws1"
    assert impl.last_memory_get_payload["include_unowned"] is True


@pytest.mark.asyncio
async def test_memory_export_wrapper_forwards_owner_scope() -> None:
    impl = _StubImpl()
    handlers = MemoryHandlers(impl, internal_ingress_marker=object())  # type: ignore[arg-type]

    result = await handlers.handle_memory_export(
        MemoryExportParams(
            format="json",
            user_id="alice",
            workspace_id="ws1",
            include_unowned=True,
        ),
        RequestContext(),
    )

    assert result.format == "json"
    assert impl.last_memory_export_payload is not None
    assert impl.last_memory_export_payload["user_id"] == "alice"
    assert impl.last_memory_export_payload["workspace_id"] == "ws1"
    assert impl.last_memory_export_payload["include_unowned"] is True


@pytest.mark.asyncio
async def test_note_and_todo_wrappers_forward_owner_scope() -> None:
    impl = _StubImpl()
    handlers = MemoryHandlers(impl, internal_ingress_marker=object())  # type: ignore[arg-type]

    await handlers.handle_note_list(
        NoteListParams(limit=5, user_id="alice", workspace_id="ws1", include_unowned=True),
        RequestContext(),
    )
    await handlers.handle_note_search(
        NoteSearchParams(query="groceries", user_id="alice", workspace_id="ws1"),
        RequestContext(),
    )
    await handlers.handle_note_get(
        NoteEntryParams(entry_id="note-1", user_id="alice", workspace_id="ws1"),
        RequestContext(),
    )
    await handlers.handle_note_delete(
        NoteEntryParams(entry_id="note-1", user_id="alice", workspace_id="ws1"),
        RequestContext(),
    )
    await handlers.handle_note_verify(
        NoteEntryParams(entry_id="note-1", user_id="alice", workspace_id="ws1"),
        RequestContext(),
    )
    await handlers.handle_note_export(
        NoteExportParams(format="json", user_id="alice", workspace_id="ws1"),
        RequestContext(),
    )
    await handlers.handle_todo_list(
        TodoListParams(limit=5, user_id="alice", workspace_id="ws1", include_unowned=True),
        RequestContext(),
    )
    await handlers.handle_todo_complete(
        TodoCompleteParams(selector="groceries", user_id="alice", workspace_id="ws1"),
        RequestContext(),
    )
    await handlers.handle_todo_get(
        TodoEntryParams(entry_id="todo-1", user_id="alice", workspace_id="ws1"),
        RequestContext(),
    )
    await handlers.handle_todo_delete(
        TodoEntryParams(entry_id="todo-1", user_id="alice", workspace_id="ws1"),
        RequestContext(),
    )
    await handlers.handle_todo_verify(
        TodoEntryParams(entry_id="todo-1", user_id="alice", workspace_id="ws1"),
        RequestContext(),
    )
    await handlers.handle_todo_export(
        TodoExportParams(format="json", user_id="alice", workspace_id="ws1"),
        RequestContext(),
    )

    for payload in [
        impl.last_note_list_payload,
        impl.last_note_search_payload,
        impl.last_note_get_payload,
        impl.last_note_delete_payload,
        impl.last_note_verify_payload,
        impl.last_note_export_payload,
        impl.last_todo_list_payload,
        impl.last_todo_complete_payload,
        impl.last_todo_get_payload,
        impl.last_todo_delete_payload,
        impl.last_todo_verify_payload,
        impl.last_todo_export_payload,
    ]:
        assert payload is not None
        assert payload["user_id"] == "alice"
        assert payload["workspace_id"] == "ws1"

    assert impl.last_note_list_payload is not None
    assert impl.last_note_list_payload["include_unowned"] is True
    assert impl.last_todo_list_payload is not None
    assert impl.last_todo_list_payload["include_unowned"] is True
