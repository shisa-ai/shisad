"""Unit checks for memory handler wrappers."""

from __future__ import annotations

import pytest

from shisad.core.api.schema import (
    MemoryEntryParams,
    MemoryIngestParams,
    MemoryLifecycleParams,
    MemoryListParams,
    MemoryMintIngressParams,
    MemoryPromoteIdentityCandidateParams,
    MemoryRejectIdentityCandidateParams,
    MemoryReviewQueueParams,
    MemoryRotateKeyParams,
    MemorySupersedeParams,
    MemoryWorkflowStateParams,
)
from shisad.daemon.context import RequestContext
from shisad.daemon.handlers.memory import MemoryHandlers


class _StubImpl:
    def __init__(self) -> None:
        self.last_memory_mint_ingress_payload: dict[str, object] | None = None
        self.last_memory_ingest_payload: dict[str, object] | None = None
        self.last_memory_supersede_payload: dict[str, object] | None = None
        self.last_memory_promote_identity_candidate_payload: dict[str, object] | None = None
        self.last_memory_reject_identity_candidate_payload: dict[str, object] | None = None
        self.last_memory_list_payload: dict[str, object] | None = None
        self.last_memory_get_payload: dict[str, object] | None = None
        self.last_memory_quarantine_payload: dict[str, object] | None = None
        self.last_memory_unquarantine_payload: dict[str, object] | None = None
        self.last_memory_set_workflow_state_payload: dict[str, object] | None = None

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

    async def do_memory_list_review_queue(self, _payload: dict[str, object]) -> dict[str, object]:
        return {"entries": [{"entry_id": "review-1"}], "count": 1}

    async def do_memory_get(self, payload: dict[str, object]) -> dict[str, object]:
        self.last_memory_get_payload = payload
        return {"entry": {"entry_id": "e1"}}

    async def do_memory_delete(self, payload: dict[str, object]) -> dict[str, object]:
        return {"deleted": True, "entry_id": str(payload["entry_id"])}

    async def do_memory_export(self, _payload: dict[str, object]) -> dict[str, object]:
        return {"format": "json", "data": {}}

    async def do_memory_verify(self, payload: dict[str, object]) -> dict[str, object]:
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
    listing = await handlers.handle_memory_list(MemoryListParams(limit=10), RequestContext())
    review_queue = await handlers.handle_memory_list_review_queue(
        MemoryReviewQueueParams(limit=10),
        RequestContext(),
    )
    assert minted.ingress_context == "handle-1"
    assert ingest.model_dump(mode="json")["source_id"] == "src-1"
    assert impl.last_memory_mint_ingress_payload is not None
    assert impl.last_memory_ingest_payload is not None
    assert impl.last_memory_ingest_payload["_control_api_authenticated_write"] is True
    assert listing.count == 1
    assert review_queue.entries[0].id == "review-1"


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
        ),
        RequestContext(),
    )

    assert result.kind == "allow"
    assert result.entry is not None
    assert result.entry["supersedes"] == "e1"
    assert impl.last_memory_supersede_payload is not None
    assert impl.last_memory_supersede_payload["supersedes"] == "e1"
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
        ),
        RequestContext(),
    )
    rejected = await handlers.handle_memory_reject_identity_candidate(
        MemoryRejectIdentityCandidateParams(
            ingress_context="handle-2",
            candidate_id="candidate-2",
        ),
        RequestContext(),
    )

    assert promoted.kind == "allow"
    assert promoted.entry is not None
    assert promoted.entry["supersedes"] == "candidate-1"
    assert impl.last_memory_promote_identity_candidate_payload is not None
    assert impl.last_memory_promote_identity_candidate_payload["candidate_id"] == "candidate-1"
    assert (
        impl.last_memory_promote_identity_candidate_payload[
            "_control_api_authenticated_write"
        ]
        is True
    )

    assert rejected.changed is True
    assert rejected.candidate_id == "candidate-2"
    assert impl.last_memory_reject_identity_candidate_payload is not None
    assert impl.last_memory_reject_identity_candidate_payload["candidate_id"] == "candidate-2"
    assert (
        impl.last_memory_reject_identity_candidate_payload[
            "_control_api_authenticated_write"
        ]
        is True
    )


@pytest.mark.asyncio
async def test_memory_verify_and_rotate_wrappers() -> None:
    handlers = MemoryHandlers(_StubImpl(), internal_ingress_marker=object())  # type: ignore[arg-type]
    verify = await handlers.handle_memory_verify(
        MemoryEntryParams(entry_id="e1"),
        RequestContext(),
    )
    rotated = await handlers.handle_memory_rotate_key(
        MemoryRotateKeyParams(reencrypt_existing=False),
        RequestContext(),
    )
    assert verify.verified is True
    assert rotated.active_key_id == "k1"


@pytest.mark.asyncio
async def test_memory_lifecycle_wrappers_forward_payloads() -> None:
    impl = _StubImpl()
    handlers = MemoryHandlers(impl, internal_ingress_marker=object())  # type: ignore[arg-type]

    quarantined = await handlers.handle_memory_quarantine(
        MemoryLifecycleParams(entry_id="e1", reason="manual-review"),
        RequestContext(),
    )
    unquarantined = await handlers.handle_memory_unquarantine(
        MemoryLifecycleParams(entry_id="e1", reason="review-cleared"),
        RequestContext(),
    )
    updated = await handlers.handle_memory_set_workflow_state(
        MemoryWorkflowStateParams(entry_id="e1", workflow_state="closed"),
        RequestContext(),
    )

    assert quarantined.changed is True
    assert unquarantined.changed is True
    assert updated.workflow_state == "closed"
    assert impl.last_memory_quarantine_payload is not None
    assert impl.last_memory_quarantine_payload["reason"] == "manual-review"
    assert impl.last_memory_unquarantine_payload is not None
    assert impl.last_memory_unquarantine_payload["reason"] == "review-cleared"
    assert impl.last_memory_set_workflow_state_payload is not None
    assert impl.last_memory_set_workflow_state_payload["workflow_state"] == "closed"


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
        ),
        RequestContext(),
    )
    await handlers.handle_memory_get(
        MemoryEntryParams(
            entry_id="e1",
            include_deleted=True,
            include_quarantined=True,
            confirmed=True,
        ),
        RequestContext(),
    )

    assert impl.last_memory_list_payload is not None
    assert impl.last_memory_list_payload["include_deleted"] is True
    assert impl.last_memory_list_payload["include_quarantined"] is True
    assert impl.last_memory_list_payload["confirmed"] is True
    assert impl.last_memory_get_payload is not None
    assert impl.last_memory_get_payload["include_deleted"] is True
    assert impl.last_memory_get_payload["include_quarantined"] is True
    assert impl.last_memory_get_payload["confirmed"] is True
