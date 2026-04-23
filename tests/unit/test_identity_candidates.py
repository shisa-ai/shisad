from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from shisad.core.session import Session
from shisad.core.types import SessionId, SessionMode, SessionState, UserId, WorkspaceId
from shisad.daemon.handlers._impl_session import SessionImplMixin, SessionMessageValidationResult
from shisad.memory.identity_candidates import detect_identity_observation
from shisad.memory.ingress import IngressContextRegistry
from shisad.memory.manager import MemoryManager
from shisad.memory.schema import MemorySource
from shisad.security.firewall import FirewallResult


def _validation_result(
    *,
    channel: str,
    trust_level: str,
    content: str,
) -> SessionMessageValidationResult:
    session = Session(
        id=SessionId("sess-identity-observed"),
        channel=channel,
        user_id=UserId("user-identity"),
        workspace_id=WorkspaceId("workspace-identity"),
        state=SessionState.ACTIVE,
        mode=SessionMode.DEFAULT,
    )
    return SessionMessageValidationResult(
        params={"session_id": session.id, "content": content},
        sid=session.id,
        content=content,
        session=session,
        session_mode=SessionMode.DEFAULT,
        channel=channel,
        user_id=session.user_id,
        workspace_id=session.workspace_id,
        trust_level=trust_level,
        trusted_input=trust_level == "trusted",
        firewall_result=FirewallResult(
            sanitized_text=content,
            original_hash="0" * 64,
        ),
        incoming_taint_labels=set(),
        is_internal_ingress=channel != "cli",
        channel_message_id="msg-identity-1",
    )


class _IdentityCandidateHarness(SessionImplMixin):
    def __init__(self, tmp_path: Path) -> None:
        self._memory_manager = MemoryManager(tmp_path / "memory")
        self._memory_ingress_registry = IngressContextRegistry()


class _IdentityCommandHarness(_IdentityCandidateHarness):
    def __init__(self, tmp_path: Path, *, channel: str = "cli") -> None:
        super().__init__(tmp_path)
        self._channel = channel

    async def _validate_and_load_session(
        self, params: dict[str, Any]
    ) -> SessionMessageValidationResult:
        return _validation_result(
            channel=self._channel,
            trust_level="trusted",
            content=str(params.get("content", "")),
        )


def _write_pending_identity_candidate(manager: MemoryManager) -> str:
    decision = manager.write_with_provenance(
        entry_type="preference",
        key="preference:tea",
        value="I prefer tea over coffee.",
        predicate="likes(tea)",
        source=MemorySource(
            origin="external",
            source_id="candidate-1",
            extraction_method="identity.candidate",
        ),
        source_origin="external_message",
        channel_trust="shared_participant",
        confirmation_status="pending_review",
        source_id="candidate-1",
        scope="user",
        confidence=0.62,
        confirmation_satisfied=True,
        ingress_handle_id="handle-candidate",
        content_digest="digest-candidate",
    )
    assert decision.entry is not None
    return decision.entry.id


def test_m3_detect_identity_observation_matches_preference_pattern() -> None:
    observation = detect_identity_observation("I prefer tea over coffee.")

    assert observation is not None
    assert observation.category == "preference"
    assert observation.pattern_id == "preference_like"


def test_m3_record_identity_observation_candidate_writes_owner_observed_episode(
    tmp_path: Path,
) -> None:
    harness = _IdentityCandidateHarness(tmp_path)
    validated = _validation_result(
        channel="discord",
        trust_level="owner",
        content="I prefer tea over coffee.",
    )

    entry_id = harness._record_identity_observation_candidate(validated=validated)

    assert entry_id
    entries = harness._memory_manager.list_entries(entry_type="episode", limit=10)
    assert len(entries) == 1
    entry = entries[0]
    assert entry.id == entry_id
    assert entry.key.startswith("identity-observation:preference:")
    assert entry.value == "I prefer tea over coffee."
    assert entry.source_origin == "user_direct"
    assert entry.channel_trust == "owner_observed"
    assert entry.confirmation_status == "auto_accepted"
    assert entry.scope == "user"
    assert entry.confidence == pytest.approx(0.30)


def test_m3_record_identity_observation_candidate_ignores_non_owner_observed_turn(
    tmp_path: Path,
) -> None:
    harness = _IdentityCandidateHarness(tmp_path)
    validated = _validation_result(
        channel="discord",
        trust_level="public",
        content="I prefer tea over coffee.",
    )

    entry_id = harness._record_identity_observation_candidate(validated=validated)

    assert entry_id is None
    assert harness._memory_manager.list_entries(entry_type="episode", limit=10) == []


@pytest.mark.asyncio
async def test_m3_identity_review_command_lists_pending_candidates(tmp_path: Path) -> None:
    harness = _IdentityCommandHarness(tmp_path)
    candidate_id = _write_pending_identity_candidate(harness._memory_manager)

    result = await SessionImplMixin.do_session_message(
        harness,
        {"session_id": "sess-identity-observed", "content": "/identity review"},
    )  # type: ignore[arg-type]

    assert result["session_id"] == "sess-identity-observed"
    assert "Pending identity candidates" in result["response"]
    assert candidate_id in result["response"]
    assert "I prefer tea over coffee." in result["response"]


@pytest.mark.asyncio
async def test_m5_identity_commands_hide_quarantined_candidates_from_cli(tmp_path: Path) -> None:
    harness = _IdentityCommandHarness(tmp_path)
    candidate_id = _write_pending_identity_candidate(harness._memory_manager)
    assert harness._memory_manager.quarantine(candidate_id, reason="test_quarantine")

    review = await SessionImplMixin.do_session_message(
        harness,
        {"session_id": "sess-identity-observed", "content": "/identity review"},
    )  # type: ignore[arg-type]
    accept = await SessionImplMixin.do_session_message(
        harness,
        {"session_id": "sess-identity-observed", "content": f"/identity accept {candidate_id}"},
    )  # type: ignore[arg-type]
    reject = await SessionImplMixin.do_session_message(
        harness,
        {"session_id": "sess-identity-observed", "content": f"/identity reject {candidate_id}"},
    )  # type: ignore[arg-type]

    assert review["response"] == "No pending identity candidates."
    assert accept["response"] == f"Identity candidate {candidate_id} was not found."
    assert reject["response"] == f"Identity candidate {candidate_id} was not found."


@pytest.mark.asyncio
async def test_m3_identity_accept_command_promotes_pending_candidate_from_cli(
    tmp_path: Path,
) -> None:
    harness = _IdentityCommandHarness(tmp_path)
    candidate_id = _write_pending_identity_candidate(harness._memory_manager)

    result = await SessionImplMixin.do_session_message(
        harness,
        {"session_id": "sess-identity-observed", "content": f"/identity accept {candidate_id}"},
    )  # type: ignore[arg-type]

    assert result["session_id"] == "sess-identity-observed"
    assert "Remembered identity candidate" in result["response"]
    assert candidate_id in result["response"]
    assert harness._memory_manager.list_review_queue(limit=10) == []
    identity_entries = harness._memory_manager.compile_identity(max_tokens=64).entries
    assert len(identity_entries) == 1
    assert identity_entries[0].confirmation_status == "user_confirmed"


@pytest.mark.asyncio
async def test_m3_identity_commands_require_command_channel(tmp_path: Path) -> None:
    harness = _IdentityCommandHarness(tmp_path, channel="discord")
    candidate_id = _write_pending_identity_candidate(harness._memory_manager)

    result = await SessionImplMixin.do_session_message(
        harness,
        {"session_id": "sess-identity-observed", "content": f"/identity accept {candidate_id}"},
    )  # type: ignore[arg-type]

    assert "trusted command channel" in result["response"]
    assert harness._memory_manager.list_review_queue(limit=10)[0].id == candidate_id
