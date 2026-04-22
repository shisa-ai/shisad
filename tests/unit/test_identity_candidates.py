from __future__ import annotations

from pathlib import Path

import pytest

from shisad.core.session import Session
from shisad.core.types import SessionId, SessionMode, SessionState, UserId, WorkspaceId
from shisad.daemon.handlers._impl_session import SessionImplMixin, SessionMessageValidationResult
from shisad.memory.identity_candidates import detect_identity_observation
from shisad.memory.ingress import IngressContextRegistry
from shisad.memory.manager import MemoryManager
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
