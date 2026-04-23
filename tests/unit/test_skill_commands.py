from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from shisad.core.session import Session, SessionManager
from shisad.core.types import SessionId, SessionMode, SessionState, UserId, WorkspaceId
from shisad.daemon.handlers._impl_session import (
    _PENDING_SKILL_SUGGESTION_ID_KEY,
    SessionImplMixin,
    SessionMessageValidationResult,
)
from shisad.memory.manager import MemoryManager
from shisad.memory.schema import MemorySource
from shisad.security.firewall import FirewallResult


def _validation_result(
    *,
    channel: str,
    content: str,
) -> SessionMessageValidationResult:
    session = Session(
        id=SessionId("sess-skill-command"),
        channel=channel,
        user_id=UserId("user-skill"),
        workspace_id=WorkspaceId("workspace-skill"),
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
        trust_level="trusted",
        trusted_input=True,
        firewall_result=FirewallResult(
            sanitized_text=content,
            original_hash="0" * 64,
        ),
        incoming_taint_labels=set(),
        is_internal_ingress=channel != "cli",
        channel_message_id="msg-skill-1",
    )


class _SkillCommandHarness(SessionImplMixin):
    def __init__(self, tmp_path: Path, *, channel: str = "cli") -> None:
        self._memory_manager = MemoryManager(tmp_path / "memory")
        self._channel = channel

    async def _validate_and_load_session(
        self, params: dict[str, Any]
    ) -> SessionMessageValidationResult:
        return _validation_result(
            channel=self._channel,
            content=str(params.get("content", "")),
        )


class _SuggestedSkillHarness(SessionImplMixin):
    def __init__(self, tmp_path: Path) -> None:
        self._memory_manager = MemoryManager(tmp_path / "memory")
        self._session_manager = SessionManager()
        self.session = self._session_manager.create(
            channel="cli",
            user_id=UserId("user-skill"),
            workspace_id=WorkspaceId("workspace-skill"),
        )

    async def _validate_and_load_session(
        self, params: dict[str, Any]
    ) -> SessionMessageValidationResult:
        content = str(params.get("content", ""))
        session = self._session_manager.get(self.session.id)
        assert session is not None
        return SessionMessageValidationResult(
            params={"session_id": session.id, "content": content},
            sid=session.id,
            content=content,
            session=session,
            session_mode=SessionMode.DEFAULT,
            channel="cli",
            user_id=session.user_id,
            workspace_id=session.workspace_id,
            trust_level="trusted",
            trusted_input=True,
            firewall_result=FirewallResult(
                sanitized_text=content,
                original_hash="0" * 64,
            ),
            incoming_taint_labels=set(),
            is_internal_ingress=False,
            channel_message_id="msg-skill-followup-1",
        )

    def _is_admin_rpc_peer(self, _params: dict[str, Any]) -> bool:
        return False


def _write_skill(
    manager: MemoryManager,
    *,
    key: str,
    value: str,
    invocation_eligible: bool = True,
) -> str:
    decision = manager.write_with_provenance(
        entry_type="skill",
        key=key,
        value=value,
        source=MemorySource(origin="user", source_id=f"{key}-source", extraction_method="manual"),
        source_origin="user_direct",
        channel_trust="command",
        confirmation_status="user_asserted",
        source_id=f"{key}-source",
        scope="user",
        confidence=0.95,
        confirmation_satisfied=True,
        invocation_eligible=invocation_eligible,
    )
    assert decision.entry is not None
    return decision.entry.id


@pytest.mark.asyncio
async def test_m4_skills_command_lists_and_searches_invocable_artifacts(tmp_path: Path) -> None:
    harness = _SkillCommandHarness(tmp_path)
    release_id = _write_skill(
        harness._memory_manager,
        key="skill:release-close",
        value="Release close checklist\nRun the behavioral bundle before release.",
        invocation_eligible=True,
    )
    _write_skill(
        harness._memory_manager,
        key="skill:draft-only",
        value="Draft-only skill\nThis should stay out of the browse surface.",
        invocation_eligible=False,
    )

    listed = await SessionImplMixin.do_session_message(
        harness,
        {"session_id": "sess-skill-command", "content": "/skills"},
    )  # type: ignore[arg-type]
    searched = await SessionImplMixin.do_session_message(
        harness,
        {"session_id": "sess-skill-command", "content": "/skills search behavioral"},
    )  # type: ignore[arg-type]

    assert release_id in str(listed["response"])
    assert "release-close" in str(listed["response"])
    assert "draft-only" not in str(listed["response"])
    assert release_id in str(searched["response"])
    assert "behavioral bundle" in str(searched["response"])


@pytest.mark.asyncio
async def test_m4_skill_command_requires_exact_id_and_records_invocation(tmp_path: Path) -> None:
    harness = _SkillCommandHarness(tmp_path)
    release_id = _write_skill(
        harness._memory_manager,
        key="skill:release-close",
        value="Release close checklist\nRun the behavioral bundle before release.",
        invocation_eligible=True,
    )

    missing = await SessionImplMixin.do_session_message(
        harness,
        {"session_id": "sess-skill-command", "content": "/skill release-close"},
    )  # type: ignore[arg-type]
    invoked = await SessionImplMixin.do_session_message(
        harness,
        {"session_id": "sess-skill-command", "content": f"/skill {release_id}"},
    )  # type: ignore[arg-type]

    assert "was not found" in str(missing["response"])
    assert "Loaded skill" in str(invoked["response"])
    assert release_id in str(invoked["response"])
    assert "Release close checklist" in str(invoked["response"])
    events = harness._memory_manager.list_events(
        entry_id=release_id,
        event_type="skill_invoked",
        limit=10,
    )
    assert len(events) == 1
    entry = harness._memory_manager.get_entry(release_id)
    assert entry is not None
    assert entry.citation_count == 1


@pytest.mark.asyncio
async def test_m4_skill_info_command_returns_preview_metadata(tmp_path: Path) -> None:
    harness = _SkillCommandHarness(tmp_path)
    release_id = _write_skill(
        harness._memory_manager,
        key="skill:release-close",
        value="Release close checklist\nRun the behavioral bundle before release.",
        invocation_eligible=True,
    )

    result = await SessionImplMixin.do_session_message(
        harness,
        {"session_id": "sess-skill-command", "content": f"/skill info {release_id}"},
    )  # type: ignore[arg-type]

    assert release_id in str(result["response"])
    assert "Trust band: elevated" in str(result["response"])
    assert "Source origin: user_direct" in str(result["response"])
    assert "Release close checklist" in str(result["response"])


@pytest.mark.asyncio
async def test_m4_skill_info_command_previews_pending_review_candidate(tmp_path: Path) -> None:
    harness = _SkillCommandHarness(tmp_path)
    current_id = _write_skill(
        harness._memory_manager,
        key="skill:release-close",
        value="Release close checklist\nCurrent version",
        invocation_eligible=True,
    )
    candidate = harness._memory_manager.write_with_provenance(
        entry_type="skill",
        key="skill:release-close",
        value="Release close checklist\nCandidate version",
        source=MemorySource(
            origin="external",
            source_id="review-candidate-5",
            extraction_method="review.queue",
        ),
        source_origin="external_message",
        channel_trust="shared_participant",
        confirmation_status="pending_review",
        source_id="review-candidate-5",
        scope="user",
        confidence=0.62,
        confirmation_satisfied=True,
    )
    assert candidate.entry is not None

    result = await SessionImplMixin.do_session_message(
        harness,
        {"session_id": "sess-skill-command", "content": f"/skill info {candidate.entry.id}"},
    )  # type: ignore[arg-type]

    assert current_id in str(result["response"])
    assert "pending_review" in str(result["response"])
    assert "Candidate version" in str(result["response"])
    assert "Current version" in str(result["response"])


@pytest.mark.asyncio
async def test_m4_skill_commands_require_trusted_command_channel(tmp_path: Path) -> None:
    harness = _SkillCommandHarness(tmp_path, channel="discord")
    release_id = _write_skill(
        harness._memory_manager,
        key="skill:release-close",
        value="Release close checklist\nRun the behavioral bundle before release.",
        invocation_eligible=True,
    )

    result = await SessionImplMixin.do_session_message(
        harness,
        {"session_id": "sess-skill-command", "content": f"/skill {release_id}"},
    )  # type: ignore[arg-type]

    assert "trusted command channel" in str(result["response"])
    assert (
        harness._memory_manager.list_events(
            entry_id=release_id,
            event_type="skill_invoked",
            limit=10,
        )
        == []
    )


@pytest.mark.asyncio
async def test_m4_pending_review_skill_refuses_invocation_until_promoted(tmp_path: Path) -> None:
    harness = _SkillCommandHarness(tmp_path)
    candidate = harness._memory_manager.write_with_provenance(
        entry_type="skill",
        key="skill:release-close",
        value="Release close checklist\nCandidate version",
        source=MemorySource(
            origin="external",
            source_id="review-candidate-6",
            extraction_method="review.queue",
        ),
        source_origin="external_message",
        channel_trust="shared_participant",
        confirmation_status="pending_review",
        source_id="review-candidate-6",
        scope="user",
        confidence=0.62,
        confirmation_satisfied=True,
    )
    assert candidate.entry is not None

    result = await SessionImplMixin.do_session_message(
        harness,
        {"session_id": "sess-skill-command", "content": f"/skill {candidate.entry.id}"},
    )  # type: ignore[arg-type]

    assert "is not invocable" in str(result["response"])


@pytest.mark.asyncio
async def test_m4_skill_suggestion_yes_followup_loads_pending_artifact(tmp_path: Path) -> None:
    harness = _SuggestedSkillHarness(tmp_path)
    release_id = _write_skill(
        harness._memory_manager,
        key="skill:release-close",
        value="Release close checklist\nRun the behavioral bundle before release.",
        invocation_eligible=True,
    )
    harness.session.metadata[_PENDING_SKILL_SUGGESTION_ID_KEY] = release_id

    result = await SessionImplMixin.do_session_message(
        harness,
        {"session_id": str(harness.session.id), "content": "yes"},
    )  # type: ignore[arg-type]

    assert "Loaded skill" in str(result["response"])
    assert "Release close checklist" in str(result["response"])
    assert _PENDING_SKILL_SUGGESTION_ID_KEY not in harness.session.metadata
