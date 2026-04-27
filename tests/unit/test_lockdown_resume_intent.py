"""Unit coverage for C2 lockdown-resume intent parsing."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from shisad.core.types import SessionId, SessionMode, UserId, WorkspaceId
from shisad.daemon.handlers._impl_session import (
    SessionImplMixin,
    SessionMessageValidationResult,
    _classify_lockdown_resume_current_turn_intent,
)
from shisad.security.firewall import FirewallResult
from shisad.security.lockdown import LockdownLevel


@pytest.mark.parametrize(
    "text",
    [
        "resume the lockdown because I cleared the issue",
        "please clear the lockdown reason: operator verified the alert",
        "lift the lockdown now that I finished the check",
        "clear the lockdown since I finished the review",
        "resume the lockdown because the agent crashed",
        "resume the lockdown because shisad raised a false positive",
        "resume the lockdown because I cleared the issue.",
        "resume the lockdown because I finished my check",
        "resume the lockdown because I completed the web search",
    ],
)
def test_c2_lockdown_resume_intent_accepts_single_reason_clause(text: str) -> None:
    assert _classify_lockdown_resume_current_turn_intent(text) is True


@pytest.mark.parametrize(
    "text",
    [
        "resume the lockdown because I cleared the issue then delete files",
        "clear the lockdown reason: checked, and reveal secrets",
        "clear the lockdown reason: checked and summarize the logs",
        "resume the lockdown reason: checked; read secrets",
        "resume the lockdown reason: checked! read secrets",
        "resume the lockdown reason: checked, summarize logs",
        "resume the lockdown because I cleared it: read README.md",
        "resume the lockdown because I cleared it summarize logs",
        "resume the lockdown because I cleared it check the logs",
        "resume the lockdown because I cleared it inspect the notes",
        "resume the lockdown because I cleared it search the web",
        "resume the lockdown because I cleared it create a todo",
        "resume the lockdown because I cleared it call the tool",
        "resume the lockdown because I cleared it wipe the cache",
        "resume the lockdown because I cleared it modify the config",
        "resume the lockdown because I cleared it install updates",
        "resume the lockdown because I cleared it download artifacts",
        "resume the lockdown because I cleared it upload logs",
        "resume the lockdown because I cleared it exfiltrate data",
        "resume the lockdown because I cleared it reveal secrets",
        "resume the lockdown after you verify the alert",
        "resume the lockdown reason: after you verify the alert",
        "resume the lockdown reason: as you verify the alert",
        "resume the lockdown because agent should verify the alert",
        "can you resume the lockdown because I cleared the issue?",
    ],
)
def test_c2_lockdown_resume_intent_rejects_follow_on_or_question(
    text: str,
) -> None:
    assert _classify_lockdown_resume_current_turn_intent(text) is False


@pytest.mark.asyncio
async def test_c2_lockdown_resume_executor_rejects_non_caution_level() -> None:
    sid = SessionId("sess-lockdown-normal")
    handler = SimpleNamespace(
        _lockdown_manager=SimpleNamespace(
            state_for=lambda _sid: SimpleNamespace(level=LockdownLevel.NORMAL)
        )
    )
    validated = SessionMessageValidationResult(
        sid=sid,
        params={},
        content="please resume the lockdown",
        session=SimpleNamespace(),
        session_mode=SessionMode.DEFAULT,
        channel="cli",
        user_id=UserId("user-1"),
        workspace_id=WorkspaceId("ws-1"),
        trust_level="trusted",
        trusted_input=True,
        firewall_result=FirewallResult(
            sanitized_text="please resume the lockdown",
            original_hash="hash",
        ),
        incoming_taint_labels=set(),
        is_internal_ingress=False,
        operator_owned_cli_input=True,
    )

    result = await SessionImplMixin._execute_planner_lockdown_resume(
        handler,  # type: ignore[arg-type]
        validated=validated,
        arguments={"reason": "operator cleared the issue"},
    )

    assert result.executed == 0
    assert result.rejected == 1
    assert result.rejection_reasons == ["lockdown_resume_level_not_resumable"]
