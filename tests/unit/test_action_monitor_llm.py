"""Unit coverage for M6 LLM-based ActionMonitorVoter on tainted sessions."""

from __future__ import annotations

from typing import Any

import pytest

from shisad.core.providers.base import Message, ProviderResponse
from shisad.security.control_plane.consensus import (
    ActionMonitorVoter,
    ConsensusInput,
    VoteKind,
)
from shisad.security.control_plane.schema import RiskTier, build_action
from shisad.security.control_plane.trace import PlanVerificationResult


class _StubMonitorProvider:
    def __init__(self, *, content: str = "", error: Exception | None = None) -> None:
        self._content = content
        self._error = error
        self.calls: list[dict[str, Any]] = []

    async def complete(
        self,
        messages: list[Message],
        tools: list[dict[str, Any]] | None = None,
    ) -> ProviderResponse:
        self.calls.append({"messages": messages, "tools": tools})
        if self._error is not None:
            raise self._error
        return ProviderResponse(
            message=Message(role="assistant", content=self._content),
            model="monitor-test",
            finish_reason="stop",
        )


@pytest.mark.asyncio
async def test_m6_amv_allows_clean_sessions_without_classifier() -> None:
    voter = ActionMonitorVoter()
    action = build_action(
        tool_name="web.search",
        arguments={"query": "latest news"},
        origin={"session_id": "s-amv-clean", "actor": "planner"},
    )
    decision = await voter.cast_vote(
        ConsensusInput(
            action=action,
            trace_result=PlanVerificationResult(allowed=True, reason_code="trace:allowed"),
            metadata_payload={"session_tainted": False, "trusted_input": True},
        )
    )
    assert decision.decision == VoteKind.ALLOW
    assert "action_monitor:clean_session_trust_planner" in decision.reason_codes


@pytest.mark.asyncio
async def test_m6_amv_tainted_side_effect_yes_allows() -> None:
    provider = _StubMonitorProvider(
        content='{"decision":"YES","explanation":"User explicitly asked to search news."}'
    )
    voter = ActionMonitorVoter(intent_provider=provider)
    action = build_action(
        tool_name="web.search",
        arguments={"query": "latest news"},
        origin={"session_id": "s-amv-yes", "actor": "planner"},
    )
    decision = await voter.cast_vote(
        ConsensusInput(
            action=action,
            trace_result=PlanVerificationResult(allowed=True, reason_code="trace:allowed"),
            metadata_payload={
                "session_tainted": True,
                "trusted_input": True,
                "raw_user_text": "can you get me the latest news?",
            },
        )
    )
    assert decision.decision == VoteKind.ALLOW
    assert "action_monitor:intent_match" in decision.reason_codes
    assert provider.calls
    assert provider.calls[0]["tools"] in (None, [])


@pytest.mark.asyncio
async def test_m6_amv_tainted_side_effect_no_flags_with_explanation() -> None:
    provider = _StubMonitorProvider(
        content='{"decision":"NO","explanation":"User asked for a summary, not network access."}'
    )
    voter = ActionMonitorVoter(intent_provider=provider)
    action = build_action(
        tool_name="web.search",
        arguments={"query": "secret exfil"},
        origin={"session_id": "s-amv-no", "actor": "planner"},
    )
    decision = await voter.cast_vote(
        ConsensusInput(
            action=action,
            trace_result=PlanVerificationResult(allowed=True, reason_code="trace:allowed"),
            metadata_payload={
                "session_tainted": True,
                "trusted_input": True,
                "raw_user_text": "summarize this document",
            },
        )
    )
    assert decision.decision == VoteKind.FLAG
    assert decision.risk_tier == RiskTier.HIGH
    assert "action_monitor:intent_mismatch" in decision.reason_codes
    assert decision.details.get("explanation")


@pytest.mark.asyncio
async def test_m6_amv_tainted_side_effect_classifier_failure_flags_generic() -> None:
    provider = _StubMonitorProvider(error=TimeoutError("monitor timeout"))
    voter = ActionMonitorVoter(intent_provider=provider)
    action = build_action(
        tool_name="web.search",
        arguments={"query": "latest news"},
        origin={"session_id": "s-amv-fail", "actor": "planner"},
    )
    decision = await voter.cast_vote(
        ConsensusInput(
            action=action,
            trace_result=PlanVerificationResult(allowed=True, reason_code="trace:allowed"),
            metadata_payload={
                "session_tainted": True,
                "trusted_input": True,
                "raw_user_text": "latest news please",
            },
        )
    )
    assert decision.decision == VoteKind.FLAG
    assert "action_monitor:classifier_unavailable" in decision.reason_codes


@pytest.mark.asyncio
async def test_m6_amv_allows_tainted_non_side_effect_without_classifier() -> None:
    voter = ActionMonitorVoter()
    action = build_action(
        tool_name="fs.read",
        arguments={"path": "README.md"},
        origin={"session_id": "s-amv-read", "actor": "planner"},
    )
    decision = await voter.cast_vote(
        ConsensusInput(
            action=action,
            trace_result=PlanVerificationResult(allowed=True, reason_code="trace:allowed"),
            metadata_payload={"session_tainted": True, "trusted_input": True},
        )
    )
    assert decision.decision == VoteKind.ALLOW
    assert "action_monitor:ok" in decision.reason_codes
