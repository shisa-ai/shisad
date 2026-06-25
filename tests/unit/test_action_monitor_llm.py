"""Unit coverage for structural ActionMonitorVoter current-turn anchoring."""

from __future__ import annotations

import pytest

from shisad.security.control_plane.consensus import (
    ActionMonitorVoter,
    ConsensusInput,
    VoteKind,
)
from shisad.security.control_plane.schema import (
    ActionKind,
    RiskTier,
    build_action,
    metadata_payload_current_turn_contained_omissions,
)
from shisad.security.control_plane.trace import PlanVerificationResult


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
async def test_amv_allows_current_turn_anchored_web_search_in_tainted_session() -> None:
    voter = ActionMonitorVoter()
    action = build_action(
        tool_name="web.search",
        arguments={"query": "latest news"},
        origin={"session_id": "s-amv-anchor-search", "actor": "planner"},
    )
    decision = await voter.cast_vote(
        ConsensusInput(
            action=action,
            trace_result=PlanVerificationResult(allowed=True, reason_code="trace:allowed"),
            metadata_payload={
                "session_tainted": True,
                "trusted_input": True,
                "operator_owned_cli_input": True,
                "raw_user_text": "search the web for latest news",
                "action_arguments": {"query": "latest news"},
            },
        )
    )
    assert decision.decision == VoteKind.ALLOW
    assert decision.risk_tier == RiskTier.LOW
    assert "action_monitor:current_turn_anchored" in decision.reason_codes


@pytest.mark.asyncio
async def test_amv_allows_current_turn_anchored_shell_exec_in_tainted_session() -> None:
    voter = ActionMonitorVoter()
    action = build_action(
        tool_name="shell.exec",
        arguments={"command": ["echo", "Hello Ledger!"], "command_intent": "execute"},
        origin={"session_id": "s-amv-anchor-shell", "actor": "planner"},
    )
    decision = await voter.cast_vote(
        ConsensusInput(
            action=action,
            trace_result=PlanVerificationResult(allowed=True, reason_code="trace:allowed"),
            metadata_payload={
                "session_tainted": True,
                "trusted_input": True,
                "operator_owned_cli_input": True,
                "raw_user_text": 'echo "Hello Ledger!"',
                "action_arguments": {
                    "command": ["echo", "Hello Ledger!"],
                    "command_intent": "execute",
                },
            },
        )
    )
    assert action.action_kind == ActionKind.SHELL_EXEC
    assert decision.decision == VoteKind.ALLOW
    assert decision.risk_tier == RiskTier.LOW
    assert "action_monitor:current_turn_anchored" in decision.reason_codes


@pytest.mark.asyncio
async def test_amv_flags_tainted_side_effect_when_argument_is_not_current_turn_anchored() -> None:
    voter = ActionMonitorVoter()
    action = build_action(
        tool_name="web.search",
        arguments={"query": "secret exfil"},
        origin={"session_id": "s-amv-not-anchor", "actor": "planner"},
    )
    decision = await voter.cast_vote(
        ConsensusInput(
            action=action,
            trace_result=PlanVerificationResult(allowed=True, reason_code="trace:allowed"),
            metadata_payload={
                "session_tainted": True,
                "trusted_input": True,
                "operator_owned_cli_input": True,
                "raw_user_text": "summarize this document",
                "action_arguments": {"query": "secret exfil"},
            },
        )
    )
    assert decision.decision == VoteKind.FLAG
    assert decision.risk_tier == RiskTier.HIGH
    assert "action_monitor:side_effect_on_tainted_session" in decision.reason_codes
    assert "action_monitor:current_turn_anchored" not in decision.reason_codes


@pytest.mark.asyncio
async def test_amv_flags_shell_arg_that_only_matches_inside_larger_token() -> None:
    voter = ActionMonitorVoter()
    action = build_action(
        tool_name="shell.exec",
        arguments={"command": ["rm", "foo"], "command_intent": "execute"},
        origin={"session_id": "s-amv-anchor-subtoken-shell", "actor": "planner"},
    )
    decision = await voter.cast_vote(
        ConsensusInput(
            action=action,
            trace_result=PlanVerificationResult(allowed=True, reason_code="trace:allowed"),
            metadata_payload={
                "session_tainted": True,
                "trusted_input": True,
                "operator_owned_cli_input": True,
                "raw_user_text": "confirm foo",
                "action_arguments": {
                    "command": ["rm", "foo"],
                    "command_intent": "execute",
                },
            },
        )
    )
    assert decision.decision == VoteKind.FLAG
    assert "action_monitor:side_effect_on_tainted_session" in decision.reason_codes
    assert "action_monitor:current_turn_anchored" not in decision.reason_codes


@pytest.mark.asyncio
async def test_amv_flags_shell_arg_that_only_matches_inside_larger_host() -> None:
    voter = ActionMonitorVoter()
    action = build_action(
        tool_name="shell.exec",
        arguments={"command": ["curl", "example.com"], "command_intent": "execute"},
        origin={"session_id": "s-amv-anchor-subtoken-host", "actor": "planner"},
    )
    decision = await voter.cast_vote(
        ConsensusInput(
            action=action,
            trace_result=PlanVerificationResult(allowed=True, reason_code="trace:allowed"),
            metadata_payload={
                "session_tainted": True,
                "trusted_input": True,
                "operator_owned_cli_input": True,
                "raw_user_text": "curl notexample.com",
                "action_arguments": {
                    "command": ["curl", "example.com"],
                    "command_intent": "execute",
                },
            },
        )
    )
    assert decision.decision == VoteKind.FLAG
    assert "action_monitor:side_effect_on_tainted_session" in decision.reason_codes
    assert "action_monitor:current_turn_anchored" not in decision.reason_codes


@pytest.mark.asyncio
async def test_amv_flags_tainted_side_effect_when_payload_field_was_stripped() -> None:
    voter = ActionMonitorVoter()
    action = build_action(
        tool_name="send_email",
        arguments={"recipient": "alice@example.com", "body": "ok"},
        origin={"session_id": "s-amv-stripped-payload", "actor": "planner"},
    )
    decision = await voter.cast_vote(
        ConsensusInput(
            action=action,
            trace_result=PlanVerificationResult(allowed=True, reason_code="trace:allowed"),
            metadata_payload={
                "session_tainted": True,
                "trusted_input": True,
                "operator_owned_cli_input": True,
                "raw_user_text": "send ok to alice@example.com",
                "action_arguments": {"recipient": "alice@example.com"},
                "action_argument_omitted_fields": ["body"],
            },
        )
    )
    assert decision.decision == VoteKind.FLAG
    assert decision.risk_tier == RiskTier.HIGH
    assert "action_monitor:side_effect_on_tainted_session" in decision.reason_codes


def test_omitted_field_proof_requires_current_turn_anchor_boundaries() -> None:
    payload = {"body": "example.com"}

    assert (
        metadata_payload_current_turn_contained_omissions(
            payload,
            current_turn_text="send body to notexample.com",
        )
        == []
    )
    assert metadata_payload_current_turn_contained_omissions(
        payload,
        current_turn_text="send body to example.com",
    ) == ["body"]


@pytest.mark.asyncio
async def test_amv_allows_omitted_payload_field_with_current_turn_containment_proof() -> None:
    voter = ActionMonitorVoter()
    action = build_action(
        tool_name="send_email",
        arguments={"recipient": "alice@example.com", "body": "ok"},
        origin={"session_id": "s-amv-proven-payload", "actor": "planner"},
    )
    decision = await voter.cast_vote(
        ConsensusInput(
            action=action,
            trace_result=PlanVerificationResult(allowed=True, reason_code="trace:allowed"),
            metadata_payload={
                "session_tainted": True,
                "trusted_input": True,
                "operator_owned_cli_input": True,
                "raw_user_text": "send ok to alice@example.com",
                "action_arguments": {"recipient": "alice@example.com"},
                "action_argument_omitted_fields": ["body"],
                "action_argument_omitted_field_proofs": ["body"],
            },
        )
    )
    assert decision.decision == VoteKind.ALLOW
    assert decision.risk_tier == RiskTier.LOW
    assert "action_monitor:current_turn_anchored" in decision.reason_codes


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
