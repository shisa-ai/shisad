"""Regression coverage for planner tool-context trust normalization."""

from __future__ import annotations

from shisad.core.tools.schema import ToolDefinition, ToolParameter
from shisad.core.types import Capability, ToolName
from shisad.daemon.handlers._impl_session import (
    _blocked_action_feedback,
    _build_planner_tool_context,
    _coerce_blocked_action_response_text,
)


def test_m6_planner_tool_context_normalizes_trust_level_casing() -> None:
    tool = ToolDefinition(
        name=ToolName("web_search"),
        description="Search backend",
        parameters=[ToolParameter(name="query", type="string", required=True)],
        capabilities_required=[Capability.HTTP_REQUEST],
    )

    # Mixed-case trusted identity should receive trusted-context detail.
    context = _build_planner_tool_context(
        registry_tools=[tool],
        capabilities=set(),
        tool_allowlist=None,
        trust_level="Trusted",
    )
    assert "Enabled tools: none" in context
    assert "Unavailable tools in this session:" in context


def test_cc19_planner_tool_context_documents_native_tool_aliases() -> None:
    tool = ToolDefinition(
        name=ToolName("fs.list"),
        description="List files",
        parameters=[],
        capabilities_required=[],
    )

    context = _build_planner_tool_context(
        registry_tools=[tool],
        capabilities={Capability.FILE_READ},
        tool_allowlist=None,
        trust_level="trusted",
    )
    assert "Tool-name alias note:" in context
    assert "fs.list -> fs_list" in context
    assert "fs.list (native function: fs_list)" in context


def test_m3_s0b3_blocked_action_feedback_explains_web_policy_restriction() -> None:
    message = _blocked_action_feedback(
        [
            "consensus:veto:BehavioralSequenceAnalyzer,"
            "consensus:veto:ExecutionTraceVerifier,trace:stage2_upgrade_required",
            "web_search_disabled",
        ]
    )
    assert "live web access is disabled or restricted" in message


def test_m3_s0b3_blocked_action_feedback_explains_backend_config_error() -> None:
    message = _blocked_action_feedback(["web_search_backend_unconfigured"])
    assert "live web access is disabled or restricted" in message


def test_m3_s0b3_blocked_action_feedback_explains_stage2_gate() -> None:
    message = _blocked_action_feedback(
        ["consensus:veto:ExecutionTraceVerifier,trace:stage2_upgrade_required"]
    )
    assert "requires elevated runtime actions" in message


def test_m3_s0b3_blocked_action_feedback_falls_back_to_reason_code() -> None:
    message = _blocked_action_feedback(["rate_limit:too_many_actions"])
    assert "reason: rate_limit:too_many_actions" in message


def test_m3_s0b3_coerces_generic_blocked_text_to_actionable_feedback() -> None:
    response = _coerce_blocked_action_response_text(
        response_text="I could not safely execute the proposed action(s) under current policy.",
        rejected=1,
        pending_confirmation=0,
        executed_tool_outputs=0,
        rejection_reasons=["consensus:veto:ExecutionTraceVerifier,trace:stage2_upgrade_required"],
    )
    assert "requires elevated runtime actions" in response


def test_m3_s0b3_does_not_coerce_non_generic_response() -> None:
    response = _coerce_blocked_action_response_text(
        response_text="I can't access that right now.",
        rejected=1,
        pending_confirmation=0,
        executed_tool_outputs=0,
        rejection_reasons=["web_search_disabled"],
    )
    assert response == "I can't access that right now."
