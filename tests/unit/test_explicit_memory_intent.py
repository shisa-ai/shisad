"""M1 explicit memory-intent fallback coverage."""

from __future__ import annotations

import pytest

from shisad.core.planner import (
    ActionProposal,
    EvaluatedProposal,
    PlannerOutput,
    PlannerResult,
)
from shisad.core.tools.registry import ToolRegistry
from shisad.core.tools.schema import ToolDefinition, ToolParameter
from shisad.core.types import Capability, PEPDecision, PEPDecisionKind, ToolName
from shisad.daemon.handlers._impl_session import (
    _build_explicit_memory_intent_proposal,
    _rewrite_explicit_memory_intent_planner_result,
    _rewrite_plain_greeting_planner_result,
)
from shisad.security.pep import PEP, PolicyContext
from shisad.security.policy import PolicyBundle


def _memory_registry() -> ToolRegistry:
    registry = ToolRegistry()
    registry.register(
        ToolDefinition(
            name=ToolName("note.create"),
            description="Create note",
            parameters=[ToolParameter(name="content", type="string", required=True)],
            capabilities_required=[Capability.MEMORY_WRITE],
        )
    )
    registry.register(
        ToolDefinition(
            name=ToolName("note.search"),
            description="Search notes",
            parameters=[ToolParameter(name="query", type="string", required=True)],
            capabilities_required=[Capability.MEMORY_READ],
        )
    )
    registry.register(
        ToolDefinition(
            name=ToolName("todo.create"),
            description="Create todo",
            parameters=[ToolParameter(name="title", type="string", required=True)],
            capabilities_required=[Capability.MEMORY_WRITE],
        )
    )
    registry.register(
        ToolDefinition(
            name=ToolName("todo.list"),
            description="List todos",
            capabilities_required=[Capability.MEMORY_READ],
        )
    )
    registry.register(
        ToolDefinition(
            name=ToolName("todo.complete"),
            description="Complete todo",
            parameters=[ToolParameter(name="selector", type="string", required=True)],
            capabilities_required=[Capability.MEMORY_WRITE],
        )
    )
    registry.register(
        ToolDefinition(
            name=ToolName("reminder.create"),
            description="Create reminder",
            parameters=[
                ToolParameter(name="message", type="string", required=True),
                ToolParameter(name="when", type="string", required=True),
            ],
            capabilities_required=[Capability.MEMORY_WRITE, Capability.MESSAGE_SEND],
        )
    )
    registry.register(
        ToolDefinition(
            name=ToolName("reminder.list"),
            description="List reminders",
            capabilities_required=[Capability.MEMORY_READ],
        )
    )
    return registry


@pytest.mark.parametrize(
    ("user_text", "tool_name", "arguments"),
    [
        (
            "add a note: remember to buy groceries",
            "note.create",
            {"content": "remember to buy groceries"},
        ),
        (
            "search my notes for groceries",
            "note.search",
            {"query": "groceries"},
        ),
        (
            "add todo: review PRs",
            "todo.create",
            {"title": "review PRs"},
        ),
        (
            "list my todos",
            "todo.list",
            {},
        ),
        (
            "mark the review PRs todo complete",
            "todo.complete",
            {"selector": "review PRs"},
        ),
        (
            "remind me to check email in 5 seconds",
            "reminder.create",
            {"message": "check email", "when": "in 5 seconds"},
        ),
        (
            "list my reminders",
            "reminder.list",
            {},
        ),
    ],
)
def test_m1_explicit_memory_intent_parser_covers_weekend_sprint_commands(
    user_text: str,
    tool_name: str,
    arguments: dict[str, str],
) -> None:
    proposal = _build_explicit_memory_intent_proposal(user_text)

    assert proposal is not None
    assert proposal.tool_name == ToolName(tool_name)
    assert proposal.arguments == arguments


def test_m1_explicit_memory_intent_rewrite_replaces_spurious_planner_actions() -> None:
    registry = _memory_registry()
    pep = PEP(PolicyBundle(default_require_confirmation=False), registry)
    wrong_proposal = ActionProposal(
        action_id="a-1",
        tool_name=ToolName("note.create"),
        arguments={"content": "Remind me to review PRs", "key": "review_prs"},
        reasoning="Store a note.",
        data_sources=[],
    )
    wrong_decision = PEPDecision(
        kind=PEPDecisionKind.ALLOW,
        reason="allow",
        tool_name=wrong_proposal.tool_name,
        risk_score=0.0,
    )
    planner_result = PlannerResult(
        output=PlannerOutput(
            assistant_response="The correct tool call would be note.create.",
            actions=[wrong_proposal],
        ),
        evaluated=[EvaluatedProposal(proposal=wrong_proposal, decision=wrong_decision)],
        attempts=1,
        provider_response=None,
        messages_sent=(),
    )

    rewritten = _rewrite_explicit_memory_intent_planner_result(
        user_text="add todo: review PRs",
        planner_result=planner_result,
        pep=pep,
        context=PolicyContext(
            capabilities={Capability.MEMORY_READ, Capability.MEMORY_WRITE, Capability.MESSAGE_SEND}
        ),
    )

    assert rewritten.output.assistant_response == ""
    assert len(rewritten.evaluated) == 1
    assert rewritten.evaluated[0].proposal.tool_name == ToolName("todo.create")
    assert rewritten.evaluated[0].proposal.arguments == {"title": "review PRs"}
    assert rewritten.evaluated[0].decision.kind == PEPDecisionKind.ALLOW


def test_m1_plain_greeting_rewrite_drops_spurious_tool_actions() -> None:
    wrong_proposal = ActionProposal(
        action_id="a-hello",
        tool_name=ToolName("note.create"),
        arguments={"content": "hello"},
        reasoning="Store hello.",
        data_sources=[],
    )
    planner_result = PlannerResult(
        output=PlannerOutput(
            assistant_response="Tool results summary: - note.create: success=True",
            actions=[wrong_proposal],
        ),
        evaluated=[],
        attempts=1,
        provider_response=None,
        messages_sent=(),
    )

    rewritten = _rewrite_plain_greeting_planner_result(
        user_text="hello",
        planner_result=planner_result,
    )

    assert rewritten.output.actions == []
    assert rewritten.evaluated == []
    assert rewritten.output.assistant_response == "Hello. How can I help?"
