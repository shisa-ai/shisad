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
        (
            "fetch https://example.com",
            "web.fetch",
            {"url": "https://example.com"},
        ),
        (
            "fetch https://example.com/ and summarize it",
            "web.fetch",
            {"url": "https://example.com/"},
        ),
        (
            "Use web.fetch to fetch https://example.com/ and tell me the title.",
            "web.fetch",
            {"url": "https://example.com/"},
        ),
        (
            "Please web fetch https://example.org/page.",
            "web.fetch",
            {"url": "https://example.org/page"},
        ),
        (
            "read evidence ev_test_123",
            "evidence.read",
            {"ref_id": "ev_test_123"},
        ),
        (
            "evidence.read ev_test_123",
            "evidence.read",
            {"ref_id": "ev_test_123"},
        ),
        (
            'evidence.read("ev_test_456")',
            "evidence.read",
            {"ref_id": "ev_test_456"},
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


def test_m1_plain_greeting_rewrite_ignores_greeting_prefixed_commands() -> None:
    planner_result = PlannerResult(
        output=PlannerOutput(assistant_response="", actions=[]),
        evaluated=[],
        attempts=1,
        provider_response=None,
        messages_sent=(),
    )

    rewritten = _rewrite_plain_greeting_planner_result(
        user_text="hello, add a note: test",
        planner_result=planner_result,
    )

    assert rewritten is planner_result


def test_m1_plain_greeting_rewrite_preserves_existing_tool_free_response() -> None:
    planner_result = PlannerResult(
        output=PlannerOutput(assistant_response="ok", actions=[]),
        evaluated=[],
        attempts=1,
        provider_response=None,
        messages_sent=(),
    )

    rewritten = _rewrite_plain_greeting_planner_result(
        user_text="hello",
        planner_result=planner_result,
    )

    assert rewritten is planner_result


def test_m1_explicit_memory_intent_parser_allows_greeting_prefix_before_command() -> None:
    proposal = _build_explicit_memory_intent_proposal("hello, add a note: test")

    assert proposal is not None
    assert proposal.tool_name == ToolName("note.create")
    assert proposal.arguments == {"content": "test"}


@pytest.mark.parametrize(
    "user_text",
    [
        "add todo: review PRs and list my todos",
        "add todo: review PRs; list my todos",
        "add todo: review PRs, list my todos",
        "add todo: review PRs; read README.md",
        "add todo: review PRs, read README.md",
        "remind me to check email on 2026-03-30T12:00:00Z",
    ],
)
def test_m1_explicit_memory_intent_parser_rejects_ambiguous_or_unsupported_forms(
    user_text: str,
) -> None:
    assert _build_explicit_memory_intent_proposal(user_text) is None


def test_m1_explicit_memory_intent_parser_allows_at_iso_reminder_datetime() -> None:
    proposal = _build_explicit_memory_intent_proposal(
        "remind me to check email at 2026-03-30T12:00:00Z"
    )

    assert proposal is not None
    assert proposal.tool_name == ToolName("reminder.create")
    assert proposal.arguments == {
        "message": "check email",
        "when": "at 2026-03-30T12:00:00Z",
    }


def test_m1_explicit_memory_intent_parser_keeps_comma_separated_note_content() -> None:
    proposal = _build_explicit_memory_intent_proposal("add a note: buy milk, eggs, bread")

    assert proposal is not None
    assert proposal.tool_name == ToolName("note.create")
    assert proposal.arguments == {"content": "buy milk, eggs, bread"}


@pytest.mark.parametrize(
    "user_text",
    [
        "add todo: review PRs and list my todos",
        "add todo: review PRs; list my todos",
        "add todo: review PRs, list my todos",
    ],
)
def test_m1_explicit_memory_intent_rewrite_preserves_multi_action_planner_results(
    user_text: str,
) -> None:
    registry = _memory_registry()
    pep = PEP(PolicyBundle(default_require_confirmation=False), registry)
    first = ActionProposal(
        action_id="a-1",
        tool_name=ToolName("todo.create"),
        arguments={"title": "review PRs"},
        reasoning="Create todo.",
        data_sources=[],
    )
    second = ActionProposal(
        action_id="a-2",
        tool_name=ToolName("todo.list"),
        arguments={},
        reasoning="List todos.",
        data_sources=[],
    )
    planner_result = PlannerResult(
        output=PlannerOutput(assistant_response="", actions=[first, second]),
        evaluated=[
            EvaluatedProposal(
                proposal=first,
                decision=PEPDecision(
                    kind=PEPDecisionKind.ALLOW,
                    reason="allow",
                    tool_name=first.tool_name,
                    risk_score=0.0,
                ),
            ),
            EvaluatedProposal(
                proposal=second,
                decision=PEPDecision(
                    kind=PEPDecisionKind.ALLOW,
                    reason="allow",
                    tool_name=second.tool_name,
                    risk_score=0.0,
                ),
            ),
        ],
        attempts=1,
        provider_response=None,
        messages_sent=(),
    )

    rewritten = _rewrite_explicit_memory_intent_planner_result(
        user_text=user_text,
        planner_result=planner_result,
        pep=pep,
        context=PolicyContext(capabilities={Capability.MEMORY_READ, Capability.MEMORY_WRITE}),
    )

    assert rewritten is planner_result


@pytest.mark.parametrize(
    "user_text",
    [
        "add todo: review PRs; read README.md",
        "add todo: review PRs, read README.md",
    ],
)
def test_m1_explicit_memory_intent_rewrite_preserves_non_memory_follow_on_results(
    user_text: str,
) -> None:
    registry = _memory_registry()
    pep = PEP(PolicyBundle(default_require_confirmation=False), registry)
    planner_result = PlannerResult(
        output=PlannerOutput(
            assistant_response=(
                "Tool results summary: - todo.create: success=True - fs.read: success=True"
            ),
            actions=[
                ActionProposal(
                    action_id="todo-create",
                    tool_name=ToolName("todo.create"),
                    arguments={"title": "review PRs"},
                    reasoning="Create the todo.",
                    data_sources=[],
                ),
                ActionProposal(
                    action_id="fs-read",
                    tool_name=ToolName("fs.read"),
                    arguments={"path": "README.md"},
                    reasoning="Read the requested file.",
                    data_sources=[],
                ),
            ],
        ),
        evaluated=[],
        attempts=1,
        provider_response=None,
        messages_sent=(),
    )

    rewritten = _rewrite_explicit_memory_intent_planner_result(
        user_text=user_text,
        planner_result=planner_result,
        pep=pep,
        context=PolicyContext(capabilities={Capability.MEMORY_READ, Capability.MEMORY_WRITE}),
    )

    assert rewritten is planner_result
