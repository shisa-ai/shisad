"""Retained greeting boundary after F13B removes explicit-intent fallback."""

from __future__ import annotations

from shisad.core.planner import ActionProposal, PlannerOutput, PlannerResult
from shisad.core.types import ToolName
from shisad.daemon.handlers._impl_session import _rewrite_plain_greeting_planner_result


def _planner_result(
    *,
    response: str = "",
    actions: list[ActionProposal] | None = None,
    attempts: int = 1,
) -> PlannerResult:
    return PlannerResult(
        output=PlannerOutput(
            assistant_response=response,
            actions=list(actions or []),
        ),
        evaluated=[],
        attempts=attempts,
    )


def test_plain_greeting_rewrite_drops_spurious_tool_actions() -> None:
    wrong_proposal = ActionProposal(
        action_id="a-hello",
        tool_name=ToolName("note.create"),
        arguments={"content": "hello"},
        reasoning="Store hello.",
        data_sources=[],
    )

    rewritten = _rewrite_plain_greeting_planner_result(
        user_text="hello",
        planner_result=_planner_result(
            response="Tool results summary: - note.create: success=True",
            actions=[wrong_proposal],
        ),
    )

    assert rewritten.output.actions == []
    assert rewritten.evaluated == []
    assert rewritten.output.assistant_response == "Hello. How can I help?"


def test_plain_greeting_rewrite_ignores_greeting_prefixed_commands() -> None:
    planner_result = _planner_result(response="Creating your requested note.")

    rewritten = _rewrite_plain_greeting_planner_result(
        user_text="hello, add a note: test",
        planner_result=planner_result,
    )

    assert rewritten is planner_result


def test_plain_greeting_rewrite_normalizes_existing_tool_free_response() -> None:
    planner_result = _planner_result(response="ok")

    rewritten = _rewrite_plain_greeting_planner_result(
        user_text="hello",
        planner_result=planner_result,
    )

    assert rewritten is not planner_result
    assert rewritten.output.actions == []
    assert rewritten.evaluated == []
    assert rewritten.output.assistant_response == "Hello. How can I help?"


def test_plain_greeting_rewrite_normalizes_planner_validation_fallback() -> None:
    rewritten = _rewrite_plain_greeting_planner_result(
        user_text="hello",
        planner_result=_planner_result(
            response="Assistant planner error (planner_output_invalid). Please retry.",
            attempts=0,
        ),
    )

    assert rewritten.output.actions == []
    assert rewritten.evaluated == []
    assert rewritten.output.assistant_response == "Hello. How can I help?"


def test_plain_greeting_rewrite_keeps_authenticated_configuration_fallback() -> None:
    planner_result = _planner_result(
        response=(
            "[PLANNER FALLBACK: CONFIGURATION] No language model configured. "
            "Configure a planner route or local planner preset."
        ),
        attempts=0,
    )

    rewritten = _rewrite_plain_greeting_planner_result(
        user_text="hello there",
        planner_result=planner_result,
    )

    assert rewritten is planner_result
