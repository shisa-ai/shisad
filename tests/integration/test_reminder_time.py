"""Malformed reminder arguments retain actionable feedback through the daemon."""

import pytest

from shisad.core.api.schema import SessionCreateParams, SessionMessageParams
from shisad.core.config import DaemonConfig
from shisad.core.planner import (
    ActionProposal,
    EvaluatedProposal,
    Planner,
    PlannerOutput,
    PlannerResult,
)
from shisad.core.request_context import RequestContext
from shisad.core.types import ToolName
from shisad.daemon.control_handlers import DaemonControlHandlers
from shisad.daemon.services import DaemonServices
from tests.helpers.daemon import clear_remote_provider_env


@pytest.mark.asyncio
async def test_invalid_reminder_time_reaches_synthesis_without_scheduling(tmp_path, monkeypatch):
    clear_remote_provider_env(monkeypatch)
    policy = tmp_path / "policy.yaml"
    policy.write_text('version: "1"\ndefault_require_confirmation: false\n')
    services = await DaemonServices.build(
        DaemonConfig(
            data_dir=tmp_path / "data",
            socket_path=tmp_path / "control.sock",
            policy_path=policy,
        )
    )
    calls = 0

    async def propose(self, user_content, context, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 1:
            proposal = ActionProposal(
                action_id="bad-time",
                tool_name=ToolName("reminder.create"),
                arguments={"message": "check results", "when": "in ten minutes"},
                reasoning="The user requested this reminder",
            )
            return PlannerResult(
                output=PlannerOutput(actions=[proposal], assistant_response=""),
                evaluated=[
                    EvaluatedProposal(
                        proposal=proposal,
                        decision=kwargs["pep"].evaluate(
                            proposal.tool_name, proposal.arguments, context
                        ),
                    )
                ],
                attempts=1,
            )
        assert calls == 2
        user_content = user_content.replace("^", "")
        assert "POST-TOOL SYNTHESIS PASS" in user_content
        assert "reminder_time_unsupported" in user_content
        assert "No reminder was created" in user_content
        assert "in 10 minutes" in user_content
        return PlannerResult(
            output=PlannerOutput(
                actions=[],
                assistant_response="The time format was invalid; no reminder was created.",
            ),
            evaluated=[],
            attempts=1,
        )

    monkeypatch.setattr(Planner, "propose_with_pep", propose)
    try:
        handlers = DaemonControlHandlers(services=services)
        request_context = RequestContext()
        created = await handlers.session.handle_session_create(
            SessionCreateParams(channel="cli", user_id="alice", workspace_id="local"),
            request_context,
        )
        result = await handlers.session.handle_session_message(
            SessionMessageParams(
                session_id=created.session_id,
                channel="cli",
                user_id="alice",
                workspace_id="local",
                content="Remind me in ten minutes to check results",
            ),
            request_context,
        )
        assert calls == 2
        assert result.response == "The time format was invalid; no reminder was created."
        assert services.scheduler.list_tasks() == []
        assert result.lockdown_level == "normal"
    finally:
        await services.shutdown()
