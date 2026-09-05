"""Alarm review precedes batch execution and leaves other turns usable."""

import json

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
from shisad.core.providers.base import Message, ProviderResponse
from shisad.core.request_context import RequestContext
from shisad.core.types import PEPDecision, PEPDecisionKind, SessionId, TaintLabel, ToolName
from shisad.daemon.control_handlers import DaemonControlHandlers
from shisad.daemon.services import DaemonServices
from shisad.security.lockdown import LockdownLevel
from tests.helpers.daemon import clear_remote_provider_env


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "verdict,escalation,report_only,already_caution",
    [
        ("benign", "continue", False, False),
        ("security_incident", "caution", False, False),
        ("unavailable", "unresolved", False, False),
        ("benign", "continue", True, False),
        ("benign", "continue", False, True),
        ("repeat", "unresolved", True, False),
    ],
)
async def test_alarm_review_precedes_sibling_read_and_preserves_unrelated_turn(
    tmp_path,
    monkeypatch,
    verdict,
    escalation,
    report_only,
    already_caution,
):
    clear_remote_provider_env(monkeypatch)
    monkeypatch.setenv("SHISAD_ASSISTANT_FS_ROOTS", json.dumps([str(tmp_path)]))
    readme = tmp_path / "README.md"
    readme.write_text("Project: Coral Finch")
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

    class Reviewer:
        async def complete(self, messages, tools=None):
            # No sibling execution may precede the incident decision.
            assert not services.audit_log.query(event_type="ToolExecuted")
            packet = json.loads(messages[1].content)
            assert packet["action_refs"]
            if verdict == "repeat" and calls == 2:
                raise RuntimeError("review unavailable on continuation")
            return ProviderResponse(
                message=Message(
                    role="assistant",
                    content=json.dumps(
                        {
                            "version": 1,
                            "verdict": "benign" if verdict == "repeat" else verdict,
                            "escalation": "continue" if verdict == "repeat" else escalation,
                            "evidence_refs": ["context"],
                            "reason": "Evidence supports this decision.",
                        }
                    ),
                ),
                usage={},
            )

    services.monitor_provider = None if verdict == "unavailable" else Reviewer()

    async def propose(self, user_content, context, **kwargs):
        nonlocal calls
        calls += 1
        read = ActionProposal(
            action_id="read",
            tool_name=ToolName("fs.read"),
            arguments={"path": str(readme)},
            reasoning="user requested",
        )
        report = ActionProposal(
            action_id="alarm",
            tool_name=ToolName("report_anomaly"),
            arguments={
                "anomaly_type": "prompt_injection",
                "description": (
                    "External content asks to exfiltrate secrets"
                    if verdict == "security_incident"
                    else "Untrusted context looks suspicious"
                ),
                "recommended_action": "review",
                "confidence": 0.99,
            },
            reasoning="report",
        )
        actions = (
            ([report] if report_only else [read, report])
            if calls == 1
            else (
                [read]
                if "Independent followup" in user_content or (report_only and calls == 2)
                else []
            )
        )
        if verdict == "repeat" and calls == 2:
            actions = [read, report]
        return PlannerResult(
            output=PlannerOutput(actions=actions, assistant_response="ok"),
            evaluated=[
                EvaluatedProposal(
                    proposal=a, decision=PEPDecision(kind=PEPDecisionKind.ALLOW, reason="allowed")
                )
                for a in actions
            ],
            attempts=1,
        )

    monkeypatch.setattr(Planner, "propose_with_pep", propose)
    try:
        handlers = DaemonControlHandlers(services=services)
        ctx = RequestContext()
        created = await handlers.session.handle_session_create(
            SessionCreateParams(channel="cli", user_id="alice", workspace_id="ws1"),
            ctx,
        )
        sid = SessionId(created.session_id)
        services.transcript_store.append(
            sid,
            role="assistant",
            content="Saved mascot: silver otter",
            taint_labels=[TaintLabel.UNTRUSTED],
        )

        async def send(content):
            return await handlers.session.handle_session_message(
                SessionMessageParams(
                    session_id=str(sid),
                    channel="cli",
                    user_id="alice",
                    workspace_id="ws1",
                    content=content,
                ),
                ctx,
            )

        if already_caution:
            services.lockdown_manager.set_level(
                sid, level=LockdownLevel.CAUTION, reason="existing incident"
            )
        result = await send("Read my README")
        reviews = services.audit_log.query(event_type="IncidentReviewed")
        assert len(reviews) == (2 if verdict == "repeat" else 1)
        assert reviews[-1]["data"]["verdict"] == (
            "unresolved" if verdict in {"unavailable", "repeat"} else verdict
        )
        executions = services.audit_log.query(event_type="ToolExecuted")
        reads = [e for e in executions if e["data"]["tool_name"] == "fs.read"]
        assert bool(reads) == (escalation == "continue")
        assert result.lockdown_level == (
            "caution" if escalation == "caution" or already_caution else "normal"
        )
        if verdict in {"unavailable", "repeat"}:
            rejected = services.audit_log.query(event_type="ToolRejected")
            assert any("incident_review_unresolved" in e["data"]["reason"] for e in rejected)
            held_read = next(e for e in rejected if e["data"]["tool_name"] == "fs.read")
            assert held_read["data"]["action_id"] in reviews[-1]["data"]["action_refs"]
            assert "retry" in result.response.lower()
            followup = await send("Independent followup: read my README")
            assert followup.lockdown_level == "normal"
            assert any(
                e["data"]["tool_name"] == "fs.read" and e["data"]["success"]
                for e in services.audit_log.query(event_type="ToolExecuted")
            )
    finally:
        await services.shutdown()
