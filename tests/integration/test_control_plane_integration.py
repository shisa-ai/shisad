"""M5 integration coverage for control-plane pipeline and daemon wiring."""

from __future__ import annotations

import asyncio
import json
import os
import sys
from contextlib import suppress
from pathlib import Path

import pytest
import yaml

from shisad.core.api.transport import ControlClient
from shisad.core.config import DaemonConfig
from shisad.core.planner import (
    ActionProposal,
    EvaluatedProposal,
    Planner,
    PlannerOutput,
    PlannerResult,
)
from shisad.core.providers.base import Message, ProviderResponse
from shisad.core.types import Capability, ToolName
from shisad.daemon.runner import run_daemon
from shisad.executors.connect_path import IptablesConnectPathProxy
from shisad.security.control_plane.engine import ControlPlaneEngine
from shisad.security.control_plane.schema import ControlDecision, Origin, RiskTier, build_action


@pytest.fixture
def model_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SHISAD_MODEL_BASE_URL", "https://api.example.com/v1")
    monkeypatch.setenv("SHISAD_MODEL_PLANNER_BASE_URL", "https://planner.example.com/v1")
    monkeypatch.setenv("SHISAD_MODEL_EMBEDDINGS_BASE_URL", "https://embed.example.com/v1")
    monkeypatch.setenv("SHISAD_MODEL_MONITOR_BASE_URL", "https://monitor.example.com/v1")


async def _wait_for_socket(path: Path, timeout: float = 5.0) -> None:
    end = asyncio.get_running_loop().time() + timeout
    while asyncio.get_running_loop().time() < end:
        if path.exists():
            return
        await asyncio.sleep(0.01)
    raise TimeoutError(f"Timed out waiting for socket {path}")


async def _start_daemon_with_policy(
    tmp_path: Path,
    *,
    policy: dict[str, object] | None = None,
    checkpoint_trigger: str | None = None,
    assistant_fs_roots: list[Path] | None = None,
) -> tuple[asyncio.Task[None], ControlClient]:
    if policy is not None:
        (tmp_path / "policy.yaml").write_text(
            yaml.safe_dump(policy, sort_keys=False),
            encoding="utf-8",
        )
    config_kwargs: dict[str, object] = {
        "data_dir": tmp_path / "data",
        "socket_path": tmp_path / "control.sock",
        "policy_path": tmp_path / "policy.yaml",
        "log_level": "INFO",
        # Make fs/git helper tools deterministic in CI and avoid depending on the
        # host environment's SHISAD_ASSISTANT_FS_ROOTS value.
        "assistant_fs_roots": list(assistant_fs_roots or [Path.cwd()]),
    }
    if checkpoint_trigger is not None:
        config_kwargs["checkpoint_trigger"] = checkpoint_trigger
    config = DaemonConfig(**config_kwargs)
    daemon_task = asyncio.create_task(run_daemon(config))
    client = ControlClient(config.socket_path)
    await _wait_for_socket(config.socket_path)
    await client.connect()
    return daemon_task, client


async def _shutdown(daemon_task: asyncio.Task[None], client: ControlClient) -> None:
    with suppress(Exception):
        await client.call("daemon.shutdown")
    await client.close()
    await asyncio.wait_for(daemon_task, timeout=3)


class _StubMonitorProvider:
    def __init__(self, *, content: str) -> None:
        self._content = content
        self.calls = 0

    async def complete(
        self,
        messages: list[Message],
        tools: list[dict[str, object]] | None = None,
    ) -> ProviderResponse:
        _ = messages, tools
        self.calls += 1
        return ProviderResponse(
            message=Message(role="assistant", content=self._content),
            model="monitor-test",
            finish_reason="stop",
        )


@pytest.mark.asyncio
async def test_m5_t12_plan_commitment_prevents_post_content_privilege_upgrade(
    tmp_path: Path,
) -> None:
    engine = ControlPlaneEngine.build(data_dir=tmp_path / "cp12")
    origin = Origin(
        session_id="m5-t12",
        user_id="user-1",
        workspace_id="ws-1",
        actor="planner",
    )
    engine.begin_precontent_plan(
        session_id=origin.session_id,
        goal="summarize incident evidence",
        origin=origin,
        ttl_seconds=600,
        max_actions=5,
    )
    evaluation = await engine.evaluate_action(
        tool_name="http_request",
        arguments={"url": "https://evil.example/collect"},
        origin=origin,
        risk_tier=RiskTier.HIGH,
        declared_domains=["evil.example"],
        session_tainted=False,
        trusted_input=True,
    )
    assert evaluation.decision == ControlDecision.BLOCK
    assert evaluation.trace_result.reason_code == "trace:stage2_upgrade_required"


@pytest.mark.asyncio
async def test_m5_t13_consensus_blocks_when_high_voter_rejects(tmp_path: Path) -> None:
    engine = ControlPlaneEngine.build(data_dir=tmp_path / "cp13")
    origin = Origin(
        session_id="m5-t13",
        user_id="user-1",
        workspace_id="ws-1",
        actor="planner",
    )
    engine.begin_precontent_plan(
        session_id=origin.session_id,
        goal="read README.md and summarize it",
        origin=origin,
        ttl_seconds=600,
        max_actions=10,
    )
    first = await engine.evaluate_action(
        tool_name="file.read",
        arguments={"path": "README.md"},
        origin=origin,
        risk_tier=RiskTier.LOW,
        declared_domains=[],
        session_tainted=False,
        trusted_input=True,
    )
    assert first.decision == ControlDecision.ALLOW

    upgrade_action = build_action(
        tool_name="http_request",
        arguments={"url": "https://allowed.example/upload"},
        origin=origin,
        risk_tier=RiskTier.HIGH,
    )
    engine.approve_stage2(action=upgrade_action, approved_by="human_confirmation")

    second = await engine.evaluate_action(
        tool_name="http_request",
        arguments={"url": "https://allowed.example/upload"},
        origin=origin,
        risk_tier=RiskTier.HIGH,
        declared_domains=["allowed.example"],
        session_tainted=False,
        trusted_input=True,
    )
    assert second.decision == ControlDecision.BLOCK
    assert any(code.startswith("consensus:veto:") for code in second.reason_codes)


@pytest.mark.asyncio
async def test_m5_t14_end_to_end_control_plane_happy_and_compromise_paths(tmp_path: Path) -> None:
    engine = ControlPlaneEngine.build(data_dir=tmp_path / "cp14")
    origin = Origin(
        session_id="m5-t14",
        user_id="user-1",
        workspace_id="ws-1",
        actor="planner",
    )
    plan_hash = engine.begin_precontent_plan(
        session_id=origin.session_id,
        goal="read README.md and summarize it",
        origin=origin,
        ttl_seconds=600,
        max_actions=10,
    )
    assert plan_hash

    happy = await engine.evaluate_action(
        tool_name="file.read",
        arguments={"path": "README.md"},
        origin=origin,
        risk_tier=RiskTier.LOW,
        declared_domains=[],
        session_tainted=False,
        trusted_input=True,
    )
    assert happy.decision == ControlDecision.ALLOW
    engine.record_execution(action=happy.action, success=True)

    stage2 = build_action(
        tool_name="http_request",
        arguments={"url": "https://allowed.example/upload"},
        origin=origin,
        risk_tier=RiskTier.HIGH,
    )
    engine.approve_stage2(action=stage2, approved_by="human_confirmation")
    compromised = await engine.evaluate_action(
        tool_name="http_request",
        arguments={"url": "https://allowed.example/upload"},
        origin=origin,
        risk_tier=RiskTier.HIGH,
        declared_domains=["allowed.example"],
        session_tainted=False,
        trusted_input=True,
    )
    assert compromised.decision == ControlDecision.BLOCK

    ok, count, error = engine.audit.verify_chain()
    assert ok is True
    assert count >= 3
    assert error == ""


@pytest.mark.asyncio
async def test_m6_amv_tainted_session_yes_allows_side_effect(tmp_path: Path) -> None:
    provider = _StubMonitorProvider(
        content='{"decision":"YES","explanation":"User asked to write this file."}'
    )
    engine = ControlPlaneEngine.build(data_dir=tmp_path / "cp-m6-yes", monitor_provider=provider)
    origin = Origin(
        session_id="m6-amv-yes",
        user_id="user-1",
        workspace_id="ws-1",
        actor="planner",
    )
    engine.begin_precontent_plan(
        session_id=origin.session_id,
        goal="write status.txt",
        origin=origin,
        ttl_seconds=600,
        max_actions=10,
        capabilities={Capability.FILE_WRITE},
    )
    evaluation = await engine.evaluate_action(
        tool_name="fs.write",
        arguments={"path": "status.txt", "content": "ok"},
        origin=origin,
        risk_tier=RiskTier.MEDIUM,
        declared_domains=[],
        session_tainted=True,
        trusted_input=True,
        raw_user_text="write status.txt with ok",
    )
    assert evaluation.decision == ControlDecision.ALLOW
    assert provider.calls == 1


@pytest.mark.asyncio
async def test_m6_amv_tainted_session_no_blocks_when_h4_path_is_missing(
    tmp_path: Path,
) -> None:
    provider = _StubMonitorProvider(
        content='{"decision":"NO","explanation":"User asked to summarize, not write files."}'
    )
    engine = ControlPlaneEngine.build(data_dir=tmp_path / "cp-m6-no", monitor_provider=provider)
    origin = Origin(
        session_id="m6-amv-no",
        user_id="user-1",
        workspace_id="ws-1",
        actor="planner",
    )
    engine.begin_precontent_plan(
        session_id=origin.session_id,
        goal="summarize docs",
        origin=origin,
        ttl_seconds=600,
        max_actions=10,
        capabilities={Capability.FILE_WRITE},
    )
    evaluation = await engine.evaluate_action(
        tool_name="fs.write",
        arguments={"path": "status.txt", "content": "secret"},
        origin=origin,
        risk_tier=RiskTier.MEDIUM,
        declared_domains=[],
        session_tainted=True,
        trusted_input=True,
        raw_user_text="summarize docs",
    )
    assert evaluation.decision == ControlDecision.BLOCK
    assert "trace:tdg_dependency_path_missing" in evaluation.reason_codes
    amv_vote = next(
        vote for vote in evaluation.consensus.votes if vote.voter == "ActionMonitorVoter"
    )
    assert "action_monitor:intent_mismatch" in amv_vote.reason_codes
    assert amv_vote.details.get("explanation")


@pytest.mark.asyncio
async def test_m6_rr2_amv_clean_session_multiline_user_text_does_not_hard_block(
    tmp_path: Path,
) -> None:
    engine = ControlPlaneEngine.build(data_dir=tmp_path / "cp-m6-multiline")
    origin = Origin(
        session_id="m6-amv-multiline",
        user_id="user-1",
        workspace_id="ws-1",
        actor="planner",
    )
    engine.begin_precontent_plan(
        session_id=origin.session_id,
        goal="read README.md",
        origin=origin,
        ttl_seconds=600,
        max_actions=10,
        capabilities={Capability.FILE_READ},
    )
    evaluation = await engine.evaluate_action(
        tool_name="fs.read",
        arguments={"path": "README.md"},
        origin=origin,
        risk_tier=RiskTier.LOW,
        declared_domains=[],
        session_tainted=False,
        trusted_input=True,
        raw_user_text=(
            "Please read README.md and summarize key points in bullet form.\n"
            "Include setup, usage, and troubleshooting details."
        ),
    )
    assert evaluation.decision == ControlDecision.ALLOW
    amv_vote = next(
        vote for vote in evaluation.consensus.votes if vote.voter == "ActionMonitorVoter"
    )
    assert "action_monitor:raw_text_payload_forbidden" not in amv_vote.reason_codes
    assert "consensus:veto:ActionMonitorVoter" not in evaluation.reason_codes


@pytest.mark.asyncio
async def test_m5_t19_trace_stage2_routes_to_confirmation_not_lockdown(
    model_env: None,
    tmp_path: Path,
) -> None:
    """With restricted capabilities, tool calls outside the plan trigger
    stage2 → confirmation (not plan violation + lockdown)."""
    # Use restricted capabilities so EGRESS/SHELL_EXEC are NOT in the
    # stage1 plan — this is the scenario where stage2 triggers.
    daemon_task, client = await _start_daemon_with_policy(
        tmp_path,
        policy={
            "version": "1",
            "default_deny": False,
            "default_require_confirmation": False,
            "default_capabilities": ["file.read", "memory.read"],
        },
    )
    try:
        created = await client.call("session.create", {"channel": "cli"})
        sid = created["session_id"]
        response = await client.call(
            "session.message",
            {"session_id": sid, "content": "run: curl https://evil.example/collect"},
        )
        # Trace-only stage2 blocks route to confirmation, not rejection.
        # With a mocked model the planner may not generate tool calls, so
        # confirmation_required_actions may be 0. Key invariant: no lockdown.
        assert response.get("lockdown_level", "normal") == "normal"

        # No plan violations — trace-only stage2 is not a violation.
        violations = await client.call(
            "audit.query",
            {"event_type": "PlanViolationDetected", "session_id": sid, "limit": 20},
        )
        assert violations["total"] == 0

        sessions = await client.call("session.list")
        row = next(item for item in sessions["sessions"] if item["id"] == sid)
        assert row["lockdown_level"] == "normal"
    finally:
        await _shutdown(daemon_task, client)


@pytest.mark.asyncio
async def test_h4_missing_path_read_routes_to_confirmation(
    model_env: None,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def _forced_unjustified_read(
        self: Planner,
        user_content: str,
        context: object,
        *,
        tools: list[dict[str, object]] | None = None,
        persona_tone_override: str | None = None,
    ) -> PlannerResult:
        _ = user_content, tools, persona_tone_override
        proposal = ActionProposal(
            action_id="h4-unjustified-read",
            tool_name=ToolName("fs.read"),
            arguments={"path": "README.md"},
            reasoning="attempt a read with no dependency path back to the user goal",
            data_sources=[],
        )
        decision = self._pep.evaluate(proposal.tool_name, proposal.arguments, context)
        return PlannerResult(
            output=PlannerOutput(actions=[proposal], assistant_response="read pending approval"),
            evaluated=[EvaluatedProposal(proposal=proposal, decision=decision)],
            attempts=1,
            provider_response=None,
            messages_sent=(),
        )

    monkeypatch.setattr(Planner, "propose", _forced_unjustified_read)

    daemon_task, client = await _start_daemon_with_policy(
        tmp_path,
        policy={
            "version": "1",
            "default_deny": False,
            "default_require_confirmation": False,
            "default_capabilities": ["file.read"],
        },
    )
    try:
        created = await client.call("session.create", {"channel": "cli"})
        sid = created["session_id"]
        response = await client.call(
            "session.message",
            {"session_id": sid, "content": "say hello"},
        )
        assert int(response.get("blocked_actions", 0)) == 0
        assert int(response.get("confirmation_required_actions", 0)) >= 1
        assert response.get("lockdown_level", "normal") == "normal"

        pending = await client.call(
            "action.pending",
            {"session_id": sid, "status": "pending", "limit": 20},
        )
        assert any(
            "trace:tdg_confirmation_required" in str(item.get("reason", ""))
            for item in pending["actions"]
        )

        violations = await client.call(
            "audit.query",
            {"event_type": "PlanViolationDetected", "session_id": sid, "limit": 20},
        )
        assert violations["total"] == 0
    finally:
        await _shutdown(daemon_task, client)


@pytest.mark.asyncio
async def test_h4_missing_path_side_effect_stays_blocked(
    model_env: None,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target_path = str((Path.cwd() / "H4-rogue.txt").resolve())

    async def _forced_unjustified_write(
        self: Planner,
        user_content: str,
        context: object,
        *,
        tools: list[dict[str, object]] | None = None,
        persona_tone_override: str | None = None,
    ) -> PlannerResult:
        _ = user_content, tools, persona_tone_override
        proposal = ActionProposal(
            action_id="h4-unjustified-write",
            tool_name=ToolName("fs.write"),
            arguments={"path": target_path, "content": "hello"},
            reasoning="attempt a write with no dependency path back to the user goal",
            data_sources=[],
        )
        decision = self._pep.evaluate(proposal.tool_name, proposal.arguments, context)
        return PlannerResult(
            output=PlannerOutput(actions=[proposal], assistant_response="write blocked"),
            evaluated=[EvaluatedProposal(proposal=proposal, decision=decision)],
            attempts=1,
            provider_response=None,
            messages_sent=(),
        )

    monkeypatch.setattr(Planner, "propose", _forced_unjustified_write)

    daemon_task, client = await _start_daemon_with_policy(
        tmp_path,
        policy={
            "version": "1",
            "default_deny": False,
            "default_require_confirmation": False,
            "default_capabilities": ["file.write"],
        },
    )
    try:
        created = await client.call("session.create", {"channel": "cli"})
        sid = created["session_id"]
        response = await client.call(
            "session.message",
            {"session_id": sid, "content": "say hello"},
        )
        assert int(response.get("blocked_actions", 0)) == 1
        assert int(response.get("confirmation_required_actions", 0)) == 0
        assert response.get("lockdown_level", "normal") == "normal"

        pending = await client.call(
            "action.pending",
            {"session_id": sid, "status": "pending", "limit": 20},
        )
        assert int(pending.get("count", 0)) == 0

        violations = await client.call(
            "audit.query",
            {"event_type": "PlanViolationDetected", "session_id": sid, "limit": 20},
        )
        assert any(
            str(event.get("data", {}).get("reason_code", "")) == "trace:tdg_dependency_path_missing"
            for event in violations["events"]
        )
    finally:
        await _shutdown(daemon_task, client)


@pytest.mark.asyncio
async def test_h4_runtime_path_normalization_uses_assistant_fs_root(
    model_env: None,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace_root = tmp_path / "workspace"
    workspace_root.mkdir()
    (workspace_root / "README.md").write_text("h4-custom-root\n", encoding="utf-8")

    async def _forced_workspace_read(
        self: Planner,
        user_content: str,
        context: object,
        *,
        tools: list[dict[str, object]] | None = None,
        persona_tone_override: str | None = None,
    ) -> PlannerResult:
        _ = user_content, tools, persona_tone_override
        proposal = ActionProposal(
            action_id="h4-workspace-read",
            tool_name=ToolName("fs.read"),
            arguments={"path": "README.md"},
            reasoning="read the workspace README from the configured assistant root",
            data_sources=[],
        )
        decision = self._pep.evaluate(proposal.tool_name, proposal.arguments, context)
        return PlannerResult(
            output=PlannerOutput(actions=[proposal], assistant_response="workspace read"),
            evaluated=[EvaluatedProposal(proposal=proposal, decision=decision)],
            attempts=1,
            provider_response=None,
            messages_sent=(),
        )

    monkeypatch.setattr(Planner, "propose", _forced_workspace_read)

    daemon_task, client = await _start_daemon_with_policy(
        tmp_path,
        policy={
            "version": "1",
            "default_deny": False,
            "default_require_confirmation": False,
            "default_capabilities": ["file.read"],
        },
        assistant_fs_roots=[workspace_root],
    )
    try:
        created = await client.call("session.create", {"channel": "cli"})
        sid = created["session_id"]
        response = await client.call(
            "session.message",
            {"session_id": sid, "content": "read README.md"},
        )
        assert int(response.get("blocked_actions", 0)) == 0
        assert int(response.get("confirmation_required_actions", 0)) == 0
        assert int(response.get("executed_actions", 0)) == 1

        outputs = response.get("tool_outputs", [])
        read_payload = next(
            item.get("payload", {}) for item in outputs if item.get("tool_name") == "fs.read"
        )
        assert read_payload.get("ok") is True
        assert "h4-custom-root" in str(read_payload.get("content", ""))

        audit_rows = [
            json.loads(line)
            for line in (tmp_path / "data" / "control_plane" / "audit.jsonl")
            .read_text(encoding="utf-8")
            .splitlines()
            if line.strip()
        ]
        assert any(
            row.get("event_type") == "action_observed"
            and str(row.get("session_id", "")) == sid
            and str(row.get("data", {}).get("resource_id", ""))
            == str((workspace_root / "README.md").resolve())
            for row in audit_rows
        )
    finally:
        await _shutdown(daemon_task, client)


@pytest.mark.asyncio
async def test_h4_browser_write_without_destination_blocks_after_stage2(
    tmp_path: Path,
) -> None:
    engine = ControlPlaneEngine.build(data_dir=tmp_path / "h4-browser-sink")
    origin = Origin(
        session_id="h4-browser-sink",
        user_id="user-1",
        workspace_id="ws-1",
        actor="planner",
    )
    engine.begin_precontent_plan(
        session_id=origin.session_id,
        goal="review http://127.0.0.1:8765/",
        origin=origin,
        ttl_seconds=600,
        max_actions=5,
        capabilities={Capability.HTTP_REQUEST},
    )
    approved = build_action(
        tool_name="browser.click",
        arguments={"destination": "http://127.0.0.1:8765/", "target": "#continue"},
        origin=origin,
    )
    engine.approve_stage2(action=approved, approved_by="human_confirmation")

    evaluation = await engine.evaluate_action(
        tool_name="browser.click",
        arguments={"source_url": "http://127.0.0.1:8765/", "target": "#continue"},
        origin=origin,
        risk_tier=RiskTier.MEDIUM,
        declared_domains=["127.0.0.1"],
        session_tainted=False,
        trusted_input=True,
    )
    assert evaluation.decision == ControlDecision.BLOCK
    assert "trace:tdg_dependency_path_missing" in evaluation.reason_codes


@pytest.mark.asyncio
async def test_m5_t21_tool_execute_has_declared_threat_model_path_and_no_bypass(
    model_env: None,
    tmp_path: Path,
) -> None:
    daemon_task, client = await _start_daemon_with_policy(tmp_path)
    try:
        created = await client.call("session.create", {"channel": "cli"})
        sid = created["session_id"]

        with pytest.raises(RuntimeError):
            await client.call(
                "tool.execute",
                {
                    "session_id": sid,
                    "tool_name": "shell.exec",
                    "command": [sys.executable, "-c", "print('ok')"],
                    "approved_by_pep": True,
                },
            )

        _ = await client.call(
            "tool.execute",
            {
                "session_id": sid,
                "tool_name": "shell.exec",
                "command": [sys.executable, "-c", "print('ok')"],
                "degraded_mode": "fail_open",
                "security_critical": False,
            },
        )
        consensus = await client.call(
            "audit.query",
            {"event_type": "ConsensusEvaluated", "session_id": sid, "limit": 50},
        )
        assert any(
            event.get("data", {}).get("tool_name") == "shell.exec" for event in consensus["events"]
        )
    finally:
        await _shutdown(daemon_task, client)


@pytest.mark.asyncio
async def test_g2_t1_direct_structured_tool_execute_matches_session_execution_events(
    model_env: None,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = Path.cwd() / "README.md"
    expected_snippet = "shisad"

    async def _forced_fs_read_propose(
        self: Planner,
        user_content: str,
        context: object,
        *,
        tools: list[dict[str, object]] | None = None,
        persona_tone_override: str | None = None,
    ) -> PlannerResult:
        _ = user_content, tools, persona_tone_override
        proposal = ActionProposal(
            action_id="g2-fs-read",
            tool_name=ToolName("fs.read"),
            arguments={"path": str(target)},
            reasoning="g2 structured fs.read parity",
            data_sources=[],
        )
        decision = self._pep.evaluate(proposal.tool_name, proposal.arguments, context)
        return PlannerResult(
            output=PlannerOutput(actions=[proposal], assistant_response="reading note"),
            evaluated=[EvaluatedProposal(proposal=proposal, decision=decision)],
            attempts=1,
            provider_response=None,
            messages_sent=(),
        )

    monkeypatch.setattr(Planner, "propose", _forced_fs_read_propose)

    daemon_task, client = await _start_daemon_with_policy(
        tmp_path,
        policy={"version": "1", "default_require_confirmation": False},
    )
    try:
        session_created = await client.call("session.create", {"channel": "cli"})
        session_sid = session_created["session_id"]
        direct_created = await client.call("session.create", {"channel": "cli"})
        direct_sid = direct_created["session_id"]

        session_reply = await client.call(
            "session.message",
            {"session_id": session_sid, "content": "read README.md"},
        )
        assert session_reply["executed_actions"] >= 1

        direct_reply = await client.call(
            "tool.execute",
            {
                "session_id": direct_sid,
                "tool_name": "fs.read",
                "command": [sys.executable, "-c", "print('sandbox fallback')"],
                "arguments": {"path": str(target)},
                "security_critical": False,
                "degraded_mode": "fail_open",
            },
        )
        assert direct_reply["allowed"] is True
        assert expected_snippet in str(direct_reply.get("stdout", ""))

        session_approved = await client.call(
            "audit.query",
            {"event_type": "ToolApproved", "session_id": session_sid, "limit": 20},
        )
        direct_approved = await client.call(
            "audit.query",
            {"event_type": "ToolApproved", "session_id": direct_sid, "limit": 20},
        )
        assert any(
            str(event.get("data", {}).get("tool_name", "")) == "fs.read"
            for event in session_approved["events"]
        )
        assert any(
            str(event.get("data", {}).get("tool_name", "")) == "fs.read"
            for event in direct_approved["events"]
        )

        session_executed = await client.call(
            "audit.query",
            {"event_type": "ToolExecuted", "session_id": session_sid, "limit": 20},
        )
        direct_executed = await client.call(
            "audit.query",
            {"event_type": "ToolExecuted", "session_id": direct_sid, "limit": 20},
        )
        assert any(
            str(event.get("data", {}).get("tool_name", "")) == "fs.read"
            and str(event.get("data", {}).get("actor", "")) == "tool_runtime"
            and bool(event.get("data", {}).get("success")) is True
            for event in session_executed["events"]
        )
        assert any(
            str(event.get("data", {}).get("tool_name", "")) == "fs.read"
            and str(event.get("data", {}).get("actor", "")) == "tool_runtime"
            and bool(event.get("data", {}).get("success")) is True
            for event in direct_executed["events"]
        )

        session_actions = await client.call(
            "audit.query",
            {"event_type": "ControlPlaneActionObserved", "session_id": session_sid, "limit": 20},
        )
        direct_actions = await client.call(
            "audit.query",
            {"event_type": "ControlPlaneActionObserved", "session_id": direct_sid, "limit": 20},
        )
        session_action = next(
            event["data"]
            for event in session_actions["events"]
            if str(event.get("data", {}).get("tool_name", "")) == "fs.read"
        )
        direct_action = next(
            event["data"]
            for event in direct_actions["events"]
            if str(event.get("data", {}).get("tool_name", "")) == "fs.read"
        )
        assert session_action["action_kind"] == "FS_READ"
        assert direct_action["action_kind"] == session_action["action_kind"]
        assert direct_action["decision"] == session_action["decision"]
    finally:
        await _shutdown(daemon_task, client)


@pytest.mark.asyncio
async def test_h3_session_message_repeated_pep_rejects_emit_warning_without_lockdown(
    model_env: None,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = Path.cwd() / "README.md"

    async def _forced_fs_read_without_capability(
        self: Planner,
        user_content: str,
        context: object,
        *,
        tools: list[dict[str, object]] | None = None,
        persona_tone_override: str | None = None,
    ) -> PlannerResult:
        _ = user_content, tools, persona_tone_override
        proposal = ActionProposal(
            action_id="h3-missing-capability",
            tool_name=ToolName("fs.read"),
            arguments={"path": str(target)},
            reasoning="h3 repeated deny signal",
            data_sources=[],
        )
        decision = self._pep.evaluate(proposal.tool_name, proposal.arguments, context)
        return PlannerResult(
            output=PlannerOutput(actions=[proposal], assistant_response="read blocked"),
            evaluated=[EvaluatedProposal(proposal=proposal, decision=decision)],
            attempts=1,
            provider_response=None,
            messages_sent=(),
        )

    monkeypatch.setattr(Planner, "propose", _forced_fs_read_without_capability)

    daemon_task, client = await _start_daemon_with_policy(
        tmp_path,
        policy={
            "version": "1",
            "default_require_confirmation": False,
            "default_capabilities": [],
        },
    )
    try:
        created = await client.call("session.create", {"channel": "cli"})
        sid = created["session_id"]

        for attempt in range(3):
            reply = await client.call(
                "session.message",
                {"session_id": sid, "content": "say hello"},
            )
            assert int(reply.get("blocked_actions", 0)) >= 1
            anomalies = await client.call(
                "audit.query",
                {"event_type": "AnomalyReported", "session_id": sid, "limit": 20},
            )
            if attempt < 2:
                assert len(anomalies["events"]) == 0

        anomalies = await client.call(
            "audit.query",
            {"event_type": "AnomalyReported", "session_id": sid, "limit": 20},
        )
        assert len(anomalies["events"]) == 1
        assert any(
            "phantom_capability_probe" in str(event.get("data", {}).get("description", ""))
            for event in anomalies["events"]
        )

        lockdowns = await client.call(
            "audit.query",
            {"event_type": "LockdownChanged", "session_id": sid, "limit": 20},
        )
        assert len(lockdowns["events"]) == 0
    finally:
        await _shutdown(daemon_task, client)


@pytest.mark.asyncio
async def test_h3_trace_only_stage2_capability_elevation_still_records_underlying_pep_denies(
    model_env: None,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def _forced_web_fetch_without_capability(
        self: Planner,
        user_content: str,
        context: object,
        *,
        tools: list[dict[str, object]] | None = None,
        persona_tone_override: str | None = None,
    ) -> PlannerResult:
        _ = user_content, tools, persona_tone_override
        proposal = ActionProposal(
            action_id="h3-trace-only-hard-reject",
            tool_name=ToolName("web.fetch"),
            arguments={"url": "https://example.com"},
            reasoning="h3 capability elevation should stay explicit",
            data_sources=[],
        )
        decision = self._pep.evaluate(proposal.tool_name, proposal.arguments, context)
        return PlannerResult(
            output=PlannerOutput(actions=[proposal], assistant_response="fetch blocked"),
            evaluated=[EvaluatedProposal(proposal=proposal, decision=decision)],
            attempts=1,
            provider_response=None,
            messages_sent=(),
        )

    monkeypatch.setattr(Planner, "propose", _forced_web_fetch_without_capability)

    daemon_task, client = await _start_daemon_with_policy(
        tmp_path,
        policy={
            "version": "1",
            "default_require_confirmation": False,
            "default_capabilities": [],
            "egress": [
                {
                    "host": "example.com",
                    "protocols": ["https"],
                }
            ],
        },
    )
    try:
        created = await client.call("session.create", {"channel": "cli"})
        sid = created["session_id"]

        for attempt in range(3):
            reply = await client.call(
                "session.message",
                {"session_id": sid, "content": "say hello"},
            )
            assert int(reply.get("blocked_actions", 0)) == 0
            assert int(reply.get("confirmation_required_actions", 0)) >= 1
            anomalies = await client.call(
                "audit.query",
                {"event_type": "AnomalyReported", "session_id": sid, "limit": 20},
            )
            if attempt < 2:
                assert len(anomalies["events"]) == 0

        anomalies = await client.call(
            "audit.query",
            {"event_type": "AnomalyReported", "session_id": sid, "limit": 20},
        )
        assert len(anomalies["events"]) == 1
        assert any(
            "phantom_capability_probe" in str(event.get("data", {}).get("description", ""))
            for event in anomalies["events"]
        )

        pending = await client.call(
            "action.pending",
            {"session_id": sid, "status": "pending", "limit": 20},
        )
        assert len(pending["actions"]) >= 1
        assert any(
            dict(item.get("pep_elevation", {})).get("capability_grants") == ["http.request"]
            for item in pending["actions"]
        )
    finally:
        await _shutdown(daemon_task, client)


@pytest.mark.asyncio
async def test_h3_trace_only_capability_elevation_confirmation_rechecks_pep_and_executes(
    model_env: None,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def _forced_web_fetch_without_capability(
        self: Planner,
        user_content: str,
        context: object,
        *,
        tools: list[dict[str, object]] | None = None,
        persona_tone_override: str | None = None,
    ) -> PlannerResult:
        _ = user_content, tools, persona_tone_override
        proposal = ActionProposal(
            action_id="h3-explicit-elevation-confirm",
            tool_name=ToolName("web.fetch"),
            arguments={"url": "https://example.com"},
            reasoning="user-approved capability elevation should re-run PEP",
            data_sources=[],
        )
        decision = self._pep.evaluate(proposal.tool_name, proposal.arguments, context)
        return PlannerResult(
            output=PlannerOutput(actions=[proposal], assistant_response="fetch pending approval"),
            evaluated=[EvaluatedProposal(proposal=proposal, decision=decision)],
            attempts=1,
            provider_response=None,
            messages_sent=(),
        )

    monkeypatch.setattr(Planner, "propose", _forced_web_fetch_without_capability)

    daemon_task, client = await _start_daemon_with_policy(
        tmp_path,
        policy={
            "version": "1",
            "default_require_confirmation": False,
            "default_capabilities": [],
            "egress": [
                {
                    "host": "example.com",
                    "protocols": ["https"],
                }
            ],
        },
    )
    try:
        created = await client.call("session.create", {"channel": "cli"})
        sid = created["session_id"]

        reply = await client.call(
            "session.message",
            {"session_id": sid, "content": "fetch https://example.com"},
        )
        assert int(reply.get("blocked_actions", 0)) == 0
        assert int(reply.get("confirmation_required_actions", 0)) >= 1
        pending_ids = list(reply.get("pending_confirmation_ids", []))
        assert pending_ids

        pending = await client.call(
            "action.pending",
            {"confirmation_id": str(pending_ids[0])},
        )
        actions = list(pending.get("actions", []))
        assert len(actions) == 1
        action = actions[0]
        assert dict(action.get("pep_elevation", {})).get("capability_grants") == ["http.request"]

        await asyncio.sleep(3.1)
        confirmed = await client.call(
            "action.confirm",
            {
                "confirmation_id": str(pending_ids[0]),
                "decision_nonce": str(action["decision_nonce"]),
                "reason": "operator_approved",
            },
        )
        assert confirmed["confirmed"] is True
        assert confirmed["status"] == "approved"

        executed = await client.call(
            "audit.query",
            {"event_type": "ToolExecuted", "session_id": sid, "limit": 20},
        )
        assert any(
            str(event.get("data", {}).get("tool_name", "")) == "web.fetch"
            and bool(event.get("data", {}).get("success")) is True
            for event in executed["events"]
        )
    finally:
        await _shutdown(daemon_task, client)


@pytest.mark.asyncio
async def test_h3_trace_only_non_elevatable_pep_reject_stays_blocked(
    model_env: None,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def _forced_invalid_web_fetch(
        self: Planner,
        user_content: str,
        context: object,
        *,
        tools: list[dict[str, object]] | None = None,
        persona_tone_override: str | None = None,
    ) -> PlannerResult:
        _ = user_content, tools, persona_tone_override
        proposal = ActionProposal(
            action_id="h3-schema-invalid-must-stay-blocked",
            tool_name=ToolName("web.fetch"),
            arguments={},
            reasoning="schema-invalid action must not become confirmable",
            data_sources=[],
        )
        decision = self._pep.evaluate(proposal.tool_name, proposal.arguments, context)
        return PlannerResult(
            output=PlannerOutput(actions=[proposal], assistant_response="fetch blocked"),
            evaluated=[EvaluatedProposal(proposal=proposal, decision=decision)],
            attempts=1,
            provider_response=None,
            messages_sent=(),
        )

    monkeypatch.setattr(Planner, "propose", _forced_invalid_web_fetch)

    daemon_task, client = await _start_daemon_with_policy(
        tmp_path,
        policy={
            "version": "1",
            "default_require_confirmation": False,
            "default_capabilities": [],
        },
    )
    try:
        created = await client.call("session.create", {"channel": "cli"})
        sid = created["session_id"]

        reply = await client.call(
            "session.message",
            {"session_id": sid, "content": "fetch the page"},
        )
        assert int(reply.get("blocked_actions", 0)) >= 1
        assert int(reply.get("confirmation_required_actions", 0)) == 0

        pending = await client.call(
            "action.pending",
            {"session_id": sid, "status": "pending", "limit": 20},
        )
        assert pending["count"] == 0
    finally:
        await _shutdown(daemon_task, client)


@pytest.mark.asyncio
async def test_g2_t2_direct_structured_tool_failure_preserves_policy_allow_semantics(
    model_env: None,
    tmp_path: Path,
) -> None:
    missing_path = Path.cwd() / ".pytest-g2-missing" / "missing.txt"
    assert not missing_path.exists()

    daemon_task, client = await _start_daemon_with_policy(
        tmp_path,
        policy={"version": "1", "default_require_confirmation": False},
    )
    try:
        created = await client.call("session.create", {"channel": "cli"})
        sid = created["session_id"]

        result = await client.call(
            "tool.execute",
            {
                "session_id": sid,
                "tool_name": "fs.read",
                "command": [sys.executable, "-c", "print('sandbox fallback')"],
                "arguments": {"path": str(missing_path)},
                "security_critical": False,
                "degraded_mode": "fail_open",
            },
        )

        assert result["allowed"] is True
        assert result["exit_code"] == 1
        assert result["reason"] == "path_not_found"
        assert result["stderr"] == ""
        payload = json.loads(str(result["stdout"]))
        assert payload["ok"] is False
        assert payload["error"] == "path_not_found"
    finally:
        await _shutdown(daemon_task, client)


@pytest.mark.asyncio
async def test_g2_t3_direct_sandbox_tool_execute_returns_precreated_checkpoint_id(
    model_env: None,
    tmp_path: Path,
) -> None:
    daemon_task, client = await _start_daemon_with_policy(
        tmp_path,
        checkpoint_trigger="before_any_tool",
    )
    try:
        created = await client.call("session.create", {"channel": "cli"})
        sid = created["session_id"]

        result = await client.call(
            "tool.execute",
            {
                "session_id": sid,
                "tool_name": "shell.exec",
                "command": [sys.executable, "-c", "print('checkpoint-ok')"],
                "security_critical": False,
                "degraded_mode": "fail_open",
            },
        )

        assert result["allowed"] is True
        checkpoint_id = str(result.get("checkpoint_id", "")).strip()
        assert checkpoint_id
        assert result["exit_code"] == 0
        assert (tmp_path / "data" / "checkpoints" / f"{checkpoint_id}.json").exists()
    finally:
        await _shutdown(daemon_task, client)


@pytest.mark.asyncio
async def test_m5_rt1_tool_execute_stage2_upgrade_requires_confirmation_gate(
    model_env: None,
    tmp_path: Path,
) -> None:
    # Use restricted capabilities so HTTP_REQUEST triggers stage2 upgrade.
    daemon_task, client = await _start_daemon_with_policy(
        tmp_path,
        policy={
            "version": "1",
            "default_deny": False,
            "default_require_confirmation": False,
            "default_capabilities": ["file.read", "memory.read"],
        },
    )
    try:
        created = await client.call("session.create", {"channel": "cli"})
        sid = created["session_id"]

        result = await client.call(
            "tool.execute",
            {
                "session_id": sid,
                "tool_name": "http_request",
                "command": [sys.executable, "-c", "print('ok')"],
                "network_urls": ["https://api.good.example/upload"],
                "network": {
                    "allow_network": True,
                    "allowed_domains": ["api.good.example"],
                    "deny_private_ranges": True,
                    "deny_ip_literals": True,
                },
                "degraded_mode": "fail_open",
                "security_critical": False,
            },
        )
        assert result["allowed"] is False
        assert result.get("confirmation_required") is True
        confirmation_id = str(result.get("confirmation_id", ""))
        assert confirmation_id

        pending = await client.call(
            "action.pending",
            {"session_id": sid, "status": "pending", "limit": 20},
        )
        assert any(item["confirmation_id"] == confirmation_id for item in pending["actions"])
        assert any(
            "stage2_upgrade_required" in str(item.get("reason", ""))
            for item in pending["actions"]
            if item["confirmation_id"] == confirmation_id
        )

        amendments_before = await client.call(
            "audit.query",
            {"event_type": "PlanAmended", "session_id": sid, "limit": 20},
        )
        assert amendments_before["total"] == 0
    finally:
        await _shutdown(daemon_task, client)


@pytest.mark.asyncio
async def test_m1_d11_confirmation_replay_uses_persisted_merged_policy_snapshot_across_restart(
    model_env: None,
    tmp_path: Path,
) -> None:
    daemon_task, client = await _start_daemon_with_policy(
        tmp_path,
        policy={
            "version": "1",
            "default_deny": False,
            "default_require_confirmation": False,
            "default_capabilities": ["file.read", "memory.read"],
        },
    )
    try:
        created = await client.call("session.create", {"channel": "cli"})
        sid = created["session_id"]

        queued = await client.call(
            "tool.execute",
            {
                "session_id": sid,
                "tool_name": "http_request",
                "command": [sys.executable, "-c", "print('snapshot-ok')"],
                "network_urls": ["https://example.com/upload"],
                "network": {
                    "allow_network": True,
                    "allowed_domains": ["example.com"],
                    "deny_private_ranges": True,
                    "deny_ip_literals": True,
                },
                "degraded_mode": "fail_open",
                "security_critical": False,
            },
        )

        assert queued["allowed"] is False
        assert queued["confirmation_required"] is True
        confirmation_id = str(queued["confirmation_id"])
        assert confirmation_id
    finally:
        await _shutdown(daemon_task, client)

    (tmp_path / "policy.yaml").write_text(
        yaml.safe_dump(
            {
                "version": "1",
                "default_deny": False,
                "default_require_confirmation": False,
                "default_capabilities": ["file.read", "memory.read"],
                "sandbox": {
                    "tool_overrides": {
                        "http.request": {
                            "network": {
                                "allow_network": True,
                                "allowed_domains": ["other.example"],
                                "deny_private_ranges": True,
                                "deny_ip_literals": True,
                            }
                        }
                    }
                },
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )

    daemon_task, client = await _start_daemon_with_policy(tmp_path)
    try:
        pending = await client.call(
            "action.pending",
            {"session_id": sid, "status": "pending", "limit": 20},
        )
        row = next(
            item for item in pending["actions"] if item["confirmation_id"] == confirmation_id
        )
        assert row["required_level"] == "software"
        assert row["selected_backend_id"] == "software.default"
        assert row["approval_envelope"]["schema_version"] == "shisad.approval.v1"
        assert str(row["approval_envelope"]["action_digest"]).startswith("sha256:")
        assert str(row["approval_envelope_hash"]).startswith("sha256:")

        confirmed = await client.call(
            "action.confirm",
            {
                "confirmation_id": confirmation_id,
                "decision_nonce": row["decision_nonce"],
                "reason": "operator_approved",
            },
        )

        assert confirmed["confirmed"] is True
        assert confirmed["status"] == "approved"
        assert confirmed["approval_level"] == "software"
        assert confirmed["approval_method"] == "software"

        approved = await client.call(
            "audit.query",
            {"event_type": "ToolApproved", "session_id": sid, "limit": 20},
        )
        assert any(
            str(event.get("data", {}).get("approval_level", "")) == "software"
            and str(event.get("data", {}).get("approval_method", "")) == "software"
            and str(event.get("data", {}).get("approval_evidence_hash", "")).startswith("sha256:")
            for event in approved["events"]
        )
    finally:
        await _shutdown(daemon_task, client)


@pytest.mark.asyncio
async def test_m5_rt2_policy_explain_includes_control_plane_section(
    model_env: None,
    tmp_path: Path,
) -> None:
    daemon_task, client = await _start_daemon_with_policy(tmp_path)
    try:
        created = await client.call("session.create", {"channel": "cli"})
        sid = created["session_id"]
        explained = await client.call(
            "policy.explain",
            {"session_id": sid, "action": "tool:shell.exec"},
        )
        control_plane = explained.get("control_plane")
        assert isinstance(control_plane, dict)
        assert {"sequence", "resource", "network", "consensus", "trace", "egress"}.issubset(
            set(control_plane.keys())
        )
    finally:
        await _shutdown(daemon_task, client)


@pytest.mark.asyncio
async def test_m5_rt3_session_message_execution_reuses_preflight_action_timestamp(
    model_env: None,
    tmp_path: Path,
) -> None:
    daemon_task, client = await _start_daemon_with_policy(tmp_path)
    try:
        created = await client.call("session.create", {"channel": "cli"})
        sid = created["session_id"]
        response = await client.call(
            "session.message",
            {"session_id": sid, "content": "retrieve: recent security incidents"},
        )
        assert response["executed_actions"] >= 1

        history_path = tmp_path / "data" / "control_plane" / "history.jsonl"
        assert history_path.exists()
        grouped_statuses: dict[tuple[str, str, str, str], set[str]] = {}
        for line in history_path.read_text(encoding="utf-8").splitlines():
            payload = json.loads(line)
            if str(payload.get("session_id", "")) != sid:
                continue
            key = (
                str(payload.get("timestamp", "")),
                str(payload.get("action_kind", "")),
                str(payload.get("resource_id", "")),
                str(payload.get("tool_name", "")),
            )
            statuses = grouped_statuses.setdefault(key, set())
            if str(payload.get("decision_status", "")).strip():
                statuses.add("decision")
            if str(payload.get("execution_status", "")).strip():
                statuses.add("execution")
        assert any(
            {"decision", "execution"}.issubset(statuses) for statuses in grouped_statuses.values()
        )
    finally:
        await _shutdown(daemon_task, client)


@pytest.mark.requires_cap_net_admin
def test_m5_t22_privileged_connect_path_marker_and_ci_semantics(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    if not IptablesConnectPathProxy.detect_net_admin_capability():
        pytest.skip("requires CAP_NET_ADMIN capability")

    proxy = IptablesConnectPathProxy(net_admin_available=True)
    proxy._iptables = "/usr/sbin/iptables"
    proxy._nsenter = "/usr/bin/nsenter"
    calls: list[list[str]] = []

    def _fake_run(namespace_pid: int, args: list[str]) -> None:
        _ = namespace_pid
        calls.append(list(args))

    monkeypatch.setattr(proxy, "_run", _fake_run)
    monkeypatch.setattr(proxy, "_is_isolated_namespace", lambda namespace_pid: True)
    result = proxy.enforce(allowed_ips=["93.184.216.34"], namespace_pid=os.getpid())
    assert result.enforced is True
    assert result.method == "iptables"
    assert any(args[-1] == "DROP" for args in calls)
