"""H1 control-plane sidecar process boundary coverage."""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import signal
import sys
from types import SimpleNamespace

import pytest

from shisad.core.api.transport import ControlClient, JsonRpcCallError
from shisad.core.request_context import RequestContext
from shisad.core.types import Capability
from shisad.security.control_plane.consensus import ConsensusDecision
from shisad.security.control_plane.engine import ControlPlaneEngine, ControlPlaneEvaluation
from shisad.security.control_plane.schema import (
    ControlDecision,
    Origin,
    RiskTier,
    build_action,
)
from shisad.security.control_plane.sidecar import (
    ControlPlaneRpcError,
    ControlPlaneSidecarClient,
    ControlPlaneUnavailableError,
    _ControlPlaneSidecarHandlers,
    _EvaluateActionParams,
    _RecordExecutionParams,
    start_control_plane_sidecar,
)
from shisad.security.control_plane.trace import ExecutionTraceVerifier, PlanVerificationResult


def _clear_remote_provider_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SHISA_API_KEY", raising=False)
    monkeypatch.delenv("SHISAD_MODEL_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    monkeypatch.setenv("SHISAD_MODEL_REMOTE_ENABLED", "false")
    monkeypatch.setenv("SHISAD_MODEL_MONITOR_REMOTE_ENABLED", "false")


@pytest.mark.parametrize("failed_trace_write", [1, 2])
@pytest.mark.parametrize("replace_plan_before_replay", [False, True])
@pytest.mark.asyncio
async def test_f2_sidecar_handler_replays_interrupted_trace_accounting(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
    failed_trace_write: int,
    replace_plan_before_replay: bool,
) -> None:
    data_dir = tmp_path / (
        f"cp-f2-sidecar-trace-{failed_trace_write}-{replace_plan_before_replay}"
    )
    engine = ControlPlaneEngine.build(data_dir=data_dir, workspace_roots=[tmp_path])
    origin = Origin(
        session_id=(
            f"sess-f2-sidecar-trace-{failed_trace_write}-{replace_plan_before_replay}"
        ),
        user_id="alice",
        workspace_id="ws-f2",
        actor="recovery",
    )
    original_plan_hash = engine.begin_precontent_plan(
        session_id=origin.session_id,
        goal=f"read {tmp_path / 'source.txt'}",
        origin=origin,
        ttl_seconds=300,
        max_actions=5,
        capabilities={Capability.FILE_READ},
    )
    action = build_action(
        tool_name="file.read",
        arguments={"path": str(tmp_path / "source.txt")},
        origin=origin,
        workspace_roots=[tmp_path],
    )
    handlers = _ControlPlaneSidecarHandlers(engine=engine)
    verifier = engine._trace_verifier
    real_persist = verifier._persist
    trace_writes = 0

    def _fail_one_trace_write() -> None:
        nonlocal trace_writes
        trace_writes += 1
        if trace_writes == failed_trace_write:
            raise OSError("simulated sidecar trace persistence interruption")
        real_persist()

    monkeypatch.setattr(verifier, "_persist", _fail_one_trace_write)
    idempotency_key = (
        f"f2-sidecar-trace-{failed_trace_write}-{replace_plan_before_replay}"
    )
    params = _RecordExecutionParams(
        action=action,
        success=True,
        idempotency_key=idempotency_key,
    )
    with pytest.raises(OSError, match="sidecar trace persistence interruption"):
        await handlers.handle_record_execution(params, RequestContext())

    if replace_plan_before_replay:
        engine.begin_precontent_plan(
            session_id=origin.session_id,
            goal=f"read {tmp_path / 'replacement.txt'}",
            origin=origin,
            ttl_seconds=300,
            max_actions=5,
            capabilities={Capability.FILE_READ},
        )

    await handlers.handle_record_execution(params, RequestContext())

    reloaded = ExecutionTraceVerifier(
        storage_path=data_dir / "control_plane" / "plans.json",
        workspace_roots=[tmp_path],
    )
    plan = reloaded.active_plan(origin.session_id)
    assert plan is not None
    if replace_plan_before_replay:
        assert plan.plan_hash != original_plan_hash
        assert plan.executed_actions == 0
        assert set(action.resource_ids).isdisjoint(plan.reachable_resources)
    else:
        assert plan.executed_actions == 1
        assert set(action.resource_ids).issubset(plan.reachable_resources)
    execution_rows = [
        json.loads(line)
        for line in (data_dir / "control_plane" / "history.jsonl")
        .read_text(encoding="utf-8")
        .splitlines()
        if line.strip()
    ]
    assert len(execution_rows) == 1
    assert execution_rows[0]["idempotency_key"] == idempotency_key
    assert execution_rows[0]["trace_plan_hash"] == original_plan_hash


@pytest.mark.asyncio
async def test_gh33_control_plane_sidecar_client_serializes_monitor_arguments(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}
    client = ControlPlaneSidecarClient(tmp_path / "control.sock")

    async def _fake_call(
        method: str,
        params: dict[str, object],
        result_model: object,
        *,
        timeout_seconds: float | None = None,
    ) -> object:
        _ = (result_model, timeout_seconds)
        captured["method"] = method
        captured["params"] = params
        return SimpleNamespace(evaluation="ok")

    monkeypatch.setattr(client, "_call", _fake_call)

    result = await client.evaluate_action(
        tool_name="shell.exec",
        arguments={"command": ["curl", "https://secret.example/upload"]},
        monitor_arguments={},
        origin=Origin(
            session_id="sess-gh33-sidecar-client",
            user_id="alice",
            workspace_id="ws-gh33",
            actor="planner",
        ),
        risk_tier=RiskTier.HIGH,
        declared_domains=[],
        session_tainted=True,
        trusted_input=True,
        raw_user_text="[sensitive text redacted]",
    )

    assert result == "ok"
    assert captured["method"] == "control_plane.evaluate_action"
    assert captured["params"]["arguments"] == {"command": ["curl", "https://secret.example/upload"]}
    assert captured["params"]["monitor_arguments"] == {}


class _MonitorArgumentCaptureEngine:
    def __init__(self) -> None:
        self.evaluate_kwargs: dict[str, object] = {}

    async def evaluate_action(self, **kwargs: object) -> ControlPlaneEvaluation:
        self.evaluate_kwargs = dict(kwargs)
        action = build_action(
            tool_name=str(kwargs["tool_name"]),
            arguments=dict(kwargs["arguments"]),
            origin=kwargs["origin"],
            risk_tier=kwargs["risk_tier"],
        )
        return ControlPlaneEvaluation(
            action=action,
            trace_result=PlanVerificationResult(
                allowed=True,
                reason_code="trace:allowed",
            ),
            consensus=ConsensusDecision(
                decision=ControlDecision.ALLOW,
                risk_tier=RiskTier.LOW,
            ),
            decision=ControlDecision.ALLOW,
            reason_codes=[],
        )


@pytest.mark.asyncio
async def test_gh33_control_plane_sidecar_handler_forwards_monitor_arguments() -> None:
    engine = _MonitorArgumentCaptureEngine()
    handlers = _ControlPlaneSidecarHandlers(engine=engine)  # type: ignore[arg-type]
    origin = Origin(
        session_id="sess-gh33-sidecar-handler",
        user_id="alice",
        workspace_id="ws-gh33",
        actor="planner",
    )

    result = await handlers.handle_evaluate_action(
        _EvaluateActionParams(
            tool_name="shell.exec",
            arguments={"command": ["curl", "https://secret.example/upload"]},
            monitor_arguments={},
            origin=origin,
            risk_tier=RiskTier.HIGH,
            declared_domains=[],
            session_tainted=True,
            trusted_input=True,
            raw_user_text="[sensitive text redacted]",
        ),
        RequestContext(),
    )

    assert engine.evaluate_kwargs["arguments"] == {
        "command": ["curl", "https://secret.example/upload"]
    }
    assert engine.evaluate_kwargs["monitor_arguments"] == {}
    assert result["evaluation"]["action"]["network_hosts"] == ["secret.example"]


@pytest.mark.asyncio
async def test_h1_control_plane_sidecar_round_trips_evaluation_and_audit_writes(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear_remote_provider_env(monkeypatch)
    handle = await start_control_plane_sidecar(
        data_dir=tmp_path / "data",
        policy_path=tmp_path / "policy.yaml",
    )
    try:
        origin = Origin(
            session_id="sess-h1",
            user_id="alice",
            workspace_id="ws-h1",
            actor="planner",
        )
        plan_hash = await handle.client.begin_precontent_plan(
            session_id="sess-h1",
            goal="fetch https://example.com",
            origin=origin,
            ttl_seconds=300,
            max_actions=5,
            capabilities={Capability.HTTP_REQUEST},
        )
        evaluation = await handle.client.evaluate_action(
            tool_name="web.fetch",
            arguments={"url": "https://example.com"},
            origin=origin,
            risk_tier=RiskTier.LOW,
            declared_domains=["example.com"],
            session_tainted=False,
            trusted_input=True,
            raw_user_text="fetch example.com",
        )
        assert await handle.client.active_plan_hash("sess-h1") == plan_hash
        assert evaluation.action.tool_name == "web.fetch"
        assert evaluation.action.origin.session_id == "sess-h1"
        assert evaluation.trace_result.allowed is True

        await handle.client.record_execution(action=evaluation.action, success=True)

        history_path = tmp_path / "data" / "control_plane" / "history.jsonl"
        history_rows = [
            json.loads(line)
            for line in history_path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        assert history_rows[0]["timestamp"] == history_rows[1]["timestamp"]

        audit_path = tmp_path / "data" / "control_plane" / "audit.jsonl"
        assert audit_path.exists()
        event_types = [
            json.loads(line)["event_type"]
            for line in audit_path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        assert "plan_committed" in event_types
        assert "action_observed" in event_types
    finally:
        await handle.close()

    assert handle.process.returncode is not None
    assert not handle.socket_path.exists()


@pytest.mark.asyncio
async def test_h1_control_plane_sidecar_respects_overridden_startup_timeout(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear_remote_provider_env(monkeypatch)
    handle = await start_control_plane_sidecar(
        data_dir=tmp_path / "data",
        policy_path=tmp_path / "policy.yaml",
        startup_timeout_seconds=7.25,
    )
    try:
        assert handle.startup_timeout_seconds == pytest.approx(7.25)
        assert await handle.client.ping() is True
    finally:
        await handle.close()


@pytest.mark.asyncio
async def test_u5_control_plane_sidecar_round_trips_operator_owned_cli_metadata(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear_remote_provider_env(monkeypatch)
    handle = await start_control_plane_sidecar(
        data_dir=tmp_path / "data",
        policy_path=tmp_path / "policy.yaml",
    )
    try:
        output_path = tmp_path / "operator-output.txt"
        origin = Origin(
            session_id="sess-u5-operator-cli",
            user_id="alice",
            workspace_id="ws-u5",
            actor="planner",
        )
        await handle.client.begin_precontent_plan(
            session_id=origin.session_id,
            goal=f"write hello to {output_path}",
            origin=origin,
            ttl_seconds=300,
            max_actions=5,
            capabilities={Capability.FILE_WRITE},
            declared_resource_roots=[str(tmp_path)],
        )

        evaluation = await handle.client.evaluate_action(
            tool_name="fs.write",
            arguments={"path": str(output_path), "content": "hello"},
            origin=origin,
            risk_tier=RiskTier.LOW,
            declared_domains=[],
            session_tainted=False,
            trusted_input=False,
            operator_owned_cli_input=True,
            raw_user_text=f"write hello to {output_path}",
        )

        assert evaluation.trace_result.allowed is True
        assert evaluation.decision == ControlDecision.ALLOW
        vote_reason_codes = [
            reason_code for vote in evaluation.consensus.votes for reason_code in vote.reason_codes
        ]
        assert "action_monitor:clean_operator_cli_intent" in vote_reason_codes
        assert "action_monitor:untrusted_input_side_effect" not in vote_reason_codes
    finally:
        await handle.close()


@pytest.mark.asyncio
async def test_h1_control_plane_sidecar_surfaces_semantic_rpc_errors(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear_remote_provider_env(monkeypatch)
    handle = await start_control_plane_sidecar(
        data_dir=tmp_path / "data",
        policy_path=tmp_path / "policy.yaml",
    )
    try:
        action = (
            await handle.client.evaluate_action(
                tool_name="web.fetch",
                arguments={"url": "https://example.com"},
                origin=Origin(
                    session_id="sess-h1",
                    user_id="alice",
                    workspace_id="ws-h1",
                    actor="planner",
                ),
                risk_tier=RiskTier.LOW,
                declared_domains=["example.com"],
                session_tainted=False,
                trusted_input=True,
                raw_user_text="fetch example.com",
            )
        ).action
        with pytest.raises(ControlPlaneRpcError) as excinfo:
            await handle.client.approve_stage2(
                action=action,
                approved_by="human_confirmation",
            )
        assert excinfo.value.reason_code == "rpc.invalid_params"
        assert "inactive plan" in excinfo.value.message
    finally:
        await handle.close()


@pytest.mark.asyncio
async def test_h1_control_plane_sidecar_fails_closed_after_midrun_exit(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear_remote_provider_env(monkeypatch)
    handle = await start_control_plane_sidecar(
        data_dir=tmp_path / "data",
        policy_path=tmp_path / "policy.yaml",
    )
    try:
        handle.process.kill()
        await handle.process.wait()
        with pytest.raises(ControlPlaneUnavailableError):
            await handle.client.ping()
    finally:
        await handle.close()


@pytest.mark.asyncio
async def test_h1_control_plane_sidecar_rejects_client_when_parent_pid_mismatches(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear_remote_provider_env(monkeypatch)
    socket_path = tmp_path / "data" / "control_plane" / "sidecar.sock"
    socket_path.parent.mkdir(parents=True, exist_ok=True)
    process = await asyncio.create_subprocess_exec(
        sys.executable,
        "-m",
        "shisad.security.control_plane.sidecar",
        "--socket-path",
        str(socket_path),
        "--data-dir",
        str(tmp_path / "data"),
        "--policy-path",
        str(tmp_path / "policy.yaml"),
        "--parent-pid",
        str(os.getpid() + 99999),
    )
    client = ControlClient(socket_path)
    try:
        deadline = asyncio.get_running_loop().time() + 5.0
        last_error: Exception | None = None
        while asyncio.get_running_loop().time() < deadline:
            if process.returncode is not None:
                raise AssertionError(f"sidecar exited early: {process.returncode}") from last_error
            try:
                await client.connect()
                with pytest.raises(JsonRpcCallError) as excinfo:
                    await client.call("control_plane.ping", {})
                assert excinfo.value.reason_code == "rpc.permission_denied"
                return
            except (ConnectionError, FileNotFoundError, OSError) as exc:
                last_error = exc
                await asyncio.sleep(0.05)
            finally:
                with contextlib.suppress(OSError, RuntimeError):
                    await client.close()
        raise AssertionError("sidecar socket never became ready for authorization check")
    finally:
        if process.returncode is None:
            process.send_signal(signal.SIGTERM)
            try:
                await asyncio.wait_for(process.wait(), timeout=5.0)
            except TimeoutError:
                process.kill()
                await process.wait()


@pytest.mark.asyncio
async def test_h3_control_plane_sidecar_round_trips_denied_action_observation(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear_remote_provider_env(monkeypatch)
    handle = await start_control_plane_sidecar(
        data_dir=tmp_path / "data",
        policy_path=tmp_path / "policy.yaml",
    )
    try:
        origin = Origin(
            session_id="sess-h3",
            user_id="alice",
            workspace_id="ws-h3",
            actor="planner",
        )
        findings = []
        for index in range(3):
            findings = await handle.client.observe_denied_action(
                action=build_action(
                    tool_name="file.read",
                    arguments={"path": f"/tmp/h3-{index}.txt"},
                    origin=origin,
                ),
                source="policy_loop",
                reason_code="pep:missing_capabilities",
            )
            if index < 2:
                assert findings == []

        assert len(findings) == 1
        assert findings[0].pattern_name == "phantom_capability_probe"

        audit_path = tmp_path / "data" / "control_plane" / "audit.jsonl"
        audit_rows = [
            json.loads(line)
            for line in audit_path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        event_types = [row["event_type"] for row in audit_rows]
        assert event_types.count("denied_action_observed") == 3
        assert "phantom_action_detected" in event_types
        deny_event = next(
            row for row in audit_rows if row["event_type"] == "denied_action_observed"
        )
        assert deny_event["data"]["reason_code"] == "pep:missing_capabilities"
        assert "reason" not in deny_event["data"]
    finally:
        await handle.close()
