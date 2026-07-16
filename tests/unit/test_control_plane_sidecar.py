"""H1 control-plane sidecar process boundary coverage."""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import signal
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

import shisad.security.control_plane.sidecar as sidecar_module
from shisad.core.api.transport import ControlClient, ControlServer, JsonRpcCallError
from shisad.core.authority import (
    AuthorityClaimError,
    DaemonAuthorityClaim,
    acquire_daemon_authority_claim,
    initialize_claimed_daemon_authorities,
)
from shisad.core.config import DaemonConfig
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
    ControlPlaneSidecarHandle,
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


async def _start_claimed_sidecar(
    *,
    data_dir: Path,
    policy_path: Path,
    startup_timeout_seconds: float = 15.0,
) -> tuple[ControlPlaneSidecarHandle, DaemonAuthorityClaim]:
    config = DaemonConfig(
        data_dir=data_dir,
        socket_path=data_dir / "daemon.sock",
        policy_path=policy_path,
    )
    claim = acquire_daemon_authority_claim(config)
    initialize_claimed_daemon_authorities(config, claim)
    try:
        handle = await start_control_plane_sidecar(
            data_dir=data_dir,
            policy_path=policy_path,
            authority_claim=claim,
            startup_timeout_seconds=startup_timeout_seconds,
        )
    except BaseException:
        claim.release()
        raise
    return handle, claim


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


@pytest.mark.parametrize("failed_trace_write", [1, 2])
@pytest.mark.asyncio
async def test_f2_sidecar_handler_cancels_hashless_uncertain_active_plan(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
    failed_trace_write: int,
) -> None:
    data_dir = tmp_path / f"cp-f2-sidecar-hashless-{failed_trace_write}"
    engine = ControlPlaneEngine.build(data_dir=data_dir, workspace_roots=[tmp_path])
    origin = Origin(
        session_id=f"sess-f2-sidecar-hashless-{failed_trace_write}",
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
    verifier = engine._trace_verifier
    real_persist = verifier._persist
    trace_writes = 0

    def _fail_one_trace_write() -> None:
        nonlocal trace_writes
        trace_writes += 1
        if trace_writes == failed_trace_write:
            raise OSError("simulated legacy sidecar trace interruption")
        real_persist()

    monkeypatch.setattr(verifier, "_persist", _fail_one_trace_write)
    idempotency_key = f"f2-sidecar-hashless-{failed_trace_write}"
    params = _RecordExecutionParams(
        action=action,
        success=True,
        idempotency_key=idempotency_key,
    )
    handlers = _ControlPlaneSidecarHandlers(engine=engine)
    with pytest.raises(OSError, match="legacy sidecar trace interruption"):
        await handlers.handle_record_execution(params, RequestContext())

    history_path = data_dir / "control_plane" / "history.jsonl"
    history_rows = [json.loads(line) for line in history_path.read_text().splitlines()]
    assert history_rows[0].pop("trace_plan_hash") == original_plan_hash
    history_path.write_text(
        "\n".join(json.dumps(row, sort_keys=True) for row in history_rows) + "\n",
        encoding="utf-8",
    )

    restarted = ControlPlaneEngine.build(data_dir=data_dir, workspace_roots=[tmp_path])
    restarted_handlers = _ControlPlaneSidecarHandlers(engine=restarted)
    assert restarted.active_plan_hash(origin.session_id) == original_plan_hash

    await restarted_handlers.handle_record_execution(params, RequestContext())

    assert restarted.active_plan_hash(origin.session_id) == ""
    cancelled = restarted._trace_verifier._plans[origin.session_id]
    assert cancelled.cancelled is True
    assert cancelled.cancelled_reason == "trace_accounting_plan_binding_unavailable"


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
    handle, claim = await _start_claimed_sidecar(
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

        execution_key = "h1-sidecar-execution"
        assert await handle.client.execution_status(idempotency_key=execution_key) == ""
        await handle.client.record_execution(
            action=evaluation.action,
            success=True,
            idempotency_key=execution_key,
        )
        assert (
            await handle.client.execution_status(idempotency_key=execution_key)
            == "success"
        )

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
        claim.release()

    assert handle.process.returncode is not None
    assert not handle.socket_path.exists()


@pytest.mark.asyncio
async def test_h1_control_plane_sidecar_respects_overridden_startup_timeout(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear_remote_provider_env(monkeypatch)
    handle, claim = await _start_claimed_sidecar(
        data_dir=tmp_path / "data",
        policy_path=tmp_path / "policy.yaml",
        startup_timeout_seconds=7.25,
    )
    try:
        assert handle.startup_timeout_seconds == pytest.approx(7.25)
        assert await handle.client.ping() is True
    finally:
        await handle.close()
        claim.release()


@pytest.mark.asyncio
async def test_f3_sidecar_rejects_mismatched_claim_before_target_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear_remote_provider_env(monkeypatch)
    claimed_config = DaemonConfig(
        data_dir=tmp_path / "claimed-data",
        socket_path=tmp_path / "claimed.sock",
        policy_path=tmp_path / "policy.yaml",
    )
    claim = acquire_daemon_authority_claim(claimed_config)
    unclaimed_data = tmp_path / "unclaimed-parent" / "data"
    try:
        with pytest.raises(AuthorityClaimError, match="data root"):
            await start_control_plane_sidecar(
                data_dir=unclaimed_data,
                policy_path=claimed_config.policy_path,
                authority_claim=claim,
            )
        assert not unclaimed_data.parent.exists()
    finally:
        claim.release()


@pytest.mark.asyncio
async def test_f3_sidecar_exec_rejects_wrong_inherited_descriptor_before_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear_remote_provider_env(monkeypatch)
    config = DaemonConfig(
        data_dir=tmp_path / "uninitialized-data",
        socket_path=tmp_path / "daemon.sock",
        policy_path=tmp_path / "policy.yaml",
    )
    claim = acquire_daemon_authority_claim(config)
    lease = claim.duplicate_lease()
    wrong_fd = os.open(lease.record_path, os.O_RDWR)
    try:
        process = await asyncio.create_subprocess_exec(
            sys.executable,
            "-m",
            "shisad.security.control_plane.sidecar",
            "--socket-path",
            str(config.data_dir / "control_plane" / "sidecar.sock"),
            "--data-dir",
            str(config.data_dir),
            "--policy-path",
            str(config.policy_path),
            "--parent-pid",
            str(os.getpid()),
            "--authority-lease-fd",
            str(wrong_fd),
            "--authority-record-path",
            str(lease.record_path),
            pass_fds=(wrong_fd,),
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.PIPE,
        )
        os.close(wrong_fd)
        wrong_fd = -1
        _stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=5)
        assert process.returncode not in {None, 0}
        assert b"lock is not held" in stderr
        assert not config.data_dir.exists()
    finally:
        if wrong_fd >= 0:
            os.close(wrong_fd)
        lease.close()
        claim.release()


@pytest.mark.asyncio
async def test_f3_sidecar_spawn_failure_closes_parent_lease_duplicate(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    lease_closed = 0

    class _Lease:
        fd = 0
        record_path = tmp_path / "claim.json"

        def close(self) -> None:
            nonlocal lease_closed
            lease_closed += 1

    lease = _Lease()
    claim = SimpleNamespace(duplicate_lease=lambda: lease)

    async def _fail_spawn(*_args, **_kwargs):
        raise OSError("spawn failed")

    monkeypatch.setattr(
        sidecar_module,
        "verify_inherited_daemon_authority_lease",
        lambda *_args, **_kwargs: (),
    )
    monkeypatch.setattr(sidecar_module.asyncio, "create_subprocess_exec", _fail_spawn)

    with pytest.raises(OSError, match="spawn failed"):
        await start_control_plane_sidecar(
            data_dir=tmp_path / "data",
            policy_path=tmp_path / "policy.yaml",
            authority_claim=claim,  # type: ignore[arg-type]
        )

    assert lease_closed == 1


@pytest.mark.asyncio
async def test_f3_sidecar_spawn_cancellation_joins_spawned_child_and_closes_duplicate(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    lease_closed = 0
    spawn_started = asyncio.Event()
    allow_spawn = asyncio.Event()
    process_stopped = asyncio.Event()

    class _Lease:
        fd = 0
        record_path = tmp_path / "claim.json"

        def close(self) -> None:
            nonlocal lease_closed
            lease_closed += 1

    class _Process:
        pid = os.getpid()
        returncode: int | None = None

        def terminate(self) -> None:
            self.returncode = -signal.SIGTERM
            process_stopped.set()

        def kill(self) -> None:
            self.returncode = -signal.SIGKILL
            process_stopped.set()

        async def wait(self) -> int:
            await process_stopped.wait()
            assert self.returncode is not None
            return self.returncode

    lease = _Lease()
    process = _Process()
    claim = SimpleNamespace(duplicate_lease=lambda: lease)

    async def _delayed_spawn(*_args, **_kwargs):
        spawn_started.set()
        await allow_spawn.wait()
        return process

    monkeypatch.setattr(
        sidecar_module,
        "verify_inherited_daemon_authority_lease",
        lambda *_args, **_kwargs: (),
    )
    monkeypatch.setattr(sidecar_module.asyncio, "create_subprocess_exec", _delayed_spawn)

    start_task = asyncio.create_task(
        start_control_plane_sidecar(
            data_dir=tmp_path / "data",
            policy_path=tmp_path / "policy.yaml",
            authority_claim=claim,  # type: ignore[arg-type]
        )
    )
    await spawn_started.wait()
    start_task.cancel()
    allow_spawn.set()

    with pytest.raises(asyncio.CancelledError):
        await start_task
    assert process.returncode == -signal.SIGTERM
    assert lease_closed == 1


@pytest.mark.asyncio
async def test_f3_sidecar_readiness_failure_joins_spawned_child(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    lease_closed = 0
    process_stopped = asyncio.Event()

    class _Lease:
        fd = 0
        record_path = tmp_path / "claim.json"

        def close(self) -> None:
            nonlocal lease_closed
            lease_closed += 1

    class _Process:
        pid = os.getpid()
        returncode: int | None = None

        def terminate(self) -> None:
            self.returncode = -signal.SIGTERM
            process_stopped.set()

        def kill(self) -> None:
            self.returncode = -signal.SIGKILL
            process_stopped.set()

        async def wait(self) -> int:
            await process_stopped.wait()
            assert self.returncode is not None
            return self.returncode

    lease = _Lease()
    process = _Process()
    claim = SimpleNamespace(duplicate_lease=lambda: lease)

    async def _spawn(*_args, **_kwargs):
        return process

    async def _fail_readiness(_handle: ControlPlaneSidecarHandle) -> None:
        raise ControlPlaneUnavailableError(reason_code="control_plane.startup_failed")

    monkeypatch.setattr(
        sidecar_module,
        "verify_inherited_daemon_authority_lease",
        lambda *_args, **_kwargs: (),
    )
    monkeypatch.setattr(sidecar_module.asyncio, "create_subprocess_exec", _spawn)
    monkeypatch.setattr(sidecar_module, "_wait_for_sidecar_ready", _fail_readiness)

    with pytest.raises(ControlPlaneUnavailableError):
        await start_control_plane_sidecar(
            data_dir=tmp_path / "data",
            policy_path=tmp_path / "policy.yaml",
            authority_claim=claim,  # type: ignore[arg-type]
        )
    assert process.returncode == -signal.SIGTERM
    assert lease_closed == 1


@pytest.mark.asyncio
async def test_f3_sidecar_readiness_cancellation_joins_spawned_child(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    lease_closed = 0
    readiness_started = asyncio.Event()
    process_stopped = asyncio.Event()

    class _Lease:
        fd = 0
        record_path = tmp_path / "claim.json"

        def close(self) -> None:
            nonlocal lease_closed
            lease_closed += 1

    class _Process:
        pid = os.getpid()
        returncode: int | None = None

        def terminate(self) -> None:
            self.returncode = -signal.SIGTERM
            process_stopped.set()

        def kill(self) -> None:
            self.returncode = -signal.SIGKILL
            process_stopped.set()

        async def wait(self) -> int:
            await process_stopped.wait()
            assert self.returncode is not None
            return self.returncode

    lease = _Lease()
    process = _Process()
    claim = SimpleNamespace(duplicate_lease=lambda: lease)

    async def _spawn(*_args, **_kwargs):
        return process

    async def _wait_forever(_handle: ControlPlaneSidecarHandle) -> None:
        readiness_started.set()
        await asyncio.Event().wait()

    monkeypatch.setattr(
        sidecar_module,
        "verify_inherited_daemon_authority_lease",
        lambda *_args, **_kwargs: (),
    )
    monkeypatch.setattr(sidecar_module.asyncio, "create_subprocess_exec", _spawn)
    monkeypatch.setattr(sidecar_module, "_wait_for_sidecar_ready", _wait_forever)

    start_task = asyncio.create_task(
        start_control_plane_sidecar(
            data_dir=tmp_path / "data",
            policy_path=tmp_path / "policy.yaml",
            authority_claim=claim,  # type: ignore[arg-type]
        )
    )
    await readiness_started.wait()
    start_task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await start_task
    assert process.returncode == -signal.SIGTERM
    assert lease_closed == 1


@pytest.mark.asyncio
async def test_f3_sidecar_close_reaches_process_terminal_before_reraising_cancellation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear_remote_provider_env(monkeypatch)
    handle, claim = await _start_claimed_sidecar(
        data_dir=tmp_path / "data",
        policy_path=tmp_path / "policy.yaml",
    )
    os.kill(handle.process.pid, signal.SIGSTOP)
    close_task = asyncio.create_task(handle.close())
    try:
        deadline = asyncio.get_running_loop().time() + 1
        while handle._close_task is None:
            if asyncio.get_running_loop().time() >= deadline:
                raise AssertionError("sidecar terminal close task did not start")
            await asyncio.sleep(0)
        close_task.cancel()
        await asyncio.sleep(0.05)
        assert not close_task.done()
        assert handle.process.returncode is None

        os.kill(handle.process.pid, signal.SIGCONT)
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(close_task, timeout=3)
        assert handle.process.returncode is not None
    finally:
        with contextlib.suppress(ProcessLookupError):
            os.kill(handle.process.pid, signal.SIGCONT)
        with contextlib.suppress(asyncio.CancelledError):
            await handle.close()
        claim.release()


@pytest.mark.asyncio
async def test_f3_sidecar_close_kills_child_after_termination_timeout(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear_remote_provider_env(monkeypatch)
    handle, claim = await _start_claimed_sidecar(
        data_dir=tmp_path / "data",
        policy_path=tmp_path / "policy.yaml",
    )
    handle.termination_timeout_seconds = 0.05
    os.kill(handle.process.pid, signal.SIGSTOP)
    try:
        await handle.close()
        assert handle.process.returncode == -signal.SIGKILL
    finally:
        with contextlib.suppress(ProcessLookupError):
            os.kill(handle.process.pid, signal.SIGCONT)
        await handle.close()
        claim.release()


@pytest.mark.asyncio
async def test_f3_sidecar_handle_close_does_not_unlink_successor_socket(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear_remote_provider_env(monkeypatch)
    handle, claim = await _start_claimed_sidecar(
        data_dir=tmp_path / "data",
        policy_path=tmp_path / "policy.yaml",
    )
    successor = ControlServer(handle.socket_path)
    try:
        handle.process.kill()
        await handle.process.wait()
        handle.socket_path.unlink()
        await successor.start()
        successor_stat = handle.socket_path.stat()

        await handle.close()

        current_stat = handle.socket_path.stat()
        assert (current_stat.st_dev, current_stat.st_ino) == (
            successor_stat.st_dev,
            successor_stat.st_ino,
        )
    finally:
        await successor.stop()
        await handle.close()
        claim.release()


@pytest.mark.asyncio
async def test_u5_control_plane_sidecar_round_trips_operator_owned_cli_metadata(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear_remote_provider_env(monkeypatch)
    handle, claim = await _start_claimed_sidecar(
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
        claim.release()


@pytest.mark.asyncio
async def test_h1_control_plane_sidecar_surfaces_semantic_rpc_errors(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear_remote_provider_env(monkeypatch)
    handle, claim = await _start_claimed_sidecar(
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
        claim.release()


@pytest.mark.asyncio
async def test_f2_control_plane_sidecar_cancels_exact_stage2_correlation(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear_remote_provider_env(monkeypatch)
    handle, claim = await _start_claimed_sidecar(
        data_dir=tmp_path / "data",
        policy_path=tmp_path / "policy.yaml",
    )
    try:
        origin = Origin(
            session_id="sess-f2-stage2-cancel",
            user_id="alice",
            workspace_id="ws-f2",
            actor="planner",
        )
        previous_hash = await handle.client.begin_precontent_plan(
            session_id=origin.session_id,
            goal="read then send",
            origin=origin,
            ttl_seconds=300,
            max_actions=3,
            capabilities={Capability.FILE_READ},
        )
        action = build_action(
            tool_name="message.send",
            arguments={"recipient": "alice", "content": "done"},
            origin=origin,
            risk_tier=RiskTier.MEDIUM,
            workspace_roots=[tmp_path],
        )
        correlation_id = "confirmation-1:attempt-1"
        amended_hash = await handle.client.approve_stage2(
            action=action,
            approved_by="human_confirmation",
            correlation_id=correlation_id,
            expected_previous_hash=previous_hash,
            execution_idempotency_key="execution:attempt-1:control-plane",
        )

        assert await handle.client.active_plan_hash(origin.session_id) == amended_hash
        assert await handle.client.cancel_stage2(
            session_id=origin.session_id,
            correlation_id=correlation_id,
            expected_plan_hash=amended_hash,
            reason="stage2_ready_transition_failed",
            actor="human_confirmation",
        )
        assert await handle.client.active_plan_hash(origin.session_id) == ""
    finally:
        await handle.close()
        claim.release()


@pytest.mark.asyncio
async def test_h1_control_plane_sidecar_fails_closed_after_midrun_exit(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear_remote_provider_env(monkeypatch)
    handle, claim = await _start_claimed_sidecar(
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
        claim.release()


@pytest.mark.asyncio
async def test_h1_control_plane_sidecar_rejects_client_when_parent_pid_mismatches(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear_remote_provider_env(monkeypatch)
    config = DaemonConfig(
        data_dir=tmp_path / "data",
        socket_path=tmp_path / "data" / "daemon.sock",
        policy_path=tmp_path / "policy.yaml",
    )
    claim = acquire_daemon_authority_claim(config)
    initialize_claimed_daemon_authorities(config, claim)
    socket_path = config.data_dir / "control_plane" / "sidecar.sock"
    socket_path.parent.mkdir(parents=True, exist_ok=True)
    lease = claim.duplicate_lease()
    try:
        process = await asyncio.create_subprocess_exec(
            sys.executable,
            "-m",
            "shisad.security.control_plane.sidecar",
            "--socket-path",
            str(socket_path),
            "--data-dir",
            str(config.data_dir),
            "--policy-path",
            str(config.policy_path),
            "--parent-pid",
            str(os.getpid() + 99999),
            "--authority-lease-fd",
            str(lease.fd),
            "--authority-record-path",
            str(lease.record_path),
            pass_fds=(lease.fd,),
        )
    finally:
        lease.close()
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
        claim.release()


@pytest.mark.asyncio
async def test_h3_control_plane_sidecar_round_trips_denied_action_observation(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear_remote_provider_env(monkeypatch)
    handle, claim = await _start_claimed_sidecar(
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
        claim.release()
