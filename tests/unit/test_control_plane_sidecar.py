"""H1 control-plane sidecar process boundary coverage."""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import signal
import sys

import pytest

from shisad.core.api.transport import ControlClient, JsonRpcCallError
from shisad.core.types import Capability
from shisad.security.control_plane.schema import Origin, RiskTier, build_action
from shisad.security.control_plane.sidecar import (
    ControlPlaneRpcError,
    ControlPlaneUnavailableError,
    start_control_plane_sidecar,
)


def _clear_remote_provider_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SHISA_API_KEY", raising=False)
    monkeypatch.delenv("SHISAD_MODEL_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    monkeypatch.setenv("SHISAD_MODEL_REMOTE_ENABLED", "false")
    monkeypatch.setenv("SHISAD_MODEL_MONITOR_REMOTE_ENABLED", "false")


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
