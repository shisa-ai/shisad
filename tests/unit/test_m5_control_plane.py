"""M5 unit coverage for control-plane analyzers, trace, and consensus."""

from __future__ import annotations

import asyncio
import hashlib
import json
from datetime import UTC, datetime, timedelta

import pytest

from shisad.core.events import (
    ControlPlaneActionObserved,
    ControlPlaneNetworkObserved,
    ControlPlaneResourceObserved,
    ProxyRequestEvaluated,
)
from shisad.core.providers.base import Message, ProviderResponse
from shisad.security.control_plane.consensus import (
    ActionMonitorVoter,
    ConsensusInput,
    ConsensusPolicy,
    ConsensusVotingSystem,
    VoteKind,
    VoterDecision,
)
from shisad.security.control_plane.history import ActionHistoryRecord, SessionActionHistoryStore
from shisad.security.control_plane.network import (
    BaselineDatabase,
    NetworkIntelligenceMonitor,
    extract_network_metadata,
)
from shisad.security.control_plane.resource import ResourceAccessMonitor
from shisad.security.control_plane.schema import (
    ActionKind,
    ControlPlaneAction,
    Origin,
    RiskTier,
    build_action,
    infer_action_kind,
    sanitize_metadata_payload,
)
from shisad.security.control_plane.sequence import BehavioralSequenceAnalyzer
from shisad.security.control_plane.trace import (
    ExecutionTraceVerifier,
    PlanStage,
    PlanVerificationResult,
)


def _origin(session_id: str = "s1") -> Origin:
    return Origin(
        session_id=session_id,
        user_id="user-1",
        workspace_id="ws-1",
        actor="planner",
        trust_level="untrusted",
    )


def test_m5_t1_sequence_detects_fs_read_then_egress() -> None:
    history = SessionActionHistoryStore()
    analyzer = BehavioralSequenceAnalyzer()
    origin = _origin()

    read_action = build_action(
        tool_name="file.read",
        arguments={"path": "README.md"},
        origin=origin,
    )
    history.append_action(read_action, decision_status="allow")
    candidate = build_action(
        tool_name="http_request",
        arguments={"url": "https://exfil.example/upload"},
        origin=origin,
        risk_tier=RiskTier.HIGH,
    )

    findings = analyzer.analyze(history=history, candidate_action=candidate)
    assert any(item.pattern_name == "exfil_after_read" for item in findings)


def test_m5_t2_sequence_detects_rapid_fire_pattern() -> None:
    history = SessionActionHistoryStore()
    analyzer = BehavioralSequenceAnalyzer()
    origin = _origin()
    base = datetime.now(UTC)
    for index in range(4):
        history.append(
            ActionHistoryRecord(
                timestamp=base + timedelta(milliseconds=index * 100),
                session_id=origin.session_id,
                origin=origin,
                action_kind=ActionKind.FS_LIST,
                resource_id=f"/tmp/{index}",
                tool_name="file.read",
                decision_status="allow",
            )
        )

    candidate = ControlPlaneAction(
        timestamp=base + timedelta(milliseconds=500),
        origin=origin,
        tool_name="file.read",
        action_kind=ActionKind.FS_LIST,
        resource_id="/tmp/4",
    )
    findings = analyzer.analyze(history=history, candidate_action=candidate, now=base)
    assert any(item.pattern_name == "rapid_fire" for item in findings)


def test_m5_t3_resource_monitor_detects_credential_access() -> None:
    history = SessionActionHistoryStore()
    monitor = ResourceAccessMonitor()
    action = build_action(
        tool_name="file.read",
        arguments={"path": "~/.ssh/id_rsa"},
        origin=_origin(),
    )
    findings = monitor.analyze(history=history, candidate_action=action)
    assert any(item.reason_code == "resource:sensitive_access" for item in findings)


def test_m5_t4_resource_monitor_detects_enumeration_pattern() -> None:
    history = SessionActionHistoryStore()
    monitor = ResourceAccessMonitor()
    origin = _origin()
    now = datetime.now(UTC)
    for index in range(20):
        history.append(
            ActionHistoryRecord(
                timestamp=now - timedelta(seconds=20),
                session_id=origin.session_id,
                origin=origin,
                action_kind=ActionKind.FS_LIST,
                resource_id=f"/tmp/enumerate/{index}",
                tool_name="file.read",
                decision_status="allow",
            )
        )

    candidate = build_action(
        tool_name="file.read",
        arguments={"path": "/tmp/enumerate/20"},
        origin=origin,
    )
    findings = monitor.analyze(history=history, candidate_action=candidate, now=now)
    assert any(item.reason_code == "resource:enumeration_many_resources" for item in findings)


def test_m5_t5_network_metadata_enrichment_is_correct() -> None:
    baseline = BaselineDatabase()
    monitor = NetworkIntelligenceMonitor(
        baseline_db=baseline,
        cache_ttl_seconds=-1,
    )
    origin = _origin()
    known = extract_network_metadata(
        origin=origin,
        tool_name="http_request",
        destination_host="api.good.com",
        destination_port=443,
        protocol="https",
        request_size=100,
    )
    monitor.record_learning(
        metadata=known,
        allow_or_confirmed=True,
        suspicious=False,
        lockdown=False,
    )
    current = extract_network_metadata(
        origin=origin,
        tool_name="http_request",
        destination_host="api.good.com",
        destination_port=443,
        protocol="https",
        request_size=120,
    )
    enrichment = monitor.enrich(metadata=current, declared_domains=["api.good.com"])
    assert enrichment["declared_domain"] is True
    assert enrichment["baseline_known"] is True
    assert enrichment["new_domain"] is False
    assert enrichment["size_delta_ratio"] > 0


@pytest.mark.asyncio
async def test_m5_t6_network_flags_new_domain_high_rate_small_requests() -> None:
    monitor = NetworkIntelligenceMonitor(
        baseline_db=BaselineDatabase(),
        cache_ttl_seconds=-1,
    )
    origin = _origin()
    now = datetime.now(UTC)
    decision = None
    for index in range(8):
        metadata = extract_network_metadata(
            origin=origin,
            tool_name="http_request",
            destination_host="tracker.evil.example",
            destination_port=443,
            protocol="https",
            request_size=64,
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


def test_m5_t7_plan_commit_hash_is_deterministic_and_correct() -> None:
    verifier = ExecutionTraceVerifier()
    committed_at = datetime(2026, 1, 1, tzinfo=UTC)
    expires_at = committed_at + timedelta(minutes=30)
    plan_a = verifier._commit_plan(
        session_id="sess-1",
        allowed_actions={ActionKind.FS_READ, ActionKind.FS_LIST},
        allowed_resources={"/tmp/*"},
        forbidden_actions={ActionKind.SHELL_EXEC},
        max_actions=7,
        committed_at=committed_at,
        expires_at=expires_at,
        stage=PlanStage.STAGE1_PRECONTENT,
        amendment_of="",
    )
    plan_b = verifier._commit_plan(
        session_id="sess-1",
        allowed_actions={ActionKind.FS_READ, ActionKind.FS_LIST},
        allowed_resources={"/tmp/*"},
        forbidden_actions={ActionKind.SHELL_EXEC},
        max_actions=7,
        committed_at=committed_at,
        expires_at=expires_at,
        stage=PlanStage.STAGE1_PRECONTENT,
        amendment_of="",
    )
    expected_payload = {
        "session_id": "sess-1",
        "allowed_actions": ["FS_LIST", "FS_READ"],
        "allowed_resources": ["/tmp/*"],
        "forbidden_actions": ["SHELL_EXEC"],
        "max_actions": 7,
        "committed_at": committed_at.isoformat(),
        "expires_at": expires_at.isoformat(),
        "stage": PlanStage.STAGE1_PRECONTENT,
        "amendment_of": "",
    }
    expected_hash = hashlib.sha256(
        json.dumps(expected_payload, sort_keys=True).encode("utf-8")
    ).hexdigest()
    assert plan_a.plan_hash == plan_b.plan_hash == expected_hash


def test_m5_t8_trace_rejects_action_not_in_plan() -> None:
    verifier = ExecutionTraceVerifier()
    origin = _origin()
    verifier.begin_precontent_plan(
        session_id=origin.session_id,
        goal="summarize report",
        origin=origin,
    )
    action = build_action(tool_name="unknown_tool", arguments={}, origin=origin)
    result = verifier.verify_action(session_id=origin.session_id, action=action)
    assert result.allowed is False
    assert result.reason_code == "trace:action_not_committed"


def test_m5_t9_trace_rejects_forbidden_action() -> None:
    verifier = ExecutionTraceVerifier()
    origin = _origin("s-forbidden")
    committed_at = datetime.now(UTC)
    plan = verifier._commit_plan(
        session_id=origin.session_id,
        allowed_actions={ActionKind.SHELL_EXEC},
        allowed_resources=set(),
        forbidden_actions={ActionKind.SHELL_EXEC},
        max_actions=5,
        committed_at=committed_at,
        expires_at=committed_at + timedelta(minutes=5),
        stage=PlanStage.STAGE1_PRECONTENT,
        amendment_of="",
    )
    verifier._plans[origin.session_id] = plan
    action = build_action(
        tool_name="shell_exec",
        arguments={"command": ["python", "-c", "print('ok')"]},
        origin=origin,
    )
    result = verifier.verify_action(session_id=origin.session_id, action=action)
    assert result.allowed is False
    assert result.reason_code == "trace:forbidden_action"


class _StaticVoter:
    def __init__(self, vote: VoterDecision) -> None:
        self._vote = vote

    async def cast_vote(self, data: ConsensusInput) -> VoterDecision:
        _ = data
        return self._vote


@pytest.mark.asyncio
async def test_m5_t10_consensus_thresholds_apply_correctly() -> None:
    action = build_action(
        tool_name="file.read",
        arguments={"path": "README.md"},
        origin=_origin("s-consensus"),
    )
    data = ConsensusInput(
        action=action,
        trace_result=PlanVerificationResult(allowed=True, reason_code="trace:allowed"),
    )
    system = ConsensusVotingSystem(
        voters=[
            _StaticVoter(
                VoterDecision(
                    voter="v1",
                    decision=VoteKind.ALLOW,
                    risk_tier=RiskTier.LOW,
                    reason_codes=["allow"],
                )
            ),
            _StaticVoter(
                VoterDecision(
                    voter="v2",
                    decision=VoteKind.ALLOW,
                    risk_tier=RiskTier.LOW,
                    reason_codes=["allow"],
                )
            ),
            _StaticVoter(
                VoterDecision(
                    voter="v3",
                    decision=VoteKind.FLAG,
                    risk_tier=RiskTier.LOW,
                    reason_codes=["flag"],
                )
            ),
        ],
        policy=ConsensusPolicy(required_approvals_low=2),
    )
    decision = await system.evaluate(data)
    assert decision.decision.value == "require_confirmation"


@pytest.mark.asyncio
async def test_m5_t11_consensus_veto_works_for_high_risk() -> None:
    action = build_action(
        tool_name="shell_exec",
        arguments={"command": ["python", "-c", "print('ok')"]},
        origin=_origin("s-veto"),
        risk_tier=RiskTier.HIGH,
    )
    data = ConsensusInput(
        action=action,
        trace_result=PlanVerificationResult(allowed=True, reason_code="trace:allowed"),
    )
    system = ConsensusVotingSystem(
        voters=[
            _StaticVoter(
                VoterDecision(
                    voter="allow-voter",
                    decision=VoteKind.ALLOW,
                    risk_tier=RiskTier.HIGH,
                    reason_codes=["allow"],
                )
            ),
            _StaticVoter(
                VoterDecision(
                    voter="reject-voter",
                    decision=VoteKind.BLOCK,
                    risk_tier=RiskTier.HIGH,
                    reason_codes=["reject"],
                )
            ),
        ],
        policy=ConsensusPolicy(required_approvals_high=1, veto_for_high_and_critical=True),
    )
    decision = await system.evaluate(data)
    assert decision.decision.value == "block"
    assert any(code.startswith("consensus:veto:") for code in decision.reason_codes)


def test_m5_t15_action_normalization_maps_aliases_to_canonical_kind() -> None:
    assert infer_action_kind("file_read", {"path": "README.md"}) == ActionKind.FS_READ
    assert infer_action_kind(
        "shell.exec",
        {"command": ["python", "-c", "print('ok')"]},
    ) == ActionKind.SHELL_EXEC
    assert infer_action_kind(
        "shell.exec",
        {"command": ["curl", "https://example.com"]},
    ) == ActionKind.EGRESS


def test_m5_t16_control_plane_metadata_events_exclude_raw_payload_fields() -> None:
    disallowed = {
        "payload",
        "body",
        "raw_args",
        "request_body",
        "request_headers",
        "arguments",
        "raw_text",
    }
    for event_type in (
        ProxyRequestEvaluated,
        ControlPlaneActionObserved,
        ControlPlaneResourceObserved,
        ControlPlaneNetworkObserved,
    ):
        assert disallowed.isdisjoint(set(event_type.model_fields))

    cleaned = sanitize_metadata_payload(
        {
            "tool_name": "http_request",
            "request_body": "secret",
            "headers": {"authorization": "token"},
            "raw_args": {"command": ["curl", "https://example.com"]},
            "resource_ids": ["/tmp/a"],
        }
    )
    assert "request_body" not in cleaned
    assert "headers" not in cleaned
    assert "raw_args" not in cleaned
    assert cleaned["resource_ids"] == ["/tmp/a"]


class _SlowMonitorProvider:
    async def complete(
        self,
        messages: list[Message],
        tools: list[dict[str, object]] | None = None,
    ) -> ProviderResponse:
        _ = messages, tools
        await asyncio.sleep(0.05)
        return ProviderResponse(
            message=Message(
                role="assistant",
                content='{"decision":"ALLOW","reason_codes":["network:slow"]}',
            ),
            finish_reason="stop",
            usage={"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
        )


@pytest.mark.asyncio
async def test_m5_t17_high_critical_monitor_timeout_cannot_fail_open() -> None:
    monitor = NetworkIntelligenceMonitor(
        baseline_db=BaselineDatabase(),
        monitor_provider=_SlowMonitorProvider(),
        timeout_seconds=0.01,
        high_critical_timeout_action="ALLOW",
        low_medium_timeout_action="FLAG",
    )
    metadata = extract_network_metadata(
        origin=_origin("s-timeout"),
        tool_name="http_request",
        destination_host="timeout.example",
        destination_port=443,
        protocol="https",
        request_size=64,
    )
    decision = await monitor.evaluate(
        metadata=metadata,
        declared_domains=[],
        risk_tier=RiskTier.HIGH,
    )
    assert decision.timed_out is True
    assert decision.decision != "ALLOW"


def test_m5_t18_plan_lifecycle_expiry_cancel_amendment_semantics() -> None:
    verifier = ExecutionTraceVerifier(default_ttl_seconds=60)
    origin = _origin("s-lifecycle")

    first = verifier.begin_precontent_plan(
        session_id=origin.session_id,
        goal="summarize docs",
        origin=origin,
    )
    assert verifier.active_plan(origin.session_id) is not None
    assert verifier.cancel(session_id=origin.session_id, reason="manual") is True
    assert verifier.active_plan(origin.session_id) is None

    second = verifier.begin_precontent_plan(
        session_id=origin.session_id,
        goal="summarize docs",
        origin=origin,
    )
    amended = verifier.amend(
        session_id=origin.session_id,
        approved_by="human",
        allow_actions={ActionKind.EGRESS},
        allow_resources={"*.example.com"},
    )
    assert amended.stage == PlanStage.STAGE2_POSTEVIDENCE
    assert amended.amendment_of == second.plan_hash
    verifier._plans[origin.session_id].expires_at = datetime.now(UTC) - timedelta(seconds=1)
    assert verifier.active_plan(origin.session_id) is None
    assert first.plan_hash != second.plan_hash


@pytest.mark.asyncio
async def test_m5_t20_action_monitor_voter_rejects_raw_text_payloads() -> None:
    voter = ActionMonitorVoter()
    action = build_action(
        tool_name="file.read",
        arguments={"path": "README.md"},
        origin=_origin("s-action-monitor"),
    )
    decision = await voter.cast_vote(
        ConsensusInput(
            action=action,
            trace_result=PlanVerificationResult(allowed=True, reason_code="trace:allowed"),
            metadata_payload={"raw_text": "forbidden"},
        )
    )
    assert decision.decision == VoteKind.BLOCK
    assert decision.risk_tier == RiskTier.CRITICAL
