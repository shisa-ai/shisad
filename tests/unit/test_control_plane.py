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
from shisad.core.types import Capability
from shisad.security.control_plane.audit import ControlPlaneAuditLog
from shisad.security.control_plane.consensus import (
    ActionMonitorVoter,
    ConsensusInput,
    ConsensusPolicy,
    ConsensusVotingSystem,
    ResourceVoter,
    SequenceVoter,
    VoteKind,
    VoterDecision,
)
from shisad.security.control_plane.engine import ControlPlaneEngine
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
    contains_freeform_text,
    extract_request_size_bytes,
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


def test_m5_rt1_sequence_detects_fs_read_then_egress_with_intervening_action() -> None:
    history = SessionActionHistoryStore()
    analyzer = BehavioralSequenceAnalyzer()
    origin = _origin("s1-rt1")

    history.append_action(
        build_action(
            tool_name="file.read",
            arguments={"path": "README.md"},
            origin=origin,
        ),
        decision_status="allow",
    )
    history.append_action(
        build_action(
            tool_name="file.read",
            arguments={"path": "docs/ROADMAP.md"},
            origin=origin,
        ),
        decision_status="allow",
    )
    candidate = build_action(
        tool_name="http_request",
        arguments={"url": "https://exfil.example/upload"},
        origin=origin,
        risk_tier=RiskTier.HIGH,
    )

    findings = analyzer.analyze(history=history, candidate_action=candidate)
    assert any(item.pattern_name == "exfil_after_read" for item in findings)


@pytest.mark.asyncio
async def test_m5_t1b_sequence_voter_allows_web_search_after_read() -> None:
    history = SessionActionHistoryStore()
    analyzer = BehavioralSequenceAnalyzer()
    origin = _origin("s1-t1b")

    history.append_action(
        build_action(
            tool_name="file.read",
            arguments={"path": "README.md"},
            origin=origin,
        ),
        decision_status="allow",
    )
    candidate = build_action(
        tool_name="web.search",
        arguments={"query": "latest news", "limit": 1},
        origin=origin,
        risk_tier=RiskTier.MEDIUM,
    )

    vote = await SequenceVoter(analyzer=analyzer, history=history).cast_vote(
        ConsensusInput(
            action=candidate,
            trace_result=PlanVerificationResult(allowed=True, reason_code="trace:allowed"),
            network_metadata=[],
            declared_domains=[],
            metadata_payload={},
        )
    )
    assert vote.decision == VoteKind.ALLOW
    assert "sequence:allow_safe_egress_after_read" in vote.reason_codes


@pytest.mark.asyncio
async def test_m5_t1c_sequence_voter_blocks_http_request_after_read() -> None:
    history = SessionActionHistoryStore()
    analyzer = BehavioralSequenceAnalyzer()
    origin = _origin("s1-t1c")

    history.append_action(
        build_action(
            tool_name="file.read",
            arguments={"path": "README.md"},
            origin=origin,
        ),
        decision_status="allow",
    )
    candidate = build_action(
        tool_name="http_request",
        arguments={"url": "https://exfil.example/upload"},
        origin=origin,
        risk_tier=RiskTier.HIGH,
    )

    vote = await SequenceVoter(analyzer=analyzer, history=history).cast_vote(
        ConsensusInput(
            action=candidate,
            trace_result=PlanVerificationResult(allowed=True, reason_code="trace:allowed"),
            network_metadata=[],
            declared_domains=[],
            metadata_payload={},
        )
    )
    assert vote.decision == VoteKind.BLOCK


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


def test_h3_phantom_action_threshold_crossing_emits_single_finding(tmp_path) -> None:
    engine = ControlPlaneEngine.build(data_dir=tmp_path / "cp-h3-threshold")
    origin = _origin("h3-threshold")

    findings = []
    for index in range(3):
        findings = engine.observe_denied_action(
            action=build_action(
                tool_name="file.read",
                arguments={"path": f"/tmp/secret-{index}.txt"},
                origin=origin,
            ),
            source="policy_loop",
            reason_code="pep:missing_capabilities",
        )
        if index < 2:
            assert findings == []

    assert len(findings) == 1
    assert findings[0].pattern_name == "phantom_capability_probe"
    assert findings[0].reason_code == "sequence:phantom_capability_probe"
    assert findings[0].observation_count == 3

    deny_rows = engine.audit.query(
        event_type="denied_action_observed",
        session_id=origin.session_id,
    )
    phantom_rows = engine.audit.query(
        event_type="phantom_action_detected",
        session_id=origin.session_id,
    )
    assert len(deny_rows) == 3
    assert len(phantom_rows) == 1
    assert phantom_rows[0]["data"]["pattern_name"] == "phantom_capability_probe"
    assert phantom_rows[0]["data"]["observation_count"] == 3


def test_h3_nonqualifying_denies_do_not_emit_phantom_signal(tmp_path) -> None:
    engine = ControlPlaneEngine.build(data_dir=tmp_path / "cp-h3-filter")
    origin = _origin("h3-filter")

    for index in range(4):
        findings = engine.observe_denied_action(
            action=build_action(
                tool_name="file.read",
                arguments={"path": f"/tmp/schema-{index}.txt"},
                origin=origin,
            ),
            source="policy_loop",
            reason_code="pep:schema_validation_failed",
        )
        assert findings == []

    deny_rows = engine.audit.query(
        event_type="denied_action_observed",
        session_id=origin.session_id,
    )
    phantom_rows = engine.audit.query(
        event_type="phantom_action_detected",
        session_id=origin.session_id,
    )
    assert len(deny_rows) == 4
    assert phantom_rows == []


def test_h3_mixed_capability_rule_reason_codes_still_cross_threshold(tmp_path) -> None:
    engine = ControlPlaneEngine.build(data_dir=tmp_path / "cp-h3-mixed")
    origin = _origin("h3-mixed")

    findings = []
    for index, reason_code in enumerate(
        (
            "pep:missing_capabilities",
            "pep:tool_not_permitted",
            "pep:resource_authorization_failed",
        )
    ):
        findings = engine.observe_denied_action(
            action=build_action(
                tool_name="file.read",
                arguments={"path": f"/tmp/mixed-{index}.txt"},
                origin=origin,
            ),
            source="policy_loop",
            reason_code=reason_code,
        )
        if index < 2:
            assert findings == []

    assert len(findings) == 1
    assert findings[0].pattern_name == "phantom_capability_probe"
    assert findings[0].observation_count == 3


def test_h3_unattributed_egress_audit_stays_metadata_only(tmp_path) -> None:
    engine = ControlPlaneEngine.build(
        data_dir=tmp_path / "cp-h3-egress",
        phantom_deny_threshold=0,
    )
    origin = _origin("h3-egress")

    findings = []
    for host in ("one.example", "two.example"):
        findings = engine.observe_denied_action(
            action=build_action(
                tool_name="http_request",
                arguments={"url": f"https://{host}/upload"},
                origin=origin,
            ),
            source="policy_loop",
            reason_code="pep:destination_unattributed",
        )

    assert len(findings) == 1
    assert findings[0].pattern_name == "phantom_unattributed_egress"
    assert findings[0].observation_count == 2

    deny_rows = engine.audit.query(
        event_type="denied_action_observed",
        session_id=origin.session_id,
    )
    assert len(deny_rows) == 2
    assert deny_rows[0]["data"]["reason_code"] == "pep:destination_unattributed"
    assert "reason" not in deny_rows[0]["data"]


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


def test_m7_trace_stage1_shell_exec_requires_stage2_upgrade() -> None:
    verifier = ExecutionTraceVerifier()
    origin = _origin("s-shell-upgrade")
    verifier.begin_precontent_plan(
        session_id=origin.session_id,
        goal="inspect local repo",
        origin=origin,
    )
    action = build_action(
        tool_name="shell_exec",
        arguments={"command": ["python", "-c", "print('ok')"]},
        origin=origin,
    )
    result = verifier.verify_action(session_id=origin.session_id, action=action)
    assert result.allowed is False
    assert result.reason_code == "trace:stage2_upgrade_required"


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


@pytest.mark.asyncio
async def test_m5_rt2_resource_voter_blocks_high_risk_sensitive_access() -> None:
    history = SessionActionHistoryStore()
    monitor = ResourceAccessMonitor()
    voter = ResourceVoter(monitor=monitor, history=history)
    action = build_action(
        tool_name="file.read",
        arguments={"path": "~/.ssh/id_rsa"},
        origin=_origin("s-rt2"),
        risk_tier=RiskTier.HIGH,
    )
    decision = await voter.cast_vote(
        ConsensusInput(
            action=action,
            trace_result=PlanVerificationResult(allowed=True, reason_code="trace:allowed"),
        )
    )
    assert decision.decision == VoteKind.BLOCK
    assert decision.risk_tier == RiskTier.HIGH


class _SleepVoter:
    def __init__(self, voter: str, delay_seconds: float) -> None:
        self._voter = voter
        self._delay_seconds = delay_seconds

    async def cast_vote(self, data: ConsensusInput) -> VoterDecision:
        _ = data
        await asyncio.sleep(self._delay_seconds)
        return VoterDecision(
            voter=self._voter,
            decision=VoteKind.ALLOW,
            risk_tier=RiskTier.LOW,
            reason_codes=["allow"],
        )


@pytest.mark.asyncio
async def test_m5_rt3_consensus_runs_voters_in_parallel() -> None:
    action = build_action(
        tool_name="file.read",
        arguments={"path": "README.md"},
        origin=_origin("s-rt3"),
    )
    data = ConsensusInput(
        action=action,
        trace_result=PlanVerificationResult(allowed=True, reason_code="trace:allowed"),
    )
    system = ConsensusVotingSystem(
        voters=[_SleepVoter(f"v{i}", 0.05) for i in range(5)],
        policy=ConsensusPolicy(required_approvals_low=5, voter_timeout_seconds=0.5),
    )
    start = asyncio.get_running_loop().time()
    decision = await system.evaluate(data)
    elapsed = asyncio.get_running_loop().time() - start
    assert decision.decision.value == "allow"
    assert elapsed < 0.18


def test_m5_t15_action_normalization_maps_aliases_to_canonical_kind() -> None:
    assert infer_action_kind("file_read", {"path": "README.md"}) == ActionKind.FS_READ
    assert (
        infer_action_kind(
            "shell.exec",
            {"command": ["python", "-c", "print('ok')"]},
        )
        == ActionKind.SHELL_EXEC
    )
    assert (
        infer_action_kind(
            "shell.exec",
            {"command": ["curl", "https://example.com"]},
        )
        == ActionKind.EGRESS
    )


def test_s9_infer_action_kind_treats_web_search_as_egress() -> None:
    assert infer_action_kind("web.search", {"query": "security updates"}) == ActionKind.EGRESS


def test_m6_infer_action_kind_treats_browser_tools_as_browser_read_write() -> None:
    assert infer_action_kind("browser.navigate", {"url": "https://example.com"}) == (
        ActionKind.BROWSER_READ
    )
    assert infer_action_kind("browser.read_page", {}) == ActionKind.BROWSER_READ
    assert infer_action_kind("browser.screenshot", {}) == ActionKind.BROWSER_READ
    assert infer_action_kind("browser.click", {"target": "#continue"}) == (ActionKind.BROWSER_WRITE)
    assert infer_action_kind("browser.type_text", {"target": "#search", "text": "hello"}) == (
        ActionKind.BROWSER_WRITE
    )


def test_s9_infer_action_kind_treats_fs_list_without_path_as_fs_list() -> None:
    assert infer_action_kind("fs.list", {}) == ActionKind.FS_LIST


def test_s9_infer_action_kind_treats_git_status_as_fs_read() -> None:
    assert infer_action_kind("git.status", {}) == ActionKind.FS_READ


def test_m1_infer_action_kind_covers_note_todo_and_reminder_tools() -> None:
    assert infer_action_kind("note.search", {"query": "groceries"}) == ActionKind.MEMORY_READ
    assert infer_action_kind("todo.complete", {"selector": "buy milk"}) == ActionKind.MEMORY_WRITE
    assert infer_action_kind("reminder.create", {"message": "stand up", "when": "in 1 minute"}) == (
        ActionKind.MEMORY_WRITE
    )


def test_m5_rt9_command_filename_token_is_not_misclassified_as_egress() -> None:
    kind = infer_action_kind(
        "shell.exec",
        {"command": ["cat", "config.json"]},
    )
    assert kind != ActionKind.EGRESS


def test_m5_rt10_trace_allows_fs_list_without_path_arguments() -> None:
    verifier = ExecutionTraceVerifier()
    origin = _origin("s-rt10")
    verifier.begin_precontent_plan(
        session_id=origin.session_id,
        goal="list files",
        origin=origin,
    )
    action = build_action(tool_name="fs.list", arguments={}, origin=origin)
    result = verifier.verify_action(session_id=origin.session_id, action=action)
    assert result.allowed is True
    assert result.reason_code == "trace:allowed"


def test_m6_trace_requires_stage2_for_browser_write_actions() -> None:
    verifier = ExecutionTraceVerifier()
    origin = _origin("s-m6-browser-write")
    verifier.begin_precontent_plan(
        session_id=origin.session_id,
        goal="click continue in the browser",
        origin=origin,
        capabilities={Capability.HTTP_REQUEST},
    )
    action = build_action(
        tool_name="browser.click",
        arguments={"target": "#continue"},
        origin=origin,
    )
    result = verifier.verify_action(session_id=origin.session_id, action=action)
    assert result.allowed is False
    assert result.reason_code == "trace:stage2_upgrade_required"


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


@pytest.mark.asyncio
async def test_m6_low_risk_declared_domain_timeout_uses_heuristic_allow() -> None:
    monitor = NetworkIntelligenceMonitor(
        baseline_db=BaselineDatabase(),
        monitor_provider=_SlowMonitorProvider(),
        timeout_seconds=0.01,
        high_critical_timeout_action="BLOCK",
        low_medium_timeout_action="FLAG",
    )
    metadata = extract_network_metadata(
        origin=_origin("s-browser-timeout"),
        tool_name="browser.navigate",
        destination_host="localhost",
        destination_port=443,
        protocol="https",
        request_size=0,
    )
    decision = await monitor.evaluate(
        metadata=metadata,
        declared_domains=["localhost"],
        risk_tier=RiskTier.LOW,
    )
    assert decision.timed_out is True
    assert decision.decision == "ALLOW"
    assert "network:monitor_timeout_heuristic_allow" in decision.reason_codes


@pytest.mark.asyncio
async def test_m5_rt10_network_cache_does_not_reuse_allow_across_contexts() -> None:
    monitor = NetworkIntelligenceMonitor(
        baseline_db=BaselineDatabase(),
        cache_ttl_seconds=300,
    )
    first_origin = Origin(
        session_id="s-cache-1",
        user_id="user-a",
        workspace_id="ws-a",
        skill_name="skill-x",
        actor="planner",
    )
    second_origin = Origin(
        session_id="s-cache-2",
        user_id="user-b",
        workspace_id="ws-b",
        skill_name="skill-x",
        actor="planner",
    )

    first = extract_network_metadata(
        origin=first_origin,
        tool_name="http_request",
        destination_host="api.good.example",
        destination_port=443,
        protocol="https",
        request_size=128,
    )
    second = extract_network_metadata(
        origin=second_origin,
        tool_name="http_request",
        destination_host="api.good.example",
        destination_port=443,
        protocol="https",
        request_size=128,
    )
    _ = await monitor.evaluate(
        metadata=first,
        declared_domains=["api.good.example"],
        risk_tier=RiskTier.LOW,
    )
    second_decision = await monitor.evaluate(
        metadata=second,
        declared_domains=[],
        risk_tier=RiskTier.HIGH,
    )
    assert second_decision.decision != "ALLOW"
    assert "network:undeclared_new_domain" in second_decision.reason_codes


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


@pytest.mark.asyncio
async def test_m1_rlc7_action_monitor_voter_allows_clean_trusted_side_effect() -> None:
    voter = ActionMonitorVoter()
    action = build_action(
        tool_name="web.search",
        arguments={"query": "latest news"},
        origin=_origin("s-action-monitor-clean"),
    )
    decision = await voter.cast_vote(
        ConsensusInput(
            action=action,
            trace_result=PlanVerificationResult(allowed=True, reason_code="trace:allowed"),
            metadata_payload={
                "session_tainted": False,
                "trusted_input": True,
            },
        )
    )
    assert decision.decision == VoteKind.ALLOW
    assert decision.risk_tier == RiskTier.LOW
    assert "action_monitor:clean_session_trust_planner" in decision.reason_codes


@pytest.mark.asyncio
async def test_m1_rlc7_action_monitor_voter_flags_tainted_side_effect() -> None:
    voter = ActionMonitorVoter()
    action = build_action(
        tool_name="web.search",
        arguments={"query": "latest news"},
        origin=_origin("s-action-monitor-tainted"),
    )
    decision = await voter.cast_vote(
        ConsensusInput(
            action=action,
            trace_result=PlanVerificationResult(allowed=True, reason_code="trace:allowed"),
            metadata_payload={
                "session_tainted": True,
                "trusted_input": True,
            },
        )
    )
    assert decision.decision == VoteKind.FLAG
    assert decision.risk_tier == RiskTier.HIGH
    assert "action_monitor:side_effect_on_tainted_session" in decision.reason_codes


@pytest.mark.asyncio
async def test_m1_action_monitor_allows_explicit_tainted_memory_write() -> None:
    voter = ActionMonitorVoter()
    action = build_action(
        tool_name="todo.complete",
        arguments={"selector": "review PRs"},
        origin=_origin("s-action-monitor-tainted-memory-write"),
    )
    decision = await voter.cast_vote(
        ConsensusInput(
            action=action,
            trace_result=PlanVerificationResult(allowed=True, reason_code="trace:allowed"),
            metadata_payload={
                "session_tainted": True,
                "trusted_input": True,
                "raw_user_text": "mark the review PRs todo complete",
                "action_arguments": {"selector": "review PRs"},
            },
        )
    )
    assert decision.decision == VoteKind.ALLOW
    assert decision.risk_tier == RiskTier.LOW
    assert "action_monitor:deterministic_intent_match" in decision.reason_codes


@pytest.mark.asyncio
async def test_m1_rr1_action_monitor_does_not_allow_note_create_for_note_search_text() -> None:
    voter = ActionMonitorVoter()
    action = build_action(
        tool_name="note.create",
        arguments={"key": "note:groceries"},
        origin=_origin("s-action-monitor-note-search-mismatch"),
    )
    decision = await voter.cast_vote(
        ConsensusInput(
            action=action,
            trace_result=PlanVerificationResult(allowed=True, reason_code="trace:allowed"),
            metadata_payload={
                "session_tainted": True,
                "trusted_input": True,
                "raw_user_text": "search my notes for groceries",
                "action_arguments": {"key": "note:groceries"},
            },
        )
    )
    assert decision.decision == VoteKind.FLAG
    assert "action_monitor:deterministic_intent_match" not in decision.reason_codes


@pytest.mark.asyncio
async def test_m1_rr1_action_monitor_does_not_allow_negated_todo_completion() -> None:
    voter = ActionMonitorVoter()
    action = build_action(
        tool_name="todo.complete",
        arguments={"selector": "review PRs"},
        origin=_origin("s-action-monitor-negated-complete"),
    )
    decision = await voter.cast_vote(
        ConsensusInput(
            action=action,
            trace_result=PlanVerificationResult(allowed=True, reason_code="trace:allowed"),
            metadata_payload={
                "session_tainted": True,
                "trusted_input": True,
                "raw_user_text": "don't mark the review PRs todo complete",
                "action_arguments": {"selector": "review PRs"},
            },
        )
    )
    assert decision.decision == VoteKind.FLAG
    assert "action_monitor:deterministic_intent_match" not in decision.reason_codes


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "raw_user_text",
    [
        "add todo: review PRs; list my todos",
        "add todo: review PRs, list my todos",
        "add todo: review PRs; read README.md",
        "add todo: review PRs, read README.md",
    ],
)
async def test_m1_rr2_action_monitor_rejects_punctuation_separated_follow_on_commands(
    raw_user_text: str,
) -> None:
    voter = ActionMonitorVoter()
    action = build_action(
        tool_name="todo.create",
        arguments={"title": "review PRs"},
        origin=_origin("s-action-monitor-follow-on-punctuation"),
    )
    decision = await voter.cast_vote(
        ConsensusInput(
            action=action,
            trace_result=PlanVerificationResult(allowed=True, reason_code="trace:allowed"),
            metadata_payload={
                "session_tainted": True,
                "trusted_input": True,
                "raw_user_text": raw_user_text,
                "action_arguments": {"title": "review PRs"},
            },
        )
    )
    assert decision.decision == VoteKind.FLAG
    assert "action_monitor:deterministic_intent_match" not in decision.reason_codes


@pytest.mark.asyncio
async def test_m1_rr1_action_monitor_matches_only_primary_note_fields() -> None:
    voter = ActionMonitorVoter()
    action = build_action(
        tool_name="note.create",
        arguments={"key": "note:groceries"},
        origin=_origin("s-action-monitor-note-primary-fields"),
    )
    decision = await voter.cast_vote(
        ConsensusInput(
            action=action,
            trace_result=PlanVerificationResult(allowed=True, reason_code="trace:allowed"),
            metadata_payload={
                "session_tainted": True,
                "trusted_input": True,
                "raw_user_text": "add a note: groceries",
                "action_arguments": {"key": "note:groceries"},
            },
        )
    )
    assert decision.decision == VoteKind.FLAG
    assert "action_monitor:deterministic_intent_match" not in decision.reason_codes


@pytest.mark.asyncio
async def test_m1_rr2_action_monitor_allows_at_iso_reminder_datetime() -> None:
    voter = ActionMonitorVoter()
    action = build_action(
        tool_name="reminder.create",
        arguments={"message": "check email", "when": "at 2026-03-30T12:00:00Z"},
        origin=_origin("s-action-monitor-reminder-at-iso"),
    )
    decision = await voter.cast_vote(
        ConsensusInput(
            action=action,
            trace_result=PlanVerificationResult(allowed=True, reason_code="trace:allowed"),
            metadata_payload={
                "session_tainted": True,
                "trusted_input": True,
                "raw_user_text": "remind me to check email at 2026-03-30T12:00:00Z",
                "action_arguments": {
                    "message": "check email",
                    "when": "at 2026-03-30T12:00:00Z",
                },
            },
        )
    )
    assert decision.decision == VoteKind.ALLOW
    assert "action_monitor:deterministic_intent_match" in decision.reason_codes


@pytest.mark.asyncio
async def test_m1_rlc7_action_monitor_voter_flags_untrusted_clean_side_effect() -> None:
    voter = ActionMonitorVoter()
    action = build_action(
        tool_name="web.search",
        arguments={"query": "latest news"},
        origin=_origin("s-action-monitor-untrusted-clean"),
    )
    decision = await voter.cast_vote(
        ConsensusInput(
            action=action,
            trace_result=PlanVerificationResult(allowed=True, reason_code="trace:allowed"),
            metadata_payload={
                "session_tainted": False,
                "trusted_input": False,
            },
        )
    )
    assert decision.decision == VoteKind.FLAG
    assert decision.risk_tier == RiskTier.HIGH
    assert "action_monitor:untrusted_input_side_effect" in decision.reason_codes


@pytest.mark.asyncio
async def test_m1_rlc7_action_monitor_voter_flags_tainted_untrusted_side_effect() -> None:
    voter = ActionMonitorVoter()
    action = build_action(
        tool_name="web.search",
        arguments={"query": "latest news"},
        origin=_origin("s-action-monitor-untrusted-tainted"),
    )
    decision = await voter.cast_vote(
        ConsensusInput(
            action=action,
            trace_result=PlanVerificationResult(allowed=True, reason_code="trace:allowed"),
            metadata_payload={
                "session_tainted": True,
                "trusted_input": False,
            },
        )
    )
    assert decision.decision == VoteKind.FLAG
    assert decision.risk_tier == RiskTier.HIGH
    assert "action_monitor:side_effect_on_tainted_session" in decision.reason_codes


@pytest.mark.asyncio
async def test_m1_rr2_action_monitor_voter_missing_metadata_fails_closed() -> None:
    voter = ActionMonitorVoter()
    action = build_action(
        tool_name="web.search",
        arguments={"query": "latest news"},
        origin=_origin("s-action-monitor-missing-metadata"),
    )
    decision = await voter.cast_vote(
        ConsensusInput(
            action=action,
            trace_result=PlanVerificationResult(allowed=True, reason_code="trace:allowed"),
            metadata_payload={},
        )
    )
    assert decision.decision == VoteKind.FLAG
    assert decision.risk_tier == RiskTier.HIGH
    assert "action_monitor:side_effect_on_tainted_session" in decision.reason_codes


@pytest.mark.asyncio
async def test_m1_rr2_action_monitor_voter_string_metadata_fails_closed() -> None:
    voter = ActionMonitorVoter()
    action = build_action(
        tool_name="web.search",
        arguments={"query": "latest news"},
        origin=_origin("s-action-monitor-string-metadata"),
    )
    decision = await voter.cast_vote(
        ConsensusInput(
            action=action,
            trace_result=PlanVerificationResult(allowed=True, reason_code="trace:allowed"),
            metadata_payload={
                "session_tainted": "false",
                "trusted_input": "true",
            },
        )
    )
    assert decision.decision == VoteKind.FLAG
    assert decision.risk_tier == RiskTier.HIGH
    assert "action_monitor:side_effect_on_tainted_session" in decision.reason_codes


@pytest.mark.asyncio
async def test_m1_rr2_action_monitor_voter_string_false_trusted_input_fails_closed() -> None:
    voter = ActionMonitorVoter()
    action = build_action(
        tool_name="web.search",
        arguments={"query": "latest news"},
        origin=_origin("s-action-monitor-string-false"),
    )
    decision = await voter.cast_vote(
        ConsensusInput(
            action=action,
            trace_result=PlanVerificationResult(allowed=True, reason_code="trace:allowed"),
            metadata_payload={
                "session_tainted": False,
                "trusted_input": "false",
            },
        )
    )
    assert decision.decision == VoteKind.FLAG
    assert decision.risk_tier == RiskTier.HIGH
    assert "action_monitor:untrusted_input_side_effect" in decision.reason_codes


def test_m5_rt4_contains_freeform_text_blocks_large_single_line_values() -> None:
    assert contains_freeform_text({"note": "a" * 257}) is True
    assert contains_freeform_text({"note": "a" * 256}) is False


def test_m5_rt5_extract_request_size_is_metadata_only() -> None:
    assert extract_request_size_bytes({"request_body": "x" * 4096}) == 0
    assert (
        extract_request_size_bytes(
            {"request_body": "x" * 4096, "request_headers": {"Content-Length": "42"}}
        )
        == 42
    )


def test_m5_rt6_baseline_known_hosts_handles_colons_in_origin_fields() -> None:
    baseline = BaselineDatabase()
    origin = Origin(
        session_id="s-rt6",
        user_id="user:alpha",
        workspace_id="ws:beta",
        skill_name="skill:gamma",
        actor="planner",
    )
    metadata = extract_network_metadata(
        origin=origin,
        tool_name="http_request",
        destination_host="api.good.example",
        destination_port=443,
        protocol="https",
        request_size=128,
    )
    baseline.record(
        metadata=metadata,
        allow_or_confirmed=True,
        suspicious=False,
        lockdown=False,
    )
    assert baseline.known_hosts_for_origin(origin) == {"api.good.example"}


def test_m5_rt7_control_plane_audit_chain_detects_whitespace_tamper(tmp_path) -> None:
    path = tmp_path / "control-plane-audit.jsonl"
    log = ControlPlaneAuditLog(path)
    log.append(event_type="e1", session_id="s", actor="a", data={"k": "v1"})
    log.append(event_type="e2", session_id="s", actor="a", data={"k": "v2"})
    ok_before, _, _ = log.verify_chain()
    assert ok_before is True

    lines = path.read_text(encoding="utf-8").splitlines()
    lines[0] = lines[0] + "  "
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    ok_after, _, error = log.verify_chain()
    assert ok_after is False
    assert "chain break" in error


def test_m5_rt8_history_load_logs_malformed_records(
    tmp_path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    history_path = tmp_path / "history.jsonl"
    history_path.write_text("{not-json}\n", encoding="utf-8")
    caplog.set_level("WARNING", logger="shisad.security.control_plane.history")
    _ = SessionActionHistoryStore(history_path)
    assert "skipping malformed record" in caplog.text


def test_m5_rt11_sequence_analyzer_dedupes_preflight_and_execution_rows() -> None:
    history = SessionActionHistoryStore()
    analyzer = BehavioralSequenceAnalyzer()
    origin = _origin("s-seq-dedupe")
    now = datetime.now(UTC)
    for index in range(2):
        action = ControlPlaneAction(
            timestamp=now + timedelta(seconds=index),
            origin=origin,
            tool_name="file.read",
            action_kind=ActionKind.FS_LIST,
            resource_id=f"/tmp/{index}",
        )
        history.append_action(action, decision_status="allow")
        history.append_action(action, decision_status="allow", execution_status="success")

    candidate = ControlPlaneAction(
        timestamp=now + timedelta(seconds=3),
        origin=origin,
        tool_name="file.read",
        action_kind=ActionKind.FS_LIST,
        resource_id="/tmp/2",
    )
    findings = analyzer.analyze(history=history, candidate_action=candidate, now=now)
    assert all(item.pattern_name != "mass_enum" for item in findings)
