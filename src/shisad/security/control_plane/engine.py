"""Injection-proof control-plane engine orchestration."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from shisad.core.types import Capability
from shisad.security.control_plane.audit import ControlPlaneAuditLog
from shisad.security.control_plane.consensus import (
    ActionMonitorVoter,
    ConsensusDecision,
    ConsensusInput,
    ConsensusPolicy,
    ConsensusVotingSystem,
    NetworkVoter,
    ResourceVoter,
    SequenceVoter,
    TraceVoter,
)
from shisad.security.control_plane.history import SessionActionHistoryStore
from shisad.security.control_plane.network import (
    BaselineDatabase,
    NetworkIntelligenceMonitor,
    ThreatIntelStub,
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
    extract_request_size_bytes,
    sanitize_metadata_payload,
)
from shisad.security.control_plane.sequence import BehavioralSequenceAnalyzer
from shisad.security.control_plane.trace import ExecutionTraceVerifier, PlanVerificationResult


class ControlPlaneEvaluation(BaseModel, frozen=True):
    action: ControlPlaneAction
    trace_result: PlanVerificationResult
    consensus: ConsensusDecision
    decision: ControlDecision
    reason_codes: list[str] = Field(default_factory=list)


class ControlPlaneEngine:
    """Coordinates M5 voters, plan commitment, and metadata-only auditing."""

    def __init__(
        self,
        *,
        history_store: SessionActionHistoryStore,
        trace_verifier: ExecutionTraceVerifier,
        sequence_analyzer: BehavioralSequenceAnalyzer,
        resource_monitor: ResourceAccessMonitor,
        network_monitor: NetworkIntelligenceMonitor,
        consensus_policy: ConsensusPolicy,
        audit_log: ControlPlaneAuditLog,
    ) -> None:
        self._history_store = history_store
        self._trace_verifier = trace_verifier
        self._sequence_analyzer = sequence_analyzer
        self._resource_monitor = resource_monitor
        self._network_monitor = network_monitor
        self._audit_log = audit_log
        self._consensus = ConsensusVotingSystem(
            voters=[
                NetworkVoter(monitor=self._network_monitor),
                SequenceVoter(analyzer=self._sequence_analyzer, history=self._history_store),
                ResourceVoter(monitor=self._resource_monitor, history=self._history_store),
                TraceVoter(),
                ActionMonitorVoter(),
            ],
            policy=consensus_policy,
            audit_hook=self._audit_consensus,
        )

    @classmethod
    def build(
        cls,
        *,
        data_dir: Path,
        monitor_provider: Any | None = None,
        monitor_timeout_seconds: float = 0.5,
        monitor_cache_ttl_seconds: int = 300,
        baseline_learning_rate: float = 0.1,
        high_critical_timeout_action: str = "BLOCK",
        low_medium_timeout_action: str = "FLAG",
        trace_ttl_seconds: int = 1800,
        trace_max_actions: int = 10,
        consensus_policy: ConsensusPolicy | None = None,
    ) -> ControlPlaneEngine:
        control_plane_dir = data_dir / "control_plane"
        history_store = SessionActionHistoryStore(control_plane_dir / "history.jsonl")
        trace_verifier = ExecutionTraceVerifier(
            storage_path=control_plane_dir / "plans.json",
            default_ttl_seconds=trace_ttl_seconds,
            default_max_actions=trace_max_actions,
        )
        sequence_analyzer = BehavioralSequenceAnalyzer()
        resource_monitor = ResourceAccessMonitor()
        baseline_db = BaselineDatabase(
            storage_path=str(control_plane_dir / "network_baseline.json"),
            learning_rate=baseline_learning_rate,
        )
        network_monitor = NetworkIntelligenceMonitor(
            baseline_db=baseline_db,
            threat_intel=ThreatIntelStub(),
            monitor_provider=monitor_provider,
            timeout_seconds=monitor_timeout_seconds,
            cache_ttl_seconds=monitor_cache_ttl_seconds,
            high_critical_timeout_action=high_critical_timeout_action,
            low_medium_timeout_action=low_medium_timeout_action,
        )
        audit_log = ControlPlaneAuditLog(control_plane_dir / "audit.jsonl")
        return cls(
            history_store=history_store,
            trace_verifier=trace_verifier,
            sequence_analyzer=sequence_analyzer,
            resource_monitor=resource_monitor,
            network_monitor=network_monitor,
            consensus_policy=consensus_policy or ConsensusPolicy(),
            audit_log=audit_log,
        )

    @property
    def audit(self) -> ControlPlaneAuditLog:
        return self._audit_log

    def begin_precontent_plan(
        self,
        *,
        session_id: str,
        goal: str,
        origin: Origin,
        ttl_seconds: int,
        max_actions: int,
        capabilities: set[Capability] | None = None,
    ) -> str:
        active = self._trace_verifier.active_plan(session_id)
        if active is not None:
            self._trace_verifier.cancel(session_id=session_id, reason="superseded_by_new_goal")
            self._audit_log.append(
                event_type="plan_cancelled",
                session_id=session_id,
                actor=origin.actor,
                data={"reason": "superseded_by_new_goal", "plan_hash": active.plan_hash},
            )
        committed = self._trace_verifier.begin_precontent_plan(
            session_id=session_id,
            goal=goal,
            origin=origin,
            ttl_seconds=ttl_seconds,
            max_actions=max_actions,
            capabilities=capabilities,
        )
        self._audit_log.append(
            event_type="plan_committed",
            session_id=session_id,
            actor=origin.actor,
            data={
                "plan_hash": committed.plan_hash,
                "stage": committed.stage,
                "expires_at": committed.expires_at.isoformat(),
                "allowed_actions": sorted(item.value for item in committed.allowed_actions),
                "forbidden_actions": sorted(item.value for item in committed.forbidden_actions),
                "max_actions": committed.max_actions,
            },
        )
        return committed.plan_hash

    async def evaluate_action(
        self,
        *,
        tool_name: str,
        arguments: dict[str, Any],
        origin: Origin,
        risk_tier: RiskTier,
        declared_domains: list[str],
        session_tainted: bool,
        trusted_input: bool,
    ) -> ControlPlaneEvaluation:
        metadata_arguments = sanitize_metadata_payload(arguments)
        action = build_action(
            tool_name=tool_name,
            arguments=metadata_arguments,
            origin=origin,
            risk_tier=risk_tier,
        )

        trace_result = self._trace_verifier.verify_action(
            session_id=origin.session_id,
            action=action,
        )

        request_size = extract_request_size_bytes(arguments)
        network_metadata = [
            extract_network_metadata(
                origin=origin,
                tool_name=action.tool_name,
                destination_host=host,
                destination_port=443,
                protocol="https",
                request_size=request_size,
                timestamp=action.timestamp,
            )
            for host in action.network_hosts
        ]

        consensus = await self._consensus.evaluate(
            ConsensusInput(
                action=action,
                trace_result=trace_result,
                network_metadata=network_metadata,
                declared_domains=declared_domains,
                metadata_payload={
                    "session_tainted": session_tainted,
                    "trusted_input": trusted_input,
                    "action_kind": action.action_kind.value,
                    "resource_ids": list(action.resource_ids),
                    "network_hosts": list(action.network_hosts),
                    "request_size_bytes": request_size,
                },
            )
        )

        final_decision = consensus.decision
        reason_codes = list(consensus.reason_codes)
        if not trace_result.allowed:
            final_decision = ControlDecision.BLOCK
            if trace_result.reason_code not in reason_codes:
                reason_codes.append(trace_result.reason_code)

        self._history_store.append_action(action, decision_status=final_decision.value)
        self._audit_log.append(
            event_type="action_observed",
            session_id=origin.session_id,
            actor=origin.actor,
            data={
                "tool_name": action.tool_name,
                "action_kind": action.action_kind.value,
                "risk_tier": action.risk_tier.value,
                "resource_id": action.resource_id,
                "network_hosts": list(action.network_hosts),
                "decision": final_decision.value,
                "reason_codes": reason_codes,
            },
        )

        return ControlPlaneEvaluation(
            action=action,
            trace_result=trace_result,
            consensus=consensus,
            decision=final_decision,
            reason_codes=reason_codes,
        )

    def record_execution(self, *, action: ControlPlaneAction, success: bool) -> None:
        self._history_store.append_action(
            action,
            decision_status=ControlDecision.ALLOW.value,
            execution_status="success" if success else "failed",
        )
        if success:
            self._trace_verifier.record_action(session_id=action.origin.session_id)

    def approve_stage2(
        self,
        *,
        action: ControlPlaneAction,
        approved_by: str,
    ) -> str:
        amended = self._trace_verifier.amend(
            session_id=action.origin.session_id,
            approved_by=approved_by,
            allow_actions={
                action.action_kind,
                ActionKind.EGRESS,
                ActionKind.FS_WRITE,
                ActionKind.MEMORY_WRITE,
                ActionKind.MESSAGE_SEND,
            },
            allow_resources=set(action.resource_ids),
        )
        self._audit_log.append(
            event_type="plan_amended",
            session_id=action.origin.session_id,
            actor=approved_by,
            data={
                "plan_hash": amended.plan_hash,
                "amendment_of": amended.amendment_of,
                "stage": amended.stage,
                "allowed_actions": sorted(item.value for item in amended.allowed_actions),
            },
        )
        return amended.plan_hash

    def cancel_plan(self, *, session_id: str, reason: str, actor: str) -> bool:
        cancelled = self._trace_verifier.cancel(session_id=session_id, reason=reason)
        if cancelled:
            self._audit_log.append(
                event_type="plan_cancelled",
                session_id=session_id,
                actor=actor,
                data={"reason": reason},
            )
        return cancelled

    def active_plan_hash(self, session_id: str) -> str:
        plan = self._trace_verifier.active_plan(session_id)
        if plan is None:
            return ""
        return plan.plan_hash

    def observe_runtime_network(
        self,
        *,
        origin: Origin,
        tool_name: str,
        destination_host: str,
        destination_port: int | None,
        protocol: str,
        allowed: bool,
        reason: str,
        request_size: int,
        resolved_addresses: list[str],
    ) -> None:
        metadata = extract_network_metadata(
            origin=origin,
            tool_name=tool_name,
            destination_host=destination_host,
            destination_port=destination_port,
            protocol=protocol,
            request_size=request_size,
            resolved_addresses=resolved_addresses,
            timestamp=datetime.now(UTC),
        )
        self._network_monitor.record_learning(
            metadata=metadata,
            allow_or_confirmed=allowed,
            suspicious=not allowed,
            lockdown=False,
        )
        self._audit_log.append(
            event_type="network_observed",
            session_id=origin.session_id,
            actor=origin.actor or "egress_proxy",
            data={
                "tool_name": tool_name,
                "destination_host": destination_host,
                "destination_port": destination_port,
                "protocol": protocol,
                "allowed": allowed,
                "reason": reason,
                "request_size": request_size,
                "resolved_addresses": list(resolved_addresses),
            },
        )

    def _audit_consensus(self, payload: dict[str, Any]) -> None:
        session_id = str(payload.get("session_id", "")).strip()
        self._audit_log.append(
            event_type="consensus_evaluated",
            session_id=session_id,
            actor="consensus",
            data=payload,
        )
