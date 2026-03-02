"""Consensus voting system for metadata-only control-plane decisions."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Protocol

from pydantic import BaseModel, Field

from shisad.security.control_plane.history import SessionActionHistoryStore
from shisad.security.control_plane.network import (
    NetworkIntelligenceMonitor,
    NetworkMetadata,
    NetworkMonitorDecisionKind,
)
from shisad.security.control_plane.resource import ResourceAccessMonitor
from shisad.security.control_plane.schema import (
    ActionKind,
    ControlDecision,
    ControlPlaneAction,
    RiskTier,
    contains_freeform_text,
    risk_rank,
)
from shisad.security.control_plane.sequence import BehavioralSequenceAnalyzer
from shisad.security.control_plane.trace import PlanVerificationResult


class VoteKind(StrEnum):
    ALLOW = "ALLOW"
    FLAG = "FLAG"
    BLOCK = "BLOCK"


class VoterDecision(BaseModel, frozen=True):
    voter: str
    decision: VoteKind
    risk_tier: RiskTier
    reason_codes: list[str] = Field(default_factory=list)


class ConsensusInput(BaseModel, frozen=True):
    action: ControlPlaneAction
    trace_result: PlanVerificationResult
    network_metadata: list[NetworkMetadata] = Field(default_factory=list)
    declared_domains: list[str] = Field(default_factory=list)
    metadata_payload: dict[str, Any] = Field(default_factory=dict)


class ConsensusDecision(BaseModel, frozen=True):
    decision: ControlDecision
    risk_tier: RiskTier
    reason_codes: list[str] = Field(default_factory=list)
    votes: list[VoterDecision] = Field(default_factory=list)


class Voter(Protocol):
    async def cast_vote(self, data: ConsensusInput) -> VoterDecision: ...


class SequenceVoter:
    _SAFE_EGRESS_AFTER_READ_TOOLS: frozenset[str] = frozenset(
        {
            "web.search",
            "web.fetch",
        }
    )

    def __init__(
        self,
        *,
        analyzer: BehavioralSequenceAnalyzer,
        history: SessionActionHistoryStore,
    ) -> None:
        self._analyzer = analyzer
        self._history = history

    async def cast_vote(self, data: ConsensusInput) -> VoterDecision:
        findings = self._analyzer.analyze(history=self._history, candidate_action=data.action)
        if not findings:
            return VoterDecision(
                voter="BehavioralSequenceAnalyzer",
                decision=VoteKind.ALLOW,
                risk_tier=RiskTier.LOW,
                reason_codes=["sequence:ok"],
            )
        if any(item.pattern_name == "exfil_after_read" for item in findings):
            tool_name = str(data.action.tool_name).strip()
            reasons = [item.reason_code for item in findings]
            if tool_name in self._SAFE_EGRESS_AFTER_READ_TOOLS:
                return VoterDecision(
                    voter="BehavioralSequenceAnalyzer",
                    decision=VoteKind.ALLOW,
                    risk_tier=RiskTier.MEDIUM,
                    reason_codes=[
                        *reasons,
                        "sequence:allow_safe_egress_after_read",
                    ],
                )
            highest = max(findings, key=lambda item: risk_rank(item.risk_tier))
            kind = (
                VoteKind.BLOCK
                if highest.risk_tier in {RiskTier.HIGH, RiskTier.CRITICAL}
                else VoteKind.FLAG
            )
            return VoterDecision(
                voter="BehavioralSequenceAnalyzer",
                decision=kind,
                risk_tier=highest.risk_tier,
                reason_codes=reasons,
            )
        highest = max(findings, key=lambda item: risk_rank(item.risk_tier))
        kind = (
            VoteKind.BLOCK
            if highest.risk_tier in {RiskTier.HIGH, RiskTier.CRITICAL}
            else VoteKind.FLAG
        )
        reasons = [item.reason_code for item in findings]
        return VoterDecision(
            voter="BehavioralSequenceAnalyzer",
            decision=kind,
            risk_tier=highest.risk_tier,
            reason_codes=reasons,
        )


class ResourceVoter:
    def __init__(
        self,
        *,
        monitor: ResourceAccessMonitor,
        history: SessionActionHistoryStore,
    ) -> None:
        self._monitor = monitor
        self._history = history

    async def cast_vote(self, data: ConsensusInput) -> VoterDecision:
        findings = self._monitor.analyze(history=self._history, candidate_action=data.action)
        if not findings:
            return VoterDecision(
                voter="ResourceAccessMonitor",
                decision=VoteKind.ALLOW,
                risk_tier=RiskTier.LOW,
                reason_codes=["resource:ok"],
            )
        highest = max(findings, key=lambda item: risk_rank(item.risk_tier))
        kind = (
            VoteKind.BLOCK
            if highest.risk_tier in {RiskTier.HIGH, RiskTier.CRITICAL}
            else VoteKind.FLAG
        )
        return VoterDecision(
            voter="ResourceAccessMonitor",
            decision=kind,
            risk_tier=highest.risk_tier,
            reason_codes=[item.reason_code for item in findings],
        )


class TraceVoter:
    async def cast_vote(self, data: ConsensusInput) -> VoterDecision:
        if data.trace_result.allowed:
            return VoterDecision(
                voter="ExecutionTraceVerifier",
                decision=VoteKind.ALLOW,
                risk_tier=RiskTier.LOW,
                reason_codes=[data.trace_result.reason_code],
            )
        return VoterDecision(
            voter="ExecutionTraceVerifier",
            decision=VoteKind.BLOCK,
            risk_tier=data.trace_result.risk_tier,
            reason_codes=[data.trace_result.reason_code],
        )


class NetworkVoter:
    def __init__(self, *, monitor: NetworkIntelligenceMonitor) -> None:
        self._monitor = monitor

    async def cast_vote(self, data: ConsensusInput) -> VoterDecision:
        if not data.network_metadata:
            return VoterDecision(
                voter="NetworkIntelligenceMonitor",
                decision=VoteKind.ALLOW,
                risk_tier=RiskTier.LOW,
                reason_codes=["network:none"],
            )

        decisions = await asyncio.gather(
            *[
                self._monitor.evaluate(
                    metadata=item,
                    declared_domains=list(data.declared_domains),
                    risk_tier=data.action.risk_tier,
                )
                for item in data.network_metadata
            ]
        )
        highest = max(decisions, key=lambda item: risk_rank(item.risk_tier))
        if any(item.decision == NetworkMonitorDecisionKind.BLOCK for item in decisions):
            vote = VoteKind.BLOCK
        elif any(item.decision == NetworkMonitorDecisionKind.FLAG for item in decisions):
            vote = VoteKind.FLAG
        else:
            vote = VoteKind.ALLOW

        reason_codes: list[str] = []
        for item in decisions:
            reason_codes.extend(item.reason_codes)

        suspicious = vote in {VoteKind.FLAG, VoteKind.BLOCK}
        for metadata_item in data.network_metadata:
            self._monitor.record_learning(
                metadata=metadata_item,
                allow_or_confirmed=(vote == VoteKind.ALLOW),
                suspicious=suspicious,
                lockdown=False,
            )

        return VoterDecision(
            voter="NetworkIntelligenceMonitor",
            decision=vote,
            risk_tier=highest.risk_tier,
            reason_codes=list(dict.fromkeys(reason_codes)) or ["network:ok"],
        )


def _strict_metadata_bool(value: Any, *, default: bool) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, int) and value in {0, 1}:
        return bool(value)
    return default


class ActionMonitorVoter:
    """Metadata-only action monitor voter used in M5 consensus path."""

    async def cast_vote(self, data: ConsensusInput) -> VoterDecision:
        if contains_freeform_text(data.metadata_payload):
            return VoterDecision(
                voter="ActionMonitorVoter",
                decision=VoteKind.BLOCK,
                risk_tier=RiskTier.CRITICAL,
                reason_codes=["action_monitor:raw_text_payload_forbidden"],
            )

        action = data.action
        session_tainted = _strict_metadata_bool(
            data.metadata_payload.get("session_tainted"),
            default=True,
        )
        trusted_input = _strict_metadata_bool(
            data.metadata_payload.get("trusted_input"),
            default=False,
        )
        if trusted_input and not session_tainted:
            return VoterDecision(
                voter="ActionMonitorVoter",
                decision=VoteKind.ALLOW,
                risk_tier=RiskTier.LOW,
                reason_codes=["action_monitor:clean_session_trust_planner"],
            )

        if action.action_kind in {
            ActionKind.EGRESS,
            ActionKind.FS_WRITE,
            ActionKind.MEMORY_WRITE,
            ActionKind.MESSAGE_SEND,
        } and session_tainted:
            return VoterDecision(
                voter="ActionMonitorVoter",
                decision=VoteKind.FLAG,
                risk_tier=RiskTier.HIGH,
                reason_codes=["action_monitor:side_effect_on_tainted_session"],
            )
        if action.action_kind in {
            ActionKind.EGRESS,
            ActionKind.FS_WRITE,
            ActionKind.MEMORY_WRITE,
            ActionKind.MESSAGE_SEND,
        } and not trusted_input:
            return VoterDecision(
                voter="ActionMonitorVoter",
                decision=VoteKind.FLAG,
                risk_tier=RiskTier.HIGH,
                reason_codes=["action_monitor:untrusted_input_side_effect"],
            )

        return VoterDecision(
            voter="ActionMonitorVoter",
            decision=VoteKind.ALLOW,
            risk_tier=RiskTier.LOW,
            reason_codes=["action_monitor:ok"],
        )


class ConsensusPolicy(BaseModel):
    required_approvals_low: int = 1
    required_approvals_medium: int = 3
    required_approvals_high: int = 4
    required_approvals_critical: int = 5
    veto_for_high_and_critical: bool = True
    voter_timeout_seconds: float = 0.5


class ConsensusVotingSystem:
    """Aggregates isolated voter decisions into ALLOW/BLOCK/REQUIRE_CONFIRMATION."""

    def __init__(
        self,
        *,
        voters: list[Voter],
        policy: ConsensusPolicy | None = None,
        audit_hook: Any | None = None,
    ) -> None:
        self._voters = list(voters)
        self._policy = policy or ConsensusPolicy()
        self._audit_hook = audit_hook

    async def evaluate(self, data: ConsensusInput) -> ConsensusDecision:
        vote_payload = data.model_dump_json()
        session_id = data.action.origin.session_id
        votes = await asyncio.gather(
            *[
                self._evaluate_voter(voter=voter, vote_payload=vote_payload)
                for voter in self._voters
            ]
        )

        risk_tier = _max_risk(votes) if votes else RiskTier.LOW
        required = self._required_approvals(risk_tier)
        approvals = sum(1 for vote in votes if vote.decision == VoteKind.ALLOW)
        blocks = [vote for vote in votes if vote.decision == VoteKind.BLOCK]
        flags = [vote for vote in votes if vote.decision == VoteKind.FLAG]

        if self._policy.veto_for_high_and_critical and risk_tier in {
            RiskTier.HIGH,
            RiskTier.CRITICAL,
        } and blocks:
            decision = ConsensusDecision(
                decision=ControlDecision.BLOCK,
                risk_tier=risk_tier,
                reason_codes=[f"consensus:veto:{vote.voter}" for vote in blocks],
                votes=votes,
            )
            self._audit(decision, session_id=session_id)
            return decision

        if blocks:
            decision = ConsensusDecision(
                decision=ControlDecision.REQUIRE_CONFIRMATION,
                risk_tier=risk_tier,
                reason_codes=[f"consensus:block_vote:{vote.voter}" for vote in blocks],
                votes=votes,
            )
            self._audit(decision, session_id=session_id)
            return decision

        if approvals >= required and not flags:
            decision = ConsensusDecision(
                decision=ControlDecision.ALLOW,
                risk_tier=risk_tier,
                reason_codes=["consensus:threshold_met"],
                votes=votes,
            )
            self._audit(decision, session_id=session_id)
            return decision

        if approvals >= required and flags:
            decision = ConsensusDecision(
                decision=ControlDecision.REQUIRE_CONFIRMATION,
                risk_tier=risk_tier,
                reason_codes=[f"consensus:flag_vote:{vote.voter}" for vote in flags],
                votes=votes,
            )
            self._audit(decision, session_id=session_id)
            return decision

        decision = ConsensusDecision(
            decision=ControlDecision.BLOCK,
            risk_tier=risk_tier,
            reason_codes=["consensus:insufficient_approvals"],
            votes=votes,
        )
        self._audit(decision, session_id=session_id)
        return decision

    async def _evaluate_voter(self, *, voter: Voter, vote_payload: str) -> VoterDecision:
        frozen_input = ConsensusInput.model_validate_json(vote_payload)
        voter_name = voter.__class__.__name__
        try:
            return await asyncio.wait_for(
                voter.cast_vote(frozen_input),
                timeout=self._policy.voter_timeout_seconds,
            )
        except TimeoutError:
            return VoterDecision(
                voter=voter_name,
                decision=VoteKind.FLAG,
                risk_tier=RiskTier.HIGH,
                reason_codes=["consensus:voter_timeout"],
            )
        except (OSError, RuntimeError, TypeError, ValueError):
            return VoterDecision(
                voter=voter_name,
                decision=VoteKind.FLAG,
                risk_tier=RiskTier.HIGH,
                reason_codes=["consensus:voter_error"],
            )

    def _required_approvals(self, risk_tier: RiskTier) -> int:
        if risk_tier == RiskTier.CRITICAL:
            return self._policy.required_approvals_critical
        if risk_tier == RiskTier.HIGH:
            return self._policy.required_approvals_high
        if risk_tier == RiskTier.MEDIUM:
            return self._policy.required_approvals_medium
        return self._policy.required_approvals_low

    def _audit(self, decision: ConsensusDecision, *, session_id: str) -> None:
        if self._audit_hook is None:
            return
        self._audit_hook(
            {
                "timestamp": datetime.now(UTC).isoformat(),
                "session_id": session_id,
                "decision": decision.decision,
                "risk_tier": decision.risk_tier,
                "reason_codes": list(decision.reason_codes),
                "votes": [vote.model_dump(mode="json") for vote in decision.votes],
            }
        )


def _max_risk(votes: list[VoterDecision]) -> RiskTier:
    highest = RiskTier.LOW
    for vote in votes:
        if risk_rank(vote.risk_tier) > risk_rank(highest):
            highest = vote.risk_tier
    return highest
