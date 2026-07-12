"""Consensus voting system for metadata-only control-plane decisions."""

from __future__ import annotations

import asyncio
import re
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Protocol

from pydantic import BaseModel, Field

from shisad.core.action_state import (
    CURRENT_TURN_REMINDER_CREATE_INTENT,
    reminder_create_arguments_are_current_turn_anchored,
)
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
    metadata_value_is_current_turn_anchored,
    risk_rank,
)
from shisad.security.control_plane.sequence import BehavioralSequenceAnalyzer
from shisad.security.control_plane.trace import PlanVerificationResult
from shisad.security.intent_matching import (
    normalize_intent_text,
    strip_optional_greeting_prefix,
)

TRACE_VOTER_NAME = "ExecutionTraceVerifier"
_CURRENT_TURN_LOCAL_READ_FILESYSTEM_INTENT = "current_turn_local_read"
_READ_ONLY_FILESYSTEM_ACTION_KINDS = frozenset({ActionKind.FS_READ, ActionKind.FS_LIST})


class VoteKind(StrEnum):
    ALLOW = "ALLOW"
    FLAG = "FLAG"
    BLOCK = "BLOCK"


class VoterDecision(BaseModel, frozen=True):
    voter: str
    decision: VoteKind
    risk_tier: RiskTier
    reason_codes: list[str] = Field(default_factory=list)
    details: dict[str, Any] = Field(default_factory=dict)


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
    _SAFE_TRUSTED_READONLY_MEMORY_TOOLS: frozenset[str] = frozenset(
        {
            "reminder.list",
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
        reasons = [item.reason_code for item in findings]
        if self._allow_structural_current_turn_reminder_after_rapid_fire(
            data=data,
            findings=findings,
        ):
            return VoterDecision(
                voter="BehavioralSequenceAnalyzer",
                decision=VoteKind.ALLOW,
                risk_tier=RiskTier.MEDIUM,
                reason_codes=[
                    *reasons,
                    "sequence:allow_structural_current_turn_reminder",
                ],
            )
        if self._allow_trusted_readonly_memory_after_rapid_fire(data=data, findings=findings):
            return VoterDecision(
                voter="BehavioralSequenceAnalyzer",
                decision=VoteKind.ALLOW,
                risk_tier=RiskTier.MEDIUM,
                reason_codes=[
                    *reasons,
                    "sequence:allow_trusted_readonly_memory_after_rapid_fire",
                ],
            )
        if any(item.pattern_name == "exfil_after_read" for item in findings):
            tool_name = str(data.action.tool_name).strip()
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

    @classmethod
    def _allow_trusted_readonly_memory_after_rapid_fire(
        cls,
        *,
        data: ConsensusInput,
        findings: list[Any],
    ) -> bool:
        if any(item.pattern_name != "rapid_fire" for item in findings):
            return False
        if not data.trace_result.allowed:
            return False
        action = data.action
        tool_name = str(action.tool_name).strip()
        if action.action_kind != ActionKind.MEMORY_READ:
            return False
        if tool_name not in cls._SAFE_TRUSTED_READONLY_MEMORY_TOOLS:
            return False
        if not _strict_metadata_bool(data.metadata_payload.get("trusted_input"), default=False):
            return False
        user_text = str(data.metadata_payload.get("raw_user_text", "")).strip()
        if not user_text:
            return False
        return cls._trusted_readonly_memory_intent_match(
            user_text=user_text,
            tool_name=tool_name,
        )

    @staticmethod
    def _trusted_readonly_memory_intent_match(*, user_text: str, tool_name: str) -> bool:
        normalized = normalize_intent_text(strip_optional_greeting_prefix(user_text))
        if tool_name == "reminder.list":
            return bool(
                re.fullmatch(
                    r"(?:(?:list|show) (?:my )?reminders|what reminders do (?:i|we) have\??)",
                    normalized,
                    flags=re.IGNORECASE,
                )
            )
        return False

    @staticmethod
    def _allow_structural_current_turn_reminder_after_rapid_fire(
        *,
        data: ConsensusInput,
        findings: list[Any],
    ) -> bool:
        if any(item.pattern_name != "rapid_fire" for item in findings):
            return False
        if not data.trace_result.allowed:
            return False
        if data.action.action_kind != ActionKind.MEMORY_WRITE:
            return False
        if str(data.action.tool_name).strip() != "reminder.create":
            return False
        if not _strict_metadata_bool(data.metadata_payload.get("trusted_input"), default=False):
            return False
        if not _strict_metadata_bool(
            data.metadata_payload.get("operator_owned_cli_input"),
            default=False,
        ):
            return False
        action_arguments = data.metadata_payload.get("action_arguments")
        if not isinstance(action_arguments, dict):
            return False
        if (
            str(action_arguments.get("reminder_intent", "")).strip()
            != CURRENT_TURN_REMINDER_CREATE_INTENT
        ):
            return False
        current_turn = str(data.metadata_payload.get("raw_user_text", "")).strip()
        return bool(current_turn) and reminder_create_arguments_are_current_turn_anchored(
            action_arguments,
            current_turn=current_turn,
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
                voter=TRACE_VOTER_NAME,
                decision=VoteKind.ALLOW,
                risk_tier=RiskTier.LOW,
                reason_codes=[data.trace_result.reason_code],
            )
        if self._allows_current_turn_filesystem_read_intent(data):
            return VoterDecision(
                voter=TRACE_VOTER_NAME,
                decision=VoteKind.ALLOW,
                risk_tier=RiskTier.LOW,
                reason_codes=[
                    data.trace_result.reason_code,
                    "trace:current_turn_local_filesystem_read_intent",
                ],
            )
        return VoterDecision(
            voter=TRACE_VOTER_NAME,
            decision=VoteKind.BLOCK,
            risk_tier=data.trace_result.risk_tier,
            reason_codes=[data.trace_result.reason_code],
        )

    @staticmethod
    def _allows_current_turn_filesystem_read_intent(data: ConsensusInput) -> bool:
        if data.trace_result.reason_code != "trace:tdg_confirmation_required":
            return False
        if data.action.action_kind not in _READ_ONLY_FILESYSTEM_ACTION_KINDS:
            return False
        if not _strict_metadata_bool(data.metadata_payload.get("trusted_input"), default=False):
            return False
        if not _strict_metadata_bool(
            data.metadata_payload.get("operator_owned_cli_input"),
            default=False,
        ):
            return False
        intent = str(data.metadata_payload.get("filesystem_intent", "")).strip()
        if not intent:
            action_arguments = data.metadata_payload.get("action_arguments")
            if isinstance(action_arguments, dict):
                intent = str(action_arguments.get("filesystem_intent", "")).strip()
        return intent == _CURRENT_TURN_LOCAL_READ_FILESYSTEM_INTENT


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
    """Taint-aware action monitor voter using structural current-turn anchoring."""

    _SIDE_EFFECT_KINDS: frozenset[ActionKind] = frozenset(
        {
            ActionKind.EGRESS,
            ActionKind.BROWSER_WRITE,
            ActionKind.FS_WRITE,
            ActionKind.MEMORY_WRITE,
            ActionKind.MESSAGE_SEND,
            ActionKind.MCP_EXTERNAL,
            ActionKind.SHELL_EXEC,
        }
    )
    _ANCHOR_IGNORED_ARGUMENT_FIELDS: frozenset[str] = frozenset(
        {
            "action_intent",
            "command_intent",
            "content_length",
            "filesystem_intent",
            "limit",
            "max_bytes",
            "max_results",
            "mode",
            "reminder_intent",
            "request_bytes",
            "request_size",
            "timeout",
            "timeout_seconds",
            "top_k",
        }
    )

    @classmethod
    def _anchor_ignored_fields_for_tool(cls, tool_name: str) -> frozenset[str]:
        ignored = set(cls._ANCHOR_IGNORED_ARGUMENT_FIELDS)
        if tool_name == "note.create":
            ignored.add("key")
        return frozenset(ignored)

    @staticmethod
    def _normalized_text(value: Any) -> str:
        return normalize_intent_text(str(value or ""))

    @classmethod
    def _value_is_current_turn_contained(cls, *, user_text: str, value: Any) -> bool:
        candidate = cls._normalized_text(value)
        if not candidate:
            return True
        return metadata_value_is_current_turn_anchored(
            candidate,
            normalized_current_turn=user_text,
        )

    @classmethod
    def _iter_anchor_argument_values(
        cls,
        value: Any,
        *,
        ignored_fields: frozenset[str],
        field_name: str = "",
    ) -> list[str]:
        lowered_field = field_name.lower().strip()
        if lowered_field in ignored_fields:
            return []
        if isinstance(value, dict):
            values: list[str] = []
            for key, item in value.items():
                values.extend(
                    cls._iter_anchor_argument_values(
                        item,
                        ignored_fields=ignored_fields,
                        field_name=str(key),
                    )
                )
            return values
        if isinstance(value, list):
            values = []
            for item in value:
                values.extend(
                    cls._iter_anchor_argument_values(
                        item,
                        ignored_fields=ignored_fields,
                        field_name=field_name,
                    )
                )
            return values
        if isinstance(value, str):
            normalized = cls._normalized_text(value)
            return [normalized] if normalized else []
        return []

    @staticmethod
    def _omitted_argument_fields(payload: dict[str, Any]) -> set[str]:
        omitted = payload.get("action_argument_omitted_fields")
        if not isinstance(omitted, list):
            return set()
        return {str(item).strip() for item in omitted if str(item).strip()}

    @classmethod
    def _has_unproven_omitted_argument_fields(cls, payload: dict[str, Any]) -> bool:
        omitted_fields = cls._omitted_argument_fields(payload)
        if not omitted_fields:
            return False
        proofs = payload.get("action_argument_omitted_field_proofs")
        if not isinstance(proofs, list):
            return True
        proven_fields = {str(item).strip() for item in proofs if str(item).strip()}
        return not omitted_fields.issubset(proven_fields)

    @classmethod
    def _is_current_turn_anchored(cls, data: ConsensusInput, *, user_text: str) -> bool:
        if cls._has_unproven_omitted_argument_fields(data.metadata_payload):
            return False
        action_arguments = data.metadata_payload.get("action_arguments", {})
        if not isinstance(action_arguments, dict):
            return False
        if (
            str(data.action.tool_name).strip() == "reminder.create"
            and str(action_arguments.get("reminder_intent", "")).strip()
            == CURRENT_TURN_REMINDER_CREATE_INTENT
        ):
            return reminder_create_arguments_are_current_turn_anchored(
                action_arguments,
                current_turn=user_text,
            )
        values = cls._iter_anchor_argument_values(
            action_arguments,
            ignored_fields=cls._anchor_ignored_fields_for_tool(str(data.action.tool_name)),
        )
        if not values and not cls._omitted_argument_fields(data.metadata_payload):
            return False
        normalized_user_text = cls._normalized_text(user_text)
        if not normalized_user_text:
            return False
        return all(
            cls._value_is_current_turn_contained(
                user_text=normalized_user_text,
                value=value,
            )
            for value in values
        )

    async def cast_vote(self, data: ConsensusInput) -> VoterDecision:
        session_tainted = _strict_metadata_bool(
            data.metadata_payload.get("session_tainted"),
            default=True,
        )
        trusted_input = _strict_metadata_bool(
            data.metadata_payload.get("trusted_input"),
            default=False,
        )
        operator_owned_cli_input = _strict_metadata_bool(
            data.metadata_payload.get("operator_owned_cli_input"),
            default=False,
        )
        if trusted_input and not session_tainted:
            return VoterDecision(
                voter="ActionMonitorVoter",
                decision=VoteKind.ALLOW,
                risk_tier=RiskTier.LOW,
                reason_codes=["action_monitor:clean_session_trust_planner"],
            )
        if contains_freeform_text(data.metadata_payload):
            return VoterDecision(
                voter="ActionMonitorVoter",
                decision=VoteKind.BLOCK,
                risk_tier=RiskTier.CRITICAL,
                reason_codes=["action_monitor:raw_text_payload_forbidden"],
            )

        action = data.action

        if (
            operator_owned_cli_input
            and not session_tainted
            and action.action_kind in self._SIDE_EFFECT_KINDS
        ):
            return VoterDecision(
                voter="ActionMonitorVoter",
                decision=VoteKind.ALLOW,
                risk_tier=RiskTier.LOW,
                reason_codes=["action_monitor:clean_operator_cli_intent"],
            )

        if action.action_kind in self._SIDE_EFFECT_KINDS and session_tainted:
            user_text = str(data.metadata_payload.get("raw_user_text", "")).strip()
            if (
                trusted_input
                and operator_owned_cli_input
                and user_text
                and self._is_current_turn_anchored(data, user_text=user_text)
            ):
                return VoterDecision(
                    voter="ActionMonitorVoter",
                    decision=VoteKind.ALLOW,
                    risk_tier=RiskTier.LOW,
                    reason_codes=["action_monitor:current_turn_anchored"],
                )
            return VoterDecision(
                voter="ActionMonitorVoter",
                decision=VoteKind.FLAG,
                risk_tier=RiskTier.HIGH,
                reason_codes=["action_monitor:side_effect_on_tainted_session"],
            )
        if action.action_kind in self._SIDE_EFFECT_KINDS and not trusted_input:
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

        if (
            self._policy.veto_for_high_and_critical
            and risk_tier
            in {
                RiskTier.HIGH,
                RiskTier.CRITICAL,
            }
            and blocks
        ):
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
