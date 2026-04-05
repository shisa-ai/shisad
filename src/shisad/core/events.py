"""Event system for shisad.

In-process async event bus with typed event schemas. Events are immutable
once emitted and are persisted to the audit log.
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from collections import defaultdict
from datetime import UTC, datetime
from typing import Any, Protocol

from pydantic import BaseModel, Field

from shisad.core.types import (
    EventId,
    PEPDecisionKind,
    SessionId,
    ToolName,
    UserId,
)

logger = logging.getLogger(__name__)


# --- Event schemas ---


class BaseEvent(BaseModel, frozen=True):
    """Base class for all events. Immutable once created."""

    event_id: EventId = Field(default_factory=lambda: EventId(uuid.uuid4().hex))
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    session_id: SessionId | None = None
    actor: str = ""


class SessionCreated(BaseEvent):
    """A new session was created."""

    user_id: UserId
    workspace_id: str = ""


class SessionModeChanged(BaseEvent):
    """Session mode transition recorded."""

    mode: str = "default"
    changed: bool = False
    reason: str = ""


class SessionMessageReceived(BaseEvent):
    """A session received a user message."""

    content_hash: str = ""
    channel: str = ""
    user_id: str = ""
    workspace_id: str = ""
    trust_level: str = ""
    taint_labels: list[str] = Field(default_factory=list)
    risk_score: float = 0.0


class SessionMessageResponded(BaseEvent):
    """A session produced an assistant response."""

    response_hash: str = ""
    blocked_actions: int = 0
    executed_actions: int = 0
    trust_level: str = ""
    taint_labels: list[str] = Field(default_factory=list)
    risk_score: float = 0.0


class ChannelPairingRequested(BaseEvent):
    """Unmapped external identity attempted ingress on a default-deny channel."""

    channel: str = ""
    external_user_id: str = ""
    workspace_hint: str = ""
    reason: str = "identity_not_allowlisted"


class ChannelPairingProposalGenerated(BaseEvent):
    """Proposal artifact generated from pairing request evidence."""

    proposal_id: str = ""
    proposal_path: str = ""
    entries_count: int = 0


class ChannelDeliveryAttempted(BaseEvent):
    """Outbound channel delivery attempt for ingress response/audit trail."""

    channel: str = ""
    recipient: str = ""
    workspace_hint: str = ""
    thread_id: str = ""
    sent: bool = False
    reason: str = ""


class SessionTerminated(BaseEvent):
    """A session was terminated."""

    reason: str = ""


class SessionRehydrated(BaseEvent):
    """A persisted/checkpoint/archive session state was accepted and restored."""

    source: str = ""
    schema_version: int = 0
    migrated: bool = False
    migration_reason: str = ""
    role: str = ""
    mode: str = ""
    lockdown_level: str = ""


class SessionRehydrateRejected(BaseEvent):
    """A persisted/checkpoint/archive session state was rejected."""

    source: str = ""
    reason: str = ""
    schema_version: int = 0
    path: str = ""


class SessionArchiveExported(BaseEvent):
    """A bounded single-session archive was written."""

    archive_path: str = ""
    original_session_id: str = ""
    transcript_entries: int = 0
    checkpoint_count: int = 0
    archive_sha256: str = ""


class SessionArchiveImported(BaseEvent):
    """A bounded single-session archive was imported into a fresh session."""

    archive_path: str = ""
    original_session_id: str = ""
    imported_session_id: str = ""
    transcript_entries: int = 0
    checkpoint_count: int = 0


class CapabilityGranted(BaseEvent):
    """Capabilities were granted to a session by a non-agent actor."""

    capabilities: list[str] = Field(default_factory=list)
    granted_by: str = ""
    reason: str = ""


class ToolProposed(BaseEvent):
    """The planner proposed a tool call."""

    tool_name: ToolName
    arguments: dict[str, Any] = Field(default_factory=dict)


class ToolApproved(BaseEvent):
    """A tool call was approved by the PEP."""

    tool_name: ToolName
    decision: PEPDecisionKind = PEPDecisionKind.ALLOW
    approval_session_id: str = ""
    approval_task_envelope_id: str = ""
    approval_confirmation_id: str = ""
    approval_decision_nonce: str = ""
    approval_timestamp: str = ""


class ToolRejected(BaseEvent):
    """A tool call was rejected by the PEP."""

    tool_name: ToolName
    decision: PEPDecisionKind = PEPDecisionKind.REJECT
    reason: str = ""
    approval_session_id: str = ""
    approval_task_envelope_id: str = ""
    approval_confirmation_id: str = ""
    approval_decision_nonce: str = ""
    approval_timestamp: str = ""


class ToolExecuted(BaseEvent):
    """A tool call was executed."""

    tool_name: ToolName
    success: bool = True
    error: str = ""
    approval_session_id: str = ""
    approval_task_envelope_id: str = ""
    approval_confirmation_id: str = ""
    approval_decision_nonce: str = ""
    approval_timestamp: str = ""


class AnomalyReported(BaseEvent):
    """An anomaly was detected and reported (alarm bell)."""

    severity: str = "warning"
    description: str = ""
    recommended_action: str = ""


class CredentialAccessed(BaseEvent):
    """A credential reference was used (never logs raw values)."""

    credential_ref: str
    destination_host: str = ""
    allowed: bool = True
    reason: str = ""


class MonitorEvaluated(BaseEvent):
    """Action monitor outcome for a planner proposal."""

    tool_name: ToolName
    decision: str = ""
    reason: str = ""


class LockdownChanged(BaseEvent):
    """Session lockdown state transition."""

    level: str = ""
    reason: str = ""
    trigger: str = ""


class RateLimitTriggered(BaseEvent):
    """Rate limiter blocked or escalated tool activity."""

    tool_name: ToolName
    reason: str = ""
    count: int = 0


class MemoryEntryStored(BaseEvent):
    """Memory entry persisted."""

    memory_id: str = ""
    key: str = ""
    source_origin: str = ""


class MemoryEntryDeleted(BaseEvent):
    """Memory entry soft-deleted."""

    memory_id: str = ""


class SkillReviewRequested(BaseEvent):
    """Skill review request completed with static findings."""

    skill_name: str = ""
    version: str = ""
    source_repo: str = ""
    signature_status: str = ""
    findings_count: int = 0


class SkillInstalled(BaseEvent):
    """Skill installation decision recorded."""

    skill_name: str = ""
    version: str = ""
    source_repo: str = ""
    manifest_hash: str = ""
    status: str = ""
    allowed: bool = False
    signature_status: str = ""
    findings_count: int = 0
    artifact_state: str = ""


class SkillProfiled(BaseEvent):
    """Skill capability profile generated."""

    skill_name: str = ""
    version: str = ""
    capabilities: dict[str, list[str]] = Field(default_factory=dict)


class SkillRevoked(BaseEvent):
    """Installed skill moved into revoked state."""

    skill_name: str = ""
    reason: str = ""
    previous_state: str = ""


class SkillToolRegistrationDropped(BaseEvent):
    """Reviewed skill tool was fail-closed during registration/reload."""

    skill_name: str = ""
    version: str = ""
    tool_name: ToolName
    reason_code: str = ""
    registration_source: str = ""
    expected_hash_prefix: str = ""
    actual_hash_prefix: str = ""


class TaskScheduled(BaseEvent):
    """Background task created."""

    task_id: str = ""
    name: str = ""


class TaskTriggered(BaseEvent):
    """Background task trigger accepted."""

    task_id: str = ""
    event_type: str = ""


class TaskDelegationAdvisory(BaseEvent):
    """Advisory command/task delegation recommendation (telemetry-only)."""

    delegate: bool = False
    action_count: int = 0
    reason_codes: list[str] = Field(default_factory=list)
    tools: list[str] = Field(default_factory=list)


class TaskSessionStarted(BaseEvent):
    """Ephemeral delegated TASK session started from a COMMAND session."""

    parent_session_id: str = ""
    task_description_hash: str = ""
    file_refs: list[str] = Field(default_factory=list)
    capabilities: list[str] = Field(default_factory=list)
    executor: str = "planner"
    agent: str = ""
    handoff_mode: str = "summary_only"


class TaskSessionCompleted(BaseEvent):
    """Delegated TASK session completed and returned a structured handoff."""

    parent_session_id: str = ""
    success: bool = True
    reason: str = ""
    duration_ms: int = 0
    files_changed: list[str] = Field(default_factory=list)
    executor: str = "planner"
    agent: str = ""
    cost: float | None = None
    proposal_ref: str = ""
    raw_log_ref: str = ""
    handoff_mode: str = "summary_only"
    command_context: str = "clean"
    taint_labels: list[str] = Field(default_factory=list)
    self_check_status: str = ""
    self_check_ref: str = ""
    summary_checkpoint_ref: str = ""


class CodingAgentSelected(BaseEvent):
    """Coding-agent selection result for an isolated TASK invocation."""

    preferred_agent: str = ""
    fallback_agents: list[str] = Field(default_factory=list)
    selected_agent: str = ""
    fallback_used: bool = False
    attempts: list[dict[str, Any]] = Field(default_factory=list)


class CodingAgentSessionStarted(BaseEvent):
    """ACP-backed coding-agent task started inside an isolated worktree."""

    agent: str = ""
    task_kind: str = ""
    read_only: bool = False
    worktree_path: str = ""


class CodingAgentSessionCompleted(BaseEvent):
    """ACP-backed coding-agent task finished and returned a proposal/log summary."""

    agent: str = ""
    task_kind: str = ""
    success: bool = True
    reason: str = ""
    stop_reason: str = ""
    duration_ms: int = 0
    cost: float | None = None
    files_changed: list[str] = Field(default_factory=list)


class CommandContextDegraded(BaseEvent):
    """COMMAND session ingested raw TASK content and entered degraded mode."""

    task_session_id: str = ""
    reason: str = ""
    recovery_checkpoint_id: str = ""


class OutputFirewallAlert(BaseEvent):
    """Outbound content triggered firewall controls."""

    blocked: bool = False
    require_confirmation: bool = False
    reason_codes: list[str] = Field(default_factory=list)
    secret_findings: list[str] = Field(default_factory=list)
    pii_findings: list[str] = Field(default_factory=list)


class SandboxDegraded(BaseEvent):
    """Sandbox backend could not enforce requested controls."""

    tool_name: ToolName
    backend: str = ""
    controls: list[str] = Field(default_factory=list)


class SandboxEscapeDetected(BaseEvent):
    """Sandbox escape signal detected during execution."""

    tool_name: ToolName
    reason: str = ""


class ProxyRequestEvaluated(BaseEvent):
    """Egress proxy evaluated an outbound request."""

    tool_name: ToolName
    destination_host: str = ""
    destination_port: int | None = None
    protocol: str = "https"
    request_size: int = 0
    resolved_addresses: list[str] = Field(default_factory=list)
    allowed: bool = False
    reason: str = ""
    credential_placeholders: list[str] = Field(default_factory=list)
    origin: dict[str, str] = Field(default_factory=dict)


class ControlPlaneActionObserved(BaseEvent):
    """Metadata-only action observation emitted to control-plane stream."""

    tool_name: ToolName
    action_kind: str = ""
    resource_id: str = ""
    decision: str = ""
    reason_codes: list[str] = Field(default_factory=list)
    origin: dict[str, str] = Field(default_factory=dict)


class ControlPlaneResourceObserved(BaseEvent):
    """Metadata-only resource access observation."""

    tool_name: ToolName
    action_kind: str = ""
    resource_id: str = ""
    category: str = ""
    origin: dict[str, str] = Field(default_factory=dict)


class ControlPlaneNetworkObserved(BaseEvent):
    """Metadata-only network access observation."""

    tool_name: ToolName
    destination_host: str = ""
    destination_port: int | None = None
    protocol: str = "https"
    request_size: int = 0
    allowed: bool = False
    reason: str = ""
    resolved_addresses: list[str] = Field(default_factory=list)
    origin: dict[str, str] = Field(default_factory=dict)


class PlanCommitted(BaseEvent):
    """Plan commitment created for a session."""

    plan_hash: str = ""
    stage: str = ""
    expires_at: str = ""


class PlanAmended(BaseEvent):
    """Plan commitment amended with explicit approval."""

    plan_hash: str = ""
    amendment_of: str = ""
    stage: str = ""


class PlanCancelled(BaseEvent):
    """Plan commitment cancelled."""

    plan_hash: str = ""
    reason: str = ""


class PlanViolationDetected(BaseEvent):
    """Execution action violated active committed plan."""

    tool_name: ToolName
    action_kind: str = ""
    reason_code: str = ""
    risk_tier: str = ""


class ConsensusEvaluated(BaseEvent):
    """Consensus voting decision for one proposed action."""

    tool_name: ToolName
    decision: str = ""
    risk_tier: str = ""
    reason_codes: list[str] = Field(default_factory=list)
    votes: list[dict[str, Any]] = Field(default_factory=list)


class SessionRolledBack(BaseEvent):
    """Session state restored to a prior checkpoint."""

    checkpoint_id: str = ""


class SandboxExecutionIntent(BaseEvent):
    """Write-ahead envelope before sandbox subprocess launch."""

    tool_name: ToolName
    action_hash: str
    command_hash: str = ""


class SandboxPreCheckpoint(BaseEvent):
    """Audit marker before destructive execution checkpoint workflow."""

    tool_name: ToolName
    action_hash: str


class SandboxExecutionCompleted(BaseEvent):
    """Execution envelope completion record."""

    tool_name: ToolName
    action_hash: str
    success: bool = True
    error: str = ""


# Union of all event types for type-safe handling
type AnyEvent = (
    SessionCreated
    | SessionModeChanged
    | SessionMessageReceived
    | SessionMessageResponded
    | ChannelPairingRequested
    | ChannelPairingProposalGenerated
    | ChannelDeliveryAttempted
    | SessionTerminated
    | CapabilityGranted
    | ToolProposed
    | ToolApproved
    | ToolRejected
    | ToolExecuted
    | AnomalyReported
    | CredentialAccessed
    | MonitorEvaluated
    | LockdownChanged
    | RateLimitTriggered
    | MemoryEntryStored
    | MemoryEntryDeleted
    | SkillReviewRequested
    | SkillInstalled
    | SkillProfiled
    | SkillRevoked
    | SkillToolRegistrationDropped
    | TaskScheduled
    | TaskTriggered
    | TaskDelegationAdvisory
    | TaskSessionStarted
    | TaskSessionCompleted
    | CodingAgentSelected
    | CodingAgentSessionStarted
    | CodingAgentSessionCompleted
    | CommandContextDegraded
    | OutputFirewallAlert
    | SandboxDegraded
    | SandboxEscapeDetected
    | ProxyRequestEvaluated
    | ControlPlaneActionObserved
    | ControlPlaneResourceObserved
    | ControlPlaneNetworkObserved
    | PlanCommitted
    | PlanAmended
    | PlanCancelled
    | PlanViolationDetected
    | ConsensusEvaluated
    | SessionRolledBack
    | SandboxExecutionIntent
    | SandboxPreCheckpoint
    | SandboxExecutionCompleted
)

EVENT_TYPES: dict[str, type[BaseEvent]] = {
    "SessionCreated": SessionCreated,
    "SessionModeChanged": SessionModeChanged,
    "SessionMessageReceived": SessionMessageReceived,
    "SessionMessageResponded": SessionMessageResponded,
    "ChannelPairingRequested": ChannelPairingRequested,
    "ChannelPairingProposalGenerated": ChannelPairingProposalGenerated,
    "ChannelDeliveryAttempted": ChannelDeliveryAttempted,
    "SessionTerminated": SessionTerminated,
    "CapabilityGranted": CapabilityGranted,
    "ToolProposed": ToolProposed,
    "ToolApproved": ToolApproved,
    "ToolRejected": ToolRejected,
    "ToolExecuted": ToolExecuted,
    "AnomalyReported": AnomalyReported,
    "CredentialAccessed": CredentialAccessed,
    "MonitorEvaluated": MonitorEvaluated,
    "LockdownChanged": LockdownChanged,
    "RateLimitTriggered": RateLimitTriggered,
    "MemoryEntryStored": MemoryEntryStored,
    "MemoryEntryDeleted": MemoryEntryDeleted,
    "SkillReviewRequested": SkillReviewRequested,
    "SkillInstalled": SkillInstalled,
    "SkillProfiled": SkillProfiled,
    "SkillRevoked": SkillRevoked,
    "SkillToolRegistrationDropped": SkillToolRegistrationDropped,
    "TaskScheduled": TaskScheduled,
    "TaskTriggered": TaskTriggered,
    "TaskDelegationAdvisory": TaskDelegationAdvisory,
    "TaskSessionStarted": TaskSessionStarted,
    "TaskSessionCompleted": TaskSessionCompleted,
    "CodingAgentSelected": CodingAgentSelected,
    "CodingAgentSessionStarted": CodingAgentSessionStarted,
    "CodingAgentSessionCompleted": CodingAgentSessionCompleted,
    "CommandContextDegraded": CommandContextDegraded,
    "OutputFirewallAlert": OutputFirewallAlert,
    "SandboxDegraded": SandboxDegraded,
    "SandboxEscapeDetected": SandboxEscapeDetected,
    "ProxyRequestEvaluated": ProxyRequestEvaluated,
    "ControlPlaneActionObserved": ControlPlaneActionObserved,
    "ControlPlaneResourceObserved": ControlPlaneResourceObserved,
    "ControlPlaneNetworkObserved": ControlPlaneNetworkObserved,
    "PlanCommitted": PlanCommitted,
    "PlanAmended": PlanAmended,
    "PlanCancelled": PlanCancelled,
    "PlanViolationDetected": PlanViolationDetected,
    "ConsensusEvaluated": ConsensusEvaluated,
    "SessionRolledBack": SessionRolledBack,
    "SandboxExecutionIntent": SandboxExecutionIntent,
    "SandboxPreCheckpoint": SandboxPreCheckpoint,
    "SandboxExecutionCompleted": SandboxExecutionCompleted,
}


# --- Event persistence protocol ---


class EventPersister(Protocol):
    """Protocol for event persistence backends (audit log)."""

    async def persist(self, event: BaseEvent) -> None: ...


# --- Event bus ---


type EventHandler = Any  # Callable[[BaseEvent], Awaitable[None]]


class EventBus:
    """In-process async event bus.

    Supports subscribe/publish with typed event routing.
    Events are persisted via an optional EventPersister (the audit log).
    """

    def __init__(self, persister: EventPersister | None = None) -> None:
        self._handlers: defaultdict[type[BaseEvent], list[EventHandler]] = defaultdict(list)
        self._global_handlers: list[EventHandler] = []
        self._persister = persister

    def subscribe(
        self,
        event_type: type[BaseEvent],
        handler: EventHandler,
    ) -> None:
        """Subscribe to a specific event type."""
        self._handlers[event_type].append(handler)

    def subscribe_all(self, handler: EventHandler) -> None:
        """Subscribe to all events."""
        self._global_handlers.append(handler)

    async def publish(self, event: BaseEvent) -> None:
        """Publish an event to all subscribers and persist it.

        Events are immutable once published. Handlers are called concurrently
        but failures in one handler don't prevent others from running.
        """
        # Persist first (audit log is the source of truth)
        if self._persister is not None:
            await self._persister.persist(event)

        # Dispatch to type-specific handlers
        handlers = list(self._handlers.get(type(event), []))
        handlers.extend(self._global_handlers)

        if not handlers:
            return

        results = await asyncio.gather(
            *[h(event) for h in handlers],
            return_exceptions=True,
        )
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                logger.error(
                    "Event handler %s failed for %s: %s",
                    handlers[i],
                    type(event).__name__,
                    result,
                )
