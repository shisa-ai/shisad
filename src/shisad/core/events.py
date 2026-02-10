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


class SessionMessageReceived(BaseEvent):
    """A session received a user message."""

    content_hash: str = ""


class SessionMessageResponded(BaseEvent):
    """A session produced an assistant response."""

    response_hash: str = ""
    blocked_actions: int = 0
    executed_actions: int = 0


class SessionTerminated(BaseEvent):
    """A session was terminated."""

    reason: str = ""


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


class ToolRejected(BaseEvent):
    """A tool call was rejected by the PEP."""

    tool_name: ToolName
    decision: PEPDecisionKind = PEPDecisionKind.REJECT
    reason: str = ""


class ToolExecuted(BaseEvent):
    """A tool call was executed."""

    tool_name: ToolName
    success: bool = True
    error: str = ""


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


class TaskScheduled(BaseEvent):
    """Background task created."""

    task_id: str = ""
    name: str = ""


class TaskTriggered(BaseEvent):
    """Background task trigger accepted."""

    task_id: str = ""
    event_type: str = ""


class OutputFirewallAlert(BaseEvent):
    """Outbound content triggered firewall controls."""

    blocked: bool = False
    require_confirmation: bool = False
    reason_codes: list[str] = Field(default_factory=list)
    secret_findings: list[str] = Field(default_factory=list)


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
    allowed: bool = False
    reason: str = ""
    credential_placeholders: list[str] = Field(default_factory=list)


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
    | SessionMessageReceived
    | SessionMessageResponded
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
    | TaskScheduled
    | TaskTriggered
    | OutputFirewallAlert
    | SandboxDegraded
    | SandboxEscapeDetected
    | ProxyRequestEvaluated
    | SessionRolledBack
    | SandboxExecutionIntent
    | SandboxPreCheckpoint
    | SandboxExecutionCompleted
)

EVENT_TYPES: dict[str, type[BaseEvent]] = {
    "SessionCreated": SessionCreated,
    "SessionMessageReceived": SessionMessageReceived,
    "SessionMessageResponded": SessionMessageResponded,
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
    "TaskScheduled": TaskScheduled,
    "TaskTriggered": TaskTriggered,
    "OutputFirewallAlert": OutputFirewallAlert,
    "SandboxDegraded": SandboxDegraded,
    "SandboxEscapeDetected": SandboxEscapeDetected,
    "ProxyRequestEvaluated": ProxyRequestEvaluated,
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
