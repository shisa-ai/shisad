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


class SessionTerminated(BaseEvent):
    """A session was terminated."""

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


# Union of all event types for type-safe handling
type AnyEvent = (
    SessionCreated
    | SessionTerminated
    | ToolProposed
    | ToolApproved
    | ToolRejected
    | ToolExecuted
    | AnomalyReported
    | CredentialAccessed
)

EVENT_TYPES: dict[str, type[BaseEvent]] = {
    "SessionCreated": SessionCreated,
    "SessionTerminated": SessionTerminated,
    "ToolProposed": ToolProposed,
    "ToolApproved": ToolApproved,
    "ToolRejected": ToolRejected,
    "ToolExecuted": ToolExecuted,
    "AnomalyReported": AnomalyReported,
    "CredentialAccessed": CredentialAccessed,
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
