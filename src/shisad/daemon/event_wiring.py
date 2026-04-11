"""Daemon event callback wiring extracted from startup orchestration."""

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING, Any, Protocol

from shisad.channels.base import Channel
from shisad.channels.state import ChannelStateStore
from shisad.core.api.schema import ChannelIngestParams
from shisad.core.api.transport import ControlServer
from shisad.core.events import (
    BaseEvent,
    CapabilityGranted,
    CredentialAccessed,
    EventBus,
    LockdownChanged,
    MemoryEntryDeleted,
    MemoryEntryStored,
    OutputFirewallAlert,
    RateLimitTriggered,
    SessionArchiveExported,
    SessionArchiveImported,
    SessionRehydrated,
    SessionRehydrateRejected,
)
from shisad.core.types import SessionId, ToolName
from shisad.daemon.context import RequestContext
from shisad.security.lockdown import LockdownManager
from shisad.security.pep import CredentialUseAttempt
from shisad.security.ratelimit import RateLimitEvent

if TYPE_CHECKING:
    from shisad.channels.matrix import MatrixChannel

logger = logging.getLogger(__name__)


class _ChannelIngestHandler(Protocol):
    async def handle_channel_ingest(
        self,
        params: ChannelIngestParams,
        ctx: RequestContext,
    ) -> Any: ...


class DaemonEventWiring:
    """Named callback set used during daemon runtime wiring."""

    def __init__(self, *, event_bus: EventBus, server: ControlServer) -> None:
        self._event_bus = event_bus
        self._server = server
        self._loop = asyncio.get_running_loop()
        self._lockdown_manager: LockdownManager | None = None

    def bind_lockdown_manager(self, manager: LockdownManager) -> None:
        self._lockdown_manager = manager

    async def forward_event_to_subscribers(self, event: BaseEvent) -> None:
        payload = event.model_dump(mode="json")
        payload["event_type"] = type(event).__name__
        await self._server.broadcast_event(payload)

    def publish_async(self, event: BaseEvent) -> None:
        event_type = type(event).__name__

        def _done_callback(done_task: asyncio.Task[None]) -> None:
            try:
                done_task.result()
            except (OSError, RuntimeError, ValueError, TypeError):
                logger.exception("Async event publish failed for %s", event_type)

        def _schedule() -> None:
            try:
                task = self._loop.create_task(self._event_bus.publish(event))
            except RuntimeError:
                logger.exception(
                    "Async event publish failed for %s: event loop unavailable",
                    event_type,
                )
                return
            task.add_done_callback(_done_callback)

        try:
            running_loop = asyncio.get_running_loop()
        except RuntimeError:
            running_loop = None

        if running_loop is self._loop:
            _schedule()
            return
        try:
            self._loop.call_soon_threadsafe(_schedule)
        except RuntimeError:
            logger.exception(
                "Async event publish failed for %s: event loop unavailable",
                event_type,
            )

    def audit_session_event(self, action: str, data: dict[str, Any]) -> None:
        if action != "session.capability_granted":
            if action == "session.rehydrated":
                self.publish_async(
                    SessionRehydrated(
                        session_id=SessionId(str(data.get("session_id", ""))),
                        actor="session_manager",
                        source=str(data.get("source", "")),
                        schema_version=int(data.get("schema_version", 0) or 0),
                        migrated=bool(data.get("migrated", False)),
                        migration_reason=str(data.get("migration_reason", "")),
                        role=str(data.get("role", "")),
                        mode=str(data.get("mode", "")),
                        lockdown_level=str(data.get("lockdown_level", "")),
                    )
                )
            elif action == "session.rehydrate_rejected":
                raw_session_id = str(data.get("session_id", "")).strip()
                session_id = SessionId(raw_session_id) if raw_session_id else None
                self.publish_async(
                    SessionRehydrateRejected(
                        session_id=session_id,
                        actor="session_manager",
                        source=str(data.get("source", "")),
                        reason=str(data.get("reason", "")),
                        schema_version=int(data.get("schema_version", 0) or 0),
                        path=str(data.get("path", "")),
                    )
                )
            return
        raw_granted = data.get("granted")
        granted = [str(item) for item in raw_granted] if isinstance(raw_granted, list) else []
        self.publish_async(
            CapabilityGranted(
                session_id=SessionId(str(data.get("session_id", ""))),
                actor="session_manager",
                capabilities=granted,
                granted_by=str(data.get("actor", "")),
                reason=str(data.get("reason", "")),
            )
        )

    def audit_capability_event(self, action: str, data: dict[str, Any]) -> None:
        self.audit_session_event(action, data)

    def audit_archive_export(self, data: dict[str, Any]) -> None:
        self.publish_async(
            SessionArchiveExported(
                session_id=SessionId(str(data.get("session_id", ""))),
                actor="session_archive",
                archive_path=str(data.get("archive_path", "")),
                original_session_id=str(data.get("original_session_id", "")),
                transcript_entries=int(data.get("transcript_entries", 0) or 0),
                checkpoint_count=int(data.get("checkpoint_count", 0) or 0),
                archive_sha256=str(data.get("archive_sha256", "")),
            )
        )

    def audit_archive_import(self, data: dict[str, Any]) -> None:
        self.publish_async(
            SessionArchiveImported(
                session_id=SessionId(str(data.get("session_id", ""))),
                actor="session_archive",
                archive_path=str(data.get("archive_path", "")),
                original_session_id=str(data.get("original_session_id", "")),
                imported_session_id=str(data.get("imported_session_id", "")),
                transcript_entries=int(data.get("transcript_entries", 0) or 0),
                checkpoint_count=int(data.get("checkpoint_count", 0) or 0),
            )
        )

    def audit_credential_use(self, attempt: CredentialUseAttempt) -> None:
        self.publish_async(
            CredentialAccessed(
                session_id=None,
                actor="pep",
                credential_ref=str(attempt.credential_ref),
                destination_host=attempt.destination_host,
                allowed=attempt.allowed,
                reason=attempt.reason,
            )
        )

    def audit_memory_event(self, action: str, data: dict[str, Any]) -> None:
        if action == "memory.write":
            self.publish_async(
                MemoryEntryStored(
                    session_id=None,
                    actor="memory_manager",
                    memory_id=str(data.get("entry_id", "")),
                    key=str(data.get("key", "")),
                    source_origin=str(data.get("source_origin", "")),
                )
            )
            return
        if action == "memory.delete":
            self.publish_async(
                MemoryEntryDeleted(
                    session_id=None,
                    actor="memory_manager",
                    memory_id=str(data.get("entry_id", "")),
                )
            )

    def audit_output_event(self, data: dict[str, Any]) -> None:
        context = data.get("context", {})
        if isinstance(context, dict):
            raw_session_id = str(context.get("session_id", "")).strip()
        else:
            raw_session_id = ""
        session_id = SessionId(raw_session_id) if raw_session_id else None
        reason_codes = data.get("reason_codes", [])
        secret_findings = data.get("secret_findings", [])
        pii_findings = data.get("pii_findings", [])
        self.publish_async(
            OutputFirewallAlert(
                session_id=session_id,
                actor="output_firewall",
                blocked=bool(data.get("blocked", False)),
                require_confirmation=bool(data.get("require_confirmation", False)),
                reason_codes=(
                    [str(item) for item in reason_codes] if isinstance(reason_codes, list) else []
                ),
                secret_findings=(
                    [str(item) for item in secret_findings]
                    if isinstance(secret_findings, list)
                    else []
                ),
                pii_findings=(
                    [str(item) for item in pii_findings] if isinstance(pii_findings, list) else []
                ),
            )
        )

    def lockdown_notify(self, session_id: SessionId, message: str) -> None:
        if self._lockdown_manager is None:
            logger.warning("Lockdown callback invoked before lock manager bind: %s", message)
            return
        state = self._lockdown_manager.state_for(session_id)
        self.publish_async(
            LockdownChanged(
                session_id=session_id,
                actor="lockdown",
                level=state.level.value,
                reason=state.reason,
                trigger=state.trigger,
            )
        )
        logger.warning("lockdown notification: %s", message)

    def on_ratelimit(self, event: RateLimitEvent) -> None:
        self.publish_async(
            RateLimitTriggered(
                session_id=SessionId(event.session_id),
                actor="ratelimiter",
                tool_name=ToolName(event.tool_name),
                reason=event.reason,
                count=event.count,
            )
        )
        if self._lockdown_manager is None:
            logger.warning("Rate-limit callback invoked before lock manager bind")
            return
        self._lockdown_manager.trigger(
            SessionId(event.session_id),
            trigger="rate_limit",
            reason=f"{event.reason} ({event.count})",
        )


async def matrix_receive_pump(
    *,
    matrix_channel: MatrixChannel,
    shutdown_event: asyncio.Event,
    handlers: _ChannelIngestHandler,
    state_store: ChannelStateStore | None = None,
) -> None:
    await channel_receive_pump(
        channel_name="matrix",
        channel=matrix_channel,
        shutdown_event=shutdown_event,
        handlers=handlers,
        state_store=state_store,
    )


async def channel_receive_pump(
    *,
    channel_name: str,
    channel: Channel,
    shutdown_event: asyncio.Event,
    handlers: _ChannelIngestHandler,
    state_store: ChannelStateStore | None = None,
) -> None:
    """Continuously ingest channel messages until shutdown is requested."""
    while not shutdown_event.is_set():
        try:
            message = await asyncio.wait_for(channel.receive(), timeout=0.5)
        except TimeoutError:
            continue
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("%s receive loop error", channel_name)
            await asyncio.sleep(0.2)
            continue

        message_id = str(getattr(message, "message_id", "")).strip()
        if (
            state_store is not None
            and message_id
            and _is_replay_message(
                state_store=state_store,
                channel_name=channel_name,
                message_id=message_id,
            )
        ):
            continue

        try:
            await handlers.handle_channel_ingest(
                ChannelIngestParams(
                    message={
                        "channel": message.channel,
                        "external_user_id": message.external_user_id,
                        "workspace_hint": message.workspace_hint,
                        "content": message.content,
                        "message_id": message_id,
                        "reply_target": str(getattr(message, "reply_target", "")),
                        "thread_id": str(getattr(message, "thread_id", "")),
                    }
                ),
                RequestContext(is_internal_ingress=True),
            )
        except Exception:
            logger.exception("%s ingress processing failed", channel_name)
            continue

        if state_store is not None and message_id:
            _mark_processed_message(
                state_store=state_store,
                channel_name=channel_name,
                message_id=message_id,
            )


def _is_replay_message(
    *,
    state_store: ChannelStateStore,
    channel_name: str,
    message_id: str,
) -> bool:
    try:
        return state_store.has_seen(channel=channel_name, message_id=message_id)
    except Exception:
        logger.exception(
            "%s replay guard read failed; continuing without replay check",
            channel_name,
        )
        return False


def _mark_processed_message(
    *,
    state_store: ChannelStateStore,
    channel_name: str,
    message_id: str,
) -> None:
    try:
        state_store.mark_seen(channel=channel_name, message_id=message_id)
    except Exception:
        logger.exception(
            "%s replay guard persist failed after successful ingest",
            channel_name,
        )
