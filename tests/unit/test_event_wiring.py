"""M2 event wiring extraction coverage."""

from __future__ import annotations

import asyncio
import threading
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import pytest

from shisad.channels.base import ReplayEventVariant, ReplayIdentity
from shisad.core.events import (
    CapabilityGranted,
    SessionArchiveExported,
    SessionCreated,
    SessionRehydrated,
    SessionRehydrateRejected,
)
from shisad.core.types import SessionId
from shisad.daemon.event_wiring import DaemonEventWiring, channel_receive_pump, matrix_receive_pump
from shisad.security.lockdown import LockdownManager
from shisad.security.ratelimit import RateLimitEvent


class _RecordingEventBus:
    def __init__(self) -> None:
        self.events: list[Any] = []

    async def publish(self, event: Any) -> None:
        self.events.append(event)


class _RecordingServer:
    def __init__(self) -> None:
        self.payloads: list[dict[str, Any]] = []

    async def broadcast_event(self, payload: dict[str, Any]) -> None:
        self.payloads.append(payload)


@dataclass
class _MatrixMessage:
    channel: str
    external_user_id: str
    workspace_hint: str
    content: str
    message_id: str = ""
    reply_target: str = ""
    thread_id: str = ""


class _MatrixChannelStub:
    def __init__(self, message: _MatrixMessage) -> None:
        self._message = message
        self._emitted = False

    async def receive(self) -> _MatrixMessage:
        if not self._emitted:
            self._emitted = True
            return self._message
        await asyncio.sleep(1)
        return self._message

    def replay_identity(self, message: _MatrixMessage) -> ReplayIdentity:
        return ReplayIdentity(
            provider=message.channel,
            account_id="matrix-account",
            tenant_id="matrix.example",
            delivery_id=message.reply_target or "!room:matrix.example",
            event_variant=ReplayEventVariant.ORDINARY_MESSAGE,
            message_id=message.message_id,
        )


class _ChannelIngestHandlerStub:
    def __init__(self, shutdown_event: asyncio.Event) -> None:
        self._shutdown_event = shutdown_event
        self.calls: list[tuple[dict[str, Any], bool]] = []

    async def handle_channel_ingest(self, params: Any, ctx: Any) -> None:
        self.calls.append((params.model_dump(mode="json"), bool(ctx.is_internal_ingress)))
        self._shutdown_event.set()


class _ClosedLoopStub:
    def create_task(self, coro: Any) -> Any:
        coro.close()
        raise RuntimeError("Event loop is closed")

    def call_soon_threadsafe(self, callback: Any) -> None:
        callback()


@pytest.mark.asyncio
async def test_forward_event_to_subscribers_adds_event_type() -> None:
    bus = _RecordingEventBus()
    server = _RecordingServer()
    wiring = DaemonEventWiring(event_bus=bus, server=server)  # type: ignore[arg-type]

    event = SessionCreated(session_id=SessionId("s1"), actor="tester", user_id="u1")
    await wiring.forward_event_to_subscribers(event)

    assert server.payloads
    assert server.payloads[0]["event_type"] == "SessionCreated"


@pytest.mark.asyncio
async def test_audit_capability_event_publishes_grant_event() -> None:
    bus = _RecordingEventBus()
    server = _RecordingServer()
    wiring = DaemonEventWiring(event_bus=bus, server=server)  # type: ignore[arg-type]

    wiring.audit_capability_event(
        "session.capability_granted",
        {
            "session_id": "s1",
            "granted": ["http.request"],
            "actor": "uid:1000",
            "reason": "manual",
        },
    )
    await asyncio.sleep(0)

    assert bus.events
    assert isinstance(bus.events[0], CapabilityGranted)
    assert bus.events[0].capabilities == ["http.request"]


@pytest.mark.asyncio
async def test_audit_session_event_publishes_rehydration_events() -> None:
    bus = _RecordingEventBus()
    server = _RecordingServer()
    wiring = DaemonEventWiring(event_bus=bus, server=server)  # type: ignore[arg-type]

    wiring.audit_session_event(
        "session.rehydrated",
        {
            "session_id": "s1",
            "source": "startup",
            "schema_version": 1,
            "migrated": True,
            "migration_reason": "legacy_fixup",
            "role": "orchestrator",
            "mode": "default",
            "lockdown_level": "caution",
        },
    )
    wiring.audit_session_event(
        "session.rehydrate_rejected",
        {
            "source": "startup",
            "reason": "unsupported_schema_version:99",
            "path": "/tmp/s1.json",
            "schema_version": 99,
        },
    )
    await asyncio.sleep(0)

    assert isinstance(bus.events[0], SessionRehydrated)
    assert isinstance(bus.events[1], SessionRehydrateRejected)


@pytest.mark.asyncio
async def test_audit_archive_events_publish_archive_telemetry() -> None:
    bus = _RecordingEventBus()
    server = _RecordingServer()
    wiring = DaemonEventWiring(event_bus=bus, server=server)  # type: ignore[arg-type]

    wiring.audit_archive_export(
        {
            "session_id": "s1",
            "archive_path": "/tmp/archive.zip",
            "original_session_id": "s1",
            "transcript_entries": 2,
            "checkpoint_count": 1,
            "archive_sha256": "abc123",
        }
    )
    await asyncio.sleep(0)

    assert isinstance(bus.events[0], SessionArchiveExported)


@pytest.mark.asyncio
async def test_on_ratelimit_publishes_event_and_triggers_lockdown() -> None:
    bus = _RecordingEventBus()
    server = _RecordingServer()
    wiring = DaemonEventWiring(event_bus=bus, server=server)  # type: ignore[arg-type]
    lockdown = LockdownManager()
    wiring.bind_lockdown_manager(lockdown)

    wiring.on_ratelimit(
        RateLimitEvent(
            timestamp=datetime.now(UTC),
            session_id="s-rate",
            user_id="user-1",
            tool_name="shell.exec",
            reason="tool_limit_exceeded",
            count=5,
        )
    )
    await asyncio.sleep(0)

    assert bus.events
    assert lockdown.state_for(SessionId("s-rate")).trigger == "rate_limit"


@pytest.mark.asyncio
async def test_matrix_receive_pump_forwards_message_as_internal_ingress() -> None:
    shutdown_event = asyncio.Event()
    handler = _ChannelIngestHandlerStub(shutdown_event)
    channel = _MatrixChannelStub(
        _MatrixMessage(
            channel="matrix",
            external_user_id="@user:example.com",
            workspace_hint="ops",
            content="hello",
            message_id="event-1",
            reply_target="!ops:example.com",
        )
    )

    await matrix_receive_pump(
        matrix_channel=channel,  # type: ignore[arg-type]
        shutdown_event=shutdown_event,
        handlers=handler,
    )

    assert handler.calls
    payload, is_internal = handler.calls[0]
    assert payload["message"]["channel"] == "matrix"
    assert payload["message"]["content"] == "hello"
    assert is_internal is True


@pytest.mark.asyncio
async def test_channel_receive_pump_reserves_before_ingest_and_marks_terminal() -> None:
    shutdown_event = asyncio.Event()
    message = _MatrixMessage(
        channel="discord",
        external_user_id="u1",
        workspace_hint="ws1",
        content="hello",
        message_id="m-1",
    )
    channel = _MatrixChannelStub(message)

    class _StateStore:
        def __init__(self) -> None:
            self.transitions: list[str] = []

        def reserve(self, *, identity: ReplayIdentity) -> bool:
            self.transitions.append(f"reserve:{identity.provider}:{identity.message_id}")
            return False

        def mark_terminal(self, *, identity: ReplayIdentity) -> None:
            self.transitions.append(f"terminal:{identity.provider}:{identity.message_id}")
            shutdown_event.set()

        def mark_uncertain(self, *, identity: ReplayIdentity) -> None:
            self.transitions.append(f"uncertain:{identity.provider}:{identity.message_id}")

    class _Handler:
        async def handle_channel_ingest(self, params: Any, ctx: Any) -> None:
            _ = (params, ctx)

    state_store = _StateStore()
    await channel_receive_pump(
        channel_name="discord",
        channel=channel,  # type: ignore[arg-type]
        shutdown_event=shutdown_event,
        handlers=_Handler(),
        state_store=state_store,  # type: ignore[arg-type]
    )

    assert state_store.transitions == [
        "reserve:discord:m-1",
        "terminal:discord:m-1",
    ]


@pytest.mark.asyncio
async def test_channel_receive_pump_marks_reserved_ingest_uncertain_when_handler_fails() -> None:
    shutdown_event = asyncio.Event()
    message = _MatrixMessage(
        channel="discord",
        external_user_id="u1",
        workspace_hint="ws1",
        content="hello",
        message_id="m-1",
    )
    channel = _MatrixChannelStub(message)

    class _StateStore:
        def __init__(self) -> None:
            self.transitions: list[str] = []

        def reserve(self, *, identity: ReplayIdentity) -> bool:
            self.transitions.append(f"reserve:{identity.provider}:{identity.message_id}")
            return False

        def mark_terminal(self, *, identity: ReplayIdentity) -> None:
            self.transitions.append(f"terminal:{identity.provider}:{identity.message_id}")

        def mark_uncertain(self, *, identity: ReplayIdentity) -> None:
            self.transitions.append(f"uncertain:{identity.provider}:{identity.message_id}")

    class _FailingHandler:
        async def handle_channel_ingest(self, params: Any, ctx: Any) -> None:
            _ = (params, ctx)
            shutdown_event.set()
            raise RuntimeError("ingest failed")

    state_store = _StateStore()
    await channel_receive_pump(
        channel_name="discord",
        channel=channel,  # type: ignore[arg-type]
        shutdown_event=shutdown_event,
        handlers=_FailingHandler(),
        state_store=state_store,  # type: ignore[arg-type]
    )

    assert state_store.transitions == [
        "reserve:discord:m-1",
        "uncertain:discord:m-1",
    ]


@pytest.mark.asyncio
async def test_channel_receive_pump_blocks_when_replay_reservation_fails() -> None:
    shutdown_event = asyncio.Event()
    message = _MatrixMessage(
        channel="discord",
        external_user_id="u1",
        workspace_hint="ws1",
        content="hello",
        message_id="m-1",
    )
    channel = _MatrixChannelStub(message)

    class _StateStore:
        def reserve(self, *, identity: ReplayIdentity) -> bool:
            _ = identity
            shutdown_event.set()
            raise RuntimeError("state read failed")

        def mark_terminal(self, *, identity: ReplayIdentity) -> None:
            _ = identity

        def mark_uncertain(self, *, identity: ReplayIdentity) -> None:
            _ = identity

    class _Handler:
        def __init__(self) -> None:
            self.calls = 0

        async def handle_channel_ingest(self, params: Any, ctx: Any) -> None:
            _ = (params, ctx)
            self.calls += 1

    handler = _Handler()
    await channel_receive_pump(
        channel_name="discord",
        channel=channel,  # type: ignore[arg-type]
        shutdown_event=shutdown_event,
        handlers=handler,  # type: ignore[arg-type]
        state_store=_StateStore(),  # type: ignore[arg-type]
    )

    assert handler.calls == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("fault", ["missing", "provider_mismatch", "message_mismatch"])
async def test_channel_receive_pump_blocks_missing_or_mismatched_adapter_identity(
    fault: str,
) -> None:
    shutdown_event = asyncio.Event()
    message = _MatrixMessage(
        channel="discord",
        external_user_id="u1",
        workspace_hint="guild-1",
        content="hello",
        message_id="m-1",
        reply_target="channel-1",
    )

    class _Channel(_MatrixChannelStub):
        def replay_identity(self, current: _MatrixMessage) -> ReplayIdentity | None:
            shutdown_event.set()
            if fault == "missing":
                return None
            return ReplayIdentity(
                provider="slack" if fault == "provider_mismatch" else "discord",
                account_id="acct-1",
                tenant_id="guild-1",
                delivery_id="channel-1",
                event_variant=ReplayEventVariant.ORDINARY_MESSAGE,
                message_id="m-2" if fault == "message_mismatch" else current.message_id,
            )

    class _Handler:
        calls = 0

        async def handle_channel_ingest(self, _params: Any, _ctx: Any) -> None:
            self.calls += 1

    handler = _Handler()
    await channel_receive_pump(
        channel_name="discord",
        channel=_Channel(message),  # type: ignore[arg-type]
        shutdown_event=shutdown_event,
        handlers=handler,  # type: ignore[arg-type]
        state_store=None,
    )
    assert handler.calls == 0


@pytest.mark.asyncio
async def test_publish_async_handles_cross_thread_invocation() -> None:
    bus = _RecordingEventBus()
    server = _RecordingServer()
    wiring = DaemonEventWiring(event_bus=bus, server=server)  # type: ignore[arg-type]

    event = SessionCreated(session_id=SessionId("s1"), actor="tester", user_id="u1")

    thread = threading.Thread(target=lambda: wiring.publish_async(event))
    thread.start()
    thread.join(timeout=1.0)
    assert not thread.is_alive()

    await asyncio.sleep(0)
    await asyncio.sleep(0)
    assert bus.events
    assert isinstance(bus.events[0], SessionCreated)


def test_publish_async_same_loop_closed_is_swallowed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bus = _RecordingEventBus()
    server = _RecordingServer()
    loop_stub = _ClosedLoopStub()
    wiring = object.__new__(DaemonEventWiring)
    wiring._event_bus = bus
    wiring._server = server
    wiring._loop = loop_stub
    wiring._lockdown_manager = None
    monkeypatch.setattr(asyncio, "get_running_loop", lambda: loop_stub)

    wiring.publish_async(SessionCreated(session_id=SessionId("s1"), actor="tester", user_id="u1"))
    assert bus.events == []
