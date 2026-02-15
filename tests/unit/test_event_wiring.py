"""M2 event wiring extraction coverage."""

from __future__ import annotations

import asyncio
import threading
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import pytest

from shisad.core.events import CapabilityGranted, SessionCreated
from shisad.core.types import SessionId
from shisad.daemon.event_wiring import DaemonEventWiring, matrix_receive_pump
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
