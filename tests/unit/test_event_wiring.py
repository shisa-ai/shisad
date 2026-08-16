"""M2 event wiring extraction coverage."""

from __future__ import annotations

import asyncio
import inspect
import threading
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import pytest

from shisad.channels.base import DeliveryTarget
from shisad.core.events import (
    CapabilityGranted,
    SessionArchiveExported,
    SessionCreated,
    SessionRehydrated,
    SessionRehydrateRejected,
    ToolApproved,
    ToolExecuted,
    ToolRejected,
)
from shisad.core.types import PEPDecisionKind, SessionId, ToolName
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


def test_o3e_progress_projection_is_structural_bounded_and_redacted() -> None:
    from shisad.channels.progress import project_action_progress

    identity = {
        "session_id": SessionId("session-1"),
        "actor": "policy_loop",
        "tool_name": ToolName("shell.exec\nsecret"),
        "action_id": "action-1",
        "origin_turn_id": "turn-1",
        "delivery_target": {
            "channel": "discord",
            "recipient": "100",
            "thread_id": "200",
        },
    }
    events = [
        ToolApproved(**identity),
        ToolRejected(
            **identity,
            decision=PEPDecisionKind.REQUIRE_CONFIRMATION,
            reason="contains TOP-SECRET and /private/path",
        ),
        ToolExecuted(
            **identity,
            success=False,
            error="TOP-SECRET",
            details={"result": "TOP-SECRET"},
        ),
    ]

    views = [project_action_progress(event) for event in events]

    assert [view.state for view in views if view is not None] == [
        "running",
        "awaiting_confirmation",
        "failed",
    ]
    serialized = " ".join(view.model_dump_json() for view in views if view is not None)
    assert "TOP-SECRET" not in serialized
    assert "/private/path" not in serialized
    assert "\n" not in views[0].tool_name  # type: ignore[union-attr]
    assert len(views[0].tool_name) <= 64  # type: ignore[union-attr]


@pytest.mark.asyncio
async def test_o3e_event_wiring_broadcasts_safe_view_and_exact_discord_target() -> None:
    bus = _RecordingEventBus()
    server = _RecordingServer()
    deliveries: list[object] = []

    class _ProgressChannel:
        async def publish_progress(self, progress: object, *, target: object) -> None:
            deliveries.append((progress, target))

    wiring = DaemonEventWiring(event_bus=bus, server=server)  # type: ignore[arg-type]
    wiring.bind_progress_channels({"discord": _ProgressChannel()})  # type: ignore[dict-item]
    event = ToolExecuted(
        session_id=SessionId("session-1"),
        actor="executor",
        tool_name=ToolName("web.fetch"),
        action_id="action-1",
        origin_turn_id="turn-1",
        delivery_target={"channel": "discord", "recipient": "100", "thread_id": "200"},
        success=True,
        details={"body": "TOP-SECRET"},
    )

    await wiring.forward_event_to_subscribers(event)

    safe = next(payload for payload in server.payloads if payload["event_type"] == "ActionProgress")
    assert safe == {
        "event_type": "ActionProgress",
        "session_id": "session-1",
        "action_id": "action-1",
        "origin_turn_id": "turn-1",
        "tool_name": "web.fetch",
        "state": "succeeded",
    }
    assert len(deliveries) == 1
    delivered_progress, delivered_target = deliveries[0]  # type: ignore[misc]
    assert delivered_progress.action_id == "action-1"  # type: ignore[attr-defined]
    assert delivered_target == DeliveryTarget(channel="discord", recipient="100", thread_id="200")


@pytest.mark.asyncio
async def test_o3e_event_wiring_contains_provider_specific_progress_failure() -> None:
    class _ProviderFailure(Exception):
        pass

    class _FailingProgressChannel:
        async def publish_progress(self, progress: object, *, target: object) -> None:
            del progress, target
            raise _ProviderFailure

    server = _RecordingServer()
    wiring = DaemonEventWiring(  # type: ignore[arg-type]
        event_bus=_RecordingEventBus(),
        server=server,
    )
    wiring.bind_progress_channels(  # type: ignore[dict-item]
        {"discord": _FailingProgressChannel()}
    )
    event = ToolApproved(
        session_id=SessionId("session-1"),
        tool_name=ToolName("web.fetch"),
        action_id="action-1",
        origin_turn_id="turn-1",
        delivery_target={"channel": "discord", "recipient": "100"},
    )

    await wiring.forward_event_to_subscribers(event)

    assert [payload["event_type"] for payload in server.payloads] == [
        "ToolApproved",
        "ActionProgress",
    ]


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
async def test_channel_receive_pump_delegates_replay_admission_to_common_handler() -> None:
    shutdown_event = asyncio.Event()
    message = _MatrixMessage(
        channel="discord",
        external_user_id="u1",
        workspace_hint="ws1",
        content="hello",
        message_id="m-1",
    )
    channel = _MatrixChannelStub(message)

    class _Handler:
        def __init__(self) -> None:
            self.calls: list[tuple[dict[str, Any], bool]] = []

        async def handle_channel_ingest(self, params: Any, ctx: Any) -> None:
            self.calls.append((params.model_dump(mode="json"), ctx.is_internal_ingress))
            shutdown_event.set()

    handler = _Handler()
    await channel_receive_pump(
        channel_name="discord",
        channel=channel,  # type: ignore[arg-type]
        shutdown_event=shutdown_event,
        handlers=handler,  # type: ignore[arg-type]
    )

    assert "state_store" not in inspect.signature(channel_receive_pump).parameters
    assert len(handler.calls) == 1
    assert handler.calls[0][0]["message"]["message_id"] == "m-1"
    assert handler.calls[0][1] is True


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
