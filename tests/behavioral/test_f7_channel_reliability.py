"""Behavioral journeys for F7 chosen-channel reliability."""

from __future__ import annotations

import asyncio
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from shisad.channels import discord as discord_module
from shisad.channels import state as channel_state
from shisad.channels.base import ChannelMessage, DeliveryTarget, InMemoryChannel
from shisad.channels.delivery import ChannelDeliveryService, DeliveryIntent
from shisad.channels.discord import DiscordChannel, DiscordConfig
from shisad.core.session import Session, SessionManager
from shisad.core.transcript import TranscriptStore
from shisad.core.types import SessionId, UserId, WorkspaceId
from shisad.daemon.event_wiring import channel_receive_pump
from shisad.daemon.handlers._impl_admin import AdminImplMixin
from shisad.daemon.handlers.admin import AdminHandlers


class _OneMessageChannel:
    def __init__(self, message: ChannelMessage, shutdown: asyncio.Event) -> None:
        self._message = message
        self._shutdown = shutdown

    async def receive(self) -> ChannelMessage:
        self._shutdown.set()
        return self._message


class _ReplayJourneyImpl(AdminImplMixin):
    def __init__(self, *, root: Path, marker: object) -> None:
        self._internal_ingress_marker = marker
        self._config = SimpleNamespace(data_dir=root.parent.parent)
        self._services = SimpleNamespace(channel_state_store=channel_state.ChannelStateStore(root))
        self.effects: list[str] = []

    async def do_channel_ingest(self, params: dict[str, Any]) -> dict[str, Any]:
        self.effects.append(str(params["message"]["content"]))
        return {
            "session_id": "journey-session",
            "response": "handled once",
            "ingress_risk": 0.1,
        }


class _OutboundJourneyImpl(AdminImplMixin):
    def __init__(
        self,
        *,
        root: Path,
        marker: object,
        delivery: ChannelDeliveryService,
        transcripts: TranscriptStore,
    ) -> None:
        self._internal_ingress_marker = marker
        self._config = SimpleNamespace(data_dir=root.parent.parent)
        self._services = SimpleNamespace(channel_state_store=channel_state.ChannelStateStore(root))
        self._delivery = delivery
        self._transcripts = transcripts
        self.delivery_state = ""
        self.reservation_id = ""

    async def do_channel_ingest(self, params: dict[str, Any]) -> dict[str, Any]:
        message = ChannelMessage.model_validate(params["message"])
        target = DeliveryTarget(
            channel=message.channel,
            recipient=message.reply_target,
            workspace_hint=message.workspace_hint,
        )
        reservation = self._delivery.reserve(
            DeliveryIntent(
                source_id=str(params["_delivery_source_id"]),
                kind="channel_result",
                target=target,
            )
        )
        self.reservation_id = reservation.reservation_id
        self._transcripts.append(
            SessionId("journey-session"),
            role="assistant",
            content="one committed result",
            metadata={
                "delivery_target": target.model_dump(mode="json"),
                "outbound_delivery_reservation_id": reservation.reservation_id,
            },
            durable=True,
        )
        prepared = self._delivery.prepare(
            reservation.reservation_id,
            message="one committed result",
        )
        result = await self._delivery.send_prepared(prepared.reservation_id)
        self.delivery_state = result.state
        return {
            "session_id": "journey-session",
            "response": "one committed result",
            "ingress_risk": 0.1,
            "delivery": result.as_dict(),
        }


async def _pump_impl(*, impl: AdminImplMixin, marker: object, message: ChannelMessage) -> None:
    shutdown = asyncio.Event()
    handlers = AdminHandlers(impl, internal_ingress_marker=marker)  # type: ignore[arg-type]
    await channel_receive_pump(
        channel_name="matrix",
        channel=_OneMessageChannel(message, shutdown),  # type: ignore[arg-type]
        shutdown_event=shutdown,
        handlers=handlers,
    )


async def _run_one_pump(
    *,
    root: Path,
    marker: object,
    message: ChannelMessage,
) -> _ReplayJourneyImpl:
    impl = _ReplayJourneyImpl(root=root, marker=marker)
    await _pump_impl(impl=impl, marker=marker, message=message)
    return impl


@pytest.mark.asyncio
async def test_channel_ingress_reservation_survives_restart_without_redispatch(
    tmp_path: Path,
) -> None:
    root = tmp_path / "data" / "channels" / "state"
    marker = object()
    identity = channel_state.ReplayIdentity(
        provider="matrix",
        account_id='["https://matrix.example.org","@bot:example.org"]',
        scope_id='["!room:example.org"]',
        event_kind="message",
        event_id="$event-1",
    )
    message = ChannelMessage(
        channel="matrix",
        external_user_id="@alice:example.org",
        workspace_hint="workspace-1",
        content="perform the chosen-channel request",
        message_id="$event-1",
        reply_target="!room:example.org",
        metadata=channel_state.replay_identity_metadata(identity),
    )

    first_process = await _run_one_pump(root=root, marker=marker, message=message)
    restarted_process = await _run_one_pump(root=root, marker=marker, message=message)

    assert first_process.effects == ["perform the chosen-channel request"]
    assert restarted_process.effects == []
    restarted_store = channel_state.ChannelStateStore(root)
    assert restarted_store.state_for(identity) == "terminal"
    assert restarted_store.record_count() == 1


@pytest.mark.asyncio
async def test_channel_result_outbox_survives_restart_without_duplicate_effect(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A shipped no-proof channel exposes uncertainty without replaying its effect."""

    class _AcceptedThenLostChannel(InMemoryChannel):
        def __init__(self) -> None:
            super().__init__(name="matrix")
            self.effects: list[str] = []

        async def send(
            self,
            message: str,
            *,
            target: DeliveryTarget | None = None,
            metadata: dict[str, Any] | None = None,
        ) -> None:
            _ = (target, metadata)
            self.effects.append(message)

    state_root = tmp_path / "data" / "channels" / "state"
    delivery_root = tmp_path / "data" / "channels" / "delivery"
    transcript_root = tmp_path / "data" / "sessions"
    marker = object()
    identity = channel_state.ReplayIdentity(
        provider="matrix",
        account_id='["https://matrix.example.org","@bot:example.org"]',
        scope_id='["!room:example.org"]',
        event_kind="message",
        event_id="$result-event-1",
    )
    message = ChannelMessage(
        channel="matrix",
        external_user_id="@alice:example.org",
        workspace_hint="workspace-1",
        content="produce the chosen-channel result",
        message_id="$result-event-1",
        reply_target="!room:example.org",
        metadata=channel_state.replay_identity_metadata(identity),
    )
    channel = _AcceptedThenLostChannel()
    await channel.connect()
    transcripts = TranscriptStore(transcript_root)
    first = ChannelDeliveryService(
        {"matrix": channel}, state_root=delivery_root, transcript_store=transcripts
    )

    def lose_receipt(*_args: object, **_kwargs: object) -> None:
        raise OSError("simulated process loss after provider acceptance")

    monkeypatch.setattr(first._store, "mark_delivered", lose_receipt)
    first_process = _OutboundJourneyImpl(
        root=state_root,
        marker=marker,
        delivery=first,
        transcripts=transcripts,
    )
    await _pump_impl(impl=first_process, marker=marker, message=message)

    assert first_process.delivery_state == "attempt_started"
    assert channel.effects == ["one committed result"]
    assert len(transcripts.list_entries(SessionId("journey-session"))) == 1
    first.close()

    restarted = ChannelDeliveryService(
        {"matrix": channel},
        state_root=delivery_root,
        transcript_store=TranscriptStore(transcript_root),
    )
    recovery = await restarted.recover()
    restarted_process = _OutboundJourneyImpl(
        root=state_root,
        marker=marker,
        delivery=restarted,
        transcripts=TranscriptStore(transcript_root),
    )
    await _pump_impl(impl=restarted_process, marker=marker, message=message)

    assert len(recovery) == 1
    assert recovery[0].outcome_unknown is True
    assert channel.effects == ["one committed result"]
    assert restarted_process.delivery_state == ""
    assert restarted.record(first_process.reservation_id).state == "outcome_unknown"
    assert channel_state.ChannelStateStore(state_root).state_for(identity) == "terminal"


@pytest.mark.asyncio
async def test_o3d_discord_thread_mode_preserves_session_and_delivery_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _Intents:
        message_content = False

        @classmethod
        def default(cls) -> _Intents:
            return cls()

    class _Target:
        def __init__(self, target_id: str, *, parent_id: str = "") -> None:
            self.id = target_id
            self.parent_id = parent_id or None
            self.sent: list[str] = []

        async def send(self, content: str, **_kwargs: object) -> None:
            self.sent.append(content)

    class _Client:
        def __init__(self, *, intents: _Intents) -> None:
            self.intents = intents
            self.user = SimpleNamespace(id="999", name="shisad")
            self.targets: dict[int, _Target] = {}

        def event(self, coro):
            setattr(self, coro.__name__, coro)
            return coro

        async def start(self, _token: str) -> None:
            return None

        async def close(self) -> None:
            return None

        def get_channel(self, channel_id: int) -> _Target | None:
            return self.targets.get(channel_id)

        async def fetch_channel(self, channel_id: int) -> _Target | None:
            return self.targets.get(channel_id)

    class _Message:
        def __init__(
            self,
            *,
            message_id: str,
            channel: _Target,
            created_thread: _Target | None = None,
        ) -> None:
            self.id = message_id
            self.author = SimpleNamespace(id="alice", bot=False)
            self.content = "<@999> continue"
            self.guild = SimpleNamespace(id="guild-1", get_thread=lambda _thread_id: None)
            self.channel = channel
            self.mentions = [SimpleNamespace(id="999")]
            self.thread: _Target | None = None
            self.created_thread = created_thread

        async def create_thread(self, *, name: str) -> _Target:
            assert name == f"shisad-{self.id}"
            assert self.created_thread is not None
            self.thread = self.created_thread
            return self.created_thread

    monkeypatch.setattr(
        discord_module,
        "discord",
        SimpleNamespace(Intents=_Intents, Client=_Client),
    )
    parent = _Target("100")
    thread_one = _Target("201", parent_id="100")
    thread_two = _Target("202", parent_id="100")
    channel = DiscordChannel(DiscordConfig(bot_token="token", use_threads=True))
    await channel.connect()
    assert isinstance(channel._client, _Client)
    channel._client.targets = {100: parent, 201: thread_one, 202: thread_two}

    first = _Message(message_id="201", channel=parent, created_thread=thread_one)
    repeated = _Message(message_id="301", channel=thread_one)
    sibling = _Message(message_id="202", channel=parent, created_thread=thread_two)
    await channel._client.on_message(first)
    await channel._client.on_message(repeated)
    await channel._client.on_message(sibling)
    incoming = [await asyncio.wait_for(channel.receive(), timeout=0.2) for _ in range(3)]

    manager = SessionManager()

    def session_for(message: ChannelMessage) -> Session:
        found = manager.find_by_binding(
            channel=message.channel,
            user_id=UserId(message.external_user_id),
            workspace_id=WorkspaceId(message.workspace_hint),
            delivery_thread_id=message.thread_id,
        )
        if found is not None:
            return found
        return manager.create(
            channel=message.channel,
            user_id=UserId(message.external_user_id),
            workspace_id=WorkspaceId(message.workspace_hint),
            metadata={
                "delivery_target": DeliveryTarget(
                    channel=message.channel,
                    recipient=message.reply_target,
                    workspace_hint=message.workspace_hint,
                    thread_id=message.thread_id,
                ).model_dump(mode="json")
            },
        )

    sessions = [session_for(message) for message in incoming]
    assert sessions[0] is sessions[1]
    assert sessions[2] is not sessions[0]

    for index in (0, 2):
        message = incoming[index]
        await channel.send(
            f"result-{index}",
            target=DeliveryTarget(
                channel="discord",
                recipient=message.reply_target,
                workspace_hint=message.workspace_hint,
                thread_id=message.thread_id,
            ),
        )
    assert thread_one.sent == ["result-0"]
    assert thread_two.sent == ["result-2"]
    assert parent.sent == []
    await channel.disconnect()
