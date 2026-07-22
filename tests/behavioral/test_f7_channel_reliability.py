"""Behavioral journeys for F7 chosen-channel reliability."""

from __future__ import annotations

import asyncio
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from shisad.channels import state as channel_state
from shisad.channels.base import ChannelMessage, DeliveryTarget, InMemoryChannel
from shisad.channels.delivery import ChannelDeliveryService, DeliveryIntent
from shisad.core.transcript import TranscriptStore
from shisad.core.types import SessionId
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
