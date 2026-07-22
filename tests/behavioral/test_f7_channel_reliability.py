"""Behavioral journeys for F7 chosen-channel reliability."""

from __future__ import annotations

import asyncio
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from shisad.channels import state as channel_state
from shisad.channels.base import ChannelMessage
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


async def _run_one_pump(
    *,
    root: Path,
    marker: object,
    message: ChannelMessage,
) -> _ReplayJourneyImpl:
    shutdown = asyncio.Event()
    impl = _ReplayJourneyImpl(root=root, marker=marker)
    handlers = AdminHandlers(impl, internal_ingress_marker=marker)  # type: ignore[arg-type]
    await channel_receive_pump(
        channel_name="matrix",
        channel=_OneMessageChannel(message, shutdown),  # type: ignore[arg-type]
        shutdown_event=shutdown,
        handlers=handlers,
    )
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
