"""Focused channel receive-pump integration coverage."""

from __future__ import annotations

import asyncio
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

from shisad.channels.base import InMemoryChannel
from shisad.channels.discord import DiscordChannel
from shisad.channels.matrix import MatrixChannel
from shisad.channels.slack import SlackChannel
from shisad.channels.telegram import TelegramChannel
from shisad.core.api.transport import ControlClient
from shisad.core.config import DaemonConfig
from shisad.daemon.runner import run_daemon
from tests.helpers.daemon import wait_for_socket as _wait_for_socket


@pytest.fixture
def model_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SHISAD_MODEL_BASE_URL", "https://api.example.com/v1")
    monkeypatch.setenv("SHISAD_MODEL_PLANNER_BASE_URL", "https://planner.example.com/v1")
    monkeypatch.setenv("SHISAD_MODEL_EMBEDDINGS_BASE_URL", "https://embed.example.com/v1")
    monkeypatch.setenv("SHISAD_MODEL_MONITOR_BASE_URL", "https://monitor.example.com/v1")


@dataclass(frozen=True)
class _PumpCase:
    channel_name: str
    channel_cls: type[Any]
    config_overrides: dict[str, object]
    workspace_hint: str
    allowed_user: str
    blocked_user: str


_CASES: tuple[_PumpCase, ...] = (
    _PumpCase(
        channel_name="matrix",
        channel_cls=MatrixChannel,
        config_overrides={
            "matrix_enabled": True,
            "matrix_homeserver": "https://matrix.example.org",
            "matrix_user_id": "@bot:example.org",
            "matrix_access_token": "token",
            "matrix_room_id": "!room:example.org",
        },
        workspace_hint="!room:example.org",
        allowed_user="@alice:example.org",
        blocked_user="@mallory:example.org",
    ),
    _PumpCase(
        channel_name="discord",
        channel_cls=DiscordChannel,
        config_overrides={
            "discord_enabled": True,
            "discord_bot_token": "token",
        },
        workspace_hint="guild-1",
        allowed_user="discord-allow",
        blocked_user="discord-blocked",
    ),
    _PumpCase(
        channel_name="telegram",
        channel_cls=TelegramChannel,
        config_overrides={
            "telegram_enabled": True,
            "telegram_bot_token": "token",
        },
        workspace_hint="chat-1",
        allowed_user="telegram-allow",
        blocked_user="telegram-blocked",
    ),
    _PumpCase(
        channel_name="slack",
        channel_cls=SlackChannel,
        config_overrides={
            "slack_enabled": True,
            "slack_bot_token": "xoxb-token",
            "slack_app_token": "xapp-token",
        },
        workspace_hint="team-1",
        allowed_user="slack-allow",
        blocked_user="slack-blocked",
    ),
)


@pytest.mark.asyncio
@pytest.mark.parametrize("case", _CASES, ids=[item.channel_name for item in _CASES])
async def test_m3_channel_pump_enforces_allowlist_routes_session_and_emits_audit(
    model_env: None,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    case: _PumpCase,
) -> None:
    async def _fake_connect(self: InMemoryChannel) -> None:
        await InMemoryChannel.connect(self)
        await self.inject(case.blocked_user, "blocked inbound message", case.workspace_hint)
        await self.inject(case.allowed_user, "allowed inbound message", case.workspace_hint)

    monkeypatch.setattr(case.channel_cls, "connect", _fake_connect)

    config_kwargs: dict[str, object] = {
        "data_dir": tmp_path / "data",
        "socket_path": tmp_path / "control.sock",
        "policy_path": tmp_path / "policy.yaml",
        "log_level": "INFO",
        "channel_identity_allowlist": {case.channel_name: [case.allowed_user]},
    }
    config_kwargs.update(case.config_overrides)
    config = DaemonConfig(**config_kwargs)

    daemon_task = asyncio.create_task(run_daemon(config))
    client = ControlClient(config.socket_path)
    try:
        await _wait_for_socket(config.socket_path)
        await client.connect()

        allowed_sessions: list[dict[str, Any]] = []
        blocked_sessions: list[dict[str, Any]] = []
        pairing_matches: list[dict[str, Any]] = []
        delivery_matches: list[dict[str, Any]] = []
        received_total = 0
        for _ in range(80):
            sessions = await client.call("session.list")
            session_rows = sessions.get("sessions", [])
            if isinstance(session_rows, list):
                allowed_sessions = [
                    item
                    for item in session_rows
                    if isinstance(item, dict)
                    and item.get("channel") == case.channel_name
                    and item.get("user_id") == case.allowed_user
                ]
                blocked_sessions = [
                    item
                    for item in session_rows
                    if isinstance(item, dict)
                    and item.get("channel") == case.channel_name
                    and item.get("user_id") == case.blocked_user
                ]

            received = await client.call(
                "audit.query",
                {
                    "event_type": "SessionMessageReceived",
                    "actor": case.allowed_user,
                    "limit": 20,
                },
            )
            received_total = int(received.get("total", 0))

            pairing = await client.call(
                "audit.query",
                {
                    "event_type": "ChannelPairingRequested",
                    "actor": "channel_ingest",
                    "limit": 20,
                },
            )
            pairing_rows = pairing.get("events", [])
            if isinstance(pairing_rows, list):
                pairing_matches = [
                    item.get("data", {})
                    for item in pairing_rows
                    if isinstance(item, dict)
                    and isinstance(item.get("data"), dict)
                    and item["data"].get("channel") == case.channel_name
                    and item["data"].get("external_user_id") == case.blocked_user
                ]

            delivery = await client.call(
                "audit.query",
                {
                    "event_type": "ChannelDeliveryAttempted",
                    "actor": "channel_delivery",
                    "limit": 20,
                },
            )
            delivery_rows = delivery.get("events", [])
            if isinstance(delivery_rows, list):
                delivery_matches = [
                    item.get("data", {})
                    for item in delivery_rows
                    if isinstance(item, dict)
                    and isinstance(item.get("data"), dict)
                    and item["data"].get("channel") == case.channel_name
                ]

            if (
                len(allowed_sessions) == 1
                and not blocked_sessions
                and received_total >= 1
                and pairing_matches
                and delivery_matches
            ):
                break
            await asyncio.sleep(0.05)

        assert len(allowed_sessions) == 1
        assert blocked_sessions == []
        assert received_total >= 1
        assert pairing_matches
        assert delivery_matches
    finally:
        with suppress(Exception):
            await client.call("daemon.shutdown")
        await client.close()
        await asyncio.wait_for(daemon_task, timeout=3)
