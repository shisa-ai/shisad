"""Unit coverage for MatrixChannel optional transport paths.

CI enforces per-module coverage floors; this file exercises both the in-memory
fallback (nio unavailable) and a small dummy nio transport (nio available).
"""

from __future__ import annotations

import asyncio

import pytest

import shisad.channels.matrix as matrix_mod
from shisad.channels.base import DeliveryTarget
from shisad.channels.matrix import MatrixChannel, MatrixConfig


@pytest.mark.asyncio
async def test_matrix_channel_fallback_without_nio(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(matrix_mod, "nio", None)
    config = MatrixConfig(
        homeserver="https://example.invalid",
        user_id="@bot:example.invalid",
        access_token="token",
        room_id="!room:example.invalid",
    )
    channel = MatrixChannel(config)
    assert channel.available is False
    assert channel.e2ee_enabled is False

    await channel.connect()
    await channel.send("hello")
    assert await channel.pop_outgoing() == "hello"
    status = channel.health_status()
    assert status["available"] is False
    assert status["e2ee_enabled"] is False
    await channel.disconnect()


@pytest.mark.asyncio
async def test_matrix_channel_dummy_nio_paths(monkeypatch: pytest.MonkeyPatch) -> None:
    sync_block = asyncio.Event()

    class DummyClientConfig:
        def __init__(self, *, encryption_enabled: bool) -> None:
            self.encryption_enabled = encryption_enabled

    class DummyAsyncClient:
        def __init__(self, homeserver: str, user_id: str, *, config: object | None = None) -> None:
            self.homeserver = homeserver
            self.user_id = user_id
            self.config = config
            self.access_token: str = ""
            self.device_id: str = ""
            self.callbacks: list[tuple[object, object]] = []
            self.sent: list[dict[str, object]] = []
            self.closed = False

        def add_event_callback(self, callback: object, event_type: object) -> None:
            self.callbacks.append((callback, event_type))

        async def sync_forever(self, *, timeout: int, full_state: bool) -> None:
            _ = (timeout, full_state)
            await sync_block.wait()

        async def room_send(
            self,
            *,
            room_id: str,
            message_type: str,
            content: dict[str, object],
        ) -> None:
            self.sent.append(
                {
                    "room_id": room_id,
                    "message_type": message_type,
                    "content": dict(content),
                }
            )

        async def close(self) -> None:
            self.closed = True

    class DummyNio:
        AsyncClientConfig = DummyClientConfig
        AsyncClient = DummyAsyncClient
        RoomMessageText = object()

    monkeypatch.setattr(matrix_mod, "nio", DummyNio)

    config = MatrixConfig(
        homeserver="https://example.invalid",
        user_id="@bot:example.invalid",
        access_token="token",
        room_id="!room:example.invalid",
        device_id="dev1",
        enable_e2ee=True,
        room_workspace_map={"!room:example.invalid": "ws1"},
        trusted_users={"@alice:example.invalid"},
    )
    channel = MatrixChannel(config)
    assert channel.available is True
    assert channel.e2ee_enabled is True
    assert channel.workspace_for_room("!room:example.invalid") == "ws1"
    assert channel.is_user_verified("@alice:example.invalid") is True
    assert channel.is_user_verified("@bob:example.invalid") is False

    await channel.connect()
    assert channel.health_status()["available"] is True
    assert channel.health_status()["sync_task_running"] is True

    await channel.send(
        "hi",
        target=DeliveryTarget(channel="matrix", recipient="!other:example.invalid"),
    )
    client = channel._client  # type: ignore[attr-defined]
    assert isinstance(client, DummyAsyncClient)
    assert client.access_token == "token"
    assert client.device_id == "dev1"
    assert client.sent[0]["room_id"] == "!other:example.invalid"

    room = type("Room", (), {"room_id": "!room:example.invalid"})()
    event = type(
        "Event",
        (),
        {
            "body": "incoming",
            "sender": "@alice:example.invalid",
            "event_id": "$e1",
        },
    )()
    await channel._on_room_message(room, event)  # type: ignore[attr-defined]
    received = await channel.receive()
    assert received.content == "incoming"
    assert received.workspace_hint == "ws1"
    assert received.reply_target == "!room:example.invalid"

    await channel.disconnect()
    assert client.closed is True
