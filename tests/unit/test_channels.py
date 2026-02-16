"""M2 channel trust + matrix integration tests."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest

from shisad.channels.base import DeliveryTarget, InMemoryChannel
from shisad.channels.delivery import ChannelDeliveryService
from shisad.channels.discord import DiscordChannel, DiscordConfig
from shisad.channels.identity import ChannelIdentityMap
from shisad.channels.matrix import MatrixChannel, MatrixConfig
from shisad.channels.slack import SlackChannel, SlackConfig
from shisad.channels.state import ChannelStateStore
from shisad.channels.telegram import TelegramChannel, TelegramConfig
from shisad.core.tools.registry import ToolRegistry
from shisad.core.tools.schema import ToolDefinition, ToolParameter
from shisad.core.types import Capability, PEPDecisionKind, ToolName, UserId, WorkspaceId
from shisad.security.pep import PEP, PolicyContext
from shisad.security.policy import EgressRule, PolicyBundle, RiskPolicy


def test_channel_identity_map_applies_per_channel_default_trust() -> None:
    identity_map = ChannelIdentityMap(default_trust={"matrix": "trusted"})
    identity_map.bind(
        channel="matrix",
        external_user_id="@alice:example.org",
        user_id=UserId("alice"),
        workspace_id=WorkspaceId("ws-main"),
    )
    identity = identity_map.resolve(channel="matrix", external_user_id="@alice:example.org")
    assert identity is not None
    assert identity.trust_level == "trusted"

    identity_map.configure_channel_trust(channel="matrix", trust_level="untrusted")
    identity_map.bind(
        channel="matrix",
        external_user_id="@bob:example.org",
        user_id=UserId("bob"),
        workspace_id=WorkspaceId("ws-main"),
    )
    bob = identity_map.resolve(channel="matrix", external_user_id="@bob:example.org")
    assert bob is not None
    assert bob.trust_level == "untrusted"


def test_channel_identity_map_default_deny_allowlist_and_pairing_requests() -> None:
    identity_map = ChannelIdentityMap(default_trust={"discord": "untrusted"})
    assert identity_map.is_allowed(channel="discord", external_user_id="123") is False

    pairing, is_new = identity_map.record_pairing_request(
        channel="discord",
        external_user_id="123",
        workspace_hint="guild-1",
    )
    assert is_new is True
    assert pairing.channel == "discord"
    assert pairing.external_user_id == "123"
    repeated, is_new = identity_map.record_pairing_request(
        channel="discord",
        external_user_id="123",
        workspace_hint="guild-1",
    )
    assert is_new is False
    assert repeated == pairing

    identity_map.allow_identity(channel="discord", external_user_id="123")
    assert identity_map.is_allowed(channel="discord", external_user_id="123 ")


def test_channel_trust_level_influences_pep_risk_outcome() -> None:
    registry = ToolRegistry()
    registry.register(
        ToolDefinition(
            name=ToolName("http_request"),
            description="HTTP request",
            parameters=[ToolParameter(name="url", type="string", required=True)],
            capabilities_required=[Capability.HTTP_REQUEST],
            require_confirmation=False,
        )
    )
    policy = PolicyBundle(
        default_require_confirmation=False,
        egress=[EgressRule(host="api.example.com", protocols=["https"], ports=[443])],
        risk_policy=RiskPolicy(auto_approve_threshold=0.4, block_threshold=0.9),
    )
    pep = PEP(policy, registry)

    untrusted = pep.evaluate(
        ToolName("http_request"),
        {"url": "https://api.example.com/v1/send"},
        PolicyContext(
            capabilities={Capability.HTTP_REQUEST},
            trust_level="untrusted",
        ),
    )
    trusted = pep.evaluate(
        ToolName("http_request"),
        {"url": "https://api.example.com/v1/send"},
        PolicyContext(
            capabilities={Capability.HTTP_REQUEST},
            trust_level="trusted",
        ),
    )

    assert untrusted.kind == PEPDecisionKind.REQUIRE_CONFIRMATION
    assert trusted.kind == PEPDecisionKind.ALLOW


@pytest.mark.asyncio
async def test_inmemory_channel_offline_buffer_heartbeat_and_health() -> None:
    channel = InMemoryChannel(name="test", max_buffer=8)
    await channel.send("queued-while-offline")
    assert channel.pending_outgoing() == 1

    await channel.connect()
    health = channel.health_status()
    assert health["connected"] is True
    assert health["last_heartbeat"] is not None
    assert channel.pending_outgoing() == 1
    assert await channel.pop_outgoing() == "queued-while-offline"

    await channel.heartbeat()
    assert channel.health_status()["heartbeat_age_seconds"] is not None
    await channel.disconnect()


@pytest.mark.asyncio
async def test_channel_delivery_service_routes_to_targeted_channel() -> None:
    channel = InMemoryChannel(name="discord")
    await channel.connect()
    delivery = ChannelDeliveryService({"discord": channel})
    result = await delivery.send(
        target=DeliveryTarget(channel="discord", recipient="chan-1", workspace_hint="guild-1"),
        message="hello world",
    )
    assert result.sent is True
    envelope = await channel.pop_outgoing_delivery()
    assert envelope.content == "hello world"
    assert envelope.target.recipient == "chan-1"
    await channel.disconnect()


@pytest.mark.asyncio
async def test_channel_delivery_service_treats_dependency_unavailable_as_unsent() -> None:
    class _UnavailableChannel(InMemoryChannel):
        @property
        def available(self) -> bool:
            return False

    channel = _UnavailableChannel(name="discord")
    await channel.connect()
    delivery = ChannelDeliveryService({"discord": channel})
    result = await delivery.send(
        target=DeliveryTarget(channel="discord", recipient="chan-1"),
        message="hello world",
    )
    assert result.sent is False
    assert result.reason == "channel_dependency_unavailable"
    await channel.disconnect()


def test_channel_state_store_persists_seen_message_ids(tmp_path) -> None:
    store = ChannelStateStore(tmp_path / "state")
    assert store.is_replay(channel="matrix", message_id="m1") is False
    assert store.is_replay(channel="matrix", message_id="m1") is True

    reloaded = ChannelStateStore(tmp_path / "state")
    assert reloaded.is_replay(channel="matrix", message_id="m1") is True
    assert reloaded.is_replay(channel="matrix", message_id="m2") is False


@pytest.mark.asyncio
async def test_inmemory_channel_reconnect_exponential_backoff() -> None:
    channel = InMemoryChannel(
        name="test",
        reconnect_backoff_base=0.001,
        reconnect_backoff_max=0.002,
    )
    attempts = {"count": 0}

    async def flaky_operation() -> str:
        attempts["count"] += 1
        if attempts["count"] < 3:
            raise ConnectionError("transient")
        return "ok"

    result = await channel.run_with_reconnect(flaky_operation, attempts=4)
    assert result == "ok"
    assert attempts["count"] == 3


@pytest.mark.asyncio
async def test_discord_telegram_slack_fallback_channels_support_inmemory_io(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from shisad.channels import discord as discord_module
    from shisad.channels import slack as slack_module
    from shisad.channels import telegram as telegram_module

    monkeypatch.setattr(discord_module, "discord", None)
    monkeypatch.setattr(telegram_module, "Application", None)
    monkeypatch.setattr(telegram_module, "MessageHandler", None)
    monkeypatch.setattr(telegram_module, "filters", None)
    monkeypatch.setattr(slack_module, "AsyncApp", None)
    monkeypatch.setattr(slack_module, "AsyncSocketModeHandler", None)

    discord_channel = DiscordChannel(DiscordConfig(bot_token="token"))
    telegram_channel = TelegramChannel(TelegramConfig(bot_token="token"))
    slack_channel = SlackChannel(SlackConfig(bot_token="xoxb", app_token="xapp"))
    channels = [discord_channel, telegram_channel, slack_channel]

    for channel in channels:
        await channel.connect()
        await channel.inject(external_user_id="u1", content="hello", workspace_hint="ws1")
        msg = await channel.receive()
        assert msg.content == "hello"
        await channel.send("reply", target=DeliveryTarget(channel=msg.channel, recipient="r1"))
        assert await channel.pop_outgoing() == "reply"
        await channel.disconnect()


@pytest.mark.asyncio
async def test_discord_channel_registers_dispatchable_on_message_handler(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from shisad.channels import discord as discord_module

    class _FakeIntents:
        def __init__(self) -> None:
            self.message_content = False

        @classmethod
        def default(cls) -> _FakeIntents:
            return cls()

    class _FakeClient:
        def __init__(self, *, intents: _FakeIntents) -> None:
            self.intents = intents
            self.user = SimpleNamespace(id="bot-999")

        def event(self, coro):
            setattr(self, coro.__name__, coro)
            return coro

        async def start(self, _token: str) -> None:
            return None

        async def close(self) -> None:
            return None

        async def dispatch(self, message: object) -> None:
            handler = getattr(self, "on_message", None)
            if handler is not None:
                await handler(message)

    monkeypatch.setattr(
        discord_module,
        "discord",
        SimpleNamespace(Intents=_FakeIntents, Client=_FakeClient),
    )

    channel = DiscordChannel(DiscordConfig(bot_token="token"))
    await channel.connect()
    assert channel._client is not None
    bot_user = SimpleNamespace(id="bot-999")
    # Guild message with bot mention — should be processed.
    message = SimpleNamespace(
        author=SimpleNamespace(id="u-1", bot=False),
        content="<@bot-999> hello",
        guild=SimpleNamespace(id="g-1"),
        channel=SimpleNamespace(id="c-1"),
        id="m-1",
        mentions=[bot_user],
    )
    await channel._client.dispatch(message)
    received = await asyncio.wait_for(channel.receive(), timeout=0.2)
    assert received.channel == "discord"
    assert received.external_user_id == "u-1"
    assert received.reply_target == "c-1"
    # Bot mention tag should be stripped from content.
    assert received.content == "hello"
    await channel.disconnect()


@pytest.mark.asyncio
async def test_discord_channel_ignores_guild_messages_without_mention(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Guild messages that don't @mention the bot should be silently dropped."""
    from shisad.channels import discord as discord_module

    class _FakeIntents:
        def __init__(self) -> None:
            self.message_content = False

        @classmethod
        def default(cls) -> _FakeIntents:
            return cls()

    class _FakeClient:
        def __init__(self, *, intents: _FakeIntents) -> None:
            self.intents = intents
            self.user = SimpleNamespace(id="bot-999")

        def event(self, coro):
            setattr(self, coro.__name__, coro)
            return coro

        async def start(self, _token: str) -> None:
            return None

        async def close(self) -> None:
            return None

        async def dispatch(self, message: object) -> None:
            handler = getattr(self, "on_message", None)
            if handler is not None:
                await handler(message)

    monkeypatch.setattr(
        discord_module,
        "discord",
        SimpleNamespace(Intents=_FakeIntents, Client=_FakeClient),
    )

    channel = DiscordChannel(DiscordConfig(bot_token="token"))
    await channel.connect()
    assert channel._client is not None
    # Guild message WITHOUT bot mention — should be ignored.
    message = SimpleNamespace(
        author=SimpleNamespace(id="u-1", bot=False),
        content="la la la",
        guild=SimpleNamespace(id="g-1"),
        channel=SimpleNamespace(id="c-1"),
        id="m-2",
        mentions=[],
    )
    await channel._client.dispatch(message)
    with pytest.raises(TimeoutError):
        await asyncio.wait_for(channel.receive(), timeout=0.1)
    await channel.disconnect()


@pytest.mark.asyncio
async def test_discord_channel_processes_dm_without_mention(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """DMs (guild=None) should always be processed, no mention required."""
    from shisad.channels import discord as discord_module

    class _FakeIntents:
        def __init__(self) -> None:
            self.message_content = False

        @classmethod
        def default(cls) -> _FakeIntents:
            return cls()

    class _FakeClient:
        def __init__(self, *, intents: _FakeIntents) -> None:
            self.intents = intents
            self.user = SimpleNamespace(id="bot-999")

        def event(self, coro):
            setattr(self, coro.__name__, coro)
            return coro

        async def start(self, _token: str) -> None:
            return None

        async def close(self) -> None:
            return None

        async def dispatch(self, message: object) -> None:
            handler = getattr(self, "on_message", None)
            if handler is not None:
                await handler(message)

    monkeypatch.setattr(
        discord_module,
        "discord",
        SimpleNamespace(Intents=_FakeIntents, Client=_FakeClient),
    )

    channel = DiscordChannel(DiscordConfig(bot_token="token"))
    await channel.connect()
    assert channel._client is not None
    # DM — no guild, no mention required.
    message = SimpleNamespace(
        author=SimpleNamespace(id="u-2", bot=False),
        content="hey there",
        guild=None,
        channel=SimpleNamespace(id="dm-1"),
        id="m-3",
        mentions=[],
    )
    await channel._client.dispatch(message)
    received = await asyncio.wait_for(channel.receive(), timeout=0.2)
    assert received.channel == "discord"
    assert received.external_user_id == "u-2"
    assert received.content == "hey there"
    await channel.disconnect()


@pytest.mark.asyncio
async def test_discord_channel_accepts_raw_mentions_when_mentions_are_unresolved(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Guild mentions should still route when only raw mention ids are populated."""
    from shisad.channels import discord as discord_module

    class _FakeIntents:
        def __init__(self) -> None:
            self.message_content = False

        @classmethod
        def default(cls) -> _FakeIntents:
            return cls()

    class _FakeClient:
        def __init__(self, *, intents: _FakeIntents) -> None:
            self.intents = intents
            self.user = SimpleNamespace(id="bot-999")

        def event(self, coro):
            setattr(self, coro.__name__, coro)
            return coro

        async def start(self, _token: str) -> None:
            return None

        async def close(self) -> None:
            return None

        async def dispatch(self, message: object) -> None:
            handler = getattr(self, "on_message", None)
            if handler is not None:
                await handler(message)

    monkeypatch.setattr(
        discord_module,
        "discord",
        SimpleNamespace(Intents=_FakeIntents, Client=_FakeClient),
    )

    channel = DiscordChannel(DiscordConfig(bot_token="token"))
    await channel.connect()
    assert channel._client is not None
    message = SimpleNamespace(
        author=SimpleNamespace(id="u-3", bot=False),
        content="<@bot-999> trace five",
        guild=SimpleNamespace(id="g-1"),
        channel=SimpleNamespace(id="c-1"),
        id="m-4",
        mentions=[],
        raw_mentions=["bot-999"],
    )
    await channel._client.dispatch(message)
    received = await asyncio.wait_for(channel.receive(), timeout=0.2)
    assert received.channel == "discord"
    assert received.external_user_id == "u-3"
    assert received.reply_target == "c-1"
    assert received.content == "trace five"
    await channel.disconnect()


@pytest.mark.asyncio
async def test_discord_channel_accepts_plain_name_prefix_without_mentions(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Guild messages can use @botname prefix even if mentions are unresolved."""
    from shisad.channels import discord as discord_module

    class _FakeIntents:
        def __init__(self) -> None:
            self.message_content = False

        @classmethod
        def default(cls) -> _FakeIntents:
            return cls()

    class _FakeClient:
        def __init__(self, *, intents: _FakeIntents) -> None:
            self.intents = intents
            self.user = SimpleNamespace(
                id="bot-999",
                name="shisad",
                display_name="Shisad",
                global_name="SHISAD",
            )

        def event(self, coro):
            setattr(self, coro.__name__, coro)
            return coro

        async def start(self, _token: str) -> None:
            return None

        async def close(self) -> None:
            return None

        async def dispatch(self, message: object) -> None:
            handler = getattr(self, "on_message", None)
            if handler is not None:
                await handler(message)

    monkeypatch.setattr(
        discord_module,
        "discord",
        SimpleNamespace(Intents=_FakeIntents, Client=_FakeClient),
    )

    channel = DiscordChannel(DiscordConfig(bot_token="token"))
    await channel.connect()
    assert channel._client is not None
    message = SimpleNamespace(
        author=SimpleNamespace(id="u-4", bot=False),
        content="@shisad trace six xyz123",
        guild=SimpleNamespace(id="g-1"),
        channel=SimpleNamespace(id="c-1"),
        id="m-5",
        mentions=[],
        raw_mentions=[],
    )
    await channel._client.dispatch(message)
    received = await asyncio.wait_for(channel.receive(), timeout=0.2)
    assert received.channel == "discord"
    assert received.external_user_id == "u-4"
    assert received.reply_target == "c-1"
    assert received.content == "trace six xyz123"
    await channel.disconnect()


@pytest.mark.asyncio
async def test_discord_channel_ignores_plain_name_when_not_prefix(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Plain @botname text should only trigger when used as a prefix."""
    from shisad.channels import discord as discord_module

    class _FakeIntents:
        def __init__(self) -> None:
            self.message_content = False

        @classmethod
        def default(cls) -> _FakeIntents:
            return cls()

    class _FakeClient:
        def __init__(self, *, intents: _FakeIntents) -> None:
            self.intents = intents
            self.user = SimpleNamespace(id="bot-999", name="shisad")

        def event(self, coro):
            setattr(self, coro.__name__, coro)
            return coro

        async def start(self, _token: str) -> None:
            return None

        async def close(self) -> None:
            return None

        async def dispatch(self, message: object) -> None:
            handler = getattr(self, "on_message", None)
            if handler is not None:
                await handler(message)

    monkeypatch.setattr(
        discord_module,
        "discord",
        SimpleNamespace(Intents=_FakeIntents, Client=_FakeClient),
    )

    channel = DiscordChannel(DiscordConfig(bot_token="token"))
    await channel.connect()
    assert channel._client is not None
    message = SimpleNamespace(
        author=SimpleNamespace(id="u-5", bot=False),
        content="can @shisad see this",
        guild=SimpleNamespace(id="g-1"),
        channel=SimpleNamespace(id="c-1"),
        id="m-6",
        mentions=[],
        raw_mentions=[],
    )
    await channel._client.dispatch(message)
    with pytest.raises(TimeoutError):
        await asyncio.wait_for(channel.receive(), timeout=0.1)
    await channel.disconnect()


@pytest.mark.asyncio
async def test_slack_channel_handler_accepts_say_and_filters_bot_messages(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from shisad.channels import slack as slack_module

    class _FakeApp:
        def __init__(self, *, token: str) -> None:
            self.token = token
            self._callbacks: dict[str, object] = {}
            self.client = SimpleNamespace(chat_postMessage=self._chat_post_message)

        async def _chat_post_message(self, **_kwargs: object) -> None:
            return None

        def event(self, name: str):
            def _decorator(callback):
                self._callbacks[name] = callback
                return callback

            return _decorator

        async def invoke_message(self, event: dict[str, object], body: dict[str, object]) -> None:
            callback = self._callbacks["message"]
            await callback(event=event, body=body, say=lambda *_args, **_kwargs: None)

    class _FakeSocketHandler:
        def __init__(self, app: _FakeApp, _token: str) -> None:
            self.app = app

        async def start_async(self) -> None:
            return None

        async def close_async(self) -> None:
            return None

    monkeypatch.setattr(slack_module, "AsyncApp", _FakeApp)
    monkeypatch.setattr(slack_module, "AsyncSocketModeHandler", _FakeSocketHandler)

    channel = SlackChannel(SlackConfig(bot_token="xoxb", app_token="xapp"))
    await channel.connect()
    assert channel._app is not None
    await channel._app.invoke_message(
        event={"user": "U1", "text": "bot echo", "channel": "C1", "bot_id": "B1"},
        body={"team_id": "T1"},
    )
    with pytest.raises(asyncio.TimeoutError):
        await asyncio.wait_for(channel.receive(), timeout=0.05)
    await channel._app.invoke_message(
        event={"user": "U1", "text": "hello", "channel": "C1", "ts": "1.23"},
        body={"team_id": "T1"},
    )
    message = await asyncio.wait_for(channel.receive(), timeout=0.2)
    assert message.channel == "slack"
    assert message.external_user_id == "U1"
    assert message.workspace_hint == "T1"
    await channel.disconnect()


@pytest.mark.asyncio
async def test_telegram_channel_ignores_bot_messages(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from shisad.channels import telegram as telegram_module

    class _FakeFilter:
        def __and__(self, _other: object) -> _FakeFilter:
            return self

        def __invert__(self) -> _FakeFilter:
            return self

    class _FakeMessageHandler:
        def __init__(self, _filters: object, callback) -> None:
            self.callback = callback

    class _FakeUpdater:
        async def start_polling(self) -> None:
            return None

        async def stop(self) -> None:
            return None

    class _FakeApplication:
        def __init__(self) -> None:
            self.handlers: list[_FakeMessageHandler] = []
            self.updater = _FakeUpdater()
            self.bot = SimpleNamespace(send_message=self._send_message)

        async def _send_message(self, **_kwargs: object) -> None:
            return None

        def add_handler(self, handler: _FakeMessageHandler) -> None:
            self.handlers.append(handler)

        async def initialize(self) -> None:
            return None

        async def start(self) -> None:
            return None

        async def stop(self) -> None:
            return None

        async def shutdown(self) -> None:
            return None

    class _FakeApplicationBuilder:
        def __init__(self) -> None:
            self._token = ""

        def token(self, token: str) -> _FakeApplicationBuilder:
            self._token = token
            return self

        def build(self) -> _FakeApplication:
            return _FakeApplication()

    class _FakeApplicationFactory:
        @staticmethod
        def builder() -> _FakeApplicationBuilder:
            return _FakeApplicationBuilder()

    monkeypatch.setattr(telegram_module, "Application", _FakeApplicationFactory)
    monkeypatch.setattr(telegram_module, "MessageHandler", _FakeMessageHandler)
    monkeypatch.setattr(
        telegram_module,
        "filters",
        SimpleNamespace(TEXT=_FakeFilter(), COMMAND=_FakeFilter()),
    )

    channel = TelegramChannel(TelegramConfig(bot_token="token"))
    await channel.connect()
    assert channel._application is not None
    handler = channel._application.handlers[0]
    bot_update = SimpleNamespace(
        effective_message=SimpleNamespace(text="echo", message_id="m1", message_thread_id=""),
        effective_user=SimpleNamespace(id="bot-user", is_bot=True),
        effective_chat=SimpleNamespace(id="chat-1"),
    )
    await handler.callback(bot_update, None)
    with pytest.raises(asyncio.TimeoutError):
        await asyncio.wait_for(channel.receive(), timeout=0.05)
    user_update = SimpleNamespace(
        effective_message=SimpleNamespace(text="hello", message_id="m2", message_thread_id=""),
        effective_user=SimpleNamespace(id="u-1", is_bot=False),
        effective_chat=SimpleNamespace(id="chat-1"),
    )
    await handler.callback(user_update, None)
    message = await asyncio.wait_for(channel.receive(), timeout=0.2)
    assert message.channel == "telegram"
    assert message.external_user_id == "u-1"
    await channel.disconnect()


@pytest.mark.asyncio
async def test_matrix_channel_fallback_and_workspace_mapping(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from shisad.channels import matrix as matrix_module

    monkeypatch.setattr(matrix_module, "nio", None)

    channel = MatrixChannel(
        MatrixConfig(
            homeserver="https://matrix.example.org",
            user_id="@bot:example.org",
            access_token="token",
            room_id="!room:example.org",
            room_workspace_map={"!room:example.org": "workspace-1"},
            trusted_users={"@alice:example.org"},
        )
    )

    await channel.connect()
    await channel.inject(
        external_user_id="@alice:example.org",
        content="hello from matrix",
        workspace_hint="!room:example.org",
    )
    message = await channel.receive()

    assert message.channel == "matrix"
    assert message.external_user_id == "@alice:example.org"
    assert channel.workspace_for_room("!room:example.org") == "workspace-1"
    assert channel.is_user_verified("@alice:example.org")
    await channel.disconnect()
