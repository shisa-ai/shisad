"""Discord channel integration with optional runtime dependency."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import re
from dataclasses import dataclass
from typing import Any

from shisad.channels.base import ChannelMessage, DeliveryTarget, InMemoryChannel

try:  # pragma: no cover - optional dependency.
    import discord  # type: ignore
except ImportError:  # pragma: no cover - optional dependency.
    discord = None

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class DiscordConfig:
    bot_token: str
    default_channel_id: str = ""
    guild_workspace_map: dict[str, str] | None = None
    trusted_users: set[str] | None = None


class DiscordChannel(InMemoryChannel):
    """Discord wrapper with in-memory fallback when discord.py is unavailable."""

    def __init__(self, config: DiscordConfig) -> None:
        super().__init__(name="discord")
        self._config = config
        self._client: Any | None = None
        self._client_task: asyncio.Task[None] | None = None

    @property
    def available(self) -> bool:
        return discord is not None

    async def connect(self) -> None:
        await super().connect()
        if discord is None or not self._config.bot_token:
            return
        if self._client_task is not None and not self._client_task.done():
            return

        intents_ctor = getattr(discord, "Intents", None)
        client_ctor = getattr(discord, "Client", None)
        if intents_ctor is None or client_ctor is None:
            return
        intents = intents_ctor.default()
        if hasattr(intents, "message_content"):
            intents.message_content = True
        self._client = client_ctor(intents=intents)
        event_decorator = getattr(self._client, "event", None)
        if callable(event_decorator):
            async def on_message(message: Any) -> None:
                author = getattr(message, "author", None)
                if author is None:
                    return
                if bool(getattr(author, "bot", False)):
                    return
                guild = getattr(message, "guild", None)
                # In guild channels, only respond when the bot is @mentioned.
                # DMs (guild is None) are always processed.
                if guild is not None and self._client is not None:
                    bot_user = getattr(self._client, "user", None)
                    if bot_user is not None:
                        bot_id = str(getattr(bot_user, "id", ""))
                        mentions = getattr(message, "mentions", []) or []
                        mention_ids = {
                            str(getattr(m, "id", "")) for m in mentions
                        }
                        if bot_id not in mention_ids:
                            return
                content = str(getattr(message, "content", "")).strip()
                # Strip the bot mention tag from content so the planner
                # receives clean text (e.g. "<@123456> hello" → "hello").
                if self._client is not None:
                    bot_user = getattr(self._client, "user", None)
                    if bot_user is not None:
                        bot_id = str(getattr(bot_user, "id", ""))
                        if bot_id:
                            content = re.sub(
                                rf"<@!?{re.escape(bot_id)}>\s*", "", content
                            ).strip()
                if not content:
                    return
                guild_id = str(getattr(guild, "id", "")) if guild is not None else ""
                channel_obj = getattr(message, "channel", None)
                channel_id = str(getattr(channel_obj, "id", "")) if channel_obj is not None else ""
                message_id = str(getattr(message, "id", "")) if message is not None else ""
                await self._incoming.put(
                    ChannelMessage(
                        channel="discord",
                        external_user_id=str(getattr(author, "id", "")),
                        workspace_hint=self.workspace_for_guild(guild_id),
                        content=content,
                        message_id=message_id,
                        reply_target=channel_id,
                    )
                )

            event_decorator(on_message)

        start = getattr(self._client, "start", None)
        if callable(start):
            self._client_task = asyncio.create_task(start(self._config.bot_token))

    async def disconnect(self) -> None:
        if self._client is not None:
            close = getattr(self._client, "close", None)
            if callable(close):
                with contextlib.suppress(OSError, RuntimeError):
                    result = close()
                    if asyncio.iscoroutine(result):
                        await result
        if self._client_task is not None:
            self._client_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._client_task
            self._client_task = None
        self._client = None
        await super().disconnect()

    async def send(self, message: str, *, target: DeliveryTarget | None = None) -> None:
        if self._client is not None:
            recipient = (target.recipient if target is not None else "").strip()
            if not recipient:
                recipient = self._config.default_channel_id
            if recipient:
                try:
                    channel_id = int(recipient)
                except ValueError:
                    channel_id = 0
                if channel_id:
                    channel_obj = None
                    get_channel = getattr(self._client, "get_channel", None)
                    if callable(get_channel):
                        channel_obj = get_channel(channel_id)
                    if channel_obj is None:
                        fetch_channel = getattr(self._client, "fetch_channel", None)
                        if callable(fetch_channel):
                            channel_obj = await fetch_channel(channel_id)
                    if channel_obj is not None:
                        send = getattr(channel_obj, "send", None)
                        if callable(send):
                            await send(message)
                            return
        await super().send(message, target=target)

    def workspace_for_guild(self, guild_id: str) -> str:
        mapping = self._config.guild_workspace_map or {}
        if guild_id:
            return mapping.get(guild_id, guild_id)
        return "discord"

    def is_user_verified(self, user_id: str) -> bool:
        trusted = self._config.trusted_users or set()
        return user_id in trusted

    def health_status(self) -> dict[str, Any]:
        status = super().health_status()
        status.update({"available": self.available, "client_active": self._client is not None})
        return status
