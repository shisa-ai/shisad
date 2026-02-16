"""Discord channel integration with optional runtime dependency."""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import logging
import re
from dataclasses import dataclass
from typing import Any

from shisad.channels.base import ChannelMessage, DeliveryTarget, InMemoryChannel

_discord: Any | None
try:  # pragma: no cover - optional dependency.
    import discord as _discord
except ImportError:  # pragma: no cover - optional dependency.
    _discord = None

discord: Any | None = _discord

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
                message_id = str(getattr(message, "id", ""))
                guild = getattr(message, "guild", None)
                guild_id = str(getattr(guild, "id", "")) if guild is not None else ""
                channel_obj = getattr(message, "channel", None)
                channel_id = str(getattr(channel_obj, "id", "")) if channel_obj is not None else ""
                author = getattr(message, "author", None)
                if author is None:
                    logger.debug(
                        "Discord ingress dropped "
                        "(reason=missing_author message_id=%s guild_id=%s channel_id=%s)",
                        message_id,
                        guild_id,
                        channel_id,
                    )
                    return
                author_id = str(getattr(author, "id", ""))
                if bool(getattr(author, "bot", False)):
                    logger.debug(
                        "Discord ingress dropped "
                        "(reason=author_is_bot message_id=%s guild_id=%s "
                        "channel_id=%s author_id=%s)",
                        message_id,
                        guild_id,
                        channel_id,
                        author_id,
                    )
                    return
                content = str(getattr(message, "content", "")).strip()
                logger.debug(
                    "Discord ingress received "
                    "(message_id=%s guild_id=%s channel_id=%s author_id=%s "
                    "content_len=%d content_hash=%s)",
                    message_id,
                    guild_id,
                    channel_id,
                    author_id,
                    len(content),
                    self._content_fingerprint(content),
                )
                # In guild channels, only respond when the bot is @mentioned.
                # DMs (guild is None) are always processed.
                addressed_by_resolved = False
                addressed_by_content_tag = False
                addressed_by_name_prefix = False
                if guild is not None and self._client is not None:
                    bot_user = getattr(self._client, "user", None)
                    if bot_user is not None:
                        bot_id = str(getattr(bot_user, "id", "")).strip()
                        mention_ids = self._message_mention_ids(message)
                        addressed_by_resolved = bot_id in mention_ids
                        addressed_by_content_tag = self._content_mentions_bot(
                            content, bot_id
                        )
                        name_aliases = self._bot_name_aliases(bot_user)
                        addressed_by_name_prefix = self._content_mentions_bot_name_prefix(
                            content, name_aliases
                        )
                        if (
                            not addressed_by_resolved
                            and not addressed_by_content_tag
                            and not addressed_by_name_prefix
                        ):
                            raw_mentions = tuple(
                                mention_id
                                for mention_id in (
                                    str(raw_mention).strip()
                                    for raw_mention in (
                                        getattr(message, "raw_mentions", []) or []
                                    )
                                )
                                if mention_id
                            )
                            logger.debug(
                                "Discord ingress dropped "
                                "(reason=not_addressed message_id=%s guild_id=%s channel_id=%s "
                                "author_id=%s bot_id=%s mention_ids=%s raw_mentions=%s aliases=%s)",
                                message_id,
                                guild_id,
                                channel_id,
                                author_id,
                                bot_id,
                                sorted(mention_ids),
                                list(raw_mentions),
                                list(name_aliases),
                            )
                            return
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
                        content = self._strip_plain_name_prefix(
                            content, self._bot_name_aliases(bot_user)
                        )
                if not content:
                    logger.debug(
                        "Discord ingress dropped "
                        "(reason=empty_after_strip message_id=%s guild_id=%s "
                        "channel_id=%s author_id=%s)",
                        message_id,
                        guild_id,
                        channel_id,
                        author_id,
                    )
                    return
                workspace_hint = self.workspace_for_guild(guild_id)
                logger.debug(
                    "Discord ingress accepted "
                    "(message_id=%s guild_id=%s channel_id=%s author_id=%s workspace_hint=%s "
                    "addressed_by_resolved=%s addressed_by_content_tag=%s "
                    "addressed_by_name_prefix=%s content_len=%d content_hash=%s)",
                    message_id,
                    guild_id,
                    channel_id,
                    author_id,
                    workspace_hint,
                    addressed_by_resolved,
                    addressed_by_content_tag,
                    addressed_by_name_prefix,
                    len(content),
                    self._content_fingerprint(content),
                )
                await self._incoming.put(
                    ChannelMessage(
                        channel="discord",
                        external_user_id=author_id,
                        workspace_hint=workspace_hint,
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

    @staticmethod
    def _message_mention_ids(message: Any) -> set[str]:
        mention_ids = {
            str(getattr(member, "id", "")).strip()
            for member in (getattr(message, "mentions", []) or [])
        }
        mention_ids.discard("")
        for raw_mention in (getattr(message, "raw_mentions", []) or []):
            mention_id = str(raw_mention).strip()
            if mention_id:
                mention_ids.add(mention_id)
        return mention_ids

    @staticmethod
    def _content_mentions_bot(content: str, bot_id: str) -> bool:
        if not content or not bot_id:
            return False
        return re.search(rf"<@!?{re.escape(bot_id)}>", content) is not None

    @staticmethod
    def _bot_name_aliases(bot_user: Any) -> tuple[str, ...]:
        aliases = {
            str(getattr(bot_user, field, "")).strip()
            for field in ("name", "display_name", "global_name")
        }
        aliases.discard("")
        return tuple(sorted(aliases, key=len, reverse=True))

    @staticmethod
    def _content_mentions_bot_name_prefix(
        content: str, aliases: tuple[str, ...]
    ) -> bool:
        if not content:
            return False
        for alias in aliases:
            if re.match(
                rf"^\s*@{re.escape(alias)}(?=$|[\s,:-])",
                content,
                flags=re.IGNORECASE,
            ):
                return True
        return False

    @staticmethod
    def _strip_plain_name_prefix(content: str, aliases: tuple[str, ...]) -> str:
        if not content:
            return content
        for alias in aliases:
            stripped = re.sub(
                rf"^\s*@{re.escape(alias)}(?=$|[\s,:-])[\s,:-]*",
                "",
                content,
                count=1,
                flags=re.IGNORECASE,
            )
            if stripped != content:
                return stripped.strip()
        return content.strip()

    @staticmethod
    def _content_fingerprint(content: str) -> str:
        if not content:
            return ""
        return hashlib.blake2s(content.encode("utf-8"), digest_size=8).hexdigest()

    def is_user_verified(self, user_id: str) -> bool:
        trusted = self._config.trusted_users or set()
        return user_id in trusted

    def health_status(self) -> dict[str, Any]:
        status = super().health_status()
        status.update({"available": self.available, "client_active": self._client is not None})
        return status
