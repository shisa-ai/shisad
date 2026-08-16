"""Discord channel integration with optional runtime dependency."""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import importlib
import logging
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from shisad.channels.base import ChannelMessage, DeliveryTarget, InMemoryChannel
from shisad.channels.discord_components import (
    DiscordApprovalInteraction,
    discord_approval_custom_id,
    parse_discord_approval_custom_id,
)
from shisad.channels.discord_policy import (
    DiscordChannelPolicy,
    DiscordChannelPolicyDecision,
    DiscordChannelRule,
)
from shisad.channels.state import (
    ChannelStateStore,
    ReplayIdentity,
    replay_identity_metadata,
    structural_replay_id,
)

# Resolve optional runtime dependency dynamically so type-checking does not
# require the external discord package to be installed.
try:  # pragma: no cover - optional dependency.
    _discord: Any | None = importlib.import_module("discord")
except ImportError:  # pragma: no cover - optional dependency.
    _discord = None

discord: Any | None = _discord

logger = logging.getLogger(__name__)

_DISCORD_TOTP_CODE_FIELD_ID = "totp_code"
_DISCORD_RESPONSE_FALLBACK_EXCEPTIONS: tuple[type[BaseException], ...] = (
    TypeError,
    RuntimeError,
    OSError,
)
_DISCORD_DEFAULT_APPROVAL_ACK = "Approval response received."
_DISCORD_MESSAGE_CONTENT_LIMIT = 2000
_DISCORD_ACTION_COMPONENT_LIMIT = 5
_DISCORD_THREAD_PERMISSION_GUIDANCE = (
    "I couldn't create a Discord thread. Grant Create Public Threads and "
    "Send Messages in Threads permissions, then try again."
)


def _chunk_discord_message(
    message: str,
    *,
    max_length: int = _DISCORD_MESSAGE_CONTENT_LIMIT,
) -> tuple[str, ...]:
    """Split Discord content at stable boundaries without changing its bytes."""

    if max_length <= 0:
        raise ValueError("Discord message limit must be positive")
    remaining = str(message)
    if not remaining.strip():
        raise ValueError("Discord message content must not be empty")
    chunks: list[str] = []
    while remaining:
        if len(remaining) <= max_length:
            chunks.append(remaining)
            break
        window = remaining[:max_length]
        paragraph_start = window.rfind("\n\n")
        line_start = window.rfind("\n")
        whitespace_start = next(
            (index for index in range(len(window) - 1, -1, -1) if window[index].isspace()),
            -1,
        )
        split_at = max_length
        for candidate in (
            paragraph_start + 2 if paragraph_start >= 0 else 0,
            line_start + 1 if line_start >= 0 else 0,
            whitespace_start + 1 if whitespace_start >= 0 else 0,
        ):
            if candidate and remaining[:candidate].strip():
                split_at = candidate
                break
        chunks.append(remaining[:split_at])
        remaining = remaining[split_at:]
    return tuple(chunks)


@dataclass(slots=True)
class DiscordConfig:
    bot_token: str
    default_channel_id: str = ""
    use_threads: bool = False
    guild_workspace_map: dict[str, str] | None = None
    trusted_users: set[str] | None = None
    channel_rules: list[DiscordChannelRule] | None = None


def _discord_response_exceptions() -> tuple[type[BaseException], ...]:
    discord_exception = getattr(discord, "DiscordException", None)
    if isinstance(discord_exception, type) and issubclass(
        discord_exception,
        BaseException,
    ):
        return (*_DISCORD_RESPONSE_FALLBACK_EXCEPTIONS, discord_exception)
    return _DISCORD_RESPONSE_FALLBACK_EXCEPTIONS


async def _call_discord_response(
    callback: Any,
    *args: Any,
    **kwargs: Any,
) -> bool:
    if not callable(callback):
        return False
    with contextlib.suppress(*_discord_response_exceptions()):
        result = callback(*args, **kwargs)
        if asyncio.iscoroutine(result):
            await result
        return True
    return False


class DiscordChannel(InMemoryChannel):
    """Discord wrapper with in-memory fallback when discord.py is unavailable."""

    def __init__(
        self,
        config: DiscordConfig,
        *,
        replay_state_store: ChannelStateStore | None = None,
    ) -> None:
        super().__init__(name="discord")
        self._config = config
        self._channel_policy = DiscordChannelPolicy(tuple(config.channel_rules or ()))
        self._replay_state_store = replay_state_store
        self._client: Any | None = None
        self._client_task: asyncio.Task[None] | None = None
        self._pending_interactions: dict[tuple[str, str, str, str, str], Any] = {}

    @property
    def available(self) -> bool:
        return discord is not None

    @property
    def supports_components(self) -> bool:
        if discord is None:
            return False
        ui = getattr(discord, "ui", None)
        view_ctor = getattr(ui, "View", None) if ui is not None else None
        button_ctor = getattr(ui, "Button", None) if ui is not None else None
        return callable(view_ctor) and callable(button_ctor)

    @property
    def supports_totp_modal(self) -> bool:
        return (
            self._totp_modal(
                DiscordApprovalInteraction(
                    action="totp",
                    confirmation_id="probe",
                    decision_nonce="probe",
                )
            )
            is not None
        )

    @staticmethod
    def _delivery_coordinates(channel_obj: Any) -> tuple[str, str]:
        """Return the parent recipient and optional concrete thread identity."""
        channel_id = str(getattr(channel_obj, "id", "") or "").strip()
        parent_id = str(getattr(channel_obj, "parent_id", "") or "").strip()
        if not parent_id:
            parent = getattr(channel_obj, "parent", None)
            parent_id = str(getattr(parent, "id", "") or "").strip()
        if parent_id:
            return parent_id, channel_id
        return channel_id, ""

    def _existing_message_thread(self, message: Any, guild: Any) -> Any | None:
        thread = getattr(message, "thread", None)
        if thread is not None and str(getattr(thread, "id", "") or "").strip():
            return thread
        message_id = str(getattr(message, "id", "") or "").strip()
        try:
            numeric_message_id = int(message_id)
        except ValueError:
            return None
        get_thread = getattr(guild, "get_thread", None)
        if callable(get_thread):
            thread = get_thread(numeric_message_id)
            if thread is not None:
                return thread
        return None

    async def _create_message_thread(self, message: Any, guild: Any) -> Any | None:
        existing = self._existing_message_thread(message, guild)
        if existing is not None:
            return existing
        message_id = str(getattr(message, "id", "") or "").strip()
        create_thread = getattr(message, "create_thread", None)
        if not message_id or not callable(create_thread):
            await _call_discord_response(
                getattr(message, "reply", None),
                _DISCORD_THREAD_PERMISSION_GUIDANCE,
            )
            logger.warning("Discord thread creation unavailable for addressed message")
            return None
        try:
            thread = create_thread(name=f"shisad-{message_id}"[:100])
            if asyncio.iscoroutine(thread):
                thread = await thread
        except _discord_response_exceptions() as exc:
            thread = self._existing_message_thread(message, guild)
            if thread is None and self._client is not None:
                try:
                    numeric_message_id = int(message_id)
                except ValueError:
                    numeric_message_id = 0
                get_channel = getattr(self._client, "get_channel", None)
                if numeric_message_id and callable(get_channel):
                    thread = get_channel(numeric_message_id)
            if thread is not None:
                return thread
            await _call_discord_response(
                getattr(message, "reply", None),
                _DISCORD_THREAD_PERMISSION_GUIDANCE,
            )
            logger.warning(
                "Discord thread creation failed (error=%s)",
                exc.__class__.__name__,
            )
            return None
        if not str(getattr(thread, "id", "") or "").strip():
            await _call_discord_response(
                getattr(message, "reply", None),
                _DISCORD_THREAD_PERMISSION_GUIDANCE,
            )
            logger.warning("Discord thread creation returned no structural thread identity")
            return None
        return thread

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
                event_channel_id = (
                    str(getattr(channel_obj, "id", "")) if channel_obj is not None else ""
                )
                channel_id, thread_id = (
                    self._delivery_coordinates(channel_obj)
                    if self._config.use_threads
                    else (event_channel_id, "")
                )
                replay_metadata = self._replay_metadata(
                    guild_id=guild_id,
                    channel_id=event_channel_id,
                    event_kind="message",
                    event_id=message_id,
                )
                if replay_metadata is None:
                    logger.warning(
                        "Discord ingress dropped because structural replay identity is missing"
                    )
                    return
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
                addressed_by_role_mention = False
                if guild is not None and self._client is not None:
                    bot_user = getattr(self._client, "user", None)
                    if bot_user is not None:
                        bot_id = str(getattr(bot_user, "id", "")).strip()
                        mention_ids = self._message_mention_ids(message)
                        addressed_by_resolved = bot_id in mention_ids
                        addressed_by_content_tag = self._content_mentions_bot(content, bot_id)
                        name_aliases = self._bot_name_aliases(bot_user)
                        addressed_by_name_prefix = self._content_mentions_bot_name_prefix(
                            content, name_aliases
                        )
                        role_mention_ids = self._message_role_mention_ids(message)
                        bot_role_ids = self._bot_role_ids(guild, bot_id)
                        addressed_by_role_mention = bool(
                            role_mention_ids.intersection(bot_role_ids)
                        )
                        addressed = (
                            addressed_by_resolved
                            or addressed_by_content_tag
                            or addressed_by_name_prefix
                            or addressed_by_role_mention
                        )
                        policy_decision = self.policy_decision_for(
                            guild_id=guild_id,
                            channel_id=channel_id,
                            external_user_id=author_id,
                        )
                        if (
                            not addressed_by_resolved
                            and not addressed_by_content_tag
                            and not addressed_by_name_prefix
                            and not addressed_by_role_mention
                        ):
                            if policy_decision.engagement_mode in {
                                "read-along",
                                "passive-observe",
                            }:
                                relevance = policy_decision.relevance_for(content)
                                proactive_eligible = (
                                    policy_decision.engagement_mode == "read-along"
                                    and relevance.relevant
                                )
                                passive_reason = (
                                    ""
                                    if proactive_eligible
                                    else (
                                        relevance.reason
                                        if policy_decision.engagement_mode == "read-along"
                                        else "passive_observe"
                                    )
                                )
                                workspace_hint = self.workspace_for_guild(guild_id)
                                await self._incoming.put(
                                    ChannelMessage(
                                        channel="discord",
                                        external_user_id=author_id,
                                        workspace_hint=workspace_hint,
                                        content=content,
                                        message_id=message_id,
                                        reply_target=channel_id,
                                        thread_id=thread_id,
                                        metadata={
                                            **replay_metadata,
                                            "discord_guild_id": guild_id,
                                            "discord_channel_id": channel_id,
                                            "discord_thread_id": thread_id,
                                            "addressed": addressed,
                                            "interaction_type": "observed",
                                            "engagement_mode": policy_decision.engagement_mode,
                                            "proactive_eligible": proactive_eligible,
                                            "matched_relevance_keywords": list(
                                                relevance.matched_keywords
                                            ),
                                            "passive_reason": passive_reason,
                                        },
                                    )
                                )
                                logger.debug(
                                    "Discord ingress accepted observed message "
                                    "(message_id=%s guild_id=%s channel_id=%s author_id=%s "
                                    "mode=%s proactive_eligible=%s relevance_reason=%s)",
                                    message_id,
                                    guild_id,
                                    channel_id,
                                    author_id,
                                    policy_decision.engagement_mode,
                                    proactive_eligible,
                                    relevance.reason,
                                )
                                return
                            raw_mentions = tuple(
                                mention_id
                                for mention_id in (
                                    str(raw_mention).strip()
                                    for raw_mention in (getattr(message, "raw_mentions", []) or [])
                                )
                                if mention_id
                            )
                            logger.debug(
                                "Discord ingress dropped "
                                "(reason=not_addressed message_id=%s guild_id=%s channel_id=%s "
                                "author_id=%s bot_id=%s mention_ids=%s raw_mentions=%s "
                                "role_mentions=%s bot_role_ids=%s aliases=%s)",
                                message_id,
                                guild_id,
                                channel_id,
                                author_id,
                                bot_id,
                                sorted(mention_ids),
                                list(raw_mentions),
                                sorted(role_mention_ids),
                                sorted(bot_role_ids),
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
                            content = re.sub(rf"<@!?{re.escape(bot_id)}>\s*", "", content).strip()
                        content = self._strip_plain_name_prefix(
                            content, self._bot_name_aliases(bot_user)
                        )
                        content = self._strip_role_mention_tags(
                            content,
                            self._bot_role_ids(guild, bot_id),
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
                if self._config.use_threads and guild is not None and not thread_id:
                    thread = await self._create_message_thread(message, guild)
                    if thread is None:
                        return
                    thread_id = str(getattr(thread, "id", "") or "").strip()
                workspace_hint = self.workspace_for_guild(guild_id)
                logger.debug(
                    "Discord ingress accepted "
                    "(message_id=%s guild_id=%s channel_id=%s author_id=%s workspace_hint=%s "
                    "addressed_by_resolved=%s addressed_by_content_tag=%s "
                    "addressed_by_name_prefix=%s addressed_by_role_mention=%s "
                    "content_len=%d content_hash=%s)",
                    message_id,
                    guild_id,
                    channel_id,
                    author_id,
                    workspace_hint,
                    addressed_by_resolved,
                    addressed_by_content_tag,
                    addressed_by_name_prefix,
                    addressed_by_role_mention,
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
                        thread_id=thread_id,
                        metadata={
                            **replay_metadata,
                            "discord_guild_id": guild_id,
                            "discord_channel_id": channel_id,
                            "discord_thread_id": thread_id,
                            "addressed": True,
                            "interaction_type": "direct",
                            "engagement_mode": "mention-only",
                            "proactive_eligible": False,
                        },
                    )
                )

            async def on_interaction(interaction: Any) -> None:
                if not str(getattr(interaction, "id", "") or "").strip():
                    logger.warning(
                        "Discord interaction dropped because its raw interaction ID is missing"
                    )
                    return
                data = getattr(interaction, "data", None)
                if not isinstance(data, Mapping):
                    return
                parsed = parse_discord_approval_custom_id(str(data.get("custom_id") or ""))
                if parsed is None:
                    return
                if parsed.action == "totp":
                    await self._open_totp_modal_reserved(interaction, parsed)
                    return
                if parsed.action == "totp_submit":
                    code = self._interaction_totp_code(data)
                    if not code:
                        await self._enqueue_approval_interaction(
                            interaction=interaction,
                            parsed=parsed,
                            content="",
                            interaction_type="approval_invalid",
                            ack_only_message="TOTP code is required.",
                        )
                        return
                    await self._enqueue_approval_interaction(
                        interaction=interaction,
                        parsed=parsed,
                        content=f"confirm {parsed.confirmation_id} {code}",
                        interaction_type="approval_modal",
                    )
                elif parsed.action in {"confirm", "reject"}:
                    await self._enqueue_approval_interaction(
                        interaction=interaction,
                        parsed=parsed,
                        content=f"{parsed.action} {parsed.confirmation_id}",
                        interaction_type="approval_component",
                    )
                else:
                    return

            event_decorator(on_message)
            event_decorator(on_interaction)

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
        self._pending_interactions.clear()
        await super().disconnect()

    async def disconnect_strict(self) -> None:
        """Disconnect a failed startup while surfacing incomplete cleanup."""
        client = self._client
        if client is not None:
            close = getattr(client, "close", None)
            if callable(close):
                result = close()
                if asyncio.iscoroutine(result):
                    await result

        client_task = self._client_task
        if client_task is not None:
            client_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await client_task

        self._client_task = None
        self._client = None
        self._pending_interactions.clear()
        await super().disconnect()

    async def send(
        self,
        message: str,
        *,
        target: DeliveryTarget | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        if self._client is not None:
            thread_recipient = (target.thread_id if target is not None else "").strip()
            recipient = thread_recipient or (target.recipient if target is not None else "").strip()
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
                            message_parts = self._delivery_message_parts(
                                message,
                                metadata or {},
                            )
                            for native_content, fallback_content, part_metadata in message_parts:
                                components = part_metadata.get("discord_components")
                                has_components = isinstance(components, list) and bool(components)
                                view = self._view_from_delivery_metadata(part_metadata)
                                content = (
                                    native_content
                                    if view is not None or not has_components
                                    else fallback_content
                                )
                                chunks = _chunk_discord_message(content)
                                for index, chunk in enumerate(chunks):
                                    kwargs: dict[str, Any] = {}
                                    if view is not None and index == len(chunks) - 1:
                                        kwargs["view"] = view
                                    await send(chunk, **kwargs)
                            return
            raise RuntimeError("Discord could not resolve the delivery target")
        await super().send(message, target=target, metadata=metadata)

    async def _enqueue_approval_interaction(
        self,
        *,
        interaction: Any,
        parsed: DiscordApprovalInteraction,
        content: str,
        interaction_type: str,
        ack_only_message: str = "",
    ) -> bool:
        user = getattr(interaction, "user", None)
        if user is None or bool(getattr(user, "bot", False)):
            return False
        user_id = str(getattr(user, "id", "")).strip()
        if not user_id:
            return False
        guild = getattr(interaction, "guild", None)
        guild_id = str(getattr(guild, "id", "")).strip() if guild is not None else ""
        channel_obj = getattr(interaction, "channel", None)
        event_channel_id = (
            str(getattr(channel_obj, "id", "")).strip() if channel_obj is not None else ""
        )
        channel_id, thread_id = (
            self._delivery_coordinates(channel_obj)
            if self._config.use_threads
            else (event_channel_id, "")
        )
        interaction_id = str(getattr(interaction, "id", "")).strip()
        replay_metadata = self._replay_metadata(
            guild_id=guild_id,
            channel_id=event_channel_id,
            event_kind="interaction",
            event_id=interaction_id,
        )
        if replay_metadata is None:
            return False
        identity = ReplayIdentity.from_mapping(replay_metadata["replay_identity"])
        self._pending_interactions.setdefault(identity.key, interaction)
        try:
            await self._incoming.put(
                ChannelMessage(
                    channel="discord",
                    external_user_id=user_id,
                    workspace_hint=self.workspace_for_guild(guild_id),
                    content=content.strip(),
                    message_id=interaction_id,
                    reply_target=channel_id,
                    thread_id=thread_id,
                    metadata={
                        **replay_metadata,
                        "discord_guild_id": guild_id,
                        "discord_channel_id": channel_id,
                        "discord_thread_id": thread_id,
                        "addressed": True,
                        "interaction_type": interaction_type,
                        "approval_interaction_type": interaction_type,
                        "approval_component_action": parsed.action,
                        "approval_confirmation_id": parsed.confirmation_id,
                        "approval_decision_nonce": parsed.decision_nonce,
                        "approval_ack_only": bool(ack_only_message),
                        "approval_ack_message": ack_only_message,
                        "engagement_mode": "approval-interaction",
                        "proactive_eligible": False,
                    },
                )
            )
        except BaseException:
            if self._pending_interactions.get(identity.key) is interaction:
                self._pending_interactions.pop(identity.key, None)
            raise
        return True

    async def acknowledge_reserved_interaction(
        self,
        identity: ReplayIdentity,
        *,
        message: str = "",
    ) -> bool:
        """Acknowledge one transient Discord interaction after durable reservation."""

        interaction = self._pending_interactions.get(identity.key)
        if interaction is None:
            return False
        return await self._acknowledge_approval_interaction(
            interaction,
            message=message or _DISCORD_DEFAULT_APPROVAL_ACK,
        )

    async def finalize_reserved_interaction(
        self,
        identity: ReplayIdentity,
        *,
        remove_controls: bool,
    ) -> bool:
        """Release one transient interaction and remove only terminal controls."""

        interaction = self._pending_interactions.pop(identity.key, None)
        if interaction is None or not remove_controls:
            return False
        if self._interaction_message_has_sibling_confirmations(interaction):
            return False
        message = getattr(interaction, "message", None)
        edit = getattr(message, "edit", None) if message is not None else None
        return await _call_discord_response(edit, view=None)

    @staticmethod
    def _interaction_message_has_sibling_confirmations(interaction: Any) -> bool:
        data = getattr(interaction, "data", None)
        clicked = (
            parse_discord_approval_custom_id(str(data.get("custom_id") or ""))
            if isinstance(data, Mapping)
            else None
        )
        message = getattr(interaction, "message", None)
        rows = getattr(message, "components", ()) if message is not None else ()
        if clicked is None or not isinstance(rows, (list, tuple)):
            return False
        confirmation_ids: set[str] = set()
        for row in rows:
            children = getattr(row, "children", ())
            items = children if isinstance(children, (list, tuple)) else (row,)
            for item in items:
                custom_id = str(getattr(item, "custom_id", "") or "").strip()
                if not custom_id:
                    continue
                parsed = parse_discord_approval_custom_id(custom_id)
                if parsed is None:
                    return True
                confirmation_ids.add(parsed.confirmation_id)
        return bool(confirmation_ids - {clicked.confirmation_id})

    def discard_pending_interaction(self, identity: ReplayIdentity) -> None:
        """Discard a transient provider handle for an already-blocked replay."""

        self._pending_interactions.pop(identity.key, None)

    async def _open_totp_modal_reserved(
        self,
        interaction: Any,
        parsed: DiscordApprovalInteraction,
    ) -> None:
        guild = getattr(interaction, "guild", None)
        guild_id = str(getattr(guild, "id", "") or "").strip() if guild is not None else ""
        channel = getattr(interaction, "channel", None)
        channel_id = str(getattr(channel, "id", "") or "").strip() if channel is not None else ""
        event_id = str(getattr(interaction, "id", "") or "").strip()
        metadata = self._replay_metadata(
            guild_id=guild_id,
            channel_id=channel_id,
            event_kind="interaction",
            event_id=event_id,
        )
        state_store = self._replay_state_store
        if metadata is None or state_store is None:
            logger.warning(
                "Discord TOTP modal interaction dropped because replay state is unavailable"
            )
            return
        identity = ReplayIdentity.from_mapping(metadata["replay_identity"])
        if not state_store.reserve(identity):
            return
        try:
            await self._open_totp_modal(interaction, parsed)
        except asyncio.CancelledError:
            self._mark_replay_uncertain(identity)
            raise
        except Exception:
            self._mark_replay_uncertain(identity)
            raise
        state_store.mark_terminal(identity)

    def _mark_replay_uncertain(self, identity: ReplayIdentity) -> None:
        state_store = self._replay_state_store
        if state_store is None:
            return
        try:
            state_store.mark_uncertain(identity)
        except Exception as exc:
            logger.error(
                "Discord TOTP replay uncertainty update failed; reservation remains blocking "
                "(error=%s)",
                exc.__class__.__name__,
            )

    async def _open_totp_modal(
        self,
        interaction: Any,
        parsed: DiscordApprovalInteraction,
    ) -> None:
        response = getattr(interaction, "response", None)
        send_modal = getattr(response, "send_modal", None) if response is not None else None
        modal = self._totp_modal(parsed)
        if modal is not None and callable(send_modal):
            with contextlib.suppress(*_discord_response_exceptions()):
                result = send_modal(modal)
                if asyncio.iscoroutine(result):
                    await result
                return
        await self._acknowledge_approval_interaction(
            interaction,
            message=(
                "TOTP approval requires a code. "
                f"Reply with `confirm {parsed.confirmation_id} 123456`."
            ),
        )

    async def _acknowledge_approval_interaction(
        self,
        interaction: Any,
        *,
        message: str = _DISCORD_DEFAULT_APPROVAL_ACK,
    ) -> bool:
        must_deliver_message = message != _DISCORD_DEFAULT_APPROVAL_ACK
        response = getattr(interaction, "response", None)
        if response is not None:
            send_message = getattr(response, "send_message", None)
            if await _call_discord_response(send_message, message, ephemeral=True):
                return True
            defer = getattr(response, "defer", None)
            if await _call_discord_response(defer, ephemeral=True) and not must_deliver_message:
                return True
        followup = getattr(interaction, "followup", None)
        followup_send = getattr(followup, "send", None) if followup is not None else None
        return await _call_discord_response(followup_send, message, ephemeral=True)

    def _totp_modal(self, parsed: DiscordApprovalInteraction) -> Any | None:
        if discord is None:
            return None
        ui = getattr(discord, "ui", None)
        modal_ctor = getattr(ui, "Modal", None) if ui is not None else None
        text_input_ctor = getattr(ui, "TextInput", None) if ui is not None else None
        if not callable(modal_ctor) or not callable(text_input_ctor):
            return None
        try:
            modal = modal_ctor(
                title="TOTP approval",
                custom_id=discord_approval_custom_id(
                    action="totp_submit",
                    confirmation_id=parsed.confirmation_id,
                    decision_nonce=parsed.decision_nonce,
                ),
            )
            text_input = text_input_ctor(
                label="TOTP code",
                custom_id=_DISCORD_TOTP_CODE_FIELD_ID,
                min_length=6,
                max_length=6,
                required=True,
            )
            add_item = getattr(modal, "add_item", None)
            if not callable(add_item):
                return None
            add_item(text_input)
            return modal
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _interaction_totp_code(data: Mapping[str, Any]) -> str:
        def _walk(value: Any) -> str:
            if isinstance(value, Mapping):
                custom_id = str(value.get("custom_id") or "").strip()
                if custom_id == _DISCORD_TOTP_CODE_FIELD_ID:
                    return str(value.get("value") or "").strip()
                for nested in value.values():
                    found = _walk(nested)
                    if found:
                        return found
            elif isinstance(value, list):
                for item in value:
                    found = _walk(item)
                    if found:
                        return found
            return ""

        code = _walk(data)
        return code if re.fullmatch(r"\d{6}", code) else ""

    def _view_from_delivery_metadata(self, metadata: Mapping[str, Any]) -> Any | None:
        if discord is None:
            return None
        components = metadata.get("discord_components")
        if (
            not isinstance(components, list)
            or not components
            or len(components) > _DISCORD_ACTION_COMPONENT_LIMIT
        ):
            return None
        ui = getattr(discord, "ui", None)
        view_ctor = getattr(ui, "View", None) if ui is not None else None
        button_ctor = getattr(ui, "Button", None) if ui is not None else None
        if not callable(view_ctor) or not callable(button_ctor):
            return None
        try:
            view = view_ctor()
        except TypeError:
            return None
        add_item = getattr(view, "add_item", None)
        if not callable(add_item):
            return None
        for component in components:
            if not isinstance(component, Mapping):
                return None
            if str(component.get("type") or "button").strip().lower() != "button":
                return None
            custom_id = str(component.get("custom_id") or "").strip()
            label = str(component.get("label") or "").strip()
            if not custom_id or not label:
                return None
            kwargs: dict[str, Any] = {"label": label, "custom_id": custom_id}
            style = self._button_style(str(component.get("style") or "").strip())
            if style is not None:
                kwargs["style"] = style
            button: Any | None = None
            try:
                button = button_ctor(**kwargs)
            except TypeError:
                kwargs.pop("style", None)
                with contextlib.suppress(TypeError, ValueError):
                    button = button_ctor(**kwargs)
            except ValueError:
                return None
            if button is None:
                return None
            try:
                add_item(button)
            except (TypeError, ValueError):
                return None
        return view

    @staticmethod
    def _delivery_message_parts(
        message: str,
        metadata: Mapping[str, Any],
    ) -> list[tuple[str, str, dict[str, Any]]]:
        raw_parts = metadata.get("discord_message_parts")
        if not isinstance(raw_parts, list) or not raw_parts:
            return [(message, message, dict(metadata))]
        parts: list[tuple[str, str, dict[str, Any]]] = []
        for raw_part in raw_parts:
            if not isinstance(raw_part, Mapping):
                return [(message, message, {})]
            content = str(raw_part.get("content") or "")
            fallback_content = str(raw_part.get("fallback_content") or content)
            components = raw_part.get("discord_components", [])
            if not content or not fallback_content or not isinstance(components, list):
                return [(message, message, {})]
            parts.append(
                (
                    content,
                    fallback_content,
                    {"discord_components": list(components)},
                )
            )
        source_content = str(metadata.get("discord_source_content") or "")
        if source_content and message.endswith(source_content):
            prepared_prefix = message[: -len(source_content)]
            if prepared_prefix:
                content, fallback_content, part_metadata = parts[0]
                parts[0] = (
                    f"{prepared_prefix}{content}",
                    f"{prepared_prefix}{fallback_content}",
                    part_metadata,
                )
        return parts

    def can_build_view_from_metadata(self, metadata: Mapping[str, Any]) -> bool:
        raw_parts = metadata.get("discord_message_parts")
        if isinstance(raw_parts, list) and raw_parts:
            component_parts = [
                part
                for part in raw_parts
                if isinstance(part, Mapping) and bool(part.get("discord_components"))
            ]
            return bool(component_parts) and all(
                self._view_from_delivery_metadata(part) is not None for part in component_parts
            )
        return self._view_from_delivery_metadata(metadata) is not None

    @staticmethod
    def _button_style(style_name: str) -> Any | None:
        if discord is None:
            return None
        style_container = getattr(discord, "ButtonStyle", None)
        if style_container is None:
            return None
        normalized = style_name.strip().lower()
        for candidate in (normalized, {"success": "green", "danger": "red"}.get(normalized, "")):
            if candidate and hasattr(style_container, candidate):
                return getattr(style_container, candidate)
        return None

    def workspace_for_guild(self, guild_id: str) -> str:
        mapping = self._config.guild_workspace_map or {}
        if guild_id:
            return mapping.get(guild_id, guild_id)
        return "discord"

    def _replay_metadata(
        self,
        *,
        guild_id: str,
        channel_id: str,
        event_kind: str,
        event_id: str,
    ) -> dict[str, dict[str, str]] | None:
        bot_user = getattr(self._client, "user", None) if self._client is not None else None
        bot_id = str(getattr(bot_user, "id", "") or "").strip()
        if not bot_id or not channel_id.strip() or not event_id.strip():
            return None
        return replay_identity_metadata(
            ReplayIdentity(
                provider="discord",
                account_id=bot_id,
                scope_id=structural_replay_id(guild_id, channel_id),
                event_kind=event_kind,
                event_id=event_id,
            )
        )

    def policy_decision_for(
        self,
        *,
        guild_id: str,
        channel_id: str,
        external_user_id: str,
    ) -> DiscordChannelPolicyDecision:
        return self._channel_policy.resolve(
            guild_id=guild_id,
            channel_id=channel_id,
            external_user_id=external_user_id,
        )

    @staticmethod
    def _message_mention_ids(message: Any) -> set[str]:
        mention_ids = {
            str(getattr(member, "id", "")).strip()
            for member in (getattr(message, "mentions", []) or [])
        }
        mention_ids.discard("")
        for raw_mention in getattr(message, "raw_mentions", []) or []:
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
    def _message_role_mention_ids(message: Any) -> set[str]:
        role_ids = {
            str(getattr(role, "id", "")).strip()
            for role in (getattr(message, "role_mentions", []) or [])
        }
        role_ids.discard("")
        for raw_role in getattr(message, "raw_role_mentions", []) or []:
            role_id = str(raw_role).strip()
            if role_id:
                role_ids.add(role_id)
        return role_ids

    @staticmethod
    def _bot_role_ids(guild: Any, bot_id: str) -> set[str]:
        if guild is None or not bot_id:
            return set()
        bot_member = None
        get_member = getattr(guild, "get_member", None)
        if callable(get_member):
            with contextlib.suppress(TypeError, ValueError):
                bot_member = get_member(int(bot_id))
        if bot_member is None:
            return set()
        role_ids = {
            str(getattr(role, "id", "")).strip()
            for role in (getattr(bot_member, "roles", []) or [])
        }
        role_ids.discard("")
        return role_ids

    @staticmethod
    def _bot_name_aliases(bot_user: Any) -> tuple[str, ...]:
        aliases = {
            str(getattr(bot_user, field, "")).strip()
            for field in ("name", "display_name", "global_name")
        }
        aliases.discard("")
        return tuple(sorted(aliases, key=len, reverse=True))

    @staticmethod
    def _content_mentions_bot_name_prefix(content: str, aliases: tuple[str, ...]) -> bool:
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
    def _strip_role_mention_tags(content: str, role_ids: set[str]) -> str:
        if not content or not role_ids:
            return content.strip()
        for role_id in role_ids:
            content = re.sub(
                rf"<@&{re.escape(role_id)}>\s*",
                "",
                content,
                count=1,
            )
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
