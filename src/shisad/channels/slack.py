"""Slack Socket Mode integration with optional runtime dependency."""

from __future__ import annotations

import asyncio
import contextlib
import importlib
import logging
from dataclasses import dataclass
from typing import Any

from shisad.channels.base import ChannelMessage, DeliveryTarget, InMemoryChannel

_slack_app_module: Any | None
_slack_handler_module: Any | None
try:  # pragma: no cover - optional dependency.
    _slack_app_module = importlib.import_module("slack_bolt.async_app")
    _slack_handler_module = importlib.import_module("slack_bolt.adapter.socket_mode.aiohttp")
except ImportError:  # pragma: no cover - optional dependency.
    _slack_app_module = None
    _slack_handler_module = None

AsyncApp = getattr(_slack_app_module, "AsyncApp", None)
AsyncSocketModeHandler = getattr(_slack_handler_module, "AsyncSocketModeHandler", None)

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class SlackConfig:
    bot_token: str
    app_token: str
    default_channel_id: str = ""
    team_workspace_map: dict[str, str] | None = None
    trusted_users: set[str] | None = None


class SlackChannel(InMemoryChannel):
    """Slack wrapper with in-memory fallback when slack_bolt is unavailable."""

    def __init__(self, config: SlackConfig) -> None:
        super().__init__(name="slack")
        self._config = config
        self._app: Any | None = None
        self._handler: Any | None = None
        self._handler_task: asyncio.Task[None] | None = None

    @property
    def available(self) -> bool:
        return bool(AsyncApp is not None and AsyncSocketModeHandler is not None)

    async def connect(self) -> None:
        await super().connect()
        if not self.available or not self._config.bot_token or not self._config.app_token:
            return
        if self._app is not None:
            return

        app_class = AsyncApp
        socket_handler_class = AsyncSocketModeHandler
        if app_class is None or socket_handler_class is None:
            return
        self._app = app_class(token=self._config.bot_token)

        async def _on_message(
            event: dict[str, Any],
            body: dict[str, Any],
            say: Any | None = None,
        ) -> None:
            _ = say
            if event.get("bot_id") or event.get("subtype") == "bot_message":
                return
            user_id = str(event.get("user", "")).strip()
            text = str(event.get("text", "")).strip()
            channel_id = str(event.get("channel", "")).strip()
            team_id = str((body.get("team_id") if isinstance(body, dict) else "") or "").strip()
            if not user_id or not text:
                return
            await self._incoming.put(
                ChannelMessage(
                    channel="slack",
                    external_user_id=user_id,
                    workspace_hint=self.workspace_for_team(team_id),
                    content=text,
                    message_id=str(event.get("client_msg_id") or event.get("ts") or ""),
                    reply_target=channel_id,
                    thread_id=str(event.get("thread_ts", "")),
                )
            )

        event_decorator_factory = getattr(self._app, "event", None)
        if callable(event_decorator_factory):
            event_decorator = event_decorator_factory("message")
            if callable(event_decorator):
                event_decorator(_on_message)

        self._handler = socket_handler_class(self._app, self._config.app_token)
        start = getattr(self._handler, "start_async", None)
        if callable(start):
            self._handler_task = asyncio.create_task(start())

    async def disconnect(self) -> None:
        if self._handler_task is not None:
            self._handler_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._handler_task
            self._handler_task = None
        if self._handler is not None:
            close = getattr(self._handler, "close_async", None)
            if callable(close):
                with contextlib.suppress(OSError, RuntimeError, ValueError):
                    await close()
            self._handler = None
        self._app = None
        await super().disconnect()

    async def send(self, message: str, *, target: DeliveryTarget | None = None) -> None:
        if self._app is not None:
            client = getattr(self._app, "client", None)
            chat_post = getattr(client, "chat_postMessage", None) if client is not None else None
            if callable(chat_post):
                recipient = (target.recipient if target is not None else "").strip()
                if not recipient:
                    recipient = self._config.default_channel_id
                if recipient:
                    kwargs: dict[str, Any] = {"channel": recipient, "text": message}
                    if target is not None and target.thread_id.strip():
                        kwargs["thread_ts"] = target.thread_id.strip()
                    await chat_post(**kwargs)
                    return
        await super().send(message, target=target)

    def workspace_for_team(self, team_id: str) -> str:
        mapping = self._config.team_workspace_map or {}
        if team_id:
            return mapping.get(team_id, team_id)
        return "slack"

    def is_user_verified(self, user_id: str) -> bool:
        trusted = self._config.trusted_users or set()
        return user_id in trusted

    def health_status(self) -> dict[str, Any]:
        status = super().health_status()
        status.update(
            {
                "available": self.available,
                "socket_mode": self._handler is not None,
                "socket_task_running": (
                    self._handler_task is not None and not self._handler_task.done()
                ),
            }
        )
        return status
