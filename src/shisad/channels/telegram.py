"""Telegram channel integration with optional runtime dependency."""

from __future__ import annotations

import asyncio
import contextlib
import importlib
import logging
from dataclasses import dataclass
from typing import Any

from shisad.channels.base import ChannelMessage, DeliveryTarget, InMemoryChannel

_telegram_ext: Any | None
try:  # pragma: no cover - optional dependency.
    _telegram_ext = importlib.import_module("telegram.ext")
except ImportError:  # pragma: no cover - optional dependency.
    _telegram_ext = None

Application = getattr(_telegram_ext, "Application", None)
MessageHandler = getattr(_telegram_ext, "MessageHandler", None)
filters = getattr(_telegram_ext, "filters", None)

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class TelegramConfig:
    bot_token: str
    default_chat_id: str = ""
    chat_workspace_map: dict[str, str] | None = None
    trusted_users: set[str] | None = None


class TelegramChannel(InMemoryChannel):
    """Telegram wrapper with in-memory fallback when dependency is unavailable."""

    def __init__(self, config: TelegramConfig) -> None:
        super().__init__(name="telegram")
        self._config = config
        self._application: Any | None = None

    @property
    def available(self) -> bool:
        return bool(Application is not None and MessageHandler is not None and filters is not None)

    async def connect(self) -> None:
        await super().connect()
        if not self.available or not self._config.bot_token:
            return
        if self._application is not None:
            return
        app_class = Application
        if app_class is None:
            return
        builder = getattr(app_class, "builder", None)
        if not callable(builder):
            return
        app_builder = builder()
        token_setter = getattr(app_builder, "token", None)
        if not callable(token_setter):
            return
        self._application = token_setter(self._config.bot_token).build()

        async def _on_message(update: Any, _context: Any) -> None:
            message = getattr(update, "effective_message", None)
            user = getattr(update, "effective_user", None)
            chat = getattr(update, "effective_chat", None)
            if message is None or user is None:
                return
            if bool(getattr(user, "is_bot", False)):
                return
            text = str(getattr(message, "text", "") or "").strip()
            if not text:
                return
            chat_id = str(getattr(chat, "id", "")) if chat is not None else ""
            await self._incoming.put(
                ChannelMessage(
                    channel="telegram",
                    external_user_id=str(getattr(user, "id", "")),
                    workspace_hint=self.workspace_for_chat(chat_id),
                    content=text,
                    message_id=str(getattr(message, "message_id", "")),
                    reply_target=chat_id,
                    thread_id=str(getattr(message, "message_thread_id", "") or ""),
                )
            )

        message_handler = MessageHandler
        filters_module = filters
        if message_handler is not None and filters_module is not None:
            handler = message_handler(filters_module.TEXT & ~filters_module.COMMAND, _on_message)
            self._application.add_handler(handler)
        with contextlib.suppress(OSError, RuntimeError, ValueError):
            await self._application.initialize()
            await self._application.start()
            updater = getattr(self._application, "updater", None)
            if updater is not None:
                start_polling = getattr(updater, "start_polling", None)
                if callable(start_polling):
                    await start_polling()

    async def disconnect(self) -> None:
        if self._application is not None:
            updater = getattr(self._application, "updater", None)
            if updater is not None:
                stop_polling = getattr(updater, "stop", None)
                if callable(stop_polling):
                    with contextlib.suppress(OSError, RuntimeError, ValueError):
                        result = stop_polling()
                        if asyncio.iscoroutine(result):
                            await result
            stop = getattr(self._application, "stop", None)
            if callable(stop):
                with contextlib.suppress(OSError, RuntimeError, ValueError):
                    await stop()
            shutdown = getattr(self._application, "shutdown", None)
            if callable(shutdown):
                with contextlib.suppress(OSError, RuntimeError, ValueError):
                    await shutdown()
        self._application = None
        await super().disconnect()

    async def send(self, message: str, *, target: DeliveryTarget | None = None) -> None:
        if self._application is not None:
            bot = getattr(self._application, "bot", None)
            send_message = getattr(bot, "send_message", None) if bot is not None else None
            if callable(send_message):
                recipient = (target.recipient if target is not None else "").strip()
                if not recipient:
                    recipient = self._config.default_chat_id
                if recipient:
                    kwargs: dict[str, Any] = {}
                    if target is not None and target.thread_id.strip():
                        try:
                            kwargs["message_thread_id"] = int(target.thread_id.strip())
                        except ValueError:
                            kwargs["message_thread_id"] = target.thread_id.strip()
                    await send_message(chat_id=recipient, text=message, **kwargs)
                    return
        await super().send(message, target=target)

    def workspace_for_chat(self, chat_id: str) -> str:
        mapping = self._config.chat_workspace_map or {}
        if chat_id:
            return mapping.get(chat_id, chat_id)
        return "telegram"

    def is_user_verified(self, user_id: str) -> bool:
        trusted = self._config.trusted_users or set()
        return user_id in trusted

    def health_status(self) -> dict[str, Any]:
        status = super().health_status()
        status.update({"available": self.available, "app_active": self._application is not None})
        return status
