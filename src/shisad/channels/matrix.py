"""Matrix channel integration.

Supports a local in-memory fallback when `matrix-nio` is unavailable, while
exposing a stable channel interface and workspace/identity mapping hooks.
"""

from __future__ import annotations

import asyncio
import contextlib
from dataclasses import dataclass
from typing import Any

from shisad.channels.base import ChannelMessage, DeliveryTarget, InMemoryChannel

try:  # pragma: no cover - optional dependency.
    import nio  # type: ignore
except ImportError:  # pragma: no cover - optional dependency.
    nio = None


@dataclass(slots=True)
class MatrixConfig:
    homeserver: str
    user_id: str
    access_token: str
    room_id: str
    device_id: str = ""
    enable_e2ee: bool = True
    room_workspace_map: dict[str, str] | None = None
    trusted_users: set[str] | None = None


class MatrixChannel(InMemoryChannel):
    """Matrix channel wrapper with optional matrix-nio transport."""

    def __init__(self, config: MatrixConfig) -> None:
        super().__init__(name="matrix")
        self._config = config
        self._client: Any | None = None
        self._sync_task: asyncio.Task[None] | None = None

    @property
    def available(self) -> bool:
        return nio is not None

    @property
    def e2ee_enabled(self) -> bool:
        return bool(self.available and self._config.enable_e2ee)

    async def connect(self) -> None:
        await super().connect()
        if nio is not None:
            client_config = None
            config_ctor = getattr(nio, "AsyncClientConfig", None)
            if config_ctor is not None:
                client_config = config_ctor(encryption_enabled=self._config.enable_e2ee)

            client_ctor = getattr(nio, "AsyncClient", None)
            if client_ctor is None:
                return
            if client_config is not None:
                self._client = client_ctor(
                    self._config.homeserver,
                    self._config.user_id,
                    config=client_config,
                )
            else:
                self._client = client_ctor(self._config.homeserver, self._config.user_id)

            # Access token auth keeps startup deterministic for daemon mode.
            self._client.access_token = self._config.access_token
            if self._config.device_id:
                self._client.device_id = self._config.device_id

            message_event = getattr(nio, "RoomMessageText", None)
            if message_event is not None:
                self._client.add_event_callback(self._on_room_message, message_event)

            sync_forever = getattr(self._client, "sync_forever", None)
            if callable(sync_forever):
                self._sync_task = asyncio.create_task(self._sync_loop())

    async def disconnect(self) -> None:
        if self._sync_task is not None:
            self._sync_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._sync_task
            self._sync_task = None

        if self._client is not None:
            close = getattr(self._client, "close", None)
            if callable(close):
                with contextlib.suppress(OSError, RuntimeError):
                    await close()
            self._client = None

        await super().disconnect()

    async def send(self, message: str, *, target: DeliveryTarget | None = None) -> None:
        if self._client is not None:
            room_send = getattr(self._client, "room_send", None)
            if callable(room_send):
                room_id = self._config.room_id
                if target is not None and target.recipient.strip():
                    room_id = target.recipient.strip()
                await room_send(
                    room_id=room_id,
                    message_type="m.room.message",
                    content={"msgtype": "m.text", "body": message},
                )
                return
        await super().send(message, target=target)

    def workspace_for_room(self, room_id: str) -> str:
        mapping = self._config.room_workspace_map or {}
        return mapping.get(room_id, room_id or self._config.room_id)

    def is_user_verified(self, user_id: str) -> bool:
        trusted = self._config.trusted_users or set()
        return user_id in trusted

    def health_status(self) -> dict[str, Any]:
        status = super().health_status()
        status.update(
            {
                "available": self.available,
                "e2ee_enabled": self.e2ee_enabled,
                "sync_task_running": self._sync_task is not None and not self._sync_task.done(),
            }
        )
        return status

    async def _sync_loop(self) -> None:
        if self._client is None:
            return
        sync_forever = getattr(self._client, "sync_forever", None)
        if not callable(sync_forever):
            return
        try:
            await sync_forever(timeout=30_000, full_state=True)
        except asyncio.CancelledError:
            raise
        except Exception:
            return

    async def _on_room_message(self, room: Any, event: Any) -> None:
        body = str(getattr(event, "body", ""))
        sender = str(getattr(event, "sender", ""))
        room_id = str(getattr(room, "room_id", self._config.room_id))
        if not body or not sender:
            return
        await self._incoming.put(
            ChannelMessage(
                channel="matrix",
                external_user_id=sender,
                workspace_hint=self.workspace_for_room(room_id),
                content=body,
                message_id=str(getattr(event, "event_id", "") or ""),
                reply_target=room_id,
                thread_id=str(getattr(event, "event_id", "") or ""),
            )
        )
