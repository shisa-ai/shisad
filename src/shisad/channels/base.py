"""Channel abstraction and in-memory helper implementation."""

from __future__ import annotations

import asyncio
import uuid
from collections import deque
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from typing import Any, Protocol

from pydantic import BaseModel, Field


class DeliveryTarget(BaseModel):
    """Opaque channel recipient coordinates for outbound delivery."""

    channel: str
    recipient: str
    workspace_hint: str = ""
    thread_id: str = ""


class DeliveryEnvelope(BaseModel):
    """Outbound payload queued or delivered on a channel."""

    target: DeliveryTarget
    content: str
    sent_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class ChannelMessage(BaseModel):
    channel: str
    external_user_id: str
    workspace_hint: str = ""
    content: str
    message_id: str = ""
    reply_target: str = ""
    thread_id: str = ""
    received_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class Channel(Protocol):
    async def connect(self) -> None: ...

    async def disconnect(self) -> None: ...

    async def send(self, message: str, *, target: DeliveryTarget | None = None) -> None: ...

    async def receive(self) -> ChannelMessage: ...

    async def heartbeat(self) -> None: ...

    def health_status(self) -> dict[str, Any]: ...


class InMemoryChannel:
    """In-memory channel used for tests and local fallback."""

    def __init__(
        self,
        name: str = "memory",
        *,
        max_buffer: int = 256,
        reconnect_backoff_base: float = 0.1,
        reconnect_backoff_max: float = 2.0,
    ) -> None:
        self._name = name
        self._incoming: asyncio.Queue[ChannelMessage] = asyncio.Queue(maxsize=max_buffer)
        self._outgoing: asyncio.Queue[DeliveryEnvelope] = asyncio.Queue(maxsize=max_buffer)
        self._offline_outgoing: deque[DeliveryEnvelope] = deque(maxlen=max_buffer)
        self._connected = False
        self._last_heartbeat: datetime | None = None
        self._reconnect_backoff_base = reconnect_backoff_base
        self._reconnect_backoff_max = reconnect_backoff_max

    @property
    def connected(self) -> bool:
        return self._connected

    async def connect(self) -> None:
        self._connected = True
        await self.heartbeat()
        while self._offline_outgoing:
            await self._outgoing.put(self._offline_outgoing.popleft())

    async def disconnect(self) -> None:
        self._connected = False

    async def send(self, message: str, *, target: DeliveryTarget | None = None) -> None:
        envelope = DeliveryEnvelope(
            target=target
            or DeliveryTarget(
                channel=self._name,
                recipient="default",
            ),
            content=message,
        )
        if not self._connected:
            self._offline_outgoing.append(envelope)
            return
        await self._outgoing.put(envelope)

    async def receive(self) -> ChannelMessage:
        if not self._connected:
            raise RuntimeError("channel not connected")
        return await self._incoming.get()

    async def heartbeat(self) -> None:
        if not self._connected:
            return
        self._last_heartbeat = datetime.now(UTC)

    def health_status(self) -> dict[str, Any]:
        heartbeat_age: float | None = None
        if self._last_heartbeat is not None:
            heartbeat_age = (datetime.now(UTC) - self._last_heartbeat).total_seconds()
        return {
            "connected": self._connected,
            "last_heartbeat": self._last_heartbeat.isoformat() if self._last_heartbeat else None,
            "heartbeat_age_seconds": heartbeat_age,
            "pending_outgoing": self.pending_outgoing(),
            "pending_incoming": self._incoming.qsize(),
        }

    async def run_with_reconnect(
        self,
        operation: Callable[[], Awaitable[Any] | Any],
        *,
        attempts: int = 5,
    ) -> Any:
        """Run an operation and reconnect with exponential backoff on connection failures."""
        delay = self._reconnect_backoff_base
        last_error: Exception | None = None
        for _ in range(max(attempts, 1)):
            if not self._connected:
                await self.connect()
            try:
                result = operation()
                if asyncio.iscoroutine(result):
                    return await result
                if asyncio.isfuture(result):
                    return await result
                return result
            except (ConnectionError, OSError, RuntimeError) as exc:
                last_error = exc
                await self.disconnect()
                await asyncio.sleep(delay)
                delay = min(delay * 2, self._reconnect_backoff_max)
        raise RuntimeError("channel reconnect attempts exhausted") from last_error

    def pending_outgoing(self) -> int:
        return self._outgoing.qsize() + len(self._offline_outgoing)

    async def pop_outgoing(self) -> str:
        if not self._connected:
            raise RuntimeError("channel not connected")
        return (await self._outgoing.get()).content

    async def pop_outgoing_delivery(self) -> DeliveryEnvelope:
        if not self._connected:
            raise RuntimeError("channel not connected")
        return await self._outgoing.get()

    async def inject(
        self,
        external_user_id: str,
        content: str,
        workspace_hint: str = "",
        *,
        message_id: str = "",
        reply_target: str = "",
        thread_id: str = "",
    ) -> None:
        resolved_message_id = message_id.strip() or uuid.uuid4().hex
        await self._incoming.put(
            ChannelMessage(
                channel=self._name,
                external_user_id=external_user_id,
                workspace_hint=workspace_hint,
                content=content,
                message_id=resolved_message_id,
                reply_target=reply_target,
                thread_id=thread_id,
            )
        )
