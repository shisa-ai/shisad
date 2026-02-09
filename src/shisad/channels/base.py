"""Channel abstraction and in-memory helper implementation."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import Protocol

from pydantic import BaseModel, Field


class ChannelMessage(BaseModel):
    channel: str
    external_user_id: str
    workspace_hint: str = ""
    content: str
    received_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class Channel(Protocol):
    async def connect(self) -> None: ...

    async def disconnect(self) -> None: ...

    async def send(self, message: str) -> None: ...

    async def receive(self) -> ChannelMessage: ...


class InMemoryChannel:
    """In-memory channel used for tests and local fallback."""

    def __init__(self, name: str = "memory") -> None:
        self._name = name
        self._incoming: asyncio.Queue[ChannelMessage] = asyncio.Queue()
        self._outgoing: asyncio.Queue[str] = asyncio.Queue()
        self._connected = False

    async def connect(self) -> None:
        self._connected = True

    async def disconnect(self) -> None:
        self._connected = False

    async def send(self, message: str) -> None:
        if not self._connected:
            raise RuntimeError("channel not connected")
        await self._outgoing.put(message)

    async def receive(self) -> ChannelMessage:
        if not self._connected:
            raise RuntimeError("channel not connected")
        return await self._incoming.get()

    async def inject(self, external_user_id: str, content: str, workspace_hint: str = "") -> None:
        await self._incoming.put(
            ChannelMessage(
                channel=self._name,
                external_user_id=external_user_id,
                workspace_hint=workspace_hint,
                content=content,
            )
        )
