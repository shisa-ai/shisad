"""Shared outbound delivery abstraction for runtime channels."""

from __future__ import annotations

import logging
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from shisad.channels.base import Channel, DeliveryTarget

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class DeliveryResult:
    attempted: bool
    sent: bool
    reason: str = ""
    target: DeliveryTarget | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "attempted": self.attempted,
            "sent": self.sent,
            "reason": self.reason,
            "target": self.target.model_dump(mode="json") if self.target is not None else {},
        }


class ChannelDeliveryService:
    """Routes outbound messages to the correct channel implementation."""

    def __init__(self, channels: Mapping[str, Channel]) -> None:
        self._channels: dict[str, Channel] = dict(channels)

    async def send(self, *, target: DeliveryTarget, message: str) -> DeliveryResult:
        channel = self._channels.get(target.channel)
        if channel is None:
            return DeliveryResult(
                attempted=True,
                sent=False,
                reason="channel_not_available",
                target=target,
            )
        try:
            status = channel.health_status()
        except Exception:
            status = {}
        available = status.get("available")
        if available is None:
            available = bool(getattr(channel, "available", True))
        if available is False:
            return DeliveryResult(
                attempted=True,
                sent=False,
                reason="channel_dependency_unavailable",
                target=target,
            )
        connected = status.get("connected")
        if connected is None:
            connected = bool(getattr(channel, "connected", True))
        if connected is False:
            return DeliveryResult(
                attempted=True,
                sent=False,
                reason="channel_not_connected",
                target=target,
            )
        try:
            await channel.send(message, target=target)
            logger.info(
                "Outbound channel delivery succeeded (channel=%s, recipient=%s)",
                target.channel,
                target.recipient,
            )
            return DeliveryResult(attempted=True, sent=True, reason="sent", target=target)
        except Exception:
            logger.exception(
                "Outbound channel delivery failed (channel=%s, recipient=%s)",
                target.channel,
                target.recipient,
            )
            return DeliveryResult(
                attempted=True,
                sent=False,
                reason="send_failed",
                target=target,
            )

    def health_status(self) -> dict[str, dict[str, Any]]:
        status: dict[str, dict[str, Any]] = {}
        for name, channel in self._channels.items():
            try:
                status[name] = channel.health_status()
            except Exception:
                status[name] = {"connected": False, "error": "health_status_failed"}
        return status
