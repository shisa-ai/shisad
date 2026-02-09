"""Channel ingress firewall path."""

from __future__ import annotations

from dataclasses import dataclass

from shisad.channels.base import ChannelMessage
from shisad.security.firewall import ContentFirewall, FirewallResult


@dataclass(slots=True)
class ChannelIngressProcessor:
    """Ensures all channel content is sanitized before planning."""

    firewall: ContentFirewall

    def process(self, message: ChannelMessage) -> tuple[ChannelMessage, FirewallResult]:
        result = self.firewall.inspect(message.content)
        sanitized = message.model_copy(update={"content": result.sanitized_text})
        return sanitized, result

