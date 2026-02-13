"""Adapter exposing MONITOR-route completion for monitor workflows."""

from __future__ import annotations

from typing import Any

from shisad.core.providers.base import Message, ProviderResponse
from shisad.core.providers.routed_openai import RoutedOpenAIProvider


class MonitorProviderAdapter:
    """Adapter exposing MONITOR route completion for control-plane monitor calls."""

    def __init__(self, provider: RoutedOpenAIProvider) -> None:
        self._provider = provider

    async def complete(
        self,
        messages: list[Message],
        tools: list[dict[str, Any]] | None = None,
    ) -> ProviderResponse:
        return await self._provider.monitor_complete(messages, tools)
