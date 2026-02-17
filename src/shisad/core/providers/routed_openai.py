"""Routed OpenAI-compatible provider for planner/monitor/embeddings components."""

from __future__ import annotations

import json
import logging
from typing import Any

from shisad.core.providers.base import (
    EmbeddingResponse,
    Message,
    OpenAICompatibleProvider,
    ProviderResponse,
)
from shisad.core.providers.local_planner import LocalPlannerProvider
from shisad.core.providers.routing import ModelComponent, ModelRouter

logger = logging.getLogger(__name__)


class RoutedOpenAIProvider:
    """OpenAI-compatible provider bound to router component routes."""

    def __init__(
        self,
        *,
        router: ModelRouter,
        api_key: str,
        fallback: LocalPlannerProvider | None = None,
        allow_http_localhost: bool = True,
        block_private_ranges: bool = True,
        endpoint_allowlist: list[str] | None = None,
    ) -> None:
        headers = {"Authorization": f"Bearer {api_key}"}
        planner_route = router.route_for(ModelComponent.PLANNER)
        embeddings_route = router.route_for(ModelComponent.EMBEDDINGS)
        monitor_route = router.route_for(ModelComponent.MONITOR)
        self._planner_provider = OpenAICompatibleProvider(
            base_url=planner_route.base_url,
            model_id=planner_route.model_id,
            headers=headers,
            allow_http_localhost=allow_http_localhost,
            block_private_ranges=block_private_ranges,
            endpoint_allowlist=endpoint_allowlist,
        )
        self._embeddings_provider = OpenAICompatibleProvider(
            base_url=embeddings_route.base_url,
            model_id=embeddings_route.model_id,
            headers=headers,
            allow_http_localhost=allow_http_localhost,
            block_private_ranges=block_private_ranges,
            endpoint_allowlist=endpoint_allowlist,
        )
        self._monitor_provider = OpenAICompatibleProvider(
            base_url=monitor_route.base_url,
            model_id=monitor_route.model_id,
            headers=headers,
            allow_http_localhost=allow_http_localhost,
            block_private_ranges=block_private_ranges,
            endpoint_allowlist=endpoint_allowlist,
        )
        self._embeddings_model_id = embeddings_route.model_id
        self._fallback = fallback

    async def complete(
        self,
        messages: list[Message],
        tools: list[dict[str, Any]] | None = None,
    ) -> ProviderResponse:
        try:
            return await self._planner_provider.complete(messages, tools)
        except (OSError, RuntimeError, TypeError, ValueError):
            if self._fallback is None:
                raise
            logger.warning("Remote planner provider failed; falling back to local provider")
            return await self._fallback.complete(messages, tools)

    async def embeddings(
        self,
        input_texts: list[str],
        *,
        model_id: str | None = None,
    ) -> EmbeddingResponse:
        target_model = model_id or self._embeddings_model_id
        try:
            return await self._embeddings_provider.embeddings(input_texts, model_id=target_model)
        except (OSError, RuntimeError, TypeError, ValueError):
            if self._fallback is None:
                raise
            logger.warning("Remote embeddings provider failed; falling back to local provider")
            return await self._fallback.embeddings(input_texts, model_id=target_model)

    async def monitor_complete(
        self,
        messages: list[Message],
        tools: list[dict[str, Any]] | None = None,
    ) -> ProviderResponse:
        try:
            return await self._monitor_provider.complete(messages, tools)
        except (OSError, RuntimeError, TypeError, ValueError):
            logger.warning(
                "Remote monitor provider failed; using deterministic monitor fallback",
            )
            return ProviderResponse(
                message=Message(
                    role="assistant",
                    content=json.dumps(
                        {
                            "decision": "FLAG",
                            "reason_codes": ["network:monitor_route_fallback"],
                        },
                        sort_keys=True,
                    ),
                ),
                model="local-fallback",
                finish_reason="stop",
                usage={
                    "prompt_tokens": 0,
                    "completion_tokens": 0,
                    "total_tokens": 0,
                },
            )
