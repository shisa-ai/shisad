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
from shisad.core.providers.capabilities import AuthMode, EndpointFamily
from shisad.core.providers.local_planner import LocalPlannerProvider
from shisad.core.providers.routing import ModelComponent, ModelRoute, ModelRouter

logger = logging.getLogger(__name__)


class RoutedOpenAIProvider:
    """OpenAI-compatible provider bound to router component routes."""

    def __init__(
        self,
        *,
        router: ModelRouter,
        api_key: str | None = None,
        fallback: LocalPlannerProvider | None = None,
        allow_http_localhost: bool = True,
        block_private_ranges: bool = True,
        endpoint_allowlist: list[str] | None = None,
    ) -> None:
        self._fallback = fallback

        planner_route = router.route_for(ModelComponent.PLANNER)
        embeddings_route = router.route_for(ModelComponent.EMBEDDINGS)
        monitor_route = router.route_for(ModelComponent.MONITOR)

        self._planner_provider = self._build_route_provider(
            route=planner_route,
            fallback_api_key=api_key,
            force_json_response=False,
            allow_http_localhost=allow_http_localhost,
            block_private_ranges=block_private_ranges,
            endpoint_allowlist=endpoint_allowlist,
        )
        self._embeddings_provider = self._build_route_provider(
            route=embeddings_route,
            fallback_api_key=api_key,
            force_json_response=False,
            allow_http_localhost=allow_http_localhost,
            block_private_ranges=block_private_ranges,
            endpoint_allowlist=endpoint_allowlist,
        )
        self._monitor_provider = self._build_route_provider(
            route=monitor_route,
            fallback_api_key=api_key,
            force_json_response=True,
            allow_http_localhost=allow_http_localhost,
            block_private_ranges=block_private_ranges,
            endpoint_allowlist=endpoint_allowlist,
        )

        self._embeddings_model_id = embeddings_route.model_id
        self._monitor_remote_enabled = self._monitor_provider is not None

    def monitor_remote_enabled(self) -> bool:
        return self._monitor_remote_enabled

    @staticmethod
    def _build_route_provider(
        *,
        route: ModelRoute,
        fallback_api_key: str | None,
        force_json_response: bool,
        allow_http_localhost: bool,
        block_private_ranges: bool,
        endpoint_allowlist: list[str] | None,
    ) -> OpenAICompatibleProvider | None:
        fallback_key = (fallback_api_key or "").strip()
        if not route.remote_enabled:
            return None

        if (
            route.component in {ModelComponent.PLANNER, ModelComponent.MONITOR}
            and route.endpoint_family != EndpointFamily.CHAT_COMPLETIONS
        ):
            raise ValueError(
                f"{route.component.value} route endpoint_family must be chat_completions"
            )
        if (
            route.component == ModelComponent.EMBEDDINGS
            and route.endpoint_family != EndpointFamily.EMBEDDINGS
        ):
            raise ValueError("embeddings route endpoint_family must be embeddings")

        resolved_key = route.api_key or fallback_key
        headers: dict[str, str] = dict(route.extra_headers)
        if route.auth_mode == AuthMode.BEARER:
            if not resolved_key:
                logger.warning(
                    "Remote %s route disabled: bearer auth selected but API key missing",
                    route.component.value,
                )
                return None
            headers[route.auth_header_name] = f"Bearer {resolved_key}"
        elif route.auth_mode == AuthMode.HEADER:
            if not resolved_key:
                logger.warning(
                    "Remote %s route disabled: header auth selected but API key missing",
                    route.component.value,
                )
                return None
            headers[route.auth_header_name] = resolved_key

        return OpenAICompatibleProvider(
            base_url=route.base_url,
            model_id=route.model_id,
            headers=headers,
            force_json_response=force_json_response,
            request_parameters=route.request_parameters,
            allow_http_localhost=allow_http_localhost,
            block_private_ranges=block_private_ranges,
            endpoint_allowlist=endpoint_allowlist,
        )

    async def complete(
        self,
        messages: list[Message],
        tools: list[dict[str, Any]] | None = None,
    ) -> ProviderResponse:
        if self._planner_provider is None:
            if self._fallback is None:
                raise RuntimeError(
                    "planner route remote provider unavailable and no fallback configured"
                )
            return await self._fallback.complete(messages, tools)

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
        if self._embeddings_provider is None:
            if self._fallback is None:
                raise RuntimeError(
                    "embeddings route remote provider unavailable and no fallback configured"
                )
            return await self._fallback.embeddings(input_texts, model_id=target_model)

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
        if self._monitor_provider is None:
            return self._deterministic_monitor_fallback()

        try:
            return await self._monitor_provider.complete(messages, tools)
        except (OSError, RuntimeError, TypeError, ValueError):
            logger.warning(
                "Remote monitor provider failed; using deterministic monitor fallback",
            )
            return self._deterministic_monitor_fallback()

    @staticmethod
    def _deterministic_monitor_fallback() -> ProviderResponse:
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
