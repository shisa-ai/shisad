"""Per-component model routing configuration."""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, Field

from shisad.core.config import ModelConfig
from shisad.core.providers.capabilities import ProviderCapabilities, RequestParameters


class ModelComponent(StrEnum):
    PLANNER = "planner"
    EMBEDDINGS = "embeddings"
    MONITOR = "monitor"


class ModelRoute(BaseModel):
    component: ModelComponent
    model_id: str
    base_url: str
    capabilities: ProviderCapabilities = Field(default_factory=ProviderCapabilities)
    request_parameters: RequestParameters = Field(default_factory=RequestParameters)


class ModelRouter:
    """Resolves model routes per component."""

    def __init__(self, config: ModelConfig) -> None:
        self._routes: dict[ModelComponent, ModelRoute] = {
            ModelComponent.PLANNER: ModelRoute(
                component=ModelComponent.PLANNER,
                model_id=config.planner_model_id,
                base_url=config.planner_base_url or config.base_url,
                capabilities=config.planner_capabilities,
                request_parameters=config.planner_request_parameters,
            ),
            ModelComponent.EMBEDDINGS: ModelRoute(
                component=ModelComponent.EMBEDDINGS,
                model_id=config.embeddings_model_id,
                base_url=config.embeddings_base_url or config.base_url,
                capabilities=config.embeddings_capabilities,
                request_parameters=config.embeddings_request_parameters,
            ),
            ModelComponent.MONITOR: ModelRoute(
                component=ModelComponent.MONITOR,
                model_id=config.monitor_model_id,
                base_url=config.monitor_base_url or config.base_url,
                capabilities=config.monitor_capabilities,
                request_parameters=config.monitor_request_parameters,
            ),
        }

    def route_for(self, component: ModelComponent) -> ModelRoute:
        return self._routes[component]
