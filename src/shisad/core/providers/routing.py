"""Per-component model routing configuration."""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel

from shisad.core.config import ModelConfig


class ModelComponent(StrEnum):
    PLANNER = "planner"
    EMBEDDINGS = "embeddings"
    MONITOR = "monitor"


class ModelRoute(BaseModel):
    component: ModelComponent
    model_id: str
    base_url: str


class ModelRouter:
    """Resolves model routes per component."""

    def __init__(self, config: ModelConfig) -> None:
        self._routes: dict[ModelComponent, ModelRoute] = {
            ModelComponent.PLANNER: ModelRoute(
                component=ModelComponent.PLANNER,
                model_id=config.planner_model_id,
                base_url=config.planner_base_url or config.base_url,
            ),
            ModelComponent.EMBEDDINGS: ModelRoute(
                component=ModelComponent.EMBEDDINGS,
                model_id=config.embeddings_model_id,
                base_url=config.embeddings_base_url or config.base_url,
            ),
            ModelComponent.MONITOR: ModelRoute(
                component=ModelComponent.MONITOR,
                model_id=config.monitor_model_id,
                base_url=config.monitor_base_url or config.base_url,
            ),
        }

    def route_for(self, component: ModelComponent) -> ModelRoute:
        return self._routes[component]
