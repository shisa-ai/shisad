"""M2 provider capability model coverage."""

from __future__ import annotations

from shisad.core.config import ModelConfig
from shisad.core.providers.capabilities import ProviderCapabilities, RequestParameters
from shisad.core.providers.routing import ModelComponent, ModelRouter


def test_m2_provider_capabilities_default_flags() -> None:
    caps = ProviderCapabilities()

    assert caps.supports_tool_calls is True
    assert caps.supports_content_tool_calls is False
    assert caps.supports_structured_output is False


def test_m2_model_router_carries_per_route_capabilities_and_request_parameters() -> None:
    config = ModelConfig(
        base_url="https://api.default/v1",
        planner_model_id="planner-a",
        planner_capabilities=ProviderCapabilities(
            supports_tool_calls=False,
            supports_content_tool_calls=True,
            supports_structured_output=False,
        ),
        planner_request_parameters=RequestParameters(
            temperature=0.2,
            max_tokens=256,
            top_p=0.9,
        ),
    )

    router = ModelRouter(config)
    planner_route = router.route_for(ModelComponent.PLANNER)

    assert planner_route.capabilities.supports_tool_calls is False
    assert planner_route.capabilities.supports_content_tool_calls is True
    assert planner_route.request_parameters.temperature == 0.2
    assert planner_route.request_parameters.max_tokens == 256
    assert planner_route.request_parameters.top_p == 0.9


def test_m2_model_router_uses_safe_defaults_for_route_capabilities() -> None:
    router = ModelRouter(ModelConfig(base_url="https://api.default/v1"))

    planner_caps = router.route_for(ModelComponent.PLANNER).capabilities
    planner_params = router.route_for(ModelComponent.PLANNER).request_parameters

    assert planner_caps == ProviderCapabilities()
    assert planner_params == RequestParameters()
