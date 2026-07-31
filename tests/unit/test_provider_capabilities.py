"""M2 provider capability model coverage."""

from __future__ import annotations

import pytest

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


def test_m2_model_config_parses_capabilities_from_env_json(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(
        "SHISAD_MODEL_PLANNER_CAPABILITIES",
        '{"supports_tool_calls": false, "supports_content_tool_calls": true}',
    )
    config = ModelConfig()

    assert config.planner_capabilities.supports_tool_calls is False
    assert config.planner_capabilities.supports_content_tool_calls is True


def test_m2_model_config_parses_request_parameters_from_env_json(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(
        "SHISAD_MODEL_PLANNER_REQUEST_PARAMETERS",
        '{"temperature": 0.25, "max_tokens": 300, "top_p": 0.9}',
    )
    config = ModelConfig()

    assert config.planner_request_parameters.temperature == 0.25
    assert config.planner_request_parameters.max_tokens == 300
    assert config.planner_request_parameters.top_p == 0.9


def test_i2_shisa_route_discovers_known_context_window() -> None:
    shisa_route = ModelRouter(
        ModelConfig(
            planner_remote_enabled=True,
            planner_auth_mode="none",
            planner_provider_preset="shisa_default",
        )
    ).route_for(ModelComponent.PLANNER)
    assert shisa_route.capabilities.context_window_tokens == 16_384
    assert shisa_route.capabilities.output_reserve_tokens == 1_024

    custom_route = ModelRouter(
        ModelConfig(
            planner_remote_enabled=True,
            planner_auth_mode="none",
            planner_model_id="custom/model-with-unknown-window",
        )
    ).route_for(ModelComponent.PLANNER)
    assert custom_route.capabilities.context_window_tokens is None

    explicit_route = ModelRouter(
        ModelConfig(
            planner_remote_enabled=True,
            planner_auth_mode="none",
            planner_model_id="custom/model-with-configured-window",
            planner_capabilities=ProviderCapabilities(
                context_window_tokens=32_768,
                output_reserve_tokens=2_048,
            ),
        )
    ).route_for(ModelComponent.PLANNER)
    assert explicit_route.capabilities.context_window_tokens == 32_768
    assert explicit_route.capabilities.output_reserve_tokens == 2_048
