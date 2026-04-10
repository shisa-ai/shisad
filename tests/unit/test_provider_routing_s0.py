"""M3 S0 routing/config resolution coverage."""

from __future__ import annotations

import os

import pytest
from pydantic import ValidationError

from shisad.core.config import ModelConfig
from shisad.core.providers.routing import ModelComponent, ModelRouter, provider_preset_label


def _clean_api_key_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Remove env vars that could perturb isolated routing defaults."""
    for var in (
        "OPENAI_API_KEY",
        "GEMINI_API_KEY",
        "OPENROUTER_API_KEY",
        "SHISA_API_KEY",
    ):
        monkeypatch.delenv(var, raising=False)
    for var in list(os.environ):
        if var.startswith("SHISAD_MODEL_"):
            monkeypatch.delenv(var, raising=False)


@pytest.fixture(autouse=True)
def _isolate_model_route_env(monkeypatch: pytest.MonkeyPatch) -> None:
    _clean_api_key_env(monkeypatch)


def test_s0_openai_preset_resolves_route_defaults_and_global_remote(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "openai-key")

    config = ModelConfig(
        remote_enabled=True,
        planner_provider_preset="openai_default",
        planner_model_id="gpt-5.4-2026-03-05",
    )
    route = ModelRouter(config).route_for(ModelComponent.PLANNER)

    assert route.base_url == "https://api.openai.com/v1"
    assert route.remote_enabled is True
    assert route.remote_enabled_source == "global"
    assert route.auth_mode == "bearer"
    assert route.auth_header_name == "Authorization"
    assert route.api_key == "openai-key"
    assert route.api_key_source == "preset_provider:OPENAI_API_KEY"
    assert route.endpoint_family == "chat_completions"
    assert route.request_parameter_profile == "openai_chat_general"


def test_s0_route_overrides_beat_preset_defaults() -> None:
    config = ModelConfig(
        planner_provider_preset="openai_default",
        planner_base_url="https://planner.override.example/v1",
        planner_auth_mode="none",
        planner_endpoint_family="chat_completions",
    )
    route = ModelRouter(config).route_for(ModelComponent.PLANNER)

    assert route.base_url == "https://planner.override.example/v1"
    assert route.auth_mode == "none"


def test_s0_route_key_has_highest_precedence(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SHISAD_MODEL_API_KEY", "global-key")
    monkeypatch.setenv("OPENAI_API_KEY", "preset-key")
    monkeypatch.setenv("SHISAD_MODEL_PLANNER_API_KEY", "route-key")

    config = ModelConfig(planner_provider_preset="openai_default")
    route = ModelRouter(config).route_for(ModelComponent.PLANNER)

    assert route.api_key == "route-key"
    assert route.api_key_source == "route:planner_api_key"


def test_s0_header_auth_requires_header_name() -> None:
    with pytest.raises(ValidationError, match="planner_auth_header_name"):
        ModelConfig(planner_auth_mode="header")


def test_s0_extra_header_validation_enforces_token_safe_names() -> None:
    with pytest.raises(ValidationError, match="planner_extra_headers"):
        ModelConfig(planner_extra_headers={"X Unsafe": "value"})


@pytest.mark.parametrize("header_name", ["Content-Type", "Accept"])
def test_s0_extra_header_validation_rejects_reserved_system_headers(
    header_name: str,
) -> None:
    with pytest.raises(ValidationError, match="cannot override auth/system headers"):
        ModelConfig(planner_extra_headers={header_name: "text/plain"})


def test_s0_bearer_auth_rejects_custom_auth_header_name() -> None:
    with pytest.raises(ValidationError, match="planner_auth_header_name is only supported"):
        ModelConfig(
            planner_auth_mode="bearer",
            planner_auth_header_name="X-Api-Key",
        )


def test_s0_auth_mode_none_rejects_custom_auth_header_name() -> None:
    with pytest.raises(ValidationError, match="planner_auth_header_name is only supported"):
        ModelConfig(
            planner_auth_mode="none",
            planner_auth_header_name="X-Api-Key",
        )


def test_s0_openrouter_headers_are_accepted_and_normalized() -> None:
    config = ModelConfig(
        planner_provider_preset="openrouter_default",
        planner_extra_headers={
            "HTTP-Referer": "https://example.com",
            "X-Title": "shisad",
        },
    )
    route = ModelRouter(config).route_for(ModelComponent.PLANNER)

    assert route.extra_headers == {
        "http-referer": "https://example.com",
        "x-title": "shisad",
    }


def test_s0_profile_auto_selection_uses_preset_default_over_hostname_heuristic() -> None:
    config = ModelConfig(planner_base_url="https://openrouter.ai/api/v1")
    route = ModelRouter(config).route_for(ModelComponent.PLANNER)

    assert route.request_parameter_profile == "openai_chat_general"
    assert route.request_parameter_profile_source == "preset_default"


def test_s0_profile_auto_selection_uses_preset_default_for_default_preset() -> None:
    route = ModelRouter(ModelConfig()).route_for(ModelComponent.PLANNER)
    assert route.request_parameter_profile == "openai_chat_general"
    assert route.request_parameter_profile_source == "preset_default"


def test_s0_openrouter_route_does_not_fallback_to_cross_provider_keys(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "openai-key")
    monkeypatch.setenv("SHISA_API_KEY", "shisa-key")
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    monkeypatch.delenv("SHISAD_MODEL_API_KEY", raising=False)

    config = ModelConfig(planner_provider_preset="openrouter_default")
    route = ModelRouter(config).route_for(ModelComponent.PLANNER)

    assert route.api_key is None
    assert route.api_key_source == "missing"


def test_s0_global_explicit_key_can_drive_openrouter_route(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SHISAD_MODEL_API_KEY", "global-key")
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("SHISA_API_KEY", raising=False)

    config = ModelConfig(planner_provider_preset="openrouter_default")
    route = ModelRouter(config).route_for(ModelComponent.PLANNER)

    assert route.api_key == "global-key"
    assert route.api_key_source == "global:SHISAD_MODEL_API_KEY"


def test_s0_default_planner_auto_enables_remote_with_shisa_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clean_api_key_env(monkeypatch)
    monkeypatch.setenv("SHISA_API_KEY", "shisa-key")

    route = ModelRouter(ModelConfig()).route_for(ModelComponent.PLANNER)

    assert route.remote_enabled is True
    assert route.remote_enabled_source == "implicit_shisa_key"
    assert route.api_key_source == "preset_provider:SHISA_API_KEY"


def test_s0_implicit_shisa_remote_enable_only_applies_to_default_base_route(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clean_api_key_env(monkeypatch)
    monkeypatch.setenv("SHISA_API_KEY", "shisa-key")

    route = ModelRouter(ModelConfig(planner_base_url="https://planner.example.com/v1")).route_for(
        ModelComponent.PLANNER
    )

    assert route.remote_enabled is False
    assert route.remote_enabled_source == "global"


def test_s0_route_local_base_url_override_is_labeled_as_overridden(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clean_api_key_env(monkeypatch)
    route = ModelRouter(ModelConfig(planner_base_url="https://planner.example.com/v1")).route_for(
        ModelComponent.PLANNER
    )

    assert route.base_url_source == "route:planner_base_url"
    assert provider_preset_label(route) == "shisa_default (overridden)"


def test_s0_model_config_parses_reasoning_request_parameters_from_env(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(
        "SHISAD_MODEL_PLANNER_REQUEST_PARAMETERS",
        '{"temperature": 0.2, "reasoning_effort": "medium", "reasoning": {"budget_tokens": 128}}',
    )
    config = ModelConfig()

    assert config.planner_request_parameters.temperature == 0.2
    assert config.planner_request_parameters.reasoning_effort == "medium"
    assert config.planner_request_parameters.reasoning is not None
    assert config.planner_request_parameters.reasoning.budget_tokens == 128


# --- Smart model routing defaults (auto-detection) ---


def test_s0_openai_key_auto_detects_preset(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clean_api_key_env(monkeypatch)
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")

    route = ModelRouter(ModelConfig()).route_for(ModelComponent.PLANNER)

    assert route.provider_preset == "openai_default"
    assert route.provider_preset_source == "auto_detected"


def test_s0_auto_detected_preset_enables_remote_implicitly(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clean_api_key_env(monkeypatch)
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")

    route = ModelRouter(ModelConfig()).route_for(ModelComponent.PLANNER)

    assert route.remote_enabled is True
    assert route.remote_enabled_source == "implicit_preset_key:auto_detected"


def test_s0_auto_detected_preset_uses_preset_default_model_id(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clean_api_key_env(monkeypatch)
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")

    route = ModelRouter(ModelConfig()).route_for(ModelComponent.PLANNER)

    assert route.model_id == "gpt-5.4-2026-03-05"


def test_s0_auto_detected_preset_uses_preset_base_url(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clean_api_key_env(monkeypatch)
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")

    route = ModelRouter(ModelConfig()).route_for(ModelComponent.PLANNER)

    assert route.base_url == "https://api.openai.com/v1"


def test_s0_explicit_preset_overrides_auto_detection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clean_api_key_env(monkeypatch)
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    monkeypatch.setenv("OPENROUTER_API_KEY", "or-test")

    config = ModelConfig(planner_provider_preset="openrouter_default")
    route = ModelRouter(config).route_for(ModelComponent.PLANNER)

    assert route.provider_preset == "openrouter_default"
    assert route.provider_preset_source == "route_override"
    assert route.base_url == "https://openrouter.ai/api/v1"


def test_s0_explicit_model_id_overrides_preset_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clean_api_key_env(monkeypatch)
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")

    config = ModelConfig(planner_model_id="gpt-4o-custom")
    route = ModelRouter(config).route_for(ModelComponent.PLANNER)

    assert route.model_id == "gpt-4o-custom"


def test_s0_explicit_remote_false_overrides_auto_enable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clean_api_key_env(monkeypatch)
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")

    config = ModelConfig(planner_remote_enabled=False)
    route = ModelRouter(config).route_for(ModelComponent.PLANNER)

    assert route.remote_enabled is False
    assert route.remote_enabled_source == "route_override"


def test_s0_gemini_key_auto_detects_google_preset(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clean_api_key_env(monkeypatch)
    monkeypatch.setenv("GEMINI_API_KEY", "gem-test")

    route = ModelRouter(ModelConfig()).route_for(ModelComponent.PLANNER)

    assert route.provider_preset == "google_openai_default"
    assert route.provider_preset_source == "auto_detected"
    assert route.base_url == "https://generativelanguage.googleapis.com/v1beta/openai"
    assert route.model_id == "gemini-3.1-pro-preview"
    assert route.remote_enabled is True
