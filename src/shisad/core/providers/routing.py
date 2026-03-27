"""Per-component model routing configuration."""

from __future__ import annotations

import os
from enum import StrEnum

from pydantic import BaseModel, Field

from shisad.core.config import ModelConfig
from shisad.core.providers.capabilities import (
    AuthMode,
    EndpointFamily,
    ProviderCapabilities,
    ProviderPreset,
    RequestParameters,
)
from shisad.core.providers.http_headers import validate_extra_headers
from shisad.core.providers.request_profiles import (
    PROFILE_GOOGLE_OPENAI_CHAT,
    PROFILE_OPENAI_CHAT_GENERAL,
    PROFILE_OPENROUTER_CHAT,
    PROFILE_VLLM_CHAT,
    RequestProfileError,
    apply_request_profile,
    auto_select_request_profile,
)


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

    provider_preset: ProviderPreset = ProviderPreset.SHISA_DEFAULT
    provider_preset_source: str = "default"
    remote_enabled: bool = False
    remote_enabled_source: str = "global"

    auth_mode: AuthMode = AuthMode.BEARER
    auth_header_name: str = "Authorization"
    api_key: str | None = None
    api_key_source: str = "missing"
    extra_headers: dict[str, str] = Field(default_factory=dict)

    endpoint_family: EndpointFamily = EndpointFamily.CHAT_COMPLETIONS
    request_parameter_profile: str = PROFILE_OPENAI_CHAT_GENERAL
    request_parameter_profile_source: str = "endpoint_family_fallback"
    request_parameter_profile_reason: str = "default openai-compatible fallback"

    effective_request_payload: dict[str, object] = Field(default_factory=dict)
    mapped_request_fields: list[str] = Field(default_factory=list)
    rejected_request_fields: list[str] = Field(default_factory=list)


_PRESET_BASE_URLS: dict[ProviderPreset, str] = {
    ProviderPreset.SHISA_DEFAULT: "https://api.shisa.ai/openai/v1",
    ProviderPreset.OPENAI_DEFAULT: "https://api.openai.com/v1",
    ProviderPreset.OPENROUTER_DEFAULT: "https://openrouter.ai/api/v1",
    ProviderPreset.GOOGLE_OPENAI_DEFAULT: "https://generativelanguage.googleapis.com/v1beta/openai",
    ProviderPreset.VLLM_LOCAL_DEFAULT: "http://127.0.0.1:8000/v1",
}

_PRESET_AUTH_MODES: dict[ProviderPreset, AuthMode] = {
    ProviderPreset.SHISA_DEFAULT: AuthMode.BEARER,
    ProviderPreset.OPENAI_DEFAULT: AuthMode.BEARER,
    ProviderPreset.OPENROUTER_DEFAULT: AuthMode.BEARER,
    ProviderPreset.GOOGLE_OPENAI_DEFAULT: AuthMode.BEARER,
    ProviderPreset.VLLM_LOCAL_DEFAULT: AuthMode.NONE,
}

_PRESET_DEFAULT_PROFILES: dict[ProviderPreset, str] = {
    ProviderPreset.SHISA_DEFAULT: PROFILE_OPENAI_CHAT_GENERAL,
    ProviderPreset.OPENAI_DEFAULT: PROFILE_OPENAI_CHAT_GENERAL,
    ProviderPreset.OPENROUTER_DEFAULT: PROFILE_OPENROUTER_CHAT,
    ProviderPreset.GOOGLE_OPENAI_DEFAULT: PROFILE_GOOGLE_OPENAI_CHAT,
    ProviderPreset.VLLM_LOCAL_DEFAULT: PROFILE_VLLM_CHAT,
}

_PRESET_DEFAULT_MODEL_IDS: dict[ProviderPreset, dict[ModelComponent, str]] = {
    ProviderPreset.SHISA_DEFAULT: {
        ModelComponent.PLANNER: "shisa-ai/shisa-v2.1-unphi4-14b",
        ModelComponent.EMBEDDINGS: "shisa-ai/shisa-v2.1-unphi4-14b",
        ModelComponent.MONITOR: "shisa-ai/shisa-v2.1-unphi4-14b",
    },
    ProviderPreset.OPENAI_DEFAULT: {
        ModelComponent.PLANNER: "gpt-5.2-2025-12-11",
        ModelComponent.EMBEDDINGS: "text-embedding-3-small",
        ModelComponent.MONITOR: "gpt-5.2-2025-12-11",
    },
    ProviderPreset.GOOGLE_OPENAI_DEFAULT: {
        ModelComponent.PLANNER: "gemini-2.5-flash",
        ModelComponent.EMBEDDINGS: "text-embedding-004",
        ModelComponent.MONITOR: "gemini-2.5-flash",
    },
}

_API_KEY_ENV_TO_PRESET: list[tuple[str, ProviderPreset]] = [
    ("OPENAI_API_KEY", ProviderPreset.OPENAI_DEFAULT),
    ("GEMINI_API_KEY", ProviderPreset.GOOGLE_OPENAI_DEFAULT),
    ("OPENROUTER_API_KEY", ProviderPreset.OPENROUTER_DEFAULT),
]

_PRESET_PROVIDER_KEY_ENV: dict[ProviderPreset, str | None] = {
    ProviderPreset.SHISA_DEFAULT: "SHISA_API_KEY",
    ProviderPreset.OPENAI_DEFAULT: "OPENAI_API_KEY",
    ProviderPreset.OPENROUTER_DEFAULT: "OPENROUTER_API_KEY",
    ProviderPreset.GOOGLE_OPENAI_DEFAULT: "GEMINI_API_KEY",
    ProviderPreset.VLLM_LOCAL_DEFAULT: None,
}

_DEFAULT_PRESET_BY_COMPONENT: dict[ModelComponent, ProviderPreset] = {
    ModelComponent.PLANNER: ProviderPreset.SHISA_DEFAULT,
    ModelComponent.EMBEDDINGS: ProviderPreset.SHISA_DEFAULT,
    ModelComponent.MONITOR: ProviderPreset.SHISA_DEFAULT,
}

_DEFAULT_ENDPOINT_BY_COMPONENT: dict[ModelComponent, EndpointFamily] = {
    ModelComponent.PLANNER: EndpointFamily.CHAT_COMPLETIONS,
    ModelComponent.EMBEDDINGS: EndpointFamily.EMBEDDINGS,
    ModelComponent.MONITOR: EndpointFamily.CHAT_COMPLETIONS,
}


class ModelRouter:
    """Resolves model routes per component."""

    def __init__(self, config: ModelConfig) -> None:
        self._config = config
        self._routes: dict[ModelComponent, ModelRoute] = {
            component: self._resolve_component_route(component)
            for component in ModelComponent
        }

    def route_for(self, component: ModelComponent) -> ModelRoute:
        return self._routes[component]

    def all_routes(self) -> dict[ModelComponent, ModelRoute]:
        return dict(self._routes)

    def _resolve_component_route(self, component: ModelComponent) -> ModelRoute:
        prefix = component.value

        preset_override = getattr(self._config, f"{prefix}_provider_preset")
        if preset_override is None:
            detected = self._auto_detect_preset_from_api_key()
            if detected is not None:
                preset = detected
                preset_source = "auto_detected"
            else:
                preset = _DEFAULT_PRESET_BY_COMPONENT[component]
                preset_source = "default"
        else:
            preset = preset_override
            preset_source = "route_override"

        route_base_url_override = getattr(self._config, f"{prefix}_base_url")
        base_url = self._resolve_route_base_url(
            component=component,
            preset=preset,
            preset_source=preset_source,
        )

        model_id_field = f"{prefix}_model_id"
        model_id = getattr(self._config, model_id_field)
        if (
            model_id_field not in self._config.model_fields_set
            and preset != ProviderPreset.SHISA_DEFAULT
        ):
            preset_models = _PRESET_DEFAULT_MODEL_IDS.get(preset, {})
            if component in preset_models:
                model_id = preset_models[component]
        capabilities = getattr(self._config, f"{prefix}_capabilities")
        request_parameters = getattr(self._config, f"{prefix}_request_parameters")

        auth_mode = getattr(self._config, f"{prefix}_auth_mode")
        if auth_mode is None:
            auth_mode = _PRESET_AUTH_MODES[preset]

        auth_header_name = getattr(self._config, f"{prefix}_auth_header_name")
        if auth_mode == AuthMode.BEARER:
            auth_header_name = "Authorization"
        elif auth_mode == AuthMode.HEADER:
            if not auth_header_name:
                raise ValueError(
                    f"{prefix}_auth_header_name is required when {prefix}_auth_mode=header"
                )
        else:
            auth_header_name = ""

        selected_auth_header_name = auth_header_name if auth_mode != AuthMode.NONE else ""
        raw_extra_headers = getattr(self._config, f"{prefix}_extra_headers")
        extra_headers = validate_extra_headers(
            raw_extra_headers,
            selected_auth_header_name=selected_auth_header_name,
        )

        api_key, api_key_source = self._resolve_route_api_key(component=component, preset=preset)
        route_remote_override = getattr(self._config, f"{prefix}_remote_enabled")
        remote_enabled, remote_source = self._resolve_route_remote_enabled(
            component=component,
            preset=preset,
            preset_source=preset_source,
            route_base_url_override=route_base_url_override,
            route_remote_override=route_remote_override,
            api_key=api_key,
            api_key_source=api_key_source,
        )

        endpoint_family_override = getattr(self._config, f"{prefix}_endpoint_family")
        endpoint_family = endpoint_family_override or _DEFAULT_ENDPOINT_BY_COMPONENT[component]
        self._validate_component_endpoint_family(
            component=component,
            endpoint_family=endpoint_family,
        )

        profile_override = getattr(self._config, f"{prefix}_request_parameter_profile")
        preset_default_profile = _PRESET_DEFAULT_PROFILES[preset]
        selection = auto_select_request_profile(
            explicit_profile=profile_override,
            preset_default_profile=preset_default_profile,
            base_url=base_url,
            endpoint_family=endpoint_family,
            model_id=model_id,
        )

        try:
            evaluation = apply_request_profile(
                profile_name=selection.profile_name,
                endpoint_family=endpoint_family,
                model_id=model_id,
                request_parameters=request_parameters,
            )
        except RequestProfileError as exc:
            raise ValueError(
                f"{component.value} route request parameters invalid: {exc}"
            ) from exc

        return ModelRoute(
            component=component,
            model_id=model_id,
            base_url=base_url,
            capabilities=capabilities,
            request_parameters=request_parameters,
            provider_preset=preset,
            provider_preset_source=preset_source,
            remote_enabled=remote_enabled,
            remote_enabled_source=remote_source,
            auth_mode=auth_mode,
            auth_header_name=auth_header_name,
            api_key=api_key,
            api_key_source=api_key_source,
            extra_headers=extra_headers,
            endpoint_family=endpoint_family,
            request_parameter_profile=selection.profile_name,
            request_parameter_profile_source=selection.source,
            request_parameter_profile_reason=selection.reason,
            effective_request_payload=evaluation.payload,
            mapped_request_fields=list(evaluation.mapped_fields),
            rejected_request_fields=list(evaluation.rejected_fields),
        )

    def _resolve_route_base_url(
        self,
        *,
        component: ModelComponent,
        preset: ProviderPreset,
        preset_source: str,
    ) -> str:
        prefix = component.value
        route_override: str | None = getattr(self._config, f"{prefix}_base_url")
        if route_override:
            return str(route_override)
        if preset_source in {"route_override", "auto_detected"}:
            preset_url = _PRESET_BASE_URLS.get(preset, "")
            if preset_url:
                return preset_url
        return self._config.base_url

    def _resolve_route_api_key(
        self,
        *,
        component: ModelComponent,
        preset: ProviderPreset,
    ) -> tuple[str | None, str]:
        prefix = component.value
        route_key = getattr(self._config, f"{prefix}_api_key")
        if route_key:
            return route_key, f"route:{prefix}_api_key"

        preset_env = _PRESET_PROVIDER_KEY_ENV.get(preset)
        if preset_env:
            preset_key = os.getenv(preset_env, "").strip()
            if preset_key:
                return preset_key, f"preset_provider:{preset_env}"

        global_key, source = self._resolve_global_api_key(preset=preset)
        if global_key:
            return global_key, source
        return None, "missing"

    def _resolve_global_api_key(self, *, preset: ProviderPreset) -> tuple[str, str]:
        if self._config.api_key and self._config.api_key.strip():
            return self._config.api_key.strip(), "global:SHISAD_MODEL_API_KEY"

        if preset == ProviderPreset.SHISA_DEFAULT:
            shisa_key = os.getenv("SHISA_API_KEY", "").strip()
            if shisa_key:
                return shisa_key, "global:SHISA_API_KEY"

        if preset == ProviderPreset.OPENAI_DEFAULT:
            openai_key = os.getenv("OPENAI_API_KEY", "").strip()
            if openai_key:
                return openai_key, "global:OPENAI_API_KEY"

        return "", "missing"

    def _resolve_route_remote_enabled(
        self,
        *,
        component: ModelComponent,
        preset: ProviderPreset,
        preset_source: str,
        route_base_url_override: str | None,
        route_remote_override: bool | None,
        api_key: str | None,
        api_key_source: str,
    ) -> tuple[bool, str]:
        if route_remote_override is not None:
            return bool(route_remote_override), "route_override"

        if self._config.remote_enabled:
            return True, "global"

        if (
            preset_source in {"route_override", "auto_detected"}
            and bool(api_key)
            and api_key_source != "missing"
        ):
            return True, f"implicit_preset_key:{preset_source}"

        if (
            component == ModelComponent.PLANNER
            and preset == ProviderPreset.SHISA_DEFAULT
            and preset_source == "default"
            and not route_base_url_override
            and self._config.base_url == _PRESET_BASE_URLS[ProviderPreset.SHISA_DEFAULT]
            and bool(api_key)
            and api_key_source
            in {
                "route:planner_api_key",
                "preset_provider:SHISA_API_KEY",
                "global:SHISAD_MODEL_API_KEY",
            }
        ):
            return True, "implicit_shisa_key"

        return False, "global"

    @staticmethod
    def _auto_detect_preset_from_api_key() -> ProviderPreset | None:
        for env_var, preset in _API_KEY_ENV_TO_PRESET:
            if os.getenv(env_var, "").strip():
                return preset
        return None

    @staticmethod
    def _validate_component_endpoint_family(
        *,
        component: ModelComponent,
        endpoint_family: EndpointFamily,
    ) -> None:
        if component in {ModelComponent.PLANNER, ModelComponent.MONITOR}:
            if endpoint_family != EndpointFamily.CHAT_COMPLETIONS:
                raise ValueError(
                    f"{component.value}_endpoint_family must be chat_completions in v0.3.4"
                )
            return
        if endpoint_family != EndpointFamily.EMBEDDINGS:
            raise ValueError("embeddings_endpoint_family must be embeddings in v0.3.4")
