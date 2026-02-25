"""Request-parameter profiles for provider/model routing."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

from shisad.core.providers.capabilities import EndpointFamily, RequestParameters

PROFILE_OPENAI_CHAT_GENERAL = "openai_chat_general"
PROFILE_OPENROUTER_CHAT = "openrouter_chat"
PROFILE_GOOGLE_OPENAI_CHAT = "google_openai_chat"
PROFILE_VLLM_CHAT = "vllm_chat"

_PROFILE_ALLOWED_FIELDS: dict[str, set[str]] = {
    PROFILE_OPENAI_CHAT_GENERAL: {
        "temperature",
        "max_tokens",
        "max_completion_tokens",
        "top_p",
        "frequency_penalty",
        "presence_penalty",
        "reasoning_effort",
        "reasoning",
    },
    PROFILE_OPENROUTER_CHAT: {
        "temperature",
        "max_tokens",
        "top_p",
        "frequency_penalty",
        "presence_penalty",
        "reasoning_effort",
        "reasoning",
    },
    PROFILE_GOOGLE_OPENAI_CHAT: {
        "temperature",
        "max_tokens",
        "top_p",
        "frequency_penalty",
        "presence_penalty",
        "reasoning_effort",
    },
    PROFILE_VLLM_CHAT: {
        "temperature",
        "max_tokens",
        "top_p",
        "frequency_penalty",
        "presence_penalty",
    },
}


class RequestProfileError(ValueError):
    """Raised when request-parameter profile validation fails."""


@dataclass(frozen=True)
class RequestProfileEvaluation:
    payload: dict[str, Any]
    mapped_fields: list[str]
    rejected_fields: list[str]


@dataclass(frozen=True)
class ProfileSelection:
    profile_name: str
    source: str
    reason: str


def apply_request_profile(
    *,
    profile_name: str,
    endpoint_family: EndpointFamily,
    model_id: str,
    request_parameters: RequestParameters,
    supported_parameters: set[str] | None = None,
) -> RequestProfileEvaluation:
    payload = request_parameters.to_payload()
    mapped_fields: list[str] = []

    if endpoint_family == EndpointFamily.EMBEDDINGS:
        if payload:
            raise RequestProfileError(
                "embeddings endpoint does not accept chat request parameters"
            )
        return RequestProfileEvaluation(payload={}, mapped_fields=[], rejected_fields=[])

    allowed = _PROFILE_ALLOWED_FIELDS.get(profile_name)
    if allowed is None:
        raise RequestProfileError(f"unknown request-parameter profile: {profile_name}")

    for key in payload:
        if key not in allowed:
            raise RequestProfileError(
                f"field '{key}' is not allowed for profile '{profile_name}'"
            )

    if profile_name == PROFILE_OPENAI_CHAT_GENERAL and "max_tokens" in payload:
        legacy_max_tokens = payload["max_tokens"]
        explicit_max_completion_tokens = payload.get("max_completion_tokens")
        if (
            explicit_max_completion_tokens is not None
            and explicit_max_completion_tokens != legacy_max_tokens
        ):
            raise RequestProfileError(
                "fields 'max_tokens' and 'max_completion_tokens' conflict for "
                "openai_chat_general"
            )
        payload["max_completion_tokens"] = (
            explicit_max_completion_tokens
            if explicit_max_completion_tokens is not None
            else legacy_max_tokens
        )
        payload.pop("max_tokens", None)
        mapped_fields.append("max_tokens->max_completion_tokens")

    if profile_name == PROFILE_GOOGLE_OPENAI_CHAT:
        effort = payload.get("reasoning_effort")
        if effort is not None and str(effort) not in {"low", "medium", "high"}:
            raise RequestProfileError(
                "field 'reasoning_effort' is incompatible with google_openai_chat"
            )

    if profile_name == PROFILE_VLLM_CHAT and "reasoning" in payload:
        raise RequestProfileError("field 'reasoning' is incompatible with vllm_chat")

    if supported_parameters is not None:
        for key in payload:
            if key not in supported_parameters:
                raise RequestProfileError(
                    f"field '{key}' rejected by provider metadata narrowing"
                )

    _ = model_id
    return RequestProfileEvaluation(
        payload=dict(payload),
        mapped_fields=mapped_fields,
        rejected_fields=[],
    )


def auto_select_request_profile(
    *,
    explicit_profile: str | None,
    preset_default_profile: str | None,
    base_url: str,
    endpoint_family: EndpointFamily,
    model_id: str,
) -> ProfileSelection:
    if explicit_profile:
        return ProfileSelection(
            profile_name=explicit_profile,
            source="route_override",
            reason="explicit route profile",
        )
    if preset_default_profile:
        return ProfileSelection(
            profile_name=preset_default_profile,
            source="preset_default",
            reason="preset default profile",
        )

    hostname = (urlparse(base_url).hostname or "").lower()
    if endpoint_family == EndpointFamily.CHAT_COMPLETIONS:
        if _hostname_matches_domain(hostname, "openrouter.ai"):
            return ProfileSelection(
                profile_name=PROFILE_OPENROUTER_CHAT,
                source="hostname_heuristic",
                reason="openrouter hostname",
            )
        if _hostname_matches_domain(
            hostname, "generativelanguage.googleapis.com"
        ) or _hostname_matches_domain(hostname, "googleapis.com"):
            return ProfileSelection(
                profile_name=PROFILE_GOOGLE_OPENAI_CHAT,
                source="hostname_heuristic",
                reason="google hostname",
            )
        if hostname in {"localhost", "127.0.0.1", "::1"}:
            return ProfileSelection(
                profile_name=PROFILE_VLLM_CHAT,
                source="hostname_heuristic",
                reason="localhost endpoint",
            )
        if hostname in {"api.openai.com", "api.shisa.ai"}:
            return ProfileSelection(
                profile_name=PROFILE_OPENAI_CHAT_GENERAL,
                source="hostname_heuristic",
                reason="openai-compatible hostname",
            )

    model_lower = model_id.lower()
    if model_lower.startswith("gemini-"):
        return ProfileSelection(
            profile_name=PROFILE_GOOGLE_OPENAI_CHAT,
            source="model_id_tiebreaker",
            reason="gemini model prefix",
        )

    return ProfileSelection(
        profile_name=PROFILE_OPENAI_CHAT_GENERAL,
        source="endpoint_family_fallback",
        reason="default openai-compatible fallback",
    )


def _hostname_matches_domain(hostname: str, domain: str) -> bool:
    return hostname == domain or hostname.endswith(f".{domain}")
