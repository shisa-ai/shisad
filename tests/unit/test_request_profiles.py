"""M3 S0 request-parameter profile validation coverage."""

from __future__ import annotations

import pytest

from shisad.core.providers.capabilities import EndpointFamily, RequestParameters
from shisad.core.providers.request_profiles import (
    PROFILE_GOOGLE_OPENAI_CHAT,
    PROFILE_OPENAI_CHAT_GENERAL,
    PROFILE_OPENROUTER_CHAT,
    RequestProfileError,
    apply_request_profile,
    auto_select_request_profile,
)


def test_s0_openai_profile_accepts_reasoning_fields() -> None:
    evaluation = apply_request_profile(
        profile_name="openai_chat_general",
        endpoint_family=EndpointFamily.CHAT_COMPLETIONS,
        model_id="gpt-5.2-2025-12-11",
        request_parameters=RequestParameters(reasoning_effort="high", max_tokens=256),
    )

    assert evaluation.payload["reasoning_effort"] == "high"
    assert evaluation.payload["max_completion_tokens"] == 256
    assert "max_tokens" not in evaluation.payload
    assert evaluation.mapped_fields == ["max_tokens->max_completion_tokens"]
    assert evaluation.rejected_fields == []


def test_s0_openai_profile_rejects_conflicting_max_token_fields() -> None:
    with pytest.raises(RequestProfileError, match=r"max_tokens.*max_completion_tokens"):
        apply_request_profile(
            profile_name="openai_chat_general",
            endpoint_family=EndpointFamily.CHAT_COMPLETIONS,
            model_id="gpt-5.2-2025-12-11",
            request_parameters=RequestParameters(
                max_tokens=256,
                max_completion_tokens=128,
            ),
        )


def test_s0_google_profile_rejects_unsupported_reasoning_effort() -> None:
    with pytest.raises(RequestProfileError, match="reasoning_effort"):
        apply_request_profile(
            profile_name="google_openai_chat",
            endpoint_family=EndpointFamily.CHAT_COMPLETIONS,
            model_id="gemini-3.1-pro-preview",
            request_parameters=RequestParameters(reasoning_effort="minimal"),
        )


def test_s0_vllm_profile_rejects_structured_reasoning_block() -> None:
    with pytest.raises(RequestProfileError, match="reasoning"):
        apply_request_profile(
            profile_name="vllm_chat",
            endpoint_family=EndpointFamily.CHAT_COMPLETIONS,
            model_id="qwen-2.5",
            request_parameters=RequestParameters(reasoning={"budget_tokens": 64}),
        )


def test_s0_embeddings_endpoint_rejects_chat_parameters() -> None:
    with pytest.raises(RequestProfileError, match="embeddings"):
        apply_request_profile(
            profile_name="openai_chat_general",
            endpoint_family=EndpointFamily.EMBEDDINGS,
            model_id="text-embedding-3-small",
            request_parameters=RequestParameters(temperature=0.2),
        )


def test_s0_profile_heuristic_matches_openrouter_boundary_safely() -> None:
    exact = auto_select_request_profile(
        explicit_profile=None,
        preset_default_profile=None,
        base_url="https://openrouter.ai/api/v1",
        endpoint_family=EndpointFamily.CHAT_COMPLETIONS,
        model_id="qwen",
    )
    attacker = auto_select_request_profile(
        explicit_profile=None,
        preset_default_profile=None,
        base_url="https://evil-openrouter.ai.attacker.com/v1",
        endpoint_family=EndpointFamily.CHAT_COMPLETIONS,
        model_id="qwen",
    )

    assert exact.profile_name == PROFILE_OPENROUTER_CHAT
    assert exact.source == "hostname_heuristic"
    assert attacker.profile_name == PROFILE_OPENAI_CHAT_GENERAL
    assert attacker.source == "endpoint_family_fallback"


def test_s0_profile_heuristic_matches_google_boundary_safely() -> None:
    exact = auto_select_request_profile(
        explicit_profile=None,
        preset_default_profile=None,
        base_url="https://generativelanguage.googleapis.com/v1beta/openai",
        endpoint_family=EndpointFamily.CHAT_COMPLETIONS,
        model_id="gemini-3.1-pro-preview",
    )
    attacker = auto_select_request_profile(
        explicit_profile=None,
        preset_default_profile=None,
        base_url="https://notrealgenerativelanguage.googleapis.com.evil.com/v1",
        endpoint_family=EndpointFamily.CHAT_COMPLETIONS,
        model_id="gemini-3.1-pro-preview",
    )
    attacker_non_gemini = auto_select_request_profile(
        explicit_profile=None,
        preset_default_profile=None,
        base_url="https://notrealgenerativelanguage.googleapis.com.evil.com/v1",
        endpoint_family=EndpointFamily.CHAT_COMPLETIONS,
        model_id="llama-3",
    )

    assert exact.profile_name == PROFILE_GOOGLE_OPENAI_CHAT
    assert exact.source == "hostname_heuristic"
    assert attacker.profile_name == PROFILE_GOOGLE_OPENAI_CHAT
    assert attacker.source == "model_id_tiebreaker"
    assert attacker_non_gemini.profile_name == PROFILE_OPENAI_CHAT_GENERAL
    assert attacker_non_gemini.source == "endpoint_family_fallback"
