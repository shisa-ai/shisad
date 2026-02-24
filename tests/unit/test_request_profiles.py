"""M3 S0 request-parameter profile validation coverage."""

from __future__ import annotations

import pytest

from shisad.core.providers.capabilities import EndpointFamily, RequestParameters
from shisad.core.providers.request_profiles import (
    RequestProfileError,
    apply_request_profile,
)


def test_s0_openai_profile_accepts_reasoning_fields() -> None:
    evaluation = apply_request_profile(
        profile_name="openai_chat_general",
        endpoint_family=EndpointFamily.CHAT_COMPLETIONS,
        model_id="gpt-5.2-2025-12-11",
        request_parameters=RequestParameters(reasoning_effort="high", max_tokens=256),
    )

    assert evaluation.payload["reasoning_effort"] == "high"
    assert evaluation.payload["max_tokens"] == 256
    assert evaluation.rejected_fields == []


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
