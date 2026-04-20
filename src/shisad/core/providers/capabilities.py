"""Provider capability and request-parameter models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class AuthMode(StrEnum):
    """Route-level auth mode for provider requests."""

    BEARER = "bearer"
    HEADER = "header"
    NONE = "none"


class EndpointFamily(StrEnum):
    """Supported OpenAI-compatible endpoint families in v0.3.4."""

    CHAT_COMPLETIONS = "chat_completions"
    EMBEDDINGS = "embeddings"


class ProviderPreset(StrEnum):
    """Route-level provider preset names."""

    SHISA_DEFAULT = "shisa_default"
    OPENAI_DEFAULT = "openai_default"
    OPENROUTER_DEFAULT = "openrouter_default"
    GOOGLE_OPENAI_DEFAULT = "google_openai_default"
    ANTHROPIC_DEFAULT = "anthropic_default"
    VLLM_LOCAL_DEFAULT = "vllm_local_default"


class ProviderCapabilities(BaseModel):
    """Static capability declarations for a routed model provider."""

    supports_tool_calls: bool = Field(
        default=True,
        description="Provider supports native OpenAI-style `tool_calls` messages.",
    )
    supports_content_tool_calls: bool = Field(
        default=False,
        description="Provider emits tool calls in message content (e.g. Hermes tags).",
    )
    supports_structured_output: bool = Field(
        default=False,
        description="Provider supports response-format JSON schema style structured output.",
    )

    model_config = ConfigDict(frozen=True)


class ReasoningParameters(BaseModel):
    """Structured reasoning controls for compatible profiles/providers."""

    budget_tokens: int | None = Field(default=None, ge=1, le=65536)
    mode: str | None = Field(default=None, min_length=1, max_length=64)

    model_config = ConfigDict(extra="forbid", frozen=True)


class RequestParameters(BaseModel):
    """Allowlisted model request parameters configured per route."""

    temperature: float | None = Field(default=None, ge=0.0, le=2.0)
    max_tokens: int | None = Field(default=None, ge=1, le=65536)
    max_completion_tokens: int | None = Field(default=None, ge=1, le=65536)
    top_p: float | None = Field(default=None, gt=0.0, le=1.0)
    frequency_penalty: float | None = Field(default=None, ge=-2.0, le=2.0)
    presence_penalty: float | None = Field(default=None, ge=-2.0, le=2.0)
    reasoning_effort: str | None = Field(default=None, min_length=1, max_length=32)
    reasoning: ReasoningParameters | None = Field(default=None)

    model_config = ConfigDict(extra="forbid", frozen=True)

    def to_payload(self) -> dict[str, Any]:
        payload: dict[str, Any] = {}
        for key, value in self.model_dump(exclude_none=True).items():
            if isinstance(value, bool):
                # Forward-compatible branch for potential future boolean request fields.
                payload[key] = value
                continue
            if isinstance(value, (int, float)):
                payload[key] = value
                continue
            if isinstance(value, str):
                payload[key] = value
                continue
            if isinstance(value, dict):
                payload[key] = value
        return payload
