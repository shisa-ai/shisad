"""Provider capability and request-parameter models."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


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


class RequestParameters(BaseModel):
    """Allowlisted model request parameters configured per route."""

    temperature: float | None = Field(default=None, ge=0.0, le=2.0)
    max_tokens: int | None = Field(default=None, ge=1, le=65536)
    top_p: float | None = Field(default=None, gt=0.0, le=1.0)
    frequency_penalty: float | None = Field(default=None, ge=-2.0, le=2.0)
    presence_penalty: float | None = Field(default=None, ge=-2.0, le=2.0)

    model_config = ConfigDict(extra="forbid", frozen=True)

    def to_payload(self) -> dict[str, float | int]:
        payload: dict[str, float | int] = {}
        for key, value in self.model_dump(exclude_none=True).items():
            if isinstance(value, bool):
                continue
            if isinstance(value, (int, float)):
                payload[key] = value
        return payload
