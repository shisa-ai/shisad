"""Model provider abstraction.

Defines the ModelProvider protocol and an OpenAI-compatible implementation.
Includes endpoint validation (HTTPS required, SSRF protection) and
configurable prompt logging policy.
"""

from __future__ import annotations

import hashlib
import ipaddress
import logging
from typing import Any, Protocol
from urllib.parse import urlparse

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


# --- Provider protocol ---


class Message(BaseModel):
    """A single message in a conversation."""

    role: str  # "system", "user", "assistant", "tool"
    content: str = ""
    tool_calls: list[dict[str, Any]] = Field(default_factory=list)
    tool_call_id: str | None = None


class ProviderResponse(BaseModel):
    """Response from a model provider."""

    message: Message
    finish_reason: str = ""
    usage: dict[str, int] = Field(default_factory=dict)


class EmbeddingResponse(BaseModel):
    """Response for embeddings endpoints."""

    vectors: list[list[float]] = Field(default_factory=list)
    model: str = ""
    usage: dict[str, int] = Field(default_factory=dict)


class ModelProvider(Protocol):
    """Protocol for model providers.

    All providers must implement this interface. The actual HTTP call
    goes through the credential broker's egress proxy in production.
    """

    async def complete(
        self,
        messages: list[Message],
        tools: list[dict[str, Any]] | None = None,
    ) -> ProviderResponse: ...

    async def embeddings(
        self,
        input_texts: list[str],
        *,
        model_id: str | None = None,
    ) -> EmbeddingResponse: ...


# --- Endpoint validation ---


# RFC 1918 + loopback + link-local ranges
_PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]


def validate_endpoint(
    url: str,
    *,
    allow_http_localhost: bool = True,
    block_private_ranges: bool = True,
) -> list[str]:
    """Validate a model endpoint URL for security.

    Returns a list of validation errors (empty = valid).
    """
    errors: list[str] = []

    parsed = urlparse(url)

    # Scheme check
    if parsed.scheme not in ("http", "https"):
        errors.append(f"Unsupported scheme: {parsed.scheme} (must be http or https)")
        return errors

    hostname = parsed.hostname or ""

    # HTTPS required for non-localhost
    if parsed.scheme == "http":
        is_localhost = hostname in ("localhost", "127.0.0.1", "::1")
        if not is_localhost or not allow_http_localhost:
            errors.append(f"HTTP not allowed for non-localhost endpoint: {hostname}")

    # Private range check (SSRF protection)
    if block_private_ranges and hostname not in ("localhost",):
        try:
            addr = ipaddress.ip_address(hostname)
            for network in _PRIVATE_NETWORKS:
                if addr in network:
                    errors.append(f"Endpoint in private range: {hostname} ({network})")
                    break
        except ValueError:
            pass  # Not an IP literal, hostname will be resolved later

    return errors


# --- Prompt logging ---


def log_prompt_metadata(
    messages: list[Message],
    response: ProviderResponse,
    *,
    log_full: bool = False,
) -> dict[str, Any]:
    """Generate prompt metadata for audit logging.

    Default: log only hashes and metadata (no raw prompts).
    Debug mode: log full prompts (opt-in, never log credentials).
    """
    metadata: dict[str, Any] = {
        "message_count": len(messages),
        "roles": [m.role for m in messages],
        "finish_reason": response.finish_reason,
        "usage": response.usage,
    }

    if log_full:
        # Even in debug mode, we log content hashes rather than raw text
        # to avoid accidentally logging credentials
        metadata["message_hashes"] = [
            hashlib.sha256(m.content.encode()).hexdigest()[:16] for m in messages
        ]
        metadata["response_hash"] = hashlib.sha256(
            response.message.content.encode()
        ).hexdigest()[:16]

    return metadata
