"""Shared interface protocols across daemon subsystem boundaries."""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable

from pydantic import BaseModel

from shisad.core.providers.base import EmbeddingResponse
from shisad.core.request_context import RequestContext


@runtime_checkable
class TypedHandler(Protocol):
    """Typed JSON-RPC handler signature used by transport/facade wiring."""

    async def __call__(self, params: BaseModel, ctx: RequestContext) -> BaseModel | dict[str, Any]:
        """Handle validated params with request context."""


type TypedMethodRegistration = tuple[TypedHandler, bool, type[BaseModel] | None]


@runtime_checkable
class EmbeddingsProvider(Protocol):
    """Async embeddings provider consumed by sync adapter bridges."""

    async def embeddings(
        self,
        input_texts: list[str],
        *,
        model_id: str | None = None,
    ) -> EmbeddingResponse:
        """Return embeddings vectors for one or more input texts."""
