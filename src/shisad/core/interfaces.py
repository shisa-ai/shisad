"""Shared interface protocols across daemon subsystem boundaries."""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable

from pydantic import BaseModel

from shisad.core.request_context import RequestContext


@runtime_checkable
class TypedHandler(Protocol):
    """Typed JSON-RPC handler signature used by transport/facade wiring."""

    async def __call__(self, params: BaseModel, ctx: RequestContext) -> BaseModel | dict[str, Any]:
        """Handle validated params with request context."""


type TypedMethodRegistration = tuple[TypedHandler, bool, type[BaseModel] | None]
