"""Type-only helpers for handler mixins."""

from __future__ import annotations

import inspect
from typing import TYPE_CHECKING, Any


async def call_control_plane(handler: Any, method_name: str, /, *args: Any, **kwargs: Any) -> Any:
    target = getattr(handler._control_plane, method_name)
    result = target(*args, **kwargs)
    if inspect.isawaitable(result):
        return await result
    return result


if TYPE_CHECKING:

    class HandlerMixinBase:
        """Allow extracted mixins to access HandlerImplementation attributes."""

        async def _call_control_plane(
            self, method_name: str, /, *args: Any, **kwargs: Any
        ) -> Any: ...

        def __getattr__(self, name: str) -> Any: ...

else:

    class HandlerMixinBase:
        """Runtime no-op base class for handler mixins."""

        async def _call_control_plane(self, method_name: str, /, *args: Any, **kwargs: Any) -> Any:
            return await call_control_plane(self, method_name, *args, **kwargs)
