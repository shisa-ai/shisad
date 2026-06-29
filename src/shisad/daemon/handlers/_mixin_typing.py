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

        def _terminate_session(self, session_id: Any, *, reason: str = "") -> bool: ...

        def __getattr__(self, name: str) -> Any: ...

else:

    class HandlerMixinBase:
        """Runtime no-op base class for handler mixins."""

        async def _call_control_plane(self, method_name: str, /, *args: Any, **kwargs: Any) -> Any:
            return await call_control_plane(self, method_name, *args, **kwargs)

        def _terminate_session(self, session_id: Any, *, reason: str = "") -> bool:
            terminated = bool(self._session_manager.terminate(session_id, reason=reason))
            if terminated:
                plan_steps = getattr(self, "_plan_steps", None)
                if plan_steps is not None:
                    plan_steps.clear_session(session_id=session_id)
            return terminated
