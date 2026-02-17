"""Type-only helpers for handler mixins."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:

    class HandlerMixinBase:
        """Allow extracted mixins to access HandlerImplementation attributes."""

        def __getattr__(self, name: str) -> Any: ...

else:

    class HandlerMixinBase:
        """Runtime no-op base class for handler mixins."""

        pass
