"""Structured plan-step handler implementations."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, cast

from shisad.core.types import SessionId
from shisad.daemon.handlers._mixin_typing import HandlerMixinBase
from shisad.daemon.handlers._string_utils import optional_string


class PlanStepsImplMixin(HandlerMixinBase):
    async def do_plan_steps(self, params: Mapping[str, Any]) -> dict[str, Any]:
        session_id = optional_string(params.get("session_id", ""))
        limit = int(params.get("limit", 20))
        steps = self._plan_steps.list_steps(
            session_id=SessionId(session_id) if session_id else None,
            limit=limit,
            active_only=True,
        )
        return cast(
            dict[str, Any],
            {
                "session_id": session_id,
                "steps": steps,
                "count": len(steps),
            },
        )
