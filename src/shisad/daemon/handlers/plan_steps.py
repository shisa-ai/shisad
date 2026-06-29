"""Typed plan-step handler group."""

from __future__ import annotations

from shisad.core.api.schema import PlanStepsParams, PlanStepsResult
from shisad.daemon.context import RequestContext
from shisad.daemon.handlers._helpers import build_params_payload
from shisad.daemon.handlers._impl import HandlerImplementation


class PlanHandlers:
    """Read structured work-breakdown plan steps."""

    def __init__(self, impl: HandlerImplementation, *, internal_ingress_marker: object) -> None:
        self._impl = impl
        self._internal_ingress_marker = internal_ingress_marker

    async def handle_plan_steps(
        self,
        params: PlanStepsParams,
        ctx: RequestContext,
    ) -> PlanStepsResult:
        payload = build_params_payload(
            params,
            ctx,
            internal_ingress_marker=self._internal_ingress_marker,
        )
        return PlanStepsResult.model_validate(await self._impl.do_plan_steps(payload))
