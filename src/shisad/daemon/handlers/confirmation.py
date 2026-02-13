"""Typed confirmation/action handler group."""

from __future__ import annotations

from shisad.core.api.schema import (
    ActionConfirmResult,
    ActionDecisionParams,
    ActionPendingParams,
    ActionPendingResult,
    ActionRejectResult,
    ConfirmationMetricsParams,
    ConfirmationMetricsResult,
)
from shisad.daemon.context import RequestContext
from shisad.daemon.handlers._helpers import build_params_payload
from shisad.daemon.handlers._impl import HandlerImplementation


class ConfirmationHandlers:
    """Pending-action and confirmation handlers."""

    def __init__(self, impl: HandlerImplementation, *, internal_ingress_marker: object) -> None:
        self._impl = impl
        self._internal_ingress_marker = internal_ingress_marker

    async def handle_action_pending(
        self,
        params: ActionPendingParams,
        ctx: RequestContext,
    ) -> ActionPendingResult:
        payload = build_params_payload(
            params,
            ctx,
            internal_ingress_marker=self._internal_ingress_marker,
        )
        return ActionPendingResult.model_validate(await self._impl.do_action_pending(payload))

    async def handle_action_confirm(
        self,
        params: ActionDecisionParams,
        ctx: RequestContext,
    ) -> ActionConfirmResult:
        payload = build_params_payload(
            params,
            ctx,
            internal_ingress_marker=self._internal_ingress_marker,
        )
        return ActionConfirmResult.model_validate(await self._impl.do_action_confirm(payload))

    async def handle_action_reject(
        self,
        params: ActionDecisionParams,
        ctx: RequestContext,
    ) -> ActionRejectResult:
        payload = build_params_payload(
            params,
            ctx,
            internal_ingress_marker=self._internal_ingress_marker,
        )
        return ActionRejectResult.model_validate(await self._impl.do_action_reject(payload))

    async def handle_confirmation_metrics(
        self,
        params: ConfirmationMetricsParams,
        ctx: RequestContext,
    ) -> ConfirmationMetricsResult:
        payload = build_params_payload(
            params,
            ctx,
            internal_ingress_marker=self._internal_ingress_marker,
        )
        return ConfirmationMetricsResult.model_validate(
            await self._impl.do_confirmation_metrics(payload)
        )
