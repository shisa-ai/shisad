"""Typed task handler group."""

from __future__ import annotations

from shisad.core.api.schema import (
    NoParams,
    TaskCreateParams,
    TaskCreateResult,
    TaskDisableParams,
    TaskDisableResult,
    TaskListResult,
    TaskPendingConfirmationsParams,
    TaskPendingConfirmationsResult,
    TaskTriggerEventParams,
    TaskTriggerEventResult,
)
from shisad.daemon.context import RequestContext
from shisad.daemon.handlers._helpers import build_params_payload
from shisad.daemon.handlers._impl import HandlerImplementation


class TaskHandlers:
    """Task scheduling and trigger handlers."""

    def __init__(self, impl: HandlerImplementation, *, internal_ingress_marker: object) -> None:
        self._impl = impl
        self._internal_ingress_marker = internal_ingress_marker

    async def handle_task_create(
        self,
        params: TaskCreateParams,
        ctx: RequestContext,
    ) -> TaskCreateResult:
        payload = build_params_payload(
            params,
            ctx,
            internal_ingress_marker=self._internal_ingress_marker,
        )
        return TaskCreateResult.model_validate(await self._impl.do_task_create(payload))

    async def handle_task_list(
        self,
        params: NoParams,
        ctx: RequestContext,
    ) -> TaskListResult:
        _ = params, ctx
        return TaskListResult.model_validate(await self._impl.do_task_list({}))

    async def handle_task_disable(
        self,
        params: TaskDisableParams,
        ctx: RequestContext,
    ) -> TaskDisableResult:
        payload = build_params_payload(
            params,
            ctx,
            internal_ingress_marker=self._internal_ingress_marker,
        )
        return TaskDisableResult.model_validate(await self._impl.do_task_disable(payload))

    async def handle_task_trigger_event(
        self,
        params: TaskTriggerEventParams,
        ctx: RequestContext,
    ) -> TaskTriggerEventResult:
        payload = build_params_payload(
            params,
            ctx,
            internal_ingress_marker=self._internal_ingress_marker,
        )
        return TaskTriggerEventResult.model_validate(
            await self._impl.do_task_trigger_event(payload)
        )

    async def handle_task_pending_confirmations(
        self,
        params: TaskPendingConfirmationsParams,
        ctx: RequestContext,
    ) -> TaskPendingConfirmationsResult:
        payload = build_params_payload(
            params,
            ctx,
            internal_ingress_marker=self._internal_ingress_marker,
        )
        return TaskPendingConfirmationsResult.model_validate(
            await self._impl.do_task_pending_confirmations(payload)
        )
