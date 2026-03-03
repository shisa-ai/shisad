"""Typed session handler group."""

from __future__ import annotations

from shisad.core.api.schema import (
    NoParams,
    SessionCreateParams,
    SessionCreateResult,
    SessionGrantCapabilitiesParams,
    SessionGrantCapabilitiesResult,
    SessionListResult,
    SessionMessageParams,
    SessionMessageResult,
    SessionRestoreParams,
    SessionRestoreResult,
    SessionRollbackParams,
    SessionRollbackResult,
    SessionSetModeParams,
    SessionSetModeResult,
    SessionTerminateParams,
    SessionTerminateResult,
)
from shisad.daemon.context import RequestContext
from shisad.daemon.handlers._helpers import build_params_payload
from shisad.daemon.handlers._impl import HandlerImplementation


class SessionHandlers:
    """Session API handlers backed by the shared handler facade."""

    def __init__(self, impl: HandlerImplementation, *, internal_ingress_marker: object) -> None:
        self._impl = impl
        self._internal_ingress_marker = internal_ingress_marker

    async def handle_session_create(
        self,
        params: SessionCreateParams,
        ctx: RequestContext,
    ) -> SessionCreateResult:
        payload = build_params_payload(
            params,
            ctx,
            internal_ingress_marker=self._internal_ingress_marker,
        )
        return SessionCreateResult.model_validate(await self._impl.do_session_create(payload))

    async def handle_session_message(
        self,
        params: SessionMessageParams,
        ctx: RequestContext,
    ) -> SessionMessageResult:
        payload = build_params_payload(
            params,
            ctx,
            internal_ingress_marker=self._internal_ingress_marker,
        )
        return SessionMessageResult.model_validate(await self._impl.do_session_message(payload))

    async def handle_session_list(
        self,
        params: NoParams,
        ctx: RequestContext,
    ) -> SessionListResult:
        _ = params, ctx
        return SessionListResult.model_validate(await self._impl.do_session_list({}))

    async def handle_session_restore(
        self,
        params: SessionRestoreParams,
        ctx: RequestContext,
    ) -> SessionRestoreResult:
        payload = build_params_payload(
            params,
            ctx,
            internal_ingress_marker=self._internal_ingress_marker,
        )
        return SessionRestoreResult.model_validate(await self._impl.do_session_restore(payload))

    async def handle_session_rollback(
        self,
        params: SessionRollbackParams,
        ctx: RequestContext,
    ) -> SessionRollbackResult:
        payload = build_params_payload(
            params,
            ctx,
            internal_ingress_marker=self._internal_ingress_marker,
        )
        return SessionRollbackResult.model_validate(await self._impl.do_session_rollback(payload))

    async def handle_session_grant_capabilities(
        self,
        params: SessionGrantCapabilitiesParams,
        ctx: RequestContext,
    ) -> SessionGrantCapabilitiesResult:
        payload = build_params_payload(
            params,
            ctx,
            internal_ingress_marker=self._internal_ingress_marker,
        )
        return SessionGrantCapabilitiesResult.model_validate(
            await self._impl.do_session_grant_capabilities(payload)
        )

    async def handle_session_set_mode(
        self,
        params: SessionSetModeParams,
        ctx: RequestContext,
    ) -> SessionSetModeResult:
        payload = build_params_payload(
            params,
            ctx,
            internal_ingress_marker=self._internal_ingress_marker,
        )
        return SessionSetModeResult.model_validate(await self._impl.do_session_set_mode(payload))

    async def handle_session_terminate(
        self,
        params: SessionTerminateParams,
        ctx: RequestContext,
    ) -> SessionTerminateResult:
        payload = build_params_payload(
            params,
            ctx,
            internal_ingress_marker=self._internal_ingress_marker,
        )
        return SessionTerminateResult.model_validate(await self._impl.do_session_terminate(payload))
