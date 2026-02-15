"""Typed admin handler group."""

from __future__ import annotations

from shisad.core.api.schema import (
    ChannelIngestParams,
    ChannelIngestResult,
    DaemonShutdownResult,
    DaemonStatusResult,
    DoctorCheckParams,
    DoctorCheckResult,
    LockdownSetParams,
    LockdownSetResult,
    NoParams,
    PolicyExplainParams,
    PolicyExplainResult,
    RiskCalibrateResult,
)
from shisad.daemon.context import RequestContext
from shisad.daemon.handlers._helpers import build_params_payload
from shisad.daemon.handlers._impl import HandlerImplementation


class AdminHandlers:
    """Daemon administration handlers."""

    def __init__(self, impl: HandlerImplementation, *, internal_ingress_marker: object) -> None:
        self._impl = impl
        self._internal_ingress_marker = internal_ingress_marker

    async def handle_daemon_status(
        self,
        params: NoParams,
        ctx: RequestContext,
    ) -> DaemonStatusResult:
        _ = params, ctx
        return DaemonStatusResult.model_validate(await self._impl.do_daemon_status({}))

    async def handle_policy_explain(
        self,
        params: PolicyExplainParams,
        ctx: RequestContext,
    ) -> PolicyExplainResult:
        payload = build_params_payload(
            params,
            ctx,
            internal_ingress_marker=self._internal_ingress_marker,
        )
        return PolicyExplainResult.model_validate(await self._impl.do_policy_explain(payload))

    async def handle_daemon_shutdown(
        self,
        params: NoParams,
        ctx: RequestContext,
    ) -> DaemonShutdownResult:
        _ = params, ctx
        return DaemonShutdownResult.model_validate(await self._impl.do_daemon_shutdown({}))

    async def handle_doctor_check(
        self,
        params: DoctorCheckParams,
        ctx: RequestContext,
    ) -> DoctorCheckResult:
        payload = build_params_payload(
            params,
            ctx,
            internal_ingress_marker=self._internal_ingress_marker,
        )
        return DoctorCheckResult.model_validate(await self._impl.do_doctor_check(payload))

    async def handle_lockdown_set(
        self,
        params: LockdownSetParams,
        ctx: RequestContext,
    ) -> LockdownSetResult:
        payload = build_params_payload(
            params,
            ctx,
            internal_ingress_marker=self._internal_ingress_marker,
        )
        return LockdownSetResult.model_validate(await self._impl.do_lockdown_set(payload))

    async def handle_risk_calibrate(
        self,
        params: NoParams,
        ctx: RequestContext,
    ) -> RiskCalibrateResult:
        _ = params, ctx
        return RiskCalibrateResult.model_validate(await self._impl.do_risk_calibrate({}))

    async def handle_channel_ingest(
        self,
        params: ChannelIngestParams,
        ctx: RequestContext,
    ) -> ChannelIngestResult:
        payload = build_params_payload(
            params,
            ctx,
            internal_ingress_marker=self._internal_ingress_marker,
        )
        return ChannelIngestResult.model_validate(await self._impl.do_channel_ingest(payload))
