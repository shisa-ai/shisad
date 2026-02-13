"""Typed dashboard and audit handler group."""

from __future__ import annotations

from shisad.core.api.schema import (
    AuditQueryParams,
    AuditQueryResult,
    DashboardMarkFalsePositiveParams,
    DashboardMarkFalsePositiveResult,
    DashboardQueryParams,
    DashboardQueryResult,
)
from shisad.daemon.context import RequestContext
from shisad.daemon.handlers._helpers import build_params_payload
from shisad.daemon.handlers._impl import HandlerImplementation


class DashboardHandlers:
    """Audit and dashboard query handlers."""

    def __init__(self, impl: HandlerImplementation, *, internal_ingress_marker: object) -> None:
        self._impl = impl
        self._internal_ingress_marker = internal_ingress_marker

    async def handle_audit_query(
        self,
        params: AuditQueryParams,
        ctx: RequestContext,
    ) -> AuditQueryResult:
        payload = build_params_payload(
            params,
            ctx,
            internal_ingress_marker=self._internal_ingress_marker,
        )
        return AuditQueryResult.model_validate(await self._impl.do_audit_query(payload))

    async def handle_dashboard_audit_explorer(
        self,
        params: DashboardQueryParams,
        ctx: RequestContext,
    ) -> DashboardQueryResult:
        payload = build_params_payload(
            params,
            ctx,
            internal_ingress_marker=self._internal_ingress_marker,
        )
        return DashboardQueryResult.model_validate(
            await self._impl.do_dashboard_audit_explorer(payload)
        )

    async def handle_dashboard_egress_review(
        self,
        params: DashboardQueryParams,
        ctx: RequestContext,
    ) -> DashboardQueryResult:
        payload = build_params_payload(
            params,
            ctx,
            internal_ingress_marker=self._internal_ingress_marker,
        )
        return DashboardQueryResult.model_validate(
            await self._impl.do_dashboard_egress_review(payload)
        )

    async def handle_dashboard_skill_provenance(
        self,
        params: DashboardQueryParams,
        ctx: RequestContext,
    ) -> DashboardQueryResult:
        payload = build_params_payload(
            params,
            ctx,
            internal_ingress_marker=self._internal_ingress_marker,
        )
        return DashboardQueryResult.model_validate(
            await self._impl.do_dashboard_skill_provenance(payload)
        )

    async def handle_dashboard_alerts(
        self,
        params: DashboardQueryParams,
        ctx: RequestContext,
    ) -> DashboardQueryResult:
        payload = build_params_payload(
            params,
            ctx,
            internal_ingress_marker=self._internal_ingress_marker,
        )
        return DashboardQueryResult.model_validate(await self._impl.do_dashboard_alerts(payload))

    async def handle_dashboard_mark_false_positive(
        self,
        params: DashboardMarkFalsePositiveParams,
        ctx: RequestContext,
    ) -> DashboardMarkFalsePositiveResult:
        payload = build_params_payload(
            params,
            ctx,
            internal_ingress_marker=self._internal_ingress_marker,
        )
        return DashboardMarkFalsePositiveResult.model_validate(
            await self._impl.do_dashboard_mark_false_positive(payload)
        )
