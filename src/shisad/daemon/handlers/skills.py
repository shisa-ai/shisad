"""Typed skill handler group."""

from __future__ import annotations

from shisad.core.api.schema import (
    NoParams,
    SkillInstallParams,
    SkillInstallResult,
    SkillListResult,
    SkillProfileParams,
    SkillProfileResult,
    SkillReviewParams,
    SkillReviewResult,
    SkillRevokeParams,
    SkillRevokeResult,
)
from shisad.daemon.context import RequestContext
from shisad.daemon.handlers._helpers import build_params_payload
from shisad.daemon.handlers._impl import HandlerImplementation


class SkillHandlers:
    """Skill lifecycle handlers."""

    def __init__(self, impl: HandlerImplementation, *, internal_ingress_marker: object) -> None:
        self._impl = impl
        self._internal_ingress_marker = internal_ingress_marker

    async def handle_skill_list(
        self,
        params: NoParams,
        ctx: RequestContext,
    ) -> SkillListResult:
        _ = params, ctx
        return SkillListResult.model_validate(await self._impl.do_skill_list({}))

    async def handle_skill_review(
        self,
        params: SkillReviewParams,
        ctx: RequestContext,
    ) -> SkillReviewResult:
        payload = build_params_payload(
            params,
            ctx,
            internal_ingress_marker=self._internal_ingress_marker,
        )
        return SkillReviewResult.model_validate(await self._impl.do_skill_review(payload))

    async def handle_skill_install(
        self,
        params: SkillInstallParams,
        ctx: RequestContext,
    ) -> SkillInstallResult:
        payload = build_params_payload(
            params,
            ctx,
            internal_ingress_marker=self._internal_ingress_marker,
        )
        return SkillInstallResult.model_validate(await self._impl.do_skill_install(payload))

    async def handle_skill_profile(
        self,
        params: SkillProfileParams,
        ctx: RequestContext,
    ) -> SkillProfileResult:
        payload = build_params_payload(
            params,
            ctx,
            internal_ingress_marker=self._internal_ingress_marker,
        )
        return SkillProfileResult.model_validate(await self._impl.do_skill_profile(payload))

    async def handle_skill_revoke(
        self,
        params: SkillRevokeParams,
        ctx: RequestContext,
    ) -> SkillRevokeResult:
        payload = build_params_payload(
            params,
            ctx,
            internal_ingress_marker=self._internal_ingress_marker,
        )
        return SkillRevokeResult.model_validate(await self._impl.do_skill_revoke(payload))
