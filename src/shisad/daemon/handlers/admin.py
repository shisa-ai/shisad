"""Typed admin handler group."""

from __future__ import annotations

import asyncio

from shisad.channels.base import direct_replay_identity
from shisad.core.api.schema import (
    AdminSelfModApplyParams,
    AdminSelfModApplyResult,
    AdminSelfModProposeParams,
    AdminSelfModProposeResult,
    AdminSelfModRollbackParams,
    AdminSelfModRollbackResult,
    AdminSoulReadParams,
    AdminSoulReadResult,
    AdminSoulUpdateParams,
    AdminSoulUpdateResult,
    ChannelIngestParams,
    ChannelIngestResult,
    ChannelPairingProposalParams,
    ChannelPairingProposalResult,
    ChannelReplayRebaselineParams,
    ChannelReplayRebaselineResult,
    DaemonResetResult,
    DaemonShutdownResult,
    DaemonStatusResult,
    DevCloseParams,
    DevCloseResult,
    DevImplementParams,
    DevImplementResult,
    DevRemediateParams,
    DevRemediateResult,
    DevReviewParams,
    DevReviewResult,
    DoctorCheckParams,
    DoctorCheckResult,
    LockdownSetParams,
    LockdownSetResult,
    LockdownStatusParams,
    LockdownStatusResult,
    NoParams,
    PolicyExplainParams,
    PolicyExplainResult,
    RiskCalibrateResult,
)
from shisad.core.atomic_state import StatePersistenceDegradedError
from shisad.core.errors import ChannelError
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

    async def handle_daemon_reset(
        self,
        params: NoParams,
        ctx: RequestContext,
    ) -> DaemonResetResult:
        _ = params, ctx
        return DaemonResetResult.model_validate(await self._impl.do_daemon_reset({}))

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

    async def handle_lockdown_status(
        self,
        params: LockdownStatusParams,
        ctx: RequestContext,
    ) -> LockdownStatusResult:
        payload = build_params_payload(
            params,
            ctx,
            internal_ingress_marker=self._internal_ingress_marker,
        )
        return LockdownStatusResult.model_validate(await self._impl.do_lockdown_status(payload))

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
        if ctx.is_internal_ingress:
            return ChannelIngestResult.model_validate(await self._impl.do_channel_ingest(payload))

        services = getattr(self._impl, "_services", None)
        state_store = getattr(services, "channel_state_store", None)
        if state_store is None:
            raise StatePersistenceDegradedError(
                authority="channel_replay:direct",
                transition="reserve",
                stage="runtime",
                reason="replay_state_store_unavailable",
            )

        identity = direct_replay_identity(
            message_id=params.message.message_id,
            rpc_peer=ctx.rpc_peer,
        )
        is_replay = await asyncio.to_thread(state_store.reserve, identity=identity)
        if is_replay:
            raise ChannelError(
                "Channel ingress replay rejected",
                reason_code="channel.ingress_replay",
                rpc_code=-32602,
                expose_message=True,
            )
        try:
            result = ChannelIngestResult.model_validate(
                await self._impl.do_channel_ingest(payload)
            )
        except Exception:
            await asyncio.to_thread(state_store.mark_uncertain, identity=identity)
            raise
        await asyncio.to_thread(state_store.mark_terminal, identity=identity)
        return result

    async def handle_channel_pairing_propose(
        self,
        params: ChannelPairingProposalParams,
        ctx: RequestContext,
    ) -> ChannelPairingProposalResult:
        payload = build_params_payload(
            params,
            ctx,
            internal_ingress_marker=self._internal_ingress_marker,
        )
        return ChannelPairingProposalResult.model_validate(
            await self._impl.do_channel_pairing_propose(payload)
        )

    async def handle_channel_replay_rebaseline(
        self,
        params: ChannelReplayRebaselineParams,
        ctx: RequestContext,
    ) -> ChannelReplayRebaselineResult:
        _ = ctx
        if not params.confirm:
            raise ValueError("channel replay rebaseline requires confirm=true")
        services = getattr(self._impl, "_services", None)
        state_store = getattr(services, "channel_state_store", None)
        if state_store is None:
            raise StatePersistenceDegradedError(
                authority=f"channel_replay:{params.channel}",
                transition="rebaseline",
                stage="runtime",
                reason="replay_state_store_unavailable",
            )
        files_removed = await asyncio.to_thread(state_store.rebaseline, params.channel)
        return ChannelReplayRebaselineResult(
            status="rebaselined",
            channel=params.channel,
            files_removed=files_removed,
        )

    async def handle_admin_selfmod_propose(
        self,
        params: AdminSelfModProposeParams,
        ctx: RequestContext,
    ) -> AdminSelfModProposeResult:
        payload = build_params_payload(
            params,
            ctx,
            internal_ingress_marker=self._internal_ingress_marker,
        )
        return AdminSelfModProposeResult.model_validate(
            await self._impl.do_admin_selfmod_propose(payload)
        )

    async def handle_admin_selfmod_apply(
        self,
        params: AdminSelfModApplyParams,
        ctx: RequestContext,
    ) -> AdminSelfModApplyResult:
        payload = build_params_payload(
            params,
            ctx,
            internal_ingress_marker=self._internal_ingress_marker,
        )
        return AdminSelfModApplyResult.model_validate(
            await self._impl.do_admin_selfmod_apply(payload)
        )

    async def handle_admin_selfmod_rollback(
        self,
        params: AdminSelfModRollbackParams,
        ctx: RequestContext,
    ) -> AdminSelfModRollbackResult:
        payload = build_params_payload(
            params,
            ctx,
            internal_ingress_marker=self._internal_ingress_marker,
        )
        return AdminSelfModRollbackResult.model_validate(
            await self._impl.do_admin_selfmod_rollback(payload)
        )

    async def handle_admin_soul_read(
        self,
        params: AdminSoulReadParams,
        ctx: RequestContext,
    ) -> AdminSoulReadResult:
        payload = build_params_payload(
            params,
            ctx,
            internal_ingress_marker=self._internal_ingress_marker,
        )
        return AdminSoulReadResult.model_validate(await self._impl.do_admin_soul_read(payload))

    async def handle_admin_soul_update(
        self,
        params: AdminSoulUpdateParams,
        ctx: RequestContext,
    ) -> AdminSoulUpdateResult:
        payload = build_params_payload(
            params,
            ctx,
            internal_ingress_marker=self._internal_ingress_marker,
        )
        return AdminSoulUpdateResult.model_validate(await self._impl.do_admin_soul_update(payload))

    async def handle_dev_implement(
        self,
        params: DevImplementParams,
        ctx: RequestContext,
    ) -> DevImplementResult:
        payload = build_params_payload(
            params,
            ctx,
            internal_ingress_marker=self._internal_ingress_marker,
        )
        return DevImplementResult.model_validate(await self._impl.do_dev_implement(payload))

    async def handle_dev_review(
        self,
        params: DevReviewParams,
        ctx: RequestContext,
    ) -> DevReviewResult:
        payload = build_params_payload(
            params,
            ctx,
            internal_ingress_marker=self._internal_ingress_marker,
        )
        return DevReviewResult.model_validate(await self._impl.do_dev_review(payload))

    async def handle_dev_remediate(
        self,
        params: DevRemediateParams,
        ctx: RequestContext,
    ) -> DevRemediateResult:
        payload = build_params_payload(
            params,
            ctx,
            internal_ingress_marker=self._internal_ingress_marker,
        )
        return DevRemediateResult.model_validate(await self._impl.do_dev_remediate(payload))

    async def handle_dev_close(
        self,
        params: DevCloseParams,
        ctx: RequestContext,
    ) -> DevCloseResult:
        payload = build_params_payload(
            params,
            ctx,
            internal_ingress_marker=self._internal_ingress_marker,
        )
        return DevCloseResult.model_validate(await self._impl.do_dev_close(payload))
