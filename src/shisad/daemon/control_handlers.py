"""Control API facade that delegates to typed handler modules."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

from shisad.channels.identity import ChannelIdentityMap
from shisad.channels.ingress import ChannelIngressProcessor
from shisad.channels.matrix import MatrixChannel
from shisad.core.api.schema import (
    ActionConfirmResult,
    ActionDecisionParams,
    ActionPendingParams,
    ActionPendingResult,
    ActionRejectResult,
    AuditQueryParams,
    AuditQueryResult,
    BrowserPasteParams,
    BrowserScreenshotParams,
    ChannelIngestParams,
    ChannelIngestResult,
    ConfirmationMetricsParams,
    ConfirmationMetricsResult,
    DaemonShutdownResult,
    DaemonStatusResult,
    DashboardMarkFalsePositiveParams,
    DashboardMarkFalsePositiveResult,
    DashboardQueryParams,
    DashboardQueryResult,
    LockdownSetParams,
    LockdownSetResult,
    MemoryDeleteResult,
    MemoryEntryParams,
    MemoryExportParams,
    MemoryExportResult,
    MemoryGetResult,
    MemoryIngestParams,
    MemoryIngestResult,
    MemoryListParams,
    MemoryListResult,
    MemoryRetrieveParams,
    MemoryRetrieveResult,
    MemoryRotateKeyParams,
    MemoryRotateKeyResult,
    MemoryVerifyResult,
    MemoryWriteParams,
    MemoryWriteResult,
    NoParams,
    PolicyExplainParams,
    PolicyExplainResult,
    RiskCalibrateResult,
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
    SkillInstallParams,
    SkillInstallResult,
    SkillListResult,
    SkillProfileParams,
    SkillProfileResult,
    SkillReviewParams,
    SkillReviewResult,
    SkillRevokeParams,
    SkillRevokeResult,
    TaskCreateParams,
    TaskCreateResult,
    TaskDisableParams,
    TaskDisableResult,
    TaskListResult,
    TaskPendingConfirmationsParams,
    TaskPendingConfirmationsResult,
    TaskTriggerEventParams,
    TaskTriggerEventResult,
    ToolExecuteParams,
    ToolExecuteResult,
)
from shisad.core.audit import AuditLog
from shisad.core.config import DaemonConfig
from shisad.core.events import EventBus
from shisad.core.planner import Planner
from shisad.core.session import CheckpointStore, SessionManager
from shisad.core.tools.builtin.alarm import AlarmTool
from shisad.core.tools.registry import ToolRegistry
from shisad.core.trace import TraceRecorder
from shisad.core.transcript import TranscriptStore
from shisad.daemon.context import RequestContext
from shisad.daemon.handlers import (
    AdminHandlers,
    ConfirmationHandlers,
    DashboardHandlers,
    MemoryHandlers,
    SessionHandlers,
    SkillHandlers,
    TaskHandlers,
    ToolExecutionHandlers,
)
from shisad.daemon.handlers._impl import HandlerImplementation
from shisad.executors.browser import BrowserPasteResult, BrowserSandbox, BrowserScreenshotResult
from shisad.executors.sandbox import SandboxOrchestrator
from shisad.memory.ingestion import IngestionPipeline
from shisad.memory.manager import MemoryManager
from shisad.scheduler.manager import SchedulerManager
from shisad.security.control_plane.engine import ControlPlaneEngine
from shisad.security.firewall import ContentFirewall
from shisad.security.firewall.output import OutputFirewall
from shisad.security.lockdown import LockdownManager
from shisad.security.monitor import ActionMonitor
from shisad.security.policy import PolicyLoader
from shisad.security.ratelimit import RateLimiter
from shisad.security.risk import RiskCalibrator
from shisad.skills.manager import SkillManager


class DaemonControlHandlers:
    """Thin routing facade over split handler modules."""

    def __init__(
        self,
        *,
        config: DaemonConfig,
        audit_log: AuditLog,
        event_bus: EventBus,
        policy_loader: PolicyLoader,
        planner: Planner,
        registry: ToolRegistry,
        alarm_tool: AlarmTool,
        session_manager: SessionManager,
        transcript_store: TranscriptStore,
        trace_recorder: TraceRecorder | None,
        transcript_root: Path,
        checkpoint_store: CheckpointStore,
        firewall: ContentFirewall,
        output_firewall: OutputFirewall,
        channel_ingress: ChannelIngressProcessor,
        identity_map: ChannelIdentityMap,
        matrix_channel: MatrixChannel | None,
        lockdown_manager: LockdownManager,
        rate_limiter: RateLimiter,
        monitor: ActionMonitor,
        risk_calibrator: RiskCalibrator,
        ingestion: IngestionPipeline,
        memory_manager: MemoryManager,
        scheduler: SchedulerManager,
        skill_manager: SkillManager,
        sandbox: SandboxOrchestrator,
        control_plane: ControlPlaneEngine,
        browser_sandbox: BrowserSandbox,
        shutdown_event: asyncio.Event,
        provenance_status: dict[str, Any],
        model_routes: dict[str, str],
        planner_model_id: str,
        classifier_mode: str,
        internal_ingress_marker: object,
    ) -> None:
        impl = HandlerImplementation(
            config=config,
            audit_log=audit_log,
            event_bus=event_bus,
            policy_loader=policy_loader,
            planner=planner,
            registry=registry,
            alarm_tool=alarm_tool,
            session_manager=session_manager,
            transcript_store=transcript_store,
            trace_recorder=trace_recorder,
            transcript_root=transcript_root,
            checkpoint_store=checkpoint_store,
            firewall=firewall,
            output_firewall=output_firewall,
            channel_ingress=channel_ingress,
            identity_map=identity_map,
            matrix_channel=matrix_channel,
            lockdown_manager=lockdown_manager,
            rate_limiter=rate_limiter,
            monitor=monitor,
            risk_calibrator=risk_calibrator,
            ingestion=ingestion,
            memory_manager=memory_manager,
            scheduler=scheduler,
            skill_manager=skill_manager,
            sandbox=sandbox,
            control_plane=control_plane,
            browser_sandbox=browser_sandbox,
            shutdown_event=shutdown_event,
            provenance_status=provenance_status,
            model_routes=model_routes,
            planner_model_id=planner_model_id,
            classifier_mode=classifier_mode,
            internal_ingress_marker=internal_ingress_marker,
        )
        self._session = SessionHandlers(impl, internal_ingress_marker=internal_ingress_marker)
        self._tool_execution = ToolExecutionHandlers(
            impl, internal_ingress_marker=internal_ingress_marker
        )
        self._confirmation = ConfirmationHandlers(
            impl, internal_ingress_marker=internal_ingress_marker
        )
        self._memory = MemoryHandlers(impl, internal_ingress_marker=internal_ingress_marker)
        self._skills = SkillHandlers(impl, internal_ingress_marker=internal_ingress_marker)
        self._tasks = TaskHandlers(impl, internal_ingress_marker=internal_ingress_marker)
        self._dashboard = DashboardHandlers(impl, internal_ingress_marker=internal_ingress_marker)
        self._admin = AdminHandlers(impl, internal_ingress_marker=internal_ingress_marker)

    async def handle_session_create(
        self, params: SessionCreateParams, ctx: RequestContext
    ) -> SessionCreateResult:
        return await self._session.handle_session_create(params, ctx)

    async def handle_session_message(
        self, params: SessionMessageParams, ctx: RequestContext
    ) -> SessionMessageResult:
        return await self._session.handle_session_message(params, ctx)

    async def handle_session_list(self, params: NoParams, ctx: RequestContext) -> SessionListResult:
        return await self._session.handle_session_list(params, ctx)

    async def handle_session_restore(
        self, params: SessionRestoreParams, ctx: RequestContext
    ) -> SessionRestoreResult:
        return await self._session.handle_session_restore(params, ctx)

    async def handle_session_rollback(
        self, params: SessionRollbackParams, ctx: RequestContext
    ) -> SessionRollbackResult:
        return await self._session.handle_session_rollback(params, ctx)

    async def handle_session_grant_capabilities(
        self, params: SessionGrantCapabilitiesParams, ctx: RequestContext
    ) -> SessionGrantCapabilitiesResult:
        return await self._session.handle_session_grant_capabilities(params, ctx)

    async def handle_daemon_status(
        self, params: NoParams, ctx: RequestContext
    ) -> DaemonStatusResult:
        return await self._admin.handle_daemon_status(params, ctx)

    async def handle_policy_explain(
        self, params: PolicyExplainParams, ctx: RequestContext
    ) -> PolicyExplainResult:
        return await self._admin.handle_policy_explain(params, ctx)

    async def handle_daemon_shutdown(
        self, params: NoParams, ctx: RequestContext
    ) -> DaemonShutdownResult:
        return await self._admin.handle_daemon_shutdown(params, ctx)

    async def handle_audit_query(
        self, params: AuditQueryParams, ctx: RequestContext
    ) -> AuditQueryResult:
        return await self._dashboard.handle_audit_query(params, ctx)

    async def handle_dashboard_audit_explorer(
        self, params: DashboardQueryParams, ctx: RequestContext
    ) -> DashboardQueryResult:
        return await self._dashboard.handle_dashboard_audit_explorer(params, ctx)

    async def handle_dashboard_egress_review(
        self, params: DashboardQueryParams, ctx: RequestContext
    ) -> DashboardQueryResult:
        return await self._dashboard.handle_dashboard_egress_review(params, ctx)

    async def handle_dashboard_skill_provenance(
        self, params: DashboardQueryParams, ctx: RequestContext
    ) -> DashboardQueryResult:
        return await self._dashboard.handle_dashboard_skill_provenance(params, ctx)

    async def handle_dashboard_alerts(
        self, params: DashboardQueryParams, ctx: RequestContext
    ) -> DashboardQueryResult:
        return await self._dashboard.handle_dashboard_alerts(params, ctx)

    async def handle_dashboard_mark_false_positive(
        self,
        params: DashboardMarkFalsePositiveParams,
        ctx: RequestContext,
    ) -> DashboardMarkFalsePositiveResult:
        return await self._dashboard.handle_dashboard_mark_false_positive(params, ctx)

    async def handle_confirmation_metrics(
        self, params: ConfirmationMetricsParams, ctx: RequestContext
    ) -> ConfirmationMetricsResult:
        return await self._confirmation.handle_confirmation_metrics(params, ctx)

    async def handle_memory_ingest(
        self, params: MemoryIngestParams, ctx: RequestContext
    ) -> MemoryIngestResult:
        return await self._memory.handle_memory_ingest(params, ctx)

    async def handle_memory_retrieve(
        self, params: MemoryRetrieveParams, ctx: RequestContext
    ) -> MemoryRetrieveResult:
        return await self._memory.handle_memory_retrieve(params, ctx)

    async def handle_memory_write(
        self, params: MemoryWriteParams, ctx: RequestContext
    ) -> MemoryWriteResult:
        return await self._memory.handle_memory_write(params, ctx)

    async def handle_memory_list(
        self, params: MemoryListParams, ctx: RequestContext
    ) -> MemoryListResult:
        return await self._memory.handle_memory_list(params, ctx)

    async def handle_memory_get(
        self, params: MemoryEntryParams, ctx: RequestContext
    ) -> MemoryGetResult:
        return await self._memory.handle_memory_get(params, ctx)

    async def handle_memory_delete(
        self, params: MemoryEntryParams, ctx: RequestContext
    ) -> MemoryDeleteResult:
        return await self._memory.handle_memory_delete(params, ctx)

    async def handle_memory_export(
        self, params: MemoryExportParams, ctx: RequestContext
    ) -> MemoryExportResult:
        return await self._memory.handle_memory_export(params, ctx)

    async def handle_memory_verify(
        self, params: MemoryEntryParams, ctx: RequestContext
    ) -> MemoryVerifyResult:
        return await self._memory.handle_memory_verify(params, ctx)

    async def handle_memory_rotate_key(
        self, params: MemoryRotateKeyParams, ctx: RequestContext
    ) -> MemoryRotateKeyResult:
        return await self._memory.handle_memory_rotate_key(params, ctx)

    async def handle_skill_list(self, params: NoParams, ctx: RequestContext) -> SkillListResult:
        return await self._skills.handle_skill_list(params, ctx)

    async def handle_skill_review(
        self, params: SkillReviewParams, ctx: RequestContext
    ) -> SkillReviewResult:
        return await self._skills.handle_skill_review(params, ctx)

    async def handle_skill_install(
        self, params: SkillInstallParams, ctx: RequestContext
    ) -> SkillInstallResult:
        return await self._skills.handle_skill_install(params, ctx)

    async def handle_skill_profile(
        self, params: SkillProfileParams, ctx: RequestContext
    ) -> SkillProfileResult:
        return await self._skills.handle_skill_profile(params, ctx)

    async def handle_skill_revoke(
        self, params: SkillRevokeParams, ctx: RequestContext
    ) -> SkillRevokeResult:
        return await self._skills.handle_skill_revoke(params, ctx)

    async def handle_task_create(
        self, params: TaskCreateParams, ctx: RequestContext
    ) -> TaskCreateResult:
        return await self._tasks.handle_task_create(params, ctx)

    async def handle_task_list(self, params: NoParams, ctx: RequestContext) -> TaskListResult:
        return await self._tasks.handle_task_list(params, ctx)

    async def handle_task_disable(
        self, params: TaskDisableParams, ctx: RequestContext
    ) -> TaskDisableResult:
        return await self._tasks.handle_task_disable(params, ctx)

    async def handle_task_trigger_event(
        self, params: TaskTriggerEventParams, ctx: RequestContext
    ) -> TaskTriggerEventResult:
        return await self._tasks.handle_task_trigger_event(params, ctx)

    async def handle_task_pending_confirmations(
        self,
        params: TaskPendingConfirmationsParams,
        ctx: RequestContext,
    ) -> TaskPendingConfirmationsResult:
        return await self._tasks.handle_task_pending_confirmations(params, ctx)

    async def handle_action_pending(
        self, params: ActionPendingParams, ctx: RequestContext
    ) -> ActionPendingResult:
        return await self._confirmation.handle_action_pending(params, ctx)

    async def handle_action_confirm(
        self, params: ActionDecisionParams, ctx: RequestContext
    ) -> ActionConfirmResult:
        return await self._confirmation.handle_action_confirm(params, ctx)

    async def handle_action_reject(
        self, params: ActionDecisionParams, ctx: RequestContext
    ) -> ActionRejectResult:
        return await self._confirmation.handle_action_reject(params, ctx)

    async def handle_lockdown_set(
        self, params: LockdownSetParams, ctx: RequestContext
    ) -> LockdownSetResult:
        return await self._admin.handle_lockdown_set(params, ctx)

    async def handle_risk_calibrate(
        self, params: NoParams, ctx: RequestContext
    ) -> RiskCalibrateResult:
        return await self._admin.handle_risk_calibrate(params, ctx)

    async def handle_channel_ingest(
        self, params: ChannelIngestParams, ctx: RequestContext
    ) -> ChannelIngestResult:
        return await self._admin.handle_channel_ingest(params, ctx)

    async def handle_tool_execute(
        self, params: ToolExecuteParams, ctx: RequestContext
    ) -> ToolExecuteResult:
        return await self._tool_execution.handle_tool_execute(params, ctx)

    async def handle_browser_paste(
        self, params: BrowserPasteParams, ctx: RequestContext
    ) -> BrowserPasteResult:
        return await self._tool_execution.handle_browser_paste(params, ctx)

    async def handle_browser_screenshot(
        self, params: BrowserScreenshotParams, ctx: RequestContext
    ) -> BrowserScreenshotResult:
        return await self._tool_execution.handle_browser_screenshot(params, ctx)
