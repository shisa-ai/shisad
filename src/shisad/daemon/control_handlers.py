"""Control API facade that delegates to typed handler modules."""

from __future__ import annotations

from typing import TYPE_CHECKING

from shisad.core.api.schema import (
    ActionConfirmResult,
    ActionDecisionParams,
    ActionPendingParams,
    ActionPendingResult,
    ActionPurgeParams,
    ActionPurgeResult,
    ActionRejectResult,
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
    AuditQueryParams,
    AuditQueryResult,
    BrowserPasteParams,
    BrowserScreenshotParams,
    ChannelIngestParams,
    ChannelIngestResult,
    ChannelPairingProposalParams,
    ChannelPairingProposalResult,
    ConfirmationMetricsParams,
    ConfirmationMetricsResult,
    DaemonResetResult,
    DaemonShutdownResult,
    DaemonStatusResult,
    DashboardMarkFalsePositiveParams,
    DashboardMarkFalsePositiveResult,
    DashboardQueryParams,
    DashboardQueryResult,
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
    EmailReadParams,
    EmailReadResult,
    EmailSearchParams,
    EmailSearchResult,
    FsListParams,
    FsListResult,
    FsReadParams,
    FsReadResult,
    FsWriteParams,
    FsWriteResult,
    GitDiffParams,
    GitDiffResult,
    GitLogParams,
    GitLogResult,
    GitStatusParams,
    GitStatusResult,
    LockdownSetParams,
    LockdownSetResult,
    MemoryDeleteResult,
    MemoryEntryParams,
    MemoryExportParams,
    MemoryExportResult,
    MemoryGetResult,
    MemoryIngestParams,
    MemoryIngestResult,
    MemoryLifecycleParams,
    MemoryLifecycleResult,
    MemoryListParams,
    MemoryListResult,
    MemoryRetrieveParams,
    MemoryRetrieveResult,
    MemoryReviewQueueParams,
    MemoryRotateKeyParams,
    MemoryRotateKeyResult,
    MemoryVerifyResult,
    MemoryWorkflowStateParams,
    MemoryWorkflowStateResult,
    MemoryWriteParams,
    MemoryWriteResult,
    NoParams,
    NoteCreateParams,
    NoteDeleteResult,
    NoteEntryParams,
    NoteExportParams,
    NoteExportResult,
    NoteGetResult,
    NoteListParams,
    NoteListResult,
    NoteSearchParams,
    NoteSearchResult,
    NoteVerifyResult,
    PolicyExplainParams,
    PolicyExplainResult,
    RealityCheckReadParams,
    RealityCheckReadResult,
    RealityCheckSearchParams,
    RealityCheckSearchResult,
    RiskCalibrateResult,
    SessionCreateParams,
    SessionCreateResult,
    SessionExportParams,
    SessionExportResult,
    SessionGrantCapabilitiesParams,
    SessionGrantCapabilitiesResult,
    SessionImportParams,
    SessionImportResult,
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
    SignerListParams,
    SignerListResult,
    SignerRegisterParams,
    SignerRegisterResult,
    SignerRevokeParams,
    SignerRevokeResult,
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
    TodoCompleteParams,
    TodoCompleteResult,
    TodoCreateParams,
    TodoDeleteResult,
    TodoEntryParams,
    TodoExportParams,
    TodoExportResult,
    TodoGetResult,
    TodoListParams,
    TodoListResult,
    TodoVerifyResult,
    ToolExecuteParams,
    ToolExecuteResult,
    TwoFactorListParams,
    TwoFactorListResult,
    TwoFactorRegisterBeginParams,
    TwoFactorRegisterBeginResult,
    TwoFactorRegisterConfirmParams,
    TwoFactorRegisterConfirmResult,
    TwoFactorRevokeParams,
    TwoFactorRevokeResult,
    WebFetchParams,
    WebFetchResult,
    WebSearchParams,
    WebSearchResult,
)
from shisad.daemon.context import RequestContext
from shisad.daemon.handlers import (
    AdminHandlers,
    AssistantHandlers,
    ConfirmationHandlers,
    DashboardHandlers,
    MemoryHandlers,
    SessionHandlers,
    SkillHandlers,
    TaskHandlers,
    ToolExecutionHandlers,
)
from shisad.daemon.handlers._impl import HandlerImplementation

if TYPE_CHECKING:
    from shisad.daemon.services import DaemonServices
    from shisad.executors.browser import BrowserPasteResult, BrowserScreenshotResult


class DaemonControlHandlers:
    """Thin routing facade over split handler modules."""

    def __init__(self, *, services: DaemonServices) -> None:
        impl = HandlerImplementation(services=services)
        self._impl = impl
        internal_ingress_marker = services.internal_ingress_marker
        self._session = SessionHandlers(impl, internal_ingress_marker=internal_ingress_marker)
        self._tool_execution = ToolExecutionHandlers(
            impl,
            internal_ingress_marker=internal_ingress_marker,
        )
        self._confirmation = ConfirmationHandlers(
            impl,
            internal_ingress_marker=internal_ingress_marker,
        )
        self._memory = MemoryHandlers(
            impl,
            internal_ingress_marker=internal_ingress_marker,
        )
        self._skills = SkillHandlers(
            impl,
            internal_ingress_marker=internal_ingress_marker,
        )
        self._tasks = TaskHandlers(
            impl,
            internal_ingress_marker=internal_ingress_marker,
        )
        self._dashboard = DashboardHandlers(
            impl,
            internal_ingress_marker=internal_ingress_marker,
        )
        self._assistant = AssistantHandlers(
            impl,
            internal_ingress_marker=internal_ingress_marker,
        )
        self._admin = AdminHandlers(
            impl,
            internal_ingress_marker=internal_ingress_marker,
        )

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

    async def handle_session_export(
        self, params: SessionExportParams, ctx: RequestContext
    ) -> SessionExportResult:
        return await self._session.handle_session_export(params, ctx)

    async def handle_session_import(
        self, params: SessionImportParams, ctx: RequestContext
    ) -> SessionImportResult:
        return await self._session.handle_session_import(params, ctx)

    async def handle_session_rollback(
        self, params: SessionRollbackParams, ctx: RequestContext
    ) -> SessionRollbackResult:
        return await self._session.handle_session_rollback(params, ctx)

    async def handle_session_grant_capabilities(
        self, params: SessionGrantCapabilitiesParams, ctx: RequestContext
    ) -> SessionGrantCapabilitiesResult:
        return await self._session.handle_session_grant_capabilities(params, ctx)

    async def handle_session_set_mode(
        self, params: SessionSetModeParams, ctx: RequestContext
    ) -> SessionSetModeResult:
        return await self._session.handle_session_set_mode(params, ctx)

    async def handle_session_terminate(
        self, params: SessionTerminateParams, ctx: RequestContext
    ) -> SessionTerminateResult:
        return await self._session.handle_session_terminate(params, ctx)

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

    async def handle_daemon_reset(self, params: NoParams, ctx: RequestContext) -> DaemonResetResult:
        return await self._admin.handle_daemon_reset(params, ctx)

    async def handle_doctor_check(
        self, params: DoctorCheckParams, ctx: RequestContext
    ) -> DoctorCheckResult:
        return await self._admin.handle_doctor_check(params, ctx)

    async def handle_admin_selfmod_propose(
        self, params: AdminSelfModProposeParams, ctx: RequestContext
    ) -> AdminSelfModProposeResult:
        return await self._admin.handle_admin_selfmod_propose(params, ctx)

    async def handle_admin_selfmod_apply(
        self, params: AdminSelfModApplyParams, ctx: RequestContext
    ) -> AdminSelfModApplyResult:
        return await self._admin.handle_admin_selfmod_apply(params, ctx)

    async def handle_admin_selfmod_rollback(
        self, params: AdminSelfModRollbackParams, ctx: RequestContext
    ) -> AdminSelfModRollbackResult:
        return await self._admin.handle_admin_selfmod_rollback(params, ctx)

    async def handle_admin_soul_read(
        self, params: AdminSoulReadParams, ctx: RequestContext
    ) -> AdminSoulReadResult:
        return await self._admin.handle_admin_soul_read(params, ctx)

    async def handle_admin_soul_update(
        self, params: AdminSoulUpdateParams, ctx: RequestContext
    ) -> AdminSoulUpdateResult:
        return await self._admin.handle_admin_soul_update(params, ctx)

    async def handle_dev_implement(
        self, params: DevImplementParams, ctx: RequestContext
    ) -> DevImplementResult:
        return await self._admin.handle_dev_implement(params, ctx)

    async def handle_dev_review(
        self, params: DevReviewParams, ctx: RequestContext
    ) -> DevReviewResult:
        return await self._admin.handle_dev_review(params, ctx)

    async def handle_dev_remediate(
        self, params: DevRemediateParams, ctx: RequestContext
    ) -> DevRemediateResult:
        return await self._admin.handle_dev_remediate(params, ctx)

    async def handle_dev_close(self, params: DevCloseParams, ctx: RequestContext) -> DevCloseResult:
        return await self._admin.handle_dev_close(params, ctx)

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

    async def handle_two_factor_register_begin(
        self,
        params: TwoFactorRegisterBeginParams,
        ctx: RequestContext,
    ) -> TwoFactorRegisterBeginResult:
        return await self._confirmation.handle_two_factor_register_begin(params, ctx)

    async def handle_two_factor_register_confirm(
        self,
        params: TwoFactorRegisterConfirmParams,
        ctx: RequestContext,
    ) -> TwoFactorRegisterConfirmResult:
        return await self._confirmation.handle_two_factor_register_confirm(params, ctx)

    async def handle_two_factor_list(
        self,
        params: TwoFactorListParams,
        ctx: RequestContext,
    ) -> TwoFactorListResult:
        return await self._confirmation.handle_two_factor_list(params, ctx)

    async def handle_two_factor_revoke(
        self,
        params: TwoFactorRevokeParams,
        ctx: RequestContext,
    ) -> TwoFactorRevokeResult:
        return await self._confirmation.handle_two_factor_revoke(params, ctx)

    async def handle_signer_register(
        self,
        params: SignerRegisterParams,
        ctx: RequestContext,
    ) -> SignerRegisterResult:
        return await self._confirmation.handle_signer_register(params, ctx)

    async def handle_signer_list(
        self,
        params: SignerListParams,
        ctx: RequestContext,
    ) -> SignerListResult:
        return await self._confirmation.handle_signer_list(params, ctx)

    async def handle_signer_revoke(
        self,
        params: SignerRevokeParams,
        ctx: RequestContext,
    ) -> SignerRevokeResult:
        return await self._confirmation.handle_signer_revoke(params, ctx)

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

    async def handle_memory_list_review_queue(
        self, params: MemoryReviewQueueParams, ctx: RequestContext
    ) -> MemoryListResult:
        return await self._memory.handle_memory_list_review_queue(params, ctx)

    async def handle_memory_get(
        self, params: MemoryEntryParams, ctx: RequestContext
    ) -> MemoryGetResult:
        return await self._memory.handle_memory_get(params, ctx)

    async def handle_memory_delete(
        self, params: MemoryEntryParams, ctx: RequestContext
    ) -> MemoryDeleteResult:
        return await self._memory.handle_memory_delete(params, ctx)

    async def handle_memory_quarantine(
        self, params: MemoryLifecycleParams, ctx: RequestContext
    ) -> MemoryLifecycleResult:
        return await self._memory.handle_memory_quarantine(params, ctx)

    async def handle_memory_unquarantine(
        self, params: MemoryLifecycleParams, ctx: RequestContext
    ) -> MemoryLifecycleResult:
        return await self._memory.handle_memory_unquarantine(params, ctx)

    async def handle_memory_set_workflow_state(
        self, params: MemoryWorkflowStateParams, ctx: RequestContext
    ) -> MemoryWorkflowStateResult:
        return await self._memory.handle_memory_set_workflow_state(params, ctx)

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

    async def handle_note_create(
        self, params: NoteCreateParams, ctx: RequestContext
    ) -> MemoryWriteResult:
        return await self._memory.handle_note_create(params, ctx)

    async def handle_note_list(self, params: NoteListParams, ctx: RequestContext) -> NoteListResult:
        return await self._memory.handle_note_list(params, ctx)

    async def handle_note_search(
        self, params: NoteSearchParams, ctx: RequestContext
    ) -> NoteSearchResult:
        return await self._memory.handle_note_search(params, ctx)

    async def handle_note_get(self, params: NoteEntryParams, ctx: RequestContext) -> NoteGetResult:
        return await self._memory.handle_note_get(params, ctx)

    async def handle_note_delete(
        self, params: NoteEntryParams, ctx: RequestContext
    ) -> NoteDeleteResult:
        return await self._memory.handle_note_delete(params, ctx)

    async def handle_note_verify(
        self, params: NoteEntryParams, ctx: RequestContext
    ) -> NoteVerifyResult:
        return await self._memory.handle_note_verify(params, ctx)

    async def handle_note_export(
        self, params: NoteExportParams, ctx: RequestContext
    ) -> NoteExportResult:
        return await self._memory.handle_note_export(params, ctx)

    async def handle_todo_create(
        self, params: TodoCreateParams, ctx: RequestContext
    ) -> MemoryWriteResult:
        return await self._memory.handle_todo_create(params, ctx)

    async def handle_todo_list(self, params: TodoListParams, ctx: RequestContext) -> TodoListResult:
        return await self._memory.handle_todo_list(params, ctx)

    async def handle_todo_complete(
        self, params: TodoCompleteParams, ctx: RequestContext
    ) -> TodoCompleteResult:
        return await self._memory.handle_todo_complete(params, ctx)

    async def handle_todo_get(self, params: TodoEntryParams, ctx: RequestContext) -> TodoGetResult:
        return await self._memory.handle_todo_get(params, ctx)

    async def handle_todo_delete(
        self, params: TodoEntryParams, ctx: RequestContext
    ) -> TodoDeleteResult:
        return await self._memory.handle_todo_delete(params, ctx)

    async def handle_todo_verify(
        self, params: TodoEntryParams, ctx: RequestContext
    ) -> TodoVerifyResult:
        return await self._memory.handle_todo_verify(params, ctx)

    async def handle_todo_export(
        self, params: TodoExportParams, ctx: RequestContext
    ) -> TodoExportResult:
        return await self._memory.handle_todo_export(params, ctx)

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

    async def handle_web_search(
        self, params: WebSearchParams, ctx: RequestContext
    ) -> WebSearchResult:
        return await self._assistant.handle_web_search(params, ctx)

    async def handle_web_fetch(self, params: WebFetchParams, ctx: RequestContext) -> WebFetchResult:
        return await self._assistant.handle_web_fetch(params, ctx)

    async def handle_realitycheck_search(
        self, params: RealityCheckSearchParams, ctx: RequestContext
    ) -> RealityCheckSearchResult:
        return await self._assistant.handle_realitycheck_search(params, ctx)

    async def handle_realitycheck_read(
        self, params: RealityCheckReadParams, ctx: RequestContext
    ) -> RealityCheckReadResult:
        return await self._assistant.handle_realitycheck_read(params, ctx)

    async def handle_email_search(
        self, params: EmailSearchParams, ctx: RequestContext
    ) -> EmailSearchResult:
        return await self._assistant.handle_email_search(params, ctx)

    async def handle_email_read(
        self, params: EmailReadParams, ctx: RequestContext
    ) -> EmailReadResult:
        return await self._assistant.handle_email_read(params, ctx)

    async def handle_fs_list(self, params: FsListParams, ctx: RequestContext) -> FsListResult:
        return await self._assistant.handle_fs_list(params, ctx)

    async def handle_fs_read(self, params: FsReadParams, ctx: RequestContext) -> FsReadResult:
        return await self._assistant.handle_fs_read(params, ctx)

    async def handle_fs_write(self, params: FsWriteParams, ctx: RequestContext) -> FsWriteResult:
        return await self._assistant.handle_fs_write(params, ctx)

    async def handle_git_status(
        self, params: GitStatusParams, ctx: RequestContext
    ) -> GitStatusResult:
        return await self._assistant.handle_git_status(params, ctx)

    async def handle_git_diff(self, params: GitDiffParams, ctx: RequestContext) -> GitDiffResult:
        return await self._assistant.handle_git_diff(params, ctx)

    async def handle_git_log(self, params: GitLogParams, ctx: RequestContext) -> GitLogResult:
        return await self._assistant.handle_git_log(params, ctx)

    async def handle_action_pending(
        self, params: ActionPendingParams, ctx: RequestContext
    ) -> ActionPendingResult:
        return await self._confirmation.handle_action_pending(params, ctx)

    async def handle_action_purge(
        self, params: ActionPurgeParams, ctx: RequestContext
    ) -> ActionPurgeResult:
        return await self._confirmation.handle_action_purge(params, ctx)

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

    async def handle_channel_pairing_propose(
        self, params: ChannelPairingProposalParams, ctx: RequestContext
    ) -> ChannelPairingProposalResult:
        return await self._admin.handle_channel_pairing_propose(params, ctx)

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
