"""Explicit control-RPC descriptors and machine introspection."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from importlib import import_module

from pydantic import BaseModel

from shisad.core.api import schema as api_schema

_ALLOWED_RESULT_MODULES = frozenset(
    {
        "shisad.core.api.schema",
        "shisad.executors.browser",
    }
)


class RpcAvailability(StrEnum):
    """Registration posture for one control method."""

    ALWAYS = "always"
    TEST_MODE = "test_mode"


class RpcReadiness(StrEnum):
    """Where optional capability readiness remains enforced."""

    HANDLER_GATED = "handler_gated"


class RpcHandlerGroup(StrEnum):
    """Finite grouped-handler owners held by ``DaemonControlHandlers``."""

    ADMIN = "admin"
    ASSISTANT = "assistant"
    CONFIRMATION = "confirmation"
    DASHBOARD = "dashboard"
    MEMORY = "memory"
    PLAN_STEPS = "plan_steps"
    SESSION = "session"
    SKILLS = "skills"
    TASKS = "tasks"
    TOOL_EXECUTION = "tool_execution"


@dataclass(frozen=True, slots=True)
class RpcResultModelRef:
    """Allowlisted lazy result-model reference.

    Browser result models intentionally remain executor-owned. Lazy resolution
    keeps importing this core registry from importing the executor layer.
    """

    module: str
    name: str

    def __post_init__(self) -> None:
        if self.module not in _ALLOWED_RESULT_MODULES:
            raise ValueError(f"unsupported RPC result module: {self.module}")
        if not self.name.isidentifier():
            raise ValueError(f"invalid RPC result model name: {self.name}")

    @property
    def qualified_name(self) -> str:
        return f"{self.module}.{self.name}"

    def resolve(self) -> type[BaseModel]:
        model = getattr(import_module(self.module), self.name, None)
        if not isinstance(model, type) or not issubclass(model, BaseModel):
            raise RuntimeError(f"RPC result model does not resolve: {self.qualified_name}")
        return model


@dataclass(frozen=True, slots=True)
class RpcMethodDescriptor:
    """One authoritative control-method registration contract."""

    name: str
    params_model: type[BaseModel]
    result_model: RpcResultModelRef
    admin_only: bool
    handler_group: RpcHandlerGroup
    handler_method: str
    availability: RpcAvailability = RpcAvailability.ALWAYS
    readiness: RpcReadiness = RpcReadiness.HANDLER_GATED

    def __post_init__(self) -> None:
        if not self.name or self.name != self.name.strip() or "." not in self.name:
            raise ValueError(f"invalid RPC method name: {self.name!r}")
        if not isinstance(self.result_model, RpcResultModelRef):
            raise TypeError(f"invalid RPC result model for {self.name}")
        if not isinstance(self.params_model, type) or not issubclass(self.params_model, BaseModel):
            raise TypeError(f"invalid RPC parameter model for {self.name}")
        if type(self.admin_only) is not bool:
            raise TypeError(f"invalid RPC admin posture for {self.name}")
        if not isinstance(self.handler_group, RpcHandlerGroup):
            raise TypeError(f"invalid RPC handler group for {self.name}")
        if not self.handler_method.startswith("handle_") or not self.handler_method.isidentifier():
            raise ValueError(f"invalid RPC handler method for {self.name}")
        if not isinstance(self.availability, RpcAvailability):
            raise TypeError(f"invalid RPC availability for {self.name}")
        if not isinstance(self.readiness, RpcReadiness):
            raise TypeError(f"invalid RPC readiness for {self.name}")


@dataclass(frozen=True, slots=True)
class RpcMethodManifestEntry:
    """Stable machine-introspection projection of one descriptor."""

    name: str
    params_model: str
    result_model: str
    admin_only: bool
    handler_group: str
    handler_method: str
    availability: str
    readiness: str


def _result_ref(module: str, name: str) -> RpcResultModelRef:
    return RpcResultModelRef(module=module, name=name)


def _schema_result(name: str) -> RpcResultModelRef:
    return _result_ref("shisad.core.api.schema", name)


def _rpc(
    name: str,
    params_model: type[BaseModel],
    result_model: RpcResultModelRef,
    admin_only: bool,
    handler_group: RpcHandlerGroup,
    handler_method: str,
    *,
    availability: RpcAvailability = RpcAvailability.ALWAYS,
) -> RpcMethodDescriptor:
    return RpcMethodDescriptor(
        name=name,
        params_model=params_model,
        result_model=result_model,
        admin_only=admin_only,
        handler_group=handler_group,
        handler_method=handler_method,
        availability=availability,
    )


_RPC_METHOD_DESCRIPTORS = (
    _rpc(
        "session.create",
        api_schema.SessionCreateParams,
        _schema_result("SessionCreateResult"),
        False,
        RpcHandlerGroup.SESSION,
        "handle_session_create",
    ),
    _rpc(
        "session.message",
        api_schema.SessionMessageParams,
        _schema_result("SessionMessageResult"),
        False,
        RpcHandlerGroup.SESSION,
        "handle_session_message",
    ),
    _rpc(
        "session.list",
        api_schema.NoParams,
        _schema_result("SessionListResult"),
        False,
        RpcHandlerGroup.SESSION,
        "handle_session_list",
    ),
    _rpc(
        "plan.steps",
        api_schema.PlanStepsParams,
        _schema_result("PlanStepsResult"),
        False,
        RpcHandlerGroup.PLAN_STEPS,
        "handle_plan_steps",
    ),
    _rpc(
        "session.terminate",
        api_schema.SessionTerminateParams,
        _schema_result("SessionTerminateResult"),
        False,
        RpcHandlerGroup.SESSION,
        "handle_session_terminate",
    ),
    _rpc(
        "session.restore",
        api_schema.SessionRestoreParams,
        _schema_result("SessionRestoreResult"),
        True,
        RpcHandlerGroup.SESSION,
        "handle_session_restore",
    ),
    _rpc(
        "session.export",
        api_schema.SessionExportParams,
        _schema_result("SessionExportResult"),
        True,
        RpcHandlerGroup.SESSION,
        "handle_session_export",
    ),
    _rpc(
        "session.import",
        api_schema.SessionImportParams,
        _schema_result("SessionImportResult"),
        True,
        RpcHandlerGroup.SESSION,
        "handle_session_import",
    ),
    _rpc(
        "session.rollback",
        api_schema.SessionRollbackParams,
        _schema_result("SessionRollbackResult"),
        True,
        RpcHandlerGroup.SESSION,
        "handle_session_rollback",
    ),
    _rpc(
        "session.grant_capabilities",
        api_schema.SessionGrantCapabilitiesParams,
        _schema_result("SessionGrantCapabilitiesResult"),
        True,
        RpcHandlerGroup.SESSION,
        "handle_session_grant_capabilities",
    ),
    _rpc(
        "session.set_mode",
        api_schema.SessionSetModeParams,
        _schema_result("SessionSetModeResult"),
        True,
        RpcHandlerGroup.SESSION,
        "handle_session_set_mode",
    ),
    _rpc(
        "daemon.status",
        api_schema.NoParams,
        _schema_result("DaemonStatusResult"),
        False,
        RpcHandlerGroup.ADMIN,
        "handle_daemon_status",
    ),
    _rpc(
        "doctor.check",
        api_schema.DoctorCheckParams,
        _schema_result("DoctorCheckResult"),
        False,
        RpcHandlerGroup.ADMIN,
        "handle_doctor_check",
    ),
    _rpc(
        "admin.selfmod.propose",
        api_schema.AdminSelfModProposeParams,
        _schema_result("AdminSelfModProposeResult"),
        True,
        RpcHandlerGroup.ADMIN,
        "handle_admin_selfmod_propose",
    ),
    _rpc(
        "admin.selfmod.apply",
        api_schema.AdminSelfModApplyParams,
        _schema_result("AdminSelfModApplyResult"),
        True,
        RpcHandlerGroup.ADMIN,
        "handle_admin_selfmod_apply",
    ),
    _rpc(
        "admin.selfmod.rollback",
        api_schema.AdminSelfModRollbackParams,
        _schema_result("AdminSelfModRollbackResult"),
        True,
        RpcHandlerGroup.ADMIN,
        "handle_admin_selfmod_rollback",
    ),
    _rpc(
        "admin.soul.read",
        api_schema.AdminSoulReadParams,
        _schema_result("AdminSoulReadResult"),
        True,
        RpcHandlerGroup.ADMIN,
        "handle_admin_soul_read",
    ),
    _rpc(
        "admin.soul.update",
        api_schema.AdminSoulUpdateParams,
        _schema_result("AdminSoulUpdateResult"),
        True,
        RpcHandlerGroup.ADMIN,
        "handle_admin_soul_update",
    ),
    _rpc(
        "dev.implement",
        api_schema.DevImplementParams,
        _schema_result("DevImplementResult"),
        True,
        RpcHandlerGroup.ADMIN,
        "handle_dev_implement",
    ),
    _rpc(
        "dev.review",
        api_schema.DevReviewParams,
        _schema_result("DevReviewResult"),
        True,
        RpcHandlerGroup.ADMIN,
        "handle_dev_review",
    ),
    _rpc(
        "dev.remediate",
        api_schema.DevRemediateParams,
        _schema_result("DevRemediateResult"),
        True,
        RpcHandlerGroup.ADMIN,
        "handle_dev_remediate",
    ),
    _rpc(
        "dev.close",
        api_schema.DevCloseParams,
        _schema_result("DevCloseResult"),
        True,
        RpcHandlerGroup.ADMIN,
        "handle_dev_close",
    ),
    _rpc(
        "policy.explain",
        api_schema.PolicyExplainParams,
        _schema_result("PolicyExplainResult"),
        False,
        RpcHandlerGroup.ADMIN,
        "handle_policy_explain",
    ),
    _rpc(
        "daemon.shutdown",
        api_schema.NoParams,
        _schema_result("DaemonShutdownResult"),
        False,
        RpcHandlerGroup.ADMIN,
        "handle_daemon_shutdown",
    ),
    _rpc(
        "daemon.reset",
        api_schema.NoParams,
        _schema_result("DaemonResetResult"),
        True,
        RpcHandlerGroup.ADMIN,
        "handle_daemon_reset",
        availability=RpcAvailability.TEST_MODE,
    ),
    _rpc(
        "audit.query",
        api_schema.AuditQueryParams,
        _schema_result("AuditQueryResult"),
        False,
        RpcHandlerGroup.DASHBOARD,
        "handle_audit_query",
    ),
    _rpc(
        "dashboard.audit_explorer",
        api_schema.DashboardQueryParams,
        _schema_result("DashboardQueryResult"),
        True,
        RpcHandlerGroup.DASHBOARD,
        "handle_dashboard_audit_explorer",
    ),
    _rpc(
        "dashboard.egress_review",
        api_schema.DashboardQueryParams,
        _schema_result("DashboardQueryResult"),
        True,
        RpcHandlerGroup.DASHBOARD,
        "handle_dashboard_egress_review",
    ),
    _rpc(
        "dashboard.skill_provenance",
        api_schema.DashboardQueryParams,
        _schema_result("DashboardQueryResult"),
        True,
        RpcHandlerGroup.DASHBOARD,
        "handle_dashboard_skill_provenance",
    ),
    _rpc(
        "dashboard.alerts",
        api_schema.DashboardQueryParams,
        _schema_result("DashboardQueryResult"),
        True,
        RpcHandlerGroup.DASHBOARD,
        "handle_dashboard_alerts",
    ),
    _rpc(
        "dashboard.mark_false_positive",
        api_schema.DashboardMarkFalsePositiveParams,
        _schema_result("DashboardMarkFalsePositiveResult"),
        True,
        RpcHandlerGroup.DASHBOARD,
        "handle_dashboard_mark_false_positive",
    ),
    _rpc(
        "confirmation.metrics",
        api_schema.ConfirmationMetricsParams,
        _schema_result("ConfirmationMetricsResult"),
        True,
        RpcHandlerGroup.CONFIRMATION,
        "handle_confirmation_metrics",
    ),
    _rpc(
        "graph.query",
        api_schema.GraphQueryParams,
        _schema_result("GraphQueryResult"),
        False,
        RpcHandlerGroup.MEMORY,
        "handle_graph_query",
    ),
    _rpc(
        "graph.export",
        api_schema.GraphExportParams,
        _schema_result("GraphExportResult"),
        False,
        RpcHandlerGroup.MEMORY,
        "handle_graph_export",
    ),
    _rpc(
        "memory.consolidate",
        api_schema.MemoryConsolidateParams,
        _schema_result("MemoryConsolidateResult"),
        True,
        RpcHandlerGroup.MEMORY,
        "handle_memory_consolidate",
    ),
    _rpc(
        "memory.mint_ingress_context",
        api_schema.MemoryMintIngressParams,
        _schema_result("MemoryMintIngressResult"),
        True,
        RpcHandlerGroup.MEMORY,
        "handle_memory_mint_ingress_context",
    ),
    _rpc(
        "memory.ingest",
        api_schema.MemoryIngestParams,
        _schema_result("MemoryIngestResult"),
        True,
        RpcHandlerGroup.MEMORY,
        "handle_memory_ingest",
    ),
    _rpc(
        "memory.retrieve",
        api_schema.MemoryRetrieveParams,
        _schema_result("MemoryRetrieveResult"),
        False,
        RpcHandlerGroup.MEMORY,
        "handle_memory_retrieve",
    ),
    _rpc(
        "memory.timeline.search",
        api_schema.MemoryTimelineSearchParams,
        _schema_result("MemoryTimelineSearchResult"),
        False,
        RpcHandlerGroup.MEMORY,
        "handle_memory_timeline_search",
    ),
    _rpc(
        "memory.timeline.read",
        api_schema.MemoryTimelineReadParams,
        _schema_result("MemoryTimelineReadResult"),
        False,
        RpcHandlerGroup.MEMORY,
        "handle_memory_timeline_read",
    ),
    _rpc(
        "memory.timeline.promote",
        api_schema.MemoryTimelinePromoteParams,
        _schema_result("MemoryWriteResult"),
        True,
        RpcHandlerGroup.MEMORY,
        "handle_memory_timeline_promote",
    ),
    _rpc(
        "memory.write",
        api_schema.MemoryWriteParams,
        _schema_result("MemoryWriteResult"),
        True,
        RpcHandlerGroup.MEMORY,
        "handle_memory_write",
    ),
    _rpc(
        "memory.supersede",
        api_schema.MemorySupersedeParams,
        _schema_result("MemoryWriteResult"),
        True,
        RpcHandlerGroup.MEMORY,
        "handle_memory_supersede",
    ),
    _rpc(
        "memory.promote_identity_candidate",
        api_schema.MemoryPromoteIdentityCandidateParams,
        _schema_result("MemoryWriteResult"),
        True,
        RpcHandlerGroup.MEMORY,
        "handle_memory_promote_identity_candidate",
    ),
    _rpc(
        "memory.promote_to_skill",
        api_schema.MemoryPromoteSkillParams,
        _schema_result("MemoryWriteResult"),
        True,
        RpcHandlerGroup.MEMORY,
        "handle_memory_promote_skill",
    ),
    _rpc(
        "memory.ingest_procedure_candidate",
        api_schema.MemoryIngestProcedureCandidateParams,
        _schema_result("MemoryWriteResult"),
        True,
        RpcHandlerGroup.MEMORY,
        "handle_memory_ingest_procedure_candidate",
    ),
    _rpc(
        "memory.review_procedure_candidate",
        api_schema.MemoryProcedureCandidateParams,
        _schema_result("MemoryProcedureCandidateReviewResult"),
        True,
        RpcHandlerGroup.MEMORY,
        "handle_memory_review_procedure_candidate",
    ),
    _rpc(
        "memory.reject_procedure_candidate",
        api_schema.MemoryRejectProcedureCandidateParams,
        _schema_result("MemoryProcedureCandidateResult"),
        True,
        RpcHandlerGroup.MEMORY,
        "handle_memory_reject_procedure_candidate",
    ),
    _rpc(
        "memory.promote_procedure_candidate",
        api_schema.MemoryPromoteProcedureCandidateParams,
        _schema_result("MemoryWriteResult"),
        True,
        RpcHandlerGroup.MEMORY,
        "handle_memory_promote_procedure_candidate",
    ),
    _rpc(
        "memory.reject_identity_candidate",
        api_schema.MemoryRejectIdentityCandidateParams,
        _schema_result("MemoryIdentityCandidateResult"),
        True,
        RpcHandlerGroup.MEMORY,
        "handle_memory_reject_identity_candidate",
    ),
    _rpc(
        "memory.list",
        api_schema.MemoryListParams,
        _schema_result("MemoryListResult"),
        False,
        RpcHandlerGroup.MEMORY,
        "handle_memory_list",
    ),
    _rpc(
        "memory.list_review_queue",
        api_schema.MemoryReviewQueueParams,
        _schema_result("MemoryListResult"),
        False,
        RpcHandlerGroup.MEMORY,
        "handle_memory_list_review_queue",
    ),
    _rpc(
        "memory.invoke_skill",
        api_schema.MemoryInvokeSkillParams,
        _schema_result("MemoryInvokeSkillResult"),
        False,
        RpcHandlerGroup.MEMORY,
        "handle_memory_invoke_skill",
    ),
    _rpc(
        "memory.read_original",
        api_schema.MemoryReadOriginalParams,
        _schema_result("MemoryReadOriginalResult"),
        False,
        RpcHandlerGroup.MEMORY,
        "handle_memory_read_original",
    ),
    _rpc(
        "memory.get",
        api_schema.MemoryEntryParams,
        _schema_result("MemoryGetResult"),
        False,
        RpcHandlerGroup.MEMORY,
        "handle_memory_get",
    ),
    _rpc(
        "memory.delete",
        api_schema.MemoryEntryParams,
        _schema_result("MemoryDeleteResult"),
        True,
        RpcHandlerGroup.MEMORY,
        "handle_memory_delete",
    ),
    _rpc(
        "memory.quarantine",
        api_schema.MemoryLifecycleParams,
        _schema_result("MemoryLifecycleResult"),
        True,
        RpcHandlerGroup.MEMORY,
        "handle_memory_quarantine",
    ),
    _rpc(
        "memory.unquarantine",
        api_schema.MemoryLifecycleParams,
        _schema_result("MemoryLifecycleResult"),
        True,
        RpcHandlerGroup.MEMORY,
        "handle_memory_unquarantine",
    ),
    _rpc(
        "memory.set_workflow_state",
        api_schema.MemoryWorkflowStateParams,
        _schema_result("MemoryWorkflowStateResult"),
        True,
        RpcHandlerGroup.MEMORY,
        "handle_memory_set_workflow_state",
    ),
    _rpc(
        "memory.export",
        api_schema.MemoryExportParams,
        _schema_result("MemoryExportResult"),
        False,
        RpcHandlerGroup.MEMORY,
        "handle_memory_export",
    ),
    _rpc(
        "memory.verify",
        api_schema.MemoryEntryParams,
        _schema_result("MemoryVerifyResult"),
        True,
        RpcHandlerGroup.MEMORY,
        "handle_memory_verify",
    ),
    _rpc(
        "memory.rotate_key",
        api_schema.MemoryRotateKeyParams,
        _schema_result("MemoryRotateKeyResult"),
        True,
        RpcHandlerGroup.MEMORY,
        "handle_memory_rotate_key",
    ),
    _rpc(
        "thread.list",
        api_schema.ThreadListParams,
        _schema_result("ThreadListResult"),
        False,
        RpcHandlerGroup.MEMORY,
        "handle_thread_list",
    ),
    _rpc(
        "thread.inspect",
        api_schema.ThreadEntryParams,
        _schema_result("ThreadInspectResult"),
        False,
        RpcHandlerGroup.MEMORY,
        "handle_thread_inspect",
    ),
    _rpc(
        "thread.resume",
        api_schema.ThreadEntryParams,
        _schema_result("ThreadMutationResult"),
        True,
        RpcHandlerGroup.MEMORY,
        "handle_thread_resume",
    ),
    _rpc(
        "thread.close",
        api_schema.ThreadCloseParams,
        _schema_result("ThreadMutationResult"),
        True,
        RpcHandlerGroup.MEMORY,
        "handle_thread_close",
    ),
    _rpc(
        "thread.why",
        api_schema.ThreadWhyParams,
        _schema_result("ThreadWhyResult"),
        False,
        RpcHandlerGroup.MEMORY,
        "handle_thread_why",
    ),
    _rpc(
        "note.create",
        api_schema.NoteCreateParams,
        _schema_result("MemoryWriteResult"),
        True,
        RpcHandlerGroup.MEMORY,
        "handle_note_create",
    ),
    _rpc(
        "note.list",
        api_schema.NoteListParams,
        _schema_result("NoteListResult"),
        False,
        RpcHandlerGroup.MEMORY,
        "handle_note_list",
    ),
    _rpc(
        "note.search",
        api_schema.NoteSearchParams,
        _schema_result("NoteSearchResult"),
        False,
        RpcHandlerGroup.MEMORY,
        "handle_note_search",
    ),
    _rpc(
        "note.get",
        api_schema.NoteEntryParams,
        _schema_result("NoteGetResult"),
        False,
        RpcHandlerGroup.MEMORY,
        "handle_note_get",
    ),
    _rpc(
        "note.delete",
        api_schema.NoteEntryParams,
        _schema_result("NoteDeleteResult"),
        True,
        RpcHandlerGroup.MEMORY,
        "handle_note_delete",
    ),
    _rpc(
        "note.verify",
        api_schema.NoteEntryParams,
        _schema_result("NoteVerifyResult"),
        True,
        RpcHandlerGroup.MEMORY,
        "handle_note_verify",
    ),
    _rpc(
        "note.export",
        api_schema.NoteExportParams,
        _schema_result("NoteExportResult"),
        False,
        RpcHandlerGroup.MEMORY,
        "handle_note_export",
    ),
    _rpc(
        "todo.create",
        api_schema.TodoCreateParams,
        _schema_result("MemoryWriteResult"),
        True,
        RpcHandlerGroup.MEMORY,
        "handle_todo_create",
    ),
    _rpc(
        "todo.list",
        api_schema.TodoListParams,
        _schema_result("TodoListResult"),
        False,
        RpcHandlerGroup.MEMORY,
        "handle_todo_list",
    ),
    _rpc(
        "todo.complete",
        api_schema.TodoCompleteParams,
        _schema_result("TodoCompleteResult"),
        True,
        RpcHandlerGroup.MEMORY,
        "handle_todo_complete",
    ),
    _rpc(
        "todo.get",
        api_schema.TodoEntryParams,
        _schema_result("TodoGetResult"),
        False,
        RpcHandlerGroup.MEMORY,
        "handle_todo_get",
    ),
    _rpc(
        "todo.delete",
        api_schema.TodoEntryParams,
        _schema_result("TodoDeleteResult"),
        True,
        RpcHandlerGroup.MEMORY,
        "handle_todo_delete",
    ),
    _rpc(
        "todo.verify",
        api_schema.TodoEntryParams,
        _schema_result("TodoVerifyResult"),
        True,
        RpcHandlerGroup.MEMORY,
        "handle_todo_verify",
    ),
    _rpc(
        "todo.export",
        api_schema.TodoExportParams,
        _schema_result("TodoExportResult"),
        False,
        RpcHandlerGroup.MEMORY,
        "handle_todo_export",
    ),
    _rpc(
        "skill.list",
        api_schema.NoParams,
        _schema_result("SkillListResult"),
        True,
        RpcHandlerGroup.SKILLS,
        "handle_skill_list",
    ),
    _rpc(
        "skill.review",
        api_schema.SkillReviewParams,
        _schema_result("SkillReviewResult"),
        True,
        RpcHandlerGroup.SKILLS,
        "handle_skill_review",
    ),
    _rpc(
        "skill.install",
        api_schema.SkillInstallParams,
        _schema_result("SkillInstallResult"),
        True,
        RpcHandlerGroup.SKILLS,
        "handle_skill_install",
    ),
    _rpc(
        "skill.profile",
        api_schema.SkillProfileParams,
        _schema_result("SkillProfileResult"),
        True,
        RpcHandlerGroup.SKILLS,
        "handle_skill_profile",
    ),
    _rpc(
        "skill.revoke",
        api_schema.SkillRevokeParams,
        _schema_result("SkillRevokeResult"),
        True,
        RpcHandlerGroup.SKILLS,
        "handle_skill_revoke",
    ),
    _rpc(
        "task.create",
        api_schema.TaskCreateParams,
        _schema_result("TaskCreateResult"),
        True,
        RpcHandlerGroup.TASKS,
        "handle_task_create",
    ),
    _rpc(
        "task.list",
        api_schema.NoParams,
        _schema_result("TaskListResult"),
        False,
        RpcHandlerGroup.TASKS,
        "handle_task_list",
    ),
    _rpc(
        "task.disable",
        api_schema.TaskDisableParams,
        _schema_result("TaskDisableResult"),
        True,
        RpcHandlerGroup.TASKS,
        "handle_task_disable",
    ),
    _rpc(
        "task.trigger_event",
        api_schema.TaskTriggerEventParams,
        _schema_result("TaskTriggerEventResult"),
        True,
        RpcHandlerGroup.TASKS,
        "handle_task_trigger_event",
    ),
    _rpc(
        "task.pending_confirmations",
        api_schema.TaskPendingConfirmationsParams,
        _schema_result("TaskPendingConfirmationsResult"),
        True,
        RpcHandlerGroup.TASKS,
        "handle_task_pending_confirmations",
    ),
    _rpc(
        "task.status_snapshot",
        api_schema.TaskStatusSnapshotParams,
        _schema_result("TaskStatusSnapshotResult"),
        False,
        RpcHandlerGroup.TASKS,
        "handle_task_status_snapshot",
    ),
    _rpc(
        "web.search",
        api_schema.WebSearchParams,
        _schema_result("WebSearchResult"),
        False,
        RpcHandlerGroup.ASSISTANT,
        "handle_web_search",
    ),
    _rpc(
        "web.fetch",
        api_schema.WebFetchParams,
        _schema_result("WebFetchResult"),
        False,
        RpcHandlerGroup.ASSISTANT,
        "handle_web_fetch",
    ),
    _rpc(
        "realitycheck.search",
        api_schema.RealityCheckSearchParams,
        _schema_result("RealityCheckSearchResult"),
        False,
        RpcHandlerGroup.ASSISTANT,
        "handle_realitycheck_search",
    ),
    _rpc(
        "realitycheck.read",
        api_schema.RealityCheckReadParams,
        _schema_result("RealityCheckReadResult"),
        False,
        RpcHandlerGroup.ASSISTANT,
        "handle_realitycheck_read",
    ),
    _rpc(
        "email.search",
        api_schema.EmailSearchParams,
        _schema_result("EmailSearchResult"),
        False,
        RpcHandlerGroup.ASSISTANT,
        "handle_email_search",
    ),
    _rpc(
        "email.read",
        api_schema.EmailReadParams,
        _schema_result("EmailReadResult"),
        False,
        RpcHandlerGroup.ASSISTANT,
        "handle_email_read",
    ),
    _rpc(
        "fs.list",
        api_schema.FsListParams,
        _schema_result("FsListResult"),
        False,
        RpcHandlerGroup.ASSISTANT,
        "handle_fs_list",
    ),
    _rpc(
        "fs.read",
        api_schema.FsReadParams,
        _schema_result("FsReadResult"),
        False,
        RpcHandlerGroup.ASSISTANT,
        "handle_fs_read",
    ),
    _rpc(
        "fs.write",
        api_schema.FsWriteParams,
        _schema_result("FsWriteResult"),
        True,
        RpcHandlerGroup.ASSISTANT,
        "handle_fs_write",
    ),
    _rpc(
        "git.status",
        api_schema.GitStatusParams,
        _schema_result("GitStatusResult"),
        False,
        RpcHandlerGroup.ASSISTANT,
        "handle_git_status",
    ),
    _rpc(
        "git.diff",
        api_schema.GitDiffParams,
        _schema_result("GitDiffResult"),
        False,
        RpcHandlerGroup.ASSISTANT,
        "handle_git_diff",
    ),
    _rpc(
        "git.log",
        api_schema.GitLogParams,
        _schema_result("GitLogResult"),
        False,
        RpcHandlerGroup.ASSISTANT,
        "handle_git_log",
    ),
    _rpc(
        "action.pending",
        api_schema.ActionPendingParams,
        _schema_result("ActionPendingResult"),
        True,
        RpcHandlerGroup.CONFIRMATION,
        "handle_action_pending",
    ),
    _rpc(
        "action.purge",
        api_schema.ActionPurgeParams,
        _schema_result("ActionPurgeResult"),
        True,
        RpcHandlerGroup.CONFIRMATION,
        "handle_action_purge",
    ),
    _rpc(
        "action.confirm",
        api_schema.ActionDecisionParams,
        _schema_result("ActionConfirmResult"),
        True,
        RpcHandlerGroup.CONFIRMATION,
        "handle_action_confirm",
    ),
    _rpc(
        "action.reject",
        api_schema.ActionDecisionParams,
        _schema_result("ActionRejectResult"),
        True,
        RpcHandlerGroup.CONFIRMATION,
        "handle_action_reject",
    ),
    _rpc(
        "2fa.register_begin",
        api_schema.TwoFactorRegisterBeginParams,
        _schema_result("TwoFactorRegisterBeginResult"),
        True,
        RpcHandlerGroup.CONFIRMATION,
        "handle_two_factor_register_begin",
    ),
    _rpc(
        "2fa.register_confirm",
        api_schema.TwoFactorRegisterConfirmParams,
        _schema_result("TwoFactorRegisterConfirmResult"),
        True,
        RpcHandlerGroup.CONFIRMATION,
        "handle_two_factor_register_confirm",
    ),
    _rpc(
        "2fa.list",
        api_schema.TwoFactorListParams,
        _schema_result("TwoFactorListResult"),
        True,
        RpcHandlerGroup.CONFIRMATION,
        "handle_two_factor_list",
    ),
    _rpc(
        "2fa.revoke",
        api_schema.TwoFactorRevokeParams,
        _schema_result("TwoFactorRevokeResult"),
        True,
        RpcHandlerGroup.CONFIRMATION,
        "handle_two_factor_revoke",
    ),
    _rpc(
        "signer.register",
        api_schema.SignerRegisterParams,
        _schema_result("SignerRegisterResult"),
        True,
        RpcHandlerGroup.CONFIRMATION,
        "handle_signer_register",
    ),
    _rpc(
        "signer.list",
        api_schema.SignerListParams,
        _schema_result("SignerListResult"),
        True,
        RpcHandlerGroup.CONFIRMATION,
        "handle_signer_list",
    ),
    _rpc(
        "signer.revoke",
        api_schema.SignerRevokeParams,
        _schema_result("SignerRevokeResult"),
        True,
        RpcHandlerGroup.CONFIRMATION,
        "handle_signer_revoke",
    ),
    _rpc(
        "lockdown.set",
        api_schema.LockdownSetParams,
        _schema_result("LockdownSetResult"),
        True,
        RpcHandlerGroup.ADMIN,
        "handle_lockdown_set",
    ),
    _rpc(
        "lockdown.status",
        api_schema.LockdownStatusParams,
        _schema_result("LockdownStatusResult"),
        True,
        RpcHandlerGroup.ADMIN,
        "handle_lockdown_status",
    ),
    _rpc(
        "risk.calibrate",
        api_schema.NoParams,
        _schema_result("RiskCalibrateResult"),
        True,
        RpcHandlerGroup.ADMIN,
        "handle_risk_calibrate",
    ),
    _rpc(
        "channel.ingest",
        api_schema.ChannelIngestParams,
        _schema_result("ChannelIngestResult"),
        True,
        RpcHandlerGroup.ADMIN,
        "handle_channel_ingest",
    ),
    _rpc(
        "channel.pairing_propose",
        api_schema.ChannelPairingProposalParams,
        _schema_result("ChannelPairingProposalResult"),
        True,
        RpcHandlerGroup.ADMIN,
        "handle_channel_pairing_propose",
    ),
    _rpc(
        "delivery.list",
        api_schema.DeliveryListParams,
        _schema_result("DeliveryListResult"),
        True,
        RpcHandlerGroup.ADMIN,
        "handle_delivery_list",
    ),
    _rpc(
        "delivery.inspect",
        api_schema.DeliveryIdentifierParams,
        _schema_result("DeliveryInspectResult"),
        True,
        RpcHandlerGroup.ADMIN,
        "handle_delivery_inspect",
    ),
    _rpc(
        "delivery.resolve",
        api_schema.DeliveryIdentifierParams,
        _schema_result("DeliveryResolveResult"),
        True,
        RpcHandlerGroup.ADMIN,
        "handle_delivery_resolve",
    ),
    _rpc(
        "tool.execute",
        api_schema.ToolExecuteParams,
        _schema_result("ToolExecuteResult"),
        True,
        RpcHandlerGroup.TOOL_EXECUTION,
        "handle_tool_execute",
    ),
    _rpc(
        "browser.paste",
        api_schema.BrowserPasteParams,
        _result_ref("shisad.executors.browser", "BrowserPasteResult"),
        True,
        RpcHandlerGroup.TOOL_EXECUTION,
        "handle_browser_paste",
    ),
    _rpc(
        "browser.screenshot",
        api_schema.BrowserScreenshotParams,
        _result_ref("shisad.executors.browser", "BrowserScreenshotResult"),
        True,
        RpcHandlerGroup.TOOL_EXECUTION,
        "handle_browser_screenshot",
    ),
)

_DESCRIPTOR_NAMES = tuple(descriptor.name for descriptor in _RPC_METHOD_DESCRIPTORS)
if len(_DESCRIPTOR_NAMES) != len(set(_DESCRIPTOR_NAMES)):
    raise RuntimeError("control RPC descriptor names must be unique")

_RPC_METHOD_DESCRIPTOR_BY_NAME = {
    descriptor.name: descriptor for descriptor in _RPC_METHOD_DESCRIPTORS
}


def rpc_method_descriptor(
    name: str,
    *,
    test_mode: bool = False,
) -> RpcMethodDescriptor | None:
    """Resolve one descriptor when it is available in the requested posture."""

    descriptor = _RPC_METHOD_DESCRIPTOR_BY_NAME.get(name)
    if descriptor is None:
        return None
    if descriptor.availability is RpcAvailability.TEST_MODE and not test_mode:
        return None
    return descriptor


def rpc_method_descriptors(*, test_mode: bool = False) -> tuple[RpcMethodDescriptor, ...]:
    """Return the immutable registration projection for the runtime posture."""

    return tuple(
        descriptor
        for descriptor in _RPC_METHOD_DESCRIPTORS
        if descriptor.availability is RpcAvailability.ALWAYS or test_mode
    )


def rpc_method_manifest(*, test_mode: bool = False) -> tuple[RpcMethodManifestEntry, ...]:
    """Return deterministic machine-readable facts from the live descriptors."""

    return tuple(
        RpcMethodManifestEntry(
            name=descriptor.name,
            params_model=(
                f"{descriptor.params_model.__module__}.{descriptor.params_model.__qualname__}"
            ),
            result_model=descriptor.result_model.qualified_name,
            admin_only=descriptor.admin_only,
            handler_group=descriptor.handler_group.value,
            handler_method=descriptor.handler_method,
            availability=descriptor.availability.value,
            readiness=descriptor.readiness.value,
        )
        for descriptor in rpc_method_descriptors(test_mode=test_mode)
    )
