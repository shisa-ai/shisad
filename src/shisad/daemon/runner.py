"""Daemon runner — main event loop for shisad."""

from __future__ import annotations

import asyncio
import contextlib
import logging
from datetime import UTC, datetime
from typing import Any, cast

from pydantic import BaseModel

from shisad.core.api.schema import (
    ActionDecisionParams,
    ActionPendingParams,
    ActionPurgeParams,
    AdminSelfModApplyParams,
    AdminSelfModProposeParams,
    AdminSelfModRollbackParams,
    AdminSoulReadParams,
    AdminSoulUpdateParams,
    AuditQueryParams,
    BrowserPasteParams,
    BrowserScreenshotParams,
    ChannelIngestParams,
    ChannelPairingProposalParams,
    ConfirmationMetricsParams,
    DashboardMarkFalsePositiveParams,
    DashboardQueryParams,
    DevCloseParams,
    DevImplementParams,
    DevRemediateParams,
    DevReviewParams,
    DoctorCheckParams,
    EmailReadParams,
    EmailSearchParams,
    FsListParams,
    FsReadParams,
    FsWriteParams,
    GitDiffParams,
    GitLogParams,
    GitStatusParams,
    LockdownSetParams,
    MemoryEntryParams,
    MemoryExportParams,
    MemoryIngestParams,
    MemoryLifecycleParams,
    MemoryListParams,
    MemoryMintIngressParams,
    MemoryRetrieveParams,
    MemoryReviewQueueParams,
    MemoryRotateKeyParams,
    MemorySupersedeParams,
    MemoryWorkflowStateParams,
    MemoryWriteParams,
    NoParams,
    NoteCreateParams,
    NoteEntryParams,
    NoteExportParams,
    NoteListParams,
    NoteSearchParams,
    PolicyExplainParams,
    RealityCheckReadParams,
    RealityCheckSearchParams,
    SessionCreateParams,
    SessionExportParams,
    SessionGrantCapabilitiesParams,
    SessionImportParams,
    SessionMessageParams,
    SessionRestoreParams,
    SessionRollbackParams,
    SessionSetModeParams,
    SessionTerminateParams,
    SignerListParams,
    SignerRegisterParams,
    SignerRevokeParams,
    SkillInstallParams,
    SkillProfileParams,
    SkillReviewParams,
    SkillRevokeParams,
    TaskCreateParams,
    TaskDisableParams,
    TaskPendingConfirmationsParams,
    TaskTriggerEventParams,
    TodoCompleteParams,
    TodoCreateParams,
    TodoEntryParams,
    TodoExportParams,
    TodoListParams,
    ToolExecuteParams,
    TwoFactorListParams,
    TwoFactorRegisterBeginParams,
    TwoFactorRegisterConfirmParams,
    TwoFactorRevokeParams,
    WebFetchParams,
    WebSearchParams,
)
from shisad.core.config import DaemonConfig, ModelConfig
from shisad.core.interfaces import TypedHandler
from shisad.core.log import setup_logging
from shisad.core.providers.routing import ModelRouter
from shisad.daemon.control_handlers import DaemonControlHandlers
from shisad.daemon.event_wiring import channel_receive_pump
from shisad.daemon.services import DaemonServices

logger = logging.getLogger(__name__)


def _validate_model_endpoints(model_config: ModelConfig, router: ModelRouter) -> None:
    """Compatibility shim for endpoint validation helper moved to services."""
    from shisad.daemon.services import _validate_model_endpoints as _validate

    _validate(model_config, router)


def _warn_on_startup_config_gaps(config: DaemonConfig) -> None:
    if config.assistant_fs_roots:
        return
    logger.warning(
        "No filesystem roots configured - fs.read, fs.list, fs.write, and git "
        "tools will not work. Set SHISAD_ASSISTANT_FS_ROOTS to enable."
    )


def _method_specs(
    handlers: DaemonControlHandlers,
    *,
    test_mode: bool = False,
) -> list[tuple[str, Any, bool, type[BaseModel]]]:
    specs: list[tuple[str, Any, bool, type[BaseModel]]] = [
        ("session.create", handlers.handle_session_create, False, SessionCreateParams),
        ("session.message", handlers.handle_session_message, False, SessionMessageParams),
        ("session.list", handlers.handle_session_list, False, NoParams),
        ("session.terminate", handlers.handle_session_terminate, False, SessionTerminateParams),
        ("session.restore", handlers.handle_session_restore, True, SessionRestoreParams),
        ("session.export", handlers.handle_session_export, True, SessionExportParams),
        ("session.import", handlers.handle_session_import, True, SessionImportParams),
        ("session.rollback", handlers.handle_session_rollback, True, SessionRollbackParams),
        (
            "session.grant_capabilities",
            handlers.handle_session_grant_capabilities,
            True,
            SessionGrantCapabilitiesParams,
        ),
        ("session.set_mode", handlers.handle_session_set_mode, True, SessionSetModeParams),
        ("daemon.status", handlers.handle_daemon_status, False, NoParams),
        ("doctor.check", handlers.handle_doctor_check, False, DoctorCheckParams),
        (
            "admin.selfmod.propose",
            handlers.handle_admin_selfmod_propose,
            True,
            AdminSelfModProposeParams,
        ),
        (
            "admin.selfmod.apply",
            handlers.handle_admin_selfmod_apply,
            True,
            AdminSelfModApplyParams,
        ),
        (
            "admin.selfmod.rollback",
            handlers.handle_admin_selfmod_rollback,
            True,
            AdminSelfModRollbackParams,
        ),
        ("admin.soul.read", handlers.handle_admin_soul_read, True, AdminSoulReadParams),
        (
            "admin.soul.update",
            handlers.handle_admin_soul_update,
            True,
            AdminSoulUpdateParams,
        ),
        ("dev.implement", handlers.handle_dev_implement, True, DevImplementParams),
        ("dev.review", handlers.handle_dev_review, True, DevReviewParams),
        ("dev.remediate", handlers.handle_dev_remediate, True, DevRemediateParams),
        ("dev.close", handlers.handle_dev_close, True, DevCloseParams),
        ("policy.explain", handlers.handle_policy_explain, False, PolicyExplainParams),
        ("daemon.shutdown", handlers.handle_daemon_shutdown, False, NoParams),
        ("audit.query", handlers.handle_audit_query, False, AuditQueryParams),
        (
            "dashboard.audit_explorer",
            handlers.handle_dashboard_audit_explorer,
            True,
            DashboardQueryParams,
        ),
        (
            "dashboard.egress_review",
            handlers.handle_dashboard_egress_review,
            True,
            DashboardQueryParams,
        ),
        (
            "dashboard.skill_provenance",
            handlers.handle_dashboard_skill_provenance,
            True,
            DashboardQueryParams,
        ),
        ("dashboard.alerts", handlers.handle_dashboard_alerts, True, DashboardQueryParams),
        (
            "dashboard.mark_false_positive",
            handlers.handle_dashboard_mark_false_positive,
            True,
            DashboardMarkFalsePositiveParams,
        ),
        (
            "confirmation.metrics",
            handlers.handle_confirmation_metrics,
            True,
            ConfirmationMetricsParams,
        ),
        (
            "memory.mint_ingress_context",
            handlers.handle_memory_mint_ingress_context,
            True,
            MemoryMintIngressParams,
        ),
        ("memory.ingest", handlers.handle_memory_ingest, True, MemoryIngestParams),
        ("memory.retrieve", handlers.handle_memory_retrieve, False, MemoryRetrieveParams),
        ("memory.write", handlers.handle_memory_write, True, MemoryWriteParams),
        ("memory.supersede", handlers.handle_memory_supersede, True, MemorySupersedeParams),
        ("memory.list", handlers.handle_memory_list, False, MemoryListParams),
        (
            "memory.list_review_queue",
            handlers.handle_memory_list_review_queue,
            False,
            MemoryReviewQueueParams,
        ),
        ("memory.get", handlers.handle_memory_get, False, MemoryEntryParams),
        ("memory.delete", handlers.handle_memory_delete, True, MemoryEntryParams),
        ("memory.quarantine", handlers.handle_memory_quarantine, True, MemoryLifecycleParams),
        (
            "memory.unquarantine",
            handlers.handle_memory_unquarantine,
            True,
            MemoryLifecycleParams,
        ),
        (
            "memory.set_workflow_state",
            handlers.handle_memory_set_workflow_state,
            True,
            MemoryWorkflowStateParams,
        ),
        ("memory.export", handlers.handle_memory_export, False, MemoryExportParams),
        ("memory.verify", handlers.handle_memory_verify, True, MemoryEntryParams),
        ("memory.rotate_key", handlers.handle_memory_rotate_key, True, MemoryRotateKeyParams),
        ("note.create", handlers.handle_note_create, True, NoteCreateParams),
        ("note.list", handlers.handle_note_list, False, NoteListParams),
        ("note.search", handlers.handle_note_search, False, NoteSearchParams),
        ("note.get", handlers.handle_note_get, False, NoteEntryParams),
        ("note.delete", handlers.handle_note_delete, True, NoteEntryParams),
        ("note.verify", handlers.handle_note_verify, True, NoteEntryParams),
        ("note.export", handlers.handle_note_export, False, NoteExportParams),
        ("todo.create", handlers.handle_todo_create, True, TodoCreateParams),
        ("todo.list", handlers.handle_todo_list, False, TodoListParams),
        ("todo.complete", handlers.handle_todo_complete, True, TodoCompleteParams),
        ("todo.get", handlers.handle_todo_get, False, TodoEntryParams),
        ("todo.delete", handlers.handle_todo_delete, True, TodoEntryParams),
        ("todo.verify", handlers.handle_todo_verify, True, TodoEntryParams),
        ("todo.export", handlers.handle_todo_export, False, TodoExportParams),
        ("skill.list", handlers.handle_skill_list, True, NoParams),
        ("skill.review", handlers.handle_skill_review, True, SkillReviewParams),
        ("skill.install", handlers.handle_skill_install, True, SkillInstallParams),
        ("skill.profile", handlers.handle_skill_profile, True, SkillProfileParams),
        ("skill.revoke", handlers.handle_skill_revoke, True, SkillRevokeParams),
        ("task.create", handlers.handle_task_create, True, TaskCreateParams),
        ("task.list", handlers.handle_task_list, False, NoParams),
        ("task.disable", handlers.handle_task_disable, True, TaskDisableParams),
        ("task.trigger_event", handlers.handle_task_trigger_event, True, TaskTriggerEventParams),
        (
            "task.pending_confirmations",
            handlers.handle_task_pending_confirmations,
            True,
            TaskPendingConfirmationsParams,
        ),
        ("web.search", handlers.handle_web_search, False, WebSearchParams),
        ("web.fetch", handlers.handle_web_fetch, False, WebFetchParams),
        (
            "realitycheck.search",
            handlers.handle_realitycheck_search,
            False,
            RealityCheckSearchParams,
        ),
        ("realitycheck.read", handlers.handle_realitycheck_read, False, RealityCheckReadParams),
        ("email.search", handlers.handle_email_search, False, EmailSearchParams),
        ("email.read", handlers.handle_email_read, False, EmailReadParams),
        ("fs.list", handlers.handle_fs_list, False, FsListParams),
        ("fs.read", handlers.handle_fs_read, False, FsReadParams),
        ("fs.write", handlers.handle_fs_write, True, FsWriteParams),
        ("git.status", handlers.handle_git_status, False, GitStatusParams),
        ("git.diff", handlers.handle_git_diff, False, GitDiffParams),
        ("git.log", handlers.handle_git_log, False, GitLogParams),
        ("action.pending", handlers.handle_action_pending, True, ActionPendingParams),
        ("action.purge", handlers.handle_action_purge, True, ActionPurgeParams),
        ("action.confirm", handlers.handle_action_confirm, True, ActionDecisionParams),
        ("action.reject", handlers.handle_action_reject, True, ActionDecisionParams),
        (
            "2fa.register_begin",
            handlers.handle_two_factor_register_begin,
            True,
            TwoFactorRegisterBeginParams,
        ),
        (
            "2fa.register_confirm",
            handlers.handle_two_factor_register_confirm,
            True,
            TwoFactorRegisterConfirmParams,
        ),
        ("2fa.list", handlers.handle_two_factor_list, True, TwoFactorListParams),
        ("2fa.revoke", handlers.handle_two_factor_revoke, True, TwoFactorRevokeParams),
        ("signer.register", handlers.handle_signer_register, True, SignerRegisterParams),
        ("signer.list", handlers.handle_signer_list, True, SignerListParams),
        ("signer.revoke", handlers.handle_signer_revoke, True, SignerRevokeParams),
        ("lockdown.set", handlers.handle_lockdown_set, True, LockdownSetParams),
        ("risk.calibrate", handlers.handle_risk_calibrate, True, NoParams),
        ("channel.ingest", handlers.handle_channel_ingest, True, ChannelIngestParams),
        (
            "channel.pairing_propose",
            handlers.handle_channel_pairing_propose,
            True,
            ChannelPairingProposalParams,
        ),
        ("tool.execute", handlers.handle_tool_execute, True, ToolExecuteParams),
        ("browser.paste", handlers.handle_browser_paste, True, BrowserPasteParams),
        ("browser.screenshot", handlers.handle_browser_screenshot, True, BrowserScreenshotParams),
    ]
    if test_mode:
        shutdown_index = next(
            (
                index
                for index, (method_name, *_rest) in enumerate(specs)
                if method_name == "daemon.shutdown"
            ),
            None,
        )
        if shutdown_index is None:
            raise ValueError("runner method registry is missing required daemon.shutdown entry")
        specs.insert(
            shutdown_index + 1,
            ("daemon.reset", handlers.handle_daemon_reset, True, NoParams),
        )
    return specs


def _wrap_tracked_handler(
    *,
    services: DaemonServices,
    method_name: str,
    method_handler: TypedHandler,
) -> TypedHandler:
    async def _tracked_handler(params: BaseModel, ctx: Any) -> Any:
        async with services.rpc_state_lock:
            if services.reset_in_progress and method_name not in {
                "daemon.reset",
                "daemon.shutdown",
            }:
                raise RuntimeError("Cannot execute control RPC while daemon.reset is in progress")
            services.active_rpc_calls += 1
        try:
            return await method_handler(params, ctx)
        finally:
            async with services.rpc_state_lock:
                if services.active_rpc_calls <= 0:
                    logger.warning(
                        (
                            "RPC activity counter underflow while finishing "
                            "method %s; resetting to zero"
                        ),
                        method_name,
                    )
                    services.active_rpc_calls = 0
                else:
                    services.active_rpc_calls -= 1

    return cast(TypedHandler, _tracked_handler)


async def _reminder_delivery_pump(
    *,
    services: DaemonServices,
    handlers: DaemonControlHandlers,
) -> None:
    """Poll scheduler due-runs and route them through the shared background executor."""
    while not services.shutdown_event.is_set():
        try:
            due_runs = services.scheduler.trigger_due(now=datetime.now(UTC))
        except Exception:
            logger.exception("scheduler due-run evaluation failed")
            due_runs = []
        for run in due_runs:
            task = services.scheduler.get_task(run.task_id)
            if task is None:
                continue
            try:
                await handlers._impl.do_task_execute_due_run(
                    run,
                    event_type=f"schedule.{task.schedule.kind.value}",
                )
            except Exception:
                logger.exception("scheduler due-run execution failed for task %s", run.task_id)
        try:
            await asyncio.wait_for(services.shutdown_event.wait(), timeout=1.0)
        except TimeoutError:
            continue


async def run_daemon(config: DaemonConfig) -> None:
    """Run the shisad daemon."""
    setup_logging(level=config.log_level)
    services = await DaemonServices.build(config)
    handlers = DaemonControlHandlers(services=services)
    await services.approval_web.start()

    for method_name, method_handler, admin_only, params_model in _method_specs(
        handlers,
        test_mode=config.test_mode,
    ):
        services.server.register_method(
            method_name,
            _wrap_tracked_handler(
                services=services,
                method_name=method_name,
                method_handler=cast(TypedHandler, method_handler),
            ),
            admin_only=admin_only,
            params_model=params_model,
        )

    await services.server.start()
    logger.info("shisad daemon started")

    # Effective config summary — so operators can verify settings from logs
    _search_status = "enabled" if config.web_search_enabled else "DISABLED"
    _fetch_status = "enabled" if config.web_fetch_enabled else "DISABLED"
    _search_backend = config.web_search_backend_url or "(not configured)"
    _n_domains = len(config.web_allowed_domains)
    logger.info(
        "Config: web.search=%s backend=%s web.fetch=%s allowed_domains=%d fs_roots=%s",
        _search_status,
        _search_backend,
        _fetch_status,
        _n_domains,
        config.assistant_fs_roots,
    )
    _warn_on_startup_config_gaps(config)
    channel_pump_tasks: list[asyncio.Task[None]] = []
    reminder_pump_task = asyncio.create_task(
        _reminder_delivery_pump(services=services, handlers=handlers)
    )
    for channel_name, channel in services.channels.items():
        channel_pump_tasks.append(
            asyncio.create_task(
                channel_receive_pump(
                    channel_name=channel_name,
                    channel=channel,
                    shutdown_event=services.shutdown_event,
                    handlers=handlers,
                    state_store=services.channel_state_store,
                )
            )
        )

    try:
        await services.shutdown_event.wait()
    finally:
        for task in channel_pump_tasks:
            task.cancel()
        reminder_pump_task.cancel()
        for task in channel_pump_tasks:
            with contextlib.suppress(asyncio.CancelledError):
                await task
        with contextlib.suppress(asyncio.CancelledError):
            await reminder_pump_task
        await services.shutdown()
        logger.info("shisad daemon stopped")
