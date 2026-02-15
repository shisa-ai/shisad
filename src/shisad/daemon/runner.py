"""Daemon runner — main event loop for shisad."""

from __future__ import annotations

import asyncio
import contextlib
import logging
from typing import Any, cast

from pydantic import BaseModel

from shisad.core.api.schema import (
    ActionDecisionParams,
    ActionPendingParams,
    AuditQueryParams,
    BrowserPasteParams,
    BrowserScreenshotParams,
    ChannelIngestParams,
    ConfirmationMetricsParams,
    DashboardMarkFalsePositiveParams,
    DashboardQueryParams,
    LockdownSetParams,
    MemoryEntryParams,
    MemoryExportParams,
    MemoryIngestParams,
    MemoryListParams,
    MemoryRetrieveParams,
    MemoryRotateKeyParams,
    MemoryWriteParams,
    NoParams,
    PolicyExplainParams,
    SessionCreateParams,
    SessionGrantCapabilitiesParams,
    SessionMessageParams,
    SessionRestoreParams,
    SessionRollbackParams,
    SkillInstallParams,
    SkillProfileParams,
    SkillReviewParams,
    SkillRevokeParams,
    TaskCreateParams,
    TaskDisableParams,
    TaskPendingConfirmationsParams,
    TaskTriggerEventParams,
    ToolExecuteParams,
)
from shisad.core.config import DaemonConfig, ModelConfig
from shisad.core.interfaces import TypedHandler
from shisad.core.providers.routing import ModelRouter
from shisad.daemon.control_handlers import DaemonControlHandlers
from shisad.daemon.event_wiring import channel_receive_pump
from shisad.daemon.services import DaemonServices

logger = logging.getLogger(__name__)


def _validate_model_endpoints(model_config: ModelConfig, router: ModelRouter) -> None:
    """Compatibility shim for endpoint validation helper moved to services."""
    from shisad.daemon.services import _validate_model_endpoints as _validate

    _validate(model_config, router)


def _method_specs(
    handlers: DaemonControlHandlers,
) -> list[tuple[str, Any, bool, type[BaseModel]]]:
    return [
        ("session.create", handlers.handle_session_create, False, SessionCreateParams),
        ("session.message", handlers.handle_session_message, False, SessionMessageParams),
        ("session.list", handlers.handle_session_list, False, NoParams),
        ("session.restore", handlers.handle_session_restore, False, SessionRestoreParams),
        ("session.rollback", handlers.handle_session_rollback, True, SessionRollbackParams),
        (
            "session.grant_capabilities",
            handlers.handle_session_grant_capabilities,
            True,
            SessionGrantCapabilitiesParams,
        ),
        ("daemon.status", handlers.handle_daemon_status, False, NoParams),
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
        ("memory.ingest", handlers.handle_memory_ingest, True, MemoryIngestParams),
        ("memory.retrieve", handlers.handle_memory_retrieve, False, MemoryRetrieveParams),
        ("memory.write", handlers.handle_memory_write, True, MemoryWriteParams),
        ("memory.list", handlers.handle_memory_list, False, MemoryListParams),
        ("memory.get", handlers.handle_memory_get, False, MemoryEntryParams),
        ("memory.delete", handlers.handle_memory_delete, True, MemoryEntryParams),
        ("memory.export", handlers.handle_memory_export, False, MemoryExportParams),
        ("memory.verify", handlers.handle_memory_verify, True, MemoryEntryParams),
        ("memory.rotate_key", handlers.handle_memory_rotate_key, True, MemoryRotateKeyParams),
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
        ("action.pending", handlers.handle_action_pending, True, ActionPendingParams),
        ("action.confirm", handlers.handle_action_confirm, True, ActionDecisionParams),
        ("action.reject", handlers.handle_action_reject, True, ActionDecisionParams),
        ("lockdown.set", handlers.handle_lockdown_set, True, LockdownSetParams),
        ("risk.calibrate", handlers.handle_risk_calibrate, True, NoParams),
        ("channel.ingest", handlers.handle_channel_ingest, True, ChannelIngestParams),
        ("tool.execute", handlers.handle_tool_execute, True, ToolExecuteParams),
        ("browser.paste", handlers.handle_browser_paste, True, BrowserPasteParams),
        ("browser.screenshot", handlers.handle_browser_screenshot, True, BrowserScreenshotParams),
    ]


async def run_daemon(config: DaemonConfig) -> None:
    """Run the shisad daemon."""
    logging.basicConfig(level=getattr(logging, config.log_level.upper(), logging.INFO))
    services = await DaemonServices.build(config)
    handlers = DaemonControlHandlers(services=services)

    for method_name, method_handler, admin_only, params_model in _method_specs(handlers):
        services.server.register_method(
            method_name,
            cast(TypedHandler, method_handler),
            admin_only=admin_only,
            params_model=params_model,
        )

    await services.server.start()
    logger.info("shisad daemon started")
    channel_pump_tasks: list[asyncio.Task[None]] = []
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
        for task in channel_pump_tasks:
            with contextlib.suppress(asyncio.CancelledError):
                await task
        await services.shutdown()
        logger.info("shisad daemon stopped")
