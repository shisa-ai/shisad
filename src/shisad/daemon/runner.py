"""Daemon runner — main event loop for shisad."""

from __future__ import annotations

import asyncio
import contextlib
import logging
from datetime import UTC, datetime
from typing import Any, cast
from urllib.parse import urlparse

from pydantic import BaseModel

from shisad.channels.base import DeliveryTarget
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
    MemoryListParams,
    MemoryRetrieveParams,
    MemoryRotateKeyParams,
    MemoryWriteParams,
    NoParams,
    NoteCreateParams,
    NoteEntryParams,
    NoteExportParams,
    NoteListParams,
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
    TodoCreateParams,
    TodoEntryParams,
    TodoExportParams,
    TodoListParams,
    ToolExecuteParams,
    WebFetchParams,
    WebSearchParams,
)
from shisad.core.config import DaemonConfig, ModelConfig
from shisad.core.events import AnomalyReported, TaskTriggered
from shisad.core.interfaces import TypedHandler
from shisad.core.providers.routing import ModelRouter
from shisad.core.types import Capability
from shisad.daemon.control_handlers import DaemonControlHandlers
from shisad.daemon.event_wiring import channel_receive_pump
from shisad.daemon.services import DaemonServices

logger = logging.getLogger(__name__)


def _recipient_matches_rule(recipient: str, rule: str) -> bool:
    normalized_recipient = recipient.strip().lower()
    normalized_rule = rule.strip().lower()
    if not normalized_recipient or not normalized_rule:
        return False
    if normalized_rule.startswith("*."):
        return normalized_recipient.endswith(normalized_rule[1:])
    return normalized_recipient == normalized_rule


def _recipient_domain(recipient: str) -> str:
    value = recipient.strip()
    if not value:
        return ""
    parsed = urlparse(value)
    if parsed.hostname:
        return parsed.hostname.lower()
    if "@" in value:
        _, _, domain = value.rpartition("@")
        return domain.lower().strip()
    return ""


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
        ("note.create", handlers.handle_note_create, True, NoteCreateParams),
        ("note.list", handlers.handle_note_list, False, NoteListParams),
        ("note.get", handlers.handle_note_get, False, NoteEntryParams),
        ("note.delete", handlers.handle_note_delete, True, NoteEntryParams),
        ("note.verify", handlers.handle_note_verify, True, NoteEntryParams),
        ("note.export", handlers.handle_note_export, False, NoteExportParams),
        ("todo.create", handlers.handle_todo_create, True, TodoCreateParams),
        ("todo.list", handlers.handle_todo_list, False, TodoListParams),
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
        ("fs.list", handlers.handle_fs_list, False, FsListParams),
        ("fs.read", handlers.handle_fs_read, False, FsReadParams),
        ("fs.write", handlers.handle_fs_write, True, FsWriteParams),
        ("git.status", handlers.handle_git_status, False, GitStatusParams),
        ("git.diff", handlers.handle_git_diff, False, GitDiffParams),
        ("git.log", handlers.handle_git_log, False, GitLogParams),
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


async def _reminder_delivery_pump(*, services: DaemonServices) -> None:
    """Poll scheduler due-runs and deliver reminder tasks over channel delivery."""
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
            await services.event_bus.publish(
                TaskTriggered(
                    session_id=None,
                    actor="scheduler",
                    task_id=task.id,
                    event_type=f"schedule.{task.schedule.kind.value}",
                )
            )
            available_caps = set(services.policy_loader.policy.default_capabilities)
            if not available_caps:
                available_caps = set(task.capability_snapshot)
            if not services.scheduler.can_execute_with_capabilities(
                task.id,
                {Capability.MESSAGE_SEND},
                available_capabilities=available_caps,
            ):
                await services.event_bus.publish(
                    AnomalyReported(
                        session_id=None,
                        actor="scheduler",
                        severity="warning",
                        description=(
                            f"Scheduled reminder blocked by capability snapshot for task {task.id}"
                        ),
                        recommended_action="review_task_capability_snapshot",
                    )
                )
                continue
            channel = task.delivery_target.get("channel", "").strip()
            recipient = task.delivery_target.get("recipient", "").strip()
            if not channel or not recipient:
                await services.event_bus.publish(
                    AnomalyReported(
                        session_id=None,
                        actor="scheduler",
                        severity="warning",
                        description=(
                            "Scheduled reminder missing delivery target "
                            f"for task {task.id}"
                        ),
                        recommended_action="update_task_delivery_target",
                    )
                )
                continue
            recipient_allowlist = [
                str(item).strip()
                for item in getattr(task, "allowed_recipients", [])
                if str(item).strip()
            ]
            if recipient_allowlist and not any(
                _recipient_matches_rule(recipient, rule) for rule in recipient_allowlist
            ):
                await services.event_bus.publish(
                    AnomalyReported(
                        session_id=None,
                        actor="scheduler",
                        severity="warning",
                        description=(
                            "Scheduled reminder blocked by recipient allowlist "
                            f"for task {task.id}"
                        ),
                        recommended_action="review_task_delivery_target",
                    )
                )
                continue
            domain_allowlist = [
                str(item).strip()
                for item in getattr(task, "allowed_domains", [])
                if str(item).strip()
            ]
            if domain_allowlist:
                destination_domain = _recipient_domain(recipient)
                if not destination_domain or not any(
                    _recipient_matches_rule(destination_domain, rule) for rule in domain_allowlist
                ):
                    await services.event_bus.publish(
                        AnomalyReported(
                            session_id=None,
                            actor="scheduler",
                            severity="warning",
                            description=(
                                "Scheduled reminder blocked by domain allowlist "
                                f"for task {task.id}"
                            ),
                            recommended_action="review_task_allowed_domains",
                        )
                    )
                    continue
            delivery_result = await services.delivery.send(
                target=DeliveryTarget(
                    channel=channel,
                    recipient=recipient,
                    workspace_hint=task.delivery_target.get("workspace_hint", ""),
                    thread_id=task.delivery_target.get("thread_id", ""),
                ),
                message=task.goal,
            )
            if not delivery_result.sent:
                await services.event_bus.publish(
                    AnomalyReported(
                        session_id=None,
                        actor="scheduler",
                        severity="warning",
                        description=(
                            "Scheduled reminder delivery failed "
                            f"for task {task.id} ({delivery_result.reason})"
                        ),
                        recommended_action="check_channel_connectivity",
                    )
                )
        try:
            await asyncio.wait_for(services.shutdown_event.wait(), timeout=1.0)
        except TimeoutError:
            continue


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
    reminder_pump_task = asyncio.create_task(_reminder_delivery_pump(services=services))
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
