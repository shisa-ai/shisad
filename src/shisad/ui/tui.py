"""Optional terminal UI surface built on top of control API endpoints."""

from __future__ import annotations

import asyncio
import importlib
import json
import logging
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from shisad.core.api.transport import ControlClient
from shisad.core.plan_steps import normalize_plan_step_status
from shisad.ui.confirmation import approval_proof_placeholder, render_pending_action

logger = logging.getLogger(__name__)

_MAX_TASK_PENDING_ACTION_ENRICHMENTS = 20
_MAX_TASK_PENDING_CONFIRMATION_ROWS = 20


@dataclass(slots=True)
class TuiSnapshot:
    sessions: list[dict[str, Any]] = field(default_factory=list)
    pending_actions: list[dict[str, Any]] = field(default_factory=list)
    plan_steps: list[dict[str, Any]] = field(default_factory=list)
    tasks: list[dict[str, Any]] = field(default_factory=list)
    channel_health: list[dict[str, Any]] = field(default_factory=list)
    alerts: list[dict[str, Any]] = field(default_factory=list)
    audit_events: list[dict[str, Any]] = field(default_factory=list)


def _safe_plan_step_rows(raw_steps: list[Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for index, raw in enumerate(raw_steps):
        if not isinstance(raw, Mapping):
            continue
        status = normalize_plan_step_status(raw.get("status", "pending"))
        order = raw.get("order", index + 1)
        try:
            order_value = int(order)
        except (TypeError, ValueError):
            order_value = index + 1
        depends_raw = raw.get("depends_on", [])
        depends_on = (
            [str(item).strip() for item in depends_raw if str(item).strip()]
            if isinstance(depends_raw, list)
            else []
        )
        rows.append(
            {
                "id": str(raw.get("id", "")).strip(),
                "session_id": str(raw.get("session_id", "")).strip(),
                "plan_hash": str(raw.get("plan_hash", "")).strip(),
                "order": max(1, order_value),
                "title": str(raw.get("title", "") or "Current request").strip(),
                "status": status,
                "current": bool(raw.get("current", False)) and status in {"in_progress", "blocked"},
                "depends_on": depends_on,
                "blocked_reason": str(raw.get("blocked_reason", "")).strip()
                if status == "blocked"
                else "",
            }
        )
    rows.sort(
        key=lambda row: (
            str(row.get("session_id", "")),
            int(row.get("order", 0)),
            str(row.get("id", "")),
        )
    )
    return rows


def _safe_task_rows(raw_tasks: list[Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for raw in raw_tasks:
        if not isinstance(raw, Mapping):
            continue
        task_id = str(raw.get("task_id", raw.get("id", ""))).strip()
        status = str(raw.get("status", "")).strip().lower()
        if not status and "enabled" in raw:
            status = "enabled" if bool(raw.get("enabled", False)) else "disabled"
        enabled = bool(raw.get("enabled", status == "enabled"))
        schedule = raw.get("schedule", {})
        delivery = raw.get("delivery_target", {})
        schedule_kind = str(raw.get("schedule_kind", "")).strip()
        if isinstance(schedule, Mapping):
            schedule_kind = schedule_kind or str(schedule.get("kind", "")).strip()
        delivery_channel = str(raw.get("delivery_channel", "")).strip()
        if isinstance(delivery, Mapping):
            delivery_channel = delivery_channel or str(delivery.get("channel", "")).strip()
        pending = _safe_task_pending_rows(raw.get("pending_confirmations", []))
        try:
            pending_count = int(raw.get("pending_confirmation_count", len(pending)) or 0)
        except (TypeError, ValueError):
            pending_count = len(pending)
        rows.append(
            {
                "id": task_id,
                "title": str(raw.get("title", "")).strip(),
                "status": status or "unknown",
                "enabled": enabled,
                "schedule_kind": schedule_kind,
                "schedule_summary": str(raw.get("schedule_summary", "")).strip(),
                "last_triggered_at": str(raw.get("last_triggered_at", "")),
                "next_run_at": str(raw.get("next_run_at", "")),
                "delivery_channel": delivery_channel,
                "pending_confirmations": pending,
                "pending_confirmation_count": max(pending_count, len(pending)),
                "confirmation_needed": bool(raw.get("confirmation_needed", False)) or bool(pending),
            }
        )
    return rows


def _safe_task_pending_rows(raw_pending: Any) -> list[dict[str, Any]]:
    if not isinstance(raw_pending, list):
        return []
    rows: list[dict[str, Any]] = []
    for raw in raw_pending[:_MAX_TASK_PENDING_CONFIRMATION_ROWS]:
        if not isinstance(raw, Mapping):
            continue
        rows.append(
            {
                "confirmation_id": str(raw.get("confirmation_id", "")).strip(),
                "action_id": str(raw.get("action_id", "")).strip(),
                "identity": dict(raw.get("identity", {}))
                if isinstance(raw.get("identity"), Mapping)
                else {},
                "task_id": str(raw.get("task_id", "")).strip(),
                "tool_name": str(raw.get("tool_name", "")).strip(),
                "event_type": str(raw.get("event_type", "")).strip(),
                "payload_taint": str(raw.get("payload_taint", "")).strip(),
                "reason": str(raw.get("reason", "")).strip(),
                "status": str(raw.get("status", "")).strip() or "pending",
                "lifecycle_state": (str(raw.get("lifecycle_state", "")).strip() or "pending"),
                "result_id": str(raw.get("result_id", "")).strip(),
                "queued_at": str(raw.get("queued_at", "")).strip(),
            }
        )
    return rows


def _task_status(row: Mapping[str, Any]) -> str:
    status = str(row.get("status", "")).strip().lower()
    if status:
        return status
    if "enabled" in row:
        return "enabled" if bool(row.get("enabled", False)) else "disabled"
    return "unknown"


def _task_enabled(row: Mapping[str, Any]) -> bool:
    if "enabled" in row:
        return bool(row.get("enabled", False))
    return _task_status(row) == "enabled"


def _task_scope_from_sessions(raw_sessions: Any) -> tuple[str, str, str] | None:
    if not isinstance(raw_sessions, list):
        return None
    scoped_sessions: list[tuple[str, str, str]] = []
    for raw in raw_sessions:
        if not isinstance(raw, Mapping):
            continue
        session_id = str(raw.get("id", "")).strip()
        if not session_id:
            continue
        if str(raw.get("state", "")).strip().lower() not in {"", "active"}:
            continue
        if str(raw.get("role", "")).strip().lower() not in {"", "orchestrator"}:
            continue
        if str(raw.get("channel", "")).strip().lower() != "cli":
            continue
        if str(raw.get("mode", "")).strip().lower() not in {"", "default"}:
            continue
        user_id = str(raw.get("user_id", "")).strip()
        workspace_id = str(raw.get("workspace_id", "")).strip()
        if user_id and workspace_id:
            scoped_sessions.append((session_id, user_id, workspace_id))
    scopes = {(user_id, workspace_id) for _session_id, user_id, workspace_id in scoped_sessions}
    if len(scopes) != 1:
        return None
    return scoped_sessions[0] if scoped_sessions else None


def _pending_actions_by_confirmation_id(
    actions: list[dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    return {
        str(row.get("confirmation_id", "")).strip(): row
        for row in actions
        if str(row.get("confirmation_id", "")).strip()
    }


def _task_pending_confirmation_enrichment_plan(
    raw_tasks: list[Any],
    pending_by_id: Mapping[str, Mapping[str, Any]],
) -> tuple[list[str], set[str]]:
    fetch_ids: list[str] = []
    limited_ids: set[str] = set()
    seen = set(pending_by_id)
    for raw in raw_tasks:
        if not isinstance(raw, Mapping):
            continue
        pending = raw.get("pending_confirmations", [])
        if not isinstance(pending, list):
            continue
        for item in pending[:_MAX_TASK_PENDING_CONFIRMATION_ROWS]:
            if not isinstance(item, Mapping):
                continue
            confirmation_id = str(item.get("confirmation_id", "")).strip()
            if not confirmation_id or confirmation_id in seen:
                continue
            seen.add(confirmation_id)
            if len(fetch_ids) < _MAX_TASK_PENDING_ACTION_ENRICHMENTS:
                fetch_ids.append(confirmation_id)
            else:
                limited_ids.add(confirmation_id)
    return fetch_ids, limited_ids


def _enrich_task_rows_with_pending_actions(
    task_rows: list[dict[str, Any]],
    pending_by_id: Mapping[str, Mapping[str, Any]],
    limited_ids: set[str],
) -> None:
    for task in task_rows:
        pending = task.get("pending_confirmations", [])
        if not isinstance(pending, list):
            continue
        for item in pending:
            if not isinstance(item, dict):
                continue
            confirmation_id = str(item.get("confirmation_id", "")).strip()
            action = pending_by_id.get(confirmation_id)
            if action:
                item["pending_action"] = dict(action)
            elif confirmation_id in limited_ids:
                item["metadata_limited"] = True


def _task_pending_approval_summaries(
    row: Mapping[str, Any],
    pending_by_id: Mapping[str, Mapping[str, Any]],
) -> list[str]:
    pending = row.get("pending_confirmations", [])
    if not isinstance(pending, list):
        pending = []
    summaries: list[str] = []
    for item in pending:
        if not isinstance(item, Mapping):
            continue
        confirmation_id = str(item.get("confirmation_id", "")).strip()
        if not confirmation_id:
            continue
        action = pending_by_id.get(confirmation_id, {})
        if not action and isinstance(item, Mapping):
            embedded_action = item.get("pending_action", {})
            if isinstance(embedded_action, Mapping):
                action = embedded_action
        capability = action.get("channel_capability", {}) if isinstance(action, Mapping) else {}
        route = (
            str(capability.get("approval_route", "")).strip()
            if isinstance(capability, Mapping)
            else ""
        )
        proof = str(action.get("required_proof_tier", "")).strip()
        method = str(action.get("selected_backend_method", "")).strip()
        has_action_metadata = isinstance(action, Mapping) and bool(action)
        can_carry = (
            bool(capability.get("can_carry", False)) if isinstance(capability, Mapping) else False
        )
        can_collect_inline_totp = (
            bool(capability.get("can_collect_selected_method", False)) and method == "totp"
            if isinstance(capability, Mapping)
            else False
        )
        can_reject = (
            bool(capability.get("can_reject", True)) if isinstance(capability, Mapping) else True
        )
        requires_second_factor = (
            bool(capability.get("requires_second_factor", False))
            if isinstance(capability, Mapping)
            else False
        ) or method in {"totp", "recovery_code"}
        parts = [f"confirmation={confirmation_id}"]
        if proof:
            parts.append(f"proof={proof}")
        if method:
            parts.append(f"method={method}")
        if route:
            parts.append(f"route={route}")
        if has_action_metadata and (can_carry or can_collect_inline_totp):
            if requires_second_factor:
                proof_placeholder = approval_proof_placeholder(method)
                parts.append(f"approve_hint=c {confirmation_id} {proof_placeholder}")
            else:
                parts.append(f"approve_hint=c {confirmation_id}")
        else:
            reason = (
                str(capability.get("cannot_carry_reason", "")).strip()
                if isinstance(capability, Mapping)
                else ""
            )
            if not reason and has_action_metadata:
                reason = "surface_cannot_carry"
            if not reason:
                reason = (
                    "metadata_enrichment_limit_reached"
                    if bool(item.get("metadata_limited", False))
                    else "confirmation_metadata_unavailable"
                )
            parts.append(f"approve_unavailable={reason}")
        if can_reject:
            parts.append(f"reject_hint=x {confirmation_id}")
        summaries.append(" ".join(parts))
    try:
        pending_count = int(row.get("pending_confirmation_count", 0) or 0)
    except (TypeError, ValueError):
        pending_count = 0
    if summaries:
        if pending_count > len(pending):
            summaries.append(f"pending_count={pending_count} rendered={len(pending)}")
        return summaries
    if pending_count > 0:
        return [f"pending_count={pending_count}"]
    return []


def _show_plan_step_sessions(rows: list[dict[str, Any]]) -> bool:
    session_ids = {str(row.get("session_id", "")).strip() for row in rows if row.get("session_id")}
    return len(session_ids) > 1


def _derive_channel_status(
    *,
    enabled: bool,
    available: bool,
    connected: bool,
    status: object,
) -> str:
    normalized = str(status or "").strip()
    if normalized:
        return normalized
    if not enabled:
        return "disabled"
    if not available:
        return "misconfigured"
    if not connected:
        return "degraded"
    return "ok"


def _safe_channel_rows(raw_channels: Mapping[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for raw_name, raw in raw_channels.items():
        name = str(raw_name).strip().lower()
        if not isinstance(raw, Mapping):
            raw = {}
        enabled = bool(raw.get("enabled", False))
        available = bool(raw.get("available", False))
        connected = bool(raw.get("connected", False))
        rows.append(
            {
                "channel": name,
                "enabled": enabled,
                "available": available,
                "connected": connected,
                "status": _derive_channel_status(
                    enabled=enabled,
                    available=available,
                    connected=connected,
                    status=raw.get("status", ""),
                ),
            }
        )
    rows.sort(key=lambda row: str(row.get("channel", "")))
    return rows


def _safe_pending_action_rows(raw_actions: list[Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for item in raw_actions:
        if not isinstance(item, Mapping):
            continue
        capability = item.get("channel_capability", {})
        rows.append(
            {
                "confirmation_id": str(item.get("confirmation_id", "")),
                "action_id": str(item.get("action_id", "")),
                "identity": dict(item.get("identity", {}))
                if isinstance(item.get("identity"), Mapping)
                else {},
                "origin_turn_id": str(item.get("origin_turn_id", "")),
                "execution_attempt_id": str(item.get("execution_attempt_id", "")),
                "result_id": str(item.get("result_id", "")),
                "followup_id": str(item.get("followup_id", "")),
                "tool_name": str(item.get("tool_name", "")),
                "status": str(item.get("status", "")),
                "lifecycle_state": str(item.get("lifecycle_state", "")),
                "created_at": str(item.get("created_at", "")),
                "risk_level": str(item.get("risk_level", "")),
                "required_proof_tier": str(item.get("required_proof_tier", "")),
                "required_level": str(item.get("required_level", "")),
                "selected_backend_id": str(item.get("selected_backend_id", "")),
                "selected_backend_method": str(item.get("selected_backend_method", "")),
                "channel_capability": dict(capability) if isinstance(capability, Mapping) else {},
                "allowed_channel_principals": [
                    str(value).strip()
                    for value in item.get("allowed_channel_principals", [])
                    if str(value).strip()
                ]
                if isinstance(item.get("allowed_channel_principals", []), list)
                else [],
                "safe_preview": str(item.get("safe_preview", "")),
                "warnings": [
                    str(value).strip() for value in item.get("warnings", []) if str(value).strip()
                ]
                if isinstance(item.get("warnings", []), list)
                else [],
            }
        )
    return rows


async def fetch_snapshot(socket_path: Path) -> TuiSnapshot:
    """Fetch a multi-panel snapshot from daemon control API."""
    client = ControlClient(socket_path)

    async def _safe_call(
        method: str,
        params: dict[str, object] | None = None,
        *,
        default: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        fallback = dict(default or {})
        try:
            payload = await client.call(method, params)
        except Exception:
            logger.exception("tui snapshot call failed: %s", method)
            return fallback
        if not isinstance(payload, Mapping):
            logger.warning("tui snapshot call returned non-mapping payload: %s", method)
            return fallback
        return dict(payload)

    try:
        await client.connect()
        sessions_result = await _safe_call("session.list", default={"sessions": []})
        raw_sessions = [
            dict(item) for item in sessions_result.get("sessions", []) if isinstance(item, Mapping)
        ]
        pending_result = await _safe_call(
            "action.pending",
            {"status": "pending", "limit": 20},
            default={"actions": []},
        )
        pending_action_rows = _safe_pending_action_rows(
            [item for item in pending_result.get("actions", [])]
        )
        pending_by_id = _pending_actions_by_confirmation_id(pending_action_rows)
        plan_steps_result = await _safe_call("plan.steps", {"limit": 20}, default={"steps": []})
        task_scope = _task_scope_from_sessions(raw_sessions)
        if task_scope is not None:
            task_session_id, task_user_id, task_workspace_id = task_scope
            tasks_result = await _safe_call(
                "task.status_snapshot",
                {"session_id": task_session_id, "limit": 20},
                default={"tasks": []},
            )
            if (
                str(tasks_result.get("scope_status", "")).strip() != "scoped"
                or str(tasks_result.get("user_id", "")).strip() != task_user_id
                or str(tasks_result.get("workspace_id", "")).strip() != task_workspace_id
            ):
                tasks_result = {"tasks": []}
        else:
            tasks_result = {"tasks": []}
        raw_task_rows = [item for item in tasks_result.get("tasks", [])]
        missing_task_confirmation_ids, limited_task_confirmation_ids = (
            _task_pending_confirmation_enrichment_plan(raw_task_rows, pending_by_id)
        )
        for confirmation_id in missing_task_confirmation_ids:
            exact_pending = await _safe_call(
                "action.pending",
                {
                    "confirmation_id": confirmation_id,
                    "status": "pending",
                    "limit": 1,
                    "include_ui": True,
                },
                default={"actions": []},
            )
            for action in _safe_pending_action_rows(
                [item for item in exact_pending.get("actions", [])]
            ):
                confirmation_id = str(action.get("confirmation_id", "")).strip()
                if confirmation_id:
                    pending_by_id[confirmation_id] = action
        task_rows = _safe_task_rows(raw_task_rows)
        _enrich_task_rows_with_pending_actions(
            task_rows,
            pending_by_id,
            limited_task_confirmation_ids,
        )
        status_result = await _safe_call("daemon.status", default={"channels": {}})
        alerts_result = await _safe_call("dashboard.alerts", {"limit": 20}, default={"alerts": []})
        audit_result = await _safe_call(
            "dashboard.audit_explorer",
            {"limit": 20},
            default={"events": []},
        )
    finally:
        await client.close()
    return TuiSnapshot(
        sessions=raw_sessions,
        pending_actions=pending_action_rows,
        plan_steps=_safe_plan_step_rows([item for item in plan_steps_result.get("steps", [])]),
        tasks=task_rows,
        channel_health=_safe_channel_rows(
            status_result.get("channels", {})
            if isinstance(status_result.get("channels", {}), Mapping)
            else {}
        ),
        alerts=[
            dict(item) for item in alerts_result.get("alerts", []) if isinstance(item, Mapping)
        ],
        audit_events=[
            dict(item) for item in audit_result.get("events", []) if isinstance(item, Mapping)
        ],
    )


def _channel_status(row: Mapping[str, Any]) -> str:
    return _derive_channel_status(
        enabled=bool(row.get("enabled", False)),
        available=bool(row.get("available", False)),
        connected=bool(row.get("connected", False)),
        status=row.get("status", ""),
    ).lower()


def _channel_is_configured(row: Mapping[str, Any]) -> bool:
    status = _channel_status(row)
    if status == "disabled":
        return False
    if status in {"ok", "degraded", "misconfigured"}:
        return True
    if bool(row.get("enabled", False)):
        return True
    return bool(row.get("available", False)) or bool(row.get("connected", False))


def _configured_channel_rows(snapshot: TuiSnapshot) -> list[dict[str, Any]]:
    return [row for row in snapshot.channel_health if _channel_is_configured(row)]


def _alert_acknowledged(row: Mapping[str, Any]) -> bool:
    return bool(str(row.get("acknowledged_reason", "")).strip())


def _active_alert_rows(snapshot: TuiSnapshot) -> list[dict[str, Any]]:
    return [row for row in snapshot.alerts if not _alert_acknowledged(row)]


def _acknowledged_alert_rows(snapshot: TuiSnapshot) -> list[dict[str, Any]]:
    return [row for row in snapshot.alerts if _alert_acknowledged(row)]


def render_plain(snapshot: TuiSnapshot) -> str:
    """Render a deterministic plaintext dashboard for non-rich terminals."""
    channel_rows = _configured_channel_rows(snapshot)
    active_alerts = _active_alert_rows(snapshot)
    acknowledged_alerts = _acknowledged_alert_rows(snapshot)
    plan_step_rows = _safe_plan_step_rows(snapshot.plan_steps)
    pending_by_id = _pending_actions_by_confirmation_id(snapshot.pending_actions)
    lines: list[str] = []
    lines.append("SHISAD TUI SNAPSHOT")
    lines.append("SUMMARY:")
    lines.append("  " + _summary_counts_line(snapshot))
    lines.append("SESSIONS:")
    if not snapshot.sessions:
        lines.append("  no active sessions")
    for row in snapshot.sessions:
        lines.append(
            "  "
            f"{row.get('id', '')} user={row.get('user_id', '')} "
            f"lockdown={row.get('lockdown_level', '')}"
        )
    lines.append("PENDING CONFIRMATIONS:")
    if not snapshot.pending_actions:
        lines.append("  no pending confirmations")
    for row in snapshot.pending_actions:
        lines.append("  " + render_pending_action(row))
    lines.append("WORK BREAKDOWN:")
    if not plan_step_rows:
        lines.append("  no active plan")
    show_plan_sessions = _show_plan_step_sessions(plan_step_rows)
    for row in plan_step_rows:
        marker = "> " if bool(row.get("current", False)) else ""
        details: list[str] = []
        session_id = str(row.get("session_id", "")).strip()
        if show_plan_sessions and session_id:
            details.append(f"session={session_id}")
        depends_on = row.get("depends_on", [])
        if isinstance(depends_on, list) and depends_on:
            details.append("depends_on=" + ",".join(str(item) for item in depends_on))
        blocked_reason = str(row.get("blocked_reason", "")).strip()
        if blocked_reason:
            details.append(f"blocked={blocked_reason}")
        suffix = f" {' '.join(details)}" if details else ""
        lines.append(
            "  "
            f"{marker}[{row.get('status', 'unknown')}] "
            f"{row.get('order', '')}. {row.get('title', '')}{suffix}"
        )
    lines.append("TASKS:")
    if not snapshot.tasks:
        lines.append("  no background tasks")
    for row in snapshot.tasks:
        task_details: list[str] = []
        schedule_summary = str(row.get("schedule_summary", "")).strip()
        if schedule_summary:
            task_details.append(f"summary={schedule_summary}")
        last_triggered_at = str(row.get("last_triggered_at", "")).strip()
        if last_triggered_at:
            task_details.append(f"last={last_triggered_at}")
        next_run_at = str(row.get("next_run_at", "")).strip()
        if next_run_at:
            task_details.append(f"next={next_run_at}")
        suffix = f" {' '.join(task_details)}" if task_details else ""
        lines.append(
            "  "
            f"{row.get('id', '')} "
            f"status={_task_status(row)} "
            f"enabled={_task_enabled(row)} "
            f"schedule={row.get('schedule_kind', '')} "
            f"delivery={row.get('delivery_channel', '')}{suffix}"
        )
        for approval in _task_pending_approval_summaries(row, pending_by_id):
            lines.append(f"    waiting_on_approval {approval}")
    lines.append("CHANNEL HEALTH:")
    if not channel_rows:
        lines.append("  no configured channels")
    for row in channel_rows:
        lines.append(
            "  "
            f"{row.get('channel', '')} "
            f"enabled={row.get('enabled', False)} "
            f"available={row.get('available', False)} "
            f"connected={row.get('connected', False)} "
            f"status={_channel_status(row)}"
        )
    lines.append("ALERTS:")
    if not active_alerts:
        lines.append("  no active alerts")
    for row in active_alerts:
        lines.append(
            f"  active {row.get('event_type', '')} ack={row.get('acknowledged_reason', '')}"
        )
    for row in acknowledged_alerts:
        lines.append(
            f"  acknowledged {row.get('event_type', '')} ack={row.get('acknowledged_reason', '')}"
        )
    lines.append("AUDIT EVENTS:")
    if not snapshot.audit_events:
        lines.append("  no recent audit events")
    for row in snapshot.audit_events:
        lines.append(
            "  "
            f"{row.get('timestamp', '')} {row.get('event_type', '')} "
            f"session={row.get('session_id', '')}"
        )
    return "\n".join(lines)


def _summary_counts(snapshot: TuiSnapshot) -> dict[str, int]:
    channel_rows = _configured_channel_rows(snapshot)
    active_alerts = _active_alert_rows(snapshot)
    acknowledged_alerts = _acknowledged_alert_rows(snapshot)
    return {
        "sessions": len(snapshot.sessions),
        "lockdown": sum(
            1
            for row in snapshot.sessions
            if str(row.get("lockdown_level", "")).strip().lower() not in {"", "normal"}
        ),
        "pending_confirmations": len(snapshot.pending_actions),
        "tasks": len(snapshot.tasks),
        "enabled_tasks": sum(1 for row in snapshot.tasks if _task_enabled(row)),
        "channels": len(channel_rows),
        "connected_channels": sum(1 for row in channel_rows if bool(row.get("connected", False))),
        "alerts": len(active_alerts),
        "acknowledged_alerts": len(acknowledged_alerts),
        "audit_events": len(snapshot.audit_events),
    }


def _summary_counts_line(snapshot: TuiSnapshot) -> str:
    summary = _summary_counts(snapshot)
    return (
        f"sessions={summary['sessions']} "
        f"lockdown={summary['lockdown']} "
        f"pending_confirmations={summary['pending_confirmations']} "
        f"tasks={summary['tasks']} "
        f"enabled_tasks={summary['enabled_tasks']} "
        f"channels={summary['channels']} "
        f"connected_channels={summary['connected_channels']} "
        f"alerts={summary['alerts']} "
        f"acknowledged_alerts={summary['acknowledged_alerts']} "
        f"audit_events={summary['audit_events']}"
    )


def _lockdown_style(level: object) -> str:
    normalized = str(level or "").strip().lower()
    if normalized in {"", "normal"}:
        return "green"
    if normalized in {"caution", "warning"}:
        return "yellow"
    return "red"


def _pending_status_style(status: object) -> str:
    normalized = str(status or "").strip().lower()
    if normalized == "pending":
        return "yellow"
    if normalized in {"approved", "executed"}:
        return "green"
    if normalized in {
        "rejected",
        "expired",
        "failed",
        "cancelled",
        "superseded",
        "outcome_unknown",
        "error",
    }:
        return "red"
    return "dim"


def _plan_step_status_style(status: object) -> str:
    normalized = str(status or "").strip().lower()
    if normalized == "done":
        return "green"
    if normalized in {"in_progress", "blocked"}:
        return "yellow"
    if normalized == "failed":
        return "red"
    return "dim"


def _enabled_style(value: object) -> str:
    return "green" if bool(value) else "dim"


def _channel_style(row: Mapping[str, Any]) -> str:
    status = _channel_status(row)
    if status == "ok":
        return "green"
    if status == "degraded":
        return "yellow"
    if status == "misconfigured":
        return "red"
    if status == "disabled":
        return "dim"
    if bool(row.get("enabled", False)) and not bool(row.get("available", False)):
        return "red"
    if bool(row.get("enabled", False)) and not bool(row.get("connected", False)):
        return "yellow"
    if bool(row.get("connected", False)):
        return "green"
    return "dim"


def _alert_style(row: Mapping[str, Any]) -> str:
    if _alert_acknowledged(row):
        return "dim"
    return "red" if str(row.get("event_type", "")).strip() else "dim"


def render_rich(snapshot: TuiSnapshot) -> str:
    """Render snapshot with rich panels when available."""
    try:
        rich_console = importlib.import_module("rich.console")
        rich_panel = importlib.import_module("rich.panel")
        rich_table = importlib.import_module("rich.table")
    except ImportError:
        return render_plain(snapshot)
    Console = rich_console.Console
    Panel = rich_panel.Panel
    Table = rich_table.Table

    console = Console(record=True)
    channel_rows = _configured_channel_rows(snapshot)
    active_alerts = _active_alert_rows(snapshot)
    acknowledged_alerts = _acknowledged_alert_rows(snapshot)
    plan_step_rows = _safe_plan_step_rows(snapshot.plan_steps)
    pending_by_id = _pending_actions_by_confirmation_id(snapshot.pending_actions)

    summary = Table(title="Summary", show_lines=False, row_styles=["", "dim"])
    summary.add_column("Metric")
    summary.add_column("Count", justify="right")
    for label, count in _summary_counts(snapshot).items():
        summary.add_row(label, str(count))

    sessions = Table(title="Sessions", show_lines=False, row_styles=["", "dim"])
    sessions.add_column("Session")
    sessions.add_column("User")
    sessions.add_column("Lockdown")
    for row in snapshot.sessions:
        sessions.add_row(
            str(row.get("id", "")),
            str(row.get("user_id", "")),
            str(row.get("lockdown_level", "")),
            style=_lockdown_style(row.get("lockdown_level", "")),
        )
    if not snapshot.sessions:
        sessions.add_row("(none)", "", "")

    pending = Table(title="Pending Confirmations", show_lines=False, row_styles=["", "dim"])
    pending.add_column("Confirmation")
    pending.add_column("Tool")
    pending.add_column("Status")
    pending.add_column("Proof")
    pending.add_column("Details")
    for row in snapshot.pending_actions:
        lifecycle_state = (
            str(row.get("lifecycle_state", "")).strip() or str(row.get("status", "")).strip()
        )
        pending.add_row(
            str(row.get("confirmation_id", "")),
            str(row.get("tool_name", "")),
            lifecycle_state,
            str(row.get("required_proof_tier", "")),
            render_pending_action(row),
            style=_pending_status_style(lifecycle_state),
        )
    if not snapshot.pending_actions:
        pending.add_row("(none)", "", "", "", "")

    plan_steps = Table(title="Work Breakdown", show_lines=False, row_styles=["", "dim"])
    plan_steps.add_column("Step")
    plan_steps.add_column("Order", justify="right")
    plan_steps.add_column("Title")
    plan_steps.add_column("Status")
    plan_steps.add_column("Current")
    plan_steps.add_column("Details")
    show_plan_sessions = _show_plan_step_sessions(plan_step_rows)
    for row in plan_step_rows:
        details: list[str] = []
        session_id = str(row.get("session_id", "")).strip()
        if show_plan_sessions and session_id:
            details.append(f"session={session_id}")
        depends_on = row.get("depends_on", [])
        if isinstance(depends_on, list) and depends_on:
            details.append("depends_on=" + ",".join(str(item) for item in depends_on))
        blocked_reason = str(row.get("blocked_reason", "")).strip()
        if blocked_reason:
            details.append(blocked_reason)
        plan_steps.add_row(
            str(row.get("id", "")),
            str(row.get("order", "")),
            str(row.get("title", "")),
            str(row.get("status", "unknown")),
            "yes" if bool(row.get("current", False)) else "no",
            " ".join(details),
            style=_plan_step_status_style(row.get("status", "")),
        )
    if not plan_step_rows:
        plan_steps.add_row("(none)", "", "", "", "", "")

    tasks = Table(title="Tasks", show_lines=False, row_styles=["", "dim"])
    tasks.add_column("Task")
    tasks.add_column("Status")
    tasks.add_column("Schedule")
    tasks.add_column("Delivery")
    tasks.add_column("Last")
    tasks.add_column("Next")
    tasks.add_column("Approval")
    for row in snapshot.tasks:
        approval = "; ".join(_task_pending_approval_summaries(row, pending_by_id))
        tasks.add_row(
            str(row.get("id", "")),
            _task_status(row),
            str(row.get("schedule_kind", "")),
            str(row.get("delivery_channel", "")),
            str(row.get("last_triggered_at", "")),
            str(row.get("next_run_at", "")),
            approval,
            style=_enabled_style(_task_enabled(row)),
        )
    if not snapshot.tasks:
        tasks.add_row("(none)", "", "", "", "", "", "")

    channels = Table(title="Channel Health", show_lines=False, row_styles=["", "dim"])
    channels.add_column("Channel")
    channels.add_column("Enabled")
    channels.add_column("Available")
    channels.add_column("Connected")
    channels.add_column("Status")
    for row in channel_rows:
        channels.add_row(
            str(row.get("channel", "")),
            str(row.get("enabled", False)),
            str(row.get("available", False)),
            str(row.get("connected", False)),
            _channel_status(row),
            style=_channel_style(row),
        )
    if not channel_rows:
        channels.add_row("(none)", "", "", "", "")

    alerts = Table(title="Alerts", show_lines=False, row_styles=["", "dim"])
    alerts.add_column("Status")
    alerts.add_column("Event")
    alerts.add_column("Ack")
    for row in active_alerts:
        alerts.add_row(
            "active",
            str(row.get("event_type", "")),
            str(row.get("acknowledged_reason", "")),
            style=_alert_style(row),
        )
    for row in acknowledged_alerts:
        alerts.add_row(
            "acknowledged",
            str(row.get("event_type", "")),
            str(row.get("acknowledged_reason", "")),
            style=_alert_style(row),
        )
    if not active_alerts and not acknowledged_alerts:
        alerts.add_row("(none)", "", "")

    audit = Table(title="Audit Events", show_lines=False, row_styles=["", "dim"])
    audit.add_column("Timestamp")
    audit.add_column("Event")
    audit.add_column("Session")
    for row in snapshot.audit_events:
        audit.add_row(
            str(row.get("timestamp", "")),
            str(row.get("event_type", "")),
            str(row.get("session_id", "")),
        )
    if not snapshot.audit_events:
        audit.add_row("(none)", "", "")

    console.print(Panel.fit(summary))
    console.print(Panel.fit(sessions))
    console.print(Panel.fit(pending))
    console.print(Panel.fit(plan_steps))
    console.print(Panel.fit(tasks))
    console.print(Panel.fit(channels))
    console.print(Panel.fit(alerts))
    console.print(Panel.fit(audit))
    return str(console.export_text())


async def run_once(socket_path: Path, *, rich_output: bool = True) -> str:
    """Return one snapshot render suitable for CLI output."""
    snapshot = await fetch_snapshot(socket_path)
    if rich_output:
        return render_rich(snapshot)
    return render_plain(snapshot)


async def run_interactive(socket_path: Path) -> None:
    """Very small interactive loop for session/confirmation/audit inspection."""
    while True:
        snapshot = await fetch_snapshot(socket_path)
        print(render_plain(snapshot))
        print("")
        print("[r]efresh  [c]onfirm <id> [proof-code]  [x] reject <id>  [q]uit")
        command = input("> ").strip()
        if not command:
            continue
        if command.lower() == "q":
            return
        if command.lower() == "r":
            continue
        if command.startswith("c "):
            parts = command.split()
            confirmation_id = parts[1].strip() if len(parts) > 1 else ""
            proof_code = parts[2].strip() if len(parts) > 2 else ""
            if proof_code:
                await _decision(
                    socket_path,
                    "action.confirm",
                    confirmation_id,
                    proof_code=proof_code,
                )
            else:
                await _decision(socket_path, "action.confirm", confirmation_id)
            continue
        if command.startswith("x "):
            confirmation_id = command.split(" ", 1)[1].strip()
            await _decision(socket_path, "action.reject", confirmation_id)
            continue
        print("Unknown command")


async def _decision(
    socket_path: Path,
    method: str,
    confirmation_id: str,
    *,
    proof_code: str = "",
    totp_code: str = "",
) -> None:
    if not confirmation_id:
        print("confirmation_id required")
        return
    client = ControlClient(socket_path)
    try:
        await client.connect()
        payload: dict[str, Any] = {"confirmation_id": confirmation_id}
        if method in {"action.confirm", "action.reject"}:
            decision_nonce = ""
            channel_principal_id = ""
            selected_backend_method = ""
            used_unfiltered_fallback = False
            terminal_lifecycle_state = ""
            pending_queries = (
                {
                    "confirmation_id": confirmation_id,
                    "status": "pending",
                    "limit": 1,
                    "include_ui": False,
                },
                {
                    "confirmation_id": confirmation_id,
                    "limit": 1,
                    "include_ui": False,
                },
            )
            for pending_query in pending_queries:
                pending_payload = await client.call("action.pending", pending_query)
                if not isinstance(pending_payload, Mapping):
                    continue
                actions = pending_payload.get("actions", [])
                if not isinstance(actions, list):
                    continue
                for raw in actions:
                    if not isinstance(raw, Mapping):
                        continue
                    if str(raw.get("confirmation_id", "")).strip() != confirmation_id:
                        continue
                    decision_nonce = str(raw.get("decision_nonce", "")).strip()
                    lifecycle_state = (
                        str(raw.get("lifecycle_state") or raw.get("status") or "").strip().lower()
                    )
                    selected_backend_method = str(raw.get("selected_backend_method", "")).strip()
                    allowed_channel_principals_raw = raw.get(
                        "allowed_channel_principals",
                        [],
                    )
                    allowed_channel_principals = (
                        [
                            str(value).strip()
                            for value in allowed_channel_principals_raw
                            if str(value).strip()
                        ]
                        if isinstance(allowed_channel_principals_raw, list)
                        else []
                    )
                    if len(allowed_channel_principals) == 1:
                        channel_principal_id = allowed_channel_principals[0]
                    if lifecycle_state and lifecycle_state != "pending":
                        terminal_lifecycle_state = lifecycle_state
                    break
                if decision_nonce or terminal_lifecycle_state:
                    used_unfiltered_fallback = "status" not in pending_query
                    break
            if not decision_nonce and not terminal_lifecycle_state:
                print("decision_nonce not found for confirmation_id")
                return
            payload["decision_nonce"] = decision_nonce
            if method in {"action.confirm", "action.reject"} and channel_principal_id:
                payload["principal_id"] = channel_principal_id
            supplied_proof = proof_code.strip() or totp_code.strip()
            if method == "action.confirm" and supplied_proof and not terminal_lifecycle_state:
                if selected_backend_method == "recovery_code":
                    payload["approval_method"] = "recovery_code"
                    payload["proof"] = {"recovery_code": supplied_proof}
                elif selected_backend_method in {"", "totp"}:
                    payload["approval_method"] = "totp"
                    payload["proof"] = {"totp_code": supplied_proof}
                else:
                    print(f"{selected_backend_method} cannot use a typed proof code here")
                    return
            elif (
                method == "action.confirm"
                and not terminal_lifecycle_state
                and selected_backend_method
                in {
                    "totp",
                    "recovery_code",
                }
                and not used_unfiltered_fallback
            ):
                required_label = approval_proof_placeholder(selected_backend_method).strip("<>")
                print(f"{required_label} required for this confirmation")
                return
        result = await client.call(
            method,
            payload,
        )
    finally:
        await client.close()
    print(json.dumps(result, indent=2))
    await asyncio.sleep(0.05)
