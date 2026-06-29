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
from shisad.ui.confirmation import render_pending_action

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class TuiSnapshot:
    sessions: list[dict[str, Any]] = field(default_factory=list)
    pending_actions: list[dict[str, Any]] = field(default_factory=list)
    tasks: list[dict[str, Any]] = field(default_factory=list)
    channel_health: list[dict[str, Any]] = field(default_factory=list)
    alerts: list[dict[str, Any]] = field(default_factory=list)
    audit_events: list[dict[str, Any]] = field(default_factory=list)


def _safe_task_rows(raw_tasks: list[Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for raw in raw_tasks:
        if not isinstance(raw, Mapping):
            continue
        schedule = raw.get("schedule", {})
        delivery = raw.get("delivery_target", {})
        schedule_kind = ""
        if isinstance(schedule, Mapping):
            schedule_kind = str(schedule.get("kind", "")).strip()
        delivery_channel = ""
        if isinstance(delivery, Mapping):
            delivery_channel = str(delivery.get("channel", "")).strip()
        rows.append(
            {
                "id": str(raw.get("id", "")),
                "enabled": bool(raw.get("enabled", False)),
                "schedule_kind": schedule_kind,
                "last_triggered_at": str(raw.get("last_triggered_at", "")),
                "delivery_channel": delivery_channel,
            }
        )
    return rows


def _safe_channel_rows(raw_channels: Mapping[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for raw_name, raw in raw_channels.items():
        name = str(raw_name).strip().lower()
        if not isinstance(raw, Mapping):
            raw = {}
        rows.append(
            {
                "channel": name,
                "enabled": bool(raw.get("enabled", False)),
                "available": bool(raw.get("available", False)),
                "connected": bool(raw.get("connected", False)),
                "status": str(raw.get("status", "")).strip(),
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
                "tool_name": str(item.get("tool_name", "")),
                "status": str(item.get("status", "")),
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
                    str(value).strip()
                    for value in item.get("warnings", [])
                    if str(value).strip()
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
        pending_result = await _safe_call(
            "action.pending",
            {"status": "pending", "limit": 20},
            default={"actions": []},
        )
        tasks_result = await _safe_call("task.list", default={"tasks": []})
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
        sessions=[
            dict(item) for item in sessions_result.get("sessions", []) if isinstance(item, Mapping)
        ],
        pending_actions=_safe_pending_action_rows(
            [item for item in pending_result.get("actions", [])]
        ),
        tasks=_safe_task_rows([item for item in tasks_result.get("tasks", [])]),
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
    return str(row.get("status", "")).strip().lower()


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
    lines.append("TASKS:")
    if not snapshot.tasks:
        lines.append("  no background tasks")
    for row in snapshot.tasks:
        lines.append(
            "  "
            f"{row.get('id', '')} "
            f"enabled={row.get('enabled', False)} "
            f"schedule={row.get('schedule_kind', '')} "
            f"delivery={row.get('delivery_channel', '')}"
        )
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
            f"status={row.get('status', '')}"
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
            "  "
            f"acknowledged {row.get('event_type', '')} "
            f"ack={row.get('acknowledged_reason', '')}"
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
        "enabled_tasks": sum(1 for row in snapshot.tasks if bool(row.get("enabled", False))),
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
    if normalized == "approved":
        return "green"
    if normalized in {"rejected", "expired", "failed", "error"}:
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
        pending.add_row(
            str(row.get("confirmation_id", "")),
            str(row.get("tool_name", "")),
            str(row.get("status", "")),
            str(row.get("required_proof_tier", "")),
            render_pending_action(row),
            style=_pending_status_style(row.get("status", "")),
        )
    if not snapshot.pending_actions:
        pending.add_row("(none)", "", "", "", "")

    tasks = Table(title="Tasks", show_lines=False, row_styles=["", "dim"])
    tasks.add_column("Task")
    tasks.add_column("Enabled")
    tasks.add_column("Schedule")
    tasks.add_column("Delivery")
    for row in snapshot.tasks:
        tasks.add_row(
            str(row.get("id", "")),
            str(row.get("enabled", False)),
            str(row.get("schedule_kind", "")),
            str(row.get("delivery_channel", "")),
            style=_enabled_style(row.get("enabled", False)),
        )
    if not snapshot.tasks:
        tasks.add_row("(none)", "", "", "")

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
            str(row.get("status", "")),
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
        print("[r]efresh  [c]onfirm <id> [totp-code]  [x] reject <id>  [q]uit")
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
            totp_code = parts[2].strip() if len(parts) > 2 else ""
            if totp_code:
                await _decision(
                    socket_path,
                    "action.confirm",
                    confirmation_id,
                    totp_code=totp_code,
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
            pending_payload = await client.call(
                "action.pending",
                {
                    "confirmation_id": confirmation_id,
                    "status": "pending",
                    "limit": 1,
                    "include_ui": False,
                },
            )
            decision_nonce = ""
            channel_principal_id = ""
            selected_backend_method = ""
            if isinstance(pending_payload, Mapping):
                actions = pending_payload.get("actions", [])
                if isinstance(actions, list):
                    for raw in actions:
                        if not isinstance(raw, Mapping):
                            continue
                        if str(raw.get("confirmation_id", "")).strip() != confirmation_id:
                            continue
                        decision_nonce = str(raw.get("decision_nonce", "")).strip()
                        selected_backend_method = str(
                            raw.get("selected_backend_method", "")
                        ).strip()
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
                        break
            if not decision_nonce:
                print("decision_nonce not found for confirmation_id")
                return
            payload["decision_nonce"] = decision_nonce
            if method in {"action.confirm", "action.reject"} and channel_principal_id:
                payload["principal_id"] = channel_principal_id
            if method == "action.confirm" and totp_code.strip():
                payload["approval_method"] = "totp"
                payload["proof"] = {"totp_code": totp_code.strip()}
            elif method == "action.confirm" and selected_backend_method == "totp":
                print("totp_code required for this confirmation")
                return
        result = await client.call(
            method,
            payload,
        )
    finally:
        await client.close()
    print(json.dumps(result, indent=2))
    await asyncio.sleep(0.05)
