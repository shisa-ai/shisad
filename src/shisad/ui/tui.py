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
        pending_actions=[
            {
                "confirmation_id": str(item.get("confirmation_id", "")),
                "tool_name": str(item.get("tool_name", "")),
                "status": str(item.get("status", "")),
                "created_at": str(item.get("created_at", "")),
            }
            for item in pending_result.get("actions", [])
            if isinstance(item, Mapping)
        ],
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


def render_plain(snapshot: TuiSnapshot) -> str:
    """Render a deterministic plaintext dashboard for non-rich terminals."""
    lines: list[str] = []
    lines.append("SHISAD TUI SNAPSHOT")
    lines.append("SESSIONS:")
    if not snapshot.sessions:
        lines.append("  (none)")
    for row in snapshot.sessions:
        lines.append(
            "  "
            f"{row.get('id', '')} user={row.get('user_id', '')} "
            f"lockdown={row.get('lockdown_level', '')}"
        )
    lines.append("PENDING CONFIRMATIONS:")
    if not snapshot.pending_actions:
        lines.append("  (none)")
    for row in snapshot.pending_actions:
        lines.append(
            "  "
            f"{row.get('confirmation_id', '')} "
            f"tool={row.get('tool_name', '')} "
            f"status={row.get('status', '')}"
        )
    lines.append("TASKS:")
    if not snapshot.tasks:
        lines.append("  (none)")
    for row in snapshot.tasks:
        lines.append(
            "  "
            f"{row.get('id', '')} "
            f"enabled={row.get('enabled', False)} "
            f"schedule={row.get('schedule_kind', '')} "
            f"delivery={row.get('delivery_channel', '')}"
        )
    lines.append("CHANNEL HEALTH:")
    if not snapshot.channel_health:
        lines.append("  (none)")
    for row in snapshot.channel_health:
        lines.append(
            "  "
            f"{row.get('channel', '')} "
            f"enabled={row.get('enabled', False)} "
            f"available={row.get('available', False)} "
            f"connected={row.get('connected', False)}"
        )
    lines.append("ALERTS:")
    if not snapshot.alerts:
        lines.append("  (none)")
    for row in snapshot.alerts:
        lines.append(f"  {row.get('event_type', '')} ack={row.get('acknowledged_reason', '')}")
    lines.append("AUDIT EVENTS:")
    if not snapshot.audit_events:
        lines.append("  (none)")
    for row in snapshot.audit_events:
        lines.append(
            "  "
            f"{row.get('timestamp', '')} {row.get('event_type', '')} "
            f"session={row.get('session_id', '')}"
        )
    return "\n".join(lines)


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

    sessions = Table(title="Sessions", show_lines=False)
    sessions.add_column("Session")
    sessions.add_column("User")
    sessions.add_column("Lockdown")
    for row in snapshot.sessions:
        sessions.add_row(
            str(row.get("id", "")),
            str(row.get("user_id", "")),
            str(row.get("lockdown_level", "")),
        )
    if not snapshot.sessions:
        sessions.add_row("(none)", "", "")

    pending = Table(title="Pending Confirmations", show_lines=False)
    pending.add_column("Confirmation")
    pending.add_column("Tool")
    pending.add_column("Status")
    for row in snapshot.pending_actions:
        pending.add_row(
            str(row.get("confirmation_id", "")),
            str(row.get("tool_name", "")),
            str(row.get("status", "")),
        )
    if not snapshot.pending_actions:
        pending.add_row("(none)", "", "")

    tasks = Table(title="Tasks", show_lines=False)
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
        )
    if not snapshot.tasks:
        tasks.add_row("(none)", "", "", "")

    channels = Table(title="Channel Health", show_lines=False)
    channels.add_column("Channel")
    channels.add_column("Enabled")
    channels.add_column("Available")
    channels.add_column("Connected")
    for row in snapshot.channel_health:
        channels.add_row(
            str(row.get("channel", "")),
            str(row.get("enabled", False)),
            str(row.get("available", False)),
            str(row.get("connected", False)),
        )
    if not snapshot.channel_health:
        channels.add_row("(none)", "", "", "")

    alerts = Table(title="Alerts", show_lines=False)
    alerts.add_column("Event")
    alerts.add_column("Ack")
    for row in snapshot.alerts:
        alerts.add_row(
            str(row.get("event_type", "")),
            str(row.get("acknowledged_reason", "")),
        )
    if not snapshot.alerts:
        alerts.add_row("(none)", "")

    audit = Table(title="Audit Events", show_lines=False)
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
        print("[r]efresh  [c]onfirm <id>  [x] reject <id>  [q]uit")
        command = input("> ").strip()
        if not command:
            continue
        if command.lower() == "q":
            return
        if command.lower() == "r":
            continue
        if command.startswith("c "):
            confirmation_id = command.split(" ", 1)[1].strip()
            await _decision(socket_path, "action.confirm", confirmation_id)
            continue
        if command.startswith("x "):
            confirmation_id = command.split(" ", 1)[1].strip()
            await _decision(socket_path, "action.reject", confirmation_id)
            continue
        print("Unknown command")


async def _decision(socket_path: Path, method: str, confirmation_id: str) -> None:
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
            if isinstance(pending_payload, Mapping):
                actions = pending_payload.get("actions", [])
                if isinstance(actions, list):
                    for raw in actions:
                        if not isinstance(raw, Mapping):
                            continue
                        if str(raw.get("confirmation_id", "")).strip() != confirmation_id:
                            continue
                        decision_nonce = str(raw.get("decision_nonce", "")).strip()
                        break
            if not decision_nonce:
                print("decision_nonce not found for confirmation_id")
                return
            payload["decision_nonce"] = decision_nonce
        result = await client.call(
            method,
            payload,
        )
    finally:
        await client.close()
    print(json.dumps(result, indent=2))
    await asyncio.sleep(0.05)
