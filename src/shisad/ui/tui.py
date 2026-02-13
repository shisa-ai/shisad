"""Optional terminal UI surface built on top of control API endpoints."""

from __future__ import annotations

import asyncio
import importlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from shisad.core.api.transport import ControlClient


@dataclass(slots=True)
class TuiSnapshot:
    sessions: list[dict[str, Any]]
    pending_actions: list[dict[str, Any]]
    alerts: list[dict[str, Any]]
    audit_events: list[dict[str, Any]]


async def fetch_snapshot(socket_path: Path) -> TuiSnapshot:
    """Fetch a multi-panel snapshot from daemon control API."""
    client = ControlClient(socket_path)
    try:
        await client.connect()
        sessions_result = await client.call("session.list")
        pending_result = await client.call(
            "action.pending",
            {"status": "pending", "limit": 20},
        )
        alerts_result = await client.call("dashboard.alerts", {"limit": 20})
        audit_result = await client.call("dashboard.audit_explorer", {"limit": 20})
    finally:
        await client.close()
    return TuiSnapshot(
        sessions=[dict(item) for item in sessions_result.get("sessions", [])],
        pending_actions=[dict(item) for item in pending_result.get("actions", [])],
        alerts=[dict(item) for item in alerts_result.get("alerts", [])],
        audit_events=[dict(item) for item in audit_result.get("events", [])],
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
            f"{row.get('id','')} user={row.get('user_id','')} "
            f"lockdown={row.get('lockdown_level','')}"
        )
    lines.append("PENDING CONFIRMATIONS:")
    if not snapshot.pending_actions:
        lines.append("  (none)")
    for row in snapshot.pending_actions:
        lines.append(
            "  "
            f"{row.get('confirmation_id','')} "
            f"tool={row.get('tool_name','')} "
            f"reason={row.get('reason','')}"
        )
    lines.append("ALERTS:")
    if not snapshot.alerts:
        lines.append("  (none)")
    for row in snapshot.alerts:
        lines.append(
            "  "
            f"{row.get('event_type','')} "
            f"ack={row.get('acknowledged_reason','')}"
        )
    lines.append("AUDIT EVENTS:")
    if not snapshot.audit_events:
        lines.append("  (none)")
    for row in snapshot.audit_events:
        lines.append(
            "  "
            f"{row.get('timestamp','')} {row.get('event_type','')} "
            f"session={row.get('session_id','')}"
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
    pending.add_column("Reason")
    for row in snapshot.pending_actions:
        pending.add_row(
            str(row.get("confirmation_id", "")),
            str(row.get("tool_name", "")),
            str(row.get("reason", "")),
        )
    if not snapshot.pending_actions:
        pending.add_row("(none)", "", "")

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

    console.print(Panel.fit(sessions))
    console.print(Panel.fit(pending))
    console.print(Panel.fit(alerts))
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
        result = await client.call(
            method,
            {"confirmation_id": confirmation_id},
        )
    finally:
        await client.close()
    print(json.dumps(result, indent=2))
    await asyncio.sleep(0.05)
