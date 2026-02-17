#!/usr/bin/env python3
"""Daily-driver evidence harness for v0.3.2.

This script exercises a minimal operator flow and prints machine-readable
evidence for:
1) daemon startup
2) session message path
3) direct tool execution path
4) reminder pump trigger and delivery/fail-safe behavior
5) audit-trail emission

Usage:
  uv run python scripts/daily_driver_evidence.py --help
"""

from __future__ import annotations

import argparse
import asyncio
import json
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from shisad.core.api.transport import ControlClient
from shisad.core.config import DaemonConfig
from shisad.daemon.runner import run_daemon


async def _wait_for_socket(path: Path, timeout_seconds: float) -> None:
    end = asyncio.get_running_loop().time() + timeout_seconds
    while asyncio.get_running_loop().time() < end:
        if path.exists():
            return
        await asyncio.sleep(0.05)
    raise TimeoutError(f"Timed out waiting for socket: {path}")


def _event_total(response: dict[str, Any]) -> int:
    try:
        return int(response.get("total", 0))
    except (TypeError, ValueError):
        return 0


def _task_triggered_for_task(response: dict[str, Any], task_id: str) -> bool:
    if not task_id:
        return False
    events = response.get("events", [])
    if not isinstance(events, list):
        return False
    for event in events:
        if not isinstance(event, dict):
            continue
        data = event.get("data", {})
        if not isinstance(data, dict):
            continue
        if str(data.get("task_id", "")) == task_id:
            return True
    return False


def _task_trigger_count_for_task(response: dict[str, Any], task_id: str) -> int:
    if not task_id:
        return 0
    events = response.get("events", [])
    if not isinstance(events, list):
        return 0
    count = 0
    for event in events:
        if not isinstance(event, dict):
            continue
        data = event.get("data", {})
        if not isinstance(data, dict):
            continue
        if str(data.get("task_id", "")) == task_id:
            count += 1
    return count


@dataclass(slots=True)
class EvidenceSummary:
    session_id: str
    session_message_response_preview: str
    tool_executed_events: int
    task_triggered_events: int
    reminder_status: str
    scheduler_anomaly_events: int
    session_created_events: int
    session_message_events: int

    def as_dict(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "session_message_response_preview": self.session_message_response_preview,
            "tool_executed_events": self.tool_executed_events,
            "task_triggered_events": self.task_triggered_events,
            "reminder_status": self.reminder_status,
            "scheduler_anomaly_events": self.scheduler_anomaly_events,
            "session_created_events": self.session_created_events,
            "session_message_events": self.session_message_events,
        }


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Run a daily-driver evidence flow against a fresh local daemon instance "
            "and print verification artifacts."
        )
    )
    parser.add_argument(
        "--data-dir",
        type=Path,
        default=Path("/tmp/shisad-daily-driver"),
        help="Daemon data directory for this run (default: /tmp/shisad-daily-driver).",
    )
    parser.add_argument(
        "--socket-path",
        type=Path,
        default=None,
        help="Unix socket path override (default: <data-dir>/control.sock).",
    )
    parser.add_argument(
        "--policy-path",
        type=Path,
        default=None,
        help="Policy path override (default: <data-dir>/policy.yaml).",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=8.0,
        help="Seconds to wait for socket/events before failing.",
    )
    parser.add_argument("--channel", default="cli", help="Session channel (default: cli).")
    parser.add_argument("--user-id", default="daily-driver", help="Session user id.")
    parser.add_argument("--workspace-id", default="daily", help="Session workspace id.")
    parser.add_argument(
        "--message",
        default="Daily driver evidence ping. Reply with a short acknowledgement.",
        help="Message for session.message validation.",
    )
    parser.add_argument(
        "--tool-name",
        default="shell.exec",
        help="Tool name used for tool.execute validation.",
    )
    parser.add_argument(
        "--tool-command",
        nargs="+",
        default=["/bin/echo", "daily-driver-tool-check"],
        help="Command list passed to tool.execute.",
    )
    parser.add_argument(
        "--reminder-channel",
        default="noop",
        help=(
            "Delivery channel for reminder task check (default: noop). "
            "Use --allow-live-channels to opt in to live channel delivery."
        ),
    )
    parser.add_argument(
        "--reminder-recipient",
        default="daily-driver-room",
        help="Delivery recipient for reminder task check.",
    )
    parser.add_argument(
        "--allow-live-channels",
        action="store_true",
        help=(
            "Allow runtime channel clients (Matrix/Discord/Telegram/Slack). "
            "Default behavior is fail-safe with channel runtimes disabled."
        ),
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print compact JSON only (no human-readable preamble).",
    )
    return parser


async def _run(args: argparse.Namespace) -> EvidenceSummary:
    run_started = datetime.now(UTC)
    run_since = run_started.isoformat()
    data_dir = args.data_dir.resolve()
    data_dir.mkdir(parents=True, exist_ok=True)
    socket_path = (
        args.socket_path.resolve()
        if isinstance(args.socket_path, Path)
        else (data_dir / "control.sock")
    )
    policy_path = (
        args.policy_path.resolve()
        if isinstance(args.policy_path, Path)
        else (data_dir / "policy.yaml")
    )
    with suppress(FileNotFoundError):
        socket_path.unlink()

    config_kwargs: dict[str, Any] = {
        "data_dir": data_dir,
        "socket_path": socket_path,
        "policy_path": policy_path,
        "log_level": "INFO",
    }
    if not bool(args.allow_live_channels):
        config_kwargs.update(
            {
                "matrix_enabled": False,
                "discord_enabled": False,
                "telegram_enabled": False,
                "slack_enabled": False,
            }
        )
    config = DaemonConfig(**config_kwargs)
    daemon_task = asyncio.create_task(run_daemon(config))
    client = ControlClient(socket_path)

    try:
        await _wait_for_socket(socket_path, timeout_seconds=float(args.timeout))
        await client.connect()

        created = await client.call(
            "session.create",
            {
                "channel": str(args.channel),
                "user_id": str(args.user_id),
                "workspace_id": str(args.workspace_id),
            },
        )
        session_id = str(created["session_id"])

        session_reply = await client.call(
            "session.message",
            {
                "session_id": session_id,
                "channel": str(args.channel),
                "user_id": str(args.user_id),
                "workspace_id": str(args.workspace_id),
                "content": str(args.message),
            },
        )
        response_preview = str(session_reply.get("response", ""))[:240]
        if not response_preview:
            raise RuntimeError("session.message returned an empty response")

        await client.call(
            "tool.execute",
            {
                "session_id": session_id,
                "tool_name": str(args.tool_name),
                "command": [str(token) for token in args.tool_command],
            },
        )
        tool_events = await client.call(
            "audit.query",
            {
                "event_type": "ToolExecuted",
                "session_id": session_id,
                "limit": 50,
            },
        )
        tool_total = _event_total(tool_events)
        if tool_total < 1:
            raise RuntimeError("tool.execute did not emit ToolExecuted audit evidence")

        task = await client.call(
            "task.create",
            {
                "name": "daily-driver-reminder",
                "goal": "Daily-driver reminder check",
                "schedule": {"kind": "interval", "expression": "1s"},
                "capability_snapshot": ["message.send"],
                "policy_snapshot_ref": "daily-driver",
                "created_by": str(args.user_id),
                "allowed_recipients": [str(args.reminder_recipient)],
                "delivery_target": {
                    "channel": str(args.reminder_channel),
                    "recipient": str(args.reminder_recipient),
                },
            },
        )
        task_id = str(task.get("id", ""))

        task_trigger_total = 0
        scheduler_anomaly_total = 0
        reminder_status = "pending"
        for _ in range(max(1, int(float(args.timeout) * 2))):
            triggered = await client.call(
                "audit.query",
                {
                    "event_type": "TaskTriggered",
                    "actor": "scheduler",
                    "since": run_since,
                    "limit": 200,
                },
            )
            anomalies = await client.call(
                "audit.query",
                {
                    "event_type": "AnomalyReported",
                    "actor": "scheduler",
                    "since": run_since,
                    "limit": 200,
                },
            )
            task_trigger_total = _task_trigger_count_for_task(triggered, task_id)
            scheduler_anomaly_total = _event_total(anomalies)

            anomaly_events = anomalies.get("events", [])
            delivery_failure_seen = False
            if isinstance(anomaly_events, list):
                for event in anomaly_events:
                    if not isinstance(event, dict):
                        continue
                    data = event.get("data", {})
                    if not isinstance(data, dict):
                        continue
                    description = str(data.get("description", ""))
                    if task_id and task_id in description and "delivery failed" in description:
                        delivery_failure_seen = True
                        break

            if _task_triggered_for_task(triggered, task_id):
                if delivery_failure_seen:
                    reminder_status = "triggered_fail_safe_anomaly"
                    break
                # Reminder trigger fired and no delivery-failure anomaly was observed.
                # This indicates either a successful send or an alternate policy branch.
                reminder_status = "triggered"
                break

            await asyncio.sleep(0.5)

        if task_trigger_total < 1:
            raise RuntimeError("Reminder pump did not emit TaskTriggered evidence")

        session_created = await client.call(
            "audit.query",
            {
                "event_type": "SessionCreated",
                "session_id": session_id,
                "limit": 10,
            },
        )
        session_received = await client.call(
            "audit.query",
            {
                "event_type": "SessionMessageReceived",
                "session_id": session_id,
                "limit": 10,
            },
        )
        created_total = _event_total(session_created)
        received_total = _event_total(session_received)
        if created_total < 1 or received_total < 1:
            raise RuntimeError("Audit trail evidence is incomplete for session lifecycle")

        return EvidenceSummary(
            session_id=session_id,
            session_message_response_preview=response_preview,
            tool_executed_events=tool_total,
            task_triggered_events=task_trigger_total,
            reminder_status=reminder_status,
            scheduler_anomaly_events=scheduler_anomaly_total,
            session_created_events=created_total,
            session_message_events=received_total,
        )
    finally:
        with suppress(Exception):
            await client.call("daemon.shutdown")
        with suppress(Exception):
            await client.close()
        with suppress(Exception):
            await asyncio.wait_for(daemon_task, timeout=5)


def main() -> int:
    parser = _build_parser()
    args = parser.parse_args()
    try:
        summary = asyncio.run(_run(args))
    except Exception as exc:  # pragma: no cover
        payload = {"ok": False, "error": f"{exc.__class__.__name__}: {exc}"}
        if args.json:
            print(json.dumps(payload, ensure_ascii=True))
        else:
            print("Daily-driver evidence run failed.")
            print(json.dumps(payload, ensure_ascii=True, indent=2))
        return 1

    result_payload = {"ok": True, "evidence": summary.as_dict()}
    if args.json:
        print(json.dumps(result_payload, ensure_ascii=True))
    else:
        print("Daily-driver evidence run complete.")
        print(json.dumps(result_payload, ensure_ascii=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
