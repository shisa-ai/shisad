"""User-facing rendering helpers for scheduler metadata."""

from __future__ import annotations

import re
from typing import Any

from shisad.scheduler.schema import ScheduleKind


def parse_interval_seconds(expression: str) -> int:
    value = expression.strip().lower()
    if not value:
        raise ValueError("interval expression is required")
    if value.isdigit():
        seconds = int(value)
    else:
        match = re.fullmatch(r"(\d+)([smhd])", value)
        if match is None:
            raise ValueError("interval expression must be integer seconds or Ns/Nm/Nh/Nd")
        amount = int(match.group(1))
        unit = match.group(2)
        multipliers = {"s": 1, "m": 60, "h": 3600, "d": 86_400}
        seconds = amount * multipliers[unit]
    if seconds <= 0:
        raise ValueError("interval expression must be greater than zero")
    return seconds


def _plural(amount: int, unit: str) -> str:
    suffix = "" if amount == 1 else "s"
    return f"{amount} {unit}{suffix}"


def _human_interval(seconds: int) -> str:
    if seconds % 86_400 == 0:
        return _plural(seconds // 86_400, "day")
    if seconds % 3_600 == 0:
        return _plural(seconds // 3_600, "hour")
    if seconds % 60 == 0:
        return _plural(seconds // 60, "minute")
    return _plural(seconds, "second")


def task_schedule_rendering(task: Any) -> dict[str, str]:
    schedule = getattr(task, "schedule", None)
    kind = getattr(schedule, "kind", "")
    expression = str(getattr(schedule, "expression", "")).strip()
    max_runs = int(getattr(task, "max_runs", 0) or 0)

    if kind == ScheduleKind.INTERVAL or str(kind) == ScheduleKind.INTERVAL.value:
        try:
            interval = _human_interval(parse_interval_seconds(expression))
        except ValueError:
            interval = expression or "unknown interval"
        if max_runs == 1:
            success_count = int(getattr(task, "success_count", 0) or 0)
            if success_count >= 1:
                summary = f"one-shot, was due about {interval} after creation and has already fired"
            else:
                summary = f"one-shot, due about {interval} after creation"
            return {"schedule_kind": "one_shot_interval", "schedule_summary": summary}
        summary = f"every {interval}"
        if max_runs > 1:
            summary = f"{summary}, up to {max_runs} runs"
        return {"schedule_kind": "recurring_interval", "schedule_summary": summary}

    if kind == ScheduleKind.CRON or str(kind) == ScheduleKind.CRON.value:
        return {
            "schedule_kind": "cron",
            "schedule_summary": f"cron schedule: {expression or 'unspecified'}",
        }

    if kind == ScheduleKind.EVENT or str(kind) == ScheduleKind.EVENT.value:
        event_type = str(getattr(schedule, "event_type", "") or expression).strip()
        return {
            "schedule_kind": "event",
            "schedule_summary": f"event-triggered: {event_type or 'unspecified'}",
        }

    return {
        "schedule_kind": str(kind or "unknown"),
        "schedule_summary": expression or "unspecified",
    }
