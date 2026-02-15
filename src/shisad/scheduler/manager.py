"""Task scheduler foundation with capability snapshots."""

from __future__ import annotations

import json
import re
from collections import defaultdict
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from shisad.core.types import Capability, UserId
from shisad.scheduler.schema import Schedule, ScheduledTask, ScheduleKind, TaskRunRequest


class SchedulerManager:
    """Stores tasks and creates safe run requests from triggers."""

    def __init__(
        self,
        *,
        storage_dir: Path | None = None,
        audit_hook: Callable[[str, dict[str, Any]], None] | None = None,
    ) -> None:
        self._tasks: dict[str, ScheduledTask] = {}
        self._pending_confirmations: dict[str, list[dict[str, Any]]] = defaultdict(list)
        self._audit_hook = audit_hook
        self._storage_dir = storage_dir
        self._tasks_file = self._storage_dir / "tasks.json" if self._storage_dir else None
        self._pending_file = (
            self._storage_dir / "pending_confirmations.json" if self._storage_dir else None
        )
        if self._storage_dir is not None:
            self._storage_dir.mkdir(parents=True, exist_ok=True)
        self._load_tasks()
        self._load_pending_confirmations()

    def create_task(
        self,
        *,
        name: str,
        goal: str,
        schedule: Schedule,
        capability_snapshot: set[Capability],
        policy_snapshot_ref: str,
        created_by: UserId,
        allowed_recipients: list[str] | None = None,
        allowed_domains: list[str] | None = None,
        delivery_target: dict[str, str] | None = None,
    ) -> ScheduledTask:
        self._validate_schedule(schedule)
        task = ScheduledTask(
            name=name,
            goal=goal,
            schedule=schedule,
            capability_snapshot=set(capability_snapshot),
            policy_snapshot_ref=policy_snapshot_ref,
            allowed_recipients=allowed_recipients or [],
            allowed_domains=allowed_domains or [],
            delivery_target=dict(delivery_target or {}),
            created_by=created_by,
        )
        self._tasks[task.id] = task
        self._persist_tasks()
        self._audit("task.create", {"task_id": task.id, "name": name})
        return task

    def list_tasks(self) -> list[ScheduledTask]:
        return sorted(self._tasks.values(), key=lambda item: item.created_at, reverse=True)

    def get_task(self, task_id: str) -> ScheduledTask | None:
        return self._tasks.get(task_id)

    def disable_task(self, task_id: str) -> bool:
        task = self._tasks.get(task_id)
        if task is None:
            return False
        task.enabled = False
        self._persist_tasks()
        self._audit("task.disable", {"task_id": task_id})
        return True

    def can_execute_with_capabilities(
        self,
        task_id: str,
        requested_capabilities: set[Capability],
        *,
        available_capabilities: set[Capability] | None = None,
    ) -> bool:
        """Check whether a requested execution capability set is safe for this task.

        Safety rules:
        - Requested capabilities must be a subset of the task's immutable snapshot.
        - If runtime availability is provided, requested capabilities must also be
          available at execution time.
        """
        task = self._tasks.get(task_id)
        if task is None:
            return False
        requested = set(requested_capabilities)
        if not requested.issubset(task.capability_snapshot):
            return False
        if available_capabilities is not None:
            return requested.issubset(set(available_capabilities))
        return True

    def trigger_event(
        self,
        *,
        event_type: str,
        payload: str,
    ) -> list[TaskRunRequest]:
        requests: list[TaskRunRequest] = []
        for task in self._tasks.values():
            if not task.enabled:
                continue
            if task.schedule.kind != ScheduleKind.EVENT:
                continue
            if task.schedule.event_type != event_type:
                continue
            requests.append(
                TaskRunRequest(
                    task_id=task.id,
                    trigger_payload=payload,
                    plan_commitment=task.commitment_hash(),
                )
            )
            self._audit(
                "task.trigger",
                {"task_id": task.id, "event_type": event_type, "payload_taint": "UNTRUSTED"},
            )
        return requests

    def trigger_due(
        self,
        *,
        now: datetime | None = None,
    ) -> list[TaskRunRequest]:
        current = now or datetime.now(UTC)
        requests: list[TaskRunRequest] = []
        dirty = False
        current_minute = current.replace(second=0, microsecond=0)
        for task in self._tasks.values():
            if not task.enabled:
                continue
            if task.schedule.kind == ScheduleKind.EVENT:
                continue
            if task.schedule.kind == ScheduleKind.INTERVAL:
                interval_seconds = self._parse_interval_seconds(task.schedule.expression)
                baseline = task.last_triggered_at or task.created_at
                if (current - baseline).total_seconds() < interval_seconds:
                    continue
            elif task.schedule.kind == ScheduleKind.CRON:
                if not self._cron_matches(task.schedule.expression, current):
                    continue
                last_minute = (
                    task.last_triggered_at.replace(second=0, microsecond=0)
                    if task.last_triggered_at is not None
                    else None
                )
                if last_minute == current_minute:
                    continue
            else:
                continue
            task.last_triggered_at = current
            dirty = True
            requests.append(
                TaskRunRequest(
                    task_id=task.id,
                    trigger_payload=f"scheduled:{current.isoformat()}",
                    payload_taint="trusted_scheduler",
                    plan_commitment=task.commitment_hash(),
                )
            )
            self._audit(
                "task.trigger_due",
                {
                    "task_id": task.id,
                    "schedule_kind": task.schedule.kind.value,
                },
            )
        if dirty:
            self._persist_tasks()
        return requests

    def queue_confirmation(self, task_id: str, action: dict[str, Any]) -> None:
        self._pending_confirmations[task_id].append(action)
        self._persist_pending_confirmations()
        self._audit("task.confirmation_queued", {"task_id": task_id})

    def pending_confirmations(self, task_id: str) -> list[dict[str, Any]]:
        return list(self._pending_confirmations.get(task_id, []))

    def _validate_schedule(self, schedule: Schedule) -> None:
        if schedule.kind == ScheduleKind.EVENT:
            if not schedule.event_type:
                raise ValueError("event schedule requires event_type")
            for key in schedule.event_filter:
                if not key.replace("_", "").isalnum():
                    raise ValueError("event filter keys must be simple alphanumeric tokens")
            return
        if schedule.kind == ScheduleKind.INTERVAL:
            self._parse_interval_seconds(schedule.expression)
            return
        if schedule.kind == ScheduleKind.CRON:
            fields = schedule.expression.split()
            if len(fields) != 5:
                raise ValueError("cron schedule requires exactly 5 fields")
            ranges = [(0, 59), (0, 23), (1, 31), (1, 12), (0, 7)]
            for field, (minimum, maximum) in zip(fields, ranges, strict=True):
                self._validate_cron_field(field, minimum=minimum, maximum=maximum)
            return
        raise ValueError(f"unsupported schedule kind: {schedule.kind}")

    @staticmethod
    def _parse_interval_seconds(expression: str) -> int:
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

    @staticmethod
    def _validate_cron_field(field: str, *, minimum: int, maximum: int) -> None:
        parts = [item.strip() for item in field.split(",") if item.strip()]
        if not parts:
            raise ValueError("cron field cannot be empty")
        for part in parts:
            if part == "*":
                continue
            if part.startswith("*/"):
                step = part[2:]
                if not step.isdigit() or int(step) <= 0:
                    raise ValueError("cron step must be positive integer")
                continue
            if "-" in part:
                start_raw, end_raw = part.split("-", 1)
                if not start_raw.isdigit() or not end_raw.isdigit():
                    raise ValueError("cron range must be numeric")
                start = int(start_raw)
                end = int(end_raw)
                if start > end:
                    raise ValueError("cron range start must be <= end")
                if start < minimum or end > maximum:
                    raise ValueError("cron range out of bounds")
                continue
            if not part.isdigit():
                raise ValueError("cron field must be numeric, wildcard, step, or range")
            value = int(part)
            if value < minimum or value > maximum:
                raise ValueError("cron field value out of bounds")

    @staticmethod
    def _cron_matches(expression: str, moment: datetime) -> bool:
        fields = expression.split()
        if len(fields) != 5:
            return False
        values = [
            moment.minute,
            moment.hour,
            moment.day,
            moment.month,
            (moment.weekday() + 1) % 7,
        ]
        bounds = [(0, 59), (0, 23), (1, 31), (1, 12), (0, 7)]
        for field, value, (minimum, maximum) in zip(fields, values, bounds, strict=True):
            if not SchedulerManager._cron_field_matches(
                field,
                value=value,
                minimum=minimum,
                maximum=maximum,
            ):
                return False
        return True

    @staticmethod
    def _cron_field_matches(
        field: str,
        *,
        value: int,
        minimum: int,
        maximum: int,
    ) -> bool:
        for part in [item.strip() for item in field.split(",") if item.strip()]:
            if part == "*":
                return True
            if part.startswith("*/"):
                step = int(part[2:])
                if step > 0 and (value - minimum) % step == 0:
                    return True
                continue
            if "-" in part:
                start_raw, end_raw = part.split("-", 1)
                start = int(start_raw)
                end = int(end_raw)
                if start <= value <= end:
                    return True
                if maximum == 7 and end == 7 and value == 0:
                    return True
                continue
            literal = int(part)
            if maximum == 7 and literal == 7:
                literal = 0
            if literal == value:
                return True
        return False

    def _audit(self, action: str, payload: dict[str, Any]) -> None:
        if self._audit_hook is not None:
            self._audit_hook(action, payload)

    def _persist_tasks(self) -> None:
        if self._tasks_file is None:
            return
        payload = [task.model_dump(mode="json") for task in self._tasks.values()]
        self._tasks_file.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    def _load_tasks(self) -> None:
        if self._tasks_file is None or not self._tasks_file.exists():
            return
        try:
            raw = json.loads(self._tasks_file.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError):
            return
        if not isinstance(raw, list):
            return
        for item in raw:
            try:
                task = ScheduledTask.model_validate(item)
            except ValidationError:
                continue
            self._tasks[task.id] = task

    def _persist_pending_confirmations(self) -> None:
        if self._pending_file is None:
            return
        payload = {task_id: rows for task_id, rows in self._pending_confirmations.items()}
        self._pending_file.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    def _load_pending_confirmations(self) -> None:
        if self._pending_file is None or not self._pending_file.exists():
            return
        try:
            raw = json.loads(self._pending_file.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError):
            return
        if not isinstance(raw, dict):
            return
        restored: defaultdict[str, list[dict[str, Any]]] = defaultdict(list)
        for task_id, rows in raw.items():
            if not isinstance(task_id, str):
                continue
            if not isinstance(rows, list):
                continue
            cleaned_rows = [item for item in rows if isinstance(item, dict)]
            if cleaned_rows:
                restored[task_id] = cleaned_rows
        self._pending_confirmations = restored
