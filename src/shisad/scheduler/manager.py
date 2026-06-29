"""Task scheduler foundation with capability snapshots."""

from __future__ import annotations

import json
from collections import defaultdict
from collections.abc import Callable, Mapping
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from shisad.core.types import Capability, UserId, WorkspaceId
from shisad.scheduler.rendering import parse_interval_seconds, task_schedule_rendering
from shisad.scheduler.schema import (
    Schedule,
    ScheduledTask,
    ScheduleKind,
    TaskEnvelope,
    TaskRunRequest,
)

_MAX_RESOLVED_CONFIRMATIONS_PER_TASK = 32
_MAX_CRON_LOOKAHEAD_DAYS = 400 * 366


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
        workspace_id: WorkspaceId | None = None,
        allowed_recipients: list[str] | None = None,
        allowed_domains: list[str] | None = None,
        delivery_target: dict[str, str] | None = None,
        credential_refs: list[str] | None = None,
        resource_scope_ids: list[str] | None = None,
        resource_scope_prefixes: list[str] | None = None,
        untrusted_payload_action: str = "require_confirmation",
        max_runs: int = 0,
    ) -> ScheduledTask:
        self._validate_schedule(schedule)
        capability_snapshot_frozen = frozenset(capability_snapshot)
        owner = str(created_by or "unknown")
        workspace = str(workspace_id or WorkspaceId(""))
        orchestrator_provenance = f"scheduler:{owner}:{workspace}"
        task = ScheduledTask(
            name=name,
            goal=goal,
            schedule=schedule,
            capability_snapshot=capability_snapshot_frozen,
            policy_snapshot_ref=policy_snapshot_ref,
            task_envelope=TaskEnvelope(
                capability_snapshot=capability_snapshot_frozen,
                parent_session_id="",
                orchestrator_provenance=orchestrator_provenance,
                audit_trail_ref="",
                policy_snapshot_ref=policy_snapshot_ref,
                lockdown_state_inheritance="inherit_runtime_restrictions",
                credential_refs=tuple(credential_refs or ()),
                resource_scope_ids=tuple(resource_scope_ids or ()),
                resource_scope_prefixes=tuple(resource_scope_prefixes or ()),
                untrusted_payload_action=untrusted_payload_action,
            ),
            allowed_recipients=allowed_recipients or [],
            allowed_domains=allowed_domains or [],
            delivery_target=dict(delivery_target or {}),
            created_by=created_by,
            workspace_id=workspace_id or WorkspaceId(""),
            max_runs=max(0, int(max_runs)),
        )
        self._tasks[task.id] = task
        self._persist_tasks()
        self._audit("task.create", {"task_id": task.id, "name": name, "max_runs": task.max_runs})
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

    def attach_execution_session(self, task_id: str, session_id: str) -> bool:
        task = self._tasks.get(task_id)
        normalized = session_id.strip()
        if task is None or not normalized:
            return False
        task.execution_session_id = normalized
        self._persist_tasks()
        self._audit("task.attach_execution_session", {"task_id": task_id, "session_id": normalized})
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
        dirty = False
        for task in self._tasks.values():
            if not task.enabled:
                continue
            if task.schedule.kind != ScheduleKind.EVENT:
                continue
            if task.schedule.event_type != event_type:
                continue
            task.trigger_count += 1
            dirty = True
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
        if dirty:
            self._persist_tasks()
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
            try:
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
            except ValueError as exc:
                self._audit(
                    "task.invalid_schedule",
                    {
                        "task_id": task.id,
                        "schedule_kind": getattr(
                            task.schedule.kind,
                            "value",
                            str(task.schedule.kind),
                        ),
                        "reason": str(exc),
                    },
                )
                continue
            task.last_triggered_at = current
            task.trigger_count += 1
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
        payload = dict(action)
        payload["status"] = str(payload.get("status", "pending") or "pending")
        payload["queued_at"] = (
            str(payload.get("queued_at", "")).strip() or datetime.now(UTC).isoformat()
        )
        self._pending_confirmations[task_id].append(payload)
        self._prune_confirmation_rows(task_id)
        self._persist_pending_confirmations()
        self._audit("task.confirmation_queued", {"task_id": task_id})

    def pending_confirmations(self, task_id: str) -> list[dict[str, Any]]:
        pending: list[dict[str, Any]] = []
        for row in self._pending_confirmations.get(task_id, []):
            status = str(row.get("status", "pending") or "pending").strip().lower()
            if status == "pending":
                pending.append(dict(row))
        return pending

    def resolve_confirmation(
        self,
        task_id: str,
        *,
        confirmation_id: str,
        status: str,
        status_reason: str = "",
    ) -> bool:
        rows = self._pending_confirmations.get(task_id, [])
        normalized_confirmation = confirmation_id.strip()
        normalized_status = status.strip().lower()
        if not normalized_confirmation or not normalized_status:
            return False
        for row in rows:
            if str(row.get("confirmation_id", "")).strip() != normalized_confirmation:
                continue
            row["status"] = normalized_status
            row["status_reason"] = status_reason.strip()
            row["resolved_at"] = datetime.now(UTC).isoformat()
            self._prune_confirmation_rows(task_id)
            self._persist_pending_confirmations()
            self._audit(
                "task.confirmation_resolved",
                {
                    "task_id": task_id,
                    "confirmation_id": normalized_confirmation,
                    "status": normalized_status,
                },
            )
            return True
        return False

    def record_run_outcome(self, task_id: str, *, success: bool) -> bool:
        task = self._tasks.get(task_id)
        if task is None:
            return False
        if success:
            task.success_count += 1
        else:
            task.failure_count += 1
        self._persist_tasks()
        self._audit(
            "task.run_outcome",
            {
                "task_id": task_id,
                "success": success,
                "success_count": task.success_count,
                "failure_count": task.failure_count,
            },
        )
        if success and task.max_runs > 0 and task.success_count >= task.max_runs and task.enabled:
            self.disable_task(task_id)
        return True

    def task_status_snapshot(
        self,
        *,
        limit: int = 8,
        created_by: UserId | None = None,
        workspace_id: WorkspaceId | None = None,
        now: datetime | None = None,
    ) -> list[dict[str, Any]]:
        current = now or datetime.now(UTC)
        tasks = sorted(
            self._tasks.values(),
            key=lambda item: (item.created_at, item.id),
            reverse=True,
        )
        owner = str(created_by or "").strip()
        workspace = str(workspace_id or "").strip()
        if owner:
            tasks = [task for task in tasks if str(task.created_by).strip() == owner]
        if workspace:
            tasks = [task for task in tasks if str(task.workspace_id).strip() == workspace]
        rows: list[dict[str, Any]] = []
        for task in tasks[: max(0, int(limit))]:
            pending = len(self.pending_confirmations(task.id))
            schedule_rendering = task_schedule_rendering(task)
            delivery_target = (
                task.delivery_target if isinstance(task.delivery_target, Mapping) else {}
            )
            delivery_channel = str(delivery_target.get("channel", "")).strip()
            rows.append(
                {
                    "task_id": task.id,
                    "title": task.name,
                    "status": "enabled" if task.enabled else "disabled",
                    **schedule_rendering,
                    "created_at": task.created_at.isoformat(),
                    "last_triggered_at": (
                        task.last_triggered_at.isoformat()
                        if task.last_triggered_at is not None
                        else ""
                    ),
                    "next_run_at": self._next_run_at(task, now=current),
                    "confirmation_needed": pending > 0,
                    "pending_confirmation_count": pending,
                    "trigger_count": int(task.trigger_count),
                    "success_count": int(task.success_count),
                    "failure_count": int(task.failure_count),
                    "max_runs": int(task.max_runs),
                    "created_by": str(task.created_by),
                    "workspace_id": str(task.workspace_id),
                    "delivery_channel": delivery_channel,
                }
            )
        return rows

    def _next_run_at(self, task: ScheduledTask, *, now: datetime) -> str:
        if not task.enabled:
            return ""
        if task.schedule.kind == ScheduleKind.EVENT:
            return ""
        if task.max_runs > 0 and task.trigger_count >= task.max_runs:
            return ""
        try:
            if task.schedule.kind == ScheduleKind.INTERVAL:
                interval_seconds = self._parse_interval_seconds(task.schedule.expression)
                due_at = (task.last_triggered_at or task.created_at) + timedelta(
                    seconds=interval_seconds
                )
                if due_at <= now:
                    missed_runs = int((now - due_at).total_seconds() // interval_seconds) + 1
                    due_at += timedelta(seconds=interval_seconds * missed_runs)
                return due_at.isoformat()
            if task.schedule.kind == ScheduleKind.CRON:
                next_cron = self._next_cron_run(
                    task.schedule.expression,
                    now=now,
                    last_triggered_at=task.last_triggered_at,
                )
                return next_cron.isoformat() if next_cron is not None else ""
        except ValueError:
            return ""
        return ""

    def _next_cron_run(
        self,
        expression: str,
        *,
        now: datetime,
        last_triggered_at: datetime | None,
    ) -> datetime | None:
        start = now.replace(second=0, microsecond=0)
        if now.second or now.microsecond:
            start += timedelta(minutes=1)
        fields = expression.split()
        if len(fields) != 5:
            raise ValueError("cron schedule requires exactly 5 fields")
        minute_field, hour_field, day_field, month_field, weekday_field = fields
        allowed_minutes = self._cron_allowed_values(minute_field, minimum=0, maximum=59)
        allowed_hours = self._cron_allowed_values(hour_field, minimum=0, maximum=23)
        allowed_days = self._cron_allowed_values(day_field, minimum=1, maximum=31)
        allowed_months = self._cron_allowed_values(month_field, minimum=1, maximum=12)
        last_minute = (
            last_triggered_at.replace(second=0, microsecond=0)
            if last_triggered_at is not None
            else None
        )
        end = start + timedelta(days=_MAX_CRON_LOOKAHEAD_DAYS)
        for year in range(start.year, end.year + 1):
            for month in allowed_months:
                if year == start.year and month < start.month:
                    continue
                if year == end.year and month > end.month:
                    continue
                for day in allowed_days:
                    try:
                        day_start = datetime(year, month, day, tzinfo=start.tzinfo)
                    except ValueError:
                        continue
                    if day_start.date() < start.date() or day_start.date() > end.date():
                        continue
                    weekday = (day_start.weekday() + 1) % 7
                    if not self._cron_field_matches(
                        weekday_field,
                        value=weekday,
                        minimum=0,
                        maximum=7,
                    ):
                        continue
                    for hour in allowed_hours:
                        for minute in allowed_minutes:
                            candidate = day_start.replace(hour=hour, minute=minute)
                            if candidate < start or candidate > end or candidate == last_minute:
                                continue
                            return candidate
        return None

    @staticmethod
    def _cron_allowed_values(field: str, *, minimum: int, maximum: int) -> list[int]:
        SchedulerManager._validate_cron_field(field, minimum=minimum, maximum=maximum)
        return [
            value
            for value in range(minimum, maximum + 1)
            if SchedulerManager._cron_field_matches(
                field,
                value=value,
                minimum=minimum,
                maximum=maximum,
            )
        ]

    def _prune_confirmation_rows(self, task_id: str) -> None:
        rows = list(self._pending_confirmations.get(task_id, []))
        if not rows:
            return
        pending: list[dict[str, Any]] = []
        resolved: list[dict[str, Any]] = []
        for row in rows:
            status = str(row.get("status", "pending") or "pending").strip().lower()
            if status == "pending":
                pending.append(row)
            else:
                resolved.append(row)
        resolved.sort(
            key=lambda row: (
                str(row.get("resolved_at", "")).strip(),
                str(row.get("queued_at", "")).strip(),
                str(row.get("confirmation_id", "")).strip(),
            )
        )
        if len(resolved) > _MAX_RESOLVED_CONFIRMATIONS_PER_TASK:
            resolved = resolved[-_MAX_RESOLVED_CONFIRMATIONS_PER_TASK:]
        self._pending_confirmations[task_id] = [*pending, *resolved]

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
        return parse_interval_seconds(expression)

    @staticmethod
    def _validate_cron_field(field: str, *, minimum: int, maximum: int) -> None:
        for part in SchedulerManager._cron_field_parts(field):
            if part == "*":
                continue
            if "/" in part:
                base, step_raw = part.split("/", 1)
                if not step_raw.isdigit() or int(step_raw) <= 0:
                    raise ValueError("cron step must be positive integer")
                SchedulerManager._validate_cron_step_base(
                    base,
                    minimum=minimum,
                    maximum=maximum,
                )
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
    def _cron_field_parts(field: str) -> list[str]:
        parts = [item.strip() for item in field.split(",")]
        if not parts or any(not part for part in parts):
            raise ValueError("cron field cannot be empty")
        return parts

    @staticmethod
    def _validate_cron_step_base(base: str, *, minimum: int, maximum: int) -> None:
        token = base.strip()
        if token == "*":
            return
        if "-" in token:
            start_raw, end_raw = token.split("-", 1)
            if not start_raw.isdigit() or not end_raw.isdigit():
                raise ValueError("cron range must be numeric")
            start = int(start_raw)
            end = int(end_raw)
            if start > end:
                raise ValueError("cron range start must be <= end")
            if start < minimum or end > maximum:
                raise ValueError("cron range out of bounds")
            return
        if not token.isdigit():
            raise ValueError("cron step base must be wildcard, range, or numeric")
        value = int(token)
        if value < minimum or value > maximum:
            raise ValueError("cron field value out of bounds")

    @staticmethod
    def _cron_matches(expression: str, moment: datetime) -> bool:
        fields = expression.split()
        if len(fields) != 5:
            raise ValueError("cron schedule requires exactly 5 fields")
        values = [
            moment.minute,
            moment.hour,
            moment.day,
            moment.month,
            (moment.weekday() + 1) % 7,
        ]
        bounds = [(0, 59), (0, 23), (1, 31), (1, 12), (0, 7)]
        for field, value, (minimum, maximum) in zip(fields, values, bounds, strict=True):
            SchedulerManager._validate_cron_field(field, minimum=minimum, maximum=maximum)
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
        for part in SchedulerManager._cron_field_parts(field):
            if part == "*":
                return True
            if "/" in part:
                if SchedulerManager._cron_step_part_matches(
                    part,
                    value=value,
                    minimum=minimum,
                    maximum=maximum,
                ):
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

    @staticmethod
    def _cron_step_part_matches(
        part: str,
        *,
        value: int,
        minimum: int,
        maximum: int,
    ) -> bool:
        try:
            base, step_raw = part.split("/", 1)
        except ValueError:
            return False
        if not step_raw.isdigit():
            return False
        step = int(step_raw)
        if step <= 0:
            return False
        bounds = SchedulerManager._cron_step_bounds(
            base,
            minimum=minimum,
            maximum=maximum,
        )
        if bounds is None:
            return False
        start, end = bounds
        for offset, raw_candidate in enumerate(range(start, end + 1)):
            if offset % step != 0:
                continue
            candidate = raw_candidate
            if maximum == 7 and candidate == 7:
                candidate = 0
            if candidate == value:
                return True
        return False

    @staticmethod
    def _cron_step_bounds(
        base: str,
        *,
        minimum: int,
        maximum: int,
    ) -> tuple[int, int] | None:
        token = base.strip()
        if token == "*":
            return (minimum, maximum)
        if "-" in token:
            start_raw, end_raw = token.split("-", 1)
            if not start_raw.isdigit() or not end_raw.isdigit():
                return None
            start = int(start_raw)
            end = int(end_raw)
            if start > end:
                return None
            if start < minimum or end > maximum:
                return None
            return (start, end)
        if not token.isdigit():
            return None
        literal = int(token)
        if literal < minimum or literal > maximum:
            return None
        return (literal, maximum)

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
