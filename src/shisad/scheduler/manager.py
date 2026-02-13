"""Task scheduler foundation with capability snapshots."""

from __future__ import annotations

import json
from collections import defaultdict
from collections.abc import Callable
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
        except (OSError, json.JSONDecodeError):
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
        except (OSError, json.JSONDecodeError):
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
