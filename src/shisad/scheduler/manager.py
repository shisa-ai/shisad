"""Task scheduler foundation with capability snapshots."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Callable
from typing import Any

from shisad.core.types import Capability, UserId
from shisad.scheduler.schema import Schedule, ScheduledTask, ScheduleKind, TaskRunRequest


class SchedulerManager:
    """Stores tasks and creates safe run requests from triggers."""

    def __init__(
        self,
        *,
        audit_hook: Callable[[str, dict[str, Any]], None] | None = None,
    ) -> None:
        self._tasks: dict[str, ScheduledTask] = {}
        self._pending_confirmations: dict[str, list[dict[str, Any]]] = defaultdict(list)
        self._audit_hook = audit_hook

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
        self._audit("task.disable", {"task_id": task_id})
        return True

    def can_execute_with_capabilities(
        self,
        task_id: str,
        current_capabilities: set[Capability],
    ) -> bool:
        task = self._tasks.get(task_id)
        if task is None:
            return False
        return set(current_capabilities).issubset(task.capability_snapshot)

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

