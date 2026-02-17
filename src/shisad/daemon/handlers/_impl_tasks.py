"""Task scheduler handler implementations."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, cast

from shisad.core.events import TaskScheduled, TaskTriggered
from shisad.core.types import Capability, UserId
from shisad.daemon.handlers._mixin_typing import HandlerMixinBase
from shisad.scheduler.schema import Schedule


class TasksImplMixin(HandlerMixinBase):
    async def do_task_create(self, params: Mapping[str, Any]) -> dict[str, Any]:
        schedule = Schedule.model_validate(params.get("schedule", {}))
        raw_delivery_target = params.get("delivery_target", {})
        delivery_target: dict[str, str]
        if isinstance(raw_delivery_target, Mapping):
            delivery_target = {
                str(key): str(value)
                for key, value in raw_delivery_target.items()
                if str(key).strip() and str(value).strip()
            }
        else:
            delivery_target = {}
        task = self._scheduler.create_task(
            name=str(params.get("name", "")),
            goal=str(params.get("goal", "")),
            schedule=schedule,
            capability_snapshot={Capability(cap) for cap in params.get("capability_snapshot", [])},
            policy_snapshot_ref=str(params.get("policy_snapshot_ref", "")),
            created_by=UserId(str(params.get("created_by", ""))),
            allowed_recipients=list(params.get("allowed_recipients", [])),
            allowed_domains=list(params.get("allowed_domains", [])),
            delivery_target=delivery_target,
        )
        await self._event_bus.publish(
            TaskScheduled(
                session_id=None,
                actor="scheduler",
                task_id=task.id,
                name=task.name,
            )
        )
        return cast(dict[str, Any], task.model_dump(mode="json"))

    async def do_task_list(self, params: Mapping[str, Any]) -> dict[str, Any]:
        _ = params
        tasks = self._scheduler.list_tasks()
        return {"tasks": [task.model_dump(mode="json") for task in tasks], "count": len(tasks)}

    async def do_task_disable(self, params: Mapping[str, Any]) -> dict[str, Any]:
        task_id = str(params.get("task_id", ""))
        disabled = self._scheduler.disable_task(task_id)
        return {"disabled": disabled, "task_id": task_id}

    async def do_task_trigger_event(self, params: Mapping[str, Any]) -> dict[str, Any]:
        event_type = str(params.get("event_type", ""))
        payload = str(params.get("payload", ""))
        runs = self._scheduler.trigger_event(event_type=event_type, payload=payload)
        accepted: list[dict[str, Any]] = []
        blocked = 0
        queued = 0
        for run in runs:
            task = self._scheduler.get_task(run.task_id)
            if task is None:
                blocked += 1
                continue
            if run.plan_commitment != task.commitment_hash():
                blocked += 1
                continue
            available_caps = set(self._policy_loader.policy.default_capabilities)
            if not available_caps:
                available_caps = set(task.capability_snapshot)
            if not self._scheduler.can_execute_with_capabilities(
                run.task_id,
                task.capability_snapshot,
                available_capabilities=available_caps,
            ):
                blocked += 1
                continue

            confirmation = {
                "task_id": run.task_id,
                "event_type": event_type,
                "trigger_payload": run.trigger_payload,
                "plan_commitment": run.plan_commitment,
                "payload_taint": run.payload_taint,
                "status": "pending",
            }
            self._scheduler.queue_confirmation(run.task_id, confirmation)
            queued += 1
            accepted.append(run.model_dump(mode="json"))
            await self._event_bus.publish(
                TaskTriggered(
                    session_id=None,
                    actor="scheduler",
                    task_id=run.task_id,
                    event_type=event_type,
                )
            )
        return {
            "runs": accepted,
            "count": len(accepted),
            "queued_confirmations": queued,
            "blocked_runs": blocked,
        }

    async def do_task_pending_confirmations(self, params: Mapping[str, Any]) -> dict[str, Any]:
        task_id = str(params.get("task_id", ""))
        pending = self._scheduler.pending_confirmations(task_id)
        return {"task_id": task_id, "pending": pending, "count": len(pending)}
