"""Task scheduler foundation with capability snapshots."""

from __future__ import annotations

import copy
import json
from collections import defaultdict
from collections.abc import Callable, Mapping
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from shisad.core.action_state import action_lifecycle_state
from shisad.core.atomic_state import (
    AtomicWriteError,
    AtomicWriteFaultInjector,
    StateLoadResult,
    StateLoadStatus,
    StatePersistenceDegradedError,
    atomic_write_bytes,
    decode_versioned_json_snapshot,
    encode_versioned_json_snapshot,
    ensure_owner_only_directory,
    read_owner_only_regular_file,
)
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
_SCHEDULER_STATE_VERSION = 1
_PENDING_STRING_FIELDS = frozenset(
    {
        "action_id",
        "confirmation_id",
        "event_type",
        "execution_attempt_id",
        "expires_at",
        "lifecycle_state",
        "payload_taint",
        "plan_commitment",
        "processing_started_at",
        "queued_at",
        "reason",
        "resolved_at",
        "result_id",
        "session_id",
        "status",
        "status_reason",
        "task_id",
        "tool_name",
        "trigger_payload",
    }
)
_PENDING_IDENTITY_STRING_FIELDS = frozenset(
    {
        "action_id",
        "confirmation_id",
        "execution_attempt_id",
        "followup_id",
        "origin_turn_id",
        "result_id",
        "session_id",
        "task_id",
        "user_id",
        "workspace_id",
    }
)


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
        self._state_fault_injector: AtomicWriteFaultInjector | None = None
        self._state_load_results = {
            "tasks": StateLoadResult(StateLoadStatus.MISSING),
            "pending_confirmations": StateLoadResult(StateLoadStatus.MISSING),
        }
        self._state_persistence_degradation: dict[str, AtomicWriteError] = {}
        self._durable_tasks: dict[str, ScheduledTask] = {}
        self._durable_pending_confirmations: defaultdict[
            str, list[dict[str, Any]]
        ] = defaultdict(list)
        if self._storage_dir is not None:
            ensure_owner_only_directory(self._storage_dir)
        self._load_tasks()
        pending_confirmation_state_loaded = self._load_pending_confirmations()
        if pending_confirmation_state_loaded:
            for task_id in self._tasks:
                self._prune_confirmation_outcome_dedup(task_id)

    @property
    def state_degraded(self) -> bool:
        return bool(self._state_persistence_degradation) or any(
            result.status
            in {StateLoadStatus.CORRUPT, StateLoadStatus.UNSUPPORTED_SCHEMA}
            for result in self._state_load_results.values()
        )

    def state_load_result(self, authority: str) -> StateLoadResult:
        try:
            return self._state_load_results[authority]
        except KeyError as exc:
            raise ValueError(f"unknown scheduler state authority: {authority}") from exc

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
        self._require_state_writable("tasks", transition="create")
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
        self._require_state_readable("tasks", transition="list")
        return sorted(self._tasks.values(), key=lambda item: item.created_at, reverse=True)

    def get_task(self, task_id: str) -> ScheduledTask | None:
        self._require_state_readable("tasks", transition="get")
        return self._tasks.get(task_id)

    def disable_task(self, task_id: str) -> bool:
        self._require_state_writable("tasks", transition="disable")
        task = self._tasks.get(task_id)
        if task is None:
            return False
        task.enabled = False
        task.recovery_containment_token = ""
        self._persist_tasks()
        self._audit("task.disable", {"task_id": task_id})
        return True

    def contain_task_for_recovery(self, task_id: str, *, token: str) -> bool:
        self._require_state_writable("tasks", transition="contain_for_recovery")
        task = self._tasks.get(task_id)
        normalized_token = token.strip()
        if task is None or not normalized_token:
            return False
        task.enabled = False
        task.recovery_containment_token = normalized_token
        self._persist_tasks()
        self._audit("task.recovery_contain", {"task_id": task_id})
        return True

    def release_task_recovery_containment(
        self,
        task_id: str,
        *,
        token: str,
        enable: bool,
    ) -> bool:
        self._require_state_writable("tasks", transition="release_recovery_containment")
        task = self._tasks.get(task_id)
        normalized_token = token.strip()
        if task is None or not normalized_token:
            return False
        if task.recovery_containment_token != normalized_token:
            return not task.recovery_containment_token
        task.recovery_containment_token = ""
        if enable:
            task.enabled = True
        self._persist_tasks()
        self._audit(
            "task.recovery_release",
            {"task_id": task_id, "enabled": task.enabled},
        )
        return True

    def attach_execution_session(self, task_id: str, session_id: str) -> bool:
        self._require_state_writable("tasks", transition="attach_execution_session")
        task = self._tasks.get(task_id)
        normalized = session_id.strip()
        if task is None or not normalized:
            return False
        task.execution_session_id = normalized
        self._persist_tasks()
        self._audit(
            "task.attach_execution_session",
            {"task_id": task_id, "session_id": normalized},
        )
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
        self._require_state_readable("tasks", transition="capability_check")
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
        self._require_state_writable("tasks", transition="trigger_event")
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
                {
                    "task_id": task.id,
                    "event_type": event_type,
                    "payload_taint": "UNTRUSTED",
                },
            )
        if dirty:
            self._persist_tasks()
        return requests

    def trigger_due(
        self,
        *,
        now: datetime | None = None,
    ) -> list[TaskRunRequest]:
        self._require_state_writable("tasks", transition="trigger_due")
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
        self._require_state_writable(
            "pending_confirmations",
            transition="queue_confirmation",
        )
        if task_id not in self._tasks:
            raise ValueError("pending confirmation task does not exist")
        payload = dict(action)
        confirmation_id = payload.get("confirmation_id")
        if not isinstance(confirmation_id, str) or not confirmation_id.strip():
            raise ValueError("pending confirmation requires confirmation_id")
        confirmation_id = confirmation_id.strip()
        payload["confirmation_id"] = confirmation_id
        row_task_id = payload.get("task_id")
        if row_task_id is not None and (
            not isinstance(row_task_id, str) or row_task_id.strip() != task_id
        ):
            raise ValueError("pending confirmation task identity mismatch")
        payload["task_id"] = task_id
        raw_identity = payload.get("identity")
        if raw_identity is None:
            identity: dict[str, Any] = {}
        elif isinstance(raw_identity, dict):
            identity = dict(raw_identity)
        else:
            raise ValueError("pending confirmation identity must be a mapping")
        identity_task_id = identity.get("task_id")
        if identity_task_id is not None and (
            not isinstance(identity_task_id, str) or identity_task_id.strip() != task_id
        ):
            raise ValueError("pending confirmation nested task identity mismatch")
        identity_confirmation_id = identity.get("confirmation_id")
        if identity_confirmation_id is not None and (
            not isinstance(identity_confirmation_id, str)
            or identity_confirmation_id.strip() != confirmation_id
        ):
            raise ValueError("pending confirmation nested confirmation identity mismatch")
        identity["task_id"] = task_id
        identity["confirmation_id"] = confirmation_id
        payload["identity"] = identity
        payload["status"] = str(payload.get("status", "pending") or "pending")
        payload["run_outcome_recorded"] = False
        payload.pop("run_outcome_success", None)
        payload.pop("processing_started_at", None)
        payload.pop("resolved_at", None)
        payload["queued_at"] = (
            str(payload.get("queued_at", "")).strip() or datetime.now(UTC).isoformat()
        )
        if not self._pending_row_is_valid(payload, task_id=task_id):
            raise ValueError("pending confirmation has invalid retained semantics")
        if any(
            str(row.get("confirmation_id", "")).strip() == confirmation_id
            for rows in self._pending_confirmations.values()
            for row in rows
        ):
            raise ValueError("pending confirmation identity already exists")
        self._pending_confirmations[task_id].append(payload)
        self._prune_confirmation_rows(task_id)
        self._persist_pending_confirmations()
        self._prune_confirmation_outcome_dedup(task_id)
        self._audit("task.confirmation_queued", {"task_id": task_id})

    def pending_confirmations(self, task_id: str) -> list[dict[str, Any]]:
        self._require_state_writable(
            "pending_confirmations",
            transition="list",
        )
        self._require_state_writable("tasks", transition="reconcile_expiry")
        pending: list[dict[str, Any]] = []
        current = datetime.now(UTC)
        reconciled_expiry = False
        for row in self._pending_confirmations.get(task_id, []):
            status = str(row.get("status", "pending") or "pending").strip().lower()
            expires_at: datetime | None = None
            raw_expires_at = str(row.get("expires_at", "") or "").strip()
            if raw_expires_at:
                try:
                    expires_at = datetime.fromisoformat(raw_expires_at)
                except ValueError:
                    expires_at = None
            lifecycle_state = action_lifecycle_state(
                status=status,
                status_reason=str(row.get("status_reason", "") or ""),
                expires_at=expires_at,
                now=current,
            )
            if status == "pending" and lifecycle_state == "expired":
                row["status"] = "failed"
                row["status_reason"] = "approval_expired"
                row["lifecycle_state"] = "expired"
                row["resolved_at"] = current.isoformat()
                self._record_confirmation_outcome_row(task_id, row=row, success=False)
                self._audit(
                    "task.confirmation_resolved",
                    {
                        "task_id": task_id,
                        "confirmation_id": str(row.get("confirmation_id", "")).strip(),
                        "status": "failed",
                    },
                )
                reconciled_expiry = True
                continue
            if lifecycle_state == "pending":
                payload = dict(row)
                payload["lifecycle_state"] = lifecycle_state
                pending.append(payload)
        if reconciled_expiry:
            self._prune_confirmation_rows(task_id)
            self._persist_pending_confirmations()
            self._prune_confirmation_outcome_dedup(task_id)
        return pending

    def _record_confirmation_outcome_row(
        self,
        task_id: str,
        *,
        row: dict[str, Any],
        success: bool,
    ) -> bool:
        task = self._tasks.get(task_id)
        if task is None:
            return False
        confirmation_id = str(row.get("confirmation_id", "")).strip()
        if confirmation_id in task.confirmation_outcome_dedup:
            recorded_success = task.confirmation_outcome_dedup[confirmation_id]
            row["run_outcome_recorded"] = True
            row["run_outcome_success"] = recorded_success
            self._persist_pending_confirmations()
            self._prune_confirmation_outcome_dedup(task_id)
            return True
        if bool(row.get("run_outcome_recorded", False)):
            if confirmation_id:
                task.confirmation_outcome_dedup[confirmation_id] = bool(
                    row.get("run_outcome_success", success)
                )
                self._persist_tasks()
            return True
        row["run_outcome_recorded"] = True
        row["run_outcome_success"] = bool(success)
        if confirmation_id:
            task.confirmation_outcome_dedup[confirmation_id] = bool(success)
        if success:
            task.success_count += 1
        else:
            task.failure_count += 1
        try:
            self._persist_tasks()
        except AtomicWriteError as exc:
            if not exc.publication_may_have_committed:
                self._restore_durable_pending_confirmations()
            raise
        except (TypeError, ValueError):
            self._restore_durable_pending_confirmations()
            raise
        self._persist_pending_confirmations()
        self._prune_confirmation_outcome_dedup(task_id)
        self._audit(
            "task.run_outcome",
            {
                "task_id": task_id,
                "confirmation_id": confirmation_id,
                "success": success,
                "success_count": task.success_count,
                "failure_count": task.failure_count,
            },
        )
        return True

    def resolve_confirmation(
        self,
        task_id: str,
        *,
        confirmation_id: str,
        status: str,
        status_reason: str = "",
        lifecycle_state: str = "",
        action_id: str = "",
        execution_attempt_id: str = "",
        result_id: str = "",
    ) -> bool:
        self._require_state_writable(
            "pending_confirmations",
            transition="resolve_confirmation",
        )
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
            if lifecycle_state.strip():
                row["lifecycle_state"] = lifecycle_state.strip()
            if action_id.strip():
                row["action_id"] = action_id.strip()
            if execution_attempt_id.strip():
                row["execution_attempt_id"] = execution_attempt_id.strip()
            if result_id.strip():
                row["result_id"] = result_id.strip()
            identity = row.get("identity")
            if isinstance(identity, dict):
                if action_id.strip():
                    identity["action_id"] = action_id.strip()
                if execution_attempt_id.strip():
                    identity["execution_attempt_id"] = execution_attempt_id.strip()
                if result_id.strip():
                    identity["result_id"] = result_id.strip()
            transition_at = datetime.now(UTC).isoformat()
            if normalized_status == "executing":
                row["processing_started_at"] = (
                    str(row.get("processing_started_at", "")).strip() or transition_at
                )
                row.pop("resolved_at", None)
                audit_event = "task.confirmation_processing"
            else:
                row["resolved_at"] = transition_at
                audit_event = "task.confirmation_resolved"
            self._prune_confirmation_rows(task_id)
            self._persist_pending_confirmations()
            self._prune_confirmation_outcome_dedup(task_id)
            self._audit(
                audit_event,
                {
                    "task_id": task_id,
                    "confirmation_id": normalized_confirmation,
                    "status": normalized_status,
                },
            )
            return True
        return False

    def record_confirmation_outcome(
        self,
        task_id: str,
        *,
        confirmation_id: str,
        success: bool,
    ) -> bool:
        self._require_state_writable("tasks", transition="record_confirmation_outcome")
        self._require_state_writable(
            "pending_confirmations",
            transition="record_confirmation_outcome",
        )
        normalized_confirmation = confirmation_id.strip()
        if not normalized_confirmation:
            return False
        for row in self._pending_confirmations.get(task_id, []):
            if str(row.get("confirmation_id", "")).strip() != normalized_confirmation:
                continue
            return self._record_confirmation_outcome_row(task_id, row=row, success=success)
        return False

    def confirmation_outcome(
        self,
        task_id: str,
        *,
        confirmation_id: str,
    ) -> bool | None:
        self._require_state_readable(
            "pending_confirmations",
            transition="confirmation_outcome",
        )
        normalized_confirmation = confirmation_id.strip()
        if not normalized_confirmation:
            return None
        for row in self._pending_confirmations.get(task_id, []):
            if str(row.get("confirmation_id", "")).strip() != normalized_confirmation:
                continue
            if not bool(row.get("run_outcome_recorded", False)):
                return None
            return bool(row.get("run_outcome_success", False))
        return None

    def has_terminal_confirmation_shadow(
        self,
        task_id: str,
        *,
        confirmation_id: str,
    ) -> bool:
        """Return whether the scheduler has a matching effect-terminal shadow."""

        self._require_state_readable(
            "pending_confirmations",
            transition="terminal_confirmation_shadow",
        )
        normalized_confirmation = confirmation_id.strip()
        if not normalized_confirmation:
            return False
        for row in self._pending_confirmations.get(task_id, []):
            if str(row.get("confirmation_id", "")).strip() != normalized_confirmation:
                continue
            status = str(row.get("status", "pending") or "pending").strip().lower()
            return status in {
                "executing",
                "approved",
                "failed",
                "outcome_unknown",
            }
        return False

    def task_ids_for_confirmation(self, confirmation_id: str) -> list[str]:
        self._require_state_readable(
            "pending_confirmations",
            transition="task_ids_for_confirmation",
        )
        normalized_confirmation = confirmation_id.strip()
        if not normalized_confirmation:
            return []
        return sorted(
            task_id
            for task_id, rows in self._pending_confirmations.items()
            if any(
                str(row.get("confirmation_id", "")).strip() == normalized_confirmation
                for row in rows
            )
        )

    def record_run_outcome(self, task_id: str, *, success: bool) -> bool:
        self._require_state_writable("tasks", transition="record_run_outcome")
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
        return True

    def task_status_snapshot(
        self,
        *,
        limit: int = 8,
        created_by: UserId | None = None,
        workspace_id: WorkspaceId | None = None,
        now: datetime | None = None,
    ) -> list[dict[str, Any]]:
        self._require_state_readable("tasks", transition="status_snapshot")
        self._require_state_writable(
            "pending_confirmations",
            transition="status_snapshot",
        )
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
        active: list[dict[str, Any]] = []
        resolved: list[dict[str, Any]] = []
        for row in rows:
            status = str(row.get("status", "pending") or "pending").strip().lower()
            if status in {"pending", "executing"}:
                active.append(row)
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
        self._pending_confirmations[task_id] = [*active, *resolved]

    def _prune_confirmation_outcome_dedup(self, task_id: str) -> None:
        """Drop task tombstones only after the retained row set is durable."""

        task = self._tasks.get(task_id)
        if task is None or not task.confirmation_outcome_dedup:
            return
        retained_ids = {
            str(row.get("confirmation_id", "")).strip()
            for row in self._pending_confirmations.get(task_id, [])
            if str(row.get("confirmation_id", "")).strip()
        }
        stale_ids = set(task.confirmation_outcome_dedup).difference(retained_ids)
        if not stale_ids:
            return
        for confirmation_id in stale_ids:
            task.confirmation_outcome_dedup.pop(confirmation_id, None)
        self._persist_tasks()

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

    def _require_state_readable(self, authority: str, *, transition: str) -> None:
        result = self._state_load_results[authority]
        if result.status not in {
            StateLoadStatus.CORRUPT,
            StateLoadStatus.UNSUPPORTED_SCHEMA,
        }:
            return
        raise StatePersistenceDegradedError(
            authority=f"scheduler.{authority}",
            transition=transition,
            stage="load",
            reason=result.reason or result.status.value,
        )

    def _require_state_writable(self, authority: str, *, transition: str) -> None:
        self._require_state_readable(authority, transition=transition)
        degradation = self._state_persistence_degradation.get(authority)
        if degradation is None:
            return
        raise StatePersistenceDegradedError(
            authority=f"scheduler.{authority}",
            transition=transition,
            stage=degradation.stage.value,
            reason="prior_publication_commit_uncertain",
        )

    @staticmethod
    def _clone_tasks(tasks: Mapping[str, ScheduledTask]) -> dict[str, ScheduledTask]:
        return {task_id: task.model_copy(deep=True) for task_id, task in tasks.items()}

    @staticmethod
    def _clone_pending_confirmations(
        pending: Mapping[str, list[dict[str, Any]]],
    ) -> defaultdict[str, list[dict[str, Any]]]:
        cloned: defaultdict[str, list[dict[str, Any]]] = defaultdict(list)
        for task_id, rows in pending.items():
            cloned[task_id] = copy.deepcopy(rows)
        return cloned

    def _restore_durable_tasks(self) -> None:
        self._tasks = self._clone_tasks(self._durable_tasks)

    def _restore_durable_pending_confirmations(self) -> None:
        self._pending_confirmations = self._clone_pending_confirmations(
            self._durable_pending_confirmations
        )

    @staticmethod
    def _semantic_corruption_result(
        result: StateLoadResult,
        reason: str,
    ) -> StateLoadResult:
        return StateLoadResult(
            StateLoadStatus.CORRUPT,
            reason=reason,
            schema_version=result.schema_version,
            legacy=result.legacy,
        )

    def _persist_tasks(self) -> None:
        if self._tasks_file is None:
            return
        try:
            self._require_state_writable("tasks", transition="persist")
        except StatePersistenceDegradedError:
            self._restore_durable_tasks()
            raise
        payload: list[dict[str, Any]] = []
        for task in self._tasks.values():
            task_payload = task.model_dump(mode="json")
            if task.confirmation_outcome_dedup:
                task_payload["_confirmation_outcome_dedup"] = dict(task.confirmation_outcome_dedup)
            if task.recovery_containment_token:
                task_payload["_recovery_containment_token"] = task.recovery_containment_token
            payload.append(task_payload)
        try:
            snapshot = encode_versioned_json_snapshot(
                payload,
                version=_SCHEDULER_STATE_VERSION,
            )
        except (TypeError, ValueError):
            self._restore_durable_tasks()
            raise
        try:
            atomic_write_bytes(
                self._tasks_file,
                snapshot,
                fault_injector=self._state_fault_injector,
            )
        except AtomicWriteError as exc:
            if exc.publication_may_have_committed:
                self._state_persistence_degradation["tasks"] = exc
            else:
                self._restore_durable_tasks()
            raise
        self._durable_tasks = self._clone_tasks(self._tasks)
        self._state_load_results["tasks"] = StateLoadResult(
            StateLoadStatus.OK,
            schema_version=_SCHEDULER_STATE_VERSION,
        )

    def _load_tasks(self) -> None:
        if self._tasks_file is None:
            return
        try:
            raw_bytes = read_owner_only_regular_file(self._tasks_file)
        except OSError:
            self._state_load_results["tasks"] = StateLoadResult(
                StateLoadStatus.CORRUPT,
                reason="read_error",
            )
            return
        if raw_bytes is None:
            self._state_load_results["tasks"] = StateLoadResult(StateLoadStatus.MISSING)
            self._durable_tasks = {}
            return
        try:
            raw = json.loads(raw_bytes.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError, RecursionError):
            raw = None
        result: StateLoadResult
        payload: Any
        if isinstance(raw, list):
            result = StateLoadResult(StateLoadStatus.OK, legacy=True)
            payload = raw
        else:
            result, payload = decode_versioned_json_snapshot(
                raw_bytes,
                supported_version=_SCHEDULER_STATE_VERSION,
            )
        if result.status != StateLoadStatus.OK:
            self._state_load_results["tasks"] = result
            return
        if not isinstance(payload, list):
            self._state_load_results["tasks"] = self._semantic_corruption_result(
                result,
                "invalid_tasks_payload",
            )
            return
        restored: dict[str, ScheduledTask] = {}
        for item in payload:
            if not isinstance(item, dict):
                self._state_load_results["tasks"] = self._semantic_corruption_result(
                    result,
                    "invalid_task_row",
                )
                return
            counter_fields = ("trigger_count", "success_count", "failure_count", "max_runs")
            if any(
                type(item.get(field, 0)) is not int or item.get(field, 0) < 0
                for field in counter_fields
            ):
                self._state_load_results["tasks"] = self._semantic_corruption_result(
                    result,
                    "invalid_task_counters",
                )
                return
            try:
                task = ScheduledTask.model_validate(item)
            except ValidationError:
                self._state_load_results["tasks"] = self._semantic_corruption_result(
                    result,
                    "invalid_task_row",
                )
                return
            try:
                self._validate_schedule(task.schedule)
            except ValueError:
                self._state_load_results["tasks"] = self._semantic_corruption_result(
                    result,
                    "invalid_task_schedule",
                )
                return
            outcome_dedup = item.get("_confirmation_outcome_dedup", {})
            if not isinstance(outcome_dedup, dict):
                self._state_load_results["tasks"] = self._semantic_corruption_result(
                    result,
                    "invalid_task_outcome_dedup",
                )
                return
            if any(
                not isinstance(confirmation_id, str)
                or not confirmation_id.strip()
                or not isinstance(outcome, bool)
                for confirmation_id, outcome in outcome_dedup.items()
            ):
                self._state_load_results["tasks"] = self._semantic_corruption_result(
                    result,
                    "invalid_task_outcome_dedup",
                )
                return
            task.confirmation_outcome_dedup = {
                confirmation_id.strip(): outcome
                for confirmation_id, outcome in outcome_dedup.items()
                if isinstance(confirmation_id, str)
                and confirmation_id.strip()
                and isinstance(outcome, bool)
            }
            recovery_containment_token = item.get("_recovery_containment_token", "")
            if not isinstance(recovery_containment_token, str):
                self._state_load_results["tasks"] = self._semantic_corruption_result(
                    result,
                    "invalid_recovery_containment_token",
                )
                return
            task.recovery_containment_token = recovery_containment_token.strip()
            if task.id in restored:
                self._state_load_results["tasks"] = self._semantic_corruption_result(
                    result,
                    "duplicate_task_id",
                )
                return
            restored[task.id] = task
        self._tasks = restored
        self._durable_tasks = self._clone_tasks(restored)
        self._state_load_results["tasks"] = result

    def _persist_pending_confirmations(self) -> None:
        if self._pending_file is None:
            return
        try:
            self._require_state_writable(
                "pending_confirmations",
                transition="persist",
            )
        except StatePersistenceDegradedError:
            self._restore_durable_pending_confirmations()
            raise
        payload = {task_id: rows for task_id, rows in self._pending_confirmations.items()}
        try:
            snapshot = encode_versioned_json_snapshot(
                payload,
                version=_SCHEDULER_STATE_VERSION,
            )
        except (TypeError, ValueError):
            self._restore_durable_pending_confirmations()
            raise
        try:
            atomic_write_bytes(
                self._pending_file,
                snapshot,
                fault_injector=self._state_fault_injector,
            )
        except AtomicWriteError as exc:
            if exc.publication_may_have_committed:
                self._state_persistence_degradation["pending_confirmations"] = exc
            else:
                self._restore_durable_pending_confirmations()
            raise
        self._durable_pending_confirmations = self._clone_pending_confirmations(
            self._pending_confirmations
        )
        self._state_load_results["pending_confirmations"] = StateLoadResult(
            StateLoadStatus.OK,
            schema_version=_SCHEDULER_STATE_VERSION,
        )

    def _load_pending_confirmations(self) -> bool:
        if self._pending_file is None:
            return False
        try:
            raw_bytes = read_owner_only_regular_file(self._pending_file)
        except OSError:
            self._state_load_results["pending_confirmations"] = StateLoadResult(
                StateLoadStatus.CORRUPT,
                reason="read_error",
            )
            return False
        if raw_bytes is None:
            self._state_load_results["pending_confirmations"] = StateLoadResult(
                StateLoadStatus.MISSING
            )
            self._durable_pending_confirmations = defaultdict(list)
            return False
        try:
            raw = json.loads(raw_bytes.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError, RecursionError):
            raw = None
        result: StateLoadResult
        payload: Any
        if isinstance(raw, dict) and not {
            "version",
            "checksum",
            "payload",
        }.intersection(raw):
            result = StateLoadResult(StateLoadStatus.OK, legacy=True)
            payload = raw
        else:
            result, payload = decode_versioned_json_snapshot(
                raw_bytes,
                supported_version=_SCHEDULER_STATE_VERSION,
            )
        if result.status != StateLoadStatus.OK:
            self._state_load_results["pending_confirmations"] = result
            return False
        if not isinstance(payload, dict):
            self._state_load_results[
                "pending_confirmations"
            ] = self._semantic_corruption_result(
                result,
                "invalid_pending_payload",
            )
            return False
        restored: defaultdict[str, list[dict[str, Any]]] = defaultdict(list)
        confirmation_ids: set[str] = set()
        for task_id, rows in payload.items():
            if not isinstance(task_id, str) or not task_id.strip():
                self._state_load_results[
                    "pending_confirmations"
                ] = self._semantic_corruption_result(
                    result,
                    "invalid_pending_task_id",
                )
                return False
            if task_id not in self._tasks:
                self._state_load_results[
                    "pending_confirmations"
                ] = self._semantic_corruption_result(
                    result,
                    "unknown_pending_task",
                )
                return False
            if not isinstance(rows, list):
                self._state_load_results[
                    "pending_confirmations"
                ] = self._semantic_corruption_result(
                    result,
                    "invalid_pending_rows",
                )
                return False
            for item in rows:
                if not isinstance(item, dict) or not self._pending_row_is_valid(
                    item,
                    task_id=task_id,
                ):
                    self._state_load_results[
                        "pending_confirmations"
                    ] = self._semantic_corruption_result(
                        result,
                        "invalid_pending_row",
                    )
                    return False
                confirmation_id = item["confirmation_id"].strip()
                if item.get("run_outcome_recorded") is True:
                    task_outcome = self._tasks[
                        task_id
                    ].confirmation_outcome_dedup.get(confirmation_id)
                    if task_outcome is None or task_outcome is not item.get(
                        "run_outcome_success"
                    ):
                        self._state_load_results[
                            "pending_confirmations"
                        ] = self._semantic_corruption_result(
                            result,
                            "invalid_pending_outcome_state",
                        )
                        return False
                if confirmation_id in confirmation_ids:
                    self._state_load_results[
                        "pending_confirmations"
                    ] = self._semantic_corruption_result(
                        result,
                        "duplicate_pending_confirmation",
                    )
                    return False
                confirmation_ids.add(confirmation_id)
            if rows:
                restored[task_id] = copy.deepcopy(rows)
        self._pending_confirmations = restored
        self._durable_pending_confirmations = self._clone_pending_confirmations(restored)
        self._state_load_results["pending_confirmations"] = result
        return True

    @staticmethod
    def _pending_row_is_valid(row: dict[str, Any], *, task_id: str) -> bool:
        confirmation_id = row.get("confirmation_id")
        if not isinstance(confirmation_id, str) or not confirmation_id.strip():
            return False
        for field in _PENDING_STRING_FIELDS:
            if field in row and not isinstance(row[field], str):
                return False
        row_task_id = row.get("task_id")
        if not isinstance(row_task_id, str) or row_task_id.strip() != task_id:
            return False
        for field in ("run_outcome_recorded", "run_outcome_success"):
            if field in row and not isinstance(row[field], bool):
                return False
        if row.get("run_outcome_recorded") is True and not isinstance(
            row.get("run_outcome_success"),
            bool,
        ):
            return False
        identity = row.get("identity")
        if not isinstance(identity, dict):
            return False
        for field in _PENDING_IDENTITY_STRING_FIELDS:
            if field in identity and not isinstance(identity[field], str):
                return False
        delivery_target = identity.get("delivery_target")
        if delivery_target is not None and not isinstance(delivery_target, dict):
            return False
        identity_task_id = identity.get("task_id")
        if not isinstance(identity_task_id, str) or identity_task_id.strip() != task_id:
            return False
        identity_confirmation_id = identity.get("confirmation_id")
        return (
            isinstance(identity_confirmation_id, str)
            and identity_confirmation_id.strip() == confirmation_id.strip()
        )
