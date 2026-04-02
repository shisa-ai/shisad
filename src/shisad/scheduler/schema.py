"""Scheduler data models."""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, Field, model_validator

from shisad.core.types import Capability, UserId, WorkspaceId


class ScheduleKind(StrEnum):
    CRON = "cron"
    INTERVAL = "interval"
    EVENT = "event"


class Schedule(BaseModel):
    kind: ScheduleKind
    expression: str
    event_type: str | None = None
    event_filter: dict[str, str] = Field(default_factory=dict)

    @classmethod
    def from_event(cls, event_type: str, event_filter: dict[str, str] | None = None) -> Schedule:
        return cls(
            kind=ScheduleKind.EVENT,
            expression=event_type,
            event_type=event_type,
            event_filter=event_filter or {},
        )


class TaskEnvelope(BaseModel):
    """Immutable task-execution boundary metadata."""

    envelope_id: str = Field(default_factory=lambda: uuid.uuid4().hex)
    capability_snapshot: frozenset[Capability] = Field(default_factory=frozenset)
    parent_session_id: str = ""
    orchestrator_provenance: str = ""
    audit_trail_ref: str = ""
    policy_snapshot_ref: str = ""
    lockdown_state_inheritance: str = "inherit_runtime_restrictions"
    credential_refs: tuple[str, ...] = ()
    resource_scope_ids: tuple[str, ...] = ()
    resource_scope_prefixes: tuple[str, ...] = ()
    untrusted_payload_action: str = "require_confirmation"

    @model_validator(mode="before")
    @classmethod
    def _normalize_scope_fields(cls, value: object) -> object:
        if not isinstance(value, dict):
            return value
        payload = dict(value)

        def _normalized_sequence(raw: object) -> tuple[str, ...]:
            if not isinstance(raw, (list, tuple)):
                return ()
            items: list[str] = []
            for item in raw:
                normalized = str(item).strip()
                if normalized and normalized not in items:
                    items.append(normalized)
            return tuple(items)

        payload["credential_refs"] = _normalized_sequence(payload.get("credential_refs", ()))
        payload["resource_scope_ids"] = _normalized_sequence(
            payload.get("resource_scope_ids", ())
        )
        payload["resource_scope_prefixes"] = _normalized_sequence(
            payload.get("resource_scope_prefixes", ())
        )
        action = (
            str(payload.get("untrusted_payload_action", "require_confirmation"))
            .strip()
            .lower()
        )
        if action not in {"require_confirmation", "reject"}:
            action = "require_confirmation"
        payload["untrusted_payload_action"] = action
        return payload

    model_config = {"frozen": True}


class ScheduledTask(BaseModel):
    id: str = Field(default_factory=lambda: uuid.uuid4().hex)
    name: str
    schedule: Schedule
    goal: str
    capability_snapshot: frozenset[Capability] = Field(default_factory=frozenset)
    policy_snapshot_ref: str
    task_envelope: TaskEnvelope = Field(default_factory=TaskEnvelope)
    allowed_recipients: list[str] = Field(default_factory=list)
    allowed_domains: list[str] = Field(default_factory=list)
    delivery_target: dict[str, str] = Field(default_factory=dict)
    created_by: UserId
    workspace_id: WorkspaceId = Field(default_factory=lambda: WorkspaceId(""))
    execution_session_id: str = ""
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    last_triggered_at: datetime | None = None
    trigger_count: int = 0
    success_count: int = 0
    failure_count: int = 0
    max_runs: int = 0
    enabled: bool = True

    @model_validator(mode="before")
    @classmethod
    def _backfill_task_envelope(cls, value: object) -> object:
        if not isinstance(value, dict):
            return value
        payload = dict(value)
        if "task_envelope" not in payload:
            created_by = str(payload.get("created_by", "")).strip()
            workspace_id = str(payload.get("workspace_id", "")).strip()
            provenance = "scheduler"
            if created_by or workspace_id:
                provenance = f"scheduler:{created_by or 'unknown'}:{workspace_id or 'default'}"
            payload["task_envelope"] = {
                "envelope_id": uuid.uuid4().hex,
                "capability_snapshot": list(payload.get("capability_snapshot", [])),
                "parent_session_id": "",
                "orchestrator_provenance": provenance,
                "audit_trail_ref": "",
                "policy_snapshot_ref": str(payload.get("policy_snapshot_ref", "")).strip(),
                "lockdown_state_inheritance": "inherit_runtime_restrictions",
                "credential_refs": [],
                "resource_scope_ids": [],
                "resource_scope_prefixes": [],
                "untrusted_payload_action": "require_confirmation",
            }
        return payload

    def commitment_hash(self) -> str:
        payload = {
            "id": self.id,
            "name": self.name,
            "goal": self.goal,
            "schedule": self.schedule.model_dump(mode="json"),
            "capability_snapshot": sorted(cap.value for cap in self.capability_snapshot),
            "policy_snapshot_ref": self.policy_snapshot_ref,
            "task_envelope": {
                "envelope_id": self.task_envelope.envelope_id,
                "capability_snapshot": sorted(
                    cap.value for cap in self.task_envelope.capability_snapshot
                ),
                "parent_session_id": self.task_envelope.parent_session_id,
                "orchestrator_provenance": self.task_envelope.orchestrator_provenance,
                "audit_trail_ref": self.task_envelope.audit_trail_ref,
                "policy_snapshot_ref": self.task_envelope.policy_snapshot_ref,
                "lockdown_state_inheritance": self.task_envelope.lockdown_state_inheritance,
                "credential_refs": sorted(self.task_envelope.credential_refs),
                "resource_scope_ids": sorted(self.task_envelope.resource_scope_ids),
                "resource_scope_prefixes": sorted(self.task_envelope.resource_scope_prefixes),
                "untrusted_payload_action": self.task_envelope.untrusted_payload_action,
            },
            "allowed_recipients": sorted(self.allowed_recipients),
            "allowed_domains": sorted(self.allowed_domains),
            "delivery_target": dict(self.delivery_target),
            "created_by": str(self.created_by),
            "workspace_id": str(self.workspace_id),
            "created_at": self.created_at.isoformat(),
            "max_runs": int(self.max_runs),
        }
        encoded = json.dumps(payload, sort_keys=True)
        return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


class TaskRunRequest(BaseModel):
    task_id: str
    trigger_payload: str
    payload_taint: str = "UNTRUSTED"
    plan_commitment: str
