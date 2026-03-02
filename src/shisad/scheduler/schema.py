"""Scheduler data models."""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, Field

from shisad.core.types import Capability, UserId


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


class ScheduledTask(BaseModel):
    id: str = Field(default_factory=lambda: uuid.uuid4().hex)
    name: str
    schedule: Schedule
    goal: str
    capability_snapshot: set[Capability] = Field(default_factory=set)
    policy_snapshot_ref: str
    allowed_recipients: list[str] = Field(default_factory=list)
    allowed_domains: list[str] = Field(default_factory=list)
    delivery_target: dict[str, str] = Field(default_factory=dict)
    created_by: UserId
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    last_triggered_at: datetime | None = None
    trigger_count: int = 0
    success_count: int = 0
    failure_count: int = 0
    enabled: bool = True

    def commitment_hash(self) -> str:
        payload = {
            "id": self.id,
            "name": self.name,
            "goal": self.goal,
            "schedule": self.schedule.model_dump(mode="json"),
            "capability_snapshot": sorted(cap.value for cap in self.capability_snapshot),
            "policy_snapshot_ref": self.policy_snapshot_ref,
            "allowed_recipients": sorted(self.allowed_recipients),
            "allowed_domains": sorted(self.allowed_domains),
            "delivery_target": dict(self.delivery_target),
            "created_by": str(self.created_by),
            "created_at": self.created_at.isoformat(),
        }
        encoded = json.dumps(payload, sort_keys=True)
        return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


class TaskRunRequest(BaseModel):
    task_id: str
    trigger_payload: str
    payload_taint: str = "UNTRUSTED"
    plan_commitment: str
