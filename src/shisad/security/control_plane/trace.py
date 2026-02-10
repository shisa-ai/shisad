"""Execution trace verifier and plan commitment lifecycle."""

from __future__ import annotations

import fnmatch
import hashlib
import json
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from shisad.security.control_plane.schema import ActionKind, ControlPlaneAction, Origin, RiskTier


class PlanStage(StrEnum):
    STAGE1_PRECONTENT = "stage1_precontent"
    STAGE2_POSTEVIDENCE = "stage2_postevidence"


class CommittedPlan(BaseModel):
    session_id: str
    plan_hash: str
    allowed_actions: set[ActionKind] = Field(default_factory=set)
    allowed_resources: set[str] = Field(default_factory=set)
    forbidden_actions: set[ActionKind] = Field(default_factory=set)
    max_actions: int = 10
    committed_at: datetime
    expires_at: datetime
    stage: str = PlanStage.STAGE1_PRECONTENT
    amendment_of: str = ""
    cancelled: bool = False
    cancelled_reason: str = ""
    executed_actions: int = 0


class PlanVerificationResult(BaseModel, frozen=True):
    allowed: bool
    reason_code: str
    risk_tier: RiskTier = RiskTier.LOW


class ExecutionTraceVerifier:
    """Commits structural plans and verifies execution against them."""

    def __init__(
        self,
        *,
        storage_path: Path | None = None,
        default_ttl_seconds: int = 1800,
        default_max_actions: int = 10,
    ) -> None:
        self._storage_path = storage_path
        self._default_ttl_seconds = default_ttl_seconds
        self._default_max_actions = default_max_actions
        self._plans: dict[str, CommittedPlan] = {}
        self._load()

    def begin_precontent_plan(
        self,
        *,
        session_id: str,
        goal: str,
        origin: Origin,
        ttl_seconds: int | None = None,
        max_actions: int | None = None,
    ) -> CommittedPlan:
        _ = origin
        now = datetime.now(UTC)
        ttl = ttl_seconds or self._default_ttl_seconds
        max_allowed = max_actions or self._default_max_actions
        allowed_actions = self._stage1_allowed_actions(goal)

        plan = self._commit_plan(
            session_id=session_id,
            allowed_actions=allowed_actions,
            allowed_resources=set(),
            forbidden_actions=set(),
            max_actions=max_allowed,
            committed_at=now,
            expires_at=now + timedelta(seconds=ttl),
            stage=PlanStage.STAGE1_PRECONTENT,
            amendment_of="",
        )
        self._plans[session_id] = plan
        self._persist()
        return plan

    def active_plan(self, session_id: str) -> CommittedPlan | None:
        plan = self._plans.get(session_id)
        if plan is None:
            return None
        if plan.cancelled:
            return None
        if datetime.now(UTC) > plan.expires_at:
            return None
        return plan

    def verify_action(
        self,
        *,
        session_id: str,
        action: ControlPlaneAction,
    ) -> PlanVerificationResult:
        plan = self.active_plan(session_id)
        if plan is None:
            return PlanVerificationResult(
                allowed=False,
                reason_code="trace:no_active_plan",
                risk_tier=RiskTier.HIGH,
            )

        if action.action_kind in plan.forbidden_actions:
            return PlanVerificationResult(
                allowed=False,
                reason_code="trace:forbidden_action",
                risk_tier=RiskTier.CRITICAL,
            )

        if action.tool_name == "report_anomaly":
            if plan.executed_actions >= plan.max_actions:
                return PlanVerificationResult(
                    allowed=False,
                    reason_code="trace:max_actions_exceeded",
                    risk_tier=RiskTier.MEDIUM,
                )
            return PlanVerificationResult(
                allowed=True,
                reason_code="trace:allowed_safety_tool",
                risk_tier=RiskTier.LOW,
            )

        if action.action_kind not in plan.allowed_actions:
            if plan.stage == PlanStage.STAGE1_PRECONTENT and action.action_kind in {
                ActionKind.EGRESS,
                ActionKind.FS_WRITE,
                ActionKind.MEMORY_WRITE,
                ActionKind.MESSAGE_SEND,
            }:
                return PlanVerificationResult(
                    allowed=False,
                    reason_code="trace:stage2_upgrade_required",
                    risk_tier=RiskTier.HIGH,
                )
            return PlanVerificationResult(
                allowed=False,
                reason_code="trace:action_not_committed",
                risk_tier=RiskTier.HIGH,
            )

        if plan.allowed_resources and action.resource_id and not any(
            fnmatch.fnmatch(action.resource_id, pattern) for pattern in plan.allowed_resources
        ):
            return PlanVerificationResult(
                allowed=False,
                reason_code="trace:resource_not_committed",
                risk_tier=RiskTier.HIGH,
            )

        if plan.executed_actions >= plan.max_actions:
            return PlanVerificationResult(
                allowed=False,
                reason_code="trace:max_actions_exceeded",
                risk_tier=RiskTier.MEDIUM,
            )

        return PlanVerificationResult(
            allowed=True,
            reason_code="trace:allowed",
            risk_tier=RiskTier.LOW,
        )

    def record_action(self, *, session_id: str) -> None:
        plan = self._plans.get(session_id)
        if plan is None:
            return
        plan.executed_actions += 1
        self._persist()

    def cancel(self, *, session_id: str, reason: str) -> bool:
        plan = self._plans.get(session_id)
        if plan is None:
            return False
        plan.cancelled = True
        plan.cancelled_reason = reason
        self._persist()
        return True

    def amend(
        self,
        *,
        session_id: str,
        approved_by: str,
        allow_actions: set[ActionKind],
        allow_resources: set[str],
        ttl_seconds: int | None = None,
    ) -> CommittedPlan:
        if not approved_by.strip():
            raise ValueError("approved_by is required for plan amendment")
        current = self.active_plan(session_id)
        if current is None:
            raise ValueError("cannot amend missing or inactive plan")
        now = datetime.now(UTC)
        ttl = ttl_seconds or self._default_ttl_seconds
        amended = self._commit_plan(
            session_id=session_id,
            allowed_actions=set(current.allowed_actions) | set(allow_actions),
            allowed_resources=set(current.allowed_resources) | set(allow_resources),
            forbidden_actions=set(current.forbidden_actions) - set(allow_actions),
            max_actions=current.max_actions,
            committed_at=now,
            expires_at=now + timedelta(seconds=ttl),
            stage=PlanStage.STAGE2_POSTEVIDENCE,
            amendment_of=current.plan_hash,
        )
        self._plans[session_id] = amended
        self._persist()
        return amended

    def _commit_plan(
        self,
        *,
        session_id: str,
        allowed_actions: set[ActionKind],
        allowed_resources: set[str],
        forbidden_actions: set[ActionKind],
        max_actions: int,
        committed_at: datetime,
        expires_at: datetime,
        stage: str,
        amendment_of: str,
    ) -> CommittedPlan:
        payload: dict[str, Any] = {
            "session_id": session_id,
            "allowed_actions": sorted(item.value for item in allowed_actions),
            "allowed_resources": sorted(allowed_resources),
            "forbidden_actions": sorted(item.value for item in forbidden_actions),
            "max_actions": max_actions,
            "committed_at": committed_at.isoformat(),
            "expires_at": expires_at.isoformat(),
            "stage": stage,
            "amendment_of": amendment_of,
        }
        encoded = json.dumps(payload, sort_keys=True)
        plan_hash = hashlib.sha256(encoded.encode("utf-8")).hexdigest()
        return CommittedPlan(
            session_id=session_id,
            plan_hash=plan_hash,
            allowed_actions=set(allowed_actions),
            allowed_resources=set(allowed_resources),
            forbidden_actions=set(forbidden_actions),
            max_actions=max_actions,
            committed_at=committed_at,
            expires_at=expires_at,
            stage=stage,
            amendment_of=amendment_of,
            executed_actions=0,
        )

    @staticmethod
    def _strict_stage1_actions() -> set[ActionKind]:
        return {
            ActionKind.FS_READ,
            ActionKind.FS_LIST,
            ActionKind.MEMORY_READ,
            ActionKind.SHELL_EXEC,
        }

    def _stage1_allowed_actions(self, goal: str) -> set[ActionKind]:
        _ = goal
        return self._strict_stage1_actions()

    def _persist(self) -> None:
        if self._storage_path is None:
            return
        self._storage_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            session_id: plan.model_dump(mode="json")
            for session_id, plan in sorted(self._plans.items(), key=lambda item: item[0])
        }
        self._storage_path.write_text(
            json.dumps(payload, indent=2, sort_keys=True),
            encoding="utf-8",
        )

    def _load(self) -> None:
        if self._storage_path is None or not self._storage_path.exists():
            return
        try:
            payload = json.loads(self._storage_path.read_text(encoding="utf-8"))
        except Exception:
            return
        if not isinstance(payload, dict):
            return
        for key, value in payload.items():
            if not isinstance(key, str):
                continue
            try:
                self._plans[key] = CommittedPlan.model_validate(value)
            except Exception:
                continue
