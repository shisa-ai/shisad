"""Execution trace verifier and plan commitment lifecycle."""

from __future__ import annotations

import contextlib
import fnmatch
import hashlib
import json
import re
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from shisad.core.atomic_state import (
    AtomicWriteError,
    AtomicWriteFaultInjector,
    StateLoadResult,
    StateLoadStatus,
    StatePersistenceDegradedError,
    atomic_write_bytes,
    decode_json_document,
    decode_versioned_json_snapshot,
    encode_versioned_json_snapshot,
    read_owner_only_regular_file,
)
from shisad.core.types import Capability
from shisad.core.url_parsing import safe_url_hostname
from shisad.security.control_plane.schema import (
    ActionKind,
    ControlPlaneAction,
    Origin,
    RiskTier,
    action_kinds_for_capabilities,
    control_plane_trace_action_idempotency_key,
    normalize_workspace_path,
)
from shisad.security.host_extraction import extract_hosts_from_text, host_patterns


class PlanStage(StrEnum):
    STAGE1_PRECONTENT = "stage1_precontent"
    STAGE2_POSTEVIDENCE = "stage2_postevidence"


TRACE_CONFIRMATION_REASON_CODES: frozenset[str] = frozenset(
    {
        "trace:stage2_upgrade_required",
        "trace:tdg_confirmation_required",
    }
)

_TDG_CONFIRMATION_REASON = "trace:tdg_confirmation_required"
_TDG_BLOCK_REASON = "trace:tdg_dependency_path_missing"
_TDG_ENFORCED_ACTION_KINDS: frozenset[ActionKind] = frozenset(
    {
        ActionKind.FS_READ,
        ActionKind.FS_LIST,
        ActionKind.FS_WRITE,
        ActionKind.EGRESS,
        ActionKind.BROWSER_READ,
        ActionKind.BROWSER_WRITE,
    }
)
_TDG_READ_LIKE_ACTION_KINDS: frozenset[ActionKind] = frozenset(
    {
        ActionKind.FS_READ,
        ActionKind.FS_LIST,
        ActionKind.BROWSER_READ,
    }
)
_TDG_READ_LIKE_TOOLS: frozenset[str] = frozenset(
    {
        "file.read",
        "fs.list",
        "fs.read",
        "git.diff",
        "git.log",
        "git.status",
        "web.fetch",
        "web.search",
        "browser.navigate",
        "browser.read_page",
        "browser.screenshot",
    }
)
_GOAL_PATH_TOKEN_RE = re.compile(r"[^\s<>()\"'`]+")
_GOAL_LOCAL_FILE_EXTENSIONS: frozenset[str] = frozenset(
    {
        ".txt",
        ".md",
        ".rst",
        ".json",
        ".yaml",
        ".yml",
        ".toml",
        ".ini",
        ".conf",
        ".cfg",
        ".csv",
        ".tsv",
        ".log",
        ".xml",
        ".py",
        ".ts",
        ".js",
        ".sh",
        ".bash",
        ".zsh",
        ".ps1",
        ".sql",
    }
)
_GOAL_BARE_FILE_NAMES: frozenset[str] = frozenset(
    {
        "README",
        "LICENSE",
        "CHANGELOG",
        "MAKEFILE",
    }
)
_WORKSPACE_ROOT_MARKER = "workspace_root:"
_WORKSPACE_ROOT_DIRECTORY_ACTION_RE = re.compile(
    r"\b(?:list|show|display|inspect|explore|open|read|check|look at|review)\b"
    r".{0,80}\b(?:current folder|current directory|working directory|"
    r"folder you're in|directory you're in|this folder|this directory|"
    r"the folder|the directory|here)\b",
    re.IGNORECASE,
)
_WORKSPACE_ROOT_GIT_ACTION_RE = re.compile(
    r"\b(?:show|display|check|inspect|run|get|look at|review)\b"
    r".{0,80}\b(?:git status|git diff|git log|repo status|repo diff|repo log|"
    r"repository status|repository diff|repository log)\b",
    re.IGNORECASE,
)
_WORKSPACE_ROOT_GIT_COMMAND_RE = re.compile(
    r"^\s*(?:git status|git diff|git log|repo status|repo diff|repo log|"
    r"repository status|repository diff|repository log)\s*[.!?]?\s*$",
    re.IGNORECASE,
)
_TRACE_STATE_VERSION = 1


def trace_reason_requires_confirmation(reason_code: str) -> bool:
    return reason_code.strip() in TRACE_CONFIRMATION_REASON_CODES


class CommittedPlan(BaseModel):
    model_config = ConfigDict(extra="forbid")

    session_id: str
    plan_hash: str
    allowed_actions: set[ActionKind] = Field(default_factory=set)
    allowed_resources: set[str] = Field(default_factory=set)
    goal_resource_patterns: set[str] = Field(default_factory=set)
    declared_resource_roots: set[str] = Field(default_factory=set)
    reachable_resources: set[str] = Field(default_factory=set)
    forbidden_actions: set[ActionKind] = Field(default_factory=set)
    max_actions: int = Field(default=10, gt=0, strict=True)
    committed_at: datetime
    expires_at: datetime
    stage: str = PlanStage.STAGE1_PRECONTENT
    amendment_of: str = ""
    amendment_correlation_id: str = ""
    amendment_execution_idempotency_key: str = ""
    cancelled: bool = Field(default=False, strict=True)
    cancelled_reason: str = ""
    executed_actions: int = Field(default=0, ge=0, strict=True)
    recorded_dependency_keys: set[str] = Field(default_factory=set)
    recorded_action_keys: set[str] = Field(default_factory=set)

    @field_validator("committed_at", "expires_at")
    @classmethod
    def _require_aware_timestamp(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("plan timestamps must be timezone-aware")
        return value


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
        workspace_roots: list[Path] | None = None,
    ) -> None:
        self._storage_path = storage_path
        self._default_ttl_seconds = default_ttl_seconds
        self._default_max_actions = default_max_actions
        self._workspace_roots = [
            item.expanduser().resolve(strict=False) for item in (workspace_roots or [Path.cwd()])
        ]
        self._plans: dict[str, CommittedPlan] = {}
        self._state_load_result = StateLoadResult(
            StateLoadStatus.OK if storage_path is None else StateLoadStatus.MISSING
        )
        self._persistence_degradation: AtomicWriteError | None = None
        self._state_fault_injector: AtomicWriteFaultInjector | None = None
        self._load()

    @property
    def state_load_result(self) -> StateLoadResult:
        return self._state_load_result

    @property
    def state_degraded(self) -> bool:
        return self._persistence_degradation is not None or self._state_load_result.status in {
            StateLoadStatus.CORRUPT,
            StateLoadStatus.UNSUPPORTED_SCHEMA,
        }

    def state_status(self) -> dict[str, Any]:
        persistence = self._persistence_degradation
        load_result = self._state_load_result
        return {
            "status": "degraded" if self.state_degraded else "ok",
            "problems": ["control_plane_trace_state_degraded"] if self.state_degraded else [],
            "path": str(self._storage_path or ""),
            "load_status": load_result.status.value,
            "reason": load_result.reason,
            "schema_version": load_result.schema_version,
            "legacy": load_result.legacy,
            "fail_closed": self.state_degraded,
            "stage": persistence.stage.value if persistence is not None else "",
            "remediation": (
                "Restore or explicitly reset the retained control-plane plan snapshot, then "
                "restart shisad."
                if self.state_degraded
                else ""
            ),
        }

    def reset_state(self) -> int:
        """Durably replace retained plans with an empty current-schema snapshot."""

        cleared = len(self._plans)
        if self._storage_path is not None:
            try:
                atomic_write_bytes(
                    self._storage_path,
                    encode_versioned_json_snapshot({}, version=_TRACE_STATE_VERSION),
                    fault_injector=self._state_fault_injector,
                )
            except AtomicWriteError as exc:
                if exc.publication_may_have_committed:
                    self._persistence_degradation = exc
                raise
        self._plans.clear()
        self._persistence_degradation = None
        self._state_load_result = StateLoadResult(
            StateLoadStatus.OK,
            schema_version=_TRACE_STATE_VERSION,
        )
        return cleared

    def _require_available(self, *, transition: str) -> None:
        if not self.state_degraded:
            return
        persistence = self._persistence_degradation
        raise StatePersistenceDegradedError(
            authority="control_plane_trace",
            transition=transition,
            stage=persistence.stage.value if persistence is not None else "load",
            reason=(
                "publication_commit_uncertain"
                if persistence is not None and persistence.publication_may_have_committed
                else "persistence_failed"
                if persistence is not None
                else self._state_load_result.reason or self._state_load_result.status.value
            ),
        )

    def begin_precontent_plan(
        self,
        *,
        session_id: str,
        goal: str,
        origin: Origin,
        ttl_seconds: int | None = None,
        max_actions: int | None = None,
        capabilities: set[Capability] | None = None,
        declared_resource_roots: set[str] | None = None,
    ) -> CommittedPlan:
        self._require_available(transition="begin_precontent_plan")
        _ = origin
        now = datetime.now(UTC)
        ttl = ttl_seconds or self._default_ttl_seconds
        max_allowed = max_actions or self._default_max_actions
        allowed_actions = self._stage1_allowed_actions(goal, capabilities=capabilities)
        goal_resource_patterns = self._goal_resource_patterns(goal)
        normalized_declared_roots = self._normalize_declared_resource_roots(
            declared_resource_roots or set()
        )

        plan = self._commit_plan(
            session_id=session_id,
            allowed_actions=allowed_actions,
            allowed_resources=set(),
            goal_resource_patterns=goal_resource_patterns,
            declared_resource_roots=normalized_declared_roots,
            forbidden_actions=set(),
            max_actions=max_allowed,
            committed_at=now,
            expires_at=now + timedelta(seconds=ttl),
            stage=PlanStage.STAGE1_PRECONTENT,
            amendment_of="",
        )
        candidate = dict(self._plans)
        candidate[session_id] = plan
        self._commit_candidate(candidate)
        return plan.model_copy(deep=True)

    def active_plan(self, session_id: str) -> CommittedPlan | None:
        if self.state_degraded:
            return None
        plan = self._plans.get(session_id)
        if plan is None:
            return None
        if plan.cancelled:
            return None
        if datetime.now(UTC) > plan.expires_at:
            return None
        return plan.model_copy(deep=True)

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
                ActionKind.BROWSER_WRITE,
                ActionKind.FS_WRITE,
                ActionKind.MEMORY_WRITE,
                ActionKind.MESSAGE_SEND,
                ActionKind.SHELL_EXEC,
                ActionKind.MCP_EXTERNAL,
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

        if (
            plan.allowed_resources
            and action.resource_id
            and not any(
                fnmatch.fnmatch(action.resource_id, pattern) for pattern in plan.allowed_resources
            )
        ):
            return PlanVerificationResult(
                allowed=False,
                reason_code="trace:resource_not_committed",
                risk_tier=RiskTier.HIGH,
            )

        tdg_reason = self._tdg_reason(plan=plan, action=action)
        if tdg_reason:
            return PlanVerificationResult(
                allowed=False,
                reason_code=tdg_reason,
                risk_tier=(
                    RiskTier.MEDIUM if tdg_reason == _TDG_CONFIRMATION_REASON else RiskTier.HIGH
                ),
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

    def record_action(
        self,
        *,
        session_id: str,
        idempotency_key: str = "",
        expected_plan_hash: str = "",
    ) -> None:
        self._require_available(transition="record_action")
        plan = self._plans.get(session_id)
        if plan is None:
            return
        normalized_plan_hash = expected_plan_hash.strip()
        if normalized_plan_hash and plan.plan_hash != normalized_plan_hash:
            return
        normalized_key = idempotency_key.strip()
        if normalized_key and normalized_key in plan.recorded_action_keys:
            # A prior mutation may have reached memory but failed persistence.
            # Persist the same state again so replay repairs that boundary.
            self._persist()
            return
        candidate = self._copy_plans()
        candidate_plan = candidate[session_id]
        candidate_plan.executed_actions += 1
        if normalized_key:
            candidate_plan.recorded_action_keys.add(normalized_key)
        self._commit_candidate(candidate)

    def record_dependency_path(
        self,
        *,
        session_id: str,
        action: ControlPlaneAction,
        idempotency_key: str = "",
        expected_plan_hash: str = "",
    ) -> None:
        self._require_available(transition="record_dependency_path")
        plan = self._plans.get(session_id)
        if plan is None:
            return
        normalized_plan_hash = expected_plan_hash.strip()
        if normalized_plan_hash and plan.plan_hash != normalized_plan_hash:
            return
        if not self._tdg_enforcement_applies(action):
            return
        normalized_key = idempotency_key.strip()
        if normalized_key and normalized_key in plan.recorded_dependency_keys:
            # Re-persist duplicate replay so an interrupted prior write is
            # repaired without applying the dependency mutation twice.
            self._persist()
            return
        candidate = self._copy_plans()
        candidate_plan = candidate[session_id]
        candidate_plan.reachable_resources.update(item for item in action.resource_ids if item)
        if normalized_key:
            candidate_plan.recorded_dependency_keys.add(normalized_key)
        self._commit_candidate(candidate)

    def cancel(self, *, session_id: str, reason: str) -> bool:
        self._require_available(transition="cancel")
        plan = self._plans.get(session_id)
        if plan is None:
            return False
        candidate = self._copy_plans()
        candidate[session_id].cancelled = True
        candidate[session_id].cancelled_reason = reason
        self._commit_candidate(candidate)
        return True

    def amend(
        self,
        *,
        session_id: str,
        approved_by: str,
        allow_actions: set[ActionKind],
        allow_resources: set[str],
        ttl_seconds: int | None = None,
        correlation_id: str = "",
        expected_previous_hash: str = "",
        execution_idempotency_key: str = "",
    ) -> CommittedPlan:
        self._require_available(transition="amend")
        if not approved_by.strip():
            raise ValueError("approved_by is required for plan amendment")
        current = self.active_plan(session_id)
        if current is None:
            raise ValueError("cannot amend missing or inactive plan")
        normalized_correlation = correlation_id.strip()
        normalized_previous_hash = expected_previous_hash.strip()
        normalized_execution_key = execution_idempotency_key.strip()
        if bool(normalized_correlation) != bool(normalized_execution_key):
            raise ValueError("stage2 correlation execution-key mismatch")
        if normalized_correlation and current.amendment_correlation_id == normalized_correlation:
            if normalized_previous_hash and current.amendment_of != normalized_previous_hash:
                raise ValueError("stage2 correlation previous-plan mismatch")
            if current.amendment_execution_idempotency_key != normalized_execution_key:
                raise ValueError("stage2 correlation execution-key mismatch")
            return current
        if normalized_previous_hash and current.plan_hash != normalized_previous_hash:
            raise ValueError("stage2 previous plan changed")
        now = datetime.now(UTC)
        ttl = ttl_seconds or self._default_ttl_seconds
        amended = self._commit_plan(
            session_id=session_id,
            allowed_actions=set(current.allowed_actions) | set(allow_actions),
            allowed_resources=set(current.allowed_resources) | set(allow_resources),
            goal_resource_patterns=set(current.goal_resource_patterns),
            declared_resource_roots=set(current.declared_resource_roots),
            forbidden_actions=set(current.forbidden_actions) - set(allow_actions),
            max_actions=current.max_actions,
            committed_at=now,
            expires_at=now + timedelta(seconds=ttl),
            stage=PlanStage.STAGE2_POSTEVIDENCE,
            amendment_of=current.plan_hash,
            amendment_correlation_id=normalized_correlation,
            amendment_execution_idempotency_key=normalized_execution_key,
        )
        amended.reachable_resources = set(current.reachable_resources)
        amended.recorded_dependency_keys = set(current.recorded_dependency_keys)
        amended.recorded_action_keys = set(current.recorded_action_keys)
        candidate = dict(self._plans)
        candidate[session_id] = amended
        self._commit_candidate(candidate)
        return amended

    def _commit_plan(
        self,
        *,
        session_id: str,
        allowed_actions: set[ActionKind],
        allowed_resources: set[str],
        goal_resource_patterns: set[str],
        declared_resource_roots: set[str],
        forbidden_actions: set[ActionKind],
        max_actions: int,
        committed_at: datetime,
        expires_at: datetime,
        stage: str,
        amendment_of: str,
        amendment_correlation_id: str = "",
        amendment_execution_idempotency_key: str = "",
    ) -> CommittedPlan:
        plan_hash = self._plan_commitment_hash(
            session_id=session_id,
            allowed_actions=allowed_actions,
            allowed_resources=allowed_resources,
            goal_resource_patterns=goal_resource_patterns,
            declared_resource_roots=declared_resource_roots,
            forbidden_actions=forbidden_actions,
            max_actions=max_actions,
            committed_at=committed_at,
            expires_at=expires_at,
            stage=stage,
            amendment_of=amendment_of,
            amendment_correlation_id=amendment_correlation_id,
            amendment_execution_idempotency_key=amendment_execution_idempotency_key,
        )
        return CommittedPlan(
            session_id=session_id,
            plan_hash=plan_hash,
            allowed_actions=set(allowed_actions),
            allowed_resources=set(allowed_resources),
            goal_resource_patterns=set(goal_resource_patterns),
            declared_resource_roots=set(declared_resource_roots),
            forbidden_actions=set(forbidden_actions),
            max_actions=max_actions,
            committed_at=committed_at,
            expires_at=expires_at,
            stage=stage,
            amendment_of=amendment_of,
            amendment_correlation_id=amendment_correlation_id,
            amendment_execution_idempotency_key=(amendment_execution_idempotency_key),
            executed_actions=0,
        )

    @staticmethod
    def _plan_commitment_hash(
        *,
        session_id: str,
        allowed_actions: set[ActionKind],
        allowed_resources: set[str],
        goal_resource_patterns: set[str],
        declared_resource_roots: set[str],
        forbidden_actions: set[ActionKind],
        max_actions: int,
        committed_at: datetime,
        expires_at: datetime,
        stage: str,
        amendment_of: str,
        amendment_correlation_id: str = "",
        amendment_execution_idempotency_key: str = "",
    ) -> str:
        payload: dict[str, Any] = {
            "session_id": session_id,
            "allowed_actions": sorted(item.value for item in allowed_actions),
            "allowed_resources": sorted(allowed_resources),
            "goal_resource_patterns": sorted(goal_resource_patterns),
            "declared_resource_roots": sorted(declared_resource_roots),
            "forbidden_actions": sorted(item.value for item in forbidden_actions),
            "max_actions": max_actions,
            "committed_at": committed_at.isoformat(),
            "expires_at": expires_at.isoformat(),
            "stage": stage,
            "amendment_of": amendment_of,
        }
        if amendment_correlation_id:
            payload["amendment_correlation_id"] = amendment_correlation_id
        if amendment_execution_idempotency_key:
            payload["amendment_execution_idempotency_key"] = amendment_execution_idempotency_key
        encoded = json.dumps(payload, sort_keys=True)
        return hashlib.sha256(encoded.encode("utf-8")).hexdigest()

    @staticmethod
    def _strict_stage1_actions() -> set[ActionKind]:
        return {
            ActionKind.FS_READ,
            ActionKind.FS_LIST,
            ActionKind.MEMORY_READ,
            ActionKind.RUNTIME_READ,
        }

    def _stage1_allowed_actions(
        self, goal: str, *, capabilities: set[Capability] | None = None
    ) -> set[ActionKind]:
        _ = goal
        base = self._strict_stage1_actions()
        if capabilities:
            base = base | action_kinds_for_capabilities(capabilities)
        return base

    def _goal_resource_patterns(self, goal: str) -> set[str]:
        patterns = host_patterns(extract_hosts_from_text(goal))
        patterns.update(self._extract_goal_path_patterns(goal))
        patterns.update(self._goal_workspace_root_patterns(goal))
        return patterns

    def _tdg_reason(self, *, plan: CommittedPlan, action: ControlPlaneAction) -> str:
        if not self._tdg_enforcement_applies(action):
            return ""
        candidate_resources = [item for item in action.resource_ids if item]
        if not candidate_resources:
            if action.action_kind == ActionKind.BROWSER_WRITE:
                return _TDG_BLOCK_REASON
            return ""
        dependency_roots = (
            set(plan.goal_resource_patterns)
            | set(plan.declared_resource_roots)
            | set(plan.reachable_resources)
            | set(plan.allowed_resources)
        )
        if self._all_resources_grounded(candidate_resources, dependency_roots):
            return ""
        if self._tdg_read_like_action(action):
            return _TDG_CONFIRMATION_REASON
        return _TDG_BLOCK_REASON

    @staticmethod
    def _tdg_enforcement_applies(action: ControlPlaneAction) -> bool:
        if action.origin.actor == "control_api":
            return False
        return action.action_kind in _TDG_ENFORCED_ACTION_KINDS

    @staticmethod
    def _tdg_read_like_action(action: ControlPlaneAction) -> bool:
        if action.tool_name in _TDG_READ_LIKE_TOOLS:
            return True
        return action.action_kind in _TDG_READ_LIKE_ACTION_KINDS

    def _all_resources_grounded(
        self,
        candidate_resources: list[str],
        dependency_roots: set[str],
    ) -> bool:
        for candidate in candidate_resources:
            if not any(
                self._resource_matches(root=root, candidate=candidate) for root in dependency_roots
            ):
                return False
        return True

    @staticmethod
    def _resource_matches(*, root: str, candidate: str) -> bool:
        normalized_root = root.strip()
        normalized_candidate = candidate.strip()
        if not normalized_root or not normalized_candidate:
            return False
        if normalized_root.startswith(_WORKSPACE_ROOT_MARKER):
            exact_root = normalized_root.removeprefix(_WORKSPACE_ROOT_MARKER).strip()
            return normalized_candidate == exact_root
        if any(char in normalized_root for char in "*?[]"):
            return fnmatch.fnmatch(normalized_candidate.lower(), normalized_root.lower())
        if ExecutionTraceVerifier._looks_like_path_resource(normalized_root) and (
            ExecutionTraceVerifier._looks_like_path_resource(normalized_candidate)
        ):
            root_prefix = normalized_root.rstrip("/")
            candidate_prefix = normalized_candidate.rstrip("/")
            if candidate_prefix == root_prefix or candidate_prefix.startswith(f"{root_prefix}/"):
                return True
            root_name = Path(root_prefix).name
            candidate_name = Path(candidate_prefix).name
            if root_name and candidate_name and "." not in root_name:
                candidate_stem = Path(candidate_name).stem
                return (
                    candidate_stem.lower() == root_name.lower()
                    and Path(candidate_prefix).parent == Path(root_prefix).parent
                )
            return False
        return normalized_candidate.lower() == normalized_root.lower()

    @staticmethod
    def _looks_like_path_resource(value: str) -> bool:
        stripped = value.strip()
        if not stripped:
            return False
        return stripped.startswith(("/", "./", "../", "~/")) or "/" in stripped or "\\" in stripped

    def _extract_goal_path_patterns(self, goal: str) -> set[str]:
        patterns: set[str] = set()
        for match in _GOAL_PATH_TOKEN_RE.finditer(goal):
            token = match.group(0).strip(" \t\r\n\"'`.,;:!?)]}>")
            if not self._looks_like_goal_path_token(token):
                continue
            normalized = self._normalize_goal_path(token)
            if normalized:
                patterns.add(normalized)
        return patterns

    def _goal_workspace_root_patterns(self, goal: str) -> set[str]:
        if not self._goal_requests_workspace_root(goal):
            return set()
        if not self._workspace_roots:
            return set()
        return {f"{_WORKSPACE_ROOT_MARKER}{self._workspace_roots[0]}"}

    def _normalize_declared_resource_roots(self, roots: set[str]) -> set[str]:
        normalized: set[str] = set()
        for raw in roots:
            value = self._normalize_declared_resource_root(raw)
            if value:
                normalized.add(value)
        return normalized

    def _normalize_declared_resource_root(self, raw: str) -> str:
        value = str(raw).strip()
        if not value:
            return ""
        if "://" in value:
            return safe_url_hostname(value, strip_trailing_dot=True)
        if self._looks_like_path_resource(value) or self._looks_like_goal_path_token(value):
            return normalize_workspace_path(value, workspace_roots=self._workspace_roots)
        return value.lower()

    @staticmethod
    def _goal_requests_workspace_root(goal: str) -> bool:
        return bool(
            _WORKSPACE_ROOT_DIRECTORY_ACTION_RE.search(goal)
            or _WORKSPACE_ROOT_GIT_ACTION_RE.search(goal)
            or _WORKSPACE_ROOT_GIT_COMMAND_RE.match(goal)
        )

    @staticmethod
    def _looks_like_goal_path_token(token: str) -> bool:
        if not token or "://" in token or "@" in token:
            return False
        if token.startswith(("/", "./", "../", "~/", ".\\", "..\\")):
            return True
        if "/" in token or "\\" in token:
            return True
        suffix = Path(token).suffix.lower()
        if token.strip().upper() in _GOAL_BARE_FILE_NAMES:
            return True
        return suffix in _GOAL_LOCAL_FILE_EXTENSIONS

    def _normalize_goal_path(self, token: str) -> str:
        return normalize_workspace_path(token, workspace_roots=self._workspace_roots)

    def _copy_plans(self) -> dict[str, CommittedPlan]:
        return {session_id: plan.model_copy(deep=True) for session_id, plan in self._plans.items()}

    def _commit_candidate(self, candidate: dict[str, CommittedPlan]) -> None:
        validated: dict[str, CommittedPlan] = {}
        for session_id, plan in candidate.items():
            validated_plan = CommittedPlan.model_validate(plan.model_dump(mode="python"))
            if validated_plan.session_id != session_id:
                raise ValueError("trace plan session does not match candidate key")
            validated[session_id] = validated_plan
        previous = self._plans
        self._plans = validated
        try:
            self._persist()
        except Exception:
            self._plans = previous
            raise
        if self._storage_path is not None:
            self._state_load_result = StateLoadResult(
                StateLoadStatus.OK,
                schema_version=_TRACE_STATE_VERSION,
            )

    def _persist(self) -> None:
        if self._storage_path is None:
            return
        payload: dict[str, Any] = {}
        for session_id, plan in sorted(self._plans.items(), key=lambda item: item[0]):
            validated = CommittedPlan.model_validate(plan.model_dump(mode="python"))
            if validated.session_id != session_id:
                raise ValueError("trace plan session does not match retained key")
            payload[session_id] = validated.model_dump(mode="json")
        try:
            atomic_write_bytes(
                self._storage_path,
                encode_versioned_json_snapshot(payload, version=_TRACE_STATE_VERSION),
                fault_injector=self._state_fault_injector,
            )
        except AtomicWriteError as exc:
            if exc.publication_may_have_committed:
                self._persistence_degradation = exc
            raise

    def _load(self) -> None:
        if self._storage_path is None:
            return
        try:
            raw_bytes = read_owner_only_regular_file(self._storage_path)
        except OSError:
            self._state_load_result = StateLoadResult(
                StateLoadStatus.CORRUPT,
                reason="trace_read_failed",
            )
            return
        if raw_bytes is None:
            return
        document_result, raw_payload = decode_json_document(raw_bytes)
        if document_result.status is not StateLoadStatus.OK:
            self._state_load_result = document_result
            return
        if not isinstance(raw_payload, dict):
            self._state_load_result = StateLoadResult(
                StateLoadStatus.CORRUPT,
                reason="invalid_trace_payload",
            )
            return

        envelope_keys = {"version", "checksum", "payload"}
        legacy = not bool(envelope_keys.intersection(raw_payload))
        if legacy:
            payload: Any = raw_payload
            load_result = StateLoadResult(StateLoadStatus.OK, legacy=True)
        else:
            load_result, payload = decode_versioned_json_snapshot(
                raw_bytes,
                supported_version=_TRACE_STATE_VERSION,
            )
            if load_result.status != StateLoadStatus.OK:
                self._state_load_result = load_result
                return
        if not isinstance(payload, dict):
            self._state_load_result = StateLoadResult(
                StateLoadStatus.CORRUPT,
                reason="invalid_trace_payload",
                schema_version=load_result.schema_version,
                legacy=legacy,
            )
            return

        candidate: dict[str, CommittedPlan] = {}
        cancel_unreconciled_stage2 = False
        for key, value in payload.items():
            if not isinstance(key, str):
                self._state_load_result = StateLoadResult(
                    StateLoadStatus.CORRUPT,
                    reason="invalid_trace_session_key",
                    schema_version=load_result.schema_version,
                    legacy=legacy,
                )
                return
            try:
                plan = CommittedPlan.model_validate(value)
            except ValidationError:
                self._state_load_result = StateLoadResult(
                    StateLoadStatus.CORRUPT,
                    reason=f"invalid_trace_plan:{key}",
                    schema_version=load_result.schema_version,
                    legacy=legacy,
                )
                return
            if plan.session_id != key:
                self._state_load_result = StateLoadResult(
                    StateLoadStatus.CORRUPT,
                    reason=f"trace_session_mismatch:{key}",
                    schema_version=load_result.schema_version,
                    legacy=legacy,
                )
                return
            expected_plan_hash = self._plan_commitment_hash(
                session_id=plan.session_id,
                allowed_actions=plan.allowed_actions,
                allowed_resources=plan.allowed_resources,
                goal_resource_patterns=plan.goal_resource_patterns,
                declared_resource_roots=plan.declared_resource_roots,
                forbidden_actions=plan.forbidden_actions,
                max_actions=plan.max_actions,
                committed_at=plan.committed_at,
                expires_at=plan.expires_at,
                stage=plan.stage,
                amendment_of=plan.amendment_of,
                amendment_correlation_id=plan.amendment_correlation_id,
                amendment_execution_idempotency_key=(plan.amendment_execution_idempotency_key),
            )
            if plan.plan_hash != expected_plan_hash:
                self._state_load_result = StateLoadResult(
                    StateLoadStatus.CORRUPT,
                    reason=f"trace_plan_hash_mismatch:{key}",
                    schema_version=load_result.schema_version,
                    legacy=legacy,
                )
                return
            correlated_action_key = control_plane_trace_action_idempotency_key(
                plan.amendment_execution_idempotency_key
            )
            correlated_execution_recorded = (
                plan.executed_actions > 0
                and bool(correlated_action_key)
                and correlated_action_key in plan.recorded_action_keys
            )
            if (
                plan.amendment_correlation_id
                and not correlated_execution_recorded
                and not plan.cancelled
            ):
                plan.cancelled = True
                plan.cancelled_reason = "unreconciled_stage2_restart"
                cancel_unreconciled_stage2 = True
            candidate[key] = plan
        self._plans = candidate
        self._state_load_result = StateLoadResult(
            StateLoadStatus.OK,
            schema_version=load_result.schema_version,
            legacy=legacy,
        )
        if cancel_unreconciled_stage2:
            try:
                self._persist()
            except AtomicWriteError as exc:
                # An unreconciled stage-2 plan must never become live merely
                # because its conservative cancellation could not be published.
                self._persistence_degradation = exc
        elif legacy:
            # A fully validated legacy snapshot remains authoritative when a
            # safe migration did not publish.
            with contextlib.suppress(AtomicWriteError):
                self._persist()
