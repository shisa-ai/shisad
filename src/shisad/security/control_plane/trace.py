"""Execution trace verifier and plan commitment lifecycle."""

from __future__ import annotations

import fnmatch
import hashlib
import json
import re
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from pydantic import BaseModel, Field, ValidationError

from shisad.core.types import Capability
from shisad.security.control_plane.schema import (
    ActionKind,
    ControlPlaneAction,
    Origin,
    RiskTier,
    action_kinds_for_capabilities,
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


def trace_reason_requires_confirmation(reason_code: str) -> bool:
    return reason_code.strip() in TRACE_CONFIRMATION_REASON_CODES


class CommittedPlan(BaseModel):
    session_id: str
    plan_hash: str
    allowed_actions: set[ActionKind] = Field(default_factory=set)
    allowed_resources: set[str] = Field(default_factory=set)
    goal_resource_patterns: set[str] = Field(default_factory=set)
    declared_resource_roots: set[str] = Field(default_factory=set)
    reachable_resources: set[str] = Field(default_factory=set)
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
        workspace_roots: list[Path] | None = None,
    ) -> None:
        self._storage_path = storage_path
        self._default_ttl_seconds = default_ttl_seconds
        self._default_max_actions = default_max_actions
        self._workspace_roots = [
            item.expanduser().resolve(strict=False) for item in (workspace_roots or [Path.cwd()])
        ]
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
        capabilities: set[Capability] | None = None,
        declared_resource_roots: set[str] | None = None,
    ) -> CommittedPlan:
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
                ActionKind.BROWSER_WRITE,
                ActionKind.FS_WRITE,
                ActionKind.MEMORY_WRITE,
                ActionKind.MESSAGE_SEND,
                ActionKind.SHELL_EXEC,
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

    def record_action(self, *, session_id: str) -> None:
        plan = self._plans.get(session_id)
        if plan is None:
            return
        plan.executed_actions += 1
        self._persist()

    def record_dependency_path(
        self,
        *,
        session_id: str,
        action: ControlPlaneAction,
    ) -> None:
        plan = self._plans.get(session_id)
        if plan is None:
            return
        if not self._tdg_enforcement_applies(action):
            return
        plan.reachable_resources.update(item for item in action.resource_ids if item)
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
            goal_resource_patterns=set(current.goal_resource_patterns),
            declared_resource_roots=set(current.declared_resource_roots),
            forbidden_actions=set(current.forbidden_actions) - set(allow_actions),
            max_actions=current.max_actions,
            committed_at=now,
            expires_at=now + timedelta(seconds=ttl),
            stage=PlanStage.STAGE2_POSTEVIDENCE,
            amendment_of=current.plan_hash,
        )
        amended.reachable_resources = set(current.reachable_resources)
        self._plans[session_id] = amended
        self._persist()
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
    ) -> CommittedPlan:
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
        encoded = json.dumps(payload, sort_keys=True)
        plan_hash = hashlib.sha256(encoded.encode("utf-8")).hexdigest()
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
            executed_actions=0,
        )

    @staticmethod
    def _strict_stage1_actions() -> set[ActionKind]:
        return {
            ActionKind.FS_READ,
            ActionKind.FS_LIST,
            ActionKind.MEMORY_READ,
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
            parsed = urlparse(value)
            if parsed.hostname:
                return parsed.hostname.lower().rstrip(".")
            return ""
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
        except (OSError, json.JSONDecodeError):
            return
        if not isinstance(payload, dict):
            return
        for key, value in payload.items():
            if not isinstance(key, str):
                continue
            try:
                self._plans[key] = CommittedPlan.model_validate(value)
            except ValidationError:
                continue
