"""Control API handler bundle for daemon runtime."""

from __future__ import annotations

import base64
import binascii
import hashlib
import inspect
import json
import logging
import os
import re
import uuid
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from functools import lru_cache
from pathlib import Path
from typing import TYPE_CHECKING, Any

from pydantic import ValidationError

from shisad.assistant.fs_git import FsGitToolkit
from shisad.assistant.web import WebToolkit
from shisad.channels.base import DeliveryTarget
from shisad.core.events import (
    AnomalyReported,
    BaseEvent,
    ConsensusEvaluated,
    ControlPlaneActionObserved,
    ControlPlaneNetworkObserved,
    ControlPlaneResourceObserved,
    EventBus,
    LockdownChanged,
    PlanViolationDetected,
    ProxyRequestEvaluated,
    SandboxDegraded,
    SandboxEscapeDetected,
    SandboxExecutionCompleted,
    SandboxExecutionIntent,
    SandboxPreCheckpoint,
    ToolApproved,
    ToolExecuted,
    ToolRejected,
)
from shisad.core.session import Session
from shisad.core.session_archive import SessionArchiveManager
from shisad.core.tools.builtin.alarm import AnomalyReportInput
from shisad.core.tools.schema import ToolDefinition
from shisad.core.types import (
    Capability,
    SessionId,
    SessionMode,
    TaintLabel,
    ToolName,
    UserId,
    WorkspaceId,
)
from shisad.daemon.handlers._helpers import publish_event
from shisad.daemon.handlers._impl_admin import AdminImplMixin
from shisad.daemon.handlers._impl_assistant import AssistantImplMixin
from shisad.daemon.handlers._impl_confirmation import ConfirmationImplMixin
from shisad.daemon.handlers._impl_dashboard import DashboardImplMixin
from shisad.daemon.handlers._impl_memory import MemoryImplMixin
from shisad.daemon.handlers._impl_session import SessionImplMixin
from shisad.daemon.handlers._impl_skills import SkillsImplMixin
from shisad.daemon.handlers._impl_tasks import TasksImplMixin
from shisad.daemon.handlers._impl_tool_execution import ToolExecutionImplMixin
from shisad.daemon.handlers._side_effects import is_side_effect_tool
from shisad.daemon.handlers._string_utils import optional_string
from shisad.daemon.handlers._tool_exec_helpers import execute_structured_tool
from shisad.executors.mounts import FilesystemPolicy
from shisad.executors.proxy import NetworkPolicy
from shisad.executors.sandbox import (
    DegradedModePolicy,
    EnvironmentPolicy,
    ResourceLimits,
    SandboxConfig,
    SandboxOrchestrator,
    SandboxResult,
    SandboxType,
)
from shisad.governance.merge import (
    PolicyMerge,
    PolicyMergeError,
    ToolExecutionPolicy,
    normalize_patch,
)
from shisad.memory.summarizer import ConversationSummarizer
from shisad.security.control_plane.engine import ControlPlaneEvaluation
from shisad.security.control_plane.schema import (
    ActionKind,
    ControlDecision,
    ControlPlaneAction,
    Origin,
    RiskTier,
    build_action,
    extract_request_size_bytes,
)
from shisad.security.leakcheck import CrossThreadLeakDetector
from shisad.security.reputation import ReputationScorer
from shisad.security.taint import label_tool_output, normalize_retrieval_taints
from shisad.skills.manifest import parse_manifest
from shisad.ui.confirmation import (
    ConfirmationAnalytics,
    ConfirmationWarningGenerator,
    render_structured_confirmation,
    safe_summary,
)
from shisad.ui.dashboard import SecurityDashboard

if TYPE_CHECKING:
    from shisad.daemon.services import DaemonServices

logger = logging.getLogger(__name__)

_MONITOR_REJECT_THRESHOLD = 3
_HIGH_RISK_CONFIRM_TOKENS: tuple[str, ...] = ("send", "share", "delete")
_CONFIRMATION_ALERT_COOLDOWN_SECONDS = 600


class _EventPublisher:
    def __init__(self, event_bus: EventBus) -> None:
        self._event_bus = event_bus

    async def publish(self, event: BaseEvent) -> None:
        await publish_event(self._event_bus, event)


def _should_checkpoint(trigger: str, tool: ToolDefinition | None) -> bool:
    if trigger == "never":
        return False
    if trigger == "before_any_tool":
        return tool is not None
    if trigger == "before_side_effects":
        return tool is not None and is_side_effect_tool(tool)
    return False


def _optional_int(value: Any) -> int | None:
    if value in {None, ""}:
        return None
    return int(value)


def _argument_string(
    arguments: Mapping[str, Any],
    key: str,
    *,
    default: str = "",
) -> str:
    return optional_string(arguments.get(key, default), default=default)


def _argument_int(
    arguments: Mapping[str, Any],
    key: str,
    *,
    default: int,
    minimum: int | None = None,
) -> int:
    value = arguments.get(key, default)
    resolved = int(default) if value in {None, ""} else int(value)
    if minimum is not None:
        resolved = max(int(minimum), resolved)
    return resolved


def _structured_web_search(
    handler: Any,
    arguments: Mapping[str, Any],
    _context: StructuredToolContext | None = None,
) -> Mapping[str, Any]:
    return dict(
        handler._web_toolkit.search(
            query=_argument_string(arguments, "query"),
            limit=_argument_int(arguments, "limit", default=5, minimum=1),
        )
    )


def _structured_web_fetch(
    handler: Any,
    arguments: Mapping[str, Any],
    _context: StructuredToolContext | None = None,
) -> Mapping[str, Any]:
    return dict(
        handler._web_toolkit.fetch(
            url=_argument_string(arguments, "url"),
            snapshot=bool(arguments.get("snapshot", False)),
            max_bytes=_optional_int(arguments.get("max_bytes")),
        )
    )


def _structured_realitycheck_search(
    handler: Any,
    arguments: Mapping[str, Any],
    _context: StructuredToolContext | None = None,
) -> Mapping[str, Any]:
    return dict(
        handler._realitycheck_toolkit.search(
            query=_argument_string(arguments, "query"),
            limit=_argument_int(arguments, "limit", default=5, minimum=1),
            mode=_argument_string(arguments, "mode", default="auto") or "auto",
        )
    )


def _structured_realitycheck_read(
    handler: Any,
    arguments: Mapping[str, Any],
    _context: StructuredToolContext | None = None,
) -> Mapping[str, Any]:
    return dict(
        handler._realitycheck_toolkit.read_source(
            path=_argument_string(arguments, "path"),
            max_bytes=_optional_int(arguments.get("max_bytes")),
        )
    )


def _structured_fs_list(
    handler: Any,
    arguments: Mapping[str, Any],
    _context: StructuredToolContext | None = None,
) -> Mapping[str, Any]:
    return dict(
        handler._fs_git_toolkit.list_dir(
            path=_argument_string(arguments, "path", default=".") or ".",
            recursive=bool(arguments.get("recursive", False)),
            limit=_argument_int(arguments, "limit", default=200, minimum=1),
        )
    )


def _structured_fs_read(
    handler: Any,
    arguments: Mapping[str, Any],
    _context: StructuredToolContext | None = None,
) -> Mapping[str, Any]:
    return dict(
        handler._fs_git_toolkit.read_file(
            path=_argument_string(arguments, "path"),
            max_bytes=_optional_int(arguments.get("max_bytes")),
        )
    )


def _structured_fs_write(
    handler: Any,
    arguments: Mapping[str, Any],
    _context: StructuredToolContext | None = None,
) -> Mapping[str, Any]:
    return dict(
        handler._fs_git_toolkit.write_file(
            path=_argument_string(arguments, "path"),
            content=_argument_string(arguments, "content"),
            confirm=bool(arguments.get("confirm", False)),
        )
    )


def _structured_git_status(
    handler: Any,
    arguments: Mapping[str, Any],
    _context: StructuredToolContext | None = None,
) -> Mapping[str, Any]:
    return dict(
        handler._fs_git_toolkit.git_status(
            repo_path=_argument_string(arguments, "repo_path", default=".") or ".",
        )
    )


def _structured_git_diff(
    handler: Any,
    arguments: Mapping[str, Any],
    _context: StructuredToolContext | None = None,
) -> Mapping[str, Any]:
    return dict(
        handler._fs_git_toolkit.git_diff(
            repo_path=_argument_string(arguments, "repo_path", default=".") or ".",
            ref=_argument_string(arguments, "ref"),
            max_lines=_argument_int(arguments, "max_lines", default=400, minimum=1),
        )
    )


def _structured_git_log(
    handler: Any,
    arguments: Mapping[str, Any],
    _context: StructuredToolContext | None = None,
) -> Mapping[str, Any]:
    return dict(
        handler._fs_git_toolkit.git_log(
            repo_path=_argument_string(arguments, "repo_path", default=".") or ".",
            limit=_argument_int(arguments, "limit", default=20, minimum=1),
        )
    )


_REMINDER_IN_RE = re.compile(
    r"^in (?P<value>\d+) (?P<unit>seconds?|minutes?|hours?)$",
    flags=re.IGNORECASE,
)
_REMINDER_AT_RE = re.compile(
    r"^at (?P<hour>\d{1,2})(?::(?P<minute>\d{2}))?\s*(?P<ampm>am|pm)?$",
    flags=re.IGNORECASE,
)


@dataclass(frozen=True, slots=True)
class StructuredToolContext:
    session_id: SessionId
    user_id: UserId
    workspace_id: WorkspaceId
    session: Session
    user_confirmed: bool = False


StructuredPayloadBuilder = Callable[
    [Any, Mapping[str, Any], StructuredToolContext],
    Mapping[str, Any] | Awaitable[Mapping[str, Any]],
]


def _slugify_memory_key(prefix: str, text: str, *, max_words: int = 6) -> str:
    words = [token for token in re.findall(r"[a-z0-9]+", text.lower()) if token]
    suffix = "-".join(words[:max_words]) if words else "item"
    return f"{prefix}:{suffix}"


def _wrap_structured_payload(payload: Mapping[str, Any], *, ok: bool = True) -> dict[str, Any]:
    structured = dict(payload)
    structured["ok"] = ok
    return structured


def _resolve_session_delivery_target(
    session: Session,
    *,
    session_id: SessionId,
) -> dict[str, str]:
    raw_target = session.metadata.get("delivery_target")
    if isinstance(raw_target, dict):
        channel = optional_string(raw_target.get("channel", ""))
        recipient = optional_string(raw_target.get("recipient", ""))
        if channel and recipient:
            normalized: dict[str, str] = {}
            for key, value in raw_target.items():
                key_name = optional_string(key)
                value_text = optional_string(value)
                if key_name and value_text:
                    normalized[key_name] = value_text
            return normalized
    return {"channel": "session", "recipient": str(session_id)}


def _parse_reminder_delay_seconds(when: str, *, now: datetime) -> int:
    normalized = when.strip()
    if not normalized:
        raise ValueError("reminder_when_required")
    relative = _REMINDER_IN_RE.match(normalized)
    if relative is not None:
        value = max(1, int(relative.group("value")))
        unit = relative.group("unit").lower()
        multiplier = 1
        if unit.startswith("minute"):
            multiplier = 60
        elif unit.startswith("hour"):
            multiplier = 3600
        return max(1, value * multiplier)

    at_match = _REMINDER_AT_RE.match(normalized)
    if at_match is not None:
        hour = int(at_match.group("hour"))
        minute = int(at_match.group("minute") or 0)
        ampm = str(at_match.group("ampm") or "").lower()
        if ampm:
            if hour < 1 or hour > 12:
                raise ValueError("reminder_time_invalid")
            hour %= 12
            if ampm == "pm":
                hour += 12
        elif hour > 23:
            raise ValueError("reminder_time_invalid")
        if minute > 59:
            raise ValueError("reminder_time_invalid")
        target = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
        if target <= now:
            target += timedelta(days=1)
        return max(1, int((target - now).total_seconds()))

    iso_source = normalized[3:].strip() if normalized.lower().startswith("at ") else normalized
    iso_candidate = iso_source[:-1] + "+00:00" if iso_source.endswith("Z") else iso_source
    try:
        parsed = datetime.fromisoformat(iso_candidate)
    except ValueError as exc:  # pragma: no cover - exercised through reminder behavior tests
        raise ValueError("reminder_time_unsupported") from exc
    parsed = (
        parsed.replace(tzinfo=UTC)
        if parsed.tzinfo is None
        else parsed.astimezone(UTC)
    )
    return max(1, int((parsed - now).total_seconds()))


async def _structured_note_create(
    handler: Any,
    arguments: Mapping[str, Any],
    context: StructuredToolContext,
) -> Mapping[str, Any]:
    content = _argument_string(arguments, "content")
    if not content:
        return {"ok": False, "error": "note_content_required"}
    payload = await handler.do_note_create(
        {
            "key": _argument_string(arguments, "key")
            or _slugify_memory_key("note", content),
            "content": content,
            "origin": "user",
            "source_id": str(context.session_id),
            "user_confirmed": context.user_confirmed,
        }
    )
    return _wrap_structured_payload(payload, ok=str(payload.get("kind", "")) == "allow")


async def _structured_note_list(
    handler: Any,
    arguments: Mapping[str, Any],
    _context: StructuredToolContext,
) -> Mapping[str, Any]:
    payload = await handler.do_note_list(
        {"limit": _argument_int(arguments, "limit", default=20, minimum=1)}
    )
    return _wrap_structured_payload(payload)


async def _structured_note_search(
    handler: Any,
    arguments: Mapping[str, Any],
    _context: StructuredToolContext,
) -> Mapping[str, Any]:
    query = _argument_string(arguments, "query")
    if not query:
        return {
            "ok": False,
            "error": "note_search_query_required",
            "query": "",
            "entries": [],
            "count": 0,
        }
    payload = await handler.do_note_search(
        {
            "query": query,
            "limit": _argument_int(arguments, "limit", default=20, minimum=1),
        }
    )
    return _wrap_structured_payload(payload)


async def _structured_todo_create(
    handler: Any,
    arguments: Mapping[str, Any],
    context: StructuredToolContext,
) -> Mapping[str, Any]:
    title = _argument_string(arguments, "title")
    if not title:
        return {"ok": False, "error": "todo_title_required"}
    payload = await handler.do_todo_create(
        {
            "title": title,
            "details": _argument_string(arguments, "details"),
            "due_date": _argument_string(arguments, "due_date"),
            "origin": "user",
            "source_id": str(context.session_id),
            "user_confirmed": context.user_confirmed,
        }
    )
    return _wrap_structured_payload(payload, ok=str(payload.get("kind", "")) == "allow")


async def _structured_todo_list(
    handler: Any,
    arguments: Mapping[str, Any],
    _context: StructuredToolContext,
) -> Mapping[str, Any]:
    payload = await handler.do_todo_list(
        {"limit": _argument_int(arguments, "limit", default=20, minimum=1)}
    )
    return _wrap_structured_payload(payload)


async def _structured_todo_complete(
    handler: Any,
    arguments: Mapping[str, Any],
    _context: StructuredToolContext,
) -> Mapping[str, Any]:
    selector = _argument_string(arguments, "selector")
    if not selector:
        return {
            "ok": False,
            "completed": False,
            "entry_id": "",
            "entry": None,
            "reason": "todo_selector_required",
            "matches": [],
        }
    payload = await handler.do_todo_complete({"selector": selector})
    return _wrap_structured_payload(payload, ok=bool(payload.get("completed", False)))


async def _structured_reminder_create(
    handler: Any,
    arguments: Mapping[str, Any],
    context: StructuredToolContext,
) -> Mapping[str, Any]:
    message = _argument_string(arguments, "message")
    when = _argument_string(arguments, "when")
    if not message:
        return {"ok": False, "error": "reminder_message_required"}
    try:
        delay_seconds = _parse_reminder_delay_seconds(when, now=datetime.now(UTC))
    except ValueError as exc:
        return {"ok": False, "error": str(exc)}
    delivery_target = _resolve_session_delivery_target(
        context.session,
        session_id=context.session_id,
    )
    recipient = str(delivery_target.get("recipient", "")).strip()
    task_payload = await handler.do_task_create(
        {
            "schedule": {"kind": "interval", "expression": f"{delay_seconds}s"},
            "name": _argument_string(arguments, "name")
            or _slugify_memory_key("reminder", message),
            "goal": f"Reminder: {message}",
            "capability_snapshot": [Capability.MESSAGE_SEND.value],
            "policy_snapshot_ref": "planner:reminder.create",
            "created_by": str(context.user_id),
            "workspace_id": str(context.workspace_id),
            "allowed_recipients": [recipient] if recipient else [],
            "allowed_domains": [],
            "delivery_target": delivery_target,
            "max_runs": 1,
        }
    )
    return {"ok": True, "task": task_payload}


async def _structured_reminder_list(
    handler: Any,
    arguments: Mapping[str, Any],
    context: StructuredToolContext,
) -> Mapping[str, Any]:
    limit = _argument_int(arguments, "limit", default=20, minimum=1)
    rows: list[dict[str, Any]] = []
    for task in handler._scheduler.list_tasks():
        if str(getattr(task, "created_by", "")).strip() != str(context.user_id).strip():
            continue
        if str(getattr(task, "workspace_id", "")).strip() != str(context.workspace_id).strip():
            continue
        if not str(getattr(task, "goal", "")).startswith("Reminder: "):
            continue
        rows.append(task.model_dump(mode="json"))
        if len(rows) >= limit:
            break
    return {"ok": True, "tasks": rows, "count": len(rows)}


async def _structured_evidence_read(
    handler: Any,
    arguments: Mapping[str, Any],
    context: StructuredToolContext,
) -> Mapping[str, Any]:
    ref_id = _argument_string(arguments, "ref_id")
    if not ref_id:
        return {"ok": False, "error": "invalid or unknown evidence reference"}
    store = getattr(handler, "_evidence_store", None)
    if store is None:
        return {"ok": False, "error": "invalid or unknown evidence reference"}
    ref = store.get_ref(context.session_id, ref_id)
    content = store.read(context.session_id, ref_id)
    if ref is None or content is None:
        return {"ok": False, "error": "invalid or unknown evidence reference", "ref_id": ref_id}
    return {
        "ok": True,
        "ref_id": ref_id,
        "source": ref.source,
        "summary": ref.summary,
        "content": content,
        "taint_labels": [label.value for label in ref.taint_labels],
    }


async def _structured_evidence_promote(
    handler: Any,
    arguments: Mapping[str, Any],
    context: StructuredToolContext,
) -> Mapping[str, Any]:
    ref_id = _argument_string(arguments, "ref_id")
    if not ref_id:
        return {"ok": False, "error": "invalid or unknown evidence reference"}
    store = getattr(handler, "_evidence_store", None)
    if store is None:
        return {"ok": False, "error": "invalid or unknown evidence reference"}
    ref = store.get_ref(context.session_id, ref_id)
    content = store.read(context.session_id, ref_id)
    if ref is None or content is None:
        return {"ok": False, "error": "invalid or unknown evidence reference", "ref_id": ref_id}
    taint_labels = sorted(
        {
            *[label.value for label in ref.taint_labels if label != TaintLabel.UNTRUSTED],
            TaintLabel.USER_REVIEWED.value,
        }
    )
    return {
        "ok": True,
        "ref_id": ref_id,
        "source": ref.source,
        "summary": ref.summary,
        "content": content,
        "taint_labels": taint_labels,
    }

@dataclass(slots=True)
class PendingAction:
    confirmation_id: str
    decision_nonce: str
    session_id: SessionId
    user_id: UserId
    workspace_id: WorkspaceId
    tool_name: ToolName
    arguments: dict[str, Any]
    reason: str
    capabilities: set[Capability]
    created_at: datetime
    task_id: str = ""
    preflight_action: ControlPlaneAction | None = None
    execute_after: datetime | None = None
    safe_preview: str = ""
    warnings: list[str] = field(default_factory=list)
    leak_check: dict[str, Any] = field(default_factory=dict)
    merged_policy: ToolExecutionPolicy | None = None
    status: str = "pending"
    status_reason: str = ""


@dataclass(slots=True)
class ToolOutputRecord:
    tool_name: str
    content: str
    success: bool = True
    taint_labels: set[TaintLabel] = field(default_factory=set)


@dataclass(slots=True)
class ApprovedToolExecutionResult:
    success: bool
    checkpoint_id: str | None = None
    tool_output: ToolOutputRecord | None = None
    sandbox_result: SandboxResult | None = None


class HandlerImplementation(
    SessionImplMixin,
    ToolExecutionImplMixin,
    ConfirmationImplMixin,
    MemoryImplMixin,
    SkillsImplMixin,
    TasksImplMixin,
    DashboardImplMixin,
    AssistantImplMixin,
    AdminImplMixin,
):
    """Owns JSON-RPC control handlers for the daemon."""

    def __init__(self, *, services: DaemonServices) -> None:
        self._config = services.config
        self._audit_log = services.audit_log
        self._event_bus = _EventPublisher(services.event_bus)
        self._policy_loader = services.policy_loader
        self._planner = services.planner
        self._registry = services.registry
        self._alarm_tool = services.alarm_tool
        self._session_manager = services.session_manager
        self._transcript_store = services.transcript_store
        self._evidence_store = services.evidence_store
        self._trace_recorder = services.trace_recorder
        self._transcript_root = services.transcript_root
        self._checkpoint_store = services.checkpoint_store
        self._session_archive = SessionArchiveManager(
            session_manager=services.session_manager,
            transcript_store=services.transcript_store,
            checkpoint_store=services.checkpoint_store,
            lockdown_manager=services.lockdown_manager,
            archive_dir=self._config.data_dir / "session_archives",
        )
        self._firewall = services.firewall
        self._output_firewall = services.output_firewall
        self._channel_ingress = services.channel_ingress
        self._identity_map = services.identity_map
        self._delivery = services.delivery
        self._channels = services.channels
        self._matrix_channel = services.matrix_channel
        self._discord_channel = services.discord_channel
        self._telegram_channel = services.telegram_channel
        self._slack_channel = services.slack_channel
        self._lockdown_manager = services.lockdown_manager
        self._rate_limiter = services.rate_limiter
        self._monitor = services.monitor
        self._risk_calibrator = services.risk_calibrator
        self._ingestion = services.ingestion
        self._memory_manager = services.memory_manager
        self._conversation_summarizer = ConversationSummarizer(provider=services.provider)
        self._scheduler = services.scheduler
        self._skill_manager = services.skill_manager
        self._coding_manager = services.coding_manager
        self._selfmod_manager = services.selfmod_manager
        self._realitycheck_toolkit = services.realitycheck_toolkit
        self._sandbox = services.sandbox
        self._control_plane = services.control_plane
        self._pep = services.pep
        self._browser_sandbox = services.browser_sandbox
        self._shutdown_event = services.shutdown_event
        self._provenance_status = services.provenance_status
        self._model_routes = services.model_routes
        self._provider_diagnostics = services.provider_diagnostics
        self._planner_model_id = services.planner_model_id
        self._classifier_mode = services.firewall.classifier_mode
        self._internal_ingress_marker = services.internal_ingress_marker
        self._pairing_requests_file = self._config.data_dir / "channels" / "pairing_requests.jsonl"
        self._pending_actions_file = self._config.data_dir / "pending_actions.json"
        self._pending_actions: dict[str, PendingAction] = {}
        self._pending_by_session: dict[SessionId, list[str]] = {}
        self._monitor_reject_counts: dict[SessionId, int] = {}
        self._plan_violation_counts: dict[SessionId, int] = {}
        self._confirmation_warning_generator = ConfirmationWarningGenerator()
        self._confirmation_analytics = ConfirmationAnalytics()
        self._confirmation_alerted_at: dict[str, datetime] = {}
        self._leak_detector = CrossThreadLeakDetector()
        self._reputation_scorer = ReputationScorer(submission_limit=20)
        self._dashboard = SecurityDashboard(
            audit_log=self._audit_log,
            marks_path=self._config.data_dir / "dashboard" / "false_positives.json",
        )
        web_allowed_domains = [item for item in self._config.web_allowed_domains if item.strip()]
        if not web_allowed_domains:
            web_allowed_domains = [
                rule.host.strip()
                for rule in self._policy_loader.policy.egress
                if rule.host.strip()
            ]
        self._web_toolkit = WebToolkit(
            data_dir=self._config.data_dir,
            search_enabled=self._config.web_search_enabled,
            search_backend_url=self._config.web_search_backend_url,
            fetch_enabled=self._config.web_fetch_enabled,
            allowed_domains=web_allowed_domains,
            timeout_seconds=self._config.web_timeout_seconds,
            max_fetch_bytes=self._config.web_max_fetch_bytes,
        )
        self._fs_git_toolkit = FsGitToolkit(
            roots=list(self._config.assistant_fs_roots),
            max_read_bytes=self._config.assistant_max_read_bytes,
            git_timeout_seconds=self._config.assistant_git_timeout_seconds,
        )
        self._load_pending_actions()

    @staticmethod
    def _load_skill_manifest(skill_path: Path) -> Any | None:
        manifest_path = skill_path / "skill.manifest.yaml"
        if not manifest_path.exists():
            return None
        try:
            return parse_manifest(manifest_path)
        except (OSError, TypeError, ValueError):
            return None

    def _skill_reputation(
        self,
        *,
        manifest: Any | None,
        signature_status: str,
        findings: list[dict[str, Any]],
    ) -> dict[str, Any]:
        positives: list[str] = []
        negatives: list[str] = []
        if manifest is not None:
            source_repo = str(getattr(manifest, "source_repo", "")).lower().strip()
            author = str(getattr(manifest, "author", "")).strip()
            description = str(getattr(manifest, "description", "")).lower()
            capabilities = getattr(manifest, "capabilities", None)
            if source_repo.startswith("https://github.com/") or source_repo.startswith(
                "git@github.com:"
            ):
                positives.append("verified_repo")
            if author:
                positives.append("verified_author")
            if "audit" in description:
                positives.append("audited")
            if capabilities is not None:
                if list(getattr(capabilities, "shell", []) or []):
                    negatives.append("shell_access")
                if list(getattr(capabilities, "network", []) or []):
                    negatives.append("network_egress")
        if signature_status.lower() in {"trusted", "untrusted"}:
            positives.append("signed")
        for finding in findings:
            code = str(finding.get("code", "")).lower()
            description = str(finding.get("description", "")).lower()
            if "obfus" in code or "obfus" in description:
                negatives.append("obfuscated")
                break
        result = self._reputation_scorer.score(
            positive=sorted(set(positives)),
            negative=sorted(set(negatives)),
        )
        return {
            "score": result.score,
            "tier": result.tier,
            "breakdown": result.breakdown,
            "positive_signals": sorted(set(positives)),
            "negative_signals": sorted(set(negatives)),
        }

    async def _maybe_emit_confirmation_hygiene_alert(
        self,
        *,
        user_id: str,
        session_id: SessionId,
    ) -> None:
        metrics = self._confirmation_analytics.metrics(user_id=user_id)
        if not (metrics.get("rubber_stamping") or metrics.get("fatigue_detected")):
            return
        now = datetime.now(UTC)
        last = self._confirmation_alerted_at.get(user_id)
        if (
            last is not None
            and (now - last).total_seconds() < _CONFIRMATION_ALERT_COOLDOWN_SECONDS
        ):
            return
        reasons: list[str] = []
        if metrics.get("rubber_stamping"):
            reasons.append("rubber_stamping")
        if metrics.get("fatigue_detected"):
            reasons.append("fatigue_detected")
        await self._event_bus.publish(
            AnomalyReported(
                session_id=session_id,
                actor="confirmation_analytics",
                severity="warning",
                description=(
                    "confirmation hygiene degraded: " + ",".join(reasons)
                    if reasons
                    else "confirmation hygiene degraded"
                ),
                recommended_action="review confirmations and reduce approval fatigue",
            )
        )
        self._confirmation_alerted_at[user_id] = now

    def _compute_tool_policy_floor(
        self,
        *,
        tool_name: ToolName,
        tool_definition: ToolDefinition | None,
        operator_surface: bool = False,
    ) -> ToolExecutionPolicy:
        if tool_definition is None:
            raise ValueError(f"unknown tool: {tool_name}")
        sandbox_policy = self._policy_loader.policy.sandbox
        if tool_definition.sandbox_type:
            sandbox_type = SandboxType(str(tool_definition.sandbox_type))
        elif tool_definition.destinations:
            sandbox_type = SandboxType(sandbox_policy.network_backend)
        else:
            sandbox_type = SandboxType(sandbox_policy.default_backend)

        required_caps = set(tool_definition.capabilities_required)
        default_allow_network = bool(tool_definition.destinations) or (
            Capability.HTTP_REQUEST in required_caps
        )
        rollout_phase = (
            self._policy_loader.policy.control_plane.egress.wildcard_rollout_phase.strip().lower()
        )
        default_domains = (
            list(tool_definition.destinations)
            if tool_definition.destinations
            else (
                ["*"]
                if default_allow_network
                and (rollout_phase in {"warn", "deprecate"} or operator_surface)
                else []
            )
        )
        network = NetworkPolicy(
            allow_network=default_allow_network,
            allowed_domains=default_domains,
            deny_private_ranges=True,
            deny_ip_literals=True,
        )
        if Capability.FILE_WRITE in required_caps:
            filesystem = FilesystemPolicy(mounts=[{"path": "/**", "mode": "rw"}])
        elif Capability.FILE_READ in required_caps:
            filesystem = FilesystemPolicy(mounts=[{"path": "/**", "mode": "ro"}])
        else:
            filesystem = FilesystemPolicy()
        environment = EnvironmentPolicy(
            allowed_keys=list(sandbox_policy.env_allowlist),
            max_keys=sandbox_policy.env_max_keys,
            max_total_bytes=sandbox_policy.env_max_total_bytes,
        )
        limits = ResourceLimits()
        degraded_mode = DegradedModePolicy.FAIL_OPEN
        security_critical = False

        override = sandbox_policy.tool_overrides.get(tool_name)
        if override is not None:
            if override.sandbox_type:
                sandbox_type = SandboxType(str(override.sandbox_type))
            if override.network is not None:
                network = NetworkPolicy.model_validate(override.network.model_dump(mode="json"))
            if override.filesystem is not None:
                filesystem = FilesystemPolicy.model_validate(
                    override.filesystem.model_dump(mode="json")
                )
            if override.environment is not None:
                env_payload = override.environment.model_dump(mode="json")
                if not env_payload.get("allowed_keys"):
                    env_payload["allowed_keys"] = list(sandbox_policy.env_allowlist)
                if env_payload.get("max_keys") is None:
                    env_payload["max_keys"] = sandbox_policy.env_max_keys
                if env_payload.get("max_total_bytes") is None:
                    env_payload["max_total_bytes"] = sandbox_policy.env_max_total_bytes
                environment = EnvironmentPolicy.model_validate(env_payload)
            if override.limits is not None:
                limit_payload = {
                    **limits.model_dump(mode="json"),
                    **override.limits.model_dump(mode="json", exclude_none=True),
                }
                limits = ResourceLimits.model_validate(limit_payload)
            if override.degraded_mode:
                degraded_mode = DegradedModePolicy(str(override.degraded_mode))
            if override.security_critical is not None:
                security_critical = bool(override.security_critical)

        return ToolExecutionPolicy(
            sandbox_type=sandbox_type,
            network=network,
            filesystem=filesystem,
            environment=environment,
            limits=limits,
            degraded_mode=degraded_mode,
            security_critical=security_critical,
        )

    @staticmethod
    def _origin_for(
        *,
        session: Session,
        actor: str,
        skill_name: str = "",
        task_id: str = "",
    ) -> Origin:
        return Origin(
            session_id=str(session.id),
            user_id=str(session.user_id),
            workspace_id=str(session.workspace_id),
            task_id=task_id,
            skill_name=skill_name,
            actor=actor,
            channel=str(session.channel),
            trust_level=str(session.metadata.get("trust_level", "untrusted")),
        )

    @staticmethod
    def _risk_tier_for_tool_execute(
        *,
        network_enabled: bool,
        write_paths: list[str],
        security_critical: bool,
    ) -> RiskTier:
        if security_critical:
            return RiskTier.CRITICAL
        if network_enabled:
            return RiskTier.HIGH
        if write_paths:
            return RiskTier.MEDIUM
        return RiskTier.LOW

    def _build_merged_policy(
        self,
        *,
        tool_name: ToolName,
        arguments: Mapping[str, Any],
        tool_definition: ToolDefinition | None,
        operator_surface: bool = False,
    ) -> ToolExecutionPolicy:
        floor = self._compute_tool_policy_floor(
            tool_name=tool_name,
            tool_definition=tool_definition,
            operator_surface=operator_surface,
        )
        return PolicyMerge.merge(server=floor, caller=normalize_patch(dict(arguments)))

    @staticmethod
    def _build_sandbox_config(
        *,
        sid: SessionId | str,
        tool_name: ToolName | str,
        params: Mapping[str, Any],
        merged_policy: ToolExecutionPolicy,
        origin: Origin,
        approved_by_pep: bool,
    ) -> SandboxConfig:
        return SandboxConfig(
            session_id=str(sid),
            tool_name=str(tool_name),
            command=[str(token) for token in params.get("command", [])],
            read_paths=[str(item) for item in params.get("read_paths", [])],
            write_paths=[str(item) for item in params.get("write_paths", [])],
            network_urls=[str(item) for item in params.get("network_urls", [])],
            env={str(k): str(v) for k, v in dict(params.get("env", {})).items()},
            request_headers={
                str(k): str(v) for k, v in dict(params.get("request_headers", {})).items()
            },
            request_body=str(params.get("request_body", "")),
            cwd=str(params.get("cwd", "")),
            sandbox_type=merged_policy.sandbox_type,
            security_critical=merged_policy.security_critical,
            approved_by_pep=approved_by_pep,
            filesystem=merged_policy.filesystem,
            network=merged_policy.network,
            environment=merged_policy.environment,
            limits=merged_policy.limits,
            degraded_mode=merged_policy.degraded_mode,
            origin=origin.model_dump(mode="json"),
        )

    async def _publish_control_plane_evaluation(
        self,
        *,
        sid: SessionId,
        tool_name: ToolName,
        arguments: Mapping[str, Any],
        evaluation: ControlPlaneEvaluation,
    ) -> None:
        await self._event_bus.publish(
            ConsensusEvaluated(
                session_id=sid,
                actor="control_plane",
                tool_name=tool_name,
                decision=evaluation.decision.value,
                risk_tier=evaluation.consensus.risk_tier.value,
                reason_codes=list(evaluation.reason_codes),
                votes=[vote.model_dump(mode="json") for vote in evaluation.consensus.votes],
            )
        )
        await self._event_bus.publish(
            ControlPlaneActionObserved(
                session_id=sid,
                actor="control_plane",
                tool_name=tool_name,
                action_kind=evaluation.action.action_kind.value,
                resource_id=evaluation.action.resource_id,
                decision=evaluation.decision.value,
                reason_codes=list(evaluation.reason_codes),
                origin=evaluation.action.origin.model_dump(mode="json"),
            )
        )
        for resource in evaluation.action.resource_ids:
            await self._event_bus.publish(
                ControlPlaneResourceObserved(
                    session_id=sid,
                    actor="control_plane",
                    tool_name=tool_name,
                    action_kind=evaluation.action.action_kind.value,
                    resource_id=resource,
                    origin=evaluation.action.origin.model_dump(mode="json"),
                )
            )
        request_size = extract_request_size_bytes(dict(arguments))
        for host in evaluation.action.network_hosts:
            await self._event_bus.publish(
                ControlPlaneNetworkObserved(
                    session_id=sid,
                    actor="control_plane",
                    tool_name=tool_name,
                    destination_host=host,
                    destination_port=443,
                    protocol="https",
                    request_size=request_size,
                    allowed=evaluation.decision == ControlDecision.ALLOW,
                    reason="preflight",
                    origin=evaluation.action.origin.model_dump(mode="json"),
                )
            )

    @staticmethod
    def _structured_tool_reason(tool_output: ToolOutputRecord | None) -> str:
        if tool_output is None or not tool_output.content:
            return ""
        try:
            payload = json.loads(tool_output.content)
        except (TypeError, ValueError):
            return ""
        if isinstance(payload, dict):
            reason = str(payload.get("error", "")).strip()
            if reason:
                return reason
        return ""

    def _tool_execute_result_from_execution(
        self,
        *,
        execution: ApprovedToolExecutionResult,
        origin: Origin,
    ) -> dict[str, Any]:
        if execution.sandbox_result is not None:
            checkpoint_id = execution.checkpoint_id or execution.sandbox_result.checkpoint_id
            sandbox_result = execution.sandbox_result
            if checkpoint_id != sandbox_result.checkpoint_id:
                sandbox_result = sandbox_result.model_copy(
                    update={"checkpoint_id": checkpoint_id}
                )
            return sandbox_result.model_dump(mode="json")
        tool_output = execution.tool_output
        success = execution.success
        payload = SandboxResult(
            # For direct tool.execute, "allowed" reports the policy decision.
            # Structured tools can still fail operationally after approval.
            allowed=True,
            exit_code=0 if success else 1,
            stdout=tool_output.content if tool_output is not None else "",
            stderr="",
            reason="" if success else self._structured_tool_reason(tool_output),
            checkpoint_id=execution.checkpoint_id or "",
            origin=origin.model_dump(mode="json"),
        )
        return payload.model_dump(mode="json")

    @staticmethod
    def _action_hash(*, session_id: SessionId, tool_name: ToolName, command: list[str]) -> str:
        payload = {
            "session_id": str(session_id),
            "tool_name": str(tool_name),
            "command": list(command),
        }
        encoded = json.dumps(payload, sort_keys=True).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    @staticmethod
    def _is_admin_rpc_peer(params: Mapping[str, Any]) -> bool:
        peer = params.get("_rpc_peer", {})
        if not isinstance(peer, Mapping):
            return False
        uid = peer.get("uid")
        if not isinstance(uid, int):
            return False
        return uid in {0, os.getuid()}

    @staticmethod
    def _session_mode(session: Session) -> SessionMode:
        raw_mode = str(session.metadata.get("session_mode", "")).strip()
        if raw_mode:
            try:
                return SessionMode(raw_mode)
            except ValueError:
                return SessionMode.DEFAULT
        return session.mode

    def _session_has_tainted_history(self, session_id: SessionId) -> bool:
        return any(entry.taint_labels for entry in self._transcript_store.list_entries(session_id))

    def _session_has_tainted_user_history(self, session_id: SessionId) -> bool:
        return any(
            entry.taint_labels
            for entry in self._transcript_store.list_entries(session_id)
            if str(entry.role).strip().lower() == "user"
        )

    def _doctor_dependencies_status(self) -> dict[str, Any]:
        channel_rows: dict[str, dict[str, Any]] = {}
        problems: list[str] = []
        for name, enabled, channel in (
            ("matrix", self._config.matrix_enabled, self._matrix_channel),
            ("discord", self._config.discord_enabled, self._discord_channel),
            ("telegram", self._config.telegram_enabled, self._telegram_channel),
            ("slack", self._config.slack_enabled, self._slack_channel),
        ):
            available = bool(channel.available) if channel is not None else False
            row = {
                "enabled": bool(enabled),
                "available": available,
                "dependency_missing": bool(enabled and not available),
            }
            channel_rows[name] = row
            if row["dependency_missing"]:
                problems.append(f"{name}_dependency_missing")
        provider = type(getattr(self._planner, "_provider", object())).__name__
        return {
            "status": "misconfigured" if problems else "ok",
            "problems": sorted(set(problems)),
            "provider": provider,
            "classifier_mode": self._classifier_mode,
            "channels": channel_rows,
        }

    def _doctor_provider_status(self) -> dict[str, Any]:
        payload = self._provider_diagnostics
        if not isinstance(payload, dict):
            return {
                "status": "error",
                "problems": ["provider_diagnostics_unavailable"],
            }
        return dict(payload)

    def _doctor_policy_status(self) -> dict[str, Any]:
        problems: list[str] = []
        posture_notes: list[str] = []
        if not self._config.policy_path.exists():
            problems.append("policy_file_missing")
        try:
            integrity_ok = self._policy_loader.verify_integrity()
        except OSError:
            integrity_ok = False
            problems.append("policy_integrity_check_failed")
        if not integrity_ok:
            problems.append("policy_hash_mismatch")
        using_defaults = self._policy_loader.file_hash == ""
        if using_defaults and "policy_file_missing" in problems:
            problems = [item for item in problems if item != "policy_hash_mismatch"]
        if using_defaults:
            problems.append("policy_defaults_active")
        if not self._policy_loader.policy.default_deny:
            posture_notes.append("default_deny_disabled")
        status = "ok"
        if "policy_hash_mismatch" in problems or "policy_integrity_check_failed" in problems:
            status = "misconfigured"
        elif problems:
            status = "degraded"
        posture = "restrictive" if self._policy_loader.policy.default_deny else "permissive"
        return {
            "status": status,
            "problems": sorted(set(problems)),
            "path": str(self._config.policy_path),
            "hash_prefix": (
                self._policy_loader.file_hash[:12] if self._policy_loader.file_hash else ""
            ),
            "default_deny": bool(self._policy_loader.policy.default_deny),
            "posture": posture,
            "posture_notes": sorted(set(posture_notes)),
        }

    def _doctor_channels_status(self) -> dict[str, Any]:
        rows: dict[str, dict[str, Any]] = {}
        problems: list[str] = []
        active_statuses: list[str] = []
        for name, enabled, channel in (
            ("matrix", self._config.matrix_enabled, self._matrix_channel),
            ("discord", self._config.discord_enabled, self._discord_channel),
            ("telegram", self._config.telegram_enabled, self._telegram_channel),
            ("slack", self._config.slack_enabled, self._slack_channel),
        ):
            available = bool(channel.available) if channel is not None else False
            connected = bool(channel.connected) if channel is not None else False
            status = "disabled"
            if enabled and not available:
                status = "misconfigured"
                problems.append(f"{name}_dependency_unavailable")
            elif enabled and not connected:
                status = "degraded"
                problems.append(f"{name}_not_connected")
            elif enabled:
                status = "ok"
            rows[name] = {
                "status": status,
                "enabled": bool(enabled),
                "available": available,
                "connected": connected,
            }
            if enabled:
                active_statuses.append(status)
        overall = "disabled"
        if any(item == "misconfigured" for item in active_statuses):
            overall = "misconfigured"
        elif any(item == "degraded" for item in active_statuses):
            overall = "degraded"
        elif any(item == "ok" for item in active_statuses):
            overall = "ok"
        return {
            "status": overall,
            "problems": sorted(set(problems)),
            "channels": rows,
            "delivery": self._delivery.health_status(),
        }

    def _doctor_sandbox_status(self) -> dict[str, Any]:
        problems: list[str] = []
        connect_path = self._sandbox.connect_path_status()
        if not bool(connect_path.get("available", False)):
            problems.append("connect_path_unavailable")
        if not bool(self._policy_loader.policy.sandbox.fail_closed_security_critical):
            problems.append("fail_closed_security_critical_disabled")
        status = "ok"
        if "fail_closed_security_critical_disabled" in problems:
            status = "misconfigured"
        elif problems:
            status = "degraded"
        return {
            "status": status,
            "problems": sorted(set(problems)),
            "connect_path": connect_path,
            "sandbox_policy": {
                "default_backend": self._policy_loader.policy.sandbox.default_backend,
                "network_backend": self._policy_loader.policy.sandbox.network_backend,
                "fail_closed_security_critical": bool(
                    self._policy_loader.policy.sandbox.fail_closed_security_critical
                ),
            },
        }

    @staticmethod
    def _normalized_pairing_request_entry(raw: Mapping[str, Any]) -> dict[str, str] | None:
        channel = str(raw.get("channel", "")).strip().lower()
        external_user_id = str(raw.get("external_user_id", "")).strip()
        workspace_hint = str(raw.get("workspace_hint", "")).strip()
        reason = (
            str(raw.get("reason", "identity_not_allowlisted")).strip()
            or "identity_not_allowlisted"
        )
        if not channel or not external_user_id:
            return None
        if len(channel) > 64 or len(external_user_id) > 256:
            return None
        if any(ord(char) < 0x20 for char in channel):
            return None
        if any(ord(char) < 0x20 for char in external_user_id):
            return None
        if any(char.isspace() for char in channel):
            return None
        return {
            "channel": channel,
            "external_user_id": external_user_id,
            "workspace_hint": workspace_hint,
            "reason": reason,
        }

    def _load_pairing_request_artifacts(
        self,
        *,
        limit: int,
    ) -> tuple[list[dict[str, str]], list[dict[str, Any]]]:
        rows: list[dict[str, str]] = []
        invalid: list[dict[str, Any]] = []
        if not self._pairing_requests_file.exists():
            return rows, invalid
        try:
            lines = self._pairing_requests_file.read_text(encoding="utf-8").splitlines()
        except OSError as exc:
            invalid.append({"error": f"artifact_read_failed:{exc.__class__.__name__}"})
            return rows, invalid
        for index, line in enumerate(lines, start=1):
            if not line.strip():
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                invalid.append({"line": index, "error": "invalid_json"})
                continue
            if not isinstance(payload, Mapping):
                invalid.append({"line": index, "error": "invalid_shape"})
                continue
            normalized = self._normalized_pairing_request_entry(payload)
            if normalized is None:
                invalid.append({"line": index, "error": "missing_required_fields"})
                continue
            rows.append(normalized)
            if len(rows) >= limit:
                break
        return rows, invalid

    async def _execute_sandbox_config(
        self,
        *,
        sid: SessionId,
        session: Session,
        tool_name: ToolName,
        config: SandboxConfig,
    ) -> SandboxResult:
        action_hash = self._action_hash(
            session_id=sid,
            tool_name=tool_name,
            command=list(config.command),
        )
        command_hash = hashlib.sha256(
            " ".join(config.command).encode("utf-8", errors="ignore")
        ).hexdigest()
        try:
            await self._event_bus.publish(
                SandboxExecutionIntent(
                    session_id=sid,
                    actor="sandbox",
                    tool_name=tool_name,
                    action_hash=action_hash,
                    command_hash=command_hash,
                )
            )
        except (OSError, RuntimeError, TypeError, ValueError):
            return SandboxResult(
                allowed=False,
                reason="audit_unavailable_prelaunch",
                backend=config.sandbox_type,
                action_hash=action_hash,
                origin=dict(config.origin),
            )

        if SandboxOrchestrator.is_destructive(config.command):
            try:
                await self._event_bus.publish(
                    SandboxPreCheckpoint(
                        session_id=sid,
                        actor="sandbox",
                        tool_name=tool_name,
                        action_hash=action_hash,
                    )
                )
            except (OSError, RuntimeError, TypeError, ValueError):
                return SandboxResult(
                    allowed=False,
                    reason="audit_unavailable_prelaunch",
                    backend=config.sandbox_type,
                    action_hash=action_hash,
                    origin=dict(config.origin),
                )

        result = await self._sandbox.execute_async(config, session=session)
        result = result.model_copy(update={"action_hash": action_hash})
        try:
            await self._event_bus.publish(
                SandboxExecutionCompleted(
                    session_id=sid,
                    actor="sandbox",
                    tool_name=tool_name,
                    action_hash=action_hash,
                    success=bool(
                        result.allowed and not result.timed_out and (result.exit_code or 0) == 0
                    ),
                    error="" if result.allowed else result.reason,
                )
            )
        except (OSError, RuntimeError, TypeError, ValueError) as exc:
            await self._handle_lockdown_transition(
                sid,
                trigger="audit_failure",
                reason=f"audit durability failure after launch: {exc.__class__.__name__}",
                recommended_action="quarantine",
            )
        return result

    async def _handle_lockdown_transition(
        self,
        sid: SessionId,
        trigger: str,
        reason: str,
        recommended_action: str = "",
    ) -> None:
        state = self._lockdown_manager.trigger(
            sid,
            trigger=trigger,
            reason=reason,
            recommended_action=recommended_action,
        )
        await self._event_bus.publish(
            LockdownChanged(
                session_id=sid,
                actor="lockdown",
                level=state.level.value,
                reason=state.reason,
                trigger=state.trigger,
            )
        )

    @staticmethod
    def _pending_to_dict(pending: PendingAction) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "confirmation_id": pending.confirmation_id,
            "decision_nonce": pending.decision_nonce,
            "session_id": str(pending.session_id),
            "user_id": str(pending.user_id),
            "workspace_id": str(pending.workspace_id),
            "task_id": pending.task_id,
            "tool_name": str(pending.tool_name),
            "arguments": dict(pending.arguments),
            "reason": pending.reason,
            "capabilities": sorted(cap.value for cap in pending.capabilities),
            "created_at": pending.created_at.isoformat(),
            "execute_after": pending.execute_after.isoformat() if pending.execute_after else "",
            "safe_preview": pending.safe_preview,
            "warnings": list(pending.warnings),
            "leak_check": dict(pending.leak_check),
            "status": pending.status,
            "status_reason": pending.status_reason,
        }
        if pending.preflight_action is not None:
            payload["preflight_action"] = pending.preflight_action.model_dump(mode="json")
        if pending.merged_policy is not None:
            payload["merged_policy"] = pending.merged_policy.model_dump(mode="json")
        return payload

    @staticmethod
    def _is_high_risk_confirmation(tool_name: ToolName, arguments: dict[str, Any]) -> bool:
        lowered = str(tool_name).lower()
        if any(token in lowered for token in _HIGH_RISK_CONFIRM_TOKENS):
            return True
        candidate = str(
            arguments.get("to")
            or arguments.get("recipient")
            or arguments.get("destination")
            or arguments.get("url")
            or ""
        ).lower()
        return bool(
            candidate and ("http://" in candidate or "https://" in candidate or "@" in candidate)
        )

    def _session_source_text_by_id(self, session_id: SessionId) -> dict[str, str]:
        source_text: dict[str, str] = {}
        for entry in self._transcript_store.list_entries(session_id):
            if entry.role != "user":
                continue
            source_text[entry.content_hash] = entry.content_preview
        return source_text

    @staticmethod
    def _extract_outbound_text(arguments: dict[str, Any]) -> str:
        for key in ("body", "content", "message", "text", "request_body"):
            value = arguments.get(key)
            if isinstance(value, str) and value.strip():
                return value
        return ""

    def _queue_pending_action(
        self,
        *,
        session_id: SessionId,
        user_id: UserId,
        workspace_id: WorkspaceId,
        tool_name: ToolName,
        arguments: dict[str, Any],
        reason: str,
        capabilities: set[Capability],
        task_id: str = "",
        preflight_action: ControlPlaneAction | None = None,
        merged_policy: ToolExecutionPolicy | None = None,
        taint_labels: list[TaintLabel] | None = None,
        extra_warnings: list[str] | None = None,
    ) -> PendingAction:
        created_at = datetime.now(UTC)
        decision_nonce = uuid.uuid4().hex
        confirmation_id = uuid.uuid4().hex
        summary = safe_summary(
            action=str(tool_name),
            risk_level=(
                "high" if self._is_high_risk_confirmation(tool_name, arguments) else "medium"
            ),
            arguments=arguments,
        )
        warnings = self._confirmation_warning_generator.generate(
            user_id=str(user_id),
            tool_name=str(tool_name),
            arguments=arguments,
            taint_labels=[label.value for label in taint_labels or []],
        )
        if extra_warnings:
            warnings.extend(str(item).strip() for item in extra_warnings if str(item).strip())
        leak_result_payload: dict[str, Any] = {}
        outbound_text = self._extract_outbound_text(arguments)
        if outbound_text:
            leak_result = self._leak_detector.evaluate(
                outbound_text=outbound_text,
                source_text_by_id=self._session_source_text_by_id(session_id),
                allowed_source_ids={
                    str(item)
                    for item in arguments.get("source_ids", [])
                    if str(item).strip()
                }
                if isinstance(arguments.get("source_ids"), list)
                else set(),
                explicit_cross_thread_intent=bool(arguments.get("explicit_share_intent")),
            )
            leak_result_payload = {
                "detected": leak_result.detected,
                "overlap_score": leak_result.overlap_score,
                "matched_source_ids": list(leak_result.matched_source_ids),
                "reason_codes": list(leak_result.reason_codes),
                "requires_confirmation": leak_result.requires_confirmation,
                "detector_version": leak_result.detector_version,
            }
            if leak_result.detected:
                warnings.append("Cross-thread overlap detected")
                if leak_result.requires_confirmation:
                    reason = (
                        f"{reason},leakcheck:high_overlap_requires_confirmation"
                        if reason
                        else "leakcheck:high_overlap_requires_confirmation"
                    )
        execute_after: datetime | None = None
        if self._is_high_risk_confirmation(tool_name, arguments):
            execute_after = created_at + timedelta(seconds=3)
        pending = PendingAction(
            confirmation_id=confirmation_id,
            decision_nonce=decision_nonce,
            session_id=session_id,
            user_id=user_id,
            workspace_id=workspace_id,
            task_id=task_id,
            tool_name=tool_name,
            arguments=dict(arguments),
            reason=reason,
            capabilities=set(capabilities),
            created_at=created_at,
            preflight_action=preflight_action,
            execute_after=execute_after,
            safe_preview=render_structured_confirmation(summary, warnings=sorted(set(warnings))),
            warnings=sorted(set(warnings)),
            leak_check=leak_result_payload,
            merged_policy=(
                merged_policy.model_copy(deep=True)
                if merged_policy is not None
                else None
            ),
        )
        self._pending_actions[confirmation_id] = pending
        self._pending_by_session.setdefault(session_id, []).append(confirmation_id)
        self._persist_pending_actions()
        return pending

    def _persist_pending_actions(self) -> None:
        payload = [self._pending_to_dict(item) for item in self._pending_actions.values()]
        self._pending_actions_file.parent.mkdir(parents=True, exist_ok=True)
        self._pending_actions_file.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    def _load_pending_actions(self) -> None:
        if not self._pending_actions_file.exists():
            return
        try:
            raw = json.loads(self._pending_actions_file.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return
        if not isinstance(raw, list):
            return
        for item in raw:
            if not isinstance(item, dict):
                continue
            try:
                confirmation_id = str(item.get("confirmation_id", "")).strip()
                if not confirmation_id:
                    continue
                created_at = datetime.fromisoformat(str(item.get("created_at", "")).strip())
                session_id = SessionId(str(item.get("session_id", "")))
                preflight_action_payload = item.get("preflight_action")
                preflight_action = (
                    ControlPlaneAction.model_validate(preflight_action_payload)
                    if isinstance(preflight_action_payload, dict)
                    else None
                )
                merged_policy_payload = item.get("merged_policy")
                merged_policy = (
                    ToolExecutionPolicy.model_validate(merged_policy_payload)
                    if isinstance(merged_policy_payload, dict)
                    else None
                )
                execute_after_raw = str(item.get("execute_after", "")).strip()
                execute_after = (
                    datetime.fromisoformat(execute_after_raw) if execute_after_raw else None
                )
                pending = PendingAction(
                    confirmation_id=confirmation_id,
                    decision_nonce=str(item.get("decision_nonce", "")) or uuid.uuid4().hex,
                    session_id=session_id,
                    user_id=UserId(str(item.get("user_id", ""))),
                    workspace_id=WorkspaceId(str(item.get("workspace_id", ""))),
                    task_id=str(item.get("task_id", "")),
                    tool_name=ToolName(str(item.get("tool_name", ""))),
                    arguments=dict(item.get("arguments", {})),
                    reason=str(item.get("reason", "")),
                    capabilities={
                        Capability(str(cap))
                        for cap in item.get("capabilities", [])
                        if str(cap)
                    },
                    created_at=created_at,
                    preflight_action=preflight_action,
                    execute_after=execute_after,
                    safe_preview=str(item.get("safe_preview", "")),
                    warnings=[str(value) for value in item.get("warnings", [])],
                    leak_check=dict(item.get("leak_check", {})),
                    merged_policy=merged_policy,
                    status=str(item.get("status", "pending")),
                    status_reason=str(item.get("status_reason", "")),
                )
            except (TypeError, ValueError, ValidationError):
                continue
            self._pending_actions[pending.confirmation_id] = pending
            self._pending_by_session.setdefault(
                pending.session_id,
                [],
            ).append(pending.confirmation_id)

    def _is_verified_channel_identity(self, *, channel: str, external_user_id: str) -> bool:
        if channel == "matrix" and self._matrix_channel is not None:
            return self._matrix_channel.is_user_verified(external_user_id)
        if channel == "discord" and self._discord_channel is not None:
            return self._discord_channel.is_user_verified(external_user_id)
        if channel == "telegram" and self._telegram_channel is not None:
            return self._telegram_channel.is_user_verified(external_user_id)
        if channel == "slack" and self._slack_channel is not None:
            return self._slack_channel.is_user_verified(external_user_id)
        return False

    def _record_pairing_request_artifact(
        self,
        *,
        channel: str,
        external_user_id: str,
        workspace_hint: str,
        reason: str,
    ) -> None:
        payload = {
            "channel": channel,
            "external_user_id": external_user_id,
            "workspace_hint": workspace_hint,
            "reason": reason,
            "requested_at": datetime.now(UTC).isoformat(),
        }
        self._pairing_requests_file.parent.mkdir(parents=True, exist_ok=True)
        with self._pairing_requests_file.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(payload) + "\n")

    async def _record_monitor_reject(self, sid: SessionId, reason: str) -> None:
        count = self._monitor_reject_counts.get(sid, 0) + 1
        self._monitor_reject_counts[sid] = count
        if count < _MONITOR_REJECT_THRESHOLD:
            return
        await self._handle_lockdown_transition(
            sid,
            trigger="monitor_reject",
            reason=f"{count} monitor rejects: {reason}",
        )
        self._monitor_reject_counts[sid] = 0

    async def _record_plan_violation(
        self,
        *,
        sid: SessionId,
        tool_name: ToolName,
        action_kind: ActionKind,
        reason_code: str,
        risk_tier: RiskTier,
    ) -> None:
        count = self._plan_violation_counts.get(sid, 0) + 1
        self._plan_violation_counts[sid] = count
        await self._event_bus.publish(
            PlanViolationDetected(
                session_id=sid,
                actor="control_plane",
                tool_name=tool_name,
                action_kind=action_kind.value,
                reason_code=reason_code,
                risk_tier=risk_tier.value,
            )
        )
        threshold = max(1, int(self._policy_loader.policy.control_plane.trace.escalation_threshold))
        if count >= threshold:
            await self._handle_lockdown_transition(
                sid,
                trigger="plan_violation",
                reason=f"{reason_code} ({count})",
            )

    async def _execute_approved_action(
        self,
        *,
        sid: SessionId,
        user_id: UserId,
        tool_name: ToolName,
        arguments: dict[str, Any],
        capabilities: set[Capability],
        approval_actor: str,
        execution_action: ControlPlaneAction | None = None,
        merged_policy: ToolExecutionPolicy | None = None,
        user_confirmed: bool = False,
    ) -> ApprovedToolExecutionResult:
        session = self._session_manager.get(sid)
        if session is None:
            return ApprovedToolExecutionResult(success=False)

        origin = self._origin_for(
            session=session,
            actor=approval_actor,
            skill_name=str(arguments.get("skill_name") or "").strip(),
        )
        executed_action = execution_action or build_action(
            tool_name=str(tool_name),
            arguments=dict(arguments),
            origin=origin,
            risk_tier=RiskTier.LOW,
        )

        self._rate_limiter.consume(
            session_id=str(sid),
            user_id=str(user_id),
            tool_name=str(tool_name),
        )

        checkpoint_id: str | None = None
        tool = self._registry.get_tool(tool_name)
        if _should_checkpoint(self._config.checkpoint_trigger, tool):
            checkpoint = self._checkpoint_store.create(session)
            checkpoint_id = checkpoint.checkpoint_id

        await self._event_bus.publish(
            ToolApproved(
                session_id=sid,
                actor=approval_actor,
                tool_name=tool_name,
            )
        )

        if tool_name == "report_anomaly":
            payload = AnomalyReportInput.model_validate(arguments)
            await self._alarm_tool.execute(
                session_id=sid,
                actor="planner",
                payload=payload,
            )
            # On clean (untainted) sessions, report_anomaly is a content-seeing
            # component that can false-positive on platform formatting.  Log the
            # anomaly for audit but do NOT escalate lockdown — the session is
            # still trusted.  Escalate only when the session already carries
            # tainted history, where the anomaly is more likely to be genuine.
            session_tainted = self._session_has_tainted_history(sid)
            if session_tainted:
                await self._handle_lockdown_transition(
                    sid,
                    trigger="alarm_bell",
                    reason=payload.description,
                    recommended_action=payload.recommended_action,
                )
            await self._event_bus.publish(
                ToolExecuted(
                    session_id=sid,
                    actor="tool_runtime",
                    tool_name=tool_name,
                    success=True,
                )
            )
            self._control_plane.record_execution(action=executed_action, success=True)
            return ApprovedToolExecutionResult(
                success=True,
                checkpoint_id=checkpoint_id,
                tool_output=ToolOutputRecord(
                    tool_name=str(tool_name),
                    content="Anomaly reported and lockdown evaluation triggered.",
                    taint_labels=set(),
                ),
            )

        if tool_name == "retrieve_rag":
            records = self._ingestion.retrieve(
                query=str(arguments.get("query", "")),
                limit=int(arguments.get("limit", 5)),
                capabilities=capabilities,
            )
            await self._event_bus.publish(
                ToolExecuted(
                    session_id=sid,
                    actor="tool_runtime",
                    tool_name=tool_name,
                    success=True,
                )
            )
            self._control_plane.record_execution(action=executed_action, success=True)
            preview_rows = [
                {
                    "chunk_id": item.chunk_id,
                    "source_id": item.source_id,
                    "collection": item.collection,
                    "content": item.content_sanitized[:180],
                }
                for item in records
            ]
            retrieval_taints: set[TaintLabel] = set()
            for item in records:
                retrieval_taints.update(
                    normalize_retrieval_taints(
                        taint_labels=item.taint_labels,
                        collection=item.collection,
                    )
                )
            return ApprovedToolExecutionResult(
                success=True,
                checkpoint_id=checkpoint_id,
                tool_output=ToolOutputRecord(
                    tool_name=str(tool_name),
                    content=self._sanitize_tool_output_text(
                        json.dumps(preview_rows, ensure_ascii=True)
                    ),
                    taint_labels=retrieval_taints,
                ),
            )

        if tool_name == "message.send":
            target = DeliveryTarget(
                channel=optional_string(arguments.get("channel", "")),
                recipient=optional_string(arguments.get("recipient", "")),
                workspace_hint=optional_string(arguments.get("workspace_hint", "")),
                thread_id=optional_string(arguments.get("thread_id", "")),
            )
            message_text = optional_string(arguments.get("message", ""))
            if target.channel == "session":
                reason = ""
                target_session = (
                    self._session_manager.get(SessionId(target.recipient))
                    if target.recipient
                    else None
                )
                if approval_actor != "scheduler":
                    reason = "session_delivery_requires_scheduler_actor"
                elif target_session is None:
                    reason = "session_delivery_session_not_found"
                if reason:
                    delivery_payload = {
                        "attempted": True,
                        "sent": False,
                        "reason": reason,
                        "target": {
                            "channel": target.channel,
                            "recipient": target.recipient,
                            "workspace_hint": target.workspace_hint,
                            "thread_id": target.thread_id,
                        },
                    }
                    await self._event_bus.publish(
                        ToolRejected(
                            session_id=sid,
                            actor="tool_runtime",
                            tool_name=tool_name,
                            reason=reason,
                        )
                    )
                    await self._event_bus.publish(
                        ToolExecuted(
                            session_id=sid,
                            actor="tool_runtime",
                            tool_name=tool_name,
                            success=False,
                        )
                    )
                    self._control_plane.record_execution(action=executed_action, success=False)
                    return ApprovedToolExecutionResult(
                        success=False,
                        checkpoint_id=checkpoint_id,
                        tool_output=ToolOutputRecord(
                            tool_name=str(tool_name),
                            content=self._sanitize_tool_output_text(
                                json.dumps(delivery_payload, ensure_ascii=True)
                            ),
                            success=False,
                            taint_labels=set(),
                        ),
                    )

                transcript_metadata: dict[str, Any] = {
                    "channel": "session",
                    "timestamp_utc": datetime.now(UTC).isoformat(),
                    "session_mode": (target_session or session).mode.value,
                    "delivered_by": approval_actor,
                    "delivery_target": {
                        "channel": target.channel,
                        "recipient": target.recipient,
                        "workspace_hint": target.workspace_hint,
                        "thread_id": target.thread_id,
                    },
                }
                task_id = str(executed_action.origin.task_id).strip()
                if task_id:
                    transcript_metadata["task_id"] = task_id
                self._transcript_store.append(
                    SessionId(target.recipient),
                    role="assistant",
                    content=message_text,
                    taint_labels=set(),
                    metadata=transcript_metadata,
                )
                delivery_payload = {
                    "attempted": True,
                    "sent": True,
                    "reason": "session_transcript_appended",
                    "target": {
                        "channel": target.channel,
                        "recipient": target.recipient,
                        "workspace_hint": target.workspace_hint,
                        "thread_id": target.thread_id,
                    },
                }
                await self._event_bus.publish(
                    ToolExecuted(
                        session_id=sid,
                        actor="tool_runtime",
                        tool_name=tool_name,
                        success=True,
                    )
                )
                self._control_plane.record_execution(action=executed_action, success=True)
                return ApprovedToolExecutionResult(
                    success=True,
                    checkpoint_id=checkpoint_id,
                    tool_output=ToolOutputRecord(
                        tool_name=str(tool_name),
                        content=self._sanitize_tool_output_text(
                            json.dumps(delivery_payload, ensure_ascii=True)
                        ),
                        success=True,
                        taint_labels=set(),
                    ),
                )

            delivery_result = await self._delivery.send(
                target=target,
                message=message_text,
            )
            as_dict = getattr(delivery_result, "as_dict", None)
            if callable(as_dict):
                delivery_payload = as_dict()
            else:
                delivery_payload = {
                    "attempted": True,
                    "sent": bool(getattr(delivery_result, "sent", False)),
                    "reason": str(getattr(delivery_result, "reason", "")),
                    "target": {
                        "channel": target.channel,
                        "recipient": target.recipient,
                        "workspace_hint": target.workspace_hint,
                        "thread_id": target.thread_id,
                    },
                }
            success = bool(delivery_result.sent)
            if not success:
                await self._event_bus.publish(
                    ToolRejected(
                        session_id=sid,
                        actor="tool_runtime",
                        tool_name=tool_name,
                        reason=delivery_result.reason or "message_send_failed",
                    )
                )
            await self._event_bus.publish(
                ToolExecuted(
                    session_id=sid,
                    actor="tool_runtime",
                    tool_name=tool_name,
                    success=success,
                )
            )
            self._control_plane.record_execution(action=executed_action, success=success)
            return ApprovedToolExecutionResult(
                success=success,
                checkpoint_id=checkpoint_id,
                tool_output=ToolOutputRecord(
                    tool_name=str(tool_name),
                    content=self._sanitize_tool_output_text(
                        json.dumps(delivery_payload, ensure_ascii=True)
                    ),
                    success=success,
                    taint_labels=set(),
                ),
            )

        def _record_execution(success: bool) -> None:
            self._control_plane.record_execution(action=executed_action, success=success)

        async def _execute_structured_payload_tool(
            payload: Mapping[str, Any],
            *,
            default_error: str,
        ) -> ApprovedToolExecutionResult:
            result = await execute_structured_tool(
                session_id=sid,
                tool_name=tool_name,
                payload=payload,
                default_error=default_error,
                actor="tool_runtime",
                emit_event=self._event_bus.publish,
                record_execution=_record_execution,
                sanitize_output=self._sanitize_tool_output_text,
                taint_labels=label_tool_output(str(tool_name)),
            )
            return ApprovedToolExecutionResult(
                success=result.success,
                checkpoint_id=checkpoint_id,
                tool_output=ToolOutputRecord(
                    tool_name=str(tool_name),
                    content=result.content,
                    success=result.success,
                    taint_labels=result.taint_labels,
                ),
            )

        structured_handler = HandlerImplementation._structured_tool_registry().get(
            str(tool_name)
        )
        if structured_handler is not None:
            payload_builder, default_error = structured_handler
            structured_context = StructuredToolContext(
                session_id=sid,
                user_id=user_id,
                workspace_id=session.workspace_id,
                session=session,
                user_confirmed=user_confirmed,
            )
            try:
                structured_payload_result = payload_builder(
                    self,
                    arguments,
                    structured_context,
                )
                if inspect.isawaitable(structured_payload_result):
                    structured_payload = await structured_payload_result
                else:
                    structured_payload = structured_payload_result
                if not isinstance(structured_payload, Mapping):
                    raise TypeError("structured tool payload must be a mapping")
            except Exception as exc:
                logger.exception(
                    "Structured tool payload build failed: tool=%s error=%s",
                    tool_name,
                    exc,
                )
                structured_payload = {
                    "ok": False,
                    "error": str(exc).strip() or default_error,
                }
            return await _execute_structured_payload_tool(
                structured_payload,
                default_error=default_error,
            )

        if tool is None:
            await self._event_bus.publish(
                ToolExecuted(
                    session_id=sid,
                    actor="tool_runtime",
                    tool_name=tool_name,
                    success=False,
                )
            )
            self._control_plane.record_execution(action=executed_action, success=False)
            return ApprovedToolExecutionResult(
                success=False,
                checkpoint_id=checkpoint_id,
            )

        sandbox_result = await self._execute_via_sandbox(
            sid=sid,
            session=session,
            tool=tool,
            arguments=arguments,
            origin=origin,
            approved_by_pep=True,
            merged_policy=merged_policy,
        )
        await self._publish_sandbox_events(
            sid=sid,
            config_tool_name=tool_name,
            result=sandbox_result,
        )
        if sandbox_result.checkpoint_id:
            checkpoint_id = sandbox_result.checkpoint_id
        success = bool(
            sandbox_result.allowed
            and not sandbox_result.timed_out
            and (sandbox_result.exit_code or 0) == 0
        )
        if not success:
            await self._event_bus.publish(
                ToolRejected(
                    session_id=sid,
                    actor="tool_runtime",
                    tool_name=tool_name,
                    reason=sandbox_result.reason or "sandbox_execution_failed",
                )
            )
        await self._event_bus.publish(
            ToolExecuted(
                session_id=sid,
                actor="sandbox",
                tool_name=tool_name,
                success=success,
            )
        )
        self._control_plane.record_execution(action=executed_action, success=success)
        raw_output = "\n".join(
            segment for segment in [sandbox_result.stdout, sandbox_result.stderr] if segment
        ).strip()
        return ApprovedToolExecutionResult(
            success=success,
            checkpoint_id=checkpoint_id,
            tool_output=ToolOutputRecord(
                tool_name=str(tool_name),
                content=self._sanitize_tool_output_text(raw_output),
                success=success,
                taint_labels=label_tool_output(str(tool_name)),
            )
            if raw_output
            else None,
            sandbox_result=sandbox_result,
        )

    @staticmethod
    @lru_cache(maxsize=1)
    def _structured_tool_registry() -> dict[
        str,
        tuple[StructuredPayloadBuilder, str],
    ]:
        return {
            "web.search": (_structured_web_search, "web_search_failed"),
            "web.fetch": (_structured_web_fetch, "web_fetch_failed"),
            "realitycheck.search": (
                _structured_realitycheck_search,
                "realitycheck_search_failed",
            ),
            "realitycheck.read": (_structured_realitycheck_read, "realitycheck_read_failed"),
            "fs.list": (_structured_fs_list, "fs_list_failed"),
            "fs.read": (_structured_fs_read, "fs_read_failed"),
            "fs.write": (_structured_fs_write, "fs_write_failed"),
            "git.status": (_structured_git_status, "git_status_failed"),
            "git.diff": (_structured_git_diff, "git_diff_failed"),
            "git.log": (_structured_git_log, "git_log_failed"),
            "note.create": (_structured_note_create, "note_create_failed"),
            "note.list": (_structured_note_list, "note_list_failed"),
            "note.search": (_structured_note_search, "note_search_failed"),
            "todo.create": (_structured_todo_create, "todo_create_failed"),
            "todo.list": (_structured_todo_list, "todo_list_failed"),
            "todo.complete": (_structured_todo_complete, "todo_complete_failed"),
            "reminder.create": (_structured_reminder_create, "reminder_create_failed"),
            "reminder.list": (_structured_reminder_list, "reminder_list_failed"),
            "evidence.read": (_structured_evidence_read, "evidence_read_failed"),
            "evidence.promote": (_structured_evidence_promote, "evidence_promote_failed"),
        }

    def _sanitize_tool_output_text(self, raw: str) -> str:
        if not raw:
            return ""
        inspected = self._output_firewall.inspect(
            raw,
            context={"actor": "tool_output_boundary"},
        )
        cleaned = inspected.sanitized_text
        return (
            cleaned.replace("TOOL_OUTPUT_BEGIN", "TOOL_OUTPUT_MARKER")
            .replace("TOOL_OUTPUT_END", "TOOL_OUTPUT_MARKER")
            .strip()
        )

    async def _execute_via_sandbox(
        self,
        *,
        sid: SessionId,
        session: Session,
        tool: ToolDefinition,
        arguments: dict[str, Any],
        origin: Origin,
        approved_by_pep: bool,
        merged_policy: ToolExecutionPolicy | None = None,
    ) -> SandboxResult:
        raw_command = arguments.get("command", [])
        command = [str(token) for token in raw_command] if isinstance(raw_command, list) else []
        if not command:
            return await self._sandbox.execute_async(
                SandboxConfig(
                    session_id=str(sid),
                    tool_name=str(tool.name),
                    command=[],
                    origin=origin.model_dump(mode="json"),
                ),
                session=session,
            )
        if merged_policy is None:
            try:
                merged_policy = self._build_merged_policy(
                    tool_name=tool.name,
                    arguments=arguments,
                    tool_definition=tool,
                )
            except PolicyMergeError as exc:
                return SandboxResult(
                    allowed=False,
                    reason=f"policy_merge:{exc}",
                    origin=origin.model_dump(mode="json"),
                )

        config = self._build_sandbox_config(
            sid=sid,
            tool_name=tool.name,
            params={**dict(arguments), "command": command},
            merged_policy=merged_policy,
            origin=origin,
            approved_by_pep=approved_by_pep,
        )
        return await self._execute_sandbox_config(
            sid=sid,
            session=session,
            tool_name=tool.name,
            config=config,
        )

    async def _publish_sandbox_events(
        self,
        *,
        sid: SessionId,
        config_tool_name: ToolName,
        result: SandboxResult,
    ) -> None:
        origin_data = {str(key): str(value) for key, value in dict(result.origin).items()}
        try:
            origin = Origin.model_validate(origin_data)
        except ValidationError:
            origin = Origin(session_id=str(sid), actor="sandbox")
        if result.degraded_controls:
            await self._event_bus.publish(
                SandboxDegraded(
                    session_id=sid,
                    actor="sandbox",
                    tool_name=config_tool_name,
                    backend=result.backend.value if result.backend is not None else "",
                    controls=list(result.degraded_controls),
                )
            )
        for decision in result.network_decisions:
            await self._event_bus.publish(
                ProxyRequestEvaluated(
                    session_id=sid,
                    actor="egress_proxy",
                    tool_name=config_tool_name,
                    destination_host=decision.destination_host,
                    destination_port=decision.destination_port,
                    protocol=decision.protocol,
                    request_size=decision.request_size,
                    resolved_addresses=list(decision.resolved_addresses),
                    allowed=decision.allowed,
                    reason=decision.reason,
                    credential_placeholders=list(decision.used_placeholders),
                    origin=origin_data,
                )
            )
            self._control_plane.observe_runtime_network(
                origin=origin,
                tool_name=str(config_tool_name),
                destination_host=decision.destination_host,
                destination_port=decision.destination_port,
                protocol=decision.protocol,
                allowed=decision.allowed,
                reason=decision.reason,
                request_size=decision.request_size,
                resolved_addresses=list(decision.resolved_addresses),
            )
            await self._event_bus.publish(
                ControlPlaneNetworkObserved(
                    session_id=sid,
                    actor="control_plane",
                    tool_name=config_tool_name,
                    destination_host=decision.destination_host,
                    destination_port=decision.destination_port,
                    protocol=decision.protocol,
                    request_size=decision.request_size,
                    allowed=decision.allowed,
                    reason=decision.reason,
                    resolved_addresses=list(decision.resolved_addresses),
                    origin=origin_data,
                )
            )
        if result.escape_detected:
            await self._event_bus.publish(
                SandboxEscapeDetected(
                    session_id=sid,
                    actor="sandbox",
                    tool_name=config_tool_name,
                    reason=result.reason,
                )
            )
            await self._handle_lockdown_transition(
                sid,
                trigger="sandbox_escape",
                reason=result.reason or "sandbox escape detected",
            )

    @staticmethod
    def _restore_filesystem_from_checkpoint(
        state: dict[str, Any],
    ) -> tuple[int, int, list[str]]:
        snapshots = state.get("filesystem_snapshot", [])
        if not isinstance(snapshots, list):
            return 0, 0, []
        restored = 0
        deleted = 0
        errors: list[str] = []
        for item in snapshots:
            if not isinstance(item, dict):
                continue
            path = str(item.get("path", "")).strip()
            if not path:
                continue
            candidate = Path(path).expanduser()
            existed = bool(item.get("existed", False))
            try:
                if existed:
                    encoded = item.get("content_b64")
                    if not isinstance(encoded, str):
                        continue
                    data = base64.b64decode(encoded.encode("utf-8"), validate=True)
                    candidate.parent.mkdir(parents=True, exist_ok=True)
                    candidate.write_bytes(data)
                    restored += 1
                    continue
                if candidate.exists() and candidate.is_file():
                    candidate.unlink()
                    deleted += 1
            except (OSError, TypeError, ValueError, binascii.Error) as exc:  # pragma: no cover
                errors.append(f"{path}:{exc.__class__.__name__}")
        return restored, deleted, errors
