"""Control API handler bundle for daemon runtime."""

from __future__ import annotations

import asyncio
import base64
import binascii
import contextlib
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
from typing import TYPE_CHECKING, Any, cast

from pydantic import ValidationError

from shisad.assistant.fs_git import FsGitToolkit
from shisad.assistant.web import WebToolkit
from shisad.channels.base import DeliveryTarget
from shisad.core.approval import (
    ApprovalEnvelope,
    ApprovalRoutingError,
    ConfirmationBackendRegistry,
    ConfirmationCapabilities,
    ConfirmationEvidence,
    ConfirmationFallbackPolicy,
    ConfirmationLevel,
    ConfirmationMethodLockoutTracker,
    ConfirmationRequirement,
    EnterpriseKmsSignerBackend,
    IntentAction,
    IntentEnvelope,
    IntentPolicyContext,
    LedgerSignerBackend,
    LocalFido2Backend,
    SignerConfirmationAdapter,
    SoftwareConfirmationBackend,
    TOTPBackend,
    WebAuthnBackend,
    approval_audit_fields,
    approval_envelope_hash,
    compute_action_digest,
    intent_envelope_hash,
    legacy_software_confirmation_requirement,
    new_approval_nonce,
    resolve_confirmation_destinations,
)
from shisad.core.attachments import AttachmentIngestor, AttachmentIngestPolicy
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
from shisad.daemon.handlers._impl_tool_execution import (
    ToolExecutionImplMixin,
    _tool_execute_runtime_arguments,
)
from shisad.daemon.handlers._mixin_typing import call_control_plane as _call_control_plane
from shisad.daemon.handlers._pending_approval import (
    PendingPepContextSnapshot,
    PendingPepElevationRequest,
    pending_pep_context_from_payload,
    pending_pep_context_to_payload,
    pending_pep_elevation_from_payload,
    pending_pep_elevation_to_payload,
    pending_pep_elevation_warning,
    pep_arguments_for_policy_evaluation,
)
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
from shisad.memory.ingress import IngressContext
from shisad.memory.remap import digest_memory_value
from shisad.memory.summarizer import ConversationSummarizer
from shisad.memory.trust import ChannelTrust, SourceOrigin
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
from shisad.security.control_plane.sidecar import (
    ControlPlaneRpcError,
    ControlPlaneUnavailableError,
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
_CONTROL_API_AUTHENTICATED_WRITE = "_control_api_authenticated_write"


class _EventPublisher:
    def __init__(self, event_bus: EventBus) -> None:
        self._event_bus = event_bus

    async def publish(self, event: BaseEvent) -> None:
        await publish_event(self._event_bus, event)


class _LazyBrowserToolkit:
    def __init__(self, **kwargs: Any) -> None:
        self._kwargs = dict(kwargs)
        self._impl: Any | None = None

    def _load(self) -> Any:
        if self._impl is None:
            from shisad.executors.browser import BrowserToolkit

            self._impl = BrowserToolkit(**self._kwargs)
        return self._impl

    async def prepare_action_arguments(self, **kwargs: Any) -> dict[str, Any]:
        return dict(await self._load().prepare_action_arguments(**kwargs))

    async def navigate(self, **kwargs: Any) -> dict[str, Any]:
        return dict(await self._load().navigate(**kwargs))

    async def read_page(self, **kwargs: Any) -> dict[str, Any]:
        return dict(await self._load().read_page(**kwargs))

    async def screenshot(self, **kwargs: Any) -> dict[str, Any]:
        return dict(await self._load().screenshot(**kwargs))

    async def click(self, **kwargs: Any) -> dict[str, Any]:
        return dict(await self._load().click(**kwargs))

    async def type_text(self, **kwargs: Any) -> dict[str, Any]:
        return dict(await self._load().type_text(**kwargs))

    async def end_session(self, **kwargs: Any) -> dict[str, Any]:
        return dict(await self._load().end_session(**kwargs))


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


async def _structured_browser_navigate(
    handler: Any,
    arguments: Mapping[str, Any],
    context: StructuredToolContext,
) -> Mapping[str, Any]:
    return dict(
        await handler._browser_toolkit.navigate(
            session=context.session,
            url=_argument_string(arguments, "url"),
        )
    )


async def _structured_browser_read_page(
    handler: Any,
    arguments: Mapping[str, Any],
    context: StructuredToolContext,
) -> Mapping[str, Any]:
    _ = arguments
    return dict(await handler._browser_toolkit.read_page(session=context.session))


async def _structured_browser_screenshot(
    handler: Any,
    arguments: Mapping[str, Any],
    context: StructuredToolContext,
) -> Mapping[str, Any]:
    _ = arguments
    return dict(await handler._browser_toolkit.screenshot(session=context.session))


async def _structured_browser_click(
    handler: Any,
    arguments: Mapping[str, Any],
    context: StructuredToolContext,
) -> Mapping[str, Any]:
    return dict(
        await handler._browser_toolkit.click(
            session=context.session,
            target=_argument_string(arguments, "target"),
            description=_argument_string(arguments, "description"),
            resolved_target=_argument_string(arguments, "resolved_target"),
            destination=_argument_string(arguments, "destination"),
            source_url=_argument_string(arguments, "source_url"),
            source_binding=_argument_string(arguments, "source_binding"),
        )
    )


async def _structured_browser_type_text(
    handler: Any,
    arguments: Mapping[str, Any],
    context: StructuredToolContext,
) -> Mapping[str, Any]:
    return dict(
        await handler._browser_toolkit.type_text(
            session=context.session,
            target=_argument_string(arguments, "target"),
            text=_argument_string(arguments, "text"),
            is_sensitive=bool(arguments.get("is_sensitive", False)),
            submit=bool(arguments.get("submit", False)),
            resolved_target=_argument_string(arguments, "resolved_target"),
            destination=_argument_string(arguments, "destination"),
            source_url=_argument_string(arguments, "source_url"),
            source_binding=_argument_string(arguments, "source_binding"),
        )
    )


async def _structured_browser_end_session(
    handler: Any,
    arguments: Mapping[str, Any],
    context: StructuredToolContext,
) -> Mapping[str, Any]:
    _ = arguments
    return dict(await handler._browser_toolkit.end_session(session=context.session))


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


def _structured_email_search(
    handler: Any,
    arguments: Mapping[str, Any],
    _context: StructuredToolContext | None = None,
) -> Mapping[str, Any]:
    query = _argument_string(arguments, "query")
    if not query:
        return {
            "ok": False,
            "error": "email_search_query_required",
            "taint_labels": [TaintLabel.UNTRUSTED.value, TaintLabel.SENSITIVE_EMAIL.value],
        }
    return dict(
        handler._msgvault_toolkit.search(
            query=query,
            limit=_argument_int(arguments, "limit", default=10, minimum=1),
            offset=_argument_int(arguments, "offset", default=0, minimum=0),
            account=_argument_string(arguments, "account"),
        )
    )


def _structured_email_read(
    handler: Any,
    arguments: Mapping[str, Any],
    _context: StructuredToolContext | None = None,
) -> Mapping[str, Any]:
    message_id = _argument_string(arguments, "message_id") or _argument_string(arguments, "id")
    if not message_id:
        return {
            "ok": False,
            "error": "email_message_id_required",
            "taint_labels": [TaintLabel.UNTRUSTED.value, TaintLabel.SENSITIVE_EMAIL.value],
        }
    return dict(
        handler._msgvault_toolkit.read_message(
            message_id=message_id,
            account=_argument_string(arguments, "account"),
        )
    )


def _structured_fs_list(
    handler: Any,
    arguments: Mapping[str, Any],
    context: StructuredToolContext | None = None,
) -> Mapping[str, Any]:
    toolkit = _fs_git_toolkit_for_context(handler, context)
    return dict(
        toolkit.list_dir(
            path=_argument_string(arguments, "path", default=".") or ".",
            recursive=bool(arguments.get("recursive", False)),
            limit=_argument_int(arguments, "limit", default=200, minimum=1),
        )
    )


def _structured_fs_read(
    handler: Any,
    arguments: Mapping[str, Any],
    context: StructuredToolContext | None = None,
) -> Mapping[str, Any]:
    toolkit = _fs_git_toolkit_for_context(handler, context)
    return dict(
        toolkit.read_file(
            path=_argument_string(arguments, "path"),
            max_bytes=_optional_int(arguments.get("max_bytes")),
        )
    )


def _structured_attachment_ingest(
    handler: Any,
    arguments: Mapping[str, Any],
    context: StructuredToolContext | None = None,
) -> Mapping[str, Any]:
    if context is None:
        return {
            "ok": False,
            "error": "attachment_context_required",
            "taint_labels": [TaintLabel.UNTRUSTED.value],
        }
    ingestor = getattr(handler, "_attachment_ingestor", None)
    if ingestor is None:
        return {
            "ok": False,
            "error": "attachment_ingest_unavailable",
            "taint_labels": [TaintLabel.UNTRUSTED.value],
        }
    return dict(
        ingestor.ingest_path(
            session_id=context.session_id,
            path=_argument_string(arguments, "path"),
            declared_mime_type=(
                _argument_string(arguments, "mime_type")
                or _argument_string(arguments, "declared_mime_type")
            ),
            filename=_argument_string(arguments, "filename"),
            transcript_text=_argument_string(arguments, "transcript_text"),
            max_bytes=_optional_int(arguments.get("max_bytes")),
        )
    )


def _structured_fs_write(
    handler: Any,
    arguments: Mapping[str, Any],
    context: StructuredToolContext | None = None,
) -> Mapping[str, Any]:
    trust_level = (
        str(context.session.metadata.get("trust_level", "")).strip().lower()
        if context is not None
        else ""
    )
    trusted_cli_policy_approved = (
        context is not None
        and context.session.channel == "cli"
        and context.session.mode == SessionMode.DEFAULT
        and (
            trust_level == "trusted_cli"
            or (
                trust_level == "trusted"
                and bool(context.session.metadata.get("operator_owned_cli", False))
            )
        )
    )
    return dict(
        _fs_git_toolkit_for_context(handler, context).write_file(
            path=_argument_string(arguments, "path"),
            content=_argument_string(arguments, "content"),
            confirm=bool(arguments.get("confirm", False))
            or bool(context and context.user_confirmed)
            or trusted_cli_policy_approved,
        )
    )


def _structured_git_status(
    handler: Any,
    arguments: Mapping[str, Any],
    context: StructuredToolContext | None = None,
) -> Mapping[str, Any]:
    toolkit = _fs_git_toolkit_for_context(handler, context)
    return dict(
        toolkit.git_status(
            repo_path=_argument_string(arguments, "repo_path", default=".") or ".",
        )
    )


def _structured_git_diff(
    handler: Any,
    arguments: Mapping[str, Any],
    context: StructuredToolContext | None = None,
) -> Mapping[str, Any]:
    toolkit = _fs_git_toolkit_for_context(handler, context)
    return dict(
        toolkit.git_diff(
            repo_path=_argument_string(arguments, "repo_path", default=".") or ".",
            ref=_argument_string(arguments, "ref"),
            max_lines=_argument_int(arguments, "max_lines", default=400, minimum=1),
        )
    )


def _structured_git_log(
    handler: Any,
    arguments: Mapping[str, Any],
    context: StructuredToolContext | None = None,
) -> Mapping[str, Any]:
    toolkit = _fs_git_toolkit_for_context(handler, context)
    return dict(
        toolkit.git_log(
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
    memory_ingress_context: IngressContext | None = None


def _task_declared_fs_runtime_roots(session: Session) -> list[Path]:
    if session.mode != SessionMode.TASK:
        return []
    raw_envelope = session.metadata.get("task_envelope")
    if not isinstance(raw_envelope, Mapping):
        return []
    authority = str(raw_envelope.get("resource_scope_authority", "")).strip().lower()
    if authority != "command_clean":
        return []
    resource_scope_ids = raw_envelope.get("resource_scope_ids", [])
    resource_scope_prefixes = raw_envelope.get("resource_scope_prefixes", [])
    declared_scope = [
        str(item).strip()
        for items in (resource_scope_ids, resource_scope_prefixes)
        if isinstance(items, list)
        for item in items
        if str(item).strip()
    ]
    if not declared_scope:
        return []
    return [Path.cwd().expanduser().resolve(strict=False)]


def _fs_git_toolkit_for_context(
    handler: Any,
    context: StructuredToolContext | None,
) -> FsGitToolkit:
    toolkit = cast(FsGitToolkit, handler._fs_git_toolkit)
    if getattr(toolkit, "roots", None):
        return toolkit
    if context is None:
        return toolkit
    scoped_roots = _task_declared_fs_runtime_roots(context.session)
    if not scoped_roots:
        return toolkit
    return FsGitToolkit(
        roots=scoped_roots,
        max_read_bytes=handler._config.assistant_max_read_bytes,
        git_timeout_seconds=handler._config.assistant_git_timeout_seconds,
        protected_write_paths=tuple(getattr(toolkit, "protected_write_paths", ())),
    )


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
    parsed = parsed.replace(tzinfo=UTC) if parsed.tzinfo is None else parsed.astimezone(UTC)
    return max(1, int((parsed - now).total_seconds()))


async def _structured_note_create(
    handler: Any,
    arguments: Mapping[str, Any],
    context: StructuredToolContext,
) -> Mapping[str, Any]:
    content = _argument_string(arguments, "content")
    if not content:
        return {"ok": False, "error": "note_content_required"}
    if context.memory_ingress_context is not None:
        payload = await handler.do_note_create(
            {
                "key": _argument_string(arguments, "key") or _slugify_memory_key("note", content),
                "content": content,
                "ingress_context": context.memory_ingress_context.handle_id,
                "content_digest": digest_memory_value(content),
                "derivation_path": "extracted",
                "parent_digest": context.memory_ingress_context.content_digest,
            }
        )
        return _wrap_structured_payload(payload, ok=str(payload.get("kind", "")) == "allow")
    payload = await handler.do_note_create(
        {
            "key": _argument_string(arguments, "key") or _slugify_memory_key("note", content),
            "content": content,
            _CONTROL_API_AUTHENTICATED_WRITE: True,
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
    todo_payload = {
        "title": title,
        "details": _argument_string(arguments, "details"),
        "due_date": _argument_string(arguments, "due_date"),
    }
    if context.memory_ingress_context is not None:
        payload = await handler.do_todo_create(
            {
                **todo_payload,
                "ingress_context": context.memory_ingress_context.handle_id,
                "content_digest": digest_memory_value({**todo_payload, "status": "open"}),
                "derivation_path": "extracted",
                "parent_digest": context.memory_ingress_context.content_digest,
            }
        )
        return _wrap_structured_payload(payload, ok=str(payload.get("kind", "")) == "allow")
    payload = await handler.do_todo_create(
        {
            **todo_payload,
            _CONTROL_API_AUTHENTICATED_WRITE: True,
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
            "name": _argument_string(arguments, "name") or _slugify_memory_key("reminder", message),
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
    ref, content = await asyncio.to_thread(store.resolve_ref_content, context.session_id, ref_id)
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
    ref, content = await asyncio.to_thread(store.resolve_ref_content, context.session_id, ref_id)
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
    delivery_target: DeliveryTarget | None = None
    task_id: str = ""
    preflight_action: ControlPlaneAction | None = None
    execute_after: datetime | None = None
    safe_preview: str = ""
    warnings: list[str] = field(default_factory=list)
    leak_check: dict[str, Any] = field(default_factory=dict)
    merged_policy: ToolExecutionPolicy | None = None
    approval_task_envelope_id: str = ""
    pep_context: PendingPepContextSnapshot | None = None
    pep_elevation: PendingPepElevationRequest | None = None
    required_level: ConfirmationLevel = ConfirmationLevel.SOFTWARE
    required_methods: list[str] = field(default_factory=list)
    allowed_principals: list[str] = field(default_factory=list)
    allowed_credentials: list[str] = field(default_factory=list)
    required_capabilities: ConfirmationCapabilities = field(
        default_factory=ConfirmationCapabilities
    )
    approval_envelope: ApprovalEnvelope | None = None
    approval_envelope_hash: str = ""
    intent_envelope: IntentEnvelope | None = None
    confirmation_evidence: ConfirmationEvidence | None = None
    fallback: ConfirmationFallbackPolicy = field(default_factory=ConfirmationFallbackPolicy)
    expires_at: datetime | None = None
    selected_backend_id: str = ""
    selected_backend_method: str = ""
    fallback_used: bool = False
    strip_direct_tool_execute_envelope_keys: bool = False
    status: str = "pending"
    status_reason: str = ""

    @staticmethod
    def _is_legacy_direct_mcp_tool_execute_shape(
        *,
        tool_name: ToolName | str,
        arguments: Mapping[str, Any],
        preflight_action: ControlPlaneAction | Mapping[str, Any] | None,
    ) -> bool:
        if not str(tool_name).strip().startswith("mcp."):
            return False
        if not all(key in arguments for key in ("session_id", "tool_name", "command")):
            return False
        if isinstance(preflight_action, Mapping):
            origin = preflight_action.get("origin")
            if isinstance(origin, Mapping):
                return str(origin.get("actor", "")).strip() == "control_api"
            return False
        return str(getattr(getattr(preflight_action, "origin", None), "actor", "")).strip() == (
            "control_api"
        )

    def should_strip_direct_tool_execute_envelope_keys(self) -> bool:
        return bool(self.strip_direct_tool_execute_envelope_keys) or (
            PendingAction._is_legacy_direct_mcp_tool_execute_shape(
                tool_name=self.tool_name,
                arguments=self.arguments,
                preflight_action=self.preflight_action,
            )
        )


@dataclass(slots=True)
class ToolOutputRecord:
    tool_name: str
    content: str
    success: bool = True
    taint_labels: set[TaintLabel] = field(default_factory=set)
    ingress_context: str | None = None
    content_digest: str | None = None


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
        self._services = services
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
        self._approval_web = services.approval_web
        self._channels = services.channels
        self._matrix_channel = services.matrix_channel
        self._discord_channel = services.discord_channel
        self._telegram_channel = services.telegram_channel
        self._slack_channel = services.slack_channel
        self._credential_store = services.credential_store
        self._lockdown_manager = services.lockdown_manager
        self._rate_limiter = services.rate_limiter
        self._monitor = services.monitor
        self._risk_calibrator = services.risk_calibrator
        self._ingestion = services.ingestion
        self._memory_manager = services.memory_manager
        self._memory_ingress_registry = services.memory_ingress_registry
        self._conversation_summarizer = ConversationSummarizer(provider=services.provider)
        self._scheduler = services.scheduler
        self._skill_manager = services.skill_manager
        self._coding_manager = services.coding_manager
        self._selfmod_manager = services.selfmod_manager
        self._mcp_manager = services.mcp_manager
        self._msgvault_toolkit = services.msgvault_toolkit
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
        self._channel_proactive_last_sent_at: dict[str, datetime] = {}
        self._confirmation_warning_generator = ConfirmationWarningGenerator()
        self._confirmation_analytics = ConfirmationAnalytics()
        self._confirmation_alerted_at: dict[str, datetime] = {}
        self._pending_two_factor_enrollments: dict[str, object] = {}
        self._daemon_id = hashlib.sha256(
            str(self._config.data_dir.resolve()).encode("utf-8", errors="ignore")
        ).hexdigest()[:32]
        self._confirmation_backend_registry = ConfirmationBackendRegistry()
        self._confirmation_backend_registry.register(SoftwareConfirmationBackend())
        self._confirmation_backend_registry.register(
            TOTPBackend(credential_store=services.credential_store)
        )
        if self._approval_web.enabled:
            self._confirmation_backend_registry.register(
                WebAuthnBackend(
                    credential_store=services.credential_store,
                    approval_origin=self._config.approval_origin,
                    rp_id=self._config.approval_rp_id,
                )
            )
        else:
            self._confirmation_backend_registry.register(
                LocalFido2Backend(
                    credential_store=services.credential_store,
                    daemon_id=self._daemon_id,
                )
            )
        if self._config.signer_kms_url.strip():
            self._confirmation_backend_registry.register(
                SignerConfirmationAdapter(
                    EnterpriseKmsSignerBackend(
                        credential_store=services.credential_store,
                        endpoint_url=self._config.signer_kms_url,
                        bearer_token=self._config.signer_kms_bearer_token,
                    )
                )
            )
        if self._config.signer_ledger_url.strip():
            self._confirmation_backend_registry.register(
                SignerConfirmationAdapter(
                    LedgerSignerBackend(
                        credential_store=services.credential_store,
                        endpoint_url=self._config.signer_ledger_url,
                        bearer_token=self._config.signer_ledger_bearer_token,
                    )
                )
            )
        self._confirmation_failure_tracker = ConfirmationMethodLockoutTracker(
            state_path=self._config.data_dir / "confirmation_lockouts.json"
        )
        self._leak_detector = CrossThreadLeakDetector()
        self._reputation_scorer = ReputationScorer(submission_limit=20)
        self._dashboard = SecurityDashboard(
            audit_log=self._audit_log,
            marks_path=self._config.data_dir / "dashboard" / "false_positives.json",
        )
        web_allowed_domains = [item for item in self._config.web_allowed_domains if item.strip()]
        if not web_allowed_domains:
            web_allowed_domains = [
                rule.host.strip() for rule in self._policy_loader.policy.egress if rule.host.strip()
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
        browser_allowed_domains = [
            item for item in self._config.browser_allowed_domains if item.strip()
        ]
        if not browser_allowed_domains:
            browser_allowed_domains = list(web_allowed_domains)
        browser_toolkit_kwargs: dict[str, Any] = {
            "enabled": bool(self._config.browser_enabled),
            "command": self._config.browser_command,
            "session_root": self._config.data_dir / "browser",
            "allowed_domains": browser_allowed_domains,
            "timeout_seconds": self._config.browser_timeout_seconds,
            "require_hardened_isolation": bool(self._config.browser_require_hardened_isolation),
            "max_read_bytes": self._config.browser_max_read_bytes,
            "sandbox_runner": self._sandbox,
            "browser_sandbox": self._browser_sandbox,
        }
        self._browser_toolkit: Any
        if self._config.browser_enabled:
            from shisad.executors.browser import BrowserToolkit

            self._browser_toolkit = BrowserToolkit(**browser_toolkit_kwargs)
        else:
            self._browser_toolkit = _LazyBrowserToolkit(**browser_toolkit_kwargs)
        self._fs_git_toolkit = FsGitToolkit(
            roots=list(self._config.assistant_fs_roots),
            max_read_bytes=self._config.assistant_max_read_bytes,
            git_timeout_seconds=self._config.assistant_git_timeout_seconds,
            protected_write_paths=(
                (self._config.assistant_persona_soul_path,)
                if self._config.assistant_persona_soul_path is not None
                else ()
            ),
        )
        self._attachment_ingestor = AttachmentIngestor(
            roots=list(self._config.assistant_fs_roots),
            evidence_store=self._evidence_store,
            firewall=self._firewall,
            policy=AttachmentIngestPolicy(
                max_image_bytes=self._config.attachment_max_image_bytes,
                max_audio_bytes=self._config.attachment_max_audio_bytes,
                max_image_pixels=self._config.attachment_max_image_pixels,
                max_audio_duration_seconds=self._config.attachment_max_audio_duration_seconds,
                max_transcript_chars=self._config.attachment_max_transcript_chars,
            ),
        )
        self._load_pending_actions()
        self._approval_web.bind_callbacks(
            loop=asyncio.get_running_loop(),
            registration_context=self._webauthn_registration_ceremony_context,
            registration_complete=self._complete_webauthn_registration_ceremony,
            approval_context=self._webauthn_approval_ceremony_context,
            approval_complete=self._complete_webauthn_approval_ceremony,
        )

    def _with_tool_output_ingress(
        self,
        *,
        session: Session,
        tool_output: ToolOutputRecord | None,
    ) -> ToolOutputRecord | None:
        if tool_output is None:
            return None
        content = str(tool_output.content).strip()
        if not content:
            return tool_output

        source_origin: SourceOrigin = "tool_output"
        channel_trust: ChannelTrust = "tool_passed"
        source_id = f"{session.id}:{tool_output.tool_name}"
        if tool_output.tool_name == "web.fetch":
            source_origin = "external_web"
            channel_trust = "web_passed"
            try:
                payload = json.loads(content)
            except json.JSONDecodeError:
                payload = None
            if isinstance(payload, Mapping):
                source_id = str(payload.get("url", "")).strip() or source_id

        context = self._memory_ingress_registry.mint(
            source_origin=source_origin,
            channel_trust=channel_trust,
            confirmation_status="auto_accepted",
            scope="session",
            source_id=source_id,
            content=content,
            taint_labels=sorted(tool_output.taint_labels, key=lambda label: label.value),
        )
        return ToolOutputRecord(
            tool_name=tool_output.tool_name,
            content=tool_output.content,
            success=tool_output.success,
            taint_labels=set(tool_output.taint_labels),
            ingress_context=context.handle_id,
            content_digest=context.content_digest,
        )

    async def reset_test_state(self) -> dict[str, Any]:
        """Clear handler-owned mutable state in addition to service state."""
        if not self._config.test_mode:
            raise RuntimeError("daemon.reset is unavailable outside explicit test mode")
        async with self._services.rpc_state_lock:
            if self._services.reset_in_progress:
                raise RuntimeError("daemon.reset is already in progress")
            if self._services.active_rpc_calls > 1:
                raise RuntimeError("Cannot reset daemon while another control RPC is in flight")
            if len(getattr(self._services.embeddings_adapter, "_inflight", ())) > 0:
                raise RuntimeError("Cannot reset daemon while embeddings requests are in flight")
            self._services.reset_in_progress = True

        try:
            scheduler_pending = sum(
                len(rows) for rows in self._scheduler._pending_confirmations.values()
            )
            quiescent = not any(
                (
                    scheduler_pending,
                    len(self._pending_actions),
                    len(self._pending_by_session),
                    len(self._pending_two_factor_enrollments),
                    len(self._monitor_reject_counts),
                    len(self._plan_violation_counts),
                    len(self._confirmation_alerted_at),
                    len(self._identity_map._pairing_requests),
                    len(self._confirmation_failure_tracker._state),
                )
            )

            service_result = await self._services.reset_test_state()
            cleared = dict(service_result.get("cleared", {}))
            if "identity_pairing_requests" in cleared:
                cleared.setdefault("pairing_requests", int(cleared["identity_pairing_requests"]))
            cleared.update(self._clear_handler_test_state())
            invariants = self._reset_invariants()
            status = "reset" if all(invariants.values()) else "reset_failed"
            return {
                "status": status,
                "cleared": cleared,
                "quiescent": quiescent,
                "invariants": invariants,
            }
        finally:
            async with self._services.rpc_state_lock:
                self._services.reset_in_progress = False

    def _clear_handler_test_state(self) -> dict[str, int]:
        pairing_request_artifacts = int(self._pairing_requests_file.exists())
        cleared = {
            "pending_actions": len(self._pending_actions),
            "pending_action_sessions": len(self._pending_by_session),
            "monitor_reject_counts": len(self._monitor_reject_counts),
            "plan_violation_counts": len(self._plan_violation_counts),
            "confirmation_alerts": len(self._confirmation_alerted_at),
            "pending_two_factor_enrollments": len(self._pending_two_factor_enrollments),
            "confirmation_lockouts": len(self._confirmation_failure_tracker._state),
            "pairing_request_artifacts": pairing_request_artifacts,
        }
        self._pending_actions.clear()
        self._pending_by_session.clear()
        self._monitor_reject_counts.clear()
        self._plan_violation_counts.clear()
        self._confirmation_alerted_at.clear()
        self._pending_two_factor_enrollments.clear()
        self._confirmation_failure_tracker._state.clear()
        self._pending_actions_file.unlink(missing_ok=True)
        self._pairing_requests_file.unlink(missing_ok=True)
        lockout_state_path = self._confirmation_failure_tracker._state_path
        if lockout_state_path is not None:
            lockout_state_path.unlink(missing_ok=True)
        return cleared

    def _reset_invariants(self) -> dict[str, bool]:
        def _dir_empty(path: Path) -> bool:
            return (not path.exists()) or (not any(path.iterdir()))

        archive_dir = self._config.data_dir / "session_archives"
        trace_dir = self._config.data_dir / "traces"
        channel_state_root = self._services.channel_state_store._root_dir
        approval_store_path = self._credential_store._approval_store_path
        identity_allowlists_match = {
            channel: set(values) for channel, values in self._identity_map._allowlists.items()
        } == {
            channel: set(values)
            for channel, values in self._services.identity_allowlists_baseline.items()
        }
        return {
            "sessions_empty": not self._session_manager._sessions,
            "scheduler_empty": (
                not self._scheduler._tasks
                and not any(self._scheduler._pending_confirmations.values())
            ),
            "memory_empty": not self._memory_manager._entries,
            "lockdown_empty": not self._lockdown_manager._states,
            "rate_limiter_empty": not (
                self._rate_limiter._by_tool
                or self._rate_limiter._by_user
                or self._rate_limiter._by_session
                or self._rate_limiter._by_tool_burst
            ),
            "audit_empty": self._audit_log.entry_count == 0,
            "checkpoints_empty": not any(self._checkpoint_store._dir.iterdir()),
            "channel_state_empty": not (
                self._services.channel_state_store._seen_ids
                or self._services.channel_state_store._seen_id_sets
            ),
            "channel_state_disk_empty": _dir_empty(channel_state_root),
            "transcripts_empty": _dir_empty(self._transcript_store._transcript_dir),
            "transcript_blobs_empty": _dir_empty(self._transcript_store._blob_dir),
            "evidence_empty": not self._evidence_store._refs,
            "evidence_disk_empty": _dir_empty(self._evidence_store._blob_dir)
            and not self._evidence_store._metadata_path.exists()
            and _dir_empty(self._evidence_store._quarantine_dir),
            "ingestion_empty": self._ingestion.artifacts_empty(),
            "ingestion_artifacts_empty": self._ingestion.artifacts_empty(),
            "selfmod_empty": not self._selfmod_manager._inventory.skills
            and not self._selfmod_manager._inventory.behavior_packs,
            "selfmod_artifacts_empty": _dir_empty(self._selfmod_manager._proposal_dir)
            and _dir_empty(self._selfmod_manager._change_dir)
            and _dir_empty(self._selfmod_manager._artifact_root)
            and not self._selfmod_manager._inventory_path.exists()
            and not self._selfmod_manager._incident_path.exists(),
            "skills_empty": not self._skill_manager._inventory
            and not self._skill_manager._skill_tool_map
            and not self._skill_manager._pending_registration_events,
            "skill_storage_empty": _dir_empty(self._skill_manager._storage_dir),
            "trace_empty": not trace_dir.exists() or not any(trace_dir.iterdir()),
            "archives_empty": not archive_dir.exists() or not any(archive_dir.iterdir()),
            "approval_state_empty": not (
                self._credential_store._approval_factors or self._credential_store._signer_keys
            )
            and (
                approval_store_path is None
                or (
                    not approval_store_path.exists()
                    and not any(
                        approval_store_path.parent.glob(f"{approval_store_path.name}.corrupt.*")
                    )
                )
            ),
            "identity_runtime_empty": (
                not self._identity_map._map
                and not self._identity_map._pairing_requests
                and dict(self._identity_map._default_trust)
                == dict(self._services.identity_default_trust_baseline)
                and identity_allowlists_match
            ),
            "risk_files_empty": (
                not self._risk_calibrator.observations_path.exists()
                and not self._risk_calibrator.policy_path.exists()
            ),
            "handler_pending_empty": not (
                self._pending_actions
                or self._pending_by_session
                or self._pending_two_factor_enrollments
                or self._monitor_reject_counts
                or self._plan_violation_counts
                or self._confirmation_alerted_at
                or self._confirmation_failure_tracker._state
            )
            and not self._pending_actions_file.exists()
            and not self._pairing_requests_file.exists()
            and (
                self._confirmation_failure_tracker._state_path is None
                or not self._confirmation_failure_tracker._state_path.exists()
            ),
        }

    async def _prepare_browser_tool_arguments(
        self,
        *,
        session: Session,
        tool_name: ToolName,
        arguments: Mapping[str, Any],
    ) -> dict[str, Any]:
        tool_name_value = str(tool_name)
        if tool_name_value not in {"browser.navigate", "browser.click", "browser.type_text"}:
            return dict(arguments)
        return dict(
            await self._browser_toolkit.prepare_action_arguments(
                session=session,
                tool_name=tool_name_value,
                arguments=arguments,
            )
        )

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
        if last is not None and (now - last).total_seconds() < _CONFIRMATION_ALERT_COOLDOWN_SECONDS:
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
    def _approval_task_envelope_id_for_session(session: Session | None) -> str:
        if session is None:
            return ""
        raw_envelope = session.metadata.get("task_envelope")
        if not isinstance(raw_envelope, Mapping):
            return ""
        return str(raw_envelope.get("envelope_id", "")).strip()

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

    async def _observe_pep_reject_signal(
        self,
        *,
        sid: SessionId,
        tool_name: ToolName,
        action: ControlPlaneAction,
        final_kind: str,
        final_reason: str,
        pep_kind: str,
        pep_reason: str,
        pep_reason_code: str,
        source: str,
        trace_only_stage2_confirmation: bool = False,
    ) -> None:
        if pep_kind != "reject":
            return
        if trace_only_stage2_confirmation:
            if final_kind != "require_confirmation":
                return
        else:
            if final_kind != "reject":
                return
            normalized_final_reason = final_reason.strip()
            normalized_pep_reason = pep_reason.strip()
            if normalized_final_reason not in {normalized_pep_reason, "pep_reject"}:
                return
        try:
            findings = await _call_control_plane(
                self,
                "observe_denied_action",
                action=action,
                source=source,
                reason_code=pep_reason_code,
            )
        except (ControlPlaneRpcError, ControlPlaneUnavailableError) as exc:
            logger.warning(
                "Denied-action observation unavailable; continuing without H3 warning "
                "(session_id=%s tool_name=%s reason_code=%s)",
                sid,
                tool_name,
                getattr(exc, "reason_code", "control_plane.unavailable"),
            )
            return
        for finding in findings:
            await self._event_bus.publish(
                AnomalyReported(
                    session_id=sid,
                    actor="control_plane",
                    severity="warning",
                    description=(
                        "Repeated denied action pattern detected: "
                        f"{getattr(finding, 'pattern_name', 'phantom_action')}"
                    ),
                    recommended_action="review recent denied-action audit events",
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
                sandbox_result = sandbox_result.model_copy(update={"checkpoint_id": checkpoint_id})
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

    @staticmethod
    def _transcript_entry_has_firewall_risk(entry: Any) -> bool:
        metadata = getattr(entry, "metadata", {})
        if not isinstance(metadata, Mapping):
            return False
        for key in (
            "firewall_risk_factors",
            "firewall_secret_findings",
            "firewall_decode_reason_codes",
        ):
            value = metadata.get(key)
            if isinstance(value, list) and value:
                return True
        return False

    def _session_has_tainted_history(self, session_id: SessionId) -> bool:
        return any(
            entry.taint_labels or HandlerImplementation._transcript_entry_has_firewall_risk(entry)
            for entry in self._transcript_store.list_entries(session_id)
        )

    def _session_has_tainted_user_history(self, session_id: SessionId) -> bool:
        return any(
            entry.taint_labels or HandlerImplementation._transcript_entry_has_firewall_risk(entry)
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
            str(raw.get("reason", "identity_not_allowlisted")).strip() or "identity_not_allowlisted"
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
            "delivery_target": (
                pending.delivery_target.model_dump(mode="json")
                if pending.delivery_target is not None
                else None
            ),
            "execute_after": pending.execute_after.isoformat() if pending.execute_after else "",
            "safe_preview": pending.safe_preview,
            "warnings": list(pending.warnings),
            "leak_check": dict(pending.leak_check),
            "approval_task_envelope_id": pending.approval_task_envelope_id,
            "required_level": pending.required_level.value,
            "required_methods": list(pending.required_methods),
            "allowed_principals": list(pending.allowed_principals),
            "allowed_credentials": list(pending.allowed_credentials),
            "required_capabilities": pending.required_capabilities.model_dump(mode="json"),
            "approval_envelope_hash": pending.approval_envelope_hash,
            "fallback": pending.fallback.model_dump(mode="json"),
            "expires_at": pending.expires_at.isoformat() if pending.expires_at else "",
            "selected_backend_id": pending.selected_backend_id,
            "selected_backend_method": pending.selected_backend_method,
            "fallback_used": bool(pending.fallback_used),
            "strip_direct_tool_execute_envelope_keys": bool(
                pending.strip_direct_tool_execute_envelope_keys
            ),
            "status": pending.status,
            "status_reason": pending.status_reason,
        }
        if pending.preflight_action is not None:
            payload["preflight_action"] = pending.preflight_action.model_dump(mode="json")
        if pending.merged_policy is not None:
            payload["merged_policy"] = pending.merged_policy.model_dump(mode="json")
        if pending.pep_context is not None:
            payload["pep_context"] = pending_pep_context_to_payload(pending.pep_context)
        if pending.pep_elevation is not None:
            payload["pep_elevation"] = pending_pep_elevation_to_payload(pending.pep_elevation)
        if pending.approval_envelope is not None:
            payload["approval_envelope"] = pending.approval_envelope.model_dump(mode="json")
        if pending.intent_envelope is not None:
            payload["intent_envelope"] = pending.intent_envelope.model_dump(mode="json")
        if pending.confirmation_evidence is not None:
            payload["confirmation_evidence"] = pending.confirmation_evidence.model_dump(mode="json")
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
        delivery_target: DeliveryTarget | None = None,
        task_id: str = "",
        preflight_action: ControlPlaneAction | None = None,
        merged_policy: ToolExecutionPolicy | None = None,
        taint_labels: list[TaintLabel] | None = None,
        extra_warnings: list[str] | None = None,
        pep_context: PendingPepContextSnapshot | None = None,
        pep_elevation: PendingPepElevationRequest | None = None,
        confirmation_requirement: ConfirmationRequirement | None = None,
        strip_direct_tool_execute_envelope_keys: bool = False,
    ) -> PendingAction:
        created_at = datetime.now(UTC)
        decision_nonce = uuid.uuid4().hex
        confirmation_id = uuid.uuid4().hex
        requirement = (
            confirmation_requirement.model_copy(deep=True)
            if confirmation_requirement is not None
            else legacy_software_confirmation_requirement()
        )
        if not requirement.routeable:
            raise ApprovalRoutingError(
                requirement.route_reason or "confirmation_requirement_conflict"
            )
        backend_resolution = self._confirmation_backend_registry.resolve(
            requirement,
            user_id=str(user_id),
        )
        if backend_resolution is None:
            raise ApprovalRoutingError("confirmation_backend_unavailable")
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
        elevation_warning = pending_pep_elevation_warning(pep_elevation)
        if elevation_warning:
            warnings.append(elevation_warning)
        if requirement.level != ConfirmationLevel.SOFTWARE:
            warnings.append(f"Required approval level: {requirement.level.value}")
        if backend_resolution.fallback_used:
            warnings.append(
                "Approval fallback engaged: "
                f"{backend_resolution.backend.method}/{backend_resolution.backend.level.value}"
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
                    str(item) for item in arguments.get("source_ids", []) if str(item).strip()
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
        expires_at = (
            created_at + timedelta(seconds=int(requirement.timeout_seconds))
            if requirement.timeout_seconds is not None
            else None
        )
        session = self._session_manager.get(session_id)
        normalized_arguments = pep_arguments_for_policy_evaluation(tool_name, arguments)
        tool_definition = self._registry.get_tool(tool_name)
        resolved_destinations = resolve_confirmation_destinations(
            tool_definition=tool_definition
            or ToolDefinition(
                name=tool_name,
                description="",
                parameters=[],
                capabilities_required=[],
            ),
            arguments=normalized_arguments,
        )
        action_digest = compute_action_digest(
            tool_definition=tool_definition
            or ToolDefinition(
                name=tool_name,
                description="",
                parameters=[],
                capabilities_required=[],
            ),
            arguments=normalized_arguments,
            destinations=resolved_destinations,
        )
        action_summary = f"{summary.action}: " + ", ".join(
            f"{key}={value}" for key, value in summary.parameters[:6]
        )
        intent_envelope: IntentEnvelope | None = None
        intent_hash: str | None = None
        if (
            requirement.level.priority >= ConfirmationLevel.SIGNED_AUTHORIZATION.priority
            or requirement.require_capabilities.full_intent_signature
        ):
            intent_envelope = IntentEnvelope(
                intent_id=confirmation_id,
                agent_id=self._daemon_id,
                workspace_id=str(workspace_id),
                session_id=str(session_id),
                created_at=created_at,
                expires_at=expires_at,
                action=IntentAction(
                    tool=str(tool_name),
                    display_summary=action_summary.strip(),
                    parameters=dict(normalized_arguments),
                    destinations=list(resolved_destinations),
                ),
                policy_context=IntentPolicyContext(
                    required_level=requirement.level,
                    confirmation_reason=reason,
                    matched_rule=str(tool_name),
                    action_digest=action_digest,
                ),
                nonce=new_approval_nonce(),
            )
            intent_hash = intent_envelope_hash(intent_envelope)
        approval_envelope = ApprovalEnvelope(
            approval_id=confirmation_id,
            pending_action_id=confirmation_id,
            workspace_id=str(workspace_id),
            daemon_id=self._daemon_id,
            session_id=str(session_id),
            required_level=requirement.level,
            policy_reason=reason,
            action_digest=action_digest,
            allowed_principals=list(requirement.allowed_principals),
            allowed_credentials=list(requirement.allowed_credentials),
            expires_at=expires_at,
            nonce=new_approval_nonce(),
            intent_envelope_hash=intent_hash,
            action_summary=action_summary.strip(),
        )
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
            delivery_target=delivery_target.model_copy(deep=True)
            if delivery_target is not None
            else None,
            preflight_action=preflight_action,
            execute_after=execute_after,
            safe_preview=render_structured_confirmation(summary, warnings=sorted(set(warnings))),
            warnings=sorted(set(warnings)),
            leak_check=leak_result_payload,
            merged_policy=(
                merged_policy.model_copy(deep=True) if merged_policy is not None else None
            ),
            approval_task_envelope_id=HandlerImplementation._approval_task_envelope_id_for_session(
                session
            ),
            pep_context=(
                PendingPepContextSnapshot(
                    capabilities=set(pep_context.capabilities),
                    taint_labels=set(pep_context.taint_labels),
                    user_goal_host_patterns=set(pep_context.user_goal_host_patterns),
                    untrusted_host_patterns=set(pep_context.untrusted_host_patterns),
                    tool_allowlist=(
                        set(pep_context.tool_allowlist)
                        if pep_context.tool_allowlist is not None
                        else None
                    ),
                    trust_level=pep_context.trust_level,
                    credential_refs=set(pep_context.credential_refs),
                    enforce_explicit_credential_refs=bool(
                        pep_context.enforce_explicit_credential_refs
                    ),
                    filesystem_roots=tuple(str(root) for root in pep_context.filesystem_roots),
                )
                if pep_context is not None
                else None
            ),
            pep_elevation=(
                PendingPepElevationRequest(
                    kind=pep_elevation.kind,
                    reason_code=pep_elevation.reason_code,
                    capability_grants=set(pep_elevation.capability_grants),
                )
                if pep_elevation is not None
                else None
            ),
            required_level=requirement.level,
            required_methods=list(requirement.methods),
            allowed_principals=list(requirement.allowed_principals),
            allowed_credentials=list(requirement.allowed_credentials),
            required_capabilities=requirement.require_capabilities.model_copy(deep=True),
            approval_envelope=approval_envelope,
            approval_envelope_hash=approval_envelope_hash(approval_envelope),
            intent_envelope=intent_envelope,
            fallback=requirement.fallback.model_copy(deep=True),
            expires_at=expires_at,
            selected_backend_id=str(backend_resolution.backend.backend_id),
            selected_backend_method=str(backend_resolution.backend.method),
            fallback_used=bool(backend_resolution.fallback_used),
            strip_direct_tool_execute_envelope_keys=bool(strip_direct_tool_execute_envelope_keys),
        )
        self._pending_actions[confirmation_id] = pending
        self._pending_by_session.setdefault(session_id, []).append(confirmation_id)
        self._persist_pending_actions()
        return pending

    def _persist_pending_actions(self) -> None:
        payload = [self._pending_to_dict(item) for item in self._pending_actions.values()]
        self._pending_actions_file.parent.mkdir(parents=True, exist_ok=True)
        with contextlib.suppress(OSError):
            self._pending_actions_file.parent.chmod(0o700)
        self._pending_actions_file.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        with contextlib.suppress(OSError):
            self._pending_actions_file.chmod(0o600)

    def _load_pending_actions(self) -> None:
        if not self._pending_actions_file.exists():
            return
        try:
            raw = json.loads(self._pending_actions_file.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return
        if not isinstance(raw, list):
            return
        pruned_stale = False
        migrated_legacy_strip_intent = False
        for item in raw:
            if not isinstance(item, dict):
                continue
            try:
                confirmation_id = str(item.get("confirmation_id", "")).strip()
                if not confirmation_id:
                    continue
                created_at = datetime.fromisoformat(str(item.get("created_at", "")).strip())
                session_id = SessionId(str(item.get("session_id", "")))
                delivery_target_payload = item.get("delivery_target")
                delivery_target = (
                    DeliveryTarget.model_validate(delivery_target_payload)
                    if isinstance(delivery_target_payload, Mapping)
                    else None
                )
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
                expires_at_raw = str(item.get("expires_at", "")).strip()
                expires_at = datetime.fromisoformat(expires_at_raw) if expires_at_raw else None
                pep_context_payload = item.get("pep_context")
                pep_context = (
                    pending_pep_context_from_payload(pep_context_payload)
                    if isinstance(pep_context_payload, Mapping)
                    else None
                )
                pep_elevation_payload = item.get("pep_elevation")
                pep_elevation = (
                    pending_pep_elevation_from_payload(pep_elevation_payload)
                    if isinstance(pep_elevation_payload, Mapping)
                    else None
                )
                approval_envelope_payload = item.get("approval_envelope")
                approval_envelope = (
                    ApprovalEnvelope.model_validate(approval_envelope_payload)
                    if isinstance(approval_envelope_payload, Mapping)
                    else None
                )
                intent_envelope_payload = item.get("intent_envelope")
                intent_envelope = (
                    IntentEnvelope.model_validate(intent_envelope_payload)
                    if isinstance(intent_envelope_payload, Mapping)
                    else None
                )
                confirmation_evidence_payload = item.get("confirmation_evidence")
                confirmation_evidence = (
                    ConfirmationEvidence.model_validate(confirmation_evidence_payload)
                    if isinstance(confirmation_evidence_payload, Mapping)
                    else None
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
                        Capability(str(cap)) for cap in item.get("capabilities", []) if str(cap)
                    },
                    created_at=created_at,
                    delivery_target=delivery_target,
                    preflight_action=preflight_action,
                    execute_after=execute_after,
                    safe_preview=str(item.get("safe_preview", "")),
                    warnings=[str(value) for value in item.get("warnings", [])],
                    leak_check=dict(item.get("leak_check", {})),
                    merged_policy=merged_policy,
                    approval_task_envelope_id=str(
                        item.get("approval_task_envelope_id", "")
                    ).strip(),
                    pep_context=pep_context,
                    pep_elevation=pep_elevation,
                    required_level=ConfirmationLevel(
                        str(item.get("required_level", ConfirmationLevel.SOFTWARE.value))
                    ),
                    required_methods=[
                        str(value).strip()
                        for value in item.get("required_methods", [])
                        if str(value).strip()
                    ],
                    allowed_principals=[
                        str(value).strip()
                        for value in item.get("allowed_principals", [])
                        if str(value).strip()
                    ],
                    allowed_credentials=[
                        str(value).strip()
                        for value in item.get("allowed_credentials", [])
                        if str(value).strip()
                    ],
                    required_capabilities=ConfirmationCapabilities.model_validate(
                        item.get("required_capabilities", {})
                    ),
                    approval_envelope=approval_envelope,
                    approval_envelope_hash=str(item.get("approval_envelope_hash", "")).strip(),
                    intent_envelope=intent_envelope,
                    confirmation_evidence=confirmation_evidence,
                    fallback=ConfirmationFallbackPolicy.model_validate(item.get("fallback", {})),
                    expires_at=expires_at,
                    selected_backend_id=(
                        str(item.get("selected_backend_id", "")).strip() or "software.default"
                    ),
                    selected_backend_method=(
                        str(item.get("selected_backend_method", "")).strip() or "software"
                    ),
                    fallback_used=bool(item.get("fallback_used", False)),
                    strip_direct_tool_execute_envelope_keys=bool(
                        item.get("strip_direct_tool_execute_envelope_keys", False)
                    ),
                    status=str(item.get("status", "pending")),
                    status_reason=str(item.get("status_reason", "")),
                )
            except (TypeError, ValueError, ValidationError):
                continue
            if (
                not pending.strip_direct_tool_execute_envelope_keys
                and pending.should_strip_direct_tool_execute_envelope_keys()
            ):
                pending.strip_direct_tool_execute_envelope_keys = True
                migrated_legacy_strip_intent = True
            self._pending_actions[pending.confirmation_id] = pending
            self._pending_by_session.setdefault(
                pending.session_id,
                [],
            ).append(pending.confirmation_id)
            stale_reason = self._stale_pending_action_reason(pending)
            if stale_reason:
                self._mark_stale_pending_action(
                    pending,
                    reason=stale_reason,
                    persist=False,
                )
                pruned_stale = True
        if pruned_stale or migrated_legacy_strip_intent:
            self._persist_pending_actions()

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
        approval_confirmation_id: str = "",
        approval_decision_nonce: str = "",
        approval_task_envelope_id: str = "",
        approval_timestamp: str = "",
        approval_evidence: ConfirmationEvidence | None = None,
        strip_direct_tool_execute_envelope_keys: bool = False,
        memory_ingress_context: IngressContext | None = None,
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
            workspace_roots=list(
                getattr(getattr(self, "_config", None), "assistant_fs_roots", [Path.cwd()])
            ),
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

        approval_event_fields = {
            "approval_session_id": str(sid),
            "approval_task_envelope_id": (
                approval_task_envelope_id
                or HandlerImplementation._approval_task_envelope_id_for_session(session)
            ),
            "approval_confirmation_id": approval_confirmation_id,
            "approval_decision_nonce": approval_decision_nonce,
            "approval_timestamp": approval_timestamp or datetime.now(UTC).isoformat(),
            **approval_audit_fields(approval_evidence),
        }

        await self._event_bus.publish(
            ToolApproved(
                session_id=sid,
                actor=approval_actor,
                tool_name=tool_name,
                **approval_event_fields,
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
                    **approval_event_fields,
                )
            )
            await _call_control_plane(
                self,
                "record_execution",
                action=executed_action,
                success=True,
            )
            return ApprovedToolExecutionResult(
                success=True,
                checkpoint_id=checkpoint_id,
                tool_output=HandlerImplementation._with_tool_output_ingress(
                    self,
                    session=session,
                    tool_output=ToolOutputRecord(
                        tool_name=str(tool_name),
                        content="Anomaly reported and lockdown evaluation triggered.",
                        taint_labels=set(),
                    ),
                ),
            )

        if tool_name == "retrieve_rag":
            pack = self._ingestion.compile_recall(
                query=str(arguments.get("query", "")),
                limit=int(arguments.get("limit", 5)),
                capabilities=capabilities,
            )
            self._ingestion.record_citations(pack.citation_ids)
            records = pack.results
            await self._event_bus.publish(
                ToolExecuted(
                    session_id=sid,
                    actor="tool_runtime",
                    tool_name=tool_name,
                    success=True,
                    **approval_event_fields,
                )
            )
            await _call_control_plane(
                self,
                "record_execution",
                action=executed_action,
                success=True,
            )
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
                tool_output=HandlerImplementation._with_tool_output_ingress(
                    self,
                    session=session,
                    tool_output=ToolOutputRecord(
                        tool_name=str(tool_name),
                        content=self._sanitize_tool_output_text(
                            json.dumps(preview_rows, ensure_ascii=True)
                        ),
                        taint_labels=retrieval_taints,
                    ),
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
                            **approval_event_fields,
                        )
                    )
                    await self._event_bus.publish(
                        ToolExecuted(
                            session_id=sid,
                            actor="tool_runtime",
                            tool_name=tool_name,
                            success=False,
                            **approval_event_fields,
                        )
                    )
                    await _call_control_plane(
                        self,
                        "record_execution",
                        action=executed_action,
                        success=False,
                    )
                    return ApprovedToolExecutionResult(
                        success=False,
                        checkpoint_id=checkpoint_id,
                        tool_output=HandlerImplementation._with_tool_output_ingress(
                            self,
                            session=session,
                            tool_output=ToolOutputRecord(
                                tool_name=str(tool_name),
                                content=self._sanitize_tool_output_text(
                                    json.dumps(delivery_payload, ensure_ascii=True)
                                ),
                                success=False,
                                taint_labels=set(),
                            ),
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
                        **approval_event_fields,
                    )
                )
                await _call_control_plane(
                    self,
                    "record_execution",
                    action=executed_action,
                    success=True,
                )
                return ApprovedToolExecutionResult(
                    success=True,
                    checkpoint_id=checkpoint_id,
                    tool_output=HandlerImplementation._with_tool_output_ingress(
                        self,
                        session=session,
                        tool_output=ToolOutputRecord(
                            tool_name=str(tool_name),
                            content=self._sanitize_tool_output_text(
                                json.dumps(delivery_payload, ensure_ascii=True)
                            ),
                            success=True,
                            taint_labels=set(),
                        ),
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
                        **approval_event_fields,
                    )
                )
            await self._event_bus.publish(
                ToolExecuted(
                    session_id=sid,
                    actor="tool_runtime",
                    tool_name=tool_name,
                    success=success,
                    **approval_event_fields,
                )
            )
            await _call_control_plane(
                self,
                "record_execution",
                action=executed_action,
                success=success,
            )
            return ApprovedToolExecutionResult(
                success=success,
                checkpoint_id=checkpoint_id,
                tool_output=HandlerImplementation._with_tool_output_ingress(
                    self,
                    session=session,
                    tool_output=ToolOutputRecord(
                        tool_name=str(tool_name),
                        content=self._sanitize_tool_output_text(
                            json.dumps(delivery_payload, ensure_ascii=True)
                        ),
                        success=success,
                        taint_labels=set(),
                    ),
                ),
            )

        async def _record_execution(success: bool) -> None:
            await _call_control_plane(
                self,
                "record_execution",
                action=executed_action,
                success=success,
            )

        async def _execute_structured_payload_tool(
            payload: Mapping[str, Any],
            *,
            default_error: str,
        ) -> ApprovedToolExecutionResult:
            execution_taints = label_tool_output(str(tool_name))
            sanitize_output = self._sanitize_tool_output_text
            if TaintLabel.MCP_EXTERNAL in execution_taints:
                sanitize_output = self._sanitize_untrusted_tool_output_text
            result = await execute_structured_tool(
                session_id=sid,
                tool_name=tool_name,
                payload=payload,
                default_error=default_error,
                actor="tool_runtime",
                emit_event=self._event_bus.publish,
                record_execution=_record_execution,
                sanitize_output=sanitize_output,
                taint_labels=execution_taints,
                approval_event_fields=approval_event_fields,
            )
            return ApprovedToolExecutionResult(
                success=result.success,
                checkpoint_id=checkpoint_id,
                tool_output=HandlerImplementation._with_tool_output_ingress(
                    self,
                    session=session,
                    tool_output=ToolOutputRecord(
                        tool_name=str(tool_name),
                        content=result.content,
                        success=result.success,
                        taint_labels=result.taint_labels,
                    ),
                ),
            )

        structured_handler = HandlerImplementation._structured_tool_registry().get(str(tool_name))
        if structured_handler is not None:
            payload_builder, default_error = structured_handler
            structured_context = StructuredToolContext(
                session_id=sid,
                user_id=user_id,
                workspace_id=session.workspace_id,
                session=session,
                user_confirmed=user_confirmed,
                memory_ingress_context=memory_ingress_context,
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

        if tool is not None and str(getattr(tool, "registration_source", "")).strip() == "mcp":
            server_name = str(getattr(tool, "registration_source_id", "")).strip()
            upstream_tool_name = str(getattr(tool, "upstream_tool_name", "")).strip()
            mcp_arguments = _tool_execute_runtime_arguments(
                tool,
                arguments,
                strip_direct_tool_execute_envelope_keys=strip_direct_tool_execute_envelope_keys,
            )
            validation_errors = self._registry.validate_call(tool_name, mcp_arguments)
            if validation_errors:
                return await _execute_structured_payload_tool(
                    {
                        "ok": False,
                        "error": (
                            "invalid_tool_arguments:schema validation failed: "
                            + "; ".join(validation_errors)
                        ),
                    },
                    default_error="invalid_tool_arguments",
                )
            mcp_payload: Mapping[str, Any]
            mcp_manager = getattr(self, "_mcp_manager", None)
            if mcp_manager is None or not server_name or not upstream_tool_name:
                mcp_payload = {"ok": False, "error": "mcp_tool_unavailable"}
            else:
                try:
                    mcp_payload = await mcp_manager.call_tool(
                        server_name=server_name,
                        tool_name=upstream_tool_name,
                        arguments=mcp_arguments,
                    )
                except Exception as exc:
                    logger.exception(
                        "MCP tool execution failed: server=%s upstream_tool=%s error=%s",
                        server_name,
                        upstream_tool_name,
                        exc,
                    )
                    mcp_payload = {"ok": False, "error": str(exc).strip() or "mcp_tool_failed"}
            return await _execute_structured_payload_tool(
                mcp_payload,
                default_error="mcp_tool_failed",
            )

        if tool is None:
            await self._event_bus.publish(
                ToolExecuted(
                    session_id=sid,
                    actor="tool_runtime",
                    tool_name=tool_name,
                    success=False,
                    **approval_event_fields,
                )
            )
            await _call_control_plane(
                self,
                "record_execution",
                action=executed_action,
                success=False,
            )
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
                    **approval_event_fields,
                )
            )
        await self._event_bus.publish(
            ToolExecuted(
                session_id=sid,
                actor="sandbox",
                tool_name=tool_name,
                success=success,
                **approval_event_fields,
            )
        )
        await _call_control_plane(
            self,
            "record_execution",
            action=executed_action,
            success=success,
        )
        raw_output = "\n".join(
            segment for segment in [sandbox_result.stdout, sandbox_result.stderr] if segment
        ).strip()
        return ApprovedToolExecutionResult(
            success=success,
            checkpoint_id=checkpoint_id,
            tool_output=HandlerImplementation._with_tool_output_ingress(
                self,
                session=session,
                tool_output=ToolOutputRecord(
                    tool_name=str(tool_name),
                    content=self._sanitize_tool_output_text(raw_output),
                    success=success,
                    taint_labels=label_tool_output(str(tool_name)),
                ),
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
            "browser.navigate": (_structured_browser_navigate, "browser_navigate_failed"),
            "browser.read_page": (_structured_browser_read_page, "browser_read_page_failed"),
            "browser.screenshot": (_structured_browser_screenshot, "browser_screenshot_failed"),
            "browser.click": (_structured_browser_click, "browser_click_failed"),
            "browser.type_text": (_structured_browser_type_text, "browser_type_text_failed"),
            "browser.end_session": (
                _structured_browser_end_session,
                "browser_end_session_failed",
            ),
            "realitycheck.search": (
                _structured_realitycheck_search,
                "realitycheck_search_failed",
            ),
            "realitycheck.read": (_structured_realitycheck_read, "realitycheck_read_failed"),
            "attachment.ingest": (_structured_attachment_ingest, "attachment_ingest_failed"),
            "email.search": (_structured_email_search, "email_search_failed"),
            "email.read": (_structured_email_read, "email_read_failed"),
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

    def _sanitize_untrusted_tool_output_text(self, raw: str) -> str:
        if not raw:
            return ""
        firewall = getattr(self, "_firewall", None)
        if firewall is not None:
            inspect = getattr(firewall, "inspect", None)
            if callable(inspect):
                raw = str(inspect(raw).sanitized_text)
        return self._sanitize_tool_output_text(raw)

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
            await _call_control_plane(
                self,
                "observe_runtime_network",
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
