"""Control API handler bundle for daemon runtime."""

from __future__ import annotations

import asyncio
import base64
import binascii
import hashlib
import inspect
import json
import logging
import math
import os
import re
import uuid
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta
from functools import lru_cache
from pathlib import Path
from time import monotonic as _monotonic
from time import sleep as _sleep
from typing import TYPE_CHECKING, Any, cast

from pydantic import ValidationError

from shisad.assistant.fs_git import FsGitToolkit
from shisad.assistant.web import WebToolkit
from shisad.channels.base import DeliveryTarget
from shisad.core.action_state import (
    CURRENT_TURN_REMINDER_CREATE_INTENT,
    ReminderStatusView,
    derive_action_followup_id,
    derive_legacy_action_id,
    mint_action_operation_identity,
    parse_reminder_relative_duration,
    reminder_status_view_for_task,
    select_reminder_status_view,
)
from shisad.core.approval import (
    ApprovalEnvelope,
    ApprovalRoutingError,
    ConfirmationBackendRegistry,
    ConfirmationCapabilities,
    ConfirmationEvidence,
    ConfirmationEvidenceAuthenticator,
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
    ResolvedConfirmationBackend,
    SignerConfirmationAdapter,
    SoftwareConfirmationBackend,
    TOTPBackend,
    WebAuthnBackend,
    approval_audit_fields,
    approval_envelope_hash,
    compute_action_digest,
    confirmation_backend_satisfies_constraints,
    confirmation_evidence_satisfies_requirement,
    effective_pending_action_ttl_seconds,
    intent_envelope_hash,
    legacy_software_confirmation_requirement,
    new_approval_nonce,
    resolve_confirmation_destinations,
    safe_compare_sha256,
)
from shisad.core.atomic_state import (
    AtomicWriteError,
    StatePersistenceDegradedError,
    atomic_write_bytes,
    durable_append_bytes,
)
from shisad.core.attachments import AttachmentIngestor, AttachmentIngestPolicy
from shisad.core.clock import current_time_payload
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
from shisad.core.plan_steps import PlanStepStore
from shisad.core.session import Session
from shisad.core.session_archive import SessionArchiveManager
from shisad.core.tools.builtin.alarm import AnomalyReportInput
from shisad.core.tools.names import canonical_tool_name
from shisad.core.tools.schema import (
    StableIdempotencyAdapter,
    ToolDefinition,
    ToolRetryClass,
    ToolRetryDescriptor,
)
from shisad.core.types import (
    Capability,
    EventId,
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
from shisad.daemon.handlers._impl_plan_steps import PlanStepsImplMixin
from shisad.daemon.handlers._impl_session import (
    SessionImplMixin,
    _browser_runtime_unavailable_rejection_reason,
)
from shisad.daemon.handlers._impl_skills import SkillsImplMixin
from shisad.daemon.handlers._impl_tasks import TasksImplMixin
from shisad.daemon.handlers._impl_tool_execution import (
    ToolExecutionImplMixin,
    _tool_execute_runtime_arguments,
)
from shisad.daemon.handlers._mixin_typing import (
    call_control_plane as _call_control_plane,
)
from shisad.daemon.handlers._pending_approval import (
    PendingPepContextSnapshot,
    PendingPepElevationRequest,
    build_policy_context_for_pending_action,
    pending_action_event_identity_fields,
    pending_action_state_view,
    pending_approval_contract_hash,
    pending_approval_parent_contract_hash,
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
from shisad.memory.context_defaults import resolve_active_attention_defaults
from shisad.memory.ingress import IngressContext
from shisad.memory.remap import digest_memory_value
from shisad.memory.sqlite_diagnostics import sqlite_runtime_status
from shisad.memory.summarizer import ConversationSummarizer
from shisad.memory.trust import ChannelTrust, SourceOrigin
from shisad.scheduler.rendering import task_schedule_rendering
from shisad.security.control_plane.engine import ControlPlaneEvaluation
from shisad.security.control_plane.schema import (
    ActionKind,
    ControlDecision,
    ControlPlaneAction,
    Origin,
    RiskTier,
    build_action,
    control_plane_execution_idempotency_key,
    extract_request_size_bytes,
    infer_action_kind,
)
from shisad.security.control_plane.sidecar import (
    ControlPlaneRpcError,
    ControlPlaneUnavailableError,
)
from shisad.security.leakcheck import CrossThreadLeakDetector
from shisad.security.pep import PolicyContext
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
_GH12_READ_ONLY_SHELL_COMMANDS = frozenset({"fd", "find", "grep", "ls", "rg"})
_AUTO_RECOVERY_STARTUP_BACKOFF_SECONDS = 0.05
_SENSITIVE_PENDING_TEXT_REDACTION = "[sensitive text redacted]"
_PENDING_ACTION_STORED_STATUSES = frozenset(
    {
        "pending",
        "executing",
        "approved",
        "failed",
        "rejected",
        "cancelled",
        "superseded",
        "outcome_unknown",
    }
)
_SCHEDULER_ACCOUNTING_MODES = frozenset({"", "failure", "shadow_only", "ambiguous"})
_EXECUTION_AUTHORIZATION_KINDS = frozenset({"", "policy_allow"})
_INTERNAL_PENDING_ARGUMENT_KEYS_BY_ACTION: dict[str, frozenset[str]] = {
    "shell.exec": frozenset({"command_intent"}),
    "reminder.create": frozenset({"reminder_intent"}),
}


def _has_sensitive_pending_text(tool_name: ToolName | str, arguments: Mapping[str, Any]) -> bool:
    return (
        canonical_tool_name(str(tool_name), warn_on_alias=False) == "browser.type_text"
        and bool(arguments.get("is_sensitive", False))
        and ("text" in arguments or "description" in arguments)
    )


def _pending_payload_session(item: Mapping[str, Any]) -> str:
    return str(item.get("session_id", "")).strip()


def _pending_payload_group(item: Mapping[str, Any]) -> tuple[str, str] | None:
    task_id = str(item.get("task_id", "")).strip()
    if not task_id:
        return None
    session_id = str(item.get("session_id", "")).strip()
    if not session_id:
        return None
    return (session_id, task_id)


def _loaded_state_mapping(value: Any) -> tuple[dict[str, Any], bool]:
    if isinstance(value, Mapping):
        return dict(value), True
    return {}, False


def _require_native_json_payload(value: Any) -> None:
    """Reject values that require Python-specific normalization before JSON."""

    def _validate(candidate: Any) -> None:
        if candidate is None or isinstance(candidate, (bool, int)):
            return
        if isinstance(candidate, float):
            if not math.isfinite(candidate):
                raise ValueError("non-finite floats are not valid JSON")
            return
        if isinstance(candidate, str):
            candidate.encode("utf-8")
            return
        if isinstance(candidate, list):
            for item in candidate:
                _validate(item)
            return
        if isinstance(candidate, dict):
            for key, item in candidate.items():
                if not isinstance(key, str):
                    raise TypeError("JSON object keys must be strings")
                key.encode("utf-8")
                _validate(item)
            return
        raise TypeError(f"{type(candidate).__name__} is not a native JSON value")

    _validate(value)
    json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _native_json_payload_is_valid(value: Any) -> bool:
    try:
        _require_native_json_payload(value)
    except (TypeError, ValueError, UnicodeEncodeError):
        return False
    return True


def _sanitize_loaded_json_payload(value: Any) -> tuple[Any, bool]:
    """Return a native-JSON-safe loaded value plus whether it was unchanged."""

    if value is None or isinstance(value, (bool, int)):
        return value, True
    if isinstance(value, float):
        return (value, True) if math.isfinite(value) else (None, False)
    if isinstance(value, str):
        try:
            value.encode("utf-8")
        except UnicodeEncodeError:
            return "", False
        return value, True
    if isinstance(value, list):
        sanitized_items: list[Any] = []
        valid = True
        for item in value:
            sanitized, item_valid = _sanitize_loaded_json_payload(item)
            sanitized_items.append(sanitized)
            valid = valid and item_valid
        return sanitized_items, valid
    if isinstance(value, dict):
        sanitized_mapping: dict[str, Any] = {}
        valid = True
        for key, item in value.items():
            if not isinstance(key, str):
                valid = False
                continue
            try:
                key.encode("utf-8")
            except UnicodeEncodeError:
                valid = False
                continue
            sanitized, item_valid = _sanitize_loaded_json_payload(item)
            sanitized_mapping[key] = sanitized
            valid = valid and item_valid
        return sanitized_mapping, valid
    return None, False


def _loaded_state_optional_mapping(
    value: Any,
) -> tuple[dict[str, Any] | None, bool]:
    if value is None:
        return None, True
    if isinstance(value, Mapping):
        return dict(value), True
    return None, False


def _loaded_state_string_list(value: Any) -> tuple[list[str], bool]:
    if not isinstance(value, list):
        return [], False
    valid = all(isinstance(item, str) for item in value)
    return [item.strip() for item in value if isinstance(item, str) and item.strip()], valid


def _loaded_state_capabilities(value: Any) -> tuple[set[Capability], bool]:
    if not isinstance(value, list):
        return set(), False
    capabilities: set[Capability] = set()
    valid = True
    for item in value:
        if not isinstance(item, str):
            valid = False
            continue
        try:
            capabilities.add(Capability(item))
        except ValueError:
            valid = False
    return capabilities, valid


def _loaded_state_text(value: Any) -> tuple[str, bool]:
    if isinstance(value, str):
        return value.strip(), True
    return "", False


def _loaded_state_bool(value: Any) -> tuple[bool, bool]:
    if isinstance(value, bool):
        return value, True
    return False, False


def _sensitive_pending_text_values(
    tool_name: ToolName | str,
    arguments: Mapping[str, Any],
) -> tuple[str, ...]:
    if not _has_sensitive_pending_text(tool_name, arguments):
        return ()
    return tuple(
        value
        for key in ("text", "description")
        if isinstance((value := arguments.get(key)), str)
        and value
        and value != _SENSITIVE_PENDING_TEXT_REDACTION
    )


def _payload_contains_sensitive_value(
    payload: Mapping[str, Any],
    values: tuple[str, ...],
) -> bool:
    if not values:
        return False
    value_set = frozenset(values)
    return any(
        _value_contains_sensitive_leaf(candidate, value_set)
        for candidate in (
            payload.get("arguments"),
            payload.get("safe_preview"),
            payload.get("preflight_action"),
        )
    )


def _value_contains_sensitive_leaf(candidate: Any, values: frozenset[str]) -> bool:
    if isinstance(candidate, str):
        return candidate in values
    if isinstance(candidate, Mapping):
        return any(_value_contains_sensitive_leaf(value, values) for value in candidate.values())
    if isinstance(candidate, (list, tuple)):
        return any(_value_contains_sensitive_leaf(value, values) for value in candidate)
    return False


def _redact_sensitive_pending_arguments(
    tool_name: ToolName | str,
    arguments: Mapping[str, Any],
    *,
    hide_internal: bool = False,
) -> dict[str, Any]:
    payload = dict(arguments)
    if hide_internal:
        canonical_name = canonical_tool_name(str(tool_name), warn_on_alias=False)
        for key in _INTERNAL_PENDING_ARGUMENT_KEYS_BY_ACTION.get(canonical_name, frozenset()):
            payload.pop(key, None)
    if _has_sensitive_pending_text(tool_name, payload):
        if "text" in payload:
            payload["text"] = _SENSITIVE_PENDING_TEXT_REDACTION
        if "description" in payload:
            payload["description"] = _SENSITIVE_PENDING_TEXT_REDACTION
    return payload


def _redact_public_intent_envelope_payload(
    tool_name: ToolName | str,
    payload: dict[str, Any],
) -> dict[str, Any]:
    action = payload.get("action")
    if not isinstance(action, dict):
        return payload
    parameters = action.get("parameters")
    if isinstance(parameters, Mapping):
        action["parameters"] = _redact_sensitive_pending_arguments(
            tool_name,
            parameters,
            hide_internal=True,
        )
        action["display_summary"] = _confirmation_action_summary(tool_name, action["parameters"])
    return payload


def _confirmation_action_summary(
    tool_name: ToolName | str,
    arguments: Mapping[str, Any],
) -> str:
    summary = safe_summary(
        action=str(tool_name),
        risk_level=(
            "high" if _is_high_risk_confirmation_arguments(tool_name, arguments) else "medium"
        ),
        arguments=dict(arguments),
    )
    details = ", ".join(f"{key}={value}" for key, value in summary.parameters[:6])
    return f"{summary.action}: {details}".strip()


def _is_high_risk_confirmation_arguments(
    tool_name: ToolName | str,
    arguments: Mapping[str, Any],
) -> bool:
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


def _redacted_sensitive_confirmation_summary(
    tool_name: ToolName | str,
    arguments: Mapping[str, Any],
) -> tuple[Any, str]:
    summary = safe_summary(
        action=str(tool_name),
        risk_level=(
            "high" if _is_high_risk_confirmation_arguments(tool_name, arguments) else "medium"
        ),
        arguments=_redact_sensitive_pending_arguments(tool_name, arguments),
    )
    action_summary = f"{summary.action}: " + ", ".join(
        f"{key}={value}" for key, value in summary.parameters[:6]
    )
    return summary, action_summary.strip()


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

    def current_state(self, **kwargs: Any) -> dict[str, Any]:
        return dict(self._load().current_state(**kwargs))

    async def doctor_status(self) -> dict[str, Any]:
        return dict(await self._load().doctor_status())


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


def _structured_time_now(
    _handler: Any,
    arguments: Mapping[str, Any],
    _context: StructuredToolContext | None = None,
) -> Mapping[str, Any]:
    return current_time_payload(timezone=_argument_string(arguments, "timezone"))


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
            click_target=_argument_string(arguments, "click_target"),
            resolved_target=_argument_string(arguments, "resolved_target"),
            resolved_click_target=_argument_string(arguments, "resolved_click_target"),
            destination=_argument_string(arguments, "destination"),
            source_url=_argument_string(arguments, "source_url"),
            source_binding=_argument_string(arguments, "source_binding"),
            click_source_binding=_argument_string(arguments, "click_source_binding"),
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
            "taint_labels": [
                TaintLabel.UNTRUSTED.value,
                TaintLabel.SENSITIVE_EMAIL.value,
            ],
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
            "taint_labels": [
                TaintLabel.UNTRUSTED.value,
                TaintLabel.SENSITIVE_EMAIL.value,
            ],
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


_THREAD_CONTEXT_FALLBACK_SCOPE_FILTER = frozenset({"session", "project", "user"})


def _thread_context_filter_payload(context: StructuredToolContext) -> dict[str, Any]:
    payload: dict[str, Any] = {"session_scope_id": str(context.session_id)}
    raw_target = _resolve_session_delivery_target(context.session, session_id=context.session_id)
    try:
        delivery_target = DeliveryTarget.model_validate(raw_target)
    except ValidationError:
        delivery_target = None
    defaults = resolve_active_attention_defaults(
        channel=str(context.session.channel),
        delivery_target=delivery_target,
    )
    if defaults is None:
        payload["scope_filter"] = sorted(_THREAD_CONTEXT_FALLBACK_SCOPE_FILTER)
        return payload
    payload["scope_filter"] = sorted(defaults.scope_filter)
    if defaults.allowed_channel_trusts is not None:
        payload["allowed_channel_trusts"] = sorted(defaults.allowed_channel_trusts)
    if defaults.channel_binding is not None:
        payload["channel_binding"] = defaults.channel_binding
    return payload


def _parse_reminder_delay_seconds(when: str, *, now: datetime) -> int:
    normalized = when.strip()
    if not normalized:
        raise ValueError("reminder_when_required")
    relative = parse_reminder_relative_duration(normalized)
    if relative is not None:
        return max(1, relative.seconds)

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
                "user_id": str(context.user_id),
                "workspace_id": str(context.workspace_id),
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
            "user_id": str(context.user_id),
            "workspace_id": str(context.workspace_id),
        }
    )
    return _wrap_structured_payload(payload, ok=str(payload.get("kind", "")) == "allow")


async def _structured_note_list(
    handler: Any,
    arguments: Mapping[str, Any],
    context: StructuredToolContext,
) -> Mapping[str, Any]:
    payload = await handler.do_note_list(
        {
            "limit": _argument_int(arguments, "limit", default=20, minimum=1),
            "user_id": str(context.user_id),
            "workspace_id": str(context.workspace_id),
        }
    )
    return _wrap_structured_payload(payload)


async def _structured_note_search(
    handler: Any,
    arguments: Mapping[str, Any],
    context: StructuredToolContext,
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
            "user_id": str(context.user_id),
            "workspace_id": str(context.workspace_id),
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
                "user_id": str(context.user_id),
                "workspace_id": str(context.workspace_id),
            }
        )
        return _wrap_structured_payload(payload, ok=str(payload.get("kind", "")) == "allow")
    payload = await handler.do_todo_create(
        {
            **todo_payload,
            _CONTROL_API_AUTHENTICATED_WRITE: True,
            "source_id": str(context.session_id),
            "user_confirmed": context.user_confirmed,
            "user_id": str(context.user_id),
            "workspace_id": str(context.workspace_id),
        }
    )
    return _wrap_structured_payload(payload, ok=str(payload.get("kind", "")) == "allow")


async def _structured_todo_list(
    handler: Any,
    arguments: Mapping[str, Any],
    context: StructuredToolContext,
) -> Mapping[str, Any]:
    payload = await handler.do_todo_list(
        {
            "limit": _argument_int(arguments, "limit", default=20, minimum=1),
            "user_id": str(context.user_id),
            "workspace_id": str(context.workspace_id),
        }
    )
    return _wrap_structured_payload(payload)


async def _structured_todo_complete(
    handler: Any,
    arguments: Mapping[str, Any],
    context: StructuredToolContext,
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
    payload = await handler.do_todo_complete(
        {
            "selector": selector,
            "user_id": str(context.user_id),
            "workspace_id": str(context.workspace_id),
        }
    )
    return _wrap_structured_payload(payload, ok=bool(payload.get("completed", False)))


async def _structured_thread_list(
    handler: Any,
    arguments: Mapping[str, Any],
    context: StructuredToolContext,
) -> Mapping[str, Any]:
    payload = await handler.do_thread_list(
        {
            "limit": _argument_int(arguments, "limit", default=20, minimum=1),
            "state": _argument_string(arguments, "state") or "open",
            **_thread_context_filter_payload(context),
            "user_id": str(context.user_id),
            "workspace_id": str(context.workspace_id),
        }
    )
    return _wrap_structured_payload(payload)


async def _structured_thread_inspect(
    handler: Any,
    arguments: Mapping[str, Any],
    context: StructuredToolContext,
) -> Mapping[str, Any]:
    thread_id = _argument_string(arguments, "thread_id")
    if not thread_id:
        return {"ok": False, "found": False, "error": "thread_id_required"}
    payload = await handler.do_thread_inspect(
        {
            "thread_id": thread_id,
            **_thread_context_filter_payload(context),
            "user_id": str(context.user_id),
            "workspace_id": str(context.workspace_id),
        }
    )
    return _wrap_structured_payload(payload, ok=bool(payload.get("found", False)))


async def _structured_thread_resume(
    handler: Any,
    arguments: Mapping[str, Any],
    context: StructuredToolContext,
) -> Mapping[str, Any]:
    thread_id = _argument_string(arguments, "thread_id")
    if not thread_id:
        return {"ok": False, "changed": False, "error": "thread_id_required"}
    payload = await handler.do_thread_resume(
        {
            "thread_id": thread_id,
            **_thread_context_filter_payload(context),
            "user_id": str(context.user_id),
            "workspace_id": str(context.workspace_id),
        }
    )
    return _wrap_structured_payload(payload, ok=bool(payload.get("changed", False)))


async def _structured_thread_close(
    handler: Any,
    arguments: Mapping[str, Any],
    context: StructuredToolContext,
) -> Mapping[str, Any]:
    thread_id = _argument_string(arguments, "thread_id")
    if not thread_id:
        return {"ok": False, "changed": False, "error": "thread_id_required"}
    payload = await handler.do_thread_close(
        {
            "thread_id": thread_id,
            "reason": _argument_string(arguments, "reason"),
            **_thread_context_filter_payload(context),
            "user_id": str(context.user_id),
            "workspace_id": str(context.workspace_id),
        }
    )
    return _wrap_structured_payload(payload, ok=bool(payload.get("changed", False)))


async def _structured_thread_why(
    handler: Any,
    arguments: Mapping[str, Any],
    context: StructuredToolContext,
) -> Mapping[str, Any]:
    query = _argument_string(arguments, "query")
    if not query:
        return {"ok": False, "selected": False, "error": "thread_query_required"}
    payload = await handler.do_thread_why(
        {
            "query": query,
            "thread_id": _argument_string(arguments, "thread_id"),
            **_thread_context_filter_payload(context),
            "user_id": str(context.user_id),
            "workspace_id": str(context.workspace_id),
        }
    )
    return _wrap_structured_payload(payload)


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
    views: list[ReminderStatusView] = []
    current_target_payload = _resolve_session_delivery_target(
        context.session,
        session_id=context.session_id,
    )
    pending_confirmations = getattr(handler._scheduler, "pending_confirmations", None)
    for task in handler._scheduler.list_tasks():
        if str(getattr(task, "created_by", "")).strip() != str(context.user_id).strip():
            continue
        if str(getattr(task, "workspace_id", "")).strip() != str(context.workspace_id).strip():
            continue
        if not str(getattr(task, "goal", "")).startswith("Reminder: "):
            continue
        task_id = str(getattr(task, "id", "")).strip()
        pending_count = 0
        if task_id and callable(pending_confirmations):
            try:
                pending_count = len(pending_confirmations(task_id))
            except (AttributeError, TypeError, ValueError):
                pending_count = 0
        view = reminder_status_view_for_task(
            task,
            current_delivery_target=current_target_payload,
            pending_confirmation_count=pending_count,
        )
        if view is None:
            continue
        views.append(view)
        if len(rows) < limit:
            row = task.model_dump(mode="json")
            row.update(task_schedule_rendering(task))
            row["lifecycle_state"] = view.lifecycle_state
            row["current_binding"] = view.current_binding
            rows.append(row)
    selection = select_reminder_status_view(views)
    return {
        "ok": True,
        "tasks": rows,
        "count": len(rows),
        "selection": selection.status,
        "selected_task_id": (
            selection.selected.identity.task_id if selection.selected is not None else ""
        ),
        "candidate_task_ids": [item.identity.task_id for item in selection.candidates],
    }


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
        return {
            "ok": False,
            "error": "invalid or unknown evidence reference",
            "ref_id": ref_id,
        }
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
        return {
            "ok": False,
            "error": "invalid or unknown evidence reference",
            "ref_id": ref_id,
        }
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


_CHANNEL_NATIVE_APPROVAL_METHODS = frozenset({"software", "totp", "recovery_code"})
_EXTERNAL_SIGNER_APPROVAL_METHODS = frozenset({"kms", "ledger"})


def _required_proof_tier(level: ConfirmationLevel | str) -> str:
    try:
        normalized = ConfirmationLevel(str(getattr(level, "value", level)))
    except ValueError:
        return "method_specific"
    if normalized == ConfirmationLevel.SOFTWARE:
        return "T0_identity"
    if normalized == ConfirmationLevel.REAUTHENTICATED:
        return "T1_stepup"
    return "method_specific"


def _pending_origin_channel(pending: Any) -> str:
    delivery_target = getattr(pending, "delivery_target", None)
    if delivery_target is not None:
        channel = str(getattr(delivery_target, "channel", "")).strip().lower()
        if channel:
            return channel
    preflight_action = getattr(pending, "preflight_action", None)
    origin = getattr(preflight_action, "origin", None)
    return str(getattr(origin, "channel", "")).strip().lower()


def _pending_action_kind_value(pending: Any, arguments: dict[str, Any]) -> str:
    preflight_action = getattr(pending, "preflight_action", None)
    preflight_kind = getattr(preflight_action, "action_kind", "")
    if preflight_kind:
        return str(getattr(preflight_kind, "value", preflight_kind))
    return infer_action_kind(str(getattr(pending, "tool_name", "")), arguments).value


def _approval_route_for_method(method: str, *, origin_channel: str) -> str:
    if method in _CHANNEL_NATIVE_APPROVAL_METHODS:
        return "channel_native" if origin_channel else "host_cli"
    if method in {"webauthn", "local_fido2"}:
        return "browser"
    if method in _EXTERNAL_SIGNER_APPROVAL_METHODS:
        return "external_signer"
    return "unknown"


def _selected_method_proof_tier(method: str) -> str:
    if method == "software":
        return "T0_identity"
    if method in {"totp", "recovery_code"}:
        return "T1_stepup"
    if method:
        return "method_specific"
    return ""


def _cannot_carry_reason(
    *,
    proof_tier: str,
    selected_method: str,
    selected_method_proof_tier: str,
    approval_route: str,
    can_collect_selected_method: bool,
) -> str:
    if approval_route in {"channel_native", "host_cli"}:
        if can_collect_selected_method and selected_method_proof_tier != proof_tier:
            return f"selected_method_requires_{selected_method_proof_tier}"
        return ""
    if proof_tier == "method_specific" and selected_method:
        return f"method_specific_approval_requires_{selected_method}"
    if selected_method:
        return f"approval_requires_{selected_method}"
    return "approval_method_unavailable"


def _pending_channel_capability_payload(
    pending: Any,
    *,
    origin_channel: str,
    required_proof_tier: str,
    selected_backend_available: bool | None = None,
) -> dict[str, Any]:
    selected_method = str(getattr(pending, "selected_backend_method", "")).strip().lower()
    selected_method_proof_tier = _selected_method_proof_tier(selected_method)
    required_level = getattr(pending, "required_level", "")
    required_level_value = str(getattr(required_level, "value", required_level)).strip()
    state_view = pending_action_state_view(pending)
    is_pending = state_view.is_live_pending
    is_expired = state_view.lifecycle_state == "expired"
    is_live_pending = state_view.is_live_pending
    backend_available = (
        True if selected_backend_available is None else bool(selected_backend_available)
    )
    approval_route = (
        _approval_route_for_method(selected_method, origin_channel=origin_channel)
        if backend_available
        else "unavailable"
    )
    can_collect_selected_method = (
        is_live_pending and backend_available and approval_route in {"channel_native", "host_cli"}
    )
    can_carry_t0_identity = (
        can_collect_selected_method and selected_method_proof_tier == "T0_identity"
    )
    can_carry_t1_stepup = can_collect_selected_method and selected_method_proof_tier == "T1_stepup"
    can_carry_method_specific = (
        can_collect_selected_method and selected_method_proof_tier == "method_specific"
    )
    can_carry_required_proof_tier = {
        "T0_identity": can_carry_t0_identity,
        "T1_stepup": can_carry_t1_stepup,
        "method_specific": can_carry_method_specific,
    }.get(required_proof_tier, False)
    if can_carry_required_proof_tier:
        cannot_carry_reason = ""
    elif is_expired:
        cannot_carry_reason = "approval_expired"
    elif not is_pending:
        cannot_carry_reason = "approval_not_pending"
    elif not backend_available:
        cannot_carry_reason = "confirmation_backend_unavailable"
    else:
        cannot_carry_reason = _cannot_carry_reason(
            proof_tier=required_proof_tier,
            selected_method=selected_method,
            selected_method_proof_tier=selected_method_proof_tier,
            approval_route=approval_route,
            can_collect_selected_method=can_collect_selected_method,
        )
    allowed_channel_principals = [
        str(value).strip()
        for value in getattr(pending, "allowed_channel_principals", ())
        if str(value).strip()
    ]
    return {
        "origin_channel": origin_channel,
        "approval_route": approval_route,
        "selected_backend_id": str(getattr(pending, "selected_backend_id", "")).strip(),
        "selected_method": selected_method,
        "backend_available": backend_available,
        "selected_method_proof_tier": selected_method_proof_tier,
        "required_proof_tier": required_proof_tier,
        "required_level": required_level_value,
        "required_methods": list(getattr(pending, "required_methods", ())),
        "can_approve": bool(selected_method) and backend_available and is_live_pending,
        "can_reject": is_pending,
        "can_collect_selected_method": can_collect_selected_method,
        "can_carry": can_carry_required_proof_tier,
        "can_carry_required_proof_tier": can_carry_required_proof_tier,
        "can_carry_t0_identity": can_carry_t0_identity,
        "can_carry_t1_stepup": can_carry_t1_stepup,
        "can_carry_method_specific": can_carry_method_specific,
        "requires_channel_principal": bool(
            allowed_channel_principals and selected_method in {"software", "totp", "recovery_code"}
        ),
        "requires_second_factor": selected_method_proof_tier == "T1_stepup",
        "requires_proof_input": selected_method != "software",
        "cannot_carry_reason": cannot_carry_reason,
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
    public_arguments: dict[str, Any] | None = None
    sensitive_public_payload: bool = False
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
    allowed_channel_principals: list[str] = field(default_factory=list)
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
    continuation_user_goal: str = ""
    continuation_mode: str = ""
    status: str = "pending"
    status_reason: str = ""
    action_id: str = ""
    origin_turn_id: str = ""
    action_digest: str = ""
    approval_evidence_hash: str = ""
    execution_authorization_kind: str = ""
    retry_descriptor: ToolRetryDescriptor | None = None
    retry_generation: int = 0
    recovery_started_at: datetime | None = None
    recovery_result: dict[str, Any] = field(default_factory=dict)
    recovery_accounting_pending: bool = False
    recovery_effect_invoked: bool = False
    recovery_scheduler_accounted: bool = False
    recovery_scheduler_posture_captured: bool = False
    recovery_scheduler_restore_enabled: bool = False
    scheduler_accounting_pending: bool = False
    scheduler_accounting_mode: str = ""
    stage2_correlation_id: str = ""
    stage2_previous_plan_hash: str = ""
    stage2_plan_hash: str = ""
    stable_idempotency_key: str = ""
    provider_operation_id: str = ""
    execution_attempt_id: str = ""
    result_id: str = ""
    followup_id: str = ""
    recovery_authority_mac: str = ""
    recovery_event_identity_untrusted: bool = False
    recovery_event_identity_untrusted_at: datetime | None = None
    recovery_anonymous_accounting_id: str = ""
    recovery_event_identity_trusted_at: datetime | None = field(
        default=None,
        repr=False,
        compare=False,
    )
    recovery_anonymous_accounting_id_trusted: str = field(
        default="",
        repr=False,
        compare=False,
    )

    def __post_init__(self) -> None:
        if not self.action_id.strip():
            self.action_id = derive_legacy_action_id(
                confirmation_id=self.confirmation_id,
                session_id=str(self.session_id),
                created_at=self.created_at,
            )
        if not self.followup_id.strip():
            self.followup_id = derive_action_followup_id(self.action_id)

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


def _pending_action_has_started_execution_authority(pending: PendingAction) -> bool:
    """Return whether a stored pending row carries post-decision authority."""

    return bool(
        pending.execution_attempt_id.strip()
        or pending.result_id.strip()
        or pending.provider_operation_id.strip()
        or pending.approval_evidence_hash.strip()
        or pending.execution_authorization_kind.strip()
        or pending.confirmation_evidence is not None
        or pending.retry_generation > 0
        or pending.recovery_started_at is not None
        or pending.recovery_result
        or pending.recovery_accounting_pending
        or pending.recovery_effect_invoked
        or pending.recovery_scheduler_accounted
        or pending.recovery_scheduler_posture_captured
        or pending.recovery_scheduler_restore_enabled
        or pending.scheduler_accounting_pending
        or pending.scheduler_accounting_mode.strip()
        or pending.stage2_correlation_id.strip()
        or pending.stage2_previous_plan_hash.strip()
        or pending.stage2_plan_hash.strip()
    )


def _loaded_pending_payload_has_started_execution_authority(
    item: Mapping[str, Any],
) -> bool:
    """Detect raw post-decision markers before load sanitation can erase them."""

    identity = item.get("identity")
    identity_fields = identity if isinstance(identity, Mapping) else {}

    def _text_marker_present(value: Any) -> bool:
        return bool(value.strip()) if isinstance(value, str) else value is not None

    if any(
        _text_marker_present(item.get(field, ""))
        for field in (
            "execution_attempt_id",
            "result_id",
            "provider_operation_id",
            "approval_evidence_hash",
            "execution_authorization_kind",
            "recovery_started_at",
            "stage2_correlation_id",
            "stage2_previous_plan_hash",
            "stage2_plan_hash",
            "recovery_authority_mac",
            "scheduler_accounting_mode",
        )
    ):
        return True
    if any(
        _text_marker_present(identity_fields.get(field, ""))
        for field in ("execution_attempt_id", "result_id")
    ):
        return True
    if item.get("confirmation_evidence") is not None:
        return True
    if item.get("retry_generation", 0) != 0:
        return True
    if item.get("recovery_result", {}) != {}:
        return True
    return any(
        item.get(field, False) is not False
        for field in (
            "recovery_accounting_pending",
            "recovery_effect_invoked",
            "recovery_scheduler_accounted",
            "recovery_scheduler_posture_captured",
            "recovery_scheduler_restore_enabled",
            "scheduler_accounting_pending",
        )
    )


def _loaded_pending_payload_has_recovery_event_identity_marker(
    item: Mapping[str, Any],
) -> bool:
    """Detect raw anonymous recovery-audit markers before load sanitation."""

    marker = item.get("recovery_event_identity_untrusted", False)
    if marker is not False:
        return True
    return any(
        bool(value.strip()) if isinstance(value, str) else value is not None
        for value in (
            item.get("recovery_event_identity_untrusted_at"),
            item.get("recovery_anonymous_accounting_id"),
        )
    )


def _loaded_pending_has_terminal_scheduler_shadow(
    scheduler: Any,
    item: Mapping[str, Any],
) -> bool:
    """Detect independent durable evidence of unresolved terminal accounting."""

    identity = item.get("identity")
    identity_fields = identity if isinstance(identity, Mapping) else {}
    confirmation_ids: set[str] = set()
    for value in (
        item.get("confirmation_id", ""),
        identity_fields.get("confirmation_id", ""),
    ):
        confirmation_id, valid = _loaded_state_text(value)
        if valid and confirmation_id:
            confirmation_ids.add(confirmation_id)
    task_ids_for_confirmation = getattr(scheduler, "task_ids_for_confirmation", None)
    has_terminal_shadow = getattr(
        scheduler,
        "has_terminal_confirmation_shadow",
        None,
    )
    if not callable(task_ids_for_confirmation) or not callable(has_terminal_shadow):
        return False
    return any(
        has_terminal_shadow(task_id, confirmation_id=confirmation_id)
        for confirmation_id in confirmation_ids
        for task_id in task_ids_for_confirmation(confirmation_id)
    )


def _pending_recovery_authority_snapshot(pending: PendingAction) -> dict[str, Any]:
    """Return the daemon-authenticated post-decision recovery snapshot."""

    evidence = pending.confirmation_evidence
    snapshot = {
        "schema_version": "shisad.pending_recovery_snapshot.v7",
        "confirmation_id": pending.confirmation_id,
        "action_id": pending.action_id,
        "origin_turn_id": pending.origin_turn_id,
        "session_id": str(pending.session_id),
        "user_id": str(pending.user_id),
        "workspace_id": str(pending.workspace_id),
        "task_id": pending.task_id,
        "delivery_target": (
            pending.delivery_target.model_dump(mode="json")
            if pending.delivery_target is not None
            else None
        ),
        "approval_task_envelope_id": pending.approval_task_envelope_id.strip(),
        "tool_name": str(pending.tool_name),
        "arguments": dict(pending.arguments),
        "action_digest": pending.action_digest,
        "approval_envelope_hash": pending.approval_envelope_hash,
        "approval_evidence_hash": pending.approval_evidence_hash,
        "confirmation_evidence_hash": (evidence.evidence_hash if evidence is not None else ""),
        "confirmation_evidence_authenticator_mac": (
            evidence.authenticator_mac if evidence is not None else ""
        ),
        "confirmation_evidence": (
            evidence.model_dump(mode="json") if evidence is not None else None
        ),
        "decision_nonce": pending.decision_nonce,
        "status": pending.status,
        "status_reason": pending.status_reason,
        "execution_attempt_id": pending.execution_attempt_id,
        "result_id": pending.result_id,
        "followup_id": pending.followup_id,
        "provider_operation_id": pending.provider_operation_id,
        "preflight_action": (
            pending.preflight_action.model_dump(mode="json")
            if pending.preflight_action is not None
            else None
        ),
        "retry_descriptor": (
            pending.retry_descriptor.model_dump(mode="json")
            if pending.retry_descriptor is not None
            else None
        ),
        "retry_generation": pending.retry_generation,
        "recovery_started_at": (
            pending.recovery_started_at.isoformat()
            if pending.recovery_started_at is not None
            else ""
        ),
        "recovery_result": dict(pending.recovery_result),
        "recovery_accounting_pending": pending.recovery_accounting_pending,
        "recovery_effect_invoked": pending.recovery_effect_invoked,
        "recovery_event_identity_untrusted": pending.recovery_event_identity_untrusted,
        "recovery_event_identity_untrusted_at": (
            pending.recovery_event_identity_untrusted_at.isoformat()
            if pending.recovery_event_identity_untrusted_at is not None
            else ""
        ),
        "recovery_anonymous_accounting_id": pending.recovery_anonymous_accounting_id,
        "recovery_scheduler_accounted": pending.recovery_scheduler_accounted,
        "scheduler_accounting_pending": pending.scheduler_accounting_pending,
        "stable_idempotency_key": pending.stable_idempotency_key,
        "stage2_correlation_id": pending.stage2_correlation_id,
        "stage2_previous_plan_hash": pending.stage2_previous_plan_hash,
        "stage2_plan_hash": pending.stage2_plan_hash,
        "created_at": pending.created_at.isoformat(),
        "expires_at": pending.expires_at.isoformat() if pending.expires_at else "",
    }
    if pending.execution_authorization_kind:
        snapshot["execution_authorization_kind"] = pending.execution_authorization_kind
    if pending.recovery_scheduler_posture_captured or pending.recovery_scheduler_restore_enabled:
        snapshot.update(
            {
                "recovery_scheduler_posture_captured": (
                    pending.recovery_scheduler_posture_captured
                ),
                "recovery_scheduler_restore_enabled": (pending.recovery_scheduler_restore_enabled),
            }
        )
    if pending.scheduler_accounting_mode:
        snapshot["scheduler_accounting_mode"] = pending.scheduler_accounting_mode
    return snapshot


def _neutralize_untrusted_recovery_event_identity(pending: PendingAction) -> None:
    pending.delivery_target = None
    pending.approval_task_envelope_id = ""


def _clear_recovery_event_identity_marker(pending: PendingAction) -> None:
    pending.recovery_event_identity_untrusted = False
    pending.recovery_event_identity_untrusted_at = None
    pending.recovery_anonymous_accounting_id = ""
    pending.recovery_event_identity_trusted_at = None
    pending.recovery_anonymous_accounting_id_trusted = ""


def _ensure_trusted_recovery_event_identity_marker(pending: PendingAction) -> None:
    pending.recovery_event_identity_untrusted = True
    if (
        pending.recovery_event_identity_untrusted_at is None
        or pending.recovery_event_identity_untrusted_at
        != pending.recovery_event_identity_trusted_at
    ):
        pending.recovery_event_identity_untrusted_at = datetime.now(UTC)
    if (
        not pending.recovery_anonymous_accounting_id.strip()
        or pending.recovery_anonymous_accounting_id
        != pending.recovery_anonymous_accounting_id_trusted
    ):
        pending.recovery_anonymous_accounting_id = uuid.uuid4().hex
    pending.recovery_event_identity_trusted_at = pending.recovery_event_identity_untrusted_at
    pending.recovery_anonymous_accounting_id_trusted = (
        pending.recovery_anonymous_accounting_id
    )


def _unauthenticated_recovery_event_identity_fields() -> dict[str, Any]:
    return {
        "action_id": "",
        "origin_turn_id": "",
        "user_id": "",
        "workspace_id": "",
        "task_id": "",
        "delivery_target": None,
        "execution_attempt_id": "",
        "result_id": "",
        "followup_id": "",
        "approval_session_id": "",
        "approval_task_envelope_id": "",
        "approval_confirmation_id": "",
    }


def _neutralize_untrusted_scheduler_accounting_intent(
    pending: PendingAction,
    *,
    intent_present: bool | None = None,
) -> None:
    """Replace unauthenticated scheduler intent with conservative local state."""

    accounting_mode = pending.scheduler_accounting_mode.strip()
    has_intent = (
        bool(
            pending.scheduler_accounting_pending
            or (
                accounting_mode
                and not (
                    accounting_mode == "ambiguous"
                    and pending.recovery_scheduler_accounted
                )
            )
        )
        if intent_present is None
        else intent_present
    )
    if not has_intent:
        return
    scheduled = bool(pending.task_id.strip())
    pending.scheduler_accounting_pending = scheduled
    pending.scheduler_accounting_mode = "ambiguous" if scheduled else ""
    pending.recovery_scheduler_accounted = False


@dataclass(slots=True)
class ToolOutputRecord:
    tool_name: str
    content: str
    success: bool = True
    taint_labels: set[TaintLabel] = field(default_factory=set)
    ingress_context: str | None = None
    content_digest: str | None = None
    arguments: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class ApprovedToolExecutionResult:
    success: bool
    checkpoint_id: str | None = None
    tool_output: ToolOutputRecord | None = None
    sandbox_result: SandboxResult | None = None
    error: str = ""
    provider_operation_id: str = ""
    outcome_unknown: bool = False


class HandlerImplementation(
    SessionImplMixin,
    PlanStepsImplMixin,
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
        self._plan_steps = PlanStepStore()
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
        self._timeline_index = services.timeline_index
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
        self._recovery_accounting_tasks: set[asyncio.Task[None]] = set()
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
        self._confirmation_evidence_authenticator = ConfirmationEvidenceAuthenticator.from_path(
            self._config.data_dir / "confirmation_evidence.key"
        )
        self._confirmation_backend_registry = ConfirmationBackendRegistry()
        self._confirmation_backend_registry.register(SoftwareConfirmationBackend())
        if services.credential_store.approval_state_degraded:
            logger.warning(
                "Approval-factor state is degraded; store-backed confirmation and signer "
                "backends remain disabled until retained state is restored and shisad restarts"
            )
        else:
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
            arguments=dict(tool_output.arguments),
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
        tool_name_value = canonical_tool_name(str(tool_name), warn_on_alias=False)
        if tool_name_value not in {
            "browser.navigate",
            "browser.click",
            "browser.type_text",
        }:
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
        workspace_root: Path | None = None,
    ) -> SandboxConfig:
        workspace = workspace_root.expanduser().resolve(strict=False) if workspace_root else None

        def _workspace_path(value: Any) -> str:
            text = str(value)
            if workspace is None or not text:
                return text
            path = Path(text).expanduser()
            if path.is_absolute():
                return str(path)
            return str((workspace / path).resolve(strict=False))

        read_paths = [_workspace_path(item) for item in params.get("read_paths", [])]
        write_paths = [_workspace_path(item) for item in params.get("write_paths", [])]
        cwd_raw = str(params.get("cwd", ""))
        cwd = _workspace_path(cwd_raw) if cwd_raw else (str(workspace) if workspace else "")
        command = [str(token) for token in params.get("command", [])]
        env = {str(k): str(v) for k, v in dict(params.get("env", {})).items()}
        if HandlerImplementation._uses_gh12_read_only_shell_command(
            tool_name=tool_name,
            command=command,
        ):
            env["PATH"] = HandlerImplementation._trusted_shell_path_without_workspace(workspace)
        return SandboxConfig(
            session_id=str(sid),
            tool_name=str(tool_name),
            command=command,
            read_paths=read_paths,
            write_paths=write_paths,
            network_urls=[str(item) for item in params.get("network_urls", [])],
            env=env,
            request_headers={
                str(k): str(v) for k, v in dict(params.get("request_headers", {})).items()
            },
            request_body=str(params.get("request_body", "")),
            cwd=cwd,
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

    @staticmethod
    def _uses_gh12_read_only_shell_command(
        *,
        tool_name: ToolName | str,
        command: list[str],
    ) -> bool:
        if str(tool_name) != "shell.exec" or not command:
            return False
        executable = command[0].strip()
        if not executable or "/" in executable or "\\" in executable:
            return False
        return executable.lower() in _GH12_READ_ONLY_SHELL_COMMANDS

    @staticmethod
    def _trusted_shell_path_without_workspace(workspace: Path | None) -> str:
        workspace_resolved = workspace.resolve(strict=False) if workspace else None
        trusted_entries: list[str] = []
        for raw_entry in os.environ.get("PATH", os.defpath).split(os.pathsep):
            if not raw_entry:
                continue
            entry = Path(raw_entry).expanduser()
            if not entry.is_absolute():
                continue
            lexical = Path(os.path.normpath(str(entry)))
            if workspace_resolved and (
                lexical == workspace_resolved or workspace_resolved in lexical.parents
            ):
                continue
            resolved = entry.resolve(strict=False)
            if workspace_resolved and (
                resolved == workspace_resolved or workspace_resolved in resolved.parents
            ):
                continue
            trusted_entries.append(str(resolved))
        for raw_entry in os.defpath.split(os.pathsep):
            entry = Path(raw_entry).resolve(strict=False)
            trusted_entries.append(str(entry))
        return os.pathsep.join(dict.fromkeys(trusted_entries))

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
            normalized_pep_reason_code = pep_reason_code.strip()
            pep_reject_reasons = {normalized_pep_reason, "pep_reject"}
            if normalized_pep_reason_code:
                pep_reject_reasons.add(normalized_pep_reason_code)
            if normalized_final_reason not in pep_reject_reasons:
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
            for key in ("error", "reason", "status_reason"):
                reason = str(payload.get(key, "")).strip()
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
            reason=(
                ""
                if success
                else HandlerImplementation._structured_tool_reason(tool_output) or execution.error
            ),
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

    def _doctor_storage_status(self) -> dict[str, Any]:
        return sqlite_runtime_status()

    def _doctor_approval_status(self) -> dict[str, Any]:
        return self._credential_store.approval_state_status()

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

    async def _doctor_browser_status(self) -> dict[str, Any]:
        return dict(await self._browser_toolkit.doctor_status())

    @staticmethod
    def _normalized_pairing_request_entry(
        raw: Mapping[str, Any],
    ) -> dict[str, str] | None:
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
    def _pending_to_dict(
        pending: PendingAction,
        *,
        public: bool = False,
        selected_backend_available: bool | None = None,
    ) -> dict[str, Any]:
        browser_sensitive_pending = _has_sensitive_pending_text(
            pending.tool_name,
            pending.arguments,
        )
        sensitive_pending = browser_sensitive_pending or bool(pending.sensitive_public_payload)
        if pending.public_arguments is not None:
            public_argument_source = pending.public_arguments
        elif pending.sensitive_public_payload:
            public_argument_source = {}
        else:
            public_argument_source = pending.arguments
        arguments = _redact_sensitive_pending_arguments(
            pending.tool_name,
            public_argument_source,
            hide_internal=public,
        )
        sensitive_summary = None
        regenerate_public_summary = pending.sensitive_public_payload or (
            public
            and canonical_tool_name(str(pending.tool_name), warn_on_alias=False) == "shell.exec"
        )
        if browser_sensitive_pending:
            sensitive_summary = _redacted_sensitive_confirmation_summary(
                pending.tool_name,
                pending.arguments,
            )[0]
        elif regenerate_public_summary:
            sensitive_summary = safe_summary(
                action=str(pending.tool_name),
                risk_level=(
                    "high"
                    if _is_high_risk_confirmation_arguments(pending.tool_name, arguments)
                    else "medium"
                ),
                arguments=arguments,
            )
        safe_preview = (
            render_structured_confirmation(
                sensitive_summary,
                warnings=sorted(set(pending.warnings)),
            )
            if sensitive_summary is not None
            else pending.safe_preview
        )
        state_view = pending_action_state_view(pending)
        identity_payload = state_view.identity.to_payload()
        action_kind = _pending_action_kind_value(pending, pending.arguments)
        origin_channel = _pending_origin_channel(pending)
        required_proof_tier = _required_proof_tier(pending.required_level)
        preflight_risk_tier = getattr(getattr(pending, "preflight_action", None), "risk_tier", "")
        risk_level = str(getattr(preflight_risk_tier, "value", preflight_risk_tier)).strip()
        payload: dict[str, Any] = {
            "confirmation_id": pending.confirmation_id,
            "action_id": state_view.identity.action_id,
            "identity": identity_payload,
            "origin_turn_id": state_view.identity.origin_turn_id,
            "action_digest": pending.action_digest,
            "approval_evidence_hash": pending.approval_evidence_hash,
            "execution_authorization_kind": pending.execution_authorization_kind,
            "retry_descriptor": (
                pending.retry_descriptor.model_dump(mode="json")
                if pending.retry_descriptor is not None
                else None
            ),
            "retry_generation": pending.retry_generation,
            "recovery_started_at": (
                pending.recovery_started_at.isoformat() if pending.recovery_started_at else ""
            ),
            "recovery_result": dict(pending.recovery_result),
            "recovery_accounting_pending": pending.recovery_accounting_pending,
            "recovery_effect_invoked": pending.recovery_effect_invoked,
            "recovery_event_identity_untrusted": pending.recovery_event_identity_untrusted,
            "recovery_event_identity_untrusted_at": (
                pending.recovery_event_identity_untrusted_at.isoformat()
                if pending.recovery_event_identity_untrusted_at is not None
                else ""
            ),
            "recovery_anonymous_accounting_id": pending.recovery_anonymous_accounting_id,
            "recovery_scheduler_accounted": pending.recovery_scheduler_accounted,
            "recovery_scheduler_posture_captured": (pending.recovery_scheduler_posture_captured),
            "recovery_scheduler_restore_enabled": (pending.recovery_scheduler_restore_enabled),
            "scheduler_accounting_pending": pending.scheduler_accounting_pending,
            "scheduler_accounting_mode": pending.scheduler_accounting_mode,
            "stage2_correlation_id": pending.stage2_correlation_id,
            "stage2_previous_plan_hash": pending.stage2_previous_plan_hash,
            "stage2_plan_hash": pending.stage2_plan_hash,
            "stable_idempotency_key": pending.stable_idempotency_key,
            "provider_operation_id": pending.provider_operation_id,
            "execution_attempt_id": state_view.identity.execution_attempt_id,
            "result_id": state_view.identity.result_id,
            "followup_id": state_view.identity.followup_id,
            "recovery_authority_mac": pending.recovery_authority_mac,
            "action_kind": action_kind,
            "decision_nonce": pending.decision_nonce,
            "session_id": str(pending.session_id),
            "user_id": str(pending.user_id),
            "workspace_id": str(pending.workspace_id),
            "origin_channel": origin_channel,
            "task_id": pending.task_id,
            "tool_name": str(pending.tool_name),
            "arguments": arguments,
            "reason": pending.reason,
            "risk_level": risk_level,
            "capabilities": sorted(cap.value for cap in pending.capabilities),
            "created_at": pending.created_at.isoformat(),
            "age_seconds": state_view.age_seconds(),
            "delivery_target": (
                pending.delivery_target.model_dump(mode="json")
                if pending.delivery_target is not None
                else None
            ),
            "execute_after": pending.execute_after.isoformat() if pending.execute_after else "",
            "safe_preview": safe_preview,
            "warnings": list(pending.warnings),
            "leak_check": dict(pending.leak_check),
            "approval_task_envelope_id": pending.approval_task_envelope_id,
            "required_proof_tier": required_proof_tier,
            "required_level": pending.required_level.value,
            "required_methods": list(pending.required_methods),
            "channel_capability": _pending_channel_capability_payload(
                pending,
                origin_channel=origin_channel,
                required_proof_tier=required_proof_tier,
                selected_backend_available=selected_backend_available,
            ),
            "allowed_principals": list(pending.allowed_principals),
            "allowed_channel_principals": list(pending.allowed_channel_principals),
            "allowed_credentials": list(pending.allowed_credentials),
            "required_capabilities": pending.required_capabilities.model_dump(mode="json"),
            "approval_envelope_hash": "" if sensitive_pending else pending.approval_envelope_hash,
            "fallback": pending.fallback.model_dump(mode="json"),
            "expires_at": pending.expires_at.isoformat() if pending.expires_at else "",
            "selected_backend_id": pending.selected_backend_id,
            "selected_backend_method": pending.selected_backend_method,
            "fallback_used": bool(pending.fallback_used),
            "strip_direct_tool_execute_envelope_keys": bool(
                pending.strip_direct_tool_execute_envelope_keys
            ),
            "continuation_user_goal": pending.continuation_user_goal,
            "continuation_mode": pending.continuation_mode,
            "status": pending.status,
            "lifecycle_state": state_view.lifecycle_state,
            "status_reason": state_view.status_reason,
        }
        if pending.sensitive_public_payload:
            payload["sensitive_public_payload"] = True
        if pending.preflight_action is not None:
            if sensitive_pending:
                payload["preflight_action_redacted"] = True
            else:
                payload["preflight_action"] = pending.preflight_action.model_dump(mode="json")
        if pending.merged_policy is not None:
            payload["merged_policy"] = pending.merged_policy.model_dump(mode="json")
        if pending.pep_context is not None:
            payload["pep_context"] = pending_pep_context_to_payload(pending.pep_context)
        if pending.pep_elevation is not None:
            payload["pep_elevation"] = pending_pep_elevation_to_payload(pending.pep_elevation)
        if pending.approval_envelope is not None:
            if sensitive_pending:
                payload["approval_envelope_redacted"] = True
            else:
                approval_envelope_payload = pending.approval_envelope.model_dump(mode="json")
                if public:
                    approval_envelope_payload["action_summary"] = _confirmation_action_summary(
                        pending.tool_name,
                        arguments,
                    )
                payload["approval_envelope"] = approval_envelope_payload
        if pending.intent_envelope is not None:
            if sensitive_pending:
                payload["intent_envelope_redacted"] = True
            else:
                intent_envelope_payload = pending.intent_envelope.model_dump(mode="json")
                if public:
                    intent_envelope_payload = _redact_public_intent_envelope_payload(
                        pending.tool_name,
                        intent_envelope_payload,
                    )
                payload["intent_envelope"] = intent_envelope_payload
        if pending.confirmation_evidence is not None:
            if sensitive_pending:
                payload["confirmation_evidence_redacted"] = True
            else:
                payload["confirmation_evidence"] = pending.confirmation_evidence.model_dump(
                    mode="json"
                )
        if public:
            payload.pop("recovery_accounting_pending", None)
            payload.pop("recovery_effect_invoked", None)
            payload.pop("recovery_event_identity_untrusted", None)
            payload.pop("recovery_event_identity_untrusted_at", None)
            payload.pop("recovery_anonymous_accounting_id", None)
            payload.pop("recovery_scheduler_accounted", None)
            payload.pop("recovery_scheduler_posture_captured", None)
            payload.pop("recovery_scheduler_restore_enabled", None)
            payload.pop("scheduler_accounting_pending", None)
            payload.pop("scheduler_accounting_mode", None)
            payload.pop("stage2_correlation_id", None)
            payload.pop("stage2_previous_plan_hash", None)
            payload.pop("stage2_plan_hash", None)
            payload.pop("recovery_authority_mac", None)
            payload.pop("execution_authorization_kind", None)
            payload.pop("stable_idempotency_key", None)
            payload["stable_idempotency_key_present"] = bool(pending.stable_idempotency_key)
            retry_descriptor_payload = payload.get("retry_descriptor")
            if isinstance(retry_descriptor_payload, dict):
                retry_descriptor_payload.pop("stable_idempotency_key", None)
                retry_descriptor_payload.pop("stable_adapter_guarantee_id", None)
            public_structural_clock_result = (
                pending.retry_descriptor is not None
                and pending.retry_descriptor.retry_class == ToolRetryClass.STRUCTURAL_READ
                and str(pending.tool_name) == "time.now"
            )
            if not public_structural_clock_result:
                payload.pop("recovery_result", None)
                payload["recovery_result_available"] = bool(pending.recovery_result)
            if state_view.lifecycle_state == "outcome_unknown":
                payload["uncertainty_evidence"] = {
                    "action_digest": pending.action_digest,
                    "execution_attempt_id": pending.execution_attempt_id,
                    "result_id": pending.result_id,
                    "provider_operation_id": pending.provider_operation_id,
                    "retry_generation": pending.retry_generation,
                }
                payload["manual_retry"] = {
                    "requires_fresh_approval": True,
                    "reuse_confirmation_id": False,
                    "provider_reconciliation_available": False,
                    "instruction": (
                        "Inspect provider or local evidence before retrying. If you choose "
                        "to retry, re-request the action; a new approval is required. Do "
                        "not reuse this confirmation ID or decision nonce."
                    ),
                }
        return payload

    def _pending_selected_backend_available(self, pending: PendingAction) -> bool:
        registry = getattr(self, "_confirmation_backend_registry", None)
        get_backend = getattr(registry, "get_backend", None)
        if not callable(get_backend):
            return False
        selected_backend_id = (
            str(getattr(pending, "selected_backend_id", "")).strip() or "software.default"
        )
        backend = get_backend(selected_backend_id)
        if backend is None:
            return False
        selected_method = str(getattr(pending, "selected_backend_method", "")).strip()
        if selected_method and str(getattr(backend, "method", "")).strip() != selected_method:
            return False
        return confirmation_backend_satisfies_constraints(
            backend,
            user_id=str(getattr(pending, "user_id", "")),
            required_capabilities=getattr(
                pending,
                "required_capabilities",
                ConfirmationCapabilities(),
            ),
            allowed_principals=getattr(pending, "allowed_principals", ()),
            allowed_credentials=getattr(pending, "allowed_credentials", ()),
        )

    @staticmethod
    def _is_high_risk_confirmation(tool_name: ToolName, arguments: dict[str, Any]) -> bool:
        return _is_high_risk_confirmation_arguments(tool_name, arguments)

    # Session-recent window for the cross-thread leak detector source. Limits
    # the detector to the most recent N user entries instead of the full
    # session transcript to avoid false positives as the session history
    # grows.
    _LEAK_SOURCE_RECENT_USER_ENTRIES: int = 20

    def _session_source_text_by_id(self, session_id: SessionId) -> dict[str, str]:
        user_entries = [
            entry
            for entry in self._transcript_store.list_entries(session_id)
            if entry.role == "user"
        ]
        recent = user_entries[-self._LEAK_SOURCE_RECENT_USER_ENTRIES :]
        return {entry.content_hash: entry.content_preview for entry in recent}

    @staticmethod
    def _extract_outbound_text(arguments: dict[str, Any]) -> str:
        for key in ("body", "content", "message", "text", "request_body"):
            value = arguments.get(key)
            if isinstance(value, str) and value.strip():
                return value
        return ""

    def _channel_usable_confirmation_backend(
        self,
        *,
        requirement: ConfirmationRequirement,
        user_id: str,
        delivery_target: DeliveryTarget | None,
    ) -> ResolvedConfirmationBackend | None:
        channel = ""
        if delivery_target is not None:
            channel = str(getattr(delivery_target, "channel", "")).strip().lower()
        if not channel:
            return None
        backend = self._confirmation_backend_registry.get_backend("totp.default")
        if backend is None:
            return None
        if backend.level.priority < requirement.level.priority:
            return None
        if not confirmation_backend_satisfies_constraints(
            backend,
            user_id=user_id,
            required_capabilities=requirement.require_capabilities,
            allowed_principals=requirement.allowed_principals,
            allowed_credentials=requirement.allowed_credentials,
        ):
            return None
        if requirement.methods:
            first_selectable_method = self._confirmation_backend_registry.first_selectable_method(
                requirement,
                user_id=user_id,
                allow_stronger_level=True,
            )
            if first_selectable_method != "totp":
                return None
        return ResolvedConfirmationBackend(backend=backend, fallback_used=False)

    def _queue_pending_action(
        self,
        *,
        session_id: SessionId,
        user_id: UserId,
        workspace_id: WorkspaceId,
        tool_name: ToolName,
        arguments: dict[str, Any],
        public_arguments: dict[str, Any] | None = None,
        sensitive_public_payload: bool = False,
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
        trusted_current_turn_reminder_create: bool = False,
        continuation_user_goal: str = "",
        continuation_mode: str = "",
        origin_turn_id: str = "",
        action_id: str = "",
        execution_attempt_id: str = "",
        result_id: str = "",
        followup_id: str = "",
        start_executing: bool = False,
    ) -> PendingAction:
        degradation = getattr(self, "_pending_state_degradation", None)
        if isinstance(degradation, Mapping):
            raise StatePersistenceDegradedError(
                authority="pending_actions",
                transition=str(degradation.get("transition", "")),
                stage=str(degradation.get("stage", "")),
                reason=str(degradation.get("reason", "pending_state_persistence_degraded")),
            )
        created_at = datetime.now(UTC)
        decision_nonce = "" if start_executing else uuid.uuid4().hex
        confirmation_id = uuid.uuid4().hex
        action_id = action_id.strip() or f"act-{uuid.uuid4().hex}"
        followup_id = followup_id.strip() or f"followup-{uuid.uuid4().hex}"
        execution_attempt_id = (
            (execution_attempt_id.strip() or f"attempt-{uuid.uuid4().hex}")
            if start_executing
            else ""
        )
        result_id = (
            result_id.strip() or f"result-{uuid.uuid4().hex}"
            if start_executing
            else ""
        )
        requirement = (
            confirmation_requirement.model_copy(deep=True)
            if confirmation_requirement is not None
            else legacy_software_confirmation_requirement()
        )
        if not requirement.routeable:
            raise ApprovalRoutingError(
                requirement.route_reason or "confirmation_requirement_conflict"
            )
        normalized_user_id = str(user_id)
        if delivery_target is not None and not normalized_user_id.strip():
            raise ApprovalRoutingError("channel_principal_unavailable")
        backend_resolution = self._channel_usable_confirmation_backend(
            requirement=requirement,
            user_id=normalized_user_id,
            delivery_target=delivery_target,
        )
        if backend_resolution is None:
            backend_resolution = self._confirmation_backend_registry.resolve(
                requirement,
                user_id=normalized_user_id,
            )
        if backend_resolution is None:
            raise ApprovalRoutingError("confirmation_backend_unavailable")
        if public_arguments is not None:
            public_argument_source = public_arguments
        elif sensitive_public_payload:
            public_argument_source = {}
        else:
            public_argument_source = arguments
        trusted_current_turn_reminder_create = bool(
            trusted_current_turn_reminder_create
            and canonical_tool_name(str(tool_name), warn_on_alias=False) == "reminder.create"
            and str(arguments.get("reminder_intent", "")).strip()
            == CURRENT_TURN_REMINDER_CREATE_INTENT
        )
        confirmation_arguments = _redact_sensitive_pending_arguments(
            tool_name,
            public_argument_source,
            hide_internal=True,
        )
        summary = safe_summary(
            action=str(tool_name),
            risk_level=(
                "high" if self._is_high_risk_confirmation(tool_name, arguments) else "medium"
            ),
            arguments=confirmation_arguments,
        )
        warnings = self._confirmation_warning_generator.generate(
            user_id=str(user_id),
            tool_name=str(tool_name),
            arguments=confirmation_arguments,
            taint_labels=[label.value for label in taint_labels or []],
        )
        if trusted_current_turn_reminder_create:
            warnings = [
                warning
                for warning in warnings
                if warning
                not in {
                    "Contains tainted data",
                    "Unusual action for this user",
                }
            ]
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
        if outbound_text and trusted_current_turn_reminder_create:
            leak_result_payload = {
                "detected": False,
                "overlap_score": 0.0,
                "matched_source_ids": [],
                "reason_codes": ["leakcheck:trusted_current_turn_reminder_create"],
                "requires_confirmation": False,
                "detector_version": "m6-leakcheck-v1",
            }
        elif outbound_text:
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
        expires_at = created_at + timedelta(
            seconds=effective_pending_action_ttl_seconds(requirement.timeout_seconds)
        )
        session = self._session_manager.get(session_id)
        normalized_arguments = pep_arguments_for_policy_evaluation(tool_name, arguments)
        normalized_confirmation_arguments = pep_arguments_for_policy_evaluation(
            tool_name,
            confirmation_arguments,
        )
        tool_definition = self._registry.get_tool(tool_name)
        effective_tool_definition = tool_definition or ToolDefinition(
            name=tool_name,
            description="",
            parameters=[],
            capabilities_required=[],
        )
        stable_idempotency_key = ""
        stable_adapter_guarantee_id = ""
        if effective_tool_definition.retry_class == ToolRetryClass.STABLE_IDEMPOTENCY_KEY:
            adapter_registration = self._stable_key_adapter_registration(tool_name)
            if adapter_registration is not None:
                stable_adapter_guarantee_id = adapter_registration.guarantee_id
            stable_idempotency_key = (
                "shisad-"
                + hashlib.sha256(
                    (
                        f"{action_id}\x00{effective_tool_definition.name}\x00"
                        f"{effective_tool_definition.schema_hash()}\x00"
                        f"{stable_adapter_guarantee_id}"
                    ).encode()
                ).hexdigest()
            )
        retry_descriptor = ToolRetryDescriptor.from_tool_definition(
            effective_tool_definition,
            stable_idempotency_key=stable_idempotency_key,
            stable_adapter_guarantee_id=stable_adapter_guarantee_id,
        )
        resolved_destinations = resolve_confirmation_destinations(
            tool_definition=effective_tool_definition,
            arguments=normalized_arguments,
        )
        action_digest = compute_action_digest(
            tool_definition=effective_tool_definition,
            arguments=normalized_arguments,
            destinations=resolved_destinations,
            stable_idempotency_key=stable_idempotency_key,
            stable_adapter_guarantee_id=stable_adapter_guarantee_id,
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
                intent_id=action_id,
                agent_id=self._daemon_id,
                workspace_id=str(workspace_id),
                session_id=str(session_id),
                created_at=created_at,
                expires_at=expires_at,
                action=IntentAction(
                    tool=str(tool_name),
                    display_summary=action_summary.strip(),
                    parameters=dict(normalized_confirmation_arguments),
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
            pending_action_id=action_id,
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
            action_id=action_id,
            origin_turn_id=str(origin_turn_id).strip(),
            action_digest=action_digest,
            execution_authorization_kind=("policy_allow" if start_executing else ""),
            retry_descriptor=retry_descriptor,
            stable_idempotency_key=stable_idempotency_key,
            execution_attempt_id=execution_attempt_id,
            result_id=result_id,
            followup_id=followup_id,
            session_id=session_id,
            user_id=user_id,
            workspace_id=workspace_id,
            task_id=task_id,
            tool_name=tool_name,
            arguments=dict(arguments),
            reason=reason,
            capabilities=set(capabilities),
            created_at=created_at,
            public_arguments=dict(public_arguments) if public_arguments is not None else None,
            sensitive_public_payload=bool(sensitive_public_payload),
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
                    same_session_user_goal_host_patterns=set(
                        pep_context.same_session_user_goal_host_patterns
                    ),
                    context_confirmation_host_patterns=set(
                        pep_context.context_confirmation_host_patterns
                    ),
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
            allowed_channel_principals=(
                [normalized_user_id]
                if delivery_target is not None and normalized_user_id.strip()
                else []
            ),
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
            continuation_user_goal=str(continuation_user_goal).strip(),
            continuation_mode=str(continuation_mode).strip(),
            status="executing" if start_executing else "pending",
            status_reason=(str(reason).strip() if start_executing else ""),
        )
        approval_envelope = approval_envelope.model_copy(
            update={
                "approval_contract_hash": pending_approval_contract_hash(pending),
            }
        )
        pending.approval_envelope = approval_envelope
        pending.approval_envelope_hash = approval_envelope_hash(approval_envelope)
        self._pending_actions[confirmation_id] = pending
        self._pending_by_session.setdefault(session_id, []).append(confirmation_id)
        try:
            self._persist_pending_actions()
        except AtomicWriteError as write_error:
            self._pending_actions.pop(confirmation_id, None)
            session_pending_ids = self._pending_by_session.get(session_id, [])
            remaining_ids = [
                pending_id for pending_id in session_pending_ids if pending_id != confirmation_id
            ]
            if remaining_ids:
                self._pending_by_session[session_id] = remaining_ids
            else:
                self._pending_by_session.pop(session_id, None)
            if write_error.publication_may_have_committed:
                try:
                    self._persist_pending_actions()
                except AtomicWriteError as rollback_error:
                    self._pending_actions[confirmation_id] = pending
                    self._pending_by_session.setdefault(session_id, []).append(confirmation_id)
                    self._pending_state_degradation = {
                        "transition": "queue",
                        "stage": rollback_error.stage.value,
                        "reason": "pending_state_rollback_uncommitted",
                    }
                    raise rollback_error from write_error
            raise
        return pending

    def _persist_pending_actions(self) -> None:
        for pending in self._pending_actions.values():
            prior_local_marker_present = bool(
                pending.recovery_event_identity_trusted_at is not None
                and pending.recovery_anonymous_accounting_id_trusted
            )
            if pending.recovery_event_identity_untrusted:
                marker_is_locally_trusted = bool(
                    pending.recovery_event_identity_untrusted_at is not None
                    and pending.recovery_event_identity_untrusted_at
                    == pending.recovery_event_identity_trusted_at
                    and pending.recovery_anonymous_accounting_id.strip()
                    and pending.recovery_anonymous_accounting_id
                    == pending.recovery_anonymous_accounting_id_trusted
                )
                if not marker_is_locally_trusted:
                    if prior_local_marker_present:
                        _ensure_trusted_recovery_event_identity_marker(pending)
                    else:
                        _clear_recovery_event_identity_marker(pending)
            elif prior_local_marker_present:
                _ensure_trusted_recovery_event_identity_marker(pending)
            elif (
                pending.recovery_event_identity_untrusted_at is not None
                or pending.recovery_anonymous_accounting_id
                or pending.recovery_event_identity_trusted_at is not None
                or pending.recovery_anonymous_accounting_id_trusted
            ):
                _clear_recovery_event_identity_marker(pending)
            canonical_identity = pending_action_state_view(pending).identity
            stored_status = str(pending.status).strip().lower()
            if (
                stored_status in _PENDING_ACTION_STORED_STATUSES - {"pending", "executing"}
                and canonical_identity.result_id
                and not pending.result_id.strip()
            ):
                pending.result_id = canonical_identity.result_id
            if _pending_action_has_started_execution_authority(pending):
                recovery_authority_mac = (
                    self._confirmation_evidence_authenticator.authenticate_recovery_snapshot(
                        _pending_recovery_authority_snapshot(pending)
                    )
                )
                if not recovery_authority_mac:
                    raise ValueError("pending recovery snapshot is not canonical")
                pending.recovery_authority_mac = recovery_authority_mac
            else:
                pending.recovery_authority_mac = ""
        payload = [self._pending_to_dict(item) for item in self._pending_actions.values()]
        atomic_write_bytes(
            self._pending_actions_file,
            json.dumps(payload, indent=2).encode("utf-8"),
            fault_injector=getattr(self, "_pending_state_fault_injector", None),
        )

    @staticmethod
    def _fallback_corrupt_pending_action(
        item: Mapping[str, Any],
    ) -> PendingAction | None:
        confirmation_id, confirmation_id_valid = _loaded_state_text(item.get("confirmation_id", ""))
        if not confirmation_id or not confirmation_id_valid:
            return None
        identity = item.get("identity")
        identity_fields = dict(identity) if isinstance(identity, Mapping) else {}

        def _identity_text(key: str) -> str:
            direct, _ = _loaded_state_text(item.get(key, ""))
            nested, _ = _loaded_state_text(identity_fields.get(key, ""))
            return direct or nested

        created_at_raw, _ = _loaded_state_text(item.get("created_at", ""))
        try:
            created_at = datetime.fromisoformat(created_at_raw)
        except ValueError:
            created_at = datetime.fromtimestamp(0, UTC)
        status, _ = _loaded_state_text(item.get("status", ""))
        execution_attempt_id = _identity_text("execution_attempt_id")
        uncertain_attempt = bool(execution_attempt_id) or status == "executing"
        arguments = dict(item["arguments"]) if isinstance(item.get("arguments"), Mapping) else {}
        session_id, _ = _loaded_state_text(item.get("session_id", ""))
        user_id, _ = _loaded_state_text(item.get("user_id", ""))
        workspace_id, _ = _loaded_state_text(item.get("workspace_id", ""))
        task_id, _ = _loaded_state_text(item.get("task_id", ""))
        tool_name, _ = _loaded_state_text(item.get("tool_name", ""))
        reason, _ = _loaded_state_text(item.get("reason", ""))
        action_digest, _ = _loaded_state_text(item.get("action_digest", ""))
        approval_evidence_hash, _ = _loaded_state_text(item.get("approval_evidence_hash", ""))
        stable_idempotency_key, _ = _loaded_state_text(item.get("stable_idempotency_key", ""))
        provider_operation_id, _ = _loaded_state_text(item.get("provider_operation_id", ""))
        stage2_correlation_id, _ = _loaded_state_text(item.get("stage2_correlation_id", ""))
        stage2_previous_plan_hash, _ = _loaded_state_text(item.get("stage2_previous_plan_hash", ""))
        stage2_plan_hash, _ = _loaded_state_text(item.get("stage2_plan_hash", ""))
        recovery_result = (
            dict(item["recovery_result"])
            if isinstance(item.get("recovery_result"), Mapping)
            else {}
        )
        return PendingAction(
            confirmation_id=confirmation_id,
            decision_nonce="",
            action_id=_identity_text("action_id"),
            origin_turn_id=_identity_text("origin_turn_id"),
            action_digest=action_digest,
            approval_evidence_hash=approval_evidence_hash,
            retry_descriptor=None,
            recovery_result=recovery_result,
            stable_idempotency_key=stable_idempotency_key,
            provider_operation_id=provider_operation_id,
            stage2_correlation_id=stage2_correlation_id,
            stage2_previous_plan_hash=stage2_previous_plan_hash,
            stage2_plan_hash=stage2_plan_hash,
            execution_attempt_id=execution_attempt_id,
            result_id=_identity_text("result_id"),
            followup_id=_identity_text("followup_id"),
            session_id=SessionId(session_id),
            user_id=UserId(user_id),
            workspace_id=WorkspaceId(workspace_id),
            task_id=task_id,
            tool_name=ToolName(tool_name or "unknown"),
            arguments=arguments,
            reason=reason,
            capabilities=set(),
            created_at=created_at,
            status="outcome_unknown" if uncertain_attempt else "failed",
            status_reason=(
                "uncertain_effect_requires_fresh_approval"
                if uncertain_attempt
                else "pending_state_metadata_invalid"
            ),
        )

    def _canonicalize_loaded_pending_identity(
        self,
        item: Mapping[str, Any],
    ) -> tuple[dict[str, Any], bool]:
        normalized = dict(item)
        scheduler = getattr(self, "_scheduler", None)
        raw_identity = item.get("identity")
        binding_fields = (
            "confirmation_id",
            "action_id",
            "origin_turn_id",
            "session_id",
            "user_id",
            "workspace_id",
            "task_id",
            "execution_attempt_id",
            "result_id",
            "followup_id",
        )

        def _shadow_bindings(confirmation_ids: set[str]) -> set[tuple[str, str]]:
            task_ids_for_confirmation = getattr(scheduler, "task_ids_for_confirmation", None)
            if not callable(task_ids_for_confirmation):
                return set()
            return {
                (confirmation_id, task_id)
                for confirmation_id in confirmation_ids
                for task_id in task_ids_for_confirmation(confirmation_id)
            }

        def _disable_tasks(task_ids: set[str]) -> None:
            disable_task = getattr(scheduler, "disable_task", None)
            if not callable(disable_task):
                return
            for task_id in task_ids:
                disable_task(task_id)

        if raw_identity is None:
            legacy_invalid = any(
                key in item and not isinstance(item.get(key), str) for key in binding_fields
            )
            scheduler_accounting_pending, scheduler_marker_valid = _loaded_state_bool(
                item.get("scheduler_accounting_pending", False)
            )
            confirmation_id, confirmation_id_valid = _loaded_state_text(
                item.get("confirmation_id", "")
            )
            task_id, task_id_valid = _loaded_state_text(item.get("task_id", ""))
            confirmation_candidates = (
                {confirmation_id} if confirmation_id_valid and confirmation_id else set()
            )
            task_candidates = {task_id} if task_id_valid and task_id else set()
            shadow_bindings = _shadow_bindings(confirmation_candidates)
            has_terminal_shadow = getattr(
                scheduler,
                "has_terminal_confirmation_shadow",
                None,
            )
            terminal_shadow_present = callable(has_terminal_shadow) and any(
                has_terminal_shadow(
                    shadow_task_id,
                    confirmation_id=shadow_confirmation_id,
                )
                for shadow_confirmation_id, shadow_task_id in shadow_bindings
            )
            if (
                not legacy_invalid
                and scheduler_marker_valid
                and not scheduler_accounting_pending
                and not terminal_shadow_present
            ):
                return normalized, False
            if len(shadow_bindings) == 1:
                canonical_confirmation_id, canonical_task_id = next(iter(shadow_bindings))
                normalized["confirmation_id"] = canonical_confirmation_id
                normalized["task_id"] = canonical_task_id
            else:
                _disable_tasks(task_candidates | {task_id for _, task_id in shadow_bindings})
                normalized["task_id"] = ""
            return normalized, True
        if not isinstance(raw_identity, Mapping):
            confirmation_id, confirmation_id_valid = _loaded_state_text(
                item.get("confirmation_id", "")
            )
            task_id, task_id_valid = _loaded_state_text(item.get("task_id", ""))
            confirmation_candidates = (
                {confirmation_id} if confirmation_id_valid and confirmation_id else set()
            )
            task_candidates = {task_id} if task_id_valid and task_id else set()
            shadow_bindings = _shadow_bindings(confirmation_candidates)
            if len(shadow_bindings) == 1:
                canonical_confirmation_id, canonical_task_id = next(iter(shadow_bindings))
                normalized["confirmation_id"] = canonical_confirmation_id
                normalized["task_id"] = canonical_task_id
            else:
                _disable_tasks(task_candidates | {task_id for _, task_id in shadow_bindings})
                normalized["task_id"] = ""
            return normalized, True

        identity = dict(raw_identity)
        binding_invalid = False
        direct_values: dict[str, str] = {}
        nested_values: dict[str, str] = {}
        for key in binding_fields:
            direct, direct_valid = _loaded_state_text(item.get(key))
            nested, nested_valid = _loaded_state_text(identity.get(key))
            direct_values[key] = direct
            nested_values[key] = nested
            if not direct_valid or not nested_valid or direct != nested:
                binding_invalid = True
            canonical = nested if nested_valid else direct
            normalized[key] = canonical
            identity[key] = canonical

        confirmation_candidates = {
            value
            for value in (
                direct_values["confirmation_id"],
                nested_values["confirmation_id"],
            )
            if value
        }
        if not direct_values["confirmation_id"] or not nested_values["confirmation_id"]:
            binding_invalid = True
        task_candidates = {
            value for value in (direct_values["task_id"], nested_values["task_id"]) if value
        }
        shadow_bindings = _shadow_bindings(confirmation_candidates)
        if shadow_bindings and (not direct_values["task_id"] or not nested_values["task_id"]):
            binding_invalid = True
        stored_status, stored_status_valid = _loaded_state_text(item.get("status", "pending"))
        if (
            shadow_bindings
            and stored_status_valid
            and stored_status in {"approved", "failed", "outcome_unknown"}
            and any(
                not direct_values[key] or not nested_values[key]
                for key in ("execution_attempt_id", "result_id")
            )
        ):
            binding_invalid = True
        if len(shadow_bindings) == 1:
            canonical_confirmation_id, canonical_task_id = next(iter(shadow_bindings))
            normalized["confirmation_id"] = canonical_confirmation_id
            normalized["task_id"] = canonical_task_id
            identity["confirmation_id"] = canonical_confirmation_id
            identity["task_id"] = canonical_task_id
        elif binding_invalid:
            _disable_tasks(task_candidates | {task_id for _, task_id in shadow_bindings})
            normalized["task_id"] = ""
            identity["task_id"] = ""

        normalized["identity"] = identity
        return normalized, binding_invalid

    def _load_pending_actions(self) -> None:
        if not self._pending_actions_file.exists():
            return
        try:
            raw = json.loads(self._pending_actions_file.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return
        if not isinstance(raw, list):
            return
        sensitive_pending_groups: set[tuple[str, str]] = set()
        sensitive_values_by_session: dict[str, list[str]] = {}
        for item in raw:
            if not isinstance(item, Mapping):
                continue
            status = str(item.get("status", "pending")).strip() or "pending"
            if status != "pending":
                continue
            arguments_payload = item.get("arguments")
            if not isinstance(arguments_payload, Mapping):
                continue
            if not _has_sensitive_pending_text(
                str(item.get("tool_name", "")),
                arguments_payload,
            ):
                continue
            session_id = _pending_payload_session(item)
            if session_id:
                grouped_values = sensitive_values_by_session.setdefault(session_id, [])
                for value in _sensitive_pending_text_values(
                    str(item.get("tool_name", "")),
                    arguments_payload,
                ):
                    if value not in grouped_values:
                        grouped_values.append(value)
            group = _pending_payload_group(item)
            if group is None:
                continue
            sensitive_pending_groups.add(group)
        pruned_stale = False
        migrated_legacy_strip_intent = False
        migrated_legacy_channel_principal = False
        migrated_legacy_action_identity = False
        migrated_legacy_decision_nonce = False
        migrated_expired_approval = False
        migrated_attempt_metadata = False
        loaded_terminal_side_effects: list[PendingAction] = []
        for item in raw:
            if not isinstance(item, dict):
                continue
            raw_started_authority_present = (
                _loaded_pending_payload_has_started_execution_authority(item)
            )
            raw_recovery_event_identity_marker_present = (
                _loaded_pending_payload_has_recovery_event_identity_marker(item)
            )
            raw_scheduler_accounting_mode = item.get("scheduler_accounting_mode", "")
            raw_terminal_scheduler_shadow = (
                _loaded_pending_has_terminal_scheduler_shadow(
                    getattr(self, "_scheduler", None),
                    item,
                )
            )
            raw_scheduler_accounting_intent_present = (
                item.get("scheduler_accounting_pending", False) is not False
                or (
                    bool(raw_scheduler_accounting_mode.strip())
                    if isinstance(raw_scheduler_accounting_mode, str)
                    else raw_scheduler_accounting_mode is not None
                )
                or raw_terminal_scheduler_shadow
            )
            recovery_result_json_valid = _native_json_payload_is_valid(
                item.get("recovery_result", {})
            )
            sanitized_item, item_json_valid = _sanitize_loaded_json_payload(item)
            if not isinstance(sanitized_item, dict):
                continue
            item = sanitized_item
            item, identity_binding_invalid = self._canonicalize_loaded_pending_identity(item)
            if (
                raw_recovery_event_identity_marker_present
                and not raw_started_authority_present
            ):
                item["recovery_event_identity_untrusted"] = False
                item["recovery_event_identity_untrusted_at"] = ""
                item["recovery_anonymous_accounting_id"] = ""
                pruned_stale = True
            legacy_mixed_sensitive_payload = False
            erased_recovery_authority_present = False
            try:
                confirmation_id, confirmation_id_valid = _loaded_state_text(
                    item.get("confirmation_id", "")
                )
                if not confirmation_id:
                    continue
                recovery_authority_invalid = not confirmation_id_valid or identity_binding_invalid
                created_at_raw, created_at_valid = _loaded_state_text(item.get("created_at", ""))
                try:
                    created_at = datetime.fromisoformat(created_at_raw)
                except ValueError:
                    created_at = datetime.fromtimestamp(0, UTC)
                    created_at_valid = False
                recovery_authority_invalid = recovery_authority_invalid or not created_at_valid
                session_id_raw, session_id_valid = _loaded_state_text(item.get("session_id", ""))
                session_id = SessionId(session_id_raw)
                recovery_authority_invalid = recovery_authority_invalid or not session_id_valid
                delivery_target_payload, delivery_target_valid = _loaded_state_optional_mapping(
                    item.get("delivery_target")
                )
                try:
                    delivery_target = (
                        DeliveryTarget.model_validate(delivery_target_payload)
                        if delivery_target_payload is not None
                        else None
                    )
                except ValidationError:
                    delivery_target = None
                    delivery_target_valid = False
                recovery_authority_invalid = recovery_authority_invalid or not delivery_target_valid
                preflight_action_payload, preflight_action_valid = _loaded_state_optional_mapping(
                    item.get("preflight_action")
                )
                try:
                    preflight_action = (
                        ControlPlaneAction.model_validate(preflight_action_payload)
                        if preflight_action_payload is not None
                        else None
                    )
                except ValidationError:
                    preflight_action = None
                    preflight_action_valid = False
                recovery_authority_invalid = (
                    recovery_authority_invalid or not preflight_action_valid
                )
                merged_policy_payload, merged_policy_valid = _loaded_state_optional_mapping(
                    item.get("merged_policy")
                )
                try:
                    merged_policy = (
                        ToolExecutionPolicy.model_validate(merged_policy_payload)
                        if merged_policy_payload is not None
                        else None
                    )
                except ValidationError:
                    merged_policy = None
                    merged_policy_valid = False
                recovery_authority_invalid = recovery_authority_invalid or not merged_policy_valid
                execute_after_raw = str(item.get("execute_after", "")).strip()
                try:
                    execute_after = (
                        datetime.fromisoformat(execute_after_raw) if execute_after_raw else None
                    )
                except ValueError:
                    execute_after = None
                    recovery_authority_invalid = True
                expires_at_raw = str(item.get("expires_at", "")).strip()
                try:
                    expires_at = datetime.fromisoformat(expires_at_raw) if expires_at_raw else None
                except ValueError:
                    expires_at = None
                    recovery_authority_invalid = True
                legacy_null_expiry = not expires_at_raw
                pep_context_payload, pep_context_valid = _loaded_state_optional_mapping(
                    item.get("pep_context")
                )
                try:
                    pep_context = (
                        pending_pep_context_from_payload(pep_context_payload)
                        if pep_context_payload is not None
                        else None
                    )
                except (TypeError, ValueError, ValidationError):
                    pep_context = None
                    pep_context_valid = False
                recovery_authority_invalid = recovery_authority_invalid or not pep_context_valid
                pep_elevation_payload, pep_elevation_valid = _loaded_state_optional_mapping(
                    item.get("pep_elevation")
                )
                try:
                    pep_elevation = (
                        pending_pep_elevation_from_payload(pep_elevation_payload)
                        if pep_elevation_payload is not None
                        else None
                    )
                except (TypeError, ValueError, ValidationError):
                    pep_elevation = None
                    pep_elevation_valid = False
                recovery_authority_invalid = recovery_authority_invalid or not pep_elevation_valid
                approval_envelope_payload, approval_envelope_valid = _loaded_state_optional_mapping(
                    item.get("approval_envelope")
                )
                try:
                    approval_envelope = (
                        ApprovalEnvelope.model_validate(approval_envelope_payload)
                        if approval_envelope_payload is not None
                        else None
                    )
                except ValidationError:
                    approval_envelope = None
                    approval_envelope_valid = False
                recovery_authority_invalid = (
                    recovery_authority_invalid or not approval_envelope_valid
                )
                intent_envelope_payload, intent_envelope_valid = _loaded_state_optional_mapping(
                    item.get("intent_envelope")
                )
                try:
                    intent_envelope = (
                        IntentEnvelope.model_validate(intent_envelope_payload)
                        if intent_envelope_payload is not None
                        else None
                    )
                except ValidationError:
                    intent_envelope = None
                    intent_envelope_valid = False
                recovery_authority_invalid = recovery_authority_invalid or not intent_envelope_valid
                confirmation_evidence_payload, confirmation_evidence_valid = (
                    _loaded_state_optional_mapping(item.get("confirmation_evidence"))
                )
                try:
                    confirmation_evidence = (
                        ConfirmationEvidence.model_validate(confirmation_evidence_payload)
                        if confirmation_evidence_payload is not None
                        else None
                    )
                except ValidationError:
                    confirmation_evidence = None
                    confirmation_evidence_valid = False
                recovery_authority_invalid = (
                    recovery_authority_invalid or not confirmation_evidence_valid
                )
                retry_descriptor_payload, retry_descriptor_valid = _loaded_state_optional_mapping(
                    item.get("retry_descriptor")
                )
                try:
                    retry_descriptor = (
                        ToolRetryDescriptor.model_validate(retry_descriptor_payload)
                        if retry_descriptor_payload is not None
                        else None
                    )
                except ValidationError:
                    retry_descriptor = None
                    retry_descriptor_valid = False
                recovery_authority_invalid = (
                    recovery_authority_invalid or not retry_descriptor_valid
                )
                if recovery_authority_invalid:
                    retry_descriptor = None
                raw_retry_generation = item.get("retry_generation", 0)
                if (
                    isinstance(raw_retry_generation, int)
                    and not isinstance(raw_retry_generation, bool)
                    and raw_retry_generation >= 0
                ):
                    retry_generation = raw_retry_generation
                else:
                    retry_generation = 0
                    erased_recovery_authority_present = True
                    retry_descriptor = None
                recovery_started_at_raw = str(item.get("recovery_started_at", "")).strip()
                try:
                    recovery_started_at = (
                        datetime.fromisoformat(recovery_started_at_raw)
                        if recovery_started_at_raw
                        else None
                    )
                except ValueError:
                    recovery_started_at = None
                    retry_descriptor = None
                    erased_recovery_authority_present = True
                recovery_result_payload = item.get("recovery_result", {})
                recovery_result, recovery_result_valid = _loaded_state_mapping(
                    recovery_result_payload
                )
                if not recovery_result_json_valid:
                    recovery_result = {}
                    recovery_result_valid = False
                recovery_accounting_pending, recovery_accounting_pending_valid = _loaded_state_bool(
                    item.get("recovery_accounting_pending", False)
                )
                recovery_effect_invoked, recovery_effect_invoked_valid = _loaded_state_bool(
                    item.get("recovery_effect_invoked", False)
                )
                (
                    recovery_event_identity_untrusted,
                    recovery_event_identity_untrusted_valid,
                ) = _loaded_state_bool(item.get("recovery_event_identity_untrusted", False))
                recovery_event_identity_untrusted_at_raw = str(
                    item.get("recovery_event_identity_untrusted_at", "")
                ).strip()
                try:
                    recovery_event_identity_untrusted_at = (
                        datetime.fromisoformat(recovery_event_identity_untrusted_at_raw)
                        if recovery_event_identity_untrusted_at_raw
                        else None
                    )
                    recovery_event_identity_untrusted_at_valid = (
                        recovery_event_identity_untrusted
                        == (recovery_event_identity_untrusted_at is not None)
                    )
                except ValueError:
                    recovery_event_identity_untrusted_at = None
                    recovery_event_identity_untrusted_at_valid = False
                (
                    recovery_anonymous_accounting_id,
                    recovery_anonymous_accounting_id_valid,
                ) = _loaded_state_text(item.get("recovery_anonymous_accounting_id", ""))
                recovery_anonymous_accounting_id_valid = (
                    recovery_anonymous_accounting_id_valid
                    and recovery_event_identity_untrusted
                    == bool(recovery_anonymous_accounting_id)
                )
                recovery_scheduler_accounted, recovery_scheduler_accounted_valid = (
                    _loaded_state_bool(item.get("recovery_scheduler_accounted", False))
                )
                (
                    recovery_scheduler_posture_captured,
                    recovery_scheduler_posture_captured_valid,
                ) = _loaded_state_bool(item.get("recovery_scheduler_posture_captured", False))
                (
                    recovery_scheduler_restore_enabled,
                    recovery_scheduler_restore_enabled_valid,
                ) = _loaded_state_bool(item.get("recovery_scheduler_restore_enabled", False))
                scheduler_accounting_pending, scheduler_accounting_pending_valid = (
                    _loaded_state_bool(item.get("scheduler_accounting_pending", False))
                )
                scheduler_accounting_mode, scheduler_accounting_mode_valid = _loaded_state_text(
                    item.get("scheduler_accounting_mode", "")
                )
                scheduler_accounting_mode_valid = (
                    scheduler_accounting_mode_valid
                    and scheduler_accounting_mode in _SCHEDULER_ACCOUNTING_MODES
                )
                recovery_authority_invalid = recovery_authority_invalid or not all(
                    (
                        recovery_accounting_pending_valid,
                        recovery_effect_invoked_valid,
                        recovery_event_identity_untrusted_valid,
                        recovery_event_identity_untrusted_at_valid,
                        recovery_anonymous_accounting_id_valid,
                        recovery_scheduler_accounted_valid,
                        recovery_scheduler_posture_captured_valid,
                        recovery_scheduler_restore_enabled_valid,
                        scheduler_accounting_pending_valid,
                        scheduler_accounting_mode_valid,
                        recovery_result_valid,
                    )
                )
                raw_arguments, arguments_valid = _loaded_state_mapping(item.get("arguments", {}))
                recovery_authority_invalid = recovery_authority_invalid or not arguments_valid
                sensitive_public_payload = bool(item.get("sensitive_public_payload", False))
                group = _pending_payload_group(item)
                payload_session_id = _pending_payload_session(item)
                blank_task_sensitive_payload = (
                    group is None
                    and bool(payload_session_id)
                    and _payload_contains_sensitive_value(
                        item,
                        tuple(sensitive_values_by_session.get(payload_session_id, ())),
                    )
                )
                legacy_mixed_sensitive_payload = (
                    (group in sensitive_pending_groups or blank_task_sensitive_payload)
                    and not sensitive_public_payload
                    and not _has_sensitive_pending_text(
                        str(item.get("tool_name", "")),
                        raw_arguments,
                    )
                )
                public_arguments = dict(raw_arguments) if sensitive_public_payload else None
                identity_payload = item.get("identity")
                identity_fields: dict[str, Any]
                if identity_payload is None:
                    identity_fields, identity_valid = {}, True
                else:
                    identity_fields, identity_valid = _loaded_state_mapping(identity_payload)
                recovery_authority_invalid = recovery_authority_invalid or not identity_valid
                loaded_action_id, action_id_valid = _loaded_state_text(item.get("action_id", ""))
                identity_action_id, identity_action_id_valid = _loaded_state_text(
                    identity_fields.get("action_id", "")
                )
                loaded_action_id = loaded_action_id or identity_action_id
                loaded_followup_id, followup_id_valid = _loaded_state_text(
                    item.get("followup_id", "")
                )
                identity_followup_id, identity_followup_id_valid = _loaded_state_text(
                    identity_fields.get("followup_id", "")
                )
                loaded_followup_id = loaded_followup_id or identity_followup_id
                recovery_authority_invalid = recovery_authority_invalid or not all(
                    (
                        action_id_valid,
                        identity_action_id_valid,
                        followup_id_valid,
                        identity_followup_id_valid,
                    )
                )
                if not loaded_action_id or loaded_action_id == confirmation_id:
                    loaded_action_id = ""
                    migrated_legacy_action_identity = True
                if not loaded_followup_id:
                    migrated_legacy_action_identity = True
                loaded_execution_attempt_id, execution_attempt_id_valid = _loaded_state_text(
                    item.get("execution_attempt_id", "")
                )
                identity_execution_attempt_id, identity_execution_attempt_id_valid = (
                    _loaded_state_text(identity_fields.get("execution_attempt_id", ""))
                )
                loaded_execution_attempt_id = (
                    loaded_execution_attempt_id or identity_execution_attempt_id
                )
                loaded_result_id, result_id_valid = _loaded_state_text(item.get("result_id", ""))
                identity_result_id, identity_result_id_valid = _loaded_state_text(
                    identity_fields.get("result_id", "")
                )
                loaded_result_id = loaded_result_id or identity_result_id
                recovery_authority_invalid = recovery_authority_invalid or not all(
                    (
                        execution_attempt_id_valid,
                        identity_execution_attempt_id_valid,
                        result_id_valid,
                        identity_result_id_valid,
                    )
                )
                loaded_recovery_authority_mac, recovery_authority_mac_valid = _loaded_state_text(
                    item.get("recovery_authority_mac", "")
                )
                (
                    loaded_execution_authorization_kind,
                    execution_authorization_kind_valid,
                ) = _loaded_state_text(item.get("execution_authorization_kind", ""))
                execution_authorization_kind_valid = (
                    execution_authorization_kind_valid
                    and loaded_execution_authorization_kind in _EXECUTION_AUTHORIZATION_KINDS
                )
                loaded_stage2_correlation_id, stage2_correlation_id_valid = _loaded_state_text(
                    item.get("stage2_correlation_id", "")
                )
                loaded_stage2_previous_plan_hash, stage2_previous_plan_hash_valid = (
                    _loaded_state_text(item.get("stage2_previous_plan_hash", ""))
                )
                loaded_stage2_plan_hash, stage2_plan_hash_valid = _loaded_state_text(
                    item.get("stage2_plan_hash", "")
                )
                recovery_authority_invalid = recovery_authority_invalid or not all(
                    (
                        stage2_correlation_id_valid,
                        stage2_previous_plan_hash_valid,
                        stage2_plan_hash_valid,
                        execution_authorization_kind_valid,
                    )
                )
                loaded_status, status_valid = _loaded_state_text(item.get("status", "pending"))
                if loaded_status not in _PENDING_ACTION_STORED_STATUSES:
                    status_valid = False
                if not status_valid:
                    loaded_status = "outcome_unknown" if loaded_execution_attempt_id else "failed"
                recovery_authority_invalid = recovery_authority_invalid or not status_valid
                loaded_status_reason, status_reason_valid = _loaded_state_text(
                    item.get("status_reason", "")
                )
                loaded_decision_nonce, decision_nonce_valid = _loaded_state_text(
                    item.get("decision_nonce", "")
                )
                recovery_authority_invalid = recovery_authority_invalid or not all(
                    (status_reason_valid, decision_nonce_valid)
                )
                if legacy_null_expiry and loaded_status == "pending":
                    expires_at = datetime.now(UTC) - timedelta(microseconds=1)
                loaded_action_digest = str(item.get("action_digest", "")).strip()
                if not loaded_action_digest and approval_envelope is not None:
                    loaded_action_digest = str(approval_envelope.action_digest).strip()
                    migrated_attempt_metadata = migrated_attempt_metadata or bool(
                        loaded_action_digest
                    )
                loaded_approval_evidence_hash = str(item.get("approval_evidence_hash", "")).strip()
                if not loaded_approval_evidence_hash and confirmation_evidence is not None:
                    loaded_approval_evidence_hash = str(confirmation_evidence.evidence_hash).strip()
                    migrated_attempt_metadata = migrated_attempt_metadata or bool(
                        loaded_approval_evidence_hash
                    )
                capabilities, capabilities_valid = _loaded_state_capabilities(
                    item.get("capabilities", [])
                )
                warnings, warnings_valid = _loaded_state_string_list(item.get("warnings", []))
                required_methods, required_methods_valid = _loaded_state_string_list(
                    item.get("required_methods", [])
                )
                allowed_principals, allowed_principals_valid = _loaded_state_string_list(
                    item.get("allowed_principals", [])
                )
                allowed_channel_principals, allowed_channel_principals_valid = (
                    _loaded_state_string_list(item.get("allowed_channel_principals", []))
                )
                allowed_credentials, allowed_credentials_valid = _loaded_state_string_list(
                    item.get("allowed_credentials", [])
                )
                leak_check, leak_check_valid = _loaded_state_mapping(item.get("leak_check", {}))
                try:
                    required_level = ConfirmationLevel(
                        item.get("required_level", ConfirmationLevel.SOFTWARE.value)
                    )
                    required_level_valid = True
                except (TypeError, ValueError):
                    required_level = ConfirmationLevel.SOFTWARE
                    required_level_valid = False
                try:
                    required_capabilities = ConfirmationCapabilities.model_validate(
                        item.get("required_capabilities", {})
                    )
                    required_capabilities_valid = True
                except ValidationError:
                    required_capabilities = ConfirmationCapabilities()
                    required_capabilities_valid = False
                try:
                    fallback = ConfirmationFallbackPolicy.model_validate(item.get("fallback", {}))
                    fallback_valid = True
                except ValidationError:
                    fallback = ConfirmationFallbackPolicy()
                    fallback_valid = False
                origin_turn_id, origin_turn_id_valid = _loaded_state_text(
                    item.get("origin_turn_id", "")
                )
                identity_origin_turn_id, identity_origin_turn_id_valid = _loaded_state_text(
                    identity_fields.get("origin_turn_id", "")
                )
                origin_turn_id = origin_turn_id or identity_origin_turn_id
                recovery_authority_invalid = recovery_authority_invalid or not all(
                    (
                        capabilities_valid,
                        warnings_valid,
                        required_methods_valid,
                        allowed_principals_valid,
                        allowed_channel_principals_valid,
                        allowed_credentials_valid,
                        leak_check_valid,
                        required_level_valid,
                        required_capabilities_valid,
                        fallback_valid,
                        origin_turn_id_valid,
                        identity_origin_turn_id_valid,
                    )
                )
                if recovery_authority_invalid:
                    retry_descriptor = None
                pending = PendingAction(
                    confirmation_id=confirmation_id,
                    decision_nonce=loaded_decision_nonce,
                    action_id=loaded_action_id,
                    origin_turn_id=origin_turn_id,
                    action_digest=loaded_action_digest,
                    approval_evidence_hash=loaded_approval_evidence_hash,
                    execution_authorization_kind=loaded_execution_authorization_kind,
                    retry_descriptor=retry_descriptor,
                    retry_generation=retry_generation,
                    recovery_started_at=recovery_started_at,
                    recovery_result=recovery_result,
                    recovery_accounting_pending=recovery_accounting_pending,
                    recovery_effect_invoked=recovery_effect_invoked,
                    recovery_event_identity_untrusted=recovery_event_identity_untrusted,
                    recovery_event_identity_untrusted_at=recovery_event_identity_untrusted_at,
                    recovery_anonymous_accounting_id=recovery_anonymous_accounting_id,
                    recovery_scheduler_accounted=recovery_scheduler_accounted,
                    recovery_scheduler_posture_captured=(recovery_scheduler_posture_captured),
                    recovery_scheduler_restore_enabled=(recovery_scheduler_restore_enabled),
                    scheduler_accounting_pending=scheduler_accounting_pending,
                    scheduler_accounting_mode=scheduler_accounting_mode,
                    stage2_correlation_id=loaded_stage2_correlation_id,
                    stage2_previous_plan_hash=loaded_stage2_previous_plan_hash,
                    stage2_plan_hash=loaded_stage2_plan_hash,
                    stable_idempotency_key=str(item.get("stable_idempotency_key", "")).strip(),
                    provider_operation_id=str(item.get("provider_operation_id", "")).strip(),
                    execution_attempt_id=loaded_execution_attempt_id,
                    result_id=loaded_result_id,
                    followup_id=loaded_followup_id,
                    recovery_authority_mac=loaded_recovery_authority_mac,
                    session_id=session_id,
                    user_id=UserId(str(item.get("user_id", ""))),
                    workspace_id=WorkspaceId(str(item.get("workspace_id", ""))),
                    task_id=str(item.get("task_id", "")),
                    tool_name=ToolName(str(item.get("tool_name", ""))),
                    arguments=raw_arguments,
                    reason=str(item.get("reason", "")),
                    capabilities=capabilities,
                    created_at=created_at,
                    public_arguments=public_arguments,
                    sensitive_public_payload=sensitive_public_payload,
                    delivery_target=delivery_target,
                    preflight_action=preflight_action,
                    execute_after=execute_after,
                    safe_preview=str(item.get("safe_preview", "")),
                    warnings=warnings,
                    leak_check=leak_check,
                    merged_policy=merged_policy,
                    approval_task_envelope_id=str(
                        item.get("approval_task_envelope_id", "")
                    ).strip(),
                    pep_context=pep_context,
                    pep_elevation=pep_elevation,
                    required_level=required_level,
                    required_methods=required_methods,
                    allowed_principals=allowed_principals,
                    allowed_channel_principals=allowed_channel_principals,
                    allowed_credentials=allowed_credentials,
                    required_capabilities=required_capabilities,
                    approval_envelope=approval_envelope,
                    approval_envelope_hash=str(item.get("approval_envelope_hash", "")).strip(),
                    intent_envelope=intent_envelope,
                    confirmation_evidence=confirmation_evidence,
                    fallback=fallback,
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
                    continuation_user_goal=str(item.get("continuation_user_goal", "")).strip(),
                    continuation_mode=str(item.get("continuation_mode", "")).strip(),
                    status=loaded_status,
                    status_reason=loaded_status_reason,
                )
            except (TypeError, ValueError, ValidationError):
                fallback_pending = self._fallback_corrupt_pending_action(item)
                if fallback_pending is None:
                    continue
                pending = fallback_pending
                recovery_authority_invalid = True
                recovery_authority_mac_valid = False
            started_recovery_authority = _pending_action_has_started_execution_authority(pending)
            if raw_started_authority_present and not started_recovery_authority:
                erased_recovery_authority_present = True
            if (
                raw_terminal_scheduler_shadow
                and pending.status == "pending"
                and not started_recovery_authority
            ):
                erased_recovery_authority_present = True
            if started_recovery_authority and not item_json_valid:
                recovery_authority_invalid = True
            recovery_authority_snapshot_mac_valid = False
            if started_recovery_authority:
                recovery_authority_snapshot_mac_valid = (
                    recovery_authority_mac_valid
                    and self._confirmation_evidence_authenticator.verify_recovery_snapshot(
                        _pending_recovery_authority_snapshot(pending),
                        pending.recovery_authority_mac,
                    )
                )
                recovery_authority_invalid = (
                    recovery_authority_invalid or not recovery_authority_snapshot_mac_valid
                )
            pending.recovery_event_identity_trusted_at = (
                pending.recovery_event_identity_untrusted_at
                if recovery_authority_snapshot_mac_valid
                and pending.recovery_event_identity_untrusted
                else None
            )
            pending.recovery_anonymous_accounting_id_trusted = (
                pending.recovery_anonymous_accounting_id
                if recovery_authority_snapshot_mac_valid
                and pending.recovery_event_identity_untrusted
                else ""
            )
            recovery_rejection_accounting_required = pending.recovery_accounting_pending or (
                started_recovery_authority
                and (pending.status == "executing" or recovery_authority_invalid)
            )
            if pending.status == "pending" and (
                erased_recovery_authority_present
                or _pending_action_has_started_execution_authority(pending)
            ):
                pending.status = "outcome_unknown"
                recovery_authority_invalid = True
            if recovery_authority_invalid:
                pruned_stale = True
                pending.retry_descriptor = None
                pending.recovery_effect_invoked = False
                pending.recovery_accounting_pending = recovery_rejection_accounting_required
                if recovery_rejection_accounting_required:
                    _ensure_trusted_recovery_event_identity_marker(pending)
                else:
                    _clear_recovery_event_identity_marker(pending)
                _neutralize_untrusted_recovery_event_identity(pending)
                if started_recovery_authority or pending.status in {
                    "executing",
                    "outcome_unknown",
                }:
                    pending.status = "outcome_unknown"
                    pending.status_reason = "uncertain_effect_requires_fresh_approval"
                    pending.decision_nonce = ""
                elif pending.status == "pending":
                    pending.status = "failed"
                    pending.status_reason = "pending_state_metadata_invalid"
                    pending.decision_nonce = ""
                scheduled_terminal = bool(pending.task_id.strip()) and pending.status in {
                    "approved",
                    "failed",
                    "outcome_unknown",
                }
                scheduled_terminal_attempt = (
                    scheduled_terminal
                    and bool(pending.execution_attempt_id.strip())
                    and bool(pending.result_id.strip())
                )
                scheduler_accounting_intent_present = (
                    raw_scheduler_accounting_intent_present
                    or pending.scheduler_accounting_pending
                    or scheduled_terminal_attempt
                )
                if scheduled_terminal_attempt and not identity_binding_invalid:
                    pending.scheduler_accounting_pending = True
                elif scheduled_terminal or pending.scheduler_accounting_pending:
                    pending.status = "outcome_unknown"
                    pending.status_reason = "uncertain_effect_requires_fresh_approval"
                    pending.decision_nonce = ""
                    pending.scheduler_accounting_pending = False
                _neutralize_untrusted_scheduler_accounting_intent(
                    pending,
                    intent_present=scheduler_accounting_intent_present,
                )
            if (
                pending.status == "pending"
                and pending_action_state_view(pending).lifecycle_state == "expired"
            ):
                self._mark_stale_pending_action(
                    pending,
                    reason="approval_expired",
                    persist=False,
                )
                loaded_terminal_side_effects.append(pending)
                migrated_expired_approval = True
            if (
                not pending.strip_direct_tool_execute_envelope_keys
                and pending.should_strip_direct_tool_execute_envelope_keys()
            ):
                pending.strip_direct_tool_execute_envelope_keys = True
                migrated_legacy_strip_intent = True
            if pending.delivery_target is not None and not pending.allowed_channel_principals:
                channel_principal = str(pending.user_id).strip()
                if channel_principal:
                    pending.allowed_channel_principals = [channel_principal]
                    migrated_legacy_channel_principal = True
                elif pending.status == "pending":
                    pending.status = "failed"
                    pending.status_reason = "channel_principal_unavailable"
                    pruned_stale = True
            if _has_sensitive_pending_text(pending.tool_name, pending.arguments):
                pending.arguments = _redact_sensitive_pending_arguments(
                    pending.tool_name,
                    pending.arguments,
                )
                if pending.status == "pending":
                    pending.status = "failed"
                    pending.status_reason = "sensitive_confirmation_secret_unavailable"
                pruned_stale = True
            elif pending.sensitive_public_payload:
                if pending.public_arguments is None:
                    pending.public_arguments = _redact_sensitive_pending_arguments(
                        pending.tool_name,
                        pending.arguments,
                    )
                if pending.status == "pending":
                    pending.status = "failed"
                    pending.status_reason = "sensitive_confirmation_secret_unavailable"
                pruned_stale = True
            elif legacy_mixed_sensitive_payload:
                pending.arguments = {}
                pending.public_arguments = {}
                pending.sensitive_public_payload = True
                if pending.status == "pending":
                    pending.status = "failed"
                    pending.status_reason = "sensitive_confirmation_secret_unavailable"
                pruned_stale = True
            self._pending_actions[pending.confirmation_id] = pending
            self._pending_by_session.setdefault(
                pending.session_id,
                [],
            ).append(pending.confirmation_id)
            parent_contract_verified = False
            if (
                not pending.decision_nonce
                and pending_action_state_view(pending).is_live_pending
                and pending.approval_envelope is not None
                and pending.approval_envelope.schema_version == "shisad.approval.v2"
            ):
                try:
                    expected_envelope_hash = approval_envelope_hash(pending.approval_envelope)
                    expected_parent_contract_hash = pending_approval_parent_contract_hash(pending)
                except (TypeError, ValueError):
                    pass
                else:
                    parent_contract_verified = safe_compare_sha256(
                        pending.approval_envelope_hash,
                        expected_envelope_hash,
                    ) and safe_compare_sha256(
                        pending.approval_envelope.approval_contract_hash,
                        expected_parent_contract_hash,
                    )
            if parent_contract_verified:
                assert pending.approval_envelope is not None
                pending.decision_nonce = uuid.uuid4().hex
                pending.approval_envelope = pending.approval_envelope.model_copy(
                    update={
                        "approval_contract_hash": pending_approval_contract_hash(pending),
                    }
                )
                pending.approval_envelope_hash = approval_envelope_hash(pending.approval_envelope)
                migrated_legacy_decision_nonce = True
            stale_reason = self._stale_pending_action_reason(pending)
            if stale_reason:
                self._mark_stale_pending_action(
                    pending,
                    reason=stale_reason,
                    persist=False,
                )
                loaded_terminal_side_effects.append(pending)
                pruned_stale = True
            if not pending.decision_nonce and pending_action_state_view(pending).is_live_pending:
                self._mark_stale_pending_action(
                    pending,
                    reason="approval_contract_mismatch",
                    persist=False,
                )
                loaded_terminal_side_effects.append(pending)
                pruned_stale = True
        if (
            pruned_stale
            or migrated_legacy_strip_intent
            or migrated_legacy_channel_principal
            or migrated_legacy_action_identity
            or migrated_legacy_decision_nonce
            or migrated_expired_approval
            or migrated_attempt_metadata
        ):
            self._persist_pending_actions()
        for pending in loaded_terminal_side_effects:
            self._complete_committed_terminal_scheduler_accounting(pending)
        self._recover_loaded_pending_attempts()

    @staticmethod
    def _policy_allow_execution_authority_is_current(pending: PendingAction) -> bool:
        """Validate the distinct, non-human authority for an allowed execution."""

        if pending.execution_authorization_kind != "policy_allow":
            return False
        if (
            pending.confirmation_evidence is not None
            or pending.approval_evidence_hash
            or pending.decision_nonce
        ):
            return False
        preflight_action = pending.preflight_action
        if preflight_action is None or preflight_action.tool_name != str(pending.tool_name):
            return False
        origin = preflight_action.origin
        return (
            origin.session_id == str(pending.session_id)
            and origin.user_id == str(pending.user_id)
            and origin.workspace_id == str(pending.workspace_id)
            and origin.task_id == pending.task_id
        )

    def _stable_key_adapter_registration(
        self,
        tool_name: ToolName,
    ) -> StableIdempotencyAdapter | None:
        registration = self._services.idempotent_recovery_adapters.get(str(tool_name))
        return registration if isinstance(registration, StableIdempotencyAdapter) else None

    def _recovery_descriptor_is_current(
        self,
        pending: PendingAction,
        *,
        retry_class: ToolRetryClass,
    ) -> bool:
        if str(getattr(pending, "status_reason", "")).strip() == "stage2_amendment_pending":
            return False
        if str(getattr(pending, "stage2_correlation_id", "")).strip():
            return False
        policy_allow_authority = self._policy_allow_execution_authority_is_current(pending)
        if pending.execution_authorization_kind and not policy_allow_authority:
            return False
        if self._pending_approval_contract_invalid_reason(
            pending,
            require_evidence=not policy_allow_authority,
        ):
            return False
        descriptor = pending.retry_descriptor
        if descriptor is None:
            return False
        if descriptor.retry_class != retry_class:
            return False
        if descriptor.tool_name != str(pending.tool_name):
            return False
        stable_idempotency_key = pending.stable_idempotency_key
        if retry_class == ToolRetryClass.STABLE_IDEMPOTENCY_KEY:
            if not stable_idempotency_key:
                return False
            if descriptor.stable_idempotency_key != stable_idempotency_key:
                return False
        elif descriptor.stable_idempotency_key or stable_idempotency_key:
            return False
        if pending.retry_generation >= descriptor.max_auto_attempts:
            return False
        tool_definition = self._registry.get_tool(pending.tool_name)
        if tool_definition is None or tool_definition.retry_class != retry_class:
            return False
        stable_adapter_guarantee_id = ""
        if retry_class == ToolRetryClass.STABLE_IDEMPOTENCY_KEY:
            adapter_registration = self._stable_key_adapter_registration(pending.tool_name)
            if adapter_registration is None:
                return False
            stable_adapter_guarantee_id = adapter_registration.guarantee_id
            if descriptor.stable_adapter_guarantee_id != stable_adapter_guarantee_id:
                return False
        expected_descriptor = ToolRetryDescriptor.from_tool_definition(
            tool_definition,
            stable_idempotency_key=stable_idempotency_key,
            stable_adapter_guarantee_id=stable_adapter_guarantee_id,
        )
        if descriptor != expected_descriptor:
            return False
        try:
            normalized_arguments = pep_arguments_for_policy_evaluation(
                pending.tool_name,
                pending.arguments,
            )
            destinations = resolve_confirmation_destinations(
                tool_definition=tool_definition,
                arguments=normalized_arguments,
            )
            expected_action_digest = compute_action_digest(
                tool_definition=tool_definition,
                arguments=normalized_arguments,
                destinations=destinations,
                stable_idempotency_key=stable_idempotency_key,
                stable_adapter_guarantee_id=stable_adapter_guarantee_id,
            )
        except (TypeError, ValueError):
            return False
        if pending.action_digest != expected_action_digest:
            return False
        approval_envelope = pending.approval_envelope
        if approval_envelope is None or approval_envelope.action_digest != expected_action_digest:
            return False
        try:
            expected_approval_envelope_hash = approval_envelope_hash(approval_envelope)
        except (TypeError, ValueError):
            return False
        if expected_approval_envelope_hash != pending.approval_envelope_hash:
            return False
        if not policy_allow_authority:
            evidence = pending.confirmation_evidence
            if evidence is None or not pending.approval_evidence_hash:
                return False
            if evidence.evidence_hash != pending.approval_evidence_hash:
                return False
            if evidence.action_digest != expected_action_digest:
                return False
            if evidence.approval_envelope_hash != pending.approval_envelope_hash:
                return False
            if evidence.decision_nonce != pending.decision_nonce:
                return False
        session = self._session_manager.get(pending.session_id)
        if session is None:
            return False
        if session.user_id != pending.user_id or session.workspace_id != pending.workspace_id:
            return False
        if pending.delivery_target is not None:
            return False
        if not pending.execution_attempt_id or not pending.result_id:
            return False
        if not self._recovery_policy_allows(pending, session=session):
            return False
        expires_at = pending.expires_at
        return expires_at is not None and expires_at > datetime.now(UTC)

    def _recovery_policy_allows(
        self,
        pending: PendingAction,
        *,
        session: Session,
    ) -> bool:
        if self._lockdown_manager.should_block_all_actions(pending.session_id):
            return False
        snapshot = pending.pep_context
        if snapshot is not None:
            context = build_policy_context_for_pending_action(
                session=session,
                pending_session_id=pending.session_id,
                pending_workspace_id=pending.workspace_id,
                pending_user_id=pending.user_id,
                snapshot=snapshot,
                elevation=pending.pep_elevation,
            )
            context.capabilities.intersection_update(session.capabilities)
        else:
            context = PolicyContext(
                capabilities=set(pending.capabilities).intersection(session.capabilities),
                session_id=pending.session_id,
                workspace_id=pending.workspace_id,
                user_id=pending.user_id,
                filesystem_roots=tuple(self._config.assistant_fs_roots),
                trust_level="untrusted",
            )
        context.capabilities = self._lockdown_manager.apply_capability_restrictions(
            pending.session_id,
            context.capabilities,
        )

        live_policy = self._policy_loader.policy
        live_allowlist: set[ToolName] | None = None
        if live_policy.session_tool_allowlist:
            live_allowlist = set(live_policy.session_tool_allowlist)
        elif live_policy.default_deny and live_policy.tools:
            live_allowlist = set(live_policy.tools)
        if live_allowlist is not None:
            context.tool_allowlist = (
                live_allowlist
                if context.tool_allowlist is None
                else context.tool_allowlist.intersection(live_allowlist)
            )

        decision = self._pep.evaluate(
            pending.tool_name,
            pep_arguments_for_policy_evaluation(pending.tool_name, pending.arguments),
            context,
        )
        if decision.kind.value == "reject":
            return False
        if decision.kind.value != "require_confirmation":
            return True
        requirement_payload = decision.confirmation_requirement
        if not isinstance(requirement_payload, Mapping):
            return False
        try:
            requirement = ConfirmationRequirement.model_validate(requirement_payload)
        except ValidationError:
            return False
        backend = self._confirmation_backend_registry.get_backend(
            pending.selected_backend_id or "software.default"
        )
        return (
            pending.confirmation_evidence is not None
            and backend is not None
            and confirmation_evidence_satisfies_requirement(
                requirement=requirement,
                evidence=pending.confirmation_evidence,
                backend=backend,
            )
        )

    def _time_now_recovery_descriptor_is_current(self, pending: PendingAction) -> bool:
        return str(pending.tool_name) == "time.now" and self._recovery_descriptor_is_current(
            pending,
            retry_class=ToolRetryClass.STRUCTURAL_READ,
        )

    def _stable_key_recovery_adapter(self, pending: PendingAction) -> Any | None:
        if not self._recovery_descriptor_is_current(
            pending,
            retry_class=ToolRetryClass.STABLE_IDEMPOTENCY_KEY,
        ):
            return None
        return self._stable_key_adapter_registration(pending.tool_name)

    @staticmethod
    def _recovery_accounting_key(
        pending: PendingAction,
        sink: str,
        *,
        authority_authenticated: bool = True,
    ) -> str:
        if authority_authenticated:
            identity = pending_action_state_view(pending).identity
            payload = {
                "sink": sink,
                "confirmation_id": identity.confirmation_id,
                "action_id": identity.action_id,
                "execution_attempt_id": identity.execution_attempt_id,
                "result_id": identity.result_id,
                "retry_generation": pending.retry_generation,
                "effect_invoked": pending.recovery_effect_invoked,
            }
        else:
            anonymous_accounting_id = pending.recovery_anonymous_accounting_id.strip()
            if not anonymous_accounting_id:
                raise ValueError("anonymous recovery accounting identity unavailable")
            payload = {
                "sink": sink,
                "anonymous_accounting_id": anonymous_accounting_id,
            }
        digest = hashlib.sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        return f"recovery:{digest}"

    @staticmethod
    def _recovery_scheduler_containment_token(pending: PendingAction) -> str:
        identity = pending_action_state_view(pending).identity
        payload = {
            "confirmation_id": identity.confirmation_id,
            "action_id": identity.action_id,
            "execution_attempt_id": identity.execution_attempt_id,
            "task_id": identity.task_id,
        }
        digest = hashlib.sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        return f"recovery-containment:{digest}"

    @staticmethod
    def _recovery_event_timestamp(pending: PendingAction) -> datetime:
        if pending.recovery_started_at is not None:
            return pending.recovery_started_at
        if pending.confirmation_evidence is not None:
            return pending.confirmation_evidence.verified_at
        return pending.created_at

    def _capture_pending_scheduler_posture(self, pending: PendingAction) -> bool:
        task_id = pending.task_id.strip()
        if not task_id:
            return False
        task = self._scheduler.get_task(task_id)
        if task is None:
            return False
        if not pending.recovery_scheduler_posture_captured:
            pending.recovery_scheduler_posture_captured = True
            pending.recovery_scheduler_restore_enabled = bool(getattr(task, "enabled", False))
            return True
        return False

    def _precontain_pending_scheduler_task(self, pending: PendingAction) -> None:
        posture_changed = self._capture_pending_scheduler_posture(pending)
        if not pending.recovery_scheduler_posture_captured:
            return
        if posture_changed:
            self._persist_pending_actions()
        task_id = pending.task_id.strip()
        task = self._scheduler.get_task(task_id)
        if task is None:
            return
        containment_token = self._recovery_scheduler_containment_token(pending)
        if not bool(getattr(task, "enabled", False)):
            existing_token = str(getattr(task, "recovery_containment_token", "")).strip()
            if existing_token != containment_token:
                pending.recovery_scheduler_restore_enabled = False
                self._persist_pending_actions()
            return
        contain_task = getattr(self._scheduler, "contain_task_for_recovery", None)
        if not callable(contain_task) or not contain_task(
            task_id,
            token=containment_token,
        ):
            raise RuntimeError("recovery_scheduler_containment_failed")

    def _record_pending_scheduler_state(self, pending: PendingAction) -> bool:
        task_id = pending.task_id.strip()
        if not task_id:
            changed = not pending.recovery_scheduler_accounted or bool(
                pending.recovery_scheduler_posture_captured
                or pending.recovery_scheduler_restore_enabled
            )
            pending.recovery_scheduler_accounted = True
            pending.recovery_scheduler_posture_captured = False
            pending.recovery_scheduler_restore_enabled = False
            return changed

        scheduler = self._scheduler
        confirmation_id = pending.confirmation_id.strip()
        success = pending.status == "approved"
        accounting_mode = pending.scheduler_accounting_mode.strip()
        if accounting_mode in {"shadow_only", "ambiguous"}:
            changed = not pending.recovery_scheduler_accounted
            if not changed:
                return False
            if accounting_mode == "ambiguous":
                task = scheduler.get_task(task_id)
                if (
                    task is not None
                    and bool(getattr(task, "enabled", False))
                    and not scheduler.disable_task(task_id)
                ):
                    raise RuntimeError("scheduler_accounting_ambiguity_containment_failed")
                logger.warning(
                    "Scheduler accounting intent is ambiguous for confirmation %s; "
                    "task disabled without inventing a run outcome",
                    confirmation_id,
                )
            self._sync_task_confirmation_status(pending)
            pending.recovery_scheduler_accounted = True
            return changed
        outcome_reader = getattr(scheduler, "confirmation_outcome", None)
        recorded_outcome = (
            outcome_reader(task_id, confirmation_id=confirmation_id)
            if callable(outcome_reader)
            else None
        )
        if recorded_outcome is not None and recorded_outcome != success:
            pending.status = "outcome_unknown"
            pending.status_reason = "uncertain_effect_requires_fresh_approval"
            pending.decision_nonce = ""
            self._sync_task_confirmation_status(pending)
            task = scheduler.get_task(task_id)
            if task is not None and not scheduler.disable_task(task_id):
                raise RuntimeError("recovery_scheduler_containment_failed")
            logger.warning(
                "Recovery scheduler outcome conflicts with pending state for %s; task disabled",
                confirmation_id,
            )
            pending.recovery_scheduler_accounted = True
            pending.recovery_scheduler_posture_captured = False
            pending.recovery_scheduler_restore_enabled = False
            return True
        changed = not pending.recovery_scheduler_accounted
        if recorded_outcome is None:
            self._sync_task_confirmation_status(pending)
            recorder = getattr(scheduler, "record_confirmation_outcome", None)
            if not callable(recorder) or not bool(
                recorder(
                    task_id,
                    confirmation_id=confirmation_id,
                    success=success,
                )
            ):
                task = scheduler.get_task(task_id)
                if (
                    task is not None
                    and bool(getattr(task, "enabled", False))
                    and not scheduler.disable_task(task_id)
                ):
                    raise RuntimeError("recovery_scheduler_containment_failed")
                logger.warning(
                    "Recovery scheduler shadow missing for confirmation %s; task disabled",
                    confirmation_id,
                )
                pending.recovery_scheduler_accounted = True
                pending.recovery_scheduler_posture_captured = False
                pending.recovery_scheduler_restore_enabled = False
                return True
            changed = True

        task = scheduler.get_task(task_id)
        should_disable = pending.status == "outcome_unknown"
        if task is not None and success:
            should_disable = should_disable or (
                int(getattr(task, "max_runs", 0)) > 0
                and int(getattr(task, "success_count", 0)) >= int(getattr(task, "max_runs", 0))
            )
        if (
            task is not None
            and should_disable
            and bool(getattr(task, "enabled", False))
            and not scheduler.disable_task(task_id)
        ):
            raise RuntimeError("recovery_scheduler_containment_failed")
        if task is not None and pending.recovery_scheduler_posture_captured:
            release_containment = getattr(
                self._scheduler,
                "release_task_recovery_containment",
                None,
            )
            if not callable(release_containment) or not release_containment(
                task_id,
                token=self._recovery_scheduler_containment_token(pending),
                enable=(not should_disable and pending.recovery_scheduler_restore_enabled),
            ):
                raise RuntimeError("recovery_scheduler_restore_failed")
        if (
            pending.recovery_scheduler_posture_captured
            or pending.recovery_scheduler_restore_enabled
        ):
            changed = True
        pending.recovery_scheduler_posture_captured = False
        pending.recovery_scheduler_restore_enabled = False
        pending.recovery_scheduler_accounted = True
        return changed

    def _complete_pending_scheduler_accounting(self, pending: PendingAction) -> str:
        if not pending.scheduler_accounting_pending:
            return self._recovery_task_cancel_reason(pending)
        scheduler_state_changed = self._record_pending_scheduler_state(pending)
        cancel_reason = self._recovery_task_cancel_reason(pending)
        if cancel_reason:
            if scheduler_state_changed:
                self._persist_pending_actions()
        else:
            self._finalize_pending_scheduler_accounting(pending)
        return cancel_reason

    def _finalize_pending_scheduler_accounting(self, pending: PendingAction) -> None:
        if not pending.scheduler_accounting_pending:
            return
        pending.scheduler_accounting_pending = False
        try:
            self._persist_pending_actions()
        except AtomicWriteError:
            pending.scheduler_accounting_pending = True
            raise

    def _recovery_task_cancel_reason(self, pending: PendingAction) -> str:
        task_id = pending.task_id.strip()
        if not task_id:
            return ""
        if pending.status == "outcome_unknown":
            return "outcome_unknown"
        if pending.status != "approved":
            return ""
        task = self._scheduler.get_task(task_id)
        if task is None:
            return ""
        if int(getattr(task, "max_runs", 0)) > 0 and int(getattr(task, "success_count", 0)) >= int(
            getattr(task, "max_runs", 0)
        ):
            return "max_runs_reached"
        return ""

    def _schedule_recovery_accounting(self, pending: PendingAction) -> None:
        if not pending.recovery_accounting_pending:
            return
        task = asyncio.create_task(
            self._account_recovered_attempt(pending.confirmation_id),
            name=f"shisad-recovery-accounting-{pending.confirmation_id}",
        )
        self._recovery_accounting_tasks.add(task)

        def _accounting_done(completed: asyncio.Task[None]) -> None:
            self._recovery_accounting_tasks.discard(completed)
            if completed.cancelled():
                return
            error = completed.exception()
            if error is not None:
                logger.error(
                    "Recovery accounting failed for confirmation %s",
                    pending.confirmation_id,
                    exc_info=(type(error), error, error.__traceback__),
                )

        task.add_done_callback(_accounting_done)

    async def _cancel_recovered_task_siblings(
        self,
        *,
        pending: PendingAction,
        reason: str,
    ) -> None:
        await self._cancel_pending_actions_for_task(pending.task_id, reason=reason)
        self._finalize_pending_scheduler_accounting(pending)

    def _schedule_recovered_task_cancellation(
        self,
        pending: PendingAction,
        *,
        reason: str,
    ) -> None:
        task = asyncio.create_task(
            self._cancel_recovered_task_siblings(
                pending=pending,
                reason=reason,
            ),
            name=f"shisad-recovery-task-cancel-{pending.confirmation_id}",
        )
        self._recovery_accounting_tasks.add(task)

        def _cancellation_done(completed: asyncio.Task[None]) -> None:
            self._recovery_accounting_tasks.discard(completed)
            if completed.cancelled():
                return
            error = completed.exception()
            if error is not None:
                logger.error(
                    "Recovery sibling cancellation failed for confirmation %s",
                    pending.confirmation_id,
                    exc_info=(type(error), error, error.__traceback__),
                )

        task.add_done_callback(_cancellation_done)

    def _recovery_approval_event_fields(
        self,
        pending: PendingAction,
        *,
        authority_authenticated: bool,
    ) -> dict[str, Any]:
        evidence = pending.confirmation_evidence if authority_authenticated else None
        approval_timestamp = (
            self._recovery_event_timestamp(pending).isoformat()
            if authority_authenticated
            else ""
        )
        return {
            **(
                pending_action_event_identity_fields(pending)
                if authority_authenticated
                else _unauthenticated_recovery_event_identity_fields()
            ),
            "approval_decision_nonce": (evidence.decision_nonce if evidence is not None else ""),
            "approval_timestamp": approval_timestamp,
            **approval_audit_fields(evidence),
        }

    def _recovery_authority_snapshot_mac_is_valid(
        self,
        pending: PendingAction,
    ) -> bool:
        return bool(pending.recovery_authority_mac) and (
            self._confirmation_evidence_authenticator.verify_recovery_snapshot(
                _pending_recovery_authority_snapshot(pending),
                pending.recovery_authority_mac,
            )
        )

    def _recovery_authority_snapshot_is_authenticated(
        self,
        pending: PendingAction,
    ) -> bool:
        return (
            not pending.recovery_event_identity_untrusted
            and self._recovery_authority_snapshot_mac_is_valid(pending)
        )

    def _recovered_authority_invalid_reason(
        self,
        pending: PendingAction,
        *,
        require_live_authority: bool = True,
    ) -> str:
        if not self._recovery_authority_snapshot_is_authenticated(pending):
            return "recovery_authority_mismatch"
        if not require_live_authority:
            return ""
        policy_allow_authority = self._policy_allow_execution_authority_is_current(pending)
        if pending.execution_authorization_kind and not policy_allow_authority:
            return "recovery_authority_mismatch"
        evidence = pending.confirmation_evidence
        require_evidence = not policy_allow_authority and (
            evidence is not None or bool(pending.approval_evidence_hash.strip())
        )
        validation_pending = (
            replace(pending, decision_nonce=evidence.decision_nonce)
            if evidence is not None and not policy_allow_authority
            else pending
        )
        return self._pending_approval_contract_invalid_reason(
            validation_pending,
            require_evidence=require_evidence,
        )

    def _invalidate_recovered_authority(
        self,
        pending: PendingAction,
        *,
        preserve_authenticated_effect_posture: bool = False,
    ) -> None:
        authenticated_effect_invoked = bool(
            preserve_authenticated_effect_posture and pending.recovery_effect_invoked
        )
        pending.status = "outcome_unknown"
        pending.status_reason = "uncertain_effect_requires_fresh_approval"
        pending.decision_nonce = ""
        pending.approval_evidence_hash = ""
        pending.execution_authorization_kind = ""
        pending.confirmation_evidence = None
        pending.preflight_action = None
        if not preserve_authenticated_effect_posture:
            _ensure_trusted_recovery_event_identity_marker(pending)
        _neutralize_untrusted_recovery_event_identity(pending)
        pending.merged_policy = None
        pending.pep_context = None
        pending.pep_elevation = None
        pending.retry_descriptor = None
        pending.provider_operation_id = ""
        pending.recovery_result = {}
        pending.recovery_effect_invoked = authenticated_effect_invoked
        _neutralize_untrusted_scheduler_accounting_intent(pending)

    def _recovery_control_plane_action(
        self,
        pending: PendingAction,
        *,
        session: Session,
    ) -> ControlPlaneAction:
        origin = self._origin_for(
            session=session,
            actor="recovery",
            skill_name=str(pending.arguments.get("skill_name") or "").strip(),
            task_id=pending.task_id,
        )
        if pending.preflight_action is not None:
            return pending.preflight_action
        action = build_action(
            tool_name=str(pending.tool_name),
            arguments=dict(pending.arguments),
            origin=origin,
            risk_tier=RiskTier.LOW,
            workspace_roots=list(self._config.assistant_fs_roots),
        )
        return action.model_copy(update={"timestamp": self._recovery_event_timestamp(pending)})

    async def _account_recovered_attempt(self, confirmation_id: str) -> None:
        pending = self._pending_actions.get(confirmation_id)
        if pending is None or not pending.recovery_accounting_pending:
            return

        recovery_authority_authenticated = self._recovery_authority_snapshot_is_authenticated(
            pending
        )
        terminal_recovery_result_published = bool(
            pending.recovery_effect_invoked
            and pending.retry_generation > 0
            and pending.recovery_started_at is not None
            and pending.status in {"approved", "failed", "outcome_unknown"}
        )
        if self._recovered_authority_invalid_reason(
            pending,
            require_live_authority=not terminal_recovery_result_published,
        ):
            self._invalidate_recovered_authority(
                pending,
                preserve_authenticated_effect_posture=recovery_authority_authenticated,
            )

        execution_key = ""
        accounting_status = ""
        recovery_session: Session | None = None
        if pending.recovery_effect_invoked:
            recovery_session = self._session_manager.get(pending.session_id)
            if recovery_session is None:
                raise RuntimeError("recovery_accounting_session_missing")
            execution_key = control_plane_execution_idempotency_key(
                pending.execution_attempt_id,
            )
            durable_status = str(
                await _call_control_plane(
                    self,
                    "execution_status",
                    idempotency_key=execution_key,
                )
            ).strip()
            recovered_status = (
                "success"
                if pending.status == "approved"
                else "failed"
                if pending.status == "failed"
                else "outcome_unknown"
                if pending.status == "outcome_unknown"
                else ""
            )
            if (
                durable_status in {"success", "failed", "outcome_unknown"}
                and recovered_status
                and recovered_status != durable_status
                and recovered_status != "outcome_unknown"
            ):
                pending.status = "outcome_unknown"
                pending.status_reason = "idempotent_adapter_outcome_conflict"
                pending.decision_nonce = ""
                self._persist_pending_actions()
                self._sync_task_confirmation_status(pending)
            if durable_status in {"success", "failed", "outcome_unknown"}:
                accounting_status = durable_status
            elif recovered_status:
                accounting_status = recovered_status

        success = pending.status == "approved"
        outcome_unknown = pending.status == "outcome_unknown"
        error = "" if success else pending.status_reason or "recovery_failed"
        event_fields = self._recovery_approval_event_fields(
            pending,
            authority_authenticated=recovery_authority_authenticated,
        )
        event_timestamp = (
            self._recovery_event_timestamp(pending)
            if recovery_authority_authenticated
            else pending.recovery_event_identity_untrusted_at or datetime.now(UTC)
        )
        event_session_id = pending.session_id if recovery_authority_authenticated else None
        event_tool_name = pending.tool_name if recovery_authority_authenticated else ToolName("")

        if pending.recovery_effect_invoked:
            if not success:
                await self._event_bus.publish(
                    ToolRejected(
                        event_id=EventId(
                            self._recovery_accounting_key(
                                pending,
                                "audit:ToolRejected",
                                authority_authenticated=recovery_authority_authenticated,
                            )
                        ),
                        timestamp=event_timestamp,
                        session_id=event_session_id,
                        actor="recovery",
                        tool_name=event_tool_name,
                        reason=error,
                        **event_fields,
                    )
                )
            await self._event_bus.publish(
                ToolExecuted(
                    event_id=EventId(
                        self._recovery_accounting_key(
                            pending,
                            "audit:ToolExecuted",
                            authority_authenticated=recovery_authority_authenticated,
                        )
                    ),
                    timestamp=event_timestamp,
                    session_id=event_session_id,
                    actor="recovery",
                    tool_name=event_tool_name,
                    success=success,
                    error=error,
                    details={"outcome_unknown": outcome_unknown},
                    **event_fields,
                )
            )
            if accounting_status and recovery_session is not None:
                await _call_control_plane(
                    self,
                    "record_execution",
                    action=self._recovery_control_plane_action(
                        pending,
                        session=recovery_session,
                    ),
                    success=accounting_status == "success",
                    outcome_unknown=accounting_status == "outcome_unknown",
                    idempotency_key=execution_key,
                )
        else:
            await self._event_bus.publish(
                ToolRejected(
                    event_id=EventId(
                        self._recovery_accounting_key(
                            pending,
                            "audit:ToolRejected",
                            authority_authenticated=recovery_authority_authenticated,
                        )
                    ),
                    timestamp=event_timestamp,
                    session_id=event_session_id,
                    actor="recovery",
                    tool_name=event_tool_name,
                    reason=error,
                    **event_fields,
                )
            )

        self._record_pending_scheduler_state(pending)
        cancel_reason = self._recovery_task_cancel_reason(pending)
        if cancel_reason:
            await self._cancel_pending_actions_for_task(
                pending.task_id,
                reason=cancel_reason,
            )
        if pending.confirmation_evidence is not None:
            self._confirmation_analytics.record(
                user_id=str(pending.user_id),
                decision="approve" if success or outcome_unknown else "reject",
                created_at=pending.created_at,
            )

        pending.recovery_accounting_pending = False
        try:
            self._persist_pending_actions()
        except AtomicWriteError:
            pending.recovery_accounting_pending = True
            raise
        self._sync_task_confirmation_status(pending)

    def _recover_loaded_pending_attempts(self) -> None:
        legacy_scheduler_accounting_marked = False
        scheduler = getattr(self, "_scheduler", None)
        outcome_reader = getattr(scheduler, "confirmation_outcome", None)
        for pending in self._pending_actions.values():
            terminal_status = str(pending.status).strip().lower()
            task_id = pending.task_id.strip()
            confirmation_id = pending.confirmation_id.strip()
            if (
                pending.scheduler_accounting_pending
                or not task_id
                or not confirmation_id
                or pending.scheduler_accounting_mode.strip()
                or terminal_status
                not in {"failed", "rejected", "cancelled", "superseded"}
            ):
                continue
            recorded_outcome = (
                outcome_reader(task_id, confirmation_id=confirmation_id)
                if callable(outcome_reader)
                else None
            )
            if recorded_outcome is None:
                if terminal_status == "cancelled":
                    pending.scheduler_accounting_mode = (
                        "shadow_only"
                        if pending.status_reason
                        in {"max_runs_reached", "outcome_unknown", "task_cancelled"}
                        else "ambiguous"
                    )
                    if pending.scheduler_accounting_mode == "ambiguous":
                        pending.status_reason = "legacy_scheduler_accounting_intent_unknown"
                else:
                    pending.scheduler_accounting_mode = "failure"
                pending.recovery_scheduler_accounted = False
                pending.scheduler_accounting_pending = True
                legacy_scheduler_accounting_marked = True
        if legacy_scheduler_accounting_marked:
            self._persist_pending_actions()

        recovery_not_before = _monotonic() + _AUTO_RECOVERY_STARTUP_BACKOFF_SECONDS
        recovery_backoff_applied = False
        executing = [
            pending
            for pending in self._pending_actions.values()
            if str(pending.status).strip().lower() == "executing"
        ]
        for pending in executing:
            structural_read_recovery = self._time_now_recovery_descriptor_is_current(pending)
            stable_key_adapter = self._stable_key_recovery_adapter(pending)
            if not structural_read_recovery and stable_key_adapter is None:
                pending.status = "outcome_unknown"
                pending.status_reason = "uncertain_effect_requires_fresh_approval"
                pending.decision_nonce = ""
                pending.recovery_effect_invoked = True
                pending.recovery_accounting_pending = True
                self._persist_pending_actions()
                self._sync_task_confirmation_status(pending)
                continue

            pending.retry_generation += 1
            pending.recovery_started_at = datetime.now(UTC)
            pending.status_reason = (
                "structural_retry_started"
                if structural_read_recovery
                else "stable_idempotency_key_retry_started"
            )
            self._persist_pending_actions()
            if not recovery_backoff_applied:
                remaining_backoff = recovery_not_before - _monotonic()
                if remaining_backoff > 0:
                    _sleep(remaining_backoff)
                recovery_backoff_applied = True
            adapter_outcome_unknown = False
            if structural_read_recovery:
                result = current_time_payload(
                    timezone=str(pending.arguments.get("timezone", "")).strip()
                )
                recovered_reason = "recovered_structural_read"
                failure_reason = "structural_read_failed"
            else:
                assert stable_key_adapter is not None
                try:
                    result = dict(
                        stable_key_adapter(
                            dict(pending.arguments),
                            pending.stable_idempotency_key,
                        )
                    )
                    _require_native_json_payload(result)
                except Exception:
                    logger.warning(
                        "Stable-key recovery adapter outcome is uncertain for %s",
                        pending.tool_name,
                        exc_info=True,
                    )
                    result = {
                        "ok": False,
                        "error": "idempotent_adapter_outcome_unknown",
                    }
                    adapter_outcome_unknown = True
                recovered_reason = "recovered_stable_idempotency_key"
                failure_reason = "stable_idempotency_key_retry_failed"
            pending.recovery_result = dict(result)
            pending.provider_operation_id = str(
                result.get("provider_operation_id", pending.provider_operation_id)
            ).strip()
            pending.decision_nonce = ""
            if result.get("ok") is True:
                pending.status = "approved"
                pending.status_reason = recovered_reason
            elif not structural_read_recovery and adapter_outcome_unknown:
                pending.status = "outcome_unknown"
                pending.status_reason = "idempotent_adapter_outcome_unknown"
            else:
                pending.status = "failed"
                error = str(result.get("error", failure_reason)).strip()
                pending.status_reason = f"{failure_reason}:{error}"
            pending.recovery_effect_invoked = True
            pending.recovery_accounting_pending = True
            self._persist_pending_actions()
            self._sync_task_confirmation_status(pending)
        scheduler_state_changed = False
        for pending in self._pending_actions.values():
            if pending.scheduler_accounting_pending:
                cancel_reason = self._complete_pending_scheduler_accounting(pending)
                if cancel_reason:
                    self._schedule_recovered_task_cancellation(
                        pending,
                        reason=cancel_reason,
                    )
                continue
            deferred_stable_key_accounting = (
                pending.recovery_accounting_pending
                and pending.recovery_effect_invoked
                and pending.retry_descriptor is not None
                and pending.retry_descriptor.retry_class == ToolRetryClass.STABLE_IDEMPOTENCY_KEY
            )
            if deferred_stable_key_accounting:
                self._precontain_pending_scheduler_task(pending)
                continue
            if pending.recovery_accounting_pending or pending.status == "outcome_unknown":
                scheduler_state_changed = (
                    self._record_pending_scheduler_state(pending) or scheduler_state_changed
                )
        if scheduler_state_changed:
            self._persist_pending_actions()
        for pending in self._pending_actions.values():
            self._schedule_recovery_accounting(pending)

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
        durable_append_bytes(
            self._pairing_requests_file,
            (json.dumps(payload, ensure_ascii=True, sort_keys=True) + "\n").encode("utf-8"),
        )

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
        action_id: str = "",
        origin_turn_id: str = "",
        execution_attempt_id: str = "",
        result_id: str = "",
        followup_id: str = "",
        workspace_id: WorkspaceId | None = None,
        task_id: str = "",
        delivery_target: DeliveryTarget | None = None,
        approval_confirmation_id: str = "",
        approval_decision_nonce: str = "",
        approval_task_envelope_id: str = "",
        approval_timestamp: str = "",
        approval_evidence: ConfirmationEvidence | None = None,
        strip_direct_tool_execute_envelope_keys: bool = False,
        memory_ingress_context: IngressContext | None = None,
        persist_attempt_before_effect: bool = False,
    ) -> ApprovedToolExecutionResult:
        session = self._session_manager.get(sid)
        if session is None:
            return ApprovedToolExecutionResult(success=False, error="session_missing")

        if persist_attempt_before_effect:
            pending = self._queue_pending_action(
                session_id=sid,
                user_id=user_id,
                workspace_id=(
                    workspace_id
                    if workspace_id is not None
                    else WorkspaceId(str(getattr(session, "workspace_id", "")))
                ),
                tool_name=tool_name,
                arguments=dict(arguments),
                reason=f"{approval_actor}_execution_started",
                capabilities=set(capabilities),
                delivery_target=delivery_target,
                task_id=task_id,
                preflight_action=execution_action,
                merged_policy=merged_policy,
                strip_direct_tool_execute_envelope_keys=(
                    strip_direct_tool_execute_envelope_keys
                ),
                origin_turn_id=origin_turn_id,
                action_id=action_id,
                execution_attempt_id=execution_attempt_id,
                result_id=result_id,
                followup_id=followup_id,
                start_executing=True,
            )
            pending_identity = pending_action_state_view(pending).identity
            try:
                execution = await self._execute_approved_action(
                    sid=sid,
                    user_id=user_id,
                    tool_name=tool_name,
                    arguments=dict(arguments),
                    capabilities=set(capabilities),
                    approval_actor=approval_actor,
                    execution_action=execution_action,
                    merged_policy=merged_policy,
                    user_confirmed=user_confirmed,
                    action_id=pending_identity.action_id,
                    origin_turn_id=pending_identity.origin_turn_id,
                    execution_attempt_id=pending_identity.execution_attempt_id,
                    result_id=pending_identity.result_id,
                    followup_id=pending_identity.followup_id,
                    workspace_id=workspace_id,
                    task_id=task_id,
                    delivery_target=delivery_target,
                    approval_confirmation_id=pending.confirmation_id,
                    approval_decision_nonce=pending.decision_nonce,
                    approval_task_envelope_id=pending.approval_task_envelope_id,
                    approval_timestamp=pending.created_at.isoformat(),
                    approval_evidence=approval_evidence,
                    strip_direct_tool_execute_envelope_keys=(
                        strip_direct_tool_execute_envelope_keys
                    ),
                    memory_ingress_context=memory_ingress_context,
                )
            except (Exception, asyncio.CancelledError):
                await self._contain_confirmed_execution_exception(pending)
                raise

            pending.provider_operation_id = str(execution.provider_operation_id).strip()
            pending.recovery_effect_invoked = True
            if execution.success:
                pending.status = "approved"
                pending.status_reason = "allowed_execution_succeeded"
            elif execution.outcome_unknown:
                pending.status = "outcome_unknown"
                pending.status_reason = execution.error or "allowed_execution_outcome_unknown"
            else:
                pending.status = "failed"
                pending.status_reason = execution.error or "allowed_execution_failed"
            try:
                self._persist_pending_actions()
                self._sync_task_confirmation_status(pending)
            except (Exception, asyncio.CancelledError):
                await self._contain_confirmed_execution_exception(pending)
                raise
            return execution

        tool_name = ToolName(canonical_tool_name(str(tool_name), warn_on_alias=False))
        origin = self._origin_for(
            session=session,
            actor=approval_actor,
            skill_name=str(arguments.get("skill_name") or "").strip(),
            task_id=str(task_id).strip(),
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
        operation_identity = mint_action_operation_identity(
            action_id=action_id,
            origin_turn_id=origin_turn_id,
            execution_attempt_id=execution_attempt_id,
            result_id=result_id,
            followup_id=followup_id,
        )
        control_plane_execution_key = control_plane_execution_idempotency_key(
            operation_identity.execution_attempt_id
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
            **operation_identity.to_event_fields(),
            "user_id": str(user_id),
            "workspace_id": (
                str(workspace_id)
                if workspace_id is not None
                else str(getattr(session, "workspace_id", ""))
            ),
            "task_id": str(task_id).strip(),
            "delivery_target": (
                delivery_target.model_dump(mode="json", exclude_none=True)
                if delivery_target is not None
                else None
            ),
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

        suppressed_browser_reason = _browser_runtime_unavailable_rejection_reason(
            getattr(getattr(self, "_services", None), "browser_status", {}),
            tool_name=tool_name,
        )
        if tool is None and suppressed_browser_reason:
            await self._event_bus.publish(
                ToolRejected(
                    session_id=sid,
                    actor="tool_runtime",
                    tool_name=tool_name,
                    reason=suppressed_browser_reason,
                    **approval_event_fields,
                )
            )
            await self._event_bus.publish(
                ToolExecuted(
                    session_id=sid,
                    actor="tool_runtime",
                    tool_name=tool_name,
                    success=False,
                    error=suppressed_browser_reason,
                    **approval_event_fields,
                )
            )
            await _call_control_plane(
                self,
                "record_execution",
                action=executed_action,
                success=False,
                idempotency_key=control_plane_execution_key,
            )
            return ApprovedToolExecutionResult(
                success=False,
                checkpoint_id=checkpoint_id,
                error=suppressed_browser_reason,
                tool_output=HandlerImplementation._with_tool_output_ingress(
                    self,
                    session=session,
                    tool_output=ToolOutputRecord(
                        tool_name=str(tool_name),
                        content=self._sanitize_tool_output_text(
                            json.dumps(
                                {
                                    "ok": False,
                                    "error": suppressed_browser_reason,
                                },
                                ensure_ascii=True,
                            )
                        ),
                        success=False,
                        taint_labels=label_tool_output(str(tool_name)),
                        arguments=dict(arguments),
                    ),
                ),
            )

        if tool is not None and tool.retry_class == ToolRetryClass.STABLE_IDEMPOTENCY_KEY:
            stable_idempotency_key = ""
            pending_actions = getattr(self, "_pending_actions", {})
            pending_attempt = (
                pending_actions.get(approval_confirmation_id)
                if isinstance(pending_actions, Mapping)
                else None
            )
            if (
                pending_attempt is not None
                and pending_attempt.status == "executing"
                and pending_attempt.tool_name == tool_name
                and pending_attempt.action_id == operation_identity.action_id
                and pending_attempt.execution_attempt_id == operation_identity.execution_attempt_id
            ):
                stable_idempotency_key = pending_attempt.stable_idempotency_key
            adapter_registration = self._stable_key_adapter_registration(tool_name)
            bound_adapter_guarantee_id = str(
                getattr(
                    getattr(pending_attempt, "retry_descriptor", None),
                    "stable_adapter_guarantee_id",
                    "",
                )
            ).strip()
            provider_payload: dict[str, Any]
            provider_operation_id = ""
            provider_outcome_unknown = False
            if not stable_idempotency_key:
                provider_payload = {
                    "ok": False,
                    "error": "stable_idempotency_key_missing",
                }
            elif adapter_registration is None:
                provider_payload = {
                    "ok": False,
                    "error": "idempotent_adapter_unavailable",
                }
            elif bound_adapter_guarantee_id != adapter_registration.guarantee_id:
                provider_payload = {
                    "ok": False,
                    "error": "idempotent_adapter_identity_mismatch",
                }
            else:
                try:
                    provider_payload = dict(
                        adapter_registration(dict(arguments), stable_idempotency_key)
                    )
                    _require_native_json_payload(provider_payload)
                except Exception:
                    logger.warning(
                        "Stable-key adapter outcome is uncertain for %s",
                        tool_name,
                        exc_info=True,
                    )
                    provider_payload = {
                        "ok": False,
                        "error": "idempotent_adapter_outcome_unknown",
                    }
                    provider_outcome_unknown = True
            success = provider_payload.get("ok") is True
            provider_operation_id = str(provider_payload.get("provider_operation_id", "")).strip()
            error = "" if success else str(provider_payload.get("error", "adapter_failed"))
            if not success:
                await self._event_bus.publish(
                    ToolRejected(
                        session_id=sid,
                        actor="tool_runtime",
                        tool_name=tool_name,
                        reason=error,
                        **approval_event_fields,
                    )
                )
            await self._event_bus.publish(
                ToolExecuted(
                    session_id=sid,
                    actor="tool_runtime",
                    tool_name=tool_name,
                    success=success,
                    error=error,
                    details=(
                        {"outcome_unknown": True} if provider_outcome_unknown else {}
                    ),
                    **approval_event_fields,
                )
            )
            await _call_control_plane(
                self,
                "record_execution",
                action=executed_action,
                success=success,
                outcome_unknown=provider_outcome_unknown,
                idempotency_key=control_plane_execution_key,
            )
            return ApprovedToolExecutionResult(
                success=success,
                checkpoint_id=checkpoint_id,
                error=error,
                provider_operation_id=provider_operation_id,
                outcome_unknown=provider_outcome_unknown,
                tool_output=HandlerImplementation._with_tool_output_ingress(
                    self,
                    session=session,
                    tool_output=ToolOutputRecord(
                        tool_name=str(tool_name),
                        content=self._sanitize_tool_output_text(
                            json.dumps(provider_payload, ensure_ascii=True, sort_keys=True)
                        ),
                        success=success,
                        taint_labels=label_tool_output(str(tool_name)),
                        arguments=dict(arguments),
                    ),
                ),
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
                idempotency_key=control_plane_execution_key,
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
                user_id=str(session.user_id),
                workspace_id=str(session.workspace_id),
            )
            records = pack.results
            self._ingestion.record_citations([item.chunk_id for item in records])
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
                idempotency_key=control_plane_execution_key,
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
                        idempotency_key=control_plane_execution_key,
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
                    "user_id": str((target_session or session).user_id),
                    "workspace_id": str((target_session or session).workspace_id),
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
                    idempotency_key=control_plane_execution_key,
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
                idempotency_key=control_plane_execution_key,
            )
            return ApprovedToolExecutionResult(
                success=success,
                checkpoint_id=checkpoint_id,
                error="" if success else delivery_result.reason or "message_send_failed",
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
                idempotency_key=control_plane_execution_key,
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
                        arguments=dict(arguments),
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
                    mcp_payload = {
                        "ok": False,
                        "error": str(exc).strip() or "mcp_tool_failed",
                    }
            return await _execute_structured_payload_tool(
                mcp_payload,
                default_error="mcp_tool_failed",
            )

        if tool is None:
            tool_unavailable_reason = "tool_unavailable"
            await self._event_bus.publish(
                ToolRejected(
                    session_id=sid,
                    actor="tool_runtime",
                    tool_name=tool_name,
                    reason=tool_unavailable_reason,
                    **approval_event_fields,
                )
            )
            await self._event_bus.publish(
                ToolExecuted(
                    session_id=sid,
                    actor="tool_runtime",
                    tool_name=tool_name,
                    success=False,
                    error=tool_unavailable_reason,
                    **approval_event_fields,
                )
            )
            await _call_control_plane(
                self,
                "record_execution",
                action=executed_action,
                success=False,
                idempotency_key=control_plane_execution_key,
            )
            return ApprovedToolExecutionResult(
                success=False,
                checkpoint_id=checkpoint_id,
                error=tool_unavailable_reason,
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
            idempotency_key=control_plane_execution_key,
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
            "time.now": (_structured_time_now, "time_now_failed"),
            "browser.navigate": (
                _structured_browser_navigate,
                "browser_navigate_failed",
            ),
            "browser.read_page": (
                _structured_browser_read_page,
                "browser_read_page_failed",
            ),
            "browser.screenshot": (
                _structured_browser_screenshot,
                "browser_screenshot_failed",
            ),
            "browser.click": (_structured_browser_click, "browser_click_failed"),
            "browser.type_text": (
                _structured_browser_type_text,
                "browser_type_text_failed",
            ),
            "browser.end_session": (
                _structured_browser_end_session,
                "browser_end_session_failed",
            ),
            "realitycheck.search": (
                _structured_realitycheck_search,
                "realitycheck_search_failed",
            ),
            "realitycheck.read": (
                _structured_realitycheck_read,
                "realitycheck_read_failed",
            ),
            "attachment.ingest": (
                _structured_attachment_ingest,
                "attachment_ingest_failed",
            ),
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
            "thread.list": (_structured_thread_list, "thread_list_failed"),
            "thread.inspect": (_structured_thread_inspect, "thread_inspect_failed"),
            "thread.resume": (_structured_thread_resume, "thread_resume_failed"),
            "thread.close": (_structured_thread_close, "thread_close_failed"),
            "thread.why": (_structured_thread_why, "thread_why_failed"),
            "reminder.create": (_structured_reminder_create, "reminder_create_failed"),
            "reminder.list": (_structured_reminder_list, "reminder_list_failed"),
            "evidence.read": (_structured_evidence_read, "evidence_read_failed"),
            "evidence.promote": (
                _structured_evidence_promote,
                "evidence_promote_failed",
            ),
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
            workspace_root=(
                self._config.assistant_fs_roots[0]
                if str(tool.name) == "shell.exec" and self._config.assistant_fs_roots
                else None
            ),
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
            except (
                OSError,
                TypeError,
                ValueError,
                binascii.Error,
            ) as exc:  # pragma: no cover
                errors.append(f"{path}:{exc.__class__.__name__}")
        return restored, deleted, errors
