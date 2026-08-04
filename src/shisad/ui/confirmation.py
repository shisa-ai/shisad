"""Confirmation UI safety helpers and confirmation analytics."""

from __future__ import annotations

import html
import math
import shlex
from collections import defaultdict, deque
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlparse

from shisad.core.api.schema import ActionConfirmResult
from shisad.core.failure_presentation import render_user_facing_failure
from shisad.core.tools.names import canonical_tool_name
from shisad.ui.evidence import sanitize_terminal_field, sanitize_terminal_text

HIGH_VALUE_ACTION_TOKENS = ("send", "share", "delete", "egress", "upload")
_INTERNAL_CONFIRMATION_ARGUMENT_KEYS = frozenset(
    {
        "_control_api_authenticated_write",
        "_internal_ingress_marker",
        "_rpc_peer",
        "action_id",
        "command_intent",
        "confirmation_id",
        "decision_nonce",
        "degraded_mode",
        "filesystem_intent",
        "limits",
        "origin_turn_id",
        "reminder_intent",
        "security_critical",
        "session_id",
        "task_id",
        "tool_name",
        "user_id",
        "workspace_id",
    }
)


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _stringify(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def _escape(value: str) -> str:
    return html.escape(value, quote=False).replace("\n", "\\n")


def _summarize_scalar(value: Any, *, max_len: int = 96) -> str:
    raw = _escape(_stringify(value))
    if len(raw) <= max_len:
        return raw
    return f"{raw[:max_len]}… [{len(raw)} chars]"


def _summarize_shell_command(command: list[Any], *, max_len: int = 240) -> str | None:
    if not command or not all(isinstance(item, str) for item in command):
        return None
    return _summarize_scalar(shlex.join(command), max_len=max_len)


def _summarize_review_scalar(value: Any, *, max_len: int = 96) -> str:
    raw = _stringify(value).replace("\n", "\\n")
    if len(raw) <= max_len:
        return raw
    return f"{raw[:max_len]}… [{len(raw)} chars]"


def _summarize_review_shell_command(
    command: list[Any],
    *,
    max_len: int = 240,
) -> str | None:
    if not command or not all(isinstance(item, str) for item in command):
        return None
    return _summarize_review_scalar(shlex.join(command), max_len=max_len)


def _recipient_hint(arguments: dict[str, Any]) -> str:
    for key in ("to", "recipient", "email", "destination", "url"):
        value = arguments.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def _external_destination(value: str) -> bool:
    parsed = urlparse(value if "://" in value else f"mailto://{value}")
    host = (parsed.hostname or "").lower()
    if not host and "@" in value:
        host = value.split("@", 1)[-1].lower().strip()
    if not host:
        return False
    return not (host.endswith(".internal") or host.endswith(".local") or host == "localhost")


@dataclass(slots=True)
class ConfirmationSummary:
    """Sanitized summary payload for confirmation rendering."""

    action: str
    risk_level: str
    review: str
    parameters: list[tuple[str, str]] = field(default_factory=list)
    hidden_fields: list[str] = field(default_factory=list)


def public_confirmation_arguments(
    action: str,
    arguments: Mapping[str, Any],
) -> dict[str, Any]:
    """Return typed tool arguments without daemon/control routing fields."""
    _ = canonical_tool_name(action, warn_on_alias=False)
    return {
        key: value
        for key, value in arguments.items()
        if key not in _INTERNAL_CONFIRMATION_ARGUMENT_KEYS
    }


def _review_value(arguments: Mapping[str, Any], *keys: str) -> str:
    for key in keys:
        value = arguments.get(key)
        if isinstance(value, str) and value.strip():
            return _summarize_review_scalar(value.strip(), max_len=160)
    return ""


def _action_review(action: str, arguments: Mapping[str, Any]) -> str:
    normalized_action = canonical_tool_name(action, warn_on_alias=False)
    if normalized_action == "shell.exec":
        command = arguments.get("command")
        if isinstance(command, list):
            command_summary = _summarize_review_shell_command(command)
            if command_summary:
                return f"Run command: {command_summary}"
    if normalized_action in {"file.read", "fs.read", "fs.list"}:
        path = _review_value(arguments, "path")
        if path:
            verb = "List files at" if normalized_action == "fs.list" else "Read file"
            return f"{verb}: {path}"
    if normalized_action in {"file.write", "fs.write", "fs.delete"}:
        path = _review_value(arguments, "path")
        if path:
            verb = "Delete file" if normalized_action == "fs.delete" else "Write file"
            return f"{verb}: {path}"
    if normalized_action == "web.fetch":
        url = _review_value(arguments, "url")
        if url:
            return f"Fetch URL: {url}"
    if normalized_action == "web.search":
        query = _review_value(arguments, "query")
        if query:
            return f"Search the web for: {query}"
    if normalized_action == "http.request":
        url = _review_value(arguments, "url")
        method = _review_value(arguments, "method") or "GET"
        if url:
            return f"Send {method.upper()} request to: {url}"
    if normalized_action == "message.send":
        recipient = _review_value(arguments, "recipient", "to")
        channel = _review_value(arguments, "channel")
        if recipient and channel:
            return f"Send message to {recipient} on {channel}"
        if recipient:
            return f"Send message to: {recipient}"
    if normalized_action == "reminder.create":
        message = _review_value(arguments, "message")
        when = _review_value(arguments, "when")
        if message and when:
            return f"Create reminder: {message} — {when}"
        if message:
            return f"Create reminder: {message}"
    if normalized_action == "browser.navigate":
        url = _review_value(arguments, "url")
        if url:
            return f"Navigate browser to: {url}"
    if normalized_action == "browser.click":
        target = _review_value(arguments, "description", "target")
        if target:
            return f"Click browser target: {target}"
    if normalized_action == "browser.type_text":
        target = _review_value(arguments, "description", "target")
        return f"Type text into browser target: {target}" if target else "Type text in browser"
    return f"Run {_summarize_review_scalar(action, max_len=48)}"


def safe_summary(
    *,
    action: str,
    risk_level: str,
    arguments: dict[str, Any],
) -> ConfirmationSummary:
    """Generate a safe, metadata-first summary for confirmation dialogs."""
    params: list[tuple[str, str]] = []
    hidden: list[str] = []
    normalized_action = canonical_tool_name(action, warn_on_alias=False)
    public_arguments = public_confirmation_arguments(action, arguments)
    for key in sorted(public_arguments.keys()):
        value = public_arguments[key]
        if isinstance(value, dict):
            params.append((key, f"{{{len(value)} keys}}"))
            hidden.append(key)
            continue
        if isinstance(value, list):
            if normalized_action == "shell.exec" and key == "command":
                command_summary = _summarize_shell_command(value)
                if command_summary is not None:
                    params.append((key, command_summary))
                    continue
            params.append((key, f"[{len(value)} items]"))
            if value and isinstance(value[0], str):
                hidden.append(key)
            continue
        params.append((key, _summarize_scalar(value)))
    return ConfirmationSummary(
        action=_summarize_scalar(action, max_len=48),
        risk_level=risk_level.upper(),
        review=_action_review(normalized_action, public_arguments),
        parameters=params,
        hidden_fields=hidden,
    )


def render_structured_confirmation(
    summary: ConfirmationSummary,
    *,
    warnings: list[str] | None = None,
) -> str:
    """Render a deterministic structured confirmation card."""
    warnings = warnings or []
    lines = [
        "ACTION CONFIRMATION",
        f"Review: {summary.review}",
        f"Action: {summary.action}",
        f"Risk Level: {summary.risk_level}",
        "PARAMETERS:",
    ]
    for key, value in summary.parameters:
        lines.append(f"  {key}: {value}")
    if warnings:
        lines.append("WARNINGS:")
        for warning in warnings:
            lines.append(f"  - {warning}")
    return "\n".join(lines)


@dataclass(frozen=True, slots=True)
class CompactConfirmationReview:
    """Small review projection extracted from the closed safe-preview format."""

    review: str
    risk_level: str


def compact_confirmation_review(
    preview: object,
    *,
    fallback_action: object,
) -> CompactConfirmationReview:
    """Extract only machine-owned review labels from a structured preview."""

    safe_preview = sanitize_terminal_text(str(preview or ""))
    lines = safe_preview.splitlines()
    review = ""
    risk_level = ""
    if (
        len(lines) >= 5
        and lines[0].strip() == "ACTION CONFIRMATION"
        and lines[1].startswith("Review:")
        and lines[2].startswith("Action:")
        and lines[3].startswith("Risk Level:")
        and lines[4].strip() == "PARAMETERS:"
    ):
        review = lines[1].partition(":")[2].strip()
        risk_level = lines[3].partition(":")[2].strip().upper()
    if not review:
        action = sanitize_terminal_field(str(fallback_action or "").strip())
        review = f"Run {action or 'pending action'}"
    return CompactConfirmationReview(
        review=review,
        risk_level=risk_level or "UNKNOWN",
    )


def render_compact_confirmation_review(
    preview: object,
    *,
    fallback_action: object,
) -> str:
    """Render the compact channel-neutral review without raw parameters."""

    compact = compact_confirmation_review(preview, fallback_action=fallback_action)
    return f"Review: {compact.review}\nRisk Level: {compact.risk_level}"


def _preview_confirmation_tool_text(
    value: object,
    *,
    max_chars: int = 1600,
    max_lines: int = 24,
) -> str:
    text = sanitize_terminal_text(str(value or "")).strip()
    if not text:
        return ""
    lines = text.splitlines()
    truncated = len(lines) > max_lines or len(text) > max_chars
    preview = "\n".join(lines[:max_lines])
    if len(preview) > max_chars:
        preview = preview[:max_chars].rstrip()
    if truncated:
        preview = f"{preview}\n... (truncated)"
    return preview


def _confirmation_tool_error_detail_line(
    payload: dict[str, Any],
    *,
    max_chars: int = 240,
) -> str:
    details = payload.get("details")
    if not isinstance(details, dict):
        return ""
    raw_detail = ""
    for key in ("stderr", "stdout"):
        value = details.get(key)
        if isinstance(value, str) and value.strip():
            raw_detail = value
            break
    if not raw_detail and details.get("exit_code") not in ("", None):
        raw_detail = f"exit_code={details.get('exit_code')}"
    text = sanitize_terminal_text(raw_detail).strip()
    if not text:
        return ""
    first_line = text.splitlines()[0].strip()
    if len(first_line) > max_chars:
        first_line = f"{first_line[: max_chars - 3].rstrip()}..."
    if not first_line:
        return ""
    return f"  detail: {sanitize_terminal_field(first_line)}"


def render_confirmed_tool_output(record: dict[str, Any]) -> list[str]:
    """Render one confirmed tool output for ordinary human-facing terminals."""

    tool_name = sanitize_terminal_field(str(record.get("tool_name", "")).strip() or "tool")
    payload = record.get("payload")
    if not isinstance(payload, dict):
        return [f"{tool_name}: completed."]
    path = sanitize_terminal_field(str(payload.get("path", "")).strip())
    ok_value = payload.get("ok")
    ok_suffix = "" if ok_value in ("", None) else f" ok={bool(ok_value)}"
    error = sanitize_terminal_field(str(payload.get("error", "")).strip())
    if tool_name == "fs.list":
        entries = payload.get("entries")
        count = payload.get("count", len(entries) if isinstance(entries, list) else 0)
        header = f"fs.list returned {count} entr{'y' if count == 1 else 'ies'}"
        if path:
            header = f"{header} for {path}"
        lines = [f"{header}."]
        if isinstance(entries, list) and entries:
            names: list[str] = []
            for entry in entries[:12]:
                if isinstance(entry, dict):
                    name = str(entry.get("name") or entry.get("path") or "").strip()
                else:
                    name = str(entry).strip()
                if name:
                    names.append(sanitize_terminal_field(name))
            if names:
                lines.append("Entries: " + ", ".join(names))
                if len(entries) > len(names):
                    lines.append(f"... ({len(entries) - len(names)} more)")
        return lines
    if tool_name == "fs.read":
        content = str(payload.get("content", "") or "")
        header = "fs.read completed"
        if path:
            header = f"fs.read read {path}"
        if content:
            header = f"{header} ({len(content)} chars)."
            preview = _preview_confirmation_tool_text(content)
            return [header, preview] if preview else [header]
        if error:
            return [f"{header} failed: {error}."]
        return [f"{header}{ok_suffix}."]
    if tool_name == "web.fetch":
        url = sanitize_terminal_field(str(payload.get("url", "")).strip())
        title = sanitize_terminal_field(str(payload.get("title", "")).strip())
        content = str(payload.get("content", "") or payload.get("text", "") or "")
        header = "web.fetch completed"
        if url:
            header = f"web.fetch fetched {url}"
        if title:
            header = f"{header}: {title}"
        preview = _preview_confirmation_tool_text(content, max_chars=1000, max_lines=12)
        if not preview and error:
            return [f"{header} failed: {error}."]
        return [f"{header}.", preview] if preview else [f"{header}{ok_suffix}."]
    if tool_name.startswith("note."):
        return [f"{tool_name}: completed{ok_suffix}."]
    summary_parts = [f"{tool_name}: completed{ok_suffix}."]
    for key in ("status", "count", "error"):
        value = payload.get(key)
        if value not in ("", None, [], {}):
            summary_parts.append(f"{key}={sanitize_terminal_field(str(value))}")
    lines = [" ".join(summary_parts)]
    if error:
        detail_line = _confirmation_tool_error_detail_line(payload)
        if detail_line:
            lines.append(detail_line)
    return lines


def render_action_confirm_result(result: ActionConfirmResult) -> str:
    """Render an action-confirm result for ordinary CLI and TUI output."""

    confirmation_id = sanitize_terminal_field(result.confirmation_id)
    if result.failure is not None:
        lines = [f"Action {confirmation_id}", render_user_facing_failure(result.failure)]
        if result.checkpoint_id:
            lines.append(f"checkpoint={sanitize_terminal_field(result.checkpoint_id)}")
        return "\n".join(lines)
    if result.confirmed:
        status = sanitize_terminal_field(
            str(result.status or result.status_reason or result.reason or "").strip()
        )
        first = f"Confirmed {confirmation_id}"
        if status:
            first = f"{first}: {status}"
    else:
        status = sanitize_terminal_field(
            str(result.reason or result.status_reason or result.status or "").strip()
        )
        first = f"Confirmation failed for {confirmation_id}"
        if status:
            first = f"{first}: {status}"
    lines = [first]
    if (
        not result.confirmed
        and result.reason
        and result.status_reason
        and result.reason != result.status_reason
    ):
        lines.append(f"status_reason={sanitize_terminal_field(result.status_reason)}")
    if not result.confirmed and result.retry_after_seconds is not None:
        retry_after = sanitize_terminal_field(str(result.retry_after_seconds))
        lines.append(f"retry_after_seconds={retry_after}")
    if result.checkpoint_id:
        lines.append(f"checkpoint={sanitize_terminal_field(result.checkpoint_id)}")
    for record in result.tool_outputs:
        lines.extend(render_confirmed_tool_output(record))
    return "\n".join(line for line in lines if str(line).strip())


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _preview_excerpt(value: Any, *, max_len: int = 320, max_lines: int = 8) -> str:
    raw = str(value or "").strip()
    if not raw:
        return ""
    lines = [line.strip() for line in raw.splitlines() if line.strip()]
    excerpt = " | ".join(lines[:max_lines])
    if len(excerpt) <= max_len:
        return excerpt
    return f"{excerpt[:max_len]}..."


def approval_proof_placeholder(selected_method: str) -> str:
    method = selected_method.strip().lower()
    if method == "recovery_code":
        return "<recovery-code>"
    if method == "totp":
        return "<totp-code>"
    return "<proof-code>"


def render_pending_action(action: Mapping[str, Any]) -> str:
    """Render a compact pending-action row from structured daemon state."""
    confirmation_id = str(action.get("confirmation_id", "")).strip()
    tool_name = str(action.get("tool_name", "")).strip() or "pending action"
    status = (
        str(action.get("lifecycle_state", "")).strip()
        or str(action.get("status", "")).strip()
        or "pending"
    )
    risk_level = str(action.get("risk_level", "")).strip() or "unknown"
    proof_tier = str(action.get("required_proof_tier", "")).strip() or "unknown"
    selected_method = str(action.get("selected_backend_method", "")).strip() or "software"
    capability = _mapping(action.get("channel_capability"))
    route = str(capability.get("approval_route", "")).strip() or "unknown"
    can_carry = bool(capability.get("can_carry", False))
    can_collect_inline_totp = (
        bool(capability.get("can_collect_selected_method", False)) and selected_method == "totp"
    )
    can_reject = bool(capability.get("can_reject", True))
    requires_second_factor = bool(
        capability.get("requires_second_factor", False)
    ) or selected_method in {"totp", "recovery_code"}
    lines = [
        f"{confirmation_id} tool={tool_name} status={status}",
        f"risk={risk_level} proof={proof_tier} method={selected_method} route={route}",
    ]
    lifetime_parts: list[str] = []
    try:
        age_seconds = max(0, int(action.get("age_seconds", 0) or 0))
    except (TypeError, ValueError):
        age_seconds = 0
    lifetime_parts.append(f"age={age_seconds}s")
    created_at = str(action.get("created_at", "")).strip()
    if created_at:
        lifetime_parts.append(f"created_at={created_at}")
    expires_at = str(action.get("expires_at", "")).strip()
    if expires_at:
        lifetime_parts.append(f"expires_at={expires_at}")
    origin_turn_id = str(action.get("origin_turn_id", "")).strip()
    if origin_turn_id:
        lifetime_parts.append(f"origin_turn={origin_turn_id}")
    status_reason = str(action.get("status_reason", "")).strip()
    if status_reason:
        lifetime_parts.append(f"state_reason={status_reason}")
    lines.append(" ".join(lifetime_parts))
    if can_carry or can_collect_inline_totp:
        if requires_second_factor:
            proof_placeholder = approval_proof_placeholder(selected_method)
            lines.append(f"approve: c {confirmation_id} {proof_placeholder}")
        else:
            lines.append(f"approve: c {confirmation_id}")
    else:
        reason = str(capability.get("cannot_carry_reason", "")).strip() or "surface_cannot_carry"
        lines.append(f"approve: cannot carry on this surface ({reason})")
    if can_reject:
        lines.append(f"reject: x {confirmation_id}")
    preview = _preview_excerpt(action.get("safe_preview"))
    if preview:
        lines.append(f"preview: {preview}")
    warnings = action.get("warnings")
    if isinstance(warnings, list) and warnings:
        warning_labels = [str(warning).strip() for warning in warnings if str(warning).strip()]
        if warning_labels:
            labels = "; ".join(warning_labels)
            lines.append(f"warnings={len(warning_labels)}: {labels}")
        else:
            lines.append(f"warnings={len(warnings)}")
    return "\n    ".join(lines)


class ConfirmationWarningGenerator:
    """Generate high-signal warning labels for confirmations."""

    def __init__(self) -> None:
        self._seen_recipients: dict[str, set[str]] = defaultdict(set)
        self._seen_actions: dict[str, set[str]] = defaultdict(set)

    def generate(
        self,
        *,
        user_id: str,
        tool_name: str,
        arguments: dict[str, Any],
        taint_labels: list[str] | None = None,
    ) -> list[str]:
        warnings: list[str] = []
        recipient = _recipient_hint(arguments)
        if recipient and recipient not in self._seen_recipients[user_id]:
            warnings.append("First-time recipient/destination")
        if recipient and _external_destination(recipient):
            warnings.append("External destination")
        if taint_labels and any(
            label.lower() in {"untrusted", "sensitive"} for label in taint_labels
        ):
            warnings.append("Contains tainted data")
        known_actions = self._seen_actions[user_id]
        if known_actions and tool_name not in known_actions:
            warnings.append("Unusual action for this user")
        lowered = tool_name.lower()
        if any(token in lowered for token in HIGH_VALUE_ACTION_TOKENS):
            warnings.append("High-value action")

        if recipient:
            self._seen_recipients[user_id].add(recipient)
        self._seen_actions[user_id].add(tool_name)
        return warnings


@dataclass(slots=True)
class ConfirmationDecision:
    """A single confirmation decision record."""

    user_id: str
    decision: str
    created_at: datetime
    decided_at: datetime

    @property
    def response_seconds(self) -> float:
        return max(0.0, (self.decided_at - self.created_at).total_seconds())


class ConfirmationAnalytics:
    """Track confirmation hygiene and produce operator analytics."""

    def __init__(self, *, max_records_per_user: int = 2048) -> None:
        self._records: dict[str, deque[ConfirmationDecision]] = defaultdict(
            lambda: deque(maxlen=max_records_per_user)
        )

    def record(
        self,
        *,
        user_id: str,
        decision: str,
        created_at: datetime | None = None,
        decided_at: datetime | None = None,
    ) -> None:
        created = created_at or _utc_now()
        decided = decided_at or _utc_now()
        self._records[user_id].append(
            ConfirmationDecision(
                user_id=user_id,
                decision=decision.lower().strip(),
                created_at=created,
                decided_at=decided,
            )
        )

    def metrics(self, *, user_id: str, window_seconds: int = 900) -> dict[str, Any]:
        now = _utc_now()
        cutoff = now.timestamp() - float(window_seconds)
        records = [
            record
            for record in self._records.get(user_id, [])
            if record.decided_at.timestamp() >= cutoff
        ]
        if not records:
            return {
                "user_id": user_id,
                "decisions": 0,
                "approve_rate": 0.0,
                "median_response_seconds": 0.0,
                "rubber_stamping": False,
                "fatigue_detected": False,
            }

        approved = sum(1 for record in records if record.decision == "approve")
        response_times = sorted(record.response_seconds for record in records)
        midpoint = len(response_times) // 2
        if len(response_times) % 2 == 0:
            median_response = (response_times[midpoint - 1] + response_times[midpoint]) / 2.0
        else:
            median_response = response_times[midpoint]
        approve_rate = approved / float(len(records))
        rubber = len(records) >= 10 and approve_rate >= 0.9
        fatigue = self._fatigue_detected(records)
        return {
            "user_id": user_id,
            "decisions": len(records),
            "approve_rate": round(approve_rate, 4),
            "median_response_seconds": round(median_response, 3),
            "rubber_stamping": rubber,
            "fatigue_detected": fatigue,
        }

    def users(self) -> list[str]:
        return sorted(self._records.keys())

    @staticmethod
    def _fatigue_detected(records: list[ConfirmationDecision]) -> bool:
        if len(records) < 6:
            return False
        ordered = sorted(records, key=lambda record: record.decided_at)
        y = [record.response_seconds for record in ordered]
        x = list(range(len(y)))
        mean_x = sum(x) / len(x)
        mean_y = sum(y) / len(y)
        numerator = sum((xv - mean_x) * (yv - mean_y) for xv, yv in zip(x, y, strict=False))
        denominator = sum((xv - mean_x) ** 2 for xv in x)
        if denominator <= 0:
            return False
        slope = numerator / denominator
        # Negative slope means responses are becoming faster. Require meaningful trend.
        return slope <= -0.25 and math.fabs(slope) >= 0.25
