"""Confirmation UI safety helpers and confirmation analytics."""

from __future__ import annotations

import html
import math
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlparse

HIGH_VALUE_ACTION_TOKENS = ("send", "share", "delete", "egress", "upload")


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
    parameters: list[tuple[str, str]] = field(default_factory=list)
    hidden_fields: list[str] = field(default_factory=list)


def safe_summary(
    *,
    action: str,
    risk_level: str,
    arguments: dict[str, Any],
) -> ConfirmationSummary:
    """Generate a safe, metadata-first summary for confirmation dialogs."""
    params: list[tuple[str, str]] = []
    hidden: list[str] = []
    for key in sorted(arguments.keys()):
        value = arguments[key]
        if isinstance(value, dict):
            params.append((key, f"{{{len(value)} keys}}"))
            hidden.append(key)
            continue
        if isinstance(value, list):
            params.append((key, f"[{len(value)} items]"))
            if value and isinstance(value[0], str):
                hidden.append(key)
            continue
        params.append((key, _summarize_scalar(value)))
    return ConfirmationSummary(
        action=_summarize_scalar(action, max_len=48),
        risk_level=risk_level.upper(),
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
