"""Action monitor (clean-room guardrail layer)."""

from __future__ import annotations

from enum import StrEnum
from typing import Any, ClassVar

from pydantic import BaseModel, Field

from shisad.core.tools.names import canonical_tool_name


class MonitorDecisionType(StrEnum):
    APPROVE = "approve"
    REJECT = "reject"
    SUSPICIOUS = "suspicious"
    ESCALATE = "escalate"


class MonitorDecision(BaseModel):
    kind: MonitorDecisionType
    reason: str = ""
    flags: list[str] = Field(default_factory=list)


class ActionMonitor:
    """Deterministic M2 monitor with clean-room constraints."""

    _HIGH_RISK_TOOLS: ClassVar[set[str]] = {
        "http.request",
        "send_email",
        "file.write",
        "shell.exec",
    }
    _SUSPICIOUS_ARG_TOKENS: ClassVar[set[str]] = {
        "evil.com",
        "attacker",
        "exfiltrate",
        "bypass",
        "steal",
        "ignore policy",
    }

    def evaluate(self, *, user_goal: str, actions: list[Any]) -> MonitorDecision:
        if not actions:
            return MonitorDecision(kind=MonitorDecisionType.APPROVE)

        goal_text = user_goal.lower()
        reject_flags: list[str] = []
        suspicious_flags: list[str] = []

        for action in actions:
            tool = canonical_tool_name(str(getattr(action, "tool_name", "")))
            argument_text = self._flatten_arguments(getattr(action, "arguments", {}))
            if any(token in argument_text for token in self._SUSPICIOUS_ARG_TOKENS):
                reject_flags.append(f"{tool}:suspicious_argument_content")
                continue

            if tool in self._HIGH_RISK_TOOLS and not self._goal_mentions_side_effect(goal_text):
                reject_flags.append(f"{tool}:goal_misaligned_high_risk")
                continue

            if self._looks_suspicious_url(argument_text):
                suspicious_flags.append(f"{tool}:suspicious_destination")

        if reject_flags:
            return MonitorDecision(
                kind=MonitorDecisionType.REJECT,
                reason="Action monitor rejected goal-misaligned or policy-evasive plan",
                flags=reject_flags,
            )
        if suspicious_flags:
            return MonitorDecision(
                kind=MonitorDecisionType.SUSPICIOUS,
                reason="Action monitor flagged unusual high-risk behavior",
                flags=suspicious_flags,
            )
        return MonitorDecision(kind=MonitorDecisionType.APPROVE)

    @staticmethod
    def _goal_mentions_side_effect(goal_text: str) -> bool:
        cues = (
            "send",
            "post",
            "publish",
            "email",
            "write",
            "update",
            "save",
            "search",
            "fetch",
            "browse",
            "open",
            "visit",
            "look up",
            "lookup",
            "download",
        )
        return any(token in goal_text for token in cues)

    @staticmethod
    def _flatten_arguments(arguments: Any) -> str:
        if isinstance(arguments, dict):
            parts = [str(value) for value in arguments.values()]
            return " ".join(parts).lower()
        if isinstance(arguments, list):
            return " ".join(str(item) for item in arguments).lower()
        return str(arguments).lower()

    @staticmethod
    def _looks_suspicious_url(argument_text: str) -> bool:
        return "http://" in argument_text or ".onion" in argument_text


def combine_monitor_with_policy(
    *,
    pep_kind: str,
    monitor: MonitorDecision,
    risk_score: float,
    auto_approve_threshold: float,
    block_threshold: float,
) -> tuple[str, str]:
    """Combine PEP and monitor outcomes using M2 rules."""
    if pep_kind == "reject":
        return ("reject", "pep_reject")
    if monitor.kind == MonitorDecisionType.REJECT:
        return ("reject", monitor.reason or "monitor_reject")

    # High risk requires confirmation even if monitor approves.
    if risk_score >= block_threshold:
        return ("require_confirmation", "high_risk_requires_human")

    # Medium risk requires monitor + PEP agreement.
    if risk_score >= auto_approve_threshold:
        if monitor.kind == MonitorDecisionType.APPROVE and pep_kind == "allow":
            return ("allow", "pep_monitor_agree")
        return ("require_confirmation", monitor.reason or "monitor_not_confident")

    if pep_kind == "require_confirmation":
        return ("require_confirmation", "pep_requires_confirmation")
    if monitor.kind in {MonitorDecisionType.SUSPICIOUS, MonitorDecisionType.ESCALATE}:
        return ("require_confirmation", monitor.reason or "monitor_escalate")
    return ("allow", "low_risk_allow")
