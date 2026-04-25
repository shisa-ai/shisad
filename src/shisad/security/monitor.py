"""Action monitor (clean-room guardrail layer)."""

from __future__ import annotations

import re
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

    _READ_ONLY_BROWSER_TOOLS: ClassVar[set[str]] = {
        "browser.navigate",
        "browser.read_page",
        "browser.screenshot",
    }
    _HIGH_RISK_TOOLS: ClassVar[set[str]] = {
        "http.request",
        "send_email",
        "file.write",
        "shell.exec",
    }
    _READ_ONLY_FILE_DISCOVERY_SHELL_COMMANDS: ClassVar[set[str]] = {
        "fd",
        "find",
        "ls",
    }
    _FORBIDDEN_FILE_DISCOVERY_SHELL_TOKENS: ClassVar[set[str]] = {
        "&&",
        "||",
        ";",
        "|",
        ">",
        ">>",
        "-delete",
        "-exec",
        "-execdir",
        "-fls",
        "-fprint",
        "-fprint0",
        "-fprintf",
        "-ok",
        "-okdir",
        "-x",
        "--exec",
        "--exec-batch",
    }
    _FORBIDDEN_FILE_DISCOVERY_SHELL_TOKEN_PREFIXES: ClassVar[tuple[str, ...]] = (
        "--exec=",
        "--exec-batch=",
    )
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

            if tool == "shell.exec" and self._is_read_only_shell_file_discovery(
                goal_text=goal_text,
                arguments=getattr(action, "arguments", {}),
            ):
                suspicious_flags.append("read_only_file_discovery")
                continue

            if tool in self._HIGH_RISK_TOOLS and not self._goal_mentions_side_effect(goal_text):
                reject_flags.append(f"{tool}:goal_misaligned_high_risk")
                continue

            if tool in self._READ_ONLY_BROWSER_TOOLS and self._goal_mentions_browser_navigation(
                goal_text
            ):
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
    def _goal_mentions_browser_navigation(goal_text: str) -> bool:
        cues = (
            "browser",
            "browse",
            "open",
            "visit",
            "navigate",
        )
        return any(token in goal_text for token in cues)

    @staticmethod
    def _cue_matches(goal_text: str, cue: str) -> bool:
        escaped_parts = [re.escape(part) for part in cue.split()]
        pattern = r"\b" + r"\s+".join(escaped_parts) + r"\b"
        return bool(re.search(pattern, goal_text, flags=re.IGNORECASE))

    @classmethod
    def _goal_mentions_file_discovery(cls, goal_text: str) -> bool:
        file_cues = (
            "directories",
            "directory",
            "file",
            "files",
            "filepath",
            "filepaths",
            "filename",
            "filenames",
            "folder",
            "folders",
            "log",
            "logfile",
            "logfiles",
            "logs",
            "path",
            "paths",
        )
        discovery_cues = (
            "find",
            "list",
            "locate",
            "look for",
            "search",
            "show",
            "similar",
            "where",
        )
        return any(cls._cue_matches(goal_text, cue) for cue in file_cues) and any(
            cls._cue_matches(goal_text, cue) for cue in discovery_cues
        )

    @classmethod
    def _is_read_only_shell_file_discovery(
        cls,
        *,
        goal_text: str,
        arguments: Any,
    ) -> bool:
        if not cls._goal_mentions_file_discovery(goal_text):
            return False
        if not isinstance(arguments, dict):
            return False
        for risky_field in ("write_paths", "network_urls", "env"):
            value = arguments.get(risky_field)
            if value not in (None, "", [], {}, ()):
                return False
        command_raw = arguments.get("command")
        if not isinstance(command_raw, list) or not command_raw:
            return False
        command: list[str] = []
        for token in command_raw:
            if not isinstance(token, str):
                return False
            stripped = token.strip()
            if not stripped:
                return False
            command.append(stripped)
        command_name = command[0].rsplit("/", 1)[-1].lower()
        if command_name not in cls._READ_ONLY_FILE_DISCOVERY_SHELL_COMMANDS:
            return False
        lowered_tokens = {token.lower() for token in command}
        has_forbidden_prefix = any(
            token.startswith(prefix)
            for token in lowered_tokens
            for prefix in cls._FORBIDDEN_FILE_DISCOVERY_SHELL_TOKEN_PREFIXES
        )
        if (
            lowered_tokens.intersection(cls._FORBIDDEN_FILE_DISCOVERY_SHELL_TOKENS)
            or has_forbidden_prefix
        ):
            return False
        return not any("://" in token or token.startswith("`") for token in lowered_tokens)

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
