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


class _DiagnosticShellCommandDecision(StrEnum):
    ALLOW = "allow"
    REJECT = "reject"
    NOT_DIAGNOSTIC = "not_diagnostic"


class ActionMonitor:
    """Deterministic M2 monitor with clean-room constraints."""

    _LOCAL_DIAGNOSTIC_CLI_COMMANDS: ClassVar[set[str]] = {
        "shisactl",
        "shisad",
    }
    _READ_ONLY_BROWSER_TOOLS: ClassVar[set[str]] = {
        "browser.navigate",
        "browser.read_page",
        "browser.screenshot",
        "browser.end_session",
    }
    _LOCAL_DIAGNOSTIC_ARGUMENT_KEYS: ClassVar[frozenset[str]] = frozenset(
        {"command", "command_intent"}
    )
    _SHELL_EXECUTE_COMMAND_INTENT: ClassVar[str] = "execute"
    _LOCAL_DIAGNOSTIC_FLAG_OPTIONS: ClassVar[dict[tuple[str, ...], frozenset[str]]] = {
        ("action", "list"): frozenset({"--json", "--raw"}),
        ("action", "pending"): frozenset({"--raw"}),
        ("audit", "query"): frozenset({"--all", "--json"}),
        ("audit", "verify"): frozenset(),
        ("lockdown", "status"): frozenset({"--all", "--json"}),
        ("status",): frozenset(),
    }
    _LOCAL_DIAGNOSTIC_VALUE_OPTIONS: ClassVar[dict[tuple[str, ...], frozenset[str]]] = {
        ("action", "list"): frozenset({"--limit", "--session", "--status"}),
        ("action", "pending"): frozenset({"--limit", "--session", "--status"}),
        ("audit", "query"): frozenset(
            {"--actor", "--data-dir", "--limit", "--session", "--since", "--type"}
        ),
        ("audit", "verify"): frozenset({"--data-dir"}),
        ("lockdown", "status"): frozenset({"--session"}),
        ("status",): frozenset(),
    }
    _SUSPICIOUS_ARG_TOKENS: ClassVar[set[str]] = {
        "evil.com",
        "attacker",
        "exfiltrate",
        "bypass",
        "steal",
        "ignore policy",
    }

    def evaluate(
        self,
        *,
        user_goal: str,
        actions: list[Any],
        operator_owned_cli_input: bool = False,
    ) -> MonitorDecision:
        if not actions:
            return MonitorDecision(kind=MonitorDecisionType.APPROVE)

        _ = user_goal
        reject_flags: list[str] = []
        suspicious_flags: list[str] = []

        for action in actions:
            tool = canonical_tool_name(str(getattr(action, "tool_name", "")))
            argument_text = self._flatten_arguments(getattr(action, "arguments", {}))
            if any(token in argument_text for token in self._SUSPICIOUS_ARG_TOKENS):
                reject_flags.append(f"{tool}:suspicious_argument_content")
                continue

            if tool == "shell.exec":
                arguments = getattr(action, "arguments", {})
                if (
                    not isinstance(arguments, dict)
                    or arguments.get("command_intent") != self._SHELL_EXECUTE_COMMAND_INTENT
                ):
                    reject_flags.append(f"{tool}:shell_command_intent_not_execute")
                    continue
                diagnostic_decision = self._local_diagnostic_shell_command_decision(
                    arguments=arguments,
                    operator_owned_cli_input=operator_owned_cli_input,
                )
                if diagnostic_decision == _DiagnosticShellCommandDecision.ALLOW:
                    continue
                if diagnostic_decision == _DiagnosticShellCommandDecision.REJECT:
                    reject_flags.append(f"{tool}:local_diagnostic_shell_not_authorized")
                    continue

            if tool in self._READ_ONLY_BROWSER_TOOLS:
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
    def _shell_command_name(token: str) -> str:
        if "/" in token or "\\" in token:
            return ""
        return token.lower()

    @classmethod
    def _diagnostic_command_prefix(cls, command: list[str]) -> tuple[tuple[str, ...], int] | None:
        if len(command) < 2:
            return None
        executable = cls._shell_command_name(command[0])
        if executable not in cls._LOCAL_DIAGNOSTIC_CLI_COMMANDS:
            return None
        lowered = [token.lower() for token in command]
        candidates: tuple[tuple[str, ...], ...] = (
            ("action", "list"),
            ("action", "pending"),
            ("audit", "query"),
            ("audit", "verify"),
            ("lockdown", "status"),
            ("status",),
        )
        for prefix in candidates:
            end = 1 + len(prefix)
            if tuple(lowered[1:end]) == prefix:
                return prefix, end
        return None

    @staticmethod
    def _diagnostic_option_value_is_safe(value: str) -> bool:
        stripped = value.strip()
        if not stripped:
            return False
        return not any(char in stripped for char in ("\x00", "\n", "\r"))

    @classmethod
    def _diagnostic_options_are_read_only(
        cls,
        *,
        prefix: tuple[str, ...],
        command: list[str],
        start_index: int,
    ) -> bool:
        flag_options = cls._LOCAL_DIAGNOSTIC_FLAG_OPTIONS.get(prefix)
        value_options = cls._LOCAL_DIAGNOSTIC_VALUE_OPTIONS.get(prefix)
        if flag_options is None or value_options is None:
            return False
        index = start_index
        while index < len(command):
            token = command[index]
            lowered = token.lower()
            if not lowered.startswith("--") or lowered == "--":
                return False
            option, has_inline_value, inline_value = lowered.partition("=")
            if option in flag_options:
                if has_inline_value:
                    return False
                index += 1
                continue
            if option not in value_options:
                return False
            if has_inline_value:
                if not cls._diagnostic_option_value_is_safe(inline_value):
                    return False
                index += 1
                continue
            if index + 1 >= len(command):
                return False
            value = command[index + 1]
            if value.startswith("--") or not cls._diagnostic_option_value_is_safe(value):
                return False
            index += 2
        return True

    @classmethod
    def _local_diagnostic_shell_command_decision(
        cls,
        *,
        arguments: Any,
        operator_owned_cli_input: bool,
    ) -> _DiagnosticShellCommandDecision:
        if not isinstance(arguments, dict):
            return _DiagnosticShellCommandDecision.NOT_DIAGNOSTIC
        command_raw = arguments.get("command")
        if not isinstance(command_raw, list) or not command_raw:
            return _DiagnosticShellCommandDecision.NOT_DIAGNOSTIC
        command: list[str] = []
        for token in command_raw:
            if not isinstance(token, str):
                return _DiagnosticShellCommandDecision.REJECT
            stripped = token.strip()
            if not stripped:
                return _DiagnosticShellCommandDecision.REJECT
            command.append(stripped)
        prefix_match = cls._diagnostic_command_prefix(command)
        if prefix_match is None:
            executable = cls._shell_command_name(command[0])
            if executable in cls._LOCAL_DIAGNOSTIC_CLI_COMMANDS:
                return _DiagnosticShellCommandDecision.REJECT
            return _DiagnosticShellCommandDecision.NOT_DIAGNOSTIC
        for key, value in arguments.items():
            if key not in cls._LOCAL_DIAGNOSTIC_ARGUMENT_KEYS and value not in (
                None,
                "",
                [],
                {},
                (),
            ):
                return _DiagnosticShellCommandDecision.REJECT
        if not operator_owned_cli_input:
            return _DiagnosticShellCommandDecision.REJECT
        if arguments.get("command_intent") != cls._SHELL_EXECUTE_COMMAND_INTENT:
            return _DiagnosticShellCommandDecision.REJECT
        prefix, start_index = prefix_match
        if not cls._diagnostic_options_are_read_only(
            prefix=prefix,
            command=command,
            start_index=start_index,
        ):
            return _DiagnosticShellCommandDecision.REJECT
        return _DiagnosticShellCommandDecision.ALLOW

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
        if monitor.kind == MonitorDecisionType.APPROVE and pep_kind == "require_confirmation":
            return ("require_confirmation", "pep_requires_confirmation")
        return ("require_confirmation", monitor.reason or "monitor_not_confident")

    if pep_kind == "require_confirmation":
        return ("require_confirmation", "pep_requires_confirmation")
    if monitor.kind in {MonitorDecisionType.SUSPICIOUS, MonitorDecisionType.ESCALATE}:
        return ("require_confirmation", monitor.reason or "monitor_escalate")
    return ("allow", "low_risk_allow")
