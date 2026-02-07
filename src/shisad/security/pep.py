"""Policy Enforcement Point (PEP).

Evaluates tool call proposals against the active policy. In M0 this
implements schema validation and tool allowlist checks. Later milestones
add taint-aware checks, egress enforcement, and credential verification.
"""

from __future__ import annotations

import logging
from typing import Any

from shisad.core.tools.registry import ToolRegistry
from shisad.core.types import Capability, PEPDecision, PEPDecisionKind, ToolName
from shisad.security.policy import PolicyBundle

logger = logging.getLogger(__name__)


class PolicyContext:
    """Context for a PEP evaluation — the session's granted capabilities."""

    def __init__(self, capabilities: set[Capability] | None = None) -> None:
        self.capabilities: set[Capability] = capabilities or set()


class PEP:
    """Policy Enforcement Point.

    LLM outputs are proposals, never authority. The PEP is the sole
    arbiter of whether a proposed tool call is allowed to execute.
    """

    def __init__(self, policy: PolicyBundle, tool_registry: ToolRegistry) -> None:
        self._policy = policy
        self._tool_registry = tool_registry

    def evaluate(
        self,
        tool_name: ToolName,
        arguments: dict[str, Any],
        context: PolicyContext,
    ) -> PEPDecision:
        """Evaluate a tool call proposal.

        Checks are applied in order; first rejection wins.
        """
        # 1. Tool allowlist check (default-deny)
        if not self._tool_registry.has_tool(tool_name):
            return PEPDecision(
                kind=PEPDecisionKind.REJECT,
                reason=f"Unknown tool: {tool_name}",
                tool_name=tool_name,
            )

        # 2. Schema validation
        validation_errors = self._tool_registry.validate_call(tool_name, arguments)
        if validation_errors:
            return PEPDecision(
                kind=PEPDecisionKind.REJECT,
                reason=f"Schema validation failed: {'; '.join(validation_errors)}",
                tool_name=tool_name,
            )

        # 3. Capability check
        tool = self._tool_registry.get_tool(tool_name)
        if tool is not None:
            missing = set(tool.capabilities_required) - context.capabilities
            if missing:
                return PEPDecision(
                    kind=PEPDecisionKind.REJECT,
                    reason=f"Missing capabilities: {', '.join(sorted(missing))}",
                    tool_name=tool_name,
                )

            # 4. Confirmation check
            tool_policy = self._policy.tools.get(tool_name)
            needs_confirmation = (
                tool.require_confirmation
                or (tool_policy is not None and tool_policy.require_confirmation)
                or self._policy.default_require_confirmation
            )
            if needs_confirmation:
                return PEPDecision(
                    kind=PEPDecisionKind.REQUIRE_CONFIRMATION,
                    reason=f"Tool '{tool_name}' requires user confirmation",
                    tool_name=tool_name,
                )

        # 5. Credential check (placeholder — expanded in M0.8)
        secret_errors = self._check_for_raw_secrets(arguments)
        if secret_errors:
            return PEPDecision(
                kind=PEPDecisionKind.REJECT,
                reason=f"Raw secrets detected in arguments: {'; '.join(secret_errors)}",
                tool_name=tool_name,
            )

        return PEPDecision(
            kind=PEPDecisionKind.ALLOW,
            tool_name=tool_name,
        )

    @staticmethod
    def _check_for_raw_secrets(arguments: dict[str, Any]) -> list[str]:
        """Scan tool arguments for patterns that look like raw secrets.

        This is a basic check — the credential broker (M0.8) provides
        the full implementation. Here we catch obvious leaks.
        """
        errors: list[str] = []
        secret_prefixes = (
            "sk-",       # OpenAI
            "sk_live_",  # Stripe
            "ghp_",      # GitHub PAT
            "gho_",      # GitHub OAuth
            "xoxb-",     # Slack bot
            "xoxp-",     # Slack user
            "AKIA",      # AWS access key
        )

        for key, value in arguments.items():
            if not isinstance(value, str):
                continue
            for prefix in secret_prefixes:
                if value.startswith(prefix):
                    errors.append(f"Argument '{key}' appears to contain a raw secret ({prefix}…)")
                    break

        return errors
