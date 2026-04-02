"""Policy Enforcement Point (PEP).

The PEP is the sole authority for approving proposed tool calls.
"""

from __future__ import annotations

import ipaddress
import logging
import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, ClassVar
from urllib.parse import urlparse

from shisad.core.evidence import ArtifactEndorsementState, ArtifactLedger
from shisad.core.host_matching import host_matches
from shisad.core.tools.names import canonical_tool_name_typed
from shisad.core.tools.registry import ToolRegistry
from shisad.core.types import (
    Capability,
    CredentialRef,
    PEPDecision,
    PEPDecisionKind,
    SessionId,
    TaintLabel,
    ToolName,
    UserId,
    WorkspaceId,
)
from shisad.security.credentials import CredentialStore
from shisad.security.policy import PolicyBundle
from shisad.security.taint import sink_decision_for_tool

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class EgressAttempt:
    """Audit-friendly egress evaluation record."""

    tool_name: ToolName
    host: str
    protocol: str | None
    port: int | None
    allowed: bool
    reason: str


@dataclass(frozen=True)
class EgressDestination:
    """Parsed destination metadata for egress checks."""

    host: str
    protocol: str | None = None
    port: int | None = None


@dataclass(frozen=True)
class CredentialUseAttempt:
    """Credential reference usage record (never includes raw secret material)."""

    tool_name: ToolName
    credential_ref: CredentialRef
    destination_host: str
    allowed: bool
    reason: str


class PolicyContext:
    """Context for a PEP evaluation."""

    def __init__(
        self,
        *,
        capabilities: set[Capability] | None = None,
        taint_labels: set[TaintLabel] | None = None,
        user_goal_host_patterns: set[str] | None = None,
        untrusted_host_patterns: set[str] | None = None,
        session_id: SessionId | None = None,
        workspace_id: WorkspaceId | None = None,
        user_id: UserId | None = None,
        action_count: int = 0,
        resource_authorizer: Callable[[str, WorkspaceId, UserId], bool] | None = None,
        tool_allowlist: set[ToolName] | None = None,
        trust_level: str = "untrusted",
        credential_refs: set[CredentialRef] | None = None,
        enforce_explicit_credential_refs: bool = False,
    ) -> None:
        self.capabilities: set[Capability] = capabilities or set()
        self.taint_labels: set[TaintLabel] = taint_labels or set()
        self.user_goal_host_patterns: set[str] = user_goal_host_patterns or set()
        self.untrusted_host_patterns: set[str] = untrusted_host_patterns or set()
        self.session_id: SessionId = session_id or SessionId("")
        self.workspace_id: WorkspaceId = workspace_id or WorkspaceId("")
        self.user_id: UserId = user_id or UserId("")
        self.action_count = action_count
        self.resource_authorizer = resource_authorizer
        self.tool_allowlist = tool_allowlist
        self.trust_level = trust_level
        self.credential_refs: set[CredentialRef] = credential_refs or set()
        self.enforce_explicit_credential_refs = enforce_explicit_credential_refs


class PEP:
    """Policy Enforcement Point.

    LLM outputs are proposals, never authority.
    """

    _SECRET_PATTERNS: ClassVar[list[re.Pattern[str]]] = [
        re.compile(r"\bsk-[A-Za-z0-9_-]{16,}\b"),
        re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
        re.compile(r"\bya29\.[A-Za-z0-9._-]{20,}\b"),
    ]
    _CREDENTIAL_REF_KEYS: ClassVar[set[str]] = {"credential_ref"}
    _RESOURCE_ARG_SUFFIX: ClassVar[str] = "_id"
    _RESOURCE_ARG_ALLOWLIST: ClassVar[set[str]] = {"session_id", "ref_id"}

    def __init__(
        self,
        policy: PolicyBundle,
        tool_registry: ToolRegistry,
        *,
        evidence_store: ArtifactLedger | None = None,
        credential_store: CredentialStore | None = None,
        credential_audit_hook: Callable[[CredentialUseAttempt], None] | None = None,
    ) -> None:
        self._policy = policy
        self._tool_registry = tool_registry
        self._evidence_store = evidence_store
        self._credential_store = credential_store
        self._credential_audit_hook = credential_audit_hook
        self.egress_attempts: list[EgressAttempt] = []
        self.credential_attempts: list[CredentialUseAttempt] = []

    def evaluate(
        self,
        tool_name: ToolName,
        arguments: dict[str, Any],
        context: PolicyContext,
    ) -> PEPDecision:
        """Evaluate a tool call proposal."""
        tool_name = canonical_tool_name_typed(tool_name)
        # 1. Tool allowlist check (default-deny)
        if not self._tool_registry.has_tool(tool_name):
            return self._reject(tool_name, f"Unknown tool: {tool_name}")

        # 1.5. Per-session/policy tool allowlist
        allowed_tools = self._effective_tool_allowlist(context)
        if allowed_tools is not None and tool_name not in allowed_tools:
            return self._reject(
                tool_name,
                f"Tool '{tool_name}' not permitted by session/policy allowlist",
            )

        # 2. Schema validation
        validation_errors = self._tool_registry.validate_call(tool_name, arguments)
        if validation_errors:
            return self._reject(
                tool_name,
                f"Schema validation failed: {'; '.join(validation_errors)}",
            )

        tool = self._tool_registry.get_tool(tool_name)
        if tool is None:
            return self._reject(tool_name, f"Unknown tool: {tool_name}")
        tool_policy = self._policy.tools.get(tool_name)

        allowed_arg_error = self._check_allowed_args(tool_name, arguments, tool_policy)
        if allowed_arg_error is not None:
            return self._reject(tool_name, allowed_arg_error)

        # 3. Capability check
        missing = set(tool.capabilities_required) - context.capabilities
        if missing:
            return self._reject(
                tool_name,
                f"Missing capabilities: {', '.join(sorted(m.value for m in missing))}",
            )

        # 4. Argument DLP checks (raw secrets only; do not block PII-by-default)
        dlp_issues = self._check_argument_dlp(arguments)
        if dlp_issues:
            return self._reject(
                tool_name,
                "Blocked by DLP policy: " + "; ".join(dlp_issues),
            )

        # 5. Object-level resource authorization checks
        auth_issues = self._check_resource_authorization(arguments, context)
        if auth_issues:
            return self._reject(
                tool_name,
                "Resource authorization failed: " + "; ".join(auth_issues),
            )

        evidence_ref_error = self._check_evidence_ref(tool_name, arguments, context)
        if evidence_ref_error is not None:
            return evidence_ref_error

        endorsement_decision = self._check_artifact_endorsement(tool_name, arguments, context)
        if endorsement_decision is not None:
            return endorsement_decision

        # 6. Egress allowlist enforcement
        destination_declared_by_tool = False
        try:
            destination = self._extract_destination(arguments)
            if destination is None:
                destination = self._infer_destination_from_tool(tool)
                destination_declared_by_tool = destination is not None
        except ValueError:
            return self._reject(
                tool_name,
                (
                    "Egress blocked: malformed destination URL. "
                    "Fix the destination and retry with a valid host/port."
                ),
            )

        # 6.5 Credential reference checks (host-scoped binding)
        credential_error = self._check_credential_refs(
            tool_name,
            tool,
            arguments,
            destination,
            context,
        )
        if credential_error is not None:
            return credential_error

        egress_requires_confirmation = False
        egress_reason = ""
        if destination is not None:
            if destination.protocol and destination.protocol not in {"http", "https"}:
                self.egress_attempts.append(
                    EgressAttempt(
                        tool_name=tool_name,
                        host=destination.host,
                        protocol=destination.protocol,
                        port=destination.port,
                        allowed=False,
                        reason="unsupported_protocol",
                    )
                )
                return self._reject(
                    tool_name,
                    (
                        f"Egress blocked: unsupported protocol '{destination.protocol}'. "
                        "Use http(s) destinations only."
                    ),
                )

            allowlisted = self._is_egress_allowed(destination)
            if destination_declared_by_tool:
                allowlisted = True
            user_requested = self._host_matches_any(
                destination.host, context.user_goal_host_patterns
            )
            untrusted_suggested = self._host_matches_any(
                destination.host, context.untrusted_host_patterns
            )

            if self._is_ip_literal(destination.host) and not allowlisted:
                self.egress_attempts.append(
                    EgressAttempt(
                        tool_name=tool_name,
                        host=destination.host,
                        protocol=destination.protocol,
                        port=destination.port,
                        allowed=False,
                        reason="ip_literal_not_allowlisted",
                    )
                )
                return self._reject(
                    tool_name,
                    (
                        f"Egress blocked: destination '{destination.host}' is an IP literal "
                        "and is not allowlisted by operator policy."
                    ),
                )
            if self._looks_like_local_destination(destination.host) and not allowlisted:
                self.egress_attempts.append(
                    EgressAttempt(
                        tool_name=tool_name,
                        host=destination.host,
                        protocol=destination.protocol,
                        port=destination.port,
                        allowed=False,
                        reason="local_destination_not_allowlisted",
                    )
                )
                return self._reject(
                    tool_name,
                    (
                        f"Egress blocked: destination '{destination.host}' looks like a local/"
                        "private network target and is not allowlisted by operator policy."
                    ),
                )

            if destination_declared_by_tool:
                self.egress_attempts.append(
                    EgressAttempt(
                        tool_name=tool_name,
                        host=destination.host,
                        protocol=destination.protocol,
                        port=destination.port,
                        allowed=True,
                        reason="tool_declared",
                    )
                )
            elif allowlisted:
                self.egress_attempts.append(
                    EgressAttempt(
                        tool_name=tool_name,
                        host=destination.host,
                        protocol=destination.protocol,
                        port=destination.port,
                        allowed=True,
                        reason="allowlisted",
                    )
                )
            elif user_requested:
                self.egress_attempts.append(
                    EgressAttempt(
                        tool_name=tool_name,
                        host=destination.host,
                        protocol=destination.protocol,
                        port=destination.port,
                        allowed=True,
                        reason="user_goal",
                    )
                )
            elif untrusted_suggested:
                egress_requires_confirmation = True
                egress_reason = "untrusted_suggested_destination"
                self.egress_attempts.append(
                    EgressAttempt(
                        tool_name=tool_name,
                        host=destination.host,
                        protocol=destination.protocol,
                        port=destination.port,
                        allowed=False,
                        reason="confirmation_required_untrusted_suggestion",
                    )
                )
            else:
                self.egress_attempts.append(
                    EgressAttempt(
                        tool_name=tool_name,
                        host=destination.host,
                        protocol=destination.protocol,
                        port=destination.port,
                        allowed=False,
                        reason="destination_unattributed",
                    )
                )
                return self._reject(
                    tool_name,
                    (
                        f"Egress blocked: destination '{destination.host}' is not allowlisted "
                        "and was not explicitly requested by the (trusted) user goal. "
                        "If the user wants this destination, have them request it directly."
                    ),
                )

        # 7. Taint sink enforcement
        taint_decision = sink_decision_for_tool(str(tool_name), context.taint_labels)
        if taint_decision.block:
            return self._reject(
                tool_name,
                (
                    "Blocked by taint sink rule: "
                    f"{taint_decision.reason}. If this is unexpected, report_anomaly."
                ),
            )

        # 8. Risk scoring and policy-driven decision
        risk_score = self._score_risk(
            tool_name,
            context,
            destination.host if destination else None,
        )
        block_threshold = self._policy.risk_policy.block_threshold
        auto_approve_threshold = self._policy.risk_policy.auto_approve_threshold

        # Alarm bell must remain callable to surface suspected attacks.
        if str(tool_name) == "report_anomaly":
            return PEPDecision(
                kind=PEPDecisionKind.ALLOW,
                tool_name=tool_name,
                risk_score=risk_score,
            )

        if risk_score >= block_threshold:
            taint_summary = (
                ",".join(sorted(label.value for label in context.taint_labels)) or "none"
            )
            return self._reject(
                tool_name,
                (
                    f"Action blocked by risk policy (risk={risk_score:.2f}, "
                    f"taint={taint_summary}). "
                    "Choose a lower-risk path or request user confirmation. "
                    "If behavior seems malicious, call report_anomaly."
                ),
            )

        needs_confirmation = (
            egress_requires_confirmation
            or taint_decision.require_confirmation
            or tool.require_confirmation
            or (tool_policy is not None and tool_policy.require_confirmation)
            or self._policy.default_require_confirmation
            or risk_score >= auto_approve_threshold
        )

        if needs_confirmation:
            reason_suffix = ""
            if destination is not None and egress_reason:
                reason_suffix = (
                    f" Egress destination '{destination.host}' requires confirmation: "
                    f"{egress_reason}."
                )
            return PEPDecision(
                kind=PEPDecisionKind.REQUIRE_CONFIRMATION,
                reason=(
                    f"Tool '{tool_name}' requires confirmation (risk={risk_score:.2f}). "
                    "Use an approved destination/scope or ask for explicit user approval."
                    + reason_suffix
                ),
                tool_name=tool_name,
                risk_score=risk_score,
            )

        return PEPDecision(
            kind=PEPDecisionKind.ALLOW,
            tool_name=tool_name,
            risk_score=risk_score,
        )

    def _effective_tool_allowlist(
        self,
        context: PolicyContext,
    ) -> set[ToolName] | None:
        if context.tool_allowlist is not None:
            return {canonical_tool_name_typed(item) for item in context.tool_allowlist}
        if self._policy.session_tool_allowlist:
            return {canonical_tool_name_typed(item) for item in self._policy.session_tool_allowlist}
        if self._policy.default_deny and self._policy.tools:
            return {canonical_tool_name_typed(item) for item in self._policy.tools}
        return None

    def _check_evidence_ref(
        self,
        tool_name: ToolName,
        arguments: dict[str, Any],
        context: PolicyContext,
    ) -> PEPDecision | None:
        if str(tool_name) not in {"evidence.read", "evidence.promote"}:
            return None
        ref_id = str(arguments.get("ref_id", "")).strip()
        if not ref_id:
            return self._reject(tool_name, "invalid or unknown evidence reference")
        if self._evidence_store is None:
            return self._reject(
                tool_name,
                "invalid or unknown evidence reference",
            )
        if not self._evidence_store.validate_ref_id(context.session_id, ref_id):
            return self._reject(tool_name, "invalid or unknown evidence reference")
        return None

    def _check_artifact_endorsement(
        self,
        tool_name: ToolName,
        arguments: dict[str, Any],
        context: PolicyContext,
    ) -> PEPDecision | None:
        if str(tool_name) != "evidence.promote":
            return None
        if self._evidence_store is None:
            return self._reject(tool_name, "invalid or unknown evidence reference")
        ref_id = str(arguments.get("ref_id", "")).strip()
        if not ref_id:
            return self._reject(tool_name, "invalid or unknown evidence reference")
        ref = self._evidence_store.get_ref(context.session_id, ref_id)
        if ref is None:
            return self._reject(tool_name, "invalid or unknown evidence reference")
        if ref.endorsement_state == ArtifactEndorsementState.UNENDORSED:
            return PEPDecision(
                kind=PEPDecisionKind.REQUIRE_CONFIRMATION,
                reason=(
                    "Artifact is unendorsed; user confirmation is required before "
                    "it can be promoted into persistent conversation context."
                ),
                tool_name=tool_name,
            )
        return None

    def _check_allowed_args(
        self,
        tool_name: ToolName,
        arguments: dict[str, Any],
        tool_policy: Any | None,
    ) -> str | None:
        if tool_policy is None or tool_policy.allowed_args is None:
            return None
        if not isinstance(tool_policy.allowed_args, dict):
            return f"Policy for '{tool_name}' has invalid allowed_args format"
        if self._matches_allowed_args(arguments, tool_policy.allowed_args):
            return None
        return f"Arguments for '{tool_name}' do not match policy allowed_args constraints"

    def _matches_allowed_args(self, actual: Any, expected: Any) -> bool:
        if expected == "*":
            return True
        if isinstance(expected, dict):
            if not isinstance(actual, dict):
                return False
            if set(actual.keys()) != set(expected.keys()):
                return False
            return all(
                self._matches_allowed_args(actual.get(key), value)
                for key, value in expected.items()
            )
        if isinstance(expected, list):
            if not isinstance(actual, list):
                return False
            if len(expected) == 1 and expected[0] == "*":
                return True
            if len(actual) != len(expected):
                return False
            return all(
                self._matches_allowed_args(a, e) for a, e in zip(actual, expected, strict=True)
            )
        return bool(actual == expected)

    def _check_argument_dlp(self, arguments: dict[str, Any]) -> list[str]:
        issues: list[str] = []
        for key, value in self._iter_string_arguments(arguments):
            for pattern in self._SECRET_PATTERNS:
                if pattern.search(value):
                    issues.append(f"Argument '{key}' appears to contain a raw secret")
                    break

        return issues

    @staticmethod
    def _host_matches_any(host: str, patterns: set[str]) -> bool:
        return any(host_matches(host, pattern) for pattern in patterns)

    @staticmethod
    def _is_ip_literal(host: str) -> bool:
        try:
            ipaddress.ip_address(host)
        except ValueError:
            return False
        return True

    @staticmethod
    def _looks_like_local_destination(host: str) -> bool:
        lowered = host.strip().lower()
        if not lowered:
            return False
        if lowered in {"localhost"}:
            return True
        return (
            lowered.endswith(".local")
            or lowered.endswith(".internal")
            or lowered.endswith(".lan")
        )

    def _check_resource_authorization(
        self,
        arguments: dict[str, Any],
        context: PolicyContext,
    ) -> list[str]:
        if context.resource_authorizer is None:
            return []

        failures: list[str] = []
        for key, value in arguments.items():
            if not isinstance(value, str):
                continue
            if not key.endswith(self._RESOURCE_ARG_SUFFIX):
                continue
            if key in self._RESOURCE_ARG_ALLOWLIST:
                continue
            if not context.resource_authorizer(value, context.workspace_id, context.user_id):
                failures.append(f"'{key}' not authorized in current workspace/user scope")
        return failures

    def _check_credential_refs(
        self,
        tool_name: ToolName,
        tool: Any,
        arguments: dict[str, Any],
        destination: EgressDestination | None,
        context: PolicyContext,
    ) -> PEPDecision | None:
        credential_refs = self._extract_credential_refs(arguments)
        if not credential_refs:
            return None

        if context.enforce_explicit_credential_refs:
            allowed_refs = set(context.credential_refs)
            rejected_refs = [
                credential_ref
                for credential_ref in credential_refs
                if credential_ref not in allowed_refs
            ]
            for credential_ref in rejected_refs:
                self._record_credential_attempt(
                    CredentialUseAttempt(
                        tool_name=tool_name,
                        credential_ref=credential_ref,
                        destination_host=destination.host if destination is not None else "",
                        allowed=False,
                        reason="credential_ref_out_of_scope",
                    )
                )
            if rejected_refs:
                credential_ref = rejected_refs[0]
                return self._reject(
                    tool_name,
                    f"credential_ref '{credential_ref}' is out of scope for this task/session",
                )

        if destination is None:
            for credential_ref in credential_refs:
                self._record_credential_attempt(
                    CredentialUseAttempt(
                        tool_name=tool_name,
                        credential_ref=credential_ref,
                        destination_host="",
                        allowed=False,
                        reason="missing_destination",
                    )
                )
            return self._reject(
                tool_name,
                "credential_ref requires explicit destination host in tool arguments",
            )

        if not tool.destinations:
            for credential_ref in credential_refs:
                self._record_credential_attempt(
                    CredentialUseAttempt(
                        tool_name=tool_name,
                        credential_ref=credential_ref,
                        destination_host=destination.host,
                        allowed=False,
                        reason="missing_tool_destinations",
                    )
                )
            return self._reject(
                tool_name,
                (
                    f"Tool '{tool_name}' uses credential_ref but has no declared destinations; "
                    "define tool destinations before credential use"
                ),
            )

        for credential_ref in credential_refs:
            if self._credential_store is None:
                self._record_credential_attempt(
                    CredentialUseAttempt(
                        tool_name=tool_name,
                        credential_ref=credential_ref,
                        destination_host=destination.host,
                        allowed=False,
                        reason="credential_store_unavailable",
                    )
                )
                return self._reject(
                    tool_name,
                    "credential_ref cannot be validated because credential store is unavailable",
                )

            if not self._credential_store.has_credential(credential_ref):
                self._record_credential_attempt(
                    CredentialUseAttempt(
                        tool_name=tool_name,
                        credential_ref=credential_ref,
                        destination_host=destination.host,
                        allowed=False,
                        reason="unknown_credential_ref",
                    )
                )
                return self._reject(
                    tool_name,
                    f"Unknown credential_ref: {credential_ref}",
                )

            allowed_hosts = self._credential_store.allowed_hosts(credential_ref)
            if not any(host_matches(destination.host, pattern) for pattern in allowed_hosts):
                self._record_credential_attempt(
                    CredentialUseAttempt(
                        tool_name=tool_name,
                        credential_ref=credential_ref,
                        destination_host=destination.host,
                        allowed=False,
                        reason="credential_host_mismatch",
                    )
                )
                return self._reject(
                    tool_name,
                    (
                        f"credential_ref '{credential_ref}' is not allowed for destination "
                        f"'{destination.host}'"
                    ),
                )

            declared_destination_hosts = [
                self._destination_host_pattern(str(pattern))
                for pattern in tool.destinations
            ]
            if not any(
                pattern and host_matches(destination.host, pattern)
                for pattern in declared_destination_hosts
            ):
                self._record_credential_attempt(
                    CredentialUseAttempt(
                        tool_name=tool_name,
                        credential_ref=credential_ref,
                        destination_host=destination.host,
                        allowed=False,
                        reason="tool_destination_mismatch",
                    )
                )
                return self._reject(
                    tool_name,
                    (
                        f"Destination '{destination.host}' is not declared for tool '{tool_name}' "
                        "credential use"
                    ),
                )

            self._record_credential_attempt(
                CredentialUseAttempt(
                    tool_name=tool_name,
                    credential_ref=credential_ref,
                    destination_host=destination.host,
                    allowed=True,
                    reason="allowed",
                )
            )

        return None

    def _extract_credential_refs(self, arguments: dict[str, Any]) -> list[CredentialRef]:
        refs: list[CredentialRef] = []
        for key, value in self._iter_string_arguments(arguments):
            normalized_key = key.split(".")[-1]
            if normalized_key in self._CREDENTIAL_REF_KEYS or normalized_key.endswith(
                "_credential_ref"
            ):
                refs.append(CredentialRef(value))
        return refs

    def _record_credential_attempt(self, attempt: CredentialUseAttempt) -> None:
        self.credential_attempts.append(attempt)
        logger.info(
            "credential_ref usage %s: tool=%s ref=%s destination=%s reason=%s",
            "allowed" if attempt.allowed else "rejected",
            attempt.tool_name,
            attempt.credential_ref,
            attempt.destination_host,
            attempt.reason,
        )
        if self._credential_audit_hook is not None:
            self._credential_audit_hook(attempt)

    def _extract_destination(self, arguments: dict[str, Any]) -> EgressDestination | None:
        url_fields = ("url", "endpoint", "destination", "webhook_url")
        for field in url_fields:
            value = arguments.get(field)
            if not isinstance(value, str) or not value:
                continue

            parsed = urlparse(value)
            if parsed.hostname:
                protocol = parsed.scheme.lower() if parsed.scheme else None
                port = self._safe_url_port(parsed)
                if port is None and protocol in {"http", "https"}:
                    port = 80 if protocol == "http" else 443
                return EgressDestination(host=parsed.hostname, protocol=protocol, port=port)

        host = arguments.get("host")
        if isinstance(host, str) and host:
            protocol = arguments.get("protocol")
            protocol_value = protocol.lower() if isinstance(protocol, str) else None
            port = arguments.get("port")
            port_value = int(port) if isinstance(port, int | str) and str(port).isdigit() else None
            return EgressDestination(host=host, protocol=protocol_value, port=port_value)

        return None

    @staticmethod
    def _infer_destination_from_tool(tool: Any) -> EgressDestination | None:
        destinations = [str(item).strip().lower() for item in getattr(tool, "destinations", [])]
        if len(destinations) != 1:
            return None
        destination = destinations[0]
        if not destination or any(token in destination for token in ("*", "?", "[", "]")):
            return None
        if "://" in destination:
            parsed = urlparse(destination)
            host = (parsed.hostname or "").lower()
            if not host:
                return None
            protocol = (parsed.scheme or "").lower() or None
            port = PEP._safe_url_port(parsed)
            if port is None and protocol in {"http", "https"}:
                port = 80 if protocol == "http" else 443
            return EgressDestination(host=host, protocol=protocol, port=port)
        return EgressDestination(host=destination, protocol="https", port=443)

    @staticmethod
    def _safe_url_port(parsed: Any) -> int | None:
        try:
            port = parsed.port
        except ValueError as exc:
            raise ValueError("invalid_destination_port") from exc
        if port is None:
            return None
        if isinstance(port, int):
            return port
        return None

    @staticmethod
    def _destination_host_pattern(destination: str) -> str:
        value = destination.strip().lower()
        if "://" not in value:
            return value
        parsed = urlparse(value)
        return (parsed.hostname or "").lower()

    def _is_egress_allowed(self, destination: EgressDestination) -> bool:
        if not self._policy.egress:
            return False

        for rule in self._policy.egress:
            if not host_matches(destination.host, rule.host):
                continue

            if destination.protocol is None:
                continue
            if rule.protocols and destination.protocol not in rule.protocols:
                continue

            if destination.port is None:
                continue
            if rule.ports and destination.port not in rule.ports:
                continue

            return True

        return False

    @staticmethod
    def _iter_string_arguments(arguments: dict[str, Any]) -> list[tuple[str, str]]:
        pairs: list[tuple[str, str]] = []
        for key, value in arguments.items():
            if isinstance(value, str):
                pairs.append((key, value))
            elif isinstance(value, dict):
                for nested_key, nested_value in value.items():
                    if isinstance(nested_value, str):
                        pairs.append((f"{key}.{nested_key}", nested_value))
            elif isinstance(value, list):
                for i, item in enumerate(value):
                    if isinstance(item, str):
                        pairs.append((f"{key}[{i}]", item))
        return pairs

    @staticmethod
    def _score_risk(
        tool_name: ToolName,
        context: PolicyContext,
        destination_host: str | None,
    ) -> float:
        score = 0.0

        high_risk_tools = {
            "send_email": 0.4,
            "message.send": 0.4,
            "http.request": 0.45,
            "shell.exec": 0.55,
            "file.write": 0.45,
        }
        score += high_risk_tools.get(str(tool_name), 0.1)

        if TaintLabel.UNTRUSTED in context.taint_labels:
            score += 0.2
        if any(
            label in context.taint_labels
            for label in {
                TaintLabel.SENSITIVE_EMAIL,
                TaintLabel.SENSITIVE_FILE,
                TaintLabel.SENSITIVE_CALENDAR,
            }
        ):
            score += 0.3
        if TaintLabel.USER_CREDENTIALS in context.taint_labels:
            score += 0.5

        if destination_host and destination_host.count(".") >= 2:
            score += 0.05

        if context.action_count >= 3:
            score += min(context.action_count * 0.03, 0.2)

        # Channel trust can soften risk for verified identities.
        trust = context.trust_level.lower().strip()
        trust_discount = {
            "trusted": 0.15,
            "verified": 0.15,
            "internal": 0.1,
            "medium": 0.05,
        }.get(trust, 0.0)
        score = max(0.0, score - trust_discount)

        return min(score, 1.0)

    @staticmethod
    def _reject(tool_name: ToolName, reason: str) -> PEPDecision:
        return PEPDecision(
            kind=PEPDecisionKind.REJECT,
            reason=reason,
            tool_name=tool_name,
        )
