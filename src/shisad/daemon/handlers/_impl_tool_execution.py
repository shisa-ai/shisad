"""Tool and browser execution handler implementations."""

from __future__ import annotations

import logging
from collections.abc import Mapping
from typing import Any, cast
from urllib.parse import urlparse

from shisad.core.approval import (
    ApprovalRoutingError,
    ConfirmationRequirement,
    legacy_software_confirmation_requirement,
    merge_confirmation_requirements,
)
from shisad.core.events import PlanCancelled, PlanCommitted, ToolRejected
from shisad.core.tools.names import canonical_tool_name
from shisad.core.types import Capability, SessionId, TaintLabel, ToolName
from shisad.daemon.handlers._mixin_typing import (
    HandlerMixinBase,
)
from shisad.daemon.handlers._mixin_typing import (
    call_control_plane as _call_control_plane,
)
from shisad.executors.sandbox import DegradedModePolicy, SandboxResult
from shisad.governance.merge import PolicyMergeError, normalize_patch
from shisad.security.control_plane.consensus import TRACE_VOTER_NAME
from shisad.security.control_plane.schema import ControlDecision
from shisad.security.control_plane.trace import trace_reason_requires_confirmation
from shisad.skills.sandbox import SkillExecutionRequest

logger = logging.getLogger(__name__)

_RESERVED_TOOL_EXECUTION_ARGUMENT_KEYS: frozenset[str] = frozenset(
    {
        "session_id",
        "tool_name",
        "skill_name",
        "arguments",
        "command",
        "read_paths",
        "write_paths",
        "network_urls",
        "env",
        "cwd",
        "sandbox_type",
        "security_critical",
        "request_headers",
        "request_body",
        "source_ids",
        "explicit_share_intent",
        "degraded_mode",
        "filesystem",
        "network",
        "environment",
        "limits",
        "_rpc_peer",
        "_internal_ingress_marker",
        "_firewall_result",
        "trust_level",
    }
)


class ToolExecutionImplMixin(HandlerMixinBase):
    def _operator_confirmation_requirement(
        self,
        *,
        tool_name: ToolName,
        tool_definition: Any,
    ) -> ConfirmationRequirement | None:
        tool_policy = self._policy_loader.policy.tools.get(str(tool_name))
        requirements: list[ConfirmationRequirement] = []
        if (
            bool(getattr(tool_definition, "require_confirmation", False))
            or bool(getattr(tool_policy, "require_confirmation", False))
            or bool(self._policy_loader.policy.default_require_confirmation)
        ):
            requirements.append(legacy_software_confirmation_requirement())
        explicit = getattr(tool_policy, "confirmation", None)
        if explicit is not None:
            requirements.append(explicit)
        return merge_confirmation_requirements(requirements)

    async def do_tool_execute(self, params: Mapping[str, Any]) -> dict[str, Any]:
        sid = SessionId(str(params.get("session_id", "")))
        if not sid:
            raise ValueError("session_id is required")
        if not list(params.get("command", [])):
            raise ValueError("command must contain at least one token")
        session = self._session_manager.get(sid)
        if session is None:
            raise ValueError(f"Unknown session: {sid}")

        tool_name_value = canonical_tool_name(str(params.get("tool_name", "")))
        if not tool_name_value:
            raise ValueError("tool_name is required")
        tool_name = self._registry.resolve_name(tool_name_value) or ToolName(tool_name_value)
        tool_def = self._registry.get_tool(tool_name)
        if tool_def is None:
            await self._event_bus.publish(
                ToolRejected(
                    session_id=sid,
                    actor="control_api",
                    tool_name=tool_name,
                    reason="unknown_tool",
                )
            )
            raise ValueError(f"unknown tool: {tool_name}")
        try:
            params = self._merge_tool_arguments(params)
        except ValueError as exc:
            await self._event_bus.publish(
                ToolRejected(
                    session_id=sid,
                    actor="control_api",
                    tool_name=tool_name,
                    reason=f"invalid_tool_arguments:{exc}",
                )
            )
            raise
        params = await self._prepare_browser_tool_arguments(
            session=session,
            tool_name=tool_name,
            arguments=params,
        )
        skill_name = str(params.get("skill_name") or "").strip()
        if skill_name:
            network_hosts: list[str] = []
            for raw in params.get("network_urls", []):
                token = str(raw).strip()
                if not token:
                    continue
                host = urlparse(token).hostname or ""
                if host:
                    network_hosts.append(host.lower())
            for token in params.get("command", []):
                host = urlparse(str(token)).hostname or ""
                if host:
                    network_hosts.append(host.lower())
            runtime_decision = self._skill_manager.authorize_runtime(
                skill_name=skill_name,
                request=SkillExecutionRequest(
                    skill_name=skill_name,
                    network_hosts=network_hosts,
                    filesystem_paths=[str(item) for item in params.get("read_paths", [])]
                    + [str(item) for item in params.get("write_paths", [])],
                    shell_commands=[" ".join(str(token) for token in params.get("command", []))],
                    environment_vars=list(dict(params.get("env", {})).keys()),
                ),
            )
            if not runtime_decision.allowed:
                reason = runtime_decision.reason
                if runtime_decision.violations:
                    reason = reason + ":" + ",".join(runtime_decision.violations)
                await self._event_bus.publish(
                    ToolRejected(
                        session_id=sid,
                        actor="skill_sandbox",
                        tool_name=tool_name,
                        reason=reason,
                    )
                )
                return SandboxResult(
                    allowed=False,
                    reason=reason,
                ).model_dump(mode="json")

        patch_params = normalize_patch(dict(params))
        # Default direct admin execution posture to fail-closed when omitted.
        if (
            "degraded_mode" not in patch_params.model_fields_set
            or "security_critical" not in patch_params.model_fields_set
        ):
            strict_defaults = self._policy_loader.policy.sandbox.fail_closed_security_critical
            patched_params = dict(params)
            if "degraded_mode" not in patch_params.model_fields_set:
                patched_params["degraded_mode"] = (
                    DegradedModePolicy.FAIL_CLOSED.value
                    if strict_defaults
                    else DegradedModePolicy.FAIL_OPEN.value
                )
            if "security_critical" not in patch_params.model_fields_set:
                patched_params["security_critical"] = bool(strict_defaults)
            params = patched_params

        try:
            merged_policy = self._build_merged_policy(
                tool_name=tool_name,
                arguments=params,
                tool_definition=tool_def,
                operator_surface=True,
            )
        except PolicyMergeError as exc:
            await self._event_bus.publish(
                ToolRejected(
                    session_id=sid,
                    actor="control_api",
                    tool_name=tool_name,
                    reason=f"policy_floor_violation:{exc}",
                )
            )
            raise ValueError(f"policy floor violation: {exc}") from exc

        required_caps = set(tool_def.capabilities_required)
        if Capability.HTTP_REQUEST in required_caps and not tool_def.destinations:
            domains = [
                item.strip().lower() for item in merged_policy.network.allowed_domains if item
            ]
            if not domains:
                await self._event_bus.publish(
                    ToolRejected(
                        session_id=sid,
                        actor="control_api",
                        tool_name=tool_name,
                        reason="http.request_allowlist_required",
                    )
                )
                raise ValueError(
                    "http.request requires explicit network.allowed_domains "
                    "(policy override or per-call narrowing)"
                )
            if "*" in domains:
                await self._event_bus.publish(
                    ToolRejected(
                        session_id=sid,
                        actor="control_api",
                        tool_name=tool_name,
                        reason="http.request_wildcard_disallowed",
                    )
                )
                raise ValueError(
                    "http.request wildcard domains are not allowed; provide explicit domains"
                )

        rollout_phase = (
            self._policy_loader.policy.control_plane.egress.wildcard_rollout_phase.strip().lower()
        )
        merged_domains = [
            item.strip().lower() for item in merged_policy.network.allowed_domains if item
        ]
        if rollout_phase == "enforce" and "*" in merged_domains:
            await self._event_bus.publish(
                ToolRejected(
                    session_id=sid,
                    actor="control_api",
                    tool_name=tool_name,
                    reason="egress_wildcard_disallowed_without_break_glass",
                )
            )
            raise ValueError(
                "network wildcard domains are disallowed during enforce phase; "
                "use explicit host allowlists"
            )

        operator_origin = self._origin_for(
            session=session,
            actor="control_api",
            skill_name=skill_name,
        )
        trace_policy = self._policy_loader.policy.control_plane.trace
        previous_plan_hash = await _call_control_plane(self, "active_plan_hash", str(sid))
        committed_plan_hash = await _call_control_plane(
            self,
            "begin_precontent_plan",
            session_id=str(sid),
            goal=f"tool.execute:{tool_name_value}",
            origin=operator_origin,
            ttl_seconds=int(trace_policy.ttl_seconds),
            max_actions=int(trace_policy.max_actions),
            capabilities=session.capabilities,
        )
        if previous_plan_hash:
            await self._event_bus.publish(
                PlanCancelled(
                    session_id=sid,
                    actor="control_plane",
                    plan_hash=previous_plan_hash,
                    reason="superseded_by_tool_execute",
                )
            )
        plan_hash = (
            await _call_control_plane(self, "active_plan_hash", str(sid))
        ) or committed_plan_hash
        await self._event_bus.publish(
            PlanCommitted(
                session_id=sid,
                actor="control_plane",
                plan_hash=plan_hash,
                stage="stage1_precontent",
                expires_at="",
            )
        )

        risk_tier = self._risk_tier_for_tool_execute(
            network_enabled=bool(merged_policy.network.allow_network),
            write_paths=[str(item) for item in params.get("write_paths", [])],
            security_critical=bool(merged_policy.security_critical),
        )
        cp_eval = await _call_control_plane(
            self,
            "evaluate_action",
            tool_name=tool_name_value,
            arguments=dict(params),
            origin=operator_origin,
            risk_tier=risk_tier,
            declared_domains=merged_domains,
            # tool.execute is an explicit operator-initiated RPC path.
            # Keep this trusted/clean to preserve operator override semantics.
            session_tainted=False,
            trusted_input=True,
        )
        await self._publish_control_plane_evaluation(
            sid=sid,
            tool_name=tool_name,
            arguments=params,
            evaluation=cp_eval,
        )

        trace_only_confirmation_block = trace_reason_requires_confirmation(
            cp_eval.trace_result.reason_code
        ) and not any(
            vote.decision.value == "BLOCK" and vote.voter != TRACE_VOTER_NAME
            for vote in cp_eval.consensus.votes
        )
        stage2_upgrade_required = (
            cp_eval.trace_result.reason_code == "trace:stage2_upgrade_required"
        )
        trace_only_stage2_block = stage2_upgrade_required and trace_only_confirmation_block
        operator_confirmation_requirement = self._operator_confirmation_requirement(
            tool_name=tool_name,
            tool_definition=tool_def,
        )
        strip_direct_tool_execute_envelope_keys = (
            str(getattr(tool_def, "registration_source", "")).strip() == "mcp"
        )
        if trace_only_stage2_block and not bool(
            self._policy_loader.policy.control_plane.trace.allow_amendment
        ):
            reason = "trace:plan_amendment_disabled"
            await self._event_bus.publish(
                ToolRejected(
                    session_id=sid,
                    actor="control_api",
                    tool_name=tool_name,
                    reason=reason,
                )
            )
            return SandboxResult(
                allowed=False,
                reason=reason,
                origin=cp_eval.action.origin.model_dump(mode="json"),
            ).model_dump(mode="json")

        if (
            trace_only_confirmation_block
            or cp_eval.decision == ControlDecision.REQUIRE_CONFIRMATION
            or operator_confirmation_requirement is not None
        ):
            reason_codes = list(cp_eval.reason_codes)
            trace_reason = cp_eval.trace_result.reason_code
            if trace_only_confirmation_block and trace_reason not in reason_codes:
                reason_codes.append(trace_reason)
            if (
                operator_confirmation_requirement is not None
                and "policy:confirmation_required" not in reason_codes
            ):
                reason_codes.append("policy:confirmation_required")
            reason = ",".join(reason_codes) or "control_plane_confirmation_required"
            effective_caps = self._lockdown_manager.apply_capability_restrictions(
                sid,
                session.capabilities,
            )
            confirmation_requirement = operator_confirmation_requirement
            if (
                trace_only_confirmation_block
                or cp_eval.decision == ControlDecision.REQUIRE_CONFIRMATION
            ):
                requirements = [legacy_software_confirmation_requirement()]
                if operator_confirmation_requirement is not None:
                    requirements.append(operator_confirmation_requirement)
                confirmation_requirement = merge_confirmation_requirements(requirements)
            try:
                pending = self._queue_pending_action(
                    session_id=sid,
                    user_id=session.user_id,
                    workspace_id=session.workspace_id,
                    tool_name=tool_name,
                    arguments=dict(params),
                    reason=reason,
                    capabilities=effective_caps,
                    preflight_action=cp_eval.action,
                    merged_policy=merged_policy,
                    taint_labels=[],
                    confirmation_requirement=confirmation_requirement,
                    strip_direct_tool_execute_envelope_keys=(
                        strip_direct_tool_execute_envelope_keys
                    ),
                )
            except ApprovalRoutingError as exc:
                await self._event_bus.publish(
                    ToolRejected(
                        session_id=sid,
                        actor="control_api",
                        tool_name=tool_name,
                        reason=str(exc.reason),
                    )
                )
                return SandboxResult(
                    allowed=False,
                    reason=str(exc.reason),
                    origin=cp_eval.action.origin.model_dump(mode="json"),
                ).model_dump(mode="json")
            await self._event_bus.publish(
                ToolRejected(
                    session_id=sid,
                    actor="control_api",
                    tool_name=tool_name,
                    reason=f"{pending.reason} ({pending.confirmation_id})",
                )
            )
            confirmation_payload = SandboxResult(
                allowed=False,
                reason=reason,
                origin=cp_eval.action.origin.model_dump(mode="json"),
            ).model_dump(mode="json")
            confirmation_payload["confirmation_required"] = True
            confirmation_payload["confirmation_id"] = pending.confirmation_id
            confirmation_payload["decision_nonce"] = pending.decision_nonce
            confirmation_payload["safe_preview"] = pending.safe_preview
            confirmation_payload["warnings"] = list(pending.warnings)
            if pending.execute_after is not None:
                confirmation_payload["execute_after"] = pending.execute_after.isoformat()
            return confirmation_payload

        if cp_eval.decision == ControlDecision.BLOCK:
            if not cp_eval.trace_result.allowed:
                await self._record_plan_violation(
                    sid=sid,
                    tool_name=tool_name,
                    action_kind=cp_eval.action.action_kind,
                    reason_code=cp_eval.trace_result.reason_code,
                    risk_tier=cp_eval.trace_result.risk_tier,
                )
            reason = ",".join(cp_eval.reason_codes) or "control_plane_block"
            await self._event_bus.publish(
                ToolRejected(
                    session_id=sid,
                    actor="control_api",
                    tool_name=tool_name,
                    reason=reason,
                )
            )
            return SandboxResult(
                allowed=False,
                reason=reason,
                origin=cp_eval.action.origin.model_dump(mode="json"),
            ).model_dump(mode="json")

        execution = await self._execute_approved_action(
            sid=sid,
            user_id=session.user_id,
            tool_name=tool_name,
            arguments=dict(params),
            capabilities=set(session.capabilities),
            approval_actor="control_api",
            execution_action=cp_eval.action,
            merged_policy=merged_policy,
            user_confirmed=True,
            strip_direct_tool_execute_envelope_keys=strip_direct_tool_execute_envelope_keys,
        )
        return cast(
            dict[str, Any],
            self._tool_execute_result_from_execution(
                execution=execution,
                origin=operator_origin,
            ),
        )

    @staticmethod
    def _merge_tool_arguments(params: Mapping[str, Any]) -> dict[str, Any]:
        payload = dict(params)
        raw_arguments = payload.pop("arguments", {})
        if not raw_arguments:
            return payload
        if not isinstance(raw_arguments, Mapping):
            raise ValueError("arguments must be an object")
        merged_arguments: dict[str, Any] = {}
        for raw_key, value in raw_arguments.items():
            key = str(raw_key).strip()
            if not key:
                raise ValueError("arguments keys must be non-empty strings")
            merged_arguments[key] = value
        collisions = sorted(
            key for key in merged_arguments if key in _RESERVED_TOOL_EXECUTION_ARGUMENT_KEYS
        )
        if collisions:
            joined = ", ".join(collisions)
            raise ValueError(f"arguments must not include reserved execution keys: {joined}")
        payload.update(merged_arguments)
        return payload

    async def do_browser_paste(self, params: Mapping[str, Any]) -> dict[str, Any]:
        sid = SessionId(str(params.get("session_id", "")))
        if not sid:
            raise ValueError("session_id is required")
        labels: set[TaintLabel] = set()
        for raw in params.get("taint_labels", []):
            try:
                labels.add(TaintLabel(str(raw)))
            except ValueError:
                continue
        result = self._browser_sandbox.paste(str(params.get("text", "")), taint_labels=labels)
        if not result.allowed:
            await self._event_bus.publish(
                ToolRejected(
                    session_id=sid,
                    actor="browser_sandbox",
                    tool_name=ToolName("browser.paste"),
                    reason=result.reason or "browser_paste_blocked",
                )
            )
        return cast(dict[str, Any], result.model_dump(mode="json"))

    async def do_browser_screenshot(self, params: Mapping[str, Any]) -> dict[str, Any]:
        sid = SessionId(str(params.get("session_id", "")))
        if not sid:
            raise ValueError("session_id is required")
        result = self._browser_sandbox.store_screenshot(
            session_id=str(sid),
            image_base64=str(params.get("image_base64", "")),
            ocr_text=str(params.get("ocr_text", "")),
        )
        return cast(dict[str, Any], result.model_dump(mode="json"))
