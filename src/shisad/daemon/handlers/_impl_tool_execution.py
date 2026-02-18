"""Tool and browser execution handler implementations."""

from __future__ import annotations

import logging
from collections.abc import Mapping
from typing import Any, cast
from urllib.parse import urlparse

from shisad.core.events import (
    ConsensusEvaluated,
    ControlPlaneActionObserved,
    ControlPlaneNetworkObserved,
    ControlPlaneResourceObserved,
    PlanCancelled,
    PlanCommitted,
    ToolExecuted,
    ToolRejected,
)
from shisad.core.tools.names import canonical_tool_name
from shisad.core.types import Capability, SessionId, TaintLabel, ToolName
from shisad.daemon.handlers._mixin_typing import HandlerMixinBase
from shisad.executors.sandbox import DegradedModePolicy, SandboxConfig, SandboxResult
from shisad.governance.merge import PolicyMerge, PolicyMergeError, normalize_patch
from shisad.security.control_plane.schema import ControlDecision, extract_request_size_bytes
from shisad.skills.sandbox import SkillExecutionRequest

logger = logging.getLogger(__name__)


class ToolExecutionImplMixin(HandlerMixinBase):
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
        tool_name = ToolName(tool_name_value)
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
                    filesystem_paths=[
                        str(item) for item in params.get("read_paths", [])
                    ]
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
            patch_params = normalize_patch(params)

        floor = self._compute_tool_policy_floor(
            tool_name=tool_name,
            tool_definition=tool_def,
            operator_surface=True,
        )
        try:
            merged_policy = PolicyMerge.merge(server=floor, caller=patch_params)
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
                item.strip().lower()
                for item in merged_policy.network.allowed_domains
                if item
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
        previous_plan_hash = self._control_plane.active_plan_hash(str(sid))
        committed_plan_hash = self._control_plane.begin_precontent_plan(
            session_id=str(sid),
            goal=f"tool.execute:{tool_name_value}",
            origin=operator_origin,
            ttl_seconds=int(trace_policy.ttl_seconds),
            max_actions=int(trace_policy.max_actions),
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
        plan_hash = self._control_plane.active_plan_hash(str(sid)) or committed_plan_hash
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
        cp_eval = await self._control_plane.evaluate_action(
            tool_name=tool_name_value,
            arguments=dict(params),
            origin=operator_origin,
            risk_tier=risk_tier,
            declared_domains=merged_domains,
            explicit_side_effect_intent=True,
        )
        await self._event_bus.publish(
            ConsensusEvaluated(
                session_id=sid,
                actor="control_plane",
                tool_name=tool_name,
                decision=cp_eval.decision.value,
                risk_tier=cp_eval.consensus.risk_tier.value,
                reason_codes=list(cp_eval.reason_codes),
                votes=[vote.model_dump(mode="json") for vote in cp_eval.consensus.votes],
            )
        )
        await self._event_bus.publish(
            ControlPlaneActionObserved(
                session_id=sid,
                actor="control_plane",
                tool_name=tool_name,
                action_kind=cp_eval.action.action_kind.value,
                resource_id=cp_eval.action.resource_id,
                decision=cp_eval.decision.value,
                reason_codes=list(cp_eval.reason_codes),
                origin=cp_eval.action.origin.model_dump(mode="json"),
            )
        )
        for resource in cp_eval.action.resource_ids:
            await self._event_bus.publish(
                ControlPlaneResourceObserved(
                    session_id=sid,
                    actor="control_plane",
                    tool_name=tool_name,
                    action_kind=cp_eval.action.action_kind.value,
                    resource_id=resource,
                    origin=cp_eval.action.origin.model_dump(mode="json"),
                )
            )
        for host in cp_eval.action.network_hosts:
            await self._event_bus.publish(
                ControlPlaneNetworkObserved(
                    session_id=sid,
                    actor="control_plane",
                    tool_name=tool_name,
                    destination_host=host,
                    destination_port=443,
                    protocol="https",
                    request_size=extract_request_size_bytes(dict(params)),
                    allowed=cp_eval.decision == ControlDecision.ALLOW,
                    reason="preflight",
                    origin=cp_eval.action.origin.model_dump(mode="json"),
                )
            )

        stage2_upgrade_required = (
            cp_eval.trace_result.reason_code == "trace:stage2_upgrade_required"
        )
        trace_only_stage2_block = stage2_upgrade_required and not any(
            vote.decision.value == "BLOCK" and vote.voter != "ExecutionTraceVerifier"
            for vote in cp_eval.consensus.votes
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

        if trace_only_stage2_block or cp_eval.decision == ControlDecision.REQUIRE_CONFIRMATION:
            reason_codes = list(cp_eval.reason_codes)
            if trace_only_stage2_block and "trace:stage2_upgrade_required" not in reason_codes:
                reason_codes.append("trace:stage2_upgrade_required")
            reason = ",".join(reason_codes) or "control_plane_confirmation_required"
            effective_caps = self._lockdown_manager.apply_capability_restrictions(
                sid,
                session.capabilities,
            )
            pending = self._queue_pending_action(
                session_id=sid,
                user_id=session.user_id,
                workspace_id=session.workspace_id,
                tool_name=tool_name,
                arguments=dict(params),
                reason=reason,
                capabilities=effective_caps,
                preflight_action=cp_eval.action,
                taint_labels=[],
            )
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

        config = SandboxConfig(
            session_id=str(sid),
            tool_name=tool_name_value,
            command=list(params.get("command", [])),
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
            approved_by_pep=cp_eval.decision == ControlDecision.ALLOW,
            filesystem=merged_policy.filesystem,
            network=merged_policy.network,
            environment=merged_policy.environment,
            limits=merged_policy.limits,
            degraded_mode=merged_policy.degraded_mode,
            origin=operator_origin.model_dump(mode="json"),
        )
        result = await self._execute_sandbox_config(
            sid=sid,
            session=session,
            tool_name=ToolName(config.tool_name),
            config=config,
        )
        await self._publish_sandbox_events(
            sid=sid,
            config_tool_name=ToolName(config.tool_name),
            result=result,
        )

        await self._event_bus.publish(
            ToolExecuted(
                session_id=sid,
                actor="sandbox",
                tool_name=ToolName(config.tool_name),
                success=bool(
                    result.allowed and not result.timed_out and (result.exit_code or 0) == 0
                ),
                error="" if result.allowed else result.reason,
            )
        )
        success = bool(result.allowed and not result.timed_out and (result.exit_code or 0) == 0)
        self._control_plane.record_execution(action=cp_eval.action, success=success)
        return cast(dict[str, Any], result.model_dump(mode="json"))

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
