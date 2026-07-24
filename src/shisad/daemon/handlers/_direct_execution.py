"""Shared execution authority for typed direct convenience RPCs."""

from __future__ import annotations

import json
import logging
import os
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from shisad.core.action_state import ActionOperationIdentity, mint_action_operation_identity
from shisad.core.api.rpc_registry import (
    RpcHandlerGroup,
    RpcMethodDescriptor,
    rpc_method_descriptor,
)
from shisad.core.events import PlanCommitted, SessionCreated, SessionTerminated, ToolRejected
from shisad.core.types import PEPDecisionKind, SessionMode, ToolName, UserId, WorkspaceId
from shisad.core.url_parsing import safe_url_hostname
from shisad.daemon.handlers._mixin_typing import HandlerMixinBase
from shisad.daemon.handlers._mixin_typing import call_control_plane as _call_control_plane
from shisad.governance.merge import PolicyMergeError
from shisad.security.control_plane.consensus import TRACE_VOTER_NAME
from shisad.security.control_plane.schema import ControlDecision, RiskTier
from shisad.security.control_plane.trace import trace_reason_requires_confirmation
from shisad.security.pep import PolicyContext

logger = logging.getLogger(__name__)


def _authenticated_peer_uid(params: Mapping[str, Any]) -> int | None:
    peer = params.get("_rpc_peer")
    if not isinstance(peer, Mapping):
        return None
    uid = peer.get("uid")
    if type(uid) is not int or uid < 0:
        return None
    return uid


def _risk_tier_from_score(score: float | None) -> RiskTier:
    value = float(score or 0.0)
    if value >= 0.9:
        return RiskTier.CRITICAL
    if value >= 0.75:
        return RiskTier.HIGH
    if value >= 0.45:
        return RiskTier.MEDIUM
    return RiskTier.LOW


def _direct_failure(
    tool_name: str,
    reason: str,
    *,
    confirmation_required: bool = False,
) -> dict[str, Any]:
    payload: dict[str, Any] = {"ok": False}
    if tool_name == "fs.write":
        payload.update(
            {
                "written": False,
                "confirmation_required": confirmation_required,
            }
        )
    payload["error"] = reason
    return payload


def _declared_domains(tool_definition: Any, arguments: Mapping[str, Any]) -> list[str]:
    domains: set[str] = set()

    def _add_exact(host: str) -> None:
        normalized = host.strip().lower().rstrip(".")
        if normalized and not any(token in normalized for token in ("*", "?", "[", "]")):
            domains.add(normalized)

    for destination in getattr(tool_definition, "destinations", []):
        value = str(destination).strip().lower()
        if not value:
            continue
        if "://" in value:
            _add_exact(safe_url_hostname(value, strip_trailing_dot=True))
            continue
        _add_exact(value.split(":", 1)[0])
    url = arguments.get("url")
    if isinstance(url, str):
        _add_exact(safe_url_hostname(url, strip_trailing_dot=True))
    return sorted(domains)


class DirectExecutionMixin(HandlerMixinBase):
    """Enter shared policy and execution authority from typed direct RPCs."""

    async def _execute_direct_tool_rpc(
        self,
        tool_name: str,
        params: Mapping[str, Any],
    ) -> dict[str, Any]:
        descriptor = rpc_method_descriptor(tool_name)
        if descriptor is None or descriptor.handler_group is not RpcHandlerGroup.ASSISTANT:
            return _direct_failure(tool_name, "direct_rpc_route_not_permitted")

        uid = _authenticated_peer_uid(params)
        if uid is None:
            return _direct_failure(tool_name, "direct_rpc_authenticated_peer_required")
        owner_uid = int(getattr(self, "_daemon_owner_uid", os.getuid()))
        if descriptor.admin_only and uid not in {0, owner_uid}:
            return _direct_failure(tool_name, "direct_rpc_admin_peer_required")

        arguments = self._validated_direct_arguments(descriptor, params)
        if arguments is None:
            return _direct_failure(tool_name, "direct_rpc_invalid_parameters")

        session = None
        operation_identity = mint_action_operation_identity()
        user_id = UserId(f"uid:{uid}")
        workspace_id = WorkspaceId("direct-rpc")
        try:
            peer = params.get("_rpc_peer")
            peer_metadata = (
                {
                    str(key): value
                    for key, value in peer.items()
                    if isinstance(key, str) and type(value) is int
                }
                if isinstance(peer, Mapping)
                else {}
            )
            session = self._session_manager.create(
                channel="direct_rpc",
                user_id=user_id,
                workspace_id=workspace_id,
                mode=SessionMode.DEFAULT,
                capabilities=set(self._policy_loader.policy.default_capabilities),
                metadata={
                    "trust_level": "trusted",
                    "session_mode": SessionMode.DEFAULT.value,
                    "operator_owned_direct_rpc": True,
                    "capability_sync_mode": "policy_default",
                    "created_rpc_peer": peer_metadata,
                },
            )
            await self._event_bus.publish(
                SessionCreated(
                    session_id=session.id,
                    user_id=user_id,
                    workspace_id=workspace_id,
                    actor="direct_rpc",
                )
            )
            return await self._execute_direct_in_session(
                descriptor=descriptor,
                arguments=arguments,
                session=session,
                operation_identity=operation_identity,
            )
        except Exception:
            logger.exception("Direct RPC execution failed: tool=%s", tool_name)
            return _direct_failure(tool_name, "direct_execution_unavailable")
        finally:
            if session is not None:
                self._lockdown_manager.clear_state(session.id)
                self._monitor_reject_counts.pop(session.id, None)
                self._plan_violation_counts.pop(session.id, None)
                terminated = self._terminate_session(
                    session.id,
                    reason="direct_rpc_complete",
                )
                if terminated:
                    try:
                        await self._event_bus.publish(
                            SessionTerminated(
                                session_id=session.id,
                                actor="direct_rpc",
                                reason="direct_rpc_complete",
                            )
                        )
                    except Exception:
                        logger.exception(
                            "Direct RPC termination audit failed: session=%s",
                            session.id,
                        )

    @staticmethod
    def _validated_direct_arguments(
        descriptor: RpcMethodDescriptor,
        params: Mapping[str, Any],
    ) -> dict[str, Any] | None:
        public_payload = {
            name: params[name] for name in descriptor.params_model.model_fields if name in params
        }
        try:
            validated = descriptor.params_model.model_validate(public_payload)
        except ValidationError:
            return None
        return validated.model_dump(mode="json", exclude_unset=True)

    async def _execute_direct_in_session(
        self,
        *,
        descriptor: RpcMethodDescriptor,
        arguments: dict[str, Any],
        session: Any,
        operation_identity: ActionOperationIdentity,
    ) -> dict[str, Any]:
        tool_name = ToolName(descriptor.name)
        host_patterns = set(_declared_domains(None, arguments))
        context = PolicyContext(
            capabilities=set(session.capabilities),
            session_id=session.id,
            workspace_id=session.workspace_id,
            user_id=session.user_id,
            tool_allowlist=None,
            trust_level="trusted",
            trusted_cli_confirmation_bypass=True,
            user_goal_host_patterns=host_patterns,
            filesystem_roots=tuple(
                Path(item) for item in getattr(self._config, "assistant_fs_roots", [])
            ),
        )
        pep_decision = self._pep.for_policy(self._policy_loader.policy).evaluate(
            tool_name,
            arguments,
            context,
        )
        tool_definition = self._registry.get_tool(tool_name)
        if pep_decision.kind is not PEPDecisionKind.ALLOW:
            await self._publish_direct_rejection(
                session=session,
                tool_name=tool_name,
                reason=pep_decision.reason_code or "pep:rejected",
                decision=pep_decision.kind,
                operation_identity=operation_identity,
            )
            readiness = self._realitycheck_readiness_payload(
                tool_name=tool_name,
                arguments=arguments,
                tool_definition=tool_definition,
            )
            if readiness is not None:
                return readiness
            return _direct_failure(
                str(tool_name),
                pep_decision.reason_code or "pep:rejected",
                confirmation_required=(pep_decision.kind is PEPDecisionKind.REQUIRE_CONFIRMATION),
            )

        if tool_definition is None:
            await self._publish_direct_rejection(
                session=session,
                tool_name=tool_name,
                reason="pep:unknown_tool",
                decision=PEPDecisionKind.REJECT,
                operation_identity=operation_identity,
            )
            return _direct_failure(str(tool_name), "pep:unknown_tool")

        try:
            merged_policy = self._build_merged_policy(
                tool_name=tool_name,
                arguments=arguments,
                tool_definition=tool_definition,
                operator_surface=True,
            )
        except PolicyMergeError:
            await self._publish_direct_rejection(
                session=session,
                tool_name=tool_name,
                reason="policy_floor_violation",
                decision=PEPDecisionKind.REJECT,
                operation_identity=operation_identity,
            )
            return _direct_failure(str(tool_name), "policy_floor_violation")

        domains = _declared_domains(tool_definition, arguments)
        resource_roots = [str(item) for item in getattr(self._config, "assistant_fs_roots", [])]
        trace_policy = self._policy_loader.policy.control_plane.trace
        origin = self._origin_for(session=session, actor="direct_rpc")
        plan_hash = await _call_control_plane(
            self,
            "begin_precontent_plan",
            session_id=str(session.id),
            goal=f"direct_rpc:{tool_name}",
            origin=origin,
            ttl_seconds=int(trace_policy.ttl_seconds),
            max_actions=int(trace_policy.max_actions),
            capabilities=set(session.capabilities),
            declared_resource_roots=[*resource_roots, *domains],
        )
        await self._event_bus.publish(
            PlanCommitted(
                session_id=session.id,
                actor="control_plane",
                plan_hash=plan_hash,
                stage="stage1_precontent",
                expires_at="",
            )
        )
        control_evaluation = await _call_control_plane(
            self,
            "evaluate_action",
            tool_name=str(tool_name),
            arguments=dict(arguments),
            origin=origin,
            risk_tier=_risk_tier_from_score(pep_decision.risk_score),
            declared_domains=domains,
            session_tainted=False,
            trusted_input=True,
            operator_owned_cli_input=True,
        )
        await self._publish_control_plane_evaluation(
            sid=session.id,
            tool_name=tool_name,
            arguments=arguments,
            evaluation=control_evaluation,
        )

        trace_only_confirmation = trace_reason_requires_confirmation(
            control_evaluation.trace_result.reason_code
        ) and not any(
            vote.decision.value == "BLOCK" and vote.voter != TRACE_VOTER_NAME
            for vote in control_evaluation.consensus.votes
        )
        if (
            trace_only_confirmation
            or control_evaluation.decision is ControlDecision.REQUIRE_CONFIRMATION
        ):
            reason = self._sanitized_direct_reason(
                (
                    ",".join(control_evaluation.reason_codes)
                    or control_evaluation.trace_result.reason_code
                ),
                fallback="control_plane_confirmation_required",
            )
            await self._publish_direct_rejection(
                session=session,
                tool_name=tool_name,
                reason=reason,
                decision=PEPDecisionKind.REQUIRE_CONFIRMATION,
                operation_identity=operation_identity,
            )
            return _direct_failure(
                str(tool_name),
                reason,
                confirmation_required=True,
            )
        if control_evaluation.decision is ControlDecision.BLOCK:
            if not control_evaluation.trace_result.allowed:
                await self._record_plan_violation(
                    sid=session.id,
                    tool_name=tool_name,
                    action_kind=control_evaluation.action.action_kind,
                    reason_code=control_evaluation.trace_result.reason_code,
                    risk_tier=control_evaluation.trace_result.risk_tier,
                )
            reason = self._sanitized_direct_reason(
                ",".join(control_evaluation.reason_codes),
                fallback="control_plane_block",
            )
            await self._publish_direct_rejection(
                session=session,
                tool_name=tool_name,
                reason=reason,
                decision=PEPDecisionKind.REJECT,
                operation_identity=operation_identity,
            )
            boundary_payload = self._filesystem_boundary_payload(
                tool_name=tool_name,
                arguments=arguments,
            )
            if boundary_payload is not None:
                return boundary_payload
            return _direct_failure(str(tool_name), reason)

        rate_decision = self._rate_limiter.evaluate(
            session_id=str(session.id),
            user_id=str(session.user_id),
            tool_name=str(tool_name),
            consume=False,
        )
        if rate_decision.block or rate_decision.require_confirmation:
            requires_confirmation = bool(rate_decision.require_confirmation)
            reason = f"rate_limit:{rate_decision.reason}"
            if rate_decision.block:
                await self._handle_lockdown_transition(
                    session.id,
                    trigger="rate_limit",
                    reason=rate_decision.reason,
                )
            await self._publish_direct_rejection(
                session=session,
                tool_name=tool_name,
                reason=reason,
                decision=(
                    PEPDecisionKind.REQUIRE_CONFIRMATION
                    if requires_confirmation
                    else PEPDecisionKind.REJECT
                ),
                operation_identity=operation_identity,
            )
            return _direct_failure(
                str(tool_name),
                reason,
                confirmation_required=requires_confirmation,
            )

        execution = await self._execute_approved_action(
            sid=session.id,
            user_id=session.user_id,
            workspace_id=session.workspace_id,
            tool_name=tool_name,
            arguments=dict(arguments),
            capabilities=set(session.capabilities),
            approval_actor="direct_rpc",
            execution_action=control_evaluation.action,
            merged_policy=merged_policy,
            user_confirmed=bool(tool_name == ToolName("fs.write") and arguments.get("confirm")),
            persist_attempt_before_effect=True,
            **operation_identity.to_event_fields(),
        )
        if execution.tool_output is None:
            return _direct_failure(
                str(tool_name),
                self._sanitized_direct_reason(
                    execution.error,
                    fallback="direct_execution_failed",
                ),
            )
        try:
            payload = json.loads(execution.tool_output.content)
        except (TypeError, json.JSONDecodeError):
            return _direct_failure(str(tool_name), "direct_execution_invalid_result")
        if not isinstance(payload, dict):
            return _direct_failure(str(tool_name), "direct_execution_invalid_result")
        return payload

    def _sanitized_direct_reason(self, reason: str, *, fallback: str) -> str:
        sanitized = self._sanitize_tool_output_text(str(reason)).strip()
        return sanitized[:512] or fallback

    async def _publish_direct_rejection(
        self,
        *,
        session: Any,
        tool_name: ToolName,
        reason: str,
        decision: PEPDecisionKind,
        operation_identity: ActionOperationIdentity,
    ) -> None:
        await self._event_bus.publish(
            ToolRejected(
                session_id=session.id,
                actor="direct_rpc",
                tool_name=tool_name,
                decision=decision,
                reason=reason,
                user_id=str(session.user_id),
                workspace_id=str(session.workspace_id),
                approval_session_id=str(session.id),
                **operation_identity.to_event_fields(),
            )
        )

    def _realitycheck_readiness_payload(
        self,
        *,
        tool_name: ToolName,
        arguments: Mapping[str, Any],
        tool_definition: Any,
    ) -> dict[str, Any] | None:
        if tool_definition is not None or str(tool_name) not in {
            "realitycheck.search",
            "realitycheck.read",
        }:
            return None
        status = self._realitycheck_toolkit.doctor_status()
        if str(status.get("status", "")).strip() not in {"disabled", "misconfigured"}:
            return None
        if str(tool_name) == "realitycheck.search":
            payload = self._realitycheck_toolkit.search(
                query=str(arguments.get("query", "")),
                limit=int(arguments.get("limit", 5)),
                mode=str(arguments.get("mode", "auto")),
            )
        else:
            raw_max_bytes = arguments.get("max_bytes")
            payload = self._realitycheck_toolkit.read_source(
                path=str(arguments.get("path", "")),
                max_bytes=int(raw_max_bytes) if raw_max_bytes is not None else None,
            )
        sanitized = self._sanitize_tool_output_text(json.dumps(dict(payload), ensure_ascii=True))
        try:
            decoded = json.loads(sanitized)
        except json.JSONDecodeError:
            return _direct_failure(str(tool_name), "realitycheck_unavailable")
        return decoded if isinstance(decoded, dict) else None

    def _filesystem_boundary_payload(
        self,
        *,
        tool_name: ToolName,
        arguments: Mapping[str, Any],
    ) -> dict[str, Any] | None:
        path_key = "repo_path" if str(tool_name).startswith("git.") else "path"
        if path_key not in arguments:
            return None
        resolver = getattr(self._fs_git_toolkit, "_resolve_path", None)
        if not callable(resolver):
            return None
        try:
            resolution = resolver(str(arguments[path_key]))
        except (OSError, RuntimeError, TypeError, ValueError):
            return None
        if not isinstance(resolution, Mapping):
            return None
        payload = dict(resolution)
        if payload.get("error") not in {
            "fs_roots_unconfigured",
            "path_not_allowlisted",
            "protected_control_plane_path",
        }:
            return None
        sanitized = self._sanitize_tool_output_text(json.dumps(payload, ensure_ascii=True))
        try:
            decoded = json.loads(sanitized)
        except json.JSONDecodeError:
            return None
        return decoded if isinstance(decoded, dict) else None
