"""Task scheduler handler implementations."""

from __future__ import annotations

import asyncio
import hashlib
from collections.abc import Mapping
from typing import Any, cast

from shisad.channels.base import DeliveryTarget
from shisad.core.action_state import mint_action_operation_identity
from shisad.core.approval import ApprovalRoutingError, ConfirmationRequirement
from shisad.core.events import (
    AnomalyReported,
    PlanCancelled,
    PlanCommitted,
    TaskScheduled,
    TaskTriggered,
    ToolRejected,
)
from shisad.core.types import (
    Capability,
    CredentialRef,
    PEPDecisionKind,
    SessionId,
    SessionMode,
    SessionRole,
    SessionState,
    TaintLabel,
    ToolName,
    UserId,
    WorkspaceId,
)
from shisad.core.url_parsing import safe_url_hostname
from shisad.daemon.handlers._mixin_typing import (
    HandlerMixinBase,
)
from shisad.daemon.handlers._mixin_typing import (
    call_control_plane as _call_control_plane,
)
from shisad.daemon.handlers._pending_approval import (
    pending_action_event_identity_fields,
    pending_action_state_view,
)
from shisad.daemon.handlers._string_utils import optional_string
from shisad.daemon.handlers._task_scope import task_resource_authorizer
from shisad.scheduler.schema import Schedule
from shisad.security.control_plane.consensus import TRACE_VOTER_NAME
from shisad.security.control_plane.schema import ControlDecision, Origin, RiskTier
from shisad.security.pep import PolicyContext

_BACKGROUND_MESSAGE_SEND = ToolName("message.send")


def _recipient_matches_rule(recipient: str, rule: str) -> bool:
    normalized_recipient = recipient.strip().lower()
    normalized_rule = rule.strip().lower()
    if not normalized_recipient or not normalized_rule:
        return False
    if normalized_rule.startswith("*."):
        return normalized_recipient.endswith(normalized_rule[1:])
    return normalized_recipient == normalized_rule


def _recipient_domain(recipient: str) -> str:
    value = recipient.strip()
    if not value:
        return ""
    parsed_host = safe_url_hostname(value)
    if parsed_host:
        return parsed_host
    fallback_host = safe_url_hostname(f"https://{value}")
    if fallback_host:
        return fallback_host
    if "@" in value:
        _, _, domain = value.rpartition("@")
        return domain.lower().strip()
    return ""


def _payload_taints(payload_taint: str) -> set[TaintLabel]:
    if payload_taint.strip().lower() == "trusted_scheduler":
        return set()
    return {TaintLabel.UNTRUSTED}


def _payload_trust_level(payload_taint: str) -> str:
    if payload_taint.strip().lower() == "trusted_scheduler":
        return "internal"
    return "untrusted"


def _join_reason_codes(*codes: str) -> str:
    ordered: list[str] = []
    for code in codes:
        normalized = str(code).strip()
        if normalized and normalized not in ordered:
            ordered.append(normalized)
    return ",".join(ordered)


class TasksImplMixin(HandlerMixinBase):
    def _task_lifecycle_lock(self, task_id: str) -> asyncio.Lock:
        locks = getattr(self, "_task_lifecycle_locks", None)
        if not isinstance(locks, dict):
            locks = {}
            self._task_lifecycle_locks = locks
        lock = locks.get(task_id)
        if lock is None:
            lock = asyncio.Lock()
            locks[task_id] = lock
        return lock

    def _discard_task_lifecycle_lock_if_idle(
        self,
        task_id: str,
        lock: asyncio.Lock,
    ) -> None:
        if lock.locked() or bool(getattr(lock, "_waiters", None)):
            return
        locks = getattr(self, "_task_lifecycle_locks", None)
        if isinstance(locks, dict) and locks.get(task_id) is lock:
            locks.pop(task_id, None)

    async def _publish_task_anomaly(
        self,
        *,
        session_id: SessionId | None,
        description: str,
        recommended_action: str,
    ) -> None:
        await self._event_bus.publish(
            AnomalyReported(
                session_id=session_id,
                actor="scheduler",
                severity="warning",
                description=description,
                recommended_action=recommended_action,
            )
        )

    @staticmethod
    def _task_delivery_arguments(task: Any) -> dict[str, Any] | None:
        delivery_target = getattr(task, "delivery_target", {}) or {}
        if not isinstance(delivery_target, Mapping):
            return None
        channel = optional_string(delivery_target.get("channel", ""))
        recipient = optional_string(delivery_target.get("recipient", ""))
        if not channel or not recipient:
            return None
        payload: dict[str, Any] = {
            "channel": channel,
            "recipient": recipient,
            "message": optional_string(getattr(task, "goal", "")),
        }
        workspace_hint = optional_string(delivery_target.get("workspace_hint", ""))
        thread_id = optional_string(delivery_target.get("thread_id", ""))
        if workspace_hint:
            payload["workspace_hint"] = workspace_hint
        if thread_id:
            payload["thread_id"] = thread_id
        return payload

    @staticmethod
    def _task_delivery_target(task: Any) -> DeliveryTarget | None:
        arguments = TasksImplMixin._task_delivery_arguments(task)
        if arguments is None:
            return None
        return DeliveryTarget(
            channel=str(arguments["channel"]),
            recipient=str(arguments["recipient"]),
            workspace_hint=str(arguments.get("workspace_hint", "")),
            thread_id=str(arguments.get("thread_id", "")),
        )

    @staticmethod
    def _task_scope_mismatch_reason(task: Any, arguments: Mapping[str, Any]) -> str:
        recipient = str(arguments.get("recipient", "")).strip()
        recipient_allowlist = [
            str(item).strip()
            for item in getattr(task, "allowed_recipients", [])
            if str(item).strip()
        ]
        if recipient_allowlist and not any(
            _recipient_matches_rule(recipient, rule) for rule in recipient_allowlist
        ):
            return "background:recipient_scope_mismatch"

        domain_allowlist = [
            str(item).strip() for item in getattr(task, "allowed_domains", []) if str(item).strip()
        ]
        if domain_allowlist:
            destination_domain = _recipient_domain(recipient)
            if not destination_domain or not any(
                _recipient_matches_rule(destination_domain, rule) for rule in domain_allowlist
            ):
                return "background:domain_scope_mismatch"
        return ""

    def _ensure_task_execution_session(self, task: Any) -> Any:
        existing_id = str(getattr(task, "execution_session_id", "")).strip()
        if existing_id:
            existing = self._session_manager.get(SessionId(existing_id))
            if existing is not None:
                return existing

        task_envelope = getattr(task, "task_envelope", None)
        parent_session_id = None
        if task_envelope is not None:
            raw_parent_session_id = str(getattr(task_envelope, "parent_session_id", "")).strip()
            if raw_parent_session_id:
                parent_session_id = SessionId(raw_parent_session_id)

        session = self._session_manager.create_subagent_session(
            channel="scheduler",
            user_id=UserId(str(getattr(task, "created_by", ""))),
            workspace_id=WorkspaceId(str(getattr(task, "workspace_id", ""))),
            parent_session_id=parent_session_id,
            mode=SessionMode.DEFAULT,
            capabilities=set(getattr(task, "capability_snapshot", set())),
            metadata={
                "trust_level": "internal",
                "background_task_id": str(getattr(task, "id", "")),
                "task_envelope": (
                    task_envelope.model_dump(mode="json") if task_envelope is not None else {}
                ),
            },
        )
        self._scheduler.attach_execution_session(str(getattr(task, "id", "")), str(session.id))
        return session

    @staticmethod
    def _task_origin_for(
        *,
        session: Any,
        task: Any,
        trust_level: str,
    ) -> Origin:
        return Origin(
            session_id=str(session.id),
            user_id=str(getattr(task, "created_by", "")),
            workspace_id=str(getattr(task, "workspace_id", "")),
            task_id=str(getattr(task, "id", "")),
            actor="scheduler",
            channel=str(getattr(session, "channel", "scheduler")),
            trust_level=trust_level,
        )

    @staticmethod
    def _background_risk_tier(*, payload_taint: str, scope_mismatch: bool) -> RiskTier:
        if payload_taint.strip().lower() != "trusted_scheduler":
            return RiskTier.HIGH
        if scope_mismatch:
            return RiskTier.MEDIUM
        return RiskTier.LOW

    async def _queue_task_confirmation(
        self,
        *,
        task: Any,
        run: Any,
        event_type: str,
        session: Any,
        arguments: dict[str, Any],
        reason: str,
        capabilities: set[Capability],
        preflight_action: Any | None,
        confirmation_requirement: ConfirmationRequirement | None = None,
    ) -> str:
        pending = self._queue_pending_action(
            session_id=session.id,
            user_id=UserId(str(getattr(task, "created_by", ""))),
            workspace_id=WorkspaceId(str(getattr(task, "workspace_id", ""))),
            task_id=str(getattr(task, "id", "")),
            tool_name=_BACKGROUND_MESSAGE_SEND,
            arguments=dict(arguments),
            reason=reason,
            capabilities=set(capabilities),
            delivery_target=self._task_delivery_target(task),
            preflight_action=preflight_action,
            taint_labels=list(_payload_taints(str(getattr(run, "payload_taint", "")))),
            confirmation_requirement=confirmation_requirement,
            origin_turn_id=(
                "task-run:"
                + hashlib.sha256(
                    (
                        f"{getattr(task, 'id', '')}\x00"
                        f"{getattr(task, 'trigger_count', '')}\x00"
                        f"{getattr(run, 'plan_commitment', '')}\x00"
                        f"{getattr(run, 'trigger_payload', '')}"
                    ).encode()
                ).hexdigest()[:32]
            ),
        )
        action_state = pending_action_state_view(pending)
        self._scheduler.queue_confirmation(
            str(getattr(task, "id", "")),
            {
                "confirmation_id": pending.confirmation_id,
                "action_id": action_state.identity.action_id,
                "execution_attempt_id": action_state.identity.execution_attempt_id,
                "identity": action_state.identity.to_payload(),
                "lifecycle_state": action_state.lifecycle_state,
                "session_id": str(session.id),
                "task_id": str(getattr(task, "id", "")),
                "tool_name": str(_BACKGROUND_MESSAGE_SEND),
                "event_type": event_type,
                "trigger_payload": str(getattr(run, "trigger_payload", "")),
                "plan_commitment": str(getattr(run, "plan_commitment", "")),
                "payload_taint": str(getattr(run, "payload_taint", "")),
                "reason": reason,
                "status": "pending",
                "expires_at": pending.expires_at.isoformat() if pending.expires_at else "",
            },
        )
        await self._event_bus.publish(
            ToolRejected(
                session_id=session.id,
                actor="scheduler",
                tool_name=_BACKGROUND_MESSAGE_SEND,
                decision=PEPDecisionKind.REQUIRE_CONFIRMATION,
                reason=f"{reason} ({pending.confirmation_id})",
                **pending_action_event_identity_fields(pending),
            )
        )
        return str(pending.confirmation_id)

    @staticmethod
    def _public_task_confirmation_row(row: Mapping[str, Any]) -> dict[str, Any]:
        return {
            "confirmation_id": optional_string(row.get("confirmation_id", "")),
            "action_id": optional_string(row.get("action_id", "")),
            "execution_attempt_id": optional_string(row.get("execution_attempt_id", "")),
            "identity": dict(row.get("identity", {}))
            if isinstance(row.get("identity"), Mapping)
            else {},
            "task_id": optional_string(row.get("task_id", "")),
            "tool_name": optional_string(row.get("tool_name", "")),
            "event_type": optional_string(row.get("event_type", "")),
            "payload_taint": optional_string(row.get("payload_taint", "")),
            "reason": optional_string(row.get("reason", "")),
            "status": optional_string(row.get("status", "pending")) or "pending",
            "lifecycle_state": (
                optional_string(row.get("lifecycle_state", "pending")) or "pending"
            ),
            "result_id": optional_string(row.get("result_id", "")),
            "expires_at": optional_string(row.get("expires_at", "")),
            "queued_at": optional_string(row.get("queued_at", "")),
        }

    async def _reject_task_run(
        self,
        *,
        sid: SessionId,
        task: Any,
        reason: str,
    ) -> dict[str, Any]:
        delivery_target = self._task_delivery_target(task)
        operation_identity = mint_action_operation_identity(
            origin_turn_id=f"task:{getattr(task, 'id', '')}",
        )
        await self._event_bus.publish(
            ToolRejected(
                session_id=sid,
                actor="policy_loop",
                tool_name=_BACKGROUND_MESSAGE_SEND,
                reason=reason,
                **operation_identity.to_event_fields(),
                user_id=str(getattr(task, "created_by", "")),
                workspace_id=str(getattr(task, "workspace_id", "")),
                task_id=str(getattr(task, "id", "")),
                delivery_target=(
                    delivery_target.model_dump(mode="json", exclude_none=True)
                    if delivery_target is not None
                    else None
                ),
            )
        )
        self._scheduler.record_run_outcome(str(getattr(task, "id", "")), success=False)
        return {"accepted": False, "queued_confirmation": False, "executed": False}

    async def _execute_task_run(
        self,
        run: Any,
        *,
        event_type: str,
        due_run: bool,
    ) -> dict[str, Any]:
        task_id = str(getattr(run, "task_id", "")).strip()
        if not task_id:
            return {"accepted": False, "queued_confirmation": False, "executed": False}
        lock = self._task_lifecycle_lock(task_id)
        try:
            async with lock:
                return await self._execute_task_run_locked(
                    run,
                    event_type=event_type,
                    due_run=due_run,
                )
        finally:
            self._discard_task_lifecycle_lock_if_idle(task_id, lock)

    async def _execute_task_run_locked(
        self,
        run: Any,
        *,
        event_type: str,
        due_run: bool,
    ) -> dict[str, Any]:
        _ = due_run
        task = self._scheduler.get_task(str(getattr(run, "task_id", "")))
        if task is None or not bool(getattr(task, "enabled", False)):
            return {"accepted": False, "queued_confirmation": False, "executed": False}
        task_envelope = getattr(task, "task_envelope", None)

        if str(getattr(run, "plan_commitment", "")) != str(task.commitment_hash()):
            await self._publish_task_anomaly(
                session_id=None,
                description=f"Task plan commitment mismatch blocked execution for task {task.id}",
                recommended_action="review_task_commitment",
            )
            self._scheduler.record_run_outcome(task.id, success=False)
            return {"accepted": False, "queued_confirmation": False, "executed": False}

        delivery_arguments = self._task_delivery_arguments(task)
        if delivery_arguments is None:
            await self._event_bus.publish(
                TaskTriggered(
                    session_id=None,
                    actor="scheduler",
                    task_id=task.id,
                    event_type=event_type,
                )
            )
            await self._publish_task_anomaly(
                session_id=None,
                description=f"Background task missing delivery target for task {task.id}",
                recommended_action="update_task_delivery_target",
            )
            self._scheduler.record_run_outcome(task.id, success=False)
            return {"accepted": False, "queued_confirmation": False, "executed": False}

        session = self._ensure_task_execution_session(task)
        sid = SessionId(str(session.id))
        trust_level = _payload_trust_level(str(getattr(run, "payload_taint", "")))
        origin = self._task_origin_for(session=session, task=task, trust_level=trust_level)

        previous_plan_hash = await _call_control_plane(self, "active_plan_hash", str(sid))
        trace_policy = self._policy_loader.policy.control_plane.trace
        committed_plan_hash = await _call_control_plane(
            self,
            "begin_precontent_plan",
            session_id=str(sid),
            goal=str(getattr(task, "goal", "")),
            origin=origin,
            ttl_seconds=int(trace_policy.ttl_seconds),
            max_actions=int(trace_policy.max_actions),
            capabilities=set(getattr(task, "capability_snapshot", set())),
        )
        if previous_plan_hash:
            await self._event_bus.publish(
                PlanCancelled(
                    session_id=sid,
                    actor="control_plane",
                    plan_hash=previous_plan_hash,
                    reason="superseded_by_task_run",
                )
            )
        await self._event_bus.publish(
            PlanCommitted(
                session_id=sid,
                actor="control_plane",
                plan_hash=(await _call_control_plane(self, "active_plan_hash", str(sid)))
                or committed_plan_hash,
                stage="stage1_precontent",
                expires_at="",
            )
        )
        await self._event_bus.publish(
            TaskTriggered(
                session_id=sid,
                actor="scheduler",
                task_id=task.id,
                event_type=event_type,
            )
        )

        scope_reason = self._task_scope_mismatch_reason(task, delivery_arguments)
        effective_capabilities = self._lockdown_manager.apply_capability_restrictions(
            sid,
            set(getattr(task, "capability_snapshot", set())),
        )
        cp_eval = await _call_control_plane(
            self,
            "evaluate_action",
            tool_name=str(_BACKGROUND_MESSAGE_SEND),
            arguments=dict(delivery_arguments),
            origin=origin,
            risk_tier=self._background_risk_tier(
                payload_taint=str(getattr(run, "payload_taint", "")),
                scope_mismatch=bool(scope_reason),
            ),
            declared_domains=[],
            session_tainted=bool(_payload_taints(str(getattr(run, "payload_taint", "")))),
            trusted_input=trust_level in {"trusted", "verified", "internal"},
            raw_user_text=(
                str(getattr(run, "trigger_payload", "")) or str(getattr(task, "goal", ""))
            ),
        )
        await self._publish_control_plane_evaluation(
            sid=sid,
            tool_name=_BACKGROUND_MESSAGE_SEND,
            arguments=delivery_arguments,
            evaluation=cp_eval,
        )

        pep_decision = self._pep.evaluate(
            _BACKGROUND_MESSAGE_SEND,
            dict(delivery_arguments),
            PolicyContext(
                capabilities=effective_capabilities,
                taint_labels=_payload_taints(str(getattr(run, "payload_taint", ""))),
                session_id=sid,
                workspace_id=WorkspaceId(str(getattr(task, "workspace_id", ""))),
                user_id=UserId(str(getattr(task, "created_by", ""))),
                resource_authorizer=task_resource_authorizer(task_envelope),
                trust_level=trust_level,
                credential_refs={
                    CredentialRef(str(item))
                    for item in getattr(task_envelope, "credential_refs", ())
                    if str(item).strip()
                },
                enforce_explicit_credential_refs=task_envelope is not None,
            ),
        )

        trace_only_stage2_block = (
            cp_eval.trace_result.reason_code == "trace:stage2_upgrade_required"
            and not any(
                vote.decision.value == "BLOCK" and vote.voter != TRACE_VOTER_NAME
                for vote in cp_eval.consensus.votes
            )
        )
        final_kind = pep_decision.kind.value
        final_reason = pep_decision.reason
        if (
            trace_only_stage2_block
            and final_kind != PEPDecisionKind.REJECT.value
            and not bool(self._policy_loader.policy.control_plane.trace.allow_amendment)
        ):
            final_kind = PEPDecisionKind.REJECT.value
            final_reason = "trace:plan_amendment_disabled"
        if cp_eval.decision == ControlDecision.BLOCK:
            if trace_only_stage2_block and final_kind == PEPDecisionKind.ALLOW.value:
                final_kind = PEPDecisionKind.REQUIRE_CONFIRMATION.value
                final_reason = ",".join(cp_eval.reason_codes) or "trace:stage2_upgrade_required"
            elif (
                trace_only_stage2_block and final_kind == PEPDecisionKind.REQUIRE_CONFIRMATION.value
            ):
                final_reason = _join_reason_codes(
                    final_reason,
                    ",".join(cp_eval.reason_codes) or "trace:stage2_upgrade_required",
                )
            elif trace_only_stage2_block and final_kind == PEPDecisionKind.REJECT.value:
                final_reason = final_reason or pep_decision.reason or "pep_reject"
            else:
                final_kind = PEPDecisionKind.REJECT.value
                final_reason = ",".join(cp_eval.reason_codes) or "control_plane_block"
        elif (
            cp_eval.decision == ControlDecision.REQUIRE_CONFIRMATION
            and final_kind == PEPDecisionKind.ALLOW.value
        ):
            final_kind = PEPDecisionKind.REQUIRE_CONFIRMATION.value
            final_reason = ",".join(cp_eval.reason_codes) or "control_plane_confirmation"
        elif (
            cp_eval.decision == ControlDecision.REQUIRE_CONFIRMATION
            and final_kind == PEPDecisionKind.REQUIRE_CONFIRMATION.value
        ):
            final_reason = _join_reason_codes(
                final_reason,
                ",".join(cp_eval.reason_codes) or "control_plane_confirmation",
            )

        if self._lockdown_manager.should_block_all_actions(sid):
            final_kind = PEPDecisionKind.REJECT.value
            final_reason = "session_in_lockdown"

        if scope_reason and final_kind != PEPDecisionKind.REJECT.value:
            if final_kind == PEPDecisionKind.ALLOW.value:
                final_kind = PEPDecisionKind.REQUIRE_CONFIRMATION.value
                final_reason = scope_reason
            else:
                final_reason = _join_reason_codes(final_reason, scope_reason)

        payload_policy = (
            str(getattr(task_envelope, "untrusted_payload_action", "require_confirmation"))
            .strip()
            .lower()
        )
        if str(getattr(run, "payload_taint", "")).strip().lower() != "trusted_scheduler":
            if payload_policy == "reject":
                final_kind = PEPDecisionKind.REJECT.value
                final_reason = "background:tainted_trigger_scope_block"
            elif final_kind == PEPDecisionKind.ALLOW.value:
                final_kind = PEPDecisionKind.REQUIRE_CONFIRMATION.value
                final_reason = "background:tainted_trigger_requires_confirmation"
            elif final_kind == PEPDecisionKind.REQUIRE_CONFIRMATION.value:
                final_reason = _join_reason_codes(
                    final_reason,
                    "background:tainted_trigger_requires_confirmation",
                )

        if final_kind == PEPDecisionKind.REJECT.value:
            await self._observe_pep_reject_signal(
                sid=sid,
                tool_name=_BACKGROUND_MESSAGE_SEND,
                action=cp_eval.action,
                final_kind=final_kind,
                final_reason=final_reason or pep_decision.reason,
                pep_kind=pep_decision.kind.value,
                pep_reason=pep_decision.reason,
                pep_reason_code=pep_decision.reason_code.strip(),
                source="scheduler",
            )
            return await self._reject_task_run(
                sid=sid,
                task=task,
                reason=final_reason or pep_decision.reason or "background_execution_rejected",
            )

        if final_kind == PEPDecisionKind.REQUIRE_CONFIRMATION.value:
            confirmation_requirement = (
                ConfirmationRequirement.model_validate(pep_decision.confirmation_requirement)
                if pep_decision.confirmation_requirement is not None
                else None
            )
            try:
                await self._queue_task_confirmation(
                    task=task,
                    run=run,
                    event_type=event_type,
                    session=session,
                    arguments=delivery_arguments,
                    reason=final_reason or "requires_confirmation",
                    capabilities=effective_capabilities,
                    preflight_action=cp_eval.action,
                    confirmation_requirement=confirmation_requirement,
                )
            except ApprovalRoutingError as exc:
                return await self._reject_task_run(
                    sid=sid,
                    task=task,
                    reason=str(exc.reason),
                )
            return {"accepted": True, "queued_confirmation": True, "executed": False}

        execution = await self._execute_approved_action(
            sid=sid,
            user_id=UserId(str(getattr(task, "created_by", ""))),
            workspace_id=WorkspaceId(str(getattr(task, "workspace_id", ""))),
            task_id=str(task.id),
            delivery_target=self._task_delivery_target(task),
            tool_name=_BACKGROUND_MESSAGE_SEND,
            arguments=delivery_arguments,
            capabilities=effective_capabilities,
            approval_actor="scheduler",
            execution_action=cp_eval.action,
            user_confirmed=False,
        )
        self._scheduler.record_run_outcome(task.id, success=execution.success)
        if not execution.success:
            await self._publish_task_anomaly(
                session_id=sid,
                description=f"Scheduled reminder delivery failed for task {task.id}",
                recommended_action="check_channel_connectivity",
            )
        return {
            "accepted": bool(execution.success),
            "queued_confirmation": False,
            "executed": bool(execution.success),
        }

    async def do_task_execute_due_run(self, run: Any, *, event_type: str) -> dict[str, Any]:
        return await self._execute_task_run(run, event_type=event_type, due_run=True)

    async def do_task_create(self, params: Mapping[str, Any]) -> dict[str, Any]:
        schedule = Schedule.model_validate(params.get("schedule", {}))
        workspace_raw = optional_string(params.get("workspace_id", ""))
        if not workspace_raw:
            raise ValueError("workspace_id is required")
        raw_delivery_target = params.get("delivery_target", {})
        delivery_target: dict[str, str]
        if isinstance(raw_delivery_target, Mapping):
            delivery_target = {}
            for key, value in raw_delivery_target.items():
                key_name = optional_string(key)
                value_text = optional_string(value)
                if key_name and value_text:
                    delivery_target[key_name] = value_text
        else:
            delivery_target = {}
        task = self._scheduler.create_task(
            name=optional_string(params.get("name", "")),
            goal=optional_string(params.get("goal", "")),
            schedule=schedule,
            capability_snapshot={Capability(cap) for cap in params.get("capability_snapshot", [])},
            policy_snapshot_ref=optional_string(params.get("policy_snapshot_ref", "")),
            created_by=UserId(optional_string(params.get("created_by", ""))),
            workspace_id=WorkspaceId(workspace_raw),
            allowed_recipients=list(params.get("allowed_recipients", [])),
            allowed_domains=list(params.get("allowed_domains", [])),
            delivery_target=delivery_target,
            credential_refs=list(params.get("credential_refs", [])),
            resource_scope_ids=list(params.get("resource_scope_ids", [])),
            resource_scope_prefixes=list(params.get("resource_scope_prefixes", [])),
            untrusted_payload_action=optional_string(
                params.get("untrusted_payload_action", "require_confirmation")
            )
            or "require_confirmation",
            max_runs=int(params.get("max_runs", 0)),
        )
        await self._event_bus.publish(
            TaskScheduled(
                session_id=None,
                actor="scheduler",
                task_id=task.id,
                name=task.name,
            )
        )
        return cast(dict[str, Any], task.model_dump(mode="json"))

    async def do_task_list(self, params: Mapping[str, Any]) -> dict[str, Any]:
        _ = params
        tasks = self._scheduler.list_tasks()
        return {"tasks": [task.model_dump(mode="json") for task in tasks], "count": len(tasks)}

    async def do_task_disable(self, params: Mapping[str, Any]) -> dict[str, Any]:
        task_id = str(params.get("task_id", "")).strip()
        if not task_id:
            return {"disabled": False, "task_id": task_id}
        lock = self._task_lifecycle_lock(task_id)
        try:
            async with lock:
                disabled = self._scheduler.disable_task(task_id)
                if disabled:
                    await self._cancel_pending_actions_for_task(
                        task_id,
                        reason="task_disabled",
                    )
        finally:
            self._discard_task_lifecycle_lock_if_idle(task_id, lock)
        return {"disabled": disabled, "task_id": task_id}

    async def do_task_trigger_event(self, params: Mapping[str, Any]) -> dict[str, Any]:
        event_type = str(params.get("event_type", ""))
        payload = str(params.get("payload", ""))
        runs = self._scheduler.trigger_event(event_type=event_type, payload=payload)
        accepted: list[dict[str, Any]] = []
        blocked = 0
        queued = 0
        for run in runs:
            outcome = await self._execute_task_run(run, event_type=event_type, due_run=False)
            if not outcome.get("accepted", False):
                blocked += 1
                continue
            if outcome.get("queued_confirmation", False):
                queued += 1
            accepted.append(run.model_dump(mode="json"))
        return {
            "runs": accepted,
            "count": len(accepted),
            "queued_confirmations": queued,
            "blocked_runs": blocked,
        }

    async def do_task_pending_confirmations(self, params: Mapping[str, Any]) -> dict[str, Any]:
        task_id = str(params.get("task_id", ""))
        pending = self._scheduler.pending_confirmations(task_id)
        return {"task_id": task_id, "pending": pending, "count": len(pending)}

    @staticmethod
    def _peer_uid(peer: Any) -> int | None:
        if not isinstance(peer, Mapping):
            return None
        value = peer.get("uid")
        if isinstance(value, bool):
            return None
        if isinstance(value, int):
            return value
        return None

    @staticmethod
    def _operator_session_matches_peer(session: Any, rpc_peer: Any) -> bool:
        peer_uid = TasksImplMixin._peer_uid(rpc_peer)
        if peer_uid is None:
            return False
        metadata = getattr(session, "metadata", {})
        if not isinstance(metadata, Mapping):
            return False
        created_peer = metadata.get("created_rpc_peer")
        created_uid = TasksImplMixin._peer_uid(created_peer)
        return created_uid is not None and created_uid == peer_uid

    def _task_status_snapshot_scope(
        self,
        *,
        session_id: str,
        rpc_peer: Any,
    ) -> tuple[str, str] | None:
        if not session_id:
            return None
        session_manager = getattr(self, "_session_manager", None)
        get_session = getattr(session_manager, "get", None)
        if not callable(get_session):
            return None
        try:
            session = get_session(SessionId(session_id))
        except (OSError, RuntimeError, TypeError, ValueError):
            return None
        if session is None:
            return None
        metadata = getattr(session, "metadata", {})
        if not isinstance(metadata, Mapping):
            return None
        if getattr(session, "state", None) != SessionState.ACTIVE:
            return None
        if getattr(session, "role", None) != SessionRole.ORCHESTRATOR:
            return None
        if getattr(session, "mode", None) != SessionMode.DEFAULT:
            return None
        if optional_string(getattr(session, "channel", "")).lower() != "cli":
            return None
        if metadata.get("operator_owned_cli") is not True:
            return None
        if not self._operator_session_matches_peer(session, rpc_peer):
            return None

        user_id = optional_string(getattr(session, "user_id", ""))
        workspace_id = optional_string(getattr(session, "workspace_id", ""))
        if not user_id or not workspace_id:
            return None
        return user_id, workspace_id

    async def do_task_status_snapshot(self, params: Mapping[str, Any]) -> dict[str, Any]:
        limit = max(0, int(params.get("limit", 20) or 20))
        scope = self._task_status_snapshot_scope(
            session_id=optional_string(params.get("session_id", "")),
            rpc_peer=params.get("_rpc_peer"),
        )
        if scope is None:
            return {
                "tasks": [],
                "count": 0,
                "user_id": "",
                "workspace_id": "",
                "scope_status": "missing_scope",
            }

        user_id, workspace_id = scope
        if not user_id or not workspace_id:
            return {
                "tasks": [],
                "count": 0,
                "user_id": user_id,
                "workspace_id": workspace_id,
                "scope_status": "missing_scope",
            }

        rows = self._scheduler.task_status_snapshot(
            limit=limit,
            created_by=UserId(user_id),
            workspace_id=WorkspaceId(workspace_id),
        )
        visible_rows: list[dict[str, Any]] = []
        for row in rows:
            task_id = optional_string(row.get("task_id", ""))
            public_row = dict(row)
            pending_source = self._scheduler.pending_confirmations(task_id) if task_id else []
            pending_rows = [
                TasksImplMixin._public_task_confirmation_row(raw)
                for raw in pending_source
                if isinstance(raw, Mapping)
            ]
            public_row["pending_confirmations"] = pending_rows
            public_row["pending_confirmation_count"] = len(pending_rows)
            public_row["confirmation_needed"] = bool(pending_rows)
            visible_rows.append(public_row)
        return {
            "tasks": visible_rows,
            "count": len(visible_rows),
            "user_id": user_id,
            "workspace_id": workspace_id,
            "scope_status": "scoped",
        }
