"""Task scheduler handler implementations."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, cast
from urllib.parse import urlparse

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
    TaintLabel,
    ToolName,
    UserId,
    WorkspaceId,
)
from shisad.daemon.handlers._mixin_typing import (
    HandlerMixinBase,
)
from shisad.daemon.handlers._mixin_typing import (
    call_control_plane as _call_control_plane,
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
    parsed = urlparse(value)
    if parsed.hostname:
        return parsed.hostname.lower().strip()
    fallback = urlparse(f"https://{value}")
    if fallback.hostname:
        return fallback.hostname.lower().strip()
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

    def _queue_task_confirmation(
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
            preflight_action=preflight_action,
            taint_labels=list(_payload_taints(str(getattr(run, "payload_taint", "")))),
            confirmation_requirement=confirmation_requirement,
        )
        self._scheduler.queue_confirmation(
            str(getattr(task, "id", "")),
            {
                "confirmation_id": pending.confirmation_id,
                "session_id": str(session.id),
                "task_id": str(getattr(task, "id", "")),
                "tool_name": str(_BACKGROUND_MESSAGE_SEND),
                "event_type": event_type,
                "trigger_payload": str(getattr(run, "trigger_payload", "")),
                "plan_commitment": str(getattr(run, "plan_commitment", "")),
                "payload_taint": str(getattr(run, "payload_taint", "")),
                "reason": reason,
                "status": "pending",
            },
        )
        return str(pending.confirmation_id)

    async def _reject_task_run(
        self,
        *,
        sid: SessionId,
        task: Any,
        reason: str,
    ) -> dict[str, Any]:
        await self._event_bus.publish(
            ToolRejected(
                session_id=sid,
                actor="policy_loop",
                tool_name=_BACKGROUND_MESSAGE_SEND,
                reason=reason,
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
        _ = due_run
        task = self._scheduler.get_task(str(getattr(run, "task_id", "")))
        if task is None:
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
                self._queue_task_confirmation(
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
        task_id = str(params.get("task_id", ""))
        disabled = self._scheduler.disable_task(task_id)
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
