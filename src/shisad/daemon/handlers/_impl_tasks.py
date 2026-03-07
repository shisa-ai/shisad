"""Task scheduler handler implementations."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, cast

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
    PEPDecisionKind,
    SessionId,
    TaintLabel,
    ToolName,
    UserId,
    WorkspaceId,
)
from shisad.daemon.handlers._mixin_typing import HandlerMixinBase
from shisad.scheduler.schema import Schedule
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
        channel = str(delivery_target.get("channel", "")).strip()
        recipient = str(delivery_target.get("recipient", "")).strip()
        if not channel or not recipient:
            return None
        return {
            "channel": channel,
            "recipient": recipient,
            "workspace_hint": str(delivery_target.get("workspace_hint", "")).strip(),
            "thread_id": str(delivery_target.get("thread_id", "")).strip(),
            "message": str(getattr(task, "goal", "")),
        }

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
            str(item).strip()
            for item in getattr(task, "allowed_domains", [])
            if str(item).strip()
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

        session = self._session_manager.create(
            channel="scheduler",
            user_id=UserId(str(getattr(task, "created_by", ""))),
            workspace_id=WorkspaceId(str(getattr(task, "workspace_id", ""))),
            capabilities=set(getattr(task, "capability_snapshot", set())),
            metadata={
                "capability_sync_mode": "manual_override",
                "trust_level": "internal",
                "background_task_id": str(getattr(task, "id", "")),
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

    @staticmethod
    def _stage2_reason(reason_codes: list[str], extra_code: str) -> str:
        ordered: list[str] = []
        for code in ["trace:stage2_upgrade_required", *reason_codes, extra_code]:
            normalized = str(code).strip()
            if normalized and normalized not in ordered:
                ordered.append(normalized)
        return ",".join(ordered)

    def _queue_task_confirmation(
        self,
        *,
        task: Any,
        run: Any,
        event_type: str,
        session: Any,
        arguments: dict[str, Any],
        reason: str,
        preflight_action: Any | None,
    ) -> str:
        pending = self._queue_pending_action(
            session_id=session.id,
            user_id=UserId(str(getattr(task, "created_by", ""))),
            workspace_id=WorkspaceId(str(getattr(task, "workspace_id", ""))),
            task_id=str(getattr(task, "id", "")),
            tool_name=_BACKGROUND_MESSAGE_SEND,
            arguments=dict(arguments),
            reason=reason,
            capabilities=set(getattr(task, "capability_snapshot", set())),
            preflight_action=preflight_action,
            taint_labels=list(_payload_taints(str(getattr(run, "payload_taint", "")))),
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

    async def _execute_task_run(
        self,
        run: Any,
        *,
        event_type: str,
        due_run: bool,
    ) -> dict[str, Any]:
        task = self._scheduler.get_task(str(getattr(run, "task_id", "")))
        if task is None:
            return {"accepted": False, "queued_confirmation": False, "executed": False}

        if str(getattr(run, "plan_commitment", "")) != str(task.commitment_hash()):
            await self._publish_task_anomaly(
                session_id=None,
                description=f"Task plan commitment mismatch blocked execution for task {task.id}",
                recommended_action="review_task_commitment",
            )
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
            if due_run:
                await self._publish_task_anomaly(
                    session_id=None,
                    description=f"Scheduled reminder missing delivery target for task {task.id}",
                    recommended_action="update_task_delivery_target",
                )
                return {"accepted": False, "queued_confirmation": False, "executed": False}
            self._scheduler.queue_confirmation(
                task.id,
                {
                    "task_id": task.id,
                    "event_type": event_type,
                    "trigger_payload": str(getattr(run, "trigger_payload", "")),
                    "plan_commitment": str(getattr(run, "plan_commitment", "")),
                    "payload_taint": str(getattr(run, "payload_taint", "")),
                    "reason": "background:missing_delivery_target",
                    "status": "pending",
                },
            )
            return {"accepted": True, "queued_confirmation": True, "executed": False}

        session = self._ensure_task_execution_session(task)
        sid = SessionId(str(session.id))
        trust_level = _payload_trust_level(str(getattr(run, "payload_taint", "")))
        origin = self._task_origin_for(session=session, task=task, trust_level=trust_level)

        previous_plan_hash = self._control_plane.active_plan_hash(str(sid))
        trace_policy = self._policy_loader.policy.control_plane.trace
        committed_plan_hash = self._control_plane.begin_precontent_plan(
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
                plan_hash=self._control_plane.active_plan_hash(str(sid)) or committed_plan_hash,
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
        cp_eval = await self._control_plane.evaluate_action(
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
                str(getattr(run, "trigger_payload", ""))
                or str(getattr(task, "goal", ""))
            ),
        )
        await self._publish_control_plane_evaluation(
            sid=sid,
            tool_name=_BACKGROUND_MESSAGE_SEND,
            arguments=delivery_arguments,
            evaluation=cp_eval,
        )

        if Capability.MESSAGE_SEND not in set(getattr(task, "capability_snapshot", set())):
            self._queue_task_confirmation(
                task=task,
                run=run,
                event_type=event_type,
                session=session,
                arguments=delivery_arguments,
                reason=self._stage2_reason(
                    list(getattr(cp_eval, "reason_codes", [])),
                    "background:capability_snapshot_scope_mismatch",
                ),
                preflight_action=cp_eval.action,
            )
            return {"accepted": True, "queued_confirmation": True, "executed": False}

        if scope_reason:
            self._queue_task_confirmation(
                task=task,
                run=run,
                event_type=event_type,
                session=session,
                arguments=delivery_arguments,
                reason=self._stage2_reason(
                    list(getattr(cp_eval, "reason_codes", [])),
                    scope_reason,
                ),
                preflight_action=cp_eval.action,
            )
            return {"accepted": True, "queued_confirmation": True, "executed": False}

        pep_decision = self._pep.evaluate(
            _BACKGROUND_MESSAGE_SEND,
            dict(delivery_arguments),
            PolicyContext(
                capabilities=set(getattr(task, "capability_snapshot", set())),
                taint_labels=_payload_taints(str(getattr(run, "payload_taint", ""))),
                workspace_id=WorkspaceId(str(getattr(task, "workspace_id", ""))),
                user_id=UserId(str(getattr(task, "created_by", ""))),
                trust_level=trust_level,
            ),
        )

        trace_only_stage2_block = (
            cp_eval.trace_result.reason_code == "trace:stage2_upgrade_required"
            and not any(
                vote.decision.value == "BLOCK" and vote.voter != "ExecutionTraceVerifier"
                for vote in cp_eval.consensus.votes
            )
        )
        final_kind = pep_decision.kind.value
        final_reason = pep_decision.reason
        if cp_eval.decision == ControlDecision.BLOCK:
            if trace_only_stage2_block:
                final_kind = PEPDecisionKind.REQUIRE_CONFIRMATION.value
                final_reason = ",".join(cp_eval.reason_codes) or "trace:stage2_upgrade_required"
            else:
                final_kind = PEPDecisionKind.REJECT.value
                final_reason = ",".join(cp_eval.reason_codes) or "control_plane_block"
        elif (
            cp_eval.decision == ControlDecision.REQUIRE_CONFIRMATION
            and final_kind == PEPDecisionKind.ALLOW.value
        ):
            final_kind = PEPDecisionKind.REQUIRE_CONFIRMATION.value
            final_reason = ",".join(cp_eval.reason_codes) or "control_plane_confirmation"

        if final_kind == PEPDecisionKind.REJECT.value:
            await self._event_bus.publish(
                ToolRejected(
                    session_id=sid,
                    actor="policy_loop",
                    tool_name=_BACKGROUND_MESSAGE_SEND,
                    reason=final_reason or pep_decision.reason,
                )
            )
            self._scheduler.record_run_outcome(task.id, success=False)
            return {"accepted": False, "queued_confirmation": False, "executed": False}

        if final_kind == PEPDecisionKind.REQUIRE_CONFIRMATION.value:
            self._queue_task_confirmation(
                task=task,
                run=run,
                event_type=event_type,
                session=session,
                arguments=delivery_arguments,
                reason=final_reason or "requires_confirmation",
                preflight_action=cp_eval.action,
            )
            return {"accepted": True, "queued_confirmation": True, "executed": False}

        execution = await self._execute_approved_action(
            sid=sid,
            user_id=UserId(str(getattr(task, "created_by", ""))),
            tool_name=_BACKGROUND_MESSAGE_SEND,
            arguments=delivery_arguments,
            capabilities=set(getattr(task, "capability_snapshot", set())),
            approval_actor="scheduler",
            execution_action=cp_eval.action,
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
        workspace_raw = str(params.get("workspace_id", "")).strip()
        if not workspace_raw:
            raise ValueError("workspace_id is required")
        raw_delivery_target = params.get("delivery_target", {})
        delivery_target: dict[str, str]
        if isinstance(raw_delivery_target, Mapping):
            delivery_target = {
                str(key): str(value)
                for key, value in raw_delivery_target.items()
                if str(key).strip() and str(value).strip()
            }
        else:
            delivery_target = {}
        task = self._scheduler.create_task(
            name=str(params.get("name", "")),
            goal=str(params.get("goal", "")),
            schedule=schedule,
            capability_snapshot={Capability(cap) for cap in params.get("capability_snapshot", [])},
            policy_snapshot_ref=str(params.get("policy_snapshot_ref", "")),
            created_by=UserId(str(params.get("created_by", ""))),
            workspace_id=WorkspaceId(workspace_raw),
            allowed_recipients=list(params.get("allowed_recipients", [])),
            allowed_domains=list(params.get("allowed_domains", [])),
            delivery_target=delivery_target,
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
