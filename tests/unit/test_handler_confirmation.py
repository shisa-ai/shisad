"""Unit checks for confirmation handler wrappers."""

from __future__ import annotations

import asyncio
import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest

from shisad.channels.base import DeliveryTarget
from shisad.channels.delivery import CapabilityDeliveryIntent
from shisad.core.api.schema import (
    ActionDecisionParams,
    ActionPendingEntry,
    ActionPendingParams,
    ActionPurgeParams,
    ConfirmationMetricsParams,
)
from shisad.core.approval import (
    ApprovalEnvelope,
    ApprovalRoutingError,
    ConfirmationBackendRegistry,
    ConfirmationCapabilities,
    ConfirmationEvidence,
    ConfirmationEvidenceAuthenticator,
    ConfirmationFallbackPolicy,
    ConfirmationLevel,
    ConfirmationMethodLockoutTracker,
    ConfirmationRequirement,
    EnterpriseKmsSignerBackend,
    IntentAction,
    IntentEnvelope,
    IntentPolicyContext,
    LocalFido2Backend,
    SignerConfirmationAdapter,
    SoftwareConfirmationBackend,
    TOTPBackend,
    WebAuthnBackend,
    approval_envelope_hash,
    canonical_sha256,
    compute_action_digest,
    generate_totp_code,
    hash_recovery_code,
    intent_envelope_hash,
    resolve_confirmation_destinations,
)
from shisad.core.atomic_state import (
    AtomicWriteError,
    AtomicWriteStage,
    StatePersistenceDegradedError,
)
from shisad.core.events import (
    PlanAmended,
    ToolApproved,
    ToolExecuted,
    ToolRejected,
    TwoFactorEnrolled,
    TwoFactorRevoked,
)
from shisad.core.evidence import ArtifactEndorsementState, EvidenceStore
from shisad.core.tools.names import canonical_tool_name
from shisad.core.tools.registry import ToolRegistry
from shisad.core.tools.schema import (
    ToolDefinition,
    ToolParameter,
    ToolRetryClass,
    ToolRetryDescriptor,
)
from shisad.core.transcript import TranscriptStore
from shisad.core.types import (
    Capability,
    SessionId,
    SessionMode,
    TaintLabel,
    ToolName,
    UserId,
    WorkspaceId,
)
from shisad.daemon.context import RequestContext
from shisad.daemon.handlers._impl import HandlerImplementation, PendingAction
from shisad.daemon.handlers._impl_confirmation import ConfirmationImplMixin
from shisad.daemon.handlers._impl_tasks import TasksImplMixin
from shisad.daemon.handlers._pending_approval import (
    PendingPepContextSnapshot,
    PendingPepElevationRequest,
    pending_action_state_view,
    pending_approval_contract_hash,
    pending_approval_contract_payload,
    pep_arguments_for_policy_evaluation,
)
from shisad.daemon.handlers.confirmation import ConfirmationHandlers
from shisad.daemon.pending_actions import (
    PendingActionMutation,
    PendingActionMutationKind,
    PendingActionTransitionError,
    PendingActionTransitionGuard,
    capture_pending_action_mutation,
)
from shisad.memory.timeline import TimelineIndex
from shisad.scheduler.manager import SchedulerManager
from shisad.scheduler.schema import Schedule
from shisad.security.control_plane.schema import ActionKind, ControlPlaneAction, Origin, RiskTier
from shisad.security.control_plane.sidecar import (
    ControlPlaneRpcError,
    ControlPlaneUnavailableError,
)
from shisad.security.credentials import (
    ApprovalFactorRecord,
    InMemoryCredentialStore,
    RecoveryCodeRecord,
    SignerKeyRecord,
)
from shisad.security.leakcheck import CrossThreadLeakDetector
from shisad.security.pep import PEP, PolicyContext
from shisad.security.policy import PolicyBundle
from shisad.ui.confirmation import ConfirmationWarningGenerator
from tests.helpers.signer import generate_secp256k1_private_key, public_key_pem
from tests.helpers.webauthn import make_authentication_payload, make_registration_payload


class _StubImpl:
    def __init__(self) -> None:
        self.calls: list[str] = []

    async def do_action_pending(self, payload: dict[str, object]) -> dict[str, object]:
        self.calls.append("pending")
        return {"actions": [payload], "count": 1}

    async def do_action_purge(self, payload: dict[str, object]) -> dict[str, object]:
        self.calls.append("purge")
        return {
            "purged": 1,
            "confirmation_ids": [str(payload.get("status", "terminal"))],
            "remaining": 0,
            "dry_run": bool(payload.get("dry_run", False)),
        }

    async def do_action_confirm(self, payload: dict[str, object]) -> dict[str, object]:
        self.calls.append("confirm")
        return {"confirmed": True, "confirmation_id": str(payload["confirmation_id"])}

    async def do_action_reject(self, payload: dict[str, object]) -> dict[str, object]:
        self.calls.append("reject")
        return {"rejected": True, "confirmation_id": str(payload["confirmation_id"])}

    async def do_confirmation_metrics(self, payload: dict[str, object]) -> dict[str, object]:
        self.calls.append("metrics")
        return {"metrics": [payload], "count": 1}


@pytest.mark.asyncio
async def test_confirmation_wrappers_validate_shapes() -> None:
    handlers = ConfirmationHandlers(  # type: ignore[arg-type]
        _StubImpl(),
        internal_ingress_marker=object(),
    )
    result = await handlers.handle_action_pending(ActionPendingParams(limit=5), RequestContext())
    assert result.count == 1

    purged = await handlers.handle_action_purge(
        ActionPurgeParams(status="terminal"),
        RequestContext(),
    )
    assert purged.purged == 1


@pytest.mark.asyncio
async def test_confirmation_metrics_wrapper_returns_model() -> None:
    handlers = ConfirmationHandlers(  # type: ignore[arg-type]
        _StubImpl(),
        internal_ingress_marker=object(),
    )
    result = await handlers.handle_confirmation_metrics(
        ConfirmationMetricsParams(user_id="alice", window_seconds=120),
        RequestContext(),
    )
    assert result.count == 1


@pytest.mark.asyncio
async def test_confirmation_decision_wrappers() -> None:
    handlers = ConfirmationHandlers(  # type: ignore[arg-type]
        _StubImpl(),
        internal_ingress_marker=object(),
    )
    confirm = await handlers.handle_action_confirm(
        ActionDecisionParams(confirmation_id="c1"),
        RequestContext(),
    )
    reject = await handlers.handle_action_reject(
        ActionDecisionParams(confirmation_id="c2"),
        RequestContext(),
    )
    assert confirm.confirmed is True
    assert reject.rejected is True


def _registry_for_evidence() -> ToolRegistry:
    registry = ToolRegistry()
    registry.register(
        ToolDefinition(
            name=ToolName("evidence.promote"),
            description="promote evidence",
            parameters=[ToolParameter(name="ref_id", type="string", required=True)],
            capabilities_required=[Capability.MEMORY_READ],
        )
    )
    return registry


def _registry_for_confirmation() -> ToolRegistry:
    registry = _registry_for_evidence()
    registry.register(
        ToolDefinition(
            name=ToolName("web.fetch"),
            description="fetch a URL",
            parameters=[ToolParameter(name="url", type="string", required=True)],
            capabilities_required=[Capability.HTTP_REQUEST],
            require_confirmation=False,
        )
    )
    registry.register(
        ToolDefinition(
            name=ToolName("web.search"),
            description="search the web",
            parameters=[ToolParameter(name="query", type="string", required=True)],
            capabilities_required=[Capability.HTTP_REQUEST],
            require_confirmation=False,
        )
    )
    registry.register(
        ToolDefinition(
            name=ToolName("shell.exec"),
            description="execute a command",
            parameters=[ToolParameter(name="command", type="array", required=True)],
            capabilities_required=[Capability.SHELL_EXEC],
            require_confirmation=False,
        )
    )
    registry.register(
        ToolDefinition(
            name=ToolName("browser.click"),
            description="click a browser target",
            parameters=[
                ToolParameter(name="target", type="string", required=True),
                ToolParameter(name="description", type="string", required=False),
            ],
            capabilities_required=[Capability.HTTP_REQUEST],
            require_confirmation=False,
        )
    )
    return registry


class _ControlPlaneRecorder:
    def __init__(self) -> None:
        self.approved_actions: list[object] = []
        self.approved_correlations: list[tuple[str, str, str]] = []
        self.cancelled_correlations: list[str] = []

    def active_plan_hash(self, _session_id: str) -> str:
        return "plan-before"

    def approve_stage2(
        self,
        *,
        action: object,
        approved_by: str,
        correlation_id: str = "",
        expected_previous_hash: str = "",
        execution_idempotency_key: str = "",
    ) -> str:
        _ = approved_by
        self.approved_actions.append(action)
        self.approved_correlations.append(
            (correlation_id, expected_previous_hash, execution_idempotency_key)
        )
        return "plan-after"

    def cancel_stage2(
        self,
        *,
        session_id: str,
        correlation_id: str,
        expected_plan_hash: str = "",
        reason: str,
        actor: str,
    ) -> bool:
        _ = session_id, expected_plan_hash, reason, actor
        self.cancelled_correlations.append(correlation_id)
        return True


class _SchedulerRecorder:
    def __init__(self) -> None:
        self.resolved_confirmations: list[dict[str, object]] = []
        self.run_outcomes: list[dict[str, object]] = []
        self.confirmation_outcomes: dict[tuple[str, str], bool] = {}
        self.resolve_failures_remaining = 0
        self.task: object | None = None

    def get_task(self, _task_id: str) -> object | None:
        return self.task

    def disable_task(self, _task_id: str) -> bool:
        if self.task is None:
            return False
        self.task.enabled = False
        return True

    def resolve_confirmation(
        self,
        task_id: str,
        *,
        confirmation_id: str,
        status: str,
        status_reason: str = "",
        lifecycle_state: str = "",
        action_id: str = "",
        execution_attempt_id: str = "",
        result_id: str = "",
    ) -> bool:
        if self.resolve_failures_remaining:
            self.resolve_failures_remaining -= 1
            raise RuntimeError("injected scheduler confirmation publication fault")
        self.resolved_confirmations.append(
            {
                "task_id": task_id,
                "confirmation_id": confirmation_id,
                "status": status,
                "status_reason": status_reason,
                "lifecycle_state": lifecycle_state,
                "action_id": action_id,
                "execution_attempt_id": execution_attempt_id,
                "result_id": result_id,
            }
        )
        return True

    def record_run_outcome(self, task_id: str, *, success: bool) -> bool:
        self.run_outcomes.append({"task_id": task_id, "success": success})
        return True

    def confirmation_outcome(
        self,
        task_id: str,
        *,
        confirmation_id: str,
    ) -> bool | None:
        return self.confirmation_outcomes.get((task_id, confirmation_id))

    def record_confirmation_outcome(
        self,
        task_id: str,
        *,
        confirmation_id: str,
        success: bool,
    ) -> bool:
        key = (task_id, confirmation_id)
        existing = self.confirmation_outcomes.get(key)
        if existing is not None:
            return existing == success
        self.confirmation_outcomes[key] = success
        self.run_outcomes.append({"task_id": task_id, "success": success})
        return True


class _ApprovalWebRecorder:
    enabled = True

    def __init__(self) -> None:
        self.issued: list[str] = []

    def issue_approval_link(
        self, confirmation_id: str, *, expires_at: datetime | None = None
    ) -> str:
        _ = expires_at
        self.issued.append(confirmation_id)
        return f"https://approvals.test/{confirmation_id}"

    def rotate_approval_link(self, confirmation_id: str, *, expires_at: datetime) -> str:
        return self.issue_approval_link(confirmation_id, expires_at=expires_at)

    def qr_ascii(self, approval_url: str) -> str:
        return f"QR {approval_url}"


class _DeliveryRecorder:
    def __init__(self) -> None:
        self.messages: list[dict[str, object]] = []
        self.intents: list[object] = []

    async def send_capability(
        self, *, intent: object, resolver: object, rotate: bool = False
    ) -> object:
        self.intents.append(intent)
        payload = await resolver(intent, rotate=rotate)  # type: ignore[operator]
        if payload is not None:
            self.messages.append(
                {
                    "intent": intent,
                    "target": intent.target,  # type: ignore[attr-defined]
                    "message": payload.message,
                    "expires_at": payload.expires_at,
                }
            )
        return SimpleNamespace(attempted=payload is not None, sent=payload is not None)


class _AvailableWebAuthnRouteBackend:
    backend_id = "webauthn.default"
    method = "webauthn"
    level = ConfirmationLevel.BOUND_APPROVAL
    capabilities = ConfirmationCapabilities(
        principal_binding=True,
        approval_binding=True,
    )
    third_party_verifiable = False

    def is_available_for(self, *, user_id: str) -> bool:
        _ = user_id
        return True

    def principals_for_user(self, *, user_id: str) -> set[str]:
        _ = user_id
        return {"ops-laptop"}

    def credentials_for_user(self, *, user_id: str) -> set[str]:
        _ = user_id
        return {"webauthn-1"}

    def verify(
        self,
        *,
        pending_action: object,
        params: dict[str, object],
        now: datetime | None = None,
    ) -> ConfirmationEvidence:
        _ = pending_action, params, now
        raise AssertionError("route advertisement tests must not verify WebAuthn")


class _ConfirmationImplHarness(ConfirmationImplMixin):
    _capture_pending_scheduler_posture = HandlerImplementation._capture_pending_scheduler_posture
    _recovery_policy_allows = HandlerImplementation._recovery_policy_allows

    def __init__(
        self,
        tmp_path,
        *,
        allow_amendment: bool = False,
        execute_success: bool = True,
        execution_error: str = "",
        execution_error_tool_output: bool = True,
    ) -> None:
        self._pending_actions: dict[str, PendingAction] = {}
        self._pending_by_session: dict[SessionId, list[str]] = {}
        self._lockdown_manager = SimpleNamespace(
            should_block_all_actions=lambda _sid: False,
            apply_capability_restrictions=lambda _sid, capabilities: set(capabilities),
        )
        self.published_events: list[object] = []
        self._event_bus = SimpleNamespace(publish=self._noop_publish)
        self._session = SimpleNamespace(
            id=SessionId("s-1"),
            channel="cli",
            mode=SessionMode.DEFAULT,
            user_id=UserId("alice"),
            workspace_id=WorkspaceId("w-1"),
            capabilities=set(Capability),
        )
        self._session_manager = SimpleNamespace(get=lambda _sid: self._session)
        initial_policy = PolicyBundle.model_validate(
            {
                "default_require_confirmation": False,
                "control_plane": {"trace": {"allow_amendment": allow_amendment}},
            }
        )
        self._policy_loader = SimpleNamespace(policy=initial_policy)
        self._config = SimpleNamespace(assistant_fs_roots=[tmp_path])
        self._control_plane = _ControlPlaneRecorder()
        self._confirmation_analytics = SimpleNamespace(record=lambda **_kwargs: None)
        self._confirmation_backend_registry = ConfirmationBackendRegistry()
        self._confirmation_evidence_authenticator = ConfirmationEvidenceAuthenticator(b"a" * 32)
        self._credential_store = InMemoryCredentialStore()
        self._credential_store.set_approval_store_path(tmp_path / "approval-factors.json")
        self._pending_two_factor_enrollments: dict[str, object] = {}
        self._confirmation_backend_registry.register(SoftwareConfirmationBackend())
        self._confirmation_backend_registry.register(
            TOTPBackend(credential_store=self._credential_store)
        )
        self._confirmation_failure_tracker = ConfirmationMethodLockoutTracker()
        self._daemon_id = "daemon-1"
        self._registry = _registry_for_confirmation()
        self.execution_merged_policies: list[object | None] = []
        self.execution_kwargs: list[dict[str, object]] = []
        self._transcript_store = TranscriptStore(tmp_path / "sessions")
        self._evidence_store = EvidenceStore(tmp_path / "evidence", salt=b"a" * 32)
        self._execute_success = execute_success
        self._execution_error = execution_error
        self._execution_error_tool_output = execution_error_tool_output
        self.persist_calls = 0
        self._pep = PEP(
            initial_policy,
            self._registry,
            evidence_store=self._evidence_store,
        )

    def set_policy(self, policy: PolicyBundle) -> None:
        self._policy_loader.policy = policy
        self._pep = PEP(
            policy,
            self._registry,
            evidence_store=self._evidence_store,
        )

    async def _noop_publish(self, _event: object) -> None:
        self.published_events.append(_event)
        return None

    async def _maybe_emit_confirmation_hygiene_alert(self, **_kwargs: object) -> None:
        return None

    def _persist_pending_actions(self) -> None:
        self.persist_calls += 1

    @staticmethod
    def _origin_for(*, session: object, actor: str, skill_name: str = "") -> Origin:
        _ = session, skill_name
        return Origin(
            session_id="s-1",
            user_id="alice",
            workspace_id="w-1",
            actor=actor,
        )

    async def _execute_approved_action(
        self,
        *,
        sid: SessionId,
        user_id: UserId,
        tool_name: ToolName,
        arguments: dict[str, object],
        capabilities: set[Capability],
        approval_actor: str,
        execution_action: object | None = None,
        merged_policy: object | None = None,
        user_confirmed: bool = False,
        action_id: str = "",
        origin_turn_id: str = "",
        execution_attempt_id: str = "",
        result_id: str = "",
        followup_id: str = "",
        workspace_id: WorkspaceId | None = None,
        task_id: str = "",
        delivery_target: DeliveryTarget | None = None,
        approval_confirmation_id: str = "",
        approval_decision_nonce: str = "",
        approval_task_envelope_id: str = "",
        approval_timestamp: str = "",
        approval_evidence: object | None = None,
        strip_direct_tool_execute_envelope_keys: bool = False,
    ) -> object:
        _ = (
            sid,
            user_id,
            arguments,
            capabilities,
            approval_actor,
            execution_action,
            user_confirmed,
            approval_evidence,
        )
        self.execution_merged_policies.append(merged_policy)
        self.execution_kwargs.append(
            {
                "tool_name": str(tool_name),
                "capabilities": sorted(cap.value for cap in capabilities),
                "action_id": action_id,
                "origin_turn_id": origin_turn_id,
                "execution_attempt_id": execution_attempt_id,
                "result_id": result_id,
                "followup_id": followup_id,
                "workspace_id": str(workspace_id or ""),
                "task_id": task_id,
                "delivery_target": (
                    delivery_target.model_dump(mode="json", exclude_none=True)
                    if delivery_target is not None
                    else None
                ),
                "approval_confirmation_id": approval_confirmation_id,
                "approval_decision_nonce": approval_decision_nonce,
                "approval_task_envelope_id": approval_task_envelope_id,
                "approval_timestamp": approval_timestamp,
                "approval_evidence": approval_evidence,
                "strip_direct_tool_execute_envelope_keys": (
                    strip_direct_tool_execute_envelope_keys
                ),
            }
        )
        tool_output = None
        if canonical_tool_name(str(tool_name), warn_on_alias=False) == "evidence.promote":
            tool_output = SimpleNamespace(
                content=json.dumps(
                    {
                        "content": "promoted body",
                        "ref_id": str(arguments.get("ref_id", "")),
                    }
                ),
                taint_labels={TaintLabel.USER_REVIEWED},
            )
        elif (
            not self._execute_success
            and self._execution_error
            and self._execution_error_tool_output
        ):
            tool_output = SimpleNamespace(
                content=json.dumps({"ok": False, "error": self._execution_error}),
                taint_labels=set(),
                success=False,
            )
        return SimpleNamespace(
            success=self._execute_success,
            checkpoint_id=None,
            tool_output=tool_output if (self._execute_success or self._execution_error) else None,
            error=self._execution_error if not self._execute_success else "",
        )

    @staticmethod
    def _pending_to_dict(
        pending: PendingAction,
        *,
        public: bool = False,
        selected_backend_available: bool | None = None,
    ) -> dict[str, object]:
        _ = public, selected_backend_available
        return {
            "confirmation_id": pending.confirmation_id,
            "decision_nonce": pending.decision_nonce,
            "session_id": str(pending.session_id),
            "user_id": str(pending.user_id),
            "workspace_id": str(pending.workspace_id),
            "tool_name": str(pending.tool_name),
            "arguments": dict(pending.arguments),
            "reason": pending.reason,
            "capabilities": sorted(cap.value for cap in pending.capabilities),
            "created_at": pending.created_at.isoformat(),
            "execute_after": pending.execute_after.isoformat() if pending.execute_after else "",
            "safe_preview": pending.safe_preview,
            "warnings": list(pending.warnings),
            "leak_check": dict(pending.leak_check),
            "approval_task_envelope_id": pending.approval_task_envelope_id,
            "strip_direct_tool_execute_envelope_keys": bool(
                pending.strip_direct_tool_execute_envelope_keys
            ),
            "status": pending.status,
            "status_reason": pending.status_reason,
        }


class _QueuePendingHarness(HandlerImplementation):
    def __init__(self, tmp_path: Path) -> None:
        self._pending_actions: dict[str, PendingAction] = {}
        self._pending_by_session: dict[SessionId, list[str]] = {}
        self._pending_actions_file = tmp_path / "pending_actions.json"
        self._confirmation_warning_generator = ConfirmationWarningGenerator()
        self._confirmation_backend_registry = ConfirmationBackendRegistry()
        self._confirmation_evidence_authenticator = ConfirmationEvidenceAuthenticator(b"a" * 32)
        self._credential_store = InMemoryCredentialStore()
        self._credential_store.set_approval_store_path(tmp_path / "approval-factors.json")
        self._confirmation_backend_registry.register(SoftwareConfirmationBackend())
        self._confirmation_backend_registry.register(
            TOTPBackend(credential_store=self._credential_store)
        )
        self._transcript_store = TranscriptStore(tmp_path / "sessions")
        self._leak_detector = CrossThreadLeakDetector()
        self._daemon_id = "test-daemon"
        self._session_manager = SimpleNamespace(get=lambda _sid: SimpleNamespace(metadata={}))
        registry = _registry_for_confirmation()
        registry.register(
            ToolDefinition(
                name=ToolName("reminder.create"),
                description="create a reminder",
                parameters=[
                    ToolParameter(name="message", type="string", required=True),
                    ToolParameter(name="when", type="string", required=True),
                    ToolParameter(name="name", type="string", required=False),
                    ToolParameter(
                        name="reminder_intent",
                        type="string",
                        required=False,
                        enum=["current_turn_reminder_create"],
                    ),
                ],
                capabilities_required=[Capability.MEMORY_WRITE, Capability.MESSAGE_SEND],
            )
        )
        self._registry = registry


class _AtomicConfirmationHarness(_ConfirmationImplHarness):
    _pending_to_dict = staticmethod(HandlerImplementation._pending_to_dict)

    def __init__(self, tmp_path: Path, *, allow_amendment: bool = False) -> None:
        super().__init__(tmp_path, allow_amendment=allow_amendment)
        self._pending_actions_file = tmp_path / "pending_actions.json"
        self._pending_state_fault_injector = None
        self.effect_calls = 0

    def _persist_pending_actions(self) -> None:
        HandlerImplementation._persist_pending_actions(self)  # type: ignore[arg-type]

    async def _execute_approved_action(self, **kwargs: object) -> object:
        self.effect_calls += 1
        return await super()._execute_approved_action(**kwargs)  # type: ignore[arg-type]


def _pending_action(*, nonce: str, execute_after: datetime | None = None) -> PendingAction:
    created_at = datetime.now(UTC)
    expires_at = created_at + timedelta(hours=1)
    envelope = _software_approval_envelope(tool_name=ToolName("web.search")).model_copy(
        update={"expires_at": expires_at}
    )
    pending = PendingAction(
        confirmation_id="c-1",
        decision_nonce=nonce,
        session_id=SessionId("s-1"),
        user_id=UserId("alice"),
        workspace_id=WorkspaceId("w-1"),
        tool_name=ToolName("web.search"),
        arguments={"query": "hello"},
        reason="manual",
        capabilities={Capability.HTTP_REQUEST},
        created_at=created_at,
        execute_after=execute_after,
        approval_envelope=envelope,
        approval_envelope_hash=approval_envelope_hash(envelope),
        expires_at=expires_at,
        selected_backend_id="software.default",
        selected_backend_method="software",
    )
    _bind_pending_action_identity(pending)
    return pending


def _bind_pending_action_identity(pending: PendingAction) -> None:
    """Rebind a mutated test fixture to the new queue-time envelope identity."""

    assert pending.approval_envelope is not None
    registry = _registry_for_confirmation()
    tool_definition = registry.get_tool(pending.tool_name) or registry.get_tool(
        ToolName(canonical_tool_name(str(pending.tool_name), warn_on_alias=False))
    )
    assert tool_definition is not None
    if pending.expires_at is None:
        pending.expires_at = pending.created_at + timedelta(hours=1)
    normalized_arguments = pep_arguments_for_policy_evaluation(
        pending.tool_name,
        pending.arguments,
    )
    pending.action_digest = compute_action_digest(
        tool_definition=tool_definition,
        arguments=normalized_arguments,
        destinations=resolve_confirmation_destinations(
            tool_definition=tool_definition,
            arguments=normalized_arguments,
        ),
        stable_idempotency_key=pending.stable_idempotency_key,
    )
    pending.approval_envelope = pending.approval_envelope.model_copy(
        update={
            "schema_version": "shisad.approval.v2",
            "approval_id": pending.confirmation_id,
            "pending_action_id": pending.action_id,
            "session_id": str(pending.session_id),
            "workspace_id": str(pending.workspace_id),
            "daemon_id": "daemon-1",
            "required_level": pending.required_level,
            "policy_reason": pending.reason,
            "action_digest": pending.action_digest,
            "allowed_principals": list(pending.allowed_principals),
            "allowed_credentials": list(pending.allowed_credentials),
            "expires_at": pending.expires_at,
            "approval_contract_hash": "",
        }
    )
    pending.approval_envelope = pending.approval_envelope.model_copy(
        update={
            "approval_contract_hash": pending_approval_contract_hash(pending),
        }
    )
    pending.approval_envelope_hash = approval_envelope_hash(pending.approval_envelope)


def test_f10b_terminal_guard_failure_restores_caller_staged_mutation(tmp_path: Path) -> None:
    harness = _ConfirmationImplHarness(tmp_path)
    pending = _pending_action(nonce="nonce-1")
    harness._pending_actions[pending.confirmation_id] = pending
    harness._pending_by_session[pending.session_id] = [pending.confirmation_id]
    snapshot = capture_pending_action_mutation(pending)
    pending.approval_evidence_hash = f"sha256:{'7' * 64}"
    pending.execution_attempt_id = "attempt-staged"
    guard = replace(
        PendingActionTransitionGuard.for_record(pending),
        expected_action_id="act-other",
    )

    with pytest.raises(PendingActionTransitionError, match="guard_mismatch"):
        harness._commit_pending_terminal_state(
            pending,
            status="cancelled",
            reason="cancelled",
            rollback_snapshot=snapshot,
            transition_guard=guard,
        )

    assert capture_pending_action_mutation(pending) == snapshot


def test_f10d_terminal_builder_uses_explicit_mutation_scheduler_mode(
    tmp_path: Path,
) -> None:
    harness = _ConfirmationImplHarness(tmp_path)
    pending = _pending_action(nonce="nonce-1")
    pending.task_id = "task-1"
    requests = []
    harness._pending_action_lifecycle = SimpleNamespace(
        degradation=None,
        transition_many=lambda items, **_: requests.extend(items),
    )

    harness._commit_pending_terminal_state(
        pending,
        status="outcome_unknown",
        reason="uncertain_effect_requires_fresh_approval",
        mutation=PendingActionMutation(
            kind=PendingActionMutationKind.EXECUTION,
            values={"scheduler_accounting_mode": "ambiguous"},
        ),
    )

    assert len(requests) == 1
    assert requests[0].scheduler_accounting_mode == "ambiguous"


@pytest.mark.asyncio
async def test_f10b_start_guard_failure_restores_predecision_state(tmp_path: Path) -> None:
    harness = _ConfirmationImplHarness(tmp_path)
    pending = _pending_action(nonce="expected")
    harness._pending_actions[pending.confirmation_id] = pending
    harness._pending_by_session[pending.session_id] = [pending.confirmation_id]
    harness._pending_action_lifecycle_authority()
    snapshot = capture_pending_action_mutation(pending)
    harness._pending_by_session.clear()

    with pytest.raises(PendingActionTransitionError, match="store_index_mismatch"):
        await harness.do_action_confirm(
            {
                "confirmation_id": pending.confirmation_id,
                "decision_nonce": "expected",
            }
        )

    assert harness.execution_kwargs == []
    assert capture_pending_action_mutation(pending) == snapshot


@pytest.mark.asyncio
async def test_signer_register_rejects_unsupported_ledger_signing_scheme(
    tmp_path: Path,
) -> None:
    harness = _ConfirmationImplHarness(tmp_path)
    private_key = generate_secp256k1_private_key()

    registered = await harness.do_signer_register(
        {
            "backend": "ledger",
            "user_id": "alice",
            "key_id": "ledger:stax-1",
            "name": "alice-ledger",
            "algorithm": "ecdsa-secp256k1",
            "device_type": "ledger-consumer",
            "signing_scheme": "raw",
            "public_key_pem": public_key_pem(private_key),
        }
    )

    assert registered["registered"] is False
    assert registered["reason"] == "unsupported_ledger_signing_scheme"
    assert harness._credential_store.get_signer_key("ledger:stax-1") is None


@pytest.mark.asyncio
async def test_signer_register_ledger_persists_eip712_signing_scheme(
    tmp_path: Path,
) -> None:
    harness = _ConfirmationImplHarness(tmp_path)
    private_key = generate_secp256k1_private_key()

    registered = await harness.do_signer_register(
        {
            "backend": "ledger",
            "user_id": "alice",
            "key_id": "ledger:stax-1",
            "name": "alice-ledger",
            "public_key_pem": public_key_pem(private_key),
        }
    )

    assert registered["registered"] is True
    assert registered["algorithm"] == "ecdsa-secp256k1"

    reloaded = InMemoryCredentialStore()
    reloaded.set_approval_store_path(tmp_path / "approval-factors.json")
    record = reloaded.get_signer_key("ledger:stax-1")
    assert record is not None
    assert record.backend == "ledger"
    assert record.algorithm == "ecdsa-secp256k1"
    assert record.signing_scheme == "eip712"
    assert record.device_type == "ledger-consumer"


def test_gh49_current_turn_reminder_confirmation_drops_false_provenance_warnings(
    tmp_path: Path,
) -> None:
    harness = _QueuePendingHarness(tmp_path)
    sid = SessionId("s-gh49")
    user_id = UserId("alice")
    workspace_id = WorkspaceId("w-1")
    harness._transcript_store.append(
        sid,
        role="user",
        content='can you set a reminder for 1 minute from now to say "timer done"',
    )
    harness._confirmation_warning_generator.generate(
        user_id=str(user_id),
        tool_name="note.create",
        arguments={"content": "previous safe note"},
        taint_labels=[],
    )

    pending = harness._queue_pending_action(
        session_id=sid,
        user_id=user_id,
        workspace_id=workspace_id,
        tool_name=ToolName("reminder.create"),
        arguments={
            "message": "timer done",
            "when": "in 1 minute",
            "reminder_intent": "current_turn_reminder_create",
        },
        reason="requires_confirmation",
        capabilities={Capability.MEMORY_WRITE, Capability.MESSAGE_SEND},
        taint_labels=[TaintLabel.UNTRUSTED],
        trusted_current_turn_reminder_create=True,
    )

    assert "Contains tainted data" not in pending.warnings
    assert "Cross-thread overlap detected" not in pending.warnings
    assert "Unusual action for this user" not in pending.warnings
    assert pending.leak_check.get("detected") is False
    assert "reminder_intent" not in pending.safe_preview


def test_gh64_discord_pending_prefers_totp_backend_when_available(tmp_path: Path) -> None:
    harness = _QueuePendingHarness(tmp_path)
    _register_totp_factor(harness)  # type: ignore[arg-type]

    pending = harness._queue_pending_action(
        session_id=SessionId("s-gh64"),
        user_id=UserId("alice"),
        workspace_id=WorkspaceId("w-1"),
        tool_name=ToolName("web.search"),
        arguments={"query": "discord approvals"},
        reason="requires_confirmation",
        capabilities={Capability.HTTP_REQUEST},
        delivery_target=DeliveryTarget(channel="discord", recipient="chan-1"),
    )

    assert pending.selected_backend_id == "totp.default"
    assert pending.selected_backend_method == "totp"
    assert pending.required_level == ConfirmationLevel.SOFTWARE
    assert pending.required_methods == []


def test_gh64_discord_pending_keeps_software_when_totp_unavailable(
    tmp_path: Path,
) -> None:
    harness = _QueuePendingHarness(tmp_path)

    pending = harness._queue_pending_action(
        session_id=SessionId("s-gh64"),
        user_id=UserId("alice"),
        workspace_id=WorkspaceId("w-1"),
        tool_name=ToolName("web.search"),
        arguments={"query": "discord approvals"},
        reason="requires_confirmation",
        capabilities={Capability.HTTP_REQUEST},
        delivery_target=DeliveryTarget(channel="discord", recipient="chan-1"),
    )

    assert pending.selected_backend_id == "software.default"
    assert pending.selected_backend_method == "software"
    assert pending.allowed_channel_principals == ["alice"]


def test_a1_queue_pending_action_rejects_channel_target_without_principal(
    tmp_path: Path,
) -> None:
    harness = _QueuePendingHarness(tmp_path)

    with pytest.raises(ApprovalRoutingError, match="channel_principal_unavailable"):
        harness._queue_pending_action(
            session_id=SessionId("s-a1"),
            user_id=UserId(""),
            workspace_id=WorkspaceId("w-1"),
            tool_name=ToolName("web.search"),
            arguments={"query": "discord approvals"},
            reason="requires_confirmation",
            capabilities={Capability.HTTP_REQUEST},
            delivery_target=DeliveryTarget(channel="discord", recipient="chan-1"),
        )


def test_gh64_discord_pending_respects_explicit_non_totp_method_constraint(
    tmp_path: Path,
) -> None:
    harness = _QueuePendingHarness(tmp_path)
    _register_totp_factor(harness)  # type: ignore[arg-type]

    pending = harness._queue_pending_action(
        session_id=SessionId("s-gh64"),
        user_id=UserId("alice"),
        workspace_id=WorkspaceId("w-1"),
        tool_name=ToolName("web.search"),
        arguments={"query": "discord approvals"},
        reason="requires_confirmation",
        capabilities={Capability.HTTP_REQUEST},
        delivery_target=DeliveryTarget(channel="discord", recipient="chan-1"),
        confirmation_requirement=ConfirmationRequirement(
            level=ConfirmationLevel.SOFTWARE,
            methods=["software"],
        ),
    )

    assert pending.selected_backend_id == "software.default"
    assert pending.selected_backend_method == "software"


def test_gh64_discord_pending_respects_ordered_method_preference(
    tmp_path: Path,
) -> None:
    harness = _QueuePendingHarness(tmp_path)
    _register_totp_factor(harness)  # type: ignore[arg-type]

    pending = harness._queue_pending_action(
        session_id=SessionId("s-gh64"),
        user_id=UserId("alice"),
        workspace_id=WorkspaceId("w-1"),
        tool_name=ToolName("web.search"),
        arguments={"query": "discord approvals"},
        reason="requires_confirmation",
        capabilities={Capability.HTTP_REQUEST},
        delivery_target=DeliveryTarget(channel="discord", recipient="chan-1"),
        confirmation_requirement=ConfirmationRequirement(
            level=ConfirmationLevel.SOFTWARE,
            methods=["software", "totp"],
        ),
    )

    assert pending.selected_backend_id == "software.default"
    assert pending.selected_backend_method == "software"


def test_gh64_discord_pending_uses_later_totp_when_earlier_method_ineligible(
    tmp_path: Path,
) -> None:
    harness = _QueuePendingHarness(tmp_path)
    _register_totp_factor(harness)  # type: ignore[arg-type]

    pending = harness._queue_pending_action(
        session_id=SessionId("s-gh64"),
        user_id=UserId("alice"),
        workspace_id=WorkspaceId("w-1"),
        tool_name=ToolName("web.search"),
        arguments={"query": "discord approvals"},
        reason="requires_confirmation",
        capabilities={Capability.HTTP_REQUEST},
        delivery_target=DeliveryTarget(channel="discord", recipient="chan-1"),
        confirmation_requirement=ConfirmationRequirement(
            level=ConfirmationLevel.SOFTWARE,
            methods=["software", "totp"],
            allowed_principals=["ops-laptop"],
        ),
    )

    assert pending.selected_backend_id == "totp.default"
    assert pending.selected_backend_method == "totp"


def test_a1_public_pending_payload_exposes_shared_approval_contract(
    tmp_path: Path,
) -> None:
    harness = _QueuePendingHarness(tmp_path)
    _register_totp_factor(harness)  # type: ignore[arg-type]

    pending = harness._queue_pending_action(
        session_id=SessionId("s-a1"),
        user_id=UserId("alice"),
        workspace_id=WorkspaceId("w-1"),
        tool_name=ToolName("web.fetch"),
        arguments={"url": "https://example.test/page?token=secret-token"},
        public_arguments={"url": "https://example.test/page"},
        sensitive_public_payload=True,
        reason="requires_confirmation",
        capabilities={Capability.HTTP_REQUEST},
        delivery_target=DeliveryTarget(channel="discord", recipient="chan-1"),
        confirmation_requirement=ConfirmationRequirement(
            level=ConfirmationLevel.SOFTWARE,
            allowed_principals=["ops-laptop"],
        ),
    )

    public = harness._pending_to_dict(pending, public=True)

    assert "action_id" in ActionPendingEntry.model_fields
    entry = ActionPendingEntry.model_validate(public)
    assert entry.action_id
    assert entry.action_id != pending.confirmation_id
    assert entry.lifecycle_state == "pending"
    assert entry.identity.action_id == entry.action_id
    assert entry.identity.confirmation_id == pending.confirmation_id
    assert pending.approval_envelope is not None
    assert pending.approval_envelope.pending_action_id == entry.action_id
    assert entry.identity.delivery_target == {
        "channel": "discord",
        "recipient": "chan-1",
        "thread_id": "",
        "workspace_hint": "",
    }
    assert entry.action_kind == ActionKind.EGRESS.value
    assert entry.origin_channel == "discord"
    assert entry.required_proof_tier == "T0_identity"
    assert entry.required_level == ConfirmationLevel.SOFTWARE.value
    assert entry.required_methods == []
    assert entry.arguments == {"url": "https://example.test/page"}
    assert "secret-token" not in json.dumps(public, sort_keys=True)

    capability = entry.channel_capability
    assert capability["origin_channel"] == "discord"
    assert capability["required_proof_tier"] == "T0_identity"
    assert capability["required_level"] == ConfirmationLevel.SOFTWARE.value
    assert capability["selected_method"] == "totp"
    assert capability["selected_method_proof_tier"] == "T1_stepup"
    assert capability["can_reject"] is True
    assert capability["can_collect_selected_method"] is True
    assert capability["can_carry"] is False
    assert capability["can_carry_required_proof_tier"] is False
    assert capability["can_carry_t0_identity"] is False
    assert capability["can_carry_t1_stepup"] is True
    assert capability["requires_second_factor"] is True
    assert capability["requires_proof_input"] is True
    assert capability["cannot_carry_reason"] == "selected_method_requires_T1_stepup"


def test_f2_public_pending_payload_never_exposes_stable_idempotency_key() -> None:
    pending = _pending_action(nonce="expected")
    stable_key = "shisad-provider-key-must-remain-private"
    tool_definition = ToolDefinition(
        name=pending.tool_name,
        description="fixture",
        retry_class=ToolRetryClass.STABLE_IDEMPOTENCY_KEY,
    )
    pending.stable_idempotency_key = stable_key
    pending.recovery_authority_mac = "hmac-sha256:" + ("a" * 64)
    pending.recovery_result = {
        "ok": True,
        "stable_idempotency_key": stable_key,
        "provider_private_detail": "must-not-be-public",
    }
    pending.retry_descriptor = ToolRetryDescriptor.from_tool_definition(
        tool_definition,
        stable_idempotency_key=stable_key,
        stable_adapter_guarantee_id="provider.private/v1",
    )

    durable = HandlerImplementation._pending_to_dict(pending)
    public = HandlerImplementation._pending_to_dict(pending, public=True)

    assert durable["stable_idempotency_key"] == stable_key
    assert durable["recovery_authority_mac"] == pending.recovery_authority_mac
    assert durable["retry_descriptor"]["stable_idempotency_key"] == stable_key
    assert durable["retry_descriptor"]["stable_adapter_guarantee_id"] == "provider.private/v1"
    assert durable["recovery_result"]["stable_idempotency_key"] == stable_key
    assert public["stable_idempotency_key_present"] is True
    assert public["recovery_result_available"] is True
    assert "stable_idempotency_key" not in public
    assert "recovery_authority_mac" not in public
    assert "stable_idempotency_key" not in public["retry_descriptor"]
    assert "stable_adapter_guarantee_id" not in public["retry_descriptor"]
    assert "recovery_result" not in public
    assert stable_key not in json.dumps(public, sort_keys=True)
    assert "provider.private/v1" not in json.dumps(public, sort_keys=True)


def test_f2_pending_persist_rejects_empty_recovery_authenticator(tmp_path: Path) -> None:
    harness = _AtomicConfirmationHarness(tmp_path)
    pending = _pending_action(nonce="")
    pending.status = "failed"
    pending.status_reason = "terminal-fixture"
    harness._pending_actions[pending.confirmation_id] = pending
    harness._pending_by_session[pending.session_id] = [pending.confirmation_id]
    harness._confirmation_evidence_authenticator = SimpleNamespace(
        authenticate_recovery_snapshot=lambda _snapshot: "",
    )

    with pytest.raises(ValueError, match="recovery snapshot is not canonical"):
        harness._persist_pending_actions()

    assert not harness._pending_actions_file.exists()


def test_f2_outcome_unknown_payload_shows_evidence_and_requires_fresh_approval() -> None:
    pending = _pending_action(nonce="must-not-remain-reusable")
    pending.status = "outcome_unknown"
    pending.status_reason = "uncertain_effect_requires_fresh_approval"
    pending.decision_nonce = ""
    pending.action_digest = "sha256:action-digest"
    pending.execution_attempt_id = "attempt-uncertain"
    pending.result_id = "result-uncertain"
    pending.provider_operation_id = "provider-operation-known"

    public = HandlerImplementation._pending_to_dict(pending, public=True)
    entry = ActionPendingEntry.model_validate(public)

    assert entry.lifecycle_state == "outcome_unknown"
    assert entry.decision_nonce == ""
    assert entry.uncertainty_evidence == {
        "action_digest": "sha256:action-digest",
        "execution_attempt_id": "attempt-uncertain",
        "result_id": "result-uncertain",
        "provider_operation_id": "provider-operation-known",
        "retry_generation": 0,
    }
    assert entry.manual_retry["requires_fresh_approval"] is True
    assert entry.manual_retry["reuse_confirmation_id"] is False
    assert entry.manual_retry["provider_reconciliation_available"] is False
    assert "re-request" in entry.manual_retry["instruction"]


def test_f1_pending_action_identity_survives_restart(tmp_path: Path) -> None:
    harness = _QueuePendingHarness(tmp_path)
    pending = harness._queue_pending_action(
        session_id=SessionId("s-restart"),
        user_id=UserId("alice"),
        workspace_id=WorkspaceId("w-1"),
        tool_name=ToolName("web.search"),
        arguments={"query": "restart identity"},
        reason="requires_confirmation",
        capabilities={Capability.HTTP_REQUEST},
        delivery_target=DeliveryTarget(
            channel="discord",
            recipient="chan-1",
            workspace_hint="guild-1",
            thread_id="thread-1",
        ),
        origin_turn_id="tx-current",
    )
    before = harness._pending_to_dict(pending, public=True)

    restarted = _QueuePendingHarness(tmp_path)
    restarted._load_pending_actions()

    loaded = restarted._pending_actions[pending.confirmation_id]
    after = restarted._pending_to_dict(loaded, public=True)
    assert after["identity"] == before["identity"]
    assert after["action_id"] == pending.action_id
    assert after["origin_turn_id"] == "tx-current"
    assert after["lifecycle_state"] == "pending"


def test_f10a_load_migrates_legacy_record_schema_after_safe_hydration(tmp_path: Path) -> None:
    pending = _pending_action(nonce="legacy-schema-nonce")
    payload = HandlerImplementation._pending_to_dict(pending)
    payload.pop("record_schema_version", None)
    pending_actions_file = tmp_path / "pending_actions.json"
    pending_actions_file.write_text(json.dumps([payload]), encoding="utf-8")
    harness = _load_pending_actions_harness(pending_actions_file=pending_actions_file)

    harness._load_pending_actions()

    loaded = harness._pending_actions[pending.confirmation_id]
    assert loaded.status == "pending"
    persisted = json.loads(pending_actions_file.read_text(encoding="utf-8"))
    assert persisted[0]["record_schema_version"] == 1


def test_f10a_unhydrated_legacy_record_is_not_rewritten_as_healthy_empty(
    tmp_path: Path,
) -> None:
    pending_actions_file = tmp_path / "pending_actions.json"
    raw = json.dumps([{"confirmation_id": "", "status": "pending"}]).encode()
    pending_actions_file.write_bytes(raw)
    harness = _load_pending_actions_harness(pending_actions_file=pending_actions_file)

    harness._load_pending_actions()

    assert harness._pending_actions == {}
    assert harness._pending_by_session == {}
    assert harness._pending_state_degradation == {
        "transition": "load",
        "stage": "legacy_hydration",
        "reason": "pending_state_legacy_hydration_incomplete",
    }
    assert pending_actions_file.read_bytes() == raw

    with pytest.raises(StatePersistenceDegradedError, match="pending_actions persistence"):
        harness._persist_pending_actions()
    assert pending_actions_file.read_bytes() == raw


def test_f10a_mixed_unhydrated_legacy_store_blocks_later_mutation_without_byte_loss(
    tmp_path: Path,
) -> None:
    valid = HandlerImplementation._pending_to_dict(_pending_action(nonce="mixed-legacy-nonce"))
    valid.pop("record_schema_version", None)
    raw = json.dumps([valid, {"confirmation_id": "", "status": "pending"}]).encode()
    harness = _QueuePendingHarness(tmp_path)
    harness._pending_actions_file.write_bytes(raw)

    harness._load_pending_actions()

    assert harness._pending_actions == {}
    assert harness._pending_state_degradation == {
        "transition": "load",
        "stage": "legacy_hydration",
        "reason": "pending_state_legacy_hydration_incomplete",
    }
    with pytest.raises(StatePersistenceDegradedError, match="pending_actions persistence"):
        harness._queue_pending_action(
            session_id=SessionId("s-next"),
            user_id=UserId("alice"),
            workspace_id=WorkspaceId("w-1"),
            tool_name=ToolName("web.search"),
            arguments={"query": "must not replace legacy bytes"},
            reason="requires_confirmation",
            capabilities={Capability.HTTP_REQUEST},
        )
    assert harness._pending_actions_file.read_bytes() == raw


def test_f10a_invalid_hydrated_legacy_identity_quarantines_without_startup_crash(
    tmp_path: Path,
) -> None:
    payload = HandlerImplementation._pending_to_dict(
        _pending_action(nonce="invalid-legacy-identity")
    )
    payload.pop("record_schema_version", None)
    payload["session_id"] = ""
    identity = payload["identity"]
    assert isinstance(identity, dict)
    identity["session_id"] = ""
    raw = json.dumps([payload]).encode()
    harness = _QueuePendingHarness(tmp_path)
    harness._pending_actions_file.write_bytes(raw)

    harness._load_pending_actions()

    assert harness._pending_actions == {}
    assert harness._pending_by_session == {}
    assert harness._pending_state_degradation == {
        "transition": "load",
        "stage": "corrupt",
        "reason": "pending_state_corrupt",
    }
    quarantined = list(tmp_path.glob("pending_actions.json.corrupt.*"))
    assert len(quarantined) == 1
    assert quarantined[0].read_bytes() == raw
    assert not harness._pending_actions_file.exists()
    with pytest.raises(StatePersistenceDegradedError, match="pending_actions persistence"):
        harness._queue_pending_action(
            session_id=SessionId("s-next"),
            user_id=UserId("alice"),
            workspace_id=WorkspaceId("w-1"),
            tool_name=ToolName("web.search"),
            arguments={"query": "must stay blocked"},
            reason="requires_confirmation",
            capabilities={Capability.HTTP_REQUEST},
        )


def test_f10a_unusable_store_is_quarantined_and_blocks_new_pending_mutation(
    tmp_path: Path,
) -> None:
    harness = _QueuePendingHarness(tmp_path)
    raw = json.dumps(
        [
            {
                "record_schema_version": 2,
                "confirmation_id": "c-future",
                "session_id": "session-1",
                "identity": {
                    "confirmation_id": "c-future",
                    "session_id": "session-1",
                },
            }
        ]
    ).encode()
    harness._pending_actions_file.write_bytes(raw)

    harness._load_pending_actions()

    assert harness._pending_actions == {}
    assert harness._pending_by_session == {}
    assert harness._pending_state_degradation == {
        "transition": "load",
        "stage": "unsupported_schema",
        "reason": "pending_state_unsupported_schema",
    }
    quarantined = list(tmp_path.glob("pending_actions.json.corrupt.*"))
    assert len(quarantined) == 1
    assert quarantined[0].read_bytes() == raw
    assert not harness._pending_actions_file.exists()

    with pytest.raises(StatePersistenceDegradedError, match="pending_actions persistence"):
        harness._queue_pending_action(
            session_id=SessionId("session-1"),
            user_id=UserId("alice"),
            workspace_id=WorkspaceId("workspace-1"),
            tool_name=ToolName("web.search"),
            arguments={"query": "must stay blocked"},
            reason="requires_confirmation",
            capabilities={Capability.HTTP_REQUEST},
        )


def test_f2_queue_applies_default_and_caps_explicit_approval_lifetime(
    tmp_path: Path,
) -> None:
    harness = _QueuePendingHarness(tmp_path)

    default_lifetime = harness._queue_pending_action(
        session_id=SessionId("s-default-lifetime"),
        user_id=UserId("alice"),
        workspace_id=WorkspaceId("w-1"),
        tool_name=ToolName("web.search"),
        arguments={"query": "default lifetime"},
        reason="requires_confirmation",
        capabilities={Capability.HTTP_REQUEST},
    )
    capped_lifetime = harness._queue_pending_action(
        session_id=SessionId("s-capped-lifetime"),
        user_id=UserId("alice"),
        workspace_id=WorkspaceId("w-1"),
        tool_name=ToolName("web.search"),
        arguments={"query": "capped lifetime"},
        reason="requires_confirmation",
        capabilities={Capability.HTTP_REQUEST},
        confirmation_requirement=ConfirmationRequirement(
            timeout_seconds=7 * 24 * 60 * 60,
        ),
    )

    assert default_lifetime.expires_at is not None
    assert default_lifetime.expires_at - default_lifetime.created_at == timedelta(hours=1)
    assert capped_lifetime.expires_at is not None
    assert capped_lifetime.expires_at - capped_lifetime.created_at == timedelta(hours=24)


def test_f2_legacy_null_expiry_is_terminal_and_invalidates_nonce_on_restart(
    tmp_path: Path,
) -> None:
    pending = _pending_action(nonce="legacy-reusable-nonce")
    payload = HandlerImplementation._pending_to_dict(pending)
    payload["expires_at"] = ""
    approval_envelope = payload.get("approval_envelope")
    assert isinstance(approval_envelope, dict)
    approval_envelope["expires_at"] = None
    pending_actions_file = tmp_path / "pending_actions.json"
    pending_actions_file.write_text(json.dumps([payload]), encoding="utf-8")
    harness = _load_pending_actions_harness(
        pending_actions_file=pending_actions_file,
    )

    harness._load_pending_actions()

    loaded = harness._pending_actions[pending.confirmation_id]
    public = HandlerImplementation._pending_to_dict(loaded, public=True)
    assert loaded.status == "failed"
    assert loaded.status_reason == "approval_expired"
    assert loaded.decision_nonce == ""
    assert loaded.expires_at is not None
    assert loaded.expires_at <= datetime.now(UTC)
    assert public["lifecycle_state"] == "expired"
    persisted = json.loads(pending_actions_file.read_text(encoding="utf-8"))[0]
    assert persisted["decision_nonce"] == ""
    assert persisted["status_reason"] == "approval_expired"
    assert persisted["expires_at"]


def test_f2_load_expired_task_action_reconciles_scheduler_shadow_once(
    tmp_path: Path,
) -> None:
    scheduler = SchedulerManager(storage_dir=tmp_path / "scheduler")
    task = scheduler.create_task(
        name="reminder:legacy-expiry",
        goal="Reminder: legacy expiry",
        schedule=Schedule.from_event("message.received"),
        capability_snapshot={Capability.MESSAGE_SEND},
        policy_snapshot_ref="p1",
        created_by=UserId("alice"),
        workspace_id=WorkspaceId("w-1"),
        max_runs=1,
    )
    task.trigger_count = 1
    pending = _pending_action(nonce="legacy-task-nonce")
    pending.task_id = task.id
    _bind_pending_action_identity(pending)
    payload = HandlerImplementation._pending_to_dict(pending)
    payload["expires_at"] = ""
    approval_envelope = payload.get("approval_envelope")
    assert isinstance(approval_envelope, dict)
    approval_envelope["expires_at"] = None
    pending_actions_file = tmp_path / "pending_actions.json"
    pending_actions_file.write_text(json.dumps([payload]), encoding="utf-8")
    scheduler.queue_confirmation(
        task.id,
        {
            "confirmation_id": pending.confirmation_id,
            "task_id": task.id,
            "status": "pending",
            "lifecycle_state": "pending",
            "expires_at": "",
        },
    )
    harness = _load_pending_actions_harness(
        pending_actions_file=pending_actions_file,
    )
    harness._scheduler = scheduler

    harness._load_pending_actions()

    shadow = scheduler._pending_confirmations[task.id][0]
    assert shadow["status"] == "failed"
    assert shadow["lifecycle_state"] == "expired"
    assert shadow["status_reason"] == "approval_expired"
    assert shadow["run_outcome_recorded"] is True
    assert task.failure_count == 1


@pytest.mark.parametrize(
    "fault_stage",
    [
        AtomicWriteStage.TEMP_OPEN,
        AtomicWriteStage.WRITE,
        AtomicWriteStage.FILE_FSYNC,
        AtomicWriteStage.REPLACE,
        AtomicWriteStage.PARENT_FSYNC,
    ],
)
def test_f2_queue_persistence_failure_restores_only_durable_old_state(
    tmp_path: Path,
    fault_stage: AtomicWriteStage,
) -> None:
    harness = _QueuePendingHarness(tmp_path)
    failures_remaining = 1

    def _fail_once(stage: AtomicWriteStage) -> None:
        nonlocal failures_remaining
        if stage == fault_stage and failures_remaining:
            failures_remaining -= 1
            raise OSError(f"injected queue fault:{stage.value}")

    harness._pending_state_fault_injector = _fail_once

    with pytest.raises(AtomicWriteError):
        harness._queue_pending_action(
            session_id=SessionId("s-queue-atomic-fault"),
            user_id=UserId("alice"),
            workspace_id=WorkspaceId("w-1"),
            tool_name=ToolName("web.search"),
            arguments={"query": "must not remain fresh"},
            reason="requires_confirmation",
            capabilities={Capability.HTTP_REQUEST},
        )

    assert harness._pending_actions == {}
    assert harness._pending_by_session == {}
    if harness._pending_actions_file.exists():
        assert json.loads(harness._pending_actions_file.read_text(encoding="utf-8")) == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "fault_stage",
    [
        AtomicWriteStage.TEMP_OPEN,
        AtomicWriteStage.WRITE,
        AtomicWriteStage.FILE_FSYNC,
        AtomicWriteStage.REPLACE,
        AtomicWriteStage.PARENT_FSYNC,
    ],
)
async def test_f2_pre_effect_attempt_fault_invokes_nothing_and_restores_pending(
    tmp_path: Path,
    fault_stage: AtomicWriteStage,
) -> None:
    harness = _AtomicConfirmationHarness(tmp_path)
    pending = _pending_action(nonce="expected")
    harness._pending_actions[pending.confirmation_id] = pending
    harness._persist_pending_actions()
    failures_remaining = 1

    def _fail_once(stage: AtomicWriteStage) -> None:
        nonlocal failures_remaining
        if stage == fault_stage and failures_remaining:
            failures_remaining -= 1
            raise OSError(f"injected executing fault:{stage.value}")

    harness._pending_state_fault_injector = _fail_once

    with pytest.raises(AtomicWriteError):
        await harness.do_action_confirm(
            {"confirmation_id": pending.confirmation_id, "decision_nonce": "expected"}
        )

    assert harness.effect_calls == 0
    assert pending.status == "pending"
    assert pending.execution_attempt_id == ""
    assert pending.result_id == ""
    assert pending.confirmation_evidence is None
    assert pending.recovery_authority_mac == ""
    durable = json.loads(harness._pending_actions_file.read_text(encoding="utf-8"))[0]
    assert durable["status"] == "pending"
    assert durable["execution_attempt_id"] == ""


@pytest.mark.asyncio
async def test_pending_attempt_state_is_durable_before_effect(tmp_path: Path) -> None:
    class _InspectingHarness(_AtomicConfirmationHarness):
        async def _execute_approved_action(self, **kwargs: object) -> object:
            durable = json.loads(self._pending_actions_file.read_text(encoding="utf-8"))[0]
            assert durable["status"] == "executing"
            assert durable["execution_attempt_id"]
            assert durable["result_id"]
            assert durable["action_digest"] == durable["approval_envelope"]["action_digest"]
            assert durable["approval_evidence_hash"].startswith("sha256:")
            return await super()._execute_approved_action(**kwargs)

    harness = _InspectingHarness(tmp_path)
    pending = _pending_action(nonce="expected")
    harness._pending_actions[pending.confirmation_id] = pending
    harness._persist_pending_actions()

    result = await harness.do_action_confirm(
        {"confirmation_id": pending.confirmation_id, "decision_nonce": "expected"}
    )

    assert result["confirmed"] is True
    assert harness.effect_calls == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("scheduled", [False, True])
async def test_f2_confirmed_post_effect_exception_persists_uncertainty(
    tmp_path: Path,
    scheduled: bool,
) -> None:
    class _PostEffectExceptionHarness(_AtomicConfirmationHarness):
        async def _execute_approved_action(self, **_kwargs: object) -> object:
            self.effect_calls += 1
            raise RuntimeError("provider failed after possible effect")

    harness = _PostEffectExceptionHarness(tmp_path, allow_amendment=True)
    pending = _pending_action(nonce="expected")
    pending.reason = "trace:stage2_upgrade_required"
    scheduler: _SchedulerRecorder | None = None
    if scheduled:
        pending.task_id = "task-confirmed-post-effect-exception"
        scheduler = _SchedulerRecorder()
        scheduler.task = SimpleNamespace(
            enabled=True,
            max_runs=3,
            success_count=0,
            recovery_containment_token="",
        )
        harness._scheduler = scheduler
        for method_name in (
            "_record_pending_scheduler_state",
            "_complete_pending_scheduler_accounting",
            "_finalize_pending_scheduler_accounting",
            "_recovery_task_cancel_reason",
        ):
            method = getattr(HandlerImplementation, method_name)
            setattr(harness, method_name, method.__get__(harness, HandlerImplementation))
    _bind_pending_action_identity(pending)
    harness._pending_actions[pending.confirmation_id] = pending
    harness._persist_pending_actions()

    with pytest.raises(RuntimeError, match="possible effect"):
        await harness.do_action_confirm(
            {"confirmation_id": pending.confirmation_id, "decision_nonce": "expected"}
        )

    assert harness.effect_calls == 1
    assert pending.status == "outcome_unknown"
    assert pending.status_reason == "uncertain_effect_requires_fresh_approval"
    assert pending.decision_nonce == ""
    assert pending.recovery_effect_invoked is True
    assert harness._control_plane.cancelled_correlations == [pending.stage2_correlation_id]
    durable = json.loads(harness._pending_actions_file.read_text(encoding="utf-8"))[0]
    assert durable["status"] == "outcome_unknown"
    assert durable["decision_nonce"] == ""
    replay = await harness.do_action_confirm(
        {"confirmation_id": pending.confirmation_id, "decision_nonce": "expected"}
    )
    assert replay["confirmed"] is False
    assert harness.effect_calls == 1
    if scheduled:
        assert scheduler is not None
        assert scheduler.task is not None
        assert scheduler.task.enabled is False
        assert scheduler.run_outcomes == []
        assert pending.scheduler_accounting_mode == "ambiguous"
        assert pending.scheduler_accounting_pending is False


@pytest.mark.asyncio
async def test_f2_confirmed_exception_revokes_stage2_when_fallback_containment_fails(
    tmp_path: Path,
) -> None:
    class _PersistentContainmentFailureHarness(_AtomicConfirmationHarness):
        def __init__(self, path: Path) -> None:
            super().__init__(path, allow_amendment=True)
            self.fallback_containment_attempts = 0

        async def _execute_approved_action(self, **_kwargs: object) -> object:
            self.effect_calls += 1

            def _fail_pending_persistence(stage: AtomicWriteStage) -> None:
                if stage == AtomicWriteStage.FILE_FSYNC:
                    raise OSError("persistent post-effect state failure")

            self._pending_state_fault_injector = _fail_pending_persistence
            raise RuntimeError("provider failed after possible effect")

        def _contain_confirmation_scheduler_attempt(self, _pending: object) -> None:
            self.fallback_containment_attempts += 1
            self._persist_pending_actions()

    harness = _PersistentContainmentFailureHarness(tmp_path)
    pending = _pending_action(nonce="expected")
    pending.reason = "trace:stage2_upgrade_required"
    pending.task_id = "task-confirmed-degraded-containment"
    _bind_pending_action_identity(pending)
    harness._scheduler = _SchedulerRecorder()
    harness._scheduler.task = SimpleNamespace(enabled=True)
    harness._pending_actions[pending.confirmation_id] = pending
    harness._persist_pending_actions()

    with pytest.raises(AtomicWriteError):
        await harness.do_action_confirm(
            {"confirmation_id": pending.confirmation_id, "decision_nonce": "expected"}
        )

    assert harness.effect_calls == 1
    assert harness.fallback_containment_attempts == 1
    assert pending.stage2_correlation_id
    assert harness._control_plane.cancelled_correlations == [pending.stage2_correlation_id]
    durable = json.loads(harness._pending_actions_file.read_text(encoding="utf-8"))[0]
    assert durable["status"] == "executing"
    assert durable["stage2_correlation_id"] == pending.stage2_correlation_id


@pytest.mark.asyncio
async def test_f2_cancelled_confirmed_effect_contains_uncertainty_and_authority(
    tmp_path: Path,
) -> None:
    class _CancelledEffectHarness(_AtomicConfirmationHarness):
        def __init__(self, path: Path) -> None:
            super().__init__(path, allow_amendment=True)
            self.effect_started = asyncio.Event()

        async def _execute_approved_action(self, **_kwargs: object) -> object:
            self.effect_calls += 1
            self.effect_started.set()
            await asyncio.Future()
            raise AssertionError("cancelled effect unexpectedly resumed")

    harness = _CancelledEffectHarness(tmp_path)
    pending = _pending_action(nonce="expected")
    pending.reason = "trace:stage2_upgrade_required"
    pending.task_id = "task-cancelled-confirmed-effect"
    _bind_pending_action_identity(pending)
    scheduler = _SchedulerRecorder()
    scheduler.task = SimpleNamespace(
        enabled=True,
        max_runs=3,
        success_count=0,
        recovery_containment_token="",
    )
    harness._scheduler = scheduler
    for method_name in (
        "_record_pending_scheduler_state",
        "_complete_pending_scheduler_accounting",
        "_finalize_pending_scheduler_accounting",
        "_recovery_task_cancel_reason",
    ):
        method = getattr(HandlerImplementation, method_name)
        setattr(harness, method_name, method.__get__(harness, HandlerImplementation))
    harness._pending_actions[pending.confirmation_id] = pending
    harness._persist_pending_actions()

    confirmation_task = asyncio.create_task(
        harness.do_action_confirm(
            {"confirmation_id": pending.confirmation_id, "decision_nonce": "expected"}
        )
    )
    await asyncio.wait_for(harness.effect_started.wait(), timeout=1.0)
    confirmation_task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await confirmation_task

    assert harness.effect_calls == 1
    assert pending.status == "outcome_unknown"
    assert pending.decision_nonce == ""
    assert pending.recovery_effect_invoked is True
    assert scheduler.task.enabled is False
    assert scheduler.run_outcomes == []
    assert pending.stage2_correlation_id
    assert harness._control_plane.cancelled_correlations == [pending.stage2_correlation_id]


@pytest.mark.asyncio
async def test_f2_cancelled_stage2_ready_transition_revokes_correlation(
    tmp_path: Path,
) -> None:
    harness = _AtomicConfirmationHarness(tmp_path, allow_amendment=True)
    stage2_publication_started = asyncio.Event()

    async def _block_stage2_publication(event: object) -> None:
        if isinstance(event, PlanAmended):
            stage2_publication_started.set()
            await asyncio.Future()
        harness.published_events.append(event)

    harness._event_bus = SimpleNamespace(publish=_block_stage2_publication)
    pending = _pending_action(nonce="expected")
    pending.reason = "trace:stage2_upgrade_required"
    pending.task_id = "task-stage2-ready-cancelled"
    _bind_pending_action_identity(pending)
    scheduler = _SchedulerRecorder()
    scheduler.task = SimpleNamespace(enabled=True)
    harness._scheduler = scheduler
    harness._pending_actions[pending.confirmation_id] = pending
    harness._persist_pending_actions()

    confirmation_task = asyncio.create_task(
        harness.do_action_confirm(
            {"confirmation_id": pending.confirmation_id, "decision_nonce": "expected"}
        )
    )
    await asyncio.wait_for(stage2_publication_started.wait(), timeout=1.0)
    confirmation_task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await confirmation_task

    assert harness.effect_calls == 0
    assert pending.stage2_correlation_id
    assert harness._control_plane.cancelled_correlations == [pending.stage2_correlation_id]
    assert pending.status in {"failed", "cancelled"}
    assert pending.status_reason
    assert scheduler.run_outcomes == [{"task_id": pending.task_id, "success": False}]
    durable = json.loads(harness._pending_actions_file.read_text(encoding="utf-8"))[0]
    assert durable["status"] in {"failed", "cancelled"}
    assert durable["status_reason"]


@pytest.mark.asyncio
async def test_f2_cancelled_stage2_reconciliation_terminates_session(tmp_path: Path) -> None:
    harness = _AtomicConfirmationHarness(tmp_path)

    async def _cancel_stage2(**_kwargs: object) -> bool:
        raise asyncio.CancelledError

    harness._control_plane = SimpleNamespace(cancel_stage2=_cancel_stage2)
    terminated: list[tuple[SessionId, str]] = []

    def _terminate_session(session_id: SessionId, *, reason: str = "") -> bool:
        terminated.append((session_id, reason))
        return True

    harness._terminate_session = _terminate_session  # type: ignore[method-assign]
    pending = _pending_action(nonce="expected")
    pending.stage2_correlation_id = "stage2-cancelled-reconciliation"
    pending.stage2_plan_hash = "plan-stage2"

    cancelled = await harness._cancel_stage2_authority(
        pending,
        reason="cancelled_reconciliation_test",
    )

    assert cancelled is False
    assert terminated == [(pending.session_id, "stage2_authority_reconciliation_failed")]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "fault_stage",
    [
        AtomicWriteStage.TEMP_OPEN,
        AtomicWriteStage.WRITE,
        AtomicWriteStage.FILE_FSYNC,
        AtomicWriteStage.REPLACE,
        AtomicWriteStage.PARENT_FSYNC,
    ],
)
async def test_f2_post_effect_terminal_fault_matches_publication_posture(
    tmp_path: Path,
    fault_stage: AtomicWriteStage,
) -> None:
    class _TerminalFaultHarness(_AtomicConfirmationHarness):
        async def _execute_approved_action(self, **kwargs: object) -> object:
            result = await super()._execute_approved_action(**kwargs)
            failures_remaining = 1

            def _fail_terminal_write(stage: AtomicWriteStage) -> None:
                nonlocal failures_remaining
                if stage == fault_stage and failures_remaining:
                    failures_remaining -= 1
                    raise OSError("injected terminal persistence fault")

            self._pending_state_fault_injector = _fail_terminal_write
            return result

    harness = _TerminalFaultHarness(tmp_path)
    pending = _pending_action(nonce="expected")
    harness._pending_actions[pending.confirmation_id] = pending
    harness._persist_pending_actions()

    with pytest.raises(AtomicWriteError):
        await harness.do_action_confirm(
            {"confirmation_id": pending.confirmation_id, "decision_nonce": "expected"}
        )

    assert harness.effect_calls == 1
    expected_status = "approved" if fault_stage == AtomicWriteStage.PARENT_FSYNC else "executing"
    assert pending.status == expected_status
    durable = json.loads(harness._pending_actions_file.read_text(encoding="utf-8"))[0]
    assert durable["status"] == expected_status
    assert durable["execution_attempt_id"] == pending.execution_attempt_id


@pytest.mark.asyncio
async def test_f2_failed_queue_rollback_surfaces_typed_persistence_degradation(
    tmp_path: Path,
) -> None:
    harness = _QueuePendingHarness(tmp_path)

    def _fail_parent_fsync(stage: AtomicWriteStage) -> None:
        if stage == AtomicWriteStage.PARENT_FSYNC:
            raise OSError("injected queue and rollback parent-fsync fault")

    harness._pending_state_fault_injector = _fail_parent_fsync

    with pytest.raises(AtomicWriteError):
        harness._queue_pending_action(
            session_id=SessionId("s-queue-degraded"),
            user_id=UserId("alice"),
            workspace_id=WorkspaceId("w-1"),
            tool_name=ToolName("web.search"),
            arguments={"query": "retain possible publication"},
            reason="requires_confirmation",
            capabilities={Capability.HTTP_REQUEST},
        )

    assert len(harness._pending_actions) == 1
    pending = next(iter(harness._pending_actions.values()))
    assert pending.status == "pending"
    result = await harness.do_action_pending({"status": "all"})
    assert result["persistence_status"] == "degraded"
    assert result["persistence_reason"] == "pending_state_rollback_uncommitted"
    assert result["persistence_stage"] == "parent_fsync"
    assert result["persistence_transition"] == "queue"

    harness._pending_state_fault_injector = None
    with pytest.raises(StatePersistenceDegradedError):
        harness._queue_pending_action(
            session_id=SessionId("s-queue-must-stay-blocked"),
            user_id=UserId("alice"),
            workspace_id=WorkspaceId("w-1"),
            tool_name=ToolName("web.search"),
            arguments={"query": "must require restart recovery"},
            reason="requires_confirmation",
            capabilities={Capability.HTTP_REQUEST},
        )
    assert len(harness._pending_actions) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("decision", ["confirm", "reject"])
async def test_f2_persistence_degradation_blocks_decisions_until_recovery(
    tmp_path: Path,
    decision: str,
) -> None:
    harness = _AtomicConfirmationHarness(tmp_path)
    pending = _pending_action(nonce="expected")
    harness._pending_actions[pending.confirmation_id] = pending
    harness._persist_pending_actions()
    harness._pending_state_degradation = {
        "transition": "executing",
        "stage": "parent_fsync",
        "reason": "pending_state_rollback_uncommitted",
    }

    handler = harness.do_action_confirm if decision == "confirm" else harness.do_action_reject
    result = await handler(
        {"confirmation_id": pending.confirmation_id, "decision_nonce": "expected"}
    )

    assert result[f"{decision}ed"] is False
    assert result["reason"] == "pending_state_persistence_degraded"
    assert result["persistence_stage"] == "parent_fsync"
    assert harness.effect_calls == 0
    assert pending.status == "pending"


@pytest.mark.asyncio
async def test_f2_reject_terminal_state_commits_before_rejection_side_effects(
    tmp_path: Path,
) -> None:
    harness = _AtomicConfirmationHarness(tmp_path)
    pending = _pending_action(nonce="expected")
    harness._pending_actions[pending.confirmation_id] = pending
    harness._persist_pending_actions()
    failures_remaining = 1

    def _fail_terminal_write(stage: AtomicWriteStage) -> None:
        nonlocal failures_remaining
        if stage == AtomicWriteStage.FILE_FSYNC and failures_remaining:
            failures_remaining -= 1
            raise OSError("injected reject terminal persistence fault")

    harness._pending_state_fault_injector = _fail_terminal_write

    with pytest.raises(AtomicWriteError):
        await harness.do_action_reject(
            {"confirmation_id": pending.confirmation_id, "decision_nonce": "expected"}
        )

    assert pending.status == "pending"
    assert pending.status_reason == ""
    assert pending.decision_nonce == "expected"
    assert harness.published_events == []
    durable = json.loads(harness._pending_actions_file.read_text(encoding="utf-8"))[0]
    assert durable["status"] == "pending"
    assert durable["decision_nonce"] == "expected"


def test_f2_stale_terminal_state_commits_before_scheduler_side_effects(
    tmp_path: Path,
) -> None:
    harness = _AtomicConfirmationHarness(tmp_path)
    scheduler = _SchedulerRecorder()
    harness._scheduler = scheduler
    pending = _pending_action(nonce="expected")
    pending.task_id = "task-f2-terminal-order"
    harness._pending_actions[pending.confirmation_id] = pending
    harness._persist_pending_actions()
    failures_remaining = 1

    def _fail_terminal_write(stage: AtomicWriteStage) -> None:
        nonlocal failures_remaining
        if stage == AtomicWriteStage.FILE_FSYNC and failures_remaining:
            failures_remaining -= 1
            raise OSError("injected stale terminal persistence fault")

    harness._pending_state_fault_injector = _fail_terminal_write

    with pytest.raises(AtomicWriteError):
        harness._mark_stale_pending_action(pending, reason="approval_expired")

    assert pending.status == "pending"
    assert pending.status_reason == ""
    assert pending.decision_nonce == "expected"
    assert pending.scheduler_accounting_pending is False
    assert pending.scheduler_accounting_mode == ""
    assert scheduler.resolved_confirmations == []
    assert scheduler.run_outcomes == []


@pytest.mark.asyncio
@pytest.mark.parametrize("terminal_family", ["disabled", "task_cancel", "lockdown"])
async def test_f2_neighbor_terminal_families_commit_before_side_effects(
    tmp_path: Path,
    terminal_family: str,
) -> None:
    harness = _AtomicConfirmationHarness(tmp_path)
    scheduler = _SchedulerRecorder()
    harness._scheduler = scheduler
    pending = _pending_action(nonce="expected")
    pending.task_id = "task-f2-neighbor-terminal"
    _bind_pending_action_identity(pending)
    scheduler.task = SimpleNamespace(enabled=terminal_family != "disabled")
    harness._pending_actions[pending.confirmation_id] = pending
    harness._persist_pending_actions()
    failures_remaining = 1

    def _fail_terminal_write(stage: AtomicWriteStage) -> None:
        nonlocal failures_remaining
        if stage == AtomicWriteStage.FILE_FSYNC and failures_remaining:
            failures_remaining -= 1
            raise OSError(f"injected {terminal_family} terminal persistence fault")

    harness._pending_state_fault_injector = _fail_terminal_write
    if terminal_family == "lockdown":
        harness._lockdown_manager = SimpleNamespace(should_block_all_actions=lambda _sid: True)

    with pytest.raises(AtomicWriteError):
        if terminal_family == "task_cancel":
            await harness._cancel_pending_actions_for_task(
                pending.task_id,
                reason="task_disabled",
            )
        else:
            await harness.do_action_confirm(
                {
                    "confirmation_id": pending.confirmation_id,
                    "decision_nonce": "expected",
                }
            )

    assert pending.status == "pending"
    assert pending.status_reason == ""
    assert pending.decision_nonce == "expected"
    assert pending.scheduler_accounting_pending is False
    assert pending.scheduler_accounting_mode == ""
    assert harness.published_events == []
    assert scheduler.resolved_confirmations == []
    assert scheduler.run_outcomes == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    (
        "terminal_family",
        "expected_status",
        "expected_reason",
        "expected_failure_accounting",
    ),
    [
        pytest.param("reject", "rejected", "user_rejected", True, id="explicit-rejection"),
        pytest.param("expired", "failed", "approval_expired", True, id="expiry"),
        pytest.param("disabled", "cancelled", "task_disabled", True, id="task-disabled"),
        pytest.param(
            "task_cancel",
            "cancelled",
            "task_cancelled",
            False,
            id="task-cancel",
        ),
        pytest.param("lockdown", "rejected", "session_in_lockdown", True, id="lockdown"),
        pytest.param(
            "backend",
            "failed",
            "approval_contract_mismatch",
            True,
            id="backend-contract-invalid",
        ),
        pytest.param(
            "pep",
            "rejected",
            "pep:schema_validation_failed",
            True,
            id="pep-reject",
        ),
    ],
)
async def test_f2_scheduled_terminal_postcommit_fault_replays_after_restart(
    tmp_path: Path,
    terminal_family: str,
    expected_status: str,
    expected_reason: str,
    expected_failure_accounting: bool,
) -> None:
    harness = _AtomicConfirmationHarness(
        tmp_path,
        allow_amendment=terminal_family == "pep",
    )
    scheduler = _SchedulerRecorder()
    scheduler.task = SimpleNamespace(enabled=terminal_family != "disabled")
    scheduler.resolve_failures_remaining = 1
    harness._scheduler = scheduler
    pending = _pending_action(nonce="expected")
    pending.task_id = "task-f2-terminal-replay"
    if terminal_family == "expired":
        pending.expires_at = datetime.now(UTC) - timedelta(seconds=1)
    elif terminal_family == "backend":
        pending.selected_backend_id = "missing.backend"
    if terminal_family == "lockdown":
        harness._lockdown_manager = SimpleNamespace(should_block_all_actions=lambda _sid: True)
    _bind_pending_action_identity(pending)
    harness._pending_actions[pending.confirmation_id] = pending
    harness._persist_pending_actions()

    with pytest.raises(RuntimeError, match="scheduler confirmation publication fault"):
        if terminal_family == "task_cancel":
            await harness._cancel_pending_actions_for_task(
                pending.task_id,
                reason=expected_reason,
            )
        elif terminal_family == "reject":
            await harness.do_action_reject(
                {
                    "confirmation_id": pending.confirmation_id,
                    "decision_nonce": pending.decision_nonce,
                    "reason": expected_reason,
                }
            )
        elif terminal_family == "pep":
            await harness._commit_and_publish_pending_terminal(
                pending,
                status=expected_status,
                status_reason=expected_reason,
            )
        else:
            await harness.do_action_confirm(
                {
                    "confirmation_id": pending.confirmation_id,
                    "decision_nonce": pending.decision_nonce,
                }
            )

    durable = json.loads(harness._pending_actions_file.read_text(encoding="utf-8"))[0]
    assert durable["status"] == expected_status
    assert durable["status_reason"] == expected_reason
    assert durable["scheduler_accounting_pending"] is True
    assert durable["scheduler_accounting_mode"] == (
        "failure" if expected_failure_accounting else "shadow_only"
    )
    assert scheduler.run_outcomes == []

    restarted = _load_pending_actions_harness(
        pending_actions_file=harness._pending_actions_file,
    )
    restarted._scheduler = scheduler
    restarted._load_pending_actions()

    recovered = restarted._pending_actions[pending.confirmation_id]
    assert recovered.status == expected_status
    assert recovered.status_reason == expected_reason
    assert recovered.scheduler_accounting_pending is False
    assert recovered.scheduler_accounting_mode == (
        "failure" if expected_failure_accounting else "shadow_only"
    )
    assert scheduler.resolved_confirmations[-1]["status"] == expected_status
    if expected_failure_accounting:
        assert scheduler.confirmation_outcomes[(pending.task_id, pending.confirmation_id)] is False
        assert len(scheduler.run_outcomes) == 1
    else:
        assert (pending.task_id, pending.confirmation_id) not in scheduler.confirmation_outcomes
        assert scheduler.run_outcomes == []

    resolution_count = len(scheduler.resolved_confirmations)
    second_restart = _load_pending_actions_harness(
        pending_actions_file=harness._pending_actions_file,
    )
    second_restart._scheduler = scheduler
    second_restart._load_pending_actions()
    assert len(scheduler.run_outcomes) == int(expected_failure_accounting)
    assert len(scheduler.resolved_confirmations) == resolution_count


def test_f2_canonical_scheduled_terminal_without_marker_reconciles_once(
    tmp_path: Path,
) -> None:
    pending = _pending_action(nonce="expected")
    pending.task_id = "task-f2-legacy-terminal-replay"
    pending.status = "rejected"
    pending.status_reason = "user_rejected"
    pending.decision_nonce = ""
    pending_actions_file = tmp_path / "pending_actions.json"
    harness = _load_pending_actions_harness(
        pending_actions_file=pending_actions_file,
    )
    harness._pending_actions[pending.confirmation_id] = pending
    harness._persist_pending_actions()
    scheduler = _SchedulerRecorder()
    scheduler.task = SimpleNamespace(enabled=True)
    harness._pending_actions = {}
    harness._pending_by_session = {}
    harness._scheduler = scheduler

    harness._load_pending_actions()

    recovered = harness._pending_actions[pending.confirmation_id]
    assert recovered.status == "rejected"
    assert recovered.status_reason == "user_rejected"
    assert recovered.scheduler_accounting_pending is False
    assert scheduler.resolved_confirmations[-1]["status"] == "rejected"
    assert scheduler.confirmation_outcomes[(pending.task_id, pending.confirmation_id)] is False
    assert len(scheduler.run_outcomes) == 1

    second_restart = _load_pending_actions_harness(
        pending_actions_file=pending_actions_file,
    )
    second_restart._scheduler = scheduler
    second_restart._load_pending_actions()
    assert len(scheduler.run_outcomes) == 1


def test_f2_legacy_cancelled_accounting_ambiguity_converges_once(
    tmp_path: Path,
) -> None:
    pending = _pending_action(nonce="expected")
    pending.task_id = "task-f2-legacy-cancelled-ambiguity"
    pending.status = "cancelled"
    pending.status_reason = "task_disabled"
    pending.decision_nonce = ""
    pending_actions_file = tmp_path / "pending_actions.json"
    harness = _load_pending_actions_harness(
        pending_actions_file=pending_actions_file,
    )
    harness._pending_actions[pending.confirmation_id] = pending
    harness._persist_pending_actions()
    scheduler = _SchedulerRecorder()
    scheduler.task = SimpleNamespace(enabled=True)
    harness._pending_actions = {}
    harness._pending_by_session = {}
    harness._scheduler = scheduler

    harness._load_pending_actions()

    recovered = harness._pending_actions[pending.confirmation_id]
    assert recovered.status == "cancelled"
    assert recovered.status_reason == "legacy_scheduler_accounting_intent_unknown"
    assert recovered.scheduler_accounting_mode == "ambiguous"
    assert recovered.scheduler_accounting_pending is False
    assert scheduler.task.enabled is False
    assert scheduler.resolved_confirmations[-1]["status"] == "cancelled"
    assert scheduler.run_outcomes == []
    assert scheduler.confirmation_outcomes == {}
    resolution_count = len(scheduler.resolved_confirmations)

    second_restart = _load_pending_actions_harness(
        pending_actions_file=pending_actions_file,
    )
    second_restart._scheduler = scheduler
    second_restart._load_pending_actions()
    assert len(scheduler.resolved_confirmations) == resolution_count
    assert scheduler.run_outcomes == []


@pytest.mark.parametrize(
    ("original_mode", "tampered_mode", "status", "status_reason"),
    [
        ("failure", "shadow_only", "failed", "terminal-fixture"),
        ("shadow_only", "failure", "cancelled", "task_cancelled"),
        (
            "ambiguous",
            "shadow_only",
            "cancelled",
            "legacy_scheduler_accounting_intent_unknown",
        ),
    ],
)
def test_f2_invalid_recovery_mac_neutralizes_valid_scheduler_mode_substitution(
    tmp_path: Path,
    original_mode: str,
    tampered_mode: str,
    status: str,
    status_reason: str,
) -> None:
    pending = _pending_action(nonce="")
    pending.task_id = "task-f2-invalid-accounting-mode"
    pending.status = status
    pending.status_reason = status_reason
    pending.scheduler_accounting_pending = True
    pending.scheduler_accounting_mode = original_mode
    _bind_pending_action_identity(pending)
    pending_actions_file = tmp_path / "pending_actions.json"
    harness = _load_pending_actions_harness(
        pending_actions_file=pending_actions_file,
    )
    scheduler = _SchedulerRecorder()
    scheduler.task = SimpleNamespace(enabled=True)
    harness._scheduler = scheduler
    harness._pending_actions[pending.confirmation_id] = pending
    harness._pending_by_session[pending.session_id] = [pending.confirmation_id]
    harness._persist_pending_actions()
    durable_rows = json.loads(pending_actions_file.read_text(encoding="utf-8"))
    original_mac = durable_rows[0]["recovery_authority_mac"]
    durable_rows[0]["scheduler_accounting_mode"] = tampered_mode
    pending_actions_file.write_text(json.dumps(durable_rows), encoding="utf-8")
    harness = _load_pending_actions_harness(
        pending_actions_file=pending_actions_file,
    )
    harness._scheduler = scheduler
    harness._load_pending_actions()

    recovered = harness._pending_actions[pending.confirmation_id]
    assert recovered.status == "outcome_unknown"
    assert recovered.status_reason == "uncertain_effect_requires_fresh_approval"
    assert recovered.scheduler_accounting_mode == "ambiguous"
    assert recovered.scheduler_accounting_pending is True
    assert recovered.recovery_scheduler_accounted is True
    assert scheduler.task.enabled is False
    assert scheduler.run_outcomes == []
    persisted = json.loads(pending_actions_file.read_text(encoding="utf-8"))[0]
    assert persisted["scheduler_accounting_mode"] == "ambiguous"
    assert persisted["scheduler_accounting_pending"] is True
    assert persisted["recovery_authority_mac"] != original_mac
    harness._finalize_pending_scheduler_accounting(recovered)
    resolution_count = len(scheduler.resolved_confirmations)

    second_restart = _load_pending_actions_harness(
        pending_actions_file=pending_actions_file,
    )
    second_restart._scheduler = scheduler
    second_restart._load_pending_actions()
    replayed = second_restart._pending_actions[pending.confirmation_id]
    assert replayed.scheduler_accounting_mode == "ambiguous"
    assert replayed.scheduler_accounting_pending is False
    assert len(scheduler.resolved_confirmations) == resolution_count


@pytest.mark.parametrize("untrusted_mode", ["", "failure", "shadow_only"])
def test_f2_runtime_authority_invalidation_neutralizes_scheduler_intent(
    tmp_path: Path,
    untrusted_mode: str,
) -> None:
    pending = _pending_action(nonce="")
    pending.task_id = "task-f2-runtime-invalid-accounting-mode"
    pending.status = "failed"
    pending.scheduler_accounting_pending = True
    pending.scheduler_accounting_mode = untrusted_mode
    harness = _load_pending_actions_harness(
        pending_actions_file=tmp_path / "pending_actions.json",
    )
    harness._pending_actions[pending.confirmation_id] = pending
    harness._pending_by_session[pending.session_id] = [pending.confirmation_id]

    harness._invalidate_recovered_authority(pending)

    assert pending.status == "outcome_unknown"
    assert pending.status_reason == "uncertain_effect_requires_fresh_approval"
    assert pending.scheduler_accounting_mode == "ambiguous"
    assert pending.scheduler_accounting_pending is True
    assert pending.recovery_scheduler_accounted is False


@pytest.mark.asyncio
async def test_f2_stage2_amendment_waits_for_durable_executing_attempt(
    tmp_path: Path,
) -> None:
    harness = _AtomicConfirmationHarness(tmp_path, allow_amendment=True)
    pending = _pending_action(nonce="expected")
    pending.reason = "trace:stage2_upgrade_required"
    pending.preflight_action = None
    _bind_pending_action_identity(pending)
    harness._pending_actions[pending.confirmation_id] = pending
    harness._persist_pending_actions()
    failures_remaining = 1

    def _fail_executing_write(stage: AtomicWriteStage) -> None:
        nonlocal failures_remaining
        if stage == AtomicWriteStage.FILE_FSYNC and failures_remaining:
            failures_remaining -= 1
            raise OSError("injected pre-stage2 executing persistence fault")

    harness._pending_state_fault_injector = _fail_executing_write

    with pytest.raises(AtomicWriteError):
        await harness.do_action_confirm(
            {"confirmation_id": pending.confirmation_id, "decision_nonce": "expected"}
        )

    assert pending.status == "pending"
    assert pending.decision_nonce == "expected"
    assert harness._control_plane.approved_actions == []
    assert not any(isinstance(event, PlanAmended) for event in harness.published_events)
    assert harness.effect_calls == 0


@pytest.mark.asyncio
async def test_f2_stage2_ready_write_fault_resolves_durable_attempt_before_effect(
    tmp_path: Path,
) -> None:
    harness = _AtomicConfirmationHarness(tmp_path, allow_amendment=True)
    pending = _pending_action(nonce="expected")
    pending.reason = "trace:stage2_upgrade_required"
    pending.preflight_action = None
    _bind_pending_action_identity(pending)
    harness._pending_actions[pending.confirmation_id] = pending
    harness._persist_pending_actions()
    publications = 0

    def _fail_stage2_ready_write(stage: AtomicWriteStage) -> None:
        nonlocal publications
        if stage == AtomicWriteStage.TEMP_OPEN:
            publications += 1
        if publications == 2 and stage == AtomicWriteStage.FILE_FSYNC:
            raise OSError("injected post-stage2 ready persistence fault")

    harness._pending_state_fault_injector = _fail_stage2_ready_write

    with pytest.raises(AtomicWriteError):
        await harness.do_action_confirm(
            {"confirmation_id": pending.confirmation_id, "decision_nonce": "expected"}
        )

    assert len(harness._control_plane.approved_actions) == 1
    assert pending.stage2_correlation_id
    assert harness._control_plane.approved_correlations == [
        (
            pending.stage2_correlation_id,
            "plan-before",
            f"execution:{pending.execution_attempt_id}:control-plane",
        )
    ]
    assert harness._control_plane.cancelled_correlations == [pending.stage2_correlation_id]
    assert sum(isinstance(event, PlanAmended) for event in harness.published_events) == 1
    assert pending.status == "failed"
    assert pending.status_reason == "stage2_ready_transition_failed"
    assert harness.effect_calls == 0
    durable = json.loads(harness._pending_actions_file.read_text(encoding="utf-8"))[0]
    assert durable["status"] == "failed"
    assert durable["status_reason"] == "stage2_ready_transition_failed"
    assert (
        HandlerImplementation._recovery_descriptor_is_current(
            harness,  # type: ignore[arg-type]
            pending,
            retry_class=ToolRetryClass.STRUCTURAL_READ,
        )
        is False
    )


@pytest.mark.asyncio
async def test_f2_stage2_commit_then_response_loss_cancels_exact_correlation(
    tmp_path: Path,
) -> None:
    harness = _AtomicConfirmationHarness(tmp_path, allow_amendment=True)

    class _CommitThenResponseLoss(_ControlPlaneRecorder):
        def approve_stage2(
            self,
            *,
            action: object,
            approved_by: str,
            correlation_id: str = "",
            expected_previous_hash: str = "",
            execution_idempotency_key: str = "",
        ) -> str:
            super().approve_stage2(
                action=action,
                approved_by=approved_by,
                correlation_id=correlation_id,
                expected_previous_hash=expected_previous_hash,
                execution_idempotency_key=execution_idempotency_key,
            )
            raise ControlPlaneUnavailableError(
                message="stage2 committed before response loss",
            )

    control_plane = _CommitThenResponseLoss()
    harness._control_plane = control_plane
    pending = _pending_action(nonce="expected")
    pending.reason = "trace:stage2_upgrade_required"
    pending.preflight_action = None
    _bind_pending_action_identity(pending)
    harness._pending_actions[pending.confirmation_id] = pending
    harness._persist_pending_actions()

    result = await harness.do_action_confirm(
        {"confirmation_id": pending.confirmation_id, "decision_nonce": "expected"}
    )

    assert result["confirmed"] is False
    assert pending.stage2_correlation_id
    assert control_plane.cancelled_correlations == [pending.stage2_correlation_id]
    assert harness.effect_calls == 0


@pytest.mark.asyncio
async def test_f2_stage2_post_commit_task_cancellation_resolves_durable_attempt(
    tmp_path: Path,
) -> None:
    harness = _AtomicConfirmationHarness(tmp_path, allow_amendment=True)
    stage2_committed = asyncio.Event()

    class _CommitThenBlock(_ControlPlaneRecorder):
        async def approve_stage2(
            self,
            *,
            action: object,
            approved_by: str,
            correlation_id: str = "",
            expected_previous_hash: str = "",
            execution_idempotency_key: str = "",
        ) -> str:
            super().approve_stage2(
                action=action,
                approved_by=approved_by,
                correlation_id=correlation_id,
                expected_previous_hash=expected_previous_hash,
                execution_idempotency_key=execution_idempotency_key,
            )
            stage2_committed.set()
            await asyncio.Future()
            raise AssertionError("cancelled stage-two approval unexpectedly resumed")

    control_plane = _CommitThenBlock()
    harness._control_plane = control_plane
    pending = _pending_action(nonce="expected")
    pending.reason = "trace:stage2_upgrade_required"
    pending.preflight_action = None
    _bind_pending_action_identity(pending)
    harness._pending_actions[pending.confirmation_id] = pending
    harness._persist_pending_actions()

    confirmation_task = asyncio.create_task(
        harness.do_action_confirm(
            {"confirmation_id": pending.confirmation_id, "decision_nonce": "expected"}
        )
    )
    await asyncio.wait_for(stage2_committed.wait(), timeout=1.0)
    confirmation_task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await confirmation_task

    assert pending.stage2_correlation_id
    assert control_plane.cancelled_correlations == [pending.stage2_correlation_id]
    assert pending.status in {"failed", "cancelled"}
    assert pending.status_reason
    durable = json.loads((tmp_path / "pending_actions.json").read_text(encoding="utf-8"))[0]
    assert durable["status"] in {"failed", "cancelled"}
    assert durable["status_reason"]
    assert harness.effect_calls == 0


@pytest.mark.asyncio
async def test_f2_stage2_post_commit_rpc_internal_error_cancels_exact_correlation(
    tmp_path: Path,
) -> None:
    harness = _AtomicConfirmationHarness(tmp_path, allow_amendment=True)

    class _CommitThenAuditFailure(_ControlPlaneRecorder):
        def approve_stage2(
            self,
            *,
            action: object,
            approved_by: str,
            correlation_id: str = "",
            expected_previous_hash: str = "",
            execution_idempotency_key: str = "",
        ) -> str:
            super().approve_stage2(
                action=action,
                approved_by=approved_by,
                correlation_id=correlation_id,
                expected_previous_hash=expected_previous_hash,
                execution_idempotency_key=execution_idempotency_key,
            )
            raise ControlPlaneRpcError(
                message="plan audit failed after stage2 commit",
                reason_code="rpc.internal_error",
            )

    control_plane = _CommitThenAuditFailure()
    harness._control_plane = control_plane
    pending = _pending_action(nonce="expected")
    pending.reason = "trace:stage2_upgrade_required"
    pending.preflight_action = None
    _bind_pending_action_identity(pending)
    harness._pending_actions[pending.confirmation_id] = pending
    harness._persist_pending_actions()

    result = await harness.do_action_confirm(
        {"confirmation_id": pending.confirmation_id, "decision_nonce": "expected"}
    )

    assert result["confirmed"] is False
    assert pending.stage2_correlation_id
    assert control_plane.cancelled_correlations == [pending.stage2_correlation_id]
    assert harness.effect_calls == 0


@pytest.mark.asyncio
async def test_f2_stage2_event_publication_failure_cancels_exact_correlation(
    tmp_path: Path,
) -> None:
    harness = _AtomicConfirmationHarness(tmp_path, allow_amendment=True)

    async def _fail_plan_amended(event: object) -> None:
        if isinstance(event, PlanAmended):
            raise OSError("plan amendment audit unavailable")
        harness.published_events.append(event)

    harness._event_bus = SimpleNamespace(publish=_fail_plan_amended)
    pending = _pending_action(nonce="expected")
    pending.reason = "trace:stage2_upgrade_required"
    pending.preflight_action = None
    _bind_pending_action_identity(pending)
    harness._pending_actions[pending.confirmation_id] = pending
    harness._persist_pending_actions()

    with pytest.raises(OSError, match="audit unavailable"):
        await harness.do_action_confirm(
            {"confirmation_id": pending.confirmation_id, "decision_nonce": "expected"}
        )

    assert pending.stage2_correlation_id
    assert harness._control_plane.cancelled_correlations == [pending.stage2_correlation_id]
    assert harness.effect_calls == 0


@pytest.mark.asyncio
async def test_f2_pending_purge_rolls_back_when_deletion_is_not_durable(
    tmp_path: Path,
) -> None:
    harness = _AtomicConfirmationHarness(tmp_path)
    scheduler = _SchedulerRecorder()
    harness._scheduler = scheduler
    pending = _pending_action(nonce="expected")
    pending.created_at = datetime.now(UTC) - timedelta(days=10)
    pending.task_id = "task-f2-purge-terminal"
    _bind_pending_action_identity(pending)
    harness._pending_actions[pending.confirmation_id] = pending
    harness._pending_by_session[pending.session_id] = [pending.confirmation_id]
    harness._persist_pending_actions()
    failures_remaining = 1

    def _fail_purge_write(stage: AtomicWriteStage) -> None:
        nonlocal failures_remaining
        if stage == AtomicWriteStage.FILE_FSYNC and failures_remaining:
            failures_remaining -= 1
            raise OSError("injected pending purge persistence fault")

    harness._pending_state_fault_injector = _fail_purge_write

    with pytest.raises(AtomicWriteError):
        await harness.do_action_purge({"status": "pending", "older_than_days": 7, "limit": 10})

    assert harness._pending_actions[pending.confirmation_id] is pending
    assert harness._pending_by_session[pending.session_id] == [pending.confirmation_id]
    assert pending.status == "pending"
    assert pending.status_reason == ""
    assert pending.decision_nonce == "expected"
    assert scheduler.resolved_confirmations == []
    assert scheduler.run_outcomes == []
    durable = json.loads(harness._pending_actions_file.read_text(encoding="utf-8"))[0]
    assert durable["status"] == "pending"
    assert durable["decision_nonce"] == "expected"


@pytest.mark.asyncio
async def test_f2_pending_purge_postcommit_scheduler_fault_replays_before_deletion(
    tmp_path: Path,
) -> None:
    harness = _AtomicConfirmationHarness(tmp_path)
    scheduler = _SchedulerRecorder()
    scheduler.task = SimpleNamespace(enabled=True)
    scheduler.resolve_failures_remaining = 1
    harness._scheduler = scheduler
    pending = _pending_action(nonce="expected")
    pending.created_at = datetime.now(UTC) - timedelta(days=10)
    pending.task_id = "task-f2-purge-replay"
    _bind_pending_action_identity(pending)
    harness._pending_actions[pending.confirmation_id] = pending
    harness._pending_by_session[pending.session_id] = [pending.confirmation_id]
    harness._persist_pending_actions()

    with pytest.raises(RuntimeError, match="scheduler confirmation publication fault"):
        await harness.do_action_purge({"status": "pending", "older_than_days": 7, "limit": 10})

    durable = json.loads(harness._pending_actions_file.read_text(encoding="utf-8"))[0]
    assert durable["status"] == "failed"
    assert durable["status_reason"] == "purged_stale_pending_action"
    assert durable["scheduler_accounting_pending"] is True
    assert durable["scheduler_accounting_mode"] == "failure"
    assert scheduler.run_outcomes == []

    restarted = _load_pending_actions_harness(
        pending_actions_file=harness._pending_actions_file,
    )
    restarted._scheduler = scheduler
    restarted._load_pending_actions()
    recovered = restarted._pending_actions[pending.confirmation_id]
    assert recovered.scheduler_accounting_pending is False
    assert scheduler.confirmation_outcomes[(pending.task_id, pending.confirmation_id)] is False
    assert len(scheduler.run_outcomes) == 1

    purge_result = await restarted.do_action_purge({"status": "terminal", "limit": 10})
    assert purge_result["confirmation_ids"] == [pending.confirmation_id]
    assert json.loads(harness._pending_actions_file.read_text(encoding="utf-8")) == []


@pytest.mark.asyncio
@pytest.mark.parametrize("retry_status", ["terminal", "superseded", "all"])
async def test_f2_pending_purge_retry_completes_terminal_accounting_before_deletion(
    tmp_path: Path,
    retry_status: str,
) -> None:
    harness = _AtomicConfirmationHarness(tmp_path)
    scheduler = _SchedulerRecorder()
    scheduler.task = SimpleNamespace(enabled=True)
    scheduler.resolve_failures_remaining = 1
    harness._scheduler = scheduler
    pending = _pending_action(nonce="expected")
    pending.created_at = datetime.now(UTC) - timedelta(days=10)
    pending.task_id = "task-f2-purge-same-process-replay"
    _bind_pending_action_identity(pending)
    harness._pending_actions[pending.confirmation_id] = pending
    harness._pending_by_session[pending.session_id] = [pending.confirmation_id]
    harness._persist_pending_actions()

    with pytest.raises(RuntimeError, match="scheduler confirmation publication fault"):
        await harness.do_action_purge({"status": "pending", "older_than_days": 7, "limit": 10})

    assert pending.status == "failed"
    assert pending.scheduler_accounting_pending is True
    retry_params: dict[str, object] = {"status": retry_status, "limit": 10}
    if retry_status == "all":
        retry_params["older_than_days"] = 7
    purge_result = await harness.do_action_purge(retry_params)

    assert purge_result["confirmation_ids"] == [pending.confirmation_id]
    assert scheduler.confirmation_outcomes[(pending.task_id, pending.confirmation_id)] is False
    assert len(scheduler.run_outcomes) == 1
    assert json.loads(harness._pending_actions_file.read_text(encoding="utf-8")) == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    (
        "status",
        "status_reason",
        "accounting_mode",
        "purge_status",
        "cancel_reason",
        "max_runs",
        "success_count",
        "expected_run_outcomes",
        "purge_sibling",
    ),
    [
        (
            "outcome_unknown",
            "uncertain_effect_requires_fresh_approval",
            "ambiguous",
            "outcome_unknown",
            "outcome_unknown",
            0,
            0,
            0,
            False,
        ),
        (
            "approved",
            "recovered_structural_read",
            "failure",
            "executed",
            "max_runs_reached",
            1,
            1,
            1,
            False,
        ),
        (
            "outcome_unknown",
            "uncertain_effect_requires_fresh_approval",
            "ambiguous",
            "all",
            "outcome_unknown",
            0,
            0,
            0,
            True,
        ),
    ],
)
async def test_f2_pending_purge_completes_cancellation_required_accounting(
    tmp_path: Path,
    status: str,
    status_reason: str,
    accounting_mode: str,
    purge_status: str,
    cancel_reason: str,
    max_runs: int,
    success_count: int,
    expected_run_outcomes: int,
    purge_sibling: bool,
) -> None:
    harness = _AtomicConfirmationHarness(tmp_path)
    for method_name in (
        "_record_pending_scheduler_state",
        "_complete_pending_scheduler_accounting",
        "_finalize_pending_scheduler_accounting",
        "_recovery_task_cancel_reason",
    ):
        method = getattr(HandlerImplementation, method_name)
        setattr(harness, method_name, method.__get__(harness, HandlerImplementation))
    scheduler = _SchedulerRecorder()
    scheduler.task = SimpleNamespace(
        enabled=True,
        max_runs=max_runs,
        success_count=success_count,
        recovery_containment_token="",
    )
    harness._scheduler = scheduler
    pending = _pending_action(nonce="")
    pending.task_id = "task-f2-purge-cancellation"
    pending.status = status
    pending.status_reason = status_reason
    pending.scheduler_accounting_pending = True
    pending.scheduler_accounting_mode = accounting_mode
    if purge_status == "all":
        pending.created_at = datetime.now(UTC) - timedelta(days=10)
    _bind_pending_action_identity(pending)
    sibling = _pending_action(nonce="sibling-nonce")
    sibling.confirmation_id = "c-sibling"
    sibling.task_id = pending.task_id
    if purge_status == "all":
        sibling.created_at = datetime.now(UTC) - timedelta(days=10)
    _bind_pending_action_identity(sibling)
    harness._pending_actions = {
        pending.confirmation_id: pending,
        sibling.confirmation_id: sibling,
    }
    harness._pending_by_session[pending.session_id] = [
        pending.confirmation_id,
        sibling.confirmation_id,
    ]
    harness._persist_pending_actions()

    purge_params: dict[str, object] = {"status": purge_status, "limit": 10}
    if purge_status == "all":
        purge_params["older_than_days"] = 7
    purge_result = await asyncio.wait_for(
        harness.do_action_purge(purge_params),
        timeout=2,
    )

    assert purge_result["confirmation_ids"] == (
        [pending.confirmation_id, sibling.confirmation_id]
        if purge_sibling
        else [pending.confirmation_id]
    )
    assert pending.scheduler_accounting_pending is False
    assert sibling.status == "cancelled"
    assert sibling.status_reason == cancel_reason
    assert sibling.decision_nonce == ""
    assert scheduler.task.enabled is False
    assert len(scheduler.run_outcomes) == expected_run_outcomes
    durable_rows = json.loads(harness._pending_actions_file.read_text(encoding="utf-8"))
    assert [row["confirmation_id"] for row in durable_rows] == (
        [] if purge_sibling else [sibling.confirmation_id]
    )


@pytest.mark.asyncio
async def test_f2_pending_purge_deletion_fault_restores_committed_terminal_row(
    tmp_path: Path,
) -> None:
    harness = _AtomicConfirmationHarness(tmp_path)
    scheduler = _SchedulerRecorder()
    scheduler.task = SimpleNamespace(enabled=True)
    harness._scheduler = scheduler
    pending = _pending_action(nonce="expected")
    pending.created_at = datetime.now(UTC) - timedelta(days=10)
    pending.task_id = "task-f2-purge-delete-rollback"
    _bind_pending_action_identity(pending)
    harness._pending_actions[pending.confirmation_id] = pending
    harness._pending_by_session[pending.session_id] = [pending.confirmation_id]
    harness._persist_pending_actions()
    publication = 0

    def _fail_deletion_write(stage: AtomicWriteStage) -> None:
        nonlocal publication
        if stage == AtomicWriteStage.TEMP_OPEN:
            publication += 1
        if publication == 3 and stage == AtomicWriteStage.FILE_FSYNC:
            raise OSError("injected purge deletion persistence fault")

    harness._pending_state_fault_injector = _fail_deletion_write

    with pytest.raises(AtomicWriteError):
        await harness.do_action_purge({"status": "pending", "older_than_days": 7, "limit": 10})

    assert harness._pending_actions[pending.confirmation_id] is pending
    assert pending.status == "failed"
    assert pending.status_reason == "purged_stale_pending_action"
    assert pending.scheduler_accounting_pending is False
    assert scheduler.confirmation_outcomes[(pending.task_id, pending.confirmation_id)] is False
    assert len(scheduler.run_outcomes) == 1
    durable = json.loads(harness._pending_actions_file.read_text(encoding="utf-8"))[0]
    assert durable["status"] == "failed"
    assert durable["scheduler_accounting_pending"] is False

    harness._pending_state_fault_injector = None
    purge_result = await harness.do_action_purge({"status": "terminal", "limit": 10})
    assert purge_result["confirmation_ids"] == [pending.confirmation_id]
    assert json.loads(harness._pending_actions_file.read_text(encoding="utf-8")) == []


@pytest.mark.asyncio
async def test_f2_pending_purge_failed_rollback_surfaces_degradation(
    tmp_path: Path,
) -> None:
    harness = _AtomicConfirmationHarness(tmp_path)
    scheduler = _SchedulerRecorder()
    harness._scheduler = scheduler
    pending = _pending_action(nonce="expected")
    pending.created_at = datetime.now(UTC) - timedelta(days=10)
    pending.task_id = "task-f2-purge-degraded"
    _bind_pending_action_identity(pending)
    harness._pending_actions[pending.confirmation_id] = pending
    harness._pending_by_session[pending.session_id] = [pending.confirmation_id]
    harness._persist_pending_actions()

    def _fail_parent_fsync(stage: AtomicWriteStage) -> None:
        if stage == AtomicWriteStage.PARENT_FSYNC:
            raise OSError("injected purge and rollback parent-fsync fault")

    harness._pending_state_fault_injector = _fail_parent_fsync

    with pytest.raises(AtomicWriteError):
        await harness.do_action_purge({"status": "pending", "older_than_days": 7, "limit": 10})

    assert harness._pending_actions[pending.confirmation_id] is pending
    assert pending.status == "failed"
    assert pending.decision_nonce == ""
    assert pending.scheduler_accounting_pending is True
    assert pending.scheduler_accounting_mode == "failure"
    assert scheduler.resolved_confirmations == []
    assert scheduler.run_outcomes == []
    result = await harness.do_action_pending({"status": "all"})
    assert result["persistence_status"] == "degraded"
    assert result["persistence_transition"] == "terminal"
    assert result["persistence_stage"] == "parent_fsync"
    assert result["persistence_reason"] == "pending_state_rollback_uncommitted"

    with pytest.raises(StatePersistenceDegradedError):
        await harness.do_action_purge({"status": "terminal", "limit": 10})


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "drift",
    [
        "arguments",
        "origin_identity",
        "expiry",
        "fallback",
        "decision_nonce",
        "execute_after_removed",
        "execute_after_shortened",
        "execute_after_naive",
    ],
)
async def test_f2_confirmation_rejects_valid_shape_approval_contract_drift(
    tmp_path: Path,
    drift: str,
) -> None:
    harness = _AtomicConfirmationHarness(tmp_path)
    execute_after = (
        datetime.now(UTC) + timedelta(seconds=30) if drift.startswith("execute_after_") else None
    )
    pending = _pending_action(nonce="expected", execute_after=execute_after)
    if drift == "arguments":
        pending.arguments = {"query": "different query"}
    elif drift == "origin_identity":
        pending.origin_turn_id = "different-origin-turn"
    elif drift == "expiry":
        assert pending.expires_at is not None
        pending.expires_at += timedelta(hours=1)
    elif drift == "fallback":
        pending.fallback = ConfirmationFallbackPolicy(
            mode="allow_levels",
            allow_levels=[ConfirmationLevel.SOFTWARE],
        )
    elif drift == "decision_nonce":
        pending.decision_nonce = "replacement-nonce"
    elif drift == "execute_after_removed":
        pending.execute_after = None
    elif drift == "execute_after_shortened":
        pending.execute_after = datetime.now(UTC) - timedelta(seconds=1)
    elif drift == "execute_after_naive":
        pending.execute_after = datetime.now()
    harness._pending_actions[pending.confirmation_id] = pending
    harness._persist_pending_actions()

    result = await harness.do_action_confirm(
        {
            "confirmation_id": pending.confirmation_id,
            "decision_nonce": ("replacement-nonce" if drift == "decision_nonce" else "expected"),
        }
    )

    assert result["confirmed"] is False
    assert result["reason"] == "approval_contract_mismatch"
    assert pending.status == "failed"
    assert pending.decision_nonce == ""
    assert harness.effect_calls == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("tamper", ["backend_id", "evidence_hash"])
async def test_f2_confirmation_rejects_noncanonical_backend_evidence(
    tmp_path: Path,
    tamper: str,
) -> None:
    harness = _AtomicConfirmationHarness(tmp_path)

    class _SelfAssertingBackend(SoftwareConfirmationBackend):
        def __init__(self) -> None:
            super().__init__()
            self.backend_id = "self-asserting.default"

        def verify(
            self,
            *,
            pending_action: object,
            params: dict[str, object],
            now: datetime | None = None,
        ) -> ConfirmationEvidence:
            evidence = super().verify(
                pending_action=pending_action,
                params=params,
                now=now,
            )
            return evidence.model_copy(
                update=(
                    {"backend_id": "fabricated.backend"}
                    if tamper == "backend_id"
                    else {"evidence_hash": "sha256:" + ("0" * 64)}
                )
            )

    harness._confirmation_backend_registry.register(_SelfAssertingBackend())
    pending = _pending_action(nonce="expected")
    pending.selected_backend_id = "self-asserting.default"
    _bind_pending_action_identity(pending)
    harness._pending_actions[pending.confirmation_id] = pending

    result = await harness.do_action_confirm(
        {"confirmation_id": pending.confirmation_id, "decision_nonce": "expected"}
    )

    assert result["confirmed"] is False
    assert result["reason"] == "approval_contract_mismatch"
    assert pending.confirmation_evidence is None
    assert harness.effect_calls == 0


@pytest.mark.parametrize(
    "proof_backend",
    ["totp", "webauthn", "local_fido2", "signer"],
)
def test_f2_real_proof_backends_reject_coherent_fabricated_evidence(
    tmp_path: Path,
    proof_backend: str,
) -> None:
    harness = _ConfirmationImplHarness(tmp_path)
    pending: PendingAction
    extra_payload: dict[str, object] = {}
    evidence_updates: dict[str, object] = {}
    if proof_backend == "totp":
        factor = _register_totp_factor(harness)
        pending = _totp_pending_action(nonce="expected", required_methods=["totp"])
        backend = harness._confirmation_backend_registry.get_backend("totp.default")
        assert isinstance(backend, TOTPBackend)
    else:
        factor = ApprovalFactorRecord(
            credential_id=f"{proof_backend}-credential",
            user_id="alice",
            method="local_fido2" if proof_backend == "local_fido2" else "webauthn",
            principal_id=f"{proof_backend}-principal",
            webauthn_rp_id="",
        )
        if proof_backend == "webauthn":
            backend = WebAuthnBackend(
                credential_store=harness._credential_store,
                approval_origin="https://approver.example.test",
                rp_id="approver.example.test",
            )
        elif proof_backend == "local_fido2":
            backend = LocalFido2Backend(
                credential_store=harness._credential_store,
                daemon_id="daemon-1",
            )
        else:
            private_key = generate_secp256k1_private_key()
            harness._credential_store.register_signer_key(
                SignerKeyRecord(
                    credential_id="kms-key-1",
                    user_id="alice",
                    backend="kms",
                    principal_id="kms-principal",
                    algorithm="ecdsa-secp256k1",
                    device_type="kms",
                    public_key_pem=public_key_pem(private_key),
                )
            )
            backend = SignerConfirmationAdapter(
                EnterpriseKmsSignerBackend(
                    credential_store=harness._credential_store,
                    endpoint_url="https://kms.example.test/sign",
                )
            )
            factor = SimpleNamespace(
                credential_id="kms-key-1",
                principal_id="kms-principal",
            )
        harness._confirmation_backend_registry.register(backend)
        pending = _webauthn_pending_action(nonce="expected")
        pending.delivery_target = None
        pending.allowed_channel_principals = []
        pending.allowed_principals = []
        pending.allowed_credentials = []
        pending.selected_backend_id = backend.backend_id
        pending.selected_backend_method = backend.method
        pending.required_level = backend.level
        pending.required_methods = [backend.method]
        pending.required_capabilities = ConfirmationCapabilities()
        if proof_backend == "signer":
            pending.intent_envelope = IntentEnvelope(
                intent_id=pending.action_id,
                agent_id="daemon-1",
                workspace_id=str(pending.workspace_id),
                session_id=str(pending.session_id),
                created_at=pending.created_at,
                expires_at=pending.expires_at,
                action=IntentAction(
                    tool=str(pending.tool_name),
                    display_summary="fabricated signer evidence",
                    parameters=dict(pending.arguments),
                    destinations=[],
                ),
                policy_context=IntentPolicyContext(
                    required_level=backend.level,
                    confirmation_reason=pending.reason,
                    action_digest=pending.action_digest,
                ),
                nonce="signer-intent-nonce",
            )
            assert pending.approval_envelope is not None
            pending.approval_envelope = pending.approval_envelope.model_copy(
                update={"intent_envelope_hash": intent_envelope_hash(pending.intent_envelope)}
            )
        elif isinstance(backend, WebAuthnBackend):
            factor.webauthn_rp_id = backend.rp_id
            harness._credential_store.register_approval_factor(factor)
            extra_payload = {
                "rp_id": backend.rp_id,
                "origin": backend.approval_origin,
                "sign_count": 0,
            }
        _bind_pending_action_identity(pending)

    payload: dict[str, object] = {
        "schema_version": "shisad.confirmation_evidence.v1",
        "backend_id": backend.backend_id,
        "method": backend.method,
        "confirmation_id": pending.confirmation_id,
        "decision_nonce": pending.decision_nonce,
        "approval_envelope_hash": pending.approval_envelope_hash,
        "action_digest": pending.action_digest,
        "approver_principal_id": factor.principal_id,
        "credential_id": factor.credential_id,
        "fallback_used": pending.fallback_used,
        **extra_payload,
    }
    if proof_backend == "signer":
        assert pending.intent_envelope is not None
        payload.update(
            {
                "intent_envelope_hash": intent_envelope_hash(pending.intent_envelope),
                "signature": "",
                "signer_key_id": "",
                "review_surface": backend.review_surface.value,
                "blind_sign_detected": False,
            }
        )
        evidence_updates = {
            "intent_envelope_hash": payload["intent_envelope_hash"],
        }
    evidence = ConfirmationEvidence(
        level=backend.level,
        method=backend.method,
        backend_id=backend.backend_id,
        approver_principal_id=factor.principal_id,
        credential_id=factor.credential_id,
        binding_scope=backend.binding_scope,
        review_surface=backend.review_surface,
        third_party_verifiable=backend.third_party_verifiable,
        approval_envelope_hash=pending.approval_envelope_hash,
        action_digest=pending.action_digest,
        decision_nonce=pending.decision_nonce,
        fallback_used=pending.fallback_used,
        evidence_payload=payload,
        evidence_hash=canonical_sha256(payload),
        **evidence_updates,
    )
    pending.confirmation_evidence = evidence

    assert (
        harness._pending_approval_contract_invalid_reason(
            pending,
            require_evidence=True,
        )
        == "approval_contract_mismatch"
    )


@pytest.mark.asyncio
async def test_f2_live_totp_backend_cannot_self_assert_unverified_evidence(
    tmp_path: Path,
) -> None:
    harness = _ConfirmationImplHarness(tmp_path)
    factor = _register_totp_factor(harness)

    class _FabricatingTotpBackend(TOTPBackend):
        def verify(
            self,
            *,
            pending_action: object,
            params: dict[str, object],
            now: datetime | None = None,
        ) -> ConfirmationEvidence:
            _ = params, now
            payload = {
                "schema_version": "shisad.confirmation_evidence.v1",
                "backend_id": self.backend_id,
                "method": self.method,
                "confirmation_id": str(getattr(pending_action, "confirmation_id", "")),
                "decision_nonce": str(getattr(pending_action, "decision_nonce", "")),
                "approval_envelope_hash": str(
                    getattr(pending_action, "approval_envelope_hash", "")
                ),
                "action_digest": str(getattr(pending_action, "action_digest", "")),
                "approver_principal_id": factor.principal_id,
                "channel_principal_id": "",
                "credential_id": factor.credential_id,
                "fallback_used": False,
            }
            return ConfirmationEvidence(
                level=self.level,
                method=self.method,
                backend_id=self.backend_id,
                approver_principal_id=factor.principal_id,
                credential_id=factor.credential_id,
                binding_scope=self.binding_scope,
                review_surface=self.review_surface,
                third_party_verifiable=self.third_party_verifiable,
                approval_envelope_hash=str(payload["approval_envelope_hash"]),
                action_digest=str(payload["action_digest"]),
                decision_nonce=str(payload["decision_nonce"]),
                evidence_payload=payload,
                evidence_hash=canonical_sha256(payload),
            )

    harness._confirmation_backend_registry.register(
        _FabricatingTotpBackend(credential_store=harness._credential_store)
    )
    pending = _totp_pending_action(nonce="expected", required_methods=["totp"])
    harness._pending_actions[pending.confirmation_id] = pending

    result = await harness.do_action_confirm(
        {"confirmation_id": pending.confirmation_id, "decision_nonce": "expected"}
    )

    assert result["confirmed"] is False
    assert result["reason"] == "approval_contract_mismatch"
    assert pending.confirmation_evidence is None
    assert harness.execution_kwargs == []


@pytest.mark.asyncio
async def test_f2_live_webauthn_migrates_legacy_blank_rp_id_after_verification(
    tmp_path: Path,
) -> None:
    harness = _ConfirmationImplHarness(tmp_path)
    backend = WebAuthnBackend(
        credential_store=harness._credential_store,
        approval_origin="https://approve.example.test",
        rp_id="approve.example.test",
    )
    harness._confirmation_backend_registry.register(backend)
    registration_options, registration_state = backend.registration_begin(
        user_id="alice",
        principal_id="ops-phone",
        credential_id="webauthn-legacy",
    )
    credential, registration_payload = make_registration_payload(
        public_key_options=registration_options,
        origin=backend.approval_origin,
        rp_id=backend.rp_id,
    )
    factor = backend.registration_complete(
        credential_id="webauthn-legacy",
        user_id="alice",
        principal_id="ops-phone",
        created_at=datetime.now(UTC),
        state=registration_state,
        response_payload=registration_payload,
    ).model_copy(update={"webauthn_rp_id": ""})
    harness._credential_store.register_approval_factor(factor)
    pending = _webauthn_pending_action(nonce="expected")
    pending.delivery_target = None
    pending.allowed_channel_principals = []
    pending.allowed_principals = [factor.principal_id]
    pending.allowed_credentials = [factor.credential_id]
    _bind_pending_action_identity(pending)
    harness._pending_actions[pending.confirmation_id] = pending
    assertion = make_authentication_payload(
        public_key_options=backend.approval_request_options(pending_action=pending),
        credential=credential,
    )

    result = await harness.do_action_confirm(
        {
            "confirmation_id": pending.confirmation_id,
            "decision_nonce": pending.decision_nonce,
            "approval_method": "webauthn",
            "credential_id": factor.credential_id,
            "proof": assertion,
        }
    )

    assert result["confirmed"] is True
    migrated = harness._credential_store.get_approval_factor(factor.credential_id)
    assert migrated is not None
    assert migrated.webauthn_rp_id == backend.rp_id


@pytest.mark.parametrize("proof_backend", ["software", "totp", "webauthn", "signer"])
def test_f2_approval_contract_validator_is_shared_across_proof_backends(
    tmp_path: Path,
    proof_backend: str,
) -> None:
    harness = _ConfirmationImplHarness(tmp_path)
    if proof_backend == "totp":
        _register_totp_factor(harness)
        pending = _totp_pending_action(nonce="expected", required_methods=["totp"])
    elif proof_backend == "webauthn":
        harness._confirmation_backend_registry.register(_AvailableWebAuthnRouteBackend())
        pending = _webauthn_pending_action(nonce="expected")
    else:
        pending = _pending_action(nonce="expected")
        if proof_backend == "signer":

            class _AvailableSignerBackend:
                backend_id = "kms.test"
                method = "kms"
                level = ConfirmationLevel.SIGNED_AUTHORIZATION
                capabilities = ConfirmationCapabilities()
                third_party_verifiable = True

                def is_available_for(self, *, user_id: str) -> bool:
                    _ = user_id
                    return True

                def principals_for_user(self, *, user_id: str) -> set[str]:
                    _ = user_id
                    return set()

                def credentials_for_user(self, *, user_id: str) -> set[str]:
                    _ = user_id
                    return set()

            harness._confirmation_backend_registry.register(_AvailableSignerBackend())
            pending.required_level = ConfirmationLevel.SIGNED_AUTHORIZATION
            pending.required_methods = ["kms"]
            pending.selected_backend_id = "kms.test"
            pending.selected_backend_method = "kms"
            _bind_pending_action_identity(pending)

    pending.arguments = {"query": "different query"}

    assert (
        harness._pending_approval_contract_invalid_reason(pending) == "approval_contract_mismatch"
    )


@pytest.mark.parametrize("status_reason", ["task_disabled", "max_runs_reached"])
def test_f1_cancelled_pending_action_keeps_empty_nonce_after_restart(
    tmp_path: Path,
    status_reason: str,
) -> None:
    pending = _pending_action(nonce="")
    pending.status = "cancelled"
    pending.status_reason = status_reason
    pending.task_id = "task-1"
    _bind_pending_action_identity(pending)
    pending_actions_file = tmp_path / "pending_actions.json"
    harness = _load_pending_actions_harness(
        pending_actions_file=pending_actions_file,
    )
    harness._pending_actions[pending.confirmation_id] = pending
    harness._pending_by_session[pending.session_id] = [pending.confirmation_id]
    harness._persist_pending_actions()
    persisted = json.loads(pending_actions_file.read_text(encoding="utf-8"))[0]
    assert persisted["result_id"]
    assert persisted["recovery_authority_mac"].startswith("hmac-sha256:")
    harness = _load_pending_actions_harness(
        pending_actions_file=pending_actions_file,
    )
    harness._load_pending_actions()

    loaded = harness._pending_actions[pending.confirmation_id]
    assert loaded.status == "cancelled"
    assert loaded.status_reason == (
        "legacy_scheduler_accounting_intent_unknown"
        if status_reason == "task_disabled"
        else status_reason
    )
    assert loaded.scheduler_accounting_mode == (
        "ambiguous" if status_reason == "task_disabled" else "shadow_only"
    )
    assert loaded.decision_nonce == ""
    assert loaded.recovery_accounting_pending is False


def test_f2_expired_pending_persist_does_not_mint_terminal_recovery_authority(
    tmp_path: Path,
) -> None:
    pending = _pending_action(nonce="expected")
    now = datetime.now(UTC)
    pending.created_at = now - timedelta(hours=2)
    pending.expires_at = now - timedelta(hours=1)
    pending.task_id = "task-expired"
    _bind_pending_action_identity(pending)
    pending_actions_file = tmp_path / "pending_actions.json"
    harness = _load_pending_actions_harness(
        pending_actions_file=pending_actions_file,
    )
    harness._pending_actions[pending.confirmation_id] = pending
    harness._pending_by_session[pending.session_id] = [pending.confirmation_id]

    harness._persist_pending_actions()

    persisted = json.loads(pending_actions_file.read_text(encoding="utf-8"))[0]
    assert persisted["status"] == "pending"
    assert persisted["result_id"] == ""
    assert persisted["recovery_authority_mac"] == ""
    harness._pending_actions = {}
    harness._pending_by_session = {}
    harness._load_pending_actions()
    loaded = harness._pending_actions[pending.confirmation_id]
    assert loaded.status == "failed"
    assert loaded.status_reason == "approval_expired"
    assert loaded.recovery_accounting_pending is False


@pytest.mark.parametrize(
    "authority_marker",
    [
        "recovery_started_at",
        "execution_attempt_id",
        "result_id",
        "approval_evidence_hash",
        "provider_operation_id",
        "stage2_correlation_id",
        "stage2_previous_plan_hash",
        "stage2_plan_hash",
        "recovery_authority_mac",
    ],
)
def test_f2_sanitized_raw_recovery_marker_cannot_restore_live_pending(
    tmp_path: Path,
    authority_marker: str,
) -> None:
    pending = _pending_action(nonce="expected")
    payload = HandlerImplementation._pending_to_dict(pending)
    payload[authority_marker] = "\ud800"
    if authority_marker in {"execution_attempt_id", "result_id"}:
        payload["identity"][authority_marker] = "\ud800"
    pending_actions_file = tmp_path / "pending_actions.json"
    pending_actions_file.write_text(json.dumps([payload]), encoding="utf-8")
    harness = _load_pending_actions_harness(
        pending_actions_file=pending_actions_file,
    )

    harness._load_pending_actions()

    loaded = harness._pending_actions[pending.confirmation_id]
    assert loaded.status == "outcome_unknown"
    assert loaded.status_reason == "uncertain_effect_requires_fresh_approval"
    assert loaded.decision_nonce == ""
    assert loaded.recovery_accounting_pending is False
    persisted = json.loads(pending_actions_file.read_text(encoding="utf-8"))[0]
    assert persisted["recovery_authority_mac"].startswith("hmac-sha256:")
    harness = _load_pending_actions_harness(
        pending_actions_file=pending_actions_file,
    )
    harness._load_pending_actions()

    replayed = harness._pending_actions[pending.confirmation_id]
    assert replayed.status == "outcome_unknown"
    assert replayed.decision_nonce == ""
    assert replayed.recovery_accounting_pending is False


def test_f2_current_contract_blank_nonce_fails_closed(tmp_path: Path) -> None:
    pending = _pending_action(nonce="")
    payload = HandlerImplementation._pending_to_dict(pending)
    pending_actions_file = tmp_path / "pending_actions.json"
    pending_actions_file.write_text(json.dumps([payload]), encoding="utf-8")
    harness = _load_pending_actions_harness(
        pending_actions_file=pending_actions_file,
    )

    harness._load_pending_actions()

    loaded = harness._pending_actions[pending.confirmation_id]
    assert loaded.status == "failed"
    assert loaded.status_reason == "approval_contract_mismatch"
    assert loaded.decision_nonce == ""
    persisted = json.loads(pending_actions_file.read_text(encoding="utf-8"))[0]
    assert persisted["status"] == "failed"
    assert persisted["decision_nonce"] == ""


def test_f2_parent_contract_blank_nonce_migration_is_verified_and_rebound(
    tmp_path: Path,
) -> None:
    pending = _pending_action(nonce="")
    assert pending.approval_envelope is not None
    legacy_contract = pending_approval_contract_payload(pending)
    identity = legacy_contract["identity"]
    assert isinstance(identity, dict)
    del identity["decision_nonce"]
    legacy_contract_hash = canonical_sha256(legacy_contract)
    pending.approval_envelope = pending.approval_envelope.model_copy(
        update={"approval_contract_hash": legacy_contract_hash}
    )
    pending.approval_envelope_hash = approval_envelope_hash(pending.approval_envelope)
    payload = HandlerImplementation._pending_to_dict(pending)
    pending_actions_file = tmp_path / "pending_actions.json"
    pending_actions_file.write_text(json.dumps([payload]), encoding="utf-8")
    harness = _load_pending_actions_harness(
        pending_actions_file=pending_actions_file,
    )

    harness._load_pending_actions()

    loaded = harness._pending_actions[pending.confirmation_id]
    assert loaded.status == "pending"
    assert loaded.decision_nonce
    assert loaded.approval_envelope is not None
    assert loaded.approval_envelope.approval_contract_hash == pending_approval_contract_hash(loaded)
    assert loaded.approval_envelope_hash == approval_envelope_hash(loaded.approval_envelope)
    persisted = json.loads(pending_actions_file.read_text(encoding="utf-8"))[0]
    assert persisted["decision_nonce"] == loaded.decision_nonce
    assert persisted["approval_envelope_hash"] == loaded.approval_envelope_hash


@pytest.mark.parametrize(
    "malformed_surface",
    ["contract", "envelope", "arguments_text", "arguments_non_finite"],
)
def test_f2_parent_contract_malformed_text_fails_closed(
    tmp_path: Path,
    malformed_surface: str,
) -> None:
    pending = _pending_action(nonce="")
    payload = HandlerImplementation._pending_to_dict(pending)
    if malformed_surface == "contract":
        payload["safe_preview"] = "\ud800"
    elif malformed_surface == "envelope":
        envelope = payload["approval_envelope"]
        assert isinstance(envelope, dict)
        envelope["policy_reason"] = "\ud800"
    elif malformed_surface == "arguments_text":
        payload["arguments"] = {"query": "\ud800"}
    else:
        payload["arguments"] = {"query": float("nan")}
    pending_actions_file = tmp_path / "pending_actions.json"
    pending_actions_file.write_text(json.dumps([payload]), encoding="utf-8")
    harness = _load_pending_actions_harness(
        pending_actions_file=pending_actions_file,
    )

    harness._load_pending_actions()

    if malformed_surface == "arguments_non_finite":
        assert harness._pending_actions == {}
        assert harness._pending_state_degradation == {
            "transition": "load",
            "stage": "corrupt",
            "reason": "pending_state_corrupt",
        }
        assert len(list(tmp_path.glob("pending_actions.json.corrupt.*"))) == 1
        return
    loaded = harness._pending_actions[pending.confirmation_id]
    assert loaded.status == "failed"
    assert loaded.status_reason == "approval_contract_mismatch"
    assert loaded.decision_nonce == ""


@pytest.mark.parametrize("decision_nonce", ["expected", ""])
def test_f2_pending_attempt_identity_recovers_as_outcome_unknown(
    tmp_path: Path,
    decision_nonce: str,
) -> None:
    pending = _pending_action(nonce=decision_nonce)
    pending.execution_attempt_id = "attempt-already-started"
    pending.result_id = "result-already-reserved"
    payload = HandlerImplementation._pending_to_dict(pending)
    pending_actions_file = tmp_path / "pending_actions.json"
    pending_actions_file.write_text(json.dumps([payload]), encoding="utf-8")
    harness = _load_pending_actions_harness(
        pending_actions_file=pending_actions_file,
    )

    harness._load_pending_actions()

    loaded = harness._pending_actions[pending.confirmation_id]
    assert loaded.status == "outcome_unknown"
    assert loaded.status_reason == "uncertain_effect_requires_fresh_approval"
    assert loaded.decision_nonce == ""
    persisted = json.loads(pending_actions_file.read_text(encoding="utf-8"))[0]
    assert persisted["status"] == "outcome_unknown"
    assert persisted["decision_nonce"] == ""


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("retry_generation", "not-an-integer"),
        ("retry_generation", -1),
        ("retry_generation", float("inf")),
        ("retry_generation", False),
        ("recovery_started_at", "not-a-timestamp"),
    ],
)
def test_f2_pending_erased_recovery_authority_recovers_as_outcome_unknown(
    tmp_path: Path,
    field: str,
    value: object,
) -> None:
    pending = _pending_action(nonce="expected")
    payload = HandlerImplementation._pending_to_dict(pending)
    payload[field] = value
    pending_actions_file = tmp_path / "pending_actions.json"
    pending_actions_file.write_text(json.dumps([payload]), encoding="utf-8")
    harness = _load_pending_actions_harness(
        pending_actions_file=pending_actions_file,
    )

    harness._load_pending_actions()

    if field == "retry_generation" and value == float("inf"):
        assert harness._pending_actions == {}
        assert harness._pending_state_degradation == {
            "transition": "load",
            "stage": "corrupt",
            "reason": "pending_state_corrupt",
        }
        assert len(list(tmp_path.glob("pending_actions.json.corrupt.*"))) == 1
        return
    loaded = harness._pending_actions[pending.confirmation_id]
    assert loaded.status == "outcome_unknown"
    assert loaded.status_reason == "uncertain_effect_requires_fresh_approval"
    assert loaded.decision_nonce == ""


@pytest.mark.parametrize("drift", ["removed", "shortened", "naive"])
def test_f2_load_terminalizes_execute_after_contract_drift(
    tmp_path: Path,
    drift: str,
) -> None:
    pending = _pending_action(
        nonce="expected",
        execute_after=datetime.now(UTC) + timedelta(seconds=30),
    )
    payload = HandlerImplementation._pending_to_dict(pending)
    if drift == "removed":
        payload["execute_after"] = ""
    elif drift == "shortened":
        payload["execute_after"] = (pending.created_at + timedelta(seconds=1)).isoformat()
    else:
        assert pending.execute_after is not None
        payload["execute_after"] = pending.execute_after.replace(tzinfo=None).isoformat()
    pending_actions_file = tmp_path / "pending_actions.json"
    pending_actions_file.write_text(json.dumps([payload]), encoding="utf-8")
    harness = _load_pending_actions_harness(
        pending_actions_file=pending_actions_file,
    )

    harness._load_pending_actions()

    loaded = harness._pending_actions[pending.confirmation_id]
    assert loaded.status == "failed"
    assert loaded.status_reason == "approval_contract_mismatch"
    assert loaded.decision_nonce == ""


def test_f1_legacy_confirmation_alias_migrates_to_distinct_action_identity(
    tmp_path: Path,
) -> None:
    pending = _pending_action(nonce="expected")
    payload = HandlerImplementation._pending_to_dict(pending)
    payload.pop("record_schema_version")
    payload["action_id"] = pending.confirmation_id
    for key in (
        "identity",
        "origin_turn_id",
        "execution_attempt_id",
        "result_id",
        "followup_id",
        "lifecycle_state",
    ):
        payload.pop(key, None)
    pending_actions_file = tmp_path / "pending_actions.json"
    pending_actions_file.write_text(json.dumps([payload]), encoding="utf-8")
    harness = _load_pending_actions_harness(
        pending_actions_file=pending_actions_file,
    )

    harness._load_pending_actions()

    loaded = harness._pending_actions[pending.confirmation_id]
    assert loaded.action_id.startswith("act-")
    assert loaded.action_id != pending.confirmation_id
    assert loaded.followup_id.startswith("followup-")
    persisted = json.loads(pending_actions_file.read_text(encoding="utf-8"))[0]
    assert persisted["action_id"] == loaded.action_id
    assert persisted["identity"]["action_id"] == loaded.action_id
    assert persisted["followup_id"] == loaded.followup_id


@pytest.mark.asyncio
async def test_a1_action_pending_fails_closed_when_selected_backend_disappears(
    tmp_path: Path,
) -> None:
    harness = _QueuePendingHarness(tmp_path)
    _register_totp_factor(harness)  # type: ignore[arg-type]

    pending = harness._queue_pending_action(
        session_id=SessionId("s-a1"),
        user_id=UserId("alice"),
        workspace_id=WorkspaceId("w-1"),
        tool_name=ToolName("web.fetch"),
        arguments={"url": "https://example.test/page"},
        reason="requires_confirmation",
        capabilities={Capability.HTTP_REQUEST},
        delivery_target=DeliveryTarget(channel="discord", recipient="chan-1"),
        confirmation_requirement=ConfirmationRequirement(level=ConfirmationLevel.SOFTWARE),
    )
    assert pending.selected_backend_id == "totp.default"

    harness._confirmation_backend_registry._backends.pop("totp.default")

    result = await harness.do_action_pending({"confirmation_id": pending.confirmation_id})

    assert result["count"] == 1
    entry = ActionPendingEntry.model_validate(result["actions"][0])
    capability = entry.channel_capability
    assert capability["backend_available"] is False
    assert capability["can_approve"] is False
    assert capability["can_collect_selected_method"] is False
    assert capability["can_carry"] is False
    assert capability["can_carry_required_proof_tier"] is False
    assert capability["cannot_carry_reason"] == "confirmation_backend_unavailable"


@pytest.mark.asyncio
async def test_a1_action_pending_suppresses_webauthn_link_when_backend_unavailable(
    tmp_path: Path,
) -> None:
    harness = _QueuePendingHarness(tmp_path)
    approval_web = _ApprovalWebRecorder()
    harness._approval_web = approval_web
    pending = _webauthn_pending_action(nonce="expected")
    harness._pending_actions[pending.confirmation_id] = pending

    result = await harness.do_action_pending({"confirmation_id": pending.confirmation_id})

    assert result["count"] == 1
    action = result["actions"][0]
    entry = ActionPendingEntry.model_validate(action)
    capability = entry.channel_capability
    assert capability["backend_available"] is False
    assert capability["can_approve"] is False
    assert capability["can_collect_selected_method"] is False
    assert capability["can_carry"] is False
    assert capability["cannot_carry_reason"] == "confirmation_backend_unavailable"
    assert "approval_url" not in action
    assert "approval_qr_ascii" not in action
    assert approval_web.issued == []


@pytest.mark.asyncio
async def test_a1_chat_notifications_skip_webauthn_link_when_backend_unavailable(
    tmp_path: Path,
) -> None:
    harness = _QueuePendingHarness(tmp_path)
    approval_web = _ApprovalWebRecorder()
    delivery = _DeliveryRecorder()
    harness._approval_web = approval_web
    harness._delivery = delivery
    pending = _webauthn_pending_action(nonce="expected")
    harness._pending_actions[pending.confirmation_id] = pending

    await harness._send_chat_approval_link_notifications(
        confirmation_ids=[pending.confirmation_id],
        delivery_target=DeliveryTarget(channel="discord", recipient="chan-1"),
    )

    assert approval_web.issued == []
    assert delivery.messages == []
    assert delivery.intents == []


@pytest.mark.asyncio
async def test_f7b_chat_approval_notification_resolves_ephemeral_capability(
    tmp_path: Path,
) -> None:
    harness = _QueuePendingHarness(tmp_path)
    approval_web = _ApprovalWebRecorder()
    delivery = _DeliveryRecorder()
    harness._approval_web = approval_web
    harness._delivery = delivery
    harness._confirmation_backend_registry.register(_AvailableWebAuthnRouteBackend())
    pending = _webauthn_pending_action(nonce="expected")
    harness._pending_actions[pending.confirmation_id] = pending
    target = DeliveryTarget(channel="discord", recipient="chan-1")

    await harness._send_chat_approval_link_notifications(
        confirmation_ids=[pending.confirmation_id],
        delivery_target=target,
    )

    assert approval_web.issued == [pending.confirmation_id]
    assert len(delivery.messages) == 1
    delivered = delivery.messages[0]
    intent = delivered["intent"]
    assert isinstance(intent, CapabilityDeliveryIntent)
    assert intent.confirmation_id == pending.confirmation_id
    assert intent.target == target
    assert "https://approvals.test/c-webauthn" in str(delivered["message"])
    assert "https://" not in repr(intent)


@pytest.mark.asyncio
async def test_f7b_chat_approval_capability_rejects_cross_target_resolution(
    tmp_path: Path,
) -> None:
    harness = _QueuePendingHarness(tmp_path)
    approval_web = _ApprovalWebRecorder()
    delivery = _DeliveryRecorder()
    harness._approval_web = approval_web
    harness._delivery = delivery
    harness._confirmation_backend_registry.register(_AvailableWebAuthnRouteBackend())
    pending = _webauthn_pending_action(nonce="expected")
    harness._pending_actions[pending.confirmation_id] = pending

    await harness._send_chat_approval_link_notifications(
        confirmation_ids=[pending.confirmation_id],
        delivery_target=DeliveryTarget(channel="discord", recipient="other-room"),
    )
    recovered = await harness._resolve_chat_approval_capability(
        CapabilityDeliveryIntent(
            confirmation_id=pending.confirmation_id,
            target=DeliveryTarget(channel="discord", recipient="other-room"),
            expires_at=pending.expires_at,
        ),
        rotate=True,
    )

    assert recovered is None
    assert approval_web.issued == []
    assert delivery.messages == []


@pytest.mark.asyncio
async def test_a1_webauthn_ceremony_context_fails_closed_when_backend_unavailable(
    tmp_path: Path,
) -> None:
    harness = _QueuePendingHarness(tmp_path)
    pending = _webauthn_pending_action(nonce="expected")
    harness._pending_actions[pending.confirmation_id] = pending

    result = await harness._webauthn_approval_ceremony_context(pending.confirmation_id)

    assert result["ok"] is False
    assert result["status"] == "unavailable"
    assert result["reason"] == "confirmation_backend_unavailable"


@pytest.mark.asyncio
async def test_a1_action_pending_backend_availability_respects_pending_principal(
    tmp_path: Path,
) -> None:
    harness = _QueuePendingHarness(tmp_path)
    _register_totp_factor(harness)  # type: ignore[arg-type]
    pending = _totp_pending_action(nonce="expected", required_methods=["totp"])
    pending.required_level = ConfirmationLevel.SOFTWARE
    pending.allowed_principals = ["removed-laptop"]
    harness._pending_actions[pending.confirmation_id] = pending

    result = await harness.do_action_pending({"confirmation_id": pending.confirmation_id})

    assert result["count"] == 1
    entry = ActionPendingEntry.model_validate(result["actions"][0])
    capability = entry.channel_capability
    assert capability["backend_available"] is False
    assert capability["can_approve"] is False
    assert capability["cannot_carry_reason"] == "confirmation_backend_unavailable"


@pytest.mark.asyncio
async def test_a1_action_pending_backend_availability_respects_pending_credential(
    tmp_path: Path,
) -> None:
    harness = _QueuePendingHarness(tmp_path)
    _register_totp_factor(harness)  # type: ignore[arg-type]
    pending = _totp_pending_action(nonce="expected", required_methods=["totp"])
    pending.required_level = ConfirmationLevel.SOFTWARE
    pending.allowed_credentials = ["removed-credential"]
    harness._pending_actions[pending.confirmation_id] = pending

    result = await harness.do_action_pending({"confirmation_id": pending.confirmation_id})

    assert result["count"] == 1
    entry = ActionPendingEntry.model_validate(result["actions"][0])
    capability = entry.channel_capability
    assert capability["backend_available"] is False
    assert capability["can_approve"] is False
    assert capability["cannot_carry_reason"] == "confirmation_backend_unavailable"


@pytest.mark.asyncio
async def test_a1_action_pending_backend_availability_requires_same_factor(
    tmp_path: Path,
) -> None:
    harness = _QueuePendingHarness(tmp_path)
    _register_totp_factor(harness)  # type: ignore[arg-type]
    harness._credential_store.register_approval_factor(
        ApprovalFactorRecord(
            credential_id="totp-2",
            user_id="alice",
            method="totp",
            principal_id="backup-laptop",
            secret_b32="GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
        )
    )
    pending = _totp_pending_action(nonce="expected", required_methods=["totp"])
    pending.required_level = ConfirmationLevel.SOFTWARE
    pending.allowed_principals = ["ops-laptop"]
    pending.allowed_credentials = ["totp-2"]
    harness._pending_actions[pending.confirmation_id] = pending

    result = await harness.do_action_pending({"confirmation_id": pending.confirmation_id})

    assert result["count"] == 1
    entry = ActionPendingEntry.model_validate(result["actions"][0])
    capability = entry.channel_capability
    assert capability["backend_available"] is False
    assert capability["can_approve"] is False
    assert capability["cannot_carry_reason"] == "confirmation_backend_unavailable"


@pytest.mark.asyncio
async def test_a1_action_pending_suppresses_webauthn_link_when_expired(
    tmp_path: Path,
) -> None:
    harness = _QueuePendingHarness(tmp_path)
    approval_web = _ApprovalWebRecorder()
    harness._approval_web = approval_web
    harness._confirmation_backend_registry.register(_AvailableWebAuthnRouteBackend())
    pending = _webauthn_pending_action(nonce="expected")
    pending.expires_at = datetime.now(UTC) - timedelta(seconds=1)
    harness._pending_actions[pending.confirmation_id] = pending

    result = await harness.do_action_pending({"confirmation_id": pending.confirmation_id})

    assert result["count"] == 1
    action = result["actions"][0]
    assert action["age_seconds"] >= 0
    assert action["created_at"]
    assert action["expires_at"]
    assert action["origin_turn_id"] == pending.origin_turn_id
    assert action["decision_nonce"] == ""
    entry = ActionPendingEntry.model_validate(action)
    assert entry.lifecycle_state == "expired"
    assert entry.status_reason == "approval_expired"
    capability = entry.channel_capability
    assert capability["backend_available"] is True
    assert capability["can_approve"] is False
    assert capability["can_collect_selected_method"] is False
    assert capability["can_carry"] is False
    assert capability["cannot_carry_reason"] == "approval_expired"
    assert "approval_url" not in action
    assert "approval_qr_ascii" not in action
    assert approval_web.issued == []

    live_pending = await harness.do_action_pending({"status": "pending"})
    assert live_pending == {"actions": [], "count": 0}


@pytest.mark.asyncio
async def test_a1_chat_notifications_skip_webauthn_link_when_expired(
    tmp_path: Path,
) -> None:
    harness = _QueuePendingHarness(tmp_path)
    approval_web = _ApprovalWebRecorder()
    delivery = _DeliveryRecorder()
    harness._approval_web = approval_web
    harness._delivery = delivery
    harness._confirmation_backend_registry.register(_AvailableWebAuthnRouteBackend())
    pending = _webauthn_pending_action(nonce="expected")
    pending.expires_at = datetime.now(UTC) - timedelta(seconds=1)
    harness._pending_actions[pending.confirmation_id] = pending

    await harness._send_chat_approval_link_notifications(
        confirmation_ids=[pending.confirmation_id],
        delivery_target=DeliveryTarget(channel="discord", recipient="chan-1"),
    )

    assert approval_web.issued == []
    assert delivery.messages == []


@pytest.mark.asyncio
async def test_a1_action_pending_suppresses_local_fido2_helper_when_expired(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = _QueuePendingHarness(tmp_path)
    calls: list[str] = []

    def local_fido2_helper(pending: PendingAction) -> dict[str, object]:
        calls.append(pending.confirmation_id)
        return {
            "ok": True,
            "origin": "http://127.0.0.1:8765",
            "rp_id": "127.0.0.1",
            "public_key": {"challenge": "test"},
        }

    monkeypatch.setattr(harness, "_local_fido2_approval_context", local_fido2_helper)
    pending = _webauthn_pending_action(nonce="expected")
    pending.selected_backend_id = "approver.local_fido2"
    pending.selected_backend_method = "local_fido2"
    pending.required_methods = ["local_fido2"]
    pending.expires_at = datetime.now(UTC) - timedelta(seconds=1)
    harness._pending_actions[pending.confirmation_id] = pending

    result = await harness.do_action_pending({"confirmation_id": pending.confirmation_id})

    assert result["count"] == 1
    action = result["actions"][0]
    assert "helper_origin" not in action
    assert "helper_rp_id" not in action
    assert "helper_public_key" not in action
    assert calls == []


@pytest.mark.asyncio
async def test_a1_action_pending_suppresses_local_fido2_helper_when_backend_unavailable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = _QueuePendingHarness(tmp_path)
    calls: list[str] = []

    def local_fido2_helper(pending: PendingAction) -> dict[str, object]:
        calls.append(pending.confirmation_id)
        return {
            "ok": True,
            "origin": "http://127.0.0.1:8765",
            "rp_id": "127.0.0.1",
            "public_key": {"challenge": "test"},
        }

    monkeypatch.setattr(harness, "_local_fido2_approval_context", local_fido2_helper)
    pending = _webauthn_pending_action(nonce="expected")
    pending.selected_backend_id = "approver.local_fido2"
    pending.selected_backend_method = "local_fido2"
    pending.required_methods = ["local_fido2"]
    harness._pending_actions[pending.confirmation_id] = pending

    result = await harness.do_action_pending({"confirmation_id": pending.confirmation_id})

    assert result["count"] == 1
    action = result["actions"][0]
    entry = ActionPendingEntry.model_validate(action)
    capability = entry.channel_capability
    assert capability["backend_available"] is False
    assert capability["can_approve"] is False
    assert "helper_origin" not in action
    assert "helper_rp_id" not in action
    assert "helper_public_key" not in action
    assert calls == []


def test_a1_public_pending_payload_marks_stronger_method_uncarryable_on_discord(
    tmp_path: Path,
) -> None:
    harness = _QueuePendingHarness(tmp_path)

    class _AvailableKmsBackend:
        backend_id = "kms.test"
        method = "kms"
        level = ConfirmationLevel.SIGNED_AUTHORIZATION
        capabilities = ConfirmationCapabilities()
        third_party_verifiable = True

        def is_available_for(self, *, user_id: str) -> bool:
            _ = user_id
            return True

        def principals_for_user(self, *, user_id: str) -> set[str]:
            _ = user_id
            return set()

        def credentials_for_user(self, *, user_id: str) -> set[str]:
            _ = user_id
            return set()

        def verify(
            self,
            *,
            pending_action: object,
            params: dict[str, object],
            now: datetime | None = None,
        ) -> ConfirmationEvidence:
            _ = pending_action, params, now
            raise AssertionError("serialization test must not verify KMS evidence")

    harness._confirmation_backend_registry.register(_AvailableKmsBackend())

    pending = harness._queue_pending_action(
        session_id=SessionId("s-a1-kms"),
        user_id=UserId("alice"),
        workspace_id=WorkspaceId("w-1"),
        tool_name=ToolName("web.fetch"),
        arguments={"url": "https://example.test/signed"},
        reason="requires_signed_authorization",
        capabilities={Capability.HTTP_REQUEST},
        delivery_target=DeliveryTarget(channel="discord", recipient="chan-1"),
        confirmation_requirement=ConfirmationRequirement(
            level=ConfirmationLevel.SIGNED_AUTHORIZATION,
            methods=["kms"],
        ),
    )

    public = harness._pending_to_dict(pending, public=True)
    entry = ActionPendingEntry.model_validate(public)

    assert entry.required_proof_tier == "method_specific"
    assert entry.required_level == ConfirmationLevel.SIGNED_AUTHORIZATION.value
    assert entry.required_methods == ["kms"]
    assert entry.selected_backend_method == "kms"
    capability = entry.channel_capability
    assert capability["origin_channel"] == "discord"
    assert capability["required_level"] == ConfirmationLevel.SIGNED_AUTHORIZATION.value
    assert capability["selected_method"] == "kms"
    assert capability["selected_method_proof_tier"] == "method_specific"
    assert capability["approval_route"] == "external_signer"
    assert capability["can_carry"] is False
    assert capability["can_collect_selected_method"] is False
    assert capability["can_carry_required_proof_tier"] is False
    assert capability["cannot_carry_reason"] == "method_specific_approval_requires_kms"


@pytest.mark.asyncio
async def test_a1_totp_confirmation_binds_allowed_principal(tmp_path: Path) -> None:
    harness = _ConfirmationImplHarness(tmp_path)
    _register_totp_factor(harness)
    pending = _totp_pending_action(nonce="expected", required_methods=["totp"])
    pending.required_level = ConfirmationLevel.SOFTWARE
    pending.allowed_principals = ["ops-laptop"]
    pending.approval_envelope = _software_approval_envelope(tool_name=ToolName("web.search"))
    _bind_pending_action_identity(pending)
    harness._pending_actions[pending.confirmation_id] = pending

    result = await harness.do_action_confirm(
        {
            "confirmation_id": "c-1",
            "decision_nonce": "expected",
            "approval_method": "totp",
            "proof": {"totp_code": generate_totp_code("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")},
        }
    )

    assert result["confirmed"] is True
    assert result["approval_level"] == ConfirmationLevel.REAUTHENTICATED.value
    assert result["approval_method"] == "totp"
    evidence = harness._pending_actions["c-1"].confirmation_evidence
    assert evidence is not None
    assert evidence.approver_principal_id == "ops-laptop"


@pytest.mark.asyncio
async def test_a1_software_channel_confirmation_requires_bound_principal(
    tmp_path: Path,
) -> None:
    harness = _ConfirmationImplHarness(tmp_path)
    pending = _pending_action(nonce="expected")
    pending.delivery_target = DeliveryTarget(channel="discord", recipient="chan-1")
    pending.allowed_channel_principals = ["alice"]
    _bind_pending_action_identity(pending)
    harness._pending_actions[pending.confirmation_id] = pending

    result = await harness.do_action_confirm(
        {"confirmation_id": "c-1", "decision_nonce": "expected"}
    )

    assert result["confirmed"] is False
    assert result["reason"] == "missing_channel_principal"
    assert harness.execution_kwargs == []


@pytest.mark.asyncio
async def test_a1_software_channel_confirmation_rejects_wrong_bound_principal(
    tmp_path: Path,
) -> None:
    harness = _ConfirmationImplHarness(tmp_path)
    pending = _pending_action(nonce="expected")
    pending.delivery_target = DeliveryTarget(channel="discord", recipient="chan-1")
    pending.allowed_channel_principals = ["alice"]
    _bind_pending_action_identity(pending)
    harness._pending_actions[pending.confirmation_id] = pending

    result = await harness.do_action_confirm(
        {
            "confirmation_id": "c-1",
            "decision_nonce": "expected",
            "principal_id": "bob",
        }
    )

    assert result["confirmed"] is False
    assert result["reason"] == "channel_principal_not_allowed"
    assert harness.execution_kwargs == []


@pytest.mark.asyncio
async def test_a1_software_channel_confirmation_accepts_bound_principal(
    tmp_path: Path,
) -> None:
    harness = _ConfirmationImplHarness(tmp_path)
    pending = _pending_action(nonce="expected")
    pending.delivery_target = DeliveryTarget(channel="discord", recipient="chan-1")
    pending.allowed_channel_principals = ["alice"]
    _bind_pending_action_identity(pending)
    harness._pending_actions[pending.confirmation_id] = pending

    result = await harness.do_action_confirm(
        {
            "confirmation_id": "c-1",
            "decision_nonce": "expected",
            "principal_id": "alice",
        }
    )

    assert result["confirmed"] is True
    evidence = harness._pending_actions["c-1"].confirmation_evidence
    assert evidence is not None
    assert evidence.approver_principal_id == "alice"


def test_a2_discord_pending_delivery_metadata_caps_component_budget() -> None:
    harness = object.__new__(HandlerImplementation)
    delivery_target = DeliveryTarget(channel="discord", recipient="chan-1")
    pending_actions: dict[str, PendingAction] = {}
    pending_ids: list[str] = []
    for index in range(13):
        confirmation_id = f"c-{index}"
        pending = _pending_action(nonce=f"nonce-{index}")
        pending.confirmation_id = confirmation_id
        pending.decision_nonce = f"nonce-{index}"
        pending.delivery_target = delivery_target
        pending.allowed_channel_principals = ["alice"]
        pending_actions[confirmation_id] = pending
        pending_ids.append(confirmation_id)
    harness._pending_actions = pending_actions
    harness._pending_selected_backend_available = lambda _pending: True

    metadata = HandlerImplementation._discord_pending_delivery_metadata(
        harness,
        {
            "pending_confirmation_ids": pending_ids,
            "response_action_confirmation_ids": pending_ids,
        },
        principal_id="alice",
        workspace_id="w-1",
        delivery_target=delivery_target,
    )

    components = metadata["discord_components"]
    assert len(components) == 24
    assert components[-1]["label"] == "Reject"
    custom_ids = [str(component["custom_id"]) for component in components]
    assert any("c-11" in custom_id for custom_id in custom_ids)
    assert all("c-12" not in custom_id for custom_id in custom_ids)
    assert all(custom_id.strip() for custom_id in custom_ids)
    assert metadata["discord_component_confirmation_ids"] == [f"c-{index}" for index in range(12)]
    assert metadata["discord_approval_confirmation_ids"] == [f"c-{index}" for index in range(12)]
    assert metadata["discord_reject_confirmation_ids"] == [f"c-{index}" for index in range(12)]


def test_a2_discord_pending_delivery_metadata_respects_live_backend_carryability() -> None:
    harness = object.__new__(HandlerImplementation)
    delivery_target = DeliveryTarget(channel="discord", recipient="chan-1")
    expired = _pending_action(nonce="expired-nonce")
    expired.confirmation_id = "c-expired"
    expired.expires_at = datetime.now(UTC) - timedelta(minutes=1)
    unavailable = _totp_pending_action(nonce="unavailable-nonce", required_methods=["totp"])
    unavailable.confirmation_id = "c-unavailable"
    unavailable.selected_backend_id = "totp.default"
    unavailable.selected_backend_method = "totp"
    live = _pending_action(nonce="live-nonce")
    live.confirmation_id = "c-live"
    for pending in (expired, unavailable, live):
        pending.delivery_target = delivery_target
        pending.allowed_channel_principals = ["alice"]
    harness._pending_actions = {
        expired.confirmation_id: expired,
        unavailable.confirmation_id: unavailable,
        live.confirmation_id: live,
    }
    harness._pending_selected_backend_available = lambda pending: pending is not unavailable

    metadata = HandlerImplementation._discord_pending_delivery_metadata(
        harness,
        {
            "pending_confirmation_ids": ["c-expired", "c-unavailable", "c-live"],
            "response_action_confirmation_ids": [
                "c-expired",
                "c-unavailable",
                "c-live",
            ],
        },
        principal_id="alice",
        workspace_id="w-1",
        delivery_target=delivery_target,
    )

    custom_ids = [str(component["custom_id"]) for component in metadata["discord_components"]]
    assert all("c-expired" not in custom_id for custom_id in custom_ids)
    assert sum("c-unavailable" in custom_id for custom_id in custom_ids) == 1
    assert any("reject" in custom_id and "c-unavailable" in custom_id for custom_id in custom_ids)
    assert sum("c-live" in custom_id for custom_id in custom_ids) == 2


def test_a2_discord_pending_delivery_metadata_skips_totp_approve_without_modal_support() -> None:
    harness = object.__new__(HandlerImplementation)
    delivery_target = DeliveryTarget(channel="discord", recipient="chan-1")
    pending = _totp_pending_action(nonce="totp-nonce", required_methods=["totp"])
    pending.confirmation_id = "c-totp"
    pending.selected_backend_id = "totp.default"
    pending.selected_backend_method = "totp"
    pending.delivery_target = delivery_target
    pending.allowed_channel_principals = ["alice"]
    harness._pending_actions = {pending.confirmation_id: pending}
    harness._pending_selected_backend_available = lambda _pending: True

    metadata = HandlerImplementation._discord_pending_delivery_metadata(
        harness,
        {
            "pending_confirmation_ids": ["c-totp"],
            "response_action_confirmation_ids": ["c-totp"],
        },
        principal_id="alice",
        workspace_id="w-1",
        delivery_target=delivery_target,
        supports_totp_modal=False,
    )

    components = metadata["discord_components"]
    assert len(components) == 1
    assert components[0]["label"] == "Reject"
    assert "reject:c-totp" in str(components[0]["custom_id"])


def test_m5_confirmed_tool_output_transcript_records_owner_projection(tmp_path) -> None:
    harness = _ConfirmationImplHarness(tmp_path)
    pending = _pending_action(nonce="expected")
    pending.action_id = "act-1"
    pending.origin_turn_id = "tx-current"
    pending.execution_attempt_id = "attempt-1"
    pending.result_id = "result-1"
    pending.followup_id = "followup-1"

    harness._append_confirmed_tool_output_transcript(
        pending=pending,
        tool_output=SimpleNamespace(
            content="confirmed search result",
            taint_labels=set(),
            success=True,
        ),
        decision_timestamp="2026-05-08T17:15:00+00:00",
    )

    entries = harness._transcript_store.list_entries(SessionId("s-1"))
    assert len(entries) == 1
    assert entries[0].metadata["user_id"] == "alice"
    assert entries[0].metadata["workspace_id"] == "w-1"
    assert entries[0].metadata["action_identity"] == {
        "action_id": "act-1",
        "origin_turn_id": "tx-current",
        "session_id": "s-1",
        "user_id": "alice",
        "workspace_id": "w-1",
        "task_id": "",
        "delivery_target": None,
        "confirmation_id": "c-1",
        "execution_attempt_id": "attempt-1",
        "result_id": "result-1",
        "followup_id": "followup-1",
    }


def test_confirmed_browser_tool_output_transcript_strips_page_title(tmp_path) -> None:
    harness = _ConfirmationImplHarness(tmp_path)
    pending = _pending_action(nonce="expected")
    pending.tool_name = ToolName("browser.screenshot")
    content = json.dumps(
        {
            "ok": True,
            "title": "Reserve Online | Venue",
            "ocr_text": "Visible page text only.",
            "screenshot_id": "shot-1",
        },
        sort_keys=True,
    )

    harness._append_confirmed_tool_output_transcript(
        pending=pending,
        tool_output=SimpleNamespace(
            content=content,
            taint_labels={TaintLabel.UNTRUSTED},
            success=True,
        ),
        decision_timestamp="2026-05-08T17:15:00+00:00",
    )

    entries = harness._transcript_store.list_entries(SessionId("s-1"))
    assert len(entries) == 1
    assert "Visible page text only." in entries[0].content_preview
    assert "Reserve Online" not in entries[0].content_preview
    assert '"title"' not in entries[0].content_preview
    assert entries[0].metadata["page_title_metadata"] == {
        "screenshot_id": "shot-1",
        "title": "Reserve Online | Venue",
    }
    assert entries[0].metadata["tool_name"] == "browser.screenshot"


def test_gh34_confirmed_browser_alias_transcript_strips_page_title(tmp_path) -> None:
    harness = _ConfirmationImplHarness(tmp_path)
    pending = _pending_action(nonce="expected")
    pending.tool_name = ToolName("browser-screenshot")
    content = json.dumps(
        {
            "ok": True,
            "title": "Reserve Online | Venue",
            "ocr_text": "Visible page text only.",
            "screenshot_id": "shot-1",
        },
        sort_keys=True,
    )

    harness._append_confirmed_tool_output_transcript(
        pending=pending,
        tool_output=SimpleNamespace(
            content=content,
            taint_labels={TaintLabel.UNTRUSTED},
            success=True,
        ),
        decision_timestamp="2026-05-08T17:15:00+00:00",
    )

    entries = harness._transcript_store.list_entries(SessionId("s-1"))
    assert len(entries) == 1
    assert "Visible page text only." in entries[0].content_preview
    assert "Reserve Online" not in entries[0].content_preview
    assert '"title"' not in entries[0].content_preview
    assert entries[0].metadata["page_title_metadata"] == {
        "screenshot_id": "shot-1",
        "title": "Reserve Online | Venue",
    }
    assert entries[0].metadata["tool_name"] == "browser-screenshot"


def test_m5_confirmed_tool_output_rebuild_preserves_shared_channel(
    tmp_path,
) -> None:
    harness = _ConfirmationImplHarness(tmp_path)
    pending = _pending_action(nonce="expected")
    delivery_target = DeliveryTarget(
        channel="discord",
        recipient="room-a",
        workspace_hint="guild-1",
        thread_id="thread-1",
    )
    pending.delivery_target = delivery_target

    harness._append_confirmed_tool_output_transcript(
        pending=pending,
        tool_output=SimpleNamespace(
            content="confirmed shared result",
            taint_labels=set(),
            success=True,
        ),
        decision_timestamp="2026-05-08T18:30:00+00:00",
    )

    entries = harness._transcript_store.list_entries(SessionId("s-1"))
    assert entries[0].metadata["channel"] == "discord"
    timeline = TimelineIndex(
        tmp_path / "timeline-confirmed-shared",
        transcript_store=harness._transcript_store,
        session_lookup=lambda _sid: None,
    )
    assert timeline.rebuild_session(SessionId("s-1")) == 1

    result = timeline.search(
        query="shared result",
        user_id="alice",
        workspace_id="w-1",
        context_channel="discord",
        context_delivery_target=delivery_target.model_dump(mode="json"),
    )
    assert result.results_count == 1


def _register_totp_factor(
    harness: _ConfirmationImplHarness,
    *,
    recovery_code_hashes: list[str] | None = None,
) -> ApprovalFactorRecord:
    factor = ApprovalFactorRecord(
        credential_id="totp-1",
        user_id="alice",
        method="totp",
        principal_id="ops-laptop",
        secret_b32="GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
        recovery_codes=[
            RecoveryCodeRecord(code_hash=value) for value in (recovery_code_hashes or [])
        ],
    )
    harness._credential_store.register_approval_factor(factor)
    return factor


def _totp_pending_action(
    *,
    nonce: str,
    required_methods: list[str] | None = None,
) -> PendingAction:
    created_at = datetime.now(UTC)
    expires_at = created_at + timedelta(hours=1)
    envelope = _software_approval_envelope(tool_name=ToolName("web.search")).model_copy(
        update={
            "required_level": ConfirmationLevel.REAUTHENTICATED,
            "expires_at": expires_at,
        }
    )
    pending = PendingAction(
        confirmation_id="c-1",
        decision_nonce=nonce,
        session_id=SessionId("s-1"),
        user_id=UserId("alice"),
        workspace_id=WorkspaceId("w-1"),
        tool_name=ToolName("web.search"),
        arguments={"query": "hello"},
        reason="manual",
        capabilities={Capability.HTTP_REQUEST},
        created_at=created_at,
        required_level=ConfirmationLevel.REAUTHENTICATED,
        required_methods=list(required_methods or []),
        required_capabilities=ConfirmationCapabilities(),
        approval_envelope=envelope,
        approval_envelope_hash=approval_envelope_hash(envelope),
        expires_at=expires_at,
        selected_backend_id="totp.default",
        selected_backend_method="totp",
    )
    _bind_pending_action_identity(pending)
    return pending


def _webauthn_pending_action(*, nonce: str) -> PendingAction:
    created_at = datetime.now(UTC)
    expires_at = created_at + timedelta(hours=1)
    envelope = _software_approval_envelope(tool_name=ToolName("web.search")).model_copy(
        update={
            "required_level": ConfirmationLevel.BOUND_APPROVAL,
            "expires_at": expires_at,
        }
    )
    pending = PendingAction(
        confirmation_id="c-webauthn",
        decision_nonce=nonce,
        session_id=SessionId("s-1"),
        user_id=UserId("alice"),
        workspace_id=WorkspaceId("w-1"),
        tool_name=ToolName("web.search"),
        arguments={"query": "hello"},
        reason="manual",
        capabilities={Capability.HTTP_REQUEST},
        created_at=created_at,
        delivery_target=DeliveryTarget(channel="discord", recipient="chan-1"),
        required_level=ConfirmationLevel.BOUND_APPROVAL,
        required_methods=["webauthn"],
        required_capabilities=ConfirmationCapabilities(
            principal_binding=True,
            approval_binding=True,
        ),
        allowed_channel_principals=["alice"],
        approval_envelope=envelope,
        approval_envelope_hash=approval_envelope_hash(envelope),
        expires_at=expires_at,
        selected_backend_id="webauthn.default",
        selected_backend_method="webauthn",
    )
    _bind_pending_action_identity(pending)
    return pending


def _software_approval_envelope(*, tool_name: ToolName) -> ApprovalEnvelope:
    return ApprovalEnvelope(
        approval_id="c-1",
        pending_action_id="c-1",
        workspace_id="w-1",
        daemon_id="daemon-1",
        session_id="s-1",
        required_level=ConfirmationLevel.SOFTWARE,
        policy_reason=f"{tool_name} confirmation",
        action_digest="sha256:test-action-digest",
        nonce="b64:test-nonce",
    )


# HDL-M1: these tests intentionally use ``object.__new__(HandlerImplementation)``
# to exercise ``_load_pending_actions`` without paying the cost of building a
# full daemon services container (sessions, channels, credential store, etc.).
# Any regression that makes ``_load_pending_actions`` depend on a *new*
# attribute that isn't set here will surface as an ``AttributeError`` during
# the call below — the helper centralizes the bypass so that drift only needs
# to be fixed in one place. If the set of required attributes keeps growing,
# the next cleanup step is to split ``_load_pending_actions`` into a pure
# function so tests can stop bypassing construction entirely.
def _load_pending_actions_harness(
    *,
    pending_actions_file: Path,
) -> HandlerImplementation:
    harness = object.__new__(HandlerImplementation)
    harness._pending_actions_file = pending_actions_file
    harness._pending_actions = {}
    harness._pending_by_session = {}
    harness._confirmation_failure_tracker = ConfirmationMethodLockoutTracker()
    harness._scheduler = _SchedulerRecorder()
    harness._schedule_recovery_accounting = lambda _pending: None  # type: ignore[method-assign]
    harness._schedule_recovered_task_cancellation = (  # type: ignore[method-assign]
        lambda _pending, *, reason: None
    )
    harness._daemon_id = "daemon-1"
    harness._registry = _registry_for_confirmation()
    harness._confirmation_backend_registry = ConfirmationBackendRegistry()
    harness._confirmation_backend_registry.register(SoftwareConfirmationBackend())
    harness._confirmation_evidence_authenticator = ConfirmationEvidenceAuthenticator(b"a" * 32)
    return harness


def test_lt3_load_pending_actions_fails_legacy_missing_approval_envelope(tmp_path) -> None:
    pending = _pending_action(nonce="expected")
    payload = HandlerImplementation._pending_to_dict(pending)
    payload.pop("approval_envelope", None)
    payload["approval_envelope_hash"] = ""
    pending_actions_file = tmp_path / "data" / "pending_actions.json"
    pending_actions_file.parent.mkdir(parents=True)
    pending_actions_file.write_text(json.dumps([payload]), encoding="utf-8")
    harness = _load_pending_actions_harness(pending_actions_file=pending_actions_file)

    HandlerImplementation._load_pending_actions(harness)

    loaded = harness._pending_actions["c-1"]
    assert loaded.status == "failed"
    assert loaded.status_reason == "approval_envelope_missing"
    persisted = json.loads(pending_actions_file.read_text(encoding="utf-8"))
    assert persisted[0]["status"] == "failed"
    assert persisted[0]["status_reason"] == "approval_envelope_missing"


def test_f1_load_stale_terminalization_does_not_mint_decision_nonce(
    tmp_path: Path,
) -> None:
    pending = _pending_action(nonce="")
    payload = HandlerImplementation._pending_to_dict(pending)
    payload.pop("approval_envelope", None)
    payload["approval_envelope_hash"] = ""
    pending_actions_file = tmp_path / "data" / "pending_actions.json"
    pending_actions_file.parent.mkdir(parents=True)
    pending_actions_file.write_text(json.dumps([payload]), encoding="utf-8")
    harness = _load_pending_actions_harness(pending_actions_file=pending_actions_file)

    harness._load_pending_actions()

    loaded = harness._pending_actions[pending.confirmation_id]
    assert loaded.status == "failed"
    assert loaded.status_reason == "approval_envelope_missing"
    assert loaded.decision_nonce == ""
    persisted = json.loads(pending_actions_file.read_text(encoding="utf-8"))[0]
    assert persisted["decision_nonce"] == ""


def test_lt3_load_pending_actions_fails_pending_rows_during_lockout_only(tmp_path) -> None:
    pending = _pending_action(nonce="expected")
    pending_payload = HandlerImplementation._pending_to_dict(pending)
    approved_payload = dict(pending_payload)
    approved_payload["confirmation_id"] = "c-2"
    approved_identity = approved_payload.get("identity")
    assert isinstance(approved_identity, dict)
    approved_payload["identity"] = {
        **approved_identity,
        "confirmation_id": "c-2",
    }
    approved_payload["decision_nonce"] = "nonce-2"
    approved_payload["status"] = "approved"
    approved_payload["status_reason"] = "approved"
    pending_actions_file = tmp_path / "data" / "pending_actions.json"
    pending_actions_file.parent.mkdir(parents=True)
    pending_actions_file.write_text(
        json.dumps([pending_payload, approved_payload]),
        encoding="utf-8",
    )
    harness = _load_pending_actions_harness(pending_actions_file=pending_actions_file)
    for _ in range(5):
        harness._confirmation_failure_tracker.record_failure(user_id="alice", method="software")

    HandlerImplementation._load_pending_actions(harness)

    assert harness._pending_actions["c-1"].status == "failed"
    assert harness._pending_actions["c-1"].status_reason == "confirmation_method_locked_out"
    assert harness._pending_actions["c-2"].status == "approved"
    assert harness._pending_actions["c-2"].status_reason == "approved"
    persisted = {
        item["confirmation_id"]: item
        for item in json.loads(pending_actions_file.read_text(encoding="utf-8"))
    }
    assert persisted["c-1"]["status"] == "failed"
    assert persisted["c-1"]["status_reason"] == "confirmation_method_locked_out"
    assert persisted["c-2"]["status"] == "approved"
    assert persisted["c-2"]["status_reason"] == "approved"


def test_gh33_pending_sensitive_browser_text_redacts_persisted_payload(tmp_path) -> None:
    pending = _pending_action(nonce="expected")
    pending.tool_name = ToolName("browser.type_text")
    pending.arguments = {
        "target": "#name",
        "text": "browser-sensitive-token",
        "is_sensitive": True,
        "click_target": "#send",
        "description": "browser-sensitive-token",
    }
    pending.safe_preview = "browser.type_text text=browser-sensitive-token"

    payload = HandlerImplementation._pending_to_dict(pending)

    serialized = json.dumps(payload, sort_keys=True)
    assert "browser-sensitive-token" not in serialized
    assert payload["arguments"]["text"] == "[sensitive text redacted]"
    assert payload["arguments"]["description"] == "[sensitive text redacted]"
    pending_actions_file = tmp_path / "data" / "pending_actions.json"
    pending_actions_file.parent.mkdir(parents=True)
    pending_actions_file.write_text(json.dumps([payload]), encoding="utf-8")
    harness = _load_pending_actions_harness(pending_actions_file=pending_actions_file)

    HandlerImplementation._load_pending_actions(harness)

    loaded = harness._pending_actions["c-1"]
    assert loaded.status == "failed"
    assert loaded.status_reason == "sensitive_confirmation_secret_unavailable"
    persisted = json.loads(pending_actions_file.read_text(encoding="utf-8"))
    persisted_serialized = json.dumps(persisted, sort_keys=True)
    assert "browser-sensitive-token" not in persisted_serialized
    assert persisted[0]["status"] == "failed"
    assert persisted[0]["status_reason"] == "sensitive_confirmation_secret_unavailable"

    short_pending = _pending_action(nonce="expected")
    short_pending.tool_name = ToolName("browser.type_text")
    short_pending.arguments = {
        "target": "#name",
        "text": "a",
        "is_sensitive": True,
        "description": "a",
    }
    short_pending.approval_envelope = short_pending.approval_envelope.model_copy(
        update={"action_summary": "text=a", "intent_envelope_hash": "old-intent-hash"}
    )
    short_pending.intent_envelope = IntentEnvelope(
        intent_id="c-1",
        agent_id="daemon-1",
        workspace_id="w-1",
        session_id="s-1",
        created_at=datetime.now(UTC),
        expires_at=None,
        action=IntentAction(
            tool="browser.type_text",
            display_summary="text=a",
            parameters={"target": "#name", "text": "a", "is_sensitive": True},
            destinations=[],
        ),
        policy_context=IntentPolicyContext(
            required_level=ConfirmationLevel.SIGNED_AUTHORIZATION,
            confirmation_reason="test",
            matched_rule="browser.type_text",
            action_digest="sha256:test-action-digest",
        ),
        nonce="b64:test-intent-nonce",
    )
    short_pending.approval_envelope = short_pending.approval_envelope.model_copy(
        update={"intent_envelope_hash": intent_envelope_hash(short_pending.intent_envelope)}
    )
    short_pending.approval_envelope_hash = approval_envelope_hash(short_pending.approval_envelope)
    short_pending.confirmation_evidence = ConfirmationEvidence(
        level=ConfirmationLevel.SIGNED_AUTHORIZATION,
        method="signed",
        backend_id="signed.default",
        approval_envelope_hash=short_pending.approval_envelope_hash,
        action_digest="sha256:test-action-digest",
        decision_nonce="expected",
        evidence_hash="sha256:test-evidence",
        intent_envelope_hash=intent_envelope_hash(short_pending.intent_envelope),
        signature="base64:test-signature",
        signer_key_id="signer-1",
    )
    short_payload = HandlerImplementation._pending_to_dict(short_pending)
    assert short_payload["arguments"]["text"] == "[sensitive text redacted]"
    assert short_payload["arguments"]["description"] == "[sensitive text redacted]"
    assert short_payload["approval_envelope_hash"] == ""
    assert short_payload["approval_envelope_redacted"] is True
    assert "approval_envelope" not in short_payload
    assert short_payload["confirmation_evidence_redacted"] is True
    assert "confirmation_evidence" not in short_payload
    assert short_payload["intent_envelope_redacted"] is True
    assert "intent_envelope" not in short_payload
    short_serialized = json.dumps(short_payload, sort_keys=True)
    assert "sha256:test-action-digest" not in short_serialized
    assert "sha256:test-evidence" not in short_serialized
    assert "base64:test-signature" not in short_serialized

    description_only_pending = _pending_action(nonce="expected")
    description_only_pending.tool_name = ToolName("browser.type_text")
    description_only_pending.arguments = {
        "target": "#name",
        "is_sensitive": True,
        "description": "description-only-secret",
    }
    description_only_payload = HandlerImplementation._pending_to_dict(description_only_pending)
    assert "description-only-secret" not in json.dumps(
        description_only_payload,
        sort_keys=True,
    )
    assert "text" not in description_only_payload["arguments"]
    assert description_only_payload["arguments"]["description"] == ("[sensitive text redacted]")
    assert description_only_payload["approval_envelope_hash"] == ""
    assert description_only_payload["approval_envelope_redacted"] is True

    raw_payload = HandlerImplementation._pending_to_dict(pending)
    raw_payload["confirmation_id"] = "c-raw"
    raw_identity = raw_payload.get("identity")
    assert isinstance(raw_identity, dict)
    raw_payload["identity"] = {
        **raw_identity,
        "confirmation_id": "c-raw",
    }
    raw_payload["decision_nonce"] = "raw-nonce"
    raw_payload["arguments"]["text"] = "raw-upgrade-token"
    raw_payload["safe_preview"] = "browser.type_text text=raw-upgrade-token"
    raw_payload["status"] = "pending"
    raw_payload["status_reason"] = ""
    pending_actions_file.write_text(json.dumps([raw_payload]), encoding="utf-8")
    raw_harness = _load_pending_actions_harness(pending_actions_file=pending_actions_file)

    HandlerImplementation._load_pending_actions(raw_harness)

    loaded_raw = raw_harness._pending_actions["c-raw"]
    assert loaded_raw.status == "failed"
    assert loaded_raw.status_reason == "sensitive_confirmation_secret_unavailable"
    raw_persisted = json.loads(pending_actions_file.read_text(encoding="utf-8"))
    raw_persisted_serialized = json.dumps(raw_persisted, sort_keys=True)
    assert "raw-upgrade-token" not in raw_persisted_serialized
    assert raw_persisted[0]["arguments"]["text"] == "[sensitive text redacted]"


@pytest.mark.parametrize("tool_name", ["browser_type_text", "browser-type-text"])
def test_gh34_pending_sensitive_browser_text_alias_redacts_persisted_payload(
    tmp_path,
    tool_name: str,
) -> None:
    pending = _pending_action(nonce="expected")
    pending.tool_name = ToolName(tool_name)
    pending.arguments = {
        "target": "#name",
        "text": "browser-alias-secret",
        "is_sensitive": True,
        "description": "browser-alias-secret",
    }
    pending.safe_preview = f"{tool_name} text=browser-alias-secret"

    payload = HandlerImplementation._pending_to_dict(pending)

    serialized = json.dumps(payload, sort_keys=True)
    assert "browser-alias-secret" not in serialized
    assert payload["arguments"]["text"] == "[sensitive text redacted]"
    assert payload["arguments"]["description"] == "[sensitive text redacted]"

    raw_payload = dict(payload)
    raw_payload["confirmation_id"] = f"c-raw-{tool_name}"
    raw_identity = raw_payload.get("identity")
    assert isinstance(raw_identity, dict)
    raw_payload["identity"] = {
        **raw_identity,
        "confirmation_id": f"c-raw-{tool_name}",
    }
    raw_payload["decision_nonce"] = f"raw-nonce-{tool_name}"
    raw_payload["arguments"] = dict(payload["arguments"])
    raw_payload["arguments"]["text"] = "browser-alias-raw-secret"
    raw_payload["arguments"]["description"] = "browser-alias-raw-secret"
    raw_payload["safe_preview"] = f"{tool_name} text=browser-alias-raw-secret"
    raw_payload["status"] = "pending"
    raw_payload["status_reason"] = ""
    pending_actions_file = tmp_path / "data" / "pending_actions.json"
    pending_actions_file.parent.mkdir(parents=True)
    pending_actions_file.write_text(json.dumps([raw_payload]), encoding="utf-8")
    harness = _load_pending_actions_harness(pending_actions_file=pending_actions_file)

    HandlerImplementation._load_pending_actions(harness)

    loaded = harness._pending_actions[f"c-raw-{tool_name}"]
    assert loaded.status == "failed"
    assert loaded.status_reason == "sensitive_confirmation_secret_unavailable"
    persisted = json.loads(pending_actions_file.read_text(encoding="utf-8"))
    persisted_serialized = json.dumps(persisted, sort_keys=True)
    assert "browser-alias-raw-secret" not in persisted_serialized
    assert persisted[0]["arguments"]["text"] == "[sensitive text redacted]"
    assert persisted[0]["arguments"]["description"] == "[sensitive text redacted]"


def test_gh33_pending_sensitive_mixed_sibling_uses_public_payload(tmp_path) -> None:
    pending = _pending_action(nonce="expected")
    pending.tool_name = ToolName("shell.exec")
    pending.arguments = {"command": ["echo", "mixed-browser-secret"]}
    pending.public_arguments = {}
    pending.sensitive_public_payload = True
    pending.preflight_action = ControlPlaneAction(
        origin=Origin(
            session_id="s-1",
            user_id="alice",
            workspace_id="w-1",
            actor="planner",
        ),
        tool_name="shell.exec",
        action_kind=ActionKind.EGRESS,
        risk_tier=RiskTier.HIGH,
        resource_id="secret.example",
        resource_ids=["secret.example"],
        network_hosts=["secret.example"],
    )
    pending.safe_preview = "shell.exec command=mixed-browser-secret"

    payload = HandlerImplementation._pending_to_dict(pending)

    serialized = json.dumps(payload, sort_keys=True)
    assert "mixed-browser-secret" not in serialized
    assert "secret.example" not in serialized
    assert payload["arguments"] == {}
    assert payload["safe_preview"] != pending.safe_preview
    assert "mixed-browser-secret" not in payload["safe_preview"]
    assert "preflight_action" not in payload
    assert payload["preflight_action_redacted"] is True
    assert payload["approval_envelope_hash"] == ""
    assert payload["approval_envelope_redacted"] is True
    assert payload["sensitive_public_payload"] is True

    pending_actions_file = tmp_path / "data" / "pending_actions.json"
    pending_actions_file.parent.mkdir(parents=True)
    pending_actions_file.write_text(json.dumps([payload]), encoding="utf-8")
    harness = _load_pending_actions_harness(pending_actions_file=pending_actions_file)

    HandlerImplementation._load_pending_actions(harness)

    loaded = harness._pending_actions["c-1"]
    assert loaded.status == "failed"
    assert loaded.status_reason == "sensitive_confirmation_secret_unavailable"
    persisted = json.loads(pending_actions_file.read_text(encoding="utf-8"))
    persisted_serialized = json.dumps(persisted, sort_keys=True)
    assert "mixed-browser-secret" not in persisted_serialized
    assert "secret.example" not in persisted_serialized
    assert persisted[0]["arguments"] == {}
    assert "preflight_action" not in persisted[0]
    assert persisted[0]["status"] == "failed"
    assert persisted[0]["status_reason"] == "sensitive_confirmation_secret_unavailable"


def test_gh33_load_pending_actions_fails_legacy_mixed_sensitive_sibling(tmp_path) -> None:
    browser_pending = _pending_action(nonce="browser")
    browser_pending.confirmation_id = "c-browser"
    browser_pending.decision_nonce = "browser-nonce"
    browser_pending.task_id = "turn-1"
    browser_pending.tool_name = ToolName("browser.type_text")
    browser_pending.arguments = {
        "target": "#token",
        "text": "legacy-mixed-secret",
        "is_sensitive": True,
    }
    browser_pending.safe_preview = "browser.type_text text=legacy-mixed-secret"
    browser_payload = HandlerImplementation._pending_to_dict(browser_pending)
    browser_payload["status"] = "pending"
    browser_payload["status_reason"] = ""
    browser_payload.pop("sensitive_public_payload", None)
    assert "legacy-mixed-secret" not in json.dumps(browser_payload, sort_keys=True)

    sibling_pending = _pending_action(nonce="sibling")
    sibling_pending.confirmation_id = "c-shell"
    sibling_pending.decision_nonce = "sibling-nonce"
    sibling_pending.task_id = "turn-1"
    sibling_pending.tool_name = ToolName("shell.exec")
    sibling_pending.arguments = {"command": ["echo", "legacy-mixed-secret"]}
    sibling_pending.safe_preview = "shell.exec command=legacy-mixed-secret"
    sibling_payload = HandlerImplementation._pending_to_dict(sibling_pending)
    sibling_payload["status"] = "pending"
    sibling_payload["status_reason"] = ""
    sibling_payload.pop("sensitive_public_payload", None)

    pending_actions_file = tmp_path / "data" / "pending_actions.json"
    pending_actions_file.parent.mkdir(parents=True)
    pending_actions_file.write_text(
        json.dumps([browser_payload, sibling_payload]),
        encoding="utf-8",
    )
    harness = _load_pending_actions_harness(pending_actions_file=pending_actions_file)

    HandlerImplementation._load_pending_actions(harness)

    loaded_browser = harness._pending_actions["c-browser"]
    assert loaded_browser.status == "failed"
    assert loaded_browser.status_reason == "sensitive_confirmation_secret_unavailable"
    assert loaded_browser.arguments["text"] == "[sensitive text redacted]"

    loaded_sibling = harness._pending_actions["c-shell"]
    assert loaded_sibling.status == "failed"
    assert loaded_sibling.status_reason == "sensitive_confirmation_secret_unavailable"
    assert loaded_sibling.arguments == {}
    assert loaded_sibling.public_arguments == {}
    assert loaded_sibling.sensitive_public_payload is True

    persisted = json.loads(pending_actions_file.read_text(encoding="utf-8"))
    persisted_by_id = {item["confirmation_id"]: item for item in persisted}
    persisted_serialized = json.dumps(persisted, sort_keys=True)
    assert "legacy-mixed-secret" not in persisted_serialized
    assert persisted_by_id["c-shell"]["arguments"] == {}
    assert persisted_by_id["c-shell"]["sensitive_public_payload"] is True
    assert persisted_by_id["c-shell"]["status"] == "failed"
    assert persisted_by_id["c-shell"]["status_reason"] == (
        "sensitive_confirmation_secret_unavailable"
    )


def test_gh33_load_pending_actions_fails_blank_task_legacy_sibling_on_raw_value(
    tmp_path,
) -> None:
    browser_pending = _pending_action(nonce="browser")
    browser_pending.confirmation_id = "c-browser"
    browser_pending.decision_nonce = "browser-nonce"
    browser_pending.tool_name = ToolName("browser.type_text")
    browser_pending.arguments = {
        "target": "#token",
        "text": "legacy-blank-task-secret",
        "is_sensitive": True,
    }
    browser_payload = HandlerImplementation._pending_to_dict(browser_pending)
    browser_payload["arguments"] = {
        "target": "#token",
        "text": "legacy-blank-task-secret",
        "is_sensitive": True,
    }
    browser_payload["safe_preview"] = "browser.type_text text=legacy-blank-task-secret"
    browser_payload["status"] = "pending"
    browser_payload["status_reason"] = ""
    browser_payload.pop("sensitive_public_payload", None)

    sibling_pending = _pending_action(nonce="sibling")
    sibling_pending.confirmation_id = "c-shell"
    sibling_pending.decision_nonce = "sibling-nonce"
    sibling_pending.tool_name = ToolName("shell.exec")
    sibling_pending.arguments = {"command": ["echo", "legacy-blank-task-secret"]}
    sibling_pending.safe_preview = "shell.exec command=legacy-blank-task-secret"
    sibling_payload = HandlerImplementation._pending_to_dict(sibling_pending)
    sibling_payload["status"] = "pending"
    sibling_payload["status_reason"] = ""
    sibling_payload.pop("sensitive_public_payload", None)

    pending_actions_file = tmp_path / "data" / "pending_actions.json"
    pending_actions_file.parent.mkdir(parents=True)
    pending_actions_file.write_text(
        json.dumps([browser_payload, sibling_payload]),
        encoding="utf-8",
    )
    harness = _load_pending_actions_harness(pending_actions_file=pending_actions_file)

    HandlerImplementation._load_pending_actions(harness)

    loaded_sibling = harness._pending_actions["c-shell"]
    assert loaded_sibling.status == "failed"
    assert loaded_sibling.status_reason == "sensitive_confirmation_secret_unavailable"
    assert loaded_sibling.arguments == {}

    persisted = json.loads(pending_actions_file.read_text(encoding="utf-8"))
    persisted_serialized = json.dumps(persisted, sort_keys=True)
    assert "legacy-blank-task-secret" not in persisted_serialized


def test_gh33_load_pending_actions_fails_blank_task_legacy_sibling_on_escaped_value(
    tmp_path,
) -> None:
    escaped_secret = 'legacy "quoted"\nsecret'
    browser_pending = _pending_action(nonce="browser")
    browser_pending.confirmation_id = "c-browser"
    browser_pending.decision_nonce = "browser-nonce"
    browser_pending.tool_name = ToolName("browser.type_text")
    browser_pending.arguments = {
        "target": "#token",
        "text": escaped_secret,
        "is_sensitive": True,
    }
    browser_payload = HandlerImplementation._pending_to_dict(browser_pending)
    browser_payload["arguments"] = {
        "target": "#token",
        "text": escaped_secret,
        "is_sensitive": True,
    }
    browser_payload["status"] = "pending"
    browser_payload["status_reason"] = ""
    browser_payload.pop("sensitive_public_payload", None)

    sibling_pending = _pending_action(nonce="sibling")
    sibling_pending.confirmation_id = "c-shell"
    sibling_pending.decision_nonce = "sibling-nonce"
    sibling_pending.tool_name = ToolName("shell.exec")
    sibling_pending.arguments = {"command": ["echo", escaped_secret]}
    sibling_payload = HandlerImplementation._pending_to_dict(sibling_pending)
    sibling_payload["status"] = "pending"
    sibling_payload["status_reason"] = ""
    sibling_payload.pop("sensitive_public_payload", None)

    pending_actions_file = tmp_path / "data" / "pending_actions.json"
    pending_actions_file.parent.mkdir(parents=True)
    pending_actions_file.write_text(
        json.dumps([browser_payload, sibling_payload]),
        encoding="utf-8",
    )
    harness = _load_pending_actions_harness(pending_actions_file=pending_actions_file)

    HandlerImplementation._load_pending_actions(harness)

    loaded_sibling = harness._pending_actions["c-shell"]
    assert loaded_sibling.status == "failed"
    assert loaded_sibling.status_reason == "sensitive_confirmation_secret_unavailable"
    assert loaded_sibling.arguments == {}

    persisted = json.loads(pending_actions_file.read_text(encoding="utf-8"))
    persisted_by_id = {item["confirmation_id"]: item for item in persisted}
    assert persisted_by_id["c-shell"]["arguments"] == {}


def test_gh33_load_pending_actions_preserves_blank_task_partial_overlap_sibling(
    tmp_path,
) -> None:
    browser_pending = _pending_action(nonce="browser")
    browser_pending.confirmation_id = "c-browser"
    browser_pending.decision_nonce = "browser-nonce"
    browser_pending.tool_name = ToolName("browser.type_text")
    browser_pending.arguments = {
        "target": "#token",
        "text": "id",
        "is_sensitive": True,
    }
    browser_payload = HandlerImplementation._pending_to_dict(browser_pending)
    browser_payload["arguments"] = {
        "target": "#token",
        "text": "id",
        "is_sensitive": True,
    }
    browser_payload["status"] = "pending"
    browser_payload["status_reason"] = ""
    browser_payload.pop("sensitive_public_payload", None)

    sibling_pending = _pending_action(nonce="sibling")
    sibling_pending.confirmation_id = "c-shell"
    sibling_pending.decision_nonce = "sibling-nonce"
    sibling_pending.tool_name = ToolName("shell.exec")
    sibling_pending.arguments = {"command": ["echo", "identity"]}
    sibling_pending.safe_preview = "shell.exec command=identity"
    _bind_pending_action_identity(sibling_pending)
    sibling_payload = HandlerImplementation._pending_to_dict(sibling_pending)
    sibling_payload["status"] = "pending"
    sibling_payload["status_reason"] = ""
    sibling_payload.pop("sensitive_public_payload", None)

    pending_actions_file = tmp_path / "data" / "pending_actions.json"
    pending_actions_file.parent.mkdir(parents=True)
    pending_actions_file.write_text(
        json.dumps([browser_payload, sibling_payload]),
        encoding="utf-8",
    )
    harness = _load_pending_actions_harness(pending_actions_file=pending_actions_file)

    HandlerImplementation._load_pending_actions(harness)

    loaded_sibling = harness._pending_actions["c-shell"]
    assert loaded_sibling.status == "pending"
    assert loaded_sibling.status_reason == ""
    assert loaded_sibling.arguments == {"command": ["echo", "identity"]}
    assert loaded_sibling.sensitive_public_payload is False


def test_gh33_load_pending_actions_preserves_unrelated_blank_task_sibling(
    tmp_path,
) -> None:
    browser_pending = _pending_action(nonce="browser")
    browser_pending.confirmation_id = "c-browser"
    browser_pending.decision_nonce = "browser-nonce"
    browser_pending.tool_name = ToolName("browser.type_text")
    browser_pending.arguments = {
        "target": "#token",
        "text": "legacy-unrelated-secret",
        "is_sensitive": True,
    }
    browser_payload = HandlerImplementation._pending_to_dict(browser_pending)
    browser_payload["status"] = "pending"
    browser_payload["status_reason"] = ""
    browser_payload.pop("sensitive_public_payload", None)
    assert "legacy-unrelated-secret" not in json.dumps(browser_payload, sort_keys=True)

    sibling_pending = _pending_action(nonce="sibling")
    sibling_pending.confirmation_id = "c-shell"
    sibling_pending.decision_nonce = "sibling-nonce"
    sibling_pending.tool_name = ToolName("shell.exec")
    sibling_pending.arguments = {"command": ["echo", "ordinary-value"]}
    sibling_pending.safe_preview = "shell.exec command=ordinary-value"
    _bind_pending_action_identity(sibling_pending)
    sibling_payload = HandlerImplementation._pending_to_dict(sibling_pending)
    sibling_payload["status"] = "pending"
    sibling_payload["status_reason"] = ""
    sibling_payload.pop("sensitive_public_payload", None)

    pending_actions_file = tmp_path / "data" / "pending_actions.json"
    pending_actions_file.parent.mkdir(parents=True)
    pending_actions_file.write_text(
        json.dumps([browser_payload, sibling_payload]),
        encoding="utf-8",
    )
    harness = _load_pending_actions_harness(pending_actions_file=pending_actions_file)

    HandlerImplementation._load_pending_actions(harness)

    loaded_browser = harness._pending_actions["c-browser"]
    assert loaded_browser.status == "failed"
    assert loaded_browser.status_reason == "sensitive_confirmation_secret_unavailable"

    loaded_sibling = harness._pending_actions["c-shell"]
    assert loaded_sibling.status == "pending"
    assert loaded_sibling.status_reason == ""
    assert loaded_sibling.arguments == {"command": ["echo", "ordinary-value"]}
    assert loaded_sibling.public_arguments is None
    assert loaded_sibling.sensitive_public_payload is False

    persisted = json.loads(pending_actions_file.read_text(encoding="utf-8"))
    persisted_by_id = {item["confirmation_id"]: item for item in persisted}
    assert persisted_by_id["c-shell"]["status"] == "pending"
    assert persisted_by_id["c-shell"]["arguments"] == {"command": ["echo", "ordinary-value"]}
    assert "sensitive_public_payload" not in persisted_by_id["c-shell"]


def test_i1_load_pending_actions_migrates_legacy_direct_mcp_strip_intent(tmp_path) -> None:
    pending = _pending_action(nonce="expected")
    pending.tool_name = ToolName("mcp.docs.lookup-doc")
    pending.arguments = {
        "session_id": "s-1",
        "tool_name": "mcp.docs.lookup-doc",
        "command": ["mcp"],
        "query": "roadmap",
    }
    pending.preflight_action = ControlPlaneAction(
        tool_name="mcp.docs.lookup-doc",
        action_kind=ActionKind.SHELL_EXEC,
        origin=Origin(actor="control_api"),
        resource_id="mcp.docs.lookup-doc",
    )
    payload = HandlerImplementation._pending_to_dict(pending)
    payload.pop("strip_direct_tool_execute_envelope_keys", None)
    pending_actions_file = tmp_path / "data" / "pending_actions.json"
    pending_actions_file.parent.mkdir(parents=True)
    pending_actions_file.write_text(json.dumps([payload]), encoding="utf-8")
    harness = _load_pending_actions_harness(pending_actions_file=pending_actions_file)

    HandlerImplementation._load_pending_actions(harness)

    loaded = harness._pending_actions["c-1"]
    assert loaded.strip_direct_tool_execute_envelope_keys is True
    persisted = json.loads(pending_actions_file.read_text(encoding="utf-8"))
    assert persisted[0]["strip_direct_tool_execute_envelope_keys"] is True


def test_a1_load_pending_actions_backfills_legacy_channel_principal(tmp_path) -> None:
    pending = _pending_action(nonce="expected")
    pending.delivery_target = DeliveryTarget(channel="discord", recipient="chan-1")
    payload = HandlerImplementation._pending_to_dict(pending)
    payload.pop("allowed_channel_principals", None)
    pending_actions_file = tmp_path / "data" / "pending_actions.json"
    pending_actions_file.parent.mkdir(parents=True)
    pending_actions_file.write_text(json.dumps([payload]), encoding="utf-8")
    harness = _load_pending_actions_harness(pending_actions_file=pending_actions_file)

    HandlerImplementation._load_pending_actions(harness)

    loaded = harness._pending_actions["c-1"]
    assert loaded.allowed_channel_principals == ["alice"]
    persisted = json.loads(pending_actions_file.read_text(encoding="utf-8"))
    assert persisted[0]["allowed_channel_principals"] == ["alice"]


def test_f10c_load_quarantines_channel_pending_without_principal_identity(
    tmp_path,
) -> None:
    pending = _pending_action(nonce="expected")
    pending.user_id = UserId("")
    pending.delivery_target = DeliveryTarget(channel="discord", recipient="chan-1")
    payload = HandlerImplementation._pending_to_dict(pending)
    payload.pop("allowed_channel_principals", None)
    pending_actions_file = tmp_path / "data" / "pending_actions.json"
    pending_actions_file.parent.mkdir(parents=True)
    pending_actions_file.write_text(json.dumps([payload]), encoding="utf-8")
    harness = _load_pending_actions_harness(pending_actions_file=pending_actions_file)

    HandlerImplementation._load_pending_actions(harness)

    assert harness._pending_actions == {}
    assert harness._pending_by_session == {}
    assert harness._pending_state_degradation == {
        "transition": "load",
        "stage": "corrupt",
        "reason": "pending_state_corrupt",
    }
    quarantined = list(pending_actions_file.parent.glob("pending_actions.json.corrupt.*"))
    assert len(quarantined) == 1


def _pep_context_snapshot(
    *,
    capabilities: set[Capability],
) -> PendingPepContextSnapshot:
    return PendingPepContextSnapshot(
        capabilities=set(capabilities),
        taint_labels=set(),
        user_goal_host_patterns={"example.com"},
        untrusted_host_patterns=set(),
        tool_allowlist=None,
        trust_level="trusted",
        credential_refs=set(),
        enforce_explicit_credential_refs=False,
    )


@pytest.mark.asyncio
async def test_m1_rr3_action_pending_filters_by_confirmation_id(tmp_path) -> None:
    harness = _ConfirmationImplHarness(tmp_path)
    first = _pending_action(nonce="first")
    second = _pending_action(nonce="second")
    second.confirmation_id = "c-2"
    harness._pending_actions[first.confirmation_id] = first
    harness._pending_actions[second.confirmation_id] = second

    filtered = await harness.do_action_pending({"confirmation_id": "c-2", "limit": 10})
    assert filtered["count"] == 1
    assert filtered["actions"][0]["confirmation_id"] == "c-2"


@pytest.mark.asyncio
async def test_lt5_action_purge_defaults_to_terminal_rows(tmp_path) -> None:
    harness = _ConfirmationImplHarness(tmp_path)
    pending = _pending_action(nonce="pending")
    failed = _pending_action(nonce="failed")
    failed.confirmation_id = "c-failed"
    failed.status = "failed"
    failed.status_reason = "approval_envelope_missing"
    harness._pending_actions[pending.confirmation_id] = pending
    harness._pending_actions[failed.confirmation_id] = failed

    result = await harness.do_action_purge({"status": "terminal", "limit": 10})

    assert result == {
        "purged": 1,
        "confirmation_ids": ["c-failed"],
        "remaining": 1,
        "dry_run": False,
    }
    assert pending.confirmation_id in harness._pending_actions
    assert "c-failed" not in harness._pending_actions


@pytest.mark.asyncio
async def test_lt5_action_purge_dry_run_leaves_rows_and_session_index(tmp_path) -> None:
    harness = _ConfirmationImplHarness(tmp_path)
    failed = _pending_action(nonce="failed")
    failed.confirmation_id = "c-failed"
    failed.status = "failed"
    failed.status_reason = "approval_envelope_missing"
    harness._pending_actions[failed.confirmation_id] = failed
    harness._pending_by_session[failed.session_id] = [failed.confirmation_id]

    result = await harness.do_action_purge({"status": "terminal", "limit": 10, "dry_run": True})

    assert result == {
        "purged": 1,
        "confirmation_ids": ["c-failed"],
        "remaining": 1,
        "dry_run": True,
    }
    assert "c-failed" in harness._pending_actions
    assert harness._pending_by_session[failed.session_id] == ["c-failed"]
    assert harness.persist_calls == 0


@pytest.mark.asyncio
async def test_lt5_action_purge_can_clear_aged_pending_rows(tmp_path) -> None:
    harness = _ConfirmationImplHarness(tmp_path)
    scheduler = _SchedulerRecorder()
    harness._scheduler = scheduler
    recent = _pending_action(nonce="recent")
    old = _pending_action(nonce="old")
    old.confirmation_id = "c-old"
    old.task_id = "task-old"
    old.created_at = datetime.now(UTC) - timedelta(days=10)
    harness._pending_actions[recent.confirmation_id] = recent
    harness._pending_actions[old.confirmation_id] = old
    harness._pending_by_session[recent.session_id] = [
        recent.confirmation_id,
        old.confirmation_id,
    ]

    result = await harness.do_action_purge({"status": "pending", "older_than_days": 7, "limit": 10})

    assert result["confirmation_ids"] == ["c-old"]
    assert recent.confirmation_id in harness._pending_actions
    assert "c-old" not in harness._pending_actions
    assert harness._pending_by_session[recent.session_id] == [recent.confirmation_id]
    assert len(scheduler.resolved_confirmations) == 1
    resolution = scheduler.resolved_confirmations[0]
    assert resolution["task_id"] == "task-old"
    assert resolution["confirmation_id"] == "c-old"
    assert resolution["status"] == "failed"
    assert resolution["status_reason"] == "purged_stale_pending_action"
    assert resolution["lifecycle_state"] == "superseded"
    assert str(resolution["action_id"]).startswith("act-")
    assert str(resolution["result_id"]).startswith("result-")
    assert scheduler.run_outcomes == [{"task_id": "task-old", "success": False}]


@pytest.mark.asyncio
async def test_f1_action_purge_filters_canonical_lifecycle_exclusively(tmp_path: Path) -> None:
    harness = _ConfirmationImplHarness(tmp_path)
    now = datetime.now(UTC)

    live_pending = _pending_action(nonce="pending")
    live_pending.confirmation_id = "c-pending"
    live_pending.created_at = now - timedelta(days=10)
    live_pending.expires_at = now + timedelta(days=1)

    raw_expired = _pending_action(nonce="raw-expired")
    raw_expired.confirmation_id = "c-raw-expired"
    raw_expired.created_at = now - timedelta(days=10)
    raw_expired.expires_at = now - timedelta(days=1)

    failed_expired = _pending_action(nonce="failed-expired")
    failed_expired.confirmation_id = "c-failed-expired"
    failed_expired.status = "failed"
    failed_expired.status_reason = "approval_expired"

    failed = _pending_action(nonce="failed")
    failed.confirmation_id = "c-failed"
    failed.status = "failed"
    failed.status_reason = "execution_failed"

    approved = _pending_action(nonce="approved")
    approved.confirmation_id = "c-approved"
    approved.status = "approved"

    executed = _pending_action(nonce="executed")
    executed.confirmation_id = "c-executed"
    executed.status = "executed"

    harness._pending_actions = {
        item.confirmation_id: item
        for item in (
            live_pending,
            raw_expired,
            failed_expired,
            failed,
            approved,
            executed,
        )
    }

    pending_result = await harness.do_action_purge(
        {"status": "pending", "older_than_days": 7, "dry_run": True, "limit": 20}
    )
    failed_result = await harness.do_action_purge(
        {"status": "failed", "dry_run": True, "limit": 20}
    )
    expired_result = await harness.do_action_purge(
        {"status": "expired", "dry_run": True, "limit": 20}
    )
    approved_result = await harness.do_action_purge(
        {"status": "approved", "dry_run": True, "limit": 20}
    )

    assert pending_result["confirmation_ids"] == ["c-pending"]
    assert failed_result["confirmation_ids"] == ["c-failed"]
    assert set(expired_result["confirmation_ids"]) == {
        "c-raw-expired",
        "c-failed-expired",
    }
    assert set(approved_result["confirmation_ids"]) == {"c-approved", "c-executed"}


@pytest.mark.asyncio
async def test_f1_terminal_purge_preserves_expired_task_projection(tmp_path: Path) -> None:
    harness = _ConfirmationImplHarness(tmp_path)
    scheduler = _SchedulerRecorder()
    harness._scheduler = scheduler
    expired = _pending_action(nonce="expired")
    expired.confirmation_id = "c-expired"
    expired.task_id = "task-expired"
    expired.expires_at = datetime.now(UTC) - timedelta(seconds=1)
    harness._pending_actions[expired.confirmation_id] = expired

    result = await harness.do_action_purge({"status": "terminal", "limit": 10})

    assert result["confirmation_ids"] == ["c-expired"]
    assert len(scheduler.resolved_confirmations) == 1
    resolution = scheduler.resolved_confirmations[0]
    assert resolution["task_id"] == "task-expired"
    assert resolution["confirmation_id"] == "c-expired"
    assert resolution["status"] == "failed"
    assert resolution["status_reason"] == "approval_expired"
    assert resolution["lifecycle_state"] == "expired"
    assert resolution["action_id"] == expired.action_id
    assert str(resolution["result_id"]).startswith("result-")
    assert scheduler.run_outcomes == [{"task_id": "task-expired", "success": False}]


@pytest.mark.asyncio
async def test_lt5_action_purge_limit_zero_purges_no_rows(tmp_path) -> None:
    harness = _ConfirmationImplHarness(tmp_path)
    failed = _pending_action(nonce="failed")
    failed.confirmation_id = "c-failed"
    failed.status = "failed"
    failed.status_reason = "approval_envelope_missing"
    harness._pending_actions[failed.confirmation_id] = failed

    result = await harness.do_action_purge({"status": "terminal", "limit": 0})

    assert result == {
        "purged": 0,
        "confirmation_ids": [],
        "remaining": 1,
        "dry_run": False,
    }
    assert "c-failed" in harness._pending_actions


@pytest.mark.asyncio
async def test_lt5_action_purge_requires_age_for_pending_rows(tmp_path) -> None:
    harness = _ConfirmationImplHarness(tmp_path)

    with pytest.raises(ValueError, match="older_than_days must be positive"):
        await harness.do_action_purge({"status": "pending", "limit": 10})


@pytest.mark.asyncio
async def test_lt5_action_purge_rejects_nonpositive_age_for_pending_rows(
    tmp_path,
) -> None:
    harness = _ConfirmationImplHarness(tmp_path)

    with pytest.raises(ValueError, match="older_than_days must be positive"):
        await harness.do_action_purge({"status": "pending", "older_than_days": 0, "limit": 10})


@pytest.mark.asyncio
async def test_m1_pf11_confirmation_rejects_invalid_nonce(tmp_path) -> None:
    harness = _ConfirmationImplHarness(tmp_path)
    harness._pending_actions["c-1"] = _pending_action(nonce="expected")
    result = await harness.do_action_confirm(
        {"confirmation_id": "c-1", "decision_nonce": "invalid"}
    )
    assert result["confirmed"] is False
    assert result["reason"] == "invalid_decision_nonce"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("decision_method", "decision_field"),
    [("confirm", "confirmed"), ("reject", "rejected")],
)
@pytest.mark.parametrize("invalid_nonce", ["☃", "\ud800"])
async def test_f2_non_ascii_decision_nonce_fails_closed(
    tmp_path: Path,
    decision_method: str,
    decision_field: str,
    invalid_nonce: str,
) -> None:
    harness = _ConfirmationImplHarness(tmp_path)
    pending = _pending_action(nonce="expected")
    harness._pending_actions[pending.confirmation_id] = pending
    decision = (
        harness.do_action_confirm if decision_method == "confirm" else harness.do_action_reject
    )

    result = await decision(
        {"confirmation_id": pending.confirmation_id, "decision_nonce": invalid_nonce}
    )

    assert result[decision_field] is False
    assert result["reason"] == "invalid_decision_nonce"
    assert pending.status == "pending"


@pytest.mark.asyncio
async def test_m1_pf11_confirmation_rejects_invalid_nonce_before_cooldown(tmp_path) -> None:
    harness = _ConfirmationImplHarness(tmp_path)
    harness._pending_actions["c-1"] = _pending_action(
        nonce="expected",
        execute_after=datetime.now(UTC) + timedelta(seconds=30),
    )

    result = await harness.do_action_confirm(
        {"confirmation_id": "c-1", "decision_nonce": "invalid"}
    )

    assert result["confirmed"] is False
    assert result["reason"] == "invalid_decision_nonce"


@pytest.mark.asyncio
async def test_m1_pf11_confirmation_accepts_valid_nonce_and_rejects_missing_nonce(
    tmp_path,
) -> None:
    harness = _ConfirmationImplHarness(tmp_path)
    harness._pending_actions["c-1"] = _pending_action(nonce="expected")
    valid = await harness.do_action_confirm(
        {"confirmation_id": "c-1", "decision_nonce": "expected"}
    )
    assert valid["confirmed"] is True
    assert valid["status"] == "approved"
    assert valid["lifecycle_state"] == "executed"
    assert valid["action_id"] != valid["confirmation_id"]
    assert valid["identity"]["execution_attempt_id"]
    assert valid["identity"]["result_id"]
    assert valid["identity"]["followup_id"]
    assert harness.execution_kwargs[0]["action_id"] == valid["action_id"]
    assert (
        harness.execution_kwargs[0]["execution_attempt_id"]
        == valid["identity"]["execution_attempt_id"]
    )
    assert harness.execution_kwargs[0]["result_id"] == valid["identity"]["result_id"]

    harness = _ConfirmationImplHarness(tmp_path)
    harness._pending_actions["c-1"] = _pending_action(nonce="expected")
    missing = await harness.do_action_confirm({"confirmation_id": "c-1"})
    assert missing["confirmed"] is False
    assert missing["reason"] == "missing_decision_nonce"


@pytest.mark.asyncio
async def test_f1_confirmation_resolution_carries_complete_audit_and_task_identity(
    tmp_path: Path,
) -> None:
    harness = _ConfirmationImplHarness(tmp_path)
    scheduler = _SchedulerRecorder()
    harness._scheduler = scheduler
    pending = _pending_action(nonce="expected")
    pending.task_id = "task-1"
    pending.delivery_target = DeliveryTarget(channel="discord", recipient="chan-1")
    pending.allowed_channel_principals = ["alice"]
    _bind_pending_action_identity(pending)
    harness._pending_actions[pending.confirmation_id] = pending

    result = await harness.do_action_confirm(
        {
            "confirmation_id": pending.confirmation_id,
            "decision_nonce": "expected",
            "principal_id": "alice",
        }
    )

    assert result["confirmed"] is True
    execution_call = harness.execution_kwargs[-1]
    assert execution_call["workspace_id"] == "w-1"
    assert execution_call["task_id"] == "task-1"
    assert execution_call["delivery_target"] == {
        "channel": "discord",
        "recipient": "chan-1",
        "thread_id": "",
        "workspace_hint": "",
    }
    resolution = scheduler.resolved_confirmations[-1]
    assert resolution["execution_attempt_id"] == result["identity"]["execution_attempt_id"]
    assert resolution["result_id"] == result["identity"]["result_id"]

    rejected_pending = _pending_action(nonce="reject-expected")
    rejected_pending.confirmation_id = "c-reject"
    rejected_pending.task_id = "task-1"
    rejected_pending.delivery_target = DeliveryTarget(
        channel="discord",
        recipient="chan-1",
    )
    rejected_pending.allowed_channel_principals = ["alice"]
    harness._pending_actions[rejected_pending.confirmation_id] = rejected_pending
    harness._pending_by_session.setdefault(rejected_pending.session_id, []).append(
        rejected_pending.confirmation_id
    )
    await harness.do_action_reject(
        {
            "confirmation_id": rejected_pending.confirmation_id,
            "decision_nonce": "reject-expected",
            "principal_id": "alice",
        }
    )
    rejected = next(
        event
        for event in harness.published_events
        if isinstance(event, ToolRejected) and event.actor == "human_confirmation"
    )
    assert rejected.user_id == "alice"
    assert rejected.workspace_id == "w-1"
    assert rejected.task_id == "task-1"
    assert rejected.delivery_target == {
        "channel": "discord",
        "recipient": "chan-1",
        "thread_id": "",
        "workspace_hint": "",
    }
    assert rejected.result_id == pending_action_state_view(rejected_pending).identity.result_id
    assert rejected.result_id.startswith("result-")


@pytest.mark.parametrize("event_type", [ToolApproved, ToolRejected, ToolExecuted])
def test_f1_tool_audit_event_schemas_include_complete_action_scope(
    event_type: type[object],
) -> None:
    for field_name in ("user_id", "workspace_id", "task_id", "delivery_target"):
        assert field_name in event_type.model_fields  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_a0_confirmation_success_records_software_level_evidence(tmp_path) -> None:
    harness = _ConfirmationImplHarness(tmp_path)
    harness._pending_actions["c-1"] = _pending_action(nonce="expected")

    result = await harness.do_action_confirm(
        {"confirmation_id": "c-1", "decision_nonce": "expected"}
    )

    assert result["confirmed"] is True
    assert result["approval_level"] == ConfirmationLevel.SOFTWARE.value
    assert result["approval_method"] == "software"

    pending = harness._pending_actions["c-1"]
    assert pending.confirmation_evidence is not None
    assert pending.confirmation_evidence.level == ConfirmationLevel.SOFTWARE
    assert pending.confirmation_evidence.method == "software"
    assert pending.confirmation_evidence.authenticator_mac.startswith("hmac-sha256:")
    assert len(harness.execution_kwargs) == 1
    forwarded_evidence = harness.execution_kwargs[0]["approval_evidence"]
    assert forwarded_evidence is not None
    assert getattr(forwarded_evidence, "level", None) == ConfirmationLevel.SOFTWARE
    assert getattr(forwarded_evidence, "method", "") == "software"


@pytest.mark.asyncio
async def test_a1_confirmation_rejects_recovery_code_when_pending_methods_require_totp(
    tmp_path,
) -> None:
    harness = _ConfirmationImplHarness(tmp_path)
    recovery_code = "ABCD-EFGH"
    _register_totp_factor(
        harness,
        recovery_code_hashes=[hash_recovery_code(recovery_code)],
    )
    harness._pending_actions["c-1"] = _totp_pending_action(
        nonce="expected",
        required_methods=["totp"],
    )

    result = await harness.do_action_confirm(
        {
            "confirmation_id": "c-1",
            "decision_nonce": "expected",
            "approval_method": "recovery_code",
            "proof": {"recovery_code": recovery_code},
        }
    )

    assert result["confirmed"] is False
    assert result["reason"] == "confirmation_method_not_allowed"
    factor = harness._credential_store.get_approval_factor("totp-1")
    assert factor is not None
    assert factor.recovery_codes[0].consumed_at is None
    assert harness.execution_kwargs == []


@pytest.mark.asyncio
async def test_a1_confirmation_rejects_backend_evidence_that_does_not_satisfy_pending_requirement(
    tmp_path,
) -> None:
    harness = _ConfirmationImplHarness(tmp_path)

    class _BrokenBackend(SoftwareConfirmationBackend):
        def __init__(self) -> None:
            super().__init__()
            self.backend_id = "broken.default"
            self.method = "software"

        def verify(
            self,
            *,
            pending_action: object,
            params: dict[str, object],
        ) -> ConfirmationEvidence:
            _ = (pending_action, params)
            return ConfirmationEvidence(
                level=ConfirmationLevel.SOFTWARE,
                method="software",
                backend_id=self.backend_id,
                approval_envelope_hash="sha256:test-envelope",
                action_digest="sha256:test-action",
                decision_nonce="expected",
                fallback_used=False,
            )

    harness._confirmation_backend_registry.register(_BrokenBackend())
    pending = _pending_action(nonce="expected")
    pending.required_level = ConfirmationLevel.REAUTHENTICATED
    pending.selected_backend_id = "broken.default"
    pending.selected_backend_method = "software"
    _bind_pending_action_identity(pending)
    harness._pending_actions["c-1"] = pending

    result = await harness.do_action_confirm(
        {"confirmation_id": "c-1", "decision_nonce": "expected"}
    )

    assert result["confirmed"] is False
    assert result["reason"] == "confirmation_requirement_unsatisfied"
    assert pending.confirmation_evidence is None
    assert harness.execution_kwargs == []


@pytest.mark.asyncio
async def test_a0_confirmation_lockout_triggers_after_repeated_invalid_nonce(tmp_path) -> None:
    harness = _ConfirmationImplHarness(tmp_path)
    harness._pending_actions["c-1"] = _pending_action(nonce="expected")

    for _ in range(5):
        invalid = await harness.do_action_confirm(
            {"confirmation_id": "c-1", "decision_nonce": "wrong"}
        )
        assert invalid["confirmed"] is False
        assert invalid["reason"] == "invalid_decision_nonce"

    locked = await harness.do_action_confirm(
        {"confirmation_id": "c-1", "decision_nonce": "expected"}
    )

    assert locked["confirmed"] is False
    assert locked["reason"] == "confirmation_method_locked_out"
    assert float(locked["retry_after_seconds"]) > 0
    assert harness._pending_actions["c-1"].status == "failed"
    assert harness._pending_actions["c-1"].status_reason == "confirmation_method_locked_out"


@pytest.mark.asyncio
async def test_lt3_action_confirm_fails_missing_approval_envelope_terminally(tmp_path) -> None:
    harness = _ConfirmationImplHarness(tmp_path)
    pending = _pending_action(nonce="expected")
    pending.approval_envelope = None
    pending.approval_envelope_hash = ""
    harness._pending_actions["c-1"] = pending

    result = await harness.do_action_confirm(
        {"confirmation_id": "c-1", "decision_nonce": "expected"}
    )

    assert result["confirmed"] is False
    assert result["reason"] == "approval_envelope_missing"
    assert result["status"] == "failed"
    assert pending.status == "failed"
    assert pending.status_reason == "approval_envelope_missing"
    assert harness.execution_kwargs == []


@pytest.mark.asyncio
async def test_lt3_action_confirm_fails_missing_action_digest_terminally(tmp_path) -> None:
    harness = _ConfirmationImplHarness(tmp_path)
    pending = _pending_action(nonce="expected")
    assert pending.approval_envelope is not None
    pending.approval_envelope = pending.approval_envelope.model_copy(update={"action_digest": ""})
    pending.approval_envelope_hash = approval_envelope_hash(pending.approval_envelope)
    harness._pending_actions["c-1"] = pending

    result = await harness.do_action_confirm(
        {"confirmation_id": "c-1", "decision_nonce": "expected"}
    )

    assert result["confirmed"] is False
    assert result["reason"] == "action_digest_missing"
    assert result["status"] == "failed"
    assert pending.status == "failed"
    assert pending.status_reason == "action_digest_missing"
    assert harness.execution_kwargs == []


@pytest.mark.asyncio
async def test_f1_action_confirm_rejects_identity_not_bound_by_approval_envelope(
    tmp_path: Path,
) -> None:
    harness = _ConfirmationImplHarness(tmp_path)
    pending = _pending_action(nonce="expected")
    assert pending.approval_envelope is not None
    pending.approval_envelope = pending.approval_envelope.model_copy(
        update={"pending_action_id": pending.action_id}
    )
    pending.approval_envelope_hash = approval_envelope_hash(pending.approval_envelope)
    pending.action_id = "act-tampered"
    harness._pending_actions["c-1"] = pending

    result = await harness.do_action_confirm(
        {"confirmation_id": "c-1", "decision_nonce": "expected"}
    )

    assert result["confirmed"] is False
    assert result["reason"] == "action_identity_mismatch"
    assert result["lifecycle_state"] == "failed"
    assert harness.execution_kwargs == []


@pytest.mark.asyncio
async def test_f1_legacy_approval_alias_must_equal_its_confirmation_id(
    tmp_path: Path,
) -> None:
    harness = _ConfirmationImplHarness(tmp_path)
    pending = _pending_action(nonce="expected")
    assert pending.approval_envelope is not None
    pending.approval_envelope = pending.approval_envelope.model_copy(
        update={"approval_id": "c-unrelated", "pending_action_id": "c-unrelated"}
    )
    pending.approval_envelope_hash = approval_envelope_hash(pending.approval_envelope)
    harness._pending_actions["c-1"] = pending

    result = await harness.do_action_confirm(
        {"confirmation_id": "c-1", "decision_nonce": "expected"}
    )

    assert result["confirmed"] is False
    assert result["reason"] == "action_identity_mismatch"
    assert result["lifecycle_state"] == "failed"
    assert harness.execution_kwargs == []


@pytest.mark.asyncio
async def test_a0_closed_confirmation_invalid_nonce_does_not_increment_lockout(tmp_path) -> None:
    harness = _ConfirmationImplHarness(tmp_path)
    pending = _pending_action(nonce="expected")
    pending.status = "approved"
    harness._pending_actions["c-1"] = pending

    for _ in range(5):
        result = await harness.do_action_confirm(
            {"confirmation_id": "c-1", "decision_nonce": "wrong"}
        )
        assert result["confirmed"] is False
        assert result["reason"] == "already_approved"

    assert harness._confirmation_failure_tracker.status(user_id="alice", method="software") is None


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("decision_method", "decision_field"),
    [("confirm", "confirmed"), ("reject", "rejected")],
)
async def test_f1_decision_race_observes_disabled_task_before_execution(
    tmp_path: Path,
    decision_method: str,
    decision_field: str,
) -> None:
    harness = _ConfirmationImplHarness(tmp_path)
    pending = _pending_action(nonce="expected")
    pending.task_id = "task-1"
    _bind_pending_action_identity(pending)
    harness._pending_actions["c-1"] = pending
    harness._scheduler = SimpleNamespace(
        get_task=lambda _task_id: SimpleNamespace(enabled=False),
        resolve_confirmation=lambda *_args, **_kwargs: True,
    )

    decision = (
        harness.do_action_confirm if decision_method == "confirm" else harness.do_action_reject
    )
    result = await decision({"confirmation_id": "c-1", "decision_nonce": "expected"})

    assert result[decision_field] is False
    assert result["reason"] == "task_disabled"
    assert result["status"] == "cancelled"
    assert result["status_reason"] == "task_disabled"
    assert pending.status == "cancelled"
    assert pending.decision_nonce == ""
    assert harness.execution_kwargs == []
    cancelled = [
        event
        for event in harness.published_events
        if isinstance(event, ToolRejected) and event.reason == "task_disabled"
    ]
    assert len(cancelled) == 1
    assert cancelled[0].result_id == pending_action_state_view(pending).identity.result_id
    assert cancelled[0].result_id.startswith("result-")


@pytest.mark.asyncio
async def test_f1_confirmation_and_disable_share_task_then_confirmation_lock_order(
    tmp_path: Path,
) -> None:
    class _RaceHarness(_ConfirmationImplHarness, TasksImplMixin):
        def __init__(self, root: Path) -> None:
            super().__init__(root)
            self.execution_started = asyncio.Event()
            self.release_execution = asyncio.Event()

        async def _execute_approved_action(self, **kwargs: object) -> object:
            self.execution_started.set()
            await self.release_execution.wait()
            return await super()._execute_approved_action(**kwargs)  # type: ignore[arg-type]

    harness = _RaceHarness(tmp_path)
    scheduled_task = SimpleNamespace(id="task-1", enabled=True)

    def _disable_task(_task_id: str) -> bool:
        scheduled_task.enabled = False
        return True

    harness._scheduler = SimpleNamespace(
        get_task=lambda _task_id: scheduled_task,
        disable_task=_disable_task,
        resolve_confirmation=lambda *_args, **_kwargs: True,
        record_run_outcome=lambda *_args, **_kwargs: True,
    )
    pending = _pending_action(nonce="expected")
    pending.task_id = "task-1"
    _bind_pending_action_identity(pending)
    harness._pending_actions["c-1"] = pending

    confirm_task = asyncio.create_task(
        harness.do_action_confirm({"confirmation_id": "c-1", "decision_nonce": "expected"})
    )
    await harness.execution_started.wait()
    disable_task = asyncio.create_task(harness.do_task_disable({"task_id": "task-1"}))
    await asyncio.sleep(0)

    assert disable_task.done() is False
    assert scheduled_task.enabled is True

    harness.release_execution.set()

    confirmed = await confirm_task
    disabled = await disable_task
    assert confirmed["confirmed"] is True
    assert disabled == {"disabled": True, "task_id": "task-1"}
    assert scheduled_task.enabled is False
    assert len(harness.execution_kwargs) == 1


@pytest.mark.asyncio
async def test_f1_max_runs_success_cancels_sibling_pending_confirmations(
    tmp_path: Path,
) -> None:
    harness = _ConfirmationImplHarness(tmp_path)
    scheduler = SchedulerManager(storage_dir=tmp_path / "scheduler")
    task = scheduler.create_task(
        name="one-success-only",
        goal="Deliver once",
        schedule=Schedule.from_event("message.received"),
        capability_snapshot={Capability.HTTP_REQUEST},
        policy_snapshot_ref="p1",
        created_by=UserId("alice"),
        workspace_id=WorkspaceId("w-1"),
        max_runs=1,
    )
    harness._scheduler = scheduler

    first = _pending_action(nonce="nonce-1")
    first.task_id = task.id
    _bind_pending_action_identity(first)
    second = _pending_action(nonce="nonce-2")
    second.confirmation_id = "c-2"
    second.task_id = task.id
    _bind_pending_action_identity(second)
    harness._pending_actions = {"c-1": first, "c-2": second}
    for pending in (first, second):
        scheduler.queue_confirmation(
            task.id,
            {
                "confirmation_id": pending.confirmation_id,
                "status": "pending",
                "identity": {"action_id": pending.action_id},
            },
        )

    confirmed = await harness.do_action_confirm(
        {"confirmation_id": "c-1", "decision_nonce": "nonce-1"}
    )

    assert confirmed["confirmed"] is True
    assert scheduler.get_task(task.id).enabled is False  # type: ignore[union-attr]
    assert first.status == "approved"
    assert second.status == "cancelled"
    assert second.status_reason == "max_runs_reached"
    assert second.decision_nonce == ""
    assert scheduler.pending_confirmations(task.id) == []
    cancelled = [
        event
        for event in harness.published_events
        if isinstance(event, ToolRejected)
        and event.approval_confirmation_id == "c-2"
        and event.reason == "max_runs_reached"
    ]
    assert len(cancelled) == 1


@pytest.mark.asyncio
async def test_f1_max_runs_confirmation_allows_pending_sibling_purge_while_executing(
    tmp_path: Path,
) -> None:
    class _SlowExecutionHarness(_ConfirmationImplHarness):
        def __init__(self, root: Path) -> None:
            super().__init__(root)
            self.execution_started = asyncio.Event()
            self.release_execution = asyncio.Event()

        async def _execute_approved_action(self, **kwargs: object) -> object:
            self.execution_started.set()
            await self.release_execution.wait()
            return await super()._execute_approved_action(**kwargs)  # type: ignore[arg-type]

    harness = _SlowExecutionHarness(tmp_path)
    scheduler = SchedulerManager(storage_dir=tmp_path / "scheduler")
    task = scheduler.create_task(
        name="one-success-only",
        goal="Deliver once",
        schedule=Schedule.from_event("message.received"),
        capability_snapshot={Capability.HTTP_REQUEST},
        policy_snapshot_ref="p1",
        created_by=UserId("alice"),
        workspace_id=WorkspaceId("w-1"),
        max_runs=1,
    )
    harness._scheduler = scheduler

    created_at = datetime.now(UTC) - timedelta(days=10)
    sibling = _pending_action(nonce="nonce-1")
    sibling.task_id = task.id
    sibling.created_at = created_at
    current = _pending_action(nonce="nonce-2")
    current.confirmation_id = "c-2"
    current.task_id = task.id
    current.created_at = created_at
    _bind_pending_action_identity(current)
    harness._pending_actions = {"c-1": sibling, "c-2": current}

    confirm_task = asyncio.create_task(
        harness.do_action_confirm({"confirmation_id": "c-2", "decision_nonce": "nonce-2"})
    )
    await harness.execution_started.wait()
    purge_task = asyncio.create_task(
        harness.do_action_purge({"status": "pending", "older_than_days": 7, "limit": 10})
    )
    purged = await asyncio.wait_for(purge_task, timeout=1.0)

    assert purged["confirmation_ids"] == ["c-1"]
    assert current.status == "executing"
    assert "c-2" in harness._pending_actions
    harness.release_execution.set()
    confirmed = await asyncio.wait_for(confirm_task, timeout=1.0)

    assert confirmed["confirmed"] is True
    assert scheduler.get_task(task.id).enabled is False  # type: ignore[union-attr]
    assert current.status == "approved"
    assert "c-1" not in harness._pending_actions


@pytest.mark.asyncio
async def test_a1_two_factor_register_confirm_emits_audit_event(tmp_path) -> None:
    harness = _ConfirmationImplHarness(tmp_path)

    started = await harness.do_two_factor_register_begin(
        {"method": "totp", "user_id": "alice", "name": "ops-laptop"}
    )
    assert started["started"] is True

    confirmed = await harness.do_two_factor_register_confirm(
        {
            "enrollment_id": started["enrollment_id"],
            "verify_code": generate_totp_code(str(started["secret"])),
        }
    )

    assert confirmed["registered"] is True
    event = next(item for item in harness.published_events if isinstance(item, TwoFactorEnrolled))
    assert event.user_id == "alice"
    assert event.method == "totp"
    assert event.credential_id == confirmed["credential_id"]
    assert event.principal_id == "ops-laptop"


@pytest.mark.asyncio
async def test_a1_two_factor_revoke_emits_audit_event(tmp_path) -> None:
    harness = _ConfirmationImplHarness(tmp_path)
    factor = _register_totp_factor(harness)

    result = await harness.do_two_factor_revoke(
        {"method": "totp", "user_id": "alice", "credential_id": factor.credential_id}
    )

    assert result["revoked"] is True
    event = next(item for item in harness.published_events if isinstance(item, TwoFactorRevoked))
    assert event.user_id == "alice"
    assert event.method == "totp"
    assert event.credential_id == factor.credential_id
    assert event.principal_id == "ops-laptop"


@pytest.mark.asyncio
async def test_m1_d11_confirmation_reuses_pending_merged_policy_snapshot(tmp_path) -> None:
    harness = _ConfirmationImplHarness(tmp_path)
    pending = _pending_action(nonce="expected")
    pending.merged_policy = SimpleNamespace(snapshot="queue-time")
    _bind_pending_action_identity(pending)
    harness._pending_actions["c-1"] = pending

    result = await harness.do_action_confirm(
        {"confirmation_id": "c-1", "decision_nonce": "expected"}
    )

    assert result["confirmed"] is True
    assert harness.execution_merged_policies == [pending.merged_policy]


@pytest.mark.asyncio
async def test_f15_confirmation_rechecks_current_policy_before_effect(tmp_path: Path) -> None:
    harness = _ConfirmationImplHarness(tmp_path)
    pending = _pending_action(nonce="expected")
    _bind_pending_action_identity(pending)
    harness._pending_actions["c-1"] = pending
    harness._policy_loader.policy = PolicyBundle(
        default_require_confirmation=False,
        session_tool_allowlist=[ToolName("fs.read")],
    )

    result = await harness.do_action_confirm(
        {"confirmation_id": "c-1", "decision_nonce": "expected"}
    )

    assert result["confirmed"] is False
    assert result["status"] == "rejected"
    assert result["reason"] == "policy_changed_after_queue"
    assert pending.status_reason == "policy_changed_after_queue"
    assert harness.execution_kwargs == []


@pytest.mark.asyncio
async def test_f15_confirmation_preserves_direct_operator_override_semantics(
    tmp_path: Path,
) -> None:
    harness = _ConfirmationImplHarness(tmp_path)
    pending = _pending_action(nonce="expected")
    pending.preflight_action = ControlPlaneAction(
        tool_name="web.search",
        action_kind=ActionKind.EGRESS,
        origin=Origin(actor="control_api"),
        resource_id="https://example.com",
    )
    _bind_pending_action_identity(pending)
    harness._pending_actions["c-1"] = pending
    harness._policy_loader.policy = PolicyBundle(
        default_require_confirmation=False,
        session_tool_allowlist=[ToolName("fs.read")],
    )

    result = await harness.do_action_confirm(
        {"confirmation_id": "c-1", "decision_nonce": "expected"}
    )

    assert result["confirmed"] is True
    assert pending.status_reason != "policy_changed_after_queue"
    assert len(harness.execution_kwargs) == 1


@pytest.mark.asyncio
async def test_i1_confirmation_replays_direct_mcp_strip_intent(tmp_path) -> None:
    harness = _ConfirmationImplHarness(tmp_path)
    harness._registry.register(
        ToolDefinition(
            name=ToolName("mcp.docs.lookup-doc"),
            description="lookup documentation",
            parameters=[
                ToolParameter(name="session_id", type="string", required=True),
                ToolParameter(name="tool_name", type="string", required=True),
                ToolParameter(name="command", type="array", required=True),
                ToolParameter(name="query", type="string", required=True),
            ],
            capabilities_required=[Capability.HTTP_REQUEST],
        )
    )
    pending = _pending_action(nonce="expected")
    pending.tool_name = ToolName("mcp.docs.lookup-doc")
    pending.arguments = {
        "session_id": "s-1",
        "tool_name": "mcp.docs.lookup-doc",
        "command": ["mcp"],
        "query": "roadmap",
    }
    pending.strip_direct_tool_execute_envelope_keys = True
    tool_definition = harness._registry.get_tool(pending.tool_name)
    assert tool_definition is not None
    normalized_arguments = pep_arguments_for_policy_evaluation(
        pending.tool_name,
        pending.arguments,
    )
    pending.action_digest = compute_action_digest(
        tool_definition=tool_definition,
        arguments=normalized_arguments,
        destinations=resolve_confirmation_destinations(
            tool_definition=tool_definition,
            arguments=normalized_arguments,
        ),
    )
    assert pending.approval_envelope is not None
    pending.approval_envelope = pending.approval_envelope.model_copy(
        update={
            "action_digest": pending.action_digest,
            "approval_contract_hash": "",
        }
    )
    pending.approval_envelope = pending.approval_envelope.model_copy(
        update={"approval_contract_hash": pending_approval_contract_hash(pending)}
    )
    pending.approval_envelope_hash = approval_envelope_hash(pending.approval_envelope)
    harness._pending_actions["c-1"] = pending

    result = await harness.do_action_confirm(
        {"confirmation_id": "c-1", "decision_nonce": "expected"}
    )

    assert result["confirmed"] is True
    assert harness.execution_kwargs[0]["strip_direct_tool_execute_envelope_keys"] is True


@pytest.mark.asyncio
async def test_m6_s8_reject_requires_valid_decision_nonce(tmp_path) -> None:
    harness = _ConfirmationImplHarness(tmp_path)
    harness._pending_actions["c-1"] = _pending_action(nonce="expected")

    missing = await harness.do_action_reject({"confirmation_id": "c-1"})
    assert missing["rejected"] is False
    assert missing["reason"] == "missing_decision_nonce"

    invalid = await harness.do_action_reject({"confirmation_id": "c-1", "decision_nonce": "wrong"})
    assert invalid["rejected"] is False
    assert invalid["reason"] == "invalid_decision_nonce"

    valid = await harness.do_action_reject({"confirmation_id": "c-1", "decision_nonce": "expected"})
    assert valid["rejected"] is True
    assert valid["status"] == "rejected"


@pytest.mark.asyncio
async def test_f1_expired_reject_returns_approval_expired(tmp_path: Path) -> None:
    harness = _ConfirmationImplHarness(tmp_path)
    pending = _pending_action(nonce="expected")
    pending.expires_at = datetime.now(UTC) - timedelta(seconds=1)
    harness._pending_actions[pending.confirmation_id] = pending

    result = await harness.do_action_reject(
        {"confirmation_id": pending.confirmation_id, "decision_nonce": "expected"}
    )

    assert result["rejected"] is False
    assert result["reason"] == "approval_expired"
    assert result["status"] == "failed"
    assert result["status_reason"] == "approval_expired"
    assert pending.status == "failed"
    assert pending.status_reason == "approval_expired"


@pytest.mark.asyncio
async def test_f1_scheduler_expiry_and_late_decision_record_one_failed_outcome(
    tmp_path: Path,
) -> None:
    harness = _ConfirmationImplHarness(tmp_path)
    scheduler = SchedulerManager(storage_dir=tmp_path / "scheduler")
    task = scheduler.create_task(
        name="reminder:deployment-check",
        goal="Reminder: check deployment status",
        schedule=Schedule.from_event("message.received"),
        capability_snapshot={Capability.MESSAGE_SEND},
        policy_snapshot_ref="p1",
        created_by=UserId("alice"),
        workspace_id=WorkspaceId("w-1"),
        max_runs=1,
    )
    task.trigger_count = 1
    pending = _pending_action(nonce="expected")
    pending.task_id = task.id
    pending.expires_at = datetime.now(UTC) - timedelta(seconds=1)
    harness._pending_actions[pending.confirmation_id] = pending
    harness._scheduler = scheduler
    scheduler.queue_confirmation(
        task.id,
        {
            "confirmation_id": pending.confirmation_id,
            "task_id": task.id,
            "status": "pending",
            "lifecycle_state": "pending",
            "expires_at": pending.expires_at.isoformat(),
        },
    )

    assert scheduler.pending_confirmations(task.id) == []
    assert task.failure_count == 1

    result = await harness.do_action_reject(
        {"confirmation_id": pending.confirmation_id, "decision_nonce": "expected"}
    )

    assert result["reason"] == "approval_expired"
    assert task.failure_count == 1
    resolved = scheduler._pending_confirmations[task.id][0]
    assert resolved["run_outcome_recorded"] is True


@pytest.mark.asyncio
@pytest.mark.parametrize("execute_success", [True, False])
async def test_f1_inflight_confirmation_status_read_records_one_terminal_outcome(
    tmp_path: Path,
    execute_success: bool,
) -> None:
    class _SlowExecutionHarness(_ConfirmationImplHarness):
        def __init__(self, root: Path) -> None:
            super().__init__(root, execute_success=execute_success)
            self.execution_started = asyncio.Event()
            self.release_execution = asyncio.Event()

        async def _execute_approved_action(self, **kwargs: object) -> object:
            self.execution_started.set()
            await self.release_execution.wait()
            return await super()._execute_approved_action(**kwargs)  # type: ignore[arg-type]

    harness = _SlowExecutionHarness(tmp_path)
    scheduler = SchedulerManager(storage_dir=tmp_path / "scheduler-inflight")
    task = scheduler.create_task(
        name="reminder:inflight-check",
        goal="Reminder: finish the in-flight check",
        schedule=Schedule.from_event("message.received"),
        capability_snapshot={Capability.MESSAGE_SEND},
        policy_snapshot_ref="p1",
        created_by=UserId("alice"),
        workspace_id=WorkspaceId("w-1"),
        max_runs=1,
    )
    task.trigger_count = 1
    pending = _pending_action(nonce="expected")
    pending.task_id = task.id
    pending.expires_at = datetime.now(UTC) + timedelta(minutes=1)
    _bind_pending_action_identity(pending)
    harness._pending_actions[pending.confirmation_id] = pending
    harness._scheduler = scheduler
    scheduler.queue_confirmation(
        task.id,
        {
            "confirmation_id": pending.confirmation_id,
            "task_id": task.id,
            "status": "pending",
            "lifecycle_state": "pending",
            "expires_at": pending.expires_at.isoformat(),
        },
    )

    confirmation = asyncio.create_task(
        harness.do_action_confirm(
            {"confirmation_id": pending.confirmation_id, "decision_nonce": "expected"}
        )
    )
    await harness.execution_started.wait()
    expired_at = datetime.now(UTC) - timedelta(seconds=1)
    pending.expires_at = expired_at
    shadow = scheduler._pending_confirmations[task.id][0]
    shadow["expires_at"] = expired_at.isoformat()

    assert scheduler.pending_confirmations(task.id) == []
    assert pending.status == "executing"
    assert shadow["status"] == "executing"
    assert str(shadow["processing_started_at"])
    assert "resolved_at" not in shadow
    assert task.success_count == 0
    assert task.failure_count == 0

    harness.release_execution.set()
    result = await confirmation

    assert result["confirmed"] is execute_success
    assert task.success_count == int(execute_success)
    assert task.failure_count == int(not execute_success)
    assert shadow["run_outcome_recorded"] is True
    assert str(shadow["resolved_at"])


@pytest.mark.asyncio
@pytest.mark.parametrize("decision_nonce", [None, "wrong"])
async def test_f1_expired_reject_projects_expiry_before_nonce_validation(
    tmp_path: Path,
    decision_nonce: str | None,
) -> None:
    harness = _ConfirmationImplHarness(tmp_path)
    pending = _pending_action(nonce="expected")
    pending.expires_at = datetime.now(UTC) - timedelta(seconds=1)
    harness._pending_actions[pending.confirmation_id] = pending
    params: dict[str, object] = {"confirmation_id": pending.confirmation_id}
    if decision_nonce is not None:
        params["decision_nonce"] = decision_nonce

    result = await harness.do_action_reject(params)

    assert result["rejected"] is False
    assert result["reason"] == "approval_expired"
    assert result["status"] == "failed"
    assert result["status_reason"] == "approval_expired"
    assert pending.status == "failed"
    assert pending.status_reason == "approval_expired"


@pytest.mark.asyncio
async def test_a2_reject_requires_bound_channel_principal(tmp_path: Path) -> None:
    harness = _ConfirmationImplHarness(tmp_path)
    pending = _pending_action(nonce="expected")
    pending.delivery_target = DeliveryTarget(channel="discord", recipient="chan-1")
    pending.allowed_channel_principals = ["alice"]
    harness._pending_actions[pending.confirmation_id] = pending

    missing = await harness.do_action_reject(
        {"confirmation_id": "c-1", "decision_nonce": "expected"}
    )
    assert missing["rejected"] is False
    assert missing["reason"] == "missing_channel_principal"
    assert pending.status == "pending"

    wrong = await harness.do_action_reject(
        {
            "confirmation_id": "c-1",
            "decision_nonce": "expected",
            "principal_id": "bob",
        }
    )
    assert wrong["rejected"] is False
    assert wrong["reason"] == "channel_principal_not_allowed"
    assert pending.status == "pending"

    valid = await harness.do_action_reject(
        {
            "confirmation_id": "c-1",
            "decision_nonce": "expected",
            "principal_id": "alice",
        }
    )
    assert valid["rejected"] is True
    assert valid["status"] == "rejected"
    assert pending.status == "rejected"


@pytest.mark.asyncio
async def test_m1_pf11_confirmation_cooldown_active_and_expired(tmp_path) -> None:
    harness = _ConfirmationImplHarness(tmp_path)
    harness._pending_actions["c-1"] = _pending_action(
        nonce="expected",
        execute_after=datetime.now(UTC) + timedelta(seconds=30),
    )
    cooling = await harness.do_action_confirm(
        {"confirmation_id": "c-1", "decision_nonce": "expected"}
    )
    assert cooling["confirmed"] is False
    assert cooling["reason"] == "cooldown_active"
    assert float(cooling["retry_after_seconds"]) > 0

    harness = _ConfirmationImplHarness(tmp_path)
    now = datetime.now(UTC)
    expired_cooldown = _pending_action(nonce="expected")
    expired_cooldown.created_at = now - timedelta(seconds=5)
    expired_cooldown.execute_after = now - timedelta(seconds=1)
    _bind_pending_action_identity(expired_cooldown)
    harness._pending_actions["c-1"] = expired_cooldown
    expired = await harness.do_action_confirm(
        {"confirmation_id": "c-1", "decision_nonce": "expected"}
    )
    assert expired["confirmed"] is True
    assert expired["status"] == "approved"


@pytest.mark.asyncio
async def test_gh42_direct_confirmation_waits_short_cross_session_cooldown(
    tmp_path,
) -> None:
    harness = _ConfirmationImplHarness(tmp_path)
    first = _pending_action(nonce="nonce-a")
    first.confirmation_id = "c-a"
    first.session_id = SessionId("session-a")
    first.user_id = UserId("alice")
    first.workspace_id = WorkspaceId("workspace-a")
    second = _pending_action(
        nonce="nonce-b",
        execute_after=datetime.now(UTC) + timedelta(seconds=0.01),
    )
    second.confirmation_id = "c-b"
    second.session_id = SessionId("session-b")
    second.user_id = UserId("bob")
    second.workspace_id = WorkspaceId("workspace-b")
    second.tool_name = ToolName("web.fetch")
    second.arguments = {"url": "https://example.com/"}
    second.pep_context = _pep_context_snapshot(
        capabilities={Capability.HTTP_REQUEST},
    )
    _bind_pending_action_identity(first)
    _bind_pending_action_identity(second)
    harness._pending_actions[first.confirmation_id] = first
    harness._pending_actions[second.confirmation_id] = second

    confirmed_first = await harness.do_action_confirm(
        {"confirmation_id": "c-a", "decision_nonce": "nonce-a"}
    )
    confirmed_second = await harness.do_action_confirm(
        {"confirmation_id": "c-b", "decision_nonce": "nonce-b"}
    )

    assert confirmed_first["confirmed"] is True
    assert confirmed_second["confirmed"] is True
    assert confirmed_second["status"] == "approved"
    assert "retry_after_seconds" not in confirmed_second
    assert [call["approval_confirmation_id"] for call in harness.execution_kwargs] == [
        "c-a",
        "c-b",
    ]


@pytest.mark.asyncio
async def test_gh42_direct_confirmation_rechecks_expiry_after_short_cooldown(
    tmp_path,
) -> None:
    harness = _ConfirmationImplHarness(tmp_path)
    now = datetime.now(UTC)
    pending = _pending_action(
        nonce="expected",
        execute_after=now + timedelta(seconds=0.03),
    )
    pending.expires_at = now + timedelta(seconds=0.04)
    _bind_pending_action_identity(pending)
    harness._pending_actions["c-1"] = pending

    result = await harness.do_action_confirm(
        {"confirmation_id": "c-1", "decision_nonce": "expected"}
    )

    assert result["confirmed"] is False
    assert result["reason"] == "approval_expired"
    assert result["status"] == "failed"
    assert pending.status == "failed"
    assert pending.status_reason == "approval_expired"
    assert harness.execution_kwargs == []


@pytest.mark.asyncio
async def test_gh42_direct_confirmation_serializes_same_cid_cooldown_wait(
    tmp_path,
) -> None:
    class _SlowExecutionHarness(_ConfirmationImplHarness):
        async def _execute_approved_action(self, **kwargs: object) -> object:
            await asyncio.sleep(0.02)
            return await super()._execute_approved_action(**kwargs)  # type: ignore[arg-type]

    harness = _SlowExecutionHarness(tmp_path)
    pending = _pending_action(
        nonce="expected",
        execute_after=datetime.now(UTC) + timedelta(seconds=0.05),
    )
    harness._pending_actions["c-1"] = pending

    results = await asyncio.gather(
        harness.do_action_confirm({"confirmation_id": "c-1", "decision_nonce": "expected"}),
        harness.do_action_confirm({"confirmation_id": "c-1", "decision_nonce": "expected"}),
        return_exceptions=True,
    )

    assert all(not isinstance(result, Exception) for result in results)
    payloads = [result for result in results if isinstance(result, dict)]
    assert len([result for result in payloads if result.get("confirmed") is True]) == 1
    assert len([result for result in payloads if result.get("reason") == "already_approved"]) == 1
    assert len(harness.execution_kwargs) == 1
    assert harness.execution_kwargs[0]["approval_confirmation_id"] == "c-1"


@pytest.mark.asyncio
async def test_gh42_direct_confirmation_reject_can_cancel_during_short_cooldown(
    tmp_path,
) -> None:
    harness = _ConfirmationImplHarness(tmp_path)
    pending = _pending_action(
        nonce="expected",
        execute_after=datetime.now(UTC) + timedelta(seconds=0.08),
    )
    harness._pending_actions["c-1"] = pending

    confirm_task = asyncio.create_task(
        harness.do_action_confirm({"confirmation_id": "c-1", "decision_nonce": "expected"})
    )
    await asyncio.sleep(0)
    rejected = await harness.do_action_reject(
        {
            "confirmation_id": "c-1",
            "decision_nonce": "expected",
            "reason": "operator_changed_mind",
        }
    )
    confirmed = await confirm_task

    assert rejected["rejected"] is True
    assert rejected["status"] == "rejected"
    assert rejected["status_reason"] == "operator_changed_mind"
    assert confirmed["confirmed"] is False
    assert confirmed["reason"] == "already_rejected"
    assert pending.status == "rejected"
    assert len(harness.execution_kwargs) == 0


@pytest.mark.asyncio
async def test_gh42_direct_confirmation_serializes_reject_during_confirm_execution(
    tmp_path,
) -> None:
    class _SlowExecutionHarness(_ConfirmationImplHarness):
        def __init__(self, tmp_path: Path) -> None:
            super().__init__(tmp_path)
            self.execution_started = asyncio.Event()

        async def _execute_approved_action(self, **kwargs: object) -> object:
            self.execution_started.set()
            await asyncio.sleep(0.02)
            return await super()._execute_approved_action(**kwargs)  # type: ignore[arg-type]

    harness = _SlowExecutionHarness(tmp_path)
    harness._pending_actions["c-1"] = _pending_action(nonce="expected")

    confirm_task = asyncio.create_task(
        harness.do_action_confirm({"confirmation_id": "c-1", "decision_nonce": "expected"})
    )
    await harness.execution_started.wait()
    rejected = await harness.do_action_reject(
        {
            "confirmation_id": "c-1",
            "decision_nonce": "expected",
            "reason": "operator_changed_mind",
        }
    )
    confirmed = await confirm_task

    assert confirmed["confirmed"] is True
    assert rejected["rejected"] is False
    assert rejected["reason"] == "already_approved"
    assert len(harness.execution_kwargs) == 1
    assert harness._pending_actions["c-1"].status == "approved"


@pytest.mark.asyncio
async def test_gh42_action_confirmation_locks_do_not_leak_for_not_found_or_terminal(
    tmp_path,
) -> None:
    harness = _ConfirmationImplHarness(tmp_path)

    for index in range(3):
        missing = await harness.do_action_confirm(
            {"confirmation_id": f"missing-{index}", "decision_nonce": "unused"}
        )
        assert missing["reason"] == "not_found"

    assert getattr(harness, "_action_confirmation_locks", {}) == {}

    harness._pending_actions["c-1"] = _pending_action(nonce="expected")
    confirmed = await harness.do_action_confirm(
        {"confirmation_id": "c-1", "decision_nonce": "expected"}
    )

    assert confirmed["confirmed"] is True
    assert getattr(harness, "_action_confirmation_locks", {}) == {}


@pytest.mark.asyncio
async def test_gh42_action_confirmation_lock_cleanup_keeps_woken_waiter(
    tmp_path,
) -> None:
    harness = _ConfirmationImplHarness(tmp_path)
    lock = harness._action_confirmation_lock("c-1")
    await lock.acquire()
    waiter = asyncio.create_task(lock.acquire())
    await asyncio.sleep(0)

    lock.release()
    harness._discard_action_confirmation_lock_if_idle("c-1", lock)

    assert getattr(harness, "_action_confirmation_locks", {})["c-1"] is lock

    await waiter
    lock.release()
    harness._discard_action_confirmation_lock_if_idle("c-1", lock)

    assert getattr(harness, "_action_confirmation_locks", {}) == {}


@pytest.mark.asyncio
async def test_gh42_pending_purge_excludes_inflight_confirmation(tmp_path) -> None:
    class _SlowExecutionHarness(_ConfirmationImplHarness):
        def __init__(self, tmp_path: Path) -> None:
            super().__init__(tmp_path)
            self.execution_started = asyncio.Event()
            self.release_execution = asyncio.Event()

        async def _execute_approved_action(self, **kwargs: object) -> object:
            self.execution_started.set()
            await self.release_execution.wait()
            return await super()._execute_approved_action(**kwargs)  # type: ignore[arg-type]

    harness = _SlowExecutionHarness(tmp_path)
    pending = _pending_action(nonce="expected")
    pending.created_at = datetime.now(UTC) - timedelta(days=10)
    _bind_pending_action_identity(pending)
    harness._pending_actions["c-1"] = pending
    harness._pending_by_session[pending.session_id] = ["c-1"]

    confirm_task = asyncio.create_task(
        harness.do_action_confirm({"confirmation_id": "c-1", "decision_nonce": "expected"})
    )
    await harness.execution_started.wait()

    purge_task = asyncio.create_task(
        harness.do_action_purge({"status": "pending", "older_than_days": 7, "limit": 10})
    )
    purged = await asyncio.wait_for(purge_task, timeout=1.0)

    assert purged["purged"] == 0
    assert pending.status == "executing"
    assert "c-1" in harness._pending_actions
    harness.release_execution.set()
    confirmed = await confirm_task

    assert confirmed["confirmed"] is True
    assert "c-1" in harness._pending_actions
    assert harness._pending_actions["c-1"].status == "approved"
    assert harness._pending_by_session[pending.session_id] == ["c-1"]
    assert len(harness.execution_kwargs) == 1


@pytest.mark.asyncio
async def test_m1_rlc3_stage2_fallback_confirmation_uses_low_risk_tier(tmp_path) -> None:
    harness = _ConfirmationImplHarness(tmp_path, allow_amendment=True)
    pending = _pending_action(nonce="expected")
    pending.reason = "trace:stage2_upgrade_required"
    pending.preflight_action = None
    _bind_pending_action_identity(pending)
    harness._pending_actions["c-1"] = pending

    result = await harness.do_action_confirm(
        {"confirmation_id": "c-1", "decision_nonce": "expected"}
    )
    assert result["confirmed"] is True
    assert harness._control_plane.approved_actions
    approved = harness._control_plane.approved_actions[0]
    assert getattr(approved, "risk_tier", None) == RiskTier.LOW


@pytest.mark.asyncio
async def test_trace_only_capability_elevation_rechecks_pep_and_executes(tmp_path) -> None:
    harness = _ConfirmationImplHarness(tmp_path, allow_amendment=True)
    pending = _pending_action(nonce="expected")
    pending.tool_name = ToolName("web.fetch")
    pending.arguments = {"url": "https://example.com"}
    pending.reason = "trace:stage2_upgrade_required"
    pending.capabilities = set()
    pending.pep_context = _pep_context_snapshot(capabilities=set())
    pending.pep_elevation = PendingPepElevationRequest(
        kind="capability_grant",
        reason_code="pep:missing_capabilities",
        capability_grants={Capability.HTTP_REQUEST},
    )
    _bind_pending_action_identity(pending)
    harness._pending_actions["c-1"] = pending

    result = await harness.do_action_confirm(
        {"confirmation_id": "c-1", "decision_nonce": "expected"}
    )

    assert result["confirmed"] is True
    assert len(harness.execution_kwargs) == 1
    assert harness.execution_kwargs[0]["tool_name"] == "web.fetch"
    assert harness.execution_kwargs[0]["capabilities"] == ["http.request"]


@pytest.mark.asyncio
async def test_trace_only_capability_elevation_fails_closed_when_pep_still_rejects(
    tmp_path,
) -> None:
    harness = _ConfirmationImplHarness(tmp_path, allow_amendment=True)
    pending = _pending_action(nonce="expected")
    pending.tool_name = ToolName("web.fetch")
    pending.arguments = {}
    pending.reason = "trace:stage2_upgrade_required"
    pending.capabilities = set()
    pending.pep_context = _pep_context_snapshot(capabilities=set())
    pending.pep_elevation = PendingPepElevationRequest(
        kind="capability_grant",
        reason_code="pep:missing_capabilities",
        capability_grants={Capability.HTTP_REQUEST},
    )
    _bind_pending_action_identity(pending)
    harness._pending_actions["c-1"] = pending

    result = await harness.do_action_confirm(
        {"confirmation_id": "c-1", "decision_nonce": "expected"}
    )

    assert result["confirmed"] is False
    assert result["status"] == "rejected"
    assert result["status_reason"] == "pep:schema_validation_failed"
    assert harness.execution_kwargs == []


@pytest.mark.asyncio
async def test_trace_only_capability_elevation_fails_closed_when_pep_requires_stronger_confirmation(
    tmp_path,
) -> None:
    harness = _ConfirmationImplHarness(tmp_path, allow_amendment=True)
    harness._policy_loader.policy = PolicyBundle.model_validate(
        {
            "default_require_confirmation": False,
            "tools": {
                "web.fetch": {
                    "confirmation": {
                        "level": "bound_approval",
                    }
                }
            },
        }
    )
    pending = _pending_action(nonce="expected")
    pending.tool_name = ToolName("web.fetch")
    pending.arguments = {"url": "https://example.com"}
    pending.reason = "trace:stage2_upgrade_required"
    pending.capabilities = set()
    pending.pep_context = _pep_context_snapshot(capabilities=set())
    pending.pep_elevation = PendingPepElevationRequest(
        kind="capability_grant",
        reason_code="pep:missing_capabilities",
        capability_grants={Capability.HTTP_REQUEST},
    )
    _bind_pending_action_identity(pending)
    harness._pending_actions["c-1"] = pending

    result = await harness.do_action_confirm(
        {"confirmation_id": "c-1", "decision_nonce": "expected"}
    )

    assert result["confirmed"] is False
    assert result["status"] == "rejected"
    assert result["status_reason"] == "confirmation_requirement_unsatisfied_after_confirmation"
    assert pending.confirmation_evidence is not None
    rejected = next(
        event for event in reversed(harness.published_events) if isinstance(event, ToolRejected)
    )
    assert rejected.approval_level == ConfirmationLevel.SOFTWARE.value
    assert rejected.approval_method == "software"
    assert rejected.approval_evidence_hash == pending.confirmation_evidence.evidence_hash
    assert harness.execution_kwargs == []


@pytest.mark.asyncio
async def test_trace_only_capability_elevation_accepts_explicit_fallback_confirmation(
    tmp_path,
) -> None:
    harness = _ConfirmationImplHarness(tmp_path, allow_amendment=True)
    harness.set_policy(
        PolicyBundle.model_validate(
            {
                "default_require_confirmation": False,
                "tools": {
                    "web.fetch": {
                        "confirmation": {
                            "level": "bound_approval",
                            "fallback": {
                                "mode": "allow_levels",
                                "allow_levels": ["software"],
                            },
                        }
                    }
                },
            }
        ),
    )
    pending = _pending_action(nonce="expected")
    pending.tool_name = ToolName("web.fetch")
    pending.arguments = {"url": "https://example.com"}
    pending.reason = "trace:stage2_upgrade_required"
    pending.capabilities = set()
    pending.required_level = ConfirmationLevel.BOUND_APPROVAL
    pending.fallback = ConfirmationFallbackPolicy(
        mode="allow_levels",
        allow_levels=[ConfirmationLevel.SOFTWARE],
    )
    pending.fallback_used = True
    pending.approval_envelope = _software_approval_envelope(
        tool_name=ToolName("web.fetch")
    ).model_copy(update={"required_level": ConfirmationLevel.BOUND_APPROVAL})
    pending.approval_envelope_hash = approval_envelope_hash(pending.approval_envelope)
    pending.pep_context = _pep_context_snapshot(capabilities=set())
    pending.pep_elevation = PendingPepElevationRequest(
        kind="capability_grant",
        reason_code="pep:missing_capabilities",
        capability_grants={Capability.HTTP_REQUEST},
    )
    _bind_pending_action_identity(pending)
    harness._pending_actions["c-1"] = pending

    result = await harness.do_action_confirm(
        {"confirmation_id": "c-1", "decision_nonce": "expected"}
    )

    assert result["confirmed"] is True
    assert result["status"] == "approved"
    assert result["approval_level"] == ConfirmationLevel.SOFTWARE.value
    assert harness.execution_kwargs[0]["tool_name"] == "web.fetch"
    assert harness.execution_kwargs[0]["capabilities"] == ["http.request"]


@pytest.mark.asyncio
async def test_h1_confirmation_returns_plan_state_failure_when_stage2_amend_rejected(
    tmp_path,
) -> None:
    harness = _ConfirmationImplHarness(tmp_path, allow_amendment=True)

    class _RejectingControlPlane:
        def active_plan_hash(self, _session_id: str) -> str:
            return ""

        def approve_stage2(
            self,
            *,
            action: object,
            approved_by: str,
            correlation_id: str = "",
            expected_previous_hash: str = "",
            execution_idempotency_key: str = "",
        ) -> str:
            _ = (
                action,
                approved_by,
                correlation_id,
                expected_previous_hash,
                execution_idempotency_key,
            )
            raise ControlPlaneRpcError(
                message="cannot amend missing or inactive plan",
                reason_code="rpc.invalid_params",
            )

    harness._control_plane = _RejectingControlPlane()
    pending = _pending_action(nonce="expected")
    pending.reason = "trace:stage2_upgrade_required"
    _bind_pending_action_identity(pending)
    harness._pending_actions["c-1"] = pending

    result = await harness.do_action_confirm(
        {"confirmation_id": "c-1", "decision_nonce": "expected"}
    )

    assert result["confirmed"] is False
    assert result["reason"] == "plan_missing_or_inactive"
    assert result["status"] == "failed"
    assert pending.status_reason == "plan_missing_or_inactive"


@pytest.mark.asyncio
async def test_m4_confirmation_endorses_promoted_evidence_and_passes_provenance(
    tmp_path,
) -> None:
    harness = _ConfirmationImplHarness(tmp_path)
    harness._session.channel = "discord"
    delivery_target = DeliveryTarget(
        channel="discord",
        recipient="room-a",
        workspace_hint="guild-1",
        thread_id="thread-1",
    )
    ref = harness._evidence_store.store(
        SessionId("s-1"),
        "promoted body",
        taint_labels={TaintLabel.UNTRUSTED},
        source="web.fetch:example.com",
        summary="promoted body",
    )
    pending = PendingAction(
        confirmation_id="c-1",
        decision_nonce="expected",
        session_id=SessionId("s-1"),
        user_id=UserId("alice"),
        workspace_id=WorkspaceId("w-1"),
        tool_name=ToolName("evidence.promote"),
        arguments={"ref_id": ref.ref_id},
        reason="manual",
        capabilities={Capability.MEMORY_READ},
        created_at=datetime.now(UTC),
        delivery_target=delivery_target,
        approval_task_envelope_id="env-task-1",
        approval_envelope=_software_approval_envelope(tool_name=ToolName("evidence.promote")),
        approval_envelope_hash=approval_envelope_hash(
            _software_approval_envelope(tool_name=ToolName("evidence.promote"))
        ),
        selected_backend_id="software.default",
        selected_backend_method="software",
    )
    _bind_pending_action_identity(pending)
    harness._pending_actions[pending.confirmation_id] = pending

    result = await harness.do_action_confirm(
        {"confirmation_id": "c-1", "decision_nonce": "expected"}
    )

    assert result["confirmed"] is True
    endorsed = harness._evidence_store.get_ref(SessionId("s-1"), ref.ref_id)
    assert endorsed is not None
    assert endorsed.endorsement_state == ArtifactEndorsementState.USER_ENDORSED
    assert endorsed.endorsed_by == "human_confirmation"
    assert endorsed.endorsed_at == datetime.fromisoformat(
        str(harness.execution_kwargs[0]["approval_timestamp"])
    )
    assert len(harness.execution_kwargs) == 1
    assert harness.execution_kwargs[0]["tool_name"] == "evidence.promote"
    assert harness.execution_kwargs[0]["approval_confirmation_id"] == "c-1"
    assert harness.execution_kwargs[0]["approval_decision_nonce"] == "expected"
    assert harness.execution_kwargs[0]["approval_task_envelope_id"] == "env-task-1"
    assert str(harness.execution_kwargs[0]["approval_timestamp"]).strip()
    transcript_entries = harness._transcript_store.list_entries(SessionId("s-1"))
    assert transcript_entries[-1].metadata["promoted_evidence"] is True
    assert transcript_entries[-1].metadata["promoted_ref_id"] == ref.ref_id
    assert transcript_entries[-1].metadata["user_id"] == "alice"
    assert transcript_entries[-1].metadata["workspace_id"] == "w-1"
    assert transcript_entries[-1].metadata["channel"] == "discord"
    assert transcript_entries[-1].metadata["delivery_target"] == delivery_target.model_dump(
        mode="json"
    )
    timeline = TimelineIndex(
        tmp_path / "timeline-promoted-evidence",
        transcript_store=harness._transcript_store,
        session_lookup=lambda _sid: None,
    )
    assert timeline.rebuild_session(SessionId("s-1")) == 1
    result = timeline.search(
        query="promoted body",
        user_id="alice",
        workspace_id="w-1",
        context_channel="discord",
        context_delivery_target=delivery_target.model_dump(mode="json"),
    )
    assert result.results_count == 1


@pytest.mark.asyncio
async def test_gh34_confirmation_evidence_promote_alias_uses_canonical_followup(
    tmp_path,
) -> None:
    harness = _ConfirmationImplHarness(tmp_path)
    ref = harness._evidence_store.store(
        SessionId("s-1"),
        "promoted body",
        taint_labels={TaintLabel.UNTRUSTED},
        source="web.fetch:example.com",
        summary="promoted body",
    )
    envelope = _software_approval_envelope(tool_name=ToolName("evidence-promote"))
    pending = PendingAction(
        confirmation_id="c-1",
        decision_nonce="expected",
        session_id=SessionId("s-1"),
        user_id=UserId("alice"),
        workspace_id=WorkspaceId("w-1"),
        tool_name=ToolName("evidence-promote"),
        arguments={"ref_id": ref.ref_id},
        reason="manual",
        capabilities={Capability.MEMORY_READ},
        created_at=datetime.now(UTC),
        approval_envelope=envelope,
        approval_envelope_hash=approval_envelope_hash(envelope),
        selected_backend_id="software.default",
        selected_backend_method="software",
    )
    _bind_pending_action_identity(pending)
    harness._pending_actions[pending.confirmation_id] = pending

    result = await harness.do_action_confirm(
        {"confirmation_id": "c-1", "decision_nonce": "expected"}
    )

    assert result["confirmed"] is True
    endorsed = harness._evidence_store.get_ref(SessionId("s-1"), ref.ref_id)
    assert endorsed is not None
    assert endorsed.endorsement_state == ArtifactEndorsementState.USER_ENDORSED
    transcript_entries = harness._transcript_store.list_entries(SessionId("s-1"))
    assert len(transcript_entries) == 1
    assert transcript_entries[0].metadata["promoted_evidence"] is True
    assert transcript_entries[0].metadata["promoted_ref_id"] == ref.ref_id
    assert transcript_entries[0].metadata.get("tool_name") is None


@pytest.mark.asyncio
async def test_m4_failed_confirmed_promote_does_not_endorse_artifact(tmp_path) -> None:
    harness = _ConfirmationImplHarness(tmp_path, execute_success=False)
    ref = harness._evidence_store.store(
        SessionId("s-1"),
        "promoted body",
        taint_labels={TaintLabel.UNTRUSTED},
        source="web.fetch:example.com",
        summary="promoted body",
    )
    pending = PendingAction(
        confirmation_id="c-1",
        decision_nonce="expected",
        session_id=SessionId("s-1"),
        user_id=UserId("alice"),
        workspace_id=WorkspaceId("w-1"),
        tool_name=ToolName("evidence.promote"),
        arguments={"ref_id": ref.ref_id},
        reason="manual",
        capabilities={Capability.MEMORY_READ},
        created_at=datetime.now(UTC),
        approval_envelope=_software_approval_envelope(tool_name=ToolName("evidence.promote")),
        approval_envelope_hash=approval_envelope_hash(
            _software_approval_envelope(tool_name=ToolName("evidence.promote"))
        ),
        selected_backend_id="software.default",
        selected_backend_method="software",
    )
    _bind_pending_action_identity(pending)
    harness._pending_actions[pending.confirmation_id] = pending

    result = await harness.do_action_confirm(
        {"confirmation_id": "c-1", "decision_nonce": "expected"}
    )

    assert result["confirmed"] is False
    endorsed = harness._evidence_store.get_ref(SessionId("s-1"), ref.ref_id)
    assert endorsed is not None
    assert endorsed.endorsement_state == ArtifactEndorsementState.UNENDORSED
    pep = PEP(
        PolicyBundle(default_require_confirmation=False),
        _registry_for_evidence(),
        evidence_store=harness._evidence_store,
    )
    decision = pep.evaluate(
        ToolName("evidence.promote"),
        {"ref_id": ref.ref_id},
        PolicyContext(capabilities={Capability.MEMORY_READ}, session_id=SessionId("s-1")),
    )
    assert decision.kind.value == "require_confirmation"


@pytest.mark.asyncio
async def test_gh47_confirmation_preserves_runtime_unavailable_execution_reason(
    tmp_path,
) -> None:
    reason = "browser_runtime_unavailable:misconfigured:browser_command_unconfigured"
    harness = _ConfirmationImplHarness(
        tmp_path,
        execute_success=False,
        execution_error=reason,
    )
    pending = _pending_action(nonce="expected")
    pending.tool_name = ToolName("browser.click")
    pending.arguments = {"target": "continue", "description": "continue"}
    pending.approval_envelope = _software_approval_envelope(tool_name=pending.tool_name)
    _bind_pending_action_identity(pending)
    harness._pending_actions[pending.confirmation_id] = pending

    result = await harness.do_action_confirm(
        {"confirmation_id": "c-1", "decision_nonce": "expected"}
    )

    assert result["confirmed"] is False
    assert result["status"] == "failed"
    assert result["status_reason"] == reason
    assert harness._pending_actions["c-1"].status_reason == reason


@pytest.mark.asyncio
async def test_gh47_confirmation_preserves_unstructured_execution_error(
    tmp_path,
) -> None:
    harness = _ConfirmationImplHarness(
        tmp_path,
        execute_success=False,
        execution_error="tool_unavailable",
        execution_error_tool_output=False,
    )
    pending = _pending_action(nonce="expected")
    harness._pending_actions[pending.confirmation_id] = pending

    result = await harness.do_action_confirm(
        {
            "confirmation_id": "c-1",
            "decision_nonce": "expected",
            "reason": "planner_action_resolve",
        }
    )

    assert result["confirmed"] is False
    assert result["status_reason"] == "tool_unavailable"
    assert result["status_reason"] != "planner_action_resolve"


@pytest.mark.asyncio
async def test_m4_endorsement_failure_rolls_back_promoted_transcript_entry(tmp_path) -> None:
    harness = _ConfirmationImplHarness(tmp_path)
    ref = harness._evidence_store.store(
        SessionId("s-1"),
        "promoted body",
        taint_labels={TaintLabel.UNTRUSTED},
        source="web.fetch:example.com",
        summary="promoted body",
    )
    pending = PendingAction(
        confirmation_id="c-1",
        decision_nonce="expected",
        session_id=SessionId("s-1"),
        user_id=UserId("alice"),
        workspace_id=WorkspaceId("w-1"),
        tool_name=ToolName("evidence.promote"),
        arguments={"ref_id": ref.ref_id},
        reason="manual",
        capabilities={Capability.MEMORY_READ},
        created_at=datetime.now(UTC),
        approval_envelope=_software_approval_envelope(tool_name=ToolName("evidence.promote")),
        approval_envelope_hash=approval_envelope_hash(
            _software_approval_envelope(tool_name=ToolName("evidence.promote"))
        ),
        selected_backend_id="software.default",
        selected_backend_method="software",
    )
    _bind_pending_action_identity(pending)
    harness._pending_actions[pending.confirmation_id] = pending

    original_endorse = harness._evidence_store.endorse

    def _fail_endorse(*args, **kwargs):
        raise OSError("endorse failed after promote")

    harness._evidence_store.endorse = _fail_endorse  # type: ignore[method-assign]
    try:
        result = await harness.do_action_confirm(
            {"confirmation_id": "c-1", "decision_nonce": "expected"}
        )
    finally:
        harness._evidence_store.endorse = original_endorse  # type: ignore[method-assign]

    assert result["confirmed"] is False
    assert result["status_reason"] == "artifact_endorse_failed"
    assert harness._transcript_store.list_entries(SessionId("s-1")) == []
    endorsed = harness._evidence_store.get_ref(SessionId("s-1"), ref.ref_id)
    assert endorsed is not None
    assert endorsed.endorsement_state == ArtifactEndorsementState.UNENDORSED
    pep = PEP(
        PolicyBundle(default_require_confirmation=False),
        _registry_for_evidence(),
        evidence_store=harness._evidence_store,
    )
    decision = pep.evaluate(
        ToolName("evidence.promote"),
        {"ref_id": ref.ref_id},
        PolicyContext(capabilities={Capability.MEMORY_READ}, session_id=SessionId("s-1")),
    )
    assert decision.kind.value == "require_confirmation"


@pytest.mark.asyncio
async def test_m4_promote_confirmation_fails_closed_when_transcript_snapshot_read_fails(
    tmp_path,
) -> None:
    harness = _ConfirmationImplHarness(tmp_path)
    ref = harness._evidence_store.store(
        SessionId("s-1"),
        "promoted body",
        taint_labels={TaintLabel.UNTRUSTED},
        source="web.fetch:example.com",
        summary="promoted body",
    )
    pending = PendingAction(
        confirmation_id="c-1",
        decision_nonce="expected",
        session_id=SessionId("s-1"),
        user_id=UserId("alice"),
        workspace_id=WorkspaceId("w-1"),
        tool_name=ToolName("evidence.promote"),
        arguments={"ref_id": ref.ref_id},
        reason="manual",
        capabilities={Capability.MEMORY_READ},
        created_at=datetime.now(UTC),
        approval_envelope=_software_approval_envelope(tool_name=ToolName("evidence.promote")),
        approval_envelope_hash=approval_envelope_hash(
            _software_approval_envelope(tool_name=ToolName("evidence.promote"))
        ),
        selected_backend_id="software.default",
        selected_backend_method="software",
    )
    _bind_pending_action_identity(pending)
    harness._pending_actions[pending.confirmation_id] = pending

    original_list_entries = harness._transcript_store.list_entries

    def _fail_list_entries(_session_id: SessionId):
        raise OSError("transcript read failed")

    harness._transcript_store.list_entries = _fail_list_entries  # type: ignore[method-assign]
    try:
        result = await harness.do_action_confirm(
            {"confirmation_id": "c-1", "decision_nonce": "expected"}
        )
    finally:
        harness._transcript_store.list_entries = original_list_entries  # type: ignore[method-assign]

    assert result["confirmed"] is False
    assert result["status_reason"] == "artifact_endorse_failed"
    endorsed = harness._evidence_store.get_ref(SessionId("s-1"), ref.ref_id)
    assert endorsed is not None
    assert endorsed.endorsement_state == ArtifactEndorsementState.UNENDORSED
