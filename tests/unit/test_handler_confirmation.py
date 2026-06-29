"""Unit checks for confirmation handler wrappers."""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest

from shisad.channels.base import DeliveryTarget
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
    ConfirmationFallbackPolicy,
    ConfirmationLevel,
    ConfirmationMethodLockoutTracker,
    ConfirmationRequirement,
    IntentAction,
    IntentEnvelope,
    IntentPolicyContext,
    SoftwareConfirmationBackend,
    TOTPBackend,
    approval_envelope_hash,
    generate_totp_code,
    hash_recovery_code,
    intent_envelope_hash,
)
from shisad.core.events import TwoFactorEnrolled, TwoFactorRevoked
from shisad.core.evidence import ArtifactEndorsementState, EvidenceStore
from shisad.core.tools.names import canonical_tool_name
from shisad.core.tools.registry import ToolRegistry
from shisad.core.tools.schema import ToolDefinition, ToolParameter
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
from shisad.daemon.handlers._pending_approval import (
    PendingPepContextSnapshot,
    PendingPepElevationRequest,
)
from shisad.daemon.handlers.confirmation import ConfirmationHandlers
from shisad.memory.timeline import TimelineIndex
from shisad.security.control_plane.schema import ActionKind, ControlPlaneAction, Origin, RiskTier
from shisad.security.control_plane.sidecar import ControlPlaneRpcError
from shisad.security.credentials import (
    ApprovalFactorRecord,
    InMemoryCredentialStore,
    RecoveryCodeRecord,
)
from shisad.security.leakcheck import CrossThreadLeakDetector
from shisad.security.pep import PEP, PolicyContext
from shisad.security.policy import PolicyBundle
from shisad.ui.confirmation import ConfirmationWarningGenerator
from tests.helpers.signer import generate_secp256k1_private_key, public_key_pem


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
    return registry


class _ControlPlaneRecorder:
    def __init__(self) -> None:
        self.approved_actions: list[object] = []

    def active_plan_hash(self, _session_id: str) -> str:
        return "plan-before"

    def approve_stage2(self, *, action: object, approved_by: str) -> str:
        _ = approved_by
        self.approved_actions.append(action)
        return "plan-after"


class _SchedulerRecorder:
    def __init__(self) -> None:
        self.resolved_confirmations: list[dict[str, object]] = []
        self.run_outcomes: list[dict[str, object]] = []

    def resolve_confirmation(
        self,
        task_id: str,
        *,
        confirmation_id: str,
        status: str,
        status_reason: str = "",
    ) -> bool:
        self.resolved_confirmations.append(
            {
                "task_id": task_id,
                "confirmation_id": confirmation_id,
                "status": status,
                "status_reason": status_reason,
            }
        )
        return True

    def record_run_outcome(self, task_id: str, *, success: bool) -> bool:
        self.run_outcomes.append({"task_id": task_id, "success": success})
        return True


class _ApprovalWebRecorder:
    enabled = True

    def __init__(self) -> None:
        self.issued: list[str] = []

    def issue_approval_link(self, confirmation_id: str) -> str:
        self.issued.append(confirmation_id)
        return f"https://approvals.test/{confirmation_id}"

    def qr_ascii(self, approval_url: str) -> str:
        return f"QR {approval_url}"


class _DeliveryRecorder:
    def __init__(self) -> None:
        self.messages: list[dict[str, object]] = []

    async def send(self, *, target: DeliveryTarget, message: str) -> object:
        self.messages.append({"target": target, "message": message})
        return SimpleNamespace(attempted=True, sent=True, reason="sent", target=target)


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
        self._lockdown_manager = SimpleNamespace(should_block_all_actions=lambda _sid: False)
        self.published_events: list[object] = []
        self._event_bus = SimpleNamespace(publish=self._noop_publish)
        self._session = SimpleNamespace(
            channel="cli",
            mode=SessionMode.DEFAULT,
            workspace_id=WorkspaceId("w-1"),
        )
        self._session_manager = SimpleNamespace(get=lambda _sid: self._session)
        self._policy_loader = SimpleNamespace(
            policy=SimpleNamespace(
                control_plane=SimpleNamespace(
                    trace=SimpleNamespace(allow_amendment=allow_amendment)
                )
            )
        )
        self._control_plane = _ControlPlaneRecorder()
        self._confirmation_analytics = SimpleNamespace(record=lambda **_kwargs: None)
        self._confirmation_backend_registry = ConfirmationBackendRegistry()
        self._credential_store = InMemoryCredentialStore()
        self._credential_store.set_approval_store_path(tmp_path / "approval-factors.json")
        self._pending_two_factor_enrollments: dict[str, object] = {}
        self._confirmation_backend_registry.register(SoftwareConfirmationBackend())
        self._confirmation_backend_registry.register(
            TOTPBackend(credential_store=self._credential_store)
        )
        self._confirmation_failure_tracker = ConfirmationMethodLockoutTracker()
        self.execution_merged_policies: list[object | None] = []
        self.execution_kwargs: list[dict[str, object]] = []
        self._transcript_store = TranscriptStore(tmp_path / "sessions")
        self._evidence_store = EvidenceStore(tmp_path / "evidence", salt=b"a" * 32)
        self._execute_success = execute_success
        self._execution_error = execution_error
        self._execution_error_tool_output = execution_error_tool_output
        self.persist_calls = 0
        self._pep = PEP(
            PolicyBundle(default_require_confirmation=False),
            _registry_for_confirmation(),
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


def _pending_action(*, nonce: str, execute_after: datetime | None = None) -> PendingAction:
    envelope = _software_approval_envelope(tool_name=ToolName("web.search"))
    return PendingAction(
        confirmation_id="c-1",
        decision_nonce=nonce,
        session_id=SessionId("s-1"),
        user_id=UserId("alice"),
        workspace_id=WorkspaceId("w-1"),
        tool_name=ToolName("web.search"),
        arguments={"query": "hello"},
        reason="manual",
        capabilities={Capability.HTTP_REQUEST},
        created_at=datetime.now(UTC),
        execute_after=execute_after,
        approval_envelope=envelope,
        approval_envelope_hash=approval_envelope_hash(envelope),
        selected_backend_id="software.default",
        selected_backend_method="software",
    )


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
    assert entry.action_id == pending.confirmation_id
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
    entry = ActionPendingEntry.model_validate(action)
    capability = entry.channel_capability
    assert capability["backend_available"] is True
    assert capability["can_approve"] is False
    assert capability["can_collect_selected_method"] is False
    assert capability["can_carry"] is False
    assert capability["cannot_carry_reason"] == "approval_expired"
    assert "approval_url" not in action
    assert "approval_qr_ascii" not in action
    assert approval_web.issued == []


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
    pending.approval_envelope_hash = approval_envelope_hash(pending.approval_envelope)
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


def test_m5_confirmed_tool_output_transcript_records_owner_projection(tmp_path) -> None:
    harness = _ConfirmationImplHarness(tmp_path)
    pending = _pending_action(nonce="expected")

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
    envelope = _software_approval_envelope(tool_name=ToolName("web.search")).model_copy(
        update={"required_level": ConfirmationLevel.REAUTHENTICATED}
    )
    return PendingAction(
        confirmation_id="c-1",
        decision_nonce=nonce,
        session_id=SessionId("s-1"),
        user_id=UserId("alice"),
        workspace_id=WorkspaceId("w-1"),
        tool_name=ToolName("web.search"),
        arguments={"query": "hello"},
        reason="manual",
        capabilities={Capability.HTTP_REQUEST},
        created_at=datetime.now(UTC),
        required_level=ConfirmationLevel.REAUTHENTICATED,
        required_methods=list(required_methods or []),
        required_capabilities=ConfirmationCapabilities(),
        approval_envelope=envelope,
        approval_envelope_hash=approval_envelope_hash(envelope),
        selected_backend_id="totp.default",
        selected_backend_method="totp",
    )


def _webauthn_pending_action(*, nonce: str) -> PendingAction:
    envelope = _software_approval_envelope(tool_name=ToolName("web.search")).model_copy(
        update={"required_level": ConfirmationLevel.BOUND_APPROVAL}
    )
    return PendingAction(
        confirmation_id="c-webauthn",
        decision_nonce=nonce,
        session_id=SessionId("s-1"),
        user_id=UserId("alice"),
        workspace_id=WorkspaceId("w-1"),
        tool_name=ToolName("web.search"),
        arguments={"query": "hello"},
        reason="manual",
        capabilities={Capability.HTTP_REQUEST},
        created_at=datetime.now(UTC),
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
        selected_backend_id="webauthn.default",
        selected_backend_method="webauthn",
    )


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


def test_lt3_load_pending_actions_fails_pending_rows_during_lockout_only(tmp_path) -> None:
    pending = _pending_action(nonce="expected")
    pending_payload = HandlerImplementation._pending_to_dict(pending)
    approved_payload = dict(pending_payload)
    approved_payload["confirmation_id"] = "c-2"
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


def test_a1_load_pending_actions_fails_legacy_channel_pending_without_principal(
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

    loaded = harness._pending_actions["c-1"]
    assert loaded.allowed_channel_principals == []
    assert loaded.status == "failed"
    assert loaded.status_reason == "channel_principal_unavailable"
    public = HandlerImplementation._pending_to_dict(loaded, public=True)
    capability = public["channel_capability"]
    assert capability["can_approve"] is False
    assert capability["can_collect_selected_method"] is False
    assert capability["can_carry"] is False
    assert capability["can_carry_required_proof_tier"] is False
    persisted = json.loads(pending_actions_file.read_text(encoding="utf-8"))
    assert persisted[0]["status"] == "failed"
    assert persisted[0]["status_reason"] == "channel_principal_unavailable"


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
    assert scheduler.resolved_confirmations == [
        {
            "task_id": "task-old",
            "confirmation_id": "c-old",
            "status": "failed",
            "status_reason": "purged_stale_pending_action",
        }
    ]
    assert scheduler.run_outcomes == [{"task_id": "task-old", "success": False}]


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

    harness = _ConfirmationImplHarness(tmp_path)
    harness._pending_actions["c-1"] = _pending_action(nonce="expected")
    missing = await harness.do_action_confirm({"confirmation_id": "c-1"})
    assert missing["confirmed"] is False
    assert missing["reason"] == "missing_decision_nonce"


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
    harness._pending_actions["c-1"] = pending

    result = await harness.do_action_confirm(
        {"confirmation_id": "c-1", "decision_nonce": "expected"}
    )

    assert result["confirmed"] is True
    assert harness.execution_merged_policies == [pending.merged_policy]


@pytest.mark.asyncio
async def test_i1_confirmation_replays_direct_mcp_strip_intent(tmp_path) -> None:
    harness = _ConfirmationImplHarness(tmp_path)
    pending = _pending_action(nonce="expected")
    pending.tool_name = ToolName("mcp.docs.lookup-doc")
    pending.arguments = {
        "session_id": "s-1",
        "tool_name": "mcp.docs.lookup-doc",
        "command": ["mcp"],
        "query": "roadmap",
    }
    pending.strip_direct_tool_execute_envelope_keys = True
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
    harness._pending_actions["c-1"] = _pending_action(
        nonce="expected",
        execute_after=datetime.now(UTC) - timedelta(seconds=1),
    )
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
        execute_after=now + timedelta(seconds=0.08),
    )
    pending.expires_at = now + timedelta(seconds=0.04)
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
async def test_gh42_action_purge_waits_for_inflight_confirmation(tmp_path) -> None:
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
    harness._pending_actions["c-1"] = pending
    harness._pending_by_session[pending.session_id] = ["c-1"]

    confirm_task = asyncio.create_task(
        harness.do_action_confirm({"confirmation_id": "c-1", "decision_nonce": "expected"})
    )
    await harness.execution_started.wait()

    purge_task = asyncio.create_task(
        harness.do_action_purge({"status": "pending", "older_than_days": 7, "limit": 10})
    )
    await asyncio.sleep(0)
    purge_completed_before_confirmation = purge_task.done()

    harness.release_execution.set()
    confirmed, purged = await asyncio.gather(confirm_task, purge_task)

    assert purge_completed_before_confirmation is False
    assert confirmed["confirmed"] is True
    assert purged["purged"] == 0
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
    harness._pep = PEP(
        PolicyBundle.model_validate(
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
        ),
        _registry_for_confirmation(),
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
    harness._pending_actions["c-1"] = pending

    result = await harness.do_action_confirm(
        {"confirmation_id": "c-1", "decision_nonce": "expected"}
    )

    assert result["confirmed"] is False
    assert result["status"] == "rejected"
    assert result["status_reason"] == "confirmation_requirement_unsatisfied_after_confirmation"
    assert harness.execution_kwargs == []


@pytest.mark.asyncio
async def test_trace_only_capability_elevation_accepts_explicit_fallback_confirmation(
    tmp_path,
) -> None:
    harness = _ConfirmationImplHarness(tmp_path, allow_amendment=True)
    harness._pep = PEP(
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
        _registry_for_confirmation(),
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

        def approve_stage2(self, *, action: object, approved_by: str) -> str:
            _ = (action, approved_by)
            raise ControlPlaneRpcError(
                message="cannot amend missing or inactive plan",
                reason_code="rpc.invalid_params",
            )

    harness._control_plane = _RejectingControlPlane()
    pending = _pending_action(nonce="expected")
    pending.reason = "trace:stage2_upgrade_required"
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
    pending.approval_envelope_hash = approval_envelope_hash(pending.approval_envelope)
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
