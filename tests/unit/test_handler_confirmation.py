"""Unit checks for confirmation handler wrappers."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest

from shisad.core.api.schema import (
    ActionDecisionParams,
    ActionPendingParams,
    ActionPurgeParams,
    ConfirmationMetricsParams,
)
from shisad.core.approval import (
    ApprovalEnvelope,
    ConfirmationBackendRegistry,
    ConfirmationCapabilities,
    ConfirmationEvidence,
    ConfirmationFallbackPolicy,
    ConfirmationLevel,
    ConfirmationMethodLockoutTracker,
    SoftwareConfirmationBackend,
    TOTPBackend,
    approval_envelope_hash,
    generate_totp_code,
    hash_recovery_code,
)
from shisad.core.events import TwoFactorEnrolled, TwoFactorRevoked
from shisad.core.evidence import ArtifactEndorsementState, EvidenceStore
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
from shisad.security.control_plane.schema import ActionKind, ControlPlaneAction, Origin, RiskTier
from shisad.security.control_plane.sidecar import ControlPlaneRpcError
from shisad.security.credentials import (
    ApprovalFactorRecord,
    InMemoryCredentialStore,
    RecoveryCodeRecord,
)
from shisad.security.pep import PEP, PolicyContext
from shisad.security.policy import PolicyBundle


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


class _ConfirmationImplHarness(ConfirmationImplMixin):
    def __init__(
        self,
        tmp_path,
        *,
        allow_amendment: bool = False,
        execute_success: bool = True,
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
        if str(tool_name) == "evidence.promote":
            tool_output = SimpleNamespace(
                content=json.dumps(
                    {
                        "content": "promoted body",
                        "ref_id": str(arguments.get("ref_id", "")),
                    }
                ),
                taint_labels={TaintLabel.USER_REVIEWED},
            )
        return SimpleNamespace(
            success=self._execute_success,
            checkpoint_id=None,
            tool_output=tool_output if self._execute_success else None,
        )

    @staticmethod
    def _pending_to_dict(pending: PendingAction) -> dict[str, object]:
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
