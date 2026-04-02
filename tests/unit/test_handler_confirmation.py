"""Unit checks for confirmation handler wrappers."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest

from shisad.core.api.schema import (
    ActionDecisionParams,
    ActionPendingParams,
    ConfirmationMetricsParams,
)
from shisad.core.evidence import ArtifactEndorsementState, EvidenceStore
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
from shisad.daemon.handlers._impl import PendingAction
from shisad.daemon.handlers._impl_confirmation import ConfirmationImplMixin
from shisad.daemon.handlers.confirmation import ConfirmationHandlers
from shisad.security.control_plane.schema import Origin, RiskTier


class _StubImpl:
    def __init__(self) -> None:
        self.calls: list[str] = []

    async def do_action_pending(self, payload: dict[str, object]) -> dict[str, object]:
        self.calls.append("pending")
        return {"actions": [payload], "count": 1}

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


class _ControlPlaneRecorder:
    def __init__(self) -> None:
        self.approved_actions: list[object] = []

    def active_plan_hash(self, _session_id: str) -> str:
        return "plan-before"

    def approve_stage2(self, *, action: object, approved_by: str) -> str:
        _ = approved_by
        self.approved_actions.append(action)
        return "plan-after"


class _ConfirmationImplHarness(ConfirmationImplMixin):
    def __init__(self, tmp_path, *, allow_amendment: bool = False) -> None:
        self._pending_actions: dict[str, PendingAction] = {}
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
        self.execution_merged_policies: list[object | None] = []
        self.execution_kwargs: list[dict[str, object]] = []
        self._transcript_store = TranscriptStore(tmp_path / "sessions")
        self._evidence_store = EvidenceStore(tmp_path / "evidence", salt=b"a" * 32)

    async def _noop_publish(self, _event: object) -> None:
        self.published_events.append(_event)
        return None

    async def _maybe_emit_confirmation_hygiene_alert(self, **_kwargs: object) -> None:
        return None

    def _persist_pending_actions(self) -> None:
        return None

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
    ) -> object:
        _ = (
            sid,
            user_id,
            arguments,
            capabilities,
            approval_actor,
            execution_action,
            user_confirmed,
        )
        self.execution_merged_policies.append(merged_policy)
        self.execution_kwargs.append(
            {
                "tool_name": str(tool_name),
                "approval_confirmation_id": approval_confirmation_id,
                "approval_decision_nonce": approval_decision_nonce,
                "approval_task_envelope_id": approval_task_envelope_id,
                "approval_timestamp": approval_timestamp,
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
        return SimpleNamespace(success=True, checkpoint_id=None, tool_output=tool_output)

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
            "status": pending.status,
            "status_reason": pending.status_reason,
        }


def _pending_action(*, nonce: str, execute_after: datetime | None = None) -> PendingAction:
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
async def test_m1_pf11_confirmation_rejects_invalid_nonce(tmp_path) -> None:
    harness = _ConfirmationImplHarness(tmp_path)
    harness._pending_actions["c-1"] = _pending_action(nonce="expected")
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
async def test_m6_s8_reject_requires_valid_decision_nonce(tmp_path) -> None:
    harness = _ConfirmationImplHarness(tmp_path)
    harness._pending_actions["c-1"] = _pending_action(nonce="expected")

    missing = await harness.do_action_reject({"confirmation_id": "c-1"})
    assert missing["rejected"] is False
    assert missing["reason"] == "missing_decision_nonce"

    invalid = await harness.do_action_reject(
        {"confirmation_id": "c-1", "decision_nonce": "wrong"}
    )
    assert invalid["rejected"] is False
    assert invalid["reason"] == "invalid_decision_nonce"

    valid = await harness.do_action_reject(
        {"confirmation_id": "c-1", "decision_nonce": "expected"}
    )
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
    assert len(harness.execution_kwargs) == 1
    assert harness.execution_kwargs[0]["tool_name"] == "evidence.promote"
    assert harness.execution_kwargs[0]["approval_confirmation_id"] == "c-1"
    assert harness.execution_kwargs[0]["approval_decision_nonce"] == "expected"
    assert harness.execution_kwargs[0]["approval_task_envelope_id"] == "env-task-1"
    assert str(harness.execution_kwargs[0]["approval_timestamp"]).strip()
    transcript_entries = harness._transcript_store.list_entries(SessionId("s-1"))
    assert transcript_entries[-1].metadata["promoted_evidence"] is True
    assert transcript_entries[-1].metadata["promoted_ref_id"] == ref.ref_id
