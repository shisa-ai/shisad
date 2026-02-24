"""Unit checks for confirmation handler wrappers."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest

from shisad.core.api.schema import (
    ActionDecisionParams,
    ActionPendingParams,
    ConfirmationMetricsParams,
)
from shisad.core.types import Capability, SessionId, ToolName, UserId, WorkspaceId
from shisad.daemon.context import RequestContext
from shisad.daemon.handlers._impl import PendingAction
from shisad.daemon.handlers._impl_confirmation import ConfirmationImplMixin
from shisad.daemon.handlers.confirmation import ConfirmationHandlers


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


class _ConfirmationImplHarness(ConfirmationImplMixin):
    def __init__(self) -> None:
        self._pending_actions: dict[str, PendingAction] = {}
        self._lockdown_manager = SimpleNamespace(should_block_all_actions=lambda _sid: False)
        self._event_bus = SimpleNamespace(publish=self._noop_publish)
        self._session_manager = SimpleNamespace(get=lambda _sid: object())
        self._policy_loader = SimpleNamespace(
            policy=SimpleNamespace(
                control_plane=SimpleNamespace(trace=SimpleNamespace(allow_amendment=False))
            )
        )
        self._confirmation_analytics = SimpleNamespace(record=lambda **_kwargs: None)

    async def _noop_publish(self, _event: object) -> None:
        return None

    async def _maybe_emit_confirmation_hygiene_alert(self, **_kwargs: object) -> None:
        return None

    def _persist_pending_actions(self) -> None:
        return None

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
    ) -> tuple[bool, str | None, object | None]:
        _ = (sid, user_id, tool_name, arguments, capabilities, approval_actor, execution_action)
        return True, None, None


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
async def test_m1_pf11_confirmation_rejects_invalid_nonce() -> None:
    harness = _ConfirmationImplHarness()
    harness._pending_actions["c-1"] = _pending_action(nonce="expected")
    result = await harness.do_action_confirm(
        {"confirmation_id": "c-1", "decision_nonce": "invalid"}
    )
    assert result["confirmed"] is False
    assert result["reason"] == "invalid_decision_nonce"


@pytest.mark.asyncio
async def test_m1_pf11_confirmation_accepts_valid_nonce_and_rejects_missing_nonce() -> None:
    harness = _ConfirmationImplHarness()
    harness._pending_actions["c-1"] = _pending_action(nonce="expected")
    valid = await harness.do_action_confirm(
        {"confirmation_id": "c-1", "decision_nonce": "expected"}
    )
    assert valid["confirmed"] is True
    assert valid["status"] == "approved"

    harness = _ConfirmationImplHarness()
    harness._pending_actions["c-1"] = _pending_action(nonce="expected")
    missing = await harness.do_action_confirm({"confirmation_id": "c-1"})
    assert missing["confirmed"] is False
    assert missing["reason"] == "missing_decision_nonce"


@pytest.mark.asyncio
async def test_m1_pf11_confirmation_cooldown_active_and_expired() -> None:
    harness = _ConfirmationImplHarness()
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

    harness = _ConfirmationImplHarness()
    harness._pending_actions["c-1"] = _pending_action(
        nonce="expected",
        execute_after=datetime.now(UTC) - timedelta(seconds=1),
    )
    expired = await harness.do_action_confirm(
        {"confirmation_id": "c-1", "decision_nonce": "expected"}
    )
    assert expired["confirmed"] is True
    assert expired["status"] == "approved"
