"""Behavioral contract for restart recovery through the shipped action surface."""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from shisad.core.api.schema import (
    ActionDecisionParams,
    ActionPendingParams,
    SessionCreateParams,
)
from shisad.core.approval import legacy_software_confirmation_requirement
from shisad.core.atomic_state import AtomicWriteError, AtomicWriteStage
from shisad.core.config import DaemonConfig
from shisad.core.request_context import RequestContext
from shisad.core.types import SessionId, ToolName
from shisad.daemon.control_handlers import DaemonControlHandlers
from shisad.daemon.services import DaemonServices


def _configure_model_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SHISAD_MODEL_BASE_URL", "https://api.example.com/v1")
    monkeypatch.setenv(
        "SHISAD_MODEL_PLANNER_BASE_URL", "https://planner.example.com/v1"
    )
    monkeypatch.setenv(
        "SHISAD_MODEL_EMBEDDINGS_BASE_URL", "https://embed.example.com/v1"
    )
    monkeypatch.setenv(
        "SHISAD_MODEL_MONITOR_BASE_URL", "https://monitor.example.com/v1"
    )


def _config(tmp_path: Path) -> DaemonConfig:
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        'version: "1"\ndefault_require_confirmation: false\n',
        encoding="utf-8",
    )
    return DaemonConfig(
        data_dir=tmp_path / "data",
        socket_path=tmp_path / "control.sock",
        policy_path=policy_path,
        assistant_fs_roots=[tmp_path],
        log_level="INFO",
    )


@pytest.mark.asyncio
async def test_f2_user_can_inspect_automatically_recovered_action_after_restart(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure_model_env(monkeypatch)
    config = _config(tmp_path)
    services = await DaemonServices.build(config)
    try:
        handlers = DaemonControlHandlers(services=services)
        created = await handlers.handle_session_create(
            SessionCreateParams(channel="cli", user_id="alice", workspace_id="ws1"),
            RequestContext(),
        )
        session_id = SessionId(created.session_id)
        session = services.session_manager.get(session_id)
        assert session is not None
        pending = handlers._impl._queue_pending_action(
            session_id=session_id,
            user_id=session.user_id,
            workspace_id=session.workspace_id,
            tool_name=ToolName("time.now"),
            arguments={"timezone": "UTC"},
            reason="behavioral-restart-recovery",
            capabilities=set(),
            confirmation_requirement=legacy_software_confirmation_requirement(),
            origin_turn_id="turn-behavioral-recovery",
        )
        publications = 0

        def _fail_terminal_write(stage: AtomicWriteStage) -> None:
            nonlocal publications
            if stage == AtomicWriteStage.TEMP_OPEN:
                publications += 1
            if publications == 2 and stage == AtomicWriteStage.FILE_FSYNC:
                raise OSError("crash after effect before terminal action publication")

        handlers._impl._pending_state_fault_injector = _fail_terminal_write
        with pytest.raises(AtomicWriteError):
            await handlers.handle_action_confirm(
                ActionDecisionParams(
                    confirmation_id=pending.confirmation_id,
                    decision_nonce=pending.decision_nonce,
                ),
                RequestContext(),
            )
    finally:
        await services.shutdown()

    restarted = await DaemonServices.build(config)
    try:
        handlers = DaemonControlHandlers(services=restarted)
        accounting_tasks = list(handlers._impl._recovery_accounting_tasks)
        if accounting_tasks:
            await asyncio.gather(*accounting_tasks)
        listed = await handlers.handle_action_pending(
            ActionPendingParams(
                confirmation_id=pending.confirmation_id,
                status="all",
                include_ui=False,
            ),
            RequestContext(),
        )

        assert listed.count == 1
        action = listed.actions[0]
        assert action.confirmation_id == pending.confirmation_id
        assert action.status == "approved"
        assert action.status_reason == "recovered_structural_read"
        assert action.retry_generation == 1
        assert action.recovery_result["ok"] is True
        assert action.recovery_result["source"] == "daemon_clock"
        assert action.identity.execution_attempt_id == pending.execution_attempt_id
        assert action.decision_nonce == ""
    finally:
        await restarted.shutdown()
