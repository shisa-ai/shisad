"""H1 control-plane sidecar process boundary coverage."""

from __future__ import annotations

import json

import pytest

from shisad.core.types import Capability
from shisad.security.control_plane.schema import Origin, RiskTier
from shisad.security.control_plane.sidecar import start_control_plane_sidecar


def _clear_remote_provider_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SHISA_API_KEY", raising=False)
    monkeypatch.delenv("SHISAD_MODEL_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    monkeypatch.setenv("SHISAD_MODEL_REMOTE_ENABLED", "false")
    monkeypatch.setenv("SHISAD_MODEL_MONITOR_REMOTE_ENABLED", "false")


@pytest.mark.asyncio
async def test_h1_control_plane_sidecar_round_trips_evaluation_and_audit_writes(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear_remote_provider_env(monkeypatch)
    handle = await start_control_plane_sidecar(
        data_dir=tmp_path / "data",
        policy_path=tmp_path / "policy.yaml",
    )
    try:
        origin = Origin(
            session_id="sess-h1",
            user_id="alice",
            workspace_id="ws-h1",
            actor="planner",
        )
        plan_hash = await handle.client.begin_precontent_plan(
            session_id="sess-h1",
            goal="fetch example",
            origin=origin,
            ttl_seconds=300,
            max_actions=5,
            capabilities={Capability.HTTP_REQUEST},
        )
        evaluation = await handle.client.evaluate_action(
            tool_name="web.fetch",
            arguments={"url": "https://example.com"},
            origin=origin,
            risk_tier=RiskTier.LOW,
            declared_domains=["example.com"],
            session_tainted=False,
            trusted_input=True,
            raw_user_text="fetch example.com",
        )
        assert await handle.client.active_plan_hash("sess-h1") == plan_hash
        assert evaluation.action.tool_name == "web.fetch"
        assert evaluation.action.origin.session_id == "sess-h1"
        assert evaluation.trace_result.allowed is True

        await handle.client.record_execution(action=evaluation.action, success=True)

        history_path = tmp_path / "data" / "control_plane" / "history.jsonl"
        history_rows = [
            json.loads(line)
            for line in history_path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        assert history_rows[0]["timestamp"] == history_rows[1]["timestamp"]

        audit_path = tmp_path / "data" / "control_plane" / "audit.jsonl"
        assert audit_path.exists()
        event_types = [
            json.loads(line)["event_type"]
            for line in audit_path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        assert "plan_committed" in event_types
        assert "action_observed" in event_types
    finally:
        await handle.close()

    assert handle.process.returncode is not None
    assert not handle.socket_path.exists()
