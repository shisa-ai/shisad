from __future__ import annotations

import sys
from pathlib import Path

import pytest

from shisad.coding.acp_adapter import AcpAdapter
from shisad.coding.models import CodingAgentConfig
from shisad.coding.registry import AgentCommandSpec


def _fake_agent_spec(agent_name: str, *extra_args: str) -> AgentCommandSpec:
    script = Path(__file__).resolve().parents[1] / "fixtures" / "fake_acp_agent.py"
    return AgentCommandSpec(
        name=agent_name,
        command=(sys.executable, str(script), "--agent-name", agent_name, *extra_args),
        read_only_modes=("plan", "read-only"),
        write_modes=("build", "auto"),
    )


@pytest.mark.asyncio
async def test_m3_acp_adapter_collects_summary_mode_cost_and_raw_updates(
    tmp_path: Path,
) -> None:
    adapter = AcpAdapter(spec=_fake_agent_spec("codex"))

    result = await adapter.run(
        prompt_text="TASK KIND: implement\nFILES:\n- README.md\nMULTI_CHUNK_SUMMARY\n",
        workdir=tmp_path,
        config=CodingAgentConfig(
            preferred_agent="codex",
            read_only=False,
            model="fast-model",
            reasoning_effort="high",
            max_turns=8,
        ),
    )

    assert result.result.success is True
    assert result.result.agent == "codex"
    assert "mode=build" in result.result.summary
    assert "model=fast-model" in result.result.summary
    assert result.result.files_changed == ("README.md",)
    assert result.result.cost == pytest.approx(0.42)
    assert result.selected_mode == "build"
    assert result.applied_config["model"] == "fast-model"
    assert result.applied_config["reasoning_effort"] == "high"
    assert result.applied_config["max_turns"] == "8"
    assert result.applied_config["permission_mode"] == "approve-all"
    assert result.raw_updates
    assert result.stop_reason == "end_turn"


@pytest.mark.asyncio
async def test_m3_acp_adapter_review_mode_uses_read_only_session_mode(
    tmp_path: Path,
) -> None:
    adapter = AcpAdapter(spec=_fake_agent_spec("claude"))

    result = await adapter.run(
        prompt_text="TASK KIND: review\nFILES:\n- README.md\nOPPORTUNISTIC_EDIT\n",
        workdir=tmp_path,
        config=CodingAgentConfig(
            preferred_agent="claude",
            read_only=True,
        ),
    )

    assert result.result.success is True
    assert result.selected_mode == "plan"
    assert "mode=plan" in result.result.summary


@pytest.mark.asyncio
async def test_m3_acp_adapter_keeps_existing_preferred_mode(tmp_path: Path) -> None:
    adapter = AcpAdapter(spec=_fake_agent_spec("codex", "--default-mode", "build"))

    result = await adapter.run(
        prompt_text="TASK KIND: implement\nFILES:\n- README.md\n",
        workdir=tmp_path,
        config=CodingAgentConfig(
            preferred_agent="codex",
            read_only=False,
        ),
    )

    assert result.result.success is True
    assert result.selected_mode == "build"
    assert "mode=build" in result.result.summary


@pytest.mark.asyncio
async def test_m3_acp_adapter_timeout_maps_to_clean_failure(tmp_path: Path) -> None:
    adapter = AcpAdapter(spec=_fake_agent_spec("opencode"))

    result = await adapter.run(
        prompt_text="TASK KIND: implement\nSLEEP: 0.25\nFILES:\n- README.md\n",
        workdir=tmp_path,
        config=CodingAgentConfig(
            preferred_agent="opencode",
            timeout_sec=0.05,
        ),
    )

    assert result.result.success is False
    assert result.error_code == "timeout"
    assert "timed out" in result.result.summary.lower()


@pytest.mark.asyncio
async def test_m3_acp_adapter_timeout_covers_initialize_handshake(tmp_path: Path) -> None:
    adapter = AcpAdapter(spec=_fake_agent_spec("claude", "--initialize-sleep", "0.25"))

    result = await adapter.run(
        prompt_text="TASK KIND: review\nFILES:\n- README.md\n",
        workdir=tmp_path,
        config=CodingAgentConfig(
            preferred_agent="claude",
            timeout_sec=0.05,
            read_only=True,
        ),
    )

    assert result.result.success is False
    assert result.error_code == "timeout"
    assert "timed out" in result.result.summary.lower()


@pytest.mark.asyncio
async def test_m3_acp_adapter_handles_large_single_line_updates(tmp_path: Path) -> None:
    adapter = AcpAdapter(
        spec=_fake_agent_spec(
            "codex",
            "--large-single-line-summary-bytes",
            "70000",
        )
    )

    result = await adapter.run(
        prompt_text="TASK KIND: review\nFILES:\n- README.md\n",
        workdir=tmp_path,
        config=CodingAgentConfig(
            preferred_agent="codex",
            read_only=True,
        ),
    )

    assert result.result.success is True
    assert result.error_code == ""
    assert result.result.summary.startswith("codex large-response mode=plan ")
    assert len(result.result.summary) <= 4000
    assert result.result.summary.endswith("[truncated]")


@pytest.mark.asyncio
async def test_m3_acp_adapter_preserves_agent_auth_env(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-anthropic-key")
    adapter = AcpAdapter(spec=_fake_agent_spec("claude", "--require-env", "ANTHROPIC_API_KEY"))

    result = await adapter.run(
        prompt_text="TASK KIND: review\nFILES:\n- README.md\n",
        workdir=tmp_path,
        config=CodingAgentConfig(
            preferred_agent="claude",
            read_only=True,
        ),
    )

    assert result.result.success is True
    assert result.error_code == ""
    assert "mode=plan" in result.result.summary


@pytest.mark.asyncio
async def test_m3_acp_adapter_initialize_failure_maps_to_protocol_error(
    tmp_path: Path,
) -> None:
    adapter = AcpAdapter(spec=_fake_agent_spec("claude", "--fail-initialize"))

    result = await adapter.run(
        prompt_text="TASK KIND: review\nFILES:\n- README.md\n",
        workdir=tmp_path,
        config=CodingAgentConfig(
            preferred_agent="claude",
            read_only=True,
        ),
    )

    assert result.result.success is False
    assert result.error_code == "protocol_error"
    assert "failed during acp negotiation" in result.result.summary.lower()
    assert "invalid request" in result.result.summary.lower()


@pytest.mark.asyncio
async def test_m3_acp_adapter_spawn_failure_is_actionable_unavailable(tmp_path: Path) -> None:
    adapter = AcpAdapter(
        spec=AgentCommandSpec(
            name="codex",
            command=("definitely-missing-acp-adapter",),
        )
    )

    result = await adapter.run(
        prompt_text="TASK KIND: implement\nFILES:\n- README.md\n",
        workdir=tmp_path,
        config=CodingAgentConfig(preferred_agent="codex"),
    )

    assert result.result.success is False
    assert result.error_code == "agent_unavailable"
    assert "not available" in result.result.summary.lower()
