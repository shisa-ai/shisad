"""Opt-in live smoke coverage for provisioned ACP coding agents."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from shisad.coding.acp_adapter import AcpAdapter
from shisad.coding.models import CodingAgentConfig
from shisad.coding.registry import build_default_agent_registry


def _live_agents() -> list[str]:
    raw = os.getenv("SHISAD_LIVE_CODING_AGENTS", "").strip()
    if not raw:
        return []
    return [item.strip().lower() for item in raw.split(",") if item.strip()]


pytestmark = pytest.mark.skipif(
    not _live_agents(),
    reason=(
        "set SHISAD_LIVE_CODING_AGENTS=claude,codex,opencode to run live coding-agent smoke tests"
    ),
)


@pytest.mark.asyncio
@pytest.mark.parametrize("agent_name", _live_agents())
async def test_m3_live_coding_agent_smoke(agent_name: str, tmp_path: Path) -> None:
    registry = build_default_agent_registry()
    spec = registry[agent_name]
    adapter = AcpAdapter(spec=spec)
    (tmp_path / "README.md").write_text("live smoke\n", encoding="utf-8")

    result = await adapter.run(
        prompt_text="TASK KIND: review\nFILES:\n- README.md\nINSTRUCTIONS:\nReview README.md.",
        workdir=tmp_path,
        config=CodingAgentConfig(
            preferred_agent=agent_name,
            read_only=True,
            timeout_sec=120.0,
        ),
    )

    assert result.result.summary


@pytest.mark.asyncio
@pytest.mark.parametrize("agent_name", _live_agents())
async def test_m3_live_coding_agent_implement_smoke(
    agent_name: str,
    tmp_path: Path,
) -> None:
    registry = build_default_agent_registry()
    spec = registry[agent_name]
    adapter = AcpAdapter(spec=spec)
    readme_path = tmp_path / "README.md"
    readme_path.write_text("live smoke\n", encoding="utf-8")

    result = await adapter.run(
        prompt_text=(
            "TASK KIND: implement\nFILES:\n- README.md\nINSTRUCTIONS:\n"
            "Append a short live-smoke note to README.md.\n"
        ),
        workdir=tmp_path,
        config=CodingAgentConfig(
            preferred_agent=agent_name,
            read_only=False,
            timeout_sec=120.0,
        ),
    )

    assert result.result.summary
