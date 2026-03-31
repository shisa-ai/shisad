from __future__ import annotations

from pathlib import Path

from shisad.coding.models import CodingAgentConfig
from shisad.coding.registry import (
    AgentAvailability,
    AgentCommandSpec,
    build_default_agent_registry,
    select_coding_agent,
)


def test_m3_default_agent_registry_contains_pinned_acp_commands() -> None:
    registry = build_default_agent_registry()

    assert registry["claude"].command == (
        "npx",
        "-y",
        "@zed-industries/claude-agent-acp@0.21.0",
    )
    assert registry["codex"].command == (
        "npx",
        "@zed-industries/codex-acp@0.9.5",
    )
    assert registry["opencode"].command == (
        "npx",
        "-y",
        "opencode-ai@1.3.10",
        "acp",
    )


def test_m3_agent_selection_uses_fallback_chain_when_preferred_agent_unavailable() -> None:
    registry = {
        "codex": AgentCommandSpec(
            name="codex",
            command=("missing-codex",),
        ),
        "claude": AgentCommandSpec(
            name="claude",
            command=("python", str(Path(__file__))),
        ),
    }

    def _availability(spec: AgentCommandSpec) -> AgentAvailability:
        if spec.name == "codex":
            return AgentAvailability(available=False, reason="binary_not_found")
        return AgentAvailability(available=True, reason="ok")

    selection = select_coding_agent(
        registry=registry,
        config=CodingAgentConfig(
            preferred_agent="codex",
            fallback_agents=("claude",),
        ),
        availability_checker=_availability,
    )

    assert selection.spec.name == "claude"
    assert selection.fallback_used is True
    assert [attempt.agent for attempt in selection.attempts] == ["codex", "claude"]
    assert selection.attempts[0].available is False
    assert selection.attempts[1].available is True


def test_m3_agent_registry_accepts_operator_command_overrides() -> None:
    registry = build_default_agent_registry(
        overrides={
            "codex": "python /tmp/fake-acp-agent.py --agent-name codex",
        }
    )

    assert registry["codex"].command == (
        "python",
        "/tmp/fake-acp-agent.py",
        "--agent-name",
        "codex",
    )
