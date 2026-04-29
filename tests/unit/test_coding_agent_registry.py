from __future__ import annotations

from pathlib import Path

import pytest

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
        "@agentclientprotocol/claude-agent-acp@0.29.2",
    )
    assert registry["codex"].command == (
        "npx",
        "-y",
        "@zed-industries/codex-acp@0.12.0",
    )
    assert registry["opencode"].command == (
        "npx",
        "-y",
        "opencode-ai@1.3.10",
        "acp",
    )


def test_m3_default_agent_registry_pins_every_npx_package_to_an_explicit_version() -> None:
    # PLN-L2: the previous pinning test was configuration identity
    # (compare the tuple against itself). A regression that swapped the
    # pinned version for `@latest` or dropped the `@X.Y.Z` suffix
    # (silently tracking upstream) still matched the exact same tuple
    # literal if the literal happened to get rewritten. This behavioral
    # test pins the *class* of pin (explicit semver) so drift in either
    # direction fails.
    import re

    semver_pin = re.compile(r"@\d+\.\d+\.\d+$")
    forbidden = {"@latest", "@next", "@beta", "@canary"}

    registry = build_default_agent_registry()
    for agent_name, spec in registry.items():
        npx_args = [part for part in spec.command if part.startswith("@") or "@" in part]
        # Every command has at least one `@package@version` argument.
        assert any("@" in part for part in spec.command), (
            f"{agent_name}: command must include an `@` package reference"
        )
        for part in npx_args:
            for banned in forbidden:
                assert banned not in part, (
                    f"{agent_name}: {part!r} uses forbidden mutable tag {banned!r}"
                )
            if part.startswith("@") or part.count("@") >= 1:
                # Package spec is either bare `name@X.Y.Z` or `@scope/pkg@X.Y.Z`.
                assert semver_pin.search(part), (
                    f"{agent_name}: {part!r} is not pinned to an explicit semver"
                )


def test_m3_default_agent_registry_uses_noninteractive_npx() -> None:
    registry = build_default_agent_registry()

    for agent_name, spec in registry.items():
        if spec.command[0] == "npx":
            assert "-y" in spec.command, f"{agent_name}: npx command must be noninteractive"


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


def test_require_local_adapters_replaces_npx_with_local_binaries() -> None:
    registry = build_default_agent_registry(require_local=True)

    assert registry["claude"].command == ("claude-agent-acp",)
    assert registry["codex"].command == ("codex-acp",)
    assert registry["opencode"].command == ("opencode", "acp")
    for spec in registry.values():
        assert spec.command[0] != "npx"


def test_require_local_adapters_env_var(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SHISAD_REQUIRE_LOCAL_ADAPTERS", "1")
    registry = build_default_agent_registry()

    for spec in registry.values():
        assert spec.command[0] != "npx"


def test_require_local_adapters_overrides_still_apply() -> None:
    registry = build_default_agent_registry(
        overrides={"claude": "/usr/local/bin/my-claude"},
        require_local=True,
    )

    assert registry["claude"].command == ("/usr/local/bin/my-claude",)
    assert registry["codex"].command == ("codex-acp",)


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
