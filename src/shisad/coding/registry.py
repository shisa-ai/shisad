"""Coding-agent command registry and selection helpers."""

from __future__ import annotations

import os
import shlex
import shutil
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path

from .models import CodingAgentConfig


@dataclass(frozen=True, slots=True)
class AgentCommandSpec:
    """Pinned command and transport hints for a coding-agent adapter."""

    name: str
    command: tuple[str, ...]
    read_only_modes: tuple[str, ...] = ("plan", "read-only")
    write_modes: tuple[str, ...] = ("build", "auto")
    skill_name: str = ""

    def __post_init__(self) -> None:
        if not self.skill_name:
            object.__setattr__(self, "skill_name", f"coding.{self.name}")


@dataclass(frozen=True, slots=True)
class AgentAvailability:
    available: bool
    reason: str = ""


@dataclass(frozen=True, slots=True)
class AgentSelectionAttempt:
    agent: str
    available: bool
    reason: str = ""


@dataclass(frozen=True, slots=True)
class AgentSelectionResult:
    spec: AgentCommandSpec | None
    attempts: tuple[AgentSelectionAttempt, ...]
    fallback_used: bool = False


def _parse_command(command: str) -> tuple[str, ...]:
    parsed = tuple(shlex.split(command))
    if not parsed:
        raise ValueError("coding-agent command override must not be empty")
    return parsed


def _require_local_adapters() -> bool:
    """Check whether runtime npx fetches are disallowed.

    Set ``SHISAD_REQUIRE_LOCAL_ADAPTERS=1`` to require adapters to be
    pre-installed locally.  When enabled, the default registry uses bare
    binary names instead of ``npx`` invocations, and
    :func:`select_coding_agent` will only succeed if the binary is
    already on ``$PATH``.
    """
    return os.environ.get("SHISAD_REQUIRE_LOCAL_ADAPTERS", "").strip() in ("1", "true", "yes")


def build_default_agent_registry(
    overrides: Mapping[str, str] | None = None,
    *,
    require_local: bool | None = None,
) -> dict[str, AgentCommandSpec]:
    if require_local is None:
        require_local = _require_local_adapters()

    if require_local:
        registry = {
            "claude": AgentCommandSpec(
                name="claude",
                command=("claude-agent-acp",),
            ),
            "codex": AgentCommandSpec(
                name="codex",
                command=("codex-acp",),
            ),
            "opencode": AgentCommandSpec(
                name="opencode",
                command=("opencode", "acp"),
            ),
        }
    else:
        registry = {
            "claude": AgentCommandSpec(
                name="claude",
                command=("npx", "-y", "@agentclientprotocol/claude-agent-acp@0.29.2"),
            ),
            "codex": AgentCommandSpec(
                name="codex",
                command=("npx", "@zed-industries/codex-acp@0.12.0"),
            ),
            "opencode": AgentCommandSpec(
                name="opencode",
                command=("npx", "-y", "opencode-ai@1.3.10", "acp"),
            ),
        }
    for raw_name, raw_command in (overrides or {}).items():
        name = str(raw_name).strip().lower()
        command = str(raw_command).strip()
        if not name or not command:
            continue
        base = registry.get(name)
        registry[name] = AgentCommandSpec(
            name=name,
            command=_parse_command(command),
            read_only_modes=base.read_only_modes if base is not None else ("plan", "read-only"),
            write_modes=base.write_modes if base is not None else ("build", "auto"),
        )
    return registry


def default_agent_availability(spec: AgentCommandSpec) -> AgentAvailability:
    executable = spec.command[0]
    if Path(executable).is_absolute():
        return AgentAvailability(
            available=Path(executable).exists(),
            reason="ok" if Path(executable).exists() else "binary_not_found",
        )
    return AgentAvailability(
        available=shutil.which(executable) is not None,
        reason="ok" if shutil.which(executable) is not None else "binary_not_found",
    )


def select_coding_agent(
    *,
    registry: Mapping[str, AgentCommandSpec],
    config: CodingAgentConfig,
    availability_checker: Callable[[AgentCommandSpec], AgentAvailability] | None = None,
) -> AgentSelectionResult:
    checker = availability_checker or default_agent_availability
    attempts: list[AgentSelectionAttempt] = []
    chain = config.selection_chain()
    for index, agent_name in enumerate(chain):
        spec = registry.get(agent_name)
        if spec is None:
            attempts.append(
                AgentSelectionAttempt(
                    agent=agent_name,
                    available=False,
                    reason="unknown_agent",
                )
            )
            continue
        availability = checker(spec)
        attempts.append(
            AgentSelectionAttempt(
                agent=agent_name,
                available=availability.available,
                reason=availability.reason,
            )
        )
        if availability.available:
            return AgentSelectionResult(
                spec=spec,
                attempts=tuple(attempts),
                fallback_used=index > 0,
            )
    return AgentSelectionResult(spec=None, attempts=tuple(attempts), fallback_used=False)
