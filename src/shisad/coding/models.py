"""Shared coding-agent result and request models."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True, slots=True)
class CodingAgentConfig:
    """Normalized request surface for a coding-agent invocation."""

    preferred_agent: str | None = None
    fallback_agents: tuple[str, ...] = ()
    timeout_sec: float | None = None
    max_budget_usd: float | None = None
    read_only: bool = False
    task_kind: str = "implement"
    max_turns: int | None = None
    model: str | None = None
    reasoning_effort: str | None = None
    allowed_tools: tuple[str, ...] = ()
    permission_mode: str = "approve-all"

    def selection_chain(self) -> tuple[str, ...]:
        ordered: list[str] = []
        for candidate in [self.preferred_agent, *self.fallback_agents]:
            normalized = str(candidate or "").strip().lower()
            if normalized and normalized not in ordered:
                ordered.append(normalized)
        return tuple(ordered)


@dataclass(frozen=True, slots=True)
class CodingAgentResult:
    """Common cross-agent result contract surfaced back to COMMAND."""

    agent: str
    task: str
    success: bool
    summary: str
    files_changed: tuple[str, ...] = ()
    cost: float | None = None
    duration_ms: int = 0
    proposal_ref: str | None = None
    raw_log_ref: str | None = None


@dataclass(frozen=True, slots=True)
class CodingAgentRunOutput:
    """Adapter-level output including transport metadata and raw updates."""

    result: CodingAgentResult
    error_code: str = ""
    stop_reason: str = ""
    session_id: str = ""
    raw_updates: tuple[dict[str, Any], ...] = ()
    selected_mode: str | None = None
    applied_config: dict[str, str] = field(default_factory=dict)
