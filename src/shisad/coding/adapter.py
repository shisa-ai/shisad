"""Coding-agent adapter interface."""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path

from .models import CodingAgentConfig, CodingAgentRunOutput


class CodingAgentAdapter(ABC):
    """Abstract transport wrapper for an external coding agent."""

    @abstractmethod
    async def run(
        self,
        *,
        prompt_text: str,
        workdir: Path,
        config: CodingAgentConfig,
    ) -> CodingAgentRunOutput:
        """Execute a one-shot coding task inside ``workdir``."""
