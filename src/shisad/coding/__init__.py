"""Coding-agent transport and task-isolation helpers."""

from .acp_adapter import AcpAdapter
from .adapter import CodingAgentAdapter
from .manager import CodingAgentExecutionRecord, CodingAgentManager
from .models import CodingAgentConfig, CodingAgentResult, CodingAgentRunOutput
from .registry import (
    AgentAvailability,
    AgentCommandSpec,
    AgentSelectionAttempt,
    AgentSelectionResult,
    build_default_agent_registry,
    select_coding_agent,
)

__all__ = [
    "AcpAdapter",
    "AgentAvailability",
    "AgentCommandSpec",
    "AgentSelectionAttempt",
    "AgentSelectionResult",
    "CodingAgentAdapter",
    "CodingAgentConfig",
    "CodingAgentExecutionRecord",
    "CodingAgentManager",
    "CodingAgentResult",
    "CodingAgentRunOutput",
    "build_default_agent_registry",
    "select_coding_agent",
]
