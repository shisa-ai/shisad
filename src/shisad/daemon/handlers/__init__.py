"""Daemon control handler modules grouped by API domain."""

from shisad.daemon.handlers.admin import AdminHandlers
from shisad.daemon.handlers.confirmation import ConfirmationHandlers
from shisad.daemon.handlers.dashboard import DashboardHandlers
from shisad.daemon.handlers.memory import MemoryHandlers
from shisad.daemon.handlers.session import SessionHandlers
from shisad.daemon.handlers.skills import SkillHandlers
from shisad.daemon.handlers.tasks import TaskHandlers
from shisad.daemon.handlers.tool_execution import ToolExecutionHandlers

__all__ = [
    "AdminHandlers",
    "ConfirmationHandlers",
    "DashboardHandlers",
    "MemoryHandlers",
    "SessionHandlers",
    "SkillHandlers",
    "TaskHandlers",
    "ToolExecutionHandlers",
]
