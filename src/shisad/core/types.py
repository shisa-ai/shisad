"""Core type definitions for shisad.

NewTypes for type safety across the codebase. Capability and TaintLabel enums
define the permission and information flow control vocabulary.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any, NewType

from pydantic import BaseModel

# --- Identity types ---

SessionId = NewType("SessionId", str)
UserId = NewType("UserId", str)
WorkspaceId = NewType("WorkspaceId", str)
ToolName = NewType("ToolName", str)
CredentialRef = NewType("CredentialRef", str)
EventId = NewType("EventId", str)


class Capability(StrEnum):
    """Tool capabilities that can be granted per-session via policy.

    Organized by domain. Each tool declares which capabilities it requires;
    the PEP checks the session's granted set before allowing execution.
    """

    # Email
    EMAIL_READ = "email.read"
    EMAIL_WRITE = "email.write"
    EMAIL_SEND = "email.send"

    # Calendar
    CALENDAR_READ = "calendar.read"
    CALENDAR_WRITE = "calendar.write"

    # Filesystem
    FILE_READ = "file.read"
    FILE_WRITE = "file.write"

    # Network
    HTTP_REQUEST = "http.request"

    # Shell
    SHELL_EXEC = "shell.exec"

    # Memory
    MEMORY_READ = "memory.read"
    MEMORY_WRITE = "memory.write"

    # Messaging
    MESSAGE_READ = "message.read"
    MESSAGE_SEND = "message.send"


class TaintLabel(StrEnum):
    """Information flow labels for taint tracking.

    Every piece of content in the system carries one or more taint labels.
    The PEP and Output Firewall use these to enforce information flow policies
    (e.g., SENSITIVE_FILE content cannot reach HTTP_REQUEST egress without approval).
    """

    UNTRUSTED = "untrusted"
    MCP_EXTERNAL = "mcp_external"
    USER_REVIEWED = "user_reviewed"
    SENSITIVE_EMAIL = "email"
    SENSITIVE_FILE = "file"
    SENSITIVE_CALENDAR = "calendar"
    USER_CREDENTIALS = "credentials"
    SYSTEM_PROMPT = "system"


class ThreatCategory(StrEnum):
    """Standardized threat classification codes.

    Adapted from Cisco AITech taxonomy categories used in analysis docs.
    """

    PROMPT_INJECTION_DIRECT = "AITech-1.1"
    PROMPT_INJECTION_INDIRECT = "AITech-1.2"
    JAILBREAK = "AITech-2.1"
    MASQUERADING = "AITech-3.1"
    PERSISTENCE = "AITech-5.1"
    DATA_EXFILTRATION = "AITech-8.1"
    SUPPLY_CHAIN = "AITech-9.1"
    TOOL_POISONING = "AITech-12.1"
    TOOL_SHADOWING = "AITech-12.2"
    RESOURCE_ABUSE = "AITech-13.1"
    PRIVILEGE_ESCALATION = "AITech-14.1"


class PEPDecisionKind(StrEnum):
    """Outcome of a PEP evaluation."""

    ALLOW = "allow"
    REJECT = "reject"
    REQUIRE_CONFIRMATION = "require_confirmation"


class PEPDecision(BaseModel):
    """Result of a Policy Enforcement Point evaluation."""

    kind: PEPDecisionKind
    reason: str = ""
    reason_code: str = ""
    tool_name: ToolName | None = None
    risk_score: float | None = None
    timestamp: datetime | None = None
    confirmation_requirement: dict[str, Any] | None = None


class SessionState(StrEnum):
    """Session lifecycle states."""

    ACTIVE = "active"
    SUSPENDED = "suspended"
    TERMINATED = "terminated"


class SessionMode(StrEnum):
    """Session execution mode."""

    DEFAULT = "default"
    ADMIN_CLEANROOM = "admin_cleanroom"
    TASK = "task"


class SessionRole(StrEnum):
    """Session trust-boundary role."""

    ORCHESTRATOR = "orchestrator"
    SUBAGENT = "subagent"
