"""Helpers for transcript-visible daemon control notices."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

LOCKDOWN_NOTICE_TRANSCRIPT_MARKER = "[LOCKDOWN NOTICE]"
LOCKDOWN_RECOVERY_NOTICE_METADATA_KEY = "lockdown_recovery_notice"
LOCKDOWN_RECOVERY_PROMPT_METADATA_KEY = "lockdown_recovery_prompt"
DAEMON_CONTROL_NOTICE_METADATA_KEY = "daemon_control_notice"
LOCKDOWN_NOTICE_METADATA_KEYS = frozenset(
    {
        LOCKDOWN_RECOVERY_NOTICE_METADATA_KEY,
        LOCKDOWN_RECOVERY_PROMPT_METADATA_KEY,
        DAEMON_CONTROL_NOTICE_METADATA_KEY,
    }
)


def strip_daemon_lockdown_notice_suffix(
    content: str,
    metadata: Mapping[str, Any] | None = None,
    *,
    role: str = "",
) -> str:
    """Strip a final daemon-generated lockdown notice suffix from transcript text."""
    metadata = metadata or {}
    metadata_tagged = any(bool(metadata.get(key)) for key in LOCKDOWN_NOTICE_METADATA_KEYS)
    legacy_assistant_row = str(role).strip().lower() == "assistant"
    marker_index = content.rfind(f"\n\n{LOCKDOWN_NOTICE_TRANSCRIPT_MARKER}")
    if marker_index < 0:
        if not (metadata_tagged or legacy_assistant_row):
            return content
        marker_index = content.rfind(LOCKDOWN_NOTICE_TRANSCRIPT_MARKER)
    if marker_index < 0:
        return content
    suffix = content[marker_index:]
    if not metadata_tagged and not (
        legacy_assistant_row and _looks_like_daemon_lockdown_notice(suffix)
    ):
        return content
    return content[:marker_index].rstrip()


def _looks_like_daemon_lockdown_notice(suffix: str) -> bool:
    normalized = " ".join(suffix.casefold().split())
    if not normalized.startswith(LOCKDOWN_NOTICE_TRANSCRIPT_MARKER.casefold()):
        return False
    if "to recover:" in normalized:
        return (
            "shisad lockdown resume" in normalized
            or "ask the agent to resume" in normalized
            or (
                "ask the agent what to do" in normalized
                and "to resume the lockdown" in normalized
            )
        )
    return (
        (
            "what should i do:" in normalized
            and "keep the session locked" in normalized
            and "clear the lockdown" in normalized
        )
        or (
            "what should i do next?" in normalized
            and "session is in " in normalized
            and "lockdown" in normalized
        )
        or (
            "ask the agent what to do" in normalized
            and "to resume the lockdown" in normalized
        )
    )
