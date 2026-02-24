"""Canonical tool-name helpers.

Runtime and control-plane logic use dotted tool IDs as canonical names.
Legacy underscore/hyphen aliases are translated through this module only.
"""

from __future__ import annotations

import logging

from shisad.core.types import ToolName

logger = logging.getLogger(__name__)
_WARNED_LEGACY_ALIASES: set[str] = set()

# Transitional alias map kept in one place to avoid split classifier/runtime drift.
LEGACY_TOOL_NAME_ALIASES: dict[str, str] = {
    "shell_exec": "shell.exec",
    "shell-exec": "shell.exec",
    "http_request": "http.request",
    "http-request": "http.request",
    "file_read": "file.read",
    "file-read": "file.read",
    "file_write": "file.write",
    "file-write": "file.write",
    "write_file": "file.write",
    "write-file": "file.write",
    "web_search": "web.search",
    "web-search": "web.search",
    "web_fetch": "web.fetch",
    "web-fetch": "web.fetch",
}


def canonical_tool_name(name: str) -> str:
    """Return canonical dotted tool name for runtime/control-plane use."""
    lowered = name.strip().lower()
    if not lowered:
        return ""
    canonical = LEGACY_TOOL_NAME_ALIASES.get(lowered)
    if canonical is not None:
        if lowered not in _WARNED_LEGACY_ALIASES:
            logger.warning(
                "Legacy tool alias '%s' is deprecated; use '%s' instead.",
                lowered,
                canonical,
            )
            _WARNED_LEGACY_ALIASES.add(lowered)
        return canonical
    return lowered


def canonical_tool_name_typed(name: ToolName | str) -> ToolName:
    """Typed wrapper over :func:`canonical_tool_name`."""
    return ToolName(canonical_tool_name(str(name)))
