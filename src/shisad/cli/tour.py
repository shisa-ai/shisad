"""Deterministic first-use guidance for the shipped CLI surfaces."""

from __future__ import annotations

import sys
from typing import TextIO

CHAT_SUGGESTION = "Try asking shisad to read a file in your workspace."

_TOUR_SECTIONS = (
    (
        "1. Readiness",
        "Use shisad status for daemon state and shisad doctor for bounded component checks.",
    ),
    (
        "2. Chat",
        "Use shisad chat for ordinary conversation. The core chat remains usable "
        "when optional channels are unavailable.",
    ),
    (
        "3. Tools and policy",
        "Tool actions may be auto-approved, require confirmation, be denied, or be "
        "blocked by live policy.",
    ),
    (
        "4. Dashboard",
        "Use shisad tui to inspect runtime state and pending actions; displayed state "
        "does not grant approval.",
    ),
    (
        "5. Recovery and next steps",
        "Re-check with shisad status or shisad doctor, start chat with shisad chat, "
        "and rerun this guide with shisad tour.",
    ),
)


def render_tour() -> str:
    """Render maintained guidance without consulting a model or runtime state."""

    lines = ["shisad guided tour", ""]
    for title, description in _TOUR_SECTIONS:
        lines.extend((title, f"  {description}", ""))
    lines.extend(
        (
            "The normal planner, policy, confirmation, and tool paths remain in effect.",
            "This tour does not submit a message, start a daemon, or change configuration.",
        )
    )
    return "\n".join(lines)


def is_interactive_tour(
    *,
    stdin: TextIO | None = None,
    stdout: TextIO | None = None,
) -> bool:
    """Return whether both tour streams are attached to an interactive terminal."""

    input_stream = sys.stdin if stdin is None else stdin
    output_stream = sys.stdout if stdout is None else stdout
    return bool(
        getattr(input_stream, "isatty", lambda: False)()
        and getattr(output_stream, "isatty", lambda: False)()
    )
