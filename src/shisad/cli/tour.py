"""Deterministic first-use guidance for the shipped CLI surfaces."""

from __future__ import annotations

import sys
from typing import TextIO

from shisad.cli.lifecycle import BackgroundStartResult, render_background_start

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
        "Re-check with shisad status or shisad doctor, inspect with shisad tui, "
        "start chat with shisad chat, and rerun this guide with shisad tour. If chat "
        "cannot connect, start the daemon with shisad start.",
    ),
)


def render_tour(*, health: BackgroundStartResult | None = None) -> str:
    """Render maintained guidance from optional bounded typed health."""

    lines = ["shisad guided tour", ""]
    for title, description in _TOUR_SECTIONS:
        lines.extend((title, f"  {description}", ""))
        if title == "1. Readiness":
            if health is None:
                lines.extend(
                    (
                        "  Current O3A health: unavailable; run shisad start, then "
                        "shisad status or shisad doctor.",
                        "",
                    )
                )
            else:
                lines.append("  Current O3A health:")
                lines.extend(f"    {line}" for line in render_background_start(health))
                lines.append("")
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
