"""User-interface support utilities for CLI/TUI/Web surfaces."""

from shisad.ui.confirmation import (
    ConfirmationAnalytics,
    ConfirmationSummary,
    ConfirmationWarningGenerator,
    render_structured_confirmation,
    safe_summary,
)
from shisad.ui.dashboard import DashboardQuery, SecurityDashboard
from shisad.ui.tui import TuiSnapshot, fetch_snapshot, run_interactive, run_once
from shisad.ui.web import fetch_web_snapshot, render_web_snapshot, write_web_snapshot

__all__ = [
    "ConfirmationAnalytics",
    "ConfirmationSummary",
    "ConfirmationWarningGenerator",
    "DashboardQuery",
    "SecurityDashboard",
    "TuiSnapshot",
    "fetch_snapshot",
    "fetch_web_snapshot",
    "render_structured_confirmation",
    "render_web_snapshot",
    "run_interactive",
    "run_once",
    "safe_summary",
    "write_web_snapshot",
]
