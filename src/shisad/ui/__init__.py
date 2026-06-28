"""User-interface support utilities for CLI/TUI/Web surfaces."""

from shisad.ui.confirmation import (
    ConfirmationAnalytics,
    ConfirmationSummary,
    ConfirmationWarningGenerator,
    render_structured_confirmation,
    safe_summary,
)
from shisad.ui.dashboard import DashboardQuery, SecurityDashboard
from shisad.ui.theme import (
    BASE16_SLOTS,
    SEMANTIC_ALIASES,
    ThemePalette,
    ThemeValidationError,
    get_builtin_theme,
    load_theme,
    parse_btop_theme,
    rich_style_map,
    textual_theme_css,
    web_css_variables,
)
from shisad.ui.tui import TuiSnapshot, fetch_snapshot, run_interactive, run_once
from shisad.ui.web import fetch_web_snapshot, render_web_snapshot, write_web_snapshot

__all__ = [
    "BASE16_SLOTS",
    "SEMANTIC_ALIASES",
    "ConfirmationAnalytics",
    "ConfirmationSummary",
    "ConfirmationWarningGenerator",
    "DashboardQuery",
    "SecurityDashboard",
    "ThemePalette",
    "ThemeValidationError",
    "TuiSnapshot",
    "fetch_snapshot",
    "fetch_web_snapshot",
    "get_builtin_theme",
    "load_theme",
    "parse_btop_theme",
    "render_structured_confirmation",
    "render_web_snapshot",
    "rich_style_map",
    "run_interactive",
    "run_once",
    "safe_summary",
    "textual_theme_css",
    "web_css_variables",
    "write_web_snapshot",
]
