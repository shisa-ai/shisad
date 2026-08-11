"""Bounded read-only environment detection and welcome projection."""

from __future__ import annotations

import asyncio
import os
import sys
from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
from enum import StrEnum
from pathlib import Path

import click

from shisad.cli.presentation import safe_cli_text
from shisad.core.api.schema import DaemonStatusResult
from shisad.core.api.transport import ControlClient
from shisad.core.config_file import load_effective_config, selected_config_path
from shisad.ui.motion import glyph
from shisad.ui.theme import UiPosture

_TRUTHY = frozenset({"1", "true", "yes", "on"})
_FALSY = frozenset({"0", "false", "no", "off"})
_CONTAINER_MARKERS = (Path("/.dockerenv"), Path("/run/.containerenv"))
_SUPPORTED_PYTHON = (3, 12)


class ConfiguredPosture(StrEnum):
    """Finite top-level presentation posture for a bare invocation."""

    FRESH = "fresh"
    RETURNING = "returning"
    UPGRADE_REQUIRED = "upgrade_required"
    MANAGED = "managed"
    NON_INTERACTIVE = "non_interactive"


class CheckRequirement(StrEnum):
    REQUIRED = "required"
    OPTIONAL = "optional"
    INFORMATIONAL = "informational"


class CheckState(StrEnum):
    PASS = "pass"
    FAIL = "fail"
    DEGRADED = "degraded"
    INFO = "info"


class EnvironmentDetectionError(ValueError):
    """An explicit environment value cannot be interpreted safely."""


@dataclass(frozen=True, slots=True)
class EnvironmentFacts:
    posture: ConfiguredPosture
    config_path: Path
    config_present: bool
    explicit_config: bool
    interactive: bool
    managed: bool
    containerized: bool
    python_version: tuple[int, int, int]
    policy_present: bool
    daemon_reachable: bool
    ui_theme: str = "shisa-dark"
    reduce_motion: bool = False


@dataclass(frozen=True, slots=True)
class PreflightCheck:
    check_id: str
    label: str
    requirement: CheckRequirement
    state: CheckState
    detail: str


@dataclass(frozen=True, slots=True)
class PreflightReport:
    facts: EnvironmentFacts
    checks: tuple[PreflightCheck, ...]
    next_action: str

    @property
    def blocked(self) -> bool:
        return any(
            check.requirement is CheckRequirement.REQUIRED and check.state is CheckState.FAIL
            for check in self.checks
        )


def parse_managed_posture(environ: Mapping[str, str]) -> bool:
    """Parse the finite managed-mode flag without treating invalid as false."""

    value = str(environ.get("SHISAD_MANAGED", "")).lower()
    if not value or value in _FALSY:
        return False
    if value in _TRUTHY:
        return True
    raise EnvironmentDetectionError(
        "SHISAD_MANAGED must be set to true or false "
        "(accepted values: 1/0, true/false, yes/no, on/off)."
    )


def classify_configured_posture(
    *,
    config_present: bool,
    interactive: bool,
    managed: bool,
    schema_supported: bool,
) -> ConfiguredPosture:
    """Select a posture from finite machine facts with fail-safe precedence."""

    if not schema_supported:
        return ConfiguredPosture.UPGRADE_REQUIRED
    if managed:
        return ConfiguredPosture.MANAGED
    if not interactive:
        return ConfiguredPosture.NON_INTERACTIVE
    if config_present:
        return ConfiguredPosture.RETURNING
    return ConfiguredPosture.FRESH


def detect_container(
    markers: tuple[Path, ...] = _CONTAINER_MARKERS,
) -> bool:
    """Return the bounded informational container marker fact."""

    return any(marker.exists() for marker in markers)


async def probe_daemon(socket_path: Path, *, timeout: float = 1.0) -> bool:
    """Bound one read-only status request and close any connected client."""

    client = ControlClient(socket_path)
    connected = False
    reachable = False
    loop = asyncio.get_running_loop()
    deadline = loop.time() + max(0.001, timeout)
    try:
        async with asyncio.timeout_at(deadline):
            await client.connect()
            connected = True
            payload = await client.call("daemon.status")
            status = DaemonStatusResult.model_validate(payload)
            reachable = status.status == "running"
    except (TimeoutError, AttributeError, OSError, RuntimeError, TypeError, ValueError):
        reachable = False
    finally:
        if connected:
            try:
                async with asyncio.timeout_at(deadline):
                    await client.close()
            except (TimeoutError, AttributeError, OSError, RuntimeError, TypeError, ValueError):
                reachable = False
    return reachable


def _sync_daemon_probe(socket_path: Path) -> bool:
    return asyncio.run(probe_daemon(socket_path))


def inspect_onboarding_environment(
    config_path: Path | None,
    *,
    environ: Mapping[str, str] | None = None,
    interactive: bool | None = None,
    python_version: tuple[int, int, int] | None = None,
    containerized: bool | None = None,
    daemon_probe: Callable[[Path], bool] | None = None,
) -> PreflightReport:
    """Load canonical facts and build the bare-command preflight projection."""

    effective_env = dict(os.environ if environ is None else environ)
    managed = parse_managed_posture(effective_env)
    selected = selected_config_path(config_path, environ=effective_env)
    explicit = config_path is not None or bool(
        str(effective_env.get("SHISAD_CONFIG_PATH", "")).strip()
    )
    config_present = selected.exists()
    loaded = load_effective_config(config_path, environ=effective_env)
    is_interactive = sys.stdout.isatty() if interactive is None else bool(interactive)
    posture = classify_configured_posture(
        config_present=config_present,
        interactive=is_interactive,
        managed=managed,
        schema_supported=True,
    )
    reachable = False
    if config_present and loaded.daemon.socket_path.exists():
        reachable = (daemon_probe or _sync_daemon_probe)(loaded.daemon.socket_path)
    version = python_version or (
        sys.version_info.major,
        sys.version_info.minor,
        sys.version_info.micro,
    )
    facts = EnvironmentFacts(
        posture=posture,
        config_path=selected,
        config_present=config_present,
        explicit_config=explicit,
        interactive=is_interactive,
        managed=managed,
        containerized=detect_container() if containerized is None else containerized,
        python_version=version,
        policy_present=loaded.daemon.policy_path.exists(),
        daemon_reachable=reachable,
        ui_theme=loaded.daemon.ui_theme,
        reduce_motion=loaded.daemon.reduce_motion,
    )
    return build_preflight_report(facts)


def build_preflight_report(facts: EnvironmentFacts) -> PreflightReport:
    """Project required, optional, and informational checks from typed facts."""

    runtime_supported = facts.python_version[:2] >= _SUPPORTED_PYTHON
    checks = [
        PreflightCheck(
            check_id="runtime",
            label="Python runtime",
            requirement=CheckRequirement.REQUIRED,
            state=CheckState.PASS if runtime_supported else CheckState.FAIL,
            detail=(
                f"{'.'.join(str(part) for part in facts.python_version)} supported"
                if runtime_supported
                else "Python 3.12 or newer is required"
            ),
        ),
        PreflightCheck(
            check_id="config",
            label="Configuration",
            requirement=(
                CheckRequirement.REQUIRED
                if facts.config_present
                else CheckRequirement.INFORMATIONAL
            ),
            state=CheckState.PASS if facts.config_present else CheckState.INFO,
            detail=(
                f"valid: {facts.config_path}"
                if facts.config_present
                else f"not created: {facts.config_path}"
            ),
        ),
        PreflightCheck(
            check_id="policy",
            label="Policy",
            requirement=CheckRequirement.OPTIONAL,
            state=CheckState.PASS if facts.policy_present else CheckState.DEGRADED,
            detail=(
                "configured policy is present"
                if facts.policy_present
                else "not present; explicit startup retains warned default policy"
            ),
        ),
        PreflightCheck(
            check_id="daemon",
            label="Daemon",
            requirement=(
                CheckRequirement.OPTIONAL
                if facts.config_present
                else CheckRequirement.INFORMATIONAL
            ),
            state=(
                CheckState.PASS
                if facts.daemon_reachable
                else CheckState.DEGRADED
                if facts.config_present
                else CheckState.INFO
            ),
            detail=(
                "running and reachable"
                if facts.daemon_reachable
                else "stopped or unreachable"
                if facts.config_present
                else "not checked before configuration"
            ),
        ),
        PreflightCheck(
            check_id="environment",
            label="Environment",
            requirement=CheckRequirement.INFORMATIONAL,
            state=CheckState.INFO,
            detail=_environment_detail(facts),
        ),
    ]
    return PreflightReport(
        facts=facts,
        checks=tuple(checks),
        next_action=_next_action(facts, runtime_supported=runtime_supported),
    )


def _environment_detail(facts: EnvironmentFacts) -> str:
    mode = "managed" if facts.managed else "interactive" if facts.interactive else "non-interactive"
    container = ", container marker present" if facts.containerized else ""
    return f"{mode}{container}"


def _next_action(facts: EnvironmentFacts, *, runtime_supported: bool) -> str:
    if not runtime_supported:
        return "install Python 3.12 or newer, then run: shisad"
    if facts.posture is ConfiguredPosture.UPGRADE_REQUIRED:
        return "restore a supported schema_version=1 config, then run: shisad config validate"
    if facts.posture is ConfiguredPosture.MANAGED:
        return "shisad status" if facts.daemon_reachable else "shisad doctor"
    if facts.posture is ConfiguredPosture.NON_INTERACTIVE:
        if not facts.config_present:
            return "shisad init"
        return "shisad status" if facts.daemon_reachable else "shisad doctor"
    if facts.posture is ConfiguredPosture.FRESH:
        return "shisad init"
    return "shisad chat" if facts.daemon_reachable else "shisad start --foreground"


def render_welcome(report: PreflightReport, *, ui_posture: UiPosture) -> str:
    """Render one semantic report with Unicode/color or deterministic fallback."""

    lines = [_render_logo(ui_posture), "", _welcome_label(report.facts), "", "Preflight"]
    render_capabilities = replace(
        ui_posture.capabilities,
        unicode=_unicode_rendering_enabled(ui_posture),
    )
    for check in report.checks:
        icon_name, color_name = _check_style(check.state)
        marker = glyph(icon_name, render_capabilities)
        prefix = _style(
            f"{marker} {check.label}",
            semantic=color_name,
            ui_posture=ui_posture,
            bold=check.requirement is CheckRequirement.REQUIRED,
        )
        lines.append(
            f"{prefix} [{check.requirement.value}]: {safe_cli_text(check.detail, limit=512)}"
        )
    lines.extend(
        [
            "",
            _style(
                f"Next action: {safe_cli_text(report.next_action, limit=512)}",
                semantic="accent",
                ui_posture=ui_posture,
                bold=True,
            ),
        ]
    )
    return "\n".join(lines)


def _welcome_label(facts: EnvironmentFacts) -> str:
    install = "Returning installation" if facts.config_present else "Fresh install"
    if facts.posture is ConfiguredPosture.MANAGED:
        return f"Managed environment ({install})"
    if facts.posture is ConfiguredPosture.NON_INTERACTIVE:
        return f"Non-interactive environment ({install})"
    if facts.posture is ConfiguredPosture.UPGRADE_REQUIRED:
        return "Upgrade required"
    return install


def _render_logo(ui_posture: UiPosture) -> str:
    if _unicode_rendering_enabled(ui_posture):
        logo = "╭─ shisad ─╮\n╰ security-first agent daemon ╯"
    else:
        logo = "[ shisad ]\nsecurity-first agent daemon"
    return _style(logo, semantic="accent", ui_posture=ui_posture, bold=True)


def _unicode_rendering_enabled(ui_posture: UiPosture) -> bool:
    return ui_posture.color_enabled and ui_posture.capabilities.unicode


def _check_style(state: CheckState) -> tuple[str, str]:
    if state is CheckState.PASS:
        return "success", "success"
    if state is CheckState.FAIL:
        return "error", "danger"
    if state is CheckState.DEGRADED:
        return "warning", "warning"
    return "info", "info"


def _style(
    text: str,
    *,
    semantic: str,
    ui_posture: UiPosture,
    bold: bool = False,
) -> str:
    if (
        not ui_posture.color_enabled
        or not ui_posture.capabilities.unicode
        or ui_posture.capabilities.color_mode == "none"
    ):
        return text
    color = ui_posture.palette.color(semantic)
    rgb = (
        int(color[1:3], 16),
        int(color[3:5], 16),
        int(color[5:7], 16),
    )
    return click.style(text, fg=rgb, bold=bold)
