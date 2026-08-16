"""CLI projection for bounded operator-config upgrades."""

from __future__ import annotations

import json
import os
import shlex
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

import click

from shisad.cli.presentation import (
    CliErrorEnvelope,
    StructuredCliError,
    safe_cli_text,
    safe_error_detail,
)
from shisad.core.config_file import selected_config_path
from shisad.core.config_upgrade import (
    ConfigUpgradeError,
    ConfigUpgradePlan,
    ConfigUpgradeResult,
    ConfigUpgradeStatus,
    apply_config_upgrade,
    plan_config_upgrade,
)


@dataclass(frozen=True, slots=True)
class StartupConfigUpgrade:
    """Visible startup disposition for one safe legacy config."""

    plan: ConfigUpgradePlan
    persisted: bool
    backup_path: Path | None
    permissions: str
    parent_sync: str


def prepare_config_for_startup(
    path: Path,
    *,
    managed: bool,
    interactive: bool,
    environ: Mapping[str, str] | None = None,
) -> StartupConfigUpgrade | None:
    """Prepare one existing config before daemon construction."""

    if not path.exists() and not path.is_symlink():
        return None
    effective_environ = dict(os.environ if environ is None else environ)
    plan = plan_config_upgrade(path, environ=effective_environ)
    if plan.status is ConfigUpgradeStatus.CURRENT:
        return None
    if managed or not interactive:
        return StartupConfigUpgrade(
            plan=plan,
            persisted=False,
            backup_path=None,
            permissions="not_applicable",
            parent_sync="not_applicable",
        )
    result = apply_config_upgrade(path, environ=effective_environ)
    return StartupConfigUpgrade(
        plan=plan,
        persisted=True,
        backup_path=result.backup_path,
        permissions=result.permissions,
        parent_sync=result.parent_sync,
    )


def startup_upgrade_lines(result: StartupConfigUpgrade, *, command_path: Path) -> list[str]:
    """Render bounded human guidance for a startup migration disposition."""

    transition = f"schema {result.plan.from_version} -> {result.plan.to_version}"
    safe_path = shlex.quote(safe_cli_text(command_path, limit=320))
    safe_backup_path = shlex.quote(safe_cli_text(result.backup_path, limit=320))
    if not result.persisted:
        return [
            f"Configuration compatibility: {transition} applied in memory; not persisted.",
            "Managed/non-interactive mode does not rewrite operator configuration.",
            f"Next: shisad --config {safe_path} config upgrade --write",
        ]
    return [
        f"Configuration upgraded: {transition}; validation passed.",
        f"Rollback copy: {safe_backup_path}",
        (f"Storage capability: permissions={result.permissions} parent_sync={result.parent_sync}."),
        (
            "Rollback: stop shisad, restore that exact copy to "
            f"{safe_path}, then run config validate."
        ),
    ]


@click.command("upgrade")
@click.option("--write", is_flag=True, help="Persist the known safe migration.")
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["human", "json"]),
    default="human",
    show_default=True,
)
@click.pass_context
def config_upgrade_command(ctx: click.Context, write: bool, output_format: str) -> None:
    """Inspect or explicitly persist a known operator-config migration."""

    root_obj = ctx.find_root().obj
    configured = root_obj.get("config_path") if isinstance(root_obj, dict) else None
    path = selected_config_path(
        configured if isinstance(configured, Path) else None,
    )
    try:
        plan = plan_config_upgrade(path, environ=os.environ)
        result: ConfigUpgradeResult | None = None
        if write and plan.status is ConfigUpgradeStatus.SAFE_MIGRATION:
            result = apply_config_upgrade(path, environ=os.environ)
    except ConfigUpgradeError as exc:
        missing = not path.exists() and not path.is_symlink()
        safe_path = shlex.quote(safe_cli_text(path, limit=320))
        raise StructuredCliError(
            CliErrorEnvelope(
                error_type="config_upgrade",
                exit_code=3,
                what_failed="Could not plan or persist the selected config upgrade.",
                what_still_works="help, version, config template, and config schema commands.",
                likely_cause=(
                    "the config is missing, malformed, unsafe, or uses an unsupported schema."
                ),
                next_action=(
                    f"shisad --config {safe_path} init"
                    if missing
                    else (
                        "use a compatible shisad version or restore a schema_version 1 "
                        "config, then rerun config validate"
                    )
                ),
                technical_details=safe_error_detail(exc),
            ),
            output_format=output_format,
        ) from exc

    changed = bool(result and result.changed)
    backup_path = result.backup_path if result is not None else None
    payload: dict[str, object] = {
        "path": str(path),
        "status": plan.status.value,
        "from_schema_version": plan.from_version,
        "to_schema_version": plan.to_version,
        "breaking": plan.breaking,
        "write_requested": write,
        "changed": changed,
        "source_validated": True,
        "migrated_candidate_validated": result.validated if result is not None else None,
        "permissions": result.permissions if result is not None else "not_applicable",
        "parent_sync": result.parent_sync if result is not None else "not_applicable",
        "backup_path": str(backup_path) if backup_path is not None else None,
        "rollback": (
            f"stop shisad and restore {backup_path} to {path}, then run config validate"
            if backup_path is not None
            else "no rollback needed; configuration was not changed"
        ),
    }
    if output_format == "json":
        click.echo(json.dumps(payload, indent=2, sort_keys=True))
        return
    if plan.status is ConfigUpgradeStatus.CURRENT:
        click.echo(f"Configuration is current (schema_version={plan.to_version}); no change.")
        return
    if result is None:
        click.echo(
            f"Configuration migration available: schema {plan.from_version} -> "
            f"{plan.to_version} (safe, non-breaking)."
        )
        click.echo("Dry run only; rerun with --write to persist it.")
        return
    for line in startup_upgrade_lines(
        StartupConfigUpgrade(
            plan=plan,
            persisted=True,
            backup_path=backup_path,
            permissions=result.permissions,
            parent_sync=result.parent_sync,
        ),
        command_path=path,
    ):
        click.echo(line)
