"""Offline CLI projection for full data-root backup and restore."""

from __future__ import annotations

import json
from pathlib import Path

import click

from shisad.cli.presentation import (
    CliErrorEnvelope,
    StructuredCliError,
    safe_cli_text,
    safe_error_detail,
)
from shisad.core.config_file import ConfigFileError, load_effective_config
from shisad.core.data_backup import (
    DataBackupError,
    DataBackupResult,
    DataRestoreResult,
    create_data_backup,
    restore_data_backup,
)

_OUTPUT_FORMAT = click.option(
    "--format",
    "output_format",
    type=click.Choice(["human", "json"]),
    default="human",
    show_default=True,
)


@click.group()
def data() -> None:
    """Create or restore a stopped-daemon data-root backup."""


@data.command("backup")
@click.argument("destination", type=click.Path(path_type=Path))
@_OUTPUT_FORMAT
@click.pass_context
def data_backup(ctx: click.Context, destination: Path, output_format: str) -> None:
    """Back up the configured data root while the daemon is stopped."""

    root_obj = ctx.find_root().obj
    configured = root_obj.get("config_path") if isinstance(root_obj, dict) else None
    try:
        source = load_effective_config(
            configured if isinstance(configured, Path) else None
        ).daemon.data_dir
        result = create_data_backup(source, destination)
    except ConfigFileError as exc:
        raise _data_cli_error(
            operation="backup",
            exc=exc,
            output_format=output_format,
            next_action="review the selected config, then rerun the data backup",
        ) from exc
    except DataBackupError as exc:
        raise _data_cli_error(
            operation="backup",
            exc=exc,
            output_format=output_format,
            next_action="stop shisad, correct the reported path, then rerun data backup",
        ) from exc
    _emit_backup(result, output_format=output_format)


@data.command("restore")
@click.argument("backup", type=click.Path(path_type=Path))
@click.option(
    "--destination",
    required=True,
    type=click.Path(path_type=Path),
    help="Absent or empty data root to restore; never inferred implicitly.",
)
@_OUTPUT_FORMAT
def data_restore(backup: Path, destination: Path, output_format: str) -> None:
    """Verify and restore a backup without starting or stopping shisad."""

    try:
        result = restore_data_backup(backup, destination)
    except DataBackupError as exc:
        raise _data_cli_error(
            operation="restore",
            exc=exc,
            output_format=output_format,
            next_action=(
                "stop shisad, select an absent or empty destination, verify the backup, "
                "then rerun data restore"
            ),
        ) from exc
    _emit_restore(result, output_format=output_format)


def _data_cli_error(
    *,
    operation: str,
    exc: BaseException,
    output_format: str,
    next_action: str,
) -> StructuredCliError:
    return StructuredCliError(
        CliErrorEnvelope(
            error_type=f"data_{operation}",
            exit_code=3,
            what_failed=f"Could not complete the offline data-root {operation}.",
            what_still_works="help, config inspection, and non-mutating diagnostics.",
            likely_cause="the daemon is running, a path is unsafe, or verification failed.",
            next_action=next_action,
            technical_details=safe_error_detail(exc),
        ),
        output_format=output_format,
    )


def _emit_backup(result: DataBackupResult, *, output_format: str) -> None:
    payload: dict[str, object] = {
        "backup_id": result.backup_id,
        "source": str(result.source),
        "destination": str(result.destination),
        "source_root_fingerprint": result.source_root_fingerprint,
        "file_count": result.file_count,
        "directory_count": result.directory_count,
        "total_bytes": result.total_bytes,
        "verified": result.verified,
        "permissions": result.permissions,
        "parent_sync": result.parent_sync,
        "sensitive_archive": True,
        "next_actions": [
            "store the archive in operator-controlled storage",
            f"shisad data restore {result.destination} --destination <empty-data-root>",
        ],
    }
    if output_format == "json":
        click.echo(json.dumps(payload, sort_keys=True))
        return
    click.echo(f"Verified backup {result.backup_id}: {safe_cli_text(result.destination)}")
    click.echo(f"Source: {safe_cli_text(result.source)}")
    click.echo(
        f"Included {result.file_count} files and {result.directory_count} directories "
        f"({result.total_bytes} bytes)."
    )
    click.echo(
        f"Storage capability: permissions={result.permissions} parent_sync={result.parent_sync}."
    )
    click.echo("Sensitive archive: keep this owner-only file in operator-controlled storage.")
    click.echo(
        f"Restore: shisad data restore {safe_cli_text(result.destination)} "
        "--destination <empty-data-root>"
    )


def _emit_restore(result: DataRestoreResult, *, output_format: str) -> None:
    payload: dict[str, object] = {
        "backup_id": result.backup_id,
        "archive": str(result.archive),
        "destination": str(result.destination),
        "source_root_fingerprint": result.source_root_fingerprint,
        "file_count": result.file_count,
        "directory_count": result.directory_count,
        "total_bytes": result.total_bytes,
        "verified": result.verified,
        "permissions": result.permissions,
        "parent_sync": result.parent_sync,
        "offline_health_verified": False,
        "next_actions": ["shisad start", "shisad status", "shisad doctor"],
        "rollback": "stop shisad and restore a different verified backup into a new empty root",
    }
    if output_format == "json":
        click.echo(json.dumps(payload, sort_keys=True))
        return
    click.echo(
        f"Verified backup {result.backup_id} restored to {safe_cli_text(result.destination)}."
    )
    click.echo(f"Archive: {safe_cli_text(result.archive)}")
    click.echo(f"Source-root fingerprint: {result.source_root_fingerprint}")
    click.echo(
        f"Restored {result.file_count} files and {result.directory_count} directories "
        f"({result.total_bytes} bytes)."
    )
    click.echo(
        f"Storage capability: permissions={result.permissions} parent_sync={result.parent_sync}."
    )
    click.echo("Sensitive archive: retain the owner-controlled backup for rollback.")
    click.echo("Offline health is not yet verified.")
    click.echo("Next: shisad start")
    click.echo("Then: shisad status")
    click.echo("Finally: shisad doctor")
    click.echo(
        "Rollback: stop shisad and restore a different verified backup into a new empty root."
    )
