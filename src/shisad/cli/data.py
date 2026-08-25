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

_CROSS_ROOT_ENCRYPTED_MEMORY_GUIDANCE = (
    "Starting encrypted memory at a different absolute data root requires an explicit stable "
    "SHISAD_MEMORY_MASTER_KEY configured before the source data was created and the same value "
    "at startup. Memory using the default path-derived key can be reopened only at its original "
    "absolute data root."
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
            "backup", exc, output_format, "review the selected config, then rerun the data backup"
        ) from exc
    except DataBackupError as exc:
        raise _data_cli_error(
            "backup",
            exc,
            output_format,
            "stop shisad, correct the reported path, then rerun data backup",
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
            "restore",
            exc,
            output_format,
            (
                "stop shisad, select an absent or empty destination, verify the backup, "
                "then rerun data restore"
            ),
        ) from exc
    _emit_restore(result, output_format=output_format)


def _data_cli_error(
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
    payload = _transfer_payload(result) | {
        "source": str(result.source),
        "sensitive_archive": True,
        "next_actions": [
            "store the archive in operator-controlled storage",
            f"shisad data restore {result.destination} --destination <empty-data-root>",
        ],
    }
    if output_format == "json":
        click.echo(json.dumps(payload, sort_keys=True))
        return
    click.echo(
        f"Verified backup {result.backup_id}: {safe_cli_text(result.destination)}\n"
        f"Source: {safe_cli_text(result.source)}\n"
        f"Included {result.file_count} files and {result.directory_count} directories "
        f"({result.total_bytes} bytes).\n"
        f"Storage capability: permissions={result.permissions} "
        f"parent_sync={result.parent_sync}.\n"
        "Sensitive archive: keep this owner-only file in operator-controlled storage.\n"
        f"Restore: shisad data restore {safe_cli_text(result.destination)} "
        "--destination <empty-data-root>"
    )


def _emit_restore(result: DataRestoreResult, *, output_format: str) -> None:
    payload = _transfer_payload(result) | {
        "archive": str(result.archive),
        "sensitive_archive": True,
        "sensitive_archive_handling": "retain in operator-controlled storage",
        "offline_health_verified": False,
        "cross_root_encrypted_memory": _CROSS_ROOT_ENCRYPTED_MEMORY_GUIDANCE,
        "next_actions": ["shisad start", "shisad status", "shisad doctor"],
        "rollback": "stop shisad and restore a different verified backup into a new empty root",
    }
    if output_format == "json":
        click.echo(json.dumps(payload, sort_keys=True))
        return
    click.echo(
        f"Verified backup {result.backup_id} restored to "
        f"{safe_cli_text(result.destination)}.\n"
        f"Archive: {safe_cli_text(result.archive)}\n"
        f"Source-root fingerprint: {result.source_root_fingerprint}\n"
        f"Restored {result.file_count} files and {result.directory_count} directories "
        f"({result.total_bytes} bytes).\n"
        f"Storage capability: permissions={result.permissions} "
        f"parent_sync={result.parent_sync}.\n"
        "Sensitive archive: retain the owner-controlled backup for rollback.\n"
        "Offline health is not yet verified.\n"
        f"Encrypted-memory relocation: {_CROSS_ROOT_ENCRYPTED_MEMORY_GUIDANCE}\n"
        "Next: shisad start\nThen: shisad status\n"
        "Finally: shisad doctor\nRollback: stop shisad and restore a different verified backup "
        "into a new empty root."
    )


def _transfer_payload(result: DataBackupResult | DataRestoreResult) -> dict[str, object]:
    names = (
        "backup_id file_count directory_count total_bytes verified permissions parent_sync "
        "source_root_fingerprint"
    )
    return {name: getattr(result, name) for name in names.split()} | {
        "destination": str(result.destination)
    }
