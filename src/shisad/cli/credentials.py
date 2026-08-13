"""Credential-reference administration commands for O2 setup."""

from __future__ import annotations

import json
import os
import sys
from collections.abc import Mapping
from pathlib import Path

import click

from shisad.cli.onboarding import EnvironmentDetectionError, parse_managed_posture
from shisad.cli.presentation import CliErrorEnvelope, StructuredCliError
from shisad.core.config import effective_credential_reference_paths
from shisad.core.config_file import ConfigFileError, load_effective_config
from shisad.security.credential_refs import (
    CredentialBackend,
    CredentialReference,
    CredentialReferenceError,
    CredentialReferenceStore,
    CredentialStatus,
)


class CredentialCliError(StructuredCliError):
    """Expected credential administration failure."""

    exit_code = 3

    def __init__(self, *, reason: str, next_action: str, output_format: str) -> None:
        super().__init__(
            CliErrorEnvelope(
                error_type="credential",
                exit_code=self.exit_code,
                what_failed="Could not update credential reference state.",
                what_still_works="help, config inspection, and unrelated local daemon features.",
                likely_cause=reason,
                next_action=next_action,
                technical_details=reason,
            ),
            output_format=output_format,
        )


def _store_from_context(ctx: click.Context, *, output_format: str) -> CredentialReferenceStore:
    root = ctx.find_root()
    selected = (root.obj or {}).get("config_path")
    config_path = selected if isinstance(selected, Path) else None
    try:
        loaded = load_effective_config(config_path, environ=os.environ)
    except ConfigFileError as exc:
        raise CredentialCliError(
            reason="operator configuration is missing, invalid, unsafe, or unsupported",
            next_action="repair the selected config, then rerun the credential command",
            output_format=output_format,
        ) from exc
    registry_path, secret_root = effective_credential_reference_paths(
        data_dir=loaded.daemon.data_dir,
        configured_store_path=loaded.security.credential_reference_store_path,
        configured_secret_dir=loaded.security.credential_secret_dir,
    )
    return CredentialReferenceStore(
        registry_path=registry_path,
        secret_root=secret_root,
        environ=os.environ,
    )


def _status_payload(status: CredentialStatus) -> dict[str, object]:
    return status.model_dump(mode="json")


def _emit_status(status: CredentialStatus, *, output_format: str) -> None:
    payload = _status_payload(status)
    if output_format == "json":
        click.echo(json.dumps(payload, indent=2, sort_keys=True))
        return
    backend = status.backend.value if status.backend is not None else "none"
    click.echo(
        f"{status.name} backend={backend} "
        f"configured={'yes' if status.configured else 'no'} "
        f"available={'yes' if status.available else 'no'} "
        f"reason={status.reason}"
    )


def _credential_error(
    exc: CredentialReferenceError,
    *,
    output_format: str,
) -> CredentialCliError:
    actions: Mapping[str, str] = {
        "credential_reference_invalid": "use a lowercase logical name and valid backend locator",
        "credential_reference_exists": "rerun with --replace or remove the existing reference",
        "credential_backend_material_exists": (
            "rerun with --replace to claim and replace the existing backend value"
        ),
        "credential_secret_required": "supply the secret through --stdin or an interactive prompt",
        "keyring_backend_unavailable": (
            "install shisad[credentials] and configure a usable OS keyring"
        ),
        "credential_registry_busy": "wait for the current credential operation, then retry",
    }
    return CredentialCliError(
        reason=exc.reason,
        next_action=actions.get(exc.reason, "inspect credential status and retry explicitly"),
        output_format=output_format,
    )


def _secret_input(*, use_stdin: bool, output_format: str) -> str:
    try:
        managed = parse_managed_posture(os.environ)
    except EnvironmentDetectionError as exc:
        raise CredentialCliError(
            reason="SHISAD_MANAGED has an unsupported explicit value",
            next_action="set SHISAD_MANAGED to true or false, then retry",
            output_format=output_format,
        ) from exc
    if use_stdin:
        if bool(getattr(sys.stdin, "isatty", lambda: False)()):
            raise CredentialCliError(
                reason="credential_secret_input_tty",
                next_action="pipe the secret from non-interactive standard input",
                output_format=output_format,
            )
        secret = sys.stdin.read()
        secret = secret.removesuffix("\r\n").removesuffix("\n").removesuffix("\r")
        if not secret:
            raise CredentialCliError(
                reason="credential_secret_required",
                next_action="pipe a non-empty secret to the command's standard input",
                output_format=output_format,
            )
        return secret
    if managed or not bool(getattr(sys.stdin, "isatty", lambda: False)()):
        raise CredentialCliError(
            reason="credential_secret_input_required",
            next_action="rerun with --stdin and pipe the secret through standard input",
            output_format=output_format,
        )
    return str(
        click.prompt(
            "Credential secret",
            hide_input=True,
            confirmation_prompt=True,
            type=str,
        )
    )


@click.group("credential")
def credential() -> None:
    """Manage provider-agnostic credential references."""


@credential.command("set")
@click.argument("name")
@click.option(
    "--backend",
    type=click.Choice([backend.value for backend in CredentialBackend]),
    required=True,
)
@click.option("--locator", default="", help="Environment variable or keyring service name.")
@click.option("--stdin", "use_stdin", is_flag=True, help="Read the secret from standard input.")
@click.option("--replace", is_flag=True, help="Explicitly replace an existing reference.")
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["human", "json"]),
    default="human",
    show_default=True,
)
@click.pass_context
def credential_set(
    ctx: click.Context,
    name: str,
    backend: str,
    locator: str,
    use_stdin: bool,
    replace: bool,
    output_format: str,
) -> None:
    """Register a logical credential without placing its value in argv."""
    selected_backend = CredentialBackend(backend)
    if selected_backend is CredentialBackend.ENV and use_stdin:
        raise CredentialCliError(
            reason="env_backend_rejects_secret_value",
            next_action="omit --stdin; environment entries persist only the variable name",
            output_format=output_format,
        )
    if selected_backend is CredentialBackend.FILE and locator:
        raise CredentialCliError(
            reason="file_backend_rejects_locator",
            next_action="omit --locator; file entries are contained by their logical name",
            output_format=output_format,
        )
    if selected_backend is CredentialBackend.KEYRING and not locator:
        locator = "shisad"
    try:
        CredentialReference(
            name=name,
            backend=selected_backend,
            locator=name if selected_backend is CredentialBackend.FILE else locator,
        )
    except ValueError:
        raise _credential_error(
            CredentialReferenceError("credential_reference_invalid"),
            output_format=output_format,
        ) from None
    secret = (
        None
        if selected_backend is CredentialBackend.ENV
        else _secret_input(use_stdin=use_stdin, output_format=output_format)
    )
    try:
        status = _store_from_context(ctx, output_format=output_format).set_reference(
            name=name,
            backend=selected_backend,
            locator=locator,
            secret=secret,
            replace=replace,
        )
    except CredentialReferenceError as exc:
        raise _credential_error(exc, output_format=output_format) from exc
    _emit_status(status, output_format=output_format)


@credential.command("status")
@click.argument("name")
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["human", "json"]),
    default="human",
    show_default=True,
)
@click.pass_context
def credential_status(ctx: click.Context, name: str, output_format: str) -> None:
    """Report one credential reference without resolving its value to output."""
    try:
        status = _store_from_context(ctx, output_format=output_format).status(name)
    except CredentialReferenceError as exc:
        raise _credential_error(exc, output_format=output_format) from exc
    _emit_status(status, output_format=output_format)


@credential.command("remove")
@click.argument("name")
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["human", "json"]),
    default="human",
    show_default=True,
)
@click.pass_context
def credential_remove(ctx: click.Context, name: str, output_format: str) -> None:
    """Remove backend material and its logical reference."""
    try:
        status = _store_from_context(ctx, output_format=output_format).remove(name)
    except CredentialReferenceError as exc:
        raise _credential_error(exc, output_format=output_format) from exc
    _emit_status(status, output_format=output_format)
