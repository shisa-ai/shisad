"""Shared RPC helpers for CLI commands."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Awaitable, Callable, Coroutine
from contextlib import asynccontextmanager, suppress
from typing import Any, overload

import click
from pydantic import BaseModel, ValidationError

from shisad.cli.presentation import CliErrorEnvelope, StructuredCliError, safe_error_detail
from shisad.core.api.transport import ControlClient
from shisad.core.config import DaemonConfig


class DaemonCliError(StructuredCliError):
    """Expected daemon/runtime failure with the documented CLI exit status."""

    exit_code = 2


def daemon_cli_error(
    *,
    what_failed: str,
    exc: BaseException,
    next_action: str = "shisad doctor",
) -> DaemonCliError:
    """Build the shared expected-error envelope used by daemon-facing commands."""

    return DaemonCliError(
        CliErrorEnvelope(
            error_type="daemon",
            exit_code=DaemonCliError.exit_code,
            what_failed=what_failed,
            what_still_works="config, help, and offline inspection commands.",
            likely_cause="the daemon is stopped, unreachable, or rejected the request.",
            next_action=next_action,
            technical_details=safe_error_detail(exc),
        )
    )


def run_async[T](coro: Coroutine[Any, Any, T]) -> T:
    return asyncio.run(coro)


def _connection_error(config: DaemonConfig, exc: OSError) -> DaemonCliError:
    return daemon_cli_error(
        what_failed=f"Could not connect to the shisad daemon at {config.socket_path}.",
        exc=exc,
        next_action="shisad start --foreground",
    )


@asynccontextmanager
async def rpc_client(config: DaemonConfig) -> AsyncIterator[ControlClient]:
    client = ControlClient(config.socket_path)
    try:
        await client.connect()
    except OSError as exc:
        raise _connection_error(config, exc) from exc

    try:
        yield client
    finally:
        with suppress(OSError, RuntimeError):
            await client.close()


async def _rpc_run_async[T](
    config: DaemonConfig,
    operation: Callable[[ControlClient], Awaitable[T]],
) -> T:
    async with rpc_client(config) as client:
        return await operation(client)


def rpc_run[T](
    config: DaemonConfig,
    operation: Callable[[ControlClient], Awaitable[T]],
    *,
    action: str,
) -> T:
    try:
        return run_async(_rpc_run_async(config, operation))
    except click.ClickException:
        raise
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        raise daemon_cli_error(what_failed=f"{action} failed.", exc=exc) from exc


async def _rpc_call_async(
    config: DaemonConfig,
    method: str,
    params: dict[str, Any] | None = None,
) -> Any:
    async with rpc_client(config) as client:
        return await client.call(method, params=params or {})


@overload
def rpc_call[T: BaseModel](
    config: DaemonConfig,
    method: str,
    params: dict[str, Any] | None = None,
    *,
    response_model: type[T],
) -> T: ...


@overload
def rpc_call(
    config: DaemonConfig,
    method: str,
    params: dict[str, Any] | None = None,
    *,
    response_model: None = None,
) -> dict[str, Any]: ...


def rpc_call(
    config: DaemonConfig,
    method: str,
    params: dict[str, Any] | None = None,
    *,
    response_model: type[BaseModel] | None = None,
) -> BaseModel | dict[str, Any]:
    try:
        payload = run_async(_rpc_call_async(config, method, params))
    except click.ClickException:
        raise
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        raise daemon_cli_error(what_failed=f"{method} failed.", exc=exc) from exc

    if response_model is None:
        if not isinstance(payload, dict):
            raise click.ClickException(
                f"{method} returned invalid response type: {type(payload).__name__}"
            )
        return payload

    try:
        return response_model.model_validate(payload)
    except ValidationError as exc:
        raise daemon_cli_error(
            what_failed=f"{method} returned an invalid response.",
            exc=exc,
        ) from exc
    except (RuntimeError, TypeError, ValueError) as exc:
        raise daemon_cli_error(
            what_failed=f"{method} response validation failed.",
            exc=exc,
        ) from exc
