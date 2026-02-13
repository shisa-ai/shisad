"""Shared RPC helpers for CLI commands."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Awaitable, Callable, Coroutine
from contextlib import asynccontextmanager, suppress
from typing import Any, overload

import click
from pydantic import BaseModel, ValidationError

from shisad.core.api.transport import ControlClient
from shisad.core.config import DaemonConfig


def run_async[T](coro: Coroutine[Any, Any, T]) -> T:
    return asyncio.run(coro)


def _connection_error(config: DaemonConfig, exc: OSError) -> click.ClickException:
    return click.ClickException(f"Unable to connect to daemon at {config.socket_path}: {exc}")


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
    except Exception as exc:
        raise click.ClickException(f"{action} failed: {exc}") from exc


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
    except Exception as exc:
        raise click.ClickException(f"{method} failed: {exc}") from exc

    if response_model is None:
        if not isinstance(payload, dict):
            raise click.ClickException(
                f"{method} returned invalid response type: {type(payload).__name__}"
            )
        return payload

    try:
        return response_model.model_validate(payload)
    except ValidationError as exc:
        raise click.ClickException(f"{method} returned invalid response: {exc}") from exc
    except Exception as exc:
        raise click.ClickException(f"{method} response validation failed: {exc}") from exc
