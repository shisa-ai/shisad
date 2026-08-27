"""Daemon runner — main event loop for shisad."""

from __future__ import annotations

import asyncio
import contextlib
import logging
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any, cast

from pydantic import BaseModel

from shisad.core.api.rpc_registry import rpc_method_descriptors
from shisad.core.config import DaemonConfig
from shisad.core.interfaces import TypedHandler
from shisad.core.log import setup_logging
from shisad.daemon.control_handlers import DaemonControlHandlers
from shisad.daemon.event_wiring import channel_receive_pump
from shisad.daemon.services import DaemonServices

logger = logging.getLogger(__name__)


def _warn_on_startup_config_gaps(config: DaemonConfig) -> None:
    if config.assistant_fs_roots:
        return
    logger.warning(
        "No filesystem roots configured - fs.read, fs.list, fs.write, and git "
        "tools will not work. Set SHISAD_ASSISTANT_FS_ROOTS to enable."
    )


def _method_specs(
    handlers: DaemonControlHandlers,
    *,
    test_mode: bool = False,
) -> list[tuple[str, TypedHandler, bool, type[BaseModel]]]:
    return [
        (
            descriptor.name,
            handlers.bind_rpc_handler(descriptor),
            descriptor.admin_only,
            descriptor.params_model,
        )
        for descriptor in rpc_method_descriptors(test_mode=test_mode)
    ]


def _wrap_tracked_handler(
    *,
    services: DaemonServices,
    method_name: str,
    method_handler: TypedHandler,
) -> TypedHandler:
    async def _tracked_handler(params: BaseModel, ctx: Any) -> Any:
        async with services.rpc_state_lock:
            if services.reset_in_progress and method_name not in {
                "daemon.reset",
                "daemon.shutdown",
            }:
                raise RuntimeError("Cannot execute control RPC while daemon.reset is in progress")
            services.active_rpc_calls += 1
        try:
            return await method_handler(params, ctx)
        finally:
            async with services.rpc_state_lock:
                if services.active_rpc_calls <= 0:
                    logger.warning(
                        (
                            "RPC activity counter underflow while finishing "
                            "method %s; resetting to zero"
                        ),
                        method_name,
                    )
                    services.active_rpc_calls = 0
                else:
                    services.active_rpc_calls -= 1

    return cast(TypedHandler, _tracked_handler)


async def _reminder_delivery_pump(
    *,
    services: DaemonServices,
    handlers: DaemonControlHandlers,
) -> None:
    """Poll scheduler due-runs and route them through the shared background executor."""
    while not services.shutdown_event.is_set():
        try:
            due_runs = services.scheduler.trigger_due(now=datetime.now(UTC))
        except Exception:
            logger.exception("scheduler due-run evaluation failed")
            due_runs = []
        for run in due_runs:
            task = services.scheduler.get_task(run.task_id)
            if task is None:
                continue
            try:
                await handlers._impl.do_task_execute_due_run(
                    run,
                    event_type=f"schedule.{task.schedule.kind.value}",
                )
            except Exception:
                logger.exception("scheduler due-run execution failed for task %s", run.task_id)
        try:
            await asyncio.wait_for(services.shutdown_event.wait(), timeout=1.0)
        except TimeoutError:
            continue


async def run_daemon(config: DaemonConfig, on_started: Callable[[], None] | None = None) -> None:
    """Run the shisad daemon."""
    setup_logging(level=config.log_level)
    services = await DaemonServices.build(config)
    try:
        await _serve_daemon(config, services, on_started)
    finally:
        await services.shutdown()


async def _serve_daemon(
    config: DaemonConfig, services: DaemonServices, on_started: Callable[[], None] | None
) -> None:
    handlers = services.control_handlers
    await services.approval_web.start()
    await services.delivery.recover(
        capability_resolver=handlers._impl._resolve_chat_approval_capability
    )

    for method_name, method_handler, admin_only, params_model in _method_specs(
        handlers,
        test_mode=config.test_mode,
    ):
        services.server.register_method(
            method_name,
            _wrap_tracked_handler(
                services=services,
                method_name=method_name,
                method_handler=method_handler,
            ),
            admin_only=admin_only,
            params_model=params_model,
        )

    await services.server.start()
    logger.info("shisad daemon started")
    if on_started is not None:
        try:
            on_started()
        except Exception:
            logger.exception("daemon started callback failed")

    # Effective config summary — so operators can verify settings from logs
    _search_status = "enabled" if config.web_search_enabled else "DISABLED"
    _fetch_status = "enabled" if config.web_fetch_enabled else "DISABLED"
    _search_backend = config.web_search_backend_url or "(not configured)"
    _n_domains = len(config.web_allowed_domains)
    logger.info(
        "Config: web.search=%s backend=%s web.fetch=%s allowed_domains=%d fs_roots=%s",
        _search_status,
        _search_backend,
        _fetch_status,
        _n_domains,
        config.assistant_fs_roots,
    )
    _warn_on_startup_config_gaps(config)
    channel_pump_tasks: list[asyncio.Task[None]] = []
    reminder_pump_task = asyncio.create_task(
        _reminder_delivery_pump(services=services, handlers=handlers)
    )
    for channel_name, channel in services.channels.items():
        channel_pump_tasks.append(
            asyncio.create_task(
                channel_receive_pump(
                    channel_name=channel_name,
                    channel=channel,
                    shutdown_event=services.shutdown_event,
                    handlers=handlers.admin,
                )
            )
        )

    try:
        await services.shutdown_event.wait()
    finally:
        for task in channel_pump_tasks:
            task.cancel()
        reminder_pump_task.cancel()
        for task in channel_pump_tasks:
            with contextlib.suppress(asyncio.CancelledError):
                await task
        with contextlib.suppress(asyncio.CancelledError):
            await reminder_pump_task
        logger.info("shisad daemon stopped")
