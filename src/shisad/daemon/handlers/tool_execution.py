"""Typed tool execution handler group."""

from __future__ import annotations

from typing import TYPE_CHECKING

from shisad.core.api.schema import (
    BrowserPasteParams,
    BrowserScreenshotParams,
    ToolExecuteParams,
    ToolExecuteResult,
)
from shisad.daemon.context import RequestContext
from shisad.daemon.handlers._helpers import build_params_payload
from shisad.daemon.handlers._impl import HandlerImplementation

if TYPE_CHECKING:
    from shisad.executors.browser import BrowserPasteResult, BrowserScreenshotResult


class ToolExecutionHandlers:
    """Tool and browser execution handlers."""

    def __init__(self, impl: HandlerImplementation, *, internal_ingress_marker: object) -> None:
        self._impl = impl
        self._internal_ingress_marker = internal_ingress_marker

    async def handle_tool_execute(
        self,
        params: ToolExecuteParams,
        ctx: RequestContext,
    ) -> ToolExecuteResult:
        payload = build_params_payload(
            params,
            ctx,
            internal_ingress_marker=self._internal_ingress_marker,
        )
        return ToolExecuteResult.model_validate(await self._impl.do_tool_execute(payload))

    async def handle_browser_paste(
        self,
        params: BrowserPasteParams,
        ctx: RequestContext,
    ) -> BrowserPasteResult:
        payload = build_params_payload(
            params,
            ctx,
            internal_ingress_marker=self._internal_ingress_marker,
        )
        from shisad.executors.browser import BrowserPasteResult

        return BrowserPasteResult.model_validate(await self._impl.do_browser_paste(payload))

    async def handle_browser_screenshot(
        self,
        params: BrowserScreenshotParams,
        ctx: RequestContext,
    ) -> BrowserScreenshotResult:
        payload = build_params_payload(
            params,
            ctx,
            internal_ingress_marker=self._internal_ingress_marker,
        )
        from shisad.executors.browser import BrowserScreenshotResult

        return BrowserScreenshotResult.model_validate(
            await self._impl.do_browser_screenshot(payload)
        )
