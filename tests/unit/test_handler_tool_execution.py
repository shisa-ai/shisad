"""Unit checks for tool-execution handler wrappers."""

from __future__ import annotations

import pytest

from shisad.core.api.schema import BrowserScreenshotParams, ToolExecuteParams
from shisad.daemon.context import RequestContext
from shisad.daemon.handlers.tool_execution import ToolExecutionHandlers


class _StubImpl:
    def __init__(self) -> None:
        self.payloads: list[tuple[str, dict[str, object]]] = []

    async def do_tool_execute(self, payload: dict[str, object]) -> dict[str, object]:
        self.payloads.append(("tool", payload))
        return {"allowed": True}

    async def do_browser_paste(self, payload: dict[str, object]) -> dict[str, object]:
        self.payloads.append(("paste", payload))
        return {"allowed": True}

    async def do_browser_screenshot(self, payload: dict[str, object]) -> dict[str, object]:
        self.payloads.append(("screenshot", payload))
        return {"screenshot_id": "img-1", "path": "/tmp/a.png", "size_bytes": 32}


@pytest.mark.asyncio
async def test_tool_execute_handler_uses_typed_model() -> None:
    impl = _StubImpl()
    handlers = ToolExecutionHandlers(impl, internal_ingress_marker=object())  # type: ignore[arg-type]

    result = await handlers.handle_tool_execute(
        ToolExecuteParams(session_id="s1", tool_name="shell_exec", command=["echo", "hi"]),
        RequestContext(),
    )

    assert result.allowed is True
    assert impl.payloads[0][0] == "tool"
    assert impl.payloads[0][1]["tool_name"] == "shell_exec"


@pytest.mark.asyncio
async def test_browser_screenshot_handler_validates_result() -> None:
    impl = _StubImpl()
    handlers = ToolExecutionHandlers(impl, internal_ingress_marker=object())  # type: ignore[arg-type]

    result = await handlers.handle_browser_screenshot(
        BrowserScreenshotParams(session_id="s1", image_base64="Zm9v"),
        RequestContext(),
    )

    assert result.screenshot_id == "img-1"
