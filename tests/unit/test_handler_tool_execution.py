"""Unit checks for tool-execution handler wrappers."""

from __future__ import annotations

from typing import Any

import pytest

from shisad.core.api.schema import BrowserScreenshotParams, ToolExecuteParams
from shisad.daemon.context import RequestContext
from shisad.daemon.handlers.tool_execution import ToolExecutionHandlers


class _ProgrammableImpl:
    """Stub that records payloads and returns per-call scripted results."""

    def __init__(self) -> None:
        self.payloads: list[tuple[str, dict[str, object]]] = []
        self.tool_results: list[dict[str, object] | Exception] = []
        self.paste_results: list[dict[str, object] | Exception] = []
        self.screenshot_results: list[dict[str, object] | Exception] = []

    async def do_tool_execute(self, payload: dict[str, object]) -> dict[str, object]:
        self.payloads.append(("tool", payload))
        return self._next("tool", self.tool_results, {"allowed": True})

    async def do_browser_paste(self, payload: dict[str, object]) -> dict[str, object]:
        self.payloads.append(("paste", payload))
        return self._next("paste", self.paste_results, {"allowed": True})

    async def do_browser_screenshot(self, payload: dict[str, object]) -> dict[str, object]:
        self.payloads.append(("screenshot", payload))
        return self._next(
            "screenshot",
            self.screenshot_results,
            {"screenshot_id": "img-1", "path": "/tmp/a.png", "size_bytes": 32},
        )

    @staticmethod
    def _next(
        kind: str,
        queue: list[dict[str, object] | Exception],
        default: dict[str, object],
    ) -> dict[str, object]:
        _ = kind
        if not queue:
            return dict(default)
        scripted = queue.pop(0)
        if isinstance(scripted, Exception):
            raise scripted
        return dict(scripted)


def _handlers(impl: _ProgrammableImpl, marker: object | None = None) -> ToolExecutionHandlers:
    return ToolExecutionHandlers(
        impl,  # type: ignore[arg-type]
        internal_ingress_marker=marker or object(),
    )


@pytest.mark.asyncio
async def test_tool_execute_forwards_payload_fields_to_impl() -> None:
    impl = _ProgrammableImpl()
    handlers = _handlers(impl)

    await handlers.handle_tool_execute(
        ToolExecuteParams(session_id="s1", tool_name="shell_exec", command=["echo", "hi"]),
        RequestContext(),
    )

    assert len(impl.payloads) == 1
    kind, payload = impl.payloads[0]
    assert kind == "tool"
    assert payload["session_id"] == "s1"
    assert payload["tool_name"] == "shell_exec"
    assert payload["command"] == ["echo", "hi"]
    # internal_ingress / rpc_peer / trust override must not be injected when ctx is empty.
    assert "_internal_ingress_marker" not in payload
    assert "_rpc_peer" not in payload
    assert "trust_level" not in payload


@pytest.mark.asyncio
async def test_tool_execute_propagates_rpc_and_ingress_context() -> None:
    impl = _ProgrammableImpl()
    marker = object()
    handlers = _handlers(impl, marker=marker)

    ctx = RequestContext(
        rpc_peer={"uid": 1000},
        is_internal_ingress=True,
        trust_level_override="trusted",
    )
    await handlers.handle_tool_execute(
        ToolExecuteParams(session_id="s1", tool_name="shell_exec", command=["echo", "hi"]),
        ctx,
    )

    payload = impl.payloads[0][1]
    assert payload["_rpc_peer"] == {"uid": 1000}
    assert payload["_internal_ingress_marker"] is marker
    assert payload["trust_level"] == "trusted"


@pytest.mark.asyncio
async def test_tool_execute_propagates_allowed_false_rejection_payload() -> None:
    impl = _ProgrammableImpl()
    impl.tool_results.append(
        {
            "allowed": False,
            "reason": "policy blocked shell_exec under current taint labels",
        }
    )
    handlers = _handlers(impl)

    result = await handlers.handle_tool_execute(
        ToolExecuteParams(session_id="s1", tool_name="shell_exec", command=["echo", "hi"]),
        RequestContext(),
    )

    assert result.allowed is False
    assert result.reason == "policy blocked shell_exec under current taint labels"


@pytest.mark.asyncio
async def test_tool_execute_propagates_confirmation_required_payload() -> None:
    impl = _ProgrammableImpl()
    impl.tool_results.append(
        {
            "allowed": False,
            "reason": "awaiting operator confirmation",
            "confirmation_required": True,
            "confirmation_id": "cf-42",
            "decision_nonce": "nonce-abc",
            "safe_preview": "echo hi",
        }
    )
    handlers = _handlers(impl)

    result = await handlers.handle_tool_execute(
        ToolExecuteParams(session_id="s1", tool_name="shell_exec", command=["echo", "hi"]),
        RequestContext(),
    )

    assert result.allowed is False
    assert result.confirmation_required is True
    assert result.confirmation_id == "cf-42"
    assert result.decision_nonce == "nonce-abc"
    assert result.safe_preview == "echo hi"


@pytest.mark.asyncio
async def test_tool_execute_propagates_lockdown_rejection_payload() -> None:
    impl = _ProgrammableImpl()
    impl.tool_results.append(
        {
            "allowed": False,
            "reason": "session is in lockdown; tool execution disabled",
            "warnings": ["lockdown_active"],
        }
    )
    handlers = _handlers(impl)

    result = await handlers.handle_tool_execute(
        ToolExecuteParams(session_id="s1", tool_name="shell_exec", command=["echo", "hi"]),
        RequestContext(),
    )

    assert result.allowed is False
    assert "lockdown" in result.reason
    assert "lockdown_active" in result.warnings


@pytest.mark.asyncio
async def test_tool_execute_bubbles_up_unknown_session_valueerror() -> None:
    impl = _ProgrammableImpl()
    impl.tool_results.append(ValueError("Unknown session: s1"))
    handlers = _handlers(impl)

    with pytest.raises(ValueError, match="Unknown session"):
        await handlers.handle_tool_execute(
            ToolExecuteParams(session_id="s1", tool_name="shell_exec", command=["echo", "hi"]),
            RequestContext(),
        )


@pytest.mark.asyncio
async def test_tool_execute_bubbles_up_unknown_tool_valueerror() -> None:
    impl = _ProgrammableImpl()
    impl.tool_results.append(ValueError("tool_name is required"))
    handlers = _handlers(impl)

    with pytest.raises(ValueError, match="tool_name"):
        await handlers.handle_tool_execute(
            ToolExecuteParams(session_id="s1", tool_name="", command=["echo", "hi"]),
            RequestContext(),
        )


@pytest.mark.asyncio
async def test_tool_execute_rejects_impl_payload_missing_allowed_field() -> None:
    from pydantic import ValidationError

    impl = _ProgrammableImpl()
    # ToolExecuteResult inherits SandboxResult where `allowed` is required.
    impl.tool_results.append({"reason": "no allowed field"})
    handlers = _handlers(impl)

    with pytest.raises(ValidationError) as exc_info:
        await handlers.handle_tool_execute(
            ToolExecuteParams(session_id="s1", tool_name="shell_exec", command=["echo", "hi"]),
            RequestContext(),
        )
    # Pydantic validation surfaces the missing required field to callers.
    message = str(exc_info.value).lower()
    assert "allowed" in message


@pytest.mark.asyncio
async def test_browser_screenshot_validates_result_shape() -> None:
    impl = _ProgrammableImpl()
    handlers = _handlers(impl)

    result = await handlers.handle_browser_screenshot(
        BrowserScreenshotParams(session_id="s1", image_base64="Zm9v"),
        RequestContext(),
    )

    assert result.screenshot_id == "img-1"


@pytest.mark.asyncio
async def test_browser_screenshot_rejects_payload_missing_required_fields() -> None:
    from pydantic import ValidationError

    impl = _ProgrammableImpl()
    impl.screenshot_results.append({"screenshot_id": ""})  # missing path/size_bytes
    handlers = _handlers(impl)

    with pytest.raises(ValidationError):
        await handlers.handle_browser_screenshot(
            BrowserScreenshotParams(session_id="s1", image_base64="Zm9v"),
            RequestContext(),
        )


@pytest.mark.asyncio
async def test_tool_execute_passes_arguments_and_sandbox_fields_through() -> None:
    impl = _ProgrammableImpl()
    handlers = _handlers(impl)

    params: dict[str, Any] = {
        "session_id": "s1",
        "tool_name": "shell_exec",
        "command": ["ls"],
        "arguments": {"key": "value"},
        "read_paths": ["/tmp/a"],
        "write_paths": ["/tmp/b"],
        "network_urls": ["https://api.example.com"],
        "sandbox_type": "subprocess",
    }
    await handlers.handle_tool_execute(ToolExecuteParams(**params), RequestContext())

    payload = impl.payloads[0][1]
    assert payload["arguments"] == {"key": "value"}
    assert payload["read_paths"] == ["/tmp/a"]
    assert payload["write_paths"] == ["/tmp/b"]
    assert payload["network_urls"] == ["https://api.example.com"]
    assert payload["sandbox_type"] == "subprocess"
