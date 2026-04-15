"""MCP client manager for external tool discovery and invocation."""

from __future__ import annotations

import asyncio
import os
from contextlib import AsyncExitStack
from dataclasses import dataclass
from datetime import timedelta
from typing import Any

from shisad.core.config import McpServerConfig, McpStdioServerConfig
from shisad.core.tools.registry import ToolRegistry
from shisad.core.types import ToolName
from shisad.interop.mcp_tools import McpDiscoveredTool, mcp_tool_to_registry_entry

_STDIO_BLOCKED_ENV_PREFIXES = ("SHISAD_",)
_STDIO_BLOCKED_ENV_EXACT = frozenset(
    {
        "ANTHROPIC_API_KEY",
        "GEMINI_API_KEY",
        "OPENAI_API_KEY",
        "OPENROUTER_API_KEY",
        "SHISA_API_KEY",
    }
)
_STDIO_BLOCKED_ENV_SUFFIXES = (
    "_ACCESS_TOKEN",
    "_API_KEY",
    "_AUTH_TOKEN",
    "_PASSWORD",
    "_SECRET",
    "_TOKEN",
)


@dataclass(slots=True, frozen=True)
class _McpSdk:
    ClientSession: Any
    StdioServerParameters: Any
    stdio_client: Any
    streamable_http_client: Any
    httpx: Any


@dataclass(slots=True)
class _ServerRuntime:
    config: McpServerConfig
    exit_stack: AsyncExitStack
    session: Any


def _load_mcp_sdk() -> _McpSdk:
    try:
        import httpx
        from mcp.client.session import ClientSession
        from mcp.client.stdio import StdioServerParameters, stdio_client
        from mcp.client.streamable_http import streamable_http_client
    except ImportError as exc:  # pragma: no cover - exercised via actionable runtime error
        raise RuntimeError(
            "MCP interop requires the optional 'interop' dependency group. "
            "Install with `uv sync --dev --group interop`."
        ) from exc
    return _McpSdk(
        ClientSession=ClientSession,
        StdioServerParameters=StdioServerParameters,
        stdio_client=stdio_client,
        streamable_http_client=streamable_http_client,
        httpx=httpx,
    )


def _jsonable(value: Any) -> Any:
    if hasattr(value, "model_dump"):
        return value.model_dump(mode="json", exclude_none=True)
    if isinstance(value, dict):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(item) for item in value]
    return value


def _is_timeout_error(exc: BaseException) -> bool:
    return isinstance(exc, TimeoutError) or "timed out" in str(exc).strip().lower()


def _stdio_process_env(overrides: dict[str, str]) -> dict[str, str]:
    env = {
        key: value
        for key, value in os.environ.items()
        if value
        and key not in _STDIO_BLOCKED_ENV_EXACT
        and not key.startswith(_STDIO_BLOCKED_ENV_PREFIXES)
        and not key.endswith(_STDIO_BLOCKED_ENV_SUFFIXES)
    }
    env.update(overrides)
    return env


async def _aclose_quietly(exit_stack: AsyncExitStack) -> None:
    try:
        await exit_stack.aclose()
    except asyncio.CancelledError:
        return
    except Exception:
        return


class McpClientManager:
    """Connect to configured MCP servers and bridge their tools into shisad."""

    def __init__(
        self,
        *,
        server_configs: list[McpServerConfig],
        tool_registry: ToolRegistry | None = None,
    ) -> None:
        self._server_configs = {server.name: server for server in server_configs}
        self._tool_registry = tool_registry
        self._runtimes: dict[str, _ServerRuntime] = {}
        self._registered_tools: dict[str, tuple[ToolName, ...]] = {}

    async def connect_all(self) -> None:
        """Connect to every configured server and register discovered tools."""
        for server_name in self._server_configs:
            await self._connect_and_register(server_name)

    async def shutdown(self) -> None:
        """Close all active sessions and unregister bridged tools."""
        if self._tool_registry is not None:
            for tool_names in self._registered_tools.values():
                for tool_name in tool_names:
                    self._tool_registry.unregister(tool_name)
        self._registered_tools.clear()
        runtimes = list(self._runtimes.keys())
        for server_name in runtimes:
            await self._disconnect_runtime(server_name)

    async def discover_tools(self, server_name: str) -> list[McpDiscoveredTool]:
        """List tools exposed by one configured MCP server."""
        runtime = await self._ensure_connected(server_name)
        try:
            return await self._discover_from_runtime(server_name, runtime)
        except Exception:
            await self._disconnect_runtime(server_name)
            runtime = await self._ensure_connected(server_name)
            return await self._discover_from_runtime(server_name, runtime)

    async def call_tool(
        self,
        server_name: str,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> dict[str, Any]:
        """Invoke one upstream MCP tool and return a JSON-serializable payload."""
        runtime = await self._ensure_connected(server_name)
        try:
            result = await runtime.session.call_tool(tool_name, arguments)
        except Exception as exc:
            if not _is_timeout_error(exc):
                await self._disconnect_runtime(server_name)
                raise RuntimeError(
                    f"MCP server '{server_name}' call to tool '{tool_name}' failed: {exc}"
                ) from exc
            await self._disconnect_runtime(server_name)
            raise RuntimeError(
                f"MCP server '{server_name}' call to tool '{tool_name}' timed out after "
                f"{runtime.config.timeout_seconds:.1f}s"
            ) from exc
        return {
            "ok": not bool(getattr(result, "isError", False)),
            "content": [_jsonable(item) for item in list(getattr(result, "content", []) or [])],
            "structured_content": _jsonable(getattr(result, "structuredContent", None)),
            "is_error": bool(getattr(result, "isError", False)),
        }

    async def _connect_and_register(self, server_name: str) -> None:
        if server_name in self._registered_tools:
            return
        runtime = await self._ensure_connected(server_name)
        tools = await self._discover_from_runtime(server_name, runtime)
        if self._tool_registry is None:
            return
        registered: list[ToolName] = []
        try:
            for tool in tools:
                entry = mcp_tool_to_registry_entry(tool, server_name)
                self._tool_registry.register(entry)
                registered.append(entry.name)
        except Exception as exc:
            for tool_name in reversed(registered):
                self._tool_registry.unregister(tool_name)
            raise RuntimeError(
                f"MCP server '{server_name}' tool registration failed: {exc}"
            ) from exc
        self._registered_tools[server_name] = tuple(registered)

    async def _ensure_connected(self, server_name: str) -> _ServerRuntime:
        runtime = self._runtimes.get(server_name)
        if runtime is not None:
            return runtime
        config = self._server_configs.get(server_name)
        if config is None:
            raise RuntimeError(f"Unknown MCP server '{server_name}'")

        sdk = _load_mcp_sdk()
        exit_stack = AsyncExitStack()
        try:
            if isinstance(config, McpStdioServerConfig):
                stdio_parameters = sdk.StdioServerParameters(
                    command=config.command[0],
                    args=list(config.command[1:]),
                    env=_stdio_process_env(dict(config.env)),
                    cwd=config.cwd,
                )
                read_stream, write_stream = await exit_stack.enter_async_context(
                    sdk.stdio_client(stdio_parameters)
                )
            else:
                http_client = await exit_stack.enter_async_context(
                    sdk.httpx.AsyncClient(
                        headers=dict(config.headers),
                        timeout=config.timeout_seconds,
                    )
                )
                read_stream, write_stream, _session_id = await exit_stack.enter_async_context(
                    sdk.streamable_http_client(
                        config.url,
                        http_client=http_client,
                    )
                )
            session = await exit_stack.enter_async_context(
                sdk.ClientSession(
                    read_stream,
                    write_stream,
                    read_timeout_seconds=timedelta(seconds=config.timeout_seconds),
                )
            )
            await session.initialize()
        except Exception as exc:
            if not _is_timeout_error(exc):
                await _aclose_quietly(exit_stack)
                raise RuntimeError(f"MCP server '{server_name}' connection failed: {exc}") from exc
            await _aclose_quietly(exit_stack)
            raise RuntimeError(
                f"MCP server '{server_name}' connection timed out after "
                f"{config.timeout_seconds:.1f}s"
            ) from exc

        runtime = _ServerRuntime(config=config, exit_stack=exit_stack, session=session)
        self._runtimes[server_name] = runtime
        return runtime

    async def _discover_from_runtime(
        self,
        server_name: str,
        runtime: _ServerRuntime,
    ) -> list[McpDiscoveredTool]:
        cursor: str | None = None
        discovered: list[McpDiscoveredTool] = []
        while True:
            try:
                result = await runtime.session.list_tools(cursor=cursor)
            except Exception as exc:
                if not _is_timeout_error(exc):
                    raise RuntimeError(
                        f"MCP server '{server_name}' tools/list failed: {exc}"
                    ) from exc
                raise RuntimeError(
                    f"MCP server '{server_name}' tools/list timed out after "
                    f"{runtime.config.timeout_seconds:.1f}s"
                ) from exc
            for tool in list(getattr(result, "tools", []) or []):
                discovered.append(
                    McpDiscoveredTool(
                        name=str(getattr(tool, "name", "")).strip(),
                        description=str(getattr(tool, "description", "")).strip(),
                        input_schema=_jsonable(getattr(tool, "inputSchema", {}) or {}),
                    )
                )
            cursor = str(getattr(result, "nextCursor", "") or "").strip() or None
            if cursor is None:
                break
        return discovered

    async def _disconnect_runtime(self, server_name: str) -> None:
        runtime = self._runtimes.pop(server_name, None)
        if runtime is None:
            return
        await _aclose_quietly(runtime.exit_stack)
