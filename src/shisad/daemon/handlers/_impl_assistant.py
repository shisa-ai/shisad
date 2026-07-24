"""Assistant toolkit handler implementations."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from shisad.daemon.handlers._direct_execution import DirectExecutionMixin


class AssistantImplMixin(DirectExecutionMixin):
    async def do_web_search(self, params: Mapping[str, Any]) -> dict[str, Any]:
        return await self._execute_direct_tool_rpc("web.search", params)

    async def do_web_fetch(self, params: Mapping[str, Any]) -> dict[str, Any]:
        return await self._execute_direct_tool_rpc("web.fetch", params)

    async def do_realitycheck_search(self, params: Mapping[str, Any]) -> dict[str, Any]:
        return await self._execute_direct_tool_rpc("realitycheck.search", params)

    async def do_realitycheck_read(self, params: Mapping[str, Any]) -> dict[str, Any]:
        return await self._execute_direct_tool_rpc("realitycheck.read", params)

    async def do_email_search(self, params: Mapping[str, Any]) -> dict[str, Any]:
        return await self._execute_direct_tool_rpc("email.search", params)

    async def do_email_read(self, params: Mapping[str, Any]) -> dict[str, Any]:
        return await self._execute_direct_tool_rpc("email.read", params)

    async def do_fs_list(self, params: Mapping[str, Any]) -> dict[str, Any]:
        return await self._execute_direct_tool_rpc("fs.list", params)

    async def do_fs_read(self, params: Mapping[str, Any]) -> dict[str, Any]:
        return await self._execute_direct_tool_rpc("fs.read", params)

    async def do_fs_write(self, params: Mapping[str, Any]) -> dict[str, Any]:
        return await self._execute_direct_tool_rpc("fs.write", params)

    async def do_git_status(self, params: Mapping[str, Any]) -> dict[str, Any]:
        return await self._execute_direct_tool_rpc("git.status", params)

    async def do_git_diff(self, params: Mapping[str, Any]) -> dict[str, Any]:
        return await self._execute_direct_tool_rpc("git.diff", params)

    async def do_git_log(self, params: Mapping[str, Any]) -> dict[str, Any]:
        return await self._execute_direct_tool_rpc("git.log", params)
