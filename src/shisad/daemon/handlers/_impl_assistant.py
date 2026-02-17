"""Assistant toolkit handler implementations."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, cast

from shisad.daemon.handlers._mixin_typing import HandlerMixinBase


class AssistantImplMixin(HandlerMixinBase):
    async def do_web_search(self, params: Mapping[str, Any]) -> dict[str, Any]:
        query = str(params.get("query", ""))
        limit = int(params.get("limit", 5))
        return cast(dict[str, Any], self._web_toolkit.search(query=query, limit=limit))

    async def do_web_fetch(self, params: Mapping[str, Any]) -> dict[str, Any]:
        url = str(params.get("url", ""))
        snapshot = bool(params.get("snapshot", False))
        raw_max_bytes = params.get("max_bytes")
        max_bytes = int(raw_max_bytes) if raw_max_bytes is not None else None
        return cast(
            dict[str, Any],
            self._web_toolkit.fetch(url=url, snapshot=snapshot, max_bytes=max_bytes),
        )

    async def do_realitycheck_search(self, params: Mapping[str, Any]) -> dict[str, Any]:
        query = str(params.get("query", ""))
        limit = int(params.get("limit", 5))
        mode = str(params.get("mode", "auto"))
        return cast(
            dict[str, Any],
            self._realitycheck_toolkit.search(query=query, limit=limit, mode=mode),
        )

    async def do_realitycheck_read(self, params: Mapping[str, Any]) -> dict[str, Any]:
        path = str(params.get("path", ""))
        raw_max_bytes = params.get("max_bytes")
        max_bytes = int(raw_max_bytes) if raw_max_bytes is not None else None
        return cast(
            dict[str, Any],
            self._realitycheck_toolkit.read_source(path=path, max_bytes=max_bytes),
        )

    async def do_fs_list(self, params: Mapping[str, Any]) -> dict[str, Any]:
        return cast(
            dict[str, Any],
            self._fs_git_toolkit.list_dir(
                path=str(params.get("path", ".")),
                recursive=bool(params.get("recursive", False)),
                limit=int(params.get("limit", 200)),
            ),
        )

    async def do_fs_read(self, params: Mapping[str, Any]) -> dict[str, Any]:
        raw_max_bytes = params.get("max_bytes")
        max_bytes = int(raw_max_bytes) if raw_max_bytes is not None else None
        return cast(
            dict[str, Any],
            self._fs_git_toolkit.read_file(
                path=str(params.get("path", "")),
                max_bytes=max_bytes,
            ),
        )

    async def do_fs_write(self, params: Mapping[str, Any]) -> dict[str, Any]:
        return cast(
            dict[str, Any],
            self._fs_git_toolkit.write_file(
                path=str(params.get("path", "")),
                content=str(params.get("content", "")),
                confirm=bool(params.get("confirm", False)),
            ),
        )

    async def do_git_status(self, params: Mapping[str, Any]) -> dict[str, Any]:
        return cast(
            dict[str, Any],
            self._fs_git_toolkit.git_status(repo_path=str(params.get("repo_path", "."))),
        )

    async def do_git_diff(self, params: Mapping[str, Any]) -> dict[str, Any]:
        return cast(
            dict[str, Any],
            self._fs_git_toolkit.git_diff(
                repo_path=str(params.get("repo_path", ".")),
                ref=str(params.get("ref", "")),
                max_lines=int(params.get("max_lines", 400)),
            ),
        )

    async def do_git_log(self, params: Mapping[str, Any]) -> dict[str, Any]:
        return cast(
            dict[str, Any],
            self._fs_git_toolkit.git_log(
                repo_path=str(params.get("repo_path", ".")),
                limit=int(params.get("limit", 20)),
            ),
        )
