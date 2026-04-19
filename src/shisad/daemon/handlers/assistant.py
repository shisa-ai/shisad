"""Typed assistant primitive handler group (web/fs/git)."""

from __future__ import annotations

from shisad.core.api.schema import (
    EmailReadParams,
    EmailReadResult,
    EmailSearchParams,
    EmailSearchResult,
    FsListParams,
    FsListResult,
    FsReadParams,
    FsReadResult,
    FsWriteParams,
    FsWriteResult,
    GitDiffParams,
    GitDiffResult,
    GitLogParams,
    GitLogResult,
    GitStatusParams,
    GitStatusResult,
    RealityCheckReadParams,
    RealityCheckReadResult,
    RealityCheckSearchParams,
    RealityCheckSearchResult,
    WebFetchParams,
    WebFetchResult,
    WebSearchParams,
    WebSearchResult,
)
from shisad.daemon.context import RequestContext
from shisad.daemon.handlers._helpers import build_params_payload
from shisad.daemon.handlers._impl import HandlerImplementation


class AssistantHandlers:
    """Web/search and fs/git helper handlers."""

    def __init__(self, impl: HandlerImplementation, *, internal_ingress_marker: object) -> None:
        self._impl = impl
        self._internal_ingress_marker = internal_ingress_marker

    async def handle_web_search(
        self,
        params: WebSearchParams,
        ctx: RequestContext,
    ) -> WebSearchResult:
        payload = build_params_payload(
            params,
            ctx,
            internal_ingress_marker=self._internal_ingress_marker,
        )
        return WebSearchResult.model_validate(await self._impl.do_web_search(payload))

    async def handle_web_fetch(
        self,
        params: WebFetchParams,
        ctx: RequestContext,
    ) -> WebFetchResult:
        payload = build_params_payload(
            params,
            ctx,
            internal_ingress_marker=self._internal_ingress_marker,
        )
        return WebFetchResult.model_validate(await self._impl.do_web_fetch(payload))

    async def handle_realitycheck_search(
        self,
        params: RealityCheckSearchParams,
        ctx: RequestContext,
    ) -> RealityCheckSearchResult:
        payload = build_params_payload(
            params,
            ctx,
            internal_ingress_marker=self._internal_ingress_marker,
        )
        return RealityCheckSearchResult.model_validate(
            await self._impl.do_realitycheck_search(payload)
        )

    async def handle_realitycheck_read(
        self,
        params: RealityCheckReadParams,
        ctx: RequestContext,
    ) -> RealityCheckReadResult:
        payload = build_params_payload(
            params,
            ctx,
            internal_ingress_marker=self._internal_ingress_marker,
        )
        return RealityCheckReadResult.model_validate(await self._impl.do_realitycheck_read(payload))

    async def handle_email_search(
        self,
        params: EmailSearchParams,
        ctx: RequestContext,
    ) -> EmailSearchResult:
        payload = build_params_payload(
            params,
            ctx,
            internal_ingress_marker=self._internal_ingress_marker,
        )
        return EmailSearchResult.model_validate(await self._impl.do_email_search(payload))

    async def handle_email_read(
        self,
        params: EmailReadParams,
        ctx: RequestContext,
    ) -> EmailReadResult:
        payload = build_params_payload(
            params,
            ctx,
            internal_ingress_marker=self._internal_ingress_marker,
        )
        return EmailReadResult.model_validate(await self._impl.do_email_read(payload))

    async def handle_fs_list(self, params: FsListParams, ctx: RequestContext) -> FsListResult:
        payload = build_params_payload(
            params,
            ctx,
            internal_ingress_marker=self._internal_ingress_marker,
        )
        return FsListResult.model_validate(await self._impl.do_fs_list(payload))

    async def handle_fs_read(self, params: FsReadParams, ctx: RequestContext) -> FsReadResult:
        payload = build_params_payload(
            params,
            ctx,
            internal_ingress_marker=self._internal_ingress_marker,
        )
        return FsReadResult.model_validate(await self._impl.do_fs_read(payload))

    async def handle_fs_write(self, params: FsWriteParams, ctx: RequestContext) -> FsWriteResult:
        payload = build_params_payload(
            params,
            ctx,
            internal_ingress_marker=self._internal_ingress_marker,
        )
        return FsWriteResult.model_validate(await self._impl.do_fs_write(payload))

    async def handle_git_status(
        self,
        params: GitStatusParams,
        ctx: RequestContext,
    ) -> GitStatusResult:
        payload = build_params_payload(
            params,
            ctx,
            internal_ingress_marker=self._internal_ingress_marker,
        )
        return GitStatusResult.model_validate(await self._impl.do_git_status(payload))

    async def handle_git_diff(self, params: GitDiffParams, ctx: RequestContext) -> GitDiffResult:
        payload = build_params_payload(
            params,
            ctx,
            internal_ingress_marker=self._internal_ingress_marker,
        )
        return GitDiffResult.model_validate(await self._impl.do_git_diff(payload))

    async def handle_git_log(self, params: GitLogParams, ctx: RequestContext) -> GitLogResult:
        payload = build_params_payload(
            params,
            ctx,
            internal_ingress_marker=self._internal_ingress_marker,
        )
        return GitLogResult.model_validate(await self._impl.do_git_log(payload))
