"""Typed memory handler group."""

from __future__ import annotations

from shisad.core.api.schema import (
    MemoryDeleteResult,
    MemoryEntryParams,
    MemoryExportParams,
    MemoryExportResult,
    MemoryGetResult,
    MemoryIngestParams,
    MemoryIngestResult,
    MemoryListParams,
    MemoryListResult,
    MemoryRetrieveParams,
    MemoryRetrieveResult,
    MemoryRotateKeyParams,
    MemoryRotateKeyResult,
    MemoryVerifyResult,
    MemoryWriteParams,
    MemoryWriteResult,
)
from shisad.daemon.context import RequestContext
from shisad.daemon.handlers._helpers import build_params_payload
from shisad.daemon.handlers._impl import HandlerImplementation


class MemoryHandlers:
    """Memory CRUD and retrieval handlers."""

    def __init__(self, impl: HandlerImplementation, *, internal_ingress_marker: object) -> None:
        self._impl = impl
        self._internal_ingress_marker = internal_ingress_marker

    async def handle_memory_ingest(
        self,
        params: MemoryIngestParams,
        ctx: RequestContext,
    ) -> MemoryIngestResult:
        payload = build_params_payload(
            params,
            ctx,
            internal_ingress_marker=self._internal_ingress_marker,
        )
        return MemoryIngestResult.model_validate(await self._impl.do_memory_ingest(payload))

    async def handle_memory_retrieve(
        self,
        params: MemoryRetrieveParams,
        ctx: RequestContext,
    ) -> MemoryRetrieveResult:
        payload = build_params_payload(
            params,
            ctx,
            internal_ingress_marker=self._internal_ingress_marker,
        )
        return MemoryRetrieveResult.model_validate(await self._impl.do_memory_retrieve(payload))

    async def handle_memory_write(
        self,
        params: MemoryWriteParams,
        ctx: RequestContext,
    ) -> MemoryWriteResult:
        payload = build_params_payload(
            params,
            ctx,
            internal_ingress_marker=self._internal_ingress_marker,
        )
        return MemoryWriteResult.model_validate(await self._impl.do_memory_write(payload))

    async def handle_memory_list(
        self,
        params: MemoryListParams,
        ctx: RequestContext,
    ) -> MemoryListResult:
        payload = build_params_payload(
            params,
            ctx,
            internal_ingress_marker=self._internal_ingress_marker,
        )
        return MemoryListResult.model_validate(await self._impl.do_memory_list(payload))

    async def handle_memory_get(
        self,
        params: MemoryEntryParams,
        ctx: RequestContext,
    ) -> MemoryGetResult:
        payload = build_params_payload(
            params,
            ctx,
            internal_ingress_marker=self._internal_ingress_marker,
        )
        return MemoryGetResult.model_validate(await self._impl.do_memory_get(payload))

    async def handle_memory_delete(
        self,
        params: MemoryEntryParams,
        ctx: RequestContext,
    ) -> MemoryDeleteResult:
        payload = build_params_payload(
            params,
            ctx,
            internal_ingress_marker=self._internal_ingress_marker,
        )
        return MemoryDeleteResult.model_validate(await self._impl.do_memory_delete(payload))

    async def handle_memory_export(
        self,
        params: MemoryExportParams,
        ctx: RequestContext,
    ) -> MemoryExportResult:
        payload = build_params_payload(
            params,
            ctx,
            internal_ingress_marker=self._internal_ingress_marker,
        )
        return MemoryExportResult.model_validate(await self._impl.do_memory_export(payload))

    async def handle_memory_verify(
        self,
        params: MemoryEntryParams,
        ctx: RequestContext,
    ) -> MemoryVerifyResult:
        payload = build_params_payload(
            params,
            ctx,
            internal_ingress_marker=self._internal_ingress_marker,
        )
        return MemoryVerifyResult.model_validate(await self._impl.do_memory_verify(payload))

    async def handle_memory_rotate_key(
        self,
        params: MemoryRotateKeyParams,
        ctx: RequestContext,
    ) -> MemoryRotateKeyResult:
        payload = build_params_payload(
            params,
            ctx,
            internal_ingress_marker=self._internal_ingress_marker,
        )
        return MemoryRotateKeyResult.model_validate(await self._impl.do_memory_rotate_key(payload))
