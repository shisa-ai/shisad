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
    MemoryReviewQueueParams,
    MemoryRotateKeyParams,
    MemoryRotateKeyResult,
    MemoryVerifyResult,
    MemoryWriteParams,
    MemoryWriteResult,
    NoteCreateParams,
    NoteDeleteResult,
    NoteEntryParams,
    NoteExportParams,
    NoteExportResult,
    NoteGetResult,
    NoteListParams,
    NoteListResult,
    NoteSearchParams,
    NoteSearchResult,
    NoteVerifyResult,
    TodoCompleteParams,
    TodoCompleteResult,
    TodoCreateParams,
    TodoDeleteResult,
    TodoEntryParams,
    TodoExportParams,
    TodoExportResult,
    TodoGetResult,
    TodoListParams,
    TodoListResult,
    TodoVerifyResult,
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

    async def handle_memory_list_review_queue(
        self,
        params: MemoryReviewQueueParams,
        ctx: RequestContext,
    ) -> MemoryListResult:
        payload = build_params_payload(
            params,
            ctx,
            internal_ingress_marker=self._internal_ingress_marker,
        )
        return MemoryListResult.model_validate(
            await self._impl.do_memory_list_review_queue(payload)
        )

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

    async def handle_note_create(
        self,
        params: NoteCreateParams,
        ctx: RequestContext,
    ) -> MemoryWriteResult:
        payload = build_params_payload(
            params,
            ctx,
            internal_ingress_marker=self._internal_ingress_marker,
        )
        return MemoryWriteResult.model_validate(await self._impl.do_note_create(payload))

    async def handle_note_list(
        self,
        params: NoteListParams,
        ctx: RequestContext,
    ) -> NoteListResult:
        payload = build_params_payload(
            params,
            ctx,
            internal_ingress_marker=self._internal_ingress_marker,
        )
        return NoteListResult.model_validate(await self._impl.do_note_list(payload))

    async def handle_note_search(
        self,
        params: NoteSearchParams,
        ctx: RequestContext,
    ) -> NoteSearchResult:
        payload = build_params_payload(
            params,
            ctx,
            internal_ingress_marker=self._internal_ingress_marker,
        )
        return NoteSearchResult.model_validate(await self._impl.do_note_search(payload))

    async def handle_note_get(
        self,
        params: NoteEntryParams,
        ctx: RequestContext,
    ) -> NoteGetResult:
        payload = build_params_payload(
            params,
            ctx,
            internal_ingress_marker=self._internal_ingress_marker,
        )
        return NoteGetResult.model_validate(await self._impl.do_note_get(payload))

    async def handle_note_delete(
        self,
        params: NoteEntryParams,
        ctx: RequestContext,
    ) -> NoteDeleteResult:
        payload = build_params_payload(
            params,
            ctx,
            internal_ingress_marker=self._internal_ingress_marker,
        )
        return NoteDeleteResult.model_validate(await self._impl.do_note_delete(payload))

    async def handle_note_verify(
        self,
        params: NoteEntryParams,
        ctx: RequestContext,
    ) -> NoteVerifyResult:
        payload = build_params_payload(
            params,
            ctx,
            internal_ingress_marker=self._internal_ingress_marker,
        )
        return NoteVerifyResult.model_validate(await self._impl.do_note_verify(payload))

    async def handle_note_export(
        self,
        params: NoteExportParams,
        ctx: RequestContext,
    ) -> NoteExportResult:
        payload = build_params_payload(
            params,
            ctx,
            internal_ingress_marker=self._internal_ingress_marker,
        )
        return NoteExportResult.model_validate(await self._impl.do_note_export(payload))

    async def handle_todo_create(
        self,
        params: TodoCreateParams,
        ctx: RequestContext,
    ) -> MemoryWriteResult:
        payload = build_params_payload(
            params,
            ctx,
            internal_ingress_marker=self._internal_ingress_marker,
        )
        return MemoryWriteResult.model_validate(await self._impl.do_todo_create(payload))

    async def handle_todo_list(
        self,
        params: TodoListParams,
        ctx: RequestContext,
    ) -> TodoListResult:
        payload = build_params_payload(
            params,
            ctx,
            internal_ingress_marker=self._internal_ingress_marker,
        )
        return TodoListResult.model_validate(await self._impl.do_todo_list(payload))

    async def handle_todo_complete(
        self,
        params: TodoCompleteParams,
        ctx: RequestContext,
    ) -> TodoCompleteResult:
        payload = build_params_payload(
            params,
            ctx,
            internal_ingress_marker=self._internal_ingress_marker,
        )
        return TodoCompleteResult.model_validate(await self._impl.do_todo_complete(payload))

    async def handle_todo_get(
        self,
        params: TodoEntryParams,
        ctx: RequestContext,
    ) -> TodoGetResult:
        payload = build_params_payload(
            params,
            ctx,
            internal_ingress_marker=self._internal_ingress_marker,
        )
        return TodoGetResult.model_validate(await self._impl.do_todo_get(payload))

    async def handle_todo_delete(
        self,
        params: TodoEntryParams,
        ctx: RequestContext,
    ) -> TodoDeleteResult:
        payload = build_params_payload(
            params,
            ctx,
            internal_ingress_marker=self._internal_ingress_marker,
        )
        return TodoDeleteResult.model_validate(await self._impl.do_todo_delete(payload))

    async def handle_todo_verify(
        self,
        params: TodoEntryParams,
        ctx: RequestContext,
    ) -> TodoVerifyResult:
        payload = build_params_payload(
            params,
            ctx,
            internal_ingress_marker=self._internal_ingress_marker,
        )
        return TodoVerifyResult.model_validate(await self._impl.do_todo_verify(payload))

    async def handle_todo_export(
        self,
        params: TodoExportParams,
        ctx: RequestContext,
    ) -> TodoExportResult:
        payload = build_params_payload(
            params,
            ctx,
            internal_ingress_marker=self._internal_ingress_marker,
        )
        return TodoExportResult.model_validate(await self._impl.do_todo_export(payload))
