"""Sync embeddings bridge over async providers."""

from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor

from shisad.core.interfaces import EmbeddingsProvider


class SyncEmbeddingsAdapter:
    """Threaded adapter to use async provider embeddings from sync retrieval code."""

    def __init__(self, provider: EmbeddingsProvider, *, model_id: str) -> None:
        self._provider = provider
        self._model_id = model_id
        self._executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="shisad-embed")

    def embed(self, input_texts: list[str]) -> list[list[float]]:
        future = self._executor.submit(self._run_embed, list(input_texts))
        return future.result(timeout=15.0)

    def _run_embed(self, input_texts: list[str]) -> list[list[float]]:
        response = asyncio.run(self._provider.embeddings(input_texts, model_id=self._model_id))
        return response.vectors

    def close(self) -> None:
        self._executor.shutdown(wait=False, cancel_futures=True)
