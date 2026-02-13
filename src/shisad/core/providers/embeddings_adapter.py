"""Sync embeddings bridge over async providers."""

from __future__ import annotations

import asyncio
from concurrent.futures import Future, ThreadPoolExecutor, TimeoutError
from threading import Lock

from shisad.core.interfaces import EmbeddingsProvider


class SyncEmbeddingsAdapter:
    """Threaded adapter to use async provider embeddings from sync retrieval code."""

    def __init__(
        self,
        provider: EmbeddingsProvider,
        *,
        model_id: str,
        timeout_seconds: float = 35.0,
    ) -> None:
        self._provider = provider
        self._model_id = model_id
        self._timeout_seconds = timeout_seconds
        self._executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="shisad-embed")
        self._lock = Lock()
        self._inflight: set[Future[list[list[float]]]] = set()

    def embed(self, input_texts: list[str]) -> list[list[float]]:
        future = self._executor.submit(self._run_embed, list(input_texts))
        with self._lock:
            self._inflight.add(future)
        try:
            return future.result(timeout=self._timeout_seconds)
        except TimeoutError as exc:
            future.cancel()
            raise TimeoutError(
                f"Embeddings request exceeded {self._timeout_seconds:.1f}s adapter timeout"
            ) from exc
        finally:
            with self._lock:
                self._inflight.discard(future)

    def _run_embed(self, input_texts: list[str]) -> list[list[float]]:
        response = asyncio.run(self._provider.embeddings(input_texts, model_id=self._model_id))
        return response.vectors

    def close(self, *, wait: bool = True) -> None:
        with self._lock:
            inflight = list(self._inflight)
        for future in inflight:
            future.cancel()
        self._executor.shutdown(wait=wait, cancel_futures=True)
