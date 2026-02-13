"""M2 provider extraction coverage."""

from __future__ import annotations

import asyncio
import json
import threading
import time
from typing import Any

import pytest

from shisad.core.config import ModelConfig
from shisad.core.interfaces import EmbeddingsProvider
from shisad.core.providers.base import EmbeddingResponse, Message, ProviderResponse
from shisad.core.providers.embeddings_adapter import SyncEmbeddingsAdapter
from shisad.core.providers.local_planner import LocalPlannerProvider
from shisad.core.providers.monitor_adapter import MonitorProviderAdapter
from shisad.core.providers.routed_openai import RoutedOpenAIProvider
from shisad.core.providers.routing import ModelRouter


@pytest.mark.asyncio
async def test_local_planner_provider_handles_retrieve_run_and_anomaly_paths() -> None:
    provider = LocalPlannerProvider()
    response = await provider.complete(
        [
            Message(
                role="user",
                content=(
                    "=== USER GOAL ===\n"
                    "Task:\n"
                    "retrieve: suspicious login indicators\n"
                    "run: echo hello\n"
                    "report anomaly\n\n"
                    "=== EXTERNAL CONTENT\n"
                    "none"
                ),
            )
        ]
    )
    payload = json.loads(response.message.content)
    tool_names = {action.get("tool_name") for action in payload.get("actions", [])}
    assert {"retrieve_rag", "shell_exec", "report_anomaly"} <= tool_names


@pytest.mark.asyncio
async def test_routed_openai_provider_uses_component_routes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SHISAD_MODEL_BASE_URL", "https://api.example.com/v1")
    monkeypatch.setenv("SHISAD_MODEL_PLANNER_BASE_URL", "https://planner.example.com/v1")
    monkeypatch.setenv("SHISAD_MODEL_EMBEDDINGS_BASE_URL", "https://embed.example.com/v1")
    monkeypatch.setenv("SHISAD_MODEL_MONITOR_BASE_URL", "https://monitor.example.com/v1")

    created: list[tuple[str, str]] = []

    class _FakeOpenAIProvider:
        def __init__(self, *, base_url: str, model_id: str, headers: dict[str, str]) -> None:
            _ = headers
            self._base_url = base_url
            self._model_id = model_id
            created.append((base_url, model_id))

        async def complete(
            self,
            messages: list[Message],
            tools: list[dict[str, Any]] | None = None,
        ) -> ProviderResponse:
            _ = tools
            return ProviderResponse(
                message=Message(role="assistant", content=f"{self._base_url}:{len(messages)}"),
                model=self._model_id,
            )

        async def embeddings(
            self,
            input_texts: list[str],
            *,
            model_id: str | None = None,
        ) -> EmbeddingResponse:
            _ = input_texts
            return EmbeddingResponse(vectors=[[1.0]], model=model_id or self._model_id)

    monkeypatch.setattr(
        "shisad.core.providers.routed_openai.OpenAICompatibleProvider",
        _FakeOpenAIProvider,
    )

    provider = RoutedOpenAIProvider(router=ModelRouter(ModelConfig()), api_key="token")
    await provider.complete([Message(role="user", content="hello")])
    await provider.embeddings(["hello"])
    await provider.monitor_complete([Message(role="user", content="monitor")])

    base_urls = {base for base, _model in created}
    assert base_urls == {
        "https://planner.example.com/v1",
        "https://embed.example.com/v1",
        "https://monitor.example.com/v1",
    }


@pytest.mark.asyncio
async def test_monitor_provider_adapter_delegates_to_monitor_route() -> None:
    class _StubProvider:
        async def monitor_complete(
            self,
            messages: list[Message],
            tools: list[dict[str, Any]] | None = None,
        ) -> ProviderResponse:
            _ = tools
            return ProviderResponse(
                message=Message(role="assistant", content=str(len(messages))),
                model="monitor",
            )

    adapter = MonitorProviderAdapter(_StubProvider())  # type: ignore[arg-type]
    result = await adapter.complete([Message(role="user", content="x")])
    assert result.message.content == "1"


@pytest.mark.asyncio
async def test_sync_embeddings_adapter_bridges_async_provider() -> None:
    class _StubEmbeddingsProvider(EmbeddingsProvider):
        async def embeddings(
            self,
            input_texts: list[str],
            *,
            model_id: str | None = None,
        ) -> EmbeddingResponse:
            _ = model_id
            return EmbeddingResponse(vectors=[[float(len(text))] for text in input_texts])

    adapter = SyncEmbeddingsAdapter(_StubEmbeddingsProvider(), model_id="embed-v1")
    try:
        vectors = adapter.embed(["aa", "bbbb"])
        assert vectors == [[2.0], [4.0]]
    finally:
        adapter.close()


@pytest.mark.asyncio
async def test_sync_embeddings_adapter_timeout_path() -> None:
    class _SlowEmbeddingsProvider(EmbeddingsProvider):
        async def embeddings(
            self,
            input_texts: list[str],
            *,
            model_id: str | None = None,
        ) -> EmbeddingResponse:
            _ = (input_texts, model_id)
            await asyncio.sleep(0.05)
            return EmbeddingResponse(vectors=[[1.0]])

    adapter = SyncEmbeddingsAdapter(
        _SlowEmbeddingsProvider(),
        model_id="embed-v1",
        timeout_seconds=0.01,
    )
    try:
        with pytest.raises(TimeoutError, match="adapter timeout"):
            adapter.embed(["x"])
    finally:
        adapter.close()


@pytest.mark.asyncio
async def test_sync_embeddings_adapter_close_wait_false_does_not_block() -> None:
    started = threading.Event()
    released = threading.Event()
    result: dict[str, Any] = {}

    class _BlockingEmbeddingsProvider(EmbeddingsProvider):
        async def embeddings(
            self,
            input_texts: list[str],
            *,
            model_id: str | None = None,
        ) -> EmbeddingResponse:
            _ = (input_texts, model_id)
            started.set()
            await asyncio.to_thread(released.wait)
            return EmbeddingResponse(vectors=[[2.0]])

    adapter = SyncEmbeddingsAdapter(
        _BlockingEmbeddingsProvider(),
        model_id="embed-v1",
        timeout_seconds=2.0,
    )

    def _run_embed() -> None:
        try:
            result["vectors"] = adapter.embed(["x"])
        except Exception as exc:
            result["error"] = exc

    worker = threading.Thread(target=_run_embed)
    worker.start()
    assert started.wait(timeout=1.0)
    before = time.monotonic()
    adapter.close(wait=False)
    elapsed = time.monotonic() - before
    assert elapsed < 0.2

    released.set()
    worker.join(timeout=1.0)
    assert not worker.is_alive()
    assert "error" not in result
    assert result["vectors"] == [[2.0]]


@pytest.mark.asyncio
async def test_routed_openai_provider_fallbacks(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SHISAD_MODEL_BASE_URL", "https://api.example.com/v1")
    monkeypatch.setenv("SHISAD_MODEL_PLANNER_BASE_URL", "https://planner.example.com/v1")
    monkeypatch.setenv("SHISAD_MODEL_EMBEDDINGS_BASE_URL", "https://embed.example.com/v1")
    monkeypatch.setenv("SHISAD_MODEL_MONITOR_BASE_URL", "https://monitor.example.com/v1")

    class _ExplodingOpenAIProvider:
        def __init__(self, *, base_url: str, model_id: str, headers: dict[str, str]) -> None:
            _ = (base_url, model_id, headers)

        async def complete(
            self,
            messages: list[Message],
            tools: list[dict[str, Any]] | None = None,
        ) -> ProviderResponse:
            _ = (messages, tools)
            raise RuntimeError("boom")

        async def embeddings(
            self,
            input_texts: list[str],
            *,
            model_id: str | None = None,
        ) -> EmbeddingResponse:
            _ = (input_texts, model_id)
            raise RuntimeError("boom")

    monkeypatch.setattr(
        "shisad.core.providers.routed_openai.OpenAICompatibleProvider",
        _ExplodingOpenAIProvider,
    )

    class _Fallback(LocalPlannerProvider):
        async def complete(
            self,
            messages: list[Message],
            tools: list[dict[str, Any]] | None = None,
        ) -> ProviderResponse:
            _ = (messages, tools)
            return ProviderResponse(message=Message(role="assistant", content="fallback-complete"))

        async def embeddings(
            self,
            input_texts: list[str],
            *,
            model_id: str | None = None,
        ) -> EmbeddingResponse:
            _ = (input_texts, model_id)
            return EmbeddingResponse(vectors=[[9.0]])

    provider = RoutedOpenAIProvider(
        router=ModelRouter(ModelConfig()),
        api_key="token",
        fallback=_Fallback(),
    )

    complete = await provider.complete([Message(role="user", content="x")])
    assert complete.message.content == "fallback-complete"
    embeddings = await provider.embeddings(["x"])
    assert embeddings.vectors == [[9.0]]

    monitor = await provider.monitor_complete([Message(role="user", content="x")])
    parsed = json.loads(monitor.message.content)
    assert parsed["decision"] == "FLAG"
