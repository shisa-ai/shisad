"""M2 provider extraction coverage."""

from __future__ import annotations

import asyncio
import base64
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
from shisad.security.spotlight import datamark_text


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
    tool_names = {
        str(item.get("function", {}).get("name", ""))
        for item in response.message.tool_calls
        if isinstance(item, dict)
    }
    assert {"retrieve_rag", "shell.exec", "report_anomaly"} <= tool_names


@pytest.mark.asyncio
async def test_local_planner_provider_returns_structured_task_close_gate_verdict() -> None:
    provider = LocalPlannerProvider()
    evidence = (
        "ORIGINAL TASK DESCRIPTION:\n"
        "Review README.md and summarize the outcome.\n\n"
        "TASK OUTPUT SUMMARY:\n"
        "codex completed mode=plan model=fake-model permission_mode=approve-all\n\n"
        "TASK OUTPUT RESPONSE:\n"
        "codex completed mode=plan model=fake-model permission_mode=approve-all\n\n"
        "TASK FILES CHANGED:\n"
        "(none)\n"
    )
    encoded = base64.b64encode(evidence.encode("utf-8")).decode("ascii")
    planner_input = (
        "=== RUNTIME GUIDANCE ===\n"
        "^^SYSTEM_START_test^^\n"
        "TASK CLOSE-GATE SELF-CHECK\n\n"
        "=== USER REQUEST ===\n"
        "^^USER_GOAL_test^^\n"
        "Assess whether the delegated task completed the original request.\n\n"
        "=== DATA EVIDENCE (UNTRUSTED) ===\n"
        "^^EVIDENCE_START_test^^\n"
        f"{datamark_text(encoded)}\n"
        "^^EVIDENCE_END_test^^\n\n"
        "=== END PAYLOAD ==="
    )

    response = await provider.complete([Message(role="user", content=planner_input)])

    assert "SELF_CHECK_STATUS: COMPLETE" in response.message.content
    assert "SELF_CHECK_REASON: complete" in response.message.content


@pytest.mark.asyncio
async def test_local_planner_provider_treats_proposal_diff_as_concrete_close_gate_evidence(
) -> None:
    provider = LocalPlannerProvider()
    evidence = (
        "ORIGINAL TASK DESCRIPTION:\n"
        "Add a tiny implementation note to README.md.\n\n"
        "TASK RESULT SIGNALS:\n"
        "executor=coding_agent\n"
        "agent=codex\n"
        "handoff_mode=summary_only\n"
        "task_kind=implement\n"
        "read_only=false\n"
        "summary_present=yes\n"
        "response_present=yes\n"
        "files_changed_count=1\n"
        "tool_output_count=0\n"
        "proposal_present=yes\n"
        "proposal_has_diff=yes\n"
        "proposal_files_changed_count=1\n\n"
        "TASK OUTPUT SUMMARY:\n"
        "codex completed mode=build model=fake-model permission_mode=approve-all\n\n"
        "TASK OUTPUT RESPONSE:\n"
        "codex completed mode=build model=fake-model permission_mode=approve-all\n\n"
        "TASK FILES CHANGED:\n"
        "- README.md\n\n"
        "TASK PROPOSAL DIFF:\n"
        "diff --git a/README.md b/README.md\n"
        "+++ b/README.md\n"
        "+Fake ACP edit from codex mode=build reasoning=medium\n"
    )
    encoded = base64.b64encode(evidence.encode("utf-8")).decode("ascii")
    planner_input = (
        "=== RUNTIME GUIDANCE ===\n"
        "^^SYSTEM_START_test^^\n"
        "TASK CLOSE-GATE SELF-CHECK\n\n"
        "=== USER REQUEST ===\n"
        "^^USER_GOAL_test^^\n"
        "Assess whether the delegated task completed the original request.\n\n"
        "=== DATA EVIDENCE (UNTRUSTED) ===\n"
        "^^EVIDENCE_START_test^^\n"
        f"{datamark_text(encoded)}\n"
        "^^EVIDENCE_END_test^^\n\n"
        "=== END PAYLOAD ==="
    )

    response = await provider.complete([Message(role="user", content=planner_input)])

    assert "SELF_CHECK_STATUS: COMPLETE" in response.message.content
    assert "SELF_CHECK_REASON: complete" in response.message.content


@pytest.mark.asyncio
async def test_local_planner_provider_does_not_treat_plain_header_text_as_close_gate_prompt(
) -> None:
    provider = LocalPlannerProvider()

    response = await provider.complete(
        [Message(role="user", content="Please explain TASK CLOSE-GATE SELF-CHECK to me.")]
    )

    assert "SELF_CHECK_STATUS:" not in response.message.content


@pytest.mark.asyncio
async def test_routed_openai_provider_uses_component_routes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SHISAD_MODEL_REMOTE_ENABLED", "true")
    monkeypatch.setenv("SHISAD_MODEL_BASE_URL", "https://api.example.com/v1")
    monkeypatch.setenv("SHISAD_MODEL_PLANNER_BASE_URL", "https://planner.example.com/v1")
    monkeypatch.setenv("SHISAD_MODEL_EMBEDDINGS_BASE_URL", "https://embed.example.com/v1")
    monkeypatch.setenv("SHISAD_MODEL_MONITOR_BASE_URL", "https://monitor.example.com/v1")

    created: list[tuple[str, str, bool]] = []

    class _FakeOpenAIProvider:
        def __init__(
            self,
            *,
            base_url: str,
            model_id: str,
            headers: dict[str, str],
            force_json_response: bool = False,
            request_parameters: Any | None = None,
            allow_http_localhost: bool = True,
            block_private_ranges: bool = True,
            endpoint_allowlist: list[str] | None = None,
        ) -> None:
            _ = (
                headers,
                force_json_response,
                request_parameters,
                allow_http_localhost,
                block_private_ranges,
                endpoint_allowlist,
            )
            self._base_url = base_url
            self._model_id = model_id
            created.append((base_url, model_id, force_json_response))

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

    base_urls = {base for base, _model, _force_json in created}
    assert base_urls == {
        "https://planner.example.com/v1",
        "https://embed.example.com/v1",
        "https://monitor.example.com/v1",
    }
    route_flags = {base: force_json for base, _model, force_json in created}
    assert route_flags["https://planner.example.com/v1"] is False
    assert route_flags["https://embed.example.com/v1"] is False
    assert route_flags["https://monitor.example.com/v1"] is True


@pytest.mark.asyncio
async def test_s0_routed_provider_does_not_bypass_route_toggles_with_constructor_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("SHISAD_MODEL_REMOTE_ENABLED", raising=False)
    monkeypatch.delenv("SHISA_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    monkeypatch.delenv("SHISAD_MODEL_API_KEY", raising=False)
    monkeypatch.setenv("SHISAD_MODEL_BASE_URL", "https://api.example.com/v1")

    created: list[str] = []

    class _FakeOpenAIProvider:
        def __init__(
            self,
            *,
            base_url: str,
            model_id: str,
            headers: dict[str, str],
            force_json_response: bool = False,
            request_parameters: Any | None = None,
            allow_http_localhost: bool = True,
            block_private_ranges: bool = True,
            endpoint_allowlist: list[str] | None = None,
        ) -> None:
            _ = (
                model_id,
                headers,
                force_json_response,
                request_parameters,
                allow_http_localhost,
                block_private_ranges,
                endpoint_allowlist,
            )
            created.append(base_url)

        async def complete(
            self,
            messages: list[Message],
            tools: list[dict[str, Any]] | None = None,
        ) -> ProviderResponse:
            _ = (messages, tools)
            return ProviderResponse(message=Message(role="assistant", content="remote"))

        async def embeddings(
            self,
            input_texts: list[str],
            *,
            model_id: str | None = None,
        ) -> EmbeddingResponse:
            _ = (input_texts, model_id)
            return EmbeddingResponse(vectors=[[9.0]])

    monkeypatch.setattr(
        "shisad.core.providers.routed_openai.OpenAICompatibleProvider",
        _FakeOpenAIProvider,
    )

    class _Fallback(LocalPlannerProvider):
        async def complete(
            self,
            messages: list[Message],
            tools: list[dict[str, Any]] | None = None,
        ) -> ProviderResponse:
            _ = (messages, tools)
            return ProviderResponse(message=Message(role="assistant", content="fallback"))

    provider = RoutedOpenAIProvider(
        router=ModelRouter(ModelConfig()),
        api_key="token",
        fallback=_Fallback(),
    )

    result = await provider.complete([Message(role="user", content="hello")])

    assert created == []
    assert provider.monitor_remote_enabled() is False
    assert result.message.content == "fallback"


@pytest.mark.asyncio
async def test_s0_routed_provider_supports_mixed_mode_and_route_local_auth(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SHISAD_MODEL_REMOTE_ENABLED", "true")
    monkeypatch.setenv("SHISAD_MODEL_BASE_URL", "https://api.example.com/v1")
    monkeypatch.setenv("SHISAD_MODEL_PLANNER_BASE_URL", "https://planner.example.com/v1")
    monkeypatch.setenv("SHISAD_MODEL_EMBEDDINGS_PROVIDER_PRESET", "vllm_local_default")
    monkeypatch.setenv("SHISAD_MODEL_EMBEDDINGS_BASE_URL", "http://127.0.0.1:8000/v1")
    monkeypatch.setenv("SHISAD_MODEL_MONITOR_BASE_URL", "https://monitor.example.com/v1")
    monkeypatch.setenv("SHISAD_MODEL_MONITOR_REMOTE_ENABLED", "false")

    monkeypatch.setenv("SHISAD_MODEL_PLANNER_AUTH_MODE", "header")
    monkeypatch.setenv("SHISAD_MODEL_PLANNER_AUTH_HEADER_NAME", "X-Api-Key")
    monkeypatch.setenv("SHISAD_MODEL_PLANNER_API_KEY", "planner-key")
    monkeypatch.setenv("SHISAD_MODEL_PLANNER_EXTRA_HEADERS", '{"X-Title":"planner-route"}')

    monkeypatch.setenv("SHISAD_MODEL_EMBEDDINGS_AUTH_MODE", "none")
    monkeypatch.setenv("SHISAD_MODEL_EMBEDDINGS_REMOTE_ENABLED", "true")

    captured_headers: dict[str, dict[str, str]] = {}

    class _FakeOpenAIProvider:
        def __init__(
            self,
            *,
            base_url: str,
            model_id: str,
            headers: dict[str, str],
            force_json_response: bool = False,
            request_parameters: Any | None = None,
            allow_http_localhost: bool = True,
            block_private_ranges: bool = True,
            endpoint_allowlist: list[str] | None = None,
        ) -> None:
            _ = (
                model_id,
                force_json_response,
                request_parameters,
                allow_http_localhost,
                block_private_ranges,
                endpoint_allowlist,
            )
            captured_headers[base_url] = dict(headers)
            self._base_url = base_url

        async def complete(
            self,
            messages: list[Message],
            tools: list[dict[str, Any]] | None = None,
        ) -> ProviderResponse:
            _ = tools
            return ProviderResponse(
                message=Message(
                    role="assistant",
                    content=f"remote:{self._base_url}:{len(messages)}",
                ),
                model="remote-model",
            )

        async def embeddings(
            self,
            input_texts: list[str],
            *,
            model_id: str | None = None,
        ) -> EmbeddingResponse:
            _ = (input_texts, model_id)
            return EmbeddingResponse(vectors=[[2.0]], model="embed-model")

    monkeypatch.setattr(
        "shisad.core.providers.routed_openai.OpenAICompatibleProvider",
        _FakeOpenAIProvider,
    )

    class _Fallback(LocalPlannerProvider):
        async def complete(
            self,
            messages: list[Message],
            tools: list[dict[str, Any]] | None = None,
        ) -> ProviderResponse:
            _ = (messages, tools)
            return ProviderResponse(message=Message(role="assistant", content="fallback"))

    provider = RoutedOpenAIProvider(
        router=ModelRouter(ModelConfig()),
        fallback=_Fallback(),
    )

    planner_resp = await provider.complete([Message(role="user", content="hello")])
    embeddings_resp = await provider.embeddings(["hello"])
    monitor_resp = await provider.monitor_complete([Message(role="user", content="monitor")])

    assert planner_resp.message.content.startswith("remote:https://planner.example.com/v1")
    assert embeddings_resp.vectors == [[2.0]]
    monitor_payload = json.loads(monitor_resp.message.content)
    assert monitor_payload["decision"] == "FLAG"

    planner_headers = {
        key.lower(): value for key, value in captured_headers["https://planner.example.com/v1"].items()
    }
    assert planner_headers["x-api-key"] == "planner-key"
    assert planner_headers["x-title"] == "planner-route"
    embeddings_headers = {
        key.lower(): value for key, value in captured_headers["http://127.0.0.1:8000/v1"].items()
    }
    assert "authorization" not in embeddings_headers


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
        def __init__(
            self,
            *,
            base_url: str,
            model_id: str,
            headers: dict[str, str],
            force_json_response: bool = False,
            request_parameters: Any | None = None,
            allow_http_localhost: bool = True,
            block_private_ranges: bool = True,
            endpoint_allowlist: list[str] | None = None,
        ) -> None:
            _ = (
                base_url,
                model_id,
                headers,
                force_json_response,
                request_parameters,
                allow_http_localhost,
                block_private_ranges,
                endpoint_allowlist,
            )

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
