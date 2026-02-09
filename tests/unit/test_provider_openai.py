"""M0 provider abstraction: OpenAI-compatible transport behavior."""

from __future__ import annotations

import json
from typing import Any

import pytest

from shisad.core.providers.base import Message, OpenAICompatibleProvider


class _FakeHttpResponse:
    def __init__(self, payload: dict[str, Any]) -> None:
        self._payload = payload

    def __enter__(self) -> _FakeHttpResponse:
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        return None

    def read(self) -> bytes:
        return json.dumps(self._payload).encode("utf-8")


@pytest.mark.asyncio
async def test_openai_compatible_complete_uses_base_url_headers_and_model(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, Any] = {}

    def fake_urlopen(request: Any, timeout: float = 0.0) -> _FakeHttpResponse:
        captured["url"] = request.full_url
        captured["headers"] = dict(request.header_items())
        captured["payload"] = json.loads(request.data.decode("utf-8"))
        captured["timeout"] = timeout
        return _FakeHttpResponse(
            {
                "choices": [
                    {
                        "message": {"role": "assistant", "content": "hello"},
                        "finish_reason": "stop",
                    }
                ],
                "usage": {"prompt_tokens": 2, "completion_tokens": 1, "total_tokens": 3},
            }
        )

    monkeypatch.setattr("shisad.core.providers.base.request.urlopen", fake_urlopen)

    provider = OpenAICompatibleProvider(
        base_url="https://api.example.com/v1",
        model_id="gpt-test",
        headers={"Authorization": "Bearer test-token", "X-Custom": "yes"},
        timeout_seconds=12.0,
    )
    response = await provider.complete([Message(role="user", content="Hi")])

    assert captured["url"] == "https://api.example.com/v1/chat/completions"
    assert captured["payload"]["model"] == "gpt-test"
    assert captured["payload"]["messages"] == [{"role": "user", "content": "Hi"}]
    assert captured["headers"]["Authorization"] == "Bearer test-token"
    assert captured["headers"]["X-custom"] == "yes"
    assert captured["timeout"] == 12.0
    assert response.message.content == "hello"
    assert response.finish_reason == "stop"
    assert response.usage["total_tokens"] == 3


@pytest.mark.asyncio
async def test_openai_compatible_embeddings_maps_openai_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_urlopen(request: Any, timeout: float = 0.0) -> _FakeHttpResponse:
        _ = (request, timeout)
        return _FakeHttpResponse(
            {
                "data": [
                    {"embedding": [0.1, 0.2]},
                    {"embedding": [0.3, 0.4]},
                ],
                "model": "text-embedding-3-small",
                "usage": {"prompt_tokens": 4, "total_tokens": 4},
            }
        )

    monkeypatch.setattr("shisad.core.providers.base.request.urlopen", fake_urlopen)

    provider = OpenAICompatibleProvider(
        base_url="https://api.example.com/v1",
        model_id="unused",
    )
    response = await provider.embeddings(["hello", "world"], model_id="embed-test")

    assert response.vectors == [[0.1, 0.2], [0.3, 0.4]]
    assert response.model == "text-embedding-3-small"
    assert response.usage["total_tokens"] == 4
