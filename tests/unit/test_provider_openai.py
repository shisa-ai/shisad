"""M0 provider abstraction: OpenAI-compatible transport behavior."""

from __future__ import annotations

import json
from typing import Any
from urllib.error import HTTPError

import pytest

from shisad.core.providers.base import (
    Message,
    OpenAICompatibleProvider,
    _validate_runtime_endpoint_url,
)


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

    def fake_open(request: Any, timeout: float = 0.0) -> _FakeHttpResponse:
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

    monkeypatch.setattr("shisad.core.providers.base._open_no_redirect", fake_open)

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
    assert "response_format" not in captured["payload"]
    assert captured["headers"]["Authorization"] == "Bearer test-token"
    assert captured["headers"]["X-custom"] == "yes"
    assert captured["timeout"] == 12.0
    assert response.message.content == "hello"
    assert response.finish_reason == "stop"
    assert response.usage["total_tokens"] == 3


@pytest.mark.asyncio
async def test_openai_compatible_complete_forces_json_mode_when_enabled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, Any] = {}

    def fake_open(request: Any, timeout: float = 0.0) -> _FakeHttpResponse:
        captured["payload"] = json.loads(request.data.decode("utf-8"))
        _ = timeout
        return _FakeHttpResponse(
            {
                "choices": [
                    {
                        "message": {"role": "assistant", "content": '{"ok":true}'},
                        "finish_reason": "stop",
                    }
                ],
            }
        )

    monkeypatch.setattr("shisad.core.providers.base._open_no_redirect", fake_open)

    provider = OpenAICompatibleProvider(
        base_url="https://api.example.com/v1",
        model_id="gpt-test",
        force_json_response=True,
    )
    await provider.complete([Message(role="user", content="Hi")])

    assert captured["payload"]["response_format"] == {"type": "json_object"}


@pytest.mark.asyncio
async def test_openai_compatible_embeddings_maps_openai_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_open(request: Any, timeout: float = 0.0) -> _FakeHttpResponse:
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

    monkeypatch.setattr("shisad.core.providers.base._open_no_redirect", fake_open)

    provider = OpenAICompatibleProvider(
        base_url="https://api.example.com/v1",
        model_id="unused",
    )
    response = await provider.embeddings(["hello", "world"], model_id="embed-test")

    assert response.vectors == [[0.1, 0.2], [0.3, 0.4]]
    assert response.model == "text-embedding-3-small"
    assert response.usage["total_tokens"] == 4


@pytest.mark.asyncio
async def test_openai_compatible_complete_normalizes_null_content(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_open(request: Any, timeout: float = 0.0) -> _FakeHttpResponse:
        _ = (request, timeout)
        return _FakeHttpResponse(
            {
                "choices": [
                    {
                        "message": {"role": "assistant", "content": None},
                        "finish_reason": "stop",
                    }
                ],
            }
        )

    monkeypatch.setattr("shisad.core.providers.base._open_no_redirect", fake_open)

    provider = OpenAICompatibleProvider(
        base_url="https://api.example.com/v1",
        model_id="gpt-test",
    )
    response = await provider.complete([Message(role="user", content="Hi")])
    assert response.message.content == ""


@pytest.mark.asyncio
async def test_openai_compatible_complete_validates_redirect_hops(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []

    def fake_open(request: Any, timeout: float = 0.0) -> _FakeHttpResponse:
        _ = timeout
        calls.append(str(request.full_url))
        if len(calls) == 1:
            raise HTTPError(
                url=str(request.full_url),
                code=307,
                msg="Temporary Redirect",
                hdrs={"Location": "https://api.example.com/v1/chat/completions?region=us"},
                fp=None,
            )
        return _FakeHttpResponse(
            {
                "choices": [
                    {
                        "message": {"role": "assistant", "content": "redirect-ok"},
                        "finish_reason": "stop",
                    }
                ],
                "usage": {"total_tokens": 1},
            }
        )

    validations: list[str] = []
    monkeypatch.setattr("shisad.core.providers.base._open_no_redirect", fake_open)
    monkeypatch.setattr(
        "shisad.core.providers.base._validate_runtime_endpoint_url",
        lambda url, **kwargs: validations.append(str(url)) or [],
    )

    provider = OpenAICompatibleProvider(
        base_url="https://api.example.com/v1",
        model_id="gpt-test",
    )
    response = await provider.complete([Message(role="user", content="Hi")])
    assert response.message.content == "redirect-ok"
    assert calls[0].endswith("/chat/completions")
    assert calls[1].startswith("https://api.example.com/v1/chat/completions")
    assert validations[0].endswith("/chat/completions")
    assert validations[1].startswith("https://api.example.com/v1/chat/completions")


@pytest.mark.asyncio
async def test_openai_compatible_complete_blocks_redirect_to_private_range(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_open(request: Any, timeout: float = 0.0) -> _FakeHttpResponse:
        _ = timeout
        raise HTTPError(
            url=str(request.full_url),
            code=302,
            msg="Found",
            hdrs={"Location": "http://169.254.169.254/latest/meta-data"},
            fp=None,
        )

    monkeypatch.setattr("shisad.core.providers.base._open_no_redirect", fake_open)
    monkeypatch.setattr(
        "shisad.core.providers.base._validate_runtime_endpoint_url",
        lambda url, **kwargs: (  # type: ignore[no-any-return]
            ["Endpoint in private range"] if "169.254.169.254" in str(url) else []
        ),
    )
    provider = OpenAICompatibleProvider(
        base_url="https://api.example.com/v1",
        model_id="gpt-test",
    )
    with pytest.raises(RuntimeError, match="Provider redirect blocked"):
        await provider.complete([Message(role="user", content="Hi")])


def test_runtime_endpoint_validation_blocks_private_resolved_hostname(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "shisad.core.providers.base.socket.getaddrinfo",
        lambda *args, **kwargs: [  # type: ignore[no-any-return]
            (0, 0, 0, "", ("10.0.0.5", 443)),
        ],
    )
    errors = _validate_runtime_endpoint_url("https://planner.example.com/v1")
    assert any("private range" in error.lower() for error in errors)
