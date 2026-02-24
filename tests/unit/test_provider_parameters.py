"""M2 provider request-parameter allowlist coverage."""

from __future__ import annotations

import json
from typing import Any

import pytest
from pydantic import ValidationError

from shisad.core.providers.base import Message, OpenAICompatibleProvider
from shisad.core.providers.capabilities import RequestParameters


class _FakeHttpResponse:
    def __init__(self, payload: dict[str, Any]) -> None:
        self._payload = payload

    def __enter__(self) -> _FakeHttpResponse:
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        return None

    def read(self) -> bytes:
        return json.dumps(self._payload).encode("utf-8")


def test_m2_request_parameters_reject_forbidden_extra_fields() -> None:
    with pytest.raises(ValidationError):
        RequestParameters.model_validate(
            {
                "temperature": 0.2,
                "stop": ["bad"],
            }
        )


def test_m2_request_parameters_enforce_range_validation() -> None:
    with pytest.raises(ValidationError):
        RequestParameters(temperature=2.5)
    with pytest.raises(ValidationError):
        RequestParameters(max_tokens=0)
    with pytest.raises(ValidationError):
        RequestParameters(max_tokens=1_000_000)
    with pytest.raises(ValidationError):
        RequestParameters(top_p=0.0)
    with pytest.raises(ValidationError):
        RequestParameters(frequency_penalty=3.0)
    with pytest.raises(ValidationError):
        RequestParameters(presence_penalty=-3.0)


def test_s0_request_parameters_support_reasoning_fields_in_payload() -> None:
    payload = RequestParameters(
        max_tokens=128,
        reasoning_effort="medium",
        reasoning={"budget_tokens": 64, "mode": "deliberate"},
    ).to_payload()

    assert payload["max_tokens"] == 128
    assert payload["reasoning_effort"] == "medium"
    assert payload["reasoning"] == {"budget_tokens": 64, "mode": "deliberate"}


@pytest.mark.asyncio
async def test_m2_openai_provider_merges_allowlisted_request_parameters(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, Any] = {}

    def fake_open(request: Any, timeout: float = 0.0) -> _FakeHttpResponse:
        _ = timeout
        captured["payload"] = json.loads(request.data.decode("utf-8"))
        return _FakeHttpResponse(
            {
                "choices": [
                    {
                        "message": {"role": "assistant", "content": "ok"},
                        "finish_reason": "stop",
                    }
                ]
            }
        )

    monkeypatch.setattr("shisad.core.providers.base._open_no_redirect", fake_open)

    provider = OpenAICompatibleProvider(
        base_url="https://api.example.com/v1",
        model_id="gpt-test",
        request_parameters=RequestParameters(
            temperature=0.15,
            max_tokens=321,
            top_p=0.8,
            frequency_penalty=0.25,
            presence_penalty=0.5,
        ),
    )
    await provider.complete([Message(role="user", content="hello")])

    payload = captured["payload"]
    assert payload["temperature"] == 0.15
    assert payload["max_tokens"] == 321
    assert payload["top_p"] == 0.8
    assert payload["frequency_penalty"] == 0.25
    assert payload["presence_penalty"] == 0.5


@pytest.mark.asyncio
async def test_m2_openai_provider_omits_unset_request_parameters(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, Any] = {}

    def fake_open(request: Any, timeout: float = 0.0) -> _FakeHttpResponse:
        _ = timeout
        captured["payload"] = json.loads(request.data.decode("utf-8"))
        return _FakeHttpResponse(
            {
                "choices": [
                    {
                        "message": {"role": "assistant", "content": "ok"},
                        "finish_reason": "stop",
                    }
                ]
            }
        )

    monkeypatch.setattr("shisad.core.providers.base._open_no_redirect", fake_open)

    provider = OpenAICompatibleProvider(
        base_url="https://api.example.com/v1",
        model_id="gpt-test",
        request_parameters=RequestParameters(temperature=0.3),
    )
    await provider.complete([Message(role="user", content="hello")])

    payload = captured["payload"]
    assert payload["temperature"] == 0.3
    assert "max_tokens" not in payload
    assert "top_p" not in payload
    assert "frequency_penalty" not in payload
    assert "presence_penalty" not in payload
