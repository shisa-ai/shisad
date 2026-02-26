"""Runtime model endpoint validation used by daemon startup."""

from __future__ import annotations

import pytest

from shisad.core.config import ModelConfig
from shisad.core.providers.routing import ModelRouter
from shisad.daemon.runner import _validate_model_endpoints


def test_model_endpoint_validation_rejects_remote_http(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    config = ModelConfig(base_url="http://example.com/v1", allow_http_localhost=False)
    router = ModelRouter(config)

    with pytest.raises(ValueError):
        _validate_model_endpoints(config, router)


def test_model_endpoint_validation_accepts_https_routes() -> None:
    config = ModelConfig(base_url="https://api.example.com/v1")
    router = ModelRouter(config)

    _validate_model_endpoints(config, router)


def test_model_endpoint_validation_enforces_configured_allowlist() -> None:
    config = ModelConfig(
        base_url="https://api.example.com/v1",
        endpoint_allowlist=["https://planner.example.com/v1"],
    )
    router = ModelRouter(config)

    with pytest.raises(ValueError):
        _validate_model_endpoints(config, router)
