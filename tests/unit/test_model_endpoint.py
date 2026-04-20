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
    # P1-U1: prior version called `_validate_model_endpoints` without any
    # explicit assertion — relied on the "no exception raised ⇒ pass"
    # pytest convention, which would also silently pass if the function
    # became a no-op. Pin the contract: the function returns None on
    # success.
    config = ModelConfig(base_url="https://api.example.com/v1")
    router = ModelRouter(config)

    assert _validate_model_endpoints(config, router) is None


def test_model_endpoint_validation_checks_all_model_components() -> None:
    # P1-U1 companion: prove every ModelComponent route is validated by
    # constructing a config whose per-component override is invalid and
    # confirming the specific component name appears in the raised
    # error. If the validator short-circuited after the default base_url,
    # the planner override would slip through.
    config = ModelConfig(
        base_url="https://api.example.com/v1",
        planner_base_url="http://planner.example.com/v1",  # HTTP → invalid
    )
    router = ModelRouter(config)

    with pytest.raises(ValueError, match="planner"):
        _validate_model_endpoints(config, router)


def test_model_endpoint_validation_enforces_configured_allowlist() -> None:
    config = ModelConfig(
        base_url="https://api.example.com/v1",
        endpoint_allowlist=["https://planner.example.com/v1"],
    )
    router = ModelRouter(config)

    with pytest.raises(ValueError):
        _validate_model_endpoints(config, router)
