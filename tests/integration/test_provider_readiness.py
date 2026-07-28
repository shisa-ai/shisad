"""U41 provider readiness and opt-in probe contracts."""

from __future__ import annotations

from types import SimpleNamespace

from shisad.core.config import DaemonConfig, ModelConfig
from shisad.core.providers.routed_openai import RoutedOpenAIProvider
from shisad.core.providers.routing import ModelRouter
from shisad.core.readiness import ReadinessState, normalize_readiness_payload
from shisad.daemon.handlers._impl import HandlerImplementation
from shisad.daemon.handlers._impl_admin import AdminImplMixin
from shisad.daemon.services import _build_provider_diagnostics


def test_u41_provider_readiness_never_false_green_when_routes_are_unprobed(
    monkeypatch,
) -> None:
    for key in (
        "SHISA_API_KEY",
        "OPENAI_API_KEY",
        "OPENROUTER_API_KEY",
        "GEMINI_API_KEY",
        "ANTHROPIC_API_KEY",
    ):
        monkeypatch.delenv(key, raising=False)
    router = ModelRouter(ModelConfig())

    diagnostics = _build_provider_diagnostics(router)

    assert diagnostics["status"] == ReadinessState.DEGRADED
    planner = diagnostics["routes"]["planner"]
    assert planner["readiness"]["state"] == ReadinessState.BLOCKED
    assert planner["readiness"]["verified"] is False
    assert planner["readiness"]["evidence"] == "config_only"
    assert "live probe has not run" in planner["readiness"]["next_action"]


def test_u41_present_provider_key_is_configured_not_authenticated(monkeypatch) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "present-but-unverified")
    router = ModelRouter(ModelConfig(planner_provider_preset="openai_default"))

    diagnostics = _build_provider_diagnostics(router)

    planner = diagnostics["routes"]["planner"]["readiness"]
    assert planner["state"] == ReadinessState.CONFIGURED
    assert planner["authenticated"] is False
    assert planner["verified"] is False
    assert planner["evidence"] == "config_only"
    assert "present-but-unverified" not in str(diagnostics)


def test_u41_missing_key_for_enabled_route_is_blocked(monkeypatch) -> None:
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    config = ModelConfig(
        planner_provider_preset="openai_default",
        planner_remote_enabled=True,
        planner_api_key=None,
    )

    planner = _build_provider_diagnostics(ModelRouter(config))["routes"]["planner"]

    assert planner["readiness"]["state"] == ReadinessState.BLOCKED
    assert planner["readiness"]["reason"] == "missing_api_key"


def test_u41_legacy_component_states_project_through_one_typed_vocabulary() -> None:
    verified = normalize_readiness_payload({"status": "ok"})
    assert verified["status"] == "verified"
    assert verified["reason"] == "legacy_ok"
    assert verified["next_action"] == "none"
    assert normalize_readiness_payload({"status": "disabled"})["status"] == "absent"
    blocked = normalize_readiness_payload(
        {"status": "misconfigured", "problems": ["missing_setting"]}
    )
    assert blocked["status"] == "blocked"
    assert blocked["legacy_status"] == "misconfigured"
    nested = normalize_readiness_payload(
        {
            "status": "disabled",
            "channels": {"matrix": {"status": "disabled"}},
        }
    )
    assert nested["channels"]["matrix"]["status"] == "absent"
    assert nested["channels"]["matrix"]["next_action"] != ""


async def test_u41_opt_in_live_probe_distinguishes_verified_and_invalid_auth(
    monkeypatch,
) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "probe-placeholder")
    router = ModelRouter(ModelConfig(planner_provider_preset="openai_default"))
    provider = RoutedOpenAIProvider(router=router)

    class _ProbeProvider:
        async def complete(self, _messages):
            return object()

    monkeypatch.setattr(provider, "_build_route_provider", lambda **_kwargs: _ProbeProvider())
    verified = await provider.probe_planner(timeout_seconds=0.5)
    assert verified.state == ReadinessState.VERIFIED
    assert verified.authenticated is True

    class _UnauthorizedProvider:
        async def complete(self, _messages):
            raise RuntimeError("Provider HTTP error 401 for https://provider.invalid/v1")

    monkeypatch.setattr(
        provider,
        "_build_route_provider",
        lambda **_kwargs: _UnauthorizedProvider(),
    )
    unauthorized = await provider.probe_planner(timeout_seconds=0.5)
    assert unauthorized.state == ReadinessState.BLOCKED
    assert unauthorized.reachable is True
    assert unauthorized.authenticated is False
    assert unauthorized.reason == "authentication_failed"


async def test_u41_live_doctor_replaces_config_only_planner_evidence(monkeypatch) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "probe-placeholder")
    router = ModelRouter(ModelConfig(planner_provider_preset="openai_default"))
    provider = RoutedOpenAIProvider(router=router)
    diagnostics = _build_provider_diagnostics(router)

    async def _verified(*, timeout_seconds: float):
        assert timeout_seconds == 1.25
        from shisad.core.readiness import verified_probe_readiness

        return verified_probe_readiness()

    monkeypatch.setattr(provider, "probe_planner", _verified)
    fake_impl = SimpleNamespace(
        _provider=provider,
        _provider_diagnostics=diagnostics,
    )

    result = await HandlerImplementation._doctor_provider_status(
        fake_impl,
        live=True,
        timeout_seconds=1.25,
    )

    assert result["status"] == ReadinessState.VERIFIED
    assert result["live_probe"] == "completed"
    assert result["routes"]["planner"]["readiness"]["verified"] is True


async def test_u41_doctor_projects_all_components_through_shared_states() -> None:
    fake = SimpleNamespace(
        _doctor_dependencies_status=lambda: {"status": "ok"},
        _doctor_storage_status=lambda: {"status": "ok"},
        _doctor_provider_status=lambda **_kwargs: {"status": "configured"},
        _doctor_policy_status=lambda: {"status": "ok"},
        _doctor_channels_status=lambda: {
            "status": "disabled",
            "channels": {"matrix": {"status": "disabled"}},
        },
        _doctor_sandbox_status=lambda: {"status": "ok"},
        _doctor_browser_status=lambda: {"status": "missing"},
        _doctor_mcp_status=lambda: {"status": "disabled"},
        _doctor_search_status=lambda: {"status": "disabled"},
        _realitycheck_toolkit=SimpleNamespace(doctor_status=lambda: {"status": "ok"}),
    )

    result = await AdminImplMixin.do_doctor_check(fake, {"component": "all"})

    assert result["status"] == ReadinessState.CONFIGURED
    assert result["checks"]["dependencies"]["status"] == ReadinessState.VERIFIED
    assert result["checks"]["channels"]["status"] == ReadinessState.ABSENT
    assert result["checks"]["channels"]["channels"]["matrix"]["status"] == (ReadinessState.ABSENT)
    assert result["checks"]["browser"]["status"] == ReadinessState.ABSENT
    assert result["checks"]["mcp"]["status"] == ReadinessState.ABSENT
    assert result["checks"]["search"]["status"] == ReadinessState.ABSENT


def test_u41_search_readiness_blocks_when_backend_is_unconfigured() -> None:
    fake = SimpleNamespace(
        _config=DaemonConfig(web_search_enabled=True, web_search_backend_url=""),
        _realitycheck_toolkit=SimpleNamespace(
            doctor_status=lambda: {"status": "disabled", "problems": []}
        ),
    )

    result = HandlerImplementation._doctor_search_status(fake)

    assert result["status"] == "misconfigured"
    assert result["web"]["status"] == "misconfigured"
    assert result["web"]["reason"] == "web_search_backend_unconfigured"
    assert "configure" in result["web"]["next_action"]
