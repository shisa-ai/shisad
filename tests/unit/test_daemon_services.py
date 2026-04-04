"""M2 daemon services extraction coverage."""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from shisad.core.config import DaemonConfig, ModelConfig
from shisad.core.events import EventBus
from shisad.core.providers.local_planner import LocalPlannerProvider
from shisad.core.providers.routed_openai import RoutedOpenAIProvider
from shisad.core.providers.routing import ModelRouter
from shisad.core.types import Capability, ToolName
from shisad.daemon.services import (
    DaemonServices,
    _build_tool_registry,
    _key_gated_acceptance_matrix,
    _normalize_tool_destination,
    _register_route_credentials,
    _validate_security_route_pins,
)
from shisad.security.control_plane.sidecar import ControlPlaneUnavailableError
from shisad.security.credentials import InMemoryCredentialStore


def _clear_remote_provider_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SHISA_API_KEY", raising=False)
    monkeypatch.delenv("SHISAD_MODEL_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    monkeypatch.setenv("SHISAD_MODEL_REMOTE_ENABLED", "false")
    monkeypatch.setenv("SHISAD_MODEL_MONITOR_REMOTE_ENABLED", "false")


@pytest.mark.asyncio
async def test_daemon_services_builds_with_local_provider(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Explicitly clear API key overrides to force local provider path.
    _clear_remote_provider_env(monkeypatch)
    config = DaemonConfig(
        data_dir=tmp_path / "data",
        socket_path=tmp_path / "control.sock",
        policy_path=tmp_path / "policy.yaml",
    )
    services = await DaemonServices.build(config)
    try:
        assert isinstance(services.provider, LocalPlannerProvider)
        assert services.matrix_channel is None
        assert services.server is not None
        assert services.internal_ingress_marker is not None
    finally:
        await services.shutdown()


@pytest.mark.asyncio
async def test_h2_daemon_services_reuses_firewall_for_ingestion_pipeline(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear_remote_provider_env(monkeypatch)
    config = DaemonConfig(
        data_dir=tmp_path / "data",
        socket_path=tmp_path / "control.sock",
        policy_path=tmp_path / "policy.yaml",
    )
    services = await DaemonServices.build(config)
    try:
        assert services.ingestion._firewall is services.firewall
    finally:
        await services.shutdown()


@pytest.mark.asyncio
async def test_h1_daemon_services_builds_with_supervised_control_plane_sidecar(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear_remote_provider_env(monkeypatch)
    config = DaemonConfig(
        data_dir=tmp_path / "data",
        socket_path=tmp_path / "control.sock",
        policy_path=tmp_path / "policy.yaml",
    )
    services = await DaemonServices.build(config)
    sidecar = services.control_plane_sidecar
    assert sidecar is not None
    assert sidecar.process.returncode is None
    assert await services.control_plane.ping() is True

    await services.shutdown()

    assert sidecar.process.returncode is not None
    assert not sidecar.socket_path.exists()


@pytest.mark.asyncio
async def test_h1_daemon_services_build_fails_closed_when_control_plane_sidecar_unavailable(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def _raise_sidecar(*, data_dir, policy_path):  # type: ignore[no-untyped-def]
        _ = (data_dir, policy_path)
        raise ControlPlaneUnavailableError(reason_code="control_plane.startup_failed")

    monkeypatch.setattr("shisad.daemon.services.start_control_plane_sidecar", _raise_sidecar)
    config = DaemonConfig(
        data_dir=tmp_path / "data",
        socket_path=tmp_path / "control.sock",
        policy_path=tmp_path / "policy.yaml",
    )

    with pytest.raises(ControlPlaneUnavailableError, match="Control-plane sidecar unavailable"):
        await DaemonServices.build(config)


@pytest.mark.asyncio
async def test_h1_daemon_services_closes_started_sidecar_on_late_build_failure(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    closed: list[bool] = []

    class _FakeSidecar:
        def __init__(self) -> None:
            self.client = SimpleNamespace(ping=self._ping)
            self.process = SimpleNamespace(returncode=None)
            self.socket_path = tmp_path / "data" / "control_plane" / "fake.sock"

        async def _ping(self) -> bool:
            return True

        async def close(self) -> None:
            closed.append(True)

    async def _fake_start(*, data_dir, policy_path):  # type: ignore[no-untyped-def]
        _ = (data_dir, policy_path)
        return _FakeSidecar()

    monkeypatch.setattr("shisad.daemon.services.start_control_plane_sidecar", _fake_start)
    monkeypatch.setattr(
        "shisad.daemon.services._load_provenance",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("boom")),
    )
    config = DaemonConfig(
        data_dir=tmp_path / "data",
        socket_path=tmp_path / "control.sock",
        policy_path=tmp_path / "policy.yaml",
    )

    with pytest.raises(RuntimeError, match="boom"):
        await DaemonServices.build(config)

    assert closed == [True]


@pytest.mark.asyncio
async def test_daemon_services_builds_with_remote_provider_when_enabled(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SHISA_API_KEY", "test-token")
    monkeypatch.setenv("SHISAD_MODEL_REMOTE_ENABLED", "true")
    monkeypatch.setenv("SHISAD_MODEL_BASE_URL", "https://api.example.com/v1")
    monkeypatch.setenv("SHISAD_MODEL_PLANNER_BASE_URL", "https://planner.example.com/v1")
    monkeypatch.setenv("SHISAD_MODEL_EMBEDDINGS_BASE_URL", "https://embed.example.com/v1")
    monkeypatch.setenv("SHISAD_MODEL_MONITOR_BASE_URL", "https://monitor.example.com/v1")

    config = DaemonConfig(
        data_dir=tmp_path / "data",
        socket_path=tmp_path / "control.sock",
        policy_path=tmp_path / "policy.yaml",
    )
    services = await DaemonServices.build(config)
    try:
        assert isinstance(services.provider, RoutedOpenAIProvider)
    finally:
        await services.shutdown()


@pytest.mark.asyncio
async def test_s0_daemon_services_supports_remote_route_with_auth_none(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("SHISA_API_KEY", raising=False)
    monkeypatch.delenv("SHISAD_MODEL_API_KEY", raising=False)
    monkeypatch.setenv("SHISAD_MODEL_PLANNER_PROVIDER_PRESET", "vllm_local_default")
    monkeypatch.setenv("SHISAD_MODEL_PLANNER_BASE_URL", "http://127.0.0.1:8000/v1")
    monkeypatch.setenv("SHISAD_MODEL_PLANNER_REMOTE_ENABLED", "true")
    monkeypatch.setenv("SHISAD_MODEL_PLANNER_AUTH_MODE", "none")

    config = DaemonConfig(
        data_dir=tmp_path / "data",
        socket_path=tmp_path / "control.sock",
        policy_path=tmp_path / "policy.yaml",
    )
    services = await DaemonServices.build(config)
    try:
        assert isinstance(services.provider, RoutedOpenAIProvider)
    finally:
        await services.shutdown()


@pytest.mark.asyncio
async def test_s0_daemon_services_registers_credentials_per_route_host(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SHISAD_MODEL_REMOTE_ENABLED", "true")
    monkeypatch.setenv("SHISAD_MODEL_PLANNER_PROVIDER_PRESET", "openai_default")
    monkeypatch.setenv("SHISAD_MODEL_PLANNER_API_KEY", "planner-key")
    monkeypatch.setenv("SHISAD_MODEL_MONITOR_PROVIDER_PRESET", "openrouter_default")
    monkeypatch.setenv("SHISAD_MODEL_MONITOR_API_KEY", "monitor-key")
    monkeypatch.setenv("SHISAD_MODEL_MONITOR_REMOTE_ENABLED", "true")
    monkeypatch.setenv("SHISAD_MODEL_EMBEDDINGS_PROVIDER_PRESET", "vllm_local_default")
    monkeypatch.setenv("SHISAD_MODEL_EMBEDDINGS_REMOTE_ENABLED", "true")
    monkeypatch.setenv("SHISAD_MODEL_EMBEDDINGS_AUTH_MODE", "none")

    captured: list[tuple[str, str, tuple[str, ...], str, str]] = []

    class _CapturingCredentialStore(InMemoryCredentialStore):
        def register(self, ref, value, config):  # type: ignore[no-untyped-def]
            captured.append(
                (
                    str(ref),
                    value,
                    tuple(config.allowed_hosts),
                    config.header_name,
                    config.header_prefix,
                )
            )
            super().register(ref, value, config)

    monkeypatch.setattr("shisad.daemon.services.InMemoryCredentialStore", _CapturingCredentialStore)

    config = DaemonConfig(
        data_dir=tmp_path / "data",
        socket_path=tmp_path / "control.sock",
        policy_path=tmp_path / "policy.yaml",
    )
    services = await DaemonServices.build(config)
    try:
        hosts = {entry[2][0] for entry in captured}
        assert "api.openai.com" in hosts
        assert "openrouter.ai" in hosts
        assert "api.shisa.ai" not in hosts
        assert all(prefix == "Bearer " for *_rest, prefix in captured)
    finally:
        await services.shutdown()


def test_s0_register_route_credentials_coalesces_duplicate_signatures(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("SHISA_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("SHISAD_MODEL_API_KEY", raising=False)

    captured: list[tuple[str, str, tuple[str, ...], str, str]] = []

    class _CapturingCredentialStore(InMemoryCredentialStore):
        def register(self, ref, value, config):  # type: ignore[no-untyped-def]
            captured.append(
                (
                    str(ref),
                    value,
                    tuple(config.allowed_hosts),
                    config.header_name,
                    config.header_prefix,
                )
            )
            super().register(ref, value, config)

    router = ModelRouter(
        ModelConfig(
            remote_enabled=True,
            planner_provider_preset="openai_default",
            monitor_provider_preset="openai_default",
            planner_api_key="shared-key",
            monitor_api_key="shared-key",
            embeddings_remote_enabled=False,
        )
    )
    store = _CapturingCredentialStore()
    _register_route_credentials(credential_store=store, router=router)

    assert len(captured) == 1
    assert captured[0][1] == "shared-key"
    assert captured[0][2] == ("api.openai.com",)
    assert captured[0][3] == "Authorization"
    assert captured[0][4] == "Bearer "


def test_s0_register_route_credentials_skips_local_only_routes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("SHISA_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("SHISAD_MODEL_API_KEY", raising=False)

    captured: list[str] = []

    class _CapturingCredentialStore(InMemoryCredentialStore):
        def register(self, ref, value, config):  # type: ignore[no-untyped-def]
            _ = (ref, value, config)
            captured.append("registered")
            super().register(ref, value, config)

    router = ModelRouter(
        ModelConfig(
            planner_provider_preset="openai_default",
            planner_api_key="planner-key",
            planner_remote_enabled=False,
            monitor_remote_enabled=False,
            embeddings_remote_enabled=False,
        )
    )
    store = _CapturingCredentialStore()
    _register_route_credentials(credential_store=store, router=router)

    assert captured == []


def test_s0_key_gated_acceptance_reports_env_eligibility_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "openai-key")
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("SHISA_API_KEY", raising=False)

    matrix = _key_gated_acceptance_matrix()

    assert matrix["openai"]["status"] == "eligible (key env present)"
    assert matrix["openai"]["evidence"] == "env_presence_only"
    assert matrix["openai"]["scope"] == "route_configurable"
    assert matrix["openrouter"]["status"] == "N/A (key missing)"
    assert matrix["shisa_default"]["scope"] == "planner_only"
    assert "planner route only" in matrix["shisa_default"]["note"]


@pytest.mark.asyncio
async def test_daemon_services_matrix_missing_config_raises(tmp_path) -> None:
    config = DaemonConfig(
        data_dir=tmp_path / "data",
        socket_path=tmp_path / "control.sock",
        policy_path=tmp_path / "policy.yaml",
        matrix_enabled=True,
    )
    with pytest.raises(ValueError, match="Matrix channel is enabled but missing required config"):
        await DaemonServices.build(config)


@pytest.mark.asyncio
async def test_daemon_services_discord_missing_config_raises(tmp_path) -> None:
    config = DaemonConfig(
        data_dir=tmp_path / "data",
        socket_path=tmp_path / "control.sock",
        policy_path=tmp_path / "policy.yaml",
        discord_enabled=True,
    )
    with pytest.raises(ValueError, match="Discord channel is enabled but missing required config"):
        await DaemonServices.build(config)


@pytest.mark.asyncio
async def test_daemon_services_telegram_missing_config_raises(tmp_path) -> None:
    config = DaemonConfig(
        data_dir=tmp_path / "data",
        socket_path=tmp_path / "control.sock",
        policy_path=tmp_path / "policy.yaml",
        telegram_enabled=True,
    )
    with pytest.raises(ValueError, match="Telegram channel is enabled but missing required config"):
        await DaemonServices.build(config)


@pytest.mark.asyncio
async def test_daemon_services_slack_missing_config_raises(tmp_path) -> None:
    config = DaemonConfig(
        data_dir=tmp_path / "data",
        socket_path=tmp_path / "control.sock",
        policy_path=tmp_path / "policy.yaml",
        slack_enabled=True,
    )
    with pytest.raises(ValueError, match="Slack channel is enabled but missing required config"):
        await DaemonServices.build(config)


@pytest.mark.asyncio
async def test_daemon_services_build_rolls_back_connected_matrix_on_failure(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    disconnected = False

    class _MatrixStub:
        async def disconnect(self) -> None:
            nonlocal disconnected
            disconnected = True

    async def _fake_build_matrix_channel(config: DaemonConfig):  # type: ignore[no-untyped-def]
        _ = config
        return _MatrixStub()

    class _ExplodingCredentialStore:
        def __init__(self) -> None:
            raise RuntimeError("credential store exploded")

    monkeypatch.setattr(
        "shisad.daemon.services._build_matrix_channel",
        _fake_build_matrix_channel,
    )
    monkeypatch.setattr(
        "shisad.daemon.services.InMemoryCredentialStore",
        _ExplodingCredentialStore,
    )
    config = DaemonConfig(
        data_dir=tmp_path / "data",
        socket_path=tmp_path / "control.sock",
        policy_path=tmp_path / "policy.yaml",
    )
    with pytest.raises(RuntimeError, match="credential store exploded"):
        await DaemonServices.build(config)
    assert disconnected is True


@pytest.mark.asyncio
async def test_daemon_services_build_rolls_back_connected_matrix_on_unexpected_failure(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    disconnected = False

    class _MatrixStub:
        async def disconnect(self) -> None:
            nonlocal disconnected
            disconnected = True

    async def _fake_build_matrix_channel(config: DaemonConfig):  # type: ignore[no-untyped-def]
        _ = config
        return _MatrixStub()

    class _ExplodingCredentialStore:
        def __init__(self) -> None:
            raise KeyError("credential store exploded")

    monkeypatch.setattr(
        "shisad.daemon.services._build_matrix_channel",
        _fake_build_matrix_channel,
    )
    monkeypatch.setattr(
        "shisad.daemon.services.InMemoryCredentialStore",
        _ExplodingCredentialStore,
    )
    config = DaemonConfig(
        data_dir=tmp_path / "data",
        socket_path=tmp_path / "control.sock",
        policy_path=tmp_path / "policy.yaml",
    )
    with pytest.raises(KeyError, match="credential store exploded"):
        await DaemonServices.build(config)
    assert disconnected is True


@pytest.mark.asyncio
async def test_daemon_services_build_rolls_back_when_container_construction_fails(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    disconnected = False

    class _MatrixStub:
        async def disconnect(self) -> None:
            nonlocal disconnected
            disconnected = True

    async def _fake_build_matrix_channel(config: DaemonConfig):  # type: ignore[no-untyped-def]
        _ = config
        return _MatrixStub()

    class _ExplodingServices(DaemonServices):
        def __init__(self, *args: object, **kwargs: object) -> None:
            _ = args, kwargs
            raise RuntimeError("services construction exploded")

    monkeypatch.setattr(
        "shisad.daemon.services._build_matrix_channel",
        _fake_build_matrix_channel,
    )
    config = DaemonConfig(
        data_dir=tmp_path / "data",
        socket_path=tmp_path / "control.sock",
        policy_path=tmp_path / "policy.yaml",
    )
    with pytest.raises(RuntimeError, match="services construction exploded"):
        await _ExplodingServices.build(config)
    assert disconnected is True


@pytest.mark.asyncio
async def test_daemon_services_shutdown_continues_after_disconnect_error() -> None:
    calls: list[str] = []

    class _EmbeddingsAdapterStub:
        def close(self, *, wait: bool = True) -> None:
            calls.append(f"embed:{wait}")

    class _MatrixStub:
        async def disconnect(self) -> None:
            calls.append("matrix")
            raise RuntimeError("disconnect failed")

    class _ServerStub:
        async def stop(self) -> None:
            calls.append("server")

    services = object.__new__(DaemonServices)
    services.embeddings_adapter = _EmbeddingsAdapterStub()  # type: ignore[assignment]
    services.matrix_channel = _MatrixStub()  # type: ignore[assignment]
    services.server = _ServerStub()  # type: ignore[assignment]

    await DaemonServices.shutdown(services)
    assert calls[0] == "embed:True"
    assert "matrix" in calls
    assert calls[-1] == "server"


def test_m3_normalize_tool_destination_preserves_scheme_and_port() -> None:
    assert _normalize_tool_destination("https://search.example") == "https://search.example:443"
    assert (
        _normalize_tool_destination("http://search.example:8080/api?q=1")
        == "http://search.example:8080"
    )
    assert _normalize_tool_destination("search.example") == "search.example"


def test_m6_normalize_tool_destination_rejects_invalid_port() -> None:
    assert _normalize_tool_destination("https://search.example:99999") == ""


def test_m3_tool_registry_omits_realitycheck_tools_when_surface_disabled() -> None:
    registry, _alarm = _build_tool_registry(
        EventBus(),
        realitycheck_surface_enabled=False,
    )
    names = {str(item.name) for item in registry.list_tools()}
    assert "realitycheck.search" not in names
    assert "realitycheck.read" not in names


def test_s9_tool_registry_uses_dotted_canonical_runtime_ids_only() -> None:
    registry, _alarm = _build_tool_registry(
        EventBus(),
        realitycheck_surface_enabled=False,
    )
    names = {str(item.name) for item in registry.list_tools()}
    assert {"shell.exec", "http.request", "web.search", "web.fetch"} <= names
    assert "shell_exec" not in names
    assert "http_request" not in names
    assert "web_search" not in names
    assert "web_fetch" not in names


def test_m3_tool_registry_registers_realitycheck_tools_with_endpoint_caps() -> None:
    registry, _alarm = _build_tool_registry(
        EventBus(),
        realitycheck_surface_enabled=True,
        realitycheck_endpoint_enabled=True,
        realitycheck_endpoint_host="realitycheck.example",
    )
    search_tool = registry.get_tool(ToolName("realitycheck.search"))
    read_tool = registry.get_tool(ToolName("realitycheck.read"))
    assert search_tool is not None
    assert read_tool is not None
    assert set(search_tool.capabilities_required) == {Capability.FILE_READ, Capability.HTTP_REQUEST}
    assert search_tool.destinations == ["realitycheck.example"]
    assert set(read_tool.capabilities_required) == {Capability.FILE_READ}


def test_m6_tool_registry_registers_browser_scope_destinations() -> None:
    registry, _alarm = _build_tool_registry(
        EventBus(),
        browser_surface_enabled=True,
        browser_destinations=["localhost", "127.0.0.1"],
    )
    navigate_tool = registry.get_tool(ToolName("browser.navigate"))
    click_tool = registry.get_tool(ToolName("browser.click"))
    assert navigate_tool is not None
    assert click_tool is not None
    assert navigate_tool.destinations == ["localhost", "127.0.0.1"]
    assert click_tool.destinations == ["localhost", "127.0.0.1"]
    assert any(param.name == "destination" for param in click_tool.parameters)


@pytest.mark.parametrize(
    ("browser_allowed_domains", "web_allowed_domains"),
    [
        (["*.browser.example"], []),
        ([], ["*.browser.example"]),
    ],
)
def test_m6_daemon_config_rejects_wildcard_browser_scope_under_hardened_isolation(
    tmp_path,
    browser_allowed_domains: list[str],
    web_allowed_domains: list[str],
) -> None:
    with pytest.raises(ValidationError, match="wildcard browser scope"):
        DaemonConfig(
            data_dir=tmp_path / "data",
            socket_path=tmp_path / "control.sock",
            policy_path=tmp_path / "policy.yaml",
            browser_enabled=True,
            browser_require_hardened_isolation=True,
            browser_allowed_domains=browser_allowed_domains,
            web_allowed_domains=web_allowed_domains,
        )


@pytest.mark.asyncio
async def test_m6_daemon_services_browser_registry_falls_back_to_web_allowlist(
    tmp_path,
) -> None:
    config = DaemonConfig(
        data_dir=tmp_path / "data",
        socket_path=tmp_path / "control.sock",
        policy_path=tmp_path / "policy.yaml",
        browser_enabled=True,
        web_allowed_domains=["localhost"],
        browser_allowed_domains=[],
    )
    services = await DaemonServices.build(config)
    try:
        navigate_tool = services.registry.get_tool(ToolName("browser.navigate"))
        assert navigate_tool is not None
        assert navigate_tool.destinations == ["localhost"]
    finally:
        await services.shutdown()


@pytest.mark.asyncio
async def test_m3_daemon_services_fail_closed_when_realitycheck_disabled(tmp_path) -> None:
    config = DaemonConfig(
        data_dir=tmp_path / "data",
        socket_path=tmp_path / "control.sock",
        policy_path=tmp_path / "policy.yaml",
        realitycheck_enabled=False,
    )
    services = await DaemonServices.build(config)
    try:
        assert services.realitycheck_status["status"] == "disabled"
        assert services.registry.get_tool(ToolName("realitycheck.search")) is None
        assert services.registry.get_tool(ToolName("realitycheck.read")) is None
    finally:
        await services.shutdown()


@pytest.mark.asyncio
async def test_m3_daemon_services_enable_realitycheck_surface_when_config_valid(tmp_path) -> None:
    repo_root = tmp_path / "realitycheck"
    data_root = tmp_path / "realitycheck-data"
    repo_root.mkdir(parents=True)
    data_root.mkdir(parents=True)

    config = DaemonConfig(
        data_dir=tmp_path / "data",
        socket_path=tmp_path / "control.sock",
        policy_path=tmp_path / "policy.yaml",
        realitycheck_enabled=True,
        realitycheck_repo_root=repo_root,
        realitycheck_data_roots=[data_root],
        realitycheck_endpoint_enabled=False,
    )
    services = await DaemonServices.build(config)
    try:
        assert services.realitycheck_status["status"] == "ok"
        assert services.registry.get_tool(ToolName("realitycheck.search")) is not None
        assert services.registry.get_tool(ToolName("realitycheck.read")) is not None
    finally:
        await services.shutdown()


@pytest.mark.asyncio
async def test_m3_daemon_services_fail_closed_on_invalid_endpoint_port(tmp_path) -> None:
    repo_root = tmp_path / "realitycheck"
    data_root = tmp_path / "realitycheck-data"
    repo_root.mkdir(parents=True)
    data_root.mkdir(parents=True)

    config = DaemonConfig(
        data_dir=tmp_path / "data",
        socket_path=tmp_path / "control.sock",
        policy_path=tmp_path / "policy.yaml",
        realitycheck_enabled=True,
        realitycheck_repo_root=repo_root,
        realitycheck_data_roots=[data_root],
        realitycheck_endpoint_enabled=True,
        realitycheck_endpoint_url="https://allowed.example:abc/search",
        realitycheck_allowed_domains=["allowed.example"],
    )
    services = await DaemonServices.build(config)
    try:
        assert services.realitycheck_status["status"] == "misconfigured"
        assert "endpoint_port_invalid" in services.realitycheck_status["problems"]
        assert services.registry.get_tool(ToolName("realitycheck.search")) is None
        assert services.registry.get_tool(ToolName("realitycheck.read")) is None
    finally:
        await services.shutdown()


def test_m1_pf11_model_route_pinning_rejects_mismatch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SHISAD_MODEL_REMOTE_ENABLED", "true")
    monkeypatch.setenv("SHISAD_MODEL_MONITOR_MODEL", "monitor-live")
    monkeypatch.setenv("SHISAD_MODEL_PLANNER_MODEL", "planner-live")
    monkeypatch.setenv("SHISAD_MODEL_ENFORCE_SECURITY_ROUTE_PINNING", "true")
    monkeypatch.setenv("SHISAD_MODEL_PINNED_MONITOR_MODEL_ID", "monitor-pinned")
    monkeypatch.setenv("SHISAD_MODEL_PINNED_PLANNER_MODEL_ID", "planner-live")
    model = ModelConfig()
    router = ModelRouter(model)
    with pytest.raises(ValueError, match="Security monitor route model id mismatch"):
        _validate_security_route_pins(model, router)


def test_m1_pf11_model_route_pinning_disabled_allows_mismatch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SHISAD_MODEL_REMOTE_ENABLED", "true")
    monkeypatch.setenv("SHISAD_MODEL_MONITOR_MODEL", "monitor-live")
    monkeypatch.setenv("SHISAD_MODEL_PLANNER_MODEL", "planner-live")
    monkeypatch.setenv("SHISAD_MODEL_ENFORCE_SECURITY_ROUTE_PINNING", "false")
    monkeypatch.setenv("SHISAD_MODEL_PINNED_MONITOR_MODEL_ID", "monitor-pinned")
    monkeypatch.setenv("SHISAD_MODEL_PINNED_PLANNER_MODEL_ID", "planner-pinned")
    model = ModelConfig()
    router = ModelRouter(model)
    _validate_security_route_pins(model, router)


def test_m1_pf11_model_route_pinning_default_allows_mismatch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("SHISAD_MODEL_ENFORCE_SECURITY_ROUTE_PINNING", raising=False)
    monkeypatch.setenv("SHISAD_MODEL_PINNED_MONITOR_MODEL_ID", "monitor-pinned")
    monkeypatch.setenv("SHISAD_MODEL_PINNED_PLANNER_MODEL_ID", "planner-pinned")
    model = ModelConfig()
    router = ModelRouter(model)
    _validate_security_route_pins(model, router)
