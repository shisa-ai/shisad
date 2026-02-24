"""M2 daemon services extraction coverage."""

from __future__ import annotations

import pytest

from shisad.core.config import DaemonConfig, ModelConfig
from shisad.core.events import EventBus
from shisad.core.providers.local_planner import LocalPlannerProvider
from shisad.core.providers.routed_openai import RoutedOpenAIProvider
from shisad.core.providers.routing import ModelRouter
from shisad.core.types import Capability, ToolName
from shisad.daemon.services import (
    DaemonServices,
    _build_tool_registry,
    _normalize_tool_destination,
    _validate_security_route_pins,
)
from shisad.security.credentials import InMemoryCredentialStore


@pytest.mark.asyncio
async def test_daemon_services_builds_with_local_provider(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Explicitly clear API key overrides to force local provider path.
    monkeypatch.delenv("SHISA_API_KEY", raising=False)
    monkeypatch.delenv("SHISAD_MODEL_API_KEY", raising=False)
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
