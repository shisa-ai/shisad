"""M2 daemon services extraction coverage."""

from __future__ import annotations

import pytest

from shisad.core.config import DaemonConfig
from shisad.core.providers.local_planner import LocalPlannerProvider
from shisad.core.providers.routed_openai import RoutedOpenAIProvider
from shisad.daemon.services import DaemonServices


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
