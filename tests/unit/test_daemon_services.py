"""M2 daemon services extraction coverage."""

from __future__ import annotations

import asyncio
import sqlite3
import subprocess
import sys
import textwrap
from datetime import UTC, datetime
from threading import Event, Thread
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from shisad.core.config import DaemonConfig, ModelConfig
from shisad.core.events import EventBus, SessionCreated
from shisad.core.evidence import ArtifactLedger
from shisad.core.providers.local_planner import LocalPlannerProvider
from shisad.core.providers.routed_openai import RoutedOpenAIProvider
from shisad.core.providers.routing import ModelRouter
from shisad.core.session import SessionManager
from shisad.core.trace import TraceMessage, TraceToolCall, TraceTurn
from shisad.core.transcript import TranscriptStore
from shisad.core.types import Capability, CredentialRef, SessionId, ToolName, UserId, WorkspaceId
from shisad.daemon.handlers._impl import HandlerImplementation, PendingAction
from shisad.daemon.services import (
    DaemonServices,
    _browser_runtime_unavailable_planner_note,
    _build_provider_diagnostics,
    _build_tool_registry,
    _key_gated_acceptance_matrix,
    _log_provider_route_summary,
    _normalize_tool_destination,
    _promptguard_degraded_hint,
    _register_route_credentials,
    _validate_security_route_pins,
    _warn_on_evidence_kms_endpoint_config,
    _warn_on_provider_route_gaps,
)
from shisad.memory.schema import MemorySource
from shisad.scheduler.schema import Schedule
from shisad.security.control_plane.sidecar import ControlPlaneUnavailableError
from shisad.security.credentials import (
    ApprovalFactorRecord,
    CredentialConfig,
    InMemoryCredentialStore,
    SignerKeyRecord,
)
from shisad.security.lockdown import LockdownLevel
from shisad.security.risk import RiskObservation, RiskPolicyVersion
from shisad.skills.artifacts import ArtifactState
from shisad.skills.manager import InstalledSkill
from shisad.ui.tui import TuiSnapshot, _safe_channel_rows, render_plain


def _write_browser_wrapper(path) -> None:
    path.write_text(
        "\n".join(
            [
                "#!/usr/bin/env python3",
                "import sys",
                "if '--shisad-browser-wrapper-version' in sys.argv:",
                "    print('shisad-browser-wrapper 2')",
                "    raise SystemExit(0)",
                "if '--shisad-browser-wrapper-doctor' in sys.argv:",
                "    print('shisad-browser-wrapper doctor ok')",
                "    raise SystemExit(0)",
                "raise SystemExit(1)",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    path.chmod(0o755)


def test_u8_daemon_runner_import_defers_disabled_backend_modules() -> None:
    code = textwrap.dedent(
        """
        import sys

        import shisad.daemon.runner

        eager_modules = [
            "shisad.assistant.realitycheck",
            "shisad.channels.discord",
            "shisad.channels.matrix",
            "shisad.channels.slack",
            "shisad.channels.telegram",
            "shisad.executors.browser",
        ]
        for name in eager_modules:
            if name in sys.modules:
                print(name)
        """
    )
    result = subprocess.run(
        [sys.executable, "-c", code],
        check=True,
        text=True,
        capture_output=True,
    )
    assert result.stdout.strip() == ""


def _clear_remote_provider_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for env_var in (
        "SHISA_API_KEY",
        "SHISAD_MODEL_API_KEY",
        "OPENAI_API_KEY",
        "GEMINI_API_KEY",
        "OPENROUTER_API_KEY",
        "ANTHROPIC_API_KEY",
        "SHISAD_MODEL_PLANNER_PROVIDER_PRESET",
        "SHISAD_MODEL_PLANNER_BASE_URL",
        "SHISAD_MODEL_PLANNER_REMOTE_ENABLED",
        "SHISAD_MODEL_PLANNER_API_KEY",
        "SHISAD_MODEL_PLANNER_AUTH_MODE",
        "SHISAD_MODEL_EMBEDDINGS_PROVIDER_PRESET",
        "SHISAD_MODEL_EMBEDDINGS_BASE_URL",
        "SHISAD_MODEL_EMBEDDINGS_REMOTE_ENABLED",
        "SHISAD_MODEL_EMBEDDINGS_API_KEY",
        "SHISAD_MODEL_EMBEDDINGS_AUTH_MODE",
        "SHISAD_MODEL_MONITOR_PROVIDER_PRESET",
        "SHISAD_MODEL_MONITOR_BASE_URL",
        "SHISAD_MODEL_MONITOR_REMOTE_ENABLED",
        "SHISAD_MODEL_MONITOR_API_KEY",
        "SHISAD_MODEL_MONITOR_AUTH_MODE",
    ):
        monkeypatch.delenv(env_var, raising=False)
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
        impl = HandlerImplementation(services=services)
        status = await impl.do_daemon_status({})
        doctor = await impl.do_doctor_check({"component": "approvals"})
        skill_doctor = await impl.do_doctor_check({"component": "skills"})
        selfmod_doctor = await impl.do_doctor_check({"component": "selfmod"})
        dashboard_doctor = await impl.do_doctor_check({"component": "dashboard"})
        control_plane_doctor = await impl.do_doctor_check({"component": "control_plane"})
        channels_doctor = await impl.do_doctor_check({"component": "channels"})
        assert isinstance(services.provider, LocalPlannerProvider)
        assert services.matrix_channel is None
        assert services.server is not None
        assert services.internal_ingress_marker is not None
        assert status["approvals"]["status"] == "ok"
        assert status["approvals"]["load_status"] == "missing"
        assert status["skills"]["status"] == "ok"
        assert status["skills"]["load_status"] == "missing"
        assert status["dashboard"]["status"] == "ok"
        assert status["dashboard"]["load_status"] == "missing"
        assert status["pairing_requests"]["status"] == "ok"
        assert status["control_plane"]["status"] == "ok"
        assert "pairing_requests" not in status["channels"]
        assert channels_doctor["status"] == "ok"
        assert all(
            row["replay_state"]["status"] == "missing"
            for row in channels_doctor["checks"]["channels"]["channels"].values()
        )
        channel_health = _safe_channel_rows(status["channels"])
        assert {row["channel"] for row in channel_health} == {
            "discord",
            "matrix",
            "slack",
            "telegram",
        }
        assert "channels=0 connected_channels=0" in render_plain(
            TuiSnapshot(channel_health=channel_health)
        )
        assert doctor["status"] == "ok"
        assert doctor["checks"]["approvals"]["load_status"] == "missing"
        assert skill_doctor["status"] == "ok"
        assert skill_doctor["checks"]["skills"]["load_status"] == "missing"
        assert selfmod_doctor["status"] == "ok"
        assert selfmod_doctor["checks"]["selfmod"]["load_status"] == "missing"
        assert dashboard_doctor["status"] == "ok"
        assert dashboard_doctor["checks"]["dashboard"]["load_status"] == "missing"
        assert control_plane_doctor["status"] == "ok"
        assert control_plane_doctor["checks"]["control_plane"]["status"] == "ok"
    finally:
        await services.shutdown()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "corrupt_bytes",
    [
        b'{"version":1,"payload":',
        b'{"version":1,"checksum":"\\u00e9","payload":{}}',
        b'{"version":1,"checksum":"unused","payload":{"text":"\\ud800"}}',
        (
            b'{"version":1,"checksum":"unused","payload":'
            + (b"[" * 10000)
            + b"0"
            + (b"]" * 10000)
            + b"}"
        ),
    ],
)
async def test_f3_corrupt_control_plane_state_is_visible_while_daemon_stays_up(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
    corrupt_bytes: bytes,
) -> None:
    _clear_remote_provider_env(monkeypatch)
    data_dir = tmp_path / "data"
    plans_path = data_dir / "control_plane" / "plans.json"
    plans_path.parent.mkdir(parents=True)
    plans_path.write_bytes(corrupt_bytes)
    config = DaemonConfig(
        data_dir=data_dir,
        socket_path=tmp_path / "control.sock",
        policy_path=tmp_path / "policy.yaml",
    )

    services = await DaemonServices.build(config)
    try:
        impl = HandlerImplementation(services=services)
        assert await services.control_plane.ping() is True
        status = await impl.do_daemon_status({})
        doctor = await impl.do_doctor_check({"component": "control_plane"})

        assert status["control_plane"]["status"] == "degraded"
        assert status["control_plane"]["fail_closed"] is True
        assert status["control_plane"]["domains"]["trace"]["load_status"] == "corrupt"
        assert doctor["status"] == "degraded"
        assert doctor["checks"]["control_plane"]["status"] == "degraded"
        assert plans_path.read_bytes() == corrupt_bytes
    finally:
        await services.shutdown()


@pytest.mark.asyncio
async def test_f3_corrupt_evidence_domain_is_visible_while_daemon_stays_up(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear_remote_provider_env(monkeypatch)
    data_dir = tmp_path / "data"
    evidence_root = data_dir / "sessions" / "evidence"
    ArtifactLedger(evidence_root, salt=b"a" * 32)
    index_path = evidence_root / "refs_index.json"
    corrupt_bytes = b'{"version":1,"payload":'
    index_path.write_bytes(corrupt_bytes)
    config = DaemonConfig(
        data_dir=data_dir,
        socket_path=tmp_path / "control.sock",
        policy_path=tmp_path / "policy.yaml",
    )

    services = await DaemonServices.build(config)
    try:
        impl = HandlerImplementation(services=services)
        assert await services.control_plane.ping() is True
        status = await impl.do_daemon_status({})
        doctor = await impl.do_doctor_check({"component": "evidence"})
        doctor_all = await impl.do_doctor_check({"component": "all"})

        assert status["status"] == "running"
        assert status["evidence"]["status"] == "degraded"
        assert status["evidence"]["scope"] == "evidence_only"
        assert status["evidence"]["fail_closed"] is True
        assert status["evidence"]["load_status"] == "corrupt"
        assert status["evidence"]["reason"] == "invalid_json"
        assert doctor["status"] == "degraded"
        assert doctor["checks"]["evidence"]["problems"] == ["invalid_json"]
        assert doctor_all["checks"]["evidence"]["problems"] == ["invalid_json"]
        assert index_path.read_bytes() == corrupt_bytes
    finally:
        await services.shutdown()


@pytest.mark.asyncio
async def test_f3_corrupt_dashboard_marks_start_visible_bounded_degraded(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear_remote_provider_env(monkeypatch)
    data_dir = tmp_path / "data"
    marks_path = data_dir / "dashboard" / "false_positives.json"
    marks_path.parent.mkdir(parents=True)
    corrupt_bytes = b'{"version":1,"payload":'
    marks_path.write_bytes(corrupt_bytes)
    config = DaemonConfig(
        data_dir=data_dir,
        socket_path=tmp_path / "control.sock",
        policy_path=tmp_path / "policy.yaml",
    )

    services = await DaemonServices.build(config)
    try:
        impl = HandlerImplementation(services=services)
        status = await impl.do_daemon_status({})
        doctor = await impl.do_doctor_check({"component": "dashboard"})

        assert status["dashboard"]["status"] == "degraded"
        assert status["dashboard"]["load_status"] == "corrupt"
        assert doctor["status"] == "degraded"
        assert doctor["checks"]["dashboard"]["problems"] == [
            "dashboard_marks_corrupt"
        ]
        assert marks_path.read_bytes() == corrupt_bytes
    finally:
        await services.shutdown()


@pytest.mark.asyncio
async def test_f3_corrupt_approval_store_starts_bounded_degraded_and_is_actionable(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear_remote_provider_env(monkeypatch)
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    approval_path = data_dir / "approval-factors.json"
    corrupt_bytes = b'{"version":3,"payload":'
    approval_path.write_bytes(corrupt_bytes)
    config = DaemonConfig(
        data_dir=data_dir,
        socket_path=tmp_path / "control.sock",
        policy_path=tmp_path / "policy.yaml",
    )

    services = await DaemonServices.build(config)
    try:
        impl = HandlerImplementation(services=services)
        status = await impl.do_daemon_status({})
        doctor = await impl.do_doctor_check({"component": "approvals"})

        assert status["status"] == "running"
        assert status["approvals"]["status"] == "degraded"
        assert status["approvals"]["load_status"] == "corrupt"
        assert status["approvals"]["fail_closed"] is True
        assert str(approval_path) == status["approvals"]["path"]
        assert "restore" in status["approvals"]["remediation"].lower()
        assert doctor["status"] == "degraded"
        assert doctor["checks"]["approvals"]["problems"] == [
            "approval_store_corrupt"
        ]
        assert impl._confirmation_backend_registry.get_backend("software.default") is not None
        assert impl._confirmation_backend_registry.get_backend("totp.default") is None
        assert impl._confirmation_backend_registry.get_backend("approver.local_fido2") is None
        assert approval_path.read_bytes() == corrupt_bytes
    finally:
        await services.shutdown()


@pytest.mark.asyncio
async def test_f3_corrupt_skill_inventory_starts_bounded_degraded_and_is_actionable(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear_remote_provider_env(monkeypatch)
    data_dir = tmp_path / "data"
    skill_dir = data_dir / "skills"
    skill_dir.mkdir(parents=True)
    inventory_path = skill_dir / "inventory.json"
    corrupt_bytes = b'{"version":1,"payload":'
    inventory_path.write_bytes(corrupt_bytes)
    config = DaemonConfig(
        data_dir=data_dir,
        socket_path=tmp_path / "control.sock",
        policy_path=tmp_path / "policy.yaml",
    )

    services = await DaemonServices.build(config)
    try:
        impl = HandlerImplementation(services=services)
        status = await impl.do_daemon_status({})
        doctor = await impl.do_doctor_check({"component": "skills"})

        assert status["status"] == "running"
        assert status["skills"]["status"] == "degraded"
        assert status["skills"]["load_status"] == "corrupt"
        assert status["skills"]["fail_closed"] is True
        assert str(inventory_path) == status["skills"]["path"]
        assert "restore" in status["skills"]["remediation"].lower()
        assert doctor["status"] == "degraded"
        assert doctor["checks"]["skills"]["problems"] == [
            "skill_inventory_corrupt"
        ]
        assert not any(
            str(tool.name).startswith("skill.") for tool in services.registry.list_tools()
        )
        assert inventory_path.read_bytes() == corrupt_bytes
    finally:
        await services.shutdown()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "corrupt_bytes",
    [
        pytest.param(b'{"version":1,"payload":', id="invalid-json"),
        pytest.param(
            (b"[" * 10000) + b"0" + (b"]" * 10000),
            id="recursive-json",
        ),
        pytest.param((b"- " * 10000) + b"0\n", id="recursive-yaml"),
    ],
)
async def test_f3_corrupt_selfmod_inventory_starts_bounded_degraded_and_is_actionable(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
    corrupt_bytes: bytes,
) -> None:
    _clear_remote_provider_env(monkeypatch)
    data_dir = tmp_path / "data"
    selfmod_dir = data_dir / "selfmod"
    selfmod_dir.mkdir(parents=True)
    inventory_path = selfmod_dir / "inventory.yaml"
    inventory_path.write_bytes(corrupt_bytes)
    config = DaemonConfig(
        data_dir=data_dir,
        socket_path=tmp_path / "control.sock",
        policy_path=tmp_path / "policy.yaml",
    )

    services = await DaemonServices.build(config)
    try:
        impl = HandlerImplementation(services=services)
        status = await impl.do_daemon_status({})
        doctor = await impl.do_doctor_check({"component": "selfmod"})

        inventory_status = status["selfmod"]["inventory"]
        assert inventory_status["status"] == "degraded"
        assert inventory_status["load_status"] == "corrupt"
        assert inventory_status["fail_closed"] is True
        assert str(inventory_path) == inventory_status["path"]
        assert doctor["status"] == "degraded"
        assert doctor["checks"]["selfmod"]["problems"] == [
            "selfmod_inventory_corrupt"
        ]
        assert services.skill_manager.state_degraded is True
        assert inventory_path.read_bytes() == corrupt_bytes
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
        assert services.ingestion._db_path == config.data_dir / "memory_entries" / "memory.sqlite3"
    finally:
        await services.shutdown()


@pytest.mark.asyncio
async def test_m5_daemon_services_wires_timeline_index_append_observer(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear_remote_provider_env(monkeypatch)
    config = DaemonConfig(
        data_dir=tmp_path / "data",
        socket_path=tmp_path / "control.sock",
        policy_path=tmp_path / "policy.yaml",
    )
    preexisting_sessions = SessionManager(state_dir=config.data_dir / "sessions" / "state")
    preexisting_transcripts = TranscriptStore(config.data_dir / "sessions")
    preexisting_session = preexisting_sessions.create(
        channel="cli",
        user_id=UserId("alice"),
        workspace_id=WorkspaceId("ws1"),
    )
    preexisting_transcripts.append(
        preexisting_session.id,
        role="user",
        content="Before observer startup we chose soba for lunch.",
        timestamp=datetime(2026, 5, 4, 12, 0, tzinfo=UTC),
    )
    services = await DaemonServices.build(config)
    try:
        rebuilt = services.timeline_index.search(
            query="soba lunch",
            user_id="alice",
            workspace_id="ws1",
            context_channel="cli",
            now=datetime(2026, 5, 8, 12, 0, tzinfo=UTC),
        )
        assert rebuilt.results_count == 1
        assert "soba" in rebuilt.results[0].snippet

        session = services.session_manager.create(
            channel="cli",
            user_id=UserId("alice"),
            workspace_id=WorkspaceId("ws1"),
        )
        services.transcript_store.append(
            session.id,
            role="user",
            content="We chose Bar Neko for lunch last time.",
            timestamp=datetime(2026, 5, 5, 12, 0, tzinfo=UTC),
        )

        result = services.timeline_index.search(
            query="lunch last time",
            user_id="alice",
            workspace_id="ws1",
            context_channel="cli",
            now=datetime(2026, 5, 8, 12, 0, tzinfo=UTC),
        )

        assert result.results_count == 2
        assert "Bar Neko" in result.results[0].snippet
    finally:
        await services.shutdown()


@pytest.mark.asyncio
async def test_m5_daemon_services_rebuilds_terminated_transcript_timeline(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear_remote_provider_env(monkeypatch)
    config = DaemonConfig(
        data_dir=tmp_path / "data",
        socket_path=tmp_path / "control.sock",
        policy_path=tmp_path / "policy.yaml",
    )
    preexisting_sessions = SessionManager(state_dir=config.data_dir / "sessions" / "state")
    preexisting_transcripts = TranscriptStore(config.data_dir / "sessions")
    terminated_session = preexisting_sessions.create(
        channel="cli",
        user_id=UserId("alice"),
        workspace_id=WorkspaceId("ws1"),
    )
    preexisting_transcripts.append(
        terminated_session.id,
        role="user",
        content="Before termination we chose katsudon for dinner.",
        metadata={
            "channel": "cli",
            "user_id": "alice",
            "workspace_id": "ws1",
        },
        timestamp=datetime(2026, 5, 4, 19, 0, tzinfo=UTC),
    )
    assert preexisting_sessions.terminate(terminated_session.id, reason="done")
    assert preexisting_sessions.list_active() == []

    services = await DaemonServices.build(config)
    try:
        result = services.timeline_index.search(
            query="katsudon dinner",
            user_id="alice",
            workspace_id="ws1",
            context_channel="cli",
            now=datetime(2026, 5, 8, 12, 0, tzinfo=UTC),
        )

        assert result.results_count == 1
        assert "katsudon" in result.results[0].snippet
        assert result.results[0].session_id == str(terminated_session.id)
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
    async def _raise_sidecar(  # type: ignore[no-untyped-def]
        *,
        data_dir,
        policy_path,
        authority_claim,
        assistant_fs_roots,
        startup_timeout_seconds,
    ):
        _ = (
            data_dir,
            policy_path,
            authority_claim,
            assistant_fs_roots,
            startup_timeout_seconds,
        )
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

    async def _fake_start(  # type: ignore[no-untyped-def]
        *,
        data_dir,
        policy_path,
        authority_claim,
        assistant_fs_roots,
        startup_timeout_seconds,
    ):
        _ = (
            data_dir,
            policy_path,
            authority_claim,
            assistant_fs_roots,
            startup_timeout_seconds,
        )
        return _FakeSidecar()

    monkeypatch.setattr("shisad.daemon.services.start_control_plane_sidecar", _fake_start)
    monkeypatch.setattr(
        "shisad.daemon.services._build_tool_registry",
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
async def test_daemon_services_threads_control_plane_startup_timeout(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear_remote_provider_env(monkeypatch)
    captured: dict[str, object] = {}

    class _FakeSidecar:
        def __init__(self) -> None:
            self.client = SimpleNamespace(ping=self._ping)
            self.process = SimpleNamespace(returncode=None)
            self.socket_path = tmp_path / "data" / "control_plane" / "fake.sock"

        async def _ping(self) -> bool:
            return True

        async def close(self) -> None:
            claim = captured["authority_claim"]
            captured["claim_released_during_sidecar_close"] = claim.released

    async def _fake_start(  # type: ignore[no-untyped-def]
        *,
        data_dir,
        policy_path,
        assistant_fs_roots,
        startup_timeout_seconds,
        authority_claim,
    ):
        _ = (data_dir, policy_path, assistant_fs_roots)
        captured["startup_timeout_seconds"] = float(startup_timeout_seconds)
        captured["authority_claim"] = authority_claim
        return _FakeSidecar()

    monkeypatch.setattr("shisad.daemon.services.start_control_plane_sidecar", _fake_start)
    config = DaemonConfig(
        data_dir=tmp_path / "data",
        socket_path=tmp_path / "control.sock",
        policy_path=tmp_path / "policy.yaml",
        control_plane_startup_timeout_seconds=12.5,
    )
    services = await DaemonServices.build(config)
    try:
        assert captured["startup_timeout_seconds"] == pytest.approx(12.5)
        assert captured["authority_claim"] is services.authority_claim
    finally:
        await services.shutdown()
    assert captured["claim_released_during_sidecar_close"] is False
    assert services.authority_claim.released is True


@pytest.mark.asyncio
async def test_daemon_services_uses_default_control_plane_startup_timeout(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear_remote_provider_env(monkeypatch)
    captured: dict[str, float] = {}

    class _FakeSidecar:
        def __init__(self) -> None:
            self.client = SimpleNamespace(ping=self._ping)
            self.process = SimpleNamespace(returncode=None)
            self.socket_path = tmp_path / "data" / "control_plane" / "fake.sock"

        async def _ping(self) -> bool:
            return True

        async def close(self) -> None:
            return None

    async def _fake_start(  # type: ignore[no-untyped-def]
        *,
        data_dir,
        policy_path,
        authority_claim,
        assistant_fs_roots,
        startup_timeout_seconds,
    ):
        _ = (data_dir, policy_path, authority_claim, assistant_fs_roots)
        captured["startup_timeout_seconds"] = float(startup_timeout_seconds)
        return _FakeSidecar()

    monkeypatch.setattr("shisad.daemon.services.start_control_plane_sidecar", _fake_start)
    config = DaemonConfig(
        data_dir=tmp_path / "data",
        socket_path=tmp_path / "control.sock",
        policy_path=tmp_path / "policy.yaml",
    )
    services = await DaemonServices.build(config)
    try:
        assert captured["startup_timeout_seconds"] == pytest.approx(15.0)
    finally:
        await services.shutdown()


@pytest.mark.asyncio
async def test_daemon_services_reset_test_state_clears_documented_subsystems(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear_remote_provider_env(monkeypatch)
    config = DaemonConfig(
        data_dir=tmp_path / "data",
        socket_path=tmp_path / "control.sock",
        policy_path=tmp_path / "policy.yaml",
        trace_enabled=True,
        test_mode=True,
        channel_identity_allowlist={"matrix": ["trusted-alice"]},
    )
    services = await DaemonServices.build(config)
    try:
        static_credential = CredentialRef("static-route-test")
        services.credential_store.register(
            static_credential,
            "super-secret",
            CredentialConfig(allowed_hosts=["example.com"]),
        )
        event_handler_count = sum(
            len(items) for items in services.event_bus._handlers.values()
        ) + len(services.event_bus._global_handlers)

        session = services.session_manager.create(
            channel="cli",
            user_id=UserId("alice"),
            workspace_id=WorkspaceId("ws1"),
        )
        task = services.scheduler.create_task(
            name="daily-summary",
            goal="summarize updates",
            schedule=Schedule.from_event("message.received"),
            capability_snapshot={Capability.MESSAGE_SEND},
            policy_snapshot_ref="policy-1",
            created_by=UserId("alice"),
            workspace_id=WorkspaceId("ws1"),
        )
        services.scheduler.queue_confirmation(
            task.id,
            {"confirmation_id": "sched-pending-1", "status": "pending"},
        )

        decision = services.memory_manager.write(
            entry_type="note",
            key="note-1",
            value="remember this",
            source=MemorySource(
                origin="user",
                source_id=str(session.id),
                extraction_method="note.create",
            ),
            user_confirmed=True,
        )
        assert decision.kind == "allow"
        assert decision.entry is not None

        services.lockdown_manager.set_level(
            session.id,
            level=LockdownLevel.CAUTION,
            reason="unit-test",
        )
        services.rate_limiter.consume(
            session_id=str(session.id),
            user_id="alice",
            tool_name="note.create",
        )
        services.checkpoint_store.create(session)
        services.channel_state_store.mark_seen(channel="matrix", message_id="msg-1")
        services.evidence_store.store(
            session.id,
            "evidence payload",
            taint_labels=set(),
            source="unit-test",
            summary="evidence summary",
        )
        services.ingestion.ingest(
            source_id="source-1",
            source_type="tool",
            content="retrieval payload",
        )

        inventory_type = services.selfmod_manager._inventory.__class__
        services.selfmod_manager._inventory = inventory_type.model_validate(
            {
                "skills": {"demo": {"enabled": True, "active_version": "1.0.0"}},
                "behavior_packs": {"persona": {"enabled": True, "active_version": "2.0.0"}},
            }
        )
        services.selfmod_manager._persist_inventory()
        (services.selfmod_manager._proposal_dir / "proposal.json").write_text(
            "{}",
            encoding="utf-8",
        )
        (services.selfmod_manager._change_dir / "change.json").write_text(
            "{}",
            encoding="utf-8",
        )
        (services.selfmod_manager._artifact_root / "artifact.txt").write_text(
            "artifact",
            encoding="utf-8",
        )
        services.selfmod_manager._incident_path.write_text(
            '{"reason": "unit-test"}',
            encoding="utf-8",
        )

        services.skill_manager._inventory["demo"] = InstalledSkill(
            name="demo",
            version="1.0.0",
            path=str(tmp_path / "demo-skill"),
            manifest_hash="abc123",
            state=ArtifactState.PUBLISHED,
            author="unit-test",
            tool_schema_hashes={},
        )
        services.skill_manager._skill_tool_map["demo"] = [ToolName("demo.tool")]
        services.skill_manager._pending_registration_events.append(object())  # type: ignore[arg-type]
        services.skill_manager._persist_inventory_snapshot(
            services.skill_manager._inventory
        )

        services.credential_store.register_approval_factor(
            ApprovalFactorRecord(
                credential_id="totp-1",
                user_id="alice",
                method="totp",
                principal_id="alice",
                secret_b32="JBSWY3DPEHPK3PXP",
            )
        )
        services.credential_store.register_signer_key(
            SignerKeyRecord(
                credential_id="signer-1",
                user_id="alice",
                backend="kms",
                principal_id="alice",
                algorithm="ed25519",
                device_type="ledger-enterprise",
                public_key_pem="-----BEGIN PUBLIC KEY-----\nQUFB\n-----END PUBLIC KEY-----",
            )
        )
        assert services.credential_store.get_or_create_local_fido2_realm_id(seed="realm") == "realm"

        services.identity_map.configure_channel_trust(channel="matrix", trust_level="trusted")
        services.identity_map.allow_identity(channel="matrix", external_user_id="extra-user")
        services.identity_map.bind(
            channel="matrix",
            external_user_id="extra-user",
            user_id=UserId("extra"),
            workspace_id=WorkspaceId("ws-extra"),
        )
        services.identity_map.record_pairing_request(
            channel="matrix",
            external_user_id="pending-user",
            workspace_hint="!room:example.org",
        )

        services.transcript_store.append(
            session.id,
            role="user",
            content="x" * 5000,
        )
        services.transcript_store.append(
            session.id,
            role="user",
            content="Timeline reset marker should not survive daemon reset.",
            timestamp=datetime(2026, 5, 8, 12, 0, tzinfo=UTC),
        )
        assert (
            services.timeline_index.search(
                query="timeline reset marker",
                user_id="alice",
                workspace_id="ws1",
                context_channel="cli",
            ).results_count
            == 1
        )
        assert services.trace_recorder is not None
        services.trace_recorder.record(
            TraceTurn(
                session_id=str(session.id),
                user_content="trace me",
            )
        )
        await services.audit_log.persist(
            SessionCreated(
                session_id=session.id,
                actor="unit-test",
                user_id=UserId("alice"),
                workspace_id="ws1",
            )
        )
        archive_dir = config.data_dir / "session_archives"
        archive_dir.mkdir(parents=True, exist_ok=True)
        (archive_dir / "archive.zip").write_text("archive", encoding="utf-8")

        services.risk_calibrator.record(
            RiskObservation(
                session_id=str(session.id),
                user_id="alice",
                tool_name="note.create",
                outcome="allowed",
                risk_score=0.4,
            )
        )
        services.risk_calibrator.save_policy(RiskPolicyVersion(version="v99"))

        result = await services.reset_test_state()

        assert result["status"] == "reset"
        assert result["cleared"]["sessions"] == 1
        assert result["cleared"]["scheduler_tasks"] == 1
        assert result["cleared"]["scheduler_pending_confirmations"] == 1
        assert result["cleared"]["memory_entries"] == 1
        assert result["cleared"]["lockdown_states"] == 1
        assert result["cleared"]["rate_limiter_windows"] >= 4
        assert result["cleared"]["audit_entries"] >= 1
        assert result["cleared"]["checkpoints"] == 1
        assert result["cleared"]["channel_state_files"] == 1
        assert result["cleared"]["channel_state_channels"] == 1
        assert result["cleared"]["evidence_refs"] == 1
        assert result["cleared"]["ingestion_records"] == 1
        assert result["cleared"]["selfmod_entries"] == 2
        assert result["cleared"]["skill_entries"] == 1
        assert result["cleared"]["approval_factors"] == 1
        assert result["cleared"]["signer_keys"] == 1
        assert result["cleared"]["identity_bindings"] == 1
        assert result["cleared"]["identity_pairing_requests"] == 1
        assert result["cleared"]["transcripts"] >= 2
        assert result["cleared"]["timeline_rows"] >= 1
        assert result["cleared"]["trace_files"] == 1
        assert result["cleared"]["session_archives"] == 1
        assert result["cleared"]["risk_observations"] == 1
        assert result["cleared"]["risk_policies"] == 1

        assert services.session_manager.list_active() == []
        assert services.scheduler.list_tasks() == []
        assert services.scheduler.pending_confirmations(task.id) == []
        assert services.memory_manager.list_entries(limit=10) == []
        assert services.lockdown_manager._states == {}
        assert services.rate_limiter._by_tool == {}
        assert services.rate_limiter._by_user == {}
        assert services.rate_limiter._by_session == {}
        assert services.rate_limiter._by_tool_burst == {}
        assert services.audit_log.entry_count == 0
        assert list(services.checkpoint_store._dir.iterdir()) == []
        assert services.channel_state_store.snapshot("matrix")["seen_count"] == 0
        assert (
            services.timeline_index.search(
                query="timeline reset marker",
                user_id="alice",
                workspace_id="ws1",
                context_channel="cli",
            ).results
            == []
        )
        assert services.evidence_store.is_empty_domain() is True
        assert services.evidence_store.state_load_result().status.value == "ok"
        reset_restarted_evidence = ArtifactLedger(
            config.data_dir / "sessions" / "evidence"
        )
        assert reset_restarted_evidence.state_load_result().status.value == "ok"
        assert reset_restarted_evidence.committed_ref_count() == 0
        assert services.ingestion.artifacts_empty()
        assert services.ingestion.search_index_count() == 0
        assert services.ingestion._active_key_id
        assert services.selfmod_manager._inventory.skills == {}
        assert services.selfmod_manager._inventory.behavior_packs == {}
        assert services.skill_manager.list_installed() == []
        assert services.skill_manager._skill_tool_map == {}
        assert services.credential_store.has_credential(static_credential) is True
        assert services.credential_store.list_approval_factors() == []
        assert services.credential_store.list_signer_keys(include_revoked=True) == []
        assert services.identity_map.is_allowed(channel="matrix", external_user_id="trusted-alice")
        assert not services.identity_map.is_allowed(channel="matrix", external_user_id="extra-user")
        assert (
            services.identity_map.resolve(channel="matrix", external_user_id="extra-user") is None
        )
        assert services.identity_map.trust_for_channel("matrix") == "untrusted"
        assert services.transcript_store.list_entries(session.id) == []
        assert services.trace_recorder.read_turns(str(session.id)) == []
        assert not any(archive_dir.iterdir())
        assert not services.risk_calibrator.observations_path.exists()
        assert not services.risk_calibrator.policy_path.exists()
        post_reset_handler_count = sum(
            len(items) for items in services.event_bus._handlers.values()
        ) + len(services.event_bus._global_handlers)
        assert post_reset_handler_count == event_handler_count

        second_ingest = services.ingestion.ingest(
            source_id="source-2",
            source_type="tool",
            content="fresh payload",
        )
        assert second_ingest.chunk_id
    finally:
        await services.shutdown()


@pytest.mark.asyncio
async def test_gh57_daemon_reset_preserves_memory_surfaces_when_ingestion_reset_fails(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear_remote_provider_env(monkeypatch)
    config = DaemonConfig(
        data_dir=tmp_path / "data",
        socket_path=tmp_path / "control.sock",
        policy_path=tmp_path / "policy.yaml",
        test_mode=True,
    )
    services = await DaemonServices.build(config)
    try:
        decision = services.memory_manager.write(
            entry_type="note",
            key="gh57.daemon.reset",
            value="daemon reset should preserve memory on ingestion failure",
            source=MemorySource(
                origin="user",
                source_id="gh57-daemon-reset",
                extraction_method="note.create",
            ),
            user_confirmed=True,
        )
        assert decision.entry is not None
        legacy_memory_path = services.memory_manager._storage_dir / "gh57-daemon-legacy.json"
        legacy_memory_path.write_text(decision.entry.model_dump_json(), encoding="utf-8")
        stored = services.ingestion.ingest(
            source_id="doc-gh57-daemon-reset",
            source_type="external",
            content="Daemon reset should preserve retrieval on ingestion failure.",
        )

        def _fail_ingestion_reset() -> None:
            raise sqlite3.OperationalError("simulated ingestion reset failure")

        monkeypatch.setattr(services.ingestion, "reset_storage", _fail_ingestion_reset)

        with pytest.raises(sqlite3.OperationalError, match="simulated ingestion reset"):
            await services.reset_test_state()

        assert services.memory_manager.get_entry(decision.entry.id) is not None
        assert services.memory_manager.count_events(entry_id=decision.entry.id) > 0
        assert legacy_memory_path.exists()
        assert not services.ingestion.artifacts_empty()
        original = services.ingestion.read_original(stored.chunk_id)
        assert original is not None
        assert "preserve retrieval" in original
    finally:
        await services.shutdown()


@pytest.mark.asyncio
async def test_gh57_daemon_reset_preserves_memory_surfaces_when_memory_reset_fails(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear_remote_provider_env(monkeypatch)
    config = DaemonConfig(
        data_dir=tmp_path / "data",
        socket_path=tmp_path / "control.sock",
        policy_path=tmp_path / "policy.yaml",
        test_mode=True,
    )
    services = await DaemonServices.build(config)
    try:
        decision = services.memory_manager.write(
            entry_type="note",
            key="gh57.daemon.memory.reset",
            value="daemon reset should roll back memory reset failure",
            source=MemorySource(
                origin="user",
                source_id="gh57-daemon-memory-reset",
                extraction_method="note.create",
            ),
            user_confirmed=True,
        )
        assert decision.entry is not None
        stored = services.ingestion.ingest(
            source_id="doc-gh57-daemon-memory-reset",
            source_type="external",
            content="Daemon reset should preserve retrieval on memory failure.",
        )
        original_reset = services.memory_manager.reset_storage

        def _fail_after_memory_reset() -> None:
            original_reset()
            raise sqlite3.OperationalError("simulated memory reset failure")

        monkeypatch.setattr(services.memory_manager, "reset_storage", _fail_after_memory_reset)

        with pytest.raises(sqlite3.OperationalError, match="simulated memory reset"):
            await services.reset_test_state()

        assert services.memory_manager.get_entry(decision.entry.id) is not None
        assert services.memory_manager.count_events(entry_id=decision.entry.id) > 0
        assert not services.ingestion.artifacts_empty()
        original = services.ingestion.read_original(stored.chunk_id)
        assert original is not None
        assert "preserve retrieval" in original
    finally:
        await services.shutdown()


@pytest.mark.asyncio
async def test_m8_daemon_trace_policy_does_not_persist_tool_arguments(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear_remote_provider_env(monkeypatch)
    config = DaemonConfig(
        data_dir=tmp_path / "data",
        socket_path=tmp_path / "control.sock",
        policy_path=tmp_path / "policy.yaml",
        trace_enabled=True,
    )
    services = await DaemonServices.build(config)
    try:
        assert services.trace_recorder is not None
        services.trace_recorder.record(
            TraceTurn(
                session_id="sess-m8-trace-policy",
                messages_sent=[
                    TraceMessage(
                        role="assistant",
                        tool_calls=[
                            {
                                "name": "shell.exec",
                                "arguments": {"command": "cat private.txt"},
                            }
                        ],
                    )
                ],
                tool_calls=[
                    TraceToolCall(
                        tool_name="shell.exec",
                        arguments={"command": "cat private.txt"},
                    )
                ],
            )
        )
        turns = services.trace_recorder.read_turns("sess-m8-trace-policy")
    finally:
        await services.shutdown()

    assert len(turns) == 1
    assert turns[0].messages_sent[0].tool_calls[0]["arguments"] == {}
    assert turns[0].tool_calls[0].arguments == {}


@pytest.mark.asyncio
async def test_daemon_services_reset_test_state_requires_explicit_test_mode(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear_remote_provider_env(monkeypatch)
    config = DaemonConfig(
        data_dir=tmp_path / "data",
        socket_path=tmp_path / "control.sock",
        policy_path=tmp_path / "policy.yaml",
        test_mode=False,
    )
    services = await DaemonServices.build(config)
    try:
        with pytest.raises(RuntimeError, match="outside explicit test mode"):
            await services.reset_test_state()
    finally:
        await services.shutdown()


@pytest.mark.asyncio
async def test_handler_daemon_reset_clears_handler_state_and_marks_non_quiescent_reset(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear_remote_provider_env(monkeypatch)
    config = DaemonConfig(
        data_dir=tmp_path / "data",
        socket_path=tmp_path / "control.sock",
        policy_path=tmp_path / "policy.yaml",
        test_mode=True,
    )
    services = await DaemonServices.build(config)
    impl = HandlerImplementation(services=services)
    try:
        session = services.session_manager.create(
            channel="cli",
            user_id=UserId("alice"),
            workspace_id=WorkspaceId("ws1"),
        )
        task = services.scheduler.create_task(
            name="approval-task",
            goal="needs confirmation",
            schedule=Schedule.from_event("message.received"),
            capability_snapshot={Capability.MESSAGE_SEND},
            policy_snapshot_ref="policy-1",
            created_by=UserId("alice"),
            workspace_id=WorkspaceId("ws1"),
        )
        services.scheduler.queue_confirmation(
            task.id,
            {"confirmation_id": "task-confirm-1", "status": "pending"},
        )

        started = await impl.do_two_factor_register_begin(
            {"method": "totp", "user_id": "alice", "name": "ops-laptop"}
        )
        enrollment_id = str(started["enrollment_id"])
        assert enrollment_id

        pending = PendingAction(
            confirmation_id="confirm-1",
            decision_nonce="nonce-1",
            session_id=SessionId(str(session.id)),
            user_id=UserId("alice"),
            workspace_id=WorkspaceId("ws1"),
            tool_name=ToolName("note.create"),
            arguments={"key": "reset"},
            reason="unit-test",
            capabilities={Capability.MEMORY_WRITE},
            created_at=datetime.now(UTC),
        )
        impl._pending_actions[pending.confirmation_id] = pending
        impl._pending_by_session[session.id] = [pending.confirmation_id]
        impl._persist_pending_actions()
        impl._monitor_reject_counts[session.id] = 2
        impl._plan_violation_counts[session.id] = 3
        impl._confirmation_alerted_at[pending.confirmation_id] = datetime.now(UTC)
        impl._confirmation_failure_tracker.record_failure(user_id="alice", method="totp")
        impl._identity_map.record_pairing_request(
            channel="matrix",
            external_user_id="mallory",
            workspace_hint="!room:example.org",
        )
        impl._record_pairing_request_artifact(
            channel="matrix",
            external_user_id="mallory",
            workspace_hint="!room:example.org",
            reason="identity_not_allowlisted",
        )

        result = await impl.do_daemon_reset({})

        assert result["status"] == "reset"
        assert result["quiescent"] is False
        assert all(result["invariants"].values())
        assert result["cleared"]["scheduler_pending_confirmations"] == 1
        assert result["cleared"]["pending_actions"] == 1
        assert result["cleared"]["pending_action_sessions"] == 1
        assert result["cleared"]["pending_two_factor_enrollments"] == 1
        assert result["cleared"]["monitor_reject_counts"] == 1
        assert result["cleared"]["plan_violation_counts"] == 1
        assert result["cleared"]["confirmation_alerts"] == 1
        assert result["cleared"]["confirmation_lockouts"] == 1
        assert result["cleared"]["pairing_requests"] == 1
        assert result["cleared"]["pairing_request_artifacts"] == 1

        assert impl._pending_actions == {}
        assert impl._pending_by_session == {}
        assert impl._pending_two_factor_enrollments == {}
        assert impl._monitor_reject_counts == {}
        assert impl._plan_violation_counts == {}
        assert impl._confirmation_alerted_at == {}
        assert impl._confirmation_failure_tracker._state == {}
        assert impl._identity_map.list_pairing_requests() == []
        assert not impl._pending_actions_file.exists()
        assert not impl._pairing_requests_file.exists()
    finally:
        await services.shutdown()


@pytest.mark.asyncio
async def test_f3_daemon_reset_route_keeps_event_loop_live_behind_ledger_writer(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear_remote_provider_env(monkeypatch)
    config = DaemonConfig(
        data_dir=tmp_path / "data",
        socket_path=tmp_path / "control.sock",
        policy_path=tmp_path / "policy.yaml",
        test_mode=True,
    )
    services = await DaemonServices.build(config)
    impl = HandlerImplementation(services=services)
    ledger = services.evidence_store
    ledger.store(
        SessionId("sess-a"),
        "reset me",
        taint_labels=set(),
        source="unit-test",
        summary="reset me",
    )
    lock_held = Event()
    release_writer = Event()
    holder_timed_out = Event()

    def _hold_writer() -> None:
        with ledger._lock:
            lock_held.set()
            if not release_writer.wait(timeout=3.0):
                holder_timed_out.set()

    holder = Thread(target=_hold_writer)
    holder.start()
    try:
        assert await asyncio.to_thread(lock_held.wait, 1.0)
        heartbeat_ticks = 0

        async def _heartbeat() -> None:
            nonlocal heartbeat_ticks
            for _ in range(5):
                heartbeat_ticks += 1
                await asyncio.sleep(0)
            release_writer.set()

        heartbeat = asyncio.create_task(_heartbeat())
        result = await impl.do_daemon_reset({})
        await heartbeat
        await asyncio.to_thread(holder.join, 1.0)

        assert holder_timed_out.is_set() is False
        assert heartbeat_ticks == 5
        assert result["status"] == "reset"
        assert result["cleared"]["evidence_refs"] == 1
        assert all(result["invariants"].values())
    finally:
        release_writer.set()
        holder.join(timeout=1.0)
        await services.shutdown()


@pytest.mark.asyncio
async def test_f3_channel_doctor_keeps_event_loop_live_behind_replay_writer(
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
    impl = HandlerImplementation(services=services)
    store = services.channel_state_store
    lock_held = Event()
    release_writer = Event()
    holder_timed_out = Event()

    def _hold_writer() -> None:
        with store._lock:
            lock_held.set()
            if not release_writer.wait(timeout=2.0):
                holder_timed_out.set()

    holder = Thread(target=_hold_writer)
    holder.start()
    try:
        assert await asyncio.to_thread(lock_held.wait, 1.0)
        heartbeat_ticks = 0

        async def _heartbeat() -> None:
            nonlocal heartbeat_ticks
            for _ in range(5):
                heartbeat_ticks += 1
                await asyncio.sleep(0)
            release_writer.set()

        heartbeat = asyncio.create_task(_heartbeat())
        result = await impl.do_doctor_check({"component": "channels"})
        await heartbeat
        await asyncio.to_thread(holder.join, 1.0)

        assert holder_timed_out.is_set() is False
        assert heartbeat_ticks == 5
        assert result["status"] == "ok"
    finally:
        release_writer.set()
        holder.join(timeout=1.0)
        await services.shutdown()


@pytest.mark.asyncio
async def test_f3_daemon_reset_keeps_event_loop_live_behind_replay_writer(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear_remote_provider_env(monkeypatch)
    config = DaemonConfig(
        data_dir=tmp_path / "data",
        socket_path=tmp_path / "control.sock",
        policy_path=tmp_path / "policy.yaml",
        test_mode=True,
    )
    services = await DaemonServices.build(config)
    impl = HandlerImplementation(services=services)
    store = services.channel_state_store
    store.mark_seen(channel="discord", message_id="m-reset")
    lock_held = Event()
    release_writer = Event()
    holder_timed_out = Event()

    def _hold_writer() -> None:
        with store._lock:
            lock_held.set()
            if not release_writer.wait(timeout=2.0):
                holder_timed_out.set()

    holder = Thread(target=_hold_writer)
    holder.start()
    try:
        assert await asyncio.to_thread(lock_held.wait, 1.0)
        heartbeat_ticks = 0

        async def _heartbeat() -> None:
            nonlocal heartbeat_ticks
            for _ in range(5):
                heartbeat_ticks += 1
                await asyncio.sleep(0)
            release_writer.set()

        heartbeat = asyncio.create_task(_heartbeat())
        result = await impl.do_daemon_reset({})
        await heartbeat
        await asyncio.to_thread(holder.join, 1.0)

        assert holder_timed_out.is_set() is False
        assert heartbeat_ticks == 5
        assert result["status"] == "reset"
        assert result["cleared"]["channel_state_channels"] == 1
        assert result["cleared"]["channel_state_files"] >= 1
        assert all(result["invariants"].values())
    finally:
        release_writer.set()
        holder.join(timeout=1.0)
        await services.shutdown()


@pytest.mark.asyncio
async def test_handler_daemon_reset_rejects_concurrent_reset_attempts(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear_remote_provider_env(monkeypatch)
    config = DaemonConfig(
        data_dir=tmp_path / "data",
        socket_path=tmp_path / "control.sock",
        policy_path=tmp_path / "policy.yaml",
        test_mode=True,
    )
    services = await DaemonServices.build(config)
    impl = HandlerImplementation(services=services)
    try:
        services.reset_in_progress = True
        with pytest.raises(RuntimeError, match="already in progress"):
            await impl.do_daemon_reset({})
    finally:
        services.reset_in_progress = False
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

    # HDL-M1: construct a minimal DaemonServices via object.__new__ so this
    # test can pin the shutdown ordering (embeddings → matrix → server) and
    # the continue-past-disconnect-error invariant without standing up the
    # full services container. If DaemonServices.shutdown starts touching a
    # new attribute this test will raise AttributeError inside the call below
    # — that is the intended drift signal. A deeper cleanup would split
    # shutdown logic into a pure function; tracked as a follow-up.
    services = object.__new__(DaemonServices)
    services.embeddings_adapter = _EmbeddingsAdapterStub()  # type: ignore[assignment]
    services.matrix_channel = _MatrixStub()  # type: ignore[assignment]
    services.server = _ServerStub()  # type: ignore[assignment]

    await DaemonServices.shutdown(services)
    assert calls[0] == "embed:True"
    assert "matrix" in calls
    assert calls[-1] == "server"


@pytest.mark.asyncio
async def test_daemon_services_shutdown_reaches_all_registered_resources() -> None:
    # HDL-L1: the prior test covered only embeddings → matrix → server.
    # Real shutdown also runs a2a_runtime.close(), any-channel.disconnect()
    # (through both the `channels` dict and per-platform attributes),
    # `control_plane_sidecar.close()`, and `approval_web.stop()`. This
    # companion exercises every documented shutdown branch and pins that
    # a single resource erroring out (here: discord.disconnect) does not
    # stop the remaining resources from being closed.
    calls: list[str] = []

    class _EmbeddingsAdapterStub:
        def close(self, *, wait: bool = True) -> None:
            calls.append(f"embed:{wait}")

    class _A2ARuntimeStub:
        async def close(self) -> None:
            calls.append("a2a")

    class _DictChannelStub:
        async def disconnect(self) -> None:
            calls.append("channels-dict:x")

    class _MatrixStub:
        async def disconnect(self) -> None:
            calls.append("matrix")

    class _DiscordStub:
        async def disconnect(self) -> None:
            calls.append("discord")
            raise RuntimeError("discord closed unexpectedly")

    class _TelegramStub:
        async def disconnect(self) -> None:
            calls.append("telegram")

    class _SlackStub:
        async def disconnect(self) -> None:
            calls.append("slack")

    class _SidecarStub:
        async def close(self) -> None:
            calls.append("sidecar")

    class _ApprovalWebStub:
        async def stop(self) -> None:
            calls.append("approval-web")

    class _ServerStub:
        async def stop(self) -> None:
            calls.append("server")

    services = object.__new__(DaemonServices)
    services.embeddings_adapter = _EmbeddingsAdapterStub()  # type: ignore[assignment]
    services.a2a_runtime = _A2ARuntimeStub()  # type: ignore[assignment]
    services.channels = {"x": _DictChannelStub()}  # type: ignore[assignment]
    services.matrix_channel = _MatrixStub()  # type: ignore[assignment]
    services.discord_channel = _DiscordStub()  # type: ignore[assignment]
    services.telegram_channel = _TelegramStub()  # type: ignore[assignment]
    services.slack_channel = _SlackStub()  # type: ignore[assignment]
    services.control_plane_sidecar = _SidecarStub()  # type: ignore[assignment]
    services.approval_web = _ApprovalWebStub()  # type: ignore[assignment]
    services.server = _ServerStub()  # type: ignore[assignment]

    await DaemonServices.shutdown(services)

    assert calls[0] == "embed:True", "embeddings adapter must close first (sync path)"
    assert "a2a" in calls
    assert "channels-dict:x" in calls
    # All four per-platform channels must be disconnected even though
    # discord raised an exception.
    for label in ("matrix", "discord", "telegram", "slack"):
        assert label in calls, f"{label} channel must be disconnected"
    assert "sidecar" in calls
    assert "approval-web" in calls
    assert calls[-1] == "server", "control server must be the last resource to stop"


def test_m3_normalize_tool_destination_preserves_scheme_and_port() -> None:
    assert _normalize_tool_destination("https://search.example") == "https://search.example:443"
    assert (
        _normalize_tool_destination("http://search.example:8080/api?q=1")
        == "http://search.example:8080"
    )
    assert _normalize_tool_destination("search.example") == "search.example"


def test_m6_normalize_tool_destination_rejects_invalid_port() -> None:
    assert _normalize_tool_destination("https://search.example:99999") == ""


def test_evidence_kms_bearer_over_non_loopback_http_logs_warning(
    tmp_path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = DaemonConfig(
        data_dir=tmp_path / "data",
        socket_path=tmp_path / "control.sock",
        policy_path=tmp_path / "policy.yaml",
        evidence_kms_url="http://10.0.0.5:8080/artifacts",
        evidence_kms_bearer_token="secret",
    )

    with caplog.at_level("WARNING"):
        _warn_on_evidence_kms_endpoint_config(config)

    assert "without TLS protection" in caplog.text


def test_evidence_kms_invalid_url_logs_warning(
    tmp_path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = DaemonConfig(
        data_dir=tmp_path / "data",
        socket_path=tmp_path / "control.sock",
        policy_path=tmp_path / "policy.yaml",
        evidence_kms_url="not-a-url",
    )

    with caplog.at_level("WARNING"):
        _warn_on_evidence_kms_endpoint_config(config)

    assert "may be misconfigured" in caplog.text


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


def test_gh12_tool_registry_steers_file_discovery_to_structured_fs_tools() -> None:
    registry, _alarm = _build_tool_registry(
        EventBus(),
        realitycheck_surface_enabled=False,
    )
    fs_list = registry.get_tool(ToolName("fs.list"))
    fs_read = registry.get_tool(ToolName("fs.read"))
    shell_exec = registry.get_tool(ToolName("shell.exec"))

    assert fs_list is not None
    assert fs_read is not None
    assert shell_exec is not None

    fs_list_description = fs_list.planner_description().lower()
    fs_read_description = fs_read.planner_description().lower()
    shell_description = shell_exec.planner_description().lower()
    assert "similar" in fs_list_description
    assert "prefer" in fs_list_description
    assert "fs.list" in fs_read_description
    assert "do not use" in shell_description
    assert "file discovery" in shell_description
    assert "fs.list" in shell_description
    assert "fs.read" in shell_description


def test_gh60_tool_registry_exposes_time_now_without_shell_capability() -> None:
    registry, _alarm = _build_tool_registry(
        EventBus(),
        realitycheck_surface_enabled=False,
    )

    time_now = registry.get_tool(ToolName("time.now"))

    assert time_now is not None
    assert time_now.capabilities_required == []
    assert time_now.require_confirmation is False
    description = time_now.planner_description().lower()
    assert "current date" in description
    assert "current time" in description
    assert "shell.exec" in description
    schema = time_now.json_schema()
    assert schema["required"] == []
    assert "timezone" in schema["properties"]


def test_gh49_reminder_create_schema_hides_current_turn_intent() -> None:
    registry, _alarm = _build_tool_registry(
        EventBus(),
        realitycheck_surface_enabled=False,
    )

    reminder_create = registry.get_tool(ToolName("reminder.create"))

    assert reminder_create is not None
    schema = reminder_create.json_schema()
    assert "reminder_intent" not in schema["required"]
    assert "reminder_intent" not in schema["properties"]


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


def test_daemon_config_canonicalizes_default_port_approval_origin(tmp_path) -> None:
    config = DaemonConfig(
        data_dir=tmp_path / "data",
        socket_path=tmp_path / "control.sock",
        policy_path=tmp_path / "policy.yaml",
        approval_origin="https://approve.example.com:443",
    )

    assert config.approval_origin == "https://approve.example.com"
    assert config.approval_rp_id == "approve.example.com"
    assert config.approval_bind_host == "127.0.0.1"


def test_daemon_config_preserves_ipv6_loopback_approval_origin(tmp_path) -> None:
    config = DaemonConfig(
        data_dir=tmp_path / "data",
        socket_path=tmp_path / "control.sock",
        policy_path=tmp_path / "policy.yaml",
        approval_origin="http://[::1]:8787",
    )

    assert config.approval_origin == "http://[::1]:8787"
    assert config.approval_rp_id == "::1"
    assert config.approval_bind_host == "::1"
    assert config.approval_bind_port == 8787


def test_gh47_browser_runtime_note_uses_specific_remediation() -> None:
    note = _browser_runtime_unavailable_planner_note(
        {
            "enabled": True,
            "status": "misconfigured",
            "problems": ["browser_runtime_isolation_unavailable"],
            "protocol": {"supported": False, "probe": "", "reason": ""},
        }
    )

    assert "browser_runtime_isolation_unavailable" in note
    assert "browser sandbox/isolation settings" in note
    assert "SHISAD_BROWSER_COMMAND" not in note


def test_gh47_browser_runtime_note_keeps_mixed_remediation_paths() -> None:
    note = _browser_runtime_unavailable_planner_note(
        {
            "enabled": True,
            "status": "misconfigured",
            "problems": [
                "browser_hardened_wildcard_scope_unsupported",
                "browser_command_unconfigured",
            ],
            "protocol": {"supported": False, "probe": "", "reason": ""},
        }
    )

    assert "browser_hardened_wildcard_scope_unsupported" in note
    assert "browser_command_unconfigured" in note
    assert "SHISAD_BROWSER_COMMAND" in note
    assert "browser sandbox/isolation settings" in note


def test_gh44_browser_runtime_note_names_node_version_requirement() -> None:
    note = _browser_runtime_unavailable_planner_note(
        {
            "enabled": True,
            "status": "misconfigured",
            "problems": ["browser_node_version_too_old"],
            "protocol": {
                "supported": False,
                "probe": "sentinel,readiness",
                "reason": "browser_node_version_too_old",
            },
        }
    )

    assert "browser_node_version_too_old" in note
    assert "Node.js 22" in note
    assert "web.search/web.fetch" in note


async def _build_browser_registry_services(config: DaemonConfig) -> DaemonServices:
    return await DaemonServices.build(config)


@pytest.mark.asyncio
async def test_m6_daemon_services_browser_registry_falls_back_to_web_allowlist(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear_remote_provider_env(monkeypatch)
    wrapper = tmp_path / "shisad-browser-wrapper"
    _write_browser_wrapper(wrapper)
    config = DaemonConfig(
        data_dir=tmp_path / "data",
        socket_path=tmp_path / "control.sock",
        policy_path=tmp_path / "policy.yaml",
        browser_enabled=True,
        browser_command=str(wrapper),
        browser_require_hardened_isolation=False,
        web_allowed_domains=["localhost"],
        browser_allowed_domains=[],
    )
    services = await _build_browser_registry_services(config)
    try:
        assert services.browser_status["status"] == "ok"
        navigate_tool = services.registry.get_tool(ToolName("browser.navigate"))
        assert navigate_tool is not None
        assert navigate_tool.destinations == ["localhost"]
    finally:
        await services.shutdown()


@pytest.mark.asyncio
async def test_gh47_browser_health_uses_policy_egress_fallback_scope(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear_remote_provider_env(monkeypatch)
    wrapper = tmp_path / "shisad-browser-wrapper"
    _write_browser_wrapper(wrapper)
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        'egress:\n  - host: "*.browser.example"\n',
        encoding="utf-8",
    )
    config = DaemonConfig(
        data_dir=tmp_path / "data",
        socket_path=tmp_path / "control.sock",
        policy_path=policy_path,
        browser_enabled=True,
        browser_command=str(wrapper),
        browser_require_hardened_isolation=True,
        web_allowed_domains=[],
        browser_allowed_domains=[],
    )
    services = await _build_browser_registry_services(config)
    try:
        assert services.browser_status["status"] == "misconfigured"
        assert "*.browser.example" in services.browser_status["allowed_domains"]
        assert "browser_hardened_wildcard_scope_unsupported" in services.browser_status["problems"]
        assert services.registry.get_tool(ToolName("browser.navigate")) is None
    finally:
        await services.shutdown()


@pytest.mark.asyncio
async def test_gh52_web_toolkit_uses_policy_egress_fallback_scope(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear_remote_provider_env(monkeypatch)
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        "egress:\n  - host: 127.0.0.1\n",
        encoding="utf-8",
    )
    config = DaemonConfig(
        data_dir=tmp_path / "data",
        socket_path=tmp_path / "control.sock",
        policy_path=policy_path,
        web_search_enabled=True,
        web_search_backend_url="http://127.0.0.1:8080",
        web_allowed_domains=[],
    )
    services = await DaemonServices.build(config)
    try:
        impl = HandlerImplementation(services=services)

        assert impl._web_toolkit.allowed_domains == ["127.0.0.1"]
        assert impl._web_toolkit._host_block_reason("127.0.0.1") == ""
    finally:
        await services.shutdown()


@pytest.mark.asyncio
async def test_gh_browser_misconfigured_runtime_suppresses_browser_tools(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear_remote_provider_env(monkeypatch)
    config = DaemonConfig(
        data_dir=tmp_path / "data",
        socket_path=tmp_path / "control.sock",
        policy_path=tmp_path / "policy.yaml",
        browser_enabled=True,
        browser_command="",
        web_allowed_domains=["localhost"],
    )

    services = await _build_browser_registry_services(config)
    try:
        assert services.browser_status["status"] == "misconfigured"
        assert "browser_command_unconfigured" in services.browser_status["problems"]
        assert (
            "Browser tools are unavailable because runtime status is misconfigured"
            in services.browser_status["planner_note"]
        )
        assert "browser_command_unconfigured" in services.browser_status["planner_note"]
        assert "web.search/web.fetch" in services.browser_status["planner_note"]
        assert services.registry.get_tool(ToolName("browser.navigate")) is None
        assert services.registry.get_tool(ToolName("browser.read_page")) is None
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


def test_u4_provider_diagnostics_marks_custom_preset_label_for_global_base_url_override(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear_remote_provider_env(monkeypatch)
    config = ModelConfig(base_url="https://proxy.example.com/v1")

    diagnostics = _build_provider_diagnostics(ModelRouter(config))

    planner_route = diagnostics["routes"]["planner"]
    assert planner_route["preset"] == "shisa_default"
    assert planner_route["preset_label"] == "custom"


def test_u4_log_provider_route_summary_marks_route_override_as_overridden(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    _clear_remote_provider_env(monkeypatch)
    config = ModelConfig(
        planner_provider_preset="openai_default",
        planner_base_url="https://proxy.example.com/v1",
    )

    with caplog.at_level("INFO"):
        _log_provider_route_summary(ModelRouter(config))

    assert "component=planner preset=openai_default (overridden)" in caplog.text


def test_u4_warn_on_provider_route_gaps_flags_missing_embeddings_route(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    _clear_remote_provider_env(monkeypatch)

    with caplog.at_level("WARNING"):
        _warn_on_provider_route_gaps(ModelRouter(ModelConfig()))

    assert "Embeddings route not configured; vector recall is off." in caplog.text
    assert "deterministic local lexical fallback" in caplog.text


def test_m7_promptguard_runtime_missing_hint_names_supported_extra() -> None:
    assert "shisad[promptguard]" in _promptguard_degraded_hint("promptguard_runtime_missing")


def test_u4_warn_on_provider_route_gaps_skips_warning_when_embeddings_route_enabled(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    _clear_remote_provider_env(monkeypatch)
    monkeypatch.setenv("SHISAD_MODEL_EMBEDDINGS_PROVIDER_PRESET", "vllm_local_default")
    monkeypatch.setenv("SHISAD_MODEL_EMBEDDINGS_BASE_URL", "http://127.0.0.1:8000/v1")
    monkeypatch.setenv("SHISAD_MODEL_EMBEDDINGS_REMOTE_ENABLED", "true")
    monkeypatch.setenv("SHISAD_MODEL_EMBEDDINGS_AUTH_MODE", "none")

    with caplog.at_level("WARNING"):
        _warn_on_provider_route_gaps(ModelRouter(ModelConfig()))

    assert "Embeddings route not configured" not in caplog.text
