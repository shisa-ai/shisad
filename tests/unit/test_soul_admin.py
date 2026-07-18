"""S9 SOUL.md admin update guardrails."""

from __future__ import annotations

import os
from types import SimpleNamespace

import pytest

from shisad.core.config import DaemonConfig
from shisad.daemon.handlers._impl_admin import AdminImplMixin


class _PlannerStub:
    def __init__(self) -> None:
        self.defaults: list[tuple[str, str]] = []

    def set_persona_defaults(self, *, tone: str, custom_text: str) -> None:
        self.defaults.append((tone, custom_text))


class _OverlaySelfmodManager:
    def __init__(self, planner: _PlannerStub) -> None:
        self._planner = planner
        self._default_persona_tone = ""
        self._default_persona_text = ""
        self.overlay_apply_count = 0

    def _apply_behavior_overlay(self) -> None:
        self.overlay_apply_count += 1
        self._planner.set_persona_defaults(
            tone="friendly",
            custom_text="Behavior pack persona overlay.",
        )


class _SoulAdminHarness(AdminImplMixin):
    def __init__(self, config: DaemonConfig, *, selfmod_manager: object | None = None) -> None:
        self._config = config
        self._planner = _PlannerStub()
        self._selfmod_manager = (
            selfmod_manager
            if selfmod_manager is not None
            else SimpleNamespace(_default_persona_text="")
        )


@pytest.mark.asyncio
async def test_s9_admin_soul_update_requires_trusted_admin_peer(tmp_path) -> None:  # type: ignore[no-untyped-def]
    harness = _SoulAdminHarness(
        DaemonConfig(
            data_dir=tmp_path / "data",
            assistant_persona_soul_path=tmp_path / "SOUL.md",
        )
    )

    with pytest.raises(ValueError, match="trusted admin command"):
        await harness.do_admin_soul_update({"content": "Prefer short replies."})


@pytest.mark.asyncio
async def test_s9_admin_soul_update_rejects_internal_ingress_marker(tmp_path) -> None:  # type: ignore[no-untyped-def]
    harness = _SoulAdminHarness(
        DaemonConfig(
            data_dir=tmp_path / "data",
            assistant_persona_soul_path=tmp_path / "SOUL.md",
        )
    )
    marker = object()
    harness._internal_ingress_marker = marker

    with pytest.raises(ValueError, match="trusted admin command"):
        await harness.do_admin_soul_update(
            {
                "content": "Prefer short replies.",
                "_internal_ingress_marker": marker,
                "_rpc_peer": {"uid": os.getuid(), "gid": os.getgid(), "pid": os.getpid()},
            }
        )


@pytest.mark.asyncio
async def test_s9_admin_soul_read_reports_unconfigured_path(tmp_path) -> None:  # type: ignore[no-untyped-def]
    harness = _SoulAdminHarness(DaemonConfig(data_dir=tmp_path / "data"))

    result = await harness.do_admin_soul_read(
        {"_rpc_peer": {"uid": os.getuid(), "gid": os.getgid(), "pid": os.getpid()}}
    )

    assert result == {
        "configured": False,
        "path": "",
        "content": "",
        "sha256": "",
        "bytes": 0,
        "warnings": [],
        "reason": "soul_path_unconfigured",
    }


@pytest.mark.asyncio
async def test_s9_admin_soul_read_reports_missing_configured_path(tmp_path) -> None:  # type: ignore[no-untyped-def]
    soul_path = tmp_path / "SOUL.md"
    harness = _SoulAdminHarness(
        DaemonConfig(data_dir=tmp_path / "data", assistant_persona_soul_path=soul_path)
    )

    result = await harness.do_admin_soul_read(
        {"_rpc_peer": {"uid": os.getuid(), "gid": os.getgid(), "pid": os.getpid()}}
    )

    assert result == {
        "configured": True,
        "path": str(soul_path),
        "content": "",
        "sha256": "",
        "bytes": 0,
        "warnings": [],
        "reason": "ok",
    }


@pytest.mark.asyncio
async def test_s9_admin_soul_update_writes_config_path_and_refreshes_planner(tmp_path) -> None:  # type: ignore[no-untyped-def]
    soul_path = tmp_path / "SOUL.md"
    harness = _SoulAdminHarness(
        DaemonConfig(
            data_dir=tmp_path / "data",
            assistant_persona_custom_text="Use direct prose.",
            assistant_persona_soul_path=soul_path,
        )
    )

    result = await harness.do_admin_soul_update(
        {
            "content": "Prefer short replies.",
            "_rpc_peer": {"uid": os.getuid(), "gid": os.getgid(), "pid": os.getpid()},
        }
    )

    assert result["updated"] is True
    assert result["path"] == str(soul_path)
    assert result["bytes"] == len(b"Prefer short replies.")
    assert result["sha256"].startswith("sha256:")
    assert soul_path.read_text(encoding="utf-8") == "Prefer short replies."
    assert harness._planner.defaults
    tone, custom_text = harness._planner.defaults[-1]
    assert tone == "neutral"
    assert "Use direct prose." in custom_text
    assert "Prefer short replies." in custom_text


@pytest.mark.asyncio
async def test_s9_admin_soul_update_preserves_active_behavior_overlay(tmp_path) -> None:  # type: ignore[no-untyped-def]
    soul_path = tmp_path / "SOUL.md"
    config = DaemonConfig(
        data_dir=tmp_path / "data",
        assistant_persona_soul_path=soul_path,
    )
    harness = _SoulAdminHarness(config)
    overlay_manager = _OverlaySelfmodManager(harness._planner)
    harness._selfmod_manager = overlay_manager

    result = await harness.do_admin_soul_update(
        {
            "content": "Prefer short replies.",
            "_rpc_peer": {"uid": os.getuid(), "gid": os.getgid(), "pid": os.getpid()},
        }
    )

    assert result["updated"] is True
    assert overlay_manager._default_persona_text == (
        "SOUL.md persona preferences:\nPrefer short replies."
    )
    assert overlay_manager.overlay_apply_count == 1
    assert harness._planner.defaults[-1] == ("friendly", "Behavior pack persona overlay.")


@pytest.mark.asyncio
async def test_s9_admin_soul_update_warns_for_project_specific_content(tmp_path) -> None:  # type: ignore[no-untyped-def]
    harness = _SoulAdminHarness(
        DaemonConfig(
            data_dir=tmp_path / "data",
            assistant_persona_soul_path=tmp_path / "SOUL.md",
        )
    )

    result = await harness.do_admin_soul_update(
        {
            "content": "For the shisad repo, remember that issue #4 is about evidence.",
            "_rpc_peer": {"uid": os.getuid(), "gid": os.getgid(), "pid": os.getpid()},
        }
    )

    assert result["updated"] is True
    assert "project_specific_memory_route_recommended" in result["warnings"]
