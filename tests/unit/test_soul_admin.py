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


class _SoulAdminHarness(AdminImplMixin):
    def __init__(self, config: DaemonConfig) -> None:
        self._config = config
        self._planner = _PlannerStub()
        self._selfmod_manager = SimpleNamespace(_default_persona_text="")


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
