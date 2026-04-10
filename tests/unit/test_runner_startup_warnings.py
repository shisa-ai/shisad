"""Startup warning coverage for daemon runner operator hints."""

from __future__ import annotations

from shisad.core.config import DaemonConfig
from shisad.daemon.runner import _warn_on_startup_config_gaps


def test_u4_warn_on_startup_config_gaps_flags_empty_fs_roots(
    tmp_path,
    caplog,
) -> None:
    config = DaemonConfig(
        data_dir=tmp_path / "data",
        socket_path=tmp_path / "control.sock",
        policy_path=tmp_path / "policy.yaml",
        assistant_fs_roots=[],
    )

    with caplog.at_level("WARNING"):
        _warn_on_startup_config_gaps(config)

    assert (
        "No filesystem roots configured - fs.read, fs.list, fs.write, and git "
        "tools will not work. Set SHISAD_ASSISTANT_FS_ROOTS to enable."
    ) in caplog.text


def test_u4_warn_on_startup_config_gaps_skips_warning_when_fs_roots_present(
    tmp_path,
    caplog,
) -> None:
    workspace_root = tmp_path / "workspace"
    workspace_root.mkdir()
    config = DaemonConfig(
        data_dir=tmp_path / "data",
        socket_path=tmp_path / "control.sock",
        policy_path=tmp_path / "policy.yaml",
        assistant_fs_roots=[workspace_root],
    )

    with caplog.at_level("WARNING"):
        _warn_on_startup_config_gaps(config)

    assert "No filesystem roots configured" not in caplog.text
