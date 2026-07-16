"""Configuration env-var parsing regressions."""

from __future__ import annotations

import os
from pathlib import Path

from shisad.core.config import DaemonConfig


def test_f3_daemon_config_and_cli_path_derivation_are_side_effect_free(
    tmp_path: Path,
    monkeypatch,
) -> None:
    direct_data_dir = tmp_path / "direct-parent" / "data"
    direct_config = DaemonConfig(data_dir=direct_data_dir)
    assert direct_config.data_dir == direct_data_dir
    assert not direct_data_dir.parent.exists()

    env_data_dir = tmp_path / "env-parent" / "data"
    monkeypatch.setenv("SHISAD_DATA_DIR", str(env_data_dir))
    env_config = DaemonConfig()
    assert env_config.data_dir == env_data_dir
    assert not env_data_dir.parent.exists()

    cli_data_dir = tmp_path / "cli-parent" / "data"
    monkeypatch.setenv("SHISAD_DATA_DIR", str(cli_data_dir))
    from shisad.cli.main import _get_config

    cli_config = _get_config()
    assert cli_config.data_dir == cli_data_dir
    assert not cli_data_dir.parent.exists()

    existing_data_dir = tmp_path / "existing"
    existing_data_dir.mkdir(mode=0o755)
    marker = existing_data_dir / "marker"
    marker.write_text("unchanged", encoding="utf-8")
    before = existing_data_dir.stat()

    existing_config = DaemonConfig(data_dir=existing_data_dir)

    after = existing_data_dir.stat()
    assert existing_config.data_dir == existing_data_dir
    assert (after.st_mode, after.st_ino, after.st_mtime_ns) == (
        before.st_mode,
        before.st_ino,
        before.st_mtime_ns,
    )
    assert marker.read_text(encoding="utf-8") == "unchanged"


def test_gh33_web_and_browser_allowed_domains_accept_bare_env_strings(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setenv("SHISAD_WEB_ALLOWED_DOMAINS", "example.com, api.example.com")
    monkeypatch.setenv("SHISAD_BROWSER_ALLOWED_DOMAINS", "browser.example.com")

    config = DaemonConfig(data_dir=tmp_path / "data")

    assert config.web_allowed_domains == ["example.com", "api.example.com"]
    assert config.browser_allowed_domains == ["browser.example.com"]


def test_gh33_web_and_browser_allowed_domains_still_accept_json_arrays(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setenv("SHISAD_WEB_ALLOWED_DOMAINS", '["example.com"]')
    monkeypatch.setenv("SHISAD_BROWSER_ALLOWED_DOMAINS", '["browser.example.com"]')

    config = DaemonConfig(data_dir=tmp_path / "data")

    assert config.web_allowed_domains == ["example.com"]
    assert config.browser_allowed_domains == ["browser.example.com"]


def test_u1_ui_theme_env_surface(tmp_path: Path, monkeypatch) -> None:
    theme_path = tmp_path / "theme.theme"
    monkeypatch.setenv("SHISAD_UI_THEME", "shisa-light")
    monkeypatch.setenv("SHISAD_UI_THEME_PATH", str(theme_path))

    config = DaemonConfig(data_dir=tmp_path / "data")

    assert config.ui_theme == "shisa-light"
    assert config.ui_theme_path == theme_path


def test_gh50_default_socket_uses_xdg_runtime_dir(
    tmp_path: Path,
    monkeypatch,
) -> None:
    runtime_dir = tmp_path / "runtime"
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(runtime_dir))
    monkeypatch.delenv("SHISAD_SOCKET_PATH", raising=False)

    config = DaemonConfig(data_dir=tmp_path / "data")

    assert config.socket_path == runtime_dir / "shisad" / "control.sock"


def test_gh50_default_socket_ignores_relative_xdg_runtime_dir(
    monkeypatch,
) -> None:
    monkeypatch.setenv("XDG_RUNTIME_DIR", "relative-runtime")
    monkeypatch.delenv("SHISAD_SOCKET_PATH", raising=False)

    config = DaemonConfig()

    assert config.socket_path == (Path("/tmp") / f"shisad-{os.getuid()}" / "control.sock")


def test_gh50_default_socket_ignores_tilde_xdg_runtime_dir(
    monkeypatch,
) -> None:
    monkeypatch.setenv("XDG_RUNTIME_DIR", "~/runtime")
    monkeypatch.delenv("SHISAD_SOCKET_PATH", raising=False)

    config = DaemonConfig()

    assert config.socket_path == (Path("/tmp") / f"shisad-{os.getuid()}" / "control.sock")


def test_gh50_default_socket_ignores_leading_whitespace_xdg_runtime_dir(
    monkeypatch,
) -> None:
    monkeypatch.setenv("XDG_RUNTIME_DIR", " /tmp/runtime")
    monkeypatch.delenv("SHISAD_SOCKET_PATH", raising=False)

    config = DaemonConfig()

    assert config.socket_path == (Path("/tmp") / f"shisad-{os.getuid()}" / "control.sock")


def test_gh50_default_socket_falls_back_to_user_tmp_dir(
    monkeypatch,
) -> None:
    monkeypatch.delenv("XDG_RUNTIME_DIR", raising=False)
    monkeypatch.delenv("SHISAD_SOCKET_PATH", raising=False)

    config = DaemonConfig()

    assert str(config.socket_path).startswith("/tmp/shisad-")
    assert config.socket_path.name == "control.sock"
    assert "/run/shisad" not in str(config.socket_path)


def test_gh50_socket_env_override_still_wins(
    tmp_path: Path,
    monkeypatch,
) -> None:
    override = tmp_path / "custom.sock"
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path / "runtime"))
    monkeypatch.setenv("SHISAD_SOCKET_PATH", str(override))

    config = DaemonConfig(data_dir=tmp_path / "data")

    assert config.socket_path == override
