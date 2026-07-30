"""Configuration env-var parsing regressions."""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from pydantic import ValidationError

from shisad.core.config import DaemonConfig


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


def test_f6_builtin_ui_theme_and_motion_env_are_live_but_custom_path_is_hidden(
    tmp_path: Path,
    monkeypatch,
) -> None:
    theme_path = tmp_path / "theme.theme"
    monkeypatch.setenv("SHISAD_UI_THEME", "shisa-light")
    monkeypatch.setenv("SHISAD_REDUCE_MOTION", "true")
    monkeypatch.setenv("SHISAD_UI_THEME_PATH", str(theme_path))

    config = DaemonConfig(data_dir=tmp_path / "data")

    assert config.ui_theme == "shisa-light"
    assert config.reduce_motion is True
    assert "ui_theme" in config.__class__.model_fields
    assert "reduce_motion" in config.__class__.model_fields
    assert "ui_theme_path" not in config.__class__.model_fields


def test_gh50_default_socket_uses_xdg_runtime_dir(
    tmp_path: Path,
    monkeypatch,
) -> None:
    runtime_dir = tmp_path / "runtime"
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(runtime_dir))
    monkeypatch.delenv("SHISAD_SOCKET_PATH", raising=False)

    config = DaemonConfig(data_dir=tmp_path / "data")

    assert config.socket_path == runtime_dir / "shisad" / "control.sock"


def test_gh111_channel_startup_timeout_default_env_and_lower_bound(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("SHISAD_CHANNEL_STARTUP_TIMEOUT_SECONDS", raising=False)
    assert DaemonConfig(data_dir=tmp_path / "default").channel_startup_timeout_seconds == 15.0

    monkeypatch.setenv("SHISAD_CHANNEL_STARTUP_TIMEOUT_SECONDS", "2.5")
    assert DaemonConfig(data_dir=tmp_path / "override").channel_startup_timeout_seconds == 2.5

    monkeypatch.setenv("SHISAD_CHANNEL_STARTUP_TIMEOUT_SECONDS", "0.09")
    with pytest.raises(ValidationError):
        DaemonConfig(data_dir=tmp_path / "invalid")


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
