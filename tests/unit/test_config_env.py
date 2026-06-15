"""Configuration env-var parsing regressions."""

from __future__ import annotations

from pathlib import Path

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


def test_gh50_default_socket_uses_xdg_runtime_dir(
    tmp_path: Path,
    monkeypatch,
) -> None:
    runtime_dir = tmp_path / "runtime"
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(runtime_dir))
    monkeypatch.delenv("SHISAD_SOCKET_PATH", raising=False)

    config = DaemonConfig(data_dir=tmp_path / "data")

    assert config.socket_path == runtime_dir / "shisad" / "control.sock"


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
