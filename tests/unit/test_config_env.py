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
