"""M6 browser toolkit coverage."""

from __future__ import annotations

import asyncio
import os
import subprocess
import sys
import threading
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest

from shisad.core.session import Session
from shisad.core.types import SessionId, TaintLabel, UserId, WorkspaceId
from shisad.executors.browser import BrowserSandbox, BrowserSandboxPolicy, BrowserToolkit
from shisad.executors.sandbox import SandboxConfig, SandboxResult
from shisad.security.firewall.output import OutputFirewall


class _BrowserFixtureHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        if self.path.startswith("/submitted"):
            body = (
                "<html><head><title>Submitted</title></head><body>"
                "Form submitted successfully."
                f"<div id='query'>{self.path}</div>"
                "</body></html>"
            )
        elif self.path == "/next":
            body = (
                "<html><head><title>Next Page</title></head><body>"
                "You reached the next page."
                "</body></html>"
            )
        else:
            body = (
                "<html><head><title>Browser Home</title></head><body>"
                "<h1>Hello browser</h1>"
                "<p>Read only content for testing.</p>"
                "<a id='continue' href='/next'>Continue</a>"
                "<form action='/submitted' method='get'>"
                "<input id='search' name='q' type='text' />"
                "<button id='submit' type='submit'>Submit</button>"
                "</form>"
                "</body></html>"
            )
        encoded = body.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def log_message(self, format: str, *args: Any) -> None:
        _ = (format, args)


@dataclass
class _FixtureServer:
    server: ThreadingHTTPServer
    thread: threading.Thread
    base_url: str

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)


@pytest.fixture
def browser_fixture_server() -> _FixtureServer:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _BrowserFixtureHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    fixture = _FixtureServer(
        server=server,
        thread=thread,
        base_url=f"http://127.0.0.1:{server.server_address[1]}",
    )
    try:
        yield fixture
    finally:
        fixture.close()


class _DirectRunner:
    def __init__(self) -> None:
        self.configs: list[SandboxConfig] = []

    async def execute_async(
        self,
        config: SandboxConfig,
        *,
        session: Session | None = None,
    ) -> SandboxResult:
        _ = session
        self.configs.append(config)
        env = {**os.environ, **dict(config.env)}
        try:
            completed = await asyncio.to_thread(
                subprocess.run,
                config.command,
                cwd=config.cwd or None,
                env=env,
                capture_output=True,
                text=True,
                timeout=max(1, int(config.limits.timeout_seconds)),
                check=False,
            )
        except subprocess.TimeoutExpired:
            return SandboxResult(
                allowed=True,
                exit_code=None,
                timed_out=True,
                reason="browser_command_timeout",
            )
        return SandboxResult(
            allowed=True,
            exit_code=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
            reason="" if completed.returncode == 0 else "browser_command_failed",
        )


def _session() -> Session:
    return Session(
        id=SessionId("browser-session"),
        channel="cli",
        user_id=UserId("user-1"),
        workspace_id=WorkspaceId("ws-1"),
    )


def _toolkit(tmp_path: Path, *, runner: _DirectRunner, enabled: bool = True) -> BrowserToolkit:
    fixture_cli = Path(__file__).resolve().parents[1] / "fixtures" / "fake_playwright_cli.py"
    browser_sandbox = BrowserSandbox(
        output_firewall=OutputFirewall(safe_domains=["127.0.0.1", "localhost"]),
        screenshots_dir=tmp_path / "screenshots",
        policy=BrowserSandboxPolicy(),
    )
    return BrowserToolkit(
        enabled=enabled,
        command=[sys.executable, str(fixture_cli)],
        session_root=tmp_path / "browser",
        allowed_domains=["127.0.0.1", "localhost"],
        timeout_seconds=10.0,
        require_hardened_isolation=False,
        max_read_bytes=16_384,
        sandbox_runner=runner,
        browser_sandbox=browser_sandbox,
    )


def test_m6_browser_toolkit_allowlisted_loopback_disables_private_range_block(
    tmp_path: Path,
) -> None:
    runner = _DirectRunner()
    toolkit = _toolkit(tmp_path, runner=runner)

    policy = toolkit._network_policy(
        target_urls=["http://127.0.0.1:8080/browser"],
        allow_network=True,
    )

    assert policy.allow_network is True
    assert policy.allowed_domains == ["127.0.0.1", "localhost"]
    assert policy.deny_private_ranges is False
    assert policy.deny_ip_literals is False


def test_m6_browser_toolkit_non_allowlisted_loopback_stays_blocked(tmp_path: Path) -> None:
    runner = _DirectRunner()
    browser_sandbox = BrowserSandbox(
        output_firewall=OutputFirewall(safe_domains=["127.0.0.1", "localhost"]),
        screenshots_dir=tmp_path / "screenshots",
        policy=BrowserSandboxPolicy(),
    )
    toolkit = BrowserToolkit(
        enabled=True,
        command=[
            sys.executable,
            str(Path(__file__).resolve().parents[1] / "fixtures" / "fake_playwright_cli.py"),
        ],
        session_root=tmp_path / "browser",
        allowed_domains=["example.com"],
        timeout_seconds=10.0,
        require_hardened_isolation=False,
        max_read_bytes=16_384,
        sandbox_runner=runner,
        browser_sandbox=browser_sandbox,
    )

    policy = toolkit._network_policy(
        target_urls=["http://127.0.0.1:8080/browser"],
        allow_network=True,
    )

    assert policy.allow_network is True
    assert policy.allowed_domains == ["example.com"]
    assert policy.deny_private_ranges is True
    assert policy.deny_ip_literals is True


@pytest.mark.asyncio
async def test_m6_browser_toolkit_navigate_returns_page_and_snapshot(
    tmp_path: Path,
    browser_fixture_server: _FixtureServer,
) -> None:
    runner = _DirectRunner()
    toolkit = _toolkit(tmp_path, runner=runner)

    result = await toolkit.navigate(
        session=_session(),
        url=f"{browser_fixture_server.base_url}/",
    )

    assert result["ok"] is True
    assert result["title"] == "Browser Home"
    assert "Hello browser" in result["content"]
    assert "[e1]" in result["snapshot"]
    assert result["taint_labels"] == [TaintLabel.UNTRUSTED.value]
    assert runner.configs
    assert any(item.tool_name == "browser.navigate" for item in runner.configs)


@pytest.mark.asyncio
async def test_m6_browser_toolkit_type_and_click_follow_form_submission(
    tmp_path: Path,
    browser_fixture_server: _FixtureServer,
) -> None:
    runner = _DirectRunner()
    toolkit = _toolkit(tmp_path, runner=runner)
    session = _session()

    opened = await toolkit.navigate(session=session, url=f"{browser_fixture_server.base_url}/")
    assert opened["ok"] is True

    typed = await toolkit.type_text(
        session=session,
        target="#search",
        text="hello",
        is_sensitive=False,
        submit=False,
    )
    assert typed["ok"] is True
    assert typed["action"] == "type_text"

    clicked = await toolkit.click(
        session=session,
        target="#submit",
        description="submit the form",
    )
    assert clicked["ok"] is True
    assert clicked["action"] == "click"
    assert clicked["title"] == "Submitted"
    assert "q=hello" in clicked["url"]


@pytest.mark.asyncio
async def test_m6_browser_toolkit_click_resolves_natural_language_target(
    tmp_path: Path,
    browser_fixture_server: _FixtureServer,
) -> None:
    runner = _DirectRunner()
    toolkit = _toolkit(tmp_path, runner=runner)
    session = _session()

    opened = await toolkit.navigate(session=session, url=f"{browser_fixture_server.base_url}/")
    assert opened["ok"] is True

    clicked = await toolkit.click(
        session=session,
        target="the continue button in the browser",
        description="continue link",
    )

    assert clicked["ok"] is True
    assert clicked["title"] == "Next Page"
    assert clicked["target"] == "#continue"
    assert clicked["requested_target"] == "the continue button in the browser"
    assert clicked["url"].endswith("/next")


@pytest.mark.asyncio
async def test_m6_browser_toolkit_screenshot_is_stored_and_untrusted(
    tmp_path: Path,
    browser_fixture_server: _FixtureServer,
) -> None:
    runner = _DirectRunner()
    toolkit = _toolkit(tmp_path, runner=runner)
    session = _session()

    await toolkit.navigate(session=session, url=f"{browser_fixture_server.base_url}/")
    result = await toolkit.screenshot(session=session)

    assert result["ok"] is True
    assert Path(result["path"]).exists()
    assert result["taint_labels"] == [TaintLabel.UNTRUSTED.value]
    assert result["url"].startswith(browser_fixture_server.base_url)


@pytest.mark.asyncio
async def test_m6_browser_toolkit_disabled_is_actionable(tmp_path: Path) -> None:
    runner = _DirectRunner()
    toolkit = _toolkit(tmp_path, runner=runner, enabled=False)

    result = await toolkit.navigate(session=_session(), url="https://example.com")

    assert result == {
        "ok": False,
        "error": "browser_disabled",
        "taint_labels": [],
    }
    assert runner.configs == []


def test_m6_browser_toolkit_private_range_error_is_actionable(tmp_path: Path) -> None:
    runner = _DirectRunner()
    toolkit = _toolkit(tmp_path, runner=runner)

    reason = toolkit._result_error_reason(
        SandboxResult(allowed=False, reason="network:private_range_blocked")
    )

    assert reason == "browser_local_network_blocked"


@pytest.mark.asyncio
async def test_m6_browser_toolkit_end_session_removes_browser_state(
    tmp_path: Path,
    browser_fixture_server: _FixtureServer,
) -> None:
    runner = _DirectRunner()
    toolkit = _toolkit(tmp_path, runner=runner)
    session = _session()

    await toolkit.navigate(session=session, url=f"{browser_fixture_server.base_url}/")
    closed = await toolkit.end_session(session=session)
    assert closed["ok"] is True
    assert closed["closed"] is True

    reread = await toolkit.read_page(session=session)
    assert reread["ok"] is False
    assert reread["error"] == "browser_session_missing"
