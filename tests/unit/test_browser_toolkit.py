"""M6 browser toolkit coverage."""

from __future__ import annotations

import asyncio
import json
import os
import shlex
import shutil
import subprocess
import sys
import threading
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import pytest

from shisad.core.session import Session
from shisad.core.types import SessionId, TaintLabel, UserId, WorkspaceId
from shisad.executors.browser import (
    BrowserSandbox,
    BrowserSandboxPolicy,
    BrowserSnapshotElement,
    BrowserToolkit,
)
from shisad.executors.sandbox import SandboxConfig, SandboxResult
from shisad.security.firewall.output import OutputFirewall

_UNREACHABLE_LOOPBACK_URL = "http://127.0.0.1:9/"
_PLAYWRIGHT_WRAPPER = Path(__file__).resolve().parents[2] / "scripts" / "shisad-playwright-cli.mjs"


def _wrapper_with_fake_playwright(tmp_path: Path) -> Path:
    project = tmp_path / "browser-wrapper"
    project.mkdir()
    wrapper = project / "shisad-playwright-cli.mjs"
    shutil.copy2(_PLAYWRIGHT_WRAPPER, wrapper)
    fake_module = project / "node_modules" / "@playwright" / "test"
    fake_module.mkdir(parents=True)
    (fake_module / "index.js").write_text(
        "exports.chromium = { launchPersistentContext: async () => ({}) };\n",
        encoding="utf-8",
    )
    return wrapper


def _make_browser_fixture_handler(
    *,
    link_href: str = "/next",
    form_action: str = "/submitted",
    state: dict[str, str] | None = None,
) -> type[BaseHTTPRequestHandler]:
    class _BrowserFixtureHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            current_link_href = str((state or {}).get("link_href", link_href))
            current_form_action = str((state or {}).get("form_action", form_action))
            current_prefix_html = str((state or {}).get("prefix_html", ""))
            if self.path.startswith("/submitted"):
                body = (
                    "<html><head><title>Submitted</title></head><body>"
                    "Form submitted successfully."
                    f"<div id='query'>{self.path}</div>"
                    "</body></html>"
                )
            elif self.path.startswith("/next"):
                body = (
                    "<html><head><title>Next Page</title></head><body>"
                    f"You reached {self.path or '/next'}."
                    "</body></html>"
                )
            else:
                body = (
                    "<html><head><title>Browser Home</title></head><body>"
                    "<h1>Hello browser</h1>"
                    "<p>Read only content for testing.</p>"
                    f"{current_prefix_html}"
                    f"<a id='continue' href='{current_link_href}'>Continue</a>"
                    f"<form action='{current_form_action}' method='get'>"
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

    return _BrowserFixtureHandler


@dataclass
class _FixtureServer:
    server: ThreadingHTTPServer
    thread: threading.Thread
    base_url: str

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)


def _start_fixture_server(
    *,
    host: str = "127.0.0.1",
    link_href: str = "/next",
    form_action: str = "/submitted",
    state: dict[str, str] | None = None,
) -> _FixtureServer:
    server = ThreadingHTTPServer(
        (host, 0),
        _make_browser_fixture_handler(
            link_href=link_href,
            form_action=form_action,
            state=state,
        ),
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return _FixtureServer(
        server=server,
        thread=thread,
        base_url=f"http://{host}:{server.server_address[1]}",
    )


@pytest.fixture
def browser_fixture_server() -> _FixtureServer:
    fixture = _start_fixture_server()
    try:
        yield fixture
    finally:
        fixture.close()


class _DirectRunner:
    def __init__(self) -> None:
        self.configs: list[SandboxConfig] = []

    async def _run_config(self, config: SandboxConfig) -> SandboxResult:
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

    async def execute_async(
        self,
        config: SandboxConfig,
        *,
        session: Session | None = None,
    ) -> SandboxResult:
        _ = session
        self.configs.append(config)
        return await self._run_config(config)


class _CapturingSuccessRunner:
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
        return SandboxResult(allowed=True, exit_code=0, reason="allowed")


class _SelectiveFailureRunner(_DirectRunner):
    def __init__(self, *, fail_tools: set[str], fail_after_goto: int = 0) -> None:
        super().__init__()
        self._fail_tools = set(fail_tools)
        self._goto_count = 0
        self._fail_after_goto = max(0, int(fail_after_goto))

    async def execute_async(
        self,
        config: SandboxConfig,
        *,
        session: Session | None = None,
    ) -> SandboxResult:
        self.configs.append(config)
        if config.tool_name in self._fail_tools and "goto" in config.command:
            self._goto_count += 1
            if self._goto_count > self._fail_after_goto:
                return SandboxResult(allowed=True, exit_code=1, reason="browser_command_failed")
        _ = session
        return await self._run_config(config)


class _ConfiguredFailureRunner(_DirectRunner):
    def __init__(self, result: SandboxResult) -> None:
        super().__init__()
        self._result = result

    async def execute_async(
        self,
        config: SandboxConfig,
        *,
        session: Session | None = None,
    ) -> SandboxResult:
        _ = session
        self.configs.append(config)
        return self._result


class _PolicyScopedRunner(_DirectRunner):
    @staticmethod
    def _state_path(config: SandboxConfig) -> Path:
        session_token = next(
            (str(item).split("=", 1)[1] for item in config.command if str(item).startswith("-s=")),
            "default",
        )
        return Path(config.cwd) / ".fake-playwright" / f"{session_token}.json"

    @staticmethod
    def _allowed_hosts(config: SandboxConfig) -> set[str]:
        hosts: set[str] = set()
        for item in config.network.allowed_domains:
            raw = str(item).strip().lower()
            if not raw:
                continue
            parsed = urlparse(raw if "://" in raw else f"https://{raw}")
            host = (parsed.hostname or "").lower()
            if host:
                hosts.add(host)
        return hosts

    async def execute_async(
        self,
        config: SandboxConfig,
        *,
        session: Session | None = None,
    ) -> SandboxResult:
        self.configs.append(config)
        if any(token in config.command for token in ("eval", "snapshot")):
            state_path = self._state_path(config)
            if state_path.exists():
                try:
                    current_url = json.loads(state_path.read_text(encoding="utf-8")).get(
                        "current_url",
                        "",
                    )
                except (OSError, ValueError, TypeError):
                    current_url = ""
                live_host = (urlparse(str(current_url)).hostname or "").lower()
                if live_host and live_host not in self._allowed_hosts(config):
                    return SandboxResult(
                        allowed=True,
                        exit_code=1,
                        reason="browser_command_failed",
                    )
        _ = session
        return await self._run_config(config)


def _session() -> Session:
    return Session(
        id=SessionId("browser-session"),
        channel="cli",
        user_id=UserId("user-1"),
        workspace_id=WorkspaceId("ws-1"),
    )


def _toolkit(
    tmp_path: Path,
    *,
    runner: Any,
    command: list[str] | None = None,
    enabled: bool = True,
    allowed_domains: list[str] | None = None,
    require_hardened_isolation: bool = False,
) -> BrowserToolkit:
    fixture_cli = Path(__file__).resolve().parents[1] / "fixtures" / "fake_playwright_cli.py"
    safe_domains = list(allowed_domains or ["127.0.0.1", "localhost"])
    browser_sandbox = BrowserSandbox(
        output_firewall=OutputFirewall(safe_domains=safe_domains),
        screenshots_dir=tmp_path / "screenshots",
        policy=BrowserSandboxPolicy(),
    )
    return BrowserToolkit(
        enabled=enabled,
        command=command if command is not None else [sys.executable, str(fixture_cli)],
        session_root=tmp_path / "browser",
        allowed_domains=list(allowed_domains or ["127.0.0.1", "localhost"]),
        timeout_seconds=10.0,
        require_hardened_isolation=require_hardened_isolation,
        max_read_bytes=16_384,
        sandbox_runner=runner,
        browser_sandbox=browser_sandbox,
    )


@pytest.mark.asyncio
async def test_gh33_browser_toolkit_doctor_accepts_shisad_playwright_wrapper(
    tmp_path: Path,
) -> None:
    if shutil.which("node") is None:
        pytest.skip("node is required for the browser wrapper protocol probe")
    runner = _DirectRunner()
    wrapper = _wrapper_with_fake_playwright(tmp_path)
    toolkit = _toolkit(tmp_path, runner=runner, command=["node", str(wrapper)])

    status = await toolkit.doctor_status()

    assert status["status"] == "ok"
    assert status["enabled"] is True
    assert status["protocol"]["supported"] is True
    assert status["protocol"]["probe"] == "sentinel,readiness"
    assert status["problems"] == []
    assert len(runner.configs) == 2
    assert [config.command[-1] for config in runner.configs] == [
        "--shisad-browser-wrapper-version",
        "--shisad-browser-wrapper-doctor",
    ]
    for config in runner.configs:
        assert config.tool_name == "browser.doctor"
        assert config.network.allow_network is False
        assert config.limits.memory_mb > 0
        assert config.limits.address_space_mb == 0
        assert config.limits.pids >= 4096


@pytest.mark.asyncio
async def test_gh33_browser_toolkit_doctor_rejects_wrapper_missing_playwright(
    tmp_path: Path,
) -> None:
    if shutil.which("node") is None:
        pytest.skip("node is required for the browser wrapper protocol probe")
    project = tmp_path / "browser-wrapper"
    project.mkdir()
    wrapper = project / "shisad-playwright-cli.mjs"
    shutil.copy2(_PLAYWRIGHT_WRAPPER, wrapper)
    runner = _DirectRunner()
    toolkit = _toolkit(tmp_path, runner=runner, command=["node", str(wrapper)])

    status = await toolkit.doctor_status()

    assert status["status"] == "misconfigured"
    assert "browser_dependency_unavailable" in status["problems"]
    assert status["protocol"]["supported"] is False
    assert status["protocol"]["probe"] == "sentinel,readiness"
    assert status["protocol"]["reason"] == "browser_dependency_unavailable"
    assert [config.command[-1] for config in runner.configs] == [
        "--shisad-browser-wrapper-version",
        "--shisad-browser-wrapper-doctor",
    ]


@pytest.mark.asyncio
async def test_gh33_browser_toolkit_doctor_rejects_old_wrapper_without_readiness_probe(
    tmp_path: Path,
) -> None:
    command = tmp_path / "old-shisad-wrapper"
    command.write_text(
        "\n".join(
            [
                "#!/usr/bin/env python3",
                "import sys",
                "if '--shisad-browser-wrapper-version' in sys.argv:",
                "    print('shisad-browser-wrapper 1')",
                "    raise SystemExit(0)",
                "if '--shisad-browser-wrapper-doctor' in sys.argv:",
                "    print(",
                "        'unsupported browser command: --shisad-browser-wrapper-doctor',",
                "        file=sys.stderr,",
                "    )",
                "    raise SystemExit(1)",
                "raise SystemExit(1)",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    command.chmod(0o755)
    runner = _DirectRunner()
    toolkit = _toolkit(tmp_path, runner=runner, command=[str(command)])

    status = await toolkit.doctor_status()

    assert status["status"] == "misconfigured"
    assert "browser_command_protocol_incompatible" in status["problems"]
    assert status["protocol"]["supported"] is False
    assert status["protocol"]["probe"] == "sentinel,readiness"
    assert status["protocol"]["reason"] == "browser_command_protocol_incompatible"


@pytest.mark.asyncio
async def test_gh33_browser_toolkit_doctor_rejects_help_only_wrapper(
    tmp_path: Path,
) -> None:
    command = tmp_path / "help-only-wrapper"
    command.write_text(
        "\n".join(
            [
                "#!/usr/bin/env python3",
                "import sys",
                "if '--help' in sys.argv:",
                "    print('Usage: shisad-compatible wrapper -s=<session>')",
                "    raise SystemExit(0)",
                "raise SystemExit(1)",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    command.chmod(0o755)
    runner = _DirectRunner()
    toolkit = _toolkit(tmp_path, runner=runner, command=[str(command)])

    status = await toolkit.doctor_status()

    assert status["status"] == "misconfigured"
    assert "browser_command_protocol_incompatible" in status["problems"]
    assert status["protocol"]["supported"] is False
    assert status["protocol"]["probe"] == "sentinel,help"
    assert status["protocol"]["reason"] == "browser_command_protocol_incompatible"
    assert [config.command[-1] for config in runner.configs] == [
        "--shisad-browser-wrapper-version",
        "--help",
    ]


@pytest.mark.asyncio
async def test_gh33_browser_toolkit_doctor_rejects_plain_playwright_cli(
    tmp_path: Path,
) -> None:
    command = tmp_path / "playwright-cli"
    command.write_text(
        "\n".join(
            [
                "#!/usr/bin/env python3",
                "import sys",
                "if '--shisad-browser-wrapper-version' in sys.argv:",
                "    print(",
                "        'error: unknown option --shisad-browser-wrapper-version',",
                "        file=sys.stderr,",
                "    )",
                "    raise SystemExit(1)",
                "if '--help' in sys.argv:",
                "    print('Usage: playwright [options] [command]')",
                "    raise SystemExit(0)",
                "raise SystemExit(0)",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    command.chmod(0o755)
    runner = _DirectRunner()
    toolkit = _toolkit(tmp_path, runner=runner, command=[str(command)])

    status = await toolkit.doctor_status()

    assert status["status"] == "misconfigured"
    assert "browser_command_protocol_incompatible" in status["problems"]
    assert status["protocol"]["supported"] is False
    assert status["protocol"]["reason"] == "browser_command_protocol_incompatible"
    assert [config.tool_name for config in runner.configs] == [
        "browser.doctor",
        "browser.doctor",
    ]
    assert all(config.network.allow_network is False for config in runner.configs)


@pytest.mark.asyncio
async def test_gh33_browser_toolkit_doctor_reports_sandbox_degraded_probe(
    tmp_path: Path,
) -> None:
    runner = _ConfiguredFailureRunner(
        SandboxResult(
            allowed=False,
            reason="degraded_enforcement",
            degraded_controls=["filesystem", "network", "seccomp"],
        )
    )
    toolkit = _toolkit(tmp_path, runner=runner, command=[sys.executable])

    status = await toolkit.doctor_status()

    assert status["status"] == "misconfigured"
    assert "browser_runtime_isolation_unavailable" in status["problems"]
    assert status["protocol"]["supported"] is False
    assert status["protocol"]["reason"] == "browser_runtime_isolation_unavailable"
    assert status["protocol"]["degraded_controls"] == [
        "filesystem",
        "network",
        "seccomp",
    ]
    assert [config.tool_name for config in runner.configs] == [
        "browser.doctor",
        "browser.doctor",
    ]
    assert all(config.network.allow_network is False for config in runner.configs)


@pytest.mark.asyncio
async def test_gh33_browser_toolkit_doctor_reports_unwritable_playwright_cache(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    if shutil.which("node") is None:
        pytest.skip("node is required for the browser wrapper protocol probe")
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    (home / ".cache").write_text("not a directory", encoding="utf-8")
    runner = _DirectRunner()
    wrapper = _wrapper_with_fake_playwright(tmp_path)
    toolkit = _toolkit(tmp_path, runner=runner, command=["node", str(wrapper)])

    status = await toolkit.doctor_status()

    assert status["status"] == "misconfigured"
    assert "browser_cache_not_writable" in status["problems"]
    assert status["protocol"]["supported"] is True
    assert status["protocol"]["probe"] == "sentinel,readiness"
    assert len(runner.configs) == 2
    assert all(config.tool_name == "browser.doctor" for config in runner.configs)


def test_gh33_browser_unknown_session_flag_reports_protocol_error(tmp_path: Path) -> None:
    toolkit = _toolkit(tmp_path, runner=_CapturingSuccessRunner())
    result = SandboxResult(
        allowed=True,
        exit_code=1,
        stderr="error: unknown option '-s=shisad-browser-session'",
        reason="browser_command_failed",
    )

    reason = toolkit._result_error_reason(result)

    assert reason == "browser_command_protocol_incompatible"


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
    assert policy.allowed_domains == ["example.com", "127.0.0.1"]
    assert policy.deny_private_ranges is True
    assert policy.deny_ip_literals is True


def test_m6_browser_toolkit_network_policy_adds_explicit_target_host(tmp_path: Path) -> None:
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
        allowed_domains=["approved.example"],
        timeout_seconds=10.0,
        require_hardened_isolation=False,
        max_read_bytes=16_384,
        sandbox_runner=runner,
        browser_sandbox=browser_sandbox,
    )

    policy = toolkit._network_policy(
        target_urls=["https://public.example/path"],
        allow_network=True,
    )

    assert policy.allow_network is True
    assert policy.allowed_domains == ["approved.example", "public.example"]


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
async def test_gh24_browser_runtime_keeps_memory_budget_without_address_rlimit(
    tmp_path: Path,
) -> None:
    runner = _CapturingSuccessRunner()
    toolkit = _toolkit(tmp_path, runner=runner)

    result = await toolkit._run_cli(
        session=_session(),
        tool_name="browser.navigate",
        args=["open"],
        network_urls=[],
        allow_network=False,
    )

    assert result is None
    assert runner.configs
    limits = runner.configs[-1].limits
    assert limits.memory_mb > 0
    assert limits.address_space_mb == 0


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
async def test_gh33_browser_toolkit_sensitive_type_text_avoids_wrapper_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = _CapturingSuccessRunner()
    toolkit = _toolkit(tmp_path, runner=runner)
    session = _session()
    toolkit._save_state(session, {"opened": True, "current_url": "http://example.test/"})

    async def capture_page_state(**_: Any) -> dict[str, Any]:
        return {
            "ok": True,
            "url": "http://example.test/",
            "title": "Browser Home",
            "content": "",
            "snapshot": "",
            "taint_labels": [TaintLabel.UNTRUSTED.value],
            "error": "",
        }

    monkeypatch.setattr(toolkit, "_capture_page_state", capture_page_state)

    typed = await toolkit.type_text(
        session=session,
        target="#search",
        resolved_target="#search",
        text="sensitive-secret",
        is_sensitive=True,
    )

    assert typed["ok"] is True
    assert typed["is_sensitive"] is True
    fill_commands = [
        config.command
        for config in runner.configs
        if config.tool_name == "browser.type_text" and "fill" in config.command
    ]
    assert fill_commands
    assert fill_commands[-1][-4:] == ["fill", "#search", "sensitive-secret", "--no-store"]


@pytest.mark.asyncio
async def test_gh33_browser_toolkit_sensitive_type_text_fake_cli_no_store(
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
        text="sensitive-secret",
        is_sensitive=True,
    )

    assert typed["ok"] is True
    state_path = (
        toolkit._session_dir(session) / ".fake-playwright" / "shisad-browser-session.json"
    )
    fake_state = json.loads(state_path.read_text(encoding="utf-8"))
    assert "sensitive-secret" not in json.dumps(fake_state, sort_keys=True)


@pytest.mark.asyncio
async def test_gh33_browser_toolkit_sensitive_type_text_can_click_atomically(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = _CapturingSuccessRunner()
    toolkit = _toolkit(tmp_path, runner=runner)
    session = _session()
    toolkit._save_state(session, {"opened": True, "current_url": "http://example.test/"})

    async def capture_page_state(**_: Any) -> dict[str, Any]:
        return {
            "ok": True,
            "url": "http://example.test/logged-in",
            "title": "Logged In",
            "content": "",
            "snapshot": "",
            "taint_labels": [TaintLabel.UNTRUSTED.value],
            "error": "",
        }

    monkeypatch.setattr(toolkit, "_capture_page_state", capture_page_state)

    typed = await toolkit.type_text(
        session=session,
        target="#search",
        resolved_target="#search",
        text="sensitive-secret",
        is_sensitive=True,
        click_target="#login",
        resolved_click_target="#login",
    )

    assert typed["ok"] is True
    assert typed["click_target"] == "#login"
    fill_commands = [
        config.command
        for config in runner.configs
        if config.tool_name == "browser.type_text" and "fill" in config.command
    ]
    assert fill_commands
    assert fill_commands[-1][-6:] == [
        "fill",
        "#search",
        "sensitive-secret",
        "--click",
        "#login",
        "--no-store",
    ]


@pytest.mark.asyncio
async def test_gh33_browser_toolkit_prepares_sensitive_type_click_binding(
    tmp_path: Path,
    browser_fixture_server: _FixtureServer,
) -> None:
    runner = _DirectRunner()
    toolkit = _toolkit(tmp_path, runner=runner)
    session = _session()

    opened = await toolkit.navigate(session=session, url=f"{browser_fixture_server.base_url}/")
    assert opened["ok"] is True
    prepared = await toolkit.prepare_action_arguments(
        session=session,
        tool_name="browser.type_text",
        arguments={
            "target": "#search",
            "text": "hello",
            "is_sensitive": True,
            "click_target": "#submit",
        },
    )

    assert prepared["source_url"] == f"{browser_fixture_server.base_url}/"
    assert str(prepared.get("source_binding", "")).strip()
    assert str(prepared.get("click_source_binding", "")).strip()
    assert str(prepared["destination"]).endswith("/submitted")

    typed = await toolkit.type_text(
        session=session,
        target=str(prepared["target"]),
        text="hello",
        is_sensitive=True,
        click_target=str(prepared["click_target"]),
        resolved_target=str(prepared.get("resolved_target", "")),
        resolved_click_target=str(prepared.get("resolved_click_target", "")),
        destination=str(prepared["destination"]),
        source_url=str(prepared["source_url"]),
        source_binding=str(prepared["source_binding"]),
        click_source_binding=str(prepared["click_source_binding"]),
    )

    assert typed["ok"] is True
    assert typed["url"].endswith("/submitted?q=hello")


@pytest.mark.asyncio
async def test_gh33_browser_toolkit_sensitive_type_click_rejects_stale_click_binding(
    tmp_path: Path,
) -> None:
    state = {"form_action": "/submitted-a"}
    browser_server = _start_fixture_server(state=state)
    try:
        runner = _DirectRunner()
        toolkit = _toolkit(tmp_path, runner=runner)
        session = _session()

        opened = await toolkit.navigate(session=session, url=f"{browser_server.base_url}/")
        assert opened["ok"] is True
        prepared = await toolkit.prepare_action_arguments(
            session=session,
            tool_name="browser.type_text",
            arguments={
                "target": "#search",
                "text": "hello",
                "is_sensitive": True,
                "click_target": "#submit",
            },
        )
        assert str(prepared["destination"]).endswith("/submitted-a")
        assert str(prepared.get("click_source_binding", "")).strip()

        state["form_action"] = "/submitted-b"
        config_count = len(runner.configs)
        blocked = await toolkit.type_text(
            session=session,
            target=str(prepared["target"]),
            text="hello",
            is_sensitive=True,
            click_target=str(prepared["click_target"]),
            resolved_target=str(prepared.get("resolved_target", "")),
            resolved_click_target=str(prepared.get("resolved_click_target", "")),
            destination=str(prepared["destination"]),
            source_url=str(prepared["source_url"]),
            source_binding=str(prepared["source_binding"]),
            click_source_binding=str(prepared["click_source_binding"]),
        )

        assert blocked == {
            "ok": False,
            "error": "browser_confirmation_context_changed",
            "taint_labels": [],
        }
        new_configs = runner.configs[config_count:]
        assert new_configs
        assert not any("fill" in config.command for config in new_configs)
    finally:
        browser_server.close()


@pytest.mark.asyncio
async def test_gh33_browser_toolkit_prepare_click_ignores_caller_runtime_fields(
    tmp_path: Path,
    browser_fixture_server: _FixtureServer,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = _DirectRunner()
    toolkit = _toolkit(tmp_path, runner=runner)
    session = _session()

    opened = await toolkit.navigate(session=session, url=f"{browser_fixture_server.base_url}/")
    assert opened["ok"] is True

    original_load_snapshot = toolkit._load_interaction_snapshot

    async def no_prepare_snapshot(**_: Any) -> list[Any]:
        return []

    monkeypatch.setattr(toolkit, "_load_interaction_snapshot", no_prepare_snapshot)
    prepared = await toolkit.prepare_action_arguments(
        session=session,
        tool_name="browser.click",
        arguments={
            "target": "#continue",
            "destination": f"{browser_fixture_server.base_url}/submitted?smuggled=1",
            "resolved_target": "#submit",
            "source_url": "http://attacker.invalid/",
            "source_binding": "",
        },
    )
    monkeypatch.setattr(toolkit, "_load_interaction_snapshot", original_load_snapshot)

    assert prepared["source_url"] == f"{browser_fixture_server.base_url}/"
    assert prepared.get("destination") != f"{browser_fixture_server.base_url}/submitted?smuggled=1"
    assert prepared.get("resolved_target") != "#submit"
    assert prepared.get("source_binding") in {None, ""}

    clicked = await toolkit.click(
        session=session,
        target=str(prepared["target"]),
        resolved_target=str(prepared.get("resolved_target", "")),
        source_url=str(prepared["source_url"]),
        source_binding=str(prepared.get("source_binding", "")),
    )

    assert clicked["ok"] is True
    assert clicked["url"].endswith("/next")


@pytest.mark.asyncio
async def test_gh33_browser_toolkit_prepare_type_click_ignores_caller_runtime_fields(
    tmp_path: Path,
    browser_fixture_server: _FixtureServer,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = _DirectRunner()
    toolkit = _toolkit(tmp_path, runner=runner)
    session = _session()

    opened = await toolkit.navigate(session=session, url=f"{browser_fixture_server.base_url}/")
    assert opened["ok"] is True

    original_load_snapshot = toolkit._load_interaction_snapshot

    async def no_prepare_snapshot(**_: Any) -> list[Any]:
        return []

    monkeypatch.setattr(toolkit, "_load_interaction_snapshot", no_prepare_snapshot)
    prepared = await toolkit.prepare_action_arguments(
        session=session,
        tool_name="browser.type_text",
        arguments={
            "target": "#search",
            "text": "hello",
            "is_sensitive": True,
            "click_target": "#submit",
            "destination": f"{browser_fixture_server.base_url}/next?smuggled=1",
            "resolved_target": "#continue",
            "resolved_click_target": "#continue",
            "source_url": "http://attacker.invalid/",
            "source_binding": "",
            "click_source_binding": "",
        },
    )
    monkeypatch.setattr(toolkit, "_load_interaction_snapshot", original_load_snapshot)

    assert prepared["source_url"] == f"{browser_fixture_server.base_url}/"
    assert prepared.get("destination") != f"{browser_fixture_server.base_url}/next?smuggled=1"
    assert prepared.get("resolved_target") != "#continue"
    assert prepared.get("resolved_click_target") != "#continue"
    assert prepared.get("source_binding") in {None, ""}
    assert prepared.get("click_source_binding") in {None, ""}

    typed = await toolkit.type_text(
        session=session,
        target=str(prepared["target"]),
        text="hello",
        is_sensitive=True,
        click_target=str(prepared["click_target"]),
        resolved_target=str(prepared.get("resolved_target", "")),
        resolved_click_target=str(prepared.get("resolved_click_target", "")),
        source_url=str(prepared["source_url"]),
        source_binding=str(prepared.get("source_binding", "")),
        click_source_binding=str(prepared.get("click_source_binding", "")),
    )

    assert typed["ok"] is True
    assert typed["url"].endswith("/submitted?q=hello")


def test_gh33_fake_playwright_cli_no_store_failure_preclears_state(
    tmp_path: Path,
    browser_fixture_server: _FixtureServer,
) -> None:
    fixture_cli = Path(__file__).resolve().parents[1] / "fixtures" / "fake_playwright_cli.py"
    state_dir = tmp_path / ".fake-playwright"
    state_dir.mkdir()
    state_path = state_dir / "shisad-browser-session.json"
    state_path.write_text(
        json.dumps(
            {
                "opened": True,
                "current_url": f"{browser_fixture_server.base_url}/next",
                "fields": {"q": "old-sensitive"},
            }
        ),
        encoding="utf-8",
    )

    completed = subprocess.run(
        [
            sys.executable,
            str(fixture_cli),
            "-s=shisad-browser-session",
            "fill",
            "#search",
            "replacement-secret",
            "--no-store",
        ],
        cwd=tmp_path,
        text=True,
        capture_output=True,
        check=False,
        timeout=10,
    )

    assert completed.returncode != 0
    fake_state = json.loads(state_path.read_text(encoding="utf-8"))
    assert "old-sensitive" not in json.dumps(fake_state, sort_keys=True)
    assert "replacement-secret" not in json.dumps(fake_state, sort_keys=True)


@pytest.mark.asyncio
async def test_m6_browser_toolkit_type_submit_submits_form_directly(
    tmp_path: Path,
    browser_fixture_server: _FixtureServer,
) -> None:
    runner = _DirectRunner()
    toolkit = _toolkit(tmp_path, runner=runner)
    session = _session()

    opened = await toolkit.navigate(session=session, url=f"{browser_fixture_server.base_url}/")
    assert opened["ok"] is True

    prepared = await toolkit.prepare_action_arguments(
        session=session,
        tool_name="browser.type_text",
        arguments={"target": "#search", "text": "hello", "submit": True},
    )
    assert prepared["destination"].endswith("/submitted")

    typed = await toolkit.type_text(
        session=session,
        target="#search",
        text="hello",
        submit=True,
        destination=str(prepared["destination"]),
    )

    assert typed["ok"] is True
    assert typed["title"] == "Submitted"
    assert "q=hello" in typed["url"]


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
async def test_m6_browser_toolkit_prepare_action_arguments_resolves_target_and_destination(
    tmp_path: Path,
    browser_fixture_server: _FixtureServer,
) -> None:
    runner = _DirectRunner()
    toolkit = _toolkit(tmp_path, runner=runner)
    session = _session()

    opened = await toolkit.navigate(session=session, url=f"{browser_fixture_server.base_url}/")
    assert opened["ok"] is True

    prepared = await toolkit.prepare_action_arguments(
        session=session,
        tool_name="browser.click",
        arguments={
            "target": "the continue button in the browser",
            "description": "continue link",
        },
    )

    assert prepared["target"] == "the continue button in the browser"
    assert prepared["resolved_target"] == "#continue"
    assert prepared["destination"].endswith("/next")
    assert prepared["source_url"] == f"{browser_fixture_server.base_url}/"
    assert str(prepared.get("source_binding", "")).strip()


def test_gh24_browser_target_resolution_prefers_exact_selector_before_fuzzy_label() -> None:
    reserve_selector = (
        "html > body > div:nth-of-type(7) > div:nth-of-type(1) > "
        "div:nth-of-type(3) > div:nth-of-type(2) > div > div > div > div > "
        "div:nth-of-type(2) > div:nth-of-type(2) > div > div > div > div > "
        "div:nth-of-type(3) > div:nth-of-type(2) > a"
    )
    elements = [
        BrowserSnapshotElement(
            ref="e1",
            kind="link",
            label="a",
            selector="#pagetop",
        ),
        BrowserSnapshotElement(
            ref="e176",
            kind="link",
            label="Reserve",
            selector=reserve_selector,
            href="#",
        ),
    ]

    matched = BrowserToolkit._match_snapshot_target(elements, reserve_selector)

    assert matched is not None
    assert matched.ref == "e176"
    assert matched.selector == reserve_selector


def test_gh24_browser_click_binding_uses_stable_element_identity() -> None:
    selector = "html > body > div:nth-of-type(7) > a"
    booking_element = BrowserSnapshotElement(
        ref="e176",
        kind="link",
        label="Reserve",
        selector=selector,
        href="/en/booking/form_course/new?member=2&rcd=13225171",
    )
    placeholder_element = BrowserSnapshotElement(
        ref="e311",
        kind="link",
        label="Reserve",
        selector=selector,
        href="#",
    )

    booking_hash = BrowserToolkit._binding_hash_for_element(
        booking_element,
        current_url="https://tabelog.com/en/tokyo/A1302/A130202/13225171/",
        submit=False,
    )
    placeholder_hash = BrowserToolkit._binding_hash_for_element(
        placeholder_element,
        current_url="https://tabelog.com/en/tokyo/A1302/A130202/13225171/",
        submit=False,
    )

    assert booking_hash == placeholder_hash


def test_gh24_browser_fragment_destinations_are_not_confirmation_targets() -> None:
    current_url = "https://tabelog.com/en/tokyo/A1302/A130202/13225171/"
    placeholder_element = BrowserSnapshotElement(
        ref="e176",
        kind="link",
        label="Reserve",
        selector="#reserve",
        href="#",
    )

    assert (
        BrowserToolkit._predict_destination_url(
            placeholder_element,
            current_url=current_url,
            submit=False,
        )
        == ""
    )
    assert BrowserToolkit._normalize_confirmation_destination("#", current_url=current_url) == ""
    assert (
        BrowserToolkit._normalize_confirmation_destination("#reserve", current_url=current_url)
        == ""
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("approved_href", "live_href"),
    [
        ("#", "/en/booking/form_course/new?member=2&rcd=13225171"),
        ("/en/booking/form_course/new?member=2&rcd=13225171", "#"),
    ],
)
async def test_gh24_browser_click_confirmation_rejects_empty_nonempty_destination_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    approved_href: str,
    live_href: str,
) -> None:
    runner = _CapturingSuccessRunner()
    toolkit = _toolkit(tmp_path, runner=runner)
    session = _session()
    source_url = "https://tabelog.com/en/tokyo/A1302/A130202/13225171/"
    selector = "#reserve"
    approved_element = BrowserSnapshotElement(
        ref="e176",
        kind="link",
        label="Reserve",
        selector=selector,
        href=approved_href,
    )
    live_element = BrowserSnapshotElement(
        ref="e176",
        kind="link",
        label="Reserve",
        selector=selector,
        href=live_href,
    )
    toolkit._save_state(session, {"opened": True, "current_url": source_url})

    async def load_snapshot(**_: Any) -> list[BrowserSnapshotElement]:
        return [live_element]

    async def fail_if_clicked(**_: Any) -> dict[str, Any] | None:
        raise AssertionError("click should not execute after destination drift")

    monkeypatch.setattr(toolkit, "_load_interaction_snapshot", load_snapshot)
    monkeypatch.setattr(toolkit, "_run_cli", fail_if_clicked)

    blocked = await toolkit.click(
        session=session,
        target=selector,
        resolved_target=selector,
        destination=BrowserToolkit._predict_destination_url(
            approved_element,
            current_url=source_url,
            submit=False,
        ),
        source_url=source_url,
        source_binding=BrowserToolkit._binding_hash_for_element(
            approved_element,
            current_url=source_url,
            submit=False,
        ),
    )

    assert blocked == {
        "ok": False,
        "error": "browser_confirmation_context_changed",
        "taint_labels": [],
    }
    assert toolkit.current_state(session=session) == {"opened": True, "current_url": source_url}


@pytest.mark.asyncio
async def test_gh24_browser_click_confirmation_rejects_post_action_destination_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = _CapturingSuccessRunner()
    toolkit = _toolkit(tmp_path, runner=runner)
    session = _session()
    source_url = "http://example.test/"
    selector = "#continue"
    element = BrowserSnapshotElement(
        ref="e1",
        kind="link",
        label="Continue",
        selector=selector,
        href="/next",
    )
    toolkit._save_state(session, {"opened": True, "current_url": source_url})

    async def load_snapshot(**_: Any) -> list[BrowserSnapshotElement]:
        return [element]

    async def run_cli(**_: Any) -> dict[str, Any] | None:
        return None

    async def capture_page_state(**_: Any) -> dict[str, Any]:
        return {
            "ok": True,
            "url": "http://example.test/elsewhere",
            "title": "Elsewhere",
            "content": "",
            "snapshot": "",
            "taint_labels": [TaintLabel.UNTRUSTED.value],
            "error": "",
        }

    monkeypatch.setattr(toolkit, "_load_interaction_snapshot", load_snapshot)
    monkeypatch.setattr(toolkit, "_run_cli", run_cli)
    monkeypatch.setattr(toolkit, "_capture_page_state", capture_page_state)

    blocked = await toolkit.click(
        session=session,
        target=selector,
        resolved_target=selector,
        destination="http://example.test/next",
        source_url=source_url,
        source_binding=BrowserToolkit._binding_hash_for_element(
            element,
            current_url=source_url,
            submit=False,
        ),
    )

    assert blocked == {
        "ok": False,
        "error": "browser_confirmation_context_changed",
        "taint_labels": [],
    }
    assert toolkit.current_state(session=session) == {"opened": False, "current_url": ""}


@pytest.mark.asyncio
async def test_gh24_browser_click_confirmation_rejects_unpredicted_js_navigation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = _CapturingSuccessRunner()
    toolkit = _toolkit(tmp_path, runner=runner)
    session = _session()
    source_url = "http://example.test/"
    selector = "#continue"
    element = BrowserSnapshotElement(
        ref="e1",
        kind="link",
        label="Continue",
        selector=selector,
        href="#",
    )
    toolkit._save_state(session, {"opened": True, "current_url": source_url})

    async def load_snapshot(**_: Any) -> list[BrowserSnapshotElement]:
        return [element]

    async def run_cli(**_: Any) -> dict[str, Any] | None:
        return None

    async def capture_page_state(**_: Any) -> dict[str, Any]:
        return {
            "ok": True,
            "url": "http://example.test/scripted",
            "title": "Scripted",
            "content": "",
            "snapshot": "",
            "taint_labels": [TaintLabel.UNTRUSTED.value],
            "error": "",
        }

    monkeypatch.setattr(toolkit, "_load_interaction_snapshot", load_snapshot)
    monkeypatch.setattr(toolkit, "_run_cli", run_cli)
    monkeypatch.setattr(toolkit, "_capture_page_state", capture_page_state)

    blocked = await toolkit.click(
        session=session,
        target=selector,
        resolved_target=selector,
        source_url=source_url,
        source_binding=BrowserToolkit._binding_hash_for_element(
            element,
            current_url=source_url,
            submit=False,
        ),
    )

    assert blocked == {
        "ok": False,
        "error": "browser_confirmation_context_changed",
        "taint_labels": [],
    }
    assert toolkit.current_state(session=session) == {"opened": False, "current_url": ""}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("href", "actual_url"),
    [
        ("#details", "http://example.test/#details"),
        ("#", "http://example.test/#"),
    ],
)
async def test_gh24_browser_click_confirmation_allows_same_document_fragment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    href: str,
    actual_url: str,
) -> None:
    runner = _CapturingSuccessRunner()
    toolkit = _toolkit(tmp_path, runner=runner)
    session = _session()
    source_url = "http://example.test/"
    selector = "#jump"
    element = BrowserSnapshotElement(
        ref="e1",
        kind="link",
        label="Jump",
        selector=selector,
        href=href,
    )
    toolkit._save_state(session, {"opened": True, "current_url": source_url})

    async def load_snapshot(**_: Any) -> list[BrowserSnapshotElement]:
        return [element]

    async def run_cli(**_: Any) -> dict[str, Any] | None:
        return None

    async def capture_page_state(**_: Any) -> dict[str, Any]:
        return {
            "ok": True,
            "url": actual_url,
            "title": "Same Page",
            "content": "",
            "snapshot": "",
            "taint_labels": [TaintLabel.UNTRUSTED.value],
            "error": "",
        }

    monkeypatch.setattr(toolkit, "_load_interaction_snapshot", load_snapshot)
    monkeypatch.setattr(toolkit, "_run_cli", run_cli)
    monkeypatch.setattr(toolkit, "_capture_page_state", capture_page_state)

    clicked = await toolkit.click(
        session=session,
        target=selector,
        resolved_target=selector,
        source_url=source_url,
        source_binding=BrowserToolkit._binding_hash_for_element(
            element,
            current_url=source_url,
            submit=False,
        ),
    )

    assert clicked["ok"] is True
    assert clicked["url"] == actual_url
    assert clicked["action"] == "click"


@pytest.mark.asyncio
async def test_gh24_browser_type_click_confirmation_allows_same_document_fragment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = _CapturingSuccessRunner()
    toolkit = _toolkit(tmp_path, runner=runner)
    session = _session()
    source_url = "http://example.test/"
    field = BrowserSnapshotElement(
        ref="e1",
        kind="field",
        label="search",
        selector="#search",
    )
    click_element = BrowserSnapshotElement(
        ref="e2",
        kind="link",
        label="Jump",
        selector="#jump",
        href="#details",
    )
    toolkit._save_state(session, {"opened": True, "current_url": source_url})

    async def load_snapshot(**_: Any) -> list[BrowserSnapshotElement]:
        return [field, click_element]

    async def run_cli(**_: Any) -> dict[str, Any] | None:
        return None

    async def capture_page_state(**_: Any) -> dict[str, Any]:
        return {
            "ok": True,
            "url": "http://example.test/#details",
            "title": "Same Page",
            "content": "",
            "snapshot": "",
            "taint_labels": [TaintLabel.UNTRUSTED.value],
            "error": "",
        }

    monkeypatch.setattr(toolkit, "_load_interaction_snapshot", load_snapshot)
    monkeypatch.setattr(toolkit, "_run_cli", run_cli)
    monkeypatch.setattr(toolkit, "_capture_page_state", capture_page_state)

    typed = await toolkit.type_text(
        session=session,
        target="#search",
        resolved_target="#search",
        text="hello",
        click_target="#jump",
        resolved_click_target="#jump",
        source_url=source_url,
        click_source_binding=BrowserToolkit._binding_hash_for_element(
            click_element,
            current_url=source_url,
            submit=False,
        ),
    )

    assert typed["ok"] is True
    assert typed["url"] == "http://example.test/#details"
    assert typed["action"] == "type_text"
    assert typed["click_target"] == "#jump"


@pytest.mark.asyncio
async def test_gh24_browser_click_submit_allows_same_document_fragment_query(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = _CapturingSuccessRunner()
    toolkit = _toolkit(tmp_path, runner=runner)
    session = _session()
    source_url = "http://example.test/"
    element = BrowserSnapshotElement(
        ref="e1",
        kind="button",
        label="Submit",
        selector="#submit",
        form_action="#details",
        form_method="get",
    )
    toolkit._save_state(session, {"opened": True, "current_url": source_url})

    async def load_snapshot(**_: Any) -> list[BrowserSnapshotElement]:
        return [element]

    async def run_cli(**_: Any) -> dict[str, Any] | None:
        return None

    async def capture_page_state(**_: Any) -> dict[str, Any]:
        return {
            "ok": True,
            "url": "http://example.test/?q=hello#details",
            "title": "Same Page",
            "content": "",
            "snapshot": "",
            "taint_labels": [TaintLabel.UNTRUSTED.value],
            "error": "",
        }

    monkeypatch.setattr(toolkit, "_load_interaction_snapshot", load_snapshot)
    monkeypatch.setattr(toolkit, "_run_cli", run_cli)
    monkeypatch.setattr(toolkit, "_capture_page_state", capture_page_state)

    clicked = await toolkit.click(
        session=session,
        target="#submit",
        resolved_target="#submit",
        source_url=source_url,
        source_binding=BrowserToolkit._binding_hash_for_element(
            element,
            current_url=source_url,
            submit=False,
        ),
    )

    assert clicked["ok"] is True
    assert clicked["url"] == "http://example.test/?q=hello#details"
    assert clicked["action"] == "click"


@pytest.mark.asyncio
async def test_gh24_browser_type_submit_allows_same_document_fragment_query(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = _CapturingSuccessRunner()
    toolkit = _toolkit(tmp_path, runner=runner)
    session = _session()
    source_url = "http://example.test/"
    element = BrowserSnapshotElement(
        ref="e1",
        kind="field",
        label="search",
        selector="#search",
        form_action="#details",
        form_method="get",
    )
    toolkit._save_state(session, {"opened": True, "current_url": source_url})

    async def load_snapshot(**_: Any) -> list[BrowserSnapshotElement]:
        return [element]

    async def run_cli(**_: Any) -> dict[str, Any] | None:
        return None

    async def capture_page_state(**_: Any) -> dict[str, Any]:
        return {
            "ok": True,
            "url": "http://example.test/?q=hello#details",
            "title": "Same Page",
            "content": "",
            "snapshot": "",
            "taint_labels": [TaintLabel.UNTRUSTED.value],
            "error": "",
        }

    monkeypatch.setattr(toolkit, "_load_interaction_snapshot", load_snapshot)
    monkeypatch.setattr(toolkit, "_run_cli", run_cli)
    monkeypatch.setattr(toolkit, "_capture_page_state", capture_page_state)

    typed = await toolkit.type_text(
        session=session,
        target="#search",
        resolved_target="#search",
        text="hello",
        submit=True,
        source_url=source_url,
        source_binding=BrowserToolkit._binding_hash_for_element(
            element,
            current_url=source_url,
            submit=True,
        ),
    )

    assert typed["ok"] is True
    assert typed["url"] == "http://example.test/?q=hello#details"
    assert typed["action"] == "type_text"


@pytest.mark.asyncio
async def test_gh24_browser_type_submit_rejects_post_action_destination_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = _CapturingSuccessRunner()
    toolkit = _toolkit(tmp_path, runner=runner)
    session = _session()
    source_url = "http://example.test/"
    selector = "#search"
    element = BrowserSnapshotElement(
        ref="e2",
        kind="field",
        label="search",
        selector=selector,
        form_action="/submitted",
        form_method="get",
    )
    toolkit._save_state(session, {"opened": True, "current_url": source_url})

    async def load_snapshot(**_: Any) -> list[BrowserSnapshotElement]:
        return [element]

    async def run_cli(**_: Any) -> dict[str, Any] | None:
        return None

    async def capture_page_state(**_: Any) -> dict[str, Any]:
        return {
            "ok": True,
            "url": "http://example.test/elsewhere",
            "title": "Elsewhere",
            "content": "",
            "snapshot": "",
            "taint_labels": [TaintLabel.UNTRUSTED.value],
            "error": "",
        }

    monkeypatch.setattr(toolkit, "_load_interaction_snapshot", load_snapshot)
    monkeypatch.setattr(toolkit, "_run_cli", run_cli)
    monkeypatch.setattr(toolkit, "_capture_page_state", capture_page_state)

    blocked = await toolkit.type_text(
        session=session,
        target=selector,
        resolved_target=selector,
        text="hello",
        submit=True,
        destination="http://example.test/submitted",
        source_url=source_url,
        source_binding=BrowserToolkit._binding_hash_for_element(
            element,
            current_url=source_url,
            submit=True,
        ),
    )

    assert blocked == {
        "ok": False,
        "error": "browser_confirmation_context_changed",
        "taint_labels": [],
    }
    assert toolkit.current_state(session=session) == {"opened": False, "current_url": ""}


@pytest.mark.asyncio
async def test_m6_browser_toolkit_click_confirmation_fails_if_page_changed_after_prepare(
    tmp_path: Path,
    browser_fixture_server: _FixtureServer,
) -> None:
    runner = _DirectRunner()
    toolkit = _toolkit(tmp_path, runner=runner)
    session = _session()

    opened = await toolkit.navigate(session=session, url=f"{browser_fixture_server.base_url}/")
    assert opened["ok"] is True
    prepared = await toolkit.prepare_action_arguments(
        session=session,
        tool_name="browser.click",
        arguments={"target": "the continue button in the browser"},
    )
    assert prepared["source_url"] == f"{browser_fixture_server.base_url}/"

    moved = await toolkit.navigate(session=session, url=f"{browser_fixture_server.base_url}/next")
    assert moved["ok"] is True
    config_count = len(runner.configs)

    blocked = await toolkit.click(
        session=session,
        target=str(prepared["target"]),
        resolved_target=str(prepared["resolved_target"]),
        destination=str(prepared["destination"]),
        source_url=str(prepared["source_url"]),
    )

    assert blocked == {
        "ok": False,
        "error": "browser_confirmation_context_changed",
        "taint_labels": [],
    }
    assert len(runner.configs) == config_count


@pytest.mark.asyncio
async def test_m6_browser_toolkit_click_confirmation_fails_if_bound_element_changes_at_same_url(
    tmp_path: Path,
) -> None:
    state = {"link_href": "/next-a"}
    browser_server = _start_fixture_server(state=state)
    try:
        runner = _DirectRunner()
        toolkit = _toolkit(tmp_path, runner=runner)
        session = _session()

        opened = await toolkit.navigate(session=session, url=f"{browser_server.base_url}/")
        assert opened["ok"] is True
        prepared = await toolkit.prepare_action_arguments(
            session=session,
            tool_name="browser.click",
            arguments={"target": "the continue button in the browser"},
        )

        assert str(prepared["destination"]).endswith("/next-a")
        assert str(prepared.get("source_binding", "")).strip()

        state["link_href"] = "/next-b"
        config_count = len(runner.configs)

        blocked = await toolkit.click(
            session=session,
            target=str(prepared["target"]),
            resolved_target=str(prepared["resolved_target"]),
            destination=str(prepared["destination"]),
            source_url=str(prepared["source_url"]),
            source_binding=str(prepared["source_binding"]),
        )

        assert blocked == {
            "ok": False,
            "error": "browser_confirmation_context_changed",
            "taint_labels": [],
        }
        new_configs = runner.configs[config_count:]
        assert new_configs
        assert not any("click" in config.command for config in new_configs)
        assert toolkit._current_url(session) == f"{browser_server.base_url}/"
    finally:
        browser_server.close()


@pytest.mark.asyncio
async def test_m6_browser_toolkit_click_confirmation_allows_same_url_sibling_reordering(
    tmp_path: Path,
) -> None:
    state = {"link_href": "/next-a"}
    browser_server = _start_fixture_server(state=state)
    try:
        runner = _DirectRunner()
        toolkit = _toolkit(tmp_path, runner=runner)
        session = _session()

        opened = await toolkit.navigate(session=session, url=f"{browser_server.base_url}/")
        assert opened["ok"] is True
        prepared = await toolkit.prepare_action_arguments(
            session=session,
            tool_name="browser.click",
            arguments={"target": "the continue button in the browser"},
        )

        assert str(prepared["destination"]).endswith("/next-a")
        assert str(prepared.get("source_binding", "")).strip()

        state["prefix_html"] = "<a id='noise' href='/noise'>Noise</a>"

        clicked = await toolkit.click(
            session=session,
            target=str(prepared["target"]),
            resolved_target=str(prepared["resolved_target"]),
            destination=str(prepared["destination"]),
            source_url=str(prepared["source_url"]),
            source_binding=str(prepared["source_binding"]),
        )

        assert clicked["ok"] is True
        assert clicked["url"] == f"{browser_server.base_url}/next-a"
        assert clicked["destination"] == f"{browser_server.base_url}/next-a"
    finally:
        browser_server.close()


@pytest.mark.asyncio
async def test_m6_browser_toolkit_click_carries_cross_host_destination_into_post_action_capture(
    tmp_path: Path,
) -> None:
    destination_server = _start_fixture_server(host="127.0.0.2")
    source_server = _start_fixture_server(
        host="127.0.0.1",
        link_href=f"{destination_server.base_url}/next",
    )
    try:
        runner = _PolicyScopedRunner()
        toolkit = _toolkit(tmp_path, runner=runner, allowed_domains=["127.0.0.1"])
        session = _session()

        opened = await toolkit.navigate(session=session, url=f"{source_server.base_url}/")
        assert opened["ok"] is True
        prepared = await toolkit.prepare_action_arguments(
            session=session,
            tool_name="browser.click",
            arguments={"target": "the continue button in the browser"},
        )

        clicked = await toolkit.click(
            session=session,
            target=str(prepared["target"]),
            resolved_target=str(prepared["resolved_target"]),
            destination=str(prepared["destination"]),
            source_url=str(prepared["source_url"]),
            source_binding=str(prepared["source_binding"]),
        )

        assert clicked["ok"] is True
        assert clicked["url"] == f"{destination_server.base_url}/next"
    finally:
        source_server.close()
        destination_server.close()


@pytest.mark.asyncio
async def test_m6_browser_toolkit_submit_carries_cross_host_destination_into_post_action_capture(
    tmp_path: Path,
) -> None:
    destination_server = _start_fixture_server(host="127.0.0.2")
    source_server = _start_fixture_server(
        host="127.0.0.1",
        form_action=f"{destination_server.base_url}/submitted",
    )
    try:
        runner = _PolicyScopedRunner()
        toolkit = _toolkit(tmp_path, runner=runner, allowed_domains=["127.0.0.1"])
        session = _session()

        opened = await toolkit.navigate(session=session, url=f"{source_server.base_url}/")
        assert opened["ok"] is True
        prepared = await toolkit.prepare_action_arguments(
            session=session,
            tool_name="browser.type_text",
            arguments={"target": "#search", "text": "hello", "submit": True},
        )

        typed = await toolkit.type_text(
            session=session,
            target=str(prepared["target"]),
            text="hello",
            submit=True,
            destination=str(prepared["destination"]),
            source_url=str(prepared["source_url"]),
            source_binding=str(prepared["source_binding"]),
        )

        assert typed["ok"] is True
        assert typed["url"].startswith(f"{destination_server.base_url}/submitted")
        assert "q=hello" in typed["url"]
    finally:
        source_server.close()
        destination_server.close()


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


@pytest.mark.asyncio
async def test_gh25_browser_toolkit_mounts_symlinked_playwright_dependency_and_cache(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("PLAYWRIGHT_BROWSERS_PATH", raising=False)
    node_modules = tmp_path / "app" / "node_modules"
    bin_dir = node_modules / ".bin"
    target_dir = node_modules / "@playwright" / "test"
    bin_dir.mkdir(parents=True)
    target_dir.mkdir(parents=True)
    target = target_dir / "cli.js"
    target.write_text("#!/usr/bin/env node\n", encoding="utf-8")
    target.chmod(0o755)
    command = bin_dir / "playwright-cli"
    command.symlink_to("../@playwright/test/cli.js")
    runner = _CapturingSuccessRunner()
    toolkit = _toolkit(tmp_path, runner=runner, command=[str(command)])

    result = await toolkit._run_cli(
        session=_session(),
        tool_name="browser.navigate",
        args=["open"],
        network_urls=[],
        allow_network=False,
    )

    assert result is None
    assert len(runner.configs) == 1
    config = runner.configs[0]
    cache_dir = home / ".cache" / "ms-playwright"
    mounts = {mount.path: mount.mode for mount in config.filesystem.mounts}
    assert str(node_modules) in config.read_paths
    assert mounts[str(node_modules)] == "ro"
    assert str(cache_dir) in config.write_paths
    assert mounts[str(cache_dir)] == "rw"
    assert config.env["PLAYWRIGHT_BROWSERS_PATH"] == str(cache_dir)
    assert "PLAYWRIGHT_BROWSERS_PATH" in config.environment.allowed_keys


@pytest.mark.asyncio
async def test_gh25_browser_toolkit_mounts_external_wrapper_path_and_parent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    wrapper_dir = tmp_path / "external-wrapper" / "bin"
    wrapper_dir.mkdir(parents=True)
    wrapper = wrapper_dir / "playwright-wrapper"
    wrapper.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    wrapper.chmod(0o755)
    runner = _CapturingSuccessRunner()
    toolkit = _toolkit(tmp_path, runner=runner, command=[str(wrapper)])

    result = await toolkit._run_cli(
        session=_session(),
        tool_name="browser.navigate",
        args=["open"],
        network_urls=[],
        allow_network=False,
    )

    assert result is None
    assert len(runner.configs) == 1
    config = runner.configs[0]
    mounts = {mount.path: mount.mode for mount in config.filesystem.mounts}
    assert str(wrapper) in config.read_paths
    assert str(wrapper_dir) in config.read_paths
    assert mounts[str(wrapper)] == "ro"
    assert mounts[str(wrapper_dir)] == "ro"


@pytest.mark.asyncio
async def test_gh25_browser_toolkit_mounts_external_symlink_wrapper_and_realpath(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    real_dir = tmp_path / "external-real" / "bin"
    real_dir.mkdir(parents=True)
    real_wrapper = real_dir / "playwright-wrapper"
    real_wrapper.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    real_wrapper.chmod(0o755)
    link_dir = tmp_path / "external-link" / "bin"
    link_dir.mkdir(parents=True)
    wrapper_link = link_dir / "playwright-wrapper"
    wrapper_link.symlink_to(real_wrapper)
    runner = _CapturingSuccessRunner()
    toolkit = _toolkit(tmp_path, runner=runner, command=[str(wrapper_link)])

    result = await toolkit._run_cli(
        session=_session(),
        tool_name="browser.navigate",
        args=["open"],
        network_urls=[],
        allow_network=False,
    )

    assert result is None
    assert len(runner.configs) == 1
    config = runner.configs[0]
    mounts = {mount.path: mount.mode for mount in config.filesystem.mounts}
    for path in (wrapper_link, link_dir, real_wrapper, real_dir):
        assert str(path) in config.read_paths
        assert mounts[str(path)] == "ro"


@pytest.mark.asyncio
async def test_gh25_browser_toolkit_absolutizes_relative_command_and_file_args(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    app_dir = tmp_path / "app"
    app_dir.mkdir()
    wrapper = app_dir / "wrapper.py"
    wrapper.write_text("print('ok')\n", encoding="utf-8")
    monkeypatch.chdir(app_dir)
    runner = _CapturingSuccessRunner()
    toolkit = _toolkit(tmp_path, runner=runner, command=[sys.executable, "wrapper.py"])

    result = await toolkit._run_cli(
        session=_session(),
        tool_name="browser.navigate",
        args=["open"],
        network_urls=[],
        allow_network=False,
    )

    assert result is None
    assert len(runner.configs) == 1
    config = runner.configs[0]
    assert config.command[:2] == [sys.executable, str(wrapper)]
    assert str(app_dir) in config.read_paths


@pytest.mark.asyncio
async def test_gh25_browser_toolkit_preserves_non_path_command_arg_values(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    app_dir = tmp_path / "app"
    app_dir.mkdir()
    (app_dir / "tests").mkdir()
    monkeypatch.chdir(app_dir)
    fixture_cli = Path(__file__).resolve().parents[1] / "fixtures" / "fake_playwright_cli.py"
    runner = _CapturingSuccessRunner()
    toolkit = _toolkit(
        tmp_path,
        runner=runner,
        command=[sys.executable, "-m", "tests", str(fixture_cli), "--project", "tests"],
    )

    result = await toolkit._run_cli(
        session=_session(),
        tool_name="browser.navigate",
        args=["open"],
        network_urls=[],
        allow_network=False,
    )

    assert result is None
    assert len(runner.configs) == 1
    config = runner.configs[0]
    assert config.command[:6] == [
        sys.executable,
        "-m",
        "tests",
        str(fixture_cli),
        "--project",
        "tests",
    ]
    assert str(app_dir / "tests") not in config.read_paths


@pytest.mark.asyncio
async def test_gh25_browser_toolkit_absolutizes_path_valued_flag_args(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    app_dir = tmp_path / "app"
    app_dir.mkdir()
    register = app_dir / "register.js"
    register.write_text("module.exports = {}\n", encoding="utf-8")
    config_path = app_dir / "playwright.config.js"
    config_path.write_text("module.exports = {}\n", encoding="utf-8")
    (app_dir / "tests").mkdir()
    monkeypatch.chdir(app_dir)
    runner = _CapturingSuccessRunner()
    toolkit = _toolkit(
        tmp_path,
        runner=runner,
        command=[
            sys.executable,
            "--require",
            "register.js",
            "--config=playwright.config.js",
            "--project",
            "tests",
        ],
    )

    result = await toolkit._run_cli(
        session=_session(),
        tool_name="browser.navigate",
        args=["open"],
        network_urls=[],
        allow_network=False,
    )

    assert result is None
    assert len(runner.configs) == 1
    config = runner.configs[0]
    assert config.command[:6] == [
        sys.executable,
        "--require",
        str(register),
        f"--config={config_path}",
        "--project",
        "tests",
    ]
    assert str(app_dir) in config.read_paths
    assert str(app_dir / "tests") not in config.read_paths


@pytest.mark.asyncio
async def test_gh25_browser_toolkit_preserves_code_bearing_interpreter_flag_values(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    node_bin = tmp_path / "node-home" / "bin"
    node_bin.mkdir(parents=True)
    node = node_bin / "node"
    node.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    node.chmod(0o755)
    monkeypatch.setenv("PATH", str(node_bin))
    app_dir = tmp_path / "app"
    app_dir.mkdir()
    for filename in ["wrapper.js", "snippet.js", "register.js", "printable.js"]:
        (app_dir / filename).write_text("console.log('ok')\n", encoding="utf-8")
    monkeypatch.chdir(app_dir)
    runner = _CapturingSuccessRunner()
    toolkit = _toolkit(
        tmp_path,
        runner=runner,
        command=[
            "node",
            "-e",
            "wrapper.js",
            "--eval",
            "./snippet.js",
            "-p",
            "printable.js",
            "--require",
            "register.js",
        ],
    )

    result = await toolkit._run_cli(
        session=_session(),
        tool_name="browser.navigate",
        args=["open"],
        network_urls=[],
        allow_network=False,
    )

    assert result is None
    assert len(runner.configs) == 1
    config = runner.configs[0]
    assert config.command[:9] == [
        str(node),
        "-e",
        "wrapper.js",
        "--eval",
        "./snippet.js",
        "-p",
        "printable.js",
        "--require",
        str(app_dir / "register.js"),
    ]
    assert str(app_dir) in config.read_paths


@pytest.mark.asyncio
async def test_gh25_browser_toolkit_absolutizes_short_flag_paths_for_custom_wrappers(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    app_dir = tmp_path / "app"
    app_dir.mkdir()
    wrapper = app_dir / "custom-playwright-wrapper"
    wrapper.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    wrapper.chmod(0o755)
    plugin = app_dir / "plugin.js"
    plugin.write_text("module.exports = {}\n", encoding="utf-8")
    entry = app_dir / "entry.js"
    entry.write_text("module.exports = {}\n", encoding="utf-8")
    monkeypatch.chdir(app_dir)
    runner = _CapturingSuccessRunner()
    toolkit = _toolkit(
        tmp_path,
        runner=runner,
        command=[str(wrapper), "-p", "plugin.js", "-e", "entry.js"],
    )

    result = await toolkit._run_cli(
        session=_session(),
        tool_name="browser.navigate",
        args=["open"],
        network_urls=[],
        allow_network=False,
    )

    assert result is None
    assert len(runner.configs) == 1
    config = runner.configs[0]
    assert config.command[:5] == [
        str(wrapper),
        "-p",
        str(plugin),
        "-e",
        str(entry),
    ]
    assert str(app_dir) in config.read_paths


@pytest.mark.asyncio
async def test_gh25_browser_toolkit_preserves_hermetic_playwright_browsers_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home = tmp_path / "home"
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("PLAYWRIGHT_BROWSERS_PATH", "0")
    runner = _CapturingSuccessRunner()
    toolkit = _toolkit(tmp_path, runner=runner)

    result = await toolkit._run_cli(
        session=_session(),
        tool_name="browser.navigate",
        args=["open"],
        network_urls=[],
        allow_network=False,
    )

    assert result is None
    assert len(runner.configs) == 1
    config = runner.configs[0]
    assert config.env["PLAYWRIGHT_BROWSERS_PATH"] == "0"
    assert str(home / ".cache" / "ms-playwright") not in config.write_paths
    assert not (home / ".cache").exists()


@pytest.mark.asyncio
async def test_gh25_browser_toolkit_preserves_code_flags_for_symlinked_node(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    node_bin = tmp_path / "node-home" / "bin"
    node_bin.mkdir(parents=True)
    node = node_bin / "node"
    node.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    node.chmod(0o755)
    app_dir = tmp_path / "app"
    app_dir.mkdir()
    node_link = app_dir / "node-link"
    node_link.symlink_to(node)
    register = app_dir / "register.js"
    register.write_text("module.exports = {}\n", encoding="utf-8")
    entry = app_dir / "entry.js"
    entry.write_text("console.log('ok')\n", encoding="utf-8")
    monkeypatch.chdir(app_dir)
    runner = _CapturingSuccessRunner()
    toolkit = _toolkit(
        tmp_path,
        runner=runner,
        command=[str(node_link), "-e", "entry.js", "--require", "register.js"],
    )

    result = await toolkit._run_cli(
        session=_session(),
        tool_name="browser.navigate",
        args=["open"],
        network_urls=[],
        allow_network=False,
    )

    assert result is None
    assert len(runner.configs) == 1
    config = runner.configs[0]
    assert config.command[:5] == [
        str(node_link),
        "-e",
        "entry.js",
        "--require",
        str(register),
    ]
    assert str(node_bin) in config.read_paths
    assert str(app_dir) in config.read_paths


@pytest.mark.asyncio
async def test_gh25_browser_toolkit_preserves_code_flags_for_env_node_launcher(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    system_bin = tmp_path / "system" / "bin"
    system_bin.mkdir(parents=True)
    env = system_bin / "env"
    env.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    env.chmod(0o755)
    node_bin = tmp_path / "node-home" / "bin"
    node_bin.mkdir(parents=True)
    node = node_bin / "node"
    node.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    node.chmod(0o755)
    monkeypatch.setenv("PATH", str(node_bin))
    app_dir = tmp_path / "app"
    app_dir.mkdir()
    register = app_dir / "register.js"
    register.write_text("module.exports = {}\n", encoding="utf-8")
    entry = app_dir / "entry.js"
    entry.write_text("console.log('ok')\n", encoding="utf-8")
    monkeypatch.chdir(app_dir)
    runner = _CapturingSuccessRunner()
    toolkit = _toolkit(
        tmp_path,
        runner=runner,
        command=[str(env), "node", "-e", "entry.js", "--require", "register.js"],
    )

    result = await toolkit._run_cli(
        session=_session(),
        tool_name="browser.navigate",
        args=["open"],
        network_urls=[],
        allow_network=False,
    )

    assert result is None
    assert len(runner.configs) == 1
    config = runner.configs[0]
    assert config.command[:6] == [
        str(env),
        "node",
        "-e",
        "entry.js",
        "--require",
        str(register),
    ]
    assert str(node_bin) in config.read_paths
    assert str(app_dir) in config.read_paths


@pytest.mark.asyncio
async def test_gh25_browser_toolkit_mounts_env_launcher_script_shebang_interpreter(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    system_bin = tmp_path / "system" / "bin"
    system_bin.mkdir(parents=True)
    env = system_bin / "env"
    env.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    env.chmod(0o755)
    node_bin = tmp_path / "node-home" / "bin"
    node_bin.mkdir(parents=True)
    node = node_bin / "node"
    node.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    node.chmod(0o755)
    app_dir = tmp_path / "app"
    node_modules = app_dir / "node_modules"
    bin_dir = node_modules / ".bin"
    target_dir = node_modules / "@playwright" / "test"
    bin_dir.mkdir(parents=True)
    target_dir.mkdir(parents=True)
    target = target_dir / "cli.js"
    target.write_text("#!/usr/bin/env node\n", encoding="utf-8")
    target.chmod(0o755)
    command = bin_dir / "playwright-cli"
    command.symlink_to("../@playwright/test/cli.js")
    monkeypatch.setenv("PATH", os.pathsep.join([str(bin_dir), str(node_bin)]))
    runner = _CapturingSuccessRunner()
    toolkit = _toolkit(tmp_path, runner=runner, command=[str(env), "playwright-cli"])

    result = await toolkit._run_cli(
        session=_session(),
        tool_name="browser.navigate",
        args=["open"],
        network_urls=[],
        allow_network=False,
    )

    assert result is None
    assert len(runner.configs) == 1
    config = runner.configs[0]
    assert config.command[:2] == [str(env), "playwright-cli"]
    assert str(node_modules) in config.read_paths
    assert str(node_bin) in config.read_paths


@pytest.mark.asyncio
async def test_gh25_browser_toolkit_env_parser_handles_options_and_path_assignment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    system_bin = tmp_path / "system" / "bin"
    system_bin.mkdir(parents=True)
    env = system_bin / "env"
    env.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    env.chmod(0o755)
    ambient_node_bin = tmp_path / "ambient-node" / "bin"
    ambient_node_bin.mkdir(parents=True)
    ambient_node = ambient_node_bin / "node"
    ambient_node.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    ambient_node.chmod(0o755)
    assigned_node_bin = tmp_path / "assigned-node" / "bin"
    assigned_node_bin.mkdir(parents=True)
    assigned_node = assigned_node_bin / "node"
    assigned_node.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    assigned_node.chmod(0o755)
    monkeypatch.setenv("PATH", str(ambient_node_bin))
    app_dir = tmp_path / "app"
    app_dir.mkdir()
    register = app_dir / "register.js"
    register.write_text("module.exports = {}\n", encoding="utf-8")
    entry = app_dir / "entry.js"
    entry.write_text("console.log('ok')\n", encoding="utf-8")
    monkeypatch.chdir(app_dir)
    runner = _CapturingSuccessRunner()
    toolkit = _toolkit(
        tmp_path,
        runner=runner,
        command=[
            str(env),
            "-u",
            "NODE_OPTIONS",
            "-C",
            str(app_dir),
            f"PATH={assigned_node_bin}",
            "node",
            "-e",
            "entry.js",
            "--require",
            "register.js",
        ],
    )

    result = await toolkit._run_cli(
        session=_session(),
        tool_name="browser.navigate",
        args=["open"],
        network_urls=[],
        allow_network=False,
    )

    assert result is None
    assert len(runner.configs) == 1
    config = runner.configs[0]
    assert config.command[:10] == [
        str(env),
        "-u",
        "NODE_OPTIONS",
        "-C",
        str(app_dir),
        f"PATH={assigned_node_bin}",
        "node",
        "-e",
        "entry.js",
        "--require",
    ]
    assert config.command[10] == str(register)
    assert str(assigned_node_bin) in config.read_paths
    assert str(ambient_node_bin) not in config.read_paths
    assert str(app_dir) in config.read_paths


@pytest.mark.asyncio
async def test_gh25_browser_toolkit_env_path_flows_into_script_shebang(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    system_bin = tmp_path / "system" / "bin"
    system_bin.mkdir(parents=True)
    env = system_bin / "env"
    env.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    env.chmod(0o755)
    node_bin = tmp_path / "node-home" / "bin"
    node_bin.mkdir(parents=True)
    node = node_bin / "node"
    node.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    node.chmod(0o755)
    app_dir = tmp_path / "app"
    node_modules = app_dir / "node_modules"
    bin_dir = node_modules / ".bin"
    target_dir = node_modules / "@playwright" / "test"
    bin_dir.mkdir(parents=True)
    target_dir.mkdir(parents=True)
    target = target_dir / "cli.js"
    target.write_text("#!/usr/bin/env node\n", encoding="utf-8")
    target.chmod(0o755)
    command = bin_dir / "playwright-cli"
    command.symlink_to("../@playwright/test/cli.js")
    monkeypatch.setenv("PATH", str(system_bin))
    runner = _CapturingSuccessRunner()
    toolkit = _toolkit(
        tmp_path,
        runner=runner,
        command=[
            str(env),
            f"PATH={os.pathsep.join([str(bin_dir), str(node_bin)])}",
            "playwright-cli",
        ],
    )

    result = await toolkit._run_cli(
        session=_session(),
        tool_name="browser.navigate",
        args=["open"],
        network_urls=[],
        allow_network=False,
    )

    assert result is None
    assert len(runner.configs) == 1
    config = runner.configs[0]
    assert str(node_modules) in config.read_paths
    assert str(node_bin) in config.read_paths


@pytest.mark.asyncio
async def test_gh25_browser_toolkit_env_chdir_resolves_relative_target_and_args(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    system_bin = tmp_path / "system" / "bin"
    system_bin.mkdir(parents=True)
    env = system_bin / "env"
    env.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    env.chmod(0o755)
    app_dir = tmp_path / "app"
    node_modules = app_dir / "node_modules"
    bin_dir = node_modules / ".bin"
    bin_dir.mkdir(parents=True)
    command = bin_dir / "playwright-cli"
    command.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    command.chmod(0o755)
    config_path = app_dir / "playwright.config.js"
    config_path.write_text("module.exports = {}\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    runner = _CapturingSuccessRunner()
    toolkit = _toolkit(
        tmp_path,
        runner=runner,
        command=[
            str(env),
            "-C",
            str(app_dir),
            "./node_modules/.bin/playwright-cli",
            "--config",
            "playwright.config.js",
        ],
    )

    result = await toolkit._run_cli(
        session=_session(),
        tool_name="browser.navigate",
        args=["open"],
        network_urls=[],
        allow_network=False,
    )

    assert result is None
    assert len(runner.configs) == 1
    config = runner.configs[0]
    assert config.command[:6] == [
        str(env),
        "-C",
        str(app_dir),
        str(command),
        "--config",
        str(config_path),
    ]
    assert str(node_modules) in config.read_paths
    assert str(app_dir) in config.read_paths


@pytest.mark.asyncio
async def test_gh25_browser_toolkit_env_relative_chdir_is_absolutized(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    system_bin = tmp_path / "system" / "bin"
    system_bin.mkdir(parents=True)
    env = system_bin / "env"
    env.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    env.chmod(0o755)
    app_dir = tmp_path / "app"
    node_modules = app_dir / "node_modules"
    bin_dir = node_modules / ".bin"
    bin_dir.mkdir(parents=True)
    command = bin_dir / "playwright-cli"
    command.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    command.chmod(0o755)
    monkeypatch.chdir(tmp_path)
    runner = _CapturingSuccessRunner()
    toolkit = _toolkit(
        tmp_path,
        runner=runner,
        command=[str(env), "-C", "app", "./node_modules/.bin/playwright-cli"],
    )

    result = await toolkit._run_cli(
        session=_session(),
        tool_name="browser.navigate",
        args=["open"],
        network_urls=[],
        allow_network=False,
    )

    assert result is None
    assert len(runner.configs) == 1
    config = runner.configs[0]
    assert config.command[:4] == [str(env), "-C", str(app_dir), str(command)]
    assert str(node_modules) in config.read_paths


@pytest.mark.asyncio
async def test_gh25_browser_toolkit_env_chdir_resolves_relative_path_assignment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    system_bin = tmp_path / "system" / "bin"
    system_bin.mkdir(parents=True)
    env = system_bin / "env"
    env.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    env.chmod(0o755)
    app_dir = tmp_path / "app"
    node_modules = app_dir / "node_modules"
    bin_dir = node_modules / ".bin"
    bin_dir.mkdir(parents=True)
    command = bin_dir / "playwright-cli"
    command.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    command.chmod(0o755)
    monkeypatch.chdir(tmp_path)
    runner = _CapturingSuccessRunner()
    toolkit = _toolkit(
        tmp_path,
        runner=runner,
        command=[str(env), "-C", "app", "PATH=node_modules/.bin", "playwright-cli"],
    )

    result = await toolkit._run_cli(
        session=_session(),
        tool_name="browser.navigate",
        args=["open"],
        network_urls=[],
        allow_network=False,
    )

    assert result is None
    assert len(runner.configs) == 1
    config = runner.configs[0]
    assert config.command[:5] == [
        str(env),
        "-C",
        str(app_dir),
        f"PATH={bin_dir}",
        "playwright-cli",
    ]
    assert str(node_modules) in config.read_paths


@pytest.mark.asyncio
async def test_gh25_browser_toolkit_env_split_string_normalizes_relative_paths(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    system_bin = tmp_path / "system" / "bin"
    system_bin.mkdir(parents=True)
    env = system_bin / "env"
    env.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    env.chmod(0o755)
    app_dir = tmp_path / "app"
    node_modules = app_dir / "node_modules"
    bin_dir = node_modules / ".bin"
    bin_dir.mkdir(parents=True)
    command = bin_dir / "playwright-cli"
    command.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    command.chmod(0o755)
    config_path = app_dir / "playwright.config.js"
    config_path.write_text("module.exports = {}\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    runner = _CapturingSuccessRunner()
    toolkit = _toolkit(
        tmp_path,
        runner=runner,
        command=[
            str(env),
            "-S",
            "-C app ./node_modules/.bin/playwright-cli --config playwright.config.js",
        ],
    )

    result = await toolkit._run_cli(
        session=_session(),
        tool_name="browser.navigate",
        args=["open"],
        network_urls=[],
        allow_network=False,
    )

    assert result is None
    assert len(runner.configs) == 1
    config = runner.configs[0]
    assert config.command[:3] == [
        str(env),
        "-S",
        shlex.join(
            [
                "-C",
                str(app_dir),
                str(command),
                "--config",
                str(config_path),
            ]
        ),
    ]
    assert str(node_modules) in config.read_paths
    assert str(app_dir) in config.read_paths


@pytest.mark.asyncio
async def test_gh25_browser_toolkit_non_env_short_s_flag_still_resolves_wrapper_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    app_dir = tmp_path / "app"
    app_dir.mkdir()
    wrapper = app_dir / "wrapper.py"
    wrapper.write_text("print('ok')\n", encoding="utf-8")
    monkeypatch.chdir(app_dir)
    runner = _CapturingSuccessRunner()
    toolkit = _toolkit(
        tmp_path,
        runner=runner,
        command=[sys.executable, "-S", "wrapper.py"],
    )

    result = await toolkit._run_cli(
        session=_session(),
        tool_name="browser.navigate",
        args=["open"],
        network_urls=[],
        allow_network=False,
    )

    assert result is None
    assert len(runner.configs) == 1
    config = runner.configs[0]
    assert config.command[:3] == [sys.executable, "-S", str(wrapper)]
    assert str(app_dir) in config.read_paths


@pytest.mark.asyncio
async def test_gh25_browser_toolkit_preserves_path_assignment_after_env_target(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    system_bin = tmp_path / "system" / "bin"
    system_bin.mkdir(parents=True)
    env = system_bin / "env"
    env.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    env.chmod(0o755)
    app_dir = tmp_path / "app"
    app_dir.mkdir()
    monkeypatch.chdir(app_dir)
    runner = _CapturingSuccessRunner()
    toolkit = _toolkit(
        tmp_path,
        runner=runner,
        command=[str(env), sys.executable, "PATH=node_modules/.bin"],
    )

    result = await toolkit._run_cli(
        session=_session(),
        tool_name="browser.navigate",
        args=["open"],
        network_urls=[],
        allow_network=False,
    )

    assert result is None
    assert len(runner.configs) == 1
    config = runner.configs[0]
    assert config.command[:3] == [str(env), sys.executable, "PATH=node_modules/.bin"]


@pytest.mark.asyncio
async def test_gh25_browser_toolkit_preserves_path_assignment_for_non_env_wrapper(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    app_dir = tmp_path / "app"
    app_dir.mkdir()
    wrapper = app_dir / "custom-playwright-wrapper"
    wrapper.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    wrapper.chmod(0o755)
    monkeypatch.chdir(app_dir)
    runner = _CapturingSuccessRunner()
    toolkit = _toolkit(
        tmp_path,
        runner=runner,
        command=[str(wrapper), "PATH=node_modules/.bin"],
    )

    result = await toolkit._run_cli(
        session=_session(),
        tool_name="browser.navigate",
        args=["open"],
        network_urls=[],
        allow_network=False,
    )

    assert result is None
    assert len(runner.configs) == 1
    config = runner.configs[0]
    assert config.command[:2] == [str(wrapper), "PATH=node_modules/.bin"]


@pytest.mark.asyncio
async def test_gh25_browser_toolkit_env_prefix_boundary_uses_target_position(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    system_bin = tmp_path / "system" / "bin"
    system_bin.mkdir(parents=True)
    env = system_bin / "env"
    env.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    env.chmod(0o755)
    app_dir = tmp_path / "app"
    node_modules = app_dir / "node_modules"
    bin_dir = node_modules / ".bin"
    bin_dir.mkdir(parents=True)
    command = bin_dir / "playwright-cli"
    command.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    command.chmod(0o755)
    monkeypatch.chdir(app_dir)
    runner = _CapturingSuccessRunner()
    toolkit = _toolkit(
        tmp_path,
        runner=runner,
        command=[
            str(env),
            "--argv0",
            "playwright-cli",
            "PATH=node_modules/.bin",
            "playwright-cli",
        ],
    )

    result = await toolkit._run_cli(
        session=_session(),
        tool_name="browser.navigate",
        args=["open"],
        network_urls=[],
        allow_network=False,
    )

    assert result is None
    assert len(runner.configs) == 1
    config = runner.configs[0]
    assert config.command[:5] == [
        str(env),
        "--argv0",
        "playwright-cli",
        f"PATH={bin_dir}",
        "playwright-cli",
    ]
    assert str(node_modules) in config.read_paths


@pytest.mark.parametrize(
    ("option_tokens", "expected_tokens"),
    [
        (
            ["--argv0", "./node_modules/.bin/playwright-cli"],
            ["--argv0", "./node_modules/.bin/playwright-cli"],
        ),
        (
            ["-a", "./node_modules/.bin/playwright-cli"],
            ["-a", "./node_modules/.bin/playwright-cli"],
        ),
        (
            ["--argv0", "--split-string=./node_modules/.bin/playwright-cli"],
            ["--argv0", "--split-string=./node_modules/.bin/playwright-cli"],
        ),
        (["--argv0", "--split-string"], ["--argv0", "--split-string"]),
        (
            ["--argv0=./node_modules/.bin/playwright-cli"],
            ["--argv0=./node_modules/.bin/playwright-cli"],
        ),
        (["-u", "./NODE_OPTIONS"], ["-u", "./NODE_OPTIONS"]),
        (["--unset", "./NODE_OPTIONS"], ["--unset", "./NODE_OPTIONS"]),
        (
            ["--unset", "--split-string=./NODE_OPTIONS"],
            ["--unset", "--split-string=./NODE_OPTIONS"],
        ),
        (["--unset", "-S"], ["--unset", "-S"]),
        (["--unset=./NODE_OPTIONS"], ["--unset=./NODE_OPTIONS"]),
    ],
)
@pytest.mark.asyncio
async def test_gh25_browser_toolkit_preserves_env_option_pathlike_operands(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    option_tokens: list[str],
    expected_tokens: list[str],
) -> None:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    system_bin = tmp_path / "system" / "bin"
    system_bin.mkdir(parents=True)
    env = system_bin / "env"
    env.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    env.chmod(0o755)
    app_dir = tmp_path / "app"
    node_modules = app_dir / "node_modules"
    bin_dir = node_modules / ".bin"
    bin_dir.mkdir(parents=True)
    command = bin_dir / "playwright-cli"
    command.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    command.chmod(0o755)
    unset_operand = app_dir / "NODE_OPTIONS"
    unset_operand.write_text("not an env option path\n", encoding="utf-8")
    monkeypatch.chdir(app_dir)
    runner = _CapturingSuccessRunner()
    toolkit = _toolkit(
        tmp_path,
        runner=runner,
        command=[
            str(env),
            *option_tokens,
            "PATH=node_modules/.bin",
            "playwright-cli",
        ],
    )

    result = await toolkit._run_cli(
        session=_session(),
        tool_name="browser.navigate",
        args=["open"],
        network_urls=[],
        allow_network=False,
    )

    assert result is None
    assert len(runner.configs) == 1
    config = runner.configs[0]
    assert config.command[: 1 + len(expected_tokens) + 2] == [
        str(env),
        *expected_tokens,
        f"PATH={bin_dir}",
        "playwright-cli",
    ]
    assert str(unset_operand) not in config.command
    assert str(node_modules) in config.read_paths


@pytest.mark.parametrize(
    ("env_args", "expected_args"),
    [
        (
            ["--", "--split-string=playwright-cli"],
            ["--", "--split-string=playwright-cli"],
        ),
        (
            ["-S", "-- --split-string=playwright-cli"],
            ["-S", shlex.join(["--", "--split-string=playwright-cli"])],
        ),
    ],
)
@pytest.mark.asyncio
async def test_gh25_browser_toolkit_env_double_dash_stops_option_parsing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    env_args: list[str],
    expected_args: list[str],
) -> None:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    system_bin = tmp_path / "system" / "bin"
    system_bin.mkdir(parents=True)
    env = system_bin / "env"
    env.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    env.chmod(0o755)
    target_bin = tmp_path / "target-bin"
    target_bin.mkdir()
    target = target_bin / "--split-string=playwright-cli"
    target.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    target.chmod(0o755)
    monkeypatch.setenv("PATH", str(target_bin))
    runner = _CapturingSuccessRunner()
    toolkit = _toolkit(
        tmp_path,
        runner=runner,
        command=[str(env), *env_args],
    )

    result = await toolkit._run_cli(
        session=_session(),
        tool_name="browser.navigate",
        args=["open"],
        network_urls=[],
        allow_network=False,
    )

    assert result is None
    assert len(runner.configs) == 1
    config = runner.configs[0]
    assert config.command[: 1 + len(expected_args)] == [str(env), *expected_args]
    assert str(target_bin) in config.read_paths


@pytest.mark.asyncio
async def test_gh25_browser_toolkit_preserves_exact_split_literal_before_env_option(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    system_bin = tmp_path / "system" / "bin"
    system_bin.mkdir(parents=True)
    env = system_bin / "env"
    env.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    env.chmod(0o755)
    app_dir = tmp_path / "app"
    node_modules = app_dir / "node_modules"
    bin_dir = node_modules / ".bin"
    bin_dir.mkdir(parents=True)
    command = bin_dir / "playwright-cli"
    command.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    command.chmod(0o755)
    monkeypatch.chdir(tmp_path)
    runner = _CapturingSuccessRunner()
    toolkit = _toolkit(
        tmp_path,
        runner=runner,
        command=[
            str(env),
            "--argv0",
            "--split-string",
            "-C",
            "app",
            "PATH=node_modules/.bin",
            "playwright-cli",
        ],
    )

    result = await toolkit._run_cli(
        session=_session(),
        tool_name="browser.navigate",
        args=["open"],
        network_urls=[],
        allow_network=False,
    )

    assert result is None
    assert len(runner.configs) == 1
    config = runner.configs[0]
    assert config.command[:7] == [
        str(env),
        "--argv0",
        "--split-string",
        "-C",
        str(app_dir),
        f"PATH={bin_dir}",
        "playwright-cli",
    ]
    assert str(node_modules) in config.read_paths


@pytest.mark.asyncio
async def test_gh25_browser_toolkit_literal_value_flag_before_real_split_option(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    system_bin = tmp_path / "system" / "bin"
    system_bin.mkdir(parents=True)
    env = system_bin / "env"
    env.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    env.chmod(0o755)
    app_dir = tmp_path / "app"
    node_modules = app_dir / "node_modules"
    bin_dir = node_modules / ".bin"
    bin_dir.mkdir(parents=True)
    command = bin_dir / "playwright-cli"
    command.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    command.chmod(0o755)
    monkeypatch.chdir(tmp_path)
    runner = _CapturingSuccessRunner()
    split_payload = "-C app PATH=node_modules/.bin playwright-cli"
    toolkit = _toolkit(
        tmp_path,
        runner=runner,
        command=[
            str(env),
            "--argv0",
            "-C",
            f"--split-string={split_payload}",
        ],
    )

    result = await toolkit._run_cli(
        session=_session(),
        tool_name="browser.navigate",
        args=["open"],
        network_urls=[],
        allow_network=False,
    )

    assert result is None
    assert len(runner.configs) == 1
    config = runner.configs[0]
    assert config.command[:4] == [
        str(env),
        "--argv0",
        "-C",
        f"--split-string={shlex.join(['-C', str(app_dir), f'PATH={bin_dir}', 'playwright-cli'])}",
    ]
    assert str(app_dir) in config.read_paths
    assert str(node_modules) in config.read_paths


@pytest.mark.asyncio
async def test_gh25_browser_toolkit_absolutizes_relative_playwright_symlink(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    app_dir = tmp_path / "app"
    node_modules = app_dir / "node_modules"
    bin_dir = node_modules / ".bin"
    target_dir = node_modules / "@playwright" / "test"
    bin_dir.mkdir(parents=True)
    target_dir.mkdir(parents=True)
    target = target_dir / "cli.js"
    target.write_text("#!/usr/bin/env node\n", encoding="utf-8")
    command = bin_dir / "playwright-cli"
    command.symlink_to("../@playwright/test/cli.js")
    monkeypatch.chdir(app_dir)
    runner = _CapturingSuccessRunner()
    toolkit = _toolkit(tmp_path, runner=runner, command=["./node_modules/.bin/playwright-cli"])

    result = await toolkit._run_cli(
        session=_session(),
        tool_name="browser.navigate",
        args=["open"],
        network_urls=[],
        allow_network=False,
    )

    assert result is None
    assert len(runner.configs) == 1
    config = runner.configs[0]
    assert config.command[0] == str(command)
    assert str(node_modules) in config.read_paths


@pytest.mark.asyncio
async def test_gh25_browser_toolkit_mounts_env_shebang_interpreter_from_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    node_bin = tmp_path / "node-home" / "bin"
    node_bin.mkdir(parents=True)
    node = node_bin / "node"
    node.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    node.chmod(0o755)
    monkeypatch.setenv("PATH", str(node_bin))
    node_modules = tmp_path / "app" / "node_modules"
    bin_dir = node_modules / ".bin"
    target_dir = node_modules / "@playwright" / "test"
    bin_dir.mkdir(parents=True)
    target_dir.mkdir(parents=True)
    target = target_dir / "cli.js"
    target.write_text("#!/usr/bin/env node\n", encoding="utf-8")
    command = bin_dir / "playwright-cli"
    command.symlink_to("../@playwright/test/cli.js")
    runner = _CapturingSuccessRunner()
    toolkit = _toolkit(tmp_path, runner=runner, command=[str(command)])

    result = await toolkit._run_cli(
        session=_session(),
        tool_name="browser.navigate",
        args=["open"],
        network_urls=[],
        allow_network=False,
    )

    assert result is None
    assert len(runner.configs) == 1
    config = runner.configs[0]
    assert str(node_modules) in config.read_paths
    assert str(node_bin) in config.read_paths


@pytest.mark.asyncio
async def test_gh26_browser_toolkit_unconfigured_command_reports_preflight_stage(
    tmp_path: Path,
) -> None:
    runner = _CapturingSuccessRunner()
    toolkit = _toolkit(tmp_path, runner=runner, command=[])

    result = await toolkit.navigate(session=_session(), url=_UNREACHABLE_LOOPBACK_URL)

    assert result == {
        "ok": False,
        "error": "browser_command_unconfigured",
        "details": {
            "reason": "browser_command_unconfigured",
            "stage": "command_preflight",
        },
        "taint_labels": [],
    }
    assert runner.configs == []


@pytest.mark.asyncio
async def test_gh26_browser_toolkit_missing_command_reports_preflight_stage(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    missing_command = tmp_path / "app" / "missing-playwright"
    runner = _CapturingSuccessRunner()
    toolkit = _toolkit(tmp_path, runner=runner, command=[str(missing_command)])

    result = await toolkit._run_cli(
        session=_session(),
        tool_name="browser.navigate",
        args=["open"],
        network_urls=[],
        allow_network=False,
    )

    assert result == {
        "ok": False,
        "error": "browser_command_unavailable",
        "details": {
            "reason": "browser_command_unavailable",
            "stage": "command_preflight",
        },
        "taint_labels": [],
    }
    assert str(missing_command) not in json.dumps(result, sort_keys=True)
    assert runner.configs == []


@pytest.mark.asyncio
async def test_gh25_browser_toolkit_broken_playwright_symlink_fails_before_exec(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    node_modules = tmp_path / "app" / "node_modules"
    bin_dir = node_modules / ".bin"
    bin_dir.mkdir(parents=True)
    command = bin_dir / "playwright-cli"
    command.symlink_to("../@playwright/test/missing.js")
    runner = _CapturingSuccessRunner()
    toolkit = _toolkit(tmp_path, runner=runner, command=[str(command)])

    result = await toolkit._run_cli(
        session=_session(),
        tool_name="browser.navigate",
        args=["open"],
        network_urls=[],
        allow_network=False,
    )

    assert result == {
        "ok": False,
        "error": "browser_dependency_unavailable",
        "details": {
            "reason": "browser_dependency_unavailable",
            "stage": "dependency_preflight",
        },
        "taint_labels": [],
    }
    assert str(command) not in json.dumps(result, sort_keys=True)
    assert runner.configs == []


@pytest.mark.asyncio
async def test_gh25_browser_toolkit_unwritable_playwright_cache_fails_before_exec(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    (home / ".cache").write_text("not a directory", encoding="utf-8")
    runner = _CapturingSuccessRunner()
    toolkit = _toolkit(tmp_path, runner=runner)

    result = await toolkit._run_cli(
        session=_session(),
        tool_name="browser.navigate",
        args=["open"],
        network_urls=[],
        allow_network=False,
    )

    assert result == {
        "ok": False,
        "error": "browser_cache_not_writable",
        "details": {
            "reason": "browser_cache_not_writable",
            "stage": "cache_preflight",
        },
        "taint_labels": [],
    }
    assert str(home) not in json.dumps(result, sort_keys=True)
    assert runner.configs == []


@pytest.mark.asyncio
async def test_gh26_browser_toolkit_subprocess_failure_sanitizes_details(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("PLAYWRIGHT_BROWSERS_PATH", raising=False)
    leaked_path = tmp_path / "browser" / "browser-session" / "state.json"
    leaked_cache = home / ".cache" / "ms-playwright" / "chromium"
    secret_value = "sk-test-gh26-secret-value"
    runner = _ConfiguredFailureRunner(
        SandboxResult(
            allowed=True,
            exit_code=17,
            stdout=f"operation failed at {leaked_cache}",
            stderr=f"failed to read {leaked_path} SHISAD_API_KEY={secret_value}",
            reason="browser_command_failed",
        )
    )
    toolkit = _toolkit(tmp_path, runner=runner)

    result = await toolkit._run_cli(
        session=_session(),
        tool_name="browser.navigate",
        args=["goto", _UNREACHABLE_LOOPBACK_URL],
        network_urls=[_UNREACHABLE_LOOPBACK_URL],
        allow_network=True,
    )

    assert result["ok"] is False
    assert result["error"] == "browser_subprocess_failed"
    assert result["details"] == {
        "reason": "browser_subprocess_failed",
        "stage": "subprocess",
        "sandbox_reason": "browser_command_failed",
        "exit_code": 17,
        "stderr": "failed to read [path]",
        "stdout": "operation failed at [path]",
    }
    serialized = json.dumps(result, sort_keys=True)
    assert str(leaked_path) not in serialized
    assert str(leaked_cache) not in serialized
    assert secret_value not in serialized
    assert len(runner.configs) == 1


@pytest.mark.asyncio
async def test_gh26_browser_toolkit_subprocess_failure_sanitizes_file_urls(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    leaked_path = tmp_path / "profile" / "state.json"
    runner = _ConfiguredFailureRunner(
        SandboxResult(
            allowed=True,
            exit_code=17,
            stderr=f"failed to read file://{leaked_path}",
            reason="browser_command_failed",
        )
    )
    toolkit = _toolkit(tmp_path, runner=runner)

    result = await toolkit._run_cli(
        session=_session(),
        tool_name="browser.navigate",
        args=["goto", _UNREACHABLE_LOOPBACK_URL],
        network_urls=[_UNREACHABLE_LOOPBACK_URL],
        allow_network=True,
    )

    assert result["error"] == "browser_subprocess_failed"
    assert result["details"]["stderr"] == "failed to read file://[path]"
    assert str(leaked_path) not in json.dumps(result, sort_keys=True)


@pytest.mark.parametrize(
    ("raw_stderr", "expected_stderr"),
    [
        (
            "failed to read /Users/Alice Smith/Library/Caches/ms-playwright/state.json",
            "failed to read [path]",
        ),
        (
            "failed to read /Users/O'Connor/Library/Caches/ms-playwright/state.json",
            "failed to read [path]",
        ),
        (
            "ENOENT:/Users/O'Connor/Library/Caches/ms-playwright/state.json",
            "ENOENT:[path]",
        ),
        (
            'failed to read /tmp/Quote"Name/ms-playwright/state.json',
            "failed to read [path]",
        ),
        (
            'path:/tmp/Quote"Name/ms-playwright/state.json',
            "path:[path]",
        ),
        (
            "failed to read /tmp/Angle<Name>/ms-playwright/state.json",
            "failed to read [path]",
        ),
        (
            "failed to read /Applications/My App.app/Contents/ms-playwright/state.json",
            "failed to read [path]",
        ),
        (
            "failed to read /opt/Program Files (x86)/ms-playwright/state.json",
            "failed to read [path]",
        ),
        (
            r"failed to read C:\Users\alice\AppData\Local\ms-playwright\state.json",
            "failed to read [path]",
        ),
        (
            r"failed to read C:\Users\Alice Smith\AppData\Local\ms-playwright\state.json",
            "failed to read [path]",
        ),
        (
            r"failed to read C:\Users\O'Connor\AppData\Local\ms-playwright\state.json",
            "failed to read [path]",
        ),
        (
            r"failed to read C:\Program Files\ms-playwright\state.json",
            "failed to read [path]",
        ),
        (
            r"failed to read C:\Program Files (x86)\ms-playwright\state.json",
            "failed to read [path]",
        ),
        (
            "failed to read C:/Users/alice/AppData/Local/ms-playwright/state.json",
            "failed to read [path]",
        ),
        (
            "failed to read C://Users/Alice Smith/AppData/Local/ms-playwright/state.json",
            "failed to read [path]",
        ),
        (
            "failed to read D://Users/O'Connor/AppData/Local/ms-playwright/state.json",
            "failed to read [path]",
        ),
        (
            r"failed to read \\server\share\ms-playwright\state.json",
            "failed to read [path]",
        ),
        (
            r"failed to read \\server\share name\ms-playwright\state.json",
            "failed to read [path]",
        ),
        (
            r"failed to read \\server\O'Connor share\ms-playwright\state.json",
            "failed to read [path]",
        ),
        (
            "failed to read file:///C:/Users/alice/AppData/Local/ms-playwright/state.json",
            "failed to read file://[path]",
        ),
        (
            "failed to read file:///C:/Users/Alice Smith/AppData/Local/ms-playwright/state.json",
            "failed to read file://[path]",
        ),
        (
            "failed to read file:///C:/Users/O'Connor/AppData/Local/ms-playwright/state.json",
            "failed to read file://[path]",
        ),
        (
            "failed to read file:///C:/Program Files (x86)/ms-playwright/state.json",
            "failed to read file://[path]",
        ),
        (
            "failed to read file://server/share/ms-playwright/state.json",
            "failed to read file://[path]",
        ),
        (
            "failed to read file://server/share name/ms-playwright/state.json",
            "failed to read file://[path]",
        ),
        (
            "navigation failed https://example.com/path?q=1",
            "navigation failed https://example.com/path?q=1",
        ),
        (
            "navigation failed https://example.com/#/settings",
            "navigation failed https://example.com/#/settings",
        ),
        (
            "navigation failed https://example.com/?next=/login",
            "navigation failed https://example.com/?next=/login",
        ),
        (
            "navigation failed https://example.com/(foo)/bar",
            "navigation failed https://example.com/(foo)/bar",
        ),
        (
            "navigation failed https://example.com/#/settings cache /Users/Alice Smith/state.json",
            "navigation failed https://example.com/#/settings cache [path]",
        ),
    ],
)
@pytest.mark.asyncio
async def test_gh26_browser_toolkit_subprocess_failure_sanitizes_file_url_variants(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    raw_stderr: str,
    expected_stderr: str,
) -> None:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    runner = _ConfiguredFailureRunner(
        SandboxResult(
            allowed=True,
            exit_code=17,
            stderr=raw_stderr,
            reason="browser_command_failed",
        )
    )
    toolkit = _toolkit(tmp_path, runner=runner)

    result = await toolkit._run_cli(
        session=_session(),
        tool_name="browser.navigate",
        args=["goto", _UNREACHABLE_LOOPBACK_URL],
        network_urls=[_UNREACHABLE_LOOPBACK_URL],
        allow_network=True,
    )

    assert result["error"] == "browser_subprocess_failed"
    assert result["details"]["stderr"] == expected_stderr
    assert "Alice Smith" not in json.dumps(result, sort_keys=True)
    assert "O'Connor" not in json.dumps(result, sort_keys=True)
    assert "Quote" not in json.dumps(result, sort_keys=True)
    assert "Angle" not in json.dumps(result, sort_keys=True)
    assert "My App.app" not in json.dumps(result, sort_keys=True)
    assert "Program Files" not in json.dumps(result, sort_keys=True)
    assert "x86" not in json.dumps(result, sort_keys=True)
    assert "Users/alice" not in json.dumps(result, sort_keys=True)
    assert "server/share" not in json.dumps(result, sort_keys=True)
    assert r"server\share" not in json.dumps(result, sort_keys=True)
    assert "share name" not in json.dumps(result, sort_keys=True)


@pytest.mark.asyncio
async def test_gh26_browser_toolkit_launched_subprocess_enoent_stays_runtime_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    leaked_path = tmp_path / "runtime" / "missing-state.json"
    runner = _ConfiguredFailureRunner(
        SandboxResult(
            allowed=True,
            exit_code=17,
            stderr=f"ENOENT: no such file or directory, open {leaked_path}",
            reason="allowed",
        )
    )
    toolkit = _toolkit(tmp_path, runner=runner)

    result = await toolkit._run_cli(
        session=_session(),
        tool_name="browser.navigate",
        args=["goto", _UNREACHABLE_LOOPBACK_URL],
        network_urls=[_UNREACHABLE_LOOPBACK_URL],
        allow_network=True,
    )

    assert result["error"] == "browser_subprocess_failed"
    assert result["details"] == {
        "reason": "browser_subprocess_failed",
        "stage": "subprocess",
        "exit_code": 17,
        "stderr": "ENOENT: no such file or directory, open [path]",
    }
    assert str(leaked_path) not in json.dumps(result, sort_keys=True)


@pytest.mark.asyncio
async def test_gh26_browser_toolkit_subprocess_read_only_cache_classified(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    leaked_cache = home / ".cache" / "ms-playwright"
    runner = _ConfiguredFailureRunner(
        SandboxResult(
            allowed=True,
            exit_code=1,
            stderr=f"EROFS: read-only file system, mkdir '{leaked_cache}'",
            reason="browser_command_failed",
        )
    )
    toolkit = _toolkit(tmp_path, runner=runner)

    result = await toolkit._run_cli(
        session=_session(),
        tool_name="browser.navigate",
        args=["goto", _UNREACHABLE_LOOPBACK_URL],
        network_urls=[_UNREACHABLE_LOOPBACK_URL],
        allow_network=True,
    )

    assert result["ok"] is False
    assert result["error"] == "browser_cache_not_writable"
    assert result["details"]["reason"] == "browser_cache_not_writable"
    assert result["details"]["stage"] == "subprocess"
    assert "read-only file system" in str(result["details"]["stderr"]).lower()
    assert str(leaked_cache) not in json.dumps(result, sort_keys=True)


@pytest.mark.asyncio
async def test_gh26_browser_toolkit_subprocess_missing_dependency_classified(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    runner = _ConfiguredFailureRunner(
        SandboxResult(
            allowed=True,
            exit_code=127,
            stderr=(
                "error while loading shared libraries: libnss3.so:"
                " cannot open shared object file"
            ),
            reason="browser_command_failed",
        )
    )
    toolkit = _toolkit(tmp_path, runner=runner)

    result = await toolkit._run_cli(
        session=_session(),
        tool_name="browser.navigate",
        args=["goto", _UNREACHABLE_LOOPBACK_URL],
        network_urls=[_UNREACHABLE_LOOPBACK_URL],
        allow_network=True,
    )

    assert result["ok"] is False
    assert result["error"] == "browser_dependency_unavailable"
    assert result["details"]["reason"] == "browser_dependency_unavailable"
    assert result["details"]["stage"] == "subprocess"
    assert (
        result["details"]["stderr"]
        == "error while loading shared libraries: libnss3.so:"
        " cannot open shared object file"
    )


@pytest.mark.asyncio
async def test_gh26_browser_toolkit_subprocess_missing_executable_classified(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    runner = _ConfiguredFailureRunner(
        SandboxResult(
            allowed=True,
            exit_code=1,
            stderr="browserType.launch: Executable doesn't exist at /opt/ms-playwright/chromium",
            reason="browser_command_failed",
        )
    )
    toolkit = _toolkit(tmp_path, runner=runner)

    result = await toolkit._run_cli(
        session=_session(),
        tool_name="browser.navigate",
        args=["goto", _UNREACHABLE_LOOPBACK_URL],
        network_urls=[_UNREACHABLE_LOOPBACK_URL],
        allow_network=True,
    )

    assert result["ok"] is False
    assert result["error"] == "browser_command_unavailable"
    assert result["details"]["reason"] == "browser_command_unavailable"
    assert result["details"]["stage"] == "subprocess"
    assert "executable doesn't exist" in str(result["details"]["stderr"]).lower()
    assert "/opt/ms-playwright/chromium" not in json.dumps(result, sort_keys=True)


@pytest.mark.asyncio
async def test_gh13_browser_toolkit_malformed_redacted_url_is_actionable(
    tmp_path: Path,
) -> None:
    runner = _DirectRunner()
    toolkit = _toolkit(tmp_path, runner=runner)

    result = await toolkit.navigate(
        session=_session(),
        url="https://www.hareruyamtg.[REDACTED:high_entropy_secret]",
    )

    assert result == {
        "ok": False,
        "error": "browser_url_invalid",
        "taint_labels": [],
    }
    assert runner.configs == []


@pytest.mark.asyncio
async def test_m6_browser_toolkit_hardened_wildcard_scope_is_actionable(tmp_path: Path) -> None:
    runner = _DirectRunner()
    toolkit = _toolkit(
        tmp_path,
        runner=runner,
        allowed_domains=["*.browser.example"],
        require_hardened_isolation=True,
    )

    result = await toolkit.navigate(session=_session(), url="https://sub.browser.example/")

    assert result == {
        "ok": False,
        "error": "browser_hardened_wildcard_scope_unsupported",
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


@pytest.mark.asyncio
async def test_m6_browser_toolkit_failed_navigation_preserves_previous_url(
    tmp_path: Path,
    browser_fixture_server: _FixtureServer,
) -> None:
    runner = _SelectiveFailureRunner(fail_tools={"browser.navigate"}, fail_after_goto=1)
    toolkit = _toolkit(tmp_path, runner=runner)
    session = _session()

    opened = await toolkit.navigate(session=session, url=f"{browser_fixture_server.base_url}/")
    assert opened["ok"] is True

    failed = await toolkit.navigate(session=session, url="https://example.com/other")

    assert failed["ok"] is False
    assert toolkit._current_url(session) == f"{browser_fixture_server.base_url}/"
