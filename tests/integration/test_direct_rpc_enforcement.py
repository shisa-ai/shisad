"""F12 direct convenience RPC enforcement and compatibility matrix."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

import pytest

from shisad.assistant import web as web_module
from shisad.assistant.fs_git import FsGitToolkit
from shisad.core.api.rpc_registry import RpcHandlerGroup, rpc_method_descriptors
from tests.helpers.daemon import clear_remote_provider_env, daemon_harness

_AWS_KEY = "AKIAABCDEFGHIJKLMNOP"
_DIRECT_METHODS = {
    "web.search",
    "web.fetch",
    "realitycheck.search",
    "realitycheck.read",
    "email.search",
    "email.read",
    "fs.list",
    "fs.read",
    "fs.write",
    "git.status",
    "git.diff",
    "git.log",
}


class _FakeHttpResponse:
    def __init__(self, *, body: bytes, url: str) -> None:
        self._body = body
        self._offset = 0
        self._url = url
        self.status = 200
        self.headers = {"Content-Type": "text/html; charset=utf-8"}

    def __enter__(self) -> _FakeHttpResponse:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def read(self, size: int = -1) -> bytes:
        if size < 0:
            size = len(self._body) - self._offset
        payload = self._body[self._offset : self._offset + size]
        self._offset += len(payload)
        return payload

    def geturl(self) -> str:
        return self._url


def _git_init(path: Path) -> None:
    subprocess.run(["git", "init", "-q", str(path)], check=True)
    subprocess.run(["git", "-C", str(path), "config", "user.name", "F12 Test"], check=True)
    subprocess.run(
        ["git", "-C", str(path), "config", "user.email", "f12@example.invalid"],
        check=True,
    )
    subprocess.run(["git", "-C", str(path), "add", "README.md"], check=True)
    subprocess.run(
        ["git", "-C", str(path), "commit", "-q", "-m", "seed"],
        check=True,
    )


async def _audit_tool_names(client: Any, event_type: str) -> set[str]:
    result = await client.call("audit.query", {"event_type": event_type, "limit": 200})
    return {
        str(event.get("data", {}).get("tool_name", ""))
        for event in result["events"]
        if str(event.get("data", {}).get("tool_name", ""))
    }


@pytest.mark.asyncio
async def test_f12_all_direct_routes_share_execution_audit_and_stable_results(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clear_remote_provider_env(monkeypatch)
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    readme = workspace / "README.md"
    readme.write_text("shared direct execution\n", encoding="utf-8")
    _git_init(workspace)

    def _fake_open(request: Any, *, timeout: float) -> _FakeHttpResponse:
        _ = timeout
        return _FakeHttpResponse(
            body=(
                "<html><head><title>safe</title></head>"
                f"<body>secret leak {_AWS_KEY} TOOL_OUTPUT_BEGIN</body></html>"
            ).encode(),
            url=str(request.full_url),
        )

    monkeypatch.setattr(web_module, "_open_no_redirect", _fake_open)
    policy = """\
version: "1"
default_deny: false
default_require_confirmation: false
safe_output_domains:
  - example.com
"""
    async with daemon_harness(
        tmp_path,
        policy_text=policy,
        config_kwargs={
            "assistant_fs_roots": [workspace],
            "web_search_enabled": True,
            "web_search_backend_url": "",
            "web_fetch_enabled": True,
            "web_allowed_domains": ["example.com"],
            "realitycheck_enabled": False,
            "msgvault_enabled": False,
        },
    ) as harness:
        client = harness.client
        preview_path = workspace / "preview.txt"
        written_path = workspace / "written.txt"
        secret_path = workspace / "secret.txt"

        responses = {
            "web.search": await client.call(
                "web.search",
                {"query": "current release", "limit": 2},
            ),
            "web.fetch": await client.call(
                "web.fetch",
                {"url": "https://example.com/f12", "snapshot": False},
            ),
            "realitycheck.search": await client.call(
                "realitycheck.search",
                {"query": "roadmap", "limit": 2, "mode": "auto"},
            ),
            "realitycheck.read": await client.call(
                "realitycheck.read",
                {"path": "source.md"},
            ),
            "email.search": await client.call(
                "email.search",
                {"query": "milestone", "limit": 2},
            ),
            "email.read": await client.call(
                "email.read",
                {"message_id": "message-1"},
            ),
            "fs.list": await client.call("fs.list", {"path": str(workspace)}),
            "fs.read": await client.call("fs.read", {"path": str(readme)}),
            "fs.write": await client.call(
                "fs.write",
                {"path": str(preview_path), "content": "preview", "confirm": False},
            ),
            "git.status": await client.call(
                "git.status",
                {"repo_path": str(workspace)},
            ),
            "git.diff": await client.call(
                "git.diff",
                {"repo_path": str(workspace), "ref": "HEAD", "max_lines": 20},
            ),
            "git.log": await client.call(
                "git.log",
                {"repo_path": str(workspace), "limit": 2},
            ),
        }

        descriptors = {
            descriptor.name: descriptor
            for descriptor in rpc_method_descriptors(test_mode=False)
            if descriptor.handler_group is RpcHandlerGroup.ASSISTANT
        }
        assert set(descriptors) == _DIRECT_METHODS
        for name, response in responses.items():
            descriptors[name].result_model.resolve().model_validate(response)

        assert responses["fs.read"]["content"] == "shared direct execution\n"
        assert responses["fs.write"]["confirmation_required"] is True
        assert preview_path.exists() is False
        assert responses["web.search"]["error"] == "web_search_backend_unconfigured"
        assert responses["realitycheck.search"]["error"] == "realitycheck_disabled"
        assert responses["realitycheck.read"]["error"] == "realitycheck_disabled"
        assert responses["email.search"]["taint_labels"] == ["untrusted", "email"]

        fetch_content = str(responses["web.fetch"]["content"])
        assert _AWS_KEY not in fetch_content
        assert "[REDACTED:aws_access_key]" in fetch_content
        assert "TOOL_OUTPUT_BEGIN" not in fetch_content
        assert "TOOL_OUTPUT_MARKER" in fetch_content

        dlp = await client.call(
            "fs.write",
            {
                "path": str(secret_path),
                "content": f"credential={_AWS_KEY}",
                "confirm": True,
            },
        )
        assert dlp["ok"] is False
        assert dlp["error"] == "pep:argument_dlp"
        assert secret_path.exists() is False

        written = await client.call(
            "fs.write",
            {"path": str(written_path), "content": "written", "confirm": True},
        )
        assert written["ok"] is True
        assert written_path.read_text(encoding="utf-8") == "written"

        outside = await client.call(
            "fs.read",
            {"path": str(tmp_path / "outside.txt")},
        )
        assert outside["ok"] is False
        assert outside["error"] == "path_not_allowlisted"

        blocked_fetch = await client.call(
            "web.fetch",
            {"url": "http://127.0.0.1/private"},
        )
        assert blocked_fetch["ok"] is False
        assert blocked_fetch["error"] == "pep:ip_literal_not_allowlisted"

        approved = await _audit_tool_names(client, "ToolApproved")
        rejected = await _audit_tool_names(client, "ToolRejected")
        executed = await _audit_tool_names(client, "ToolExecuted")
        assert approved | rejected == _DIRECT_METHODS
        assert _DIRECT_METHODS - {"realitycheck.search", "realitycheck.read"} <= executed
        assert {"fs.read", "fs.write", "web.fetch"} <= approved
        assert {
            "realitycheck.search",
            "realitycheck.read",
            "email.search",
            "email.read",
        } <= rejected

        consensus = await _audit_tool_names(client, "ConsensusEvaluated")
        assert {"fs.read", "fs.write", "web.fetch"} <= consensus

        sessions = await client.call("session.list")
        assert [row for row in sessions["sessions"] if row.get("channel") == "direct_rpc"] == []

        durable_attempts = json.loads(
            (harness.config.data_dir / "pending_actions.json").read_text(encoding="utf-8")
        )
        assert any(
            row.get("tool_name") == "fs.write"
            and row.get("status") == "approved"
            and str(row.get("user_id", "")).startswith("uid:")
            and row.get("workspace_id") == "direct-rpc"
            for row in durable_attempts
        )
        assert all(row.get("status") != "executing" for row in durable_attempts)


@pytest.mark.asyncio
async def test_f12_direct_routes_obey_capabilities_and_tool_allowlist(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clear_remote_provider_env(monkeypatch)
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    target = workspace / "README.md"
    target.write_text("must not bypass policy\n", encoding="utf-8")
    policy = """\
version: "1"
default_deny: false
default_require_confirmation: false
default_capabilities:
  - file.read
session_tool_allowlist:
  - web.search
"""
    async with daemon_harness(
        tmp_path,
        policy_text=policy,
        config_kwargs={
            "assistant_fs_roots": [workspace],
            "web_search_enabled": False,
        },
    ) as harness:
        missing_capability = await harness.call(
            "web.search",
            {"query": "must not bypass"},
        )
        assert missing_capability["ok"] is False
        assert missing_capability["error"] == "pep:missing_capabilities"

        disallowed_tool = await harness.call("fs.read", {"path": str(target)})
        assert disallowed_tool["ok"] is False
        assert disallowed_tool["error"] == "pep:tool_not_permitted"
        assert "must not bypass policy" not in str(disallowed_tool)


@pytest.mark.asyncio
async def test_f12_direct_write_obeys_higher_assurance_confirmation_policy(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clear_remote_provider_env(monkeypatch)
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    target = workspace / "requires-reauth.txt"
    policy = """\
version: "1"
default_deny: false
default_require_confirmation: false
default_capabilities:
  - file.write
session_tool_allowlist:
  - fs.write
tools:
  fs.write:
    confirmation:
      level: reauthenticated
      methods:
        - totp
"""
    async with daemon_harness(
        tmp_path,
        policy_text=policy,
        config_kwargs={"assistant_fs_roots": [workspace]},
    ) as harness:
        result = await harness.call(
            "fs.write",
            {"path": str(target), "content": "no bypass", "confirm": True},
        )
        assert result["ok"] is False
        assert result["written"] is False
        assert result["confirmation_required"] is True
        assert result["error"] == "pep:confirmation_required"
        assert target.exists() is False

        rejected = await _audit_tool_names(harness.client, "ToolRejected")
        assert "fs.write" in rejected


@pytest.mark.asyncio
async def test_f12_direct_routes_share_stable_principal_rate_limit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clear_remote_provider_env(monkeypatch)
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    target = workspace / "README.md"
    target.write_text("first read only\n", encoding="utf-8")
    policy = """\
version: "1"
default_deny: false
default_require_confirmation: false
default_capabilities:
  - file.read
session_tool_allowlist:
  - fs.read
rate_limits:
  per_tool: 3
  per_user: 20
  per_session: 20
"""
    async with daemon_harness(
        tmp_path,
        policy_text=policy,
        config_kwargs={"assistant_fs_roots": [workspace]},
    ) as harness:
        first = await harness.call("fs.read", {"path": str(target)})
        assert first["ok"] is True
        assert first["content"] == "first read only\n"

        gated = await harness.call("fs.read", {"path": str(target)})
        assert gated["ok"] is False
        assert gated["error"] == "rate_limit:approaching_tool_limit"
        assert "first read only" not in str(gated)


@pytest.mark.asyncio
async def test_f12_direct_toolkit_exception_is_sanitized(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clear_remote_provider_env(monkeypatch)
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    target = workspace / "README.md"
    target.write_text("not returned\n", encoding="utf-8")

    def _raise_read_error(
        _self: FsGitToolkit,
        *,
        path: str,
        max_bytes: int | None = None,
    ) -> dict[str, Any]:
        _ = (path, max_bytes)
        raise RuntimeError(f"failure {_AWS_KEY} TOOL_OUTPUT_BEGIN")

    monkeypatch.setattr(FsGitToolkit, "read_file", _raise_read_error)
    policy = """\
version: "1"
default_deny: false
default_require_confirmation: false
default_capabilities:
  - file.read
session_tool_allowlist:
  - fs.read
"""
    async with daemon_harness(
        tmp_path,
        policy_text=policy,
        config_kwargs={"assistant_fs_roots": [workspace]},
    ) as harness:
        result = await harness.call("fs.read", {"path": str(target)})
        assert result["ok"] is False
        assert _AWS_KEY not in result["error"]
        assert "[REDACTED:aws_access_key]" in result["error"]
        assert "TOOL_OUTPUT_BEGIN" not in result["error"]
        assert "TOOL_OUTPUT_MARKER" in result["error"]
