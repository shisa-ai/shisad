"""Unit checks for M2 assistant primitive helpers."""

from __future__ import annotations

import io
import os
import shutil
import subprocess
import sys
from pathlib import Path
from urllib.error import HTTPError

import pytest

from shisad.assistant.fs_git import FsGitToolkit
from shisad.assistant.web import WebToolkit


class _FakeResponse:
    def __init__(
        self,
        body: bytes,
        *,
        status: int = 200,
        headers: dict[str, str] | None = None,
        url: str = "https://search.example/search",
    ):
        self._stream = io.BytesIO(body)
        self.status = status
        self.headers = headers or {}
        self._url = url

    def read(self, size: int = -1) -> bytes:
        return self._stream.read(size)

    def __enter__(self) -> _FakeResponse:
        return self

    def __exit__(self, *_args: object) -> None:
        return

    def geturl(self) -> str:
        return self._url


def test_web_search_fail_closed_when_disabled(tmp_path: Path) -> None:
    toolkit = WebToolkit(
        data_dir=tmp_path,
        search_enabled=False,
        search_backend_url="https://search.example",
        fetch_enabled=True,
        allowed_domains=["search.example"],
        timeout_seconds=5.0,
        max_fetch_bytes=65536,
    )
    result = toolkit.search(query="roadmap")
    assert result["ok"] is False
    assert result["error"] == "web_search_disabled"


def test_web_search_returns_structured_results(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    payload = {
        "results": [
            {
                "title": "Result 1",
                "url": "https://docs.example.com/a",
                "content": "summary",
                "engine": "searxng",
            }
        ]
    }
    monkeypatch.setattr(
        "shisad.assistant.web._open_no_redirect",
        lambda *_args, **_kwargs: _FakeResponse(
            body=str(payload).replace("'", '"').encode("utf-8"),
            status=200,
            headers={"Content-Type": "application/json"},
        ),
    )
    toolkit = WebToolkit(
        data_dir=tmp_path,
        search_enabled=True,
        search_backend_url="https://search.example",
        fetch_enabled=True,
        allowed_domains=["search.example", "*.example.com"],
        timeout_seconds=5.0,
        max_fetch_bytes=65536,
    )
    result = toolkit.search(query="shisad roadmap", limit=1)
    assert result["ok"] is True
    assert result["results"][0]["url"] == "https://docs.example.com/a"
    assert result["taint_labels"] == ["untrusted"]
    assert result["evidence"]["operation"] == "web_search"


def test_web_search_allows_public_backend_without_allowlist(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(
        "shisad.assistant.web._open_no_redirect",
        lambda *_args, **_kwargs: _FakeResponse(
            body=b'{"results": [{"title": "Result", "url": "https://docs.example/a"}]}',
            status=200,
            headers={"Content-Type": "application/json"},
        ),
    )
    toolkit = WebToolkit(
        data_dir=tmp_path,
        search_enabled=True,
        search_backend_url="https://search.example",
        fetch_enabled=True,
        allowed_domains=[],
        timeout_seconds=5.0,
        max_fetch_bytes=65536,
    )

    result = toolkit.search(query="shisad roadmap", limit=1)

    assert result["ok"] is True
    assert result["backend"] == "https://search.example"
    assert result["results"][0]["url"] == "https://docs.example/a"


@pytest.mark.parametrize(
    ("backend_url", "reason"),
    (
        ("http://127.0.0.1:8080", "ip_literal_not_allowlisted"),
        ("http://localhost:8080", "local_destination_not_allowlisted"),
        ("http://search.local:8080", "local_destination_not_allowlisted"),
    ),
)
def test_web_search_blocks_local_backend_without_allowlist(
    tmp_path: Path,
    backend_url: str,
    reason: str,
) -> None:
    toolkit = WebToolkit(
        data_dir=tmp_path,
        search_enabled=True,
        search_backend_url=backend_url,
        fetch_enabled=True,
        allowed_domains=[],
        timeout_seconds=5.0,
        max_fetch_bytes=65536,
    )

    result = toolkit.search(query="shisad roadmap")

    assert result["ok"] is False
    assert result["error"] == reason


def test_web_fetch_allows_public_destination_without_allowlist(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(
        "shisad.assistant.web._open_no_redirect",
        lambda *_args, **_kwargs: _FakeResponse(
            body=b"<html><title>Hello</title><body>ok</body></html>",
            status=200,
            headers={"Content-Type": "text/html"},
            url="https://blocked.example/path",
        ),
    )
    toolkit = WebToolkit(
        data_dir=tmp_path,
        search_enabled=True,
        search_backend_url="https://search.example",
        fetch_enabled=True,
        allowed_domains=[],
        timeout_seconds=5.0,
        max_fetch_bytes=65536,
    )
    result = toolkit.fetch(url="https://blocked.example/path")
    assert result["ok"] is True
    assert result["title"] == "Hello"


def test_web_fetch_detects_interstitial(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(
        "shisad.assistant.web._open_no_redirect",
        lambda *_args, **_kwargs: _FakeResponse(
            body=b"<html><title>Verify</title><body>Verify you are human</body></html>",
            status=200,
            headers={"Content-Type": "text/html"},
            url="https://blocked.example/login",
        ),
    )
    toolkit = WebToolkit(
        data_dir=tmp_path,
        search_enabled=True,
        search_backend_url="https://search.example",
        fetch_enabled=True,
        allowed_domains=["blocked.example"],
        timeout_seconds=5.0,
        max_fetch_bytes=65536,
    )
    result = toolkit.fetch(url="https://blocked.example/login")
    assert result["ok"] is False
    assert result["error"] == "blocked_page_detected"
    assert result["blocked_reason"] == "verify_you_are_human"


def test_fs_git_toolkit_read_first_and_write_confirmation(tmp_path: Path) -> None:
    root = tmp_path / "workspace"
    root.mkdir(parents=True)
    target = root / "notes.txt"
    target.write_text("hello", encoding="utf-8")
    toolkit = FsGitToolkit(roots=[root], max_read_bytes=1024)

    listing = toolkit.list_dir(path=".")
    assert listing["ok"] is True
    assert listing["count"] >= 1

    read = toolkit.read_file(path="notes.txt")
    assert read["ok"] is True
    assert read["content"] == "hello"

    blocked_write = toolkit.write_file(path="notes.txt", content="updated", confirm=False)
    assert blocked_write["ok"] is False
    assert blocked_write["confirmation_required"] is True

    allowed_write = toolkit.write_file(path="notes.txt", content="updated", confirm=True)
    assert allowed_write["ok"] is True
    assert (root / "notes.txt").read_text(encoding="utf-8") == "updated"


def test_s9_fs_git_toolkit_blocks_configured_soul_write_path(tmp_path: Path) -> None:
    root = tmp_path / "workspace"
    root.mkdir(parents=True)
    soul_path = root / "SOUL.md"
    soul_path.write_text("trusted persona", encoding="utf-8")
    toolkit = FsGitToolkit(
        roots=[root],
        max_read_bytes=1024,
        protected_write_paths=(soul_path,),
    )

    unconfirmed = toolkit.write_file(path="SOUL.md", content="attacker persona", confirm=False)
    assert unconfirmed["ok"] is False
    assert unconfirmed["confirmation_required"] is False
    assert unconfirmed["error"] == "protected_control_plane_path"

    blocked = toolkit.write_file(path="SOUL.md", content="attacker persona", confirm=True)

    assert blocked["ok"] is False
    assert blocked["written"] is False
    assert blocked["confirmation_required"] is False
    assert blocked["error"] == "protected_control_plane_path"
    assert soul_path.read_text(encoding="utf-8") == "trusted persona"

    allowed = toolkit.write_file(path="notes.txt", content="normal write", confirm=True)
    assert allowed["ok"] is True
    assert (root / "notes.txt").read_text(encoding="utf-8") == "normal write"


def test_s9_fs_git_toolkit_blocks_hard_link_to_configured_soul_path(tmp_path: Path) -> None:
    root = tmp_path / "workspace"
    root.mkdir(parents=True)
    soul_path = root / "SOUL.md"
    soul_path.write_text("trusted persona", encoding="utf-8")
    alias_path = root / "alias.md"
    os.link(soul_path, alias_path)
    toolkit = FsGitToolkit(
        roots=[root],
        max_read_bytes=1024,
        protected_write_paths=(soul_path,),
    )

    blocked = toolkit.write_file(path="alias.md", content="attacker persona", confirm=True)

    assert blocked["ok"] is False
    assert blocked["written"] is False
    assert blocked["error"] == "protected_control_plane_path"
    assert soul_path.read_text(encoding="utf-8") == "trusted persona"
    assert alias_path.read_text(encoding="utf-8") == "trusted persona"


@pytest.mark.parametrize("operation", ["list", "read", "write", "git"])
def test_f3_fs_git_toolkit_blocks_all_managed_data_root_targets(
    tmp_path: Path,
    operation: str,
) -> None:
    workspace = tmp_path / "workspace"
    managed = workspace / ".shisad-data"
    managed.mkdir(parents=True)
    (managed / "secret.json").write_text("control state", encoding="utf-8")
    (managed / ".git").mkdir()
    toolkit = FsGitToolkit(
        roots=[workspace],
        max_read_bytes=1024,
        protected_roots=(managed,),
    )

    if operation == "list":
        result = toolkit.list_dir(path=str(managed))
    elif operation == "read":
        result = toolkit.read_file(path=str(managed / "secret.json"))
    elif operation == "write":
        result = toolkit.write_file(
            path=str(managed / "secret.json"),
            content="attacker overwrite",
            confirm=True,
        )
    else:
        result = toolkit.git_status(repo_path=str(managed))

    assert result["ok"] is False
    assert result["error"] == "protected_control_plane_path"
    assert (managed / "secret.json").read_text(encoding="utf-8") == "control state"


@pytest.mark.parametrize("operation", ["list", "read", "write", "git"])
def test_f3_fs_git_toolkit_blocks_exact_external_control_files_and_adjacent_locks(
    tmp_path: Path,
    operation: str,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    soul = workspace / "SOUL.md"
    soul.write_text("trusted persona", encoding="utf-8")
    soul_lock = workspace / "SOUL.md.lock"
    soul_lock.write_text("", encoding="utf-8")
    toolkit = FsGitToolkit(
        roots=[workspace],
        max_read_bytes=1024,
        protected_paths=(soul, soul_lock),
    )
    target = soul_lock if operation == "list" else soul

    if operation == "list":
        result = toolkit.list_dir(path=str(target))
    elif operation == "read":
        result = toolkit.read_file(path=str(target))
    elif operation == "write":
        result = toolkit.write_file(path=str(target), content="attacker", confirm=True)
    else:
        result = toolkit.git_status(repo_path=str(target))

    assert result["ok"] is False
    assert result["error"] == "protected_control_plane_path"
    assert soul.read_text(encoding="utf-8") == "trusted persona"


def test_f3_fs_git_toolkit_keeps_unrelated_authorized_paths_usable(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    managed = workspace / ".shisad-data"
    managed.mkdir(parents=True)
    notes = workspace / "notes.txt"
    notes.write_text("healthy", encoding="utf-8")
    toolkit = FsGitToolkit(
        roots=[workspace],
        max_read_bytes=1024,
        protected_roots=(managed,),
    )

    assert toolkit.read_file(path=str(notes))["content"] == "healthy"
    written = toolkit.write_file(path=str(notes), content="still healthy", confirm=True)

    assert written["ok"] is True
    assert notes.read_text(encoding="utf-8") == "still healthy"


def test_fs_git_toolkit_git_status_and_log(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir(parents=True)
    subprocess.run(["git", "-C", str(repo), "init"], check=True, capture_output=True, text=True)
    subprocess.run(
        ["git", "-C", str(repo), "config", "user.email", "test@example.com"],
        check=True,
        capture_output=True,
        text=True,
    )
    subprocess.run(
        ["git", "-C", str(repo), "config", "user.name", "Test User"],
        check=True,
        capture_output=True,
        text=True,
    )
    (repo / "README.md").write_text("hello\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(repo), "add", "README.md"], check=True, capture_output=True)
    subprocess.run(
        ["git", "-C", str(repo), "commit", "-m", "init"],
        check=True,
        capture_output=True,
        text=True,
    )

    toolkit = FsGitToolkit(roots=[repo], max_read_bytes=1024)
    status = toolkit.git_status(repo_path=".")
    assert status["ok"] is True
    assert "##" in status["output"]

    log = toolkit.git_log(repo_path=".", limit=5)
    assert log["ok"] is True
    assert "init" in log["output"]


def test_f4c_fs_git_invocations_neutralize_repository_helpers(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)
    calls: list[tuple[list[str], dict[str, object]]] = []

    def _run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[object]:
        calls.append((list(command), dict(kwargs)))
        if kwargs.get("text") is True:
            return subprocess.CompletedProcess(command, 0, stdout="ordinary output\n", stderr="")
        return subprocess.CompletedProcess(command, 0, stdout=b"", stderr=b"")

    monkeypatch.setenv("GIT_CONFIG_COUNT", "1")
    monkeypatch.setenv("GIT_CONFIG_KEY_0", "core.fsmonitor")
    monkeypatch.setenv("GIT_CONFIG_VALUE_0", "/tmp/poison-fsmonitor")
    monkeypatch.setenv("GIT_EXTERNAL_DIFF", "/tmp/poison-diff")
    monkeypatch.setattr(subprocess, "run", _run)
    toolkit = FsGitToolkit(roots=[repo], max_read_bytes=1024)

    assert toolkit.git_status(repo_path=".")["ok"] is True
    assert toolkit.git_diff(repo_path=".")["ok"] is True
    assert toolkit.git_log(repo_path=".")["ok"] is True

    final_calls = [item for item in calls if item[1].get("text") is True]
    assert len(final_calls) == 3
    for command, kwargs in final_calls:
        config_values = {
            command[index + 1] for index, token in enumerate(command[:-1]) if token == "-c"
        }
        assert "core.hooksPath=" in "\n".join(config_values)
        assert "core.fsmonitor=false" in config_values
        assert "log.showSignature=false" in config_values
        assert "gpg.program=" in config_values
        assert "gpg.openpgp.program=" in config_values
        assert "gpg.ssh.program=" in config_values
        assert "gpg.x509.program=" in config_values
        env = kwargs["env"]
        assert isinstance(env, dict)
        assert env["GIT_TERMINAL_PROMPT"] == "0"
        assert "GIT_CONFIG_COUNT" not in env
        assert "GIT_EXTERNAL_DIFF" not in env

    status_command = next(command for command, _kwargs in final_calls if "status" in command)
    diff_command = next(command for command, _kwargs in final_calls if "diff" in command)
    log_command = next(command for command, _kwargs in final_calls if "log" in command)
    assert "--no-ext-diff" in diff_command
    assert "--no-textconv" in diff_command
    assert "--no-show-signature" in log_command
    assert "--branch" in status_command


@pytest.mark.skipif(
    os.name != "posix" or shutil.which("ssh-keygen") is None,
    reason="hostile helper and signed-commit fixture requires POSIX ssh-keygen",
)
def test_f4c_fs_git_tools_return_results_without_executing_hostile_helpers(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "-C", str(repo), "init"], check=True, capture_output=True)
    subprocess.run(
        ["git", "-C", str(repo), "config", "user.email", "test@example.com"],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(repo), "config", "user.name", "Test User"],
        check=True,
    )
    signing_key = tmp_path / "signing-key"
    subprocess.run(
        ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(signing_key)],
        check=True,
    )
    (repo / ".gitattributes").write_text("README.md diff=poison\n", encoding="utf-8")
    (repo / "README.md").write_text("initial\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
    subprocess.run(
        [
            "git",
            "-C",
            str(repo),
            "-c",
            "gpg.format=ssh",
            "-c",
            f"user.signingkey={signing_key}",
            "commit",
            "-S",
            "-m",
            "signed init",
        ],
        check=True,
        capture_output=True,
    )

    markers = {name: tmp_path / f"{name}.marker" for name in ("fsmonitor", "diff", "signature")}
    helpers: dict[str, Path] = {}
    for name, marker in markers.items():
        helper = tmp_path / f"{name}-helper.py"
        helper.write_text(
            f"#!{sys.executable}\nfrom pathlib import Path\nPath({str(marker)!r}).touch()\n",
            encoding="utf-8",
        )
        helper.chmod(0o755)
        helpers[name] = helper

    for key, value in (
        ("core.fsmonitor", helpers["fsmonitor"]),
        ("diff.external", helpers["diff"]),
        ("diff.poison.textconv", helpers["diff"]),
        ("log.showSignature", "true"),
        ("gpg.format", "ssh"),
        ("gpg.ssh.program", helpers["signature"]),
    ):
        subprocess.run(
            ["git", "-C", str(repo), "config", key, str(value)],
            check=True,
        )
    (repo / "README.md").write_text("updated\n", encoding="utf-8")

    toolkit = FsGitToolkit(roots=[repo], max_read_bytes=1024)
    status = toolkit.git_status(repo_path=".")
    diff = toolkit.git_diff(repo_path=".")
    log = toolkit.git_log(repo_path=".")

    assert status["ok"] is True
    assert "README.md" in status["output"]
    assert diff["ok"] is True
    assert "updated" in diff["output"]
    assert log["ok"] is True
    assert "signed init" in log["output"]
    assert all(not marker.exists() for marker in markers.values())


@pytest.mark.skipif(os.name != "posix", reason="executable filter fixture is POSIX")
def test_f4c_fs_git_worktree_reads_block_required_filter_but_log_remains_usable(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "-C", str(repo), "init"], check=True, capture_output=True)
    subprocess.run(
        ["git", "-C", str(repo), "config", "user.email", "test@example.com"],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(repo), "config", "user.name", "Test User"],
        check=True,
    )
    (repo / ".gitattributes").write_text("payload.txt filter=poison\n", encoding="utf-8")
    (repo / "payload.txt").write_text("payload\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
    subprocess.run(
        ["git", "-C", str(repo), "commit", "-m", "init"],
        check=True,
        capture_output=True,
    )

    marker = tmp_path / "filter.marker"
    helper = tmp_path / "filter-helper.py"
    helper.write_text(
        f"#!{sys.executable}\nfrom pathlib import Path\nPath({str(marker)!r}).touch()\n",
        encoding="utf-8",
    )
    helper.chmod(0o755)
    subprocess.run(
        ["git", "-C", str(repo), "config", "filter.poison.clean", str(helper)],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(repo), "config", "filter.poison.required", "true"],
        check=True,
    )

    toolkit = FsGitToolkit(roots=[repo], max_read_bytes=1024)
    status = toolkit.git_status(repo_path=".")
    diff = toolkit.git_diff(repo_path=".")
    log = toolkit.git_log(repo_path=".")

    for result in (status, diff):
        assert result["ok"] is False
        assert result["error"].startswith("git_required_filter_blocked:")
        assert "disable the filter or use a separately audited checkout" in result["error"]
    assert log["ok"] is True
    assert "init" in log["output"]
    assert not marker.exists()


def test_web_fetch_redirect_blocks_unallowlisted_destination(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    def _redirect_then_block(*_args: object, **_kwargs: object) -> _FakeResponse:
        raise HTTPError(
            "https://allowed.example/start",
            302,
            "Found",
            {"Location": "https://evil.example/pivot"},
            None,
        )

    monkeypatch.setattr("shisad.assistant.web._open_no_redirect", _redirect_then_block)
    toolkit = WebToolkit(
        data_dir=tmp_path,
        search_enabled=True,
        search_backend_url="https://search.example",
        fetch_enabled=True,
        allowed_domains=["allowed.example"],
        timeout_seconds=5.0,
        max_fetch_bytes=65536,
    )
    result = toolkit.fetch(url="https://allowed.example/start")
    assert result["ok"] is False
    assert result["error"] == "redirect_host_not_preapproved"
    assert result["redirect_host"] == "evil.example"


def test_web_search_redirect_blocks_unallowlisted_backend(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    def _redirect_then_block(*_args: object, **_kwargs: object) -> _FakeResponse:
        raise HTTPError(
            "https://search.example/search?q=roadmap",
            302,
            "Found",
            {"Location": "https://evil.example/search?q=roadmap"},
            None,
        )

    monkeypatch.setattr("shisad.assistant.web._open_no_redirect", _redirect_then_block)
    toolkit = WebToolkit(
        data_dir=tmp_path,
        search_enabled=True,
        search_backend_url="https://search.example",
        fetch_enabled=True,
        allowed_domains=["search.example"],
        timeout_seconds=5.0,
        max_fetch_bytes=65536,
    )
    result = toolkit.search(query="roadmap")
    assert result["ok"] is False
    assert result["error"] == "redirect_host_not_preapproved"
    assert result["redirect_host"] == "evil.example"


def test_web_fetch_strips_script_and_style_content(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(
        "shisad.assistant.web._open_no_redirect",
        lambda *_args, **_kwargs: _FakeResponse(
            body=(
                b"<html><head><style>body{display:none}</style></head>"
                b"<body><script>alert('x')</script><p>Hello world</p></body></html>"
            ),
            status=200,
            headers={"Content-Type": "text/html"},
            url="https://allowed.example/page",
        ),
    )
    toolkit = WebToolkit(
        data_dir=tmp_path,
        search_enabled=True,
        search_backend_url="https://search.example",
        fetch_enabled=True,
        allowed_domains=["allowed.example"],
        timeout_seconds=5.0,
        max_fetch_bytes=65536,
    )
    result = toolkit.fetch(url="https://allowed.example/page")
    assert result["ok"] is True
    assert "Hello world" in result["content"]
    assert "alert('x')" not in result["content"]
    assert "display:none" not in result["content"]


def test_fs_git_toolkit_git_diff_rejects_flag_like_ref(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir(parents=True)
    subprocess.run(["git", "-C", str(repo), "init"], check=True, capture_output=True, text=True)
    subprocess.run(
        ["git", "-C", str(repo), "config", "user.email", "test@example.com"],
        check=True,
        capture_output=True,
        text=True,
    )
    subprocess.run(
        ["git", "-C", str(repo), "config", "user.name", "Test User"],
        check=True,
        capture_output=True,
        text=True,
    )
    (repo / "README.md").write_text("hello\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(repo), "add", "README.md"], check=True, capture_output=True)
    subprocess.run(
        ["git", "-C", str(repo), "commit", "-m", "init"],
        check=True,
        capture_output=True,
        text=True,
    )

    toolkit = FsGitToolkit(roots=[repo], max_read_bytes=1024)
    blocked = toolkit.git_diff(repo_path=".", ref="--output=/tmp/evil")
    assert blocked["ok"] is False
    assert blocked["error"] == "invalid_ref"


def test_m6_fs_git_toolkit_read_file_uses_bounded_stream_reads(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "workspace"
    root.mkdir(parents=True)
    target = root / "large.txt"
    target.write_text("a" * 4096, encoding="utf-8")
    toolkit = FsGitToolkit(roots=[root], max_read_bytes=1024)

    def _read_bytes_guard(self: Path) -> bytes:  # pragma: no cover - regression guard
        raise AssertionError("read_file regressed to Path.read_bytes full-file read")

    monkeypatch.setattr(Path, "read_bytes", _read_bytes_guard)
    read = toolkit.read_file(path="large.txt")
    assert read["ok"] is True
    assert read["truncated"] is True
    assert len(str(read["content"])) == 1024


def test_m6_fs_git_toolkit_git_status_fails_closed_on_timeout(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)
    toolkit = FsGitToolkit(roots=[repo], max_read_bytes=1024)

    def _timeout(*args: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
        raise subprocess.TimeoutExpired(
            cmd=args[0] if args else "git",
            timeout=float(kwargs.get("timeout", 0)),
        )

    monkeypatch.setattr(subprocess, "run", _timeout)
    status = toolkit.git_status(repo_path=".")
    assert status["ok"] is False
    assert status["error"] == "git_execution_timeout"
