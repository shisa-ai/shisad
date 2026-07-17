"""Unit checks for M2 assistant primitive helpers."""

from __future__ import annotations

import io
import os
import subprocess
from pathlib import Path
from urllib.error import HTTPError

import pytest

from shisad.assistant.fs_git import FsGitToolkit
from shisad.assistant.web import WebToolkit
from shisad.core.authority import DaemonAuthorityCandidate


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


def test_f3_fs_git_toolkit_blocks_authority_tree_and_derived_paths(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    data_root = workspace / ".shisad"
    approval_path = workspace / "approval.json"
    workspace.mkdir()
    toolkit = FsGitToolkit(
        roots=[workspace],
        max_read_bytes=1024,
        protected_write_authorities=(
            DaemonAuthorityCandidate(role="data_root", path=data_root),
            DaemonAuthorityCandidate(role="approval_factor_store", path=approval_path),
        ),
    )

    blocked_tree = toolkit.write_file(
        path=str(data_root / "audit.jsonl"),
        content="attacker",
        confirm=True,
    )
    blocked_derived = toolkit.write_file(
        path=str(workspace / "approval.json.corrupt.retained"),
        content="attacker",
        confirm=True,
    )
    allowed = toolkit.write_file(
        path=str(workspace / "notes.txt"),
        content="normal",
        confirm=True,
    )

    assert blocked_tree["error"] == "protected_control_plane_path"
    assert blocked_derived["error"] == "protected_control_plane_path"
    assert allowed["ok"] is True


@pytest.mark.parametrize("protection_kind", ["authority", "configured_root"])
def test_f3_fs_git_toolkit_hardlink_write_preserves_protected_tree_inode(
    tmp_path: Path,
    protection_kind: str,
) -> None:
    workspace = tmp_path / "workspace"
    protected_root = workspace / ".shisad"
    protected_root.mkdir(parents=True)
    protected_path = protected_root / "claim.json"
    protected_path.write_text("trusted claim", encoding="utf-8")
    alias_path = workspace / "claim-alias.json"
    os.link(protected_path, alias_path)
    original_inode = protected_path.stat().st_ino
    kwargs: dict[str, object]
    if protection_kind == "authority":
        kwargs = {
            "protected_write_authorities": (
                DaemonAuthorityCandidate(role="data_root", path=protected_root),
            )
        }
    else:
        kwargs = {"protected_write_roots": (protected_root,)}
    toolkit = FsGitToolkit(roots=[workspace], max_read_bytes=1024, **kwargs)

    result = toolkit.write_file(
        path=str(alias_path),
        content="authorized alias update",
        confirm=True,
    )

    assert result["ok"] is True
    assert protected_path.read_text(encoding="utf-8") == "trusted claim"
    assert protected_path.stat().st_ino == original_inode
    assert alias_path.read_text(encoding="utf-8") == "authorized alias update"
    assert alias_path.stat().st_ino != original_inode


def test_f3_fs_git_toolkit_write_supports_long_valid_basename(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    target = workspace / ("n" * 240)
    target.write_text("original", encoding="utf-8")
    toolkit = FsGitToolkit(roots=[workspace], max_read_bytes=1024)

    result = toolkit.write_file(
        path=str(target),
        content="updated",
        confirm=True,
    )

    assert result["ok"] is True
    assert target.read_text(encoding="utf-8") == "updated"


@pytest.mark.parametrize("operation", ["list", "read", "write", "git"])
def test_f3_fs_git_toolkit_parent_swap_cannot_escape_allowlisted_root(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    operation: str,
) -> None:
    workspace = tmp_path / "workspace"
    safe_parent = workspace / "safe"
    outside_parent = tmp_path / "outside"
    safe_parent.mkdir(parents=True)
    outside_parent.mkdir()
    (safe_parent / "target.txt").write_text("safe", encoding="utf-8")
    (outside_parent / "target.txt").write_text("outside", encoding="utf-8")
    (outside_parent / "outside-only.txt").write_text("outside", encoding="utf-8")
    for repo, message in ((safe_parent, "safe-commit"), (outside_parent, "outside-commit")):
        subprocess.run(["git", "-C", str(repo), "init"], check=True, capture_output=True)
        subprocess.run(
            ["git", "-C", str(repo), "config", "user.email", "test@example.com"],
            check=True,
            capture_output=True,
        )
        subprocess.run(
            ["git", "-C", str(repo), "config", "user.name", "Test User"],
            check=True,
            capture_output=True,
        )
        subprocess.run(
            ["git", "-C", str(repo), "add", "target.txt"],
            check=True,
            capture_output=True,
        )
        subprocess.run(
            ["git", "-C", str(repo), "commit", "-m", message],
            check=True,
            capture_output=True,
        )

    toolkit = FsGitToolkit(roots=[workspace], max_read_bytes=1024)
    original_resolve = FsGitToolkit._resolve_path
    moved_parent = workspace / "safe-before-swap"
    swapped = False

    def _resolve_then_swap(self: FsGitToolkit, value: str) -> Path | dict[str, object]:
        nonlocal swapped
        resolved = original_resolve(self, value)
        if not swapped and not isinstance(resolved, dict):
            safe_parent.rename(moved_parent)
            safe_parent.symlink_to(outside_parent, target_is_directory=True)
            swapped = True
        return resolved

    monkeypatch.setattr(FsGitToolkit, "_resolve_path", _resolve_then_swap)

    if operation == "list":
        result = toolkit.list_dir(path="safe")
        if result["ok"]:
            assert "outside-only.txt" not in {row["name"] for row in result["entries"]}
    elif operation == "read":
        result = toolkit.read_file(path="safe/target.txt")
        if result["ok"]:
            assert result["content"] == "safe"
    elif operation == "write":
        result = toolkit.write_file(path="safe/target.txt", content="updated", confirm=True)
        assert outside_parent.joinpath("target.txt").read_text(encoding="utf-8") == "outside"
    else:
        result = toolkit.git_log(repo_path="safe", limit=1)
        if result["ok"]:
            assert "outside-commit" not in result["output"]

    assert swapped is True


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
