"""Unit checks for M2 assistant primitive helpers."""

from __future__ import annotations

import io
import subprocess
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


def test_web_fetch_blocks_unallowlisted_destination(tmp_path: Path) -> None:
    toolkit = WebToolkit(
        data_dir=tmp_path,
        search_enabled=True,
        search_backend_url="https://search.example",
        fetch_enabled=True,
        allowed_domains=["allowed.example"],
        timeout_seconds=5.0,
        max_fetch_bytes=65536,
    )
    result = toolkit.fetch(url="https://blocked.example/path")
    assert result["ok"] is False
    assert result["error"] == "destination_not_allowlisted"


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
    assert result["error"] == "destination_not_allowlisted"


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
    assert result["error"] == "web_search_backend_not_allowlisted"


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
