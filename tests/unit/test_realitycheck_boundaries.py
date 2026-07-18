"""Focused boundary tests for Reality Check controls."""

from __future__ import annotations

from pathlib import Path
from typing import Any
from urllib.error import HTTPError

import pytest

import shisad.assistant.realitycheck as realitycheck_module
from shisad.assistant.realitycheck import RealityCheckToolkit


def _toolkit(
    *,
    repo_root: Path,
    data_roots: list[Path],
    endpoint_enabled: bool = False,
    endpoint_url: str = "",
    allowed_domains: list[str] | None = None,
    max_read_bytes: int = 65536,
) -> RealityCheckToolkit:
    return RealityCheckToolkit(
        enabled=True,
        repo_root=repo_root,
        data_roots=data_roots,
        endpoint_enabled=endpoint_enabled,
        endpoint_url=endpoint_url,
        allowed_domains=allowed_domains or [],
        timeout_seconds=3.0,
        max_read_bytes=max_read_bytes,
    )


def test_m3_realitycheck_read_blocks_symlink_escape(tmp_path: Path) -> None:
    repo_root = tmp_path / "repo"
    data_root = tmp_path / "data"
    repo_root.mkdir(parents=True)
    data_root.mkdir(parents=True)

    outside = tmp_path / "outside.md"
    outside.write_text("outside", encoding="utf-8")
    (data_root / "escape.md").symlink_to(outside)

    toolkit = _toolkit(repo_root=repo_root, data_roots=[data_root])
    result = toolkit.read_source(path="escape.md")
    assert result["ok"] is False
    assert result["error"] == "path_not_allowlisted"


def test_m3_realitycheck_search_remote_blocks_redirects(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo_root = tmp_path / "repo"
    data_root = tmp_path / "data"
    repo_root.mkdir(parents=True)
    data_root.mkdir(parents=True)

    toolkit = _toolkit(
        repo_root=repo_root,
        data_roots=[data_root],
        endpoint_enabled=True,
        endpoint_url="https://allowed.example/search",
        allowed_domains=["allowed.example"],
    )

    class _RedirectingOpener:
        def open(self, request: Any, timeout: float = 0.0) -> Any:
            _ = timeout
            raise HTTPError(
                url=str(getattr(request, "full_url", "")),
                code=302,
                msg="Found",
                hdrs=None,
                fp=None,
            )

    monkeypatch.setattr(realitycheck_module, "_NO_REDIRECT_OPENER", _RedirectingOpener())

    result = toolkit.search(query="roadmap", mode="remote")
    assert result["ok"] is False
    assert result["error"] == "endpoint_redirect_disallowed"


def test_m3_realitycheck_read_reports_truncation_when_limit_exceeded(tmp_path: Path) -> None:
    repo_root = tmp_path / "repo"
    data_root = tmp_path / "data"
    repo_root.mkdir(parents=True)
    data_root.mkdir(parents=True)

    source = data_root / "large.txt"
    source.write_text("A" * 4096, encoding="utf-8")

    toolkit = _toolkit(repo_root=repo_root, data_roots=[data_root], max_read_bytes=4096)
    result = toolkit.read_source(path="large.txt", max_bytes=128)
    assert result["ok"] is True
    assert result["truncated"] is True
    # read_source enforces a minimum byte limit of 1024 even when max_bytes is lower.
    assert len(str(result["content"]).encode("utf-8")) <= 1024
