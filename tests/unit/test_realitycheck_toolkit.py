"""Unit coverage for M3 Reality Check toolkit boundaries."""

from __future__ import annotations

from pathlib import Path

from shisad.assistant.realitycheck import RealityCheckToolkit


def _toolkit(
    *,
    repo_root: Path,
    data_roots: list[Path],
    enabled: bool = True,
    endpoint_enabled: bool = False,
    endpoint_url: str = "",
    allowed_domains: list[str] | None = None,
) -> RealityCheckToolkit:
    return RealityCheckToolkit(
        enabled=enabled,
        repo_root=repo_root,
        data_roots=data_roots,
        endpoint_enabled=endpoint_enabled,
        endpoint_url=endpoint_url,
        allowed_domains=allowed_domains or [],
        timeout_seconds=5.0,
        max_read_bytes=65536,
    )


def test_m3_realitycheck_fail_closed_when_disabled(tmp_path: Path) -> None:
    repo_root = tmp_path / "realitycheck"
    data_root = tmp_path / "realitycheck-data"
    repo_root.mkdir(parents=True)
    data_root.mkdir(parents=True)
    toolkit = _toolkit(
        repo_root=repo_root,
        data_roots=[data_root],
        enabled=False,
    )
    search = toolkit.search(query="roadmap")
    read = toolkit.read_source(path="docs/source.md")
    assert search["ok"] is False
    assert search["error"] == "realitycheck_disabled"
    assert read["ok"] is False
    assert read["error"] == "realitycheck_disabled"


def test_m3_realitycheck_fail_closed_when_misconfigured(tmp_path: Path) -> None:
    toolkit = _toolkit(
        repo_root=tmp_path / "missing-repo",
        data_roots=[tmp_path / "missing-data"],
        enabled=True,
    )
    health = toolkit.doctor_status()
    result = toolkit.search(query="roadmap")
    assert health["status"] == "misconfigured"
    assert "repo_root_missing" in health["problems"]
    assert "data_roots_missing" in health["problems"]
    assert result["ok"] is False
    assert result["error"] == "realitycheck_misconfigured"


def test_m3_realitycheck_read_blocks_path_traversal(tmp_path: Path) -> None:
    repo_root = tmp_path / "realitycheck"
    data_root = tmp_path / "realitycheck-data"
    repo_root.mkdir(parents=True)
    data_root.mkdir(parents=True)
    (tmp_path / "outside.md").write_text("outside", encoding="utf-8")

    toolkit = _toolkit(repo_root=repo_root, data_roots=[data_root], enabled=True)
    blocked = toolkit.read_source(path="../outside.md")
    assert blocked["ok"] is False
    assert blocked["error"] == "path_not_allowlisted"


def test_m3_realitycheck_read_returns_tainted_evidence(tmp_path: Path) -> None:
    repo_root = tmp_path / "realitycheck"
    data_root = tmp_path / "realitycheck-data"
    repo_root.mkdir(parents=True)
    data_root.mkdir(parents=True)
    source = data_root / "source.md"
    source.write_text("hello world", encoding="utf-8")

    toolkit = _toolkit(repo_root=repo_root, data_roots=[data_root], enabled=True)
    result = toolkit.read_source(path="source.md")
    assert result["ok"] is True
    assert result["path"] == str(source.resolve(strict=False))
    assert result["content"] == "hello world"
    assert result["taint_labels"] == ["untrusted"]
    assert result["evidence"]["operation"] == "realitycheck.read"


def test_m3_realitycheck_search_local_returns_citations_and_taint(tmp_path: Path) -> None:
    repo_root = tmp_path / "realitycheck"
    data_root = tmp_path / "realitycheck-data"
    repo_root.mkdir(parents=True)
    data_root.mkdir(parents=True)
    source = data_root / "claim.md"
    source.write_text("Security roadmap includes hard boundaries.", encoding="utf-8")

    toolkit = _toolkit(repo_root=repo_root, data_roots=[data_root], enabled=True)
    result = toolkit.search(query="hard boundaries", limit=3, mode="local")
    assert result["ok"] is True
    assert result["mode"] == "local"
    assert result["results"]
    citation = result["results"][0]["citation"]
    assert citation["path"] == str(source.resolve(strict=False))
    assert result["taint_labels"] == ["untrusted"]
    assert result["evidence"]["operation"] == "realitycheck.search"


def test_m3_realitycheck_endpoint_host_must_be_allowlisted(tmp_path: Path) -> None:
    repo_root = tmp_path / "realitycheck"
    data_root = tmp_path / "realitycheck-data"
    repo_root.mkdir(parents=True)
    data_root.mkdir(parents=True)

    toolkit = _toolkit(
        repo_root=repo_root,
        data_roots=[data_root],
        enabled=True,
        endpoint_enabled=True,
        endpoint_url="https://blocked.example/search",
        allowed_domains=["allowed.example"],
    )
    health = toolkit.doctor_status()
    result = toolkit.search(query="roadmap", mode="remote")
    assert health["status"] == "misconfigured"
    assert "endpoint_not_allowlisted" in health["problems"]
    assert result["ok"] is False
    assert result["error"] == "realitycheck_misconfigured"
