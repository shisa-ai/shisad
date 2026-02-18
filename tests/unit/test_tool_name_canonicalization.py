"""Tool-name canonicalization coverage for S9 migration adapter."""

from __future__ import annotations

from shisad.core.tools.names import canonical_tool_name


def test_s9_canonical_tool_name_maps_legacy_aliases() -> None:
    assert canonical_tool_name("shell_exec") == "shell.exec"
    assert canonical_tool_name("http_request") == "http.request"
    assert canonical_tool_name("web_search") == "web.search"
    assert canonical_tool_name("web_fetch") == "web.fetch"
    assert canonical_tool_name("file_read") == "file.read"
    assert canonical_tool_name("file_write") == "file.write"


def test_s9_canonical_tool_name_preserves_canonical_ids() -> None:
    assert canonical_tool_name("shell.exec") == "shell.exec"
    assert canonical_tool_name("http.request") == "http.request"
    assert canonical_tool_name("web.search") == "web.search"
    assert canonical_tool_name("web.fetch") == "web.fetch"
    assert canonical_tool_name("realitycheck.search") == "realitycheck.search"
