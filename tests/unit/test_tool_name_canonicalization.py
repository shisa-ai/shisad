"""Tool-name canonicalization coverage for S9 migration adapter."""

from __future__ import annotations

import logging

import pytest

from shisad.core.tools import names as names_module
from shisad.core.tools.names import canonical_tool_name


@pytest.fixture(autouse=True)
def _reset_deprecation_warning_cache() -> None:
    names_module._WARNED_LEGACY_ALIASES.clear()


def test_s9_canonical_tool_name_maps_legacy_aliases() -> None:
    assert canonical_tool_name("shell_exec") == "shell.exec"
    assert canonical_tool_name("http_request") == "http.request"
    assert canonical_tool_name("web_search") == "web.search"
    assert canonical_tool_name("web_fetch") == "web.fetch"
    assert canonical_tool_name("file_read") == "file.read"
    assert canonical_tool_name("file_write") == "file.write"
    assert canonical_tool_name("fs_list") == "fs.list"
    assert canonical_tool_name("fs_read") == "fs.read"
    assert canonical_tool_name("fs_write") == "fs.write"
    assert canonical_tool_name("git_status") == "git.status"
    assert canonical_tool_name("git_diff") == "git.diff"
    assert canonical_tool_name("git_log") == "git.log"
    assert canonical_tool_name("realitycheck_search") == "realitycheck.search"
    assert canonical_tool_name("realitycheck_read") == "realitycheck.read"
    assert canonical_tool_name("note_create") == "note.create"
    assert canonical_tool_name("note_list") == "note.list"
    assert canonical_tool_name("note_search") == "note.search"
    assert canonical_tool_name("todo_create") == "todo.create"
    assert canonical_tool_name("todo_list") == "todo.list"
    assert canonical_tool_name("todo_complete") == "todo.complete"
    assert canonical_tool_name("reminder_create") == "reminder.create"
    assert canonical_tool_name("reminder_list") == "reminder.list"
    assert canonical_tool_name("message_send") == "message.send"


def test_s9_canonical_tool_name_accepts_functions_namespace_aliases() -> None:
    assert canonical_tool_name("functions.fs_list") == "fs.list"
    assert canonical_tool_name("functions.fs.read") == "fs.read"
    assert canonical_tool_name("functions.web_search") == "web.search"
    assert canonical_tool_name("functions.report_anomaly") == "report_anomaly"


def test_s9_canonical_tool_name_preserves_canonical_ids() -> None:
    assert canonical_tool_name("shell.exec") == "shell.exec"
    assert canonical_tool_name("http.request") == "http.request"
    assert canonical_tool_name("web.search") == "web.search"
    assert canonical_tool_name("web.fetch") == "web.fetch"
    assert canonical_tool_name("realitycheck.search") == "realitycheck.search"


def test_m1_pf36_legacy_alias_emits_deprecation_warning(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.WARNING, logger="shisad.core.tools.names"):
        resolved = canonical_tool_name("shell_exec")
    assert resolved == "shell.exec"
    assert any("deprecated" in record.getMessage().lower() for record in caplog.records)


def test_m1_pf36_legacy_alias_warning_emits_once(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.WARNING, logger="shisad.core.tools.names"):
        assert canonical_tool_name("shell_exec") == "shell.exec"
        assert canonical_tool_name("shell_exec") == "shell.exec"
    assert sum("deprecated" in record.getMessage().lower() for record in caplog.records) == 1


def test_m3_tool_alias_can_be_resolved_without_warning(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.WARNING, logger="shisad.core.tools.names"):
        resolved = canonical_tool_name("fs_read", warn_on_alias=False)
    assert resolved == "fs.read"
    assert not caplog.records
