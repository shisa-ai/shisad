"""Unit checks for delegated TASK-session helper logic."""

from __future__ import annotations

import pytest

from shisad.core.types import Capability
from shisad.daemon.handlers._impl_session import (
    _compose_task_request_content,
    _resolve_task_capability_scope,
)


def test_m2_task_capability_scope_defaults_to_parent_capabilities() -> None:
    parent = {Capability.FILE_READ, Capability.HTTP_REQUEST}

    scoped = _resolve_task_capability_scope(parent_capabilities=parent, requested_capabilities=None)

    assert scoped == parent


def test_m2_task_capability_scope_rejects_scope_widening() -> None:
    parent = {Capability.FILE_READ}

    with pytest.raises(ValueError, match="outside parent session scope"):
        _resolve_task_capability_scope(
            parent_capabilities=parent,
            requested_capabilities=["file.read", "shell.exec"],
        )


def test_m2_compose_task_request_content_includes_deduped_file_refs() -> None:
    content = _compose_task_request_content(
        task_description="Review the listed files.",
        file_refs=["README.md", " README.md ", "original v0.4 M3 design notes", ""],
    )

    assert content.startswith("TASK REQUEST:")
    assert "Review the listed files." in content
    assert "- README.md" in content
    assert "- original v0.4 M3 design notes" in content
    assert content.count("README.md") == 1
