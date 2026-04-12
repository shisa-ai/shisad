"""Cover lazy-import __getattr__ in assistant and executors __init__."""

from __future__ import annotations

import pytest


class TestAssistantLazyInit:
    def test_lazy_import_resolves_known_name(self) -> None:
        from shisad.assistant import FsGitToolkit

        assert FsGitToolkit is not None

    def test_lazy_import_raises_on_unknown(self) -> None:
        import shisad.assistant as mod

        with pytest.raises(AttributeError, match="has no attribute"):
            mod.__getattr__("NoSuchThing")


class TestExecutorsLazyInit:
    def test_lazy_import_resolves_known_name(self) -> None:
        from shisad.executors import SandboxType

        assert SandboxType is not None

    def test_lazy_import_raises_on_unknown(self) -> None:
        import shisad.executors as mod

        with pytest.raises(AttributeError, match="has no attribute"):
            mod.__getattr__("NoSuchThing")
