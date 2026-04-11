"""Assistant primitive helpers for v0.3 runtime features."""

from __future__ import annotations

from importlib import import_module
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from shisad.assistant.fs_git import FsGitToolkit
    from shisad.assistant.realitycheck import RealityCheckToolkit
    from shisad.assistant.web import WebToolkit

_EXPORT_MODULES = {
    "FsGitToolkit": "shisad.assistant.fs_git",
    "RealityCheckToolkit": "shisad.assistant.realitycheck",
    "WebToolkit": "shisad.assistant.web",
}

__all__ = ["FsGitToolkit", "RealityCheckToolkit", "WebToolkit"]


def __getattr__(name: str) -> Any:
    module_name = _EXPORT_MODULES.get(name)
    if module_name is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    value = getattr(import_module(module_name), name)
    globals()[name] = value
    return value
