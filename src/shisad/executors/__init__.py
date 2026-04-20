"""Sandboxed executor subsystem."""

from __future__ import annotations

from importlib import import_module
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from shisad.executors.browser import (
        BrowserClipboardMode,
        BrowserCommandRunner,
        BrowserCookiesMode,
        BrowserDownloadsMode,
        BrowserExtensionsMode,
        BrowserLocalNetworkMode,
        BrowserPasteResult,
        BrowserSandbox,
        BrowserSandboxMode,
        BrowserSandboxPolicy,
        BrowserScreenshotResult,
        BrowserToolkit,
    )
    from shisad.executors.connect_path import (
        ConnectPathProxy,
        ConnectPathResult,
        IptablesConnectPathProxy,
        NoopConnectPathProxy,
    )
    from shisad.executors.mounts import (
        FilesystemAccessDecision,
        FilesystemPolicy,
        MountManager,
        MountRule,
    )
    from shisad.executors.proxy import EgressProxy, NetworkPolicy, ProxyDecision
    from shisad.executors.sandbox import (
        DegradedModePolicy,
        EnvironmentPolicy,
        ResourceLimits,
        SandboxConfig,
        SandboxOrchestrator,
        SandboxResult,
        SandboxType,
    )

_EXPORT_MODULES = {
    "BrowserClipboardMode": "shisad.executors.browser",
    "BrowserCommandRunner": "shisad.executors.browser",
    "BrowserCookiesMode": "shisad.executors.browser",
    "BrowserDownloadsMode": "shisad.executors.browser",
    "BrowserExtensionsMode": "shisad.executors.browser",
    "BrowserLocalNetworkMode": "shisad.executors.browser",
    "BrowserPasteResult": "shisad.executors.browser",
    "BrowserSandbox": "shisad.executors.browser",
    "BrowserSandboxMode": "shisad.executors.browser",
    "BrowserSandboxPolicy": "shisad.executors.browser",
    "BrowserScreenshotResult": "shisad.executors.browser",
    "BrowserToolkit": "shisad.executors.browser",
    "ConnectPathProxy": "shisad.executors.connect_path",
    "ConnectPathResult": "shisad.executors.connect_path",
    "DegradedModePolicy": "shisad.executors.sandbox",
    "EgressProxy": "shisad.executors.proxy",
    "EnvironmentPolicy": "shisad.executors.sandbox",
    "FilesystemAccessDecision": "shisad.executors.mounts",
    "FilesystemPolicy": "shisad.executors.mounts",
    "IptablesConnectPathProxy": "shisad.executors.connect_path",
    "MountManager": "shisad.executors.mounts",
    "MountRule": "shisad.executors.mounts",
    "NetworkPolicy": "shisad.executors.proxy",
    "NoopConnectPathProxy": "shisad.executors.connect_path",
    "ProxyDecision": "shisad.executors.proxy",
    "ResourceLimits": "shisad.executors.sandbox",
    "SandboxConfig": "shisad.executors.sandbox",
    "SandboxOrchestrator": "shisad.executors.sandbox",
    "SandboxResult": "shisad.executors.sandbox",
    "SandboxType": "shisad.executors.sandbox",
}

__all__ = [
    "BrowserClipboardMode",
    "BrowserCommandRunner",
    "BrowserCookiesMode",
    "BrowserDownloadsMode",
    "BrowserExtensionsMode",
    "BrowserLocalNetworkMode",
    "BrowserPasteResult",
    "BrowserSandbox",
    "BrowserSandboxMode",
    "BrowserSandboxPolicy",
    "BrowserScreenshotResult",
    "BrowserToolkit",
    "ConnectPathProxy",
    "ConnectPathResult",
    "DegradedModePolicy",
    "EgressProxy",
    "EnvironmentPolicy",
    "FilesystemAccessDecision",
    "FilesystemPolicy",
    "IptablesConnectPathProxy",
    "MountManager",
    "MountRule",
    "NetworkPolicy",
    "NoopConnectPathProxy",
    "ProxyDecision",
    "ResourceLimits",
    "SandboxConfig",
    "SandboxOrchestrator",
    "SandboxResult",
    "SandboxType",
]


def __getattr__(name: str) -> Any:
    module_name = _EXPORT_MODULES.get(name)
    if module_name is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    value = getattr(import_module(module_name), name)
    globals()[name] = value
    return value
