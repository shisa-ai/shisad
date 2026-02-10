"""Sandboxed executor subsystem."""

from shisad.executors.browser import (
    BrowserClipboardMode,
    BrowserCookiesMode,
    BrowserDownloadsMode,
    BrowserExtensionsMode,
    BrowserLocalNetworkMode,
    BrowserPasteResult,
    BrowserSandbox,
    BrowserSandboxMode,
    BrowserSandboxPolicy,
    BrowserScreenshotResult,
)
from shisad.executors.connect_path import ConnectPathProxy, ConnectPathResult, NoopConnectPathProxy
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

__all__ = [
    "BrowserClipboardMode",
    "BrowserCookiesMode",
    "BrowserDownloadsMode",
    "BrowserExtensionsMode",
    "BrowserLocalNetworkMode",
    "BrowserPasteResult",
    "BrowserSandbox",
    "BrowserSandboxMode",
    "BrowserSandboxPolicy",
    "BrowserScreenshotResult",
    "ConnectPathProxy",
    "ConnectPathResult",
    "DegradedModePolicy",
    "EgressProxy",
    "EnvironmentPolicy",
    "FilesystemAccessDecision",
    "FilesystemPolicy",
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
