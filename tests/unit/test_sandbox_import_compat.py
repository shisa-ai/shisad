"""M3 import compatibility checks for sandbox package migration."""

from __future__ import annotations

from shisad.executors.sandbox import SandboxConfig, SandboxOrchestrator, SandboxResult


def test_m3_sandbox_import_path_compatibility() -> None:
    assert SandboxOrchestrator.__name__ == "SandboxOrchestrator"
    assert SandboxConfig.__name__ == "SandboxConfig"
    assert SandboxResult.__name__ == "SandboxResult"
