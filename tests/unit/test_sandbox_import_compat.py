"""The supported sandbox import path exposes the canonical implementation types."""

from shisad.executors.sandbox import SandboxConfig, SandboxOrchestrator, SandboxResult
from shisad.executors.sandbox.models import SandboxConfig as ConfigImplementation
from shisad.executors.sandbox.models import SandboxResult as ResultImplementation
from shisad.executors.sandbox.orchestrator import SandboxOrchestrator as OrchestratorImplementation


def test_sandbox_import_path_compatibility() -> None:
    assert SandboxOrchestrator is OrchestratorImplementation
    assert SandboxConfig is ConfigImplementation
    assert SandboxResult is ResultImplementation
