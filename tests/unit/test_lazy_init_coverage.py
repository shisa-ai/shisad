"""Public lazy exports resolve to the canonical implementation objects."""

from importlib import import_module

import pytest


@pytest.mark.parametrize(
    ("package", "name", "implementation"),
    [
        ("shisad.assistant", "FsGitToolkit", "shisad.assistant.fs_git"),
        ("shisad.executors", "SandboxType", "shisad.executors.sandbox.models"),
    ],
)
def test_public_lazy_export_identity(package: str, name: str, implementation: str) -> None:
    exported = getattr(import_module(package), name)
    assert exported is getattr(import_module(implementation), name)


@pytest.mark.parametrize("package", ["shisad.assistant", "shisad.executors"])
def test_unknown_public_export_raises(package: str) -> None:
    with pytest.raises(AttributeError, match="NoSuchThing"):
        _ = import_module(package).NoSuchThing
