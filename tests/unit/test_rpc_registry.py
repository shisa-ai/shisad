"""F11A authoritative control-RPC descriptor contract."""

from __future__ import annotations

import hashlib
import inspect
import subprocess
import sys
from dataclasses import replace
from types import SimpleNamespace
from typing import get_type_hints

import pytest

from shisad.core.api.rpc_registry import (
    RpcAvailability,
    RpcHandlerGroup,
    RpcResultModelRef,
    rpc_method_descriptors,
    rpc_method_manifest,
)
from shisad.daemon.control_handlers import DaemonControlHandlers
from shisad.daemon.handlers import (
    AdminHandlers,
    AssistantHandlers,
    ConfirmationHandlers,
    DashboardHandlers,
    MemoryHandlers,
    PlanHandlers,
    SessionHandlers,
    SkillHandlers,
    TaskHandlers,
    ToolExecutionHandlers,
)

_FROZEN_F11A_MANIFEST_SHA256 = "d91a1699974a7202ee5461bdc4a23a3c1d1ef940dae53af31fa0271630add9ff"
_GROUP_TYPES = {
    RpcHandlerGroup.ADMIN: AdminHandlers,
    RpcHandlerGroup.ASSISTANT: AssistantHandlers,
    RpcHandlerGroup.CONFIRMATION: ConfirmationHandlers,
    RpcHandlerGroup.DASHBOARD: DashboardHandlers,
    RpcHandlerGroup.MEMORY: MemoryHandlers,
    RpcHandlerGroup.PLAN_STEPS: PlanHandlers,
    RpcHandlerGroup.SESSION: SessionHandlers,
    RpcHandlerGroup.SKILLS: SkillHandlers,
    RpcHandlerGroup.TASKS: TaskHandlers,
    RpcHandlerGroup.TOOL_EXECUTION: ToolExecutionHandlers,
}
_GROUP_ATTRIBUTES = {
    RpcHandlerGroup.ADMIN: "admin",
    RpcHandlerGroup.ASSISTANT: "assistant",
    RpcHandlerGroup.CONFIRMATION: "confirmation",
    RpcHandlerGroup.DASHBOARD: "dashboard",
    RpcHandlerGroup.MEMORY: "memory",
    RpcHandlerGroup.PLAN_STEPS: "plan_steps",
    RpcHandlerGroup.SESSION: "session",
    RpcHandlerGroup.SKILLS: "skills",
    RpcHandlerGroup.TASKS: "tasks",
    RpcHandlerGroup.TOOL_EXECUTION: "tool_execution",
}


def _annotation_name(annotation: object) -> str:
    return annotation if isinstance(annotation, str) else str(getattr(annotation, "__name__", ""))


def _manifest_digest() -> str:
    rows = (
        "|".join(
            (
                descriptor.name,
                f"{descriptor.params_model.__module__}.{descriptor.params_model.__qualname__}",
                descriptor.result_model.qualified_name,
                str(int(descriptor.admin_only)),
                descriptor.handler_group.value,
                descriptor.handler_method,
                descriptor.availability.value,
                descriptor.readiness.value,
            )
        )
        for descriptor in rpc_method_descriptors(test_mode=True)
    )
    return hashlib.sha256("\n".join(rows).encode()).hexdigest()


def test_f11a_descriptor_manifest_matches_frozen_transport_contract() -> None:
    production = rpc_method_descriptors(test_mode=False)
    test_mode = rpc_method_descriptors(test_mode=True)

    assert isinstance(production, tuple)
    assert isinstance(test_mode, tuple)
    assert len(production) == 122
    assert len(test_mode) == 123
    assert len({descriptor.name for descriptor in test_mode}) == 123
    assert sum(descriptor.admin_only for descriptor in test_mode) == 79
    assert _manifest_digest() == _FROZEN_F11A_MANIFEST_SHA256

    production_names = [descriptor.name for descriptor in production]
    test_names = [descriptor.name for descriptor in test_mode]
    assert "daemon.reset" not in production_names
    assert test_names.index("daemon.reset") == test_names.index("daemon.shutdown") + 1
    reset = test_mode[test_names.index("daemon.reset")]
    assert reset.availability is RpcAvailability.TEST_MODE


def test_f11a_descriptor_routes_match_every_typed_group_signature() -> None:
    for descriptor in rpc_method_descriptors(test_mode=True):
        owner_type = _GROUP_TYPES[descriptor.handler_group]
        handler = getattr(owner_type, descriptor.handler_method)
        signature = inspect.signature(handler)

        assert _annotation_name(signature.parameters["params"].annotation) == (
            descriptor.params_model.__name__
        )
        assert _annotation_name(signature.return_annotation) == descriptor.result_model.name


def test_f11b_control_graph_exposes_every_typed_group() -> None:
    annotations = get_type_hints(DaemonControlHandlers)

    assert {attribute: annotations.get(attribute) for attribute in _GROUP_ATTRIBUTES.values()} == {
        _GROUP_ATTRIBUTES[group]: owner_type for group, owner_type in _GROUP_TYPES.items()
    }


def test_f11b_control_graph_has_no_rpc_forwarding_methods() -> None:
    assert [
        name
        for name, member in vars(DaemonControlHandlers).items()
        if name.startswith("handle_") and callable(member)
    ] == []


def test_f11_control_graph_binds_only_explicit_owned_groups() -> None:
    graph = object.__new__(DaemonControlHandlers)
    expected = {}
    for group, attribute in _GROUP_ATTRIBUTES.items():
        methods = {}
        for descriptor in rpc_method_descriptors(test_mode=True):
            if descriptor.handler_group is not group:
                continue

            async def _handler(*_args: object, **_kwargs: object) -> None:
                return None

            methods[descriptor.handler_method] = _handler
            expected[descriptor.name] = _handler
        setattr(graph, attribute, SimpleNamespace(**methods))

    for descriptor in rpc_method_descriptors(test_mode=True):
        assert graph.bind_rpc_handler(descriptor) is expected[descriptor.name]


def test_f11_control_graph_rejects_missing_explicit_route() -> None:
    graph = object.__new__(DaemonControlHandlers)
    descriptor = replace(
        rpc_method_descriptors(test_mode=False)[0],
        handler_method="handle_missing",
    )
    for attribute in _GROUP_ATTRIBUTES.values():
        setattr(graph, attribute, SimpleNamespace())

    with pytest.raises(RuntimeError, match="control RPC handler does not resolve"):
        graph.bind_rpc_handler(descriptor)


def test_f11a_manifest_is_the_same_immutable_descriptor_projection() -> None:
    descriptors = rpc_method_descriptors(test_mode=True)
    manifest = rpc_method_manifest(test_mode=True)

    assert isinstance(manifest, tuple)
    assert len(manifest) == len(descriptors)
    assert manifest[0].name == "session.create"
    assert manifest[0].params_model == "shisad.core.api.schema.SessionCreateParams"
    assert manifest[0].result_model == "shisad.core.api.schema.SessionCreateResult"
    assert manifest[-1].name == "browser.screenshot"
    assert manifest[-1].result_model == "shisad.executors.browser.BrowserScreenshotResult"
    assert [entry.name for entry in manifest] == [descriptor.name for descriptor in descriptors]


def test_f11a_every_result_model_reference_resolves_to_declared_type() -> None:
    for descriptor in rpc_method_descriptors(test_mode=True):
        result_model = descriptor.result_model.resolve()
        assert result_model.__module__ == descriptor.result_model.module
        assert result_model.__name__ == descriptor.result_model.name


def test_f11a_descriptor_types_fail_closed() -> None:
    descriptor = rpc_method_descriptors(test_mode=False)[0]

    with pytest.raises(TypeError, match="result model"):
        replace(descriptor, result_model=object())  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="handler group"):
        replace(descriptor, handler_group="session")  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="availability"):
        replace(descriptor, availability="always")  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="readiness"):
        replace(descriptor, readiness="handler_gated")  # type: ignore[arg-type]


def test_f11a_result_model_references_are_allowlisted_and_resolvable() -> None:
    with pytest.raises(ValueError, match="unsupported RPC result module"):
        RpcResultModelRef(module="builtins", name="dict")
    with pytest.raises(ValueError, match="invalid RPC result model name"):
        RpcResultModelRef(module="shisad.core.api.schema", name="not.valid")
    with pytest.raises(RuntimeError, match="RPC result model does not resolve"):
        RpcResultModelRef(
            module="shisad.core.api.schema",
            name="MissingResult",
        ).resolve()


def test_f11a_descriptor_value_validation_rejects_malformed_entries() -> None:
    descriptor = rpc_method_descriptors(test_mode=False)[0]

    with pytest.raises(ValueError, match="invalid RPC method name"):
        replace(descriptor, name="session")
    with pytest.raises(TypeError, match="parameter model"):
        replace(descriptor, params_model=str)  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="admin posture"):
        replace(descriptor, admin_only=1)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="handler method"):
        replace(descriptor, handler_method="create")


def test_f11a_core_registry_does_not_eagerly_import_browser_executor() -> None:
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            (
                "import sys; import shisad.core.api.rpc_registry; "
                "assert 'shisad.executors.browser' not in sys.modules"
            ),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
