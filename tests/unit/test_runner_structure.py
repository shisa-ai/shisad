"""M2 runner structure guardrails."""

from __future__ import annotations

import ast
from pathlib import Path

from shisad.core.api.schema import (
    AdminSoulReadParams,
    AdminSoulUpdateParams,
    ChannelPairingProposalParams,
    DevCloseParams,
    DevImplementParams,
    DevRemediateParams,
    DevReviewParams,
    DoctorCheckParams,
    EmailReadParams,
    EmailSearchParams,
    RealityCheckReadParams,
    RealityCheckSearchParams,
    SessionSetModeParams,
    SessionTerminateParams,
)
from shisad.daemon.runner import _method_specs


def test_run_daemon_is_orchestration_only() -> None:
    tree = ast.parse(Path("src/shisad/daemon/runner.py").read_text(encoding="utf-8"))
    run = next(
        node
        for node in tree.body
        if isinstance(node, ast.AsyncFunctionDef) and node.name == "run_daemon"
    )
    length = (run.end_lineno or run.lineno) - run.lineno + 1
    assert length <= 200

    nested = [
        node
        for node in ast.walk(run)
        if node is not run
        and isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
    ]
    assert nested == []


def test_runner_has_no_private_provider_classes() -> None:
    tree = ast.parse(Path("src/shisad/daemon/runner.py").read_text(encoding="utf-8"))
    private_classes = [
        node.name
        for node in tree.body
        if isinstance(node, ast.ClassDef) and node.name.startswith("_")
    ]
    assert private_classes == []


def test_runner_registers_m4_dev_methods_and_m3_realitycheck_and_doctor_methods() -> None:
    class _HandlerStub:
        def __getattr__(self, _name: str):  # type: ignore[no-untyped-def]
            async def _handler(*_args: object, **_kwargs: object) -> dict[str, object]:
                return {}

            return _handler

    specs = _method_specs(_HandlerStub(), test_mode=False)
    mapping = {name: params_model for name, _handler, _admin_only, params_model in specs}
    admin_only = {name: is_admin for name, _handler, is_admin, _params_model in specs}
    assert mapping["doctor.check"] is DoctorCheckParams
    assert mapping["dev.implement"] is DevImplementParams
    assert mapping["dev.review"] is DevReviewParams
    assert mapping["dev.remediate"] is DevRemediateParams
    assert mapping["dev.close"] is DevCloseParams
    assert mapping["admin.soul.read"] is AdminSoulReadParams
    assert mapping["admin.soul.update"] is AdminSoulUpdateParams
    assert mapping["session.set_mode"] is SessionSetModeParams
    assert mapping["session.terminate"] is SessionTerminateParams
    assert mapping["channel.pairing_propose"] is ChannelPairingProposalParams
    assert mapping["realitycheck.search"] is RealityCheckSearchParams
    assert mapping["realitycheck.read"] is RealityCheckReadParams
    assert mapping["email.search"] is EmailSearchParams
    assert mapping["email.read"] is EmailReadParams
    assert admin_only["dev.implement"] is True
    assert admin_only["dev.review"] is True
    assert admin_only["dev.remediate"] is True
    assert admin_only["dev.close"] is True
    assert admin_only["admin.soul.read"] is True
    assert admin_only["admin.soul.update"] is True
    assert admin_only["session.restore"] is True
    assert admin_only["session.export"] is True
    assert "daemon.reset" not in mapping

    test_mode_specs = _method_specs(_HandlerStub(), test_mode=True)
    test_mode_methods = [name for name, _handler, _admin_only, _params_model in test_mode_specs]
    assert "daemon.reset" in test_mode_methods
    assert test_mode_methods.index("daemon.reset") == test_mode_methods.index("daemon.shutdown") + 1
