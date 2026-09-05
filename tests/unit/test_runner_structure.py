"""Control method registration preserves schemas, authority, and bound handlers."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

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
    MemoryProcedureCandidateParams,
    MemoryTimelinePromoteParams,
    MemoryTimelineReadParams,
    MemoryTimelineSearchParams,
    PlanStepsParams,
    RealityCheckReadParams,
    RealityCheckSearchParams,
    SessionSetModeParams,
    SessionTerminateParams,
    TaskStatusSnapshotParams,
)
from shisad.daemon import runner
from shisad.daemon.runner import _method_specs


def test_runner_registers_m4_dev_methods_and_m3_realitycheck_and_doctor_methods() -> None:
    class _HandlerStub:
        def __getattr__(self, _name: str):  # type: ignore[no-untyped-def]
            async def _handler(*_args: object, **_kwargs: object) -> dict[str, object]:
                return {}

            return _handler

        def bind_rpc_handler(self, descriptor):  # type: ignore[no-untyped-def]
            return getattr(self, descriptor.handler_method)

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
    assert mapping["plan.steps"] is PlanStepsParams
    assert mapping["task.status_snapshot"] is TaskStatusSnapshotParams
    assert mapping["channel.pairing_propose"] is ChannelPairingProposalParams
    assert mapping["realitycheck.search"] is RealityCheckSearchParams
    assert mapping["realitycheck.read"] is RealityCheckReadParams
    assert mapping["email.search"] is EmailSearchParams
    assert mapping["email.read"] is EmailReadParams
    assert mapping["memory.review_procedure_candidate"] is MemoryProcedureCandidateParams
    assert mapping["memory.timeline.search"] is MemoryTimelineSearchParams
    assert mapping["memory.timeline.read"] is MemoryTimelineReadParams
    assert mapping["memory.timeline.promote"] is MemoryTimelinePromoteParams
    assert admin_only["dev.implement"] is True
    assert admin_only["dev.review"] is True
    assert admin_only["dev.remediate"] is True
    assert admin_only["dev.close"] is True
    assert admin_only["admin.soul.read"] is True
    assert admin_only["admin.soul.update"] is True
    assert admin_only["session.restore"] is True
    assert admin_only["session.export"] is True
    assert admin_only["plan.steps"] is False
    assert admin_only["task.status_snapshot"] is False
    assert admin_only["memory.review_procedure_candidate"] is True
    assert admin_only["memory.timeline.search"] is False
    assert admin_only["memory.timeline.read"] is False
    assert admin_only["memory.timeline.promote"] is True
    assert "daemon.reset" not in mapping

    test_mode_specs = _method_specs(_HandlerStub(), test_mode=True)
    test_mode_methods = [name for name, _handler, _admin_only, _params_model in test_mode_specs]
    assert "daemon.reset" in test_mode_methods


@pytest.mark.parametrize("test_mode", [False, True])
def test_runner_registers_descriptor_handler_schema_and_authority(
    monkeypatch: pytest.MonkeyPatch,
    test_mode: bool,
) -> None:
    async def handler(params, ctx):
        return params

    descriptor = SimpleNamespace(
        name="example.operation",
        admin_only=True,
        params_model=DoctorCheckParams,
    )
    requested_modes = []
    bound = []

    def descriptors(*, test_mode):
        requested_modes.append(test_mode)
        return (descriptor,)

    def bind(item):
        bound.append(item)
        return handler

    monkeypatch.setattr(runner, "rpc_method_descriptors", descriptors)
    specs = _method_specs(SimpleNamespace(bind_rpc_handler=bind), test_mode=test_mode)

    assert specs == [("example.operation", handler, True, DoctorCheckParams)]
    assert bound == [descriptor]
    assert requested_modes == [test_mode]
