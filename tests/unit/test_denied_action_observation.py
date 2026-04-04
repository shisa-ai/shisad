"""H3 deny-observation failure handling coverage."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from shisad.core.types import SessionId, ToolName
from shisad.daemon.handlers._impl import HandlerImplementation
from shisad.security.control_plane.schema import Origin, build_action
from shisad.security.control_plane.sidecar import (
    ControlPlaneRpcError,
    ControlPlaneUnavailableError,
)


class _DeniedActionObservationHarness:
    def __init__(self, exc: Exception) -> None:
        self._control_plane = SimpleNamespace(observe_denied_action=self._observe_denied_action)
        self._event_bus = SimpleNamespace(publish=self._publish)
        self._exc = exc
        self.events: list[object] = []

    async def _observe_denied_action(self, **_kwargs: object) -> list[object]:
        raise self._exc

    async def _publish(self, event: object) -> None:
        self.events.append(event)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "exc",
    (
        ControlPlaneUnavailableError(reason_code="control_plane.unavailable"),
        ControlPlaneRpcError(reason_code="rpc.invalid_params"),
    ),
)
async def test_h3_denied_action_observation_degrades_on_sidecar_failure(
    caplog: pytest.LogCaptureFixture,
    exc: Exception,
) -> None:
    harness = _DeniedActionObservationHarness(exc)
    action = build_action(
        tool_name="file.read",
        arguments={"path": "/tmp/secret.txt"},
        origin=Origin(
            session_id="sess-h3-observe",
            user_id="alice",
            workspace_id="ws-h3",
            actor="planner",
        ),
    )

    with caplog.at_level("WARNING"):
        await HandlerImplementation._observe_pep_reject_signal(
            harness,  # type: ignore[arg-type]
            sid=SessionId("sess-h3-observe"),
            tool_name=ToolName("file.read"),
            action=action,
            final_kind="reject",
            final_reason="pep_reject",
            pep_kind="reject",
            pep_reason="Missing capabilities: FILE_READ",
            pep_reason_code="pep:missing_capabilities",
            source="policy_loop",
        )

    assert harness.events == []
    assert "Denied-action observation unavailable" in caplog.text
