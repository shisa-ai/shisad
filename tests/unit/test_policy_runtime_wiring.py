"""Policy-file settings reach their control-plane enforcement owners."""

from pathlib import Path

import pytest

from shisad.security.control_plane import sidecar
from shisad.security.control_plane.schema import Origin, build_action


@pytest.mark.parametrize("window, detected", [(1, False), (5, True)])
def test_sidecar_policy_controls_sequence_and_resource_settings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, window: int, detected: bool
) -> None:
    path = tmp_path / "policy.yaml"
    path.write_text(
        f"""version: '1'
control_plane:
  sequence:
    exfil_after_read_window_actions: {window}
    env_then_egress_window_actions: 7
    mass_enum_window_actions: 12
    rapid_fire_window_seconds: 4
  resource:
    enumeration_resource_threshold: 9
    enumeration_directory_threshold: 8
    enumeration_window_seconds: 30
""",
        encoding="utf-8",
    )
    monkeypatch.setattr(sidecar, "_build_sidecar_monitor_provider", lambda: None)
    engine = sidecar._build_control_plane_engine(data_dir=tmp_path / "data", policy_path=path)
    origin = Origin(session_id="policy-test", user_id="u", workspace_id="w", actor="planner")
    engine._history_store.append_action(
        build_action(tool_name="fs.read", arguments={"path": "notes.txt"}, origin=origin),
        decision_status="allow",
    )
    candidate = build_action(
        tool_name="http.request", arguments={"url": "https://example.com/"}, origin=origin
    )
    findings = engine._sequence_analyzer.analyze(
        history=engine._history_store, candidate_action=candidate
    )
    assert any(item.pattern_name == "exfil_after_read" for item in findings) is detected
    patterns = {pattern.name: pattern for pattern in engine._sequence_analyzer._patterns}
    assert patterns["env_then_egress"].window_actions == 7
    assert patterns["mass_enum"].window_actions == 12
    assert patterns["rapid_fire"].window_seconds == 4
    assert engine._resource_monitor._enum_resource_threshold == 9
    assert engine._resource_monitor._enum_directory_threshold == 8
    assert engine._resource_monitor._enum_window_seconds == 30
