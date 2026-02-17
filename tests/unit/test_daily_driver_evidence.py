"""Unit checks for daily-driver evidence harness helpers."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


def _load_daily_driver_module():
    script_path = (
        Path(__file__).resolve().parents[2] / "scripts" / "daily_driver_evidence.py"
    )
    spec = importlib.util.spec_from_file_location("daily_driver_evidence", script_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_daily_driver_parser_defaults_are_fail_safe() -> None:
    daily_driver_evidence = _load_daily_driver_module()
    parser = daily_driver_evidence._build_parser()
    args = parser.parse_args([])

    assert args.allow_live_channels is False
    assert args.reminder_channel == "noop"


def test_daily_driver_task_trigger_detection_matches_task_id() -> None:
    daily_driver_evidence = _load_daily_driver_module()
    events = {
        "total": 3,
        "events": [
            {"data": {"task_id": "task-old"}},
            {"data": {"task_id": "task-other"}},
        ],
    }
    assert daily_driver_evidence._task_triggered_for_task(events, "task-current") is False
    assert daily_driver_evidence._task_triggered_for_task(events, "task-old") is True
