"""M4 cron parser edge corpus coverage."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from shisad.core.types import Capability, UserId
from shisad.scheduler.manager import SchedulerManager
from shisad.scheduler.schema import Schedule


def _create_cron_task(scheduler: SchedulerManager, expression: str) -> str:
    task = scheduler.create_task(
        name="cron-task",
        goal="cron parser validation",
        schedule=Schedule(kind="cron", expression=expression),
        capability_snapshot={Capability.MESSAGE_SEND},
        policy_snapshot_ref="m4-cron",
        created_by=UserId("alice"),
    )
    return task.id


def test_m4_cron_matches_feb_29_only_in_leap_years() -> None:
    scheduler = SchedulerManager()
    task_id = _create_cron_task(scheduler, "0 0 29 2 *")
    task = scheduler.get_task(task_id)
    assert task is not None
    task.created_at = datetime(2024, 2, 28, 0, 0, 0, tzinfo=UTC)

    assert scheduler.trigger_due(now=datetime(2024, 2, 28, 0, 0, 0, tzinfo=UTC)) == []
    leap_runs = scheduler.trigger_due(now=datetime(2024, 2, 29, 0, 0, 0, tzinfo=UTC))
    assert len(leap_runs) == 1
    assert leap_runs[0].task_id == task_id
    assert scheduler.trigger_due(now=datetime(2025, 2, 28, 0, 0, 0, tzinfo=UTC)) == []


def test_m4_cron_month_end_invalid_date_never_triggers() -> None:
    scheduler = SchedulerManager()
    task_id = _create_cron_task(scheduler, "0 0 31 4 *")
    task = scheduler.get_task(task_id)
    assert task is not None
    task.created_at = datetime(2026, 4, 1, 0, 0, 0, tzinfo=UTC)

    assert scheduler.trigger_due(now=datetime(2026, 4, 1, 0, 0, 0, tzinfo=UTC)) == []
    assert scheduler.trigger_due(now=datetime(2026, 4, 15, 0, 0, 0, tzinfo=UTC)) == []
    assert scheduler.trigger_due(now=datetime(2026, 4, 30, 0, 0, 0, tzinfo=UTC)) == []


def test_m4_cron_day_of_week_wraparound_treats_7_as_sunday() -> None:
    scheduler = SchedulerManager()
    sunday_as_zero = _create_cron_task(scheduler, "0 9 * * 0")
    sunday_as_seven = _create_cron_task(scheduler, "0 9 * * 7")
    for task_id in (sunday_as_zero, sunday_as_seven):
        task = scheduler.get_task(task_id)
        assert task is not None
        task.created_at = datetime(2026, 2, 14, 9, 0, 0, tzinfo=UTC)

    sunday = datetime(2026, 2, 15, 9, 0, 0, tzinfo=UTC)
    assert sunday.weekday() == 6

    runs = scheduler.trigger_due(now=sunday)
    run_ids = {run.task_id for run in runs}
    assert run_ids == {sunday_as_zero, sunday_as_seven}


def test_m4_cron_supports_step_ranges() -> None:
    scheduler = SchedulerManager()
    task_id = _create_cron_task(scheduler, "0 0 1-10/2 * *")
    task = scheduler.get_task(task_id)
    assert task is not None
    task.created_at = datetime(2026, 3, 1, 0, 0, 0, tzinfo=UTC)

    assert len(scheduler.trigger_due(now=datetime(2026, 3, 1, 0, 0, 0, tzinfo=UTC))) == 1
    assert scheduler.trigger_due(now=datetime(2026, 3, 2, 0, 0, 0, tzinfo=UTC)) == []
    assert len(scheduler.trigger_due(now=datetime(2026, 3, 3, 0, 0, 0, tzinfo=UTC))) == 1
    assert scheduler.trigger_due(now=datetime(2026, 3, 10, 0, 0, 0, tzinfo=UTC)) == []


def test_m4_cron_rejects_invalid_ranges_and_steps() -> None:
    scheduler = SchedulerManager()
    with pytest.raises(ValueError, match="cron range start must be <= end"):
        _create_cron_task(scheduler, "0 0 10-5 * *")
    with pytest.raises(ValueError, match="cron range out of bounds"):
        _create_cron_task(scheduler, "0 0 1-40 * *")
    with pytest.raises(ValueError, match="cron step must be positive integer"):
        _create_cron_task(scheduler, "0 0 */0 * *")
