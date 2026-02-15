"""M2 reminder pump runtime wiring tests."""

from __future__ import annotations

import asyncio
from datetime import datetime
from types import SimpleNamespace
from typing import Any

import pytest

from shisad.channels.base import DeliveryTarget
from shisad.channels.delivery import DeliveryResult
from shisad.core.events import AnomalyReported, TaskTriggered
from shisad.core.types import Capability
from shisad.daemon.runner import _reminder_delivery_pump
from shisad.scheduler.schema import Schedule, TaskRunRequest


class _RecordingEventBus:
    def __init__(self) -> None:
        self.events: list[Any] = []

    async def publish(self, event: Any) -> None:
        self.events.append(event)


class _RecordingDelivery:
    def __init__(self, *, sent: bool = True) -> None:
        self.sent = sent
        self.calls: list[tuple[DeliveryTarget, str]] = []

    async def send(self, *, target: DeliveryTarget, message: str) -> DeliveryResult:
        self.calls.append((target, message))
        return DeliveryResult(
            attempted=True,
            sent=self.sent,
            reason="sent" if self.sent else "send_failed",
            target=target,
        )


class _SchedulerStub:
    def __init__(
        self,
        *,
        shutdown_event: asyncio.Event,
        run: TaskRunRequest,
        task: Any,
        can_execute: bool,
    ) -> None:
        self._shutdown_event = shutdown_event
        self._run = run
        self._task = task
        self._can_execute = can_execute
        self._trigger_calls = 0

    def trigger_due(self, *, now: datetime | None = None) -> list[TaskRunRequest]:
        _ = now
        self._trigger_calls += 1
        if self._trigger_calls == 1:
            self._shutdown_event.set()
            return [self._run]
        return []

    def get_task(self, task_id: str) -> Any:
        if task_id == self._task.id:
            return self._task
        return None

    def can_execute_with_capabilities(
        self,
        task_id: str,
        requested_capabilities: set[Capability],
        *,
        available_capabilities: set[Capability] | None = None,
    ) -> bool:
        _ = (task_id, requested_capabilities, available_capabilities)
        return self._can_execute


@pytest.mark.asyncio
async def test_reminder_delivery_pump_sends_due_task_with_message_send_capability() -> None:
    shutdown_event = asyncio.Event()
    schedule = Schedule(kind="interval", expression="1s")
    task = SimpleNamespace(
        id="task-1",
        schedule=schedule,
        capability_snapshot={Capability.MESSAGE_SEND},
        delivery_target={"channel": "discord", "recipient": "chan-1"},
        goal="Reminder: standup",
    )
    run = TaskRunRequest(
        task_id=task.id,
        trigger_payload="scheduled",
        payload_taint="trusted_scheduler",
        plan_commitment="hash",
    )
    event_bus = _RecordingEventBus()
    delivery = _RecordingDelivery(sent=True)
    services = SimpleNamespace(
        shutdown_event=shutdown_event,
        scheduler=_SchedulerStub(
            shutdown_event=shutdown_event,
            run=run,
            task=task,
            can_execute=True,
        ),
        event_bus=event_bus,
        delivery=delivery,
        policy_loader=SimpleNamespace(policy=SimpleNamespace(default_capabilities=[Capability.MESSAGE_SEND])),
    )

    await _reminder_delivery_pump(services=services)

    assert len(delivery.calls) == 1
    target, message = delivery.calls[0]
    assert target.channel == "discord"
    assert target.recipient == "chan-1"
    assert message == "Reminder: standup"
    assert any(isinstance(event, TaskTriggered) for event in event_bus.events)
    assert not any(isinstance(event, AnomalyReported) for event in event_bus.events)


@pytest.mark.asyncio
async def test_reminder_delivery_pump_emits_anomaly_when_capability_check_fails() -> None:
    shutdown_event = asyncio.Event()
    schedule = Schedule(kind="interval", expression="1s")
    task = SimpleNamespace(
        id="task-1",
        schedule=schedule,
        capability_snapshot={Capability.MESSAGE_SEND},
        delivery_target={"channel": "discord", "recipient": "chan-1"},
        goal="Reminder: standup",
    )
    run = TaskRunRequest(
        task_id=task.id,
        trigger_payload="scheduled",
        payload_taint="trusted_scheduler",
        plan_commitment="hash",
    )
    event_bus = _RecordingEventBus()
    delivery = _RecordingDelivery(sent=True)
    services = SimpleNamespace(
        shutdown_event=shutdown_event,
        scheduler=_SchedulerStub(
            shutdown_event=shutdown_event,
            run=run,
            task=task,
            can_execute=False,
        ),
        event_bus=event_bus,
        delivery=delivery,
        policy_loader=SimpleNamespace(policy=SimpleNamespace(default_capabilities=[Capability.MESSAGE_SEND])),
    )

    await _reminder_delivery_pump(services=services)

    assert delivery.calls == []
    assert any(isinstance(event, TaskTriggered) for event in event_bus.events)
    assert any(isinstance(event, AnomalyReported) for event in event_bus.events)
