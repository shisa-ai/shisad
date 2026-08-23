"""F7B crash/restart coverage for durable outbound delivery."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import sqlite3
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from shisad.channels.base import (
    DeliveryReconciliation,
    DeliveryReconciliationStatus,
    DeliveryRecoveryCapability,
    DeliveryRecoveryKind,
    DeliveryTarget,
    InMemoryChannel,
    ProviderDeliveryReceipt,
)
from shisad.channels.delivery import (
    CapabilityDeliveryIntent,
    CapabilityPayload,
    ChannelDeliveryService,
    DeliveryIntent,
    DeliveryStateError,
)
from shisad.core.transcript import TranscriptStore
from shisad.core.types import SessionId


class _RecoveryChannel(InMemoryChannel):
    def __init__(self, *, recovery_kind: DeliveryRecoveryKind) -> None:
        super().__init__(name="matrix")
        self.recovery_kind = recovery_kind
        self.reconcile_override: DeliveryReconciliation | BaseException | None = None
        self.send_calls: list[dict[str, Any]] = []
        self.reconcile_calls: list[str] = []
        self.effects: dict[str, str] = {}

    def delivery_recovery_capability(self) -> DeliveryRecoveryCapability:
        return DeliveryRecoveryCapability(
            kind=self.recovery_kind,
            guarantee_id=f"test.{self.recovery_kind.value}.v1",
        )

    async def send(
        self,
        message: str,
        *,
        target: DeliveryTarget | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> ProviderDeliveryReceipt:
        call_metadata = dict(metadata or {})
        self.send_calls.append({"message": message, "target": target, "metadata": call_metadata})
        delivery_id = str(call_metadata.get("shisad_delivery_id", ""))
        idempotency_key = str(call_metadata.get("shisad_idempotency_key", ""))
        effect_key = idempotency_key or f"call:{len(self.send_calls)}"
        receipt = self.effects.get(effect_key)
        if receipt is None:
            receipt = f"event-{len(self.effects) + 1}"
            self.effects[effect_key] = receipt
        return ProviderDeliveryReceipt(
            provider="matrix",
            receipt_id=receipt,
            delivery_id=delivery_id,
        )

    async def reconcile_delivery(
        self,
        *,
        delivery_id: str,
        target: DeliveryTarget,
    ) -> DeliveryReconciliation:
        _ = target
        self.reconcile_calls.append(delivery_id)
        if isinstance(self.reconcile_override, BaseException):
            raise self.reconcile_override
        if self.reconcile_override is not None:
            return self.reconcile_override
        for receipt in self.effects.values():
            return DeliveryReconciliation(
                status=DeliveryReconciliationStatus.DELIVERED,
                receipt=ProviderDeliveryReceipt(
                    provider="matrix",
                    receipt_id=receipt,
                    delivery_id=delivery_id,
                ),
            )
        return DeliveryReconciliation(status=DeliveryReconciliationStatus.ABSENT)


def _intent(*, source_id: str = "source-1", channel: str = "matrix") -> DeliveryIntent:
    return DeliveryIntent(
        source_id=source_id,
        kind="channel_result",
        target=DeliveryTarget(
            channel=channel,
            recipient="!room:example.org",
            workspace_hint="workspace-1",
        ),
    )


def _seed_outcome_unknown(
    delivery: ChannelDeliveryService,
    *,
    source_id: str = "unknown-source",
    channel: str = "matrix",
    message: str = "sensitive delivery body",
    metadata: dict[str, Any] | None = None,
) -> str:
    reserved = delivery.reserve(_intent(source_id=source_id, channel=channel))
    prepared = delivery.prepare(
        reserved.reservation_id,
        message=message,
        metadata=metadata,
    )
    assert delivery._store is not None
    claimed = delivery._store.claim_attempt(prepared.reservation_id)
    assert claimed is not None
    delivery._store.mark_outcome_unknown(prepared.reservation_id, "provider_attempt_failed")
    return prepared.delivery_id


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("recovery_kind", "expected_state", "expected_send_calls", "expected_reconcile_calls"),
    [
        (DeliveryRecoveryKind.NEITHER, "outcome_unknown", 1, 0),
        (DeliveryRecoveryKind.EXACT_IDEMPOTENCY_KEY, "delivered", 2, 0),
        (DeliveryRecoveryKind.AUTHORITATIVE_RECONCILIATION, "delivered", 1, 1),
    ],
)
async def test_outbound_delivery_crash_never_loses_or_auto_duplicates_result(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    recovery_kind: DeliveryRecoveryKind,
    expected_state: str,
    expected_send_calls: int,
    expected_reconcile_calls: int,
) -> None:
    """Post-provider receipt loss recovers only under exact structural proof."""

    root = tmp_path / "channels" / "delivery"
    channel = _RecoveryChannel(recovery_kind=recovery_kind)
    await channel.connect()
    first = ChannelDeliveryService({"matrix": channel}, state_root=root)

    def lose_receipt(*_args: object, **_kwargs: object) -> None:
        raise OSError("crash before durable receipt")

    monkeypatch.setattr(first._store, "mark_delivered", lose_receipt)
    initial = await first.send(intent=_intent(), message="durable result")

    assert initial.sent is False
    assert initial.outcome_unknown is True
    assert len(channel.effects) == 1
    assert first.record(initial.reservation_id).state == "attempt_started"

    restarted = ChannelDeliveryService({"matrix": channel}, state_root=root)
    recovered = await restarted.recover()

    final = restarted.record(initial.reservation_id)
    assert final is not None
    assert final.state == expected_state
    assert len(channel.effects) == 1
    assert len(channel.send_calls) == expected_send_calls
    assert len(channel.reconcile_calls) == expected_reconcile_calls
    if recovery_kind is DeliveryRecoveryKind.NEITHER:
        assert recovered[0].outcome_unknown is True
    else:
        assert recovered[0].sent is True


@pytest.mark.asyncio
async def test_authoritative_absence_after_restart_terminalizes_without_replay(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "channels" / "delivery"
    channel = _RecoveryChannel(recovery_kind=DeliveryRecoveryKind.AUTHORITATIVE_RECONCILIATION)
    channel.reconcile_override = DeliveryReconciliation(status=DeliveryReconciliationStatus.ABSENT)
    await channel.connect()
    first = ChannelDeliveryService({"matrix": channel}, state_root=root)

    def lose_receipt(*_args: object, **_kwargs: object) -> None:
        raise OSError("crash before durable receipt")

    assert first._store is not None
    monkeypatch.setattr(first._store, "mark_delivered", lose_receipt)
    initial = await first.send(intent=_intent(), message="one external effect")
    assert initial.outcome_unknown is True
    assert len(channel.send_calls) == 1

    restarted = ChannelDeliveryService({"matrix": channel}, state_root=root)
    recovered = await restarted.recover()

    assert recovered[0].state == "reconciled_absent"
    assert restarted.record(initial.reservation_id).state == "reconciled_absent"
    assert len(channel.send_calls) == 1
    assert channel.reconcile_calls == [initial.delivery_id]


def test_delivery_inspection_is_exact_bounded_and_payload_safe(tmp_path: Path) -> None:
    channel = _RecoveryChannel(recovery_kind=DeliveryRecoveryKind.NEITHER)
    delivery = ChannelDeliveryService(
        {"matrix": channel}, state_root=tmp_path / "channels" / "delivery"
    )
    delivery_id = _seed_outcome_unknown(
        delivery,
        message="secret message must not project",
        metadata={"secret": "metadata-secret-must-not-project"},
    )
    record = delivery._store.records()[0]  # type: ignore[union-attr]

    rows = delivery.list_deliveries(state="outcome_unknown", limit=1)
    by_delivery = delivery.inspect_delivery(delivery_id)
    by_reservation = delivery.inspect_delivery(record.reservation_id)

    assert len(rows) == 1
    assert rows[0] == by_delivery == by_reservation
    assert rows[0]["state"] == "outcome_unknown"
    assert rows[0]["target"]["channel"] == "matrix"
    assert rows[0]["recovery"] == {
        "kind": "neither",
        "guarantee_id": "test.neither.v1",
        "reconciliation_available": False,
    }
    serialized = json.dumps(rows)
    assert "secret message must not project" not in serialized
    assert "metadata-secret-must-not-project" not in serialized
    assert "payload" not in rows[0]
    assert "metadata" not in rows[0]
    assert delivery.inspect_delivery(delivery_id[:-1]) is None
    with pytest.raises(DeliveryStateError, match="limit"):
        delivery.list_deliveries(limit=0)
    with pytest.raises(DeliveryStateError, match="state"):
        delivery.list_deliveries(state="unknown-state")


@pytest.mark.asyncio
async def test_operator_resolution_records_authoritative_delivery_once(tmp_path: Path) -> None:
    channel = _RecoveryChannel(recovery_kind=DeliveryRecoveryKind.AUTHORITATIVE_RECONCILIATION)
    delivery = ChannelDeliveryService(
        {"matrix": channel}, state_root=tmp_path / "channels" / "delivery"
    )
    delivery_id = _seed_outcome_unknown(delivery)
    channel.reconcile_override = DeliveryReconciliation(
        status=DeliveryReconciliationStatus.DELIVERED,
        receipt=ProviderDeliveryReceipt("matrix", "event-authoritative", delivery_id),
    )

    resolved = await delivery.resolve_delivery(delivery_id)
    repeated = await delivery.resolve_delivery(delivery_id)

    assert resolved["lookup_attempted"] is True
    assert resolved["reconciliation_status"] == "delivered"
    assert resolved["delivery"]["state"] == "delivered"
    assert repeated["lookup_attempted"] is False
    assert repeated["reconciliation_status"] == "delivered"
    assert channel.reconcile_calls == [delivery_id]
    assert channel.send_calls == []


@pytest.mark.asyncio
async def test_operator_resolution_records_authoritative_absence_without_send(
    tmp_path: Path,
) -> None:
    channel = _RecoveryChannel(recovery_kind=DeliveryRecoveryKind.AUTHORITATIVE_RECONCILIATION)
    delivery = ChannelDeliveryService(
        {"matrix": channel}, state_root=tmp_path / "channels" / "delivery"
    )
    delivery_id = _seed_outcome_unknown(delivery)
    channel.reconcile_override = DeliveryReconciliation(status=DeliveryReconciliationStatus.ABSENT)

    resolved = await delivery.resolve_delivery(delivery_id)
    repeated = await delivery.resolve_delivery(delivery_id)

    assert resolved["lookup_attempted"] is True
    assert resolved["reconciliation_status"] == "absent"
    assert resolved["delivery"]["state"] == "reconciled_absent"
    assert "fresh request" in resolved["instruction"]
    assert repeated["lookup_attempted"] is False
    assert repeated["reconciliation_status"] == "absent"
    assert channel.reconcile_calls == [delivery_id]
    assert channel.send_calls == []


@pytest.mark.asyncio
@pytest.mark.parametrize("provider", ["matrix", "discord", "telegram", "slack"])
async def test_current_provider_without_guarantee_stays_unknown(
    tmp_path: Path,
    provider: str,
) -> None:
    channel = _RecoveryChannel(recovery_kind=DeliveryRecoveryKind.NEITHER)
    delivery = ChannelDeliveryService(
        {provider: channel}, state_root=tmp_path / provider / "delivery"
    )
    delivery_id = _seed_outcome_unknown(delivery, channel=provider)

    resolved = await delivery.resolve_delivery(delivery_id)

    assert resolved["lookup_attempted"] is False
    assert resolved["reconciliation_status"] == "unsupported"
    assert resolved["delivery"]["state"] == "outcome_unknown"
    assert channel.reconcile_calls == []
    assert channel.send_calls == []


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["unknown", "mismatch", "exception"])
async def test_untrusted_provider_resolution_never_upgrades_uncertainty(
    tmp_path: Path,
    failure: str,
) -> None:
    channel = _RecoveryChannel(recovery_kind=DeliveryRecoveryKind.AUTHORITATIVE_RECONCILIATION)
    delivery = ChannelDeliveryService(
        {"matrix": channel}, state_root=tmp_path / failure / "delivery"
    )
    delivery_id = _seed_outcome_unknown(delivery)
    if failure == "unknown":
        channel.reconcile_override = DeliveryReconciliation(
            status=DeliveryReconciliationStatus.UNKNOWN
        )
    elif failure == "mismatch":
        channel.reconcile_override = DeliveryReconciliation(
            status=DeliveryReconciliationStatus.DELIVERED,
            receipt=ProviderDeliveryReceipt("discord", "wrong", delivery_id),
        )
    else:
        channel.reconcile_override = TimeoutError("provider secret must not escape")

    resolved = await delivery.resolve_delivery(delivery_id)

    assert resolved["lookup_attempted"] is True
    assert resolved["reconciliation_status"] == "unknown"
    assert resolved["delivery"]["state"] == "outcome_unknown"
    assert "provider secret must not escape" not in json.dumps(resolved)
    assert channel.send_calls == []


@pytest.mark.asyncio
async def test_prepared_delivery_restarts_once_before_any_provider_attempt(tmp_path: Path) -> None:
    root = tmp_path / "channels" / "delivery"
    channel = _RecoveryChannel(recovery_kind=DeliveryRecoveryKind.NEITHER)
    await channel.connect()
    first = ChannelDeliveryService({"matrix": channel}, state_root=root)
    reservation = first.reserve(_intent())
    prepared = first.prepare(reservation.reservation_id, message="prepared result")

    assert prepared.state == "prepared"
    assert channel.send_calls == []

    restarted = ChannelDeliveryService({"matrix": channel}, state_root=root)
    recovered = await restarted.recover()

    assert len(recovered) == 1
    assert recovered[0].sent is True
    assert len(channel.effects) == 1
    assert restarted.record(reservation.reservation_id).state == "delivered"


@pytest.mark.asyncio
async def test_duplicate_delivery_identity_claims_at_most_one_provider_effect(
    tmp_path: Path,
) -> None:
    channel = _RecoveryChannel(recovery_kind=DeliveryRecoveryKind.NEITHER)
    await channel.connect()
    delivery = ChannelDeliveryService(
        {"matrix": channel}, state_root=tmp_path / "channels" / "delivery"
    )
    intent = _intent(source_id="one-trusted-source")

    await asyncio.gather(
        delivery.send(intent=intent, message="one result"),
        delivery.send(intent=intent, message="one result"),
    )

    assert len(channel.effects) == 1
    records = delivery._store.records()
    assert len(records) == 1
    assert records[0].state == "delivered"


@pytest.mark.asyncio
async def test_duplicate_inflight_delivery_projects_uncertainty(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    channel = _RecoveryChannel(recovery_kind=DeliveryRecoveryKind.NEITHER)
    await channel.connect()
    provider_started = asyncio.Event()
    provider_release = asyncio.Event()
    original_send = channel.send

    async def blocked_send(*args: object, **kwargs: object) -> ProviderDeliveryReceipt:
        provider_started.set()
        await provider_release.wait()
        return await original_send(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(channel, "send", blocked_send)
    delivery = ChannelDeliveryService(
        {"matrix": channel}, state_root=tmp_path / "channels" / "delivery"
    )
    intent = _intent(source_id="one-inflight-source")
    first_task = asyncio.create_task(delivery.send(intent=intent, message="one result"))
    await provider_started.wait()

    duplicate = await delivery.send(intent=intent, message="one result")
    provider_release.set()
    first = await first_task

    assert duplicate.attempted is True
    assert duplicate.sent is False
    assert duplicate.outcome_unknown is True
    assert duplicate.state == "attempt_started"
    assert first.sent is True
    assert len(channel.effects) == 1


@pytest.mark.asyncio
async def test_distinct_ordinary_reservations_coexist_in_one_outbox(tmp_path: Path) -> None:
    channel = _RecoveryChannel(recovery_kind=DeliveryRecoveryKind.NEITHER)
    await channel.connect()
    delivery = ChannelDeliveryService(
        {"matrix": channel}, state_root=tmp_path / "channels" / "delivery"
    )

    first = delivery.reserve(_intent(source_id="trusted-source-1"))
    second = delivery.reserve(_intent(source_id="trusted-source-2"))

    assert first.reservation_id != second.reservation_id
    assert len(delivery._store.records()) == 2
    assert channel.effects == {}


def test_presentation_prefix_cannot_split_one_trusted_reservation(tmp_path: Path) -> None:
    delivery = ChannelDeliveryService({}, state_root=tmp_path / "channels" / "delivery")
    intent = _intent(source_id="one-prefixed-source")
    reserved = delivery.reserve(intent)

    with pytest.raises(DeliveryStateError):
        delivery.reserve(replace(intent, message_prefix="[proactive] "))

    assert delivery._store is not None
    assert [record.reservation_id for record in delivery._store.records()] == [
        reserved.reservation_id
    ]


@pytest.mark.asyncio
async def test_conflicting_payload_for_reserved_identity_blocks_before_effect(
    tmp_path: Path,
) -> None:
    channel = _RecoveryChannel(recovery_kind=DeliveryRecoveryKind.NEITHER)
    await channel.connect()
    delivery = ChannelDeliveryService(
        {"matrix": channel}, state_root=tmp_path / "channels" / "delivery"
    )
    intent = _intent(source_id="one-trusted-source")

    first = await delivery.send(intent=intent, message="first result")
    conflict = await delivery.send(intent=intent, message="different result")

    assert first.sent is True
    assert conflict.sent is False
    assert conflict.attempted is False
    assert len(channel.effects) == 1


@pytest.mark.asyncio
async def test_provider_exception_after_attempt_is_uncertain_and_not_replayed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "channels" / "delivery"
    channel = _RecoveryChannel(recovery_kind=DeliveryRecoveryKind.NEITHER)
    await channel.connect()

    async def fail_after_attempt(*_args: object, **_kwargs: object) -> None:
        raise TimeoutError("provider outcome unavailable")

    monkeypatch.setattr(channel, "send", fail_after_attempt)
    delivery = ChannelDeliveryService({"matrix": channel}, state_root=root)
    result = await delivery.send(intent=_intent(), message="one result")

    assert result.outcome_unknown is True
    restarted = ChannelDeliveryService({"matrix": channel}, state_root=root)
    recovered = await restarted.recover()
    assert recovered == []
    assert restarted.record(result.reservation_id).state == "outcome_unknown"
    assert len(channel.send_calls) == 0


@pytest.mark.asyncio
async def test_mismatched_provider_receipt_never_commits_delivery(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    channel = _RecoveryChannel(recovery_kind=DeliveryRecoveryKind.NEITHER)
    await channel.connect()

    async def mismatched_receipt(*_args: object, **_kwargs: object) -> ProviderDeliveryReceipt:
        return ProviderDeliveryReceipt("matrix", "event-wrong", "dly-wrong")

    monkeypatch.setattr(channel, "send", mismatched_receipt)
    delivery = ChannelDeliveryService(
        {"matrix": channel}, state_root=tmp_path / "channels" / "delivery"
    )

    result = await delivery.send(intent=_intent(), message="one result")

    assert result.sent is False
    assert result.outcome_unknown is True
    assert delivery.record(result.reservation_id).state == "attempt_started"


@pytest.mark.asyncio
async def test_mismatched_provider_name_never_commits_delivery(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    channel = _RecoveryChannel(recovery_kind=DeliveryRecoveryKind.NEITHER)
    await channel.connect()

    async def mismatched_provider(
        *_args: object,
        **kwargs: object,
    ) -> ProviderDeliveryReceipt:
        metadata = kwargs.get("metadata")
        assert isinstance(metadata, dict)
        return ProviderDeliveryReceipt(
            "discord",
            "event-wrong-provider",
            str(metadata["shisad_delivery_id"]),
        )

    monkeypatch.setattr(channel, "send", mismatched_provider)
    delivery = ChannelDeliveryService(
        {"matrix": channel}, state_root=tmp_path / "channels" / "delivery"
    )

    result = await delivery.send(intent=_intent(), message="one result")

    assert result.sent is False
    assert result.outcome_unknown is True
    assert delivery.record(result.reservation_id).state == "attempt_started"


@pytest.mark.asyncio
async def test_authoritative_reconciliation_rejects_mismatched_receipt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "channels" / "delivery"
    channel = _RecoveryChannel(recovery_kind=DeliveryRecoveryKind.AUTHORITATIVE_RECONCILIATION)
    await channel.connect()
    first = ChannelDeliveryService({"matrix": channel}, state_root=root)

    def lose_receipt(*_args: object, **_kwargs: object) -> None:
        raise OSError("receipt lost")

    async def mismatched_reconciliation(
        *, delivery_id: str, target: DeliveryTarget
    ) -> DeliveryReconciliation:
        _ = (delivery_id, target)
        return DeliveryReconciliation(
            DeliveryReconciliationStatus.DELIVERED,
            ProviderDeliveryReceipt("matrix", "event-wrong", "dly-wrong"),
        )

    monkeypatch.setattr(first._store, "mark_delivered", lose_receipt)
    initial = await first.send(intent=_intent(), message="one result")
    monkeypatch.setattr(channel, "reconcile_delivery", mismatched_reconciliation)

    restarted = ChannelDeliveryService({"matrix": channel}, state_root=root)
    recovered = await restarted.recover()

    assert recovered[0].outcome_unknown is True
    assert restarted.record(initial.reservation_id).state == "attempt_started"
    assert len(channel.send_calls) == 1


@pytest.mark.asyncio
async def test_unversioned_recovery_claim_cannot_authorize_replay(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "channels" / "delivery"
    channel = _RecoveryChannel(recovery_kind=DeliveryRecoveryKind.EXACT_IDEMPOTENCY_KEY)
    await channel.connect()
    first = ChannelDeliveryService({"matrix": channel}, state_root=root)

    def lose_receipt(*_args: object, **_kwargs: object) -> None:
        raise OSError("receipt lost")

    monkeypatch.setattr(first._store, "mark_delivered", lose_receipt)
    initial = await first.send(intent=_intent(), message="one result")
    monkeypatch.setattr(
        channel,
        "delivery_recovery_capability",
        lambda: DeliveryRecoveryCapability(
            DeliveryRecoveryKind.EXACT_IDEMPOTENCY_KEY, "unversioned"
        ),
    )

    restarted = ChannelDeliveryService({"matrix": channel}, state_root=root)
    recovered = await restarted.recover()

    assert recovered[0].outcome_unknown is True
    assert restarted.record(initial.reservation_id).state == "outcome_unknown"
    assert len(channel.send_calls) == 1


@pytest.mark.asyncio
async def test_cancellation_after_attempt_records_uncertainty_before_propagating(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    channel = _RecoveryChannel(recovery_kind=DeliveryRecoveryKind.NEITHER)
    await channel.connect()
    started = asyncio.Event()

    async def wait_forever(*_args: object, **_kwargs: object) -> None:
        started.set()
        await asyncio.Event().wait()

    monkeypatch.setattr(channel, "send", wait_forever)
    delivery = ChannelDeliveryService(
        {"matrix": channel}, state_root=tmp_path / "channels" / "delivery"
    )
    reservation = delivery.reserve(_intent())
    delivery.prepare(reservation.reservation_id, message="one result")
    task = asyncio.create_task(delivery.send_prepared(reservation.reservation_id))
    await started.wait()

    with pytest.raises(DeliveryStateError):
        delivery.reset()

    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    assert delivery.record(reservation.reservation_id).state == "outcome_unknown"


@pytest.mark.asyncio
async def test_reset_is_blocked_until_provider_receipt_is_durable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    channel = _RecoveryChannel(recovery_kind=DeliveryRecoveryKind.NEITHER)
    await channel.connect()
    delivery = ChannelDeliveryService(
        {"matrix": channel}, state_root=tmp_path / "channels" / "delivery"
    )
    store = delivery._store
    assert store is not None
    original_mark_delivered = store.mark_delivered
    reset_observations: list[str] = []

    def reset_at_receipt_boundary(
        reservation_id: str,
        receipt: ProviderDeliveryReceipt,
    ) -> object:
        try:
            delivery.reset()
        except DeliveryStateError:
            reset_observations.append("blocked")
        else:
            reset_observations.append("cleared")
        return original_mark_delivered(reservation_id, receipt)

    monkeypatch.setattr(store, "mark_delivered", reset_at_receipt_boundary)

    result = await delivery.send(intent=_intent(), message="one result")

    assert reset_observations == ["blocked"]
    assert result.sent is True
    assert delivery.record(result.reservation_id).state == "delivered"


@pytest.mark.asyncio
async def test_preparing_result_reconciles_durable_transcript_after_restart(
    tmp_path: Path,
) -> None:
    root = tmp_path / "channels" / "delivery"
    transcripts = TranscriptStore(tmp_path / "sessions")
    channel = _RecoveryChannel(recovery_kind=DeliveryRecoveryKind.NEITHER)
    await channel.connect()
    first = ChannelDeliveryService(
        {"matrix": channel},
        state_root=root,
        transcript_store=transcripts,
    )
    reservation = first.reserve(_intent(source_id="trusted-replay-key"))
    transcripts.append(
        SessionId("session-1"),
        role="assistant",
        content="committed but not yet prepared",
        metadata={
            "delivery_target": _intent().target.model_dump(mode="json"),
            "outbound_delivery_reservation_id": reservation.reservation_id,
        },
        durable=True,
    )

    restarted = ChannelDeliveryService(
        {"matrix": channel},
        state_root=root,
        transcript_store=TranscriptStore(tmp_path / "sessions"),
    )
    recovered = await restarted.recover()

    assert len(recovered) == 1
    assert recovered[0].sent is True
    assert channel.send_calls[0]["message"] == "committed but not yet prepared"
    assert restarted.record(reservation.reservation_id).state == "delivered"


@pytest.mark.asyncio
async def test_preparing_without_committed_transcript_fails_before_effect(
    tmp_path: Path,
) -> None:
    root = tmp_path / "channels" / "delivery"
    channel = _RecoveryChannel(recovery_kind=DeliveryRecoveryKind.NEITHER)
    await channel.connect()
    first = ChannelDeliveryService(
        {"matrix": channel},
        state_root=root,
        transcript_store=TranscriptStore(tmp_path / "sessions"),
    )
    reservation = first.reserve(_intent(source_id="missing-result"))

    restarted = ChannelDeliveryService(
        {"matrix": channel},
        state_root=root,
        transcript_store=TranscriptStore(tmp_path / "sessions"),
    )
    recovered = await restarted.recover()

    assert recovered == []
    assert restarted.record(reservation.reservation_id).state == "failed_pre_effect"
    assert channel.send_calls == []


@pytest.mark.asyncio
async def test_imported_transcript_cannot_supply_channel_recovery_result(
    tmp_path: Path,
) -> None:
    root = tmp_path / "channels" / "delivery"
    transcripts = TranscriptStore(tmp_path / "sessions")
    channel = _RecoveryChannel(recovery_kind=DeliveryRecoveryKind.NEITHER)
    await channel.connect()
    first = ChannelDeliveryService(
        {"matrix": channel}, state_root=root, transcript_store=transcripts
    )
    reservation = first.reserve(_intent(source_id="imported-channel-result"))
    transcripts.append(
        SessionId("session-1"),
        role="assistant",
        content="imported spoof",
        metadata={
            "_archive_imported": True,
            "outbound_delivery_reservation_id": reservation.reservation_id,
            "delivery_target": _intent().target.model_dump(mode="json"),
        },
        durable=True,
    )

    restarted = ChannelDeliveryService(
        {"matrix": channel}, state_root=root, transcript_store=transcripts
    )
    recovered = await restarted.recover()

    assert recovered == []
    assert restarted.record(reservation.reservation_id).state == "failed_pre_effect"
    assert channel.send_calls == []


@pytest.mark.asyncio
async def test_oversized_committed_transcript_fails_before_recovery_effect(
    tmp_path: Path,
) -> None:
    root = tmp_path / "channels" / "delivery"
    transcripts = TranscriptStore(tmp_path / "sessions")
    channel = _RecoveryChannel(recovery_kind=DeliveryRecoveryKind.NEITHER)
    await channel.connect()
    first = ChannelDeliveryService(
        {"matrix": channel}, state_root=root, transcript_store=transcripts
    )
    reservation = first.reserve(_intent(source_id="oversized-result"))
    transcripts.append(
        SessionId("session-1"),
        role="assistant",
        content="x" * (64 * 1024 + 1),
        metadata={
            "outbound_delivery_reservation_id": reservation.reservation_id,
            "delivery_target": _intent().target.model_dump(mode="json"),
        },
        durable=True,
    )

    restarted = ChannelDeliveryService(
        {"matrix": channel}, state_root=root, transcript_store=transcripts
    )
    recovered = await restarted.recover()

    assert recovered == []
    assert restarted.record(reservation.reservation_id).state == "failed_pre_effect"
    assert channel.send_calls == []


@pytest.mark.asyncio
async def test_proactive_transcript_recovery_does_not_duplicate_marker(
    tmp_path: Path,
) -> None:
    root = tmp_path / "channels" / "delivery"
    transcripts = TranscriptStore(tmp_path / "sessions")
    channel = _RecoveryChannel(recovery_kind=DeliveryRecoveryKind.NEITHER)
    await channel.connect()
    first = ChannelDeliveryService(
        {"matrix": channel}, state_root=root, transcript_store=transcripts
    )
    reservation = first.reserve(
        DeliveryIntent(
            source_id="proactive-source",
            kind="channel_result",
            target=_intent().target,
            message_prefix="[proactive] ",
        )
    )
    transcripts.append(
        SessionId("session-1"),
        role="assistant",
        content="one result",
        metadata={
            "outbound_delivery_reservation_id": reservation.reservation_id,
            "delivery_target": _intent().target.model_dump(mode="json"),
        },
        durable=True,
    )

    restarted = ChannelDeliveryService(
        {"matrix": channel}, state_root=root, transcript_store=transcripts
    )
    await restarted.recover()

    assert channel.send_calls[0]["message"] == "[proactive] one result"


@pytest.mark.asyncio
@pytest.mark.parametrize("corruption", ["invalid_json", "preview_hash", "blob_ref"])
async def test_corrupt_committed_transcript_never_becomes_recovered_content(
    tmp_path: Path,
    corruption: str,
) -> None:
    root = tmp_path / "channels" / "delivery"
    session_root = tmp_path / "sessions"
    transcripts = TranscriptStore(session_root)
    channel = _RecoveryChannel(recovery_kind=DeliveryRecoveryKind.NEITHER)
    await channel.connect()
    first = ChannelDeliveryService(
        {"matrix": channel}, state_root=root, transcript_store=transcripts
    )
    reservation = first.reserve(_intent(source_id=f"corrupt-transcript-{corruption}"))
    content = "committed result" if corruption != "blob_ref" else "x" * 5000
    transcripts.append(
        SessionId("session-1"),
        role="assistant",
        content=content,
        metadata={
            "outbound_delivery_reservation_id": reservation.reservation_id,
            "delivery_target": _intent().target.model_dump(mode="json"),
        },
        durable=True,
    )
    transcript_path = session_root / "transcripts" / "session-1.jsonl"
    if corruption == "invalid_json":
        transcript_path.write_text("{not-json}\n", encoding="utf-8")
    else:
        payload = json.loads(transcript_path.read_text(encoding="utf-8"))
        if corruption == "preview_hash":
            payload["content_preview"] = "tampered result"
        else:
            alternate = "tampered blob"
            alternate_hash = hashlib.sha256(alternate.encode()).hexdigest()
            (session_root / "blobs" / f"{alternate_hash}.txt").write_text(
                alternate, encoding="utf-8"
            )
            payload["blob_ref"] = alternate_hash
        transcript_path.write_text(json.dumps(payload) + "\n", encoding="utf-8")

    restarted = ChannelDeliveryService(
        {"matrix": channel},
        state_root=root,
        transcript_store=TranscriptStore(session_root),
    )
    recovered = await restarted.recover()

    assert recovered == []
    assert restarted.record(reservation.reservation_id).state == "failed_pre_effect"
    assert channel.send_calls == []


@pytest.mark.asyncio
async def test_local_session_delivery_reconciles_marker_without_duplicate_append(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "channels" / "delivery"
    transcripts = TranscriptStore(tmp_path / "sessions")
    first = ChannelDeliveryService(
        {},
        state_root=root,
        transcript_store=transcripts,
    )
    intent = DeliveryIntent(
        source_id="f2-execution-attempt-1",
        kind="message_send",
        target=DeliveryTarget(channel="session", recipient="session-1"),
    )

    def lose_receipt(*_args: object, **_kwargs: object) -> None:
        raise OSError("crash after transcript append")

    monkeypatch.setattr(first._store, "mark_delivered", lose_receipt)
    initial = await first.send(
        intent=intent,
        message="one local reminder",
        metadata={"delivered_by": "scheduler"},
    )
    assert initial.outcome_unknown is True
    assert len(transcripts.list_entries(SessionId("session-1"))) == 1

    restarted = ChannelDeliveryService(
        {},
        state_root=root,
        transcript_store=TranscriptStore(tmp_path / "sessions"),
    )
    recovered = await restarted.recover()

    assert recovered[0].sent is True
    entries = transcripts.list_entries(SessionId("session-1"))
    assert len(entries) == 1
    assert entries[0].metadata["outbound_delivery_id"] == initial.delivery_id
    assert restarted.record(initial.reservation_id).state == "delivered"


@pytest.mark.asyncio
async def test_imported_transcript_row_cannot_spoof_local_delivery_receipt(
    tmp_path: Path,
) -> None:
    root = tmp_path / "channels" / "delivery"
    transcripts = TranscriptStore(tmp_path / "sessions")
    first = ChannelDeliveryService({}, state_root=root, transcript_store=transcripts)
    intent = DeliveryIntent(
        source_id="f2-import-spoof",
        kind="message_send",
        target=DeliveryTarget(channel="session", recipient="session-1"),
    )
    reservation = first.reserve(intent)
    prepared = first.prepare(reservation.reservation_id, message="real local reminder")
    assert first._store is not None
    assert first._store.claim_attempt(prepared.reservation_id) is not None
    transcripts.append(
        SessionId("session-1"),
        role="assistant",
        content="imported spoof",
        metadata={
            "_archive_imported": True,
            "outbound_delivery_id": prepared.delivery_id,
        },
        durable=True,
    )

    restarted = ChannelDeliveryService({}, state_root=root, transcript_store=transcripts)
    recovered = await restarted.recover()

    entries = transcripts.list_entries(SessionId("session-1"))
    assert recovered[0].sent is True
    assert len(entries) == 2
    assert transcripts.entry_content(entries[-1]) == "real local reminder"
    assert restarted.record(prepared.reservation_id).receipt.receipt_id == entries[-1].entry_id


@pytest.mark.asyncio
async def test_tampered_local_transcript_marker_never_becomes_delivery_receipt(
    tmp_path: Path,
) -> None:
    root = tmp_path / "channels" / "delivery"
    transcripts = TranscriptStore(tmp_path / "sessions")
    first = ChannelDeliveryService({}, state_root=root, transcript_store=transcripts)
    intent = DeliveryIntent(
        source_id="f2-tampered-local-receipt",
        kind="message_send",
        target=DeliveryTarget(channel="session", recipient="session-1"),
    )
    reservation = first.reserve(intent)
    prepared = first.prepare(reservation.reservation_id, message="authentic reminder")
    assert first._store is not None
    assert first._store.claim_attempt(prepared.reservation_id) is not None
    transcripts.append(
        SessionId("session-1"),
        role="assistant",
        content="tampered reminder",
        metadata={
            "delivery_target": intent.target.model_dump(mode="json"),
            "outbound_delivery_id": prepared.delivery_id,
        },
        durable=True,
    )

    restarted = ChannelDeliveryService({}, state_root=root, transcript_store=transcripts)
    recovered = await restarted.recover()

    assert len(recovered) == 1
    assert recovered[0].reason == "delivery_state_unavailable"
    assert len(transcripts.list_entries(SessionId("session-1"))) == 1
    assert restarted.health_status()["_outbox"]["status"] == "degraded"


@pytest.mark.asyncio
async def test_capability_notification_restart_never_replays_stale_url(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "channels" / "delivery"
    channel = _RecoveryChannel(recovery_kind=DeliveryRecoveryKind.NEITHER)
    await channel.connect()
    first = ChannelDeliveryService({"matrix": channel}, state_root=root)
    active_tokens: set[str] = set()
    issued_tokens: list[str] = []

    async def resolve(
        intent: CapabilityDeliveryIntent,
        *,
        rotate: bool,
    ) -> CapabilityPayload | None:
        if rotate:
            active_tokens.clear()
        token = f"secret-token-{len(issued_tokens) + 1}"
        issued_tokens.append(token)
        active_tokens.add(token)
        return CapabilityPayload(
            message=(
                "Approval required\n"
                f"https://approval.example/approve/{intent.confirmation_id}?token={token}"
            ),
            expires_at=datetime.now(UTC) + timedelta(minutes=2),
        )

    capability_intent = CapabilityDeliveryIntent(
        confirmation_id="confirm-1",
        target=DeliveryTarget(channel="matrix", recipient="!room:example.org"),
        expires_at=datetime.now(UTC) + timedelta(minutes=5),
    )

    def lose_receipt(*_args: object, **_kwargs: object) -> None:
        raise OSError("provider accepted capability before receipt commit")

    monkeypatch.setattr(first._store, "mark_delivered", lose_receipt)
    initial = await first.send_capability(intent=capability_intent, resolver=resolve)
    assert initial.outcome_unknown is True
    assert issued_tokens == ["secret-token-1"]

    restarted = ChannelDeliveryService({"matrix": channel}, state_root=root)
    recovered = await restarted.recover(capability_resolver=resolve)

    assert len(recovered) == 1
    assert recovered[0].sent is True
    assert issued_tokens == ["secret-token-1", "secret-token-2"]
    assert active_tokens == {"secret-token-2"}
    assert restarted.record(initial.reservation_id).state == "superseded"
    assert len(channel.effects) == 2
    database_bytes = (root / "outbox.sqlite3").read_bytes()
    assert b"secret-token-1" not in database_bytes
    assert b"secret-token-2" not in database_bytes
    assert b"approval.example" not in database_bytes
    assert b"?token=" not in database_bytes
    for sidecar in root.glob("outbox.sqlite3*"):
        assert b"secret-token" not in sidecar.read_bytes()
        assert b"approval.example" not in sidecar.read_bytes()


@pytest.mark.asyncio
@pytest.mark.parametrize("prior_state", ["delivered", "outcome_unknown"])
async def test_capability_restart_rotates_delivered_or_uncertain_notification(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    prior_state: str,
) -> None:
    root = tmp_path / "channels" / "delivery"
    channel = _RecoveryChannel(recovery_kind=DeliveryRecoveryKind.NEITHER)
    await channel.connect()
    first = ChannelDeliveryService({"matrix": channel}, state_root=root)
    issued_tokens: list[str] = []

    async def resolve(
        intent: CapabilityDeliveryIntent,
        *,
        rotate: bool,
    ) -> CapabilityPayload:
        _ = rotate
        token = f"rotated-{len(issued_tokens) + 1}"
        issued_tokens.append(token)
        return CapabilityPayload(
            message=f"https://approval.invalid/{intent.confirmation_id}?token={token}",
            expires_at=datetime.now(UTC) + timedelta(minutes=1),
        )

    original_send = channel.send
    if prior_state == "outcome_unknown":

        async def fail_send(
            _message: str,
            *,
            target: DeliveryTarget | None = None,
            metadata: dict[str, Any] | None = None,
        ) -> ProviderDeliveryReceipt:
            _ = (target, metadata)
            raise RuntimeError("provider outcome unavailable")

        monkeypatch.setattr(channel, "send", fail_send)
    initial = await first.send_capability(
        intent=CapabilityDeliveryIntent(
            confirmation_id=f"confirm-{prior_state}",
            target=DeliveryTarget(channel="matrix", recipient="!room:example.org"),
            expires_at=datetime.now(UTC) + timedelta(minutes=5),
        ),
        resolver=resolve,
    )
    assert initial.state == prior_state
    monkeypatch.setattr(channel, "send", original_send)
    first.close()

    restarted = ChannelDeliveryService({"matrix": channel}, state_root=root)
    recovered = await restarted.recover(capability_resolver=resolve)

    assert len(recovered) == 1
    assert recovered[0].sent is True
    assert issued_tokens == ["rotated-1", "rotated-2"]
    assert restarted.record(initial.reservation_id).state == "superseded"


@pytest.mark.asyncio
async def test_expired_capability_recovery_cancels_without_issuing_or_sending(
    tmp_path: Path,
) -> None:
    root = tmp_path / "channels" / "delivery"
    channel = _RecoveryChannel(recovery_kind=DeliveryRecoveryKind.NEITHER)
    await channel.connect()
    first = ChannelDeliveryService({"matrix": channel}, state_root=root)
    intent = CapabilityDeliveryIntent(
        confirmation_id="confirm-expired",
        target=DeliveryTarget(channel="matrix", recipient="!room:example.org"),
        expires_at=datetime.now(UTC) - timedelta(seconds=1),
    )

    async def should_not_resolve(
        _intent: CapabilityDeliveryIntent,
        *,
        rotate: bool,
    ) -> CapabilityPayload | None:
        _ = rotate
        raise AssertionError("expired intent must not issue a capability")

    result = await first.send_capability(intent=intent, resolver=should_not_resolve)

    assert result.sent is False
    assert result.state == "cancelled"
    assert channel.send_calls == []


@pytest.mark.asyncio
async def test_resolver_cannot_emit_already_expired_capability(
    tmp_path: Path,
) -> None:
    channel = _RecoveryChannel(recovery_kind=DeliveryRecoveryKind.NEITHER)
    await channel.connect()
    delivery = ChannelDeliveryService(
        {"matrix": channel}, state_root=tmp_path / "channels" / "delivery"
    )
    intent = CapabilityDeliveryIntent(
        confirmation_id="confirm-live",
        target=DeliveryTarget(channel="matrix", recipient="!room:example.org"),
        expires_at=datetime.now(UTC) + timedelta(minutes=5),
    )

    async def expired_payload(
        _intent: CapabilityDeliveryIntent, *, rotate: bool
    ) -> CapabilityPayload:
        _ = rotate
        return CapabilityPayload(
            message="stale capability",
            expires_at=datetime.now(UTC) - timedelta(seconds=1),
        )

    result = await delivery.send_capability(intent=intent, resolver=expired_payload)

    assert result.state == "cancelled"
    assert channel.send_calls == []


@pytest.mark.asyncio
async def test_existing_empty_outbox_degrades_without_provider_effect(tmp_path: Path) -> None:
    root = tmp_path / "channels" / "delivery"
    root.mkdir(parents=True)
    (root / "outbox.sqlite3").write_bytes(b"")
    channel = _RecoveryChannel(recovery_kind=DeliveryRecoveryKind.NEITHER)
    await channel.connect()

    delivery = ChannelDeliveryService({"matrix": channel}, state_root=root)
    result = await delivery.send(intent=_intent(), message="must not escape")

    assert result.sent is False
    assert result.attempted is False
    assert result.reason == "delivery_state_unavailable"
    assert channel.send_calls == []
    assert delivery.health_status()["_outbox"]["status"] == "degraded"


@pytest.mark.asyncio
@pytest.mark.parametrize("state_kind", ["malformed", "newer", "symlink"])
async def test_unsafe_or_unsupported_outbox_never_becomes_fresh_work(
    tmp_path: Path,
    state_kind: str,
) -> None:
    root = tmp_path / "channels" / "delivery"
    root.mkdir(parents=True)
    database = root / "outbox.sqlite3"
    if state_kind == "malformed":
        database.write_bytes(b"not a sqlite database")
    elif state_kind == "newer":
        first = ChannelDeliveryService({}, state_root=root)
        first.close()
        with sqlite3.connect(database) as connection:
            connection.execute("PRAGMA user_version = 2")
    else:
        target = tmp_path / "unsafe.sqlite3"
        target.write_bytes(b"not authority")
        database.symlink_to(target)
    channel = _RecoveryChannel(recovery_kind=DeliveryRecoveryKind.NEITHER)
    await channel.connect()

    delivery = ChannelDeliveryService({"matrix": channel}, state_root=root)
    result = await delivery.send(intent=_intent(), message="must not escape")

    assert result.reason == "delivery_state_unavailable"
    assert channel.send_calls == []
    assert delivery.health_status()["_outbox"]["status"] == "degraded"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "schema_variant",
    ["missing_columns", "wrong_unique_target", "wrong_type_and_nullability"],
)
async def test_same_version_wrong_schema_degrades_before_new_effect(
    tmp_path: Path,
    schema_variant: str,
) -> None:
    root = tmp_path / "channels" / "delivery"
    root.mkdir(parents=True)
    with sqlite3.connect(root / "outbox.sqlite3") as connection:
        if schema_variant == "missing_columns":
            connection.execute("CREATE TABLE deliveries (reservation_id TEXT PRIMARY KEY)")
        else:
            reservation_type = "BLOB" if schema_variant == "wrong_type_and_nullability" else "TEXT"
            intent_required = "" if schema_variant == "wrong_type_and_nullability" else " NOT NULL"
            delivery_unique = "" if schema_variant == "wrong_unique_target" else " UNIQUE"
            payload_unique = " UNIQUE" if schema_variant == "wrong_unique_target" else ""
            connection.execute(
                f"""
                CREATE TABLE deliveries (
                    reservation_id {reservation_type} PRIMARY KEY,
                    delivery_id TEXT{delivery_unique},
                    intent_json TEXT{intent_required},
                    payload TEXT NOT NULL{payload_unique},
                    payload_digest TEXT NOT NULL,
                    metadata_json TEXT NOT NULL,
                    state TEXT NOT NULL,
                    receipt_json TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
                """
            )
        connection.execute("PRAGMA user_version = 1")
    channel = _RecoveryChannel(recovery_kind=DeliveryRecoveryKind.NEITHER)
    await channel.connect()

    delivery = ChannelDeliveryService({"matrix": channel}, state_root=root)
    result = await delivery.send(intent=_intent(), message="must not escape")

    assert delivery._store is None
    assert delivery.health_status()["_outbox"]["status"] == "degraded"
    assert result.reason == "delivery_state_unavailable"
    assert channel.send_calls == []


@pytest.mark.asyncio
async def test_semantically_corrupt_outbox_blocks_all_new_effects(tmp_path: Path) -> None:
    root = tmp_path / "channels" / "delivery"
    first = ChannelDeliveryService({}, state_root=root)
    reservation = first.reserve(_intent())
    first.prepare(reservation.reservation_id, message="authentic result")
    first.close()
    with sqlite3.connect(root / "outbox.sqlite3") as connection:
        connection.execute(
            "UPDATE deliveries SET payload = 'tampered result' WHERE reservation_id = ?",
            (reservation.reservation_id,),
        )
    channel = _RecoveryChannel(recovery_kind=DeliveryRecoveryKind.NEITHER)
    await channel.connect()

    restarted = ChannelDeliveryService({"matrix": channel}, state_root=root)
    result = await restarted.send(
        intent=_intent(source_id="different-source"), message="must not escape"
    )

    assert result.reason == "delivery_state_unavailable"
    assert restarted.health_status()["_outbox"]["status"] == "degraded"
    assert channel.send_calls == []


@pytest.mark.asyncio
async def test_recovery_transaction_failure_degrades_only_delivery(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "channels" / "delivery"
    channel = _RecoveryChannel(recovery_kind=DeliveryRecoveryKind.NEITHER)
    await channel.connect()
    first = ChannelDeliveryService({"matrix": channel}, state_root=root)

    def lose_receipt(*_args: object, **_kwargs: object) -> None:
        raise OSError("receipt write unavailable")

    assert first._store is not None
    monkeypatch.setattr(first._store, "mark_delivered", lose_receipt)
    initial = await first.send(intent=_intent(), message="one result")
    restarted = ChannelDeliveryService({"matrix": channel}, state_root=root)
    assert restarted._store is not None

    def fail_recovery_transition(*_args: object, **_kwargs: object) -> None:
        raise DeliveryStateError("recovery transaction failed")

    monkeypatch.setattr(restarted._store, "mark_outcome_unknown", fail_recovery_transition)

    recovered = await restarted.recover()
    followup = await restarted.send(
        intent=_intent(source_id="blocked-after-transaction-failure"),
        message="must not escape",
    )

    assert initial.outcome_unknown is True
    assert recovered[0].reason == "delivery_state_unavailable"
    assert restarted.health_status()["_outbox"] == {
        "status": "degraded",
        "reason": "recovery transaction failed",
    }
    assert followup.reason == "delivery_state_unavailable"
    assert len(channel.send_calls) == 1


@pytest.mark.asyncio
async def test_recovery_read_failure_degrades_before_processing_records(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    channel = _RecoveryChannel(recovery_kind=DeliveryRecoveryKind.NEITHER)
    await channel.connect()
    delivery = ChannelDeliveryService(
        {"matrix": channel}, state_root=tmp_path / "channels" / "delivery"
    )
    assert delivery._store is not None

    def fail_record_scan(*_args: object, **_kwargs: object) -> None:
        raise DeliveryStateError("recovery scan failed")

    monkeypatch.setattr(delivery._store, "records", fail_record_scan)

    recovered = await delivery.recover()

    assert recovered[0].reason == "delivery_state_unavailable"
    assert delivery.health_status()["_outbox"] == {
        "status": "degraded",
        "reason": "recovery scan failed",
    }
    assert channel.send_calls == []


def test_outbox_permissions_schema_and_explicit_reset(tmp_path: Path) -> None:
    root = tmp_path / "channels" / "delivery"
    previous_umask = os.umask(0)
    try:
        delivery = ChannelDeliveryService({}, state_root=root)
    finally:
        os.umask(previous_umask)
    reserved = delivery.reserve(
        DeliveryIntent(
            source_id="reset-source",
            kind="message_send",
            target=DeliveryTarget(channel="session", recipient="session-1"),
        )
    )

    with sqlite3.connect(root / "outbox.sqlite3") as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 1
    assert root.stat().st_mode & 0o777 == 0o700
    assert (root / "outbox.sqlite3").stat().st_mode & 0o777 == 0o600
    assert delivery.reset() == 1
    assert delivery.record(reserved.reservation_id) is None
