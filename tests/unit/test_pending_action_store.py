"""F10A contracts for the versioned pending-action record/store boundary."""

from __future__ import annotations

import inspect
import json

import pytest

import shisad.core.pending_action as pending_action_module
from shisad.core.atomic_state import AtomicWriteError, AtomicWriteStage
from shisad.core.pending_action import (
    PENDING_ACTION_RECORD_SCHEMA_VERSION,
    PendingActionRecord,
)
from shisad.daemon.handlers._impl import HandlerImplementation, PendingAction
from shisad.daemon.pending_actions import (
    PendingActionStore,
    PendingActionStoreLoadStatus,
)
from tests.helpers.approval import make_pending_action


def _durable_payload(record: PendingActionRecord) -> dict[str, object]:
    return HandlerImplementation._pending_to_dict(record)


def test_f10a_record_schema_preserves_former_optional_positional_slots() -> None:
    template = make_pending_action(confirmation_id="c-positional")
    required = (
        template.confirmation_id,
        template.decision_nonce,
        template.session_id,
        template.user_id,
        template.workspace_id,
        template.tool_name,
        template.arguments,
        template.reason,
        template.capabilities,
        template.created_at,
    )

    record = PendingActionRecord(*required, {"query": "public-record"})
    alias_record = PendingAction(*required, {"query": "public-alias"})

    assert record.public_arguments == {"query": "public-record"}
    assert alias_record.public_arguments == {"query": "public-alias"}
    assert record.record_schema_version == PENDING_ACTION_RECORD_SCHEMA_VERSION
    assert alias_record.record_schema_version == PENDING_ACTION_RECORD_SCHEMA_VERSION


def test_f10c_core_record_has_no_daemon_type_dependency() -> None:
    assert "shisad.daemon" not in inspect.getsource(pending_action_module)


def test_f10a_current_record_round_trips_with_index_parity(tmp_path) -> None:
    store = PendingActionStore(tmp_path / "pending_actions.json")
    record = make_pending_action(confirmation_id="c-current")

    assert isinstance(record, PendingActionRecord)
    assert PendingAction is PendingActionRecord

    store.add(record)
    store.assert_index_parity()
    store.write_payloads([_durable_payload(record)])

    loaded = store.load_payloads()

    assert loaded.status is PendingActionStoreLoadStatus.CURRENT
    assert loaded.quarantined_path is None
    assert len(loaded.payloads) == 1
    assert loaded.payloads[0]["record_schema_version"] == PENDING_ACTION_RECORD_SCHEMA_VERSION
    assert loaded.payloads[0]["confirmation_id"] == "c-current"


def test_f10a_store_add_remove_owns_session_index_parity(tmp_path) -> None:
    store = PendingActionStore(tmp_path / "pending_actions.json")
    first = make_pending_action(confirmation_id="c-first")
    second = make_pending_action(confirmation_id="c-second")

    store.add(first)
    store.add(second)

    assert store.actions == {"c-first": first, "c-second": second}
    assert store.by_session == {first.session_id: ["c-first", "c-second"]}
    store.assert_index_parity()

    assert store.remove("c-first") is first
    assert store.actions == {"c-second": second}
    assert store.by_session == {second.session_id: ["c-second"]}
    store.assert_index_parity()


def test_f10a_schema_less_record_is_classified_for_legacy_migration(tmp_path) -> None:
    path = tmp_path / "pending_actions.json"
    record = make_pending_action(confirmation_id="c-legacy")
    payload = _durable_payload(record)
    payload.pop("record_schema_version", None)
    path.write_text(json.dumps([payload]), encoding="utf-8")

    loaded = PendingActionStore(path).load_payloads()

    assert loaded.status is PendingActionStoreLoadStatus.LEGACY
    assert loaded.quarantined_path is None
    assert loaded.payloads == (payload,)
    assert path.exists()


def test_f10a_nonfinite_current_payload_is_typed_as_uncommitted_write_failure(
    tmp_path,
) -> None:
    path = tmp_path / "pending_actions.json"
    store = PendingActionStore(path)
    payload = _durable_payload(make_pending_action(confirmation_id="c-nonfinite"))
    payload["arguments"] = {"query": float("nan")}

    with pytest.raises(AtomicWriteError) as caught:
        store.write_payloads([payload])

    assert caught.value.path == path
    assert caught.value.stage is AtomicWriteStage.WRITE
    assert caught.value.publication_may_have_committed is False
    assert not path.exists()


@pytest.mark.parametrize(
    ("raw", "expected_status"),
    [
        (b'{"broken":', PendingActionStoreLoadStatus.CORRUPT),
        (
            json.dumps(
                [
                    {
                        "record_schema_version": None,
                        "confirmation_id": "c-null",
                        "session_id": "session-1",
                        "identity": {
                            "confirmation_id": "c-null",
                            "session_id": "session-1",
                        },
                    }
                ]
            ).encode(),
            PendingActionStoreLoadStatus.CORRUPT,
        ),
        (
            json.dumps(
                [
                    {
                        "record_schema_version": PENDING_ACTION_RECORD_SCHEMA_VERSION + 1,
                        "confirmation_id": "c-future",
                        "session_id": "session-1",
                        "identity": {
                            "confirmation_id": "c-future",
                            "session_id": "session-1",
                        },
                    }
                ]
            ).encode(),
            PendingActionStoreLoadStatus.UNSUPPORTED_SCHEMA,
        ),
    ],
)
def test_f10a_corrupt_or_future_store_is_quarantined_byte_for_byte(
    tmp_path,
    raw: bytes,
    expected_status: PendingActionStoreLoadStatus,
) -> None:
    path = tmp_path / "pending_actions.json"
    path.write_bytes(raw)

    loaded = PendingActionStore(path).load_payloads()

    assert loaded.status is expected_status
    assert loaded.payloads == ()
    assert loaded.quarantined_path is not None
    assert loaded.quarantined_path.read_bytes() == raw
    assert not path.exists()
