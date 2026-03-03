"""Unit checks for chat-based confirmation classification and routing."""

from __future__ import annotations

from shisad.daemon.handlers._impl_session import (
    ChatConfirmationIntent,
    _classify_chat_confirmation_intent,
    _resolve_chat_confirmation_indexes,
)


def test_m6_crc_classifier_handles_affirmative_negative_reference_and_passthrough() -> None:
    assert _classify_chat_confirmation_intent("yes") == ChatConfirmationIntent(
        action="confirm",
        target="single",
        index=None,
    )
    assert _classify_chat_confirmation_intent("go ahead") == ChatConfirmationIntent(
        action="confirm",
        target="single",
        index=None,
    )
    assert _classify_chat_confirmation_intent("confirm 2") == ChatConfirmationIntent(
        action="confirm",
        target="index",
        index=2,
    )
    assert _classify_chat_confirmation_intent("yes to all") == ChatConfirmationIntent(
        action="confirm",
        target="all",
        index=None,
    )
    assert _classify_chat_confirmation_intent("reject 1") == ChatConfirmationIntent(
        action="reject",
        target="index",
        index=1,
    )
    assert _classify_chat_confirmation_intent("no to all") == ChatConfirmationIntent(
        action="reject",
        target="all",
        index=None,
    )
    assert _classify_chat_confirmation_intent("what tools do you have?") == ChatConfirmationIntent(
        action="none",
        target="none",
        index=None,
    )


def test_m6_crc_routing_clean_session_auto_confirms_single_pending() -> None:
    intent = ChatConfirmationIntent(action="confirm", target="single", index=None)
    resolved = _resolve_chat_confirmation_indexes(
        intent=intent,
        pending_count=1,
        tainted_session=False,
    )
    assert resolved == [0]


def test_m6_crc_routing_requires_reference_for_tainted_or_multi_pending() -> None:
    intent = ChatConfirmationIntent(action="confirm", target="single", index=None)
    assert (
        _resolve_chat_confirmation_indexes(
            intent=intent,
            pending_count=1,
            tainted_session=True,
        )
        == []
    )
    assert (
        _resolve_chat_confirmation_indexes(
            intent=intent,
            pending_count=2,
            tainted_session=False,
        )
        == []
    )
    explicit = ChatConfirmationIntent(action="confirm", target="index", index=2)
    assert _resolve_chat_confirmation_indexes(
        intent=explicit,
        pending_count=2,
        tainted_session=True,
    ) == [1]
