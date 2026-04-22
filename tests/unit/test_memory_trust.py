"""Unit coverage for v0.7 memory trust derivation foundations."""

from __future__ import annotations

from itertools import product

import pytest

from shisad.memory.trust import (
    _VALID_TRUST_MATRIX,
    CHANNEL_TRUST_VALUES,
    CONFIRMATION_STATUS_VALUES,
    SOURCE_ORIGIN_VALUES,
    TrustGateViolation,
    backfill_legacy_triple,
    clamp_confidence,
    default_confidence_for_triple,
    derive_trust_band,
    is_invocation_eligible_triple,
    validate_trust_triple,
)


@pytest.mark.parametrize(
    ("source_origin", "channel_trust", "confirmation_status", "trust_band", "confidence"),
    [
        ("user_direct", "command", "user_asserted", "elevated", 0.95),
        ("user_confirmed", "command", "auto_accepted", "untrusted", None),
        ("tool_output", "tool_passed", "pep_approved", "untrusted", 0.70),
        ("consolidation_derived", "consolidation", "auto_accepted", "untrusted", None),
        ("user_direct", "command", "auto_accepted", "untrusted", None),
    ],
)
def test_validate_trust_triple_accepts_documented_rows(
    source_origin: str,
    channel_trust: str,
    confirmation_status: str,
    trust_band: str,
    confidence: float | None,
) -> None:
    rule = validate_trust_triple(source_origin, channel_trust, confirmation_status)
    assert rule.trust_band == trust_band
    assert rule.default_confidence == confidence


def test_m1_trust_matrix_validates_every_canonical_non_pending_row() -> None:
    for (
        source_origin,
        channel_trust,
        confirmation_status,
    ), expected in _VALID_TRUST_MATRIX.items():
        assert validate_trust_triple(
            source_origin,
            channel_trust,
            confirmation_status,
            enable_observed=True,
        ) == expected


def test_m1_trust_matrix_rejects_every_unlisted_non_pending_triple() -> None:
    for source_origin, channel_trust, confirmation_status in product(
        SOURCE_ORIGIN_VALUES,
        CHANNEL_TRUST_VALUES,
        CONFIRMATION_STATUS_VALUES,
    ):
        if confirmation_status == "pending_review":
            continue
        if (source_origin, channel_trust, confirmation_status) in _VALID_TRUST_MATRIX:
            continue
        with pytest.raises(TrustGateViolation):
            validate_trust_triple(
                source_origin,
                channel_trust,
                confirmation_status,
                enable_observed=True,
            )


def test_owner_observed_row_is_untrusted_in_v070_and_observed_when_enabled() -> None:
    assert (
        derive_trust_band("user_direct", "owner_observed", "auto_accepted")
        == "untrusted"
    )
    assert (
        derive_trust_band(
            "user_direct",
            "owner_observed",
            "auto_accepted",
            enable_observed=True,
        )
        == "observed"
    )


def test_pending_review_dominates_otherwise_valid_triples() -> None:
    rule = validate_trust_triple("external_message", "shared_participant", "pending_review")
    assert rule.trust_band == "untrusted"
    assert rule.confidence_mode == "preserved"


def test_invalid_triple_rejected() -> None:
    with pytest.raises(TrustGateViolation):
        validate_trust_triple("user_direct", "external_incoming", "user_asserted")


def test_clamp_confidence_uses_rule_cap() -> None:
    assert clamp_confidence(
        0.99,
        "user_confirmed",
        "command",
        "user_confirmed",
    ) == pytest.approx(0.90)
    assert clamp_confidence(
        None,
        "user_corrected",
        "command",
        "user_corrected",
    ) == pytest.approx(0.85)


def test_preserved_confidence_rows_require_fallback_or_explicit_value() -> None:
    with pytest.raises(ValueError):
        clamp_confidence(None, "user_direct", "command", "auto_accepted")
    assert clamp_confidence(
        None,
        "user_direct",
        "command",
        "auto_accepted",
        fallback=0.42,
    ) == pytest.approx(0.42)


@pytest.mark.parametrize(
    ("source_origin", "channel_trust", "confirmation_status", "eligible"),
    [
        ("user_direct", "command", "user_asserted", True),
        ("user_confirmed", "command", "user_confirmed", True),
        ("tool_output", "tool_passed", "pep_approved", True),
        ("tool_output", "tool_passed", "auto_accepted", False),
        ("external_web", "web_passed", "auto_accepted", False),
    ],
)
def test_invocation_eligibility_tracks_install_predicate(
    source_origin: str,
    channel_trust: str,
    confirmation_status: str,
    eligible: bool,
) -> None:
    assert (
        is_invocation_eligible_triple(source_origin, channel_trust, confirmation_status)
        is eligible
    )


def test_default_confidence_for_triple_returns_none_for_inherited_or_preserved_rows() -> None:
    assert (
        default_confidence_for_triple(
            "consolidation_derived",
            "consolidation",
            "auto_accepted",
        )
        is None
    )
    assert default_confidence_for_triple("user_direct", "command", "auto_accepted") is None


def test_backfill_legacy_user_origin_resolves_to_passive_command_row() -> None:
    triple = backfill_legacy_triple(legacy_origin="user")
    assert triple == ("user_direct", "command", "auto_accepted")
    assert derive_trust_band(*triple) == "untrusted"


def test_backfill_legacy_project_doc_maps_to_tool_passed() -> None:
    assert backfill_legacy_triple(legacy_origin="project_doc") == (
        "tool_output",
        "tool_passed",
        "auto_accepted",
    )
