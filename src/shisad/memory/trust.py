"""Trust derivation and legacy-remap helpers for v0.7 memory."""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Literal

SourceOrigin = Literal[
    "user_direct",
    "user_confirmed",
    "user_corrected",
    "tool_output",
    "external_web",
    "external_message",
    "consolidation_derived",
    "rc_evidence",
]
ChannelTrust = Literal[
    "command",
    "owner_observed",
    "shared_participant",
    "external_incoming",
    "tool_passed",
    "web_passed",
    "consolidation",
]
ConfirmationStatus = Literal[
    "user_asserted",
    "user_confirmed",
    "user_corrected",
    "pep_approved",
    "auto_accepted",
    "pending_review",
]
TrustBand = Literal["elevated", "observed", "untrusted"]
ConfidenceMode = Literal["fixed", "inherit_weighted", "preserved"]

SOURCE_ORIGIN_VALUES: tuple[SourceOrigin, ...] = (
    "user_direct",
    "user_confirmed",
    "user_corrected",
    "tool_output",
    "external_web",
    "external_message",
    "consolidation_derived",
    "rc_evidence",
)
CHANNEL_TRUST_VALUES: tuple[ChannelTrust, ...] = (
    "command",
    "owner_observed",
    "shared_participant",
    "external_incoming",
    "tool_passed",
    "web_passed",
    "consolidation",
)
CONFIRMATION_STATUS_VALUES: tuple[ConfirmationStatus, ...] = (
    "user_asserted",
    "user_confirmed",
    "user_corrected",
    "pep_approved",
    "auto_accepted",
    "pending_review",
)


class TrustGateViolation(ValueError):
    """Raised when a provenance triple or handle binding is invalid."""


@dataclass(frozen=True)
class TrustRule:
    """Resolved trust-matrix rule."""

    trust_band: TrustBand
    default_confidence: float | None
    confidence_mode: ConfidenceMode = "fixed"
    note: str = ""


_PENDING_REVIEW_RULE = TrustRule(
    trust_band="untrusted",
    default_confidence=None,
    confidence_mode="preserved",
    note="review queue entries preserve prior confidence and never surface by default",
)

_VALID_TRUST_MATRIX: dict[tuple[SourceOrigin, ChannelTrust, ConfirmationStatus], TrustRule] = {
    ("user_direct", "command", "user_asserted"): TrustRule("elevated", 0.95),
    ("user_confirmed", "command", "user_confirmed"): TrustRule("elevated", 0.90),
    ("user_corrected", "command", "user_corrected"): TrustRule("elevated", 0.85),
    (
        "user_confirmed",
        "command",
        "auto_accepted",
    ): TrustRule(
        "untrusted",
        None,
        confidence_mode="preserved",
        note="legacy/backfill compatibility row for passive confirmed assertions",
    ),
    ("user_direct", "owner_observed", "auto_accepted"): TrustRule("observed", 0.30),
    ("external_message", "external_incoming", "auto_accepted"): TrustRule("untrusted", 0.40),
    ("external_message", "shared_participant", "auto_accepted"): TrustRule("untrusted", 0.40),
    ("tool_output", "tool_passed", "pep_approved"): TrustRule("untrusted", 0.70),
    ("tool_output", "tool_passed", "auto_accepted"): TrustRule("untrusted", 0.50),
    ("external_web", "web_passed", "auto_accepted"): TrustRule("untrusted", 0.40),
    (
        "consolidation_derived",
        "consolidation",
        "auto_accepted",
    ): TrustRule(
        "untrusted",
        None,
        confidence_mode="inherit_weighted",
        note="consolidation inherits confidence from source entries",
    ),
    ("rc_evidence", "tool_passed", "auto_accepted"): TrustRule("untrusted", 0.60),
    ("user_confirmed", "tool_passed", "user_confirmed"): TrustRule("elevated", 0.90),
    ("user_corrected", "tool_passed", "user_corrected"): TrustRule("elevated", 0.85),
    (
        "user_direct",
        "command",
        "auto_accepted",
    ): TrustRule(
        "untrusted",
        None,
        confidence_mode="preserved",
        note="legacy/backfill compatibility row for v0.6 command-channel assertions",
    ),
}

_LEGACY_ORIGIN_MAP: dict[str, SourceOrigin] = {
    "user": "user_direct",
    "inferred": "consolidation_derived",
    "external": "external_web",
    "user_curated": "user_direct",
    "project_doc": "tool_output",
}

_DEFAULT_CHANNEL_BY_SOURCE: dict[SourceOrigin, ChannelTrust] = {
    "user_direct": "command",
    "user_confirmed": "command",
    "user_corrected": "command",
    "tool_output": "tool_passed",
    "external_web": "web_passed",
    "external_message": "external_incoming",
    "consolidation_derived": "consolidation",
    "rc_evidence": "tool_passed",
}


def _ensure_known_value(value: str, *, allowed: tuple[str, ...], field: str) -> None:
    if value not in allowed:
        raise TrustGateViolation(f"unknown {field}: {value}")


def validate_trust_triple(
    source_origin: SourceOrigin,
    channel_trust: ChannelTrust,
    confirmation_status: ConfirmationStatus,
    *,
    enable_observed: bool = False,
) -> TrustRule:
    """Validate and resolve a trust triple through the canonical matrix."""

    _ensure_known_value(source_origin, allowed=SOURCE_ORIGIN_VALUES, field="source_origin")
    _ensure_known_value(channel_trust, allowed=CHANNEL_TRUST_VALUES, field="channel_trust")
    _ensure_known_value(
        confirmation_status,
        allowed=CONFIRMATION_STATUS_VALUES,
        field="confirmation_status",
    )
    if confirmation_status == "pending_review":
        return _PENDING_REVIEW_RULE

    rule = _VALID_TRUST_MATRIX.get((source_origin, channel_trust, confirmation_status))
    if rule is None:
        raise TrustGateViolation(
            f"invalid trust triple: {source_origin}/{channel_trust}/{confirmation_status}"
        )
    if rule.trust_band == "observed" and not enable_observed:
        return replace(rule, trust_band="untrusted")
    return rule


def derive_trust_band(
    source_origin: SourceOrigin,
    channel_trust: ChannelTrust,
    confirmation_status: ConfirmationStatus,
    *,
    enable_observed: bool = False,
) -> TrustBand:
    """Return the derived trust band for a valid triple."""

    return validate_trust_triple(
        source_origin,
        channel_trust,
        confirmation_status,
        enable_observed=enable_observed,
    ).trust_band


def default_confidence_for_triple(
    source_origin: SourceOrigin,
    channel_trust: ChannelTrust,
    confirmation_status: ConfirmationStatus,
    *,
    enable_observed: bool = False,
) -> float | None:
    """Return the matrix default confidence, if the rule has a fixed cap."""

    return validate_trust_triple(
        source_origin,
        channel_trust,
        confirmation_status,
        enable_observed=enable_observed,
    ).default_confidence


def clamp_confidence(
    requested: float | None,
    source_origin: SourceOrigin,
    channel_trust: ChannelTrust,
    confirmation_status: ConfirmationStatus,
    *,
    fallback: float | None = None,
    enable_observed: bool = False,
) -> float:
    """Clamp caller confidence to the matrix rule or preserve/inherit fallback."""

    rule = validate_trust_triple(
        source_origin,
        channel_trust,
        confirmation_status,
        enable_observed=enable_observed,
    )
    if rule.default_confidence is None:
        resolved = requested if requested is not None else fallback
        if resolved is None:
            raise ValueError(
                "confidence required for preserved/inherited trust rows without fallback"
            )
        return max(0.0, min(resolved, 0.99))

    if requested is None:
        return rule.default_confidence
    return max(0.0, min(requested, rule.default_confidence))


def is_invocation_eligible_triple(
    source_origin: SourceOrigin,
    channel_trust: ChannelTrust,
    confirmation_status: ConfirmationStatus,
) -> bool:
    """Whether this install-time triple can mark a procedural artifact invocable."""

    rule = validate_trust_triple(source_origin, channel_trust, confirmation_status)
    if rule.trust_band == "elevated":
        return True
    return (
        source_origin == "tool_output"
        and channel_trust == "tool_passed"
        and confirmation_status == "pep_approved"
    )


def backfill_legacy_triple(
    *,
    legacy_origin: str | None = None,
    source_origin: SourceOrigin | None = None,
    channel_trust: ChannelTrust | None = None,
    confirmation_status: ConfirmationStatus | None = None,
) -> tuple[SourceOrigin, ChannelTrust, ConfirmationStatus]:
    """Resolve a legacy v0.6 provenance shape to a conservative v0.7 triple."""

    resolved_origin = source_origin
    if resolved_origin is None:
        if legacy_origin is None:
            raise TrustGateViolation("legacy backfill requires source_origin or legacy_origin")
        try:
            resolved_origin = _LEGACY_ORIGIN_MAP[legacy_origin]
        except KeyError as exc:
            raise TrustGateViolation(f"unknown legacy origin: {legacy_origin}") from exc

    resolved_channel = channel_trust or _DEFAULT_CHANNEL_BY_SOURCE[resolved_origin]
    resolved_confirmation = confirmation_status or "auto_accepted"
    validate_trust_triple(resolved_origin, resolved_channel, resolved_confirmation)
    return (resolved_origin, resolved_channel, resolved_confirmation)
