"""Unit tests for domain error taxonomy."""

from __future__ import annotations

from shisad.core.errors import (
    ChannelError,
    ConfigError,
    PolicyError,
    SandboxError,
    ShisadError,
    SkillError,
    StorageError,
    TransportError,
)


def test_error_hierarchy_and_defaults() -> None:
    instances = [
        TransportError(),
        PolicyError(),
        SandboxError(),
        ChannelError(),
        StorageError(),
        SkillError(),
        ConfigError(),
    ]
    for err in instances:
        assert isinstance(err, ShisadError)
        assert isinstance(err.reason_code, str)
        assert err.reason_code


def test_error_serialization_includes_reason_code() -> None:
    err = PolicyError(
        "capability denied",
        reason_code="policy.capability_denied",
        details={"capability": "network"},
    )
    public_payload = err.as_error_data()
    detailed_payload = err.as_error_data(include_details=True)
    assert public_payload == {"reason_code": "policy.capability_denied"}
    assert detailed_payload == {
        "reason_code": "policy.capability_denied",
        "details": {"capability": "network"},
    }


def test_public_message_respects_exposure_policy() -> None:
    internal = StorageError("sqlite busy", reason_code="storage.sqlite_busy")
    user_facing = SkillError("skill path missing", reason_code="skill.path_missing")
    assert internal.public_message == "Internal error"
    assert user_facing.public_message == "skill path missing"
