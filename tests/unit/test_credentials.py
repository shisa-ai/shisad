"""M0.T9, T11-T13: Credential broker tests."""

from __future__ import annotations

import json
import os
import stat
from datetime import UTC, datetime
from pathlib import Path

import pytest

import shisad.core.atomic_state as atomic_state
from shisad.core.atomic_state import (
    AtomicWriteError,
    AtomicWriteStage,
    StateLoadStatus,
    StatePersistenceDegradedError,
    encode_versioned_json_snapshot,
)
from shisad.core.tools.registry import ToolRegistry
from shisad.core.tools.schema import ToolDefinition, ToolParameter
from shisad.core.types import Capability, PEPDecisionKind, ToolName
from shisad.security.credentials import (
    ApprovalFactorRecord,
    CredentialConfig,
    CredentialRef,
    InMemoryCredentialStore,
    RecoveryCodeRecord,
    SignerKeyRecord,
    generate_placeholder,
    is_placeholder,
)
from shisad.security.pep import PEP, PolicyContext
from shisad.security.policy import EgressRule, PolicyBundle


class TestPepRejectsRawSecrets:
    """M0.T9: credential broker rejects raw secrets in tool args."""

    def test_rejects_openai_key(self) -> None:
        registry = ToolRegistry()
        registry.register(
            ToolDefinition(
                name=ToolName("http_call"),
                description="Make HTTP request",
                parameters=[ToolParameter(name="url", type="string")],
                capabilities_required=[Capability.HTTP_REQUEST],
            )
        )
        policy = PolicyBundle(default_require_confirmation=False)
        pep = PEP(policy, registry)
        ctx = PolicyContext(capabilities={Capability.HTTP_REQUEST})

        decision = pep.evaluate(
            ToolName("http_call"),
            {"url": "https://api.example.com", "api_key": "sk-proj-abc123def456"},
            ctx,
        )
        assert decision.kind == PEPDecisionKind.REJECT
        assert "raw secret" in decision.reason.lower() or "Unexpected argument" in decision.reason

    def test_rejects_aws_key(self) -> None:
        registry = ToolRegistry()
        registry.register(
            ToolDefinition(
                name=ToolName("aws_call"),
                description="AWS API call",
                parameters=[
                    ToolParameter(name="service", type="string"),
                    ToolParameter(name="key", type="string"),
                ],
                capabilities_required=[Capability.HTTP_REQUEST],
            )
        )
        policy = PolicyBundle(default_require_confirmation=False)
        pep = PEP(policy, registry)
        ctx = PolicyContext(capabilities={Capability.HTTP_REQUEST})

        decision = pep.evaluate(
            ToolName("aws_call"),
            {"service": "s3", "key": "AKIAIOSFODNN7EXAMPLE"},
            ctx,
        )
        assert decision.kind == PEPDecisionKind.REJECT
        assert "raw secret" in decision.reason.lower()


class TestPlaceholderGeneration:
    """M0.T11: placeholder generation is deterministic per credential_ref."""

    def test_deterministic(self) -> None:
        ref = CredentialRef("openai_api_key")
        p1 = generate_placeholder(ref)
        p2 = generate_placeholder(ref)
        assert p1 == p2

    def test_different_refs_different_placeholders(self) -> None:
        p1 = generate_placeholder(CredentialRef("key_a"))
        p2 = generate_placeholder(CredentialRef("key_b"))
        assert p1 != p2

    def test_is_placeholder(self) -> None:
        ref = CredentialRef("test")
        p = generate_placeholder(ref)
        assert is_placeholder(p)
        assert not is_placeholder("not_a_placeholder")


class TestCredentialStoreReturnsPlaceholder:
    """M0.T12: credential store returns placeholder, never raw value."""

    def test_get_placeholder_not_raw_value(self) -> None:
        store = InMemoryCredentialStore()
        ref = CredentialRef("openai_key")
        store.register(
            ref,
            "sk-real-secret-value",
            CredentialConfig(allowed_hosts=["api.openai.com"]),
        )
        placeholder = store.get_placeholder(ref)
        assert "sk-real-secret-value" not in placeholder
        assert is_placeholder(placeholder)

    def test_unknown_ref_raises(self) -> None:
        store = InMemoryCredentialStore()
        with pytest.raises(KeyError):
            store.get_placeholder(CredentialRef("nonexistent"))


class TestHostScopedBinding:
    """M0.T13: host-scoped binding rejects credential use for non-allowed host."""

    def test_allowed_host_resolves(self) -> None:
        store = InMemoryCredentialStore()
        ref = CredentialRef("openai_key")
        store.register(
            ref,
            "sk-real-secret",
            CredentialConfig(allowed_hosts=["api.openai.com"]),
        )
        placeholder = store.get_placeholder(ref)
        value = store.resolve(placeholder, "api.openai.com")
        assert value == "sk-real-secret"

    def test_disallowed_host_returns_none(self) -> None:
        store = InMemoryCredentialStore()
        ref = CredentialRef("openai_key")
        store.register(
            ref,
            "sk-real-secret",
            CredentialConfig(allowed_hosts=["api.openai.com"]),
        )
        placeholder = store.get_placeholder(ref)
        value = store.resolve(placeholder, "evil.com")
        assert value is None

    def test_glob_pattern_matching(self) -> None:
        store = InMemoryCredentialStore()
        ref = CredentialRef("anthropic_key")
        store.register(
            ref,
            "sk-ant-secret",
            CredentialConfig(allowed_hosts=["*.anthropic.com"]),
        )
        placeholder = store.get_placeholder(ref)
        assert store.resolve(placeholder, "api.anthropic.com") == "sk-ant-secret"
        assert store.resolve(placeholder, "docs.anthropic.com") == "sk-ant-secret"
        assert store.resolve(placeholder, "evil.com") is None


class TestPepCredentialRefValidation:
    """M0.8.4: PEP validates credential_ref host binding and logs usage."""

    def _make_registry(self) -> ToolRegistry:
        registry = ToolRegistry()
        registry.register(
            ToolDefinition(
                name=ToolName("http_call"),
                description="Make HTTP request with a credential ref",
                parameters=[
                    ToolParameter(name="url", type="string", required=True),
                    ToolParameter(name="credential_ref", type="string", required=True),
                ],
                capabilities_required=[Capability.HTTP_REQUEST],
                destinations=["api.openai.com"],
            )
        )
        return registry

    def test_credential_ref_allowed_for_destination(self) -> None:
        store = InMemoryCredentialStore()
        store.register(
            CredentialRef("openai_api_key"),
            "sk-real-secret",
            CredentialConfig(allowed_hosts=["api.openai.com"]),
        )
        pep = PEP(
            PolicyBundle(
                default_require_confirmation=False,
                egress=[EgressRule(host="api.openai.com")],
            ),
            self._make_registry(),
            credential_store=store,
        )

        decision = pep.evaluate(
            ToolName("http_call"),
            {
                "url": "https://api.openai.com/v1/chat/completions",
                "credential_ref": "openai_api_key",
            },
            PolicyContext(capabilities={Capability.HTTP_REQUEST}),
        )
        assert decision.kind == PEPDecisionKind.ALLOW
        assert pep.credential_attempts
        assert pep.credential_attempts[-1].destination_host == "api.openai.com"

    def test_credential_ref_rejected_for_non_allowed_host(self) -> None:
        store = InMemoryCredentialStore()
        store.register(
            CredentialRef("openai_api_key"),
            "sk-real-secret",
            CredentialConfig(allowed_hosts=["api.openai.com"]),
        )
        pep = PEP(
            PolicyBundle(default_require_confirmation=False),
            self._make_registry(),
            credential_store=store,
        )

        decision = pep.evaluate(
            ToolName("http_call"),
            {
                "url": "https://evil.com/exfil",
                "credential_ref": "openai_api_key",
            },
            PolicyContext(capabilities={Capability.HTTP_REQUEST}),
        )
        assert decision.kind == PEPDecisionKind.REJECT
        assert "credential_ref" in decision.reason


class TestApprovalFactorStore:
    def test_approval_factor_store_persists_and_round_trips(self, tmp_path) -> None:
        store_path = tmp_path / "credentials.json"
        store = InMemoryCredentialStore()
        store.set_approval_store_path(store_path)
        factor = ApprovalFactorRecord(
            credential_id="totp-1",
            user_id="alice",
            method="totp",
            principal_id="ops-laptop",
            secret_b32="GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
            created_at=datetime(2026, 4, 6, 12, 0, 0, tzinfo=UTC),
            recovery_codes=[RecoveryCodeRecord(code_hash="recovery-hash")],
        )

        store.register_approval_factor(factor)

        envelope = json.loads(store_path.read_text(encoding="utf-8"))
        assert envelope["version"] == 3
        assert isinstance(envelope["checksum"], str)
        assert envelope["payload"]["approval_factors"][0]["credential_id"] == "totp-1"

        reloaded = InMemoryCredentialStore()
        reloaded.set_approval_store_path(store_path)
        entries = reloaded.list_approval_factors(user_id="alice", method="totp")

        result = reloaded.approval_state_load_result()
        assert result.status == StateLoadStatus.OK
        assert result.schema_version == 3
        assert len(entries) == 1
        assert entries[0].credential_id == "totp-1"
        assert entries[0].principal_id == "ops-laptop"
        assert entries[0].recovery_codes[0].code_hash == "recovery-hash"

    def test_approval_factor_store_supports_long_valid_basename(self, tmp_path) -> None:
        store_path = tmp_path / ("a" * 240)
        store = InMemoryCredentialStore()
        store.set_approval_store_path(store_path)

        store.register_approval_factor(
            ApprovalFactorRecord(
                credential_id="totp-long-name",
                user_id="alice",
                method="totp",
                principal_id="ops-laptop",
                secret_b32="GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
            )
        )

        assert store_path.exists()
        assert [item.credential_id for item in store.list_approval_factors()] == [
            "totp-long-name"
        ]

    def test_approval_factor_revoke_filters_by_user_and_method(self, tmp_path) -> None:
        store = InMemoryCredentialStore()
        store.set_approval_store_path(tmp_path / "credentials.json")
        store.register_approval_factor(
            ApprovalFactorRecord(
                credential_id="totp-a",
                user_id="alice",
                method="totp",
                principal_id="alice-device",
                secret_b32="GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
            )
        )
        store.register_approval_factor(
            ApprovalFactorRecord(
                credential_id="totp-b",
                user_id="bob",
                method="totp",
                principal_id="bob-device",
                secret_b32="GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
            )
        )

        removed = store.revoke_approval_factor(user_id="alice", method="totp")

        assert removed == 1
        assert [item.credential_id for item in store.list_approval_factors()] == ["totp-b"]

    def test_approval_factor_store_retains_and_blocks_malformed_json(self, tmp_path) -> None:
        store_path = tmp_path / "approval-factors.json"
        corrupt_bytes = b"{not-json"
        store_path.write_bytes(corrupt_bytes)
        store_path.chmod(0o600)

        store = InMemoryCredentialStore()
        store.set_approval_store_path(store_path)

        result = store.approval_state_load_result()
        assert result.status == StateLoadStatus.CORRUPT
        assert result.reason == "invalid_json"
        assert store.approval_state_degraded is True
        with pytest.raises(StatePersistenceDegradedError, match="invalid_json"):
            store.list_approval_factors()
        assert store_path.read_bytes() == corrupt_bytes
        assert list(tmp_path.glob("approval-factors.json.corrupt.*")) == []

    def test_local_fido2_realm_id_persists_with_factor_store(self, tmp_path) -> None:
        store_path = tmp_path / "approval-factors.json"
        store = InMemoryCredentialStore()
        store.set_approval_store_path(store_path)
        realm_id = store.get_or_create_local_fido2_realm_id(seed="deadbeefcafebabe")

        store.register_approval_factor(
            ApprovalFactorRecord(
                credential_id="local_fido2-1",
                user_id="alice",
                method="local_fido2",
                principal_id="ops-key",
                webauthn_rp_id=f"{realm_id}.approver.shisad.invalid",
            )
        )

        envelope = json.loads(store_path.read_text(encoding="utf-8"))
        assert envelope["payload"]["local_fido2_realm_id"] == realm_id

        reloaded = InMemoryCredentialStore()
        reloaded.set_approval_store_path(store_path)
        assert reloaded.get_or_create_local_fido2_realm_id() == realm_id

    def test_local_fido2_realm_id_derives_from_legacy_store_without_metadata(
        self,
        tmp_path,
    ) -> None:
        store_path = tmp_path / "approval-factors.json"
        store_path.write_text(
            json.dumps(
                {
                    "schema_version": "shisad.approval_factor_store.v1",
                    "approval_factors": [
                        {
                            "credential_id": "local_fido2-1",
                            "user_id": "alice",
                            "method": "local_fido2",
                            "principal_id": "ops-key",
                            "webauthn_rp_id": "deadbeefcafebabe.approver.shisad.invalid",
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        store_path.chmod(0o600)

        store = InMemoryCredentialStore()
        store.set_approval_store_path(store_path)

        assert store.approval_state_load_result().legacy is True
        assert store.get_or_create_local_fido2_realm_id() == "deadbeefcafebabe"

    @pytest.mark.parametrize(
        "schema_version",
        [
            "shisad.approval_factor_store.v1",
            "shisad.approval_factor_store.v2",
        ],
    )
    def test_f3_legacy_approval_store_loads_and_migrates_on_mutation(
        self,
        tmp_path,
        schema_version: str,
    ) -> None:  # type: ignore[no-untyped-def]
        store_path = tmp_path / "approval-factors.json"
        legacy_payload = {
            "schema_version": schema_version,
            "approval_factors": [],
            "signer_keys": [],
        }
        store_path.write_text(json.dumps(legacy_payload), encoding="utf-8")
        store_path.chmod(0o600)
        store = InMemoryCredentialStore()

        store.set_approval_store_path(store_path)

        result = store.approval_state_load_result()
        assert result.status == StateLoadStatus.OK
        assert result.legacy is True
        store.register_approval_factor(
            ApprovalFactorRecord(
                credential_id="factor-migrated",
                user_id="alice",
                method="totp",
                principal_id="device",
                secret_b32="GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
            )
        )
        envelope = json.loads(store_path.read_text(encoding="utf-8"))
        assert envelope["version"] == 3
        assert "checksum" in envelope
        assert envelope["payload"]["approval_factors"][0]["credential_id"] == (
            "factor-migrated"
        )

    def test_f3_approval_store_checksum_tamper_is_retained_and_fail_closed(
        self,
        tmp_path,
    ) -> None:
        store_path = tmp_path / "approval-factors.json"
        store = InMemoryCredentialStore()
        store.set_approval_store_path(store_path)
        store.register_approval_factor(
            ApprovalFactorRecord(
                credential_id="factor-1",
                user_id="alice",
                method="totp",
                principal_id="device",
                secret_b32="GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
            )
        )
        envelope = json.loads(store_path.read_text(encoding="utf-8"))
        envelope["payload"]["approval_factors"][0]["principal_id"] = "tampered"
        store_path.write_text(json.dumps(envelope), encoding="utf-8")
        tampered_bytes = store_path.read_bytes()

        restarted = InMemoryCredentialStore()
        restarted.set_approval_store_path(store_path)

        result = restarted.approval_state_load_result()
        assert result.status == StateLoadStatus.CORRUPT
        assert result.reason == "checksum_mismatch"
        with pytest.raises(StatePersistenceDegradedError, match="checksum_mismatch"):
            restarted.get_approval_factor("factor-1")
        with pytest.raises(StatePersistenceDegradedError, match="checksum_mismatch"):
            restarted.get_signer_key("signer-1")
        with pytest.raises(StatePersistenceDegradedError, match="checksum_mismatch"):
            restarted.get_or_create_local_fido2_realm_id()
        assert store_path.read_bytes() == tampered_bytes

    def test_f3_approval_store_future_schema_is_typed_and_retained(self, tmp_path) -> None:
        store_path = tmp_path / "approval-factors.json"
        unsupported_bytes = encode_versioned_json_snapshot(
            {"approval_factors": [], "signer_keys": []},
            version=99,
        )
        store_path.write_bytes(unsupported_bytes)
        store_path.chmod(0o600)
        store = InMemoryCredentialStore()

        store.set_approval_store_path(store_path)

        result = store.approval_state_load_result()
        assert result.status == StateLoadStatus.UNSUPPORTED_SCHEMA
        assert result.schema_version == 99
        with pytest.raises(StatePersistenceDegradedError, match="unsupported_schema"):
            store.list_signer_keys()
        assert store_path.read_bytes() == unsupported_bytes

    def test_f3_checksum_valid_invalid_approval_payload_is_corrupt(self, tmp_path) -> None:
        store_path = tmp_path / "approval-factors.json"
        invalid_bytes = encode_versioned_json_snapshot(
            {
                "approval_factors": [{"credential_id": "incomplete"}],
                "signer_keys": [],
            },
            version=3,
        )
        store_path.write_bytes(invalid_bytes)
        store_path.chmod(0o600)
        store = InMemoryCredentialStore()

        store.set_approval_store_path(store_path)

        result = store.approval_state_load_result()
        assert result.status == StateLoadStatus.CORRUPT
        assert result.reason == "invalid_approval_factors"
        with pytest.raises(StatePersistenceDegradedError, match="invalid_approval_factors"):
            store.list_approval_factors()
        assert store_path.read_bytes() == invalid_bytes

    @pytest.mark.parametrize(
        ("missing_key", "reason"),
        [
            ("approval_factors", "missing_approval_factors"),
            ("signer_keys", "missing_signer_keys"),
        ],
    )
    def test_f3_v3_approval_store_requires_both_authority_collections(
        self,
        tmp_path,
        missing_key: str,
        reason: str,
    ) -> None:  # type: ignore[no-untyped-def]
        store_path = tmp_path / "approval-factors.json"
        payload = {"approval_factors": [], "signer_keys": []}
        payload.pop(missing_key)
        invalid_bytes = encode_versioned_json_snapshot(payload, version=3)
        store_path.write_bytes(invalid_bytes)
        store_path.chmod(0o600)
        store = InMemoryCredentialStore()

        store.set_approval_store_path(store_path)

        result = store.approval_state_load_result()
        assert result.status == StateLoadStatus.CORRUPT
        assert result.reason == reason
        with pytest.raises(StatePersistenceDegradedError, match=reason):
            store.list_approval_factors()
        assert store_path.read_bytes() == invalid_bytes

    @pytest.mark.parametrize("envelope_marker", ["checksum", "payload"])
    def test_f3_legacy_envelope_marker_collision_is_retained_and_fail_closed(
        self,
        tmp_path,
        envelope_marker: str,
    ) -> None:  # type: ignore[no-untyped-def]
        store_path = tmp_path / "approval-factors.json"
        ambiguous = {
            "schema_version": "shisad.approval_factor_store.v2",
            "approval_factors": [],
            "signer_keys": [],
            envelope_marker: {} if envelope_marker == "payload" else "unchecked",
        }
        ambiguous_bytes = json.dumps(ambiguous).encode("utf-8")
        store_path.write_bytes(ambiguous_bytes)
        store_path.chmod(0o600)
        store = InMemoryCredentialStore()

        store.set_approval_store_path(store_path)

        result = store.approval_state_load_result()
        assert result.status == StateLoadStatus.CORRUPT
        assert result.reason == "ambiguous_snapshot_format"
        with pytest.raises(StatePersistenceDegradedError, match="ambiguous_snapshot_format"):
            store.list_signer_keys()
        assert store_path.read_bytes() == ambiguous_bytes

    def test_f3_legacy_v2_requires_signer_collection(self, tmp_path) -> None:
        store_path = tmp_path / "approval-factors.json"
        invalid_bytes = json.dumps(
            {
                "schema_version": "shisad.approval_factor_store.v2",
                "approval_factors": [],
            }
        ).encode("utf-8")
        store_path.write_bytes(invalid_bytes)
        store_path.chmod(0o600)
        store = InMemoryCredentialStore()

        store.set_approval_store_path(store_path)

        result = store.approval_state_load_result()
        assert result.status == StateLoadStatus.CORRUPT
        assert result.reason == "missing_signer_keys"
        assert store_path.read_bytes() == invalid_bytes

    def test_f3_missing_primary_with_corrupt_artifact_is_not_new_authority(
        self,
        tmp_path,
    ) -> None:
        store_path = tmp_path / "approval-factors.json"
        artifact = tmp_path / "approval-factors.json.corrupt.20260715T000000Z"
        artifact.write_bytes(b"retained-corrupt-state")
        store = InMemoryCredentialStore()

        store.set_approval_store_path(store_path)

        result = store.approval_state_load_result()
        assert result.status == StateLoadStatus.CORRUPT
        assert result.reason == "prior_corrupt_artifact_present"
        with pytest.raises(StatePersistenceDegradedError, match="prior_corrupt_artifact"):
            store.register_approval_factor(
                ApprovalFactorRecord(
                    credential_id="must-not-create",
                    user_id="alice",
                    method="totp",
                    principal_id="device",
                    secret_b32="GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
                )
            )
        assert not store_path.exists()
        assert artifact.read_bytes() == b"retained-corrupt-state"

    def test_f3_broken_approval_store_link_is_not_treated_as_missing(self, tmp_path) -> None:
        store_path = tmp_path / "approval-factors.json"
        store_path.symlink_to(tmp_path / "missing-target.json")
        store = InMemoryCredentialStore()

        store.set_approval_store_path(store_path)

        result = store.approval_state_load_result()
        assert result.status == StateLoadStatus.CORRUPT
        assert result.reason == "read_error"
        with pytest.raises(StatePersistenceDegradedError, match="read_error"):
            store.list_approval_factors()
        assert store_path.is_symlink()

    def test_f3_approval_store_reopen_rejects_permissive_mode(self, tmp_path) -> None:
        store_path = tmp_path / "approval-factors.json"
        store = InMemoryCredentialStore()
        store.set_approval_store_path(store_path)
        store.register_approval_factor(
            ApprovalFactorRecord(
                credential_id="factor-1",
                user_id="alice",
                method="totp",
                principal_id="device",
                secret_b32="GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
            )
        )
        retained = store_path.read_bytes()
        store_path.chmod(0o644)

        restarted = InMemoryCredentialStore()
        restarted.set_approval_store_path(store_path)

        result = restarted.approval_state_load_result()
        assert result.status == StateLoadStatus.CORRUPT
        assert result.reason == "read_error"
        with pytest.raises(StatePersistenceDegradedError, match="read_error"):
            restarted.list_approval_factors()
        assert store_path.read_bytes() == retained
        assert stat.S_IMODE(store_path.stat().st_mode) == 0o644

    def test_f3_approval_store_reopen_rejects_foreign_created_file(
        self,
        tmp_path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        store_path = tmp_path / "approval-factors.json"
        store = InMemoryCredentialStore()
        store.set_approval_store_path(store_path)
        store.register_approval_factor(
            ApprovalFactorRecord(
                credential_id="factor-1",
                user_id="alice",
                method="totp",
                principal_id="device",
                secret_b32="GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
            )
        )
        retained = store_path.read_bytes()
        original_fstat = os.fstat

        def _foreign_regular_fstat(fd: int) -> os.stat_result:
            result = original_fstat(fd)
            if not stat.S_ISREG(result.st_mode):
                return result
            values = list(result)
            values[4] = result.st_uid + 1
            return os.stat_result(values)

        monkeypatch.setattr(atomic_state.os, "fstat", _foreign_regular_fstat)

        restarted = InMemoryCredentialStore()
        restarted.set_approval_store_path(store_path)

        result = restarted.approval_state_load_result()
        assert result.status == StateLoadStatus.CORRUPT
        assert result.reason == "read_error"
        assert store_path.read_bytes() == retained

    @pytest.mark.parametrize(
        "fault_stage",
        [
            AtomicWriteStage.TEMP_OPEN,
            AtomicWriteStage.WRITE,
            AtomicWriteStage.FILE_FSYNC,
            AtomicWriteStage.REPLACE,
            AtomicWriteStage.PARENT_FSYNC,
        ],
    )
    def test_f3_approval_factor_publication_fault_is_old_or_new(
        self,
        tmp_path,
        fault_stage: AtomicWriteStage,
    ) -> None:  # type: ignore[no-untyped-def]
        store_path = tmp_path / "state" / "approval-factors.json"
        store = InMemoryCredentialStore()
        store.set_approval_store_path(store_path)
        store.register_approval_factor(
            ApprovalFactorRecord(
                credential_id="factor-old",
                user_id="alice",
                method="totp",
                principal_id="old-device",
                secret_b32="GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
            )
        )

        def _inject(stage: AtomicWriteStage) -> None:
            if stage == fault_stage:
                raise OSError(f"fault:{stage.value}")

        store._approval_state_fault_injector = _inject
        with pytest.raises(AtomicWriteError):
            store.register_approval_factor(
                ApprovalFactorRecord(
                    credential_id="factor-new",
                    user_id="alice",
                    method="totp",
                    principal_id="new-device",
                    secret_b32="GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
                )
            )

        published_new = fault_stage == AtomicWriteStage.PARENT_FSYNC
        if published_new:
            assert store.approval_state_degraded is True
            with pytest.raises(StatePersistenceDegradedError):
                store.list_approval_factors()
        else:
            assert [
                item.credential_id for item in store.list_approval_factors()
            ] == ["factor-old"]
        assert list(store_path.parent.glob(f".{store_path.name}.*.tmp")) == []
        assert not store_path.with_suffix(f"{store_path.suffix}.tmp").exists()

        restarted = InMemoryCredentialStore()
        restarted.set_approval_store_path(store_path)
        assert [
            item.credential_id for item in restarted.list_approval_factors()
        ] == (["factor-old", "factor-new"] if published_new else ["factor-old"])

    @pytest.mark.parametrize(
        "fault_stage",
        [
            AtomicWriteStage.TEMP_OPEN,
            AtomicWriteStage.WRITE,
            AtomicWriteStage.FILE_FSYNC,
            AtomicWriteStage.REPLACE,
            AtomicWriteStage.PARENT_FSYNC,
        ],
    )
    def test_f3_signer_revocation_fault_is_old_or_new(
        self,
        tmp_path,
        fault_stage: AtomicWriteStage,
    ) -> None:  # type: ignore[no-untyped-def]
        store_path = tmp_path / "state" / "approval-factors.json"
        store = InMemoryCredentialStore()
        store.set_approval_store_path(store_path)
        store.register_signer_key(
            SignerKeyRecord(
                credential_id="kms:primary",
                user_id="alice",
                backend="kms",
                principal_id="finance-owner",
                algorithm="ed25519",
                device_type="enterprise",
                public_key_pem="test-public-key",
            )
        )

        def _inject(stage: AtomicWriteStage) -> None:
            if stage == fault_stage:
                raise OSError(f"fault:{stage.value}")

        store._approval_state_fault_injector = _inject
        with pytest.raises(AtomicWriteError):
            store.revoke_signer_key(credential_id="kms:primary")

        published_revocation = fault_stage == AtomicWriteStage.PARENT_FSYNC
        if published_revocation:
            with pytest.raises(StatePersistenceDegradedError):
                store.get_signer_key("kms:primary")
        else:
            current = store.get_signer_key("kms:primary")
            assert current is not None
            assert current.revoked_at is None

        restarted = InMemoryCredentialStore()
        restarted.set_approval_store_path(store_path)
        durable = restarted.get_signer_key("kms:primary")
        assert durable is not None
        assert (durable.revoked_at is not None) is published_revocation

    def test_f3_approval_store_uses_owner_only_modes_under_permissive_umask(
        self,
        tmp_path,
    ) -> None:  # type: ignore[no-untyped-def]
        store_path = tmp_path / "state" / "approval-factors.json"
        store = InMemoryCredentialStore()
        store.set_approval_store_path(store_path)
        previous_umask = os.umask(0)
        try:
            store.register_approval_factor(
                ApprovalFactorRecord(
                    credential_id="factor-1",
                    user_id="alice",
                    method="totp",
                    principal_id="device",
                    secret_b32="GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
                )
            )
        finally:
            os.umask(previous_umask)

        assert stat.S_IMODE(store_path.parent.stat().st_mode) == 0o700
        assert stat.S_IMODE(store_path.stat().st_mode) == 0o600

    def test_f3_factor_serialization_failure_restores_durable_view(
        self,
        tmp_path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:  # type: ignore[no-untyped-def]
        store_path = tmp_path / "state" / "approval-factors.json"
        store = InMemoryCredentialStore()
        store.set_approval_store_path(store_path)
        store.register_approval_factor(
            ApprovalFactorRecord(
                credential_id="factor-old",
                user_id="alice",
                method="totp",
                principal_id="old-device",
                secret_b32="GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
            )
        )

        def _fail_dump(*args: object, **kwargs: object) -> dict[str, object]:
            raise TypeError("injected factor serialization failure")

        monkeypatch.setattr(ApprovalFactorRecord, "model_dump", _fail_dump)

        with pytest.raises(TypeError, match="factor serialization"):
            store.register_approval_factor(
                ApprovalFactorRecord(
                    credential_id="factor-new",
                    user_id="alice",
                    method="totp",
                    principal_id="new-device",
                    secret_b32="GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
                )
            )

        assert [
            item.credential_id for item in store.list_approval_factors()
        ] == ["factor-old"]

    def test_f3_signer_serialization_failure_restores_durable_view(
        self,
        tmp_path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:  # type: ignore[no-untyped-def]
        store_path = tmp_path / "state" / "approval-factors.json"
        store = InMemoryCredentialStore()
        store.set_approval_store_path(store_path)
        store.register_signer_key(
            SignerKeyRecord(
                credential_id="kms:primary",
                user_id="alice",
                backend="kms",
                principal_id="finance-owner",
                algorithm="ed25519",
                device_type="enterprise",
                public_key_pem="test-public-key",
            )
        )

        def _fail_dump(*args: object, **kwargs: object) -> dict[str, object]:
            raise TypeError("injected signer serialization failure")

        monkeypatch.setattr(SignerKeyRecord, "model_dump", _fail_dump)

        with pytest.raises(TypeError, match="signer serialization"):
            store.revoke_signer_key(credential_id="kms:primary")

        current = store.get_signer_key("kms:primary")
        assert current is not None
        assert current.revoked_at is None

    def test_f3_target_validation_error_restores_approval_mutation(
        self,
        tmp_path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:  # type: ignore[no-untyped-def]
        store_path = tmp_path / "state" / "approval-factors.json"
        store = InMemoryCredentialStore()
        store.set_approval_store_path(store_path)
        store.register_approval_factor(
            ApprovalFactorRecord(
                credential_id="factor-old",
                user_id="alice",
                method="totp",
                principal_id="old-device",
                secret_b32="GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
            )
        )
        real_lstat = Path.lstat

        def _deny_target(path: Path) -> os.stat_result:
            if path == store_path:
                raise PermissionError("injected approval target lstat denial")
            return real_lstat(path)

        monkeypatch.setattr(Path, "lstat", _deny_target)

        with pytest.raises(AtomicWriteError) as raised:
            store.register_approval_factor(
                ApprovalFactorRecord(
                    credential_id="factor-new",
                    user_id="alice",
                    method="totp",
                    principal_id="new-device",
                    secret_b32="GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
                )
            )

        assert raised.value.stage == AtomicWriteStage.TARGET_VALIDATE
        assert raised.value.publication_may_have_committed is False
        assert [
            item.credential_id for item in store.list_approval_factors()
        ] == ["factor-old"]
