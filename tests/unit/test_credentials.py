"""M0.T9, T11-T13: Credential broker tests."""

from __future__ import annotations

import json
import os
import stat
from datetime import UTC, datetime
from pathlib import Path

import pytest

from shisad.core.atomic_state import (
    AtomicWriteError,
    AtomicWriteStage,
    StatePersistenceDegradedError,
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

        reloaded = InMemoryCredentialStore()
        reloaded.set_approval_store_path(store_path)
        entries = reloaded.list_approval_factors(user_id="alice", method="totp")

        assert len(entries) == 1
        assert entries[0].credential_id == "totp-1"
        assert entries[0].principal_id == "ops-laptop"
        assert entries[0].recovery_codes[0].code_hash == "recovery-hash"

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

    def test_approval_factor_store_quarantines_malformed_json(self, tmp_path) -> None:
        store_path = tmp_path / "approval-factors.json"
        store_path.write_text("{not-json", encoding="utf-8")

        store = InMemoryCredentialStore()
        store.set_approval_store_path(store_path)

        assert store.list_approval_factors() == []
        assert not store_path.exists()
        quarantined = list(tmp_path.glob("approval-factors.json.corrupt.*"))
        assert len(quarantined) == 1

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

        payload = json.loads(store_path.read_text(encoding="utf-8"))
        assert payload["local_fido2_realm_id"] == realm_id

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

        store = InMemoryCredentialStore()
        store.set_approval_store_path(store_path)

        assert store.get_or_create_local_fido2_realm_id() == "deadbeefcafebabe"

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
