"""O2A credential-reference registry and backend contracts."""

from __future__ import annotations

import json
import stat
from pathlib import Path

import pytest
from pydantic import ValidationError

import shisad.security.credential_refs as credential_refs_module
from shisad.security.credential_refs import (
    CredentialBackend,
    CredentialReference,
    CredentialReferenceError,
    CredentialReferenceStore,
    CredentialReferenceUnavailable,
)


class FakeKeyring:
    def __init__(self, *, fail: bool = False) -> None:
        self.values: dict[tuple[str, str], str] = {}
        self.fail = fail

    def get_password(self, service_name: str, username: str) -> str | None:
        if self.fail:
            raise RuntimeError("host keyring detail must stay private")
        return self.values.get((service_name, username))

    def set_password(self, service_name: str, username: str, password: str) -> None:
        if self.fail:
            raise RuntimeError("host keyring detail must stay private")
        self.values[(service_name, username)] = password

    def delete_password(self, service_name: str, username: str) -> None:
        if self.fail:
            raise RuntimeError("host keyring detail must stay private")
        self.values.pop((service_name, username), None)


def _store(
    tmp_path: Path,
    *,
    environ: dict[str, str] | None = None,
    keyring: FakeKeyring | None = None,
) -> CredentialReferenceStore:
    return CredentialReferenceStore(
        registry_path=tmp_path / "state" / "credential-references.json",
        secret_root=tmp_path / "state" / "credentials.d",
        environ={} if environ is None else environ,
        keyring_backend=keyring,
    )


def test_o2a_versioned_reference_rejects_unknown_or_unsafe_metadata() -> None:
    valid = CredentialReference(
        name="model.primary",
        backend=CredentialBackend.ENV,
        locator="OPENAI_API_KEY",
    )

    assert valid.schema_version == "shisad.credential_reference.v1"
    with pytest.raises(ValidationError):
        CredentialReference.model_validate(
            {
                "schema_version": "shisad.credential_reference.v2",
                "name": "model.primary",
                "backend": "env",
                "locator": "OPENAI_API_KEY",
            }
        )
    for unsafe_name in ("", "Model.Primary", "../secret", "model\x1b[31m", "a" * 129):
        with pytest.raises(ValidationError):
            CredentialReference(
                name=unsafe_name,
                backend=CredentialBackend.ENV,
                locator="OPENAI_API_KEY",
            )
    with pytest.raises(ValidationError):
        CredentialReference(
            name="model.primary",
            backend=CredentialBackend.ENV,
            locator="NOT-AN-ENV-VAR",
        )
    for backend, locator in (
        (CredentialBackend.ENV, ""),
        (CredentialBackend.KEYRING, "keyring\nservice"),
        (CredentialBackend.FILE, "different.name"),
    ):
        with pytest.raises(ValidationError):
            CredentialReference(
                name="model.primary",
                backend=backend,
                locator=locator,
            )


def test_o2a_env_reference_round_trip_status_resolve_and_remove_is_redacted(
    tmp_path: Path,
) -> None:
    secret = "ambient-provider-secret"
    environ = {"OPENAI_API_KEY": secret}
    store = _store(tmp_path, environ=environ)

    created = store.set_reference(
        name="model.primary",
        backend=CredentialBackend.ENV,
        locator="OPENAI_API_KEY",
    )

    assert created.configured is True
    assert created.available is True
    assert created.backend is CredentialBackend.ENV
    assert store.resolve("model.primary") == secret
    raw = (tmp_path / "state" / "credential-references.json").read_text(encoding="utf-8")
    assert "OPENAI_API_KEY" in raw
    assert secret not in raw
    assert store.list_status() == [created]

    removed = store.remove("model.primary")

    assert removed.configured is False
    assert removed.available is False
    assert environ["OPENAI_API_KEY"] == secret
    assert store.status("model.primary").reason == "credential_reference_not_configured"


def test_o2a_env_registration_rejects_a_secret_value(tmp_path: Path) -> None:
    with pytest.raises(CredentialReferenceError) as exc:
        _store(tmp_path).set_reference(
            name="model.primary",
            backend=CredentialBackend.ENV,
            locator="OPENAI_API_KEY",
            secret="must-not-persist",
        )

    assert exc.value.reason == "env_backend_rejects_secret_value"
    assert not (tmp_path / "state" / "credential-references.json").exists()


def test_o2a_keyring_has_no_file_fallback_and_never_serializes_secret(tmp_path: Path) -> None:
    keyring = FakeKeyring()
    store = _store(tmp_path, keyring=keyring)
    secret = "keyring-only-secret"

    status = store.set_reference(
        name="model.primary",
        backend=CredentialBackend.KEYRING,
        locator="shisad-test",
        secret=secret,
    )

    assert status.available is True
    assert store.resolve("model.primary") == secret
    assert secret not in (tmp_path / "state" / "credential-references.json").read_text(
        encoding="utf-8"
    )
    assert not (tmp_path / "state" / "credentials.d").exists()

    removed = store.remove("model.primary")

    assert removed.configured is False
    assert keyring.values == {}


def test_o2a_keyring_remove_failure_retains_truthful_metadata(tmp_path: Path) -> None:
    keyring = FakeKeyring()
    store = _store(tmp_path, keyring=keyring)
    store.set_reference(
        name="model.primary",
        backend=CredentialBackend.KEYRING,
        locator="shisad-test",
        secret="keyring-secret",
    )
    keyring.fail = True

    with pytest.raises(CredentialReferenceError) as exc:
        store.remove("model.primary")

    assert exc.value.reason == "credential_backend_remove_failed"
    status = store.status("model.primary")
    assert status.configured is True
    assert status.available is False
    assert status.reason == "keyring_backend_unavailable"


def test_o2a_keyring_failure_is_bounded_and_does_not_publish_metadata(tmp_path: Path) -> None:
    store = _store(tmp_path, keyring=FakeKeyring(fail=True))

    with pytest.raises(CredentialReferenceError) as exc:
        store.set_reference(
            name="model.primary",
            backend=CredentialBackend.KEYRING,
            locator="shisad-test",
            secret="do-not-leak",
        )

    assert exc.value.reason == "keyring_backend_unavailable"
    assert "host keyring detail" not in str(exc.value)
    assert not (tmp_path / "state" / "credential-references.json").exists()
    assert not (tmp_path / "state" / "credentials.d").exists()


def test_o2a_missing_keyring_dependency_is_actionable_without_host_access(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _missing(_name: str) -> object:
        raise ModuleNotFoundError("keyring")

    monkeypatch.setattr(credential_refs_module.importlib, "import_module", _missing)

    with pytest.raises(CredentialReferenceError) as exc:
        _store(tmp_path).set_reference(
            name="model.primary",
            backend=CredentialBackend.KEYRING,
            locator="shisad",
            secret="do-not-persist",
        )

    assert exc.value.reason == "keyring_backend_unavailable"
    assert not (tmp_path / "state" / "credential-references.json").exists()


@pytest.mark.skipif(not hasattr(stat, "S_IMODE"), reason="POSIX mode inspection unavailable")
def test_o2a_file_backend_is_contained_owner_only_and_removable(tmp_path: Path) -> None:
    store = _store(tmp_path)
    secret = "plaintext-but-owner-only"

    created = store.set_reference(
        name="model.primary",
        backend=CredentialBackend.FILE,
        secret=secret,
    )

    registry = tmp_path / "state" / "credential-references.json"
    secret_root = tmp_path / "state" / "credentials.d"
    secret_file = secret_root / "model.primary"
    assert created.available is True
    assert store.resolve("model.primary") == secret
    assert secret_file.read_text(encoding="utf-8") == secret
    assert stat.S_IMODE(registry.stat().st_mode) == 0o600
    assert stat.S_IMODE(secret_file.stat().st_mode) == 0o600
    assert stat.S_IMODE(secret_root.stat().st_mode) == 0o700
    assert secret not in registry.read_text(encoding="utf-8")

    store.remove("model.primary")

    assert not secret_file.exists()
    assert store.status("model.primary").configured is False


def test_o2a_file_backend_rejects_symlink_destination_without_mutation(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.write_text("keep", encoding="utf-8")
    secret_root = tmp_path / "state" / "credentials.d"
    secret_root.mkdir(parents=True)
    (secret_root / "model.primary").symlink_to(outside)
    store = _store(tmp_path)

    with pytest.raises(CredentialReferenceError) as exc:
        store.set_reference(
            name="model.primary",
            backend=CredentialBackend.FILE,
            secret="replacement",
        )

    assert exc.value.reason == "credential_file_unsafe"
    assert outside.read_text(encoding="utf-8") == "keep"
    assert not (tmp_path / "state" / "credential-references.json").exists()


def test_o2a_replace_requires_explicit_authority(tmp_path: Path) -> None:
    store = _store(tmp_path, environ={"OPENAI_API_KEY": "one", "SHISA_API_KEY": "two"})
    store.set_reference(
        name="model.primary",
        backend=CredentialBackend.ENV,
        locator="OPENAI_API_KEY",
    )

    with pytest.raises(CredentialReferenceError) as exc:
        store.set_reference(
            name="model.primary",
            backend=CredentialBackend.ENV,
            locator="SHISA_API_KEY",
        )

    assert exc.value.reason == "credential_reference_exists"
    replaced = store.set_reference(
        name="model.primary",
        backend=CredentialBackend.ENV,
        locator="SHISA_API_KEY",
        replace=True,
    )
    assert replaced.locator == "SHISA_API_KEY"
    assert store.resolve("model.primary") == "two"


def test_o2a_backend_and_keyring_locator_changes_require_remove(tmp_path: Path) -> None:
    keyring = FakeKeyring()
    store = _store(tmp_path, keyring=keyring)
    store.set_reference(
        name="model.primary",
        backend=CredentialBackend.KEYRING,
        locator="service-one",
        secret="one",
    )

    with pytest.raises(CredentialReferenceError) as backend_exc:
        store.set_reference(
            name="model.primary",
            backend=CredentialBackend.FILE,
            secret="two",
            replace=True,
        )
    with pytest.raises(CredentialReferenceError) as locator_exc:
        store.set_reference(
            name="model.primary",
            backend=CredentialBackend.KEYRING,
            locator="service-two",
            secret="two",
            replace=True,
        )

    assert backend_exc.value.reason == "credential_backend_change_requires_remove"
    assert locator_exc.value.reason == "credential_locator_change_requires_remove"
    assert keyring.values == {("service-one", "model.primary"): "one"}


def test_o2a_corrupt_registry_fails_bounded_without_backend_access(tmp_path: Path) -> None:
    registry = tmp_path / "state" / "credential-references.json"
    registry.parent.mkdir(parents=True)
    registry.write_text(
        json.dumps({"schema": 99, "sha256": "unused", "payload": {}}),
        encoding="utf-8",
    )
    registry.chmod(0o600)
    store = _store(tmp_path, environ={"OPENAI_API_KEY": "do-not-read"})

    with pytest.raises(CredentialReferenceError) as exc:
        store.status("model.primary")

    assert exc.value.reason == "credential_registry_unsupported"
    assert "do-not-read" not in str(exc.value)


def test_o2a_missing_backend_value_raises_redacted_unavailable(tmp_path: Path) -> None:
    store = _store(tmp_path)
    store.set_reference(
        name="model.primary",
        backend=CredentialBackend.ENV,
        locator="OPENAI_API_KEY",
    )

    with pytest.raises(CredentialReferenceUnavailable) as exc:
        store.resolve("model.primary")

    assert exc.value.reason == "credential_value_unavailable"


def test_o2a_unconfigured_resolve_and_remove_are_idempotent(tmp_path: Path) -> None:
    store = _store(tmp_path)

    with pytest.raises(CredentialReferenceUnavailable) as exc:
        store.resolve("model.primary")
    removed = store.remove("model.primary")

    assert exc.value.reason == "credential_reference_not_configured"
    assert removed.configured is False
    assert removed.reason == "credential_reference_not_configured"
