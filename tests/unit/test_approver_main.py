"""Unit coverage for the local approver helper service."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

import click
import pytest

from shisad.approver.main import ApproverService, _build_socket_endpoint


class _FakeDevice:
    def __init__(self) -> None:
        self.registration_calls: list[tuple[dict[str, Any], str]] = []
        self.assertion_calls: list[tuple[dict[str, Any], str]] = []

    def register_credential(
        self,
        *,
        public_key_options: dict[str, Any],
        origin: str,
    ) -> dict[str, Any]:
        self.registration_calls.append((public_key_options, origin))
        return {"id": "cred-1"}

    def get_assertion(
        self,
        *,
        public_key_options: dict[str, Any],
        origin: str,
    ) -> dict[str, Any]:
        self.assertion_calls.append((public_key_options, origin))
        return {"id": "assertion-1"}


class _HarnessService(ApproverService):
    def __init__(
        self,
        *,
        responses: dict[str, list[dict[str, Any]]],
        device: _FakeDevice,
    ) -> None:
        super().__init__(socket_path=Path("/tmp/approver.sock"), device=device)
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self._responses = {key: list(value) for key, value in responses.items()}

    async def _call(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        self.calls.append((method, params))
        payloads = self._responses[method]
        return payloads.pop(0)


def test_approver_service_enrolls_local_fido2_factor() -> None:
    device = _FakeDevice()
    service = _HarnessService(
        device=device,
        responses={
            "2fa.register_begin": [
                {
                    "started": True,
                    "enrollment_id": "enroll-1",
                    "helper_origin": "https://deadbeef.approver.shisad.invalid",
                    "helper_public_key": {"challenge": "abc"},
                }
            ],
            "2fa.register_confirm": [
                {
                    "registered": True,
                    "user_id": "alice",
                    "method": "local_fido2",
                    "principal_id": "ops-key",
                    "credential_id": "local_fido2-1",
                }
            ],
        },
    )

    result = asyncio.run(service.enroll(user_id="alice", name="ops-key"))

    assert result["credential_id"] == "local_fido2-1"
    assert device.registration_calls == [
        ({"challenge": "abc"}, "https://deadbeef.approver.shisad.invalid")
    ]
    assert service.calls == [
        (
            "2fa.register_begin",
            {"method": "local_fido2", "user_id": "alice", "name": "ops-key"},
        ),
        ("2fa.register_confirm", {"enrollment_id": "enroll-1", "proof": {"id": "cred-1"}}),
    ]


def test_approver_service_process_pending_once_confirms_local_fido2_action() -> None:
    device = _FakeDevice()
    service = _HarnessService(
        device=device,
        responses={
            "action.pending": [
                {
                    "actions": [
                        {
                            "confirmation_id": "c-1",
                            "decision_nonce": "nonce-1",
                            "selected_backend_method": "local_fido2",
                            "helper_origin": "https://deadbeef.approver.shisad.invalid",
                            "helper_public_key": {"challenge": "xyz"},
                        }
                    ]
                }
            ],
            "action.confirm": [
                {
                    "confirmed": True,
                    "confirmation_id": "c-1",
                }
            ],
        },
    )

    result = asyncio.run(service.process_pending_once(prompt=lambda _row: True))

    assert result == {"processed": 1, "approved": 1, "rejected": 0}
    assert device.assertion_calls == [
        ({"challenge": "xyz"}, "https://deadbeef.approver.shisad.invalid")
    ]
    assert service.calls == [
        ("action.pending", {"status": "pending", "limit": 100, "include_ui": True}),
        (
            "action.confirm",
            {
                "confirmation_id": "c-1",
                "decision_nonce": "nonce-1",
                "approval_method": "local_fido2",
                "proof": {"id": "assertion-1"},
            },
        ),
    ]


def test_approver_service_process_pending_once_rejects_when_prompt_declines() -> None:
    device = _FakeDevice()
    service = _HarnessService(
        device=device,
        responses={
            "action.pending": [
                {
                    "actions": [
                        {
                            "confirmation_id": "c-1",
                            "decision_nonce": "nonce-1",
                            "selected_backend_method": "local_fido2",
                        }
                    ]
                }
            ],
            "action.reject": [
                {
                    "rejected": True,
                    "confirmation_id": "c-1",
                }
            ],
        },
    )

    result = asyncio.run(service.process_pending_once(prompt=lambda _row: False))

    assert result == {"processed": 1, "approved": 0, "rejected": 1}
    assert device.assertion_calls == []
    assert service.calls == [
        ("action.pending", {"status": "pending", "limit": 100, "include_ui": True}),
        (
            "action.reject",
            {
                "confirmation_id": "c-1",
                "decision_nonce": "nonce-1",
                "reason": "local_helper_reject",
            },
        ),
    ]


def test_build_socket_endpoint_reports_ssh_forward_failures(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    class _FakeProcess:
        def __init__(self) -> None:
            self.terminated = False
            self.killed = False
            self._returncode: int | None = None

        def communicate(self, timeout: float | None = None) -> tuple[bytes, bytes]:
            _ = timeout
            return b"", b"permission denied"

        def poll(self) -> int | None:
            return self._returncode

        def terminate(self) -> None:
            self.terminated = True
            self._returncode = 255

        def kill(self) -> None:
            self.killed = True
            self._returncode = -9

    fake_process = _FakeProcess()

    def _fake_popen(*args: Any, **kwargs: Any) -> _FakeProcess:
        _ = args, kwargs
        return fake_process

    def _raise_timeout(path: Path, *, timeout_seconds: float = 5.0) -> None:
        _ = path, timeout_seconds
        raise RuntimeError("timeout")

    monkeypatch.setattr("shisad.approver.main.subprocess.Popen", _fake_popen)
    monkeypatch.setattr("shisad.approver.main._wait_for_socket", _raise_timeout)

    with pytest.raises(click.ClickException, match="SSH socket forward failed: permission denied"):
        _build_socket_endpoint(
            socket_path=tmp_path / "local.sock",
            ssh_target="user@example.com",
            remote_socket=tmp_path / "remote.sock",
            ssh_command="ssh",
            ssh_timeout_seconds=1.0,
        )

    assert fake_process.terminated is True
    assert fake_process.killed is False
