"""Unit coverage for the local approver helper service."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

import click
import pytest

from shisad.approver.main import ApproverService, _build_socket_endpoint, _render_prompt


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


class _FakeProcess:
    def __init__(self, *, stderr: bytes = b"", returncode: int | None = None) -> None:
        self.stderr = stderr
        self.terminated = False
        self.killed = False
        self._returncode = returncode

    def communicate(self, timeout: float | None = None) -> tuple[bytes, bytes]:
        _ = timeout
        return b"", self.stderr

    def poll(self) -> int | None:
        return self._returncode

    def terminate(self) -> None:
        self.terminated = True
        self._returncode = 0 if self._returncode is None else self._returncode

    def kill(self) -> None:
        self.killed = True
        self._returncode = -9

    def wait(self, timeout: float | None = None) -> int:
        _ = timeout
        self._returncode = 0 if self._returncode is None else self._returncode
        return self._returncode


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


def test_approver_service_defaults_principal_label_to_helper_username(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
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
                    "principal_id": "helper-laptop",
                    "credential_id": "local_fido2-1",
                }
            ],
        },
    )
    monkeypatch.setattr("shisad.approver.main.getpass.getuser", lambda: "helper-laptop")

    asyncio.run(service.enroll(user_id="alice"))

    assert service.calls[0] == (
        "2fa.register_begin",
        {"method": "local_fido2", "user_id": "alice", "name": "helper-laptop"},
    )


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
                            "allowed_channel_principals": ["alice"],
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
                "principal_id": "alice",
            },
        ),
    ]


def test_f15_approver_service_keeps_available_helper_row_for_cli_origin() -> None:
    service = _HarnessService(
        device=_FakeDevice(),
        responses={
            "action.pending": [
                {
                    "actions": [
                        {
                            "confirmation_id": "c-1",
                            "decision_nonce": "nonce-1",
                            "selected_backend_method": "local_fido2",
                            "channel_capability": {
                                "backend_available": True,
                                "can_approve": False,
                            },
                        }
                    ]
                }
            ],
        },
    )

    rows = asyncio.run(service.pending_local_fido2_actions())

    assert [row["confirmation_id"] for row in rows] == ["c-1"]


def test_approver_service_skips_unavailable_local_fido2_action() -> None:
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
                            "channel_capability": {
                                "backend_available": False,
                                "can_approve": False,
                            },
                        }
                    ]
                }
            ],
        },
    )

    def fail_prompt(_row: dict[str, Any]) -> bool:
        raise AssertionError("unavailable local FIDO2 rows must not be prompted")

    result = asyncio.run(service.process_pending_once(prompt=fail_prompt))

    assert result == {"processed": 0, "approved": 0, "rejected": 0}
    assert device.assertion_calls == []
    assert service.calls == [
        ("action.pending", {"status": "pending", "limit": 100, "include_ui": True}),
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
                            "allowed_channel_principals": ["alice"],
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
                "principal_id": "alice",
            },
        ),
    ]


def test_build_socket_endpoint_reports_ssh_forward_failures(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fake_process = _FakeProcess(stderr=b"permission denied", returncode=255)

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


def test_build_socket_endpoint_local_mode_preserves_daemon_socket_path(tmp_path: Path) -> None:
    socket_path = tmp_path / "daemon.sock"
    socket_path.write_text("daemon-socket", encoding="utf-8")

    endpoint = _build_socket_endpoint(
        socket_path=socket_path,
        ssh_target="",
        remote_socket=None,
        ssh_command="ssh",
        ssh_timeout_seconds=1.0,
    )
    endpoint.close()

    assert socket_path.exists()


def test_build_socket_endpoint_uses_private_dir_and_ssh_hardening(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fake_process = _FakeProcess()
    launched: list[list[str]] = []
    launched_envs: list[dict[str, str]] = []
    private_dir = tmp_path / "private-socket-dir"
    private_dir.mkdir(mode=0o700)

    def _fake_popen(command: list[str], *args: Any, **kwargs: Any) -> _FakeProcess:
        _ = args
        launched.append(list(command))
        launched_envs.append(dict(kwargs["env"]))
        return fake_process

    def _fake_wait_for_socket(path: Path, *, timeout_seconds: float = 5.0) -> None:
        _ = timeout_seconds
        path.write_text("socket", encoding="utf-8")

    monkeypatch.setattr("shisad.approver.main.subprocess.Popen", _fake_popen)
    monkeypatch.setattr("shisad.approver.main._wait_for_socket", _fake_wait_for_socket)
    monkeypatch.setattr("shisad.approver.main.tempfile.mkdtemp", lambda prefix="": str(private_dir))
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("SSH_AUTH_SOCK", str(tmp_path / "agent.sock"))
    monkeypatch.setenv("OPENAI_API_KEY", "must-not-cross")
    monkeypatch.setenv("SSH_ASKPASS", "/tmp/poison-askpass")
    monkeypatch.setenv("GIT_SSH_COMMAND", "/tmp/poison-git-ssh")

    endpoint = _build_socket_endpoint(
        socket_path=None,
        ssh_target="user@example.com",
        remote_socket=tmp_path / "remote.sock",
        ssh_command="ssh",
        ssh_timeout_seconds=1.0,
    )
    try:
        assert endpoint.socket_path.parent == private_dir
        assert launched == [
            [
                "ssh",
                "-NT",
                "-o",
                "ExitOnForwardFailure=yes",
                "-o",
                "StreamLocalBindMask=0177",
                "-L",
                f"{endpoint.socket_path}:{tmp_path / 'remote.sock'}",
                "user@example.com",
            ]
        ]
        assert launched_envs[0]["HOME"] == str(tmp_path / "home")
        assert launched_envs[0]["SSH_AUTH_SOCK"] == str(tmp_path / "agent.sock")
        assert "PATH" in launched_envs[0]
        assert "OPENAI_API_KEY" not in launched_envs[0]
        assert "SSH_ASKPASS" not in launched_envs[0]
        assert "GIT_SSH_COMMAND" not in launched_envs[0]
    finally:
        endpoint.close()

    assert fake_process.terminated is True
    assert not private_dir.exists()


def test_render_prompt_sanitizes_terminal_sequences(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr("shisad.approver.main.click.confirm", lambda *args, **kwargs: False)

    approved = _render_prompt(
        {
            "confirmation_id": "c-\x1b[31m1",
            "tool_name": "shell.exec\x1b]2;bad\x07",
            "required_level": "bound_approval",
            "safe_preview": "line1\rline2\x1b[31m",
            "warnings": ["warn\x1b[31m", "two\twords"],
        }
    )

    assert approved is False
    output = capsys.readouterr().out
    assert "\x1b" not in output
    assert "[c-1] shell.exec" in output
    assert "line1\nline2" in output
    assert "warning: warn" in output
    assert "warning: two words" in output
