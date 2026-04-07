"""Integration coverage for daemon-backed 2FA enrollment management."""

from __future__ import annotations

import asyncio
import json
import socket
import urllib.error
import urllib.request
from contextlib import suppress
from pathlib import Path
from typing import Any

import pytest

from shisad.core.api.transport import ControlClient
from shisad.core.approval import generate_totp_code
from shisad.core.config import DaemonConfig
from shisad.daemon.runner import run_daemon
from tests.helpers.webauthn import make_registration_payload


async def _wait_for_socket(path: Path, timeout: float = 5.0) -> None:
    end = asyncio.get_running_loop().time() + timeout
    while asyncio.get_running_loop().time() < end:
        if path.exists():
            return
        await asyncio.sleep(0.01)
    raise TimeoutError(f"Timed out waiting for socket {path}")


def _configure_model_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SHISAD_MODEL_BASE_URL", "https://api.example.com/v1")
    monkeypatch.setenv("SHISAD_MODEL_PLANNER_BASE_URL", "https://planner.example.com/v1")
    monkeypatch.setenv("SHISAD_MODEL_EMBEDDINGS_BASE_URL", "https://embed.example.com/v1")
    monkeypatch.setenv("SHISAD_MODEL_MONITOR_BASE_URL", "https://monitor.example.com/v1")


async def _start_daemon(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    config_overrides: dict[str, Any] | None = None,
) -> tuple[asyncio.Task[None], ControlClient]:
    _configure_model_env(monkeypatch)
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text('version: "1"\ndefault_require_confirmation: false\n', encoding="utf-8")
    config_kwargs: dict[str, Any] = {
        "data_dir": tmp_path / "data",
        "socket_path": tmp_path / "control.sock",
        "policy_path": policy_path,
        "log_level": "INFO",
    }
    if config_overrides:
        config_kwargs.update(config_overrides)
    config = DaemonConfig(**config_kwargs)
    daemon_task = asyncio.create_task(run_daemon(config))
    client = ControlClient(config.socket_path)
    await _wait_for_socket(config.socket_path)
    await client.connect()
    return daemon_task, client


async def _shutdown_daemon(daemon_task: asyncio.Task[None], client: ControlClient) -> None:
    with suppress(Exception):
        await client.call("daemon.shutdown")
    await client.close()
    await asyncio.wait_for(daemon_task, timeout=3)


def _reserve_local_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _approval_json_url(url: str) -> str:
    separator = "&" if "?" in url else "?"
    return f"{url}{separator}format=json"


def _http_get_json(url: str) -> tuple[int, dict[str, Any]]:
    request = urllib.request.Request(_approval_json_url(url), method="GET")
    try:
        with urllib.request.urlopen(request, timeout=5.0) as response:
            return response.status, json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8")
        return exc.code, json.loads(body) if body else {}


def _http_post_json(url: str, payload: dict[str, Any]) -> tuple[int, dict[str, Any]]:
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=5.0) as response:
            return response.status, json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8")
        return exc.code, json.loads(body) if body else {}


@pytest.mark.asyncio
async def test_two_factor_register_list_revoke_persists_across_restart(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    daemon_task, client = await _start_daemon(tmp_path, monkeypatch)
    try:
        started = await client.call(
            "2fa.register_begin",
            {"method": "totp", "user_id": "alice", "name": "ops-laptop"},
        )
        assert started["started"] is True
        confirm = await client.call(
            "2fa.register_confirm",
            {
                "enrollment_id": started["enrollment_id"],
                "verify_code": generate_totp_code(str(started["secret"])),
            },
        )
        assert confirm["registered"] is True
        listed = await client.call("2fa.list", {"user_id": "alice"})
        assert listed["count"] == 1
        assert listed["entries"][0]["principal_id"] == "ops-laptop"
        assert listed["entries"][0]["credential_id"] == confirm["credential_id"]
        enrolled_events = await client.call(
            "audit.query",
            {"event_type": "TwoFactorEnrolled", "limit": 10},
        )
        assert any(
            str(event.get("data", {}).get("credential_id", "")) == confirm["credential_id"]
            and str(event.get("data", {}).get("principal_id", "")) == "ops-laptop"
            for event in enrolled_events.get("events", [])
        )
    finally:
        await _shutdown_daemon(daemon_task, client)

    daemon_task, client = await _start_daemon(tmp_path, monkeypatch)
    try:
        listed = await client.call("2fa.list", {"user_id": "alice"})
        assert listed["count"] == 1
        revoke = await client.call(
            "2fa.revoke",
            {
                "method": "totp",
                "user_id": "alice",
                "credential_id": listed["entries"][0]["credential_id"],
            },
        )
        assert revoke["revoked"] is True
        assert revoke["removed"] == 1
        listed_after = await client.call("2fa.list", {"user_id": "alice"})
        assert listed_after["count"] == 0
        revoked_events = await client.call(
            "audit.query",
            {"event_type": "TwoFactorRevoked", "limit": 10},
        )
        assert any(
            str(event.get("data", {}).get("credential_id", ""))
            == listed["entries"][0]["credential_id"]
            and str(event.get("data", {}).get("principal_id", "")) == "ops-laptop"
            for event in revoked_events.get("events", [])
        )
    finally:
        await _shutdown_daemon(daemon_task, client)


@pytest.mark.asyncio
async def test_local_fido2_register_list_revoke_persists_across_restart(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    daemon_task, client = await _start_daemon(tmp_path, monkeypatch)
    try:
        started = await client.call(
            "2fa.register_begin",
            {"method": "local_fido2", "user_id": "alice", "name": "ops-key"},
        )
        assert started["started"] is True
        _credential, registration_payload = make_registration_payload(
            public_key_options=started["helper_public_key"],
            origin=started["helper_origin"],
            rp_id=started["helper_rp_id"],
        )
        confirm = await client.call(
            "2fa.register_confirm",
            {
                "enrollment_id": started["enrollment_id"],
                "proof": registration_payload,
            },
        )
        assert confirm["registered"] is True
        listed = await client.call("2fa.list", {"user_id": "alice", "method": "local_fido2"})
        assert listed["count"] == 1
        assert listed["entries"][0]["principal_id"] == "ops-key"
        assert listed["entries"][0]["credential_id"] == confirm["credential_id"]
        enrolled_events = await client.call(
            "audit.query",
            {"event_type": "TwoFactorEnrolled", "limit": 10},
        )
        assert any(
            str(event.get("data", {}).get("credential_id", "")) == confirm["credential_id"]
            and str(event.get("data", {}).get("method", "")) == "local_fido2"
            and str(event.get("data", {}).get("principal_id", "")) == "ops-key"
            for event in enrolled_events.get("events", [])
        )
    finally:
        await _shutdown_daemon(daemon_task, client)

    daemon_task, client = await _start_daemon(tmp_path, monkeypatch)
    try:
        listed = await client.call("2fa.list", {"user_id": "alice", "method": "local_fido2"})
        assert listed["count"] == 1
        revoke = await client.call(
            "2fa.revoke",
            {
                "method": "local_fido2",
                "user_id": "alice",
                "credential_id": listed["entries"][0]["credential_id"],
            },
        )
        assert revoke["revoked"] is True
        assert revoke["removed"] == 1
        listed_after = await client.call(
            "2fa.list",
            {"user_id": "alice", "method": "local_fido2"},
        )
        assert listed_after["count"] == 0
        revoked_events = await client.call(
            "audit.query",
            {"event_type": "TwoFactorRevoked", "limit": 10},
        )
        assert any(
            str(event.get("data", {}).get("credential_id", ""))
            == listed["entries"][0]["credential_id"]
            and str(event.get("data", {}).get("method", "")) == "local_fido2"
            and str(event.get("data", {}).get("principal_id", "")) == "ops-key"
            for event in revoked_events.get("events", [])
        )
    finally:
        await _shutdown_daemon(daemon_task, client)


@pytest.mark.asyncio
async def test_two_factor_daemon_starts_with_malformed_persisted_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    data_dir = tmp_path / "data"
    data_dir.mkdir(parents=True, exist_ok=True)
    (data_dir / "approval-factors.json").write_text("{not-json", encoding="utf-8")
    (data_dir / "confirmation_lockouts.json").write_text("{not-json", encoding="utf-8")

    daemon_task, client = await _start_daemon(tmp_path, monkeypatch)
    try:
        listed = await client.call("2fa.list", {"user_id": "alice"})
        assert listed["count"] == 0
    finally:
        await _shutdown_daemon(daemon_task, client)

    assert not (data_dir / "approval-factors.json").exists()
    assert not (data_dir / "confirmation_lockouts.json").exists()
    assert list(data_dir.glob("approval-factors.json.corrupt.*"))
    assert list(data_dir.glob("confirmation_lockouts.json.corrupt.*"))


@pytest.mark.asyncio
async def test_webauthn_register_list_revoke_persists_across_restart(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    port = _reserve_local_port()
    origin = f"http://127.0.0.1:{port}"
    config_overrides = {
        "approval_origin": origin,
        "approval_bind_host": "127.0.0.1",
        "approval_bind_port": port,
    }

    daemon_task, client = await _start_daemon(
        tmp_path,
        monkeypatch,
        config_overrides=config_overrides,
    )
    try:
        started = await client.call(
            "2fa.register_begin",
            {"method": "webauthn", "user_id": "alice", "name": "ops-phone"},
        )
        assert started["started"] is True
        status_code, context = await asyncio.to_thread(
            _http_get_json,
            str(started["registration_url"]),
        )
        assert status_code == 200
        assert context["ok"] is True
        credential, registration_payload = make_registration_payload(
            public_key_options=context["public_key"],
            origin=context["origin"],
            rp_id=context["rp_id"],
        )
        _ = credential
        register_code, register_result = await asyncio.to_thread(
            _http_post_json,
            str(started["registration_url"]),
            registration_payload,
        )
        assert register_code == 200
        assert register_result["registered"] is True
        listed = await client.call("2fa.list", {"user_id": "alice", "method": "webauthn"})
        assert listed["count"] == 1
        assert listed["entries"][0]["principal_id"] == "ops-phone"
        assert listed["entries"][0]["credential_id"] == register_result["credential_id"]
        enrolled_events = await client.call(
            "audit.query",
            {"event_type": "TwoFactorEnrolled", "limit": 10},
        )
        assert any(
            str(event.get("data", {}).get("credential_id", "")) == register_result["credential_id"]
            and str(event.get("data", {}).get("principal_id", "")) == "ops-phone"
            and str(event.get("data", {}).get("method", "")) == "webauthn"
            for event in enrolled_events.get("events", [])
        )
    finally:
        await _shutdown_daemon(daemon_task, client)

    daemon_task, client = await _start_daemon(
        tmp_path,
        monkeypatch,
        config_overrides=config_overrides,
    )
    try:
        listed = await client.call("2fa.list", {"user_id": "alice", "method": "webauthn"})
        assert listed["count"] == 1
        revoke = await client.call(
            "2fa.revoke",
            {
                "method": "webauthn",
                "user_id": "alice",
                "credential_id": listed["entries"][0]["credential_id"],
            },
        )
        assert revoke["revoked"] is True
        assert revoke["removed"] == 1
        listed_after = await client.call("2fa.list", {"user_id": "alice", "method": "webauthn"})
        assert listed_after["count"] == 0
        revoked_events = await client.call(
            "audit.query",
            {"event_type": "TwoFactorRevoked", "limit": 10},
        )
        assert any(
            str(event.get("data", {}).get("credential_id", ""))
            == listed["entries"][0]["credential_id"]
            and str(event.get("data", {}).get("principal_id", "")) == "ops-phone"
            and str(event.get("data", {}).get("method", "")) == "webauthn"
            for event in revoked_events.get("events", [])
        )
    finally:
        await _shutdown_daemon(daemon_task, client)
