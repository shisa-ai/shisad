"""Local helper for SSH/private approval flows."""

from __future__ import annotations

import asyncio
import base64
import os
import subprocess
import tempfile
import time
import uuid
from collections.abc import Callable, Mapping
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

import click
from fido2.client import UserInteraction

from shisad.core.api.transport import ControlClient


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


class ApproverDevice(Protocol):
    def register_credential(
        self,
        *,
        public_key_options: Mapping[str, Any],
        origin: str,
    ) -> dict[str, Any]:
        ...

    def get_assertion(
        self,
        *,
        public_key_options: Mapping[str, Any],
        origin: str,
    ) -> dict[str, Any]:
        ...


class _ConsoleUserInteraction(UserInteraction):
    def prompt_up(self) -> None:
        click.echo("Touch your security key to continue.", err=True)

    def request_pin(self, permissions: object, rp_id: str | None) -> str | None:
        _ = permissions
        label = rp_id or "this authenticator"
        value = click.prompt(
            f"Security key PIN for {label}",
            hide_input=True,
            default="",
            show_default=False,
        )
        return value.strip() or None

    def request_uv(self, permissions: object, rp_id: str | None) -> bool:
        _ = permissions
        if rp_id:
            click.echo(f"Complete user verification for {rp_id}.", err=True)
        return True


def _registration_payload_from_response(response: Any) -> dict[str, Any]:
    return {
        "id": str(response.id),
        "rawId": _b64url_encode(bytes(response.raw_id)),
        "type": getattr(response.type, "value", str(response.type)),
        "response": {
            "clientDataJSON": _b64url_encode(bytes(response.response.client_data)),
            "attestationObject": _b64url_encode(bytes(response.response.attestation_object)),
        },
    }


def _assertion_payload_from_response(response: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "id": str(response.id),
        "rawId": _b64url_encode(bytes(response.raw_id)),
        "type": getattr(response.type, "value", str(response.type)),
        "response": {
            "clientDataJSON": _b64url_encode(bytes(response.response.client_data)),
            "authenticatorData": _b64url_encode(bytes(response.response.authenticator_data)),
            "signature": _b64url_encode(bytes(response.response.signature)),
        },
    }
    user_handle = getattr(response.response, "user_handle", None)
    if user_handle is not None:
        payload["response"]["userHandle"] = _b64url_encode(bytes(user_handle))
    return payload


class HardwareLocalFido2Device:
    """Real USB/HID-backed FIDO2 helper device."""

    def __init__(self) -> None:
        self._interaction = _ConsoleUserInteraction()

    @staticmethod
    def _select_device() -> Any:
        from fido2.hid import CtapHidDevice

        devices = list(CtapHidDevice.list_devices())
        if not devices:
            raise RuntimeError("No FIDO2 authenticator detected")
        return devices[0]

    def _client(self, *, origin: str) -> Any:
        from fido2.client import DefaultClientDataCollector, Fido2Client

        return Fido2Client(
            self._select_device(),
            DefaultClientDataCollector(origin),
            user_interaction=self._interaction,
        )

    def register_credential(
        self,
        *,
        public_key_options: Mapping[str, Any],
        origin: str,
    ) -> dict[str, Any]:
        from fido2.webauthn import PublicKeyCredentialCreationOptions

        client = self._client(origin=origin)
        options = PublicKeyCredentialCreationOptions.from_dict(dict(public_key_options))
        response = client.make_credential(options)
        return _registration_payload_from_response(response)

    def get_assertion(
        self,
        *,
        public_key_options: Mapping[str, Any],
        origin: str,
    ) -> dict[str, Any]:
        from fido2.webauthn import PublicKeyCredentialRequestOptions

        client = self._client(origin=origin)
        options = PublicKeyCredentialRequestOptions.from_dict(dict(public_key_options))
        selection = client.get_assertion(options)
        response = selection.get_response(0)
        return _assertion_payload_from_response(response)


@dataclass(slots=True)
class _SocketEndpoint:
    socket_path: Path
    process: subprocess.Popen[bytes] | None = None
    cleanup_path: bool = False

    def close(self) -> None:
        if self.process is not None:
            with suppress(ProcessLookupError):
                self.process.terminate()
            with suppress(subprocess.TimeoutExpired):
                self.process.wait(timeout=3)
            if self.process.poll() is None:
                with suppress(ProcessLookupError):
                    self.process.kill()
                with suppress(subprocess.TimeoutExpired):
                    self.process.wait(timeout=1)
        if self.cleanup_path and self.socket_path.exists():
            with suppress(OSError):
                self.socket_path.unlink()


class ApproverService:
    def __init__(
        self,
        *,
        socket_path: Path,
        device: ApproverDevice | None = None,
        session_id: str = "",
    ) -> None:
        self._socket_path = Path(socket_path)
        self._device = device or HardwareLocalFido2Device()
        self._session_id = session_id.strip()

    async def _call(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        client = ControlClient(self._socket_path)
        try:
            await client.connect()
            payload = await client.call(method, params)
        finally:
            with suppress(OSError, RuntimeError):
                await client.close()
        if not isinstance(payload, dict):
            raise RuntimeError(f"{method} returned invalid response type: {type(payload).__name__}")
        return payload

    async def enroll(self, *, user_id: str, name: str = "") -> dict[str, Any]:
        started = await self._call(
            "2fa.register_begin",
            {
                "method": "local_fido2",
                "user_id": user_id,
                "name": name or None,
            },
        )
        if not bool(started.get("started")):
            raise RuntimeError(str(started.get("reason", "")) or "local_fido2 enrollment failed")
        public_key = started.get("helper_public_key")
        origin = str(started.get("helper_origin", "")).strip()
        if not isinstance(public_key, dict) or not origin:
            raise RuntimeError("Daemon did not return local helper enrollment options")
        proof = self._device.register_credential(
            public_key_options=public_key,
            origin=origin,
        )
        confirmed = await self._call(
            "2fa.register_confirm",
            {
                "enrollment_id": str(started.get("enrollment_id", "")),
                "proof": proof,
            },
        )
        if not bool(confirmed.get("registered")):
            raise RuntimeError(
                str(confirmed.get("reason", "")) or "local_fido2 enrollment confirmation failed"
            )
        return confirmed

    async def pending_local_fido2_actions(self) -> list[dict[str, Any]]:
        payload: dict[str, Any] = {"status": "pending", "limit": 100, "include_ui": True}
        if self._session_id:
            payload["session_id"] = self._session_id
        pending = await self._call("action.pending", payload)
        actions = pending.get("actions")
        if not isinstance(actions, list):
            return []
        rows: list[dict[str, Any]] = []
        for item in actions:
            if not isinstance(item, dict):
                continue
            if str(item.get("selected_backend_method", "")).strip() != "local_fido2":
                continue
            rows.append(item)
        return rows

    async def process_pending_once(
        self,
        *,
        prompt: Callable[[dict[str, Any]], bool],
    ) -> dict[str, int]:
        rows = await self.pending_local_fido2_actions()
        processed = 0
        approved = 0
        rejected = 0
        for row in rows:
            processed += 1
            confirmation_id = str(row.get("confirmation_id", "")).strip()
            decision_nonce = str(row.get("decision_nonce", "")).strip()
            if not confirmation_id or not decision_nonce:
                raise RuntimeError("Pending approval is missing confirmation_id or decision_nonce")
            if prompt(row):
                public_key = row.get("helper_public_key")
                origin = str(row.get("helper_origin", "")).strip()
                if not isinstance(public_key, dict) or not origin:
                    raise RuntimeError(
                        f"Pending approval {confirmation_id} is missing helper FIDO2 options"
                    )
                proof = self._device.get_assertion(
                    public_key_options=public_key,
                    origin=origin,
                )
                result = await self._call(
                    "action.confirm",
                    {
                        "confirmation_id": confirmation_id,
                        "decision_nonce": decision_nonce,
                        "approval_method": "local_fido2",
                        "proof": proof,
                    },
                )
                if not bool(result.get("confirmed")):
                    raise RuntimeError(
                        str(result.get("reason", "")) or f"Confirmation {confirmation_id} failed"
                    )
                approved += 1
            else:
                result = await self._call(
                    "action.reject",
                    {
                        "confirmation_id": confirmation_id,
                        "decision_nonce": decision_nonce,
                        "reason": "local_helper_reject",
                    },
                )
                if not bool(result.get("rejected")):
                    raise RuntimeError(
                        str(result.get("reason", "")) or f"Rejection {confirmation_id} failed"
                    )
                rejected += 1
        return {"processed": processed, "approved": approved, "rejected": rejected}

    async def watch(
        self,
        *,
        prompt: Callable[[dict[str, Any]], bool],
        poll_interval_seconds: float,
        once: bool,
    ) -> dict[str, int]:
        totals = {"processed": 0, "approved": 0, "rejected": 0}
        while True:
            result = await self.process_pending_once(prompt=prompt)
            for key in totals:
                totals[key] += int(result.get(key, 0))
            if once:
                return totals
            await asyncio.sleep(max(0.1, poll_interval_seconds))


def _wait_for_socket(path: Path, *, timeout_seconds: float = 5.0) -> None:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        if path.exists():
            return
        time.sleep(0.05)
    raise click.ClickException(f"Timed out waiting for forwarded socket {path}")


def _build_socket_endpoint(
    *,
    socket_path: Path | None,
    ssh_target: str,
    remote_socket: Path | None,
    ssh_command: str,
    ssh_timeout_seconds: float,
) -> _SocketEndpoint:
    if not ssh_target.strip():
        if socket_path is None:
            raise click.ClickException("--socket-path is required when --ssh-target is not used.")
        return _SocketEndpoint(socket_path=Path(socket_path))
    if remote_socket is None:
        raise click.ClickException("--remote-socket is required with --ssh-target.")

    if socket_path is None:
        local_socket = Path(tempfile.gettempdir()) / f"shisad-approver-{uuid.uuid4().hex}.sock"
        cleanup_path = True
    else:
        local_socket = Path(socket_path)
        cleanup_path = False

    with suppress(OSError):
        local_socket.unlink()

    command = [
        ssh_command,
        "-NT",
        "-L",
        f"{os.fspath(local_socket)}:{os.fspath(remote_socket)}",
        ssh_target,
    ]
    process = subprocess.Popen(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    try:
        _wait_for_socket(local_socket, timeout_seconds=ssh_timeout_seconds)
    except Exception:
        with suppress(ProcessLookupError):
            process.terminate()
        stderr = b""
        with suppress(subprocess.TimeoutExpired):
            _stdout, stderr = process.communicate(timeout=1)
        if process.poll() is None:
            with suppress(ProcessLookupError):
                process.kill()
            with suppress(subprocess.TimeoutExpired):
                _stdout, stderr = process.communicate(timeout=1)
        detail = stderr.decode("utf-8", errors="ignore").strip()
        if detail:
            raise click.ClickException(f"SSH socket forward failed: {detail}") from None
        raise
    return _SocketEndpoint(
        socket_path=local_socket,
        process=process,
        cleanup_path=cleanup_path,
    )


def _render_prompt(row: dict[str, Any]) -> bool:
    confirmation_id = str(row.get("confirmation_id", "")).strip()
    preview = str(row.get("safe_preview", "")).strip()
    tool_name = str(row.get("tool_name", "")).strip()
    required_level = str(row.get("required_level", "")).strip()
    click.echo(f"[{confirmation_id}] {tool_name or 'pending_action'}")
    if required_level:
        click.echo(f"required_level={required_level}")
    if preview:
        click.echo(preview)
    warnings = row.get("warnings")
    if isinstance(warnings, list):
        for warning in warnings:
            value = str(warning).strip()
            if value:
                click.echo(f"warning: {value}")
    return click.confirm("Approve this action?", default=False)


@click.group()
def cli() -> None:
    """Local helper for SSH/private approval flows."""


def _with_endpoint(
    fn: Callable[[_SocketEndpoint], None],
    *,
    socket_path: Path | None,
    ssh_target: str,
    remote_socket: Path | None,
    ssh_command: str,
    ssh_timeout_seconds: float,
) -> None:
    endpoint = _build_socket_endpoint(
        socket_path=socket_path,
        ssh_target=ssh_target,
        remote_socket=remote_socket,
        ssh_command=ssh_command,
        ssh_timeout_seconds=ssh_timeout_seconds,
    )
    try:
        fn(endpoint)
    finally:
        endpoint.close()


def _socket_options(fn: Callable[..., None]) -> Callable[..., None]:
    fn = click.option(
        "--ssh-timeout",
        "ssh_timeout_seconds",
        default=5.0,
        show_default=True,
        type=click.FloatRange(min=1.0),
        help="Seconds to wait for an SSH-forwarded socket to appear.",
    )(fn)
    fn = click.option(
        "--ssh-command",
        default="ssh",
        show_default=True,
        help="SSH binary used for Unix-socket forwarding.",
    )(fn)
    fn = click.option(
        "--remote-socket",
        type=click.Path(path_type=Path),
        default=None,
        help="Remote daemon control socket path when using --ssh-target.",
    )(fn)
    fn = click.option(
        "--ssh-target",
        default="",
        help="Optional SSH target used to forward the daemon control socket.",
    )(fn)
    fn = click.option(
        "--socket-path",
        type=click.Path(path_type=Path),
        default=None,
        help="Local daemon control socket path (or the local end of an SSH forward).",
    )(fn)
    return fn


@cli.command("register")
@_socket_options
@click.option("--user", "user_id", required=True, help="Target user ID.")
@click.option("--name", default="", help="Audit principal label.")
def register_command(
    socket_path: Path | None,
    ssh_target: str,
    remote_socket: Path | None,
    ssh_command: str,
    ssh_timeout_seconds: float,
    user_id: str,
    name: str,
) -> None:
    """Enroll a local helper FIDO2 credential."""

    def _run(endpoint: _SocketEndpoint) -> None:
        service = ApproverService(socket_path=endpoint.socket_path)
        result = asyncio.run(service.enroll(user_id=user_id, name=name.strip()))
        click.echo(f"User: {result['user_id']}")
        click.echo(f"Method: {result['method']}")
        click.echo(f"Principal: {result['principal_id']}")
        click.echo(f"Credential: {result['credential_id']}")

    _with_endpoint(
        _run,
        socket_path=socket_path,
        ssh_target=ssh_target,
        remote_socket=remote_socket,
        ssh_command=ssh_command,
        ssh_timeout_seconds=ssh_timeout_seconds,
    )


@cli.command("run")
@_socket_options
@click.option("--session-id", default="", help="Optional session filter.")
@click.option(
    "--poll-interval",
    "poll_interval_seconds",
    default=2.0,
    show_default=True,
    type=click.FloatRange(min=0.1),
    help="Seconds between pending-approval polls.",
)
@click.option("--once", is_flag=True, help="Process the current pending set once and exit.")
def run_command(
    socket_path: Path | None,
    ssh_target: str,
    remote_socket: Path | None,
    ssh_command: str,
    ssh_timeout_seconds: float,
    session_id: str,
    poll_interval_seconds: float,
    once: bool,
) -> None:
    """Watch for local-helper confirmations and prompt in the terminal."""

    def _run(endpoint: _SocketEndpoint) -> None:
        service = ApproverService(
            socket_path=endpoint.socket_path,
            session_id=session_id,
        )
        totals = asyncio.run(
            service.watch(
                prompt=_render_prompt,
                poll_interval_seconds=poll_interval_seconds,
                once=once,
            )
        )
        if once:
            click.echo(
                "processed={processed} approved={approved} rejected={rejected}".format(**totals)
            )

    _with_endpoint(
        _run,
        socket_path=socket_path,
        ssh_target=ssh_target,
        remote_socket=remote_socket,
        ssh_command=ssh_command,
        ssh_timeout_seconds=ssh_timeout_seconds,
    )


if __name__ == "__main__":  # pragma: no cover
    cli()
