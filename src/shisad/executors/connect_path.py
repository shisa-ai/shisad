"""Connect-path network enforcement for sandboxed execution."""

from __future__ import annotations

import os
import shutil
import subprocess
from typing import Protocol

from pydantic import BaseModel


class ConnectPathResult(BaseModel):
    enforced: bool
    method: str = "none"
    reason: str = ""


class ConnectPathProxy(Protocol):
    """Interface for connect-path network enforcement."""

    def enforce(self, *, allowed_ips: list[str], namespace_pid: int) -> ConnectPathResult: ...


class IptablesConnectPathProxy:
    """iptables-based connect-path restriction inside a target network namespace."""

    def __init__(self, *, net_admin_available: bool | None = None) -> None:
        self._iptables = shutil.which("iptables") or ""
        self._nsenter = shutil.which("nsenter") or ""
        self._daemon_netns_signature = self._namespace_signature(os.getpid())
        self._net_admin_available = (
            self.detect_net_admin_capability()
            if net_admin_available is None
            else net_admin_available
        )

    @property
    def net_admin_available(self) -> bool:
        return self._net_admin_available

    def enforce(self, *, allowed_ips: list[str], namespace_pid: int) -> ConnectPathResult:
        if not self._net_admin_available:
            return ConnectPathResult(
                enforced=False,
                method="none",
                reason="CAP_NET_ADMIN unavailable",
            )
        if not self._iptables or not self._nsenter:
            return ConnectPathResult(
                enforced=False,
                method="none",
                reason="iptables/nsenter unavailable",
            )
        if namespace_pid <= 0:
            return ConnectPathResult(
                enforced=False,
                method="iptables",
                reason="invalid_namespace_pid",
            )
        if not self._is_isolated_namespace(namespace_pid):
            return ConnectPathResult(
                enforced=False,
                method="iptables",
                reason="host_namespace_unsafe",
            )

        unique_ips = sorted({ip.strip() for ip in allowed_ips if ip.strip()})
        if not unique_ips:
            return ConnectPathResult(
                enforced=False,
                method="iptables",
                reason="empty_allowed_ips",
            )

        try:
            self._run(namespace_pid, ["-F", "OUTPUT"])
            self._run(namespace_pid, ["-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"])
            for ip in unique_ips:
                self._run(namespace_pid, ["-A", "OUTPUT", "-d", ip, "-j", "ACCEPT"])
            self._run(namespace_pid, ["-A", "OUTPUT", "-j", "DROP"])
        except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as exc:
            return ConnectPathResult(
                enforced=False,
                method="iptables",
                reason=f"iptables_failed:{exc.__class__.__name__}",
            )

        return ConnectPathResult(enforced=True, method="iptables", reason="enforced")

    def _is_isolated_namespace(self, namespace_pid: int) -> bool:
        target_signature = self._namespace_signature(namespace_pid)
        if not target_signature:
            return False
        daemon_signature = self._daemon_netns_signature or self._namespace_signature(os.getpid())
        if not daemon_signature:
            return False
        return target_signature != daemon_signature

    @staticmethod
    def _namespace_signature(pid: int) -> str:
        try:
            return os.readlink(f"/proc/{pid}/ns/net")
        except OSError:
            return ""

    def _run(self, namespace_pid: int, args: list[str]) -> None:
        cmd = [
            self._nsenter,
            "-t",
            str(namespace_pid),
            "-n",
            self._iptables,
            *args,
        ]
        subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=2,
            check=True,
        )

    @staticmethod
    def detect_net_admin_capability() -> bool:
        if os.geteuid() == 0 and shutil.which("iptables"):
            return True
        capsh = shutil.which("capsh")
        if not capsh:
            return False
        try:
            completed = subprocess.run(
                [capsh, "--print"],
                capture_output=True,
                text=True,
                timeout=1,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            return False
        output = f"{completed.stdout}\n{completed.stderr}".lower()
        return "cap_net_admin" in output and "ep" in output


class NoopConnectPathProxy:
    """Fallback implementation used when connect-path enforcement is unavailable."""

    def __init__(self, *, net_admin_available: bool | None = None) -> None:
        self._net_admin_available = (
            self.detect_net_admin_capability()
            if net_admin_available is None
            else net_admin_available
        )

    @property
    def net_admin_available(self) -> bool:
        return self._net_admin_available

    @staticmethod
    def detect_net_admin_capability() -> bool:
        return IptablesConnectPathProxy.detect_net_admin_capability()

    def enforce(self, *, allowed_ips: list[str], namespace_pid: int) -> ConnectPathResult:
        _ = allowed_ips, namespace_pid
        if not self._net_admin_available:
            return ConnectPathResult(
                enforced=False,
                method="none",
                reason="CAP_NET_ADMIN unavailable",
            )
        return ConnectPathResult(
            enforced=False,
            method="none",
            reason="connect-path stub not implemented",
        )
