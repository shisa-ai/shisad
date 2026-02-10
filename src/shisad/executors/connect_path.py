"""Connect-path proxy interface stub (M4.10)."""

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


class NoopConnectPathProxy:
    """Stub implementation used until real iptables path is added."""

    def __init__(self, *, net_admin_available: bool | None = None) -> None:
        self._net_admin_available = (
            self.detect_net_admin_capability()
            if net_admin_available is None
            else net_admin_available
        )

    @property
    def net_admin_available(self) -> bool:
        return self._net_admin_available

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

    @staticmethod
    def detect_net_admin_capability() -> bool:
        if os.geteuid() == 0 and shutil.which("iptables"):
            return True
        probe = shutil.which("capsh")
        if not probe:
            return False
        try:
            completed = subprocess.run(
                [probe, "--print"],
                capture_output=True,
                text=True,
                timeout=1,
                check=False,
            )
        except Exception:
            return False
        output = f"{completed.stdout}\n{completed.stderr}".lower()
        return "cap_net_admin" in output and "ep" in output
