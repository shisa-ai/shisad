"""Security properties required of shared networking dependencies."""

import ssl
import subprocess
import sys
from unittest.mock import AsyncMock, Mock

import pytest
from anyio.streams.tls import TLSStream


@pytest.mark.asyncio
async def test_tls_preserves_idna_2008_hostname(monkeypatch: pytest.MonkeyPatch) -> None:
    # Isolate hostname preparation from network I/O; stdlib SSL exposes the
    # hostname it will verify even before the handshake completes.
    monkeypatch.setattr(TLSStream, "_call_sslobject_method", AsyncMock())
    stream = await TLSStream.wrap(
        Mock(), hostname="faß.de", ssl_context=ssl.create_default_context()
    )
    assert stream._ssl_object.server_hostname == "xn--fa-hia.de"


def test_process_worker_stderr_cannot_block_result() -> None:
    # A separate interpreter owns the pool and its cleanup. The inner deadline
    # cancels a blocked worker; the outer deadline also bounds failed cleanup.
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "import anyio, anyio.to_process\n"
            "async def main():\n"
            "    with anyio.fail_after(3):\n"
            "        count = await anyio.to_process.run_sync(\n"
            "            eval, \"__import__('sys').stderr.write('x' * 1_000_000)\",\n"
            "            cancellable=True)\n"
            "        assert count == 1_000_000\n"
            "anyio.run(main)\n",
        ],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert result.returncode == 0, result.stderr
