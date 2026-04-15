"""Test helpers for MCP server fixtures."""

from __future__ import annotations

import os
import socket
import subprocess
import sys
import textwrap
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

MOCK_MCP_SERVER_SOURCE = textwrap.dedent(
    """
    import asyncio
    import os

    from mcp.server.fastmcp import FastMCP

    port = int(os.environ.get("MOCK_MCP_PORT", "8000"))
    transport = os.environ.get("MOCK_MCP_TRANSPORT", "stdio").strip().lower()

    app = FastMCP("demo", host="127.0.0.1", port=port)


    @app.tool(name="lookup-doc")
    def lookup_doc(query: str, limit: int = 3) -> dict[str, object]:
        return {
            "query": query,
            "limit": limit,
            "answer": f"echo:{query}",
        }


    @app.tool()
    async def sleepy(query: str, delay_seconds: float = 1.0) -> dict[str, object]:
        await asyncio.sleep(delay_seconds)
        return {
            "query": query,
            "delay_seconds": delay_seconds,
            "answer": "slow",
        }


    @app.tool(name="env-snapshot")
    def env_snapshot(name: str) -> dict[str, object]:
        return {
            "name": name,
            "value": os.environ.get(name),
        }


    if __name__ == "__main__":
        app.run("streamable-http" if transport == "http" else "stdio")
    """
)


def write_mock_mcp_server(path: Path) -> Path:
    """Write a reusable mock MCP server script to *path*."""
    path.write_text(MOCK_MCP_SERVER_SOURCE, encoding="utf-8")
    return path


def reserve_local_port() -> int:
    """Reserve a currently-free localhost TCP port."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def wait_for_tcp_port(
    host: str,
    port: int,
    *,
    timeout: float = 10.0,
    process: subprocess.Popen[str] | None = None,
) -> None:
    """Block until *host:port* accepts TCP connections or raise."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process is not None and process.poll() is not None:
            _stdout, stderr = process.communicate(timeout=1)
            raise RuntimeError(
                f"MCP server exited before becoming ready (code {process.returncode}): "
                f"{stderr.strip()}"
            )
        try:
            with socket.create_connection((host, port), timeout=0.2):
                return
        except OSError:
            time.sleep(0.05)
    raise RuntimeError(f"Timed out waiting for TCP port {host}:{port}")


@contextmanager
def running_http_mcp_server(
    script_path: Path,
    *,
    port: int,
    python_executable: str | None = None,
) -> Iterator[subprocess.Popen[str]]:
    """Run the mock MCP server over streamable HTTP for the duration of a context."""
    env = dict(os.environ)
    env["MOCK_MCP_TRANSPORT"] = "http"
    env["MOCK_MCP_PORT"] = str(port)
    process = subprocess.Popen(
        [python_executable or sys.executable, str(script_path)],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        wait_for_tcp_port("127.0.0.1", port, process=process)
        yield process
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.communicate(timeout=5)
