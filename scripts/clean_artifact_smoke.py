#!/usr/local/bin/python3
# ruff: noqa: SIM905
"""Preflight container isolation and gate shisad's bwrap discovery probe."""

import os
import subprocess
import sys
import time
from pathlib import Path

REAL_BWRAP, PASTA = "/usr/bin/bwrap", "/usr/bin/pasta"
READY = Path("/run/shisad/bwrap-network-ready")
PROBE_ENV = {"PATH": "/usr/bin:/bin"}
DISCOVERY_ARGS = "--ro-bind / / --proc /proc --dev /dev -- /bin/true".split()
BASE_ARGS = "--ro-bind / / --proc /proc --dev /dev".split()
PASTA_ARGS = (
    "--quiet --config-net --ipv4-only --no-map-gw --no-splice "
    "-D none -t none -u none -T none -U none"
).split()


def _network_probe() -> bool:
    child: subprocess.Popen[bytes] | None = None
    try:
        full = subprocess.run(
            [
                REAL_BWRAP,
                *BASE_ARGS,
                "--unshare-pid",
                "--unshare-uts",
                "--unshare-ipc",
                "--unshare-net",
                "--",
                "/bin/true",
            ],
            capture_output=True,
            env=PROBE_ENV,
            timeout=3,
            check=False,
        )
        if full.returncode:
            return False
        child = subprocess.Popen(
            [REAL_BWRAP, *BASE_ARGS, "--unshare-net", "--", "/bin/sleep", "8"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=PROBE_ENV,
        )
        host_namespace = os.readlink("/proc/self/ns/net")
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline and child.poll() is None:
            if os.readlink(f"/proc/{child.pid}/ns/net") != host_namespace:
                break
            time.sleep(0.05)
        else:
            return False
        attached = subprocess.run(
            [PASTA, *PASTA_ARGS, str(child.pid)],
            capture_output=True,
            env=PROBE_ENV,
            timeout=5,
            check=False,
        )
        return attached.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False
    finally:
        if child is not None and child.poll() is None:
            child.terminate()
            try:
                child.wait(timeout=1)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(timeout=1)


def main() -> int:
    args = sys.argv[1:]
    if Path(sys.argv[0]).name == "bwrap":
        if args == DISCOVERY_ARGS and not READY.is_file():
            return 1
        os.execv(REAL_BWRAP, [REAL_BWRAP, *args])
    if not args:
        return 64
    READY.unlink(missing_ok=True)
    if _network_probe():
        READY.touch(mode=0o600)
    os.execvp(args[0], args)


if __name__ == "__main__":
    raise SystemExit(main())
