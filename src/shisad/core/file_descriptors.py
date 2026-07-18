"""Small descriptor-transfer invariants shared by subprocess callers."""

from __future__ import annotations

import fcntl
import os

_FIRST_NONSTANDARD_DESCRIPTOR = 3


def duplicate_fd_above_standard_streams(fd: int) -> int:
    """Return an owned duplicate that cannot collide with child stdio pipes."""

    if fd < 0:
        raise ValueError("file descriptor must be non-negative")
    command = getattr(fcntl, "F_DUPFD_CLOEXEC", fcntl.F_DUPFD)
    duplicate = int(fcntl.fcntl(fd, command, _FIRST_NONSTANDARD_DESCRIPTOR))
    if duplicate < _FIRST_NONSTANDARD_DESCRIPTOR:
        os.close(duplicate)
        raise OSError("duplicated descriptor overlaps standard streams")
    return duplicate
