"""Logging configuration for shisad.

Sets up loguru as the primary log sink and intercepts stdlib logging so all
existing ``logging.getLogger(__name__)`` call-sites route through loguru
with colored, structured output.
"""

from __future__ import annotations

import logging
import sys
from typing import TYPE_CHECKING

from loguru import logger

if TYPE_CHECKING:
    pass

# Canonical format — concise, colored, easy to scan in a terminal.
#   08:23:45.123 | INFO     | shisad.daemon.runner - daemon started
LOG_FORMAT = (
    "<green>{time:HH:mm:ss.SSS}</green> | "
    "<level>{level: <8}</level> | "
    "<cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - "
    "<level>{message}</level>"
)

# Logfile format — full ISO timestamp, no ANSI escapes.
LOG_FORMAT_FILE = (
    "{time:YYYY-MM-DDTHH:mm:ss.SSSZ} | "
    "{level: <8} | "
    "{name}:{function}:{line} - "
    "{message}"
)


class _InterceptHandler(logging.Handler):
    """Route stdlib ``logging`` calls into loguru.

    This allows the 26+ modules that use ``logger = logging.getLogger(__name__)``
    to emit through loguru without any code changes.
    """

    def emit(self, record: logging.LogRecord) -> None:
        # Map stdlib level to loguru level name.
        try:
            level = logger.level(record.levelname).name
        except ValueError:
            level = str(record.levelno)

        # Find the originating frame so loguru reports the correct caller.
        frame = logging.currentframe()
        depth = 0
        while frame is not None:
            if frame.f_code.co_filename == logging.__file__:
                frame = frame.f_back  # type: ignore[assignment]
                depth += 1
                continue
            break

        logger.opt(depth=depth, exception=record.exc_info).log(
            level, record.getMessage()
        )


def setup_logging(
    *,
    level: str = "INFO",
    colorize: bool | None = None,
) -> None:
    """Configure loguru + stdlib interception.

    Call once at process startup (daemon runner, CLI, or test harness).

    Args:
        level: Minimum log level (DEBUG, INFO, WARNING, ERROR, CRITICAL).
        colorize: Force color on/off. ``None`` = auto-detect from tty.
    """
    # Normalize level string.
    level = level.upper().strip()
    if level not in ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"):
        level = "INFO"

    # Remove loguru defaults (avoid duplicate stderr sinks on re-init).
    logger.remove()

    # Primary stderr sink — colored when interactive.
    logger.add(
        sys.stderr,
        format=LOG_FORMAT,
        level=level,
        colorize=colorize,
        backtrace=False,
        diagnose=False,
    )

    # Intercept all stdlib logging and route through loguru.
    logging.basicConfig(handlers=[_InterceptHandler()], level=0, force=True)
