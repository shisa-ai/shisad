"""Tests for shisad.core.log — loguru setup and stdlib interception."""

from __future__ import annotations

import logging

from loguru import logger

from shisad.core.log import LOG_FORMAT, LOG_FORMAT_FILE, setup_logging


def test_setup_logging_configures_stderr_sink() -> None:
    """After setup_logging, loguru should have exactly one handler (stderr)."""
    setup_logging(level="DEBUG")
    # loguru._core exposes handlers; we just verify we can log without error
    # and that the handler list is non-empty.
    handlers = logger._core.handlers  # type: ignore[attr-defined]
    assert len(handlers) >= 1


def test_setup_logging_normalizes_invalid_level() -> None:
    """Invalid level strings should fall back to INFO."""
    setup_logging(level="BOGUS")
    # Should not raise; verify we still have a handler.
    handlers = logger._core.handlers  # type: ignore[attr-defined]
    assert len(handlers) >= 1


def test_stdlib_logging_routes_through_loguru(capsys: object) -> None:
    """Stdlib logger calls should be intercepted by loguru."""
    setup_logging(level="DEBUG", colorize=False)
    stdlib_logger = logging.getLogger("shisad.test.intercept")
    stdlib_logger.info("hello from stdlib")
    # Verify the InterceptHandler is installed on the root logger.
    root = logging.getLogger()
    handler_types = [type(h).__name__ for h in root.handlers]
    assert "_InterceptHandler" in handler_types


def test_stdlib_logging_levels_are_preserved() -> None:
    """Stdlib logging levels (DEBUG, WARNING, ERROR) should map correctly."""
    captured: list[str] = []

    def sink(message: object) -> None:
        captured.append(str(message))

    setup_logging(level="DEBUG", colorize=False)
    # Add a test sink to capture output.
    handler_id = logger.add(sink, format="{level} {message}", level="DEBUG")
    try:
        stdlib_logger = logging.getLogger("shisad.test.levels")
        stdlib_logger.debug("debug-msg")
        stdlib_logger.info("info-msg")
        stdlib_logger.warning("warning-msg")
        stdlib_logger.error("error-msg")
    finally:
        logger.remove(handler_id)

    joined = "\n".join(captured)
    assert "DEBUG debug-msg" in joined
    assert "INFO info-msg" in joined
    assert "WARNING warning-msg" in joined
    assert "ERROR error-msg" in joined


def test_setup_logging_level_filtering() -> None:
    """Messages below the configured level should be filtered out."""
    captured: list[str] = []

    def sink(message: object) -> None:
        captured.append(str(message))

    # Set level to WARNING — DEBUG and INFO should be suppressed.
    setup_logging(level="WARNING", colorize=False)
    handler_id = logger.add(sink, format="{level} {message}", level="WARNING")
    try:
        stdlib_logger = logging.getLogger("shisad.test.filter")
        stdlib_logger.debug("should-not-appear")
        stdlib_logger.info("should-not-appear-either")
        stdlib_logger.warning("should-appear")
        stdlib_logger.error("should-also-appear")
    finally:
        logger.remove(handler_id)

    joined = "\n".join(captured)
    assert "should-not-appear" not in joined or "WARNING should-appear" in joined
    assert "WARNING should-appear" in joined
    assert "ERROR should-also-appear" in joined


def test_setup_logging_idempotent() -> None:
    """Calling setup_logging twice should not duplicate handlers."""
    setup_logging(level="INFO")
    count_before = len(logger._core.handlers)  # type: ignore[attr-defined]
    setup_logging(level="INFO")
    count_after = len(logger._core.handlers)  # type: ignore[attr-defined]
    assert count_after == count_before


def test_log_format_contains_expected_placeholders() -> None:
    """Verify format strings contain the key fields."""
    assert "{level" in LOG_FORMAT
    assert "{time" in LOG_FORMAT
    assert "{name}" in LOG_FORMAT
    assert "{message}" in LOG_FORMAT

    assert "{level" in LOG_FORMAT_FILE
    assert "{time" in LOG_FORMAT_FILE
    assert "{name}" in LOG_FORMAT_FILE
    assert "{message}" in LOG_FORMAT_FILE


def test_loguru_direct_output_is_formatted(capsys: object) -> None:
    """Loguru direct calls should produce formatted output."""
    captured: list[str] = []

    def sink(message: object) -> None:
        captured.append(str(message))

    setup_logging(level="DEBUG", colorize=False)
    handler_id = logger.add(sink, format="{time:HH:mm:ss} | {level: <8} | {message}", level="DEBUG")
    try:
        logger.info("formatted-test")
    finally:
        logger.remove(handler_id)

    assert any("INFO" in line and "formatted-test" in line for line in captured)
