"""Shared typed error presentation for CLI command domains."""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Self

import click
from pydantic import ValidationError

from shisad.security.firewall.secrets import redact_ingress_secrets
from shisad.ui.evidence import sanitize_terminal_field


def safe_cli_text(value: object, *, limit: int = 4096) -> str:
    """Return bounded, redacted, single-field terminal-safe text."""

    sanitized = sanitize_terminal_field(str(value)[:4096])
    redacted, _findings = redact_ingress_secrets(sanitized)
    return redacted[: max(0, limit)]


def safe_error_detail(exc: BaseException) -> str:
    """Project an exception without payload values, secrets, or controls."""

    if isinstance(exc, ValidationError):
        failures = []
        for error_row in exc.errors(
            include_url=False,
            include_context=False,
            include_input=False,
        )[:5]:
            location = ".".join(str(part) for part in error_row.get("loc", ())) or "root"
            failures.append(f"{location}:{error_row.get('type', 'invalid')}")
        detail = ", ".join(failures) or "response:invalid"
    else:
        detail = safe_cli_text(exc, limit=4096)
    bounded = safe_cli_text(detail, limit=240)
    return f"{exc.__class__.__name__}: {bounded}" if bounded else exc.__class__.__name__


@dataclass(frozen=True, slots=True)
class CliErrorEnvelope:
    """Stable semantic fields shared by expected CLI failures."""

    error_type: str
    exit_code: int
    what_failed: str
    what_still_works: str
    likely_cause: str
    next_action: str
    technical_details: str

    def __post_init__(self) -> None:
        limits = {
            "error_type": 64,
            "what_failed": 512,
            "what_still_works": 512,
            "likely_cause": 512,
            "next_action": 512,
            "technical_details": 512,
        }
        for field_name, limit in limits.items():
            object.__setattr__(
                self,
                field_name,
                safe_cli_text(getattr(self, field_name), limit=limit),
            )

    @classmethod
    def from_mapping(cls, payload: Mapping[str, object]) -> Self:
        """Validate the compatibility mapping used by older command owners."""

        return cls(
            error_type=safe_cli_text(payload.get("error_type", "cli"), limit=64),
            exit_code=int(str(payload.get("exit_code", 1))),
            what_failed=safe_cli_text(payload.get("what_failed", "Command failed."), limit=512),
            what_still_works=safe_cli_text(payload.get("what_still_works", "help"), limit=512),
            likely_cause=safe_cli_text(payload.get("likely_cause", "unknown"), limit=512),
            next_action=safe_cli_text(payload.get("next_action", "shisad --help"), limit=512),
            technical_details=safe_cli_text(
                payload.get("technical_details", "Unavailable"),
                limit=512,
            ),
        )

    def as_payload(self) -> dict[str, object]:
        return {
            "error_type": self.error_type,
            "exit_code": self.exit_code,
            "what_failed": self.what_failed,
            "what_still_works": self.what_still_works,
            "likely_cause": self.likely_cause,
            "next_action": self.next_action,
            "technical_details": self.technical_details,
        }

    def render_human(self) -> str:
        return "\n".join(
            [
                f"What failed: {self.what_failed}",
                f"What still works: {self.what_still_works}",
                f"Likely cause: {self.likely_cause}",
                f"Next action: {self.next_action}",
                f"Technical details: {self.technical_details}",
            ]
        )


class StructuredCliError(click.ClickException):
    """Expected CLI failure with stable human and JSON projections."""

    def __init__(
        self,
        envelope: CliErrorEnvelope,
        *,
        output_format: str = "human",
    ) -> None:
        self.envelope = envelope
        self.output_format = output_format
        object.__setattr__(self, "exit_code", envelope.exit_code)
        super().__init__(envelope.render_human())

    @property
    def payload(self) -> dict[str, object]:
        return self.envelope.as_payload()

    def show(self, file: Any | None = None) -> None:
        if self.output_format != "json":
            super().show(file)
            return
        if file is None:
            file = click.get_text_stream("stderr")
        click.echo(json.dumps(self.payload, sort_keys=True), file=file)
