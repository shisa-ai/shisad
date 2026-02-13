"""Domain error taxonomy with structured reason codes."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any


class ShisadError(Exception):
    """Base error carrying structured reason-code metadata."""

    rpc_code: int = -32603
    default_reason_code = "shisad.error"
    default_message = "Internal error"
    expose_message = False

    def __init__(
        self,
        message: str | None = None,
        *,
        reason_code: str | None = None,
        details: Mapping[str, Any] | None = None,
        rpc_code: int | None = None,
        expose_message: bool | None = None,
    ) -> None:
        self.message = message or self.default_message
        self.reason_code = reason_code or self.default_reason_code
        self.details = dict(details or {})
        self.rpc_code = rpc_code if rpc_code is not None else type(self).rpc_code
        self.expose_message = (
            expose_message if expose_message is not None else type(self).expose_message
        )
        super().__init__(self.message)

    def as_error_data(self, *, include_details: bool = False) -> dict[str, Any]:
        payload: dict[str, Any] = {"reason_code": self.reason_code}
        if include_details and self.details:
            payload["details"] = dict(self.details)
        return payload

    @property
    def public_message(self) -> str:
        if self.expose_message:
            return self.message
        return "Internal error"


class TransportError(ShisadError):
    default_reason_code = "transport.error"
    default_message = "Transport error"
    rpc_code = -32603


class PolicyError(ShisadError):
    default_reason_code = "policy.error"
    default_message = "Policy rejected request"
    rpc_code = -32602
    expose_message = True


class SandboxError(ShisadError):
    default_reason_code = "sandbox.error"
    default_message = "Sandbox execution failed"
    rpc_code = -32603


class ChannelError(ShisadError):
    default_reason_code = "channel.error"
    default_message = "Channel operation failed"
    rpc_code = -32603


class StorageError(ShisadError):
    default_reason_code = "storage.error"
    default_message = "Storage operation failed"
    rpc_code = -32603


class SkillError(ShisadError):
    default_reason_code = "skill.error"
    default_message = "Skill operation failed"
    rpc_code = -32602
    expose_message = True


class ConfigError(ShisadError):
    default_reason_code = "config.error"
    default_message = "Configuration invalid"
    rpc_code = -32602
    expose_message = True
