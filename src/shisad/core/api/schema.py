"""JSON-RPC 2.0 request/response schemas for the control API."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

# --- JSON-RPC 2.0 wire format ---


class JsonRpcRequest(BaseModel):
    """JSON-RPC 2.0 request."""

    jsonrpc: str = "2.0"
    method: str
    params: dict[str, Any] = Field(default_factory=dict)
    id: str | int | None = None


class JsonRpcError(BaseModel):
    """JSON-RPC 2.0 error object."""

    code: int
    message: str
    data: Any = None


class JsonRpcResponse(BaseModel):
    """JSON-RPC 2.0 response."""

    jsonrpc: str = "2.0"
    result: Any = None
    error: JsonRpcError | None = None
    id: str | int | None = None


# --- Standard JSON-RPC error codes ---

PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
INTERNAL_ERROR = -32603


# --- Application-level request/response models ---


class SessionCreateParams(BaseModel):
    """Parameters for session.create."""

    channel: str = "cli"
    user_id: str = ""
    workspace_id: str = ""


class SessionCreateResult(BaseModel):
    """Result for session.create."""

    session_id: str


class SessionMessageParams(BaseModel):
    """Parameters for session.message."""

    session_id: str
    content: str
    channel: str = "cli"
    user_id: str | None = None
    workspace_id: str | None = None


class SessionMessageResult(BaseModel):
    """Result for session.message."""

    response: str
    session_id: str


class SessionListResult(BaseModel):
    """Result for session.list."""

    sessions: list[dict[str, Any]]


class AuditQueryParams(BaseModel):
    """Parameters for audit.query."""

    since: str | None = None
    event_type: str | None = None
    session_id: str | None = None
    limit: int = 100


class AuditQueryResult(BaseModel):
    """Result for audit.query."""

    events: list[dict[str, Any]]
    total: int = 0
