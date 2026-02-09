"""JSON-RPC 2.0 request/response schemas for the control API."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

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


class _StrictParams(BaseModel):
    """Base schema with explicit parameter surface."""

    model_config = ConfigDict(extra="forbid")


class NoParams(_StrictParams):
    """Methods that do not accept parameters."""


class SessionCreateParams(_StrictParams):
    """Parameters for session.create."""

    channel: str = "cli"
    user_id: str = ""
    workspace_id: str = ""


class SessionCreateResult(BaseModel):
    """Result for session.create."""

    session_id: str


class SessionMessageParams(_StrictParams):
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


class SessionRestoreParams(_StrictParams):
    """Parameters for session.restore."""

    checkpoint_id: str


class SessionRestoreResult(BaseModel):
    """Result for session.restore."""

    restored: bool
    session_id: str | None = None
    checkpoint_id: str


class SessionGrantCapabilitiesParams(_StrictParams):
    """Parameters for session.grant_capabilities."""

    session_id: str
    capabilities: list[str] = Field(default_factory=list)
    actor: str | None = None
    reason: str = ""


class AuditQueryParams(_StrictParams):
    """Parameters for audit.query."""

    since: str | None = None
    event_type: str | None = None
    session_id: str | None = None
    actor: str | None = None
    limit: int = 100


class AuditQueryResult(BaseModel):
    """Result for audit.query."""

    events: list[dict[str, Any]]
    total: int = 0


class MemoryIngestParams(_StrictParams):
    source_id: str
    source_type: str = "user"
    content: str
    collection: str | None = None


class MemoryRetrieveParams(_StrictParams):
    query: str
    limit: int = 5
    capabilities: list[str] = Field(default_factory=list)
    require_corroboration: bool = False


class MemoryWriteParams(_StrictParams):
    source: dict[str, Any]
    entry_type: str = "fact"
    key: str
    value: Any = None
    confidence: float = 0.5
    user_confirmed: bool = False


class MemoryListParams(_StrictParams):
    limit: int = 100


class MemoryEntryParams(_StrictParams):
    entry_id: str


class MemoryExportParams(_StrictParams):
    format: str = "json"


class MemoryRotateKeyParams(_StrictParams):
    reencrypt_existing: bool = True


class TaskCreateParams(_StrictParams):
    schedule: dict[str, Any]
    name: str
    goal: str
    capability_snapshot: list[str] = Field(default_factory=list)
    policy_snapshot_ref: str
    created_by: str
    allowed_recipients: list[str] = Field(default_factory=list)
    allowed_domains: list[str] = Field(default_factory=list)


class TaskDisableParams(_StrictParams):
    task_id: str


class TaskTriggerEventParams(_StrictParams):
    event_type: str
    payload: str = ""


class TaskPendingConfirmationsParams(_StrictParams):
    task_id: str


class LockdownSetParams(_StrictParams):
    session_id: str
    action: str = "caution"
    reason: str = "manual"


class ChannelMessageParams(_StrictParams):
    channel: str
    external_user_id: str
    workspace_hint: str = ""
    content: str


class ChannelIngestParams(_StrictParams):
    message: ChannelMessageParams
    session_id: str = ""


class ActionPendingParams(_StrictParams):
    session_id: str | None = None
    status: str | None = None
    limit: int = 100


class ActionDecisionParams(_StrictParams):
    confirmation_id: str
    reason: str = ""
