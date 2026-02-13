"""JSON-RPC 2.0 request/response schemas for the control API."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from shisad.executors.sandbox import SandboxResult

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

    model_config = ConfigDict(extra="allow")
    response: str
    session_id: str


class SessionListResult(BaseModel):
    """Result for session.list."""

    sessions: list[dict[str, Any]]


class SessionRestoreParams(_StrictParams):
    """Parameters for session.restore."""

    checkpoint_id: str


class SessionRollbackParams(_StrictParams):
    """Parameters for session.rollback."""

    checkpoint_id: str


class SessionRestoreResult(BaseModel):
    """Result for session.restore."""

    restored: bool
    session_id: str | None = None
    checkpoint_id: str


class SessionRollbackResult(BaseModel):
    """Result for session.rollback."""

    rolled_back: bool
    checkpoint_id: str
    session_id: str | None = None
    files_restored: int = 0
    files_deleted: int = 0
    restore_errors: list[str] = Field(default_factory=list)


class SessionGrantCapabilitiesParams(_StrictParams):
    """Parameters for session.grant_capabilities."""

    session_id: str
    capabilities: list[str] = Field(default_factory=list)
    actor: str | None = None
    reason: str = ""


class SessionGrantCapabilitiesResult(BaseModel):
    """Result for session.grant_capabilities."""

    session_id: str
    granted: bool
    capabilities: list[str] = Field(default_factory=list)


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


class MemoryIngestResult(BaseModel):
    model_config = ConfigDict(extra="allow")


class MemoryRetrieveResult(BaseModel):
    results: list[dict[str, Any]] = Field(default_factory=list)
    count: int = 0


class MemoryWriteResult(BaseModel):
    model_config = ConfigDict(extra="allow")


class MemoryListResult(BaseModel):
    entries: list[dict[str, Any]] = Field(default_factory=list)
    count: int = 0


class MemoryGetResult(BaseModel):
    entry: dict[str, Any] | None = None


class MemoryDeleteResult(BaseModel):
    deleted: bool
    entry_id: str


class MemoryExportResult(BaseModel):
    format: str
    data: Any = None


class MemoryVerifyResult(BaseModel):
    verified: bool
    entry_id: str


class MemoryRotateKeyResult(BaseModel):
    rotated: bool
    active_key_id: str
    reencrypt_existing: bool


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


class TaskCreateResult(BaseModel):
    model_config = ConfigDict(extra="allow")


class TaskListResult(BaseModel):
    tasks: list[dict[str, Any]] = Field(default_factory=list)
    count: int = 0


class TaskDisableResult(BaseModel):
    disabled: bool
    task_id: str


class TaskTriggerEventResult(BaseModel):
    runs: list[dict[str, Any]] = Field(default_factory=list)
    count: int = 0
    queued_confirmations: int = 0
    blocked_runs: int = 0


class TaskPendingConfirmationsResult(BaseModel):
    task_id: str
    pending: list[dict[str, Any]] = Field(default_factory=list)
    count: int = 0


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


class ChannelIngestResult(SessionMessageResult):
    ingress_risk: float


class ActionPendingParams(_StrictParams):
    session_id: str | None = None
    status: str | None = None
    limit: int = 100
    include_ui: bool = True


class ActionDecisionParams(_StrictParams):
    confirmation_id: str
    decision_nonce: str | None = None
    reason: str = ""


class ActionPendingResult(BaseModel):
    actions: list[dict[str, Any]] = Field(default_factory=list)
    count: int = 0


class ActionConfirmResult(BaseModel):
    confirmed: bool
    confirmation_id: str
    decision_nonce: str | None = None
    status: str | None = None
    status_reason: str | None = None
    checkpoint_id: str | None = None
    reason: str | None = None
    retry_after_seconds: float | None = None


class ActionRejectResult(BaseModel):
    rejected: bool
    confirmation_id: str
    status: str | None = None
    status_reason: str | None = None
    reason: str | None = None


class PolicyExplainParams(_StrictParams):
    session_id: str | None = None
    action: str = ""
    tool_name: str | None = None


class PolicyExplainResult(BaseModel):
    model_config = ConfigDict(extra="allow")
    session_id: str
    tool_name: str
    action: str
    effective_policy: dict[str, Any] = Field(default_factory=dict)
    control_plane: dict[str, Any] = Field(default_factory=dict)
    contributors: dict[str, str] = Field(default_factory=dict)


class DaemonStatusResult(BaseModel):
    model_config = ConfigDict(extra="allow")
    status: str


class DaemonShutdownResult(BaseModel):
    status: str


class LockdownSetResult(BaseModel):
    session_id: str
    level: str
    reason: str


class RiskCalibrateResult(BaseModel):
    model_config = ConfigDict(extra="allow")


class ToolExecuteParams(_StrictParams):
    session_id: str
    tool_name: str
    skill_name: str | None = None
    command: list[str] = Field(min_length=1)
    read_paths: list[str] = Field(default_factory=list)
    write_paths: list[str] = Field(default_factory=list)
    network_urls: list[str] = Field(default_factory=list)
    env: dict[str, str] = Field(default_factory=dict)
    cwd: str = ""
    sandbox_type: str | None = None
    security_critical: bool = True
    request_headers: dict[str, str] = Field(default_factory=dict)
    request_body: str = ""
    source_ids: list[str] = Field(default_factory=list)
    explicit_share_intent: bool = False
    degraded_mode: str = "fail_closed"
    filesystem: dict[str, Any] = Field(default_factory=dict)
    network: dict[str, Any] = Field(default_factory=dict)
    environment: dict[str, Any] = Field(default_factory=dict)
    limits: dict[str, Any] = Field(default_factory=dict)


class ToolExecuteResult(SandboxResult):
    """Result envelope for tool.execute, including confirmation metadata."""

    model_config = ConfigDict(extra="allow")
    confirmation_required: bool | None = None
    confirmation_id: str | None = None
    decision_nonce: str | None = None
    safe_preview: str | None = None
    warnings: list[str] = Field(default_factory=list)
    execute_after: str | None = None


class BrowserPasteParams(_StrictParams):
    session_id: str
    text: str
    taint_labels: list[str] = Field(default_factory=list)


class BrowserScreenshotParams(_StrictParams):
    session_id: str
    image_base64: str
    ocr_text: str = ""


class SkillReviewParams(_StrictParams):
    skill_path: str


class SkillReviewResult(BaseModel):
    model_config = ConfigDict(extra="allow")


class SkillInstallParams(_StrictParams):
    skill_path: str
    approve_untrusted: bool = False


class SkillInstallResult(BaseModel):
    model_config = ConfigDict(extra="allow")


class SkillProfileParams(_StrictParams):
    skill_path: str


class SkillProfileResult(BaseModel):
    model_config = ConfigDict(extra="allow")


class SkillRevokeParams(_StrictParams):
    skill_name: str
    reason: str = "security_revoke"


class SkillListResult(BaseModel):
    skills: list[dict[str, Any]] = Field(default_factory=list)
    count: int = 0


class SkillRevokeResult(BaseModel):
    revoked: bool
    skill_name: str
    reason: str
    state: str | None = None


class DashboardQueryParams(_StrictParams):
    since: str | None = None
    event_type: str | None = None
    session_id: str | None = None
    actor: str | None = None
    text_search: str = ""
    limit: int = 100


class DashboardMarkFalsePositiveParams(_StrictParams):
    event_id: str
    reason: str = "false_positive"


class DashboardQueryResult(BaseModel):
    model_config = ConfigDict(extra="allow")


class DashboardMarkFalsePositiveResult(BaseModel):
    marked: bool
    event_id: str
    reason: str


class ConfirmationMetricsParams(_StrictParams):
    user_id: str | None = None
    window_seconds: int = 900


class ConfirmationMetricsResult(BaseModel):
    metrics: list[dict[str, Any]] = Field(default_factory=list)
    count: int = 0
