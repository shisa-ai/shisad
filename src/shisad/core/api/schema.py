"""JSON-RPC 2.0 request/response schemas for the control API."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import AliasChoices, BaseModel, ConfigDict, Field, StrictInt, StrictStr

from shisad.executors.sandbox import SandboxResult

# --- JSON-RPC 2.0 wire format ---


JsonRpcId = StrictStr | StrictInt


class JsonRpcRequest(BaseModel):
    """JSON-RPC 2.0 request."""

    jsonrpc: str = "2.0"
    method: str
    params: dict[str, Any] = Field(default_factory=dict)
    id: JsonRpcId | None = None


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
    id: JsonRpcId | None = None


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
    mode: Literal["default", "admin_cleanroom"] = "default"
    tone: Literal["strict", "neutral", "friendly"] | None = None


class SessionCreateResult(BaseModel):
    """Result for session.create."""

    session_id: str
    mode: str = "default"


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
    plan_hash: str | None = None
    risk_score: float | None = None
    blocked_actions: int = 0
    confirmation_required_actions: int = 0
    executed_actions: int = 0
    checkpoint_ids: list[str] = Field(default_factory=list)
    checkpoints_created: int = 0
    transcript_root: str | None = None
    lockdown_level: str | None = None
    trust_level: str | None = None
    session_mode: str = "default"
    proposal_only: bool = False
    proposals: list[dict[str, Any]] = Field(default_factory=list)
    cleanroom_block_reasons: list[str] = Field(default_factory=list)
    pending_confirmation_ids: list[str] = Field(default_factory=list)
    output_policy: dict[str, Any] = Field(default_factory=dict)
    delivery: dict[str, Any] = Field(default_factory=dict)


class SessionListEntry(BaseModel):
    model_config = ConfigDict(extra="allow")

    id: str
    state: str = ""
    user_id: str = ""
    workspace_id: str = ""
    channel: str = ""
    mode: str = "default"
    capabilities: list[str] = Field(default_factory=list)
    trust_level: str = ""
    session_key: str | None = None
    created_at: str | None = None
    lockdown_level: str | None = None


class SessionListResult(BaseModel):
    """Result for session.list."""

    sessions: list[SessionListEntry] = Field(default_factory=list)


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


class SessionSetModeParams(_StrictParams):
    """Parameters for session.set_mode."""

    session_id: str
    mode: Literal["default", "admin_cleanroom"] = "default"


class SessionSetModeResult(BaseModel):
    """Result for session.set_mode."""

    session_id: str
    mode: str = "default"
    changed: bool = False
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


class MemoryIngestResult(BaseModel):
    chunk_id: str
    source_id: str
    source_type: str
    collection: str
    created_at: datetime | str
    content_sanitized: str
    extracted_facts: list[dict[str, Any]] = Field(default_factory=list)
    risk_score: float
    original_hash: str
    quarantined: bool = False
    lexical_score: float = 0.0
    semantic_score: float = 0.0
    blended_score: float = 0.0
    corroborated: bool = False


class MemoryRetrieveResult(BaseModel):
    results: list[MemoryIngestResult] = Field(default_factory=list)
    count: int = 0


class MemoryWriteResult(BaseModel):
    kind: str
    reason: str = ""
    entry: dict[str, Any] | None = None


class MemoryListEntry(BaseModel):
    model_config = ConfigDict(extra="allow")

    id: str = Field(default="", validation_alias=AliasChoices("id", "entry_id"))
    entry_type: str = ""
    key: str = ""


class MemoryListResult(BaseModel):
    entries: list[MemoryListEntry] = Field(default_factory=list)
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


class NoteCreateParams(_StrictParams):
    key: str
    content: str
    origin: Literal["user", "external", "inferred"] = "user"
    source_id: str = "cli"
    user_confirmed: bool = False
    confidence: float = 0.8


class NoteListParams(_StrictParams):
    limit: int = 100


class NoteEntryParams(_StrictParams):
    entry_id: str


class NoteExportParams(_StrictParams):
    format: str = "json"


class NoteListResult(BaseModel):
    entries: list[dict[str, Any]] = Field(default_factory=list)
    count: int = 0


class NoteGetResult(BaseModel):
    entry: dict[str, Any] | None = None


class NoteDeleteResult(BaseModel):
    deleted: bool
    entry_id: str


class NoteVerifyResult(BaseModel):
    verified: bool
    entry_id: str


class NoteExportResult(BaseModel):
    format: str
    data: Any = None


class TodoCreateParams(_StrictParams):
    title: str
    details: str = ""
    status: Literal["open", "in_progress", "done"] = "open"
    due_date: str = ""
    origin: Literal["user", "external", "inferred"] = "user"
    source_id: str = "cli"
    user_confirmed: bool = False
    confidence: float = 0.8


class TodoListParams(_StrictParams):
    limit: int = 100


class TodoEntryParams(_StrictParams):
    entry_id: str


class TodoExportParams(_StrictParams):
    format: str = "json"


class TodoListResult(BaseModel):
    entries: list[dict[str, Any]] = Field(default_factory=list)
    count: int = 0


class TodoGetResult(BaseModel):
    entry: dict[str, Any] | None = None


class TodoDeleteResult(BaseModel):
    deleted: bool
    entry_id: str


class TodoVerifyResult(BaseModel):
    verified: bool
    entry_id: str


class TodoExportResult(BaseModel):
    format: str
    data: Any = None


class WebSearchParams(_StrictParams):
    query: str
    limit: int = 5


class WebSearchResult(BaseModel):
    ok: bool
    query: str = ""
    backend: str = ""
    results: list[dict[str, Any]] = Field(default_factory=list)
    taint_labels: list[str] = Field(default_factory=list)
    evidence: dict[str, Any] = Field(default_factory=dict)
    error: str = ""


class WebFetchParams(_StrictParams):
    url: str
    snapshot: bool = False
    max_bytes: int | None = None


class WebFetchResult(BaseModel):
    ok: bool
    url: str = ""
    status_code: int | None = None
    title: str = ""
    content: str = ""
    blocked_reason: str = ""
    truncated: bool = False
    taint_labels: list[str] = Field(default_factory=list)
    evidence: dict[str, Any] = Field(default_factory=dict)
    error: str = ""
    snapshot_path: str = ""


class RealityCheckSearchParams(_StrictParams):
    query: str
    limit: int = 5
    mode: Literal["auto", "local", "remote"] = "auto"


class RealityCheckSearchResult(BaseModel):
    ok: bool
    query: str = ""
    mode: str = "auto"
    results: list[dict[str, Any]] = Field(default_factory=list)
    taint_labels: list[str] = Field(default_factory=list)
    evidence: dict[str, Any] = Field(default_factory=dict)
    error: str = ""


class RealityCheckReadParams(_StrictParams):
    path: str
    max_bytes: int | None = None


class RealityCheckReadResult(BaseModel):
    ok: bool
    path: str = ""
    content: str = ""
    truncated: bool = False
    sha256: str = ""
    taint_labels: list[str] = Field(default_factory=list)
    evidence: dict[str, Any] = Field(default_factory=dict)
    error: str = ""


class FsListParams(_StrictParams):
    path: str = "."
    recursive: bool = False
    limit: int = 200


class FsListResult(BaseModel):
    ok: bool
    path: str = ""
    entries: list[dict[str, Any]] = Field(default_factory=list)
    count: int = 0
    error: str = ""


class FsReadParams(_StrictParams):
    path: str
    max_bytes: int | None = None


class FsReadResult(BaseModel):
    ok: bool
    path: str = ""
    content: str = ""
    truncated: bool = False
    sha256: str = ""
    error: str = ""


class FsWriteParams(_StrictParams):
    path: str
    content: str
    confirm: bool = False


class FsWriteResult(BaseModel):
    ok: bool
    path: str = ""
    written: bool = False
    confirmation_required: bool = False
    bytes_written: int = 0
    error: str = ""


class GitStatusParams(_StrictParams):
    repo_path: str = "."


class GitStatusResult(BaseModel):
    ok: bool
    repo_path: str = ""
    output: str = ""
    error: str = ""


class GitDiffParams(_StrictParams):
    repo_path: str = "."
    ref: str = ""
    max_lines: int = 400


class GitDiffResult(BaseModel):
    ok: bool
    repo_path: str = ""
    output: str = ""
    truncated: bool = False
    error: str = ""


class GitLogParams(_StrictParams):
    repo_path: str = "."
    limit: int = 20


class GitLogResult(BaseModel):
    ok: bool
    repo_path: str = ""
    output: str = ""
    error: str = ""


class TaskCreateParams(_StrictParams):
    schedule: dict[str, Any]
    name: str
    goal: str
    capability_snapshot: list[str] = Field(default_factory=list)
    policy_snapshot_ref: str
    created_by: str
    allowed_recipients: list[str] = Field(default_factory=list)
    allowed_domains: list[str] = Field(default_factory=list)
    delivery_target: dict[str, str] = Field(default_factory=dict)


class TaskDisableParams(_StrictParams):
    task_id: str


class TaskTriggerEventParams(_StrictParams):
    event_type: str
    payload: str = ""


class TaskPendingConfirmationsParams(_StrictParams):
    task_id: str


class TaskCreateResult(BaseModel):
    id: str
    name: str = ""
    schedule: dict[str, Any] = Field(default_factory=dict)
    goal: str = ""
    capability_snapshot: list[str] = Field(default_factory=list)
    policy_snapshot_ref: str = ""
    allowed_recipients: list[str] = Field(default_factory=list)
    allowed_domains: list[str] = Field(default_factory=list)
    delivery_target: dict[str, str] = Field(default_factory=dict)
    created_by: str = ""
    created_at: datetime | str | None = None
    last_triggered_at: datetime | str | None = None
    enabled: bool = True


class TaskListResult(BaseModel):
    tasks: list[TaskCreateResult] = Field(default_factory=list)
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
    message_id: str = ""
    reply_target: str = ""
    thread_id: str = ""


class ChannelIngestParams(_StrictParams):
    message: ChannelMessageParams
    session_id: str = ""


class ChannelIngestResult(SessionMessageResult):
    ingress_risk: float


class ChannelPairingProposalParams(_StrictParams):
    channel: str | None = None
    workspace_hint: str | None = None
    limit: int = 100


class ChannelPairingProposalResult(BaseModel):
    proposal_id: str = ""
    proposal_path: str = ""
    generated_at: str = ""
    entries: list[dict[str, Any]] = Field(default_factory=list)
    invalid_entries: list[dict[str, Any]] = Field(default_factory=list)
    count: int = 0
    config_patch: dict[str, list[str]] = Field(default_factory=dict)
    applied: bool = False


class ActionPendingParams(_StrictParams):
    session_id: str | None = None
    status: str | None = None
    limit: int = 100
    include_ui: bool = True


class ActionDecisionParams(_StrictParams):
    confirmation_id: str
    decision_nonce: str | None = None
    reason: str = ""


class ActionPendingEntry(BaseModel):
    model_config = ConfigDict(extra="allow")

    confirmation_id: str = ""
    decision_nonce: str = ""
    session_id: str = ""
    user_id: str = ""
    workspace_id: str = ""
    status: str = ""
    tool_name: str = ""
    arguments: dict[str, Any] = Field(default_factory=dict)
    reason: str = ""
    capabilities: list[str] = Field(default_factory=list)
    created_at: str = ""
    execute_after: str | None = None
    safe_preview: str | None = None
    warnings: list[str] = Field(default_factory=list)
    leak_check: dict[str, Any] = Field(default_factory=dict)
    status_reason: str | None = None
    preflight_action: dict[str, Any] | None = None


class ActionPendingResult(BaseModel):
    actions: list[ActionPendingEntry] = Field(default_factory=list)
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
    session_id: str
    tool_name: str
    action: str
    effective_policy: dict[str, Any] = Field(default_factory=dict)
    control_plane: dict[str, Any] = Field(default_factory=dict)
    contributors: dict[str, str] = Field(default_factory=dict)


class DaemonStatusResult(BaseModel):
    status: str
    sessions_active: int = 0
    audit_entries: int = 0
    policy_hash: str = ""
    tools_registered: list[str] = Field(default_factory=list)
    model_routes: dict[str, str] = Field(default_factory=dict)
    classifier_mode: str = ""
    yara_required: bool = False
    risk_policy_version: str = ""
    risk_thresholds: dict[str, float] = Field(default_factory=dict)
    channels: dict[str, Any] = Field(default_factory=dict)
    delivery: dict[str, Any] = Field(default_factory=dict)
    executors: dict[str, Any] = Field(default_factory=dict)
    realitycheck: dict[str, Any] = Field(default_factory=dict)
    provenance: dict[str, Any] = Field(default_factory=dict)


class DoctorCheckParams(_StrictParams):
    component: str = "all"


class DoctorCheckResult(BaseModel):
    status: str
    component: str = "all"
    checks: dict[str, Any] = Field(default_factory=dict)
    error: str = ""


class DaemonShutdownResult(BaseModel):
    status: str


class LockdownSetResult(BaseModel):
    session_id: str
    level: str
    reason: str


class RiskCalibrateResult(BaseModel):
    version: str
    thresholds: dict[str, float] = Field(default_factory=dict)
    updated_at: datetime | str | None = None


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
    manifest: dict[str, Any] = Field(default_factory=dict)
    files: list[dict[str, Any]] = Field(default_factory=list)
    findings: list[dict[str, Any]] = Field(default_factory=list)
    signature: str = ""
    signature_reason: str = ""
    summary: str = ""
    diff: list[dict[str, Any]] = Field(default_factory=list)
    reputation: dict[str, Any] | None = None


class SkillInstallParams(_StrictParams):
    skill_path: str
    approve_untrusted: bool = False


class SkillInstallResult(BaseModel):
    allowed: bool
    status: str
    reason: str = ""
    findings: list[dict[str, Any]] = Field(default_factory=list)
    summary: str = ""
    artifact_state: str = ""
    reputation: dict[str, Any] | None = None


class SkillProfileParams(_StrictParams):
    skill_path: str


class SkillProfileResult(BaseModel):
    network_domains: list[str] = Field(default_factory=list)
    filesystem_paths: list[str] = Field(default_factory=list)
    shell_commands: list[str] = Field(default_factory=list)
    environment_vars: list[str] = Field(default_factory=list)


class SkillRevokeParams(_StrictParams):
    skill_name: str
    reason: str = "security_revoke"


class SkillListEntry(BaseModel):
    model_config = ConfigDict(extra="allow")

    name: str = ""
    version: str = ""
    path: str = ""
    manifest_hash: str = ""
    state: str = ""
    author: str = ""


class SkillListResult(BaseModel):
    skills: list[SkillListEntry] = Field(default_factory=list)
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


class DashboardEventEntry(BaseModel):
    model_config = ConfigDict(extra="allow")

    timestamp: str | None = None
    event_type: str | None = None
    session_id: str | None = None
    actor: str | None = None
    data: dict[str, Any] = Field(default_factory=dict)


class DashboardAlertEntry(BaseModel):
    model_config = ConfigDict(extra="allow")

    event_id: str = ""
    event_type: str = ""
    acknowledged_reason: str = ""


class DashboardTimelineEntry(BaseModel):
    model_config = ConfigDict(extra="allow")

    skill_name: str = ""
    versions: list[str] = Field(default_factory=list)
    events: list[dict[str, Any]] = Field(default_factory=list)


class DashboardQueryResult(BaseModel):
    events: list[DashboardEventEntry] = Field(default_factory=list)
    alerts: list[DashboardAlertEntry] = Field(default_factory=list)
    total: int = 0
    count: int = 0
    hash_chain: dict[str, Any] | None = None
    installed: list[SkillListEntry] = Field(default_factory=list)
    timeline: list[DashboardTimelineEntry] = Field(default_factory=list)


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
