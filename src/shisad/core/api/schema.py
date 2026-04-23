"""JSON-RPC 2.0 request/response schemas for the control API."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import (
    AliasChoices,
    BaseModel,
    ConfigDict,
    Field,
    StrictInt,
    StrictStr,
    model_validator,
)

from shisad.executors.sandbox import SandboxResult
from shisad.memory.schema import MemoryEntryType

# --- JSON-RPC 2.0 wire format ---


JsonRpcId = StrictStr | StrictInt
MemoryScope = Literal["user", "project", "session", "channel", "workspace"]


def _default_user_scope_filter() -> list[MemoryScope]:
    return ["user"]


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
    role: str = "orchestrator"


class SessionMessageParams(_StrictParams):
    """Parameters for session.message."""

    session_id: str
    content: str
    channel: str = "cli"
    user_id: str | None = None
    workspace_id: str | None = None
    task: SessionTaskParams | None = None


class SessionTaskParams(_StrictParams):
    """Optional delegated TASK-session request carried on session.message."""

    enabled: bool = False
    task_description: str = ""
    file_refs: list[str] = Field(default_factory=list)
    capabilities: list[str] | None = None
    executor: Literal["planner", "coding_agent"] = "planner"
    preferred_agent: str | None = None
    fallback_agents: list[str] = Field(default_factory=list)
    read_only: bool = False
    task_kind: Literal["generic", "implement", "review"] = "generic"
    max_turns: int | None = None
    max_budget_usd: float | None = None
    model: str | None = None
    reasoning_effort: str | None = None
    timeout_sec: float | None = None
    handoff_mode: Literal["summary_only", "raw_passthrough"] = "summary_only"
    credential_refs: list[str] = Field(default_factory=list)
    resource_scope_ids: list[str] = Field(default_factory=list)
    resource_scope_prefixes: list[str] = Field(default_factory=list)


class SessionTaskResult(BaseModel):
    """Structured TASK -> COMMAND handoff payload."""

    success: bool
    summary: str = ""
    files_changed: list[str] = Field(default_factory=list)
    cost: float | None = None
    agent: str | None = None
    duration_ms: int = 0
    proposal_ref: str | None = None
    raw_log_ref: str | None = None
    summary_checkpoint_ref: str | None = None
    task_session_id: str = ""
    task_session_mode: str = "task"
    handoff_mode: str = "summary_only"
    command_context: str = "clean"
    recovery_checkpoint_id: str | None = None
    reason: str = ""
    taint_labels: list[str] = Field(default_factory=list)
    self_check_status: str = ""
    self_check_ref: str | None = None


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
    planner_error: str = ""
    tool_outputs: list[dict[str, Any]] = Field(default_factory=list)
    delivery: dict[str, Any] = Field(default_factory=dict)
    task_result: SessionTaskResult | None = None


class SessionListEntry(BaseModel):
    model_config = ConfigDict(extra="allow")

    id: str
    state: str = ""
    role: str = "orchestrator"
    user_id: str = ""
    workspace_id: str = ""
    channel: str = ""
    mode: str = "default"
    capabilities: list[str] = Field(default_factory=list)
    trust_level: str = ""
    session_key: str | None = None
    created_at: str | None = None
    lockdown_level: str | None = None
    command_context: str = "clean"
    recovery_checkpoint_id: str | None = None
    parent_session_id: str | None = None


class SessionListResult(BaseModel):
    """Result for session.list."""

    sessions: list[SessionListEntry] = Field(default_factory=list)


class SessionTerminateParams(_StrictParams):
    """Parameters for session.terminate."""

    session_id: str
    channel: str = ""
    user_id: str = ""
    workspace_id: str = ""
    reason: str = ""


class SessionTerminateResult(BaseModel):
    """Result for session.terminate."""

    session_id: str
    terminated: bool
    reason: str = ""


class SessionRestoreParams(_StrictParams):
    """Parameters for session.restore."""

    checkpoint_id: str


class SessionRollbackParams(_StrictParams):
    """Parameters for session.rollback."""

    checkpoint_id: str


class SessionExportParams(_StrictParams):
    """Parameters for session.export."""

    session_id: str
    path: str | None = None


class SessionImportParams(_StrictParams):
    """Parameters for session.import."""

    archive_path: str


class SessionRestoreResult(BaseModel):
    """Result for session.restore."""

    restored: bool
    session_id: str | None = None
    checkpoint_id: str
    reason: str = ""


class SessionRollbackResult(BaseModel):
    """Result for session.rollback."""

    rolled_back: bool
    checkpoint_id: str
    session_id: str | None = None
    files_restored: int = 0
    files_deleted: int = 0
    transcript_entries_removed: int = 0
    restore_errors: list[str] = Field(default_factory=list)
    reason: str = ""


class SessionExportResult(BaseModel):
    """Result for session.export."""

    exported: bool
    session_id: str | None = None
    archive_path: str = ""
    sha256: str = ""
    transcript_entries: int = 0
    checkpoint_count: int = 0
    reason: str = ""


class SessionImportResult(BaseModel):
    """Result for session.import."""

    imported: bool
    session_id: str | None = None
    original_session_id: str | None = None
    archive_path: str = ""
    checkpoint_ids: list[str] = Field(default_factory=list)
    transcript_entries: int = 0
    checkpoint_count: int = 0
    reason: str = ""


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
    ingress_context: str
    content: str
    collection: str | None = None
    content_digest: str | None = None
    derivation_path: Literal["direct", "extracted", "summary"] = "direct"
    parent_digest: str | None = None

    @model_validator(mode="after")
    def _validate_ingest_source_shape(self) -> MemoryIngestParams:
        if not self.ingress_context.strip():
            raise ValueError("ingress_context is required")
        return self


class MemoryRetrieveParams(_StrictParams):
    query: str
    limit: int = 5
    capabilities: list[str] = Field(default_factory=list)
    require_corroboration: bool = False
    max_tokens: int | None = None
    as_of: datetime | None = None
    include_archived: bool = False
    scope_filter: list[Literal["user", "project", "session", "channel", "workspace"]] | None = (
        None
    )


class MemoryWriteParams(_StrictParams):
    ingress_context: str
    content_digest: str | None = None
    derivation_path: Literal["direct", "extracted", "summary"] = "direct"
    parent_digest: str | None = None
    entry_type: MemoryEntryType | Literal["context"] = "fact"
    key: str
    value: Any = None
    predicate: str | None = None
    strength: Literal["weak", "moderate", "strong"] = "moderate"
    confidence: float = 0.5
    workflow_state: Literal["active", "waiting", "blocked", "stale", "closed"] | None = None
    invocation_eligible: bool = False
    supersedes: str | None = None

    @model_validator(mode="after")
    def _validate_ingress_shape(self) -> MemoryWriteParams:
        if not self.ingress_context.strip():
            raise ValueError("ingress_context is required")
        return self


class MemoryMintIngressParams(_StrictParams):
    content: Any
    source_type: Literal["user", "external", "tool"] = "user"
    source_id: str | None = None
    user_confirmed: bool = False

    @model_validator(mode="after")
    def _validate_confirmation_shape(self) -> MemoryMintIngressParams:
        if self.user_confirmed and self.source_type != "user":
            raise ValueError("user_confirmed requires source_type=user")
        return self


class MemoryPromoteIdentityCandidateParams(_StrictParams):
    ingress_context: str
    candidate_id: str
    value: Any = None

    @model_validator(mode="after")
    def _validate_candidate_shape(self) -> MemoryPromoteIdentityCandidateParams:
        if not self.ingress_context.strip():
            raise ValueError("ingress_context is required")
        if not self.candidate_id.strip():
            raise ValueError("candidate_id is required")
        return self


class MemoryPromoteSkillParams(_StrictParams):
    ingress_context: str
    entry_id: str

    @model_validator(mode="after")
    def _validate_entry_shape(self) -> MemoryPromoteSkillParams:
        if not self.ingress_context.strip():
            raise ValueError("ingress_context is required")
        if not self.entry_id.strip():
            raise ValueError("entry_id is required")
        return self


class MemoryRejectIdentityCandidateParams(_StrictParams):
    ingress_context: str
    candidate_id: str

    @model_validator(mode="after")
    def _validate_candidate_shape(self) -> MemoryRejectIdentityCandidateParams:
        if not self.ingress_context.strip():
            raise ValueError("ingress_context is required")
        if not self.candidate_id.strip():
            raise ValueError("candidate_id is required")
        return self


class MemorySupersedeParams(MemoryWriteParams):
    supersedes: str

    @model_validator(mode="after")
    def _validate_supersedes(self) -> MemorySupersedeParams:
        if not self.supersedes.strip():
            raise ValueError("supersedes is required")
        return self


class MemoryListParams(_StrictParams):
    limit: int = 100
    include_deleted: bool = False
    include_quarantined: bool = False
    confirmed: bool = False

    @model_validator(mode="after")
    def _validate_history_flags(self) -> MemoryListParams:
        if self.include_quarantined and not self.confirmed:
            raise ValueError("confirmed is required when include_quarantined is true")
        return self


class MemoryReviewQueueParams(_StrictParams):
    limit: int = 100


class MemoryReadOriginalParams(_StrictParams):
    chunk_id: str

    @model_validator(mode="after")
    def _validate_chunk_id(self) -> MemoryReadOriginalParams:
        if not self.chunk_id.strip():
            raise ValueError("chunk_id is required")
        return self


class MemoryInvokeSkillParams(_StrictParams):
    skill_id: str

    @model_validator(mode="after")
    def _validate_skill_id(self) -> MemoryInvokeSkillParams:
        if not self.skill_id.strip():
            raise ValueError("skill_id is required")
        return self


class MemoryEntryParams(_StrictParams):
    entry_id: str
    include_deleted: bool = False
    include_quarantined: bool = False
    confirmed: bool = False

    @model_validator(mode="after")
    def _validate_history_flags(self) -> MemoryEntryParams:
        if self.include_quarantined and not self.confirmed:
            raise ValueError("confirmed is required when include_quarantined is true")
        return self


class MemoryLifecycleParams(_StrictParams):
    entry_id: str
    reason: str

    @model_validator(mode="after")
    def _validate_reason(self) -> MemoryLifecycleParams:
        if not self.reason.strip():
            raise ValueError("reason is required")
        return self


class MemoryWorkflowStateParams(_StrictParams):
    entry_id: str
    workflow_state: Literal["active", "waiting", "blocked", "stale", "closed"]


class MemoryExportParams(_StrictParams):
    format: str = "json"


class GraphQueryParams(_StrictParams):
    entity: str
    depth: int = 1
    limit: int = 20
    scope_filter: list[MemoryScope] = Field(default_factory=_default_user_scope_filter)

    @model_validator(mode="after")
    def _validate_graph_query(self) -> GraphQueryParams:
        if not self.entity.strip():
            raise ValueError("entity is required")
        self.depth = max(1, min(3, int(self.depth)))
        self.limit = max(1, min(100, int(self.limit)))
        return self


class GraphExportParams(_StrictParams):
    format: Literal["json", "md"] = "json"
    scope_filter: list[MemoryScope] = Field(default_factory=_default_user_scope_filter)


class MemoryConsolidateParams(_StrictParams):
    recompute_scores: bool = True
    apply_confidence_updates: bool = True
    propose_strong_invalidations: bool = True
    accumulate_identity_candidates: bool = True
    scope_filter: list[MemoryScope] = Field(default_factory=_default_user_scope_filter)


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
    source_origin: str = ""
    channel_trust: str = ""
    confirmation_status: str = ""
    scope: str = ""
    trust_band: str = ""
    trust_caveat: str | None = None
    quarantined: bool = False
    citation_count: int = 0
    last_cited_at: datetime | str | None = None
    lexical_score: float = 0.0
    semantic_score: float = 0.0
    blended_score: float = 0.0
    confidence: float = 0.5
    importance_weight: float = 1.0
    decay_score: float = 1.0
    effective_score: float = 0.0
    corroborated: bool = False
    archived: bool = False
    stale: bool = False
    verification_gap: bool = False
    revision_churn: bool = False
    conflict: bool = False


class MemoryMintIngressResult(BaseModel):
    ingress_context: str
    content_digest: str
    source_origin: str
    channel_trust: str
    confirmation_status: str
    scope: str
    source_id: str


class MemoryRetrieveResult(BaseModel):
    results: list[MemoryIngestResult] = Field(default_factory=list)
    count: int = 0
    max_tokens: int | None = None
    as_of: datetime | str | None = None
    include_archived: bool = False


class MemoryReadOriginalResult(BaseModel):
    chunk_id: str
    found: bool = False
    content: str | None = None


class MemoryProceduralArtifactResult(BaseModel):
    id: str = Field(default="", validation_alias=AliasChoices("id", "entry_id"))
    entry_type: str = ""
    key: str = ""
    name: str = ""
    description: str = ""
    content: str = ""
    trust_band: str = ""
    source_origin: str = ""
    channel_trust: str = ""
    confirmation_status: str = ""
    last_used_at: datetime | str | None = None
    size_bytes: int = 0
    invocation_eligible: bool = False
    prior_entry_id: str | None = None
    diff_preview: str | None = None


class MemoryInvokeSkillResult(BaseModel):
    skill_id: str
    found: bool = False
    invoked: bool = False
    reason: str = ""
    artifact: MemoryProceduralArtifactResult | None = None


class MemoryWriteResult(BaseModel):
    kind: str
    reason: str = ""
    entry: dict[str, Any] | None = None


class MemoryIdentityCandidateResult(BaseModel):
    changed: bool
    candidate_id: str
    reason: str = ""


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


class MemoryLifecycleResult(BaseModel):
    changed: bool
    entry_id: str
    reason: str = ""


class MemoryWorkflowStateResult(BaseModel):
    changed: bool
    entry_id: str
    workflow_state: str = ""


class MemoryExportResult(BaseModel):
    format: str
    data: Any = None


class GraphQueryResult(BaseModel):
    root_entity_id: str = ""
    nodes: list[dict[str, Any]] = Field(default_factory=list)
    edges: list[dict[str, Any]] = Field(default_factory=list)


class GraphExportResult(BaseModel):
    format: str
    data: Any = None


class MemoryConsolidateResult(BaseModel):
    updated_entry_ids: list[str] = Field(default_factory=list)
    corroborating_entry_ids: list[str] = Field(default_factory=list)
    contradicted_entry_ids: list[str] = Field(default_factory=list)
    merged_entry_ids: list[str] = Field(default_factory=list)
    archive_candidate_ids: list[str] = Field(default_factory=list)
    quarantined_entry_ids: list[str] = Field(default_factory=list)
    strong_invalidation_count: int = 0
    identity_candidate_count: int = 0
    strong_invalidations: list[dict[str, Any]] = Field(default_factory=list)
    identity_candidate_ids: list[str] = Field(default_factory=list)
    capability_scope: dict[str, Any] = Field(default_factory=dict)


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
    ingress_context: str | None = None
    content_digest: str | None = None
    derivation_path: Literal["direct", "extracted", "summary"] = "direct"
    parent_digest: str | None = None
    confidence: float = 0.8

    @model_validator(mode="after")
    def _validate_ingress_shape(self) -> NoteCreateParams:
        if self.ingress_context is None:
            if self.content_digest is not None:
                raise ValueError("content_digest requires ingress_context")
            if self.parent_digest is not None:
                raise ValueError("parent_digest requires ingress_context")
            if self.derivation_path != "direct":
                raise ValueError("non-direct derivation requires ingress_context")
        return self


class NoteListParams(_StrictParams):
    limit: int = 100


class NoteSearchParams(_StrictParams):
    query: str
    limit: int = 20


class NoteEntryParams(_StrictParams):
    entry_id: str


class NoteExportParams(_StrictParams):
    format: str = "json"


class NoteListResult(BaseModel):
    entries: list[dict[str, Any]] = Field(default_factory=list)
    count: int = 0


class NoteGetResult(BaseModel):
    entry: dict[str, Any] | None = None


class NoteSearchResult(BaseModel):
    query: str = ""
    entries: list[dict[str, Any]] = Field(default_factory=list)
    count: int = 0


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
    ingress_context: str | None = None
    content_digest: str | None = None
    derivation_path: Literal["direct", "extracted", "summary"] = "direct"
    parent_digest: str | None = None
    confidence: float = 0.8

    @model_validator(mode="after")
    def _validate_ingress_shape(self) -> TodoCreateParams:
        if self.ingress_context is None:
            if self.content_digest is not None:
                raise ValueError("content_digest requires ingress_context")
            if self.parent_digest is not None:
                raise ValueError("parent_digest requires ingress_context")
            if self.derivation_path != "direct":
                raise ValueError("non-direct derivation requires ingress_context")
        return self


class TodoListParams(_StrictParams):
    limit: int = 100


class TodoEntryParams(_StrictParams):
    entry_id: str


class TodoCompleteParams(_StrictParams):
    selector: str


class TodoExportParams(_StrictParams):
    format: str = "json"


class TodoListResult(BaseModel):
    entries: list[dict[str, Any]] = Field(default_factory=list)
    count: int = 0


class TodoGetResult(BaseModel):
    entry: dict[str, Any] | None = None


class TodoCompleteResult(BaseModel):
    completed: bool
    entry_id: str = ""
    entry: dict[str, Any] | None = None
    reason: str = ""
    matches: list[dict[str, Any]] = Field(default_factory=list)


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


class EmailSearchParams(_StrictParams):
    query: str
    limit: int = 10
    offset: int = 0
    account: str = ""


class EmailSearchResult(BaseModel):
    ok: bool
    operation: str = "email.search"
    query: str = ""
    account: str = ""
    limit: int = 0
    offset: int = 0
    count: int = 0
    results: list[dict[str, Any]] = Field(default_factory=list)
    taint_labels: list[str] = Field(default_factory=list)
    evidence: dict[str, Any] = Field(default_factory=dict)
    actionable: str = ""
    error: str = ""


class EmailReadParams(_StrictParams):
    message_id: str
    account: str = ""


class EmailReadResult(BaseModel):
    ok: bool
    operation: str = "email.read"
    message_id: str = ""
    account: str = ""
    message: dict[str, Any] | None = None
    taint_labels: list[str] = Field(default_factory=list)
    evidence: dict[str, Any] = Field(default_factory=dict)
    actionable: str = ""
    error: str = ""


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
    workspace_id: str = Field(min_length=1)
    allowed_recipients: list[str] = Field(default_factory=list)
    allowed_domains: list[str] = Field(default_factory=list)
    delivery_target: dict[str, str] = Field(default_factory=dict)
    credential_refs: list[str] = Field(default_factory=list)
    resource_scope_ids: list[str] = Field(default_factory=list)
    resource_scope_prefixes: list[str] = Field(default_factory=list)
    untrusted_payload_action: Literal["require_confirmation", "reject"] = "require_confirmation"
    max_runs: int = Field(default=0, ge=0)


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
    task_envelope: dict[str, Any] = Field(default_factory=dict)
    allowed_recipients: list[str] = Field(default_factory=list)
    allowed_domains: list[str] = Field(default_factory=list)
    delivery_target: dict[str, str] = Field(default_factory=dict)
    created_by: str = ""
    workspace_id: str = ""
    created_at: datetime | str | None = None
    last_triggered_at: datetime | str | None = None
    trigger_count: int = 0
    success_count: int = 0
    failure_count: int = 0
    max_runs: int = 0
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
    metadata: dict[str, Any] = Field(default_factory=dict)


class ChannelIngestParams(_StrictParams):
    message: ChannelMessageParams
    session_id: str = ""


class ChannelIngestResult(SessionMessageResult):
    ingress_risk: float
    channel_policy: dict[str, Any] = Field(default_factory=dict)


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
    confirmation_id: str | None = None
    session_id: str | None = None
    status: str | None = None
    limit: int = 100
    include_ui: bool = True


class ActionPurgeParams(_StrictParams):
    session_id: str | None = None
    status: str = "terminal"
    older_than_days: int | None = None
    limit: int = 1000
    dry_run: bool = False


class ActionDecisionParams(_StrictParams):
    confirmation_id: str
    decision_nonce: str | None = None
    reason: str = ""
    approval_method: str | None = None
    principal_id: str | None = None
    credential_id: str | None = None
    proof: dict[str, Any] | None = None


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
    approval_task_envelope_id: str = ""
    required_level: str = ""
    required_methods: list[str] = Field(default_factory=list)
    allowed_principals: list[str] = Field(default_factory=list)
    allowed_credentials: list[str] = Field(default_factory=list)
    required_capabilities: dict[str, Any] = Field(default_factory=dict)
    approval_envelope: dict[str, Any] | None = None
    approval_envelope_hash: str = ""
    intent_envelope: dict[str, Any] | None = None
    fallback: dict[str, Any] = Field(default_factory=dict)
    expires_at: str | None = None
    selected_backend_id: str = ""
    selected_backend_method: str = ""
    fallback_used: bool = False
    status_reason: str | None = None
    preflight_action: dict[str, Any] | None = None
    merged_policy: dict[str, Any] | None = None
    approval_url: str | None = None
    approval_qr_ascii: str | None = None
    helper_origin: str | None = None
    helper_rp_id: str | None = None
    helper_public_key: dict[str, Any] | None = None


class ActionPendingResult(BaseModel):
    actions: list[ActionPendingEntry] = Field(default_factory=list)
    count: int = 0


class ActionPurgeResult(BaseModel):
    purged: int = 0
    confirmation_ids: list[str] = Field(default_factory=list)
    remaining: int = 0
    dry_run: bool = False


class ActionConfirmResult(BaseModel):
    confirmed: bool
    confirmation_id: str
    decision_nonce: str | None = None
    status: str | None = None
    status_reason: str | None = None
    checkpoint_id: str | None = None
    reason: str | None = None
    retry_after_seconds: float | None = None
    approval_level: str | None = None
    approval_method: str | None = None


class ActionRejectResult(BaseModel):
    rejected: bool
    confirmation_id: str
    status: str | None = None
    status_reason: str | None = None
    reason: str | None = None


class TwoFactorRegisterBeginParams(_StrictParams):
    method: str = "totp"
    user_id: str
    name: str | None = None


class TwoFactorRegisterBeginResult(BaseModel):
    started: bool
    enrollment_id: str = ""
    user_id: str = ""
    method: str = ""
    principal_id: str = ""
    credential_id: str = ""
    secret: str = ""
    otpauth_uri: str = ""
    registration_url: str = ""
    approval_origin: str = ""
    rp_id: str = ""
    helper_origin: str = ""
    helper_rp_id: str = ""
    helper_public_key: dict[str, Any] = Field(default_factory=dict)
    expires_at: str | None = None
    reason: str = ""


class TwoFactorRegisterConfirmParams(_StrictParams):
    enrollment_id: str
    verify_code: str = ""
    proof: dict[str, Any] | None = None


class TwoFactorRegisterConfirmResult(BaseModel):
    registered: bool
    user_id: str = ""
    method: str = ""
    principal_id: str = ""
    credential_id: str = ""
    recovery_codes: list[str] = Field(default_factory=list)
    reason: str = ""


class TwoFactorListParams(_StrictParams):
    user_id: str | None = None
    method: str | None = None


class TwoFactorEntry(BaseModel):
    user_id: str = ""
    method: str = ""
    principal_id: str = ""
    credential_id: str = ""
    created_at: str = ""
    last_verified_at: str | None = None
    last_used_at: str | None = None
    recovery_codes_remaining: int = 0


class TwoFactorListResult(BaseModel):
    entries: list[TwoFactorEntry] = Field(default_factory=list)
    count: int = 0


class TwoFactorRevokeParams(_StrictParams):
    method: str = "totp"
    user_id: str
    credential_id: str | None = None


class TwoFactorRevokeResult(BaseModel):
    revoked: bool
    removed: int = 0
    reason: str = ""


class SignerRegisterParams(_StrictParams):
    backend: str = "kms"
    user_id: str
    key_id: str
    name: str | None = None
    algorithm: str = "ed25519"
    device_type: str = "ledger-enterprise"
    public_key_pem: str


class SignerRegisterResult(BaseModel):
    registered: bool
    backend: str = ""
    user_id: str = ""
    principal_id: str = ""
    credential_id: str = ""
    algorithm: str = ""
    device_type: str = ""
    reason: str = ""


class SignerListParams(_StrictParams):
    user_id: str | None = None
    backend: str | None = None
    include_revoked: bool = False


class SignerEntry(BaseModel):
    user_id: str = ""
    backend: str = ""
    principal_id: str = ""
    credential_id: str = ""
    algorithm: str = ""
    device_type: str = ""
    created_at: str = ""
    last_verified_at: str | None = None
    last_used_at: str | None = None
    revoked: bool = False


class SignerListResult(BaseModel):
    entries: list[SignerEntry] = Field(default_factory=list)
    count: int = 0


class SignerRevokeParams(_StrictParams):
    key_id: str


class SignerRevokeResult(BaseModel):
    revoked: bool
    removed: int = 0
    reason: str = ""


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


class AdminSelfModProposeParams(_StrictParams):
    artifact_path: str


class AdminSelfModApplyParams(_StrictParams):
    proposal_id: str
    confirm: bool = False


class AdminSelfModRollbackParams(_StrictParams):
    change_id: str


class AdminSoulReadParams(_StrictParams):
    """Parameters for admin.soul.read."""


class AdminSoulUpdateParams(_StrictParams):
    """Parameters for admin.soul.update."""

    content: str = ""
    expected_sha256: str | None = None


class DevImplementParams(_StrictParams):
    task: str = Field(min_length=1)
    agent: str | None = None
    file_refs: list[str] = Field(default_factory=list)
    fallback_agents: list[str] = Field(default_factory=list)
    capabilities: list[str] | None = None
    max_turns: int | None = None
    max_budget_usd: float | None = None
    model: str | None = None
    reasoning_effort: str | None = None
    timeout_sec: float | None = None


class DevReviewParams(_StrictParams):
    scope: str = Field(min_length=1)
    agent: str | None = None
    mode: Literal["readonly"] = "readonly"
    file_refs: list[str] = Field(default_factory=list)
    fallback_agents: list[str] = Field(default_factory=list)
    capabilities: list[str] | None = None
    max_turns: int | None = None
    max_budget_usd: float | None = None
    model: str | None = None
    reasoning_effort: str | None = None
    timeout_sec: float | None = None


class DevRemediateParams(_StrictParams):
    findings: str = Field(min_length=1)
    agent: str | None = None
    file_refs: list[str] = Field(default_factory=list)
    fallback_agents: list[str] = Field(default_factory=list)
    capabilities: list[str] | None = None
    max_turns: int | None = None
    max_budget_usd: float | None = None
    model: str | None = None
    reasoning_effort: str | None = None
    timeout_sec: float | None = None


class DevCloseParams(_StrictParams):
    milestone: str = Field(min_length=1)
    implementation_path: str | None = None


class AdminSelfModProposeResult(BaseModel):
    proposal_id: str
    artifact_type: str
    name: str
    version: str
    artifact_path: str
    valid: bool
    warnings: list[str] = Field(default_factory=list)
    capability_diff: dict[str, Any] = Field(default_factory=dict)
    signer: str = ""
    reason: str = ""


class AdminSelfModApplyResult(BaseModel):
    applied: bool
    proposal_id: str = ""
    change_id: str = ""
    requires_confirmation: bool = False
    warnings: list[str] = Field(default_factory=list)
    capability_diff: dict[str, Any] = Field(default_factory=dict)
    active_version: str = ""
    tool_names: list[str] = Field(default_factory=list)
    reason: str = ""


class AdminSelfModRollbackResult(BaseModel):
    rolled_back: bool
    change_id: str = ""
    artifact_type: str = ""
    name: str = ""
    restored_version: str = ""
    active_version: str = ""
    reason: str = ""


class AdminSoulReadResult(BaseModel):
    configured: bool = False
    path: str = ""
    content: str = ""
    sha256: str = ""
    bytes: int = 0
    warnings: list[str] = Field(default_factory=list)
    reason: str = ""


class AdminSoulUpdateResult(BaseModel):
    updated: bool = False
    path: str = ""
    sha256: str = ""
    bytes: int = 0
    warnings: list[str] = Field(default_factory=list)
    reason: str = ""


class DevImplementResult(SessionTaskResult):
    operation: Literal["implement"] = "implement"


class DevReviewResult(SessionTaskResult):
    operation: Literal["review"] = "review"
    findings: list[str] = Field(default_factory=list)


class DevRemediateResult(SessionTaskResult):
    operation: Literal["remediate"] = "remediate"


class DevCloseResult(BaseModel):
    milestone: str
    implementation_path: str
    ready: bool
    section_found: bool = False
    runtime_wiring_recorded: bool = False
    validation_recorded: bool = False
    docs_parity_recorded: bool = False
    worklog_updated: bool = False
    review_status_recorded: bool = False
    punchlist_complete: bool = False
    acceptance_checklist_complete: bool = False
    missing_evidence: list[str] = Field(default_factory=list)
    unchecked_items: list[str] = Field(default_factory=list)
    open_finding_ids: list[str] = Field(default_factory=list)


class DaemonStatusResult(BaseModel):
    status: str
    sessions_active: int = 0
    audit_entries: int = 0
    policy_hash: str = ""
    tools_registered: list[str] = Field(default_factory=list)
    model_routes: dict[str, str] = Field(default_factory=dict)
    classifier_mode: str = ""
    content_firewall: dict[str, Any] = Field(default_factory=dict)
    yara_required: bool = False
    yara_policy_required: bool = False
    risk_policy_version: str = ""
    risk_thresholds: dict[str, float] = Field(default_factory=dict)
    channels: dict[str, Any] = Field(default_factory=dict)
    delivery: dict[str, Any] = Field(default_factory=dict)
    executors: dict[str, Any] = Field(default_factory=dict)
    selfmod: dict[str, Any] = Field(default_factory=dict)
    realitycheck: dict[str, Any] = Field(default_factory=dict)
    provenance: dict[str, Any] = Field(default_factory=dict)
    a2a: dict[str, Any] = Field(default_factory=dict)


class DoctorCheckParams(_StrictParams):
    component: str = "all"


class DoctorCheckResult(BaseModel):
    status: str
    component: str = "all"
    checks: dict[str, Any] = Field(default_factory=dict)
    error: str = ""


class DaemonShutdownResult(BaseModel):
    status: str


class DaemonResetResult(BaseModel):
    status: str
    cleared: dict[str, int] = Field(default_factory=dict)
    quiescent: bool = True
    invariants: dict[str, bool] = Field(default_factory=dict)


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
    arguments: dict[str, Any] = Field(default_factory=dict)
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
