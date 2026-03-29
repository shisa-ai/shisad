# ADR: Policy Source Authority for Sandbox Execution

## Status

Accepted (2026-02-10)

## Context

The daemon exposes two paths for tool execution:

1. **Planner path** (`_execute_via_sandbox`): Policy is derived from `ToolDefinition` + `PolicyBundle`. The PEP has already approved the action.
2. **External API path** (`handle_tool_execute`): Policy parameters (filesystem, network, environment, limits) are caller-declared via JSON-RPC params.

The external API path has transport-layer auth (admin peer UID check), so only local processes running as the same user can call it. However, a compromised local process could silently widen policy — for example, `allow_network=True, allowed_domains=["*"]`, `degraded_mode=fail_open`, `security_critical=False` — bypassing everything declared in `policy.yaml`.

Three options were evaluated.

### Option A: Admin-only by design (document status quo)

Caller is trusted to declare whatever policy they want. Transport auth is the sole trust boundary.

- **Pro**: Zero code changes, maximum flexibility for external orchestrators
- **Pro**: Matches Docker/Kubernetes API model (API = trust boundary)
- **Pro**: `approved_by_pep=False` default still blocks credential injection
- **Con**: `policy.yaml` becomes advisory, not authoritative — can't audit what's enforced by reading it
- **Con**: No defense-in-depth against local privilege escalation or compromised orchestrator
- **Con**: If daemon ever gets a non-local transport (TCP/TLS), this is a critical vulnerability

### Option B: Merge caller + server-side (most restrictive wins)

Caller can request policy parameters, but server-side `PolicyBundle` / `ToolDefinition` acts as a floor. Merge semantics: intersection for allowlists, minimum for limits, maximum for restrictions.

- **Pro**: Defense in depth — `policy.yaml` always enforced as baseline
- **Pro**: Auditable — `policy.yaml` tells you the worst-case access any tool can get
- **Pro**: Shared merge primitives with M4.9 (policy compiler scope layering)
- **Pro**: Safe if transport changes to non-local in the future
- **Con**: Need to define merge semantics for each policy dimension
- **Con**: Orchestrator needing wider access requires per-tool overrides in `policy.yaml`
- **Con**: Some merge behaviors need careful design (e.g., mount path intersection)

### Option C: Derive entirely from ToolDefinition (ignore caller policy)

All policy is server-side. Caller provides only `tool_name`, `command`, and data parameters.

- **Pro**: Simplest mental model, maximum security
- **Pro**: Trivially auditable — one source of truth
- **Con**: Kills the external API for ad-hoc tool execution
- **Con**: Every tool must be pre-registered with full policy
- **Con**: No flexibility for context-dependent policy (e.g., different `read_paths` per invocation)
- **Con**: Schema redesign required (split policy fields from data fields)

## Decision

**Option B: Merge caller + server-side (most restrictive wins).**

The merge primitives needed here are identical to what M4.9 (policy compiler scope layering) requires. Building them now as M4.7 provides a tested foundation that M4.9 reuses. The merge function is a pure function `merge(server: Policy, caller: PolicyPatch) -> Policy` with clear, testable properties.

`PolicyPatch` semantics are explicit:
- Omitted field = inherit server floor unchanged
- Explicit empty allowlist (`[]`) = intentionally narrow to deny-all
- Explicit `null` for policy fields = invalid request

### Merge rules

| Dimension | Merge rule |
|---|---|
| `allow_network` | server floor authoritative: `False` cannot be raised by caller, `True` may be narrowed to `False` |
| `allowed_domains` | intersection (caller ∩ server) |
| `sandbox_type` | server-authoritative floor; caller cannot select weaker runtime |
| `filesystem.mounts` | intersection of paths; minimum mode (`ro` beats `rw`) |
| `filesystem.denylist` | union (both denylists apply) |
| `environment.allowed_keys` | intersection |
| `environment.denied_prefixes` | union |
| numeric limits (`timeout`, `memory`, `pids`, `output_bytes`) | `min(caller, server)` |
| `degraded_mode` | most restrictive (`fail_closed` beats `fail_open`) |
| `security_critical` | `True` beats `False` |
| `deny_private_ranges` | `True` beats `False` |
| `deny_ip_literals` | `True` beats `False` |

Runtime restrictiveness order is explicit and test-covered (`vm > nsjail > container > host`).

### Per-tool override path

When an orchestrator legitimately needs wider access than global policy defaults:

1. Register the tool with appropriate `destinations` and `sandbox_type` in its `ToolDefinition`
2. Add structured per-tool override in `policy.yaml` (network/filesystem/environment/limits/degraded/security fields, not just backend string)
3. The merge uses the tool-specific policy as the floor, not the global default

### Key properties (testable)

- `merge(server, caller)` is always at least as restrictive as `server` on every dimension
- `merge(server, server) == server` (idempotent)
- `merge(server, empty_patch) == server` (omitted caller fields cannot widen)
- `merge(server, maximally_restrictive) == maximally_restrictive` (caller can narrow)

## Consequences

- `handle_tool_execute` applies merge before constructing `SandboxConfig`
- The merge function becomes shared infrastructure between `handle_tool_execute` (M4.7) and scope layering (M4.9)
- External API callers can request narrower policy but never wider
- Caller-selected `sandbox_type` is treated as a request only; weaker-than-floor requests are rejected and audited
- `policy.yaml` becomes authoritative — auditors can trust it
- Per-tool overrides in `policy.yaml` or `ToolDefinition` must exist for tools that need non-default access
- Co-design M4.7 and M4.9 together — they share the same merge function

## Related

- `src/shisad/security/policy.py` — `PolicyBundle`, `SandboxPolicy`
- `src/shisad/core/tools/schema.py` — `ToolDefinition` (destinations, sandbox_type)
- `src/shisad/daemon/control_handlers.py` — `handle_tool_execute` (caller-declared path)
- Early implementation notes — M4.7 (policy merge foundation), M4.9 (policy compiler)
