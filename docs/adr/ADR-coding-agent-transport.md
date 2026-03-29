# ADR: Coding Agent Transport — ACP via Python SDK

## Status

Accepted (2026-03-14) — transport is locked for v0.4 M3 implementation.

## Context

v0.4 M3 ("Coding Agent Skills") requires shisad to invoke external coding agents (Claude Code, Codex, OpenCode) as TASK-scoped subtasks. The original v0.4 M3 design specified three independent native integrations:

- **Claude Code**: `claude-agent-sdk` Python async API
- **Codex**: `subprocess.Popen` with `codex exec --full-auto --json`, parse JSONL events
- **OpenCode**: `subprocess.run` with `opencode run --format json`, parse JSON blob

This ADR evaluates whether to keep that approach or adopt the Agent Client Protocol (ACP) as a uniform transport layer.

### What M3 needs from a transport

From shisad's perspective, invoking a coding agent is another tool call / TASK delegation. shisad's security enforcement happens at its own borders (PEP, TASK isolation, worktree, output firewall), not inside the coding agent. The M3 plan explicitly states:

> "shisad gates the decision to invoke the agent and captures results, but does NOT intercept per-tool-call decisions within the agent."

The transport layer needs to:

1. Spawn an agent process with a task description
2. Receive structured output (not PTY scraping)
3. Respect timeout / process-level kill
4. Report success/failure with parseable results
5. Work for all target agents without agent-specific output parsers
6. Support a read-only review mode (ACP agent config). If the agent makes opportunistic changes during review, worktree isolation already makes them proposals — no hard discard.

### Options evaluated

Three options were evaluated:

1. **Independent native integrations** (original M3 plan)
2. **acpx** — TypeScript/Node.js ACP CLI client (upstream `acpx`, v0.3.0)
3. **Python ACP SDK** (`agent-client-protocol` on PyPI, v0.8.1)

A fourth protocol, **Google A2A** (Agent-to-Agent), was also considered and rejected as out of scope (see §"A2A evaluation" below).

---

## Decision

**Use the Python ACP SDK (`agent-client-protocol`) as the transport layer for M3 coding agent integrations.** Use upstream `acpx` as reference material for adapter quirks, agent command registry, and error-handling patterns — not as a runtime dependency.

Pin `agent-client-protocol==0.8.1` in project dependencies. Vendoring decision deferred to M3 implementation phase based on stability experience.

---

## Analysis

### Option 1: Independent native integrations

Each agent gets a bespoke subprocess wrapper with agent-specific output parsing.

**Pros:**
- No external protocol dependency
- Direct access to every agent-specific CLI flag
- Full control over process lifecycle per agent

**Cons:**
- Three different output formats to parse (Claude async iterator, Codex JSONL events, OpenCode JSON blob)
- Three different error-handling paths
- Three different process lifecycle patterns
- Each integration breaks independently when upstream CLIs update
- Adding a fourth agent (Gemini, Cursor, etc.) requires a fourth integration from scratch
- Largest implementation and maintenance surface

### Option 2: acpx (TypeScript ACP client)

Use `acpx <agent> exec "task" --format json` as a uniform subprocess interface.

**Pros:**
- One output format (NDJSON) across all agents
- One error normalization path
- Built-in registry of 14 agent commands
- Battle-tested adapter-specific workarounds (Gemini startup timeouts, Claude session stalls)
- Session persistence, queue coordination, crash recovery (though M3 wouldn't use most of this)
- Production-quality process lifecycle management

**Cons:**
- Introduces Node.js runtime dependency (requires `npx`)
- Alpha maturity (v0.3.0)
- TypeScript — can't integrate at the library level with shisad's Python async runtime
- Interaction is subprocess-to-subprocess (shisad → acpx → ACP adapter → agent): extra process layer
- Session persistence / queue-owner features are unused by M3's ephemeral `exec` model
- Agent-specific config passthrough depends on what each ACP adapter exposes

### Option 3: Python ACP SDK (selected)

Use `agent-client-protocol` to speak ACP directly from shisad's Python async runtime.

**Pros:**
- Pure Python, async-native — integrates directly with shisad's daemon event loop
- Pydantic schema models align with shisad's existing schema layer (`src/shisad/core/api/schema.py`)
- One protocol, one output format across all ACP-compliant agents
- No Node.js dependency, no extra subprocess layer
- Library-level integration: `connect_to_agent()` → `initialize()` → `new_session()` → `prompt()` — direct async calls, not subprocess stdout parsing
- Active maintenance (11 releases, v0.8.1 as of 2026-02-13)
- Contrib utilities (SessionAccumulator, ToolCallTracker, PermissionBroker) available if needed
- Adding agents = adding a command string to the registry, not a new integration

**Cons:**
- Newer than acpx; less battle-tested on adapter-specific quirks
- Contrib utilities marked unstable
- Agent command registry (which binary + args to spawn for each agent) must be maintained by shisad (trivial — it's a dict, and acpx's registry serves as reference)
- Adapter-specific workarounds (timeouts, startup delays) must be implemented by shisad (acpx reference provides the patterns)
- Agent-specific config passthrough still depends on what each ACP adapter exposes (same limitation as acpx)

### Why not independent integrations?

The colleague counterargument for independent integrations rested on two claims:

1. *"M3's safety story depends on agent-specific controls that acpx does not normalize"* — Claude `allowed_tools`/`permission_mode`, Codex sandbox modes, OpenCode Build/Plan permissions.

2. *"acpx is session-persistence oriented; M3 wants ephemeral TASK sessions."*

Both claims are weaker than they appear:

**On agent-specific controls:** shisad's safety story depends on shisad's controls (TASK isolation, worktree proposals, output firewall, PEP enforcement, budget/timeout kill), not on the agent's internal safety mechanisms. Agent-native controls (Claude's `allowed_tools`, Codex's OS-level sandbox) are defense-in-depth that the agent enforces regardless of transport. They are not shisad's enforcement boundary. ACP does pass through relevant session config (`allowed_tools`, `max_turns`, mode) where the adapter supports it, and shisad doesn't need to normalize what it doesn't enforce.

**On session persistence:** The Python SDK's `new_session()` + `prompt()` works for one-shot execution. There's no mandatory session persistence layer. acpx's queue-owner/persistence features are specific to acpx, not to ACP.

**On implementation cost:** Three native integrations means three output parsers, three error surfaces, three process lifecycle managers. ACP collapses this to one protocol, and the Python SDK lets us do it without leaving the Python runtime.

### A2A evaluation

Google's Agent-to-Agent (A2A) protocol was evaluated and rejected for M3:

- **Transport mismatch**: A2A is HTTP-based (agent discovery + task delegation across network boundaries). M3 needs stdio subprocess control of local coding agents.
- **No coding agent adapters**: A2A has no built-in support for Claude Code, Codex, OpenCode, or any coding agent. shisad would need to build the same adapters regardless.
- **Wrong abstraction**: A2A solves multi-agent service mesh problems (discovery, delegation, agent cards). M3 solves "spawn a coding agent, send it a task, get structured output."
- **Not a superset of ACP**: A2A and ACP are orthogonal protocols. A2A may be relevant for future inter-agent delegation (v0.5+), but does not replace the subprocess-level coding agent control that ACP provides.

---

## Implementation sketch

```
CodingAgentAdapter (shisad-owned interface)
    │
    ├── AcpAdapter (default — uses agent-client-protocol Python SDK)
    │     connect_to_agent() → initialize() → new_session() → prompt()
    │     One implementation, all ACP-compliant agents
    │
    └── (escape hatch) Direct<Agent>Adapter
          For any agent whose ACP adapter can't handle a required knob
          Built only if forced, not preemptively
```

**Agent command registry** (derived from acpx's built-in registry):

```python
ACP_AGENTS = {
    "claude": "npx -y @zed-industries/claude-agent-acp@^0.21.0",
    "codex": "npx @zed-industries/codex-acp@^0.9.5",
    "opencode": "npx -y opencode-ai acp",
    # Future: gemini, cursor, copilot, etc.
}
```

Note: the ACP adapters for each agent are separate from the agents themselves. Claude Code, Codex, and OpenCode each have an ACP adapter package (maintained by Zed/community) that wraps their native CLI into the ACP protocol. shisad spawns the ACP adapter, which in turn manages the underlying agent.

**What shisad still owns regardless of transport choice:**
- `CodingAgentAdapter` / `CodingAgentResult` interface
- TASK session lifecycle (M2)
- Git worktree isolation
- Budget / timeout enforcement
- Agent selection and fallback logic
- Output firewall (result → COMMAND handoff)
- Audit trail
- Behavioral tests

---

## Risks and mitigations

| Risk | Severity | Mitigation |
|---|---|---|
| Python ACP SDK breaks or stalls | Medium | Pin version; abstract behind `CodingAgentAdapter` interface so direct subprocess wrappers can replace any agent |
| ACP adapter for a target agent lacks needed config knob | Low | Escape hatch: `Direct<Agent>Adapter` for that specific agent only |
| ACP adapter for a target agent is unavailable or broken | Medium | acpx reference provides fallback command patterns; direct CLI subprocess is always available |
| ACP protocol evolves in breaking ways | Low | Pinned SDK version; protocol is JSON-RPC 2.0 with stable core methods |
| `npx` / Node.js required for ACP adapter binaries | Low | Already required if using Codex or OpenCode CLIs; not a new dependency class |

---

## Future considerations

### Python ACP ecosystem (as of 2026-03-14)

The Python ecosystem for ACP clients is maturing but hasn't converged on a full-featured headless client equivalent to acpx. Current landscape:

**`agent-client-protocol` SDK (selected for M3)**: SDK-level — gives you Pydantic models, async transport, `connect_to_agent()` / `spawn_agent_process()` helpers, and `acp.contrib` utilities (SessionAccumulator, PermissionBroker, ToolCallTracker). You build session persistence, queueing, crash recovery, and agent registry yourself. For M3's one-shot `new_session()` → `prompt()` pattern, this is sufficient — the features we'd need to build are exactly the features M3 doesn't need.

**AgentPool** (`phil65/agentpool`): Closest Python analog to acpx at a higher level. Unified orchestration hub wrapping heterogeneous agents (Claude Code, Codex, Goose, custom ACP, AG-UI, PydanticAI) behind YAML config + Python API. Has direct integrations for Claude Code and Codex that skip ACP adapters entirely. More ambitious scope (teams, sequential/parallel chains, multi-protocol bridging) but heavier dependency tree (PydanticAI, etc.). Worth evaluating for v0.5+ if shisad needs richer multi-agent orchestration beyond one-shot task dispatch.

**Toad** (`batrachian-toad`): Pure Python TUI client supporting 12+ agent CLIs via ACP with session resume. Solves interactive terminal UI, not programmatic agent driving. Not useful for M3 but worth tracking as ecosystem signal.

**acpx-as-subprocess fallback**: `npx acpx@latest --format json codex exec "..."` with `--json-strict` gives machine-consumable NDJSON from Python without Node-as-library. Pragmatic escape hatch if the Python SDK proves insufficient for a specific agent, without taking acpx as a library dependency.

### What M3 doesn't need (but v0.5+ might)

The features that distinguish acpx from the Python SDK — persistent named sessions, prompt queue coordination, crash reconnect, cooperative cancel, TTL-based owner lifecycle — are exactly the features M3's ephemeral TASK model doesn't use. If v0.5+ moves to persistent multi-turn coding sessions (e.g., iterative review loops where the agent retains context across rounds), this gap becomes relevant. At that point, evaluate:

1. Whether the Python SDK's `contrib.SessionAccumulator` + custom persistence is sufficient
2. Whether AgentPool has matured enough to handle the orchestration
3. Whether acpx-as-subprocess (or a Python port of its session model) is the right path

### ACP adapter churn

ACP adapter packages (`@zed-industries/claude-agent-acp`, `@zed-industries/codex-acp`, etc.) are maintained upstream and may break independently. M3 pins adapter versions in the agent command registry. Monitor:

- Adapter release cadence and breaking changes
- New agents gaining ACP adapters (expand registry opportunistically)
- Agents dropping or stalling ACP support (trigger direct-adapter escape hatch)

---

## References

- `acpx/` — upstream acpx source (v0.3.0), used as reference for agent registry and adapter workarounds
- `acpx/VISION.md` — upstream acpx design principles
- `acpx/conformance/spec/v1.md` — upstream ACP v1 conformance profile
- `acpx/agents/` — upstream per-agent documentation and quirks
- `agent-client-protocol` PyPI: https://pypi.org/project/agent-client-protocol/
- `agentclientprotocol/python-sdk` GitHub: https://github.com/agentclientprotocol/python-sdk
- Original v0.4 M3 design notes — coding agent skills specification
- `docs/adr/ADR-command-task-architecture.md` — COMMAND/TASK privilege model
- `docs/DESIGN-PHILOSOPHY.md` — governing design principles
