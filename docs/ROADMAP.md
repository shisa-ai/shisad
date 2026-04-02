# shisad Roadmap

*Created: 2026-02-26*
*Updated: 2026-04-02*
*Status: Active*

## Goal

Reach a genuinely useful personal-assistant baseline while preserving the project's security invariants: per-call enforcement, taint-safe context boundaries, clean-room workflows for privileged actions, and durable auditability.

## Guiding Constraints

- The assistant should remain capable; security is delivered by enforcement, not by disabling tools.
- All tool execution stays policy-gated and auditable.
- Untrusted content remains provenance-marked as it crosses runtime boundaries.
- Memory and long-running automation must not become durable prompt-injection channels.

## Release Progress

- `v0.3.x` established the runtime foundation: provider routing, channels, assistant primitives, and destructive-command protection.
- `v0.4.0` shipped safe self-improvement infrastructure, coding-agent runtime support, and minimal COMMAND/TASK isolation.
- `v0.5.0` is the first public release: zero-config SHISA provider, evidence references, public repo split, Apache 2.0.
- `v0.6.0` is in active execution: G0, M1, M2, M3, and M4 are closed; M5 is the active next milestone.

## Milestones

### v0.5 — First public release

Focus:

- Zero-config SHISA provider path
- Evidence references for large untrusted tool output
- Public repo split, public docs, and Apache 2.0 licensing
- Behavioral-suite green on the public repo

Exit criteria:

1. Daemon boots with `SHISA_API_KEY` zero-config.
2. CLI session path works end-to-end for a basic assistant action.
3. Evidence references work (`store` / stub / `evidence.read` / promotion flow).
4. Credential isolation is demonstrable.
5. Public repo history, docs, and licensing are release-ready.
6. `uv run pytest tests/behavioral/ -q` passes on the public repo.

### v0.6 — Orchestration foundation + tool-surface expansion

Focus:

- Full COMMAND/TASK orchestration runtime (M1-M4)
- Web tool surface and browser automation proving the orchestration model (M5-M6)
- Multi-turn taint boundaries and task handoff contract in the live runtime
- Artifact/provenance model for delegated work
- Credential scoping across delegated execution boundaries
- Type-restricted task/tool boundary schemas
- Summary firewall barrier and approval provenance

Current execution status: G0, M1, M2, M3, and M4 are closed; M5 is the active next milestone. The live runtime now has formal orchestrator/subagent session roles, immutable task envelopes, trust-aware `report_anomaly` exposure, taint-safe COMMAND↔TASK handoffs, a TASK close-gate self-check, versioned session rehydration with lockdown continuity, bounded session archive export/import with integrity checks plus fresh-session cutover, task-scoped credential refs, typed sink validation for the current built-in runtime boundaries, live resource-scope enforcement, background tainted-trigger policy, a structured ArtifactLedger with endorsement metadata and GC semantics, approval provenance attached to approval/reject/execute audit events, and a mandatory TASK summary-firewall checkpoint before delegated output crosses back into COMMAND context.

#### v0.6.1 — Security hardening

- Minimal control-plane isolation boundary (OS-level process/container)
- PromptGuard 2 ML classifier integration
- Phantom action detection
- Tool Dependency Graph verification

#### v0.6.2 — Hardware-backed approval and signing

- Ledger / hardware wallet integration for high-value operations
- Hardware token signing and artifact signing flows

#### v0.6.3 — MCP/A2A interop

- MCP/A2A compatibility
- Remote tool/server trust policy
- Interop layer for consuming or exposing remote tools without weakening local enforcement

#### v0.6.4 — Connector + skill expansions

- Email and calendar connectors
- Attachment pipeline (voice + image)
- Additional skill integrations

### v0.7 — Memory foundation

- Structured, versioned long-term memory
- Knowledge-graph and consolidation foundations
- Proposed-write path integrated with orchestration boundary
- Memory write gating, quarantine, and audit path shipped end-to-end

#### v0.7.1 — Memory hardening and benchmark closure

- Benchmark adapters and oracle diagnostics
- Retrieval/schema precision and telemetry hardening
- Memory poisoning and persistence-policy regression closure

### v0.8 — Operator web UI and multitenant support

- Operator web UI on top of daemon/event-stream surfaces
- Progress and status streaming for long-running tasks
- Org/workspace isolation for multi-tenant deployments

### v0.9+ — Collaborative workflows

- Shared and collaborative agent workflows

## Roadmap Alignment

| Capability | Target |
| --- | --- |
| Personal reminder / notetaker baseline | v0.5 |
| Evidence references | v0.5 |
| Multi-agent orchestration | v0.6.0 |
| Web tools + browser automation | v0.6.0 |
| Control-plane isolation | v0.6.1 |
| Hardware-backed approvals | v0.6.2 |
| MCP/A2A interop | v0.6.3 |
| Email / calendar connectors | v0.6.4 |
| Attachment pipeline | v0.6.4 |
| Long-term memory | v0.7 |
| Operator web UI | v0.8 |

## Critical Path

1. Public release baseline (`v0.5`)
2. Orchestration boundary + tool-surface expansion (`v0.6.0`)
3. Security hardening + control-plane isolation (`v0.6.1`)
4. Hardware-backed high-risk approvals (`v0.6.2`)
5. Remote-tool trust and interop (`v0.6.3`)
6. High-value connectors on top of stable orchestration + interop (`v0.6.4`)
7. Durable memory with gated writes (`v0.7`)
8. Operator UI and multi-tenant support (`v0.8`)

## Public Announcement Criteria

Before broader public launch:

- **Zero-friction inference**: automatic option to use [Shisa.AI](https://shisa.ai) inference infrastructure (free credits on signup, choose your model) or model partners — no BYOK required to get started
- **Official Docker image**: published container image for reproducible deployment
- **One-click instance spinup**: dedicated shisad instances from a single action (web or CLI)

## Gaps Not Yet Scheduled

- Additional messaging channels such as WhatsApp, Signal, iMessage, and WeChat
- Per-group isolation and richer group-chat routing UX
- Swarm-style multi-agent behaviors beyond the orchestrator/subagent model
