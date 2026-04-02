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
- `v0.5` is the first public-release lane.

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

### v0.6 — Orchestration foundation

- Full COMMAND/TASK orchestration runtime
- Multi-turn taint boundaries and task handoff contract in the live runtime
- Artifact/provenance model for delegated work
- Credential scoping across delegated execution boundaries
- Type-restricted task/tool boundary schemas
- Summary firewall barrier and approval provenance
- Current execution status: G0, M1, and M2 are now implementation-complete. The live runtime has formal orchestrator/subagent session roles, immutable task envelopes, trust-aware `report_anomaly` exposure, taint-safe COMMAND↔TASK handoffs, a TASK close-gate self-check, versioned session rehydration with lockdown continuity, and bounded session archive export/import with integrity checks plus fresh-session cutover.

### v0.6.1 — Interop and remote tool trust

- MCP/A2A compatibility
- Remote tool/server trust policy
- Interop layer for consuming or exposing remote tools without weakening local enforcement

### v0.7 — Tool-surface expansion

- Email and calendar connectors
- Attachment pipeline (voice + image)
- Browser automation with sandbox + policy gates
- Additional tracing, adversarial evaluation, and connector/browser hardening

#### v0.7.1 — Minimal control-plane isolation hardening

- Move core enforcement behind a minimal OS-enforced process/container boundary
- Verify the expanded tool surfaces still work cleanly across the isolation seam
- Document residual same-host non-claims and degraded-mode expectations

#### v0.7.2 — Hardware-backed approval and signing

- Hardware token signing for high-value operations
- Stronger operator authentication and artifact signing flows

### v0.8 — Memory foundation

- Structured, versioned long-term memory
- Knowledge-graph and consolidation foundations
- Proposed-write path integrated with orchestration boundary
- Memory write gating, quarantine, and audit path shipped end-to-end

### v0.8.1 — Memory hardening and benchmark closure

- Benchmark adapters and oracle diagnostics
- Retrieval/schema precision and telemetry hardening
- Memory poisoning and persistence-policy regression closure

### v0.9 — Operator web UI and multitenant support

- Operator web UI on top of daemon/event-stream surfaces
- Progress and status streaming for long-running tasks
- Org/workspace isolation for multi-tenant deployments

### v1.0+ — Collaborative workflows

- Shared and collaborative agent workflows

## Roadmap Alignment

| Capability | Target |
| --- | --- |
| Personal reminder / notetaker baseline | v0.5 |
| Evidence references | v0.5 |
| Multi-agent orchestration | v0.6 |
| MCP/A2A interop | v0.6.1 |
| Email / calendar connectors | v0.7 |
| Attachment pipeline | v0.7 |
| Browser automation | v0.7 |
| Hardware-backed approvals | v0.7.2 |
| Long-term memory | v0.8 |
| Operator web UI | v0.9 |

## Critical Path

1. Public release baseline (`v0.5`)
2. Orchestration boundary and delegated execution (`v0.6`)
3. Remote-tool trust and interop (`v0.6.1`)
4. High-value tool surfaces on top of stable orchestration (`v0.7`)
5. Stronger isolation boundary (`v0.7.1`)
6. Hardware-backed high-risk approvals (`v0.7.2`)
7. Durable memory with gated writes (`v0.8`)
8. Operator UI and multi-tenant support (`v0.9`)

## Public Announcement Criteria

Before broader public launch:

- **Zero-friction inference**: automatic option to use [Shisa.AI](https://shisa.ai) inference infrastructure (free credits on signup, choose your model) or model partners — no BYOK required to get started
- **Official Docker image**: published container image for reproducible deployment
- **One-click instance spinup**: dedicated shisad instances from a single action (web or CLI)

## Gaps Not Yet Scheduled

- Additional messaging channels such as WhatsApp, Signal, iMessage, and WeChat
- Per-group isolation and richer group-chat routing UX
- Swarm-style multi-agent behaviors beyond the orchestrator/subagent model
