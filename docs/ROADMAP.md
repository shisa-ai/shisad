# shisad Roadmap

*Created: 2026-02-26*
*Updated: 2026-04-07*
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
- `v0.6.0` is published: G0, M1, M2, M3, M4, M5, and M6 are closed, and the
  first trusted-publishing/SBOM/attestation release path is live on the
  shipped public line.
- `v0.6.1` closes the security-hardening lane on top of `v0.6.0`: minimal
  control-plane isolation, PromptGuard 2 integration, shipped YARA parity for
  the unicode-steganography rule, warning-only phantom-action detection, Tool
  Dependency Graph verification, and reviewed skill-tool drift observability.

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

Current execution status: `v0.6.0` is released. G0, M1, M2, M3, M4, M5, and
M6 are closed. The live runtime now has formal orchestrator/subagent session
roles, immutable task envelopes, trust-aware `report_anomaly` exposure,
taint-safe COMMAND↔TASK handoffs, a TASK close-gate self-check, versioned
session rehydration with lockdown continuity, bounded session archive
export/import with integrity checks plus fresh-session cutover, task-scoped
credential refs, typed sink validation for the current built-in runtime
boundaries, live resource-scope enforcement, background tainted-trigger
policy, a structured ArtifactLedger with endorsement metadata and GC
semantics, approval provenance attached to approval/reject/execute audit
events, a mandatory TASK summary-firewall checkpoint before delegated output
crosses back into COMMAND context, a browser tool surface with
confirmation-gated browser writes plus local skill tool-surface integrity
checks, and a hardened public release path using OIDC trusted publishing,
SBOMs, and provenance attestations. The active follow-on lanes are `v0.6.2`
(approval + key boundary), `v0.6.3` (critical UX fixes), and `v0.6.4`
(MCP/A2A interop), while the deferred M7 connector/skill expansion lane lives
in `v0.6.5`.

#### v0.6.1 — Security hardening

- Minimal control-plane isolation boundary (OS-level process/container)
- PromptGuard 2 ML classifier integration
- YARA rulepack runtime-parity closure for the shipped unicode-steganography rule
- Phantom action detection
- Tool Dependency Graph verification
- Skill tool schema-drift observability

Current execution note (2026-04-05): `v0.6.1` is release-closed. The shipped
lane adds sidecar-isolated control-plane analysis, PromptGuard 2 runtime
screening, the fixed shipped YARA unicode-steganography detector, structured
warning-only phantom-action detection, runtime Tool Dependency Graph
verification with clean COMMAND-declared task roots, and metadata-only
reviewed-skill schema-drift observability. The next planned lane is `v0.6.2`.

#### v0.6.2 — Hardware-backed approval and signing

Current execution note (2026-04-07): the `A0` approval-protocol foundation,
the `A1` TOTP / re-auth backend, and the `A2` WebAuthn / passkey
`bound_approval` backend are all review-closed on the active branch, and the
`A3` local-helper slice is now landed on the active branch for reviewer
handoff. The current v0.6.2 tree adds canonical `ApprovalEnvelope` /
`action_digest` hashing, approval levels (`L0`-`L4`), policy-driven
escalation, selected-backend metadata on pending approvals, richer approval
audit fields, the preserved `L0/software` backend, durable TOTP enrollment in
the credential broker, and the WebAuthn/passkey lane: approval-origin / rpId
config, a daemon-owned browser ceremony endpoint, durable WebAuthn credential
registration, chat/QR approval links, browser-bounce CLI flows for
`2fa register --method webauthn` and `action confirm`, plus behavioral and
adversarial coverage for the WebAuthn path. The post-close compatibility
follow-up keeps the strict non-origin rejection from review remediation while
accepting only root-equivalent signed-origin forms (explicit default ports and
an optional trailing `/`). The new `A3` slice adds `shisad-approver`: an
SSH/local-socket-backed `local_fido2` helper path for private / SSH-only
deployments, helper-specific origin / rpId context on registration and
pending approvals, and targeted behavioral / adversarial coverage for
helper-mediated L2 approvals. The standalone no-SSH paired-helper transport
is explicitly deferred. The remaining v0.6.2 work is signer/key-boundary
specific:

- Ledger / signer integration for high-value operations
- Hardware token signing and artifact signing flows
- Evidence encryption at rest behind the signer / key-boundary path

#### v0.6.3 — Critical UX fixes

- Confirmation gate pending-status plumbing
- Chat rendering and response formatting fixes
- No-model / missing-config diagnostics and operator usability fixes

#### v0.6.4 — MCP/A2A interop

- MCP/A2A compatibility
- Remote tool/server trust policy
- Interop layer for consuming or exposing remote tools without weakening local enforcement

#### v0.6.5 — Connector + skill expansions

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

### v0.8 — UX overhaul

- TUI visual overhaul — theme system, chat/dashboard/confirmation chrome
- CLI & config — TOML config file, help text, error messages, naming consistency
- Onboarding — first-run wizard, tutorial bot, upgrade flow
- Operator web UI on top of daemon/event-stream surfaces
- Stats & dashboard — cost/token tracking, usage display, budget controls

### v0.9 — Security quality and consolidation

- Unify secret detection patterns across ingress, egress, and PEP (eliminate coverage gaps)
- Unify URL/SSRF validation (eliminate duplicate private-range checks)
- Simplify network enforcement layers (single PEP decision point)
- Unify crypto key management across signing and encryption systems
- Wire or remove unused policy scope compilation code
- Verify and close ingress normalization ordering gap
- Extract shared firewall core library (ingress + output)
- Investigate lockdown level consolidation (4 → 3 if warranted)

### v0.10 — Multitenant support

- Org/workspace isolation for multi-tenant deployments
- Tenant policy boundaries
- Key/secrets isolation per tenant

### v0.11+ — Collaborative workflows

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
| Critical UX stabilization | v0.6.3 |
| MCP/A2A interop | v0.6.4 |
| Email / calendar connectors | v0.6.5 |
| Attachment pipeline | v0.6.5 |
| Long-term memory | v0.7 |
| UX overhaul + operator web UI | v0.8 |
| Security infrastructure consolidation | v0.9 |
| Multitenant support | v0.10 |

## Critical Path

1. Public release baseline (`v0.5`)
2. Orchestration boundary + tool-surface expansion (`v0.6.0`)
3. Security hardening + control-plane isolation (`v0.6.1`)
4. Hardware-backed high-risk approvals (`v0.6.2`)
5. Critical UX stabilization from first-user testing (`v0.6.3`)
6. Remote-tool trust and interop (`v0.6.4`)
7. High-value connectors on top of stable orchestration + interop (`v0.6.5`)
8. Durable memory with gated writes (`v0.7`)
9. UX overhaul and operator web UI (`v0.8`)
10. Security infrastructure consolidation (`v0.9`)
11. Multi-tenant support (`v0.10`)

## Public Announcement Criteria

Before broader public launch:

- **Zero-friction inference**: automatic option to use [Shisa.AI](https://shisa.ai) inference infrastructure (free credits on signup, choose your model) or model partners — no BYOK required to get started
- **Official Docker image**: published container image for reproducible deployment
- **One-click instance spinup**: dedicated shisad instances from a single action (web or CLI)

## Gaps Not Yet Scheduled

- Additional messaging channels such as WhatsApp, Signal, iMessage, and WeChat
- Per-group isolation and richer group-chat routing UX
- Swarm-style multi-agent behaviors beyond the orchestrator/subagent model
