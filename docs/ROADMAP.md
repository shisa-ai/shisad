# shisad Roadmap

*Created: 2026-02-26*
*Updated: 2026-04-16*
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
- `v0.6.2` is release-closed: multi-factor approvals, signer-backed
  authorization, local-helper approvals, and optional evidence encryption at
  rest are now on the shipped line.
- `v0.6.3` is published: critical UX fixes from first-user testing, including
  actionable pending confirmations, chat TOTP approvals, terminal QR
  enrollment, session-message newline rendering, no-model/startup diagnostics,
  and more truthful planner tool advertising for unconfigured resources. The
  LT follow-up also closed trusted-CLI confirmation handling, stale
  pending-action cleanup, and low-friction internal bookkeeping confirmation
  paths. Textual chat TUI newline rendering remains deferred to the TUI
  overhaul.
- `v0.6.4` is published: firewall scanning now routes through `textguard`,
  bundled YARA rules are validated at startup, analyzer compatibility shims
  preserve the required legacy split-base64 and phrase coverage, and the
  duplicated local shisad YARA asset copy has been removed.
- This tree contains pre-tag `v0.6.5` release content: MCP client discovery
  and execution, explicit remote tool trust semantics, and a signed A2A
  ingress foundation with replay/rate-limit controls. ReleaseClose is the
  remaining gate before tag/PyPI publication.

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
checks, a hardened public release path using OIDC trusted publishing, SBOMs,
and provenance attestations, the published `v0.6.3` critical UX
stabilization lane, and the shipped `v0.6.4` textguard migration. The active
lane is `v0.6.5` (MCP/A2A interop; ReleaseClose in progress), with `v0.6.6`
(connector/skill expansion) queued next.

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

Current execution note (2026-04-09): `v0.6.2` is release-closed. The `A0` approval-protocol foundation,
the `A1` TOTP / re-auth backend, the `A2` WebAuthn / passkey
`bound_approval` backend, and the `A3` SSH/local-helper slice are all landed
on the active branch, and the `L2` signer lane is now review-closed as well.
The current v0.6.2 tree adds canonical `ApprovalEnvelope` / `action_digest`
hashing, approval levels (`L0`-`L4`), policy-driven escalation, richer
approval audit fields, the preserved `L0/software` backend, durable TOTP
enrollment, the approval-origin / passkey ceremony surface,
`shisad-approver` for SSH/private deployments, the generic `IntentEnvelope` /
signer-verification contract for `signed_authorization`, and now the
review-closed `L1` evidence-encryption slice as well: when
`SHISAD_EVIDENCE_KMS_URL` is configured, ArtifactLedger blob payloads route
through an explicit remote artifact-crypt boundary, on-disk blob bytes stop
being plaintext, recoverable codec/config drift keeps refs available for later
recovery instead of deleting them, and `evidence.read` / `evidence.promote`
remain behaviorally covered without blocking the async runtime on remote
artifact-KMS I/O. Scope is intentionally narrow and truthful: lifecycle
metadata stays plaintext, the shipped default remains plaintext blobs when no
remote key boundary is configured, and approval-factor / recovery-code
at-rest hardening remains follow-on. Consumer-Ledger clear-signing /
trusted-display work also remains follow-on. With `A0`-`A3`, `L2`, and `L1`
now review-closed and the release-close bundle complete, the next planned lane
is `v0.6.3` rather than another in-line `v0.6.2` milestone.

Approval-level mapping for v0.6.2:

| Shorthand | Semantic name |
|---|---|
| `L0` | `software` / `SOFTWARE` |
| `L1` | `reauthenticated` / `REAUTHENTICATED` |
| `L2` | `bound_approval` / `BOUND_APPROVAL` |
| `L3` | `signed_authorization` / `SIGNED_AUTHORIZATION` |
| `L4` | `trusted_display_authorization` / `TRUSTED_DISPLAY_AUTHORIZATION` |

Minimal signer-backed policy example:

```yaml
tools:
  shell.exec:
    capabilities_required:
      - shell.exec
    confirmation:
      level: signed_authorization
      methods:
        - kms
      allowed_principals:
        - finance-owner
      allowed_credentials:
        - kms:finance-primary
      require_capabilities:
        principal_binding: true
        full_intent_signature: true
        third_party_verifiable: true
      fallback:
        mode: deny
```

#### v0.6.3 — Critical UX fixes

Current execution note (2026-04-13): `v0.6.3` is published on GitHub and PyPI.
The shipped line includes first-user UX stabilization work: confirmation-gated
actions surface actionable daemon-owned pending status, TOTP approvals can be
completed from trusted chat / command replies, TOTP enrollment renders a
terminal QR code when possible, session-message output preserves line breaks,
no-model and startup diagnostics are actionable, `shisad doctor` works as a
bare command, Anthropic default routing and chat optional install guidance are
documented, and planner-visible tool manifests truthfully hide unconfigured
filesystem/git surfaces while preserving delegated task scope enforcement. The
LT follow-up also parses confirmation replies before planner flow and closes
the CLI-trust, stale pending-action, and low-risk internal bookkeeping fixes
found during live testing. Textual chat TUI newline rendering and web-page
TOTP entry remain deferred to `v0.8.0`.

#### v0.6.4 — textguard port

- Status (2026-04-13): `v0.6.4` is published. textguard-backed screening is on
  the shipped line; PromptGuard remains opt-in through the
  `security-runtime` dependency group.
- Port PromptGuard-backed screening to the `textguard` library while keeping
  PromptGuard opt-in through the existing `security-runtime` dependency group
- Unify prompt-injection detection behind the textguard API surface
- Preserve existing PEP screening semantics and threshold tuning while
  removing the copied local YARA asset set

#### v0.6.5 — MCP/A2A interop

- Status (2026-04-16): pre-tag `v0.6.5` release content is in ReleaseClose.
  MCP client-only interop, remote tool trust policy, and the signed A2A
  socket/HTTP ingress baseline are on the release-prepared tree. Exposing
  shisad as an MCP server remains deferred.
- MCP client-only interop with external servers
- Remote tool/server trust policy
- Signed A2A external-ingress foundation
- Exposing shisad as an MCP server remains deferred

#### v0.6.6 — Connector + skill expansions

- Email and calendar connectors
- Local attachment ingest baseline for images and voice recordings; OCR, STT,
  channel downloads, email attachment export, and multimodal model input remain
  follow-on work
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
| textguard port | v0.6.4 |
| MCP/A2A interop | v0.6.5 |
| Email / calendar connectors | v0.6.6 |
| Local attachment ingest baseline | v0.6.6 |
| Full attachment processing pipeline | v0.7+ |
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
6. Port prompt-injection detection to textguard (`v0.6.4`)
7. Remote-tool trust and interop (`v0.6.5`)
8. High-value connectors on top of stable orchestration + interop (`v0.6.6`)
9. Durable memory with gated writes (`v0.7`)
10. UX overhaul and operator web UI (`v0.8`)
11. Security infrastructure consolidation (`v0.9`)
12. Multi-tenant support (`v0.10`)

## Public Announcement Criteria

Before broader public launch:

- **Zero-friction inference**: automatic option to use [Shisa.AI](https://shisa.ai) inference infrastructure (free credits on signup, choose your model) or model partners — no BYOK required to get started
- **Official Docker image**: published container image for reproducible deployment
- **One-click instance spinup**: dedicated shisad instances from a single action (web or CLI)

## Gaps Not Yet Scheduled

- Additional messaging channels such as WhatsApp, Signal, iMessage, and WeChat
- Per-group isolation and richer group-chat routing UX
- Swarm-style multi-agent behaviors beyond the orchestrator/subagent model
