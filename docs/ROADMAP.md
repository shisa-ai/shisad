# shisad Roadmap

*Created: 2026-02-26*
*Updated: 2026-07-22*
*Status: Active*

## Goal

Reach a genuinely useful personal-assistant baseline while preserving the project's security invariants: per-call enforcement, taint-safe context boundaries, clean-room workflows for privileged actions, and durable auditability.

## Guiding Constraints

- The assistant should remain capable; security is delivered by enforcement, not by disabling tools.
- Planner-proposed and shared administrative tool execution stays policy-gated
  and auditable; any distinct authenticated operator route is documented
  explicitly until it joins that authority.
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
- `v0.6.5` is published: MCP client discovery and execution with stable
  `mcp.<server>.<tool>` runtime ids, explicit remote tool trust semantics,
  and a signed A2A ingress foundation with fingerprint verification, grant
  enforcement, replay protection, and per-peer rate limits. Exposing shisad
  as an MCP server remains deferred.
- `v0.6.6` is published: config-path `SOUL.md` persona preferences, Discord
  public-channel policy controls, local MsgVault email read/search, local image
  and voice attachment ingest, and same-session evidence carry-forward for
  follow-up turns.
- `v0.6.7` is published: Ledger hardware signer approvals from shisad's first
  external pull request add EIP-712 `IntentEnvelope` signing through the local
  Ledger bridge, with conservative downgrade behavior when a device reports
  blind signing or an opaque review surface.
- `v0.7.1` is published: the v0.7 line has structured long-term memory with
  separate Identity, Active Attention, Recall, Procedural, and Evidence
  surfaces; provenance-gated memory writes with review/confirmation on
  high-risk paths; derived graph/consolidation
  foundations; and bug-fix point-release improvements for command-chat,
  lockdown recovery, memory scoping, and state-inspection UX.
- `v0.7.2` is published: memory benchmark tooling, retrieval sufficiency
  checks, memory-scope hardening, safer diagnostics, and bug-fix stabilization
  extend the structured long-term memory line.
- `v0.7.3` is published: open-thread/topic resume, fuzzy timeline/archive
  search, procedure-experience candidates, and timeline/procedure security
  hardening extend the structured long-term memory line.
- `v0.8.0b0` has been published as the first v0.8 beta checkpoint and publishes
  the reviewed post-`v0.7.4` bug-fix stack while the stable v0.8 UX overhaul
  remains in progress.
- `v0.8.0b1` is the latest v0.8 beta checkpoint: it adds structured
  turn-authorization fixes, explicit shell-command clarity, and channel target
  scoping on top of `v0.8.0b0`.
- `v0.8.0` is published: the stable release covers command-channel approval
  parity, TUI/confirmation polish, task panels, and the broader UX overhaul
  foundation.
- `v0.8.1` is in development. Its current tree adds a locked
  `shisad[assistant]` consumer profile, a tested local Linux/amd64 image
  candidate, and bounded CLI/config/runtime UX closure: no-overwrite minimal
  init, typed config/env inspection, grouped help and actionable errors,
  built-in theme/accessibility wiring, and a safe static web snapshot. It also
  adds durable pending-action/attempt/result state, conservative restart
  recovery and `outcome_unknown` containment, checksummed finite-state
  handling, single-daemon data-root ownership, managed-root filesystem/Git
  exclusions, and scoped delivery/approval continuity across Discord, Slack,
  Telegram, and Matrix. No registry image is published or signed, and this
  work does not claim the later setup wizard or live operator web application.

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
stabilization lane, the shipped `v0.6.4` textguard migration, the shipped
`v0.6.5` MCP/A2A interop lane, the shipped `v0.6.6` connector/skill expansion
lane, and the shipped `v0.6.7` Ledger signer line from the first external pull
request. The published `v0.7` memory line and the later v0.8 lines are
described below.

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
reviewed-skill schema-drift observability. At that 2026-04-05 close,
`v0.6.2` was the next planned lane; it is now published.

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
now review-closed and the release-close bundle complete, `v0.6.3` was the next
planned lane at that 2026-04-09 close; it is now published rather than another
in-line `v0.6.2` milestone.

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

- Status (2026-04-14): `v0.6.4` is published. textguard-backed screening is on
  the shipped line; PromptGuard remains opt-in through the
  `security-runtime` dependency group.
- Port PromptGuard-backed screening to the `textguard` library while keeping
  PromptGuard opt-in through the existing `security-runtime` dependency group
- Unify prompt-injection detection behind the textguard API surface
- Preserve existing PEP screening semantics and threshold tuning while
  removing the copied local YARA asset set

#### v0.6.5 — MCP/A2A interop

- Status (2026-04-17): `v0.6.5` is published. MCP client-only interop,
  remote tool trust policy, and the signed A2A socket/HTTP ingress baseline
  shipped with the release. Exposing shisad as an MCP server remains
  deferred.
- MCP client-only interop with external servers
- Remote tool/server trust policy
- Signed A2A external-ingress foundation
- Exposing shisad as an MCP server remains deferred

#### v0.6.6 — Connector + skill expansions

- Status (2026-04-19): published. Config-path `SOUL.md`, Discord
  public-channel policy controls, local MsgVault email read/search, local image
  and voice attachment ingest, and same-session evidence carry-forward are on
  the shipped line.
- Local MsgVault email read/search baseline. Email send/reply, calendar
  read/write, remote MsgVault transports, and attachment export remain
  follow-on work.
- Local attachment ingest baseline for images and voice recordings; OCR, STT,
  channel downloads, email attachment export, and multimodal model input remain
  follow-on work.
- Additional skill integrations: config-path `SOUL.md` persona preferences.
  Executable plugin installs and `outline-edit` remain deferred to the plugin
  policy lane.

#### v0.6.7 — Ledger hardware signer approvals

- Status (2026-04-21): published. The line ships the first external pull
  request, from @GuitareCiel (Ledger), for Ledger-backed ECDSA signer keys and
  a local Ledger bridge that signs EIP-712 `IntentEnvelope` approvals.
- Ledger Stax/Flex clear-signing can satisfy trusted-display authorization when
  the bridge reports a trusted device display for that request. Nano and unknown
  models are treated conservatively as opaque review surfaces for this bridge.
- Maintainer device-attached verification and Ledger's validated
  hardware/firmware/app matrix remain follow-on work in `v0.6.7.1` (`PF.92`).
- Hardware-signer support beyond the current Ethereum EIP-712 path remains
  follow-on work.

### v0.7 — Memory foundation

#### v0.7.0 — Structured long-term memory baseline

- Status (2026-04-25): published on GitHub Releases and PyPI.
- Five memory surfaces land together: Identity, Active Attention, Recall,
  Procedural (manual invoke), and Evidence.
- Memory writes are versioned, provenance-bearing, review/confirmation-gated on
  high-risk paths, and stored in the SQLite-backed memory substrate.
- Derived graph query/export and consolidation foundations land with explicit
  user confirmation for promoted identity and strong-update paths.

#### v0.7.1 — Bug-fix point release

- Status (2026-04-30): published on GitHub Releases and PyPI.
- Trusted command-chat no-regex UX fix: pending confirmations become
  planner context; confirmation/rejection uses a structured PEP-gated
  `action.resolve` planner tool instead of daemon-side fuzzy/regex parsing.
- Trusted command-chat lockdown recovery: `caution`-level session lockdown
  recoverable from the chat surface via a PEP-gated `lockdown.resume`
  planner tool; lockdown notice surfaces the in-chat and CLI recovery
  paths with the session id.
- Personal `user_curated` recall and session-derived / owner-bearing retrieval
  rows are `(user, workspace)`-scoped by default; direct retrieval without a
  complete owner tuple returns public/unowned collection rows only. Same-scope
  clean recall is not classified as untrusted solely because it came from a
  prior session. Legacy unowned owner-private rows stay excluded by default,
  with maintenance-only opt-in.
- Operator preflight cleanup: harness and CLI quality-of-life fixes
  surfaced during live verification.
- Natural file-lookup follow-ups are steered toward typed filesystem tools
  rather than the deprecated `file.read` alias or shell fallback, and operators
  can inspect pending actions and lockdown state with canonical `shisad action
  list` and `shisad lockdown status` commands.

#### v0.7.2 — Memory hardening and benchmark closure

- Status (2026-05-07): published.
- Deterministic memory benchmark command path with stage metrics, oracle
  diagnostics, threshold failures, capacity probes, and pinned v0.7.1
  adversarial baseline metrics
- Retrieval/schema precision and telemetry hardening
- Memory poisoning and persistence-policy regression closure

#### v0.7.3 — Open threads + procedural memory pilot + timeline search

- Status (2026-05-09): published.
- User-visible thread controls (list, inspect, resume, close, why/explain) on
  top of the v0.7.0 Active Attention surface. Pin/snooze are deferred to v0.8
  thread UX polish.
- Proactive thread surfacing for waiting/blocked items.
- Review-gated procedural / experience memory pilot for trace-derived reusable
  artifacts, with default-deny retrieval and explicit promotion.
- Explicit timeline/archive search and read surfaces over owner-scoped prior
  sessions, with archival evidence labeling, fuzzy time bounds, redaction, and
  promotion through existing memory write gates. Packets expose source surface
  and provenance, shared-channel reads are bound to concrete delivery targets
  when available, and audit events avoid raw query/snippet text. Model-backed
  enrichment, bounded cross-session read expansion, and operator
  snapshot/migration UX remain follow-up work unless promoted during release
  close.

#### v0.7.4 — Memory evaluation runner and reproducibility

- Status (2026-05-21): published on GitHub Releases and PyPI.
- shisad exposes a public `shisad memory sut` JSON Lines (JSONL) command so
  external evaluators can drive the memory subsystem as a black-box System
  Under Test.
- MELT provides the external evaluation runner for standard memory benchmarks
  and MELT-native lifecycle suites without importing shisad internals.
- Lifecycle smoke suites exercise raw-event write quality, structured
  correction and contradiction handling, consolidation/decay, core-memory
  stability, multi-hop recall, and abstention.
- Public docs distinguish `shisad memory benchmark` smoke diagnostics from
  MELT evaluation artifacts and truth-scope preliminary versus final results.
- External full-dataset and baseline-adapter execution remains conditional on
  locally available datasets, services, and optional dependencies.

#### v0.8.0b0 — Bug-fix beta checkpoint

- Status (2026-06-25): beta checkpoint release.
- Publishes the reviewed post-`v0.7.4` bug-fix stack for users who need a more
  current installable build before the stable `v0.8.0` UX release.
- Does not claim the full v0.8 UX overhaul; theme, onboarding, web UI, and cost
  dashboard work remain in the v0.8 line.

#### v0.8.0b1 — Structured authorization beta checkpoint

- Status (2026-06-25): beta checkpoint release.
- Replaces prose goal-alignment gates and the tainted-side-effect LLM
  authorizer with structured current-turn anchoring for self-contained
  operator commands.
- Adds regression coverage for the Ledger shell demo and explicit
  shell-command confirmation paths.
- Tightens channel pending-confirmation and planner-context scoping by delivery
  target.
- Does not claim the full v0.8 UX overhaul; theme, onboarding, web UI, and cost
  dashboard work remain in the v0.8 line.

### v0.8 — UX overhaul

- v0.8.0 stable release — command-channel approvals are not CLI-only
  for supported routine paths; Discord advertises native Approve/Reject handling
  with CLI fallback, TOTP stays on trusted command channels when possible, and
  stronger method-specific proofs route to browser/helper/signer surfaces
  truthfully
- v0.8.1 patch line (in development) — supported package assembly, a local
  container candidate, minimal no-overwrite init, typed config/env inspection,
  grouped help/actionable errors, and built-in chat/dashboard/static-snapshot
  theme and accessibility wiring; durable action attempts and conservative
  restart containment; finite-state integrity and one-daemon data-root
  ownership; managed-root containment; and four-channel scoped
  delivery/approval continuity. The remaining bounded authority-consolidation
  sequence is: one live handler/composition owner, one pending-action lifecycle
  owner, typed RPC descriptors, one enforcement contract for direct operator
  RPCs, structured planner-produced memory intent, and canonical secret plus
  URL-safety primitives. Registry publication remains a release-close decision
- TUI visual overhaul — built-in theme and accessibility wiring is present;
  broader chat/dashboard/confirmation chrome remains in the v0.8 line
- CLI & config — typed TOML plus human/JSON show, validate, schema, diff, env,
  help grouping, exit statuses, and naming compatibility
- Onboarding — the interactive wizard, tutorial bot, and upgrade flow remain
  later work; v0.8.1 `init` is only a minimal template publisher
- Operator web UI on top of daemon/event-stream surfaces remains later work;
  v0.8.1 `web-ui` is a local static investigation/export snapshot
- Stats & dashboard — cost/token tracking, usage display, budget controls

### v0.9 — Security quality and consolidation

- After the planned bounded v0.8.1 secret-pattern consolidation lands, extend
  it to broader content-firewall and credential-consumer policy where evidence
  warrants it
- If the planned v0.8.1 canonical URL/SSRF primitive lands for current
  consumers, use that boundary before simplifying the broader network
  enforcement stack
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

| Capability | Release / destination |
| --- | --- |
| Personal reminder / notetaker baseline | v0.5 (shipped) |
| Evidence references | v0.5 (shipped) |
| Multi-agent orchestration | v0.6.0 (shipped) |
| Web tools + browser automation baseline | v0.6.0 (shipped) |
| Control-plane isolation | v0.6.1 (shipped) |
| Hardware-backed approvals | v0.6.2 (shipped) |
| Critical UX stabilization | v0.6.3 (shipped) |
| textguard port | v0.6.4 (shipped) |
| MCP/A2A interop | v0.6.5 (shipped) |
| Local email connector baseline | v0.6.6 (shipped) |
| Local attachment ingest baseline | v0.6.6 (shipped) |
| Full attachment processing pipeline | Future connector work |
| Long-term memory | v0.7 (shipped) |
| Command-chat UX bug fixes (no-regex, lockdown recovery, state inspection) | v0.7.1 (shipped) |
| Memory hardening + benchmark closure | v0.7.2 (shipped) |
| Open-threads UX + procedural memory pilot + timeline search | v0.7.3 (shipped) |
| UX overhaul foundation | v0.8.0 (shipped) |
| Reliable-foundation patch line | v0.8.1 (development) |
| Live operator web UI | Later operator UX |
| Security infrastructure consolidation | v0.9 (planned) |
| Multitenant support | v0.10 (planned) |

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
10. Command-chat bug-fix point release (`v0.7.1`)
11. Memory hardening + benchmark closure (`v0.7.2`)
12. Open threads + procedural memory pilot + timeline search (`v0.7.3`)
13. UX overhaul foundation (`v0.8.0`); live operator web UI remains later work
14. Reliable-foundation patch line (`v0.8.1`, development)
15. Security infrastructure consolidation (`v0.9`, planned)
16. Multi-tenant support (`v0.10`, planned)

## Public Announcement Criteria

Before broader public launch:

- **Zero-friction inference**: automatic option to use [Shisa.AI](https://shisa.ai) inference infrastructure (free credits on signup, choose your model) or model partners — no BYOK required to get started
- **Official Docker image**: published container image for reproducible deployment
- **One-click instance spinup**: dedicated shisad instances from a single action (web or CLI)

## Gaps Not Yet Scheduled

- Additional messaging channels such as WhatsApp, Signal, iMessage, and WeChat
- Per-group isolation and richer group-chat routing UX
- Swarm-style multi-agent behaviors beyond the orchestrator/subagent model
