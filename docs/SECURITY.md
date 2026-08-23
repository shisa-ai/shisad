# shisad — Security Architecture

This document describes shisad's security model at an architectural level. For the governing design principles, see [DESIGN-PHILOSOPHY.md](DESIGN-PHILOSOPHY.md). For the research literature behind these choices, see the [agentic-security](https://github.com/lhl/agentic-security) survey (78 papers, defense taxonomy, recommended defense-in-depth stack).

---

## The Problem

LLMs destroy the instruction/data boundary that traditional computing relies on. In a normal program, code and data are separate — you can't execute data. In an LLM, everything — system prompts, user messages, retrieved documents, tool outputs — becomes a unified token stream. The model processes it all the same way. This is what makes LLMs powerful (they can reason about anything) and what makes them fundamentally insecure (anything can influence their behavior).

A general-purpose agent that has (1) access to private data, (2) exposure to untrusted content, and (3) the ability to take consequential actions is inherently high-risk. This is the [lethal trifecta](https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/) ([Fowler](https://martinfowler.com/articles/agentic-ai-security.html)). shisad has all three by design — it's meant to be a useful assistant, not a sandboxed demo. The question is not whether the LLM can be tricked (it can), but how much damage it can do when it is.

## The Approach

Since LLMs won't separate instructions from data, the surrounding architecture must re-create the boundary the LLM collapses.

**On the shared planner path, the LLM is a planner, not an executor.** It can
only *propose* actions. A separate control plane decides what executes from
structured metadata (action types, resource identifiers, timing, and sequence
patterns), rather than accepting model text as enforcement authority.
Authenticated local operator convenience RPCs are already typed rather than
planner proposals; their arguments enter the same PEP, control-plane, durable
execution, audit, taint, and output-sanitization authorities through a
short-lived internal session. Their exact route boundaries are documented
below and in [AUTHORITY-MAP.md](AUTHORITY-MAP.md).

```
                       ┌─────────────────┐
                       │   LLM (Planner) │
   Untrusted ─────────►│   [tokens mix]  │─────────► Proposed
   Content             │                 │            Actions
                       └─────────────────┘
                                                       │
   ═══════════════════════════════════════════════════════════
   ║               ARCHITECTURAL BOUNDARY                    ║
   ═══════════════════════════════════════════════════════════
                                                       │
                                                       ▾
                        ┌─────────────────┐     ┌─────────────┐
                        │ Trusted Config  │     │  Security   │
                        │ (policies,      │     │  Analyzers  │
                        │  goals)         │     │ (metadata   │
                        └─────────────────┘     │  only)      │
                                                └──────┬──────┘
                                                       ▾
                                                APPROVE / REJECT
```

This is the same principle as CPU memory protection: we don't try to make programs "not write to protected memory" — we make it architecturally impossible. We are not trying to make LLMs "robust to injection" through clever prompting. Adaptive attackers have been shown to [bypass prompting-based defenses at >90% rates](https://arxiv.org/abs/2510.09023), but even if the defense rates were massively better, say 99.9% or 99.99%, that would mean that every thousandth or ten-thousandth attack would result in a system compromise. Our architectural guarantees and defense-in-depth seek to prevent and contain damage even with a successful injection attack.

---

## Core Question: Who Asked for It?

The product goal and the security goal are the same question: **did the user request this action, or did something else cause it?**

shisad is the user's agent. It exists to do what the user asks with the highest possible fidelity. The entire security architecture — taint tracking, provenance labeling, confirmation gates, privilege separation — is infrastructure to answer that question reliably at every action. User-requested actions should succeed. Actions caused by injection, hallucination, or attacker-controlled input should not. Provenance, not phrasing, determines enforcement: the system doesn't try to decide whether a request "looks legitimate" — it traces where the request actually came from.

This is what distinguishes shisad from both permissive agents (which can't tell the difference between user intent and injected intent) and restrictive agents (which solve the problem by blocking everything). The goal is not to limit what the agent can do — it's to ensure that what it does is what the user actually wanted.

## Security Principles

**1. Content-blind enforcement vs. content-seeing detection.** Security components fall into two categories:

- **Content-blind** (control plane): see only action types, resource identifiers, timing, sequence patterns. They do not inspect file contents, message bodies, or free-form text. These are the hard enforcement boundary. Examples: the PEP's tool-registry/capability/resource/egress checks, behavioral sequence analyzer, resource access monitor, and consensus voting.
- **Content-seeing** (detection): see content to classify, score, sanitize, or apply a bounded deterministic DLP rule. These use classifiers, finite signatures, and heuristics, not general-purpose LLMs. They are not general intent authorities — they can flag, redact, add taint, escalate, or reject an exact deterministic policy match. Examples: content firewall (injection and secret detection), output firewall (secret/PII detection), and the PEP's argument DLP check.

Security signals from content-seeing components are structured metadata
(scores, flags, enum labels). A sanitizer may also return rewritten user-facing
text, but that text is not enforcement authority.

**2. Commit before contamination.** Plans are committed *before* untrusted content is seen. Even if content contains "ignore the plan", the plan is already locked.

**3. Graduated response.** Normal user-goal actions auto-approve (no confirmation). When uncertain, escalate through the confirmation ladder: confirm with the user, deny the specific action if confirmation is refused, escalate to lockdown only for genuine multi-signal anomalies. A false positive that blocks a user-requested action is a product failure.

**4. Privilege-separated control plane.** The runtime uses three privilege tiers: **TASK** agents handle untrusted content in sandboxed, ephemeral contexts. The **COMMAND** agent orchestrates — it holds user intent, dispatches TASKs, and presents results, but cannot modify system configuration. **SUDO** mode is a clean-room elevation triggered by intent detection on authenticated channels — it can modify policy, capabilities, credentials, and configuration, but its context is stripped to the current user message and system instructions only (no summaries, no artifacts, no residual TASK context), and it auto-drops back to normal operation after the privileged action completes. System modification is possible, but only through this constrained privileged workflow — there is no unconstrained self-modification and no agent-writable instruction files. Policies are read-only to the agent in normal operation. Audit logs are append-only.

**5. Stateless context is a security primitive.** LLMs have no persistent memory between turns. We have complete, deterministic control over what the model "knows" at every turn. The model cannot hide state, cannot remember something we've removed, and cannot resist a context rollback. This enables: checkpoint rollback to pre-contamination state, context forking for isolated task agents, selective context construction and taint quarantine, clean-room sessions provably free of tainted content, and differential execution to empirically test whether content is influencing behavior.

**6. Can't leak what you don't have.** Broker-managed credentials are not
placed in the LLM context. A credential broker resolves an opaque reference at
the HTTP proxy layer, so the model cannot exfiltrate the brokered value it
never receives. User-provided or retrieved text can still contain
credential-like material; bounded ingress, output, and argument-DLP detection
is defense in depth for that separate case. Model-provider references use a
separate trusted construction boundary: versioned metadata resolves only while
the daemon constructs trusted provider configuration, never in config/status
output or an LLM prompt. This is the scoped invariant I3; it is not a claim
that arbitrary user-supplied secrets cannot reach a model.

**7. Approvals don't launder provenance.** When a user confirms an ambiguous action, the confirmation authorizes *that specific action* — it does not remove taint labels, change the content's provenance, or grant blanket trust to the source. A confirmed web fetch from an untrusted page does not make the fetched content trusted. Taint persists through the full data lifecycle regardless of intermediate approvals.

Approval decisions are also bound to their origin. When an action is approved,
rejected, or executed through a confirmation path, the audit trail can record
the originating session, task-envelope ID, confirmation ID, decision nonce,
and timestamp. Approval is evidence about *who approved what*, not a trust
upgrade for the underlying content.

Pending approval authority is time-bounded in the supported profile: 1 hour by
default and at most 24 hours, including when a policy requests a longer window.
Legacy pending rows without an expiry are terminalized on first post-upgrade
load and their old decision nonce is invalidated. The action must be requested
again; a TOTP window or approval-web link lifetime is a separate challenge or
capability deadline and cannot extend the pending action.

Decision-nonce migration is restricted to the exact authenticated parent
contract from before that field existed. A current-format contract with a blank
nonce is invalid approval authority and is terminalized.

Approved execution is also crash-aware. Before invoking a tool effect, the
daemon durably records the action digest, approval-evidence hash, execution
attempt ID, result ID, and `executing` state. On restart, only the exact
in-process `time.now` route or a trusted adapter carrying the same persisted
provider idempotency key may receive one bounded automatic recovery call. The
daemon authenticates the post-decision recovery-authority snapshot with a
separate domain under its durable confirmation-evidence HMAC key, then
revalidates the live tool schema, action and retry descriptors, execution
identity, session and principal, current policy, approval evidence, and expiry
before that call. A missing or mismatched recovery authenticator fails closed
to `outcome_unknown` and clears replay authority.
Normal execution and recovery reuse one attempt-scoped control-plane accounting
identity, so history and trace counters record the logical attempt once.
Automatic recovery in v0.8.1 additionally requires that the durable attempt has
no delivery target. Any target-bearing attempt becomes `outcome_unknown`, even
when the stored target appears unchanged, because this release does not claim a
recovered-result delivery or continuation contract. Every other missing,
corrupt, drifted, exhausted, or unclassified case also becomes
`outcome_unknown`; arbitrary web requests, message delivery, dynamic skills,
MCP tools, and other external effects are not replayed merely because they look
read-like or use HTTP GET.

`outcome_unknown` means the external effect may or may not have happened. The
old decision nonce is invalidated, while `shisad action list --status
outcome_unknown` retains known action/attempt/result/provider identifiers and
gives an informed manual-retry instruction. Inspect provider or local evidence
first; retrying means re-requesting the action and satisfying a new approval.
Provider reconciliation is not generally available in v0.8.1, and shisad does
not claim universal exactly-once behavior for arbitrary external services.
Stable provider idempotency keys remain in private durable state and are not
returned by the public pending-action API. If a stable-key adapter contradicts
the first durable control-plane outcome for the same attempt, the action becomes
`outcome_unknown`; the first outcome remains authoritative for history and
trace accounting, and scheduler containment records a failure without consuming
a second logical run. If an uncertain attempt belongs to a scheduled task, that
task is disabled so it cannot automatically repeat the possibly completed
effect; you must reconcile the result before creating or enabling further work.

During a consistent stable-key recovery, the scheduler's original enabled
posture is authenticated and preserved across restart containment. The daemon
restores an originally enabled task only after accounting completes and only
when its run limit still permits another run; an already-disabled task stays
disabled, and uncertainty or contradiction never re-enables it.

Stage-two amendments are correlated to one confirmation and an explicit
execution-attempt idempotency key. Uncertain transport or internal results and
failures before the durable ready transition cancel only the exact correlated
amendment. After control-plane restart, authority remains active only when the
exact correlated attempt key appears in durable trace-action accounting;
aggregate execution by unrelated same-session actions is not reconciliation.

Concurrent confirmation clicks for one action are serialized by an in-memory
per-confirmation lock while that daemon process is running. That lock is a
local concurrency guard, not durable exactly-once evidence; the persisted
attempt/result lifecycle above is the restart authority.

**Local state integrity and ownership.** Included finite control-state stores
use a versioned JSON envelope with a SHA-256 checksum over canonical payload
bytes and publish by same-directory temporary file plus atomic replacement.
The checksum detects accidental corruption; it is not an authenticity proof
against an attacker who can rewrite the state and checksum together. Actual
file and parent-directory durability, and optional permission tightening, are
reported according to host/filesystem capability. shisad does not claim
universal power-loss durability or universal POSIX owner, descriptor, or mount
semantics.

One maintained-library file lock gives a running daemon, backup, or restore
exclusive ownership of its local data root. Each owner opens the same regular
`.shisad.lock` child relative to a pinned data-root handle, applies the existing
OS advisory lock, and verifies that the acquired descriptor has the rooted
child's identity. The lock artifact is persistent, so its presence alone does
not mean a process currently holds it. This is a same-host process-coordination
boundary, not a distributed lease, and does not defend against administrators,
root, a compromised host, or unrestricted malicious native code running as the
same user. Independent data roots remain usable concurrently.

Stopped-daemon backup and restore keep consequential traversal, creation, and
publication relative to opened directory handles on supported local POSIX and
Windows filesystems. Windows enumerates and, during failure cleanup, deletes
through verified native handles. Portable POSIX cannot conditionally unlink a
mutable name by inode; when safe ownership cannot be preserved, failure leaves
actionably reported backup or partial-restore residue rather than risking
deletion of a concurrently substituted object. This is a failure postcondition,
not a claim of universal atomic cleanup, hostile same-user isolation, or
multi-host coordination.

Malformed, checksum-mismatched, or future-version state is preserved and
degrades only its owning component. shisad does not silently replace it with an
empty store and does not provide automatic backup or repair; restore a trusted
snapshot or use an existing explicit reset/re-enrollment path. Evidence
metadata is especially conservative: cleanup, quarantine, expiry deletion, and
garbage collection stop while its metadata domain is uncertain. A crash may
therefore leave an unreferenced blob; that bounded leakage is preferred to
deleting data on uncertain authority.

Installed dynamic-skill inventory rows bind a canonical manifest-and-file
digest, and runtime drift suppresses only the affected skill. Active
self-modification inventory rows carry the corresponding signed-artifact
digest; invalid drift disables self-modification/behavior overlays and keeps
the default planner plus unrelated features available.

Assistant filesystem and Git tools reject the managed data root and exact
configured external approval, signer, and operator `SOUL.md` files (including
their adjacent lock files). This protects those files from the assistant tool
surface; it is not a host-global filesystem policy and does not restrict a
trusted operator using the host directly.

Shisad-owned child launches also use operation-specific environment profiles.
Fixed isolation/signature children receive process basics only; sidecar, SSH,
msgvault, MCP, and coding-agent children retain only their documented
component-scoped auth, transport, or explicit per-server inputs. Ambient
function exports, Python/Node runtime injection controls, unrelated
credentials, and askpass/Git helper controls are not forwarded on these paths.
This inheritance boundary does not sandbox a configured child or defend against
an unrestricted malicious same-user process.

Assistant Git reads, coding-worktree lifecycle commands, and evaluation source
probes use a fixed non-interactive Git environment and command-line overrides
for hooks, fsmonitor, external diff/textconv, and signature verification.
Filter preflight reads normal system/global/local/worktree configuration as
data, with normal precedence, but ignores ambient `GIT_CONFIG_*`
location/injection overrides and never executes configured values. Coding
worktrees are created without checkout, structurally inspect selected filter
drivers, and then check out with optional drivers disabled. A selected filter
marked required with an executable clean/smudge/process command blocks coding
checkout, assistant status/diff, and the evaluation dirty probe with actionable
guidance instead of executing silently or returning a misleading projection.
Commit-only assistant log remains available. These controls apply to
shisad-owned Git commands; they are not a claim that an authorized coding agent
cannot itself run repository commands.

Channel replay state remains a bounded best-effort guard. Corrupt replay state
may forget prior message IDs, so this layer does not claim daemon-level,
provider-level, or distributed exactly-once delivery.

**8. Context control is a first-class security primitive.** Because we construct the LLM's context each turn, we can choose exactly what the model sees — and more importantly, what it *doesn't* see. This is unique to LLM-based systems and has no equivalent in traditional software. Evidence references are the primary application: large untrusted content (web pages, email bodies, tool output) is stored out-of-band in a content-addressed evidence store, and the LLM receives only an opaque reference stub with metadata. The raw tainted content never enters the conversation history, so it cannot persist as an injection surface across turns. When the model needs to re-examine content, it makes an explicit `evidence.read` tool call — which goes through PEP enforcement and returns content into a single-turn isolated context, not the persistent transcript. This turns the usual LLM limitation (no persistent memory) into a security advantage: we can quarantine, exclude, or replace any piece of context at any time, and the model cannot tell the difference.

---

## Threat Model

### Attack Categories

| Category | Vector | Mitigation Layer |
|----------|--------|-----------------|
| Direct injection | User input | Content firewall + PEP |
| Indirect injection | External content (web, email, tool output) | Content firewall + spotlighting + taint tracking |
| Memory poisoning | Conversation / RAG | Memory manager (gated writes, provenance) |
| Tool abuse | Legitimate tool calls with malicious arguments | PEP + capability scoping + argument DLP |
| Exfiltration | Egress channels | Output firewall + egress allowlisting + taint sink enforcement |
| Multi-step chains | Orchestrated action sequences | Behavioral sequence analyzer + rate limiting + consensus |
| Supply chain | Malicious skills, upstream packages | Vetting + lockfiles + provenance/signing + sandbox |

### Security Invariants

These hold regardless of LLM behavior:

- **I1**: No outbound communication includes high-sensitivity content unless user-approved
- **I2**: Untrusted content cannot trigger new privileges
- **I3**: On shared PEP paths, broker-managed credentials use opaque refs and
  structured string arguments matching a canonical secret signature are
  rejected before execution
- **I4**: Silent forwarding is impossible (no hidden BCC, auto-forward, share-to-anyone)
- **M1**: Long-term memory writes are gated (user approval or strict schema)
- **M2**: Memory stores facts/preferences, not instructions
- **M3**: Memory is attributable (source, timestamp) and reversible
- **S1**: No third-party extension executes on a sensitive path without review or pre-approved provenance
- **S2**: All skill-initiated actions go through the PEP (no supply-chain bypass)

---

## Enforcement Architecture

```
  Channels ──► Content Firewall ──► Context Builder ──► Planner LLM
  (Discord,    (sanitize, score,     (spotlighting:      (untrusted;
   Matrix,      taint-label)          trusted/untrusted    proposes only)
   Telegram,                          separation)
   Slack)                                                    │
                                                             │ proposals
              ┌──────────────────────────────────────────────┘
              │
              ▾
  Action Monitor ◄──► Policy Enforcement Point (PEP) ◄──► Confirmation UI
  (guardrail;         (8-layer pipeline;                   (human-in-the-loop)
   detection only)      hard enforcement)
                              │
                              │ approved actions only
                              ▾
                        Tool Executors ──► Output Firewall ──► User
                        (sandboxed)       (DLP, secret/PII
                              │            redaction)
                              ▾
                        Memory Manager
                        (gated writes,
                         taint-preserved)
                              │
                              ▾
                         Audit Log
                        (append-only,
                         tamper-evident)
```

### PEP Pipeline (8 layers, shared execution path)

1. **Registry check** — is this a known, registered tool?
2. **Schema validation** — do the arguments match the tool's typed schema?
3. **Capability check** — does this session have the capability class for this tool?
4. **DLP / argument scanning** — do structured string arguments match a
   canonical secret signature? This is not general PII or password inference:
   the current finite registry covers provider API keys, GitHub/OAuth tokens,
   AWS access-key IDs, JWTs, and private-key blocks.
5. **Resource authorization** — object-level access control; planner-proposed resource IDs are treated as untrusted and verified server-side
6. **Egress allowlisting** — provenance-aware destination enforcement (see below)
7. **Credential host-scoping** — credentials resolved by the broker at the proxy layer, never exposed to LLM context
8. **Taint sink enforcement** — provenance-aware rules at egress sinks (user-goal → proceed; autonomous/unattributed → confirm; attacker-initiated → block)

### Runtime route boundary

The PEP list above applies to actions executed through the shared planner,
administrative `tool.execute`, and typed operator convenience effect paths. It
is not a universal claim about every callable daemon method.

| Route family | Authority and enforcement | Audit / observability |
|---|---|---|
| `session.message` from the local control socket or a trusted command channel | Authenticated ingress builds a session turn; planner-proposed actions enter shared policy, PEP, confirmation, control-plane, and tool-execution handling | Session, policy, confirmation, action, and execution events on the shared path |
| Signed A2A `session.message` ingress | Fingerprint verification, replay protection, intent grants, and rate limits precede the same session/planner path; the remote principal's grants remain authoritative | A2A ingress evaluation plus shared-path events |
| Administrative `tool.execute` | Local administrator RPC; invokes the shared PEP/control-plane/confirmation execution handler directly | Shared-path action and execution events |
| Convenience `web.*`, `realitycheck.*`, `email.*`, `fs.*`, and `git.*` RPCs | Authenticated local operator routes resolve descriptor/admin posture, create a short-lived direct session, and enter PEP, control-plane, durable approved-action execution, then toolkit-local checks; explicit higher-assurance policy still binds and `fs.write` retains its `confirm` gate | Shared session, plan, action, execution, taint, and sanitized-output evidence; stable typed readiness and boundary results |
| `action.confirm` / `action.reject` | Exact pending-action identity, decision nonce, actor/surface binding, required proof, and durable lifecycle checks | Durable decision and execution correlation on the pending-action path |
| Scheduler and command-channel delivery | Background work and channel ingress use shared handler execution and scoped delivery bindings; ambiguous external outcomes are contained rather than silently replayed | Scheduler, delivery-attempt, and pending-action state plus shared-path events |

The convenience methods remain distinct typed operator ingress rather than
model-controllable planner proposals. They require the local authenticated
control surface and retain their input, filesystem, Git, URL, readiness, and
configuration checks while sharing downstream decision and effect authority.

### URL and network destination facts

Matching provider endpoint, egress proxy, browser, assistant web, and PEP
paths share one typed absolute-URL projection for scheme, canonical host,
explicit port, and userinfo presence. They also share one address classifier
for standard and supported Linux/Python legacy numeric IP forms, public versus
private/special addresses, loopback, and the bounded local-name family.
Equivalent host case, one DNS root dot, legacy numeric IPv4, and IPv4-mapped
IPv6 forms therefore enter those consumers with the same structural facts.

Those facts are not themselves authorization. Each consumer retains its own
public-destination path and its explicit local/private exceptions, along with
its existing allowlist, provenance, confirmation, provider authentication,
redirect, DNS, expected-address rebinding, credential, connection-scope,
reason-code, and audit layers. Host classification alone neither pins DNS nor
verifies the peer used by a later connection, so this is not a universal SSRF
or DNS-rebinding guarantee.

### Consensus Voting (5 independent voters)

Multiple content-blind analyzers must converge before escalation:

| Voter | What it sees |
|-------|-------------|
| Behavioral Sequence Analyzer | Action patterns (read-then-exfil, rapid tool switching, unusual combinations) |
| Resource Access Monitor | Resource access per session (file paths, URLs, memory keys); flags anomalous breadth or sensitivity jumps |
| Execution Trace Verifier | Proposed actions vs. committed plans; flags plan violations and capability scope overflows |
| Network Intelligence Monitor | Egress metadata (destination reputation, frequency, timing) without seeing content |
| Consensus Voting | Aggregates all signals; escalation requires multi-voter agreement |

An attacker would need to fool all voters simultaneously. Each sees a different metadata slice.

### Content Firewall (ingress)

- HTML/text normalization (strip hidden text, zero-width chars, Unicode canonicalization)
- Canonical finite secret-signature redaction with `USER_CREDENTIALS` taint
- Prompt injection classifiers (ML-based detection + YARA pattern rules)
- Risk scoring (not just pass/fail)
- All output taint-labeled with provenance for downstream enforcement

### Context Builder (spotlighting)

Three-tier prompt layout: trusted instructions, internal state, untrusted content. Uses random delimiters and datamarking to make it structurally harder for the model to treat data as instructions. Based on the [Microsoft Spotlighting](https://arxiv.org/abs/2403.14720) approach.

### Credential Broker

Broker-managed secrets do not enter the LLM context. Tools reference those
credentials by opaque handle; the credential broker resolves handles to real
values at the HTTP proxy layer on the outbound hop. The LLM sees
`credential_ref: "gmail_oauth"`, not the actual token. This claim is scoped to
credentials held by the broker; credential-like text supplied by users or
retrieved content is handled separately by the canonical signature consumers.

For delegated TASK sessions and persisted scheduler/background tasks, credential
use is narrowed again by the immutable task envelope: the envelope carries an
explicit `credential_refs` allowlist, and the PEP denies missing or
out-of-scope refs fail closed. Tool grants do not imply credential grants.

The v0.8.2 setup foundation also administers provider-agnostic logical
references through redacted `credential set/status/remove` commands.
Environment entries persist only a variable name. The optional OS-keyring
backend never falls back to disk when unavailable. The local file backend is
truthfully permission-protected plaintext (`0700` directory, `0600` file), not
encrypted storage. Generated TOML may name a reference but does not contain the
resolved value. These references now wire model routes and enabled
Matrix/Discord/Telegram/Slack adapters at their trusted construction
boundaries. A missing channel reference or optional client runtime degrades
only that channel. Channel setup never infers an ingress identity grant, and
its optional fixed test notice requires an explicit target and makes one
normal durable-delivery attempt; an uncertain effect is not automatically
retried or described as an inbound round trip.

Combined setup accepts only the typed provider/policy/channel selection schema;
unknown fields and raw-secret fields are rejected without echoing document
contents. The interactive wizard is unavailable in managed or non-terminal
postures and uses a final default-no write confirmation. Deterministic
`setup apply` never prompts and remains a dry run unless `--write` is explicit.
It publishes the validated policy before activating that exact path in a
commented, schema-validated TOML config. Both files are exclusive no-overwrite
`0600` artifacts, and final TOML contains credential references rather than
resolved values. This ordered pair is not a transaction: a later config-write
failure can leave an inert policy artifact, which the error reports for
operator inspection or removal. Setup does not start the daemon or turn a
skipped probe into verification evidence.

### Evidence References (context isolation)

Large untrusted content is stored out-of-band in a content-addressed evidence store. The LLM context receives only a short reference stub with metadata (`[EVIDENCE ref=ev-a1b2c3d4 source=web.fetch:nytimes.com taint=untrusted size=14832 summary="..."]`). The raw tainted content never enters the conversation transcript, eliminating persistent injection surface. When the model needs to re-examine content, it calls `evidence.read(ref_id)` — which goes through PEP enforcement and returns content into a single-turn isolated context. This dramatically reduces the token-budget cost of tainted content and limits each injection payload to a single exposure window.

Internally this now lives in a structured ArtifactLedger rather than an
ad-hoc blob map. The ledger persists artifact lifecycle state and endorsement
metadata alongside the ref. Endorsement is narrow by design: a user-endorsed
artifact may pass the `evidence.promote` confirmation seam on later reuse, but
endorsement does not strip taint, upgrade provenance, or make the artifact
globally trusted.

Structured cross-boundary fields are also constrained by semantic tool-schema
types. Sink-critical arguments such as URLs, command tokens, workspace paths,
evidence refs, and thread ids are validated as atoms or opaque handles instead
of being accepted as arbitrary free text. These semantic atom checks protect
the planner / TASK orchestration path and structured TASK-return boundary; the
explicit admin `tool.execute` surface is a separately trusted operator path
with its own policy and audit controls.

Delegated TASK output crosses a second boundary before it can influence the
COMMAND transcript: the TASK raw response must pass through a mandatory
summary-firewall checkpoint, and the resulting summary checkpoint artifact is
persisted before the sanitized summary is handed back. If the checkpoint cannot
be produced, the handoff fails closed instead of letting an unchecked TASK
summary enter the orchestrator context.

### Output Firewall (egress)

- Canonical finite secret-signature redaction (API keys, tokens, JWTs, private
  keys) with typed findings that omit raw matches
- PII redaction for content crossing trust boundaries
- URL/destination validation on outbound content

The canonical registry is an ordered set of seven machine-defined signature
families shared by ingress, output, and PEP argument DLP. Each consumer keeps
its own action and preprocessing stage. The registry itself does not decode,
normalize, infer entropy or passwords, or promise recognition of encoded and
Unicode-obfuscated variants.

### Memory Manager (poisoning defense)

Memory is a high-value attack surface. Research ([MINJA](https://arxiv.org/abs/2503.03704), [AgentPoison](https://arxiv.org/abs/2407.12784)) demonstrates that attackers can inject poisoned entries into an agent's long-term memory through normal interaction — no direct database access required. The poisoned entries persist across sessions and can redirect future behavior with high success rates and minimal utility degradation, making the attack hard to detect. For the full literature survey, see [agentic-memory](https://github.com/lhl/agentic-memory).

shisad's defense is **preventive write gating** — making poisoned entries hard to store in the first place, rather than trying to detect and remove them after the fact:

- **Instruction-like pattern rejection**: deterministic filter rejects content that resembles directives ("always do X", "ignore policy", "never do Y") before it reaches storage. Memory stores facts and preferences, never instructions.
- **Provenance-gated writes**: every memory write requires structured provenance
  metadata (source, origin, actor, timestamp, capability snapshot). High-risk
  external-source writes such as web content, tool output, and email route to
  confirmation or review when the trust matrix requires it. Session-derived
  conversation-summary extraction is provenance-marked; when the session has a
  complete owner tuple, resulting writes are owner-scoped. By default, the
  summarizer attempts writes through an auto-accepted ingress path, but each
  proposed memory write still passes write policy and can be allowed, rejected,
  or require confirmation. Operators can disable automatic extraction with
  `SHISAD_MEMORY_AUTO_EXTRACTION_ENABLED=false` or raise
  `SHISAD_MEMORY_AUTO_EXTRACTION_CONFIDENCE_THRESHOLD`.
- **Subagent write restriction**: task agents handling untrusted content cannot write to long-term memory directly — they can only propose writes via structured outputs with provenance pointers. The orchestrating agent reviews proposals in a clean context with no untrusted content present. This structurally breaks the MINJA attack chain where the agent's own reasoning stores malicious entries.
- **Taint persistence through storage**: provenance and taint labels are immutable properties of stored entries. Processing, summarizing, or combining content does not upgrade its trust level — derived content inherits the most restrictive taint of its sources.
- **Append-only corrections**: updates create new records referencing what they supersede, preserving full history for audit and rollback. No silent overwrites.
- **Tiered storage**: different memory types (episodes, facts, task state, constraints, procedures) have different trust semantics and write postures. Procedural/experience memory — the highest-risk tier for instruction mimicking — is isolated with strict firewall and quarantine defaults.

---

## Trust Boundaries

| Boundary | What crosses it | Enforcement |
|----------|----------------|-------------|
| Untrusted ingress | Web pages, emails, API responses, tool output | Content firewall + taint labeling |
| LLM boundary | Constructed context → proposed actions | Not a security boundary; assume compromised |
| Model provider | Prompts sent to LLM API endpoints | Endpoint allowlisting; HTTPS for remote; no raw credentials in prompts |
| Tool boundary | Approved proposals → actual execution | PEP pipeline; sandboxed executors |
| Egress boundary | Anything leaving the system | Output firewall + provenance-aware taint sink rules |
| Persistence boundary | Memory / vector DB / logs | Gated writes; taint preserved; append-only audit |

For TASK and background sessions, the task envelope is itself part of the trust
boundary. It carries capability scope, credential refs, resource-scope ids /
prefixes, and untrusted-trigger policy. Background runs still go through the
same PEP pipeline, but the envelope can force confirmation or rejection when an
untrusted event payload tries to drive autonomous execution.

---

## Egress Model

The egress model answers "who asked for it?" at every outbound action:

| Scenario | Action |
|----------|--------|
| Destination on allowlist (pre-approved) | Proceed, audit trail (no confirmation) |
| Unknown destination, explicitly requested by user | Proceed, audit trail (no confirmation) |
| Unknown destination suggested only by untrusted content | Confirmation gate with warning |
| Unknown destination with no user attribution (hallucination/drift) | Block + actionable error |
| Known-bad destination (exfil patterns) | Block regardless |

The allowlist is an auto-approve list and a safe default for autonomous actions. It is not a hard wall for explicit user requests.

---

## Clean-Room Workflows (SUDO mode)

Privileged operations (config changes, capability grants, credential management, skill installs) trigger SUDO mode — a clean-room session that:

- Is stripped to the current user message and system instructions only (no summaries, no artifacts, no residual TASK context, no memory retrieval except trusted config state)
- Triggers automatically via intent detection on authenticated channels (the agent cannot self-escalate)
- Produces only a structured diff/proposal (never applies changes directly)
- Is enforced by deterministic validators and explicit approval before commit
- Auto-drops back to normal operation after the privileged action completes

This is what makes system modification safe without making it impossible. The COMMAND agent in normal operation has no tools to modify its own constraints. SUDO mode provides those tools, but only in a context provably free of tainted content — so even if an attacker has influenced the agent's reasoning in normal operation, that influence cannot carry into the privileged workflow.

## Destructive Command Protection

Certain catastrophic command patterns (e.g., `rm -rf /`) are blocked structurally at the sandbox/policy layer before execution, not by LLM judgment. Protected path registry, severity-tiered detection, and recursive deletion scope analysis ensure no prompt injection, jailbreak, or misconfiguration can make the agent destroy a host filesystem.

### Command containment profiles

The default `sandbox.containment_profile: supported` posture requires the
selected process-isolation backend. If that backend or its required network
boundary is unavailable, command-backed static tools and installed-skill tools
fail closed before the original command is invoked on the host. Results and
`shisad doctor check --component sandbox` report the requested backend, the
actual backend when one ran, degraded controls, and an operator next action.

On Linux, network-enabled commands additionally require `bwrap`, `pasta`, and
the configured connect-path enforcement helper. shisad creates an isolated
network namespace, holds the command behind a pre-exec gate, attaches
user-mode networking, and installs destination rules before releasing the
command. The bubblewrap command policy drops all Linux capabilities before the
tool starts. The current path is IPv4-only. Names authorized and resolved before
execution are pinned in a generated read-only hosts file; the namespace does
not receive an external DNS forwarder or host/namespace port forwarding. A
missing helper, namespace setup failure, or rule-installation failure leaves
the command unstarted in the `supported` profile. Doctor's backend rows report
network-namespace isolation, network-transport prerequisites, and DNS-control
availability separately from the base process-isolation runtime.

`sandbox.containment_profile: expert_host_fallback` is a separate explicit
operator posture for environments that accept host execution when isolation
cannot be provided. It preserves declared tool functionality but is not a
supported containment claim: startup logs, doctor output, approval previews,
sandbox results, and degraded audit events identify the fallback. Call-level
arguments and per-tool overrides cannot select this profile or weaken the
supported profile.

Installed dynamic tools carry immutable registration source, installed-skill
identity, and requested containment metadata. Immediately before any shared
execution path invokes an effect, shisad derives skill identity from that
registered definition and rechecks inventory publication, bundle and manifest
digests, tool schemas, and declared command/path/environment/network
capabilities. Executable authorization uses the original argv atom, and path
authorization includes the working directory and implicit absolute-argument
mounts; a post-authorization executable substitution is rejected before
launch. Skill and local tool identifiers are canonicalized consistently across
activation, restart, authorization, registration, and revocation. A
caller-provided `skill_name` is never treated as authority.

## Supply Chain

Dependencies are pinned via `uv.lock` with SHA256 integrity hashes. Skills are
treated as untrusted code: capability manifests declare what a skill can
access, PEP rejects undeclared operations, installed skill tools execute
through the shared tool-enforcement path, and no skill auto-installs without
user review. A caller-supplied skill name is not authority.

As of the published `v0.8.0` line, the CI/release path is also materially
hardened: GitHub Actions are pinned by SHA, CI runs dependency-review on PRs,
workflow linting (`zizmor`), and GitHub code scanning, and the public release
path goes through GitHub Actions `publish.yml` using PyPI OIDC trusted
publishing with release-time dependency audit, SPDX SBOM generation, and build
provenance attestations. The manual upload path still exists only as an
emergency fallback and does not carry the same provenance guarantees. See
`docs/AUDIT-supply-chain.md` and `analysis/ANALYSIS-supply-chain.md` for the
full analysis.

---

## Implementation Status

The latest published stable package is `v0.8.1`. The following statements
describe that public release tree and are subject to the explicit route
boundary above.

**Implemented on the shared execution path**:

- The eight PEP checks, taint/provenance labeling, ingress and output
  firewalls, five-voter control-plane analysis, credential scoping,
  confirmation, and append-only audit handling.
- Formal `COMMAND` / `TASK` orchestration with immutable task envelopes,
  taint-safe handoffs, resource and credential scopes, summary-firewall
  checkpoints, and approval provenance.
- Structured ArtifactLedger/evidence storage, restart-stable refs, memory
  surfaces with provenance-gated writes, web/browser baselines, MCP client
  tools, signed A2A ingress, and reviewed local skill-tool integrity checks.
- Multi-factor approval through software confirmation, TOTP, WebAuthn,
  local-FIDO2 helper, remote KMS, and supported Ledger signing surfaces.
- The current `v0.8.1` tree adds durable pending-action/attempt/result state,
  conservative restart recovery and `outcome_unknown` containment, finite
  state integrity handling, one-daemon data-root ownership, managed-root
  filesystem/Git exclusions, and scoped four-channel delivery/approval
  continuity.
- Supply-chain hardening for the published line: locked dependencies,
  SHA-pinned workflow actions, dependency review, workflow linting, code
  scanning, PyPI OIDC trusted publishing, SPDX SBOM generation, and provenance
  attestations.

**Current boundaries and follow-up work**:

- Authenticated operator convenience RPCs now share PEP/control-plane,
  durable-action, audit, taint, and output authorities while retaining typed
  ingress, descriptor/admin posture, and component-local readiness diagnostics.
- Live handler/composition ownership, pending-action lifecycle ownership, RPC
  descriptors, and direct effect execution each have one current runtime
  authority; later refactors must preserve those boundaries.
- COMMAND planner typed tool output now owns the characterized thread, note,
  todo, reminder, filesystem, web, browser, evidence, and multi-action
  conversational family. Session handling binds those typed consequences to
  authenticated current-turn and machine state; it no longer builds or
  substitutes those actions from prose. Separate finite state-bound
  confirmation, authentication, greeting-response, and recovery protocols
  remain.
- One canonical seven-family secret-signature registry now feeds ingress
  redaction/credential taint, output redaction/typed findings, and PEP argument
  rejection while preserving their separate actions and preprocessing.
- Canonical absolute-URL and network-address facts now feed the matching
  provider, proxy, browser, assistant-web, and PEP paths while preserving
  their separate authorization and enforcement layers. Broader network-layer
  simplification, connection-time peer verification, normalization ordering,
  differential execution, and full datamarking remain later work.
- External effects do not carry a universal exactly-once guarantee. Automatic
  restart recovery is limited to the documented trusted routes and ambiguous
  outcomes fail closed to operator reconciliation.

---

## Further Reading

- `DESIGN-PHILOSOPHY.md` — governing first principles
- `analysis/ANALYSIS-security-casestudies.md` — real-world attack patterns mapped to shisad defenses
- `analysis/ANALYSIS-supply-chain.md` — supply chain threat model and mitigations
- `adr/ADR-command-task-architecture.md` — COMMAND/TASK isolation and orchestration security
- `adr/ADR-policy-source-authority.md` — policy merge and authority model
- `AUTHORITY-MAP.md` — ref-scoped runtime ownership and route boundaries
- [agentic-security](https://github.com/lhl/agentic-security) — literature survey on LLM agent security (78 papers, defense taxonomy, production readiness assessment)
- [agentic-memory](https://github.com/lhl/agentic-memory) — literature survey on agent memory architectures and poisoning defenses (29+ references, attack taxonomy, defense recommendations)
